//! Real resource limits inside the disposable OpenWrt VM, never the host cgroup.

use super::*;
use std::fs;

const GROUP: &str = "/sys/fs/cgroup/tunnel-detour-r146";
const OWNER: &str = "resource_faults::r146_guest_cgroup_limits_refuse_process_creation_and_close_oom_workers_without_affecting_management";
const ROLE: &str = "TUNNEL_DETOUR_RESOURCE_FAULT_ROLE";

fn require_guest() -> TestResult {
    let command_line = fs::read_to_string("/proc/cmdline")?;
    for required in ["root=/dev/vda", "console=ttyS0,115200"] {
        if !command_line.split_whitespace().any(|word| word == required) {
            return Err("resource fault actor requires the disposable QEMU guest".into());
        }
    }
    if !rustix::process::geteuid().is_root() {
        return Err("resource fault actor requires guest root".into());
    }
    Ok(())
}

fn guest_role(role: &str) -> TestResult {
    require_guest()?;
    match role {
        "memory" => {
            // Admission checks precede allocation. This process is moved into the
            // same bounded guest group as the owned service, not its SSH supervisor.
            if fs::read_to_string(format!("{GROUP}/memory.max"))?.trim() != "67108864"
                || fs::read_to_string(format!("{GROUP}/memory.oom.group"))?.trim() != "1"
            {
                return Err("the 64-MiB group OOM boundary has not been armed".into());
            }
            fs::write(
                format!("{GROUP}/cgroup.procs"),
                std::process::id().to_string(),
            )?;
            let mut pages = Vec::new();
            for _ in 0..128 {
                let mut page = vec![0_u8; 1024 * 1024];
                for offset in (0..page.len()).step_by(4096) {
                    page[offset] = 1;
                }
                pages.push(page);
                std::hint::black_box(&pages);
            }
            return Err("allocation reached 128 MiB without the required group OOM".into());
        }
        "held-client" => {
            let mut stream = relay_test_stream("[2001:db8:3::2]:0", 18080, "192.0.2.2:8080")?;
            stream_echo(&mut stream, b"before constrained group memory")?;
            File::create("/tmp/inbound-test/resource-client-ready")?;
            wait_file("check-memory-pressure")?;
            stream_closed(&mut stream)?;
            File::create("/tmp/inbound-test/resource-client-closed")?;
        }
        _ => return Err("unknown resource fault actor".into()),
    }
    Ok(())
}

fn write(lab: &Lab, path: &str, value: &str) -> TestResult {
    lab.exec(&["tee", path], Some(value.as_bytes()))?;
    Ok(())
}

fn counter(lab: &Lab, file: &str, field: &str) -> TestResult<u64> {
    let text = String::from_utf8(lab.exec(&["cat", &format!("{GROUP}/{file}")], None)?)?;
    for line in text.lines() {
        let mut fields = line.split_whitespace();
        if fields.next() == Some(field) {
            return Ok(fields
                .next()
                .ok_or("missing resource counter value")?
                .parse()?);
        }
    }
    Err(format!("missing required kernel resource counter {file}:{field}").into())
}

fn ready(lab: &Lab) -> TestResult<u64> {
    let mut pid = None;
    wait(|| {
        let status = lab.ubus("tunnel-detour", "inbound_status", json!({}))?;
        if status["running"] == true && status["status"]["applied"] == true {
            pid = status["status"]["process_id"].as_u64();
        }
        Ok(pid.is_some())
    })?;
    pid.ok_or("ready inbound status has no process identifier".into())
}

fn positive(lab: &Lab) -> TestResult {
    let reply = lab.inbound_probe("relay_client")?;
    if !reply.status.success() {
        return Err(format!(
            "resource recovery lost the verified relay payload: {}",
            String::from_utf8_lossy(&reply.stderr)
        )
        .into());
    }
    Ok(())
}

fn administrative_control(lab: &Lab, configuration: &[u8]) -> TestResult {
    assert_eq!(
        lab.exec(&["uci", "export", "tunnel-detour"], None)?,
        configuration
    );
    assert!(lab.lookup("router.lan")?.contains("192.0.2.1"));
    let status: Value =
        serde_json::from_slice(&lab.exec(&["ubus", "call", "system", "info", "{}"], None)?)?;
    assert!(status["uptime"].as_u64().is_some_and(|uptime| uptime > 0));
    let before = lab.inbound_vpn_plaintext()?;
    assert!(
        lab.inbound_probe("vpn_client")?.status.success(),
        "ordinary WireGuard traffic failed during resource exhaustion"
    );
    let after = lab.inbound_vpn_plaintext()?;
    assert!(
        after[0] > before[0] && after[1] > before[1],
        "ordinary control did not traverse the real WireGuard interface in both directions"
    );
    Ok(())
}

#[test]
#[ignore = "requires the disposable QEMU OpenWrt guest with pids and memory cgroup v2 controllers"]
fn r146_guest_cgroup_limits_refuse_process_creation_and_close_oom_workers_without_affecting_management()
-> TestResult {
    if let Ok(role) = env::var(ROLE) {
        return guest_role(&role);
    }
    let lab = Lab::create(true)?;
    if lab.vm.is_none() {
        return Err(
            "R146 requires cargo xtask test-openwrt-flow r146; host cgroups are never used".into(),
        );
    }
    // No mount, limit or PID change is performed until the remote VM identity
    // and the kernel's actual controllers have both been checked.
    let command_line = String::from_utf8(lab.exec(&["cat", "/proc/cmdline"], None)?)?;
    assert!(
        command_line
            .split_whitespace()
            .any(|word| word == "root=/dev/vda")
    );
    if !lab
        .raw(&["test", "-f", "/sys/fs/cgroup/cgroup.controllers"], None)?
        .status
        .success()
    {
        lab.exec(&["mount", "-t", "cgroup2", "none", "/sys/fs/cgroup"], None)?;
    }
    let available =
        String::from_utf8(lab.exec(&["cat", "/sys/fs/cgroup/cgroup.controllers"], None)?)?;
    for required in ["pids", "memory"] {
        assert!(
            available
                .split_whitespace()
                .any(|controller| controller == required),
            "guest kernel lacks required {required} controller"
        );
    }
    let controllers =
        String::from_utf8(lab.exec(&["cat", "/sys/fs/cgroup/cgroup.subtree_control"], None)?)?;
    let added: Vec<_> = ["pids", "memory"]
        .into_iter()
        .filter(|required| {
            !controllers
                .split_whitespace()
                .any(|controller| controller == *required)
        })
        .collect();
    for controller in &added {
        write(
            &lab,
            "/sys/fs/cgroup/cgroup.subtree_control",
            &format!("+{controller}"),
        )?;
    }
    lab.exec(&["mkdir", GROUP], None)?;
    write(&lab, &format!("{GROUP}/pids.max"), "128")?;
    write(&lab, &format!("{GROUP}/memory.max"), "67108864")?;
    write(&lab, &format!("{GROUP}/memory.oom.group"), "1")?;
    if lab
        .raw(&["test", "-f", &format!("{GROUP}/memory.swap.max")], None)?
        .status
        .success()
    {
        write(&lab, &format!("{GROUP}/memory.swap.max"), "0")?;
    }

    lab.inbound_endpoints()?;
    lab.inbound_wireguard()?;
    lab.spawn_inbound_probe("relay_server")?;
    wait(|| {
        Ok(lab
            .inbound_marker("td-in-lan", "test", "relay-endpoint-ready")?
            .status
            .success())
    })?;
    let init_path = "/etc/init.d/tunnel-detour-inbound";
    let original_init = lab.exec(&["cat", init_path], None)?;
    let text = std::str::from_utf8(&original_init)?;
    let respawn = "\tprocd_set_param respawn 3600 5 5\n";
    assert_eq!(
        text.matches(respawn).count(),
        1,
        "fixture cannot disable only its owned respawn setting"
    );
    write(&lab, init_path, &text.replace(respawn, ""))?;
    lab.prepare_inbound_uci()?;
    lab.change("set tunnel-detour.sample.protocol='tcp'\nset tunnel-detour.sample.destination_address='192.0.2.2'\nset tunnel-detour.inbound.enabled='1'")?;
    let configuration = lab.exec(&["uci", "export", "tunnel-detour"], None)?;
    let pid = ready(&lab)?;
    positive(&lab)?;
    let oom_adjustment =
        String::from_utf8(lab.exec(&["cat", &format!("/proc/{pid}/oom_score_adj")], None)?)?;
    assert_ne!(
        oom_adjustment.trim(),
        "-1000",
        "the fixture cannot prove a whole-group OOM while its controller is exempt from the kernel OOM killer"
    );
    write(&lab, &format!("{GROUP}/cgroup.procs"), &pid.to_string())?;
    let result = (|| -> TestResult {
        let denied_before = counter(&lab, "pids.events", "max")?;
        // A lower-than-current limit is intentional: existing processes remain
        // runnable while the kernel refuses every subsequent fork/clone here.
        write(&lab, &format!("{GROUP}/pids.max"), "0")?;
        assert!(
            !lab.inbound_probe("relay_client")?.status.success(),
            "new flow passed without admitting an isolated worker"
        );
        assert!(
            counter(&lab, "pids.events", "max")? > denied_before,
            "no actual kernel process admission failure occurred"
        );
        eprintln!(
            "{}",
            json!({"requirement":"R146","phase":"pid_exhaustion","denied_before":denied_before,"denied_after":counter(&lab,"pids.events","max")?})
        );
        administrative_control(&lab, &configuration)?;
        write(&lab, &format!("{GROUP}/pids.max"), "128")?;
        let status = lab.ubus("tunnel-detour", "inbound_status", json!({}))?;
        let survived = status["running"] == true && status["status"]["phase"] == "ready";
        eprintln!(
            "{}",
            json!({"requirement":"R146","phase":"pid_limit_restored","controller_survived":survived})
        );
        // Either refusing just the new worker or stopping closed is valid under
        // exhaustion. Restoring resources must permit an explicit recovery.
        lab.exec(&["/etc/init.d/tunnel-detour-inbound", "restart"], None)?;
        wait(|| {
            Ok(
                String::from_utf8(lab.exec(&["cat", &format!("{GROUP}/pids.current")], None)?)?
                    .trim()
                    == "0",
            )
        })?;
        let memory_pid = ready(&lab)?;
        write(
            &lab,
            &format!("{GROUP}/cgroup.procs"),
            &memory_pid.to_string(),
        )?;
        positive(&lab)?;
        let held = lab
            .background_command(&[
                "env",
                &format!("{ROLE}=held-client"),
                "/sbin/ip",
                "netns",
                "exec",
                "td-in-wan",
                "/usr/libexec/tunnel-detour-test-fixture",
                "--ignored",
                "--exact",
                OWNER,
                "--nocapture",
            ])?
            .spawn()?;
        lab.background.borrow_mut().push(held);
        wait(|| {
            Ok(lab
                .inbound_marker("td-in-wan", "test", "resource-client-ready")?
                .status
                .success())
        })?;

        let oom_before = counter(&lab, "memory.events", "oom_kill")?;
        let filler = lab.raw(
            &[
                "env",
                &format!("{ROLE}=memory"),
                "/usr/libexec/tunnel-detour-test-fixture",
                "--ignored",
                "--exact",
                OWNER,
                "--nocapture",
            ],
            None,
        )?;
        assert!(
            !filler.status.success(),
            "memory actor unexpectedly survived its bounded group OOM"
        );
        assert!(
            counter(&lab, "memory.events", "oom_kill")? > oom_before,
            "no actual kernel OOM kill occurred"
        );
        assert!(
            counter(&lab, "memory.events", "oom_group_kill")? > 0,
            "the kernel did not kill the service as an OOM group"
        );
        eprintln!(
            "{}",
            json!({"requirement":"R146","phase":"group_oom","oom_kill_before":oom_before,"oom_kill_after":counter(&lab,"memory.events","oom_kill")?,"group_kills":counter(&lab,"memory.events","oom_group_kill")?})
        );
        wait(|| {
            let empty = lab
                .exec(&["cat", &format!("{GROUP}/cgroup.procs")], None)?
                .is_empty();
            let tasks =
                String::from_utf8(lab.exec(&["cat", &format!("{GROUP}/pids.current")], None)?)?;
            Ok(empty && tasks.trim() == "0")
        })?;
        lab.inbound_marker("td-in-wan", "touch", "check-memory-pressure")?;
        wait(|| {
            Ok(lab
                .inbound_marker("td-in-wan", "test", "resource-client-closed")?
                .status
                .success())
        })?;
        wait(|| {
            Ok(lab
                .inbound_marker("td-in-lan", "cat", "relay-server-active")?
                .stdout
                == b"0")
        })?;
        assert!(
            !lab.inbound_probe("relay_client")?.status.success(),
            "publication escaped its stopped controller"
        );
        administrative_control(&lab, &configuration)?;
        lab.exec(&["/etc/init.d/tunnel-detour-inbound", "restart"], None)?;
        assert_ne!(ready(&lab)?, memory_pid);
        positive(&lab)?;
        administrative_control(&lab, &configuration)?;
        Ok(())
    })();
    // Even a failed assertion is confined to the owned disposable VM; no cgroup
    // control files on the host or production router are ever opened for writing.
    lab.exec(&["tee", init_path], Some(&original_init))?;
    lab.exec(&["/etc/init.d/tunnel-detour-inbound", "stop"], None)?;
    if result.is_ok() {
        lab.exec(&["rmdir", GROUP], None)?;
        for controller in added {
            write(
                &lab,
                "/sys/fs/cgroup/cgroup.subtree_control",
                &format!("-{controller}"),
            )?;
        }
    }
    result
}
