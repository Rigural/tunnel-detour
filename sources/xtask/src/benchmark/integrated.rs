//! Full OpenWrt inbound-controller cost, separate from the matched transport campaign.

use super::*;
use std::{fs, time::Instant};

const NATIVE_IMAGE: &str = "tunnel-detour-openwrt-dnsmasq-lab:local";
const ACTOR_BUILD_IMAGE: &str = "tunnel-detour-integrated-actors:local";
const SCOPE: &str = "entire native OpenWrt cgroup: procd, netifd, rpcd, firewall4, local DNS, LuCI and enabled Tunnel Detour processes; endpoints and observer excluded";

struct Images {
    native: ImageSnapshot,
    actors: ImageSnapshot,
}

#[derive(Clone, Copy, PartialEq)]
pub(crate) enum DnsProfile {
    Disabled,
    Idle,
    Load,
}

fn inspect(program: &std::ffi::OsStr, root: &Path, args: &[&str]) -> Result<String> {
    let output = Command::new(program)
        .current_dir(root)
        .args(args)
        .output()?;
    if !output.status.success() {
        return Err(format!("integrated benchmark inspection failed: {args:?}").into());
    }
    Ok(String::from_utf8(output.stdout)?.trim().to_owned())
}

/// Measure production inbound UCI/procd behavior with independently accounted actors.
/// The pilot qualifies one load; the matrix observes every primary load once, with
/// no paired inference or claim about ARM64. The optional DNS process has no
/// sustained query workload; its readiness and Fake-IP delivery are checked.
pub fn run(
    cargo: &std::ffi::OsStr,
    root: &Path,
    output: &Path,
    matrix: bool,
    dns_profile: DnsProfile,
) -> Result {
    let with_dns = dns_profile != DnsProfile::Disabled;
    let target = cargo_target(cargo, root)?;
    let controller = fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(target.join(if with_dns {
            "relay-integrated-dns-benchmark.lock"
        } else {
            "relay-integrated-benchmark.lock"
        }))?;
    controller.try_lock()?;
    fs::create_dir_all(output.parent().ok_or("an output parent is required")?)?;
    fs::create_dir(output)?;
    let output = output.canonicalize()?;
    let build_guard = activity_lock(&target)?;
    let source_inputs = xtask::provenance::source_inputs(root)?;
    let worker = build_worker(cargo, root)?;
    let service = build_binary(cargo, root, "tunnel-detour-service", "tunnel-detour")?;
    for (dockerfile, image, native) in [
        (
            "sources/tests/benchmark/Dockerfile",
            ACTOR_BUILD_IMAGE,
            false,
        ),
        ("sources/tests/openwrt/Dockerfile", NATIVE_IMAGE, true),
    ] {
        let mut build = Command::new("docker");
        build
            .current_dir(root)
            .args(["build", "--tag", image, "--file", dockerfile]);
        if native {
            build.args(["--target", "dnsmasq-lab"]);
        }
        if !build.arg(".").status()?.success() {
            return Err("integrated benchmark image build failed".into());
        }
    }
    if xtask::provenance::source_inputs(root)? != source_inputs {
        return Err("source inputs changed while freezing integrated benchmark binaries".into());
    }
    let stable_worker = output.join("relay-bench-worker");
    let stable_service = output.join("tunnel-detour");
    let stable_driver = output.join("benchmark-driver");
    fs::copy(worker, &stable_worker)?;
    fs::copy(service, &stable_service)?;
    // Read our live inode directly. Cargo may atomically replace its pathname
    // during another check; a child reading /proc/self/exe would hash itself.
    fs::copy("/proc/self/exe", &stable_driver)?;
    let images = Images {
        native: freeze_image(NATIVE_IMAGE, "native")?,
        actors: freeze_image(ACTOR_BUILD_IMAGE, "integrated-actors")?,
    };
    let mut cases = Vec::new();
    for connections in if matrix {
        &[1, 4, 16, 32][..]
    } else {
        &[4][..]
    } {
        for (workload, message_bytes) in if matrix {
            &[
                ("latency", 64),
                ("latency", 256),
                ("latency", 1024),
                ("upload", 0),
                ("download", 0),
                ("duplex", 0),
                ("churn", 256),
            ][..]
        } else {
            &[("latency", 256)][..]
        } {
            cases.push(Scenario {
                prepared: false,
                observation: Observation::Full,
                workload,
                connections: *connections,
                message_bytes: *message_bytes,
                window: if *workload == "churn" {
                    Measurement::Cycles {
                        warmup: 1024,
                        measured: 8192,
                    }
                } else {
                    Measurement::Timed {
                        warmup: 5,
                        seconds: 20,
                    }
                },
                reverse: false,
                repetition: 0,
            });
        }
    }
    fs::write(
        output.join("manifest.json"),
        serde_json::to_vec_pretty(&json!({
            "source_inputs":source_inputs,
            "kind":if matrix {"integrated native matrix"} else {"integrated native qualification pilot"},
            "scope":SCOPE,"comparison":"descriptive only; do not compare this cgroup with socat's transport-only cgroup",
            "architecture":"x86_64","hardware_acceptance":false,
            "native_image":images.native.inspection[0]["Id"],"actor_image":images.actors.inspection[0]["Id"],
            "native_image_tag":images.native.tag,"actor_image_tag":images.actors.tag,
            "native_image_layers":images.native.inspection[0]["RootFS"]["Layers"],"actor_image_layers":images.actors.inspection[0]["RootFS"]["Layers"],
            "image_retention":"owned run tags are retained as replay artifacts; other builds do not replace them",
            "worker_sha256":digest(&stable_worker)?,"service_sha256":digest(&stable_service)?,
            "driver_sha256":digest(&stable_driver)?,
            "commit":inspect(std::ffi::OsStr::new("git"),root,&["rev-parse","HEAD"])?,
            "working_tree":inspect(std::ffi::OsStr::new("git"),root,&["status","--porcelain=v1"])?,
            "rustc":inspect(std::ffi::OsStr::new("rustc"),root,&["-vV"])?,
            "docker":inspect(std::ffi::OsStr::new("docker"),root,&["version","--format","{{json .}}"] )?,
            "node_cpus":2,"node_memory_limit_bytes":268435456,"actor_cpus":4,"observer_cpus":1,
            "node_uid":0,"observer_uid":0,"observer_capabilities":["SYS_PTRACE","DAC_READ_SEARCH"],
            "native_extra_capabilities":["NET_ADMIN","SYS_ADMIN"],
            "inactive_and_active_idle_seconds":10,"dns_exceptions_enabled":with_dns,"wireguard_configured":false,
            "profile":if dns_profile == DnsProfile::Load {"inbound and DNS exceptions; dnsmasq cache disabled only in the fixture; separate fixed-arrival 200-QPS UDP generator"} else if with_dns {"inbound and DNS exceptions enabled; dnsmasq frontend, synthetic resolver; no sustained DNS workload"} else {"inbound enabled; DNS exceptions disabled"},
            "resource_window":"client startup, warmup, measured load, TCP drain and final native status query; baseline is not subtracted",
            "accounting_limit":"cgroup-charged CPU and memory, plus live process PSS; unattributed host softirq work and global kernel allocations are not whole-router accounting",
            "native_security_options":["apparmor=unconfined","seccomp=unconfined"],
            "queue_limit":32,"queue_wait_milliseconds":250,"backend_connection_limit":32,
            "cases":cases.iter().map(Scenario::description).collect::<Vec<_>>()
        }))?,
    )?;
    drop(build_guard);
    let context: Value = serde_json::from_str(&docker(&strings(&["context", "inspect"]))?)?;
    let socket = context[0]["Endpoints"]["docker"]["Host"]
        .as_str()
        .and_then(|endpoint| endpoint.strip_prefix("unix://"))
        .ok_or("the integrated benchmark needs a local Docker Unix socket")?;
    let api = Api(reqwest::Client::builder()
        .no_proxy()
        .unix_socket(socket)
        .connect_timeout(Duration::from_secs(3))
        .build()?);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let mut completed = Vec::new();
    for (index, spec) in cases.iter().copied().enumerate() {
        let _activity = activity_lock(&target)?;
        let directory = output.join(format!(
            "{index:03}-{}-c{:02}-b{:04}",
            spec.workload, spec.connections, spec.message_bytes
        ));
        fs::create_dir(&directory)?;
        println!(
            "Integrated measurement {}/{}: {}, {} connections",
            index + 1,
            cases.len(),
            spec.workload,
            spec.connections
        );
        let result = runtime.block_on(measure(
            &api,
            &stable_worker,
            &stable_service,
            &images,
            &directory,
            spec,
            dns_profile,
        ));
        match result {
            Ok(summary) => completed.push(summary),
            Err(error) => {
                fs::write(
                    directory.join("invalid.json"),
                    serde_json::to_vec_pretty(
                        &json!({"valid":false,"reason":error.to_string(),"case":spec.description()}),
                    )?,
                )?;
                return Err(error);
            }
        }
        fs::write(
            output.join("summary.json"),
            serde_json::to_vec_pretty(&json!({
                "complete":false,"scope":SCOPE,"dns_exceptions_enabled":with_dns,"comparative_inference":"none; one observation per case",
                "results":completed
            }))?,
        )?;
    }
    write_tables(&output, &completed, dns_profile)?;
    fs::write(
        output.join("summary.json"),
        serde_json::to_vec_pretty(&json!({
            "complete":true,"scope":SCOPE,"dns_exceptions_enabled":with_dns,"comparative_inference":"none; one observation per case",
            "results":completed
        }))?,
    )?;
    Ok(())
}

pub(super) fn idle_summary(raw: &Value) -> Result<Value> {
    let peak = raw["memory_observer"]["samples"]
        .as_array()
        .ok_or("missing native idle memory samples")?
        .iter()
        .map(|sample| {
            sample["memory"]["pss_kib"]
                .as_u64()
                .ok_or("missing idle PSS")
        })
        .collect::<std::result::Result<Vec<_>, _>>()?
        .into_iter()
        .max()
        .ok_or("no idle PSS samples")?;
    let elapsed = raw["elapsed_microseconds"]
        .as_u64()
        .filter(|n| *n > 0)
        .ok_or("invalid native idle duration")?;
    let cpu = raw["cpu_nanoseconds"]
        .as_u64()
        .ok_or("missing native idle CPU usage")?;
    let memory = raw["after"]["memory_stats"]["usage"]
        .as_u64()
        .ok_or("missing native idle memory usage")?;
    Ok(
        json!({"elapsed_microseconds":elapsed,"cpu_nanoseconds":cpu,"sampled_process_pss_peak_kib":peak,"cgroup_memory_at_end_bytes":memory}),
    )
}

fn write_tables(output: &Path, completed: &[Value], dns_profile: DnsProfile) -> Result {
    let profile = match dns_profile {
        DnsProfile::Disabled => "inbound",
        DnsProfile::Idle => "inbound+dns-idle",
        DnsProfile::Load => "inbound+dns-load",
    };
    let mut csv = String::from(
        "profile,workload,connections,message_bytes,rtt_p95_us,connection_cycle_p95_us,exchanges_s,upload_bytes_s,download_bytes_s,cpu_ns,pss_peak_kib,cgroup_peak_bytes,inactive_idle_cpu_ns,active_idle_cpu_ns,activation_observed_us,disable_observed_us\n",
    );
    let mut table = format!(
        "# Native OpenWrt package observations\n\nProfile: `{profile}`. DNS exceptions have no sustained query load when enabled. Docker x86_64, one observation per load. The whole OpenWrt cgroup is included; endpoints and the observer are separate. Baselines are descriptive and are not subtracted. These are neither confidence intervals nor a comparison with socat's transport-only measurements. CPU/memory accounting is limited to the cgroup and sampled live process PSS, not total host or router cost. PSS and charged cgroup memory have different scopes. Latency is established RTT or, for churn, the complete connection cycle. CPU includes client startup, warmup, TCP drain and final native status queries.\n\n| Workload | Connections | Message bytes | RTT/cycle p95 (us) | Upload (MiB/s) | Download (MiB/s) | Cgroup CPU (ms) | Peak PSS (KiB) | Peak cgroup memory (MiB) |\n| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |\n",
    );
    if dns_profile == DnsProfile::Load {
        table = table.replace("DNS exceptions have no sustained query load when enabled.", "DNS has a separate fixed-arrival 200-QPS UDP generator with at most 64 outstanding requests; the fixture disables dnsmasq caching. Raw DNS RTT and scheduled-arrival histograms, request errors and local capacity refusals are in dns-load.json. Node resource accounting includes the full DNS interval and its overlap with transport, not only TCP's steady window.");
    }
    let mut baseline = String::from(
        "\n## Baselines and lifecycle\n\nEach idle observation lasts approximately ten seconds. Activation and disable durations include native UCI/procd operations, Docker control and readiness polling. Memory remains a whole-OpenWrt observation.\n\n| Workload | Connections | Message bytes | Inactive idle CPU (ms) | Active idle CPU (ms) | Inactive peak PSS (KiB) | Active peak PSS (KiB) | Activation (ms) | Disable (ms) |\n| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |\n",
    );
    for row in completed {
        let required = |pointer: &str| -> Result<f64> {
            row.pointer(pointer)
                .and_then(Value::as_f64)
                .filter(|n| n.is_finite())
                .ok_or_else(|| format!("missing integrated report metric {pointer}").into())
        };
        let optional = |name: &str| -> Result<Option<f64>> {
            row.get(name)
                .map(|v| {
                    v.as_f64()
                        .filter(|n| n.is_finite())
                        .ok_or_else(|| format!("invalid integrated metric {name}").into())
                })
                .transpose()
        };
        let workload = row["workload"]
            .as_str()
            .ok_or("missing integrated workload")?;
        let connections = row["connections"]
            .as_u64()
            .ok_or("missing integrated connection count")?;
        let message = match row
            .get("message_bytes")
            .ok_or("missing integrated message size")?
        {
            Value::Null => String::new(),
            value => value
                .as_u64()
                .ok_or("invalid integrated message size")?
                .to_string(),
        };
        let rtt = optional("rtt_p95_microseconds")?;
        let cycle = optional("connection_cycle_p95_microseconds")?;
        let exchanges = optional("exchanges_per_second")?;
        let up = optional("upload_received_bytes_per_second")?;
        let down = optional("download_received_bytes_per_second")?;
        let cpu = required("/resources/cpu_nanoseconds_including_warmup_and_drain")?;
        let pss = required("/resources/sampled_process_pss_peak_kib")?;
        let memory = required("/resources/sampled_cgroup_peak_bytes")?;
        let inactive = required("/inactive_idle/cpu_nanoseconds")?;
        let active = required("/active_idle/cpu_nanoseconds")?;
        let activate = required("/controller_activation_observed_microseconds")?;
        let disable = required("/controller_disable_observed_microseconds")?;
        let field = |value: Option<f64>, divisor: f64| {
            value
                .map(|n| format!("{:.3}", n / divisor))
                .unwrap_or_default()
        };
        csv.push_str(&format!("{profile},{workload},{connections},{message},{},{},{},{},{},{cpu:.0},{pss:.0},{memory:.0},{inactive:.0},{active:.0},{activate:.0},{disable:.0}\n",field(rtt,1.0),field(cycle,1.0),field(exchanges,1.0),field(up,1.0),field(down,1.0)));
        table.push_str(&format!("| {workload} | {connections} | {message} | {} | {} | {} | {:.3} | {pss:.0} | {:.3} |\n",field(rtt.or(cycle),1.0),field(up,1_048_576.0),field(down,1_048_576.0),cpu/1_000_000.0,memory/1_048_576.0));
        baseline.push_str(&format!("| {workload} | {connections} | {message} | {:.3} | {:.3} | {:.0} | {:.0} | {:.3} | {:.3} |\n",inactive/1_000_000.0,active/1_000_000.0,required("/inactive_idle/sampled_process_pss_peak_kib")?,required("/active_idle/sampled_process_pss_peak_kib")?,activate/1000.0,disable/1000.0));
    }
    table.push_str(&baseline);
    fs::write(output.join("observations.csv"), csv)?;
    fs::write(output.join("observations.md"), table)?;
    Ok(())
}

pub(super) fn exec(id: &str, command: &[&str]) -> Result<String> {
    let mut args = strings(&["exec", id]);
    args.extend(strings(command));
    docker(&args)
}

pub(super) fn copy_into(id: &str, path: &Path, destination: &str) -> Result {
    docker(&strings(&[
        "cp",
        path.to_str().ok_or("non-UTF8 fixture path")?,
        &format!("{id}:{destination}"),
    ]))?;
    Ok(())
}

pub(super) async fn wait_native(api: &Api, id: &str) -> Result {
    tokio::time::timeout(Duration::from_secs(45), async {
        loop {
            if api.get(&format!("/containers/{id}/json")).await?["State"]["Running"] != true {
                return Err("native OpenWrt stopped during boot".into());
            }
            let output = Command::new("timeout")
                .args([
                    "--kill-after=2",
                    "5",
                    "docker",
                    "exec",
                    id,
                    "ubus",
                    "-S",
                    "call",
                    "network.interface",
                    "dump",
                    "{}",
                ])
                .output()?;
            if output.status.success() {
                let value: Value = serde_json::from_slice(&output.stdout)?;
                let interfaces = value["interface"]
                    .as_array()
                    .ok_or("invalid native network dump")?;
                if ["lan", "wan"].iter().all(|name| {
                    interfaces
                        .iter()
                        .any(|entry| entry["interface"] == *name && entry["up"] == true)
                }) && exec(id, &["ubus", "list", "log"])? == "log"
                {
                    exec(id, &["test", "/proc/kmsg", "-ef", "/dev/null"])?;
                    exec(id, &["nft", "list", "table", "inet", "fw4"])?;
                    return Ok::<_, Box<dyn Error>>(());
                }
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await??;
    Ok(())
}

pub(super) fn node(
    lab: &mut Lab,
    service: &Path,
    image: &str,
    wan: &str,
    lan: &str,
    helper: Option<&Path>,
) -> Result<String> {
    let mut arguments = strings(&[
        "create",
        "--label",
        "tunnel-detour.task=local-validation",
        "--network",
        &format!("name={wan},driver-opt=com.docker.network.endpoint.ifname=tdwan0"),
        "--ip",
        "198.51.100.2",
        "--ip6",
        "2001:db8:101::2",
        "--dns",
        "127.0.0.1",
        "--cgroupns",
        "private",
        "--memory",
        "256m",
        "--cpus",
        "2",
        "--cap-add",
        "NET_ADMIN",
        "--cap-add",
        "SYS_ADMIN",
        "--security-opt",
        "apparmor=unconfined",
        "--security-opt",
        "seccomp=unconfined",
        "--sysctl",
        "net.ipv6.conf.all.forwarding=1",
        "--tmpfs",
        "/tmp",
        "--tmpfs",
        "/etc/tunnel-detour-container:ro,size=4096",
        "--mount",
        &format!(
            "type=bind,src={},dst=/usr/bin/tunnel-detour,readonly",
            service.display()
        ),
    ]);
    if let Some(helper) = helper {
        arguments.extend(strings(&[
            "--mount",
            &format!(
                "type=bind,src={},dst=/usr/libexec/tunnel-detour-benchmark-worker,readonly",
                helper.display()
            ),
        ]));
    }
    arguments.push(image.into());
    let id = docker(&arguments)?;
    lab.containers.push(id.clone());
    docker(&strings(&[
        "network",
        "connect",
        "--driver-opt=com.docker.network.endpoint.ifname=tdlan0",
        "--ip",
        "192.0.2.1",
        lan,
        &id,
    ]))?;
    Ok(id)
}

pub(super) fn observer(lab: &mut Lab, worker: &Path, node: &str) -> Result<String> {
    let id = docker(&strings(&[
        "create",
        "--label",
        "tunnel-detour.task=local-validation",
        "--network",
        "none",
        "--pid",
        &format!("container:{node}"),
        "--user",
        "0:0",
        "--cap-drop",
        "ALL",
        "--cap-add",
        "SYS_PTRACE",
        "--cap-add",
        "DAC_READ_SEARCH",
        "--read-only",
        "--memory",
        "128m",
        "--cpus",
        "1",
        "--mount",
        &format!(
            "type=bind,src={},dst=/relay-bench-worker,readonly",
            worker.display()
        ),
        "--env",
        "TUNNEL_DETOUR_BENCH_LAB=1",
        lab.actor_image.as_deref().unwrap_or(IMAGE),
        "/relay-bench-worker",
        "observe",
    ]))?;
    lab.containers.push(id.clone());
    start_prepared(lab, &id)?;
    Ok(id)
}

pub(super) async fn stop_observer(api: &Api, id: &str) -> Result<Value> {
    if api.get(&format!("/containers/{id}/json")).await?["State"]["Running"] != true {
        return Err(format!(
            "native resource observer exited early: {}",
            docker(&strings(&["logs", id]))?
        )
        .into());
    }
    docker(&strings(&["kill", "--signal=TERM", id]))?;
    if docker(&strings(&["wait", id]))? != "0" {
        return Err("native resource observer failed".into());
    }
    let log = docker(&strings(&["logs", id]))?;
    Ok(serde_json::from_str(
        log.lines().last().ok_or("missing native memory report")?,
    )?)
}

pub(super) async fn idle(api: &Api, lab: &mut Lab, worker: &Path, node: &str) -> Result<Value> {
    let observer = observer(lab, worker, node)?;
    api.ready(&observer).await?;
    let before = api.stats(node).await?;
    let started = Instant::now();
    tokio::time::sleep(Duration::from_secs(10)).await;
    let after = api.stats(node).await?;
    let elapsed = started.elapsed().as_micros();
    let memory = stop_observer(api, &observer).await?;
    lab.remove(&observer)?;
    let before_cpu = before["cpu_stats"]["cpu_usage"]["total_usage"]
        .as_u64()
        .ok_or("missing idle CPU baseline")?;
    let after_cpu = after["cpu_stats"]["cpu_usage"]["total_usage"]
        .as_u64()
        .ok_or("missing idle CPU result")?;
    let used = after_cpu
        .checked_sub(before_cpu)
        .ok_or("idle CPU counter regressed")?;
    Ok(
        json!({"scope":SCOPE,"elapsed_microseconds":elapsed,"cpu_nanoseconds":used,"before":before,"after":after,"memory_observer":memory}),
    )
}

async fn status(api: &Api, node: &str) -> Result<Value> {
    if api.get(&format!("/containers/{node}/json")).await?["State"]["Running"] != true {
        return Err("native OpenWrt exited during measurement".into());
    }
    Ok(serde_json::from_str(&exec(
        node,
        &[
            "ubus",
            "-S",
            "call",
            "tunnel-detour",
            "inbound_status",
            "{}",
        ],
    )?)?)
}

fn native_failure(node: &str, output: &Path, state: &Value) -> Result {
    let diagnostic = |arguments: &[&str]| match exec(node, arguments) {
        Ok(output) => json!({"output":output}),
        Err(error) => json!({"error":error.to_string()}),
    };
    fs::write(
        output.join("native-activation-failure.json"),
        serde_json::to_vec_pretty(&json!({
            "status":state,"log":diagnostic(&["logread","-l","80"]),
            "nft":diagnostic(&["nft","-j","list","ruleset"]),
            "routes":diagnostic(&["ip","-j","-6","route","show","table","all"]),
        "routes_v4":diagnostic(&["ip","-j","-4","route","show","table","all"]),
        "mounts":diagnostic(&["cat","/proc/self/mountinfo"]),
        "uci":diagnostic(&["uci","export","tunnel-detour"]),
        "services":diagnostic(&["ubus","-S","call","service","list","{}"]),
        "dns_status":diagnostic(&["ubus","-S","call","tunnel-detour","status","{}"]),
        "dns_revision":diagnostic(&["/usr/bin/tunnel-detour","--dns-revision"]),
        "dns_check":diagnostic(&["/usr/bin/tunnel-detour","--check-uci"])
        }))?,
    )?;
    Ok(())
}

pub(super) fn dns_status(node: &str) -> Result<Value> {
    Ok(serde_json::from_str(&exec(
        node,
        &["ubus", "-S", "call", "tunnel-detour", "status", "{}"],
    )?)?)
}

pub(super) async fn ready_dns(node: &str, output: &Path) -> Result<Value> {
    let result = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let state = dns_status(node)?;
            if state["status"]["phase"] == "ready"
                && state["status"]["configuration_applied"] == true
            {
                let procd: Value = serde_json::from_str(&exec(
                    node,
                    &[
                        "ubus",
                        "-S",
                        "call",
                        "service",
                        "list",
                        "{\"name\":\"tunnel-detour\"}",
                    ],
                )?)?;
                let instance = &procd["tunnel-detour"]["instances"]["main"];
                if instance["command"] != json!(["/usr/bin/tunnel-detour", "--uci"])
                    || instance["pid"] != state["status"]["process_id"]
                {
                    return Err("the measured DNS process does not match procd".into());
                }
                return Ok::<_, Box<dyn Error>>(state);
            }
            if state["status"]["phase"] == "failed" {
                return Err(format!("native DNS activation failed: {state}").into());
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await;
    let result = match result {
        Ok(result) => result,
        Err(error) => Err(error.into()),
    };
    if let Err(error) = &result {
        native_failure(node, output, &json!({"dns_error":error.to_string()}))?;
    }
    result
}

async fn measure(
    api: &Api,
    worker: &Path,
    service: &Path,
    images: &Images,
    output: &Path,
    spec: Scenario<'_>,
    dns_profile: DnsProfile,
) -> Result<Value> {
    let with_dns = dns_profile != DnsProfile::Disabled;
    let host_before = xtask::provenance::host_context();
    let origin_worker = actor_copy(worker, "integrated-origin")?;
    let generator_worker = actor_copy(worker, "integrated-generator")?;
    let observer_worker = actor_copy(worker, "integrated-observer")?;
    let mut lab = Lab {
        failure_directory: Some(output.to_path_buf()),
        containers: Vec::new(),
        networks: Vec::new(),
        actor_image: Some(images.actors.tag.clone()),
    };
    let prefix = format!("td-integrated-{}", std::process::id());
    let wan = lab.network(
        &format!("{prefix}-wan"),
        "198.51.100.0/24",
        "198.51.100.254",
        true,
    )?;
    let lan = lab.network(
        &format!("{prefix}-lan"),
        "192.0.2.0/24",
        "192.0.2.254",
        false,
    )?;
    let node = node(&mut lab, service, &images.native.tag, &wan, &lan, None)?;
    fs::write(
        output.join("network.uci"),
        if with_dns {
            format!(
                "{}\toption gateway '198.51.100.3'\n",
                include_str!("../../../tests/benchmark/integrated.network")
            )
        } else {
            include_str!("../../../tests/benchmark/integrated.network").to_owned()
        },
    )?;
    fs::write(
        output.join("tunnel-detour.uci"),
        include_str!("../../../tests/benchmark/integrated.uci"),
    )?;
    copy_into(&node, &output.join("network.uci"), "/etc/config/network")?;
    copy_into(
        &node,
        &output.join("tunnel-detour.uci"),
        "/etc/config/tunnel-detour",
    )?;
    let boot = Instant::now();
    docker(&strings(&["start", &node]))?;
    wait_native(api, &node).await?;
    if dns_profile == DnsProfile::Load {
        exec(&node, &["uci", "set", "dhcp.@dnsmasq[0].cachesize=0"])?;
        exec(&node, &["uci", "commit", "dhcp"])?;
        exec(&node, &["/etc/init.d/dnsmasq", "reload"])?;
    }
    let boot_us = boot.elapsed().as_micros();
    let inactive = status(api, &node).await?;
    if inactive["enabled"] != false || inactive["running"] != false {
        return Err("native baseline unexpectedly started inbound ports".into());
    }
    let inactive_idle = idle(api, &mut lab, &observer_worker, &node).await?;
    fs::write(
        output.join("inactive-idle.json"),
        serde_json::to_vec_pretty(&inactive_idle)?,
    )?;
    let activation_before = api.stats(&node).await?;
    let activation = Instant::now();
    exec(&node, &["uci", "set", "tunnel-detour.inbound.enabled=1"])?;
    if with_dns {
        exec(&node, &["uci", "set", "tunnel-detour.globals.enabled=1"])?;
    }
    exec(&node, &["uci", "commit", "tunnel-detour"])?;
    if with_dns {
        let check = exec(&node, &["/usr/bin/tunnel-detour", "--check-uci"])?;
        let revision = exec(&node, &["/usr/bin/tunnel-detour", "--dns-revision"])?;
        fs::write(
            output.join("dns-preflight.json"),
            serde_json::to_vec_pretty(&json!({"check":check,"revision":revision}))?,
        )?;
        exec(&node, &["/etc/init.d/tunnel-detour", "start"])?;
    }
    exec(&node, &["/etc/init.d/tunnel-detour-inbound", "reload"])?;
    let initial = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let value = status(api, &node).await?;
            if value["status"]["phase"] == "ready" && value["status"]["applied"] == true {
                return Ok::<_, Box<dyn Error>>(value);
            }
            if value["status"]["phase"] == "failed" {
                native_failure(&node, output, &value)?;
                return Err(format!("native activation failed: {value}").into());
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await??;
    let dns_initial = if with_dns {
        ready_dns(&node, output).await?
    } else {
        Value::Null
    };
    let dns_probe = if with_dns {
        let response = exec(
            &node,
            &[
                "nslookup",
                "-retry=1",
                "-timeout=2",
                "selected.example.net",
                "127.0.0.1",
            ],
        )?;
        if !response
            .lines()
            .any(|line| line.split_whitespace().any(|word| word == "198.18.0.1"))
        {
            return Err(
                "the full-package profile did not return its configured Fake-IP through dnsmasq"
                    .into(),
            );
        }
        Some(response)
    } else {
        None
    };
    let activation_us = activation.elapsed().as_micros();
    let activation_after = api.stats(&node).await?;
    let procd: Value = serde_json::from_str(&exec(
        &node,
        &[
            "ubus",
            "-S",
            "call",
            "service",
            "list",
            "{\"name\":\"tunnel-detour-inbound\"}",
        ],
    )?)?;
    let instance = &procd["tunnel-detour-inbound"]["instances"]["inbound"];
    if instance["command"] != json!(["/usr/bin/tunnel-detour", "--inbound-uci"])
        || instance["pid"] != initial["status"]["process_id"]
    {
        return Err("the measured controller does not match its native procd instance".into());
    }
    let active_idle = idle(api, &mut lab, &observer_worker, &node).await?;
    fs::write(
        output.join("active-idle.json"),
        serde_json::to_vec_pretty(&active_idle)?,
    )?;
    let origin_command = spec.origin_command();
    let refs = origin_command
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    let origin = lab.create(&origin_worker, &lan, "192.0.2.2", "4", None, &refs)?;
    docker(&strings(&["start", &origin]))?;
    api.ready(&origin).await?;
    let observer = observer(&mut lab, &observer_worker, &node)?;
    api.ready(&observer).await?;
    let generator_command = spec.generator_command("[2001:db8:101::2]:18080");
    let refs = generator_command
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    let generator = lab.create(&generator_worker, &wan, "2001:db8:101::3", "4", None, &refs)?;
    spec.window.check_ports(&exec(
        &node,
        &[
            "cat",
            "/proc/sys/net/ipv4/ip_local_port_range",
            "/proc/sys/net/ipv4/tcp_tw_reuse",
        ],
    )?)?;
    fs::write(
        output.join("environment.json"),
        serde_json::to_vec_pretty(&json!({
            "scope":SCOPE,"kernel":exec(&node,&["uname","-r"] )?,"packages":exec(&node,&["apk","info","-v"] )?,
            "native_boot_observed_microseconds":boot_us,"controller_activation_observed_microseconds":activation_us,
            "startup_scope":"includes Docker control, UCI commit, procd startup, readiness polling and the initial DNS probe when enabled",
            "activation_before":activation_before,"activation_after":activation_after,"initial_status":initial,"native_procd":procd,
            "dns_initial_status":dns_initial,"dns_probe":dns_probe,
            "inactive_idle":inactive_idle,"active_idle":active_idle,
            "networks":exec(&node,&["uci","export","network"] )?,"firewall":exec(&node,&["uci","export","firewall"] )?,
            "node_inspection":api.get(&format!("/containers/{node}/json")).await?
        }))?,
    )?;
    let before = api.stats(&node).await?;
    let origin_before = api.stats(&origin).await?;
    let mut dns_progress = Vec::new();
    let mut last_dns_poll = Instant::now();
    if dns_profile == DnsProfile::Load {
        dns_progress.push(json!({"elapsed_microseconds":0,"status":dns_status(&node)?}));
    }
    let dns_generator = if dns_profile == DnsProfile::Load {
        let seconds = match spec.window {
            Measurement::Timed { warmup, seconds } => u64::from(warmup) + u64::from(seconds) + 5,
            Measurement::Cycles { .. } => 50,
        };
        let seconds = seconds.to_string();
        let id = lab.create(
            worker,
            &lan,
            "192.0.2.4",
            "4",
            None,
            &["/relay-bench-worker", "dns-load", "192.0.2.1:53", &seconds],
        )?;
        docker(&strings(&["start", &id]))?;
        api.ready(&id).await?;
        Some(id)
    } else {
        None
    };
    let started = Instant::now();
    docker(&strings(&["start", &generator]))?;
    let mut samples = Vec::new();
    tokio::time::timeout(Duration::from_secs(60),async {
        loop {
            if dns_generator.is_some() && last_dns_poll.elapsed() >= Duration::from_secs(5) {
                dns_progress.push(json!({"elapsed_microseconds":started.elapsed().as_micros(),"status":dns_status(&node)?}));
                fs::write(output.join("dns-progress.json"), serde_json::to_vec_pretty(&dns_progress)?)?;
                last_dns_poll = Instant::now();
            }
            let state=api.get(&format!("/containers/{generator}/json")).await?;
            samples.push(json!({"elapsed_microseconds":started.elapsed().as_micros(),"relay":api.stats(&node).await?,"origin":api.stats(&origin).await?,"generator":api.stats(&generator).await?}));
            if state["State"]["Running"]==false {
                if state["State"]["ExitCode"]!=0 {return Err(format!("integrated generator failed: {}",docker(&strings(&["logs",&generator]))?).into());}
                return Ok::<_,Box<dyn Error>>(());
            }
            if samples.len()>=600 {return Err("integrated sampling capacity exceeded".into());}
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }).await??;
    if let Some(id) = &dns_generator
        && api.get(&format!("/containers/{id}/json")).await?["State"]["Running"] != true
    {
        return Err(
            "DNS generator ended before the transport workload; overlap was not established".into(),
        );
    }
    let dns_load = if let Some(id) = &dns_generator {
        tokio::time::timeout(Duration::from_secs(55), async {
            while api.get(&format!("/containers/{id}/json")).await?["State"]["Running"] == true {
                if last_dns_poll.elapsed() >= Duration::from_secs(5) {
                    dns_progress.push(json!({"elapsed_microseconds":started.elapsed().as_micros(),"status":dns_status(&node)?}));
                    fs::write(output.join("dns-progress.json"), serde_json::to_vec_pretty(&dns_progress)?)?;
                    last_dns_poll = Instant::now();
                }
                if samples.len() >= 600 { return Err("mixed-load resource sampling capacity exceeded".into()); }
                samples.push(json!({"elapsed_microseconds":started.elapsed().as_micros(),"relay":api.stats(&node).await?,"origin":api.stats(&origin).await?,"generator":api.stats(&generator).await?,"dns_generator":api.stats(id).await?}));
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            let text = docker(&strings(&["logs", id]))?;
            let value: Value = serde_json::from_str(text.lines().last().ok_or("missing DNS load result")?)?;
            fs::write(output.join("dns-load.json"), serde_json::to_vec_pretty(&value)?)?;
            if api.get(&format!("/containers/{id}/json")).await?["State"]["ExitCode"] != 0
                || value["request_errors"] != 0 || value["generator_capacity_rejections"] != 0
                || value["offered_requests"] != value["successful_replies"]
            {
                return Err("mixed DNS load failed, lost queries or could not maintain its offered schedule".into());
            }
            Ok::<_,Box<dyn Error>>(value)
        }).await??
    } else {
        Value::Null
    };
    let result: Value = serde_json::from_str(&docker(&strings(&["logs", &generator]))?)?;
    let origin_result = if spec.echo() {
        Value::Null
    } else {
        api.bulk_result(&origin).await?
    };
    let memory = stop_observer(api, &observer).await?;
    let observed = status(api, &node).await?;
    let dns_observed = if with_dns {
        dns_status(&node)?
    } else {
        Value::Null
    };
    let mut report = json!({"variant":"integrated","scope":SCOPE,"case":spec.description(),"connections":spec.connections,
        "workload":spec.workload,"origin_command":origin_command,"generator_command":generator_command,
        "result":result,"origin_result":origin_result,"memory_observer":memory,"samples":samples,
        "relay_before":before,"relay_after":api.stats(&node).await?,"origin_before":origin_before,"origin_after":api.stats(&origin).await?,
        "generator_after":api.stats(&generator).await?,"final_status":observed,"dns_final_status":dns_observed});
    report["host_before"] = host_before;
    report["host_after"] = xtask::provenance::host_context();
    report["dns_load"] = dns_load;
    if dns_profile == DnsProfile::Load {
        dns_progress.push(
            json!({"elapsed_microseconds":started.elapsed().as_micros(),"status":dns_observed}),
        );
        fs::write(
            output.join("dns-progress.json"),
            serde_json::to_vec_pretty(&dns_progress)?,
        )?;
        let counts: Vec<_> = dns_progress
            .iter()
            .map(|sample| {
                sample["status"]["status"]["dns_queries"]
                    .as_u64()
                    .ok_or("missing DNS progress counter")
            })
            .collect::<std::result::Result<_, _>>()?;
        if counts.len() < 3
            || counts.windows(2).any(|pair| pair[1] < pair[0])
            || counts[counts.len() / 2] <= counts[0]
            || counts
                .last()
                .is_none_or(|last| *last <= counts[counts.len() / 2])
        {
            return Err(
                "sustained DNS forwarding was not observed across the mixed-load interval".into(),
            );
        }
        report["dns_backend_query_delta"] = json!(counts[counts.len() - 1] - counts[0]);
        report["dns_progress"] = json!(dns_progress);
        report["dns_counter_scope"] = json!(
            "frontend coalescing/retries can change backend request counts; counters are sampled and may lag, not one-to-one client acknowledgments"
        );
    }
    report["mixed_resource_window"] = json!(
        "when loaded: includes DNS generator startup through its completion, TCP warmup/measurement/drain and native status; both client generators excluded from node accounting"
    );
    fs::write(
        output.join("integrated.json"),
        serde_json::to_vec_pretty(&report)?,
    )?;
    // Raw evidence survives a rejected result. Service restarts/errors cannot be
    // hidden by successful endpoint byte counts or by the aggregate cgroup.
    if observed["status"]["process_id"] != initial["status"]["process_id"]
        || observed["status"]["phase"] != "ready"
        || observed["status"]["applied"] != true
        || observed["status"]["relay"]["rejected"] != 0
    {
        return Err(
            "the integrated controller restarted, failed or rejected workload ingress".into(),
        );
    }
    if with_dns
        && (dns_observed["status"]["process_id"] != dns_initial["status"]["process_id"]
            || dns_observed["status"]["phase"] != "ready"
            || dns_observed["status"]["configuration_applied"] != true
            || dns_observed["status"]["failures"] != 0)
    {
        return Err(
            "the DNS-exception process failed or restarted during the full-package observation"
                .into(),
        );
    }
    let mut summary = summarize_report(&report)?;
    summary["scope"] = json!(SCOPE);
    summary["dns_exceptions_enabled"] = json!(with_dns);
    summary["dns_sustained_load"] = json!(dns_profile == DnsProfile::Load);
    summary["dns_offered_requests"] = report["dns_load"]["offered_requests"].clone();
    summary["dns_successful_replies"] = report["dns_load"]["successful_replies"].clone();
    summary["comparative_inference"] = json!(
        "none; whole OpenWrt cgroup, one observation per case, baseline is descriptive and not subtracted"
    );
    summary["message_bytes"] = spec.description()["message_bytes"].clone();
    summary["inactive_idle"] = idle_summary(&inactive_idle)?;
    summary["active_idle"] = idle_summary(&active_idle)?;
    summary["controller_activation_observed_microseconds"] = json!(activation_us);
    let disable = Instant::now();
    exec(&node, &["uci", "set", "tunnel-detour.inbound.enabled=0"])?;
    if with_dns {
        exec(&node, &["uci", "set", "tunnel-detour.globals.enabled=0"])?;
    }
    exec(&node, &["uci", "commit", "tunnel-detour"])?;
    exec(&node, &["/etc/init.d/tunnel-detour-inbound", "reload"])?;
    if with_dns {
        exec(&node, &["/etc/init.d/tunnel-detour", "reload"])?;
    }
    let disabled = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let value = status(api, &node).await?;
            if value["running"] == false {
                return Ok::<_, Box<dyn Error>>(value);
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await??;
    if with_dns {
        tokio::time::timeout(Duration::from_secs(30), async {
            loop {
                let value = dns_status(&node)?;
                if value["running"] == false {
                    return Ok::<_, Box<dyn Error>>(value);
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
        .await??;
        summary["dns_post_disable_status"] = dns_status(&node)?;
    }
    summary["controller_disable_observed_microseconds"] = json!(disable.elapsed().as_micros());
    summary["controller_post_disable_status"] = disabled;
    summary["node_after_disable"] = api.stats(&node).await?;
    docker(&strings(&["kill", "--signal=TERM", &origin]))?;
    if docker(&strings(&["wait", &origin]))? != "0" {
        return Err("integrated origin did not stop cleanly".into());
    }
    for actor in [&generator, &observer, &origin] {
        lab.remove(actor)?;
    }
    docker(&strings(&["stop", "--time", "3", &node]))?;
    lab.remove(&node)?;
    fs::write(
        output.join("summary.json"),
        serde_json::to_vec_pretty(&summary)?,
    )?;
    // Network cleanup still runs before the activity guard is released.
    lab.failure_directory = None;
    println!("Integrated raw results: {}", output.display());
    Ok(summary)
}
