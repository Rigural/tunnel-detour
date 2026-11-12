//! Native observation adapters. Only the synthetic R124 fixture is an input.

use super::{Lab, TEST, TestResult};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    env,
    io::Read,
    path::Path,
    process::{Command, Stdio},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use xtask::observe::Observer;

fn time() -> TestResult<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_millis()
        .try_into()?)
}

fn capture(args: &[&str]) -> TestResult<Value> {
    let start = time()?;
    let (program, args) = args.split_first().ok_or("observation command missing")?;
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let out = child.stdout.take().ok_or("observation stdout missing")?;
    let err = child.stderr.take().ok_or("observation stderr missing")?;
    let (status, stdout, stderr, timed_out) = std::thread::scope(|scope| -> TestResult<_> {
        let stdout = scope.spawn(move || {
            let mut bytes = Vec::new();
            out.take(16385).read_to_end(&mut bytes).map(|_| bytes)
        });
        let stderr = scope.spawn(move || {
            let mut bytes = Vec::new();
            err.take(2049).read_to_end(&mut bytes).map(|_| bytes)
        });
        let deadline = Instant::now() + Duration::from_secs(3);
        let mut timed_out = false;
        let status = loop {
            if let Some(status) = child.try_wait()? {
                break status;
            }
            if Instant::now() >= deadline {
                child.kill()?;
                timed_out = true;
                break child.wait()?;
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        Ok((
            status,
            stdout.join().map_err(|_| "stdout observation panicked")??,
            stderr.join().map_err(|_| "stderr observation panicked")??,
            timed_out,
        ))
    })?;
    let truncated = stdout.len() > 16384 || stderr.len() > 2048;
    let stdout = &stdout[..stdout.len().min(16384)];
    let stderr = &stderr[..stderr.len().min(2048)];
    Ok(
        json!({"ok":status.success()&&!truncated&&!timed_out,"exit_code":status.code(),"truncated":truncated,"timed_out":timed_out,
        "started_ms":start,"finished_ms":time()?,
        "value":serde_json::from_slice::<Value>(stdout).unwrap_or_else(|_|json!(String::from_utf8_lossy(stdout))),
        "stderr":String::from_utf8_lossy(stderr)}),
    )
}

pub(super) fn snapshot() -> TestResult {
    let mut commands: Vec<(&str, Vec<&str>)> = vec![
        ("interfaces", vec!["/sbin/ip", "-j", "address", "show"]),
        (
            "interface_counters",
            vec!["/sbin/ip", "-j", "-s", "link", "show"],
        ),
        (
            "ipv6_routes",
            vec!["/sbin/ip", "-j", "-6", "route", "show", "table", "all"],
        ),
        ("ipv6_policy", vec!["/sbin/ip", "-j", "-6", "rule", "show"]),
        (
            "packet_boundaries",
            vec!["nft", "-j", "list", "table", "inet", "external_path_probe"],
        ),
        (
            "publication_firewall",
            vec![
                "nft",
                "-j",
                "list",
                "table",
                "inet",
                "tunnel_detour_inbound",
            ],
        ),
        (
            "controller_and_relay",
            vec![
                "ubus",
                "-S",
                "call",
                "tunnel-detour",
                "inbound_status",
                "{}",
            ],
        ),
        (
            "client_conntrack",
            vec![
                "conntrack",
                "-L",
                "-f",
                "ipv6",
                "-p",
                "tcp",
                "--orig-port-dst",
                "18081",
                "-o",
                "extended",
            ],
        ),
        (
            "backend_conntrack",
            vec![
                "conntrack",
                "-L",
                "-f",
                "ipv4",
                "-p",
                "tcp",
                "--orig-port-dst",
                "8080",
                "-o",
                "extended",
            ],
        ),
        (
            "service_log",
            vec!["logread", "-e", "tunnel-detour", "-l", "20"],
        ),
        (
            "isp_routes",
            vec![
                "/sbin/ip",
                "-n",
                "td-in-wan",
                "-j",
                "-6",
                "route",
                "show",
                "table",
                "all",
            ],
        ),
        (
            "isp_firewall",
            vec![
                "/sbin/ip",
                "netns",
                "exec",
                "td-in-wan",
                "nft",
                "-j",
                "list",
                "ruleset",
            ],
        ),
        ("vpn_transfer", vec!["wg", "show", "tdvpn0", "transfer"]),
        (
            "vpn_handshake",
            vec!["wg", "show", "tdvpn0", "latest-handshakes"],
        ),
        ("router_sockets", vec!["netstat", "-nt"]),
        (
            "packet_headers",
            vec!["cat", "/tmp/inbound-test/headers/headers.txt"],
        ),
        (
            "wan_address_packet_headers",
            vec!["cat", "/tmp/inbound-test/wan-headers/headers.txt"],
        ),
        (
            "packet_capture_state",
            vec!["ls", "/tmp/inbound-test/headers"],
        ),
    ];
    if Path::new(super::dhcp::DHCP6_CONFIG).is_file() {
        let ethernet_dhcp = Path::new(super::dhcp::DHCP4_PID).is_file();
        commands.extend([
            (
                "netifd_wan",
                vec![
                    "ubus",
                    "-S",
                    "call",
                    "network.interface.wan",
                    "status",
                    "{}",
                ],
            ),
            (
                "netifd_dhcpv6_wan",
                vec![
                    "ubus",
                    "-S",
                    "call",
                    if ethernet_dhcp {
                        "network.interface.wan6"
                    } else {
                        "network.interface.wan_6"
                    },
                    "status",
                    "{}",
                ],
            ),
            (
                "lab_dhcpv6_server_log",
                vec!["tail", "-n", "18", "/tmp/inbound-test/kea.log"],
            ),
        ]);
        if ethernet_dhcp {
            commands.push((
                "lab_dhcpv4_server_log",
                vec!["tail", "-n", "18", super::dhcp::DHCP4_LOG],
            ));
        }
    }
    if Path::new("/tmp/inbound-test/wan-pppoe-headers").is_dir() {
        commands.extend([
            (
                "pppoe_receive_rules",
                vec!["nft", "-j", "list", "ruleset", "netdev"],
            ),
            (
                "wan_pppoe_ingress",
                vec!["cat", "/tmp/inbound-test/wan-pppoe-headers/headers.txt"],
            ),
            (
                "delegated_pppoe_ingress",
                vec![
                    "cat",
                    "/tmp/inbound-test/delegated-pppoe-headers/headers.txt",
                ],
            ),
        ]);
    }
    let data = std::thread::scope(|scope| -> TestResult<BTreeMap<String, Value>> {
        let jobs = commands
            .into_iter()
            .map(|(name, args)| {
                (
                    name,
                    scope.spawn(move || capture(&args).map_err(|e| e.to_string())),
                )
            })
            .collect::<Vec<_>>();
        jobs.into_iter()
            .map(|(name, job)| {
                let value = match job.join().map_err(|_| "snapshot worker panicked")? {
                    Ok(value) => value,
                    Err(error) => json!({"ok":false,"error":error}),
                };
                Ok((name.to_string(), value))
            })
            .collect()
    })?;
    println!("TD_SNAPSHOT={}", serde_json::to_string(&data)?);
    Ok(())
}

pub(super) fn start(lab: &Lab, use_pppoe: bool) -> TestResult<Option<Observer>> {
    let Some(directory) = env::var_os("TUNNEL_DETOUR_LAB_OBSERVE") else {
        return Ok(None);
    };
    let args = [
        "env",
        "TUNNEL_DETOUR_EXTERNAL_PROBE=snapshot",
        "/usr/libexec/tunnel-detour-test-fixture",
        "--ignored",
        "--exact",
        TEST,
        "--nocapture",
    ];
    let mut argv = vec!["docker".to_string()];
    if let Some(vm) = &lab.vm {
        argv.extend(vm.arguments(&args)?);
    } else {
        argv.extend(["exec".into(), "-i".into(), lab.name.clone()]);
        argv.extend(args.map(str::to_string));
    }
    let observer = Observer::start(
        Path::new(&directory),
        argv,
        json!({
            "container":lab.name,"kernel_environment":if lab.vm.is_some(){"pinned-openwrt-qemu"}else{"docker-host-kernel"},
            "luci_url":if lab.vm.is_none(){Some(&lab.http)}else{None},
            "wan_link":if use_pppoe {"pppoe-vlan"} else {"ethernet"}
        }),
    )?;
    observer.phase("topology-starting")?;
    Ok(Some(observer))
}

pub(super) fn phase(observer: Option<&Observer>, label: &str) -> TestResult {
    if let Some(observer) = observer {
        observer.phase(label)?;
    }
    Ok(())
}

pub(super) fn start_capture(lab: &Lab, use_pppoe: bool) -> TestResult {
    for capture in captures(use_pppoe) {
        let role = format!("TUNNEL_DETOUR_EXTERNAL_PROBE={}", capture.role);
        let child = lab
            .background_command(&[
                "env",
                &role,
                "/usr/libexec/tunnel-detour-test-fixture",
                "--ignored",
                "--exact",
                TEST,
                "--nocapture",
            ])?
            .spawn()?;
        lab.background.borrow_mut().push(child);
        let ready = format!("{}/ready", capture.directory);
        super::wait(|| Ok(lab.raw(&["test", "-f", &ready], None)?.status.success()))?;
    }
    Ok(())
}

struct CaptureScope {
    role: &'static str,
    address: &'static str,
    directory: &'static str,
    pppoe: bool,
}

const CAPTURES: [CaptureScope; 4] = [
    CaptureScope {
        role: "packet-headers",
        address: "2001:db8:30:ff:5444::1",
        directory: "/tmp/inbound-test/headers",
        pppoe: false,
    },
    CaptureScope {
        role: "wan-packet-headers",
        address: "2001:db8:ff::1",
        directory: "/tmp/inbound-test/wan-headers",
        pppoe: false,
    },
    CaptureScope {
        role: "wan-pppoe-headers",
        address: "2001:db8:ff::1",
        directory: "/tmp/inbound-test/wan-pppoe-headers",
        pppoe: true,
    },
    CaptureScope {
        role: "delegated-pppoe-headers",
        address: "2001:db8:30:ff:5444::1",
        directory: "/tmp/inbound-test/delegated-pppoe-headers",
        pppoe: true,
    },
];

fn captures(use_pppoe: bool) -> impl Iterator<Item = &'static CaptureScope> {
    CAPTURES
        .iter()
        .filter(move |scope| !scope.pppoe || use_pppoe)
}

pub(super) fn capture_actor(role: &str) -> Option<TestResult> {
    let scope = CAPTURES.iter().find(|scope| scope.role == role)?;
    let mut args = Vec::new();
    if scope.pppoe {
        args.extend(["--pppoe", super::pppoe::UNDERLAY].map(str::to_string));
    }
    args.extend(
        [
            "/usr/bin/tcpdump",
            "/usr/lib",
            scope.address,
            "18081",
            "90",
            scope.directory,
        ]
        .map(str::to_string),
    );
    Some(xtask::packet::run(&args))
}

pub(super) fn pppoe_ingress(lab: &Lab, delegated: bool) -> TestResult<usize> {
    let directory = if delegated {
        "/tmp/inbound-test/delegated-pppoe-headers"
    } else {
        "/tmp/inbound-test/wan-pppoe-headers"
    };
    let text = lab.exec(&["cat", &format!("{directory}/headers.txt")], None)?;
    Ok(String::from_utf8_lossy(&text)
        .lines()
        .filter(|line| line.contains("PPPoE"))
        .count())
}

pub(super) fn finish_capture(lab: &Lab, use_pppoe: bool) -> TestResult {
    for capture in captures(use_pppoe) {
        let directory = capture.directory;
        lab.exec(&["touch", &format!("{directory}/stop")], None)?;
        let finished = format!("{directory}/finished");
        super::wait(|| Ok(lab.raw(&["test", "-f", &finished], None)?.status.success()))?;
        let text =
            String::from_utf8(lab.exec(&["cat", &format!("{directory}/headers.txt")], None)?)?;
        if capture.pppoe {
            assert!(
                text.contains("PPPoE"),
                "{directory}: no encapsulated packets captured"
            );
        } else {
            assert!(
                text.contains("tdwan0") && text.contains("tdvpn0"),
                "{directory}: passive capture did not observe both WAN and WireGuard boundaries"
            );
        }
        assert!(
            !text.contains("external-path-ok") && !text.contains("GET /"),
            "{directory}: capture retained application data"
        );
    }
    Ok(())
}
