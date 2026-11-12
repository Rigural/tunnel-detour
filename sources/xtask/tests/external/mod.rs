//! Internet-side requests and a separate WireGuard exit, entirely inside the laboratory.

mod dhcp;
mod observation;
mod pppoe;

use super::{Lab, TestResult, checked, wait};
use serde_json::json;
use std::{
    env,
    io::{Read, Write},
    net::{Ipv6Addr, SocketAddr, TcpStream},
    time::{Duration, Instant},
};

const TEST: &str =
    "external::r124_internet_client_and_vpn_exit_reach_host_addressed_wan_and_routed_delegation";
const MANAGEMENT: &str = "[2001:db8:ff::1]:18081";
const DELEGATED: &str = "[2001:db8:30:ff:5444::1]:18081";
const BODY: &[u8] = b"external-path-ok\n";
const MANAGED_WAN_ADDRESS: &str = "100.64.0.2";
const MANAGED_ISP_ADDRESS: &str = "100.64.0.1";

#[derive(Clone, Copy)]
enum WanMode {
    Ethernet,
    Pppoe,
    DhcpEthernet,
    ManagedPppoe,
}

impl WanMode {
    fn uses_pppoe(self) -> bool {
        matches!(self, Self::Pppoe | Self::ManagedPppoe)
    }

    fn uses_dhcpv6(self) -> bool {
        matches!(self, Self::DhcpEthernet | Self::ManagedPppoe)
    }
}

const HTTP_ORIGINS: [(&str, &str, &str); 2] = [
    (
        "td-in-lan",
        "192.0.2.2:8080",
        "/tmp/inbound-test/lan-http.pid",
    ),
    (
        "td-ext-vpn",
        "[2001:db8:100::2]:8080",
        "/tmp/inbound-test/vpn-http.pid",
    ),
];

fn fixture_pid(lab: &Lab, file: &str, process: &str) -> TestResult<u32> {
    let value = lab.exec(&["cat", file], None)?;
    let pid: u32 = std::str::from_utf8(&value)?.trim().parse()?;
    if pid < 2 {
        return Err("invalid laboratory fixture process ID".into());
    }
    let name = lab.exec(&["cat", &format!("/proc/{pid}/comm")], None)?;
    if std::str::from_utf8(&name)?.trim() != process {
        return Err(format!("fixture PID file does not identify {process}").into());
    }
    Ok(pid)
}

fn wait_for_process_exit(lab: &Lab, pid: u32) -> TestResult {
    let path = format!("/proc/{pid}");
    wait(|| Ok(lab.raw(&["test", "!", "-d", &path], None)?.status.success()))
}

fn actor(role: &str) -> TestResult {
    if let Some(result) = observation::capture_actor(role) {
        return result;
    }
    if role == "snapshot" {
        return observation::snapshot();
    }
    if role == "router-advertisement" {
        return dhcp::advertise_router();
    }
    if role == "forwarding" {
        let router = env::var("TUNNEL_DETOUR_ROUTER_NETNS")?;
        assert_ne!(
            std::fs::read_link("/proc/self/ns/net")?.to_string_lossy(),
            router,
            "forwarding must be configured in a separate laboratory node"
        );
        // ip netns exec gives this actor a private mount namespace. A fresh proc
        // view exposes only this node's network sysctls without changing Docker's
        // read-only /proc/sys mount or the host's active network settings.
        let path = "/tmp/inbound-test/external-proc";
        std::fs::create_dir(path)?;
        checked(
            "mount",
            &["-t", "proc", "-o", "nosuid,nodev,noexec", "proc", path],
            None,
        )?;
        let result = (|| -> TestResult {
            for key in ["net/ipv6/conf/all/forwarding", "net/ipv4/ip_forward"] {
                let key = format!("{path}/sys/{key}");
                std::fs::write(&key, b"1\n")?;
                assert_eq!(std::fs::read_to_string(key)?.trim(), "1");
            }
            Ok(())
        })();
        let unmount = checked("umount", &[path], None);
        unmount?;
        std::fs::remove_dir(path)?;
        return result;
    }
    let target: SocketAddr = env::var("TUNNEL_DETOUR_EXTERNAL_TARGET")?.parse()?;
    let socket = socket2::Socket::new(
        if target.is_ipv6() {
            socket2::Domain::IPV6
        } else {
            socket2::Domain::IPV4
        },
        socket2::Type::STREAM,
        Some(socket2::Protocol::TCP),
    )?;
    if matches!(role, "vpn" | "vpn-closed" | "vpn-unavailable") {
        socket.bind_device(Some(b"tdvpn0"))?;
        socket.bind(&SocketAddr::new("fd00:bbbb::1".parse::<Ipv6Addr>()?.into(), 0).into())?;
    }
    let connected = socket.connect_timeout(&target.into(), Duration::from_secs(3));
    if matches!(role, "closed" | "vpn-closed") {
        assert!(
            connected.is_err(),
            "a deliberately unreachable endpoint completed TCP"
        );
        return Ok(());
    }
    connected?;
    let response = http_exchange(socket.into());
    if matches!(role, "unavailable" | "vpn-unavailable") {
        assert!(
            response.is_err(),
            "an unavailable backend returned the origin response"
        );
        return Ok(());
    }
    response
}

fn http_exchange(mut stream: TcpStream) -> TestResult {
    stream.set_write_timeout(Some(Duration::from_secs(3)))?;
    stream.write_all(b"GET / HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n")?;
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut response = Vec::new();
    loop {
        stream.set_read_timeout(Some(
            deadline
                .checked_duration_since(Instant::now())
                .ok_or("HTTP deadline expired")?,
        ))?;
        let mut bytes = [0; 1024];
        let count = stream.read(&mut bytes)?;
        if count == 0 {
            break;
        }
        if response.len() + count > 8192 {
            return Err("HTTP response exceeds the laboratory bound".into());
        }
        response.extend_from_slice(&bytes[..count]);
    }
    let header_end = response
        .windows(4)
        .position(|bytes| bytes == b"\r\n\r\n")
        .ok_or("missing HTTP headers")?
        + 4;
    if !(response.starts_with(b"HTTP/1.1 200 ") || response.starts_with(b"HTTP/1.0 200 ")) {
        return Err("unexpected origin HTTP status".into());
    }
    if &response[header_end..] != BODY {
        return Err("the external client received a different origin body".into());
    }
    Ok(())
}

fn forwarding(lab: &Lab, namespace: &str) -> TestResult {
    let router = String::from_utf8(lab.exec(&["readlink", "/proc/self/ns/net"], None)?)?;
    let router = format!("TUNNEL_DETOUR_ROUTER_NETNS={}", router.trim());
    lab.exec(
        &[
            "ip",
            "netns",
            "exec",
            namespace,
            "env",
            "TUNNEL_DETOUR_EXTERNAL_PROBE=forwarding",
            &router,
            "/usr/libexec/tunnel-detour-test-fixture",
            "--ignored",
            "--exact",
            TEST,
            "--nocapture",
        ],
        None,
    )?;
    lab.exec(
        &["test", "!", "-e", "/tmp/inbound-test/external-proc"],
        None,
    )?;
    Ok(())
}

fn request(lab: &Lab, namespace: Option<&str>, role: &str, target: &str) -> TestResult {
    let target = format!("TUNNEL_DETOUR_EXTERNAL_TARGET={target}");
    let role = format!("TUNNEL_DETOUR_EXTERNAL_PROBE={role}");
    let mut args = vec!["env", role.as_str(), target.as_str()];
    if let Some(namespace) = namespace {
        args.extend(["/sbin/ip", "netns", "exec", namespace]);
    }
    args.extend([
        "/usr/libexec/tunnel-detour-test-fixture",
        "--ignored",
        "--exact",
        TEST,
        "--nocapture",
    ]);
    let result = lab.raw(&args, None)?;
    if !result.status.success() {
        return Err(format!(
            "external actor {role} to {target} failed: {} {}",
            String::from_utf8_lossy(&result.stdout),
            String::from_utf8_lossy(&result.stderr)
        )
        .into());
    }
    Ok(())
}

#[derive(Debug)]
struct Counters {
    wan_ingress: u64,
    ingress_external: u64,
    ingress_vpn: u64,
    wan_in: u64,
    wan_reply: u64,
    vpn_request: u64,
    vpn_reply_leak: u64,
    relay_input: u64,
    backend_dial: u64,
    backend_reply: u64,
}

fn counters(lab: &Lab) -> TestResult<Counters> {
    let table: serde_json::Value = serde_json::from_slice(&lab.exec(
        &["nft", "-j", "list", "table", "inet", "external_path_probe"],
        None,
    )?)?;
    let entries = table["nftables"]
        .as_array()
        .ok_or("missing external counters")?;
    let read = |name: &str| -> TestResult<u64> {
        entries
            .iter()
            .find(|entry| entry["counter"]["name"] == name)
            .and_then(|entry| entry["counter"]["packets"].as_u64())
            .ok_or_else(|| format!("missing external counter {name}").into())
    };
    Ok(Counters {
        wan_ingress: read("wan_ingress")?,
        ingress_external: read("ingress_external")?,
        ingress_vpn: read("ingress_vpn")?,
        wan_in: read("wan_in")?,
        wan_reply: read("wan_reply")?,
        vpn_request: read("vpn_request")?,
        vpn_reply_leak: read("vpn_reply_leak")?,
        relay_input: read("relay_input")?,
        backend_dial: read("backend_dial")?,
        backend_reply: read("backend_reply")?,
    })
}

fn isp_fault_counters(lab: &Lab, names: &[&str]) -> TestResult {
    let table: serde_json::Value = serde_json::from_slice(&lab.exec(
        &[
            "ip",
            "netns",
            "exec",
            "td-in-wan",
            "nft",
            "-j",
            "list",
            "table",
            "inet",
            "external_isp_fault",
        ],
        None,
    )?)?;
    let entries = table["nftables"]
        .as_array()
        .ok_or("missing ISP fault observations")?;
    for name in names {
        assert!(
            entries.iter().any(|entry| {
                entry["counter"]["name"].as_str() == Some(name)
                    && entry["counter"]["packets"]
                        .as_u64()
                        .is_some_and(|count| count > 0)
            }),
            "the simulated provider did not observe {name}"
        );
    }
    Ok(())
}

fn isp_rule(lab: &Lab, rules: &[u8]) -> TestResult {
    lab.exec(
        &["ip", "netns", "exec", "td-in-wan", "nft", "-f", "-"],
        Some(rules),
    )?;
    Ok(())
}

fn clear_isp_fault(lab: &Lab) -> TestResult {
    isp_rule(lab, b"delete table inet external_isp_fault\n")
}

fn healthy_paths(
    lab: &Lab,
    label: &str,
    observer: Option<&xtask::observe::Observer>,
) -> TestResult {
    let before = counters(lab)?;
    request(lab, Some("td-ext-client"), "external", DELEGATED)
        .map_err(|error| format!("{label}, independent external path: {error}"))?;
    request(lab, None, "vpn", DELEGATED)
        .map_err(|error| format!("{label}, VPN return path: {error}"))?;
    let after = counters(lab)?;
    assert!(
        after.wan_ingress > before.wan_ingress
            && after.ingress_external > before.ingress_external
            && after.ingress_vpn > before.ingress_vpn
            && after.wan_in > before.wan_in
            && after.wan_reply > before.wan_reply
            && after.vpn_request > before.vpn_request
            && after.relay_input > before.relay_input
            && after.backend_dial > before.backend_dial
            && after.backend_reply > before.backend_reply,
        "{label}: the exact HTTP bodies did not traverse every observed boundary: {before:?} -> {after:?}"
    );
    assert_eq!(
        after.vpn_reply_leak, 0,
        "{label}: publication replies entered VPN"
    );
    eprintln!("R124: {label}: all boundaries observed; both HTTP bodies verified");
    observation::phase(observer, label)?;
    Ok(())
}

fn local_faults(lab: &Lab, observer: Option<&xtask::observe::Observer>) -> TestResult {
    let before = counters(lab)?;
    lab.exec(
        &["nft", "-f", "-"],
        Some(
            br#"table inet external_ingress_fault {
 chain early { type filter hook ingress device "tdwan0" priority -490; policy accept;
  ip6 daddr 2001:db8:30:ff:5444::1 tcp dport 18081 drop
 }
}
"#,
        ),
    )?;
    observation::phase(observer, "early-ingress-drop-installed")?;
    request(lab, Some("td-ext-client"), "closed", DELEGATED)?;
    request(lab, None, "vpn-closed", DELEGATED)?;
    let early = counters(lab)?;
    assert!(
        early.wan_ingress > before.wan_ingress
            && early.ingress_external > before.ingress_external
            && early.ingress_vpn > before.ingress_vpn
            && early.vpn_request > before.vpn_request,
        "the early ingress fault did not observe returning packets"
    );
    assert_eq!(
        early.wan_in, before.wan_in,
        "an ingress-dropped packet reached IPv6 prerouting"
    );
    assert_eq!(early.relay_input, before.relay_input);
    assert_eq!(early.backend_dial, before.backend_dial);
    observation::phase(observer, "early-ingress-drop-observed")?;
    eprintln!(
        "R124: early router ingress fault: interface received SYNs, prerouting and relay saw none; zero prerouting alone cannot establish upstream loss"
    );
    lab.exec(
        &["nft", "delete", "table", "inet", "external_ingress_fault"],
        None,
    )?;
    healthy_paths(lab, "early ingress recovery", observer)?;

    let before = counters(lab)?;
    lab.exec(
        &["nft", "-f", "-"],
        Some(
            br#"table inet external_router_fault {
 chain pre { type filter hook prerouting priority -305; policy accept;
  iifname "tdwan0" ip6 daddr 2001:db8:30:ff:5444::1 tcp dport 18081 drop
 }
}
"#,
        ),
    )?;
    observation::phase(observer, "prerouting-drop-installed")?;
    request(lab, Some("td-ext-client"), "closed", DELEGATED)?;
    request(lab, None, "vpn-closed", DELEGATED)?;
    let blocked = counters(lab)?;
    assert!(
        blocked.wan_ingress > before.wan_ingress
            && blocked.wan_in > before.wan_in
            && blocked.vpn_request > before.vpn_request
    );
    assert_eq!(
        blocked.relay_input, before.relay_input,
        "WAN drop reached the relay"
    );
    assert_eq!(
        blocked.backend_dial, before.backend_dial,
        "WAN drop dialed the backend"
    );
    eprintln!("R124: router ingress fault: WAN observed requests, relay and backend saw none");
    observation::phase(observer, "prerouting-drop-observed")?;
    lab.exec(
        &["nft", "delete", "table", "inet", "external_router_fault"],
        None,
    )?;
    healthy_paths(lab, "router ingress recovery", observer)?;

    let before = counters(lab)?;
    lab.exec(
        &["ip", "netns", "exec", "td-in-lan", "nft", "-f", "-"],
        Some(
            br#"table inet external_backend_fault {
 chain incoming { type filter hook input priority -300; policy accept;
  iifname "peer0" ip daddr 192.0.2.2 tcp dport 8080 reject with tcp reset
 }
}
"#,
        ),
    )?;
    observation::phase(observer, "backend-refusal-installed")?;
    // TCP to the publication must connect; only the subsequent HTTP exchange
    // may fail. A generic connect error cannot satisfy this backend-failure case.
    request(lab, Some("td-ext-client"), "unavailable", DELEGATED)?;
    request(lab, None, "vpn-unavailable", DELEGATED)?;
    let refused = counters(lab)?;
    assert!(
        refused.wan_in > before.wan_in
            && refused.relay_input > before.relay_input
            && refused.backend_dial > before.backend_dial
            && refused.vpn_request > before.vpn_request
    );
    assert_eq!(
        refused.backend_reply, before.backend_reply,
        "refused backend completed TCP"
    );
    observation::phase(observer, "backend-refusal-observed")?;
    assert_eq!(
        refused.vpn_reply_leak, 0,
        "backend failure leaked replies into VPN"
    );
    eprintln!(
        "R124: backend refusal: public TCP connected, relay dialed IPv4, backend supplied no SYN-ACK or HTTP"
    );
    lab.exec(
        &[
            "ip",
            "netns",
            "exec",
            "td-in-lan",
            "nft",
            "delete",
            "table",
            "inet",
            "external_backend_fault",
        ],
        None,
    )?;
    healthy_paths(lab, "backend recovery", observer)
}

fn topology(lab: &Lab, mode: WanMode) -> TestResult {
    let managed = mode.uses_dhcpv6();
    lab.inbound_endpoints()?;
    for args in [
        vec![
            "ip",
            "-6",
            "addr",
            "del",
            "2001:db8:1::1/64",
            "dev",
            "tdlan0",
        ],
        vec![
            "ip",
            "-n",
            "td-in-lan",
            "-6",
            "addr",
            "del",
            "2001:db8:1::2/64",
            "dev",
            "peer0",
        ],
        vec![
            "ip",
            "-6",
            "addr",
            "del",
            "2001:db8:2::1/64",
            "dev",
            "tdwan0",
        ],
        vec![
            "ip",
            "-6",
            "route",
            "del",
            "default",
            "via",
            "2001:db8:2::2",
            "dev",
            "tdwan0",
            "metric",
            "500",
        ],
    ] {
        lab.exec(&args, None)?;
    }
    if mode.uses_pppoe() {
        pppoe::replace_wan(lab, managed)?;
    } else if !managed {
        for args in [
            [
                "ip",
                "-6",
                "addr",
                "add",
                "fe80::1/64",
                "dev",
                "tdwan0",
                "nodad",
            ]
            .as_slice(),
            &[
                "ip",
                "-n",
                "td-in-wan",
                "-6",
                "addr",
                "add",
                "fe80::2/64",
                "dev",
                "peer0",
                "nodad",
            ],
        ] {
            lab.exec(args, None)?;
        }
    }
    lab.exec(
        &[
            "ip",
            "-n",
            "td-in-lan",
            "-6",
            "addr",
            "add",
            "fd00:1234::2/64",
            "dev",
            "peer0",
            "nodad",
        ],
        None,
    )?;
    if managed {
        dhcp::start(lab, mode.uses_pppoe())?;
    } else {
        lab.exec(&["uci", "batch"], Some(b"set network.lan.ip6addr='fd00:1234::1/64'\nset network.wan6=interface\nset network.wan6.proto='static'\nset network.wan6.device='tdwan0'\nset network.wan6.ip6addr='2001:db8:ff::1/128'\nset network.wan6.ip6gw='fe80::2'\ncommit network\n"))?;
        lab.exec(&["ubus", "call", "network", "reload", "{}"], None)?;
        wait(|| Ok(lab.ubus("network.interface.wan6", "status", json!({}))?["up"] == true))?;
    }

    for (namespace, router_link, peer_link, router4, peer4, router6, peer6) in [
        (
            "td-ext-vpn",
            "vpnnet0",
            "exit0",
            "198.51.100.1/24",
            "198.51.100.2/24",
            "2001:db8:100::1/64",
            "2001:db8:100::2/64",
        ),
        (
            "td-ext-client",
            "internet0",
            "client0",
            "198.51.101.1/24",
            "198.51.101.2/24",
            "2001:db8:101::1/64",
            "2001:db8:101::2/64",
        ),
    ] {
        for args in [
            vec!["ip", "netns", "add", namespace],
            vec![
                "ip",
                "-n",
                "td-in-wan",
                "link",
                "add",
                router_link,
                "type",
                "veth",
                "peer",
                "name",
                peer_link,
                "netns",
                namespace,
            ],
            vec!["ip", "-n", "td-in-wan", "link", "set", router_link, "up"],
            vec!["ip", "-n", namespace, "link", "set", "lo", "up"],
            vec!["ip", "-n", namespace, "link", "set", peer_link, "up"],
            vec![
                "ip",
                "-n",
                "td-in-wan",
                "addr",
                "add",
                router4,
                "dev",
                router_link,
            ],
            vec![
                "ip", "-n", namespace, "addr", "add", peer4, "dev", peer_link,
            ],
            vec![
                "ip",
                "-n",
                "td-in-wan",
                "-6",
                "addr",
                "add",
                router6,
                "dev",
                router_link,
                "nodad",
            ],
            vec![
                "ip", "-n", namespace, "-6", "addr", "add", peer6, "dev", peer_link, "nodad",
            ],
        ] {
            lab.exec(&args, None)?;
        }
    }
    forwarding(lab, "td-in-wan")?;
    forwarding(lab, "td-ext-vpn")?;
    for args in [
        vec![
            "ip",
            "-n",
            "td-ext-vpn",
            "route",
            "add",
            "default",
            "via",
            "198.51.100.1",
        ],
        vec![
            "ip",
            "-n",
            "td-ext-vpn",
            "-6",
            "route",
            "add",
            "default",
            "via",
            "2001:db8:100::1",
        ],
        vec![
            "ip",
            "-n",
            "td-ext-client",
            "-6",
            "route",
            "add",
            "default",
            "via",
            "2001:db8:101::1",
        ],
        vec![
            "ip",
            "route",
            "add",
            "198.51.100.2/32",
            "via",
            if managed {
                MANAGED_ISP_ADDRESS
            } else {
                "203.0.113.2"
            },
            "dev",
            "tdwan0",
        ],
        vec![
            "ip",
            "-n",
            "td-in-wan",
            "-6",
            "route",
            "add",
            "2001:db8:ff::1/128",
            "via",
            "fe80::1",
            "dev",
            "peer0",
        ],
        vec![
            "ip",
            "-n",
            "td-in-wan",
            "-6",
            "route",
            "add",
            "2001:db8:30::/56",
            "via",
            "fe80::1",
            "dev",
            "peer0",
        ],
    ] {
        lab.exec(&args, None)?;
    }
    if !managed {
        for args in [
            vec![
                "ip",
                "-6",
                "route",
                "add",
                "unreachable",
                "2001:db8:30::/56",
                "metric",
                "512",
            ],
            vec![
                "ip",
                "-6",
                "route",
                "replace",
                "default",
                "from",
                "2001:db8:ff::1/128",
                "via",
                "fe80::2",
                "dev",
                "tdwan0",
                "metric",
                "512",
            ],
            vec![
                "ip",
                "-6",
                "route",
                "replace",
                "default",
                "from",
                "2001:db8:30::/56",
                "via",
                "fe80::2",
                "dev",
                "tdwan0",
                "metric",
                "512",
            ],
        ] {
            lab.exec(&args, None)?;
        }
    }

    let router_endpoint = format!(
        "{}:51831",
        if managed {
            MANAGED_WAN_ADDRESS
        } else {
            "203.0.113.1"
        }
    );
    let router_key = lab.exec(&["wg", "genkey"], None)?;
    let exit_key = lab.exec(&["wg", "genkey"], None)?;
    let router_public = String::from_utf8(lab.exec(&["wg", "pubkey"], Some(&router_key))?)?;
    let exit_public = String::from_utf8(lab.exec(&["wg", "pubkey"], Some(&exit_key))?)?;
    lab.exec(
        &["tee", "/tmp/inbound-test/external-router.key"],
        Some(&router_key),
    )?;
    lab.exec(
        &["tee", "/tmp/inbound-test/external-exit.key"],
        Some(&exit_key),
    )?;
    for args in [
        vec!["ip", "link", "del", "tdvpn0"],
        vec!["ip", "link", "add", "tdvpn0", "type", "wireguard"],
        vec![
            "ip",
            "-n",
            "td-ext-vpn",
            "link",
            "add",
            "wgexit0",
            "type",
            "wireguard",
        ],
        vec![
            "wg",
            "set",
            "tdvpn0",
            "private-key",
            "/tmp/inbound-test/external-router.key",
            "listen-port",
            "51831",
            "peer",
            exit_public.trim(),
            "allowed-ips",
            "::/0",
            "endpoint",
            "198.51.100.2:51830",
        ],
        vec![
            "ip",
            "netns",
            "exec",
            "td-ext-vpn",
            "wg",
            "set",
            "wgexit0",
            "private-key",
            "/tmp/inbound-test/external-exit.key",
            "listen-port",
            "51830",
            "peer",
            router_public.trim(),
            "allowed-ips",
            "fd00:bbbb::1/128",
            "endpoint",
            &router_endpoint,
        ],
        vec!["ip", "link", "set", "tdvpn0", "up"],
        vec!["ip", "-n", "td-ext-vpn", "link", "set", "wgexit0", "up"],
        vec![
            "ip",
            "-6",
            "addr",
            "add",
            "fd00:bbbb::1/128",
            "dev",
            "tdvpn0",
            "nodad",
        ],
        vec![
            "ip",
            "-n",
            "td-ext-vpn",
            "-6",
            "addr",
            "add",
            "fd00:bbbb::2/128",
            "dev",
            "wgexit0",
            "nodad",
        ],
        vec![
            "ip",
            "-n",
            "td-ext-vpn",
            "-6",
            "route",
            "add",
            "fd00:bbbb::1/128",
            "dev",
            "wgexit0",
        ],
        vec![
            "ip",
            "-6",
            "route",
            "add",
            "default",
            "dev",
            "tdvpn0",
            "metric",
            if managed { "1024" } else { "10" },
        ],
    ] {
        lab.exec(&args, None)?;
    }
    lab.exec(&["ip", "netns", "exec", "td-ext-vpn", "nft", "-f", "-"], Some(b"table ip6 external_exit_nat {\n chain post {\n type nat hook postrouting priority srcnat; policy accept;\n oifname \"exit0\" ip6 saddr fd00:bbbb::/64 snat to 2001:db8:100::2\n }\n}\n"))?;
    lab.exec(&["nft", "-f", "-"], Some(br#"table inet external_path_probe {
 set public_v6 { type ipv6_addr; elements = { 2001:db8:ff::1, 2001:db8:30:ff:5444::1 }; }
 counter wan_in {}
 counter wan_ingress {}
 counter ingress_external {}
 counter ingress_vpn {}
 counter wan_reply {}
 counter vpn_request {}
 counter vpn_reply_leak {}
 counter relay_input {}
 counter backend_dial {}
 counter backend_reply {}
 chain ingress { type filter hook ingress device "tdwan0" priority -500; policy accept;
  ip6 daddr @public_v6 tcp dport 18081 tcp flags & (syn|ack) == syn counter name wan_ingress
  ip6 saddr 2001:db8:101::2 ip6 daddr @public_v6 tcp dport 18081 tcp flags & (syn|ack) == syn counter name ingress_external
  ip6 saddr 2001:db8:100::2 ip6 daddr @public_v6 tcp dport 18081 tcp flags & (syn|ack) == syn counter name ingress_vpn
 }
 chain pre { type filter hook prerouting priority -310; policy accept;
  iifname "tdwan0" ip6 daddr @public_v6 tcp dport 18081 tcp flags & (syn|ack) == syn counter name wan_in
  iifname "tdlan0" ip saddr 192.0.2.2 tcp sport 8080 tcp flags & (syn|ack) == (syn|ack) counter name backend_reply
 }
 chain incoming { type filter hook input priority -10; policy accept;
  iifname "tdwan0" ct original l3proto ipv6 ct original protocol tcp ct original ip6 daddr @public_v6 ct original proto-dst 18081 tcp flags & (syn|ack) == syn counter name relay_input
 }
 chain post { type filter hook postrouting priority 301; policy accept;
  oifname "tdwan0" ip6 saddr @public_v6 tcp sport 18081 counter name wan_reply
  oifname "tdvpn0" ip6 daddr @public_v6 tcp dport 18081 counter name vpn_request
  oifname "tdvpn0" ip6 saddr @public_v6 tcp sport 18081 counter name vpn_reply_leak
  oifname "tdlan0" ip daddr 192.0.2.2 tcp dport 8080 tcp flags & (syn|ack) == syn counter name backend_dial
 }
}
"#))?;
    lab.exec(&["mkdir", "/tmp/inbound-test/http"], None)?;
    lab.exec(&["tee", "/tmp/inbound-test/http/index.html"], Some(BODY))?;
    // These origins must outlive the bounded command used to start them.
    for (namespace, address, pid_file) in HTTP_ORIGINS {
        lab.exec(
            &[
                "ip",
                "netns",
                "exec",
                namespace,
                "start-stop-daemon",
                "-S",
                "-b",
                "-m",
                "-p",
                pid_file,
                "-x",
                "/usr/sbin/uhttpd",
                "--",
                "-f",
                "-h",
                "/tmp/inbound-test/http",
                "-p",
                address,
            ],
            None,
        )?;
    }
    eprintln!("R124: checking the direct IPv4 LAN origin");
    wait(|| Ok(request(lab, None, "backend", "192.0.2.2:8080").is_ok()))?;
    eprintln!("R124: checking the independent external node's routing");
    request(
        lab,
        Some("td-ext-client"),
        "external",
        "[2001:db8:100::2]:8080",
    )?;
    eprintln!("R124: checking the actual WireGuard tunnel");
    request(lab, None, "vpn", "[2001:db8:100::2]:8080")?;
    Ok(())
}

#[test]
#[ignore = "requires the isolated OpenWrt management laboratory"]
fn r124_internet_client_and_vpn_exit_reach_host_addressed_wan_and_routed_delegation() -> TestResult
{
    if let Ok(role) = env::var("TUNNEL_DETOUR_EXTERNAL_PROBE") {
        return actor(&role);
    }
    run_scenarios(WanMode::Ethernet)
}

#[test]
#[ignore = "requires an isolated OpenWrt QEMU guest with PPPoE"]
fn r127_tagged_pppoe_preserves_external_publications_and_exposes_the_receive_boundary() -> TestResult
{
    run_scenarios(WanMode::Pppoe)
}

#[test]
#[ignore = "requires the isolated netifd PPPoE and DHCPv6 QEMU fixture"]
fn r128_netifd_pppoe_and_dhcpv6_reproduce_wan_routing() -> TestResult {
    run_scenarios(WanMode::ManagedPppoe)
}

#[test]
#[ignore = "requires the isolated Ethernet DHCPv4 and DHCPv6 QEMU fixture"]
fn r129_netifd_ethernet_dhcp_acquires_leases_and_routes_publications() -> TestResult {
    run_scenarios(WanMode::DhcpEthernet)
}

fn run_scenarios(mode: WanMode) -> TestResult {
    let lab = Lab::create(true)?;
    let observer = observation::start(&lab, mode.uses_pppoe())?;
    let result = scenarios(&lab, observer.as_ref(), mode);
    if let Some(observer) = observer {
        observer.finish(result.is_ok())?;
    }
    result
}

fn scenarios(lab: &Lab, observer: Option<&xtask::observe::Observer>, mode: WanMode) -> TestResult {
    let use_pppoe = mode.uses_pppoe();
    let managed = mode.uses_dhcpv6();
    topology(lab, mode)?;
    observation::phase(observer, "topology-ready")?;
    if observer.is_some() || use_pppoe {
        observation::start_capture(lab, use_pppoe)?;
    }
    let network = lab.exec(&["uci", "export", "network"], None)?;
    let dhcp = lab.exec(&["uci", "export", "dhcp"], None)?;
    lab.exec(&["/etc/init.d/tunnel-detour-inbound", "start"], None)?;
    lab.change("set tunnel-detour.inbound=inbound\nset tunnel-detour.inbound.enabled='1'\nset tunnel-detour.inbound.lan_network='lan'\nset tunnel-detour.inbound.wan_network='wan'\nset tunnel-detour.external=inbound_port\nset tunnel-detour.external.name='External laboratory origin'\nset tunnel-detour.external.enabled='1'\nset tunnel-detour.external.protocol='tcp'\nset tunnel-detour.external.access='wan_only'\nset tunnel-detour.external.public_port='18081'\nset tunnel-detour.external.destination_address='192.0.2.2'\nset tunnel-detour.external.destination_port='8080'")?;
    wait(|| {
        Ok(lab.ubus("tunnel-detour", "inbound_status", json!({}))?["status"]["applied"] == true)
    })?;
    let before = counters(lab)?;
    request(lab, Some("td-ext-client"), "external", MANAGEMENT)?;
    let management = counters(lab)?;
    assert!(
        management.wan_in > before.wan_in && management.wan_reply > before.wan_reply,
        "the independent external request did not cross WAN in both directions"
    );
    eprintln!("R124: independent external client reached the WAN /128");
    request(lab, None, "vpn", MANAGEMENT)?;
    let management_vpn = counters(lab)?;
    assert!(
        management_vpn.vpn_request > management.vpn_request
            && management_vpn.wan_in > management.wan_in
            && management_vpn.wan_reply > management.wan_reply,
        "the VPN request to the WAN /128 did not return through WAN"
    );
    eprintln!("R124: WireGuard exit returned to the WAN /128");
    observation::phase(observer, "wan-address-both-paths-verified")?;
    let external_control = if managed {
        management_vpn
    } else {
        let before_pppoe = if use_pppoe {
            Some(observation::pppoe_ingress(lab, false)?)
        } else {
            None
        };
        // Keep the older selective control: only the VPN exit is affected.
        isp_rule(lab, br#"table inet external_isp_fault {
 counter dropped_vpn_to_wan_address {}
 chain forward { type filter hook forward priority -300; policy accept;
  oifname "peer0" ip6 saddr 2001:db8:100::2 ip6 daddr 2001:db8:ff::1 tcp dport 18081 counter name dropped_vpn_to_wan_address drop
 }
}
"#)?;
        observation::phase(observer, "selective-vpn-wan-drop-installed")?;
        let before_selective = counters(lab)?;
        request(lab, None, "vpn-closed", MANAGEMENT)?;
        let selective = counters(lab)?;
        assert!(selective.vpn_request > before_selective.vpn_request);
        assert_eq!(selective.wan_ingress, before_selective.wan_ingress);
        assert_eq!(selective.wan_in, before_selective.wan_in);
        assert_eq!(selective.relay_input, before_selective.relay_input);
        assert_eq!(selective.backend_dial, before_selective.backend_dial);
        if let Some(count) = before_pppoe {
            assert_eq!(
                observation::pppoe_ingress(lab, false)?,
                count,
                "an upstream-dropped request reached the PPPoE receive interface"
            );
        }
        isp_fault_counters(lab, &["dropped_vpn_to_wan_address"])?;
        observation::phase(observer, "selective-vpn-wan-drop-observed")?;
        request(lab, Some("td-ext-client"), "external", MANAGEMENT)?;
        let external = counters(lab)?;
        assert!(
            external.ingress_external > selective.ingress_external
                && external.wan_reply > selective.wan_reply,
            "the selective fault also blocked the independent client to the WAN address"
        );
        observation::phase(observer, "selective-drop-independent-wan-control")?;
        if let Some(count) = before_pppoe {
            wait(|| Ok(observation::pppoe_ingress(lab, false)? > count))?;
        }
        external
    };

    request(lab, Some("td-ext-client"), "closed", DELEGATED)?;
    let unassigned = counters(lab)?;
    assert!(
        unassigned.wan_in > external_control.wan_in,
        "the routed delegation did not deliver its unassigned-address probe to WAN"
    );
    request(lab, None, "vpn-closed", DELEGATED)?;
    let unassigned_vpn = counters(lab)?;
    if use_pppoe {
        wait(|| Ok(observation::pppoe_ingress(lab, true)? >= 2))?;
    }
    observation::phase(observer, "delegated-unassigned-probes-observed")?;
    assert!(
        unassigned_vpn.vpn_request > unassigned.vpn_request
            && unassigned_vpn.wan_in > unassigned.wan_in,
        "the VPN probe to the unassigned delegated address did not reach WAN"
    );

    lab.exec(
        &[
            "ip",
            "-6",
            "addr",
            "add",
            "2001:db8:30:ff:5444::1/128",
            "dev",
            "tdwan0",
            "valid_lft",
            "1200",
            "preferred_lft",
            "1200",
            "noprefixroute",
            "nodad",
        ],
        None,
    )?;
    lab.exec(&["/etc/init.d/tunnel-detour-inbound", "reload"], None)?;
    wait(|| {
        let status = lab.ubus("tunnel-detour", "inbound_status", json!({}))?;
        Ok(status["status"]["applied"] == true
            && status["status"]["public_addresses"]
                .as_array()
                .is_some_and(|addresses| addresses.contains(&json!("2001:db8:30:ff:5444::1"))))
    })?;
    request(lab, Some("td-ext-client"), "external", DELEGATED)?;
    let independent = counters(lab)?;
    assert!(
        independent.wan_in > unassigned_vpn.wan_in
            && independent.wan_reply > unassigned_vpn.wan_reply,
        "the independently routed delegated request lost WAN reachability after address assignment"
    );
    request(lab, None, "vpn", DELEGATED)?;
    let vpn = counters(lab)?;
    assert!(
        vpn.vpn_request > independent.vpn_request
            && vpn.wan_in > independent.wan_in
            && vpn.wan_reply > independent.wan_reply,
        "the VPN request did not leave the tunnel and return through WAN"
    );
    assert_eq!(
        vpn.vpn_reply_leak, 0,
        "publication replies leaked into the default VPN"
    );
    eprintln!(
        "R124: both external paths reached the same delegated address after assignment; no VPN reply leak"
    );
    observation::phase(observer, "delegated-address-both-paths-verified")?;
    if managed {
        managed_wan_route_loss(lab, observer, use_pppoe)?;
    } else {
        clear_isp_fault(lab)?;
        request(lab, None, "vpn", MANAGEMENT)?;
        let recovered = counters(lab)?;
        assert!(
            recovered.vpn_request > vpn.vpn_request
                && recovered.ingress_vpn > vpn.ingress_vpn
                && recovered.wan_in > vpn.wan_in
                && recovered.wan_reply > vpn.wan_reply
                && recovered.backend_reply > vpn.backend_reply,
            "removing the selective fault did not restore the VPN path to the WAN address"
        );
        assert_eq!(recovered.vpn_reply_leak, 0);
        observation::phase(observer, "selective-vpn-wan-drop-recovered")?;
        eprintln!(
            "R124: selective upstream drop blocked only VPN return to the WAN address; independent WAN and delegated controls passed; removal restored VPN return"
        );
        let before_upstream = if use_pppoe {
            pppoe::receive_fault(lab, observer)?;
            counters(lab)?
        } else {
            recovered
        };

        // Drop in the simulated ISP before either request can enter WAN. This
        // exercises upstream loss without attributing a real provider's behavior.
        isp_rule(lab,
            br#"table inet external_isp_fault {
 counter dropped_external {}
 counter dropped_vpn {}
 chain forward { type filter hook forward priority -300; policy accept;
  oifname "peer0" ip6 saddr 2001:db8:101::2 ip6 daddr 2001:db8:30:ff:5444::1 tcp dport 18081 counter name dropped_external drop
  oifname "peer0" ip6 saddr 2001:db8:100::2 ip6 daddr 2001:db8:30:ff:5444::1 tcp dport 18081 counter name dropped_vpn drop
 }
}
"#,
    )?;
        observation::phase(observer, "isp-drop-installed")?;
        request(lab, Some("td-ext-client"), "closed", DELEGATED)?;
        request(lab, None, "vpn-closed", DELEGATED)?;
        let blocked = counters(lab)?;
        assert_eq!(
            blocked.wan_ingress, before_upstream.wan_ingress,
            "a provider-dropped request reached the router's early ingress observer"
        );
        assert_eq!(
            blocked.wan_in, before_upstream.wan_in,
            "a provider-dropped request entered WAN"
        );
        assert!(
            blocked.vpn_request > before_upstream.vpn_request,
            "the failed VPN probe never left the tunnel"
        );
        isp_fault_counters(lab, &["dropped_external", "dropped_vpn"])?;
        observation::phase(observer, "isp-drop-both-origins-observed")?;
        clear_isp_fault(lab)?;
        healthy_paths(lab, "upstream recovery", observer)?;
        eprintln!(
            "R124: upstream packet loss failed closed; both paths recovered after removing the laboratory fault"
        );
        local_faults(lab, observer)?;
    }

    // The ordinary VPN path may be chosen by policy rules rather than the main
    // default. Keep that administrator-owned policy separate from our WAN mark.
    for args in [
        vec!["wg", "set", "tdvpn0", "fwmark", "51820"],
        vec![
            "ip", "-6", "route", "add", "default", "dev", "tdvpn0", "table", "50001",
        ],
        vec![
            "ip",
            "-6",
            "rule",
            "add",
            "priority",
            "200",
            "lookup",
            "main",
            "suppress_prefixlength",
            "0",
        ],
        vec![
            "ip", "-6", "rule", "add", "priority", "201", "not", "fwmark", "51820", "lookup",
            "50001",
        ],
        vec![
            "ip",
            "-6",
            "route",
            "del",
            "default",
            "dev",
            "tdvpn0",
            "metric",
            if managed { "1024" } else { "10" },
        ],
    ] {
        lab.exec(&args, None)?;
    }
    let vpn_policy = lab.exec(&["ip", "-6", "route", "show", "table", "50001"], None)?;
    let policy_rules = || -> TestResult<Vec<serde_json::Value>> {
        let mut rules: Vec<serde_json::Value> =
            serde_json::from_slice(&lab.exec(&["ip", "-j", "-6", "rule", "show"], None)?)?;
        rules.retain(|rule| rule["priority"] == 200 || rule["priority"] == 201);
        assert_eq!(rules.len(), 2, "the independent VPN policy lost a rule");
        Ok(rules)
    };
    let vpn_rules = policy_rules()?;
    healthy_paths(lab, "separate VPN policy table", observer)?;
    lab.change("set tunnel-detour.external.access='wan_and_lan'")?;
    wait(|| {
        let status = lab.ubus("tunnel-detour", "inbound_status", json!({}))?;
        Ok(status["status"]["applied"] == true
            && status["status"]["publications"][0]["access"] == "wan_and_lan")
    })?;
    healthy_paths(lab, "LAN access enabled with separate VPN policy", observer)?;
    if observer.is_some() || use_pppoe {
        observation::finish_capture(lab, use_pppoe)?;
    }
    if let Some(observer) = observer {
        let state: serde_json::Value = serde_json::from_reader(std::fs::File::open(
            observer.directory().join("state.json"),
        )?)?;
        assert_eq!(
            state["observation"]["ok"], true,
            "native observation adapter failed"
        );
        for name in [
            "interfaces",
            "ipv6_routes",
            "ipv6_policy",
            "packet_boundaries",
            "controller_and_relay",
        ] {
            assert_eq!(
                state["observation"]["data"][name]["ok"], true,
                "required observation {name} failed or was truncated"
            );
        }
        let seconds = env::var("TUNNEL_DETOUR_LAB_HOLD_SECONDS")?.parse()?;
        observer.hold(seconds)?;
        if use_pppoe || managed {
            request(lab, None, "vpn", MANAGEMENT)?;
            healthy_paths(lab, "post-observation WAN availability", Some(observer))?;
        }
    }
    assert_eq!(lab.exec(&["uci", "export", "network"], None)?, network);
    assert_eq!(lab.exec(&["uci", "export", "dhcp"], None)?, dhcp);
    lab.change("set tunnel-detour.inbound.enabled='0'")?;
    wait(|| Ok(lab.ubus("tunnel-detour", "inbound_status", json!({}))?["running"] == false))?;
    let remaining = lab.raw(
        &["nft", "list", "table", "inet", "tunnel_detour_inbound"],
        None,
    )?;
    assert!(
        !remaining.status.success(),
        "disabled publication retained its owned table"
    );
    assert_eq!(
        lab.exec(&["ip", "-6", "route", "show", "table", "50001"], None)?,
        vpn_policy,
        "disabling the publication modified the administrator's VPN table"
    );
    assert_eq!(
        policy_rules()?,
        vpn_rules,
        "disabling the publication modified the administrator's VPN rules"
    );
    observation::phase(observer, "publication-cleanup-verified")?;
    for (_, _, pid_file) in HTTP_ORIGINS {
        let pid = fixture_pid(lab, pid_file, "uhttpd")?;
        lab.exec(&["kill", "-TERM", &pid.to_string()], None)?;
        wait_for_process_exit(lab, pid)?;
    }
    observation::phase(observer, "http-origin-cleanup-verified")?;
    if managed {
        dhcp::stop(lab, use_pppoe)?;
    }
    if use_pppoe {
        pppoe::stop(lab, managed)?;
        observation::phase(observer, "pppoe-session-cleanup-verified")?;
    } else if managed {
        observation::phase(observer, "ethernet-dhcp-cleanup-verified")?;
    }
    Ok(())
}

fn managed_wan_route_loss(
    lab: &Lab,
    observer: Option<&xtask::observe::Observer>,
    use_pppoe: bool,
) -> TestResult {
    dhcp::set_wan_host_route(lab, false)?;
    observation::phase(observer, "upstream-wan-host-route-withdrawn")?;
    let before = counters(lab)?;
    let vlan = || {
        use_pppoe
            .then(|| observation::pppoe_ingress(lab, false))
            .transpose()
    };
    let initial_vlan = vlan()?;
    request(lab, None, "vpn-closed", MANAGEMENT)?;
    let vpn = counters(lab)?;
    assert!(vpn.vpn_request > before.vpn_request);
    assert_eq!(vpn.wan_ingress, before.wan_ingress);
    assert_eq!(vpn.wan_in, before.wan_in);
    assert_eq!(vpn.relay_input, before.relay_input);
    assert_eq!(vpn.backend_dial, before.backend_dial);
    assert_eq!(vlan()?, initial_vlan);
    observation::phase(observer, "withdrawn-wan-route-vpn-probe-observed")?;
    request(lab, Some("td-ext-client"), "closed", MANAGEMENT)?;
    let external = counters(lab)?;
    assert_eq!(external.wan_ingress, vpn.wan_ingress);
    assert_eq!(external.ingress_external, vpn.ingress_external);
    assert_eq!(external.backend_dial, vpn.backend_dial);
    assert_eq!(vlan()?, initial_vlan);
    observation::phase(observer, "withdrawn-wan-route-independent-probe-observed")?;

    healthy_paths(lab, "delegated-path-without-wan-host-route", observer)?;
    dhcp::set_wan_host_route(lab, true)?;
    let before_recovery = counters(lab)?;
    request(lab, Some("td-ext-client"), "external", MANAGEMENT)?;
    request(lab, None, "vpn", MANAGEMENT)?;
    let recovered = counters(lab)?;
    assert!(recovered.ingress_external > before_recovery.ingress_external);
    assert!(recovered.ingress_vpn > before_recovery.ingress_vpn);
    assert!(recovered.vpn_request > before_recovery.vpn_request);
    assert!(recovered.backend_reply > before_recovery.backend_reply);
    assert_eq!(recovered.vpn_reply_leak, 0);
    observation::phase(observer, "upstream-wan-host-route-restored")?;
    eprintln!(
        "Withdrawing the WAN host route blocked both origins before WAN ingress; the delegated prefix worked; restoring the route recovered both exact HTTP responses"
    );
    Ok(())
}
