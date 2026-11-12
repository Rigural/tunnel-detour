//! Synthetic WAN address and prefix assignment for the managed laboratory profiles.

use super::{
    Lab, MANAGED_ISP_ADDRESS, MANAGED_WAN_ADDRESS, TEST, TestResult, checked, fixture_pid,
    wait_for_process_exit,
};
use crate::wait_for;
use serde_json::{Value, json};
use std::{net::SocketAddrV6, thread, time::Duration};

pub(super) const DHCP6_CONFIG: &str = "/tmp/inbound-test/kea-dhcp6.json";
const PID: &str = "/tmp/inbound-test/kea-dhcp6.pid";
pub(super) const DHCP4_PID: &str = "/tmp/inbound-test/wan-dhcp4.pid";
pub(super) const DHCP4_LOG: &str = "/tmp/inbound-test/wan-dhcp4.log";

fn start_ethernet(lab: &Lab) -> TestResult {
    lab.exec(
        &[
            "ip",
            "-n",
            "td-in-wan",
            "-4",
            "addr",
            "del",
            "203.0.113.2/24",
            "dev",
            "peer0",
        ],
        None,
    )?;
    lab.exec(
        &[
            "ip",
            "-n",
            "td-in-wan",
            "-4",
            "addr",
            "add",
            &format!("{MANAGED_ISP_ADDRESS}/24"),
            "dev",
            "peer0",
        ],
        None,
    )?;
    // This instance serves only DHCPv4 on the simulated ISP link. Its DNS
    // listener and DNS option are disabled independently of the LAN frontend.
    lab.exec(
        &[
            "ip",
            "netns",
            "exec",
            "td-in-wan",
            "start-stop-daemon",
            "-S",
            "-b",
            "-m",
            "-O",
            DHCP4_LOG,
            "-p",
            DHCP4_PID,
            "-x",
            "/usr/sbin/dnsmasq",
            "--",
            "--keep-in-foreground",
            "--conf-file=/dev/null",
            "--pid-file=",
            "--port=0",
            "--interface=peer0",
            "--bind-interfaces",
            "--user=root",
            "--dhcp-authoritative",
            &format!("--dhcp-range={MANAGED_WAN_ADDRESS},{MANAGED_WAN_ADDRESS},255.255.255.0,20m"),
            &format!("--dhcp-option=option:router,{MANAGED_ISP_ADDRESS}"),
            "--dhcp-option=option:dns-server",
            "--dhcp-leasefile=/tmp/inbound-test/wan-dhcp4.leases",
            "--log-dhcp",
            "--log-facility=-",
        ],
        None,
    )?;
    lab.exec(
        &["uci", "batch"],
        Some(
            br"set network.lan.ip6addr='fd00:1234::1/64'
set network.wan.proto='dhcp'
set network.wan.peerdns='0'
set network.wan.defaultroute='0'
delete network.wan.ipaddr
delete network.wan.netmask
set network.wan6=interface
set network.wan6.proto='dhcpv6'
set network.wan6.device='tdwan0'
set network.wan6.auto='0'
set network.wan6.reqaddress='force'
set network.wan6.reqprefix='56'
set network.wan6.peerdns='0'
set network.wan6.metric='512'
commit network
set firewall.lab_dhcp4=rule
set firewall.lab_dhcp4.name='Allow-Lab-DHCPv4'
set firewall.lab_dhcp4.src='wan'
set firewall.lab_dhcp4.family='ipv4'
set firewall.lab_dhcp4.proto='udp'
set firewall.lab_dhcp4.src_port='67'
set firewall.lab_dhcp4.dest_port='68'
set firewall.lab_dhcp4.target='ACCEPT'
commit firewall
",
        ),
    )?;
    lab.exec(&["fw4", "reload"], None)?;
    lab.exec(&["ubus", "call", "network", "reload", "{}"], None)?;
    Ok(())
}

fn start_ethernet_ipv6(lab: &Lab) -> TestResult {
    // Configure after DHCPv4 brings up the device. Switching the network
    // protocol can clear manually added addresses during netifd reload.
    for (prefix, device, address) in [
        (["ip"].as_slice(), "tdwan0", "fe80::1/64"),
        (&["ip", "-n", "td-in-wan"], "peer0", "fe80::2/64"),
    ] {
        for args in [
            ["link", "set", "dev", device, "addrgenmode", "none"].as_slice(),
            &["-6", "addr", "flush", "dev", device, "scope", "link"],
            &["-6", "addr", "add", address, "dev", device, "nodad"],
        ] {
            lab.exec(&[prefix, args].concat(), None)?;
        }
    }
    lab.exec(&["ifup", "wan6"], None)?;
    Ok(())
}

fn prepare_ppp_peer(lab: &Lab) -> TestResult {
    // Kea enumerates the peer address of a PPP point-to-point record as if it
    // were local. Normalize the simulated ISP's side for its DHCPv6 socket.
    // The OpenWrt client keeps the address and peer negotiated by IPv6CP.
    for args in [
        [
            "ip",
            "-n",
            "td-in-wan",
            "-6",
            "address",
            "del",
            "fe80::2",
            "peer",
            "fe80::1/128",
            "dev",
            "peer0",
        ]
        .as_slice(),
        &[
            "ip",
            "-n",
            "td-in-wan",
            "-6",
            "address",
            "add",
            "fe80::2/64",
            "dev",
            "peer0",
            "nodad",
        ],
        &[
            "ip",
            "-n",
            "td-in-wan",
            "-6",
            "route",
            "replace",
            "fe80::1/128",
            "dev",
            "peer0",
        ],
    ] {
        lab.exec(args, None)?;
    }
    Ok(())
}

pub(super) fn start(lab: &Lab, pppoe: bool) -> TestResult {
    // Mirror OpenWrt's DHCPv6 client input allowance on this WAN only.
    lab.exec(
        &["uci", "batch"],
        Some(
            br"set firewall.lab_dhcp6=rule
set firewall.lab_dhcp6.name='Allow-Lab-DHCPv6'
set firewall.lab_dhcp6.src='wan'
set firewall.lab_dhcp6.family='ipv6'
set firewall.lab_dhcp6.proto='udp'
set firewall.lab_dhcp6.src_ip='fe80::2'
set firewall.lab_dhcp6.src_port='547'
set firewall.lab_dhcp6.dest_port='546'
set firewall.lab_dhcp6.target='ACCEPT'
commit firewall
",
        ),
    )?;
    if pppoe {
        lab.exec(&["fw4", "reload"], None)?;
        prepare_ppp_peer(lab)?;
    } else {
        start_ethernet(lab)?;
    }
    let protocol = if pppoe { "pppoe" } else { "dhcp" };
    wait_for(Duration::from_secs(15), || {
        let status = lab.ubus("network.interface.wan", "status", json!({}))?;
        Ok(status["up"] == true
            && status["proto"] == protocol
            && status["ipv4-address"].as_array().is_some_and(|items| {
                items
                    .iter()
                    .any(|item| item["address"] == MANAGED_WAN_ADDRESS)
            }))
    })
    .map_err(|error| format!("native {protocol} did not acquire the WAN IPv4 address: {error}"))?;
    if !pppoe {
        start_ethernet_ipv6(lab)?;
    }
    let config = serde_json::to_vec(&json!({
        "Dhcp6": {
            "interfaces-config": {"interfaces": ["peer0"]},
            "lease-database": {"type": "memfile", "persist": false},
            "preferred-lifetime": 1200,
            "valid-lifetime": 1800,
            "renew-timer": 1200,
            "rebind-timer": 1500,
            "subnet6": [{
                "id": 1,
                "interface": "peer0",
                "subnet": "2001:db8:ff::/64",
                "pools": [{"pool": "2001:db8:ff::1 - 2001:db8:ff::1"}],
                "pd-pools": [{"prefix": "2001:db8:30::", "prefix-len": 56, "delegated-len": 56}]
            }],
            "loggers": [{"name": "kea-dhcp6", "output_options": [{"output": "stdout"}], "severity": "INFO"}]
        }
    }))?;
    lab.exec(&["tee", DHCP6_CONFIG], Some(&config))?;
    lab.exec(
        &[
            "ip",
            "netns",
            "exec",
            "td-in-wan",
            "env",
            "KEA_DHCP_DATA_DIR=/tmp/inbound-test",
            "KEA_PIDFILE_DIR=/tmp/inbound-test",
            "KEA_LOCKFILE_DIR=/tmp/inbound-test",
            "kea-dhcp6",
            "-t",
            DHCP6_CONFIG,
        ],
        None,
    )?;
    lab.exec(
        &[
            "ip",
            "netns",
            "exec",
            "td-in-wan",
            "env",
            "KEA_DHCP_DATA_DIR=/tmp/inbound-test",
            "KEA_PIDFILE_DIR=/tmp/inbound-test",
            "KEA_LOCKFILE_DIR=/tmp/inbound-test",
            "start-stop-daemon",
            "-S",
            "-b",
            "-m",
            "-O",
            "/tmp/inbound-test/kea.log",
            "-p",
            PID,
            "-x",
            "/usr/sbin/kea-dhcp6",
            "--",
            "-c",
            DHCP6_CONFIG,
        ],
        None,
    )?;
    lab.background.borrow_mut().push(
        lab.background_command(&[
            "ip",
            "netns",
            "exec",
            "td-in-wan",
            "env",
            "TUNNEL_DETOUR_EXTERNAL_PROBE=router-advertisement",
            "/usr/libexec/tunnel-detour-test-fixture",
            "--ignored",
            "--exact",
            TEST,
            "--nocapture",
        ])?
        .spawn()?,
    );
    let ipv6_interface = if pppoe {
        "network.interface.wan_6"
    } else {
        "network.interface.wan6"
    };
    wait_for(Duration::from_secs(45), || {
        let status = lab.raw(
            &["ubus", "-S", "call", ipv6_interface, "status", "{}"],
            None,
        )?;
        if !status.status.success() {
            return Ok(false);
        }
        let status: Value = serde_json::from_slice(&status.stdout)?;
        let matching = |field: &str, address: &str, mask: u64| {
            status[field].as_array().is_some_and(|items| {
                items
                    .iter()
                    .any(|item| item["address"] == address && item["mask"] == mask)
            })
        };
        Ok(status["up"] == true
            && status["proto"] == "dhcpv6"
            && matching("ipv6-address", "2001:db8:ff::1", 128)
            && matching("ipv6-prefix", "2001:db8:30::", 56)
            && status["route"].as_array().is_some_and(|items| {
                ["2001:db8:ff::1/128", "2001:db8:30::/56"]
                    .iter()
                    .all(|source| {
                        items.iter().any(|item| {
                            item["target"] == "::"
                                && item["mask"] == 0
                                && item["nexthop"] == "fe80::2"
                                && item["source"] == *source
                                && item["metric"] == 512
                        })
                    })
            }))
    })
    .map_err(|error| {
        let diagnostics = lab.raw(&["cat", "/tmp/inbound-test/kea.log"], None);
        format!(
            "native DHCPv6 did not acquire the WAN address, delegation and RA route: {error}; {}",
            diagnostics
                .as_ref()
                .map(|o| String::from_utf8_lossy(&o.stdout))
                .unwrap_or_default()
        )
    })?;
    eprintln!(
        "Managed WAN ({protocol}): netifd acquired IPv4, DHCPv6 IA_NA /128, IA_PD /56 and source-specific RA defaults"
    );
    Ok(())
}

/// Advertise the isolated PPP peer as a router while odhcp6c acquires its leases.
pub(super) fn advertise_router() -> TestResult {
    let link = checked("ip", &["-j", "link", "show", "dev", "peer0"], None)?;
    let link: Value = serde_json::from_slice(&link)?;
    let index: u32 = link[0]["ifindex"]
        .as_u64()
        .ok_or("missing ISP peer interface index")?
        .try_into()?;
    let socket = socket2::Socket::new(
        socket2::Domain::IPV6,
        socket2::Type::RAW,
        Some(socket2::Protocol::ICMPV6),
    )?;
    socket.set_multicast_if_v6(index)?;
    socket.set_multicast_hops_v6(255)?;
    socket.bind(&SocketAddrV6::new("fe80::2".parse()?, 0, 0, index).into())?;
    let destination = SocketAddrV6::new("ff02::1".parse()?, 0, 0, index).into();
    // ICMPv6 Router Advertisement with the managed flag and a 1,200-second router lifetime.
    let frame = [134, 0, 0, 0, 64, 0x80, 0x04, 0xb0, 0, 0, 0, 0, 0, 0, 0, 0];
    for _ in 0..12 {
        if socket.send_to(&frame, &destination)? != frame.len() {
            return Err("short synthetic Router Advertisement".into());
        }
        thread::sleep(Duration::from_secs(1));
    }
    Ok(())
}

pub(super) fn stop(lab: &Lab, pppoe: bool) -> TestResult {
    if !pppoe {
        for interface in ["wan6", "wan"] {
            lab.exec(&["ifdown", interface], None)?;
            wait_for(Duration::from_secs(10), || {
                let status = lab.ubus(
                    &format!("network.interface.{interface}"),
                    "status",
                    json!({}),
                )?;
                Ok(status["up"] == false && status["pending"] == false)
            })?;
        }
        let pid = fixture_pid(lab, DHCP4_PID, "dnsmasq")?;
        lab.exec(&["kill", "-TERM", &pid.to_string()], None)?;
        wait_for_process_exit(lab, pid)?;
    }
    let pid = fixture_pid(lab, PID, "kea-dhcp6")?;
    lab.exec(&["kill", "-TERM", &pid.to_string()], None)?;
    wait_for_process_exit(lab, pid)
}

/// Change only the synthetic upstream's route for the individually assigned WAN address.
pub(super) fn set_wan_host_route(lab: &Lab, installed: bool) -> TestResult {
    lab.exec(
        &[
            "ip",
            "-n",
            "td-in-wan",
            "-6",
            "route",
            if installed { "replace" } else { "del" },
            "2001:db8:ff::1/128",
            "via",
            "fe80::1",
            "dev",
            "peer0",
        ],
        None,
    )?;
    let lookup = |address: &str| {
        lab.raw(
            &["ip", "-n", "td-in-wan", "-j", "-6", "route", "get", address],
            None,
        )
    };
    let own = lookup("2001:db8:ff::1")?;
    assert_eq!(
        own.status.success(),
        installed,
        "synthetic upstream WAN host route has the wrong reachability"
    );
    let delegated = lookup("2001:db8:30:ff:5444::1")?;
    assert!(
        delegated.status.success(),
        "WAN host route change also withdrew the delegated prefix"
    );
    let route: Value = serde_json::from_slice(&delegated.stdout)?;
    assert_eq!(route[0]["dev"], "peer0");
    assert_eq!(route[0]["gateway"], "fe80::1");
    Ok(())
}
