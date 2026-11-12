//! The simulated ISP and router negotiate PPPoE over an isolated tagged link.

use super::{
    Lab, MANAGED_ISP_ADDRESS, MANAGED_WAN_ADDRESS, MANAGEMENT, TestResult, counters, fixture_pid,
    observation, request, wait, wait_for_process_exit,
};
use crate::wait_for;
use std::time::Duration;

pub(super) const UNDERLAY: &str = "tdeth0.217";
const CONCENTRATOR_PID: &str = "/tmp/inbound-test/pppoe-concentrator.pid";
const CLIENT_PID: &str = "/var/run/pppd/tdwan0.pid";
const PEER_PID: &str = "/var/run/pppd/peer0.pid";

pub(super) fn replace_wan(lab: &Lab, managed: bool) -> TestResult {
    if lab.vm.is_none() {
        return Err("the PPPoE scenario requires the pinned OpenWrt kernel in QEMU".into());
    }
    for args in [
        vec!["ip", "link", "set", "tdwan0", "down"],
        vec!["ip", "link", "set", "tdwan0", "name", "tdeth0"],
        vec!["ip", "-n", "td-in-wan", "link", "set", "peer0", "down"],
        vec![
            "ip",
            "-n",
            "td-in-wan",
            "link",
            "set",
            "peer0",
            "name",
            "tdpeer",
        ],
        vec!["ip", "-n", "td-in-wan", "addr", "flush", "dev", "tdpeer"],
        vec!["ip", "addr", "flush", "dev", "tdeth0"],
        vec!["ip", "link", "set", "tdeth0", "up"],
        vec!["ip", "-n", "td-in-wan", "link", "set", "tdpeer", "up"],
        vec![
            "ip", "link", "add", "link", "tdeth0", "name", UNDERLAY, "type", "vlan", "id", "217",
        ],
        vec![
            "ip",
            "-n",
            "td-in-wan",
            "link",
            "add",
            "link",
            "tdpeer",
            "name",
            "tdpeer.217",
            "type",
            "vlan",
            "id",
            "217",
        ],
        vec!["ip", "link", "set", UNDERLAY, "up"],
        vec!["ip", "-n", "td-in-wan", "link", "set", "tdpeer.217", "up"],
    ] {
        lab.exec(&args, None)?;
    }
    let options = "/tmp/inbound-test/pppoe-server-options";
    lab.exec(
        &["tee", options],
        Some(b"noauth\n+ipv6\nipv6 ::2,::1\nifname peer0\nlogfile /tmp/inbound-test/pppoe-server.log\n"),
    )?;
    // The guest owns both daemons. Detach from the bounded SSH command so the
    // link remains available for the full interactive observation hold.
    let (peer, router) = if managed {
        (MANAGED_ISP_ADDRESS, MANAGED_WAN_ADDRESS)
    } else {
        ("203.0.113.2", "203.0.113.1")
    };
    lab.exec(
        &[
            "ip",
            "netns",
            "exec",
            "td-in-wan",
            "/usr/sbin/pppoe-server",
            "-k",
            "-I",
            "tdpeer.217",
            "-L",
            peer,
            "-R",
            router,
            "-N",
            "1",
            "-O",
            options,
            "-X",
            CONCENTRATOR_PID,
        ],
        None,
    )?;
    if managed {
        lab.exec(&["uci", "batch"], Some(b"set network.wan.proto='pppoe'\nset network.wan.device='tdeth0.217'\nset network.wan.pppname='tdwan0'\nset network.wan.ipv6='auto'\nset network.wan.reqprefix='56'\nset network.wan.peerdns='0'\nset network.wan.defaultroute='0'\nset network.wan.pppd_options='noauth ipv6 ::1,::2 logfile /tmp/inbound-test/pppoe-router.log'\ndelete network.wan.ipaddr\ndelete network.wan.netmask\nset network.lan.ip6addr='fd00:1234::1/64'\ncommit network\n"))?;
        lab.exec(&["ubus", "call", "network", "reload", "{}"], None)?;
    } else {
        lab.exec(
            &[
                "/usr/sbin/pppd",
                "updetach",
                "noauth",
                "maxfail",
                "1",
                "plugin",
                "pppoe.so",
                "nic-tdeth0.217",
                "ifname",
                "tdwan0",
                "203.0.113.1:203.0.113.2",
                "+ipv6",
                "ipv6",
                "::1,::2",
                "logfile",
                "/tmp/inbound-test/pppoe-router.log",
            ],
            None,
        )?;
    }
    wait_for(Duration::from_secs(35), || {
        for (prefix, expected) in [
            (
                &["ip", "-j", "-6", "addr", "show", "dev", "tdwan0"][..],
                "fe80::1",
            ),
            (
                &[
                    "ip",
                    "-n",
                    "td-in-wan",
                    "-j",
                    "-6",
                    "addr",
                    "show",
                    "dev",
                    "peer0",
                ][..],
                "fe80::2",
            ),
        ] {
            let output = lab.raw(prefix, None)?;
            if !output.status.success() {
                return Ok(false);
            }
            let interfaces: serde_json::Value = serde_json::from_slice(&output.stdout)?;
            if !interfaces[0]["addr_info"]
                .as_array()
                .is_some_and(|addresses| {
                    addresses.iter().any(|address| address["local"] == expected)
                })
            {
                return Ok(false);
            }
        }
        Ok(true)
    })
    .map_err(|error| {
        let logs = lab.raw(
            &[
                "cat",
                "/tmp/inbound-test/pppoe-server.log",
                "/tmp/inbound-test/pppoe-router.log",
            ],
            None,
        );
        format!(
            "PPPoE IPv6CP did not complete: {error}; {}",
            logs.as_ref()
                .map(|o| String::from_utf8_lossy(&o.stdout))
                .unwrap_or_default()
        )
    })?;
    let link = lab.exec(&["ip", "-details", "-json", "link", "show", "tdwan0"], None)?;
    let link: serde_json::Value = serde_json::from_slice(&link)?;
    assert_eq!(link[0]["link_type"], "ppp", "the selected WAN is not PPP");
    eprintln!("R127: negotiated a real PPPoE session over the laboratory VLAN");
    Ok(())
}

pub(super) fn stop(lab: &Lab, managed: bool) -> TestResult {
    let client = fixture_pid(lab, CLIENT_PID, "pppd")?;
    let peer = fixture_pid(lab, PEER_PID, "pppd")?;
    let concentrator = fixture_pid(lab, CONCENTRATOR_PID, "pppoe-server")?;
    if managed {
        lab.exec(&["ifdown", "wan"], None)?;
    } else {
        lab.exec(&["kill", "-TERM", &client.to_string()], None)?;
    }
    lab.exec(&["kill", "-TERM", &concentrator.to_string()], None)?;
    for pid in [client, peer, concentrator] {
        wait_for_process_exit(lab, pid)?;
    }
    Ok(())
}

pub(super) fn receive_fault(lab: &Lab, observer: Option<&xtask::observe::Observer>) -> TestResult {
    let frames = observation::pppoe_ingress(lab, false)?;
    let before = counters(lab)?;
    // The VLAN interface presents an Ethernet header without the VLAN tag.
    // Match PPPoE, PPP IPv6, the IPv6 next header and destination, then TCP port.
    lab.exec(&["nft", "-f", "-"], Some(br#"table netdev external_pppoe_fault {
 counter discarded_before_ppp {}
 chain receive { type filter hook ingress device "tdeth0.217" priority -500; policy accept;
  ether type 0x8864 @ll,160,16 0x0057 @ll,224,8 6 @ll,368,128 0x20010db800ff00000000000000000001 @ll,512,16 18081 counter name discarded_before_ppp drop
 }
}
"#))?;
    observation::phase(observer, "pppoe-receive-drop-installed")?;
    request(lab, None, "vpn-closed", MANAGEMENT)?;
    wait(|| Ok(observation::pppoe_ingress(lab, false)? > frames))?;
    let blocked = counters(lab)?;
    assert!(blocked.vpn_request > before.vpn_request);
    assert_eq!(blocked.wan_ingress, before.wan_ingress);
    assert_eq!(blocked.wan_in, before.wan_in);
    assert_eq!(blocked.relay_input, before.relay_input);
    assert_eq!(blocked.backend_dial, before.backend_dial);
    let table = lab.exec(
        &[
            "nft",
            "-j",
            "list",
            "counter",
            "netdev",
            "external_pppoe_fault",
            "discarded_before_ppp",
        ],
        None,
    )?;
    let table: serde_json::Value = serde_json::from_slice(&table)?;
    assert!(
        table["nftables"]
            .as_array()
            .is_some_and(|entries| entries.iter().any(|entry| {
                entry["counter"]["name"] == "discarded_before_ppp"
                    && entry["counter"]["packets"]
                        .as_u64()
                        .is_some_and(|count| count > 0)
            })),
        "the PPPoE ingress rule did not count the dropped frames"
    );
    observation::phase(observer, "pppoe-receive-drop-observed")?;
    lab.exec(
        &["nft", "delete", "table", "netdev", "external_pppoe_fault"],
        None,
    )?;
    request(lab, None, "vpn", MANAGEMENT)?;
    let recovered = counters(lab)?;
    assert!(
        recovered.wan_ingress > blocked.wan_ingress
            && recovered.backend_reply > blocked.backend_reply
    );
    observation::phase(observer, "pppoe-receive-drop-recovered")?;
    eprintln!(
        "R127: PPPoE receive drop was visible on the VLAN but absent after decapsulation; removing it restored the publication"
    );
    Ok(())
}
