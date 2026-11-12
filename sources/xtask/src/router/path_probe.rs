//! Passive, bounded headers around a TCP probe to the router's own WAN address.
use super::{Router, quote, write_private};
use serde_json::{Value, json};
use std::{
    env,
    error::Error,
    fs,
    net::{Ipv6Addr, SocketAddrV6},
    path::PathBuf,
    process::Stdio,
    time::{Duration, Instant},
};
type Result<T> = std::result::Result<T, Box<dyn Error>>;

fn device(value: &str) -> Result<&str> {
    if value.is_empty()
        || value.len() > 31
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
    {
        return Err("invalid live network device".into());
    }
    Ok(value)
}

fn unused_target(prefix: Ipv6Addr, mask: u32, assigned: &[Value]) -> Result<Ipv6Addr> {
    if !(48..=64).contains(&mask) || prefix.to_bits() >> 125 != 1 {
        return Err("delegation is outside the bounded global diagnostic scope".into());
    }
    let network_mask = u128::MAX
        .checked_shl(128 - mask)
        .ok_or("invalid delegation mask")?;
    let subnet = (1u128
        .checked_shl(64 - mask)
        .ok_or("invalid delegation subnet")?
        - 1)
        << 64;
    let target = Ipv6Addr::from((prefix.to_bits() & network_mask) | subnet | 0x5444_0000_0000_0002);
    for entry in assigned
        .iter()
        .flat_map(|i| i["addr_info"].as_array().into_iter().flatten())
    {
        let address: Ipv6Addr = entry["local"]
            .as_str()
            .ok_or("assigned address missing")?
            .parse()?;
        let bits: u32 = entry["prefixlen"]
            .as_u64()
            .ok_or("assigned prefix missing")?
            .try_into()?;
        if bits > 128 {
            return Err("invalid assigned prefix".into());
        }
        let mask = if bits == 0 {
            0
        } else {
            u128::MAX
                .checked_shl(128 - bits)
                .ok_or("invalid assigned prefix")?
        };
        if target.to_bits() & mask == address.to_bits() & mask {
            return Err("diagnostic target overlaps an assigned router address or subnet".into());
        }
    }
    Ok(target)
}

pub(super) fn run(router: &Router) -> Result<()> {
    let tools = PathBuf::from(
        env::var_os("TUNNEL_DETOUR_PATH_TOOLS")
            .ok_or("missing verified extracted tool directory")?,
    );
    let probe = PathBuf::from(
        env::var_os("TUNNEL_DETOUR_VPN_PROBE").ok_or("missing target-built VPN probe")?,
    );
    let observer = PathBuf::from(
        env::var_os("TUNNEL_DETOUR_PACKET_OBSERVER")
            .ok_or("missing target-built passive observer")?,
    );
    let name = router
        .directory
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or("invalid private run directory")?;
    device(name)?;
    let remote = format!("/tmp/tunnel-detour-path-{name}");
    let interfaces: Value = serde_json::from_slice(
        &router.capture("probe-interfaces", "ubus -S call network.interface dump\n")?,
    )?;
    let interfaces = interfaces["interface"]
        .as_array()
        .ok_or("missing live interface inventory")?;
    let wan =
        String::from_utf8(router.secret_output("uci -q get tunnel-detour.globals.wan_network\n")?)?;
    let wan = device(wan.trim())?;
    let wan = interfaces
        .iter()
        .find(|i| i["interface"] == wan && i["up"] == true)
        .and_then(|i| i["l3_device"].as_str())
        .ok_or("selected WAN is not live")?;
    device(wan)?;
    let vpns = interfaces
        .iter()
        .filter(|i| i["proto"] == "wireguard" && i["up"] == true)
        .filter_map(|i| i["l3_device"].as_str())
        .collect::<std::collections::BTreeSet<_>>();
    let vpn = match vpns.iter().copied().collect::<Vec<_>>().as_slice() {
        [vpn] => vpn.to_string(),
        _ => return Err("expected exactly one live WireGuard device".into()),
    };
    device(&vpn)?;
    let assigned: Vec<Value> =
        serde_json::from_slice(&router.capture("probe-addresses", "ip -json -6 address show\n")?)?;
    let addresses = |interface: &str, global: bool| -> Result<Vec<Ipv6Addr>> {
        let mut found = Vec::new();
        for info in assigned
            .iter()
            .filter(|i| i["ifname"] == interface)
            .flat_map(|i| i["addr_info"].as_array().into_iter().flatten())
        {
            if info["family"] != "inet6"
                || info["scope"] != "global"
                || info["temporary"] == true
                || info["tentative"] == true
                || info["dadfailed"] == true
                || info["deprecated"] == true
                || info["preferred_life_time"].as_u64() == Some(0)
            {
                continue;
            }
            let ip: Ipv6Addr = info["local"]
                .as_str()
                .ok_or("missing assigned address")?
                .parse()?;
            if !ip.is_unspecified()
                && !ip.is_multicast()
                && !ip.is_loopback()
                && !ip.is_unicast_link_local()
                && (!global || ip.to_bits() >> 125 == 1)
            {
                found.push(ip);
            }
        }
        found.sort();
        found.dedup();
        Ok(found)
    };
    let wan_addresses = addresses(wan, true)?;
    let vpn_addresses = addresses(&vpn, false)?;
    let [target] = wan_addresses.as_slice() else {
        return Err(
            "select a WAN with exactly one preferred global address for this diagnostic".into(),
        );
    };
    let delegated = env::var_os("TUNNEL_DETOUR_PROBE_DELEGATED").is_some();
    let target = if delegated {
        let prefixes = interfaces
            .iter()
            .filter(|i| i["up"] == true && i["l3_device"] == wan)
            .flat_map(|i| i["ipv6-prefix"].as_array().into_iter().flatten())
            .collect::<Vec<_>>();
        let [prefix] = prefixes.as_slice() else {
            return Err("expected exactly one live WAN delegation".into());
        };
        unused_target(
            prefix["address"]
                .as_str()
                .ok_or("delegation address missing")?
                .parse()?,
            prefix["mask"]
                .as_u64()
                .ok_or("delegation mask missing")?
                .try_into()?,
            &assigned,
        )?
    } else {
        *target
    };
    let [source] = vpn_addresses.as_slice() else {
        return Err("expected exactly one preferred VPN IPv6 source".into());
    };
    let listeners = String::from_utf8(router.capture("probe-listeners", "netstat -lnt\n")?)?;
    if listeners
        .lines()
        .filter_map(|s| s.split_whitespace().nth(3))
        .any(|s| s.rsplit_once(':').is_some_and(|(_, p)| p == "18081"))
    {
        return Err("diagnostic TCP port is occupied; no probe or capture started".into());
    }
    let before = router.capture(
        "probe-config-before",
        "sha256sum /etc/config/network /etc/config/firewall /etc/config/tunnel-detour\n",
    )?;
    router.capture(
        "probe-stage-create",
        &format!(
            "set -eu\numask 077\nmkdir -m 700 {}\nprintf '%s\\n' tunnel-detour-path-v1 > {}/owner\n",
            quote(&remote),
            quote(&remote)
        ),
    )?;
    let result = (|| -> Result<()> {
        for (local, name) in [
            (tools.join("usr/bin/tcpdump"), "tcpdump"),
            (tools.join("usr/lib/libpcap.so.1.10.6"), "libpcap.so.1.10.6"),
            (probe, "vpn-probe"),
            (observer, "packet-observer"),
        ] {
            router.upload(&local, &format!("{remote}/{name}"))?;
        }
        router.capture("probe-stage-ready",&format!("set -eu\nln -s libpcap.so.1.10.6 {r}/libpcap.so.1\nchmod 700 {r}/tcpdump {r}/vpn-probe {r}/packet-observer\nLD_LIBRARY_PATH={r} {r}/tcpdump --version\n",r=quote(&remote)))?;
        let mut child = router
            .ssh()?
            .arg(&router.host)
            .arg(format!(
                "exec {r}/packet-observer {r}/tcpdump {r} {target} 18081 45 {r}/capture",
                r = quote(&remote)
            ))
            .stdin(Stdio::null())
            .stdout(write_private_file(router, "capture-supervisor.stdout")?)
            .stderr(write_private_file(router, "capture-supervisor.stderr")?)
            .spawn()?;
        let measurement = (|| -> Result<()> {
            let deadline = Instant::now() + Duration::from_secs(8);
            loop {
                if let Some(status) = child.try_wait()? {
                    return Err(
                        format!("passive observer exited before readiness: {status}").into(),
                    );
                }
                if router
                    .capture(
                        "probe-capture-ready",
                        &format!("test -f {}/capture/ready\n", quote(&remote)),
                    )
                    .is_ok()
                {
                    break;
                }
                if Instant::now() >= deadline {
                    return Err("passive capture readiness expired".into());
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            let endpoint = SocketAddrV6::new(target, 18081, 0, 0);
            router.capture(
                "probe-wg-link-before",
                &format!("ip -json -statistics link show dev {}\n", quote(&vpn)),
            )?;
            router.capture("probe-wg-transfer-before", "wg show all transfer\n")?;
            router.capture("probe-wg-allowed-ips", "wg show all allowed-ips\n")?;
            let response=router.capture("probe-tcp",&format!("{r}/vpn-probe --tcp {endpoint} {vpn} {source}\nresult=$?\nprintf 'PROBE_EXIT=%s\\n' \"$result\"\nexit 0\n",r=quote(&remote),vpn=quote(&vpn)))?;
            router.capture(
                "probe-wg-link-after",
                &format!("ip -json -statistics link show dev {}\n", quote(&vpn)),
            )?;
            router.capture("probe-wg-transfer-after", "wg show all transfer\n")?;
            write_private(
                &router.directory.join("probe-scope.json"),
                &serde_json::to_vec(
                    &json!({"target":endpoint,"unused_delegated_target":delegated,"vpn_device":vpn,"vpn_source":source,"wan_device":wan,"passive_capture":true,"headers_only":true}),
                )?,
            )?;
            let text = String::from_utf8(response)?;
            let code: u8 = text
                .lines()
                .find_map(|line| line.strip_prefix("PROBE_EXIT="))
                .ok_or("TCP probe status missing")?
                .parse()?;
            println!(
                "{}",
                json!({"tcp_connected":code==0,"probe_exit":code,"unused_delegated_target":delegated,"capture_scope":"own WAN or unused delegation; diagnostic port only"})
            );
            Ok(())
        })();
        let stop = router.capture(
            "probe-capture-stop",
            &format!("touch {}/capture/stop\n", quote(&remote)),
        );
        let deadline = Instant::now() + Duration::from_secs(50);
        let status = loop {
            if let Some(status) = child.try_wait()? {
                break status;
            }
            if Instant::now() >= deadline {
                child.kill()?;
                child.wait()?;
                return Err("capture SSH completion expired; the remote supervisor has a 45-second lifetime".into());
            }
            std::thread::sleep(Duration::from_millis(100));
        };
        stop?;
        if !status.success() {
            return Err("passive observer failed; inspect private supervisor output".into());
        }
        router.capture(
            "probe-headers",
            &format!("cat {r}/capture/headers.txt\n", r = quote(&remote)),
        )?;
        router.capture(
            "probe-capture-details",
            &format!(
                "cat {r}/capture/capture.stderr {r}/capture/finished\n",
                r = quote(&remote)
            ),
        )?;
        measurement
    })();
    let cleanup=router.capture("probe-cleanup",&format!("set -eu\ntest \"$(cat {r}/owner)\" = tunnel-detour-path-v1\nrm -f {r}/tcpdump {r}/libpcap.so.1 {r}/libpcap.so.1.10.6 {r}/vpn-probe {r}/packet-observer\nif test -d {r}/capture; then rm -f {r}/capture/headers.txt {r}/capture/capture.stderr {r}/capture/ready {r}/capture/finished {r}/capture/stop; rmdir {r}/capture; fi\nrm {r}/owner\nrmdir {r}\n",r=quote(&remote)));
    let after = router.capture(
        "probe-config-after",
        "sha256sum /etc/config/network /etc/config/firewall /etc/config/tunnel-detour\n",
    )?;
    if before != after {
        return Err(
            "configuration changed during the passive diagnostic; inspect private records".into(),
        );
    }
    router.management("passive-probe-management")?;
    match (result, cleanup) {
        (Err(primary), Err(cleanup)) => {
            return Err(format!(
                "passive diagnostic failed: {primary}; cleanup also failed: {cleanup}"
            )
            .into());
        }
        (Err(error), Ok(_)) | (Ok(_), Err(error)) => return Err(error),
        (Ok(_), Ok(_)) => {}
    }
    println!(
        "Passive SYN-header diagnostic finished; temporary tools removed and persistent configuration unchanged."
    );
    Ok(())
}

fn write_private_file(router: &Router, name: &str) -> Result<fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    Ok(fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(router.directory.join(name))?)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn r126_delegated_probe_stays_in_its_live_prefix_and_refuses_assigned_subnets() -> Result<()> {
        let target = unused_target("2001:db8:1200::".parse()?, 56, &[])?;
        assert_eq!(target, "2001:db8:1200:ff:5444::2".parse::<Ipv6Addr>()?);
        for (address, bits) in [
            ("2001:db8:1200:ff:5444::2", 128),
            ("2001:db8:1200:ff::1", 64),
            ("2001:db8:1200::1", 56),
        ] {
            assert!(
                unused_target(
                    "2001:db8:1200::".parse()?,
                    56,
                    &[json!({"addr_info":[{"local":address,"prefixlen":bits}]})]
                )
                .is_err()
            );
        }
        for (prefix, mask) in [("fd00:1234::", 56), ("2001:db8::", 47), ("2001:db8::", 65)] {
            assert!(unused_target(prefix.parse()?, mask, &[]).is_err());
        }
        Ok(())
    }
}
