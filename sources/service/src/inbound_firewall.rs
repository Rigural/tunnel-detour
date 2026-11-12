//! Derived native firewall4 redirects. The inbound list remains the configuration authority.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::{InboundConfig, ServiceError, inbound_kernel::Admissions, kernel};

pub(crate) type Sections = BTreeMap<String, Value>;

fn insert_section(sections: &mut Sections, name: String, value: Value) -> Result<(), ServiceError> {
    if sections.len() >= 256 {
        return Err(ServiceError::Busy);
    }
    sections.insert(name, value);
    Ok(())
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct FirewallSnapshot {
    pub(crate) values: Sections,
}

pub(crate) async fn snapshot() -> Result<FirewallSnapshot, ServiceError> {
    let output = kernel::command_with_limit(
        "ubus",
        &[
            "-S".into(),
            "call".into(),
            "uci".into(),
            "get".into(),
            "{\"config\":\"firewall\"}".into(),
        ],
        None,
        2 * 1024 * 1024,
    )
    .await?;
    if !output.success {
        return Err(ServiceError::KernelConflict);
    }
    let mut snapshot: FirewallSnapshot = serde_json::from_slice(&output.stdout)?;
    for section in snapshot.values.values_mut() {
        let section = section
            .as_object_mut()
            .ok_or(ServiceError::KernelConflict)?;
        section.retain(|key, _| !key.starts_with('.') || key == ".type");
    }
    Ok(snapshot)
}

pub(crate) fn desired(
    config: &InboundConfig,
    admissions: &Admissions,
) -> Result<Sections, ServiceError> {
    let mut sections = Sections::new();
    for rule in config.rules.rules().iter().filter(|rule| rule.enabled()) {
        let Some(generation) = admissions.get(rule.id()) else {
            continue;
        };
        if *generation == 0 {
            return Err(ServiceError::KernelConflict);
        }
        let relay = rule.destination().requires_relay();
        for (index, address) in config.wan.addresses.iter().enumerate() {
            // Bound the total UCI footprint independently of the publication count.
            if sections.len() >= 256 {
                return Err(ServiceError::Busy);
            }
            let name = format!("td_in_{}_{index}", rule.id().as_str());
            let protocol = rule
                .protocol()
                .transports()
                .iter()
                .map(|item| item.as_str())
                .collect::<Vec<_>>()
                .join(" ");
            let destination = rule.destination().endpoint();
            let mut redirect = json!({
                ".type":"redirect", "name":format!("Tunnel Detour: {}", rule.name()),
                "enabled":"1", "family":"ipv6", "src":config.wan_zone,
                "src_dip":address.to_string(), "src_dport":rule.public_port().to_string(),
                "dest_port":if relay {config.relay.listen_port.to_string()} else {destination.port().to_string()},
                "proto":protocol, "target":"DNAT", "reflection":"0",
                "mark":format!("{}/0xffffffff", config.wan.mark_prefix | u32::from(*generation))
            });
            if !relay {
                redirect["dest"] = json!(config.lan_zone);
                redirect["dest_ip"] = json!(destination.ip().to_string());
            }
            insert_section(&mut sections, name, redirect.clone())?;
            if rule.access() == tunnel_detour_core::InboundAccess::WanAndLan {
                let mut local = redirect;
                local["src"] = json!(config.lan_zone);
                local["name"] = json!(format!("Tunnel Detour LAN access: {}", rule.name()));
                insert_section(
                    &mut sections,
                    format!("td_il_{}_{index}", rule.id().as_str()),
                    local,
                )?;
            }
        }
        // firewall4 admits local redirects through its native ct-status-DNAT input
        // rule and permits related errors. The earlier owned input guard narrows both.
        if !relay && rule.access() == tunnel_detour_core::InboundAccess::WanAndLan {
            let destination = rule.destination().endpoint();
            let std::net::IpAddr::V6(target) = destination.ip() else {
                return Err(ServiceError::KernelConflict);
            };
            let source = config.lan_source(target)?;
            let protocol = rule
                .protocol()
                .transports()
                .iter()
                .map(|item| item.as_str())
                .collect::<Vec<_>>()
                .join(" ");
            for (index, network) in config
                .lan_networks
                .iter()
                .enumerate()
                .filter(|(_, network)| matches!(network, ipnet::IpNet::V6(_)))
            {
                insert_section(
                    &mut sections,
                    format!("td_is_{}_{index}", rule.id().as_str()),
                    json!({
                        ".type":"nat", "name":format!("Tunnel Detour LAN return: {}", rule.name()),
                        "enabled":"1", "family":"ipv6", "src":config.lan_zone, "device":config.lan_device,
                        "src_ip":network.to_string(), "dest_ip":target.to_string(), "dest_port":destination.port().to_string(),
                        "snat_ip":source.to_string(), "proto":protocol, "target":"SNAT",
                        "mark":format!("{}/0xffffffff", config.wan.mark_prefix | u32::from(*generation))
                    }),
                )?;
            }
        }
    }
    Ok(sections)
}

pub(crate) fn verify_owned(
    current: &FirewallSnapshot,
    expected: &Sections,
) -> Result<(), ServiceError> {
    for (name, value) in expected {
        if current.values.get(name) != Some(value) {
            return Err(ServiceError::KernelConflict);
        }
    }
    Ok(())
}

pub(crate) async fn no_pending_changes() -> Result<(), ServiceError> {
    let output = kernel::command("uci", &["changes".into(), "firewall".into()], None).await?;
    if !output.success || !output.stdout.is_empty() {
        return Err(ServiceError::KernelConflict);
    }
    Ok(())
}

/// Existing administrator redirects take precedence: broad or opaque entries require review
/// rather than guessing that a second publication of the same WAN endpoint will be safe.
pub(crate) fn validate_frontend(
    current: &FirewallSnapshot,
    owned: &Sections,
    config: &InboundConfig,
) -> Result<(), ServiceError> {
    for zone in [&config.lan_zone, &config.wan_zone] {
        if current
            .values
            .values()
            .filter(|value| {
                value[".type"] == "zone" && value["name"].as_str() == Some(zone.as_str())
            })
            .count()
            != 1
        {
            return Err(ServiceError::KernelConflict);
        }
    }
    for (name, section) in &current.values {
        if owned.contains_key(name)
            || section[".type"] != "redirect"
            || section["enabled"] == "0"
            || section["family"] == "ipv4"
        {
            continue;
        }
        for rule in config.rules.rules().iter().filter(|rule| rule.enabled()) {
            if section["src"].as_str().is_some_and(|zone| {
                zone != config.wan_zone
                    && zone != "*"
                    && !(rule.access() == tunnel_detour_core::InboundAccess::WanAndLan
                        && zone == config.lan_zone)
            }) {
                continue;
            }
            let protocols = section["proto"].as_str();
            if protocols.is_some_and(|value| {
                !value
                    .split_whitespace()
                    .any(|value| matches!(value, "all" | "tcpudp" | "tcp" | "udp"))
            }) {
                continue;
            }
            let Some(ports) = section["src_dport"].as_str() else {
                return Err(ServiceError::KernelConflict);
            };
            for value in ports.split_whitespace() {
                let (start, end) = value
                    .split_once('-')
                    .or_else(|| value.split_once(':'))
                    .unwrap_or((value, value));
                let (Ok(start), Ok(end)) = (start.parse::<u16>(), end.parse::<u16>()) else {
                    return Err(ServiceError::KernelConflict);
                };
                if start > end || (start..=end).contains(&rule.public_port().get()) {
                    return Err(ServiceError::KernelConflict);
                }
            }
        }
    }
    Ok(())
}

/// Commit only our known sections, after checking both foreign configuration and pending
/// administrator edits. No whole-file replacement, global revert or implicit adoption.
pub(crate) async fn apply(
    before: &FirewallSnapshot,
    owned: &Sections,
    desired: &Sections,
) -> Result<(), ServiceError> {
    no_pending_changes().await?;
    verify_owned(before, owned)?;
    for name in desired.keys() {
        if before.values.contains_key(name) && !owned.contains_key(name) {
            return Err(ServiceError::KernelConflict);
        }
    }
    let staging = tokio::task::block_in_place(tempfile::tempdir)?;
    let staging_path = staging
        .path()
        .to_str()
        .ok_or(ServiceError::KernelConflict)?;
    let invoke = |operation: &str, value: String| {
        vec!["-t".into(), staging_path.into(), operation.into(), value]
    };
    for name in owned.keys() {
        kernel::checked("uci", invoke("delete", format!("firewall.{name}")), None).await?;
    }
    for (name, section) in desired {
        let section = section.as_object().ok_or(ServiceError::KernelConflict)?;
        kernel::checked(
            "uci",
            invoke(
                "set",
                format!(
                    "firewall.{name}={}",
                    match section.get(".type").and_then(Value::as_str) {
                        Some(kind @ ("redirect" | "nat")) => kind,
                        _ => return Err(ServiceError::KernelConflict),
                    }
                ),
            ),
            None,
        )
        .await?;
        for (key, value) in section.iter().filter(|(key, _)| !key.starts_with('.')) {
            let value = value.as_str().ok_or(ServiceError::KernelConflict)?;
            kernel::checked(
                "uci",
                invoke("set", format!("firewall.{name}.{key}={value}")),
                None,
            )
            .await?;
        }
    }
    no_pending_changes().await?;
    if snapshot().await? != *before {
        return Err(ServiceError::KernelConflict);
    }
    kernel::checked("uci", invoke("commit", "firewall".into()), None).await?;
    let mut expected = before.clone();
    for name in owned.keys() {
        expected.values.remove(name);
    }
    expected.values.extend(desired.clone());
    if snapshot().await? != expected {
        return Err(ServiceError::KernelConflict);
    }
    // libuci commit does not reload firewall4. Validate the committed candidate before the
    // kernel ruleset changes; the caller keeps affected admissions closed on any failure.
    kernel::checked("fw4", vec!["check".into()], None).await?;
    kernel::checked("fw4", vec!["reload".into()], None).await?;
    if snapshot().await? != expected {
        return Err(ServiceError::KernelConflict);
    }
    Ok(())
}
