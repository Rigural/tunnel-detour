//! UCI adapter for the optional inbound feature. DNS globals are never loaded here.

use std::{
    collections::BTreeSet,
    net::{IpAddr, SocketAddr},
};

use ipnet::IpNet;
use serde::Deserialize;
use serde_json::{Value, json};
use tunnel_detour_core::{INBOUND_INTERNET_V6, InboundRuleSpec};

use crate::{InboundConfig, ServiceError, UciError, kernel, uci};

pub(crate) const STATE: &str = "/etc/tunnel-detour/inbound/state.json";
pub(crate) const STATUS: &str = "/var/run/tunnel-detour/inbound/status.json";
pub(crate) const ROUTE_TABLE: u32 = 41873;
pub(crate) const MARK_PREFIX: u32 = 0x54440000;
pub(crate) const RULE_PRIORITY: u32 = 100;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Globals {
    enabled: String,
    lan_network: String,
    wan_network: String,
    relay_port: Option<String>,
    relay_connections: Option<String>,
    relay_connect_timeout: Option<String>,
    relay_idle_timeout: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    name: String,
    enabled: String,
    protocol: tunnel_detour_core::InboundProtocol,
    #[serde(default)]
    access: tunnel_detour_core::InboundAccess,
    public_port: String,
    destination_address: IpAddr,
    destination_port: String,
}

#[derive(Deserialize)]
struct Network {
    up: bool,
    l3_device: Option<String>,
}

async fn network(name: &str) -> Result<String, ServiceError> {
    if name.is_empty()
        || name.len() > 31
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
    {
        return Err(UciError::NetworkName.into());
    }
    let state: Network = serde_json::from_slice(
        &uci::ubus(&format!("network.interface.{name}"), "status", json!({})).await?,
    )?;
    if !state.up {
        return Err(UciError::Network.into());
    }
    state.l3_device.ok_or_else(|| UciError::Network.into())
}

/// Neighbor hints are scoped to the selected live LAN and never perform reverse DNS.
/// They identify known addresses, not address stability or current application reachability.
pub(crate) async fn device_hints(name: &str) -> Result<Value, ServiceError> {
    let device = network(name).await?;
    let output =
        kernel::command("ip", &["-j".into(), "address".into(), "show".into()], None).await?;
    if !output.success {
        return Err(UciError::Network.into());
    }
    let interfaces: Vec<Interface> = serde_json::from_slice(&output.stdout)?;
    let mut routers = BTreeSet::new();
    let mut networks = Vec::new();
    for interface in interfaces {
        for address in interface.addr_info {
            routers.insert(address.local);
            if interface.ifname == device
                && match address.local {
                    IpAddr::V4(ip) => {
                        !ip.is_link_local() && !ip.is_loopback() && !ip.is_unspecified()
                    }
                    IpAddr::V6(ip) => {
                        !ip.is_unicast_link_local() && !ip.is_loopback() && !ip.is_unspecified()
                    }
                }
            {
                networks.push(
                    IpNet::new(address.local, address.prefixlen)
                        .map_err(|_| UciError::Network)?
                        .trunc(),
                );
            }
        }
    }
    #[derive(Deserialize)]
    struct Neighbor {
        dst: IpAddr,
        lladdr: Option<String>,
    }
    let output = kernel::command_with_limit(
        "ip",
        &[
            "-j".into(),
            "neighbor".into(),
            "show".into(),
            "dev".into(),
            device,
        ],
        None,
        256 * 1024,
    )
    .await?;
    if !output.success {
        return Err(UciError::Network.into());
    }
    let neighbors: Vec<Neighbor> = serde_json::from_slice(&output.stdout)?;
    let mut devices = Vec::new();
    for neighbor in neighbors {
        let address = neighbor.dst;
        if !routers.contains(&address)
            && !neighbor.dst.is_multicast()
            && networks.iter().any(|network| network.contains(&address))
            && let Some(mac) = neighbor.lladdr
        {
            devices.push(json!({"address":address,"mac":mac}));
            if devices.len() == 256 {
                break;
            }
        }
    }
    Ok(json!({"network":name,"devices":devices,"stability":"unverified"}))
}

async fn zone(network: &str) -> Result<String, ServiceError> {
    let sections: uci::UciResponse =
        serde_json::from_slice(&uci::ubus("uci", "get", json!({"config":"firewall"})).await?)?;
    let mut names = BTreeSet::new();
    for section in sections
        .values
        .into_values()
        .filter(|section| section.kind == "zone")
    {
        let value = uci::section_options(section)?;
        let matches = match &value["network"] {
            Value::String(value) => value.split_whitespace().any(|value| value == network),
            Value::Array(values) => values.iter().any(|value| value.as_str() == Some(network)),
            _ => false,
        };
        if matches {
            names.insert(value["name"].as_str().ok_or(UciError::Options)?.to_owned());
        }
    }
    if names.len() != 1 {
        return Err(UciError::Network.into());
    }
    names
        .into_iter()
        .next()
        .ok_or_else(|| UciError::Network.into())
}

#[derive(Deserialize)]
struct Address {
    local: IpAddr,
    prefixlen: u8,
}
#[derive(Deserialize)]
struct Interface {
    ifname: String,
    #[serde(default)]
    addr_info: Vec<Address>,
}

/// Missing inbound settings mean disabled for installations created before this feature.
/// A disabled feature does not inspect IPv6 state, DNS settings or client reservations.
pub async fn load_inbound_uci(
    validate_disabled: bool,
) -> Result<Option<InboundConfig>, ServiceError> {
    let mut sections = uci::read_sections().await?;
    let Some(section) = sections.values.remove("inbound") else {
        return Ok(None);
    };
    if section.kind != "inbound" {
        return Err(UciError::Sections.into());
    }
    let value = uci::section_options(section)?;
    if !uci::enabled(value["enabled"].as_str().ok_or(UciError::Options)?)? && !validate_disabled {
        return Ok(None);
    }
    let globals: Globals = serde_json::from_value(value)?;
    uci::enabled(&globals.enabled)?;
    let mut relay = crate::inbound_config::InboundRelay::default();
    if let Some(value) = &globals.relay_port {
        relay.listen_port = value.parse().map_err(|_| UciError::Options)?;
    }
    if let Some(value) = &globals.relay_connections {
        relay.max_connections = value.parse().map_err(|_| UciError::Options)?;
    }
    if let Some(value) = &globals.relay_connect_timeout {
        relay.connect_timeout_seconds = value.parse().map_err(|_| UciError::Options)?;
    }
    if let Some(value) = &globals.relay_idle_timeout {
        relay.idle_timeout_seconds = value.parse().map_err(|_| UciError::Options)?;
    }
    let lan = network(&globals.lan_network).await?;
    let wan = network(&globals.wan_network).await?;
    let output =
        kernel::command("ip", &["-j".into(), "address".into(), "show".into()], None).await?;
    if !output.success {
        return Err(UciError::Network.into());
    }
    let interfaces: Vec<Interface> = serde_json::from_slice(&output.stdout)?;
    let mut router = Vec::new();
    let mut lan_router = Vec::new();
    let mut networks = BTreeSet::new();
    let mut public = BTreeSet::new();
    for interface in interfaces {
        for address in interface.addr_info {
            router.push(address.local);
            if interface.ifname == lan
                && !address.local.is_loopback()
                && !address.local.is_unspecified()
                && !matches!(address.local, IpAddr::V6(ip) if ip.is_unicast_link_local())
            {
                networks.insert(
                    IpNet::new(address.local, address.prefixlen)
                        .map_err(|_| UciError::Network)?
                        .trunc(),
                );
                if let IpAddr::V6(local) = address.local {
                    lan_router.push(local);
                }
            }
            if interface.ifname == wan
                && let IpAddr::V6(address) = address.local
                && INBOUND_INTERNET_V6.contains(&address)
            {
                public.insert(address);
            }
        }
    }
    let gateway = crate::ipv6::wan_gateway(&wan)
        .await?
        .ok_or(UciError::Network)?;
    let mut rules = Vec::new();
    for (id, section) in sections.values {
        match section.kind.as_str() {
            "globals" | "exception" => continue,
            "inbound_port" => {}
            _ => return Err(UciError::Sections.into()),
        }
        let entry: Entry = serde_json::from_value(uci::section_options(section)?)?;
        rules.push(InboundRuleSpec {
            id: id.parse()?,
            name: entry.name,
            enabled: uci::enabled(&entry.enabled)?,
            protocol: entry.protocol,
            access: entry.access,
            public_port: entry.public_port.parse().map_err(|_| UciError::Options)?,
            destination: SocketAddr::new(
                entry.destination_address,
                entry
                    .destination_port
                    .parse()
                    .map_err(|_| UciError::Options)?,
            ),
        });
    }
    let value = json!({"lan_device":lan,"lan_zone":zone(&globals.lan_network).await?,"lan_networks":networks,"router_addresses":router,"lan_router_addresses":lan_router,
        "wan_zone":zone(&globals.wan_network).await?,"wan":{"device":wan,"addresses":public,"gateway":gateway,"route_table":ROUTE_TABLE,"mark_prefix":MARK_PREFIX,"rule_priority":RULE_PRIORITY},
        "state_file":STATE,"status_file":STATUS,"rules":rules,"relay":relay});
    Ok(Some(InboundConfig::from_json(&serde_json::to_vec(
        &value,
    )?)?))
}

pub(crate) async fn is_enabled() -> Result<bool, ServiceError> {
    let mut sections = uci::read_sections().await?;
    let Some(section) = sections.values.remove("inbound") else {
        return Ok(false);
    };
    if section.kind != "inbound" {
        return Err(UciError::Sections.into());
    }
    uci::enabled(
        section
            .options
            .get("enabled")
            .and_then(Value::as_str)
            .ok_or(UciError::Options)?,
    )
    .map_err(Into::into)
}
