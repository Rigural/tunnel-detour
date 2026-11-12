//! Configuration for inbound publications; no DNS or AdGuard settings are required.

use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::{
    net::{IpAddr, Ipv6Addr},
    num::NonZeroUsize,
    path::{Component, PathBuf},
};
use thiserror::Error;
use tunnel_detour_core::{
    INBOUND_INTERNET_V6, InboundAccess, InboundError, InboundRuleSpec, InboundRules,
};

#[derive(Debug, Error)]
pub enum InboundConfigError {
    #[error("inbound configuration is not valid JSON")]
    Json(#[from] serde_json::Error),
    #[error("inbound interface names must be distinct Linux device names")]
    Device,
    #[error("select distinct native LAN and WAN firewall zones")]
    Zone,
    #[error("select a WAN with explicit global IPv6 addresses and a usable gateway")]
    Wan,
    #[error(
        "inbound routing requires a nonzero 16-bit mark prefix, private table and valid priority"
    )]
    Routing,
    #[error(
        "inbound state and status must be distinct absolute paths, outside each other's journals"
    )]
    Paths,
    #[error("inbound limits exceed the supported resource bounds")]
    Limits,
    #[error(transparent)]
    Policy(#[from] InboundError),
    #[error("inbound configuration does not match the selected live LAN/WAN interfaces")]
    Network,
    #[error("LAN public-address access requires a usable assigned LAN IPv6 source")]
    LanSource,
    #[error("inbound ownership state could not be verified")]
    State(#[source] crate::integration_state::IntegrationStateError),
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct InboundWan {
    pub device: String,
    pub addresses: Vec<Ipv6Addr>,
    pub gateway: Ipv6Addr,
    pub route_table: u32,
    /// Upper 16 bits identify the owner; lower 16 bits identify an admission generation.
    pub mark_prefix: u32,
    pub rule_priority: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct InboundRelay {
    pub listen_port: u16,
    pub max_connections: usize,
    pub connect_timeout_seconds: u64,
    pub idle_timeout_seconds: u64,
}

impl Default for InboundRelay {
    fn default() -> Self {
        Self {
            listen_port: 10537,
            max_connections: 32,
            connect_timeout_seconds: 5,
            idle_timeout_seconds: 3600,
        }
    }
}

impl InboundRelay {
    pub(crate) fn limits(&self) -> Result<crate::RelayLimits, InboundConfigError> {
        if self.listen_port == 0 {
            return Err(InboundConfigError::Limits);
        }
        crate::RelayLimits::new(
            self.max_connections,
            std::time::Duration::from_secs(self.connect_timeout_seconds),
            std::time::Duration::from_secs(self.idle_timeout_seconds),
        )
        .map_err(|_| InboundConfigError::Limits)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawInbound {
    lan_device: String,
    #[serde(default = "default_lan_zone")]
    lan_zone: String,
    #[serde(default = "default_wan_zone")]
    wan_zone: String,
    lan_networks: Vec<IpNet>,
    router_addresses: Vec<IpAddr>,
    #[serde(default)]
    lan_router_addresses: Vec<Ipv6Addr>,
    wan: InboundWan,
    #[serde(default)]
    relay: InboundRelay,
    state_file: PathBuf,
    status_file: PathBuf,
    rules: Vec<InboundRuleSpec>,
    #[serde(default = "default_capacity")]
    max_rules: usize,
}

const fn default_capacity() -> usize {
    64
}

fn default_lan_zone() -> String {
    "lan".into()
}
fn default_wan_zone() -> String {
    "wan".into()
}

/// Independent inbound configuration. Address stability is confirmed by the administrator;
/// the OS adapter must also verify that WAN and router addresses are actually assigned.
#[derive(Clone, Debug, Serialize)]
pub struct InboundConfig {
    pub(crate) lan_device: String,
    pub(crate) lan_zone: String,
    pub(crate) wan_zone: String,
    pub(crate) lan_networks: Vec<IpNet>,
    pub(crate) router_addresses: Vec<IpAddr>,
    pub(crate) lan_router_addresses: Vec<Ipv6Addr>,
    pub(crate) wan: InboundWan,
    pub(crate) relay: InboundRelay,
    pub(crate) state_file: PathBuf,
    pub(crate) status_file: PathBuf,
    pub(crate) rules: InboundRules,
    max_rules: usize,
}

impl InboundConfig {
    /// Validate the complete candidate without binding, changing routes, or contacting DNS.
    pub fn from_json(bytes: &[u8]) -> Result<Self, InboundConfigError> {
        if bytes.len() > 1_048_576 {
            return Err(InboundConfigError::Limits);
        }
        let mut raw: RawInbound = serde_json::from_slice(bytes)?;
        raw.relay.limits()?;
        if !crate::config::valid_device(&raw.lan_device)
            || !crate::config::valid_device(&raw.wan.device)
            || raw.lan_device == raw.wan.device
        {
            return Err(InboundConfigError::Device);
        }
        if raw
            .lan_zone
            .parse::<tunnel_detour_core::InboundId>()
            .is_err()
            || raw
                .wan_zone
                .parse::<tunnel_detour_core::InboundId>()
                .is_err()
            || raw.lan_zone == raw.wan_zone
        {
            return Err(InboundConfigError::Zone);
        }
        if raw.wan.addresses.is_empty()
            || raw.wan.addresses.len() > 16
            || raw
                .wan
                .addresses
                .iter()
                .any(|address| !INBOUND_INTERNET_V6.contains(address))
            || raw.wan.gateway.is_unspecified()
            || raw.wan.gateway.is_loopback()
            || raw.wan.gateway.is_multicast()
            || raw.wan.gateway.to_ipv4().is_some()
        {
            return Err(InboundConfigError::Wan);
        }
        if raw.wan.mark_prefix == 0
            || raw.wan.mark_prefix & 0xffff != 0
            || raw.wan.route_table < 256
            || raw.wan.route_table == u32::MAX
            || !(1..32766).contains(&raw.wan.rule_priority)
        {
            return Err(InboundConfigError::Routing);
        }
        if raw.max_rules == 0
            || raw.max_rules > 256
            || raw.router_addresses.len() > 256
            || raw.lan_networks.is_empty()
            || raw.lan_networks.len() > 32
            || raw.lan_router_addresses.len() > 32
        {
            return Err(InboundConfigError::Limits);
        }
        if raw.lan_networks.iter().any(|network| {
            network.prefix_len() == 0
                || network.addr() != network.network()
                || network.network().is_multicast()
                || network.network().is_unspecified()
                || network.network().is_loopback()
        }) {
            return Err(InboundError::Lan.into());
        }
        raw.wan.addresses.sort();
        raw.wan.addresses.dedup();
        for path in [&raw.state_file, &raw.status_file] {
            if !path.is_absolute()
                || path.file_name().is_none()
                || path
                    .components()
                    .any(|component| matches!(component, Component::ParentDir))
            {
                return Err(InboundConfigError::Paths);
            }
        }
        for suffix in ["", ".lock"] {
            let mut path = raw.state_file.as_os_str().to_os_string();
            path.push(suffix);
            if path == raw.status_file.as_os_str() {
                return Err(InboundConfigError::Paths);
            }
        }
        raw.lan_router_addresses.sort();
        raw.lan_router_addresses.dedup();
        if raw.lan_router_addresses.iter().any(|address| {
            address.is_unspecified()
                || address.is_loopback()
                || address.is_multicast()
                || address.is_unicast_link_local()
                || address.to_ipv4().is_some()
                || raw.wan.addresses.contains(address)
                || !raw
                    .lan_networks
                    .iter()
                    .any(|network| network.contains(&IpAddr::V6(*address)))
        }) {
            return Err(InboundConfigError::LanSource);
        }
        let mut router_addresses = raw.router_addresses;
        router_addresses.extend(raw.lan_router_addresses.iter().copied().map(IpAddr::V6));
        router_addresses.extend(raw.wan.addresses.iter().copied().map(IpAddr::V6));
        router_addresses.sort();
        router_addresses.dedup();
        if router_addresses.len() > 256 {
            return Err(InboundConfigError::Limits);
        }
        let rules = InboundRules::new(
            raw.rules,
            NonZeroUsize::new(raw.max_rules).ok_or(InboundConfigError::Limits)?,
            &raw.lan_networks,
            &router_addresses,
        )?;
        let config = Self {
            lan_device: raw.lan_device,
            lan_zone: raw.lan_zone,
            wan_zone: raw.wan_zone,
            lan_networks: raw.lan_networks,
            router_addresses,
            lan_router_addresses: raw.lan_router_addresses,
            wan: raw.wan,
            relay: raw.relay,
            state_file: raw.state_file,
            status_file: raw.status_file,
            rules,
            max_rules: raw.max_rules,
        };
        for rule in config
            .rules
            .rules()
            .iter()
            .filter(|rule| rule.enabled() && rule.access() == InboundAccess::WanAndLan)
        {
            if config.lan_router_addresses.is_empty() {
                return Err(InboundConfigError::LanSource);
            }
            if let IpAddr::V6(target) = rule.destination().endpoint().ip() {
                config.lan_source(target)?;
            }
        }
        Ok(config)
    }

    pub(crate) fn lan_source(&self, target: Ipv6Addr) -> Result<Ipv6Addr, InboundConfigError> {
        let network = self
            .lan_networks
            .iter()
            .filter(|network| {
                matches!(network, IpNet::V6(_)) && network.contains(&IpAddr::V6(target))
            })
            .max_by_key(|network| network.prefix_len())
            .ok_or(InboundConfigError::LanSource)?;
        self.lan_router_addresses
            .iter()
            .copied()
            .find(|address| network.contains(&IpAddr::V6(*address)))
            .ok_or(InboundConfigError::LanSource)
    }

    pub fn rules(&self) -> &InboundRules {
        &self.rules
    }

    pub(crate) fn has_relays(&self) -> bool {
        self.rules
            .rules()
            .iter()
            .any(|rule| rule.enabled() && rule.destination().requires_relay())
    }

    /// Check live address ownership, LAN containment, the WAN gateway and existing file safety.
    /// This read-only preflight does not install or prove the firewall publication itself.
    pub async fn check_network_and_paths(&self) -> Result<(), crate::ServiceError> {
        use std::collections::BTreeSet;
        #[derive(Deserialize)]
        struct Address {
            local: IpAddr,
            prefixlen: u8,
        }
        #[derive(Deserialize)]
        struct Interface {
            ifname: String,
            flags: Vec<String>,
            #[serde(default)]
            addr_info: Vec<Address>,
        }
        let output =
            crate::kernel::command("ip", &["-j".into(), "address".into(), "show".into()], None)
                .await?;
        if !output.success {
            return Err(InboundConfigError::Network.into());
        }
        let interfaces: Vec<Interface> = serde_json::from_slice(&output.stdout)?;
        let select = |name: &str| {
            interfaces
                .iter()
                .find(|interface| {
                    interface.ifname == name && interface.flags.iter().any(|flag| flag == "UP")
                })
                .ok_or(InboundConfigError::Network)
        };
        let lan = select(&self.lan_device)?;
        let wan = select(&self.wan.device)?;
        let actual_lan: Vec<IpNet> = lan
            .addr_info
            .iter()
            .map(|address| {
                IpNet::new(address.local, address.prefixlen)
                    .map_err(|_| InboundConfigError::Network)
            })
            .collect::<Result<_, _>>()?;
        if self.lan_networks.iter().any(|network| {
            !actual_lan.iter().any(|actual| {
                actual.contains(&network.network()) && actual.prefix_len() <= network.prefix_len()
            })
        }) || self.lan_router_addresses.iter().any(|address| {
            !lan.addr_info
                .iter()
                .any(|local| local.local == IpAddr::V6(*address))
        }) || self.wan.addresses.iter().any(|address| {
            !wan.addr_info
                .iter()
                .any(|local| local.local == IpAddr::V6(*address))
        }) {
            return Err(InboundConfigError::Network.into());
        }
        let mut router: BTreeSet<_> = interfaces
            .iter()
            .flat_map(|interface| interface.addr_info.iter().map(|address| address.local))
            .collect();
        router.extend(self.router_addresses.iter().copied());
        for rule in self.rules.rules() {
            if router.contains(&rule.destination().endpoint().ip()) {
                return Err(InboundError::Target.into());
            }
        }
        #[derive(Deserialize)]
        struct Route {
            dst: Option<String>,
            dev: Option<String>,
            gateway: Option<Ipv6Addr>,
        }
        let routes = crate::kernel::command(
            "ip",
            &[
                "-j".into(),
                "-6".into(),
                "route".into(),
                "show".into(),
                "table".into(),
                "all".into(),
            ],
            None,
        )
        .await?;
        if !routes.success {
            return Err(InboundConfigError::Network.into());
        }
        let routes: Vec<Route> = serde_json::from_slice(&routes.stdout)?;
        if !routes.iter().any(|route| {
            route.dst.as_deref() == Some("default")
                && route.dev.as_deref() == Some(self.wan.device.as_str())
                && route.gateway == Some(self.wan.gateway)
        }) {
            return Err(InboundConfigError::Network.into());
        }
        let state = self.state_file.clone();
        let status = self.status_file.clone();
        let existing = tokio::task::spawn_blocking(move || {
            use std::os::unix::fs::PermissionsExt;
            for path in [
                &state,
                &status,
                &crate::integration_state::appended_path(&state, ".lock"),
            ] {
                match std::fs::symlink_metadata(path) {
                    Ok(metadata)
                        if !metadata.is_file() || metadata.permissions().mode() & 0o077 != 0 =>
                    {
                        return Err(InboundConfigError::Paths);
                    }
                    Ok(_) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(_) => return Err(InboundConfigError::Paths),
                }
                match std::fs::symlink_metadata(path.parent().ok_or(InboundConfigError::Paths)?) {
                    Ok(metadata)
                        if !metadata.is_dir() || metadata.permissions().mode() & 0o077 != 0 =>
                    {
                        return Err(InboundConfigError::Paths);
                    }
                    Ok(_) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(_) => return Err(InboundConfigError::Paths),
                }
            }
            if let (Ok(state_parent), Ok(status_parent)) = (
                std::fs::canonicalize(state.parent().ok_or(InboundConfigError::Paths)?),
                std::fs::canonicalize(status.parent().ok_or(InboundConfigError::Paths)?),
            ) {
                let state_file = state.file_name().ok_or(InboundConfigError::Paths)?;
                let status_file = status.file_name().ok_or(InboundConfigError::Paths)?;
                for suffix in ["", ".lock"] {
                    let mut reserved = state_file.to_os_string();
                    reserved.push(suffix);
                    if state_parent == status_parent && reserved == status_file {
                        return Err(InboundConfigError::Paths);
                    }
                }
            }
            crate::integration_state::existing::<serde_json::Value>(&state)
                .map(|value| value.is_some())
                .map_err(InboundConfigError::State)
        })
        .await??;
        crate::kernel::RoutingOwner::inbound(self, existing)
            .validate_routing_ownership()
            .await?;
        if crate::kernel::Kernel::table_handle_for(
            "tunnel_detour_inbound",
            "tunnel-detour:inbound:v1",
        )
        .await?
        .is_some()
            && !existing
        {
            return Err(crate::ServiceError::KernelConflict);
        }
        Ok(())
    }
}
