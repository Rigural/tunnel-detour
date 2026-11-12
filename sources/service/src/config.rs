use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4},
    num::NonZeroUsize,
    path::PathBuf,
    time::Duration,
};

use ipnet::{IpNet, Ipv4Net};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tunnel_detour_core::{FakeIpError, FakeIpRange, Rule, RuleSet, RuleSetError};

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("configuration is not valid JSON")]
    Json(#[from] serde_json::Error),
    #[error(
        "DNS must listen on IPv4 loopback, on a separate port from the real upstream and proxy"
    )]
    DnsListener,
    #[error(
        "the real TCP resolver needs a nonzero port and an unscoped IPv4 or IPv6 unicast address outside synthetic ranges"
    )]
    Resolver,
    #[error(
        "the transparent TCP listener must bind an authorized LAN address or all IPv4 interfaces"
    )]
    ProxyListener,
    #[error(
        "configure at least one authorized LAN subnet, without multicast, default, or synthetic networks"
    )]
    Lan,
    #[error(
        "trusted clients must be at most 64 canonical IPv4/IPv6 CIDRs contained in the selected LAN networks"
    )]
    TrustedClients,
    #[error("interface names must be 1 to 15 ASCII letters, digits, underscores, hyphens, or dots")]
    Device,
    #[error("WAN and LAN must use different devices; WAN gateway must be a usable IPv4 address")]
    Wan,
    #[error(
        "IPv6 exceptions require distinct LAN/WAN, bounded native LAN prefixes and a usable explicit WAN source and gateway"
    )]
    Ipv6,
    #[error(
        "WAN mark, route table and rule priority must be nonzero and outside system-reserved values"
    )]
    Routing,
    #[error("state and status paths must be distinct absolute file paths")]
    Paths,
    #[error("resource limits and timeouts are outside the supported bounds")]
    Limits,
    #[error(
        "AdGuard API must use a router-local IPv4 HTTP URL without URL credentials, query, or fragment; provide both username and password or neither"
    )]
    AdguardEndpoint,
    #[error("the AdGuard DNS integration requires its local API settings")]
    DnsIntegration,
    #[error(transparent)]
    Range(#[from] FakeIpError),
    #[error(transparent)]
    Rules(#[from] RuleSetError),
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct ResourceLimits {
    pub max_rules: usize,
    pub max_mappings: usize,
    pub max_mappings_per_rule: usize,
    pub dns_jobs: usize,
    pub connections: usize,
    pub dns_timeout_seconds: u64,
    pub connect_timeout_seconds: u64,
    pub connection_lifetime_seconds: u64,
    pub ttl_seconds: u64,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            max_rules: 256,
            max_mappings: 4096,
            max_mappings_per_rule: 512,
            dns_jobs: 32,
            connections: 128,
            dns_timeout_seconds: 5,
            connect_timeout_seconds: 10,
            connection_lifetime_seconds: 3600,
            ttl_seconds: 60,
        }
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct WanSettings {
    pub device: String,
    pub gateway: Option<Ipv4Addr>,
    pub route_table: u32,
    pub mark: u32,
    pub rule_priority: u32,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    dns_listen: SocketAddrV4,
    proxy_listen: SocketAddrV4,
    real_upstream: SocketAddr,
    state_file: PathBuf,
    status_file: PathBuf,
    fake_range: FakeIpRange,
    lan_device: String,
    lan_networks: Vec<Ipv4Net>,
    #[serde(default)]
    trusted_clients: Vec<IpNet>,
    wan: WanSettings,
    #[serde(default)]
    ipv6: Option<crate::ipv6::Ipv6Settings>,
    rules: Vec<Rule>,
    #[serde(default)]
    limits: ResourceLimits,
    #[serde(default)]
    adguard: Option<AdguardSettings>,
    #[serde(default)]
    dns_integration: Option<DnsIntegration>,
    #[serde(default)]
    manage_adguard_upstream: bool,
    #[serde(default)]
    adguard_upstream_approval: Option<String>,
}

/// The explicitly selected DNS frontend; a failed frontend never selects another mode.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DnsIntegration {
    /// Manage the local AdGuard API and retain its filtering checks.
    Adguard,
    /// Manage forwarding in an existing, supported OpenWrt dnsmasq instance.
    Dnsmasq,
    /// The JSON caller owns delivery to the loopback DNS listener; not an OpenWrt UCI mode.
    External,
}

/// Validated configuration. Construction is fallible; invalid configuration changes no network.
#[derive(Clone)]
pub struct ServiceConfig {
    pub(crate) from_uci: bool,
    pub(crate) dns_listen: SocketAddrV4,
    pub(crate) proxy_listen: SocketAddrV4,
    pub(crate) real_upstream: SocketAddr,
    pub(crate) state_file: PathBuf,
    pub(crate) status_file: PathBuf,
    pub(crate) fake_range: FakeIpRange,
    pub(crate) lan_device: String,
    pub(crate) lan_networks: Vec<Ipv4Net>,
    pub(crate) trusted_clients: Vec<IpNet>,
    pub(crate) wan: WanSettings,
    pub(crate) ipv6: Option<crate::ipv6::Ipv6Settings>,
    pub(crate) rules: RuleSet,
    pub(crate) limits: ResourceLimits,
    pub(crate) adguard: Option<AdguardSettings>,
    pub(crate) dns_integration: DnsIntegration,
    pub(crate) manage_adguard_upstream: bool,
    pub(crate) adguard_upstream_approval: Option<String>,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AdguardSettings {
    pub api_url: String,
    pub username: Option<String>,
    pub password: Option<String>,
}

impl AdguardSettings {
    pub(crate) fn endpoint(&self) -> Result<reqwest::Url, ConfigError> {
        let mut url =
            reqwest::Url::parse(&self.api_url).map_err(|_| ConfigError::AdguardEndpoint)?;
        let unicast = url
            .host_str()
            .and_then(|host| host.parse::<Ipv4Addr>().ok())
            .is_some_and(|ip| {
                !ip.is_unspecified()
                    && !ip.is_multicast()
                    && !ip.is_broadcast()
                    && !is_benchmark(ip)
            });
        if url.scheme() != "http"
            || !unicast
            || url.port() == Some(0)
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || self.username.is_some() != self.password.is_some()
            || self
                .username
                .as_ref()
                .is_some_and(|value| value.is_empty() || value.len() > 256)
            || self
                .password
                .as_ref()
                .is_some_and(|value| value.len() > 1024)
        {
            return Err(ConfigError::AdguardEndpoint);
        }
        let prefix = url.path().trim_end_matches('/');
        let path = if prefix.ends_with("/control") {
            format!("{prefix}/")
        } else {
            format!("{prefix}/control/")
        };
        url.set_path(&path);
        Ok(url)
    }
}

impl ServiceConfig {
    /// Resolver management can be reconciled without retiring authorized TCP streams.
    /// Every other setting still requires the normal procd instance replacement.
    pub(crate) fn same_runtime(&self, candidate: &Self) -> bool {
        self.dns_listen == candidate.dns_listen
            && self.proxy_listen == candidate.proxy_listen
            && self.state_file == candidate.state_file
            && self.status_file == candidate.status_file
            && self.fake_range == candidate.fake_range
            && self.lan_device == candidate.lan_device
            && self.lan_networks == candidate.lan_networks
            && self.trusted_clients == candidate.trusted_clients
            && self.wan == candidate.wan
            && self.ipv6 == candidate.ipv6
            && self.rules.rules() == candidate.rules.rules()
            && self.limits == candidate.limits
            && self.adguard == candidate.adguard
            && self.dns_integration == candidate.dns_integration
    }

    pub fn from_json(bytes: &[u8]) -> Result<Self, ConfigError> {
        if bytes.len() > 1_048_576 {
            return Err(ConfigError::Limits);
        }
        let raw: RawConfig = serde_json::from_slice(bytes)?;
        let dns_integration = raw.dns_integration.unwrap_or(if raw.adguard.is_some() {
            DnsIntegration::Adguard
        } else {
            DnsIntegration::External
        });
        let adguard = if dns_integration == DnsIntegration::Adguard {
            Some(raw.adguard.ok_or(ConfigError::DnsIntegration)?)
        } else {
            None
        };
        if let Some(settings) = &adguard {
            let endpoint = settings.endpoint()?;
            let ip = endpoint
                .host_str()
                .and_then(|host| host.parse::<Ipv4Addr>().ok())
                .ok_or(ConfigError::AdguardEndpoint)?;
            if !ip.is_loopback() && !raw.lan_networks.iter().any(|network| network.contains(&ip)) {
                return Err(ConfigError::AdguardEndpoint);
            }
        }
        if !raw.dns_listen.ip().is_loopback()
            || SocketAddr::V4(raw.dns_listen) == raw.real_upstream
            || (raw.dns_listen.port() != 0 && raw.dns_listen.port() == raw.proxy_listen.port())
        {
            return Err(ConfigError::DnsListener);
        }
        if raw.lan_networks.is_empty()
            || raw.lan_networks.len() > 16
            || raw.lan_networks.iter().any(|network| {
                network.prefix_len() == 0
                    || network.addr() != network.network()
                    || network.network().is_multicast()
                    || network.network().is_unspecified()
                    || raw.fake_range.contains(network.network())
                    || raw.fake_range.contains(network.broadcast())
                    || network.contains(&raw.fake_range.network())
            })
        {
            return Err(ConfigError::Lan);
        }
        if !raw.proxy_listen.ip().is_unspecified()
            && !raw
                .lan_networks
                .iter()
                .any(|network| network.contains(raw.proxy_listen.ip()))
        {
            return Err(ConfigError::ProxyListener);
        }
        for device in [&raw.lan_device, &raw.wan.device] {
            if !valid_device(device) {
                return Err(ConfigError::Device);
            }
        }
        if let Some(ipv6) = &raw.ipv6 {
            ipv6.validate(&raw.lan_device, raw.fake_range)?;
        }
        if raw.trusted_clients.len() > 64
            || raw.trusted_clients.iter().any(|network| {
                if network.addr() != network.network() {
                    return true;
                }
                match network {
                    IpNet::V4(client) => !raw.lan_networks.iter().any(|lan| {
                        lan.prefix_len() <= client.prefix_len() && lan.contains(&client.network())
                    }),
                    IpNet::V6(client) => !raw.ipv6.as_ref().is_some_and(|settings| {
                        settings.lan_networks.iter().any(|lan| {
                            lan.prefix_len() <= client.prefix_len()
                                && lan.contains(&client.network())
                        })
                    }),
                }
            })
        {
            return Err(ConfigError::TrustedClients);
        }
        if raw.lan_device == raw.wan.device
            || raw.wan.gateway.is_some_and(|ip| {
                ip.is_unspecified() || ip.is_multicast() || ip.is_loopback() || is_benchmark(ip)
            })
        {
            return Err(ConfigError::Wan);
        }
        if raw.wan.mark == 0
            || raw.wan.route_table < 256
            || raw.wan.route_table == u32::MAX
            || !(1..32766).contains(&raw.wan.rule_priority)
        {
            return Err(ConfigError::Routing);
        }
        for path in [&raw.state_file, &raw.status_file] {
            if !path.is_absolute()
                || path.file_name().is_none()
                || path.parent().is_none()
                || path
                    .components()
                    .any(|component| matches!(component, std::path::Component::ParentDir))
            {
                return Err(ConfigError::Paths);
            }
        }
        if [
            "",
            ".lock",
            ".adguard.json",
            ".adguard.json.lock",
            ".adguard-preview.json",
            ".dnsmasq.json",
            ".dnsmasq.json.lock",
            ".ipv6-routing.json",
            ".ipv6-routing.json.lock",
        ]
        .iter()
        .any(|suffix| {
            let mut path = raw.state_file.as_os_str().to_os_string();
            path.push(suffix);
            path == raw.status_file.as_os_str()
        }) || raw.proxy_listen.ip().is_multicast()
            || raw.fake_range.contains(*raw.proxy_listen.ip())
        {
            return Err(ConfigError::Paths);
        }
        let limits = &raw.limits;
        if limits.max_rules == 0
            || limits.max_rules > 4096
            || limits.max_mappings == 0
            || limits.max_mappings_per_rule == 0
            || limits.max_mappings_per_rule > 131070
            || limits.max_mappings
                > usize::try_from(raw.fake_range.capacity()).map_err(|_| ConfigError::Limits)?
            || !(1..=256).contains(&limits.dns_jobs)
            || !(1..=1024).contains(&limits.connections)
            || !(1..=30).contains(&limits.dns_timeout_seconds)
            || !(1..=60).contains(&limits.connect_timeout_seconds)
            || !(1..=86400).contains(&limits.connection_lifetime_seconds)
            || !(1..=3600).contains(&limits.ttl_seconds)
        {
            return Err(ConfigError::Limits);
        }
        let rules = RuleSet::new(
            raw.rules,
            NonZeroUsize::new(limits.max_rules).ok_or(ConfigError::Limits)?,
        )?;
        let config = Self {
            from_uci: false,
            dns_listen: raw.dns_listen,
            proxy_listen: raw.proxy_listen,
            real_upstream: raw.real_upstream,
            state_file: raw.state_file,
            status_file: raw.status_file,
            fake_range: raw.fake_range,
            lan_device: raw.lan_device,
            lan_networks: raw.lan_networks,
            trusted_clients: raw.trusted_clients,
            wan: raw.wan,
            ipv6: raw.ipv6,
            rules,
            limits: raw.limits,
            adguard,
            dns_integration,
            manage_adguard_upstream: raw.manage_adguard_upstream
                && dns_integration == DnsIntegration::Adguard,
            adguard_upstream_approval: raw.adguard_upstream_approval,
        };
        config.validate_resolver_endpoint(config.real_upstream)?;
        if config
            .adguard_upstream_approval
            .as_ref()
            .is_some_and(|receipt| {
                receipt.len() != 32
                    || !receipt
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            })
        {
            return Err(ConfigError::DnsIntegration);
        }
        Ok(config)
    }

    pub(crate) fn validate_resolver_endpoint(
        &self,
        endpoint: SocketAddr,
    ) -> Result<(), ConfigError> {
        validate_tcp_resolver(endpoint)?;
        if endpoint == SocketAddr::V4(self.dns_listen) {
            return Err(ConfigError::DnsListener);
        }
        Ok(())
    }

    /// Return the selected frontend without inspecting or contacting a DNS service.
    pub fn dns_integration(&self) -> DnsIntegration {
        self.dns_integration
    }

    pub fn rules(&self) -> &RuleSet {
        &self.rules
    }
    pub(crate) fn dns_timeout(&self) -> Duration {
        Duration::from_secs(self.limits.dns_timeout_seconds)
    }
    pub(crate) fn allows_client(&self, ip: impl Into<IpAddr>) -> bool {
        let ip = ip.into();
        self.contains_lan(ip)
            && (self.trusted_clients.is_empty()
                || self
                    .trusted_clients
                    .iter()
                    .any(|network| network.contains(&ip)))
    }

    fn contains_lan(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(ip) => self
                .lan_networks
                .iter()
                .any(|network| network.contains(&ip)),
            IpAddr::V6(ip) => self
                .ipv6
                .as_ref()
                .is_some_and(|settings| settings.allows_client(ip)),
        }
    }

    /// A real destination must not turn the proxy into a gateway to management or private LANs.
    pub(crate) fn permits_real_target(&self, ip: impl Into<IpAddr>) -> bool {
        let ip = match ip.into() {
            IpAddr::V4(ip) => ip,
            IpAddr::V6(ip) => {
                return self
                    .ipv6
                    .as_ref()
                    .is_some_and(|settings| settings.permits_target(ip));
            }
        };
        let first = ip.octets()[0];
        !ip.is_unspecified()
            && !ip.is_loopback()
            && !ip.is_private()
            && !ip.is_link_local()
            && !ip.is_multicast()
            && !ip.is_broadcast()
            && first != 0
            && first < 224
            && !is_benchmark(ip)
            && !self.contains_lan(ip.into())
            && !(ip.octets()[0] == 100 && (64..=127).contains(&ip.octets()[1]))
    }
}

pub(crate) fn valid_device(device: &str) -> bool {
    !device.is_empty()
        && device.len() <= 15
        && device
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
}

/// Parse only a literal endpoint. A missing port means TCP 53; bracket IPv6
/// whenever a port is present. Never resolve a hostname or select a provider here.
pub(crate) fn parse_resolver_endpoint(value: &str) -> Result<SocketAddr, ConfigError> {
    let endpoint = value
        .parse::<SocketAddr>()
        .or_else(|_| value.parse::<IpAddr>().map(|ip| SocketAddr::new(ip, 53)))
        .map_err(|_| ConfigError::Resolver)?;
    validate_tcp_resolver(endpoint)?;
    Ok(endpoint)
}

pub(crate) fn validate_tcp_resolver(endpoint: SocketAddr) -> Result<(), ConfigError> {
    let invalid = match endpoint {
        SocketAddr::V4(endpoint) => endpoint.ip().is_broadcast() || is_benchmark(*endpoint.ip()),
        SocketAddr::V6(endpoint) => {
            let ip = endpoint.ip();
            let segments = ip.segments();
            endpoint.scope_id() != 0
                || endpoint.flowinfo() != 0
                || ip.is_unicast_link_local()
                || ip.to_ipv4_mapped().is_some()
                || (segments[..6] == [0; 6] && !ip.is_loopback())
                || segments[..3] == [0x2001, 2, 0]
        }
    };
    if invalid
        || endpoint.port() == 0
        || endpoint.ip().is_unspecified()
        || endpoint.ip().is_multicast()
    {
        return Err(ConfigError::Resolver);
    }
    Ok(())
}

fn is_benchmark(ip: Ipv4Addr) -> bool {
    ip.octets()[0] == 198 && matches!(ip.octets()[1], 18 | 19)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn r102_resolver_input_keeps_literal_address_families_and_unambiguous_ports()
    -> Result<(), Box<dyn std::error::Error>> {
        for (input, expected) in [
            ("192.0.2.53", "192.0.2.53:53"),
            ("192.0.2.53:5353", "192.0.2.53:5353"),
            ("::1", "[::1]:53"),
            ("2001:db8::5353", "[2001:db8::5353]:53"),
            ("[2001:db8::53]:5353", "[2001:db8::53]:5353"),
        ] {
            assert_eq!(
                parse_resolver_endpoint(input)?,
                expected.parse::<SocketAddr>()?,
                "{input}"
            );
        }
        for input in [
            "",
            "resolver.example.test",
            "tcp://[2001:db8::53]:5353",
            "tls://192.0.2.53",
            "user@192.0.2.53:53",
            "[2001:db8::53]",
            "[2001:db8::53]:",
            " 192.0.2.53",
            "2001:db8::53 ",
        ] {
            assert!(
                parse_resolver_endpoint(input).is_err(),
                "accepted nonliteral or ambiguous input: {input}"
            );
        }
        Ok(())
    }
}
