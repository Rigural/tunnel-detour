use std::{
    net::{Ipv4Addr, SocketAddrV4},
    num::NonZeroUsize,
    path::PathBuf,
    time::Duration,
};

use ipnet::Ipv4Net;
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
        "the transparent TCP listener must bind an authorized LAN address or all IPv4 interfaces"
    )]
    ProxyListener,
    #[error(
        "configure at least one authorized LAN subnet, without multicast, default, or synthetic networks"
    )]
    Lan,
    #[error("interface names must be 1 to 15 ASCII letters, digits, underscores, hyphens, or dots")]
    Device,
    #[error("WAN and LAN must use different devices; WAN gateway must be a usable IPv4 address")]
    Wan,
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
    #[error(transparent)]
    Range(#[from] FakeIpError),
    #[error(transparent)]
    Rules(#[from] RuleSetError),
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct ResourceLimits {
    pub max_rules: usize,
    pub max_mappings: usize,
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
            dns_jobs: 32,
            connections: 128,
            dns_timeout_seconds: 5,
            connect_timeout_seconds: 10,
            connection_lifetime_seconds: 3600,
            ttl_seconds: 60,
        }
    }
}

#[derive(Clone, Deserialize, Serialize)]
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
    real_upstream: SocketAddrV4,
    state_file: PathBuf,
    status_file: PathBuf,
    fake_range: FakeIpRange,
    lan_device: String,
    lan_networks: Vec<Ipv4Net>,
    wan: WanSettings,
    rules: Vec<Rule>,
    #[serde(default)]
    limits: ResourceLimits,
    #[serde(default)]
    adguard: Option<AdguardSettings>,
}

/// Validated configuration. Construction is fallible; invalid configuration changes no network.
#[derive(Clone)]
pub struct ServiceConfig {
    pub(crate) from_uci: bool,
    pub(crate) dns_listen: SocketAddrV4,
    pub(crate) proxy_listen: SocketAddrV4,
    pub(crate) real_upstream: SocketAddrV4,
    pub(crate) state_file: PathBuf,
    pub(crate) status_file: PathBuf,
    pub(crate) fake_range: FakeIpRange,
    pub(crate) lan_device: String,
    pub(crate) lan_networks: Vec<Ipv4Net>,
    pub(crate) wan: WanSettings,
    pub(crate) rules: RuleSet,
    pub(crate) limits: ResourceLimits,
    pub(crate) adguard: Option<AdguardSettings>,
}

#[derive(Clone, Deserialize, Serialize)]
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
    pub fn from_json(bytes: &[u8]) -> Result<Self, ConfigError> {
        if bytes.len() > 1_048_576 {
            return Err(ConfigError::Limits);
        }
        let raw: RawConfig = serde_json::from_slice(bytes)?;
        if let Some(settings) = &raw.adguard {
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
            || raw.dns_listen == raw.real_upstream
            || (raw.dns_listen.port() != 0 && raw.dns_listen.port() == raw.proxy_listen.port())
            || raw.real_upstream.port() == 0
            || raw.real_upstream.ip().is_unspecified()
            || raw.real_upstream.ip().is_multicast()
            || is_benchmark(*raw.real_upstream.ip())
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
            if device.is_empty()
                || device.len() > 15
                || !device
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
            {
                return Err(ConfigError::Device);
            }
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
        if ["", ".lock", ".adguard.json", ".adguard.json.lock"]
            .iter()
            .any(|suffix| {
                let mut path = raw.state_file.as_os_str().to_os_string();
                path.push(suffix);
                path == raw.status_file.as_os_str()
            })
            || raw.proxy_listen.ip().is_multicast()
            || raw.fake_range.contains(*raw.proxy_listen.ip())
        {
            return Err(ConfigError::Paths);
        }
        let limits = &raw.limits;
        if limits.max_rules == 0
            || limits.max_rules > 4096
            || limits.max_mappings == 0
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
        Ok(Self {
            from_uci: false,
            dns_listen: raw.dns_listen,
            proxy_listen: raw.proxy_listen,
            real_upstream: raw.real_upstream,
            state_file: raw.state_file,
            status_file: raw.status_file,
            fake_range: raw.fake_range,
            lan_device: raw.lan_device,
            lan_networks: raw.lan_networks,
            wan: raw.wan,
            rules,
            limits: raw.limits,
            adguard: raw.adguard,
        })
    }

    pub fn rules(&self) -> &RuleSet {
        &self.rules
    }
    pub(crate) fn dns_timeout(&self) -> Duration {
        Duration::from_secs(self.limits.dns_timeout_seconds)
    }
    pub(crate) fn allows_client(&self, ip: Ipv4Addr) -> bool {
        self.lan_networks
            .iter()
            .any(|network| network.contains(&ip))
    }

    /// A real destination must not turn the proxy into a gateway to management or private LANs.
    pub(crate) fn permits_real_target(&self, ip: Ipv4Addr) -> bool {
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
            && !self.allows_client(ip)
            && !(ip.octets()[0] == 100 && (64..=127).contains(&ip.octets()[1]))
    }
}

fn is_benchmark(ip: Ipv4Addr) -> bool {
    ip.octets()[0] == 198 && matches!(ip.octets()[1], 18 | 19)
}
