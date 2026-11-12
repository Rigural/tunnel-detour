use std::{
    collections::BTreeMap,
    net::{IpAddr, Ipv4Addr, SocketAddrV4},
};

use ipnet::Ipv4Net;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use thiserror::Error;
use tunnel_detour_core::{DomainPattern, Rule};

use crate::{
    ServiceConfig, ServiceError,
    config::{AdguardSettings, DnsIntegration, ResourceLimits},
    kernel,
};

pub(crate) const STATE_FILE: &str = "/etc/tunnel-detour/leases.json";
pub(crate) const STATUS_FILE: &str = "/var/run/tunnel-detour/status.json";
pub(crate) const ROUTE_TABLE: u32 = 41872;
pub(crate) const ROUTE_MARK: u32 = 21572;
pub(crate) const RULE_PRIORITY: u32 = 11000;

#[derive(Debug, Error)]
pub enum UciError {
    #[error("UCI configuration contains invalid or unsupported sections")]
    Sections,
    #[error("UCI options have an invalid type or value")]
    Options,
    #[error(
        "the selected credentials revision is unavailable; enter and apply replacement credentials or discard a superseded draft"
    )]
    Credentials,
    #[error("select AdGuard Home or an existing dnsmasq DNS integration in Settings")]
    Integration,
    #[error("UCI configuration could not be read through ubus")]
    Read,
    #[error("the selected LAN or WAN network is not up with IPv4 configuration")]
    Network,
    #[error("logical network names must use ASCII letters, digits, underscores, dots or hyphens")]
    NetworkName,
}

#[derive(Deserialize)]
pub(crate) struct UciResponse {
    pub(crate) values: BTreeMap<String, Section>,
}
#[derive(Deserialize)]
pub(crate) struct Section {
    #[serde(rename = ".type")]
    pub(crate) kind: String,
    #[serde(flatten)]
    pub(crate) options: BTreeMap<String, Value>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GlobalOptions {
    #[serde(rename = "enabled")]
    _enabled: String,
    lan_network: String,
    wan_network: String,
    #[serde(default)]
    ipv6_enabled: Option<String>,
    #[serde(default)]
    wan6_network: Option<String>,
    dns_port: String,
    proxy_port: String,
    #[serde(default)]
    real_upstream: String,
    #[serde(default)]
    adguard_url: String,
    #[serde(default)]
    dns_integration: Option<String>,
    #[serde(default)]
    adguard_username: String,
    #[serde(default)]
    adguard_password: String,
    #[serde(default)]
    adguard_credentials_revision: Option<String>,
    #[serde(default)]
    manage_adguard_upstream: Option<String>,
    #[serde(default)]
    adguard_upstream_approval: Option<String>,
    #[serde(default)]
    fake_range: Option<String>,
    #[serde(default)]
    max_mappings: Option<String>,
    #[serde(default)]
    max_mappings_per_rule: Option<String>,
    #[serde(default)]
    trusted_clients: Vec<ipnet::IpNet>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExceptionOptions {
    pattern: DomainPattern,
    enabled: String,
}

#[derive(Deserialize, Serialize)]
struct NetworkStatus {
    up: bool,
    l3_device: Option<String>,
    #[serde(rename = "ipv4-address", default)]
    addresses: Vec<Address>,
    #[serde(default)]
    route: Vec<Route>,
}
#[derive(Deserialize, Serialize)]
struct Address {
    address: Ipv4Addr,
    mask: u8,
}
#[derive(Deserialize, Serialize)]
struct Route {
    target: IpAddr,
    mask: u8,
    nexthop: Option<IpAddr>,
}

impl NetworkStatus {
    // netifd reports both route families in one array. IPv4 exceptions must
    // neither deserialize IPv6 as IPv4 nor restart for unrelated IPv6 changes.
    fn ipv4(mut self) -> Result<Self, UciError> {
        self.route.retain(|route| route.target.is_ipv4());
        if self
            .route
            .iter()
            .any(|route| route.mask > 32 || route.nexthop.is_some_and(|hop| !hop.is_ipv4()))
        {
            return Err(UciError::Network);
        }
        Ok(self)
    }
}

pub(crate) async fn ubus(
    object: &str,
    method: &str,
    payload: Value,
) -> Result<Vec<u8>, ServiceError> {
    let payload = serde_json::to_string(&payload)?;
    let output = kernel::command(
        "ubus",
        &[
            "-S".into(),
            "call".into(),
            object.into(),
            method.into(),
            payload,
        ],
        None,
    )
    .await?;
    if !output.success {
        return Err(UciError::Read.into());
    }
    Ok(output.stdout)
}

pub(crate) fn enabled(value: &str) -> Result<bool, UciError> {
    match value {
        "0" => Ok(false),
        "1" => Ok(true),
        _ => Err(UciError::Options),
    }
}

pub(crate) fn section_options(mut section: Section) -> Result<Value, ServiceError> {
    // Dot-prefixed keys are ubus's UCI section metadata, not user configuration options.
    section.options.retain(|name, _| !name.starts_with('.'));
    Ok(serde_json::to_value(section.options)?)
}

async fn network_bytes(name: &str) -> Result<Vec<u8>, ServiceError> {
    if name.is_empty()
        || name.len() > 31
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
    {
        return Err(UciError::NetworkName.into());
    }
    ubus(&format!("network.interface.{name}"), "status", json!({})).await
}

async fn network(name: &str) -> Result<NetworkStatus, ServiceError> {
    let response = network_bytes(name).await?;
    let status = serde_json::from_slice::<NetworkStatus>(&response)?.ipv4()?;
    if !status.up || status.l3_device.is_none() || status.addresses.is_empty() {
        return Err(UciError::Network.into());
    }
    Ok(status)
}

async fn ipv6_settings(
    enabled_value: Option<&str>,
    name: Option<&str>,
    lan_device: &str,
) -> Result<Option<crate::ipv6::Ipv6Settings>, ServiceError> {
    if !enabled(enabled_value.unwrap_or("0"))? {
        return Ok(None);
    }
    #[derive(Deserialize)]
    struct Status {
        up: bool,
        l3_device: Option<String>,
    }
    let status: Status =
        serde_json::from_slice(&network_bytes(name.ok_or(UciError::Options)?).await?)?;
    if !status.up {
        return Err(ServiceError::Ipv6Path);
    }
    let device = status.l3_device.ok_or(ServiceError::Ipv6Path)?;
    let gateway = crate::ipv6::wan_gateway(&device).await?;
    Ok(Some(
        crate::ipv6::Ipv6Settings::discover(lan_device, device, gateway).await?,
    ))
}

/// Load committed UCI through the real rpcd service. Disabled configurations do not inspect
/// network state or start listeners. `validate_disabled` is for an explicit configuration check.
pub async fn load_uci(validate_disabled: bool) -> Result<Option<ServiceConfig>, ServiceError> {
    let mut response = read_sections().await?;
    let globals = take_globals(&mut response)?;
    if !enabled_option(&globals)? && !validate_disabled {
        return Ok(None);
    }
    let globals: GlobalOptions = serde_json::from_value(section_options(globals)?)?;
    let mut rules = Vec::new();
    for section in response.values.into_values() {
        match section.kind.as_str() {
            "exception" => {
                let value: ExceptionOptions = serde_json::from_value(section_options(section)?)?;
                rules.push(Rule {
                    pattern: value.pattern,
                    enabled: enabled(&value.enabled)?,
                });
            }
            "inbound" | "inbound_port" => {}
            _ => return Err(UciError::Sections.into()),
        }
    }
    build(globals, rules).await.map(Some)
}

pub(crate) async fn read_sections() -> Result<UciResponse, ServiceError> {
    Ok(serde_json::from_slice(
        &ubus("uci", "get", json!({"config":"tunnel-detour"})).await?,
    )?)
}

pub(crate) async fn credential_revision() -> Result<Option<String>, ServiceError> {
    let globals = take_globals(&mut read_sections().await?)?;
    globals
        .options
        .get("adguard_credentials_revision")
        .map(|value| {
            value
                .as_str()
                .map(str::to_owned)
                .ok_or(UciError::Options.into())
        })
        .transpose()
}

fn take_globals(response: &mut UciResponse) -> Result<Section, UciError> {
    response
        .values
        .remove("globals")
        .filter(|section| section.kind == "globals")
        .ok_or(UciError::Sections)
}

fn enabled_option(globals: &Section) -> Result<bool, UciError> {
    enabled(
        globals
            .options
            .get("enabled")
            .and_then(Value::as_str)
            .ok_or(UciError::Options)?,
    )
}

pub(crate) async fn is_enabled() -> Result<bool, ServiceError> {
    let globals = take_globals(&mut read_sections().await?)?;
    Ok(enabled_option(&globals)?)
}

/// Status remains readable before a new installation has selected its DNS frontend.
pub(crate) async fn configured_integration() -> Result<Option<DnsIntegration>, ServiceError> {
    let globals = take_globals(&mut read_sections().await?)?;
    Ok(
        match globals
            .options
            .get("dns_integration")
            .and_then(Value::as_str)
        {
            None | Some("adguard") => Some(DnsIntegration::Adguard),
            Some("dnsmasq") => Some(DnsIntegration::Dnsmasq),
            Some(_) => None,
        },
    )
}

/// Digest of DNS-owned settings and relevant live network state. IPv6 is inspected
/// only when explicitly enabled; lifetime countdowns are excluded. Port-list edits
/// must not restart DNS connections. Only SHA-256 crosses the native init boundary.
/// Unavailable contexts have an explicit error fingerprint so procd retains its
/// bounded recovery instance during netifd transitions. Startup still validates
/// the real context strictly; this digest is never a readiness declaration.
pub async fn dns_revision() -> Result<String, ServiceError> {
    let sections = read_sections().await?;
    let mut owned = BTreeMap::new();
    for (name, section) in sections.values {
        if matches!(section.kind.as_str(), "globals" | "exception") {
            let kind = section.kind.clone();
            let mut options = section_options(section)?;
            if kind == "globals" {
                let fields = options.as_object_mut().ok_or(UciError::Options)?;
                for key in [
                    "real_upstream",
                    "manage_adguard_upstream",
                    "adguard_upstream_approval",
                ] {
                    fields.remove(key);
                }
            }
            owned.insert(name, json!({"kind":kind,"options":options}));
        }
    }
    let mut live = BTreeMap::new();
    let mut ipv6 = Value::Null;
    let globals = owned.get("globals").ok_or(UciError::Sections)?;
    if globals["options"]["enabled"] == "1" {
        for key in ["lan_network", "wan_network"] {
            let name = globals["options"][key].as_str().ok_or(UciError::Options)?;
            live.insert(
                key,
                match network(name).await {
                    Ok(status) => json!({"available":true,"status":status}),
                    Err(error) => json!({"available":false,"error":error.code()}),
                },
            );
        }
        let options = &globals["options"];
        if enabled(options["ipv6_enabled"].as_str().unwrap_or("0"))? {
            let context = match live
                .get("lan_network")
                .and_then(|entry| entry["status"]["l3_device"].as_str())
            {
                Some(lan_device) => {
                    ipv6_settings(
                        options["ipv6_enabled"].as_str(),
                        options["wan6_network"].as_str(),
                        lan_device,
                    )
                    .await
                }
                None => Err(ServiceError::Ipv6Path),
            };
            ipv6 = match context {
                Ok(settings) => json!({"available":true,"settings":settings}),
                Err(error) => json!({"available":false,"error":error.code()}),
            };
        }
    }
    let bytes = serde_json::to_vec(&json!({"settings":owned,"networks":live,"ipv6":ipv6}))?;
    let output = kernel::command("sha256sum", &[], Some(&bytes)).await?;
    if !output.success {
        return Err(UciError::Read.into());
    }
    let text = std::str::from_utf8(&output.stdout).map_err(|_| UciError::Read)?;
    let digest = text.split_whitespace().next().ok_or(UciError::Read)?;
    if digest.len() != 64 || !digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(UciError::Read.into());
    }
    Ok(digest.into())
}

pub(crate) async fn cleanup_settings() -> Result<AdguardSettings, ServiceError> {
    #[derive(Deserialize)]
    struct ControlOptions {
        adguard_url: String,
        #[serde(default)]
        adguard_username: String,
        #[serde(default)]
        adguard_password: String,
        #[serde(default)]
        adguard_credentials_revision: Option<String>,
    }
    // Cleanup must remain usable when a rule or a network option prevents startup.
    let globals = take_globals(&mut read_sections().await?)?;
    let globals: ControlOptions = serde_json::from_value(section_options(globals)?)?;
    let settings = settings(
        globals.adguard_url,
        globals.adguard_username,
        globals.adguard_password,
        globals.adguard_credentials_revision.as_deref(),
    )?;
    settings.endpoint()?;
    Ok(settings)
}

fn settings(
    api_url: String,
    username: String,
    password: String,
    revision: Option<&str>,
) -> Result<AdguardSettings, ServiceError> {
    if !username.is_empty() || !password.is_empty() {
        return Err(UciError::Options.into());
    }
    crate::credentials::settings(api_url, revision)
}

async fn build(globals: GlobalOptions, rules: Vec<Rule>) -> Result<ServiceConfig, ServiceError> {
    // Configurations from 0.1.0 had no selector and always used AdGuard. New installs
    // use a nonempty sentinel because libuci discards options with empty strings.
    let dns_integration = match globals.dns_integration.as_deref() {
        None | Some("adguard") => DnsIntegration::Adguard,
        Some("dnsmasq") => DnsIntegration::Dnsmasq,
        Some(_) => return Err(UciError::Integration.into()),
    };
    let manage_adguard_upstream = match globals.manage_adguard_upstream.as_deref() {
        None | Some("0") => false,
        Some("1") => true,
        Some(_) => return Err(UciError::Options.into()),
    };
    let lan = network(&globals.lan_network).await?;
    let wan = network(&globals.wan_network).await?;
    let ipv6 = ipv6_settings(
        globals.ipv6_enabled.as_deref(),
        globals.wan6_network.as_deref(),
        lan.l3_device.as_deref().ok_or(UciError::Network)?,
    )
    .await?;
    let mut networks = Vec::new();
    for address in lan.addresses {
        networks.push(
            Ipv4Net::new(address.address, address.mask)
                .map_err(|_| UciError::Network)?
                .trunc(),
        );
    }
    networks.sort();
    networks.dedup();
    let gateway = wan
        .route
        .into_iter()
        .find(|route| route.target.is_unspecified() && route.mask == 0)
        .and_then(|route| route.nexthop)
        .and_then(|hop| match hop {
            IpAddr::V4(hop) => Some(hop),
            IpAddr::V6(_) => None,
        })
        .filter(|ip| !ip.is_unspecified());
    let upstream = crate::config::parse_resolver_endpoint(&globals.real_upstream)?;
    let adguard = match dns_integration {
        DnsIntegration::Adguard => Some(settings(
            globals.adguard_url,
            globals.adguard_username,
            globals.adguard_password,
            globals.adguard_credentials_revision.as_deref(),
        )?),
        _ => None,
    };
    let mut limits = ResourceLimits::default();
    if let Some(maximum) = globals.max_mappings {
        limits.max_mappings = maximum.parse().map_err(|_| UciError::Options)?;
    }
    if let Some(maximum) = globals.max_mappings_per_rule {
        limits.max_mappings_per_rule = maximum.parse().map_err(|_| UciError::Options)?;
    }
    let dns_port: u16 = globals.dns_port.parse().map_err(|_| UciError::Options)?;
    let proxy_port: u16 = globals.proxy_port.parse().map_err(|_| UciError::Options)?;
    if dns_port == 0 || proxy_port == 0 {
        return Err(UciError::Options.into());
    }
    let config = json!({
        "dns_listen": SocketAddrV4::new(Ipv4Addr::LOCALHOST, dns_port),
        "proxy_listen": SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, proxy_port),
        "real_upstream": upstream,
        "state_file": STATE_FILE,
        "status_file": STATUS_FILE,
        "fake_range": globals.fake_range.unwrap_or_else(|| "198.18.0.0/15".into()),
        "lan_device": lan.l3_device.ok_or(UciError::Network)?,
        "lan_networks": networks,
        "trusted_clients": globals.trusted_clients,
        "wan": {
            "device": wan.l3_device.ok_or(UciError::Network)?, "gateway": gateway,
            "route_table": ROUTE_TABLE,
            "mark": ROUTE_MARK,
            "rule_priority": RULE_PRIORITY,
        },
        "ipv6": ipv6,
        "rules": rules, "limits": limits, "adguard": adguard,
        "dns_integration": dns_integration,
        "manage_adguard_upstream": manage_adguard_upstream,
        "adguard_upstream_approval": globals.adguard_upstream_approval,
    });
    let mut result = ServiceConfig::from_json(&serde_json::to_vec(&config)?)?;
    result.from_uci = true;
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn r099_netifd_dual_stack_routes_preserve_ipv4_gateway_and_ignore_ipv6_only_revision_changes()
    -> Result<(), Box<dyn std::error::Error>> {
        let mixed = json!({
            "up":true,"l3_device":"wan0",
            "ipv4-address":[{"address":"198.51.100.2","mask":24}],
            "ipv6-address":[{"address":"2001:db8:10::2","mask":64}],
            "route":[
                {"target":"::","mask":0,"nexthop":"2001:db8:10::1"},
                {"target":"2001:db8:10::","mask":64},
                {"target":"198.51.100.0","mask":24},
                {"target":"0.0.0.0","mask":0,"nexthop":"198.51.100.1"}
            ]
        });
        let normalized = serde_json::from_value::<NetworkStatus>(mixed.clone())?.ipv4()?;
        let expected = json!({
            "up":true,"l3_device":"wan0",
            "ipv4-address":[{"address":"198.51.100.2","mask":24}],
            "route":[
                {"target":"198.51.100.0","mask":24,"nexthop":null},
                {"target":"0.0.0.0","mask":0,"nexthop":"198.51.100.1"}
            ]
        });
        assert_eq!(serde_json::to_value(&normalized)?, expected);
        let mut renumbered = mixed.clone();
        renumbered["route"][0]["nexthop"] = json!("2001:db8:20::1");
        renumbered["route"][1]["target"] = json!("2001:db8:20::");
        renumbered["ipv6-address"][0]["address"] = json!("2001:db8:20::2");
        assert_eq!(
            serde_json::to_value(serde_json::from_value::<NetworkStatus>(renumbered)?.ipv4()?)?,
            expected,
            "an unrelated IPv6 change altered the IPv4 startup/reload fingerprint"
        );
        for (field, value) in [("mask", json!(33)), ("nexthop", json!("2001:db8:10::1"))] {
            let mut invalid = mixed.clone();
            invalid["route"][3][field] = value;
            assert!(
                matches!(
                    serde_json::from_value::<NetworkStatus>(invalid)?.ipv4(),
                    Err(UciError::Network)
                ),
                "a malformed IPv4 route was silently normalized: {field}"
            );
        }
        Ok(())
    }
}
