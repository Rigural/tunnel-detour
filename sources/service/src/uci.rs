use std::{
    collections::BTreeMap,
    net::{Ipv4Addr, SocketAddrV4},
};

use ipnet::Ipv4Net;
use serde::Deserialize;
use serde_json::{Value, json};
use thiserror::Error;
use tunnel_detour_core::{DomainPattern, Rule};

use crate::{
    ServiceConfig, ServiceError,
    config::{AdguardSettings, ResourceLimits},
    kernel,
};

pub(crate) const STATE_FILE: &str = "/etc/tunnel-detour/leases.json";
pub(crate) const STATUS_FILE: &str = "/var/run/tunnel-detour/status.json";
pub(crate) const ROUTE_TABLE: u32 = 41872;
pub(crate) const ROUTE_MARK: u32 = 21572;
pub(crate) const RULE_PRIORITY: u32 = 11000;

#[derive(Debug, Error)]
pub enum UciError {
    #[error(
        "UCI configuration must contain exactly one globals section and only exception sections"
    )]
    Sections,
    #[error("UCI options have an invalid type or value")]
    Options,
    #[error("UCI configuration could not be read through ubus")]
    Read,
    #[error("the selected LAN or WAN network is not up with IPv4 configuration")]
    Network,
    #[error("logical network names must use ASCII letters, digits, underscores, dots or hyphens")]
    NetworkName,
}

#[derive(Deserialize)]
struct UciResponse {
    values: BTreeMap<String, Section>,
}
#[derive(Deserialize)]
struct Section {
    #[serde(rename = ".type")]
    kind: String,
    #[serde(flatten)]
    options: BTreeMap<String, Value>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GlobalOptions {
    #[serde(rename = "enabled")]
    _enabled: String,
    lan_network: String,
    wan_network: String,
    dns_port: String,
    proxy_port: String,
    #[serde(default)]
    real_upstream: String,
    adguard_url: String,
    #[serde(default)]
    adguard_username: String,
    #[serde(default)]
    adguard_password: String,
    #[serde(default)]
    fake_range: Option<String>,
    #[serde(default)]
    max_mappings: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExceptionOptions {
    pattern: DomainPattern,
    enabled: String,
}

#[derive(Deserialize)]
struct NetworkStatus {
    up: bool,
    l3_device: Option<String>,
    #[serde(rename = "ipv4-address", default)]
    addresses: Vec<Address>,
    #[serde(default)]
    route: Vec<Route>,
}
#[derive(Deserialize)]
struct Address {
    address: Ipv4Addr,
    mask: u8,
}
#[derive(Deserialize)]
struct Route {
    target: Ipv4Addr,
    mask: u8,
    nexthop: Option<Ipv4Addr>,
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

fn enabled(value: &str) -> Result<bool, UciError> {
    match value {
        "0" => Ok(false),
        "1" => Ok(true),
        _ => Err(UciError::Options),
    }
}

fn section_options(mut section: Section) -> Result<Value, ServiceError> {
    // Dot-prefixed keys are ubus's UCI section metadata, not user configuration options.
    section.options.retain(|name, _| !name.starts_with('.'));
    Ok(serde_json::to_value(section.options)?)
}

async fn network(name: &str) -> Result<NetworkStatus, ServiceError> {
    if name.is_empty()
        || name.len() > 31
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
    {
        return Err(UciError::NetworkName.into());
    }
    let response = ubus(&format!("network.interface.{name}"), "status", json!({})).await?;
    let status: NetworkStatus = serde_json::from_slice(&response)?;
    if !status.up || status.l3_device.is_none() || status.addresses.is_empty() {
        return Err(UciError::Network.into());
    }
    Ok(status)
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
            _ => return Err(UciError::Sections.into()),
        }
    }
    build(globals, rules).await.map(Some)
}

async fn read_sections() -> Result<UciResponse, ServiceError> {
    Ok(serde_json::from_slice(
        &ubus("uci", "get", json!({"config":"tunnel-detour"})).await?,
    )?)
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

pub(crate) async fn cleanup_settings() -> Result<AdguardSettings, ServiceError> {
    #[derive(Deserialize)]
    struct ControlOptions {
        adguard_url: String,
        #[serde(default)]
        adguard_username: String,
        #[serde(default)]
        adguard_password: String,
    }
    // Cleanup must remain usable when a rule or a network option prevents startup.
    let globals = take_globals(&mut read_sections().await?)?;
    let globals: ControlOptions = serde_json::from_value(section_options(globals)?)?;
    let settings = settings(
        globals.adguard_url,
        globals.adguard_username,
        globals.adguard_password,
    );
    settings.endpoint()?;
    Ok(settings)
}

fn settings(api_url: String, username: String, password: String) -> AdguardSettings {
    let authenticated = !username.is_empty() || !password.is_empty();
    AdguardSettings {
        api_url,
        username: authenticated.then_some(username),
        password: authenticated.then_some(password),
    }
}

async fn build(globals: GlobalOptions, rules: Vec<Rule>) -> Result<ServiceConfig, ServiceError> {
    let lan = network(&globals.lan_network).await?;
    let wan = network(&globals.wan_network).await?;
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
        .filter(|ip| !ip.is_unspecified());
    let upstream = match globals.real_upstream.parse::<SocketAddrV4>() {
        Ok(address) => address,
        Err(_) => SocketAddrV4::new(
            globals
                .real_upstream
                .parse()
                .map_err(|_| UciError::Options)?,
            53,
        ),
    };
    let adguard = settings(
        globals.adguard_url,
        globals.adguard_username,
        globals.adguard_password,
    );
    let mut limits = ResourceLimits::default();
    if let Some(maximum) = globals.max_mappings {
        limits.max_mappings = maximum.parse().map_err(|_| UciError::Options)?;
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
        "wan": {
            "device": wan.l3_device.ok_or(UciError::Network)?, "gateway": gateway,
            "route_table": ROUTE_TABLE,
            "mark": ROUTE_MARK,
            "rule_priority": RULE_PRIORITY,
        },
        "rules": rules, "limits": limits, "adguard": adguard,
    });
    let mut result = ServiceConfig::from_json(&serde_json::to_vec(&config)?)?;
    result.from_uci = true;
    Ok(result)
}
