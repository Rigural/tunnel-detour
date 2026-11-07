use std::{process::Stdio, sync::Arc, time::Duration};

use serde::Deserialize;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    process::Command,
    time::timeout,
};

use crate::{ServiceConfig, ServiceError};

const TABLE: &str = "tunnel_detour";
const OWNER: &str = "tunnel-detour:v1";
const ROUTE_PROTOCOL: &str = "242";

pub(crate) struct CommandOutput {
    pub success: bool,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

async fn bounded_read(
    mut stream: impl AsyncRead + Unpin,
    maximum: u64,
) -> Result<Vec<u8>, ServiceError> {
    let mut bytes = Vec::new();
    (&mut stream)
        .take(maximum + 1)
        .read_to_end(&mut bytes)
        .await?;
    if u64::try_from(bytes.len()).map_err(|_| ServiceError::Protocol)? > maximum {
        return Err(ServiceError::Protocol);
    }
    Ok(bytes)
}

pub(crate) async fn command(
    program: &str,
    args: &[String],
    input: Option<&[u8]>,
) -> Result<CommandOutput, ServiceError> {
    let mut child = Command::new(program)
        .args(args)
        .env("LC_ALL", "C")
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()?;
    let operation = async {
        if let Some(bytes) = input {
            let mut stdin = child.stdin.take().ok_or(ServiceError::Protocol)?;
            stdin.write_all(bytes).await?;
            stdin.shutdown().await?;
        }
        let stdout = child.stdout.take().ok_or(ServiceError::Protocol)?;
        let stderr = child.stderr.take().ok_or(ServiceError::Protocol)?;
        let (stdout, stderr) =
            tokio::try_join!(bounded_read(stdout, 131072), bounded_read(stderr, 16384))?;
        let status = child.wait().await?;
        Ok(CommandOutput {
            success: status.success(),
            stdout,
            stderr,
        })
    };
    timeout(Duration::from_secs(10), operation)
        .await
        .map_err(|_| ServiceError::Timeout)?
}

async fn checked(
    program: &str,
    args: Vec<String>,
    input: Option<&[u8]>,
) -> Result<(), ServiceError> {
    let output = command(program, &args, input).await?;
    if !output.success {
        return Err(ServiceError::KernelCommand {
            detail: String::from_utf8_lossy(&output.stderr).into_owned(),
        });
    }
    Ok(())
}

#[derive(Deserialize)]
struct NftListing {
    nftables: Vec<NftObject>,
}
#[derive(Deserialize)]
struct NftObject {
    table: Option<NftTable>,
}
#[derive(Deserialize)]
struct NftTable {
    family: String,
    name: String,
    handle: Option<u64>,
    comment: Option<String>,
}

#[derive(Clone)]
pub(crate) struct Kernel {
    config: Arc<ServiceConfig>,
}

impl Kernel {
    pub fn new(config: Arc<ServiceConfig>) -> Self {
        Self { config }
    }

    async fn table_handle() -> Result<Option<u64>, ServiceError> {
        let output = command(
            "nft",
            &["-j".into(), "-a".into(), "list".into(), "tables".into()],
            None,
        )
        .await?;
        if !output.success {
            return Err(ServiceError::KernelCommand {
                detail: String::from_utf8_lossy(&output.stderr).into_owned(),
            });
        }
        let listing: NftListing = serde_json::from_slice(&output.stdout)?;
        if !listing.nftables.into_iter().any(|object| {
            object
                .table
                .is_some_and(|table| table.family == "inet" && table.name == TABLE)
        }) {
            return Ok(None);
        }
        let output = command(
            "nft",
            &[
                "-j".into(),
                "-a".into(),
                "list".into(),
                "table".into(),
                "inet".into(),
                TABLE.into(),
            ],
            None,
        )
        .await?;
        if !output.success {
            return Err(ServiceError::KernelConflict);
        }
        let listing: NftListing = serde_json::from_slice(&output.stdout)?;
        for object in listing.nftables {
            if let Some(table) = object.table
                && table.family == "inet"
                && table.name == TABLE
            {
                if table.comment.as_deref() != Some(OWNER) {
                    return Err(ServiceError::KernelConflict);
                }
                return table.handle.map(Some).ok_or(ServiceError::KernelConflict);
            }
        }
        Err(ServiceError::KernelConflict)
    }

    pub async fn install(&self, proxy_port: u16) -> Result<(), ServiceError> {
        // Refuse foreign routing objects before making any changes.
        self.validate_routing_ownership().await?;
        let previous = Self::table_handle().await?;
        let mut rules = String::new();
        if let Some(handle) = previous {
            rules.push_str(&format!("delete table inet handle {handle}\n"));
        }
        let networks = self
            .config
            .lan_networks
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ");
        let range = self.config.fake_range;
        let lan = &self.config.lan_device;
        let wan = &self.config.wan.device;
        let mark = self.config.wan.mark;
        rules.push_str(&format!(r#"table inet {TABLE} {{
 comment "{OWNER}"
 set lan_v4 {{ type ipv4_addr; flags interval; elements = {{ {networks} }} }}
 chain source_guard {{ type filter hook prerouting priority -110; policy accept;
  ip daddr {range} iifname != "{lan}" drop
  ip daddr {range} ip saddr != @lan_v4 drop
 }}
 chain proxy_redirect {{ type nat hook prerouting priority -105; policy accept;
  iifname "{lan}" ip saddr @lan_v4 ip daddr {range} tcp dport {{ 80, 443 }} redirect to :{proxy_port}
 }}
 chain input_guard {{ type filter hook input priority -5; policy accept;
  tcp dport {proxy_port} iifname != "{lan}" reject with tcp reset
  tcp dport {proxy_port} ip saddr != @lan_v4 reject with tcp reset
 }}
 chain forward_guard {{ type filter hook forward priority -5; policy accept;
  ip daddr {range} udp dport 443 reject with icmpx type port-unreachable
  ip daddr {range} reject with icmpx type admin-prohibited
 }}
 chain output_guard {{ type filter hook output priority -5; policy accept;
  ip daddr {range} reject with icmpx type admin-prohibited
  meta mark {mark} oifname != "{wan}" reject with icmpx type admin-prohibited
 }}
}}
"#));
        // One nft transaction replaces only the table whose ownership and handle were verified.
        checked("nft", vec!["-f".into(), "-".into()], Some(rules.as_bytes())).await?;
        let table = self.config.wan.route_table.to_string();
        checked(
            "ip",
            strings(&[
                "-4",
                "route",
                "replace",
                "unreachable",
                "default",
                "metric",
                "32767",
                "proto",
                ROUTE_PROTOCOL,
                "table",
                &table,
            ]),
            None,
        )
        .await?;
        if let Some(gateway) = self.config.wan.gateway {
            let gateway = gateway.to_string();
            checked(
                "ip",
                strings(&[
                    "-4",
                    "route",
                    "replace",
                    &format!("{gateway}/32"),
                    "dev",
                    wan,
                    "scope",
                    "link",
                    "proto",
                    ROUTE_PROTOCOL,
                    "table",
                    &table,
                ]),
                None,
            )
            .await?;
            checked(
                "ip",
                strings(&[
                    "-4",
                    "route",
                    "replace",
                    "default",
                    "via",
                    &gateway,
                    "dev",
                    wan,
                    "metric",
                    "10",
                    "proto",
                    ROUTE_PROTOCOL,
                    "table",
                    &table,
                ]),
                None,
            )
            .await?;
        } else {
            checked(
                "ip",
                strings(&[
                    "-4",
                    "route",
                    "replace",
                    "default",
                    "dev",
                    wan,
                    "metric",
                    "10",
                    "proto",
                    ROUTE_PROTOCOL,
                    "table",
                    &table,
                ]),
                None,
            )
            .await?;
        }
        if !self.owned_rule_exists().await? {
            checked(
                "ip",
                strings(&[
                    "-4",
                    "rule",
                    "add",
                    "priority",
                    &self.config.wan.rule_priority.to_string(),
                    "fwmark",
                    &mark.to_string(),
                    "lookup",
                    &table,
                    "protocol",
                    ROUTE_PROTOCOL,
                ]),
                None,
            )
            .await?;
        }
        Ok(())
    }

    async fn owned_rule_exists(&self) -> Result<bool, ServiceError> {
        RoutingOwner::from_config(&self.config)
            .owned_rule_exists()
            .await
    }

    async fn validate_routing_ownership(&self) -> Result<(), ServiceError> {
        RoutingOwner::from_config(&self.config)
            .validate_routing_ownership()
            .await
    }

    pub async fn stop_routes(&self) -> Result<(), ServiceError> {
        RoutingOwner::from_config(&self.config).stop_routes().await
    }

    pub(crate) async fn uninstall() -> Result<(), ServiceError> {
        RoutingOwner::production().stop_routes().await?;
        if let Some(handle) = Self::table_handle().await? {
            checked(
                "nft",
                strings(&["delete", "table", "inet", "handle", &handle.to_string()]),
                None,
            )
            .await?;
        }
        Ok(())
    }
}

struct RoutingOwner {
    route_table: u32,
    mark: u32,
    rule_priority: u32,
}

impl RoutingOwner {
    fn from_config(config: &ServiceConfig) -> Self {
        Self {
            route_table: config.wan.route_table,
            mark: config.wan.mark,
            rule_priority: config.wan.rule_priority,
        }
    }

    fn production() -> Self {
        Self {
            route_table: crate::uci::ROUTE_TABLE,
            mark: crate::uci::ROUTE_MARK,
            rule_priority: crate::uci::RULE_PRIORITY,
        }
    }

    async fn routing_rules(&self) -> Result<Vec<serde_json::Value>, ServiceError> {
        let output = command("ip", &strings(&["-j", "-N", "-4", "rule", "show"]), None).await?;
        if !output.success {
            return Err(ServiceError::KernelConflict);
        }
        Ok(serde_json::from_slice(&output.stdout)?)
    }

    async fn owned_rule_exists(&self) -> Result<bool, ServiceError> {
        let mut found = false;
        for rule in self.routing_rules().await? {
            if rule["priority"].as_u64() == Some(u64::from(self.rule_priority)) {
                let mark = rule["fwmark"].as_str().and_then(parse_number);
                let table = number(&rule["table"]);
                let protocol = number(&rule["protocol"]);
                let full_mask = rule
                    .get("fwmask")
                    .is_none_or(|value| number(value) == Some(u64::from(u32::MAX)));
                if mark != Some(u64::from(self.mark))
                    || table != Some(u64::from(self.route_table))
                    || protocol != Some(242)
                    || !full_mask
                    || found
                {
                    return Err(ServiceError::KernelConflict);
                }
                found = true;
            }
        }
        Ok(found)
    }

    async fn validate_routing_ownership(&self) -> Result<(), ServiceError> {
        self.owned_rule_exists().await?;
        let output = command(
            "ip",
            &strings(&[
                "-j",
                "-N",
                "-4",
                "route",
                "show",
                "table",
                &self.route_table.to_string(),
            ]),
            None,
        )
        .await?;
        if !output.success {
            if String::from_utf8_lossy(&output.stderr).contains("FIB table does not exist") {
                return Ok(());
            }
            return Err(ServiceError::KernelConflict);
        }
        let routes: Vec<serde_json::Value> = serde_json::from_slice(&output.stdout)?;
        if routes
            .iter()
            .any(|route| number(&route["protocol"]) != Some(242))
        {
            return Err(ServiceError::KernelConflict);
        }
        Ok(())
    }

    pub async fn stop_routes(&self) -> Result<(), ServiceError> {
        self.validate_routing_ownership().await?;
        if self.owned_rule_exists().await? {
            checked(
                "ip",
                strings(&[
                    "-4",
                    "rule",
                    "del",
                    "priority",
                    &self.rule_priority.to_string(),
                    "fwmark",
                    &self.mark.to_string(),
                    "lookup",
                    &self.route_table.to_string(),
                    "protocol",
                    ROUTE_PROTOCOL,
                ]),
                None,
            )
            .await?;
        }
        checked(
            "ip",
            strings(&[
                "-4",
                "route",
                "flush",
                "table",
                &self.route_table.to_string(),
                "proto",
                ROUTE_PROTOCOL,
            ]),
            None,
        )
        .await
    }
}

fn strings(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}
fn parse_number(value: &str) -> Option<u64> {
    match value.strip_prefix("0x") {
        Some(hex) => u64::from_str_radix(hex, 16).ok(),
        None => value.parse().ok(),
    }
}
fn number(value: &serde_json::Value) -> Option<u64> {
    value
        .as_u64()
        .or_else(|| value.as_str().and_then(parse_number))
}
