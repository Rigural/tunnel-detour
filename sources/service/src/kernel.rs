use std::{process::Stdio, sync::Arc, time::Duration};

use serde::Deserialize;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    process::Command,
    time::timeout,
};

use crate::{ServiceConfig, ServiceError};

const TABLE: &str = "tunnel_detour";
const OWNER: &str = "tunnel-detour:v2";
const LEGACY_OWNER: &str = "tunnel-detour:v1";
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
    command_with_limit(program, args, input, 131072).await
}

pub(crate) async fn command_with_limit(
    program: &str,
    args: &[String],
    input: Option<&[u8]>,
    stdout_limit: u64,
) -> Result<CommandOutput, ServiceError> {
    if stdout_limit > 4 * 1024 * 1024 {
        return Err(ServiceError::Protocol);
    }
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
        let (stdout, stderr) = tokio::try_join!(
            bounded_read(stdout, stdout_limit),
            bounded_read(stderr, 16384)
        )?;
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

pub(crate) async fn checked(
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
    ipv6_routing: Option<Arc<crate::ipv6_routing::Ipv6Routing>>,
}

impl Kernel {
    pub fn new(
        config: Arc<ServiceConfig>,
        ipv6_routing: Option<Arc<crate::ipv6_routing::Ipv6Routing>>,
    ) -> Self {
        Self {
            config,
            ipv6_routing,
        }
    }

    /// Replace only the DNS egress chain, atomically retaining the previous path
    /// until frontend reconciliation has either completed or been recovered.
    pub(crate) async fn resolver_guards(
        &self,
        paths: &[crate::upstream_route::ResolverPath],
    ) -> Result<(), ServiceError> {
        if paths.is_empty() || paths.len() > 2 || Self::table_handle().await?.is_none() {
            return Err(ServiceError::KernelConflict);
        }
        let mut rules = format!("flush chain inet {TABLE} resolver_guard\n");
        for (index, path) in paths.iter().enumerate() {
            if paths[..index].contains(path) {
                continue;
            }
            for rule in path.guard_rules().lines() {
                rules.push_str(&format!(
                    "add rule inet {TABLE} resolver_guard {}\n",
                    rule.trim()
                ));
            }
        }
        checked("nft", vec!["-f".into(), "-".into()], Some(rules.as_bytes())).await
    }

    async fn table_handle() -> Result<Option<u64>, ServiceError> {
        match Self::table_handle_for(TABLE, OWNER).await {
            Err(ServiceError::KernelConflict) => Self::table_handle_for(TABLE, LEGACY_OWNER).await,
            result => result,
        }
    }

    async fn previous_resolver_guards(
        handle: u64,
    ) -> Result<Vec<crate::upstream_route::ResolverPath>, ServiceError> {
        let output = command(
            "nft",
            &strings(&["-j", "-a", "list", "table", "inet", TABLE]),
            None,
        )
        .await?;
        if !output.success {
            return Err(ServiceError::KernelConflict);
        }
        let listing: serde_json::Value = serde_json::from_slice(&output.stdout)?;
        let objects = listing["nftables"]
            .as_array()
            .ok_or(ServiceError::KernelConflict)?;
        let tables: Vec<_> = objects
            .iter()
            .filter_map(|object| object.get("table"))
            .collect();
        let [table] = tables.as_slice() else {
            return Err(ServiceError::KernelConflict);
        };
        if table["name"] != TABLE
            || table["family"] != "inet"
            || table["handle"] != handle
            || !matches!(table["comment"].as_str(), Some(OWNER | LEGACY_OWNER))
        {
            return Err(ServiceError::KernelConflict);
        }
        let has_guard = objects
            .iter()
            .any(|object| object["chain"]["name"] == "resolver_guard");
        if table["comment"] == LEGACY_OWNER && !has_guard {
            return Ok(Vec::new());
        }
        crate::upstream_route::decode_guard_table(&listing)
    }

    pub(crate) async fn table_handle_for(
        table_name: &str,
        owner: &str,
    ) -> Result<Option<u64>, ServiceError> {
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
        for object in listing.nftables {
            if let Some(table) = object.table
                && table.family == "inet"
                && table.name == table_name
            {
                if table.comment.as_deref() != Some(owner) {
                    return Err(ServiceError::KernelConflict);
                }
                return table.handle.map(Some).ok_or(ServiceError::KernelConflict);
            }
        }
        Ok(None)
    }

    pub async fn install(
        &self,
        proxy_port: u16,
        resolver: &crate::upstream_route::ResolverPath,
    ) -> Result<(), ServiceError> {
        // Refuse foreign routing objects before making any changes.
        self.validate_routing_ownership().await?;
        let (previous, resolver_paths) = Self::resolver_transition(resolver).await?;
        let mut rules = String::new();
        if let Some(handle) = previous {
            rules.push_str(&format!("delete table inet handle {handle}\n"));
        }
        self.install_owned_rules(proxy_port, resolver_paths, rules)
            .await?;
        if let Some(routing) = &self.ipv6_routing {
            routing
                .install(self.config.ipv6.as_ref().map(|settings| &settings.wan))
                .await?;
        }
        Ok(())
    }

    pub(crate) async fn check_resolver_transition(
        resolver: &crate::upstream_route::ResolverPath,
    ) -> Result<(), ServiceError> {
        Self::resolver_transition(resolver).await.map(|_| ())
    }

    async fn resolver_transition(
        resolver: &crate::upstream_route::ResolverPath,
    ) -> Result<(Option<u64>, Vec<crate::upstream_route::ResolverPath>), ServiceError> {
        let previous = Self::table_handle().await?;
        let mut resolver_paths = match previous {
            Some(handle) => Self::previous_resolver_guards(handle).await?,
            None => Vec::new(),
        };
        if !resolver_paths.contains(resolver) {
            if resolver_paths.len() >= 2 {
                return Err(ServiceError::ResolverRecovery {
                    allowed: resolver_paths.iter().map(|path| path.endpoint).collect(),
                });
            }
            resolver_paths.push(resolver.clone());
        }
        Ok((previous, resolver_paths))
    }

    async fn install_owned_rules(
        &self,
        proxy_port: u16,
        resolver_paths: Vec<crate::upstream_route::ResolverPath>,
        mut rules: String,
    ) -> Result<(), ServiceError> {
        let networks = self
            .config
            .lan_networks
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ");
        let range = self.config.fake_range;
        let range6 = range.ipv6_range();
        let lan = &self.config.lan_device;
        let wan = &self.config.wan.device;
        let mark = self.config.wan.mark;
        let (set6, source6, redirect6, input6, output6) = match &self.config.ipv6 {
            Some(ipv6) => {
                let networks = ipv6
                    .lan_networks
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(", ");
                let wan6 = &ipv6.wan.device;
                let source = ipv6.wan.source;
                (
                    format!(
                        "set lan_v6 {{ type ipv6_addr; flags interval; elements = {{ {networks} }} }}"
                    ),
                    format!(
                        "ip6 daddr {range6} iifname != \"{lan}\" drop\n ip6 daddr {range6} ip6 saddr != @lan_v6 drop"
                    ),
                    format!(
                        "iifname \"{lan}\" ip6 saddr @lan_v6 ip6 daddr {range6} tcp dport {{ 80, 443 }} redirect to :{proxy_port}"
                    ),
                    format!(
                        "meta nfproto ipv6 tcp dport {proxy_port} iifname != \"{lan}\" reject with tcp reset\n tcp dport {proxy_port} ip6 saddr != @lan_v6 reject with tcp reset"
                    ),
                    format!(
                        "meta nfproto ipv6 meta mark {mark} oifname != \"{wan6}\" reject with icmpx type admin-prohibited\n meta mark {mark} ip6 saddr != {source} reject with icmpx type admin-prohibited"
                    ),
                )
            }
            None => (
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
            ),
        };
        let resolver_rules = resolver_paths
            .iter()
            .map(|path| path.guard_rules())
            .collect::<String>();
        rules.push_str(&format!(r#"table inet {TABLE} {{
 comment "{OWNER}"
 set lan_v4 {{ type ipv4_addr; flags interval; elements = {{ {networks} }} }}
 {set6}
 chain source_guard {{ type filter hook prerouting priority -110; policy accept;
  ip daddr {range} iifname != "{lan}" drop
  ip daddr {range} ip saddr != @lan_v4 drop
  {source6}
 }}
 chain proxy_redirect {{ type nat hook prerouting priority -105; policy accept;
  iifname "{lan}" ip saddr @lan_v4 ip daddr {range} tcp dport {{ 80, 443 }} redirect to :{proxy_port}
  {redirect6}
 }}
 chain input_guard {{ type filter hook input priority -5; policy accept;
  meta nfproto ipv4 tcp dport {proxy_port} iifname != "{lan}" reject with tcp reset
  tcp dport {proxy_port} ip saddr != @lan_v4 reject with tcp reset
  {input6}
 }}
 chain forward_guard {{ type filter hook forward priority -5; policy accept;
  ip daddr {range} udp dport 443 reject with icmpx type port-unreachable
  ip daddr {range} reject with icmpx type admin-prohibited
  ip6 daddr {range6} udp dport 443 reject with icmpx type port-unreachable
  ip6 daddr {range6} reject with icmpx type admin-prohibited
 }}
 chain output_guard {{ type filter hook output priority -5; policy accept;
  ip daddr {range} reject with icmpx type admin-prohibited
  ip6 daddr {range6} reject with icmpx type admin-prohibited
  meta nfproto ipv4 meta mark {mark} oifname != "{wan}" reject with icmpx type admin-prohibited
  {output6}
 }}
 chain resolver_guard {{ type filter hook output priority -6; policy accept;
{resolver_rules} }}
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

    pub(crate) async fn owned_rule_exists(&self) -> Result<bool, ServiceError> {
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
        let ipv4 = RoutingOwner::from_config(&self.config).stop_routes().await;
        let ipv6 = match &self.ipv6_routing {
            Some(routing) => routing.stop().await,
            None => Ok(()),
        };
        if let Err(error) = ipv4 {
            if let Err(cleanup) = ipv6 {
                tracing::error!(code = cleanup.code(), "IPv6 routing cleanup also failed");
            }
            return Err(error);
        }
        ipv6
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

pub(crate) struct RoutingOwner {
    family: &'static str,
    route_table: u32,
    mark: u32,
    mask: u32,
    rule_priority: u32,
    allow_existing: bool,
}

impl RoutingOwner {
    pub(crate) fn exception_ipv6(
        table: u32,
        mark: u32,
        priority: u32,
        allow_existing: bool,
    ) -> Self {
        Self {
            family: "-6",
            route_table: table,
            mark,
            mask: u32::MAX,
            rule_priority: priority,
            allow_existing,
        }
    }
    fn from_config(config: &ServiceConfig) -> Self {
        Self {
            family: "-4",
            route_table: config.wan.route_table,
            mark: config.wan.mark,
            mask: u32::MAX,
            rule_priority: config.wan.rule_priority,
            allow_existing: true,
        }
    }

    fn production() -> Self {
        Self {
            family: "-4",
            route_table: crate::uci::ROUTE_TABLE,
            mark: crate::uci::ROUTE_MARK,
            mask: u32::MAX,
            rule_priority: crate::uci::RULE_PRIORITY,
            allow_existing: true,
        }
    }

    pub(crate) fn inbound(config: &crate::InboundConfig, allow_existing: bool) -> Self {
        Self {
            family: "-6",
            route_table: config.wan.route_table,
            mark: config.wan.mark_prefix,
            mask: 0xffff0000,
            rule_priority: config.wan.rule_priority,
            allow_existing,
        }
    }

    async fn routing_rules(&self) -> Result<Vec<serde_json::Value>, ServiceError> {
        let output = command(
            "ip",
            &strings(&["-j", "-N", self.family, "rule", "show"]),
            None,
        )
        .await?;
        if !output.success {
            return Err(ServiceError::KernelConflict);
        }
        Ok(serde_json::from_slice(&output.stdout)?)
    }

    pub(crate) async fn owned_rule_exists(&self) -> Result<bool, ServiceError> {
        let mut found = false;
        for rule in self.routing_rules().await? {
            if self.mask != u32::MAX
                && let Some(priority) = rule["priority"].as_u64()
            {
                // Native return traffic must reach this owner before a VPN policy can
                // select another table. Keep the ordinary local-address rule first.
                if (priority > 0 && priority < u64::from(self.rule_priority))
                    || (priority == 0 && number(&rule["table"]) != Some(255))
                {
                    return Err(ServiceError::KernelConflict);
                }
            }
            if rule["priority"].as_u64() == Some(u64::from(self.rule_priority)) {
                let mark = rule["fwmark"].as_str().and_then(parse_number);
                let table = number(&rule["table"]);
                let protocol = number(&rule["protocol"]);
                let correct_mask = rule.get("fwmask").map_or(self.mask == u32::MAX, |value| {
                    number(value) == Some(u64::from(self.mask))
                });
                if mark != Some(u64::from(self.mark))
                    || table != Some(u64::from(self.route_table))
                    || protocol != Some(242)
                    || !correct_mask
                    || found
                    || !self.allow_existing
                {
                    return Err(ServiceError::KernelConflict);
                }
                found = true;
            }
        }
        Ok(found)
    }

    pub(crate) async fn validate_routing_ownership(&self) -> Result<(), ServiceError> {
        self.owned_rule_exists().await?;
        let routes = self.routing_routes().await?;
        if (!self.allow_existing && !routes.is_empty())
            || routes
                .iter()
                .any(|route| number(&route["protocol"]) != Some(242))
        {
            return Err(ServiceError::KernelConflict);
        }
        Ok(())
    }

    pub(crate) async fn routing_routes(&self) -> Result<Vec<serde_json::Value>, ServiceError> {
        let output = command(
            "ip",
            &strings(&[
                "-j",
                "-N",
                self.family,
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
                return Ok(Vec::new());
            }
            return Err(ServiceError::KernelConflict);
        }
        Ok(serde_json::from_slice(&output.stdout)?)
    }

    pub async fn stop_routes(&self) -> Result<(), ServiceError> {
        self.validate_routing_ownership().await?;
        if self.owned_rule_exists().await? {
            checked(
                "ip",
                strings(&[
                    self.family,
                    "rule",
                    "del",
                    "priority",
                    &self.rule_priority.to_string(),
                    "fwmark",
                    &if self.mask == u32::MAX {
                        self.mark.to_string()
                    } else {
                        format!("{}/{}", self.mark, self.mask)
                    },
                    "lookup",
                    &self.route_table.to_string(),
                    "protocol",
                    ROUTE_PROTOCOL,
                ]),
                None,
            )
            .await?;
        }
        // IPv6 reports ENOENT when flushing a FIB which has never contained a
        // route. Confirm actual absence rather than turning it into a failure.
        if self.routing_routes().await?.is_empty() {
            return Ok(());
        }
        checked(
            "ip",
            strings(&[
                self.family,
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
pub(crate) fn number(value: &serde_json::Value) -> Option<u64> {
    value
        .as_u64()
        .or_else(|| value.as_str().and_then(parse_number))
}
