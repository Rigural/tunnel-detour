//! Native inbound packet policy. Redirects themselves belong to firewall4/UCI.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs::OpenOptions,
    os::unix::fs::OpenOptionsExt,
    process::Stdio,
    time::Duration,
};

use crate::{
    InboundConfig, InboundRuntimeError, ServiceError,
    kernel::{Kernel, RoutingOwner, checked, command},
};
use tunnel_detour_core::{INBOUND_INTERNET_V6, InboundAccess, InboundId};

pub(crate) const TABLE: &str = "tunnel_detour_inbound";
pub(crate) const OWNER: &str = "tunnel-detour:inbound:v1";
pub(crate) type Admissions = BTreeMap<InboundId, u16>;

pub(crate) struct InboundKernel<'a> {
    config: &'a InboundConfig,
}

fn args(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).into()).collect()
}

async fn purge_conntrack(mark: String) -> Result<(), ServiceError> {
    // Tuples can contain private traffic. Discard deletion output at the source.
    let mut child = tokio::process::Command::new("conntrack")
        .args(["-D", "--family", "ipv6", "--mark", &mark])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()?;
    let status = tokio::time::timeout(Duration::from_secs(10), child.wait())
        .await
        .map_err(|_| ServiceError::Timeout)??;
    // conntrack may report no matches with exit 1; verify the postcondition.
    if !status.success() && status.code() != Some(1) {
        return Err(InboundRuntimeError::Conntrack.into());
    }
    let listing = command(
        "conntrack",
        &args(&["-L", "--family", "ipv6", "--mark", &mark]),
        None,
    )
    .await?;
    if !listing.success || !listing.stdout.is_empty() {
        return Err(InboundRuntimeError::Conntrack.into());
    }
    Ok(())
}

async fn nft_listing(options: &[&str]) -> Result<Vec<u8>, ServiceError> {
    let output =
        crate::kernel::command_with_limit("nft", &args(options), None, 4 * 1024 * 1024).await?;
    if !output.success {
        return Err(ServiceError::KernelConflict);
    }
    Ok(output.stdout)
}

/// Read only the pinned firewall4 software flowtable and its canonical user.
/// Kernel validation refuses deletion if another live rule references the table.
async fn replace_software_flowtable() -> Result<String, ServiceError> {
    let definition =
        String::from_utf8(nft_listing(&["-s", "list", "flowtable", "inet", "fw4", "ft"]).await?)
            .map_err(|_| ServiceError::KernelConflict)?;
    let mut definition = definition.lines().map(str::trim);
    if !definition.any(|line| line == "flowtable ft {") {
        return Err(ServiceError::KernelConflict);
    }
    let mut flowtable = String::from("delete flowtable inet fw4 ft\nadd flowtable inet fw4 ft {\n");
    loop {
        let line = definition.next().ok_or(ServiceError::KernelConflict)?;
        if line.starts_with("flags ") {
            return Err(ServiceError::KernelConflict);
        }
        flowtable.push_str(line);
        flowtable.push('\n');
        if line == "}" {
            break;
        }
    }
    let rules: serde_json::Value = serde_json::from_slice(
        &nft_listing(&["-j", "-s", "-a", "list", "chain", "inet", "fw4", "forward"]).await?,
    )
    .map_err(|_| ServiceError::KernelConflict)?;
    let objects = rules["nftables"]
        .as_array()
        .ok_or(ServiceError::KernelConflict)?;
    let mut rules = objects.iter().filter_map(|object| object.get("rule"));
    // In the pinned template offload is the first rule. An administrator may
    // prepend a rule, but only the unmodified native expression can be replaced.
    let canonical = |rule: &serde_json::Value| {
        let Some([filter, action]) = rule["expr"].as_array().map(Vec::as_slice) else {
            return false;
        };
        let filter = &filter["match"];
        rule.get("comment").is_none()
            && filter["op"] == "=="
            && filter["left"]["meta"]["key"] == "l4proto"
            && filter["right"]["set"].as_array().is_some_and(|set| {
                set.len() == 2
                    && set.contains(&serde_json::json!("tcp"))
                    && set.contains(&serde_json::json!("udp"))
            })
            && action["flow"]["flowtable"] == "@ft"
    };
    let rule = rules
        .find(|rule| canonical(rule))
        .ok_or(ServiceError::KernelConflict)?;
    let next = rules.next();
    let handle = rule["handle"]
        .as_u64()
        .ok_or(ServiceError::KernelConflict)?;
    let mut transaction = format!("delete rule inet fw4 forward handle {handle}\n{flowtable}");
    let expr = "meta l4proto { tcp, udp } flow offload @ft";
    if let Some(next) = next {
        let anchor = next["handle"]
            .as_u64()
            .ok_or(ServiceError::KernelConflict)?;
        transaction.push_str(&format!(
            "insert rule inet fw4 forward position {anchor} {expr}\n"
        ));
    } else {
        transaction.push_str(&format!("add rule inet fw4 forward {expr}\n"));
    }
    Ok(transaction)
}

pub(crate) async fn lock_firewall() -> Result<std::fs::File, ServiceError> {
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(
            i32::try_from((rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits())
                .map_err(|_| ServiceError::KernelConflict)?,
        )
        .open("/var/run/fw4.lock")?;
    if !lock.metadata()?.is_file() {
        return Err(ServiceError::KernelConflict);
    }
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            match lock.try_lock() {
                Ok(()) => return Ok::<(), std::io::Error>(()),
                Err(std::fs::TryLockError::WouldBlock) => {
                    tokio::time::sleep(Duration::from_millis(25)).await
                }
                Err(std::fs::TryLockError::Error(error)) => return Err(error),
            }
        }
    })
    .await
    .map_err(|_| ServiceError::Timeout)??;
    Ok(lock)
}

async fn apply_nft(rules: &str) -> Result<(), ServiceError> {
    checked(
        "nft",
        args(&["--check", "--file", "-"]),
        Some(rules.as_bytes()),
    )
    .await?;
    checked("nft", args(&["--file", "-"]), Some(rules.as_bytes())).await
}

fn route_type(value: Option<&serde_json::Value>, number: u64, name: &str) -> bool {
    // ip -N emits Linux rtnetlink RTN_* values, including string-valued "7" for
    // RTN_UNREACHABLE. Older listings use names; absent type means RTN_UNICAST (1).
    value.map_or(number == 1, |value| {
        value.as_u64() == Some(number)
            || value.as_str() == Some(name)
            || value
                .as_str()
                .is_some_and(|value| value.parse::<u64>().ok() == Some(number))
    })
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum OwnedRoute {
    ClosedDefault,
    WanDefault,
    WanGateway,
    Lan(ipnet::IpNet),
}

fn owned_route(
    route: &serde_json::Value,
    config: &InboundConfig,
) -> Result<Option<OwnedRoute>, ServiceError> {
    let destination = route["dst"].as_str().ok_or(ServiceError::KernelConflict)?;
    let device = route["dev"].as_str();
    let gateway = route["gateway"].as_str();
    let metric = route["metric"].as_u64();
    let unicast = route_type(route.get("type"), 1, "unicast");
    if destination == "default" {
        if route_type(route.get("type"), 7, "unreachable")
            && gateway.is_none()
            && metric == Some(32767)
        {
            return Ok(Some(OwnedRoute::ClosedDefault));
        }
        return Ok((unicast
            && device == Some(config.wan.device.as_str())
            && gateway == Some(config.wan.gateway.to_string().as_str())
            && metric == Some(10))
        .then_some(OwnedRoute::WanDefault));
    }
    let network: ipnet::IpNet = if destination.contains('/') {
        destination
            .parse()
            .map_err(|_| ServiceError::KernelConflict)?
    } else {
        ipnet::IpNet::new(
            destination
                .parse()
                .map_err(|_| ServiceError::KernelConflict)?,
            128,
        )
        .map_err(|_| ServiceError::KernelConflict)?
    };
    if !unicast || gateway.is_some() || metric != Some(1024) {
        return Ok(None);
    }
    if network.addr() == config.wan.gateway
        && network.prefix_len() == 128
        && device == Some(config.wan.device.as_str())
    {
        return Ok(Some(OwnedRoute::WanGateway));
    }
    Ok(
        (config.lan_networks.contains(&network) && device == Some(config.lan_device.as_str()))
            .then_some(OwnedRoute::Lan(network)),
    )
}

impl<'a> InboundKernel<'a> {
    pub(crate) fn new(config: &'a InboundConfig) -> Self {
        Self { config }
    }

    /// A protocol number alone is not ownership. A surviving journal authorizes only the
    /// exact route shapes derivable from its previous network configuration.
    pub(crate) async fn validate_routes(&self) -> Result<(), ServiceError> {
        self.validate_route_contexts(None).await
    }

    pub(crate) async fn validate_route_contexts(
        &self,
        pending: Option<&InboundConfig>,
    ) -> Result<(), ServiceError> {
        self.inspect_routes(pending).await.map(|_| ())
    }

    /// Check that every route and the selecting rule are installed, without repairing loss.
    pub(crate) async fn routes_applied(&self) -> Result<bool, ServiceError> {
        self.inspect_routes(None).await
    }

    async fn inspect_routes(&self, pending: Option<&InboundConfig>) -> Result<bool, ServiceError> {
        let owner = RoutingOwner::inbound(self.config, true);
        let rule = owner.owned_rule_exists().await?;
        let mut expected = BTreeSet::from([
            OwnedRoute::ClosedDefault,
            OwnedRoute::WanDefault,
            OwnedRoute::WanGateway,
        ]);
        expected.extend(self.config.lan_networks.iter().filter_map(|network| {
            matches!(network, ipnet::IpNet::V6(_)).then_some(OwnedRoute::Lan(*network))
        }));
        for route in owner.routing_routes().await? {
            if crate::kernel::number(&route["protocol"]) != Some(242) {
                return Err(ServiceError::KernelConflict);
            }
            if let Some(kind) = owned_route(&route, self.config)? {
                expected.remove(&kind);
            } else if let Some(config) = pending
                && owned_route(&route, config)?.is_some()
            {
                continue;
            } else {
                return Err(ServiceError::KernelConflict);
            }
        }
        Ok(rule && expected.is_empty())
    }

    /// Fingerprint only the stateless owned policy, including the kernel object handles.
    pub(crate) async fn guard_fingerprint(&self) -> Result<String, ServiceError> {
        if Kernel::table_handle_for(TABLE, OWNER).await?.is_none() {
            return Err(ServiceError::KernelConflict);
        }
        let output = crate::kernel::command_with_limit(
            "nft",
            &args(&["--stateless", "--handle", "list", "table", "inet", TABLE]),
            None,
            4 * 1024 * 1024,
        )
        .await?;
        if !output.success {
            return Err(ServiceError::KernelConflict);
        }
        let digest = command("sha256sum", &[], Some(&output.stdout)).await?;
        let digest = std::str::from_utf8(&digest.stdout)
            .ok()
            .filter(|_| digest.success)
            .and_then(|text| text.split_whitespace().next())
            .filter(|text| text.len() == 64 && text.bytes().all(|byte| byte.is_ascii_hexdigit()))
            .ok_or(ServiceError::KernelConflict)?;
        Ok(digest.to_owned())
    }

    /// Close admissions and invalidate accelerated shortcuts without erasing the
    /// retained conntrack marks that keep retired tuples from being reused.
    pub(crate) async fn close(&self) -> Result<(), ServiceError> {
        self.retire_guard(&Admissions::new()).await
    }

    /// Retire affected generations without changing the surviving connections.
    pub(crate) async fn retire(
        &self,
        current: &Admissions,
        retained: &Admissions,
    ) -> Result<(), ServiceError> {
        if current == retained {
            return self.update_guard(retained).await;
        }
        self.retire_guard(retained).await
    }

    async fn retire_guard(&self, admissions: &Admissions) -> Result<(), ServiceError> {
        let attempt = async {
            let _lock = lock_firewall().await?;
            let mut rules = self.guard_rules(admissions).await?;
            if self.software_offload().await? {
                rules.push_str(&replace_software_flowtable().await?);
            }
            apply_nft(&rules).await
        }
        .await;
        if let Err(error) = attempt {
            // Attempt both independent containment measures even if the
            // first fails. Preserve the initiating error and do not expose
            // kernel output in diagnostics.
            let guard = self.update_guard(&Admissions::new()).await;
            let conntrack = self.clear_conntrack().await;
            if guard.is_err() || conntrack.is_err() {
                tracing::error!(
                    target: "tunnel_detour::health",
                    initial = error.code(),
                    guard = guard.as_ref().err().map_or("closed", ServiceError::code),
                    conntrack = conntrack.as_ref().err().map_or("purged", ServiceError::code),
                    "inbound emergency containment could not be fully verified"
                );
            }
            return Err(error);
        }
        Ok(())
    }

    pub(crate) async fn clear_conntrack(&self) -> Result<(), ServiceError> {
        purge_conntrack(format!("{}/0xffff0000", self.config.wan.mark_prefix)).await
    }

    /// Widen only after retired marks have been purged and redirects committed.
    pub(crate) async fn admit(&self, admissions: &Admissions) -> Result<(), ServiceError> {
        if !admissions.is_empty() {
            self.check_offload().await?;
        }
        self.update_guard(admissions).await
    }

    pub(crate) async fn check_offload(&self) -> Result<(), ServiceError> {
        self.software_offload().await.map(|_| ())
    }

    async fn software_offload(&self) -> Result<bool, ServiceError> {
        let tables = command("nft", &args(&["--json", "list", "flowtables"]), None).await?;
        if !tables.success {
            return Err(ServiceError::KernelConflict);
        }
        let tables: serde_json::Value =
            serde_json::from_slice(&tables.stdout).map_err(|_| ServiceError::KernelConflict)?;
        let mut enabled = false;
        for item in tables["nftables"]
            .as_array()
            .ok_or(ServiceError::KernelConflict)?
        {
            if let Some(table) = item.get("flowtable") {
                if table["family"] != "inet"
                    || table["table"] != "fw4"
                    || table["name"] != "ft"
                    || table["flags"]
                        .as_array()
                        .is_some_and(|flags| flags.iter().any(|flag| flag == "offload"))
                {
                    return Err(ServiceError::KernelConflict);
                }
                enabled = true;
            }
        }
        Ok(enabled)
    }

    async fn update_guard(&self, admissions: &Admissions) -> Result<(), ServiceError> {
        apply_nft(&self.guard_rules(admissions).await?).await
    }

    async fn guard_rules(&self, admissions: &Admissions) -> Result<String, ServiceError> {
        let previous = Kernel::table_handle_for(TABLE, OWNER).await?;
        self.rules(admissions, previous)
    }

    fn rules(
        &self,
        admissions: &Admissions,
        previous: Option<u64>,
    ) -> Result<String, ServiceError> {
        let config = self.config;
        let mut rules = String::new();
        if let Some(handle) = previous {
            rules.push_str(&format!("delete table inet handle {handle}\n"));
        }
        let prefix = config.wan.mark_prefix;
        let wan = &config.wan.device;
        let lan = &config.lan_device;
        let addresses = config
            .wan
            .addresses
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ");
        let lan_networks = config
            .lan_networks
            .iter()
            .filter(|network| matches!(network, ipnet::IpNet::V6(_)))
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ");
        let lan_elements = if lan_networks.is_empty() {
            String::new()
        } else {
            format!("elements = {{ {lan_networks} }};")
        };
        rules.push_str(&format!(
            r#"table inet {TABLE} {{
 comment "{OWNER}"
 set public_v6 {{ type ipv6_addr; elements = {{ {addresses} }} }}
 set lan_v6 {{ type ipv6_addr; flags interval; {lan_elements} }}
 chain tag {{ type filter hook prerouting priority -101; policy accept;
"#
        ));
        let mut lan_egress = String::new();
        let mut native_wan_egress = String::new();
        let mut relay_input = String::new();
        let mut relay_egress = String::new();
        let has_relays = config.has_relays();
        for rule in config.rules.rules().iter().filter(|rule| rule.enabled()) {
            let Some(generation) = admissions.get(rule.id()) else {
                continue;
            };
            if *generation == 0 {
                return Err(ServiceError::KernelConflict);
            }
            let mark = prefix | u32::from(*generation);
            for transport in rule.protocol().transports() {
                let transport = transport.as_str();
                let handshake = if transport == "tcp" {
                    "tcp flags & (syn | ack) == syn "
                } else {
                    ""
                };
                // Never overwrite an unrelated conntrack mark or admit LAN access implicitly.
                // An Internet client cannot use a LAN or router source address: its
                // backend reply could otherwise stay on LAN or terminate on the router.
                rules.push_str(&format!("  iifname \"{wan}\" ip6 saddr {INBOUND_INTERNET_V6} ip6 saddr != @lan_v6 fib saddr type != local ip6 daddr @public_v6 ct state new ct mark 0 {handshake}{transport} dport {} ct mark set {mark}\n", rule.public_port()));
                if rule.access() == InboundAccess::WanAndLan {
                    rules.push_str(&format!("  iifname \"{lan}\" ip6 saddr @lan_v6 fib saddr type != local ip6 daddr @public_v6 ct state new ct mark 0 {handshake}{transport} dport {} ct mark set {mark}\n", rule.public_port()));
                }
            }
        }
        rules.push_str(&format!(
            "  ct mark & 0xffff0000 == {prefix} meta mark set ct mark\n }}\n"
        ));
        rules.push_str(&format!(
            r#" chain route_output {{ type route hook output priority -151; policy accept;
  ct mark & 0xffff0000 == {prefix} meta mark set ct mark
 }}
 chain authorized {{
"#
        ));
        for rule in config.rules.rules().iter().filter(|rule| rule.enabled()) {
            let Some(generation) = admissions.get(rule.id()) else {
                continue;
            };
            let destination = rule.destination().endpoint();
            let mark = prefix | u32::from(*generation);
            for transport in rule.protocol().transports() {
                let transport = transport.as_str();
                let original = format!(
                    "ct mark {mark} ct original l3proto ipv6 ct original protocol {transport} ct original ip6 daddr @public_v6 ct original proto-dst {}",
                    rule.public_port()
                );
                if rule.destination().requires_relay() {
                    let port = config.relay.listen_port;
                    // Accept ends this guard's evaluation; firewall4's later base chain
                    // still applies its native redirect and established-flow policy.
                    relay_input.push_str(&format!("  {original} ct direction original iifname \"{wan}\" ip6 saddr {INBOUND_INTERNET_V6} ip6 saddr != @lan_v6 fib saddr type != local tcp dport {port} accept\n"));
                    // Raw type byte avoids nft's inference conflict between the original
                    // TCP tuple and the current ICMPv6 header. The explicit meta protocol
                    // is mandatory: raw expressions add no protocol dependency themselves.
                    // RFC 4443 assigns error types 1 through 4 to this first header byte.
                    relay_input.push_str(&format!("  {original} ct state related meta l4proto ipv6-icmp iifname \"{wan}\" @th,0,8 {{ 1, 2, 3, 4 }} accept\n"));
                    relay_egress.push_str(&format!("  {original} ct direction reply oifname \"{wan}\" ip6 daddr {INBOUND_INTERNET_V6} ip6 daddr != @lan_v6 return\n"));
                    if rule.access() == InboundAccess::WanAndLan {
                        relay_input.push_str(&format!("  {original} ct direction original iifname \"{lan}\" ip6 saddr @lan_v6 fib saddr type != local tcp dport {port} accept\n"));
                        relay_input.push_str(&format!("  {original} ct state related meta l4proto ipv6-icmp iifname \"{lan}\" @th,0,8 {{ 1, 2, 3, 4 }} accept\n"));
                        relay_egress.push_str(&format!("  {original} ct direction reply oifname \"{lan}\" ip6 daddr @lan_v6 return\n"));
                    }
                    continue;
                }
                lan_egress.push_str(&format!("  {original} ct direction original oifname \"{lan}\" ip6 daddr {} {transport} dport {} return\n", destination.ip(), destination.port()));
                // The forward guard already checked the native backend before source NAT.
                // Postrouting must also work with an existing administrator's WAN masq6.
                native_wan_egress.push_str(&format!("  {original} ct direction reply oifname \"{wan}\" ct original ip6 saddr != @lan_v6 return\n"));
                native_wan_egress.push_str(&format!("  {original} ct state related meta l4proto ipv6-icmp oifname \"{wan}\" ct original ip6 saddr != @lan_v6 return\n"));
                // Match post-DNAT endpoints as well as the original tuple: an existing NAT
                // mapping must not authorize another host, helper port or changed publication.
                rules.push_str(&format!("  {original} ct direction original iifname \"{wan}\" oifname \"{lan}\" ip6 daddr {} {transport} dport {} return comment \"{}:original\"\n", destination.ip(), destination.port(), rule.id().as_str()));
                rules.push_str(&format!("  {original} ct direction reply iifname \"{lan}\" oifname \"{wan}\" ip6 saddr {} {transport} sport {} return comment \"{}:reply\"\n", destination.ip(), destination.port(), rule.id().as_str()));
                // PMTU and other related ICMPv6 errors carry the admitted flow's tuple.
                rules.push_str(&format!("  {original} ct state related meta l4proto ipv6-icmp iifname \"{wan}\" oifname \"{lan}\" ip6 daddr {} return\n", destination.ip()));
                rules.push_str(&format!("  {original} ct state related meta l4proto ipv6-icmp iifname \"{lan}\" oifname \"{wan}\" return\n"));
                if rule.access() == InboundAccess::WanAndLan {
                    rules.push_str(&format!("  {original} ct direction original iifname \"{lan}\" oifname \"{lan}\" ip6 daddr {} {transport} dport {} return comment \"{}:lan-original\"\n", destination.ip(), destination.port(), rule.id().as_str()));
                    rules.push_str(&format!("  {original} ct direction reply iifname \"{lan}\" oifname \"{lan}\" ip6 saddr {} {transport} sport {} return comment \"{}:lan-reply\"\n", destination.ip(), destination.port(), rule.id().as_str()));
                    rules.push_str(&format!("  {original} ct state related meta l4proto ipv6-icmp iifname \"{lan}\" oifname \"{lan}\" ip6 daddr @lan_v6 return\n"));
                    lan_egress.push_str(&format!("  {original} ct direction reply oifname \"{lan}\" ip6 daddr @lan_v6 return\n"));
                }
            }
        }
        let (relay_chain, relay_jump, wan_egress) = if has_relays {
            (
                format!(
                    " chain relay_authorized {{\n{relay_input}  meta l4proto tcp reject with tcp reset\n  reject with icmpx type admin-prohibited\n }}\n"
                ),
                format!(
                    "  meta nfproto ipv6 tcp dport {} jump relay_authorized\n  ct mark & 0xffff0000 == {prefix} meta l4proto ipv6-icmp jump relay_authorized\n",
                    config.relay.listen_port
                ),
                format!(
                    "{native_wan_egress}{relay_egress}  oifname \"{wan}\" ct original ip6 saddr != @lan_v6 tcp flags & rst == rst return\n  oifname \"{wan}\" ct original ip6 saddr != @lan_v6 ct state related meta l4proto ipv6-icmp icmpv6 type {{ destination-unreachable, packet-too-big, time-exceeded, parameter-problem }} return\n"
                ),
            )
        } else {
            (
                String::new(),
                String::new(),
                format!("  oifname \"{wan}\" ct original ip6 saddr != @lan_v6 return\n"),
            )
        };
        // OUTPUT's hook-state interface still describes the initial route after a route
        // chain changes the mark. POSTROUTING observes the effective egress, including
        // locally generated resets for retired flows, without enabling global mark reflection.
        rules.push_str(&format!(
            r#"  meta l4proto tcp reject with tcp reset
  reject with icmpx type admin-prohibited
 }}
 chain forward_guard {{ type filter hook forward priority -1; policy accept;
  ct mark & 0xffff0000 == {prefix} jump authorized
 }}
{relay_chain} chain input_guard {{ type filter hook input priority -1; policy accept;
{relay_jump}  ct mark & 0xffff0000 == {prefix} meta l4proto tcp reject with tcp reset
  ct mark & 0xffff0000 == {prefix} reject with icmpx type admin-prohibited
 }}
 chain egress_allowed {{
  ct mark & 0xffff0000 == {prefix} oifname "{lan}" ip6 daddr @lan_v6 tcp flags & rst == rst return
  ct mark & 0xffff0000 == {prefix} oifname "{lan}" ip6 daddr @lan_v6 icmpv6 type {{ destination-unreachable, packet-too-big, time-exceeded, parameter-problem }} return
{lan_egress}{wan_egress}  drop
 }}
 chain egress_guard {{ type filter hook postrouting priority 101; policy accept;
  ct mark & 0xffff0000 == {prefix} jump egress_allowed
 }}
}}
"#
        ));
        Ok(rules)
    }

    /// Install an unreachable fallback before selecting this table. A disappearing WAN must
    /// never make an admitted reply fall through to the ordinary WireGuard routing policy.
    pub(crate) async fn routes(&self) -> Result<(), ServiceError> {
        let config = self.config;
        let owner = RoutingOwner::inbound(config, true);
        self.validate_routes().await?;
        let table = config.wan.route_table.to_string();
        let wan = &config.wan.device;
        let gateway = config.wan.gateway.to_string();
        checked(
            "ip",
            args(&[
                "-6",
                "route",
                "replace",
                "unreachable",
                "default",
                "metric",
                "32767",
                "proto",
                "242",
                "table",
                &table,
            ]),
            None,
        )
        .await?;
        checked(
            "ip",
            args(&[
                "-6",
                "route",
                "replace",
                &format!("{gateway}/128"),
                "dev",
                wan,
                "proto",
                "242",
                "table",
                &table,
            ]),
            None,
        )
        .await?;
        for network in &config.lan_networks {
            if matches!(network, ipnet::IpNet::V6(_)) {
                checked(
                    "ip",
                    args(&[
                        "-6",
                        "route",
                        "replace",
                        &network.to_string(),
                        "dev",
                        &config.lan_device,
                        "proto",
                        "242",
                        "table",
                        &table,
                    ]),
                    None,
                )
                .await?;
            }
        }
        checked(
            "ip",
            args(&[
                "-6", "route", "replace", "default", "via", &gateway, "dev", wan, "metric", "10",
                "proto", "242", "table", &table,
            ]),
            None,
        )
        .await?;
        if !owner.owned_rule_exists().await? {
            checked(
                "ip",
                args(&[
                    "-6",
                    "rule",
                    "add",
                    "priority",
                    &config.wan.rule_priority.to_string(),
                    "fwmark",
                    &format!("{}/0xffff0000", config.wan.mark_prefix),
                    "lookup",
                    &table,
                    "protocol",
                    "242",
                ]),
                None,
            )
            .await?;
        }
        Ok(())
    }

    /// Only call after redirects and their conntrack entries have been removed while the
    /// closed guard is still installed. Clean uninstall intentionally leaves no hidden rules.
    pub(crate) async fn remove(&self) -> Result<(), ServiceError> {
        self.validate_routes().await?;
        RoutingOwner::inbound(self.config, true)
            .stop_routes()
            .await?;
        if let Some(handle) = Kernel::table_handle_for(TABLE, OWNER).await? {
            checked(
                "nft",
                args(&["delete", "table", "inet", "handle", &handle.to_string()]),
                None,
            )
            .await?;
        }
        Ok(())
    }
}
