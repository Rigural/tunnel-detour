//! Native inbound packet policy. Redirects themselves belong to firewall4/UCI.

use std::{collections::BTreeMap, fs::OpenOptions, os::unix::fs::OpenOptionsExt, time::Duration};

use crate::{
    InboundConfig, ServiceError,
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
        RoutingOwner::inbound(self.config, true)
            .validate_routing_ownership()
            .await?;
        let output = command(
            "ip",
            &args(&[
                "-j",
                "-N",
                "-6",
                "route",
                "show",
                "table",
                &self.config.wan.route_table.to_string(),
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
        for route in routes {
            let mut recognized = false;
            for config in std::iter::once(self.config).chain(pending) {
                let destination = route["dst"].as_str().ok_or(ServiceError::KernelConflict)?;
                let device = route["dev"].as_str();
                let gateway = route["gateway"].as_str();
                let metric = route["metric"].as_u64();
                let expected = if destination == "default" {
                    (route_type(route.get("type"), 7, "unreachable")
                        && gateway.is_none()
                        && metric == Some(32767))
                        || (route_type(route.get("type"), 1, "unicast")
                            && device == Some(config.wan.device.as_str())
                            && gateway == Some(config.wan.gateway.to_string().as_str())
                            && metric == Some(10))
                } else {
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
                    gateway.is_none()
                        && metric == Some(1024)
                        && route_type(route.get("type"), 1, "unicast")
                        && ((network.addr() == config.wan.gateway
                            && network.prefix_len() == 128
                            && device == Some(config.wan.device.as_str()))
                            || (config.lan_networks.contains(&network)
                                && device == Some(config.lan_device.as_str())))
                };
                recognized |= expected;
            }
            if !recognized {
                return Err(ServiceError::KernelConflict);
            }
        }
        Ok(())
    }

    /// One nft transaction closes retired generations before any native redirect is changed.
    pub(crate) async fn guard(&self, admissions: &Admissions) -> Result<(), ServiceError> {
        self.update_guard(admissions, true).await
    }

    /// Widen a guard only after retired shortcuts were removed and redirects committed.
    /// Cached retained generations remain valid and do not need another global reset.
    pub(crate) async fn admit(&self, admissions: &Admissions) -> Result<(), ServiceError> {
        self.update_guard(admissions, false).await
    }

    async fn update_guard(
        &self,
        admissions: &Admissions,
        invalidate_shortcuts: bool,
    ) -> Result<(), ServiceError> {
        // Serialize with native firewall4. A flowtable hit bypasses this forward guard;
        // when acceleration is present its retirement must share the same nft transaction.
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(
                i32::try_from(rustix::fs::OFlags::NOFOLLOW.bits())
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
        let previous = Kernel::table_handle_for(TABLE, OWNER).await?;
        let mut rules = self.rules(admissions, previous)?;
        let tables = command("nft", &args(&["--json", "list", "flowtables"]), None).await?;
        if !tables.success {
            return Err(ServiceError::KernelConflict);
        }
        let tables: serde_json::Value = serde_json::from_slice(&tables.stdout)?;
        let mut accelerated = false;
        for item in tables["nftables"]
            .as_array()
            .ok_or(ServiceError::KernelConflict)?
        {
            if let Some(table) = item.get("flowtable") {
                if table["family"] != "inet" || table["table"] != "fw4" || table["name"] != "ft" {
                    return Err(ServiceError::KernelConflict);
                }
                accelerated = true;
            }
        }
        if accelerated && invalidate_shortcuts {
            let native =
                crate::kernel::command_with_limit("fw4", &args(&["print"]), None, 2 * 1024 * 1024)
                    .await?;
            if !native.success {
                return Err(ServiceError::KernelConflict);
            }
            let native =
                String::from_utf8(native.stdout).map_err(|_| ServiceError::KernelConflict)?;
            if !native
                .lines()
                .any(|line| line.trim() == "delete flowtable inet fw4 ft")
            {
                return Err(ServiceError::KernelConflict);
            }
            rules.push_str(&native);
        }
        checked(
            "nft",
            args(&["--check", "--file", "-"]),
            Some(rules.as_bytes()),
        )
        .await?;
        checked("nft", args(&["--file", "-"]), Some(rules.as_bytes())).await
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
                rules.push_str(&format!("  {original} ct direction original iifname \"{wan}\" oifname \"{lan}\" ip6 daddr {} {transport} dport {} counter return comment \"{}:original\"\n", destination.ip(), destination.port(), rule.id().as_str()));
                rules.push_str(&format!("  {original} ct direction reply iifname \"{lan}\" oifname \"{wan}\" ip6 saddr {} {transport} sport {} counter return comment \"{}:reply\"\n", destination.ip(), destination.port(), rule.id().as_str()));
                // PMTU and other related ICMPv6 errors carry the admitted flow's tuple.
                rules.push_str(&format!("  {original} ct state related meta l4proto ipv6-icmp iifname \"{wan}\" oifname \"{lan}\" ip6 daddr {} return\n", destination.ip()));
                rules.push_str(&format!("  {original} ct state related meta l4proto ipv6-icmp iifname \"{lan}\" oifname \"{wan}\" return\n"));
                if rule.access() == InboundAccess::WanAndLan {
                    rules.push_str(&format!("  {original} ct direction original iifname \"{lan}\" oifname \"{lan}\" ip6 daddr {} {transport} dport {} counter return comment \"{}:lan-original\"\n", destination.ip(), destination.port(), rule.id().as_str()));
                    rules.push_str(&format!("  {original} ct direction reply iifname \"{lan}\" oifname \"{lan}\" ip6 saddr {} {transport} sport {} counter return comment \"{}:lan-reply\"\n", destination.ip(), destination.port(), rule.id().as_str()));
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
