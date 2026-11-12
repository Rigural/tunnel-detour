//! Pin real DNS to its explicitly inspected non-WAN path.

use std::net::{IpAddr, SocketAddr};

use serde::Deserialize;
use serde_json::{Value, json};

use crate::{ServiceConfig, ServiceError, kernel};

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ResolverPath {
    pub endpoint: SocketAddr,
    pub device: String,
}

impl ResolverPath {
    pub async fn prepare(config: &ServiceConfig) -> Result<Self, ServiceError> {
        config.validate_resolver_endpoint(config.real_upstream)?;
        #[derive(Deserialize)]
        struct Route {
            dev: Option<String>,
            #[serde(rename = "type")]
            kind: Option<String>,
        }
        let output = kernel::command(
            "ip",
            &[
                "-j".into(),
                if config.real_upstream.is_ipv4() {
                    "-4"
                } else {
                    "-6"
                }
                .into(),
                "route".into(),
                "get".into(),
                config.real_upstream.ip().to_string(),
                "ipproto".into(),
                "tcp".into(),
                "dport".into(),
                config.real_upstream.port().to_string(),
            ],
            None,
        )
        .await?;
        if !output.success {
            return Err(ServiceError::ResolverRoute);
        }
        let routes: Vec<Route> = serde_json::from_slice(&output.stdout)?;
        let [route] = routes.as_slice() else {
            return Err(ServiceError::ResolverRoute);
        };
        let device = route.dev.as_deref().ok_or(ServiceError::ResolverRoute)?;
        if !crate::config::valid_device(device)
            || device == config.wan.device
            || route
                .kind
                .as_deref()
                .is_some_and(|kind| !matches!(kind, "unicast" | "local"))
        {
            return Err(ServiceError::ResolverRoute);
        }
        // Resolver transport is independent of the exception families. Accept
        // only existing local/LAN paths or a native WireGuard device for IPv6;
        // another WAN or arbitrary tunnel must not become a DNS fallback.
        if config.real_upstream.is_ipv6() && device != "lo" && device != config.lan_device {
            let output = kernel::command(
                "ip",
                &[
                    "-j".into(),
                    "-d".into(),
                    "link".into(),
                    "show".into(),
                    "dev".into(),
                    device.into(),
                ],
                None,
            )
            .await?;
            if !output.success {
                return Err(ServiceError::ResolverRoute);
            }
            let links: Vec<Value> = serde_json::from_slice(&output.stdout)?;
            if links.len() != 1 || links[0]["linkinfo"]["info_kind"] != "wireguard" {
                return Err(ServiceError::ResolverRoute);
            }
        }
        Ok(Self {
            endpoint: config.real_upstream,
            device: device.to_owned(),
        })
    }

    pub fn guard_rules(&self) -> String {
        let address = self.endpoint.ip();
        let port = self.endpoint.port();
        let device = &self.device;
        let family = if self.endpoint.is_ipv4() { "ip" } else { "ip6" };
        format!(
            "  {family} daddr {address} tcp dport {port} oifname != \"{device}\" reject with icmpx type admin-prohibited\n  {family} daddr {address} udp dport {port} oifname != \"{device}\" reject with icmpx type admin-prohibited\n"
        )
    }
}

/// Decode only this owner's bounded guards, without replaying arbitrary nft text.
pub(crate) fn decode_guard_table(listing: &Value) -> Result<Vec<ResolverPath>, ServiceError> {
    let objects = listing["nftables"]
        .as_array()
        .ok_or(ServiceError::KernelConflict)?;
    let chains: Vec<_> = objects
        .iter()
        .filter_map(|object| object.get("chain"))
        .filter(|chain| chain["name"] == "resolver_guard")
        .collect();
    let [chain] = chains.as_slice() else {
        return Err(ServiceError::KernelConflict);
    };
    if chain["family"] != "inet"
        || chain["table"] != "tunnel_detour"
        || chain["type"] != "filter"
        || chain["hook"] != "output"
        || chain["prio"] != -6
        || chain["policy"] != "accept"
    {
        return Err(ServiceError::KernelConflict);
    }
    let mut paths: Vec<(ResolverPath, bool, bool)> = Vec::new();
    let mut count = 0;
    for rule in objects
        .iter()
        .filter_map(|object| object.get("rule"))
        .filter(|rule| rule["chain"] == "resolver_guard")
    {
        count += 1;
        if count > 4
            || rule["family"] != "inet"
            || rule["table"] != "tunnel_detour"
            || rule.as_object().is_none_or(|fields| {
                fields.keys().any(|key| {
                    !matches!(
                        key.as_str(),
                        "family" | "table" | "chain" | "handle" | "expr"
                    )
                })
            })
        {
            return Err(ServiceError::KernelConflict);
        }
        let expression = rule["expr"]
            .as_array()
            .ok_or(ServiceError::KernelConflict)?;
        if expression.len() != 4 {
            return Err(ServiceError::KernelConflict);
        }
        let address: IpAddr = expression[0]["match"]["right"]
            .as_str()
            .ok_or(ServiceError::KernelConflict)?
            .parse()
            .map_err(|_| ServiceError::KernelConflict)?;
        let port = expression[1]["match"]["right"]
            .as_u64()
            .and_then(|port| u16::try_from(port).ok())
            .filter(|port| *port != 0)
            .ok_or(ServiceError::KernelConflict)?;
        let protocol = expression[1]["match"]["left"]["payload"]["protocol"]
            .as_str()
            .filter(|protocol| matches!(*protocol, "tcp" | "udp"))
            .ok_or(ServiceError::KernelConflict)?;
        let device = expression[2]["match"]["right"]
            .as_str()
            .ok_or(ServiceError::KernelConflict)?;
        if device.is_empty()
            || device.len() > 15
            || !device
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
            || crate::config::validate_tcp_resolver(SocketAddr::new(address, port)).is_err()
        {
            return Err(ServiceError::KernelConflict);
        }
        let family = if address.is_ipv4() { "ip" } else { "ip6" };
        let expected = json!([
            {"match":{"op":"==","left":{"payload":{"protocol":family,"field":"daddr"}},"right":address}},
            {"match":{"op":"==","left":{"payload":{"protocol":protocol,"field":"dport"}},"right":port}},
            {"match":{"op":"!=","left":{"meta":{"key":"oifname"}},"right":device}},
            {"reject":{"type":"icmpx","expr":"admin-prohibited"}}
        ]);
        if rule["expr"] != expected {
            return Err(ServiceError::KernelConflict);
        }
        let path = ResolverPath {
            endpoint: SocketAddr::new(address, port),
            device: device.into(),
        };
        let index = match paths.iter().position(|(saved, _, _)| saved == &path) {
            Some(index) => index,
            None if paths.len() < 2 => {
                paths.push((path, false, false));
                paths.len() - 1
            }
            None => return Err(ServiceError::KernelConflict),
        };
        let seen = if protocol == "tcp" {
            &mut paths[index].1
        } else {
            &mut paths[index].2
        };
        if *seen {
            return Err(ServiceError::KernelConflict);
        }
        *seen = true;
    }
    if paths.is_empty() || paths.iter().any(|(_, tcp, udp)| !tcp || !udp) {
        return Err(ServiceError::KernelConflict);
    }
    Ok(paths.into_iter().map(|(path, _, _)| path).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn r096_resolver_guard_recovery_rejects_missing_ambiguous_or_foreign_kernel_rules()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut objects = vec![
            json!({"chain":{"family":"inet","table":"tunnel_detour","name":"resolver_guard","handle":6,"type":"filter","hook":"output","prio":-6,"policy":"accept"}}),
        ];
        for protocol in ["tcp", "udp"] {
            objects.push(json!({"rule":{"family":"inet","table":"tunnel_detour","chain":"resolver_guard","handle":8,
                "expr":[
                    {"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"daddr"}},"right":"192.0.2.53"}},
                    {"match":{"op":"==","left":{"payload":{"protocol":protocol,"field":"dport"}},"right":5353}},
                    {"match":{"op":"!=","left":{"meta":{"key":"oifname"}},"right":"wgtest0"}},
                    {"reject":{"type":"icmpx","expr":"admin-prohibited"}}
                ]}}));
        }
        let baseline = json!({"nftables":objects});
        assert_eq!(
            decode_guard_table(&baseline)?,
            vec![ResolverPath {
                endpoint: "192.0.2.53:5353".parse()?,
                device: "wgtest0".into()
            }]
        );
        let mut ipv6 = objects.clone();
        for object in &mut ipv6[1..] {
            object["rule"]["expr"][0]["match"]["left"]["payload"]["protocol"] = json!("ip6");
            object["rule"]["expr"][0]["match"]["right"] = json!("2001:db8::53");
        }
        assert_eq!(
            decode_guard_table(&json!({"nftables":ipv6}))?,
            vec![ResolverPath {
                endpoint: "[2001:db8::53]:5353".parse()?,
                device: "wgtest0".into()
            }]
        );
        let mut mixed = objects.clone();
        mixed.extend_from_slice(&ipv6[1..]);
        assert_eq!(decode_guard_table(&json!({"nftables":mixed}))?.len(), 2);
        for (pointer, value) in [
            (
                "/nftables/1/rule/expr/0/match/left/payload/protocol",
                json!("ip"),
            ),
            (
                "/nftables/1/rule/expr/0/match/right",
                json!("::ffff:192.0.2.53"),
            ),
            (
                "/nftables/1/rule/expr/0/match/right",
                json!("2001:2::c612:1"),
            ),
        ] {
            let mut invalid = json!({"nftables":ipv6});
            *invalid.pointer_mut(pointer).ok_or("IPv6 fixture pointer")? = value;
            assert!(
                decode_guard_table(&invalid).is_err(),
                "IPv6 guard accepted at {pointer}"
            );
        }
        for (pointer, value) in [
            ("/nftables/0/chain/prio", json!(-5)),
            ("/nftables/0/chain/hook", json!("forward")),
            ("/nftables/1/rule/expr/0/match/op", json!("!=")),
            ("/nftables/1/rule/expr/1/match/right", json!(0)),
            (
                "/nftables/1/rule/expr/2/match/right",
                json!("wg0\"; flush ruleset"),
            ),
            ("/nftables/1/rule/expr/3", json!({"accept":null})),
            (
                "/nftables/2/rule/expr/1/match/left/payload/protocol",
                json!("tcp"),
            ),
        ] {
            let mut changed = baseline.clone();
            *changed.pointer_mut(pointer).ok_or("fixture pointer")? = value;
            assert!(
                decode_guard_table(&changed).is_err(),
                "foreign rule accepted at {pointer}"
            );
        }
        let mut missing = objects.clone();
        missing.pop();
        assert!(decode_guard_table(&json!({"nftables":missing})).is_err());
        let mut duplicated = objects.clone();
        duplicated.push(objects[1].clone());
        assert!(decode_guard_table(&json!({"nftables":duplicated})).is_err());
        let mut extended = baseline;
        extended["nftables"][1]["rule"]["expr"]
            .as_array_mut()
            .ok_or("fixture expressions")?
            .push(json!({"counter":{"packets":0,"bytes":0}}));
        assert!(decode_guard_table(&extended).is_err());
        assert!(decode_guard_table(&json!({"nftables":[]})).is_err());
        Ok(())
    }
}
