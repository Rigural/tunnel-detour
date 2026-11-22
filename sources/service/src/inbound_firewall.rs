//! Derived native firewall4 redirects. The inbound list remains the configuration authority.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::{InboundConfig, ServiceError, inbound_kernel::Admissions, kernel};

pub(crate) type Sections = BTreeMap<String, Value>;

fn insert_section(sections: &mut Sections, name: String, value: Value) -> Result<(), ServiceError> {
    if sections.len() >= 256 {
        return Err(ServiceError::Busy);
    }
    sections.insert(name, value);
    Ok(())
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct FirewallSnapshot {
    pub(crate) values: Sections,
}

pub(crate) async fn snapshot() -> Result<FirewallSnapshot, ServiceError> {
    let output = kernel::command_with_limit(
        "ubus",
        &[
            "-S".into(),
            "call".into(),
            "uci".into(),
            "get".into(),
            "{\"config\":\"firewall\"}".into(),
        ],
        None,
        2 * 1024 * 1024,
    )
    .await?;
    if !output.success {
        return Err(ServiceError::KernelConflict);
    }
    let mut snapshot: FirewallSnapshot = serde_json::from_slice(&output.stdout)?;
    for section in snapshot.values.values_mut() {
        let section = section
            .as_object_mut()
            .ok_or(ServiceError::KernelConflict)?;
        section.retain(|key, _| !key.starts_with('.') || key == ".type");
    }
    Ok(snapshot)
}

pub(crate) fn desired(
    config: &InboundConfig,
    admissions: &Admissions,
) -> Result<Sections, ServiceError> {
    let mut sections = Sections::new();
    for rule in config.rules.rules().iter().filter(|rule| rule.enabled()) {
        let Some(generation) = admissions.get(rule.id()) else {
            continue;
        };
        if *generation == 0 {
            return Err(ServiceError::KernelConflict);
        }
        let relay = rule.destination().requires_relay();
        for (index, address) in config.wan.addresses.iter().enumerate() {
            // Bound the total UCI footprint independently of the publication count.
            if sections.len() >= 256 {
                return Err(ServiceError::Busy);
            }
            let name = format!("td_in_{}_{index}", rule.id().as_str());
            let protocol = rule
                .protocol()
                .transports()
                .iter()
                .map(|item| item.as_str())
                .collect::<Vec<_>>()
                .join(" ");
            let destination = rule.destination().endpoint();
            let mut redirect = json!({
                ".type":"redirect", "name":format!("Tunnel Detour: {}", rule.name()),
                "enabled":"1", "family":"ipv6", "src":config.wan_zone,
                "src_dip":address.to_string(), "src_dport":rule.public_port().to_string(),
                "dest_port":if relay {config.relay.listen_port.to_string()} else {destination.port().to_string()},
                "proto":protocol, "target":"DNAT", "reflection":"0",
                "mark":format!("{}/0xffffffff", config.wan.mark_prefix | u32::from(*generation))
            });
            if !relay {
                redirect["dest"] = json!(config.lan_zone);
                redirect["dest_ip"] = json!(destination.ip().to_string());
            }
            insert_section(&mut sections, name, redirect.clone())?;
            if rule.access() == tunnel_detour_core::InboundAccess::WanAndLan {
                let mut local = redirect;
                local["src"] = json!(config.lan_zone);
                local["name"] = json!(format!("Tunnel Detour LAN access: {}", rule.name()));
                insert_section(
                    &mut sections,
                    format!("td_il_{}_{index}", rule.id().as_str()),
                    local,
                )?;
            }
        }
        // firewall4 admits local redirects through its native ct-status-DNAT input
        // rule and permits related errors. The earlier owned input guard narrows both.
        if !relay && rule.access() == tunnel_detour_core::InboundAccess::WanAndLan {
            let destination = rule.destination().endpoint();
            let std::net::IpAddr::V6(target) = destination.ip() else {
                return Err(ServiceError::KernelConflict);
            };
            let source = config.lan_source(target)?;
            let protocol = rule
                .protocol()
                .transports()
                .iter()
                .map(|item| item.as_str())
                .collect::<Vec<_>>()
                .join(" ");
            for (index, network) in config
                .lan_networks
                .iter()
                .enumerate()
                .filter(|(_, network)| matches!(network, ipnet::IpNet::V6(_)))
            {
                insert_section(
                    &mut sections,
                    format!("td_is_{}_{index}", rule.id().as_str()),
                    json!({
                        ".type":"nat", "name":format!("Tunnel Detour LAN return: {}", rule.name()),
                        "enabled":"1", "family":"ipv6", "src":config.lan_zone, "device":config.lan_device,
                        "src_ip":network.to_string(), "dest_ip":target.to_string(), "dest_port":destination.port().to_string(),
                        "snat_ip":source.to_string(), "proto":protocol, "target":"SNAT",
                        "mark":format!("{}/0xffffffff", config.wan.mark_prefix | u32::from(*generation))
                    }),
                )?;
            }
        }
    }
    Ok(sections)
}

pub(crate) fn verify_owned(
    current: &FirewallSnapshot,
    expected: &Sections,
) -> Result<(), ServiceError> {
    for (name, value) in expected {
        if current.values.get(name) != Some(value) {
            return Err(ServiceError::KernelConflict);
        }
    }
    Ok(())
}

type NatRules = BTreeMap<(String, String, u64), Vec<Vec<Value>>>;
type Dispatch = (String, String, String);

const DISPATCH_OWNER: &str = "tunnel-detour:inbound-dispatch:v1";
const FILTER_OWNER: &str = "tunnel-detour:inbound-dnat-filter:v1";
const CHAIN_OWNER: &str = "tunnel-detour:inbound-nat-chain:v1";

#[derive(Default)]
struct NatProjection {
    rules: NatRules,
    dispatch: BTreeSet<Dispatch>,
    mark_prefix: Option<u32>,
}

#[derive(Default)]
struct NatInventory {
    present: Vec<(String, String, u64, Vec<Value>, u64)>,
    dispatch: BTreeSet<Dispatch>,
    chains: BTreeSet<String>,
    owned_dispatch: Vec<(Dispatch, u64)>,
    owned_chains: BTreeSet<String>,
    occupied_chains: BTreeSet<String>,
    native_references: BTreeSet<String>,
}

fn field<'a>(section: &'a Value, name: &str) -> Result<&'a str, ServiceError> {
    section[name].as_str().ok_or(ServiceError::KernelConflict)
}

fn equal(left: Value, right: Value) -> Value {
    json!({"match":{"op":"==","left":left,"right":right}})
}

fn mark_prefix(key: Value, prefix: u32) -> Value {
    equal(json!({"&":[key, 0xffff0000_u32]}), json!(prefix))
}

fn payload(protocol: &str, field: &str) -> Value {
    json!({"payload":{"protocol":protocol,"field":field}})
}

fn port(section: &Value, name: &str) -> Result<u16, ServiceError> {
    field(section, name)?
        .parse()
        .map_err(|_| ServiceError::KernelConflict)
}

fn add_nat_projection(
    projection: &mut NatProjection,
    config: &InboundConfig,
    owned: &Sections,
) -> Result<(), ServiceError> {
    if projection
        .mark_prefix
        .replace(config.wan.mark_prefix)
        .is_some_and(|prefix| prefix != config.wan.mark_prefix)
    {
        return Err(ServiceError::KernelConflict);
    }
    for section in owned.values() {
        let mark: u64 = field(section, "mark")?
            .strip_suffix("/0xffffffff")
            .ok_or(ServiceError::KernelConflict)?
            .parse()
            .map_err(|_| ServiceError::KernelConflict)?;
        let comment = format!("!fw4: {}", field(section, "name")?);
        let (base, matches, dport, action) = match field(section, ".type")? {
            "redirect" => {
                // The pinned fw4 renderer uses a local REDIRECT if DNAT has no destination IP.
                let to = port(section, "dest_port")?;
                let action = match section["dest_ip"].as_str() {
                    Some(address) => json!({"dnat":{"family":"ip6","addr":address,"port":to}}),
                    None => json!({"redirect":{"port":to}}),
                };
                (
                    "dstnat",
                    vec![equal(
                        payload("ip6", "daddr"),
                        json!(field(section, "src_dip")?),
                    )],
                    port(section, "src_dport")?,
                    action,
                )
            }
            "nat" => {
                let net: ipnet::Ipv6Net = field(section, "src_ip")?
                    .parse()
                    .map_err(|_| ServiceError::KernelConflict)?;
                let source = if net.prefix_len() == 128 {
                    json!(net.network())
                } else {
                    json!({"prefix":{"addr":net.network(),"len":net.prefix_len()}})
                };
                (
                    "srcnat",
                    vec![
                        equal(
                            json!({"meta":{"key":"oifname"}}),
                            json!(field(section, "device")?),
                        ),
                        equal(payload("ip6", "saddr"), source),
                        equal(payload("ip6", "daddr"), json!(field(section, "dest_ip")?)),
                    ],
                    port(section, "dest_port")?,
                    json!({"snat":{"family":"ip6","addr":field(section, "snat_ip")?}}),
                )
            }
            _ => return Err(ServiceError::KernelConflict),
        };
        let zone = field(section, "src")?;
        let device = if zone == config.lan_zone {
            &config.lan_device
        } else if zone == config.wan_zone {
            &config.wan.device
        } else {
            return Err(ServiceError::KernelConflict);
        };
        let chain = format!("{base}_{zone}");
        projection
            .dispatch
            .insert((base.to_owned(), chain.clone(), device.clone()));
        let rules = projection.rules.entry((chain, comment, mark)).or_default();
        for protocol in field(section, "proto")?.split_whitespace() {
            let mut expr = matches.clone();
            expr.push(equal(payload(protocol, "dport"), json!(dport)));
            expr.push(equal(json!({"meta":{"key":"mark"}}), json!(mark)));
            // The pinned fw4 template places its anonymous counter directly
            // before NAT. The stateless listing retains this shape, not its totals.
            expr.push(json!({"counter":null}));
            expr.push(action.clone());
            if !rules.contains(&expr) {
                rules.push(expr);
            }
        }
    }
    Ok(())
}

fn dispatch_applies<'a>(
    predicates: impl IntoIterator<Item = &'a Value>,
    interface_key: &str,
    device: &str,
) -> Result<bool, ServiceError> {
    let mut verified = true;
    'predicates: for entry in predicates {
        if entry.get("counter").is_some() || entry.get("log").is_some() {
            continue;
        }
        let condition = &entry["match"];
        if condition["left"]["payload"]["protocol"] == "ip" {
            return Ok(false);
        }
        let key = &condition["left"]["meta"]["key"];
        let candidate = if key == interface_key {
            device
        } else if key == "nfproto" {
            "ipv6"
        } else {
            // firewall4 can narrow a zone with additional subnet predicates.
            // A matching device cannot establish that those predicates admit the publication.
            verified = false;
            continue;
        };
        let right = &condition["right"];
        let values = right["set"]
            .as_array()
            .map_or_else(|| std::slice::from_ref(right), Vec::as_slice);
        let mut matched = false;
        for value in values {
            let Some(value) = value.as_str().filter(|value| !value.starts_with('@')) else {
                verified = false;
                continue 'predicates;
            };
            matched |= value == candidate
                || (key == interface_key
                    && value
                        .strip_suffix('*')
                        .is_some_and(|prefix| candidate.starts_with(prefix)));
        }
        match condition["op"].as_str() {
            Some("==" | "in") if matched => {}
            Some("!=") if !matched => {}
            Some("==" | "in" | "!=") => return Ok(false),
            _ => verified = false,
        }
    }
    if !verified {
        return Err(ServiceError::InboundNatConflict { stage: "dispatch" });
    }
    Ok(true)
}

// The matches preceding the first packet-changing statement bound its effect.
// Counter and log statements do not affect which NAT policy processes a packet.
fn effect_predicates(expr: &[Value]) -> Option<&[Value]> {
    expr.iter()
        .position(|entry| {
            entry.get("match").is_none()
                && entry.get("counter").is_none()
                && entry.get("log").is_none()
        })
        .map(|effect| &expr[..effect])
}

fn match_excludes_owned(condition: &Value, wanted: &[Value]) -> bool {
    let left = &condition["left"];
    if left["payload"]["protocol"] == "ip" {
        return true;
    }
    if left["meta"]["key"] == "nfproto"
        && let Some(only_v4) = condition["right"].as_str().map(|name| name == "ipv4")
    {
        return matches!(
            (condition["op"].as_str(), only_v4),
            (Some("==" | "in"), true)
        ) || (condition["op"] == "!=" && condition["right"] == "ipv6");
    }
    let wanted_value = wanted.iter().find_map(|entry| {
        let expected = &entry["match"];
        (expected["op"] == "==" && expected["left"] == *left)
            .then_some(&expected["right"])
            .filter(|value| value.is_number() || value.is_string())
    });
    let Some(wanted_value) = wanted_value else {
        // A TCP or UDP payload expression carries an implicit protocol check.
        let protocol = left["payload"]["protocol"].as_str();
        return matches!(protocol, Some("tcp" | "udp"))
            && wanted.iter().any(|entry| {
                let other = entry["match"]["left"]["payload"]["protocol"].as_str();
                matches!(other, Some("tcp" | "udp")) && protocol != other
            });
    };
    let right = &condition["right"];
    let values = right["set"]
        .as_array()
        .map_or_else(|| std::slice::from_ref(right), Vec::as_slice);
    if values.is_empty()
        || !values.iter().all(|value| {
            value.is_number()
                || value
                    .as_str()
                    .is_some_and(|item| !item.starts_with('@') && !item.ends_with('*'))
        })
    {
        return false;
    }
    let matches = values.contains(wanted_value);
    match condition["op"].as_str() {
        Some("==" | "in") => !matches,
        Some("!=") => matches,
        _ => false,
    }
}

/// Compare the live NAT expressions from OpenWrt 25.12's firewall4 with the owned
/// UCI projection. Handles and numeric counter totals are not part of the
/// policy; counter identity and placement are.
/// Missing owned rules can be repaired only through a verified IPv6 dispatch.
/// The base chains and their jumps are foreign policy, including jumps that
/// match the intended device but exclude IPv6.
pub(crate) async fn effective_nat_matches(
    config: &InboundConfig,
    owned: &Sections,
) -> Result<bool, ServiceError> {
    let mut expected = NatProjection::default();
    add_nat_projection(&mut expected, config, owned)?;
    let expected_count: usize = expected.rules.values().map(Vec::len).sum();
    let live = inspect_nat(expected, true).await?;
    Ok(live.present.len() == expected_count)
}

/// Reject live NAT restrictions before planning any owned changes.
/// A new candidate or an interrupted transaction may have only a subset of
/// its possible rules and zones in the kernel.
pub(crate) async fn verify_nat_before_change(
    policies: &[(&InboundConfig, &Sections)],
) -> Result<(), ServiceError> {
    let mut expected = NatProjection::default();
    for (config, owned) in policies {
        add_nat_projection(&mut expected, config, owned)?;
    }
    inspect_nat(expected, false).await?;
    Ok(())
}

async fn list_nat(args: &[String]) -> Result<Vec<Value>, ServiceError> {
    #[derive(Deserialize)]
    struct Listing {
        nftables: Vec<Value>,
    }

    let inspection = |error| ServiceError::InboundNatInspection(Box::new(error));
    let reply = kernel::command_with_limit("nft", args, None, 4 * 1024 * 1024)
        .await
        .map_err(inspection)?;
    if !reply.success {
        return Err(ServiceError::InboundNatConflict {
            stage: "inspection",
        });
    }
    serde_json::from_slice::<Listing>(&reply.stdout)
        .map(|listing| listing.nftables)
        .map_err(|error| inspection(error.into()))
}

async fn inspect_nat(
    mut expected: NatProjection,
    require_dispatch: bool,
) -> Result<NatInventory, ServiceError> {
    let mut chains: BTreeSet<_> = expected
        .dispatch
        .iter()
        .flat_map(|(base, target, _)| [base.clone(), target.clone()])
        .collect();
    if !require_dispatch && !chains.is_empty() {
        // Inventory chains without loading unrelated rules and sets. Only an
        // absent chain confirmed by this inventory can be skipped.
        let objects = list_nat(&[
            "-j".into(),
            "-s".into(),
            "list".into(),
            "chains".into(),
            "inet".into(),
        ])
        .await?;
        let existing: BTreeSet<_> = objects
            .iter()
            .filter_map(|entry| entry.get("chain"))
            .filter(|chain| chain["family"] == "inet" && chain["table"] == "fw4")
            .filter_map(|chain| chain["name"].as_str())
            .collect();
        chains.retain(|name| existing.contains(name.as_str()));
    }
    let mut dispatched = BTreeSet::new();
    let mut restricted_dispatches = BTreeSet::new();
    let mut present = Vec::new();
    let mut owned_dispatch = Vec::new();
    let mut owned_chains = BTreeSet::new();
    let mut occupied_chains = BTreeSet::new();
    let mut native_references = BTreeSet::new();
    // A large unrelated filter or set cannot widen the NAT policy inspection.
    for name in &chains {
        let objects = list_chain(name).await?;
        let fw4 = |object: &&Value| object["family"] == "inet" && object["table"] == "fw4";
        if objects
            .iter()
            .filter_map(|object| object.get("chain"))
            .filter(fw4)
            .any(|chain| {
                chain["name"] == name.as_str()
                    && chain["comment"] == CHAIN_OWNER
                    && chain.get("hook").is_none()
            })
        {
            owned_chains.insert(name.clone());
        }
        let base = match name.as_str() {
            "dstnat" => Some(("prerouting", -100, "iifname")),
            "srcnat" => Some(("postrouting", 100, "oifname")),
            _ => None,
        };
        if let Some((hook, priority, _)) = base
            && !objects
                .iter()
                .filter_map(|object| object.get("chain"))
                .filter(fw4)
                .any(|chain| {
                    chain["name"] == name.as_str()
                        && chain["type"] == "nat"
                        && chain["hook"] == hook
                        && chain["prio"] == priority
                        && chain["policy"] == "accept"
                })
        {
            return Err(ServiceError::InboundNatConflict { stage: "dispatch" });
        }
        for rule in objects
            .iter()
            .filter_map(|object| object.get("rule"))
            .filter(fw4)
        {
            let Some(expr) = rule["expr"]
                .as_array()
                .filter(|_| rule["chain"] == name.as_str())
            else {
                continue;
            };
            if let Some((_, _, interface_key)) = base {
                let jump_target = expr
                    .last()
                    .and_then(|entry| entry["jump"]["target"].as_str());
                let owned = rule["comment"] == DISPATCH_OWNER;
                let scope = expected
                    .mark_prefix
                    .map(|prefix| mark_prefix(json!({"meta":{"key":"mark"}}), prefix));
                if let Some(target) = jump_target
                    && !owned
                {
                    native_references.insert(target.to_owned());
                }
                for key @ (source, target, device) in &expected.dispatch {
                    if source != name {
                        continue;
                    }
                    let matches_dispatch = || -> Result<bool, ServiceError> {
                        let predicates = &expr[..expr.len() - 1];
                        if !owned {
                            return dispatch_applies(predicates, interface_key, device);
                        }
                        let scope = scope.as_ref().ok_or(ServiceError::KernelConflict)?;
                        if predicates.iter().any(|entry| entry.get("match").is_none())
                            || !predicates.contains(scope)
                            || !predicates
                                .contains(&equal(json!({"meta":{"key":"nfproto"}}), json!("ipv6")))
                        {
                            return Err(ServiceError::InboundNatConflict { stage: "dispatch" });
                        }
                        dispatch_applies(
                            predicates.iter().filter(|entry| *entry != scope),
                            interface_key,
                            device,
                        )
                    };
                    if dispatched.contains(key) {
                        if owned && jump_target == Some(target) && matches_dispatch()? {
                            owned_dispatch.push((key.clone(), rule_handle(rule)?));
                        }
                        continue;
                    }
                    if jump_target == Some(target.as_str()) {
                        if matches_dispatch()? {
                            dispatched.insert(key.clone());
                            if owned {
                                owned_dispatch.push((key.clone(), rule_handle(rule)?));
                            }
                        } else if !require_dispatch
                            && !matches!(
                                dispatch_applies(
                                    expr[..expr.len() - 1].iter().filter(|entry| {
                                        entry["match"]["left"]["meta"]["key"] == interface_key
                                    }),
                                    interface_key,
                                    device,
                                ),
                                Ok(false)
                            )
                        {
                            restricted_dispatches.insert(key);
                        }
                    } else if let Some(predicates) = effect_predicates(expr)
                        && !matches!(
                            dispatch_applies(predicates, interface_key, device),
                            Ok(false)
                        )
                        && expected.rules.iter().any(|((chain, _, _), rules)| {
                            chain == target
                                && rules.iter().any(|wanted| {
                                    !predicates
                                        .iter()
                                        .any(|entry| match_excludes_owned(&entry["match"], wanted))
                                })
                        })
                    {
                        // An earlier verdict or branch might prevent this dispatch.
                        return Err(ServiceError::InboundNatConflict {
                            stage: "rule_order",
                        });
                    }
                }
                continue;
            }
            let mark = expr.iter().find_map(|entry| {
                let condition = &entry["match"];
                (condition["op"] == "==" && condition["left"]["meta"]["key"] == "mark")
                    .then(|| kernel::number(&condition["right"]))
                    .flatten()
            });
            let comment = rule["comment"].as_str();
            let candidates = comment.zip(mark).and_then(|(comment, mark)| {
                expected
                    .rules
                    .get_mut(&(name.clone(), comment.to_owned(), mark))
            });
            if let Some(remaining) = candidates {
                let Some(index) = remaining.iter().position(|wanted| expr == wanted) else {
                    return Err(ServiceError::InboundNatConflict {
                        stage: "owned_rule",
                    });
                };
                let handle = rule_handle(rule)?;
                let (comment, mark) = comment.zip(mark).ok_or(ServiceError::KernelConflict)?;
                present.push((
                    name.clone(),
                    comment.to_owned(),
                    mark,
                    remaining.swap_remove(index),
                    handle,
                ));
            } else if expected
                .rules
                .keys()
                .any(|(chain, owned_comment, owned_mark)| {
                    chain == name
                        && (comment == Some(owned_comment.as_str()) || mark == Some(*owned_mark))
                })
            {
                // A rule with part of our ownership identity is unverified.
                // Reloading fw4 here could remove a live administrator restriction.
                return Err(ServiceError::InboundNatConflict {
                    stage: "owned_rule",
                });
            } else if let Some(predicates) = effect_predicates(expr)
                && expected.rules.iter().any(|((chain, _, _), rules)| {
                    chain == name
                        && rules.iter().any(|wanted| {
                            !predicates
                                .iter()
                                .any(|entry| match_excludes_owned(&entry["match"], wanted))
                        })
                })
            {
                return Err(ServiceError::InboundNatConflict {
                    stage: "rule_order",
                });
            } else {
                occupied_chains.insert(name.clone());
            }
        }
    }
    let dispatched_all = dispatched.len() == expected.dispatch.len();
    if (require_dispatch && !dispatched_all)
        || restricted_dispatches
            .iter()
            .any(|key| !dispatched.contains(*key))
    {
        return Err(ServiceError::InboundNatConflict { stage: "dispatch" });
    }
    Ok(NatInventory {
        present,
        dispatch: dispatched,
        chains,
        owned_dispatch,
        owned_chains,
        occupied_chains,
        native_references,
    })
}

fn rule_handle(rule: &Value) -> Result<u64, ServiceError> {
    rule["handle"]
        .as_u64()
        .ok_or(ServiceError::InboundNatConflict {
            stage: "inspection",
        })
}

async fn list_chain(name: &str) -> Result<Vec<Value>, ServiceError> {
    list_nat(&[
        "-j".into(),
        "-s".into(),
        "-a".into(),
        "list".into(),
        "chain".into(),
        "inet".into(),
        "fw4".into(),
        name.into(),
    ])
    .await
}

fn forget_rule(chain: &str, handle: u64) -> Value {
    json!({"delete":{"rule":{"family":"inet","table":"fw4","chain":chain,"handle":handle}}})
}

fn append_rule(chain: &str, comment: &str, expr: Vec<Value>) -> Value {
    json!({"add":{"rule":{"family":"inet","table":"fw4","chain":chain,"comment":comment,"expr":expr}}})
}

/// Add the first dispatch for a native NAT zone using its live classifier. Do
/// not infer policy from a name or replace a modified zone dispatch.
async fn provision_dispatch(
    commands: &mut Vec<Value>,
    inventory: &NatInventory,
    (base, target, device): &Dispatch,
    prefix: u32,
) -> Result<(), ServiceError> {
    let (classifier, field) = if base == "dstnat" {
        ("input", "iifname")
    } else {
        ("output", "oifname")
    };
    let zone = target
        .strip_prefix(&format!("{base}_"))
        .ok_or(ServiceError::KernelConflict)?;
    let destination = format!("{classifier}_{zone}");
    let live = list_chain(classifier).await?;
    let mut classifier = None;
    for rule in live.iter().filter_map(|item| item.get("rule")) {
        let Some(expr) = rule["expr"].as_array() else {
            return Err(ServiceError::KernelConflict);
        };
        let Some((jump, predicates)) = expr.split_last() else {
            return Err(ServiceError::KernelConflict);
        };
        if jump["jump"]["target"] == destination && dispatch_applies(predicates, field, device)? {
            if classifier.is_some() {
                return Err(ServiceError::KernelConflict);
            }
            // The live classifier may log and count for its own hook. Copy
            // only the verified selectors, never those side effects.
            classifier = Some(
                predicates
                    .iter()
                    .filter(|entry| entry.get("match").is_some())
                    .cloned()
                    .collect::<Vec<_>>(),
            );
        }
    }
    let mut expr = classifier.ok_or(ServiceError::KernelConflict)?;
    // A pre-existing chain may contain administrator rules that have never
    // received this zone's unmarked packets. Do not dispatch those packets.
    let ipv6 = equal(json!({"meta":{"key":"nfproto"}}), json!("ipv6"));
    if !expr.contains(&ipv6) {
        expr.push(ipv6);
    }
    expr.push(mark_prefix(json!({"meta":{"key":"mark"}}), prefix));
    expr.push(json!({"jump":{"target":target}}));
    if !inventory.chains.contains(target) {
        commands.push(json!({"add":{"chain":{
            "family":"inet","table":"fw4","name":target,"comment":CHAIN_OWNER
        }}}));
    }
    commands.push(append_rule(base, DISPATCH_OWNER, expr));
    Ok(())
}

async fn native_dnat_filter(
    commands: &mut Vec<Value>,
    zone: &str,
    prefix: u32,
    needed: bool,
    provision: bool,
) -> Result<(), ServiceError> {
    let status = json!({"match":{"op":"in","left":{"ct":{"key":"status"}},"right":"dnat"}});
    let accept = json!({"accept":null});
    let owned = vec![
        mark_prefix(json!({"ct":{"key":"mark"}}), prefix),
        status.clone(),
        accept.clone(),
    ];
    for (direction, jump_direction, native_comment) in [
        ("input", "from", "!fw4: Accept port redirections"),
        ("forward", "to", "!fw4: Accept port forwards"),
    ] {
        let chain = format!("{direction}_{zone}");
        let mut present = false;
        let mut anchor = None;
        for rule in list_chain(&chain)
            .await?
            .iter()
            .filter_map(|entry| entry.get("rule"))
        {
            if rule["comment"] == FILTER_OWNER {
                if rule["expr"] != json!(owned) {
                    return Err(ServiceError::KernelConflict);
                }
                present = true;
                if !needed {
                    commands.push(forget_rule(&chain, rule_handle(rule)?));
                }
            } else if rule["comment"] == native_comment && rule["expr"] == json!([status, accept]) {
                present = true;
            } else if rule.get("comment").is_none()
                && let Some([jump]) = rule["expr"].as_array().map(Vec::as_slice)
                && ["accept", "drop", "reject"].iter().any(|verdict| {
                    jump["jump"]["target"] == format!("{verdict}_{jump_direction}_{zone}")
                })
            {
                anchor = Some(rule_handle(rule)?);
            }
        }
        if needed && provision && !present {
            commands.push(json!({"insert":{"rule":{
                "family":"inet","table":"fw4","chain":chain,"comment":FILTER_OWNER,"expr":owned,
                "handle":anchor.ok_or(ServiceError::KernelConflict)?
            }}}));
        }
    }
    Ok(())
}

/// Plan a change using only verified owned NAT expressions and handles.
/// Provision missing dispatches from the live zone classifiers without a
/// full table reload.
async fn scoped_nat(
    previous: &[(&InboundConfig, &Sections)],
    candidate: (&InboundConfig, &Sections),
) -> Result<Vec<u8>, ServiceError> {
    let mut permitted = NatProjection::default();
    for (config, owned) in previous {
        add_nat_projection(&mut permitted, config, owned)?;
    }
    add_nat_projection(&mut permitted, candidate.0, candidate.1)?;
    let mut desired = NatProjection::default();
    add_nat_projection(&mut desired, candidate.0, candidate.1)?;
    let previous_dispatch = permitted.dispatch.clone();
    let live = inspect_nat(permitted, false).await?;
    let mut commands = Vec::new();
    for (key, handle) in &live.owned_dispatch {
        if !desired.dispatch.contains(key) {
            commands.push(forget_rule(&key.0, *handle));
        }
    }
    for key in desired.dispatch.difference(&live.dispatch) {
        provision_dispatch(&mut commands, &live, key, candidate.0.wan.mark_prefix).await?;
    }
    let zones: BTreeSet<_> = previous_dispatch
        .iter()
        .filter_map(|(base, target, _)| {
            (base == "dstnat")
                .then(|| target.strip_prefix("dstnat_"))
                .flatten()
        })
        .collect();
    for zone in zones {
        let chain = format!("dstnat_{zone}");
        let belongs = |(base, target, _): &Dispatch| base == "dstnat" && target == &chain;
        native_dnat_filter(
            &mut commands,
            zone,
            candidate.0.wan.mark_prefix,
            desired.dispatch.iter().any(belongs),
            desired.dispatch.difference(&live.dispatch).any(belongs),
        )
        .await?;
    }
    for (chain, comment, mark, expr, handle) in live.present {
        let keep = desired
            .rules
            .get_mut(&(chain.clone(), comment, mark))
            .and_then(|rules| {
                let index = rules.iter().position(|wanted| *wanted == expr)?;
                Some(rules.swap_remove(index))
            })
            .is_some();
        if !keep {
            commands.push(forget_rule(&chain, handle));
        }
    }
    for ((chain, comment, _mark), rules) in desired.rules {
        for expr in rules {
            // A rule after administrator policy cannot override that policy.
            commands.push(append_rule(&chain, &comment, expr));
        }
    }
    for chain in live.owned_chains {
        if !live.occupied_chains.contains(&chain)
            && !live.native_references.contains(&chain)
            && !desired
                .dispatch
                .iter()
                .any(|(_, target, _)| target == &chain)
        {
            // No flush: the kernel will also refuse if an unobserved foreign
            // branch references the chain or a rule was added concurrently.
            commands.push(json!({"delete":{"chain":{"family":"inet","table":"fw4","name":chain}}}));
        }
    }
    Ok(if commands.is_empty() {
        Vec::new()
    } else {
        serde_json::to_vec(&json!({"nftables":commands}))?
    })
}

pub(crate) async fn no_pending_changes() -> Result<(), ServiceError> {
    let output = kernel::command("uci", &["changes".into(), "firewall".into()], None).await?;
    if !output.success || !output.stdout.is_empty() {
        return Err(ServiceError::KernelConflict);
    }
    Ok(())
}

/// Existing administrator redirects take precedence: broad or opaque entries require review
/// rather than guessing that a second publication of the same WAN endpoint will be safe.
pub(crate) fn validate_frontend(
    current: &FirewallSnapshot,
    owned: &Sections,
    config: &InboundConfig,
) -> Result<(), ServiceError> {
    for zone in [&config.lan_zone, &config.wan_zone] {
        if current
            .values
            .values()
            .filter(|value| {
                value[".type"] == "zone" && value["name"].as_str() == Some(zone.as_str())
            })
            .count()
            != 1
        {
            return Err(ServiceError::KernelConflict);
        }
    }
    for (name, section) in &current.values {
        if owned.contains_key(name)
            || section[".type"] != "redirect"
            || section["enabled"] == "0"
            || section["family"] == "ipv4"
        {
            continue;
        }
        for rule in config.rules.rules().iter().filter(|rule| rule.enabled()) {
            if section["src"].as_str().is_some_and(|zone| {
                zone != config.wan_zone
                    && zone != "*"
                    && !(rule.access() == tunnel_detour_core::InboundAccess::WanAndLan
                        && zone == config.lan_zone)
            }) {
                continue;
            }
            let protocols = section["proto"].as_str();
            if protocols.is_some_and(|value| {
                !value
                    .split_whitespace()
                    .any(|value| matches!(value, "all" | "tcpudp" | "tcp" | "udp"))
            }) {
                continue;
            }
            let Some(ports) = section["src_dport"].as_str() else {
                return Err(ServiceError::KernelConflict);
            };
            for value in ports.split_whitespace() {
                let (start, end) = value
                    .split_once('-')
                    .or_else(|| value.split_once(':'))
                    .unwrap_or((value, value));
                let (Ok(start), Ok(end)) = (start.parse::<u16>(), end.parse::<u16>()) else {
                    return Err(ServiceError::KernelConflict);
                };
                if start > end || (start..=end).contains(&rule.public_port().get()) {
                    return Err(ServiceError::KernelConflict);
                }
            }
        }
    }
    Ok(())
}

/// Commit only our known sections, after checking both foreign configuration and pending
/// administrator edits. No whole-file replacement, global revert or implicit adoption.
pub(crate) async fn apply(
    before: &FirewallSnapshot,
    owned: &Sections,
    desired: &Sections,
    previous_policy: &[(&InboundConfig, &Sections)],
    config: &InboundConfig,
) -> Result<(), ServiceError> {
    let _lock = crate::inbound_kernel::lock_firewall().await?;
    no_pending_changes().await?;
    verify_owned(before, owned)?;
    for name in desired.keys() {
        if before.values.contains_key(name) && !owned.contains_key(name) {
            return Err(ServiceError::KernelConflict);
        }
    }
    let live_update = scoped_nat(previous_policy, (config, desired)).await?;
    if !live_update.is_empty() {
        kernel::checked(
            "nft",
            ["-j", "-c", "-f", "-"].map(String::from).into(),
            Some(&live_update),
        )
        .await?;
    }
    let staging = tokio::task::block_in_place(tempfile::tempdir)?;
    let staging_path = staging
        .path()
        .to_str()
        .ok_or(ServiceError::KernelConflict)?;
    let invoke = |operation: &str, value: String| {
        vec!["-t".into(), staging_path.into(), operation.into(), value]
    };
    for name in owned.keys() {
        kernel::checked("uci", invoke("delete", format!("firewall.{name}")), None).await?;
    }
    for (name, section) in desired {
        let section = section.as_object().ok_or(ServiceError::KernelConflict)?;
        kernel::checked(
            "uci",
            invoke(
                "set",
                format!(
                    "firewall.{name}={}",
                    match section.get(".type").and_then(Value::as_str) {
                        Some(kind @ ("redirect" | "nat")) => kind,
                        _ => return Err(ServiceError::KernelConflict),
                    }
                ),
            ),
            None,
        )
        .await?;
        for (key, value) in section.iter().filter(|(key, _)| !key.starts_with('.')) {
            let value = value.as_str().ok_or(ServiceError::KernelConflict)?;
            kernel::checked(
                "uci",
                invoke("set", format!("firewall.{name}.{key}={value}")),
                None,
            )
            .await?;
        }
    }
    no_pending_changes().await?;
    if snapshot().await? != *before {
        return Err(ServiceError::KernelConflict);
    }
    kernel::checked("uci", invoke("commit", "firewall".into()), None).await?;
    let mut expected = before.clone();
    for name in owned.keys() {
        expected.values.remove(name);
    }
    expected.values.extend(desired.clone());
    if snapshot().await? != expected {
        return Err(ServiceError::KernelConflict);
    }
    // Direct administrator nft edits do not take fw4.lock, and replacing a
    // rule can preserve its handle. Never carry old ownership proof over the
    // UCI commit; re-read expressions and anchors before using the plan.
    if scoped_nat(previous_policy, (config, desired)).await? != live_update {
        return Err(ServiceError::InboundNatConflict {
            stage: "concurrent_change",
        });
    }
    if !live_update.is_empty() {
        kernel::checked(
            "nft",
            ["-j", "-f", "-"].map(String::from).into(),
            Some(&live_update),
        )
        .await?;
    }
    if snapshot().await? != expected {
        return Err(ServiceError::KernelConflict);
    }
    Ok(())
}
