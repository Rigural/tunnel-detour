//! Durable ownership of the exception family's IPv6 routing objects.

use std::{
    net::Ipv6Addr,
    path::Path,
    sync::{Arc, Mutex},
};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    ServiceConfig, ServiceError,
    integration_state::{self, PrivateJournal, appended_path},
    ipv6::Ipv6Wan,
    kernel::{self, RoutingOwner},
};

pub(crate) const SUFFIX: &str = ".ipv6-routing.json";

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
enum Owner {
    #[serde(rename = "tunnel-detour:ipv6-routing:v1")]
    TunnelDetour,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Identity {
    table: u32,
    mark: u32,
    priority: u32,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct State {
    owner: Owner,
    version: u8,
    identity: Identity,
    claimed: bool,
    paths: Vec<Ipv6Wan>,
}

impl State {
    fn validate(&self) -> Result<(), ServiceError> {
        if self.version != 1
            || self.identity.table < 256
            || self.identity.table == u32::MAX
            || self.identity.mark == 0
            || !(1..32766).contains(&self.identity.priority)
            || self.paths.is_empty()
            || self.paths.len() > 2
            || (!self.claimed && self.paths.len() != 1)
            || (self.paths.len() == 2 && self.paths[0] == self.paths[1])
        {
            return Err(ServiceError::KernelConflict);
        }
        for path in &self.paths {
            path.validate()?;
        }
        Ok(())
    }

    fn owner(&self) -> RoutingOwner {
        RoutingOwner::exception_ipv6(
            self.identity.table,
            self.identity.mark,
            self.identity.priority,
            self.claimed,
        )
    }
}

pub(crate) struct Ipv6Routing {
    journal: PrivateJournal,
    state: Mutex<State>,
}

fn strings(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).into()).collect()
}

impl Ipv6Routing {
    /// An unclaimed journal is deliberately durable before cold preflight. A
    /// collision can then be corrected and retried without a lost-state lock.
    /// A disabled configuration with no journal never inspects IPv6 routing.
    pub(crate) async fn prepare(config: &ServiceConfig) -> Result<Option<Arc<Self>>, ServiceError> {
        let path = appended_path(&config.state_file, SUFFIX);
        let existing: Option<State> =
            tokio::task::block_in_place(|| integration_state::existing(&path))
                .map_err(ServiceError::Ipv6State)?;
        if existing.is_none() && config.ipv6.is_none() {
            return Ok(None);
        }
        let identity = Identity {
            table: config.wan.route_table,
            mark: config.wan.mark,
            priority: config.wan.rule_priority,
        };
        let initial = match existing {
            Some(state) => state,
            None => State {
                owner: Owner::TunnelDetour,
                version: 1,
                identity: identity.clone(),
                claimed: false,
                paths: vec![
                    config
                        .ipv6
                        .as_ref()
                        .ok_or(ServiceError::KernelConflict)?
                        .wan
                        .clone(),
                ],
            },
        };
        initial.validate()?;
        let (journal, mut state) = tokio::task::block_in_place(|| {
            let journal = PrivateJournal::open(path).map_err(ServiceError::Ipv6State)?;
            let state: State = journal.load(initial).map_err(ServiceError::Ipv6State)?;
            state.validate()?;
            journal.save(&state).map_err(ServiceError::Ipv6State)?;
            Ok::<_, ServiceError>((journal, state))
        })?;
        if let Some(settings) = &config.ipv6 {
            if state.identity != identity {
                return Err(ServiceError::KernelConflict);
            }
            Self::validate_footprint(&state).await?;
            if !state.paths.contains(&settings.wan) {
                if !state.claimed {
                    state.paths.clear();
                }
                if state.paths.len() == 2 {
                    return Err(ServiceError::KernelConflict);
                }
                state.paths.push(settings.wan.clone());
            }
            state.claimed = true;
            tokio::task::block_in_place(|| journal.save(&state))
                .map_err(ServiceError::Ipv6State)?;
        } else if state.claimed {
            Self::validate_footprint(&state).await?;
        }
        Ok(Some(Arc::new(Self {
            journal,
            state: Mutex::new(state),
        })))
    }

    fn snapshot(&self) -> Result<State, ServiceError> {
        self.state
            .lock()
            .map_err(|_| ServiceError::Poisoned)
            .map(|state| state.clone())
    }

    async fn validate_footprint(state: &State) -> Result<(), ServiceError> {
        state.owner().validate_routing_ownership().await?;
        if !state.claimed {
            return Ok(());
        }
        let routes = state.owner().routing_routes().await?;
        if routes.iter().any(|route| !Self::owns_route(state, route)) {
            return Err(ServiceError::KernelConflict);
        }
        let rules =
            kernel::command("ip", &strings(&["-j", "-N", "-6", "rule", "show"]), None).await?;
        if !rules.success {
            return Err(ServiceError::KernelConflict);
        }
        let rules: Vec<Value> = serde_json::from_slice(&rules.stdout)?;
        for rule in rules
            .iter()
            .filter(|rule| rule["priority"].as_u64() == Some(u64::from(state.identity.priority)))
        {
            let fields = rule.as_object().ok_or(ServiceError::Protocol)?;
            if fields.keys().any(|key| {
                ![
                    "priority", "src", "dst", "fwmark", "fwmask", "table", "protocol",
                ]
                .contains(&key.as_str())
            }) || rule["src"] != "all"
                || rule.get("dst").is_some_and(|value| value != "all")
            {
                return Err(ServiceError::KernelConflict);
            }
        }
        Ok(())
    }

    fn owns_route(state: &State, route: &Value) -> bool {
        let Some(fields) = route.as_object() else {
            return false;
        };
        if fields.keys().any(|key| {
            ![
                "dst", "type", "gateway", "dev", "protocol", "metric", "flags", "pref", "table",
                "prefsrc", "scope",
            ]
            .contains(&key.as_str())
        }) || kernel::number(&route["protocol"]) != Some(242)
        {
            return false;
        }
        // `ip -N` renders RTN_UNREACHABLE as "7"; IPv6 assigns its
        // rejecting route to lo, without making it a reachable local target.
        if route["type"] == "unreachable" || kernel::number(&route["type"]) == Some(7) {
            return route["dst"] == "default"
                && route["metric"] == 32767
                && route["dev"] == "lo"
                && !fields.contains_key("gateway")
                && !fields.contains_key("prefsrc");
        }
        if route
            .get("type")
            .is_some_and(|value| value != "unicast" && kernel::number(value) != Some(1))
        {
            return false;
        }
        state.paths.iter().any(|path| {
            if route["dev"] != path.device
                || route.get("prefsrc").is_some_and(|value| {
                    value
                        .as_str()
                        .and_then(|value| value.parse::<Ipv6Addr>().ok())
                        != Some(path.source)
                })
            {
                return false;
            }
            // Linux clears the preferred-source hint when netifd removes that
            // address, even if it later restores it. The journal still owns the
            // exact route tuple; a different explicit hint remains a conflict.
            // Every dial binds its validated source, so this optional kernel
            // hint never authorizes source selection or a fallback path.
            if route["dst"] == "default" {
                return route["metric"] == 10
                    && match path.gateway {
                        Some(gateway) => {
                            route["gateway"]
                                .as_str()
                                .and_then(|value| value.parse::<Ipv6Addr>().ok())
                                == Some(gateway)
                        }
                        None => !fields.contains_key("gateway"),
                    };
            }
            let target = route["dst"]
                .as_str()
                .map(|value| value.strip_suffix("/128").unwrap_or(value))
                .and_then(|value| value.parse::<Ipv6Addr>().ok());
            path.gateway.is_some()
                && target == path.gateway
                && route["metric"] == 5
                && !fields.contains_key("gateway")
        })
    }

    pub(crate) async fn stop(&self) -> Result<(), ServiceError> {
        let state = self.snapshot()?;
        if state.claimed {
            Self::validate_footprint(&state).await?;
            state.owner().stop_routes().await?;
            let released = State {
                claimed: false,
                paths: vec![
                    state
                        .paths
                        .last()
                        .ok_or(ServiceError::KernelConflict)?
                        .clone(),
                ],
                ..state
            };
            tokio::task::block_in_place(|| self.journal.save(&released))
                .map_err(ServiceError::Ipv6State)?;
            *self.state.lock().map_err(|_| ServiceError::Poisoned)? = released;
        }
        Ok(())
    }

    pub(crate) async fn install(&self, wan: Option<&Ipv6Wan>) -> Result<(), ServiceError> {
        let Some(wan) = wan else {
            return self.stop().await;
        };
        let state = self.snapshot()?;
        if !state.claimed || !state.paths.contains(wan) {
            return Err(ServiceError::KernelConflict);
        }
        // Keep the pending claim durable throughout replacement; only a real
        // stop releases it. A crash cannot leave new routes marked unclaimed.
        Self::validate_footprint(&state).await?;
        state.owner().stop_routes().await?;
        let table = state.identity.table.to_string();
        kernel::checked(
            "ip",
            strings(&[
                "-6",
                "route",
                "add",
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
        let source = wan.source.to_string();
        if let Some(gateway) = wan.gateway {
            kernel::checked(
                "ip",
                strings(&[
                    "-6",
                    "route",
                    "add",
                    &format!("{gateway}/128"),
                    "dev",
                    &wan.device,
                    "src",
                    &source,
                    "metric",
                    "5",
                    "proto",
                    "242",
                    "table",
                    &table,
                ]),
                None,
            )
            .await?;
        }
        let mut default = strings(&[
            "-6",
            "route",
            "add",
            "default",
            "dev",
            &wan.device,
            "src",
            &source,
            "metric",
            "10",
            "proto",
            "242",
            "table",
            &table,
        ]);
        if let Some(gateway) = wan.gateway {
            default.extend(["via".into(), gateway.to_string()]);
        }
        kernel::checked("ip", default, None).await?;
        kernel::checked(
            "ip",
            strings(&[
                "-6",
                "rule",
                "add",
                "priority",
                &state.identity.priority.to_string(),
                "fwmark",
                &state.identity.mark.to_string(),
                "lookup",
                &table,
                "protocol",
                "242",
            ]),
            None,
        )
        .await?;
        Self::validate_footprint(&state).await?;
        let applied = State {
            paths: vec![wan.clone()],
            ..state
        };
        tokio::task::block_in_place(|| self.journal.save(&applied))
            .map_err(ServiceError::Ipv6State)?;
        *self.state.lock().map_err(|_| ServiceError::Poisoned)? = applied;
        Ok(())
    }

    /// Offline removal uses only the journal; no current WAN or valid UCI is needed.
    /// The caller holds the lease lock and removes the two known files after success.
    pub(crate) async fn cleanup(state_file: &Path) -> Result<(), ServiceError> {
        let path = appended_path(state_file, SUFFIX);
        let existing: Option<State> =
            integration_state::existing(&path).map_err(ServiceError::Ipv6State)?;
        let Some(initial) = existing else {
            return Ok(());
        };
        let journal = PrivateJournal::open(path).map_err(ServiceError::Ipv6State)?;
        let state: State = journal.load(initial).map_err(ServiceError::Ipv6State)?;
        state.validate()?;
        Self {
            journal,
            state: Mutex::new(state),
        }
        .stop()
        .await
    }
}
