//! Independent inbound supervisor and crash-recoverable ownership of native publications.

use std::{
    collections::{BTreeMap, BTreeSet},
    net::{IpAddr, Ipv6Addr, SocketAddr},
    time::Instant,
};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;
use tokio::net::TcpListener;
use tunnel_detour_core::{INBOUND_INTERNET_V6, InboundAccess, InboundId};

use crate::{
    InboundConfig, RelayAdmission, RelayOutcome, RelaySessions, ServiceError,
    inbound_firewall::{self as firewall, Sections},
    inbound_kernel::{Admissions, InboundKernel},
    integration_state::{IntegrationStateError, PrivateJournal},
};

#[derive(Debug, Error)]
pub enum InboundRuntimeError {
    #[error("inbound ownership state is invalid or belongs to another controller")]
    State,
    #[error("inbound ownership state could not be persisted")]
    Journal(#[from] IntegrationStateError),
    #[error("stop inbound publications before changing their ownership identifiers or state paths")]
    IdentityChange,
    #[error("inbound conntrack cleanup failed; the closed guard has been retained")]
    Conntrack,
    #[error("internal relay listener on port {port} could not be opened")]
    RelayListener {
        port: u16,
        #[source]
        source: std::io::Error,
    },
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Ownership {
    version: u8,
    next_generation: u32,
    control: Value,
    admissions: Admissions,
    owned: Sections,
    pending: Option<Pending>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Pending {
    control: Value,
    admissions: Admissions,
    owned: Sections,
}

fn validate_snapshot(
    control: &Value,
    admissions: &Admissions,
    owned: &Sections,
    next: u32,
) -> Result<InboundConfig, ServiceError> {
    if owned.len() > 256 {
        return Err(InboundRuntimeError::State.into());
    }
    let config = InboundConfig::from_json(&serde_json::to_vec(control)?)?;
    let mut seen = BTreeSet::new();
    for (id, generation) in admissions {
        if *generation == 0
            || u32::from(*generation) >= next
            || !seen.insert(*generation)
            || !config
                .rules
                .rules()
                .iter()
                .any(|rule| rule.enabled() && rule.id() == id)
        {
            return Err(InboundRuntimeError::State.into());
        }
    }
    if firewall::desired(&config, admissions)? != *owned {
        return Err(InboundRuntimeError::State.into());
    }
    Ok(config)
}

impl Ownership {
    fn config(&self) -> Result<InboundConfig, ServiceError> {
        if self.version != 1 || !(1..=65536).contains(&self.next_generation) {
            return Err(InboundRuntimeError::State.into());
        }
        let config = validate_snapshot(
            &self.control,
            &self.admissions,
            &self.owned,
            self.next_generation,
        )?;
        if let Some(pending) = &self.pending {
            let candidate = validate_snapshot(
                &pending.control,
                &pending.admissions,
                &pending.owned,
                self.next_generation,
            )?;
            if !same_identity(&config, &candidate) {
                return Err(InboundRuntimeError::State.into());
            }
        }
        Ok(config)
    }

    fn observed(&self, current: &firewall::FirewallSnapshot) -> Result<Sections, ServiceError> {
        let Some(pending) = &self.pending else {
            firewall::verify_owned(current, &self.owned)?;
            return Ok(self.owned.clone());
        };
        let mut observed = Sections::new();
        for name in self.owned.keys().chain(pending.owned.keys()) {
            if let Some(value) = current.values.get(name) {
                if self.owned.get(name) != Some(value) && pending.owned.get(name) != Some(value) {
                    return Err(ServiceError::KernelConflict);
                }
                observed.insert(name.clone(), value.clone());
            }
        }
        Ok(observed)
    }
}

/// An independently owned native datapath. Callers must supervise completion and call `stop`
/// on normal termination. Failed reconciliation closes admissions and retains recovery state.
pub struct BoundInbound {
    config: InboundConfig,
    ownership: Ownership,
    journal: PrivateJournal,
    healthy: bool,
    revision: u64,
    relay_listener: Option<TcpListener>,
    relay_sessions: RelaySessions,
    relay_notices: BTreeMap<InboundId, (RelayOutcome, Instant)>,
    relay_denied: u64,
    status_error: Option<&'static str>,
    status_conflict: Value,
}

async fn prepare_relay_listener(
    config: &InboundConfig,
) -> Result<Option<TcpListener>, ServiceError> {
    if !config.has_relays() {
        return Ok(None);
    }
    let limits = config.relay.limits()?;
    let bind = || -> std::io::Result<TcpListener> {
        let socket = socket2::Socket::new(
            socket2::Domain::IPV6,
            socket2::Type::STREAM,
            Some(socket2::Protocol::TCP),
        )?;
        socket.set_only_v6(true)?;
        socket.set_reuse_address(true)?;
        socket.set_nonblocking(true)?;
        limits.configure_socket(&socket)?;
        socket.bind(&SocketAddr::from((Ipv6Addr::UNSPECIFIED, config.relay.listen_port)).into())?;
        socket.listen(crate::RELAY_LISTEN_BACKLOG)?;
        TcpListener::from_std(socket.into())
    };
    match bind() {
        Ok(listener) => Ok(Some(listener)),
        Err(source) if source.kind() == std::io::ErrorKind::AddrInUse => {
            let mut uses =
                crate::port_guard::inspect(BTreeSet::from([config.relay.listen_port])).await?;
            Err(crate::PortGuardError::RelayOccupied {
                port: config.relay.listen_port,
                uses: uses.remove(&config.relay.listen_port).unwrap_or_default(),
            }
            .into())
        }
        Err(source) => Err(InboundRuntimeError::RelayListener {
            port: config.relay.listen_port,
            source,
        }
        .into()),
    }
}

fn same_identity(left: &InboundConfig, right: &InboundConfig) -> bool {
    left.state_file == right.state_file
        && left.status_file == right.status_file
        && left.wan.mark_prefix == right.wan.mark_prefix
        && left.wan.route_table == right.wan.route_table
        && left.wan.rule_priority == right.wan.rule_priority
}

fn same_network(left: &InboundConfig, right: &InboundConfig) -> bool {
    left.lan_device == right.lan_device
        && left.lan_zone == right.lan_zone
        && left.lan_networks == right.lan_networks
        && left.lan_router_addresses == right.lan_router_addresses
        && left.wan.device == right.wan.device
        && left.wan_zone == right.wan_zone
        && left.wan.addresses == right.wan.addresses
        && left.wan.gateway == right.wan.gateway
}

impl BoundInbound {
    /// Write bounded, safe status for local management. This reports application only;
    /// reachability from LAN or the public Internet requires an explicit acceptance probe.
    pub fn report_status(&mut self, error: Option<&'static str>) -> Result<(), ServiceError> {
        self.status_error = error;
        self.status_conflict = Value::Null;
        self.refresh_status()
    }

    /// Report why a candidate was refused, exposing only bounded router-service diagnostics.
    pub fn report_error(&mut self, error: &ServiceError) -> Result<(), ServiceError> {
        self.status_error = Some(error.code());
        self.status_conflict = crate::port_guard::diagnostic(error);
        self.refresh_status()
    }

    /// Refresh volatile session state without clearing a rejected candidate's diagnostic.
    /// Only active client endpoints are retained; recent notices contain no client identity.
    pub fn refresh_status(&self) -> Result<(), ServiceError> {
        let notices: Vec<_> = self.relay_notices.iter().filter(|(_, (_, at))| at.elapsed().as_secs() < 300).map(|(id, (outcome, at))| serde_json::json!({"publication":id,"outcome":outcome,"age_seconds":at.elapsed().as_secs()})).collect();
        let value = serde_json::json!({"process_id":std::process::id(),"revision":self.revision,"phase":if self.healthy {"ready"} else {"failed"},
            "last_error":self.status_error,"port_conflict":self.status_conflict,"public_addresses":self.config.wan.addresses,"publications":self.config.rules,
            "relay":{"connections":self.relay_sessions.connections(),"rejected":self.relay_denied,"notices":notices},
            "applied":self.healthy && self.status_error.is_none(),"lan_reachability":"unverified","internet_reachability":"unverified"});
        tokio::task::block_in_place(|| {
            crate::integration_state::atomic_write(&self.config.status_file, &value)
        })
        .map_err(InboundRuntimeError::from)?;
        Ok(())
    }

    /// Whether the last accepted configuration is fully applied. Invalid candidates do not
    /// change this; an uncertain mutation requires a supervised restart and journal recovery.
    pub fn is_healthy(&self) -> bool {
        self.healthy
    }

    /// Drive one bounded relay event. Pending identity verification belongs to the
    /// session manager, so cancellation of this supervising select never detaches it.
    pub async fn relay_step(&mut self) -> Result<(), ServiceError> {
        if !self.healthy {
            return Err(InboundRuntimeError::State.into());
        }
        enum Event {
            Accepted(std::io::Result<(tokio::net::TcpStream, SocketAddr)>),
            Completed(Result<crate::RelayCompletion, crate::RelayError>),
        }
        let event = if let Some(listener) = &self.relay_listener {
            tokio::select! {
                biased;
                result = self.relay_sessions.next_completion() => Event::Completed(result),
                result = listener.accept() => Event::Accepted(result),
            }
        } else {
            Event::Completed(self.relay_sessions.next_completion().await)
        };
        match event {
            Event::Completed(result) => {
                let completion = result?;
                let id = completion.connection.publication;
                match completion.outcome {
                    RelayOutcome::IdentityRejected => {
                        self.relay_denied = self.relay_denied.saturating_add(1);
                    }
                    RelayOutcome::AdmissionTimeout => {
                        self.relay_denied = self.relay_denied.saturating_add(1);
                        self.relay_notices
                            .insert(id, (RelayOutcome::AdmissionTimeout, Instant::now()));
                    }
                    RelayOutcome::Complete
                    | RelayOutcome::IdleTimeout
                    | RelayOutcome::Cancelled => {
                        self.relay_notices.remove(&id);
                    }
                    outcome => {
                        self.relay_notices.insert(id, (outcome, Instant::now()));
                    }
                }
            }
            Event::Accepted(result) => {
                let (stream, peer) = result?;
                let SocketAddr::V6(peer) = peer else {
                    self.relay_denied = self.relay_denied.saturating_add(1);
                    return Ok(());
                };
                let public = match socket2::SockRef::from(&stream)
                    .original_dst_v6()
                    .ok()
                    .and_then(|address| address.as_socket_ipv6())
                {
                    Some(public) if self.config.wan.addresses.contains(public.ip()) => public,
                    _ => {
                        self.relay_denied = self.relay_denied.saturating_add(1);
                        return Ok(());
                    }
                };
                let Some(rule) = self.config.rules.rules().iter().find(|rule| {
                    rule.enabled()
                        && rule.destination().requires_relay()
                        && rule.public_port().get() == public.port()
                }) else {
                    self.relay_denied = self.relay_denied.saturating_add(1);
                    return Ok(());
                };
                let source = IpAddr::V6(*peer.ip());
                let on_lan = self
                    .config
                    .lan_networks
                    .iter()
                    .any(|network| network.contains(&source));
                if self.config.router_addresses.contains(&source)
                    || (on_lan && rule.access() != InboundAccess::WanAndLan)
                    || (!on_lan && !INBOUND_INTERNET_V6.contains(peer.ip()))
                {
                    self.relay_denied = self.relay_denied.saturating_add(1);
                    return Ok(());
                }
                let generation = *self
                    .ownership
                    .admissions
                    .get(rule.id())
                    .ok_or(InboundRuntimeError::State)?;
                let SocketAddr::V4(target) = rule.destination().endpoint() else {
                    return Err(InboundRuntimeError::State.into());
                };
                let admission = RelayAdmission {
                    publication: rule.id().clone(),
                    generation,
                    target,
                    lan_device: self.config.lan_device.clone(),
                    reply_device: if on_lan {
                        self.config.lan_device.clone()
                    } else {
                        self.config.wan.device.clone()
                    },
                };
                let capture = crate::relay::RelayCapture {
                    mark: self.config.wan.mark_prefix | u32::from(generation),
                    public,
                };
                match self
                    .relay_sessions
                    .enqueue_captured(stream, admission, capture)
                {
                    Ok(_) => {}
                    Err(crate::RelayError::Capacity | crate::RelayError::Io(_)) => {
                        self.relay_denied = self.relay_denied.saturating_add(1);
                    }
                    Err(error) => return Err(error.into()),
                }
            }
        }
        Ok(())
    }

    /// Verify that the live network and native redirects still implement the accepted policy.
    /// This is read-only; a caller must withdraw admissions when the accepted context is lost.
    pub async fn audit(&self) -> Result<(), ServiceError> {
        if self.relay_listener.is_some() != self.config.has_relays() {
            return Err(InboundRuntimeError::State.into());
        }
        self.config.check_network_and_paths().await?;
        crate::port_guard::check(&self.config).await?;
        InboundKernel::new(&self.config).validate_routes().await?;
        if crate::kernel::Kernel::table_handle_for(
            crate::inbound_kernel::TABLE,
            crate::inbound_kernel::OWNER,
        )
        .await?
        .is_none()
        {
            return Err(ServiceError::KernelConflict);
        }
        firewall::verify_owned(&firewall::snapshot().await?, &self.ownership.owned)
    }

    /// Retire every admission before supervised recovery. Persisting the intent prevents a
    /// later restart from reviving connections that were closed after network or policy loss.
    pub async fn fence(&mut self, error: &ServiceError) -> Result<(), ServiceError> {
        self.relay_listener = None;
        self.relay_sessions.stop_admission();
        let guarded = self.fence_owned().await;
        let drained = self.relay_sessions.shutdown().await;
        let recorded = self.report_error(error);
        guarded?;
        drained?;
        recorded
    }

    async fn fence_owned(&mut self) -> Result<(), ServiceError> {
        self.healthy = false;
        if self.ownership.pending.is_none() {
            self.ownership.pending = Some(Pending {
                control: serde_json::to_value(&self.config)?,
                admissions: Admissions::new(),
                owned: Sections::new(),
            });
        }
        let saved = self.save();
        let guarded = InboundKernel::new(&self.config)
            .guard(&Admissions::new())
            .await;
        match (saved, guarded) {
            (Err(storage), Err(guard)) => {
                tracing::error!(
                    code = storage.code(),
                    "inbound retirement intent could not be persisted"
                );
                return Err(guard);
            }
            (Err(error), Ok(())) | (Ok(()), Err(error)) => return Err(error),
            (Ok(()), Ok(())) => {}
        }
        Ok(())
    }

    /// Validate live interfaces and private ownership before creating any kernel object.
    /// No DNS frontend, resolver or exception service is required.
    pub async fn bind(config: InboundConfig) -> Result<Self, ServiceError> {
        config.check_network_and_paths().await?;
        crate::port_guard::check(&config).await?;
        firewall::no_pending_changes().await?;
        let path = config.state_file.clone();
        let status_path = config.status_file.clone();
        let initial = Ownership {
            version: 1,
            next_generation: 1,
            control: serde_json::to_value(&config)?,
            admissions: Admissions::new(),
            owned: Sections::new(),
            pending: None,
        };
        let (journal, ownership) = tokio::task::spawn_blocking(move || {
            crate::runtime::prepare_parent(&path)?;
            crate::runtime::prepare_parent(&status_path)?;
            let journal = PrivateJournal::open(path).map_err(InboundRuntimeError::from)?;
            let state = journal.load(initial).map_err(InboundRuntimeError::from)?;
            Ok::<_, ServiceError>((journal, state))
        })
        .await??;
        let previous = ownership.config()?;
        if !same_identity(&previous, &config) {
            return Err(InboundRuntimeError::IdentityChange.into());
        }
        tokio::task::block_in_place(|| journal.save(&ownership))
            .map_err(InboundRuntimeError::from)?;
        let relay_sessions = RelaySessions::new(previous.relay.limits()?)
            .with_transport(crate::transport_worker::TransportWorker::new()?);
        let mut service = Self {
            config: previous,
            ownership,
            journal,
            healthy: true,
            revision: 0,
            relay_listener: None,
            relay_sessions,
            relay_notices: BTreeMap::new(),
            relay_denied: 0,
            status_error: None,
            status_conflict: Value::Null,
        };
        if let Err(error) = service.reconfigure(config).await {
            if !service.ownership.admissions.is_empty() || service.ownership.pending.is_some() {
                service.fence(&error).await?;
            }
            return Err(error);
        }
        Ok(service)
    }

    /// Preserve unaffected admissions, while allocating never-reused generations for changes.
    /// Invalid candidates fail before changing active policy; apply failures retain a closed guard.
    pub async fn reconfigure(&mut self, config: InboundConfig) -> Result<(), ServiceError> {
        if !self.healthy {
            return Err(InboundRuntimeError::State.into());
        }
        if !same_identity(&self.config, &config) {
            return Err(InboundRuntimeError::IdentityChange.into());
        }
        config.check_network_and_paths().await?;
        firewall::no_pending_changes().await?;
        crate::port_guard::check(&config).await?;
        self.recover().await?;
        let before = firewall::snapshot().await?;
        let observed = self.ownership.observed(&before)?;
        InboundKernel::new(&self.config).validate_routes().await?;
        firewall::validate_frontend(&before, &observed, &config)?;
        let mut admissions = Admissions::new();
        let mut retained = Admissions::new();
        let mut next = self.ownership.next_generation;
        for rule in config.rules.rules().iter().filter(|rule| rule.enabled()) {
            // A new process always allocates fresh admissions. This also fences a prior
            // controller that could close the kernel guard but could not persist its intent.
            let unchanged = self.revision != 0
                && same_network(&self.config, &config)
                && self.ownership.pending.is_none()
                && self.config.rules.rules().iter().any(|previous| {
                    previous.enabled()
                        && previous.id() == rule.id()
                        && previous.protocol() == rule.protocol()
                        && previous.access() == rule.access()
                        && previous.public_port() == rule.public_port()
                        && previous.destination() == rule.destination()
                        && (!rule.destination().requires_relay()
                            || self.config.relay == config.relay)
                });
            let generation = if let Some(generation) = self
                .ownership
                .admissions
                .get(rule.id())
                .filter(|_| unchanged)
            {
                retained.insert(rule.id().clone(), *generation);
                *generation
            } else {
                let generation =
                    u16::try_from(next).map_err(|_| ServiceError::IdentifierExhausted)?;
                next = next
                    .checked_add(1)
                    .ok_or(ServiceError::IdentifierExhausted)?;
                generation
            };
            admissions.insert(rule.id().clone(), generation);
        }
        let desired = firewall::desired(&config, &admissions)?;
        // Reject a name collision before changing either the guard or the durable journal.
        for name in desired.keys() {
            if before.values.contains_key(name) && !observed.contains_key(name) {
                return Err(ServiceError::KernelConflict);
            }
        }
        let reuse_listener = config.has_relays()
            && self.relay_listener.is_some()
            && self.config.relay.listen_port == config.relay.listen_port;
        let prepared_listener = if reuse_listener {
            None
        } else {
            prepare_relay_listener(&config).await?
        };
        self.ownership.next_generation = next;
        self.ownership.pending = Some(Pending {
            control: serde_json::to_value(&config)?,
            admissions: admissions.clone(),
            owned: desired.clone(),
        });
        self.healthy = false;
        self.save()?;
        // The old context is used for retained flows; a network change retains none.
        let previous_kernel = InboundKernel::new(&self.config);
        if self.revision == 0
            || !same_network(&self.config, &config)
            || retained != self.ownership.admissions
        {
            previous_kernel.guard(&retained).await?;
        } else {
            previous_kernel.admit(&retained).await?;
        }
        self.relay_sessions.retain(&retained).await?;
        self.relay_notices.retain(|id, _| retained.contains_key(id));
        if self.config.relay != config.relay {
            let transport = crate::transport_worker::TransportWorker::new()?;
            self.relay_sessions.shutdown().await?;
            self.relay_sessions =
                RelaySessions::new(config.relay.limits()?).with_transport(transport);
        }
        if !reuse_listener {
            self.relay_listener = prepared_listener;
        }
        if let Some(listener) = &self.relay_listener {
            config.relay.limits()?.configure_socket(listener)?;
        }
        if !same_network(&self.config, &config) {
            crate::kernel::RoutingOwner::inbound(&self.config, true)
                .stop_routes()
                .await?;
        }
        let kernel = InboundKernel::new(&config);
        kernel.routes().await?;
        if observed != desired || self.ownership.pending.is_some() {
            firewall::apply(&before, &observed, &desired).await?;
        }
        let committed = Ownership {
            version: 1,
            next_generation: next,
            control: serde_json::to_value(&config)?,
            admissions: admissions.clone(),
            owned: desired,
            pending: None,
        };
        tokio::task::block_in_place(|| self.journal.save(&committed))
            .map_err(InboundRuntimeError::from)?;
        self.ownership = committed;
        self.config = config;
        InboundKernel::new(&self.config).admit(&admissions).await?;
        self.healthy = true;
        self.revision = self.revision.saturating_add(1);
        self.report_status(None)?;
        Ok(())
    }

    fn save(&self) -> Result<(), ServiceError> {
        tokio::task::block_in_place(|| self.journal.save(&self.ownership))
            .map_err(InboundRuntimeError::from)?;
        Ok(())
    }

    async fn recover(&mut self) -> Result<(), ServiceError> {
        let Some(pending) = &self.ownership.pending else {
            return Ok(());
        };
        let pending_config = InboundConfig::from_json(&serde_json::to_vec(&pending.control)?)?;
        let before = firewall::snapshot().await?;
        let observed = self.ownership.observed(&before)?;
        let kernel = InboundKernel::new(&self.config);
        kernel
            .validate_route_contexts(Some(&pending_config))
            .await?;
        self.healthy = false;
        kernel.guard(&Admissions::new()).await?;
        // The original intent already permits every intermediate subset of old/new owned
        // sections. Complete their removal before recording another intent, so a second
        // interruption cannot lose ownership of a first candidate's partially applied rules.
        firewall::apply(&before, &observed, &Sections::new()).await?;
        crate::kernel::RoutingOwner::inbound(&self.config, true)
            .stop_routes()
            .await?;
        self.ownership.admissions.clear();
        self.ownership.owned.clear();
        self.ownership.pending = None;
        self.save()?;
        self.healthy = true;
        Ok(())
    }

    /// Withdraw native redirects and clear their NAT cache before removing the closed guard.
    /// Ownership conflicts leave the guard closed for administrator review and safe recovery.
    pub async fn stop(&mut self) -> Result<(), ServiceError> {
        self.relay_listener = None;
        self.relay_sessions.stop_admission();
        let cleaned = self.stop_owned().await;
        let drained = self.relay_sessions.shutdown().await;
        cleaned?;
        drained?;
        Ok(())
    }

    async fn stop_owned(&mut self) -> Result<(), ServiceError> {
        self.recover().await?;
        self.healthy = false;
        let kernel = InboundKernel::new(&self.config);
        kernel.guard(&Admissions::new()).await?;
        self.relay_sessions.shutdown().await?;
        let before = firewall::snapshot().await?;
        let observed = self.ownership.observed(&before)?;
        let pending_config = self
            .ownership
            .pending
            .as_ref()
            .map(|pending| InboundConfig::from_json(&serde_json::to_vec(&pending.control)?))
            .transpose()?;
        kernel
            .validate_route_contexts(pending_config.as_ref())
            .await?;
        self.ownership.pending = Some(Pending {
            control: serde_json::to_value(&self.config)?,
            admissions: Admissions::new(),
            owned: Sections::new(),
        });
        self.save()?;
        firewall::apply(&before, &observed, &Sections::new()).await?;
        clear_conntrack(self.config.wan.mark_prefix).await?;
        crate::kernel::RoutingOwner::inbound(&self.config, true)
            .stop_routes()
            .await?;
        kernel.remove().await?;
        self.ownership.admissions.clear();
        self.ownership.owned.clear();
        self.ownership.pending = None;
        self.save()?;
        tokio::task::block_in_place(|| crate::integration_state::atomic_write(&self.config.status_file,
            &serde_json::json!({"process_id":std::process::id(),"phase":"stopped","applied":false}))).map_err(InboundRuntimeError::from)?;
        Ok(())
    }
}

async fn clear_conntrack(prefix: u32) -> Result<(), ServiceError> {
    // Deletion output can contain every client tuple. Discard it directly rather than
    // collecting or logging private traffic, even if the kernel contains many flows.
    let mut child = tokio::process::Command::new("conntrack")
        .args([
            "-D",
            "--family",
            "ipv6",
            "--mark",
            &format!("{prefix}/0xffff0000"),
        ])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true)
        .spawn()?;
    let status = tokio::time::timeout(std::time::Duration::from_secs(10), child.wait())
        .await
        .map_err(|_| ServiceError::Timeout)??;
    // conntrack returns 1 for no matches. Verify the actual postcondition independently.
    if !status.success() && status.code() != Some(1) {
        return Err(InboundRuntimeError::Conntrack.into());
    }
    let output = crate::kernel::command(
        "conntrack",
        &[
            "-L".into(),
            "--family".into(),
            "ipv6".into(),
            "--mark".into(),
            format!("{prefix}/0xffff0000"),
        ],
        None,
    )
    .await?;
    if !output.success || !output.stdout.is_empty() {
        return Err(InboundRuntimeError::Conntrack.into());
    }
    Ok(())
}

/// Read-only validation shared by local management and the native UCI configuration check.
pub async fn check_inbound_config(config: &InboundConfig) -> Result<(), ServiceError> {
    config.check_network_and_paths().await?;
    crate::port_guard::check(config).await?;
    firewall::no_pending_changes().await?;
    let current = firewall::snapshot().await?;
    let state = tokio::task::block_in_place(|| {
        crate::integration_state::existing::<Ownership>(&config.state_file)
    })
    .map_err(InboundRuntimeError::from)?;
    let owned = if let Some(state) = state {
        let previous = state.config()?;
        if !same_identity(&previous, config) {
            return Err(InboundRuntimeError::IdentityChange.into());
        }
        state.observed(&current)?
    } else {
        Sections::new()
    };
    firewall::validate_frontend(&current, &owned, config)?;
    let mut preview = Admissions::new();
    for rule in config.rules.rules().iter().filter(|rule| rule.enabled()) {
        preview.insert(rule.id().clone(), 1);
    }
    for name in firewall::desired(config, &preview)?.keys() {
        if current.values.contains_key(name) && !owned.contains_key(name) {
            return Err(ServiceError::KernelConflict);
        }
    }
    Ok(())
}

/// Recover and clean only the installed UCI controller's journal, even with WAN down or an
/// invalid newly edited rule. Missing ownership never authorizes adopting kernel objects.
pub async fn cleanup_inbound_uci() -> Result<(), ServiceError> {
    let ownership = tokio::task::block_in_place(|| {
        crate::integration_state::existing::<Ownership>(std::path::Path::new(
            crate::inbound_uci::STATE,
        ))
    })
    .map_err(InboundRuntimeError::from)?;
    let Some(ownership) = ownership else {
        if crate::kernel::Kernel::table_handle_for(
            crate::inbound_kernel::TABLE,
            crate::inbound_kernel::OWNER,
        )
        .await?
        .is_some()
        {
            return Err(ServiceError::KernelConflict);
        }
        return Ok(());
    };
    let config = ownership.config()?;
    if config.state_file != std::path::Path::new(crate::inbound_uci::STATE)
        || config.status_file != std::path::Path::new(crate::inbound_uci::STATUS)
        || config.wan.route_table != crate::inbound_uci::ROUTE_TABLE
        || config.wan.mark_prefix != crate::inbound_uci::MARK_PREFIX
        || config.wan.rule_priority != crate::inbound_uci::RULE_PRIORITY
    {
        return Err(InboundRuntimeError::State.into());
    }
    let path = config.state_file.clone();
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(50);
    let journal = loop {
        match tokio::task::block_in_place(|| PrivateJournal::open(path.clone())) {
            Ok(journal) => break journal,
            Err(IntegrationStateError::Lock(std::fs::TryLockError::WouldBlock))
                if tokio::time::Instant::now() < deadline =>
            {
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
            Err(error) => return Err(InboundRuntimeError::from(error).into()),
        }
    };
    let ownership = tokio::task::block_in_place(|| journal.load(ownership))
        .map_err(InboundRuntimeError::from)?;
    let actual = ownership.config()?;
    if !same_identity(&config, &actual) {
        return Err(InboundRuntimeError::State.into());
    }
    if ownership.owned.is_empty()
        && ownership.admissions.is_empty()
        && ownership.pending.is_none()
        && crate::kernel::Kernel::table_handle_for(
            crate::inbound_kernel::TABLE,
            crate::inbound_kernel::OWNER,
        )
        .await?
        .is_none()
    {
        // An empty committed journal is written only after kernel cleanup. Do not claim
        // unrelated routing objects subsequently created while this feature is disabled.
        return Ok(());
    }
    let relay_sessions = RelaySessions::new(actual.relay.limits()?);
    BoundInbound {
        config: actual,
        ownership,
        journal,
        healthy: false,
        revision: 0,
        relay_listener: None,
        relay_sessions,
        relay_notices: BTreeMap::new(),
        relay_denied: 0,
        status_error: None,
        status_conflict: Value::Null,
    }
    .stop()
    .await
}
