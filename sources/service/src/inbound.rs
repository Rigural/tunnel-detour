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
    observability::{AppliedConsent, Consent},
    status::SnapshotPublication,
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
    status_writer: Option<std::fs::File>,
    healthy: bool,
    revision: u64,
    guard_fingerprint: Option<String>,
    relay_listener: Option<TcpListener>,
    relay_sessions: RelaySessions,
    relay_observation: Option<RelayObservation>,
    applied_consent: AppliedConsent,
    observability_log: crate::ObservabilityLog,
    status_error: Option<&'static str>,
    status_conflict: Value,
    published_transport_degradation: bool,
    status_publication: SnapshotPublication,
}

#[derive(Default)]
struct RelayObservation {
    notices: BTreeMap<InboundId, (RelayOutcome, Instant)>,
    rejected: u64,
    completed: u64,
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

fn clear_prior_observations(config: &InboundConfig) {
    if config.observability_enabled() {
        return;
    }
    tokio::task::block_in_place(|| {
        if InboundConfig::check_status_path(&config.status_file, config.from_uci).is_err() {
            return;
        }
        let _status_writer = if config.from_uci {
            None
        } else {
            let Ok(guard) = InboundConfig::status_writer(&config.status_file, false) else {
                return;
            };
            guard
        };
        crate::management::clear_when_idle(&config.state_file, |lock| {
            if let Some(owner) = crate::management::snapshot_owner(&config.status_file)? {
                if owner == crate::integration_state::lock_identity(lock)? {
                    crate::management::clear_snapshot(&config.status_file, true)?;
                }
                return Ok(());
            }
            let ownership = crate::integration_state::existing::<Ownership>(&config.state_file);
            let same_owner = match ownership {
                Ok(Some(ownership)) => ownership
                    .config()
                    .is_ok_and(|previous| same_identity(&previous, config)),
                Ok(None) | Err(IntegrationStateError::Json(_)) => false,
                Err(error) => return Err(InboundRuntimeError::from(error).into()),
            };
            if same_owner {
                crate::management::clear_snapshot(&config.status_file, true)?;
            }
            Ok(())
        });
    });
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
    /// Share the daemon's local logging gate with the reload path.
    pub fn with_observability_log(mut self, log: crate::ObservabilityLog) -> Self {
        log.set_enabled(self.relay_observation.is_some());
        self.observability_log = log;
        self
    }

    fn set_observability(&mut self, applied: AppliedConsent) -> bool {
        if self.applied_consent == applied {
            return false;
        }
        self.applied_consent = applied;
        let enabled = applied.consent.enabled();
        self.observability_log.set_enabled(enabled);
        self.relay_sessions.set_observability(false);
        self.relay_sessions.set_observability(enabled);
        self.relay_observation = enabled.then(RelayObservation::default);
        if enabled {
            tracing::info!(target: "tunnel_detour::diagnostics", "inbound traffic diagnostics enabled");
        }
        true
    }

    async fn apply_observability(&mut self) {
        let applied = if self.config.from_uci {
            AppliedConsent::confirm_uci(true, self.config.observability).await
        } else {
            AppliedConsent::for_json(self.config.observability)
        };
        self.set_observability(applied);
    }

    /// Revoke diagnostics independently of a traffic-policy reconciliation.
    pub fn disable_observability(&mut self) -> Result<(), ServiceError> {
        self.publish_revocation(AppliedConsent::default())
    }

    fn publish_revocation(&mut self, applied: AppliedConsent) -> Result<(), ServiceError> {
        if self.set_observability(applied)
            && let Err(error) = self.refresh_status()
        {
            if !matches!(error, ServiceError::Io(_)) {
                tokio::task::block_in_place(|| {
                    crate::observability::discard_snapshot(&self.config.status_file)
                })?;
            }
            return Err(error);
        }
        Ok(())
    }

    /// Publish health changes and periodic traffic metrics while consent is active.
    pub fn refresh_diagnostics(&mut self) -> Result<(), ServiceError> {
        if self.config.from_uci {
            self.publish_revocation(
                self.applied_consent
                    .invalidate_uci(true, self.applied_consent.consent),
            )?;
        }
        if self.relay_observation.is_some()
            || self.published_transport_degradation != self.transport_degraded()?
            || self.status_publication.retry_pending()
        {
            self.refresh_status()?;
        }
        Ok(())
    }

    /// Read consent and the inbound candidate from one committed UCI snapshot.
    pub async fn load_uci_candidate(&mut self) -> Result<Option<InboundConfig>, ServiceError> {
        let sections = crate::uci::read_sections().await;
        let requested = sections
            .as_ref()
            .map_or(Consent::Off, |sections| sections.consent("inbound"));
        self.publish_revocation(self.applied_consent.invalidate_uci(true, requested))?;
        crate::inbound_uci::load_inbound_sections(sections?, false).await
    }

    fn reject_relay(&mut self) {
        if let Some(observation) = &mut self.relay_observation {
            observation.rejected = observation.rejected.saturating_add(1);
        }
    }

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
    pub fn refresh_status(&mut self) -> Result<(), ServiceError> {
        let transport_degraded = self.transport_degraded()?;
        let degradation =
            transport_degraded.then_some(crate::transport_worker::INITIALIZATION_FAILED);
        let mut value = serde_json::json!({"process_id":std::process::id(),"revision":self.revision,"phase":if self.healthy {"ready"} else {"failed"},
            "last_error":self.status_error,"port_conflict":self.status_conflict,"public_addresses":self.config.wan.addresses,"publications":self.config.rules,
            "degraded":degradation.as_slice(),
            "observability":self.relay_observation.is_some(),
            "applied":self.healthy && self.status_error.is_none(),"lan_reachability":"unverified","internet_reachability":"unverified"});
        if let Some(epoch) = self.applied_consent.consent.epoch() {
            value["observability_epoch"] = serde_json::json!(epoch);
        }
        if let Some(token) = self.applied_consent.grant {
            value["observability_grant"] = serde_json::json!(token);
        }
        if let Some(observation) = &mut self.relay_observation {
            observation
                .notices
                .retain(|_, (_, at)| at.elapsed().as_secs() < 300);
            let notices: Vec<_> = observation.notices.iter().map(|(id, (outcome, at))| serde_json::json!({"publication":id,"outcome":outcome,"age_seconds":at.elapsed().as_secs()})).collect();
            value["relay"] = serde_json::json!({
                "connections": self.relay_sessions.connections(),
                "rejected": observation.rejected, "notices": notices, "completed": observation.completed,
            });
        }
        self.write_status(value, self.relay_observation.is_some())?;
        self.published_transport_degradation = transport_degraded;
        Ok(())
    }

    fn write_status(&self, mut value: Value, observing: bool) -> Result<(), ServiceError> {
        tokio::task::block_in_place(|| {
            if !self.config.from_uci {
                // Every JSON snapshot belongs to this lock, including stopped status.
                value["status_owner"] = serde_json::json!(self.journal.lock_identity()?);
            }
            let path = &self.config.status_file;
            let written = match crate::integration_state::atomic_write(path, &value) {
                Ok(()) => Ok(()),
                Err(IntegrationStateError::Io(error)) => Err(error),
                Err(error) => return Err(InboundRuntimeError::from(error).into()),
            };
            self.status_publication.complete(path, observing, written)?;
            Ok(())
        })
    }

    fn transport_degraded(&self) -> Result<bool, ServiceError> {
        Ok(self.config.has_relays() && self.relay_sessions.transport_initialization_failed()?)
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
                let (Some(observation), Some(connection)) =
                    (&mut self.relay_observation, completion.connection)
                else {
                    return Ok(());
                };
                if completion.outcome == RelayOutcome::Complete {
                    observation.completed = observation.completed.saturating_add(1);
                }
                let id = connection.publication;
                match completion.outcome {
                    RelayOutcome::IdentityRejected => {
                        observation.rejected = observation.rejected.saturating_add(1);
                    }
                    RelayOutcome::AdmissionTimeout => {
                        observation.rejected = observation.rejected.saturating_add(1);
                        observation
                            .notices
                            .insert(id, (RelayOutcome::AdmissionTimeout, Instant::now()));
                    }
                    RelayOutcome::Complete
                    | RelayOutcome::IdleTimeout
                    | RelayOutcome::Cancelled => {
                        observation.notices.remove(&id);
                    }
                    outcome => {
                        observation.notices.insert(id, (outcome, Instant::now()));
                    }
                }
            }
            Event::Accepted(result) => {
                let (stream, peer) = result?;
                let SocketAddr::V6(peer) = peer else {
                    self.reject_relay();
                    return Ok(());
                };
                let public = match socket2::SockRef::from(&stream)
                    .original_dst_v6()
                    .ok()
                    .and_then(|address| address.as_socket_ipv6())
                {
                    Some(public) if self.config.wan.addresses.contains(public.ip()) => public,
                    _ => {
                        self.reject_relay();
                        return Ok(());
                    }
                };
                let Some(rule) = self.config.rules.rules().iter().find(|rule| {
                    rule.enabled()
                        && rule.destination().requires_relay()
                        && rule.public_port().get() == public.port()
                }) else {
                    self.reject_relay();
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
                    self.reject_relay();
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
                        self.reject_relay();
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
        self.config
            .check_paths_with_writer(self.status_writer.is_some())
            .await?;
        crate::port_guard::check(&self.config).await?;
        let kernel = InboundKernel::new(&self.config);
        kernel.validate_routes().await?;
        if !self.ownership.admissions.is_empty() {
            kernel.check_offload().await?;
        }
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
        let guarded = InboundKernel::new(&self.config).close().await;
        match (saved, guarded) {
            (Err(storage), Err(guard)) => {
                tracing::error!(
                    target: "tunnel_detour::health",
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
        tokio::task::block_in_place(|| {
            InboundConfig::check_status_path(&config.status_file, config.from_uci)
        })?;
        let preflight = async {
            config.check_network_and_paths().await?;
            crate::port_guard::check(&config).await?;
            firewall::no_pending_changes().await
        }
        .await;
        if let Err(error) = preflight {
            // A failed preflight must not create ownership state.
            clear_prior_observations(&config);
            return Err(error);
        }
        let path = config.state_file.clone();
        let status_path = config.status_file.clone();
        let from_uci = config.from_uci;
        let initial = Ownership {
            version: 1,
            next_generation: 1,
            control: serde_json::to_value(&config)?,
            admissions: Admissions::new(),
            owned: Sections::new(),
            pending: None,
        };
        let (journal, ownership, previous, status_writer) =
            tokio::task::spawn_blocking(move || {
                crate::runtime::prepare_parent(&path)?;
                crate::runtime::prepare_parent(&status_path)?;
                InboundConfig::check_status_path(&status_path, from_uci)?;
                let status_writer = if from_uci {
                    None
                } else {
                    let guard = InboundConfig::status_writer(&status_path, true)?;
                    InboundConfig::check_json_status_snapshot(&status_path, &path)?;
                    guard
                };
                let journal = PrivateJournal::open(path).map_err(InboundRuntimeError::from)?;
                if !from_uci {
                    let identity = journal.lock_identity()?;
                    if crate::management::snapshot_owner(&status_path)?
                        .is_some_and(|owner| owner != identity)
                    {
                        return Err(crate::InboundConfigError::Paths.into());
                    }
                }
                let state = journal.load(initial).map_err(InboundRuntimeError::from)?;
                let previous = state.config()?;
                Ok::<_, ServiceError>((journal, state, previous, status_writer))
            })
            .await?
            .inspect_err(|_| clear_prior_observations(&config))?;
        if !same_identity(&previous, &config) {
            return Err(InboundRuntimeError::IdentityChange.into());
        }
        crate::management::clear_snapshot(&config.status_file, true)?;
        if ownership.pending.is_none() && !ownership.owned.is_empty() {
            // A restart can replace the published generations. Check existing NAT
            // before entering the path that can reload firewall4, including on failure.
            let current = firewall::snapshot().await?;
            let observed = ownership.observed(&current)?;
            firewall::effective_nat_matches(&previous, &observed).await?;
        }
        tokio::task::block_in_place(|| journal.save(&ownership))
            .map_err(InboundRuntimeError::from)?;
        let relay_sessions = RelaySessions::new(previous.relay.limits()?)
            .with_transport(crate::transport_worker::TransportWorker::new()?);
        let mut service = Self {
            config: previous,
            ownership,
            journal,
            status_writer,
            healthy: true,
            revision: 0,
            guard_fingerprint: None,
            relay_listener: None,
            relay_sessions,
            relay_observation: None,
            applied_consent: AppliedConsent::default(),
            observability_log: crate::ObservabilityLog::default(),
            status_error: None,
            status_conflict: Value::Null,
            published_transport_degradation: false,
            status_publication: SnapshotPublication::default(),
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
        if !config.observability_enabled() {
            self.disable_observability()?;
        }
        if !self.healthy {
            return Err(InboundRuntimeError::State.into());
        }
        if !same_identity(&self.config, &config) {
            return Err(InboundRuntimeError::IdentityChange.into());
        }
        config
            .check_paths_with_writer(self.status_writer.is_some())
            .await?;
        firewall::no_pending_changes().await?;
        crate::port_guard::check(&config).await?;
        self.recover().await?;
        let before = firewall::snapshot().await?;
        let observed = self.ownership.observed(&before)?;
        let active_kernel = InboundKernel::new(&self.config);
        let routes_applied = active_kernel.routes_applied().await?;
        if config.rules.rules().iter().any(|rule| rule.enabled()) {
            active_kernel.check_offload().await?;
        }
        firewall::validate_frontend(&before, &observed, &config)?;
        // Inspect the current policy even when the candidate changes a different
        // publication. Reconciliation must preserve unverified live restrictions.
        let nat_applied =
            self.revision != 0 && firewall::effective_nat_matches(&self.config, &observed).await?;
        // Reload triggers are package-wide. A live, unchanged publication policy
        // does not require another guard installation or firewall reload.
        if self.revision != 0
            && self.ownership.pending.is_none()
            && same_network(&self.config, &config)
            && self.config.router_addresses == config.router_addresses
            && self.config.relay == config.relay
            && self.config.max_rules == config.max_rules
            && self.config.rules.rules() == config.rules.rules()
            && routes_applied
            && self.guard_fingerprint.is_some()
            && active_kernel
                .guard_fingerprint()
                .await
                .is_ok_and(|fingerprint| self.guard_fingerprint.as_ref() == Some(&fingerprint))
            && nat_applied
        {
            self.config = config;
            self.apply_observability().await;
            return self.report_status(None);
        }
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
        if observed != desired {
            firewall::verify_nat_before_change(&[(&self.config, &observed), (&config, &desired)])
                .await?;
        }
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
        if self.revision == 0 || !same_network(&self.config, &config) {
            previous_kernel.close().await?;
        } else {
            previous_kernel
                .retire(&self.ownership.admissions, &retained)
                .await?;
        }
        self.relay_sessions.retain(&retained).await?;
        if let Some(observation) = &mut self.relay_observation {
            observation
                .notices
                .retain(|id, _| retained.contains_key(id));
        }
        if self.config.relay != config.relay {
            let transport = self.relay_sessions.reopen_transport()?;
            self.relay_sessions.shutdown().await?;
            self.relay_sessions =
                RelaySessions::new(config.relay.limits()?).with_transport(transport);
            self.relay_sessions
                .set_observability(self.applied_consent.consent.enabled());
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
            firewall::apply(
                &before,
                &observed,
                &desired,
                &[(&self.config, &observed)],
                &config,
            )
            .await?;
        }
        if !firewall::effective_nat_matches(&config, &desired).await? {
            return Err(ServiceError::KernelConflict);
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
        let kernel = InboundKernel::new(&self.config);
        kernel.admit(&admissions).await?;
        self.guard_fingerprint = match kernel.guard_fingerprint().await {
            Ok(fingerprint) => Some(fingerprint),
            Err(error) => {
                tracing::warn!(
                    target: "tunnel_detour::health",
                    code = error.code(),
                    "could not verify the applied inbound guard"
                );
                None
            }
        };
        self.healthy = true;
        self.apply_observability().await;
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
        kernel.close().await?;
        firewall::verify_nat_before_change(&[
            (&self.config, &self.ownership.owned),
            (&pending_config, &pending.owned),
        ])
        .await?;
        // The original intent already permits every intermediate subset of old/new owned
        // sections. Complete their removal before recording another intent, so a second
        // interruption cannot lose ownership of a first candidate's partially applied rules.
        firewall::apply(
            &before,
            &observed,
            &Sections::new(),
            &[
                (&self.config, &self.ownership.owned),
                (&pending_config, &pending.owned),
            ],
            &self.config,
        )
        .await?;
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
        self.set_observability(AppliedConsent::default());
        self.relay_listener = None;
        self.relay_sessions.stop_admission();
        let cleaned = self.stop_owned().await;
        let drained = self.relay_sessions.shutdown().await;
        let cleared = crate::management::clear_snapshot(&self.config.status_file, true);
        cleaned
            .and(drained.map_err(ServiceError::from))
            .and(cleared)
    }

    async fn stop_owned(&mut self) -> Result<(), ServiceError> {
        self.recover().await?;
        self.healthy = false;
        let kernel = InboundKernel::new(&self.config);
        kernel.close().await?;
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
        if !observed.is_empty() {
            firewall::verify_nat_before_change(&[(&self.config, &observed)]).await?;
            self.ownership.pending = Some(Pending {
                control: serde_json::to_value(&self.config)?,
                admissions: Admissions::new(),
                owned: Sections::new(),
            });
            self.save()?;
            firewall::apply(
                &before,
                &observed,
                &Sections::new(),
                &[(&self.config, &observed)],
                &self.config,
            )
            .await?;
        }
        kernel.clear_conntrack().await?;
        crate::kernel::RoutingOwner::inbound(&self.config, true)
            .stop_routes()
            .await?;
        kernel.remove().await?;
        self.ownership.admissions.clear();
        self.ownership.owned.clear();
        self.ownership.pending = None;
        self.save()?;
        self.write_status(
            serde_json::json!({"process_id":std::process::id(),"phase":"stopped","applied":false,"observability":false}),
            false,
        )?;
        Ok(())
    }
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
    if !preview.is_empty() {
        InboundKernel::new(config).check_offload().await?;
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
        return crate::management::finish_uci_cleanup(true);
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
        return crate::management::finish_uci_cleanup(true);
    }
    let relay_sessions = RelaySessions::new(actual.relay.limits()?);
    let mut service = BoundInbound {
        config: actual,
        ownership,
        journal,
        status_writer: None,
        healthy: false,
        revision: 0,
        guard_fingerprint: None,
        relay_listener: None,
        relay_sessions,
        relay_observation: None,
        applied_consent: AppliedConsent::default(),
        observability_log: crate::ObservabilityLog::default(),
        status_error: None,
        status_conflict: Value::Null,
        published_transport_degradation: false,
        status_publication: SnapshotPublication::default(),
    };
    let stopped = service.stop().await;
    stopped.and(crate::management::finish_uci_cleanup(true))
}
