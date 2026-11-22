use std::{
    fs,
    io::{self, Write},
    net::SocketAddr,
    num::NonZeroUsize,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use tempfile::NamedTempFile;
use thiserror::Error;
use tokio::{
    net::{TcpListener, TcpSocket, TcpStream, UdpSocket},
    sync::Semaphore,
    task::JoinSet,
    time::{MissedTickBehavior, interval},
};
use tokio_util::sync::CancellationToken;
use tunnel_detour_core::{
    ConnectionError, DnsAddressFamilies, DnsWireError, ExceptionPolicy, LeaseStore, StoreError,
    Timestamp,
};

use crate::{
    ConfigError, ServiceConfig, ServicePhase, StatusHandle,
    dns::DnsHandler,
    kernel::Kernel,
    observability::{AppliedConsent, Consent},
    proxy::ProxyHandler,
    status::SnapshotPublication,
    upstream::RealResolver,
};

#[derive(Debug, Error)]
pub enum ServiceError {
    #[error(transparent)]
    Relay(#[from] crate::RelayError),
    #[error(transparent)]
    PortGuard(#[from] crate::port_guard::PortGuardError),
    #[error(transparent)]
    InboundRuntime(#[from] crate::inbound::InboundRuntimeError),
    #[error(transparent)]
    InboundConfig(#[from] crate::inbound_config::InboundConfigError),
    #[error(transparent)]
    InboundPolicy(#[from] tunnel_detour_core::InboundError),
    #[error(transparent)]
    Dnsmasq(#[from] crate::dnsmasq::DnsmasqError),
    #[error(transparent)]
    Uci(#[from] crate::uci::UciError),
    #[error(transparent)]
    Adguard(#[from] crate::adguard::AdguardError),
    #[error("private AdGuard credential storage failed")]
    CredentialStorage(#[source] crate::integration_state::IntegrationStateError),
    #[error("service I/O failed")]
    Io(#[from] io::Error),
    #[error("service JSON could not be processed")]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error(transparent)]
    Dns(#[from] DnsWireError),
    #[error(transparent)]
    Connection(#[from] ConnectionError),
    #[error("DNS upstream supplied an invalid or oversized response")]
    Protocol,
    #[error("DNS upstream returned an unsuccessful response ({0})")]
    UpstreamResponse(hickory_proto::op::ResponseCode),
    #[error("DNS upstream did not supply a usable destination for the enabled WAN families")]
    NoAddress,
    #[error("DNS alias chain is cyclic or too long")]
    AliasLoop,
    #[error("DNS destination is a private, local, or synthetic address")]
    ForbiddenTarget,
    #[error("the real DNS resolver needs an explicit existing route outside WAN")]
    ResolverRoute,
    #[error("finish or restore the pending resolver change before selecting another endpoint")]
    ResolverRecovery { allowed: Vec<std::net::SocketAddr> },
    #[error("AdGuard filtering or a DNS rewrite prevents this WAN destination")]
    FilteredTarget,
    #[error("client is outside the authorized LAN networks")]
    Unauthorized,
    #[error("request deadline expired")]
    Timeout,
    #[error("service operation was cancelled")]
    Cancelled,
    #[error("service request capacity is exhausted")]
    Busy,
    #[error("shared state failed; service must stop")]
    Poisoned,
    #[error("a service task failed")]
    Task(#[from] tokio::task::JoinError),
    #[error("system clock is before the Unix epoch")]
    Clock,
    #[error("connection identifier space is exhausted")]
    IdentifierExhausted,
    #[error("kernel objects conflict with existing routing or firewall configuration")]
    KernelConflict,
    #[error("inbound firewall4 NAT policy could not be verified ({stage})")]
    InboundNatConflict { stage: &'static str },
    #[error("inbound firewall4 NAT inspection failed")]
    InboundNatInspection(#[source] Box<ServiceError>),
    #[error("the selected IPv6 LAN or preferred WAN source is unavailable")]
    Ipv6Path,
    #[error("IPv6 routing ownership state failed")]
    Ipv6State(#[source] crate::integration_state::IntegrationStateError),
    #[error("kernel configuration command failed: {detail}")]
    KernelCommand { detail: String },
}

impl ServiceError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Relay(_) => "inbound_relay_failed",
            Self::InboundRuntime(crate::InboundRuntimeError::RelayListener { .. }) => {
                "inbound_relay_listener_failed"
            }
            Self::PortGuard(crate::PortGuardError::RelayOccupied { .. }) => {
                "inbound_relay_port_conflict"
            }
            Self::PortGuard(crate::PortGuardError::Occupied { .. }) => {
                "inbound_local_port_conflict"
            }
            Self::PortGuard(_) => "inbound_port_inspection_failed",
            Self::InboundConfig(_) | Self::InboundPolicy(_) => "inbound_configuration_failed",
            Self::InboundRuntime(_) => "inbound_operation_failed",
            Self::Dnsmasq(_) => "dnsmasq_integration_failed",
            Self::Uci(crate::uci::UciError::Credentials) => "adguard_credentials_unavailable",
            Self::CredentialStorage(_) => "adguard_credentials_storage_failed",
            Self::Uci(_) => "uci_configuration_failed",
            Self::Adguard(crate::adguard::AdguardError::UpstreamApproval) => {
                "adguard_upstream_approval_required"
            }
            Self::Adguard(crate::adguard::AdguardError::ConcurrentChange) => {
                "adguard_upstream_conflict"
            }
            Self::Adguard(crate::adguard::AdguardError::Ipv6Disabled) => "adguard_ipv6_disabled",
            Self::Adguard(crate::adguard::AdguardError::RemoteEndpoint) => {
                "adguard_endpoint_not_local"
            }
            Self::Adguard(
                crate::adguard::AdguardError::UnsupportedGeneralUpstreams
                | crate::adguard::AdguardError::UnsupportedUpstreams,
            ) => "adguard_upstream_unsupported",
            Self::Adguard(_) => "adguard_integration_failed",
            Self::Io(_) => "io_error",
            Self::Json(_) => "json_error",
            Self::Config(_) => "invalid_configuration",
            Self::Store(StoreError::Lease(tunnel_detour_core::FakeIpError::RuleCapacity))
            | Self::Dns(DnsWireError::Store(StoreError::Lease(
                tunnel_detour_core::FakeIpError::RuleCapacity,
            ))) => "mapping_rule_capacity",
            Self::Store(_) => "lease_storage_error",
            Self::Dns(_) => "dns_error",
            Self::Connection(_) => "connection_rejected",
            Self::Protocol => "invalid_dns_response",
            Self::UpstreamResponse(_) => "upstream_dns_rejected",
            Self::NoAddress => "no_usable_address",
            Self::AliasLoop => "dns_alias_loop",
            Self::ForbiddenTarget => "forbidden_destination",
            Self::ResolverRoute => "resolver_route_unavailable",
            Self::ResolverRecovery { .. } => "resolver_recovery_required",
            Self::FilteredTarget => "filtered_destination",
            Self::Unauthorized => "unauthorized_source",
            Self::Timeout => "deadline_expired",
            Self::Cancelled => "cancelled",
            Self::Busy => "capacity_exhausted",
            Self::Poisoned => "state_unavailable",
            Self::Task(_) => "task_failed",
            Self::Clock => "invalid_clock",
            Self::IdentifierExhausted => "identifier_exhausted",
            Self::KernelConflict
            | Self::InboundNatConflict { .. }
            | Self::InboundNatInspection(_) => "kernel_conflict",
            Self::Ipv6Path => "ipv6_path_unavailable",
            Self::Ipv6State(_) => "ipv6_routing_state_invalid",
            Self::KernelCommand { .. } => "kernel_command_failed",
        }
    }

    /// Return fixed operational context without including rule contents or traffic details.
    pub fn inbound_nat_stage(&self) -> Option<&'static str> {
        match self {
            Self::InboundNatConflict { stage } => Some(stage),
            Self::InboundNatInspection(_) => Some("inspection"),
            _ => None,
        }
    }

    pub(crate) fn is_critical(&self) -> bool {
        match self {
            Self::Store(error)
            | Self::Dns(DnsWireError::Store(error))
            | Self::Connection(ConnectionError::Store(error)) => !matches!(
                error,
                StoreError::Lease(
                    tunnel_detour_core::FakeIpError::Exhausted
                        | tunnel_detour_core::FakeIpError::RuleCapacity
                        | tunnel_detour_core::FakeIpError::ClockReversed
                        | tunnel_detour_core::FakeIpError::TimeOverflow
                        | tunnel_detour_core::FakeIpError::InvalidTtl
                )
            ),
            Self::Poisoned
            | Self::Task(_)
            | Self::Clock
            | Self::IdentifierExhausted
            | Self::KernelConflict
            | Self::InboundNatConflict { .. }
            | Self::InboundNatInspection(_)
            | Self::Ipv6Path
            | Self::Ipv6State(_)
            | Self::KernelCommand { .. } => true,
            _ => false,
        }
    }

    pub(crate) fn degradation_code(&self) -> Option<&'static str> {
        match self {
            Self::Adguard(crate::adguard::AdguardError::Ipv6Disabled)
            | Self::Dnsmasq(
                crate::dnsmasq::DnsmasqError::Profile
                | crate::dnsmasq::DnsmasqError::State
                | crate::dnsmasq::DnsmasqError::Apply,
            ) => Some(self.code()),
            Self::Dns(DnsWireError::Store(StoreError::Lease(
                tunnel_detour_core::FakeIpError::Exhausted,
            ))) => Some("mapping_pool_exhausted"),
            _ => None,
        }
    }
}

pub(crate) fn now() -> Result<Timestamp, ServiceError> {
    Ok(Timestamp::from_unix_seconds(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| ServiceError::Clock)?
            .as_secs(),
    ))
}

/// Owns listeners and persistent policy. Bind and run on a Tokio multi-thread runtime.
pub struct BoundService {
    transport: crate::transport_worker::TransportWorker,
    config: Arc<ServiceConfig>,
    dns_udp: Arc<UdpSocket>,
    dns_tcp: TcpListener,
    proxy: TcpListener,
    proxy_ipv6: Option<TcpListener>,
    ipv6_routing: Option<Arc<crate::ipv6_routing::Ipv6Routing>>,
    policy: Arc<Mutex<ExceptionPolicy>>,
    status: StatusHandle,
    status_owner: Option<[u64; 2]>,
    _status_writer: Option<fs::File>,
    status_publication: SnapshotPublication,
    observability_log: crate::ObservabilityLog,
    config_path: Option<PathBuf>,
}

impl BoundService {
    pub async fn bind(config: ServiceConfig) -> Result<Self, ServiceError> {
        let preflight = match &config.ipv6 {
            Some(ipv6) => ipv6.inspect(&config.lan_device).await,
            None => Ok(()),
        };
        let config = Arc::new(config);
        let state_config = config.clone();
        let (policy, status_owner, clear_before_bind, status_writer) =
            tokio::task::spawn_blocking(move || {
                prepare_parent(&state_config.state_file)?;
                prepare_parent(&state_config.status_file)?;
                let state_parent = state_config.state_file.parent().ok_or(ConfigError::Paths)?;
                let status_parent = state_config
                    .status_file
                    .parent()
                    .ok_or(ConfigError::Paths)?;
                let state_name = state_config
                    .state_file
                    .file_name()
                    .ok_or(ConfigError::Paths)?;
                let status_name = state_config
                    .status_file
                    .file_name()
                    .ok_or(ConfigError::Paths)?;
                if !state_config.from_uci
                    && crate::management::is_uci_status_path(&state_config.status_file)?
                {
                    return Err(ConfigError::Paths.into());
                }
                let writer =
                    crate::integration_state::status_writer_path(&state_config.status_file);
                let writer_name = writer.file_name().ok_or(ConfigError::Paths)?;
                if fs::canonicalize(state_parent)? == fs::canonicalize(status_parent)?
                    && [
                        "",
                        ".lock",
                        ".adguard.json",
                        ".adguard.json.lock",
                        ".adguard-preview.json",
                        ".dnsmasq.json",
                        ".dnsmasq.json.lock",
                        ".ipv6-routing.json",
                        ".ipv6-routing.json.lock",
                    ]
                    .iter()
                    .any(|suffix| {
                        let mut name = state_name.to_os_string();
                        name.push(suffix);
                        name == status_name || (!state_config.from_uci && name == writer_name)
                    })
                {
                    return Err(ServiceError::Config(ConfigError::Paths));
                }
                let status_writer = if state_config.from_uci {
                    Ok(None)
                } else {
                    crate::management::status_writer(
                        &state_config.status_file,
                        preflight.is_ok(),
                        || ConfigError::Paths.into(),
                    )
                };
                let (preflight, status_writer) = match (preflight, status_writer) {
                    // Cleanup is optional after a refused startup. An inaccessible
                    // writer prohibits cleanup without replacing the original error.
                    (Err(error), Err(_)) => return Err(error),
                    (preflight, writer) => (preflight, writer?),
                };
                let store = preflight
                    .and_then(|()| {
                        let capacity = NonZeroUsize::new(state_config.limits.max_mappings)
                            .ok_or(ConfigError::Limits)?;
                        LeaseStore::open(
                            &state_config.state_file,
                            state_config.fake_range,
                            capacity,
                        )
                        .map_err(ServiceError::from)
                    })
                    .inspect_err(|error| {
                        // A refused preflight or corrupt lease can leave a prior snapshot.
                        // Purge it only under idle ownership, preserving the startup error.
                        if !state_config.observability_enabled()
                            && !matches!(error, ServiceError::Store(StoreError::Lock(_)))
                        {
                            crate::management::clear_when_idle(&state_config.state_file, |lock| {
                                if state_config.from_uci
                                    || crate::management::snapshot_matches_lock(
                                        &state_config.status_file,
                                        lock,
                                    )?
                                {
                                    crate::management::clear_snapshot(
                                        &state_config.status_file,
                                        false,
                                    )?;
                                }
                                Ok(())
                            });
                        }
                    })?;
                let (status_owner, clear_before_bind) = if state_config.from_uci {
                    (None, true)
                } else {
                    let identity = store.lock_identity()?;
                    let previous = crate::management::snapshot_owner(&state_config.status_file)?;
                    if previous.is_some_and(|owner| owner != identity) {
                        return Err(ConfigError::Paths.into());
                    }
                    (Some(identity), previous.is_some())
                };
                let mut policy = ExceptionPolicy::with_families(
                    state_config.rules.clone(),
                    store,
                    Duration::from_secs(state_config.limits.ttl_seconds),
                    if state_config.ipv6.is_some() {
                        DnsAddressFamilies::DualStack
                    } else {
                        DnsAddressFamilies::Ipv4Only
                    },
                )
                .map_err(|error| ServiceError::Config(ConfigError::Range(error)))?;
                policy.set_mapping_limit_per_rule(
                    NonZeroUsize::new(state_config.limits.max_mappings_per_rule)
                        .ok_or(ConfigError::Limits)?,
                );
                Ok::<_, ServiceError>((policy, status_owner, clear_before_bind, status_writer))
            })
            .await??;
        let mut consent = AppliedConsent::for_json(config.observability);
        if config.from_uci {
            consent = AppliedConsent::confirm_uci(false, config.observability).await;
        }
        if clear_before_bind {
            crate::management::clear_snapshot(&config.status_file, false)?;
        }
        let transport = tokio::task::block_in_place(crate::transport_worker::TransportWorker::new)?;
        let dns_tcp = TcpListener::bind(config.dns_listen).await?;
        let dns_udp = Arc::new(UdpSocket::bind(dns_tcp.local_addr()?).await?);
        if dns_tcp.local_addr()? == config.real_upstream {
            return Err(ConfigError::DnsListener.into());
        }
        let proxy = TcpListener::bind(config.proxy_listen).await?;
        let proxy_ipv6 = if config.ipv6.is_some() {
            let socket = TcpSocket::new_v6()?;
            socket2::SockRef::from(&socket).set_only_v6(true)?;
            socket.set_reuseaddr(true)?;
            socket.bind(SocketAddr::new(
                std::net::Ipv6Addr::UNSPECIFIED.into(),
                proxy.local_addr()?.port(),
            ))?;
            Some(socket.listen(
                u32::try_from(config.limits.connections).map_err(|_| ConfigError::Limits)?,
            )?)
        } else {
            None
        };
        let ipv6_routing = crate::ipv6_routing::Ipv6Routing::prepare(&config).await?;
        if !clear_before_bind {
            // A legacy JSON snapshot has no ownership stamp. Adopt its path
            // only after all startup checks for this controller have passed.
            if crate::management::snapshot_owner(&config.status_file)?
                .is_some_and(|owner| Some(owner) != status_owner)
            {
                return Err(ConfigError::Paths.into());
            }
            crate::management::clear_snapshot(&config.status_file, false)?;
        }
        let status = StatusHandle::new();
        status.set_observability(consent)?;
        Ok(Self {
            transport,
            config,
            dns_tcp,
            dns_udp,
            proxy,
            proxy_ipv6,
            ipv6_routing,
            policy: Arc::new(Mutex::new(policy)),
            status,
            status_owner,
            _status_writer: status_writer,
            status_publication: SnapshotPublication::default(),
            observability_log: crate::ObservabilityLog::default(),
            config_path: None,
        })
    }

    pub fn dns_address(&self) -> Result<SocketAddr, ServiceError> {
        Ok(self.dns_tcp.local_addr()?)
    }
    pub fn proxy_address(&self) -> Result<SocketAddr, ServiceError> {
        Ok(self.proxy.local_addr()?)
    }
    pub fn status(&self) -> StatusHandle {
        self.status.clone()
    }

    /// Share the daemon's local logging gate with the reload path.
    pub fn with_observability_log(mut self, log: crate::ObservabilityLog) -> Self {
        log.set_enabled(self.status.is_observing().is_ok_and(|enabled| enabled));
        self.observability_log = log;
        self
    }

    async fn set_uci_observability(&self, consent: Consent) -> Result<(), ServiceError> {
        let applied = AppliedConsent::confirm_uci(false, consent).await;
        self.apply_observability(applied)
    }

    fn apply_observability(&self, applied: AppliedConsent) -> Result<(), ServiceError> {
        let enabled = applied.consent.enabled();
        self.observability_log.set_enabled(enabled);
        if self.status.set_observability(applied)? {
            if enabled {
                tracing::info!(target: "tunnel_detour::diagnostics", "DNS traffic diagnostics enabled");
            }
            if let Err(error) = self.write_status() {
                // Snapshot I/O errors already attempted removal. An internal
                // failure preparing the new snapshot must not skip that purge.
                if !matches!(error, ServiceError::Io(_)) {
                    tokio::task::block_in_place(|| {
                        crate::observability::discard_snapshot(&self.config.status_file)
                    })?;
                }
                return Err(error);
            }
        }
        Ok(())
    }

    /// Re-read diagnostics consent on HUP for an explicitly supplied JSON configuration.
    pub fn with_config_path(mut self, path: PathBuf) -> Self {
        self.config_path = Some(path);
        self
    }

    async fn accept_proxy(&self) -> io::Result<(TcpStream, SocketAddr)> {
        match &self.proxy_ipv6 {
            Some(ipv6) => {
                tokio::select! { result = self.proxy.accept() => result, result = ipv6.accept() => result }
            }
            None => self.proxy.accept().await,
        }
    }

    /// Install only owned kernel objects, then serve until cancellation or a critical failure.
    /// DNS and copy tasks are supervised and drained before removing the WAN routing rule.
    pub async fn run(self, cancel: CancellationToken) -> Result<(), ServiceError> {
        let reload = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())?;
        self.run_with_reload(cancel, reload).await
    }

    /// Use a signal registered before startup so native reload cannot terminate
    /// the process while its configuration and listeners are still being prepared.
    pub async fn run_with_reload(
        self,
        cancel: CancellationToken,
        mut reload: tokio::signal::unix::Signal,
    ) -> Result<(), ServiceError> {
        // Native cached-address protection must survive losing the dynamic nft
        // table at boot. The lease lock is held and no DNS work is admitted yet.
        if self.config.from_uci {
            crate::cache_guard::preserve(self.config.fake_range).await?;
        }
        if self.status.is_observing()? {
            tracing::info!(target: "tunnel_detour::diagnostics", "DNS traffic diagnostics enabled");
        }
        self.write_status()?;
        let resolver = match RealResolver::new(self.config.clone()).await {
            Ok(resolver) => resolver,
            Err(error) => {
                self.status.failure(&error)?;
                self.status.phase(ServicePhase::Failed)?;
                self.write_status()?;
                return Err(error);
            }
        };
        let kernel = Kernel::new(self.config.clone(), self.ipv6_routing.clone());
        let initial = resolver.snapshot()?;
        if let Err(error) = kernel
            .install(self.proxy.local_addr()?.port(), &initial.path)
            .await
        {
            if let Err(cleanup_error) = kernel.stop_routes().await {
                tracing::error!(
                    target: "tunnel_detour::health",
                    code = cleanup_error.code(),
                    "routing cleanup failed after kernel setup failure"
                );
            }
            self.status.failure(&error)?;
            self.status.phase(ServicePhase::Failed)?;
            self.write_status()?;
            return Err(error);
        }
        let manager = crate::frontend::FrontendManager::new(self.config.clone()).await;
        let mut manager = match manager {
            Ok(manager) => manager,
            Err(error) => {
                let cleanup = kernel.stop_routes().await;
                if let Err(cleanup_error) = cleanup {
                    tracing::error!(
                        target: "tunnel_detour::health",
                        code = cleanup_error.code(),
                        "routing cleanup failed after startup failure"
                    );
                }
                self.status.failure(&error)?;
                self.status.phase(ServicePhase::Failed)?;
                self.write_status()?;
                return Err(error);
            }
        };
        let serving = self.serve(cancel.clone(), resolver.clone());
        tokio::pin!(serving);
        let setup = async {
            let SocketAddr::V4(dns) = self.dns_address()? else {
                return Err(ServiceError::Protocol);
            };
            manager.reconcile(Some((dns, &self.config.rules))).await?;
            kernel
                .resolver_guards(std::slice::from_ref(&initial.path))
                .await?;
            self.status.resolver_applied(&self.config, &initial.path)?;
            self.write_status()?;
            let mut applied = initial;
            let mut pending_path: Option<crate::upstream_route::ResolverPath> = None;
            let mut audit = interval(Duration::from_secs(30));
            audit.set_missed_tick_behavior(MissedTickBehavior::Skip);
            audit.tick().await;
            let mut audit_healthy = true;
            loop {
                let requested = tokio::select! {
                    () = cancel.cancelled() => return Ok::<_, ServiceError>(()),
                    signal = reload.recv(), if self.config.from_uci || self.config_path.is_some() => {
                        if signal.is_none() { return Err(ServiceError::Cancelled); }
                        true
                    },
                    _ = audit.tick(), if applied.config.manage_adguard_upstream => false,
                };
                if !requested {
                    // Detect foreign edits without issuing a repairing write.
                    // Explicit reconciliation is required to leave this fence.
                    if let Err(error) = crate::frontend::check(&applied.config).await {
                        resolver.pause()?;
                        self.status.resolver_pending(Some(applied.path.endpoint))?;
                        self.status.phase(ServicePhase::Failed)?;
                        if audit_healthy {
                            self.status.failure(&error)?;
                            tracing::warn!(
                                target: "tunnel_detour::health",
                                code = error.code(),
                                "managed DNS audit failed; new exception work is fenced"
                            );
                        }
                        audit_healthy = false;
                        self.write_status()?;
                    }
                    continue;
                }
                if let Some(path) = &self.config_path {
                    let candidate = tokio::task::block_in_place(|| ServiceConfig::load_file(path));
                    match candidate {
                        Ok(candidate) => {
                            self.apply_observability(AppliedConsent::for_json(
                                candidate.observability,
                            ))?;
                            if audit_healthy && resolver.snapshot().is_ok() {
                                self.status
                                    .resolver_applied(&applied.config, &applied.path)?;
                            }
                            self.status.restart_required(
                                !self.config.same_runtime(&candidate)
                                    || !self.config.same_resolver_settings(&candidate),
                            )?;
                            self.write_status()?;
                        }
                        Err(error) => {
                            self.apply_observability(AppliedConsent::default())?;
                            if audit_healthy && resolver.snapshot().is_ok() {
                                self.status.resolver_pending(None)?;
                                self.status.failure(&error)?;
                            }
                            self.status.restart_required(false)?;
                            self.write_status()?;
                        }
                    }
                    continue;
                }
                let sections = crate::uci::read_sections().await;
                let requested = sections
                    .as_ref()
                    .map_or(Consent::Off, |sections| sections.consent("globals"));
                let control = self
                    .status
                    .applied_consent()?
                    .invalidate_uci(false, requested);
                self.apply_observability(control)?;
                let candidate = match match sections {
                    Ok(sections) => crate::uci::load_dns_sections(sections, false).await,
                    Err(error) => Err(error),
                } {
                    Ok(Some(candidate)) => Arc::new(candidate),
                    Ok(None) => return Ok(()),
                    Err(error) => {
                        self.set_uci_observability(Consent::Off).await?;
                        self.status.resolver_pending(None)?;
                        self.status.failure(&error)?;
                        self.write_status()?;
                        continue;
                    }
                };
                if !self.config.same_runtime(&candidate) {
                    // procd replaces this instance for a structural revision.
                    // Never partially apply different listeners or exception rules.
                    self.status
                        .resolver_pending(Some(candidate.real_upstream))?;
                    self.write_status()?;
                    continue;
                }
                // A package-wide configuration event can concern only inbound ports.
                // Verify the applied route and frontend before skipping a full rewrite.
                if audit_healthy
                    && pending_path.is_none()
                    && resolver.snapshot().is_ok()
                    && candidate.same_resolver_settings(&applied.config)
                    && crate::upstream_route::ResolverPath::prepare(&candidate)
                        .await
                        .is_ok_and(|path| path == applied.path)
                    && Kernel::resolver_guard_applied(&applied.path)
                        .await
                        .is_ok_and(|applied| applied)
                    && manager
                        .forwarding_applied(&candidate)
                        .await
                        .is_ok_and(|applied| applied)
                {
                    self.status.resolver_applied(&candidate, &applied.path)?;
                    self.set_uci_observability(candidate.observability).await?;
                    self.write_status()?;
                    continue;
                }
                self.status
                    .resolver_pending(Some(candidate.real_upstream))?;
                let update = async {
                    let path = crate::upstream_route::ResolverPath::prepare(&candidate).await?;
                    if let Some(pending) = &pending_path
                        && path != *pending
                        && path != applied.path
                    {
                        return Err(ServiceError::ResolverRecovery {
                            allowed: vec![applied.path.endpoint, pending.endpoint],
                        });
                    }
                    crate::frontend::check(&candidate).await?;
                    let mut guards = vec![applied.path.clone(), path.clone()];
                    if let Some(pending) = &pending_path
                        && path == applied.path
                    {
                        guards[1] = pending.clone();
                    }
                    kernel.resolver_guards(&guards).await?;
                    resolver.pause()?;
                    self.status.phase(ServicePhase::Starting)?;
                    self.write_status()?;
                    pending_path = Some(path.clone());
                    manager.resolver_settings(candidate.clone());
                    manager.reconcile(Some((dns, &candidate.rules))).await?;
                    // A confirmed AdGuard write has reconfigured its DNS proxy
                    // and closed the old upstream pool. In-flight local queries
                    // retain the device captured with their resolver snapshot.
                    kernel.resolver_guards(std::slice::from_ref(&path)).await?;
                    resolver.activate(candidate.clone(), path.clone())?;
                    self.status.resolver_applied(&candidate, &path)?;
                    self.status.clear_frontend_degradation()?;
                    self.set_uci_observability(candidate.observability).await?;
                    applied = crate::upstream::ResolverSnapshot {
                        config: candidate.clone(),
                        path,
                    };
                    pending_path = None;
                    audit_healthy = true;
                    Ok::<_, ServiceError>(())
                }
                .await;
                if let Err(error) = update {
                    self.apply_observability(AppliedConsent::default())?;
                    if pending_path.is_some()
                        || matches!(&error, ServiceError::Adguard(_) | ServiceError::Dnsmasq(_))
                    {
                        resolver.pause()?;
                        self.status.phase(ServicePhase::Failed)?;
                    }
                    self.status.failure(&error)?;
                    tracing::warn!(
                        target: "tunnel_detour::health",
                        code = error.code(),
                        "resolver change was not applied; established TCP streams are preserved"
                    );
                    if error.is_critical() {
                        return Err(error);
                    }
                }
                self.write_status()?;
            }
        };
        let result = tokio::select! {
            result = &mut serving => result,
            result = setup => match result {
                Ok(()) => { cancel.cancel(); serving.await },
                Err(error) => {
                    cancel.cancel();
                    if let Err(stop_error) = serving.await {
                        tracing::error!(
                            target: "tunnel_detour::health",
                            code = stop_error.code(),
                            "service stopped after setup failure"
                        );
                    }
                    self.status.failure(&error)?; Err(error)
                },
            },
        };
        cancel.cancel();
        let cleanup = kernel.stop_routes().await;
        if let Err(error) = &cleanup {
            if result.is_err() {
                tracing::error!(
                    target: "tunnel_detour::health",
                    code = error.code(),
                    "routing cleanup also failed; ownership state retained"
                );
            } else {
                self.status.failure(error)?;
            }
        }
        let disable = async {
            if self.config.from_uci && !crate::uci::is_enabled().await? {
                manager.reconcile(None).await?;
            }
            Ok::<_, ServiceError>(())
        }
        .await;
        if let Err(error) = &disable {
            if result.is_err() || cleanup.is_err() {
                tracing::error!(
                    target: "tunnel_detour::health",
                    code = error.code(),
                    "DNS forwarding cleanup also failed; ownership state retained"
                );
            } else {
                self.status.failure(error)?;
            }
        }
        self.status
            .phase(if result.is_ok() && cleanup.is_ok() && disable.is_ok() {
                ServicePhase::Stopped
            } else {
                ServicePhase::Failed
            })?;
        self.status.clear_connections()?;
        self.write_status()?;
        result.and(cleanup).and(disable)
    }

    fn write_status(&self) -> Result<(), ServiceError> {
        let mut status = self.status.snapshot()?;
        status.status_owner = self.status_owner;
        if status.observability {
            status.set_mapping_usage(
                self.policy
                    .lock()
                    .map_err(|_| ServiceError::Poisoned)?
                    .mapping_usage()?,
            );
        }
        let path = &self.config.status_file;
        let parent = path.parent().ok_or(ConfigError::Paths)?;
        tokio::task::block_in_place(|| {
            let bytes = serde_json::to_vec(&status)?;
            let written = (|| {
                let mut temporary = NamedTempFile::new_in(parent)?;
                temporary.write_all(&bytes)?;
                temporary.persist(path).map_err(|error| error.error)?;
                Ok(())
            })();
            self.status_publication
                .complete(path, status.observability, written)?;
            Ok(())
        })
    }

    async fn serve(
        &self,
        cancel: CancellationToken,
        resolver: RealResolver,
    ) -> Result<(), ServiceError> {
        let dns = DnsHandler {
            config: self.config.clone(),
            policy: self.policy.clone(),
            resolver: resolver.clone(),
            status: self.status.clone(),
        };
        let proxy = Arc::new(ProxyHandler {
            transport: self.transport.clone(),
            config: self.config.clone(),
            policy: self.policy.clone(),
            resolver,
            status: self.status.clone(),
        });
        let dns_slots = Arc::new(Semaphore::new(self.config.limits.dns_jobs));
        let proxy_slots = Arc::new(Semaphore::new(self.config.limits.connections));
        let job_limit = self
            .config
            .limits
            .dns_jobs
            .checked_add(self.config.limits.connections)
            .ok_or(ConfigError::Limits)?;
        let mut jobs = JoinSet::new();
        let mut packet = vec![0; usize::from(u16::MAX)];
        let mut ticker = interval(Duration::from_secs(1));
        ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
        let mut outcome = async { loop {
            tokio::select! {
                () = cancel.cancelled() => break Ok(()),
                result = self.dns_udp.recv_from(&mut packet), if jobs.len() < job_limit => {
                    let (length, peer) = match result { Ok(result) => result, Err(error) => break Err(error.into()) };
                    let observation = self.status.observation()?;
                    if !peer.ip().is_loopback() { self.status.request_failure(&observation, &ServiceError::Unauthorized)?; continue; }
                    match dns_slots.clone().try_acquire_owned() {
                        Ok(permit) => {
                            let handler = dns.clone(); let socket = self.dns_udp.clone(); let packet = packet[..length].to_vec();
                            jobs.spawn(async move { let _permit = permit; (observation, handler.udp(socket, peer, packet).await) });
                        },
                        Err(_) => self.status.request_failure(&observation, &ServiceError::Busy)?,
                    }
                },
                result = self.dns_tcp.accept(), if jobs.len() < job_limit => {
                    let (stream, peer) = match result { Ok(result) => result, Err(error) => break Err(error.into()) };
                    let observation = self.status.observation()?;
                    if !peer.ip().is_loopback() { self.status.request_failure(&observation, &ServiceError::Unauthorized)?; continue; }
                    match dns_slots.clone().try_acquire_owned() {
                        Ok(permit) => {
                            let handler = dns.clone(); let token = cancel.clone();
                            jobs.spawn(async move { let _permit = permit; (observation, handler.tcp(stream, token).await) });
                        },
                        Err(_) => self.status.request_failure(&observation, &ServiceError::Busy)?,
                    }
                },
                result = self.accept_proxy(), if jobs.len() < job_limit => {
                    let (stream, peer) = match result { Ok(result) => result, Err(error) => break Err(error.into()) };
                    let observation = self.status.observation()?;
                    match proxy_slots.clone().try_acquire_owned() {
                        Ok(permit) => {
                            let handler = proxy.clone(); let token = cancel.clone();
                            jobs.spawn(async move { let _permit = permit; let result = handler.serve(&observation, stream, peer, token).await; (observation, result) });
                        },
                        Err(_) => self.status.request_failure(&observation, &ServiceError::Busy)?,
                    }
                },
                result = jobs.join_next(), if !jobs.is_empty() => {
                    match result {
                        Some(Ok((_, Ok(())))) => {},
                        Some(Ok((observation, Err(error)))) => {
                            if error.is_critical() { break Err(error); }
                            self.status.request_failure(&observation, &error)?;
                        },
                        Some(Err(error)) => break Err(ServiceError::Task(error)),
                        None => {},
                    }
                },
                _ = ticker.tick() => {
                    if self.config.from_uci {
                        let current = self.status.applied_consent()?;
                        self.apply_observability(current.invalidate_uci(false, current.consent))?;
                    }
                    if let Some(ipv6) = &self.config.ipv6
                        && let Err(error) = ipv6.inspect(&self.config.lan_device).await
                    { break Err(error); }
                    self.status.set_transport_degraded(self.transport.initialization_failed()?)?;
                    if (self.status.take_health_change()?
                        || self.status.is_observing()?
                        || self.status_publication.retry_pending())
                        && let Err(error) = self.write_status() { break Err(error); }
                },
            }
        }}.await;
        cancel.cancel();
        if let Err(error) = &outcome
            && let Err(report) = self.status.failure(error)
        {
            // Even a broken status collector must not detach admitted jobs.
            tracing::error!(
                target: "tunnel_detour::health",
                code = report.code(),
                "fatal traffic failure could not be recorded"
            );
        }
        if let Err(error) = self.status.phase(if outcome.is_ok() {
            ServicePhase::Stopping
        } else {
            ServicePhase::Failed
        }) && outcome.is_ok()
        {
            outcome = Err(error);
        }
        // Network waits are bounded or cancellation-aware. Never abort a durable state operation
        // mid-poll: even if shutdown races an fsync, its completion stays owned by this JoinSet.
        while let Some(result) = jobs.join_next().await {
            match result {
                Ok((_, Ok(()))) => {}
                Ok((observation, Err(error))) => {
                    let report = if !error.is_critical() {
                        self.status.request_failure(&observation, &error)
                    } else if outcome.is_err() {
                        self.status.secondary_failure(&error)
                    } else {
                        self.status.failure(&error)
                    };
                    if let Err(status_error) = report
                        && outcome.is_ok()
                    {
                        outcome = Err(status_error);
                    }
                    if error.is_critical() && outcome.is_ok() {
                        outcome = Err(error);
                    }
                }
                Err(error) => {
                    if outcome.is_ok() {
                        outcome = Err(error.into());
                    }
                }
            }
        }
        outcome
    }
}

pub(crate) fn prepare_parent(path: &std::path::Path) -> Result<(), ServiceError> {
    let parent = path.parent().ok_or(ConfigError::Paths)?;
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(parent)?;
    let metadata = fs::symlink_metadata(parent)?;
    if !metadata.is_dir() {
        return Err(ConfigError::Paths.into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.permissions().mode() & 0o077 != 0
            || metadata.uid() != rustix::process::geteuid().as_raw()
        {
            return Err(StoreError::UnsafeFile.into());
        }
    }
    Ok(())
}
