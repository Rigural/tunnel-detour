use std::{
    fs,
    io::{self, Write},
    net::SocketAddr,
    num::NonZeroUsize,
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
    ConfigError, ServiceConfig, ServicePhase, StatusHandle, dns::DnsHandler, kernel::Kernel,
    proxy::ProxyHandler, upstream::RealResolver,
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
            Self::KernelConflict => "kernel_conflict",
            Self::Ipv6Path => "ipv6_path_unavailable",
            Self::Ipv6State(_) => "ipv6_routing_state_invalid",
            Self::KernelCommand { .. } => "kernel_command_failed",
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
            | Self::Ipv6Path
            | Self::Ipv6State(_)
            | Self::KernelCommand { .. } => true,
            _ => false,
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
}

impl BoundService {
    pub async fn bind(config: ServiceConfig) -> Result<Self, ServiceError> {
        if let Some(ipv6) = &config.ipv6 {
            ipv6.inspect(&config.lan_device).await?;
        }
        let config = Arc::new(config);
        let state_config = config.clone();
        let policy = tokio::task::spawn_blocking(move || {
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
                    name == status_name
                })
            {
                return Err(ServiceError::Config(ConfigError::Paths));
            }
            let capacity =
                NonZeroUsize::new(state_config.limits.max_mappings).ok_or(ConfigError::Limits)?;
            let store =
                LeaseStore::open(&state_config.state_file, state_config.fake_range, capacity)?;
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
            Ok::<_, ServiceError>(policy)
        })
        .await??;
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
        Ok(Self {
            transport,
            config,
            dns_tcp,
            dns_udp,
            proxy,
            proxy_ipv6,
            ipv6_routing,
            policy: Arc::new(Mutex::new(policy)),
            status: StatusHandle::new(),
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
                    signal = reload.recv(), if self.config.from_uci => {
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
                                code = error.code(),
                                "managed DNS audit failed; new exception work is fenced"
                            );
                        }
                        audit_healthy = false;
                        self.write_status()?;
                    }
                    continue;
                }
                let candidate = match crate::uci::load_uci(false).await {
                    Ok(Some(candidate)) => Arc::new(candidate),
                    Ok(None) => return Ok(()),
                    Err(error) => {
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
                    if pending_path.is_some()
                        || matches!(&error, ServiceError::Adguard(_) | ServiceError::Dnsmasq(_))
                    {
                        resolver.pause()?;
                        self.status.phase(ServicePhase::Failed)?;
                    }
                    self.status.failure(&error)?;
                    tracing::warn!(
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
                    if let Err(stop_error) = serving.await { tracing::error!(code = stop_error.code(), "service stopped after setup failure"); }
                    self.status.failure(&error)?; Err(error)
                },
            },
        };
        cancel.cancel();
        let cleanup = kernel.stop_routes().await;
        if let Err(error) = &cleanup {
            if result.is_err() {
                tracing::error!(
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
        self.write_status()?;
        result.and(cleanup).and(disable)
    }

    fn write_status(&self) -> Result<(), ServiceError> {
        let mut status = self.status.snapshot()?;
        status.mapping_usage = Some(
            self.policy
                .lock()
                .map_err(|_| ServiceError::Poisoned)?
                .mapping_usage()?,
        );
        let path = self.config.status_file.clone();
        tokio::task::block_in_place(move || {
            let mut temporary = NamedTempFile::new_in(path.parent().ok_or(ConfigError::Paths)?)?;
            temporary.write_all(&serde_json::to_vec(&status)?)?;
            temporary.persist(path).map_err(|error| error.error)?;
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
        let mut next_id = 0_u64;
        let mut ticker = interval(Duration::from_secs(1));
        ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
        let mut outcome = async { loop {
            tokio::select! {
                () = cancel.cancelled() => break Ok(()),
                result = self.dns_udp.recv_from(&mut packet), if jobs.len() < job_limit => {
                    let (length, peer) = match result { Ok(result) => result, Err(error) => break Err(error.into()) };
                    if !peer.ip().is_loopback() { self.status.failure(&ServiceError::Unauthorized)?; continue; }
                    match dns_slots.clone().try_acquire_owned() {
                        Ok(permit) => {
                            let handler = dns.clone(); let socket = self.dns_udp.clone(); let packet = packet[..length].to_vec();
                            jobs.spawn(async move { let _permit = permit; handler.udp(socket, peer, packet).await });
                        },
                        Err(_) => self.status.failure(&ServiceError::Busy)?,
                    }
                },
                result = self.dns_tcp.accept(), if jobs.len() < job_limit => {
                    let (stream, peer) = match result { Ok(result) => result, Err(error) => break Err(error.into()) };
                    if !peer.ip().is_loopback() { self.status.failure(&ServiceError::Unauthorized)?; continue; }
                    match dns_slots.clone().try_acquire_owned() {
                        Ok(permit) => {
                            let handler = dns.clone(); let token = cancel.clone();
                            jobs.spawn(async move { let _permit = permit; handler.tcp(stream, token).await });
                        },
                        Err(_) => self.status.failure(&ServiceError::Busy)?,
                    }
                },
                result = self.accept_proxy(), if jobs.len() < job_limit => {
                    let (stream, peer) = match result { Ok(result) => result, Err(error) => break Err(error.into()) };
                    match proxy_slots.clone().try_acquire_owned() {
                        Ok(permit) => {
                            next_id = next_id.checked_add(1).ok_or(ServiceError::IdentifierExhausted)?;
                            let id = next_id.to_string(); let handler = proxy.clone(); let token = cancel.clone();
                            jobs.spawn(async move { let _permit = permit; handler.serve(id, stream, peer, token).await });
                        },
                        Err(_) => self.status.failure(&ServiceError::Busy)?,
                    }
                },
                result = jobs.join_next(), if !jobs.is_empty() => {
                    match result {
                        Some(Ok(Ok(()))) => {},
                        Some(Ok(Err(error))) => {
                            if error.is_critical() { break Err(error); }
                            self.status.failure(&error)?;
                            if let ServiceError::Io(cause) = &error {
                                tracing::warn!(code = error.code(), kind = ?cause.kind(), errno = cause.raw_os_error(), "request failed");
                            } else {
                                tracing::warn!(code = error.code(), "request failed");
                            }
                        },
                        Some(Err(error)) => break Err(ServiceError::Task(error)),
                        None => {},
                    }
                },
                _ = ticker.tick() => {
                    if let Some(ipv6) = &self.config.ipv6
                        && let Err(error) = ipv6.inspect(&self.config.lan_device).await
                    { break Err(error); }
                    if let Err(error) = self.write_status() { break Err(error); }
                },
            }
        }}.await;
        cancel.cancel();
        if let Err(error) = &outcome
            && let Err(report) = self.status.failure(error)
        {
            // Even a broken status collector must not detach admitted jobs.
            tracing::error!(
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
                Ok(Ok(())) => {}
                Ok(Err(error)) => {
                    let report = if outcome.is_err() {
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
