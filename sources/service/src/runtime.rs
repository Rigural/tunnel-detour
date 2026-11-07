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
    net::{TcpListener, UdpSocket},
    sync::Semaphore,
    task::JoinSet,
    time::{MissedTickBehavior, interval},
};
use tokio_util::sync::CancellationToken;
use tunnel_detour_core::{
    ConnectionError, DnsWireError, ExceptionPolicy, LeaseStore, StoreError, Timestamp,
};

use crate::{
    ConfigError, ServiceConfig, ServicePhase, StatusHandle, dns::DnsHandler, kernel::Kernel,
    proxy::ProxyHandler, upstream::RealResolver,
};

#[derive(Debug, Error)]
pub enum ServiceError {
    #[error(transparent)]
    Uci(#[from] crate::uci::UciError),
    #[error(transparent)]
    Adguard(#[from] crate::adguard::AdguardError),
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
    #[error("DNS upstream did not supply an IPv4 destination")]
    NoAddress,
    #[error("DNS alias chain is cyclic or too long")]
    AliasLoop,
    #[error("DNS destination is a private, local, or synthetic address")]
    ForbiddenTarget,
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
    #[error("kernel configuration command failed: {detail}")]
    KernelCommand { detail: String },
}

impl ServiceError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Uci(_) => "uci_configuration_failed",
            Self::Adguard(_) => "adguard_integration_failed",
            Self::Io(_) => "io_error",
            Self::Json(_) => "json_error",
            Self::Config(_) => "invalid_configuration",
            Self::Store(_) => "lease_storage_error",
            Self::Dns(_) => "dns_error",
            Self::Connection(_) => "connection_rejected",
            Self::Protocol => "invalid_dns_response",
            Self::NoAddress => "no_ipv4_address",
            Self::AliasLoop => "dns_alias_loop",
            Self::ForbiddenTarget => "forbidden_destination",
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
    config: Arc<ServiceConfig>,
    dns_udp: Arc<UdpSocket>,
    dns_tcp: TcpListener,
    proxy: TcpListener,
    policy: Arc<Mutex<ExceptionPolicy>>,
    status: StatusHandle,
}

impl BoundService {
    pub async fn bind(config: ServiceConfig) -> Result<Self, ServiceError> {
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
                && ["", ".lock", ".adguard.json", ".adguard.json.lock"]
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
            ExceptionPolicy::new(
                state_config.rules.clone(),
                store,
                Duration::from_secs(state_config.limits.ttl_seconds),
            )
            .map_err(|error| ServiceError::Config(ConfigError::Range(error)))
        })
        .await??;
        let dns_tcp = TcpListener::bind(config.dns_listen).await?;
        let dns_udp = Arc::new(UdpSocket::bind(dns_tcp.local_addr()?).await?);
        if dns_tcp.local_addr()? == SocketAddr::V4(config.real_upstream) {
            return Err(ConfigError::DnsListener.into());
        }
        let proxy = TcpListener::bind(config.proxy_listen).await?;
        Ok(Self {
            config,
            dns_tcp,
            dns_udp,
            proxy,
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

    /// Install only owned kernel objects, then serve until cancellation or a critical failure.
    /// DNS and copy tasks are supervised and drained before removing the WAN routing rule.
    pub async fn run(self, cancel: CancellationToken) -> Result<(), ServiceError> {
        self.write_status()?;
        let kernel = Kernel::new(self.config.clone());
        if let Err(error) = kernel.install(self.proxy.local_addr()?.port()).await {
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
        let manager = tokio::task::block_in_place(|| {
            crate::adguard::AdguardManager::new(self.config.clone())
        });
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
        let serving = self.serve(cancel.clone());
        tokio::pin!(serving);
        let setup = async {
            if let Some(manager) = &mut manager {
                let SocketAddr::V4(dns) = self.dns_address()? else {
                    return Err(ServiceError::Protocol);
                };
                manager.reconcile(Some((dns, &self.config.rules))).await?;
            }
            self.status.phase(ServicePhase::Ready)?;
            self.write_status()?;
            Ok::<_, ServiceError>(())
        };
        let result = tokio::select! {
            result = &mut serving => result,
            result = setup => match result {
                Ok(()) => serving.await,
                Err(error) => {
                    cancel.cancel();
                    if let Err(stop_error) = serving.await { tracing::error!(code = stop_error.code(), "service stopped after setup failure"); }
                    self.status.failure(&error)?; Err(error)
                },
            },
        };
        cancel.cancel();
        let cleanup = kernel.stop_routes().await;
        let disable = async {
            if self.config.from_uci
                && !crate::uci::is_enabled().await?
                && let Some(manager) = &mut manager
            {
                manager.reconcile(None).await?;
            }
            Ok::<_, ServiceError>(())
        }
        .await;
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
        let status = self.status.snapshot()?;
        let path = self.config.status_file.clone();
        tokio::task::block_in_place(move || {
            let mut temporary = NamedTempFile::new_in(path.parent().ok_or(ConfigError::Paths)?)?;
            temporary.write_all(&serde_json::to_vec(&status)?)?;
            temporary.persist(path).map_err(|error| error.error)?;
            Ok(())
        })
    }

    async fn serve(&self, cancel: CancellationToken) -> Result<(), ServiceError> {
        let resolver = RealResolver::new(self.config.clone())?;
        let dns = DnsHandler {
            config: self.config.clone(),
            policy: self.policy.clone(),
            resolver: resolver.clone(),
            status: self.status.clone(),
        };
        let proxy = Arc::new(ProxyHandler {
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
                result = self.proxy.accept(), if jobs.len() < job_limit => {
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
                            self.status.failure(&error)?;
                            tracing::warn!(code = error.code(), "request failed");
                            if error.is_critical() { break Err(error); }
                        },
                        Some(Err(error)) => break Err(ServiceError::Task(error)),
                        None => {},
                    }
                },
                _ = ticker.tick() => { if let Err(error) = self.write_status() { break Err(error); } },
            }
        }}.await;
        cancel.cancel();
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
                    if let Err(status_error) = self.status.failure(&error)
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

fn prepare_parent(path: &std::path::Path) -> Result<(), ServiceError> {
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
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(StoreError::UnsafeFile.into());
        }
    }
    Ok(())
}
