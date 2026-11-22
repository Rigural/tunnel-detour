use std::{
    collections::{BTreeMap, BTreeSet},
    io,
    path::Path,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
};

use serde::Serialize;
use tunnel_detour_core::{DomainName, MappingUsage, Timestamp};

use crate::{
    ServiceError,
    observability::{AppliedConsent, Consent, ConsentToken},
};

/// The controller serializes snapshot writes and retries after an I/O failure.
#[derive(Default)]
pub(crate) struct SnapshotPublication {
    unavailable: AtomicBool,
    may_contain_diagnostics: AtomicBool,
}

impl SnapshotPublication {
    pub(crate) fn retry_pending(&self) -> bool {
        self.unavailable.load(Ordering::Relaxed)
    }

    pub(crate) fn complete(
        &self,
        path: &Path,
        observing: bool,
        written: io::Result<()>,
    ) -> io::Result<()> {
        let Err(error) = written else {
            self.may_contain_diagnostics
                .store(observing, Ordering::Relaxed);
            self.unavailable.store(false, Ordering::Relaxed);
            return Ok(());
        };
        if !self.unavailable.swap(true, Ordering::Relaxed) {
            tracing::warn!(
                target: "tunnel_detour::health",
                code = "status_publication_failed",
                kind = ?error.kind(),
                "local status snapshot could not be published"
            );
        }
        // A write can fail after replacing the snapshot. Track whether either
        // version may contain diagnostics until a write or removal succeeds.
        let previous = self
            .may_contain_diagnostics
            .fetch_or(observing, Ordering::Relaxed);
        match crate::observability::discard_snapshot(path) {
            Ok(()) => self.may_contain_diagnostics.store(false, Ordering::Relaxed),
            Err(error) if previous && !observing => return Err(error),
            Err(_) => {}
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ServicePhase {
    Starting,
    Ready,
    Stopping,
    Stopped,
    Failed,
}

#[derive(Clone, Serialize)]
pub struct ConnectionStatus {
    pub id: String,
    pub domain: DomainName,
    pub client: std::net::SocketAddr,
    pub destination: std::net::SocketAddr,
    pub started_at: Timestamp,
}

#[derive(Clone, Serialize)]
struct TrafficStatus {
    #[serde(skip)]
    epoch: Arc<()>,
    #[serde(skip)]
    next_connection_id: u64,
    mapping_usage: Option<MappingUsage>,
    dns_queries: u64,
    failures: u64,
    completed_connections: u64,
    last_request_error: Option<&'static str>,
    connections: BTreeMap<String, ConnectionStatus>,
}

#[derive(Clone)]
pub(crate) struct Observation(Option<Arc<()>>);

#[derive(Clone, Serialize)]
pub struct ServiceStatus {
    pub process_id: u32,
    pub phase: ServicePhase,
    pub observability: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) status_owner: Option<[u64; 2]>,
    #[serde(skip_serializing_if = "Option::is_none")]
    observability_epoch: Option<ConsentToken>,
    #[serde(skip_serializing_if = "Option::is_none")]
    observability_grant: Option<ConsentToken>,
    #[serde(flatten)]
    traffic: Option<TrafficStatus>,
    pub last_error: Option<&'static str>,
    pub degraded: BTreeSet<&'static str>,
    #[serde(skip)]
    health_changed: bool,
    pub applied_resolver: Option<std::net::SocketAddr>,
    pub resolver_device: Option<String>,
    pub ipv6_wan_source: Option<std::net::Ipv6Addr>,
    pub ipv6_wan_device: Option<String>,
    pub managed_upstream: bool,
    pub pending_resolver: Option<std::net::SocketAddr>,
    pub configuration_applied: bool,
    pub restart_required: bool,
    pub recovery_resolvers: Vec<std::net::SocketAddr>,
}

impl ServiceStatus {
    pub(crate) fn set_mapping_usage(&mut self, usage: MappingUsage) {
        if let Some(traffic) = &mut self.traffic {
            traffic.mapping_usage = Some(usage);
        }
    }
}

#[derive(Clone)]
pub struct StatusHandle {
    inner: Arc<Mutex<ServiceStatus>>,
}

impl StatusHandle {
    pub(crate) fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(ServiceStatus {
                process_id: std::process::id(),
                phase: ServicePhase::Starting,
                observability: false,
                status_owner: None,
                observability_epoch: None,
                observability_grant: None,
                traffic: None,
                last_error: None,
                degraded: BTreeSet::new(),
                health_changed: false,
                applied_resolver: None,
                resolver_device: None,
                ipv6_wan_source: None,
                ipv6_wan_device: None,
                managed_upstream: false,
                pending_resolver: None,
                configuration_applied: false,
                restart_required: false,
                recovery_resolvers: Vec::new(),
            })),
        }
    }

    pub fn snapshot(&self) -> Result<ServiceStatus, ServiceError> {
        Ok(self
            .inner
            .lock()
            .map_err(|_| ServiceError::Poisoned)?
            .clone())
    }

    pub(crate) fn phase(&self, phase: ServicePhase) -> Result<(), ServiceError> {
        self.inner.lock().map_err(|_| ServiceError::Poisoned)?.phase = phase;
        Ok(())
    }

    pub(crate) fn clear_connections(&self) -> Result<(), ServiceError> {
        let mut status = self.inner.lock().map_err(|_| ServiceError::Poisoned)?;
        if let Some(traffic) = &mut status.traffic {
            traffic.connections.clear();
        }
        Ok(())
    }

    pub(crate) fn set_observability(&self, control: AppliedConsent) -> Result<bool, ServiceError> {
        let mut status = self.inner.lock().map_err(|_| ServiceError::Poisoned)?;
        let enabled = control.consent.enabled();
        let epoch = control.consent.epoch();
        if status.observability == enabled
            && status.observability_epoch == epoch
            && status.observability_grant == control.grant
        {
            return Ok(false);
        }
        status.observability = enabled;
        status.observability_epoch = epoch;
        status.observability_grant = control.grant;
        status.traffic = enabled.then(|| TrafficStatus {
            epoch: Arc::new(()),
            next_connection_id: 1,
            mapping_usage: None,
            dns_queries: 0,
            failures: 0,
            completed_connections: 0,
            last_request_error: None,
            connections: BTreeMap::new(),
        });
        Ok(true)
    }

    pub(crate) fn observation(&self) -> Result<Observation, ServiceError> {
        let status = self.inner.lock().map_err(|_| ServiceError::Poisoned)?;
        Ok(Observation(
            status.traffic.as_ref().map(|traffic| traffic.epoch.clone()),
        ))
    }

    pub(crate) fn is_observing(&self) -> Result<bool, ServiceError> {
        Ok(self
            .inner
            .lock()
            .map_err(|_| ServiceError::Poisoned)?
            .observability)
    }

    pub(crate) fn applied_consent(&self) -> Result<AppliedConsent, ServiceError> {
        let status = self.inner.lock().map_err(|_| ServiceError::Poisoned)?;
        Ok(AppliedConsent {
            consent: if status.observability {
                Consent::On(status.observability_epoch)
            } else {
                Consent::Off
            },
            grant: status.observability_grant,
        })
    }

    fn update_traffic(
        &self,
        observation: &Observation,
        update: impl FnOnce(&mut TrafficStatus) -> Result<(), ServiceError>,
    ) -> Result<(), ServiceError> {
        if let Some(epoch) = &observation.0 {
            let mut status = self.inner.lock().map_err(|_| ServiceError::Poisoned)?;
            if let Some(traffic) = &mut status.traffic
                && Arc::ptr_eq(epoch, &traffic.epoch)
            {
                update(traffic)?;
            }
        }
        Ok(())
    }

    pub(crate) fn resolver_applied(
        &self,
        config: &crate::ServiceConfig,
        path: &crate::upstream_route::ResolverPath,
    ) -> Result<(), ServiceError> {
        let mut status = self.inner.lock().map_err(|_| ServiceError::Poisoned)?;
        status.applied_resolver = Some(path.endpoint);
        status.resolver_device = Some(path.device.clone());
        status.ipv6_wan_source = config.ipv6.as_ref().map(|settings| settings.wan.source);
        status.ipv6_wan_device = config
            .ipv6
            .as_ref()
            .map(|settings| settings.wan.device.clone());
        status.managed_upstream = config.manage_adguard_upstream;
        status.pending_resolver = None;
        status.configuration_applied = true;
        status.last_error = None;
        status.recovery_resolvers.clear();
        status.phase = ServicePhase::Ready;
        Ok(())
    }

    pub(crate) fn resolver_pending(
        &self,
        endpoint: Option<std::net::SocketAddr>,
    ) -> Result<(), ServiceError> {
        let mut status = self.inner.lock().map_err(|_| ServiceError::Poisoned)?;
        status.pending_resolver = endpoint;
        status.configuration_applied = false;
        Ok(())
    }

    pub(crate) fn restart_required(&self, required: bool) -> Result<(), ServiceError> {
        let mut status = self.inner.lock().map_err(|_| ServiceError::Poisoned)?;
        status.restart_required = required;
        if required {
            status.configuration_applied = false;
        }
        Ok(())
    }

    pub(crate) fn clear_frontend_degradation(&self) -> Result<(), ServiceError> {
        let mut status = self.inner.lock().map_err(|_| ServiceError::Poisoned)?;
        let previous = status.degraded.len();
        status.degraded.retain(|code| {
            matches!(
                *code,
                "mapping_pool_exhausted" | crate::transport_worker::INITIALIZATION_FAILED
            )
        });
        status.health_changed |= status.degraded.len() != previous;
        Ok(())
    }

    pub(crate) fn set_transport_degraded(&self, failed: bool) -> Result<(), ServiceError> {
        let mut status = self.inner.lock().map_err(|_| ServiceError::Poisoned)?;
        let code = crate::transport_worker::INITIALIZATION_FAILED;
        let changed = if failed {
            status.degraded.insert(code)
        } else {
            status.degraded.remove(code)
        };
        status.health_changed |= changed;
        Ok(())
    }

    pub(crate) fn take_health_change(&self) -> Result<bool, ServiceError> {
        let mut status = self.inner.lock().map_err(|_| ServiceError::Poisoned)?;
        Ok(std::mem::take(&mut status.health_changed))
    }

    pub(crate) fn dns_query(&self) -> Result<Observation, ServiceError> {
        let mut status = self.inner.lock().map_err(|_| ServiceError::Poisoned)?;
        Ok(Observation(status.traffic.as_mut().map(|traffic| {
            traffic.dns_queries = traffic.dns_queries.saturating_add(1);
            traffic.epoch.clone()
        })))
    }

    pub(crate) fn failure(&self, error: &ServiceError) -> Result<(), ServiceError> {
        self.record_failure(error, false)
    }

    /// Preserve the first critical cause when a draining task also fails.
    pub(crate) fn secondary_failure(&self, error: &ServiceError) -> Result<(), ServiceError> {
        self.record_failure(error, true)
    }

    fn record_failure(
        &self,
        error: &ServiceError,
        preserve_cause: bool,
    ) -> Result<(), ServiceError> {
        let mut status = self.inner.lock().map_err(|_| ServiceError::Poisoned)?;
        if let Some(traffic) = &mut status.traffic {
            traffic.failures = traffic.failures.saturating_add(1);
        }
        if preserve_cause && status.last_error.is_some() {
            return Ok(());
        }
        status.last_error = Some(error.code());
        if let ServiceError::ResolverRecovery { allowed } = error {
            status.recovery_resolvers.clone_from(allowed);
        }
        Ok(())
    }

    pub(crate) fn request_failure(
        &self,
        observation: &Observation,
        error: &ServiceError,
    ) -> Result<(), ServiceError> {
        if let Some(code) = error.degradation_code() {
            let mut status = self.inner.lock().map_err(|_| ServiceError::Poisoned)?;
            if status.degraded.insert(code) {
                status.health_changed = true;
            }
        }
        self.update_traffic(observation, |traffic| {
            traffic.failures = traffic.failures.saturating_add(1);
            traffic.last_request_error = Some(error.code());
            Ok(())
        })
    }

    pub(crate) fn insert(
        &self,
        observation: &Observation,
        connection: impl FnOnce(String) -> Result<ConnectionStatus, ServiceError>,
    ) -> Result<Option<String>, ServiceError> {
        let mut inserted = None;
        self.update_traffic(observation, |traffic| {
            let id = traffic.next_connection_id.to_string();
            traffic.next_connection_id = traffic
                .next_connection_id
                .checked_add(1)
                .ok_or(ServiceError::IdentifierExhausted)?;
            traffic
                .connections
                .insert(id.clone(), connection(id.clone())?);
            inserted = Some(id);
            Ok(())
        })?;
        Ok(inserted)
    }

    pub(crate) fn finish(
        &self,
        observation: &Observation,
        id: &str,
        completed: bool,
    ) -> Result<(), ServiceError> {
        self.update_traffic(observation, |traffic| {
            if traffic.connections.remove(id).is_some() && completed {
                traffic.completed_connections = traffic.completed_connections.saturating_add(1);
            }
            Ok(())
        })
    }
}
