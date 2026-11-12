use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};

use serde::Serialize;
use tunnel_detour_core::{DomainName, Timestamp};

use crate::ServiceError;

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
pub struct ServiceStatus {
    pub mapping_usage: Option<tunnel_detour_core::MappingUsage>,
    pub process_id: u32,
    pub phase: ServicePhase,
    pub dns_queries: u64,
    pub failures: u64,
    pub completed_connections: u64,
    pub bytes_to_wan: u64,
    pub bytes_from_wan: u64,
    pub last_error: Option<&'static str>,
    pub connections: BTreeMap<String, ConnectionStatus>,
    pub applied_resolver: Option<std::net::SocketAddr>,
    pub resolver_device: Option<String>,
    pub ipv6_wan_source: Option<std::net::Ipv6Addr>,
    pub ipv6_wan_device: Option<String>,
    pub managed_upstream: bool,
    pub pending_resolver: Option<std::net::SocketAddr>,
    pub configuration_applied: bool,
    pub recovery_resolvers: Vec<std::net::SocketAddr>,
}

#[derive(Clone)]
pub struct StatusHandle {
    inner: Arc<Mutex<ServiceStatus>>,
}

impl StatusHandle {
    pub(crate) fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(ServiceStatus {
                mapping_usage: None,
                process_id: std::process::id(),
                phase: ServicePhase::Starting,
                dns_queries: 0,
                failures: 0,
                completed_connections: 0,
                bytes_to_wan: 0,
                bytes_from_wan: 0,
                last_error: None,
                connections: BTreeMap::new(),
                applied_resolver: None,
                resolver_device: None,
                ipv6_wan_source: None,
                ipv6_wan_device: None,
                managed_upstream: false,
                pending_resolver: None,
                configuration_applied: false,
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

    pub(crate) fn dns_query(&self) -> Result<(), ServiceError> {
        let mut status = self.inner.lock().map_err(|_| ServiceError::Poisoned)?;
        // Operational counters saturate deliberately; exhaustion cannot change traffic policy.
        status.dns_queries = status.dns_queries.saturating_add(1);
        Ok(())
    }

    pub(crate) fn failure(&self, error: &ServiceError) -> Result<(), ServiceError> {
        self.record_failure(error, false)
    }

    /// Count a drained request failure without concealing the service's stop cause.
    pub(crate) fn secondary_failure(&self, error: &ServiceError) -> Result<(), ServiceError> {
        self.record_failure(error, true)
    }

    fn record_failure(
        &self,
        error: &ServiceError,
        preserve_cause: bool,
    ) -> Result<(), ServiceError> {
        let mut status = self.inner.lock().map_err(|_| ServiceError::Poisoned)?;
        status.failures = status.failures.saturating_add(1);
        if preserve_cause && status.last_error.is_some() {
            return Ok(());
        }
        status.last_error = Some(error.code());
        if let ServiceError::ResolverRecovery { allowed } = error {
            status.recovery_resolvers.clone_from(allowed);
        }
        Ok(())
    }

    pub(crate) fn insert(&self, connection: ConnectionStatus) -> Result<(), ServiceError> {
        self.inner
            .lock()
            .map_err(|_| ServiceError::Poisoned)?
            .connections
            .insert(connection.id.clone(), connection);
        Ok(())
    }

    pub(crate) fn finish(&self, id: &str, bytes: Option<(u64, u64)>) -> Result<(), ServiceError> {
        let mut status = self.inner.lock().map_err(|_| ServiceError::Poisoned)?;
        status.connections.remove(id);
        if let Some((sent, received)) = bytes {
            status.completed_connections = status.completed_connections.saturating_add(1);
            status.bytes_to_wan = status.bytes_to_wan.saturating_add(sent);
            status.bytes_from_wan = status.bytes_from_wan.saturating_add(received);
        }
        Ok(())
    }
}
