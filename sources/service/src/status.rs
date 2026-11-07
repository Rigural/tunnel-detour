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
    pub destination: std::net::SocketAddrV4,
    pub started_at: Timestamp,
}

#[derive(Clone, Serialize)]
pub struct ServiceStatus {
    pub process_id: u32,
    pub phase: ServicePhase,
    pub dns_queries: u64,
    pub failures: u64,
    pub completed_connections: u64,
    pub bytes_to_wan: u64,
    pub bytes_from_wan: u64,
    pub last_error: Option<&'static str>,
    pub connections: BTreeMap<String, ConnectionStatus>,
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
                dns_queries: 0,
                failures: 0,
                completed_connections: 0,
                bytes_to_wan: 0,
                bytes_from_wan: 0,
                last_error: None,
                connections: BTreeMap::new(),
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

    pub(crate) fn dns_query(&self) -> Result<(), ServiceError> {
        let mut status = self.inner.lock().map_err(|_| ServiceError::Poisoned)?;
        // Operational counters saturate deliberately; exhaustion cannot change traffic policy.
        status.dns_queries = status.dns_queries.saturating_add(1);
        Ok(())
    }

    pub(crate) fn failure(&self, error: &ServiceError) -> Result<(), ServiceError> {
        let mut status = self.inner.lock().map_err(|_| ServiceError::Poisoned)?;
        status.failures = status.failures.saturating_add(1);
        status.last_error = Some(error.code());
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
