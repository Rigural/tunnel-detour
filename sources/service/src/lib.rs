//! Linux service adapters. Network mutation is confined to explicitly owned kernel objects.

mod adguard;
mod cache_guard;
mod config;
mod credentials;
mod dns;
mod dnsmasq;
mod frontend;
mod inbound;
mod inbound_config;
mod inbound_firewall;
mod inbound_kernel;
mod inbound_uci;
mod integration_state;
mod ipv6;
mod ipv6_routing;
mod kernel;
mod kernel_netlink;
mod management;
mod port_guard;
mod proxy;
mod relay;
mod relay_ingress;
mod runtime;
mod status;
mod tcp_close;
mod transfer;
mod transport_worker;
mod uci;
mod upstream;
mod upstream_route;

pub use adguard::preview_adguard_upstream;
pub use config::{ConfigError, DnsIntegration, ServiceConfig};
pub use credentials::migrate_adguard_credentials;
pub use inbound::{BoundInbound, InboundRuntimeError, check_inbound_config, cleanup_inbound_uci};
pub use inbound_config::{InboundConfig, InboundConfigError};
pub use inbound_uci::load_inbound_uci;
pub use management::{cleanup_uci, rpc_call, rpc_methods, validate_patterns};
pub use port_guard::{PortGuardError, PortUse};
pub use relay::{
    RELAY_ADMISSION_WAIT, RELAY_LISTEN_BACKLOG, RELAY_PENDING_LIMIT, RelayAdmission, RelayCapture,
    RelayCompletion, RelayConnection, RelayError, RelayLimits, RelayOutcome, RelaySessions,
};
pub use relay_ingress::{RelayIngress, RelayIngressError, inspect_relay_ingress};
pub use runtime::{BoundService, ServiceError};
pub use status::{ConnectionStatus, ServicePhase, ServiceStatus, StatusHandle};
pub use transfer::{TCP_TRANSFER_BUFFER_BYTES, transfer_tcp};
pub use transport_worker::{
    PreparedTransportWorker, prepare_transport_worker, run_transport_worker,
    transport_worker_entrypoint,
};
pub use uci::{UciError, dns_revision, load_uci};

/// Exercise private journal and API response validators without reading files,
/// changing state or contacting a frontend. Disabled in production builds.
///
/// # Errors
/// Reports valid-input serialization/validation regressions. Invalid candidate
/// data is expected and rejected by the owning parser without invoking recovery.
#[cfg(feature = "fuzzing")]
pub fn fuzz_private_state_parsers(bytes: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    if bytes.len() > 65_536 {
        return Ok(());
    }
    credentials::fuzz_parser(bytes)?;
    adguard::fuzz_parser(bytes)?;
    dnsmasq::fuzz_parser(bytes)
}

/// Exercise AdGuard response parsing up to the actual HTTP body's size limit.
/// This development-only path performs no file, recovery, OS or network operations.
///
/// # Errors
/// Reports valid-document round-trip/validation regressions. Invalid or oversized
/// input is rejected by its owning parser without applying configuration.
#[cfg(feature = "fuzzing")]
pub fn fuzz_adguard_api_response(bytes: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    adguard::fuzz_parser(bytes)
}
