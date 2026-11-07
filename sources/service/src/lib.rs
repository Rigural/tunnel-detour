//! Linux service adapters. Network mutation is confined to explicitly owned kernel objects.

mod adguard;
mod config;
mod dns;
mod kernel;
mod management;
mod proxy;
mod runtime;
mod status;
mod uci;
mod upstream;

pub use config::{ConfigError, ServiceConfig};
pub use management::{cleanup_uci, rpc_call, rpc_methods, validate_patterns};
pub use runtime::{BoundService, ServiceError};
pub use status::{ConnectionStatus, ServicePhase, ServiceStatus, StatusHandle};
pub use uci::{UciError, load_uci};
