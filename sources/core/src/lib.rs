//! Router-independent policy for domain exceptions and durable Fake-IP leases.
//!
//! This crate makes policy decisions. It does not change system DNS, routes, or firewall rules.

mod dns;
mod domain;
mod lease;
mod policy;
mod store;

pub use dns::{DnsWireDecision, DnsWireError, answer_dns, validate_upstream_reply};
pub use domain::{DomainError, DomainName, DomainPattern, MatchScope, Rule, RuleSet, RuleSetError};
pub use lease::{FakeIpError, FakeIpRange, Lease, LeaseTable, Timestamp};
pub use policy::{ConnectionError, DnsDecision, DnsQuestionType, ExceptionPolicy};
pub use store::{LeaseStore, StoreError};
