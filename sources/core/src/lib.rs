//! Router-independent policy for domain exceptions and durable Fake-IP leases.
//!
//! This crate makes policy decisions. It does not change system DNS, routes, or firewall rules.

mod dns;
mod domain;
mod inbound;
mod lease;
mod policy;
mod service_binding;
mod store;

pub use dns::{DnsWireDecision, DnsWireError, answer_dns, validate_upstream_reply};
pub use domain::{DomainError, DomainName, DomainPattern, MatchScope, Rule, RuleSet, RuleSetError};
pub use inbound::{
    INBOUND_INTERNET_V6, InboundAccess, InboundError, InboundId, InboundProtocol, InboundRule,
    InboundRuleSpec, InboundRules, InboundTarget, InboundTransport,
};
pub use lease::{FakeIpError, FakeIpRange, Lease, LeaseTable, Timestamp};
pub use policy::{
    ConnectionError, DnsAddressFamilies, DnsDecision, DnsQuestionType, ExceptionPolicy,
    MappingUsage,
};
pub use service_binding::HttpsBindingQuery;
pub use store::{LeaseStore, StoreError};
