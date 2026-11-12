use serde::Serialize;
use std::{net::IpAddr, num::NonZeroUsize, time::Duration};

use thiserror::Error;

use crate::{DomainName, FakeIpError, Lease, LeaseStore, RuleSet, StoreError, Timestamp};

/// DNS record classes are validated by the transport adapter before policy dispatch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DnsQuestionType {
    A,
    Aaaa,
    Https,
    Svcb,
    Other,
}

/// Families whose Fake-IP data paths the caller has prepared. This does not
/// configure listeners, routes or firewall rules; callers must prepare those
/// before serving DNS and retain closed guards for previously cached answers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DnsAddressFamilies {
    /// Compatibility mode: synthesize A and suppress AAAA.
    Ipv4Only,
    /// A and AAAA share one durable hostname lease and expiry.
    DualStack,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DnsDecision {
    /// Use the dedicated real upstream; never forward back to this service through AdGuard.
    Forward,
    /// Successful empty response. Suppress alternate-address and service-binding bypasses.
    Empty,
    /// Return the synthetic address only after its association has been durably saved.
    Synthetic(Lease),
}

#[derive(Debug, Error)]
pub enum ConnectionError {
    #[error("IPv6 exceptions are not enabled")]
    UnsupportedFamily,
    #[error("only TCP ports 80 and 443 are eligible for exception connections")]
    UnsupportedPort,
    #[error("the mapped hostname is no longer selected by the exception rules")]
    NotExcepted,
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error(transparent)]
    Lease(#[from] FakeIpError),
}

pub struct ExceptionPolicy {
    rules: RuleSet,
    store: LeaseStore,
    ttl: Duration,
    families: DnsAddressFamilies,
    mapping_limit_per_rule: Option<NonZeroUsize>,
}

#[derive(Clone, Serialize)]
pub struct MappingUsage {
    pub allocated: usize,
    pub capacity: usize,
    pub per_rule_limit: Option<usize>,
}

impl ExceptionPolicy {
    pub fn new(rules: RuleSet, store: LeaseStore, ttl: Duration) -> Result<Self, FakeIpError> {
        Self::with_families(rules, store, ttl, DnsAddressFamilies::Ipv4Only)
    }

    /// Select the prepared data paths explicitly. Reopening the same store in
    /// IPv4-only mode refuses cached IPv6 identities without reassigning them.
    pub fn with_families(
        rules: RuleSet,
        store: LeaseStore,
        ttl: Duration,
        families: DnsAddressFamilies,
    ) -> Result<Self, FakeIpError> {
        if ttl.is_zero() || ttl.subsec_nanos() != 0 || ttl.as_secs() > u64::from(u32::MAX) {
            return Err(FakeIpError::InvalidTtl);
        }
        Ok(Self {
            rules,
            store,
            ttl,
            families,
            mapping_limit_per_rule: None,
        })
    }

    pub fn replace_rules(&mut self, rules: RuleSet) {
        self.rules = rules;
    }
    pub fn rules(&self) -> &RuleSet {
        &self.rules
    }

    /// Limit new names while retaining every previously issued identity and renewal.
    pub fn set_mapping_limit_per_rule(&mut self, limit: NonZeroUsize) {
        self.mapping_limit_per_rule = Some(limit);
    }

    pub fn mapping_usage(&self) -> Result<MappingUsage, StoreError> {
        let table = self.store.table()?;
        Ok(MappingUsage {
            allocated: table.len(),
            capacity: table.capacity(),
            per_rule_limit: self.mapping_limit_per_rule.map(NonZeroUsize::get),
        })
    }

    pub(crate) fn synthetic_range(&self) -> Result<crate::FakeIpRange, StoreError> {
        Ok(self.store.table()?.range())
    }

    pub(crate) fn address_families(&self) -> DnsAddressFamilies {
        self.families
    }

    /// Selection occurs by hostname before real DNS resolution. Real CDN IPs and TLS SNI are
    /// deliberately not inputs, so shared upstream addresses cannot widen an exception.
    pub fn decide_dns(
        &mut self,
        name: &DomainName,
        kind: DnsQuestionType,
        now: Timestamp,
    ) -> Result<DnsDecision, StoreError> {
        if !self.rules.selects(name) {
            return Ok(DnsDecision::Forward);
        }
        self.store.table()?;
        if kind == DnsQuestionType::A
            || (kind == DnsQuestionType::Aaaa && self.families == DnsAddressFamilies::DualStack)
        {
            // Known reusable identities require no admission scan or persistence.
            // Perform the indexed lookup before per-rule accounting, which applies
            // only to new names, rather than walking every mapping on every query.
            // Reuse at least half a TTL; the wire answer publishes the remaining
            // durable lifetime, never an unpersisted extension.
            let minimum = Duration::from_secs((self.ttl.as_secs() / 2).max(1));
            if let Some(lease) = self.store.table()?.reusable(name, now, minimum)? {
                return Ok(DnsDecision::Synthetic(lease.clone()));
            }
            if let Some(limit) = self.mapping_limit_per_rule {
                let table = self.store.table()?;
                let existing = table.contains_domain(name);
                let pattern = self
                    .rules
                    .selecting_pattern(name)
                    .ok_or(FakeIpError::UnknownAddress)?;
                if !existing
                    && table
                        .leases()
                        .filter(|lease| pattern.matches(lease.domain()))
                        .count()
                        >= limit.get()
                {
                    return Err(FakeIpError::RuleCapacity.into());
                }
            }
            // Publish a new deadline only after its complete durable update.
            Ok(DnsDecision::Synthetic(
                self.store.issue(name, now, self.ttl)?,
            ))
        } else {
            Ok(DnsDecision::Empty)
        }
    }

    /// Authorize either family's identity against the current rules and a still-valid
    /// shared lease. The caller must separately validate the source LAN, ensure that
    /// family's data path is ready, and explicitly open the WAN connection.
    pub fn authorize_tcp(
        &self,
        address: impl Into<IpAddr>,
        port: u16,
        now: Timestamp,
    ) -> Result<&DomainName, ConnectionError> {
        if !matches!(port, 80 | 443) {
            return Err(ConnectionError::UnsupportedPort);
        }
        let table = self.store.table()?;
        let lease = match address.into() {
            IpAddr::V4(address) => table.lookup(address, now)?,
            IpAddr::V6(address) if self.families == DnsAddressFamilies::DualStack => {
                table.lookup_ipv6(address, now)?
            }
            IpAddr::V6(_) => return Err(ConnectionError::UnsupportedFamily),
        };
        if !self.rules.selects(lease.domain()) {
            return Err(ConnectionError::NotExcepted);
        }
        Ok(lease.domain())
    }
}
