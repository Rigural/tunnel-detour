use std::{net::Ipv4Addr, time::Duration};

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
}

impl ExceptionPolicy {
    pub fn new(rules: RuleSet, store: LeaseStore, ttl: Duration) -> Result<Self, FakeIpError> {
        if ttl.is_zero() || ttl.subsec_nanos() != 0 || ttl.as_secs() > u64::from(u32::MAX) {
            return Err(FakeIpError::InvalidTtl);
        }
        Ok(Self { rules, store, ttl })
    }

    pub fn replace_rules(&mut self, rules: RuleSet) {
        self.rules = rules;
    }
    pub fn rules(&self) -> &RuleSet {
        &self.rules
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
        match kind {
            DnsQuestionType::A => {
                // Reuse the already durable deadline while at least half its configured TTL
                // remains. The wire answer uses the remaining TTL, avoiding flash writes for
                // repeated queries without publishing an unpersisted extension.
                let minimum = Duration::from_secs((self.ttl.as_secs() / 2).max(1));
                if let Some(lease) = self.store.table()?.reusable(name, now, minimum)? {
                    Ok(DnsDecision::Synthetic(lease.clone()))
                } else {
                    Ok(DnsDecision::Synthetic(
                        self.store.issue(name, now, self.ttl)?,
                    ))
                }
            }
            DnsQuestionType::Aaaa
            | DnsQuestionType::Https
            | DnsQuestionType::Svcb
            | DnsQuestionType::Other => Ok(DnsDecision::Empty),
        }
    }

    /// Authorize new connections against the current rules and a still-valid mapping. The
    /// caller must separately validate the source LAN and explicitly open the WAN connection.
    pub fn authorize_tcp(
        &self,
        address: Ipv4Addr,
        port: u16,
        now: Timestamp,
    ) -> Result<&DomainName, ConnectionError> {
        if !matches!(port, 80 | 443) {
            return Err(ConnectionError::UnsupportedPort);
        }
        let lease = self.store.table()?.lookup(address, now)?;
        if !self.rules.selects(lease.domain()) {
            return Err(ConnectionError::NotExcepted);
        }
        Ok(lease.domain())
    }
}
