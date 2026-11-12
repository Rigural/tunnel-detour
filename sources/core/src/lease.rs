use std::{
    collections::BTreeMap,
    fmt,
    net::{Ipv4Addr, Ipv6Addr},
    num::NonZeroUsize,
    str::FromStr,
    time::Duration,
};

use ipnet::{Ipv4Net, Ipv6Net};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::DomainName;

/// UTC seconds since the Unix epoch. Callers obtain the reference time once per decision.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Timestamp(u64);

impl Timestamp {
    pub const fn from_unix_seconds(seconds: u64) -> Self {
        Self(seconds)
    }

    pub const fn unix_seconds(self) -> u64 {
        self.0
    }

    fn checked_add(self, duration: Duration) -> Result<Self, FakeIpError> {
        if duration.is_zero()
            || duration.subsec_nanos() != 0
            || duration.as_secs() > u64::from(u32::MAX)
        {
            return Err(FakeIpError::InvalidTtl);
        }
        self.0
            .checked_add(duration.as_secs())
            .map(Self)
            .ok_or(FakeIpError::TimeOverflow)
    }
}

/// An aligned IPv4 benchmark subnet, with network and broadcast addresses excluded.
///
/// Each usable address also identifies exactly one IPv6 address: its four octets
/// occupy the low 32 bits of 2001:2::/96, inside IANA's IPv6 benchmarking allocation
/// (RFC 5180, corrected by erratum 1752). Both families share one permanent lease;
/// deriving IPv6 identities requires no second allocator or persistence migration.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct FakeIpRange {
    ipv4: Ipv4Net,
    ipv6: Ipv6Net,
}

fn paired_ipv6(address: Ipv4Addr) -> Ipv6Addr {
    let [a, b, c, d] = address.octets();
    Ipv6Addr::new(
        0x2001,
        2,
        0,
        0,
        0,
        0,
        u16::from_be_bytes([a, b]),
        u16::from_be_bytes([c, d]),
    )
}

impl FakeIpRange {
    pub fn network(self) -> Ipv4Addr {
        self.ipv4.network()
    }

    pub fn contains(self, address: Ipv4Addr) -> bool {
        self.ipv4.contains(&address)
    }

    /// The deterministic IPv6 subnet paired with this IPv4 range. Its first and
    /// last addresses remain unused, matching IPv4 lease allocation exactly.
    /// This describes identity space; it does not enable DNS answers or routing.
    pub fn ipv6_range(self) -> Ipv6Net {
        self.ipv6
    }

    /// Recover an allocatable IPv4 identity only within this exact paired subnet.
    /// The result is not authorization: a current lease and rule are still required.
    pub fn ipv4_identity(self, address: Ipv6Addr) -> Option<Ipv4Addr> {
        if !self.ipv6.contains(&address) {
            return None;
        }
        let octets = address.octets();
        let ipv4 = Ipv4Addr::new(octets[12], octets[13], octets[14], octets[15]);
        (ipv4 != self.ipv4.network() && ipv4 != self.ipv4.broadcast()).then_some(ipv4)
    }

    pub fn capacity(self) -> u32 {
        u32::from(self.ipv4.broadcast()) - u32::from(self.ipv4.network()) - 1
    }

    fn address_at(self, offset: usize) -> Result<Ipv4Addr, FakeIpError> {
        let offset = u32::try_from(offset).map_err(|_| FakeIpError::Exhausted)?;
        if offset >= self.capacity() {
            return Err(FakeIpError::Exhausted);
        }
        let address = u32::from(self.ipv4.network())
            .checked_add(offset)
            .and_then(|value| value.checked_add(1))
            .ok_or(FakeIpError::Exhausted)?;
        Ok(Ipv4Addr::from(address))
    }
}

impl FromStr for FakeIpRange {
    type Err = FakeIpError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let network: Ipv4Net = value.parse().map_err(|_| FakeIpError::InvalidRange)?;
        let root = Ipv4Net::new(Ipv4Addr::new(198, 18, 0, 0), 15)
            .map_err(|_| FakeIpError::InvalidRange)?;
        if network.addr() != network.network()
            || !(15..=30).contains(&network.prefix_len())
            || !root.contains(&network.network())
            || !root.contains(&network.broadcast())
        {
            return Err(FakeIpError::InvalidRange);
        }
        let ipv6 = Ipv6Net::new(paired_ipv6(network.network()), 96 + network.prefix_len())
            .map_err(|_| FakeIpError::InvalidRange)?;
        Ok(Self {
            ipv4: network,
            ipv6,
        })
    }
}

impl TryFrom<String> for FakeIpRange {
    type Error = FakeIpError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.parse()
    }
}

impl From<FakeIpRange> for String {
    fn from(value: FakeIpRange) -> Self {
        value.to_string()
    }
}

impl fmt::Display for FakeIpRange {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.ipv4.fmt(formatter)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Lease {
    domain: DomainName,
    address: Ipv4Addr,
    issued_at: Timestamp,
    expires_at: Timestamp,
}

impl Lease {
    pub fn domain(&self) -> &DomainName {
        &self.domain
    }
    pub fn address(&self) -> Ipv4Addr {
        self.address
    }
    /// Permanent IPv6 identity paired with the existing IPv4 lease. Both share
    /// the same hostname, validity and renewal; this never allocates another lease.
    pub fn ipv6_address(&self) -> Ipv6Addr {
        paired_ipv6(self.address)
    }
    pub fn issued_at(&self) -> Timestamp {
        self.issued_at
    }
    pub fn expires_at(&self) -> Timestamp {
        self.expires_at
    }
    pub fn is_valid_at(&self, now: Timestamp) -> bool {
        self.issued_at <= now && now < self.expires_at
    }
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum FakeIpError {
    #[error("the synthetic range must be an aligned /15 through /30 within 198.18.0.0/15")]
    InvalidRange,
    #[error("the synthetic address space or configured mapping capacity is exhausted")]
    Exhausted,
    #[error("the selected rule has reached its permanent hostname budget")]
    RuleCapacity,
    #[error("the lease TTL must be a positive whole number of seconds")]
    InvalidTtl,
    #[error("the lease deadline overflows the supported timestamp")]
    TimeOverflow,
    #[error("the system clock moved backwards relative to the last issued lease")]
    ClockReversed,
    #[error("the synthetic address has no known association")]
    UnknownAddress,
    #[error("the synthetic address association is expired or not yet valid")]
    Expired,
    #[error("the saved lease state is invalid or belongs to a different range")]
    InvalidSnapshot,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Snapshot {
    version: u32,
    range: FakeIpRange,
    last_issued_at: Option<Timestamp>,
    entries: Vec<Lease>,
}

/// Address identities are never recycled. Expiry controls admission, not identity ownership.
///
/// Exhaustion deliberately fails closed. Removing an exception does not free its addresses,
/// because clients can retain them beyond DNS TTLs. Persist this table before publishing leases.
#[derive(Clone, Debug)]
pub struct LeaseTable {
    range: FakeIpRange,
    capacity: NonZeroUsize,
    by_domain: BTreeMap<DomainName, Lease>,
    by_address: BTreeMap<Ipv4Addr, DomainName>,
    last_issued_at: Option<Timestamp>,
}

impl LeaseTable {
    pub fn new(range: FakeIpRange, capacity: NonZeroUsize) -> Result<Self, FakeIpError> {
        if capacity.get() > usize::try_from(range.capacity()).map_err(|_| FakeIpError::Exhausted)? {
            return Err(FakeIpError::Exhausted);
        }
        Ok(Self {
            range,
            capacity,
            by_domain: BTreeMap::new(),
            by_address: BTreeMap::new(),
            last_issued_at: None,
        })
    }

    pub fn range(&self) -> FakeIpRange {
        self.range
    }
    pub fn len(&self) -> usize {
        self.by_domain.len()
    }
    pub fn is_empty(&self) -> bool {
        self.by_domain.is_empty()
    }

    pub fn capacity(&self) -> usize {
        self.capacity.get()
    }

    /// Include expired identities because their addresses remain permanently reserved.
    pub fn leases(&self) -> impl Iterator<Item = &Lease> {
        self.by_domain.values()
    }

    /// Expired entries still own their identities and may renew above a quota.
    pub(crate) fn contains_domain(&self, domain: &DomainName) -> bool {
        self.by_domain.contains_key(domain)
    }

    /// Allocate or renew a hostname's permanent address identity.
    /// Returns errors before modifying state for overflow, exhaustion, or a backwards clock.
    pub fn issue(
        &mut self,
        domain: &DomainName,
        now: Timestamp,
        ttl: Duration,
    ) -> Result<Lease, FakeIpError> {
        let expires_at = now.checked_add(ttl)?;
        if self.last_issued_at.is_some_and(|previous| now < previous) {
            return Err(FakeIpError::ClockReversed);
        }
        let address = match self.by_domain.get(domain) {
            Some(previous) => previous.address,
            None if self.len() < self.capacity.get() => self.range.address_at(self.len())?,
            None => return Err(FakeIpError::Exhausted),
        };
        // A renewal must not shorten an already published lease.
        let expires_at = self
            .by_domain
            .get(domain)
            .map_or(expires_at, |old| expires_at.max(old.expires_at));
        let lease = Lease {
            domain: domain.clone(),
            address,
            issued_at: now,
            expires_at,
        };
        self.by_domain.insert(domain.clone(), lease.clone());
        self.by_address.insert(address, domain.clone());
        self.last_issued_at = Some(now);
        Ok(lease)
    }

    pub(crate) fn reusable(
        &self,
        domain: &DomainName,
        now: Timestamp,
        minimum_ttl: Duration,
    ) -> Result<Option<&Lease>, FakeIpError> {
        if self.last_issued_at.is_some_and(|previous| now < previous) {
            return Err(FakeIpError::ClockReversed);
        }
        let minimum_deadline = now.checked_add(minimum_ttl)?;
        Ok(self
            .by_domain
            .get(domain)
            .filter(|lease| lease.is_valid_at(now) && lease.expires_at >= minimum_deadline))
    }

    pub fn lookup(&self, address: Ipv4Addr, now: Timestamp) -> Result<&Lease, FakeIpError> {
        if self.last_issued_at.is_some_and(|previous| now < previous) {
            return Err(FakeIpError::ClockReversed);
        }
        let domain = self
            .by_address
            .get(&address)
            .ok_or(FakeIpError::UnknownAddress)?;
        let lease = self
            .by_domain
            .get(domain)
            .ok_or(FakeIpError::InvalidSnapshot)?;
        if !lease.is_valid_at(now) {
            return Err(FakeIpError::Expired);
        }
        Ok(lease)
    }

    /// Look up a paired IPv6 identity under the same expiry and clock checks as
    /// IPv4. Outside, unused and unissued addresses fail closed.
    pub fn lookup_ipv6(&self, address: Ipv6Addr, now: Timestamp) -> Result<&Lease, FakeIpError> {
        let ipv4 = self
            .range
            .ipv4_identity(address)
            .ok_or(FakeIpError::UnknownAddress)?;
        self.lookup(ipv4, now)
    }

    pub(crate) fn snapshot(&self) -> Snapshot {
        let mut entries: Vec<_> = self.by_domain.values().cloned().collect();
        entries.sort_by_key(|lease| lease.address);
        Snapshot {
            version: 1,
            range: self.range,
            last_issued_at: self.last_issued_at,
            entries,
        }
    }

    pub(crate) fn restore(
        snapshot: Snapshot,
        range: FakeIpRange,
        capacity: NonZeroUsize,
    ) -> Result<Self, FakeIpError> {
        if snapshot.version != 1
            || snapshot.range != range
            || snapshot.entries.len() > capacity.get()
            || snapshot.entries.is_empty() != snapshot.last_issued_at.is_none()
        {
            return Err(FakeIpError::InvalidSnapshot);
        }
        let mut table = Self::new(range, capacity)?;
        for (index, lease) in snapshot.entries.into_iter().enumerate() {
            if lease.address != range.address_at(index)?
                || lease.issued_at >= lease.expires_at
                || snapshot
                    .last_issued_at
                    .is_none_or(|last| lease.issued_at > last)
                || table.by_domain.contains_key(&lease.domain)
            {
                return Err(FakeIpError::InvalidSnapshot);
            }
            table.by_address.insert(lease.address, lease.domain.clone());
            table.by_domain.insert(lease.domain.clone(), lease);
        }
        table.last_issued_at = snapshot.last_issued_at;
        Ok(table)
    }
}
