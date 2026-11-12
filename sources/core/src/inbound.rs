//! Validated inbound publications, independent of DNS and operating-system adapters.

use std::{
    collections::BTreeSet,
    net::{IpAddr, Ipv6Addr, SocketAddr},
    num::{NonZeroU16, NonZeroUsize},
    str::FromStr,
};

use ipnet::{IpNet, Ipv6Net};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Internet-facing IPv6 admission uses the global-unicast aggregate. Membership alone
/// does not establish reachability; adapters still verify interfaces and exclude local scopes.
/// The literal prefix length is validated during constant evaluation, never from user input.
pub const INBOUND_INTERNET_V6: Ipv6Net =
    Ipv6Net::new_assert(Ipv6Addr::new(0x2000, 0, 0, 0, 0, 0, 0, 0), 3);

/// Invalid input never produces a partially validated publication list.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum InboundError {
    #[error("publication identifiers must contain 1 to 64 ASCII letters, digits or underscores")]
    Identifier,
    #[error("publication names must contain 1 to 80 bytes and no control characters")]
    Name,
    #[error("publication ports must be between 1 and 65535")]
    Port,
    #[error("configure an explicit authorized LAN scope")]
    Lan,
    #[error("the destination must be a unicast LAN host, excluding router and synthetic addresses")]
    Target,
    #[error("IPv6 to IPv4 relay publications support TCP only")]
    RelayProtocol,
    #[error("publication identifiers must be unique")]
    DuplicateIdentifier,
    #[error("enabled publications cannot share a public port and transport")]
    PortConflict,
    #[error("the publication list exceeds its configured capacity")]
    Capacity,
}

/// Stable identity shared by UCI, ownership and status. Never derived from the display name.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(try_from = "String", into = "String")]
pub struct InboundId(String);

impl InboundId {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for InboundId {
    type Err = InboundError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.is_empty()
            || value.len() > 64
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        {
            return Err(InboundError::Identifier);
        }
        Ok(Self(value.to_owned()))
    }
}

impl TryFrom<String> for InboundId {
    type Error = InboundError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.parse()
    }
}

impl From<InboundId> for String {
    fn from(value: InboundId) -> Self {
        value.0
    }
}

/// A single kernel transport. Combining protocols expands to two explicit admissions.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InboundTransport {
    Tcp,
    Udp,
}

impl InboundTransport {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        }
    }
}

/// Native IPv6 forwarding supports both protocols; the IPv4 relay is TCP only.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InboundProtocol {
    Tcp,
    Udp,
    TcpUdp,
}

impl InboundProtocol {
    pub fn transports(self) -> &'static [InboundTransport] {
        match self {
            Self::Tcp => &[InboundTransport::Tcp],
            Self::Udp => &[InboundTransport::Udp],
            Self::TcpUdp => &[InboundTransport::Tcp, InboundTransport::Udp],
        }
    }
}

/// Where a publication accepts connections addressed to the router's public endpoint.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InboundAccess {
    /// Public-address access is accepted from Internet only. LAN clients use the LAN endpoint.
    #[default]
    WanOnly,
    /// Authorized LAN clients may also use the public address. This does not prove Internet access.
    WanAndLan,
}

/// Input boundary only: callers must build `InboundRules` before changing listeners or rules.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InboundRuleSpec {
    pub id: InboundId,
    pub name: String,
    pub enabled: bool,
    pub protocol: InboundProtocol,
    #[serde(default)]
    pub access: InboundAccess,
    pub public_port: u16,
    pub destination: SocketAddr,
}

/// A fixed, authorized host endpoint. Clients cannot choose another destination in their payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct InboundTarget(SocketAddr);

impl InboundTarget {
    /// Reject router addresses, out-of-scope hosts, non-unicast and synthetic destinations.
    /// This validates address authorization, not remote-host address stability or availability.
    pub fn new(
        destination: SocketAddr,
        lan_networks: &[IpNet],
        router_addresses: &[IpAddr],
    ) -> Result<Self, InboundError> {
        if destination.port() == 0 {
            return Err(InboundError::Port);
        }
        if lan_networks.is_empty() || lan_networks.iter().any(|network| network.prefix_len() == 0) {
            return Err(InboundError::Lan);
        }
        let address = destination.ip();
        let unicast = match destination {
            SocketAddr::V4(endpoint) => {
                let ip = endpoint.ip();
                let octets = ip.octets();
                !ip.is_unspecified()
                    && !ip.is_loopback()
                    && !ip.is_link_local()
                    && !ip.is_broadcast()
                    && octets[0] != 0
                    && octets[0] < 224
                    && !(octets[0] == 198 && matches!(octets[1], 18 | 19))
                    && !lan_networks.iter().any(|network| match network {
                        IpNet::V4(network) if network.prefix_len() <= 30 => {
                            *ip == network.network() || *ip == network.broadcast()
                        }
                        _ => false,
                    })
            }
            SocketAddr::V6(endpoint) => {
                let ip = endpoint.ip();
                !ip.is_unspecified()
                    && !ip.is_loopback()
                    && !ip.is_multicast()
                    && !ip.is_unicast_link_local()
                    && ip.to_ipv4().is_none()
                    && endpoint.scope_id() == 0
                    && endpoint.flowinfo() == 0
            }
        };
        if !unicast
            || router_addresses.contains(&address)
            || !lan_networks
                .iter()
                .any(|network| network.contains(&address))
        {
            return Err(InboundError::Target);
        }
        Ok(Self(destination))
    }

    pub fn endpoint(self) -> SocketAddr {
        self.0
    }

    /// A v4 destination requires a userspace TCP relay; v6 uses native forwarding.
    pub fn requires_relay(self) -> bool {
        self.0.is_ipv4()
    }
}

/// A complete, validated publication. Its destination and ports cannot be changed independently.
#[derive(Clone, Debug, Serialize)]
pub struct InboundRule {
    id: InboundId,
    name: String,
    enabled: bool,
    protocol: InboundProtocol,
    access: InboundAccess,
    public_port: NonZeroU16,
    destination: InboundTarget,
}

impl InboundRule {
    pub fn id(&self) -> &InboundId {
        &self.id
    }
    pub fn name(&self) -> &str {
        &self.name
    }
    pub fn enabled(&self) -> bool {
        self.enabled
    }
    pub fn protocol(&self) -> InboundProtocol {
        self.protocol
    }
    pub fn access(&self) -> InboundAccess {
        self.access
    }
    pub fn public_port(&self) -> NonZeroU16 {
        self.public_port
    }
    pub fn destination(&self) -> InboundTarget {
        self.destination
    }
}

/// One authoritative list. Construction is all-or-nothing and performs no network mutation.
#[derive(Clone, Debug, Serialize)]
pub struct InboundRules(Vec<InboundRule>);

impl InboundRules {
    /// Validate capacity, identity, host authorization and conflicting enabled admissions.
    pub fn new(
        specs: Vec<InboundRuleSpec>,
        capacity: NonZeroUsize,
        lan_networks: &[IpNet],
        router_addresses: &[IpAddr],
    ) -> Result<Self, InboundError> {
        if specs.len() > capacity.get() {
            return Err(InboundError::Capacity);
        }
        let mut identifiers = BTreeSet::new();
        let mut admissions = BTreeSet::new();
        let mut rules = Vec::with_capacity(specs.len());
        for spec in specs {
            let name = spec.name.trim();
            if name.is_empty() || name.len() > 80 || name.chars().any(char::is_control) {
                return Err(InboundError::Name);
            }
            if !identifiers.insert(spec.id.clone()) {
                return Err(InboundError::DuplicateIdentifier);
            }
            let public_port = NonZeroU16::new(spec.public_port).ok_or(InboundError::Port)?;
            let destination = InboundTarget::new(spec.destination, lan_networks, router_addresses)?;
            if destination.requires_relay() && spec.protocol != InboundProtocol::Tcp {
                return Err(InboundError::RelayProtocol);
            }
            if spec.enabled {
                for transport in spec.protocol.transports() {
                    if !admissions.insert((*transport, public_port)) {
                        return Err(InboundError::PortConflict);
                    }
                }
            }
            rules.push(InboundRule {
                id: spec.id,
                name: name.to_owned(),
                enabled: spec.enabled,
                protocol: spec.protocol,
                access: spec.access,
                public_port,
                destination,
            });
        }
        Ok(Self(rules))
    }

    pub fn rules(&self) -> &[InboundRule] {
        &self.0
    }
}
