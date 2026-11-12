use std::{
    collections::{BTreeSet, VecDeque},
    net::IpAddr,
    sync::{Arc, Mutex},
};

use hickory_proto::{
    op::{Message, Query, ResponseCode},
    rr::{DNSClass, Name, RData, RecordType},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpSocket,
};
use tunnel_detour_core::{DomainName, validate_upstream_reply};

use crate::{ServiceConfig, ServiceError, adguard::AdguardControl, config::DnsIntegration};

#[derive(Clone)]
pub(crate) struct RealResolver {
    active: Arc<Mutex<Option<ResolverSnapshot>>>,
    filtering: Option<AdguardControl>,
}

#[derive(Clone)]
pub(crate) struct ResolverSnapshot {
    pub config: Arc<ServiceConfig>,
    pub path: crate::upstream_route::ResolverPath,
}

impl RealResolver {
    pub async fn new(config: Arc<ServiceConfig>) -> Result<Self, ServiceError> {
        let path = crate::upstream_route::ResolverPath::prepare(&config).await?;
        let filtering = config
            .adguard
            .clone()
            .map(AdguardControl::new)
            .transpose()?;
        Ok(Self {
            active: Arc::new(Mutex::new(Some(ResolverSnapshot { config, path }))),
            filtering,
        })
    }

    pub(crate) fn snapshot(&self) -> Result<ResolverSnapshot, ServiceError> {
        self.active
            .lock()
            .map_err(|_| ServiceError::Poisoned)?
            .clone()
            .ok_or(ServiceError::Busy)
    }

    pub(crate) fn pause(&self) -> Result<(), ServiceError> {
        *self.active.lock().map_err(|_| ServiceError::Poisoned)? = None;
        Ok(())
    }

    pub(crate) fn activate(
        &self,
        config: Arc<ServiceConfig>,
        path: crate::upstream_route::ResolverPath,
    ) -> Result<(), ServiceError> {
        *self.active.lock().map_err(|_| ServiceError::Poisoned)? =
            Some(ResolverSnapshot { config, path });
        Ok(())
    }

    /// Connected TCP binds responses to one peer and avoids UDP spoofing and fragmentation.
    pub async fn exchange(&self, query: &[u8]) -> Result<Vec<u8>, ServiceError> {
        self.exchange_at(&self.snapshot()?, query).await
    }

    async fn exchange_at(
        &self,
        snapshot: &ResolverSnapshot,
        query: &[u8],
    ) -> Result<Vec<u8>, ServiceError> {
        let socket = if snapshot.path.endpoint.is_ipv4() {
            TcpSocket::new_v4()?
        } else {
            TcpSocket::new_v6()?
        };
        socket2::SockRef::from(&socket).bind_device(Some(snapshot.path.device.as_bytes()))?;
        let mut stream = socket.connect(snapshot.path.endpoint).await?;
        stream
            .write_u16(u16::try_from(query.len()).map_err(|_| ServiceError::Protocol)?)
            .await?;
        stream.write_all(query).await?;
        let length = stream.read_u16().await?;
        if length < 12 {
            return Err(ServiceError::Protocol);
        }
        let mut response = vec![0; usize::from(length)];
        stream.read_exact(&mut response).await?;
        validate_upstream_reply(query, &response, snapshot.config.fake_range)?;
        Ok(response)
    }

    pub async fn resolve(
        &self,
        domain: &DomainName,
        client: IpAddr,
        synthetic: IpAddr,
    ) -> Result<Vec<IpAddr>, ServiceError> {
        // Both families and complete alias chains use one prepared endpoint,
        // even across reload. Absence may select the other family; filtering,
        // malformed replies and other failures never become a bypass fallback.
        let snapshot = self.snapshot()?;
        if snapshot.config.ipv6.is_some()
            && let Some(filtering) = &self.filtering
        {
            filtering.require_ipv6_enabled().await?;
        }
        let config = &snapshot.config;
        let dnsmasq_owned = if config.dns_integration == DnsIntegration::Dnsmasq {
            let owned = config
                .rules
                .rules()
                .iter()
                .filter(|rule| rule.enabled)
                .map(|rule| {
                    format!(
                        "/{}/{ip}#{port}",
                        rule.pattern.domain,
                        ip = config.dns_listen.ip(),
                        port = config.dns_listen.port()
                    )
                })
                .collect();
            crate::dnsmasq::validate_frontend(config, &owned, true).await?;
            Some(owned)
        } else {
            None
        };
        let filtering = match &self.filtering {
            Some(filtering) if filtering.filtering_enabled(client).await? => Some(filtering),
            _ => None,
        };
        if let Some(filtering) = filtering {
            filtering
                .check_host(
                    &synthetic.to_string(),
                    if synthetic.is_ipv6() { "AAAA" } else { "A" },
                    client,
                )
                .await?;
        }
        let resolve = |kind| {
            let snapshot = &snapshot;
            let owned = dnsmasq_owned.as_ref();
            async move {
                match self
                    .resolve_at(snapshot, domain, client, kind, owned, filtering)
                    .await
                {
                    Ok(addresses) => Ok(addresses),
                    Err(ServiceError::NoAddress) => Ok(Vec::new()),
                    Err(error) => Err(error),
                }
            }
        };
        let addresses = if snapshot.config.ipv6.is_none() {
            resolve(RecordType::A).await?
        } else {
            // Both complete chains must pass before any WAN dial. Either error
            // cancels the other read-only path, never becoming a family fallback.
            let (mut a, aaaa) =
                tokio::try_join!(resolve(RecordType::A), resolve(RecordType::AAAA))?;
            a.extend(aaaa);
            a
        };
        if addresses.is_empty() {
            return Err(ServiceError::NoAddress);
        }
        let (mut preferred, mut other): (VecDeque<_>, VecDeque<_>) = addresses
            .into_iter()
            .partition(|address| address.is_ipv6() == client.is_ipv6());
        let mut ordered = Vec::new();
        while !preferred.is_empty() || !other.is_empty() {
            if let Some(address) = preferred.pop_front() {
                ordered.push(address);
            }
            if let Some(address) = other.pop_front() {
                ordered.push(address);
            }
        }
        Ok(ordered)
    }

    async fn resolve_at(
        &self,
        snapshot: &ResolverSnapshot,
        domain: &DomainName,
        client: IpAddr,
        kind: RecordType,
        dnsmasq_owned: Option<&BTreeSet<String>>,
        filtering: Option<&AdguardControl>,
    ) -> Result<Vec<IpAddr>, ServiceError> {
        let config = &snapshot.config;
        let mut current = domain.clone();
        let mut visited = BTreeSet::from([current.clone()]);
        let mut checked = BTreeSet::new();
        for _ in 0..8 {
            let mut query = Message::query();
            query.metadata.recursion_desired = true;
            query.add_query(Query::query(absolute_name(&current)?, kind));
            let bytes = self
                .exchange_at(
                    snapshot,
                    &query.to_vec().map_err(|_| ServiceError::Protocol)?,
                )
                .await?;
            let answer = Message::from_vec(&bytes).map_err(|_| ServiceError::Protocol)?;
            if answer.metadata.response_code != ResponseCode::NoError {
                return Err(ServiceError::NoAddress);
            }
            // Follow only owner-matching CNAMEs. Unrelated additional records cannot select an egress target.
            let mut followed_in_packet = false;
            for _ in 0..8 {
                // Fake-IP conceals the upstream alias chain from AdGuard's DNS response
                // filtering. Check each owner, with the original client identity, before WAN.
                if checked.insert(current.clone()) {
                    if let Some(owned) = dnsmasq_owned
                        && &current != domain
                    {
                        crate::dnsmasq::validate_alias(config, owned, &current).await?;
                    }
                    if let Some(filtering) = filtering {
                        filtering
                            .check_host(
                                current.as_str(),
                                if kind == RecordType::AAAA {
                                    "AAAA"
                                } else {
                                    "A"
                                },
                                client,
                            )
                            .await?;
                        if &current != domain {
                            // The pinned AdGuard version also filters aliases
                            // using the query type, not just the CNAME RR type.
                            filtering
                                .check_host(current.as_str(), "CNAME", client)
                                .await?;
                        }
                    }
                }
                let mut addresses = BTreeSet::new();
                let mut alias = None;
                let current_name = absolute_name(&current)?;
                for record in &answer.answers {
                    if record.dns_class != DNSClass::IN || record.name != current_name {
                        continue;
                    }
                    let address = match &record.data {
                        RData::A(value) if kind == RecordType::A => Some(IpAddr::V4(value.0)),
                        RData::AAAA(value) if kind == RecordType::AAAA => Some(IpAddr::V6(value.0)),
                        RData::CNAME(value) => {
                            let target: DomainName = value
                                .0
                                .to_ascii()
                                .parse()
                                .map_err(|_| ServiceError::Protocol)?;
                            if alias.as_ref().is_some_and(|old| old != &target) {
                                return Err(ServiceError::Protocol);
                            }
                            alias = Some(target);
                            None
                        }
                        _ => None,
                    };
                    if let Some(address) = address {
                        if !config.permits_real_target(address) {
                            return Err(ServiceError::ForbiddenTarget);
                        }
                        if dnsmasq_owned.is_some() {
                            crate::dnsmasq::validate_target(domain, address).await?;
                            if &current != domain {
                                crate::dnsmasq::validate_target(&current, address).await?;
                            }
                        }
                        addresses.insert(address);
                        if addresses.len() > 16 {
                            return Err(ServiceError::Protocol);
                        }
                    }
                }
                if !addresses.is_empty() {
                    if alias.is_some() {
                        return Err(ServiceError::Protocol);
                    }
                    if let Some(filtering) = filtering {
                        for address in &addresses {
                            filtering
                                .check_host(
                                    &address.to_string(),
                                    if kind == RecordType::AAAA {
                                        "AAAA"
                                    } else {
                                        "A"
                                    },
                                    client,
                                )
                                .await?;
                        }
                    }
                    return Ok(addresses.into_iter().collect());
                }
                match alias {
                    Some(target) => {
                        if !visited.insert(target.clone()) || visited.len() > 8 {
                            return Err(ServiceError::AliasLoop);
                        }
                        current = target;
                        followed_in_packet = true;
                    }
                    None if !followed_in_packet => return Err(ServiceError::NoAddress),
                    None => break,
                }
            }
        }
        Err(ServiceError::AliasLoop)
    }
}

fn absolute_name(domain: &DomainName) -> Result<Name, ServiceError> {
    Name::from_ascii(format!("{domain}.")).map_err(|_| ServiceError::Protocol)
}
