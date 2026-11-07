use std::{collections::BTreeSet, net::Ipv4Addr, sync::Arc};

use hickory_proto::{
    op::{Message, Query, ResponseCode},
    rr::{DNSClass, Name, RData, RecordType},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use tunnel_detour_core::{DomainName, validate_upstream_reply};

use crate::{ServiceConfig, ServiceError, adguard::AdguardControl};

#[derive(Clone)]
pub(crate) struct RealResolver {
    config: Arc<ServiceConfig>,
    filtering: Option<AdguardControl>,
}

impl RealResolver {
    pub fn new(config: Arc<ServiceConfig>) -> Result<Self, ServiceError> {
        let filtering = config
            .adguard
            .clone()
            .map(AdguardControl::new)
            .transpose()?;
        Ok(Self { config, filtering })
    }

    /// Connected TCP binds responses to one peer and avoids UDP spoofing and fragmentation.
    pub async fn exchange(&self, query: &[u8]) -> Result<Vec<u8>, ServiceError> {
        let mut stream = TcpStream::connect(self.config.real_upstream).await?;
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
        validate_upstream_reply(query, &response, self.config.fake_range)?;
        Ok(response)
    }

    pub async fn resolve(
        &self,
        domain: &DomainName,
        client: Ipv4Addr,
    ) -> Result<Vec<Ipv4Addr>, ServiceError> {
        let mut current = domain.clone();
        let mut visited = BTreeSet::from([current.clone()]);
        let mut checked = BTreeSet::new();
        let filtering = match &self.filtering {
            Some(filtering) if filtering.filtering_enabled(client).await? => Some(filtering),
            _ => None,
        };
        for _ in 0..8 {
            let mut query = Message::query();
            query.metadata.recursion_desired = true;
            query.add_query(Query::query(absolute_name(&current)?, RecordType::A));
            let bytes = self
                .exchange(&query.to_vec().map_err(|_| ServiceError::Protocol)?)
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
                if checked.insert(current.clone())
                    && let Some(filtering) = filtering
                {
                    filtering
                        .check_host(
                            current.as_str(),
                            if &current == domain { "A" } else { "CNAME" },
                            client,
                        )
                        .await?;
                }
                let mut addresses = BTreeSet::new();
                let mut alias = None;
                let current_name = absolute_name(&current)?;
                for record in &answer.answers {
                    if record.dns_class != DNSClass::IN || record.name != current_name {
                        continue;
                    }
                    match &record.data {
                        RData::A(value) => {
                            if !self.config.permits_real_target(value.0) {
                                return Err(ServiceError::ForbiddenTarget);
                            }
                            addresses.insert(value.0);
                            if addresses.len() > 16 {
                                return Err(ServiceError::Protocol);
                            }
                        }
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
                        }
                        _ => {}
                    }
                }
                if !addresses.is_empty() {
                    if alias.is_some() {
                        return Err(ServiceError::Protocol);
                    }
                    if let Some(filtering) = filtering {
                        for address in &addresses {
                            filtering
                                .check_host(&address.to_string(), "A", client)
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
