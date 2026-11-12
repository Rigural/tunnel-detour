//! Conservative RFC 9460 ServiceMode answers for the existing HTTP/TCP path.

use hickory_proto::{
    op::{Message, ResponseCode},
    rr::{
        DNSClass, Name, RData, Record,
        rdata::{
            A, AAAA, HTTPS, SVCB,
            svcb::{Alpn, IpHint, SvcParamKey as Key, SvcParamValue as Value},
        },
    },
};

use crate::{
    DnsAddressFamilies, DnsDecision, DnsQuestionType, DnsWireError, DomainName, ExceptionPolicy,
    Timestamp, dns::response_for, validate_upstream_reply,
};

/// A validated selected HTTPS question. Only `answer_dns` constructs it.
/// The adapter must exchange `packet()` with its dedicated real resolver and
/// call `answer()`; forwarding that reply verbatim would bypass Fake-IP policy.
#[derive(Debug, Eq, PartialEq)]
pub struct HttpsBindingQuery {
    packet: Vec<u8>,
    domain: DomainName,
}

impl HttpsBindingQuery {
    pub(crate) fn new(packet: Vec<u8>, domain: DomainName) -> Self {
        Self { packet, domain }
    }

    /// The original validated query, for the separately routed real resolver.
    pub fn packet(&self) -> &[u8] {
        &self.packet
    }

    /// Return only direct, same-host HTTP/TCP bindings with synthetic hints.
    /// Unsupported aliases, endpoints, protocols, ECH and unknown parameters
    /// retain the previous empty-answer behavior. No lease is allocated unless
    /// at least one supported record survives. Synthetic answers clear DNSSEC
    /// authentication and omit real address glue and signatures.
    ///
    /// Errors preserve upstream-envelope, range, persistence and encoding causes.
    pub fn answer(
        &self,
        policy: &mut ExceptionPolicy,
        upstream: &[u8],
        now: Timestamp,
    ) -> Result<Vec<u8>, DnsWireError> {
        validate_upstream_reply(&self.packet, upstream, policy.synthetic_range()?)?;
        let request = Message::from_vec(&self.packet)?;
        let mut response = response_for(&request, ResponseCode::NoError);
        if policy.decide_dns(&self.domain, DnsQuestionType::Other, now)? != DnsDecision::Empty {
            response.metadata.response_code = ResponseCode::Refused;
            return Ok(response.to_vec()?);
        }
        let real = Message::from_vec(upstream)?;
        if real.metadata.response_code != ResponseCode::NoError || real.answers.len() > 32 {
            return Ok(response.to_vec()?);
        }
        let owner = request
            .queries
            .first()
            .ok_or(DnsWireError::UnexpectedUpstream)?
            .name()
            .clone();
        let families = policy.address_families();
        let mut selected = Vec::new();
        for record in &real.answers {
            // AliasMode overrides ServiceMode in the complete RRset. CNAME
            // chains and alternate targets require separate endpoint ownership.
            if matches!(record.data, RData::CNAME(_)) {
                return Ok(response.to_vec()?);
            }
            let binding = match &record.data {
                RData::HTTPS(value) => &value.0,
                _ => continue,
            };
            if binding.svc_priority == 0 {
                return Ok(response.to_vec()?);
            }
            if record.name != owner || record.dns_class != DNSClass::IN {
                continue;
            }
            if let Some(binding) = sanitize(binding, &owner, families) {
                selected.push((record.ttl, binding));
            }
        }
        if selected.is_empty() {
            return Ok(response.to_vec()?);
        }
        let DnsDecision::Synthetic(lease) =
            policy.decide_dns(&self.domain, DnsQuestionType::A, now)?
        else {
            return Err(DnsWireError::UnsupportedSynthesis);
        };
        let remaining = lease
            .expires_at()
            .unix_seconds()
            .checked_sub(now.unix_seconds())
            .ok_or(DnsWireError::Ttl)?;
        let remaining = u32::try_from(remaining).map_err(|_| DnsWireError::Ttl)?;
        for (ttl, mut binding) in selected {
            for (_, value) in &mut binding.svc_params {
                match value {
                    Value::Ipv4Hint(hints) => *hints = IpHint(vec![A(lease.address())]),
                    Value::Ipv6Hint(hints) => *hints = IpHint(vec![AAAA(lease.ipv6_address())]),
                    _ => {}
                }
            }
            let data = RData::HTTPS(HTTPS(binding));
            response.add_answer(Record::from_rdata(owner.clone(), ttl.min(remaining), data));
        }
        Ok(response.to_vec()?)
    }
}

fn sanitize(binding: &SVCB, owner: &Name, families: DnsAddressFamilies) -> Option<SVCB> {
    if !(binding.target_name.is_root() || &binding.target_name == owner) {
        return None;
    }
    let mut previous = None;
    let mut params = Vec::new();
    let mut mandatory = Vec::new();
    let mut has_alpn = false;
    let mut no_default = false;
    for (key, value) in &binding.svc_params {
        let number = u16::from(*key);
        if previous.is_some_and(|old| old >= number) {
            return None;
        }
        previous = Some(number);
        let value = match (key, value) {
            (Key::Mandatory, Value::Mandatory(keys)) => {
                if keys.0.is_empty() {
                    return None;
                }
                let mut previous = 0;
                for key in &keys.0 {
                    let number = u16::from(*key);
                    if number <= previous {
                        return None;
                    }
                    previous = number;
                }
                mandatory = keys.0.clone();
                value.clone()
            }
            (Key::Alpn, Value::Alpn(protocols)) => {
                if protocols.0.is_empty() {
                    return None;
                }
                let protocols: Vec<_> = protocols
                    .0
                    .iter()
                    .filter(|protocol| matches!(protocol.as_str(), "h2" | "http/1.1"))
                    .cloned()
                    .collect();
                if protocols.is_empty() {
                    continue;
                }
                has_alpn = true;
                Value::Alpn(Alpn(protocols))
            }
            (Key::NoDefaultAlpn, Value::NoDefaultAlpn) => {
                no_default = true;
                Value::NoDefaultAlpn
            }
            (Key::Port, Value::Port(443)) => Value::Port(443),
            (Key::Ipv4Hint, Value::Ipv4Hint(hints)) if !hints.0.is_empty() => value.clone(),
            (Key::Ipv6Hint, Value::Ipv6Hint(hints)) if !hints.0.is_empty() => {
                if families != DnsAddressFamilies::DualStack {
                    continue;
                }
                value.clone()
            }
            // Do not strip opaque/unknown semantics and pretend compatibility.
            _ => return None,
        };
        params.push((*key, value));
    }
    if (no_default && !has_alpn)
        || mandatory
            .iter()
            .any(|required| !params.iter().any(|(key, _)| key == required))
    {
        return None;
    }
    Some(SVCB::new(binding.svc_priority, Name::root(), params))
}
