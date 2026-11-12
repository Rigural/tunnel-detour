use hickory_proto::{
    ProtoError,
    op::{Edns, Message, MessageType, OpCode, ResponseCode},
    rr::{
        DNSClass, RData, Record, RecordType,
        rdata::{A, AAAA},
    },
    serialize::binary::DecodeError,
};
use thiserror::Error;

use crate::{
    DnsDecision, DnsQuestionType, DomainName, ExceptionPolicy, FakeIpRange, StoreError, Timestamp,
};

#[derive(Debug, Eq, PartialEq)]
pub enum DnsWireDecision {
    Reply(Vec<u8>),
    /// Forward these unmodified bytes to the dedicated real resolver, never to AdGuard.
    Forward(Vec<u8>),
    /// Resolve through the dedicated real endpoint, then apply the owning
    /// policy before returning any service-binding data to the client.
    ServiceBinding(crate::HttpsBindingQuery),
}

#[derive(Debug, Error)]
pub enum DnsWireError {
    #[error("DNS message exceeds the protocol size bound")]
    TooLarge,
    #[error("DNS message could not be decoded")]
    Decode(#[from] DecodeError),
    #[error("DNS response could not be encoded")]
    Encode(#[from] ProtoError),
    #[error("DNS hostname is invalid")]
    Domain(#[from] crate::DomainError),
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error("DNS response TTL is outside the supported range")]
    Ttl,
    #[error("DNS policy selected an unsupported synthetic record type")]
    UnsupportedSynthesis,
    #[error("real DNS upstream response does not match the request")]
    UnexpectedUpstream,
    #[error("real DNS upstream returned a synthetic address; resolver loop or range conflict")]
    SyntheticUpstream,
}

/// Apply policy to a single DNS query. Transport adapters authenticate callers and bound I/O.
/// Malformed data never reaches allocation. Synthetic answers never claim DNSSEC validation.
pub fn answer_dns(
    policy: &mut ExceptionPolicy,
    packet: &[u8],
    now: Timestamp,
) -> Result<DnsWireDecision, DnsWireError> {
    if packet.len() > usize::from(u16::MAX) {
        return Err(DnsWireError::TooLarge);
    }
    let request = Message::from_vec(packet)?;
    if request.metadata.message_type != MessageType::Query
        || request.queries.len() != 1
        || request.metadata.truncation
        || !request.answers.is_empty()
        || !request.authorities.is_empty()
        || request.signature.is_some()
        || !request.additionals.is_empty()
    {
        return reply(&request, ResponseCode::FormErr);
    }
    if request.metadata.op_code != OpCode::Query {
        return reply(&request, ResponseCode::NotImp);
    }
    let query = &request.queries[0];
    if query.query_class() != DNSClass::IN {
        return reply(&request, ResponseCode::Refused);
    }
    if request
        .edns
        .as_ref()
        .is_some_and(|edns| edns.version() != 0)
    {
        return reply(&request, ResponseCode::BADVERS);
    }
    let name: DomainName = match query.name().to_ascii().parse() {
        Ok(name) => name,
        // Non-hostname questions, including root and DNS-SD labels, still need ordinary DNS.
        // They cannot match the validated hostname-only exception list.
        Err(_) => {
            // Qualified service-binding owners still refer to the selected
            // hostname. Suppress their unsupported port/protocol mapping rather
            // than forwarding real address hints merely because '_' is not a
            // hostname label. Ordinary DNS-SD and unrelated hosts stay intact.
            if let Some(host) = qualified_binding_host(query.query_type(), &query.name().to_ascii())
                && policy.decide_dns(&host, DnsQuestionType::Other, now)? == DnsDecision::Empty
            {
                return reply(&request, ResponseCode::NoError);
            }
            return Ok(DnsWireDecision::Forward(packet.to_vec()));
        }
    };
    let kind = match query.query_type() {
        RecordType::A => DnsQuestionType::A,
        RecordType::AAAA => DnsQuestionType::Aaaa,
        RecordType::HTTPS => DnsQuestionType::Https,
        RecordType::SVCB => DnsQuestionType::Svcb,
        _ => DnsQuestionType::Other,
    };
    let mut response = response_for(&request, ResponseCode::NoError);
    match policy.decide_dns(&name, kind, now)? {
        DnsDecision::Forward => return Ok(DnsWireDecision::Forward(packet.to_vec())),
        DnsDecision::Empty if kind == DnsQuestionType::Https => {
            return Ok(DnsWireDecision::ServiceBinding(
                crate::HttpsBindingQuery::new(packet.to_vec(), name),
            ));
        }
        DnsDecision::Empty => {}
        DnsDecision::Synthetic(lease) => {
            let ttl = lease
                .expires_at()
                .unix_seconds()
                .checked_sub(now.unix_seconds())
                .and_then(|ttl| u32::try_from(ttl).ok())
                .ok_or(DnsWireError::Ttl)?;
            let address = match query.query_type() {
                RecordType::A => RData::A(A(lease.address())),
                RecordType::AAAA => RData::AAAA(AAAA(lease.ipv6_address())),
                _ => return Err(DnsWireError::UnsupportedSynthesis),
            };
            response.add_answer(Record::from_rdata(query.name().clone(), ttl, address));
        }
    }
    Ok(DnsWireDecision::Reply(response.to_vec()?))
}

fn qualified_binding_host(kind: RecordType, owner: &str) -> Option<DomainName> {
    if !matches!(kind, RecordType::HTTPS | RecordType::SVCB) {
        return None;
    }
    let mut parts = owner.splitn(3, '.');
    parts.next()?.strip_prefix('_')?.parse::<u16>().ok()?;
    let protocol = parts.next()?;
    if !protocol.eq_ignore_ascii_case("_https")
        && !(kind == RecordType::SVCB
            && (protocol.eq_ignore_ascii_case("_tcp") || protocol.eq_ignore_ascii_case("_udp")))
    {
        return None;
    }
    parts.next()?.parse().ok()
}

pub(crate) fn response_for(request: &Message, code: ResponseCode) -> Message {
    let mut response = Message::response(request.metadata.id, request.metadata.op_code);
    response.metadata.response_code = code;
    response.metadata.recursion_desired = request.metadata.recursion_desired;
    response.metadata.recursion_available = true;
    response.add_queries(request.queries.iter().take(1).cloned());
    if let Some(edns) = &request.edns {
        let mut output = Edns::new();
        output
            .set_version(0)
            .set_max_payload(edns.max_payload().clamp(512, 1232));
        response.set_edns(output);
    }
    response
}

fn reply(request: &Message, code: ResponseCode) -> Result<DnsWireDecision, DnsWireError> {
    Ok(DnsWireDecision::Reply(
        response_for(request, code).to_vec()?,
    ))
}

/// Validate a dedicated real resolver's response before forwarding or using it for egress.
/// The network adapter must also use a connected, authenticated-by-peer transport.
pub fn validate_upstream_reply(
    query: &[u8],
    response: &[u8],
    synthetic: FakeIpRange,
) -> Result<(), DnsWireError> {
    if query.len() > usize::from(u16::MAX) || response.len() > usize::from(u16::MAX) {
        return Err(DnsWireError::TooLarge);
    }
    let query = Message::from_vec(query)?;
    let response = Message::from_vec(response)?;
    if query.metadata.message_type != MessageType::Query
        || query.queries.len() != 1
        || response.metadata.message_type != MessageType::Response
        || response.metadata.id != query.metadata.id
        || response.metadata.op_code != query.metadata.op_code
        || response.queries != query.queries
        || response.metadata.truncation
    {
        return Err(DnsWireError::UnexpectedUpstream);
    }
    for record in response
        .answers
        .iter()
        .chain(&response.authorities)
        .chain(&response.additionals)
    {
        let synthetic_address = match &record.data {
            RData::A(address) => synthetic.contains(address.0),
            RData::AAAA(address) => synthetic.ipv6_range().contains(&address.0),
            RData::HTTPS(binding) => synthetic_hints(&binding.0, synthetic),
            RData::SVCB(binding) => synthetic_hints(binding, synthetic),
            _ => false,
        };
        if synthetic_address {
            return Err(DnsWireError::SyntheticUpstream);
        }
    }
    Ok(())
}

fn synthetic_hints(binding: &hickory_proto::rr::rdata::SVCB, range: FakeIpRange) -> bool {
    use hickory_proto::rr::rdata::svcb::SvcParamValue;
    binding.svc_params.iter().any(|(_, value)| match value {
        SvcParamValue::Ipv4Hint(hints) => hints.0.iter().any(|address| range.contains(address.0)),
        SvcParamValue::Ipv6Hint(hints) => hints
            .0
            .iter()
            .any(|address| range.ipv6_range().contains(&address.0)),
        _ => false,
    })
}
