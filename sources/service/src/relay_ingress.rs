//! Exact conntrack identity for an accepted, locally redirected IPv6 TCP connection.
//! Linux 6.12 UAPI: nfnetlink.h and nfnetlink_conntrack.h. No conntrack dump or mutation.

use rustix::net::netlink;
use std::{
    collections::BTreeMap,
    io,
    net::{Ipv6Addr, SocketAddr, SocketAddrV6},
};
use thiserror::Error;
use tokio::net::TcpStream;

#[derive(Debug, Error)]
pub enum RelayIngressError {
    #[error("the accepted connection has no verifiable kernel identity")]
    Invalid,
    #[error("the accepted connection is no longer tracked")]
    Missing,
    #[error("kernel connection inspection timed out")]
    Timeout,
    #[error("kernel connection inspection failed")]
    Io(#[from] io::Error),
}

/// Kernel-observed identity only. The caller must authorize its mark generation, original
/// public endpoint and source against the current policy before connecting a LAN target.
#[derive(Debug)]
pub struct RelayIngress {
    pub original_source: SocketAddrV6,
    pub original_destination: SocketAddrV6,
    pub mark: u32,
}

type Result<T> = std::result::Result<T, RelayIngressError>;

fn attribute(kind: u16, payload: &[u8]) -> Result<Vec<u8>> {
    let length = u16::try_from(
        payload
            .len()
            .checked_add(4)
            .ok_or(RelayIngressError::Invalid)?,
    )
    .map_err(|_| RelayIngressError::Invalid)?;
    let mut bytes = Vec::with_capacity((usize::from(length) + 3) & !3);
    bytes.extend(length.to_ne_bytes());
    bytes.extend(kind.to_ne_bytes());
    bytes.extend(payload);
    bytes.resize((usize::from(length) + 3) & !3, 0);
    Ok(bytes)
}

fn attributes(mut bytes: &[u8]) -> Result<BTreeMap<u16, &[u8]>> {
    let mut result = BTreeMap::new();
    while !bytes.is_empty() {
        if bytes.len() < 4 || result.len() >= 64 {
            return Err(RelayIngressError::Invalid);
        }
        let length = usize::from(u16::from_ne_bytes([bytes[0], bytes[1]]));
        let kind = u16::from_ne_bytes([bytes[2], bytes[3]]) & 0x3fff;
        if length < 4 || length > bytes.len() || result.insert(kind, &bytes[4..length]).is_some() {
            return Err(RelayIngressError::Invalid);
        }
        let aligned = (length + 3) & !3;
        bytes = if aligned <= bytes.len() {
            &bytes[aligned..]
        } else if length == bytes.len() {
            &[]
        } else {
            return Err(RelayIngressError::Invalid);
        };
    }
    Ok(result)
}

fn required<'a>(attributes: &BTreeMap<u16, &'a [u8]>, kind: u16) -> Result<&'a [u8]> {
    attributes
        .get(&kind)
        .copied()
        .ok_or(RelayIngressError::Invalid)
}

fn tuple(bytes: &[u8]) -> Result<(SocketAddrV6, SocketAddrV6)> {
    let attrs = attributes(bytes)?;
    let ip = attributes(required(&attrs, 1)?)?;
    let proto = attributes(required(&attrs, 2)?)?;
    if required(&proto, 1)? != [6] {
        return Err(RelayIngressError::Invalid);
    }
    let source = Ipv6Addr::from(
        <[u8; 16]>::try_from(required(&ip, 3)?).map_err(|_| RelayIngressError::Invalid)?,
    );
    let destination = Ipv6Addr::from(
        <[u8; 16]>::try_from(required(&ip, 4)?).map_err(|_| RelayIngressError::Invalid)?,
    );
    let port = |kind| -> Result<u16> {
        Ok(u16::from_be_bytes(
            required(&proto, kind)?
                .try_into()
                .map_err(|_| RelayIngressError::Invalid)?,
        ))
    };
    Ok((
        SocketAddrV6::new(source, port(2)?, 0, 0),
        SocketAddrV6::new(destination, port(3)?, 0, 0),
    ))
}

fn request(local: SocketAddrV6, peer: SocketAddrV6) -> Result<Vec<u8>> {
    let mut ip = attribute(3, &local.ip().octets())?;
    ip.extend(attribute(4, &peer.ip().octets())?);
    let mut proto = attribute(1, &[6])?;
    proto.extend(attribute(2, &local.port().to_be_bytes())?);
    proto.extend(attribute(3, &peer.port().to_be_bytes())?);
    let mut tuple = attribute(0x8001, &ip)?;
    tuple.extend(attribute(0x8002, &proto)?);
    // Look up the reply tuple: it contains the translated local socket endpoint.
    // The returned original tuple and mark identify the public publication generation.
    let mut bytes = vec![0; 20];
    bytes[4..6].copy_from_slice(&0x101_u16.to_ne_bytes()); // CTNETLINK / CT_GET
    bytes[6..8].copy_from_slice(&1_u16.to_ne_bytes()); // REQUEST, no dump or event subscription
    bytes[8..12].copy_from_slice(&1_u32.to_ne_bytes());
    bytes[16] = 10; // AF_INET6, NFNETLINK_V0, default zone
    bytes.extend(attribute(0x8002, &tuple)?); // CTA_TUPLE_REPLY
    let length = u32::try_from(bytes.len()).map_err(|_| RelayIngressError::Invalid)?;
    bytes[0..4].copy_from_slice(&length.to_ne_bytes());
    Ok(bytes)
}

fn response(
    bytes: &[u8],
    local: SocketAddrV6,
    peer: SocketAddrV6,
    original: SocketAddrV6,
) -> Result<RelayIngress> {
    if bytes.len() < 20
        || usize::try_from(u32::from_ne_bytes(
            bytes[0..4]
                .try_into()
                .map_err(|_| RelayIngressError::Invalid)?,
        ))
        .map_err(|_| RelayIngressError::Invalid)?
            != bytes.len()
        || u32::from_ne_bytes(
            bytes[8..12]
                .try_into()
                .map_err(|_| RelayIngressError::Invalid)?,
        ) != 1
    {
        return Err(RelayIngressError::Invalid);
    }
    // CT_GET can label its single unicast response MULTI. This request never asks
    // for a dump; all other flags (especially DUMP_INTR) are invalid here.
    if u16::from_ne_bytes([bytes[6], bytes[7]]) & !2 != 0 {
        return Err(RelayIngressError::Invalid);
    }
    let kind = u16::from_ne_bytes([bytes[4], bytes[5]]);
    if kind == 2 {
        let code = i32::from_ne_bytes(
            bytes[16..20]
                .try_into()
                .map_err(|_| RelayIngressError::Invalid)?,
        );
        return Err(if code == -2 {
            RelayIngressError::Missing
        } else if let Some(errno) = code.checked_neg().filter(|code| *code > 0) {
            RelayIngressError::Io(io::Error::from_raw_os_error(errno))
        } else {
            RelayIngressError::Invalid
        });
    }
    if kind != 0x100 || bytes[16..20] != [10, 0, 0, 0] {
        return Err(RelayIngressError::Invalid);
    }
    let attrs = attributes(&bytes[20..])?;
    if attrs.get(&18).is_some_and(|zone| *zone != [0, 0]) {
        return Err(RelayIngressError::Invalid);
    }
    let (original_source, original_destination) = tuple(required(&attrs, 1)?)?;
    if tuple(required(&attrs, 2)?)? != (local, peer)
        || original_source != peer
        || original_destination != original
    {
        return Err(RelayIngressError::Invalid);
    }
    // The kernel omits CTA_MARK when the mark is zero. Such an identity is observable,
    // but never an admission: the adapter must require its nonzero owned generation.
    let mark = match attrs.get(&8) {
        None => 0,
        Some(mark) => {
            u32::from_be_bytes((*mark).try_into().map_err(|_| RelayIngressError::Invalid)?)
        }
    };
    Ok(RelayIngress {
        original_source,
        original_destination,
        mark,
    })
}

/// Read exact original endpoints and conntrack mark without inspecting application bytes.
/// Missing, ambiguous, changed or untracked identities fail closed. This future is cancellable:
/// it owns its nonblocking Netlink socket and starts no detached or blocking task.
pub async fn inspect_relay_ingress(stream: &TcpStream) -> Result<RelayIngress> {
    let (SocketAddr::V6(local), SocketAddr::V6(peer)) = (stream.local_addr()?, stream.peer_addr()?)
    else {
        return Err(RelayIngressError::Invalid);
    };
    let original = socket2::SockRef::from(stream)
        .original_dst_v6()?
        .as_socket_ipv6()
        .ok_or(RelayIngressError::Invalid)?;
    if [local, peer, original].iter().any(|address| {
        address.scope_id() != 0
            || address.flowinfo() != 0
            || address.ip().to_ipv4_mapped().is_some()
    }) {
        return Err(RelayIngressError::Invalid);
    }
    let message = request(local, peer)?;
    let bytes = crate::kernel_netlink::query(netlink::NETFILTER, &message)
        .await
        .map_err(|error| match error.kind() {
            io::ErrorKind::TimedOut => RelayIngressError::Timeout,
            _ => RelayIngressError::Io(error),
        })?;
    response(&bytes, local, peer, original)
}

#[cfg(test)]
mod tests {
    use super::{RelayIngressError, attributes, response};

    #[test]
    fn r076_kernel_identity_decoder_rejects_truncation_ambiguous_attributes_and_failed_queries()
    -> Result<(), Box<dyn std::error::Error>> {
        // Lengths/types are independent wire scenarios, not output from the encoder.
        for malformed in [
            vec![1, 2, 3],
            vec![3, 0, 1, 0],
            vec![8, 0, 1, 0],
            vec![4, 0, 1, 0, 4, 0, 1, 128],
            vec![5, 0, 1, 0, 6, 0],
        ] {
            assert!(
                attributes(&malformed).is_err(),
                "malformed or duplicate kernel attributes were accepted"
            );
        }
        let mut oversized = Vec::new();
        for kind in 1_u16..=65 {
            oversized.extend(4_u16.to_ne_bytes());
            oversized.extend(kind.to_ne_bytes());
        }
        assert!(
            attributes(&oversized).is_err(),
            "attribute collections must stay bounded"
        );
        let mut missing = vec![0; 20];
        missing[0..4].copy_from_slice(&20_u32.to_ne_bytes());
        missing[4..6].copy_from_slice(&2_u16.to_ne_bytes()); // NLMSG_ERROR
        missing[8..12].copy_from_slice(&1_u32.to_ne_bytes());
        missing[16..20].copy_from_slice(&(-2_i32).to_ne_bytes()); // ENOENT
        let local = "[2001:db8:1::1]:19537".parse()?;
        let peer = "[2001:db8:1::2]:42001".parse()?;
        let original = "[2001:db8:1::1]:18080".parse()?;
        assert!(matches!(
            response(&missing, local, peer, original),
            Err(RelayIngressError::Missing)
        ));
        missing[8..12].copy_from_slice(&2_u32.to_ne_bytes());
        assert!(
            matches!(
                response(&missing, local, peer, original),
                Err(RelayIngressError::Invalid)
            ),
            "a different request's result is not this connection's identity"
        );
        Ok(())
    }
}
