//! Bounded, cancellable kernel unicast queries. Callers own protocol framing and identity.

use rustix::net::{
    self, AddressFamily, Protocol, RecvFlags, SendFlags, SocketFlags, SocketType, netlink,
};
use std::{io, time::Duration};

pub(crate) async fn query(protocol: Protocol, message: &[u8]) -> io::Result<Vec<u8>> {
    let fd = net::socket_with(
        AddressFamily::NETLINK,
        SocketType::DGRAM,
        SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
        Some(protocol),
    )?;
    net::connect(&fd, &netlink::SocketAddrNetlink::new(0, 0))?;
    // Normally send() has already produced the reply. On deferred readiness, yield
    // without blocking a Tokio worker or detaching ownership of this descriptor.
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            match net::send(&fd, message, SendFlags::empty()) {
                Ok(length) if length == message.len() => break,
                Ok(_) => return Err(io::Error::from(io::ErrorKind::InvalidData)),
                Err(rustix::io::Errno::AGAIN) => {
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
                Err(rustix::io::Errno::INTR) => {}
                Err(error) => return Err(error.into()),
            }
        }
        let mut bytes = vec![0; 16_384];
        loop {
            match net::recvfrom(&fd, bytes.as_mut_slice(), RecvFlags::TRUNC) {
                Ok((_, length, address)) => {
                    if length > bytes.len()
                        || address
                            .and_then(|address| netlink::SocketAddrNetlink::try_from(address).ok())
                            .is_none_or(|address| address.pid() != 0)
                    {
                        return Err(io::Error::from(io::ErrorKind::InvalidData));
                    }
                    bytes.truncate(length);
                    return Ok(bytes);
                }
                Err(rustix::io::Errno::AGAIN) => {
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
                Err(rustix::io::Errno::INTR) => {}
                Err(error) => return Err(error.into()),
            }
        }
    })
    .await
    .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?
}
