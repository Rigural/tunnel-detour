//! Keep ownership of TCP send queues until their data and FIN have been acknowledged.
//! Linux 6.12 inet_diag UAPI; no dumps, mutation, payload inspection or unsafe FFI.

use rustix::net::{netdevice, netlink};
use std::{io, net::SocketAddr, time::Duration};
use tokio::net::TcpStream;

fn invalid() -> io::Error {
    io::Error::from(io::ErrorKind::InvalidData)
}

fn closed(stream: &TcpStream) -> io::Result<bool> {
    if let Some(error) = stream.take_error()? {
        return Err(error);
    }
    match stream.peer_addr() {
        Ok(_) => Ok(false),
        Err(error) if error.raw_os_error() == Some(rustix::io::Errno::NOTCONN.raw_os_error()) => {
            Ok(true)
        }
        Err(error) => Err(error),
    }
}

fn request(stream: &TcpStream) -> io::Result<[u8; 72]> {
    let local = stream.local_addr()?;
    let peer = stream.peer_addr()?;
    let socket = socket2::SockRef::from(stream);
    let mut message = [0; 72];
    message[..4].copy_from_slice(&72_u32.to_ne_bytes());
    message[4..6].copy_from_slice(&20_u16.to_ne_bytes()); // SOCK_DIAG_BY_FAMILY
    message[6..8].copy_from_slice(&1_u16.to_ne_bytes()); // REQUEST, not a dump
    message[8..12].copy_from_slice(&1_u32.to_ne_bytes());
    message[16] = if local.is_ipv4() { 2 } else { 10 };
    message[17] = 6; // TCP
    message[20..24].copy_from_slice(&u32::MAX.to_ne_bytes());
    message[24..26].copy_from_slice(&local.port().to_be_bytes());
    message[26..28].copy_from_slice(&peer.port().to_be_bytes());
    for (address, offset) in [(local, 28), (peer, 44)] {
        match address {
            SocketAddr::V4(address) => {
                message[offset..offset + 4].copy_from_slice(&address.ip().octets());
            }
            SocketAddr::V6(address) => {
                message[offset..offset + 16].copy_from_slice(&address.ip().octets());
            }
        }
    }
    if let Some(device) = socket.device()? {
        let device = std::str::from_utf8(&device).map_err(|_| invalid())?;
        message[60..64].copy_from_slice(&netdevice::name_to_index(stream, device)?.to_ne_bytes());
    }
    // The UAPI uses low and high native-endian u32 words, including on big-endian hosts.
    let cookie = socket.cookie()?;
    let low = u32::try_from(cookie & u64::from(u32::MAX)).map_err(|_| invalid())?;
    let high = u32::try_from(cookie >> 32).map_err(|_| invalid())?;
    message[64..68].copy_from_slice(&low.to_ne_bytes());
    message[68..72].copy_from_slice(&high.to_ne_bytes());
    Ok(message)
}

fn queue(response: &[u8], request: &[u8; 72]) -> io::Result<u32> {
    if response.len() < 20
        || usize::try_from(u32::from_ne_bytes(
            response[..4].try_into().map_err(|_| invalid())?,
        ))
        .map_err(|_| invalid())?
            != response.len()
        || response[6..8] != [0, 0]
        || response[8..12] != request[8..12]
    {
        return Err(invalid());
    }
    if u16::from_ne_bytes([response[4], response[5]]) == 2 {
        let code = i32::from_ne_bytes(response[16..20].try_into().map_err(|_| invalid())?);
        return Err(code
            .checked_neg()
            .filter(|code| *code > 0)
            .map(io::Error::from_raw_os_error)
            .unwrap_or_else(invalid));
    }
    if response.len() < 88
        || response[4..6] != request[4..6]
        || response[16] != request[16]
        || response[20..68] != request[24..72]
    {
        return Err(invalid());
    }
    // tcp_diag_get_info(): write_seq - snd_una includes queued, unacknowledged
    // application bytes and FIN. It cannot be replaced with socket write readiness.
    Ok(u32::from_ne_bytes(
        response[76..80].try_into().map_err(|_| invalid())?,
    ))
}

async fn pending(stream: &TcpStream) -> io::Result<u32> {
    if closed(stream)? {
        return Ok(0);
    }
    let result = async {
        let request = request(stream)?;
        let response = crate::kernel_netlink::query(netlink::SOCK_DIAG, &request).await?;
        queue(&response, &request)
    }
    .await;
    match result {
        // The socket can leave the established hash during the exact lookup. Only
        // this still-owned FD's confirmed close can turn a missing result into success.
        Err(error)
            if matches!(
                error.raw_os_error(),
                Some(code) if code == rustix::io::Errno::NOENT.raw_os_error()
                    || code == rustix::io::Errno::NOTCONN.raw_os_error()
            ) && closed(stream)? =>
        {
            Ok(0)
        }
        other => other,
    }
}

/// Call after copying both directions and shutting down their write halves. The
/// caller must keep its cancellation/inactivity deadline around this future and
/// abort on drop; acknowledgements, rather than poll attempts, count as progress.
pub(crate) async fn drain(
    first: &TcpStream,
    second: &TcpStream,
    mut progressed: impl FnMut(),
) -> io::Result<()> {
    let mut previous = [u32::MAX; 2];
    let mut pause = Duration::from_millis(1);
    loop {
        let pending = [pending(first).await?, pending(second).await?];
        if pending == [0, 0] {
            return Ok(());
        }
        if pending
            .iter()
            .zip(previous)
            .any(|(now, before)| *now < before)
        {
            if previous != [u32::MAX; 2] {
                progressed();
            }
            pause = Duration::from_millis(1);
        }
        previous = pending;
        tokio::time::sleep(pause).await;
        pause = (pause * 2).min(Duration::from_millis(50));
    }
}
