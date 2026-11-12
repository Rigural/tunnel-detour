//! One bounded HTTP request or TCP connection through an existing VPN device for authorized tests.
//! It changes no interfaces, addresses, routing rules or VPN peer configuration.
#![forbid(unsafe_code)]

use std::{
    error::Error,
    io::{Read, Write},
    net::{Ipv6Addr, SocketAddr, TcpStream},
    time::{Duration, Instant},
};

fn main() -> Result<(), Box<dyn Error>> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    let (tcp_only, operands) = if args.first().is_some_and(|mode| mode == "--tcp") {
        (true, &args[1..])
    } else {
        (false, args.as_slice())
    };
    let [endpoint, device, source] = operands else {
        return Err(
            "usage: vpn-http-probe [--tcp] <[IPv6]:port> <VPN-device> <VPN-IPv6-source>".into(),
        );
    };
    let endpoint: SocketAddr = endpoint.parse()?;
    let source: Ipv6Addr = source.parse()?;
    if !endpoint.is_ipv6()
        || endpoint.port() == 0
        || source.is_unspecified()
        || source.is_multicast()
        || source.is_loopback()
        || device.is_empty()
        || device.len() > 15
        || !device
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-'))
    {
        return Err("invalid IPv6 test path".into());
    }
    let socket = socket2::Socket::new(
        socket2::Domain::IPV6,
        socket2::Type::STREAM,
        Some(socket2::Protocol::TCP),
    )?;
    socket.bind_device(Some(device.as_bytes()))?;
    socket.bind(&SocketAddr::new(source.into(), 0).into())?;
    socket.connect_timeout(&endpoint.into(), Duration::from_secs(5))?;
    if tcp_only {
        println!("{{\"tcp_connected\":true,\"vpn_device_bound\":true}}");
        return Ok(());
    }
    let mut stream: TcpStream = socket.into();
    stream.set_write_timeout(Some(Duration::from_secs(3)))?;
    stream.write_all(b"GET / HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n")?;
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut response = Vec::new();
    loop {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or("HTTP deadline expired")?;
        stream.set_read_timeout(Some(remaining))?;
        let mut buffer = [0; 512];
        let count = stream.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        if response.len() + count > 4096 {
            return Err("HTTP response exceeds bound".into());
        }
        response.extend_from_slice(&buffer[..count]);
    }
    if !response.starts_with(b"HTTP/1.1 200 OK\r\n")
        || !response.ends_with(b"\r\n\r\nTunnel Detour temporary test is working.\n")
    {
        return Err("unexpected temporary HTTP response".into());
    }
    println!("{{\"http_status\":200,\"body_verified\":true,\"vpn_device_bound\":true}}");
    Ok(())
}
