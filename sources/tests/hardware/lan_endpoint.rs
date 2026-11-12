//! Bounded, dependency-free endpoint for separately authorized physical LAN acceptance.
//! Compile with the LAN host's native rustc; this file is never shipped in an APK.
#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used)]

use std::{
    error::Error,
    io::{Read, Write},
    net::{IpAddr, SocketAddr, TcpListener, TcpStream, UdpSocket},
    path::Path,
    thread,
    time::{Duration, Instant},
};

const PAYLOAD: &[u8] = b"tunnel-detour:synthetic-lan-acceptance";
type Result<T = ()> = std::result::Result<T, Box<dyn Error>>;

struct Session {
    stream: TcpStream,
    pending: Vec<u8>,
    written: usize,
    bytes: usize,
    active: Instant,
    http: bool,
    request: Vec<u8>,
}

impl Session {
    fn tick(&mut self) -> std::io::Result<bool> {
        if self.active.elapsed() > Duration::from_secs(30) || self.bytes > 1_048_576 {
            return Ok(false);
        }
        if self.written == self.pending.len() {
            let mut buffer = [0; 4096];
            match self.stream.read(&mut buffer) {
                Ok(0) => return Ok(false),
                Ok(count) => {
                    self.pending.clear();
                    if self.http {
                        if self.request.len() + count > 4096 {
                            return Ok(false);
                        }
                        self.request.extend_from_slice(&buffer[..count]);
                        if !self.request.windows(4).any(|bytes| bytes == b"\r\n\r\n") {
                            return Ok(true);
                        }
                        let (status, body) = if self.request.starts_with(b"GET ") {
                            ("200 OK", "Tunnel Detour temporary test is working.\n")
                        } else {
                            (
                                "405 Method Not Allowed",
                                "Use GET for this temporary test.\n",
                            )
                        };
                        self.pending.extend_from_slice(format!("HTTP/1.1 {status}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes());
                    } else {
                        self.pending.extend_from_slice(&buffer[..count]);
                    }
                    self.written = 0;
                    self.bytes += count;
                    self.active = Instant::now();
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => return Ok(true),
                Err(error) => return Err(error),
            }
        }
        match self.stream.write(&self.pending[self.written..]) {
            Ok(0) => Ok(false),
            Ok(count) => {
                self.written += count;
                Ok(!self.http || self.written < self.pending.len())
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => Ok(true),
            Err(error) => Err(error),
        }
    }
}

fn serve(
    v4: SocketAddr,
    v6: SocketAddr,
    router4: IpAddr,
    router6: IpAddr,
    stop: &Path,
    seconds: u64,
    http: bool,
) -> Result {
    if !v4.is_ipv4()
        || !v6.is_ipv6()
        || !router4.is_ipv4()
        || !router6.is_ipv6()
        || v4.port() < 1024
        || v6.port() != v4.port()
        || !(1..=900).contains(&seconds)
    {
        return Err("invalid bounded LAN endpoint parameters".into());
    }
    let listeners = [TcpListener::bind(v4)?, TcpListener::bind(v6)?];
    for listener in &listeners {
        listener.set_nonblocking(true)?;
    }
    let udp = UdpSocket::bind(v6)?;
    udp.set_nonblocking(true)?;
    let mut sessions = Vec::<Session>::new();
    let deadline = Instant::now() + Duration::from_secs(seconds);
    println!("{{\"ready\":true,\"process_id\":{}}}", std::process::id());
    std::io::stdout().flush()?;
    while Instant::now() < deadline && !stop.exists() {
        for listener in &listeners {
            for _ in 0..16 {
                match listener.accept() {
                    Ok((stream, peer)) => {
                        if ![router4, router6, v4.ip(), v6.ip()].contains(&peer.ip())
                            || sessions.len() >= 16
                        {
                            continue;
                        }
                        stream.set_nonblocking(true)?;
                        println!(
                            "{{\"accepted_tcp\":\"{peer}\",\"local\":\"{}\"}}",
                            stream.local_addr()?
                        );
                        sessions.push(Session {
                            stream,
                            pending: Vec::new(),
                            written: 0,
                            bytes: 0,
                            active: Instant::now(),
                            http,
                            request: Vec::new(),
                        });
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(error) => return Err(error.into()),
                }
            }
        }
        let mut index = 0;
        while index < sessions.len() {
            match sessions[index].tick() {
                Ok(true) => index += 1,
                Ok(false) => {
                    sessions.swap_remove(index);
                }
                Err(error) => {
                    eprintln!("accepted TCP session closed: {:?}", error.kind());
                    sessions.swap_remove(index);
                }
            }
        }
        for _ in 0..16 {
            let mut buffer = [0; 512];
            match udp.recv_from(&mut buffer) {
                Ok((count, peer)) if peer.ip() == router6 && &buffer[..count] == PAYLOAD => {
                    if udp.send_to(PAYLOAD, peer)? != PAYLOAD.len() {
                        return Err("incomplete UDP response".into());
                    }
                    println!("{{\"accepted_udp\":\"{peer}\"}}");
                }
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(error) => return Err(error.into()),
            }
        }
        thread::sleep(Duration::from_millis(5));
    }
    drop(sessions);
    println!("{{\"stopped\":true}}");
    Ok(())
}

fn probe(transport: &str, target: SocketAddr) -> Result {
    let wait = Duration::from_secs(3);
    if matches!(transport, "tcp" | "http") {
        let mut stream = TcpStream::connect_timeout(&target, wait)?;
        stream.set_read_timeout(Some(wait))?;
        stream.set_write_timeout(Some(wait))?;
        if transport == "http" {
            stream.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")?;
            let deadline = Instant::now() + wait;
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
                return Err("unexpected HTTP test response".into());
            }
            println!("{{\"http_status\":200,\"body_verified\":true}}");
            return Ok(());
        }
        stream.write_all(PAYLOAD)?;
        let mut response = vec![0; PAYLOAD.len()];
        stream.read_exact(&mut response)?;
        if response != PAYLOAD {
            return Err("TCP payload differs".into());
        }
    } else if transport == "udp" && target.is_ipv6() {
        let udp = UdpSocket::bind("[::]:0")?;
        udp.set_read_timeout(Some(wait))?;
        udp.set_write_timeout(Some(wait))?;
        udp.connect(target)?;
        if udp.send(PAYLOAD)? != PAYLOAD.len() {
            return Err("incomplete UDP request".into());
        }
        let mut response = [0; 512];
        let count = udp.recv(&mut response)?;
        if &response[..count] != PAYLOAD {
            return Err("UDP payload differs".into());
        }
    } else {
        return Err("expected HTTP, TCP or IPv6 UDP".into());
    }
    println!("{{\"payload_verified\":true,\"transport\":\"{transport}\"}}");
    Ok(())
}

fn main() -> Result {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    match args.as_slice() {
        [mode, v4, v6, router4, router6, stop, seconds] if matches!(mode.as_str(), "serve" | "serve-http") =>
            serve(v4.parse()?, v6.parse()?, router4.parse()?, router6.parse()?, Path::new(stop), seconds.parse()?, mode == "serve-http"),
        [mode, transport, target] if mode == "probe" => probe(transport, target.parse()?),
        _ => Err("usage: lan_endpoint <serve|serve-http> <IPv4:port> <[IPv6]:port> <router-IPv4> <router-IPv6> <stop-file> <1..900 seconds> | probe <http|tcp|udp> <endpoint>".into()),
    }
}
