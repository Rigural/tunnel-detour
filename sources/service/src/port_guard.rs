//! Router socket ownership. No command lines, payloads or external name lookups are inspected.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    os::unix::fs::MetadataExt,
    time::{Duration, Instant},
};

use rustix::net::{self, AddressFamily, RecvFlags, SendFlags, SocketFlags, SocketType, netlink};
use serde::Serialize;
use thiserror::Error;
use tunnel_detour_core::InboundId;

use crate::{InboundConfig, ServiceError};

#[derive(Debug, Error)]
pub enum PortGuardError {
    #[error("router port inspection failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("router port ownership could not be inspected safely")]
    Inspection,
    #[error("router port inspection exceeded its resource bounds")]
    Capacity,
    #[error("port {port} is occupied by another router service")]
    Occupied {
        publication: InboundId,
        port: u16,
        uses: Vec<PortUse>,
    },
    #[error("internal relay port {port} is occupied by another router service")]
    RelayOccupied { port: u16, uses: Vec<PortUse> },
}

/// A bounded diagnostic for an authorized administrator, without executable paths or arguments.
#[derive(Clone, Debug, Serialize)]
pub struct PortUse {
    pub protocol: &'static str,
    pub family: u8,
    pub services: Vec<String>,
    pub tunnel_detour: bool,
}

struct SocketUse {
    port: u16,
    inode: u64,
    protocol: &'static str,
    family: u8,
}

fn inspection<T>(value: Result<T, impl Into<std::io::Error>>) -> Result<T, PortGuardError> {
    value.map_err(|error| PortGuardError::Io(error.into()))
}

fn u32_at(bytes: &[u8], offset: usize) -> Result<u32, PortGuardError> {
    Ok(u32::from_ne_bytes(
        bytes
            .get(offset..offset + 4)
            .ok_or(PortGuardError::Inspection)?
            .try_into()
            .map_err(|_| PortGuardError::Inspection)?,
    ))
}

// inet_diag_req_v2 / inet_diag_msg are the Linux 6.12 UAPI. Only fixed headers are
// required; variable attributes are skipped after validating each Netlink message length.
fn sockets(
    ports: &BTreeSet<u16>,
    family: u8,
    protocol: u8,
    deadline: Instant,
) -> Result<Vec<SocketUse>, PortGuardError> {
    let fd = inspection(net::socket_with(
        AddressFamily::NETLINK,
        SocketType::DGRAM,
        SocketFlags::CLOEXEC,
        Some(netlink::SOCK_DIAG),
    ))?;
    inspection(net::sockopt::set_socket_timeout(
        &fd,
        net::sockopt::Timeout::Recv,
        Some(Duration::from_millis(500)),
    ))?;
    let kernel = netlink::SocketAddrNetlink::new(0, 0);
    inspection(net::connect(&fd, &kernel))?;
    let mut request = [0_u8; 72];
    request[0..4].copy_from_slice(&72_u32.to_ne_bytes());
    request[4..6].copy_from_slice(&20_u16.to_ne_bytes()); // SOCK_DIAG_BY_FAMILY
    request[6..8].copy_from_slice(&0x301_u16.to_ne_bytes()); // REQUEST | DUMP
    request[8..12].copy_from_slice(&1_u32.to_ne_bytes());
    request[16] = family;
    request[17] = protocol;
    let states = if protocol == 6 {
        (1_u32 << 10) | (1_u32 << 13)
    } else {
        u32::MAX
    };
    request[20..24].copy_from_slice(&states.to_ne_bytes());
    request[64..72].fill(0xff); // INET_DIAG_NOCOOKIE
    if inspection(net::send(&fd, &request, SendFlags::empty()))? != request.len() {
        return Err(PortGuardError::Inspection);
    }
    let mut buffer = vec![0_u8; 65_536];
    let mut total = 0_usize;
    let mut found = Vec::new();
    loop {
        if Instant::now() >= deadline {
            return Err(PortGuardError::Capacity);
        }
        let (_, length, peer) =
            inspection(net::recvfrom(&fd, buffer.as_mut_slice(), RecvFlags::TRUNC))?;
        if length == 0
            || length > buffer.len()
            || peer
                .and_then(|peer| netlink::SocketAddrNetlink::try_from(peer).ok())
                .is_none_or(|peer| peer.pid() != 0)
        {
            return Err(PortGuardError::Inspection);
        }
        total = total.checked_add(length).ok_or(PortGuardError::Capacity)?;
        if total > 2 * 1024 * 1024 {
            return Err(PortGuardError::Capacity);
        }
        let mut offset = 0;
        while offset < length {
            let header = buffer
                .get(offset..length)
                .ok_or(PortGuardError::Inspection)?;
            let size =
                usize::try_from(u32_at(header, 0)?).map_err(|_| PortGuardError::Inspection)?;
            if size < 16 || size > header.len() || u32_at(header, 8)? != 1 {
                return Err(PortGuardError::Inspection);
            }
            let kind = u16::from_ne_bytes(
                header[4..6]
                    .try_into()
                    .map_err(|_| PortGuardError::Inspection)?,
            );
            let flags = u16::from_ne_bytes(
                header[6..8]
                    .try_into()
                    .map_err(|_| PortGuardError::Inspection)?,
            );
            if flags & 0x10 != 0 {
                return Err(PortGuardError::Inspection);
            } // interrupted dump
            if kind == 3 {
                if size >= 20 && u32_at(header, 16)? != 0 {
                    return Err(PortGuardError::Inspection);
                }
                return Ok(found);
            }
            if kind == 2 {
                if size < 20 {
                    return Err(PortGuardError::Inspection);
                }
                let code = i32::from_ne_bytes(
                    header[16..20]
                        .try_into()
                        .map_err(|_| PortGuardError::Inspection)?,
                );
                if code != 0 {
                    let errno = code.checked_neg().ok_or(PortGuardError::Inspection)?;
                    return Err(std::io::Error::from_raw_os_error(errno).into());
                }
            } else if kind == 20 {
                if size < 88 || header[16] != family {
                    return Err(PortGuardError::Inspection);
                }
                let port = u16::from_be_bytes(
                    header[20..22]
                        .try_into()
                        .map_err(|_| PortGuardError::Inspection)?,
                );
                if ports.contains(&port) {
                    if found.len() >= 1024 {
                        return Err(PortGuardError::Capacity);
                    }
                    found.push(SocketUse {
                        port,
                        inode: u64::from(u32_at(header, 84)?),
                        protocol: if protocol == 6 { "tcp" } else { "udp" },
                        family: if family == 2 { 4 } else { 6 },
                    });
                }
            } else {
                return Err(PortGuardError::Inspection);
            }
            offset = offset
                .checked_add(size.checked_add(3).ok_or(PortGuardError::Capacity)? & !3)
                .ok_or(PortGuardError::Capacity)?;
        }
    }
}

fn snapshot(ports: &BTreeSet<u16>) -> Result<BTreeMap<u16, Vec<PortUse>>, PortGuardError> {
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut claims = Vec::new();
    for family in [2, 10] {
        for protocol in [6, 17] {
            claims.extend(sockets(ports, family, protocol, deadline)?);
        }
    }
    // Inspect only: temporary bind probes can conflict with a real daemon starting,
    // or with another administrator's concurrent check. The supported kernel exposes
    // bound-but-not-listening TCP sockets through TCP_BOUND_INACTIVE above.
    if claims.is_empty() {
        return Ok(BTreeMap::new());
    }
    if claims.len() > 1024 {
        return Err(PortGuardError::Capacity);
    }
    let wanted: BTreeSet<_> = claims.iter().map(|claim| claim.inode).collect();
    let own = inspection(fs::metadata(inspection(std::env::current_exe())?))?;
    let mut holders: BTreeMap<u64, Vec<(String, bool)>> = BTreeMap::new();
    let mut pids = 0_usize;
    let mut descriptors = 0_usize;
    for process in inspection(fs::read_dir("/proc"))? {
        let process = inspection(process)?;
        if process
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<u32>().ok())
            .is_none()
        {
            continue;
        }
        pids += 1;
        if pids > 1024 || Instant::now() >= deadline {
            return Err(PortGuardError::Capacity);
        }
        let descriptor_directory = match fs::read_dir(process.path().join("fd")) {
            Ok(directory) => directory,
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::NotFound | std::io::ErrorKind::PermissionDenied
                ) =>
            {
                continue;
            }
            Err(_) => return Err(PortGuardError::Inspection),
        };
        let executable = fs::metadata(process.path().join("exe"));
        let owned = executable
            .is_ok_and(|metadata| metadata.dev() == own.dev() && metadata.ino() == own.ino());
        let name = if owned {
            "Tunnel Detour".to_owned()
        } else {
            fs::read_link(process.path().join("exe"))
                .ok()
                .and_then(|path| {
                    path.file_name()
                        .and_then(|name| name.to_str())
                        .map(str::to_owned)
                })
                .map(|name| {
                    name.chars()
                        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
                        .take(80)
                        .collect::<String>()
                })
                .filter(|name| !name.is_empty())
                .unwrap_or_else(|| "Unidentified process".into())
        };
        for descriptor in descriptor_directory {
            descriptors += 1;
            if descriptors > 32768 || Instant::now() >= deadline {
                return Err(PortGuardError::Capacity);
            }
            let descriptor = inspection(descriptor)?;
            let link = match fs::read_link(descriptor.path()) {
                Ok(link) => link,
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::NotFound | std::io::ErrorKind::PermissionDenied
                    ) =>
                {
                    continue;
                }
                Err(_) => return Err(PortGuardError::Inspection),
            };
            let inode = link
                .to_str()
                .and_then(|link| link.strip_prefix("socket:["))
                .and_then(|link| link.strip_suffix(']'))
                .and_then(|inode| inode.parse::<u64>().ok());
            if let Some(inode) = inode.filter(|inode| wanted.contains(inode)) {
                let entries = holders.entry(inode).or_default();
                if !entries.contains(&(name.clone(), owned)) {
                    if entries.len() >= 8 {
                        return Err(PortGuardError::Capacity);
                    }
                    entries.push((name.clone(), owned));
                }
            }
        }
    }
    let mut result: BTreeMap<u16, Vec<PortUse>> = BTreeMap::new();
    for claim in claims {
        let users = holders.get(&claim.inode);
        let owned =
            users.is_some_and(|users| !users.is_empty() && users.iter().all(|(_, owned)| *owned));
        result.entry(claim.port).or_default().push(PortUse {
            protocol: claim.protocol,
            family: claim.family,
            services: users
                .map(|users| users.iter().map(|(name, _)| name.clone()).collect())
                .unwrap_or_default(),
            tunnel_detour: owned,
        });
    }
    Ok(result)
}

pub(crate) async fn inspect(
    ports: BTreeSet<u16>,
) -> Result<BTreeMap<u16, Vec<PortUse>>, ServiceError> {
    if ports.is_empty() {
        return Ok(BTreeMap::new());
    }
    if ports.len() > 256 || ports.contains(&0) {
        return Err(PortGuardError::Capacity.into());
    }
    match tokio::task::spawn_blocking(move || snapshot(&ports)).await? {
        Ok(uses) => Ok(uses),
        Err(error) => {
            tracing::warn!(error=%error, "router socket ownership inspection failed");
            Err(error.into())
        }
    }
}

pub(crate) async fn check(config: &InboundConfig) -> Result<(), ServiceError> {
    let mut ports: BTreeSet<_> = config
        .rules
        .rules()
        .iter()
        .filter(|rule| rule.enabled())
        .map(|rule| rule.public_port().get())
        .collect();
    let relay = config.has_relays();
    if relay {
        ports.insert(config.relay.listen_port);
    }
    let mut uses = inspect(ports).await?;
    // Preserve this separate diagnostic if a public port is also the internal port.
    // Public ownership checks below consume their map entries.
    let relay_uses = uses.get(&config.relay.listen_port).cloned();
    for rule in config.rules.rules().iter().filter(|rule| rule.enabled()) {
        if let Some(usages) = uses.remove(&rule.public_port().get())
            && usages.iter().any(|usage| !usage.tunnel_detour)
        {
            return Err(PortGuardError::Occupied {
                publication: rule.id().clone(),
                port: rule.public_port().get(),
                uses: usages,
            }
            .into());
        }
    }
    if relay
        && let Some(uses) = relay_uses
        && uses.iter().any(|usage| !usage.tunnel_detour)
    {
        return Err(PortGuardError::RelayOccupied {
            port: config.relay.listen_port,
            uses,
        }
        .into());
    }
    Ok(())
}

pub(crate) fn diagnostic(error: &ServiceError) -> serde_json::Value {
    match error {
        ServiceError::PortGuard(PortGuardError::Occupied {
            publication,
            port,
            uses,
        }) => serde_json::json!({"publication":publication,"port":port,"uses":uses}),
        ServiceError::PortGuard(PortGuardError::RelayOccupied { port, uses }) => {
            serde_json::json!({"location":"relay_listener","port":port,"uses":uses})
        }
        _ => serde_json::Value::Null,
    }
}
