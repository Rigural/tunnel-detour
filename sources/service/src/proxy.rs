use std::{
    net::{SocketAddr, SocketAddrV4},
    sync::{Arc, Mutex},
    time::Duration,
};

use socket2::SockRef;
use tokio::{
    io::copy_bidirectional,
    net::{TcpSocket, TcpStream},
    time::timeout,
};
use tokio_util::sync::CancellationToken;
use tunnel_detour_core::ExceptionPolicy;

use crate::{
    ConnectionStatus, ServiceConfig, ServiceError, StatusHandle, runtime::now,
    upstream::RealResolver,
};

pub(crate) struct ProxyHandler {
    pub config: Arc<ServiceConfig>,
    pub policy: Arc<Mutex<ExceptionPolicy>>,
    pub resolver: RealResolver,
    pub status: StatusHandle,
}

impl ProxyHandler {
    pub async fn serve(
        &self,
        id: String,
        mut incoming: TcpStream,
        peer: SocketAddr,
        cancel: CancellationToken,
    ) -> Result<(), ServiceError> {
        let SocketAddr::V4(peer_v4) = peer else {
            return Err(ServiceError::Unauthorized);
        };
        if !self.config.allows_client(*peer_v4.ip()) {
            return Err(ServiceError::Unauthorized);
        }
        let original = SockRef::from(&incoming)
            .original_dst_v4()?
            .as_socket_ipv4()
            .ok_or(ServiceError::Protocol)?;
        let domain = tokio::task::block_in_place(|| {
            Ok::<_, ServiceError>(
                self.policy
                    .lock()
                    .map_err(|_| ServiceError::Poisoned)?
                    .authorize_tcp(*original.ip(), original.port(), now()?)?
                    .clone(),
            )
        })?;
        let addresses = tokio::select! {
            result = timeout(self.config.dns_timeout(), self.resolver.resolve(&domain, *peer_v4.ip())) => result.map_err(|_| ServiceError::Timeout)??,
            () = cancel.cancelled() => return Ok(()),
        };
        let connect = async {
            let mut last_error = ServiceError::NoAddress;
            for address in addresses {
                let target = SocketAddrV4::new(address, original.port());
                let socket = TcpSocket::new_v4()?;
                {
                    let options = SockRef::from(&socket);
                    options.bind_device(Some(self.config.wan.device.as_bytes()))?;
                    options.set_mark(self.config.wan.mark)?;
                }
                match socket.connect(target.into()).await {
                    Ok(stream) => return Ok((stream, target)),
                    Err(error) => last_error = error.into(),
                }
            }
            Err(last_error)
        };
        let (mut outgoing, destination) = tokio::select! {
            result = timeout(Duration::from_secs(self.config.limits.connect_timeout_seconds), connect) => result.map_err(|_| ServiceError::Timeout)??,
            () = cancel.cancelled() => return Ok(()),
        };
        // Revalidate after DNS and connection setup: an expired mapping must not admit a new relay.
        tokio::task::block_in_place(|| {
            self.policy
                .lock()
                .map_err(|_| ServiceError::Poisoned)?
                .authorize_tcp(*original.ip(), original.port(), now()?)?;
            Ok::<_, ServiceError>(())
        })?;
        self.status.insert(ConnectionStatus {
            id: id.clone(),
            domain,
            client: peer,
            destination,
            started_at: now()?,
        })?;
        let result = tokio::select! {
            result = timeout(Duration::from_secs(self.config.limits.connection_lifetime_seconds), copy_bidirectional(&mut incoming, &mut outgoing)) => match result {
                Ok(result) => result.map_err(ServiceError::from), Err(_) => Err(ServiceError::Timeout),
            },
            () = cancel.cancelled() => Err(ServiceError::Cancelled),
        };
        self.status.finish(&id, result.as_ref().ok().copied())?;
        match result {
            Err(ServiceError::Cancelled) => Ok(()),
            other => other.map(|_| ()),
        }
    }
}
