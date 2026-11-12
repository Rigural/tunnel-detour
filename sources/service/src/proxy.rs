use std::{
    future::Future,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    sync::{Arc, Mutex},
    time::Duration,
};

use socket2::SockRef;
use tokio::{
    net::{TcpSocket, TcpStream},
    time::{Instant, sleep_until, timeout},
};
use tokio_util::sync::CancellationToken;
use tunnel_detour_core::ExceptionPolicy;

use crate::{
    ConnectionStatus, ServiceConfig, ServiceError, StatusHandle, runtime::now,
    upstream::RealResolver,
};

pub(crate) struct ProxyHandler {
    pub transport: crate::transport_worker::TransportWorker,
    pub config: Arc<ServiceConfig>,
    pub policy: Arc<Mutex<ExceptionPolicy>>,
    pub resolver: RealResolver,
    pub status: StatusHandle,
}

type WanDial<'a> =
    Pin<Box<dyn Future<Output = Result<(TcpStream, SocketAddr), ServiceError>> + Send + 'a>>;

async fn dial_result(
    slot: &mut Option<WanDial<'_>>,
) -> Result<(TcpStream, SocketAddr), ServiceError> {
    match slot {
        Some(dial) => dial.await,
        None => std::future::pending().await,
    }
}

impl ProxyHandler {
    pub async fn serve(
        &self,
        id: String,
        incoming: TcpStream,
        peer: SocketAddr,
        cancel: CancellationToken,
    ) -> Result<(), ServiceError> {
        if !self.config.allows_client(peer.ip()) {
            return Err(ServiceError::Unauthorized);
        }
        let socket = SockRef::from(&incoming);
        let original = if peer.is_ipv6() {
            socket.original_dst_v6()?
        } else {
            socket.original_dst_v4()?
        }
        .as_socket()
        .ok_or(ServiceError::Protocol)?;
        let domain = tokio::task::block_in_place(|| {
            Ok::<_, ServiceError>(
                self.policy
                    .lock()
                    .map_err(|_| ServiceError::Poisoned)?
                    .authorize_tcp(original.ip(), original.port(), now()?)?
                    .clone(),
            )
        })?;
        let addresses = tokio::select! {
            result = timeout(self.config.dns_timeout(), self.resolver.resolve(&domain, peer.ip(), original.ip())) => result.map_err(|_| ServiceError::Timeout)??,
            () = cancel.cancelled() => return Ok(()),
        };
        let (outgoing, destination) = tokio::select! {
            result = timeout(Duration::from_secs(self.config.limits.connect_timeout_seconds), self.connect(addresses, original.port())) => result.map_err(|_| ServiceError::Timeout)??,
            () = cancel.cancelled() => return Ok(()),
        };
        // Revalidate after DNS and connection setup: an expired mapping must not admit a new relay.
        tokio::task::block_in_place(|| {
            self.policy
                .lock()
                .map_err(|_| ServiceError::Poisoned)?
                .authorize_tcp(original.ip(), original.port(), now()?)?;
            Ok::<_, ServiceError>(())
        })?;
        self.status.insert(ConnectionStatus {
            id: id.clone(),
            domain,
            client: peer,
            destination,
            started_at: now()?,
        })?;
        let result = match self
            .transport
            .transfer(
                incoming,
                outgoing,
                crate::transport_worker::Mode::Proxy,
                cancel,
                Some(Duration::from_secs(
                    self.config.limits.connection_lifetime_seconds,
                )),
            )
            .await
        {
            Ok(crate::transport_worker::Outcome::Complete(bytes)) => Ok(bytes),
            Ok(crate::transport_worker::Outcome::Cancelled) => Err(ServiceError::Cancelled),
            Ok(_) => Err(ServiceError::Timeout),
            Err(error) => Err(ServiceError::Io(error)),
        };
        self.status.finish(&id, result.as_ref().ok().copied())?;
        match result {
            Err(ServiceError::Cancelled) => Ok(()),
            other => other.map(|_| ()),
        }
    }

    /// Two owned futures stagger attempts by 250 ms. No task is detached, and
    /// dropping this future cancels both sockets. Per-attempt and caller-wide
    /// deadlines bound blackholes without serializing both address families.
    async fn connect(
        &self,
        addresses: Vec<IpAddr>,
        port: u16,
    ) -> Result<(TcpStream, SocketAddr), ServiceError> {
        self.resolver.snapshot()?;
        let mut targets = addresses
            .into_iter()
            .map(|address| SocketAddr::new(address, port));
        let attempt = |target| -> WanDial<'_> {
            Box::pin(async move {
                timeout(
                    Duration::from_secs(self.config.limits.connect_timeout_seconds.min(3)),
                    self.dial(target),
                )
                .await
                .map_err(|_| ServiceError::Timeout)?
            })
        };
        let mut first = None;
        let mut second = None;
        let mut next_start = Instant::now();
        let mut last_error = ServiceError::NoAddress;
        loop {
            if first.is_none() && second.is_none() {
                let Some(target) = targets.next() else {
                    return Err(last_error);
                };
                first = Some(attempt(target));
                next_start = Instant::now() + Duration::from_millis(250);
            }
            let can_start = targets.len() > 0 && (first.is_none() || second.is_none());
            let (slot, result) = tokio::select! {
                result = dial_result(&mut first) => (0, result),
                result = dial_result(&mut second) => (1, result),
                _ = sleep_until(next_start), if can_start => {
                    let target = targets.next().ok_or(ServiceError::Protocol)?;
                    if first.is_none() { first = Some(attempt(target)); } else { second = Some(attempt(target)); }
                    next_start = Instant::now() + Duration::from_millis(250);
                    continue;
                },
            };
            if slot == 0 {
                first = None;
            } else {
                second = None;
            }
            match result {
                Ok(stream) => return Ok(stream),
                Err(error) => {
                    last_error = error;
                    next_start = Instant::now();
                }
            }
        }
    }

    async fn dial(&self, target: SocketAddr) -> Result<(TcpStream, SocketAddr), ServiceError> {
        let socket = if target.is_ipv6() {
            TcpSocket::new_v6()?
        } else {
            TcpSocket::new_v4()?
        };
        let device = if target.is_ipv6() {
            let settings = self
                .config
                .ipv6
                .as_ref()
                .ok_or(ServiceError::ForbiddenTarget)?;
            socket.bind(SocketAddr::new(settings.wan.source.into(), 0))?;
            &settings.wan.device
        } else {
            &self.config.wan.device
        };
        let options = SockRef::from(&socket);
        options.bind_device(Some(device.as_bytes()))?;
        options.set_mark(self.config.wan.mark)?;
        Ok((socket.connect(target).await?, target))
    }
}
