//! Bounded TCP sessions for the IPv6-to-IPv4 adapter. Callers own packet admission and routing.

use std::{
    collections::{BTreeMap, VecDeque},
    io,
    net::{SocketAddrV4, SocketAddrV6},
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};

use serde::Serialize;
use thiserror::Error;
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::{TcpSocket, TcpStream},
    task::{AbortHandle, Id, JoinSet},
    time::{Instant, timeout},
};
use tokio_util::sync::CancellationToken;
use tunnel_detour_core::InboundId;

/// Requested accept backlog, separate from the admitted-session capacity.
pub const RELAY_LISTEN_BACKLOG: i32 = 32;
/// Extra ingress sockets awaiting a backend slot; no target connection is opened yet.
pub const RELAY_PENDING_LIMIT: usize = 32;
/// A full backend pool may delay ingress for this long, then closes it.
pub const RELAY_ADMISSION_WAIT: Duration = Duration::from_millis(250);

#[derive(Debug, Error)]
pub enum RelayError {
    #[error("relay limits or LAN device are invalid")]
    Configuration,
    #[error("relay connection capacity is exhausted")]
    Capacity,
    #[error("relay admission has stopped")]
    Stopped,
    #[error("relay I/O failed")]
    Io(#[from] io::Error),
    #[error(transparent)]
    Ingress(#[from] crate::RelayIngressError),
    #[error("the accepted connection belongs to another publication generation")]
    IdentityMismatch,
    #[error("relay connection identifiers are exhausted")]
    Identifiers,
    #[error("relay task ownership is inconsistent")]
    Ownership,
    #[error("a relay task failed")]
    Task(#[from] tokio::task::JoinError),
    #[error("relay tasks did not terminate within the shutdown deadline")]
    Shutdown,
}

/// Independent limits: active traffic has no total lifetime limit. Inactivity starts
/// after connection establishment, and a half-closed connection can still make progress.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RelayLimits {
    connections: usize,
    connect: Duration,
    idle: Duration,
}

impl RelayLimits {
    /// Requested bytes per TCP send/receive buffer. Linux doubles the accounting
    /// value: two sockets, two buffers and that multiplier share 64 MiB across the
    /// configured session capacity. A single option never requests over 512 KiB.
    /// Listener backlog, queued ingress, protocol bookkeeping and userspace are additional.
    pub fn socket_buffer_bytes(&self) -> usize {
        // The private constructor guarantees a nonzero capacity of at most 256.
        (64 * 1024 * 1024 / self.connections / 8).min(512 * 1024)
    }

    /// Cap TCP buffers on a listener or session socket, disabling receive autotuning.
    /// Configure listeners before the handshake so unaccepted connections inherit
    /// the cap. Platform failures or a larger effective cap are errors.
    pub fn configure_socket<T: std::os::fd::AsFd>(&self, socket: &T) -> io::Result<()> {
        let socket = socket2::SockRef::from(socket);
        let bytes = self.socket_buffer_bytes();
        socket.set_recv_buffer_size(bytes)?;
        socket.set_send_buffer_size(bytes)?;
        if socket.recv_buffer_size()? > bytes * 2 || socket.send_buffer_size()? > bytes * 2 {
            return Err(io::Error::other(
                "kernel TCP buffers exceed the relay budget",
            ));
        }
        Ok(())
    }

    /// Validate router resource bounds without opening a socket.
    pub fn new(connections: usize, connect: Duration, idle: Duration) -> Result<Self, RelayError> {
        if !(1..=256).contains(&connections)
            || connect.is_zero()
            || connect > Duration::from_secs(30)
            || idle < Duration::from_millis(10)
            || idle > Duration::from_secs(86_400)
        {
            return Err(RelayError::Configuration);
        }
        Ok(Self {
            connections,
            connect,
            idle,
        })
    }
}

/// A single fixed destination selected by the policy adapter, never by client bytes.
/// The adapter must validate LAN containment and exclude router/synthetic addresses first.
#[derive(Clone)]
pub struct RelayAdmission {
    pub publication: InboundId,
    pub generation: u16,
    pub target: SocketAddrV4,
    pub lan_device: String,
    /// The fixed return interface, independently selected from the incoming client's scope.
    pub reply_device: String,
}

/// Safe state for authorized local administration; no transferred contents are retained.
#[derive(Clone, Debug, Serialize)]
pub struct RelayConnection {
    pub id: u64,
    pub publication: InboundId,
    pub generation: u16,
    pub client: SocketAddrV6,
    pub target: SocketAddrV4,
    pub connected: bool,
    pub queued: bool,
    pub age_seconds: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RelayOutcome {
    Complete,
    Cancelled,
    ConnectTimeout,
    ConnectFailed,
    IdleTimeout,
    TransferFailed,
    IdentityRejected,
    AdmissionTimeout,
    AdmissionFailed,
}

#[derive(Debug)]
pub struct RelayCompletion {
    pub connection: RelayConnection,
    pub outcome: RelayOutcome,
    /// Counts are available only after a successful complete transfer.
    pub bytes: Option<(u64, u64)>,
    /// Internal cause for diagnostics. Management should display the safe outcome code.
    pub error: Option<RelayError>,
}

struct SessionResult {
    outcome: RelayOutcome,
    bytes: Option<(u64, u64)>,
    error: Option<RelayError>,
}

/// Current policy identity expected for a locally redirected connection. The
/// kernel must independently prove both values before the adapter dials its target.
pub struct RelayCapture {
    pub mark: u32,
    pub public: SocketAddrV6,
}

struct Control {
    connection: RelayConnection,
    started: Instant,
    connected: Arc<AtomicBool>,
    cancellation: CancellationToken,
    abort: AbortHandle,
    waiting_sender: Option<tokio::sync::oneshot::Sender<()>>,
}

struct AdmissionWait {
    ready: tokio::sync::oneshot::Receiver<()>,
    deadline: Instant,
}

impl Control {
    fn snapshot(&self) -> RelayConnection {
        let mut value = self.connection.clone();
        value.connected = self.connected.load(Ordering::Acquire);
        value.age_seconds = self.started.elapsed().as_secs();
        value
    }
}

/// Every admitted session stays owned until its result is observed. The supervising adapter
/// must drive `next_completion` and call `shutdown` before dropping the manager.
pub struct RelaySessions {
    transport: Option<crate::transport_worker::TransportWorker>,
    limits: RelayLimits,
    next_id: u64,
    stopped: bool,
    controls: BTreeMap<u64, Control>,
    jobs: JoinSet<SessionResult>,
    pending: VecDeque<u64>,
}

impl RelaySessions {
    /// Isolate each admitted transport using this executable's internal worker
    /// entrypoint. The controller must be root; workers drop to the platform's
    /// non-root nobody account after entering an empty private root directory.
    /// Call `transport_worker_entrypoint` before any executable startup work.
    ///
    /// # Errors
    /// Refuses missing/unsafe platform identities or unavailable private storage.
    pub fn with_isolated_transport(self) -> io::Result<Self> {
        Ok(self.with_transport(crate::transport_worker::TransportWorker::new()?))
    }

    pub fn new(limits: RelayLimits) -> Self {
        Self {
            transport: None,
            limits,
            next_id: 1,
            stopped: false,
            controls: BTreeMap::new(),
            jobs: JoinSet::new(),
            pending: VecDeque::new(),
        }
    }

    pub(crate) fn with_transport(
        mut self,
        transport: crate::transport_worker::TransportWorker,
    ) -> Self {
        self.transport = Some(transport);
        self
    }

    /// Admit an already-authorized IPv6 connection. Exhaustion drops it without spawning
    /// work. No DNS lookup, alternate route, reconnect or application-header injection occurs.
    pub fn admit(
        &mut self,
        incoming: TcpStream,
        admission: RelayAdmission,
    ) -> Result<u64, RelayError> {
        self.admit_inner(incoming, admission, None, false)
    }

    /// Own verification as part of the session task, so management ticks cannot drop
    /// a connection while its kernel lookup is pending. No LAN dial precedes proof.
    pub fn admit_captured(
        &mut self,
        incoming: TcpStream,
        admission: RelayAdmission,
        capture: RelayCapture,
    ) -> Result<u64, RelayError> {
        self.admit_inner(incoming, admission, Some(capture), false)
    }

    /// Admit, or wait up to 250 ms in a FIFO of at most 32 extra ingress sockets.
    /// Drive `next_completion` to promote work and observe its outcomes. Deadline
    /// closure is independent of that polling. Generation retirement/shutdown cancels
    /// and observes waiting jobs without opening their backend connection.
    ///
    /// # Errors
    /// Returns the same validation/I/O errors as `admit`, or `Capacity` if the queue is full.
    pub fn enqueue(
        &mut self,
        incoming: TcpStream,
        admission: RelayAdmission,
    ) -> Result<u64, RelayError> {
        self.admit_inner(incoming, admission, None, true)
    }

    /// Queue an authorized redirect without bypassing its exact kernel proof on promotion.
    ///
    /// # Errors
    /// Rejects invalid capture generations, unsafe socket settings, and a full queue.
    pub fn enqueue_captured(
        &mut self,
        incoming: TcpStream,
        admission: RelayAdmission,
        capture: RelayCapture,
    ) -> Result<u64, RelayError> {
        self.admit_inner(incoming, admission, Some(capture), true)
    }

    fn admit_inner(
        &mut self,
        incoming: TcpStream,
        admission: RelayAdmission,
        capture: Option<RelayCapture>,
        allow_queue: bool,
    ) -> Result<u64, RelayError> {
        // Rejected, cancelled and panicking jobs must discard queued bytes immediately.
        // Successful sessions explicitly release this abort policy after transfer/drain.
        socket2::SockRef::from(&incoming).set_linger(Some(Duration::ZERO))?;
        self.limits.configure_socket(&incoming)?;
        if capture.as_ref().is_some_and(|capture| {
            capture.mark & 0xffff0000 == 0
                || capture.mark & 0xffff != u32::from(admission.generation)
        }) {
            return Err(RelayError::Configuration);
        }
        if [&admission.lan_device, &admission.reply_device]
            .iter()
            .any(|device| !crate::config::valid_device(device))
        {
            return Err(RelayError::Configuration);
        }
        // This constraint also survives FD closure and late TCP control packets, so a
        // disappearing conntrack entry or policy route cannot select WireGuard instead.
        let socket = socket2::SockRef::from(&incoming);
        if socket.device()?.as_deref() != Some(admission.reply_device.as_bytes()) {
            // An already-correct binding needs no reassignment, which would require
            // additional privileges even when its value is unchanged.
            socket.bind_device(Some(admission.reply_device.as_bytes()))?;
        }
        if self.stopped {
            return Err(RelayError::Stopped);
        }
        if admission.generation == 0 || admission.target.port() == 0 {
            return Err(RelayError::Configuration);
        }
        let std::net::SocketAddr::V6(client) = incoming.peer_addr()? else {
            return Err(RelayError::Configuration);
        };
        if client.ip().to_ipv4_mapped().is_some() {
            return Err(RelayError::Configuration);
        }
        incoming.set_nodelay(false)?;
        let active = self
            .controls
            .values()
            .filter(|control| !control.connection.queued)
            .count();
        let waiting = active >= self.limits.connections || !self.pending.is_empty();
        let queued = self
            .controls
            .values()
            .filter(|control| control.connection.queued)
            .count();
        if waiting && (!allow_queue || queued >= RELAY_PENDING_LIMIT) {
            return Err(RelayError::Capacity);
        }
        let id = self.next_id;
        self.next_id = id.checked_add(1).ok_or(RelayError::Identifiers)?;
        let started = Instant::now();
        let (waiting_sender, wait) = if waiting {
            let (sender, ready) = tokio::sync::oneshot::channel();
            (
                Some(sender),
                Some(AdmissionWait {
                    ready,
                    deadline: started + RELAY_ADMISSION_WAIT,
                }),
            )
        } else {
            (None, None)
        };
        let connected = Arc::new(AtomicBool::new(false));
        let cancellation = CancellationToken::new();
        let connection = RelayConnection {
            id,
            publication: admission.publication.clone(),
            generation: admission.generation,
            client,
            target: admission.target,
            connected: false,
            queued: waiting,
            age_seconds: 0,
        };
        let abort = self.jobs.spawn(session(
            incoming,
            admission,
            (self.limits, self.transport.clone()),
            connected.clone(),
            cancellation.clone(),
            capture,
            wait,
        ));
        self.controls.insert(
            id,
            Control {
                connection,
                started,
                connected,
                cancellation,
                abort,
                waiting_sender,
            },
        );
        if waiting {
            self.pending.push_back(id);
        }
        Ok(id)
    }

    pub fn connections(&self) -> Vec<RelayConnection> {
        self.controls.values().map(Control::snapshot).collect()
    }

    fn observe(
        &mut self,
        result: Result<(Id, SessionResult), tokio::task::JoinError>,
    ) -> Result<RelayCompletion, RelayError> {
        let task = match &result {
            Ok((id, _)) => *id,
            Err(error) => error.id(),
        };
        let id = self
            .controls
            .iter()
            .find_map(|(id, control)| (control.abort.id() == task).then_some(*id))
            .ok_or(RelayError::Ownership)?;
        let control = self.controls.remove(&id).ok_or(RelayError::Ownership)?;
        self.pending.retain(|pending| *pending != id);
        let result = match result {
            Ok((_, result)) => result,
            Err(error) if error.is_cancelled() => SessionResult {
                outcome: RelayOutcome::Cancelled,
                bytes: None,
                error: None,
            },
            Err(error) => return Err(RelayError::Task(error)),
        };
        Ok(RelayCompletion {
            connection: control.snapshot(),
            outcome: result.outcome,
            bytes: result.bytes,
            error: result.error,
        })
    }

    /// Cancellation safe for a supervising `select!`. With no jobs it stays pending.
    pub async fn next_completion(&mut self) -> Result<RelayCompletion, RelayError> {
        self.promote_pending()?;
        match self.jobs.join_next_with_id().await {
            Some(result) => self.observe(result),
            None => std::future::pending().await,
        }
    }

    fn promote_pending(&mut self) -> Result<(), RelayError> {
        if self.stopped {
            return Ok(());
        }
        let mut active = self
            .controls
            .values()
            .filter(|control| !control.connection.queued)
            .count();
        while active < self.limits.connections {
            let Some(id) = self.pending.pop_front() else {
                break;
            };
            let control = self.controls.get_mut(&id).ok_or(RelayError::Ownership)?;
            let sender = control.waiting_sender.take().ok_or(RelayError::Ownership)?;
            if control.cancellation.is_cancelled() {
                drop(sender);
                continue;
            }
            // Expired jobs have already closed their socket, even while the controller
            // was busy. A failed send does not consume a backend slot.
            if sender.send(()).is_ok() {
                control.connection.queued = false;
                active += 1;
            }
        }
        Ok(())
    }

    /// Cancel changed/disabled generations and observe their completion while unaffected
    /// sessions continue. A bounded abort fallback is observed as well, never detached.
    pub async fn retain(&mut self, retained: &BTreeMap<InboundId, u16>) -> Result<(), RelayError> {
        let retired: Vec<_> = self
            .controls
            .iter()
            .filter_map(|(id, control)| {
                (retained.get(&control.connection.publication)
                    != Some(&control.connection.generation))
                .then_some(*id)
            })
            .collect();
        for id in &retired {
            if let Some(control) = self.controls.get(id) {
                control.cancellation.cancel();
            }
        }
        let mut failure = None;
        let graceful = timeout(Duration::from_secs(5), async {
            while retired.iter().any(|id| self.controls.contains_key(id)) {
                if let Err(error) = self.next_completion().await {
                    failure.get_or_insert(error);
                }
            }
        })
        .await;
        if graceful.is_err() {
            for id in &retired {
                if let Some(control) = self.controls.get(id) {
                    control.abort.abort();
                }
            }
            timeout(Duration::from_secs(2), async {
                while retired.iter().any(|id| self.controls.contains_key(id)) {
                    if let Err(error) = self.next_completion().await {
                        failure.get_or_insert(error);
                    }
                }
            })
            .await
            .map_err(|_| RelayError::Shutdown)?;
        }
        match failure {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    pub async fn shutdown(&mut self) -> Result<(), RelayError> {
        self.stop_admission();
        self.retain(&BTreeMap::new()).await
    }

    /// Stop admission and signal every job immediately. The owner must still await
    /// `shutdown` to observe completion, even if closing the kernel guard also fails.
    pub fn stop_admission(&mut self) {
        self.stopped = true;
        self.pending.clear();
        for control in self.controls.values() {
            control.cancellation.cancel();
        }
    }
}

// Count actual I/O progress with a monotonic clock. EOF, readiness and empty writes do
// not reset inactivity. Fixed-size transfer buffers provide pressure back to the sender.
struct IdleWatch {
    epoch: Instant,
    monotonic_epoch: u64,
    timeout_nanoseconds: u64,
    deadline: AtomicU64,
}

fn monotonic_nanoseconds() -> io::Result<u64> {
    let now = rustix::time::clock_gettime(rustix::time::ClockId::Monotonic);
    u64::try_from(now.tv_sec)
        .ok()
        .and_then(|seconds| seconds.checked_mul(1_000_000_000))
        .and_then(|seconds| seconds.checked_add(u64::try_from(now.tv_nsec).ok()?))
        .ok_or_else(|| io::Error::other("invalid monotonic transport clock"))
}

impl IdleWatch {
    fn new(timeout: Duration, existing_deadline: Option<u64>) -> io::Result<Arc<Self>> {
        // Pair clocks conservatively: creating a report never extends its
        // deadline, and consuming it never grants the IPC/scheduling delay again.
        let (epoch, monotonic_epoch) = if existing_deadline.is_some() {
            let epoch = Instant::now();
            (epoch, monotonic_nanoseconds()?)
        } else {
            let monotonic_epoch = monotonic_nanoseconds()?;
            (Instant::now(), monotonic_epoch)
        };
        let timeout_nanoseconds = u64::try_from(timeout.as_nanos()).map_err(io::Error::other)?;
        let upper = monotonic_epoch
            .checked_add(timeout_nanoseconds)
            .ok_or_else(|| io::Error::other("transport deadline overflow"))?;
        let deadline = existing_deadline.unwrap_or(upper);
        if deadline > upper {
            return Err(io::Error::other("invalid transport inactivity deadline"));
        }
        Ok(Arc::new(Self {
            epoch,
            monotonic_epoch,
            timeout_nanoseconds,
            deadline: AtomicU64::new(deadline.saturating_sub(monotonic_epoch)),
        }))
    }

    fn progressed(&self) {
        self.deadline.store(
            u64::try_from(self.epoch.elapsed().as_nanos())
                .unwrap_or(u64::MAX)
                .saturating_add(self.timeout_nanoseconds),
            Ordering::Relaxed,
        );
    }

    fn absolute_deadline(&self) -> io::Result<u64> {
        self.monotonic_epoch
            .checked_add(self.deadline.load(Ordering::Relaxed))
            .ok_or_else(|| io::Error::other("transport deadline overflow"))
    }

    async fn expired(&self) {
        loop {
            let deadline = self.deadline.load(Ordering::Relaxed);
            let remaining = Duration::from_nanos(deadline).saturating_sub(self.epoch.elapsed());
            tokio::time::sleep(remaining).await;
            if self.deadline.load(Ordering::Relaxed) == deadline {
                return;
            }
        }
    }
}

struct ProgressIo<T> {
    inner: T,
    idle: Arc<IdleWatch>,
}
impl<T: AsyncRead + Unpin> AsyncRead for ProgressIo<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let before = buffer.filled().len();
        let result = Pin::new(&mut this.inner).poll_read(cx, buffer);
        if matches!(result, Poll::Ready(Ok(()))) && buffer.filled().len() > before {
            this.idle.progressed();
        }
        result
    }
}
impl<T: AsyncWrite + Unpin> AsyncWrite for ProgressIo<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let result = Pin::new(&mut this.inner).poll_write(cx, bytes);
        if matches!(result, Poll::Ready(Ok(count)) if count > 0) {
            this.idle.progressed();
        }
        result
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

async fn session(
    incoming: TcpStream,
    admission: RelayAdmission,
    transport: (
        RelayLimits,
        Option<crate::transport_worker::TransportWorker>,
    ),
    connected: Arc<AtomicBool>,
    cancellation: CancellationToken,
    capture: Option<RelayCapture>,
    wait: Option<AdmissionWait>,
) -> SessionResult {
    let (limits, transport) = transport;
    if let Some(wait) = wait {
        tokio::select! {
            biased;
            _=cancellation.cancelled()=>return SessionResult{outcome:RelayOutcome::Cancelled,bytes:None,error:None},
            _=tokio::time::sleep_until(wait.deadline)=>return SessionResult{outcome:RelayOutcome::AdmissionTimeout,bytes:None,error:None},
            result=wait.ready=>if result.is_err() {
                return SessionResult{outcome:RelayOutcome::AdmissionFailed,bytes:None,error:Some(RelayError::Ownership)};
            }
        }
    }
    if let Some(capture) = capture {
        let proof = tokio::select! {
            biased;
            _ = cancellation.cancelled() => return SessionResult { outcome: RelayOutcome::Cancelled, bytes: None, error: None },
            result = crate::inspect_relay_ingress(&incoming) => result,
        };
        match proof {
            Ok(identity)
                if identity.mark == capture.mark
                    && identity.original_destination == capture.public => {}
            Ok(_) => {
                return SessionResult {
                    outcome: RelayOutcome::IdentityRejected,
                    bytes: None,
                    error: Some(RelayError::IdentityMismatch),
                };
            }
            Err(error) => {
                return SessionResult {
                    outcome: RelayOutcome::IdentityRejected,
                    bytes: None,
                    error: Some(error.into()),
                };
            }
        }
    }
    let connect = async {
        let socket = TcpSocket::new_v4()?;
        limits.configure_socket(&socket)?;
        socket.bind_device(Some(admission.lan_device.as_bytes()))?;
        socket2::SockRef::from(&socket).set_linger(Some(Duration::ZERO))?;
        // Keep TCP defaults explicit for the matched benchmark and opaque application data.
        socket.set_nodelay(false)?;
        socket.connect(admission.target.into()).await
    };
    let outgoing = tokio::select! {
        biased;
        _ = cancellation.cancelled() => return SessionResult { outcome: RelayOutcome::Cancelled, bytes: None, error: None },
        result = timeout(limits.connect, connect) => match result {
            Ok(Ok(stream)) => stream,
            Ok(Err(error)) => return SessionResult { outcome: RelayOutcome::ConnectFailed, bytes: None, error: Some(error.into()) },
            Err(_) => return SessionResult { outcome: RelayOutcome::ConnectTimeout, bytes: None, error: None },
        }
    };
    connected.store(true, Ordering::Release);
    if let Some(transport) = transport {
        return match transport
            .transfer(
                incoming,
                outgoing,
                crate::transport_worker::Mode::Relay(limits.idle),
                cancellation,
                None,
            )
            .await
        {
            Ok(crate::transport_worker::Outcome::Complete(bytes)) => SessionResult {
                outcome: RelayOutcome::Complete,
                bytes: Some(bytes),
                error: None,
            },
            Ok(crate::transport_worker::Outcome::Idle) => SessionResult {
                outcome: RelayOutcome::IdleTimeout,
                bytes: None,
                error: None,
            },
            Ok(crate::transport_worker::Outcome::Cancelled) => SessionResult {
                outcome: RelayOutcome::Cancelled,
                bytes: None,
                error: None,
            },
            Ok(crate::transport_worker::Outcome::Deadline) => SessionResult {
                outcome: RelayOutcome::TransferFailed,
                bytes: None,
                error: Some(io::Error::other("unexpected relay lifetime limit").into()),
            },
            Err(error) => SessionResult {
                outcome: RelayOutcome::TransferFailed,
                bytes: None,
                error: Some(error.into()),
            },
        };
    }
    tokio::select! {
        biased;
        _ = cancellation.cancelled() => SessionResult { outcome: RelayOutcome::Cancelled, bytes: None, error: None },
        result = transfer_with_idle(incoming, outgoing, limits.idle) => match result {
            Ok(Some(bytes)) => SessionResult { outcome: RelayOutcome::Complete, bytes: Some(bytes), error: None },
            Ok(None) => SessionResult { outcome: RelayOutcome::IdleTimeout, bytes: None, error: None },
            Err(error) => SessionResult { outcome: RelayOutcome::TransferFailed, bytes: None, error: Some(error.into()) },
        },
    }
}

pub(crate) async fn transfer_with_idle(
    incoming: TcpStream,
    outgoing: TcpStream,
    idle_timeout: Duration,
) -> io::Result<Option<(u64, u64)>> {
    Ok(
        transfer_with_completion(incoming, outgoing, idle_timeout, Finish::Acknowledge)
            .await?
            .map(|completed| completed.bytes),
    )
}

pub(crate) struct Copied {
    pub bytes: (u64, u64),
    /// CLOCK_MONOTONIC deadline, shared by the worker and its controller.
    pub idle_deadline: u64,
}

#[derive(Eq, PartialEq)]
enum Finish {
    Copy,
    Acknowledge,
}

/// The isolated copier cannot query kernel queues or change socket options.
pub(crate) async fn copy_with_idle(
    incoming: TcpStream,
    outgoing: TcpStream,
    idle_timeout: Duration,
) -> io::Result<Option<Copied>> {
    transfer_with_completion(incoming, outgoing, idle_timeout, Finish::Copy).await
}

async fn transfer_with_completion(
    incoming: TcpStream,
    outgoing: TcpStream,
    idle_timeout: Duration,
    finish: Finish,
) -> io::Result<Option<Copied>> {
    let idle = IdleWatch::new(idle_timeout, None)?;
    let mut incoming = ProgressIo {
        inner: incoming,
        idle: idle.clone(),
    };
    let mut outgoing = ProgressIo {
        inner: outgoing,
        idle: idle.clone(),
    };
    let transfer = async {
        let bytes = crate::transfer_tcp(&mut incoming, &mut outgoing).await?;
        if finish == Finish::Acknowledge {
            crate::tcp_close::drain(&incoming.inner, &outgoing.inner, || idle.progressed()).await?;
        }
        Ok::<_, io::Error>(Copied {
            bytes,
            idle_deadline: idle.absolute_deadline()?,
        })
    };
    let result = tokio::select! {
        biased;
        _ = idle.expired() => Ok(None),
        result = transfer => result.map(Some),
    };
    if finish == Finish::Acknowledge && matches!(result, Ok(Some(_))) {
        let release = socket2::SockRef::from(&incoming.inner)
            .set_linger(None)
            .and_then(|()| socket2::SockRef::from(&outgoing.inner).set_linger(None));
        release?;
    }
    result
}

/// Retain the slot and sockets in the controller until their queued data and FIN
/// are acknowledged. The worker's absolute deadline prevents reporting, process
/// exit or controller scheduling delays from resetting inactivity.
pub(crate) async fn acknowledge_copied(
    incoming: &TcpStream,
    outgoing: &TcpStream,
    idle_timeout: Duration,
    deadline: u64,
) -> io::Result<bool> {
    let idle = IdleWatch::new(idle_timeout, Some(deadline))?;
    if idle.deadline.load(Ordering::Relaxed) == 0 {
        return Ok(false);
    }
    tokio::select! {
        biased;
        _ = idle.expired() => Ok(false),
        result = crate::tcp_close::drain(incoming, outgoing, || idle.progressed()) => result.map(|()| true),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn r072_importing_an_idle_deadline_does_not_renew_expired_time_or_accept_unbounded_time()
    -> Result<(), Box<dyn std::error::Error>> {
        let timeout = Duration::from_secs(1);
        let expired = IdleWatch::new(timeout, Some(0))?;
        tokio::time::timeout(Duration::from_millis(100), expired.expired()).await?;
        assert!(
            IdleWatch::new(timeout, Some(u64::MAX)).is_err(),
            "a worker report must not exceed the configured inactivity budget"
        );
        Ok(())
    }
}
