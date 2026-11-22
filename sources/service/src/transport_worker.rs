//! Opaque TCP transport in a separate, unprivileged process. Only two already
//! authorized connected sockets cross this boundary; no policy or secrets do.

mod syscalls;

use std::{
    fs,
    io::{self, Read, Write},
    net::Shutdown,
    os::{
        fd::{AsFd, OwnedFd},
        unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, PermissionsExt},
    },
    path::{Path, PathBuf},
    process::Stdio,
    sync::{Arc, Mutex, MutexGuard},
    time::{Duration, Instant},
};
use tokio::{io::AsyncReadExt, net::TcpStream, process::Command, time::timeout};
use tokio_util::sync::CancellationToken;

#[derive(Clone)]
pub(crate) struct TransportWorker {
    root: Arc<PathBuf>,
    executable: PathBuf,
    uid: u32,
    gid: u32,
    health: Arc<Mutex<WorkerHealth>>,
}

const ROOT: &str = "/var/run/tunnel-detour/transport";
const REPORT_BYTES: usize = 9;
const HEALTH_LOG_INTERVAL: Duration = Duration::from_secs(30);
pub(crate) const INITIALIZATION_FAILED: &str = "transport_worker_failed";

#[derive(Clone, Copy)]
#[repr(u8)]
enum WorkerStage {
    Arguments = 1,
    Root,
    Parent,
    InheritedDescriptors,
    ParentWatch,
    Filesystem,
    Credentials,
    Limits,
    Sandbox,
    Runtime,
    Sockets,
    Spawn,
    Report,
}

impl WorkerStage {
    const fn label(self) -> &'static str {
        match self {
            Self::Arguments => "arguments",
            Self::Root => "worker_root",
            Self::Parent => "controller_identity",
            Self::InheritedDescriptors => "inherited_descriptors",
            Self::ParentWatch => "controller_watch",
            Self::Filesystem => "filesystem",
            Self::Credentials => "credentials",
            Self::Limits => "resource_limits",
            Self::Sandbox => "sandbox",
            Self::Runtime => "runtime",
            Self::Sockets => "connected_sockets",
            Self::Spawn => "spawn",
            Self::Report => "worker_report",
        }
    }

    fn decode(byte: u8) -> Option<Self> {
        [
            Self::Arguments,
            Self::Root,
            Self::Parent,
            Self::InheritedDescriptors,
            Self::ParentWatch,
            Self::Filesystem,
            Self::Credentials,
            Self::Limits,
            Self::Sandbox,
            Self::Runtime,
            Self::Sockets,
        ]
        .into_iter()
        .find(|stage| byte == *stage as u8)
    }
}

#[derive(Clone, Copy)]
#[repr(u8)]
enum DescriptorReason {
    OpenDirectory = 1,
    ReadEntry,
    InvalidIndex,
    Limit,
    Recheck,
    Present,
}

impl DescriptorReason {
    const fn label(self) -> &'static str {
        match self {
            Self::OpenDirectory => "open_fd_directory",
            Self::ReadEntry => "read_fd_entry",
            Self::InvalidIndex => "invalid_fd_entry",
            Self::Limit => "fd_limit",
            Self::Recheck => "recheck_fd_entry",
            Self::Present => "unexpected_descriptor",
        }
    }

    fn decode(byte: u8) -> Option<Self> {
        [
            Self::OpenDirectory,
            Self::ReadEntry,
            Self::InvalidIndex,
            Self::Limit,
            Self::Recheck,
            Self::Present,
        ]
        .into_iter()
        .find(|reason| *reason as u8 == byte)
    }
}

#[derive(Clone, Copy)]
#[repr(u8)]
enum DescriptorKind {
    Socket = 1,
    Pipe,
    Directory,
    File,
    Device,
    Other,
}

impl DescriptorKind {
    fn inspect(path: &Path) -> Option<Self> {
        // Obtain only the file type, never the resolved path or any contents.
        let kind = fs::metadata(path).ok()?.file_type();
        Some(if kind.is_socket() {
            Self::Socket
        } else if kind.is_fifo() {
            Self::Pipe
        } else if kind.is_dir() {
            Self::Directory
        } else if kind.is_file() {
            Self::File
        } else if kind.is_char_device() || kind.is_block_device() {
            Self::Device
        } else {
            Self::Other
        })
    }

    const fn label(self) -> &'static str {
        match self {
            Self::Socket => "socket",
            Self::Pipe => "pipe",
            Self::Directory => "directory",
            Self::File => "file",
            Self::Device => "device",
            Self::Other => "other",
        }
    }

    fn decode(byte: u8) -> Option<Self> {
        [
            Self::Socket,
            Self::Pipe,
            Self::Directory,
            Self::File,
            Self::Device,
            Self::Other,
        ]
        .into_iter()
        .find(|kind| *kind as u8 == byte)
    }
}

#[derive(Clone, Copy)]
struct DescriptorDiagnostic {
    reason: DescriptorReason,
    kind: Option<DescriptorKind>,
    close_on_exec: Option<bool>,
}

fn descriptor_close_on_exec(path: &Path) -> Option<bool> {
    let info = Path::new("/proc/self/fdinfo").join(path.file_name()?);
    let mut text = String::new();
    fs::File::open(info)
        .ok()?
        .take(256)
        .read_to_string(&mut text)
        .ok()?;
    let flags = text.lines().find_map(|line| line.strip_prefix("flags:"))?;
    let bits = u32::from_str_radix(flags.trim(), 8).ok()?;
    Some(bits & rustix::fs::OFlags::CLOEXEC.bits() != 0)
}

fn worker_failure_report(
    stage: WorkerStage,
    errno: Option<i32>,
    descriptor: Option<DescriptorDiagnostic>,
) -> [u8; REPORT_BYTES] {
    let [a, b, c, d] = errno.unwrap_or(0).to_le_bytes();
    let reason = descriptor.map_or(0, |detail| detail.reason as u8);
    let kind = descriptor
        .and_then(|detail| detail.kind)
        .map_or(0, |kind| kind as u8);
    let flags = match descriptor.and_then(|detail| detail.close_on_exec) {
        None => 0,
        Some(true) => 1,
        Some(false) => 2,
    };
    [3, stage as u8, a, b, c, d, reason, kind, flags]
}

fn read_worker_failure(report: &[u8]) -> Option<(WorkerStage, i32, Option<DescriptorDiagnostic>)> {
    let &[3, stage, a, b, c, d, reason, kind, flags] = report else {
        return None;
    };
    let stage = WorkerStage::decode(stage)?;
    let descriptor = match (stage, reason, kind, flags) {
        (_, 0, 0, 0) => None,
        (WorkerStage::InheritedDescriptors, reason, kind, flags) => {
            let reason = DescriptorReason::decode(reason)?;
            let kind = match (reason, kind) {
                (_, 0) => None,
                (DescriptorReason::Present, kind) => Some(DescriptorKind::decode(kind)?),
                _ => return None,
            };
            let close_on_exec = match (reason, flags) {
                (_, 0) => None,
                (DescriptorReason::Present, 1) => Some(true),
                (DescriptorReason::Present, 2) => Some(false),
                _ => return None,
            };
            Some(DescriptorDiagnostic {
                reason,
                kind,
                close_on_exec,
            })
        }
        _ => return None,
    };
    Some((stage, i32::from_le_bytes([a, b, c, d]), descriptor))
}

#[derive(Default)]
struct WorkerHealth {
    last_failure: Option<Instant>,
    last_warning: Option<Instant>,
}

fn validate_root(root: &Path) -> io::Result<()> {
    let metadata = fs::symlink_metadata(root)?;
    if !root.is_absolute()
        || !metadata.is_dir()
        || metadata.uid() != 0
        || metadata.permissions().mode() & 0o077 != 0
        || fs::read_dir(root)?.next().is_some()
    {
        return Err(denied());
    }
    Ok(())
}

#[derive(Clone, Copy)]
pub(crate) enum Mode {
    Proxy,
    Relay(Duration),
}

pub(crate) enum Outcome {
    Complete,
    Idle,
    Cancelled,
    Deadline,
}

/// A worker whose filesystem and credentials have already been isolated. The
/// process handle observes its controller's entire thread group, without PID reuse.
pub struct PreparedTransportWorker {
    parent: OwnedFd,
    idle: Duration,
}

fn denied() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "transport isolation is unavailable",
    )
}

fn refuse_inherited_descriptors(detail: &mut Option<DescriptorDiagnostic>) -> io::Result<()> {
    // Run before threads and before opening the owned pidfd. Command normally
    // inherits only stdio, but an accidentally non-CLOEXEC secret descriptor in
    // the controller must never become readable through the permitted TCP pair.
    // Finish enumeration first so its own proc directory descriptor is closed.
    let mut set = |reason, kind, close_on_exec| {
        *detail = Some(DescriptorDiagnostic {
            reason,
            kind,
            close_on_exec,
        });
    };
    let mut candidates = Vec::new();
    set(DescriptorReason::OpenDirectory, None, None);
    for entry in fs::read_dir("/proc/self/fd")? {
        set(DescriptorReason::ReadEntry, None, None);
        let entry = entry?;
        set(DescriptorReason::InvalidIndex, None, None);
        let number = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<u32>().ok())
            .ok_or_else(denied)?;
        if number > 2 {
            candidates.push(entry.path());
        }
        if candidates.len() > 32 {
            set(DescriptorReason::Limit, None, None);
            return Err(denied());
        }
    }
    for path in candidates {
        match fs::symlink_metadata(&path) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => {
                set(DescriptorReason::Recheck, None, None);
                return Err(error);
            }
            Ok(_) => {
                set(
                    DescriptorReason::Present,
                    DescriptorKind::inspect(&path),
                    descriptor_close_on_exec(&path),
                );
                return Err(denied());
            }
        }
    }
    *detail = None;
    Ok(())
}

impl TransportWorker {
    pub(crate) fn new() -> io::Result<Self> {
        Self::open(Arc::default())
    }

    /// Revalidate the worker configuration for a new relay policy in the same controller.
    pub(crate) fn reopen(&self) -> io::Result<Self> {
        Self::open(self.health.clone())
    }

    fn open(health: Arc<Mutex<WorkerHealth>>) -> io::Result<Self> {
        if !rustix::process::geteuid().is_root() {
            return Err(denied());
        }
        let mut account = String::new();
        fs::File::open("/etc/passwd")?
            .take(65_537)
            .read_to_string(&mut account)?;
        if account.len() > 65_536 {
            return Err(denied());
        }
        let mut accounts = account.lines().filter(|line| line.starts_with("nobody:"));
        let fields: Vec<_> = accounts.next().ok_or_else(denied)?.split(':').collect();
        if accounts.next().is_some() {
            return Err(denied());
        }
        let uid: u32 = fields
            .get(2)
            .ok_or_else(denied)?
            .parse()
            .map_err(|_| denied())?;
        let gid: u32 = fields
            .get(3)
            .ok_or_else(denied)?
            .parse()
            .map_err(|_| denied())?;
        if [uid, gid].iter().any(|id| *id == 0 || *id == u32::MAX) {
            return Err(denied());
        }
        // Reuse one empty package-owned root across the independent features.
        // Per-controller tempdirs survive SIGKILL and grow on every respawn.
        // This root stays bounded, contains no data and is removed on uninstall.
        let root = PathBuf::from(ROOT);
        let parent = root.parent().ok_or_else(denied)?;
        fs::DirBuilder::new()
            .mode(0o700)
            .recursive(true)
            .create(parent)?;
        let metadata = fs::symlink_metadata(parent)?;
        if !metadata.is_dir() || metadata.uid() != 0 || metadata.permissions().mode() & 0o077 != 0 {
            return Err(denied());
        }
        match fs::DirBuilder::new().mode(0o700).create(&root) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error),
        }
        validate_root(&root)?;
        Ok(Self {
            root: Arc::new(root),
            executable: std::env::current_exe()?,
            uid,
            gid,
            health,
        })
    }

    pub(crate) fn initialization_failed(&self) -> io::Result<bool> {
        Ok(self.worker_health()?.last_failure.is_some())
    }

    fn worker_health(&self) -> io::Result<MutexGuard<'_, WorkerHealth>> {
        self.health
            .lock()
            .map_err(|_| io::Error::other("transport worker health state unavailable"))
    }

    fn report_initialization_failure(
        &self,
        stage: WorkerStage,
        errno: Option<i32>,
        descriptor: Option<DescriptorDiagnostic>,
    ) -> io::Result<()> {
        let mut health = self.worker_health()?;
        let now = Instant::now();
        let was_failed = health.last_failure.replace(now).is_some();
        if was_failed
            || health
                .last_warning
                .is_some_and(|last| now.duration_since(last) < HEALTH_LOG_INTERVAL)
        {
            return Ok(());
        }
        health.last_warning = Some(now);
        drop(health);
        tracing::warn!(
            target: "tunnel_detour::health",
            code = INITIALIZATION_FAILED,
            stage = stage.label(),
            reason = descriptor.map(|detail| detail.reason.label()),
            "isolated TCP transport worker could not start"
        );
        let errno = errno.filter(|code| *code != 0);
        let descriptor_kind = descriptor
            .and_then(|detail| detail.kind)
            .map(DescriptorKind::label);
        let descriptor_close_on_exec = descriptor.and_then(|detail| detail.close_on_exec);
        if errno.is_some() || descriptor_kind.is_some() || descriptor_close_on_exec.is_some() {
            tracing::warn!(
                target: "tunnel_detour::diagnostics",
                errno,
                descriptor_kind,
                descriptor_close_on_exec,
                "transport worker initialization details"
            );
        }
        Ok(())
    }

    fn record_verified_initialization(&self, launched: Instant) -> io::Result<()> {
        let mut health = self.worker_health()?;
        // A long-lived worker launched before the failure does not prove recovery.
        if health.last_failure.is_some_and(|failed| launched > failed) {
            health.last_failure = None;
        }
        Ok(())
    }

    pub(crate) async fn transfer(
        &self,
        incoming: TcpStream,
        outgoing: TcpStream,
        mode: Mode,
        cancel: CancellationToken,
        lifetime: Option<Duration>,
    ) -> io::Result<Outcome> {
        for stream in [&incoming, &outgoing] {
            socket2::SockRef::from(stream).set_linger(Some(Duration::ZERO))?;
        }
        let idle = match mode {
            Mode::Proxy => 0,
            Mode::Relay(idle) => u64::try_from(idle.as_millis()).map_err(|_| denied())?,
        };
        let launched = Instant::now();
        let child = Command::new(&self.executable)
            .args([
                "--transport-worker",
                &self.uid.to_string(),
                &self.gid.to_string(),
                self.root.to_str().ok_or_else(denied)?,
                &std::process::id().to_string(),
                &idle.to_string(),
            ])
            .env_clear()
            .current_dir("/")
            .stdin(Stdio::from(incoming.as_fd().try_clone_to_owned()?))
            .stdout(Stdio::from(outgoing.as_fd().try_clone_to_owned()?))
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn();
        let mut child = match child {
            Ok(child) => child,
            Err(error) => {
                self.report_initialization_failure(WorkerStage::Spawn, error.raw_os_error(), None)?;
                return Err(error);
            }
        };
        let operation = async {
            let stderr = child.stderr.take().ok_or_else(denied)?;
            let mut response = Vec::new();
            stderr
                .take(u64::try_from(REPORT_BYTES + 1).map_err(|_| denied())?)
                .read_to_end(&mut response)
                .await?;
            if response.len() != REPORT_BYTES {
                // A worker killed mid-transfer also leaves no completion
                // report. Without a startup report this is not a refusal.
                return Err(io::Error::other("transport worker failed"));
            }
            let status = timeout(Duration::from_secs(2), child.wait())
                .await
                .map_err(|_| {
                    io::Error::other("transport worker did not finish its completion report")
                })??;
            if response[0] == 3 {
                if let Some((stage, errno, descriptor)) = read_worker_failure(&response) {
                    self.report_initialization_failure(stage, Some(errno), descriptor)?;
                } else {
                    self.report_initialization_failure(WorkerStage::Report, None, None)?;
                }
            }
            if !status.success() {
                return Err(io::Error::other(
                    "transport worker did not complete successfully",
                ));
            }
            // A valid completion, idle timeout or copy failure proves that this
            // worker entered the sandbox and opened both transport directions.
            if matches!(response[0], 0..=2) {
                self.record_verified_initialization(launched)?;
            }
            match response[0] {
                0 => {
                    match mode {
                        Mode::Relay(idle) => {
                            if !crate::relay::acknowledge_copied(
                                &incoming,
                                &outgoing,
                                idle,
                                u64::from_le_bytes(response[1..].try_into().map_err(|_| denied())?),
                            )
                            .await?
                            {
                                return Ok(Outcome::Idle);
                            }
                        }
                        Mode::Proxy => {
                            crate::tcp_close::drain(&incoming, &outgoing, || {}).await?;
                        }
                    }
                    Ok(Outcome::Complete)
                }
                1 => Ok(Outcome::Idle),
                _ => Err(io::Error::other("transport worker I/O failed")),
            }
        };
        let deadline = async {
            match lifetime {
                Some(duration) => tokio::time::sleep(duration).await,
                None => std::future::pending().await,
            }
        };
        let result = tokio::select! {
            biased;
            () = cancel.cancelled() => Ok(Outcome::Cancelled),
            result = operation => result,
            () = deadline => Ok(Outcome::Deadline),
        };
        if matches!(result, Ok(Outcome::Complete)) {
            // The controller retains both sockets through worker exit and ACK
            // drain. Only it may change the abortive policy to a graceful close.
            for stream in [&incoming, &outgoing] {
                socket2::SockRef::from(stream).set_linger(None)?;
            }
        } else {
            // Parent descriptors close both TCP directions even if child termination
            // fails. Await reaping on cancellation, timeout and malformed reports.
            let incoming_closed = socket2::SockRef::from(&incoming).shutdown(Shutdown::Both);
            let outgoing_closed = socket2::SockRef::from(&outgoing).shutdown(Shutdown::Both);
            if child.try_wait()?.is_none() {
                timeout(Duration::from_secs(2), child.kill())
                    .await
                    .map_err(|_| io::Error::other("transport worker did not stop"))??;
            }
            for closed in [incoming_closed, outgoing_closed] {
                if let Err(error) = closed
                    && error.raw_os_error() != Some(rustix::io::Errno::NOTCONN.raw_os_error())
                {
                    return Err(error);
                }
            }
        }
        result
    }
}

/// Enter the transport boundary before creating any runtime threads. Called only
/// by the executable's internal worker branch; never after ordinary startup.
/// Returns the controller lifetime handle and inactivity policy after isolation.
///
/// # Errors
/// Refuses unsafe arguments/storage or unavailable kernel isolation. The caller
/// must exit on failure because process credentials/root may already have changed.
pub fn prepare_transport_worker(
    arguments: &[std::ffi::OsString],
) -> io::Result<PreparedTransportWorker> {
    prepare_worker(arguments, &mut WorkerStage::Arguments, &mut None)
}

fn prepare_worker(
    arguments: &[std::ffi::OsString],
    stage: &mut WorkerStage,
    descriptor: &mut Option<DescriptorDiagnostic>,
) -> io::Result<PreparedTransportWorker> {
    *stage = WorkerStage::Arguments;
    if arguments.len() != 5 || !rustix::process::geteuid().is_root() {
        return Err(denied());
    }
    let parse = |index: usize| -> io::Result<u32> {
        arguments[index]
            .to_str()
            .ok_or_else(denied)?
            .parse()
            .map_err(|_| denied())
    };
    let uid = parse(0)?;
    let gid = parse(1)?;
    let parent = parse(3)?;
    if [uid, gid, parent]
        .iter()
        .any(|id| *id == 0 || *id == u32::MAX)
    {
        return Err(denied());
    }
    let root = PathBuf::from(&arguments[2]);
    let idle: u64 = arguments[4]
        .to_str()
        .ok_or_else(denied)?
        .parse()
        .map_err(|_| denied())?;
    if idle > 86_400_000 {
        return Err(denied());
    }
    let parent = rustix::process::Pid::from_raw(i32::try_from(parent).map_err(|_| denied())?)
        .ok_or_else(denied)?;
    *stage = WorkerStage::Root;
    validate_root(&root)?;
    *stage = WorkerStage::Parent;
    if rustix::process::getppid() != Some(parent) {
        return Err(denied());
    }
    *stage = WorkerStage::InheritedDescriptors;
    refuse_inherited_descriptors(descriptor)?;
    *stage = WorkerStage::ParentWatch;
    let lifetime = rustix::process::pidfd_open(parent, rustix::process::PidfdFlags::NONBLOCK)?;
    *stage = WorkerStage::Filesystem;
    rustix::process::chroot(&root)?;
    std::env::set_current_dir("/")?;
    *stage = WorkerStage::Credentials;
    rustix::thread::set_no_new_privs(true)?;
    rustix::thread::set_thread_groups(&[])?;
    let gid = rustix::thread::Gid::from_raw(gid);
    rustix::thread::set_thread_res_gid(gid, gid, gid)?;
    let uid = rustix::thread::Uid::from_raw(uid);
    rustix::thread::set_thread_res_uid(uid, uid, uid)?;
    rustix::thread::set_capabilities(
        None,
        rustix::thread::CapabilitySets {
            effective: rustix::thread::CapabilitySet::empty(),
            permitted: rustix::thread::CapabilitySet::empty(),
            inheritable: rustix::thread::CapabilitySet::empty(),
        },
    )?;
    rustix::process::set_dumpable_behavior(rustix::process::DumpableBehavior::NotDumpable)?;
    *stage = WorkerStage::Parent;
    if rustix::process::getppid() != Some(parent) {
        return Err(denied());
    }
    *stage = WorkerStage::Limits;
    rustix::process::setrlimit(
        rustix::process::Resource::Nofile,
        rustix::process::Rlimit {
            current: Some(32),
            maximum: Some(32),
        },
    )?;
    rustix::process::setrlimit(
        rustix::process::Resource::Core,
        rustix::process::Rlimit {
            current: Some(0),
            maximum: Some(0),
        },
    )?;
    // Install before creating the current-thread runtime or touching payloads.
    // An unavailable filter refuses the connection instead of weakening isolation.
    *stage = WorkerStage::Sandbox;
    syscalls::install()?;
    Ok(PreparedTransportWorker {
        parent: lifetime,
        idle: Duration::from_millis(idle),
    })
}

/// Copy only the inherited connected sockets. The completion record carries the
/// outcome and the deadline needed to finish the close, without traffic totals.
///
/// # Errors
/// Fails if standard descriptors are not connected TCP sockets or the completion
/// record cannot be written. Invoke only after successful worker preparation,
/// without text logging, and exit the worker when this operation returns.
pub async fn run_transport_worker(prepared: PreparedTransportWorker) -> io::Result<()> {
    run_worker(prepared, &mut WorkerStage::Runtime).await
}

async fn run_worker(prepared: PreparedTransportWorker, stage: &mut WorkerStage) -> io::Result<()> {
    // Tokio 1.54 deprecated this generic safe constructor because AsRawFd alone
    // cannot guarantee I/O safety. Here the concrete OwnedFd is private, remains
    // open and immutable, and is dropped only with AsyncFd, satisfying that contract.
    *stage = WorkerStage::ParentWatch;
    #[allow(
        deprecated,
        reason = "concrete exclusively owned pidfd satisfies the constructor's descriptor-lifetime invariant without repository unsafe code"
    )]
    let parent = tokio::io::unix::AsyncFd::new(prepared.parent)?;
    *stage = WorkerStage::Sockets;
    let incoming = std::net::TcpStream::from(rustix::stdio::stdin().try_clone_to_owned()?);
    let outgoing = std::net::TcpStream::from(rustix::stdio::stdout().try_clone_to_owned()?);
    incoming.peer_addr()?;
    outgoing.peer_addr()?;
    incoming.set_nonblocking(true)?;
    outgoing.set_nonblocking(true)?;
    let mut incoming = TcpStream::from_std(incoming)?;
    let mut outgoing = TcpStream::from_std(outgoing)?;
    let transfer = async {
        if prepared.idle.is_zero() {
            crate::transfer_tcp(&mut incoming, &mut outgoing).await?;
            Ok(Some(0))
        } else {
            crate::relay::copy_with_idle(incoming, outgoing, prepared.idle).await
        }
    };
    let result = tokio::select! {
        biased;
        ready = parent.readable() => {
            *stage = WorkerStage::ParentWatch;
            let _ready = ready?;
            return Err(io::Error::other("transport controller exited"));
        },
        result = transfer => result,
    };
    let mut response = [0; REPORT_BYTES];
    match result {
        Ok(Some(idle_deadline)) => response[1..].copy_from_slice(&idle_deadline.to_le_bytes()),
        Ok(None) => response[0] = 1,
        Err(_) => response[0] = 2,
    }
    std::io::stderr().write_all(&response)
}

/// Handle the internal transport command before an executable starts threads or
/// logging. Returns `None` for ordinary commands. Binaries using the isolated
/// relay constructor must dispatch this branch at the start of `main`.
pub fn transport_worker_entrypoint() -> Option<std::process::ExitCode> {
    use std::process::ExitCode;
    let arguments: Vec<_> = std::env::args_os().skip(1).collect();
    if arguments
        .first()
        .is_none_or(|value| value != "--transport-worker")
    {
        return None;
    }
    let mut stage = WorkerStage::Arguments;
    let mut descriptor = None;
    let result = prepare_worker(&arguments[1..], &mut stage, &mut descriptor).and_then(|idle| {
        stage = WorkerStage::Runtime;
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(run_worker(idle, &mut stage))
    });
    Some(match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            let report = worker_failure_report(stage, error.raw_os_error(), descriptor);
            if let Err(_write_error) = std::io::stderr().write_all(&report) {
                return Some(ExitCode::FAILURE);
            }
            ExitCode::FAILURE
        }
    })
}
