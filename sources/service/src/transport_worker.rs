//! Opaque TCP transport in a separate, unprivileged process. Only two already
//! authorized connected sockets cross this boundary; no policy or secrets do.

mod syscalls;

use std::{
    fs,
    io::{self, Read, Write},
    net::Shutdown,
    os::{
        fd::{AsFd, OwnedFd},
        unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt},
    },
    path::{Path, PathBuf},
    process::Stdio,
    sync::Arc,
    time::Duration,
};
use tokio::{io::AsyncReadExt, net::TcpStream, process::Command, time::timeout};
use tokio_util::sync::CancellationToken;

#[derive(Clone)]
pub(crate) struct TransportWorker {
    root: Arc<PathBuf>,
    executable: PathBuf,
    uid: u32,
    gid: u32,
}

const ROOT: &str = "/var/run/tunnel-detour/transport";
const REPORT_BYTES: usize = 25;

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
    Complete((u64, u64)),
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

fn refuse_inherited_descriptors() -> io::Result<()> {
    // Run before threads and before opening the owned pidfd. Command normally
    // inherits only stdio, but an accidentally non-CLOEXEC secret descriptor in
    // the controller must never become readable through the permitted TCP pair.
    // Finish enumeration first so its own proc directory descriptor is closed.
    let mut candidates = Vec::new();
    for entry in fs::read_dir("/proc/self/fd")? {
        let entry = entry?;
        let number = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<u32>().ok())
            .ok_or_else(denied)?;
        if number > 2 {
            candidates.push(entry.path());
        }
        if candidates.len() > 32 {
            return Err(denied());
        }
    }
    for path in candidates {
        match fs::symlink_metadata(path) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
            Ok(_) => return Err(denied()),
        }
    }
    Ok(())
}

impl TransportWorker {
    pub(crate) fn new() -> io::Result<Self> {
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
        })
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
        let mut child = Command::new(&self.executable)
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
            .spawn()?;
        let operation = async {
            let stderr = child.stderr.take().ok_or_else(denied)?;
            let mut response = Vec::new();
            stderr
                .take(u64::try_from(REPORT_BYTES + 1).map_err(|_| denied())?)
                .read_to_end(&mut response)
                .await?;
            if response.len() != REPORT_BYTES {
                return Err(io::Error::other("transport worker failed"));
            }
            let status = timeout(Duration::from_secs(2), child.wait())
                .await
                .map_err(|_| {
                    io::Error::other("transport worker did not finish its completion report")
                })??;
            if response[0] == 3 {
                tracing::warn!(
                    errno = u64::from_le_bytes(response[1..9].try_into().map_err(|_| denied())?),
                    "transport worker initialization failed"
                );
            }
            if !status.success() {
                return Err(io::Error::other(
                    "transport worker did not complete successfully",
                ));
            }
            let count = |offset: usize| -> io::Result<u64> {
                Ok(u64::from_le_bytes(
                    response[offset..offset + 8]
                        .try_into()
                        .map_err(|_| denied())?,
                ))
            };
            match response[0] {
                0 => {
                    match mode {
                        Mode::Relay(idle) => {
                            if !crate::relay::acknowledge_copied(
                                &incoming,
                                &outgoing,
                                idle,
                                count(17)?,
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
                    Ok(Outcome::Complete((count(1)?, count(9)?)))
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
        if matches!(result, Ok(Outcome::Complete(_))) {
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
    validate_root(&root)?;
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
    if rustix::process::getppid() != Some(parent) {
        return Err(denied());
    }
    refuse_inherited_descriptors()?;
    let lifetime = rustix::process::pidfd_open(parent, rustix::process::PidfdFlags::NONBLOCK)?;
    rustix::process::chroot(&root)?;
    std::env::set_current_dir("/")?;
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
    if rustix::process::getppid() != Some(parent) {
        return Err(denied());
    }
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
    syscalls::install()?;
    Ok(PreparedTransportWorker {
        parent: lifetime,
        idle: Duration::from_millis(idle),
    })
}

/// Copy only the inherited connected sockets. The fixed-size binary completion
/// record contains counters and an outcome, never transferred bytes or errors.
///
/// # Errors
/// Fails if standard descriptors are not connected TCP sockets or the completion
/// record cannot be written. Invoke only after successful worker preparation,
/// without text logging, and exit the worker when this operation returns.
pub async fn run_transport_worker(prepared: PreparedTransportWorker) -> io::Result<()> {
    // Tokio 1.54 deprecated this generic safe constructor because AsRawFd alone
    // cannot guarantee I/O safety. Here the concrete OwnedFd is private, remains
    // open and immutable, and is dropped only with AsyncFd, satisfying that contract.
    #[allow(
        deprecated,
        reason = "concrete exclusively owned pidfd satisfies the constructor's descriptor-lifetime invariant without repository unsafe code"
    )]
    let parent = tokio::io::unix::AsyncFd::new(prepared.parent)?;
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
            crate::transfer_tcp(&mut incoming, &mut outgoing)
                .await
                .map(|bytes| {
                    Some(crate::relay::Copied {
                        bytes,
                        idle_deadline: 0,
                    })
                })
        } else {
            crate::relay::copy_with_idle(incoming, outgoing, prepared.idle).await
        }
    };
    let result = tokio::select! {
        biased;
        ready = parent.readable() => { let _ready = ready?; return Err(io::Error::other("transport controller exited")); },
        result = transfer => result,
    };
    let mut response = [0; REPORT_BYTES];
    match result {
        Ok(Some(crate::relay::Copied {
            bytes: (forward, reverse),
            idle_deadline,
        })) => {
            response[1..9].copy_from_slice(&forward.to_le_bytes());
            response[9..17].copy_from_slice(&reverse.to_le_bytes());
            response[17..].copy_from_slice(&idle_deadline.to_le_bytes());
        }
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
    let result = prepare_transport_worker(&arguments[1..]).and_then(|idle| {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(run_transport_worker(idle))
    });
    Some(match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            let mut report = [0; REPORT_BYTES];
            report[0] = 3;
            report[1..9]
                .copy_from_slice(&i64::from(error.raw_os_error().unwrap_or(0)).to_le_bytes());
            if let Err(_write_error) = std::io::stderr().write_all(&report) {
                return Some(ExitCode::FAILURE);
            }
            ExitCode::FAILURE
        }
    })
}
