//! Test-only adversarial actor. Run solely inside the isolated OpenWrt laboratory.
use rustix::net::{
    self, AddressFamily, Protocol, RecvFlags, SendFlags, SocketFlags, SocketType,
    netlink::SocketAddrNetlink,
};
use std::{
    error::Error,
    fs,
    process::ExitCode,
    time::{Duration, Instant},
};

#[path = "../../../tests/transport/acknowledgements.rs"]
mod acknowledgements;

fn mutation_is_denied(
    protocol: Option<Protocol>,
    kind: u16,
    payload: &[u8],
) -> Result<(), Box<dyn Error>> {
    let fd = match net::socket_with(
        AddressFamily::NETLINK,
        SocketType::DGRAM,
        SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
        protocol,
    ) {
        Ok(fd) => fd,
        Err(rustix::io::Errno::PERM) => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    net::connect(&fd, &SocketAddrNetlink::new(0, 0))?;
    let mut message = Vec::new();
    message.extend(u32::try_from(16 + payload.len())?.to_ne_bytes());
    message.extend(kind.to_ne_bytes());
    message.extend(0x605_u16.to_ne_bytes());
    message.extend(1_u32.to_ne_bytes());
    message.extend(0_u32.to_ne_bytes());
    message.extend(payload);
    net::send(&fd, &message, SendFlags::empty())?;
    let deadline = Instant::now() + Duration::from_secs(1);
    let mut bytes = [0; 256];
    loop {
        match net::recvfrom(&fd, bytes.as_mut_slice(), RecvFlags::TRUNC) {
            Ok((_, length, peer)) => {
                if length < 20
                    || length > bytes.len()
                    || peer
                        .and_then(|peer| SocketAddrNetlink::try_from(peer).ok())
                        .is_none_or(|peer| peer.pid() != 0)
                {
                    return Err("invalid kernel response".into());
                }
                if u16::from_ne_bytes(bytes[4..6].try_into()?) != 2
                    || i32::from_ne_bytes(bytes[16..20].try_into()?) != -1
                {
                    return Err("sandbox did not refuse mutation with EPERM".into());
                }
                return Ok(());
            }
            Err(rustix::io::Errno::AGAIN | rustix::io::Errno::INTR)
                if Instant::now() < deadline =>
            {
                std::thread::sleep(Duration::from_millis(1))
            }
            Err(error) => return Err(error.into()),
        }
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Scenario {
    CreatorThread,
    InheritedDescriptor,
    FilterUnavailable,
}

fn prevent_filter_installation() -> Result<(), Box<dyn Error>> {
    use seccompiler::{
        BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter,
        SeccompRule, TargetArch,
    };
    // This outer filter belongs only to the test actor and its children. Permit
    // normal setup, but deny both kernel interfaces for installing another filter.
    let prctl = SeccompRule::new(vec![SeccompCondition::new(
        0,
        SeccompCmpArgLen::Dword,
        SeccompCmpOp::Eq,
        u64::try_from(libc::PR_SET_SECCOMP)?,
    )?])?;
    let filter = SeccompFilter::new(
        [(libc::SYS_seccomp, vec![]), (libc::SYS_prctl, vec![prctl])].into(),
        SeccompAction::Allow,
        SeccompAction::Errno(u32::try_from(libc::EPERM)?),
        TargetArch::try_from(std::env::consts::ARCH)?,
    )?;
    let program: BpfProgram = filter.try_into()?;
    seccompiler::apply_filter(&program)?;
    match seccompiler::apply_filter(&program) {
        Err(seccompiler::Error::Seccomp(error)) if error.raw_os_error() == Some(libc::EPERM) => {
            Ok(())
        }
        _ => Err("test filter did not deny further filter installation".into()),
    }
}

fn thread_lifetime(root: std::ffi::OsString, scenario: Scenario) -> Result<(), Box<dyn Error>> {
    use std::{
        io::{Read, Write},
        net::{TcpListener, TcpStream},
        os::fd::AsFd,
        process::{Command, Stdio},
    };
    rustix::thread::set_no_new_privs(true)?;
    if scenario == Scenario::FilterUnavailable {
        prevent_filter_installation()?;
    }
    let ingress = TcpListener::bind(("127.0.0.1", 0))?;
    let mut client = TcpStream::connect(ingress.local_addr()?)?;
    let (incoming, _) = ingress.accept()?;
    let origin = TcpListener::bind(("127.0.0.1", 0))?;
    let outgoing = TcpStream::connect(origin.local_addr()?)?;
    let (mut backend, _) = origin.accept()?;
    for stream in [&client, &backend] {
        stream.set_read_timeout(Some(Duration::from_secs(2)))?;
        stream.set_write_timeout(Some(Duration::from_secs(2)))?;
    }
    let parent = std::process::id().to_string();
    let inherited = if scenario == Scenario::InheritedDescriptor {
        let file = fs::File::open("/etc/config/tunnel-detour")?;
        rustix::io::fcntl_setfd(&file, rustix::io::FdFlags::empty())?;
        Some(file)
    } else {
        None
    };
    let (release, wait) = std::sync::mpsc::channel();
    let creator = std::thread::spawn(move || -> Result<std::process::Child, String> {
        let operation = || -> Result<std::process::Child, Box<dyn Error>> {
            let mut child = Command::new("/usr/bin/tunnel-detour")
                .args([
                    std::ffi::OsStr::new("--transport-worker"),
                    "65534".as_ref(),
                    "65534".as_ref(),
                    &root,
                    parent.as_ref(),
                    "0".as_ref(),
                ])
                .env_clear()
                .stdin(Stdio::from(incoming.as_fd().try_clone_to_owned()?))
                .stdout(Stdio::from(outgoing.as_fd().try_clone_to_owned()?))
                .stderr(if scenario == Scenario::CreatorThread {
                    Stdio::null()
                } else {
                    Stdio::piped()
                })
                .spawn()?;
            if wait.recv().is_err() {
                child.kill()?;
                child.wait()?;
                return Err("creator lost its controller".into());
            }
            Ok(child)
        };
        operation().map_err(|error| error.to_string())
    });
    let exchange =
        |client: &mut TcpStream, backend: &mut TcpStream| -> Result<(), Box<dyn Error>> {
            client.write_all(b"scope")?;
            let mut body = [0; 5];
            backend.read_exact(&mut body)?;
            if &body != b"scope" {
                return Err("incorrect isolated transport payload".into());
            }
            backend.write_all(b"scope")?;
            client.read_exact(&mut body)?;
            if &body != b"scope" {
                return Err("incorrect isolated transport reply".into());
            }
            Ok(())
        };
    let before = if scenario == Scenario::CreatorThread {
        exchange(&mut client, &mut backend)
            .map_err(|error| format!("before creator-thread exit: {error}"))
    } else {
        // Read one byte, not read_exact: a partial unauthorized copy must fail
        // this test rather than being mistaken for an expected timeout.
        let mut refused = || -> Result<(), Box<dyn Error>> {
            client.write_all(b"scope")?;
            backend.write_all(b"reply")?;
            for endpoint in [&mut backend, &mut client] {
                match endpoint.read(&mut [0; 1]) {
                    Ok(0) => {}
                    Err(error)
                        if matches!(
                            error.kind(),
                            std::io::ErrorKind::WouldBlock
                                | std::io::ErrorKind::TimedOut
                                | std::io::ErrorKind::ConnectionReset
                                | std::io::ErrorKind::ConnectionAborted
                        ) => {}
                    other => return Err(format!("refused worker copied a byte: {other:?}").into()),
                }
            }
            Ok(())
        };
        refused().map_err(|error| format!("refusal before copying: {error}"))
    };
    let released = release.send(());
    let mut child = creator.join().map_err(|_| "creator thread failed")??;
    let after = if scenario == Scenario::CreatorThread && before.is_ok() {
        exchange(&mut client, &mut backend)
            .map_err(|error| format!("after creator-thread exit: {error}"))
    } else {
        before
    };
    if child.try_wait()?.is_none() {
        child.kill()?;
    }
    let status = child.wait()?;
    drop(inherited);
    released?;
    if scenario != Scenario::CreatorThread {
        after?;
        if status.success() {
            return Err("worker admitted a refused transport".into());
        }
        let mut report = Vec::new();
        child
            .stderr
            .take()
            .ok_or("missing worker failure report")?
            .take(26)
            .read_to_end(&mut report)?;
        if report.len() != 25 || report.first() != Some(&3) {
            return Err("missing worker initialization refusal".into());
        }
        match scenario {
            Scenario::FilterUnavailable => {
                println!("unavailable syscall filter refused before copying in either direction")
            }
            _ => println!("unexpected inherited descriptor refused before copying"),
        }
        return Ok(());
    }
    after?;
    println!("creator thread exited; the controller process retained both TCP directions");
    Ok(())
}

fn run() -> Result<(), Box<dyn Error>> {
    if std::env::var("TUNNEL_DETOUR_TRANSPORT_LAB").as_deref() != Ok("1") {
        return Err("use the isolated OpenWrt requirement laboratory".into());
    }
    let root = std::env::args_os().nth(1).ok_or("missing test root")?;
    if root == "--acknowledgements" {
        return tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()?
            .block_on(acknowledgements::run(true));
    }
    if root == "--thread-lifetime"
        || root == "--inherited-descriptor"
        || root == "--filter-unavailable"
    {
        return thread_lifetime(
            std::env::args_os().nth(2).ok_or("missing test root")?,
            if root == "--filter-unavailable" {
                Scenario::FilterUnavailable
            } else if root == "--inherited-descriptor" {
                Scenario::InheritedDescriptor
            } else {
                Scenario::CreatorThread
            },
        );
    }
    let parent = rustix::process::getppid()
        .ok_or("missing test parent")?
        .as_raw_pid();
    tunnel_detour_service::prepare_transport_worker(&[
        "65534".into(),
        "65534".into(),
        root,
        parent.to_string().into(),
        "0".into(),
    ])?;
    match net::socket(
        AddressFamily::INET,
        SocketType::STREAM,
        Some(net::ipproto::TCP),
    ) {
        Err(rustix::io::Errno::PERM) => {}
        _ => return Err("worker can create an unauthorized network socket".into()),
    }
    // Signal zero checks permission without delivering a signal, even before the
    // boundary is fixed. The sandbox must refuse the syscall, including same-UID peers.
    match rustix::process::test_kill_process(rustix::process::getpid()) {
        Err(rustix::io::Errno::PERM) => {}
        _ => return Err("worker can signal another same-UID process".into()),
    }
    match rustix::fs::fcntl_setfl(rustix::stdio::stdin(), rustix::fs::OFlags::ASYNC) {
        Err(rustix::io::Errno::PERM) => {}
        _ => return Err("worker can enable asynchronous descriptor signals".into()),
    }
    match socket2::SockRef::from(&rustix::stdio::stdin()).set_recv_buffer_size(4096) {
        Err(error) if error.raw_os_error() == Some(rustix::io::Errno::PERM.raw_os_error()) => {}
        _ => {
            return Err(
                "worker did not refuse socket reconfiguration at the syscall boundary".into(),
            );
        }
    }
    match socket2::SockRef::from(&rustix::stdio::stdin()).set_linger(None) {
        Err(error) if error.raw_os_error() == Some(rustix::io::Errno::PERM.raw_os_error()) => {}
        _ => return Err("worker can enter the socket close-policy syscall".into()),
    }
    if fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open("/etc/config/tunnel-detour")
        .is_ok()
    {
        return Err("worker can edit UCI".into());
    }
    if std::os::unix::net::UnixStream::connect("/var/run/ubus/ubus.sock").is_ok() {
        return Err("worker can reach ubus".into());
    }
    if fs::write("/escaped", b"forbidden").is_ok() {
        return Err("worker can write to its root".into());
    }
    match rustix::thread::set_thread_res_uid(
        rustix::thread::Uid::ROOT,
        rustix::thread::Uid::ROOT,
        rustix::thread::Uid::ROOT,
    ) {
        Err(rustix::io::Errno::PERM) => {}
        _ => return Err("worker can regain root".into()),
    }
    // RTM_NEWROUTE: a blackhole documentation host in an isolated test table.
    let mut route = vec![2, 32, 0, 0, 201, 4, 0, 6, 0, 0, 0, 0];
    route.extend(8_u16.to_ne_bytes());
    route.extend(1_u16.to_ne_bytes());
    route.extend([203, 0, 113, 253]);
    mutation_is_denied(None, 24, &route)?;
    // NFT_MSG_NEWTABLE in the inet family, with a bounded synthetic table name.
    let name = b"td_boundary_probe\0";
    let mut table = vec![1, 0, 0, 0];
    table.extend(u16::try_from(4 + name.len())?.to_ne_bytes());
    table.extend(1_u16.to_ne_bytes());
    table.extend(name);
    table.resize((table.len() + 3) & !3, 0);
    mutation_is_denied(Some(net::netlink::NETFILTER), 10 << 8, &table)?;
    println!(
        "{}",
        serde_json::json!({"uci_write_denied":true,"ubus_denied":true,"filesystem_write_denied":true,"root_recovery_denied":true,"route_write_denied":true,"nft_write_denied":true,"new_network_socket_denied":true,"process_signal_denied":true,"async_signal_denied":true,"socket_reconfiguration_denied":true})
    );
    Ok(())
}

fn main() -> ExitCode {
    if let Some(result) = tunnel_detour_service::transport_worker_entrypoint() {
        return result;
    }
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}
