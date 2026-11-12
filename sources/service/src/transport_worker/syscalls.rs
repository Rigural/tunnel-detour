//! Allow only copying inherited TCP descriptors and running a single-threaded reactor.
//! New sockets, filesystem access, exec/clone, signals, ptrace, io_uring and kernel
//! configuration have no rule and receive EPERM. The compiler verifies the ABI.

use std::{collections::BTreeMap, io};

use seccompiler::{
    BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter,
    SeccompRule, TargetArch,
};

pub(super) fn install() -> io::Result<()> {
    let allowed = [
        // Already-connected streams, completion pipe and owned reactor descriptors.
        libc::SYS_read,
        libc::SYS_write,
        libc::SYS_readv,
        libc::SYS_writev,
        libc::SYS_recvfrom,
        libc::SYS_sendto,
        libc::SYS_recvmsg,
        libc::SYS_sendmsg,
        libc::SYS_shutdown,
        libc::SYS_getsockname,
        libc::SYS_getpeername,
        libc::SYS_getsockopt,
        libc::SYS_close,
        libc::SYS_dup,
        libc::SYS_dup3,
        libc::SYS_fstat,
        libc::SYS_epoll_create1,
        libc::SYS_epoll_ctl,
        libc::SYS_epoll_pwait,
        libc::SYS_eventfd2,
        // Allocator, clock, synchronization, local signal handling and process exit.
        libc::SYS_brk,
        libc::SYS_mmap,
        libc::SYS_mprotect,
        libc::SYS_mremap,
        libc::SYS_munmap,
        libc::SYS_madvise,
        libc::SYS_futex,
        libc::SYS_clock_gettime,
        libc::SYS_clock_nanosleep,
        libc::SYS_nanosleep,
        libc::SYS_sched_yield,
        libc::SYS_sched_getaffinity,
        libc::SYS_rt_sigaction,
        libc::SYS_rt_sigprocmask,
        libc::SYS_rt_sigreturn,
        libc::SYS_sigaltstack,
        libc::SYS_restart_syscall,
        libc::SYS_getpid,
        libc::SYS_getppid,
        libc::SYS_gettid,
        libc::SYS_getrandom,
        libc::SYS_exit,
        libc::SYS_exit_group,
    ];
    let mut rules: BTreeMap<i64, Vec<SeccompRule>> = allowed
        .into_iter()
        .map(|number| (number, Vec::new()))
        .collect();
    // AArch64's reactor uses epoll_pwait; x86_64 also exposes epoll_wait.
    #[cfg(target_arch = "x86_64")]
    rules.insert(libc::SYS_epoll_wait, Vec::new());

    // Unrestricted fcntl would permit F_SETOWN plus O_ASYNC, an indirect route
    // to same-UID SIGIO even though kill/tgkill are denied. Permit only descriptor
    // operations used by the reactor, with asynchronous notification disabled.
    let command = |value: i32| -> io::Result<SeccompCondition> {
        SeccompCondition::new(
            1,
            SeccompCmpArgLen::Dword,
            SeccompCmpOp::Eq,
            u64::try_from(value).map_err(io::Error::other)?,
        )
        .map_err(io::Error::other)
    };
    let mut fcntl = Vec::new();
    for value in [libc::F_GETFD, libc::F_GETFL, libc::F_DUPFD_CLOEXEC] {
        fcntl.push(SeccompRule::new(vec![command(value)?]).map_err(io::Error::other)?);
    }
    fcntl.push(
        SeccompRule::new(vec![
            command(libc::F_SETFD)?,
            SeccompCondition::new(
                2,
                SeccompCmpArgLen::Dword,
                SeccompCmpOp::Eq,
                u64::try_from(libc::FD_CLOEXEC).map_err(io::Error::other)?,
            )
            .map_err(io::Error::other)?,
        ])
        .map_err(io::Error::other)?,
    );
    fcntl.push(
        SeccompRule::new(vec![
            command(libc::F_SETFL)?,
            SeccompCondition::new(
                2,
                SeccompCmpArgLen::Dword,
                SeccompCmpOp::MaskedEq(u64::try_from(libc::O_ASYNC).map_err(io::Error::other)?),
                0,
            )
            .map_err(io::Error::other)?,
        ])
        .map_err(io::Error::other)?,
    );
    rules.insert(libc::SYS_fcntl, fcntl);

    // mio uses FIONBIO on inherited streams. Other ioctls are not transport work.
    #[allow(
        clippy::useless_conversion,
        reason = "libc ioctl constants are u64 on the glibc host and i32 on the musl target"
    )]
    let fionbio = u64::try_from(libc::FIONBIO).map_err(io::Error::other)?;
    let nonblocking = SeccompCondition::new(1, SeccompCmpArgLen::Dword, SeccompCmpOp::Eq, fionbio)
        .map_err(io::Error::other)?;
    rules.insert(
        libc::SYS_ioctl,
        vec![SeccompRule::new(vec![nonblocking]).map_err(io::Error::other)?],
    );
    // Tokio's compiled-in signal driver creates an anonymous local wakeup pair,
    // even on a current-thread runtime with no registered signal handlers. It
    // cannot connect to another process or create an IP/network endpoint.
    let local_pair = SeccompCondition::new(
        0,
        SeccompCmpArgLen::Dword,
        SeccompCmpOp::Eq,
        u64::try_from(libc::AF_UNIX).map_err(io::Error::other)?,
    )
    .map_err(io::Error::other)?;
    rules.insert(
        libc::SYS_socketpair,
        vec![SeccompRule::new(vec![local_pair]).map_err(io::Error::other)?],
    );
    let filter = SeccompFilter::new(
        rules,
        SeccompAction::Errno(u32::try_from(libc::EPERM).map_err(io::Error::other)?),
        SeccompAction::Allow,
        TargetArch::try_from(std::env::consts::ARCH).map_err(io::Error::other)?,
    )
    .map_err(io::Error::other)?;
    let program: BpfProgram = filter.try_into().map_err(io::Error::other)?;
    seccompiler::apply_filter(&program).map_err(io::Error::other)
}
