// SPDX-License-Identifier: Apache-2.0
//! The confinement of a helper that parses what the network sends: a
//! pull worker of the registry fetcher.
//!
//! A worker talks to a registry and decompresses what it sends, both with C
//! libraries (OpenSSL, zlib, zstd) on bytes nobody has checked yet.  Before
//! it reads the first request it gives up what it does not need:
//!
//! * a user namespace of its own, as `nobody` when the daemon is the
//!   host's root (else as the daemon's user), with its IPC, host name and
//!   mounts;
//! * a session of its own, `/dev/null` for the standard streams, no core
//!   dump, not dumpable, no file descriptor but the one to the daemon;
//! * `no_new_privs` and no capability;
//! * Landlock (ABI 9, every right a must: a kernel that cannot
//!   enforce all of it does not run a worker): no path is writable, a few
//!   are readable (the libraries, the certificate stores, the files of the
//!   resolver); no TCP bind; TCP connections only to the ports the front
//!   named at the start (`--connect-port`: those of the registry or the
//!   URL the worker is for, `velarx_registry_lib::net::pool::connect_ports`); abstract
//!   UNIX sockets and signals outside the sandbox are denied;
//! * seccomp: mounts, ptrace, bpf, keyctl, module loading, `mknod`, the
//!   `set*id` family, the Landlock calls, `fork`, `execve` and the creation
//!   of namespaces are refused, `clone` is for threads only and sockets are
//!   for IPv4 and IPv6 only.
//!
//! Nothing is optional: a worker that cannot confine itself exits with an
//! error, and the pull fails.

pub mod fetch;
pub mod tunables;

use landlock::{AccessFs, AccessNet, ABI};
use rustix::process::{Resource, Rlimit};
use rustix::thread::UnshareFlags;
use seccompiler::{BpfProgram, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompRule};
use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
use std::path::PathBuf;
use velarx_sys::allow::{self, Allow};

/// Descriptors a worker may have open.
const WORKER_MAX_FILES: u64 = 1024;

/// Address space of a worker.
const WORKER_MAX_ADDRESS_SPACE: u64 = 16 << 30;

/// Files and directories the worker may read.
pub const READABLE: &[&str] = &[
    "/usr/lib",
    "/usr/lib64",
    "/lib",
    "/lib64",
    "/usr/share/ca-certificates",
    "/usr/share/crypto-policies",
    "/etc/crypto-policies",
    "/etc/pki",
    "/etc/ssl",
    "/etc/ca-certificates",
    "/etc/ld.so.cache",
    "/etc/resolv.conf",
    "/etc/hosts",
    "/etc/nsswitch.conf",
    "/etc/host.conf",
    "/etc/gai.conf",
    "/etc/services",
    "/etc/protocols",
    "/etc/localtime",
    "/proc/self",
    "/proc/sys/crypto",
    "/sys/fs/cgroup",
    "/sys/devices/system/cpu",
    "/dev/urandom",
    "/dev/random",
    "/dev/null",
];

pub fn rule(conditions: Vec<SeccompCondition>) -> Result<SeccompRule, String> {
    SeccompRule::new(conditions).map_err(|e| e.to_string())
}

pub fn condition(
    arg: u8,
    len: SeccompCmpArgLen,
    op: SeccompCmpOp,
    value: u64,
) -> Result<SeccompCondition, String> {
    SeccompCondition::new(arg, len, op, value).map_err(|e| e.to_string())
}

/// What a pull worker makes on top of [`Allow::runtime`]: the files it
/// reads (the libraries the resolver loads, the certificates, its
/// configuration), TCP and UDP sockets of IPv4 and IPv6 to the registry and
/// the resolver, and a pair of UNIX sockets of its own for the runtime.
pub fn net_client(allow: Allow) -> Allow {
    let allow = allow
        .calls(&[
            libc::SYS_openat,
            libc::SYS_readlinkat,
            libc::SYS_faccessat,
            libc::SYS_faccessat2,
            libc::SYS_getdents64,
            libc::SYS_connect,
            // the resolver sends its queries in batches and asks the
            // version of the kernel
            libc::SYS_sendmmsg,
            libc::SYS_recvmmsg,
            libc::SYS_uname,
        ])
        // (the C library's resolver also tries a netlink socket, to sort the
        // addresses, and the UNIX socket of systemd-resolved; refused, it
        // goes on to the next source of the hosts line of nsswitch.conf: the
        // sockets of a worker are the connections to the registries and the
        // DNS servers)
        .when(
            libc::SYS_socket,
            allow::one_of(0, &[libc::AF_INET as u64, libc::AF_INET6 as u64]),
        )
        .when(
            libc::SYS_socketpair,
            vec![allow::is(0, libc::AF_UNIX as u64)],
        );
    #[cfg(target_arch = "x86_64")]
    let allow = allow.calls(&[libc::SYS_open, libc::SYS_readlink, libc::SYS_access]);
    allow
}

/// The programs of a pull worker.
fn seccomp_programs(pid: u32) -> Result<Vec<BpfProgram>, String> {
    net_client(Allow::runtime(pid)?).programs()
}

/// Move the socket of the daemon (the standard input) to descriptor 3,
/// point the standard streams to `/dev/null` and close everything else.  A
/// failure leaves the socket as the standard input, where the daemon is
/// told why.
pub(crate) fn descriptors(startup: &velarx_sys::fd::Startup) -> Result<OwnedFd, String> {
    let ipc = rustix::io::fcntl_dupfd_cloexec(rustix::stdio::stdin(), 3)
        .map_err(|e| format!("duplicate the socket: {e}"))?;
    let null = rustix::fs::open(
        "/dev/null",
        rustix::fs::OFlags::RDWR | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(|e| format!("open /dev/null: {e}"))?;
    let redirected = (|| {
        rustix::stdio::dup2_stdin(&null)?;
        rustix::stdio::dup2_stdout(&null)?;
        rustix::stdio::dup2_stderr(&null)
    })();
    if let Err(e) = redirected {
        // (the daemon is told on the standard input)
        let _ = rustix::stdio::dup2_stdin(&ipc);
        return Err(format!("redirect the standard streams: {e}"));
    }
    drop(null);
    // Everything above the socket, and the temporary descriptors.
    let keep = ipc.as_raw_fd();
    if keep > 3 {
        startup.close_range(3, keep as u32 - 1);
    }
    startup.close_from(keep as u32 + 1);
    Ok(ipc)
}

/// The calls the kernel needs the process to make on itself.
pub fn process_limits() -> Result<(), String> {
    process_limits_with(&[
        (Resource::Nofile, "RLIMIT_NOFILE", WORKER_MAX_FILES),
        (Resource::As, "RLIMIT_AS", WORKER_MAX_ADDRESS_SPACE),
    ])
}

/// [`process_limits`] with the resource limits `limits` (the resource, its
/// name for the errors, the value for the soft and the hard limit).
pub(crate) fn process_limits_with(limits: &[(Resource, &str, u64)]) -> Result<(), String> {
    // Leader of a session of its own, or already one: both are fine.
    let _ = rustix::process::setsid();
    rustix::process::set_dumpable_behavior(rustix::process::DumpableBehavior::NotDumpable)
        .map_err(|e| format!("PR_SET_DUMPABLE: {e}"))?;
    rustix::process::setrlimit(
        Resource::Core,
        Rlimit {
            current: Some(0),
            maximum: Some(0),
        },
    )
    .map_err(|e| format!("RLIMIT_CORE: {e}"))?;
    // A worker has the socket to the daemon and its connections; its
    // memory is its buffers and its threads.  It cannot fork (seccomp)
    // and RLIMIT_NPROC would count every process of the user.
    for &(resource, what, value) in limits {
        let cur = rustix::process::getrlimit(resource);
        let value = cur.maximum.map_or(value, |m| value.min(m));
        rustix::process::setrlimit(
            resource,
            Rlimit {
                current: Some(value),
                maximum: Some(value),
            },
        )
        .map_err(|e| format!("{what}: {e}"))?;
    }
    // Gone with the daemon.
    rustix::process::set_parent_process_death_signal(Some(rustix::process::Signal::KILL))
        .map_err(|e| format!("PR_SET_PDEATHSIG: {e}"))?;
    rustix::thread::set_no_new_privs(true).map_err(|e| format!("PR_SET_NO_NEW_PRIVS: {e}"))?;
    Ok(())
}

/// Fail when the daemon has closed its end of SOCKET: the signal that is
/// sent when it dies (set by [`process_limits`]) does not come for a daemon
/// that was gone before the signal was asked for.
pub(crate) fn ensure_daemon_present(socket: BorrowedFd<'_>) -> Result<(), String> {
    use rustix::event::{poll, PollFd, PollFlags};
    let mut fds = [PollFd::new(&socket, PollFlags::RDHUP)];
    // (a call that does not wait: the state of the socket now)
    let now = rustix::event::Timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    poll(&mut fds, Some(&now)).map_err(|e| format!("poll the daemon's socket: {e}"))?;
    if fds[0]
        .revents()
        .intersects(PollFlags::HUP | PollFlags::RDHUP)
    {
        return Err("the daemon is gone".into());
    }
    Ok(())
}

/// The user namespace the worker was started in, to tell it left it.
static OUTER_USERNS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Whether the worker got a user namespace of its own.
static HAS_USERNS: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Whether the worker is in a user namespace of its own.
pub fn has_userns() -> bool {
    HAS_USERNS.load(std::sync::atomic::Ordering::Relaxed)
}

/// The user a worker of a root daemon runs as.
const NOBODY: u32 = 65534;

fn userns_inode() -> u64 {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata("/proc/self/ns/user")
        .map(|m| m.ino())
        .unwrap_or(0)
}

/// A user namespace of its own (with its own IPC, host name and mounts):
/// the worker's capabilities, whatever it gets in there, are nothing
/// outside.  A worker of a root daemon becomes `nobody` first, so that it
/// is not root for the files of the host either.  Call it before
/// `process_limits` (a change of credentials resets the parent death
/// signal and the dumpable flag).
///
/// A kernel that refuses user namespaces (EPERM, ENOSPC: none allowed,
/// EINVAL) leaves the worker in the daemon's with the rest of the sandbox,
/// unless REQUIRED.
pub(crate) fn user_namespace(required: bool, nobody: bool) -> Result<(), String> {
    OUTER_USERNS.store(userns_inode(), std::sync::atomic::Ordering::Relaxed);
    // Root of the host only: in the user namespace of a rootless
    // engine, root is the user already (and nobody may be unmapped).
    if nobody
        && rustix::process::geteuid().is_root()
        && !velarx_base::ids::in_user_namespace().map_err(|e| e.to_string())?
    {
        let nobody = (
            rustix::process::Uid::from_raw(NOBODY),
            rustix::process::Gid::from_raw(NOBODY),
        );
        rustix::thread::set_thread_groups(&[]).map_err(|e| format!("setgroups: {e}"))?;
        rustix::thread::set_thread_res_gid(nobody.1, nobody.1, nobody.1)
            .map_err(|e| format!("setresgid: {e}"))?;
        rustix::thread::set_thread_res_uid(nobody.0, nobody.0, nobody.0)
            .map_err(|e| format!("setresuid: {e}"))?;
        // A change of user made the process not dumpable, and its
        // /proc files root's: it could not write its maps.
        // process_limits makes it not dumpable again.
        rustix::process::set_dumpable_behavior(rustix::process::DumpableBehavior::Dumpable)
            .map_err(|e| format!("PR_SET_DUMPABLE: {e}"))?;
    }
    let (uid, gid) = (
        rustix::process::geteuid().as_raw(),
        rustix::process::getegid().as_raw(),
    );
    let all = UnshareFlags::NEWIPC | UnshareFlags::NEWUTS | UnshareFlags::NEWNS;
    let refused = velarx_sys::namespace::unshare(all | UnshareFlags::NEWUSER)
        .err()
        .map(|e| e.raw_os_error().unwrap_or(0));
    match refused {
        None => {}
        Some(e) if !required && matches!(e, libc::EPERM | libc::ENOSPC | libc::EINVAL) => {
            // What the process may have without one: only a process with
            // CAP_SYS_ADMIN can leave the namespaces it shares.
            let caps = rustix::thread::capabilities(None).map_err(|e| format!("capget: {e}"))?;
            if caps
                .effective
                .contains(rustix::thread::CapabilitySet::SYS_ADMIN)
            {
                velarx_sys::namespace::unshare(all)
                    .map_err(|e| format!("unshare the IPC, UTS and mount namespaces: {e}"))?;
            }
            return Ok(());
        }
        Some(e) => {
            return Err(format!(
                "unshare a user namespace: {} (the pull workers need one: [pull] \
                 require_userns = false confines them without)",
                io::Error::from_raw_os_error(e)
            ));
        }
    }
    for (file, content) in [
        ("/proc/self/setgroups", "deny".to_string()),
        ("/proc/self/uid_map", format!("0 {uid} 1")),
        ("/proc/self/gid_map", format!("0 {gid} 1")),
    ] {
        std::fs::write(file, content).map_err(|e| format!("write {file}: {e}"))?;
    }
    HAS_USERNS.store(true, std::sync::atomic::Ordering::Relaxed);
    Ok(())
}

/// Leave the namespaces the worker shares (as far as it is allowed to) and
/// give up every capability.
pub fn drop_privileges() -> Result<(), String> {
    use rustix::thread::CapabilitySet;
    velarx_sys::caps::drop_bounding_except(|_| false)
        .map_err(|e| format!("capabilities of the bounding set: {e}"))?;
    velarx_sys::caps::clear_ambient().map_err(|e| format!("ambient capabilities: {e}"))?;
    rustix::thread::set_capabilities(
        None,
        rustix::thread::CapabilitySets {
            effective: CapabilitySet::empty(),
            permitted: CapabilitySet::empty(),
            inheritable: CapabilitySet::empty(),
        },
    )
    .map_err(|e| format!("capset: {e}"))?;
    Ok(())
}

/// The Landlock ABI a worker needs: every right below is a must (the ABI of
/// the fetchers', 9).
const WORKER_ABI: ABI = ABI::V9;

fn landlock(ports: &[u16]) -> Result<(), String> {
    use velarx_sys::ruleset::{Handles, Must, Rules};
    let mut readable: Vec<PathBuf> = READABLE.iter().map(PathBuf::from).collect();
    for var in ["SSL_CERT_FILE", "SSL_CERT_DIR"] {
        if let Some(p) = std::env::var_os(var) {
            readable.push(p.into());
        }
    }
    let mut rules = Rules::new(Handles {
        abi: WORKER_ABI,
        net: AccessNet::BindTcp | AccessNet::ConnectTcp,
        scopes: true,
        must: Must::Everything,
    })?;
    let read = AccessFs::from_read(WORKER_ABI);
    for path in &readable {
        rules.beneath_if_present(path, read)?;
    }
    for port in ports {
        rules.port(*port, AccessNet::ConnectTcp)?;
    }
    rules.restrict_fully("a worker").map(drop)
}

/// Confine the process and return the descriptor of the daemon's socket.
/// Call it before any thread is started: the filters apply to the threads
/// that are created afterwards.
pub fn enter(
    startup: &velarx_sys::fd::Startup,
    require_userns: bool,
    ports: &[u16],
) -> Result<OwnedFd, String> {
    let ipc = descriptors(startup)?;
    let confined = || -> Result<(), String> {
        user_namespace(require_userns, true)?;
        process_limits()?;
        ensure_daemon_present(ipc.as_fd())?;
        drop_privileges()?;
        // (the user namespace is the worker's: what it says of the ids
        // stays)
        velarx_base::ids::settle().map_err(|e| e.to_string())?;
        landlock(ports)?;
        allow::apply(&seccomp_programs(std::process::id())?)?;
        Ok(())
    };
    if let Err(e) = confined() {
        // The socket stays open for the daemon to be told why, as the
        // standard input again (it is not on descriptor 3 when a
        // descriptor of the parent that is not close-on-exec was there:
        // the standard input is /dev/null now, and the message would be
        // written to it).
        let _ = rustix::stdio::dup2_stdin(&ipc);
        std::mem::forget(ipc);
        return Err(e);
    }
    debug_assert!(ipc.as_raw_fd() >= 3);
    Ok(ipc)
}

/// Try what the sandbox forbids, and what it allows: `(what, as it should
/// be)`.  Meant to run after [`enter`] with `ports`.
pub fn probes(ports: &[u16]) -> Vec<(&'static str, bool)> {
    use rustix::fs::{open, OFlags};
    use rustix::io::Errno;
    use rustix::net::{AddressFamily, SocketType};
    let mut out = Vec::new();
    let open_with =
        |path: &str, flags: OFlags| open(path, flags, rustix::fs::Mode::from_raw_mode(0o600));
    let created = open_with(
        "/tmp/velarx-pull-worker-probe",
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL,
    );
    out.push((
        "create a file",
        created.as_ref().err() == Some(&Errno::ACCESS),
    ));
    if created.is_ok() {
        let _ = rustix::fs::unlink("/tmp/velarx-pull-worker-probe");
    }
    out.push((
        "read /etc/passwd",
        open_with("/etc/passwd", OFlags::RDONLY).err() == Some(Errno::ACCESS),
    ));
    out.push((
        "read /etc/shadow",
        open_with("/etc/shadow", OFlags::RDONLY).is_err(),
    ));
    out.push((
        "read /etc/hosts",
        open_with("/etc/hosts", OFlags::RDONLY).map_or_else(|e| e == Errno::NOENT, |_| true),
    ));
    out.push((
        "write /dev/null",
        open_with("/dev/null", OFlags::WRONLY).map_or_else(|e| e == Errno::ACCESS, |_| true),
    ));
    let forked = velarx_sys::process::fork_status(|| 0);
    out.push((
        "fork",
        forked.is_err_and(|e| e.raw_os_error() == Some(libc::EPERM)),
    ));
    out.push((
        "execve",
        velarx_sys::process::try_exec(c"/bin/true") == libc::EPERM,
    ));
    let socket = |family| rustix::net::socket(family, SocketType::STREAM, None);
    out.push((
        "a UNIX socket",
        socket(AddressFamily::UNIX).err() == Some(Errno::PERM),
    ));
    out.push(("an IPv4 socket", socket(AddressFamily::INET).is_ok()));
    // TCP: the ports named at the start only (Landlock refuses the others
    // with EACCES before any packet; a port allowed is refused by the peer,
    // or not at all, but never by Landlock)
    let connect = |port: u16| {
        let s = socket(AddressFamily::INET).ok()?;
        let at = rustix::net::SocketAddrV4::new(std::net::Ipv4Addr::LOCALHOST, port);
        Some(rustix::net::connect(&s, &at).err())
    };
    let other = (1..=u16::MAX).find(|p| !ports.contains(p)).unwrap_or(1);
    out.push((
        "connect to a TCP port it was not given",
        connect(other) == Some(Some(Errno::ACCESS)),
    ));
    if let Some(port) = ports.first() {
        out.push((
            "connect to a TCP port it was given",
            connect(*port).is_some_and(|e| e != Some(Errno::ACCESS)),
        ));
    }
    let bound = socket(AddressFamily::INET).ok().map(|s| {
        rustix::net::bind(
            &s,
            &rustix::net::SocketAddrV4::new(std::net::Ipv4Addr::LOCALHOST, 0),
        )
        .err()
    });
    // (Landlock refuses it, and so does the filter, which comes first)
    out.push(("bind a TCP port", bound.is_some_and(|e| e.is_some())));
    out.push((
        "an IPv6 socket",
        socket(AddressFamily::INET6).map_or_else(|e| e == Errno::AFNOSUPPORT, |_| true),
    ));
    out.push((
        "mount",
        rustix::mount::mount(
            "none",
            "/tmp",
            "tmpfs",
            rustix::mount::MountFlags::empty(),
            None,
        )
        .is_err(),
    ));
    // The resolver of the C library opens a netlink socket (to sort the
    // addresses) and, for a name the hosts file lacks, the UNIX socket of
    // systemd-resolved: the filter refuses both and the library goes on to
    // the next source of the hosts line of nsswitch.conf.
    out.push((
        "resolves a name",
        std::net::ToSocketAddrs::to_socket_addrs(&("localhost", 80))
            .is_ok_and(|mut a| a.any(|a| a.ip().is_loopback())),
    ));
    out.push(("ptrace", velarx_sys::probe::ptrace_traceme().is_err()));
    out.push((
        "unshare",
        velarx_sys::namespace::unshare(UnshareFlags::NEWNS).is_err(),
    ));
    out.push((
        "setuid",
        rustix::thread::set_thread_uid(rustix::process::Uid::ROOT).is_err(),
    ));
    out.push(("bpf", velarx_sys::probe::bpf_nothing() == Err(libc::EPERM)));
    out.push((
        "io_uring",
        velarx_sys::probe::io_uring_setup().err() == Some(libc::EPERM),
    ));
    // Signals to itself only, whatever the kernel's Landlock.
    let parent = rustix::process::getppid().map_or(0, |p| p.as_raw_nonzero().get());
    out.push((
        "signal the daemon",
        velarx_sys::probe::kill_nothing(parent) == Err(libc::EPERM),
    ));
    out.push((
        "tgkill the daemon",
        velarx_sys::probe::tgkill_nothing(parent, parent) == Err(libc::EPERM),
    ));
    out.push((
        "signal every process",
        velarx_sys::probe::kill_nothing(-1) == Err(libc::EPERM),
    ));
    out.push((
        "signal itself",
        rustix::process::test_kill_process(rustix::process::getpid()).is_ok(),
    ));
    let max = |r| rustix::process::getrlimit(r).maximum;
    out.push((
        "RLIMIT_NOFILE",
        max(Resource::Nofile).is_some_and(|m| m <= WORKER_MAX_FILES),
    ));
    out.push((
        "RLIMIT_AS",
        max(Resource::As).is_some_and(|m| m <= WORKER_MAX_ADDRESS_SPACE),
    ));
    // Threads are allowed.
    let thread = velarx_sys::probe::a_thread_runs();
    out.push(("a thread", thread));
    // (what the kernel says of every thread: the confinement is of the
    // process, the threads of its runtime are made after it)
    let every = velarx_sys::probe::every_thread_has;
    out.push(("no_new_privs", every("NoNewPrivs", "1")));
    let outer = OUTER_USERNS.load(std::sync::atomic::Ordering::Relaxed);
    // Without one (the kernel refused it), said as such: the rest of the
    // sandbox holds.
    if has_userns() {
        out.push((
            "a user namespace of its own",
            outer != 0 && userns_inode() != outer,
        ));
        out.push((
            "root of its user namespace only",
            rustix::process::getuid().is_root(),
        ));
    } else {
        out.push(("no user namespace: the kernel refused it", true));
        out.push((
            "not the host's root without a user namespace",
            // (an unreadable map is no proof of anything: the check fails)
            velarx_base::ids::host_uid().is_ok_and(|uid| uid != 0),
        ));
    }
    out.push((
        "no capability",
        every("CapEff", "0000000000000000") && every("CapPrm", "0000000000000000"),
    ));
    out.push(("seccomp filter mode", every("Seccomp", "2")));
    out.push(("no core dump", max(Resource::Core) == Some(0)));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use velarx_sys::allow::testing::{Expect, ALLOW, ENOSYS, EPERM};

    /// A daemon that closed its socket is gone, whatever its pid (the engine
    /// may be the process 1 of a container); one that holds it is not.
    #[test]
    fn a_daemon_is_gone_when_its_socket_is_closed() {
        let (mine, theirs) = std::os::unix::net::UnixStream::pair().unwrap();
        ensure_daemon_present(theirs.as_fd()).unwrap();
        drop(mine);
        let e = ensure_daemon_present(theirs.as_fd()).unwrap_err();
        assert_eq!(e, "the daemon is gone");
    }

    fn verdict(nr: i64, args: [u64; 6]) -> u32 {
        let programs = seccomp_programs(1).unwrap();
        assert_eq!(programs.len(), 2);
        velarx_sys::confine::seccomp_verdict(&programs, nr as u32, velarx_sys::confine::ARCH, args)
    }

    /// The program of a pull worker, evaluated: what the runtime needs and
    /// the sockets of a client are allowed, the kernel interface it never
    /// uses is refused, whatever the kernel adds is `ENOSYS`.
    #[test]
    fn the_filters_allow_a_client_and_refuse_the_rest() {
        let af = |d: i32| [d as u64, 0, 0, 0, 0, 0];
        velarx_sys::allow::testing::check_runtime(&verdict);
        let table: &[Expect] = &[
            (libc::SYS_openat, [0; 6], ALLOW),
            (libc::SYS_connect, [0; 6], ALLOW),
            (libc::SYS_socket, af(libc::AF_INET), ALLOW),
            (libc::SYS_socket, af(libc::AF_INET6), ALLOW),
            (libc::SYS_socket, af(libc::AF_UNIX), EPERM),
            (libc::SYS_socket, af(libc::AF_NETLINK), EPERM),
            (libc::SYS_socket, af(libc::AF_PACKET), EPERM),
            (libc::SYS_socketpair, af(libc::AF_UNIX), ALLOW),
            (libc::SYS_socketpair, af(libc::AF_INET), EPERM),
            (libc::SYS_bind, [0; 6], EPERM),
            (libc::SYS_listen, [0; 6], EPERM),
            (libc::SYS_memfd_create, [0; 6], EPERM),
            (libc::SYS_execve, [0; 6], EPERM),
            (libc::SYS_mount, [0; 6], EPERM),
            (libc::SYS_unshare, [0; 6], EPERM),
            (libc::SYS_kill, [0; 6], EPERM),
            (libc::SYS_unlinkat, [0; 6], EPERM),
            (libc::SYS_pidfd_send_signal, [0; 6], EPERM),
        ];
        velarx_sys::allow::testing::check(&verdict, table);
        let _ = ENOSYS;
        // another ABI
        let programs = seccomp_programs(1).unwrap();
        assert_eq!(
            velarx_sys::confine::seccomp_verdict(
                &programs,
                libc::SYS_read as u32,
                0x4000_0003,
                [0; 6]
            ),
            libc::SECCOMP_RET_KILL_PROCESS
        );
    }
}
