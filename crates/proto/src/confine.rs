// SPDX-License-Identifier: Apache-2.0
//! The confinement of a frontend.
//!
//! A frontend decodes what clients send (HTTP, gRPC) and calls the engine;
//! it has no reason to touch the storage, the database, the credentials or
//! any file but its own sockets.  Before it serves anything it gives up the
//! rest:
//!
//! * `PR_SET_NO_NEW_PRIVS`, no ptrace of it (`PR_SET_DUMPABLE`), and every
//!   capability;
//! * Landlock: it reaches nothing in the file system but the directories it
//!   is told ([`Reach`]): the engine's socket to connect to (ABI 9 and later
//!   kernels check the connect; older ones cannot, and the rest still
//!   applies).  It removes nothing, not even the sockets it bound (a
//!   socket that nobody serves is replaced at the next start): the right
//!   to remove would be for the whole directory, which holds the engine's
//!   socket and the state of the containers.  What it needs from files (the configuration, the certificates) it reads
//!   before it confines itself.  TCP is refused for connect, and bind is
//!   allowed for the ports it is told;
//! * seccomp: an allow-list of the calls a frontend makes: no `execve`,
//!   `ptrace`, `mount`, `bpf`, `keyctl`, `unshare`, `io_uring`..., no new
//!   process (threads only), sockets of the UNIX, IPv4 and IPv6 families
//!   only; the rest of the kernel fails with `EPERM`, what it adds later
//!   with `ENOSYS`.
//!
//! Call [`enter`] before any thread is started (the runtime's): Landlock
//! and seccomp apply to the threads created afterwards.

use landlock::{AccessFs, AccessNet, ABI};
use seccompiler::BpfProgram;
use std::path::{Path, PathBuf};
use velarx_sys::allow::Allow;

/// The newest Landlock ABI the access rights are asked for.
const NEWEST: ABI = velarx_sys::ruleset::NEWEST;

/// What a frontend may reach after it confined itself.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Reach {
    /// Look up UNIX sockets beneath these (the engine's socket)
    pub connect: Vec<PathBuf>,
    /// TCP ports this process may bind (after the confinement)
    pub bind_tcp: Vec<u16>,
    /// Directories where it may make a file and write it, and nothing else:
    /// no read, no removal
    pub create: Vec<PathBuf>,
    /// Directories whose files it may remove (what it made there and
    /// must take back; with `create` or not)
    pub remove: Vec<PathBuf>,
    /// Directories whose entries it may list (the names, not the files)
    pub list: Vec<PathBuf>,
    /// Directories whose files it may read and whose entries it may list:
    /// nothing else (no write, no removal)
    pub read: Vec<PathBuf>,
    /// TCP ports this process may connect to (none: no TCP connection); a
    /// process with one resolves names, so its filter lets it ask the
    /// resolver
    pub connect_tcp: Vec<u16>,
    /// It serves sockets it has (a frontend: `accept`, `bind`, `listen`)
    /// and makes the memory files of the bodies it receives; a client that
    /// only calls the engine (`velarx-kube`) has neither
    pub serves: bool,
    /// Every right of Landlock ABI 9 (the file rights of the earlier ABIs,
    /// truncate, the TCP ports, the scopes, UNIX sockets looked up by name) must be enforced by the kernel:
    /// a kernel that cannot enforce them refuses the process (the rights of
    /// the later ABIs are asked for as far as the kernel has them)
    pub strict: bool,
}

/// What of the confinement the kernel enforces, for the logs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Enforced {
    pub abi: ABI,
    /// Every right asked for is enforced
    pub full: bool,
}

fn landlock(reach: &Reach) -> Result<Enforced, String> {
    use velarx_sys::ruleset::{Handles, Must, Rules};
    // (the files are a must, the rest is for the kernels that have it:
    // every right when `strict`)
    let mut rules = Rules::new(Handles {
        abi: NEWEST,
        net: AccessNet::BindTcp | AccessNet::ConnectTcp,
        scopes: true,
        must: if reach.strict {
            Must::Everything
        } else {
            Must::Files
        },
    })?;
    let lists: [(&[PathBuf], landlock::BitFlags<AccessFs>); 5] = [
        // (looked up by name: a socket)
        (&reach.connect, AccessFs::ResolveUnix.into()),
        (
            &reach.create,
            AccessFs::MakeReg | AccessFs::WriteFile | AccessFs::Truncate,
        ),
        (&reach.remove, AccessFs::RemoveFile.into()),
        (&reach.list, AccessFs::ReadDir.into()),
        (&reach.read, AccessFs::ReadFile | AccessFs::ReadDir),
    ];
    for (paths, rights) in lists {
        for path in paths {
            // (what the system does not have cannot be used)
            rules.beneath_if_present(path, rights)?;
        }
    }
    for port in &reach.connect_tcp {
        rules.port(*port, AccessNet::ConnectTcp)?;
    }
    for port in &reach.bind_tcp {
        rules.port(*port, AccessNet::BindTcp)?;
    }
    let restricted = rules.restrict()?;
    Ok(Enforced {
        abi: restricted.abi,
        full: restricted.full,
    })
}

/// Give up every capability, in the bounding set and in the process.
fn drop_capabilities() -> Result<(), String> {
    velarx_sys::caps::drop_all().map_err(|e| format!("capset: {e}"))
}

/// What a frontend makes: the runtime (threads, memory, time, descriptors),
/// the files it reads and writes where Landlock lets it, UNIX sockets to the
/// engine and IPv4 and IPv6 sockets of its clients, `connect`, `bind`,
/// `listen` and `accept`, and the sealed memory files of the parts of a
/// multipart body.  No process, no execution, no namespace, nothing of the
/// rest of the kernel: any other call fails with `EPERM`, one the kernel
/// adds later with `ENOSYS`.
fn allowed(pid: u32, reach: &Reach) -> Result<Allow, String> {
    use velarx_sys::allow::one_of;
    let allow = Allow::runtime(pid)?
        .calls(&[
            libc::SYS_openat,
            // (the checkpoints of a pod are opened below the descriptor of
            // their directory; Landlock checks it as it checks `openat`, and
            // the flags of its `how` only restrict the lookup)
            libc::SYS_openat2,
            libc::SYS_readlinkat,
            libc::SYS_faccessat,
            libc::SYS_faccessat2,
            libc::SYS_getdents64,
            libc::SYS_pwrite64,
            libc::SYS_ftruncate,
            libc::SYS_fsync,
            libc::SYS_connect,
            libc::SYS_statfs,
            libc::SYS_fstatfs,
            libc::SYS_sendfile,
            libc::SYS_flock,
            libc::SYS_fadvise64,
        ])
        // UNIX, IPv4 and IPv6 sockets only: no netlink, packet or vsock
        .when(
            libc::SYS_socket,
            one_of(
                0,
                &[
                    libc::AF_UNIX as u64,
                    libc::AF_INET as u64,
                    libc::AF_INET6 as u64,
                ],
            ),
        )
        .when(
            libc::SYS_socketpair,
            vec![velarx_sys::allow::is(0, libc::AF_UNIX as u64)],
        );
    #[cfg(target_arch = "x86_64")]
    let allow = allow.calls(&[libc::SYS_open, libc::SYS_readlink, libc::SYS_access]);
    // (what it makes with no name is given a name with `linkat`, what it
    // may remove is removed)
    let allow = if reach.create.is_empty() {
        allow
    } else {
        allow.calls(&[libc::SYS_linkat])
    };
    let allow = if reach.remove.is_empty() {
        allow
    } else {
        allow.calls(&[libc::SYS_unlinkat])
    };
    #[cfg(target_arch = "x86_64")]
    let allow = if reach.remove.is_empty() {
        allow
    } else {
        allow.calls(&[libc::SYS_unlink])
    };
    // (the secrets a frontend sends are sealed memory files: close-on-exec,
    // sealed once written)
    let allow = allow.when(
        libc::SYS_memfd_create,
        vec![velarx_sys::allow::is(1, MEMFD_FLAGS)],
    );
    let allow = if reach.serves {
        let allow = allow.calls(&[libc::SYS_bind, libc::SYS_listen, libc::SYS_accept4]);
        #[cfg(target_arch = "x86_64")]
        let allow = allow.calls(&[libc::SYS_accept]);
        allow
    } else {
        allow
    };
    // (the resolver of the C library sends its queries in batches and asks
    // the version of the kernel)
    let allow = if reach.connect_tcp.is_empty() {
        allow
    } else {
        allow.calls(&[libc::SYS_sendmmsg, libc::SYS_recvmmsg, libc::SYS_uname])
    };
    Ok(allow)
}

/// The flags of the memory files a frontend makes.
const MEMFD_FLAGS: u64 = (libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING) as u64;

/// The programs of a frontend.
fn seccomp_programs(pid: u32, reach: &Reach) -> Result<Vec<BpfProgram>, String> {
    allowed(pid, reach)?.programs()
}

fn seccomp(reach: &Reach) -> Result<(), String> {
    velarx_sys::allow::apply(&seccomp_programs(std::process::id(), reach)?)
}

/// Confine the process.  Call it before any thread is started.
pub fn enter(reach: &Reach) -> Result<Enforced, String> {
    velarx_sys::confine::require_single_thread()?;
    enter_thread(reach)
}

/// Confine the calling thread and those it makes afterwards, whatever other
/// threads the process has: for the tests, whose harness runs a test on a
/// thread of its own, and which never go on after what they try.  A program
/// calls [`enter`].
pub fn enter_thread(reach: &Reach) -> Result<Enforced, String> {
    rustix::thread::set_no_new_privs(true).map_err(|e| format!("PR_SET_NO_NEW_PRIVS: {e}"))?;
    rustix::process::set_dumpable_behavior(rustix::process::DumpableBehavior::NotDumpable)
        .map_err(|e| format!("PR_SET_DUMPABLE: {e}"))?;
    drop_capabilities()?;
    let enforced = landlock(reach)?;
    seccomp(reach)?;
    Ok(enforced)
}

/// The directory a socket is looked up in.
pub fn dir_of(socket: &Path) -> PathBuf {
    socket
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."))
        .to_path_buf()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::{UnixListener, UnixStream};

    const NAME: &str = "confine::tests::a_frontend_reaches_the_engine_socket_and_nothing_else";

    /// The programs of a frontend, evaluated: the runtime, UNIX, IPv4 and
    /// IPv6 sockets, no process, none of the calls a frontend never makes.
    #[test]
    fn the_filters_allow_a_frontend_and_refuse_the_rest() {
        use velarx_sys::allow::testing::{check, check_runtime, ALLOW, EPERM};
        let programs = seccomp_programs(
            1,
            &Reach {
                serves: true,
                ..Reach::default()
            },
        )
        .unwrap();
        let verdict = |nr: i64, args: [u64; 6]| {
            velarx_sys::confine::seccomp_verdict(
                &programs,
                nr as u32,
                velarx_sys::confine::ARCH,
                args,
            )
        };
        check_runtime(&verdict);
        let af = |d: i32| [d as u64, 0, 0, 0, 0, 0];
        check(
            &verdict,
            &[
                (libc::SYS_openat, [0; 6], ALLOW),
                (libc::SYS_openat2, [0; 6], ALLOW),
                (libc::SYS_connect, [0; 6], ALLOW),
                (libc::SYS_accept4, [0; 6], ALLOW),
                (libc::SYS_socket, af(libc::AF_UNIX), ALLOW),
                (libc::SYS_socket, af(libc::AF_INET), ALLOW),
                (libc::SYS_socket, af(libc::AF_INET6), ALLOW),
                (libc::SYS_socket, af(libc::AF_NETLINK), EPERM),
                (libc::SYS_socket, af(libc::AF_PACKET), EPERM),
                (libc::SYS_socket, af(libc::AF_VSOCK), EPERM),
                (libc::SYS_execve, [0; 6], EPERM),
                (libc::SYS_execveat, [0; 6], EPERM),
                (libc::SYS_mount, [0; 6], EPERM),
                (libc::SYS_unshare, [0; 6], EPERM),
                (libc::SYS_io_uring_setup, [0; 6], EPERM),
                (libc::SYS_memfd_create, [0, MEMFD_FLAGS, 0, 0, 0, 0], ALLOW),
                (libc::SYS_memfd_create, [0; 6], EPERM),
                (
                    libc::SYS_memfd_create,
                    [0, MEMFD_FLAGS | libc::MFD_HUGETLB as u64, 0, 0, 0, 0],
                    EPERM,
                ),
            ],
        );
    }

    const CONNECTOR_NAME: &str =
        "confine::tests::a_frontend_reaches_the_engine_through_its_connector";

    /// What `velarx-api` and `velarx-cri` ask for (no right to connect to
    /// any socket): the engine's socket is looked up by no name, and the
    /// connections come through the connector forked before.  The process
    /// runs itself again, as it cannot undo the confinement.
    #[test]
    fn a_frontend_reaches_the_engine_through_its_connector() {
        let Some(given) = std::env::var_os("VELARX_CONFINE_CHILD") else {
            let dir = tempfile::tempdir().unwrap();
            let out = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", CONNECTOR_NAME, "--nocapture", "--test-threads=1"])
                .env("VELARX_CONFINE_CHILD", dir.path())
                .output()
                .unwrap();
            assert!(
                out.status.success(),
                "the confined test failed:\n{}\n{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
            return;
        };
        let engine = std::path::PathBuf::from(given).join("engine.sock");
        let _listener = UnixListener::bind(&engine).unwrap();
        let connector =
            velarx_sys::connector::Connector::start_beside_idle_threads(&engine).unwrap();
        enter_thread(&Reach::default()).expect("the process confines itself");
        let by_name = UnixStream::connect(&engine);
        if velarx_sys::confine::landlock_abi() >= 9 {
            assert!(
                by_name.is_err(),
                "the engine's socket was looked up by name"
            );
        }
        assert!(
            connector.connect().is_ok(),
            "no connection through the connector"
        );
    }

    /// What a confined frontend can and cannot do: it connects to the
    /// engine's socket and to nothing else, reads no file, makes no process
    /// and opens no other kind of socket.  Landlock and seccomp cannot be
    /// undone, so the test runs itself again, in a process of its own.
    #[test]
    fn a_frontend_reaches_the_engine_socket_and_nothing_else() {
        // (the test process makes the directory and removes it: the confined
        // one cannot)
        let Some(given) = std::env::var_os("VELARX_CONFINE_CHILD") else {
            let dir = tempfile::tempdir().unwrap();
            let out = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", NAME, "--nocapture", "--test-threads=1"])
                .env("VELARX_CONFINE_CHILD", dir.path())
                .output()
                .unwrap();
            assert!(
                out.status.success(),
                "the confined test failed:\n{}\n{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
            return;
        };
        let dir = std::path::PathBuf::from(given);
        let engine = dir.join("engine/engine.sock");
        let other = dir.join("other/other.sock");
        let secret = dir.join("secret");
        std::fs::create_dir_all(engine.parent().unwrap()).unwrap();
        std::fs::create_dir_all(other.parent().unwrap()).unwrap();
        let made = dir.join("made");
        std::fs::create_dir(&made).unwrap();
        let removable = dir.join("removable");
        std::fs::create_dir(&removable).unwrap();
        std::fs::write(removable.join("x.tar"), "x").unwrap();
        std::fs::write(&secret, "x").unwrap();
        let listed = dir.join("listed");
        std::fs::create_dir(&listed).unwrap();
        std::fs::write(listed.join("a.conf"), "x").unwrap();
        let readable = dir.join("readable");
        std::fs::create_dir(&readable).unwrap();
        std::fs::write(readable.join("r.tar"), "x").unwrap();
        let _engine = UnixListener::bind(&engine).unwrap();
        let _other = UnixListener::bind(&other).unwrap();
        let tcp = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = tcp.local_addr().unwrap();

        let reach = Reach {
            connect: vec![dir_of(&engine)],
            create: vec![made.clone()],
            remove: vec![removable.clone()],
            list: vec![listed.clone()],
            read: vec![readable.clone()],
            ..Reach::default()
        };
        let enforced = enter_thread(&reach).expect("the process confines itself");
        let mut failed = Vec::new();
        let mut check = |what: &str, ok: bool| {
            if !ok {
                failed.push(what.to_string());
            }
        };
        check("reads no file", std::fs::read(&secret).is_err());
        {
            use rustix::fs::{open, openat2, Mode, OFlags, ResolveFlags, CWD};
            check(
                "reads no file with openat2 either (Landlock, not seccomp)",
                openat2(
                    CWD,
                    &secret,
                    OFlags::RDONLY,
                    Mode::empty(),
                    ResolveFlags::empty(),
                )
                .is_err_and(|e| e == rustix::io::Errno::ACCESS),
            );
            check(
                "opens a file below a directory it may read with openat2",
                open(&readable, OFlags::PATH | OFlags::DIRECTORY, Mode::empty())
                    .and_then(|d| {
                        openat2(
                            &d,
                            "r.tar",
                            OFlags::RDONLY,
                            Mode::empty(),
                            ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS,
                        )
                    })
                    .is_ok(),
            );
        }
        check(
            "lists the names of a directory it may list",
            std::fs::read_dir(&listed).is_ok_and(|d| d.count() == 1),
        );
        check(
            "reads no file there",
            std::fs::read(listed.join("a.conf")).is_err(),
        );
        check(
            "makes no file there",
            std::fs::write(listed.join("b.conf"), "x").is_err(),
        );
        check(
            "reads and lists the files of a directory it may read",
            std::fs::read(readable.join("r.tar")).is_ok()
                && std::fs::read_dir(&readable).is_ok_and(|d| d.count() == 1),
        );
        check(
            "writes and removes nothing there",
            std::fs::write(readable.join("r.tar"), "y").is_err()
                && std::fs::write(readable.join("n.tar"), "y").is_err()
                && std::fs::remove_file(readable.join("r.tar")).is_err(),
        );
        let new = made.join("a.tar");
        check(
            "makes and writes a file where it may",
            std::fs::write(&new, "x").is_ok(),
        );
        check(
            "makes the file only once",
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&new)
                .is_err(),
        );
        check("does not read it", std::fs::read(&new).is_err());
        check(
            "does not remove it",
            std::fs::remove_file(&new).is_err() && new.exists(),
        );
        check("makes a file unnamed and links it", {
            use rustix::fs::{linkat, openat, AtFlags, Mode, OFlags, CWD};
            let linked = rustix::fs::open(&made, OFlags::PATH | OFlags::DIRECTORY, Mode::empty())
                .and_then(|d| {
                    let f = openat(
                        &d,
                        ".",
                        OFlags::TMPFILE | OFlags::WRONLY,
                        Mode::from_raw_mode(0o600),
                    )?;
                    let p = velarx_sys::fd::proc_str(&f);
                    linkat(CWD, p.as_str(), &d, "t.tar", AtFlags::SYMLINK_FOLLOW)
                });
            linked.is_ok() && made.join("t.tar").exists()
        });
        check(
            "removes a file where it may, and writes and reads none",
            std::fs::read(removable.join("x.tar")).is_err()
                && std::fs::write(removable.join("x.tar"), "y").is_err()
                && std::fs::remove_file(removable.join("x.tar")).is_ok(),
        );
        check(
            "makes no file in the directory of the engine",
            std::fs::write(dir.join("engine/new"), "x").is_err(),
        );
        check(
            "makes no file",
            std::fs::write(dir.join("new"), "x").is_err(),
        );
        check(
            "removes nothing, not even the engine's socket",
            std::fs::remove_file(&engine).is_err() && engine.exists(),
        );
        check(
            "executes nothing",
            std::process::Command::new("/usr/bin/true")
                .status()
                .is_err(),
        );
        check(
            "connects to no TCP port",
            std::net::TcpStream::connect(addr).is_err(),
        );
        check(
            "opens no netlink socket",
            rustix::net::socket(
                rustix::net::AddressFamily::NETLINK,
                rustix::net::SocketType::RAW,
                None,
            )
            .is_err(),
        );
        check(
            "opens UNIX sockets",
            rustix::net::socket(
                rustix::net::AddressFamily::UNIX,
                rustix::net::SocketType::STREAM,
                None,
            )
            .is_ok(),
        );
        // (kernels before Landlock ABI 9 cannot tell the sockets apart)
        if enforced.abi >= ABI::V9 {
            check(
                "connects to the engine",
                UnixStream::connect(&engine).is_ok(),
            );
            check(
                "connects to no other socket",
                UnixStream::connect(&other).is_err(),
            );
        }
        check(
            "makes threads",
            std::thread::spawn(|| 1).join().is_ok_and(|n| n == 1),
        );
        assert!(failed.is_empty(), "the confined process: {failed:?}");
    }
}
