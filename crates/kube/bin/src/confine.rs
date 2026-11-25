// SPDX-License-Identifier: Apache-2.0
//! The confinement of `velarx-kube`.
//!
//! Everything that reads a file is done first: the YAML, the kubeconfig and
//! the files it names, the credentials, the secrets of the engine the
//! YAML refers to.  Then the process gives up the rest
//! (`velarx_proto::confine`, as the other frontends do it, but with every
//! right of Landlock ABI 9 a must: a kernel that cannot enforce them does
//! not run the command):
//!
//! * the files: nothing is readable but the libraries and the certificate
//!   stores of a command that makes requests (`apply`), nothing is
//!   writable and no file or directory is made: the host paths of a play
//!   (`DirectoryOrCreate`, `FileOrCreate`) are made, and the file
//!   `generate` writes is opened, before;
//! * the network: UNIX sockets to the engine (the directory of its socket,
//!   and the socket systemd is told `READY` on), and, for `apply` only, TCP
//!   connections to the port of the API server and to no other; no bind;
//!   abstract UNIX sockets and signals outside the process are denied;
//! * seccomp: no `execve`, no process but threads, no mount, no namespace,
//!   no `ptrace`, `bpf` or `io_uring`; sockets of the UNIX, IPv4 and IPv6
//!   families only.

use std::path::{Path, PathBuf};
use velarx_proto::confine::{self, Reach};

/// What the process may reach once it confined itself.
#[derive(Debug, Default, Clone)]
pub struct Needs {
    /// The port of the API server (`apply`)
    pub api_port: Option<u16>,
    /// What else is readable (the self-test reads the threads of the
    /// process: `/proc/self`)
    pub read: Vec<PathBuf>,
}

impl Needs {
    pub fn reach(&self) -> Reach {
        let mut read = self.read.clone();
        if self.api_port.is_some() {
            // (the libraries the resolver loads, the certificates, the
            // configuration of the resolver)
            read.extend(
                velarx_sandbox::READABLE
                    .iter()
                    .chain(velarx_sandbox::RESOLVER_FILES)
                    .map(PathBuf::from),
            );
            for var in ["SSL_CERT_FILE", "SSL_CERT_DIR"] {
                read.extend(std::env::var_os(var).map(PathBuf::from));
            }
        }
        Reach {
            read,
            connect_tcp: self.api_port.into_iter().collect(),
            strict: true,
            ..Reach::default()
        }
    }
}

/// Confine the process.  Call it before any thread is started.
pub fn enter(needs: &Needs) -> anyhow::Result<()> {
    // (no /proc once confined)
    velarx_base::ids::settle()?;
    confine::enter(&needs.reach()).map_err(|e| anyhow::anyhow!("cannot confine itself: {e}"))?;
    Ok(())
}

/// Try what the confinement forbids and what it allows: `(what, as it should
/// be)`.  Run after [`enter`] with the same `needs`; `outside` is a directory
/// that is not `make`.
pub fn probes(
    needs: &Needs,
    outside: &Path,
    dial: &velarx_proto::connect::Dial,
) -> Vec<(&'static str, bool)> {
    use rustix::io::Errno;
    use rustix::net::{AddressFamily, SocketType};
    let mut out = Vec::new();
    let errno = |e: &std::io::Error| e.raw_os_error();
    out.push((
        "makes no file outside",
        std::fs::write(outside.join("new"), "x").is_err_and(|e| errno(&e) == Some(libc::EACCES)),
    ));
    // (`existing` is a file of `outside` that the caller made)
    // (`outside/engine.sock` is a socket that listens: the one the
    // connector was started for is another, and it is reached through it)
    out.push((
        "connects to no UNIX socket by name",
        std::os::unix::net::UnixStream::connect(outside.join("engine.sock"))
            .is_err_and(|e| errno(&e) == Some(libc::EACCES)),
    ));
    if let velarx_proto::connect::Dial::Connector(connector, _) = dial {
        out.push((
            "connects to the engine's socket through its connector",
            connector.connect().is_ok(),
        ));
    }
    out.push((
        "rewrites no existing file",
        std::fs::write(outside.join("existing"), "x")
            .is_err_and(|e| errno(&e) == Some(libc::EACCES)),
    ));
    out.push((
        "makes no directory outside",
        std::fs::create_dir(outside.join("d")).is_err(),
    ));
    out.push((
        "reads no file",
        std::fs::read("/etc/passwd").is_err_and(|e| errno(&e) == Some(libc::EACCES)),
    ));
    out.push((
        "executes nothing",
        velarx_sys::process::try_exec(c"/bin/true") == libc::EPERM,
    ));
    out.push((
        "makes no process",
        velarx_sys::process::fork_status(|| 0)
            .is_err_and(|e| e.raw_os_error() == Some(libc::EPERM)),
    ));
    let socket = |family| rustix::net::socket(family, SocketType::STREAM, None);
    out.push(("a UNIX socket", socket(AddressFamily::UNIX).is_ok()));
    out.push((
        "no netlink socket",
        rustix::net::socket(AddressFamily::NETLINK, SocketType::RAW, None).err()
            == Some(Errno::PERM),
    ));
    // TCP: the port it was given only (Landlock refuses the others with
    // EACCES before any packet; a port allowed is refused by the peer, or
    // not at all, but never by Landlock)
    let connect = |port: u16| {
        let s = socket(AddressFamily::INET).ok()?;
        let at = rustix::net::SocketAddrV4::new(std::net::Ipv4Addr::LOCALHOST, port);
        Some(rustix::net::connect(&s, &at).err())
    };
    let given: Vec<u16> = needs.api_port.into_iter().collect();
    let other = (1..=u16::MAX).find(|p| !given.contains(p)).unwrap_or(1);
    out.push((
        "connects to no TCP port it was not given",
        connect(other) == Some(Some(Errno::ACCESS)),
    ));
    if let Some(port) = needs.api_port {
        out.push((
            "connects to the TCP port it was given",
            connect(port).is_some_and(|e| e != Some(Errno::ACCESS)),
        ));
    }
    out.push((
        "binds no TCP port",
        socket(AddressFamily::INET).ok().is_some_and(|s| {
            rustix::net::bind(
                &s,
                &rustix::net::SocketAddrV4::new(std::net::Ipv4Addr::LOCALHOST, 0),
            )
            .is_err()
        }),
    ));
    out.push((
        "mounts nothing",
        rustix::mount::mount(
            "none",
            outside,
            "tmpfs",
            rustix::mount::MountFlags::empty(),
            None,
        )
        .is_err(),
    ));
    out.push(("no ptrace", velarx_sys::probe::ptrace_traceme().is_err()));
    out.push(("no namespace", velarx_sys::probe::clone_new_user().is_err()));
    out.push((
        "no io_uring",
        velarx_sys::probe::io_uring_setup().err() == Some(libc::EPERM),
    ));
    let parent = rustix::process::getppid().map_or(0, |p| p.as_raw_nonzero().get());
    out.push((
        "signals no process outside",
        velarx_sys::probe::kill_nothing(parent) == Err(libc::EPERM),
    ));
    out.push((
        "signals no process at all but itself",
        velarx_sys::probe::kill_nothing(-1) == Err(libc::EPERM),
    ));
    out.push((
        "signals itself",
        rustix::process::test_kill_process(rustix::process::getpid()).is_ok(),
    ));
    out.push(("makes threads", velarx_sys::probe::a_thread_runs()));
    // (what the kernel says of every thread: the process is confined, not a
    // thread of it)
    out.push((
        "no_new_privs",
        velarx_sys::probe::every_thread_has("NoNewPrivs", "1"),
    ));
    out.push((
        "no capability",
        velarx_sys::probe::every_thread_has("CapEff", "0000000000000000"),
    ));
    out.push((
        "seccomp filter mode",
        velarx_sys::probe::every_thread_has("Seccomp", "2"),
    ));
    out
}
