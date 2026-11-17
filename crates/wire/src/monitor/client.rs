// SPDX-License-Identifier: Apache-2.0
//! Talking to a monitor (`org.velarx.Monitor`): the calls of the engine, and
//! the attach and exec sessions of `run`, `start -a`, `attach` and `exec`.
//! Blocking and std-only, so that the client binary can use it.
//!
//! Every connection starts with `GetInfo`: a monitor whose interface is not
//! the one of this build (one that outlived an upgrade) is refused with
//! [`MonitorError::Version`], which names both versions.

use std::io;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::{Duration, Instant};

use super::iface::{self, Rpc};
use super::proto::{self, Attach, CheckpointRequest, ExecRequest, Health, MonitorUpdate, Status};
use crate::varlink::{CallError, Conn};

/// How long `GetInfo` may take.
const INFO_TIMEOUT: Duration = Duration::from_secs(10);
/// How long a call may take (a start or a checkpoint runs the runtime).
const CALL_TIMEOUT: Duration = Duration::from_secs(130);

/// Why a monitor did not do what it was asked, in an `io::Error` (of the
/// kind `Other`; [`monitor_error`] finds it).
#[derive(Debug)]
pub enum MonitorError {
    /// The monitor speaks another interface: it is of another version of
    /// velarx, which started the container before an upgrade.
    Version { monitor: String, ours: String },
    /// An error of the interface (`org.velarx.Monitor.NotRunning`...).
    Remote { error: String, reason: String },
    /// The monitor broke the protocol.
    Protocol(String),
}

impl std::fmt::Display for MonitorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MonitorError::Version { monitor, ours } => write!(
                f,
                "the monitor of the container is {monitor}, this is {ours}: their interfaces \
                 differ (stop the container and start it again to use this version)"
            ),
            MonitorError::Remote { reason, .. } if !reason.is_empty() => write!(f, "{reason}"),
            MonitorError::Remote { error, .. } => write!(f, "the monitor: {error}"),
            MonitorError::Protocol(m) => write!(f, "the monitor broke the protocol: {m}"),
        }
    }
}

impl std::error::Error for MonitorError {}

impl MonitorError {
    /// An error of the interface named `name`.
    pub fn is(&self, name: &str) -> bool {
        matches!(self, MonitorError::Remote { error, .. } if error == name)
    }

    /// The condition of the engine's interface the error is, when it is
    /// one.
    pub fn condition(&self) -> Option<velarx_proto::engine::Condition> {
        self.is(iface::error::NOT_STARTED)
            .then_some(velarx_proto::engine::Condition::NotStarted)
    }
}

/// The error of the monitor in `e`, if it is one.
pub fn monitor_error(e: &io::Error) -> Option<&MonitorError> {
    e.get_ref()?.downcast_ref::<MonitorError>()
}

/// Whether `e` is the error `name` of the interface.
pub fn is_error(e: &io::Error, name: &str) -> bool {
    monitor_error(e).is_some_and(|m| m.is(name))
}

fn io_error(e: CallError) -> io::Error {
    match e {
        CallError::Io(e) => e,
        CallError::Protocol(m) => io::Error::other(MonitorError::Protocol(m)),
        CallError::Remote { error, reason } => {
            io::Error::other(MonitorError::Remote { error, reason })
        }
    }
}

/// What this build is, as [`MonitorError::Version`] names it.
pub fn this_version() -> String {
    format!(
        "velarx {} ({})",
        env!("CARGO_PKG_VERSION"),
        velarx_base::buildinfo::commit()
    )
}

/// The socket of the monitor in the run directory `dir` (a path of a run
/// directory can be longer than a socket address allows: through a
/// descriptor of the directory).
fn connect_socket(dir: &Path) -> io::Result<UnixStream> {
    let dirfd = rustix::fs::open(
        dir,
        rustix::fs::OFlags::PATH | rustix::fs::OFlags::DIRECTORY | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )?;
    UnixStream::connect(proto::socket_path(&dirfd, proto::SOCKET))
}

/// The process of the monitor that serves the socket of `dir` (the kernel
/// says who listens on it), whatever its version.  A pid: the monitor may
/// end and its pid be taken by another process before it is used; see
/// [`monitor_pidfd`].
pub fn monitor_pid(dir: &Path) -> io::Result<i32> {
    let cred = rustix::net::sockopt::socket_peercred(&monitor_stream(dir)?)?;
    Ok(cred.pid.as_raw_nonzero().get())
}

/// A pidfd of the monitor that serves the socket of `dir`, whatever its
/// version: that monitor even once it has ended (a monitor of another
/// version holds no lock that would tell it, see `live_monitor`).
pub fn monitor_pidfd(dir: &Path) -> io::Result<OwnedFd> {
    velarx_sys::pidfd::of_peer(monitor_stream(dir)?)
}

/// A connection to the socket of the monitor of `dir`, whatever its version.
fn monitor_stream(dir: &Path) -> io::Result<UnixStream> {
    connect_socket(dir)
}

/// A connection to the monitor in `dir` that said who it is: its interface is
/// this build's (`core`: its core is this build's, which is all the core
/// calls need), and it runs as this user or as root.
fn connect_for(dir: &Path, core: bool, digest: &str) -> io::Result<Conn> {
    let stream = connect_socket(dir)?;
    let peer = rustix::net::sockopt::socket_peercred(&stream)?.uid.as_raw();
    let ours = rustix::process::getuid().as_raw();
    if peer != ours && peer != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "the socket of the monitor in {} is of user {peer}",
                dir.display()
            ),
        ));
    }
    let mut conn = Conn::from_stream(stream);
    conn.set_deadline(Instant::now() + INFO_TIMEOUT);
    let (info, _) = conn
        .call_method(&iface::GetInfo {}, &[])
        .map_err(io_error)?;
    let speaks = if core {
        info.core == iface::CORE
    } else {
        info.core == iface::CORE && info.digest == digest
    };
    if !speaks {
        return Err(io::Error::other(MonitorError::Version {
            monitor: format!("velarx {} ({})", info.version, info.commit),
            ours: this_version(),
        }));
    }
    conn.clear_deadline();
    Ok(conn)
}

/// A connection to the monitor in `dir` for every call: its definition is
/// this build's.
pub fn connect(dir: &Path) -> io::Result<Conn> {
    connect_for(dir, false, &iface::interface_digest())
}

/// One call on a connection of its own, and its reply.  A core call is made
/// to a monitor whose core is this build's; any other, to one whose whole
/// definition is.
pub fn call<M: Rpc>(dir: &Path, m: &M) -> io::Result<M::Reply> {
    call_speaking(dir, &iface::interface_digest(), m)
}

/// [`call`] as a client that speaks the definition of `digest` (a client of
/// another version of velarx): for the tests of the core.
pub fn call_speaking<M: Rpc>(dir: &Path, digest: &str, m: &M) -> io::Result<M::Reply> {
    call_with(dir, digest, m, &[])
}

/// [`call`] with descriptors the call names by their position.
pub fn call_fds<M: Rpc>(dir: &Path, m: &M, fds: &[BorrowedFd<'_>]) -> io::Result<M::Reply> {
    call_with(dir, &iface::interface_digest(), m, fds)
}

fn call_with<M: Rpc>(
    dir: &Path,
    digest: &str,
    m: &M,
    fds: &[BorrowedFd<'_>],
) -> io::Result<M::Reply> {
    let mut conn = connect_for(dir, M::CORE, digest)?;
    if !M::WAITS {
        conn.set_deadline(Instant::now() + CALL_TIMEOUT);
    }
    Ok(conn.call_method(m, fds).map_err(io_error)?.0)
}

/// What the monitor knows of the container, whatever its version (the
/// core).
pub fn core_status(dir: &Path) -> io::Result<proto::CoreStatus> {
    Ok(call(dir, &iface::GetCoreStatus {})?.status)
}

/// Stop the container (the core): see `Stop` in the interface.  The reply
/// comes when the container exited and its exit is recorded.
pub fn stop(
    dir: &Path,
    signal: Option<i32>,
    timeout_ms: Option<u64>,
) -> io::Result<(proto::CoreStatus, bool)> {
    let r = call(dir, &iface::StopParams { signal, timeout_ms })?;
    Ok((r.status, r.killed))
}

/// Remove the container: see `Remove` in the interface.  The reply comes
/// when the container is removed (its status says `settled`).
pub fn remove(
    dir: &Path,
    force: bool,
    timeout_ms: Option<u64>,
    volumes: bool,
) -> io::Result<Status> {
    Ok(call(
        dir,
        &iface::RemoveParams {
            force,
            timeout_ms,
            volumes,
        },
    )?
    .status)
}

/// Send `signal` to the init of the container (the core): the exit that
/// follows is not restarted.
pub fn kill(dir: &Path, signal: i32) -> io::Result<()> {
    call(dir, &iface::KillParams { signal }).map(|_| ())
}

/// Wait for the exit of the container for good and its record (the core).
pub fn wait(dir: &Path) -> io::Result<proto::CoreStatus> {
    Ok(call(dir, &iface::Wait {})?.status)
}

/// What the monitor knows of the container.
pub fn status(dir: &Path) -> io::Result<Status> {
    Ok(call(dir, &iface::GetStatus {})?.status)
}

/// Start the container; with `attach_wait_ms` the start waits for the first
/// client that attaches with `start` (no status then).
pub fn start(dir: &Path, attach_wait_ms: u64) -> io::Result<Option<Status>> {
    Ok(call(dir, &iface::StartParams { attach_wait_ms })?.status)
}

/// End the monitor of a container that was not started.
pub fn quit(dir: &Path) -> io::Result<()> {
    call(dir, &iface::Quit {}).map(|_| ())
}

/// Checkpoint the container.
pub fn checkpoint(
    dir: &Path,
    req: &CheckpointRequest,
    image_dir: BorrowedFd<'_>,
    parent_dir: Option<BorrowedFd<'_>>,
) -> io::Result<Status> {
    let mut req = req.clone();
    req.image_dir = 0;
    req.parent_dir = parent_dir.map(|_| 1);
    let mut fds = vec![image_dir];
    fds.extend(parent_dir);
    Ok(call_fds(dir, &req, &fds)?.status)
}

/// Change what the monitor was given (see `Update`): `resources` is a sealed
/// memory file with the OCI `linux.resources` JSON, named by the call.
///
/// A health check that writes its results to a directory (`HealthUpdate::log_dir`)
/// names it by `log_dir`.
pub fn update(
    dir: &Path,
    u: &MonitorUpdate,
    resources: Option<BorrowedFd<'_>>,
    log_dir: Option<BorrowedFd<'_>>,
) -> io::Result<()> {
    let mut u = u.clone();
    let mut fds: Vec<BorrowedFd<'_>> = Vec::new();
    u.resources = resources.map(|fd| {
        fds.push(fd);
        fds.len() as u32 - 1
    });
    if let (Some(h), Some(fd)) = (u.health.as_mut(), log_dir) {
        fds.push(fd);
        h.log_dir = Some(fds.len() as u32 - 1);
    }
    call_fds(dir, &u, &fds).map(|_| ())
}

/// Freeze the container with the runtime.
pub fn pause(dir: &Path) -> io::Result<Status> {
    Ok(call(dir, &iface::Pause {})?.status)
}

/// Thaw a paused container.
pub fn resume(dir: &Path) -> io::Result<Status> {
    Ok(call(dir, &iface::Resume {})?.status)
}

/// Run the health check now, and its result.
pub fn run_health_check(dir: &Path) -> io::Result<Health> {
    Ok(call(dir, &iface::RunHealthCheck {})?.health)
}

/// Ask the monitor to open its log file again (after the file was rotated
/// by somebody else).
pub fn reopen_log(dir: &Path) -> io::Result<()> {
    call(dir, &iface::ReopenLog {}).map(|_| ())
}

/// The size of the container's terminal.
pub fn resize(dir: &Path, rows: u16, cols: u16) -> io::Result<()> {
    call(dir, &iface::ResizeParams { rows, cols }).map(|_| ())
}

/// A pidfd of the init of the running container of the monitor in `dir`.
pub fn open_init(dir: &Path) -> io::Result<OwnedFd> {
    let mut conn = connect(dir)?;
    conn.set_deadline(Instant::now() + INFO_TIMEOUT);
    let (r, fds) = conn
        .call_method(&iface::OpenInit {}, &[])
        .map_err(io_error)?;
    fds.into_iter()
        .nth(r.pidfd as usize)
        .ok_or_else(|| io::Error::other(MonitorError::Protocol("no pidfd in the reply".into())))
}

/// Subscribe to the events of a monitor: the connection, whose replies are
/// the events, and the status.
pub fn subscribe(dir: &Path) -> io::Result<(Conn, Status)> {
    let mut conn = connect(dir)?;
    conn.set_deadline(Instant::now() + INFO_TIMEOUT);
    conn.send_method(&iface::Subscribe {}, &[])?;
    let first: iface::Subscribed = conn.reply().map_err(io_error)?.parameters;
    let status = first.status.ok_or_else(|| {
        io::Error::other(MonitorError::Protocol(
            "a subscription without a status".into(),
        ))
    })?;
    conn.clear_deadline();
    Ok((conn, status))
}

/// A checkpoint to restore at the creation of the container.
#[derive(Debug)]
pub struct Restore {
    /// The directory of the images, which the runtime also writes its log to.
    pub image_dir: OwnedFd,
    pub tcp_established: bool,
    pub tcp_close: bool,
    pub file_locks: bool,
}

/// The first calls of the engine's own connection of a monitor, written
/// before the monitor starts (it is the monitor's `--varlink-fd`): `Create`,
/// whose reply is the result of the creation, and `Subscribe`.
pub fn write_boot_calls(stream: &UnixStream, restore: Option<&Restore>) -> io::Result<()> {
    let mut conn = Conn::from_stream(stream.try_clone()?);
    let params = proto::CreateParams {
        restore: restore.map(|r| proto::RestoreRequest {
            image_dir: 0,
            tcp_established: r.tcp_established,
            tcp_close: r.tcp_close,
            file_locks: r.file_locks,
        }),
    };
    let fds: Vec<BorrowedFd<'_>> = restore.iter().map(|r| r.image_dir.as_fd()).collect();
    conn.send_method(&params, &fds)?;
    conn.send_method(&iface::Subscribe {}, &[])
}

/// The pipes of a session.
#[derive(Debug, Default)]
pub struct Streams {
    /// What goes to the input (the write end).
    pub stdin: Option<OwnedFd>,
    /// The output (with a terminal, what it shows).
    pub stdout: Option<OwnedFd>,
    pub stderr: Option<OwnedFd>,
}

/// The descriptor at `pos` among `fds`: the connected stream socket of a
/// stream (one way: the monitor shut the other down), or a pipe (the input
/// of a command, passed on).
fn pipe_at(fds: &mut [Option<OwnedFd>], pos: Option<u32>) -> io::Result<Option<OwnedFd>> {
    let Some(pos) = pos else { return Ok(None) };
    let bad = |m: &str| io::Error::other(MonitorError::Protocol(m.into()));
    let fd = fds
        .get_mut(pos as usize)
        .and_then(Option::take)
        .ok_or_else(|| bad("a stream that is not among the descriptors"))?;
    let st = rustix::fs::fstat(&fd)?;
    let kind = rustix::fs::FileType::from_raw_mode(st.st_mode);
    let stream = kind.is_socket()
        && rustix::net::sockopt::socket_type(&fd)? == rustix::net::SocketType::STREAM;
    if !stream && !kind.is_fifo() {
        return Err(bad("a stream that is no stream socket nor pipe"));
    }
    Ok(Some(fd))
}

fn streams_of(
    conn: &mut Conn,
    stdin: Option<u32>,
    stdout: Option<u32>,
    stderr: Option<u32>,
) -> io::Result<Streams> {
    let mut fds: Vec<Option<OwnedFd>> = if [stdin, stdout, stderr].iter().any(Option::is_some) {
        conn.take_fds().into_iter().map(Some).collect()
    } else {
        Vec::new()
    };
    Ok(Streams {
        stdin: pipe_at(&mut fds, stdin)?,
        stdout: pipe_at(&mut fds, stdout)?,
        stderr: pipe_at(&mut fds, stderr)?,
    })
}

/// An attach session: its connection (the exit comes on it) and its pipes.
pub struct AttachSession {
    pub conn: Conn,
    pub streams: Streams,
    /// The container had exited already: its status.
    pub exit: Option<i32>,
}

/// Attach to the container of the monitor in `dir`.
pub fn open_attach(dir: &Path, want: &Attach) -> io::Result<AttachSession> {
    let mut conn = connect(dir)?;
    conn.set_deadline(Instant::now() + CALL_TIMEOUT);
    conn.send_method(want, &[])?;
    let first = conn.reply::<iface::AttachReply>().map_err(io_error)?;
    let streams = streams_of(
        &mut conn,
        first.parameters.stdin,
        first.parameters.stdout,
        first.parameters.stderr,
    )?;
    conn.clear_deadline();
    Ok(AttachSession {
        conn,
        streams,
        exit: first.parameters.exit.filter(|_| !first.continues),
    })
}

/// An exec session: its connection (its start and its end come on it;
/// closing it leaves the command running, as `Detach` does) and its pipes.
pub struct ExecSession {
    pub conn: Conn,
    pub streams: Streams,
}

/// Run a command in the container of the monitor in `dir`.
pub fn open_exec(dir: &Path, req: &ExecRequest) -> io::Result<ExecSession> {
    open_exec_with(dir, &[], req)
}

/// [`open_exec`], the call carrying `fds` for the command.
pub fn open_exec_with(dir: &Path, fds: &[OwnedFd], req: &ExecRequest) -> io::Result<ExecSession> {
    let mut conn = connect(dir)?;
    conn.set_deadline(Instant::now() + CALL_TIMEOUT);
    let borrowed: Vec<BorrowedFd<'_>> = fds.iter().map(AsFd::as_fd).collect();
    conn.send_method(req, &borrowed)?;
    let first = conn.reply::<iface::ExecReply>().map_err(io_error)?;
    if !first.continues {
        return Err(io::Error::other(MonitorError::Protocol(
            "an exec session that ended before it began".into(),
        )));
    }
    let streams = streams_of(
        &mut conn,
        first.parameters.stdin,
        first.parameters.stdout,
        first.parameters.stderr,
    )?;
    conn.clear_deadline();
    Ok(ExecSession { conn, streams })
}

/// The next reply of a session: an attach or exec reply, `None` at the end
/// of the connection (the monitor went away).
pub fn next_reply<T: serde::de::DeserializeOwned>(
    conn: &mut Conn,
) -> io::Result<Option<crate::varlink::Reply<T>>> {
    match conn.reply::<T>() {
        Ok(r) => Ok(Some(r)),
        Err(CallError::Io(e))
            if matches!(
                e.kind(),
                io::ErrorKind::UnexpectedEof | io::ErrorKind::ConnectionReset
            ) =>
        {
            Ok(None)
        }
        Err(e) => Err(io_error(e)),
    }
}

pub use velarx_proto::stream::DetachMatcher;

/// A descriptor that is readable once the container of the monitor in `dir`
/// ended (its monitor said so, or went away).
pub fn watch_exit(dir: &Path) -> io::Result<OwnedFd> {
    let mut conn = connect_for(dir, true, &iface::interface_digest())?;
    conn.send_method(&iface::Wait {}, &[])?;
    // (the reply of `Wait` comes when the exit is recorded: the socket is
    // readable then, or closed when the monitor went away)
    Ok(OwnedFd::from(conn.into_parts().0))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};

    #[test]
    fn the_error_of_a_command_that_did_not_start_is_a_condition() {
        use velarx_proto::engine::Condition;
        let remote = |error: &str| MonitorError::Remote {
            error: error.into(),
            reason: "any words".into(),
        };
        assert_eq!(
            remote(iface::error::NOT_STARTED).condition(),
            Some(Condition::NotStarted)
        );
        assert_eq!(remote(iface::error::FAILED).condition(), None);
    }

    /// A monitor of another version: it answers GetInfo with the digest of
    /// another definition.
    use super::iface::Info;

    fn other_monitor(dir: &Path, interface: &str, core: u32) -> std::thread::JoinHandle<()> {
        let listener = std::os::unix::net::UnixListener::bind(dir.join(proto::SOCKET)).unwrap();
        let interface = interface.to_string();
        std::thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let mut buf = [0u8; 512];
            let mut got = Vec::new();
            while !got.contains(&0) {
                let n = s.read(&mut buf).unwrap();
                assert!(n > 0);
                got.extend_from_slice(&buf[..n]);
            }
            assert!(String::from_utf8_lossy(&got).contains("GetInfo"));
            let reply = crate::varlink::encode_reply(
                &Info {
                    version: "0.0.9".into(),
                    commit: "abc1234".into(),
                    core,
                    digest: interface,
                    id: "c".into(),
                },
                false,
            );
            s.write_all(&reply).unwrap();
        })
    }

    #[test]
    fn a_monitor_of_another_interface_is_refused_with_both_versions() {
        let dir = tempfile::tempdir().unwrap();
        let t = other_monitor(dir.path(), "0123456789abcdef", iface::CORE);
        let e = connect(dir.path()).err().unwrap();
        t.join().unwrap();
        let Some(MonitorError::Version { monitor, ours }) = monitor_error(&e) else {
            panic!("{e}");
        };
        assert_eq!(monitor, "velarx 0.0.9 (abc1234)");
        assert_eq!(*ours, this_version());
        assert!(e.to_string().contains("their interfaces differ"), "{e}");
    }

    #[test]
    fn a_monitor_of_this_interface_is_taken() {
        let dir = tempfile::tempdir().unwrap();
        let t = other_monitor(dir.path(), &iface::interface_digest(), iface::CORE);
        assert!(connect(dir.path()).is_ok());
        t.join().unwrap();
    }

    /// The core is made whatever the digest of the definition; a monitor from
    /// before the core is foreign for every call.
    #[test]
    fn the_core_is_made_to_a_monitor_of_another_definition() {
        let dir = tempfile::tempdir().unwrap();
        let t = other_monitor(dir.path(), "0123456789abcdef", iface::CORE);
        assert!(connect_for(dir.path(), true, &iface::interface_digest()).is_ok());
        t.join().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let t = other_monitor(dir.path(), &iface::interface_digest(), 0);
        let e = connect_for(dir.path(), true, &iface::interface_digest())
            .err()
            .unwrap();
        t.join().unwrap();
        assert!(matches!(
            monitor_error(&e),
            Some(MonitorError::Version { .. })
        ));
    }

    /// A stream named among the descriptors must be a stream socket.
    #[test]
    fn the_streams_of_a_reply_are_checked() {
        let (a, b) = UnixStream::pair().unwrap();
        let mut fds = vec![Some(OwnedFd::from(a)), Some(OwnedFd::from(b))];
        assert!(pipe_at(&mut fds, Some(0)).unwrap().is_some());
        // taken already, out of range
        assert!(pipe_at(&mut fds, Some(0)).is_err());
        assert!(pipe_at(&mut fds, Some(7)).is_err());
        assert!(pipe_at(&mut fds, Some(1)).unwrap().is_some());
        let (r, _w) = rustix::pipe::pipe().unwrap();
        let file = tempfile::tempfile().unwrap();
        let dgram = rustix::net::socket(
            rustix::net::AddressFamily::UNIX,
            rustix::net::SocketType::DGRAM,
            None,
        )
        .unwrap();
        let mut fds = vec![Some(r), Some(OwnedFd::from(file)), Some(dgram)];
        assert!(pipe_at(&mut fds, Some(0)).unwrap().is_some());
        assert!(pipe_at(&mut fds, Some(1)).is_err());
        assert!(pipe_at(&mut fds, Some(2)).is_err());
        assert!(pipe_at(&mut fds, None).unwrap().is_none());
    }
}
