// SPDX-License-Identifier: Apache-2.0
//! The connection of a frontend to the engine: a unix socket, the engine's
//! user checked with `SO_PEERCRED`, the version checked with `GetInfo`; and,
//! for a frontend that no service manager activates the engine for, the
//! start of the engine.
//!
//! With systemd the engine is started by its socket: connecting to
//! `engine.sock` is all a frontend does, and the frontend has no unit
//! dependency on the engine.  Without it ([`start_engine`]) the frontend
//! binds the socket under a lock, starts `velarx varlink`
//! with the listener as descriptor 3, and connects; that has to happen before
//! the frontend confines itself, because a confined process cannot execute
//! anything.

use crate::engine::{EngineError, EngineProxy};
use crate::{DIGEST, PROTO};
use std::io;
use std::os::fd::{AsRawFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::time::Duration;
use zlink::futures_util::{Stream, StreamExt};

/// A connection to the engine.
pub type Conn = zlink::Connection<zlink::tokio::unix::Stream>;

/// A connection to the engine that counts in a budget of connections
/// (a semaphore) while it lives: what the REST and CRI frontends hold for
/// the length of a call.
///
/// A connection is checked once (user and version) and then used for any
/// number of calls, one after the other: when a call has been answered in
/// full the caller says so with [`Held::answered`], and the connection goes
/// back to the [`Idle`] set it came from instead of being closed.  A call
/// that was not answered in full (its future dropped, a broken connection,
/// replies not read to the end) leaves nothing to reuse: the connection is
/// closed with the `Held`.
pub struct Held {
    parked: Option<Conn>,
    idle: Idle,
    answered: bool,
    _permit: tokio::sync::OwnedSemaphorePermit,
}

impl Held {
    /// The call on this connection was answered in full: the connection is
    /// for the next one.
    pub fn answered(&mut self) {
        self.answered = true;
    }
}

impl std::ops::Deref for Held {
    type Target = Conn;
    fn deref(&self) -> &Conn {
        self.parked.as_ref().expect("a connection until dropped")
    }
}

impl std::ops::DerefMut for Held {
    fn deref_mut(&mut self) -> &mut Conn {
        self.parked.as_mut().expect("a connection until dropped")
    }
}

impl Drop for Held {
    fn drop(&mut self) {
        if let Some(parked) = self.parked.take().filter(|_| self.answered) {
            self.idle.park(parked);
        }
    }
}

/// The checked connections of a frontend that no call uses now.  A
/// connection is for one call at a time; what the engine ends (it stops, it
/// restarts) is found out when the connection is taken, never used.  An
/// open connection keeps an engine that leaves when idle from leaving, so
/// an idle one is closed after [`IDLE_FOR`].
#[derive(Clone, Default)]
pub struct Idle(std::sync::Arc<std::sync::Mutex<Parked>>);

#[derive(Default)]
struct Parked {
    conns: Vec<(Conn, tokio::time::Instant)>,
    /// A task closes the connections that stayed idle too long
    reaping: bool,
}

/// How many idle connections a frontend keeps.
const IDLE_MAX: usize = 8;

/// How long a connection stays idle at most (twice that, from the call
/// that parked it to the pass that closes it).
const IDLE_FOR: Duration = Duration::from_secs(3);

impl std::fmt::Debug for Idle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Idle({})", self.lock().conns.len())
    }
}

impl Idle {
    fn lock(&self) -> std::sync::MutexGuard<'_, Parked> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn park(&self, conn: Conn) {
        let mut parked = self.lock();
        if parked.conns.len() >= IDLE_MAX {
            return;
        }
        if !parked.reaping {
            // (no runtime to close them in: nothing is kept)
            let Ok(runtime) = tokio::runtime::Handle::try_current() else {
                return;
            };
            parked.reaping = true;
            let idle = self.clone();
            runtime.spawn(async move {
                loop {
                    tokio::time::sleep(IDLE_FOR).await;
                    let mut parked = idle.lock();
                    parked.conns.retain(|(_, since)| since.elapsed() < IDLE_FOR);
                    if parked.conns.is_empty() {
                        parked.reaping = false;
                        return;
                    }
                }
            });
        }
        parked.conns.push((conn, tokio::time::Instant::now()));
    }

    fn take(&self) -> Option<Conn> {
        self.lock().conns.pop().map(|(conn, _)| conn)
    }

    /// A checked connection to the engine by `dial`: one that is idle and
    /// still has the engine at its other end, else a new one.
    pub async fn hold(
        &self,
        dial: &Dial,
        permit: tokio::sync::OwnedSemaphorePermit,
    ) -> Result<Held, ConnectError> {
        while let Some(parked) = self.take() {
            if velarx_sys::fd::peer_silent(parked.read().read_half()) {
                return Ok(self.holding(parked, permit));
            }
        }
        let conn = connect_checked_via(dial).await?;
        Ok(self.holding(conn, permit))
    }

    fn holding(&self, parked: Conn, permit: tokio::sync::OwnedSemaphorePermit) -> Held {
        Held {
            parked: Some(parked),
            idle: self.clone(),
            answered: false,
            _permit: permit,
        }
    }
}

/// The arguments of a call are at most [`MAX_ARG_BYTES`] of JSON (what is
/// larger crosses as a descriptor): the message of the frontend's refusal
/// when they are not.
pub fn args_too_large<T: serde::Serialize + ?Sized>(method: &str, args: &T) -> Option<String> {
    let size = serde_json::to_vec(args).map_or(usize::MAX, |v| v.len());
    (size > crate::engine::MAX_ARG_BYTES).then(|| {
        format!(
            "the arguments of {method} are larger than {} bytes",
            crate::engine::MAX_ARG_BYTES
        )
    })
}

/// How long a frontend waits for the engine to answer `GetInfo`: an engine
/// that was started by its socket opens its database first.
const ANSWER: Duration = Duration::from_secs(60);

/// Why the engine cannot be used.
#[derive(Debug)]
pub enum ConnectError {
    /// Nothing answers on the socket
    Unreachable { socket: PathBuf, source: io::Error },
    /// The engine is served by a user that is not this one or root
    Untrusted { uid: u32 },
    /// The engine is not the version of this frontend, and its binary is
    /// the one installed (it is the newer one: the frontend is to restart)
    Mismatch { engine: String, frontend: String },
    /// The engine answered something else
    Protocol(String),
    /// The engine is about to exit and takes no hold: the end of the hold
    /// it keeps open until it has exited is readable (hangs up) then.
    Stopping {
        gone: std::os::unix::net::UnixStream,
    },
}

impl std::fmt::Display for ConnectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unreachable { socket, source } => {
                write!(
                    f,
                    "the engine does not answer on {}: {source}",
                    socket.display()
                )
            }
            Self::Untrusted { uid } => write!(f, "the engine is served by uid {uid}"),
            Self::Mismatch { engine, frontend } => write!(
                f,
                "this frontend is {frontend} and the engine is {engine}, the one installed: \
                 restart this frontend (the binaries are installed together)"
            ),
            Self::Protocol(m) => write!(f, "the engine: {m}"),
            Self::Stopping { .. } => write!(f, "the engine is stopping"),
        }
    }
}

impl std::error::Error for ConnectError {}

/// Where the engine's socket is reached from: by its path, or through the
/// connector of a process that looks up no path itself (confined).
#[derive(Debug, Clone)]
pub enum Dial {
    Path(PathBuf),
    Connector(std::sync::Arc<velarx_sys::connector::Connector>, PathBuf),
}

impl Dial {
    pub fn socket(&self) -> &Path {
        match self {
            Self::Path(p) | Self::Connector(_, p) => p,
        }
    }

    async fn stream(&self) -> io::Result<tokio::net::UnixStream> {
        match self {
            Self::Path(p) => tokio::net::UnixStream::connect(p).await,
            Self::Connector(c, _) => {
                // (one `sendmsg` and one `recvmsg` with its connector: done on
                // this thread, not on a thread of the runtime's blocking
                // pool, which would outlive the confinement of the process,
                // unconfined)
                let stream = c.connect()?;
                stream.set_nonblocking(true)?;
                tokio::net::UnixStream::from_std(stream)
            }
        }
    }
}

/// A connection to the engine on `socket`, its user checked.
pub async fn connect(socket: &Path) -> Result<Conn, ConnectError> {
    connect_via(&Dial::Path(socket.to_path_buf())).await
}

/// [`connect`] by a [`Dial`].
pub async fn connect_via(dial: &Dial) -> Result<Conn, ConnectError> {
    let unreachable = |source| ConnectError::Unreachable {
        socket: dial.socket().to_path_buf(),
        source,
    };
    let stream = dial.stream().await.map_err(unreachable)?;
    let cred = stream.peer_cred().map_err(unreachable)?;
    if !crate::trusted_uid(cred.uid()) {
        return Err(ConnectError::Untrusted { uid: cred.uid() });
    }
    let stream = zlink::tokio::unix::Stream::try_from(stream)
        .map_err(|e| unreachable(io::Error::other(e)))?;
    Ok(zlink::Connection::new(stream))
}

/// The version this frontend is: the package's, and the interface.
pub fn own_version() -> String {
    format!(
        "{} (interface {PROTO}, {DIGEST})",
        env!("CARGO_PKG_VERSION")
    )
}

/// Ask the engine who it is, and refuse another version (an engine whose
/// answer is not an `InfoReply` is of another version too: one whose
/// `GetInfo` has other members).
pub async fn check(conn: &mut Conn) -> Result<(), ConnectError> {
    let info = match tokio::time::timeout(ANSWER, conn.get_info())
        .await
        .map_err(|_| ConnectError::Protocol("no answer to GetInfo".into()))?
    {
        Err(zlink::Error::Json(e)) => {
            return Err(ConnectError::Mismatch {
                engine: format!("of another version ({e})"),
                frontend: own_version(),
            });
        }
        reply => reply
            .map_err(|e| ConnectError::Protocol(e.to_string()))?
            .map_err(|e: EngineError| ConnectError::Protocol(e.to_string()))?,
    };
    if info.interface != PROTO || info.version != env!("CARGO_PKG_VERSION") || info.digest != DIGEST
    {
        return Err(ConnectError::Mismatch {
            engine: format!(
                "{} (interface {}, {})",
                info.version, info.interface, info.digest
            ),
            frontend: own_version(),
        });
    }
    Ok(())
}

/// A connection to the engine on `socket`, checked: the user and the
/// version.  An engine of another version is asked to start again from the
/// binary installed (after an upgrade it is the old one that runs), and
/// connected to again: it is refused only when it is the one installed.
pub async fn connect_checked(socket: &Path) -> Result<Conn, ConnectError> {
    connect_checked_via(&Dial::Path(socket.to_path_buf())).await
}

/// [`connect_checked`] by a [`Dial`].
pub async fn connect_checked_via(dial: &Dial) -> Result<Conn, ConnectError> {
    let mut conn = connect_via(dial).await?;
    let mismatch = match check(&mut conn).await {
        Ok(()) => return Ok(conn),
        Err(e @ ConnectError::Mismatch { .. }) => e,
        Err(e) => return Err(e),
    };
    // (an engine that went before it answered restarts; one that has no
    // `Restart`, or answers that it runs the binary installed, does not)
    let restarts = match tokio::time::timeout(ANSWER, conn.restart(None)).await {
        Ok(Ok(Ok(r))) => r.restarted,
        Ok(Err(zlink::Error::UnexpectedEof | zlink::Error::Io(_))) => true,
        _ => false,
    };
    if !restarts {
        return Err(mismatch);
    }
    drop(conn);
    // (the engine stops and starts again with its socket, whose clients
    // wait in its queue: one that the old engine took ends at once, and is
    // made again)
    let mut last = mismatch;
    for _ in 0..RECONNECTS {
        let mut conn = connect_via(dial).await?;
        match check(&mut conn).await {
            Ok(()) => return Ok(conn),
            Err(e @ ConnectError::Protocol(_)) => last = e,
            Err(e) => return Err(e),
        }
    }
    Err(last)
}

/// How many times a frontend connects again to an engine that restarts.
const RECONNECTS: usize = 3;

/// The engine this process started: it stops when this is dropped, or when
/// the process ends (the engine reads the end of its lifeline).
#[derive(Debug)]
pub struct Started {
    pub child: std::process::Child,
    _lifeline: std::os::unix::net::UnixStream,
}

/// Hold the engine that is serving `socket` (started by another frontend):
/// it lives while the socket returned is open.  Keep it as long as the
/// frontend lives.
pub async fn hold(socket: &Path) -> Result<std::os::unix::net::UnixStream, ConnectError> {
    let mut conn = connect_checked(socket).await?;
    let (ours, theirs) =
        std::os::unix::net::UnixStream::pair().map_err(|e| ConnectError::Unreachable {
            socket: socket.to_path_buf(),
            source: e,
        })?;
    match conn
        .hold(vec![theirs.into()])
        .await
        .map_err(|e| ConnectError::Protocol(e.to_string()))?
    {
        Ok(_) => Ok(ours),
        // (it keeps its end of the socket until it has exited: the wait for
        // that is an event, not a loop of attempts)
        Err(EngineError::Unavailable { cause, .. }) if cause == crate::engine::STOPPING => {
            Err(ConnectError::Stopping { gone: ours })
        }
        Err(e) => Err(ConnectError::Protocol(e.to_string())),
    }
}

/// Wait until the engine whose hold `gone` came with a [`ConnectError::Stopping`] has
/// exited (the engine closes nothing before: its end hangs up with the
/// process).
pub fn wait_gone(gone: &std::os::unix::net::UnixStream) {
    use rustix::event::{poll, PollFd, PollFlags};
    loop {
        let mut fds = [PollFd::new(gone, PollFlags::IN)];
        match poll(&mut fds, None) {
            Ok(_) => {
                if !fds[0].revents().is_empty() {
                    return;
                }
            }
            Err(rustix::io::Errno::INTR) => {}
            Err(_) => return,
        }
    }
}

/// The lock of whoever binds the engine's socket: next to it.
fn lock_path(socket: &Path) -> PathBuf {
    let mut name = socket.as_os_str().to_owned();
    name.push(".lock");
    PathBuf::from(name)
}

/// The private directory of `socket`, made if need be: mode 0700, ours.
fn private_dir(socket: &Path) -> io::Result<()> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt};
    let dir = socket
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "socket without a directory"))?;
    match std::fs::symlink_metadata(dir) {
        Ok(meta) => {
            if !meta.is_dir()
                || meta.uid() != rustix::process::geteuid().as_raw()
                || meta.mode() & 0o077 != 0
            {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!(
                        "{} must be a directory of this user, mode 0700",
                        dir.display()
                    ),
                ));
            }
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            if let Some(parent) = dir.parent().filter(|p| !p.as_os_str().is_empty()) {
                std::fs::DirBuilder::new()
                    .recursive(true)
                    .mode(0o700)
                    .create(parent)?;
            }
            std::fs::DirBuilder::new().mode(0o700).create(dir)?;
        }
        Err(e) => return Err(e),
    }
    Ok(())
}

/// Start the engine for a process that no service manager activates it
/// for: under the lock of the socket, nothing is started if something
/// serves it, else the socket is bound here and `cmd` is run with the
/// listener as its descriptor 3 and a lifeline as its descriptor 4 (the
/// engine stops when the other end is closed, which the returned [`Started`]
/// holds for as long as it lives, also when this process is killed), in a
/// process group of its own.  Call it before confining the process.
/// Returns what was started, if anything was.
pub fn start_engine(socket: &Path, mut cmd: std::process::Command) -> io::Result<Option<Started>> {
    use std::os::unix::fs::FileTypeExt;
    private_dir(socket)?;
    let lock = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(lock_path(socket))?;
    velarx_sys::flock::flock_retrying(&lock, rustix::fs::FlockOperation::LockExclusive)?;
    if std::os::unix::net::UnixStream::connect(socket).is_ok() {
        return Ok(None);
    }
    match std::fs::symlink_metadata(socket) {
        Ok(meta) if meta.file_type().is_socket() => std::fs::remove_file(socket)?,
        Ok(_) => {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!("{} exists and is not a socket", socket.display()),
            ))
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    let listener = std::os::unix::net::UnixListener::bind(socket)?;
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(socket, std::fs::Permissions::from_mode(0o600))?;
    }
    cmd.stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::inherit());
    std::os::unix::process::CommandExt::process_group(&mut cmd, 0);
    let (alive, lifeline) = std::os::unix::net::UnixStream::pair()?;
    cmd.args(["--lifeline-fd", "4"]);
    let fd = listener.as_raw_fd();
    let life = lifeline.as_raw_fd();
    // (the listener and the lifeline stay open until the command is spawned)
    velarx_sys::spawn::pre_exec(&mut cmd, move |child| {
        // (out of the way of 3 and 4 first)
        let listener = child.dup_cloexec_from(fd, 10)?;
        let life = child.dup_cloexec_from(life, 10)?;
        child.dup2(listener, 3)?;
        child.dup2(life, 4)?;
        Ok(())
    });
    let spawned = cmd.spawn();
    drop(listener);
    drop(lifeline);
    match spawned {
        Ok(child) => Ok(Some(Started {
            child,
            _lifeline: alive,
        })),
        Err(e) => {
            // (nothing would ever accept on it)
            let _ = std::fs::remove_file(socket);
            Err(e)
        }
    }
}

/// An engine kept up for the length of a frontend: the one it started, or
/// the hold on the one another frontend started.  Both end with it.
#[derive(Debug, Default)]
pub struct Kept {
    pub started: Option<Started>,
    _holding: Option<std::os::unix::net::UnixStream>,
}

/// Make sure an engine serves `socket` for as long as the returned [`Kept`]
/// lives: start it with `command` (see [`start_engine`]), or hold the one
/// that serves it.  An engine that is stopping (its frontend went, nobody
/// held it) is waited for and started again.  Call it before confining the
/// process, from a process with no runtime ([`keep_engine_async`] in one).
pub fn keep_engine(
    socket: &Path,
    command: impl Fn() -> std::process::Command,
) -> Result<Kept, String> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| e.to_string())?;
    rt.block_on(keep_engine_async(socket, command))
}

/// [`keep_engine`] on the runtime of the caller.
pub async fn keep_engine_async(
    socket: &Path,
    command: impl Fn() -> std::process::Command,
) -> Result<Kept, String> {
    let mut kept = Kept::default();
    // (one that exited between the start and the hold is started again)
    let mut gone_meanwhile = 0;
    loop {
        match start_engine(socket, command()) {
            Ok(Some(started)) => {
                kept.started = Some(started);
                return Ok(kept);
            }
            Ok(None) => {}
            Err(e) => {
                return Err(format!(
                    "cannot start the engine on {}: {e}",
                    socket.display()
                ))
            }
        }
        match hold(socket).await {
            Ok(hold) => {
                kept._holding = Some(hold);
                return Ok(kept);
            }
            Err(ConnectError::Stopping { gone }) => wait_gone(&gone),
            // (or closed its socket as this connected)
            Err(ConnectError::Unreachable { .. } | ConnectError::Protocol(_))
                if gone_meanwhile < 50 =>
            {
                gone_meanwhile += 1;
            }
            Err(e) => {
                // (it serves: the frontend goes on without a hold)
                tracing::warn!("cannot hold the engine: {e:?}");
                return Ok(kept);
            }
        }
    }
}

/// The records of the replies of a list (a `more` call of the proxy), until
/// the last; `take` gets one out of a reply (none in the one reply of an
/// empty list).  An error of the engine ends them.
pub async fn records<T, R>(
    replies: impl Stream<Item = zlink::Result<Result<T, EngineError>>>,
    take: fn(T) -> Option<R>,
) -> zlink::Result<Result<Vec<R>, EngineError>> {
    let mut replies = std::pin::pin!(replies);
    let mut out = Vec::new();
    while let Some(reply) = replies.next().await {
        match reply? {
            Ok(reply) => out.extend(take(reply)),
            Err(e) => return Ok(Err(e)),
        }
    }
    Ok(Ok(out))
}

/// The replies of a call with more as they come, to `tx`, until the last or
/// until the receiver is dropped (the connection is closed then, which ends
/// the call).
pub async fn replies_to<T>(
    replies: impl Stream<Item = zlink::Result<Result<T, EngineError>>>,
    tx: tokio::sync::mpsc::Sender<T>,
) -> zlink::Result<Result<(), EngineError>> {
    let mut replies = std::pin::pin!(replies);
    loop {
        let received = tokio::select! {
            received = replies.next() => received,
            () = tx.closed() => return Ok(Ok(())),
        };
        match received {
            None => return Ok(Ok(())),
            Some(Err(e)) => return Err(e),
            Some(Ok(Err(e))) => return Ok(Err(e)),
            Some(Ok(Ok(reply))) => {
                if tx.send(reply).await.is_err() {
                    return Ok(Ok(()));
                }
            }
        }
    }
}

/// The read end of a pipe a task fills with `bytes` and closes (the task
/// ends early when the reader goes away): the content of a call that
/// carries a pipe.
pub fn filled_pipe(bytes: impl AsRef<[u8]> + Send + 'static) -> io::Result<OwnedFd> {
    use tokio::io::AsyncWriteExt;
    let (read, write) = rustix::pipe::pipe_with(rustix::pipe::PipeFlags::CLOEXEC)?;
    // (all of it in the pipe when the system lets it)
    let _ = rustix::pipe::fcntl_setpipe_size(&write, bytes.as_ref().len().max(4096));
    let mut sender = tokio::net::unix::pipe::Sender::from_owned_fd(write)?;
    tokio::spawn(async move {
        let _ = sender.write_all(bytes.as_ref()).await;
    });
    Ok(read)
}

/// The descriptors the engine passes with a reply, a file or a pipe each:
/// the one at `index`, taken out of `fds`.
pub fn take_fd(fds: Vec<OwnedFd>, index: u32) -> Option<OwnedFd> {
    fds.into_iter().nth(index as usize)
}

#[cfg(test)]
mod tests {
    /// The refusal of a connection over a limit (written by the services'
    /// accept loop, which knows only the interface the call names) is the
    /// `Unavailable` of the engine for its client.
    #[tokio::test]
    async fn a_refused_connection_is_unavailable() {
        use crate::engine::{EngineError, EngineProxy};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (a, mut b) = tokio::net::UnixStream::pair().unwrap();
        let mut client = zlink::Connection::new(zlink::tokio::unix::Stream::try_from(a).unwrap());
        let server = tokio::spawn(async move {
            let mut call = [0u8; 256];
            let _ = b.read(&mut call).await.unwrap();
            let refusal = br#"{"error":"org.velarx.Engine.Unavailable","parameters":{"reason":"too many connections (64)","cause":"too many connections","message":"too many connections (64)"}}"#;
            b.write_all(refusal).await.unwrap();
            b.write_all(b"\0").await.unwrap();
        });
        match client.ping().await.unwrap() {
            Err(EngineError::Unavailable { cause, message }) => {
                assert_eq!(cause, "too many connections");
                assert!(message.contains("64"), "{message}");
            }
            other => panic!("{other:?}"),
        }
        server.await.unwrap();
    }

    /// A descriptor that crosses a varlink connection is close-on-exec in
    /// the receiver: zlink-core's `recvmsg` (vendor/zlink-core) asks the
    /// kernel for it, so that a process the receiver starts does not inherit
    /// a lifeline or a socket of the peer.
    #[tokio::test]
    async fn received_descriptors_are_close_on_exec() {
        use rustix::io::{fcntl_getfd, FdFlags};
        let (a, b) = tokio::net::UnixStream::pair().unwrap();
        let mut client = zlink::Connection::new(zlink::tokio::unix::Stream::try_from(a).unwrap());
        let mut server = zlink::Connection::new(zlink::tokio::unix::Stream::try_from(b).unwrap());
        // (created without CLOEXEC: it is the receiver's flag that is tested)
        let (r, w) = rustix::pipe::pipe().unwrap();
        for fd in [&r, &w] {
            assert!(!fcntl_getfd(fd).unwrap().contains(FdFlags::CLOEXEC));
        }
        let call = zlink::Call::new(serde_json::json!({
            "method": "org.velarx.Test.Pass",
            "parameters": {},
        }));
        client.send_call(&call, vec![r, w]).await.unwrap();
        let (_, fds) = server.receive_call::<serde_json::Value>().await.unwrap();
        assert_eq!(fds.len(), 2);
        for fd in &fds {
            assert!(
                fcntl_getfd(fd).unwrap().contains(FdFlags::CLOEXEC),
                "a received descriptor is not close-on-exec"
            );
        }
    }

    use super::*;
    use crate::{DIGEST, PROTO};
    use std::os::unix::fs::DirBuilderExt;
    use std::time::Instant;

    /// What the file at `path` holds once it has `what` (10 s at most):
    /// inotify on its directory, no interval.
    fn wait_for(path: &Path, what: &str) -> String {
        use rustix::event::{poll, PollFd, PollFlags, Timespec};
        use rustix::fs::inotify;
        let fd =
            inotify::init(inotify::CreateFlags::CLOEXEC | inotify::CreateFlags::NONBLOCK).unwrap();
        inotify::add_watch(
            &fd,
            path.parent().unwrap(),
            inotify::WatchFlags::MODIFY
                | inotify::WatchFlags::CREATE
                | inotify::WatchFlags::MOVED_TO
                | inotify::WatchFlags::CLOSE_WRITE,
        )
        .unwrap();
        let until = Instant::now() + Duration::from_secs(10);
        loop {
            let text = std::fs::read_to_string(path).unwrap_or_default();
            let left = until.saturating_duration_since(Instant::now());
            if text.contains(what) || left.is_zero() {
                return text;
            }
            let timeout = Timespec {
                tv_sec: left.as_secs() as i64,
                tv_nsec: left.subsec_nanos() as i64,
            };
            let _ = poll(&mut [PollFd::new(&fd, PollFlags::IN)], Some(&timeout));
            let mut buf = [0u8; 4096];
            while rustix::io::read(&fd, &mut buf).is_ok_and(|n| n > 0) {}
        }
    }

    /// The engine a frontend starts gets the listening socket as its
    /// descriptor 3 and the lifeline as 4; nothing is started when something
    /// serves the socket; and the engine sees the lifeline closed when the
    /// frontend lets go of what it started.
    #[test]
    fn the_engine_started_has_the_socket_and_a_lifeline() {
        let dir = tempfile::tempdir().unwrap();
        let private = dir.path().join("run");
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&private)
            .unwrap();
        let socket = private.join("engine.sock");
        let marker = dir.path().join("marker");
        // a stand-in for the engine: it says what it has, and waits for the
        // end of the lifeline
        let script = r#"[ -S /dev/fd/3 ] && echo socket > "$1"; read _ <&4; echo closed >> "$1""#;
        let command = || {
            let mut cmd = std::process::Command::new("sh");
            cmd.args(["-c", script, "sh"]).arg(&marker);
            cmd
        };
        let started = start_engine(&socket, command()).unwrap().expect("started");
        assert_eq!(wait_for(&marker, "socket").trim(), "socket");
        assert!(
            std::os::unix::net::UnixStream::connect(&socket).is_ok(),
            "the socket listens"
        );
        // under the lock, a socket that answers is served: nothing starts
        assert!(start_engine(&socket, command()).unwrap().is_none());
        assert!(!std::fs::read_to_string(&marker).unwrap().contains("closed"));
        drop(started);
        assert_eq!(wait_for(&marker, "closed").trim(), "socket\nclosed");
    }

    /// An engine that cannot be started leaves no socket behind.
    #[test]
    fn a_command_that_cannot_run_leaves_no_socket() {
        let dir = tempfile::tempdir().unwrap();
        let private = dir.path().join("run");
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&private)
            .unwrap();
        let socket = private.join("engine.sock");
        let cmd = std::process::Command::new("/nonexistent/velarx");
        assert!(start_engine(&socket, cmd).is_err());
        assert!(!socket.exists());
    }

    /// The directory of the socket must be its user's and private.
    #[test]
    fn the_directory_of_the_socket_is_private() {
        let dir = tempfile::tempdir().unwrap();
        let open = dir.path().join("open");
        std::fs::DirBuilder::new()
            .mode(0o755)
            .create(&open)
            .unwrap();
        let cmd = std::process::Command::new("true");
        let e = start_engine(&open.join("engine.sock"), cmd).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::PermissionDenied, "{e}");
    }

    mod mock {
        use crate::engine::InfoReply;

        /// An engine that only says who it is.
        #[derive(Clone)]
        pub struct Mock(pub InfoReply);

        #[zlink::service(
            interface = "org.velarx.Engine",
            vendor = "org.velarx",
            product = "mock",
            version = "0",
            url = "https://example.org"
        )]
        impl Mock {
            async fn get_info(&self) -> InfoReply {
                self.0.clone()
            }
        }

        /// An engine that says who it is and answers pings, counting the
        /// connections it was asked who it is on.
        #[derive(Clone)]
        pub struct Counting(
            pub InfoReply,
            pub std::sync::Arc<std::sync::atomic::AtomicUsize>,
        );

        #[zlink::service(
            interface = "org.velarx.Engine",
            vendor = "org.velarx",
            product = "mock",
            version = "0",
            url = "https://example.org"
        )]
        impl Counting {
            async fn get_info(&self) -> InfoReply {
                self.1.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                self.0.clone()
            }

            async fn ping(&self) -> crate::engine::Ack {
                crate::engine::Ack {}
            }
        }

        /// An engine of another version whose binary was replaced by this
        /// one's: `Restart` makes it this version.
        #[derive(Clone)]
        pub struct Upgraded {
            pub old: InfoReply,
            pub new: InfoReply,
            pub restarted: std::sync::Arc<std::sync::atomic::AtomicBool>,
        }

        #[zlink::service(
            interface = "org.velarx.Engine",
            vendor = "org.velarx",
            product = "mock",
            version = "0",
            url = "https://example.org"
        )]
        impl Upgraded {
            async fn get_info(&self) -> InfoReply {
                if self.restarted.load(std::sync::atomic::Ordering::SeqCst) {
                    self.new.clone()
                } else {
                    self.old.clone()
                }
            }

            async fn restart(&self) -> crate::engine::Restarted {
                self.restarted
                    .store(true, std::sync::atomic::Ordering::SeqCst);
                crate::engine::Restarted { restarted: true }
            }
        }
    }

    /// A frontend checks the engine once for a connection and uses the
    /// connection for the calls that follow, one after the other: a call
    /// that was not answered in full leaves nothing to reuse, a connection
    /// whose engine went is not taken, and an idle connection is closed
    /// after a while (an engine that leaves when idle can).
    #[tokio::test]
    async fn a_checked_connection_serves_the_calls_that_follow() {
        use crate::engine::InfoReply;
        use std::sync::atomic::{AtomicUsize, Ordering};
        let own = InfoReply {
            name: "velarx".into(),
            version: env!("CARGO_PKG_VERSION").into(),
            interface: PROTO,
            digest: DIGEST.into(),
            rootful: false,
        };
        tokio::task::LocalSet::new()
            .run_until(async {
                let dir = tempfile::tempdir().unwrap();
                let socket = dir.path().join("engine.sock");
                let listener = tokio::net::UnixListener::bind(&socket).unwrap();
                let checked = std::sync::Arc::new(AtomicUsize::new(0));
                let mock = mock::Counting(own, checked.clone());
                // (what the engine serves, to end its connections)
                let served = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
                let serving = served.clone();
                let accepting = tokio::task::spawn_local(async move {
                    loop {
                        let (stream, _) = listener.accept().await.unwrap();
                        let stream = zlink::tokio::unix::Stream::try_from(stream).unwrap();
                        let server =
                            zlink::Server::new(zlink::ReadyListener::new(stream), mock.clone());
                        serving
                            .borrow_mut()
                            .push(tokio::task::spawn_local(async move {
                                let _ = server.run().await;
                            }));
                    }
                });
                let idle = Idle::default();
                let permits = std::sync::Arc::new(tokio::sync::Semaphore::new(4));
                let hold = || async {
                    let permit = permits.clone().acquire_owned().await.unwrap();
                    idle.hold(&Dial::Path(socket.clone()), permit)
                        .await
                        .unwrap()
                };
                let ping = || async {
                    let mut call = hold().await;
                    call.ping().await.unwrap().unwrap();
                    call.answered();
                };
                // answered in full: the next call has the connection
                for _ in 0..3 {
                    ping().await;
                }
                assert_eq!(checked.load(Ordering::SeqCst), 1);
                // not answered in full (its future dropped): closed
                drop(hold().await);
                assert_eq!(idle.lock().conns.len(), 0);
                ping().await;
                assert_eq!(checked.load(Ordering::SeqCst), 2);
                assert_eq!(idle.lock().conns.len(), 1);
                // the engine ends the connection: it is found out when the
                // connection is taken, and a new one is made
                let open: Vec<_> = served.borrow_mut().drain(..).collect();
                for conn in open {
                    conn.abort();
                    let _ = conn.await;
                }
                ping().await;
                assert_eq!(checked.load(Ordering::SeqCst), 3);
                // idle long enough, the connection is closed (the clock is
                // moved, not waited for), and the engine sees it end
                tokio::time::pause();
                tokio::time::advance(IDLE_FOR * 2).await;
                let open: Vec<_> = served.borrow_mut().drain(..).collect();
                for conn in open {
                    conn.await.unwrap();
                }
                assert_eq!(idle.lock().conns.len(), 0);
                assert!(!idle.lock().reaping);
                accepting.abort();
            })
            .await;
    }

    /// After an upgrade the engine that runs is the old one: a frontend of
    /// the new one asks it to start again from the binary installed, and
    /// uses it once it is of its version.
    #[tokio::test]
    async fn an_engine_of_the_old_version_is_restarted() {
        use crate::engine::InfoReply;
        let new = InfoReply {
            name: "velarx".into(),
            version: env!("CARGO_PKG_VERSION").into(),
            interface: PROTO,
            digest: DIGEST.into(),
            rootful: false,
        };
        let old = InfoReply {
            version: "0.0.1".into(),
            digest: "0123456789abcdef".into(),
            ..new.clone()
        };
        tokio::task::LocalSet::new()
            .run_until(async {
                let dir = tempfile::tempdir().unwrap();
                let socket = dir.path().join("engine.sock");
                let listener = tokio::net::UnixListener::bind(&socket).unwrap();
                let restarted = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
                let mock = mock::Upgraded {
                    old,
                    new,
                    restarted: restarted.clone(),
                };
                tokio::task::spawn_local(async move {
                    loop {
                        let (stream, _) = listener.accept().await.unwrap();
                        let stream = zlink::tokio::unix::Stream::try_from(stream).unwrap();
                        let server =
                            zlink::Server::new(zlink::ReadyListener::new(stream), mock.clone());
                        tokio::task::spawn_local(async move {
                            let _ = server.run().await;
                        });
                    }
                });
                let mut conn = connect_checked(&socket).await.unwrap();
                assert!(restarted.load(std::sync::atomic::Ordering::SeqCst));
                let info = conn.get_info().await.unwrap().unwrap();
                assert_eq!(info.digest, DIGEST);
            })
            .await;
    }

    /// An engine whose `GetInfo` answers other members is of another
    /// version: asked to start again, and refused when it runs the binary
    /// installed.
    #[tokio::test]
    async fn an_engine_whose_info_is_another_is_of_another_version() {
        use std::io::{BufRead, BufReader, Write};
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("engine.sock");
        let listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
        let engine = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut methods = Vec::new();
            for reply in [
                r#"{"parameters": {"version": "0.0.1"}}"#,
                r#"{"parameters": {"restarted": false}}"#,
            ] {
                let mut message = Vec::new();
                reader.read_until(0, &mut message).unwrap();
                message.pop();
                let call: serde_json::Value = serde_json::from_slice(&message).unwrap();
                methods.push(call["method"].as_str().unwrap().to_string());
                stream.write_all(reply.as_bytes()).unwrap();
                stream.write_all(&[0]).unwrap();
            }
            methods
        });
        match connect_checked(&socket).await {
            Err(ConnectError::Mismatch { engine, .. }) => {
                assert!(engine.contains("of another version"), "{engine}")
            }
            other => panic!("{:?}", other.map(|_| ())),
        }
        let methods = engine.join().unwrap();
        assert_eq!(
            methods,
            ["org.velarx.Engine.GetInfo", "org.velarx.Engine.Restart"]
        );
    }

    /// A frontend uses an engine of its own build and refuses another, with
    /// a message that says both.
    #[tokio::test]
    async fn an_engine_of_another_build_is_refused() {
        use crate::engine::InfoReply;
        let own = || InfoReply {
            name: "velarx".into(),
            version: env!("CARGO_PKG_VERSION").into(),
            interface: PROTO,
            digest: DIGEST.into(),
            rootful: false,
        };
        let other_version = InfoReply {
            version: "0.0.1".into(),
            ..own()
        };
        let other_interface = InfoReply {
            interface: PROTO + 1,
            ..own()
        };
        let other_digest = InfoReply {
            digest: "0123456789abcdef".into(),
            ..own()
        };
        tokio::task::LocalSet::new()
            .run_until(async {
                let dir = tempfile::tempdir().unwrap();
                for (n, (info, ok)) in [
                    (own(), true),
                    (other_version, false),
                    (other_interface, false),
                    (other_digest, false),
                ]
                .into_iter()
                .enumerate()
                {
                    let socket = dir.path().join(format!("{n}.sock"));
                    let listener = tokio::net::UnixListener::bind(&socket).unwrap();
                    let mock = mock::Mock(info.clone());
                    tokio::task::spawn_local(async move {
                        let (stream, _) = listener.accept().await.unwrap();
                        let stream = zlink::tokio::unix::Stream::try_from(stream).unwrap();
                        let server = zlink::Server::new(zlink::ReadyListener::new(stream), mock);
                        let _ = server.run().await;
                    });
                    let checked = connect_checked(&socket).await;
                    match (ok, checked) {
                        (true, Ok(_)) => {}
                        (false, Err(ConnectError::Mismatch { engine, frontend })) => {
                            assert!(frontend.contains(DIGEST), "{frontend}");
                            assert!(engine.contains(&info.digest), "{engine}");
                            assert!(engine.contains(&info.version), "{engine}");
                        }
                        (ok, other) => panic!("{ok}: {:?}", other.map(|_| ())),
                    }
                }
            })
            .await;
    }
}
