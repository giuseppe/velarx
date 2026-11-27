// SPDX-License-Identifier: Apache-2.0
//! What a varlink service of velarx needs to run as a process of its own
//! (the store service, the fetchers): the socket from systemd or from the
//! client that started it, one instance for a socket, a loop that leaves
//! when idle, and the connect of a client that starts the service if
//! nothing serves the socket.

use std::io;
use std::os::fd::{AsRawFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tracing::{debug, error, warn};
use velarx_base::ipc::{accept_failure, AcceptFailure, ACCEPT_WAIT};

/// The limits of a service (`[services]` of config.toml; the defaults
/// are its).  A connection over a limit is answered `Unavailable` to its
/// first call and closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// The most connections served at once
    pub connections: usize,
    /// The most connections of one client process at once: one frontend
    /// (or a client that leaks connections) leaves room for the others
    pub per_client: usize,
    /// How long a connection may wait before its first call: one that
    /// sends nothing is closed (it held a connection, and kept the service
    /// from leaving when idle, for ever)
    pub first_call: Duration,
}

impl Limits {
    /// The limits `[services]` of the configuration sets.
    pub fn of(config: &velarx_config::ServicesConfig) -> Self {
        Self {
            connections: config.max_connections,
            per_client: config.max_per_client,
            first_call: Duration::from_secs(config.first_call_secs),
        }
    }
}

impl Default for Limits {
    fn default() -> Self {
        Self::of(&velarx_config::ServicesConfig::default())
    }
}

/// The lock of whoever binds the socket or takes it away: held a moment,
/// never while serving.  Under it, a socket that answers is served, so one
/// instance serves a socket.
pub fn lock_path(socket: &Path) -> PathBuf {
    let mut name = socket.as_os_str().to_owned();
    name.push(".lock");
    PathBuf::from(name)
}

/// The lock of the socket `socket` (blocking: nobody holds it long), next
/// to the socket, in its private directory, made if need be.
pub fn take_lock(socket: &Path) -> io::Result<velarx_sys::flock::Held> {
    if let Some(dir) = socket.parent().filter(|p| !p.as_os_str().is_empty()) {
        velarx_base::ipc::ensure_private_dir(dir)?;
    }
    velarx_storage::locks::lock(&lock_path(socket), true)?
        .ok_or_else(|| io::Error::other("the lock of the socket was not taken"))
}

/// The lock file of `socket`, opened and not held, for
/// [`connect_or_bind_on`].
pub fn open_lock(socket: &Path) -> io::Result<std::fs::File> {
    if let Some(dir) = socket.parent().filter(|p| !p.as_os_str().is_empty()) {
        velarx_base::ipc::ensure_private_dir(dir)?;
    }
    velarx_storage::locks::open_unlocked(&lock_path(socket))
}

/// Take the lock of `socket` on `file`, the lock file opened before.  A
/// lock file replaced or removed since (a lock on it locks nothing others
/// take) is taken again as [`take_lock`] does while the directory of the
/// socket is there; with the directory gone, an error: nothing is made
/// again in its place.
fn hold_lock(socket: &Path, file: std::fs::File) -> io::Result<velarx_sys::flock::Held> {
    use std::os::unix::fs::MetadataExt;
    velarx_sys::flock::flock_retrying(&file, rustix::fs::FlockOperation::LockExclusive)?;
    let held = file.metadata()?;
    let file = velarx_sys::flock::Held::new(file);
    match std::fs::symlink_metadata(lock_path(socket)) {
        Ok(named) if (held.dev(), held.ino()) == (named.dev(), named.ino()) => return Ok(file),
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    drop(file);
    let dir = socket.parent().filter(|p| !p.as_os_str().is_empty());
    if dir.is_some_and(|dir| !dir.is_dir()) {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "the directory of the socket was removed",
        ));
    }
    take_lock(socket)
}

/// The device and inode of the socket file `socket`, for
/// [`remove_own_socket`].
pub fn socket_file_id(socket: &Path) -> Option<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    std::fs::symlink_metadata(socket)
        .ok()
        .map(|m| (m.dev(), m.ino()))
}

/// Take `socket` away, under its lock, if it is still the file `id` (from
/// [`socket_file_id`]) names: a process that ends leaves alone the socket
/// that another one bound in its place (it found this one gone, under the
/// lock, and replaced the file).
pub fn remove_own_socket(socket: &Path, id: Option<(u64, u64)>) {
    // (checked first without the lock: a socket that is not there, or a
    // directory removed meanwhile, is left alone, not made again for a lock)
    if id.is_none() || socket_file_id(socket) != id {
        return;
    }
    let Ok(_lock) = take_lock(socket) else {
        return;
    };
    if socket_file_id(socket) == id {
        let _ = std::fs::remove_file(socket);
    }
}

/// Under the lock: a connection to the instance that serves `socket`, or
/// else the socket, bound here.
pub fn connect_or_bind(
    socket: &Path,
) -> io::Result<Result<std::os::unix::net::UnixStream, std::os::unix::net::UnixListener>> {
    let _lock = take_lock(socket)?;
    connect_or_bind_held(socket)
}

/// [`connect_or_bind`] with the lock file opened before ([`open_lock`]): a
/// wait for the lock that outlives the directory of the socket (the process
/// that waited was stopped, its directory removed) ends with an error and
/// makes neither the directory, the lock nor the socket.
pub fn connect_or_bind_on(
    socket: &Path,
    lock: std::fs::File,
) -> io::Result<Result<std::os::unix::net::UnixStream, std::os::unix::net::UnixListener>> {
    let _lock = hold_lock(socket, lock)?;
    connect_or_bind_held(socket)
}

fn connect_or_bind_held(
    socket: &Path,
) -> io::Result<Result<std::os::unix::net::UnixStream, std::os::unix::net::UnixListener>> {
    match std::os::unix::net::UnixStream::connect(socket) {
        Ok(stream) => Ok(Ok(stream)),
        // (no socket, or one nobody listens on: the instance is gone)
        Err(e)
            if matches!(
                e.kind(),
                io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused
            ) =>
        {
            Ok(Err(velarx_base::ipc::bind_private(socket)?))
        }
        // (any other error says nothing of the instance: taking its socket
        // over could split the service in two)
        Err(e) => Err(e),
    }
}

/// Connections being served and when the last one ended.
pub struct Activity {
    /// How many are served (a watch: [`Activity::wait_idle`])
    active: tokio::sync::watch::Sender<usize>,
    last: Mutex<Instant>,
    ended: tokio::sync::Notify,
    /// Told to stop accepting connections ([`Activity::stop_accepting`])
    draining: tokio::sync::Notify,
    /// Whether the service does not accept connections any more
    closed: tokio::sync::watch::Sender<bool>,
    /// Whether it stopped accepting for the process that follows it: a
    /// connection between two calls ends then, so that its client (a
    /// frontend keeps its connections) connects again, to that process
    handed_over: tokio::sync::watch::Sender<bool>,
    /// Something else keeps the service from leaving (the engine follows
    /// running containers)
    held: AtomicBool,
    /// Work of the service that is not a connection keeps it ([`Keep`])
    kept: std::sync::atomic::AtomicUsize,
    /// The connections of each client
    clients: Mutex<std::collections::HashMap<Client, usize>>,
    /// A connection was served (an [`IdleExit::last`] service leaves at
    /// the end of its last one, never before its first)
    served: AtomicBool,
    limits: Limits,
}

impl Activity {
    pub fn new(limits: Limits) -> Arc<Self> {
        Arc::new(Self {
            active: tokio::sync::watch::channel(0).0,
            last: Mutex::new(Instant::now()),
            ended: tokio::sync::Notify::new(),
            draining: tokio::sync::Notify::new(),
            closed: tokio::sync::watch::channel(false).0,
            handed_over: tokio::sync::watch::channel(false).0,
            held: AtomicBool::new(false),
            kept: std::sync::atomic::AtomicUsize::new(0),
            clients: Mutex::new(std::collections::HashMap::new()),
            served: AtomicBool::new(false),
            limits,
        })
    }

    /// The limits of the service.
    pub fn limits(&self) -> Limits {
        self.limits
    }

    /// While `on`, the service does not leave, whatever the connections:
    /// the time to leave counts from the moment it is released.
    pub fn hold(&self, on: bool) {
        if self.held.swap(on, Ordering::SeqCst) && !on {
            *self.last.lock().unwrap_or_else(|e| e.into_inner()) = Instant::now();
            self.ended.notify_one();
        }
    }

    /// Keep the service from leaving while the result lives (work of its
    /// own, such as the completion of a lazy pull): it is no connection, so
    /// the end of the service does not wait for it.
    pub fn keep(self: &Arc<Self>) -> Keep {
        self.kept.fetch_add(1, Ordering::SeqCst);
        Keep {
            activity: self.clone(),
        }
    }

    /// Stop accepting connections and go on serving those that are open;
    /// the listener closes and the socket stays where it is (a copy of it
    /// is passed to the process that replaces this one, which accepts what
    /// waits in its queue).  Returns once it does not accept any more: a
    /// client that connects after that waits for the next process, not for
    /// an answer of this one.
    pub async fn stop_accepting(&self) {
        self.draining.notify_one();
        let _ = self.closed.subscribe().wait_for(|closed| *closed).await;
    }

    /// Whether the service accepts connections still.
    pub fn accepting(&self) -> bool {
        !*self.closed.borrow()
    }

    /// Since when nothing was served (`None`: something is).
    fn idle_since(&self) -> Option<Instant> {
        if self.active() > 0
            || self.held.load(Ordering::SeqCst)
            || self.kept.load(Ordering::SeqCst) > 0
        {
            return None;
        }
        Some(*self.last.lock().unwrap_or_else(|e| e.into_inner()))
    }

    pub fn active(&self) -> usize {
        *self.active.borrow()
    }

    /// Return once a connection of the ones served now ended (its descriptor
    /// is free again); never when none is served: the caller bounds the
    /// wait.
    async fn one_ended(&self) {
        let mut open = self.active.subscribe();
        let now = *open.borrow_and_update();
        if now == 0 {
            return std::future::pending().await;
        }
        let _ = open.wait_for(|n| *n < now).await;
    }

    /// Keep `other` from leaving while this serves a connection (the
    /// service of the connections that this one counts is held by them).
    /// Never returns while the connections can come.
    pub async fn keep_while_served(self: Arc<Self>, other: Arc<Activity>) {
        let mut active = self.active.subscribe();
        let mut keep = None;
        loop {
            if *active.borrow_and_update() > 0 {
                keep.get_or_insert_with(|| other.keep());
            } else {
                keep = None;
            }
            if active.changed().await.is_err() {
                return;
            }
        }
    }

    /// Return once nothing is served (at once when nothing is).
    pub async fn wait_idle(&self) {
        let _ = self.active.subscribe().wait_for(|n| *n == 0).await;
    }
}

/// What [`Activity::keep`] gives: the service stays while it lives.
pub struct Keep {
    activity: Arc<Activity>,
}

impl Drop for Keep {
    fn drop(&mut self) {
        if self.activity.kept.fetch_sub(1, Ordering::SeqCst) == 1 {
            *self.activity.last.lock().unwrap_or_else(|e| e.into_inner()) = Instant::now();
            self.activity.ended.notify_one();
        }
    }
}

/// Whose connections count together against the limit of a client
/// (`[services] max_per_client`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Client {
    /// The process at the other end of the connections a service accepted
    Process(i32),
}

/// Held while a connection is served (or something else keeps the service
/// busy).
pub struct Busy {
    activity: Arc<Activity>,
    /// The client of the connection
    client: Option<Client>,
}

impl Busy {
    pub fn new(activity: &Arc<Activity>) -> Self {
        activity.served.store(true, Ordering::SeqCst);
        activity.active.send_modify(|n| *n += 1);
        Self {
            activity: activity.clone(),
            client: None,
        }
    }

    /// A connection of `client`, unless the service or that client has as
    /// many as it may: then why not.
    pub fn for_client(activity: &Arc<Activity>, client: Client) -> Result<Self, String> {
        let mut clients = activity.clients.lock().unwrap_or_else(|e| e.into_inner());
        let Limits {
            connections,
            per_client,
            ..
        } = activity.limits;
        // (the connections, not what else keeps the service busy: the call
        // a connection runs, a stream, a hold)
        if clients.values().sum::<usize>() >= connections {
            return Err(format!("too many connections ({connections})"));
        }
        let mine = clients.entry(client).or_default();
        if *mine >= per_client {
            return Err(format!(
                "too many connections of this process ({per_client})"
            ));
        }
        *mine += 1;
        drop(clients);
        let mut busy = Self::new(activity);
        busy.client = Some(client);
        Ok(busy)
    }
}

impl Drop for Busy {
    fn drop(&mut self) {
        if let Some(client) = self.client {
            let mut clients = self
                .activity
                .clients
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            if let Some(n) = clients.get_mut(&client) {
                *n -= 1;
                if *n == 0 {
                    clients.remove(&client);
                }
            }
        }
        *self.activity.last.lock().unwrap_or_else(|e| e.into_inner()) = Instant::now();
        self.activity.active.send_modify(|n| *n -= 1);
        self.activity.ended.notify_one();
    }
}

/// When a service leaves: after `after` without a connection.  `socket` is
/// the path velarx bound its listener on, taken away (under the lock) as
/// it leaves; none for a socket systemd holds, whose clients wait in its
/// queue for the next instance.
///
/// `last`: it leaves when its last connection ends, at once (the
/// connections are what keeps it, as for the fetcher the
/// engine shares between the monitors), and `after` is the most it waits
/// for its first one.  A client that connected (under the lock of the
/// socket) before the socket was taken away is served all the same.
pub struct IdleExit {
    pub after: Duration,
    pub socket: Option<PathBuf>,
    pub last: bool,
    /// The lock of the socket ([`lock_path`]), opened before the service
    /// confined itself (it may not open a file there): taken as it leaves
    pub lock: Option<std::fs::File>,
}

impl IdleExit {
    /// When the service leaves if nothing is served from now on.
    fn deadline(&self, activity: &Activity, started: Instant) -> Option<tokio::time::Instant> {
        let at = if self.last && !activity.served.load(Ordering::SeqCst) {
            started + self.after
        } else if self.last {
            activity.idle_since()?
        } else {
            activity.idle_since()? + self.after
        };
        Some(tokio::time::Instant::from_std(at))
    }
}

/// Accept the `connections` until `idle` says to leave (never,
/// with none): each one that comes from a user `trusted` accepts, within
/// the [`Limits`] of `activity`, is given to `admit` with the
/// [`Busy`] that keeps the service from leaving while it is served; one
/// over a limit is answered `Unavailable` ([`refuse`]).  `admit` runs the connection
/// (in a local task, as the servers of zlink are not `Send`).  Returns when
/// the service left and every connection ended.
pub async fn serve_loop(
    connections: impl Into<Connections>,
    idle: Option<IdleExit>,
    trusted: fn(u32) -> bool,
    activity: Arc<Activity>,
    what: &str,
    admit: impl Fn(tokio::net::UnixStream, Busy),
) {
    let first_call = activity.limits.first_call;
    serve_loop_refusing(
        connections,
        idle,
        trusted,
        activity,
        what,
        admit,
        move |stream, reason| {
            tokio::spawn(refuse(stream, reason, first_call));
        },
    )
    .await;
}

/// [`serve_loop`] for a protocol other than varlink: a connection over a
/// limit is given to `refusal` with the reason.
pub async fn serve_loop_refusing(
    connections: impl Into<Connections>,
    idle: Option<IdleExit>,
    trusted: fn(u32) -> bool,
    activity: Arc<Activity>,
    what: &str,
    admit: impl Fn(tokio::net::UnixStream, Busy),
    refusal: impl Fn(tokio::net::UnixStream, String),
) {
    let mut connections = connections.into();
    let take = |accepted: io::Result<tokio::net::UnixStream>| match accepted {
        Ok(stream) => {
            if let Err(e) = velarx_base::ipc::check_client(&stream, trusted) {
                warn!("{what}: {e}");
                return Ok(());
            }
            let pid = rustix::net::sockopt::socket_peercred(&stream)
                .map_or(0, |c| c.pid.as_raw_nonzero().get());
            match Busy::for_client(&activity, Client::Process(pid)) {
                Ok(busy) => {
                    bound_queued_replies(&stream);
                    admit(stream, busy);
                }
                Err(reason) => {
                    warn!("{what}: a connection of process {pid} refused: {reason}");
                    refusal(stream, reason);
                }
            }
            Ok(())
        }
        Err(e) => Err(e),
    };
    let mut drained = false;
    let started = Instant::now();
    // (the socket file as it is now: the one taken away as this leaves)
    let bound = idle
        .as_ref()
        .and_then(|i| i.socket.as_deref())
        .and_then(socket_file_id);
    loop {
        let deadline = idle.as_ref().and_then(|i| i.deadline(&activity, started));
        // (in this order: a connection that waits is taken before the
        // service decides it has nothing to serve)
        tokio::select! {
            biased;
            () = activity.draining.notified() => {
                drained = true;
                break;
            }
            accepted = connections.accept() => {
                if let Err(e) = take(accepted) {
                    match accept_failure(&e) {
                        AcceptFailure::Retry => {
                            debug!("{what}: a connection went away before it was accepted: {e}");
                        }
                        AcceptFailure::Wait => {
                            warn!("{what}: cannot accept a connection: {e}");
                            // (the connection stays queued: a descriptor is
                            // free once one that is served ends, or once
                            // another process gave back what the host was
                            // out of)
                            tokio::select! {
                                () = activity.one_ended() => {}
                                () = tokio::time::sleep(ACCEPT_WAIT) => {}
                                () = activity.draining.notified() => {
                                    drained = true;
                                    break;
                                }
                            }
                        }
                        AcceptFailure::Broken => {
                            error!("{what}: cannot accept a connection: {e}");
                            break;
                        }
                    }
                }
            }
            _ = activity.ended.notified() => {}
            _ = tokio::time::sleep_until(deadline.unwrap_or_else(tokio::time::Instant::now)),
                if deadline.is_some() => break,
        }
    }
    debug!("{what}: leaving");
    activity.handed_over.send_replace(drained);
    activity.closed.send_replace(true);
    if let Some((socket, lock)) = idle
        .and_then(|i| Some((i.socket?, i.lock)))
        .filter(|_| !drained)
    {
        // nobody connects once the socket is gone; who did before is served
        let gone = tokio::task::spawn_blocking(move || {
            let _lock = match lock {
                Some(file) => hold_lock(&socket, file)?,
                None => take_lock(&socket)?,
            };
            if bound.is_some() && socket_file_id(&socket) == bound {
                std::fs::remove_file(&socket)?;
            }
            Ok::<(), io::Error>(())
        })
        .await;
        if let Ok(Err(e)) | Err(e) = gone.map_err(io::Error::other) {
            warn!("{what}: cannot take the socket away: {e}");
        }
        // (accepted here, not by the loop: what the queue holds is taken
        // whether or not the runtime was told of it yet)
        while let Some(accepted) = connections.queued() {
            if let Err(e) = take(accepted) {
                warn!("{what}: cannot accept a connection: {e}");
                break;
            }
        }
    }
    drop(connections);
    activity.wait_idle().await;
}

/// Where a service takes its connections: a listening socket, or the
/// process of the service itself, which hands it one end of a socket pair
/// for each connection (the service of a command: nothing outside the
/// process can reach it, as no name of the file system or of the abstract
/// namespace of the network namespace leads to it).
pub enum Connections {
    Listener(tokio::net::UnixListener),
    Handed(tokio::sync::mpsc::UnboundedReceiver<std::os::unix::net::UnixStream>),
}

impl From<tokio::net::UnixListener> for Connections {
    fn from(listener: tokio::net::UnixListener) -> Self {
        Self::Listener(listener)
    }
}

/// The end of a socket pair handed to a service ([`Connections::Handed`]),
/// for the runtime of the service.
fn handed(stream: std::os::unix::net::UnixStream) -> io::Result<tokio::net::UnixStream> {
    stream.set_nonblocking(true)?;
    tokio::net::UnixStream::from_std(stream)
}

impl Connections {
    /// The next connection (cancel safe: none is lost to a `select!`).
    /// Never, when nothing can hand one any more.
    async fn accept(&mut self) -> io::Result<tokio::net::UnixStream> {
        match self {
            Self::Listener(listener) => listener.accept().await.map(|(stream, _)| stream),
            Self::Handed(handed_ones) => match handed_ones.recv().await {
                Some(stream) => handed(stream),
                None => std::future::pending().await,
            },
        }
    }

    /// A connection that waits, if one does (an accept that does not wait).
    fn queued(&mut self) -> Option<io::Result<tokio::net::UnixStream>> {
        match self {
            Self::Listener(listener) => {
                let accepted = rustix::net::accept_with(
                    &*listener,
                    rustix::net::SocketFlags::NONBLOCK | rustix::net::SocketFlags::CLOEXEC,
                );
                match accepted {
                    Ok(fd) => Some(tokio::net::UnixStream::from_std(
                        std::os::unix::net::UnixStream::from(fd),
                    )),
                    Err(rustix::io::Errno::AGAIN) => None,
                    Err(e) => Some(Err(e.into())),
                }
            }
            Self::Handed(handed_ones) => handed_ones.try_recv().ok().map(handed),
        }
    }
}

/// Answer the first call of a connection the service does not take with
/// the `Unavailable` error of the interface the call names (with a `reason`,
/// and the `cause` and `message` of the engine's), and close it: the client
/// is told why, not left with an end of file.  A connection that sends no
/// call in `first_call`, or a first message larger than 64 KiB, is just
/// closed.
async fn refuse(mut stream: tokio::net::UnixStream, reason: String, first_call: Duration) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut message = Vec::new();
    let read = tokio::time::timeout(first_call, async {
        let mut chunk = [0u8; 4096];
        while !message.contains(&0) && message.len() < 64 * 1024 {
            match stream.read(&mut chunk).await {
                Ok(0) | Err(_) => return false,
                Ok(n) => message.extend_from_slice(&chunk[..n]),
            }
        }
        true
    })
    .await;
    if read != Ok(true) {
        return;
    }
    let call = message.split(|b| *b == 0).next().unwrap_or_default();
    let Some(interface) = serde_json::from_slice::<serde_json::Value>(call)
        .ok()
        .and_then(|v| {
            v["method"]
                .as_str()
                .and_then(|m| m.rsplit_once('.'))
                .map(|(i, _)| i.to_string())
        })
    else {
        return;
    };
    // (the engine's errors have a cause and a message, the others a reason)
    let parameters = if interface == "org.velarx.Engine" {
        serde_json::json!({"cause": "too many connections", "message": reason})
    } else {
        serde_json::json!({ "reason": reason })
    };
    let mut answer = serde_json::to_vec(&serde_json::json!({
        "error": format!("{interface}.Unavailable"),
        "parameters": parameters,
    }))
    .unwrap_or_default();
    answer.push(0);
    let _ = stream.write_all(&answer).await;
}

/// The most bytes a connection of a service queues for its client.  The
/// replies of the services carry descriptors (the files of the data), and
/// the kernel
/// counts every descriptor in a socket's queue against the whole user (all
/// the sockets and processes of a uid share the count, and the session bus
/// of the user is one of them: its broker dies when it is over its own
/// limit, 1024).  With the default buffer of about 200 KiB a service that
/// is faster than its client (a fetcher with the pieces of a big layer)
/// has hundreds of descriptors queued for each connection; with this one,
/// a few.  The service waits for the client to read, as it does when the
/// buffer is full.
///
/// What it bounds, in descriptors: the kernel doubles the value and raises
/// it to its minimum (4608 bytes on 64 bits), and counts each queued reply
/// with its overhead (about 700 bytes for a small one), so a connection has
/// at most 6 replies queued (fewer for larger replies, which are written in
/// parts, the descriptors with the first part).  The unit tests hold a
/// connection to 16; a user's total is that times the connections open.
pub const MAX_QUEUED_BYTES: usize = 2048;

/// Bound what a service queues for the client on `stream`
/// ([`MAX_QUEUED_BYTES`]).  A failure is not one: the connection works,
/// only with the default buffer.
pub fn bound_queued_replies(stream: &tokio::net::UnixStream) {
    if let Err(e) = rustix::net::sockopt::set_socket_send_buffer_size(stream, MAX_QUEUED_BYTES) {
        debug!("cannot bound the replies queued for a client: {e}");
    }
}

/// A descriptor of the connection `stream` to watch for the client closing
/// it (without reading it: the server owns the reads).
fn hangup_of(stream: &tokio::net::UnixStream) -> io::Result<tokio::io::unix::AsyncFd<OwnedFd>> {
    use std::os::fd::AsFd;
    let own = stream.as_fd().try_clone_to_owned()?;
    velarx_sys::fd::register(own, tokio::io::Interest::WRITABLE)
}

/// Until the peer of the socket closed it, whole (a client that only shut
/// down its writes is waiting for its answer): the kernel reports the hangup
/// as an event, so this neither polls nor reads.  Never, if the socket
/// cannot be watched.
async fn hung_up(fd: &tokio::io::unix::AsyncFd<OwnedFd>) {
    loop {
        let Ok(mut guard) = fd.ready(tokio::io::Interest::WRITABLE).await else {
            return std::future::pending().await;
        };
        if guard.ready().is_write_closed() {
            return;
        }
        guard.clear_ready();
    }
}

/// Whether the client of `stream` sent something, or closed it, within
/// `deadline`: a byte is looked at, not read (a socket just accepted is
/// reported ready before anything came).
async fn first_call(stream: &tokio::net::UnixStream, deadline: Duration) -> bool {
    let sent = async {
        let mut byte = [0u8; 1];
        loop {
            if stream.readable().await.is_err() {
                return;
            }
            let peeked = stream.try_io(tokio::io::Interest::READABLE, || {
                rustix::net::recv(stream, &mut byte, rustix::net::RecvFlags::PEEK)
                    .map_err(io::Error::from)
            });
            if !matches!(peeked, Err(e) if e.kind() == io::ErrorKind::WouldBlock) {
                return;
            }
        }
    };
    tokio::time::timeout(deadline, sent).await.is_ok()
}

/// Serve the varlink service `service` on `listener` ([`serve_loop`]): each
/// connection has a server of its own, so that a slow call of one does not
/// hold the others.  Runs in a `LocalSet` (the servers of zlink are not
/// `Send`).
pub async fn serve_varlink<S>(
    listener: tokio::net::UnixListener,
    idle: Option<IdleExit>,
    trusted: fn(u32) -> bool,
    limits: Limits,
    what: &'static str,
    service: S,
) where
    S: zlink::Service<zlink::tokio::unix::Stream> + Clone + 'static,
{
    serve_varlink_on(
        listener,
        idle,
        trusted,
        Activity::new(limits),
        what,
        service,
    )
    .await;
}

/// [`serve_varlink`] with the [`Activity`] the caller keeps (to hold the
/// service, or to look at the connections).
pub async fn serve_varlink_on<S>(
    connections: impl Into<Connections>,
    idle: Option<IdleExit>,
    trusted: fn(u32) -> bool,
    activity: Arc<Activity>,
    what: &'static str,
    service: S,
) where
    S: zlink::Service<zlink::tokio::unix::Stream> + Clone + 'static,
{
    let first = activity.limits.first_call;
    serve_loop(
        connections,
        idle,
        trusted,
        activity,
        what,
        move |stream, busy| admit_varlink(stream, busy, service.clone(), first, what),
    )
    .await;
}

/// Serve the varlink service `service` on the connection `stream` in a
/// local task of its own, while `busy` counts it: a connection that sends
/// no call in `first` is closed, one whose client went away ends with it.
pub fn admit_varlink<S>(
    stream: tokio::net::UnixStream,
    busy: Busy,
    service: S,
    first: Duration,
    what: &'static str,
) where
    S: zlink::Service<zlink::tokio::unix::Stream> + 'static,
{
    // (zlink does not read a connection that has a reply stream, so it
    // would not see the client leave: watched here)
    let gone = match hangup_of(&stream) {
        Ok(g) => g,
        Err(e) => {
            warn!("{what}: {e}");
            return;
        }
    };
    tokio::task::spawn_local(async move {
        let busy = busy;
        if !first_call(&stream, first).await {
            debug!("{what}: a client sent no call in {first:?}");
            return;
        }
        let stream = match zlink::tokio::unix::Stream::try_from(stream) {
            Ok(s) => s,
            Err(e) => {
                warn!("{what}: {e}");
                return;
            }
        };
        let server = zlink::Server::new(zlink::ReadyListener::new(stream), service);
        tokio::select! {
            served = server.run() => {
                if let Err(e) = served {
                    debug!("{what}: a connection ended: {e}");
                }
            }
            () = hung_up(&gone) => debug!("{what}: a client went away"),
            () = handed_over(&busy.activity, &gone) => {}
        }
    });
}

/// Once the service stopped accepting for the process that follows, no
/// call is read on the connection `socket` any more: one in progress is
/// answered, the connection ends where the next would be read (a call its
/// client sent already is read and answered).  Never returns.
async fn handed_over(activity: &Activity, socket: &tokio::io::unix::AsyncFd<OwnedFd>) {
    let mut handed = activity.handed_over.subscribe();
    if handed.wait_for(|h| *h).await.is_ok() {
        if let Err(e) = rustix::net::shutdown(socket.get_ref(), rustix::net::Shutdown::Read) {
            debug!("cannot end the reads of a connection: {e}");
        }
    }
    std::future::pending().await
}

/// The listening socket systemd passed (`LISTEN_FDS`, `LISTEN_PID`): the
/// first one, descriptor 3.
pub fn activated_listener(
    startup: &velarx_sys::fd::Startup,
) -> Option<io::Result<std::os::unix::net::UnixListener>> {
    let pid: u32 = std::env::var("LISTEN_PID").ok()?.parse().ok()?;
    let fds: u32 = std::env::var("LISTEN_FDS").ok()?.parse().ok()?;
    if pid != std::process::id() || fds < 1 {
        return None;
    }
    // (before any thread is started)
    std::env::remove_var("LISTEN_PID");
    std::env::remove_var("LISTEN_FDS");
    std::env::remove_var("LISTEN_FDNAMES");
    Some(inherited_listener(startup, 3))
}

/// The listener of descriptor `fd`, checked to be a listening unix socket.
pub fn inherited_listener(
    startup: &velarx_sys::fd::Startup,
    fd: i32,
) -> io::Result<std::os::unix::net::UnixListener> {
    let Some(owned) = startup.adopt(fd) else {
        return Err(io::Error::other(format!("no socket on descriptor {fd}")));
    };
    let accepting = rustix::net::sockopt::socket_acceptconn(&owned).unwrap_or(false);
    let unix = rustix::net::getsockname(&owned)
        .is_ok_and(|a| a.address_family() == rustix::net::AddressFamily::UNIX);
    if !accepting || !unix {
        return Err(io::Error::other(format!(
            "descriptor {fd} is not a listening unix socket"
        )));
    }
    // (not passed on to anything this process starts)
    rustix::io::fcntl_setfd(&owned, rustix::io::FdFlags::CLOEXEC)?;
    Ok(std::os::unix::net::UnixListener::from(owned))
}

/// The listeners a process was started with, taken at its start: systemd's
/// and the one a client passed (`--listen-fd`).
pub struct Inherited {
    activated: Option<std::os::unix::net::UnixListener>,
    passed: Option<std::os::unix::net::UnixListener>,
}

impl Inherited {
    /// Take them at the start of the process.
    pub fn take(startup: &velarx_sys::fd::Startup, listen_fd: Option<i32>) -> anyhow::Result<Self> {
        let activated = activated_listener(startup).transpose()?;
        let passed = listen_fd
            .map(|fd| {
                inherited_listener(startup, fd)
                    .map_err(|e| anyhow::anyhow!("--listen-fd {fd}: {e}"))
            })
            .transpose()?;
        Ok(Self { activated, passed })
    }
}

/// The listener of a process that is started for a socket: systemd's, the
/// descriptor a client passed (`listen_fd`), or one bound here unless
/// another instance serves `socket`.  Whether the socket is ours to take
/// away when the service leaves comes with it.
pub fn listener_for(
    socket: &Path,
    inherited: Inherited,
) -> anyhow::Result<(std::os::unix::net::UnixListener, bool)> {
    Ok(match (inherited.activated, inherited.passed) {
        (Some(l), _) => (l, false),
        (None, Some(listener)) => (listener, true),
        (None, None) => match connect_or_bind(socket)? {
            Ok(_) => anyhow::bail!("another process serves {}", socket.display()),
            Err(listener) => (listener, true),
        },
    })
}

/// Start `cmd` for the socket `socket`, which is bound here and passed as
/// its descriptor 3, in a process group of its own, its standard error
/// `stderr`: it outlives whoever started it.  Returns a connection to it,
/// or to the instance that serves the socket already (a connection made
/// under the lock is served even by one that leaves), and the process
/// started, if one was: the caller reaps it.
pub fn start(
    socket: &Path,
    mut cmd: std::process::Command,
    stderr: std::process::Stdio,
) -> io::Result<(std::os::unix::net::UnixStream, Option<std::process::Child>)> {
    let listener = match connect_or_bind(socket)? {
        Ok(stream) => return Ok((stream, None)),
        Err(listener) => listener,
    };
    // (waits in the queue of the listener until the service accepts it)
    let stream = std::os::unix::net::UnixStream::connect(socket)?;
    cmd.stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(stderr);
    std::os::unix::process::CommandExt::process_group(&mut cmd, 0);
    velarx_base::spawn::pass_as_fd3(&mut cmd, listener.as_raw_fd());
    let spawned = cmd.spawn();
    drop(listener);
    let child = match spawned {
        Ok(child) => child,
        Err(e) => {
            // (nothing would ever accept on it)
            if let Ok(_lock) = take_lock(socket) {
                let _ = std::fs::remove_file(socket);
            }
            return Err(e);
        }
    };
    Ok((stream, Some(child)))
}

/// A zlink connection on `stream`, checked to be served by a trusted user.
pub fn checked(
    stream: tokio::net::UnixStream,
) -> io::Result<zlink::Connection<zlink::tokio::unix::Stream>> {
    let cred = stream.peer_cred()?;
    if !velarx_base::ipc::trusted_uid(cred.uid()) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("the service is served by uid {}", cred.uid()),
        ));
    }
    let stream = zlink::tokio::unix::Stream::try_from(stream).map_err(io::Error::other)?;
    Ok(zlink::Connection::new(stream))
}

/// A connection to the service on `socket`, checked to be served by a
/// trusted user.
pub async fn connect(socket: &Path) -> io::Result<zlink::Connection<zlink::tokio::unix::Stream>> {
    let connector = CONNECTORS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .iter()
        .find(|(path, _)| path == socket)
        .map(|(_, c)| c.clone());
    match connector {
        Some(c) => {
            let stream = tokio::task::spawn_blocking(move || c.connect())
                .await
                .map_err(io::Error::other)??;
            stream.set_nonblocking(true)?;
            checked(tokio::net::UnixStream::from_std(stream)?)
        }
        None => checked(tokio::net::UnixStream::connect(socket).await?),
    }
}

/// The sockets this process reaches through a connector, not by name (it is
/// confined and looks up no socket).
static CONNECTORS: Mutex<Vec<(PathBuf, Arc<velarx_sys::connector::Connector>)>> =
    Mutex::new(Vec::new());

/// From now on [`connect`] to `socket` goes through `connector`.
pub fn connect_through(socket: PathBuf, connector: velarx_sys::connector::Connector) {
    CONNECTORS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .push((socket, Arc::new(connector)));
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A process that ends takes its own socket away, not the one another
    /// process bound in its place.
    #[test]
    fn only_the_own_socket_is_taken_away() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("private/s.sock");
        let Err(first) = connect_or_bind(&socket).unwrap() else {
            panic!("nothing serves it yet")
        };
        let id = socket_file_id(&socket);
        assert!(id.is_some());
        // it ends: the next one finds no one and binds the path again
        drop(first);
        let Err(_second) = connect_or_bind(&socket).unwrap() else {
            panic!("the first one is gone")
        };
        remove_own_socket(&socket, id);
        assert!(socket.exists(), "the socket of the second one stays");
        remove_own_socket(&socket, socket_file_id(&socket));
        assert!(!socket.exists());
        // a directory removed meanwhile is not made again
        let id = socket_file_id(&socket);
        let Err(_third) = connect_or_bind(&socket).unwrap() else {
            panic!("nothing serves it")
        };
        let id3 = socket_file_id(&socket);
        assert!(id.is_none() && id3.is_some());
        std::fs::remove_dir_all(socket.parent().unwrap()).unwrap();
        remove_own_socket(&socket, id3);
        assert!(!socket.parent().unwrap().exists());
    }

    /// A wait for the lock of the socket that outlives its directory makes
    /// nothing in its place (neither the directory, the lock nor the
    /// socket).
    #[test]
    fn a_wait_for_the_lock_that_outlives_the_directory_makes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("run/s.sock");
        let lock = open_lock(&socket).unwrap();
        std::fs::remove_dir_all(socket.parent().unwrap()).unwrap();
        assert!(connect_or_bind_on(&socket, lock).is_err());
        assert!(!socket.parent().unwrap().exists());
    }

    /// A lock file removed while it was waited for, its directory still
    /// there, is taken again: the socket is bound as before.
    #[test]
    fn a_lock_file_removed_during_the_wait_is_taken_again() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("run/s.sock");
        let lock = open_lock(&socket).unwrap();
        std::fs::remove_file(lock_path(&socket)).unwrap();
        assert!(matches!(connect_or_bind_on(&socket, lock), Ok(Err(_))));
        assert!(socket.exists());
        assert!(lock_path(&socket).exists());
    }

    /// A socket that cannot be connected to for another reason than the end
    /// of its instance is not taken over.
    #[test]
    fn a_socket_that_is_refused_for_another_reason_is_not_rebound() {
        use std::os::unix::fs::PermissionsExt;
        // (root connects to any socket)
        if rustix::process::geteuid().is_root() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("private/s.sock");
        let Err(listener) = connect_or_bind(&socket).unwrap() else {
            panic!("nothing serves it yet")
        };
        let id = socket_file_id(&socket);
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o000)).unwrap();
        let e = connect_or_bind(&socket).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(socket_file_id(&socket), id, "the socket is not replaced");
        drop(listener);
    }

    /// A service whose connections keep another one (the proxy of the image
    /// servers, the engine service) holds it while one is connected, and
    /// releases it when the last one ends.
    #[tokio::test]
    async fn the_connections_of_a_service_keep_another() {
        let local = tokio::task::LocalSet::new();
        local
            .run_until(async {
                let (proxy, engine) = (
                    Activity::new(Limits::default()),
                    Activity::new(Limits::default()),
                );
                tokio::task::spawn_local(proxy.clone().keep_while_served(engine.clone()));
                let kept = || engine.kept.load(Ordering::SeqCst);
                tokio::task::yield_now().await;
                assert_eq!(kept(), 0);
                let one = Busy::for_client(&proxy, Client::Process(1)).unwrap();
                let two = Busy::for_client(&proxy, Client::Process(2)).unwrap();
                tokio::task::yield_now().await;
                assert_eq!(kept(), 1, "a connection keeps the engine");
                drop(one);
                tokio::task::yield_now().await;
                assert_eq!(kept(), 1, "the other still does");
                drop(two);
                tokio::task::yield_now().await;
                assert_eq!(kept(), 0, "the last one released it");
            })
            .await;
    }

    /// Work of the service that is kept (a completion of a lazy pull)
    /// keeps it from leaving whatever the connections, and is no
    /// connection: the wait for the connections to end does not wait for
    /// it.  The last one dropped, it leaves after the idle time.
    #[tokio::test(start_paused = true)]
    async fn kept_work_keeps_the_service() {
        let local = tokio::task::LocalSet::new();
        local
            .run_until(async {
                let dir = tempfile::tempdir().unwrap();
                let dir_path = dir.path().join("private");
                velarx_base::ipc::ensure_private_dir(&dir_path).unwrap();
                let socket = dir_path.join("s.sock");
                let listener = tokio::net::UnixListener::bind(&socket).unwrap();
                let activity = Activity::new(Limits::default());
                let (one, two) = (activity.keep(), activity.keep());
                let idle = IdleExit {
                    after: Duration::from_millis(200),
                    socket: Some(socket.clone()),
                    last: false,
                    lock: None,
                };
                let mut left = Box::pin(serve_loop(
                    listener,
                    Some(idle),
                    |_| true,
                    activity.clone(),
                    "test",
                    |_, _| {},
                ));
                // (no connection: idle for the drain)
                tokio::time::timeout(Duration::from_secs(1), activity.wait_idle())
                    .await
                    .expect("kept work is no connection");
                drop(one);
                assert!(
                    tokio::time::timeout(Duration::from_millis(700), &mut left)
                        .await
                        .is_err(),
                    "the service left with work kept"
                );
                drop(two);
                tokio::time::timeout(Duration::from_secs(5), &mut left)
                    .await
                    .expect("the service leaves once nothing is kept");
            })
            .await;
    }

    /// A service that is held does not leave when idle; released, it leaves
    /// after the idle time counted from the release.
    #[tokio::test]
    async fn a_held_service_does_not_leave_when_idle() {
        let local = tokio::task::LocalSet::new();
        local
            .run_until(async {
                let dir = tempfile::tempdir().unwrap();
                // (a private directory, as a service's socket is in)
                let dir_path = dir.path().join("private");
                velarx_base::ipc::ensure_private_dir(&dir_path).unwrap();
                let socket = dir_path.join("s.sock");
                let listener = tokio::net::UnixListener::bind(&socket).unwrap();
                let activity = Activity::new(Limits::default());
                activity.hold(true);
                let idle = IdleExit {
                    after: Duration::from_millis(200),
                    socket: Some(socket.clone()),
                    last: false,
                    lock: None,
                };
                let mut left = Box::pin(serve_loop(
                    listener,
                    Some(idle),
                    |_| true,
                    activity.clone(),
                    "test",
                    |_, _| {},
                ));
                // (held: not leaving after several idle times)
                assert!(
                    tokio::time::timeout(Duration::from_millis(700), &mut left)
                        .await
                        .is_err(),
                    "the service left while held"
                );
                assert!(socket.exists());
                let released = Instant::now();
                activity.hold(false);
                tokio::time::timeout(Duration::from_secs(5), &mut left)
                    .await
                    .expect("the service leaves once released");
                assert!(released.elapsed() >= Duration::from_millis(150));
                assert!(!socket.exists(), "the socket it bound is taken away");
            })
            .await;
    }

    /// A service held by its connections waits for its first one no longer
    /// than `after`, and does not leave while one is served: it leaves as
    /// the last one ends, not `after` later.
    #[tokio::test]
    async fn a_service_held_by_its_connections_leaves_with_the_last() {
        let local = tokio::task::LocalSet::new();
        local
            .run_until(async {
                let dir = tempfile::tempdir().unwrap();
                let dir_path = dir.path().join("private");
                velarx_base::ipc::ensure_private_dir(&dir_path).unwrap();
                let socket = dir_path.join("s.sock");
                let held = |after| IdleExit {
                    after,
                    socket: Some(socket.clone()),
                    last: true,
                    lock: None,
                };
                let listener = tokio::net::UnixListener::bind(&socket).unwrap();
                let waited = Instant::now();
                tokio::time::timeout(
                    Duration::from_secs(10),
                    serve_loop(
                        listener,
                        Some(held(Duration::from_millis(200))),
                        |_| true,
                        Activity::new(Limits::default()),
                        "test",
                        |_, _| {},
                    ),
                )
                .await
                .expect("it leaves without a first connection");
                assert!(waited.elapsed() >= Duration::from_millis(150));
                assert!(!socket.exists());

                // one comes, and is served for longer than `after`
                let listener = tokio::net::UnixListener::bind(&socket).unwrap();
                let client = std::os::unix::net::UnixStream::connect(&socket).unwrap();
                let (tx, mut admitted) = tokio::sync::mpsc::unbounded_channel();
                let mut left = Box::pin(serve_loop(
                    listener,
                    Some(held(Duration::from_millis(100))),
                    |_| true,
                    Activity::new(Limits::default()),
                    "test",
                    move |stream, busy| {
                        let _ = tx.send((stream, busy));
                    },
                ));
                let served = tokio::select! {
                    _ = &mut left => panic!("it left with a connection waiting"),
                    served = admitted.recv() => served.unwrap(),
                };
                assert!(
                    tokio::time::timeout(Duration::from_millis(500), &mut left)
                        .await
                        .is_err(),
                    "it left while a connection was served"
                );
                assert!(socket.exists());
                let ended = Instant::now();
                drop(served);
                drop(client);
                tokio::time::timeout(Duration::from_secs(10), &mut left)
                    .await
                    .expect("it leaves with the last connection");
                assert!(ended.elapsed() < Duration::from_millis(100) * 10);
                assert!(!socket.exists());
            })
            .await;
    }

    /// A connection is kept once its client sent something or closed it,
    /// not before (a socket just accepted is reported ready), and what was
    /// sent is still there for the server to read.
    #[tokio::test]
    async fn a_client_that_sends_nothing_is_not_kept() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let dir = tempfile::tempdir().unwrap();
        let listener = tokio::net::UnixListener::bind(dir.path().join("s.sock")).unwrap();
        let mut client = tokio::net::UnixStream::connect(dir.path().join("s.sock"))
            .await
            .unwrap();
        let (mut server, _) = listener.accept().await.unwrap();
        assert!(!first_call(&server, Duration::from_millis(200)).await);
        client.write_all(b"{}\0").await.unwrap();
        assert!(first_call(&server, Duration::from_secs(60)).await);
        let mut sent = [0u8; 3];
        server.read_exact(&mut sent).await.unwrap();
        assert_eq!(&sent, b"{}\0");
        drop(client);
        assert!(first_call(&server, Duration::from_secs(60)).await, "an end");
    }

    /// One client process has at most `per_client` connections (of the
    /// configuration): the next is answered `Unavailable` (of the interface
    /// its call names) and closed, and a slot is free again when one of the
    /// others ends.
    #[tokio::test]
    async fn a_client_over_its_limit_is_told_why() {
        use std::io::{Read, Write};
        let local = tokio::task::LocalSet::new();
        local
            .run_until(async {
                let dir = tempfile::tempdir().unwrap();
                let socket = dir.path().join("s.sock");
                let listener = tokio::net::UnixListener::bind(&socket).unwrap();
                const PER_CLIENT: usize = 3;
                let activity = Activity::new(Limits {
                    per_client: PER_CLIENT,
                    ..Limits::default()
                });
                let (tx, mut admitted) = tokio::sync::mpsc::unbounded_channel();
                let served = activity.clone();
                tokio::task::spawn_local(serve_loop(
                    listener,
                    None,
                    |_| true,
                    served,
                    "test",
                    move |stream, busy| {
                        let _ = tx.send((stream, busy));
                    },
                ));
                let (mut kept, mut held) = (Vec::new(), Vec::new());
                for _ in 0..PER_CLIENT {
                    let path = socket.clone();
                    kept.push(
                        tokio::task::spawn_blocking(move || {
                            std::os::unix::net::UnixStream::connect(path).unwrap()
                        })
                        .await
                        .unwrap(),
                    );
                    held.push(admitted.recv().await.unwrap());
                }
                assert_eq!(activity.active(), PER_CLIENT);
                let path = socket.clone();
                let answer = tokio::task::spawn_blocking(move || {
                    let mut over = std::os::unix::net::UnixStream::connect(path).unwrap();
                    over.write_all(b"{\"method\":\"org.example.Test.Ping\"}\0")
                        .unwrap();
                    let mut answer = Vec::new();
                    over.read_to_end(&mut answer).unwrap();
                    answer
                })
                .await
                .unwrap();
                let answer: serde_json::Value =
                    serde_json::from_slice(answer.strip_suffix(b"\0").unwrap()).unwrap();
                assert_eq!(answer["error"], "org.example.Test.Unavailable");
                assert!(answer["parameters"]["reason"]
                    .as_str()
                    .unwrap()
                    .contains("this process"));
                // (the service's own count is untouched by the refusal)
                assert_eq!(activity.active(), PER_CLIENT);
            })
            .await;
    }

    /// The limit of connections counts the connections only: the call
    /// each one runs (busy work of its own) takes no slot of another.
    #[test]
    fn the_busy_work_of_a_connection_is_no_connection() {
        let activity = Activity::new(Limits {
            connections: 2,
            ..Limits::default()
        });
        let one = Busy::for_client(&activity, Client::Process(1)).unwrap();
        let call = Busy::new(&activity);
        let two = Busy::for_client(&activity, Client::Process(2)).unwrap();
        let e = Busy::for_client(&activity, Client::Process(3)).err();
        assert_eq!(e.as_deref(), Some("too many connections (2)"));
        drop((one, call, two));
        assert_eq!(activity.active(), 0);
    }

    /// A client that does not read has a few replies with descriptors
    /// queued, not hundreds (the descriptors in flight are counted for the
    /// whole user).
    #[tokio::test]
    async fn a_client_that_does_not_read_holds_few_descriptors_in_flight() {
        use rustix::net::{sendmsg, SendAncillaryBuffer, SendAncillaryMessage, SendFlags};
        use std::io::IoSlice;
        use std::os::fd::AsFd;
        let local = tokio::task::LocalSet::new();
        local
            .run_until(async {
                let dir = tempfile::tempdir().unwrap();
                let dir_path = dir.path().join("private");
                velarx_base::ipc::ensure_private_dir(&dir_path).unwrap();
                let socket = dir_path.join("s.sock");
                let listener = tokio::net::UnixListener::bind(&socket).unwrap();
                let (queued_tx, queued_rx) = tokio::sync::oneshot::channel();
                let queued_tx = std::cell::RefCell::new(Some(queued_tx));
                let activity = Activity::new(Limits::default());
                let serving = tokio::task::spawn_local(serve_loop(
                    listener,
                    None,
                    |_| true,
                    activity,
                    "test",
                    move |stream, busy| {
                        let Some(tx) = queued_tx.borrow_mut().take() else {
                            return;
                        };
                        tokio::task::spawn_local(async move {
                            let _busy = busy;
                            let null = std::fs::File::open("/dev/null").unwrap();
                            let mut sent = 0usize;
                            // (as a reply of the fetcher: a short message and a descriptor)
                            while sent < 5000 {
                                let r = stream.writable().await.and_then(|()| {
                                    stream.try_io(tokio::io::Interest::WRITABLE, || {
                                        let fds = [null.as_fd()];
                                        let mut space = [std::mem::MaybeUninit::uninit();
                                            rustix::cmsg_space!(ScmRights(1))];
                                        let mut control = SendAncillaryBuffer::new(&mut space);
                                        control.push(SendAncillaryMessage::ScmRights(&fds));
                                        sendmsg(
                                            &stream,
                                            &[IoSlice::new(&[b'x'; 100])],
                                            &mut control,
                                            SendFlags::empty(),
                                        )
                                        .map_err(std::io::Error::from)
                                    })
                                });
                                match r {
                                    Ok(_) => sent += 1,
                                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                                        // (the queue is full: nobody reads)
                                        break;
                                    }
                                    Err(e) => panic!("{e}"),
                                }
                            }
                            let _ = tx.send(sent);
                        });
                    },
                ));
                // (a client that never reads)
                let _client = std::os::unix::net::UnixStream::connect(&socket).unwrap();
                let sent = tokio::time::timeout(Duration::from_secs(10), queued_rx)
                    .await
                    .expect("the service fills the queue")
                    .unwrap();
                serving.abort();
                assert!(
                    sent <= 16,
                    "{sent} replies with a descriptor were queued for a client that does not read"
                );
            })
            .await;
    }

    /// A service that stops accepting for the process that follows ends
    /// the connections that wait for their next call (their clients
    /// connect again, to that process) once it answered the call in
    /// progress on each: a frontend that keeps its connections is not left
    /// with one to a service that goes.
    #[tokio::test]
    async fn a_service_handed_over_ends_its_idle_connections() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        #[derive(Clone)]
        struct Pinged;
        #[zlink::service(
            interface = "org.velarx.Engine",
            vendor = "org.velarx",
            product = "test",
            version = "0",
            url = "https://example.org"
        )]
        impl Pinged {
            async fn ping(&self) -> velarx_proto::engine::Ack {
                velarx_proto::engine::Ack {}
            }
        }
        async fn ping(conn: &mut tokio::net::UnixStream) -> Vec<u8> {
            conn.write_all(b"{\"method\":\"org.velarx.Engine.Ping\"}\0")
                .await
                .unwrap();
            let mut reply = Vec::new();
            while reply.last() != Some(&0) {
                let mut byte = [0u8];
                if conn.read(&mut byte).await.unwrap() == 0 {
                    break;
                }
                reply.push(byte[0]);
            }
            reply
        }
        tokio::task::LocalSet::new()
            .run_until(async {
                let dir = tempfile::tempdir().unwrap();
                let socket = dir.path().join("s.sock");
                let listener = tokio::net::UnixListener::bind(&socket).unwrap();
                let activity = Activity::new(Limits::default());
                let serving = tokio::task::spawn_local(serve_varlink_on(
                    listener,
                    None,
                    |_| true,
                    activity.clone(),
                    "test",
                    Pinged,
                ));
                let mut idle = tokio::net::UnixStream::connect(&socket).await.unwrap();
                assert!(ping(&mut idle).await.ends_with(b"}\0"));
                activity.stop_accepting().await;
                // (the end of the connection is what comes next on it)
                let mut rest = Vec::new();
                tokio::time::timeout(Duration::from_secs(10), idle.read_to_end(&mut rest))
                    .await
                    .expect("the idle connection ends")
                    .unwrap();
                assert!(rest.is_empty());
                tokio::time::timeout(Duration::from_secs(10), serving)
                    .await
                    .expect("the service leaves once its connections ended")
                    .unwrap();
            })
            .await;
    }

    /// A reply larger than what a connection queues still arrives whole,
    /// with its own descriptor: the service writes it in parts as the client
    /// reads, the descriptors go with the first part, and the client gives
    /// each reply the descriptor sent with it.
    #[tokio::test]
    async fn replies_larger_than_the_queue_arrive_whole_with_their_descriptor() {
        use crate::fetcher::fetch::FetcherError;
        use std::io::{Read, Seek, Write};
        const REPLIES: usize = 4;
        const SIZE: usize = 20 * MAX_QUEUED_BYTES;
        let local = tokio::task::LocalSet::new();
        local
            .run_until(async {
                let dir = tempfile::tempdir().unwrap();
                let dir_path = dir.path().join("private");
                velarx_base::ipc::ensure_private_dir(&dir_path).unwrap();
                let socket = dir_path.join("s.sock");
                let listener = tokio::net::UnixListener::bind(&socket).unwrap();
                let serving = tokio::task::spawn_local(serve_loop(
                    listener,
                    None,
                    |_| true,
                    Activity::new(Limits::default()),
                    "test",
                    move |stream, busy| {
                        tokio::task::spawn_local(async move {
                            let _busy = busy;
                            let stream = zlink::tokio::unix::Stream::try_from(stream).unwrap();
                            let mut conn = zlink::Connection::new(stream);
                            for i in 0..REPLIES {
                                let mut file = tempfile::tempfile().unwrap();
                                write!(file, "{i}").unwrap();
                                let body = i.to_string().repeat(SIZE);
                                let reply = zlink::Reply::new(Some(body))
                                    .set_continues(Some(i + 1 < REPLIES));
                                conn.send_reply(&reply, vec![OwnedFd::from(file)])
                                    .await
                                    .unwrap();
                            }
                        });
                    },
                ));
                let stream = tokio::net::UnixStream::connect(&socket).await.unwrap();
                let mut conn =
                    zlink::Connection::new(zlink::tokio::unix::Stream::try_from(stream).unwrap());
                for i in 0..REPLIES {
                    // (slower than the service: its writes wait for these reads)
                    tokio::time::sleep(Duration::from_millis(20)).await;
                    let (reply, fds) = tokio::time::timeout(
                        Duration::from_secs(10),
                        conn.read_mut().receive_reply::<String, FetcherError>(),
                    )
                    .await
                    .expect("the reply comes")
                    .unwrap();
                    let body = reply.unwrap().into_parameters().unwrap();
                    assert_eq!(body, i.to_string().repeat(SIZE));
                    assert_eq!(fds.len(), 1, "reply {i}");
                    let mut file = std::fs::File::from(fds.into_iter().next().unwrap());
                    let mut content = String::new();
                    file.rewind().unwrap();
                    file.read_to_string(&mut content).unwrap();
                    assert_eq!(content, i.to_string(), "the descriptor of reply {i}");
                }
                serving.abort();
            })
            .await;
    }
}
