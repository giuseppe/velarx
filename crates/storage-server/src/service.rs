// SPDX-License-Identifier: Apache-2.0
//! The socket, the connections, the dispatch of the calls, and the calls that
//! need no more than the store.

use crate::store::{Store, Stores};
use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::json;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use velarx_graph::{DriverError, DriverErrorKind, DriverResult, Keep, StorageDriver};
use velarx_storage_client::convert;
use velarx_storage_client::proto::{self, StorageError};
use velarx_storage_client::request;
use velarx_wire::varlink::{encode_error, encode_reply, parse_call, Conn};

/// The name the server calls itself.
pub const NAME: &str = "velarx-storage-ref";

/// The connections served at once (the engine opens one for each call, and a
/// few more during a pull): what a client that opens connections and leaves
/// them can hold of the server's threads.
const MAX_CONNECTIONS: usize = 512;

/// How long the server may be idle before it leaves, when it is not told.
pub const DEFAULT_IDLE_SECS: u64 = 300;

/// The idle time of a flag or `VELARX_STORAGE_IDLE_SECS`: seconds, `0` or
/// `off` for never.  `None` is a value that is none of these.
pub fn parse_idle(value: &str) -> Option<Option<Duration>> {
    let value = value.trim();
    if value.eq_ignore_ascii_case("off") {
        return Some(None);
    }
    let secs: u64 = value.parse().ok()?;
    Some((secs > 0).then(|| Duration::from_secs(secs)))
}

pub struct Config {
    /// Where the stores are.
    pub root: PathBuf,
    /// The idle deadline of the engine's calls (`[storage.varlink]
    /// timeout_secs`): a long call sends progress every half of it.
    pub timeout: Duration,
    /// How long a pull that is staged waits for the engine's decision.
    pub decision: Duration,
}

pub struct Server {
    pub(crate) config: Config,
    pub(crate) stores: Stores,
    pub(crate) rt: tokio::runtime::Runtime,
    /// The connections served now.
    live: std::sync::atomic::AtomicUsize,
    /// A handle of each connection served, by number: `Running::stop` ends
    /// their reads with it, so that a connection that waits for a call ends
    /// at once and one that serves a call ends with its reply.
    open: std::sync::Mutex<std::collections::HashMap<u64, UnixStream>>,
    next: std::sync::atomic::AtomicU64,
    /// The threads of the connections that may still run: `Running::stop`
    /// joins them, so that none holds the server (whose last holder drops
    /// its runtime and the pulls on it) once it returned.
    threads: std::sync::Mutex<Vec<std::thread::JoinHandle<()>>>,
    /// `Running::stop` ended the reads: a connection answers the call it
    /// serves and ends.
    stopping: AtomicBool,
    /// Whether the server leaves: set by `wait_idle` and looked at before
    /// each accept, under this one lock, so that a connection is either taken
    /// before the decision (and counted in `live`, which keeps the server) or
    /// never taken by this server (it stays queued: for the next server on a
    /// socket systemd passed, for `Running::leave` on one of its own).
    leaving: std::sync::Mutex<bool>,
}

/// A server that listens.
pub struct Running {
    pub socket: PathBuf,
    stop: Arc<AtomicBool>,
    /// The listening socket, to end the accept of the thread by (not by a
    /// connection to the path, which may be gone).
    listener: Option<OwnedFd>,
    thread: Option<std::thread::JoinHandle<()>>,
    server: Arc<Server>,
    /// The socket was bound by the server (`listen`), not passed (`serve`).
    own: bool,
}

impl Running {
    /// Stop accepting, let the calls in flight finish and return once every
    /// connection ended: nothing of the server runs, or touches the stores,
    /// afterwards.  A connection that waits for a call ends at once; one
    /// that serves a call ends with its reply (a call that came before is
    /// still served: it is in flight).
    pub fn stop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        // (so that the accept in the thread returns: EINVAL, the listener is
        // shut down)
        if let Some(l) = self.listener.take() {
            let _ = rustix::net::shutdown(&l, rustix::net::Shutdown::Both);
        }
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
        // (no connection comes any more: those open are all there will be)
        self.server.end_connections();
    }
}

impl Running {
    /// Whether a connection waits in the backlog of the listener.
    fn pending(&self) -> bool {
        let Some(l) = &self.listener else {
            return false;
        };
        let mut fds = [rustix::event::PollFd::new(l, rustix::event::PollFlags::IN)];
        let zero = rustix::event::Timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        rustix::event::poll(&mut fds, Some(&zero)).is_ok_and(|n| n > 0)
    }

    /// Block until the server has not been busy for `idle` and no connection
    /// waits to be accepted; from then on no connection is accepted.
    pub fn wait_idle(&self, idle: Duration) {
        self.server.wait_idle_on(idle, &|| self.pending());
    }

    /// After `wait_idle`: give up the socket.  One systemd passed is left as
    /// it is, with the connections that wait on it, for the next server it
    /// starts.  One of the server's own is removed and shut down (no
    /// connection can come any more), the connections that came before that
    /// are accepted and served, and this returns once they and the pulls they
    /// started are over: no connection the kernel took for the server is
    /// dropped.
    pub fn leave(&self) {
        if !self.own {
            return;
        }
        let _ = std::fs::remove_file(&self.socket);
        let Some(l) = &self.listener else { return };
        let _ = rustix::net::shutdown(l, rustix::net::Shutdown::Both);
        // (a listener that is shut down stays readable: accept until EAGAIN)
        let Ok(l) = l.try_clone().map(UnixListener::from) else {
            return;
        };
        if l.set_nonblocking(true).is_err() {
            return;
        }
        while let Ok((stream, _)) = l.accept() {
            // (blocking as every connection of the server)
            if stream.set_nonblocking(false).is_ok() {
                self.server.spawn_connection(stream);
            }
        }
        let activity = &self.server.stores.activity;
        loop {
            let seen = activity.generation();
            if !self.server.busy() {
                break;
            }
            activity.wait_after(seen, None);
        }
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        self.stop();
    }
}

type Out = Vec<(Vec<u8>, Vec<OwnedFd>)>;

/// What a call is, with the connection it came on.
pub(crate) struct Call<'a> {
    pub bytes: &'a [u8],
    pub fds: Vec<OwnedFd>,
    pub uid: u32,
}

#[derive(serde::Deserialize)]
struct Body<T> {
    parameters: T,
}

impl Call<'_> {
    /// The parameters of the call.
    pub fn params<T: DeserializeOwned>(&self) -> DriverResult<T> {
        serde_json::from_slice::<Body<T>>(self.bytes)
            .map(|b| b.parameters)
            .map_err(|e| DriverError::storage(NAME, format!("the parameters of the call: {e}")))
    }
}

pub(crate) fn failed(e: impl std::fmt::Display) -> DriverError {
    DriverError::storage(NAME, e.to_string())
}

/// The message of an error of the interface.
pub(crate) fn error_message(e: &StorageError) -> Vec<u8> {
    let (name, body) = match e {
        StorageError::Missing {
            reason,
            layer,
            remedy,
        } => (
            "Missing",
            json!({"reason": reason, "layer": layer, "remedy": remedy}),
        ),
        StorageError::Corrupt {
            reason,
            layer,
            remedy,
        } => (
            "Corrupt",
            json!({"reason": reason, "layer": layer, "remedy": remedy}),
        ),
        StorageError::Unsupported { reason } => ("Unsupported", json!({"reason": reason})),
        StorageError::NotFound { reason } => ("NotFound", json!({"reason": reason})),
        StorageError::Busy { reason } => ("Busy", json!({"reason": reason})),
        StorageError::LabelRefused { reason } => ("LabelRefused", json!({"reason": reason})),
        StorageError::Unavailable { reason } => ("Unavailable", json!({"reason": reason})),
        StorageError::Failed { reason } => ("Failed", json!({"reason": reason})),
    };
    encode_error(&format!("{}.{name}", proto::INTERFACE), &body)
}

pub(crate) fn reply<T: Serialize>(t: &T) -> Out {
    vec![(encode_reply(t, false), Vec::new())]
}

pub(crate) fn reply_fds<T: Serialize>(t: &T, fds: Vec<OwnedFd>) -> Out {
    vec![(encode_reply(t, false), fds)]
}

pub(crate) fn send(conn: &mut Conn, message: &[u8], fds: &[OwnedFd]) -> std::io::Result<()> {
    let borrowed: Vec<BorrowedFd<'_>> = fds.iter().map(AsFd::as_fd).collect();
    conn.send(message, &borrowed)
}

impl Server {
    pub fn new(config: Config) -> std::io::Result<Arc<Self>> {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(4)
            .thread_name("storage-server")
            .enable_all()
            .build()?;
        let stores = Stores::new(&config.root, rt.handle().clone());
        Ok(Arc::new(Self {
            config,
            stores,
            rt,
            live: Default::default(),
            open: Default::default(),
            next: Default::default(),
            threads: Default::default(),
            stopping: AtomicBool::new(false),
            leaving: Default::default(),
        }))
    }

    /// Listen on `socket` and serve the connections, each from a thread of
    /// its own.  The socket has mode 0600 from its creation; one that a
    /// server still listens on is not taken (`AddrInUse`), a stale one is
    /// replaced, and anything else at the path is an error
    /// (`velarx_base::ipc::bind_unique`).
    pub fn listen(self: &Arc<Self>, socket: &Path) -> std::io::Result<Running> {
        let mut running = self.serve(velarx_base::ipc::bind_unique(socket, true)?, socket)?;
        running.own = true;
        Ok(running)
    }

    /// Serve the connections of `listener`, a listening socket made by
    /// someone else (systemd's, passed as descriptor 3): `socket` only
    /// names it.
    pub fn serve(
        self: &Arc<Self>,
        listener: UnixListener,
        socket: &Path,
    ) -> std::io::Result<Running> {
        use velarx_base::ipc::{accept_failure, AcceptFailure, ACCEPT_WAIT};
        // (a socket passed with `NonBlocking=` would make the accept below
        // spin: it waits)
        listener.set_nonblocking(false)?;
        let held = OwnedFd::from(listener.try_clone()?);
        let stop = Arc::new(AtomicBool::new(false));
        let (server, flag) = (self.clone(), stop.clone());
        let thread = std::thread::Builder::new()
            .name("storage-accept".into())
            .spawn(move || loop {
                // (wait for a connection without taking it: whether the
                // server leaves is decided between two accepts)
                let mut fds = [rustix::event::PollFd::new(
                    &listener,
                    rustix::event::PollFlags::IN,
                )];
                if let Err(e) = rustix::event::poll(&mut fds, None) {
                    if e == rustix::io::Errno::INTR {
                        continue;
                    }
                    return;
                }
                if flag.load(Ordering::SeqCst) {
                    return;
                }
                let leaving = server.leaving.lock().unwrap_or_else(|e| e.into_inner());
                if *leaving {
                    return;
                }
                // (readable, and this thread is the only one that accepts:
                // the accept does not block)
                match listener.accept() {
                    Ok((stream, _)) => server.spawn_connection(stream),
                    Err(e) => match accept_failure(&e) {
                        AcceptFailure::Retry => {}
                        // (out of descriptors or memory: the connection
                        // stays queued until a connection ends)
                        AcceptFailure::Wait => {
                            drop(leaving);
                            std::thread::sleep(ACCEPT_WAIT);
                        }
                        AcceptFailure::Broken => return,
                    },
                }
            })?;
        Ok(Running {
            socket: socket.to_path_buf(),
            stop,
            listener: Some(held),
            thread: Some(thread),
            server: self.clone(),
            own: false,
        })
    }

    /// Whether the server has work: a connection is open (a call may be in
    /// flight on it) or a pull holds claims.  An idle server is not busy.
    pub fn busy(&self) -> bool {
        self.live.load(Ordering::SeqCst) > 0 || self.stores.holds_claims()
    }

    /// Serve `stream` from a thread of its own, counted in `live` while it
    /// lasts (one over `MAX_CONNECTIONS` is closed).
    fn spawn_connection(self: &Arc<Self>, stream: UnixStream) {
        /// (the count goes down however the connection ends)
        struct Live(Arc<Server>, u64);
        impl Drop for Live {
            fn drop(&mut self) {
                self.0
                    .open
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .remove(&self.1);
                self.0.live.fetch_sub(1, Ordering::SeqCst);
                self.0.stores.activity.notify();
            }
        }
        if self.live.fetch_add(1, Ordering::SeqCst) >= MAX_CONNECTIONS {
            self.live.fetch_sub(1, Ordering::SeqCst);
            return;
        }
        let number = self.next.fetch_add(1, Ordering::SeqCst);
        match stream.try_clone() {
            Ok(handle) => {
                self.open
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .insert(number, handle);
            }
            Err(_) => {
                self.live.fetch_sub(1, Ordering::SeqCst);
                return;
            }
        }
        self.stores.activity.notify();
        let live = Live(self.clone(), number);
        let spawned = std::thread::Builder::new()
            .name("storage-conn".into())
            .spawn(move || {
                live.0.connection(stream);
                drop(live);
            });
        if let Ok(thread) = spawned {
            let mut threads = self.threads.lock().unwrap_or_else(|e| e.into_inner());
            threads.retain(|t| !t.is_finished());
            threads.push(thread);
        }
    }

    /// End the reads of the connections open and return once their threads
    /// ended (`Running::stop`, after which none is accepted): a thread
    /// that is gone holds the server no more, so the caller's is the last
    /// hold but those it knows of.
    fn end_connections(&self) {
        self.stopping.store(true, Ordering::SeqCst);
        self.stores.activity.notify();
        for stream in self.open.lock().unwrap_or_else(|e| e.into_inner()).values() {
            // (what is queued is read first, then the end: a call that came
            // is answered; one that comes after is refused, EPIPE)
            let _ = stream.shutdown(std::net::Shutdown::Read);
        }
        let threads = std::mem::take(&mut *self.threads.lock().unwrap_or_else(|e| e.into_inner()));
        for t in threads {
            let _ = t.join();
        }
    }

    /// Block until the server has not been busy for `idle`; from then on it
    /// accepts no connection (`Running::wait_idle` also waits for the
    /// connections queued on its socket).
    pub fn wait_idle(&self, idle: Duration) {
        self.wait_idle_on(idle, &|| false);
    }

    fn wait_idle_on(&self, idle: Duration, pending: &dyn Fn() -> bool) {
        let activity = &self.stores.activity;
        // (the last time something kept the server busy or came or went)
        let mut since = std::time::Instant::now();
        loop {
            // (read before looking: a change meanwhile ends the wait below)
            let seen = activity.generation();
            // (under the lock the accept takes: a connection is counted in
            // `live` before this looks, or is never accepted)
            let mut leaving = self.leaving.lock().unwrap_or_else(|e| e.into_inner());
            if self.busy() || pending() {
                drop(leaving);
                activity.wait_after(seen, None);
                since = std::time::Instant::now();
                continue;
            }
            let left = idle.saturating_sub(since.elapsed());
            if left.is_zero() {
                *leaving = true;
                return;
            }
            drop(leaving);
            if activity.wait_after(seen, Some(left)) {
                since = std::time::Instant::now();
            }
        }
    }

    fn connection(self: &Arc<Self>, stream: UnixStream) {
        // (the user of the server and root only, as for every private
        // socket of the engine's services)
        if velarx_base::ipc::check_client(&stream, velarx_base::ipc::trusted_uid).is_err() {
            return;
        }
        let uid = match rustix::net::sockopt::socket_peercred(&stream) {
            Ok(c) => c.uid.as_raw(),
            Err(_) => return,
        };
        // (a client that stops reading does not hold the thread: a reply that
        // cannot be written within the idle deadline ends the connection, and
        // so does a call that does not come within it)
        if stream.set_write_timeout(Some(self.config.timeout)).is_err() {
            return;
        }
        let mut conn = Conn::from_stream(stream);
        loop {
            conn.set_deadline(std::time::Instant::now() + self.config.timeout);
            let Ok(bytes) = conn.message() else { return };
            conn.clear_deadline();
            let fds = conn.take_fds();
            let Ok(head) = parse_call(&bytes) else { return };
            let Some(method) = head
                .method
                .strip_prefix(proto::INTERFACE)
                .and_then(|m| m.strip_prefix('.'))
                .map(str::to_string)
            else {
                let m = encode_error(
                    "org.varlink.service.InterfaceNotFound",
                    &json!({ "interface": head.method }),
                );
                if conn.send(&m, &[]).is_err() {
                    return;
                }
                continue;
            };
            let call = Call {
                bytes: &bytes,
                fds,
                uid,
            };
            match self.dispatch(&method, call, &mut conn) {
                Ok(out) => {
                    for (message, fds) in out {
                        if send(&mut conn, &message, &fds).is_err() {
                            return;
                        }
                    }
                }
                Err(e) => {
                    let message = error_message(&convert::error_to_wire(&e));
                    if conn.send(&message, &[]).is_err() {
                        return;
                    }
                }
            }
            // (answered: no other call is served once the server stops)
            if self.stopping.load(Ordering::SeqCst) {
                return;
            }
        }
    }

    pub(crate) fn store(&self, call: &Call<'_>, id: &str) -> DriverResult<Arc<Store>> {
        self.stores.get(call.uid, id)
    }

    /// Run `op` on a thread and tell the engine it goes on, every half of the
    /// timeout, until it ends: the last reply is its result.  The messages
    /// are the replies of the call, so the reply of progress is
    /// `{"progress": {..}}`.
    pub(crate) fn long<T: Serialize + Send>(
        &self,
        conn: &mut Conn,
        what: &str,
        op: impl FnOnce() -> DriverResult<T> + Send,
    ) -> DriverResult<Out> {
        let interval = velarx_graph::longcall::progress_interval(self.config.timeout);
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::scope(|scope| {
            scope.spawn(move || {
                let _ = tx.send(op());
            });
            loop {
                match rx.recv_timeout(interval) {
                    Ok(result) => return result.map(|t| reply(&t)),
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                        let m = encode_reply(
                            &json!({"progress": {"message": format!("{what}: working")}}),
                            true,
                        );
                        conn.send(&m, &[]).map_err(failed)?;
                    }
                    Err(_) => return Err(failed(format!("{what} ended without a result"))),
                }
            }
        })
    }

    fn dispatch(
        self: &Arc<Self>,
        method: &str,
        call: Call<'_>,
        conn: &mut Conn,
    ) -> DriverResult<Out> {
        match method {
            // (the objects of the store are asked about, and the `copy`
            // events of a fetch are applied)
            "GetInfo" => Ok(reply(&convert::info_to_wire(
                NAME,
                env!("CARGO_PKG_VERSION"),
                &capabilities(),
                true,
            ))),
            "ListStores" => Ok(reply(&proto::StoresReply {
                stores: self
                    .stores
                    .list(call.uid)
                    .into_iter()
                    .map(|(store, bytes, last_open)| proto::StoreEntry {
                        store,
                        bytes,
                        last_open: last_open.map(|t| t as i64),
                    })
                    .collect(),
            })),
            "DropStore" => {
                let p: request::OfStore<String> = call.params()?;
                self.stores.drop(call.uid, &p.store)?;
                Ok(reply(&proto::Ack {}))
            }
            "HasLayers" => {
                let p: request::HasLayers<String, Vec<proto::LayerRef>> = call.params()?;
                let store = self.store(&call, &p.store)?;
                let refs = refs(&p.layers)?;
                let have = self.rt.block_on(store.vfs.has_layers(&refs))?;
                Ok(reply(&proto::HasReply { have }))
            }
            "HasObjects" => {
                let p: request::HasObjects<String, Vec<String>> = call.params()?;
                let store = self.store(&call, &p.store)?;
                if p.objects.len() as u64 > proto::MAX_WANTS {
                    return Err(DriverError::of(
                        NAME,
                        DriverErrorKind::Unsupported,
                        format!("at most {} objects in a call", proto::MAX_WANTS),
                    ));
                }
                // (an object the store has, under its name or by an alias of
                // it.  One that a pull that is not over has, and that no
                // committed layer records, is that pull's: it may still be
                // aborted and the object removed, so it is not held)
                let running: std::collections::HashSet<String> = {
                    let st = store.state();
                    st.pulls
                        .values()
                        .filter(|p| !matches!(p.phase, crate::store::Phase::Over(_)))
                        .flat_map(|p| p.keys.iter().cloned())
                        .collect()
                };
                let have = p
                    .objects
                    .iter()
                    .map(|k| {
                        let name = store.resolve(k);
                        store.files.contains(&name)
                            && (!(running.contains(k) || running.contains(&name))
                                || crate::pull::recorded(&store, &name).unwrap_or(false)
                                || crate::pull::recorded(&store, k).unwrap_or(false))
                    })
                    .collect();
                Ok(reply(&proto::ObjectsReply { have }))
            }
            "BeginPull" => self.begin_pull(call, conn),
            "ReadObjects" => self.read_objects(call, conn),
            "Commit" => self.commit(call),
            "Abort" => self.abort(call),
            "CreateRoot" => self.create_root(call, conn),
            "CreateImageVolume" => self.create_image_volume(call, conn),
            "Mounts" => self.mounts(call),
            "MountImage" => self.mount_image(call),
            "WritableRoot" | "Size" | "Exists" | "RemoveRoot" => self.container_call(method, call),
            "RemoveImage" => {
                let p: request::OfImage<String> = call.params()?;
                let store = self.store(&call, &p.store)?;
                store.vfs.remove_image(&p.image)?;
                Ok(reply(&proto::Ack {}))
            }
            "Check" => self.check(call, conn),
            "Repair" => self.repair(call, conn),
            "Collect" => self.collect(call, conn),
            "Usage" => {
                let p: request::OfStore<String> = call.params()?;
                let store = self.store(&call, &p.store)?;
                let u = store.vfs.usage()?;
                Ok(reply(&proto::UsageReply {
                    files: u.artifacts.0,
                    bytes: u.artifacts.1,
                }))
            }
            "Status" => {
                let p: request::OfStore<String> = call.params()?;
                let store = self.store(&call, &p.store)?;
                let mut pairs: Vec<proto::Pair> = store
                    .vfs
                    .status()
                    .into_iter()
                    .map(|(name, value)| proto::Pair { name, value })
                    .collect();
                pairs.push(proto::Pair {
                    name: "fetch calls".into(),
                    value: store.fetch_calls.load(Ordering::Relaxed).to_string(),
                });
                pairs.push(proto::Pair {
                    name: "fetch keys".into(),
                    value: store.fetch_keys.load(Ordering::Relaxed).to_string(),
                });
                pairs.push(proto::Pair {
                    name: "copy events".into(),
                    value: store.copy_events.load(Ordering::Relaxed).to_string(),
                });
                pairs.push(proto::Pair {
                    name: "copied bytes".into(),
                    value: store.copied_bytes.load(Ordering::Relaxed).to_string(),
                });
                pairs.push(proto::Pair {
                    name: "handed files".into(),
                    value: store.handed_files.load(Ordering::Relaxed).to_string(),
                });
                pairs.push(proto::Pair {
                    name: "handed bytes copied".into(),
                    value: store
                        .handed_copied_bytes
                        .load(Ordering::Relaxed)
                        .to_string(),
                });
                Ok(reply(&proto::StatusReply { pairs }))
            }
            other => Err(DriverError::of(
                NAME,
                DriverErrorKind::Unsupported,
                format!("the storage service has no call {other}"),
            )),
        }
    }

    /// The keep set of a `Collect`: the lines of the descriptor.
    pub(crate) fn keep_of(call: &mut Call<'_>, length: u64) -> DriverResult<Keep> {
        if call.fds.len() != 1 {
            return Err(failed("Collect carries the keep set as one descriptor"));
        }
        // (a sealed memory file of the length the call says, at most
        // `MAX_KEEP`: nothing can change it while it is read)
        let file = std::fs::File::from(call.fds.remove(0));
        let lines = velarx_base::sealed::read_sealed(&file, length, proto::MAX_KEEP)
            .map_err(|what| failed(format!("the keep set {what}")))?;
        Keep::read_lines(&mut lines.as_slice()).map_err(failed)
    }
}

/// What the server can do: what vfs does, but for the image mounts, which
/// are mounts of the copies of the images and need a process that may mount,
/// and the ids of a user namespace of the container, which are given to the
/// files as they are copied by a process that may give them.
pub(crate) fn capabilities() -> velarx_graph::Capabilities {
    let mut c = velarx_vfs::VfsDriver::capabilities_of().clone();
    if !rustix::process::geteuid().is_root() {
        c.volume = None;
        c.root = velarx_graph::MountCaps {
            idmap: velarx_graph::Prefs::NONE,
        };
    }
    c
}

/// The error of an image mount asked of a server that cannot make one.
pub(crate) fn no_mounts() -> DriverError {
    DriverError::of(
        NAME,
        DriverErrorKind::Unsupported,
        "the image mounts of this server are mounts of the copies of the images, and a server that is not root cannot make them",
    )
}

pub(crate) fn refs(layers: &[proto::LayerRef]) -> DriverResult<Vec<velarx_graph::LayerRef>> {
    layers.iter().map(convert::layer_ref).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{Decision, Phase, Pull};

    /// A pull that holds claims keeps the server busy and from being idle,
    /// with no connection open, until it is over.
    #[test]
    fn a_pull_holding_claims_keeps_the_server_busy() {
        let dir = tempfile::tempdir().unwrap();
        let server = Server::new(Config {
            root: dir.path().to_path_buf(),
            timeout: Duration::from_secs(10),
            decision: Duration::from_secs(10),
        })
        .unwrap();
        let store = server
            .stores
            .get(1000, "0123456789abcdef0123456789abcdef")
            .unwrap();
        assert!(!server.busy());
        store.state().pulls.insert(
            "p".into(),
            Pull {
                phase: Phase::Staged,
                decision: Decision::Pending,
                keys: Default::default(),
                ended: None,
            },
        );
        assert!(server.busy());
        let (tx, rx) = std::sync::mpsc::channel();
        let s = server.clone();
        std::thread::spawn(move || {
            s.wait_idle(Duration::from_millis(100));
            let _ = tx.send(());
        });
        std::thread::sleep(Duration::from_millis(800));
        assert!(rx.try_recv().is_err(), "idle while a pull holds claims");
        store.state().pulls.get_mut("p").unwrap().phase = Phase::Over(Ok(()));
        store.notify();
        rx.recv_timeout(Duration::from_secs(10))
            .expect("idle once the pull is over");
    }

    /// A call in flight when the server stops is answered before `stop`
    /// returns, and nothing of the server runs, or touches the root, after
    /// it: the connection of the call is over, the root can go.
    #[test]
    fn stop_returns_once_the_calls_in_flight_are_answered() {
        const ID: &str = "0123456789abcdef0123456789abcdef";
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("server");
        let server = Server::new(Config {
            root: root.clone(),
            timeout: Duration::from_secs(30),
            decision: Duration::from_secs(60),
        })
        .unwrap();
        let mut running = server.listen(&dir.path().join("s.sock")).unwrap();
        let uid = rustix::process::geteuid().as_raw();
        let store = server.stores.get(uid, ID).unwrap();
        store.state().pulls.insert(
            "p".into(),
            Pull {
                phase: Phase::Staged,
                decision: Decision::Pending,
                keys: Default::default(),
                ended: None,
            },
        );
        // the call: it waits for the pull to end
        let mut client = velarx_wire::varlink::Conn::connect(&running.socket).unwrap();
        client.set_deadline(std::time::Instant::now() + Duration::from_secs(30));
        client
            .call_raw(
                "org.velarx.Storage.Abort",
                Some(json!({"store": ID, "pull": "p"}).to_string().as_bytes()),
                false,
                &[],
            )
            .unwrap();
        // ... in flight: it decided, and waits (the state changes with it)
        let mut st = store.state();
        while !matches!(st.pulls["p"].decision, Decision::Abort) {
            st = store.wait(st, Duration::from_secs(30));
        }
        drop(st);
        // the pull ends once the server is stopping, not before: the call
        // is in flight when `stop` begins, and ends during it
        let (s, st2) = (server.clone(), store.clone());
        let ender = std::thread::spawn(move || {
            let activity = &s.stores.activity;
            loop {
                let seen = activity.generation();
                if s.stopping.load(Ordering::SeqCst) {
                    break;
                }
                assert!(
                    activity.wait_after(seen, Some(Duration::from_secs(30))),
                    "stop did not begin to end the connections"
                );
            }
            st2.state().pulls.get_mut("p").unwrap().phase = Phase::Over(Ok(()));
            st2.notify();
        });
        running.stop();
        ender.join().unwrap();
        // answered, and over: no connection is left to serve anything, and
        // no thread of one holds the server (the last holder drops the
        // runtime of its pulls)
        assert_eq!(server.live.load(Ordering::SeqCst), 0);
        assert_eq!(
            Arc::strong_count(&server),
            2,
            "the test's and the running's"
        );
        let reply = client.message().unwrap();
        assert!(
            !String::from_utf8_lossy(&reply).contains("error"),
            "{}",
            String::from_utf8_lossy(&reply)
        );
        // the root goes, and stays gone
        drop(store);
        std::fs::remove_dir_all(&root).unwrap();
        drop(running);
        assert!(!root.exists());
        drop(server);
    }
}
