// SPDX-License-Identifier: Apache-2.0
//! The serving end of the fetcher interface:
//! the scope of a connection (`Open`, `Layer`, `Forget`), the
//! connections for other calls (`Connect`), and the calls that bring
//! content (`GetFile`, `GetBlob`, `Probe`, `Unpack`,
//! `Fetch`), which a [`StagingFetcher`] implements.  What
//! a fetcher does not implement is `unavailable`: a [`StagingFetcher`] with
//! none of the methods is a valid fetcher that has nothing.
//!
//! The engine-side feed has no interface of its own: what a fetcher has to
//! tell the engine (a file is staged, a failure, progress) is a reply
//! of the call the engine made (`Probe`, `Fetch`).

use crate::activation;
use crate::fetcher::fetch::{
    Ack, Answer, Blob, BlobReply, EventKind, Failure, FailureClass, FetchEvent, FetchReply,
    FetcherError, FileKind, NotLazy, Parts, ProbeReply, Probed, Reuse, TocSource, Urgency,
    MAX_ACCESS, MAX_FDS, PROTO,
};
use crate::fetcher::proto::{
    Ack as RegistryAck, Downloaded, Found, Hit, RegistryError, Remote, Tagged, MAX_ANSWER,
};
use crate::fetcher::Cancel;
use crate::pusher::push::{
    Ack as PushAck, CommitReply, EventKind as PushEventKind, Have, Object, Placed,
    ProbeReply as PushProbeReply, Probed as PushProbed, PusherError, PutEvent, PutReply, Role,
    MAX_ACCESS as MAX_PUSH_ACCESS, MAX_FDS as MAX_PUSH_FDS, MAX_OBJECTS, PROTO as PUSH_PROTO,
};
use crate::serve_push::{self as push, PushScope, Pushing, PutCall};
use crate::serve_registry::{self as reg, RegistryCalls};
use async_trait::async_trait;
use futures::Stream;
use std::collections::HashMap;
use std::fs::File;
use std::os::fd::OwnedFd;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;
use velarx_proto::descriptors::Descriptors;
use velarx_proto::info::Info;
use zlink::Reply;

/// What a fetcher says about itself.
#[derive(Debug, Clone)]
pub struct Described {
    pub name: String,
    /// The words of `GetInfo`
    pub capabilities: Vec<String>,
    /// The most objects of a `Fetch`
    pub max_objects: u32,
}

/// What `Open` gave the connection.
#[derive(Debug, Clone)]
pub struct Scope {
    /// fs-verity is enabled on a file before it has its name
    pub verity: bool,
    /// What the origin's transport names (`registry/name`, `oci:PATH`, ...)
    pub source: Option<String>,
    pub tls_verify: Option<bool>,
    /// The origin the client opened, for an origin that is a path
    pub target: Option<Arc<File>>,
    /// The JSON of a `RegistryAccess`, from a sealed memory file
    pub access: Option<zeroize::Zeroizing<Vec<u8>>>,
    /// The most this connection's calls stay silent: a call with replies to
    /// come says something at least every half of it
    pub idle: std::time::Duration,
    /// What the fetcher keeps for the blobs of the scope, by the digest of
    /// the layer: let go by `Forget` of the layer and with the scope
    pub kept: Arc<Kept>,
}

/// See [`Scope::kept`].
pub type Kept = Mutex<HashMap<String, Arc<dyn std::any::Any + Send + Sync>>>;

/// `work` (the part of a fetcher that serves a call), and while it is
/// pending a beat on `out` at least every half of `idle`: the engine ends a
/// call that is silent for `idle`, and a fetcher that is alive is not
/// silent.  A beat is a `progress` with no object and no bytes.
pub async fn beating<T, F: std::future::Future>(
    out: &Out<T>,
    idle: std::time::Duration,
    beat: impl Fn() -> T,
    work: F,
) -> F::Output {
    tokio::pin!(work);
    let every = (idle / 2).max(std::time::Duration::from_micros(1));
    let mut ticker = tokio::time::interval_at(tokio::time::Instant::now() + every, every);
    loop {
        tokio::select! {
            done = &mut work => return done,
            _ = ticker.tick() => {
                // (the asker went: the call is cancelled by its end)
                let _ = out.send(beat()).await;
            }
        }
    }
}

/// The file of a `GetBlob` while the blob is written into it: the size and
/// the digest the descriptor says are checked as the bytes go, so that a
/// fetcher streams a blob of any size and holds none of it.  Whole blocks
/// of zeros are holes of the file.
pub struct BlobFile {
    out: velarx_storage::SparseWriter<File>,
    hasher: velarx_types::digest::DigestWriter,
    digest: velarx_types::digest::Digest,
    size: u64,
    /// The bytes given so far, which the call tells the engine
    written: Arc<std::sync::atomic::AtomicU64>,
}

impl BlobFile {
    pub fn new(file: File, blob: &Blob) -> Result<Self, FetcherError> {
        let digest: velarx_types::digest::Digest =
            blob.digest
                .parse()
                .map_err(|_| FetcherError::InvalidArgument {
                    reason: "not the digest of a blob".into(),
                })?;
        Ok(Self {
            out: velarx_storage::SparseWriter::new(file),
            hasher: velarx_types::digest::DigestWriter::for_digest(&digest),
            digest,
            size: blob.size,
            written: Arc::default(),
        })
    }

    /// The next bytes of the blob; more than its size is an error.
    pub fn write(&mut self, data: &[u8]) -> Result<(), FetcherError> {
        use std::sync::atomic::Ordering::Relaxed;
        let written = self.written.fetch_add(data.len() as u64, Relaxed) + data.len() as u64;
        if written > self.size {
            return Err(FetcherError::invalid(format!(
                "the blob {} is longer than the {} bytes of its descriptor",
                self.digest, self.size
            )));
        }
        self.hasher.update(data);
        self.out.write(data)?;
        Ok(())
    }

    /// The bytes given so far, as the call that wrote them tells them.
    pub fn progress(&self) -> Arc<std::sync::atomic::AtomicU64> {
        self.written.clone()
    }

    /// The blob is complete: it has all its bytes and its digest.
    pub fn finish(self) -> Result<(), FetcherError> {
        let written = self.written.load(std::sync::atomic::Ordering::Relaxed);
        if written != self.size {
            return Err(FetcherError::invalid(format!(
                "the blob {} has {written} bytes, the descriptor says {}",
                self.digest, self.size
            )));
        }
        self.out.finish()?;
        let got = self.hasher.finalize();
        if got != self.digest {
            return Err(FetcherError::invalid(format!(
                "the blob {} has the digest {got}",
                self.digest
            )));
        }
        Ok(())
    }
}

/// What `Layer` told of a layer.
pub struct LayerScope {
    /// The digest of the layer's blob, which names it
    pub layer: String,
    /// The layer's staging directory
    pub staging: File,
    /// Its table of contents as the engine verified it (compressed with
    /// zstd)
    pub toc: Option<File>,
    /// The blob of the layer, as the manifest describes it
    pub blob: Blob,
    /// Cancelled by `Forget`
    pub cancel: Cancel,
    /// What the fetcher derived from the layer as this scope told it (its
    /// parsed table of contents), made once and gone with the layer
    pub kept: std::sync::OnceLock<Arc<dyn std::any::Any + Send + Sync>>,
}

/// A `Fetch`.
pub struct FetchCall {
    pub objects: Vec<String>,
    pub urgency: Urgency,
    /// Chunks of the engine's store the files may take ([`Reuse`]), and the
    /// files they are in, by `Reuse::fd`
    pub reuse: Vec<Reuse>,
    /// A small file is handed over as a descriptor of its event, with no
    /// name in the staging (`FetchEvent::files`)
    pub handover: bool,
    pub sources: Vec<File>,
    /// Cancelled when the client goes away or the layer is cancelled
    pub cancel: Cancel,
}

/// What an `Unpack` asks.
pub struct UnpackCall {
    /// Cancelled when the client goes away or the layer is cancelled
    pub cancel: Cancel,
}

/// The most reuse hints of one `Fetch` (a chunk is 16 KiB or more: a
/// layer of a few GiB).
const MAX_HINTS: usize = 1 << 18;

/// The layers one scope keeps at once (each holds its staging directory
/// and its table of contents until `Forget`).
const MAX_LAYERS: usize = 1024;

/// `work` on `runtime`, aborted when the future of this is dropped: a
/// call whose asker went stops (its requests are dropped with it).
async fn owned<T: Send + 'static>(
    runtime: &tokio::runtime::Handle,
    work: impl std::future::Future<Output = T> + Send + 'static,
) -> Result<T, tokio::task::JoinError> {
    struct Abort(tokio::task::AbortHandle);
    impl Drop for Abort {
        fn drop(&mut self) {
            self.0.abort();
        }
    }
    let task = runtime.spawn(work);
    let _abort = Abort(task.abort_handle());
    task.await
}

/// Where the replies of a call go.
pub struct Out<T> {
    tx: mpsc::Sender<(T, Vec<OwnedFd>)>,
}

impl<T> Clone for Out<T> {
    fn clone(&self) -> Self {
        Self {
            tx: self.tx.clone(),
        }
    }
}

impl<T> Out<T> {
    pub fn new(tx: mpsc::Sender<(T, Vec<OwnedFd>)>) -> Self {
        Self { tx }
    }
}

/// The client went away.
#[derive(Debug, Clone, Copy)]
pub struct Gone;

impl<T> Out<T> {
    pub async fn send(&self, reply: T) -> Result<(), Gone> {
        self.send_with(reply, Vec::new()).await
    }

    /// A reply that carries descriptors (the order the method says).
    pub async fn send_with(&self, reply: T, fds: Vec<OwnedFd>) -> Result<(), Gone> {
        self.tx.send((reply, fds)).await.map_err(|_| Gone)
    }

    /// [`Out::send_with`] for a thread that is not one of the runtime's.
    pub fn blocking_send_with(&self, reply: T, fds: Vec<OwnedFd>) -> Result<(), Gone> {
        self.tx.blocking_send((reply, fds)).map_err(|_| Gone)
    }
}

/// What a fetcher does.  The defaults are those of a fetcher that has
/// nothing: nothing is available.
#[async_trait]
pub trait StagingFetcher: Send + Sync + 'static {
    fn described(&self) -> Described;

    /// The scope is open: what a fetcher does with its origin before the
    /// first call (the fetcher of a path confines its process here).
    async fn opened(&self, _scope: &Scope) -> Result<(), FetcherError> {
        Ok(())
    }

    /// What can this fetcher do for `layers`?  One reply for each, in any
    /// order, that carries the `parts` of a table of contents.  `again`: the
    /// index it carried for a layer without a table of contents in the last
    /// probe of the scope was wrong.
    async fn probe(
        &self,
        _scope: &Scope,
        layers: Vec<Blob>,
        (_again, _parts): (bool, Parts),
        out: &Out<Probed>,
    ) -> Result<(), FetcherError> {
        for (at, _) in layers.iter().enumerate() {
            out.send(Probed {
                layer: at as u32,
                toc: TocSource::None,
                on_demand: false,
                reason: Some(NotLazy::Unreachable),
                toc_file: None,
                tarsplit_file: None,
            })
            .await
            .map_err(gone)?;
        }
        Ok(())
    }

    /// The small file `kind` names, of `reference` (none: what the source of
    /// the scope names), at most `max` bytes: the manifest or index a tag
    /// or digest names (and its media type, when it is known), the startup
    /// profile of an image, or the signatures of a manifest or tag (a JSON
    /// array of [`SignedRecord`]).
    async fn get_file(
        &self,
        _scope: &Scope,
        _kind: FileKind,
        _reference: Option<&str>,
        _max: u64,
    ) -> Result<(File, Option<String>), FetcherError> {
        Err(FetcherError::unavailable("nobody has it"))
    }

    /// The blob the descriptor names, written into `out` (the file is
    /// empty, open for writing, the engine's): exactly the bytes the
    /// descriptor say, of its digest, and `out.finish()` at the end.  A
    /// fetcher streams it; it never holds the blob.
    async fn get_blob(
        &self,
        _scope: &Scope,
        blob: &Blob,
        _out: BlobFile,
    ) -> Result<(), FetcherError> {
        Err(FetcherError::unavailable(format!(
            "{}: nobody has it",
            blob.digest
        )))
    }

    /// Read the whole blob of the layer (one with no table of contents) and
    /// give its files, as the descriptors of `staged` events (the positions
    /// of the events' `objects`), and `toc.claim` and `tarsplit` names in its
    /// staging directory.  `out` gets `progress` events with the cumulative
    /// bytes of the blob.  Ends with `Ok` when the names are given.
    async fn unpack(
        &self,
        _scope: &Scope,
        _layer: &LayerScope,
        _call: UnpackCall,
        _out: &Out<FetchEvent>,
    ) -> Result<(), FetcherError> {
        Err(FetcherError::unavailable("this fetcher does not unpack"))
    }

    /// Bring files of the layer into its staging directory.
    async fn fetch(
        &self,
        _scope: &Scope,
        _layer: &LayerScope,
        call: FetchCall,
        out: &Out<FetchEvent>,
    ) -> Result<(), FetcherError> {
        if !call.objects.is_empty() {
            out.send(FetchEvent {
                objects: (0..call.objects.len() as u32).collect(),
                ..FetchEvent::of(EventKind::Unavailable)
            })
            .await
            .map_err(gone)?;
        }
        Ok(())
    }

    /// The repository calls, when this fetcher serves a registry
    /// (`org.velarx.Registry`).
    fn registry(&self) -> Option<Arc<dyn RegistryCalls>> {
        None
    }

    /// The pusher of this process, when it serves one (`org.velarx.Pusher`,
    /// on the same socket).
    fn pusher(&self) -> Option<Arc<dyn Pushing>> {
        None
    }
}

fn gone(_: Gone) -> FetcherError {
    FetcherError::failed("the asker is gone")
}

/// What the connections of a scope share: the scope and the layers told.
#[derive(Default)]
struct State {
    scope: Option<Arc<Scope>>,
    layers: HashMap<String, Arc<LayerScope>>,
    /// The scope of a connection used as a pusher, and the objects it was
    /// told of
    push: Option<Arc<PushScope>>,
}

/// A connection being served.
struct Peer {
    activity: Arc<activation::Activity>,
    client: activation::Client,
}

/// A stream of answers.
/// How a call's replies are made of what the fetcher says, and the error of a
/// task that stopped.
type Wrapping<T, R, E> = (fn(T) -> Option<R>, fn(String) -> E, Option<fn() -> R>);

type Answers<T, E = FetcherError> =
    Pin<Box<dyn Stream<Item = (Result<Reply<T>, E>, Vec<OwnedFd>)> + Send>>;

/// The service of one connection.
#[derive(Clone)]
pub struct FetchEndpoint {
    api: Arc<dyn StagingFetcher>,
    runtime: tokio::runtime::Handle,
    state: Arc<Mutex<State>>,
    peer: Option<Arc<Peer>>,
}

/// The reference of a `GetFile` of a fetcher whose files are all named.
pub fn named(reference: Option<&str>) -> Result<&str, FetcherError> {
    reference.ok_or_else(|| bad("a reference is needed"))
}

fn bad(reason: &str) -> FetcherError {
    FetcherError::InvalidArgument {
        reason: reason.into(),
    }
}

impl FetchEndpoint {
    pub fn new(api: Arc<dyn StagingFetcher>) -> Self {
        Self {
            api,
            runtime: tokio::runtime::Handle::current(),
            state: Arc::default(),
            peer: None,
        }
    }

    fn scope(&self) -> Result<Arc<Scope>, FetcherError> {
        Scoped::<FetcherScope>::of(self).get()
    }

    fn told(&self, layer: &str) -> Result<Arc<LayerScope>, FetcherError> {
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .layers
            .get(layer)
            .cloned()
            .ok_or_else(|| bad("a layer that was not told or was cancelled"))
    }

    fn failure<T: Send + 'static, E: Send + 'static>(error: E) -> Answers<T, E> {
        Box::pin(futures::stream::once(
            async move { (Err(error), Vec::new()) },
        ))
    }

    /// The answers of a call that runs as `task` and tells through `rx`.
    fn answers<T: Send + 'static, R: Send + 'static, E: Send + 'static>(
        cancel: Cancel,
        rx: mpsc::Receiver<(T, Vec<OwnedFd>)>,
        task: tokio::task::JoinHandle<Result<(), E>>,
        done: Option<Box<dyn Fn() -> T + Send>>,
        (wrap, stopped, empty): Wrapping<T, R, E>,
    ) -> Answers<R, E> {
        struct Guard(Cancel);
        impl Drop for Guard {
            fn drop(&mut self) {
                self.0.cancel();
            }
        }
        enum Run<T, E> {
            Going(
                mpsc::Receiver<(T, Vec<OwnedFd>)>,
                tokio::task::JoinHandle<Result<(), E>>,
            ),
            Over,
        }
        Box::pin(futures::stream::unfold(
            (Run::Going(rx, task), Guard(cancel), done),
            move |(run, guard, done)| async move {
                let Run::Going(mut rx, task) = run else {
                    return None;
                };
                while let Some((message, fds)) = rx.recv().await {
                    // (what the call's reply has no word for is not said)
                    if let Some(message) = wrap(message) {
                        let reply = Reply::new(Some(message)).set_continues(Some(true));
                        return Some(((Ok(reply), fds), (Run::Going(rx, task), guard, done)));
                    }
                }
                let outcome = task
                    .await
                    .unwrap_or_else(|e| Err(stopped(format!("the fetcher stopped: {e}"))));
                let last = match (outcome, &done) {
                    (Ok(()), Some(done)) => Ok(Reply::new(wrap(done())).set_continues(Some(false))),
                    (Ok(()), None) => {
                        Ok(Reply::new(empty.map(|empty| empty())).set_continues(Some(false)))
                    }
                    (Err(e), _) => Err(e),
                };
                Some(((last, Vec::new()), (Run::Over, guard, done)))
            },
        ))
    }

    /// Another connection with the scope of this one.
    fn another(&self) -> Result<OwnedFd, FetcherError> {
        let unavailable = |reason: String| FetcherError::unavailable(reason);
        let Some(peer) = &self.peer else {
            return Err(unavailable("this fetcher gives no other connection".into()));
        };
        let client = peer.client;
        let busy = activation::Busy::for_client(&peer.activity, client)
            .map_err(|reason| FetcherError::Busy { reason })?;
        let (ours, theirs) = std::os::unix::net::UnixStream::pair()
            .map_err(|e| unavailable(format!("a socket pair: {e}")))?;
        let ours = ours
            .set_nonblocking(true)
            .and_then(|()| tokio::net::UnixStream::from_std(ours))
            .map_err(|e| unavailable(format!("a socket pair: {e}")))?;
        activation::bound_queued_replies(&ours);
        let endpoint = FetchEndpoint {
            peer: Some(Arc::new(Peer {
                activity: peer.activity.clone(),
                client,
            })),
            ..self.clone()
        };
        activation::admit_varlink(
            ours,
            busy,
            endpoint,
            peer.activity.limits().first_call,
            "fetcher",
        );
        Ok(theirs.into())
    }
}

/// Serve `endpoint` on `connections` until the service leaves (`idle`) or
/// nothing can hand a connection any more; on a runtime of this thread with
/// a `LocalSet` (the servers of zlink are not `Send`).  The calls run on the
/// runtime the endpoint was made on.
pub async fn serve(
    connections: impl Into<activation::Connections>,
    endpoint: FetchEndpoint,
    idle: Option<activation::IdleExit>,
    trusted: fn(u32) -> bool,
    limits: activation::Limits,
) {
    let activity = activation::Activity::new(limits);
    let first = activity.limits().first_call;
    let served = activity.clone();
    activation::serve_loop(
        connections,
        idle,
        trusted,
        activity,
        "fetcher",
        move |stream, busy| {
            let pid = rustix::net::sockopt::socket_peercred(&stream)
                .map_or(0, |c| c.pid.as_raw_nonzero().get());
            // (a connection accepted has a scope of its own; those it gives
            // with Connect share it)
            let endpoint = FetchEndpoint {
                state: Arc::default(),
                peer: Some(Arc::new(Peer {
                    activity: served.clone(),
                    client: activation::Client::Process(pid),
                })),
                ..endpoint.clone()
            };
            activation::admit_varlink(stream, busy, endpoint, first, "fetcher");
        },
    )
    .await;
}

/// Serve `endpoint` on `listener` on a runtime of this thread (current
/// thread, with a `LocalSet`), until the service leaves or `stopped` is
/// done: what the fetcher process runs.
pub fn run_blocking(
    listener: std::os::unix::net::UnixListener,
    endpoint: FetchEndpoint,
    idle: Option<activation::IdleExit>,
    limits: activation::Limits,
    stopped: tokio::sync::oneshot::Receiver<()>,
) -> std::io::Result<()> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let local = tokio::task::LocalSet::new();
    local.block_on(&runtime, async move {
        listener.set_nonblocking(true)?;
        let listener = tokio::net::UnixListener::from_std(listener)?;
        tokio::select! {
            () = serve(listener, endpoint, idle, velarx_base::ipc::trusted_uid, limits) => {}
            _ = stopped => {}
        }
        Ok(())
    })
}

/// Serve `endpoint` on the one connection `stream` (the end of a socket
/// pair the process that started this passed; a service that is its
/// client's alone, no socket of the file system), on a runtime of this
/// thread, until the connection and every one it handed ended or the
/// client did not call within `idle.after`: what a fetcher process started
/// with `--varlink-fd` runs.
pub fn run_one_blocking(
    stream: std::os::unix::net::UnixStream,
    endpoint: FetchEndpoint,
    idle: activation::IdleExit,
    limits: activation::Limits,
) -> std::io::Result<()> {
    run_one(stream, move || endpoint, idle, limits)
}

/// The `main` of a fetcher program that serves what `make` gives on
/// descriptor 3 ([`run_descriptor_3`]) with the default limits.  `make` runs
/// after the descriptors the process was passed are noted.  Call it before
/// `main` opens any file: descriptor 3 must be the one passed.
pub fn main(make: impl FnOnce() -> Arc<dyn StagingFetcher>) -> std::io::Result<()> {
    let startup = velarx_sys::fd::Startup::take()
        .ok_or_else(|| std::io::Error::other("the descriptors of the start were taken"))?;
    run_descriptor_3(&startup, make(), activation::Limits::default())
}

/// Serve `api` on descriptor 3, which the process that started this passed:
/// what any fetcher program does, whoever starts it.  A listening socket (a
/// service manager's, or the one a client bound) is served as a service,
/// until the process is stopped; a connected one is served once, as
/// [`run_one_blocking`] does, and the process leaves at its end.  `startup`
/// is taken first thing in `main`.
pub fn run_descriptor_3(
    startup: &velarx_sys::fd::Startup,
    api: Arc<dyn StagingFetcher>,
    limits: activation::Limits,
) -> std::io::Result<()> {
    let socket = startup
        .adopt(3)
        .ok_or_else(|| std::io::Error::other("no socket on descriptor 3"))?;
    // (not passed on to anything this process starts)
    rustix::io::fcntl_setfd(&socket, rustix::io::FdFlags::CLOEXEC)?;
    if rustix::net::sockopt::socket_acceptconn(&socket)? {
        run_service(std::os::unix::net::UnixListener::from(socket), api, limits)
    } else {
        let idle = activation::IdleExit {
            after: limits.first_call,
            socket: None,
            last: true,
            lock: None,
        };
        run_one(
            std::os::unix::net::UnixStream::from(socket),
            move || FetchEndpoint::new(api),
            idle,
            limits,
        )
    }
}

/// Serve `api` on `listener` on a runtime of this thread, for ever.
fn run_service(
    listener: std::os::unix::net::UnixListener,
    api: Arc<dyn StagingFetcher>,
    limits: activation::Limits,
) -> std::io::Result<()> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let local = tokio::task::LocalSet::new();
    local.block_on(&runtime, async move {
        listener.set_nonblocking(true)?;
        let listener = tokio::net::UnixListener::from_std(listener)?;
        let endpoint = FetchEndpoint::new(api);
        serve(
            listener,
            endpoint,
            None,
            velarx_base::ipc::trusted_uid,
            limits,
        )
        .await;
        Ok(())
    })
}

/// [`run_one_blocking`] for an `api` whose calls run on the same thread as
/// the connection: the process has no other thread until a call makes one
/// (a pusher of a path confines the process in `Open`, which needs that).
pub fn run_one_single_thread(
    stream: std::os::unix::net::UnixStream,
    api: Arc<dyn StagingFetcher>,
    idle: activation::IdleExit,
    limits: activation::Limits,
) -> std::io::Result<()> {
    run_one(stream, move || FetchEndpoint::new(api), idle, limits)
}

fn run_one(
    stream: std::os::unix::net::UnixStream,
    make: impl FnOnce() -> FetchEndpoint,
    idle: activation::IdleExit,
    limits: activation::Limits,
) -> std::io::Result<()> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let local = tokio::task::LocalSet::new();
    local.block_on(&runtime, async move {
        let endpoint = make();
        let (handed, connections) = tokio::sync::mpsc::unbounded_channel();
        handed
            .send(stream)
            .map_err(|_| std::io::Error::other("no connection to serve"))?;
        serve(
            activation::Connections::Handed(connections),
            endpoint,
            Some(idle),
            velarx_base::ipc::trusted_uid,
            limits,
        )
        .await;
        drop(handed);
        Ok(())
    })
}

/// A server thread of [`serve_in_thread`]: it stops when this is dropped,
/// and the drop returns once it ended.
pub struct ServerThread {
    _stopping: Stopping,
}

/// What stops the thread of a fetcher served in this process, and waits
/// for its end, when it is dropped: its connections are gone then (the
/// calls they made are aborted with them).
struct Stopping {
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Drop for Stopping {
    fn drop(&mut self) {
        drop(self.stop.take());
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// Serve `api` from a thread of its own, on `listener`, until the returned
/// guard is dropped: its calls run on the runtime of the caller (a fetcher
/// that is a service of its own, such as the peers).
pub fn serve_in_thread(
    listener: std::os::unix::net::UnixListener,
    api: Arc<dyn StagingFetcher>,
    limits: activation::Limits,
) -> std::io::Result<ServerThread> {
    let endpoint = FetchEndpoint::new(api);
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let thread = std::thread::Builder::new()
        .name("fetcher".into())
        .spawn(move || {
            if let Err(e) = run_blocking(listener, endpoint, None, limits, stopped) {
                tracing::warn!("fetcher: {e}");
            }
        })?;
    Ok(ServerThread {
        _stopping: Stopping {
            stop: Some(stop),
            thread: Some(thread),
        },
    })
}

/// A fetcher served by a thread of this process: each connection to it is
/// one end of a socket pair, which no other process can reach: the fake
/// fetchers of the tests of the walker, on the same interface (the engine
/// runs no fetcher in its process).  It stops when this is dropped, and
/// the drop returns once its thread ended.
pub struct LocalFetcher {
    handed: tokio::sync::mpsc::UnboundedSender<std::os::unix::net::UnixStream>,
    _stopping: Stopping,
}

impl LocalFetcher {
    /// Serve `api`; its calls run on the runtime of the caller.
    pub fn start(
        api: Arc<dyn StagingFetcher>,
        limits: activation::Limits,
    ) -> std::io::Result<Self> {
        let endpoint = FetchEndpoint::new(api);
        let (handed, connections) = tokio::sync::mpsc::unbounded_channel();
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let thread = std::thread::Builder::new()
            .name("fetcher".into())
            .spawn(move || {
                let runtime = match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(r) => r,
                    Err(e) => {
                        tracing::warn!("fetcher: {e}");
                        return;
                    }
                };
                let local = tokio::task::LocalSet::new();
                local.block_on(&runtime, async move {
                    tokio::select! {
                        () = serve(
                            activation::Connections::Handed(connections),
                            endpoint,
                            None,
                            velarx_base::ipc::trusted_uid,
                            limits,
                        ) => {}
                        _ = stopped => {}
                    }
                });
            })?;
        Ok(Self {
            handed,
            _stopping: Stopping {
                stop: Some(stop),
                thread: Some(thread),
            },
        })
    }

    /// A new connection to the fetcher.
    pub fn connect(&self) -> std::io::Result<std::os::unix::net::UnixStream> {
        let (ours, theirs) = std::os::unix::net::UnixStream::pair()?;
        self.handed
            .send(theirs)
            .map_err(|_| std::io::Error::other("the fetcher of this process stopped"))?;
        Ok(ours)
    }
}

/// The bytes of a sealed memory file passed as the credentials, at most
/// `max`; what is wrong with them otherwise.
fn read_access(fd: OwnedFd, max: u64) -> Result<zeroize::Zeroizing<Vec<u8>>, String> {
    let file = File::from(fd);
    velarx_base::sealed::read_sealed_whole(&file, max)
        .map(zeroize::Zeroizing::new)
        .map_err(|what| format!("the access file {what}"))
}

/// What the two interfaces that open a scope have apart: the scope, the
/// words of their errors and where the endpoint keeps the scope.  `Scoped`
/// does the rest, once: `Open` once, `Connect`.
trait ScopeKind {
    type Scope: Send + Sync + 'static;
    type Error;

    /// Where the endpoint keeps the scope of this interface.
    fn slot(state: &mut State) -> &mut Option<Arc<Self::Scope>>;
    /// The most the credentials of this interface take.
    const MAX_ACCESS: u64;
    fn invalid(reason: String) -> Self::Error;
    /// A refusal of a new connection, as this interface says it.
    fn refused(e: FetcherError) -> Self::Error;
}

struct FetcherScope;
struct PusherScope;

impl ScopeKind for FetcherScope {
    type Scope = Scope;
    type Error = FetcherError;
    const MAX_ACCESS: u64 = MAX_ACCESS;

    fn slot(state: &mut State) -> &mut Option<Arc<Scope>> {
        &mut state.scope
    }

    fn invalid(reason: String) -> FetcherError {
        FetcherError::InvalidArgument { reason }
    }

    fn refused(e: FetcherError) -> FetcherError {
        e
    }
}

impl ScopeKind for PusherScope {
    type Scope = PushScope;
    type Error = PusherError;
    const MAX_ACCESS: u64 = MAX_PUSH_ACCESS;

    fn slot(state: &mut State) -> &mut Option<Arc<PushScope>> {
        &mut state.push
    }

    fn invalid(reason: String) -> PusherError {
        push::bad(reason)
    }

    fn refused(e: FetcherError) -> PusherError {
        match e {
            FetcherError::Busy { reason } => PusherError::Busy { reason },
            e => PusherError::unavailable(e.to_string()),
        }
    }
}

/// The scope of one interface of an endpoint: what `GetInfo`, `Open`,
/// and `Connect` of the fetcher and of the pusher share.
struct Scoped<'a, S: ScopeKind> {
    endpoint: &'a FetchEndpoint,
    kind: std::marker::PhantomData<S>,
}

impl<'a, S: ScopeKind> Scoped<'a, S> {
    fn of(endpoint: &'a FetchEndpoint) -> Self {
        Self {
            endpoint,
            kind: std::marker::PhantomData,
        }
    }

    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.endpoint
            .state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
    }

    /// The scope `Open` gave, or a refusal of the call.
    fn get(&self) -> Result<Arc<S::Scope>, S::Error> {
        S::slot(&mut self.state())
            .clone()
            .ok_or_else(|| S::invalid("a call before Open".into()))
    }

    /// The idle time of `Open`.
    fn idle(idle_ms: u64) -> Result<std::time::Duration, S::Error> {
        if idle_ms == 0 {
            return Err(S::invalid("idle_ms is not 0".into()));
        }
        Ok(std::time::Duration::from_millis(idle_ms))
    }

    /// The descriptor of the credentials, read.
    fn access(fd: OwnedFd) -> Result<zeroize::Zeroizing<Vec<u8>>, S::Error> {
        read_access(fd, S::MAX_ACCESS).map_err(S::invalid)
    }

    /// Keep `scope` as the scope of the connection (once) and tell `opened`
    /// of it; a scope that could not be opened is no scope.
    async fn open<F: std::future::Future<Output = Result<(), S::Error>>>(
        &self,
        scope: S::Scope,
        opened: impl FnOnce(Arc<S::Scope>) -> F,
    ) -> Result<(), S::Error> {
        let scope = {
            let mut state = self.state();
            let slot = S::slot(&mut state);
            if slot.is_some() {
                return Err(S::invalid("Open twice".into()));
            }
            let scope = Arc::new(scope);
            *slot = Some(scope.clone());
            scope
        };
        if let Err(e) = opened(scope).await {
            *S::slot(&mut self.state()) = None;
            return Err(e);
        }
        Ok(())
    }

    /// Another connection with the scope of this one.
    fn connect(&self) -> (Result<(), S::Error>, Vec<OwnedFd>) {
        if let Err(e) = self.get() {
            return (Err(e), Vec::new());
        }
        match self.endpoint.another() {
            Ok(fd) => (Ok(()), vec![fd]),
            Err(e) => (Err(S::refused(e)), Vec::new()),
        }
    }
}

/// What `GetInfo` of a fetcher or a pusher says.
fn info_of(d: Described, proto: u32) -> Info {
    Info {
        name: d.name,
        version: env!("CARGO_PKG_VERSION").to_string(),
        proto,
        capabilities: d.capabilities,
        limits: [("max_objects".to_string(), u64::from(d.max_objects))].into(),
    }
}

mod service {
    #![allow(missing_docs)]
    // (the parameters of a method are those of its call: `Fetch` has eight)
    #![allow(clippy::too_many_arguments)]
    use super::*;

    #[zlink::service(
        interface = "org.velarx.Fetcher",
        vendor = "org.velarx",
        product = "velarx",
        version = env!("CARGO_PKG_VERSION"),
        url = env!("CARGO_PKG_REPOSITORY")
    )]
    impl FetchEndpoint {
        /// Who the fetcher is and what it can do.
        #[zlink(
            interface = "org.velarx.Fetcher",
            types = [FileKind, Urgency, Blob, Reuse, TocSource, Parts, NotLazy, FailureClass, Failure, EventKind, FetchEvent, Probed]
        )]
        pub async fn get_info(&self) -> Info {
            info_of(self.api.described(), PROTO)
        }

        /// Give the connection its scope; once, before anything but
        /// `GetInfo`.  `source`: what the origin's transport names
        /// (`registry/name`, `oci:PATH`, `oci-archive:`, `SCHEME://...`);
        /// absent for a fetcher that is not the origin.  `tls_verify`
        /// (default yes) is how a network origin is reached.  `target`: the
        /// origin the client opened, for an origin that is a path (a
        /// directory, or a file open for reading).  `access`: the
        /// credentials, a sealed memory file.  `idle_ms`: the most this
        /// connection's calls stay silent.
        pub async fn open(
            &self,
            #[zlink(fds)] fds: Vec<OwnedFd>,
            verity: bool,
            source: Option<String>,
            tls_verify: Option<bool>,
            target: Option<u32>,
            access: Option<u32>,
            idle_ms: u64,
        ) -> Result<Ack, FetcherError> {
            let idle = Scoped::<FetcherScope>::idle(idle_ms)?;
            let invalid = FetcherScope::invalid;
            let mut fds = Descriptors::new(fds);
            let access = fds
                .take_opt("the access file", access)
                .map_err(invalid)?
                .map(Scoped::<FetcherScope>::access)
                .transpose()?;
            let target = fds
                .take_opt("the target", target)
                .map_err(invalid)?
                .map(|fd| Arc::new(File::from(fd)));
            fds.finish().map_err(invalid)?;
            let scope = Scope {
                verity,
                source,
                tls_verify,
                target,
                access,
                idle,
                kept: Arc::default(),
            };
            Scoped::<FetcherScope>::of(self)
                .open(scope, |scope| async move { self.api.opened(&scope).await })
                .await?;
            Ok(Ack {})
        }

        /// Another connection with the scope of this one: the reply carries
        /// its descriptor.
        #[zlink(return_fds)]
        pub async fn connect(&self) -> (Result<Ack, FetcherError>, Vec<OwnedFd>) {
            let (result, fds) = Scoped::<FetcherScope>::of(self).connect();
            (result.map(|()| Ack {}), fds)
        }

        /// Tell this fetcher of a layer: `staging` its staging directory,
        /// `toc` its table of contents (JSON, or the binary table of a layer
        /// that has one, compressed with zstd, a sealed
        /// memory file).  `Layer` again replaces it; the calls in flight on the
        /// one before end as with `Forget`.  A scope keeps at most 1024 layers
        /// (`Busy`).
        pub async fn layer(
            &self,
            #[zlink(fds)] fds: Vec<OwnedFd>,
            layer: String,
            staging: u32,
            blob: Blob,
            toc: Option<u32>,
        ) -> Result<Ack, FetcherError> {
            self.scope()?;
            let invalid = |reason: String| FetcherError::InvalidArgument { reason };
            let mut fds = Descriptors::new(fds);
            let dir = File::from(
                fds.take("the staging directory", staging)
                    .map_err(|reason| FetcherError::InvalidArgument { reason })?,
            );
            let is_dir = dir.metadata().is_ok_and(|m| m.is_dir());
            let path_only = rustix::fs::fcntl_getfl(&dir)
                .map_or(true, |f| f.contains(rustix::fs::OFlags::PATH));
            if !is_dir || path_only {
                return Err(FetcherError::InvalidArgument {
                    reason: "a directory open for reading (not O_PATH) is needed".into(),
                });
            }
            let toc = fds
                .take_opt("the table of contents", toc)
                .map_err(invalid)?
                .map(File::from);
            fds.finish().map_err(invalid)?;
            if layer.is_empty() || layer.len() > 255 {
                return Err(FetcherError::InvalidArgument {
                    reason: "not the digest of a layer".into(),
                });
            }
            let scope = LayerScope {
                layer: layer.clone(),
                staging: dir,
                toc,
                blob,
                cancel: Cancel::default(),
                kept: std::sync::OnceLock::new(),
            };
            let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
            if state.layers.len() >= MAX_LAYERS && !state.layers.contains_key(&layer) {
                return Err(FetcherError::Busy {
                    reason: format!("at most {MAX_LAYERS} layers a scope: forget one"),
                });
            }
            let scope = Arc::new(scope);
            // (told again: the calls on the staging told before end)
            if let Some(old) = state.layers.insert(layer, scope.clone()) {
                old.cancel.cancel();
            }
            drop(state);
            // (the table is parsed now, while the engine goes on, not by
            // the first `Fetch` of the layer)
            tokio::task::spawn_blocking(move || {
                let _ = crate::stager::LayerToc::kept(&scope);
            });
            Ok(Ack {})
        }

        /// Forget the layer: its calls end, later ones are `InvalidArgument`, and what
        /// the fetcher kept for its blob is let go (of a layer that was only
        /// probed too).
        pub async fn forget(&self, layer: String) -> Result<Ack, FetcherError> {
            let scope = self.scope()?;
            let kept = scope
                .kept
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(&layer)
                .is_some();
            match self
                .state
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .layers
                .remove(&layer)
            {
                Some(scope) => {
                    scope.cancel.cancel();
                    Ok(Ack {})
                }
                None if kept => Ok(Ack {}),
                None => Err(bad("a layer that was not told")),
            }
        }

        /// A small file of the origin, at most `max` bytes, in `file`, a
        /// sealed memory file in the reply.  `kind` says which: the manifest
        /// or index `reference` names (a tag or a digest), with its media
        /// type, which the engine hashes; the startup profile of the image
        /// `reference` (its id), digests of files, one a line, in the order
        /// the image read them; the signatures of the manifest or tag
        /// `reference` names (a `repository:tag`, or a manifest digest), a
        /// JSON array of records, `{"digest": "sha256:...", "signatures":
        /// ["<base64 of a signature blob>", ...]}`, which the engine judges
        /// itself.  `reference` absent: what the source of the scope names.
        /// What the fetcher has none of, and a `kind` it does not know, is
        /// `Failed` of class `unavailable`.
        #[zlink(return_fds)]
        pub async fn get_file(
            &self,
            kind: FileKind,
            reference: Option<String>,
            max: u64,
        ) -> (Result<Answer, FetcherError>, Vec<OwnedFd>) {
            let scope = match self.scope() {
                Ok(s) if max > 0 => s,
                Ok(_) => {
                    return (Err(maximum()), Vec::new());
                }
                Err(e) => return (Err(e), Vec::new()),
            };
            let api = self.api.clone();
            // (the asker went: what is being read is dropped with the call)
            let got = owned(&self.runtime, async move {
                api.get_file(&scope, kind, reference.as_deref(), max).await
            })
            .await
            .unwrap_or_else(|e| Err(stopped(e)));
            match got {
                Ok((file, media_type)) => (
                    Ok(Answer {
                        file: 0,
                        media_type,
                    }),
                    vec![file.into()],
                ),
                Err(e) => (Err(e), Vec::new()),
            }
        }

        /// A blob, its bytes written into `file`, a file with no name the
        /// engine made, open for writing, among the descriptors of the call:
        /// exactly `blob.size` bytes of the digest, which the fetcher checks as it
        /// writes and the engine checks again.  Nothing holds the blob in
        /// memory.  Called with `more`: one reply with the `bytes` written so
        /// far at least every half of `idle_ms`, then a last reply without
        /// them once the blob is complete.
        #[zlink(more, return_fds)]
        pub async fn get_blob(
            &self,
            more: bool,
            #[zlink(fds)] fds: Vec<OwnedFd>,
            blob: Blob,
            file: u32,
        ) -> impl Stream<Item = (Result<Reply<BlobReply>, FetcherError>, Vec<OwnedFd>)> + Unpin
        {
            let prepared = (|| {
                if !more {
                    return Err(FetcherError::InvalidArgument {
                        reason: "a blob is asked for with more".into(),
                    });
                }
                let scope = self.scope()?;
                let mut fds = Descriptors::new(fds);
                let file = File::from(
                    fds.take("the file of the blob", file)
                        .map_err(FetcherScope::invalid)?,
                );
                fds.finish().map_err(FetcherScope::invalid)?;
                Ok((scope, BlobFile::new(file, &blob)?))
            })();
            let (scope, out) = match prepared {
                Ok(p) => p,
                Err(e) => return Self::failure(e),
            };
            let (tx, rx) = mpsc::channel(1);
            let (api, cancel) = (self.api.clone(), Cancel::default());
            let gone = cancel.clone();
            let task = self.runtime.spawn(async move {
                let (tx, written, idle) = (Out { tx }, out.progress(), scope.idle);
                let beat = || written.load(std::sync::atomic::Ordering::Relaxed);
                tokio::select! {
                    got = beating(&tx, idle, beat, api.get_blob(&scope, &blob, out)) => got,
                    () = gone.cancelled() => Ok(()),
                }
            });
            Self::answers(
                cancel,
                rx,
                task,
                None,
                (
                    |bytes| Some(BlobReply { bytes: Some(bytes) }),
                    |reason| FetcherError::failed(reason),
                    Some(|| BlobReply { bytes: None }),
                ),
            )
        }

        /// What can this fetcher do for `layers`?  Called with `more`: one
        /// `probed` a reply, in any order, then a last reply without one.
        /// `again`: the index this fetcher carried for a layer without a
        /// table of contents in the last `Probe` of the scope was wrong (its
        /// replay failed): it carries one from another of its providers, or
        /// none.  `parts`: what of a table of contents to carry (all of it
        /// when not given).
        #[zlink(more, return_fds)]
        pub async fn probe(
            &self,
            more: bool,
            layers: Vec<Blob>,
            again: Option<bool>,
            parts: Option<Parts>,
        ) -> impl Stream<Item = (Result<Reply<ProbeReply>, FetcherError>, Vec<OwnedFd>)> + Unpin
        {
            let scope = match self.scope() {
                Ok(s) if more => s,
                Ok(_) => {
                    return Self::failure(FetcherError::InvalidArgument {
                        reason: "a probe is asked for with more".into(),
                    })
                }
                Err(e) => return Self::failure(e),
            };
            if layers.len() > MAX_LAYERS {
                return Self::failure(FetcherError::InvalidArgument {
                    reason: format!("at most {MAX_LAYERS} layers"),
                });
            }
            let (tx, rx) = mpsc::channel(4);
            let (api, cancel) = (self.api.clone(), Cancel::default());
            let gone = cancel.clone();
            let task = self.runtime.spawn(async move {
                let out = Out { tx };
                tokio::select! {
                    got = api.probe(&scope, layers, (again.unwrap_or(false), parts.unwrap_or_default()), &out) => got,
                    () = gone.cancelled() => Ok(()),
                }
            });
            Self::answers(
                cancel,
                rx,
                task,
                None,
                (
                    |probed| {
                        Some(ProbeReply {
                            probed: Some(probed),
                        })
                    },
                    |reason| FetcherError::failed(reason),
                    Some(|| ProbeReply { probed: None }),
                ),
            )
        }

        /// Read the whole blob of `layer` (one with no table of contents) and
        /// hand over its files, then give `toc.claim` and `tarsplit` names in
        /// its staging.  Called with more: the replies are the events of a
        /// `Fetch` with no objects, `progress` with the `bytes` of the blob
        /// read so far (a beat repeats them) or `staged` with `files`
        /// (complete files of the layer: the position of a descriptor of
        /// the reply each, regular files with no name, in memory when
        /// small, with fs-verity when the scope says verity), then a last
        /// reply with no event once the names are given.  A failure is the
        /// error `Failed`.
        #[zlink(more, return_fds)]
        pub async fn unpack(
            &self,
            more: bool,
            layer: String,
        ) -> impl Stream<Item = (Result<Reply<FetchReply>, FetcherError>, Vec<OwnedFd>)> + Unpin
        {
            let prepared = (|| {
                if !more {
                    return Err(FetcherError::InvalidArgument {
                        reason: "an unpack is asked for with more".into(),
                    });
                }
                Ok((self.scope()?, self.told(&layer)?))
            })();
            let (scope, layer) = match prepared {
                Ok(p) => p,
                Err(e) => return Self::failure(e),
            };
            let (tx, rx) = mpsc::channel(8);
            let cancel = Cancel::default();
            {
                let (layer, call) = (layer.cancel.clone(), cancel.clone());
                self.runtime.spawn(async move {
                    tokio::select! {
                        _ = layer.cancelled() => call.cancel(),
                        _ = call.cancelled() => {}
                    }
                });
            }
            let (api, idle) = (self.api.clone(), scope.idle);
            let call = UnpackCall {
                cancel: cancel.clone(),
            };
            let task = self.runtime.spawn(async move {
                let out = Out { tx };
                beating(
                    &out,
                    idle,
                    || FetchEvent::progress(None, 0),
                    api.unpack(&scope, &layer, call, &out),
                )
                .await
            });
            Self::answers(
                cancel,
                rx,
                task,
                None,
                (
                    |event| Some(FetchReply { event: Some(event) }),
                    |reason| FetcherError::failed(reason),
                    Some(|| FetchReply { event: None }),
                ),
            )
        }

        /// Bring files of `layer` into its staging directory, by the object
        /// contract.  Called with more.  Each object is in exactly one of `staged`,
        /// `unavailable`, `failed`; the last reply has no event.  Descriptors:
        /// the file of the chunks of the store `reuse` names, by `fd` (the
        /// engine made it of exactly those bytes; only for a fetcher that
        /// announces `reuse`).  With `handover`, a fetcher that announces the
        /// word hands over the files it keeps in memory as descriptors of
        /// its `staged` events, and names the others.
        #[zlink(more, return_fds)]
        pub async fn fetch(
            &self,
            more: bool,
            #[zlink(fds)] fds: Vec<OwnedFd>,
            layer: String,
            objects: Vec<String>,
            urgency: Urgency,
            reuse: Option<Vec<Reuse>>,
            handover: Option<bool>,
        ) -> impl Stream<Item = (Result<Reply<FetchReply>, FetcherError>, Vec<OwnedFd>)> + Unpin
        {
            let reuse = reuse.unwrap_or_default();
            let prepared = (|| {
                if !more {
                    return Err(FetcherError::InvalidArgument {
                        reason: "a fetch is asked for with more".into(),
                    });
                }
                let scope = self.scope()?;
                let layer = self.told(&layer)?;
                let most = self.api.described().max_objects as usize;
                if objects.len() > most {
                    return Err(FetcherError::InvalidArgument {
                        reason: format!("at most {most} objects"),
                    });
                }
                // (each key names a file beneath the staging: checked once
                // here, not by each fetcher)
                if let Some(bad) = objects
                    .iter()
                    .find(|k| crate::stager::staged_rel(k).is_none())
                {
                    return Err(FetcherError::InvalidArgument {
                        reason: format!("{bad:?} is not the key of a file"),
                    });
                }
                if reuse.len() > MAX_HINTS {
                    return Err(FetcherError::InvalidArgument {
                        reason: format!("at most {MAX_HINTS} reuse hints"),
                    });
                }
                if fds.len() > MAX_FDS || reuse.iter().any(|r| r.fd as usize >= fds.len()) {
                    return Err(FetcherError::InvalidArgument {
                        reason: format!(
                            "at most {MAX_FDS} files to reuse, and a hint names one of them"
                        ),
                    });
                }
                Ok((scope, layer))
            })();
            let (scope, layer) = match prepared {
                Ok(p) => p,
                Err(e) => return Self::failure(e),
            };
            let (tx, rx) = mpsc::channel(8);
            // (the call's own: cancelled when its asker goes or the layer is
            // cancelled; the end of one call cancels no other call of the
            // layer)
            let cancel = Cancel::default();
            {
                let (layer, call) = (layer.cancel.clone(), cancel.clone());
                self.runtime.spawn(async move {
                    tokio::select! {
                        _ = layer.cancelled() => call.cancel(),
                        _ = call.cancelled() => {}
                    }
                });
            }
            let (api, idle) = (self.api.clone(), scope.idle);
            let call = FetchCall {
                objects,
                urgency,
                reuse,
                handover: handover.unwrap_or(false),
                sources: fds.into_iter().map(File::from).collect(),
                cancel: cancel.clone(),
            };
            let task = self.runtime.spawn(async move {
                let out = Out { tx };
                beating(
                    &out,
                    idle,
                    || FetchEvent::progress(None, 0),
                    api.fetch(&scope, &layer, call, &out),
                )
                .await
            });
            Self::answers(
                cancel,
                rx,
                task,
                None,
                (
                    |event| Some(FetchReply { event: Some(event) }),
                    |reason| FetcherError::failed(reason),
                    Some(|| FetchReply { event: None }),
                ),
            )
        }

        /// Who serves the repository calls and what it can do.
        #[zlink(
            interface = "org.velarx.Registry",
            rename = "GetInfo",
            types = [Remote, Hit, FailureClass, Failure]
        )]
        pub async fn registry_get_info(&self) -> Result<Info, RegistryError> {
            self.registry_calls()?;
            Ok(Info {
                name: self.api.described().name,
                version: env!("CARGO_PKG_VERSION").to_string(),
                proto: crate::fetcher::proto::PROTO,
                capabilities: Vec::new(),
                limits: [("max_answer".to_string(), MAX_ANSWER)].into(),
            })
        }

        /// The tags of the repository, every page of them.  Called with
        /// `more`: one `tag` a reply, at most `max`, then a last reply
        /// without one.
        #[zlink(more, return_fds)]
        pub async fn tags(
            &self,
            more: bool,
            #[zlink(fds)] fds: Vec<OwnedFd>,
            remote: Remote,
            max: u64,
        ) -> impl Stream<Item = (Result<Reply<Tagged>, RegistryError>, Vec<OwnedFd>)> + Unpin
        {
            let prepared = (|| {
                if !more {
                    return Err(reg::bad_call("tags are asked for with more"));
                }
                let calls = self.registry_calls()?;
                let mut fds = Descriptors::new(fds);
                let call = reg::remote_call(&mut fds, remote)?;
                reg::none_left(fds)?;
                Ok((calls, call))
            })();
            let (calls, mut call) = match prepared {
                Ok(p) => p,
                Err(e) => return Self::failure(e),
            };
            let (tx, rx) = mpsc::channel(8);
            let cancel = Cancel::default();
            call.cancel = cancel.clone();
            let task = self
                .runtime
                .spawn(async move { calls.tags(call, max.min(MAX_ANSWER), &Out { tx }).await });
            Self::answers(
                cancel,
                rx,
                task,
                None,
                (
                    |tag| Some(Tagged { tag: Some(tag) }),
                    |reason| RegistryError::failed(reason),
                    Some(|| Tagged { tag: None }),
                ),
            )
        }

        /// A search of the registry of `remote` for `needle` (the v1 search
        /// where the registry has one, else its catalog; the fetcher
        /// decides).  Called with `more`: one `hit` a reply, at most
        /// `limit`, then a last reply without one.
        #[zlink(more, return_fds)]
        pub async fn search(
            &self,
            more: bool,
            #[zlink(fds)] fds: Vec<OwnedFd>,
            remote: Remote,
            needle: String,
            limit: u64,
        ) -> impl Stream<Item = (Result<Reply<Found>, RegistryError>, Vec<OwnedFd>)> + Unpin
        {
            let prepared = (|| {
                if !more {
                    return Err(reg::bad_call("a search is asked for with more"));
                }
                reg::checked_text("the search term", &needle)?;
                let calls = self.registry_calls()?;
                let mut fds = Descriptors::new(fds);
                let call = reg::remote_call(&mut fds, remote)?;
                reg::none_left(fds)?;
                Ok((calls, call))
            })();
            let (calls, mut call) = match prepared {
                Ok(p) => p,
                Err(e) => return Self::failure(e),
            };
            let (tx, rx) = mpsc::channel(8);
            let cancel = Cancel::default();
            call.cancel = cancel.clone();
            let task = self.runtime.spawn(async move {
                calls
                    .search(call, needle, limit.min(MAX_ANSWER), &Out { tx })
                    .await
            });
            Self::answers(
                cancel,
                rx,
                task,
                None,
                (
                    |hit| Some(Found { hit: Some(hit) }),
                    |reason| RegistryError::failed(reason),
                    Some(|| Found { hit: None }),
                ),
            )
        }

        /// Whether the registry takes the credentials of `remote`; `Failed`
        /// of class `unauthorized` or `forbidden` is a refusal.
        pub async fn login(
            &self,
            #[zlink(fds)] fds: Vec<OwnedFd>,
            remote: Remote,
        ) -> Result<RegistryAck, RegistryError> {
            let calls = self.registry_calls()?;
            let mut fds = Descriptors::new(fds);
            let call = reg::remote_call(&mut fds, remote)?;
            reg::none_left(fds)?;
            owned(&self.runtime, async move { calls.login(call).await })
                .await
                .map_err(reg::stopped)??;
            Ok(RegistryAck {})
        }

        /// An http or https GET of `url` (an import,
        /// an ADD of a build, a remote build context) into `file`, a file
        /// with no name the engine made, open for writing, among the
        /// descriptors of the call; at most `max` bytes.  No scope is
        /// needed.  `modified`: the Last-Modified the server said.
        pub async fn download(
            &self,
            #[zlink(fds)] fds: Vec<OwnedFd>,
            url: String,
            max: u64,
            file: u32,
        ) -> Result<Downloaded, RegistryError> {
            let calls = self.registry_calls()?;
            if max == 0 {
                return Err(reg::bad_call("a download is asked for with a maximum"));
            }
            let mut fds = Descriptors::new(fds);
            let file = File::from(
                fds.take("the file of the body", file)
                    .map_err(reg::bad_call)?,
            );
            reg::none_left(fds)?;
            let cancel = Cancel::default();
            let guard = reg::Cancelling(cancel.clone());
            let got = owned(&self.runtime, async move {
                calls.download(&url, max, file, cancel).await
            })
            .await
            .map_err(reg::stopped)?;
            drop(guard);
            got
        }

        /// Who the pusher is and what it can do.
        #[zlink(
            interface = "org.velarx.Pusher",
            rename = "GetInfo",
            types = [Role, Object, Have, FailureClass, Failure, PushEventKind, PutEvent, PushProbed, Placed]
        )]
        pub async fn push_get_info(&self) -> Result<Info, PusherError> {
            Ok(info_of(self.pusher()?.described(), PUSH_PROTO))
        }

        /// Give the connection its scope; once, before anything but
        /// `GetInfo`.  `destination`: what the destination's transport
        /// names.  `target`: the destination the client opened (a directory,
        /// or a file open for writing), for a pusher whose destination is a
        /// path; `access`: the credentials, a sealed memory file.
        /// `idle_ms`: the most this connection's calls stay silent.
        #[zlink(rename = "Open")]
        pub async fn push_open(
            &self,
            #[zlink(fds)] fds: Vec<OwnedFd>,
            destination: String,
            tls_verify: Option<bool>,
            target: Option<u32>,
            access: Option<u32>,
            idle_ms: u64,
        ) -> Result<PushAck, PusherError> {
            let pusher = self.pusher()?;
            let idle = Scoped::<PusherScope>::idle(idle_ms)?;
            push::checked_text("the destination", &destination)?;
            let mut fds = Descriptors::new(fds);
            let target = fds
                .take_opt("the target", target)
                .map_err(push::bad)?
                .map(File::from);
            let access = fds
                .take_opt("the access file", access)
                .map_err(push::bad)?
                .map(Scoped::<PusherScope>::access)
                .transpose()?;
            fds.finish().map_err(push::bad)?;
            let scope = PushScope {
                destination,
                tls_verify,
                access,
                target,
                idle,
                kept: std::sync::OnceLock::new(),
            };
            Scoped::<PusherScope>::of(self)
                .open(scope, |scope| async move { pusher.opened(&scope).await })
                .await?;
            Ok(PushAck {})
        }

        /// Another connection with the scope of this one: the reply carries
        /// its descriptor.
        #[zlink(rename = "Connect", return_fds)]
        pub async fn push_connect(&self) -> (Result<PushAck, PusherError>, Vec<OwnedFd>) {
            let (result, fds) = Scoped::<PusherScope>::of(self).connect();
            (result.map(|()| PushAck {}), fds)
        }

        /// What do you have, or what can you link, of these objects?  Called
        /// with `more`: one `probed` a reply, in any order, then a last
        /// reply without one.
        #[zlink(rename = "Probe", more, return_fds)]
        pub async fn push_probe(
            &self,
            more: bool,
            objects: Vec<Object>,
        ) -> impl Stream<Item = (Result<Reply<PushProbeReply>, PusherError>, Vec<OwnedFd>)> + Unpin
        {
            let prepared = (|| {
                if !more {
                    return Err(push::bad("a probe is asked for with more"));
                }
                let scope = self.push_scope()?;
                let api = self.pusher()?;
                push::checked_objects(&objects, api.described().max_objects as usize)?;
                Ok((scope, api))
            })();
            let (scope, api) = match prepared {
                Ok(p) => p,
                Err(e) => return Self::failure(e),
            };
            let (tx, rx) = mpsc::channel(4);
            let cancel = Cancel::default();
            let gone = cancel.clone();
            let task = self.runtime.spawn(async move {
                let out = Out::new(tx);
                tokio::select! {
                    got = api.probe(&scope, objects, &out) => got,
                    () = gone.cancelled() => Ok(()),
                }
            });
            Self::answers(
                cancel,
                rx,
                task,
                None,
                (
                    |probed| {
                        Some(PushProbeReply {
                            probed: Some(probed),
                        })
                    },
                    |reason| PusherError::failed(reason),
                    Some(|| PushProbeReply { probed: None }),
                ),
            )
        }

        /// Place the objects; `files`: for each object its data file, a
        /// regular file open for reading only, among the descriptors of the
        /// call.  Called with `more`: one `event` a reply, then a last reply
        /// without one; each object is in exactly one of placed, present,
        /// linked, unavailable, failed.
        #[zlink(rename = "Put", more, return_fds)]
        pub async fn push_put(
            &self,
            more: bool,
            #[zlink(fds)] fds: Vec<OwnedFd>,
            objects: Vec<Object>,
            files: Vec<u32>,
        ) -> impl Stream<Item = (Result<Reply<PutReply>, PusherError>, Vec<OwnedFd>)> + Unpin
        {
            let prepared = (|| {
                if !more {
                    return Err(push::bad("a put is asked for with more"));
                }
                let scope = self.push_scope()?;
                let api = self.pusher()?;
                let most = (api.described().max_objects as usize).min(MAX_OBJECTS);
                push::checked_objects(&objects, most)?;
                if files.len() != objects.len() || fds.len() > MAX_PUSH_FDS {
                    return Err(push::bad("a data file for each object, and no other"));
                }
                let mut fds = Descriptors::new(fds);
                let data = files
                    .iter()
                    .zip(&objects)
                    .map(|(at, o)| {
                        let fd = fds.take("a data file", *at).map_err(push::bad)?;
                        push::checked_data(File::from(fd), o.size)
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                fds.finish().map_err(push::bad)?;
                Ok((scope, api, data))
            })();
            let (scope, api, data) = match prepared {
                Ok(p) => p,
                Err(e) => return Self::failure(e),
            };
            let (tx, rx) = mpsc::channel(8);
            let cancel = Cancel::default();
            let call = PutCall {
                objects,
                data,
                cancel: cancel.clone(),
            };
            let idle = scope.idle;
            let task = self.runtime.spawn(async move {
                let out = Out::new(tx);
                beating(
                    &out,
                    idle,
                    || PutEvent::progress(None, 0),
                    api.put(&scope, call, &out),
                )
                .await
            });
            Self::answers(
                cancel,
                rx,
                task,
                None,
                (
                    |event| Some(PutReply { event: Some(event) }),
                    |reason| PusherError::failed(reason),
                    Some(|| PutReply { event: None }),
                ),
            )
        }

        /// Only to the pusher that owns its destination (the last of the
        /// list): put the manifest in `file` (among the descriptors of
        /// the call) as each of `names` (tags; none: by its digest only).
        /// `digest`: the digest the destination says it has; `placed`: one
        /// for each name and one for the digest.
        #[zlink(rename = "Commit")]
        pub async fn push_commit(
            &self,
            #[zlink(fds)] fds: Vec<OwnedFd>,
            manifest: Object,
            file: u32,
            names: Vec<String>,
        ) -> Result<CommitReply, PusherError> {
            let scope = self.push_scope()?;
            let api = self.pusher()?;
            push::checked_object(&manifest)?;
            for name in &names {
                push::checked_name(name)?;
            }
            let mut fds = Descriptors::new(fds);
            let fd = fds.take("the manifest", file).map_err(push::bad)?;
            fds.finish().map_err(push::bad)?;
            let data = push::checked_data(File::from(fd), manifest.size)?;
            let body = push::read_manifest(&data, manifest.size)?;
            let call = push::CommitCall {
                manifest,
                body,
                names,
            };
            owned(&self.runtime, async move { api.commit(&scope, call).await })
                .await
                .map_err(|e| PusherError::failed(format!("the pusher stopped: {e}")))?
        }

        /// To every other pusher of the push, after the commit: the
        /// destination has the manifest `digest` by `names` now.  Its answer
        /// is not waited for beyond `idle_ms`.
        #[zlink(rename = "Committed")]
        pub async fn push_committed(
            &self,
            manifest: Object,
            digest: String,
            names: Vec<String>,
        ) -> Result<PushAck, PusherError> {
            let scope = self.push_scope()?;
            let api = self.pusher()?;
            push::checked_object(&manifest)?;
            push::checked_text("the digest", &digest)?;
            for name in &names {
                push::checked_name(name)?;
            }
            let call = push::CommittedCall {
                manifest,
                digest,
                names,
            };
            owned(
                &self.runtime,
                async move { api.committed(&scope, call).await },
            )
            .await
            .map_err(|e| PusherError::failed(format!("the pusher stopped: {e}")))??;
            Ok(PushAck {})
        }

        /// The end of the scope, for every pusher: the origin finishes what
        /// it writes (the end of an archive), the others what they hold.
        #[zlink(rename = "Finish")]
        pub async fn push_finish(&self) -> Result<PushAck, PusherError> {
            let scope = self.push_scope()?;
            let api = self.pusher()?;
            owned(&self.runtime, async move { api.finish(&scope).await })
                .await
                .map_err(|e| PusherError::failed(format!("the pusher stopped: {e}")))??;
            Ok(PushAck {})
        }
    }

    impl FetchEndpoint {
        /// The pusher of the process, when it serves one.
        fn pusher(&self) -> Result<Arc<dyn Pushing>, PusherError> {
            self.api.pusher().ok_or_else(push::not_a_pusher)
        }

        fn push_scope(&self) -> Result<Arc<PushScope>, PusherError> {
            Scoped::<PusherScope>::of(self).get()
        }

        /// The repository calls of the fetcher: it has them when it serves a
        /// registry.
        fn registry_calls(&self) -> Result<Arc<dyn RegistryCalls>, RegistryError> {
            self.api.registry().ok_or_else(reg::not_a_registry)
        }
    }

    fn stopped(e: tokio::task::JoinError) -> FetcherError {
        FetcherError::failed(format!("the fetcher stopped: {e}"))
    }

    fn maximum() -> FetcherError {
        FetcherError::InvalidArgument {
            reason: "an item is asked for with a maximum".into(),
        }
    }

    /// The interface as the macro described it.
    #[cfg(test)]
    pub(super) fn description() -> String {
        format!("{}", __FetchEndpoint_INTERFACE_0)
    }

    /// The interface of the repository calls as the macro described it.
    #[cfg(test)]
    pub(super) fn registry_description() -> String {
        format!("{}", __FetchEndpoint_INTERFACE_1)
    }

    /// The interface of the pusher as the macro described it.
    #[cfg(test)]
    pub(super) fn pusher_description() -> String {
        format!("{}", __FetchEndpoint_INTERFACE_2)
    }
}

/// The interface as the macro described it.
#[cfg(test)]
pub fn description() -> String {
    service::description()
}

/// The interface of the repository calls as the macro described it.
#[cfg(test)]
pub fn registry_description() -> String {
    service::registry_description()
}

/// The interface of the pusher as the macro described it.
#[cfg(test)]
pub fn pusher_description() -> String {
    service::pusher_description()
}

/// The text of the interface definition
/// (`interfaces/org.velarx.Pusher.varlink`), made from the types and the
/// methods above, with the rules of the protocol in its header.
#[cfg(test)]
pub fn pusher_definition() -> String {
    format!(
        "# SPDX-License-Identifier: Apache-2.0\n\
         #\n\
         # The interface of pushers: a process that places the objects of an image\n\
         # (blobs, configurations, manifests) at a destination.  Every pusher serves\n\
         # it; nothing in it names a kind of pusher.  Generated from the Rust types\n\
         # (crates/content/src/pusher/push.rs and crates/content/src/serve_fetch.rs)\n\
         # by the test `interface_tests::the_pusher_interface_file_is_current`:\n\
         # VELARX_WRITE_INTERFACES=1 cargo test -p velarx-content --lib interface_tests\n\
         # writes it.  It is served on the socket of the fetcher interface of the\n\
         # same process.\n\
         #\n\
         # ONE PUSHER.  A pusher answers only for itself: what it does not place is\n\
         # unavailable, what it tried and could not place is failed.  It knows nothing\n\
         # of other pushers; the engine walks its ordered list of them, the destination's own\n\
         # pusher last, and is the one that asks the next.\n\
         # Every object of a call is answered exactly once.  Only the pusher that owns\n\
         # its destination, the last of the list, takes a Commit.\n\
         #\n\
         # THE OBJECTS.  The engine made every digest it names, and compresses and\n\
         # recreates every layer itself: a pusher places the bytes it is handed and\n\
         # never reads the store.  Each data file is a regular file open for reading\n\
         # only, which the engine keeps as it is until the call ends, in the\n\
         # descriptors of the message in the order of the objects.\n\
         #\n\
         # TRUST.  An answer is a claim.  What a pusher that does not own the\n\
         # destination says it placed is confirmed by the one that does before the\n\
         # manifest is committed.\n\
         #\n\
         # CAPABILITIES.  A pusher announces no word: a word exists only where the\n\
         # engine must do work, or choose what to send, before the call; a client\n\
         # ignores the words it does not know.  The interface grows only so: a new\n\
         # parameter or reply field is optional, a new method is answered\n\
         # MethodNotFound by a pusher that does not have it (read as `unavailable`),\n\
         # and a value of an enum that the receiver does not know is read as the most\n\
         # general one (other, unknown) or ignored.\n\
         #\n\
         # DESCRIPTORS.  A descriptor is a field of type `int` (or `?int` when it may\n\
         # be absent), named after what it is, whose value is its position among the\n\
         # descriptors of its message; at most {MAX_PUSH_FDS} for a message.  Nothing is\n\
         # counted and nothing is implied by order.  The credentials are the JSON of a\n\
         # `RegistryAccess` in a sealed memory file (at most {MAX_PUSH_ACCESS} bytes),\n\
         # which carries no length: the receiver checks the seals.\n\
         #\n\
         # REPLIES.  A method called with more answers one record a reply; its last\n\
         # reply carries no record and has continues false (`Put`: no event; `Probe`:\n\
         # no probed).  A server whose connection is closed sends nothing more.\n\
         # `progress` carries `objects` (exactly one) and `bytes`, the cumulative\n\
         # bytes of that object sent by this call; one with no object and no bytes is\n\
         # a beat.  Every other method has one reply.\n\
         #\n\
         # CANCELLATION.  Closing the connection of a call cancels it; each `Probe` and\n\
         # `Put` runs on a connection of its own (`Connect`).  An interrupted upload may\n\
         # be resumed by a later `Put` of the same object or started again; a pusher\n\
         # says nothing about it.\n\
         #\n\
         # LIVENESS.  `Open` carries `idle_ms`.  A call with more sends a reply (a\n\
         # progress when it has nothing else) at least every `idle_ms / 2`; a call with\n\
         # one reply answers within `idle_ms`.  Otherwise the engine closes the\n\
         # connection and records a transient failure, `silent for N ms`, for that\n\
         # party.\n\
         # Who may call: a peer of the same user or root (SO_PEERCRED); any\n\
         # accepted peer may make every call.\n\
         \n{}\n",
        service::pusher_description()
    )
}

/// The text of the interface definition
/// (`interfaces/org.velarx.Registry.varlink`).
#[cfg(test)]
pub fn registry_definition() -> String {
    format!(
        "# SPDX-License-Identifier: Apache-2.0\n\
         #\n\
         # The interface org.velarx.Registry: the calls about a repository of a\n\
         # registry (its tags, a search, a login) and the download of a URL, served by the registry fetcher\n\
         # (velarx-registry) on its socket beside the fetcher and pusher interfaces,\n\
         # and by no other fetcher.  Generated from the Rust types\n\
         # (crates/content/src/fetcher/proto.rs and crates/content/src/serve_fetch.rs) by\n\
         # the test `interface_tests::the_registry_interface_file_is_current`:\n\
         # VELARX_WRITE_INTERFACES=1 cargo test -p velarx-content --lib interface_tests writes it.\n\
         #\n\
         # A call names its repository and carries its own credentials: the JSON of a\n\
         # `RegistryAccess` in a sealed memory file, a descriptor `Remote.access` names\n\
         # (at most {MAX_ACCESS} bytes).  `Tags` and `Search` answer one item a reply\n\
         # (at most `max_answer` of GetInfo); their last reply has no item.  A descriptor\n\
         # is a field of type `int` whose value is its position among the descriptors\n\
         # of its message.  The Authorization of a registry goes to that registry's host\n\
         # only.  Closing the connection cancels the call.\n\
         # Who may call: a peer of the same user or root (SO_PEERCRED); any\n\
         # accepted peer may make every call.\n\
         \n{}\n",
        service::registry_description()
    )
}

/// The text of the interface definition
/// (`interfaces/org.velarx.Fetcher.varlink`), made from the types and the
/// methods above, with the rules of the protocol in its header.
#[cfg(test)]
pub fn definition() -> String {
    format!(
        "# SPDX-License-Identifier: Apache-2.0\n\
         #\n\
         # The interface of fetchers: a process that brings the\n\
         # content of images into the staging directories of a store.  Every fetcher\n\
         # serves it; nothing in it names a kind of fetcher.  Generated from the Rust\n\
         # types (crates/content/src/fetcher/fetch.rs and crates/content/src/serve_fetch.rs)\n\
         # by the test `serve_fetch::tests::the_interface_file_is_current`:\n\
         # VELARX_WRITE_INTERFACES=1 cargo test -p velarx-content --lib serve_fetch writes it.\n\
         #\n\
         # ONE FETCHER.  A fetcher answers only for itself: what it does not have is\n\
         # unavailable, what it tried and could not bring is failed, with a class that says what to do next.  It knows nothing\n\
         # of other fetchers; the engine walks its ordered list of them, and is the\n\
         # one that asks the next.  Every item of a call is answered exactly once.\n\
         #\n\
         # THE STAGING DIRECTORY OF A LAYER.  A directory open for reading (not O_PATH) on\n\
         # the file system of the store, made by the engine, one per layer.  A fetcher\n\
         # resolves every path beneath it with openat2(RESOLVE_BENEATH |\n\
         # RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_XDEV) and uses\n\
         # incoming/ (files with no name), files/ab/cd... (the files of the layer, named\n\
         # after fs-verity was enabled, by the digest the table of contents gives), and\n\
         # toc.claim and tarsplit (only for a layer without a table of contents).\n\
         # A built-in fetcher may also be confined, at its start, to the staging\n\
         # root of its store; that is its sandbox, not part of this interface: an\n\
         # external fetcher reaches a layer's staging only through the descriptor\n\
         # of `Layer`.\n\
         #\n\
         # THE OBJECT CONTRACT.  A file is written into a file with no name, each chunk\n\
         # checked against the sha256 the table of contents gives for it; the file is\n\
         # closed for writing; fs-verity is enabled on it (when the scope says verity);\n\
         # its mode is 0444; then it is given its name with linkat, never replacing.  A\n\
         # name that exists is success.  A fetcher syncs nothing, removes no name,\n\
         # writes nowhere else, and never reads the store: the chunks of the store it\n\
         # may take (`reuse` of Fetch, only for a fetcher that announces the word\n\
         # reuse) come in one file the engine made of exactly those bytes, read-only.\n\
         #\n\
         # UNPACK.  The origin reads a layer with no table of contents whole, and its\n\
         # regular files are handed over, not named: each is a descriptor of a reply of\n\
         # `Unpack`, a complete file with no name (a small one may be a file in memory)\n\
         # that has fs-verity when the scope says verity.  Then it gives `toc.claim` and\n\
         # `tarsplit` their names in the staging directory.  A file of two names is handed\n\
         # over once.\n\
         #\n\
         # HANDOVER.  A fetcher that announces the word handover and is called with\n\
         # `handover` may answer for a small file, written in memory, with a `staged`\n\
         # event that has `files`: for each of its `objects` the descriptor of the file, a\n\
         # complete file with no name, instead of a name in the staging directory.  A file\n\
         # that is not small, or that needs fs-verity, is named as before.\n\
         #\n\
         # TABLES.  A zstd:chunked layer whose descriptor has the annotations\n\
         # `table-position` and `table-checksum` is pulled by its binary table, not by\n\
         # its JSON table of contents: only a fetcher that announces the word table is\n\
         # asked for it, and the table is what `Probe` carries and `Layer` gives.\n\
         #\n\
         # TRUST.  A fetcher is not trusted.  A name it made is a claim; the engine opens\n\
         # it and takes the kernel's measure.  A file it hands over is a claim too: the\n\
         # engine copies it, or takes the kernel's measure of it, and knows it by the\n\
         # digest of the bytes it read.  What it returns with GetFile (a manifest),\n\
         # GetBlob and Probe is hashed by the engine before it is used,\n\
         # and the signatures of GetFile are judged by the engine's policy.\n\
         #\n\
         # CAPABILITIES.  What a fetcher can do is a word of capabilities in GetInfo; a\n\
         # client ignores the words it does not know.  The\n\
         # interface grows only so: a new parameter or reply field is optional, a new\n\
         # value of an enum of a call is sent only to a fetcher that announces its word,\n\
         # and a value of an enum of a reply that a client does not know is read as\n\
         # the most general one (other, none, unsupported) or ignored (an event).\n\
         #\n\
         # DESCRIPTORS.  A descriptor is a field of type `int` (or `?int` when it may\n\
         # be absent), named after what it is, whose value is its position among the\n\
         # descriptors of its message; at most {MAX_FDS} for a message.  Nothing is\n\
         # counted and nothing is implied by order.  A sealed memory file carries no\n\
         # length: the receiver checks the seals and applies the interface's maximum.\n\
         #\n\
         # REPLIES.  A method called with more answers one record a reply; its last\n\
         # reply carries no record and has continues false (`Fetch`: no event;\n\
         # `Probe`: no probed; `Unpack`: neither bytes nor files).  A server whose connection is closed sends nothing\n\
         # more.  `progress` carries `objects` (exactly one) and `bytes`, the cumulative\n\
         # bytes of that object moved by this call; with no object, the cumulative\n\
         # bytes of the blob of the layer; one with no object and no bytes is a beat.\n\
         # Every other method has one reply.\n\
         #\n\
         # LIVENESS.  `Open` carries `idle_ms`.  A call with more sends a reply (a\n\
         # progress when it has nothing else) at least every `idle_ms / 2`; a call with\n\
         # one reply answers within `idle_ms`.  Otherwise the engine closes the\n\
         # connection and records a transient failure, `silent for N ms`, for that\n\
         # party.\n\
         # Who may call: a peer of the same user or root (SO_PEERCRED); any\n\
         # accepted peer may make every call.\n\
         \n{}\n",
        service::description()
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::StreamExt;

    /// A fetcher with none of the behaviours: it has nothing.
    struct Last;

    #[async_trait]
    impl StagingFetcher for Last {
        fn described(&self) -> Described {
            Described {
                name: "last".into(),
                capabilities: Vec::new(),
                max_objects: 4,
            }
        }
    }

    fn endpoint() -> FetchEndpoint {
        FetchEndpoint::new(Arc::new(Last))
    }

    fn dir() -> OwnedFd {
        File::open(std::env::temp_dir()).unwrap().into()
    }

    async fn open(e: &FetchEndpoint) -> Result<Ack, FetcherError> {
        e.open(Vec::new(), true, None, None, None, None, 1000).await
    }

    /// The drop of a fetcher served by a thread of this process returns
    /// once the thread ended: nothing of it is left (it held the fetcher).
    #[test]
    fn a_fetcher_served_in_this_process_is_over_once_dropped() {
        // (the calls run on the runtime of the caller)
        let rt = tokio::runtime::Runtime::new().unwrap();
        let _in = rt.enter();
        let api = Arc::new(Last);
        let local = LocalFetcher::start(api.clone(), activation::Limits::default()).unwrap();
        let _conn = local.connect().unwrap();
        drop(local);
        assert_eq!(
            Arc::strong_count(&api),
            1,
            "the local fetcher's thread runs on"
        );
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("f.sock");
        let listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
        let served = serve_in_thread(listener, api.clone(), activation::Limits::default()).unwrap();
        let _conn = std::os::unix::net::UnixStream::connect(&socket).unwrap();
        drop(served);
        assert_eq!(Arc::strong_count(&api), 1, "the server thread runs on");
    }

    #[test]
    fn the_interface_file_is_current() {
        let text = definition();
        velarx_base::testing::assert_interface_file("interfaces/org.velarx.Fetcher.varlink", &text);
        for method in [
            "GetInfo", "Open", "Connect", "Layer", "Forget", "GetFile", "GetBlob", "Probe",
            "Unpack", "Fetch",
        ] {
            assert!(text.contains(&format!("method {method}(")), "{method}");
        }
        assert!(!text.contains("[`"), "a rustdoc link in the definition");
    }

    /// A fetcher that has one blob.
    struct Has(Vec<u8>);

    #[async_trait]
    impl StagingFetcher for Has {
        fn described(&self) -> Described {
            Described {
                name: "has".into(),
                capabilities: Vec::new(),
                max_objects: 4,
            }
        }

        async fn get_blob(
            &self,
            _: &Scope,
            _: &Blob,
            mut out: BlobFile,
        ) -> Result<(), FetcherError> {
            // (in pieces: no more than a piece is ever held)
            for piece in self.0.chunks(3) {
                out.write(piece)?;
            }
            out.finish()
        }
    }

    fn described_blob(bytes: &[u8]) -> Blob {
        Blob {
            digest: velarx_types::digest::Digest::of(
                velarx_types::digest::Algorithm::Sha256,
                bytes,
            )
            .to_string(),
            size: bytes.len() as u64,
            media_type: "application/octet-stream".into(),
            annotations: None,
        }
    }

    /// The first answer of a `GetBlob` that is an error.
    async fn refused_blob(e: &FetchEndpoint, fds: Vec<OwnedFd>, more: bool) -> FetcherError {
        let mut replies = e
            .get_blob(more, fds, described_blob(b"0123456789"), 0)
            .await;
        replies.next().await.unwrap().0.err().unwrap()
    }

    /// `GetBlob` writes the blob into the file the call carries, says how
    /// many bytes it wrote so far, and ends with a reply that has none.
    #[tokio::test]
    async fn a_blob_is_written_into_the_file_of_the_call() {
        use std::os::unix::fs::FileExt;
        let e = FetchEndpoint::new(Arc::new(Has(b"0123456789".to_vec())));
        open(&e).await.unwrap();
        let file = tempfile::tempfile().unwrap();
        let sent = vec![OwnedFd::from(file.try_clone().unwrap())];
        let replies: Vec<BlobReply> = e
            .get_blob(true, sent, described_blob(b"0123456789"), 0)
            .await
            .map(|(r, _)| r.unwrap().into_parameters().unwrap())
            .collect()
            .await;
        assert_eq!(replies.last().unwrap().bytes, None);
        assert!(replies[..replies.len() - 1]
            .iter()
            .all(|r| r.bytes.is_some()));
        let mut got = vec![0u8; 10];
        file.read_exact_at(&mut got, 0).unwrap();
        assert_eq!(got, b"0123456789");
        // (a file the call does not carry, a descriptor nobody names, and
        // a call without more)
        let invalid = |e: FetcherError| matches!(e, FetcherError::InvalidArgument { .. });
        assert!(invalid(refused_blob(&e, Vec::new(), true).await));
        assert!(invalid(refused_blob(&e, vec![dir(), dir()], true).await));
        assert!(invalid(refused_blob(&e, vec![dir()], false).await));
    }

    /// What does not have the size or the digest of its descriptor is
    /// `invalid`, as the bytes go, not at the end of a copy.
    #[test]
    fn a_blob_file_checks_size_and_digest_as_it_is_written() {
        let blob = described_blob(b"abcdef");
        let invalid = |e: FetcherError| e.failure().unwrap().class == FailureClass::Invalid;
        let file = || tempfile::tempfile().unwrap();
        let put = |bytes: &[u8]| {
            let mut out = BlobFile::new(file(), &blob)?;
            out.write(bytes)?;
            out.finish()
        };
        put(b"abcdef").unwrap();
        assert!(invalid(put(b"abcdefg").unwrap_err()));
        assert!(invalid(put(b"abcde").unwrap_err()));
        assert!(invalid(put(b"abcdeX").unwrap_err()));
        // (the first byte past the size is refused, without waiting for the end)
        let mut out = BlobFile::new(file(), &blob).unwrap();
        out.write(b"abcdef").unwrap();
        assert!(invalid(out.write(b"g").unwrap_err()));
    }

    /// The zeros of a blob are holes of its file.
    #[test]
    fn the_zeros_of_a_blob_are_holes() {
        use std::os::unix::fs::MetadataExt;
        let mut data = vec![7u8; 100];
        data.extend(vec![0u8; 4 << 20]);
        data.extend(b"end");
        let blob = described_blob(&data);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("blob");
        let file = std::fs::File::create(&path).unwrap();
        let mut out = BlobFile::new(file.try_clone().unwrap(), &blob).unwrap();
        for piece in data.chunks(1000) {
            out.write(piece).unwrap();
        }
        out.finish().unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), data);
        // (two blocks of data at most, where the file system has holes)
        let blocks = file.metadata().unwrap().blocks();
        assert!(blocks <= 64, "{blocks} blocks of 512 bytes");
    }

    #[tokio::test]
    async fn a_connection_has_a_scope_once_and_only_then() {
        let e = endpoint();
        let early = e
            .layer(
                vec![dir()],
                "sha256:aa".into(),
                0,
                described_blob(b"a"),
                None,
            )
            .await;
        assert!(matches!(early, Err(FetcherError::InvalidArgument { .. })));
        open(&e).await.unwrap();
        assert!(matches!(
            open(&e).await,
            Err(FetcherError::InvalidArgument { .. })
        ));
    }

    #[tokio::test]
    async fn a_layer_needs_a_directory_that_is_readable_and_is_forgotten_by_forget() {
        let e = endpoint();
        open(&e).await.unwrap();
        let o_path: OwnedFd = rustix::fs::open(
            std::env::temp_dir(),
            rustix::fs::OFlags::PATH | rustix::fs::OFlags::DIRECTORY,
            rustix::fs::Mode::empty(),
        )
        .unwrap();
        let r = e
            .layer(
                vec![o_path],
                "sha256:aa".into(),
                0,
                described_blob(b"a"),
                None,
            )
            .await;
        assert!(
            matches!(r, Err(FetcherError::InvalidArgument { .. })),
            "{r:?}"
        );
        let file: OwnedFd = tempfile::tempfile().unwrap().into();
        let r = e
            .layer(
                vec![file],
                "sha256:aa".into(),
                0,
                described_blob(b"a"),
                None,
            )
            .await;
        assert!(
            matches!(r, Err(FetcherError::InvalidArgument { .. })),
            "{r:?}"
        );
        e.layer(
            vec![dir()],
            "sha256:aa".into(),
            0,
            described_blob(b"a"),
            None,
        )
        .await
        .unwrap();
        // what the fetcher kept for the blob goes with the layer
        let kept = Arc::new(());
        let scope = e.scope().unwrap();
        scope
            .kept
            .lock()
            .unwrap()
            .insert("sha256:aa".into(), kept.clone());
        e.forget("sha256:aa".into()).await.unwrap();
        assert_eq!(Arc::strong_count(&kept), 1);
        assert!(matches!(
            e.forget("sha256:aa".into()).await,
            Err(FetcherError::InvalidArgument { .. })
        ));
        // and with a layer that was only probed, never told
        scope
            .kept
            .lock()
            .unwrap()
            .insert("sha256:bb".into(), kept.clone());
        e.forget("sha256:bb".into()).await.unwrap();
        assert_eq!(Arc::strong_count(&kept), 1);
    }

    /// A descriptor is named by the position of a field; one that no field
    /// names, one that two fields name, or one the message does not have is
    /// refused.
    #[tokio::test]
    async fn a_descriptor_is_named_by_position_and_nothing_else_is_taken() {
        let e = endpoint();
        let open = |fds, target, access| e.open(fds, true, None, None, target, access, 1000);
        let nobody = open(vec![dir()], None, None).await;
        assert!(
            matches!(nobody, Err(FetcherError::InvalidArgument { .. })),
            "{nobody:?}"
        );
        let beyond = open(vec![dir()], Some(1), None).await;
        assert!(
            matches!(beyond, Err(FetcherError::InvalidArgument { .. })),
            "{beyond:?}"
        );
        let twice = open(vec![dir()], Some(0), Some(0)).await;
        assert!(
            matches!(twice, Err(FetcherError::InvalidArgument { .. })),
            "{twice:?}"
        );
        // (none of them gave the scope)
        assert!(open(Vec::new(), None, None).await.is_ok());
    }

    #[tokio::test]
    async fn the_last_fetcher_has_nothing_and_says_so_once_for_every_item() {
        let e = endpoint();
        open(&e).await.unwrap();
        // a fetch of a layer that was not told
        let mut s = e
            .fetch(
                true,
                vec![],
                "sha256:aa".into(),
                vec![],
                Urgency::Wait,
                None,
                None,
            )
            .await;
        let (first, _) = s.next().await.unwrap();
        assert!(matches!(first, Err(FetcherError::InvalidArgument { .. })));
        e.layer(
            vec![dir()],
            "sha256:aa".into(),
            0,
            described_blob(b"a"),
            None,
        )
        .await
        .unwrap();
        let objects: Vec<String> = (0..3).map(|i| format!("sha256:{i:064}")).collect();
        let s = e
            .fetch(
                true,
                vec![],
                "sha256:aa".into(),
                objects,
                Urgency::OnDemand,
                None,
                None,
            )
            .await;
        let replies: Vec<_> = s.collect().await;
        let kinds: Vec<(Option<EventKind>, Vec<u32>, bool)> = replies
            .into_iter()
            .map(|(r, _)| {
                let r = r.unwrap();
                let more = r.continues() == Some(true);
                match r.into_parameters() {
                    Some(FetchReply { event: Some(e) }) => (Some(e.kind), e.objects, more),
                    _ => (None, vec![], more),
                }
            })
            .collect();
        assert_eq!(
            kinds,
            vec![
                (Some(EventKind::Unavailable), vec![0, 1, 2], true),
                (None, vec![], false)
            ]
        );
        // too many objects
        let many: Vec<String> = (0..5).map(|i| format!("sha256:{i:064}")).collect();
        let mut s = e
            .fetch(
                true,
                vec![],
                "sha256:aa".into(),
                many,
                Urgency::Wait,
                None,
                None,
            )
            .await;
        assert!(matches!(
            s.next().await.unwrap().0,
            Err(FetcherError::InvalidArgument { .. })
        ));
        // a probe: every layer once, unreachable
        let blob = |digest: &str| Blob {
            digest: digest.into(),
            size: 1,
            media_type: "application/octet-stream".into(),
            annotations: None,
        };
        let s = e
            .probe(true, vec![blob("sha256:aa"), blob("sha256:bb")], None, None)
            .await;
        let got: Vec<ProbeReply> = s
            .filter_map(|(r, _)| async move { r.ok().and_then(|r| r.into_parameters()) })
            .collect()
            .await;
        // (the last reply has none)
        assert_eq!(got.len(), 3);
        assert!(got[2].probed.is_none());
        assert!(got[..2].iter().all(|p| {
            let p = p.probed.as_ref().unwrap();
            p.toc == TocSource::None && p.reason == Some(NotLazy::Unreachable)
        }));
        // an item: nobody has it
        for kind in [FileKind::Manifest, FileKind::Profile, FileKind::Signatures] {
            let got = e.get_file(kind, Some("latest".into()), 100).await;
            assert!(matches!(got.0, Err(FetcherError::Failed { .. })));
        }
        let mut replies = e.get_blob(true, vec![dir()], described_blob(b"x"), 0).await;
        let got = replies.next().await.unwrap().0;
        assert!(matches!(got, Err(FetcherError::Failed { .. })));
        // (an item is asked for with a maximum)
        let got = e
            .get_file(FileKind::Manifest, Some("latest".into()), 0)
            .await;
        assert!(matches!(got.0, Err(FetcherError::InvalidArgument { .. })));
    }

    /// What a client of a later version sends: a method, a parameter, a kind
    /// of file and an urgency this fetcher does not have.
    #[zlink::proxy("org.velarx.Fetcher")]
    trait Later {
        async fn teleport(&mut self) -> zlink::Result<Result<Ack, FetcherError>>;

        async fn forget(
            &mut self,
            layer: &str,
            teleport: Option<bool>,
        ) -> zlink::Result<Result<Ack, FetcherError>>;

        #[zlink(return_fds)]
        async fn get_file(
            &mut self,
            kind: &str,
            reference: Option<&str>,
            max: u64,
        ) -> zlink::Result<(Result<Answer, FetcherError>, Vec<OwnedFd>)>;
    }

    /// The first rule of the interface: what a fetcher does not know is
    /// answered, and read, as `unavailable`.  The service of zlink answers
    /// `MethodNotFound` for a method it does not have, ignores a parameter
    /// it does not have, and the kind of a file and the urgency it does not
    /// know are read as `unknown` and `wait`.
    #[tokio::test]
    async fn what_a_fetcher_does_not_know_is_unavailable() {
        use crate::fetcher::fetch_client::{CallError, FetchConn};
        use std::sync::atomic::Ordering;
        let local = LocalFetcher::start(Arc::new(Last), activation::Limits::default()).unwrap();
        let mut conn = FetchConn::new(local.connect().unwrap()).unwrap();
        conn.open(crate::fetcher::fetch_client::Scoping::bare(
            std::time::Duration::from_secs(60),
        ))
        .await
        .unwrap();
        // a method it does not have
        let (call, busy) = conn.begin().await.unwrap();
        let got = Later::teleport(call).await;
        busy.store(false, Ordering::Release);
        let got = got.expect_err("an unknown method is an error of the service");
        assert!(matches!(
            crate::fetcher::fetch_client::zerr(got),
            CallError::NoMethod
        ));
        // a parameter it does not have is ignored (the call goes on)
        let (call, busy) = conn.begin().await.unwrap();
        let got = Later::forget(call, "sha256:aa", Some(true)).await;
        busy.store(false, Ordering::Release);
        assert!(matches!(
            got.unwrap(),
            Err(FetcherError::InvalidArgument { .. })
        ));
        // a kind of file it does not have is nobody's
        let (call, busy) = conn.begin().await.unwrap();
        let got = Later::get_file(call, "referrers", Some("sha256:aa"), 100).await;
        busy.store(false, Ordering::Release);
        let (got, _) = got.unwrap();
        assert!(matches!(
            got,
            Err(FetcherError::Failed { failure }) if failure.class == FailureClass::Unavailable
        ));
        // (and an urgency it does not have is the one of a command that
        // waits; those it has are themselves)
        let urgency = |word: &str| serde_json::from_str::<Urgency>(&format!("\"{word}\"")).unwrap();
        assert_eq!(urgency("later"), Urgency::Wait);
        for u in [
            Urgency::Background,
            Urgency::Ahead,
            Urgency::Wait,
            Urgency::OnDemand,
        ] {
            assert_eq!(
                urgency(serde_json::to_value(u).unwrap().as_str().unwrap()),
                u
            );
        }
    }
}
