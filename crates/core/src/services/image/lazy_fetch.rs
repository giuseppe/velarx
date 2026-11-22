// SPDX-License-Identifier: Apache-2.0
//! The funnel of the files of lazily pulled layers in this engine process:
//! the misses of the image servers (`crate::image_fetch`), the copies of a
//! lazy image and the completion of its pull all go through it.
//!
//! * A file is fetched once by the process: a second request for a file of
//!   a layer that is in flight joins its fetch (the table of the fetches in
//!   flight, by layer and file, is this process's only).
//! * Across processes the layer is the unit: the files are staged in the
//!   ONE staging directory of the layer (`staging/layers/<stem>`), under its
//!   lease (`staging/meta/<stem>/lease`), which this process takes once for
//!   all its fetches of the layer.  Another engine that fetches the layer
//!   holds it meanwhile: the kernel gives the lease when that one lets go
//!   (no polling), and what it staged is not asked for again.
//! * The fetches a start makes (`Wait`, `OnDemand`) go first: the completion
//!   of the pull of the layers does not send a fetch while one is in
//!   flight, nor for [`QUIET`] after the last (`yield_to_starts`).
//! * The fetch itself is the engine's ordered list of fetchers, walked by
//!   `StagedFetch` (`Fetch(layer, [digest], urgency)`): the engine routes the
//!   request; it fetches nothing itself.  The list of a repository is opened
//!   once and kept; one whose call failed is opened again by the next fetch.

use super::*;
use futures::future::{BoxFuture, FutureExt, RemoteHandle, Shared};
use std::collections::HashMap;
use std::sync::{Mutex as StdMutex, Weak};
use velarx_content::fetcher::fetch::Urgency;
use velarx_content::pull::staged_fetch::StagedFetch;
use velarx_content::pull::start_set;
use velarx_registry::auth::RegistryAccess;

/// How long after its last fetch a start is left alone by the completion:
/// a start reads in bursts (the engine, the runtime, the program's loader)
/// with short gaps between them, which this bridges.
const QUIET: std::time::Duration = std::time::Duration::from_secs(2);

type Outcome = Result<Walked, Arc<ImageError>>;
use velarx_content::pull::staged_fetch::Walked;
/// What a list of fetchers was opened for: the repository, its TLS
/// verification, whether its pull had credentials, and certificates.
type WalkKey = (String, bool, bool, bool);

/// The walker of the layers of `repository` reached as `reach` says.
fn walk_key(repository: String, reach: &velarx_db::LayerReach) -> WalkKey {
    (repository, reach.tls_verify, reach.creds, reach.certs)
}

/// A list of fetchers a pull opened, and the number of the credentials it
/// was opened with.
type OpenedWalker = Option<(u64, Arc<StagedFetch>)>;
/// The lease of a layer this process holds while it fetches into it.
type LeaseSlot = Arc<tokio::sync::Mutex<Weak<velarx_content::pull::staged::Lease>>>;
/// A file in a fetch in flight, which the requests of the file join.
struct InFlight {
    /// The number of the fetch (which entries of the table are still its
    /// own)
    id: u64,
    urgency: Urgency,
    /// True once the file is staged or the fetch ended
    staged: tokio::sync::watch::Receiver<bool>,
    fetch: Shared<BoxFuture<'static, Outcome>>,
}

/// A layer of a pull the start set is fetched from: its key, its descriptor
/// as it was staged, its table, and the table as the layer has it.
pub(super) type StartLayer = (LayerKey, OciDescriptor, Arc<Toc>, bytes::Bytes);

/// The files of the start set of an image (`start_set`), in each of its
/// layers (the lowest first): the engine's files, the program and the files
/// of the profile.
pub(super) fn plan_start_set(
    layers: &[StartLayer],
    config: &velarx_types::OciImageConfig,
    profile: &[String],
) -> Vec<Vec<String>> {
    let tocs: Vec<&Toc> = layers.iter().map(|(_, _, toc, _)| &**toc).collect();
    let mut sets = vec![Vec::new(); layers.len()];
    for (at, digest) in start_set::Layers::new(&tocs).start_set(config, profile) {
        sets[at].push(digest);
    }
    sets
}

/// What a pull tells the funnel of the layers it staged.
#[derive(Clone)]
pub(super) struct PulledFrom {
    pub repository: String,
    pub reach: velarx_db::LayerReach,
    /// The bytes of the manifest
    pub manifest: Vec<u8>,
}

impl PulledFrom {
    fn walk(&self) -> WalkKey {
        walk_key(self.repository.clone(), &self.reach)
    }
}

/// The fetches of a start in a layer: how many are in flight, and when the
/// last one ended.
struct Starting {
    inflight: usize,
    last: tokio::time::Instant,
}

/// A fetch of a start in flight (`Wait` or `OnDemand`): the completion of
/// its layer yields while it is.
struct StartGuard {
    funnel: Arc<LazyFunnel>,
    key: LayerKey,
}

impl StartGuard {
    fn new(funnel: &Arc<LazyFunnel>, key: &LayerKey) -> Self {
        funnel
            .starting
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .entry(*key)
            .or_insert(Starting {
                inflight: 0,
                last: tokio::time::Instant::now(),
            })
            .inflight += 1;
        Self {
            funnel: funnel.clone(),
            key: *key,
        }
    }
}

impl Drop for StartGuard {
    fn drop(&mut self) {
        if let Some(s) = self
            .funnel
            .starting
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get_mut(&self.key)
        {
            s.inflight -= 1;
            s.last = tokio::time::Instant::now();
        }
        self.funnel.started.notify_waiters();
    }
}

/// A start set being fetched into a layer: the window of the layer waits
/// until it is there.
struct SetGuard {
    funnel: Arc<LazyFunnel>,
    key: LayerKey,
}

impl SetGuard {
    fn new(funnel: &Arc<LazyFunnel>, key: &LayerKey) -> Self {
        *funnel
            .setting
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .entry(*key)
            .or_default() += 1;
        Self {
            funnel: funnel.clone(),
            key: *key,
        }
    }
}

impl Drop for SetGuard {
    fn drop(&mut self) {
        let mut setting = self
            .funnel
            .setting
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if let Some(n) = setting.get_mut(&self.key) {
            *n -= 1;
            if *n == 0 {
                setting.remove(&self.key);
            }
        }
    }
}

/// What a fetch of a file of a staged layer needs: its descriptor, its
/// table, and the repository and the list of fetchers it comes through.
struct LayerCtx {
    desc: OciDescriptor,
    toc: Arc<Toc>,
    /// The table as the layer has it (compressed), which the fetchers are
    /// told
    toc_z: bytes::Bytes,
    /// The position of each regular file in `toc`, by its fs-verity digest
    /// (made when a miss asks for it)
    files: std::sync::OnceLock<HashMap<String, usize>>,
    /// The startup profile of the image, when its pull got one (the files
    /// of the image in the order a start read them)
    profile: std::sync::OnceLock<Arc<[String]>>,
    /// The repository, its TLS verification, whether its pull had credentials
    walk: WalkKey,
    manifest: Vec<u8>,
}

impl LayerCtx {
    fn files(&self) -> &HashMap<String, usize> {
        self.files
            .get_or_init(|| velarx_content::pull::window::file_positions(&self.toc))
    }
}

/// The fetches of lazy files of this process.
#[derive(Default)]
pub(crate) struct LazyFunnel {
    /// The lists of fetchers, by what they were opened for, with the
    /// number of the credentials they were opened with
    walkers: tokio::sync::Mutex<HashMap<WalkKey, (u64, Arc<StagedFetch>)>>,
    /// The number of the credentials in [`LazyFunnel::access`]: a list
    /// opened with other ones is opened again
    access_epoch: std::sync::atomic::AtomicU64,
    /// The leases of the layers this process fetches into, shared by its
    /// fetches of the layer while one runs
    leases: StdMutex<HashMap<LayerKey, LeaseSlot>>,
    /// The fetches in flight, by layer and file
    inflight: StdMutex<HashMap<(LayerKey, String), InFlight>>,
    /// The number of the next fetch in flight
    fetches: std::sync::atomic::AtomicU64,
    /// The windows fetched after the misses of each layer
    windows: StdMutex<HashMap<LayerKey, u32>>,
    /// The start sets being fetched, by layer: how many
    setting: StdMutex<HashMap<LayerKey, usize>>,
    /// The fetches of the starts, by layer
    starting: StdMutex<HashMap<LayerKey, Starting>>,
    /// Told when a fetch of a start ends
    started: tokio::sync::Notify,
    /// What a fetch of each staged layer needs, read once
    layers: StdMutex<HashMap<LayerKey, Arc<LayerCtx>>>,
    /// The credentials and certificates of a command that completes a pull:
    /// in memory only
    access: StdMutex<RegistryAccess>,
}

/// `work` on the blocking pool.
async fn blocking<R: Send + 'static>(
    work: impl FnOnce() -> ImageResult<R> + Send + 'static,
) -> ImageResult<R> {
    tokio::task::spawn_blocking(work)
        .await
        .map_err(|e| ImageError::Storage(e.to_string()))?
}

/// An error of a fetch that was joined: the kind the completion acts on
/// is kept.
fn unshared(e: Arc<ImageError>) -> ImageError {
    match Arc::try_unwrap(e) {
        Ok(e) => e,
        Err(e) => match &*e {
            ImageError::Unauthorized(m) => ImageError::Unauthorized(m.clone()),
            ImageError::Forbidden(m) => ImageError::Forbidden(m.clone()),
            ImageError::RegistryNotFound(m) => ImageError::RegistryNotFound(m.clone()),
            ImageError::Contradicted(m) => ImageError::Contradicted(m.clone()),
            ImageError::Transfer {
                party,
                object,
                failure,
            } => ImageError::Transfer {
                party: party.clone(),
                object: object.clone(),
                failure: failure.clone(),
            },
            ImageError::Layer(m) => ImageError::Layer(m.clone()),
            ImageError::Io(io) => ImageError::Io(std::io::Error::new(io.kind(), io.to_string())),
            other => ImageError::transfer(
                "store",
                velarx_proto::transfer::FailureClass::Transient,
                other.to_string(),
            ),
        },
    }
}

impl ImageService {
    /// The credentials and certificates of a command that completes a pull,
    /// for the fetches of the layers that were pulled with such (they are
    /// not stored).
    pub(crate) fn set_lazy_access(&self, access: RegistryAccess) {
        if access.creds.is_none() && access.auths.is_empty() && access.certs.is_none() {
            return;
        }
        *self.funnel.access.lock().unwrap_or_else(|e| e.into_inner()) = access;
        // (the lists opened without them are opened again)
        self.funnel
            .access_epoch
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }

    /// Stage the files `files` (fs-verity digests) of the lazily staged
    /// layer `key` in its staging directory: those in flight are joined,
    /// the others fetched in one request.  Returns what this call fetched
    /// (the compressed bytes, and what the fetchers but the registry fetcher
    /// staged).
    pub async fn stage_lazy(
        &self,
        key: &LayerKey,
        files: Vec<String>,
        urgency: Urgency,
    ) -> ImageResult<Walked> {
        self.stage_begin(key, files, urgency).await
    }

    /// [`ImageService::stage_lazy`], its fetches in the table of those in
    /// flight when this returns (a fetch asked for later joins them): the
    /// future waits for them.  A request that joins a fetch waits for its
    /// own files as each is staged, not for the whole fetch.  A file in
    /// flight in the completion's batch (`background`) is asked for again on
    /// its own by a more urgent request, and the next requests of it join
    /// that one (a name that exists is success, so the two fetches agree).
    fn stage_begin(
        &self,
        key: &LayerKey,
        files: Vec<String>,
        urgency: Urgency,
    ) -> BoxFuture<'static, ImageResult<Walked>> {
        let (joined, own) = {
            let mut inflight = self
                .funnel
                .inflight
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            let mut joined = Vec::new();
            let mut new: Vec<String> = Vec::new();
            for f in files {
                match inflight.get(&(*key, f.clone())) {
                    Some(fl) if fl.urgency >= urgency.min(Urgency::Ahead) => {
                        joined.push((f, fl.staged.clone(), fl.fetch.clone()))
                    }
                    _ if !new.contains(&f) => new.push(f),
                    _ => {}
                }
            }
            let own = (!new.is_empty()).then(|| {
                let id = self
                    .funnel
                    .fetches
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let senders: Arc<HashMap<String, tokio::sync::watch::Sender<bool>>> = Arc::new(
                    new.iter()
                        .map(|f| (f.clone(), tokio::sync::watch::channel(false).0))
                        .collect(),
                );
                let (this, layer, batch) = (self.clone(), *key, new.clone());
                let funnel = Arc::downgrade(&self.funnel);
                let told = senders.clone();
                let task = tokio::spawn(async move {
                    let staged = |k: &str| {
                        if let Some(tx) = told.get(k) {
                            tx.send_replace(true);
                        }
                    };
                    let outcome = this
                        .stage_batch(&layer, batch, (urgency, &staged))
                        .await
                        .map_err(Arc::new);
                    if let Some(funnel) = funnel.upgrade() {
                        let mut inflight =
                            funnel.inflight.lock().unwrap_or_else(|e| e.into_inner());
                        for k in told.keys() {
                            // (an entry a more urgent fetch took is that one's)
                            let k = (layer, k.clone());
                            if inflight.get(&k).is_some_and(|fl| fl.id == id) {
                                inflight.remove(&k);
                            }
                        }
                    }
                    for tx in told.values() {
                        tx.send_replace(true);
                    }
                    outcome
                });
                let shared = async move {
                    task.await.unwrap_or_else(|e| {
                        Err(Arc::new(ImageError::Layer(format!("the fetch ended: {e}"))))
                    })
                }
                .boxed()
                .shared();
                for (f, tx) in senders.iter() {
                    let entry = InFlight {
                        id,
                        urgency,
                        staged: tx.subscribe(),
                        fetch: shared.clone(),
                    };
                    inflight.insert((*key, f.clone()), entry);
                }
                shared
            });
            (joined, own)
        };
        let (this, key) = (self.clone(), *key);
        let start = (urgency >= Urgency::Wait).then(|| StartGuard::new(&self.funnel, &key));
        async move {
            let _start = start;
            let mut walked = Walked::default();
            if let Some(own) = own {
                walked = own.await.map_err(unshared)?;
            }
            for (file, mut staged, fetch) in joined {
                // (the sender goes when the fetch ended)
                let _ = staged.wait_for(|s| *s).await;
                if this.lazy_file_path(&key, &file).is_none() {
                    fetch.await.map_err(unshared)?;
                    return Err(ImageError::Layer(format!(
                        "{file} of layer {key} was not staged"
                    )));
                }
            }
            Ok(walked)
        }
        .boxed()
    }

    /// Fetch the files a start of the image reads (`start_set`) from the
    /// layers `layers` (the lazy ones, the lowest first, each with its
    /// table), in the background: they are staged while the container is
    /// made, and what asks for one meanwhile joins the fetch.  `profile` is
    /// the startup profile of the image, when the pull asked for one: its
    /// files come after the others, in its order, and the window of the
    /// layers follows it.  A hint: what cannot be fetched is fetched when it
    /// is read.
    pub(super) async fn fetch_start_set(
        &self,
        (layers, pulled): (Vec<StartLayer>, PulledFrom),
        opened: impl std::future::Future<Output = OpenedWalker>,
        (first, config): (Vec<Vec<String>>, velarx_types::OciImageConfig),
        profile: Option<impl std::future::Future<Output = Vec<String>> + Send + 'static>,
    ) {
        // (what a fetch of the layers needs is what the pull has in hand:
        // it is not read from the staging and parsed again)
        let walk = pulled.walk();
        if let Some(opened) = opened.await {
            let mut walkers = self.funnel.walkers.lock().await;
            if self.kept_walker(&walkers, &walk).is_none() {
                walkers.insert(walk.clone(), opened);
            }
        }
        let ctxs: Vec<Arc<LayerCtx>> = {
            let mut kept = self.funnel.layers.lock().unwrap_or_else(|e| e.into_inner());
            layers
                .iter()
                .map(|(key, desc, toc, toc_z)| {
                    let ctx = Arc::new(LayerCtx {
                        desc: desc.clone(),
                        files: std::sync::OnceLock::new(),
                        profile: std::sync::OnceLock::new(),
                        toc: toc.clone(),
                        toc_z: toc_z.clone(),
                        walk: walk.clone(),
                        manifest: pulled.manifest.clone(),
                    });
                    kept.insert(*key, ctx.clone());
                    ctx
                })
                .collect()
        };
        // (the fetches are in the table of those in flight when this
        // returns: a read of one of the files joins it)
        let first = self.begin_set(&layers, first);
        let this = self.clone();
        tokio::spawn(async move {
            let mut done = first.await;
            if let Some(asked) = profile {
                let profile: Arc<[String]> = asked.await.into();
                if !profile.is_empty() {
                    for ctx in &ctxs {
                        let _ = ctx.profile.set(profile.clone());
                    }
                    let (tocs, files) = (layers.clone(), profile.clone());
                    let sets =
                        tokio::task::spawn_blocking(move || plan_start_set(&tocs, &config, &files))
                            .await
                            .unwrap_or_default();
                    done.extend(this.begin_set(&layers, sets).await);
                }
            }
            for failed in done.into_iter().filter_map(Result::err) {
                debug!("The start set of the image: {failed}");
            }
        });
    }

    /// Fetch the program `command` (looked up in the `PATH` `path`) of a
    /// container made on the pull `pull`, and what its loader reads, while
    /// the container is made: the program and the cache of the loader, then
    /// the interpreter and the libraries the program needs, then theirs,
    /// each round in one request for each layer, the requests of a start.
    /// A hint, in the background: what is not fetched here is fetched when
    /// it is read.
    pub(crate) fn fetch_program(
        &self,
        pull: &velarx_content::pull::staged::StagedPull,
        command: String,
        path: Option<String>,
    ) {
        /// The rounds of libraries: a program, its libraries, theirs.
        const ROUNDS: usize = 4;
        let (this, keys) = (self.clone(), pull.layers.clone());
        tokio::spawn(async move {
            // (the lazy layers of the pull, the lowest first)
            let mut layers: Vec<(LayerKey, Arc<LayerCtx>)> = Vec::new();
            for key in keys.iter().filter_map(|k| LayerKey::parse(k)) {
                if let Ok(ctx) = this.lazy_layer_ctx(&key).await {
                    layers.push((key, ctx));
                }
            }
            let tocs: Vec<Arc<Toc>> = layers.iter().map(|(_, c)| c.toc.clone()).collect();
            let keys: Vec<LayerKey> = layers.iter().map(|(k, _)| *k).collect();
            let at = |files: Vec<(usize, &velarx_storage::TocEntry)>| -> Vec<(usize, String)> {
                files
                    .into_iter()
                    .filter_map(|(l, e)| Some((l, e.verity()?)))
                    .collect()
            };
            let (mut round, cache) = {
                let all: Vec<&Toc> = tocs.iter().map(|t| &**t).collect();
                let names = start_set::Layers::new(&all);
                let program = names.program(&command, path.as_deref());
                let cache = names.file(start_set::LOADER_CACHE);
                (
                    at(program.into_iter().collect()),
                    at(cache.into_iter().collect()),
                )
            };
            let mut seen = std::collections::HashSet::new();
            for n in 0..ROUNDS {
                round.retain(|f| seen.insert(f.clone()));
                let mut fetch = round.clone();
                if n == 0 {
                    fetch.extend(cache.iter().cloned());
                }
                if fetch.is_empty() {
                    break;
                }
                let mut sets = vec![Vec::new(); keys.len()];
                for (l, d) in &fetch {
                    sets[*l].push(d.clone());
                }
                let fetches = keys
                    .iter()
                    .zip(sets)
                    .filter(|(_, files)| !files.is_empty())
                    .map(|(key, files)| this.stage_begin(key, files, Urgency::Wait));
                futures::future::join_all(fetches).await;
                let path_of = |(l, d): &(usize, String)| this.lazy_file_path(&keys[*l], d);
                let programs: Vec<PathBuf> = round.iter().filter_map(path_of).collect();
                let cache_path = cache.first().and_then(path_of);
                let tocs = tocs.clone();
                round = tokio::task::spawn_blocking(move || {
                    let all: Vec<&Toc> = tocs.iter().map(|t| &**t).collect();
                    let names = start_set::Layers::new(&all);
                    let cache = cache_path
                        .and_then(|p| std::fs::File::open(p).ok())
                        .map(|f| start_set::loader_cache(&f))
                        .unwrap_or_default();
                    let mut libraries = Vec::new();
                    for p in programs {
                        let Ok(file) = std::fs::File::open(p) else {
                            continue;
                        };
                        let loader = start_set::loader_of(&file);
                        libraries.extend(
                            names
                                .libraries(&loader, &cache)
                                .into_iter()
                                .filter_map(|(l, e)| Some((l, e.verity()?))),
                        );
                    }
                    libraries
                })
                .await
                .unwrap_or_default();
            }
        });
    }

    /// The fetches of the files `sets` of `layers`, each layer's in one
    /// request, begun now: the window of a layer waits until its fetch
    /// ends.
    fn begin_set(
        &self,
        layers: &[StartLayer],
        sets: Vec<Vec<String>>,
    ) -> impl std::future::Future<Output = Vec<ImageResult<Walked>>> {
        let fetches: Vec<_> = layers
            .iter()
            .zip(sets)
            .filter(|(_, files)| !files.is_empty())
            .map(|((key, ..), files)| {
                let guard = SetGuard::new(&self.funnel, key);
                self.stage_begin(key, files, Urgency::Wait)
                    .inspect(move |_| drop(guard))
            })
            .collect();
        futures::future::join_all(fetches)
    }

    /// Open the list of fetchers the layers of a pull will be fetched
    /// through while the pull goes on: [`ImageService::fetch_start_set`]
    /// keeps it, and it goes with the pull when the pull ends otherwise.
    /// The fetchers are told of each layer of `accepted` (its descriptor
    /// and its table as the layer has it) as soon as the pull accepted it,
    /// each layer at once: the first fetch of a layer does not wait for it.
    pub(super) fn open_walker(
        &self,
        pulled: &PulledFrom,
        accepted: futures::channel::mpsc::UnboundedReceiver<(OciDescriptor, bytes::Bytes)>,
    ) -> RemoteHandle<OpenedWalker> {
        use futures::StreamExt;
        let (this, pulled) = (self.clone(), pulled.clone());
        let (open, opened) = async move {
            let walk = pulled.walk();
            let opened = this
                .open_lazy_walker((&walk, &pulled.manifest))
                .await
                .map_err(|e| debug!("The fetchers of the pull are not opened: {e}"))
                .ok();
            if let Some((_, walker)) = &opened {
                accepted
                    .for_each_concurrent(None, |(desc, toc_z)| async move {
                        let stem = LayerKey::expected(&desc).file_stem();
                        if let Err(e) = walker.tell_layer(&stem, &desc, &toc_z).await {
                            debug!("The fetchers are not told of {}: {e}", desc.digest);
                        }
                    })
                    .await;
            }
            opened
        }
        .remote_handle();
        tokio::spawn(open);
        opened
    }

    /// Wait until no start fetches in `layers` (those of one image) and
    /// none did for [`QUIET`]: the completion of a pull sends its fetches
    /// after that, it never competes with the container being started.
    pub(super) async fn yield_to_starts(&self, layers: &[LayerKey]) {
        loop {
            let told = self.funnel.started.notified();
            tokio::pin!(told);
            told.as_mut().enable();
            let (busy, quiet_at) = {
                let starting = self
                    .funnel
                    .starting
                    .lock()
                    .unwrap_or_else(|e| e.into_inner());
                let mine = || layers.iter().filter_map(|k| starting.get(k));
                (
                    mine().any(|s| s.inflight > 0),
                    mine().map(|s| s.last + QUIET).max(),
                )
            };
            match quiet_at {
                _ if busy => told.await,
                Some(at) if at > tokio::time::Instant::now() => {
                    tokio::select! {
                        _ = tokio::time::sleep_until(at) => {}
                        _ = told => {}
                    }
                }
                _ => return,
            }
        }
    }

    /// One request for the files `files` of `key`, under the lease of the
    /// layer: what the store or the staging of the layer has by then (another
    /// engine staged it while this one waited for the lease) is not asked for.
    async fn stage_batch(
        &self,
        key: &LayerKey,
        files: Vec<String>,
        (urgency, told): (Urgency, &(dyn Fn(&str) + Send + Sync)),
    ) -> ImageResult<Walked> {
        let ctx = self.lazy_layer_ctx(key).await?;
        let lease = self.layer_lease(key).await?;
        let (store, staged) = (
            self.file_store.clone(),
            self.staging_area().layer_files(key),
        );
        let left = blocking(move || {
            let staged = velarx_storage::FileStore::new(&staged).ok();
            Ok::<_, ImageError>(
                files
                    .into_iter()
                    .filter(|d| {
                        !store.contains(d)
                            && !staged.as_ref().is_some_and(|s| s.get_path(d).is_some())
                    })
                    .collect::<Vec<_>>(),
            )
        })
        .await?;
        if left.is_empty() {
            return Ok(Walked::default());
        }
        let mut stale = false;
        let staged = match self.lazy_walker((&ctx.walk, &ctx.manifest)).await {
            Ok(walker) => {
                let staged = walker
                    .stage_files(
                        &key.file_stem(),
                        &ctx.desc,
                        (&ctx.toc, &ctx.toc_z),
                        left,
                        (urgency, told),
                    )
                    .await;
                stale = walker.stale();
                staged
            }
            Err(e) => Err(e),
        };
        if stale {
            self.funnel.walkers.lock().await.remove(&ctx.walk);
        }
        if staged.is_err() {
            // (the next fetch reads the layer and opens the list again: a
            // pull since may have changed how its registry is reached)
            self.funnel.walkers.lock().await.remove(&ctx.walk);
            self.funnel
                .layers
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(key);
        }
        drop(lease);
        self.prune_lease(key);
        staged
    }

    /// The slot of the lease of `key` goes when nothing holds the lease nor
    /// waits for it (the table of a service that lives on does not grow
    /// with the layers it ever fetched into).
    fn prune_lease(&self, key: &LayerKey) {
        let mut leases = self.funnel.leases.lock().unwrap_or_else(|e| e.into_inner());
        let idle = leases.get(key).is_some_and(|slot| {
            Arc::strong_count(slot) == 1
                && slot.try_lock().is_ok_and(|held| held.upgrade().is_none())
        });
        if idle {
            leases.remove(key);
        }
    }

    /// The fetcher that staged the file `file` of the staged layer `key`, as
    /// this process's list of fetchers knows it.
    pub(crate) async fn lazy_fetcher_of(&self, key: &LayerKey, file: &str) -> Option<String> {
        let ctx = self.lazy_layer_ctx(key).await.ok()?;
        let walker = self
            .funnel
            .walkers
            .lock()
            .await
            .get(&ctx.walk)
            .map(|(_, w)| w.clone())?;
        walker.staged_by(&ctx.desc.digest.to_string(), file)
    }

    /// The collector removed the staged layers of `report`: the fetchers of
    /// their lists forget them, as for a layer a pull discarded.
    pub async fn forget_collected(&self, report: &super::super::GcReport) {
        for key in &report.staged_layers {
            self.forget_lazy(key).await;
        }
    }

    /// The staging of the layer `key` went: the fetchers of its list forget
    /// it, and what a fetch of it needs is read again next time.
    pub(crate) async fn forget_lazy(&self, key: &LayerKey) {
        {
            // (the fetches of a start in flight keep their count: their
            // guards end it)
            let mut starting = self
                .funnel
                .starting
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            if starting.get(key).is_some_and(|s| s.inflight == 0) {
                starting.remove(key);
            }
        }
        self.funnel
            .windows
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(key);
        let ctx = self
            .funnel
            .layers
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(key);
        self.prune_lease(key);
        let Some(ctx) = ctx else { return };
        let walker = self
            .funnel
            .walkers
            .lock()
            .await
            .get(&ctx.walk)
            .map(|(_, w)| w.clone());
        if let Some(walker) = walker {
            walker.forget(&ctx.desc.digest.to_string()).await;
        }
        // (the list of fetchers of a repository no staged layer needs goes)
        let wanted = self
            .funnel
            .layers
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .any(|c| c.walk == ctx.walk);
        if !wanted {
            self.funnel.walkers.lock().await.remove(&ctx.walk);
        }
    }

    /// The lease of the layer `key` for this process: taken once (waiting
    /// for another process that holds it), shared by every fetch of the
    /// layer while one runs.
    async fn layer_lease(
        &self,
        key: &LayerKey,
    ) -> ImageResult<Arc<velarx_content::pull::staged::Lease>> {
        let slot = self
            .funnel
            .leases
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .entry(*key)
            .or_default()
            .clone();
        let mut held = slot.lock().await;
        if let Some(lease) = held.upgrade() {
            return Ok(lease);
        }
        let (area, k) = (self.staging_area(), *key);
        let lease = Arc::new(blocking(move || Ok(area.lease_layer(&k)?)).await?);
        *held = Arc::downgrade(&lease);
        Ok(lease)
    }

    /// What a fetch of the staged layer `key` needs, from the staging area
    /// (its record) and the pull that names it (its descriptor).
    async fn lazy_layer_ctx(&self, key: &LayerKey) -> ImageResult<Arc<LayerCtx>> {
        let cached = self
            .funnel
            .layers
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(key)
            .cloned();
        if let Some(ctx) = cached {
            // (a collection of another process, which this one cannot be
            // told of, may have taken the layer away: what the service
            // remembers of it goes with it)
            if self
                .staging_area()
                .layer_dir(key)
                .join("layer.json")
                .exists()
            {
                return Ok(ctx);
            }
            self.forget_lazy(key).await;
        }
        let (area, k) = (self.staging_area(), *key);
        let ctx = blocking(move || {
            let layer = area
                .layer(&k)?
                .ok_or_else(|| ImageError::Layer(format!("layer {k} is not staged")))?;
            let name = k.to_string();
            let pull = area
                .pull_records()
                .find(|p| p.layers.contains(&name))
                .ok_or_else(|| ImageError::Layer(format!("no pull names the layer {k}")))?;
            let manifest: OciManifest = serde_json::from_str(&pull.manifest)?;
            let at = pull.layers.iter().position(|l| *l == name).unwrap_or(0);
            let mut desc = manifest
                .layers
                .get(at)
                .cloned()
                .ok_or_else(|| ImageError::Manifest(format!("the pull has no layer {at}")))?;
            // (one table of contents may be named by two blobs: the blob and
            // the repository are those of the last pull of the layer)
            if let Ok(blob) = layer.meta.blob.parse() {
                (desc.digest, desc.size) = (blob, layer.meta.size);
            }
            let repository = layer
                .meta
                .registry_ref
                .clone()
                .or_else(|| pull.registry_ref.clone())
                .ok_or_else(|| ImageError::Layer(format!("layer {k} names no repository")))?;
            let text = layer.toc_text()?;
            let toc: Arc<Toc> = Arc::new(serde_json::from_str(&text)?);
            Ok::<_, ImageError>(LayerCtx {
                desc,
                files: std::sync::OnceLock::new(),
                profile: std::sync::OnceLock::new(),
                toc,
                // (the table this process fetches by, the staged one)
                toc_z: zstd::bulk::compress(text.as_bytes(), 1)?.into(),
                walk: walk_key(repository, &layer.meta.reach),
                manifest: pull.manifest.into_bytes(),
            })
        })
        .await?;
        let ctx = Arc::new(ctx);
        self.funnel
            .layers
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(*key, ctx.clone());
        Ok(ctx)
    }

    /// The list of fetchers `walk` of this process, opened on first use.
    async fn lazy_walker(
        &self,
        (walk, manifest): (&WalkKey, &[u8]),
    ) -> ImageResult<Arc<StagedFetch>> {
        let mut walkers = self.funnel.walkers.lock().await;
        if let Some(w) = self.kept_walker(&walkers, walk) {
            return Ok(w);
        }
        let (epoch, walker) = self.open_lazy_walker((walk, manifest)).await?;
        walkers.insert(walk.clone(), (epoch, walker.clone()));
        Ok(walker)
    }

    /// The list `walk` of `walkers` if it was opened with the credentials of
    /// now and its connections work (a list whose connection failed lost
    /// its scopes: a peer that restarted is reached again by a list opened
    /// anew).
    fn kept_walker(
        &self,
        walkers: &HashMap<WalkKey, (u64, Arc<StagedFetch>)>,
        walk: &WalkKey,
    ) -> Option<Arc<StagedFetch>> {
        let epoch = self
            .funnel
            .access_epoch
            .load(std::sync::atomic::Ordering::SeqCst);
        walkers
            .get(walk)
            .filter(|(opened_with, w)| *opened_with == epoch && !w.stale())
            .map(|(_, w)| w.clone())
    }

    /// A list of fetchers of the repository of `walk`, and the number of the
    /// credentials it was opened with: the credentials of a command only to
    /// layers that were pulled with some, and the stored ones of the
    /// registry.
    async fn open_lazy_walker(
        &self,
        (walk, manifest): (&WalkKey, &[u8]),
    ) -> ImageResult<(u64, Arc<StagedFetch>)> {
        let epoch = self
            .funnel
            .access_epoch
            .load(std::sync::atomic::Ordering::SeqCst);
        let (repository, tls_verify, creds, _) = walk;
        let given = self
            .funnel
            .access
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        // (what the pull brought and was not stored, the completion has to
        // bring again: a refusal of the access, which the completer of the
        // pull waits for, `needs-credentials`)
        let mut missing = Vec::new();
        if *creds && given.creds.is_none() && given.auths.is_empty() {
            missing.push("--creds or --authfile");
        }
        if walk.3 && given.certs.is_none() {
            missing.push("--cert-dir");
        }
        if !missing.is_empty() {
            return Err(ImageError::Unauthorized(format!(
                "the layers pulled from {repository} were pulled with {}, which are not stored: \
                 run `velarx image complete {} IMAGE`",
                match (*creds, walk.3) {
                    (true, true) => "credentials and certificates",
                    (true, false) => "credentials",
                    _ => "certificates",
                },
                missing.join(" ")
            )));
        }
        let given = RegistryAccess {
            creds: given.creds.filter(|_| *creds),
            auths: if *creds {
                given.auths
            } else {
                Default::default()
            },
            certs: given.certs.filter(|_| walk.3),
        };
        let access = velarx_content::pull::access::access_for(
            &self.resolver,
            repository,
            *tls_verify,
            &given,
        )?;
        let walker = self
            .staged_fetch((repository, None), *tls_verify, Some(&access), manifest)
            .await?;
        Ok((epoch, walker))
    }

    /// A miss of the file `file_digest` of the staged layer `layer`: staged
    /// on demand through the funnel if neither the store nor the staging of
    /// the layer has it, then, when no fetch had it in flight, the files that
    /// follow it in the background ([`ImageService::read_ahead`]): where it
    /// is.
    pub async fn fetch_lazy_file(
        &self,
        file_digest: &str,
        layer: &LayerKey,
    ) -> ImageResult<PathBuf> {
        if let Some(path) = self.lazy_file_path(layer, file_digest) {
            return Ok(path);
        }
        let joined = self
            .funnel
            .inflight
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&(*layer, file_digest.to_string()))
            .is_some_and(|fl| fl.urgency >= Urgency::Ahead);
        self.stage_lazy(layer, vec![file_digest.to_string()], Urgency::OnDemand)
            .await?;
        if !joined {
            self.read_ahead(layer, file_digest).await;
        }
        self.lazy_file_path(layer, file_digest).ok_or_else(|| {
            ImageError::Layer(format!(
                "{file_digest} of layer {layer} was staged and is not there"
            ))
        })
    }

    /// Whether `digest` (an fs-verity digest) is a file of the table of
    /// contents of the staged layer `key`.
    pub async fn is_file_of_lazy_layer(&self, key: &LayerKey, digest: &str) -> ImageResult<bool> {
        let ctx = self.lazy_layer_ctx(key).await?;
        Ok(ctx.files().contains_key(digest))
    }

    /// The files that follow `digest` in the staged layer `key`, in the
    /// startup profile of its image when the file is in it, else in its
    /// directory (the window of `[pull] lazy_window_files` and `lazy_window_kib`,
    /// which starts small and grows with each miss of the layer), staged in the
    /// background after a miss (`ahead`): the next reads of the container
    /// find them, or join their fetch.  It never takes the place of a miss,
    /// and what fails is fetched again when it is read.
    /// The fetch of them is in flight when this returns: the next miss of
    /// one joins it.
    async fn read_ahead(&self, key: &LayerKey, digest: &str) {
        use velarx_content::pull::window;
        let ahead = window::Window::from_config(&self.pull_config);
        let setting = self
            .funnel
            .setting
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .contains_key(key);
        if ahead.is_off() || setting {
            return;
        }
        let misses = {
            let mut windows = self
                .funnel
                .windows
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            let misses = windows.entry(*key).or_default();
            *misses += 1;
            *misses - 1
        };
        let ahead = ahead.grown(misses);
        let Ok(ctx) = self.lazy_layer_ctx(key).await else {
            return;
        };
        let Some(&at) = ctx.files().get(digest) else {
            return;
        };
        let staged = velarx_storage::FileStore::new(self.staging_area().layer_files(key)).ok();
        let wanted = |d: &str| {
            !self.file_store.contains(d)
                && !staged.as_ref().is_some_and(|s| s.get_path(d).is_some())
        };
        let positions = ctx
            .profile
            .get()
            .and_then(|p| window::follow(p, ctx.files(), digest, ahead, wanted, &ctx.toc))
            .unwrap_or_else(|| window::select(&ctx.toc, at, ahead, wanted));
        let files: Vec<String> = positions
            .iter()
            .filter_map(|&i| ctx.toc.entries[i].verity())
            .collect();
        if files.is_empty() {
            return;
        }
        let (n, key) = (files.len(), *key);
        let fetch = self.stage_begin(&key, files, Urgency::Ahead);
        tokio::spawn(async move {
            match fetch.await {
                Ok(_) => debug!("Fetched {n} more files of layer {key}"),
                Err(e) => debug!("The files after a miss of layer {key}: {e}"),
            }
        });
    }

    /// Where the file `digest` of the staged layer `key` is: the store, or
    /// the staging of the layer.
    pub(crate) fn lazy_file_path(&self, key: &LayerKey, digest: &str) -> Option<PathBuf> {
        self.file_store.get_path(digest).or_else(|| {
            velarx_storage::FileStore::new(self.staging_area().layer_files(key))
                .ok()
                .and_then(|s| s.get_path(digest))
        })
    }
}
#[cfg(test)]
impl ImageService {
    /// What a fetch of the staged layer `key` finds when it is made: the
    /// layer's description and its list of fetchers, as if the layer had
    /// been read from the staging area and the list opened.
    pub(super) async fn with_lazy_walker(
        &self,
        key: &LayerKey,
        (desc, toc): (OciDescriptor, Toc),
        walker: Arc<StagedFetch>,
    ) {
        let walk: WalkKey = ("localhost/a".to_string(), true, false, false);
        self.funnel
            .layers
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(
                *key,
                Arc::new(LayerCtx {
                    desc,
                    files: std::sync::OnceLock::new(),
                    profile: std::sync::OnceLock::new(),
                    toc_z: zstd::bulk::compress(&serde_json::to_vec(&toc).unwrap(), 1)
                        .unwrap()
                        .into(),
                    toc: Arc::new(toc),
                    walk: walk.clone(),
                    manifest: Vec::new(),
                }),
            );
        self.funnel.walkers.lock().await.insert(walk, (0, walker));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use velarx_storage::FileStore;
    use velarx_types::digest::{Algorithm, Digest};

    async fn service(tmp: &std::path::Path) -> ImageService {
        let db = velarx_db::Database::open_in_memory().await.unwrap();
        let store = Arc::new(FileStore::new(tmp.join("objects")).unwrap());
        ImageService::new(
            db,
            store,
            tmp.join("pulls"),
            velarx_storage::VerityMode::Off,
        )
        .unwrap()
    }

    /// The completion waits while a start fetches in a layer of its image
    /// and for the quiet time after it, and not for a start of another image.
    #[tokio::test(start_paused = true)]
    async fn the_completion_yields_to_a_start_of_its_image() {
        let tmp = tempfile::tempdir().unwrap();
        let service = service(tmp.path()).await;
        let key = |t: &str| LayerKey::Whole(Digest::of(Algorithm::Sha256, t.as_bytes()));
        let (mine, other) = (key("mine"), key("other"));
        service.yield_to_starts(&[mine]).await;
        let guard = StartGuard::new(&service.funnel, &other);
        service.yield_to_starts(&[mine]).await;
        drop(guard);
        let guard = StartGuard::new(&service.funnel, &mine);
        let waiting = tokio::spawn({
            let service = service.clone();
            async move { service.yield_to_starts(&[mine, other]).await }
        });
        tokio::time::sleep(Duration::from_secs(10)).await;
        assert!(!waiting.is_finished());
        drop(guard);
        tokio::time::sleep(QUIET - Duration::from_millis(1)).await;
        assert!(!waiting.is_finished());
        tokio::time::sleep(Duration::from_millis(2)).await;
        waiting.await.unwrap();
    }

    /// A layer forgotten while a fetch of a start is in flight in it keeps
    /// the count of that fetch: the completion still yields to it, and the
    /// guards end with nothing left in flight.
    #[tokio::test(start_paused = true)]
    async fn a_layer_forgotten_during_a_start_keeps_its_count() {
        let tmp = tempfile::tempdir().unwrap();
        let service = service(tmp.path()).await;
        let key = LayerKey::Whole(Digest::of(Algorithm::Sha256, b"layer"));
        let first = StartGuard::new(&service.funnel, &key);
        service.forget_lazy(&key).await;
        let second = StartGuard::new(&service.funnel, &key);
        drop(first);
        let waiting = tokio::spawn({
            let service = service.clone();
            async move { service.yield_to_starts(&[key]).await }
        });
        tokio::time::sleep(Duration::from_secs(10)).await;
        assert!(!waiting.is_finished());
        drop(second);
        let inflight = |service: &ImageService| {
            service
                .funnel
                .starting
                .lock()
                .unwrap()
                .get(&key)
                .map(|s| s.inflight)
        };
        assert_eq!(inflight(&service), Some(0));
        waiting.await.unwrap();
        service.forget_lazy(&key).await;
        assert_eq!(inflight(&service), None);
    }

    /// A minimal 64-bit ELF program with the interpreter `interp` that
    /// needs the library `needed`.
    fn elf(interp: &str, needed: &str) -> Vec<u8> {
        let (interp_at, dyn_at) = (64 + 3 * 56, 64 + 3 * 56 + 32);
        assert!(interp.len() < 32);
        let str_at = dyn_at + 4 * 16;
        let mut out = vec![0u8; 64];
        out[..6].copy_from_slice(b"\x7fELF\x02\x01");
        out[32..40].copy_from_slice(&64u64.to_le_bytes());
        out[54..56].copy_from_slice(&56u16.to_le_bytes());
        out[56..58].copy_from_slice(&3u16.to_le_bytes());
        let total = (str_at + needed.len() + 2) as u64;
        for (kind, offset, size) in [
            (1u32, 0u64, total),
            (3, interp_at as u64, interp.len() as u64 + 1),
            (2, dyn_at as u64, 64),
        ] {
            out.extend(kind.to_le_bytes());
            out.extend(0u32.to_le_bytes());
            for v in [offset, offset, offset, size, size, 0] {
                out.extend(v.to_le_bytes());
            }
        }
        out.resize(interp_at, 0);
        out.extend(interp.bytes().chain([0]));
        out.resize(dyn_at, 0);
        let strsz = needed.len() as u64 + 2;
        for (tag, value) in [(5u64, str_at as u64), (10, strsz), (1, 1), (0, 0)] {
            out.extend(tag.to_le_bytes());
            out.extend(value.to_le_bytes());
        }
        out.push(0);
        out.extend(needed.bytes().chain([0]));
        out
    }

    /// The program a container runs, its interpreter and its library are
    /// staged while the container is made, before anything reads them.
    #[tokio::test]
    async fn the_program_of_a_container_and_its_loader_are_fetched() {
        use velarx_content::fakes::{Fake, Stages};
        use velarx_content::fetcher::fetch_client::FetchConn;
        use velarx_content::serve_fetch::LocalFetcher;
        let tmp = tempfile::tempdir().unwrap();
        let service = service(tmp.path()).await;
        let area = service.staging_area();
        area.create().unwrap();
        let key = LayerKey::Whole(Digest::of(Algorithm::Sha256, b"blob"));
        std::fs::create_dir_all(area.layer_dir(&key)).unwrap();
        std::fs::write(area.layer_dir(&key).join("layer.json"), b"{}").unwrap();
        let files: Vec<(&str, Vec<u8>)> = vec![
            ("usr/bin/prog", elf("/lib/ld.so", "libc.so.6")),
            ("lib/ld.so", b"the loader".to_vec()),
            ("lib/libc.so.6", b"the library".to_vec()),
        ];
        let keyed: Vec<(String, Vec<u8>)> = files
            .iter()
            .map(|(_, body)| {
                let d = velarx_storage::fsverity_digest_of(Algorithm::Sha256, body);
                (Digest::parse_key(&d).unwrap().to_string(), body.clone())
            })
            .collect();
        let mut entries = vec![
            serde_json::json!({"name": "usr/", "type": "dir"}),
            serde_json::json!({"name": "usr/bin/", "type": "dir"}),
            serde_json::json!({"name": "lib/", "type": "dir"}),
        ];
        for ((name, body), (d, _)) in files.iter().zip(&keyed) {
            entries.push(serde_json::json!({
                "name": name, "type": "reg", "size": body.len(),
                "fsverity": velarx_storage::toc_value(&velarx_storage::to_toc(d).unwrap()),
            }));
        }
        let toc: Toc =
            serde_json::from_value(serde_json::json!({"version": 1, "entries": entries})).unwrap();
        let desc: OciDescriptor = serde_json::from_value(serde_json::json!({
            "mediaType": "application/vnd.oci.image.layer.v1.tar+zstd",
            "digest": key.digest().to_string(),
            "size": 1,
        }))
        .unwrap();
        let registry = LocalFetcher::start(
            Arc::new(Fake::of(Stages::Right, keyed.clone(), Default::default())),
            velarx_content::activation::Limits::default(),
        )
        .unwrap();
        let manifest = br#"{"schemaVersion":2,"config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:4444444444444444444444444444444444444444444444444444444444444444","size":2},"layers":[]}"#;
        let walker = StagedFetch::open(
            (
                Vec::new(),
                Some(FetchConn::new(registry.connect().unwrap()).unwrap()),
                Vec::new(),
            ),
            &service.staging_dir,
            false,
            ("localhost/a", true),
            Some(b"{}"),
            manifest,
        )
        .await
        .unwrap();
        service.with_lazy_walker(&key, (desc, toc), walker).await;
        let pull = velarx_content::pull::staged::StagedPull {
            id: "id".into(),
            manifest_digest: Digest::of(Algorithm::Sha256, b"m"),
            config_digest: Digest::of(Algorithm::Sha256, b"c"),
            manifest: String::new(),
            config: String::new(),
            layers: vec![key.to_string()],
            tags: Vec::new(),
            digest_names: Vec::new(),
            pulls: Vec::new(),
            registry_ref: None,
            started_at: String::new(),
        };
        service.fetch_program(&pull, "prog".into(), None);
        let staged = || {
            keyed
                .iter()
                .all(|(d, _)| service.lazy_file_path(&key, d).is_some())
        };
        for _ in 0..500 {
            if staged() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(
            staged(),
            "the program, its interpreter and its library are staged"
        );
    }

    /// The files a start reads are staged in the background while the
    /// layer's window waits for them.
    #[tokio::test]
    async fn the_start_set_is_staged_and_the_window_waits_for_it() {
        use velarx_content::fakes::{Fake, Stages};
        use velarx_content::fetcher::fetch_client::FetchConn;
        use velarx_content::serve_fetch::LocalFetcher;
        let tmp = tempfile::tempdir().unwrap();
        let service = service(tmp.path()).await;
        let area = service.staging_area();
        area.create().unwrap();
        let key = LayerKey::Whole(Digest::of(Algorithm::Sha256, b"blob"));
        std::fs::create_dir_all(area.layer_dir(&key)).unwrap();
        std::fs::write(area.layer_dir(&key).join("layer.json"), b"{}").unwrap();
        let body = b"root:x:0:0".to_vec();
        let file = velarx_storage::fsverity_digest_of(Algorithm::Sha256, &body);
        let file = Digest::parse_key(&file).unwrap().to_string();
        let toc: Toc = serde_json::from_value(serde_json::json!({
            "version": 1,
            "entries": [{"name": "etc/", "type": "dir"}, {
                "name": "etc/passwd", "type": "reg", "size": body.len(),
                "fsverity": velarx_storage::toc_value(&velarx_storage::to_toc(&file).unwrap()),
            }],
        }))
        .unwrap();
        let desc: OciDescriptor = serde_json::from_value(serde_json::json!({
            "mediaType": "application/vnd.oci.image.layer.v1.tar+zstd",
            "digest": key.digest().to_string(),
            "size": 1,
        }))
        .unwrap();
        let registry = LocalFetcher::start(
            Arc::new(Fake::new(Stages::Right, &file, &body, Default::default())),
            velarx_content::activation::Limits::default(),
        )
        .unwrap();
        let manifest = br#"{"schemaVersion":2,"config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:4444444444444444444444444444444444444444444444444444444444444444","size":2},"layers":[]}"#;
        let walker = StagedFetch::open(
            (
                Vec::new(),
                Some(FetchConn::new(registry.connect().unwrap()).unwrap()),
                Vec::new(),
            ),
            &service.staging_dir,
            false,
            ("localhost/a", true),
            Some(b"{}"),
            manifest,
        )
        .await
        .unwrap();
        service
            .with_lazy_walker(&key, (desc.clone(), toc.clone()), walker)
            .await;
        assert!(service.lazy_file_path(&key, &file).is_none());
        let profile = futures::future::ready(vec![file.clone()]);
        let toc_z = zstd::bulk::compress(&serde_json::to_vec(&toc).unwrap(), 1).unwrap();
        let layers = vec![(key, desc, Arc::new(toc), toc_z.into())];
        let config = velarx_types::OciImageConfig::default();
        let first = plan_start_set(&layers, &config, &[]);
        assert_eq!(first, [[file.clone()]]);
        service
            .fetch_start_set(
                (
                    layers,
                    PulledFrom {
                        repository: "localhost/a".into(),
                        reach: velarx_db::LayerReach {
                            tls_verify: true,
                            creds: false,
                            certs: false,
                        },
                        manifest: Vec::new(),
                    },
                ),
                async { None },
                (first, config),
                Some(profile),
            )
            .await;
        // (a read of the file joins the fetch begun above)
        assert!(service
            .funnel
            .inflight
            .lock()
            .unwrap()
            .contains_key(&(key, file.clone())));
        assert!(service.funnel.setting.lock().unwrap().contains_key(&key));
        service
            .stage_lazy(&key, vec![file.clone()], Urgency::OnDemand)
            .await
            .unwrap();
        assert!(service.lazy_file_path(&key, &file).is_some());
        for _ in 0..100 {
            if service.funnel.setting.lock().unwrap().is_empty() {
                // (the window of the layer follows the profile now)
                let ctx = service.funnel.layers.lock().unwrap()[&key].clone();
                assert_eq!(ctx.profile.get().map(|p| &p[..]), Some(&[file.clone()][..]));
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("the start set never ended");
    }
}
