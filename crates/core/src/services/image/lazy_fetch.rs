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
//! * The fetch itself is the engine's ordered list of fetchers, walked by
//!   `StagedFetch` (`Fetch(layer, [digest], urgency)`): the engine routes the
//!   request; it fetches nothing itself.  The list of a repository is opened
//!   once and kept; one whose call failed is opened again by the next fetch.

use super::*;
use futures::future::{BoxFuture, FutureExt, Shared};
use std::collections::HashMap;
use std::sync::{Mutex as StdMutex, Weak};
use velarx_content::fetcher::fetch::Urgency;
use velarx_content::pull::staged_fetch::StagedFetch;
use velarx_registry::auth::RegistryAccess;

type Outcome = Result<Walked, Arc<ImageError>>;
use velarx_content::pull::staged_fetch::Walked;
/// What a list of fetchers was opened for: the repository, its TLS
/// verification, whether its pull had credentials, and certificates.
type WalkKey = (String, bool, bool, bool);
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

/// What a fetch of a file of a staged layer needs: its descriptor, its
/// table, and the repository and the list of fetchers it comes through.
struct LayerCtx {
    desc: OciDescriptor,
    toc: Toc,
    /// The position of each regular file in `toc`, by its fs-verity digest
    files: HashMap<String, usize>,
    /// The repository, its TLS verification, whether its pull had credentials
    walk: WalkKey,
    shareable: bool,
    manifest: Vec<u8>,
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
    /// (the compressed bytes, and what the fetchers before the registry
    /// fetcher staged).
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
        async move {
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
        let staged = match self.lazy_walker(key, &ctx).await {
            Ok(walker) => {
                let staged = walker
                    .stage_files(&key.file_stem(), &ctx.desc, &ctx.toc, left, (urgency, told))
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
            let toc: Toc = serde_json::from_str(&layer.toc_text()?)?;
            Ok::<_, ImageError>(LayerCtx {
                desc,
                files: velarx_content::pull::window::file_positions(&toc),
                toc,
                walk: (
                    repository,
                    layer.meta.reach.tls_verify,
                    layer.meta.reach.creds,
                    layer.meta.reach.certs,
                ),
                shareable: pull.shareable,
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

    /// The list of fetchers of the repository of `ctx`, opened on first use:
    /// the credentials of a command only to a layer that was pulled with
    /// some, and the stored ones of the registry.
    async fn lazy_walker(&self, key: &LayerKey, ctx: &LayerCtx) -> ImageResult<Arc<StagedFetch>> {
        let mut walkers = self.funnel.walkers.lock().await;
        // (a list whose connection failed lost its scopes: a peer that
        // restarted is reached again by a list opened anew)
        let epoch = self
            .funnel
            .access_epoch
            .load(std::sync::atomic::Ordering::SeqCst);
        if let Some((_, w)) = walkers
            .get(&ctx.walk)
            .filter(|(opened_with, w)| *opened_with == epoch && !w.stale())
        {
            return Ok(w.clone());
        }
        let (repository, tls_verify, creds, _) = &ctx.walk;
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
        if ctx.walk.3 && given.certs.is_none() {
            missing.push("--cert-dir");
        }
        if !missing.is_empty() {
            return Err(ImageError::Unauthorized(format!(
                "layer {key} was pulled from {repository} with {}, which are not stored: \
                 run `velarx image complete {} IMAGE`",
                match (*creds, ctx.walk.3) {
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
            certs: given.certs.filter(|_| ctx.walk.3),
        };
        let access = velarx_content::pull::access::access_for(
            &self.resolver,
            repository,
            *tls_verify,
            &given,
        )?;
        let walker = self
            .staged_fetch(
                (repository, None, ctx.shareable),
                *tls_verify,
                Some(&access),
                &ctx.manifest,
            )
            .await?;
        walkers.insert(ctx.walk.clone(), (epoch, walker.clone()));
        Ok(walker)
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
        Ok(ctx.files.contains_key(digest))
    }

    /// The files that follow `digest` in the staged layer `key` (the window
    /// of `[pull] lazy_window_files` and `lazy_window_kib`), staged in the
    /// background after a miss (`ahead`): the next reads of the container
    /// find them, or join their fetch.  It never takes the place of a miss,
    /// and what fails is fetched again when it is read.
    /// The fetch of them is in flight when this returns: the next miss of
    /// one joins it.
    async fn read_ahead(&self, key: &LayerKey, digest: &str) {
        use velarx_content::pull::window;
        let ahead = window::Window::from_config(&self.pull_config);
        if ahead.is_off() {
            return;
        }
        let Ok(ctx) = self.lazy_layer_ctx(key).await else {
            return;
        };
        let Some(&at) = ctx.files.get(digest) else {
            return;
        };
        let staged = velarx_storage::FileStore::new(self.staging_area().layer_files(key)).ok();
        let positions = window::select(&ctx.toc, at, ahead, |d| {
            !self.file_store.contains(d)
                && !staged.as_ref().is_some_and(|s| s.get_path(d).is_some())
        });
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
                    files: velarx_content::pull::window::file_positions(&toc),
                    toc,
                    walk: walk.clone(),
                    shareable: false,
                    manifest: Vec::new(),
                }),
            );
        self.funnel.walkers.lock().await.insert(walk, (0, walker));
    }
}
