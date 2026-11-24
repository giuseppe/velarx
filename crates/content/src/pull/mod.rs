// SPDX-License-Identifier: Apache-2.0
//! The pull engine, and what the engine and the fetchers share of pulling:
//! the layout and leases of the staging area (`staged`), the way a staged
//! file gets its name in the store (`commit`), the entries and
//! tar-split of a layer (`entry`, `tarsplit`) and the unnamed and sealed
//! files (`unnamed`).
//!
//! A pull fetches the layers of an image at the same time.  A zstd:chunked
//! layer is pulled by ranges (`chunked`): only the files and chunks the store
//! does not have are requested.  Any other layer is streamed (`stream`).
//! Both write to a staging session (`session`) and verify every digest
//! once, as the data arrives; the diff id of each layer is checked against
//! the configuration of the image.  Only when every layer is verified is the
//! staged content synced with a `syncfs`, moved into the store, a `syncfs`
//! of the store, and the layers recorded in the database in one transaction.

pub mod access;
pub mod chunked;
pub mod index;
pub mod lazy;
pub mod made;
pub mod merge;
pub mod net;
pub mod ranges;
pub mod session;
pub mod sink;
pub mod staged_fetch;
pub mod start_set;
pub mod stream;
#[cfg(test)]
pub(crate) mod testnames;
pub mod window;

pub mod commit;
pub mod entry;
pub mod staged;
pub mod stored;
pub mod tarsplit;
pub mod unnamed;

pub use velarx_tarsplit::tar;
pub use velarx_tarsplit::{zstd_decoder, ZSTD_WINDOW_LOG_MAX};

use net::Net;
use sink::Sink;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use velarx_config::PullConfig;
use velarx_db::{ChunkLocation, Database, FileRecord, LayerCommit, LayerRecord};
use velarx_registry::target::Target;
use velarx_storage::Toc;
use velarx_types::digest::{Algorithm, Digest};
use velarx_types::{ImageError, ImageResult, LayerKey, OciDescriptor};

/// Limits that bound what a pull may use, whatever the registry sends.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Limits {
    /// Bytes a layer may inflate to.
    pub max_layer_bytes: u64,
    /// How many times its blob a layer may inflate to.
    pub inflate_ratio: u64,
    /// What a layer may always inflate to, whatever the size of its blob.
    pub inflate_floor_bytes: u64,
    /// The largest chunk decompressed in memory.
    pub max_chunk_bytes: u64,
    pub range_concurrency: usize,
    pub parallel_layers: usize,
    pub memory_bytes: u64,
    pub workers: usize,
}

/// The bytes something of `size` compressed bytes (`-1` if unknown) may
/// inflate to: `ratio` times its size, at least `floor`, never above `max`.
pub fn inflate_limit(size: i64, ratio: u64, floor: u64, max: u64) -> u64 {
    match u64::try_from(size) {
        Ok(n) if n > 0 => n.saturating_mul(ratio).max(floor).min(max),
        _ => max,
    }
}

impl Limits {
    /// The bytes the layer of a blob of `blob_size` (`-1` if unknown) may
    /// inflate to: relative to the blob, never above `max_layer_bytes`.
    pub fn inflate_cap(&self, blob_size: i64) -> u64 {
        inflate_limit(
            blob_size,
            self.inflate_ratio,
            self.inflate_floor_bytes,
            self.max_layer_bytes,
        )
    }

    pub fn from_config(c: &PullConfig) -> Self {
        let cpus = std::thread::available_parallelism().map_or(1, |n| n.get());
        let memory_bytes = c.memory_budget_mib.max(16) * 1024 * 1024;
        Self {
            max_layer_bytes: c.max_layer_gib.max(1).saturating_mul(1 << 30),
            inflate_ratio: c.max_inflate_ratio.max(1),
            inflate_floor_bytes: c.inflate_floor_mib * 1024 * 1024,
            // A chunk, its compressed bytes and its predecessors in flight
            // must fit.
            max_chunk_bytes: memory_bytes / 4,
            range_concurrency: c.range_concurrency.max(1),
            parallel_layers: c.parallel_layers.max(1),
            memory_bytes,
            // Chunks wait for memory and the page cache when written: a few
            // more threads than CPUs keep the CPUs busy.
            workers: if c.workers == 0 {
                (cpus * 3).clamp(4, 16)
            } else {
                c.workers
            },
        }
    }
}

/// How fast a pull goes: the limits, and the threads and memory it shares.
#[derive(Clone)]
pub struct Pace {
    pub limits: Arc<Limits>,
    /// Threads decompressing and hashing.
    pub workers: Arc<Semaphore>,
    /// Memory in KiB for the chunks in flight.
    memory: Arc<Semaphore>,
}

impl Pace {
    pub fn new(limits: Limits) -> Self {
        Self {
            workers: Arc::new(Semaphore::new(limits.workers)),
            memory: Arc::new(Semaphore::new((limits.memory_bytes / 1024) as usize)),
            limits: Arc::new(limits),
        }
    }

    /// Wait for `bytes` of the memory budget (at most the whole of it).
    pub async fn reserve(
        &self,
        bytes: u64,
    ) -> Result<OwnedSemaphorePermit, tokio::sync::AcquireError> {
        let kib = bytes
            .div_ceil(1024)
            .clamp(1, self.limits.memory_bytes / 1024);
        self.memory.clone().acquire_many_owned(kib as u32).await
    }
}

/// What a layer cost.
#[derive(Debug, Clone, Default)]
pub struct LayerReport {
    /// Bytes requested from the registry.
    pub fetched_bytes: u64,
    pub fetched_files: u64,
    /// Compressed bytes that were not requested because the store had them.
    pub reused_bytes: u64,
    pub reused_files: u64,
    /// What the other sources of the walk gave (compressed bytes, files),
    /// by name.
    pub sources: Vec<velarx_proto::workload::BySource>,
}

/// Resources shared by the layers of a pull.
#[derive(Clone)]
pub struct PullCtx {
    pub net: Net,
    /// Where the files of the pull go (a staging session, or the files of a
    /// driver)
    pub sink: Arc<dyn Sink>,
    pub db: Database,
    pub limits: Arc<Limits>,
    /// Threads decompressing and hashing.
    pub workers: Arc<Semaphore>,
    /// Memory in KiB for the chunks in flight.
    memory: Arc<Semaphore>,
    /// The layer whose chunks are fetched, as the sources are told it (they
    /// find who has the chunks by it); none: the layer of its blob
    pub layer: Option<LayerKey>,
    /// What says whether the store has a file, when the storage driver
    /// answers it (none: the sink does, which is what an in-process
    /// driver's answer is: [`Session::have`])
    pub have: Option<Have>,
    /// The fetcher that brings the files of the layers with a
    /// table of contents into their staging directories (none: they are
    /// fetched as chunks)
    pub staged: Option<Arc<staged_fetch::StagedFetch>>,
    /// The files the layers of this pull are fetching
    pub fetching: Arc<Fetching>,
}

/// The files the layers of one pull are fetching, by key: a layer whose
/// plan names a file another layer of the pull is fetching waits for that
/// fetch (the file is then in the pull's session) instead of asking for it
/// again; a fetch that fails lets the waiters fetch it themselves.
#[derive(Default)]
pub struct Fetching(std::sync::Mutex<HashMap<String, tokio::sync::watch::Receiver<bool>>>);

/// The files a layer fetches for the pull ([`Fetching::claim`]): the
/// layers that wait for them are told when [`Claim::done`] or when it is
/// dropped (failed).
pub struct Claim {
    table: Arc<Fetching>,
    keys: Vec<String>,
    done: tokio::sync::watch::Sender<bool>,
}

impl Fetching {
    /// Claim those of `keys` no other layer of the pull fetches; the others
    /// are returned with what tells the end of their fetch.
    #[allow(clippy::type_complexity)]
    pub fn claim(
        self: &Arc<Self>,
        keys: Vec<String>,
    ) -> (Claim, Vec<(String, tokio::sync::watch::Receiver<bool>)>) {
        let (done, rx) = tokio::sync::watch::channel(false);
        let mut table = self.0.lock().unwrap_or_else(|e| e.into_inner());
        let (mut mine, mut theirs) = (Vec::new(), Vec::new());
        for k in keys {
            match table.get(&k) {
                Some(r) => theirs.push((k, r.clone())),
                None => {
                    table.insert(k.clone(), rx.clone());
                    mine.push(k);
                }
            }
        }
        let claim = Claim {
            table: self.clone(),
            keys: mine,
            done,
        };
        (claim, theirs)
    }
}

impl Claim {
    /// The keys this layer fetches.
    pub fn keys(&self) -> &[String] {
        &self.keys
    }

    /// The files are in the session: the layers that wait for them go on.
    pub fn done(self) {
        self.done.send_replace(true);
    }
}

impl Drop for Claim {
    fn drop(&mut self) {
        let mut table = self.table.0.lock().unwrap_or_else(|e| e.into_inner());
        for k in &self.keys {
            table.remove(k);
        }
    }
}

/// Whether the fetch that `rx` tells the end of brought its files.
pub async fn fetched_by_another(mut rx: tokio::sync::watch::Receiver<bool>) -> bool {
    rx.wait_for(|done| *done).await.is_ok()
}

/// Whether the store (or an earlier layer of the pull) has the file known by
/// a key, of the size its table gives: the driver's answer to what the pull
/// is to fetch.
pub type Have = Arc<dyn Fn(&str, u64) -> bool + Send + Sync>;

impl PullCtx {
    pub fn new(net: Net, sink: Arc<dyn Sink>, db: Database, limits: Limits) -> Self {
        let workers = Arc::new(Semaphore::new(limits.workers));
        let memory = Arc::new(Semaphore::new((limits.memory_bytes / 1024) as usize));
        Self {
            net,
            sink,
            db,
            limits: Arc::new(limits),
            workers,
            memory,
            layer: None,
            have: None,
            staged: None,
            fetching: Arc::default(),
        }
    }

    /// The files of the layers with a table of contents come from the
    /// fetcher of `staged`.
    pub fn with_staged(mut self, staged: Arc<staged_fetch::StagedFetch>) -> Self {
        self.staged = Some(staged);
        self
    }

    /// The files go to `sink`.
    pub fn with_sink(mut self, sink: Arc<dyn Sink>) -> Self {
        self.sink = sink;
        self
    }

    /// The layers of this ctx fetch files of their own: what another layer
    /// fetches is not in the sink of this one ([`Fetching`]).
    pub fn with_own_fetching(mut self) -> Self {
        self.fetching = Arc::default();
        self
    }

    /// The driver says what it has ([`PullCtx::have_fn`]).
    pub fn with_have(mut self, have: Have) -> Self {
        self.have = Some(have);
        self
    }

    /// What says whether a file is there: the driver's answer, else the
    /// sink's.
    pub fn have_fn(&self) -> Have {
        self.have.clone().unwrap_or_else(|| {
            let sink = self.sink.clone();
            Arc::new(move |key, size| sink.holds(key, size))
        })
    }

    /// The chunks fetched are of the layer `key` (a layer of a TOC, which
    /// is not the layer of its blob).
    pub fn with_layer(mut self, key: LayerKey) -> Self {
        self.layer = Some(key);
        self
    }

    /// The pace of this pull.
    pub fn pace(&self) -> Pace {
        Pace {
            limits: self.limits.clone(),
            workers: self.workers.clone(),
            memory: self.memory.clone(),
        }
    }
}

/// The algorithm of the key of a file: the hash of its content
/// (`sha256:HEX`, `sha512:HEX`) or its fs-verity digest
/// (`fsverity-sha256-12:HEX`, `fsverity-sha512-12:HEX`, the name of its
/// object); none for any other text.
pub fn key_algorithm(text: &str) -> Option<Algorithm> {
    text.parse::<Digest>()
        .or_else(|_| Digest::parse_fsverity(text))
        .ok()
        .map(|d| d.alg())
}

/// Whether `text` is the key of a file: the hash of its content or the
/// fs-verity digest of it, in either algorithm.
pub fn is_file_key(text: &str) -> bool {
    key_algorithm(text).is_some()
}

/// Where the blobs of an image come from.
#[derive(Clone)]
pub enum Source {
    Registry(Target),
    /// The origin of a path (`velarx-dir --origin`): the layers are
    /// unpacked there, by the fetchers of the pull
    Path,
    /// A blob of a file (`import`: one layer made of a tar)
    Archive(Arc<crate::archive::Archive>),
}

/// A layer ingested as it was made: the files of its stream in a session
/// (a pull takes them from it), its table of contents, its diff id.  Its
/// blob is its stream, so its digest is the diff id.
pub struct Made {
    pub session: Arc<session::Session>,
    pub ingested: stream::Ingested,
}

/// A layer that is pulled and verified, not recorded yet.
#[derive(Clone)]
pub struct LayerDone {
    /// What verified it: its blob pulled whole, or the TOC its descriptor
    /// names.
    pub key: LayerKey,
    /// The digest of the blob of its descriptor.
    pub blob: Digest,
    /// The diff id it was verified against; of a lazy layer, the claim of
    /// the configuration, which nothing proved yet (it is not recorded).
    pub diff_id: Digest,
    pub size: i64,
    pub toc: Arc<Toc>,
    pub files: Vec<stream::FileUse>,
    pub chunks: Vec<ChunkLocation>,
    pub report: LayerReport,
    /// The zstd compressed tar-split.
    pub tarsplit: bytes::Bytes,
    /// What the file `toc.zst` of the layer holds: the table of a layer of a
    /// TOC as the registry sent it ([`chunked::Metadata::toc_z`]), the zstd of
    /// the JSON of `toc` for any other (made again by [`LayerDone::settle`],
    /// which changes `toc`).
    pub toc_z: bytes::Bytes,
    /// Only the metadata was fetched: the files come on demand and the layer
    /// is not verified against its diff id yet.
    pub lazy: bool,
    /// The blob was hashed to its digest: a layer pulled whole (not one of a
    /// TOC, nor one made of the files the peers have for its diff id)
    pub blob_checked: bool,
    /// The files of the layer whose fs-verity digest the kernel measured
    /// when the pull committed them.
    pub checked: std::collections::HashSet<String>,
}

impl LayerDone {
    /// Know the files of the layer by their fs-verity digest, now that the
    /// pull committed them (`committed`: the object of each key it staged,
    /// [`session::Committed`]): a file the TOC gives an fs-verity digest
    /// is that object (the commit checked it) or one the store has, the
    /// others get the digest of what they are.  The files of a lazy layer
    /// are not there yet.
    pub fn settle(
        &mut self,
        committed: &HashMap<String, velarx_storage::Object>,
        store: &velarx_storage::FileStore,
    ) -> ImageResult<()> {
        let measured: std::collections::HashSet<&str> = committed
            .values()
            .filter(|o| o.checked)
            .map(|o| o.verity.as_str())
            .collect();
        let mut ids: HashMap<String, String> = HashMap::new();
        for e in &mut Arc::make_mut(&mut self.toc).entries {
            if !e.has_content() {
                continue;
            }
            let id = match (e.verity(), e.digest.as_deref()) {
                (Some(id), _) => {
                    if !self.lazy && !committed.contains_key(&id) && !store.contains(&id) {
                        return Err(ImageError::Layer(format!(
                            "`{}` ({id}) is not in the store",
                            e.name
                        )));
                    }
                    id
                }
                (None, Some(hash)) => {
                    let o = committed.get(hash).ok_or_else(|| {
                        ImageError::Layer(format!("`{}` was not stored by the pull", e.name))
                    })?;
                    ids.insert(hash.to_string(), o.verity.clone());
                    e.fsverity = velarx_storage::to_toc(&o.verity);
                    o.verity.clone()
                }
                (None, None) => {
                    return Err(ImageError::Layer(format!("`{}` has no digest", e.name)))
                }
            };
            if measured.contains(id.as_str()) {
                self.checked.insert(id);
            }
        }
        for f in &mut self.files {
            if let Some(id) = ids.get(&f.digest) {
                f.digest = id.clone();
            }
        }
        for c in &mut self.chunks {
            if let Some(id) = ids.get(&c.file_digest) {
                c.file_digest = id.clone();
            }
        }
        self.keep_toc();
        Ok(())
    }

    /// The file `toc.zst` of a layer that is not pulled by its table holds
    /// the JSON of `toc` as it is now: made again when `toc` was changed.
    pub fn keep_toc(&mut self) {
        if !self.key.is_toc() {
            self.toc_z = stored::json_z(&self.toc);
        }
    }
}

/// TOC entries the layers of one image keep until the image is recorded.
pub const MAX_IMAGE_TOC_ENTRIES: u64 = 2 << 20;
/// Compressed tar-split bytes the layers of one image keep until then.
pub const MAX_IMAGE_TARSPLIT: u64 = 1 << 30;

/// What the layers of an image keep in memory until the image is recorded,
/// bounded for the image as a whole (each layer is bounded on its own).
#[derive(Debug, Default)]
pub struct ImageBudget {
    entries: u64,
    tarsplit: u64,
}

impl ImageBudget {
    /// Count a layer; an error if the image goes over the budget.
    pub fn add(&mut self, layer: &LayerDone) -> ImageResult<()> {
        self.entries += layer.toc.entries.len() as u64;
        self.tarsplit += layer.tarsplit.len() as u64;
        if self.entries > MAX_IMAGE_TOC_ENTRIES || self.tarsplit > MAX_IMAGE_TARSPLIT {
            return Err(ImageError::Layer(
                "the layers of the image have too much metadata".into(),
            ));
        }
        Ok(())
    }
}

/// A layer that was pulled with its table of contents: the one of the
/// descriptor (`key` is its TOC), or a peer's index (`key` is the blob).
fn layer_done(layer: &OciDescriptor, key: LayerKey, p: chunked::Pulled) -> LayerDone {
    let toc_z = match p.toc_z {
        Some(toc_z) => toc_z,
        None => stored::json_z(&p.toc),
    };
    LayerDone {
        key,
        blob: layer.digest,
        diff_id: p.diff_id,
        size: layer.size,
        toc: Arc::new(p.toc),
        files: p.files,
        chunks: p
            .chunks
            .into_iter()
            .map(|c| ChunkLocation {
                chunk_digest: c.chunk_digest,
                file_digest: c.file_digest,
                offset: c.offset,
                size: c.size,
            })
            .collect(),
        report: p.report,
        tarsplit: p.tarsplit,
        toc_z,
        lazy: false,
        blob_checked: false,
        checked: Default::default(),
    }
}

/// Pull one layer and check it against `diff_id`.  A layer whose
/// descriptor has zstd:chunked labels is pulled through the TOC they name
/// and stored by it, or not at all: it is never read as a tar stream, whose
/// view of the filesystem may not be the table's.  Only a layer without
/// the labels is pulled whole, and is the layer of its blob ([`LayerKey`]).
pub async fn pull_layer(
    ctx: &PullCtx,
    source: &Source,
    layer: &OciDescriptor,
    diff_id: &Digest,
    progress: Arc<dyn Fn(u64) + Send + Sync>,
) -> ImageResult<LayerDone> {
    let whole = LayerKey::Whole(layer.digest);
    // (a source that is not a registry gives no ranges: `pull_whole` and
    // `stream::ingest` refuse the layers that have a table)
    if let (Source::Registry(target), Some(info)) = (source, chunked::parse_info(layer)?) {
        let p = progress.clone();
        let key = LayerKey::Toc(info.checksum);
        let toc_ctx = ctx.clone().with_layer(key);
        let pulled = chunked::pull(&toc_ctx, target, layer, &info, diff_id, move |n| p(n)).await?;
        return Ok(layer_done(layer, key, pulled));
    }
    // a layer with no table of contents, through the fetchers: one
    // unpacks it, the replay proves it
    if let (Source::Registry(_) | Source::Path, Some(_), true) =
        (source, &ctx.staged, ctx.sink.proves_in_fetch())
    {
        // (only the registry fetcher, whose workers hash the blob, for one
        // the store has by its blob for another diff id: the blob, hashed,
        // says which is right)
        let registry_only = ctx.db.get_layer(&whole).await.is_ok();
        let p = progress.clone();
        let (pulled, by_registry) =
            chunked::pull_whole(ctx, registry_only, layer, diff_id, move |n| p(n)).await?;
        // (every file was measured here; the blob was hashed by the
        // origin's workers, which the index of a source did not: it is not
        // the blob's proof)
        let mut done = layer_done(layer, whole, pulled);
        done.blob_checked = by_registry;
        return Ok(done);
    }
    let p = progress.clone();
    let ingested = stream::ingest(ctx, Some(source), layer, diff_id, move |n| p(n)).await?;
    Ok(whole_done(layer, ingested))
}

/// The layer of a blob read whole, as [`stream::ingest`] made it.
pub fn whole_done(layer: &OciDescriptor, ingested: stream::Ingested) -> LayerDone {
    LayerDone {
        key: LayerKey::Whole(layer.digest),
        blob: layer.digest,
        diff_id: ingested.diff_id,
        size: layer.size,
        toc: ingested.toc.clone(),
        files: ingested.files,
        chunks: Vec::new(),
        // the whole blob, checked against its digest; not what the user's
        // own source had
        blob_checked: true,
        checked: Default::default(),
        report: ingested.report,
        tarsplit: ingested.tarsplit,
        toc_z: stored::json_z(&ingested.toc),
        lazy: false,
    }
}

/// Fetch the files the sink of `ctx` wants of a zstd:chunked layer whose
/// verified `meta` is known, and nothing else: the layer is not replayed, the
/// sink is read back by the engine to prove the diff id, which `done` carries as
/// claimed (nothing here proved it).
pub async fn pull_layer_files(
    ctx: &PullCtx,
    target: &Target,
    layer: &OciDescriptor,
    meta: chunked::Metadata,
    diff_id: &Digest,
    progress: Arc<dyn Fn(u64) + Send + Sync>,
) -> ImageResult<LayerDone> {
    let info = chunked::parse_info(layer)?
        .ok_or_else(|| ImageError::Layer("the layer is not zstd:chunked".into()))?;
    let key = LayerKey::Toc(info.checksum);
    let ctx = ctx.clone().with_layer(key);
    let p = chunked::complete_layer(&ctx, Some(target), layer, meta, 0, diff_id, move |n| {
        progress(n)
    })
    .await?;
    Ok(layer_done(layer, key, p))
}

/// Pull one layer, fetching only its metadata if it is a zstd:chunked layer
/// (its files are fetched on demand, see [`lazy`]; it is the layer of its
/// TOC, which nothing proves against a diff id yet); other layers are
/// pulled as [`pull_layer`] does.  `found` is the metadata of the layer when
/// the caller fetched it already ([`lazy::pull_metadata`]).
pub async fn pull_layer_lazy(
    ctx: &PullCtx,
    source: &Source,
    layer: &OciDescriptor,
    diff_id: &Digest,
    progress: Arc<dyn Fn(u64) + Send + Sync>,
    found: Option<lazy::Found>,
) -> ImageResult<LayerDone> {
    if let Source::Registry(_) = source {
        let found = match found {
            Some(f) => Some(f),
            None => lazy::pull_metadata(ctx, layer).await?,
        };
        // (a lazy pull is lazy or nothing: no layer of it is pulled
        // whole instead)
        let Some((info, l)) = found else {
            return Err(ImageError::Layer(format!(
                "{}: not pulled lazily: it is not a zstd:chunked layer",
                layer.digest
            )));
        };
        return Ok(LayerDone {
            key: LayerKey::Toc(info.checksum),
            blob: layer.digest,
            diff_id: *diff_id,
            size: layer.size,
            toc: l.toc,
            files: Vec::new(),
            chunks: Vec::new(),
            report: l.report,
            tarsplit: l.tarsplit,
            toc_z: l.toc_z,
            lazy: true,
            blob_checked: false,
            checked: Default::default(),
        });
    }
    pull_layer(ctx, source, layer, diff_id, progress).await
}

/// Publish the lazy layer `done` in the staging area: its table of contents
/// (the table as it came, `done.toc_z`) and tar-split, and what its fetches
/// need to reach its registry.  `erofs` and `owners` are those of the image made of its
/// table of contents.  It is durable and named when `barrier` commits.
pub fn stage_layer(
    area: &staged::Staging,
    barrier: &mut staged::Barrier,
    done: &LayerDone,
    registry_ref: Option<&str>,
    reach: velarx_db::LayerReach,
    (erofs, owners): (&str, &str),
) -> ImageResult<()> {
    area.publish_layer_in(
        &staged::NewLayer {
            meta: staged::StagedLayerMeta {
                key: done.key.to_string(),
                blob: done.blob.to_string(),
                size: done.size,
                registry_ref: registry_ref.map(str::to_string),
                reach,
                erofs: erofs.to_string(),
                owners: owners.to_string(),
                created_at: chrono::Utc::now().to_rfc3339(),
            },
            tarsplit: &done.tarsplit,
            toc_z: &done.toc_z,
        },
        barrier,
    )
    .map_err(ImageError::Io)
}

/// The rows to record for a layer that is complete, whatever made it (a
/// lazy layer is staged, not recorded, until it is: [`stage_layer`]), with
/// the size of its uncompressed tar from its tar-split: a tar-split that does
/// not give it is no layer to record.  A layer known by its table of
/// contents whose files are the table's alone (a lazy layer completed: no
/// pull walked its stream, nothing proved it) is recorded as verified by
/// that table and nothing more: no diff id (a push that must upload it recreates
/// the stream and checks it then), its files those the table gives
/// fs-verity digests to.
pub fn layer_commit(done: &LayerDone, registry_ref: Option<&str>) -> ImageResult<LayerCommit> {
    let size_error = |e: &dyn std::fmt::Display| {
        ImageError::Layer(format!("layer {}: the size of its tar: {e}", done.key))
    };
    let stream_size = crate::layer::reproduce::stream_size(&done.toc, &done.tarsplit)
        .map_err(|e| size_error(&e))
        .and_then(|n| i64::try_from(n).map_err(|e| size_error(&e)))?;
    let now = chrono::Utc::now().to_rfc3339();
    let mut counts: HashMap<String, (i64, u64)> = HashMap::new();
    if done.files.is_empty() {
        for e in &done.toc.entries {
            if !e.has_content() {
                continue;
            }
            if let Some(d) = e.verity() {
                counts.entry(d).or_insert((0, e.size)).0 += 1;
            }
        }
    }
    for f in &done.files {
        counts.entry(f.digest.clone()).or_insert((0, f.size)).0 += 1;
    }
    let (mut refs, mut files) = (Vec::new(), Vec::new());
    for (digest, (count, size)) in counts {
        files.push(FileRecord {
            digest: digest.clone(),
            size: size as i64,
            created_at: now.clone(),
            checked: done.checked.contains(&digest),
        });
        refs.push((digest, count));
    }
    // (a layer of a table of contents is verified by its table, whichever
    // way it was pulled: no diff id before a recreation of its stream
    // checks one)
    let proven = !done.key.is_toc();
    Ok(LayerCommit {
        record: LayerRecord {
            key: done.key,
            blob: Some(done.blob),
            diff_id: proven.then_some(done.diff_id),
            other_diff_id: None,
            size: done.size,
            status: "ready".to_string(),
            created_at: now,
            registry_ref: registry_ref.map(str::to_string),
            erofs: None,
            owners: None,
            stream_size: Some(stream_size),
        },
        files,
        refs,
        chunks: done.chunks.clone(),
        toc_digest: done.toc_digest(),
        tarsplit: done.tarsplit_digest(),
        blob_checked: done.blob_checked && proven,
        sealed: false,
    })
}

#[cfg(test)]
mod layer_commit_tests {
    use super::*;
    use velarx_types::digest::Algorithm;

    fn done(key: LayerKey) -> LayerDone {
        LayerDone {
            key,
            blob: Digest::of(Algorithm::Sha256, b"blob"),
            diff_id: Digest::of(Algorithm::Sha256, b"stream"),
            size: 4,
            toc: Arc::new(Toc {
                version: velarx_storage::TOC_VERSION,
                entries: Vec::new(),
                tar_split_digest: None,
            }),
            files: Vec::new(),
            chunks: Vec::new(),
            report: Default::default(),
            tarsplit: bytes::Bytes::from(zstd::encode_all(&b""[..], 0).unwrap()),
            toc_z: bytes::Bytes::from_static(b"table"),
            lazy: false,
            blob_checked: true,
            checked: Default::default(),
        }
    }

    /// A layer of a table of contents is recorded with no diff id and its blob
    /// unchecked, whichever way it was pulled and whatever the pull says of
    /// its blob: only a layer pulled whole is held to its diff id (a push
    /// that has to upload a layer of a table recreates the stream and must
    /// find the diff id of the configuration).
    #[test]
    fn a_layer_of_a_table_is_recorded_with_no_diff_id_and_its_blob_unchecked() {
        let blob = Digest::of(Algorithm::Sha256, b"blob");
        let toc = layer_commit(&done(LayerKey::Toc(blob)), None).unwrap();
        assert_eq!(toc.record.diff_id, None);
        assert!(!toc.blob_checked);
        let whole = layer_commit(&done(LayerKey::Whole(blob)), None).unwrap();
        assert_eq!(
            whole.record.diff_id,
            Some(Digest::of(Algorithm::Sha256, b"stream"))
        );
        assert!(whole.blob_checked);
    }
}

#[cfg(test)]
mod limit_tests {
    #[test]
    fn the_inflation_is_relative_to_the_blob() {
        let l = super::Limits::from_config(&velarx_config::PullConfig::default());
        let max = l.max_layer_bytes;
        assert_eq!(l.inflate_cap(-1), max);
        assert_eq!(l.inflate_cap(10), (64u64 << 20).min(max));
        assert_eq!(l.inflate_cap(1 << 40), max);
        assert!(l.inflate_cap(100 << 20) <= max);
    }
}

#[cfg(test)]
mod zstd_window_tests {
    use std::io::{Read, Write};

    fn frame(window_log: u32) -> Vec<u8> {
        let mut e = zstd::stream::write::Encoder::new(Vec::new(), 3).unwrap();
        e.set_parameter(zstd::stream::raw::CParameter::WindowLog(window_log))
            .unwrap();
        e.write_all(&[7u8; 4096]).unwrap();
        e.finish().unwrap()
    }

    #[test]
    fn a_frame_asking_for_a_big_window_is_refused() {
        let mut out = Vec::new();
        super::zstd_decoder(&frame(20)[..])
            .unwrap()
            .read_to_end(&mut out)
            .unwrap();
        assert_eq!(out.len(), 4096);
        let mut out = Vec::new();
        assert!(super::zstd_decoder(&frame(30)[..])
            .unwrap()
            .read_to_end(&mut out)
            .is_err());
    }
}

#[cfg(test)]
mod budget_tests {
    use super::*;

    fn layer(entries: usize, tarsplit: usize) -> LayerDone {
        LayerDone {
            key: LayerKey::Whole(Digest::empty(Algorithm::Sha256)),
            blob: Digest::empty(Algorithm::Sha256),
            diff_id: Digest::empty(Algorithm::Sha256),
            size: 0,
            toc: Arc::new(velarx_storage::Toc {
                version: 1,
                entries: vec![velarx_fuse::dir_entry("d"); entries],
                tar_split_digest: None,
            }),
            files: Vec::new(),
            chunks: Vec::new(),
            report: LayerReport::default(),
            tarsplit: vec![0; tarsplit].into(),
            toc_z: bytes::Bytes::new(),
            blob_checked: false,
            checked: Default::default(),
            lazy: false,
        }
    }

    /// A view of an image read from a mount keeps no more names than an
    /// image may have entries.
    #[test]
    fn a_mounted_image_keeps_the_entries_an_image_may_have() {
        assert_eq!(
            velarx_fuse::mounted::MAX_NODES as u64,
            MAX_IMAGE_TOC_ENTRIES
        );
    }

    #[test]
    fn the_metadata_of_an_image_is_bounded() {
        let mut b = ImageBudget::default();
        let one = layer((MAX_IMAGE_TOC_ENTRIES / 2) as usize, 10);
        b.add(&one).unwrap();
        b.add(&one).unwrap();
        assert!(b.add(&layer(1, 0)).is_err());
        let mut b = ImageBudget::default();
        assert!(b.add(&layer(0, MAX_IMAGE_TARSPLIT as usize + 1)).is_err());
    }
}

#[cfg(test)]
mod key_tests {
    use super::*;

    /// A key of a file is the hash of its content or the name of its
    /// object, in either algorithm; anything else is none.  The algorithm
    /// of a key is the one of its layer, whichever kind it is.
    #[test]
    fn a_key_has_the_algorithm_of_its_digest() {
        for alg in Algorithm::ALL {
            let content = Digest::of(alg, b"x").to_string();
            let object = crate::sha256_text(b"x");
            assert_eq!(key_algorithm(&content), Some(alg));
            assert_eq!(key_algorithm(&object), Some(Algorithm::Sha256));
            let verity = velarx_storage::fsverity_digest_of(alg, b"x");
            assert_eq!(key_algorithm(&verity), Some(alg));
            assert!(is_file_key(&content) && is_file_key(&verity));
        }
        for bad in [
            "",
            "sha256",
            "md5:00",
            "fsverity-sha512-16:00",
            "sha256:xyz",
        ] {
            assert_eq!(key_algorithm(bad), None, "{bad}");
        }
    }
}

/// The least a download must bring, as `config` says.
pub fn min_speed(config: &velarx_config::PullConfig) -> velarx_registry::speed::Speed {
    velarx_registry::speed::Speed::new(
        config.min_speed_kib.saturating_mul(1024),
        config.min_speed_secs,
    )
}
