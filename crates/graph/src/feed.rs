// SPDX-License-Identifier: Apache-2.0
//! The pull seam: what the engine offers a storage driver during a pull
//! ([`PullFeed`]), what the driver gives back to receive it ([`Incoming`]),
//! and the pull of the drivers that keep their store in this process
//! ([`pull_in_process`]).
//!
//! The engine owns the network: the registry, the peers and the sources, the
//! merge of the ranges of a request by their cost, the decompression and the
//! checks of every chunk against the digests of the table of contents.  The
//! driver owns the store: it says what it lacks ([`Incoming::wants`], which
//! for composefs and vfs is [`Session::have`], asked for each file as the
//! plan of the layer is made) and it receives the bytes in the files of its
//! own staging session (`Stage`).  A driver
//! whose store is not the engine's files (the `varlink` driver) implements
//! [`Incoming`] with files it hands over and answers the same questions
//! from the other side of a socket.
//!
//! The flow of [`StorageDriver::pull`]:
//!
//! 1. the driver opens its pull ([`PullFeed::begin`]: the engine holds a
//!    hold on it while it lives);
//! 2. it asks the feed for each layer ([`PullFeed::fetch`], at most
//!    [`PullFeed::parallel`] at a time): the feed plans what the driver
//!    wants, merges the ranges, fetches, verifies and gives the bytes to
//!    [`Incoming`]; what it returns is the layer pulled and verified
//!    ([`LayerDone`]);
//! 3. the feed ends ([`PullFeed::finish`]: the helpers of the engine that
//!    handled what the registry sent are gone, and the engine holds the
//!    store for the commit);
//! 4. the driver verifies what it pulled and knows what each file is to be
//!    named by (`settle`), naming nothing yet;
//! 5. the engine's check sees the settled layers ([`Settled`]): it computes
//!    the identity of each (`velarx_fuse::layer_erofs`), checks the manifest
//!    against it and hands the identities, with the images it made them
//!    from, back to the driver; a pull it refuses leaves nothing in the
//!    store;
//! 6. the driver makes what it pulled durable with two barriers, a `syncfs`
//!    of the staging and one of the store once the files are named (never
//!    more, and none of the engine's), names the
//!    files by what they hold (the commit of the session) and stores the
//!    identities (composefs writes the images the engine made: they are not
//!    built twice) and records what it made ([`Pulled::artifacts`]); what
//!    only the engine needs of the check ([`Verdict`]) goes back in
//!    [`Pulled::verdict`].
//!
//! All the layers of the image are in the pull, those the driver has marked
//! ([`FeedLayer::stored`]): which layers the store has is the engine's
//! question to the driver (`has_layers`).
//! [`PullFeed::index`] shows a driver the table of contents of a layer when
//! it wants to plan itself; the in-process drivers do not use it (the plan
//! is made by the engine from the table of contents it has to fetch anyway).

use crate::{DriverError, DriverResult, LayerArtifact};
use async_trait::async_trait;
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tracing::{info, warn};
use velarx_content::pull::net::Net;
use velarx_content::pull::session::Session;
use velarx_content::pull::sink::{FilesSink, Finished, Sink};
pub use velarx_content::pull::LayerDone;
use velarx_content::pull::{self, Have, ImageBudget, Limits, PullCtx};
use velarx_db::Database;
use velarx_fuse::layer_erofs::LayerImage;
use velarx_storage::{FileStore, Toc, VerityMode};
use velarx_types::digest::{Algorithm, Digest};
use velarx_types::{ImageError, ImageResult, LayerKey, OciDescriptor};

/// A layer the pull is to bring into the store.
#[derive(Debug, Clone)]
pub struct FeedLayer {
    /// The key the engine looks the layer up by: what its descriptor asks
    /// for.
    pub key: LayerKey,
    /// The descriptor of its blob in the manifest.
    pub descriptor: OciDescriptor,
    /// The diff id the configuration of the image says it has.
    pub diff_id: Digest,
    /// The OCI ChainID of the layer as the top of its image's stack
    /// (`velarx_types::chain_ids`), the engine's: a chained driver
    /// (`Capabilities::layer_chain`) keys the layer on it, the others ignore
    /// it.
    pub chain_id: Digest,
    /// The chain id of the layer below it in the image, none for the first:
    /// the one the layer is made on.
    pub parent: Option<Digest>,
    /// The driver already has the layer (`StorageDriver::has_layers`): it is
    /// in the list so that every layer knows its parent when only some are
    /// missing, and nothing of it is fetched.
    pub stored: bool,
}

/// The table of contents of a layer and its compressed tar-split, verified
/// against the digests the descriptor vouches for.
#[derive(Debug, Clone)]
pub struct LayerIndex {
    /// The key the layer is stored under: the one it was asked by.
    pub key: LayerKey,
    pub toc: Arc<Toc>,
    /// The zstd compressed tar-split.
    pub tarsplit: bytes::Bytes,
    /// What the file `toc.zst` of the layer holds: the table as the registry
    /// sent it, when the layer is pulled by it, else the zstd of the JSON of
    /// `toc`.
    pub toc_z: bytes::Bytes,
}

/// What the driver gives the feed to receive a pull: what it wants, and where
/// the bytes go.
pub trait Incoming: Send + Sync {
    /// Whether the driver lacks the file known by `key` (the fs-verity digest
    /// of its content as the table of contents gives it, or the hash of its
    /// content), of `size` bytes: the feed fetches what is wanted, and only
    /// that.  Called on a thread that may block, each time the plan of a
    /// layer meets a file (the driver may need to copy it from a read-only
    /// store to say it has it).
    fn wants(&self, key: &str, size: u64) -> bool;

    /// The id of this pull: what the engine's hold on it is named by, and
    /// what a driver whose store is in another process calls the pull
    /// (`BeginPull`).  A random id made for each attempt (a v4 UUID, 122
    /// random bits: [`new_pull_id`], or for a driver of the engine's process
    /// the name of its staging session, `pull-` and a v4 UUID), never one that
    /// another pull, in this process or in
    /// another on the same store, can have: a driver takes a known id for the
    /// resume of the pull that has it, so an id that was reused would resume
    /// someone else's pull.  Only the engine that made it reuses it, to
    /// resume.
    fn pull_id(&self) -> String;

    /// Where the bytes of the files go: the staging session of a driver of
    /// this process (named by what they are known by, moved into the store at
    /// the commit), or the files a driver hands over (`Sink::place`: the file
    /// and the offset it chose for a key, and no proof of the diff id here:
    /// the engine reads the layer back from the driver,
    /// [`Sink::proves_in_fetch`]).
    fn sink(&self) -> &Arc<dyn Sink>;
}

/// A new pull id: 122 random bits as 32 hex digits.
pub fn new_pull_id() -> String {
    velarx_base::random::token()
}

/// Whether `id` can be a pull id ([`new_pull_id`]) or the name of a staging
/// session (`pull-` and a v4 uuid): what a driver accepts as the name of a pull.
pub fn is_pull_id(id: &str) -> bool {
    let hex = id.strip_prefix("pull-").unwrap_or(id);
    let digits: String = hex.chars().filter(|c| *c != '-').collect();
    digits.len() == 32 && digits.bytes().all(|b| b.is_ascii_hexdigit())
}

/// The [`Incoming`] of a driver that has its store in this process: it wants
/// what the session does not hold whole (`Session::holds`: the store, or what
/// an earlier layer of the pull staged), and the bytes go to the session.
pub struct SessionIncoming(Arc<Session>, Arc<dyn Sink>);

impl SessionIncoming {
    pub fn of(session: Arc<Session>) -> Arc<dyn Incoming> {
        let sink: Arc<dyn Sink> = session.clone();
        Arc::new(Self(session, sink))
    }
}

impl Incoming for SessionIncoming {
    fn wants(&self, key: &str, size: u64) -> bool {
        !self.0.holds(key, size)
    }

    fn pull_id(&self) -> String {
        self.0.name()
    }

    fn sink(&self) -> &Arc<dyn Sink> {
        &self.1
    }
}

/// The [`Incoming`] of a driver with files of its own: it wants the keys that
/// have a place in its [`FilesSink`], and the bytes go there.
pub struct FilesIncoming {
    pull: String,
    sink: Arc<dyn Sink>,
    files: Arc<FilesSink>,
}

impl FilesIncoming {
    pub fn of(pull: &str, files: Arc<FilesSink>) -> Arc<dyn Incoming> {
        let sink: Arc<dyn Sink> = files.clone();
        Arc::new(Self {
            pull: pull.to_string(),
            sink,
            files,
        })
    }
}

impl Incoming for FilesIncoming {
    fn wants(&self, key: &str, _size: u64) -> bool {
        self.files.wants(key)
    }

    fn pull_id(&self) -> String {
        self.pull.clone()
    }

    fn sink(&self) -> &Arc<dyn Sink> {
        &self.sink
    }
}

/// An [`Incoming`] that wants the files of a set of keys and nothing else,
/// whatever its session has: what a driver that has planned its pull itself
/// (from [`PullFeed::index`]) says.  A file it does not want must be one it
/// has (the layer is checked against its diff id).
pub struct Wanted {
    session: Arc<Session>,
    sink: Arc<dyn Sink>,
    keys: HashSet<String>,
}

impl Wanted {
    pub fn of(session: Arc<Session>, keys: HashSet<String>) -> Arc<dyn Incoming> {
        let sink: Arc<dyn Sink> = session.clone();
        Arc::new(Self {
            session,
            sink,
            keys,
        })
    }
}

impl Incoming for Wanted {
    fn wants(&self, key: &str, _size: u64) -> bool {
        self.keys.contains(key)
    }

    fn pull_id(&self) -> String {
        self.session.name()
    }

    fn sink(&self) -> &Arc<dyn Sink> {
        &self.sink
    }
}

/// What the engine offers a driver during a pull.
#[async_trait]
pub trait PullFeed: Send + Sync {
    /// The driver opened its pull in `into`: the engine takes what it holds
    /// for a pull (the hold, named by [`Incoming::pull_id`], that pins the
    /// layers and keeps the staging directory from a sweep).  Before any other
    /// call.  A feed that cannot receive the bytes in `into` refuses here,
    /// naming the reason.
    async fn begin(&self, into: &Arc<dyn Incoming>) -> ImageResult<()>;

    /// How many layers the driver asks for at the same time.
    fn parallel(&self) -> usize;

    /// The verified table of contents and tar-split of a layer: the one its
    /// descriptor vouches for when it has one, else the one the engine makes
    /// by reading the layer whole (a gzip layer, one the engine made itself:
    /// a commit, a build step, an import), keeping its files for the
    /// `fetch` that follows.  None for a lazy pull, whose layers are not
    /// read, and for a layer that cannot be pulled lazily
    /// ([`PullFeed::why_not_lazy`]).
    async fn index(&self, layer: &FeedLayer) -> ImageResult<Option<LayerIndex>>;

    /// The pull is a lazy one (`--lazy`): a layer comes as its staged
    /// metadata, and its files when they are read or when the pull is
    /// completed.
    fn is_lazy(&self) -> bool {
        false
    }

    /// Why a layer of a lazy pull cannot be pulled lazily (it is not a
    /// zstd:chunked layer, or its table of contents gives no fs-verity
    /// digest for a file), or none when it can.  After `begin`; the metadata
    /// it fetches is kept for the `fetch` of the layer.
    async fn why_not_lazy(&self, _layer: &FeedLayer) -> ImageResult<Option<String>> {
        Ok(Some("the pull is not a lazy one".into()))
    }

    /// Fetch what `into` wants of a layer: the engine plans it, merges the
    /// ranges by cost, fetches from the sources and peers first, checks every
    /// chunk, writes the files into `into`, and checks the layer against its
    /// diff id.  The layer is never fetched twice by one pull.
    async fn fetch(&self, layer: &FeedLayer, into: &Arc<dyn Incoming>) -> ImageResult<LayerDone>;

    /// The driver has every file of the layer that it lacks: what the engine
    /// keeps to serve the layer's `fetch` (the spool of a layer read whole)
    /// goes, and a `fetch` of the layer after it is an error.  A layer that
    /// keeps nothing, and one released twice, are no error.
    fn release(&self, _layer: &FeedLayer) {}

    /// The driver asked for every layer: the engine's helpers are stopped
    /// before the files are named by what they hold, and the engine takes
    /// the store for the commit.
    async fn finish(&self) -> ImageResult<()>;

    /// The pull is over, whatever the way it ended: the feed lets go of the
    /// pull (the staging session the driver opened goes with its last holder).
    fn end(&self);
}

/// Prove the diff id of a pulled layer by reading it back from the driver that
/// stores it: the tar stream is rebuilt from the layer's table of contents and
/// tar-split with the bytes of its files that [`StorageDriver::read_objects`]
/// gives, and hashed.  This is the proof of a driver that is not in the
/// engine's process: what the proof must show is what the driver *stored*, not
/// what the engine fetched, so the engine's replay of the fetch cannot stand in
/// for it.  Call it on the layers of a pull after the driver staged them (the
/// keys of the table of contents are settled) and before the layers are
/// published.  A layer whose files are not all there yet (a lazy one) cannot be
/// proved, and is refused.  Blocks: call it on a thread that may.
pub fn prove_by_read_back(
    driver: Arc<dyn crate::StorageDriver>,
    layer: &LayerDone,
) -> DriverResult<()> {
    let objects = Arc::new(crate::DriverObjects::new(Arc::clone(&driver)));
    prove_with(driver.name(), objects, layer)
}

/// [`prove_by_read_back`] with the objects read by `objects`: for a driver
/// that reads the objects a pull staged, which it has not committed yet,
/// with the id of the pull (a client of a driver in another process).
pub fn prove_with(
    name: &str,
    objects: Arc<dyn velarx_storage::ObjectOpener>,
    done: &LayerDone,
) -> DriverResult<()> {
    use std::io::Read;
    if done.lazy {
        return Err(DriverError::storage(
            name,
            format!(
                "the layer {} is lazy: its files are not stored yet",
                done.key
            ),
        ));
    }
    let mut stream =
        velarx_content::layer::reproduce::stream(&done.toc, done.tarsplit.clone(), objects)
            .map_err(|e| DriverError::io(name, e))?;
    let mut hasher = velarx_types::digest::DigestWriter::for_digest(&done.diff_id);
    let mut buf = vec![0u8; 256 * 1024];
    loop {
        let n = stream.read(&mut buf).map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => {
                DriverError::missing(name, Some(&done.key), e, crate::Remedy::PullAgain)
            }
            std::io::ErrorKind::InvalidData => {
                DriverError::corrupt(name, e, crate::Remedy::PullAgain)
            }
            _ => DriverError::io(name, e),
        })?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let actual = hasher.finalize();
    if actual != done.diff_id {
        return Err(DriverError::corrupt(
            name,
            format!(
                "the layer {} read back from the driver hashes to {actual}, its diff id is {}",
                done.key, done.diff_id
            ),
            crate::Remedy::PullAgain,
        ));
    }
    Ok(())
}

/// What the engine makes of the settled layers, and gives the driver to
/// store: the identity of each layer (made from its table of contents, for
/// every driver) and the image it made it from.
#[derive(Default)]
pub struct Identities {
    pub artifacts: HashMap<LayerKey, LayerArtifact>,
    /// The EROFS image of a layer, as the identity digests it: a driver that
    /// keeps the images writes these, never building them: the engine made
    /// one for every layer it pulled.
    pub images: HashMap<LayerKey, LayerImage>,
}

/// The engine's check of a pull, called by the driver after every layer is
/// staged and proven and **before it publishes** anything (on a thread that
/// may block): it sees the layers, may refuse the pull (nothing of it is
/// visible then: `has_layers` reports none of its layers, a refusal is never
/// an orphan commit), and hands the driver the identities.  The second
/// argument says where the bytes of an object of the layers are, by its
/// fs-verity digest (the files of the pull are not named in the store yet).
pub type Settled = Box<
    dyn FnOnce(
            &mut Vec<LayerDone>,
            &dyn Fn(&str) -> Option<std::path::PathBuf>,
        ) -> ImageResult<Settlement>
        + Send,
>;

/// The id of one check of one pull: the engine makes it for the pull, its
/// check seals the [`Verdict`] with it, and the engine opens only a verdict
/// sealed with it.  The driver never sees it (the check holds its copy and
/// the verdict does not show it), so a driver cannot make the verdict of a
/// check that did not run, change one, or hand back the verdict of another
/// pull.
#[derive(Clone, PartialEq, Eq)]
pub struct CheckId([u8; 16]);

impl CheckId {
    /// A new id, of no other check.
    pub fn fresh() -> Self {
        CheckId(velarx_base::random::bytes16())
    }
}

/// What the engine's check concluded of the image.
pub struct Checked {
    /// The key of each layer of the image (a layer whose table of contents
    /// could not be used is the layer of its blob).
    pub layer_keys: Vec<LayerKey>,
    /// The merged EROFS of a complete image.
    pub merged_id: Option<(Algorithm, String)>,
    /// The images of the layers the store had.
    pub stored_erofs: HashMap<LayerKey, Option<String>>,
    /// The identity of each layer pulled, as the engine made it: what the
    /// driver records is checked against it.
    pub ours: HashMap<LayerKey, LayerArtifact>,
}

/// What the engine's check concluded, sealed with the id of the check.  The
/// driver cannot read it or change it, nor make one the engine opens: it
/// carries it back with what it pulled ([`Pulled::verdict`]), so that a pull
/// cannot end without the check having been made (there is no `Verdict` to
/// put in a [`Pulled`] otherwise), and the engine opens it where it needs it.
pub struct Verdict {
    check: CheckId,
    checked: Checked,
}

impl Verdict {
    /// The verdict of the check `check`.
    pub fn sealed(check: &CheckId, checked: Checked) -> Self {
        Verdict {
            check: check.clone(),
            checked,
        }
    }

    /// What the check concluded, if this is the verdict of `check` (`None`
    /// for the verdict of any other).
    pub fn open(self, check: &CheckId) -> Option<Checked> {
        (self.check == *check).then_some(self.checked)
    }
}

/// What the engine's check gives back: the identities for the driver to
/// record, and the verdict for the engine.
pub struct Settlement {
    pub identities: Identities,
    pub verdict: Verdict,
}

/// What [`StorageDriver::pull`] gives back.
pub struct Pulled {
    /// The layers pulled, settled, in the order they were completed.
    pub layers: Vec<LayerDone>,
    /// What the driver recorded of each.
    pub artifacts: HashMap<LayerKey, LayerArtifact>,
    /// What the engine's check concluded, handed back as the driver got it.
    pub verdict: Verdict,
}

/// The progress a [`ContentFeed`] reports for a layer.
pub type ProgressFn = Arc<dyn Fn(&FeedLayer, u64) + Send + Sync>;
/// The call when a layer is done.
pub type CompleteFn = Arc<dyn Fn(&FeedLayer, &LayerDone) + Send + Sync>;

/// The feed of the engine's pull code (`velarx_content::pull`): the layers
/// come from the fetchers of the pull, by the registry's ranges when they are
/// chunked, or were made here (a build) and are given with
/// [`ContentFeed::made`].
pub struct ContentFeed {
    net: Net,
    db: Database,
    limits: Limits,
    /// The fetcher that brings the files of layers with a table
    /// of contents
    staged: Option<Arc<pull::staged_fetch::StagedFetch>>,
    lazy: bool,
    progress: Option<(u64, ProgressFn)>,
    complete: Option<CompleteFn>,
    /// The context of the pull, made when the driver opens it and dropped
    /// when it ends
    ctx: Mutex<Option<PullCtx>>,
    /// The verified metadata of the layers the driver asked the index of: a
    /// driver that fetches by sets of files asks for the same layer many
    /// times, and its table of contents is fetched once
    metadata: Mutex<HashMap<String, pull::chunked::Metadata>>,
    /// The metadata of the lazy layers [`PullFeed::why_not_lazy`] fetched,
    /// by the digest of their blob: the `fetch` of the layer uses it
    lazy_found: Mutex<HashMap<String, pull::lazy::Found>>,
    /// The layers read whole, by the digest of their blob: their files wait in a spool for
    /// the fetches of the files the driver lacks
    spooled: Mutex<HashMap<String, Arc<Spooled>>>,
    /// The layers the driver released (`PullFeed::release`), by the digest
    /// of their blob: what is asked of them after is refused, not read again
    released: Mutex<HashSet<String>>,
}

/// A layer with no table of contents, read whole: what the engine made of it
/// and the files it kept.
struct Spooled {
    spool: Arc<dyn LocalContent>,
    ingested: pull::stream::Ingested,
    /// What the file `toc.zst` of the layer holds
    toc_z: bytes::Bytes,
    /// The blob was hashed to its digest (by the registry fetcher's workers,
    /// or as the engine read it)
    blob_checked: bool,
    /// The key and size of each file with content, once each
    keys: Vec<(String, u64)>,
    /// The session the layer was made in (a build): a pull of this process
    /// takes the staged files from it
    made: Option<Arc<Session>>,
}

impl Spooled {
    fn of(
        spool: Arc<dyn LocalContent>,
        ingested: pull::stream::Ingested,
        blob_checked: bool,
    ) -> Self {
        let mut seen = HashSet::new();
        let keys = ingested
            .files
            .iter()
            .filter(|f| seen.insert(f.digest.as_str()))
            .map(|f| (f.digest.clone(), f.size))
            .collect();
        Self {
            spool,
            toc_z: pull::stored::json_z(&ingested.toc),
            ingested,
            blob_checked,
            keys,
            made: None,
        }
    }

    fn made(mut self, session: Arc<Session>) -> Self {
        self.made = Some(session);
        self
    }
}

impl LocalContent for Session {
    fn copy_to(
        &self,
        key: &str,
        to: &std::fs::File,
        to_at: u64,
        step: &mut dyn FnMut() -> std::io::Result<()>,
        hole: &mut dyn FnMut(u64, u64),
    ) -> std::io::Result<()> {
        let path = self.content_path(key).ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::NotFound, format!("{key} is not staged"))
        })?;
        let file = std::fs::File::open(path)?;
        let size = file.metadata()?.len();
        velarx_storage::copy_region_holes(&file, 0, to, to_at, size, step, hole)
    }
}

/// Sets the flag when dropped: what a blocking copy checks to stop when the
/// call that asked for it was cancelled.
struct Stop(Arc<std::sync::atomic::AtomicBool>);

impl Drop for Stop {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Relaxed);
    }
}

impl ContentFeed {
    pub fn new(net: Net, db: Database, limits: Limits) -> Self {
        Self::with_spooled(net, db, limits, HashMap::new())
    }

    /// A feed of the layers a build made, each read once as it was made
    /// (its files are moved into the session of the pull, which commits them
    /// with the others).
    pub fn made(db: Database, limits: Limits, made: &[Arc<pull::Made>]) -> Self {
        let spooled = made
            .iter()
            .map(|m| {
                (
                    m.ingested.diff_id.to_string(),
                    Arc::new(
                        Spooled::of(m.session.clone(), m.ingested.clone(), true)
                            .made(m.session.clone()),
                    ),
                )
            })
            .collect();
        Self::with_spooled(Net::offline(), db, limits, spooled)
    }

    fn with_spooled(
        net: Net,
        db: Database,
        limits: Limits,
        spooled: HashMap<String, Arc<Spooled>>,
    ) -> Self {
        Self {
            net,
            db,
            limits,
            staged: None,
            lazy: false,
            progress: None,
            complete: None,
            ctx: Mutex::new(None),
            metadata: Mutex::default(),
            lazy_found: Mutex::default(),
            spooled: Mutex::new(spooled),
            released: Mutex::default(),
        }
    }

    /// The files of the layers with a table of contents come from the
    /// fetcher of `staged` (an eager pull).
    pub fn with_staged(mut self, staged: Arc<pull::staged_fetch::StagedFetch>) -> Self {
        self.staged = Some(staged);
        self
    }

    /// The lazy layers the engine accepted before the pull began (the
    /// metadata of each, verified), by the digest of the blob: not fetched
    /// again.
    pub fn with_lazy_found(self, found: HashMap<String, pull::lazy::Found>) -> Self {
        self.lazy_found
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .extend(found);
        self
    }

    /// Pull the chunked layers lazily: only their metadata (the files come on
    /// demand).
    pub fn lazy(mut self, lazy: bool) -> Self {
        self.lazy = lazy;
        self
    }

    /// `progress` gets the compressed bytes a layer fetched, each time it
    /// has `step` more, and `complete` the layer when it is done.
    pub fn with_progress(mut self, step: u64, progress: ProgressFn, complete: CompleteFn) -> Self {
        self.progress = Some((step, progress));
        self.complete = Some(complete);
        self
    }

    /// A layer the driver released is not read again for it: its `index` and
    /// `fetch` are refused.
    fn not_released(&self, layer: &FeedLayer) -> ImageResult<()> {
        let digest = layer.descriptor.digest.to_string();
        if self
            .released
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .contains(&digest)
        {
            return Err(ImageError::Storage(format!(
                "the layer {} was released by the storage driver: nothing is kept to fetch from",
                layer.key
            )));
        }
        Ok(())
    }

    /// The files `ctx` wants of a layer with a table of contents, into the
    /// files of its sink: the plan, the merge of the ranges, the fetch and the
    /// check of every chunk against the table of contents, and no replay of
    /// the layer (the diff id is proved by reading it back from the driver).
    async fn fetch_files(
        &self,
        ctx: &PullCtx,
        layer: &FeedLayer,
        report: Arc<dyn Fn(u64) + Send + Sync>,
    ) -> ImageResult<LayerDone> {
        if self.lazy {
            return Err(ImageError::Storage(
                "a lazy image is not pulled into the files of a storage driver".into(),
            ));
        }
        let cached = self
            .metadata
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&layer.descriptor.digest.to_string())
            .cloned();
        let meta = match cached {
            Some(m) => m,
            None => pull::chunked::layer_index(ctx, &layer.descriptor)
                .await?
                .ok_or_else(|| {
                    ImageError::Storage(format!(
                        "the layer {} has no table of contents, and was not read whole",
                        layer.key
                    ))
                })?,
        };
        // (the files of a call are written at the places the driver chose for
        // it: a file another call fetches is not in them)
        let ctx = ctx.clone().with_own_fetching();
        pull::pull_layer_files(&ctx, &layer.descriptor, meta, &layer.diff_id, report).await
    }

    /// Read a layer that has no table of contents whole: a fetcher of the
    /// pull unpacks it into its staging and the blob is checked there, the
    /// tar stream is replayed against the diff id, and the table of contents
    /// and the tar-split are made from the headers; the files wait for the
    /// driver to ask for the ones it lacks.
    async fn spool_whole(&self, ctx: &PullCtx, layer: &FeedLayer) -> ImageResult<LayerIndex> {
        let report = self.reporter(layer);
        // (the origin hands over every file: a driver copies the ones it
        // lacks from the staging)
        let unpacked =
            pull::chunked::unpack_whole(ctx, &layer.descriptor, &layer.diff_id, move |n| report(n))
                .await?;
        let w = unpacked.ingested;
        let ingested = pull::stream::Ingested {
            toc: w.toc,
            files: w.files,
            report: w.report,
            diff_id: w.diff_id,
            tarsplit: w.tarsplit,
        };
        let spool: Arc<dyn LocalContent> = Arc::new(HandedContent {
            copies: w.copies,
            _staging: unpacked.staging,
        });
        // (the workers of the origin hashed the blob)
        let spooled = Spooled::of(spool, ingested, true);
        let index = LayerIndex {
            key: LayerKey::Whole(layer.descriptor.digest),
            toc: spooled.ingested.toc.clone(),
            tarsplit: spooled.ingested.tarsplit.clone(),
            toc_z: spooled.toc_z.clone(),
        };
        self.spooled
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(layer.descriptor.digest.to_string(), Arc::new(spooled));
        Ok(index)
    }

    /// The files `into` wants of a layer read whole, from its spool into the
    /// files of its sink, each checked against its key before it is told
    /// whole.
    async fn fetch_spooled(
        &self,
        ctx: &PullCtx,
        layer: &FeedLayer,
        held: Arc<Spooled>,
        into: Arc<dyn Incoming>,
    ) -> ImageResult<LayerDone> {
        // (a layer made by a build in a session of this process is moved
        // into the session of the pull: no copy; a driver with files of its
        // own has them copied to the places it chose)
        let (files, bytes) = match (&held.made, ctx.sink.clone().session()) {
            (Some(made), Some(_)) => {
                let (made, sink, keys) = (made.clone(), ctx.sink.clone(), held.keys.clone());
                tokio::task::spawn_blocking(move || -> ImageResult<(u64, u64)> {
                    let other = sink.as_any().downcast_ref::<Session>().ok_or_else(|| {
                        ImageError::Storage("the sink of the pull is not a session".into())
                    })?;
                    let keep: HashSet<&str> = keys.iter().map(|(k, _)| k.as_str()).collect();
                    let moved: HashSet<String> =
                        made.transfer_into(other, &keep)?.into_iter().collect();
                    let bytes = keys
                        .iter()
                        .filter(|(k, _)| moved.contains(k))
                        .map(|(_, s)| s)
                        .sum();
                    Ok((moved.len() as u64, bytes))
                })
                .await
                .map_err(|e| ImageError::Layer(format!("the transfer of the files: {e}")))??
            }
            _ => {
                copy_wanted(
                    ctx.sink.clone(),
                    held.keys.clone(),
                    held.spool.clone(),
                    into,
                )
                .await?
            }
        };
        let total: u64 = held.keys.iter().map(|(_, s)| s).sum();
        // (what the layer read whole is: its table of contents and tar-split
        // are shared with the spool, not copied; a stage of this process
        // records the layer from it, a driver in another process was given
        // them with `Index` and takes only the report)
        let ingested = held.ingested.clone();
        let mut done = pull::whole_done(&layer.descriptor, ingested);
        done.blob_checked = held.blob_checked;
        done.report = pull::LayerReport {
            fetched_bytes: bytes,
            fetched_files: files,
            reused_bytes: total.saturating_sub(bytes),
            reused_files: (held.keys.len() as u64).saturating_sub(files),
            ..done.report
        };
        Ok(done)
    }

    /// The progress callback of a layer: the engine's, told each time it has
    /// `step` more compressed bytes.
    fn reporter(&self, layer: &FeedLayer) -> Arc<dyn Fn(u64) + Send + Sync> {
        match &self.progress {
            Some((step, progress)) => {
                let (step, progress, layer, last) = (
                    *step,
                    progress.clone(),
                    layer.clone(),
                    Arc::new(AtomicU64::new(0)),
                );
                Arc::new(move |n: u64| {
                    let prev = last.load(Ordering::Relaxed);
                    if n >= prev + step
                        && last
                            .compare_exchange(prev, n, Ordering::Relaxed, Ordering::Relaxed)
                            .is_ok()
                    {
                        progress(&layer, n);
                    }
                })
            }
            None => Arc::new(|_| {}),
        }
    }

    fn context(&self) -> ImageResult<PullCtx> {
        self.ctx
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
            .ok_or_else(|| ImageError::Storage("the pull was not begun".into()))
    }
}

#[async_trait]
impl PullFeed for ContentFeed {
    async fn begin(&self, into: &Arc<dyn Incoming>) -> ImageResult<()> {
        let sink = into.sink().clone();
        let mut ctx = PullCtx::new(self.net.clone(), sink, self.db.clone(), self.limits.clone());
        if let Some(staged) = &self.staged {
            ctx = ctx.with_staged(staged.clone());
        }
        *self.ctx.lock().unwrap_or_else(|e| e.into_inner()) = Some(ctx);
        Ok(())
    }

    fn parallel(&self) -> usize {
        self.limits.parallel_layers
    }

    fn is_lazy(&self) -> bool {
        self.lazy
    }

    async fn why_not_lazy(&self, layer: &FeedLayer) -> ImageResult<Option<String>> {
        let ctx = self.context()?;
        let digest = layer.descriptor.digest.to_string();
        if self
            .lazy_found
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .contains_key(&digest)
        {
            return Ok(None);
        }
        match pull::lazy::pull_metadata(&ctx, &layer.descriptor).await {
            Ok(Some(found)) => {
                self.lazy_found
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .insert(digest, found);
                Ok(None)
            }
            Ok(None) => Ok(Some("it is not a zstd:chunked layer".into())),
            Err(e) => Err(e),
        }
    }

    async fn index(&self, layer: &FeedLayer) -> ImageResult<Option<LayerIndex>> {
        let ctx = self.context()?;
        self.not_released(layer)?;
        if let Some(held) = self
            .spooled
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&layer.descriptor.digest.to_string())
        {
            return Ok(Some(LayerIndex {
                key: LayerKey::Whole(layer.descriptor.digest),
                toc: held.ingested.toc.clone(),
                tarsplit: held.ingested.tarsplit.clone(),
                toc_z: held.toc_z.clone(),
            }));
        }
        let Some(m) = pull::chunked::layer_index(&ctx, &layer.descriptor).await? else {
            if self.lazy {
                return Ok(None);
            }
            return self.spool_whole(&ctx, layer).await.map(Some);
        };
        let index = LayerIndex {
            key: layer.key,
            toc: m.stored.clone(),
            tarsplit: m.tarsplit_z.clone(),
            toc_z: m.toc_z.clone(),
        };
        self.metadata
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(layer.descriptor.digest.to_string(), m);
        Ok(Some(index))
    }

    async fn fetch(&self, layer: &FeedLayer, into: &Arc<dyn Incoming>) -> ImageResult<LayerDone> {
        let wants = into.clone();
        // (the files of this fetch: the same session for a driver of this
        // process, the places a driver chose for its wants otherwise)
        let ctx = self
            .context()?
            .with_sink(into.sink().clone())
            .with_have(Arc::new(move |key: &str, size| !wants.wants(key, size)) as Have);
        let report = self.reporter(layer);
        let spooled = || {
            self.spooled
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .get(&layer.descriptor.digest.to_string())
                .cloned()
        };
        let mut held = spooled();
        if held.is_none() {
            // (released while this fetch began: refused, not read again)
            self.not_released(layer)?;
        }
        if held.is_none() && !ctx.sink.proves_in_fetch() && !self.lazy {
            // (a driver that did not ask for the index: the layer is read now
            // if it has no table of contents)
            self.index(layer).await?;
            held = spooled();
        }
        let done = if let Some(held) = held {
            self.fetch_spooled(&ctx, layer, held, into.clone()).await?
        } else if !ctx.sink.proves_in_fetch() {
            self.fetch_files(&ctx, layer, report).await?
        } else if self.lazy {
            let found = self
                .lazy_found
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(&layer.descriptor.digest.to_string());
            pull::pull_layer_lazy(&ctx, &layer.descriptor, &layer.diff_id, found).await?
        } else {
            pull::pull_layer(&ctx, &layer.descriptor, &layer.diff_id, report).await?
        };
        if let Some(complete) = &self.complete {
            complete(layer, &done);
        }
        Ok(done)
    }

    fn release(&self, layer: &FeedLayer) {
        // (marked before the spool goes: a fetch that finds no spool finds
        // the mark)
        self.released
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(layer.descriptor.digest.to_string());
        // (the spool of the layer goes with its last holder: a copy in
        // progress holds it until it ends)
        self.spooled
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&layer.descriptor.digest.to_string());
    }

    async fn finish(&self) -> ImageResult<()> {
        // (the driver has every file of the layers read whole: their spools
        // go before the layers are read back)
        self.spooled
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
        Ok(())
    }

    fn end(&self) {
        // (the session of the pull goes with its last holder)
        *self.ctx.lock().unwrap_or_else(|e| e.into_inner()) = None;
        self.metadata
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
        self.released
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
        self.spooled
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
    }
}

/// Content the engine holds already, by the key of the file (its fs-verity
/// digest): what a fetch copies into the files of a driver that does not have
/// it.
pub trait LocalContent: Send + Sync {
    /// Copy the content of `key` to `to_at` of `to` (its holes stay holes);
    /// `step` is called between the pieces, and an error from it ends the
    /// copy; `hole(at, length)` is told of each hole.
    fn copy_to(
        &self,
        key: &str,
        to: &std::fs::File,
        to_at: u64,
        step: &mut dyn FnMut() -> std::io::Result<()>,
        hole: &mut dyn FnMut(u64, u64),
    ) -> std::io::Result<()>;
}

/// The files a fetcher handed over for a layer read whole, as the engine holds
/// them, by their key: the copy of each, in the session of the pull or in the
/// staging of the layer, which goes with it.
struct HandedContent {
    copies: HashMap<String, (std::path::PathBuf, u64, String)>,
    _staging: Arc<pull::staged_fetch::LayerStaging>,
}

impl LocalContent for HandedContent {
    fn copy_to(
        &self,
        key: &str,
        to: &std::fs::File,
        to_at: u64,
        step: &mut dyn FnMut() -> std::io::Result<()>,
        hole: &mut dyn FnMut(u64, u64),
    ) -> std::io::Result<()> {
        let (path, size, _) = self.copies.get(key).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("{key} was not handed over"),
            )
        })?;
        let file = std::fs::File::open(path)?;
        velarx_storage::copy_region_holes(&file, 0, to, to_at, *size, step, hole)
    }
}

/// The files of stores of the engine's (the pool of the staging area, the
/// engine's own objects), by their fs-verity digest: each is opened below the
/// store without following a link, and only a regular file is read.
pub struct StoreContent(pub Vec<Arc<FileStore>>);

impl LocalContent for StoreContent {
    fn copy_to(
        &self,
        key: &str,
        to: &std::fs::File,
        to_at: u64,
        step: &mut dyn FnMut() -> std::io::Result<()>,
        hole: &mut dyn FnMut(u64, u64),
    ) -> std::io::Result<()> {
        for store in &self.0 {
            let Some(file) = store.open_object(key) else {
                continue;
            };
            let file = file?;
            let size = file.metadata()?.len();
            return velarx_storage::copy_region_holes(&file, 0, to, to_at, size, step, hole);
        }
        Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("{key} is in none of the stores of the engine"),
        ))
    }
}

/// Copy the files of `keys` (key and size) that `into` wants from `content`
/// into the places its sink gives, each measured as written and checked
/// against its key before it is told whole.  The files copied and their bytes.
async fn copy_wanted(
    sink: Arc<dyn Sink>,
    keys: Vec<(String, u64)>,
    content: Arc<dyn LocalContent>,
    into: Arc<dyn Incoming>,
) -> ImageResult<(u64, u64)> {
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let _stop = Stop(stop.clone());
    tokio::task::spawn_blocking(move || -> ImageResult<(u64, u64)> {
        let mut cancelled = || {
            if stop.load(Ordering::Relaxed) {
                Err(std::io::Error::new(
                    std::io::ErrorKind::Interrupted,
                    "the fetch was cancelled",
                ))
            } else {
                Ok(())
            }
        };
        let (mut files, mut bytes) = (0u64, 0u64);
        for (key, size) in &keys {
            cancelled()?;
            if !into.wants(key, *size) {
                continue;
            }
            let place = sink.place(key, *size)?;
            // (the holes of the file stay holes; the driver is told, as it
            // is for a layer fetched by ranges)
            let told = &sink;
            content.copy_to(key, &place.file, place.base, &mut cancelled, &mut |at, len| {
                told.hole(key, at, len)
            })?;
            if let Some(actual) = sink.measure(key)? {
                if actual.to_string() != *key {
                    return Err(ImageError::Layer(format!(
                        "the file {key} of the layer reads back as {actual} from the place the storage driver gave"
                    )));
                }
            }
            sink.adopt(Finished {
                file: None,
                temp: None,
                key: key.clone(),
                name: key.clone(),
                size: *size,
                verity_keyed: false,
            })?;
            files += 1;
            bytes += size;
        }
        Ok((files, bytes))
    })
    .await
    .map_err(|e| ImageError::Layer(format!("the copy of the files of the layer: {e}")))?
}

/// The feed of a pull whose layers the engine has complete in its staging
/// area (a lazy pull being completed): the table of contents and tar-split of
/// each are the ones the pull checked against the manifest, and the files come
/// from `content`.  Nothing is fetched from the network, and what is copied is
/// measured in the places the driver gave, then proved again by the read-back
/// of the layer that the driver's pull ends with.
pub struct StagedFeed {
    layers: HashMap<LayerKey, LayerIndex>,
    content: Arc<dyn LocalContent>,
    parallel: usize,
}

impl StagedFeed {
    pub fn new(layers: Vec<LayerIndex>, content: Arc<dyn LocalContent>, parallel: usize) -> Self {
        Self {
            layers: layers.into_iter().map(|i| (i.key, i)).collect(),
            content,
            parallel,
        }
    }

    fn staged(&self, layer: &FeedLayer) -> ImageResult<&LayerIndex> {
        self.layers
            .get(&layer.key)
            .ok_or_else(|| ImageError::Layer(format!("the layer {} is not staged", layer.key)))
    }
}

#[async_trait]
impl PullFeed for StagedFeed {
    async fn begin(&self, _into: &Arc<dyn Incoming>) -> ImageResult<()> {
        Ok(())
    }

    fn parallel(&self) -> usize {
        self.parallel
    }

    async fn index(&self, layer: &FeedLayer) -> ImageResult<Option<LayerIndex>> {
        Ok(Some(self.staged(layer)?.clone()))
    }

    async fn fetch(&self, layer: &FeedLayer, into: &Arc<dyn Incoming>) -> ImageResult<LayerDone> {
        let index = self.staged(layer)?;
        let files = pull::stream::FileUse::of_toc(&index.toc);
        let mut seen = HashSet::new();
        let keys: Vec<(String, u64)> = files
            .iter()
            .filter(|f| seen.insert(f.digest.as_str()))
            .map(|f| (f.digest.clone(), f.size))
            .collect();
        let total: u64 = keys.iter().map(|(_, s)| s).sum();
        let (copied, bytes) = copy_wanted(
            into.sink().clone(),
            keys.clone(),
            self.content.clone(),
            into.clone(),
        )
        .await?;
        Ok(LayerDone {
            key: index.key,
            blob: layer.descriptor.digest,
            diff_id: layer.diff_id,
            size: layer.descriptor.size,
            toc: index.toc.clone(),
            files,
            chunks: Vec::new(),
            report: pull::LayerReport {
                fetched_bytes: bytes,
                fetched_files: copied,
                reused_bytes: total.saturating_sub(bytes),
                reused_files: (keys.len() as u64).saturating_sub(copied),
                ..Default::default()
            },
            tarsplit: index.tarsplit.clone(),
            lazy: false,
            blob_checked: false,
            checked: Default::default(),
            toc_z: index.toc_z.clone(),
        })
    }

    async fn finish(&self) -> ImageResult<()> {
        Ok(())
    }

    fn end(&self) {}
}

/// What a driver whose store is in this process pulls with.
pub struct InProcess<'a> {
    /// The name of the driver, for its errors.
    pub driver: &'a str,
    pub store: Arc<FileStore>,
    pub staging_dir: PathBuf,
    pub fsverity: VerityMode,
}

/// The layers of the list that a content keyed driver fetches: those it does
/// not have, each blob once (a descriptor whose TOC cannot be used is the
/// layer of its blob, and two blobs may name one TOC; the same layer twice in
/// an image is one fetch).  The chain ids of the others are of no use to it.
pub fn to_fetch(layers: &[FeedLayer]) -> impl Iterator<Item = &FeedLayer> {
    let mut seen = HashSet::new();
    layers
        .iter()
        .filter(|l| !l.stored)
        .filter(move |l| seen.insert((l.key, l.descriptor.digest)))
}

fn refused(driver: &str, e: ImageError) -> DriverError {
    DriverError::refused(driver, e)
}

/// The pull of a driver that keeps its store in this process (composefs,
/// vfs): the want of each file is `Session::have`, the bytes go to a staging
/// session, and what is pulled is committed with two barriers (a `syncfs`
/// before the files are moved into the store and one after, which makes the
/// names and what the driver writes in between durable).  The layers
/// come back settled, with the identities the engine's check made of them;
/// the driver stores those, and the verdict of the check goes back to the
/// engine with its [`Pulled`].
///
/// `write` runs once the files are linked, before the barrier of the store
/// (with the settled layers and the engine's identities): what it writes in
/// the store (the images of the layers) is made durable by that barrier and
/// has none of its own; it returns what the driver keeps of the pull and
/// whether it wrote anything.
pub async fn pull_in_process<R: Send + 'static>(
    parts: &InProcess<'_>,
    feed: &Arc<dyn PullFeed>,
    layers: &[FeedLayer],
    settled: Settled,
    write: Written<R>,
) -> DriverResult<(Vec<LayerDone>, Settlement, R)> {
    let result = pull_session(parts, feed, layers, settled, write).await;
    feed.end();
    result
}

/// What a driver writes in its store between the link of the files of a
/// pull and the barrier that makes them durable ([`pull_in_process`]).
pub type Written<R> =
    Box<dyn FnOnce(&[LayerDone], &mut Settlement) -> DriverResult<(R, bool)> + Send>;

async fn pull_session<R: Send + 'static>(
    parts: &InProcess<'_>,
    feed: &Arc<dyn PullFeed>,
    layers: &[FeedLayer],
    settled: Settled,
    write: Written<R>,
) -> DriverResult<(Vec<LayerDone>, Settlement, R)> {
    let name = parts.driver;
    let session = Session::create(&parts.staging_dir, parts.store.clone())
        .map_err(|e| DriverError::io(name, e))?;
    let into = SessionIncoming::of(session.clone());
    feed.begin(&into).await.map_err(|e| refused(name, e))?;

    // The layers to fetch, at most `parallel` at a time.
    let permits = Arc::new(Semaphore::new(feed.parallel().max(1)));
    let mut tasks: JoinSet<ImageResult<LayerDone>> = JoinSet::new();
    for layer in to_fetch(layers) {
        let (feed, into, layer, permits) =
            (feed.clone(), into.clone(), layer.clone(), permits.clone());
        tasks.spawn(async move {
            let _permit = permits
                .acquire_owned()
                .await
                .map_err(|_| ImageError::Layer("the pull was cancelled".into()))?;
            feed.fetch(&layer, &into).await
        });
    }
    let fetched = async {
        let mut pulled: Vec<LayerDone> = Vec::with_capacity(layers.len());
        let mut budget = ImageBudget::default();
        while let Some(joined) = tasks.join_next().await {
            let done = joined
                .map_err(|e| refused(name, ImageError::Layer(format!("layer task: {e}"))))?
                .map_err(|e| refused(name, e))?;
            budget.add(&done).map_err(|e| refused(name, e))?;
            let r = &done.report;
            info!(
                "Layer {}: fetched {} bytes in {} files, reused {} bytes in {} files",
                done.key, r.fetched_bytes, r.fetched_files, r.reused_bytes, r.reused_files
            );
            pulled.push(done);
        }
        Ok::<_, DriverError>(pulled)
    }
    .await;
    // (a refused layer ends the others: dropping the set aborts its tasks
    // but does not wait for them, and they hold the session, whose
    // directory is removed when the last of them is gone: the pull has
    // left nothing when it returns)
    tasks.abort_all();
    while let Some(joined) = tasks.join_next().await {
        // (the pull answers with its first refusal; a layer task that
        // panicked after it is still told)
        match joined {
            Err(e) if e.is_panic() => warn!("layer task of {name}: {e}"),
            _ => {}
        }
    }
    let pulled = fetched?;

    // Everything is verified: the feed's helpers are gone before the files
    // are named by what they hold; sync once, move the files into the store.
    feed.finish().await.map_err(|e| refused(name, e))?;
    let fsverity = parts.fsverity;
    let store = parts.store.clone();
    let driver = name.to_string();
    let done = tokio::task::spawn_blocking(move || {
        let verity = fsverity.manager();
        // (a file a fetcher staged that is not what its name says, or that
        // is gone: the transfer was complete and the file is not valid, the
        // pull fails)
        let failed = |e: std::io::Error| match e.kind() {
            std::io::ErrorKind::InvalidData => {
                refused(&driver, ImageError::Contradicted(e.to_string()))
            }
            _ => refused(
                &driver,
                ImageError::Storage(format!("cannot commit the pulled files: {e}")),
            ),
        };
        // Every staged file is verified first, once, and the engine's check
        // sees what each is to be named by and reads it where it is staged:
        // a pull it refuses names nothing in the store.  The commit that
        // follows only links, renames and syncs.
        let verified = session.verify(verity.as_ref()).map_err(failed)?;
        let (objects, staged) = verified.objects().map_err(failed)?;
        let objects: HashMap<String, velarx_storage::Object> =
            objects.into_iter().map(|c| (c.digest, c.object)).collect();
        let mut pulled = pulled;
        for l in &mut pulled {
            l.settle(&objects, &store)
                .map_err(|e| refused(&driver, e))?;
        }
        let at = |d: &str| staged.get(d).cloned().or_else(|| store.get_path(d));
        let mut settlement = settled(&mut pulled, &at).map_err(|e| refused(&driver, e))?;
        let mut write = Some(write);
        let mut written = None;
        let mut between = |_: &[velarx_content::pull::session::Committed]| {
            let Some(write) = write.take() else {
                return Err(std::io::Error::other("the commit wrote the pull twice"));
            };
            // (the table of contents and the tar-split of each layer, which
            // the barrier of the store makes durable with what the driver
            // writes: the rows that name the layers come after it)
            for l in pulled.iter().filter(|l| !l.lazy) {
                l.write_files(velarx_db::layer_files::root_of(store.root()))?;
            }
            match write(&pulled, &mut settlement) {
                Ok((r, wrote)) => {
                    written = Some(Ok(r));
                    Ok(wrote || pulled.iter().any(|l| !l.lazy))
                }
                Err(e) => {
                    written = Some(Err(e));
                    Err(std::io::Error::other("the pull was refused"))
                }
            }
        };
        let committed = session.commit_verified(verified, Some(&mut between));
        // (a barrier that failed after the images were written: nothing is
        // reported as pulled that is not on the disk)
        match (written, committed) {
            (Some(Err(e)), _) => Err(e),
            (Some(Ok(r)), Ok(_)) => Ok((pulled, settlement, r)),
            (_, Err(e)) => Err(failed(e)),
            (None, Ok(_)) => Err(refused(
                &driver,
                ImageError::Storage("the commit wrote nothing of the pull".to_string()),
            )),
        }
    })
    .await
    .map_err(|e| refused(name, ImageError::Storage(e.to_string())))??;
    Ok(done)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(n: u8) -> LayerKey {
        LayerKey::Whole(
            format!("sha256:{}", format!("{n:02x}").repeat(32))
                .parse()
                .unwrap(),
        )
    }

    /// A verdict opens only with the id of the check that sealed it: the
    /// verdict of another check (another pull, or one a driver made) does
    /// not.
    #[test]
    fn a_verdict_opens_only_for_its_check() {
        let checked = || Checked {
            layer_keys: vec![key(1)],
            merged_id: None,
            stored_erofs: HashMap::new(),
            ours: HashMap::new(),
        };
        let (a, b) = (CheckId::fresh(), CheckId::fresh());
        let opened = Verdict::sealed(&a, checked()).open(&a).expect("its own");
        assert_eq!(opened.layer_keys, vec![key(1)]);
        assert!(Verdict::sealed(&a, checked()).open(&b).is_none());
        assert!(Verdict::sealed(&b, checked()).open(&a).is_none());
    }

    /// The first layer of a pull is refused while the second never ends: the
    /// pull returns the refusal with the staging directory empty, the task
    /// of the second layer, which holds the session, already gone.
    #[test]
    fn a_refused_layer_leaves_no_session_when_the_pull_returns() {
        struct Refusing(std::sync::atomic::AtomicU64);
        #[async_trait]
        impl PullFeed for Refusing {
            async fn begin(&self, _: &Arc<dyn Incoming>) -> ImageResult<()> {
                Ok(())
            }
            fn parallel(&self) -> usize {
                2
            }
            async fn index(&self, _: &FeedLayer) -> ImageResult<Option<LayerIndex>> {
                Ok(None)
            }
            async fn fetch(&self, _: &FeedLayer, _: &Arc<dyn Incoming>) -> ImageResult<LayerDone> {
                if self.0.fetch_add(1, Ordering::Relaxed) == 0 {
                    return Err(ImageError::Layer("refused".into()));
                }
                std::future::pending().await
            }
            async fn finish(&self) -> ImageResult<()> {
                Ok(())
            }
            fn end(&self) {}
        }
        let dir = tempfile::tempdir().unwrap();
        let staging = dir.path().join("staging");
        let parts = InProcess {
            driver: "test",
            store: Arc::new(FileStore::new(dir.path().join("files")).unwrap()),
            staging_dir: staging.clone(),
            fsverity: VerityMode::Off,
        };
        let layer = |n: u8| {
            let d: Digest = format!("sha256:{}", format!("{n:02x}").repeat(32))
                .parse()
                .unwrap();
            FeedLayer {
                key: LayerKey::Whole(d),
                descriptor: OciDescriptor {
                    media_type: String::new(),
                    digest: d,
                    size: 0,
                    annotations: Default::default(),
                },
                diff_id: d,
                chain_id: d,
                parent: None,
                stored: false,
            }
        };
        let feed: Arc<dyn PullFeed> = Arc::new(Refusing(Default::default()));
        let settled: Settled = Box::new(|_, _| unreachable!("a refused pull is not settled"));
        // (the runtime lives until the end: it would drop the tasks it still
        // holds when it goes)
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let pulled = rt.block_on(pull_in_process(
            &parts,
            &feed,
            &[layer(1), layer(2)],
            settled,
            Box::new(|_, _| Ok(((), false))),
        ));
        assert!(pulled.is_err());
        assert_eq!(std::fs::read_dir(&staging).unwrap().count(), 0);
    }
}
