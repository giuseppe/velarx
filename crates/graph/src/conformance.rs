// SPDX-License-Identifier: Apache-2.0
//! The conformance suite of the storage drivers: the same behavioural tests
//! for every [`StorageDriver`].
//!
//! A driver registers itself with a factory, a closure that makes a driver
//! (and what the tests need to look at around it) on a scratch directory,
//! and the macro [`conformance_suite!`] makes one test of the test harness
//! for each case of this file:
//!
//! ```ignore
//! #[cfg(test)]
//! mod conformance {
//!     use velarx_graph::conformance::{conformance_suite, Factory, Subject};
//!     fn factory() -> Factory {
//!         Box::new(|dir| Box::pin(async move { Subject { /* the driver, its db and store, .. */ } }))
//!     }
//!     conformance_suite!(factory());
//! }
//! ```
//!
//! What the suite asks of a driver is the contract of the trait as the
//! engine uses it: it pulls layers and keeps them readable (byte for byte
//! as their diff id says), it answers `mounts` of the root and `image_view` for the
//! layers it has and a [`DriverError`] of the right kind for those it has
//! not, it collects and measures what it holds, it keeps the writable layer
//! of a container and says what the container changed in it as the tar of a
//! layer.  Every case begins with the capabilities of the driver: a case
//! whose subject the driver says it lacks asserts the error the contract
//! names (`Unsupported`), and a case that needs what the host does not give
//! (root, a kernel mount) says so and stops, it does not fail.  A skipped
//! case prints `SKIPPED conformance::<case>: why` (run the tests with
//! `-- --nocapture` to read them).
//!
//! The suite writes the content of a container's layer into the directory
//! `writable_paths(..).upper` of the driver, as the engine does (the files the
//! monitor mounts as the upper directory, and the engine's own files).  The
//! layer is made with the image it is of (`writable_create` gets the layers: a
//! driver that copies them copies them there), and what the container deletes
//! is a deletion in the way the driver's layer has one: `Subject::overlay_upper`
//! says the layer is an overlay's upper directory, where a deleted file is a
//! character device 0:0 and an opaque directory has `user.overlay.opaque`; else
//! the layer is a copy of the image, where the file is removed and the
//! directory made again, and `diff` says both as `.wh.` entries (an opaque
//! directory when none of the image's entries is left).  What the cases
//! take for every driver:
//!
//! - the identity of a layer is the engine's: it makes it from the table of
//!   contents, for every driver, and refuses a driver that records another.
//!   `LayerArtifact::erofs` is the digest of the EROFS image of the layer,
//!   made of its table of contents whether or not the driver keeps one, and
//!   `owners` the owners of its files, which push, a sealed manifest and the
//!   check of a start read (`the_identity_of_a_layer_is_a_property_of_the_layer`);
//! - the bytes of the stored objects are read back through the driver
//!   (`read_objects`, `open_object`): ranges of an object by its key, a
//!   `Missing` error for an object that is not there or a key that names
//!   none, `Corrupt` for one that is shorter than the index says;
//! - pulls at the same time of images that share a layer both complete, a cut
//!   pull takes nothing from the committed one, and every pull has an id of its
//!   own (`concurrent_pulls_of_a_shared_layer_both_complete`); the diff id of a
//!   pulled layer is proved by reading it back from the driver
//!   (`the_diff_id_is_proved_by_reading_back_from_the_driver`); a range larger
//!   than a pipe is read after its reply (`longcall::read_pipe_ranges`);
//! - a collection keeps what a live container (its writable layer) and a pull
//!   in progress use (`Keep::containers`, `Keep::pulls`);
//! - a kernel mount (the status says `kernel mount: yes`) is only for root;
//! - the root of a container is found by what `Subject::proc_root` makes of
//!   a `/proc/PID` directory: a mount table, or the link `root`;
//! - the objects of the `FileStore` the pull writes are the engine's to
//!   scan (`objects::objects`); `leftovers` names only the driver's own
//!   temporary files and `Usage::artifacts` what the driver made, with the
//!   state of an image (`Subject::image_state`) counted there;
//! - what `writable_create` and `image_volume_create` say a mount will be
//!   ([`Planned`]) is what `mounts` gives at every start
//!   (`the_plan_of_a_create_is_the_plan_of_every_start`);
//! - `max_layers` counts the driver's own layers, at most four of them;
//! - `writable_root` is a directory descriptor of the layer's root (an error
//!   for a layer that is not made), valid after its path is renamed, and the
//!   files written below it are the layer's (`writable_paths`, `changes`); a
//!   plan that names a descriptor (`MountFd`) has one, new at every call, and
//!   none names it otherwise (`rootfs_has_a_descriptor_when_the_plan_names_one`);
//! - the plans are of a container named by `request`: a driver whose root
//!   file system is a directory names that one.
//!
//! What the contract says for every driver, and the suite requires: a layer
//! the driver does not have is `Missing` with the remedy `PullAgain`; a
//! `size_limit` is honoured when `Capabilities::writable_size_limit` says so
//! and `Unsupported` (no layer left) when not; the size of a layer that was
//! never made is zero while its changes are errors.

pub use crate::forward;
pub mod registry;

use super::*;
use crate::forward_storage_driver;
use futures::future::BoxFuture;
use registry::Registry;
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::sync::Mutex;
use std::time::Duration;
use velarx_content::archive::{Archive, LAYER};
use velarx_content::pull::net::Net;
use velarx_content::pull::{layer_commit, LayerDone, Limits, Source};
use velarx_db::Database;
use velarx_fuse::view::VIEW_ROOT;
use velarx_storage::{FileStore, TocEntryType};
use velarx_types::digest::Digest;
use velarx_types::{ImageResult, OciDescriptor};

/// Makes a driver on a scratch directory (empty, not shared with another
/// test).
pub type Factory = Box<dyn Fn(PathBuf) -> BoxFuture<'static, Subject> + Send + Sync>;

/// Make the directory `/proc/PID` of a process (a scratch directory with what
/// the driver reads there) that of a process whose root is the layer
/// (`Some`: its paths) or another file system's (`None`).
pub type ProcRoot = Box<dyn Fn(&Path, Option<&WritablePaths>) + Send + Sync>;

/// Where the files of a container are on this host.
pub type WhereIs = Box<dyn Fn(&Writable) -> PathBuf + Send + Sync>;

/// A driver and what the cases look at around it.
pub struct Subject {
    pub driver: Arc<dyn StorageDriver>,
    /// The same stores, with the driver set to make the kernel mount what it
    /// can (None: it has no such mode).
    pub kernel: Option<Arc<dyn StorageDriver>>,
    pub db: Database,
    pub store: Arc<FileStore>,
    /// The staging area of the pulls of the store.
    pub staging: PathBuf,
    /// The scratch directory (the cases add their own files to it).
    pub dir: PathBuf,
    /// The writable layer is an overlay's upper directory (see the module).
    pub overlay_upper: bool,
    /// Damage the artifact the driver made of a layer so that `check` finds
    /// it; false when there is nothing to damage.
    pub damage: Box<dyn Fn(&LayerKey) -> bool + Send + Sync>,
    /// What a process of the container's root looks like in its `/proc`
    /// directory (an overlay's mount table, the root of a directory driver).
    pub proc_root: ProcRoot,
    /// Make the state the driver keeps of an image while its containers run
    /// (composefs: the startup profile its FUSE server records), which
    /// `remove_image` forgets and `collect` keeps for a kept image; false
    /// when the driver keeps none.
    pub image_state: Box<dyn Fn(&str) -> bool + Send + Sync>,
    /// The cases offer every layer as a zstd:chunked blob of a registry of
    /// their own, which the engine fetches by ranges (a storage service in
    /// another process asks for the files it lacks by their keys), and not as
    /// an archive read whole, which the engine reads into a spool of its own
    /// and gives the files of from there (the cases of the layers read whole
    /// offer those whatever this says).
    pub chunked_only: bool,
    /// The driver is in another process, over a socket: its roots are made at
    /// the create of the container and its `Mounts` answers for them, the
    /// layers it holds are its own (the engine's database does not change
    /// them), and the objects are not in `store`.
    pub remote: bool,
    /// Where the files of the writable layer of a container are on this
    /// host, for a driver whose `writable_paths` names none (a remote one:
    /// it hands the root over as a descriptor, and the cases read and write
    /// its files in place).
    pub upper: Option<WhereIs>,
    /// The directory of the container on this host that holds `upper`, for
    /// the same driver.
    pub bundle: Option<WhereIs>,
    /// What lives as long as the subject and is dropped with it, before the
    /// scratch directory goes: the server of a driver in another process.
    pub keep: Option<Box<dyn std::any::Any + Send + Sync>>,
}

/// What a case says when it stops for what the host lacks.
macro_rules! skip {
    ($case:expr, $($why:tt)*) => {{
        eprintln!("SKIPPED conformance::{}: {}", $case, format!($($why)*));
        return;
    }};
}

/// Root of the initial user namespace: the host's root, that can make
/// files of any owner and mount the layers with the kernel (root of a user
/// namespace, which a rootless driver runs in, is not).
fn is_root() -> bool {
    velarx_base::ids::rootful().unwrap_or(false)
}

fn ids() -> (u32, u32) {
    (
        rustix::process::geteuid().as_raw(),
        rustix::process::getegid().as_raw(),
    )
}

/// The subject of a case, or None (after saying why) when the driver cannot
/// work for the user running the tests.
async fn subject(f: &Factory, case: &str, tmp: &Path) -> Option<Subject> {
    let s = f(tmp.to_path_buf()).await;
    let c = s.driver.capabilities();
    if !c.rootless && !is_root() {
        eprintln!(
            "SKIPPED conformance::{case}: the driver {} says it needs root and this is not root",
            s.driver.name()
        );
        return None;
    }
    Some(s)
}

/// Another subject, on a directory of its own in the first one's.
async fn second(f: &Factory, s: &Subject, name: &str) -> Subject {
    let dir = s.dir.join(name);
    std::fs::create_dir_all(&dir).unwrap();
    f(dir).await
}

/// A case (or a part of one) that cannot apply to a driver in another process,
/// and why: the case stops, saying so.
macro_rules! remote_skip {
    ($s:expr, $case:expr, $($why:tt)*) => {
        if $s.remote {
            eprintln!("SKIPPED conformance::{}: {}", $case, format!($($why)*));
            return;
        }
    };
}

macro_rules! begin {
    ($f:expr, $case:expr) => {{
        let tmp = tempfile::tempdir().unwrap();
        let Some(s) = subject($f, $case, tmp.path()).await else {
            return;
        };
        (tmp, s)
    }};
}

mod volumes;
pub use volumes::*;

// Layers to pull

/// The tar of a layer, with the same times and owners every time.
struct Tar(tar::Builder<Vec<u8>>);

impl Tar {
    fn new() -> Self {
        Self(tar::Builder::new(Vec::new()))
    }

    fn header(kind: tar::EntryType, mode: u32, size: u64) -> tar::Header {
        let mut h = tar::Header::new_gnu();
        h.set_entry_type(kind);
        h.set_mode(mode);
        h.set_size(size);
        h.set_uid(0);
        h.set_gid(0);
        h.set_mtime(1_000_000);
        h
    }

    fn owned(mut self, name: &str, data: &[u8], uid: u64, gid: u64) -> Self {
        let mut h = Self::header(tar::EntryType::Regular, 0o644, data.len() as u64);
        h.set_uid(uid);
        h.set_gid(gid);
        self.0.append_data(&mut h, name, data).unwrap();
        self
    }

    fn dir(mut self, name: &str, mode: u32) -> Self {
        let mut h = Self::header(tar::EntryType::Directory, mode, 0);
        self.0
            .append_data(&mut h, format!("{name}/"), std::io::empty())
            .unwrap();
        self
    }

    fn file(mut self, name: &str, data: &[u8], mode: u32) -> Self {
        let mut h = Self::header(tar::EntryType::Regular, mode, data.len() as u64);
        self.0.append_data(&mut h, name, data).unwrap();
        self
    }

    fn symlink(mut self, name: &str, target: &str) -> Self {
        let mut h = Self::header(tar::EntryType::Symlink, 0o777, 0);
        self.0.append_link(&mut h, name, target).unwrap();
        self
    }

    fn hardlink(mut self, name: &str, target: &str) -> Self {
        let mut h = Self::header(tar::EntryType::Link, 0o644, 0);
        self.0.append_link(&mut h, name, target).unwrap();
        self
    }

    fn done(self) -> Vec<u8> {
        self.0.into_inner().unwrap()
    }
}

/// A file too big to be inlined in the image of a layer.
fn big() -> Vec<u8> {
    (0..20_000u32).map(|i| (i % 251) as u8).collect()
}

/// The lowest layer: directories, files, a link of each kind, a file that is
/// left empty, one of the size of an object.
fn base_layer() -> Vec<u8> {
    Tar::new()
        .dir("etc", 0o755)
        .dir("opt", 0o755)
        .dir("usr", 0o755)
        .dir("usr/lib", 0o755)
        .file("etc/os-release", b"base", 0o644)
        .file("etc/gone", b"will be deleted", 0o644)
        .file("etc/old", b"old content", 0o644)
        .file("etc/empty", b"", 0o600)
        .file("opt/x", b"x", 0o644)
        .file("usr/lib/big", &big(), 0o755)
        .symlink("etc/link", "os-release")
        .hardlink("etc/hard", "etc/os-release")
        .done()
}

/// The layer over it: a file that replaces one below, a file and a directory
/// that hide those below, one that is new.
fn top_layer() -> Vec<u8> {
    Tar::new()
        .dir("etc", 0o755)
        .dir("opt", 0o755)
        .dir("var", 0o700)
        .file("etc/os-release", b"top", 0o600)
        .file("etc/.wh.gone", b"", 0o644)
        .file("opt/.wh..wh..opq", b"", 0o644)
        .file("opt/y", b"y", 0o644)
        .file("var/new", b"new", 0o644)
        .done()
}

/// A layer pulled, stored by the driver and recorded, as the engine does it
/// after a pull.
struct Stored {
    key: LayerKey,
    tar: Vec<u8>,
    diff_id: Digest,
    desc: OciDescriptor,
    done: velarx_content::pull::LayerDone,
    artifact: LayerArtifact,
    /// The digests of its files in the store.
    objects: HashSet<String>,
}

/// The layer of `tar`: pulled from an archive of it through the feed (the
/// pull engine makes the table of contents, the tar-split and the files of
/// the store), stored by the driver, recorded in the database.
async fn store_layer(s: &Subject, tar: Vec<u8>) -> Stored {
    let offer = offer(s, &[&tar]).await;
    let mut pulled = offer.pull(s, engine_check()).await.expect("pull");
    let done = pulled.layers.remove(0);
    let artifact = pulled.artifacts[&done.key].clone();
    let mut commit = layer_commit(&done, None).unwrap();
    commit.record.erofs = Some(artifact.image_digest.clone());
    commit.record.owners = Some(artifact.owners.clone());
    s.db.commit_layers(vec![commit], vec![], vec![])
        .await
        .unwrap();
    Stored {
        key: done.key,
        diff_id: done.diff_id,
        objects: done.files.iter().map(|f| f.digest.clone()).collect(),
        tar,
        desc: offer.layers[0].descriptor.clone(),
        done,
        artifact,
    }
}

/// What the cases ask of the feed, and what they make it do.
#[derive(Default)]
struct Meddle {
    /// Layers (by blob digest) the feed is asked for, in order.
    asked: Mutex<Vec<Digest>>,
    /// The keys the driver said it wants, by layer blob.
    wanted: Mutex<HashMap<Digest, HashSet<String>>>,
    /// The chain id of each layer the feed is asked for, in order.
    chains: Mutex<Vec<Digest>>,
    /// The `n`th call of `fetch` (from 0) fails.
    fail_at: Mutex<Option<usize>>,
    /// Every call of `fetch` for this layer (by blob) fails.
    fail_layer: Mutex<Option<Digest>>,
    /// The layers come as lazy ones.
    lazy: std::sync::atomic::AtomicBool,
    /// How many times the driver ended the fetches (`finish`).
    finished: std::sync::atomic::AtomicUsize,
    /// The id of each pull the feed was begun for.
    pull_ids: Mutex<Vec<String>>,
}

/// The feed of the cases: each layer is an archive of its own, pulled by the
/// engine's pull code (`ContentFeed`); what the driver asks is counted.
struct ArchiveFeed {
    layers: Vec<(Digest, ContentFeed)>,
    meddle: Arc<Meddle>,
}

/// An [`Incoming`] that notes what the driver wants.
struct Noting {
    inner: Arc<dyn Incoming>,
    blob: Digest,
    meddle: Arc<Meddle>,
}

impl Incoming for Noting {
    fn wants(&self, key: &str, size: u64) -> bool {
        let wants = self.inner.wants(key, size);
        if wants {
            self.meddle
                .wanted
                .lock()
                .unwrap()
                .entry(self.blob)
                .or_default()
                .insert(key.to_string());
        }
        wants
    }

    fn pull_id(&self) -> String {
        self.inner.pull_id()
    }

    fn sink(&self) -> &Arc<dyn velarx_content::pull::sink::Sink> {
        self.inner.sink()
    }
}

#[async_trait::async_trait]
impl PullFeed for ArchiveFeed {
    async fn begin(&self, into: &Arc<dyn Incoming>) -> ImageResult<()> {
        self.meddle.pull_ids.lock().unwrap().push(into.pull_id());
        for (_, feed) in &self.layers {
            feed.begin(into).await?;
        }
        Ok(())
    }

    fn parallel(&self) -> usize {
        4
    }

    fn is_lazy(&self) -> bool {
        self.layers.iter().any(|(_, f)| f.is_lazy())
    }

    async fn why_not_lazy(&self, layer: &FeedLayer) -> ImageResult<Option<String>> {
        self.inner(layer).why_not_lazy(layer).await
    }

    async fn index(&self, layer: &FeedLayer) -> ImageResult<Option<LayerIndex>> {
        self.inner(layer).index(layer).await
    }

    async fn fetch(&self, layer: &FeedLayer, into: &Arc<dyn Incoming>) -> ImageResult<LayerDone> {
        let n = {
            let mut asked = self.meddle.asked.lock().unwrap();
            asked.push(layer.descriptor.digest);
            self.meddle.chains.lock().unwrap().push(layer.chain_id);
            asked.len() - 1
        };
        if *self.meddle.fail_at.lock().unwrap() == Some(n)
            || *self.meddle.fail_layer.lock().unwrap() == Some(layer.descriptor.digest)
        {
            return Err(ImageError::Registry("the feed was cut".into()));
        }
        let noting: Arc<dyn Incoming> = Arc::new(Noting {
            inner: into.clone(),
            blob: layer.descriptor.digest,
            meddle: self.meddle.clone(),
        });
        let mut done = self.inner(layer).fetch(layer, &noting).await?;
        done.lazy |= self.meddle.lazy.load(std::sync::atomic::Ordering::Relaxed);
        Ok(done)
    }

    fn release(&self, layer: &FeedLayer) {
        self.inner(layer).release(layer)
    }

    async fn finish(&self) -> ImageResult<()> {
        self.meddle
            .finished
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        for (_, feed) in &self.layers {
            feed.finish().await?;
        }
        Ok(())
    }

    fn end(&self) {
        for (_, feed) in &self.layers {
            feed.end();
        }
    }
}

impl ArchiveFeed {
    fn inner(&self, layer: &FeedLayer) -> &ContentFeed {
        &self
            .layers
            .iter()
            .find(|(d, _)| *d == layer.descriptor.digest)
            .expect("a layer of the offer")
            .1
    }
}

/// Give the layers their chain ids and parents, as the engine does for the
/// image they are the layers of (in this order).
fn set_chains(layers: &mut [FeedLayer]) {
    let diffs: Vec<Digest> = layers.iter().map(|l| l.diff_id).collect();
    let chains = velarx_types::chain_ids(&diffs);
    for (i, l) in layers.iter_mut().enumerate() {
        l.chain_id = chains[i];
        l.parent = i.checked_sub(1).map(|p| chains[p]);
    }
}

/// Layers as the engine offers them to a pull.
struct Offer {
    feed: Arc<ArchiveFeed>,
    layers: Vec<FeedLayer>,
    /// The registry the layers of a driver that takes only chunked ones are
    /// served by.
    _registry: Option<Registry>,
}

/// The layers `tars` as an offer: the archive of each in the directory of
/// the subject, the diff id the tar has.
async fn offer(s: &Subject, tars: &[&[u8]]) -> Offer {
    offer_with(s, tars, |_, diff_id| diff_id, |_, tar| tar.to_vec()).await
}

/// The same, with the diff id the configuration says of each layer made by
/// `diff_id` (index, the true one) and the bytes the registry gives for it
/// made by `bytes` (index, the blob's true ones).
async fn offer_with(
    s: &Subject,
    tars: &[&[u8]],
    diff_id: impl Fn(usize, Digest) -> Digest,
    bytes: impl Fn(usize, &[u8]) -> Vec<u8>,
) -> Offer {
    if s.chunked_only {
        let reg = Registry::start_blocking();
        let (mut layers, mut feeds) = (Vec::new(), Vec::new());
        for (i, tar) in tars.iter().enumerate() {
            let layer = chunked_layer_with(&reg, tar, |d| diff_id(i, d), |blob| bytes(i, blob));
            let feed = registry_feed(&reg, &s.db, &s.dir, &layer.0.descriptor, false).await;
            feeds.push((layer.0.descriptor.digest, feed));
            layers.push(layer.0);
        }
        set_chains(&mut layers);
        return Offer {
            feed: Arc::new(ArchiveFeed {
                layers: feeds,
                meddle: Arc::default(),
            }),
            layers,
            _registry: Some(reg),
        };
    }
    let (mut layers, mut feeds) = (Vec::new(), Vec::new());
    for (i, tar) in tars.iter().enumerate() {
        let blob = Digest::of(velarx_types::digest::Algorithm::Sha256, tar);
        let path = s.dir.join(format!("blob-{}-{i}", blob.hex()));
        std::fs::write(&path, bytes(i, tar)).unwrap();
        let desc = OciDescriptor {
            media_type: LAYER.to_string(),
            digest: blob,
            size: tar.len() as i64,
            annotations: Default::default(),
        };
        let archive = Archive::single(std::fs::File::open(&path).unwrap(), blob, tar.len() as u64);
        feeds.push((
            blob,
            ContentFeed::new(
                Net::offline(),
                Source::Archive(Arc::new(archive)),
                s.db.clone(),
                Limits::from_config(&velarx_config::PullConfig::default()),
            ),
        ));
        layers.push(FeedLayer {
            key: LayerKey::expected(&desc),
            descriptor: desc,
            diff_id: diff_id(i, blob),
            chain_id: diff_id(i, blob),
            parent: None,
            stored: false,
        });
    }
    set_chains(&mut layers);
    Offer {
        feed: Arc::new(ArchiveFeed {
            layers: feeds,
            meddle: Arc::default(),
        }),
        layers,
        _registry: None,
    }
}

impl Offer {
    /// The pull of every layer of the offer by the driver of `s`.
    async fn pull(&self, s: &Subject, settled: Settled) -> DriverResult<Pulled> {
        self.pull_layers(s, &self.layers, settled).await
    }

    /// The pull of some of them.
    async fn pull_layers(
        &self,
        s: &Subject,
        layers: &[FeedLayer],
        settled: Settled,
    ) -> DriverResult<Pulled> {
        let feed: Arc<dyn PullFeed> = self.feed.clone();
        s.driver.pull(&feed, layers, settled).await
    }

    /// The layers of the offer at `order` (an index may come twice: the
    /// same layer at two places) as the layers of one image: their chain ids
    /// and parents are those of that stack, none is stored.
    fn stack(&self, order: &[usize]) -> Vec<FeedLayer> {
        let mut layers: Vec<FeedLayer> = order.iter().map(|&i| self.layers[i].clone()).collect();
        set_chains(&mut layers);
        layers
    }

    /// The pull of `layers` by `driver`, which is not the subject's.
    async fn pull_by(
        &self,
        driver: &dyn StorageDriver,
        layers: &[FeedLayer],
        settled: Settled,
    ) -> DriverResult<Pulled> {
        let feed: Arc<dyn PullFeed> = self.feed.clone();
        driver.pull(&feed, layers, settled).await
    }

    fn meddle(&self) -> &Meddle {
        &self.feed.meddle
    }

    /// How many times the feed was asked for a layer.
    fn fetches(&self) -> usize {
        self.meddle().asked.lock().unwrap().len()
    }
}

/// What the engine makes of the layers a driver pulled: the identity of
/// each, from its table of contents, and the image it made it from.
fn engine_identities(pulled: &[LayerDone]) -> ImageResult<Identities> {
    let mut ids = Identities::default();
    for l in pulled {
        let image =
            velarx_fuse::layer_erofs::layer_image(&l.toc.entries).map_err(ImageError::Layer)?;
        let id = image
            .identity(l.key.digest().alg())
            .map_err(ImageError::Layer)?;
        ids.artifacts.insert(
            l.key,
            LayerArtifact {
                image_digest: id.erofs,
                owners: id.owners,
            },
        );
        ids.images.insert(l.key, image);
    }
    Ok(ids)
}

/// What a check that made `ids` of `pulled` concluded: the keys of the
/// layers, no merged image and none of the images a store had, and the
/// identities the engine made.
fn checked_of(ids: &Identities, pulled: &[LayerDone]) -> Checked {
    Checked {
        layer_keys: pulled.iter().map(|l| l.key).collect(),
        merged_id: None,
        stored_erofs: HashMap::new(),
        ours: ids.artifacts.clone(),
    }
}

/// What the check of the engine returns for `pulled` (a check nobody asks
/// the verdict of: its id is its own).
fn engine_settlement(pulled: &[LayerDone]) -> ImageResult<Settlement> {
    let identities = engine_identities(pulled)?;
    let verdict = Verdict::sealed(&CheckId::fresh(), checked_of(&identities, pulled));
    Ok(Settlement {
        identities,
        verdict,
    })
}

/// The engine's check when it has nothing to say: it makes the identities.
fn engine_check() -> Settled {
    Box::new(|pulled, _| engine_settlement(pulled))
}

fn img_digest() -> Digest {
    Digest::of(velarx_types::digest::Algorithm::Sha256, b"{}")
}

/// A lazy image is one being pulled: the pull `id` of `layers`, published
/// as the engine publishes it (the driver hands its image server the token
/// of the pull).
fn publish_pull(s: &Subject, id: &str, layers: &[String]) {
    velarx_content::pull::staged::Staging::new(&s.staging)
        .publish_pull(&velarx_content::pull::staged::StagedPull {
            id: id.to_string(),
            manifest_digest: img_digest(),
            config_digest: img_digest(),
            manifest: "{}".into(),
            config: "{}".into(),
            layers: layers.to_vec(),
            tags: vec![],
            digest_names: vec![],
            shareable: false,
            pulls: vec![],
            registry_ref: None,
            started_at: String::new(),
        })
        .unwrap();
}

/// The records the engine hands the driver for the layers of an image.
async fn records(s: &Subject, layers: &[&Stored]) -> Vec<LayerRecord> {
    let mut out = Vec::new();
    for l in layers {
        out.push(s.db.get_layer(&l.key).await.unwrap());
    }
    out
}

fn image(id: &str, layers: &[&Stored]) -> ImageRecord {
    let config = "{}".to_string();
    let manifest = serde_json::json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": {
            "mediaType": "application/vnd.oci.image.config.v1+json",
            "digest": Digest::of(velarx_types::digest::Algorithm::Sha256, config.as_bytes()),
            "size": config.len(),
        },
        "layers": layers.iter().map(|l| serde_json::to_value(&l.desc).unwrap()).collect::<Vec<_>>(),
    })
    .to_string();
    ImageRecord {
        id: id.to_string(),
        manifest_digest: Digest::of(velarx_types::digest::Algorithm::Sha256, manifest.as_bytes()),
        config_digest: Digest::of(velarx_types::digest::Algorithm::Sha256, config.as_bytes()),
        manifest,
        config,
        created_at: String::new(),
        is_lazy: false,
    }
}

fn request<'a>(image: &'a ImageRecord, layers: &'a [LayerRecord]) -> MountRequest<'a> {
    MountRequest {
        container: plan_writable(),
        purpose: Purpose::Root,
        image,
        layers,
        mapping: None,
        translate: Some(identity_translate()),
        idmap_mount: false,
        label: None,
        verity: VerityAsk::Off,
        volatile: false,
    }
}

/// How the owners of the files are shown when a case asks for no mapping: as
/// the ids this process has, and the owners it has none for as root (a driver
/// that serves the layers needs to be told; none refuses an owner it cannot
/// show).
pub(crate) fn identity_translate() -> &'static velarx_fuse::IdTranslate {
    static T: std::sync::OnceLock<velarx_fuse::IdTranslate> = std::sync::OnceLock::new();
    T.get_or_init(|| {
        let one = |id| {
            vec![velarx_proto::pod::IdMapping {
                container_id: 0,
                host_id: id,
                size: 1,
            }]
        };
        velarx_fuse::IdTranslate {
            uid: one(rustix::process::geteuid().as_raw()),
            gid: one(rustix::process::getegid().as_raw()),
            squash: true,
        }
    })
}

/// The tar stream of a layer, as the engine reads it back.
async fn open_layer(
    s: &Subject,
    key: &LayerKey,
    alg: Option<velarx_types::digest::Algorithm>,
) -> DriverResult<velarx_content::layer::reproduce::StoredLayer> {
    crate::objects::open_layer(s.driver.name(), &s.db, key, alg).await
}

/// [`open_layer`] for the layer of an image whose configuration gives the
/// diff id `expected` (a layer of a table of contents has none of its own).
async fn open_layer_for(
    s: &Subject,
    key: &LayerKey,
    expected: &velarx_types::digest::Digest,
) -> DriverResult<velarx_content::layer::reproduce::StoredLayer> {
    crate::objects::open_layer_expecting(s.driver.name(), &s.db, key, expected).await
}

/// The paths of the writable layer of a container: the driver's, or where a
/// driver in another process keeps it, which `Subject::upper` says.
fn paths(s: &Subject, w: &Writable) -> WritablePaths {
    match &s.upper {
        Some(upper) => {
            let dir = upper(w);
            WritablePaths {
                upper: dir.clone(),
                work: None,
                merged: dir,
            }
        }
        None => s.driver.writable_paths(w),
    }
}

/// The plan of the root `req` as a start gives it.  A driver that makes its
/// roots at the create of the container (a remote one: its `Mounts` answers
/// for a root it made) is asked to make it first, and one that mounts them
/// over the writable layer of the container (composefs) has the layer made,
/// where the subject is.
fn plan_of(s: &Subject, req: &MountRequest<'_>) -> DriverResult<Rootfs> {
    let own;
    let req = match req.container.id() == plan_writable().id() {
        true => {
            own = Writable::new(
                req.container.id(),
                s.dir.join("bundles").join(req.container.id()),
            );
            MountRequest {
                container: &own,
                ..req.clone()
            }
        }
        false => req.clone(),
    };
    if matches!(req.purpose, Purpose::Root) {
        if s.remote {
            s.driver.writable_create(
                req.container,
                Some(ids()),
                &WritableOptions::default(),
                Some(&req),
            )?;
        } else if !s.driver.writable_exists(req.container)? {
            // (its layer alone: what the image lacks is the error of the mount)
            s.driver.writable_create(
                req.container,
                Some(ids()),
                &WritableOptions::default(),
                None,
            )?;
        }
    }
    let r = rootfs_plan_of(&*s.driver, &req)?;
    check_server(&r);
    // a driver in another process never claims to enforce digests, or to
    // serve a mount: the engine cannot check what it did
    if s.remote {
        assert_eq!(
            r.verity,
            crate::VerityDone::None,
            "a remote driver enforces"
        );
        assert!(r.measured.is_empty() && r.server.is_none());
    }
    Ok(r)
}

/// What a process that serves a mount must be: a pidfd, of a mount the driver
/// hands over as a descriptor; a mount whose digests the process checks has
/// one.
pub(crate) fn check_server(r: &Rootfs) {
    if let Some(server) = &r.server {
        assert!(
            r.fd.is_some() && matches!(r.plan, RootfsPlan::MountFd(_)),
            "a server of what is no mount descriptor"
        );
        velarx_sys::pidfd::pid_of(server).expect("a pidfd of a live process");
    }
    assert!(
        r.verity != crate::VerityDone::OnOpen || r.server.is_some(),
        "digests checked on open, by no process"
    );
}

/// The answer of `mounts` for the root file system `req` alone.
fn rootfs_plan_of<T: StorageDriver + ?Sized>(
    driver: &T,
    req: &MountRequest<'_>,
) -> DriverResult<Rootfs> {
    driver
        .mounts(&MountsRequest {
            root: Some(req.clone()),
            volumes: Vec::new(),
        })?
        .root
        .ok_or_else(|| DriverError::storage(driver.name(), "the driver gave no root"))
}

/// The container the plans of the cases are of: a driver whose root file
/// system is a directory of the container names it in the plan (it need not
/// exist for a plan to be made).
fn plan_writable() -> &'static Writable {
    static W: std::sync::OnceLock<Writable> = std::sync::OnceLock::new();
    W.get_or_init(|| Writable::new("plan", "/velarx-conformance/bundles/plan"))
}

/// What a plan must be whatever the driver: one the monitor accepts and reads
/// back from the bundle as it was written.
fn check_plan(plan: &RootfsPlan) {
    match plan {
        RootfsPlan::Directory(d) => {
            // (what the monitor accepts: an absolute base, a relative way
            // down, no `.` or `..`)
            d.validate().unwrap_or_else(|why| panic!("{d:?}: {why}"));
        }
        RootfsPlan::MountFd(m) => {
            m.validate().unwrap_or_else(|why| panic!("{m:?}: {why}"));
        }
    }
    let bytes = plan.to_vec().unwrap();
    assert_eq!(&RootfsPlan::from_slice(&bytes).unwrap(), plan);
}

fn expect_err<T>(r: DriverResult<T>, what: &str) -> DriverError {
    match r {
        Ok(_) => panic!("{what}: expected an error"),
        Err(e) => e,
    }
}

/// The error says which driver it is of.
fn of_driver(s: &Subject, e: &DriverError) {
    assert_eq!(e.driver, s.driver.name(), "{e}");
}

// Capabilities, probe, status

pub async fn capabilities_are_consistent(f: &Factory) {
    let (_tmp, s) = begin!(f, "capabilities_are_consistent");
    let d = &s.driver;
    let c = d.capabilities();
    assert!(!d.name().is_empty() && !d.graph_name().is_empty());
    assert!(!c.verity.is_empty(), "a driver says what enforces verity");
    fn said_once<T: Copy + PartialEq>(p: Prefs<T>) -> bool {
        p.iter().collect::<Prefs<T>>() == p
    }
    assert!(
        said_once(c.verity)
            && said_once(c.root.idmap)
            && c.volume.is_none_or(|v| said_once(v.idmap)),
        "a capability is said once"
    );
    if let Some(n) = c.max_layers {
        assert!(n > 0);
    }
    // the suite and the engine read the layer the same way
    assert_eq!(
        s.overlay_upper, c.overlay_upper,
        "Subject::overlay_upper is Capabilities::overlay_upper"
    );
    // the capabilities are the same each time
    assert_eq!(d.capabilities(), c);
}

pub async fn status_is_stable_and_says_why(f: &Factory) {
    let (_tmp, s) = begin!(f, "status_is_stable_and_says_why");
    let d = &s.driver;
    let status = d.status();
    assert!(!status.is_empty());
    assert!(status.iter().all(|(k, _)| !k.is_empty()));
    assert_eq!(status, d.status(), "status is the same each time");
    // a driver that can mount in the kernel is only so as root
    if status
        .iter()
        .any(|(k, v)| k == "kernel mount" && v == "yes")
    {
        assert!(is_root(), "a kernel mount for a user that is not root");
    }
}

pub async fn rootless_driver_works_for_a_user(f: &Factory) {
    let (_tmp, s) = begin!(f, "rootless_driver_works_for_a_user");
    if is_root() {
        skip!(
            "rootless_driver_works_for_a_user",
            "this is root; the rootless run of the suite checks it"
        );
    }
    // `begin!` stopped for a driver that needs root: this one declared
    // itself rootless, and it must really make, read and remove with the
    // rights of a user
    assert!(s.driver.capabilities().rootless);
    let base = store_layer(&s, base_layer()).await;
    let layers = records(&s, &[&base]).await;
    s.driver.image_view("img", &layers).expect("a view");
    let w = Writable::new("c", s.dir.join("bundles/c"));
    s.driver
        .writable_create(&w, Some(ids()), &WritableOptions::default(), None)
        .expect("a writable layer");
    s.driver.writable_remove(&w).unwrap();
}

// Pull

pub async fn pull_makes_the_artifacts_of_the_layers(f: &Factory) {
    let (_tmp, s) = begin!(f, "pull_makes_the_artifacts_of_the_layers");
    let (base, top) = (base_layer(), top_layer());
    let offer = offer(&s, &[&base, &top]).await;
    let pulled = offer.pull(&s, engine_check()).await.unwrap();
    let keys: BTreeSet<&LayerKey> = pulled.layers.iter().map(|l| &l.key).collect();
    assert_eq!(keys.len(), 2);
    assert_eq!(pulled.artifacts.keys().collect::<BTreeSet<_>>(), keys);
    // (what the driver was asked is what it got: each layer once, under
    // the key it was asked by)
    assert_eq!(offer.fetches(), 2);
    let asked: BTreeSet<&LayerKey> = offer.layers.iter().map(|l| &l.key).collect();
    assert_eq!(asked, keys);
    for m in pulled.artifacts.values() {
        assert!(!m.image_digest.is_empty());
        // the owners are `[[uids], [gids]]`
        let owners: (Vec<u32>, Vec<u32>) = serde_json::from_str(&m.owners)
            .unwrap_or_else(|e| panic!("owners {:?}: {e}", m.owners));
        assert!(owners.0.contains(&0) && owners.1.contains(&0));
    }
    // nothing at all: nothing pulled, nothing made
    let before = s.driver.usage().unwrap();
    let none = offer.pull_layers(&s, &[], engine_check()).await.unwrap();
    assert!(none.layers.is_empty() && none.artifacts.is_empty());
    assert_eq!(offer.fetches(), 2, "no layer was asked for");
    assert_eq!(s.driver.usage().unwrap(), before);
}

/// What a push, a sealed manifest and the start check read of a layer is its
/// identity, a property of its table of contents: the digest of its EROFS
/// image (the one a manifest states for it) and its owners.  Every driver
/// records the same, whether or not it keeps an image of the layer (a driver
/// with no EROFS files records it all the same, or push says the layer has
/// no image recorded).
pub async fn the_identity_of_a_layer_is_a_property_of_the_layer(f: &Factory) {
    let (_tmp, s) = begin!(f, "the_identity_of_a_layer_is_a_property_of_the_layer");
    let base = store_layer(&s, base_layer()).await;
    let top = store_layer(&s, top_layer()).await;
    for l in [&base, &top] {
        let id =
            velarx_fuse::layer_erofs::layer_identity(l.key.digest().alg(), &l.done.toc.entries)
                .expect("the identity of the table of contents");
        assert_eq!(l.artifact.image_digest, id.erofs, "the digest of its image");
        assert_eq!(l.artifact.owners, id.owners, "its owners");
        // (the record the engine reads for a push, a sealed manifest and the
        // check of a start)
        let record = s.db.get_layer(&l.key).await.unwrap();
        assert_eq!(record.erofs.as_deref(), Some(id.erofs.as_str()));
        assert_eq!(record.owners.as_deref(), Some(id.owners.as_str()));
    }
    // the digest stated for it in a manifest is the one the driver made
    let mut desc = base.desc.clone();
    desc.annotations.insert(
        "io.containers.composefs.digest".into(),
        base.artifact.image_digest.clone(),
    );
    assert_eq!(
        desc.annotations["io.containers.composefs.digest"],
        s.db.get_layer(&base.key).await.unwrap().erofs.unwrap()
    );
    // and the layer is the same in the other store: nothing of the driver is
    // in it
    let other = second(f, &s, "other").await;
    let again = store_layer(&other, base_layer()).await;
    assert_eq!(again.artifact, base.artifact);
}

/// The same layer pulled again is the same layer: the same artifacts, and
/// nothing of the store changes.
pub async fn pull_is_idempotent(f: &Factory) {
    let (_tmp, s) = begin!(f, "pull_is_idempotent");
    let base = store_layer(&s, base_layer()).await;
    let before = s.driver.usage().unwrap();
    let again_offer = offer(&s, &[&base.tar]).await;
    let again = again_offer.pull(&s, engine_check()).await.unwrap();
    assert_eq!(again.artifacts[&base.key], base.artifact);
    assert_eq!(again.layers.len(), 1);
    assert_eq!(s.driver.usage().unwrap(), before);
    let layers = records(&s, &[&base]).await;
    s.driver.image_view("img", &layers).expect("still readable");
    // the same layer in another store makes the same artifact, if the
    // driver says it depends on the layer alone
    if !s.driver.capabilities().layer_chain {
        let other = second(f, &s, "other").await;
        let again = store_layer(&other, base_layer()).await;
        assert_eq!(
            again.artifact, base.artifact,
            "a layer's artifact is reproducible"
        );
    }
}

/// The staging areas of pulls that are left once the work in flight has
/// ended (a pull that failed lets go of its area when the last of its
/// threads is done: it is waited for a few seconds).
async fn no_staging_left(s: &Subject) -> Vec<std::path::PathBuf> {
    for _ in 0..100 {
        let left: Vec<_> = std::fs::read_dir(&s.staging)
            .map(|d| {
                d.flatten()
                    .filter(|e| e.file_name().to_string_lossy().starts_with("pull-"))
                    .map(|e| e.path())
                    .collect()
            })
            .unwrap_or_default();
        if left.is_empty() {
            return left;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    std::fs::read_dir(&s.staging)
        .map(|d| d.flatten().map(|e| e.path()).collect())
        .unwrap_or_default()
}

/// The bytes of a file of `n` bytes that do not compress, from `seed`.
fn random(seed: u64, n: usize) -> Vec<u8> {
    let mut x = seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1;
    (0..n)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x >> 24) as u8
        })
        .collect()
}

/// The layers of the chunked cases: the second has a file of the first and
/// one of its own.
fn chunked_layers() -> (Vec<u8>, Vec<u8>) {
    let first = Tar::new()
        .dir("usr", 0o755)
        .file("usr/f1", &random(1, 60_000), 0o644)
        .file("usr/f2", &random(2, 60_000), 0o644)
        .file("usr/f3", &random(3, 60_000), 0o644)
        .done();
    let second = Tar::new()
        .dir("usr", 0o755)
        .file("usr/f1", &random(1, 60_000), 0o644)
        .file("usr/f4", &random(4, 60_000), 0o644)
        .done();
    (first, second)
}

/// The zstd:chunked blob of the layer `tar`, served by `reg`: the layer as
/// the manifest describes it, and the size of the blob.
fn chunked_layer(reg: &Registry, tar: &[u8]) -> (FeedLayer, u64) {
    chunked_layer_with(reg, tar, |d| d, |b| b.to_vec())
}

/// The same, with the diff id the configuration says made by `diff_id` (from
/// the true one) and the bytes the registry serves made by `bytes` (from the
/// blob's true ones).
fn chunked_layer_with(
    reg: &Registry,
    tar: &[u8],
    diff_id: impl Fn(Digest) -> Digest,
    bytes: impl Fn(&[u8]) -> Vec<u8>,
) -> (FeedLayer, u64) {
    chunked_layer_made(reg, tar, true, diff_id, bytes)
}

/// The same, with the TOC of the blob giving the fs-verity digest of each
/// file (`verity`) or only the sha256 of its content, as a layer made by
/// containers/storage has it.
fn chunked_layer_made(
    reg: &Registry,
    tar: &[u8],
    verity: bool,
    diff_id: impl Fn(Digest) -> Digest,
    bytes: impl Fn(&[u8]) -> Vec<u8>,
) -> (FeedLayer, u64) {
    use velarx_content::layer::writer::Compression;
    registry_layer(reg, tar, Compression::ZstdChunked, verity, diff_id, bytes)
}

/// The zstd:chunked blob of the layer `tar` with the table of contents that
/// `edit` makes of its own (the descriptor vouches for the new one): what the
/// tar stream and the tar-split say is not changed.
fn chunked_layer_edited(
    reg: &Registry,
    tar: &[u8],
    edit: impl FnOnce(&mut serde_json::Value),
) -> FeedLayer {
    use velarx_content::layer::writer::{write_layer, Compression};
    let p = "io.github.containers.zstd-chunked.";
    let mut blob = Vec::new();
    let w = write_layer(
        tar,
        velarx_types::digest::Algorithm::Sha256,
        Compression::ZstdChunked,
        &mut blob,
    )
    .expect("a layer");
    let numbers = |name: &str| -> Vec<usize> {
        w.annotations[&format!("{p}{name}")]
            .split(':')
            .map(|x| x.parse().unwrap())
            .collect()
    };
    let pos = numbers("manifest-position");
    let ts = numbers("tarsplit-position");
    let mut toc: serde_json::Value =
        serde_json::from_slice(&zstd::decode_all(&blob[pos[0]..pos[0] + pos[1]]).unwrap()).unwrap();
    edit(&mut toc);
    let json = serde_json::to_vec(&toc).unwrap();
    let toc_z = zstd::encode_all(&json[..], 3).unwrap();
    let mut edited = blob[..pos[0]].to_vec();
    edited[pos[0] - 4..pos[0]].copy_from_slice(&(toc_z.len() as u32).to_le_bytes());
    edited.extend(&toc_z);
    edited.extend(&blob[pos[0] + pos[1]..]);
    let mut annotations = w.annotations.clone();
    annotations.insert(
        format!("{p}manifest-position"),
        format!("{}:{}:{}:1", pos[0], toc_z.len(), json.len()),
    );
    annotations.insert(
        format!("{p}manifest-checksum"),
        Digest::of(velarx_types::digest::Algorithm::Sha256, &toc_z).to_string(),
    );
    annotations.insert(
        format!("{p}tarsplit-position"),
        format!("{}:{}:{}", ts[0] + toc_z.len() - pos[1], ts[1], ts[2]),
    );
    let digest = Digest::of(velarx_types::digest::Algorithm::Sha256, &edited);
    reg.put(&digest.to_string(), edited.clone());
    let desc = OciDescriptor {
        media_type: w.media_type.to_string(),
        digest,
        size: edited.len() as i64,
        annotations: annotations.into_iter().collect(),
    };
    FeedLayer {
        key: LayerKey::expected(&desc),
        descriptor: desc,
        diff_id: w.diff_id,
        chain_id: w.diff_id,
        parent: None,
        stored: false,
    }
}

/// The same in the compression `compression`: a layer that is not
/// zstd:chunked has no table of contents to fetch by.
fn registry_layer(
    reg: &Registry,
    tar: &[u8],
    compression: velarx_content::layer::writer::Compression,
    verity: bool,
    diff_id: impl Fn(Digest) -> Digest,
    bytes: impl Fn(&[u8]) -> Vec<u8>,
) -> (FeedLayer, u64) {
    use velarx_content::layer::writer::{write_layer, write_layer_sha256_keyed};
    let write = if verity {
        write_layer::<&[u8], &mut Vec<u8>>
    } else {
        write_layer_sha256_keyed::<&[u8], &mut Vec<u8>>
    };
    let mut blob = Vec::new();
    let w = write(
        tar,
        velarx_types::digest::Algorithm::Sha256,
        compression,
        &mut blob,
    )
    .expect("a layer");
    let desc = OciDescriptor {
        media_type: w.media_type.to_string(),
        digest: w.digest,
        size: w.size as i64,
        annotations: w.annotations.into_iter().collect(),
    };
    reg.put(&w.digest.to_string(), bytes(&blob));
    let layer = FeedLayer {
        key: LayerKey::expected(&desc),
        descriptor: desc,
        diff_id: diff_id(w.diff_id),
        chain_id: diff_id(w.diff_id),
        parent: None,
        stored: false,
    };
    (layer, w.size)
}

/// The feed of the pull code of the layer `layer` of the registry `reg`,
/// through its registry fetcher (the staging of the layer beneath
/// `staging`).
async fn registry_feed(
    reg: &Registry,
    db: &Database,
    staging: &Path,
    layer: &OciDescriptor,
    lazy: bool,
) -> ContentFeed {
    let (staged, source) = reg.staged(staging, std::slice::from_ref(layer)).await;
    ContentFeed::new(
        Net::Offline,
        source,
        db.clone(),
        Limits::from_config(&velarx_config::PullConfig::default()),
    )
    .with_staged(staged)
    .lazy(lazy)
}

/// The layers `tars` as zstd:chunked blobs of the registry `reg`, offered to
/// a pull of `s` that gets them by ranges, and the size of each blob.
async fn chunked_offer(s: &Subject, reg: &Registry, tars: &[&[u8]]) -> (Offer, Vec<u64>) {
    let (mut layers, mut feeds, mut sizes) = (Vec::new(), Vec::new(), Vec::new());
    for tar in tars {
        let (layer, size) = chunked_layer(reg, tar);
        let feed = registry_feed(reg, &s.db, &s.dir, &layer.descriptor, false).await;
        feeds.push((layer.descriptor.digest, feed));
        sizes.push(size);
        layers.push(layer);
    }
    (
        Offer {
            feed: Arc::new(ArchiveFeed {
                layers: feeds,
                meddle: Arc::default(),
            }),
            layers,
            _registry: None,
        },
        sizes,
    )
}

/// The bytes the requests since `from` asked for, and how many requests.
fn asked_since(reg: &Registry, from: usize, size: u64) -> (u64, usize) {
    let all = reg.requests();
    let r = &all[from..];
    (r.iter().map(|r| r.bytes(size)).sum(), r.len())
}

/// A pull of layers the store has in part asks the feed for what it lacks
/// and for nothing else: the files of the store are not fetched again, a
/// layer the store has costs its metadata, and what is missing is asked of
/// the registry in as few requests as the merge of the ranges makes.  Every
/// driver asks the same, whatever it does with the bytes.
pub async fn a_chunked_pull_asks_only_for_what_the_store_lacks(f: &Factory) {
    let (_tmp, s) = begin!(f, "a_chunked_pull_asks_only_for_what_the_store_lacks");
    let reg = Registry::start().await;
    let (one, two) = chunked_layers();

    // the second layer in a store of its own: it fetches both its files,
    // each of them by one range of one request (they are next to each other)
    let cold_store = second(f, &s, "cold").await;
    let (cold_offer, sizes) = chunked_offer(&cold_store, &reg, &[&two]).await;
    let from = reg.requests().len();
    let cold = cold_offer
        .pull(&cold_store, engine_check())
        .await
        .expect("a cold pull");
    let (cold_bytes, cold_requests) = asked_since(&reg, from, sizes[0]);
    let r = &cold.layers[0].report;
    assert_eq!((r.fetched_files, r.reused_files), (2, 0), "{r:?}");
    let wanted_cold = cold_offer
        .meddle()
        .wanted
        .lock()
        .unwrap()
        .values()
        .next()
        .unwrap()
        .len();
    assert_eq!(wanted_cold, 2, "the driver wants both files");

    // the first layer, then the second in the store that has it: only the
    // file the first lacks is asked for
    let (first_offer, _) = chunked_offer(&s, &reg, &[&one]).await;
    first_offer
        .pull(&s, engine_check())
        .await
        .expect("the first layer");
    let (warm_offer, sizes) = chunked_offer(&s, &reg, &[&two]).await;
    let from = reg.requests().len();
    let warm = warm_offer
        .pull(&s, engine_check())
        .await
        .expect("a warm pull");
    let (warm_bytes, warm_requests) = asked_since(&reg, from, sizes[0]);
    let r = &warm.layers[0].report;
    assert_eq!((r.fetched_files, r.reused_files), (1, 1), "{r:?}");
    let wanted = warm_offer.meddle().wanted.lock().unwrap().clone();
    assert_eq!(
        wanted.values().next().map(HashSet::len),
        Some(1),
        "{wanted:?}"
    );
    assert!(
        warm_bytes < cold_bytes,
        "the file the store had is not asked for again: {warm_bytes} against {cold_bytes}"
    );
    assert!(
        warm_requests <= cold_requests,
        "{warm_requests} requests, a cold pull makes {cold_requests}"
    );
    assert_eq!(
        warm.artifacts[&warm.layers[0].key],
        cold.artifacts[&cold.layers[0].key]
    );

    // both layers, which the store has now: no file is asked for, only the
    // metadata of the layers, which is small; and the pull is the same
    let (all_offer, sizes) = chunked_offer(&s, &reg, &[&one, &two]).await;
    let from = reg.requests().len();
    let again = all_offer
        .pull(&s, engine_check())
        .await
        .expect("a pull of what is there");
    for l in &again.layers {
        let r = &l.report;
        assert_eq!(r.fetched_files, 0, "{r:?}");
    }
    assert!(all_offer
        .meddle()
        .wanted
        .lock()
        .unwrap()
        .values()
        .all(HashSet::is_empty));
    let all = reg.requests();
    let bytes: u64 = all[from..]
        .iter()
        .map(|r| r.bytes(sizes.iter().copied().max().unwrap()))
        .sum();
    assert!(bytes < 60_000, "only metadata is asked for: {bytes} bytes");
    assert_eq!(again.artifacts.len(), 2);
}

/// A chunk of a file that an object the driver holds has is not fetched again
/// by a later layer: the engine records where the chunks of a layer it
/// pulled are in the driver's objects, and the fetch of the next layer gives
/// the registry fetcher the chunks of the engine's store that are there, in
/// its files (the reuse hints of `Fetch`; a driver in another process holds
/// objects the engine cannot hand: their chunks are fetched).  Whatever the
/// driver does, the layer comes out as it does from a store that had nothing,
/// and the registry is asked for the chunks that differ.
pub async fn a_chunk_the_driver_holds_is_not_fetched_again(f: &Factory) {
    let (_tmp, s) = begin!(f, "a_chunk_the_driver_holds_is_not_fetched_again");
    let reg = Registry::start().await;
    let big = random(10, 700_000);
    let mut edited = big.clone();
    let end = edited.len();
    edited[end - 5000..].copy_from_slice(&random(11, 5000));
    let one = Tar::new()
        .dir("usr", 0o755)
        .file("usr/a", &big, 0o644)
        .done();
    let two = Tar::new()
        .dir("usr", 0o755)
        .file("usr/b", &edited, 0o644)
        .done();

    // the second layer in a store that has nothing: all of it is asked for
    let cold_store = second(f, &s, "cold").await;
    let (cold_offer, sizes) = chunked_offer(&cold_store, &reg, &[&two]).await;
    let from = reg.requests().len();
    let cold = cold_offer
        .pull(&cold_store, engine_check())
        .await
        .expect("a cold pull");
    let (cold_bytes, _) = asked_since(&reg, from, sizes[0]);

    // the first layer, recorded as the engine records a pull, then the second:
    // the file it has is another file, with most of the chunks of the first
    let (first_offer, _) = chunked_offer(&s, &reg, &[&one]).await;
    let first = first_offer
        .pull(&s, engine_check())
        .await
        .expect("the first layer");
    record(&s, &first).await;
    let (warm_offer, sizes) = chunked_offer(&s, &reg, &[&two]).await;
    let from = reg.requests().len();
    let warm = warm_offer
        .pull(&s, engine_check())
        .await
        .expect("a warm pull");
    let (warm_bytes, _) = asked_since(&reg, from, sizes[0]);
    let r = &warm.layers[0].report;
    assert_eq!(r.fetched_files, 1, "{r:?}");
    assert_eq!(
        warm.artifacts[&warm.layers[0].key], cold.artifacts[&cold.layers[0].key],
        "the layer is the one a cold pull makes"
    );
    // (the registry fetcher is told the chunks the engine's store holds,
    // in its files: the reuse hints of `Fetch`; the objects of a driver in
    // another process are not files of the engine, its chunks are fetched)
    if s.remote {
        assert!(
            warm_bytes <= cold_bytes,
            "{warm_bytes} against {cold_bytes}"
        );
        return;
    }
    assert!(
        warm_bytes * 2 < cold_bytes,
        "the chunks the store holds are not asked for again: {warm_bytes} against {cold_bytes}"
    );
}

/// A layer is stored by the entries of its table as a layer keeps them: the
/// name normalised, the permission bits only, none of the attributes of the
/// overlay file system.  The table of a registry that says otherwise (and
/// agrees with the tar once cleaned) is not what the driver is handed or
/// what it records, whatever the driver.
pub async fn a_driver_is_handed_the_table_a_layer_keeps(f: &Factory) {
    let (_tmp, s) = begin!(f, "a_driver_is_handed_the_table_a_layer_keeps");
    if !s.chunked_only {
        eprintln!("SKIPPED conformance::a_driver_is_handed_the_table_a_layer_keeps: the layers are archives");
        return;
    }
    let reg = Registry::start().await;
    let (_, tar) = chunked_layers();
    let layer = chunked_layer_edited(&reg, &tar, |toc| {
        for e in toc["entries"].as_array_mut().unwrap() {
            if e["name"] == "usr/f1" {
                e["name"] = "./usr//f1".into();
                e["mode"] = 0o100644.into();
                e["xattrs"] = serde_json::json!({
                    "trusted.overlay.redirect": "L2V0Yy9zaGFkb3c=",
                    "user.overlay.opaque": "eQ==",
                });
            }
        }
    });
    let mut layers = vec![layer];
    set_chains(&mut layers);
    let feed = registry_feed(&reg, &s.db, &s.dir, &layers[0].descriptor, false).await;
    let offer = Offer {
        feed: Arc::new(ArchiveFeed {
            layers: vec![(layers[0].descriptor.digest, feed)],
            meddle: Arc::default(),
        }),
        layers,
        _registry: None,
    };
    let seen = Arc::new(Mutex::new(None));
    let seen2 = seen.clone();
    offer
        .pull(
            &s,
            Box::new(move |pulled, _| {
                *seen2.lock().unwrap() = Some(pulled[0].toc.clone());
                engine_settlement(pulled)
            }),
        )
        .await
        .expect("a pull");
    let toc = seen.lock().unwrap().take().expect("the check ran");
    let e = toc
        .entries
        .iter()
        .find(|e| e.name.ends_with("f1"))
        .expect("the file");
    assert_eq!(e.name, "usr/f1");
    assert_eq!(e.mode, 0o644);
    assert!(e.xattrs.is_empty(), "{:?}", e.xattrs);
}

/// A chunked pull that is cut off in the middle stores nothing and leaves no
/// staging area; the next one fetches what the layer needs and comes to the
/// artifacts of a pull that was never cut.
pub async fn an_interrupted_chunked_pull_is_pulled_again(f: &Factory) {
    let (_tmp, s) = begin!(f, "an_interrupted_chunked_pull_is_pulled_again");
    let reg = Registry::start().await;
    let (one, _) = chunked_layers();
    let (o, _) = chunked_offer(&s, &reg, &[&one]).await;
    let before = s.driver.usage().unwrap();
    // the metadata, and then the registry hangs up
    reg.answer_only(1);
    let e = expect_err(
        o.pull(&s, engine_check()).await.map(|_| ()),
        "a registry that hangs up",
    );
    of_driver(&s, &e);
    assert_eq!(s.driver.usage().unwrap(), before, "nothing was stored");
    let stale = no_staging_left(&s).await;
    assert!(stale.is_empty(), "a staging area was left: {stale:?}");
    reg.answer_all();
    let pulled = o.pull(&s, engine_check()).await.expect("pulled again");
    let r = &pulled.layers[0].report;
    assert_eq!(r.fetched_files, 3, "{r:?}");
    let other = second(f, &s, "uncut").await;
    let (o2, _) = chunked_offer(&other, &reg, &[&one]).await;
    let uncut = o2.pull(&other, engine_check()).await.unwrap();
    assert_eq!(pulled.artifacts, uncut.artifacts);
}

/// What the engine's check sees is the layers as the driver committed them,
/// before the driver writes any artifact; a check that refuses leaves no
/// artifact.
pub async fn pull_check_sees_the_layers_first(f: &Factory) {
    let (_tmp, s) = begin!(f, "pull_check_sees_the_layers_first");
    let base = base_layer();
    let offer1 = offer(&s, &[&base]).await;
    let seen = Arc::new(Mutex::new(None));
    let seen2 = seen.clone();
    let before = s.driver.usage().unwrap();
    let driver = s.driver.clone();
    let meddle = offer1.feed.meddle.clone();
    let pulled = offer1
        .pull(
            &s,
            Box::new(move |layers, _| {
                *seen2.lock().unwrap() = Some((
                    layers.iter().map(|l| l.key).collect::<Vec<_>>(),
                    // (settled: the files have the names of what they hold)
                    layers[0].toc.entries.iter().all(|e| {
                        e.entry_type != TocEntryType::Reg || e.size == 0 || e.verity().is_some()
                    }),
                    driver.usage().unwrap(),
                    // (the feed was ended before the files were committed)
                    meddle.finished.load(std::sync::atomic::Ordering::Relaxed),
                ));
                engine_settlement(layers)
            }),
        )
        .await
        .unwrap();
    let (keys, settled, at_check, finished) = seen.lock().unwrap().take().expect("the check ran");
    assert_eq!(keys.len(), 1);
    assert_eq!(finished, 1, "the feed is finished once, before the check");
    assert!(settled, "the layers are settled when the check sees them");
    assert_eq!(
        at_check.artifacts, before.artifacts,
        "no artifact is stored before the check said yes"
    );
    assert!(s.driver.usage().unwrap().artifacts.0 > before.artifacts.0);
    assert_eq!(pulled.artifacts.len(), 1);

    // a check that refuses: the error is the check's, and no artifact is
    // left of it
    let other = second(f, &s, "refused").await;
    let top = top_layer();
    let offer2 = offer(&other, &[&top]).await;
    let before2 = other.driver.usage().unwrap().artifacts;
    let e = expect_err(
        offer2
            .pull(
                &other,
                Box::new(|_, _| {
                    Err(ImageError::Contradicted(
                        "the manifest says otherwise".into(),
                    ))
                }),
            )
            .await
            .map(|_| ()),
        "a check that refuses",
    );
    of_driver(&other, &e);
    assert!(matches!(e.kind, DriverErrorKind::Refused(_)), "{e:?}");
    assert!(matches!(ImageError::from(e), ImageError::Contradicted(m) if m.contains("otherwise")));
    assert_eq!(
        other.driver.usage().unwrap().artifacts,
        before2,
        "nothing was written"
    );
}

/// What the engine's check concluded is what the driver hands back: the
/// verdict of the check, as the check sealed it, in `Pulled::verdict` (a
/// driver that drops it cannot return a `Pulled`, and one cannot make or
/// change a verdict; the verdict opens only with the id of its check).
pub async fn a_pull_returns_the_verdict_of_the_check(f: &Factory) {
    let (_tmp, s) = begin!(f, "a_pull_returns_the_verdict_of_the_check");
    let base = base_layer();
    let top = top_layer();
    let o = offer(&s, &[&base, &top]).await;
    // a verdict no driver could make of the layers by itself
    let marker = "fsverity-sha256-12:".to_string() + &"5".repeat(64);
    let merged = (velarx_types::digest::Algorithm::Sha256, marker.clone());
    let stored_key = o.layers[0].key;
    let check = CheckId::fresh();
    let sent = Arc::new(Mutex::new(None));
    let (sent2, merged2, check2) = (sent.clone(), merged.clone(), check.clone());
    let pulled = o
        .pull(
            &s,
            Box::new(move |layers, _| {
                let identities = engine_identities(layers)?;
                let mut checked = checked_of(&identities, layers);
                checked.layer_keys.reverse();
                checked.merged_id = Some(merged2);
                checked
                    .stored_erofs
                    .insert(stored_key, Some("stored".to_string()));
                *sent2.lock().unwrap() = Some((checked.layer_keys.clone(), checked.ours.clone()));
                Ok(Settlement {
                    identities,
                    verdict: Verdict::sealed(&check2, checked),
                })
            }),
        )
        .await
        .expect("pull");
    let (keys, ours) = sent.lock().unwrap().take().expect("the check ran");
    assert_eq!(keys.len(), 2);
    let checked = pulled
        .verdict
        .open(&check)
        .expect("the verdict is the one of the check");
    assert_eq!(
        checked.layer_keys, keys,
        "the keys of the verdict are the check's"
    );
    assert_eq!(checked.merged_id, Some(merged));
    assert_eq!(
        checked.stored_erofs,
        HashMap::from([(stored_key, Some("stored".to_string()))])
    );
    assert_eq!(
        checked.ours, ours,
        "the identities of the verdict are the engine's"
    );
    assert_eq!(checked.ours.len(), pulled.layers.len());
    assert!(
        checked
            .ours
            .keys()
            .all(|k| pulled.layers.iter().any(|l| &l.key == k)),
        "the verdict is of the layers the pull brought"
    );
    // what the driver recorded is the engine's identity
    for (k, made) in &pulled.artifacts {
        assert_eq!(Some(made), checked.ours.get(k));
    }
}

/// The engine makes the image of every layer it pulled (once, in `Settled`)
/// and a driver that keeps images writes those: a settlement without the
/// image of a layer is refused before anything is written.
pub async fn a_pull_the_engine_made_no_image_for_is_refused(f: &Factory) {
    let (_tmp, s) = begin!(f, "a_pull_the_engine_made_no_image_for_is_refused");
    let base = base_layer();
    let o = offer(&s, &[&base]).await;
    let before = s.driver.usage().unwrap().artifacts;
    let pulled = o
        .pull(
            &s,
            Box::new(|layers, _| {
                // the identity of the layer and no image: the engine makes
                // the image of every layer it pulled, and a driver never
                // builds one of its own
                let mut ids = engine_identities(layers)?;
                ids.images.clear();
                let verdict = Verdict::sealed(&CheckId::fresh(), checked_of(&ids, layers));
                Ok(Settlement {
                    identities: ids,
                    verdict,
                })
            }),
        )
        .await;
    match pulled {
        // a driver that keeps no image of the layers records what it is given
        Ok(p) => assert_eq!(p.artifacts.len(), 1),
        Err(e) => {
            of_driver(&s, &e);
            assert!(matches!(e.kind, DriverErrorKind::Storage), "{e:?}");
            assert_eq!(
                s.driver.usage().unwrap().artifacts,
                before,
                "nothing was written"
            );
        }
    }
}

/// `Settled` runs when every layer is staged and proven and before the driver
/// publishes: a refusal of the engine leaves nothing for `has_layers` to
/// report, nothing of the artifacts and none of the files of the layers, and
/// the same layers pull afterwards.
pub async fn a_refusal_of_the_engine_leaves_nothing_visible(f: &Factory) {
    let (_tmp, s) = begin!(f, "a_refusal_of_the_engine_leaves_nothing_visible");
    let (a, b) = (base_layer(), top_layer());
    let o = offer(&s, &[&a, &b]).await;
    let asked: Vec<LayerRef> = o
        .layers
        .iter()
        .map(|l| LayerRef {
            key: l.key,
            diff_id: l.diff_id,
            chain_id: l.chain_id,
        })
        .collect();
    let before = s.driver.usage().unwrap().artifacts;
    let seen = Arc::new(Mutex::new(Vec::new()));
    let files = seen.clone();
    let e = expect_err(
        o.pull(
            &s,
            Box::new(move |layers, _| {
                *files.lock().unwrap() = layers
                    .iter()
                    .flat_map(|l| l.toc.entries.iter())
                    .filter(|e| e.entry_type == TocEntryType::Reg && e.size > 0)
                    .filter_map(|e| Some((e.content_key()?, e.size)))
                    .collect();
                Err(ImageError::Manifest("the manifest says no".into()))
            }),
        )
        .await
        .map(|_| ()),
        "a pull the engine refuses",
    );
    // (nor are the files of the layers in the store: none was named)
    let files = seen.lock().unwrap().clone();
    assert!(!files.is_empty());
    for (key, size) in files {
        assert!(
            s.driver.open_object(&key, size).is_err(),
            "{key} of a refused pull is in the store"
        );
    }
    assert!(
        matches!(e.kind, DriverErrorKind::Refused(_)) || e.to_string().contains("says no"),
        "{e:?}"
    );
    assert!(
        none_of(&s.driver.has_layers(&asked).await.unwrap(), asked.len()),
        "a refused layer is not reported"
    );
    assert_eq!(
        s.driver.usage().unwrap().artifacts,
        before,
        "nothing was published"
    );
    // (and the layers are pulled when the engine is satisfied)
    let again = offer(&s, &[&a, &b]).await;
    again.pull(&s, engine_check()).await.expect("pulled again");
}

/// A pull that stops in the middle leaves nothing recorded and no staging
/// area behind, and the next one pulls the layers (the files it fetched
/// before are in the store only once the whole pull is verified).
pub async fn an_interrupted_pull_is_pulled_again(f: &Factory) {
    let (_tmp, s) = begin!(f, "an_interrupted_pull_is_pulled_again");
    let (base, top) = (base_layer(), top_layer());
    let o = offer(&s, &[&base, &top]).await;
    // the second layer asked for is cut off
    *o.meddle().fail_at.lock().unwrap() = Some(1);
    let before = s.driver.usage().unwrap();
    let e = expect_err(
        o.pull(&s, engine_check()).await.map(|_| ()),
        "a feed that stops in the middle",
    );
    assert!(e.message().contains("cut"), "{e:?}");
    assert_eq!(s.driver.usage().unwrap(), before, "nothing was stored");
    let stale = no_staging_left(&s).await;
    assert!(stale.is_empty(), "a staging area was left: {stale:?}");
    // the same pull, the feed whole: every layer comes
    *o.meddle().fail_at.lock().unwrap() = None;
    let pulled = o.pull(&s, engine_check()).await.expect("pulled again");
    assert_eq!(pulled.layers.len(), 2);
    assert_eq!(pulled.artifacts.len(), 2);
    // and the same pull again changes nothing
    let more = offer(&s, &[&base, &top]).await;
    let again = more.pull(&s, engine_check()).await.unwrap();
    assert_eq!(again.artifacts, pulled.artifacts);
}

/// A third layer, unlike the others.
fn other_layer() -> Vec<u8> {
    Tar::new()
        .dir("srv", 0o755)
        .file("srv/other", &random(77, 30_000), 0o644)
        .done()
}

/// Two pulls at the same time of images that share a layer (two engine
/// processes on one store, or two pulls of one): each has an id of its own, both
/// succeed, the shared layer is complete and reads back as it was pulled, and
/// committing a layer that another pull committed meanwhile is no error.
pub async fn concurrent_pulls_of_a_shared_layer_both_complete(f: &Factory) {
    let (_tmp, s) = begin!(f, "concurrent_pulls_of_a_shared_layer_both_complete");
    let (base, top, other) = (base_layer(), top_layer(), other_layer());
    let (one, two) = (
        offer(&s, &[&base, &top]).await,
        offer(&s, &[&base, &other]).await,
    );
    let (a, b) = tokio::join!(one.pull(&s, engine_check()), two.pull(&s, engine_check()));
    let (a, b) = (a.expect("the first pull"), b.expect("the second pull"));
    // (what the shared layer is, by either)
    let shared = |p: &Pulled| {
        p.layers
            .iter()
            .find(|l| l.diff_id == one.layers[0].diff_id)
            .map(|l| l.key)
            .expect("the shared layer was pulled by it")
    };
    assert_eq!(shared(&a), shared(&b), "one layer");
    assert_eq!(
        a.artifacts[&shared(&a)],
        b.artifacts[&shared(&b)],
        "the same identity from both"
    );
    // the engine records the layers of both
    record(&s, &a).await;
    record(&s, &b).await;
    let all: Vec<LayerRef> = refs_of(&one.stack(&[0, 1]))
        .into_iter()
        .chain(refs_of(&two.stack(&[0, 1])).into_iter().skip(1))
        .collect();
    assert_eq!(s.driver.has_layers(&all).await.unwrap(), [true, true, true]);
    for p in [&a, &b] {
        for l in &p.layers {
            let d = s.driver.clone();
            let l = l.clone();
            tokio::task::spawn_blocking(move || prove_by_read_back(d, &l))
                .await
                .unwrap()
                .expect("read back as pulled");
        }
    }
    // a pull of the shared layer again, after both committed it: no error,
    // and nothing it changes is visible
    let again = offer(&s, &[&base]).await;
    let c = again
        .pull(&s, engine_check())
        .await
        .expect("committed again");
    assert_eq!(c.artifacts[&shared(&c)], a.artifacts[&shared(&a)]);
    let stale = no_staging_left(&s).await;
    assert!(stale.is_empty(), "a staging area was left: {stale:?}");
}

/// Two pulls at the same time of images that share a layer fetch the shared
/// layer once between them: the driver of a store that is shared by
/// several engine processes keeps the claims of the pulls in progress, so the
/// second pull waits for the first and then finds the layer committed.  The
/// count is the engine's: how many times its feed was asked for the files of
/// the shared layer.  A driver of the engine's process stages each pull in a
/// session of its own and fetches for each pull.
pub async fn a_layer_shared_by_concurrent_pulls_is_fetched_at_most_once(f: &Factory) {
    let (_tmp, s) = begin!(
        f,
        "a_layer_shared_by_concurrent_pulls_is_fetched_at_most_once"
    );
    if !s.remote {
        eprintln!("SKIPPED conformance::a_layer_shared_by_concurrent_pulls_is_fetched_at_most_once: a driver of the engine's process stages each pull in a session of its own and fetches for each");
        return;
    }
    let (base, top, other) = (base_layer(), top_layer(), other_layer());
    let (a, b) = (
        offer(&s, &[&base, &top]).await,
        offer(&s, &[&base, &other]).await,
    );
    let shared = a.layers[0].descriptor.digest;
    assert_eq!(shared, b.layers[0].descriptor.digest, "one layer");
    let (ra, rb) = tokio::join!(a.pull(&s, engine_check()), b.pull(&s, engine_check()));
    ra.expect("the first pull");
    rb.expect("the second pull");
    let calls = |o: &Offer| {
        o.meddle()
            .asked
            .lock()
            .unwrap()
            .iter()
            .filter(|d| **d == shared)
            .count()
    };
    let keys = |o: &Offer| {
        o.meddle()
            .wanted
            .lock()
            .unwrap()
            .get(&shared)
            .map_or(0, HashSet::len)
    };
    assert_eq!(
        calls(&a) + calls(&b),
        1,
        "the files of the shared layer were fetched once in all"
    );
    assert!(
        keys(&a) == 0 || keys(&b) == 0,
        "one pull asked for them: {} and {}",
        keys(&a),
        keys(&b)
    );
    assert!(keys(&a) + keys(&b) > 0);
    // the layers of both are there
    let all: Vec<LayerRef> = refs_of(&a.stack(&[0, 1]))
        .into_iter()
        .chain(refs_of(&b.stack(&[0, 1])).into_iter().skip(1))
        .collect();
    assert_eq!(s.driver.has_layers(&all).await.unwrap(), [true, true, true]);
    // the driver says how many fetches it made, when it counts them: one for
    // each time the engine's feed was asked
    if let Some((_, made)) = s
        .driver
        .status()
        .into_iter()
        .find(|(k, _)| k == "fetch calls")
    {
        assert_eq!(
            made.parse::<usize>().unwrap(),
            a.fetches() + b.fetches(),
            "the driver's count is the engine's"
        );
    }
}

/// A pull that is aborted while another pull of the same store commits a layer
/// they share drops only what it staged: the layer is complete and the other
/// pull's, and the aborted one's own layers are not stored.
pub async fn an_aborted_pull_leaves_what_another_pull_committed(f: &Factory) {
    let (_tmp, s) = begin!(f, "an_aborted_pull_leaves_what_another_pull_committed");
    let (base, top, other) = (base_layer(), top_layer(), other_layer());
    let (good, bad) = (
        offer(&s, &[&base, &top]).await,
        offer(&s, &[&base, &other]).await,
    );
    // the second pull is cut when it asks for its second layer (the one the
    // first pull does not have: a driver that fetches a layer once for
    // pulls that share it never asks for the shared one twice)
    *bad.meddle().fail_layer.lock().unwrap() = Some(bad.layers[1].descriptor.digest);
    let (a, b) = tokio::join!(good.pull(&s, engine_check()), bad.pull(&s, engine_check()));
    let a = a.expect("the pull that was not cut");
    let e = expect_err(b.map(|_| ()), "the pull that was cut");
    assert!(
        e.message().contains("cut"),
        "the aborted pull says why: {e:?}"
    );
    record(&s, &a).await;
    let stack = good.stack(&[0, 1]);
    assert_eq!(
        s.driver.has_layers(&refs_of(&stack)).await.unwrap(),
        [true, true]
    );
    for l in &a.layers {
        let d = s.driver.clone();
        let l = l.clone();
        tokio::task::spawn_blocking(move || prove_by_read_back(d, &l))
            .await
            .unwrap()
            .expect("the committed layers read back as pulled");
    }
    // the other pull's own layer was not stored
    let own = refs_of(&bad.stack(&[0, 1]));
    assert_eq!(
        s.driver.has_layers(&own).await.unwrap(),
        [true, false],
        "the shared layer is there, the cut pull's own is not"
    );
    let stale = no_staging_left(&s).await;
    assert!(stale.is_empty(), "a staging area was left: {stale:?}");
}

/// The id of a pull is a random id (a v4 UUID) made for each pull, so that two
/// pulls never share one; a driver that is not in the engine's process takes
/// an id it knows for a resume.
pub async fn every_pull_has_an_id_of_its_own(f: &Factory) {
    let (_tmp, s) = begin!(f, "every_pull_has_an_id_of_its_own");
    let (base, top) = (base_layer(), top_layer());
    let (one, two) = (offer(&s, &[&base]).await, offer(&s, &[&top]).await);
    let (a, b) = tokio::join!(one.pull(&s, engine_check()), two.pull(&s, engine_check()));
    a.unwrap();
    b.unwrap();
    let ids = |o: &Offer| o.meddle().pull_ids.lock().unwrap().clone();
    let (x, y) = (ids(&one), ids(&two));
    assert_eq!(
        (x.len(), y.len()),
        (1, 1),
        "one id for each pull: {x:?} {y:?}"
    );
    assert_ne!(x, y, "two pulls, two ids");
    for id in x.iter().chain(&y) {
        assert!(is_pull_id(id), "{id:?} is not a pull id");
    }
    let made: HashSet<String> = (0..64).map(|_| new_pull_id()).collect();
    assert_eq!(made.len(), 64, "ids made for the pulls are all different");
    assert!(made.iter().all(|i| is_pull_id(i) && i.len() == 32));
    assert!(!is_pull_id("") && !is_pull_id("pull-") && !is_pull_id("../etc"));
}

/// The diff id of a pulled layer is proved by reading it back from the driver
/// (what a driver outside the engine's process is held to): the layers a pull
/// stored pass, a layer whose diff id is not what was stored is `Corrupt` with
/// the remedy of pulling again, and a layer the driver lacks is `Missing`.
pub async fn the_diff_id_is_proved_by_reading_back_from_the_driver(f: &Factory) {
    let (_tmp, s) = begin!(f, "the_diff_id_is_proved_by_reading_back_from_the_driver");
    let (base, top) = (base_layer(), top_layer());
    let o = offer(&s, &[&base, &top]).await;
    let pulled = o.pull(&s, engine_check()).await.expect("pull");
    let prove = |l: &LayerDone, diff: Option<Digest>| {
        let d = s.driver.clone();
        let mut l = l.clone();
        if let Some(diff) = diff {
            l.diff_id = diff;
        }
        async move {
            tokio::task::spawn_blocking(move || prove_by_read_back(d, &l))
                .await
                .unwrap()
        }
    };
    for l in &pulled.layers {
        prove(l, None)
            .await
            .expect("the layer reads back as pulled");
    }
    let wrong = Digest::of(velarx_types::digest::Algorithm::Sha256, b"not this layer");
    let e = expect_err(
        prove(&pulled.layers[0], Some(wrong)).await,
        "a wrong diff id",
    );
    assert!(
        matches!(e.kind, DriverErrorKind::Corrupt { remedy } if remedy == Remedy::PullAgain),
        "{e:?}"
    );
    of_driver(&s, &e);
    // a lazy layer has no files to read yet
    let mut lazy = pulled.layers[0].clone();
    lazy.lazy = true;
    let e = expect_err(
        tokio::task::spawn_blocking({
            let d = s.driver.clone();
            move || prove_by_read_back(d, &lazy)
        })
        .await
        .unwrap(),
        "a lazy layer",
    );
    assert!(e.message().contains("lazy"), "{e:?}");
    // a driver that never pulled the layer lacks its files
    let other = second(f, &s, "elsewhere").await;
    let l = pulled.layers[0].clone();
    let e = expect_err(
        tokio::task::spawn_blocking({
            let d = other.driver.clone();
            move || prove_by_read_back(d, &l)
        })
        .await
        .unwrap(),
        "a layer the driver does not have",
    );
    assert!(
        matches!(e.kind, DriverErrorKind::Missing { remedy } if remedy == Remedy::PullAgain),
        "{e:?}"
    );
}

/// The engine's own feed writes the bytes of a layer it fetches by ranges into
/// the files a driver hands over, at the place the driver chose for each key
/// (some in a pack file at an offset, some in a file of their own), with no
/// staging session of the engine's: every byte that arrives is checked against
/// the table of contents, the diff id is not proved by the fetch (the layer
/// comes back claimed, not `proven`), and the layer read back from the files
/// is the layer.
pub async fn a_feed_writes_into_the_files_a_driver_hands_over(f: &Factory) {
    use std::os::unix::fs::FileExt;
    use velarx_content::pull::sink::{FilesSink, Slot, Written};
    let (_tmp, s) = begin!(f, "a_feed_writes_into_the_files_a_driver_hands_over");
    let reg = Registry::start().await;
    let (one, _) = chunked_layers();
    let (o, _) = chunked_offer(&s, &reg, &[&one]).await;
    let feed: &dyn PullFeed = &*o.feed;
    let layer = &o.layers[0];
    let scratch = s.dir.join("scratch");
    std::fs::create_dir_all(&scratch).unwrap();
    let begun = FilesIncoming::of(&new_pull_id(), FilesSink::none("test", &scratch));
    assert!(is_pull_id(&begun.pull_id()));
    feed.begin(&begun)
        .await
        .expect("a feed begins with files of a driver");
    let index = feed.index(layer).await.unwrap().expect("an index");
    let keys: Vec<(String, u64)> = index
        .toc
        .entries
        .iter()
        .filter(|e| e.entry_type == TocEntryType::Reg && e.size > 0)
        .map(|e| (e.content_key().unwrap(), e.size))
        .collect();
    assert_eq!(keys.len(), 3);
    // the first key in a file of its own, the others in a pack file, one
    // after the other from a base that is not zero
    let own_file = tempfile::tempfile().unwrap();
    let pack = tempfile::tempfile().unwrap();
    let told: Arc<Mutex<Vec<String>>> = Arc::default();
    let mut slots = vec![(
        keys[0].0.clone(),
        Slot {
            file: Arc::new(own_file.try_clone().unwrap()),
            base: 0,
            size: keys[0].1,
        },
    )];
    let mut base = 4096;
    let mut places = HashMap::new();
    places.insert(
        keys[0].0.clone(),
        (own_file.try_clone().unwrap(), 0u64, keys[0].1),
    );
    for (key, size) in &keys[1..] {
        slots.push((
            key.clone(),
            Slot {
                file: Arc::new(pack.try_clone().unwrap()),
                base,
                size: *size,
            },
        ));
        places.insert(key.clone(), (pack.try_clone().unwrap(), base, *size));
        base += size;
    }
    // (an object a fetcher staged and the engine verified is handed over as
    // the file itself, not written to its place: the contract is that the
    // object is whole in one of the two)
    type Handed = Vec<(String, Arc<std::fs::File>)>;
    let handed: Arc<Mutex<Handed>> = Arc::default();
    let sink = FilesSink::new("test", &scratch, slots, {
        let (told, handed) = (told.clone(), handed.clone());
        move |w| match w {
            Written::Whole { key } => told.lock().unwrap().push(key),
            Written::Staged { key, file, .. } => {
                told.lock().unwrap().push(key.clone());
                handed.lock().unwrap().push((key, file));
            }
            _ => {}
        }
    })
    .unwrap();
    let into = FilesIncoming::of(&begun.pull_id(), sink);
    let done = feed
        .fetch(layer, &into)
        .await
        .expect("a fetch into the files");
    for (key, file) in handed.lock().unwrap().iter() {
        let size = places[key].2;
        places.insert(key.clone(), (file.try_clone().unwrap(), 0, size));
    }
    assert!(!done.proven, "nothing proved the layer: it is read back");
    assert_eq!(done.diff_id, layer.diff_id);
    let mut got = told.lock().unwrap().clone();
    got.sort();
    let mut want: Vec<String> = keys.iter().map(|k| k.0.clone()).collect();
    want.sort();
    assert_eq!(got, want, "every object was told whole");
    // the bytes are in the places, and they are the files of the layer
    for e in index
        .toc
        .entries
        .iter()
        .filter(|e| e.entry_type == TocEntryType::Reg && e.size > 0)
    {
        let (file, base, size) = &places[&e.content_key().unwrap()];
        let mut bytes = vec![0u8; *size as usize];
        file.read_exact_at(&mut bytes, *base).unwrap();
        let hash = Digest::of(velarx_types::digest::Algorithm::Sha256, &bytes);
        assert_eq!(Some(hash.to_string()), e.digest, "{}", e.name);
    }
    // and the layer read back from them is the layer
    struct Places(HashMap<String, (std::fs::File, u64, u64)>);
    impl velarx_storage::ObjectOpener for Places {
        fn object_file(&self, key: &str, size: u64) -> std::io::Result<std::fs::File> {
            let (file, base, len) = self.0.get(key).ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::NotFound, key.to_string())
            })?;
            assert_eq!(*len, size);
            let mut bytes = vec![0u8; size as usize];
            file.read_exact_at(&mut bytes, *base)?;
            let out = tempfile::tempfile()?;
            out.write_all_at(&bytes, 0)?;
            Ok(out)
        }
    }
    let pulled = done;
    tokio::task::spawn_blocking(move || prove_with("test", Arc::new(Places(places)), &pulled))
        .await
        .unwrap()
        .expect("the diff id is proved by reading the files back");
    // a place of another size than the table of contents says is refused
    let wrong = FilesSink::new(
        "test",
        &scratch,
        [(
            keys[0].0.clone(),
            Slot {
                file: Arc::new(tempfile::tempfile().unwrap()),
                base: 0,
                size: keys[0].1 + 1,
            },
        )],
        |_| {},
    )
    .unwrap();
    let into = FilesIncoming::of(&begun.pull_id(), wrong);
    assert!(feed.fetch(layer, &into).await.is_err());
    feed.end();
}

/// What the feed gives is verified by the engine, and a driver stores nothing
/// of a layer that is not what the descriptor and the configuration say:
/// bytes that are not the blob, and a diff id that is not the layer's.
pub async fn a_feed_with_wrong_bytes_is_refused(f: &Factory) {
    let (_tmp, s) = begin!(f, "a_feed_with_wrong_bytes_is_refused");
    let base = base_layer();
    let before = s.driver.usage().unwrap();
    // (a) the configuration names another diff id
    let wrong = Digest::of(velarx_types::digest::Algorithm::Sha256, b"another layer");
    let o = offer_with(&s, &[&base], |_, _| wrong, |_, t| t.to_vec()).await;
    let e = expect_err(
        o.pull(&s, engine_check()).await.map(|_| ()),
        "a layer that is not the one of the configuration",
    );
    of_driver(&s, &e);
    assert_eq!(s.driver.usage().unwrap(), before, "nothing was stored");
    // (b) the bytes are not those of the blob's digest
    let o = offer_with(
        &s,
        &[&base],
        |_, d| d,
        |_, tar| {
            let mut bad = tar.to_vec();
            let at = bad.len() / 2;
            bad[at] ^= 0x55;
            bad
        },
    )
    .await;
    let e = expect_err(
        o.pull(&s, engine_check()).await.map(|_| ()),
        "bytes that are not the blob",
    );
    of_driver(&s, &e);
    assert_eq!(s.driver.usage().unwrap(), before, "nothing was stored");
    // (c) a blob that is not the descriptor's but inflates to the layer of the
    // right diff id (another time in its gzip header): the blob's digest is
    // checked too, not only the diff id
    let mut blob = Vec::new();
    let w = velarx_content::layer::writer::write_layer(
        &base[..],
        velarx_types::digest::Algorithm::Sha256,
        velarx_content::layer::writer::Compression::Gzip,
        &mut blob,
    )
    .expect("a gzip layer");
    let mut other = blob.clone();
    other[4] ^= 1;
    let path = s.dir.join("blob-other-gzip");
    std::fs::write(&path, &other).unwrap();
    let desc = OciDescriptor {
        media_type: w.media_type.to_string(),
        digest: w.digest,
        size: w.size as i64,
        annotations: Default::default(),
    };
    let archive = Archive::single(std::fs::File::open(&path).unwrap(), w.digest, w.size);
    let o = Offer {
        feed: Arc::new(ArchiveFeed {
            layers: vec![(
                w.digest,
                ContentFeed::new(
                    Net::offline(),
                    Source::Archive(Arc::new(archive)),
                    s.db.clone(),
                    Limits::from_config(&velarx_config::PullConfig::default()),
                ),
            )],
            meddle: Arc::default(),
        }),
        layers: vec![FeedLayer {
            key: LayerKey::expected(&desc),
            descriptor: desc,
            diff_id: w.diff_id,
            chain_id: w.diff_id,
            parent: None,
            stored: false,
        }],
        _registry: None,
    };
    let e = expect_err(
        o.pull(&s, engine_check()).await.map(|_| ()),
        "a blob that is not the descriptor's",
    );
    of_driver(&s, &e);
    assert!(
        matches!(&e.kind, DriverErrorKind::Refused(r)
            if matches!(**r, ImageError::DigestMismatch { ref actual, .. } if *actual != w.diff_id.to_string())),
        "{e:?}"
    );
    assert_eq!(s.driver.usage().unwrap(), before, "nothing was stored");
}

/// The layers `tars` as blobs of `compression`, offered as archives read
/// whole: what a commit, a build step or an import makes, and a layer of a
/// registry that has no table of contents.
fn blob_offer(
    s: &Subject,
    tars: &[&[u8]],
    compression: velarx_content::layer::writer::Compression,
) -> Offer {
    blob_offer_with(s, tars, compression, |_, blob| blob.to_vec())
}

/// The same, with the bytes of each blob (index, the true ones) made by
/// `bytes`: the descriptor names the digest and size of what `bytes` gives.
fn blob_offer_with(
    s: &Subject,
    tars: &[&[u8]],
    compression: velarx_content::layer::writer::Compression,
    bytes: impl Fn(usize, &[u8]) -> Vec<u8>,
) -> Offer {
    blob_offer_limited(
        s,
        tars,
        compression,
        Limits::from_config(&velarx_config::PullConfig::default()),
        bytes,
    )
}

/// The same, read with the limits `limits` of `[pull]`.
fn blob_offer_limited(
    s: &Subject,
    tars: &[&[u8]],
    compression: velarx_content::layer::writer::Compression,
    limits: Limits,
    bytes: impl Fn(usize, &[u8]) -> Vec<u8>,
) -> Offer {
    use velarx_content::layer::writer::write_layer;
    let (mut layers, mut feeds) = (Vec::new(), Vec::new());
    for (i, tar) in tars.iter().enumerate() {
        let mut blob = Vec::new();
        let w = write_layer(
            *tar,
            velarx_types::digest::Algorithm::Sha256,
            compression,
            &mut blob,
        )
        .expect("a layer");
        let blob = bytes(i, &blob);
        let digest = Digest::of(velarx_types::digest::Algorithm::Sha256, &blob);
        let path = s.dir.join(format!("blob-{}-{i}", digest.hex()));
        std::fs::write(&path, &blob).unwrap();
        let desc = OciDescriptor {
            media_type: w.media_type.to_string(),
            digest,
            size: blob.len() as i64,
            annotations: w.annotations.into_iter().collect(),
        };
        let archive = Archive::single(
            std::fs::File::open(&path).unwrap(),
            digest,
            blob.len() as u64,
        );
        feeds.push((
            digest,
            ContentFeed::new(
                Net::offline(),
                Source::Archive(Arc::new(archive)),
                s.db.clone(),
                limits.clone(),
            ),
        ));
        layers.push(FeedLayer {
            key: LayerKey::expected(&desc),
            descriptor: desc,
            diff_id: w.diff_id,
            chain_id: w.diff_id,
            parent: None,
            stored: false,
        });
    }
    set_chains(&mut layers);
    Offer {
        feed: Arc::new(ArchiveFeed {
            layers: feeds,
            meddle: Arc::default(),
        }),
        layers,
        _registry: None,
    }
}

/// The compressions a layer the engine reads whole comes in: a tar, gzip, and
/// zstd:chunked, which an archive cannot give by its table of contents and is
/// refused.
fn compressions() -> [velarx_content::layer::writer::Compression; 3] {
    use velarx_content::layer::writer::Compression;
    [
        Compression::None,
        Compression::Gzip,
        Compression::ZstdChunked,
    ]
}

/// A layer the engine reads whole (a commit, a build step, an import, a gzip
/// layer of a registry) is stored by the driver whatever its compression: it
/// is the layer of its blob, the artifacts are those of the same layer as a
/// plain tar, it is read back byte for byte, and the layers above it are
/// built on it.
pub async fn a_layer_read_whole_is_stored_and_read_back(f: &Factory) {
    let (_tmp, s) = begin!(f, "a_layer_read_whole_is_stored_and_read_back");
    let (base, top) = (base_layer(), top_layer());
    let plain = {
        let other = second(f, &s, "plain").await;
        let o = offer(&other, &[&base, &top]).await;
        let pulled = o.pull(&other, engine_check()).await.expect("plain tars");
        o.layers
            .iter()
            .map(|offered| {
                let l = pulled.layers.iter().find(|l| l.key == offered.key);
                pulled.artifacts[&l.expect("a layer of the offer").key].clone()
            })
            .collect::<Vec<_>>()
    };
    for (n, compression) in compressions().into_iter().enumerate() {
        let own = second(f, &s, &format!("blobs-{n}")).await;
        let o = blob_offer(&own, &[&base, &top], compression);
        if compression == velarx_content::layer::writer::Compression::ZstdChunked {
            // (a layer with a table of contents is never read as a stream)
            let refused = o.pull(&own, engine_check()).await.err().expect("refused");
            let digests: Vec<String> = o
                .layers
                .iter()
                .map(|l| l.descriptor.digest.to_string())
                .collect();
            let text = refused.to_string();
            assert!(digests.iter().any(|d| text.contains(d)), "{text}");
            assert!(text.contains("zstd:chunked"), "{text}");
            continue;
        }
        let pulled = o
            .pull(&own, engine_check())
            .await
            .unwrap_or_else(|e| panic!("{compression:?}: {e}"));
        assert_eq!(pulled.layers.len(), 2, "{compression:?}");
        let mut refs = Vec::new();
        let mut stored = Vec::new();
        for offered in &o.layers {
            let l = pulled
                .layers
                .iter()
                .find(|l| l.key == offered.key)
                .expect("a layer of the offer");
            assert_eq!(
                l.key,
                LayerKey::Whole(offered.descriptor.digest),
                "{compression:?}: a layer read whole is the layer of its blob"
            );
            assert_eq!(l.diff_id, offered.diff_id, "{compression:?}");
            refs.push(LayerRef {
                key: l.key,
                diff_id: offered.diff_id,
                chain_id: offered.chain_id,
            });
            stored.push(l);
        }
        for (l, want) in stored.iter().zip(&plain) {
            assert_eq!(
                &pulled.artifacts[&l.key], want,
                "{compression:?}: the identity is a property of the layer, not of its compression"
            );
        }
        record(&own, &pulled).await;
        assert_eq!(
            own.driver.has_layers(&refs).await.unwrap(),
            [true, true],
            "{compression:?}"
        );
        for (l, tar) in stored.iter().zip([&base, &top]) {
            let stored = open_layer(&own, &l.key, None).await.expect("open_layer");
            assert_eq!(stored.diff_id, l.diff_id);
            let mut out = Vec::new();
            stored
                .verified_stream(Arc::new(DriverObjects::new(own.driver.clone())))
                .unwrap()
                .read_to_end(&mut out)
                .unwrap();
            assert!(
                out == **tar,
                "{compression:?}: the layer is not what was made"
            );
        }
        // the pull again of what is there fetches nothing
        let again = blob_offer(&own, &[&base, &top], compression);
        let pulled = again.pull(&own, engine_check()).await.unwrap();
        if own.remote {
            assert!(pulled.layers.iter().all(|l| l.report.fetched_files == 0));
        }
    }
}

/// A layer read whole costs the driver the files it asks for and no more: a
/// file the layer has under several names is one object, asked for and
/// fetched once, and a layer the store has asks for nothing.  (The files are
/// known by the hash of their content: what a driver holds under another
/// name, such as the fs-verity digest the reference server keeps, it asks for.)
pub async fn a_layer_read_whole_asks_only_for_what_the_store_lacks(f: &Factory) {
    use velarx_content::layer::writer::Compression;
    let (_tmp, s) = begin!(f, "a_layer_read_whole_asks_only_for_what_the_store_lacks");
    let (one, two) = chunked_layers();
    if !s.remote {
        // A driver of the engine's process keeps the files of its store,
        // named by their fs-verity digest: a file of a layer read whole that
        // the store has is recognised by it as the layer is read, not written
        // again, and counted as reused.
        let first = blob_offer(&s, &[&one], Compression::Gzip)
            .pull(&s, engine_check())
            .await
            .expect("the first layer");
        let r = &first.layers[0].report;
        assert_eq!((r.fetched_files, r.reused_files), (3, 0), "{r:?}");
        let sharing = blob_offer(&s, &[&two], Compression::Gzip)
            .pull(&s, engine_check())
            .await
            .expect("a layer that shares a file with it");
        let r = &sharing.layers[0].report;
        assert_eq!((r.fetched_files, r.reused_files), (1, 1), "{r:?}");
        // a store of its own has neither
        let cold_store = second(f, &s, "cold").await;
        let cold = blob_offer(&cold_store, &[&two], Compression::Gzip)
            .pull(&cold_store, engine_check())
            .await
            .expect("a cold pull");
        let r = &cold.layers[0].report;
        assert_eq!((r.fetched_files, r.reused_files), (2, 0), "{r:?}");
        return;
    }
    let wanted = |o: &Offer| -> Vec<usize> {
        o.meddle()
            .wanted
            .lock()
            .unwrap()
            .values()
            .map(HashSet::len)
            .collect()
    };
    // the second layer in a store of its own: both its files
    let cold_store = second(f, &s, "cold").await;
    let cold_offer = blob_offer(&cold_store, &[&two], Compression::Gzip);
    let cold = cold_offer
        .pull(&cold_store, engine_check())
        .await
        .expect("a cold pull");
    let r = &cold.layers[0].report;
    assert_eq!((r.fetched_files, r.reused_files), (2, 0), "{r:?}");
    assert_eq!(wanted(&cold_offer), [2], "the driver wants both files");
    // the layers, which the store has now: nothing is asked for
    blob_offer(&s, &[&one], Compression::Gzip)
        .pull(&s, engine_check())
        .await
        .expect("the first layer");
    blob_offer(&s, &[&two], Compression::Gzip)
        .pull(&s, engine_check())
        .await
        .expect("the second layer");
    let all = blob_offer(&s, &[&one, &two], Compression::Gzip);
    let again = all.pull(&s, engine_check()).await.expect("what is there");
    assert!(again.layers.iter().all(|l| l.report.fetched_files == 0));
    assert!(wanted(&all).iter().all(|n| *n == 0), "nothing is asked for");
    // a file that a layer has under three names and as a hard link is one
    // object: asked for once, fetched once
    let content = random(9, 50_000);
    let shared = Tar::new()
        .dir("d", 0o755)
        .file("d/a", &content, 0o644)
        .file("d/b", &content, 0o600)
        .file("d/c", &content, 0o644)
        .hardlink("d/h", "d/a")
        .done();
    let o = blob_offer(&s, &[&shared], Compression::Gzip);
    let pulled = o.pull(&s, engine_check()).await.expect("shared files");
    assert_eq!(pulled.layers[0].report.fetched_files, 1);
    assert_eq!(wanted(&o), [1], "the object is asked for once");
    let tar_back = {
        let stored = pulled.layers[0].clone();
        record(&s, &pulled).await;
        let l = open_layer_for(&s, &stored.key, &stored.diff_id)
            .await
            .unwrap();
        let mut out = Vec::new();
        l.verified_stream(Arc::new(DriverObjects::new(s.driver.clone())))
            .unwrap()
            .read_to_end(&mut out)
            .unwrap();
        out
    };
    assert!(tar_back == shared, "the three names read back");
}

/// A layer the engine reads whole that is not sound is refused, whatever the
/// way it is not: nothing of it is stored, the error is the driver's, and
/// the driver is left as it was.
pub async fn a_layer_read_whole_that_is_not_sound_stores_nothing(f: &Factory) {
    use velarx_content::layer::writer::Compression;
    let (_tmp, s) = begin!(f, "a_layer_read_whole_that_is_not_sound_stores_nothing");
    let base = base_layer();
    let before = s.driver.usage().unwrap();
    let refused = |what: &str, r: DriverResult<Pulled>| {
        let e = expect_err(r.map(|_| ()), what);
        of_driver(&s, &e);
        e
    };
    // a gzip stream that ends in the middle (its blob digest is right, the
    // bytes are what a registry or a disk gave)
    let o = blob_offer_with(&s, &[&base], Compression::Gzip, |_, b| {
        b[..b.len() / 2].to_vec()
    });
    refused("a cut blob", o.pull(&s, engine_check()).await);
    assert_eq!(s.driver.usage().unwrap(), before, "nothing was stored");
    // a tar whose last file ends before its size says (the blob is the cut
    // tar, and so is the diff id)
    let cut = base[..base.len() - 4096].to_vec();
    let mut o = blob_offer_with(&s, &[&base], Compression::None, |_, _| cut.clone());
    o.layers[0].diff_id = Digest::of(velarx_types::digest::Algorithm::Sha256, &cut);
    set_chains(&mut o.layers);
    refused("a cut tar", o.pull(&s, engine_check()).await);
    assert_eq!(s.driver.usage().unwrap(), before, "nothing was stored");
    // names that go outside a layer: the layer is refused by the engine
    // before the driver is asked to store anything, and nothing is made
    // outside the store
    let mut hostile = Tar::new().dir("d", 0o755);
    for name in ["../../escape", "/abs/escape", "d/../../escape2"] {
        let mut h = Tar::header(tar::EntryType::Regular, 0o644, 3);
        let n = name.as_bytes();
        h.as_gnu_mut().unwrap().name[..n.len()].copy_from_slice(n);
        h.set_cksum();
        hostile.0.append(&h, &b"abc"[..]).unwrap();
    }
    let hostile = hostile.file("d/ok", b"fine", 0o644).done();
    let mut o = blob_offer_with(&s, &[&base], Compression::None, |_, _| hostile.clone());
    o.layers[0].diff_id = Digest::of(velarx_types::digest::Algorithm::Sha256, &hostile);
    set_chains(&mut o.layers);
    refused(
        "names that leave the layer",
        o.pull(&s, engine_check()).await,
    );
    assert_eq!(s.driver.usage().unwrap(), before, "nothing was stored");
    for place in [s.dir.join("escape"), s.dir.join("escape2")] {
        assert!(!place.exists(), "{} was made", place.display());
    }
    if let Some(parent) = s.dir.parent() {
        assert!(!parent.join("escape").exists() && !parent.join("escape2").exists());
    }
    // a layer that inflates beyond the limits of `[pull]` (a small blob of
    // many zeros): refused as it is read, whatever the driver
    let bomb = Tar::new().file("zeros", &vec![0u8; 8 << 20], 0o644).done();
    let mut limits = Limits::from_config(&velarx_config::PullConfig::default());
    limits.max_layer_bytes = 1 << 20;
    let o = blob_offer_limited(&s, &[&bomb], Compression::Gzip, limits, |_, b| b.to_vec());
    let e = refused(
        "a layer that inflates too much",
        o.pull(&s, engine_check()).await,
    );
    assert!(e.to_string().contains("larger than"), "{e}");
    assert_eq!(s.driver.usage().unwrap(), before, "nothing was stored");
}

/// The feed writes the files a driver asks for of a layer it reads whole into
/// the files the driver hands over, at the places it chose, and into nothing
/// else: the keys it does not ask for are not written, and a place of
/// another size than the layer's is refused.
pub async fn a_feed_writes_a_layer_read_whole_into_the_files_a_driver_hands_over(f: &Factory) {
    use std::os::unix::fs::FileExt;
    use velarx_content::layer::writer::Compression;
    use velarx_content::pull::sink::{FilesSink, Slot, Written};
    let (_tmp, s) = begin!(
        f,
        "a_feed_writes_a_layer_read_whole_into_the_files_a_driver_hands_over"
    );
    let (one, _) = chunked_layers();
    let o = blob_offer(&s, &[&one], Compression::Gzip);
    let feed: &dyn PullFeed = &*o.feed;
    let layer = &o.layers[0];
    let scratch = s.dir.join("scratch");
    std::fs::create_dir_all(&scratch).unwrap();
    let begun = FilesIncoming::of(&new_pull_id(), FilesSink::none("test", &scratch));
    feed.begin(&begun).await.expect("a feed begins");
    let index = feed.index(layer).await.unwrap().expect("an index");
    assert_eq!(
        index.key,
        LayerKey::Whole(layer.descriptor.digest),
        "a layer read whole is the layer of its blob"
    );
    let entries: Vec<(String, u64, String)> = index
        .toc
        .entries
        .iter()
        .filter(|e| e.entry_type == TocEntryType::Reg && e.size > 0)
        .map(|e| (e.content_key().unwrap(), e.size, e.name.clone()))
        .collect();
    assert_eq!(entries.len(), 3);
    // the first in a file of its own, the second in a pack file from a base
    // that is not zero, the third not asked for
    let own = tempfile::tempfile().unwrap();
    let pack = tempfile::tempfile().unwrap();
    let told: Arc<Mutex<Vec<String>>> = Arc::default();
    let slots = vec![
        (
            entries[0].0.clone(),
            Slot {
                file: Arc::new(own.try_clone().unwrap()),
                base: 0,
                size: entries[0].1,
            },
        ),
        (
            entries[1].0.clone(),
            Slot {
                file: Arc::new(pack.try_clone().unwrap()),
                base: 8192,
                size: entries[1].1,
            },
        ),
    ];
    let sink = FilesSink::new("test", &scratch, slots, {
        let told = told.clone();
        move |w| {
            if let Written::Whole { key } = w {
                told.lock().unwrap().push(key);
            }
        }
    })
    .unwrap();
    let into = FilesIncoming::of(&begun.pull_id(), sink);
    let done = feed
        .fetch(layer, &into)
        .await
        .expect("a fetch into the files");
    assert_eq!(done.diff_id, layer.diff_id);
    let mut got = told.lock().unwrap().clone();
    got.sort();
    let mut want = vec![entries[0].0.clone(), entries[1].0.clone()];
    want.sort();
    assert_eq!(got, want, "what was asked for, and nothing else, is whole");
    let content = |file: &std::fs::File, base: u64, size: u64| {
        let mut bytes = vec![0u8; size as usize];
        file.read_exact_at(&mut bytes, base).unwrap();
        bytes
    };
    for (file, base, (key, size, _)) in [(&own, 0, &entries[0]), (&pack, 8192, &entries[1])] {
        let bytes = content(file, base, *size);
        let hash = Digest::of(velarx_types::digest::Algorithm::Sha256, &bytes);
        assert_eq!(&hash.to_string(), key);
    }
    assert_eq!(
        pack.metadata().unwrap().len(),
        8192 + entries[1].1,
        "the pack file ends where its last object does"
    );
    // a place of another size than the layer's is refused
    let wrong = FilesSink::new(
        "test",
        &scratch,
        [(
            entries[2].0.clone(),
            Slot {
                file: Arc::new(tempfile::tempfile().unwrap()),
                base: 0,
                size: entries[2].1 + 1,
            },
        )],
        |_| {},
    )
    .unwrap();
    let into = FilesIncoming::of(&begun.pull_id(), wrong);
    assert!(feed.fetch(layer, &into).await.is_err());
    feed.end();
    // a driver that fetches without having asked for the index: the layer is
    // read when it is fetched
    let again = blob_offer(&s, &[&one], Compression::Gzip);
    let feed: &dyn PullFeed = &*again.feed;
    feed.begin(&begun).await.expect("a feed begins");
    let told: Arc<Mutex<Vec<String>>> = Arc::default();
    let sink = FilesSink::new(
        "test",
        &scratch,
        [(
            entries[2].0.clone(),
            Slot {
                file: Arc::new(tempfile::tempfile().unwrap()),
                base: 0,
                size: entries[2].1,
            },
        )],
        {
            let told = told.clone();
            move |w| {
                if let Written::Whole { key } = w {
                    told.lock().unwrap().push(key);
                }
            }
        },
    )
    .unwrap();
    let into = FilesIncoming::of(&begun.pull_id(), sink);
    feed.fetch(&again.layers[0], &into)
        .await
        .expect("a fetch without an index");
    assert_eq!(*told.lock().unwrap(), [entries[2].0.clone()]);
    // the spool of the layer is a file with no name in the engine's directory
    // of the pull, open while the layer waits for its fetches, and gone with
    // the end of the pull
    let spools = || {
        std::fs::read_dir("/proc/self/fd")
            .unwrap()
            .filter_map(|e| std::fs::read_link(e.ok()?.path()).ok())
            .filter(|l| l.starts_with(&scratch))
            .count()
    };
    assert!(spools() >= 1, "the spool of the layer is open");
    feed.end();
    assert_eq!(spools(), 0, "the spool went with the end of the pull");
    // a place that is not zeros where the file has a hole: the copy keeps the
    // hole a hole, so the place reads back as other bytes than the key names;
    // the file is refused, not told whole
    let mut sparse = vec![0u8; 3 * 4096];
    sparse[0] = 1;
    sparse[3 * 4096 - 1] = 2;
    let holey = Tar::new().file("h", &sparse, 0o644).done();
    let third = blob_offer(&s, &[&holey], Compression::Gzip);
    let feed: &dyn PullFeed = &*third.feed;
    feed.begin(&begun).await.expect("a feed begins");
    let index = feed
        .index(&third.layers[0])
        .await
        .unwrap()
        .expect("an index");
    let key = index
        .toc
        .entries
        .iter()
        .find(|e| e.entry_type == TocEntryType::Reg && e.size > 0)
        .and_then(|e| e.content_key())
        .expect("the key of the file");
    let dirty = tempfile::tempfile().unwrap();
    dirty.write_all_at(&vec![0xaa; sparse.len()], 0).unwrap();
    let told: Arc<Mutex<Vec<String>>> = Arc::default();
    let sink = FilesSink::new(
        "test",
        &scratch,
        [(
            key.clone(),
            Slot {
                file: Arc::new(dirty.try_clone().unwrap()),
                base: 0,
                size: sparse.len() as u64,
            },
        )],
        {
            let told = told.clone();
            move |w| {
                if let Written::Whole { key } = w {
                    told.lock().unwrap().push(key);
                }
            }
        },
    )
    .unwrap();
    let into = FilesIncoming::of(&begun.pull_id(), sink);
    match feed.fetch(&third.layers[0], &into).await {
        // (a file system that keeps no holes: the zeros were written)
        Ok(_) => assert_eq!(content(&dirty, 0, sparse.len() as u64), sparse),
        Err(_) => assert!(
            told.lock().unwrap().is_empty(),
            "a file that reads back wrong is not told whole"
        ),
    }
    feed.end();
}

/// A file copied from the spool of a layer read whole keeps its holes, and
/// the driver is told of them (`zeros`) as it is for a layer fetched by
/// ranges; the spool goes when the driver releases the layer (it has every
/// file it lacks), before the pull ends, and a layer released twice is not an
/// error.
pub async fn a_layer_read_whole_tells_its_holes_and_frees_its_spool(f: &Factory) {
    use std::os::unix::fs::FileExt;
    use velarx_content::layer::writer::Compression;
    use velarx_content::pull::sink::{FilesSink, Slot, Written};
    let (_tmp, s) = begin!(f, "a_layer_read_whole_tells_its_holes_and_frees_its_spool");
    let mut sparse = vec![0u8; 4 * 4096];
    sparse[0] = 1;
    sparse[4 * 4096 - 1] = 2;
    let holey = Tar::new().file("h", &sparse, 0o644).done();
    let o = blob_offer(&s, &[&holey], Compression::Gzip);
    let feed: &dyn PullFeed = &*o.feed;
    let layer = &o.layers[0];
    let scratch = s.dir.join("scratch");
    std::fs::create_dir_all(&scratch).unwrap();
    let begun = FilesIncoming::of(&new_pull_id(), FilesSink::none("test", &scratch));
    feed.begin(&begun).await.expect("a feed begins");
    let index = feed.index(layer).await.unwrap().expect("an index");
    let key = index
        .toc
        .entries
        .iter()
        .find(|e| e.entry_type == TocEntryType::Reg && e.size > 0)
        .and_then(|e| e.content_key())
        .expect("the key of the file");
    let spools = || {
        std::fs::read_dir("/proc/self/fd")
            .unwrap()
            .filter_map(|e| std::fs::read_link(e.ok()?.path()).ok())
            .filter(|l| l.starts_with(&scratch))
            .count()
    };
    assert!(spools() >= 1, "the spool of the layer is open");
    let place = tempfile::tempfile().unwrap();
    let events: Arc<Mutex<Vec<(String, u64, u64)>>> = Arc::default();
    let whole: Arc<Mutex<Vec<String>>> = Arc::default();
    let sink = FilesSink::new(
        "test",
        &scratch,
        [(
            key.clone(),
            Slot {
                file: Arc::new(place.try_clone().unwrap()),
                base: 0,
                size: sparse.len() as u64,
            },
        )],
        {
            let (events, whole) = (events.clone(), whole.clone());
            move |w| match w {
                Written::Hole { key, at, len } => events.lock().unwrap().push((key, at, len)),
                Written::Whole { key } => whole.lock().unwrap().push(key),
                Written::Copy { .. } => panic!("a layer read whole copies nothing"),
                Written::Staged { .. } => panic!("a layer read whole stages nothing"),
            }
        },
    )
    .unwrap();
    let into = FilesIncoming::of(&begun.pull_id(), sink);
    feed.fetch(layer, &into).await.expect("a fetch");
    assert_eq!(*whole.lock().unwrap(), std::slice::from_ref(&key));
    let mut bytes = vec![0u8; sparse.len()];
    place.read_exact_at(&mut bytes, 0).unwrap();
    assert!(bytes == sparse, "the file is the layer's");
    // the holes the copy left are the ones told (a file system that cannot
    // tell holes leaves none and tells none)
    let told = events.lock().unwrap().clone();
    if !told.is_empty() {
        assert_eq!(
            told,
            [(key.clone(), 4096, 2 * 4096)],
            "the hole of the file"
        );
    }
    // released: the spool goes now, not with the end of the pull
    feed.release(layer);
    assert_eq!(spools(), 0, "the spool went with the release");
    feed.release(layer);
    // what is asked of a released layer is refused, not read whole again
    match feed.fetch(layer, &into).await {
        Err(e) => assert!(e.to_string().contains("released"), "{e}"),
        Ok(_) => panic!("a fetch of a released layer"),
    }
    match feed.index(layer).await {
        Err(e) => assert!(e.to_string().contains("released"), "{e}"),
        Ok(_) => panic!("an index of a released layer"),
    }
    assert_eq!(spools(), 0, "nothing was read again");
    feed.end();
}

pub async fn pull_reads_back_byte_for_byte(f: &Factory) {
    let (_tmp, s) = begin!(f, "pull_reads_back_byte_for_byte");
    for tar in [base_layer(), top_layer()] {
        let l = store_layer(&s, tar).await;
        let stored = open_layer_for(&s, &l.key, &l.diff_id)
            .await
            .expect("open_layer");
        assert_eq!(stored.diff_id, l.diff_id);
        assert_eq!(stored.stream_size().unwrap(), l.tar.len() as u64);
        // (the size the pull recorded is the one a listing reads)
        let recorded = s.db.get_layer(&l.key).await.expect("the layer's row");
        assert_eq!(recorded.stream_size, Some(l.tar.len() as i64));
        let mut out = Vec::new();
        stored
            .verified_stream(Arc::new(DriverObjects::new(s.driver.clone())))
            .unwrap()
            .read_to_end(&mut out)
            .unwrap();
        assert!(out == l.tar, "the layer is not what was pulled");
        // with the algorithm of the image's diff ids
        open_layer_for(&s, &l.key, &l.diff_id)
            .await
            .expect("open_layer in sha256");
    }
}

/// A layer whose table of contents names its files by the sha256 of their
/// content only (no fs-verity digest: what containers/storage writes) is
/// refused, naming the layer and the file, and nothing of it is stored: the
/// fs-verity digests are not made here, and the layer is not read as a
/// stream instead.
pub async fn a_layer_keyed_by_sha256_only_is_refused(f: &Factory) {
    let (_tmp, s) = begin!(f, "a_layer_keyed_by_sha256_only_is_refused");
    let reg = Registry::start().await;
    let tar = base_layer();
    let (layer, _) = chunked_layer_made(&reg, &tar, false, |d| d, |b| b.to_vec());
    let digest = layer.descriptor.digest;
    let mut layers = vec![layer];
    set_chains(&mut layers);
    let offer = Offer {
        feed: Arc::new(ArchiveFeed {
            layers: vec![(
                digest,
                registry_feed(&reg, &s.db, &s.dir, &layers[0].descriptor, false).await,
            )],
            meddle: Arc::default(),
        }),
        layers,
        _registry: Some(reg),
    };
    let refused = offer.pull(&s, engine_check()).await.err().expect("refused");
    let text = refused.to_string();
    assert!(text.contains(&digest.to_string()), "{text}");
    assert!(text.contains("no fs-verity digest for `"), "{text}");
}

/// A gzip layer of a registry, which has no table of contents to fetch by,
/// is read whole by the engine and its files are given to the driver as the
/// driver asks: pulled, it is stored and reads back byte for byte, for a
/// driver that keeps its files in another process as for one of this.  The
/// engine's copies of the files go with the pull, and with a pull of a layer
/// that is not its diff id.
pub async fn a_gzip_layer_of_a_registry_is_pulled_and_read_back(f: &Factory) {
    use velarx_content::layer::writer::Compression;
    let (_tmp, s) = begin!(f, "a_gzip_layer_of_a_registry_is_pulled_and_read_back");
    let reg = Registry::start().await;
    let tar = base_layer();
    let gzip_offer = |diff_id: fn(Digest) -> Digest| {
        let (layer, _) =
            registry_layer(&reg, &tar, Compression::Gzip, true, diff_id, |b| b.to_vec());
        let mut layers = vec![layer];
        set_chains(&mut layers);
        async {
            Offer {
                feed: Arc::new(ArchiveFeed {
                    layers: vec![(
                        layers[0].descriptor.digest,
                        registry_feed(&reg, &s.db, &s.dir, &layers[0].descriptor, false).await,
                    )],
                    meddle: Arc::default(),
                }),
                layers,
                _registry: None,
            }
        }
    };
    let staged = || {
        std::fs::read_dir(s.dir.join(velarx_content::pull::staged_fetch::LAYERS))
            .map(|d| d.flatten().map(|e| e.path()).collect::<Vec<_>>())
            .unwrap_or_default()
    };
    let wrong =
        gzip_offer(|_| Digest::of(velarx_types::digest::Algorithm::Sha256, b"another")).await;
    let e = expect_err(
        wrong.pull(&s, engine_check()).await.map(|_| ()),
        "a layer that is not its diff id",
    );
    assert!(e.to_string().contains("mismatch"), "{e}");
    assert_eq!(
        staged(),
        Vec::<std::path::PathBuf>::new(),
        "copies were left"
    );
    let offer = gzip_offer(|d| d).await;
    let pulled = offer.pull(&s, engine_check()).await.expect("pull");
    assert_eq!(
        staged(),
        Vec::<std::path::PathBuf>::new(),
        "copies were left"
    );
    let done = &pulled.layers[0];
    assert_eq!(done.key, LayerKey::Whole(offer.layers[0].descriptor.digest));
    record(&s, &pulled).await;
    let stored = open_layer_for(&s, &done.key, &done.diff_id)
        .await
        .expect("open_layer");
    let mut out = Vec::new();
    stored
        .verified_stream(Arc::new(DriverObjects::new(s.driver.clone())))
        .unwrap()
        .read_to_end(&mut out)
        .unwrap();
    assert!(out == tar, "the layer is not what was pulled");
}

pub async fn a_layer_that_is_not_stored_is_an_error(f: &Factory) {
    let (_tmp, s) = begin!(f, "a_layer_that_is_not_stored_is_an_error");
    let key = LayerKey::Whole(format!("sha256:{}", "ee".repeat(32)).parse().unwrap());
    let e = expect_err(open_layer(&s, &key, None).await.map(|_| ()), "open_layer");
    of_driver(&s, &e);
    // one kind for every driver: missing, mended by pulling the image again
    assert!(
        matches!(e.kind, DriverErrorKind::Missing { remedy } if remedy == Remedy::PullAgain),
        "{e:?}"
    );
    assert_eq!(e.remedy(), Some(Remedy::PullAgain));
    assert_eq!(e.layer.as_deref(), Some(key.to_string().as_str()));
    assert!(e.to_string().contains(&key.to_string()), "{e}");
    assert!(
        e.to_string().ends_with(Remedy::PullAgain.text(false)),
        "{e}"
    );
    assert!(matches!(ImageError::from(e), ImageError::Storage(_)));
}

// Which layers the driver has

fn layer_refs(layers: &[&Stored]) -> Vec<LayerRef> {
    let diffs: Vec<Digest> = layers.iter().map(|l| l.diff_id).collect();
    layers
        .iter()
        .zip(independent_chains(&diffs))
        .map(|(l, chain_id)| LayerRef {
            key: l.key,
            diff_id: l.diff_id,
            chain_id,
        })
        .collect()
}

/// `have` is the answer of `has_layers` to `asked` questions, and it is
/// false for every one.
fn none_of(have: &[bool], asked: usize) -> bool {
    have.len() == asked && have.iter().all(|h| !h)
}

/// A key no layer has.
fn unknown_layer() -> LayerRef {
    LayerRef {
        key: LayerKey::Whole(format!("sha256:{}", "ab".repeat(32)).parse().unwrap()),
        diff_id: format!("sha256:{}", "cd".repeat(32)).parse().unwrap(),
        chain_id: format!("sha256:{}", "cd".repeat(32)).parse().unwrap(),
    }
}

/// What the engine's collection does to the rows of the layers that no image
/// uses (`gc`): the driver's `collect` is the other half of it.
async fn forget_layer_rows(s: &Subject, keys: &[&LayerKey]) {
    let keys: Vec<String> = keys.iter().map(|k| k.to_string()).collect();
    s.db.conn()
        .call(move |conn| {
            for k in &keys {
                conn.execute("DELETE FROM file_refs WHERE layer_id = ?1", [k])?;
                conn.execute("DELETE FROM layers WHERE id = ?1", [k])?;
            }
            Ok(())
        })
        .await
        .unwrap();
}

pub async fn has_layers_reports_what_a_pull_stored(f: &Factory) {
    let (_tmp, s) = begin!(f, "has_layers_reports_what_a_pull_stored");
    let (base, top) = (
        store_layer(&s, base_layer()).await,
        store_layer(&s, top_layer()).await,
    );
    let both = layer_refs(&[&base, &top]);
    let have = s.driver.has_layers(&both).await.expect("has_layers");
    assert_eq!(have, [true, true], "the layers a pull stored");
    // one call answers for a whole pull: the layers, a stranger, a layer twice
    let unknown = unknown_layer();
    let asked: Vec<LayerRef> = [both[0].clone(), unknown.clone(), both[0].clone()].to_vec();
    let have = s.driver.has_layers(&asked).await.unwrap();
    assert_eq!(
        have,
        [true, false, true],
        "one answer for each layer asked, in order: an unknown key is not had, \
         a layer asked twice is had twice"
    );
    // only what is asked is answered
    let have = s.driver.has_layers(&both[1..]).await.unwrap();
    assert_eq!(have, [true]);
    assert!(s.driver.has_layers(&[]).await.unwrap().is_empty());
    // a key is the layer of one content: the diff id another image states
    // for it is not the layer
    let other = LayerRef {
        key: base.key,
        diff_id: top.diff_id,
        chain_id: top.diff_id,
    };
    // (a layer of a table of contents has no diff id of its own: its key
    // is the table that verified it, and the stream is checked against the
    // diff id of the image when it is read)
    assert_eq!(
        s.driver.has_layers(&[other]).await.unwrap(),
        [base.key.is_toc()],
        "a layer proven against another diff id is not the one asked"
    );
    // asking changes nothing (a question, not an action)
    let usage = s.driver.usage().unwrap();
    s.driver.has_layers(&both).await.unwrap();
    assert_eq!(s.driver.usage().unwrap(), usage);
}

pub async fn has_layers_does_not_report_what_is_not_committed(f: &Factory) {
    let (_tmp, s) = begin!(f, "has_layers_does_not_report_what_is_not_committed");
    remote_skip!(
        s,
        "has_layers_does_not_report_what_is_not_committed",
        "a layer is committed for a driver in another process by its Commit, not by the engine's record of the image"
    );
    let base = base_layer();
    // pulled into the store by the driver, the engine has not recorded it
    // (the window of a pull between the driver's commit and the image's): the
    // layer is not complete for the engine until it is
    let o = offer(&s, &[&base]).await;
    let mut pulled = o.pull(&s, engine_check()).await.expect("pull");
    let done = pulled.layers.remove(0);
    let asked = [LayerRef {
        key: done.key,
        diff_id: done.diff_id,
        chain_id: done.diff_id,
    }];
    assert_eq!(
        s.driver.has_layers(&asked).await.unwrap(),
        [false],
        "a layer no image records is not reported"
    );
    // an interrupted pull of two layers: neither is reported
    let (a, b) = (
        top_layer(),
        Tar::new().file("has-layers-other", b"zzz", 0o644).done(),
    );
    let cut = offer(&s, &[&a, &b]).await;
    *cut.meddle().fail_at.lock().unwrap() = Some(1);
    assert!(cut.pull(&s, engine_check()).await.is_err());
    let both = refs_of(&cut.stack(&[0, 1]));
    assert_eq!(s.driver.has_layers(&both).await.unwrap(), [false, false]);
    // a lazy layer waits in the staging area: it is not in the store
    if s.driver.capabilities().lazy {
        let lazy = offer(&s, &[&a]).await;
        lazy.meddle()
            .lazy
            .store(true, std::sync::atomic::Ordering::Relaxed);
        let mut pulled = lazy.pull(&s, engine_check()).await.expect("lazy pull");
        let staged = pulled.layers.remove(0);
        let asked = [LayerRef {
            key: staged.key,
            diff_id: staged.diff_id,
            chain_id: staged.diff_id,
        }];
        assert_eq!(
            s.driver.has_layers(&asked).await.unwrap(),
            [false],
            "a staged layer is not committed"
        );
    }
    // recorded: it is
    let mut commit = layer_commit(&done, None).unwrap();
    commit.record.erofs = Some(pulled.artifacts[&done.key].image_digest.clone());
    commit.record.owners = Some(pulled.artifacts[&done.key].owners.clone());
    s.db.commit_layers(vec![commit], vec![], vec![])
        .await
        .unwrap();
    assert_eq!(s.driver.has_layers(&asked).await.unwrap(), [true]);
}

pub async fn has_layers_forgets_what_a_collection_removed(f: &Factory) {
    let (_tmp, s) = begin!(f, "has_layers_forgets_what_a_collection_removed");
    let base = store_layer(&s, base_layer()).await;
    let top = store_layer(&s, top_layer()).await;
    let both = layer_refs(&[&base, &top]);
    assert_eq!(s.driver.has_layers(&both).await.unwrap(), [true, true]);
    // the only image that used `base` is removed: its layer goes with the
    // collection (the engine's forgets the rows, the driver's removes what
    // it keeps); the layer an image keeps stays
    s.driver.remove_image("img").unwrap();
    s.driver
        .collect(&Keep {
            layers: vec![top.key],
            ..Keep::default()
        })
        .unwrap();
    forget_layer_rows(&s, &[&base.key]).await;
    assert_eq!(
        s.driver.has_layers(&both).await.unwrap(),
        [false, true],
        "the collected layer is gone, the kept one stays"
    );
    s.driver.collect(&Keep::default()).unwrap();
    forget_layer_rows(&s, &[&top.key]).await;
    assert_eq!(s.driver.has_layers(&both).await.unwrap(), [false, false]);
    // and pulled again, it is there again
    let again = store_layer(&s, base_layer()).await;
    assert_eq!(
        s.driver.has_layers(&layer_refs(&[&again])).await.unwrap(),
        [true]
    );
}

pub async fn has_layers_does_not_report_a_layer_it_cannot_serve(f: &Factory) {
    let (_tmp, s) = begin!(f, "has_layers_does_not_report_a_layer_it_cannot_serve");
    remote_skip!(
        s,
        "has_layers_does_not_report_a_layer_it_cannot_serve",
        "the case damages the row of the layer in the engine's database, which a driver in another process does not read"
    );
    let base = store_layer(&s, base_layer()).await;
    let top = store_layer(&s, top_layer()).await;
    let both = layer_refs(&[&base, &top]);
    // a layer stored without its tar-split cannot be rebuilt as a stream
    // (push, save): it is pulled again, so it is not reported
    let key = base.key.to_string();
    s.db.conn()
        .call(move |conn| {
            conn.execute("UPDATE layers SET tarsplit = NULL WHERE id = ?1", [&key])?;
            Ok(())
        })
        .await
        .unwrap();
    assert_eq!(
        s.driver.has_layers(&both).await.unwrap(),
        [false, true],
        "a layer that is to be repaired by a pull is not reported"
    );
    // the pull that repairs it makes it complete again (the pull of a layer
    // that was stored is a repair, not an error)
    let again = offer(&s, &[&base_layer()]).await;
    let mut pulled = again.pull(&s, engine_check()).await.expect("repair");
    let done = pulled.layers.remove(0);
    assert_eq!(done.key, base.key);
    let artifact = pulled.artifacts[&done.key].clone();
    let mut commit = layer_commit(&done, None).unwrap();
    commit.record.erofs = Some(artifact.image_digest);
    commit.record.owners = Some(artifact.owners);
    s.db.commit_layers(vec![commit], vec![], vec![])
        .await
        .unwrap();
    assert_eq!(s.driver.has_layers(&both).await.unwrap(), [true, true]);
}

// Remake

pub async fn repair_gives_the_artifacts_again(f: &Factory) {
    let (_tmp, s) = begin!(f, "repair_gives_the_artifacts_again");
    let base = store_layer(&s, base_layer()).await;
    let top = store_layer(&s, top_layer()).await;
    let made = s
        .driver
        .repair(&layer_refs(&[&base, &top]))
        .await
        .expect("repair");
    assert_eq!(made[&base.key], base.artifact);
    assert_eq!(made[&top.key], top.artifact);
    assert!(s.driver.repair(&[]).await.unwrap().is_empty());
    // a damaged artifact is made again, and the check finds it mended
    let layers = records(&s, &[&base, &top]).await;
    let img = image("img", &[&base, &top]);
    if (s.damage)(&base.key) {
        let found = s.driver.check(&img, &layers, false).await.unwrap();
        assert!(
            found.iter().any(|p| p.repair),
            "damage that a remake mends: {found:?}"
        );
        s.driver.repair(&layer_refs(&[&base])).await.unwrap();
        let found = s.driver.check(&img, &layers, true).await.unwrap();
        assert!(found.is_empty(), "{found:?}");
    } else {
        eprintln!("NOTE conformance::repair_gives_the_artifacts_again: the driver damages nothing");
    }
}

pub async fn remake_staged_of_a_pull_that_is_not_there(f: &Factory) {
    let (_tmp, s) = begin!(f, "remake_staged_of_a_pull_that_is_not_there");
    let e = expect_err(
        s.driver.remake_staged("no-such-pull").await,
        "remake_staged",
    );
    of_driver(&s, &e);
    if s.driver.capabilities().lazy {
        assert!(matches!(e.kind, DriverErrorKind::NotFound), "{e:?}");
        assert!(matches!(ImageError::from(e), ImageError::NotFound(_)));
    } else {
        // no staged pulls: nothing to find, or not supported
        assert!(
            matches!(
                e.kind,
                DriverErrorKind::NotFound | DriverErrorKind::Unsupported
            ),
            "{e:?}"
        );
    }
}

pub async fn a_lazy_layer_waits_and_is_completed(f: &Factory) {
    let (_tmp, s) = begin!(f, "a_lazy_layer_waits_and_is_completed");
    if !s.driver.holds_objects() {
        skip!(
            "a_lazy_layer_waits_and_is_completed",
            "the driver keeps its own files: its layers are completed by a pull (see a_lazy_pull_is_staged_by_the_engine_and_completed_into_the_driver)"
        );
    }
    let c = s.driver.capabilities();
    let base = base_layer();
    let lazy = offer(&s, &[&base]).await;
    lazy.meddle()
        .lazy
        .store(true, std::sync::atomic::Ordering::Relaxed);
    let pulled = lazy.pull(&s, engine_check()).await;
    if !c.lazy {
        // a driver without lazy images refuses them, or keeps the layer whole
        if let Err(e) = pulled {
            assert!(matches!(e.kind, DriverErrorKind::Unsupported), "{e:?}");
        }
        return;
    }
    let mut pulled = pulled.unwrap();
    let done = pulled.layers.remove(0);
    let desc = lazy.layers[0].descriptor.clone();
    let artifact = pulled.artifacts[&done.key].clone();
    // the layer of an image that is being pulled is readable and has a plan
    let mut commit = layer_commit(&done, None).unwrap();
    commit.record.erofs = Some(artifact.image_digest.clone());
    commit.record.owners = Some(artifact.owners.clone());
    let record = commit.record.clone();
    let mut img = image("lazy", &[]);
    img.is_lazy = true;
    s.driver
        .image_view("lazy", std::slice::from_ref(&record))
        .expect("a view of a layer that is staged");
    publish_pull(&s, "lazy", &[done.key.to_string()]);
    let plan = plan_of(&s, &request(&img, std::slice::from_ref(&record)))
        .map(|r| r.plan)
        .expect("a plan of an image that is being pulled");
    check_plan(&plan);
    // the layer is staged with the pull the engine publishes: the driver
    // makes it again, and it is the one the pull recorded
    let area = velarx_content::pull::staged::Staging::new(&s.staging);
    velarx_content::pull::stage_layer(
        &area,
        &done,
        None,
        velarx_db::LayerReach::default(),
        false,
        (&artifact.image_digest, &artifact.owners),
    )
    .unwrap();
    let staged_pull = |id: &str| velarx_content::pull::staged::StagedPull {
        id: id.to_string(),
        manifest_digest: img_digest(),
        config_digest: img_digest(),
        manifest: "{}".into(),
        config: "{}".into(),
        layers: vec![done.key.to_string()],
        tags: vec![],
        digest_names: vec![],
        shareable: false,
        pulls: vec![],
        registry_ref: None,
        started_at: String::new(),
    };
    area.publish_pull(&staged_pull("p1")).unwrap();
    s.driver.remake_staged("p1").await.expect("remake_staged");
    s.driver
        .image_view("lazy", std::slice::from_ref(&record))
        .expect("readable after it was made again");
    // (a pull that records another digest than the layer makes is refused)
    let lying = velarx_content::pull::staged::NewLayer {
        meta: velarx_content::pull::staged::StagedLayerMeta {
            key: done.key.to_string(),
            blob: done.blob.to_string(),
            size: done.size,
            registry_ref: None,
            reach: velarx_db::LayerReach::default(),
            public: false,
            erofs: "sha256:00".into(),
            owners: artifact.owners.clone(),
            created_at: String::new(),
        },
        toc: &serde_json::to_string(&*done.toc).unwrap(),
        tarsplit: &done.tarsplit,
        toc_z: None,
    };
    area.remove_layer(&done.key).unwrap();
    area.publish_layer(&lying).unwrap();
    let e = expect_err(
        s.driver.remake_staged("p1").await,
        "a digest the pull did not record",
    );
    assert!(matches!(e.kind, DriverErrorKind::Contradicted), "{e:?}");
    area.remove_layer(&done.key).unwrap();
    // completed, it is the store's (the commit renames the staged image into
    // the store with the layer's files, one commit), and the plan is of a
    // complete image
    let commit_of = |recorded: &str| {
        let area = velarx_content::pull::staged::Staging::new(&s.staging);
        let (objects, stem) = (area.objects_stand_in(), done.key.file_stem());
        let files = area.layer_files(&done.key);
        let staging = [velarx_content::pull::commit::Staging {
            dir: &files,
            wants: Vec::new(),
            image: Some(velarx_content::pull::commit::StagedImage {
                objects: &objects,
                stem: &stem,
                alg: done.key.digest().alg(),
                recorded,
            }),
        }];
        velarx_content::pull::commit::commit_layer(&staging, &s.store, None, None)
            .expect("commit_layer")
            .remove(0)
            .image
    };
    // what the pull recorded is what is renamed: another digest is refused,
    // and the image stays where it was
    assert_eq!(
        commit_of("sha256:00"),
        Some(velarx_content::pull::commit::ImageStep::Wrong)
    );
    assert_eq!(
        commit_of(&artifact.image_digest),
        Some(velarx_content::pull::commit::ImageStep::Moved)
    );
    // (renamed, not copied: again, the store's is found to be the recorded one)
    assert_eq!(
        commit_of(&artifact.image_digest),
        Some(velarx_content::pull::commit::ImageStep::Moved)
    );
    assert_eq!(
        commit_of("sha256:00"),
        Some(velarx_content::pull::commit::ImageStep::Missing)
    );
    img.is_lazy = false;
    let plan = plan_of(&s, &request(&img, std::slice::from_ref(&record)))
        .map(|r| r.plan)
        .unwrap();
    check_plan(&plan);
    drop(desc);
}

// the root file system (`mounts` of a root, the plan of `writable_create`)

pub async fn rootfs_plan_of_a_request(f: &Factory) {
    let (_tmp, s) = begin!(f, "rootfs_plan_of_a_request");
    let base = store_layer(&s, base_layer()).await;
    let top = store_layer(&s, top_layer()).await;
    let layers = records(&s, &[&base, &top]).await;
    let img = image("img", &[&base, &top]);
    let plan = plan_of(&s, &request(&img, &layers))
        .map(|r| r.plan)
        .expect("a plan");
    check_plan(&plan);
    // the same request, the same plan
    assert_eq!(
        plan_of(&s, &request(&img, &layers))
            .map(|r| r.plan)
            .unwrap(),
        plan
    );
    // an image of no layer (scratch) is an image too (its plan, made with
    // the container: a mount needs a layer, and is not what is asked)
    let scratch = image("scratch", &[]);
    let w = Writable::new("scratch", s.dir.join("bundles/scratch"));
    let planned = s
        .driver
        .writable_create(
            &w,
            Some(ids()),
            &WritableOptions::default(),
            Some(&MountRequest {
                container: &w,
                ..request(&scratch, &[])
            }),
        )
        .expect("a plan of scratch")
        .expect("the plan of a root made of an image");
    check_plan(&planned.plan);
}

/// What `writable_create` says the root will be ([`Planned`]: the engine
/// writes the plan of the bundle from it, and labels the files when the
/// mount does not carry the label) is what `mounts` gives at every start;
/// with no image (`--rootfs`) there is nothing to say.
pub async fn the_plan_of_a_create_is_the_plan_of_every_start(f: &Factory) {
    let (_tmp, s) = begin!(f, "the_plan_of_a_create_is_the_plan_of_every_start");
    let base = store_layer(&s, base_layer()).await;
    let layers = records(&s, &[&base]).await;
    let img = image("img", &[&base]);
    let w = Writable::new("planned", s.dir.join("bundles/planned"));
    let ask = MountRequest {
        container: &w,
        ..request(&img, &layers)
    };
    let planned = s
        .driver
        .writable_create(&w, Some(ids()), &WritableOptions::default(), Some(&ask))
        .expect("writable_create")
        .expect("the plan of a root made of an image");
    check_plan(&planned.plan);
    for _ in 0..2 {
        let started = plan_of(&s, &ask).expect("the root at a start");
        assert_eq!(
            started.planned(),
            planned,
            "the start gives what the create said"
        );
    }
    // a label asked: the answer says where it is, the same at create and start
    let labelled = MountRequest {
        label: Some("system_u:object_r:container_file_t:s0:c1,c2"),
        ..ask.clone()
    };
    let w2 = Writable::new("labelled", s.dir.join("bundles/labelled"));
    let labelled = MountRequest {
        container: &w2,
        ..labelled
    };
    let at_create = s
        .driver
        .writable_create(
            &w2,
            Some(ids()),
            &WritableOptions::default(),
            Some(&labelled),
        )
        .expect("writable_create with a label")
        .expect("a plan");
    assert_eq!(
        plan_of(&s, &labelled)
            .expect("the root at a start")
            .planned(),
        at_create
    );
    // no image: no plan
    let bare = Writable::new("bare", s.dir.join("bundles/bare"));
    assert_eq!(
        s.driver
            .writable_create(&bare, Some(ids()), &WritableOptions::default(), None)
            .expect("writable_create of no image"),
        None
    );
    for w in [&w, &w2, &bare] {
        s.driver.writable_remove(w).unwrap();
    }
}

pub async fn rootfs_plan_of_a_missing_layer_says_its_remedy(f: &Factory) {
    let (_tmp, s) = begin!(f, "rootfs_plan_of_a_missing_layer_says_its_remedy");
    let base = store_layer(&s, base_layer()).await;
    let img = image("img", &[&base]);
    // not recorded
    let mut layers = records(&s, &[&base]).await;
    if s.remote {
        eprintln!("SKIPPED conformance::rootfs_plan_of_a_missing_layer_says_its_remedy (an artifact not recorded): a driver in another process plans from the records it keeps, not the ones the request carries");
    } else {
        layers[0].erofs = None;
        let e = expect_err(
            plan_of(&s, &request(&img, &layers)).map(|r| r.plan),
            "an artifact not recorded",
        );
        of_driver(&s, &e);
        assert!(matches!(e.kind, DriverErrorKind::Missing { .. }), "{e:?}");
        assert!(e.remedy().is_some());
        assert_eq!(e.layer.as_deref(), Some(base.key.to_string().as_str()));
        assert!(matches!(ImageError::from(e), ImageError::Storage(_)));
    }
    // recorded and gone
    let mut layers = records(&s, &[&base]).await;
    if (s.damage)(&base.key) {
        let e = expect_err(
            plan_of(&s, &request(&img, &layers)).map(|r| r.plan),
            "an artifact gone",
        );
        assert!(matches!(e.kind, DriverErrorKind::Missing { .. }), "{e:?}");
        assert!(e.remedy().is_some());
    }
    // a layer the driver never saw
    layers[0].key = LayerKey::Whole(format!("sha256:{}", "dd".repeat(32)).parse().unwrap());
    let e = expect_err(
        plan_of(&s, &request(&img, &layers)).map(|r| r.plan),
        "a layer never pulled",
    );
    assert!(matches!(e.kind, DriverErrorKind::Missing { .. }), "{e:?}");
}

pub async fn rootfs_plan_declared_limits_hold(f: &Factory) {
    let (_tmp, s) = begin!(f, "rootfs_plan_declared_limits_hold");
    let c = s.driver.capabilities();
    let base = store_layer(&s, base_layer()).await;
    let one = records(&s, &[&base]).await;
    let img = image("img", &[&base]);
    // max_layers counts the layers of a container (the driver's own data
    // layers too): more than it is refused with an error, not a panic
    let Some(max) = c.max_layers else {
        eprintln!("NOTE conformance::rootfs_plan_declared_limits_hold: no limit of layers");
        return;
    };
    let many: Vec<LayerRecord> = std::iter::repeat_n(one[0].clone(), max + 1).collect();
    let e = expect_err(
        plan_of(&s, &request(&img, &many)).map(|r| r.plan),
        "more layers than max_layers",
    );
    of_driver(&s, &e);
    assert!(matches!(ImageError::from(e), ImageError::Storage(_)));
    // a few are not a problem
    let few: Vec<LayerRecord> = std::iter::repeat_n(one[0].clone(), 3).collect();
    plan_of(&s, &request(&img, &few))
        .map(|r| r.plan)
        .expect("three layers");
    // and the limit is the one said: close to it is a plan (a driver's own
    // layers take no more than `OWN_LAYERS` of it)
    const OWN_LAYERS: usize = 4;
    let close: Vec<LayerRecord> =
        std::iter::repeat_n(one[0].clone(), max.saturating_sub(OWN_LAYERS)).collect();
    plan_of(&s, &request(&img, &close))
        .map(|r| r.plan)
        .unwrap_or_else(|e| panic!("{} layers of a limit of {max}: {e}", close.len()));
}

pub async fn rootfs_plan_verity_matches_the_capability(f: &Factory) {
    let (_tmp, s) = begin!(f, "rootfs_plan_verity_matches_the_capability");
    let c = s.driver.capabilities();
    let base = store_layer(&s, base_layer()).await;
    let layers = records(&s, &[&base]).await;
    let img = image("img", &[&base]);
    let enforced = MountRequest {
        verity: VerityAsk::Enforce {
            accepted: &[],
            chain: None,
        },
        ..request(&img, &layers)
    };
    let r = plan_of(&s, &enforced).map(|r| r.plan);
    let at_run = c
        .verity
        .iter()
        .any(|v| matches!(v, VerityEnforcement::OnOpen | VerityEnforcement::Kernel));
    if !at_run {
        // an explicit request is never weakened
        let e = expect_err(
            r,
            "enforcing verity at run time that the driver cannot enforce",
        );
        assert!(
            matches!(
                e.kind,
                DriverErrorKind::DigestEnforced | DriverErrorKind::Unsupported
            ),
            "{e:?}"
        );
        return;
    }
    // it can enforce it where the store has it: the view says whether
    let has = s.driver.image_view("img", &layers).unwrap().has_verity();
    match r {
        Ok(plan) => {
            assert!(has, "enforced on a store without verity");
            check_plan(&plan);
        }
        Err(e) => {
            assert!(!has, "refused on a store with verity: {e}");
            assert!(matches!(e.kind, DriverErrorKind::DigestEnforced), "{e:?}");
            assert!(matches!(
                ImageError::from(e),
                ImageError::ComposefsDigest(_)
            ));
        }
    }
}

pub async fn rootfs_plan_idmap_matches_the_capability(f: &Factory) {
    let (_tmp, s) = begin!(f, "rootfs_plan_idmap_matches_the_capability");
    let c = s.driver.capabilities();
    let base = store_layer(&s, base_layer()).await;
    let layers = records(&s, &[&base]).await;
    let img = image("img", &[&base]);
    let map = |size| velarx_fuse::IdTranslate {
        uid: vec![velarx_proto::pod::IdMapping {
            container_id: 0,
            host_id: 100_000,
            size,
        }],
        gid: vec![velarx_proto::pod::IdMapping {
            container_id: 0,
            host_id: 100_000,
            size,
        }],
        squash: false,
    };
    let covering = map(65_536);
    let r = plan_of(
        &s,
        &MountRequest {
            mapping: Some(&covering),
            translate: Some(identity_translate()),
            ..request(&img, &layers)
        },
    )
    .map(|r| r.plan);
    if c.root.idmap.is_empty() {
        let e = expect_err(r, "a mapping the driver has no support for");
        assert!(matches!(e.kind, DriverErrorKind::Unsupported), "{e:?}");
        return;
    }
    let plan = r.expect("a plan with a mapping that covers the owners");
    check_plan(&plan);
    // one that does not cover the owners (the image has files of root):
    // never silently the same as without
    let narrow = velarx_fuse::IdTranslate {
        uid: vec![velarx_proto::pod::IdMapping {
            container_id: 1000,
            host_id: 100_000,
            size: 1,
        }],
        gid: vec![velarx_proto::pod::IdMapping {
            container_id: 1000,
            host_id: 100_000,
            size: 1,
        }],
        squash: false,
    };
    if let Ok(r) = plan_of(
        &s,
        &MountRequest {
            mapping: Some(&narrow),
            translate: Some(&narrow),
            ..request(&img, &layers)
        },
    ) {
        assert!(
            r.fd.is_none() || r.idmap != IdmapDone::Applied,
            "owners outside of the mapping on idmapped mounts"
        );
    }
}

pub async fn the_kernel_mounts_what_the_status_says(f: &Factory) {
    let (_tmp, s) = begin!(f, "the_kernel_mounts_what_the_status_says");
    let Some(kernel) = s.kernel.clone() else {
        skip!(
            "the_kernel_mounts_what_the_status_says",
            "the driver has no kernel mount mode"
        );
    };
    let mounts = |d: &dyn StorageDriver| {
        d.status()
            .iter()
            .any(|(k, v)| k == "kernel mount" && v == "yes")
    };
    if !mounts(&*kernel) {
        skip!(
            "the_kernel_mounts_what_the_status_says",
            "no kernel mount here: {:?}",
            kernel.status()
        );
    }
    let base = store_layer(&s, base_layer()).await;
    let layers = records(&s, &[&base]).await;
    let img = image("img", &[&base]);
    // (a container of the subject's own directory: a driver that mounts
    // makes the upper layer of the root where the container is)
    let w = Writable::new("kernel", s.dir.join("bundles/kernel"));
    let req = MountRequest {
        container: &w,
        ..request(&img, &layers)
    };
    let planned = kernel
        .writable_create(&w, Some(ids()), &WritableOptions::default(), Some(&req))
        .expect("writable_create")
        .expect("a plan");
    assert!(
        matches!(planned.plan, RootfsPlan::MountFd(_)),
        "the status says the kernel mounts"
    );
    for _ in 0..2 {
        let r = rootfs_plan_of(&*kernel, &req).unwrap();
        // a mount the driver made comes with its descriptor, the first one,
        // and no process serves it: the kernel does
        match &r.plan {
            RootfsPlan::MountFd(m) => {
                assert_eq!(m.fd_index, 0);
                let fd = r.fd.expect("a mount-fd plan comes with its descriptor");
                assert!(is_dir_fd(&fd), "a directory");
                assert!(cloexec(&fd), "O_CLOEXEC");
                assert!(r.server.is_none(), "the kernel mounts, no process serves");
            }
            other => panic!("the status says the kernel mounts: {other:?}"),
        }
    }
    kernel.writable_remove(&w).unwrap();
    // a lazy image is served by the other way: its files are not all there
    let mut lazy = img.clone();
    lazy.is_lazy = true;
    if kernel.capabilities().lazy {
        let r = rootfs_plan_of(&*kernel, &request(&lazy, &layers)).unwrap();
        assert!(r.server.is_some(), "a process serves an image being pulled");
    }
    // and the default driver of the subject (not set to mount) does not
    let r = plan_of(&s, &request(&img, &layers)).unwrap();
    assert_eq!(r.server.is_none(), mounts(&*s.driver));
}

/// A driver that mounts for enforced digests measures the images it mounts
/// against the lists the request accepts, and says what it measured: the
/// engine takes a mount that enforces none for refused, and the monitor
/// measures what it mounts itself.
pub async fn an_enforced_mount_carries_what_the_driver_measured(f: &Factory) {
    let case = "an_enforced_mount_carries_what_the_driver_measured";
    let (_tmp, s) = begin!(f, case);
    let Some(kernel) = s.kernel.clone() else {
        skip!(case, "the driver has no kernel mount mode");
    };
    let base = store_layer(&s, base_layer()).await;
    let top = store_layer(&s, top_layer()).await;
    let layers = records(&s, &[&base, &top]).await;
    let img = image("img", &[&base, &top]);
    if !kernel
        .image_view("img", &layers)
        .is_ok_and(|view| view.has_verity())
    {
        skip!(case, "the store has no fs-verity here");
    }
    let accepted: Vec<Vec<String>> = layers
        .iter()
        .map(|l| l.erofs.iter().cloned().collect())
        .collect();
    let w = Writable::new("enforced", s.dir.join("bundles/enforced"));
    fn enforcing<'a>(
        (w, img, layers): (&'a Writable, &'a ImageRecord, &'a [LayerRecord]),
        lists: &'a [Vec<String>],
    ) -> MountRequest<'a> {
        MountRequest {
            container: w,
            verity: VerityAsk::Enforce {
                accepted: lists,
                chain: None,
            },
            ..request(img, layers)
        }
    }
    let of = (&w, &img, &layers[..]);
    let ask = |lists| enforcing(of, lists);
    kernel
        .writable_create(
            &w,
            Some(ids()),
            &WritableOptions::default(),
            Some(&ask(&accepted)),
        )
        .expect("writable_create");
    let r = rootfs_plan_of(&*kernel, &ask(&accepted)).unwrap();
    // (a store the kernel's EROFS does not mount, a tmpfs, is left to the
    // monitor: no mount, and nothing claimed)
    let mounted = matches!(r.plan, RootfsPlan::MountFd(_));
    if mounted {
        assert_eq!(r.verity, crate::VerityDone::Kernel);
        let want: Vec<String> = accepted.iter().flatten().cloned().collect();
        assert_eq!(r.measured, want, "the digests measured, layer by layer");
        assert!(r.fd.is_some());
    } else {
        assert_eq!(r.verity, crate::VerityDone::None);
        assert!(r.measured.is_empty() && r.fd.is_none());
    }
    // a list that does not name the image: never mounted (the driver says
    // which layer, and that the image is not the one named)
    if mounted {
        let wrong: Vec<Vec<String>> = accepted
            .iter()
            .enumerate()
            .map(|(i, _)| vec![format!("sha256:{:064x}", i + 1)])
            .collect();
        let e = expect_err(
            rootfs_plan_of(&*kernel, &ask(&wrong)),
            "a digest that is not the image's",
        );
        assert!(matches!(e.kind, DriverErrorKind::Corrupt { .. }), "{e:?}");
        let e = expect_err(
            rootfs_plan_of(&*kernel, &ask(&[])),
            "no list of digests for the layers",
        );
        assert!(matches!(e.kind, DriverErrorKind::Storage), "{e:?}");
    }
    kernel.writable_remove(&w).unwrap();
}

pub async fn a_lazy_image_has_a_plan_if_the_driver_is_lazy(f: &Factory) {
    let (_tmp, s) = begin!(f, "a_lazy_image_has_a_plan_if_the_driver_is_lazy");
    if !s.driver.holds_objects() {
        skip!(
            "a_lazy_image_has_a_plan_if_the_driver_is_lazy",
            "the driver keeps its own files: an image being pulled is the engine's, a layer it has is the driver's"
        );
    }
    let base = store_layer(&s, base_layer()).await;
    let layers = records(&s, &[&base]).await;
    let mut img = image("img", &[&base]);
    img.is_lazy = true;
    publish_pull(&s, "img", &[base.key.to_string()]);
    let r = plan_of(&s, &request(&img, &layers)).map(|r| r.plan);
    if s.driver.capabilities().lazy {
        let plan = r.expect("a lazy image");
        check_plan(&plan);
    } else {
        let e = expect_err(r, "a lazy image of a driver without lazy images");
        assert!(matches!(e.kind, DriverErrorKind::Unsupported), "{e:?}");
    }
}

// the lazy phase of a driver that keeps its own files

/// A driver that keeps its own files (a storage service) is given lazy
/// images by the engine: it says it is lazy, and the engine stages the layers
/// and runs the image from the files of its own.  The cases need the layers
/// as zstd:chunked blobs of a registry.
fn lazy_phase(s: &Subject, case: &str) -> bool {
    let lazy = s.driver.capabilities().lazy && !s.driver.holds_objects();
    if lazy && !s.chunked_only {
        eprintln!(
            "SKIPPED conformance::{case}: the layers are archives, a lazy pull needs a registry"
        );
        return false;
    }
    if !lazy {
        eprintln!(
            "SKIPPED conformance::{case}: the driver does not run lazy images for the engine"
        );
    }
    lazy
}

/// The layer `tar` as a lazy pull offers it: a blob of `reg` whose table of
/// contents gives the fs-verity digest of every file (`verity`) or the sha256
/// only, as a layer written by containers/storage has it.
async fn lazy_offer(s: &Subject, reg: &Registry, tar: &[u8], verity: bool) -> Offer {
    let (layer, _) = chunked_layer_made(reg, tar, verity, |d| d, |b| b.to_vec());
    let mut layers = vec![layer];
    set_chains(&mut layers);
    let feed = registry_feed(reg, &s.db, &s.dir, &layers[0].descriptor, true).await;
    Offer {
        feed: Arc::new(ArchiveFeed {
            layers: vec![(layers[0].descriptor.digest, feed)],
            meddle: Arc::default(),
        }),
        layers,
        _registry: None,
    }
}

/// A pool of the files of `tar`, by their fs-verity digest, as the engine
/// fills it while a lazy pull is completed.
fn pool_of(dir: &Path, tar: &[u8]) -> Arc<FileStore> {
    let pool = Arc::new(FileStore::new(dir).unwrap());
    let mut archive = tar::Archive::new(tar);
    for entry in archive.entries().unwrap() {
        let mut entry = entry.unwrap();
        if entry.header().entry_type() == tar::EntryType::Regular && entry.size() > 0 {
            let mut data = Vec::new();
            std::io::Read::read_to_end(&mut entry, &mut data).unwrap();
            pool.put(velarx_types::digest::Algorithm::Sha256, &data)
                .unwrap();
        }
    }
    pool
}

/// The layers of a lazy pull are staged by the engine and the driver has
/// none of them; the engine reads the image from the staged images.  When
/// the files are in the pool the driver pulls the layers from it, as it pulls
/// from a registry: it asks for the files it lacks, the engine copies them
/// into the places the driver gave and measures them, and reads each layer
/// back to prove its diff id.  Then the driver has the layers.
pub async fn a_lazy_pull_is_staged_by_the_engine_and_completed_into_the_driver(f: &Factory) {
    let case = "a_lazy_pull_is_staged_by_the_engine_and_completed_into_the_driver";
    let (_tmp, s) = begin!(f, case);
    if !lazy_phase(&s, case) {
        return;
    }
    let tar = base_layer();
    let reg = Registry::start_blocking();
    let lazy = lazy_offer(&s, &reg, &tar, true).await;
    let pulled = lazy.pull(&s, engine_check()).await.expect("a lazy pull");
    let done = pulled.layers[0].clone();
    assert!(done.lazy, "the layer is staged, not pulled");
    let artifact = pulled.artifacts[&done.key].clone();
    let refs = vec![LayerRef {
        key: done.key,
        diff_id: done.diff_id,
        chain_id: lazy.layers[0].chain_id,
    }];
    assert_eq!(
        s.driver.has_layers(&refs).await.unwrap(),
        vec![false],
        "the driver has nothing of a lazy layer"
    );
    // the image of the staged layer is the engine's to read
    let mut commit = layer_commit(&done, None).unwrap();
    commit.record.erofs = Some(artifact.image_digest.clone());
    commit.record.owners = Some(artifact.owners.clone());
    s.driver
        .image_view("lazy", std::slice::from_ref(&commit.record))
        .expect("the staged image is read");
    // completed: the driver pulls the layer from the pool
    let pool = pool_of(&s.dir.join("pool"), &tar);
    let index = LayerIndex {
        key: done.key,
        toc: done.toc.clone(),
        tarsplit: done.tarsplit.clone(),
    };
    let feed: Arc<dyn PullFeed> = Arc::new(StagedFeed::new(
        vec![index],
        Arc::new(StoreContent(vec![pool])),
        2,
    ));
    let layers = vec![FeedLayer {
        key: done.key,
        ..lazy.layers[0].clone()
    }];
    let completed = s
        .driver
        .pull(&feed, &layers, engine_check())
        .await
        .expect("the layer is pulled from the pool");
    assert!(!completed.layers[0].lazy);
    assert_eq!(s.driver.has_layers(&refs).await.unwrap(), vec![true]);
    // what the driver stored is what the layer holds
    let ranges: Vec<ObjectRange> = done
        .toc
        .entries
        .iter()
        .filter(|e| e.entry_type == TocEntryType::Reg && e.size > 0)
        .filter_map(|e| {
            Some(ObjectRange {
                key: e.content_key()?,
                offset: 0,
                length: e.size,
            })
        })
        .collect();
    let mut bytes: Vec<Vec<u8>> = vec![Vec::new(); ranges.len()];
    s.driver
        .read_objects(&ranges, &mut |i: usize, data: &[u8]| {
            bytes[i].extend_from_slice(data);
            Ok(())
        })
        .unwrap();
    assert!(
        bytes.iter().any(|b| b == &big()),
        "the files of the layer are read back"
    );
    assert!(bytes.iter().any(|b| b == b"old content"));
}

/// The engine copies from the pool only what measures as the key says, and
/// the driver proves the layer by reading it back: a file of the pool that is
/// not what its name says (the pool is the engine's, a file in it was
/// changed) is not stored, and the driver does not have the layer.
pub async fn a_staged_file_that_is_not_its_name_is_not_stored(f: &Factory) {
    let case = "a_staged_file_that_is_not_its_name_is_not_stored";
    let (_tmp, s) = begin!(f, case);
    if !lazy_phase(&s, case) {
        return;
    }
    let tar = base_layer();
    let reg = Registry::start_blocking();
    let lazy = lazy_offer(&s, &reg, &tar, true).await;
    let pulled = lazy.pull(&s, engine_check()).await.expect("a lazy pull");
    let done = pulled.layers[0].clone();
    let pool = pool_of(&s.dir.join("pool"), &tar);
    // a file of the pool with the bytes of another of the same size
    let big_key = done
        .toc
        .entries
        .iter()
        .find(|e| e.size == big().len() as u64)
        .and_then(|e| e.content_key())
        .expect("the big file");
    let path = pool.get_path(&big_key).expect("in the pool");
    let mut bytes = std::fs::read(&path).unwrap();
    bytes[100] ^= 0xff;
    std::fs::remove_file(&path).unwrap();
    std::fs::write(&path, bytes).unwrap();
    let feed: Arc<dyn PullFeed> = Arc::new(StagedFeed::new(
        vec![LayerIndex {
            key: done.key,
            toc: done.toc.clone(),
            tarsplit: done.tarsplit.clone(),
        }],
        Arc::new(StoreContent(vec![pool])),
        2,
    ));
    let layers = vec![FeedLayer {
        key: done.key,
        ..lazy.layers[0].clone()
    }];
    let e = expect_err(
        s.driver.pull(&feed, &layers, engine_check()).await,
        "a file that is not its name",
    );
    assert!(
        e.to_string().contains("reads back") || e.to_string().contains("mismatch"),
        "{e}"
    );
    let refs = vec![LayerRef {
        key: done.key,
        diff_id: done.diff_id,
        chain_id: lazy.layers[0].chain_id,
    }];
    assert_eq!(s.driver.has_layers(&refs).await.unwrap(), vec![false]);
}

/// A layer whose table of contents does not give the fs-verity digest of its
/// files is refused, lazily or not: the pull ends before a byte of it is
/// staged, naming the layer and the file, and the driver and the staging area
/// have nothing.
pub async fn a_lazy_pull_of_a_layer_without_file_digests_is_refused(f: &Factory) {
    let case = "a_lazy_pull_of_a_layer_without_file_digests_is_refused";
    let (_tmp, s) = begin!(f, case);
    if !lazy_phase(&s, case) {
        return;
    }
    let tar = base_layer();
    let reg = Registry::start_blocking();
    let lazy = lazy_offer(&s, &reg, &tar, false).await;
    let e = expect_err(
        lazy.pull(&s, engine_check()).await,
        "a layer without fs-verity digests",
    );
    let text = e.to_string();
    assert!(
        text.contains(&lazy.layers[0].descriptor.digest.to_string()),
        "{text}"
    );
    assert!(text.contains("no fs-verity digest for `"), "{text}");
    assert_eq!(lazy.fetches(), 0, "no layer was fetched");
    let area = velarx_content::pull::staged::Staging::new(&s.staging);
    assert!(area.layer_keys().is_empty(), "nothing is staged");
    let refs = vec![LayerRef {
        key: lazy.layers[0].key,
        diff_id: lazy.layers[0].diff_id,
        chain_id: lazy.layers[0].chain_id,
    }];
    assert_eq!(s.driver.has_layers(&refs).await.unwrap(), vec![false]);
}

// image_view and owners

pub async fn image_view_is_the_merge_of_the_layers(f: &Factory) {
    let (_tmp, s) = begin!(f, "image_view_is_the_merge_of_the_layers");
    let base = store_layer(&s, base_layer()).await;
    let top = store_layer(&s, top_layer()).await;
    let layers = records(&s, &[&base, &top]).await;
    let view = s.driver.image_view("img", &layers).expect("a view");
    let names = |dir: &str| -> Vec<String> {
        let d = view.resolve(dir).unwrap_or_else(|| panic!("no {dir}"));
        view.children(d)
            .unwrap()
            .into_iter()
            .map(|(n, _)| n)
            .collect()
    };
    // the directories merge, and the names are sorted
    assert_eq!(names(""), ["etc", "opt", "usr", "var"]);
    // a file of the layer above replaces the one below, a whiteout hides one
    let etc = names("etc");
    for kept in ["os-release", "old", "empty", "link", "hard"] {
        assert!(etc.contains(&kept.to_string()), "etc/{kept} in {etc:?}");
    }
    assert!(
        !etc.contains(&"gone".to_string()),
        "a whiteout hides etc/gone: {etc:?}"
    );
    assert!(
        !etc.iter().any(|n| n.starts_with(".wh.")),
        "a whiteout is not a file: {etc:?}"
    );
    // an opaque directory hides what is below it
    assert_eq!(names("opt"), ["y"]);
    let node = |path: &str| {
        view.node(view.resolve(path).unwrap_or_else(|| panic!("no {path}")))
            .unwrap()
    };
    let os = node("etc/os-release");
    // (the layer a file comes from is for the fetch of a lazy file: a view
    // read from a mount of the image has no layers to name)
    if !s.remote {
        assert_eq!(os.layer, 1, "the file of the top layer");
        assert_eq!(node("etc/old").layer, 0);
    }
    assert_eq!(
        (os.entry.entry_type, os.entry.size, os.entry.mode & 0o777),
        (TocEntryType::Reg, 3, 0o600)
    );
    assert_eq!(node("etc/old").entry.size, 11);
    assert_eq!(node("usr/lib/big").entry.size, big().len() as u64);
    assert_eq!(node("etc/empty").entry.size, 0);
    assert!(node("var").entry.mode & 0o777 == 0o700);
    // links: a symbolic link is followed as the kernel does, a hard link
    // is the same file (the file of the layer below, and of its name)
    assert_eq!(node("etc/link").entry.entry_type, TocEntryType::Symlink);
    let followed = view
        .resolve_following("etc/link")
        .expect("the target of the link");
    assert_eq!(
        view.node(followed).unwrap().entry.size,
        3,
        "the file of the top layer"
    );
    let (a, b) = (node("etc/hard"), node("etc/os-release"));
    // (a view of the tables of contents counts the links the layer that
    // made the file had; a mount shows the file as the merged tree has it,
    // where the other name was replaced)
    if s.remote {
        assert!(a.nlink >= 1);
    } else {
        assert_eq!(a.nlink, 2, "etc/hard and etc/os-release in the lower layer");
    }
    let _ = b;
    // what is not there
    assert!(view.resolve("etc/gone").is_none());
    assert!(view.lookup(VIEW_ROOT, "nothing").is_none());
    assert!(view.node(usize::MAX).is_none());
    // the view of the layer alone shows the layer alone
    let alone = s.driver.image_view("base", &layers[..1]).unwrap();
    assert!(alone.resolve("etc/gone").is_some());
    assert_eq!(
        alone
            .node(alone.resolve("etc/os-release").unwrap())
            .unwrap()
            .entry
            .size,
        4
    );
    assert!(alone.resolve("var").is_none());
    // the view has what the layers are made of: every name of their tables
    // of contents is in the view of the layer alone, of its type and size
    for e in &base.done.toc.entries {
        if matches!(e.entry_type, TocEntryType::Chunk) {
            continue;
        }
        let name = e.name.trim_end_matches('/');
        let id = alone
            .resolve(name)
            .unwrap_or_else(|| panic!("{name} is not in the view"));
        let n = alone.node(id).unwrap();
        if e.entry_type == TocEntryType::Reg {
            assert_eq!(n.entry.size, e.size, "{name}");
        }
        if e.entry_type != TocEntryType::Hardlink {
            assert_eq!(n.entry.entry_type, e.entry_type, "{name}");
        }
    }
}

/// The links of an image are names: followed inside the image (an absolute
/// target starts at its root, `..` stays in it), and one that leads out of it
/// or to a path of the host finds nothing.  A view that reads a mount of the
/// image must not let the kernel follow them.
pub async fn image_view_follows_links_only_inside_the_image(f: &Factory) {
    let (_tmp, s) = begin!(f, "image_view_follows_links_only_inside_the_image");
    let layer = Tar::new()
        .dir("etc", 0o755)
        .dir("usr", 0o755)
        .dir("usr/lib", 0o755)
        .file("etc/passwd", b"root:x:0:0::/root:/bin/sh\n", 0o644)
        .file("usr/lib/big", &big(), 0o755)
        .symlink("etc/absolute", "/etc/passwd")
        .symlink("etc/up", "../../../../../../etc/shadow")
        .symlink("etc/host", "/proc/self/exe")
        .symlink("etc/loop", "loop")
        .symlink("lib", "usr/lib")
        .symlink("etc/dir", "/usr")
        .done();
    let stored = store_layer(&s, layer).await;
    let layers = records(&s, &[&stored]).await;
    let view = s.driver.image_view("img", &layers).expect("a view");
    let size_of = |path: &str| {
        view.resolve_following(path)
            .and_then(|n| view.node(n))
            .map(|n| n.entry.size)
    };
    assert_eq!(
        size_of("etc/absolute"),
        Some(26),
        "an absolute link starts at the root of the image"
    );
    assert_eq!(size_of("lib/big"), Some(big().len() as u64));
    assert_eq!(size_of("etc/dir/lib/big"), Some(big().len() as u64));
    // a link is a node of its own, with the name it holds
    let up = view.node(view.resolve("etc/up").unwrap()).unwrap();
    assert_eq!(up.entry.entry_type, TocEntryType::Symlink);
    assert_eq!(
        up.entry.link_name.as_deref(),
        Some("../../../../../../etc/shadow")
    );
    // a name above the root of the image is not the host's
    assert_eq!(size_of("etc/up"), None);
    assert_eq!(size_of("etc/host"), None);
    assert_eq!(size_of("etc/loop"), None);
    // nothing is found below a link by a lookup that does not follow it
    assert!(view.resolve("lib/big").is_none());
}

/// Views of one image may be held at once and each reads on after the other
/// is dropped (a driver in another process hands a new mount for each,
/// `MountImage`, which the engine drops with the view); a view asked again
/// after all were dropped reads the same files.
pub async fn image_view_is_read_while_held_and_asked_again(f: &Factory) {
    let (_tmp, s) = begin!(f, "image_view_is_read_while_held_and_asked_again");
    let base = store_layer(&s, base_layer()).await;
    let top = store_layer(&s, top_layer()).await;
    let both = records(&s, &[&base, &top]).await;
    let digests: Vec<String> = both.iter().map(|l| l.key.to_string()).collect();
    let translate = velarx_fuse::IdTranslate::default();
    let read = |view: &Arc<dyn ImageTree>, path: &str| {
        TreeSource {
            tree: &**view,
            layers: &digests,
            objects: &*s.store,
            verity: s.store.verity(),
            fetcher: None,
            translate: &translate,
        }
        .read_file(path, 1 << 20)
        .expect("read")
    };
    let first = s.driver.image_view("img", &both).expect("a view");
    let second = s.driver.image_view("img", &both).expect("a second view");
    assert_eq!(read(&first, "etc/os-release").as_deref(), Some(&b"top"[..]));
    drop(first);
    assert_eq!(
        read(&second, "etc/old").as_deref(),
        Some(&b"old content"[..]),
        "a view read after another of the image was dropped"
    );
    assert_eq!(
        read(&second, "usr/lib/big").map(|b| b.len()),
        Some(big().len())
    );
    assert_eq!(read(&second, "etc/gone"), None);
    drop(second);
    let again = s.driver.image_view("img", &both).expect("asked again");
    assert_eq!(read(&again, "etc/os-release").as_deref(), Some(&b"top"[..]));
    assert_eq!(read(&again, "opt/x"), None, "the opaque directory");
}

pub async fn image_view_of_missing_layers_says_its_remedy(f: &Factory) {
    let (_tmp, s) = begin!(f, "image_view_of_missing_layers_says_its_remedy");
    let base = store_layer(&s, base_layer()).await;
    let mut layers = records(&s, &[&base]).await;
    layers[0].key = LayerKey::Whole(format!("sha256:{}", "dd".repeat(32)).parse().unwrap());
    let Err(e) = s.driver.image_view("img", &layers) else {
        panic!("a view of a layer the driver never pulled")
    };
    of_driver(&s, &e);
    assert!(matches!(e.kind, DriverErrorKind::Missing { .. }), "{e:?}");
    assert!(e.remedy().is_some());
    assert!(matches!(ImageError::from(e), ImageError::Storage(_)));
    layers[0].erofs = None;
    assert!(s.driver.image_view("img", &layers).is_err());
}

/// The owners the engine reads of the records of the layers
/// ([`crate::objects::image_owners`]) are those of the files of the layers,
/// whatever the driver: the record is the engine's identity.
pub async fn owners_are_those_of_the_layers(f: &Factory) {
    let (_tmp, s) = begin!(f, "owners_are_those_of_the_layers");
    let base = store_layer(&s, base_layer()).await;
    let layers = records(&s, &[&base]).await;
    let (uids, gids) = crate::objects::image_owners(&layers);
    assert_eq!((uids, gids), (vec![0], vec![0]));
    assert_eq!(crate::objects::image_owners(&[]), (vec![], vec![]));
    // the owners of the files of every layer, each once
    let users = store_layer(
        &s,
        Tar::new()
            .dir("home", 0o755)
            .owned("home/a", b"a", 1000, 100)
            .owned("home/b", b"b", 70_000, 100)
            .done(),
    )
    .await;
    let (mut uids, mut gids) = crate::objects::image_owners(&records(&s, &[&base, &users]).await);
    uids.sort_unstable();
    gids.sort_unstable();
    assert_eq!((uids, gids), (vec![0, 1000, 70_000], vec![0, 100]));
}

// remove_image, check, leftovers, collect, usage

pub async fn remove_image_forgets_only_the_image(f: &Factory) {
    let (_tmp, s) = begin!(f, "remove_image_forgets_only_the_image");
    let base = store_layer(&s, base_layer()).await;
    let layers = records(&s, &[&base]).await;
    let mut img = image("img", &[&base]);
    img.is_lazy = true;
    let _ = plan_of(&s, &request(&img, &layers)).map(|r| r.plan);
    let kept = (s.image_state)("kept");
    let marked = (s.image_state)("img");
    let before = s.driver.usage().unwrap();
    s.driver.remove_image("img").unwrap();
    if marked {
        let after = s.driver.usage().unwrap();
        assert!(
            after.artifacts.0 < before.artifacts.0,
            "the state of the image is gone: {before:?} -> {after:?}"
        );
    } else {
        eprintln!("NOTE conformance::remove_image_forgets_only_the_image: the driver keeps no state of an image");
    }
    // again, and one that was never there
    let before = s.driver.usage().unwrap();
    s.driver.remove_image("img").unwrap();
    s.driver.remove_image("never-there").unwrap();
    assert_eq!(s.driver.usage().unwrap(), before);
    // the state of another image stays
    if kept {
        s.driver.remove_image("other").unwrap();
        assert_eq!(s.driver.usage().unwrap(), before, "another image's state");
    }
    // the layers stay: they are another image's too
    s.driver
        .image_view("other", &layers)
        .expect("the layers are not the image's");
}

pub async fn check_finds_nothing_in_a_good_image(f: &Factory) {
    let (_tmp, s) = begin!(f, "check_finds_nothing_in_a_good_image");
    let base = store_layer(&s, base_layer()).await;
    let top = store_layer(&s, top_layer()).await;
    let layers = records(&s, &[&base, &top]).await;
    let img = image("img", &[&base, &top]);
    for full in [false, true] {
        let found = s.driver.check(&img, &layers, full).await.unwrap();
        assert!(found.is_empty(), "full={full}: {found:?}");
    }
    // a layer whose artifact is not recorded is a problem that a remake
    // mends
    remote_skip!(
        s,
        "check_finds_nothing_in_a_good_image (the part with a record changed)",
        "a driver in another process checks the records it keeps, not the ones the request carries"
    );
    let mut bad = layers.clone();
    bad[0].erofs = None;
    let found = s.driver.check(&img, &bad, false).await.unwrap();
    assert!(
        !found.is_empty()
            && found
                .iter()
                .all(|p| !p.kind.as_str().is_empty() && !p.message.is_empty())
    );
    assert!(found.iter().any(|p| p.repair));
}

pub async fn leftovers_are_not_what_the_rows_name(f: &Factory) {
    let (_tmp, s) = begin!(f, "leftovers_are_not_what_the_rows_name");
    remote_skip!(
        s,
        "leftovers_are_not_what_the_rows_name",
        "the objects of a driver in another process are its own, not the engine's `store`; its collection removes them"
    );
    let base = store_layer(&s, base_layer()).await;
    let recorded: HashSet<String> = base.objects.clone();
    assert!(!recorded.is_empty());
    // the objects are the engine's to scan (`objects::objects`): the files no
    // row names are orphans once they are old enough, and not before
    let root = s.store.root();
    let none = crate::objects::objects(root, &recorded, Duration::ZERO).unwrap();
    assert!(none.stray.is_empty() && none.orphans.is_empty(), "{none:?}");
    let orphans = crate::objects::objects(root, &HashSet::new(), Duration::ZERO).unwrap();
    assert!(!orphans.orphans.is_empty());
    let young = crate::objects::objects(root, &HashSet::new(), Duration::from_secs(3600)).unwrap();
    assert!(
        young.orphans.is_empty() && young.stray.is_empty(),
        "{young:?}"
    );
    // the driver names only its own temporary files, and none of a store it
    // just filled (and none that is young)
    let stray = s.driver.leftovers(Duration::from_secs(3600)).await.unwrap();
    assert!(stray.is_empty(), "{stray:?}");
    let stray = s.driver.leftovers(Duration::ZERO).await.unwrap();
    assert!(stray.is_empty(), "{stray:?}");
    // reading them removes nothing
    let layers = records(&s, &[&base]).await;
    s.driver.image_view("img", &layers).unwrap();
}

pub async fn collect_keeps_what_it_is_told_to_keep(f: &Factory) {
    let (_tmp, s) = begin!(f, "collect_keeps_what_it_is_told_to_keep");
    let base = store_layer(&s, base_layer()).await;
    let top = store_layer(&s, top_layer()).await;
    let both = records(&s, &[&base, &top]).await;
    let state = (s.image_state)("img");
    let before = s.driver.usage().unwrap();
    // everything kept: nothing freed, nothing reported, nothing changed
    let kept = s
        .driver
        .collect(&Keep {
            layers: vec![base.key, top.key],
            images: vec!["img".into()],
            ..Keep::default()
        })
        .unwrap();
    assert_eq!((kept.bytes_freed, kept.errors.len()), (0, 0), "{kept:?}");
    assert_eq!(s.driver.usage().unwrap(), before);
    s.driver
        .image_view("img", &both)
        .expect("kept layers are readable");
    // only the top one: the other goes, and what was kept is still read
    let some = s
        .driver
        .collect(&Keep {
            layers: vec![top.key],
            ..Keep::default()
        })
        .unwrap();
    assert!(some.errors.is_empty(), "{some:?}");
    assert!(some.bytes_freed > 0);
    s.driver
        .image_view("top", &both[1..])
        .expect("the kept layer");
    let Err(e) = s.driver.image_view("base", &both[..1]) else {
        panic!("the layer that was not kept is collected")
    };
    assert!(matches!(e.kind, DriverErrorKind::Missing { .. }), "{e:?}");
    // an image that is kept is not removed by the collection of its layers
    let after = s.driver.usage().unwrap();
    let again = s
        .driver
        .collect(&Keep {
            layers: vec![top.key],
            images: vec!["img".into()],
            ..Keep::default()
        })
        .unwrap();
    assert_eq!(again.bytes_freed, 0);
    assert_eq!(s.driver.usage().unwrap(), after);
    // nothing kept: nothing of the layers is left, nor of the image
    let all = s.driver.collect(&Keep::default()).unwrap();
    assert!(all.errors.is_empty(), "{all:?}");
    assert!(all.bytes_freed > 0);
    if state {
        assert!(
            s.driver.usage().unwrap().artifacts.0 < after.artifacts.0,
            "the state of an image that is not kept goes"
        );
    }
    assert!(s.driver.image_view("top", &both[1..]).is_err());
    // collecting what is not there is not an error
    let nothing = s.driver.collect(&Keep::default()).unwrap();
    assert_eq!((nothing.bytes_freed, nothing.errors.len()), (0, 0));
}

// Read-back of the stored objects

/// What a sink collects: the bytes of each range, and the order they came in.
#[derive(Default)]
struct Collect {
    ranges: BTreeMap<usize, Vec<u8>>,
    order: Vec<usize>,
}

impl ObjectSink for Collect {
    fn data(&mut self, range: usize, bytes: &[u8]) -> std::io::Result<()> {
        if self.order.last() != Some(&range) {
            self.order.push(range);
        }
        self.ranges
            .entry(range)
            .or_default()
            .extend_from_slice(bytes);
        Ok(())
    }
}

/// The key and the content of the file `name` of a stored layer.
fn object_of(l: &Stored, name: &str, tar: &[u8]) -> (String, Vec<u8>) {
    let e = l
        .done
        .toc
        .entries
        .iter()
        .find(|e| e.name.trim_end_matches('/') == name)
        .unwrap_or_else(|| panic!("{name} is in the layer"));
    let content = tar::Archive::new(tar)
        .entries()
        .unwrap()
        .map(|x| x.unwrap())
        .find(|x| x.path().unwrap().to_string_lossy().trim_end_matches('/') == name)
        .map(|mut x| {
            let mut v = Vec::new();
            x.read_to_end(&mut v).unwrap();
            v
        })
        .unwrap();
    (e.verity().expect("a file with content has a key"), content)
}

pub async fn read_objects_gives_the_ranges_of_stored_objects(f: &Factory) {
    let (_tmp, s) = begin!(f, "read_objects_gives_the_ranges_of_stored_objects");
    let tar = base_layer();
    let l = store_layer(&s, tar.clone()).await;
    let (big_key, big_bytes) = object_of(&l, "usr/lib/big", &tar);
    let (os_key, os_bytes) = object_of(&l, "etc/os-release", &tar);
    let d = &s.driver;
    // the whole object, a range inside it, one that ends at its end, and an
    // empty one, in the order asked and for the index asked
    let ranges = [
        ObjectRange::whole(&big_key, big_bytes.len() as u64),
        ObjectRange {
            key: big_key.clone(),
            offset: 100,
            length: 50,
        },
        ObjectRange {
            key: os_key.clone(),
            offset: 1,
            length: os_bytes.len() as u64 - 1,
        },
        ObjectRange {
            key: big_key.clone(),
            offset: big_bytes.len() as u64,
            length: 0,
        },
        ObjectRange {
            key: big_key.clone(),
            offset: big_bytes.len() as u64 - 7,
            length: 7,
        },
    ];
    let mut got = Collect::default();
    d.read_objects(&ranges, &mut got).expect("read_objects");
    assert_eq!(
        got.order,
        vec![0, 1, 2, 4],
        "in order; an empty range gives nothing"
    );
    assert!(got.ranges[&0] == big_bytes, "the whole object");
    assert_eq!(got.ranges[&1], &big_bytes[100..150]);
    assert_eq!(got.ranges[&2], &os_bytes[1..]);
    assert_eq!(got.ranges[&4], &big_bytes[big_bytes.len() - 7..]);
    // no ranges: nothing
    let mut none = Collect::default();
    d.read_objects(&[], &mut none).unwrap();
    assert!(none.order.is_empty());
    // the object as a file: exactly its bytes, from the start
    let mut file = d
        .open_object(&big_key, big_bytes.len() as u64)
        .expect("open_object");
    let mut all = Vec::new();
    file.read_to_end(&mut all).unwrap();
    assert!(all == big_bytes);
    // a sink that fails ends the read with its error
    let e = expect_err(
        d.read_objects(&ranges, &mut |_: usize, _: &[u8]| {
            Err(std::io::Error::from_raw_os_error(libc::EPIPE))
        }),
        "a failing sink",
    );
    assert_eq!(e.into_io().raw_os_error(), Some(libc::EPIPE));
}

/// What a driver behind a pipe gives, read the way the engine reads it
/// ([`crate::longcall::read_pipe_ranges`]): the reply of a range before its
/// bytes, the pipe polled under the deadline.  The pipe holds less than the
/// object (`F_GETPIPE_SZ` is shrunk to a page), so a driver that wrote before
/// its reply, or an engine that read the pipe before the reply, would block
/// on a full pipe: neither does.
pub async fn a_range_larger_than_a_pipe_is_read_after_its_reply(f: &Factory) {
    use std::io::Write;
    let (_tmp, s) = begin!(f, "a_range_larger_than_a_pipe_is_read_after_its_reply");
    let tar = base_layer();
    let l = store_layer(&s, tar.clone()).await;
    let (key, bytes) = object_of(&l, "usr/lib/big", &tar);
    let ranges = vec![
        ObjectRange::whole(&key, bytes.len() as u64),
        ObjectRange {
            key: key.clone(),
            offset: 5,
            length: 0,
        },
        ObjectRange {
            key: key.clone(),
            offset: 100,
            length: bytes.len() as u64 - 100,
        },
    ];
    let (r, w) = rustix::pipe::pipe_with(rustix::pipe::PipeFlags::CLOEXEC).unwrap();
    rustix::pipe::fcntl_setpipe_size(&w, 4096).unwrap();
    let pipe_size = rustix::pipe::fcntl_getpipe_size(&w).unwrap();
    assert!(
        (pipe_size as usize) < bytes.len(),
        "the object ({}) is larger than the pipe ({pipe_size})",
        bytes.len()
    );
    let (tx, rx) = std::sync::mpsc::channel::<usize>();
    // the driver's end of a ReadObjects call: the reply of every range up to
    // the one whose bytes are written, and then its bytes
    let (driver, asked) = (s.driver.clone(), ranges.clone());
    let server = std::thread::spawn(move || {
        let mut w = std::fs::File::from(w);
        let mut replied = 0usize;
        let r = driver.read_objects(&asked, &mut |i: usize, data: &[u8]| {
            while replied <= i {
                tx.send(replied).map_err(std::io::Error::other)?;
                replied += 1;
            }
            w.write_all(data)
        });
        // (the ranges that gave no bytes are answered too)
        while replied < asked.len() {
            let _ = tx.send(replied);
            replied += 1;
        }
        r
    });
    let pipe = std::fs::File::from(r);
    let mut got = Collect::default();
    crate::longcall::read_pipe_ranges(
        &ranges,
        &mut |wait| Ok(rx.recv_timeout(wait).ok()),
        &pipe,
        &mut crate::longcall::IdleDeadline::new(Duration::from_secs(20)),
        &mut got,
    )
    .expect("the bytes after their replies");
    server.join().unwrap().expect("the driver's read");
    assert_eq!(got.order, vec![0, 2]);
    assert!(got.ranges[&0] == bytes);
    assert!(got.ranges[&2] == bytes[100..]);
}

pub async fn more_ranges_than_a_call_takes_are_read_in_order(f: &Factory) {
    let (_tmp, s) = begin!(f, "more_ranges_than_a_call_takes_are_read_in_order");
    let base = store_layer(&s, base_layer()).await;
    let max = s.driver.capabilities().limits.ranges;
    assert!(max > 0, "a driver states how many ranges a call takes");
    // a whole object, asked for again and again past the limit: a layer
    // of more files than `max` is read in more than one call
    let key = base
        .done
        .toc
        .entries
        .iter()
        .find(|e| e.size > 0 && e.verity().is_some())
        .expect("a file with content");
    let (name, size) = (key.verity().unwrap().to_string(), key.size);
    let ranges: Vec<ObjectRange> = (0..2 * max + 7)
        .map(|n| ObjectRange {
            key: name.clone(),
            offset: (n as u64) % size,
            length: size - (n as u64) % size,
        })
        .collect();
    let mut got: Vec<Vec<u8>> = vec![Vec::new(); ranges.len()];
    read_objects_in_batches(&*s.driver, &ranges, &mut |i: usize, b: &[u8]| {
        got[i].extend_from_slice(b);
        Ok(())
    })
    .expect("the ranges, in calls of the limit");
    let whole = &got[0];
    assert_eq!(whole.len() as u64, size);
    for (n, bytes) in got.iter().enumerate() {
        assert_eq!(bytes[..], whole[n % size as usize..], "range {n}");
    }
}

/// The objects a reader takes in the order of a list (`ObjectOpener::ordered`,
/// what push, save, export and a squash read a layer with) are the objects
/// `open_object` gives, whether the driver reads ahead or not: each file of
/// a layer, in the order of its table of contents, then one asked for again,
/// one the list does not name and one that is not there.
pub async fn objects_taken_in_order_are_the_objects_of_open_object(f: &Factory) {
    use velarx_storage::ObjectOpener;
    let (_tmp, s) = begin!(f, "objects_taken_in_order_are_the_objects_of_open_object");
    let l = store_layer(&s, base_layer()).await;
    let order = velarx_content::pull::stream::FileUse::objects_of_toc(&l.done.toc);
    assert!(!order.is_empty(), "a layer with files");
    let plain = DriverObjects::new(s.driver.clone());
    let opener = plain.ordered(&mut || order.clone());
    let opener: &dyn ObjectOpener = opener.as_deref().unwrap_or(&plain);
    let read = |o: &dyn ObjectOpener, key: &str, size: u64| {
        let mut bytes = Vec::new();
        o.object_file(key, size)?.read_to_end(&mut bytes)?;
        Ok::<_, std::io::Error>(bytes)
    };
    for (key, size) in &order {
        let want = read(&plain, key, *size).expect("open_object");
        assert_eq!(read(opener, key, *size).expect("in order"), want, "{key}");
    }
    // asked for again, and in another order
    for (key, size) in order.iter().rev() {
        let want = read(&plain, key, *size).expect("open_object");
        assert_eq!(read(opener, key, *size).expect("again"), want, "{key}");
    }
    // not a key of the list: the error of a read alone
    let err = read(
        opener,
        "sha256:00000000000000000000000000000000000000000000000000000000000000ff",
        3,
    )
    .expect_err("an object that is not there");
    let alone = read(
        &plain,
        "sha256:00000000000000000000000000000000000000000000000000000000000000ff",
        3,
    )
    .expect_err("an object that is not there");
    assert_eq!(err.kind(), alone.kind(), "{err} / {alone}");
}

pub async fn read_objects_errors_are_typed(f: &Factory) {
    let (_tmp, s) = begin!(f, "read_objects_errors_are_typed");
    let tar = base_layer();
    let l = store_layer(&s, tar.clone()).await;
    let (key, bytes) = object_of(&l, "usr/lib/big", &tar);
    let d = &s.driver;
    let len = bytes.len() as u64;
    let missing = |e: &DriverError| {
        assert!(
            matches!(e.kind, DriverErrorKind::Missing { remedy } if remedy == Remedy::PullAgain),
            "{e:?}"
        );
        assert_eq!(e.remedy(), Some(Remedy::PullAgain));
    };
    let corrupt = |e: &DriverError| {
        assert!(matches!(e.kind, DriverErrorKind::Corrupt { .. }), "{e:?}");
        assert_eq!(e.remedy(), Some(Remedy::PullAgain));
    };
    // past the end of the object: the engine's index says it has the bytes,
    // so a short object is a corrupt one, and nothing of that range is given
    for (offset, length) in [
        (0, len + 1),
        (len, 1),
        (len - 3, 4),
        (u64::MAX, 2),
        (1, u64::MAX),
    ] {
        let mut got = Collect::default();
        let e = expect_err(
            d.read_objects(
                &[ObjectRange {
                    key: key.clone(),
                    offset,
                    length,
                }],
                &mut got,
            ),
            "past the end",
        );
        of_driver(&s, &e);
        corrupt(&e);
        assert!(
            got.order.is_empty(),
            "nothing is given of a range past the end"
        );
    }
    // the size the index says is the size the object has
    for size in [len - 1, len + 1, 0] {
        let e = expect_err(d.open_object(&key, size), "the wrong size");
        of_driver(&s, &e);
        corrupt(&e);
    }
    // an object that is not there (a well formed key, and the other
    // algorithm's key for the same name)
    let absent = format!("fsverity-sha256-12:{}", "ab".repeat(32));
    let absent512 = format!("fsverity-sha512-12:{}", "ab".repeat(64));
    for k in [&absent, &absent512] {
        let e = expect_err(
            d.read_objects(&[ObjectRange::whole(k, 1)], &mut Collect::default()),
            "a missing object",
        );
        of_driver(&s, &e);
        missing(&e);
        let e = expect_err(d.open_object(k, 1), "a missing object");
        missing(&e);
    }
    // a range after one that is good is not read when the first one fails
    let mut got = Collect::default();
    let e = expect_err(
        d.read_objects(
            &[
                ObjectRange::whole(&absent, 1),
                ObjectRange::whole(&key, len),
            ],
            &mut got,
        ),
        "the first range fails",
    );
    missing(&e);
    assert!(got.order.is_empty());
    // a key that is no object's name reads nothing, whatever it says: no
    // path, no link, no other file of the store
    let secret = s.dir.join("secret");
    std::fs::write(&secret, b"secret").unwrap();
    let mut hostile = vec![
        "../secret".to_string(),
        "../../secret".to_string(),
        format!("{}", secret.display()),
        "/etc/passwd".to_string(),
        "..".to_string(),
        ".".to_string(),
        "".to_string(),
        "ab/".to_string(),
        "fsverity-sha256-12:../secret".to_string(),
        format!("fsverity-sha256-12:{}/../../x", "ab".repeat(30)),
        format!("fsverity-sha256-12:{}\0", "ab".repeat(32)),
        format!("{}\n", key),
        format!("{} ", key),
        key.to_uppercase(),
        key.replace("fsverity-sha256-12:", "sha256:"),
        "fsverity-sha256-12:é".to_string(),
        "x".repeat(10_000),
    ];
    // (the name of an object by its path below the objects, as the store has
    // it, is no key either)
    if let Some(rel) = velarx_storage::Object::new(&key, false).map(|o| o.rel()) {
        hostile.push(rel);
    }
    for k in &hostile {
        let mut got = Collect::default();
        let e = expect_err(
            d.read_objects(&[ObjectRange::whole(k, 6)], &mut got),
            "a hostile key",
        );
        of_driver(&s, &e);
        missing(&e);
        assert!(got.order.is_empty(), "{k:?}");
        missing(&expect_err(d.open_object(k, 6), "a hostile key"));
    }
    // and the error names no raw control byte of the key
    let e = expect_err(
        d.read_objects(
            &[ObjectRange::whole("a\x1b[31mb", 1)],
            &mut Collect::default(),
        ),
        "a key with an escape",
    );
    assert!(!e.to_string().contains('\x1b'), "{e}");
}

/// What a collection keeps of what a live container and a pull in progress
/// use: the writable layer of a container is never collected, whether or not
/// the engine names it; the layers its image is made of are named in
/// `Keep::layers` (the engine names the layers of every image, and an image a
/// container uses is never removed) and are read as before; what the driver
/// holds for a pull in progress stays until the pull ends.
pub async fn collect_never_removes_what_a_container_or_a_pull_uses(f: &Factory) {
    let Some(c) = changed(f, "collect_never_removes_what_a_container_or_a_pull_uses").await else {
        return;
    };
    let (s, w) = (&c.s, &c.w);
    let keys: Vec<LayerKey> = c.layers.iter().map(|l| l.key).collect();
    let upper = paths(s, w).upper;
    let changes = |what: &str| {
        assert!(
            s.driver.writable_exists(w).unwrap(),
            "{what}: the layer of the container"
        );
        assert_eq!(
            std::fs::read(upper.join("etc/new")).unwrap_or_default(),
            b"new file",
            "{what}: what the container wrote"
        );
    };
    changes("before");
    // a pull in progress holds some state of its own (the same state an image
    // has, under the id of the pull)
    let pulled = (s.image_state)("pull-1");
    let held = s.driver.usage().unwrap();
    // the container, its layers and the pull are named: nothing is removed
    let kept = s
        .driver
        .collect(&Keep {
            layers: keys.clone(),
            containers: vec!["c".into()],
            pulls: vec!["pull-1".into()],
            ..Keep::default()
        })
        .unwrap();
    assert_eq!((kept.bytes_freed, kept.errors.len()), (0, 0), "{kept:?}");
    assert_eq!(
        s.driver.usage().unwrap(),
        held,
        "nothing of the pull was removed"
    );
    changes("kept");
    s.driver
        .image_view("img", &c.layers)
        .expect("the layers of the container are read as before");
    // the pull is over: what it held goes, the container's layer stays
    let pull_over = s
        .driver
        .collect(&Keep {
            layers: keys.clone(),
            containers: vec!["c".into()],
            ..Keep::default()
        })
        .unwrap();
    assert!(pull_over.errors.is_empty(), "{pull_over:?}");
    if pulled {
        assert!(
            s.driver.usage().unwrap().artifacts.0 < held.artifacts.0,
            "what a pull held goes when it is over"
        );
    }
    changes("the pull is over");
    s.driver
        .image_view("img", &c.layers)
        .expect("the layers are still read");
    // the container's layer is the driver's to keep even when a collection is
    // told of nothing else: it removes what it made of layers, not that
    let all = s
        .driver
        .collect(&Keep {
            containers: vec!["c".into()],
            ..Keep::default()
        })
        .unwrap();
    assert!(all.errors.is_empty(), "{all:?}");
    changes("the layers are gone");
}

/// The stores a driver holds can be listed and dropped by one that serves
/// several; the driver of the engine's one store has none to name and says so
/// (`Unsupported`, both calls), and drops nothing.
pub async fn stores_are_listed_and_dropped_by_a_driver_that_serves_several(f: &Factory) {
    let (_tmp, s) = begin!(
        f,
        "stores_are_listed_and_dropped_by_a_driver_that_serves_several"
    );
    let ghost = "0123456789abcdef0123456789abcdef";
    let listed = s.driver.list_stores();
    let Ok(_) = listed else {
        // the driver of the engine's one store
        let before = s.driver.usage().unwrap();
        for e in [
            expect_err(listed.map(|_| ()), "list_stores of a single store"),
            expect_err(s.driver.drop_store(ghost), "drop_store of a single store"),
        ] {
            assert!(matches!(e.kind, DriverErrorKind::Unsupported), "{e:?}");
            of_driver(&s, &e);
            assert!(e.message().contains("one store"), "{e:?}");
        }
        assert_eq!(s.driver.usage().unwrap(), before, "nothing was dropped");
        return;
    };
    // a store nobody made is dropped without harm, again and again, and is not
    // listed; a name that is not a store id is refused before it names a path
    for _ in 0..2 {
        s.driver
            .drop_store(ghost)
            .expect("a store that is not there");
    }
    let stores = s.driver.list_stores().expect("list_stores");
    assert!(stores.iter().all(|i| i.store != ghost), "{stores:?}");
    assert!(stores.iter().all(|i| crate::stores::is_store_id(&i.store)));
    for bad in ["", "../x", "0123", "0123456789abcdef0123456789abcdeg"] {
        let e = expect_err(s.driver.drop_store(bad), "a name that is no store id");
        assert!(!matches!(e.kind, DriverErrorKind::Unsupported), "{e:?}");
    }
}

pub async fn usage_adds_up(f: &Factory) {
    let (_tmp, s) = begin!(f, "usage_adds_up");
    let empty = s.driver.usage().unwrap();
    assert_eq!(empty.artifacts, (0, 0));
    let base = store_layer(&s, base_layer()).await;
    let one = s.driver.usage().unwrap();
    // (the content of the images is the engine's to measure)
    let content = crate::objects::content_usage(&s.store);
    assert!(
        s.remote || (content.0 > 0 && content.1 > 0),
        "the files of the layer: {content:?}"
    );
    assert!(
        one.artifacts.0 > 0 && one.artifacts.1 > 0,
        "its artifacts: {one:?}"
    );
    let top = store_layer(&s, top_layer()).await;
    let two = s.driver.usage().unwrap();
    let content_two = crate::objects::content_usage(&s.store);
    assert!(s.remote || (content_two.0 >= content.0 && content_two.1 >= content.1));
    assert!(two.artifacts.0 > one.artifacts.0 && two.artifacts.1 > one.artifacts.1);
    // the same layer again adds nothing
    offer(&s, &[&top.tar])
        .await
        .pull(&s, engine_check())
        .await
        .unwrap();
    assert_eq!(s.driver.usage().unwrap(), two);
    // what a layer adds is its artifacts: the same in a store of its own
    if !s.driver.capabilities().layer_chain {
        let other = second(f, &s, "other").await;
        assert_eq!(other.driver.usage().unwrap().artifacts, (0, 0));
        store_layer(&other, top_layer()).await;
        let alone = other.driver.usage().unwrap().artifacts;
        assert_eq!(
            (
                two.artifacts.0 - one.artifacts.0,
                two.artifacts.1 - one.artifacts.1
            ),
            alone,
            "the artifacts of the top layer: {one:?} -> {two:?}, alone {alone:?}"
        );
    }
    // what a collection frees is what the usage drops by
    let freed = s
        .driver
        .collect(&Keep {
            layers: vec![base.key],
            ..Keep::default()
        })
        .unwrap();
    let after = s.driver.usage().unwrap();
    let total = |u: Usage| u.artifacts.1;
    // (a driver in another process owns the objects too, and frees them)
    if s.remote {
        assert!(freed.bytes_freed >= total(two) - total(after));
    } else {
        assert_eq!(
            total(two) - total(after),
            freed.bytes_freed,
            "{two:?} -> {after:?}"
        );
    }
    assert!(after.artifacts.0 < two.artifacts.0);
    assert_eq!(s.driver.usage().unwrap(), after, "the same each time");
    // (the collection leaves the objects: the engine removes those, with
    // the rows that name them)
    if !s.remote {
        assert_eq!(crate::objects::content_usage(&s.store), content_two);
    }
}

// The writable layer

pub async fn writable_layer_lifecycle(f: &Factory) {
    let (_tmp, s) = begin!(f, "writable_layer_lifecycle");
    let d = &s.driver;
    let w = Writable::new("c1", s.dir.join("bundles/c1"));
    assert_eq!(
        (w.id(), w.bundle()),
        ("c1", s.dir.join("bundles/c1").as_path())
    );
    assert!(!d.writable_exists(&w).unwrap());
    d.writable_create(&w, Some(ids()), &WritableOptions::default(), None)
        .expect("writable_create");
    assert!(d.writable_exists(&w).unwrap());
    let p = paths(&s, &w);
    assert_eq!(paths(&s, &w), p, "the paths are a function of the layer");
    assert!(p.upper.is_dir(), "the files of the layer");
    if s.overlay_upper {
        // (an overlay's three directories)
        let work = p.work.clone().expect("an overlay has a work directory");
        assert!(p.upper != work && p.upper != p.merged && work != p.merged);
    }
    // two layers do not share
    let other = Writable::new("c2", s.dir.join("bundles/c2"));
    assert!(paths(&s, &other).upper != p.upper);
    assert!(!d.writable_exists(&other).unwrap());
    // created again: it is there, with what it had
    std::fs::write(p.upper.join("f"), vec![1u8; 4096]).unwrap();
    d.writable_create(&w, None, &WritableOptions::default(), None)
        .expect("created again");
    assert_eq!(std::fs::read(p.upper.join("f")).unwrap().len(), 4096);
    // its size is what it holds
    assert!(d.writable_size(&w).unwrap() >= 4096);
    std::fs::create_dir_all(p.upper.join("d")).unwrap();
    std::fs::write(p.upper.join("d/g"), vec![2u8; 1000]).unwrap();
    assert!(d.writable_size(&w).unwrap() >= 5096);
    // what the driver says of the root file system is its own, with the
    // graph name of podman's `info`
    // (podman's vfs has none)
    let data = d.graph_data(&w);
    assert!(
        data.iter().all(|(k, v)| !k.is_empty() && !v.is_empty()),
        "{data:?}"
    );
    if s.overlay_upper {
        assert!(
            data.iter()
                .any(|(k, v)| k == "UpperDir" && Path::new(v) == p.upper),
            "{data:?}"
        );
    }
    assert_eq!(d.graph_data(&w), data);
    // removed: gone, and removing it again is fine
    d.writable_remove(&w).expect("writable_remove");
    assert!(!d.writable_exists(&w).unwrap());
    d.writable_remove(&w).expect("removed again");
    d.writable_remove(&other)
        .expect("a layer that was never made");
    // the size of a layer that is not there is zero, not an error (what
    // reads the layer of a container, as the changes do, is an error)
    assert_eq!(d.writable_size(&w).expect("a removed layer"), 0);
    assert_eq!(d.writable_size(&other).expect("a layer never made"), 0);
}

pub async fn writable_layer_owner_and_limits(f: &Factory) {
    let (_tmp, s) = begin!(f, "writable_layer_owner_and_limits");
    let d = &s.driver;
    // a limit of size: honoured when the capability says so, else refused as
    // unsupported, never ignored
    let w = Writable::new("q", s.dir.join("bundles/q"));
    let limit = WritableOptions {
        size_limit: Some(1 << 20),
    };
    if d.capabilities().writable_size_limit {
        d.writable_create(&w, None, &limit, None)
            .expect("the capability says a size limit works");
        assert!(d.writable_exists(&w).unwrap());
        d.writable_remove(&w).unwrap();
    } else {
        let e = expect_err(
            d.writable_create(&w, None, &limit, None),
            "a size limit without the capability",
        );
        of_driver(&s, &e);
        assert!(matches!(e.kind, DriverErrorKind::Unsupported), "{e:?}");
        assert!(matches!(ImageError::from(e), ImageError::Storage(_)));
        assert!(
            !d.writable_exists(&w).unwrap(),
            "an unsupported option leaves nothing"
        );
    }
    // the owner of the root of the container's layer
    let w = Writable::new("o", s.dir.join("bundles/o"));
    let mine = ids();
    d.writable_create(&w, Some(mine), &WritableOptions::default(), None)
        .unwrap();
    let st = std::fs::metadata(paths(&s, &w).upper).unwrap();
    assert_eq!(
        (
            std::os::unix::fs::MetadataExt::uid(&st),
            std::os::unix::fs::MetadataExt::gid(&st)
        ),
        mine
    );
    d.writable_remove(&w).unwrap();
    if !is_root() {
        skip!(
            "writable_layer_owner_and_limits",
            "an owner other than the user's needs root"
        );
    }
    let w = Writable::new("o2", s.dir.join("bundles/o2"));
    d.writable_create(&w, Some((1234, 4321)), &WritableOptions::default(), None)
        .unwrap();
    let st = std::fs::metadata(paths(&s, &w).upper).unwrap();
    assert_eq!(
        (
            std::os::unix::fs::MetadataExt::uid(&st),
            std::os::unix::fs::MetadataExt::gid(&st)
        ),
        (1234, 4321)
    );
    d.writable_remove(&w).unwrap();
}

pub async fn the_root_of_a_container_is_found(f: &Factory) {
    let (_tmp, s) = begin!(f, "the_root_of_a_container_is_found");
    remote_skip!(
        s,
        "the_root_of_a_container_is_found",
        "the root of a process is told apart by the root the monitor attached (`is_root_of` has no wire call): the engine records it, not the driver"
    );
    let d = &s.driver;
    let w = Writable::new("r", s.dir.join("bundles/r"));
    d.writable_create(&w, None, &WritableOptions::default(), None)
        .unwrap();
    let proc_dir = s.dir.join("proc");
    std::fs::create_dir_all(&proc_dir).unwrap();
    // a process whose root cannot be told is an error, not "no"
    let e = expect_err(d.is_root_of(&w, &proc_dir), "no mountinfo");
    of_driver(&s, &e);
    assert!(matches!(e.kind, DriverErrorKind::Io(_)), "{e:?}");
    // a process of another root
    (s.proc_root)(&proc_dir, None);
    assert!(!d.is_root_of(&w, &proc_dir).unwrap());
    // the root of the container, and not of another one
    let other = Writable::new("r2", s.dir.join("bundles/r2"));
    d.writable_create(&other, None, &WritableOptions::default(), None)
        .unwrap();
    (s.proc_root)(&proc_dir, Some(&paths(&s, &w)));
    assert!(d.is_root_of(&w, &proc_dir).unwrap());
    assert!(!d.is_root_of(&other, &proc_dir).unwrap());
}

// diff, changes, apply, stopped view

/// What the container did in its layer (the lowest layer is its image).
struct Changed {
    s: Subject,
    _tmp: tempfile::TempDir,
    w: Writable,
    lower: Arc<dyn ImageTree>,
    img: ImageRecord,
    layers: Vec<LayerRecord>,
    /// What the container deleted: the file `etc/gone` and the directory
    /// `opt`, which it made again (the overlay's marks in an upper
    /// directory, or the removal in a copy of the image).
    marks: bool,
    /// The file system has the xattrs of users.
    xattrs: bool,
}

fn set_xattr(path: &Path, name: &str, value: &[u8]) -> bool {
    rustix::fs::lsetxattr(path, name, value, rustix::fs::XattrFlags::empty()).is_ok()
}

/// The writable layer of a container of the image, as the engine makes it
/// (the layers it is made of for a driver that copies them).
fn create_over(s: &Subject, w: &Writable, img: &ImageRecord, layers: &[LayerRecord]) {
    s.driver
        .writable_create(
            w,
            Some(ids()),
            &WritableOptions::default(),
            Some(&MountRequest {
                container: w,
                ..request(img, layers)
            }),
        )
        .expect("writable_create");
}

const OLD_TIME: u64 = 1_500_000_000;

async fn changed(f: &Factory, case: &str) -> Option<Changed> {
    let tmp = tempfile::tempdir().unwrap();
    let s = subject(f, case, tmp.path()).await?;
    let base = store_layer(&s, base_layer()).await;
    let layers = records(&s, &[&base]).await;
    let lower = s
        .driver
        .image_view("img", &layers)
        .expect("the image below");
    let w = Writable::new("c", s.dir.join("bundles/c"));
    let img = image("img", &[&base]);
    create_over(&s, &w, &img, &layers);
    let upper = paths(&s, &w).upper;
    let put = |name: &str, data: &[u8]| {
        let p = upper.join(name);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, data).unwrap();
        p
    };
    let new = put("etc/new", b"new file");
    put("etc/hosts", b"engine");
    put("etc/secret", b"s");
    std::fs::set_permissions(
        upper.join("etc/secret"),
        std::os::unix::fs::PermissionsExt::from_mode(0o600),
    )
    .unwrap();
    put("etc/sub/f", b"in a directory");
    std::fs::hard_link(&new, upper.join("etc/sub/link")).unwrap();
    std::os::unix::fs::symlink("new", upper.join("etc/ln")).unwrap();
    std::fs::File::options()
        .write(true)
        .open(&new)
        .unwrap()
        .set_modified(std::time::UNIX_EPOCH + Duration::from_secs(OLD_TIME))
        .unwrap();
    let xattrs = set_xattr(&new, "user.conformance", b"value");
    let sparse = std::fs::File::create(upper.join("sparse")).unwrap();
    sparse.set_len(1 << 20).unwrap();
    std::os::unix::fs::FileExt::write_at(&sparse, b"x", (1 << 20) - 1).unwrap();
    let mut marks = s.overlay_upper;
    if !s.overlay_upper {
        // (the layer is a copy of the image: a deletion is a removal)
        std::fs::remove_file(upper.join("etc/gone")).unwrap();
        velarx_base::tree::remove_dir_all(upper.join("opt")).unwrap();
        put("opt/y", b"y");
        marks = true;
    } else if marks {
        marks &= rustix::fs::mknodat(
            rustix::fs::CWD,
            upper.join("etc/gone"),
            rustix::fs::FileType::CharacterDevice,
            rustix::fs::Mode::empty(),
            rustix::fs::makedev(0, 0),
        )
        .is_ok();
        put("opt/y", b"y");
        marks &= set_xattr(&upper.join("opt"), "user.overlay.opaque", b"y");
        if !marks {
            eprintln!("NOTE conformance::{case}: no overlay marks here (user xattrs or mknod): the cases of whiteouts and opaque directories are skipped");
            let _ = std::fs::remove_file(upper.join("etc/gone"));
            velarx_base::tree::remove_dir_all(upper.join("opt")).unwrap();
        }
    }
    if !xattrs {
        eprintln!("NOTE conformance::{case}: no user xattrs on this file system: the xattr checks are skipped");
    }
    Some(Changed {
        s,
        _tmp: tmp,
        w,
        lower,
        img,
        layers,
        marks,
        xattrs,
    })
}

/// An entry of a layer's tar.
#[derive(Debug, Clone)]
struct Entry {
    kind: tar::EntryType,
    size: u64,
    uid: u64,
    gid: u64,
    mtime: u64,
    mode: u32,
    link: Option<String>,
    xattrs: BTreeMap<String, Vec<u8>>,
    data: Vec<u8>,
}

fn entries(tar_bytes: &[u8]) -> BTreeMap<String, Entry> {
    let mut out = BTreeMap::new();
    for e in tar::Archive::new(tar_bytes).entries().unwrap() {
        let mut e = e.unwrap();
        let path = e
            .path()
            .unwrap()
            .to_string_lossy()
            .trim_start_matches("./")
            .trim_end_matches('/')
            .to_string();
        let mut xattrs = BTreeMap::new();
        if let Some(ext) = e.pax_extensions().unwrap() {
            for x in ext.flatten() {
                if let Some(name) = x.key().ok().and_then(|k| k.strip_prefix("SCHILY.xattr.")) {
                    xattrs.insert(name.to_string(), x.value_bytes().to_vec());
                }
            }
        }
        let h = e.header().clone();
        let uid = h.uid().unwrap_or_else(|e| panic!("the uid of {path}: {e}"));
        let gid = h.gid().unwrap_or_else(|e| panic!("the gid of {path}: {e}"));
        let link = e
            .link_name()
            .unwrap()
            .map(|l| l.to_string_lossy().trim_start_matches("./").to_string());
        let mut data = Vec::new();
        e.read_to_end(&mut data).unwrap();
        out.insert(
            path,
            Entry {
                kind: h.entry_type(),
                size: h.size().unwrap(),
                // (every entry has an owner, a whiteout too: a blank field
                // is not a number to a strict reader)
                uid,
                gid,
                mtime: h.mtime().unwrap(),
                mode: h.mode().unwrap(),
                link,
                xattrs,
                data,
            },
        );
    }
    out
}

fn engine_files() -> Vec<String> {
    dirtar::ENGINE_FILES.iter().map(|s| s.to_string()).collect()
}

fn diff_of(c: &Changed, opts: &DiffOptions) -> Vec<u8> {
    let mut out = Vec::new();
    c.s.driver
        .diff(&c.w, Some(c.lower.clone()), opts, &mut out)
        .expect("diff");
    out
}

pub async fn diff_is_the_tar_of_what_the_container_changed(f: &Factory) {
    let Some(c) = changed(f, "diff_is_the_tar_of_what_the_container_changed").await else {
        return;
    };
    let opts = DiffOptions {
        exclude: engine_files(),
        ..Default::default()
    };
    let tar = diff_of(&c, &opts);
    let e = entries(&tar);
    let (uid, gid) = ids();
    // what was added, with its content, owner and time
    let new = &e["etc/new"];
    let link = &e["etc/sub/link"];
    // (one name of the two is the file, the other a hard link to it)
    let (file, file_name, link_name) = match (new.kind, link.kind) {
        (tar::EntryType::Regular, tar::EntryType::Link) => (new, "etc/new", "etc/sub/link"),
        (tar::EntryType::Link, tar::EntryType::Regular) => (link, "etc/sub/link", "etc/new"),
        kinds => panic!("a file and its hard link, not {kinds:?}"),
    };
    assert_eq!(e[link_name].link.as_deref(), Some(file_name));
    assert_eq!(file.data, b"new file");
    assert_eq!((file.uid, file.gid), (uid as u64, gid as u64));
    assert_eq!(file.mtime, OLD_TIME);
    if c.xattrs {
        assert_eq!(
            file.xattrs.get("user.conformance").map(Vec::as_slice),
            Some(&b"value"[..])
        );
    }
    assert_eq!(e["etc/sub/f"].data, b"in a directory");
    assert!(e["etc/sub"].kind.is_dir());
    assert_eq!(e["etc/secret"].mode & 0o777, 0o600);
    let ln = &e["etc/ln"];
    assert_eq!(
        (ln.kind, ln.link.as_deref()),
        (tar::EntryType::Symlink, Some("new"))
    );
    // a sparse file is the same file
    let sparse = &e["sparse"];
    assert_eq!(sparse.size, 1 << 20);
    assert_eq!((sparse.data[0], *sparse.data.last().unwrap()), (0, b'x'));
    assert!(sparse.data[1..sparse.data.len() - 1]
        .iter()
        .all(|b| *b == 0));
    // the engine's files are left out when it says so, and only then
    assert!(!e.contains_key("etc/hosts"));
    let all = entries(&diff_of(&c, &DiffOptions::default()));
    assert!(all.contains_key("etc/hosts"));
    assert!(e.keys().all(|n| !n.is_empty()));
    // what the image below has and the container did not touch is not in it
    assert!(!e.contains_key("etc/old") && !e.contains_key("usr/lib/big"));
    if c.marks {
        // a deleted file is a whiteout, a directory made again is opaque
        assert!(e.contains_key("etc/.wh.gone"), "{:?}", e.keys());
        assert!(e.contains_key("opt/.wh..wh..opq"), "{:?}", e.keys());
        assert_eq!(e["opt/y"].data, b"y");
        // without the image below, a driver may not know what a file is
        // (and says so, as its own error) or reads the layer alone: then
        // what the container added is there all the same
        let mut out = Vec::new();
        match c.s.driver.diff(&c.w, None, &opts, &mut out) {
            Ok(()) => {
                let alone = entries(&out);
                assert!(alone.contains_key("etc/sub/f"), "{:?}", alone.keys());
            }
            Err(e) => of_driver(&c.s, &e),
        }
    }
    // the same layer, the same tar
    assert!(diff_of(&c, &opts) == tar, "diff is not deterministic");
}

pub async fn diff_applies_the_options_of_ids_and_times(f: &Factory) {
    let Some(c) = changed(f, "diff_applies_the_options_of_ids_and_times").await else {
        return;
    };
    let (uid, gid) = ids();
    let map = |host| {
        vec![IdRange {
            container: 5,
            host,
            size: 1,
        }]
    };
    // owners are those of the container: the user is its id 5
    let opts = DiffOptions {
        exclude: engine_files(),
        uid_map: map(uid),
        gid_map: map(gid),
        ..Default::default()
    };
    let e = entries(&diff_of(&c, &opts));
    for (name, entry) in e.iter().filter(|(n, _)| !n.contains(".wh.")) {
        assert_eq!((entry.uid, entry.gid), (5, 5), "{name}");
    }
    // times: fixed, or at most
    let fixed = DiffOptions {
        exclude: engine_files(),
        mtime: Mtime::Fixed(1234),
        ..Default::default()
    };
    for (name, entry) in entries(&diff_of(&c, &fixed)) {
        // (a whiteout has no time of its own, in any layer)
        let time = if name.contains(".wh.") { 0 } else { 1234 };
        assert_eq!(entry.mtime, time, "{name}");
    }
    let clamp = DiffOptions {
        exclude: engine_files(),
        mtime: Mtime::Clamp(OLD_TIME as i64 - 10),
        ..Default::default()
    };
    let clamped = entries(&diff_of(&c, &clamp));
    assert!(clamped.values().all(|e| e.mtime <= OLD_TIME - 10));
    assert_eq!(
        clamped["etc/new"].mtime.min(clamped["etc/sub/link"].mtime),
        OLD_TIME - 10
    );
    let kept = entries(&diff_of(
        &c,
        &DiffOptions {
            exclude: engine_files(),
            ..Default::default()
        },
    ));
    assert_eq!(
        kept["etc/new"].mtime.max(kept["etc/sub/link"].mtime),
        OLD_TIME
    );
    // owners of the host: a user of the image is not changed to the
    // container's root; only root can make another owner
    if !is_root() {
        eprintln!("NOTE conformance::diff_applies_the_options_of_ids_and_times: owners other than the user's need root");
        return;
    }
    let upper = paths(&c.s, &c.w).upper;
    std::os::unix::fs::lchown(upper.join("etc/sub/f"), Some(1234), Some(4321)).unwrap();
    let plain = entries(&diff_of(
        &c,
        &DiffOptions {
            exclude: engine_files(),
            ..Default::default()
        },
    ));
    assert_eq!(
        (plain["etc/sub/f"].uid, plain["etc/sub/f"].gid),
        (1234, 4321)
    );
    // (an owner that the map does not cover is an error: the map has root
    // too, which owns the rest)
    let range = |container, host| IdRange {
        container,
        host,
        size: 1,
    };
    let mapped = DiffOptions {
        exclude: engine_files(),
        uid_map: vec![range(0, 0), range(7, 1234)],
        gid_map: vec![range(0, 0), range(8, 4321)],
        ..Default::default()
    };
    let unmapped = DiffOptions {
        exclude: engine_files(),
        uid_map: vec![range(7, 1234)],
        gid_map: vec![range(8, 4321)],
        ..Default::default()
    };
    let mut out = Vec::new();
    let e = expect_err(
        c.s.driver
            .diff(&c.w, Some(c.lower.clone()), &unmapped, &mut out),
        "owners the map does not cover",
    );
    assert!(matches!(e.kind, DriverErrorKind::Io(_)), "{e:?}");
    let m = entries(&diff_of(&c, &mapped));
    assert_eq!((m["etc/sub/f"].uid, m["etc/sub/f"].gid), (7, 8));
}

pub async fn changes_list_what_diff_writes(f: &Factory) {
    let Some(c) = changed(f, "changes_list_what_diff_writes").await else {
        return;
    };
    let opts = DiffOptions {
        exclude: engine_files(),
        ..Default::default()
    };
    let list =
        c.s.driver
            .changes(&c.w, Some(c.lower.clone()), &opts)
            .expect("changes");
    let kinds: BTreeMap<&str, Change> = list.iter().map(|(p, k)| (p.as_str(), *k)).collect();
    assert_eq!(kinds.len(), list.len(), "a path once: {list:?}");
    assert_eq!(
        kinds["/etc"],
        Change::Modified,
        "a directory of the image with new files"
    );
    assert_eq!(kinds["/etc/new"], Change::Added);
    assert_eq!(kinds["/etc/sub"], Change::Added);
    assert_eq!(kinds["/sparse"], Change::Added);
    assert!(
        !kinds.contains_key("/etc/hosts"),
        "the engine's file: {list:?}"
    );
    assert!(!kinds.contains_key("/etc/old"));
    if c.marks {
        assert_eq!(kinds["/etc/gone"], Change::Deleted);
        assert_eq!(kinds["/opt/y"], Change::Added);
        assert_eq!(kinds["/opt"], Change::Modified);
    }
    // the tar says the same: what was added or modified is in it, and what
    // was deleted is a whiteout
    let tar = entries(&diff_of(&c, &opts));
    for (path, kind) in &list {
        let name = path.trim_start_matches('/');
        match kind {
            Change::Deleted => {
                let (dir, base) = name.rsplit_once('/').unwrap_or(("", name));
                let wh = if dir.is_empty() {
                    format!(".wh.{base}")
                } else {
                    format!("{dir}/.wh.{base}")
                };
                // (or the directory is opaque: it has none of the image's;
                // a marker in the root hides nothing)
                let opaque = format!("{dir}/.wh..wh..opq");
                assert!(
                    tar.contains_key(&wh) || (!dir.is_empty() && tar.contains_key(&opaque)),
                    "{name}: no {wh}"
                );
            }
            _ => assert!(
                tar.contains_key(name),
                "{name} is changed and not in the tar"
            ),
        }
    }
}

pub async fn apply_writes_what_diff_wrote(f: &Factory) {
    let Some(c) = changed(f, "apply_writes_what_diff_wrote").await else {
        return;
    };
    let (uid, gid) = ids();
    // (the user is the container's id 5: apply maps the owners of the tar
    // back to the host, it does not leave them as the tar has them)
    let opts = DiffOptions {
        mtime: Mtime::Fixed(1),
        uid_map: vec![IdRange {
            container: 5,
            host: uid,
            size: 1,
        }],
        gid_map: vec![IdRange {
            container: 5,
            host: gid,
            size: 1,
        }],
        ..Default::default()
    };
    let tar = diff_of(&c, &opts);
    let d = &c.s.driver;
    let other = Writable::new("d", c.s.dir.join("bundles/d"));
    create_over(&c.s, &other, &c.img, &c.layers);
    d.apply(&other, &opts, &mut tar.as_slice()).expect("apply");
    // the same layer comes out of it
    let mut again = Vec::new();
    d.diff(&other, Some(c.lower.clone()), &opts, &mut again)
        .unwrap();
    let (then, now) = (entries(&tar), entries(&again));
    assert_eq!(
        then.keys().collect::<Vec<_>>(),
        now.keys().collect::<Vec<_>>()
    );
    for (name, a) in &then {
        let b = &now[name];
        assert_eq!(
            (a.kind, a.size, a.uid, a.gid, a.mtime, a.mode, &a.link, &a.data, &a.xattrs),
            (b.kind, b.size, b.uid, b.gid, b.mtime, b.mode, &b.link, &b.data, &b.xattrs),
            "{name} is not what was applied"
        );
    }
    if c.xattrs {
        assert!(then.values().any(|e| !e.xattrs.is_empty()));
    }
    assert!(again == tar, "apply and diff are not inverse byte for byte");
    // and the files are the files
    let upper = paths(&c.s, &other).upper;
    assert_eq!(std::fs::read(upper.join("etc/new")).unwrap(), b"new file");
    let st = std::fs::metadata(upper.join("etc/sub/f")).unwrap();
    assert_eq!(
        (
            std::os::unix::fs::MetadataExt::uid(&st),
            std::os::unix::fs::MetadataExt::gid(&st)
        ),
        (uid, gid),
        "the owner mapped back to the host"
    );
    assert_eq!(
        std::fs::read(upper.join("etc/sub/f")).unwrap(),
        b"in a directory"
    );
    let (a, b) = (
        std::fs::metadata(upper.join("etc/new")).unwrap(),
        std::fs::metadata(upper.join("etc/sub/link")).unwrap(),
    );
    assert_eq!(
        (
            std::os::unix::fs::MetadataExt::ino(&a),
            std::os::unix::fs::MetadataExt::nlink(&a)
        ),
        (std::os::unix::fs::MetadataExt::ino(&b), 2),
        "a hard link is one file"
    );
    assert_eq!(
        std::fs::read_link(upper.join("etc/ln")).unwrap(),
        Path::new("new")
    );
    let sparse = std::fs::read(upper.join("sparse")).unwrap();
    assert_eq!(
        (sparse.len(), sparse[0], sparse[sparse.len() - 1]),
        (1 << 20, 0, b'x')
    );
    assert_eq!(
        std::os::unix::fs::PermissionsExt::mode(
            &std::fs::metadata(upper.join("etc/secret"))
                .unwrap()
                .permissions()
        ) & 0o777,
        0o600
    );
    if c.marks {
        // the deletion and the opaque directory are what the driver reads
        // as such again
        let list = d.changes(&other, Some(c.lower.clone()), &opts).unwrap();
        assert!(
            list.contains(&("/etc/gone".to_string(), Change::Deleted)),
            "{list:?}"
        );
        assert!(
            list.contains(&("/opt".to_string(), Change::Modified)),
            "{list:?}"
        );
    }
    // a layer applied is a layer with a size
    assert!(d.writable_size(&other).unwrap() > 0);
}

pub async fn diff_apply_and_view_of_a_layer_that_was_never_made(f: &Factory) {
    let Some(c) = changed(f, "diff_apply_and_view_of_a_layer_that_was_never_made").await else {
        return;
    };
    let d = &c.s.driver;
    let none = Writable::new("never", c.s.dir.join("bundles/never"));
    assert!(!d.writable_exists(&none).unwrap());
    let opts = DiffOptions::default();
    let e = expect_err(
        d.diff(&none, Some(c.lower.clone()), &opts, &mut Vec::new()),
        "diff",
    );
    of_driver(&c.s, &e);
    // (a driver in another process says the root is not there)
    assert!(
        matches!(e.kind, DriverErrorKind::Io(_))
            || (c.s.remote && matches!(e.kind, DriverErrorKind::Missing { .. })),
        "{e:?}"
    );
    assert!(d.changes(&none, Some(c.lower.clone()), &opts).is_err());
    let tar = diff_of(&c, &opts);
    assert!(d.apply(&none, &opts, &mut tar.as_slice()).is_err());
    assert!(!d.writable_exists(&none).unwrap(), "apply makes no layer");
    let store = c.s.store.clone();
    let translate = velarx_fuse::IdTranslate::default();
    let layers: Vec<String> = Vec::new();
    let Err(e) = d.stopped_view(
        &none,
        TreeSource {
            tree: &*c.lower,
            layers: &layers,
            objects: &*store,
            verity: store.verity(),
            fetcher: None,
            translate: &translate,
        },
    ) else {
        panic!("no layer, no view")
    };
    assert!(
        matches!(e.kind, DriverErrorKind::Io(_))
            || (c.s.remote && matches!(e.kind, DriverErrorKind::Missing { .. })),
        "{e:?}"
    );
    // what is not a layer is refused, and leaves the layer as it was
    let here = Writable::new("here", c.s.dir.join("bundles/here"));
    d.writable_create(&here, Some(ids()), &WritableOptions::default(), None)
        .unwrap();
    let junk = vec![0xffu8; 1024];
    assert!(
        d.apply(&here, &opts, &mut junk.as_slice()).is_err(),
        "a tar that is not one"
    );
}

pub async fn the_view_of_a_stopped_container(f: &Factory) {
    let Some(c) = changed(f, "the_view_of_a_stopped_container").await else {
        return;
    };
    let store = c.s.store.clone();
    let translate = velarx_fuse::IdTranslate::default();
    let layers: Vec<String> = Vec::new();
    let view =
        c.s.driver
            .stopped_view(
                &c.w,
                TreeSource {
                    tree: &*c.lower,
                    layers: &layers,
                    objects: &*store,
                    verity: store.verity(),
                    fetcher: None,
                    translate: &translate,
                },
            )
            .expect("stopped_view");
    // the layer over its image
    assert_eq!(view.stat("/etc/new").unwrap().0.size, 8);
    assert!(view.stat("/etc/sub").unwrap().0.is_dir);
    assert_eq!(
        view.stat("/etc/old").unwrap().0.size,
        11,
        "a file of the image"
    );
    assert_eq!(
        view.stat("/usr/lib/big").unwrap().0.size,
        big().len() as i64
    );
    assert_eq!(view.stat("/sparse").unwrap().0.size, 1 << 20);
    assert!(view.stat("/nothing").is_err());
    if c.marks {
        // what the overlay shows: the deleted file is gone, the opaque
        // directory has only what the container put in it
        assert!(view.stat("/etc/gone").is_err());
        assert!(view.stat("/opt/x").is_err());
        assert!(view.stat("/opt/y").is_ok());
    } else if c.s.overlay_upper {
        assert!(view.stat("/etc/gone").is_ok());
    }
}

// Error mapping

pub async fn errors_name_their_driver_and_map_to_the_engines(f: &Factory) {
    let (_tmp, s) = begin!(f, "errors_name_their_driver_and_map_to_the_engines");
    let d = &s.driver;
    let base = store_layer(&s, base_layer()).await;
    let img = image("img", &[&base]);
    let mut gone = records(&s, &[&base]).await;
    gone[0].key = LayerKey::Whole(format!("sha256:{}", "dd".repeat(32)).parse().unwrap());
    // a missing layer: the kind that says how to mend it, and the layer
    let e = expect_err(
        plan_of(&s, &request(&img, &gone)).map(|r| r.plan),
        "a missing layer",
    );
    of_driver(&s, &e);
    assert!(matches!(e.kind, DriverErrorKind::Missing { .. }) && e.remedy().is_some());
    assert_eq!(e.layer.as_deref(), Some(gone[0].key.to_string().as_str()));
    assert!(
        e.to_string().contains(e.remedy().unwrap().text(false)),
        "the message has the remedy: {e}"
    );
    assert!(matches!(ImageError::from(e), ImageError::Storage(_)));
    // a pull that is not there: not found
    let e = expect_err(d.remake_staged("nope").await, "a pull that is not there");
    assert!(matches!(
        e.kind,
        DriverErrorKind::NotFound | DriverErrorKind::Unsupported
    ));
    // an option the driver lacks: unsupported, and the engine's storage error
    if !d.capabilities().writable_size_limit {
        let w = Writable::new("e", s.dir.join("bundles/e"));
        let e = expect_err(
            d.writable_create(
                &w,
                None,
                &WritableOptions {
                    size_limit: Some(1),
                },
                None,
            ),
            "a size limit without the capability",
        );
        assert!(matches!(e.kind, DriverErrorKind::Unsupported), "{e:?}");
        assert!(matches!(ImageError::from(e), ImageError::Storage(_)));
    }
    // the io error of a file is the io error: the engine gets the same one
    let io = DriverError::io(d.name(), std::io::Error::from_raw_os_error(libc::ENOENT));
    assert!(
        matches!(ImageError::from(io), ImageError::Io(e) if e.raw_os_error() == Some(libc::ENOENT))
    );
    // and a refusal is the engine's error as it was
    let e = DriverError::refused(d.name(), ImageError::Contradicted("x".into()));
    assert!(matches!(ImageError::from(e), ImageError::Contradicted(m) if m == "x"));
}

// The root of the writable layer as a descriptor

/// Write `data` as `name` below the descriptor `root`, as the engine does
/// (`openat2`, beneath, no link followed).
fn write_below(root: &std::os::fd::OwnedFd, name: &str, data: &[u8]) {
    use rustix::fs::{Mode, OFlags, ResolveFlags};
    let fd = rustix::fs::openat2(
        root,
        name,
        OFlags::WRONLY | OFlags::CREATE | OFlags::TRUNC | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_raw_mode(0o644),
        ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )
    .expect("a file below the root of the layer");
    std::io::Write::write_all(&mut std::fs::File::from(fd), data).unwrap();
}

fn cloexec(fd: &std::os::fd::OwnedFd) -> bool {
    rustix::io::fcntl_getfd(fd)
        .unwrap()
        .contains(rustix::io::FdFlags::CLOEXEC)
}

fn is_dir_fd(fd: &std::os::fd::OwnedFd) -> bool {
    let st = rustix::fs::fstat(fd).unwrap();
    rustix::fs::FileType::from_raw_mode(st.st_mode) == rustix::fs::FileType::Directory
}

pub async fn writable_root_is_the_root_of_the_layer(f: &Factory) {
    let (_tmp, s) = begin!(f, "writable_root_is_the_root_of_the_layer");
    let d = &s.driver;
    let w = Writable::new("c1", s.dir.join("bundles/c1"));
    // a layer that was never made has no root (and none is made)
    expect_err(d.writable_root(&w), "a layer that was never made");
    assert!(
        !d.writable_exists(&w).unwrap(),
        "asking for the root makes no layer"
    );
    let base = store_layer(&s, base_layer()).await;
    let layers = records(&s, &[&base]).await;
    let lower = d.image_view("img", &layers).expect("the image below");
    create_over(&s, &w, &image("img", &[&base]), &layers);
    let root = d.writable_root(&w).expect("the root of the layer");
    assert!(is_dir_fd(&root), "a directory");
    assert!(cloexec(&root), "O_CLOEXEC");
    // the file written through the descriptor is a file of the layer: where
    // the driver says its files are, and what the changes list
    write_below(&root, "via-root", b"through the descriptor");
    let p = paths(&s, &w);
    assert_eq!(
        std::fs::read(p.upper.join("via-root")).unwrap(),
        b"through the descriptor"
    );
    let list = d
        .changes(&w, Some(lower), &DiffOptions::default())
        .expect("changes");
    assert!(
        list.iter()
            .any(|(p, c)| p == "/via-root" && *c == Change::Added),
        "{list:?}"
    );
    assert!(d.writable_size(&w).unwrap() >= 22);
    // every call gives a descriptor of its own, of the same directory
    let again = d.writable_root(&w).unwrap();
    assert_ne!(
        std::os::fd::AsRawFd::as_raw_fd(&root),
        std::os::fd::AsRawFd::as_raw_fd(&again)
    );
    drop(root);
    write_below(&again, "second", b"s");
    assert!(p.upper.join("second").is_file());
    // the descriptor is the directory, not its name: it stays valid when the
    // bundle is renamed, and what is written goes to the renamed directory
    let bundle = match &s.bundle {
        Some(bundle) => bundle(&w),
        None => s.dir.join("bundles/c1"),
    };
    let moved = s.dir.join("bundles/c1.moved");
    std::fs::create_dir_all(s.dir.join("bundles")).unwrap();
    std::fs::rename(&bundle, &moved).unwrap();
    write_below(&again, "after-rename", b"r");
    let rel = p.upper.strip_prefix(&bundle).unwrap();
    assert!(
        moved.join(rel).join("after-rename").is_file(),
        "written below the renamed directory"
    );
    assert!(!p.upper.join("after-rename").exists());
    std::fs::rename(&moved, &bundle).unwrap();
    // another layer's root is another directory
    let other = Writable::new("c2", s.dir.join("bundles/c2"));
    d.writable_create(&other, None, &WritableOptions::default(), None)
        .unwrap();
    let theirs = d.writable_root(&other).unwrap();
    write_below(&theirs, "only-theirs", b"t");
    assert!(!paths(&s, &w).upper.join("only-theirs").exists());
    // a link is not followed to the root: the name of a link at the end is
    // refused (the engine never writes through one)
    std::os::unix::fs::symlink("/etc", paths(&s, &w).upper.join("etc-link")).unwrap();
    let e = rustix::fs::openat2(
        &again,
        "etc-link",
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::DIRECTORY | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
        rustix::fs::ResolveFlags::BENEATH | rustix::fs::ResolveFlags::NO_SYMLINKS,
    )
    .unwrap_err();
    assert_eq!(e, rustix::io::Errno::LOOP);
    // a removed layer has no root
    d.writable_remove(&w).unwrap();
    expect_err(d.writable_root(&w), "a removed layer");
    d.writable_remove(&other).unwrap();
}

/// Returns whether the plans were `MountFd` ones (a driver of the product
/// has none yet: a test driver does, where the process may mount).
pub async fn rootfs_has_a_descriptor_when_the_plan_names_one(f: &Factory) -> bool {
    let Some(s) = ({
        let tmp = tempfile::tempdir().unwrap();
        subject(
            f,
            "rootfs_has_a_descriptor_when_the_plan_names_one",
            tmp.path(),
        )
        .await
        .map(|s| (tmp, s))
    }) else {
        return false;
    };
    let (_tmp, s) = s;
    let base = store_layer(&s, base_layer()).await;
    let layers = records(&s, &[&base]).await;
    let img = image("img", &[&base]);
    let w = Writable::new("c1", s.dir.join("bundles/c1"));
    create_over(&s, &w, &img, &layers);
    let req = MountRequest {
        container: &w,
        ..request(&img, &layers)
    };
    // (a plan of a kind that names no descriptor has none: the descriptor of
    // a `MountFd` plan is new at every call, and is the root of a mount)
    let mut held = Vec::new();
    for _ in 0..3 {
        let r = plan_of(&s, &req).expect("a plan");
        match (&r.plan, r.fd) {
            (RootfsPlan::MountFd(m), Some(fd)) => {
                assert_eq!(m.fd_index, 0, "the engine passes the one descriptor first");
                assert!(is_dir_fd(&fd), "a directory");
                assert!(
                    cloexec(&fd),
                    "O_CLOEXEC: the engine passes it on by its own"
                );
                held.push(fd);
            }
            (RootfsPlan::MountFd(_), None) => panic!("a mount-fd plan comes with its descriptor"),
            (_, Some(_)) => panic!("a descriptor with a plan that names none"),
            (_, None) => {}
        }
    }
    let raw: std::collections::HashSet<_> =
        held.iter().map(std::os::fd::AsRawFd::as_raw_fd).collect();
    assert_eq!(
        raw.len(),
        held.len(),
        "a descriptor of its own at every call"
    );
    // the same request gives the same plan, as before
    let a = plan_of(&s, &req).unwrap().plan;
    let b = plan_of(&s, &req).unwrap().plan;
    assert_eq!(a, b);
    s.driver.writable_remove(&w).unwrap();
    !held.is_empty()
}

// A chained driver (a test double)

/// A driver whose layers are chained, as a snapshot driver's are, made of a
/// real one (it keeps the bytes) with the rules of a chain on top: it holds a
/// layer under its chain id and **requires the parent** of a layer to be held
/// (or made earlier in the same pull) before it ingests it.  It fails when
/// the engine passes only the layers it lacks, without the parents, so a
/// pass proves the API (the whole list, the chain ids, `stored`, `Keep::chains`)
/// is enough for such a driver.
pub struct Chained {
    inner: Arc<dyn StorageDriver>,
    caps: Capabilities,
    /// The chain ids it holds.
    held: Mutex<HashSet<Digest>>,
}

impl Chained {
    pub fn of(inner: Arc<dyn StorageDriver>) -> Arc<Self> {
        let mut caps = inner.capabilities().clone();
        caps.layer_chain = true;
        Arc::new(Self {
            inner,
            caps,
            held: Mutex::default(),
        })
    }

    /// Whether the driver holds the layer of the chain id `chain`.
    pub fn holds(&self, chain: &Digest) -> bool {
        self.held.lock().unwrap().contains(chain)
    }

    /// Make it hold the chain ids `chains` (a store that has them).
    pub fn hold(&self, chains: &[Digest]) {
        self.held.lock().unwrap().extend(chains.iter().copied());
    }

    fn refuse(&self, why: String) -> DriverError {
        DriverError::storage(self.inner.name(), format!("chained driver: {why}"))
    }

    /// The checks of a pull of `layers`, which add the chains it will make
    /// to the returned list.
    fn check_list(&self, layers: &[FeedLayer]) -> DriverResult<Vec<Digest>> {
        // the list is the whole stack: it starts at the bottom
        if layers.first().is_some_and(|l| l.parent.is_some()) {
            return Err(self.refuse(
                "the list starts above the bottom of the stack: the layers below it are not there"
                    .into(),
            ));
        }
        let mut made = Vec::new();
        for (i, l) in layers.iter().enumerate() {
            // the chain id is the parent's and the diff id's, and the parent
            // of a layer is the layer before it in the list
            let derived = match &l.parent {
                None => l.diff_id,
                Some(p) => Digest::of(
                    velarx_types::digest::Algorithm::Sha256,
                    format!("sha256:{} sha256:{}", p.hex(), l.diff_id.hex()).as_bytes(),
                ),
            };
            if l.chain_id != derived {
                return Err(self.refuse(format!("layer {i} has the wrong chain id")));
            }
            if i > 0 && l.parent != Some(layers[i - 1].chain_id) {
                return Err(self.refuse(format!("layer {i} has the wrong parent")));
            }
            if l.stored {
                if !self.holds(&l.chain_id) {
                    return Err(self.refuse(format!("layer {i} is said stored, it is not held")));
                }
            } else {
                if let Some(parent) = &l.parent {
                    if !self.holds(parent) && !made.contains(parent) {
                        return Err(self.refuse(format!(
                            "the parent of layer {i} ({parent}) is not there: the list lacks the layers below it"
                        )));
                    }
                }
                made.push(l.chain_id);
            }
        }
        Ok(made)
    }
}

forward_storage_driver! {
    impl StorageDriver for Chained {
        inner: inner;
        forward: [name graph_name graph_data status repair remake_staged read_objects open_object objects_in_order remove_image image_volume_create mounts image_view holds_objects leftovers check writable_create writable_paths writable_root writable_size writable_remove writable_release writable_exists diff changes apply stopped_view is_root_of usage list_stores drop_store release_engine_copies lock_unused_layers];
        fn capabilities(&self) -> &Capabilities {
            &self.caps
        }
        async fn pull(
            &self,
            feed: &Arc<dyn PullFeed>,
            layers: &[FeedLayer],
            settled: Settled,
        ) -> DriverResult<Pulled> {
            let made = self.check_list(layers)?;
            let pulled = self.inner.pull(feed, layers, settled).await?;
            self.held.lock().unwrap().extend(made);
            Ok(pulled)
        }
        async fn has_layers(&self, layers: &[LayerRef]) -> DriverResult<Vec<bool>> {
            // a layer is held under its chain: each place of a stack is its own
            // answer (and the bytes are the inner driver's)
            let inner = self.inner.has_layers(layers).await?;
            Ok(inner
                .into_iter()
                .zip(layers)
                .map(|(have, l)| have && self.holds(&l.chain_id))
                .collect())
        }
        fn collect(&self, keep: &Keep) -> DriverResult<Collected> {
            // the chains it holds are those named; the bytes go by key
            let named: HashSet<Digest> = keep.chains.iter().copied().collect();
            self.held.lock().unwrap().retain(|c| named.contains(c));
            self.inner.collect(keep)
        }
    }
}

/// Record what a pull stored, as the engine does after it.
async fn record(s: &Subject, pulled: &Pulled) {
    let mut commits = Vec::new();
    for l in &pulled.layers {
        let artifact = &pulled.artifacts[&l.key];
        let mut commit = layer_commit(l, None).unwrap();
        commit.record.erofs = Some(artifact.image_digest.clone());
        commit.record.owners = Some(artifact.owners.clone());
        commits.push(commit);
    }
    s.db.commit_layers(commits, vec![], vec![]).await.unwrap();
}

/// The chain ids of `diffs` computed here, with no code of the engine: the
/// formula of the image-spec written out.
fn independent_chains(diffs: &[Digest]) -> Vec<Digest> {
    let mut out: Vec<Digest> = Vec::new();
    for d in diffs {
        let c = match out.last() {
            None => *d,
            Some(p) => Digest::of(
                velarx_types::digest::Algorithm::Sha256,
                format!("sha256:{} sha256:{}", p.hex(), d.hex()).as_bytes(),
            ),
        };
        out.push(c);
    }
    out
}

/// The refs the engine asks `has_layers` with for a stack (one per layer, in
/// order: the chain driver's question).
fn refs_of(layers: &[FeedLayer]) -> Vec<LayerRef> {
    layers
        .iter()
        .map(|l| LayerRef {
            key: l.key,
            diff_id: l.diff_id,
            chain_id: l.chain_id,
        })
        .collect()
}

pub async fn the_feed_layers_carry_the_oci_chain_ids(f: &Factory) {
    let (_tmp, s) = begin!(f, "the_feed_layers_carry_the_oci_chain_ids");
    let (base, top) = (base_layer(), top_layer());
    let offer = offer(&s, &[&base, &top]).await;
    let stack = offer.stack(&[0, 1, 0]);
    let diffs: Vec<Digest> = stack.iter().map(|l| l.diff_id).collect();
    let want = independent_chains(&diffs);
    assert_eq!(
        stack.iter().map(|l| l.chain_id).collect::<Vec<_>>(),
        want,
        "the chain ids of the OCI formula"
    );
    assert_eq!(
        stack[0].chain_id, stack[0].diff_id,
        "ChainID(L0) = DiffID(L0)"
    );
    assert_eq!(stack[0].parent, None);
    assert_eq!(stack[1].parent, Some(want[0]));
    assert_eq!(stack[2].parent, Some(want[1]));
    // what a driver pulls gets to the feed as the engine made it
    let chained = Chained::of(s.driver.clone());
    offer
        .pull_by(chained.as_ref(), &stack, engine_check())
        .await
        .expect("a chained driver pulls the whole stack");
    let seen: HashSet<Digest> = offer
        .meddle()
        .chains
        .lock()
        .unwrap()
        .iter()
        .copied()
        .collect();
    assert!(
        seen.is_subset(&want.iter().copied().collect()),
        "the feed saw a chain id the engine did not make"
    );
    assert!(seen.contains(&want[0]) && seen.contains(&want[1]));
    // a driver that holds layers by chain holds exactly the stack's
    assert!(want.iter().all(|c| chained.holds(c)));
    assert!(!chained.holds(&stack[0].diff_id) || stack[0].diff_id == want[0]);
}

pub async fn a_pull_gets_the_whole_list_with_the_stored_ones_marked(f: &Factory) {
    let (_tmp, s) = begin!(f, "a_pull_gets_the_whole_list_with_the_stored_ones_marked");
    let (base, top) = (base_layer(), top_layer());
    let first = offer(&s, &[&base]).await;
    let both = offer(&s, &[&base, &top]).await;
    let chained = Chained::of(s.driver.clone());
    // the base is stored by a first pull
    let pulled = first
        .pull_by(chained.as_ref(), &first.stack(&[0]), engine_check())
        .await
        .unwrap();
    record(&s, &pulled).await;
    // the image of both: the base is in the list, marked stored, with the
    // chain below the top layer
    let mut list = both.stack(&[0, 1]);
    list[0].stored = true;
    assert_eq!(
        chained.has_layers(&refs_of(&list)).await.unwrap(),
        [true, false],
        "the driver says it has the base and not the top: the engine marks \
         the base stored"
    );
    let pulled = both
        .pull_by(chained.as_ref(), &list, engine_check())
        .await
        .expect("the top layer's parent is in the list and held");
    assert_eq!(both.fetches(), 1, "only the missing layer is fetched");
    assert_eq!(pulled.layers.len(), 1);
    assert_eq!(pulled.layers[0].key, list[1].key);
    assert!(chained.holds(&list[1].chain_id));
    // the same with a driver that is content keyed: only what is missing
    let other = second(f, &s, "plain").await;
    let plain = offer(&other, &[&base, &top]).await;
    let mut list = plain.stack(&[0, 1]);
    list[0].stored = true;
    let pulled = plain
        .pull_layers(&other, &list, engine_check())
        .await
        .unwrap();
    assert_eq!(plain.fetches(), 1, "a stored layer is not fetched");
    assert_eq!(pulled.layers.len(), 1);
    // a list of the layers the driver lacks, without the parents, is what a
    // chained driver cannot use: it refuses it (the API must carry them)
    let fresh = Chained::of(s.driver.clone());
    let lacking = both.stack(&[0, 1]);
    let e = both
        .pull_by(fresh.as_ref(), &lacking[1..], engine_check())
        .await
        .err()
        .expect("refused");
    assert!(e.message().contains("not there"), "{e:?}");
    // and a layer marked stored that the driver does not hold
    let mut list = both.stack(&[0, 1]);
    list[0].stored = true;
    let e = both
        .pull_by(fresh.as_ref(), &list, engine_check())
        .await
        .err()
        .expect("refused");
    assert!(e.message().contains("not held"), "{e:?}");
}

pub async fn the_same_layer_at_another_place_is_another_chain(f: &Factory) {
    let (_tmp, s) = begin!(f, "the_same_layer_at_another_place_is_another_chain");
    let (base, top) = (base_layer(), top_layer());
    let o = offer(&s, &[&base, &top]).await;
    // X = base, top.  Y = base, top, base.  Z = top, base.
    let (x, y, z) = (o.stack(&[0, 1]), o.stack(&[0, 1, 0]), o.stack(&[1, 0]));
    // a shared prefix has the same chain ids
    assert_eq!(x[0].chain_id, y[0].chain_id);
    assert_eq!(x[1].chain_id, y[1].chain_id);
    // after the divergence: the same content, another chain
    assert_eq!(y[0].diff_id, y[2].diff_id);
    assert_ne!(y[0].chain_id, y[2].chain_id);
    assert_ne!(x[1].chain_id, z[0].chain_id);
    assert_ne!(x[0].chain_id, z[1].chain_id);
    assert_ne!(x[1].chain_id, z[1].chain_id);
    // a chained driver that has X has not Y's third layer (the key is the
    // base's, which it has, under another parent), nor any layer of Z
    let chained = Chained::of(s.driver.clone());
    let pulled = o
        .pull_by(chained.as_ref(), &x, engine_check())
        .await
        .unwrap();
    record(&s, &pulled).await;
    assert_eq!(
        chained.has_layers(&refs_of(&x)).await.unwrap(),
        [true, true],
        "X is held"
    );
    assert_eq!(
        chained.has_layers(&refs_of(&y)).await.unwrap(),
        [true, true, false],
        "Y: the third layer is another chain, not held"
    );
    assert_eq!(
        chained.has_layers(&refs_of(&z)).await.unwrap(),
        [false, false]
    );
    // a key asked at two places is answered at each place (one answer for
    // each position: the first is held, the other is not)
    let mut both_places = refs_of(&y[..1]);
    both_places.extend(refs_of(&y[2..]));
    assert_eq!(
        chained.has_layers(&both_places).await.unwrap(),
        [true, false]
    );
    // pulling Y with X's layers stored makes the third one: fetched again
    // only for its place
    let mut list = y.clone();
    list[0].stored = true;
    list[1].stored = true;
    let pulled = o
        .pull_by(chained.as_ref(), &list, engine_check())
        .await
        .unwrap();
    assert_eq!(pulled.layers.len(), 1);
    assert!(chained.holds(&y[2].chain_id));
    record(&s, &pulled).await;
    assert_eq!(
        chained.has_layers(&both_places).await.unwrap(),
        [true, true]
    );
}

pub async fn collect_accepts_the_chains_it_is_told_to_keep(f: &Factory) {
    let (_tmp, s) = begin!(f, "collect_accepts_the_chains_it_is_told_to_keep");
    let (base, top) = (base_layer(), top_layer());
    let o = offer(&s, &[&base, &top]).await;
    let stack = o.stack(&[0, 1]);
    let chained = Chained::of(s.driver.clone());
    o.pull_by(chained.as_ref(), &stack, engine_check())
        .await
        .unwrap();
    let keys: Vec<LayerKey> = stack.iter().map(|l| l.key).collect();
    // the chains of the stack named: everything stays
    let kept = chained.collect(&Keep {
        layers: keys.clone(),
        chains: stack.iter().map(|l| l.chain_id).collect(),
        ..Keep::default()
    });
    let kept = kept.expect("collect");
    assert!(kept.errors.is_empty(), "{kept:?}");
    assert!(stack.iter().all(|l| chained.holds(&l.chain_id)));
    // one chain named: the one above it is collected, whatever its key says
    let kept = chained.collect(&Keep {
        layers: keys.clone(),
        chains: vec![stack[0].chain_id],
        ..Keep::default()
    });
    let kept = kept.expect("collect");
    assert!(kept.errors.is_empty(), "{kept:?}");
    assert!(chained.holds(&stack[0].chain_id) && !chained.holds(&stack[1].chain_id));
    // a driver that ignores the chains (content keyed) keeps what its
    // layers name, whatever the chains say
    let plain = offer(&s, &[&base, &top]).await;
    let pulled = plain.pull(&s, engine_check()).await.unwrap();
    record(&s, &pulled).await;
    let junk = Digest::of(velarx_types::digest::Algorithm::Sha256, b"no chain");
    let kept = s.driver.collect(&Keep {
        layers: keys,
        chains: vec![junk],
        ..Keep::default()
    });
    let kept = kept.expect("collect");
    assert!(kept.errors.is_empty(), "{kept:?}");
    assert_eq!(kept.bytes_freed, 0, "the keys are the layers it keeps");
    assert_eq!(
        s.driver.has_layers(&refs_of(&stack)).await.unwrap(),
        [true, true]
    );
}

/// The cases of the suite: one test of the harness for each.  `$factory` is
/// an expression of the type [`Factory`] (evaluated in each test, so that
/// each has a driver of its own).
#[macro_export]
macro_rules! conformance_suite {
    ($factory:expr) => {
        $crate::conformance_suite_with!($crate::conformance_cases; $factory);
    };
}

/// [`conformance_suite!`] with the macro `$cases` making the tests of the
/// cases (`$cases! { $factory; case, case, }`): a suite whose cases need a
/// process of their own (a namespace) makes them its way.
#[macro_export]
macro_rules! conformance_suite_with {
    ($cases:path; $factory:expr) => {
        $cases! {
            $factory;
            capabilities_are_consistent,
            status_is_stable_and_says_why,
            rootless_driver_works_for_a_user,
            pull_makes_the_artifacts_of_the_layers,
            the_identity_of_a_layer_is_a_property_of_the_layer,
            pull_is_idempotent,
            a_chunked_pull_asks_only_for_what_the_store_lacks,
            a_chunk_the_driver_holds_is_not_fetched_again,
            a_driver_is_handed_the_table_a_layer_keeps,
            an_interrupted_chunked_pull_is_pulled_again,
            pull_check_sees_the_layers_first,
            a_pull_returns_the_verdict_of_the_check,
            a_pull_the_engine_made_no_image_for_is_refused,
            a_refusal_of_the_engine_leaves_nothing_visible,
            an_interrupted_pull_is_pulled_again,
            concurrent_pulls_of_a_shared_layer_both_complete,
            an_aborted_pull_leaves_what_another_pull_committed,
            a_layer_shared_by_concurrent_pulls_is_fetched_at_most_once,
            every_pull_has_an_id_of_its_own,
            the_diff_id_is_proved_by_reading_back_from_the_driver,
            a_feed_writes_into_the_files_a_driver_hands_over,
            a_feed_with_wrong_bytes_is_refused,
            a_layer_read_whole_is_stored_and_read_back,
            a_layer_read_whole_asks_only_for_what_the_store_lacks,
            a_layer_read_whole_that_is_not_sound_stores_nothing,
            a_feed_writes_a_layer_read_whole_into_the_files_a_driver_hands_over,
            a_layer_read_whole_tells_its_holes_and_frees_its_spool,
            pull_reads_back_byte_for_byte,
            a_layer_keyed_by_sha256_only_is_refused,
            a_gzip_layer_of_a_registry_is_pulled_and_read_back,
            a_layer_that_is_not_stored_is_an_error,
            has_layers_reports_what_a_pull_stored,
            has_layers_does_not_report_what_is_not_committed,
            has_layers_forgets_what_a_collection_removed,
            has_layers_does_not_report_a_layer_it_cannot_serve,
            the_feed_layers_carry_the_oci_chain_ids,
            a_pull_gets_the_whole_list_with_the_stored_ones_marked,
            the_same_layer_at_another_place_is_another_chain,
            collect_accepts_the_chains_it_is_told_to_keep,
            repair_gives_the_artifacts_again,
            remake_staged_of_a_pull_that_is_not_there,
            a_lazy_layer_waits_and_is_completed,
            a_lazy_pull_is_staged_by_the_engine_and_completed_into_the_driver,
            a_staged_file_that_is_not_its_name_is_not_stored,
            a_lazy_pull_of_a_layer_without_file_digests_is_refused,
            rootfs_plan_of_a_request,
            the_plan_of_a_create_is_the_plan_of_every_start,
            rootfs_plan_of_a_missing_layer_says_its_remedy,
            rootfs_plan_declared_limits_hold,
            rootfs_plan_verity_matches_the_capability,
            rootfs_plan_idmap_matches_the_capability,
            the_kernel_mounts_what_the_status_says,
            an_enforced_mount_carries_what_the_driver_measured,
            a_lazy_image_has_a_plan_if_the_driver_is_lazy,
            image_view_is_the_merge_of_the_layers,
            image_view_follows_links_only_inside_the_image,
            image_view_is_read_while_held_and_asked_again,
            image_view_of_missing_layers_says_its_remedy,
            remove_image_forgets_only_the_image,
            check_finds_nothing_in_a_good_image,
            leftovers_are_not_what_the_rows_name,
            collect_keeps_what_it_is_told_to_keep,
            collect_never_removes_what_a_container_or_a_pull_uses,
            read_objects_gives_the_ranges_of_stored_objects,
            more_ranges_than_a_call_takes_are_read_in_order,
            objects_taken_in_order_are_the_objects_of_open_object,
            a_range_larger_than_a_pipe_is_read_after_its_reply,
            read_objects_errors_are_typed,
            owners_are_those_of_the_layers,
            usage_adds_up,
            stores_are_listed_and_dropped_by_a_driver_that_serves_several,
            writable_layer_lifecycle,
            writable_layer_owner_and_limits,
            writable_root_is_the_root_of_the_layer,
            rootfs_has_a_descriptor_when_the_plan_names_one,
            image_volumes_are_what_the_capabilities_say,
            image_volume_create_is_idempotent,
            mounts_gives_a_new_descriptor_at_each_call,
            removing_a_container_removes_its_volumes,
            a_volume_that_was_not_made_is_missing,
            the_idmap_of_a_mount_is_what_was_asked,
            the_root_of_a_container_is_found,
            diff_is_the_tar_of_what_the_container_changed,
            diff_applies_the_options_of_ids_and_times,
            changes_list_what_diff_writes,
            apply_writes_what_diff_wrote,
            diff_apply_and_view_of_a_layer_that_was_never_made,
            the_view_of_a_stopped_container,
            errors_name_their_driver_and_map_to_the_engines,
        }
    };
}

#[macro_export]
macro_rules! conformance_cases {
    ($factory:expr; $($case:ident,)*) => {
        $(
            #[tokio::test]
            async fn $case() {
                let factory: $crate::conformance::Factory = $factory;
                $crate::conformance::$case(&factory).await;
            }
        )*
    };
}

pub use crate::{
    conformance_cases, conformance_suite, conformance_suite_with, volume_conformance_suite,
    volume_conformance_suite_with,
};

/// The feed, with no driver: what a driver that plans its own pull is given
/// (the table of contents) and what it gets for the set it asks.
#[cfg(test)]
mod feed_tests {
    use super::*;
    use velarx_content::pull::session::Session;

    struct Store {
        _tmp: tempfile::TempDir,
        db: Database,
        store: Arc<FileStore>,
        staging: PathBuf,
    }

    async fn store() -> Store {
        let tmp = tempfile::tempdir().unwrap();
        let db = Database::open(tmp.path().join("db")).await.unwrap();
        let store = Arc::new(FileStore::new(tmp.path().join("objects")).unwrap());
        Store {
            staging: tmp.path().join("staging"),
            _tmp: tmp,
            db,
            store,
        }
    }

    /// The layer pulled the way a driver of this process does, into the
    /// store (what `want` says it wants), and what the registry was asked.
    async fn fetch(
        st: &Store,
        reg: &Registry,
        layer: &FeedLayer,
        want: impl FnOnce(&LayerIndex, &FileStore) -> Option<HashSet<String>>,
    ) -> ImageResult<LayerDone> {
        let feed = registry_feed(reg, &st.db, &st.staging, &layer.descriptor, false).await;
        let session = Session::create(&st.staging, st.store.clone()).unwrap();
        let by_session = SessionIncoming::of(session.clone());
        feed.begin(&by_session).await?;
        let into = match want(
            &feed
                .index(layer)
                .await?
                .expect("the index of a chunked layer"),
            &st.store,
        ) {
            Some(keys) => Wanted::of(session.clone(), keys),
            None => by_session,
        };
        let done = feed.fetch(layer, &into).await?;
        feed.end();
        let committed = tokio::task::spawn_blocking(move || session.commit(None))
            .await
            .unwrap()
            .unwrap();
        assert!(!committed.is_empty() || done.report.fetched_files == 0);
        Ok(done)
    }

    /// What the index of a layer lacks in the store, by key: the plan of a
    /// driver that makes its own.
    fn lacking(index: &LayerIndex, store: &FileStore) -> HashSet<String> {
        index
            .toc
            .entries
            .iter()
            .filter(|e| e.entry_type == TocEntryType::Reg && e.size > 0)
            .filter_map(|e| e.content_key())
            .filter(|k| !store.contains(k))
            .collect()
    }

    /// A driver that asks for a set gets that set: only the objects it lacks
    /// are fetched, in as many requests as the merge of their ranges needs
    /// (the files are next to each other: one), and one that says it has a
    /// file it has not cannot pull the layer.
    #[tokio::test]
    async fn the_feed_fetches_the_set_a_driver_asks_for_and_no_more() {
        let reg = Registry::start().await;
        let (one, two) = chunked_layers();
        let (l1, _) = chunked_layer(&reg, &one);
        let (l2, size2) = chunked_layer(&reg, &two);
        let st = store().await;
        // the index is what the registry's metadata says
        let feed = registry_feed(&reg, &st.db, &st.staging, &l2.descriptor, false).await;
        let session = Session::create(&st.staging, st.store.clone()).unwrap();
        feed.begin(&SessionIncoming::of(session)).await.unwrap();
        let index = feed.index(&l2).await.unwrap().expect("an index");
        assert_eq!(
            index
                .toc
                .entries
                .iter()
                .filter(|e| e.entry_type == TocEntryType::Reg && e.size > 0)
                .count(),
            2
        );
        assert!(!index.tarsplit.is_empty());
        assert!(
            registry_feed(&reg, &st.db, &st.staging, &l1.descriptor, false)
                .await
                .index(&l1)
                .await
                .is_err(),
            "no pull was begun"
        );

        // the first layer: all of it
        let first = fetch(&st, &reg, &l1, |_, _| None).await.unwrap();
        assert_eq!(first.report.fetched_files, 3);
        // the second: the driver plans from the index, and lacks one file
        let from = reg.requests().len();
        let mut wanted = None;
        let done = fetch(&st, &reg, &l2, |index, store| {
            wanted = Some(lacking(index, store));
            wanted.clone()
        })
        .await
        .unwrap();
        assert_eq!(wanted.unwrap().len(), 1);
        assert_eq!(
            (done.report.fetched_files, done.report.reused_files),
            (1, 1)
        );
        let (_, requests) = asked_since(&reg, from, size2);
        // (the index, the metadata of the pull, and one request for the file)
        assert!(requests <= 3, "{requests} requests: {:?}", reg.requests());
        let data: Vec<_> = reg.requests()[from..]
            .iter()
            .filter(|r| r.ranges.iter().any(|r| r.end - r.start >= 50_000))
            .cloned()
            .collect();
        assert_eq!(data.len(), 1, "one request for the one file: {data:?}");

        // a driver that says it has what it has not gets no layer: the
        // settlement finds the files that are in no store
        let st2 = store().await;
        let mut done = fetch(&st2, &reg, &l2, |_, _| Some(HashSet::new()))
            .await
            .unwrap();
        assert_eq!(done.report.fetched_files, 0, "{:?}", done.report);
        let err = done.settle(&Default::default(), &st2.store).unwrap_err();
        assert!(err.to_string().contains("is not in the store"), "{err}");
    }
}
