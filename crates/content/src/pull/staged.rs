// SPDX-License-Identifier: Apache-2.0
//! The staging area of lazy pulls, below the staging directory of the store
//! `<store root>/staging` (mode 0700, the file system of `objects/`).
//!
//! The store holds only complete layers and images.  What a lazy pull has
//! before its layers are complete lives here and nowhere in the database:
//!
//! ```text
//! layers/<stem>/files/ab/cdef...  ONE staging directory per layer
//!                         (`LayerKey::file_stem`): the files fetchers staged
//!                         for it, named by their fs-verity digest, sealed
//!                         with fs-verity before they have the name; the
//!                         directory handed to the fetchers
//! meta/<stem>/            what the engine keeps of the layer, never handed
//!                         to a fetcher: `lease` (`flock`, held while files
//!                         are fetched into it), and for a lazily staged
//!                         layer layer.json (written last: the publish
//!                         point), toc.json, tarsplit.zst, toc.zst (the
//!                         table as the registry sent it)
//! composefs/              the EROFS images of the staged layers, moved to
//!                         the store's `composefs/` with the layer's commit
//!                         (`objects` beside it, never made, stands for the
//!                         objects of that store: [`Staging::objects_stand_in`])
//! pulls/<id>/             one per pulling image (the manifest digest's hex):
//!                         pull.json, state.json, progress.json, lease, token
//! ```
//!
//! Everything per pull is written once with a rename (the publish point) and
//! `state.json` and `progress.json` are replaced atomically.  A name in a
//! layer's `files/` is a complete file, so a resume is a scan of the staging
//! of each layer against its table of contents.  The `lease` of a pull is
//! held (`flock`) by the engine service of the store while it completes the
//! pull, so there is never a second; the `lease` of a layer by the process
//! that fetches into it, so that two never fetch the same layer at once.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{self, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use velarx_db::{ImageRecord, LayerKey, LayerReach, LayerRecord};
use velarx_types::digest::Digest;

/// A lease (of a pull, of a layer) or the lock of a pull's directory: let go
/// when it is dropped, also in a process forked meanwhile that still has a
/// copy of its descriptor.
pub type Lease = velarx_sys::flock::Held;

/// The directory of the pulls under the staging directory of the store:
/// `pulls/<id>`.
pub const PULLS: &str = "pulls";
/// The directory of the EROFS images of the staged layers under the
/// staging directory of the store.
pub const COMPOSEFS: &str = "composefs";
/// The directory of the staging directories of the layers, below the
/// staging directory of the store: `layers/<stem>`, which fetchers write
/// into.
pub const LAYERS: &str = "layers";
/// The directory of what the engine keeps of each layer it stages:
/// `meta/<stem>` (its lease, and what a lazy pull knows of it), never
/// handed to a fetcher.
pub const META: &str = "meta";
/// The boot the area was last used in (the kernel's boot id), below the
/// staging directory of the store.
const BOOT: &str = "boot";

/// The state of a pull that is not committed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "kebab-case")]
pub enum PullState {
    /// Waiting for the engine service to complete it (`[pull]
    /// lazy_completers` are completed at once)
    Queued,
    /// The engine service fetches the files
    Running,
    /// The registry wants credentials the engine service does not have
    NeedsCredentials,
    /// The file system is full; retried
    WaitingForSpace,
    /// An error that retrying cannot fix: the staging is kept
    Failed { reason: String },
    /// Removed by the user: collected with the next garbage collection
    Cancelled,
}

impl PullState {
    /// The engine service is to complete the pull.
    pub fn is_open(&self) -> bool {
        matches!(self, Self::Queued | Self::Running | Self::WaitingForSpace)
    }
}

/// `state.json`: the state, when it was written and the process that
/// completes the pull (the engine service of the store).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateFile {
    #[serde(flatten)]
    pub state: PullState,
    pub at: String,
    /// The pid of the process that completes it
    #[serde(default)]
    pub pid: Option<u32>,
}

/// `progress.json`: what the completion has done.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Progress {
    pub files_done: u64,
    pub files_total: u64,
    pub bytes_done: u64,
    pub bytes_total: u64,
    pub layers_done: u64,
    pub layers_total: u64,
    /// The last error that was retried
    #[serde(default)]
    pub error: Option<String>,
    pub updated: String,
}

impl Progress {
    /// Whole percent of the bytes done.
    pub fn percent(&self) -> u64 {
        if self.bytes_total == 0 {
            return if self.layers_total > 0 && self.layers_done >= self.layers_total {
                100
            } else {
                0
            };
        }
        (self.bytes_done.min(self.bytes_total) * 100) / self.bytes_total
    }
}

/// A name a pulling image is to be given when it is committed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StagedTag {
    pub repository: String,
    pub tag: String,
}

/// The signatures found by a pull, for the policy check of a start.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StagedSignatures {
    pub reference: String,
    /// The JSON of the signatures (`record_pull` writes the same)
    pub signatures: Vec<u8>,
}

/// `pull.json`: the pulling image.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StagedPull {
    /// The image id: the hex of the manifest digest
    pub id: String,
    pub manifest_digest: Digest,
    pub config_digest: Digest,
    pub manifest: String,
    pub config: String,
    /// The keys of the layers, in order
    pub layers: Vec<String>,
    pub tags: Vec<StagedTag>,
    /// `(repository, digest)` names of a pull by digest
    pub digest_names: Vec<(String, String)>,
    pub pulls: Vec<StagedSignatures>,
    /// The repository the blobs came from: `registry/repository`
    pub registry_ref: Option<String>,
    /// RFC 3339, the newest pull that named it
    pub started_at: String,
}

impl StagedPull {
    /// The record of the image as the engine's code sees an image: marked
    /// as one that is being pulled.
    pub fn image_record(&self) -> ImageRecord {
        ImageRecord {
            id: self.id.clone(),
            manifest_digest: self.manifest_digest,
            config_digest: self.config_digest,
            manifest: self.manifest.clone(),
            config: self.config.clone(),
            created_at: self.started_at.clone(),
            is_lazy: true,
        }
    }

    /// Add the names and pulls of `other` (the same image, pulled again).
    pub fn join(&mut self, other: &StagedPull) {
        for t in &other.tags {
            if !self.tags.contains(t) {
                self.tags.push(t.clone());
            }
        }
        for n in &other.digest_names {
            if !self.digest_names.contains(n) {
                self.digest_names.push(n.clone());
            }
        }
        for p in &other.pulls {
            match self.pulls.iter_mut().find(|q| q.reference == p.reference) {
                Some(q) => q.signatures = p.signatures.clone(),
                None => self.pulls.push(p.clone()),
            }
        }
        if other.started_at > self.started_at {
            self.started_at = other.started_at.clone();
        }
    }
}

/// `layer.json`: a staged layer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StagedLayerMeta {
    pub key: String,
    pub blob: String,
    pub size: i64,
    pub registry_ref: Option<String>,
    pub reach: LayerReach,
    /// The fs-verity digest of the EROFS image, and the owners of its files
    pub erofs: String,
    pub owners: String,
    pub created_at: String,
}

/// A staged layer as the engine reads it: its record, its table of
/// contents, tar-split and reuse map on demand.
#[derive(Debug, Clone)]
pub struct StagedLayer {
    pub meta: StagedLayerMeta,
    dir: PathBuf,
}

impl StagedLayer {
    pub fn key(&self) -> LayerKey {
        LayerKey::parse(&self.meta.key).expect("a staged layer has a key it was written with")
    }

    /// The record as the engine's code sees a layer: marked as lazy, with the
    /// table of contents when `toc` is asked for.
    pub fn record(&self, toc: bool) -> io::Result<LayerRecord> {
        Ok(LayerRecord {
            key: self.key(),
            blob: self.meta.blob.parse().ok(),
            diff_id: None,
            other_diff_id: None,
            size: self.meta.size,
            toc: if toc { Some(self.toc_text()?) } else { None },
            status: "lazy".to_string(),
            created_at: self.meta.created_at.clone(),
            registry_ref: self.meta.registry_ref.clone(),
            erofs: Some(self.meta.erofs.clone()),
            owners: Some(self.meta.owners.clone()),
            stream_size: None,
        })
    }

    pub fn toc_text(&self) -> io::Result<String> {
        std::fs::read_to_string(self.dir.join("toc.json"))
    }

    pub fn tarsplit(&self) -> io::Result<Vec<u8>> {
        std::fs::read(self.dir.join("tarsplit.zst"))
    }

    /// The table as the registry sent it, recorded with the layer.
    pub fn toc_z(&self) -> io::Result<Option<Vec<u8>>> {
        match std::fs::read(self.dir.join("toc.zst")) {
            Ok(toc_z) => Ok(Some(toc_z)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }
}

/// What a layer is published with.
pub struct NewLayer<'a> {
    pub meta: StagedLayerMeta,
    pub toc: &'a str,
    pub tarsplit: &'a [u8],
    pub toc_z: Option<&'a [u8]>,
}

/// A pull in the area, with what is known of its completion.
#[derive(Debug, Clone)]
pub struct PullEntry {
    pub pull: StagedPull,
    pub state: StateFile,
    pub progress: Progress,
    /// A process holds its lease: an engine service completes it
    pub completer_alive: bool,
}

/// The staging area of the store whose staging directory is `staging`.
#[derive(Debug, Clone)]
pub struct Staging {
    /// `staging`
    base: PathBuf,
}

/// What a publish writes, named once all of it is written:
///
/// 1. the files of a directory nothing reads yet (those of a pull before
///    its directory has its name, the table and the tar-split of a layer
///    before its `layer.json`) are written in place;
/// 2. then the publish points (`layer.json`), written aside, are renamed
///    into place.
///
/// A publish point names files of step 1 only: one that names another
/// publish point (a pull, which names its layers) is named after the
/// commit.  Nothing of the staging area is made durable: a lazy pull is
/// transient until it is complete, a reboot discards it
/// ([`Staging::forget_earlier_boots`]), and its completion makes the
/// layers and the image durable before it names them in the store.
#[derive(Default)]
pub struct Barrier {
    /// Written aside, renamed to the path in step 2
    points: Vec<(tempfile::NamedTempFile, PathBuf)>,
    /// Held until the points are named
    leases: Vec<Lease>,
}

impl Barrier {
    /// Write the file `path` of a directory nothing reads before a publish
    /// point of this barrier names it (what it had is replaced).
    fn write(&mut self, path: &Path, bytes: &[u8]) -> io::Result<()> {
        write_private(path, bytes)?;
        Ok(())
    }

    /// Write `bytes` aside, to be the publish point `path` in step 2.
    fn publish(&mut self, path: &Path, bytes: &[u8]) -> io::Result<()> {
        let mut tmp = tempfile::Builder::new()
            .prefix(".tmp")
            .tempfile_in(parent(path)?)?;
        tmp.write_all(bytes)?;
        self.points.push((tmp, path.to_path_buf()));
        Ok(())
    }

    /// Hold `lease` until the commit.
    fn hold(&mut self, lease: Lease) {
        self.leases.push(lease);
    }

    /// Step 2.
    pub fn commit(self) -> io::Result<()> {
        for (tmp, path) in self.points {
            tmp.persist(path).map_err(|e| e.error)?;
        }
        Ok(())
    }
}

/// Write the file `path` (mode 0600), replacing what it had.
fn write_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)
}

fn parent(path: &Path) -> io::Result<&Path> {
    path.parent()
        .ok_or_else(|| io::Error::other("a path without a directory"))
}

/// Replace the file `path` by a rename (not durable: see [`Barrier`]).
fn write_atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut tmp = tempfile::Builder::new()
        .prefix(".tmp")
        .tempfile_in(parent(path)?)?;
    tmp.write_all(bytes)?;
    tmp.persist(path).map_err(|e| e.error)?;
    Ok(())
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> io::Result<Option<T>> {
    match std::fs::read(path) {
        Ok(d) => serde_json::from_slice(&d).map(Some).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{}: {e}", path.display()),
            )
        }),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

impl Staging {
    /// The area under `staging_dir` (`<root>/staging`); nothing is made.
    pub fn new(staging_dir: &Path) -> Self {
        Self {
            base: staging_dir.to_path_buf(),
        }
    }

    /// Make the directories of the area (0700).
    pub fn create(&self) -> io::Result<()> {
        for d in [COMPOSEFS, PULLS, LAYERS, META] {
            velarx_base::ipc::create_private_dirs(&self.base.join(d))?;
        }
        Ok(())
    }

    /// What the area holds of an earlier boot goes: nothing of it was made
    /// durable ([`Barrier`]), so a lazy pull does not outlive a reboot (one
    /// whose engine stopped is resumed by the next).  Called by the process
    /// that is alone in the store at its start: the pulls and the layers a
    /// process holds stay (a process of this boot), everything else of the
    /// pulls, the layers and their EROFS images goes, read or not.
    pub fn forget_earlier_boots(&self) -> io::Result<()> {
        let now = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")?;
        let boot = self.base.join(BOOT);
        if std::fs::read_to_string(&boot).is_ok_and(|b| b == now) {
            return Ok(());
        }
        let names = |dir: &str| -> Vec<String> {
            std::fs::read_dir(self.base.join(dir))
                .into_iter()
                .flatten()
                .flatten()
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .collect()
        };
        // (what is gone meanwhile is gone)
        let removed = |r: io::Result<()>| match r {
            Err(e) if e.kind() != io::ErrorKind::NotFound => Err(e),
            _ => Ok(()),
        };
        for id in names(PULLS) {
            if id.starts_with('.') {
                removed(velarx_base::tree::remove_dir_all(
                    self.images_dir().join(&id),
                ))?;
            } else if !self.lease_held(&id) {
                self.remove_pull(&id)?;
            }
        }
        let mut stems: BTreeSet<String> = names(META).into_iter().collect();
        stems.extend(names(LAYERS));
        let mut kept = BTreeSet::new();
        for stem in stems {
            let Some(_lease) = self.lease_stem_if(&stem, false)? else {
                kept.insert(stem);
                continue;
            };
            for dir in [META, LAYERS] {
                removed(velarx_base::tree::remove_dir_all(
                    self.base.join(dir).join(&stem),
                ))?;
            }
        }
        // (an image is `layer-<stem>.<format>`)
        for name in names(COMPOSEFS) {
            let stem = name
                .strip_prefix("layer-")
                .and_then(|n| n.split('.').next());
            if !stem.is_some_and(|stem| kept.contains(stem)) {
                removed(std::fs::remove_file(self.base.join(COMPOSEFS).join(&name)))?;
            }
        }
        velarx_base::ipc::create_private_dirs(&self.base)?;
        write_atomic(&boot, now.as_bytes())
    }

    /// The staging directory of the store.
    pub fn root(&self) -> &Path {
        &self.base
    }

    /// The area must be on the file system of the objects of the store
    /// (`objects`): a staged file gets its name in the store by a link of
    /// its very inode, sealed with fs-verity as it is, never by a copy.  The
    /// error names both when it is not (a mount over `staging/`).
    pub fn require_store_fs(&self, objects: &Path) -> io::Result<()> {
        use std::os::unix::fs::MetadataExt;
        self.create()?;
        let (area, store) = (std::fs::metadata(&self.base)?, std::fs::metadata(objects)?);
        if area.dev() != store.dev() {
            return Err(io::Error::other(format!(
                "the staging area of lazy pulls {} is not on the file system of the store {}: \
                 a lazy pull needs them on one file system",
                self.base.display(),
                objects.display()
            )));
        }
        Ok(())
    }

    /// The staging directory of the layer `key`, which the fetchers stage
    /// its files in: `files/ab/cdef...` below it.
    pub fn layer_staging(&self, key: &LayerKey) -> PathBuf {
        self.base.join(LAYERS).join(key.file_stem())
    }

    /// The files staged for the layer `key`, named as in a store.
    pub fn layer_files(&self, key: &LayerKey) -> PathBuf {
        self.layer_staging(key).join("files")
    }

    /// The lease of the layer `key` (`meta/<stem>/lease`), held exclusive
    /// until the file is dropped: one process fetches into the staging of
    /// a layer at once; whoever else wants it waits for the kernel to give
    /// it the lock (no polling) and then finds what the holder staged.
    pub fn lease_layer(&self, key: &LayerKey) -> io::Result<Lease> {
        self.lease_stem(&key.file_stem())
    }

    /// [`Self::lease_layer`] of the layer whose staging is named `stem`.  An
    /// eager pull removes the staging with its lease as it lets go: a lock
    /// got on a file that is not the one of the path any more is let go and
    /// the one of the path is taken (once per holder that removed it, never
    /// a loop of tries).
    pub fn lease_stem(&self, stem: &str) -> io::Result<Lease> {
        Ok(self
            .lease_stem_if(stem, true)?
            .expect("a blocking lease is taken"))
    }

    /// The lease of the layer whose staging is named `stem`; with `wait`
    /// false, `None` when another holds it.
    fn lease_stem_if(&self, stem: &str, wait: bool) -> io::Result<Option<Lease>> {
        use rustix::fs::FlockOperation::{LockExclusive, NonBlockingLockExclusive};
        let dir = self.layers_dir().join(stem);
        loop {
            velarx_base::ipc::create_private_dirs(&dir)?;
            let lease = match std::fs::OpenOptions::new()
                .create(true)
                .truncate(false)
                .write(true)
                .mode(0o600)
                .open(dir.join("lease"))
            {
                Ok(lease) => lease,
                // (a sweep took the directory away between the two: make it
                // again; the re-check of the inode below bounds the loop)
                Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
                Err(e) => return Err(e),
            };
            match rustix::fs::flock(
                &lease,
                if wait {
                    LockExclusive
                } else {
                    NonBlockingLockExclusive
                },
            ) {
                Ok(()) => {}
                Err(rustix::io::Errno::WOULDBLOCK) if !wait => return Ok(None),
                Err(e) => return Err(e.into()),
            }
            let lease = Lease::new(lease);
            let held = rustix::fs::fstat(&lease).map_err(io::Error::from)?;
            match rustix::fs::stat(dir.join("lease")) {
                Ok(now) if (now.st_dev, now.st_ino) == (held.st_dev, held.st_ino) => {
                    return Ok(Some(lease))
                }
                _ => continue,
            }
        }
    }

    /// A path that stands for the `objects` directory of a store whose
    /// `composefs/` is that of the area: the EROFS images of the staged
    /// layers (`fuse::composefs::layer_image_path`).
    pub fn objects_stand_in(&self) -> PathBuf {
        self.base.join("objects")
    }

    fn layers_dir(&self) -> PathBuf {
        self.base.join(META)
    }

    fn images_dir(&self) -> PathBuf {
        self.base.join(PULLS)
    }

    pub fn layer_dir(&self, key: &LayerKey) -> PathBuf {
        self.layers_dir().join(key.file_stem())
    }

    pub fn image_dir(&self, id: &str) -> PathBuf {
        self.images_dir().join(id)
    }

    /// Whether the area of the pulls exists (a store that never pulled
    /// lazily has none).
    pub fn exists(&self) -> bool {
        self.images_dir().is_dir()
    }

    /// Publish a layer by rename; one that is there already is the same
    /// (its key names its table of contents) and is kept, as a completer
    /// may be reading it, with the blob and reach of this pull.
    pub fn publish_layer(&self, layer: &NewLayer<'_>) -> io::Result<()> {
        let mut barrier = Barrier::default();
        self.publish_layer_in(layer, &mut barrier)?;
        barrier.commit()
    }

    /// [`Self::publish_layer`], durable and named when `barrier` commits
    /// (before the pull that names the layer is published).
    pub fn publish_layer_in(&self, layer: &NewLayer<'_>, barrier: &mut Barrier) -> io::Result<()> {
        self.create()?;
        let key = LayerKey::parse(&layer.meta.key)
            .ok_or_else(|| io::Error::other(format!("{:?} is no layer key", layer.meta.key)))?;
        let dir = self.layer_dir(&key);
        // (under the lease of the layer, as its removal is: a publish does
        // not meet a removal half made, nor a commit that takes it away)
        barrier.hold(self.lease_layer(&key)?);
        // (the directory may be there with only the lease of a fetch)
        velarx_base::ipc::create_private_dirs(&dir)?;
        if let Some(there) = read_json::<StagedLayerMeta>(&dir.join("layer.json"))? {
            // The same TOC, pulled again: the table, the tar-split and the
            // image are the same.  The blob, the registry and how it was
            // reached are those of the last pull (the fetches ask that
            // registry for that blob).
            let meta = StagedLayerMeta {
                erofs: there.erofs.clone(),
                owners: there.owners.clone(),
                created_at: there.created_at.clone(),
                ..layer.meta.clone()
            };
            if meta != there {
                barrier.publish(
                    &dir.join("layer.json"),
                    &serde_json::to_vec(&meta).map_err(io::Error::other)?,
                )?;
            }
            return Ok(());
        }
        // (`layer.json` is the publish point: without it, nothing reads the
        // table and the tar-split, which a publish cut short left)
        barrier.write(&dir.join("toc.json"), layer.toc.as_bytes())?;
        barrier.write(&dir.join("tarsplit.zst"), layer.tarsplit)?;
        if let Some(toc_z) = layer.toc_z {
            barrier.write(&dir.join("toc.zst"), toc_z)?;
        }
        barrier.publish(
            &dir.join("layer.json"),
            &serde_json::to_vec(&layer.meta).map_err(io::Error::other)?,
        )
    }

    /// The staged layer `key`, if it is staged.
    pub fn layer(&self, key: &LayerKey) -> io::Result<Option<StagedLayer>> {
        let dir = self.layer_dir(key);
        Ok(read_json::<StagedLayerMeta>(&dir.join("layer.json"))?
            .map(|meta| StagedLayer { meta, dir }))
    }

    /// Remove the staged layer: what the engine knows of it, then its
    /// staging directory with the files staged in it, under its lease: a
    /// fetch into it (of this process too, which holds the lease by another
    /// descriptor) ends first.  The caller holds no lock a holder of the
    /// lease waits for.
    pub fn remove_layer(&self, key: &LayerKey) -> io::Result<()> {
        let _lease = self.lease_layer(key)?;
        self.remove_layer_dirs(key)
    }

    /// [`Self::remove_layer`] unless a process fetches into the layer (holds
    /// its lease): false then, and the layer stays.
    pub fn remove_layer_unless_leased(&self, key: &LayerKey) -> io::Result<bool> {
        let Some(_lease) = self.lease_stem_if(&key.file_stem(), false)? else {
            return Ok(false);
        };
        self.remove_layer_dirs(key)?;
        Ok(true)
    }

    fn remove_layer_dirs(&self, key: &LayerKey) -> io::Result<()> {
        for dir in [self.layer_dir(key), self.layer_staging(key)] {
            match velarx_base::tree::remove_dir_all(dir) {
                Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(e),
                _ => {}
            }
        }
        Ok(())
    }

    /// The keys of the staged layers.
    pub fn layer_keys(&self) -> Vec<LayerKey> {
        let Ok(entries) = std::fs::read_dir(self.layers_dir()) else {
            return Vec::new();
        };
        entries
            .flatten()
            .filter_map(|e| {
                let name = e.file_name().to_string_lossy().into_owned();
                if name.starts_with('.') {
                    return None;
                }
                read_json::<StagedLayerMeta>(&e.path().join("layer.json"))
                    .ok()
                    .flatten()
                    .and_then(|m| LayerKey::parse(&m.key))
            })
            .collect()
    }

    /// Publish a pull by rename; the names and pulls are merged into one
    /// that is there already, under its lease.  Returns the pull as it is
    /// published.
    pub fn publish_pull(&self, pull: &StagedPull) -> io::Result<StagedPull> {
        self.publish_pull_after(pull, Barrier::default())
    }

    /// [`Self::publish_pull`] once `barrier`, which holds what the pull
    /// names (its layers), is committed together with the files of the pull,
    /// which are named after it.
    pub fn publish_pull_after(
        &self,
        pull: &StagedPull,
        barrier: Barrier,
    ) -> io::Result<StagedPull> {
        self.create()?;
        let dir = self.image_dir(&pull.id);
        if dir.join("pull.json").is_file() {
            // (read under the lock: two pulls that join at once keep both
            // their names)
            let _lock = match self.lock_pull_file(&pull.id) {
                Err(e) if e.kind() == io::ErrorKind::NotFound => {
                    return self.publish_new(pull, barrier)
                }
                other => other?,
            };
            let Some(mut there) = read_json::<StagedPull>(&dir.join("pull.json"))? else {
                // (removed meanwhile: committed or cancelled; published anew)
                drop(_lock);
                return self.publish_new(pull, barrier);
            };
            there.join(pull);
            // (the layers it names first)
            barrier.commit()?;
            write_atomic(
                &dir.join("pull.json"),
                &serde_json::to_vec(&there).map_err(io::Error::other)?,
            )?;
            // (a pull again of a failed or cancelled one starts it over)
            if !self.state(&pull.id)?.state.is_open() {
                self.set_state(&pull.id, PullState::Queued, None)?;
            }
            return Ok(there);
        }
        self.publish_new(pull, barrier)
    }

    /// Publish a pull that is not there by the rename of a directory made
    /// aside; one published meanwhile by another command is joined.
    fn publish_new(&self, pull: &StagedPull, mut barrier: Barrier) -> io::Result<StagedPull> {
        let dir = self.image_dir(&pull.id);
        let new = tempfile::Builder::new()
            .prefix(".new-")
            .tempdir_in(self.images_dir())?;
        barrier.write(
            &new.path().join("pull.json"),
            &serde_json::to_vec(pull).map_err(io::Error::other)?,
        )?;
        barrier.write(
            &new.path().join("state.json"),
            &serde_json::to_vec(&StateFile {
                state: PullState::Queued,
                at: now(),
                pid: None,
            })
            .map_err(io::Error::other)?,
        )?;
        // (the token of its image servers: `Self::token`)
        barrier.write(
            &new.path().join("token"),
            velarx_base::random::token().as_bytes(),
        )?;
        barrier.commit()?;
        let new = new.keep();
        match std::fs::rename(&new, &dir) {
            Ok(()) => Ok(pull.clone()),
            // (published meanwhile by another command: join it)
            Err(_) if dir.join("pull.json").is_file() => {
                let _ = velarx_base::tree::remove_dir_all(&new);
                self.publish_pull(pull)
            }
            Err(e) => {
                let _ = velarx_base::tree::remove_dir_all(&new);
                Err(e)
            }
        }
    }

    /// The names are merged under a lock of their own: the lease is the
    /// completer's for its whole life.
    fn lock_pull_file(&self, id: &str) -> io::Result<velarx_sys::flock::Held> {
        velarx_storage::locks::lock(&self.image_dir(id).join("names.lock"), true)
            .map(|f| f.expect("a wait gives the lock or an error"))
    }

    /// The token of the pull: what the image servers of its containers are
    /// handed at their start, and show to the engine that holds the pull
    /// for each file they ask (`crate::imagefetch`).  Made with the pull,
    /// readable by its owner only.
    pub fn token(&self, id: &str) -> io::Result<String> {
        let text = std::fs::read_to_string(self.image_dir(id).join("token"))?;
        match text.len() == 32 && text.bytes().all(|b| b.is_ascii_hexdigit()) {
            true => Ok(text),
            false => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("the token of the pull {id} is not one"),
            )),
        }
    }

    pub fn pull(&self, id: &str) -> io::Result<Option<StagedPull>> {
        read_json(&self.image_dir(id).join("pull.json"))
    }

    pub fn state(&self, id: &str) -> io::Result<StateFile> {
        Ok(
            read_json(&self.image_dir(id).join("state.json"))?.unwrap_or(StateFile {
                state: PullState::Queued,
                at: now(),
                pid: None,
            }),
        )
    }

    pub fn set_state(&self, id: &str, state: PullState, pid: Option<u32>) -> io::Result<()> {
        write_atomic(
            &self.image_dir(id).join("state.json"),
            &serde_json::to_vec(&StateFile {
                state,
                at: now(),
                pid,
            })
            .map_err(io::Error::other)?,
        )
    }

    pub fn progress(&self, id: &str) -> io::Result<Progress> {
        Ok(read_json(&self.image_dir(id).join("progress.json"))?.unwrap_or_default())
    }

    pub fn set_progress(&self, id: &str, progress: &Progress) -> io::Result<()> {
        write_atomic(
            &self.image_dir(id).join("progress.json"),
            &serde_json::to_vec(progress).map_err(io::Error::other)?,
        )
    }

    /// The lease of the pull, exclusive, if nothing holds it: held for as
    /// long as the file lives.  `NotFound` when the pull is gone (nothing is
    /// made for it: a directory made here would stay and block the next
    /// publication of the pull).
    ///
    /// The lease file is opened relative to a descriptor of the pull's
    /// directory, which is locked (briefly) while the lease is tried: a
    /// look at the lease ([`Self::lease_held`]) takes it for an instant, and
    /// without that lock a process that took it at that instant would find it
    /// held, and start no completer for a pull that has none.
    pub fn take_lease(&self, id: &str) -> io::Result<Option<Lease>> {
        self.try_lease(id).map(|(lease, _guard)| lease)
    }

    /// [`Self::take_lease`] with the lock of the directory, which the caller
    /// keeps until it let the lease go if it only looks.
    fn try_lease(&self, id: &str) -> io::Result<(Option<Lease>, Lease)> {
        use rustix::fs::{openat, FlockOperation, Mode, OFlags};
        let dir = self.lock_pull_dir(id)?;
        let file = File::from(openat(
            &dir,
            "lease",
            OFlags::RDWR | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
        )?);
        match velarx_sys::flock::flock_retrying(&file, FlockOperation::NonBlockingLockExclusive) {
            Ok(()) => Ok((Some(Lease::new(file)), dir)),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok((None, dir)),
            Err(e) => Err(e),
        }
    }

    /// The directory of the pull, open and locked (exclusive): the lease is
    /// tried and the pull removed under this lock.  `NotFound` when the pull
    /// is gone.
    fn lock_pull_dir(&self, id: &str) -> io::Result<Lease> {
        use rustix::fs::FlockOperation;
        let dir = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC)
            .open(self.image_dir(id))?;
        velarx_sys::flock::flock_retrying(&dir, FlockOperation::LockExclusive)?;
        Ok(Lease::new(dir))
    }

    /// Whether a process holds the lease of the pull.
    pub fn lease_held(&self, id: &str) -> bool {
        match self.try_lease(id) {
            Ok((None, _)) => true,
            // (the lease goes before the lock of the directory does)
            Ok((Some(lease), guard)) => {
                drop(lease);
                drop(guard);
                false
            }
            Err(_) => false,
        }
    }

    /// The lease file of the pull, to wait for the end of its completion:
    /// it is held exclusive while an engine completes it, so a shared lock
    /// is got when none does.  Blocks while one does.
    pub fn wait_for_completer(&self, id: &str) -> io::Result<()> {
        use rustix::fs::FlockOperation;
        let path = self.image_dir(id).join("lease");
        let file = match std::fs::OpenOptions::new().read(true).open(&path) {
            Ok(f) => f,
            // (no pull, so no completer)
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e),
        };
        velarx_sys::flock::flock_retrying(&file, FlockOperation::LockShared)
    }

    /// The record (`pull.json`) of every pull in the area, in no order:
    /// nothing else of a pull is read, no lease is tried.
    pub fn pull_records(&self) -> impl Iterator<Item = StagedPull> + '_ {
        let entries = std::fs::read_dir(self.images_dir()).ok();
        entries
            .into_iter()
            .flatten()
            .flatten()
            .filter_map(|e| {
                let id = e.file_name().to_string_lossy().into_owned();
                (!id.starts_with('.')).then_some(id)
            })
            .filter_map(|id| self.pull(&id).ok().flatten())
    }

    /// Every pull in the area, the oldest first.
    pub fn pulls(&self) -> Vec<PullEntry> {
        let Ok(entries) = std::fs::read_dir(self.images_dir()) else {
            return Vec::new();
        };
        let mut out: Vec<PullEntry> = entries
            .flatten()
            .filter_map(|e| {
                let id = e.file_name().to_string_lossy().into_owned();
                if id.starts_with('.') {
                    return None;
                }
                let pull = self.pull(&id).ok().flatten()?;
                Some(PullEntry {
                    state: self.state(&id).ok()?,
                    progress: self.progress(&id).unwrap_or_default(),
                    completer_alive: self.lease_held(&id),
                    pull,
                })
            })
            .collect();
        out.sort_by(|a, b| a.pull.started_at.cmp(&b.pull.started_at));
        out
    }

    /// The pull that `repository:tag`, `repository@digest` or an id (or an
    /// unambiguous prefix of one) names, the newest of those that do.
    pub fn find(&self, reference: &str) -> Option<PullEntry> {
        let pulls = self.pulls();
        let by_id = |bare: &str| {
            let hits: Vec<&PullEntry> = pulls
                .iter()
                .filter(|p| !bare.is_empty() && p.pull.id.starts_with(bare))
                .collect();
            (hits.len() == 1).then(|| hits[0].clone())
        };
        let bare = reference
            .strip_prefix("sha256:")
            .or_else(|| reference.strip_prefix("sha512:"))
            .unwrap_or(reference);
        if bare.chars().all(|c| c.is_ascii_hexdigit()) {
            if let Some(p) = by_id(bare) {
                return Some(p);
            }
        }
        // (a name without a tag is the `latest` of it)
        let named = match reference.rsplit_once(':') {
            Some((_, tag)) if !tag.contains('/') && !reference.contains('@') => {
                reference.to_string()
            }
            _ if reference.contains('@') => reference.to_string(),
            _ => format!("{reference}:latest"),
        };
        pulls.into_iter().rfind(|p| {
            p.pull.tags.iter().any(|t| {
                format!("{}:{}", t.repository, t.tag) == named
                    || docker_short(&t.repository, &t.tag) == named
            }) || p
                .pull
                .digest_names
                .iter()
                .any(|(r, d)| format!("{r}@{d}") == reference)
        })
    }

    /// Remove a pull (its layers are the caller's to remove: another pull
    /// may name them).  Under the lock of its directory: a look at the lease
    /// while the files go would make a lease file again, and the directory
    /// would stay.
    pub fn remove_pull(&self, id: &str) -> io::Result<()> {
        let _dir = match self.lock_pull_dir(id) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
            other => other?,
        };
        match velarx_base::tree::remove_dir_all(self.image_dir(id)) {
            Err(e) if e.kind() != io::ErrorKind::NotFound => Err(e),
            _ => Ok(()),
        }
    }

    /// The keys of the layers that the pulls which are not cancelled name:
    /// what the garbage collection keeps, in the store (the complete layers
    /// of a pulling image) and in the area.
    pub fn pinned_layers(&self) -> BTreeSet<String> {
        self.pulls()
            .into_iter()
            .filter(|p| p.state.state != PullState::Cancelled)
            .flat_map(|p| p.pull.layers)
            .collect()
    }

    /// The staged layers no pull names.
    pub fn unnamed_layers(&self) -> Vec<LayerKey> {
        let named: BTreeSet<String> = self
            .pulls()
            .into_iter()
            .flat_map(|p| p.pull.layers)
            .collect();
        self.layer_keys()
            .into_iter()
            .filter(|k| !named.contains(&k.to_string()))
            .collect()
    }

    /// The files the tables of contents of the staged layers of the pulls
    /// that are not cancelled name, by fs-verity digest, with their sizes.
    pub fn wanted_files(&self) -> BTreeMap<String, u64> {
        let mut out = BTreeMap::new();
        let live: BTreeSet<String> = self.pinned_layers();
        for key in self.layer_keys() {
            if !live.contains(&key.to_string()) {
                continue;
            }
            let Ok(Some(layer)) = self.layer(&key) else {
                continue;
            };
            let Ok(text) = layer.toc_text() else {
                continue;
            };
            if let Ok(toc) = serde_json::from_str::<velarx_storage::Toc>(&text) {
                for e in &toc.entries {
                    if let Some(d) = e.verity() {
                        out.insert(d, e.size);
                    }
                }
            }
        }
        out
    }
}

fn docker_short(repository: &str, tag: &str) -> String {
    let short = repository
        .strip_prefix("docker.io/library/")
        .or_else(|| repository.strip_prefix("docker.io/"))
        .unwrap_or(repository);
    format!("{short}:{tag}")
}

pub fn now() -> String {
    chrono::Utc::now().to_rfc3339()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(n: u8) -> Digest {
        Digest::of(velarx_types::digest::Algorithm::Sha256, &[n])
    }

    fn pull(n: u8, tag: &str) -> StagedPull {
        StagedPull {
            id: digest(n).hex().to_string(),
            manifest_digest: digest(n),
            config_digest: digest(n + 100),
            manifest: "{}".into(),
            config: "{}".into(),
            layers: vec![format!("toc:{}", digest(n + 1))],
            tags: vec![StagedTag {
                repository: "docker.io/library/nginx".into(),
                tag: tag.into(),
            }],
            digest_names: Vec::new(),
            pulls: Vec::new(),
            registry_ref: None,
            started_at: "2026-01-01T00:00:00+00:00".into(),
        }
    }

    fn layer(n: u8) -> (StagedLayerMeta, LayerKey) {
        let key = LayerKey::Toc(digest(n));
        (
            StagedLayerMeta {
                key: key.to_string(),
                blob: digest(n + 50).to_string(),
                size: 10,
                registry_ref: Some("docker.io/library/nginx:latest".into()),
                reach: LayerReach::default(),
                erofs: "sha256:00".into(),
                owners: "[[0],[0]]".into(),
                created_at: now(),
            },
            key,
        )
    }

    /// A staging made before the pull stopped telling what may be shared
    /// still has the fields it wrote: they are ignored.
    #[test]
    fn an_old_staging_is_read() {
        let mut pull_json = serde_json::to_value(pull(1, "a")).unwrap();
        pull_json["shareable"] = true.into();
        assert_eq!(
            serde_json::from_value::<StagedPull>(pull_json).unwrap(),
            pull(1, "a")
        );
        let (meta, _) = layer(2);
        let mut layer_json = serde_json::to_value(&meta).unwrap();
        layer_json["public"] = true.into();
        assert_eq!(
            serde_json::from_value::<StagedLayerMeta>(layer_json).unwrap(),
            meta
        );
    }

    #[test]
    fn a_layer_in_a_barrier_is_named_when_it_commits() {
        let tmp = tempfile::tempdir().unwrap();
        let area = Staging::new(tmp.path());
        let mut barrier = Barrier::default();
        let keys: Vec<LayerKey> = (1..4)
            .map(|n| {
                let (meta, key) = layer(n);
                area.publish_layer_in(
                    &NewLayer {
                        meta,
                        toc: "{}",
                        tarsplit: b"ts",
                        toc_z: None,
                    },
                    &mut barrier,
                )
                .unwrap();
                key
            })
            .collect();
        assert!(keys.iter().all(|k| area.layer(k).unwrap().is_none()));
        let p = pull(1, "latest");
        area.publish_pull_after(&p, barrier).unwrap();
        for k in &keys {
            assert_eq!(area.layer(k).unwrap().unwrap().tarsplit().unwrap(), b"ts");
        }
        assert_eq!(area.pull(&p.id).unwrap().unwrap(), p);
        assert!(area.token(&p.id).is_ok());
    }

    /// The table, the tar-split and the table as sent are written before
    /// `layer.json` names them, which is when the barrier commits.
    #[test]
    fn the_files_of_a_layer_are_written_before_it_is_named() {
        let tmp = tempfile::tempdir().unwrap();
        let area = Staging::new(tmp.path());
        let (meta, key) = layer(1);
        let mut barrier = Barrier::default();
        area.publish_layer_in(
            &NewLayer {
                meta,
                toc: "{}",
                tarsplit: b"ts",
                toc_z: Some(b"tz"),
            },
            &mut barrier,
        )
        .unwrap();
        let dir = area.layer_dir(&key);
        for (name, bytes) in [
            ("toc.json", &b"{}"[..]),
            ("tarsplit.zst", b"ts"),
            ("toc.zst", b"tz"),
        ] {
            assert_eq!(std::fs::read(dir.join(name)).unwrap(), bytes);
        }
        assert!(area.layer(&key).unwrap().is_none());
        barrier.commit().unwrap();
        assert!(area.layer(&key).unwrap().is_some());
    }

    /// What the area holds of an earlier boot goes at the start of the
    /// next, read or not, but what a process holds; what this boot staged
    /// stays.
    #[test]
    fn a_reboot_discards_the_pulls_and_their_layers() {
        let tmp = tempfile::tempdir().unwrap();
        let area = Staging::new(tmp.path());
        let (meta, key) = layer(1);
        area.publish_layer(&NewLayer {
            meta,
            toc: "{}",
            tarsplit: b"ts",
            toc_z: None,
        })
        .unwrap();
        let old = pull(1, "old");
        area.publish_pull(&old).unwrap();
        let held = pull(2, "held");
        area.publish_pull(&held).unwrap();
        let _lease = area.take_lease(&held.id).unwrap().unwrap();
        // (one a crash left unreadable, and its EROFS image)
        std::fs::create_dir_all(area.image_dir("cut")).unwrap();
        std::fs::write(area.image_dir("cut").join("pull.json"), b"").unwrap();
        let image = tmp
            .path()
            .join(COMPOSEFS)
            .join(format!("layer-{}.v1.erofs", key.file_stem()));
        std::fs::write(&image, b"erofs").unwrap();
        std::fs::write(tmp.path().join(BOOT), b"an earlier boot\n").unwrap();
        area.forget_earlier_boots().unwrap();
        assert!(area.pull(&old.id).unwrap().is_none());
        assert!(area.pull(&held.id).unwrap().is_some());
        assert!(!area.image_dir("cut").exists());
        assert!(area.layer(&key).unwrap().is_none());
        assert!(!image.exists());
        // the same boot: nothing goes
        area.publish_pull(&old).unwrap();
        drop(_lease);
        area.forget_earlier_boots().unwrap();
        assert!(area.pull(&old.id).unwrap().is_some());
        assert!(area.pull(&held.id).unwrap().is_some());
    }

    #[test]
    fn a_published_layer_and_pull_are_read_back() {
        let tmp = tempfile::tempdir().unwrap();
        let area = Staging::new(tmp.path());
        let (meta, key) = layer(1);
        area.publish_layer(&NewLayer {
            meta: meta.clone(),
            toc: "{\"version\":1,\"entries\":[]}",
            tarsplit: b"ts",
            toc_z: None,
        })
        .unwrap();
        let got = area.layer(&key).unwrap().unwrap();
        assert_eq!(got.meta, meta);
        assert_eq!(got.tarsplit().unwrap(), b"ts");
        assert_eq!(got.record(true).unwrap().status, "lazy");
        assert!(got.record(false).unwrap().toc.is_none());
        let p = pull(1, "latest");
        area.publish_pull(&p).unwrap();
        assert_eq!(area.pull(&p.id).unwrap().unwrap(), p);
        // a pull has a token of its own, kept when it is joined
        let token = area.token(&p.id).unwrap();
        assert_eq!(token.len(), 32);
        area.publish_pull(&p).unwrap();
        assert_eq!(area.token(&p.id).unwrap(), token);
        assert_eq!(area.state(&p.id).unwrap().state, PullState::Queued);
        // nothing is left of the directories a publish makes
        let names: Vec<_> = std::fs::read_dir(area.root().join(PULLS))
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        assert!(names.iter().all(|n| !n.starts_with('.')), "{names:?}");
    }

    #[test]
    fn a_pull_of_the_same_image_joins_it() {
        let tmp = tempfile::tempdir().unwrap();
        let area = Staging::new(tmp.path());
        area.publish_pull(&pull(1, "latest")).unwrap();
        let mut again = pull(1, "stable");
        again.started_at = "2026-02-01T00:00:00+00:00".into();
        let joined = area.publish_pull(&again).unwrap();
        assert_eq!(joined.tags.len(), 2);
        assert_eq!(joined.started_at, "2026-02-01T00:00:00+00:00");
        assert_eq!(area.pulls().len(), 1);
        // a failed one starts over
        let id = joined.id;
        area.set_state(&id, PullState::Failed { reason: "x".into() }, None)
            .unwrap();
        area.publish_pull(&pull(1, "latest")).unwrap();
        assert_eq!(area.state(&id).unwrap().state, PullState::Queued);
    }

    #[test]
    fn a_crash_during_a_publish_leaves_no_pull() {
        let tmp = tempfile::tempdir().unwrap();
        let area = Staging::new(tmp.path());
        area.create().unwrap();
        // what a process that died before the rename leaves
        let dead = area.root().join(PULLS).join(".new-dead");
        std::fs::create_dir(&dead).unwrap();
        std::fs::write(dead.join("pull.json"), b"{}").unwrap();
        assert!(area.pulls().is_empty());
        assert!(area.pinned_layers().is_empty());
    }

    #[test]
    fn names_resolve_to_the_newest_pull() {
        let tmp = tempfile::tempdir().unwrap();
        let area = Staging::new(tmp.path());
        let old = pull(1, "latest");
        let mut new = pull(2, "latest");
        new.started_at = "2026-03-01T00:00:00+00:00".into();
        area.publish_pull(&old).unwrap();
        area.publish_pull(&new).unwrap();
        for name in ["nginx", "nginx:latest", "docker.io/library/nginx:latest"] {
            assert_eq!(area.find(name).unwrap().pull.id, new.id, "{name}");
        }
        assert_eq!(area.find(&old.id[..12]).unwrap().pull.id, old.id);
        assert!(area.find("alpine").is_none());
    }

    #[test]
    fn the_lease_is_held_by_one() {
        let tmp = tempfile::tempdir().unwrap();
        let area = Staging::new(tmp.path());
        let p = pull(1, "latest");
        area.publish_pull(&p).unwrap();
        assert!(!area.lease_held(&p.id));
        let held = area.take_lease(&p.id).unwrap().unwrap();
        assert!(area.lease_held(&p.id));
        assert!(area.take_lease(&p.id).unwrap().is_none());
        assert!(area.pulls()[0].completer_alive);
        drop(held);
        assert!(!area.lease_held(&p.id));
    }

    /// Asking whether a completer runs for a pull that is gone (committed or
    /// cancelled meanwhile) makes no directory for it: one left there made the
    /// next pull of the image fail to publish (a rename onto a directory
    /// that is not empty).
    #[test]
    fn the_lease_of_a_pull_that_is_gone_makes_no_directory() {
        let tmp = tempfile::tempdir().unwrap();
        let area = Staging::new(tmp.path());
        let p = pull(1, "latest");
        area.publish_pull(&p).unwrap();
        std::fs::remove_dir_all(area.image_dir(&p.id)).unwrap();
        assert!(!area.lease_held(&p.id));
        let e = area.take_lease(&p.id).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::NotFound);
        assert!(!area.image_dir(&p.id).exists());
        area.publish_pull(&p).unwrap();
        assert!(area.pull(&p.id).unwrap().is_some());
    }

    /// A look at the lease while the pull is removed makes no lease file
    /// again in the directory being emptied: the removal does not fail, and
    /// no directory is left to block the next publication.
    #[test]
    fn a_probe_of_the_lease_does_not_stop_a_removal() {
        let tmp = tempfile::tempdir().unwrap();
        let area = Staging::new(tmp.path());
        let p = pull(1, "latest");
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let probe = {
            let (area, id, stop) = (area.clone(), p.id.clone(), stop.clone());
            std::thread::spawn(move || {
                while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                    area.lease_held(&id);
                }
            })
        };
        let mut failed = 0;
        for _ in 0..2000 {
            if area.publish_pull(&p).is_err()
                || area.remove_pull(&p.id).is_err()
                || area.image_dir(&p.id).exists()
            {
                failed += 1;
                let _ = std::fs::remove_dir_all(area.image_dir(&p.id));
            }
        }
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        probe.join().unwrap();
        assert_eq!(failed, 0, "a removal left the directory of the pull");
    }

    /// Looking at the lease (`pulls`, `lease_held`) must not make a
    /// process that takes it at that moment think a completer runs: with
    /// nobody holding it, every take gets it, whatever the probes do.
    #[test]
    fn a_probe_of_the_lease_does_not_make_a_take_fail() {
        let tmp = tempfile::tempdir().unwrap();
        let area = Staging::new(tmp.path());
        let p = pull(1, "latest");
        area.publish_pull(&p).unwrap();
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let probes: Vec<_> = (0..2)
            .map(|_| {
                let (area, id, stop) = (area.clone(), p.id.clone(), stop.clone());
                std::thread::spawn(move || {
                    while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                        area.lease_held(&id);
                    }
                })
            })
            .collect();
        let mut refused = 0;
        for _ in 0..3000 {
            match area.take_lease(&p.id).unwrap() {
                Some(l) => drop(l),
                None => refused += 1,
            }
        }
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        for t in probes {
            t.join().unwrap();
        }
        assert_eq!(refused, 0, "a take saw a lease no completer held");
    }

    #[test]
    fn cancelled_pulls_pin_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        let area = Staging::new(tmp.path());
        let p = pull(1, "latest");
        area.publish_pull(&p).unwrap();
        assert_eq!(area.pinned_layers().len(), 1);
        area.set_state(&p.id, PullState::Cancelled, None).unwrap();
        assert!(area.pinned_layers().is_empty());
    }

    /// Pulls of one image that join at once keep every name: the names are
    /// read and written under the lock of the pull.
    #[test]
    fn pulls_that_join_at_once_keep_every_name() {
        let tmp = tempfile::tempdir().unwrap();
        let area = Staging::new(tmp.path());
        area.publish_pull(&pull(1, "first")).unwrap();
        std::thread::scope(|s| {
            for n in 0..8 {
                let area = area.clone();
                s.spawn(move || area.publish_pull(&pull(1, &format!("t{n}"))).unwrap());
            }
        });
        let tags = area.pull(&pull(1, "x").id).unwrap().unwrap().tags;
        assert_eq!(tags.len(), 9, "{tags:?}");
    }

    /// The area is on the file system of the objects, or a pull is refused
    /// by name.
    #[test]
    fn the_area_must_be_on_the_file_system_of_the_store() {
        use std::os::unix::fs::MetadataExt;
        let tmp = tempfile::tempdir().unwrap();
        let objects = tmp.path().join("objects");
        std::fs::create_dir(&objects).unwrap();
        let area = Staging::new(&tmp.path().join("staging"));
        area.require_store_fs(&objects).unwrap();
        // (another file system, where the machine has one: /dev/shm)
        let shm = std::path::Path::new("/dev/shm");
        if shm
            .metadata()
            .is_ok_and(|m| m.dev() != objects.metadata().unwrap().dev())
        {
            let Ok(other) = tempfile::tempdir_in(shm) else {
                return;
            };
            let err = Staging::new(other.path())
                .require_store_fs(&objects)
                .unwrap_err();
            assert!(
                err.to_string()
                    .contains("not on the file system of the store"),
                "{err}"
            );
        }
    }

    #[test]
    fn progress_is_a_percent_of_the_bytes() {
        let p = Progress {
            bytes_done: 62,
            bytes_total: 100,
            ..Progress::default()
        };
        assert_eq!(p.percent(), 62);
        assert_eq!(Progress::default().percent(), 0);
    }
}
