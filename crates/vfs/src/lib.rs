// SPDX-License-Identifier: Apache-2.0
//! The `vfs` storage driver: podman's driver of that name.  The root file
//! system of a container is a full copy of the files of the layers of its
//! image, made when the container is created: nothing is mounted for the
//! layers (it works rootless without FUSE), and the cost of a container is
//! linear in the size of its image, paid at the create, not at the pull or
//! the run.  It is an explicit choice (`[storage]
//! driver = "vfs"`), never a default or a fallback.
//!
//! - **Pull.**  The engine's pull makes the objects of the store (named by
//!   their fs-verity digest), the table of contents and the tar-split of each
//!   layer, as for every driver; the store has no directory for a layer.
//!   `ingest` records the identity of the layer (the digest of its EROFS image,
//!   made in memory and dropped, and its owners: a sealed manifest, a push and
//!   the checks use it whatever the driver), keeps its table of contents in
//!   `vfs/tocs` (the image view and the copy are made from the tables, without
//!   the database) and measures the files of the store against their fs-verity
//!   digests: that is the only place vfs checks them
//!   (`VerityEnforcement::PullOnly`).
//! - **Create.**  `writable_create` walks the merged tables of the layers
//!   (the whiteouts and opaque directories applied) and writes the root file
//!   system into a directory of the bundle, which is `WritablePaths::upper`:
//!   each regular file by reflink, else `copy_file_range`, else read and write,
//!   from its object of the store (holes kept), the owner, mode, times,
//!   attributes, links and special files of the table.  The ids of a user
//!   namespace are given as each file is made (`IdmapWay::AtCopy`): the
//!   image is never mapped by itself, and nothing is kept for a mapping.  No
//!   hard link of an object is made, since the owner would change the shared
//!   inode: a file is a reflink or a copy.
//! - **Run.**  The plan is `RootfsPlan::Directory { beneath, path }` (the
//!   bundle, and `vfs/root` below it): the monitor opens the copy from the
//!   checked bundle without leaving it and mounts a private `nodev` clone
//!   of it as the root.
//! - **Image mounts.**  `--mount type=image` is a copy of the mounted image for
//!   each mount, made by `image_volume_create` in `<bundle>/vfs/imagevol/N` the
//!   way the root's is (the same walk, the container's ids given as the files
//!   are made: `IdmapDone::Applied`), and removed with the container.  `mounts`
//!   hands it as a `MountFd` plan whose descriptor is a new read-only
//!   `open_tree` clone of the copy, opened below the bundle with no link
//!   followed, at every call.
//! - **Changes.**  The copy holds the whole tree, so the changes of the
//!   container are found by comparing it with the image (`dirtar::copydiff`);
//!   `apply` removes what the layer's whiteouts name.
//!
//! What it does not do (the capabilities say it, and the engine refuses the
//! request before the driver is asked): lazy images, the size limit of the writable layer, peers served from the
//! driver, read-only image stores, fs-verity checks while a container runs.

use async_trait::async_trait;
use rustix::fd::AsFd;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;
use velarx_config::ComposefsDigests;
use velarx_content::layer::dirtar::{self, Change, IdRange};
use velarx_content::layer::holes::HoleWrite;
use velarx_db::{Database, ImageRecord, LayerKey, LayerRecord};
use velarx_fuse::layer_erofs::layer_identity;
use velarx_fuse::plan::{Directory, RootfsPlan};
use velarx_fuse::view::ImageTree;
use velarx_graph::objects::problem;
use velarx_graph::{
    feed, objects, Capabilities, Collected, DiffOptions, DriverError, DriverErrorKind, DriverParts,
    DriverResult, FeedLayer, IdmapDone, IdmapWay, InProcess, Keep, LabelDone, LayerArtifact,
    LayerRef, Limits, MountCaps, MountRequest, Mounts, MountsRequest, ObjectRange, ObjectSink,
    Planned, Prefs, Problem, ProblemKind, PullFeed, Pulled, Purpose, Remedy, Rootfs, Settled,
    Settlement, StoppedView, StorageDriver, TreeSource, Usage, VerityEnforcement, Writable,
    WritableOptions, WritablePaths,
};
use velarx_storage::{FileStore, Toc, VerityMode};

pub mod checkout {
    pub use velarx_graph::directory::*;
}
pub mod view {
    pub use velarx_fuse::MergedView;
}

use checkout::{Building, Copier, Fault, TocSource};
use view::MergedView;

/// The name of the driver.
pub const NAME: &str = "vfs";

static CAPABILITIES: Capabilities = Capabilities {
    lazy: false,
    // (its objects are the engine's: the store service serves them to peers)
    serve_content: true,
    rootless: true,
    verity: Prefs::new(&[VerityEnforcement::PullOnly]),
    shared_stores: false,
    layer_chain: false,
    max_layers: None,
    overlay_upper: false,
    writable_size_limit: false,
    root: MountCaps {
        idmap: Prefs::new(&[IdmapWay::AtCopy]),
    },
    // (a copy of the image for each mount of a container, mapped as it is made)
    volume: Some(MountCaps {
        idmap: Prefs::new(&[IdmapWay::AtCopy]),
    }),
    limits: Limits::V1,
};

/// What the configuration says of the driver.
#[derive(Debug, Clone, Default)]
pub struct VfsOptions {
    /// What the manifests must say of the EROFS digests of their layers
    /// (`[storage] composefs_digests`): checked at pull, as for composefs.
    pub digests: ComposefsDigests,
    /// A process that may not give files the owners the image has (it is
    /// neither root nor in a user namespace that maps them) leaves them its
    /// own, and the files of that owner are taken to have the image's in the
    /// changes of a container (`[storage] vfs_ignore_chown_errors`).
    pub ignore_chown_errors: bool,
    /// Tests only: the plan is a `MountFd` of a detached clone of the copy
    /// (`open_tree`), where the process may mount, to test what the engine
    /// does with a root that is a descriptor; no driver of the product has one.
    #[cfg(test)]
    pub mount_fd: bool,
}

/// What an image mount is told when the driver is asked for one as a root
/// file system (the engine never does: a volume goes through
/// `image_volume_create` and `mounts`).
const NOT_A_ROOT: &str = "the vfs driver makes an image mounted in a container (--mount type=image) with image_volume_create and mounts, not as a root file system";

/// The directory of the copy in a bundle, and what is next to it.
const COPY_DIR: &str = "vfs";
const ROOT: &str = "root";
/// The directory of the copies of the images mounted in the container, in
/// `COPY_DIR`: one for each mount, named by its index.
const IMAGEVOL: &str = "imagevol";
const BASE_FILE: &str = "base.json";

/// What a container's copy was made from (for the size of what the
/// container wrote, which compares the copy with the layers).
#[derive(Debug, Serialize, Deserialize)]
struct Base {
    layers: Vec<String>,
    uid: Vec<[u32; 3]>,
    gid: Vec<[u32; 3]>,
}

pub struct VfsDriver {
    db: Database,
    store: Arc<FileStore>,
    fsverity: VerityMode,
    /// The staging area of the pulls of the store
    staging_dir: PathBuf,
    options: VfsOptions,
    root: PathBuf,
    fault: Option<Fault>,
    views: Mutex<HashMap<String, Weak<MergedView>>>,
    /// The files copied by (reflink, range, plain) by the copies.
    copied: Copied,
}

/// How many files the copies made by each way.
#[derive(Default)]
struct Copied {
    reflink: AtomicU64,
    range: AtomicU64,
    plain: AtomicU64,
}

/// The directory of the tables of contents of the driver at `root`.
fn tocs_in(root: &Path) -> PathBuf {
    root.join("tocs")
}

/// The table of contents of the layer `key` of the driver at `root`.
fn toc_in(root: &Path, key: &LayerKey) -> PathBuf {
    tocs_in(root).join(format!("{}.toc", key.file_stem()))
}

/// Check the files the layers name, and keep their tables of contents
/// (the view of an image and the copy of a container are made from them,
/// without the database).  This is where vfs checks fs-verity: the files
/// are measured against their digests now, at pull.
fn keep_tocs<T: std::borrow::Borrow<Toc>>(
    store: &FileStore,
    verity: VerityMode,
    root: &Path,
    layers: &[(LayerKey, T)],
) -> std::io::Result<()> {
    let src = TocSource { store, verity };
    for (key, toc) in layers {
        checkout::verify_objects(toc.borrow(), &src)
            .map_err(|e| std::io::Error::new(e.kind(), format!("the layer {key}: {e}")))?;
    }
    let dir = tocs_in(root);
    std::fs::create_dir_all(&dir)?;
    for (key, toc) in layers {
        let mut tmp = tempfile::Builder::new()
            .prefix(".tmp-toc")
            .tempfile_in(&dir)?;
        std::io::Write::write_all(
            &mut tmp,
            &serde_json::to_vec(toc.borrow()).map_err(std::io::Error::other)?,
        )?;
        tmp.persist(toc_in(root, key)).map_err(|e| e.error)?;
    }
    // (the files durable with one barrier, then their names)
    store.barrier(&dir)?;
    store.sync_dir(&dir)
}

/// The image below a copy, with the ranges of its user and group ids.
type Base3 = (Arc<MergedView>, Vec<IdRange>, Vec<IdRange>);

fn io_error(e: std::io::Error) -> DriverError {
    if velarx_graph::directory::is_label_refused(&e) {
        return DriverError::label_refused(NAME, e);
    }
    DriverError::io(NAME, e)
}

fn with_path(e: std::io::Error, path: &Path) -> DriverError {
    io_error(std::io::Error::new(
        e.kind(),
        format!("{}: {e}", path.display()),
    ))
}

fn join_error(e: tokio::task::JoinError) -> DriverError {
    DriverError::storage(NAME, e.to_string())
}

fn unsupported(why: impl Into<String>) -> DriverError {
    DriverError::of(NAME, DriverErrorKind::Unsupported, why)
}

fn ranges(maps: &[velarx_proto::pod::IdMapping]) -> Vec<[u32; 3]> {
    maps.iter()
        .map(|m| [m.container_id, m.host_id, m.size])
        .collect()
}

fn walk_ranges(r: &[[u32; 3]]) -> Vec<IdRange> {
    r.iter()
        .map(|[container, host, size]| IdRange {
            container: *container,
            host: *host,
            size: *size,
        })
        .collect()
}

impl VfsDriver {
    /// What the driver can do, for a server that states it before it opens a
    /// store.
    pub fn capabilities_of() -> &'static Capabilities {
        &CAPABILITIES
    }

    /// The driver of the store made of `parts`.
    pub fn new(parts: DriverParts) -> Self {
        let objects = parts.store.root().to_path_buf();
        let root = objects.parent().unwrap_or(&objects).join(COPY_DIR);
        Self {
            db: parts.db,
            store: parts.store,
            fsverity: parts.fsverity,
            staging_dir: parts.staging_dir,
            options: VfsOptions::default(),
            root,
            fault: None,
            views: Mutex::default(),
            copied: Copied::default(),
        }
    }

    pub fn with_options(mut self, options: VfsOptions) -> Self {
        self.options = options;
        self
    }

    /// Make the copies fail as `fault` says (for tests).
    pub fn with_fault(mut self, fault: Fault) -> Self {
        self.fault = Some(fault);
        self
    }

    /// The files copied by (reflink, `copy_file_range`, read and write) since
    /// the driver was made.
    pub fn copied(&self) -> (u64, u64, u64) {
        (
            self.copied.reflink.load(Ordering::Relaxed),
            self.copied.range.load(Ordering::Relaxed),
            self.copied.plain.load(Ordering::Relaxed),
        )
    }

    fn copier(&self) -> Copier {
        match &self.fault {
            Some(f) => Copier::with_fault(f.clone()),
            None => Copier::new(),
        }
        .ignoring_chown_errors(self.options.ignore_chown_errors)
    }

    /// The owner of the files that could not be given the image's.
    fn unowned(&self) -> Option<(u32, u32)> {
        self.options.ignore_chown_errors.then(|| {
            (
                rustix::process::geteuid().as_raw(),
                rustix::process::getegid().as_raw(),
            )
        })
    }

    fn account(&self, c: &Copier) {
        let (a, b, d) = c.counts.get();
        self.copied.reflink.fetch_add(a, Ordering::Relaxed);
        self.copied.range.fetch_add(b, Ordering::Relaxed);
        self.copied.plain.fetch_add(d, Ordering::Relaxed);
    }

    /// The tables of contents the driver keeps (one file for each layer).
    fn tocs_dir(&self) -> PathBuf {
        tocs_in(&self.root)
    }

    fn layer_toc(&self, key: &LayerKey) -> PathBuf {
        toc_in(&self.root, key)
    }

    /// The base (the container's bundle, with no link in its path) and the
    /// way down to the copy of a container, which the monitor mounts: it
    /// opens the base under checks and the copy from it, so it cannot be led
    /// out of the bundle.
    fn copy_root(&self, w: &Writable) -> DriverResult<(PathBuf, PathBuf)> {
        let bundle = w.bundle();
        if !bundle.is_absolute() {
            return Err(DriverError::storage(
                NAME,
                format!("the bundle {} is not an absolute path", bundle.display()),
            ));
        }
        let bundle = std::fs::canonicalize(bundle).unwrap_or_else(|_| bundle.to_path_buf());
        Ok((bundle, Path::new(COPY_DIR).join(ROOT)))
    }

    /// The directory of the copy of a container.
    fn copy_dir(&self, w: &Writable) -> DriverResult<PathBuf> {
        let (bundle, path) = self.copy_root(w)?;
        Ok(bundle.join(path))
    }

    fn toc_of(&self, key: &LayerKey) -> std::io::Result<Toc> {
        let bytes = std::fs::read(self.layer_toc(key))?;
        serde_json::from_slice(&bytes).map_err(std::io::Error::other)
    }

    fn missing_layer(&self, image_id: &str, key: &LayerKey, why: &str) -> DriverError {
        let image = match image_id {
            "" => String::new(),
            id => format!("image {id}: "),
        };
        DriverError::missing(
            NAME,
            Some(key),
            format!("{image}the table of contents of the layer {key} {why}"),
            Remedy::Repair,
        )
    }

    /// The layers of the image, each recorded and with its table of contents
    /// kept.
    fn check_layers(&self, image_id: &str, layers: &[LayerRecord]) -> DriverResult<()> {
        for l in layers {
            if l.erofs.is_none() {
                return Err(self.missing_layer(image_id, &l.key, "is not recorded"));
            }
            if !self.layer_toc(&l.key).is_file() {
                return Err(self.missing_layer(image_id, &l.key, "is not there"));
            }
        }
        Ok(())
    }

    /// The view of the layers with the keys `keys`, shared by whoever asks
    /// for the same while one is alive.
    fn view_of(&self, id: &str, keys: &[LayerKey]) -> DriverResult<Arc<MergedView>> {
        let cache_key = format!(
            "{id}:{}",
            keys.iter()
                .map(LayerKey::file_stem)
                .collect::<Vec<_>>()
                .join(",")
        );
        if let Some(v) = self
            .views
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&cache_key)
            .and_then(Weak::upgrade)
        {
            return Ok(v);
        }
        let mut tocs = Vec::with_capacity(keys.len());
        for k in keys {
            tocs.push(self.toc_of(k).map_err(|e| match e.kind() {
                std::io::ErrorKind::NotFound => {
                    self.missing_layer(id, k, "has no table of contents")
                }
                _ => io_error(e),
            })?);
        }
        let refs: Vec<&Toc> = tocs.iter().collect();
        let view = Arc::new(MergedView::new(&refs).map_err(|e| {
            DriverError::corrupt(
                NAME,
                format!("the tables of contents of the layers make no image: {e}"),
                Remedy::Repair,
            )
        })?);
        self.views
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(cache_key, Arc::downgrade(&view));
        Ok(view)
    }

    /// The identity of each layer, made at once (one thread for each).
    fn identities(
        layers: &[(LayerKey, Toc)],
    ) -> std::io::Result<HashMap<LayerKey, velarx_fuse::layer_erofs::LayerIdentity>> {
        let made: Vec<std::io::Result<_>> = std::thread::scope(|s| {
            let handles: Vec<_> = layers
                .iter()
                .map(|(key, toc)| {
                    s.spawn(move || {
                        layer_identity(key.digest().alg(), &toc.entries)
                            .map(|i| (*key, i))
                            .map_err(|e| {
                                std::io::Error::other(format!("the identity of layer {key}: {e}"))
                            })
                    })
                })
                .collect();
            handles
                .into_iter()
                .map(|h| {
                    h.join()
                        .unwrap_or_else(|_| Err(std::io::Error::other("the making panicked")))
                })
                .collect()
        });
        made.into_iter().collect()
    }

    /// The layers of an image merged (whiteouts applied) and written into the
    /// empty directory `root`, in one pass, the ids of `mapping` given as each
    /// file is made (an explicit stack: no recursion, whatever the depth); an
    /// object that has fs-verity is measured again as it is copied (an ioctl:
    /// the kernel keeps the digest), so one replaced since the pull is
    /// refused, and with `fsverity_require` one without it is too.  Nothing
    /// that is in the image is followed: a link is made as a link.  The keys
    /// of the layers, as the tables of contents are named.
    fn merge_into(
        &self,
        copier: &Copier,
        root: rustix::fd::BorrowedFd<'_>,
        image_id: &str,
        layers: &[LayerRecord],
        mapping: Option<&velarx_fuse::IdTranslate>,
    ) -> std::io::Result<Vec<String>> {
        let keys: Vec<LayerKey> = layers.iter().map(|l| l.key).collect();
        let view = self
            .view_of(image_id, &keys)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::NotFound, e.to_string()))?;
        let (tree, src) = (
            view.tree(),
            TocSource {
                store: &self.store,
                verity: self.fsverity,
            },
        );
        checkout::from_merged(copier, tree, &src, mapping, root).map_err(|e| {
            velarx_graph::directory::io_context(e, format_args!("image {image_id}: "))
        })?;
        Ok(keys.iter().map(LayerKey::file_stem).collect())
    }

    /// The copy of a container: the layers merged into a directory made next
    /// to its name, which it gets when it is whole.
    fn make_copy(
        &self,
        w: &Writable,
        owner: Option<(u32, u32)>,
        base: Option<&MountRequest<'_>>,
    ) -> DriverResult<()> {
        let root = self.copy_dir(w)?;
        if root.is_dir() {
            return Ok(());
        }
        let dir = root.parent().map(Path::to_path_buf).ok_or_else(|| {
            DriverError::storage(NAME, format!("{} has no directory", root.display()))
        })?;
        let copier = self.copier();
        let r = (|| -> std::io::Result<()> {
            let b = Building::new(&dir)?;
            let dst = objects::open_dir(b.path())?;
            let mut recorded = Vec::new();
            let mut mapping = None;
            if let Some(req) = base {
                mapping = req.mapping;
                recorded =
                    self.merge_into(&copier, dst.as_fd(), &req.image.id, req.layers, req.mapping)?;
            } else {
                // (a directory the user gave has no root of an image: the
                // root of the container owns it; the root of an image is
                // what its layers give, owned as the mapping says)
                rustix::fs::fchmod(&dst, rustix::fs::Mode::from_raw_mode(0o755))?;
                if let Some((uid, gid)) = owner {
                    rustix::fs::fchown(
                        &dst,
                        Some(rustix::fs::Uid::from_raw(uid)),
                        Some(rustix::fs::Gid::from_raw(gid)),
                    )?;
                }
            }
            if base.is_some() {
                let base = Base {
                    layers: recorded,
                    uid: mapping.map(|m| ranges(&m.uid)).unwrap_or_default(),
                    gid: mapping.map(|m| ranges(&m.gid)).unwrap_or_default(),
                };
                std::fs::write(
                    dir.join(BASE_FILE),
                    serde_json::to_vec(&base).map_err(std::io::Error::other)?,
                )?;
            }
            drop(dst);
            b.finish(&root)
        })();
        self.account(&copier);
        r.map_err(|e| {
            let _ = checkout::remove_all(&dir);
            match e.kind() {
                std::io::ErrorKind::NotFound => DriverError::of(
                    NAME,
                    DriverErrorKind::Missing {
                        remedy: Remedy::Repair,
                    },
                    e.to_string(),
                ),
                _ => io_error(e),
            }
        })
    }

    /// The image `lower` below the copy of `w`, from what the copy was made
    /// of; none for a copy of nothing (a container with no image, which has
    /// no record of one).  A record that cannot be read, or a table of
    /// contents of it that is gone, is an error.
    fn base_of(&self, w: &Writable) -> DriverResult<Option<Base3>> {
        let copy = self.copy_dir(w)?;
        let Some(dir) = copy.parent() else {
            return Err(DriverError::storage(
                NAME,
                format!("{} has no directory", copy.display()),
            ));
        };
        let file = dir.join(BASE_FILE);
        let bytes = match std::fs::read(&file) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(with_path(e, &file)),
        };
        let base: Base = serde_json::from_slice(&bytes)
            .map_err(|e| with_path(std::io::Error::other(e), &file))?;
        let mut tocs = Vec::new();
        for stem in &base.layers {
            let path = self.tocs_dir().join(format!("{stem}.toc"));
            let bytes = std::fs::read(&path).map_err(|e| with_path(e, &path))?;
            tocs.push(
                serde_json::from_slice::<Toc>(&bytes)
                    .map_err(|e| with_path(std::io::Error::other(e), &path))?,
            );
        }
        let refs: Vec<&Toc> = tocs.iter().collect();
        let view = Arc::new(MergedView::new(&refs).map_err(|e| {
            DriverError::corrupt(
                NAME,
                format!("the tables of contents of the copy make no image: {e}"),
                Remedy::Repair,
            )
        })?);
        Ok(Some((view, walk_ranges(&base.uid), walk_ranges(&base.gid))))
    }

    /// The place of the copy of the image mounted in `w` as its `index`-th
    /// `--mount type=image`: the base (the container's bundle, with no link in
    /// its path) and the way down from it, `vfs/imagevol/N`.
    fn volume_root(&self, w: &Writable, index: u32) -> DriverResult<(PathBuf, PathBuf)> {
        let (bundle, _) = self.copy_root(w)?;
        Ok((
            bundle,
            Path::new(COPY_DIR).join(IMAGEVOL).join(index.to_string()),
        ))
    }

    /// The index of the mount a request is for (a volume, never a root).
    fn volume_index(&self, m: &MountRequest<'_>) -> DriverResult<u32> {
        match m.purpose {
            Purpose::Volume { index } => Ok(index),
            Purpose::Root => Err(DriverError::storage(NAME, NOT_A_ROOT)),
        }
    }

    /// The copy of an image for a container's mount: the layers merged, the
    /// ids of the container's mapping given as each file is made, into a
    /// directory next to its name that it gets when it is whole.  A copy
    /// that is there is whole (it is renamed into place last), so it is
    /// kept; what a crash left half-made (`.tmp-*` with no writer) is removed.
    /// The bytes are the objects of the store by reflink, else
    /// `copy_file_range`, else read and write, as the root's copy.
    fn make_volume(&self, w: &Writable, m: &MountRequest<'_>) -> DriverResult<()> {
        let index = self.volume_index(m)?;
        let (bundle, rel) = self.volume_root(w, index)?;
        let to = bundle.join(&rel);
        // (the directories on the way are the engine's: one that is a link is
        // refused, never followed, before anything is looked at below it)
        for dir in [bundle.join(COPY_DIR), bundle.join(COPY_DIR).join(IMAGEVOL)] {
            match std::fs::symlink_metadata(&dir) {
                Ok(md) if !md.is_dir() => {
                    return Err(DriverError::storage(
                        NAME,
                        format!(
                            "image mount {index}: {} is not a directory (a link is not followed): remove the container and create it again",
                            dir.display()
                        ),
                    ))
                }
                _ => {}
            }
        }
        match std::fs::symlink_metadata(&to) {
            Ok(md) if md.is_dir() => return Ok(()),
            // (not a copy: a link or a file is taken away, never followed)
            Ok(_) => std::fs::remove_file(&to).map_err(io_error)?,
            Err(_) => {}
        }
        let parent = to.parent().map(Path::to_path_buf).ok_or_else(|| {
            DriverError::storage(NAME, format!("{} has no directory", to.display()))
        })?;
        // (the engine cannot label the copy of an image mount afterwards: all
        // it gets of it is a read-only clone at each start, so the files are
        // labelled as they are made)
        let copier = self.copier().labeling(m.label);
        let r = (|| -> std::io::Result<()> {
            std::fs::create_dir_all(&parent)?;
            // (only the engine reaches the copies of the images: they may hold
            // files of any mode and owner, and setuid ones)
            std::fs::set_permissions(&parent, std::os::unix::fs::PermissionsExt::from_mode(0o700))?;
            let _ = checkout::remove_abandoned(&parent);
            let b = Building::new(&parent)?;
            let dst = objects::open_dir(b.path())?;
            self.merge_into(&copier, dst.as_fd(), &m.image.id, m.layers, m.mapping)?;
            drop(dst);
            match b.finish(&to) {
                Ok(()) => Ok(()),
                // (another writer was first: what is there is the same)
                Err(e)
                    if matches!(e.raw_os_error(), Some(libc::EEXIST) | Some(libc::ENOTEMPTY)) =>
                {
                    Ok(())
                }
                Err(e) => Err(e),
            }
        })();
        self.account(&copier);
        r.map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => DriverError::of(
                NAME,
                DriverErrorKind::Missing {
                    remedy: Remedy::PullAgain,
                },
                format!("image mount {index}: {e}"),
            ),
            _ => io_error(velarx_graph::directory::io_context(
                e,
                format_args!("image mount {index}: "),
            )),
        })
    }

    /// A new detached read-only mount of the copy of volume `index` of `w`,
    /// for each call: the copy opened below the bundle with no link followed,
    /// then cloned (`open_tree`, a bind mount: no file system is made, so a
    /// process that is root of a user namespace may).  A copy that is not there
    /// is `Missing`.
    fn volume_fd(&self, w: &Writable, index: u32) -> DriverResult<std::os::fd::OwnedFd> {
        use rustix::mount::{open_tree, OpenTreeFlags};
        let (beneath, path) = self.volume_root(w, index)?;
        let base = rustix::fs::open(
            &beneath,
            rustix::fs::OFlags::PATH
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .map_err(|e| io_error(e.into()))?;
        let dir =
            velarx_sys::fs::open_beneath(base.as_fd(), &path, velarx_sys::fs::Beneath::Directory)
                .map_err(|e| match std::io::Error::from(e).kind() {
                std::io::ErrorKind::NotFound => DriverError::missing(
                    NAME,
                    None,
                    format!(
                        "the image mount {index} of the container {} was never made or is gone",
                        w.id()
                    ),
                    Remedy::RecreateContainer,
                ),
                kind => io_error(std::io::Error::new(
                    kind,
                    format!("open the copy {}: {e}", beneath.join(&path).display()),
                )),
            })?;
        let cloned = open_tree(
            &dir,
            "",
            OpenTreeFlags::OPEN_TREE_CLONE
                | OpenTreeFlags::OPEN_TREE_CLOEXEC
                | OpenTreeFlags::AT_EMPTY_PATH,
        );
        let tree = match cloned {
            Ok(tree) => tree,
            // (a test process that may not mount hands the directory: there
            // is no mount of it to make read-only)
            #[cfg(test)]
            Err(rustix::io::Errno::PERM) if !rustix::process::geteuid().is_root() => return Ok(dir),
            Err(e) => {
                return Err(io_error(std::io::Error::new(
                    std::io::Error::from(e).kind(),
                    format!(
                        "make a mount of the copy {}: {e} (a process that is neither root nor in a user and mount namespace of its own cannot)",
                        beneath.join(&path).display()
                    ),
                )))
            }
        };
        // read-only by definition (the monitor makes it nodev and private
        // when it takes it); this is the clone's own mount, not the bundle's
        velarx_sys::mount::setattr_fd(
            tree.as_fd(),
            &velarx_sys::mount::MountAttr {
                attr_set: libc::MOUNT_ATTR_RDONLY,
                ..Default::default()
            },
        )
        .map_err(|e| {
            io_error(std::io::Error::new(
                e.kind(),
                format!(
                    "make the mount of {} read-only: {e}",
                    beneath.join(&path).display()
                ),
            ))
        })?;
        Ok(tree)
    }

    fn lower(&self, tree: Option<Arc<dyn ImageTree>>) -> DriverResult<Arc<dirtar::Lower>> {
        tree.map(|tree| {
            Arc::new(dirtar::Lower {
                tree,
                objects: self.store.clone(),
            })
        })
        .ok_or_else(|| {
            DriverError::storage(
                NAME,
                "the changes of the copy of an image are found against the image: none was given",
            )
        })
    }
}

#[async_trait]
impl StorageDriver for VfsDriver {
    fn name(&self) -> &str {
        NAME
    }

    fn graph_name(&self) -> &str {
        NAME
    }

    fn capabilities(&self) -> &Capabilities {
        &CAPABILITIES
    }

    fn graph_data(&self, w: &Writable) -> Vec<(String, String)> {
        match self.copy_dir(w) {
            Ok(p) => vec![("Dir".to_string(), p.to_string_lossy().into_owned())],
            Err(_) => Vec::new(),
        }
    }

    fn status(&self) -> Vec<(String, String)> {
        let dir = if self.root.is_dir() {
            self.root.clone()
        } else {
            self.store.root().to_path_buf()
        };
        vec![
            (
                "kernel mount".into(),
                "no (vfs mounts no layer: the root file system of a container is a directory)"
                    .into(),
            ),
            (
                "vfs".into(),
                "a full copy of the files of the image for each container".into(),
            ),
            (
                "copies".into(),
                if checkout::probe_reflink(&dir) {
                    "reflink, else copy_file_range, else copy".into()
                } else {
                    "copy_file_range, else copy (the file system has no reflinks)".into()
                },
            ),
            (
                "fs-verity".into(),
                "checked at pull only (best effort while a container runs)".into(),
            ),
            (
                "composefs digests".into(),
                format!("{:?}", self.options.digests).to_lowercase(),
            ),
        ]
    }

    async fn pull(
        &self,
        feed: &Arc<dyn PullFeed>,
        layers: &[FeedLayer],
        settled: Settled,
    ) -> DriverResult<Pulled> {
        let parts = InProcess {
            driver: NAME,
            store: self.store.clone(),
            staging_dir: self.staging_dir.clone(),
            fsverity: self.fsverity,
        };
        let write: feed::Written<()> = Box::new(|_, _| Ok(((), false)));
        let (pulled, settlement, ()) =
            feed::pull_in_process(&parts, feed, layers, settled, write).await?;
        let Settlement {
            identities,
            verdict,
        } = settlement;
        if let Some(l) = pulled.iter().find(|l| l.lazy) {
            return Err(unsupported(format!(
                "the layer {} was pulled lazily, and the vfs driver copies whole layers: pull without --lazy",
                l.key
            )));
        }
        let tocs: Vec<(LayerKey, Arc<Toc>)> =
            pulled.iter().map(|l| (l.key, Arc::clone(&l.toc))).collect();
        let (store, verity, root) = (self.store.clone(), self.fsverity, self.root.clone());
        // (the identity is the engine's: nothing is made of the layers
        // here, only their tables of contents are kept)
        let artifacts = tokio::task::spawn_blocking(move || {
            keep_tocs(&store, verity, &root, &tocs).map_err(io_error)?;
            Ok::<_, DriverError>(identities.artifacts)
        })
        .await
        .map_err(join_error)??;
        Ok(Pulled {
            layers: pulled,
            artifacts,
            verdict,
        })
    }

    async fn has_layers(&self, layers: &[LayerRef]) -> DriverResult<Vec<bool>> {
        objects::has_layers(NAME, &self.db, layers).await
    }

    async fn repair(&self, layers: &[LayerRef]) -> DriverResult<HashMap<LayerKey, LayerArtifact>> {
        let layers = objects::tocs_of(NAME, &self.db, layers).await?;
        let (store, verity, root) = (self.store.clone(), self.fsverity, self.root.clone());
        tokio::task::spawn_blocking(move || {
            let ids = Self::identities(&layers).map_err(io_error)?;
            keep_tocs(&store, verity, &root, &layers).map_err(io_error)?;
            Ok(ids
                .into_iter()
                .map(|(k, i)| {
                    (
                        k,
                        LayerArtifact {
                            image_digest: i.erofs,
                            owners: i.owners,
                        },
                    )
                })
                .collect())
        })
        .await
        .map_err(join_error)?
    }

    /// Nothing is staged: there are no lazy layers.
    async fn remake_staged(&self, pull: &str) -> DriverResult<()> {
        Err(DriverError::of(
            NAME,
            DriverErrorKind::NotFound,
            format!("the pull {pull} is not there: the vfs driver stages nothing"),
        ))
    }

    fn read_objects(&self, ranges: &[ObjectRange], sink: &mut dyn ObjectSink) -> DriverResult<()> {
        objects::read_objects(NAME, &self.store, ranges, sink)
    }

    fn open_object(&self, key: &str, size: u64) -> DriverResult<std::fs::File> {
        objects::open_object(NAME, &self.store, key, size)
    }

    fn remove_image(&self, image_id: &str) -> DriverResult<()> {
        let prefix = format!("{image_id}:");
        self.views
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .retain(|k, _| !k.starts_with(&prefix));
        Ok(())
    }

    fn image_volume_create(&self, m: &MountRequest<'_>) -> DriverResult<Planned> {
        self.volume_index(m)?;
        if m.image.is_lazy {
            return Err(unsupported(format!(
                "the image {} is being pulled lazily, and the vfs driver copies whole layers",
                m.image.id
            )));
        }
        if m.verity.enforced() {
            return Err(DriverError::of(
                NAME,
                DriverErrorKind::DigestEnforced,
                "the digests of the layers are enforced, and an image mounted in a container of the vfs driver is a copy that states none (fs-verity is checked at pull only: set [storage] fsverity_best_effort = true to accept that)",
            ));
        }
        for l in m.layers {
            if l.erofs.is_none() || !self.layer_toc(&l.key).is_file() {
                return Err(DriverError::missing(
                    NAME,
                    Some(&l.key),
                    format!("image {}: the layer {} is not there", m.image.id, l.key),
                    Remedy::PullAgain,
                ));
            }
        }
        self.make_volume(m.container, m)?;
        Ok(self.volume_rootfs(m, None)?.planned())
    }

    /// The root as a root is (the plan of its copy), the images mounted in the
    /// container as the descriptors of their copies, a new one at each call.
    fn mounts(&self, req: &MountsRequest<'_>) -> DriverResult<Mounts> {
        let root = req.root.as_ref().map(|m| self.root_plan(m)).transpose()?;
        let volumes = req
            .volumes
            .iter()
            .map(|m| {
                let index = self.volume_index(m)?;
                self.volume_rootfs(m, Some(self.volume_fd(m.container, index)?))
            })
            .collect::<DriverResult<_>>()?;
        Ok(Mounts { root, volumes })
    }

    fn image_view(
        &self,
        image_id: &str,
        layers: &[LayerRecord],
    ) -> DriverResult<Arc<dyn ImageTree>> {
        self.check_layers(image_id, layers)?;
        let keys: Vec<LayerKey> = layers.iter().map(|l| l.key).collect();
        Ok(self.view_of(image_id, &keys)?)
    }

    async fn leftovers(&self, grace: Duration) -> DriverResult<Vec<(PathBuf, String)>> {
        let root = self.root.clone();
        tokio::task::spawn_blocking(move || {
            let mut stray = Vec::new();
            if let Ok(rd) = std::fs::read_dir(root.join("tocs")) {
                for e in rd.flatten() {
                    let name = e.file_name().to_string_lossy().into_owned();
                    if name.starts_with(".tmp-")
                        && objects::idle(&e.path()).is_some_and(|i| i >= grace)
                    {
                        stray.push((e.path(), "a temporary file of the vfs layers".into()));
                    }
                }
            }
            stray.sort();
            stray
        })
        .await
        .map_err(join_error)
    }

    async fn check(
        &self,
        _image: &ImageRecord,
        layers: &[LayerRecord],
        full: bool,
    ) -> DriverResult<Vec<Problem>> {
        let work: Vec<(LayerKey, PathBuf, bool, Option<String>)> = layers
            .iter()
            .map(|l| {
                (
                    l.key,
                    self.layer_toc(&l.key),
                    l.erofs.is_some(),
                    l.toc.clone(),
                )
            })
            .collect();
        let (store, fsverity) = (self.store.clone(), self.fsverity);
        tokio::task::spawn_blocking(move || {
            let mut found = Vec::new();
            for (key, toc_path, recorded, recorded_toc) in work {
                if !recorded {
                    found.push(problem(
                        ProblemKind::IdentityMissing,
                        &toc_path,
                        format!("the layer {key} has no recorded EROFS digest and owners"),
                    ));
                }
                let mut toc = match std::fs::read(&toc_path)
                    .map_err(|e| e.to_string())
                    .and_then(|b| serde_json::from_slice::<Toc>(&b).map_err(|e| e.to_string()))
                {
                    Ok(t) => t,
                    Err(e) => {
                        found.push(problem(
                            ProblemKind::TocMissing,
                            &toc_path,
                            format!("the table of contents kept for the layer {key} cannot be read: {e}"),
                        ));
                        continue;
                    }
                };
                // the one kept is the one of the layer's record (a copy is
                // made of it): one that differs is made again from the record,
                // and the files the record names are the ones checked
                if let Some(Ok(want)) = recorded_toc.map(|t| serde_json::from_str::<Toc>(&t)) {
                    let same = serde_json::to_value(&want).ok().is_some_and(|w| {
                        serde_json::to_value(&toc).ok().is_some_and(|t| t == w)
                    });
                    if !same {
                        found.push(problem(
                            ProblemKind::TocDiffers,
                            &toc_path,
                            format!(
                                "the table of contents kept for the layer {key} is not the one of its record"
                            ),
                        ));
                        toc = want;
                    }
                }
                let missing = checkout::missing_objects(&toc, &store, 5);
                if !missing.is_empty() {
                    found.push(Problem {
                        repair: false,
                        ..problem(
                            ProblemKind::ObjectMissing,
                            &toc_path,
                            format!(
                                "files of the layer {key} are not in the store ({}): pull the image again",
                                missing.join("; ")
                            ),
                        )
                    });
                    continue;
                }
                if full {
                    let src = TocSource {
                        store: &store,
                        verity: fsverity,
                    };
                    if let Err(e) = checkout::verify_objects(&toc, &src) {
                        found.push(Problem {
                            repair: false,
                            ..problem(
                                ProblemKind::ObjectDiffers,
                                &toc_path,
                                format!("a file of the layer {key}: {e}"),
                            )
                        });
                    }
                }
            }
            found
        })
        .await
        .map_err(join_error)
    }

    fn collect(&self, keep: &Keep) -> DriverResult<Collected> {
        // (what this driver holds is the tables of contents of the layers and,
        // for each container, its copy in the bundle: the first is removed
        // with the layers that are not in `keep.layers` (the layers of every
        // image, so of every live container), the second is never touched
        // here, whatever `keep.containers` and `keep.pulls` say, and a pull
        // in progress has nothing of this driver's)
        let known: HashSet<String> = keep.layers.iter().map(LayerKey::file_stem).collect();
        let tocs = self.tocs_dir();
        // (a name starting with a dot is a writer's, taken below if abandoned)
        let mut out = objects::sweep(
            &tocs,
            |name| {
                let name = name.to_string_lossy();
                known.contains(name.strip_suffix(".toc").unwrap_or(&name))
            },
            "table of contents",
            |_, _| {},
        );
        let (freed, errors) = checkout::remove_abandoned(&tocs);
        out.bytes_freed += freed;
        out.errors.extend(errors);
        Ok(out)
    }

    fn usage(&self) -> DriverResult<Usage> {
        Ok(Usage {
            artifacts: objects::files_usage(&self.tocs_dir()),
        })
    }

    // the writable layer: a copy of the layers

    fn writable_create(
        &self,
        w: &Writable,
        owner: Option<(u32, u32)>,
        opts: &WritableOptions,
        base: Option<&MountRequest<'_>>,
    ) -> DriverResult<Option<Planned>> {
        if opts.size_limit.is_some() {
            return Err(unsupported(
                "the vfs driver has no size limit for the writable layer of a container",
            ));
        }
        self.make_copy(w, owner, base)?;
        base.map(|b| self.root_plan(b).map(|r| r.planned()))
            .transpose()
    }

    fn writable_paths(&self, w: &Writable) -> WritablePaths {
        let upper = self
            .copy_dir(w)
            .unwrap_or_else(|_| w.bundle().join(COPY_DIR).join(ROOT));
        WritablePaths {
            upper,
            work: None,
            merged: w.bundle().join("rootfs"),
        }
    }

    /// The copy below the bundle, opened beneath it with no link followed (as
    /// the monitor opens the `Directory` plan).
    fn writable_root(&self, w: &Writable) -> DriverResult<std::os::fd::OwnedFd> {
        let (beneath, path) = self.copy_root(w)?;
        let base = rustix::fs::open(
            &beneath,
            rustix::fs::OFlags::PATH
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .map_err(|e| io_error(e.into()))?;
        velarx_sys::fs::open_beneath(base.as_fd(), &path, velarx_sys::fs::Beneath::Directory)
            .map_err(|e| {
                io_error(std::io::Error::new(
                    std::io::Error::from(e).kind(),
                    format!(
                        "open the root of the writable layer {}: {e}",
                        beneath.join(&path).display()
                    ),
                ))
            })
    }

    fn writable_size(&self, w: &Writable) -> DriverResult<u64> {
        let upper = self.writable_paths(w).upper;
        if !upper.is_dir() {
            return Ok(0);
        }
        // a copy of nothing: all of it is the container's
        let Some((view, uid, gid)) = self.base_of(w)? else {
            return Ok(checkout::tree_size(&upper));
        };
        let fd = objects::open_dir(&upper).map_err(io_error)?;
        let opts = dirtar::Options {
            lower: Some(Arc::new(dirtar::Lower {
                tree: view,
                objects: self.store.clone(),
            })),
            uid_map: uid,
            gid_map: gid,
            unowned: self.unowned(),
            ..Default::default()
        };
        let list = dirtar::copydiff::changes(fd.as_fd(), &opts).map_err(io_error)?;
        Ok(list
            .iter()
            .filter(|(_, c)| *c != Change::Deleted)
            .filter_map(|(p, _)| {
                std::fs::symlink_metadata(upper.join(p.trim_start_matches('/'))).ok()
            })
            .filter(|m| m.is_file())
            .map(|m| m.len())
            .sum())
    }

    fn writable_remove(&self, w: &Writable) -> DriverResult<()> {
        let dir = match self.copy_dir(w) {
            Ok(p) => p.parent().map(Path::to_path_buf),
            Err(_) => Some(w.bundle().join(COPY_DIR)),
        };
        match dir {
            Some(d) => checkout::remove_all(&d).map_err(io_error),
            None => Ok(()),
        }
    }

    fn writable_exists(&self, w: &Writable) -> DriverResult<bool> {
        Ok(self.writable_paths(w).upper.is_dir())
    }

    fn diff(
        &self,
        w: &Writable,
        lower: Option<Arc<dyn ImageTree>>,
        opts: &DiffOptions,
        out: &mut dyn HoleWrite,
    ) -> DriverResult<()> {
        let upper = self.writable_paths(w).upper;
        let fd = objects::open_dir(&upper).map_err(|e| {
            io_error(std::io::Error::new(
                e.kind(),
                format!("open {}: {e}", upper.display()),
            ))
        })?;
        let mut walk = opts.walk(Some(self.lower(lower)?));
        walk.unowned = self.unowned();
        dirtar::copydiff::write(fd.as_fd(), &walk, out).map_err(io_error)
    }

    fn changes(
        &self,
        w: &Writable,
        lower: Option<Arc<dyn ImageTree>>,
        opts: &DiffOptions,
    ) -> DriverResult<Vec<(String, Change)>> {
        let fd = self.writable_root(w)?;
        let mut walk = opts.walk(Some(self.lower(lower)?));
        walk.unowned = self.unowned();
        dirtar::copydiff::changes(fd.as_fd(), &walk).map_err(io_error)
    }

    /// Written into the copy: what a whiteout of the layer names is removed.
    fn apply(
        &self,
        w: &Writable,
        opts: &DiffOptions,
        tar: &mut dyn std::io::Read,
    ) -> DriverResult<()> {
        let fd = self.writable_root(w)?;
        let ex = velarx_wire::cp::ExtractOptions {
            archive_owners: Some(opts.id_maps()),
            owner: Some(opts.root_owner()),
            layer: true,
            whiteouts: velarx_wire::cp::Whiteouts::Remove,
            overwrite_dir_non_dir: true,
            ..Default::default()
        };
        velarx_wire::cp::extract(tar, fd.as_fd(), &ex).map_err(io_error)
    }

    fn stopped_view<'a>(
        &self,
        w: &Writable,
        image: TreeSource<'a>,
    ) -> DriverResult<StoppedView<'a>> {
        let root = rustix::fs::openat(
            rustix::fs::CWD,
            self.writable_paths(w).upper,
            rustix::fs::OFlags::PATH | rustix::fs::OFlags::DIRECTORY | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .map_err(|e| io_error(e.into()))?;
        Ok(StoppedView::directory(root, image))
    }

    /// The root of the process is the directory of the copy: the same inode.
    fn is_root_of(&self, w: &Writable, proc_dir: &Path) -> DriverResult<bool> {
        use std::os::unix::fs::MetadataExt;
        let root = std::fs::metadata(proc_dir.join("root")).map_err(io_error)?;
        let copy = std::fs::metadata(self.writable_paths(w).upper).map_err(io_error)?;
        Ok((root.dev(), root.ino()) == (copy.dev(), copy.ino()))
    }
}

impl VfsDriver {
    /// How the monitor makes the root file system of the container of `req`:
    /// the plan of its copy.  Costs O(layers).
    fn root_plan(&self, req: &MountRequest<'_>) -> DriverResult<Rootfs> {
        let w = req.container;
        if !matches!(req.purpose, Purpose::Root) {
            return Err(unsupported(NOT_A_ROOT));
        }
        if req.image.is_lazy {
            return Err(unsupported(format!(
                "the image {} is being pulled lazily, and the vfs driver copies whole layers",
                req.image.id
            )));
        }
        if req.verity.enforced() {
            return Err(DriverError::of(
                NAME,
                DriverErrorKind::DigestEnforced,
                "the digests of the layers are enforced, and the root file system of a container of the vfs driver is a copy that states none (fs-verity is checked at pull only: set [storage] fsverity_best_effort = true to accept that)",
            ));
        }
        self.check_layers(&req.image.id, req.layers)?;
        let (beneath, path) = self.copy_root(w)?;
        let plan = Directory { beneath, path };
        plan.validate().map_err(|why| {
            DriverError::storage(NAME, format!("the plan of the root file system: {why}"))
        })?;
        #[cfg(test)]
        if self.options.mount_fd {
            if let Some(r) = self.test_mount_fd(w) {
                return Ok(r);
            }
        }
        Ok(Rootfs {
            plan: RootfsPlan::Directory(plan),
            fd: None,
            idmap: if req.mapping.is_some() {
                IdmapDone::Applied
            } else {
                IdmapDone::None
            },
            label: LabelDone::None,
            verity: velarx_graph::VerityDone::None,
            measured: Vec::new(),
            server: None,
        })
    }

    /// The image mount `m` of a container as a mount descriptor: `fd` is the
    /// new detached mount of its copy (none where only the plan is wanted).
    fn volume_rootfs(
        &self,
        m: &MountRequest<'_>,
        fd: Option<std::os::fd::OwnedFd>,
    ) -> DriverResult<Rootfs> {
        Ok(Rootfs {
            plan: RootfsPlan::MountFd(velarx_fuse::plan::MountFd {
                server: false,
                fd_index: 0,
                idmap: false,
            }),
            fd,
            idmap: if m.mapping.is_some() {
                IdmapDone::Applied
            } else {
                IdmapDone::None
            },
            // (at create and at every start: the copy was labelled when it was
            // made, if a label was asked)
            label: if m.label.is_some() {
                LabelDone::Files
            } else {
                LabelDone::None
            },
            verity: velarx_graph::VerityDone::None,
            measured: Vec::new(),
            server: None,
        })
    }
}

impl VfsDriver {
    /// A new detached mount of the copy of `w`, for each call, or none where
    /// the process may not make one.
    #[cfg(test)]
    fn test_mount_fd(&self, w: &Writable) -> Option<Rootfs> {
        use rustix::mount::{open_tree, OpenTreeFlags};
        let root = self.writable_root(w).ok()?;
        let fd = open_tree(
            &root,
            "",
            OpenTreeFlags::OPEN_TREE_CLONE
                | OpenTreeFlags::OPEN_TREE_CLOEXEC
                | OpenTreeFlags::AT_EMPTY_PATH,
        )
        .ok()?;
        Some(Rootfs {
            plan: RootfsPlan::MountFd(velarx_fuse::plan::MountFd {
                server: false,
                fd_index: 0,
                idmap: false,
            }),
            fd: Some(fd),
            idmap: velarx_graph::IdmapDone::None,
            label: LabelDone::None,
            verity: velarx_graph::VerityDone::None,
            measured: Vec::new(),
            server: None,
        })
    }
}

#[cfg(test)]
mod conformance {
    use super::*;
    use velarx_graph::conformance::{conformance_suite, Factory, Subject};

    fn factory() -> Factory {
        factory_with(false)
    }

    fn factory_with(mount_fd: bool) -> Factory {
        Box::new(move |dir| {
            Box::pin(async move {
                let db = Database::open(dir.join("db")).await.unwrap();
                let store = Arc::new(FileStore::new(dir.join("objects")).unwrap());
                let staging = dir.join("staging");
                let driver = Arc::new(
                    VfsDriver::new(DriverParts {
                        db: db.clone(),
                        store: store.clone(),
                        staging_dir: staging.clone(),
                        fsverity: VerityMode::Off,
                    })
                    .with_options(VfsOptions {
                        // (a test run by a user is neither root nor in a user
                        // namespace that maps the owners of the layers)
                        ignore_chown_errors: !rustix::process::geteuid().is_root(),
                        mount_fd,
                        ..Default::default()
                    }),
                );
                let root = driver.root.clone();
                Subject {
                    driver,
                    kernel: None,
                    db,
                    store,
                    staging,
                    dir,
                    overlay_upper: false,
                    damage: Box::new(move |key| {
                        std::fs::remove_file(
                            root.join("tocs").join(format!("{}.toc", key.file_stem())),
                        )
                        .is_ok()
                    }),
                    // (the root of a process is a link in its directory of
                    // /proc: to the directory of the copy, or to another)
                    proc_root: Box::new(|dir, paths| {
                        let link = dir.join("root");
                        let _ = std::fs::remove_file(&link);
                        let to = paths.map_or_else(|| dir.to_path_buf(), |p| p.upper.clone());
                        std::os::unix::fs::symlink(to, link).unwrap();
                    }),
                    image_state: Box::new(|_| false),
                    chunked_only: false,
                    remote: false,
                    upper: None,
                    bundle: None,
                    keep: None,
                }
            })
        })
    }

    conformance_suite!(factory());

    /// The suite of the volume API on the driver wrapped in the test-only
    /// `VolumeFake`, which maps the ids by the monitor (a way the vfs driver
    /// has none of): the engine's handling of an answer that says so.  The
    /// vfs driver's own volumes are the cases of `conformance_suite!` above.
    mod volumes_by_the_monitor {
        use super::*;
        velarx_graph::volume_conformance_suite!(velarx_graph::conformance::with_volumes(
            factory(),
            Prefs::new(&[IdmapWay::MonitorMount, IdmapWay::AtCopy]),
            true
        ));
    }

    /// A volume of the vfs driver is the files of the image owned by the ids of
    /// the mapping, and a mount that cannot be written through.  Needs a
    /// process that may mount (root) for the second part.
    #[tokio::test]
    async fn a_volume_has_the_image_mapped_and_is_read_only() {
        let ran =
            velarx_graph::conformance::a_volume_has_the_image_mapped_and_is_read_only(&factory())
                .await;
        if !ran {
            eprintln!("SKIPPED vfs::read_only_volume: the process may not mount (open_tree)");
            assert!(!rustix::process::geteuid().is_root(), "root can mount");
        }
    }

    /// A `MountFd` plan comes with a descriptor of its own at every call, the
    /// root of a mount, and the descriptor is of the files of the layer: the
    /// writes through `writable_root` are seen in it.  Needs a process that
    /// may mount (root).
    #[tokio::test]
    async fn a_mount_fd_plan_has_a_fresh_descriptor_each_time() {
        let saw = velarx_graph::conformance::rootfs_has_a_descriptor_when_the_plan_names_one(
            &factory_with(true),
        )
        .await;
        if !saw {
            eprintln!("SKIPPED vfs::mount_fd: the process may not mount (open_tree)");
            assert!(!rustix::process::geteuid().is_root(), "root can mount");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use velarx_graph::VerityAsk;
    use velarx_proto::pod::IdMapping;
    use velarx_types::digest::{Algorithm, Digest};

    async fn driver(dir: &Path) -> VfsDriver {
        let db = Database::open(dir.join("db")).await.unwrap();
        let store = Arc::new(FileStore::new(dir.join("objects")).unwrap());
        VfsDriver::new(DriverParts {
            db,
            store,
            staging_dir: dir.join("staging"),
            fsverity: VerityMode::Off,
        })
        .with_options(VfsOptions {
            ignore_chown_errors: true,
            ..Default::default()
        })
    }

    fn key(c: &str) -> LayerKey {
        LayerKey::Whole(
            format!("sha256:{}", c.repeat(32))
                .parse::<Digest>()
                .unwrap(),
        )
    }

    fn record(k: &LayerKey) -> LayerRecord {
        LayerRecord {
            stream_size: Some(0),
            key: *k,
            blob: None,
            diff_id: None,
            other_diff_id: None,
            size: 0,
            toc: None,
            status: "ready".into(),
            created_at: String::new(),
            registry_ref: None,
            erofs: Some("e".into()),
            owners: None,
        }
    }

    fn image() -> ImageRecord {
        ImageRecord {
            id: "img".into(),
            manifest_digest: Digest::of(Algorithm::Sha256, b"{}"),
            config_digest: Digest::of(Algorithm::Sha256, b"{}"),
            manifest: "{}".into(),
            config: "{}".into(),
            created_at: String::new(),
            is_lazy: false,
        }
    }

    /// A layer the store has: its table of contents kept, its objects there.
    fn layer(d: &VfsDriver, k: &LayerKey, files: &[(&str, &str)]) {
        use velarx_storage::{TocEntry, TocEntryType};
        let (uid, gid) = me();
        let own = |mut e: TocEntry| {
            (e.uid, e.gid) = (uid, gid);
            e
        };
        let mut entries = vec![own(velarx_fuse::dir_entry(""))];
        let mut dirs = std::collections::BTreeSet::new();
        for (name, data) in files {
            let mut p = String::new();
            for c in name.split('/').take(name.split('/').count() - 1) {
                if !p.is_empty() {
                    p.push('/');
                }
                p.push_str(c);
                if dirs.insert(p.clone()) {
                    entries.push(own(velarx_fuse::dir_entry(&p)));
                }
            }
            let mut e: TocEntry = velarx_fuse::dir_entry(name);
            if let Some(w) = name.rsplit('/').next().filter(|n| n.starts_with(".wh.")) {
                let _ = w;
            }
            e.entry_type = TocEntryType::Reg;
            e.mode = 0o644;
            e.size = data.len() as u64;
            let (uid, gid) = me();
            (e.uid, e.gid) = (uid, gid);
            e.mod_time = Some("2017-07-14T02:40:00+00:00".into());
            if !data.is_empty() {
                let id = d.store.put(Algorithm::Sha256, data.as_bytes()).unwrap();
                e.fsverity = velarx_storage::to_toc(&id);
            }
            entries.push(e);
        }
        let toc = Toc {
            version: 1,
            entries,
            tar_split_digest: None,
        };
        keep_tocs(&d.store, d.fsverity, &d.root, &[(*k, toc)]).unwrap();
    }

    fn me() -> (u32, u32) {
        (
            rustix::process::geteuid().as_raw(),
            rustix::process::getegid().as_raw(),
        )
    }

    fn mapping(squash: bool) -> velarx_fuse::IdTranslate {
        let (u, g) = me();
        let m = |c| {
            vec![IdMapping {
                container_id: c,
                host_id: c,
                size: 1,
            }]
        };
        velarx_fuse::IdTranslate {
            uid: m(u),
            gid: m(g),
            squash,
        }
    }

    fn request<'a>(
        img: &'a ImageRecord,
        layers: &'a [LayerRecord],
        mapping: Option<&'a velarx_fuse::IdTranslate>,
        w: &'a Writable,
    ) -> MountRequest<'a> {
        MountRequest {
            translate: None,
            container: w,
            purpose: Purpose::Root,
            image: img,
            layers,
            mapping,
            idmap_mount: false,
            label: None,
            verity: VerityAsk::Off,
            volatile: false,
        }
    }

    #[tokio::test]
    async fn the_copy_is_made_at_create_from_the_merged_layers_and_nothing_is_kept_per_mapping() {
        let t = tempfile::tempdir().unwrap();
        let d = driver(t.path()).await;
        let (k1, k2) = (key("aa"), key("bb"));
        layer(&d, &k1, &[("etc/a", "1"), ("etc/gone", "x")]);
        layer(&d, &k2, &[("etc/.wh.gone", ""), ("etc/b", "2")]);
        // the layers are tables of contents, no directory
        assert!(d.layer_toc(&k1).is_file() && d.layer_toc(&k2).is_file());
        assert_eq!(
            std::fs::read_dir(d.root.join("tocs")).unwrap().count(),
            2,
            "a table for each layer, nothing else"
        );
        let (img, layers) = (image(), vec![record(&k1), record(&k2)]);
        assert_eq!(d.copied(), (0, 0, 0), "nothing is copied at pull");
        let m = mapping(false);
        let (w1, w2) = (
            Writable::new("c1", t.path().join("bundles/c1")),
            Writable::new("c2", t.path().join("bundles/c2")),
        );
        for w in [&w1, &w2] {
            d.writable_create(
                w,
                None,
                &WritableOptions::default(),
                Some(&request(&img, &layers, Some(&m), w)),
            )
            .unwrap();
        }
        let root = d.writable_paths(&w1).upper;
        assert!(root.join("etc/a").is_file() && root.join("etc/b").is_file());
        assert!(!root.join("etc/gone").exists() && !root.join("etc/.wh.gone").exists());
        // each container is copied from the objects (the whited-out file
        // is not written at all), and the store has nothing for the mapping
        let n = |c: (u64, u64, u64)| c.0 + c.1 + c.2;
        assert_eq!(n(d.copied()), 4, "{:?}", d.copied());
        assert!(!d.root.join("mapped").exists() && !d.root.join("layers").exists());
        assert_eq!(std::fs::read_dir(d.root.join("tocs")).unwrap().count(), 2);
        // the tables go with their layer at a collection
        let out = d
            .collect(&Keep {
                layers: vec![k1],
                images: vec![],
                ..Keep::default()
            })
            .unwrap();
        assert!(out.errors.is_empty(), "{:?}", out.errors);
        assert!(d.layer_toc(&k1).is_file() && !d.layer_toc(&k2).exists());
        let out = d.collect(&Keep::default()).unwrap();
        assert!(out.errors.is_empty());
        assert!(!d.layer_toc(&k1).exists());
        // and the copy of a container is its own: a layer that is gone does
        // not take it
        assert!(root.join("etc/a").is_file());
    }

    // the images mounted in a container: a copy for each mount

    fn volume<'a>(
        img: &'a ImageRecord,
        layers: &'a [LayerRecord],
        mapping: Option<&'a velarx_fuse::IdTranslate>,
        index: u32,
    ) -> MountRequest<'a> {
        MountRequest {
            translate: None,
            container: volume_owner(),
            purpose: Purpose::Volume { index },
            image: img,
            layers,
            mapping,
            idmap_mount: false,
            label: None,
            verity: VerityAsk::Off,
            volatile: false,
        }
    }

    /// The container the volumes of the cases are of until a case names one
    /// ([`make`], [`mounts_of`]).
    fn volume_owner() -> &'static Writable {
        static W: std::sync::OnceLock<Writable> = std::sync::OnceLock::new();
        W.get_or_init(|| Writable::new("unnamed", "/velarx-vfs-tests/unnamed"))
    }

    fn make(d: &VfsDriver, w: &Writable, m: MountRequest<'_>) -> DriverResult<Planned> {
        d.image_volume_create(&MountRequest { container: w, ..m })
    }

    fn mounts_of(
        d: &VfsDriver,
        w: &Writable,
        volumes: Vec<MountRequest<'_>>,
    ) -> DriverResult<Mounts> {
        d.mounts(&MountsRequest {
            root: None,
            volumes: volumes
                .into_iter()
                .map(|v| MountRequest { container: w, ..v })
                .collect(),
        })
    }

    /// The bytes of the regular files below `dir`, as the engine adds up the
    /// size of a bundle.
    fn bundle_size(dir: &Path) -> u64 {
        checkout::tree_size(dir)
    }

    /// A volume asked with a label is a copy whose every entry, its top
    /// directory too, carries it (the image's own label replaced), and the
    /// answer says so at create and at a start; with none asked, none.
    #[tokio::test]
    async fn a_volume_asked_with_a_label_is_a_copy_labelled_as_it_is_made() {
        const LABEL: &str = "system_u:object_r:container_file_t:s0:c1,c2";
        let t = tempfile::tempdir().unwrap();
        let d = driver(t.path()).await;
        let k = key("aa");
        layer(&d, &k, &[("etc/a", "1"), ("etc/sub/b", "2")]);
        let (img, layers) = (image(), vec![record(&k)]);
        let w = Writable::new("c1", t.path().join("bundles/c1"));
        let ask = || MountRequest {
            label: Some(LABEL),
            ..volume(&img, &layers, None, 0)
        };
        let planned = match make(&d, &w, ask()) {
            Ok(p) => p,
            // (a host that does not let this user put that label on a file)
            Err(e) if matches!(e.kind, DriverErrorKind::LabelRefused) => return,
            Err(e) => panic!("{e}"),
        };
        assert_eq!(planned.label, LabelDone::Files);
        let plain = make(&d, &w, volume(&img, &layers, None, 1)).unwrap();
        assert_eq!(plain.label, LabelDone::None);
        let m = mounts_of(&d, &w, vec![ask(), volume(&img, &layers, None, 1)]).unwrap();
        assert_eq!(m.volumes[0].label, LabelDone::Files);
        assert_eq!(m.volumes[1].label, LabelDone::None);
        let copy = w.bundle().join("vfs/imagevol/0");
        for path in ["", "etc", "etc/a", "etc/sub", "etc/sub/b"] {
            let mut v = [0u8; 256];
            match rustix::fs::lgetxattr(copy.join(path), "security.selinux", &mut v) {
                Ok(n) => assert_eq!(
                    String::from_utf8_lossy(&v[..n]).trim_end_matches('\0'),
                    LABEL,
                    "{path:?}"
                ),
                // (a file system with no SELinux attributes)
                Err(rustix::io::Errno::OPNOTSUPP) => return,
                Err(e) => panic!("{path:?}: {e}"),
            }
        }
    }

    /// A label the host refuses (here one that is no label at all) is the
    /// error `LabelRefused`, told from the others by its kind, not by its
    /// words.  (Needs SELinux, and a user without CAP_MAC_ADMIN, which may
    /// put any context on a file.)
    #[tokio::test]
    async fn a_label_the_host_refuses_is_label_refused() {
        if !Path::new("/sys/fs/selinux/enforce").exists() || rustix::process::geteuid().is_root() {
            eprintln!("no SELinux, or root: skipped");
            return;
        }
        let t = tempfile::tempdir().unwrap();
        let d = driver(t.path()).await;
        let k = key("ab");
        layer(&d, &k, &[("etc/a", "1")]);
        let (img, layers) = (image(), vec![record(&k)]);
        let w = Writable::new("c1", t.path().join("bundles/c1"));
        let ask = MountRequest {
            label: Some("velarx-is-not-a-label"),
            ..volume(&img, &layers, None, 0)
        };
        let Err(e) = make(&d, &w, ask) else {
            panic!("a label that is none was put on the files")
        };
        assert!(matches!(e.kind, DriverErrorKind::LabelRefused), "{e:?}");
    }

    #[tokio::test]
    async fn a_volume_is_a_copy_of_the_merged_layers_in_the_bundle_made_once() {
        let t = tempfile::tempdir().unwrap();
        let d = driver(t.path()).await;
        let (k1, k2) = (key("aa"), key("bb"));
        layer(&d, &k1, &[("etc/a", "1"), ("etc/gone", "x")]);
        layer(&d, &k2, &[("etc/.wh.gone", ""), ("etc/b", "22")]);
        let (img, layers) = (image(), vec![record(&k1), record(&k2)]);
        let m = mapping(false);
        let w = Writable::new("c1", t.path().join("bundles/c1"));
        make(&d, &w, volume(&img, &layers, Some(&m), 0)).unwrap();
        let copy = w.bundle().join("vfs/imagevol/0");
        assert_eq!(std::fs::read_to_string(copy.join("etc/a")).unwrap(), "1");
        assert_eq!(std::fs::read_to_string(copy.join("etc/b")).unwrap(), "22");
        assert!(!copy.join("etc/gone").exists() && !copy.join("etc/.wh.gone").exists());
        // (only the engine reaches the copies)
        let mode = |p: &Path| std::os::unix::fs::MetadataExt::mode(&std::fs::metadata(p).unwrap());
        assert_eq!(mode(&w.bundle().join("vfs/imagevol")) & 0o777, 0o700);
        // nothing is left next to it
        let names: Vec<_> = std::fs::read_dir(w.bundle().join("vfs/imagevol"))
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, ["0"]);
        // made again without harm: the same copy, nothing copied again
        let (before, ino) = (
            d.copied(),
            std::os::unix::fs::MetadataExt::ino(&std::fs::metadata(&copy).unwrap()),
        );
        make(&d, &w, volume(&img, &layers, Some(&m), 0)).unwrap();
        assert_eq!(d.copied(), before);
        assert_eq!(
            std::os::unix::fs::MetadataExt::ino(&std::fs::metadata(&copy).unwrap()),
            ino
        );
        // the mount: a descriptor of its own at every call, and the copy's
        // files through it; the ids were mapped as the copy was made
        let a = mounts_of(&d, &w, vec![volume(&img, &layers, Some(&m), 0)]).unwrap();
        let b = mounts_of(&d, &w, vec![volume(&img, &layers, Some(&m), 0)]).unwrap();
        assert!(a.root.is_none());
        for r in [&a.volumes[0], &b.volumes[0]] {
            assert!(matches!(r.plan, RootfsPlan::MountFd(_)), "{r:?}");
            assert_eq!(r.idmap, IdmapDone::Applied);
            let f = rustix::fs::openat(
                r.fd.as_ref().unwrap(),
                "etc/b",
                rustix::fs::OFlags::RDONLY,
                rustix::fs::Mode::empty(),
            )
            .unwrap();
            assert_eq!(
                std::io::read_to_string(std::fs::File::from(f)).unwrap(),
                "22"
            );
        }
        use std::os::fd::AsRawFd;
        assert_ne!(
            a.volumes[0].fd.as_ref().unwrap().as_raw_fd(),
            b.volumes[0].fd.as_ref().unwrap().as_raw_fd()
        );
        // no mapping, nothing mapped
        let n = mounts_of(&d, &w, vec![volume(&img, &layers, None, 0)]).unwrap();
        assert_eq!(n.volumes[0].idmap, IdmapDone::None);
        // two mounts, each its own copy, of another image
        let k3 = key("cc");
        layer(&d, &k3, &[("other", "o")]);
        let (img2, layers2) = (image(), vec![record(&k3)]);
        make(&d, &w, volume(&img2, &layers2, Some(&m), 1)).unwrap();
        assert!(w.bundle().join("vfs/imagevol/1/other").is_file());
        assert!(!w.bundle().join("vfs/imagevol/1/etc").exists());
        assert!(copy.join("etc/a").is_file(), "the first stays as it was");
        // the container's removal removes them
        d.writable_remove(&w).unwrap();
        assert!(!w.bundle().join("vfs").exists());
        // (and the mount of one that is gone says to make the container again)
        let e = mounts_of(&d, &w, vec![volume(&img, &layers, Some(&m), 0)]).unwrap_err();
        assert!(
            matches!(e.kind, DriverErrorKind::Missing { remedy } if remedy == Remedy::RecreateContainer),
            "{e:?}"
        );
    }

    #[tokio::test]
    async fn a_half_made_copy_of_a_crash_is_removed_and_made_again() {
        let t = tempfile::tempdir().unwrap();
        let d = driver(t.path()).await;
        let k = key("aa");
        layer(&d, &k, &[("f", "x")]);
        let (img, layers) = (image(), vec![record(&k)]);
        let w = Writable::new("c1", t.path().join("bundles/c1"));
        // what a process that died while it copied leaves: its directory,
        // with half a tree in it, and the lock nobody holds
        let parent = w.bundle().join("vfs/imagevol");
        std::fs::create_dir_all(parent.join(".tmp-1-2-3/half")).unwrap();
        std::fs::write(parent.join(".tmp-1-2-3/half/part"), b"x").unwrap();
        std::fs::write(parent.join(".tmp-1-2-3.lock"), b"").unwrap();
        make(&d, &w, volume(&img, &layers, None, 0)).unwrap();
        let mut names: Vec<_> = std::fs::read_dir(&parent)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        assert_eq!(names, ["0"], "the leftovers are gone, the copy is whole");
        assert_eq!(std::fs::read_to_string(parent.join("0/f")).unwrap(), "x");
        assert!(!parent.join("0/half").exists());
    }

    #[tokio::test]
    async fn a_copy_that_cannot_be_made_leaves_nothing_and_says_what_to_do() {
        let t = tempfile::tempdir().unwrap();
        let d = driver(t.path()).await;
        let k = key("aa");
        layer(&d, &k, &[("f", "x")]);
        let (img, layers) = (image(), vec![record(&k)]);
        let w = Writable::new("c1", t.path().join("bundles/c1"));
        let left = || -> Vec<String> {
            std::fs::read_dir(w.bundle().join("vfs/imagevol"))
                .map(|r| {
                    r.map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
                        .collect()
                })
                .unwrap_or_default()
        };
        // a layer the store lacks: pull the image again
        let lost = vec![record(&key("dd"))];
        let e = make(&d, &w, volume(&img, &lost, None, 0)).unwrap_err();
        assert!(
            matches!(e.kind, DriverErrorKind::Missing { remedy } if remedy == Remedy::PullAgain),
            "{e:?}"
        );
        assert!(
            e.to_string().ends_with(Remedy::PullAgain.text(false)),
            "{e}"
        );
        assert!(left().is_empty());
        // an object the store lacks: the same
        let objects: Vec<_> = walk(&t.path().join("objects"));
        assert!(!objects.is_empty());
        for o in &objects {
            std::fs::remove_file(o).unwrap();
        }
        let e = make(&d, &w, volume(&img, &layers, None, 0)).unwrap_err();
        assert!(
            matches!(e.kind, DriverErrorKind::Missing { remedy } if remedy == Remedy::PullAgain),
            "{e:?}"
        );
        assert!(left().is_empty(), "{:?}", left());
        // an owner outside the mapping is refused, as composefs does
        let (u, g) = me();
        let narrow = velarx_fuse::IdTranslate {
            uid: vec![IdMapping {
                container_id: u + 1,
                host_id: 1,
                size: 1,
            }],
            gid: vec![IdMapping {
                container_id: g + 1,
                host_id: 1,
                size: 1,
            }],
            squash: false,
        };
        let k2 = key("ee");
        layer(&d, &k2, &[("g", "y")]);
        let layers2 = vec![record(&k2)];
        let e = make(&d, &w, volume(&img, &layers2, Some(&narrow), 0)).unwrap_err();
        assert!(e.message().contains("not mapped"), "{e}");
        assert!(left().is_empty());
        assert!(!w.bundle().join("vfs/imagevol/0").exists());
        // `squash` gives them the root of the container instead (here the
        // owner of the image's files is not in the mapping unless it is root,
        // and the root of the container is this process's ids)
        let to_me = |id: u32| {
            vec![IdMapping {
                container_id: 0,
                host_id: id,
                size: 1,
            }]
        };
        let squash = velarx_fuse::IdTranslate {
            uid: to_me(u),
            gid: to_me(g),
            squash: true,
        };
        make(&d, &w, volume(&img, &layers2, Some(&squash), 0)).unwrap();
        let st = std::fs::symlink_metadata(w.bundle().join("vfs/imagevol/0/g")).unwrap();
        assert_eq!(
            (
                std::os::unix::fs::MetadataExt::uid(&st),
                std::os::unix::fs::MetadataExt::gid(&st)
            ),
            (u, g),
            "squashed to the root of the container"
        );
        d.writable_remove(&w).unwrap();
        // the digests enforced, a lazy image, a root asked as a volume
        let mut enforce = volume(&img, &layers2, None, 1);
        enforce.verity = VerityAsk::Enforce {
            accepted: &[],
            chain: None,
        };
        let e = make(&d, &w, enforce).unwrap_err();
        assert!(matches!(e.kind, DriverErrorKind::DigestEnforced), "{e:?}");
        let lazy = ImageRecord {
            is_lazy: true,
            ..image()
        };
        let e = make(&d, &w, volume(&lazy, &layers2, None, 1)).unwrap_err();
        assert!(matches!(e.kind, DriverErrorKind::Unsupported), "{e:?}");
        let mut root = volume(&img, &layers2, None, 1);
        root.purpose = Purpose::Root;
        assert!(make(&d, &w, root).is_err());
        assert!(!w.bundle().join("vfs/imagevol/1").exists());
    }

    fn walk(dir: &Path) -> Vec<PathBuf> {
        let mut out = Vec::new();
        for e in std::fs::read_dir(dir).unwrap().flatten() {
            let p = e.path();
            if e.file_type().unwrap().is_dir() {
                out.extend(walk(&p));
            } else {
                out.push(p);
            }
        }
        out
    }

    #[tokio::test]
    async fn the_size_of_a_container_counts_its_volumes_once_and_not_in_its_root_copy() {
        let t = tempfile::tempdir().unwrap();
        let d = driver(t.path()).await;
        let k = key("aa");
        layer(&d, &k, &[("etc/os", "base"), ("big", &"b".repeat(100_000))]);
        let (img, layers) = (image(), vec![record(&k)]);
        let w = Writable::new("c1", t.path().join("bundles/c1"));
        d.writable_create(
            &w,
            None,
            &WritableOptions::default(),
            Some(&request(&img, &layers, None, &w)),
        )
        .unwrap();
        std::fs::write(d.writable_paths(&w).upper.join("mine"), vec![1u8; 777]).unwrap();
        let (own, whole) = (d.writable_size(&w).unwrap(), bundle_size(w.bundle()));
        assert_eq!(own, 777, "what the container wrote");
        make(&d, &w, volume(&img, &layers, None, 0)).unwrap();
        make(&d, &w, volume(&img, &layers, None, 1)).unwrap();
        // what the container wrote is what it wrote: the copies of the images
        // are not in the size of its layer ...
        assert_eq!(d.writable_size(&w).unwrap(), own);
        // ... but they are in the bundle, which is what `df` and the size of a
        // container count, once each
        assert_eq!(bundle_size(w.bundle()), whole + 2 * 100_004);
        d.writable_remove(&w).unwrap();
        assert_eq!(bundle_size(w.bundle()), 0);
    }

    #[tokio::test]
    async fn an_image_cannot_make_the_copy_follow_a_link_or_keep_a_device() {
        use velarx_storage::TocEntryType;
        let t = tempfile::tempdir().unwrap();
        let d = driver(t.path()).await;
        let outside = t.path().join("outside");
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(outside.join("secret"), b"s").unwrap();
        // links to the host, a name made through a link, a device node and a
        // setuid file
        let k = key("aa");
        layer(&d, &k, &[("etc/ok", "1"), ("suid", "x")]);
        let (uid, gid) = me();
        let mut toc: Toc =
            serde_json::from_slice(&std::fs::read(d.layer_toc(&k)).unwrap()).unwrap();
        let mut link = |name: &str, to: &str| {
            let mut e = velarx_fuse::dir_entry(name);
            e.entry_type = TocEntryType::Symlink;
            e.link_name = Some(to.into());
            (e.uid, e.gid) = (uid, gid);
            e.mode = 0o777;
            toc.entries.push(e);
        };
        link("etc/abs", outside.to_str().unwrap());
        link("etc/up", "../../../../../../../../../../tmp");
        link("etc/loop", ".");
        let mut dev = velarx_fuse::dir_entry("etc/null");
        dev.entry_type = TocEntryType::Char;
        (dev.dev_major, dev.dev_minor) = (Some(1), Some(3));
        (dev.uid, dev.gid) = (uid, gid);
        dev.mode = 0o666;
        toc.entries.push(dev);
        for e in &mut toc.entries {
            if e.name == "suid" {
                e.mode = 0o4755;
            }
        }
        keep_tocs(&d.store, d.fsverity, &d.root, &[(k, toc)]).unwrap();
        let (img, layers) = (image(), vec![record(&k)]);
        let w = Writable::new("c1", t.path().join("bundles/c1"));
        // a planted link where the copy goes: a bundle is the engine's, but
        // the copy still replaces a link rather than follow it
        let parent = w.bundle().join("vfs/imagevol");
        std::fs::create_dir_all(&parent).unwrap();
        std::os::unix::fs::symlink(&outside, parent.join("0")).unwrap();
        make(&d, &w, volume(&img, &layers, None, 0)).unwrap();
        let copy = parent.join("0");
        let md = std::fs::symlink_metadata(&copy).unwrap();
        assert!(md.is_dir() && !md.file_type().is_symlink());
        assert_eq!(
            std::fs::read_link(copy.join("etc/abs")).unwrap(),
            outside,
            "a link is a link"
        );
        assert!(std::fs::symlink_metadata(copy.join("etc/loop"))
            .unwrap()
            .file_type()
            .is_symlink());
        assert_eq!(
            std::fs::read_dir(&outside).unwrap().count(),
            1,
            "nothing was made outside"
        );
        assert_eq!(std::fs::read(outside.join("secret")).unwrap(), b"s");
        // a device is made by root only (and is no use in a nodev mount)
        let null = std::fs::symlink_metadata(copy.join("etc/null"));
        if rustix::process::geteuid().is_root() {
            assert!(std::os::unix::fs::FileTypeExt::is_char_device(
                &null.unwrap().file_type()
            ));
        } else {
            assert!(null.is_err(), "no device for a user");
        }
        // the setuid bit is the image's: the mount is nodev, not nosuid, and
        // the bundle is the engine's alone
        assert_eq!(
            std::os::unix::fs::MetadataExt::mode(&std::fs::metadata(copy.join("suid")).unwrap())
                & 0o7777,
            0o4755
        );
        // a link where the volumes are: the mount is not led through it
        d.writable_remove(&w).unwrap();
        std::fs::create_dir_all(w.bundle().join("vfs")).unwrap();
        std::fs::create_dir_all(outside.join("0")).unwrap();
        std::os::unix::fs::symlink(&outside, w.bundle().join("vfs/imagevol")).unwrap();
        assert!(mounts_of(&d, &w, vec![volume(&img, &layers, None, 0)]).is_err());
        // nor is the copy: refused, nothing made or changed where it leads
        let mode = |p: &Path| std::os::unix::fs::MetadataExt::mode(&std::fs::metadata(p).unwrap());
        let before = mode(&outside);
        assert!(make(&d, &w, volume(&img, &layers, None, 1)).is_err());
        assert!(!outside.join("1").exists());
        assert_eq!(mode(&outside), before, "the mode of where the link leads");
        assert_eq!(std::fs::read_dir(&outside).unwrap().count(), 2);
    }

    #[tokio::test]
    async fn a_copy_that_fails_leaves_nothing_and_a_copy_is_not_made_at_pull() {
        let t = tempfile::tempdir().unwrap();
        let d = driver(t.path()).await;
        let k = key("cc");
        layer(&d, &k, &[("f", "x")]);
        let (img, layers) = (image(), vec![record(&k)]);
        // an owner that is not an id of the mapping
        let (u, g) = me();
        let narrow = velarx_fuse::IdTranslate {
            uid: vec![IdMapping {
                container_id: u + 1,
                host_id: 1,
                size: 1,
            }],
            gid: vec![IdMapping {
                container_id: g + 1,
                host_id: 1,
                size: 1,
            }],
            squash: false,
        };
        let w = Writable::new("c", t.path().join("bundles/c"));
        let e = d
            .writable_create(
                &w,
                None,
                &WritableOptions::default(),
                Some(&request(&img, &layers, Some(&narrow), &w)),
            )
            .unwrap_err();
        assert!(e.message().contains("not mapped"), "{e}");
        assert!(!d.writable_exists(&w).unwrap());
        assert!(std::fs::read_dir(w.bundle().join("vfs")).map_or(true, |r| r.count() == 0));
        // (nothing was made for the container before it was asked for)
        assert!(!w.bundle().join("vfs/root").exists());
        // a layer the store lacks is an error that says what to do
        let lost = vec![record(&key("dd"))];
        let e = d
            .writable_create(
                &w,
                None,
                &WritableOptions::default(),
                Some(&request(&img, &lost, None, &w)),
            )
            .unwrap_err();
        assert!(matches!(e.kind, DriverErrorKind::Missing { .. }), "{e:?}");
        assert!(e.remedy().is_some());
        assert!(!d.writable_exists(&w).unwrap());
    }

    #[tokio::test]
    async fn the_copy_goes_by_the_fault_a_test_injects_and_is_the_same() {
        let t = tempfile::tempdir().unwrap();
        let mut copies = Vec::new();
        for (name, fault) in [
            ("free", None),
            (
                "ranged",
                Some(Arc::new(|m| {
                    (m == checkout::Method::Reflink).then_some(rustix::io::Errno::OPNOTSUPP)
                }) as Fault),
            ),
            (
                "plain",
                Some(Arc::new(|m| match m {
                    checkout::Method::Reflink => Some(rustix::io::Errno::XDEV),
                    checkout::Method::Range => Some(rustix::io::Errno::NOSYS),
                    checkout::Method::Plain => None,
                }) as Fault),
            ),
        ] {
            let dir = t.path().join(name);
            std::fs::create_dir_all(&dir).unwrap();
            let d = match &fault {
                Some(f) => driver(&dir).await.with_fault(f.clone()),
                None => driver(&dir).await,
            };
            let k = key("ee");
            layer(&d, &k, &[("a", "alpha"), ("d/b", &"beta".repeat(10_000))]);
            let (img, layers) = (image(), vec![record(&k)]);
            let w = Writable::new("c", dir.join("bundles/c"));
            d.writable_create(
                &w,
                None,
                &WritableOptions::default(),
                Some(&request(&img, &layers, None, &w)),
            )
            .unwrap();
            let up = d.writable_paths(&w).upper;
            assert_eq!(std::fs::read(up.join("d/b")).unwrap().len(), 40_000);
            let (re, ra, pl) = d.copied();
            match name {
                "ranged" => assert!(ra >= 1 && re == 0 && pl == 0, "{re} {ra} {pl}"),
                "plain" => assert!(pl >= 1 && re == 0 && ra == 0, "{re} {ra} {pl}"),
                _ => assert!(re + ra + pl >= 1),
            }
            copies.push(std::fs::read(up.join("a")).unwrap());
        }
        assert!(copies.iter().all(|c| c == b"alpha"));
    }

    /// An image as deep as a pull takes (512 levels: `MAX_PATH_DEPTH`) is
    /// copied, and its container's changes are found, on a thread whose
    /// stack is the one of the blocking pool (2 MiB): the walks recurse once
    /// for each level, and an overflow aborts the engine.
    #[tokio::test]
    async fn a_deep_image_is_copied_and_compared_on_a_small_stack() {
        let t = tempfile::tempdir().unwrap();
        let d = Arc::new(driver(t.path()).await);
        let k = key("ab");
        let deep = format!("{}f", "d/".repeat(600));
        layer(&d, &k, &[(deep.as_str(), "bottom")]);
        let (img, layers) = (image(), vec![record(&k)]);
        let w = Writable::new("c", t.path().join("bundles/c"));
        let (d2, w2) = (d.clone(), w.clone());
        let (n, changed) = std::thread::Builder::new()
            .stack_size(2 << 20)
            .spawn(move || {
                d2.writable_create(
                    &w2,
                    None,
                    &WritableOptions::default(),
                    Some(&request(&img, &layers, None, &w2)),
                )
                .unwrap();
                let up = d2.writable_paths(&w2).upper;
                let leaf = format!("{}g", "d/".repeat(600));
                std::fs::write(up.join(&leaf), b"new").unwrap();
                let lower = d2.image_view("img", &layers).unwrap();
                let opts = DiffOptions::default();
                let mut tar = Vec::new();
                d2.diff(&w2, Some(lower.clone()), &opts, &mut tar).unwrap();
                let list = d2.changes(&w2, Some(lower), &opts).unwrap();
                (tar.len(), list)
            })
            .unwrap()
            .join()
            .expect("no overflow");
        assert!(n > 0);
        let added = changed.iter().filter(|(_, c)| *c == Change::Added).count();
        assert_eq!(
            added,
            1,
            "{:?}",
            changed.iter().rev().take(3).collect::<Vec<_>>()
        );
        assert_eq!(
            std::fs::read(d.writable_paths(&w).upper.join(&deep)).unwrap(),
            b"bottom"
        );
    }

    /// What the copy of a container records of its image is read for its
    /// size: a record that is no record, or a table of contents of it that is
    /// gone, is an error, not a copy of nothing whose whole tree counts.
    #[tokio::test]
    async fn the_size_of_a_copy_with_a_broken_record_is_an_error() {
        let t = tempfile::tempdir().unwrap();
        let d = driver(t.path()).await;
        let k = key("ae");
        layer(&d, &k, &[("etc/a", "a")]);
        let (img, layers) = (image(), vec![record(&k)]);
        let w = Writable::new("c", t.path().join("bundles/c"));
        d.writable_create(
            &w,
            None,
            &WritableOptions::default(),
            Some(&request(&img, &layers, None, &w)),
        )
        .unwrap();
        std::fs::write(d.writable_paths(&w).upper.join("mine"), b"123").unwrap();
        assert_eq!(d.writable_size(&w).unwrap(), 3);
        let record = d.copy_dir(&w).unwrap().parent().unwrap().join(BASE_FILE);
        let good = std::fs::read(&record).unwrap();
        std::fs::write(&record, b"{not json").unwrap();
        let e = d.writable_size(&w).unwrap_err();
        assert!(e.to_string().contains(BASE_FILE), "{e}");
        std::fs::write(&record, &good).unwrap();
        assert_eq!(d.writable_size(&w).unwrap(), 3);
        let toc = d.layer_toc(&k);
        std::fs::remove_file(&toc).unwrap();
        let e = d.writable_size(&w).unwrap_err();
        assert!(e.to_string().contains(".toc"), "{e}");
        std::fs::remove_file(&record).unwrap();
        assert!(
            d.writable_size(&w).unwrap() >= 3,
            "no record: a copy of nothing"
        );
    }

    /// The size of the layer of a container is what the container wrote: the
    /// files it added or changed, not the copy of its image.
    #[tokio::test]
    async fn the_size_of_a_copy_is_what_the_container_wrote() {
        let t = tempfile::tempdir().unwrap();
        let d = driver(t.path()).await;
        let k = key("ad");
        layer(&d, &k, &[("etc/a", &"a".repeat(5000)), ("etc/b", "bb")]);
        let (img, layers) = (image(), vec![record(&k)]);
        let w = Writable::new("c", t.path().join("bundles/c"));
        d.writable_create(
            &w,
            None,
            &WritableOptions::default(),
            Some(&request(&img, &layers, None, &w)),
        )
        .unwrap();
        assert_eq!(d.writable_size(&w).unwrap(), 0, "nothing written yet");
        let up = d.writable_paths(&w).upper;
        std::fs::write(up.join("etc/new"), b"123").unwrap();
        std::fs::remove_file(up.join("etc/b")).unwrap();
        assert_eq!(d.writable_size(&w).unwrap(), 3);
    }

    /// The table of contents a copy is made of is the one of the layer's
    /// record: `check` finds one that differs, and the repair makes it again.
    #[tokio::test]
    async fn check_finds_a_kept_table_that_is_not_the_records() {
        let t = tempfile::tempdir().unwrap();
        let d = driver(t.path()).await;
        let k = key("ac");
        layer(&d, &k, &[("etc/a", "1")]);
        let kept = std::fs::read_to_string(d.layer_toc(&k)).unwrap();
        let mut rec = record(&k);
        rec.toc = Some(kept.clone());
        let none = d
            .check(&image(), std::slice::from_ref(&rec), false)
            .await
            .unwrap();
        assert!(none.is_empty(), "{none:?}");
        // a file of setuid root added to the kept one
        let mut toc: Toc = serde_json::from_str(&kept).unwrap();
        let mut evil = toc.entries.last().unwrap().clone();
        evil.name = "etc/suid".into();
        evil.mode = 0o4755;
        toc.entries.push(evil);
        std::fs::write(d.layer_toc(&k), serde_json::to_vec(&toc).unwrap()).unwrap();
        let found = d
            .check(&image(), std::slice::from_ref(&rec), false)
            .await
            .unwrap();
        assert!(
            found
                .iter()
                .any(|p| p.kind == ProblemKind::TocDiffers && p.repair),
            "{found:?}"
        );
        // the repair: the record's table, made again
        let want: Toc = serde_json::from_str(&kept).unwrap();
        keep_tocs(&d.store, d.fsverity, &d.root, &[(k, want)]).unwrap();
        let again = d
            .check(&image(), std::slice::from_ref(&rec), false)
            .await
            .unwrap();
        assert!(again.is_empty(), "{again:?}");
    }
}
