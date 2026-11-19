// SPDX-License-Identifier: Apache-2.0
//! The `composefs` storage driver: the one there is, and the default.
//!
//! It holds the EROFS images of the layers of the store (`fuse::layer_erofs`):
//! made from the table of contents of each layer when it is pulled (a lazy
//! layer too: the image needs no content, only the digests of the files),
//! written next to the objects of the store with fs-verity where the file
//! system has it, and recorded with the layer (its fs-verity digest and the
//! owners of its files).  They are the store's, as the objects are: a
//! container is made of the images of the layers of its image, which are
//! checked and never made again behind the user's back; `system check
//! --repair` makes them again from the tables of contents.
//!
//! The merged EROFS of composefs-rs (`fuse::canonical`) is made only for its
//! digest, which the manifest of a sealed image states: at the pull of such
//! an image (checked), at a commit or a push (stated); it is not kept.
//!
//! This is the code that was the free functions of `ImageService`
//! (`services/image/composefs.rs`), behind [`StorageDriver`] and unchanged in
//! what it does.

use super::{
    feed, objects, Capabilities, Collected, DiffOptions, DriverError, DriverErrorKind,
    DriverResult, FeedLayer, IdmapDone, IdmapWay, InProcess, Keep, LabelDone, LayerArtifact,
    LayerRef, Limits, MountCaps, MountRequest, Mounts, MountsRequest, ObjectRange, ObjectSink,
    Planned, Prefs, Problem, ProblemKind, PullFeed, Pulled, Purpose, Remedy, Rootfs, Settled,
    StorageDriver, UnusedLayers, Usage, VerityAsk, VerityDone, VerityEnforcement, Writable,
    WritableOptions, WritablePaths,
};
use crate::services::cpview::StoppedView;
use crate::services::image::seal;
use crate::services::imagecopy::TreeSource;
use async_trait::async_trait;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, info, warn};
use velarx_config::ComposefsDigests;
use velarx_content::layer::dirtar::{self, Change};
use velarx_content::layer::holes::HoleWrite;
use velarx_content::pull::staged::Staging;
use velarx_db::{Database, ImageRecord, LayerKey, LayerRecord};
use velarx_fuse::composefs::{self as cfs};
use velarx_fuse::plan::{MountFd, RootfsPlan};
use velarx_fuse::view::{ImageTree, ImageView};
use velarx_graph::objects::{open_dir, problem, sweep};
use velarx_storage::{FileStore, Toc, VerityMode};
use velarx_types::digest::{Algorithm, Digest};
use velarx_types::{ImageError, OciManifest};

/// The name of the driver.
pub const NAME: &str = "composefs";

static CAPABILITIES: Capabilities = Capabilities {
    lazy: true,
    serve_content: true,
    rootless: true,
    // the kernel's overlay checks them on mounts of root, the FUSE file
    // system on open
    verity: Prefs::new(&[VerityEnforcement::Kernel, VerityEnforcement::OnOpen]),
    shared_stores: true,
    layer_chain: false,
    max_layers: Some(cfs::OVERLAY_MAX_STACK),
    overlay_upper: true,
    // (no quota of the layer: `size_limit` is refused)
    writable_size_limit: false,
    root: MountCaps {
        idmap: Prefs::new(&[IdmapWay::DriverMount, IdmapWay::Translate]),
    },
    // (an image mounted in a container is made of the layers at each start,
    // as the root is, with the same ways of mapping the owners)
    volume: Some(MountCaps {
        idmap: Prefs::new(&[IdmapWay::DriverMount, IdmapWay::Translate]),
    }),
    limits: Limits::V1,
};

/// What the configuration says of the driver (`[storage] composefs` and
/// `composefs_digests`).
#[derive(Debug, Clone)]
pub struct ComposefsOptions {
    /// Whether the root file systems of containers are composefs images; else
    /// the image server serves them, and why.
    pub enabled: Result<(), String>,
    /// Whether the kernel mounts them (this process is root, and the kernel
    /// mounts an EROFS image from a file: `file_backed_erofs`); else the
    /// image server serves them.
    pub kernel_mount: Result<(), String>,
    /// Whether a kernel mount holds the lock of the image of each layer, as
    /// the image server does while it serves one (`locked_erofs`: Linux 7.3
    /// or later).  Where it does not, the kernel mounts the image by the name
    /// of its descriptor and no lock is held: only the rows of the container
    /// (`container_layers`) keep the layer of the mount.
    pub kernel_lock: bool,
    /// Whether the mounts of the same image share one superblock
    /// (`shared_superblock`): the kernel mounts get the option
    /// `superblock_share`.
    pub superblock_share: bool,
    /// What the manifests must say of the EROFS images of their layers.
    pub digests: ComposefsDigests,
    /// The image server that serves the layers the kernel does not mount
    /// (`velarx-monitor --image-server`).
    pub server: ImageServer,
}

/// Where the image server is and what it needs of the host.
#[derive(Debug, Clone)]
pub struct ImageServer {
    /// The monitor binary, which is the server with `--image-server`.
    pub program: PathBuf,
    /// The run root, where the kernel's answers are kept for the boot.
    pub run_root: PathBuf,
    /// The configuration of the engine: how the server fetches the files of an
    /// image that is being pulled (`[pull]`, the fetchers, `fsverity`).
    pub config: Arc<velarx_config::Config>,
}

/// The descriptors the image server of an image that is being pulled is
/// passed after the directories of the objects.
#[derive(Default)]
struct LazyFds {
    /// The index of each layer, the lowest first.
    indexes: Vec<std::os::fd::OwnedFd>,
    /// The directory of the startup profile.
    profile_dir: Option<std::os::fd::OwnedFd>,
}

impl ImageServer {
    pub fn new(program: PathBuf, run_root: PathBuf, config: Arc<velarx_config::Config>) -> Self {
        Self {
            program,
            run_root,
            config,
        }
    }
}

impl ComposefsOptions {
    /// Options that use nothing of the host yet (`[storage] composefs` not
    /// read): the image server serves every root file system.
    pub fn new(server: ImageServer) -> Self {
        Self {
            enabled: Err("not configured".into()),
            kernel_mount: Err("not configured".into()),
            kernel_lock: false,
            superblock_share: false,
            digests: ComposefsDigests::default(),
            server,
        }
    }

    /// The options of `[storage] composefs = mode` ("auto" or "off"), with
    /// what the host allows; says in the log what the root file systems of
    /// containers will be.  `images` is the directory of the objects of the
    /// store: whether the kernel mounts an EROFS image from a file depends on
    /// the file system the images are on (`file_backed_erofs`).
    pub fn for_mode(mode: &str, server: ImageServer, images: &Path) -> Self {
        let enabled = availability(mode);
        let native = enabled
            .clone()
            .and_then(|()| native_availability(&server.run_root, images));
        let (kernel_lock, superblock_share) = native.clone().unwrap_or_default();
        let kernel_mount = native.map(drop);
        match (&enabled, &kernel_mount) {
            (Ok(()), Ok(())) => {
                info!("composefs: root file systems from the EROFS images of the layers")
            }
            (Ok(()), Err(why)) => {
                info!("composefs: images of the layers served by the image server ({why})")
            }
            (Err(why), _) => {
                info!(
                    "composefs: not used ({why}): root file systems are served by the image server"
                )
            }
        }
        Self {
            enabled,
            kernel_mount,
            kernel_lock,
            superblock_share,
            ..Self::new(server)
        }
    }
}

/// Whether the kernel may mount the images (`[storage] composefs`): else
/// why not, and the image server serves them.
fn availability(mode: &str) -> Result<(), String> {
    match mode {
        "off" => Err("[storage] composefs is off".into()),
        "auto" => Ok(()),
        other => Err(format!("[storage] composefs is {other:?}, not auto or off")),
    }
}

/// The feature of the run root that says whether the kernel mounts an EROFS
/// image from a file (`monitor::features`).
const FILE_BACKED_EROFS: &str = "erofs-file";

/// The feature of the run root that says whether the kernel mounts an EROFS
/// image from an open file and keeps the lock the file holds for as long as
/// the mount exists.  It is looked for only where the kernel mounts from a
/// file at all.
const LOCKED_EROFS: &str = "erofs-lock";

/// The feature of the run root that says whether two mounts of the same EROFS
/// image with the option `superblock_share` are one superblock.  It is looked
/// for only where the kernel mounts from a file at all.
const SUPERBLOCK_SHARE: &str = "erofs-superblock-share";

/// Whether the kernel mounts them: this process is root of the initial user
/// namespace (an unprivileged user cannot mount EROFS images, or an overlay
/// with data-only layers), knows EROFS, and mounts an image from a regular
/// file without a block device (`file_backed_erofs`).  The answer says
/// whether the mount holds the lock of the image (`locked_erofs`): the
/// collection finds the layers the kernel has mounted by that lock, and does
/// not find those of a kernel that holds none.  The second answer says whether
/// the mounts of one image share their superblock (`shared_superblock`).
fn native_availability(run_root: &Path, images: &Path) -> Result<(bool, bool), String> {
    if !velarx_base::ids::rootful().map_err(|e| e.to_string())? {
        return Err("not root of the initial user namespace".into());
    }
    // the kernel must know EROFS (the module loads on the first use)
    rustix::mount::fsopen("erofs", rustix::mount::FsOpenFlags::FSOPEN_CLOEXEC)
        .map_err(|e| format!("the kernel cannot mount EROFS: {e}"))?;
    // (an answer is about the file system of the images, in this boot)
    let key = format!(
        "{} {}",
        velarx_nsid::store::boot_id().unwrap_or_default(),
        images.display()
    );
    file_backed(run_root, &key, || file_backed_erofs(images))?;
    let lock = locked(run_root, &key, || locked_erofs(images))?;
    let share = shared_superblock(run_root, &key, || shares_superblock(images))?;
    Ok((lock, share))
}

/// The answer of the feature `erofs-file` of the run root (`probe` finds it
/// the first time in a boot, for the images `key` names): the reason the
/// kernel does not mount from a file, or why it could not be found out.
fn file_backed(
    run_root: &Path,
    key: &str,
    probe: impl FnOnce() -> std::io::Result<Option<bool>>,
) -> Result<(), String> {
    match velarx_runtime::monitor::features::cached(run_root, FILE_BACKED_EROFS, key, probe) {
        Ok(Some(false)) => Err(
            "the kernel cannot mount an EROFS image from a file (file-backed EROFS: Linux 6.12 or later) on the file system of the images".into(),
        ),
        Ok(_) => Ok(()),
        Err(e) => Err(format!(
            "cannot find out whether the kernel mounts an EROFS image from a file: {e}"
        )),
    }
}

/// The answer of the feature `erofs-lock` of the run root (asked where the
/// kernel mounts from a file): whether the mount keeps the lock of the open
/// image.  No is not an error, the kernel mounts the image by the name of its
/// descriptor and holds no lock; an answer that cannot be found out is.
fn locked(
    run_root: &Path,
    key: &str,
    probe: impl FnOnce() -> std::io::Result<Option<bool>>,
) -> Result<bool, String> {
    // (only a yes is a lock: no answer mounts by the name, as a no does)
    match velarx_runtime::monitor::features::cached(run_root, LOCKED_EROFS, key, probe) {
        Ok(answer) => Ok(answer == Some(true)),
        Err(e) => Err(format!(
            "cannot find out whether the kernel mounts an EROFS image from an open file: {e}"
        )),
    }
}

/// The answer of the feature `erofs-superblock-share` of the run root (asked
/// where the kernel mounts from a file): whether the option is known and the
/// mounts of one image are one superblock.  No is not an error, each mount has
/// its own; an answer that cannot be found out is.
fn shared_superblock(
    run_root: &Path,
    key: &str,
    probe: impl FnOnce() -> std::io::Result<Option<bool>>,
) -> Result<bool, String> {
    match velarx_runtime::monitor::features::cached(run_root, SUPERBLOCK_SHARE, key, probe) {
        Ok(answer) => Ok(answer == Some(true)),
        Err(e) => Err(format!(
            "cannot find out whether the kernel shares the superblock of EROFS mounts: {e}"
        )),
    }
}

/// The name of the image of the probe, in the directory of the images: a
/// temporary file of that directory (`stray_images`), so that one a crash
/// left is a leftover that the collection removes.
const PROBE_PREFIX: &str = ".tmp-probe-";

/// `probe` run on an empty image written in `images`, the directory of the
/// store's images, where the real ones are, opened as they are
/// (`open_layer_image`, which takes the lock).  The image is removed when it
/// returns.
fn on_probe_image<T>(
    images: &Path,
    probe: impl FnOnce(&Path, std::fs::File) -> std::io::Result<T>,
) -> std::io::Result<T> {
    use std::io::Write;
    let dir = cfs::images_dir(images);
    std::fs::create_dir_all(&dir)?;
    let image = velarx_fuse::layer_erofs::layer_image(&[]).map_err(std::io::Error::other)?;
    let mut file = tempfile::Builder::new()
        .prefix(PROBE_PREFIX)
        .suffix(".erofs")
        .tempfile_in(&dir)?;
    file.write_all(&image.image)?;
    file.flush()?;
    let opened = cfs::open_layer_image(file.path())?;
    probe(file.path(), opened)
}

/// Whether the kernel mounts an EROFS image from a regular file (Linux 6.12
/// and later, on a file system that can be read through the page cache): the
/// empty image is mounted detached, by the name of its descriptor.  An answer
/// of the kernel is `Some`; a failure that says nothing of the kernel (no
/// memory, no descriptor, a directory that cannot be written) is an error,
/// and nothing is kept.
fn file_backed_erofs(images: &Path) -> std::io::Result<Option<bool>> {
    on_probe_image(images, |_, probe| {
        file_backed_answer(
            velarx_runtime::imagemount::mount_erofs(
                &probe,
                velarx_runtime::imagemount::ErofsSource::ProcPath,
                false,
            )
            .map(drop),
        )
    })
}

/// What the mount of the image of the probe says: yes where it is mounted,
/// no where the kernel refuses a file as the source of an EROFS (what a
/// kernel that mounts only a block device answers), an error for a failure
/// that says nothing of the kernel.
fn file_backed_answer(mounted: std::io::Result<()>) -> std::io::Result<Option<bool>> {
    match mounted {
        Ok(()) => Ok(Some(true)),
        Err(e) if velarx_runtime::imagemount::refuses_a_file(&e) => {
            debug!("composefs: the kernel does not mount an EROFS image from a file: {e}");
            Ok(Some(false))
        }
        Err(e) => Err(e),
    }
}

/// Whether the kernel mounts an EROFS image from an open regular file and
/// keeps the lock the file holds (Linux 7.3 and later): the empty image is
/// mounted detached with its descriptor as the source, the descriptor closed,
/// and the lock must still be held, by the mount alone.
fn locked_erofs(images: &Path) -> std::io::Result<Option<bool>> {
    on_probe_image(images, |path, probe| {
        let mounted = velarx_runtime::imagemount::mount_erofs(
            &probe,
            velarx_runtime::imagemount::ErofsSource::Descriptor,
            false,
        );
        drop(probe);
        // (the mount is alive while the lock is asked)
        locked_answer(mounted.and_then(|_mount| {
            Ok(matches!(
                cfs::lock_unused_layer_image(path)?,
                cfs::LayerUse::InUse
            ))
        }))
    })
}

/// Whether the kernel shares the superblock of two mounts of an image with
/// `superblock_share`: the empty image is mounted twice, detached, and the
/// roots of the mounts are one device.
///
/// (The probes of `erofs-file` and `erofs-lock` mount without the option: they
/// ask what the kernel does with a file, before the option is looked for.)
fn shares_superblock(images: &Path) -> std::io::Result<Option<bool>> {
    on_probe_image(images, |_, probe| {
        use velarx_runtime::imagemount::{mount_erofs, ErofsSource};
        let first = mount_erofs(&probe, ErofsSource::ProcPath, true);
        let second = mount_erofs(&probe, ErofsSource::ProcPath, true);
        shared_answer(first.and_then(|first| {
            let second = second?;
            Ok(rustix::fs::fstat(first)?.st_dev == rustix::fs::fstat(second)?.st_dev)
        }))
    })
}

/// What the mounts of the image of the probe say: yes where both are mounted
/// and are one device, no where they are two or the kernel refuses the option
/// (`EINVAL`, an unknown parameter), an error for a failure that says nothing
/// of the kernel.
fn shared_answer(mounted: std::io::Result<bool>) -> std::io::Result<Option<bool>> {
    match mounted {
        Ok(shared) => Ok(Some(shared)),
        Err(e) if velarx_runtime::imagemount::refuses_a_file(&e) => {
            debug!("composefs: the kernel does not share the superblock of EROFS mounts: {e}");
            Ok(Some(false))
        }
        Err(e) => Err(e),
    }
}

/// What the mount of the image of the probe says: yes where it is mounted
/// and its lock is held, no where the kernel refuses a descriptor as the
/// source of an EROFS (what a kernel before 7.3 answers) or mounts it and
/// drops the lock, an error for a failure that says nothing of the kernel.
fn locked_answer(mounted: std::io::Result<bool>) -> std::io::Result<Option<bool>> {
    match mounted {
        Ok(held) => {
            if !held {
                debug!("composefs: the kernel mounted the EROFS image and dropped its lock");
            }
            Ok(Some(held))
        }
        Err(e) if velarx_runtime::imagemount::refuses_a_file(&e) => {
            debug!("composefs: the kernel does not mount an EROFS image from an open file: {e}");
            Ok(Some(false))
        }
        Err(e) => Err(e),
    }
}

/// Files written through temporary files of their directories and made
/// durable together: their contents with one barrier of the file system
/// (`[storage] sync`), then their names in the order they were given, then
/// the directories.  A crash leaves a file whole or not there, never
/// empty; a sync for each file cost more than making the images.
struct Durable<'a> {
    store: &'a velarx_storage::FileStore,
    files: Vec<(tempfile::TempPath, PathBuf)>,
    /// Whether the commit makes the files durable itself: not when a
    /// barrier of the caller does (the images of a pull are written between
    /// the link of its files and the barrier of the store; one that
    /// replaces a file is made durable before it takes the place)
    sync: bool,
}

impl<'a> Durable<'a> {
    fn new(store: &'a velarx_storage::FileStore) -> Self {
        Self {
            store,
            files: Vec::new(),
            sync: true,
        }
    }

    /// Files whose durability is the caller's: a barrier of the store that
    /// comes after [`Durable::commit`].
    fn before_barrier(store: &'a velarx_storage::FileStore) -> Self {
        Self {
            sync: false,
            ..Self::new(store)
        }
    }

    /// `contents` for `path`, in place of what is there, read-only; with
    /// `verity` (the algorithm of the digests of the layer), fs-verity with
    /// its hash is enabled on it where the file system has it.
    fn replace(
        &mut self,
        path: &Path,
        contents: &[u8],
        verity: Option<Algorithm>,
    ) -> std::io::Result<()> {
        use std::io::Write;
        use std::os::unix::fs::PermissionsExt;
        let dir = path
            .parent()
            .ok_or_else(|| std::io::Error::other("an image path without a directory"))?;
        std::fs::create_dir_all(dir)?;
        let mut tmp = tempfile::Builder::new().prefix(".tmp").tempfile_in(dir)?;
        tmp.write_all(contents)?;
        // (closed for writing, and writable by its owner: what enabling
        // fs-verity needs)
        let tmp = tmp.into_temp_path();
        if let Some((m, alg)) = VerityMode::On.manager().zip(verity) {
            match m.for_algorithm(alg).enable(&tmp) {
                Ok(()) => {}
                // (never an image of a layer of this hash without it: a
                // check against the digest of the layer would find none)
                Err(e @ velarx_storage::FsVerityError::AlgorithmUnavailable(_)) => {
                    return Err(std::io::Error::other(e.to_string()))
                }
                Err(_) => {}
            }
        }
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o444))?;
        self.files.push((tmp, path.to_path_buf()));
        Ok(())
    }

    /// Make the files durable and give them their names.
    fn commit(self) -> std::io::Result<()> {
        let Some(dir) = self
            .files
            .first()
            .and_then(|(_, p)| p.parent())
            .map(Path::to_path_buf)
        else {
            return Ok(());
        };
        if self.sync {
            self.store.barrier(&dir)?;
        }
        let mut dirs = std::collections::BTreeSet::new();
        for (tmp, path) in self.files {
            // (an image of a layer that is recorded already is never replaced
            // by bytes that are not on the disk: a crash after the rename
            // and before the barrier would tear what its row names.  A new
            // name has no row yet and its barrier is the caller's: a torn
            // image nothing records is made again by the pull that finds no
            // row, and checked against the digest before it is adopted)
            if !self.sync && path.exists() {
                std::fs::File::open(&tmp)?.sync_data()?;
            }
            tmp.persist(&path).map_err(|e| e.error)?;
            if let Some(d) = path.parent() {
                dirs.insert(d.to_path_buf());
            }
        }
        if !self.sync {
            return Ok(());
        }
        dirs.iter().try_for_each(|d| self.store.sync_dir(d))
    }
}

/// The images of layers made, not yet in the store.
struct Built(Vec<(LayerKey, velarx_fuse::layer_erofs::LayerImage, String)>);

impl Built {
    /// The images of the layers `keys` apart from the others.
    fn split(self, keys: &std::collections::HashSet<LayerKey>) -> (Built, Built) {
        let (apart, rest) = self.0.into_iter().partition(|(k, _, _)| keys.contains(k));
        (Built(apart), Built(rest))
    }

    /// The fs-verity digest of the image of each layer.
    fn digests(&self) -> HashMap<LayerKey, String> {
        self.0
            .iter()
            .map(|(layer, _, erofs)| (*layer, erofs.clone()))
            .collect()
    }
}

/// Make the images of the layers `(key, TOC)`, in memory.
fn build_layer_images(layers: &[(LayerKey, &velarx_storage::Toc)]) -> std::io::Result<Built> {
    let built: Vec<std::io::Result<(LayerKey, velarx_fuse::layer_erofs::LayerImage)>> =
        std::thread::scope(|s| {
            let handles: Vec<_> = layers
                .iter()
                .map(|(digest, toc)| {
                    s.spawn(move || {
                        let made = velarx_fuse::layer_erofs::layer_image(&toc.entries);
                        made.map(|b| (*digest, b)).map_err(|e| {
                            std::io::Error::other(format!("the EROFS image of layer {digest}: {e}"))
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
    built
        .into_iter()
        .map(|b| {
            let (digest, image) = b?;
            // (in the algorithm of the digests of the layer: its key)
            let erofs = image
                .identity(digest.digest().alg())
                .map_err(std::io::Error::other)?
                .erofs;
            Ok((digest, image, erofs))
        })
        .collect::<std::io::Result<_>>()
        .map(Built)
}

/// Write the images in the store, durably, at once (one barrier).  The same
/// layer makes the same image: one that is there is replaced by the same
/// bytes.
fn write_layer_images(
    built: Built,
    store: &velarx_storage::FileStore,
) -> std::io::Result<HashMap<LayerKey, LayerArtifact>> {
    write_layer_images_in(built, store.root(), Durable::new(store))
}

/// [`write_layer_images`] where `objects` stands for the objects directory
/// of the store whose `composefs/` they go to (the staging area's, for the
/// layers of a lazy pull).
fn write_layer_images_in(
    built: Built,
    objects: &Path,
    mut durable: Durable<'_>,
) -> std::io::Result<HashMap<LayerKey, LayerArtifact>> {
    let mut out = HashMap::new();
    for (digest, image, erofs) in built.0 {
        durable.replace(
            &cfs::layer_index_path(objects, &digest.file_stem()),
            &image.index,
            None,
        )?;
        durable.replace(
            &cfs::layer_image_path(objects, &digest.file_stem()),
            &image.image,
            Some(digest.digest().alg()),
        )?;
        out.insert(
            digest,
            LayerArtifact {
                image_digest: erofs,
                owners: image.owners_json().map_err(std::io::Error::other)?,
            },
        );
    }
    durable.commit()?;
    Ok(out)
}

/// Make and write the images of the layers `(key, TOC)` in the store.
fn make_layer_images(
    layers: &[(LayerKey, &velarx_storage::Toc)],
    store: &velarx_storage::FileStore,
) -> std::io::Result<HashMap<LayerKey, LayerArtifact>> {
    write_layer_images(build_layer_images(layers)?, store)
}

/// What is wrong with the image of a layer at `path`, recorded with the
/// fs-verity digest `recorded`; `full` reads it, and compares it with the
/// image its table of contents makes.
fn layer_problems(
    path: &Path,
    recorded: Option<&str>,
    toc: Option<&velarx_storage::Toc>,
    full: bool,
) -> Vec<Problem> {
    use std::os::unix::fs::PermissionsExt;
    let mut found = Vec::new();
    let Some(recorded) = recorded else {
        found.push(problem(
            ProblemKind::ArtifactMissing,
            path,
            "the EROFS image of the layer is not recorded",
        ));
        return found;
    };
    let meta = match std::fs::symlink_metadata(path) {
        Ok(m) if m.is_file() => m,
        Ok(_) => {
            found.push(problem(
                ProblemKind::ArtifactUnreadable,
                path,
                "the EROFS image of the layer is not a regular file",
            ));
            return found;
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            found.push(problem(
                ProblemKind::ArtifactMissing,
                path,
                "the EROFS image of the layer is not there",
            ));
            return found;
        }
        Err(e) => {
            found.push(problem(
                ProblemKind::ArtifactUnreadable,
                path,
                format!("cannot stat the EROFS image of the layer: {e}"),
            ));
            return found;
        }
    };
    if meta.permissions().mode() & 0o222 != 0 {
        found.push(problem(
            ProblemKind::ArtifactWritable,
            path,
            "the EROFS image of the layer is not read-only",
        ));
    }
    // (measured and read through one descriptor, opened as the monitor
    // opens the images it mounts)
    let mut file = match cfs::open_checked_layer_image(path, &[recorded.to_string()], false) {
        Ok(f) => f,
        Err(e) => {
            found.push(problem(
                ProblemKind::ArtifactIdMismatch,
                path,
                e.to_string(),
            ));
            return found;
        }
    };
    if !full {
        return found;
    }
    let mut bytes = Vec::new();
    if let Err(e) = std::io::Read::read_to_end(&mut file, &mut bytes) {
        found.push(problem(
            ProblemKind::ArtifactUnreadable,
            path,
            format!("cannot read the EROFS image of the layer: {e}"),
        ));
        return found;
    }
    // (in the algorithm of the digest the layer records)
    let alg = recorded
        .parse::<Digest>()
        .map_or(Algorithm::Sha256, |d| d.alg());
    let digest = velarx_storage::composefs_digest_of(alg, &bytes);
    if digest != recorded {
        found.push(problem(
            ProblemKind::ArtifactIdMismatch,
            path,
            format!(
                "the EROFS image has the fs-verity digest {digest}, its layer records {recorded}"
            ),
        ));
    }
    if let Some(toc) = toc {
        match velarx_fuse::layer_erofs::layer_image(&toc.entries) {
            Ok(made) if *made.image != *bytes => found.push(problem(
                ProblemKind::ArtifactDiffers,
                path,
                "the EROFS image is not the one the table of contents of the layer makes",
            )),
            Ok(_) => {}
            Err(e) => found.push(problem(
                ProblemKind::ArtifactUnreadable,
                path,
                format!("the table of contents of the layer makes no image: {e}"),
            )),
        }
    }
    found
}

/// The files of a layer image, as `layer_images` finds them: the image and its
/// index.
type ImageFiles = (PathBuf, PathBuf);

/// The images of the layers whose files are missing or not the ones
/// recorded, with the remedy.
fn missing_image(image_id: &str, layer: &LayerKey, why: impl std::fmt::Display) -> DriverError {
    let image = match image_id {
        "" => String::new(),
        id => format!("image {id}: "),
    };
    DriverError::missing(
        NAME,
        Some(layer),
        format!("{image}the EROFS image of the layer {layer} {why}"),
        Remedy::Repair,
    )
}

fn storage_error(e: std::io::Error) -> DriverError {
    DriverError::storage(
        NAME,
        format!("cannot make the EROFS images of the layers: {e}"),
    )
}

fn join_error(e: tokio::task::JoinError) -> DriverError {
    DriverError::storage(NAME, e.to_string())
}

/// The owners of the files of the layers (uids, gids), as their records say.
fn image_owners(layers: &[LayerRecord]) -> (Vec<u32>, Vec<u32>) {
    let mut uids = std::collections::BTreeSet::new();
    let mut gids = std::collections::BTreeSet::new();
    for l in layers {
        if let Some((u, g)) = l.owners.as_deref().and_then(cfs::parse_owners) {
            uids.extend(u);
            gids.extend(g);
        }
    }
    (uids.into_iter().collect(), gids.into_iter().collect())
}

/// The directory of a bundle with the overlay of its container: `upper` and
/// `work` (the layout of the bundles since the first release).
const OVERLAY_DIR: &str = "overlay";

/// The digests an enforced start holds the image of a layer to.
struct Enforced<'a> {
    /// The fs-verity digests of the manifest for the layer: one of them.
    accepted: &'a [String],
    /// The chain of trust of the image, if the log follows it.
    chain: Option<&'a velarx_wire::chain::Chain>,
    /// The layer, from 1.
    layer: usize,
}

/// What a container's mount is made of: the images of the layers of its
/// image, the objects and the owners.
struct Layout {
    /// The images of its layers, the lowest first.
    layers: Vec<LayerFiles>,
    /// The id of the image.
    image_id: String,
    /// The startup profile of the image (`profile_path`).
    profile: PathBuf,
    /// The owners of the files of the layers (uids, gids), which the mapping
    /// of a user namespace must cover.
    owners: (Vec<u32>, Vec<u32>),
    /// Every file of the image is in the store.
    complete: bool,
    /// The objects of the store: the data-only layer.
    objects: PathBuf,
    /// The objects of the read-only image stores: data-only layers under it,
    /// in their order.
    more_objects: Vec<PathBuf>,
    /// The staging directory of the store (`staging`) when the image is one
    /// that is being pulled: the staging directories of its layers
    /// (`layers/<stem>/files`) are its data-only layers after the objects.
    staging: Option<PathBuf>,
    /// The `verity` option of the overlay as root: off, on or require.
    verity: String,
}

/// The EROFS image of a layer and its index.
struct LayerFiles {
    /// The key of the layer, for the fetches of the files it lacks.
    layer: String,
    image: PathBuf,
    index: PathBuf,
}

/// What the driver makes of a request for a mount (`mount_plan`).
struct Prepared {
    /// What the mount is made of.
    m: Layout,
    /// The driver mounts it with the kernel: this process is root, the files
    /// of the image are all in the store, the kernel mounts an EROFS image
    /// from a file, the mapping of a user namespace covers its owners.  Else
    /// the image server serves the layers.
    kernel: bool,
    /// The layers are mounted with the mapping of the container's user
    /// namespace (idmapped mounts): it maps every owner of the image.
    idmapped: bool,
}

/// The driver of the store: the objects, the images of the layers, the files
/// of the staging area.
pub struct ComposefsDriver {
    db: Database,
    store: Arc<FileStore>,
    staging_dir: PathBuf,
    /// What fs-verity stored files get
    fsverity: VerityMode,
    options: ComposefsOptions,
}

/// Why the image server's mount could not be made: the words, and whether
/// the process had no descriptors left to open what the mount is made of.
#[derive(Debug)]
struct ServeFailure {
    message: String,
    out_of_descriptors: bool,
}

impl ServeFailure {
    fn of_io(e: std::io::Error) -> Self {
        Self {
            out_of_descriptors: velarx_runtime::imagemount::out_of_descriptors(&e),
            message: e.to_string(),
        }
    }

    fn of_io_in(what: &str, e: std::io::Error) -> Self {
        let mut failure = Self::of_io(e);
        failure.message = format!("{what}: {}", failure.message);
        failure
    }
}

impl From<String> for ServeFailure {
    fn from(message: String) -> Self {
        Self {
            message,
            out_of_descriptors: false,
        }
    }
}

impl From<&str> for ServeFailure {
    fn from(message: &str) -> Self {
        message.to_string().into()
    }
}

/// The mount of an image needs more open files than the process may have
/// ([`velarx_base::hardening::open_files_needed`]: descriptors for each of its
/// layers, two while the kernel mounts them, three for the image server of a
/// lazy image), which only a higher hard limit mends.  There is no other way
/// to mount the image.
fn no_open_files(image: &str, needed: u64) -> DriverError {
    let (soft, hard) = velarx_base::hardening::open_files();
    DriverError::storage(
        NAME,
        format!(
            "image {image}: mounting {}: raise the hard limit of open files (`ulimit -Hn`, `LimitNOFILE=` of the unit)",
            velarx_base::hardening::NoOpenFiles { needed, soft, hard }
        ),
    )
}

impl ComposefsDriver {
    /// What the driver can do, whatever its options.
    pub fn capabilities_of() -> &'static Capabilities {
        &CAPABILITIES
    }

    /// The image below an upper directory, for what the overlay's `metacopy`
    /// and `redirect` leave to it.
    fn lower(&self, tree: Option<Arc<dyn ImageTree>>) -> Option<Arc<dirtar::Lower>> {
        tree.map(|tree| {
            Arc::new(dirtar::Lower {
                tree,
                objects: self.store.clone(),
            })
        })
    }

    /// The driver of `store` (and the staging area `staging_dir` of its pulls)
    /// as `options` say.
    pub fn new(
        db: Database,
        store: Arc<FileStore>,
        staging_dir: PathBuf,
        fsverity: VerityMode,
        options: ComposefsOptions,
    ) -> Self {
        Self {
            db,
            store,
            staging_dir,
            fsverity,
            options,
        }
    }

    fn staging(&self) -> Staging {
        Staging::new(&self.staging_dir)
    }

    /// A directory beside the objects of the store (the one the images of the
    /// layers are in is `composefs`).
    pub(super) fn beside_objects(&self, name: &str) -> PathBuf {
        let objects = self.store.root();
        objects.parent().unwrap_or(objects).join(name)
    }

    /// Drop the files of the layers of `layers` that have an image in this
    /// store and are not in `keep`: the objects their tables of contents name
    /// (except the files in `retain`, and those of the layers of `keep`, which
    /// the layers that stay still name), then the image and its index.  The
    /// image goes last and says that a layer has files of this store, so a
    /// call that stops anywhere is finished by the next one.  The rows of the
    /// layers stay.  The caller holds the lock of the store exclusive.
    pub(super) async fn drop_layers(
        &self,
        layers: &[LayerKey],
        keep: &std::collections::HashSet<LayerKey>,
        retain: &std::collections::HashSet<String>,
    ) -> DriverResult<Collected> {
        let objects = self.store.root().to_path_buf();
        let mut dropping = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for key in layers {
            let image = cfs::layer_image_path(&objects, &key.file_stem());
            if !keep.contains(key) && seen.insert(*key) && image.is_file() {
                dropping.push(*key);
            }
        }
        let mut out = Collected::default();
        if dropping.is_empty() {
            return Ok(out);
        }
        // A layer a mount or a server uses stays, with its files; the
        // others are held (nothing mounts them) until their files are
        // removed, a batch at a time (a descriptor each).  The files a layer
        // that stays names stay: those of `keep` and of the layers found in
        // use.  A file that several of the layers to drop name goes with the
        // last of them: a layer of a later batch, not asked yet, may still
        // turn out in use.  (the tables of contents are read only when there
        // is something to drop, each of a layer to drop once more when its
        // files go; one that cannot be read makes the call drop nothing:
        // the files of that layer are not known)
        let mut retained = retain.clone();
        for key in keep {
            if let Some(toc) = self.toc_of(key).await? {
                retained.extend(toc_files(&toc));
            }
        }
        let mut last: std::collections::HashMap<String, usize> = Default::default();
        for (i, key) in dropping.iter().enumerate() {
            if let Some(toc) = self.toc_of(key).await? {
                last.extend(toc_files(&toc).into_iter().map(|d| (d, i)));
            }
        }
        let numbered: Vec<(usize, LayerKey)> = dropping.into_iter().enumerate().collect();
        for batch in velarx_graph::unused::unused_batches(self, numbered, |(_, k)| Some(*k)) {
            let batch = batch?;
            for (_, key) in &batch.in_use {
                if let Some(toc) = self.toc_of(key).await? {
                    retained.extend(toc_files(&toc));
                }
            }
            for &(i, key) in &batch.unused {
                let Some(toc) = self.toc_of(&key).await? else {
                    // (a layer with no row or no table of contents is the
                    // collection's: it names the files of no layer)
                    continue;
                };
                let files: Vec<String> = toc_files(&toc)
                    .into_iter()
                    .filter(|d| !retained.contains(d) && last.get(d) == Some(&i))
                    .collect();
                let store = self.store.clone();
                let stem = key.file_stem();
                let (freed, errors) = tokio::task::spawn_blocking(move || {
                    let objects = store.root().to_path_buf();
                    let (mut freed, mut errors) = (0u64, Vec::new());
                    for d in &files {
                        let Some(path) = store.local_path(d) else {
                            continue;
                        };
                        match std::fs::symlink_metadata(&path)
                            .and_then(|m| std::fs::remove_file(&path).map(|()| m.len()))
                        {
                            Ok(len) => freed += len,
                            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                            Err(e) => {
                                errors.push(format!("Failed to remove {}: {e}", path.display()))
                            }
                        }
                    }
                    if errors.is_empty() {
                        for path in [
                            cfs::layer_index_path(&objects, &stem),
                            cfs::layer_image_path(&objects, &stem),
                        ] {
                            match std::fs::symlink_metadata(&path)
                                .and_then(|m| std::fs::remove_file(&path).map(|()| m.len()))
                            {
                                Ok(len) => freed += len,
                                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                                Err(e) => {
                                    errors.push(format!("Failed to remove {}: {e}", path.display()))
                                }
                            }
                        }
                    }
                    (freed, errors)
                })
                .await
                .map_err(|e| DriverError::storage(NAME, e.to_string()))?;
                debug!("The engine's copy of the layer {key} is dropped ({freed} bytes)");
                out.bytes_freed += freed;
                out.errors.extend(errors);
            }
        }
        Ok(out)
    }

    /// The table of contents the store records for a layer: none for a
    /// layer with no row or no table of contents (it names no file of this
    /// store), an error when the row or the table of contents cannot be read.
    async fn toc_of(&self, key: &LayerKey) -> DriverResult<Option<Toc>> {
        let record = match self.db.get_own_layer(key).await {
            Ok(r) => r,
            Err(velarx_types::DbError::NotFound(_)) => return Ok(None),
            Err(e) => return Err(DriverError::storage(NAME, format!("layer {key}: {e}"))),
        };
        let Some(text) = record.toc else {
            return Ok(None);
        };
        serde_json::from_str(&text).map(Some).map_err(|e| {
            DriverError::storage(NAME, format!("the table of contents of layer {key}: {e}"))
        })
    }

    /// The objects of this store and of the read-only image stores there are.
    fn objects_dirs(&self) -> Vec<PathBuf> {
        objects::objects_dirs(&self.store)
    }

    /// The images of the layers of `image_id` (the image, its index), from
    /// the store that has each: an error when one is missing.
    fn layer_images(
        &self,
        image_id: &str,
        layers: &[LayerRecord],
    ) -> DriverResult<Vec<ImageFiles>> {
        // (the images of the layers of an image being pulled are in the
        // staging area until their layer is committed)
        let mut dirs = self.objects_dirs();
        dirs.push(self.staging().objects_stand_in());
        let dirs: Vec<&Path> = dirs.iter().map(PathBuf::as_path).collect();
        layers
            .iter()
            .map(|l| {
                if l.erofs.is_none() {
                    return Err(missing_image(image_id, &l.key, "is not recorded"));
                }
                cfs::find_layer_image(&dirs, &l.key.file_stem())
                    .ok_or_else(|| missing_image(image_id, &l.key, "is not there"))
            })
            .collect()
    }

    /// What the root file system of a container of the image of the request,
    /// or an image mounted in it, is made of: the images of its layers, the
    /// objects and the owners, and whether the driver mounts it.  Costs
    /// O(layers), never O(files).  `at_start`: the plan is for a start, not
    /// for the create of a container (see the check of the enforced digests
    /// below).
    fn mount_plan(&self, req: &MountRequest<'_>, at_start: bool) -> DriverResult<Prepared> {
        let MountRequest {
            image,
            layers,
            mapping,
            verity,
            ..
        } = req;
        let (image, layers, mapping, enforce) = (*image, *layers, *mapping, verity.enforced());
        let files = self.layer_images(&image.id, layers)?;
        // The overlay checks the fs-verity digests of the files where the
        // store has fs-verity: the images of its layers have it then, as its
        // objects (on a file system without it, every digest would be one
        // that the file lacks, and so on one whose blocks are smaller than
        // those of the digests that name the files).
        let has_verity = files
            .first()
            .is_some_and(|(image, _)| velarx_fuse::view::layer_image_has_verity(image));
        let first_image = files.first().map(|(image, _)| image.clone());
        let enforce = enforce || self.options.digests == ComposefsDigests::Require;
        let verity = match (self.fsverity, has_verity, enforce) {
            (_, _, true) | (VerityMode::Require, _, _) => "require",
            (VerityMode::Off, _, _) | (VerityMode::On, false, _) => "off",
            (VerityMode::On, true, _) => "on",
        }
        .to_string();
        let complete = !image.is_lazy;
        // (the kernel cannot check the files an image lacks, and nothing
        // else would: the files of a lazy image come as the container reads
        // them.  The engine refuses it first, with the reason it enforces
        // (the node's `require` or `--security-opt verity=enforce`), at the
        // create and at the start; this is the driver's own word at a start,
        // for a caller that did not)
        if at_start && enforce && !complete {
            return Err(DriverError::of(
                NAME,
                DriverErrorKind::DigestEnforced,
                format!(
                    "image {}: the digests are enforced and the image is not all in the store (a lazy pull): the overlay cannot check the files it lacks; let it be fetched whole first",
                    image.id
                ),
            ));
        }
        if !complete {
            // (the profile a container of the image records is saved next to
            // the records of the store: the directory is there before the
            // first layer is committed)
            if let Some(dir) = cfs::profile_path(self.store.root(), &image.id).parent() {
                std::fs::create_dir_all(dir).map_err(|e| DriverError::io(NAME, e))?;
            }
        }
        let objects = self.objects_dirs();
        // (the data-only layers: the objects of the stores, and the files
        // fetched for each layer of a lazy image; the pull refused more)
        let limit = Self::capabilities_of()
            .max_image_layers(objects.len(), !complete)
            .unwrap_or(usize::MAX);
        if layers.len() > limit {
            return Err(DriverError::storage(
                NAME,
                format!(
                    "image {}: its {} layers are more than the {limit} the overlay of a container takes with the data-only layers of the {} stores{}",
                    image.id,
                    layers.len(),
                    objects.len(),
                    if complete { "" } else { " and of the files fetched for each layer of an image that is not all in the store" },
                ),
            ));
        }
        let native_ok = self.options.enabled.is_ok() && self.options.kernel_mount.is_ok();
        let m = Layout {
            layers: layers
                .iter()
                .zip(files)
                .map(|(l, (image, index))| LayerFiles {
                    layer: l.key.to_string(),
                    image,
                    index,
                })
                .collect(),
            image_id: image.id.clone(),
            profile: cfs::profile_path(self.store.root(), &image.id),
            owners: image_owners(layers),
            complete,
            objects: objects[0].clone(),
            more_objects: objects[1..].to_vec(),
            staging: (!complete).then(|| self.staging_dir.clone()),
            verity,
        };
        let mut prepared = Prepared {
            m,
            kernel: native_ok && complete,
            idmapped: false,
        };
        // The owners of the files must be shown: the mapping of the container's
        // user namespace, or else the ids the engine has, covers every owner
        // of the image or the image does not start (squashed owners are shown
        // as the root of the container).  The driver says so itself, at the
        // create of the container and at each start, whoever would mount it.
        if let Some(why) = req
            .mapping
            .or(req.translate)
            .and_then(|t| t.unmapped_owners_error(&prepared.m.owners))
        {
            return Err(DriverError::storage(NAME, why));
        }
        // a container with a user namespace: its mapping on idmapped
        // mounts of the layers, which map every owner of the image
        // (FUSE translates those, and squashes what is not mapped)
        if let (Some(t), true) = (mapping, prepared.kernel) {
            if t.squash {
                debug!(
                    "Image {}: FUSE root file system: unmapped owners are squashed",
                    image.id
                );
                prepared.kernel = false;
            } else {
                prepared.idmapped = true;
            }
        }
        // Enforced digests need a store with fs-verity.  A start measures
        // every image strictly (`mount`) and says what is wrong with an image
        // that has none, when the file system takes fs-verity.  The create is
        // refused here, with the store named.
        if enforce && !has_verity && !(at_start && !Self::unmeasurable(first_image.as_deref())) {
            let first = first_image.as_ref().map(|i| i.display().to_string());
            return Err(DriverError::of(
                NAME,
                DriverErrorKind::DigestEnforced,
                format!(
                    "the digests of the EROFS images are enforced and the image {} has no fs-verity (the store, {}, needs a file system with fs-verity)",
                    first.unwrap_or_default(),
                    self.store.root().display()
                ),
            ));
        }
        Ok(prepared)
    }

    /// Whether the file system of the first image takes no
    /// fs-verity (or has blocks under 4096 bytes), whatever the image: the
    /// store cannot enforce digests.  False for an image that has none on a
    /// file system that does, or cannot be opened (the measure says why).
    fn unmeasurable(first: Option<&Path>) -> bool {
        first.is_some_and(|image| {
            cfs::open_layer_image(image).is_ok_and(|f| {
                matches!(
                    velarx_storage::measure_file(&f),
                    Err(velarx_storage::FsVerityError::NotSupported)
                ) || !rustix::fs::fstatfs(&f).is_ok_and(|s| s.f_bsize >= 4096)
            })
        })
    }

    /// The answer: the mount descriptor `fd` if there is one (the plan of a
    /// root or an image mount is always that of a mount descriptor, which the
    /// engine passes to the monitor), with who maps the ids and who labels
    /// the files.  `measured` is what the driver measured on the images it
    /// mounted for enforced digests, the lowest layer first.
    fn rootfs_of(
        (mapped, labelled): (bool, bool),
        fd: Option<std::os::fd::OwnedFd>,
        measured: Option<Vec<String>>,
    ) -> Rootfs {
        let (verity, measured) = match measured {
            Some(measured) if fd.is_some() => (VerityDone::Kernel, measured),
            _ => (VerityDone::None, Vec::new()),
        };
        Rootfs {
            plan: RootfsPlan::MountFd(MountFd {
                fd_index: 0,
                idmap: false,
                server: false,
            }),
            fd,
            idmap: match mapped {
                true => IdmapDone::Applied,
                false => IdmapDone::None,
            },
            // (the overlay is mounted with `context=`)
            label: if labelled {
                LabelDone::MountContext
            } else {
                LabelDone::None
            },
            verity,
            measured,
            server: None,
        }
    }

    /// Whether the request has a mapping and a label.
    fn asked(req: &MountRequest<'_>) -> (bool, bool) {
        (req.mapping.is_some(), req.label.is_some())
    }

    /// How the root file system of a container of the image of the request,
    /// or an image mounted in it, is made, with no mount made.
    fn plan(&self, req: &MountRequest<'_>) -> DriverResult<Rootfs> {
        self.mount_plan(req, false)?;
        Ok(Self::rootfs_of(Self::asked(req), None, None))
    }

    /// The mount of the request at this start: the detached overlay of the
    /// EROFS images of the layers (idmapped for a container with a user
    /// namespace), with the upper layer of the container for a root.
    ///
    /// Each image is opened once, as a name that is no link, and measured on
    /// that descriptor, which is the one mounted or served.
    /// The digests that name it are the fs-verity digest the engine recorded
    /// for it at the pull (from the table of contents of the layer), or, when
    /// the digests are enforced, the lists of the manifest for its layer,
    /// strictly: an image that has none of them, that cannot be measured, or
    /// that has no list is refused, and the overlay has `verity=require` so
    /// that the kernel checks the digest of every file it opens.  An image
    /// that is not the one named is refused, not mounted (an image without
    /// fs-verity, on a file system without it, passes unmeasured when the
    /// digests are not enforced).  The answer of an enforced mount says what
    /// the driver measured (`Rootfs::measured`).  A kernel mount that fails
    /// after these checks is not tried again: the image server serves the
    /// layers (a root engine's fallback), and a server that cannot start or
    /// answer is an error with its reason.
    fn mount(&self, req: &MountRequest<'_>) -> DriverResult<Rootfs> {
        let prepared = self.mount_plan(req, true)?;
        let (lists, chain) = match req.verity {
            // (the engine enforces the digests where the store says so: a
            // start that does not would mount images measured against
            // nothing of the manifest)
            VerityAsk::Off if self.options.digests == ComposefsDigests::Require => {
                return Err(DriverError::of(
                    NAME,
                    DriverErrorKind::DigestEnforced,
                    format!(
                        "image {}: [storage] composefs_digests is \"require\" and the start gave no digests of the manifest to measure its layers against",
                        req.image.id
                    ),
                ))
            }
            VerityAsk::Off => (None, None),
            VerityAsk::Enforce { accepted, chain } if accepted.len() == req.layers.len() => {
                (Some(accepted), chain)
            }
            VerityAsk::Enforce { accepted, .. } => {
                return Err(DriverError::storage(
                    NAME,
                    format!(
                        "image {}: {} lists of digests for its {} layers",
                        req.image.id,
                        accepted.len(),
                        req.layers.len()
                    ),
                ))
            }
        };
        // (the descriptors of the layers: the limit is raised before the first
        // is opened, or the mount is refused with nothing opened)
        let needed = velarx_base::hardening::open_files_needed(req.layers.len());
        velarx_base::hardening::ensure_open_files(needed)
            .map_err(|_| no_open_files(&req.image.id, needed))?;
        let blobs = req.image.layer_blobs();
        // (the top layer first, as the overlay lists them)
        let measured = prepared
            .m
            .layers
            .iter()
            .zip(req.layers)
            .enumerate()
            .rev()
            .map(|(i, (l, record))| {
                let enforced = lists.map(|lists| Enforced {
                    accepted: &lists[i],
                    chain,
                    layer: i + 1,
                });
                self.measured_image(&req.image.id, needed, l, record, enforced)
            })
            .collect::<DriverResult<Vec<_>>>()?;
        let (images, digests): (Vec<_>, Vec<_>) = measured.into_iter().unzip();
        let what = match req.purpose {
            Purpose::Root => "root file system".to_string(),
            Purpose::Volume { index } => format!("image mount {index}"),
        };
        let kernel = match prepared.kernel {
            true => match self.kernel_mount(req, &prepared, &images) {
                Ok(fd) => Some(fd),
                // (the image server holds as many descriptors again: no
                // other way to mount it)
                Err(e) if velarx_runtime::imagemount::out_of_descriptors(&e) => {
                    return Err(no_open_files(&req.image.id, needed))
                }
                Err(e) => {
                    info!(
                        "Image {}: the kernel mount of the {what} failed, the image server serves it: {e}",
                        req.image.id
                    );
                    None
                }
            },
            false => None,
        };
        let (fd, server) = match kernel {
            Some(fd) => (fd, None),
            None => {
                let s = self.serve_mount(req, &prepared, &images).map_err(|e| {
                    if e.out_of_descriptors {
                        return no_open_files(&req.image.id, needed);
                    }
                    DriverError::storage(
                        NAME,
                        format!(
                            "image {}: the image server cannot serve the {what}: {}",
                            req.image.id, e.message
                        ),
                    )
                })?;
                (s.overlay, Some((s.server, s.lowest_stubs)))
            }
        };
        // the links of the layers, once the mount they are for is made (a
        // kernel mount that failed was made by the image server from the images
        // measured here, not measured again)
        if let Some(chain) = chain {
            let n = req.layers.len();
            for (k, got) in digests.iter().enumerate() {
                let i = n - 1 - k;
                // (a layer the manifest names by a blob: the one of its
                // descriptor; else the layer's own key)
                let blob = blobs
                    .get(i)
                    .map_or_else(|| req.layers[i].key.to_string(), Clone::clone);
                chain.layer_measured(i + 1, &blob, got.as_deref().unwrap_or_default());
            }
            if server.as_ref().is_some_and(|(_, lowest)| *lowest) && n > 1 {
                chain.files_by_fuse(n);
            }
        }
        let measured = lists.map(|_| digests.into_iter().rev().flatten().collect());
        let mut r = Self::rootfs_of(Self::asked(req), Some(fd), measured);
        if let Some((pidfd, lowest)) = server {
            // (the overlay checks the digests of the files it opens from the
            // objects; the files of the layers above the lowest that the
            // kernel does not follow are opened, and checked, by the server)
            if r.verity != VerityDone::None && lowest && req.layers.len() > 1 {
                r.verity = VerityDone::OnOpen;
            }
            r.server = Some(pidfd);
        }
        Ok(r)
    }

    /// The EROFS image `l` of the layer `record`, opened as a name that is no
    /// link and measured on that descriptor (`mount`), with the digest it
    /// measured: against the lists of the manifest strictly when the digests
    /// are enforced (`enforced`; the link of the layer, or the one that broke,
    /// is said on the chain of trust), else against the digest the engine
    /// recorded for it.
    fn measured_image(
        &self,
        image_id: &str,
        needed: u64,
        l: &LayerFiles,
        record: &LayerRecord,
        enforced: Option<Enforced<'_>>,
    ) -> DriverResult<(std::fs::File, Option<String>)> {
        let recorded;
        let (accepted, strict) = match &enforced {
            Some(e) => (e.accepted, true),
            None => {
                recorded = [record
                    .erofs
                    .clone()
                    .ok_or_else(|| missing_image(image_id, &record.key, "is not recorded"))?];
                (&recorded[..], false)
            }
        };
        let broken = |file: Option<&std::fs::File>| {
            if let Some(Enforced {
                chain: Some(chain),
                layer,
                ..
            }) = &enforced
            {
                chain.layer_broken(*layer, accepted, || file.and_then(cfs::layer_image_digest));
            }
        };
        // (no descriptor or memory left is not the image's fault: the layer
        // is neither broken on the chain of trust nor to repair)
        let exhausted = |e: &std::io::Error| {
            velarx_runtime::imagemount::out_of_descriptors(e)
                || velarx_runtime::imagemount::out_of_system_files(e)
        };
        let failed = |e: std::io::Error| {
            if velarx_runtime::imagemount::out_of_descriptors(&e) {
                return no_open_files(image_id, needed);
            }
            if velarx_runtime::imagemount::out_of_system_files(&e) {
                return DriverError::storage(
                    NAME,
                    format!("image {image_id}: layer {}: {e}", record.key),
                );
            }
            if e.kind() == std::io::ErrorKind::NotFound {
                return missing_image(image_id, &record.key, "is not there");
            }
            if cfs::is_layer_busy(&e) {
                return DriverError::of(NAME, DriverErrorKind::Busy, e.to_string());
            }
            DriverError::corrupt(
                NAME,
                format!("image {image_id}: layer {}: {e}", record.key),
                Remedy::Repair,
            )
        };
        let file = cfs::open_layer_image(&l.image).map_err(|e| {
            if !exhausted(&e) {
                broken(None);
            }
            failed(e)
        })?;
        let got = cfs::measure_layer_image(&file, &l.image, accepted, strict).map_err(|e| {
            if !exhausted(&e) {
                broken(Some(&file));
            }
            failed(e)
        })?;
        Ok((file, got))
    }

    /// The kernel mounts of `m` from the measured `images` (the top layer
    /// first): the EROFS images, the objects, the mapping on all for a
    /// container with a user namespace, and the overlay over them, read only
    /// for an image mount and with the container's upper layer for a root.
    fn kernel_mount(
        &self,
        req: &MountRequest<'_>,
        p: &Prepared,
        images: &[std::fs::File],
    ) -> std::io::Result<std::os::fd::OwnedFd> {
        let m = &p.m;
        use velarx_runtime::imagemount::{
            mount_erofs, mtab_link, readonly_overlay, writable_overlay, ErofsSource, Parts,
            RootOverlay,
        };
        let source = if self.options.kernel_lock {
            ErofsSource::Descriptor
        } else {
            ErofsSource::ProcPath
        };
        let metas = images
            .iter()
            .map(|image| mount_erofs(image, source, self.options.superblock_share))
            .collect::<std::io::Result<Vec<_>>>()?;
        let data = std::iter::once(&m.objects)
            .chain(&m.more_objects)
            .map(|dir| open_dir(dir))
            .collect::<std::io::Result<Vec<_>>>()?;
        let mut parts = Parts::new(metas, data);
        if p.idmapped {
            let t = req
                .mapping
                .ok_or_else(|| std::io::Error::other("an idmapped image without a mapping"))?;
            parts.idmapped(t)?;
        }
        let (lowers, datas) = (parts.meta_paths(), parts.data_paths());
        match req.purpose {
            Purpose::Volume { .. } => readonly_overlay(
                &lowers,
                &datas,
                &m.verity,
                false,
                velarx_fuse::erofs_tree::Stubs::Every,
                req.label,
            ),
            Purpose::Root => {
                let paths = self.writable_paths(req.container);
                let work = paths.work.as_deref().ok_or_else(|| {
                    std::io::Error::other("the writable layer has no work directory")
                })?;
                let fd = writable_overlay(&RootOverlay {
                    lowers: &lowers,
                    datas: &datas,
                    upper: &paths.upper,
                    work,
                    verity: Some(&m.verity),
                    userxattr: false,
                    volatile: req.volatile,
                    stubs: velarx_fuse::erofs_tree::Stubs::Every,
                    label: req.label,
                })?;
                use std::os::fd::AsFd;
                mtab_link(fd.as_fd()).map_err(|e| {
                    std::io::Error::other(format!("creating /etc/mtab failed: {e}"))
                })?;
                Ok(fd)
            }
        }
    }

    /// The image server's mount of `req`, started with the measured `images`
    /// (the top layer first), the directories of the objects and what the
    /// FUSE file system needs: the overlay and the server's pidfd.
    fn serve_mount(
        &self,
        req: &MountRequest<'_>,
        p: &Prepared,
        images: &[std::fs::File],
    ) -> Result<velarx_runtime::imageserver::Served, ServeFailure> {
        use std::os::fd::AsFd;
        use velarx_runtime::imageserver::{self, RootSpec};
        let server = &self.options.server;
        let translate = req
            .translate
            .ok_or("the request does not say how the owners are shown")?;
        let m = &p.m;
        // the data-only layers: the objects of the stores, and for an image
        // that is being pulled the staging directories of its layers, in
        // the order of the layers
        let files: Vec<PathBuf> = match &m.staging {
            Some(dir) => {
                let area = velarx_content::pull::staged::Staging::new(dir);
                m.layers
                    .iter()
                    .filter_map(|l| LayerKey::parse(&l.layer))
                    .map(|k| area.layer_files(&k))
                    .collect()
            }
            None => Vec::new(),
        };
        for f in &files {
            std::fs::create_dir_all(f).map_err(|e| format!("{}: {e}", f.display()))?;
        }
        let data = std::iter::once(&m.objects)
            .chain(&m.more_objects)
            .chain(&files)
            .map(|dir| open_dir(dir))
            .collect::<std::io::Result<Vec<_>>>()
            .map_err(ServeFailure::of_io)?;
        let (lazy, lazy_fds) = match m.complete {
            true => (None, LazyFds::default()),
            false => {
                let (spec, fds) = self.lazy_spec(server, m)?;
                (Some(spec), fds)
            }
        };
        let root = match req.purpose {
            Purpose::Volume { .. } => None,
            Purpose::Root => {
                let paths = self.writable_paths(req.container);
                Some(RootSpec {
                    upper: paths.upper,
                    work: paths
                        .work
                        .ok_or("the writable layer has no work directory")?,
                    volatile: req.volatile,
                })
            }
        };
        let id = req.container.id();
        let request = imageserver::Request {
            name: format!(
                "{} {}",
                &id[..id.len().min(12)],
                match req.purpose {
                    Purpose::Root => "root".to_string(),
                    Purpose::Volume { index } => format!("mount {index}"),
                }
            ),
            layers: m.layers.iter().map(|l| l.layer.clone()).collect(),
            datas: data.len(),
            owners: m.owners.clone(),
            store: self.store.root().to_path_buf(),
            more_stores: self.store.additional().to_vec(),
            translate: translate.clone(),
            userxattr: velarx_base::ids::in_user_namespace().map_err(|e| e.to_string())?,
            verity: m.verity.clone(),
            enforce: req.verity.enforced(),
            run_root: server.run_root.clone(),
            label: req.label.map(str::to_string),
            root,
            lazy,
            debug: tracing::enabled!(tracing::Level::DEBUG),
        };
        // (the server takes the lowest layer first)
        let lowest_first: Vec<_> = images.iter().rev().map(|f| f.as_fd()).collect();
        let rest: Vec<_> = data
            .iter()
            .map(|d| d.as_fd())
            .chain(lazy_fds.indexes.iter().map(|f| f.as_fd()))
            .chain(lazy_fds.profile_dir.iter().map(|f| f.as_fd()))
            .collect();
        let log = req.container.bundle().join(imageserver::LOG_FILE);
        imageserver::start(&server.program, &request, &lowest_first, &rest, &log)
            .map_err(|e| e.to_string().into())
    }

    /// What the image server asks for the files of an image that is being
    /// pulled with: the staging area, the socket of the engine that holds
    /// the pull and its token, and the descriptors of the indexes of the
    /// layers and of the directory of the startup profile, which the server
    /// holds for as long as the container runs.
    fn lazy_spec(
        &self,
        server: &ImageServer,
        m: &Layout,
    ) -> Result<(velarx_runtime::imageserver::LazySpec, LazyFds), ServeFailure> {
        let staging = m
            .staging
            .clone()
            .ok_or("an image that is being pulled has no staging area")?;
        let config = &server.config;
        // (opened as names that are no link, as the images are)
        let indexes = m
            .layers
            .iter()
            .map(|l| cfs::open_layer_image(&l.index))
            .collect::<std::io::Result<Vec<_>>>()
            .map_err(|e| ServeFailure::of_io_in("the index of a layer", e))?;
        let profile = match config.pull.lazy_profile_secs {
            0 => None,
            _ => m
                .profile
                .parent()
                .zip(m.profile.file_name().and_then(|n| n.to_str()))
                .map(|(dir, name)| {
                    Ok::<_, ServeFailure>((
                        open_dir(dir).map_err(ServeFailure::of_io)?,
                        name.to_string(),
                    ))
                })
                .transpose()?,
        };
        let token = self
            .staging()
            .token(&m.image_id)
            .map_err(|e| format!("the token of the pull of {}: {e}", m.image_id))?;
        let spec = velarx_runtime::imageserver::LazySpec {
            image_id: m.image_id.clone(),
            staging,
            pull: config.pull.clone(),
            fsverity: (config.storage.fsverity, config.storage.fsverity_require),
            proxy: velarx_content::imagefetch::socket(&config.services_dir()),
            token,
            profile: profile.as_ref().map(|(_, name)| name.clone()),
        };
        let fds = LazyFds {
            indexes: indexes.into_iter().map(Into::into).collect(),
            profile_dir: profile.map(|(dir, _)| dir),
        };
        Ok((spec, fds))
    }

    /// The images of the layers made from their tables of contents.
    async fn make_images(
        &self,
        layers: Vec<(LayerKey, Toc)>,
    ) -> DriverResult<HashMap<LayerKey, LayerArtifact>> {
        let store = self.store.clone();
        tokio::task::spawn_blocking(move || Self::make_images_blocking(layers, &store))
            .await
            .map_err(join_error)?
            .map_err(storage_error)
    }

    fn make_images_blocking(
        layers: Vec<(LayerKey, Toc)>,
        store: &FileStore,
    ) -> std::io::Result<HashMap<LayerKey, LayerArtifact>> {
        let refs: Vec<(LayerKey, &Toc)> = layers.iter().map(|(d, t)| (*d, t)).collect();
        make_layer_images(&refs, store)
    }
}

#[async_trait]
impl StorageDriver for ComposefsDriver {
    fn name(&self) -> &str {
        NAME
    }

    fn graph_name(&self) -> &str {
        "overlay"
    }

    fn capabilities(&self) -> &Capabilities {
        &CAPABILITIES
    }

    fn graph_data(&self, w: &Writable) -> Vec<(String, String)> {
        let paths = self.writable_paths(w);
        [
            ("UpperDir", Some(paths.upper)),
            ("WorkDir", paths.work),
            ("MergedDir", Some(paths.merged)),
        ]
        .into_iter()
        .filter_map(|(k, p)| Some((k.to_string(), p?.to_string_lossy().into_owned())))
        .collect()
    }

    fn status(&self) -> Vec<(String, String)> {
        let how = |r: &Result<(), String>| match r {
            Ok(()) => "yes".to_string(),
            Err(why) => format!("no ({why})"),
        };
        vec![
            ("composefs".into(), how(&self.options.enabled)),
            ("kernel mount".into(), how(&self.options.kernel_mount)),
            (
                "composefs digests".into(),
                format!("{:?}", self.options.digests).to_lowercase(),
            ),
            (
                "kernel mount lock".into(),
                if self.options.kernel_lock {
                    "yes"
                } else {
                    "no"
                }
                .into(),
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
        let (store, area) = (self.store.clone(), self.staging());
        // (what the engine made in `settled` is what is written: the images
        // are built once, by the engine, for every layer it pulled; they are
        // written between the link of the files and the barrier of the
        // store, which makes them durable: no barrier of their own)
        let write: feed::Written<HashMap<LayerKey, LayerArtifact>> =
            Box::new(move |pulled, settlement| {
                let staged: std::collections::HashSet<LayerKey> =
                    pulled.iter().filter(|l| l.lazy).map(|l| l.key).collect();
                let ids = &mut settlement.identities;
                if let Some(l) = pulled
                    .iter()
                    .map(|l| l.key)
                    .find(|l| !ids.images.contains_key(l))
                {
                    return Err(DriverError::storage(
                        NAME,
                        format!("the engine made no image for layer {l}"),
                    ));
                }
                let mut built = Built(Vec::new());
                for (key, image) in std::mem::take(&mut ids.images) {
                    let erofs = ids
                        .artifacts
                        .get(&key)
                        .map(|a| a.image_digest.clone())
                        .ok_or_else(|| {
                            DriverError::storage(
                                NAME,
                                format!("no identity was made for layer {key}"),
                            )
                        })?;
                    built.0.push((key, image, erofs));
                }
                // the images of the layers of a lazy pull wait in the staging
                // area (not synced: the layer is in progress), the others are
                // the store's
                let (apart, own) = built.split(&staged);
                let wrote = !own.0.is_empty();
                let mut made =
                    write_layer_images_in(own, store.root(), Durable::before_barrier(&store))
                        .map_err(storage_error)?;
                if !staged.is_empty() {
                    area.create().map_err(storage_error)?;
                    let stand_in = FileStore::new(area.objects_stand_in())
                        .map_err(|e| DriverError::storage(NAME, e.to_string()))?
                        .with_sync(velarx_base::sync::SyncMode::None);
                    made.extend(
                        write_layer_images_in(apart, stand_in.root(), Durable::new(&stand_in))
                            .map_err(storage_error)?,
                    );
                }
                Ok((made, wrote))
            });
        let (pulled, settlement, artifacts) =
            feed::pull_in_process(&parts, feed, layers, settled, write).await?;
        Ok(Pulled {
            layers: pulled,
            artifacts,
            verdict: settlement.verdict,
        })
    }

    async fn has_layers(&self, layers: &[LayerRef]) -> DriverResult<Vec<bool>> {
        objects::has_layers(NAME, &self.db, layers).await
    }

    async fn repair(&self, layers: &[LayerRef]) -> DriverResult<HashMap<LayerKey, LayerArtifact>> {
        let tocs = objects::tocs_of(NAME, &self.db, layers).await?;
        self.make_images(tocs).await
    }

    async fn remake_staged(&self, id: &str) -> DriverResult<()> {
        let area = self.staging();
        let refused = |e: ImageError| DriverError::refused(NAME, e);
        let pull = area
            .pull(id)
            .map_err(|e| refused(e.into()))?
            .ok_or_else(|| {
                DriverError::of(NAME, DriverErrorKind::NotFound, format!("the pull {id}"))
            })?;
        let mut tocs = Vec::new();
        let mut recorded = HashMap::new();
        for key in &pull.layers {
            let key = LayerKey::parse(key).ok_or_else(|| {
                DriverError::of(
                    NAME,
                    DriverErrorKind::Storage,
                    format!("{key:?} is no layer key"),
                )
            })?;
            if let Some(layer) = area.layer(&key).map_err(|e| refused(e.into()))? {
                let text = layer.toc_text().map_err(|e| refused(e.into()))?;
                tocs.push((
                    key,
                    serde_json::from_str::<Toc>(&text).map_err(|e| refused(e.into()))?,
                ));
                recorded.insert(key, layer.meta.erofs.clone());
            }
        }
        tokio::task::spawn_blocking(move || {
            let refs: Vec<(LayerKey, &Toc)> = tocs.iter().map(|(d, t)| (*d, t)).collect();
            let built = build_layer_images(&refs).map_err(storage_error)?;
            for (key, digest) in built.digests() {
                if recorded.get(&key) != Some(&digest) {
                    return Err(DriverError::of(
                        NAME,
                        DriverErrorKind::Contradicted,
                        format!("the EROFS image of layer {key} is not the one the pull recorded"),
                    ));
                }
            }
            area.create().map_err(storage_error)?;
            let stand_in = FileStore::new(area.objects_stand_in())
                .map_err(|e| DriverError::storage(NAME, e.to_string()))?
                .with_sync(velarx_base::sync::SyncMode::None);
            write_layer_images_in(built, stand_in.root(), Durable::new(&stand_in))
                .map_err(storage_error)?;
            Ok(())
        })
        .await
        .map_err(join_error)?
    }

    fn read_objects(&self, ranges: &[ObjectRange], sink: &mut dyn ObjectSink) -> DriverResult<()> {
        objects::read_objects(NAME, &self.store, ranges, sink)
    }

    fn open_object(&self, key: &str, size: u64) -> DriverResult<std::fs::File> {
        objects::open_object(NAME, &self.store, key, size)
    }

    fn remove_image(&self, image_id: &str) -> DriverResult<()> {
        let p = cfs::profile_path(self.store.root(), image_id);
        match std::fs::remove_file(&p) {
            Ok(()) => {
                debug!("Removed {}", p.display());
                Ok(())
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(DriverError::io(
                NAME,
                std::io::Error::new(e.kind(), format!("remove {}: {e}", p.display())),
            )),
        }
    }

    /// Nothing is made for the container: the mount is made of the layers at
    /// each start ([`StorageDriver::mounts`]), which also checks them; the
    /// plan is what it will be.
    fn image_volume_create(&self, req: &MountRequest<'_>) -> DriverResult<Planned> {
        match req.purpose {
            Purpose::Volume { .. } => Ok(self.plan(req)?.planned()),
            Purpose::Root => Err(DriverError::storage(
                NAME,
                "an image volume is asked for a root file system",
            )),
        }
    }

    fn mounts(&self, req: &MountsRequest<'_>) -> DriverResult<Mounts> {
        Ok(Mounts {
            root: req.root.as_ref().map(|m| self.mount(m)).transpose()?,
            volumes: req
                .volumes
                .iter()
                .map(|m| self.mount(m))
                .collect::<DriverResult<_>>()?,
        })
    }

    fn image_view(
        &self,
        image_id: &str,
        layers: &[LayerRecord],
    ) -> DriverResult<Arc<dyn ImageTree>> {
        let paths: Vec<PathBuf> = self
            .layer_images(image_id, layers)?
            .into_iter()
            .map(|(image, _)| image)
            .collect();
        let view = ImageView::open(&paths).map_err(|e| {
            DriverError::corrupt(
                NAME,
                format!("the EROFS images of the layers cannot be read: {e}"),
                Remedy::Repair,
            )
        })?;
        Ok(Arc::new(view))
    }

    async fn leftovers(&self, grace: Duration) -> DriverResult<Vec<(PathBuf, String)>> {
        let objects = self.store.root().to_path_buf();
        let composefs = objects.parent().unwrap_or(&objects).join(cfs::DIR);
        tokio::task::spawn_blocking(move || stray_images(&composefs, grace))
            .await
            .map_err(|e| DriverError::storage(NAME, e.to_string()))
    }

    async fn check(
        &self,
        image: &ImageRecord,
        layers: &[LayerRecord],
        full: bool,
    ) -> DriverResult<Vec<Problem>> {
        let mut tocs = Vec::with_capacity(layers.len());
        for l in layers {
            tocs.push(
                l.toc
                    .as_deref()
                    .and_then(|t| serde_json::from_str::<Toc>(t).ok()),
            );
        }
        let mut dirs = self.objects_dirs();
        // (the images of the layers of a pull in progress are in the
        // staging area)
        dirs.push(self.staging().objects_stand_in());
        let self_dirs = dirs.clone();
        let recorded_erofs: Vec<Option<String>> = layers.iter().map(|l| l.erofs.clone()).collect();
        let recorded_algs: Vec<Algorithm> = layers.iter().map(|l| l.key.digest().alg()).collect();
        let keys: Vec<LayerKey> = layers.iter().map(|l| l.key).collect();
        let layers: Vec<(String, Option<String>)> = layers
            .iter()
            .map(|l| (l.key.file_stem(), l.erofs.clone()))
            .collect();
        // the digests the manifest states for the layers, against the
        // images the records have (lazy or not: the image needs no file)
        let mut stated = Vec::new();
        if let Ok(m) = serde_json::from_str::<OciManifest>(&image.manifest) {
            let dirs: Vec<&Path> = self_dirs.iter().map(PathBuf::as_path).collect();
            let total = m.layers.len();
            for ((i, d), (stem, _)) in m.layers.iter().enumerate().zip(&layers) {
                let path = cfs::find_layer_image(&dirs, stem)
                    .map(|(p, _)| p)
                    .unwrap_or_else(|| cfs::layer_image_path(&self_dirs[0], stem));
                let recorded = recorded_erofs.get(i).cloned().flatten();
                let found = match seal::layer_digests(d) {
                    None if self.options.digests == ComposefsDigests::Require => Some((
                        ProblemKind::AnnotationMissing,
                        format!(
                            "layer {} of {total} ({}) states no EROFS digest of ours ({}), and [storage] composefs_digests is \"require\"",
                            i + 1,
                            d.digest,
                            seal::LAYER_EROFS_ANNOTATION
                        ),
                    )),
                    // (a list with none of ours is another writer's: it is
                    // a problem only where the digests are required)
                    Some(list) => match recorded {
                        Some(r)
                            if !list.iter().any(|d| d.plain() == r)
                                && self.options.digests == ComposefsDigests::Require =>
                        {
                            Some((
                                ProblemKind::AnnotationMismatch,
                                format!(
                                    "layer {} of {total} ({}): its EROFS image has the fs-verity digest {r}, the manifest says {} ({})",
                                    i + 1,
                                    d.digest,
                                    list.iter().map(Digest::plain).collect::<Vec<_>>().join(", "),
                                    seal::LAYER_EROFS_ANNOTATION
                                ),
                            ))
                        }
                        _ => None,
                    },
                    None => None,
                };
                if let Some((kind, message)) = found {
                    stated.push(Problem {
                        repair: false,
                        ..problem(kind, &path, message)
                    });
                }
            }
        }
        let sealed = serde_json::from_str::<OciManifest>(&image.manifest)
            .ok()
            .and_then(|m| seal::expected(&m).ok())
            .and_then(|stated| {
                // (the digest of the algorithm of the layers, as the pull
                // checked it; a mixed image has none to check)
                stated
                    .into_iter()
                    .find(|(a, _)| recorded_algs.iter().all(|r| r == a))
            });
        let store = self.store.clone();
        tokio::task::spawn_blocking(move || {
            let mut found = Vec::new();
            let refs: Vec<&Path> = dirs.iter().map(PathBuf::as_path).collect();
            for (((stem, recorded), toc), key) in layers.iter().zip(&tocs).zip(&keys) {
                let path = cfs::find_layer_image(&refs, stem)
                    .map(|(p, _)| p)
                    .unwrap_or_else(|| cfs::layer_image_path(&dirs[0], stem));
                found.extend(
                    layer_problems(&path, recorded.as_deref(), toc.as_ref(), full)
                        .into_iter()
                        .map(|p| Problem {
                            layer: Some(*key),
                            ..p
                        }),
                );
            }
            if let (Some((alg, want)), true) = (&sealed, full) {
                let all: Option<Vec<&Toc>> = tocs.iter().map(Option::as_ref).collect();
                if let Some(all) = all {
                    if let Ok((_, id)) = velarx_fuse::canonical::image_of_store(*alg, &all, &store) {
                        if id != *want {
                            found.push(problem(
                                ProblemKind::ArtifactSealMismatch,
                                store.root(),
                                format!("the merged EROFS of the layers has the digest {id}, the manifest says {want}"),
                            ));
                        }
                    }
                }
            }
            found.extend(stated);
            found
        })
        .await
        .map_err(join_error)
    }

    /// The layers whose image is locked: mounted by a kernel that holds the
    /// lock (`kernel_lock`), or served by an image server.  A kernel that
    /// holds none mounts the image by the name of its descriptor (nothing to
    /// ask): those mounts are not found here, the rows of their containers
    /// keep their layers.
    fn lock_unused_layers(&self, layers: &[LayerKey]) -> DriverResult<UnusedLayers> {
        let objects = self.store.root();
        let mut out = UnusedLayers::default();
        for key in layers {
            let image = cfs::layer_image_path(objects, &key.file_stem());
            match cfs::lock_unused_layer_image(&image).map_err(|e| DriverError::io(NAME, e))? {
                cfs::LayerUse::InUse => {
                    debug!("composefs: the layer {key} is in use: its image is locked");
                    out.in_use.insert(*key);
                }
                cfs::LayerUse::Unused(Some(file)) => out.hold.push(Box::new(file)),
                cfs::LayerUse::Unused(None) => {}
            }
        }
        Ok(out)
    }

    fn collect(&self, keep: &Keep) -> DriverResult<Collected> {
        let objects = self.store.root();
        let dir = objects.parent().unwrap_or(objects).join(cfs::DIR);
        let mut known: std::collections::HashSet<std::ffi::OsString> = Default::default();
        for key in &keep.layers {
            for p in [
                cfs::layer_image_path(objects, &key.file_stem()),
                cfs::layer_index_path(objects, &key.file_stem()),
            ] {
                known.extend(p.file_name().map(|n| n.to_os_string()));
            }
        }
        // (what this driver holds per image is a startup profile; a pull in
        // progress has one too.  Its other state is the writable layers of the
        // containers, which are in their bundles and never collected here:
        // `keep.containers` has nothing more to add)
        for id in keep.images.iter().chain(&keep.pulls) {
            let p = cfs::profile_path(objects, id);
            known.extend(p.file_name().map(|n| n.to_os_string()));
        }
        Ok(sweep(
            &dir,
            |name| known.contains(name),
            "composefs image",
            // a writer in progress has a temporary file (it holds its lock)
            |path, out| match velarx_storage::remove_abandoned(path) {
                Ok(Some(size)) => {
                    debug!("Removed the temporary file {}", path.display());
                    out.bytes_freed += size;
                }
                Ok(None) => {}
                Err(err) => out
                    .errors
                    .push(format!("Failed to remove {}: {err}", path.display())),
            },
        ))
    }

    // the writable layer: the overlay of the bundle

    fn writable_create(
        &self,
        w: &Writable,
        owner: Option<(u32, u32)>,
        opts: &WritableOptions,
        base: Option<&MountRequest<'_>>,
    ) -> DriverResult<Option<Planned>> {
        if opts.size_limit.is_some() {
            return Err(DriverError::of(
                NAME,
                DriverErrorKind::Unsupported,
                "the composefs driver has no size limit for the writable layer of a container",
            ));
        }
        let p = self.writable_paths(w);
        let make = || -> std::io::Result<()> {
            std::fs::create_dir_all(&p.upper)?;
            if let Some(work) = &p.work {
                std::fs::create_dir_all(work)?;
            }
            if let Some((uid, gid)) = owner {
                // The root of the merged tree is the root of the upper
                // directory: the root of the container must own it.
                std::os::unix::fs::chown(&p.upper, Some(uid), Some(gid))?;
            }
            Ok(())
        };
        make().map_err(|e| DriverError::io(NAME, e))?;
        let Some(b) = base else {
            return Ok(None);
        };
        let prepared = self.mount_plan(b, false)?;
        // (the root of the merged tree is the root of the upper directory,
        // which the overlay shows in place of the root of the layers: it
        // is the root of the top layer, or a plain one when it has none)
        if let Some(top) = prepared.m.layers.last() {
            let root_of_top = || -> std::io::Result<()> {
                let layer = velarx_fuse::erofs_tree::Layer::of_checked_file(
                    cfs::open_layer_image(&top.image)?,
                    &top.image,
                )?;
                set_root(&p.upper, &layer, b.translate)
            };
            root_of_top().map_err(|e| DriverError::io(NAME, e))?;
        }
        Ok(Some(Self::rootfs_of(Self::asked(b), None, None).planned()))
    }

    fn writable_paths(&self, w: &Writable) -> WritablePaths {
        let overlay = w.bundle().join(OVERLAY_DIR);
        WritablePaths {
            upper: overlay.join("upper"),
            work: Some(overlay.join("work")),
            merged: w.bundle().join("rootfs"),
        }
    }

    /// The upper directory, opened without following a link at its end.
    fn writable_root(&self, w: &Writable) -> DriverResult<std::os::fd::OwnedFd> {
        let upper = self.writable_paths(w).upper;
        open_dir(&upper).map_err(|e| {
            DriverError::io(
                NAME,
                std::io::Error::new(
                    e.kind(),
                    format!(
                        "open the root of the writable layer {}: {e}",
                        upper.display()
                    ),
                ),
            )
        })
    }

    fn writable_size(&self, w: &Writable) -> DriverResult<u64> {
        Ok(velarx_graph::directory::tree_size(
            &self.writable_paths(w).upper,
        ))
    }

    fn writable_remove(&self, w: &Writable) -> DriverResult<()> {
        match velarx_base::tree::remove_dir_all_confined(w.bundle().join(OVERLAY_DIR)) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(DriverError::io(NAME, e)),
            _ => Ok(()),
        }
    }

    fn writable_exists(&self, w: &Writable) -> DriverResult<bool> {
        Ok(self.writable_paths(w).upper.is_dir())
    }

    /// The upper directory read with the overlay's meaning: whiteouts,
    /// opaque directories, and (`metacopy`, `redirect`) what the image below
    /// says (`dirtar`).
    fn diff(
        &self,
        w: &Writable,
        lower: Option<Arc<dyn ImageTree>>,
        opts: &DiffOptions,
        out: &mut dyn HoleWrite,
    ) -> DriverResult<()> {
        let upper = self.writable_paths(w).upper;
        let fd = open_dir(&upper).map_err(|e| {
            DriverError::io(
                NAME,
                std::io::Error::new(e.kind(), format!("open {}: {e}", upper.display())),
            )
        })?;
        let walk = opts.walk(self.lower(lower));
        dirtar::write(rustix::fd::AsFd::as_fd(&fd), &walk, out)
            .map_err(|e| DriverError::io(NAME, e))
    }

    fn changes(
        &self,
        w: &Writable,
        lower: Option<Arc<dyn ImageTree>>,
        opts: &DiffOptions,
    ) -> DriverResult<Vec<(String, Change)>> {
        let fd = self.writable_root(w)?;
        let walk = opts.walk(self.lower(lower));
        dirtar::changes(rustix::fd::AsFd::as_fd(&fd), &walk).map_err(|e| DriverError::io(NAME, e))
    }

    /// Written into the upper directory as the overlay keeps a layer's
    /// whiteouts (`overlay_upper`).
    fn apply(
        &self,
        w: &Writable,
        opts: &DiffOptions,
        tar: &mut dyn std::io::Read,
    ) -> DriverResult<()> {
        // an owner the container does not map is the container's root,
        // not the host's
        let (maps, root) = (opts.id_maps(), opts.root_owner());
        let fd = self.writable_root(w)?;
        let ex = velarx_wire::cp::ExtractOptions {
            archive_owners: Some(maps),
            owner: Some(root),
            overlay_upper: true,
            layer: true,
            ..Default::default()
        };
        velarx_wire::cp::extract(tar, rustix::fd::AsFd::as_fd(&fd), &ex)
            .map_err(|e| DriverError::io(NAME, e))
    }

    fn stopped_view<'a>(
        &self,
        w: &Writable,
        image: TreeSource<'a>,
    ) -> DriverResult<StoppedView<'a>> {
        let upper = rustix::fs::openat(
            rustix::fs::CWD,
            self.writable_paths(w).upper,
            rustix::fs::OFlags::PATH | rustix::fs::OFlags::DIRECTORY | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .map_err(|e| DriverError::io(NAME, e.into()))?;
        Ok(StoppedView::overlay(upper, image))
    }

    /// The mount table of the process says it (`root_is_overlay_of`).
    fn is_root_of(&self, w: &Writable, proc_dir: &Path) -> DriverResult<bool> {
        let mountinfo = std::fs::read_to_string(proc_dir.join("mountinfo"))
            .map_err(|e| DriverError::io(NAME, e))?;
        Ok(root_is_overlay_of(
            &mountinfo,
            &self.writable_paths(w).upper,
        ))
    }

    fn usage(&self) -> DriverResult<Usage> {
        let objects = self.store.root();
        Ok(Usage {
            artifacts: objects::files_usage(&objects.parent().unwrap_or(objects).join(cfs::DIR)),
        })
    }
}

/// The image of composefs-rs of the layers `tocs`, whose files are where
/// `objects` says (by their fs-verity digest), and its id.
pub(crate) fn canonical_image_of(
    alg: Algorithm,
    tocs: &[&velarx_storage::Toc],
    objects: &dyn Fn(&str) -> Option<std::path::PathBuf>,
) -> std::io::Result<(Box<[u8]>, String)> {
    velarx_fuse::canonical::image_of(alg, tocs, objects)
}

/// Give the directory `upper` the mode, owner, time and attributes of the
/// root of `layer`, the owner as the container sees it (`ids`).
fn set_root(
    upper: &Path,
    layer: &velarx_fuse::erofs_tree::Layer,
    ids: Option<&velarx_fuse::IdTranslate>,
) -> std::io::Result<()> {
    use rustix::fs::{fchmod, fchown, fsetxattr, futimens, Gid, Mode, Timestamps, Uid, XattrFlags};
    let root = layer.root();
    let a = layer
        .attr(root)
        .ok_or_else(|| std::io::Error::other("the layer has no root directory"))?;
    let dir = open_dir(upper)?;
    let (uid, gid) = ids.map_or((a.uid, a.gid), |t| (t.uid_of(a.uid), t.gid_of(a.gid)));
    let context = |what: &str, e: rustix::io::Errno| {
        std::io::Error::new(
            e.kind(),
            format!("the {what} of the root of the container cannot be set ({e})"),
        )
    };
    fchown(&dir, Some(Uid::from_raw(uid)), Some(Gid::from_raw(gid)))
        .map_err(|e| context("owner", e))?;
    fchmod(&dir, Mode::from_raw_mode(a.perm.into())).map_err(|e| context("mode", e))?;
    // (the other files have their attributes in the image of their layer,
    // which nothing has to be allowed to write: here the host is asked, and
    // it may refuse one, as the file system of the copy of the `vfs` driver
    // does)
    let mut warned = false;
    for (name, value) in layer.raw_xattrs(root) {
        let name = String::from_utf8(name).map_err(std::io::Error::other)?;
        if velarx_fuse::hidden_xattr(&name) {
            continue;
        }
        if let Err(e) = fsetxattr(&dir, name.as_str(), &value, XattrFlags::empty()) {
            if !std::mem::replace(&mut warned, true) {
                warn!(
                    "the attribute {name} of the root of the container is not set ({e}); the other attributes the host refuses are skipped without a message"
                );
            }
        }
    }
    let at = |t: std::time::SystemTime| {
        let t = chrono::DateTime::<chrono::Utc>::from(t);
        rustix::fs::Timespec {
            tv_sec: t.timestamp(),
            tv_nsec: t.timestamp_subsec_nanos().into(),
        }
    };
    futimens(
        &dir,
        &Timestamps {
            last_access: at(a.atime),
            last_modification: at(a.mtime),
        },
    )
    .map_err(|e| context("time", e))
}

/// Whether the root of the process whose mount table is `mountinfo` is the
/// overlay with the upper directory `upper`: the last mount of `/` is an
/// overlay with `upperdir=` that directory among its options (the kernel
/// writes the path escaped, as every mount table does; an option is
/// compared whole).
fn root_is_overlay_of(mountinfo: &str, upper: &Path) -> bool {
    let want = format!("upperdir={}", upper.display());
    velarx_base::mountinfo::parse(mountinfo)
        .into_iter()
        .rfind(|m| m.point == Path::new("/"))
        .is_some_and(|m| {
            m.fs_type == "overlay"
                && m.super_options
                    .split(',')
                    .any(|o| velarx_base::mountinfo::unescape(o) == want)
        })
}

/// The files of a table of contents, by fs-verity digest, each once.
fn toc_files(toc: &Toc) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    toc.entries
        .iter()
        .filter(|e| e.entry_type == velarx_storage::TocEntryType::Reg && e.size > 0)
        .filter_map(|e| e.verity())
        .filter(|d| seen.insert(d.clone()))
        .collect()
}

/// The temporary files of the composefs directory that are old enough to be
/// leftovers.
fn stray_images(composefs: &Path, grace: Duration) -> Vec<(PathBuf, String)> {
    let mut found = Vec::new();
    if let Ok(entries) = std::fs::read_dir(composefs) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if (name.starts_with(".tmp") || name.starts_with(".image"))
                && objects::idle(&entry.path()).is_some_and(|d| d >= grace)
            {
                found.push((
                    entry.path(),
                    "a temporary file of the composefs images".into(),
                ));
            }
        }
    }
    found.sort();
    found
}

/// The options of a driver on a scratch store in `dir`, for the tests of what
/// uses one: the image server is the monitor next to the test (the unit tests
/// of this package do not start it; the integration tests build and use the
/// real one).
#[cfg(test)]
pub(crate) fn options_for_tests(dir: &Path) -> ComposefsOptions {
    ComposefsOptions::new(ImageServer::new(
        velarx_base::spawn::binary(),
        dir.join("run"),
        Arc::new(velarx_config::Config::default()),
    ))
}

/// A driver on a scratch store in `dir`, for the tests of what uses one.
#[cfg(test)]
pub(crate) async fn driver_for_tests(dir: &Path) -> ComposefsDriver {
    let db = Database::open(dir.join("db")).await.unwrap();
    let store = Arc::new(FileStore::new(dir.join("objects")).unwrap());
    ComposefsDriver::new(
        db,
        store,
        dir.join("staging"),
        VerityMode::Off,
        options_for_tests(dir),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::os::unix::fs::MetadataExt;
    use velarx_storage::{FileStore, Toc, TocEntry, TocEntryType};
    use velarx_types::OciDescriptor;

    fn entry(name: &str, t: TocEntryType) -> TocEntry {
        let mut e = velarx_fuse::dir_entry(name);
        e.entry_type = t;
        e
    }

    /// An attribute of the `./` of the layer the host refuses (the value of
    /// `security.ima` is no header: `EINVAL` as root, `EPERM` rootless) does
    /// not stop the container: the mode and the owner are still set.
    #[test]
    fn a_root_attribute_the_host_refuses_is_skipped() {
        let mut root = entry("./", TocEntryType::Dir);
        root.mode = 0o750;
        (root.uid, root.gid) = (
            rustix::process::getuid().as_raw(),
            rustix::process::getgid().as_raw(),
        );
        root.xattrs.insert("security.ima".into(), "dg==".into());
        let image = velarx_fuse::layer_erofs::layer_image(&[root])
            .unwrap()
            .image;
        let layer = velarx_fuse::erofs_tree::Layer::open(Box::new(image)).unwrap();
        let dir = tempfile::tempdir().unwrap();
        set_root(dir.path(), &layer, None).unwrap();
        assert_eq!(dir.path().metadata().unwrap().mode() & 0o7777, 0o750);
    }

    fn file(name: &str, byte: u8) -> TocEntry {
        let mut e = entry(name, TocEntryType::Reg);
        (e.size, e.fsverity) = (
            3,
            velarx_storage::to_toc(&format!(
                "fsverity-sha256-12:{}",
                format!("{byte:02x}").repeat(32)
            )),
        );
        e
    }

    /// The files of a batch have their names only once it is committed,
    /// after one barrier, in order, read-only.
    #[test]
    fn the_files_of_a_batch_are_named_together_after_one_barrier() {
        let tmp = tempfile::tempdir().unwrap();
        let store = FileStore::new(tmp.path().join("files")).unwrap();
        let dir = tmp.path().join("images");
        let a = dir.join("a");
        let mut d = Durable::new(&store);
        d.replace(&a, b"first", None).unwrap();
        d.replace(&a, b"second", None).unwrap();
        assert!(!a.exists());
        assert_eq!(store.barriers(), 0);
        d.commit().unwrap();
        assert_eq!(store.barriers(), 1);
        assert_eq!(std::fs::read(&a).unwrap(), b"second");
        let mode =
            std::os::unix::fs::PermissionsExt::mode(&std::fs::metadata(&a).unwrap().permissions());
        assert_eq!(mode & 0o777, 0o444);
        // no temporary file is left
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1);
    }

    /// The image of a layer is recorded with its digest and owners, and
    /// what `system check` looks at: a missing, changed, or different one.
    #[test]
    fn the_images_of_the_layers_are_made_and_checked() {
        let tmp = tempfile::tempdir().unwrap();
        let store = FileStore::new(tmp.path().join("objects")).unwrap();
        let mut owned = file("home/f", 1);
        (owned.uid, owned.gid) = (1000, 100);
        let toc = Toc {
            version: 1,
            entries: vec![entry("home", TocEntryType::Dir), owned],
            tar_split_digest: None,
        };
        let digest = LayerKey::Toc(format!("sha256:{}", "cd".repeat(32)).parse().unwrap());
        let made = make_layer_images(&[(digest, &toc)], &store).unwrap();
        let m = &made[&digest];
        assert_eq!(m.owners, "[[0,1000],[0,100]]");
        let path = cfs::layer_image_path(store.root(), &digest.file_stem());
        assert!(cfs::layer_index_path(store.root(), &digest.file_stem()).is_file());
        let bytes = std::fs::read(&path).unwrap();
        assert_eq!(
            velarx_storage::composefs_digest_of(velarx_types::digest::Algorithm::Sha256, &bytes),
            m.image_digest
        );
        assert!(layer_problems(&path, Some(&m.image_digest), Some(&toc), true).is_empty());
        let kinds = |p: Vec<Problem>| p.into_iter().map(|p| p.kind).collect::<Vec<_>>();
        assert_eq!(
            kinds(layer_problems(&path, None, None, true)),
            [ProblemKind::ArtifactMissing]
        );
        let other = Toc {
            entries: vec![file("x", 2)],
            ..toc.clone()
        };
        assert_eq!(
            kinds(layer_problems(
                &path,
                Some(&m.image_digest),
                Some(&other),
                true
            )),
            [ProblemKind::ArtifactDiffers]
        );
        std::fs::remove_file(&path).unwrap();
        std::fs::write(&path, b"x").unwrap();
        assert_eq!(
            kinds(layer_problems(
                &path,
                Some(&m.image_digest),
                Some(&toc),
                true
            )),
            [
                ProblemKind::ArtifactWritable,
                ProblemKind::ArtifactIdMismatch,
                ProblemKind::ArtifactDiffers
            ]
        );
        std::fs::remove_file(&path).unwrap();
        assert_eq!(
            kinds(layer_problems(
                &path,
                Some(&m.image_digest),
                Some(&toc),
                false
            )),
            [ProblemKind::ArtifactMissing]
        );
    }

    /// The digest a manifest states for a layer is the one its record has,
    /// which is the one the monitor compares the image it mounts with
    /// (`measure_layer_image`, the kernel's measure where the file has
    /// fs-verity: under `VELARX_VERITY_DIR` it must have it).
    #[test]
    fn the_digest_stated_is_the_one_the_monitor_measures() {
        let verity_dir = std::env::var_os("VELARX_VERITY_DIR");
        let tmp = match &verity_dir {
            Some(d) => tempfile::tempdir_in(d).unwrap(),
            None => tempfile::tempdir().unwrap(),
        };
        let store = FileStore::new(tmp.path().join("objects")).unwrap();
        let toc = Toc {
            version: 1,
            entries: vec![entry("etc", TocEntryType::Dir), file("etc/f", 3)],
            tar_split_digest: None,
        };
        let digest = LayerKey::Whole(format!("sha256:{}", "ef".repeat(32)).parse().unwrap());
        let made = make_layer_images(&[(digest, &toc)], &store).unwrap();
        let mut d = OciDescriptor {
            media_type: "x".into(),
            digest: *digest.digest(),
            size: 1,
            annotations: Default::default(),
        };
        assert!(crate::services::image::seal::state_layer(
            &mut d,
            &made[&digest].image_digest
        ));
        let stated: Vec<String> = crate::services::image::seal::layer_digests(&d)
            .unwrap()
            .iter()
            .map(Digest::plain)
            .collect();
        assert_eq!(stated, [made[&digest].image_digest.clone()]);
        let path = cfs::layer_image_path(store.root(), &digest.file_stem());
        let f = std::fs::File::open(&path).unwrap();
        cfs::measure_layer_image(&f, &path, &stated, false).unwrap();
        if verity_dir.is_some() {
            let m = velarx_storage::measure_file(&f).unwrap();
            assert_eq!(format!("sha256:{}", hex::encode(&m.digest)), stated[0]);
            cfs::measure_layer_image(&f, &path, &stated, true).unwrap();
            assert!(cfs::measure_layer_image(
                &f,
                &path,
                &[format!("sha256:{}", "00".repeat(32))],
                false
            )
            .is_err());
        }
    }

    async fn driver(dir: &Path) -> ComposefsDriver {
        driver_for_tests(dir).await
    }

    /// What the driver says it can do, through the trait: the engine
    /// negotiates with it, so the table is what the code does.
    #[tokio::test]
    async fn the_driver_says_what_it_can_do() {
        let tmp = tempfile::tempdir().unwrap();
        let d: Arc<dyn StorageDriver> = Arc::new(driver(tmp.path()).await);
        assert_eq!(d.name(), "composefs");
        let c = d.capabilities();
        assert!(c.lazy && c.serve_content && c.rootless);
        assert!(c.shared_stores && !c.layer_chain);
        assert_eq!(
            c.verity,
            Prefs::new(&[VerityEnforcement::Kernel, VerityEnforcement::OnOpen])
        );
        assert_eq!(
            c.root.idmap,
            Prefs::new(&[IdmapWay::DriverMount, IdmapWay::Translate])
        );
        assert_eq!(c.volume, Some(c.root));
        assert_eq!(c.max_layers, Some(cfs::OVERLAY_MAX_STACK));
    }

    /// `[storage] composefs` and `composefs_digests` reach the driver: what
    /// is probed and what it reports.
    #[tokio::test]
    async fn the_options_are_probed_and_reported() {
        let tmp = tempfile::tempdir().unwrap();
        let d = driver(tmp.path()).await;
        assert_eq!(d.options.enabled, Err("not configured".to_string()));
        assert_eq!(d.options.digests, ComposefsDigests::default());
        let server = d.options.server.clone();
        let off = ComposefsDriver {
            options: ComposefsOptions {
                digests: ComposefsDigests::Require,
                ..ComposefsOptions::for_mode("off", server.clone(), d.store.root())
            },
            ..d
        };
        assert_eq!(
            off.options.enabled,
            Err("[storage] composefs is off".to_string())
        );
        assert!(off.options.kernel_mount.is_err());
        let status = off.status();
        assert_eq!(
            status[0],
            ("composefs".into(), "no ([storage] composefs is off)".into())
        );
        assert_eq!(status[2], ("composefs digests".into(), "require".into()));
        assert_eq!(
            ComposefsOptions::for_mode("auto", server.clone(), off.store.root()).enabled,
            Ok(()),
            "auto is available"
        );
        assert!(
            ComposefsOptions::for_mode("maybe", server, off.store.root())
                .enabled
                .is_err()
        );
    }

    /// What the kernel says of an EROFS mounted from a file is `yes`; a
    /// failure that says nothing of the kernel is no answer
    /// (`imagemount::refuses_a_file` tells the refusals).
    #[test]
    fn the_mount_of_the_probe_is_yes_or_no_answer() {
        assert_eq!(file_backed_answer(Ok(())).unwrap(), Some(true));
        assert!(file_backed_answer(Err(std::io::Error::other("x"))).is_err());
        assert_eq!(locked_answer(Ok(true)).unwrap(), Some(true));
        assert_eq!(locked_answer(Ok(false)).unwrap(), Some(false));
        assert!(locked_answer(Err(std::io::Error::other("x"))).is_err());
        assert_eq!(shared_answer(Ok(true)).unwrap(), Some(true));
        assert_eq!(shared_answer(Ok(false)).unwrap(), Some(false));
        assert!(shared_answer(Err(std::io::Error::other("x"))).is_err());
    }

    /// The answers are the features `erofs-file` and `erofs-lock` of the run
    /// root: found once for the images of a boot, then kept.  A kernel that
    /// mounts no file is a reason that names file-backed EROFS and the kernel
    /// that has it; one that keeps no lock is not an error (the mount is by
    /// the name of the descriptor) and says so.
    #[test]
    fn the_answers_are_features_of_the_run_root() {
        let tmp = tempfile::tempdir().unwrap();
        let run = tmp.path();
        let features = run.join("features");
        let asked = std::cell::Cell::new(0);
        let asked = &asked;
        let probe = |answer: Option<bool>| {
            move || {
                asked.set(asked.get() + 1);
                Ok(answer)
            }
        };
        // an answer is kept: yes
        assert_eq!(file_backed(run, "boot1 /s", probe(Some(true))), Ok(()));
        assert!(features.join("erofs-file-yes").is_file());
        assert!(!features.join("erofs-file-no").exists());
        // and used: the probe is not asked, whatever it would say
        assert_eq!(file_backed(run, "boot1 /s", probe(Some(false))), Ok(()));
        assert_eq!(asked.get(), 1);
        // other images, or another boot, are asked again; no is kept too
        let e = file_backed(run, "boot1 /other", probe(Some(false))).unwrap_err();
        assert!(e.contains("file-backed EROFS") && e.contains("6.12"), "{e}");
        assert_eq!(asked.get(), 2);
        assert!(features.join("erofs-file-no").is_file());
        assert!(!features.join("erofs-file-yes").exists());
        let e = file_backed(run, "boot1 /other", probe(Some(true))).unwrap_err();
        assert!(e.contains("file-backed EROFS"), "{e}");
        assert_eq!(asked.get(), 2, "kept");
        // the lock is a feature of its own, and no is not an error
        asked.set(0);
        assert_eq!(locked(run, "boot1 /s", probe(Some(true))), Ok(true));
        assert!(features.join("erofs-lock-yes").is_file());
        assert!(!features.join("erofs-lock-no").exists());
        assert_eq!(locked(run, "boot1 /s", probe(Some(false))), Ok(true));
        assert_eq!(asked.get(), 1, "kept");
        assert_eq!(locked(run, "boot1 /other", probe(Some(false))), Ok(false));
        assert!(features.join("erofs-lock-no").is_file());
        assert!(!features.join("erofs-lock-yes").exists());
        assert_eq!(locked(run, "boot1 /other", probe(Some(true))), Ok(false));
        assert_eq!(asked.get(), 2, "kept");
        // the sharing of the superblock is a feature of its own, no is not an error
        asked.set(0);
        assert_eq!(
            shared_superblock(run, "boot1 /s", probe(Some(true))),
            Ok(true)
        );
        assert!(features.join("erofs-superblock-share-yes").is_file());
        assert_eq!(
            shared_superblock(run, "boot1 /s", probe(Some(false))),
            Ok(true)
        );
        assert_eq!(asked.get(), 1, "kept");
        assert_eq!(
            shared_superblock(run, "boot1 /other", probe(Some(false))),
            Ok(false)
        );
        assert!(features.join("erofs-superblock-share-no").is_file());
        assert!(!features.join("erofs-superblock-share-yes").exists());
        // a failure that says nothing is not kept, and says why
        std::fs::remove_dir_all(&features).unwrap();
        let failing = || Err(std::io::Error::other("no memory"));
        for e in [
            file_backed(run, "boot1 /s", failing).unwrap_err(),
            locked(run, "boot1 /s", failing).unwrap_err(),
            shared_superblock(run, "boot1 /s", failing).unwrap_err(),
        ] {
            assert!(
                e.contains("cannot find out") && e.contains("no memory"),
                "{e}"
            );
        }
        assert!(!features.exists());
        // (an answer of the kernel to the image is of the file system it is on)
        assert_eq!(file_backed(run, "boot1 /s", probe(None)), Ok(()));
        assert_eq!(locked(run, "boot1 /s", probe(None)), Ok(false));
        assert_eq!(shared_superblock(run, "boot1 /s", probe(None)), Ok(false));
        assert!(!features.exists(), "no answer, nothing kept");
    }

    /// The probes write their image where the images of the store are and
    /// leave nothing there; as root, on the file system of /var/tmp, the
    /// kernel mounts an EROFS from a file (Linux 6.12 and later) and says yes
    /// to the first; the lock is the answer of the kernel to the second
    /// (yes from Linux 7.3), whichever it is, and a kernel that holds none
    /// agrees with the mount of the descriptor's name.
    #[test]
    fn the_probes_leave_nothing_in_the_images_directory() {
        let tmp = tempfile::tempdir_in("/var/tmp").unwrap();
        let objects = tmp.path().join("objects");
        let file = file_backed_erofs(&objects);
        let lock = locked_erofs(&objects);
        let share = shares_superblock(&objects);
        let left: Vec<_> = std::fs::read_dir(cfs::images_dir(&objects))
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert!(left.is_empty(), "{left:?}");
        if !velarx_base::ids::rootful().unwrap_or(false) {
            return eprintln!("skipped: only root mounts an EROFS image: {file:?} {lock:?}");
        }
        eprintln!(
            "the kernel mounts an EROFS image from a file: {file:?}, keeps its lock: {lock:?}, shares the superblock: {share:?}"
        );
        assert!(share.unwrap().is_some());
        assert_eq!(file.unwrap(), Some(true));
        assert!(lock.unwrap().is_some());
    }

    /// The probe of a store on a tmpfs gets an answer of the kernel, not an
    /// error, and leaves nothing: no from a kernel that reads the image only
    /// through `read_folio`, which a tmpfs has not, yes from a newer one
    /// (Linux 7.4 mounts it).  As root, where `/dev/shm` is a tmpfs.
    #[test]
    fn the_probe_of_a_store_on_tmpfs_answers() {
        let shm = Path::new("/dev/shm");
        let on_tmpfs = rustix::fs::statfs(shm).is_ok_and(|s| s.f_type == libc::TMPFS_MAGIC);
        if !velarx_base::ids::rootful().unwrap_or(false) || !on_tmpfs {
            return eprintln!("skipped: needs root and /dev/shm on a tmpfs");
        }
        let tmp = tempfile::tempdir_in(shm).unwrap();
        let objects = tmp.path().join("objects");
        let answer = file_backed_erofs(&objects);
        eprintln!("a store on tmpfs: {answer:?}");
        assert!(answer.unwrap().is_some());
        assert_eq!(
            std::fs::read_dir(cfs::images_dir(&objects))
                .unwrap()
                .count(),
            0
        );
    }

    /// An image that does not fit the digests of an enforced start is refused
    /// where it is measured, with the link that broke said on the chain of
    /// trust: the layer, what it may have and what it has (none: it has no
    /// digest, or is not there).
    #[tokio::test]
    async fn a_layer_image_that_is_not_the_one_named_breaks_the_chain() {
        let tmp = tempfile::tempdir().unwrap();
        let d = driver(tmp.path()).await;
        let key = LayerKey::Whole(format!("sha256:{}", "ab".repeat(32)).parse().unwrap());
        let record = LayerRecord {
            stream_size: Some(0),
            key,
            blob: None,
            diff_id: None,
            other_diff_id: None,
            size: 1,
            toc: None,
            status: "ready".into(),
            created_at: String::new(),
            registry_ref: None,
            erofs: Some("sha256:ee".into()),
            owners: None,
        };
        let image = tmp.path().join("layer.erofs");
        let layer = LayerFiles {
            layer: key.to_string(),
            image: image.clone(),
            index: PathBuf::new(),
        };
        let logged = velarx_wire::logcapture::capture(tracing::Level::DEBUG);
        let accepted = ["sha256:aa".to_string()];
        let chain = velarx_wire::chain::Chain::new("", 3);
        let enforced = || {
            Some(Enforced {
                accepted: &accepted,
                chain: Some(&chain),
                layer: 1,
            })
        };
        // not there: Missing, and the chain breaks with no digest found
        let e = d
            .measured_image("1234", 100, &layer, &record, enforced())
            .unwrap_err();
        assert!(matches!(e.kind, DriverErrorKind::Missing { .. }), "{e:?}");
        assert_eq!(e.remedy(), Some(Remedy::Repair));
        // a file the file system cannot measure, where the digests are
        // enforced: Corrupt, said once
        std::fs::write(&image, b"image").unwrap();
        let e = d
            .measured_image("1234", 100, &layer, &record, enforced())
            .unwrap_err();
        assert!(matches!(e.kind, DriverErrorKind::Corrupt { .. }), "{e:?}");
        assert!(
            e.to_string().contains("cannot be measured")
                && e.to_string().contains("digests are enforced"),
            "{e}"
        );
        let log = logged.text();
        let broken: Vec<&str> = log.lines().filter(|l| l.contains("BROKEN")).collect();
        assert_eq!(
            broken.len(),
            1,
            "a chain breaks once, at the first link that did not hold: {log}"
        );
        assert!(
            broken[0]
                .ends_with("verity chain: BROKEN layer 1 erofs fd expected sha256:aa found none"),
            "{log}"
        );
    }

    /// The layer `bytes` as its image: the record, and where the driver finds
    /// the image (in the store of `d`).
    fn a_layer(d: &ComposefsDriver, bytes: &str) -> (LayerKey, LayerRecord, LayerFiles) {
        let key = LayerKey::Whole(format!("sha256:{}", "aa".repeat(32)).parse().unwrap());
        let image = cfs::layer_image_path(d.store.root(), &key.file_stem());
        std::fs::create_dir_all(image.parent().unwrap()).unwrap();
        std::fs::write(&image, bytes).unwrap();
        let record = LayerRecord {
            stream_size: Some(0),
            key,
            blob: None,
            diff_id: None,
            other_diff_id: None,
            size: 1,
            toc: None,
            status: "ready".into(),
            created_at: String::new(),
            registry_ref: None,
            erofs: Some("sha256:ee".into()),
            owners: None,
        };
        let layer = LayerFiles {
            layer: key.to_string(),
            image,
            index: PathBuf::new(),
        };
        (key, record, layer)
    }

    /// An image the digests of which are enforced, replaced by a copy without
    /// fs-verity (what a writer of the store can do), is refused where it is
    /// measured, naming the image and that the digests are enforced.
    #[tokio::test]
    async fn an_enforced_image_without_fs_verity_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let d = driver(tmp.path()).await;
        let (_, record, layer) = a_layer(&d, "not what the manifest says");
        let digest = format!("sha256:{}", "ab".repeat(32));
        let accepted = [digest];
        let enforced = Some(Enforced {
            accepted: &accepted,
            chain: None,
            layer: 1,
        });
        let e = d
            .measured_image("1234", 100, &layer, &record, enforced)
            .unwrap_err();
        let said = e.to_string();
        assert!(
            said.contains(&layer.image.display().to_string())
                && said.contains("digests are enforced"),
            "{said}"
        );
    }

    /// A layer that measures differently from every digest the engine gave is
    /// refused, enforced or not, whatever its record says.  Under
    /// `VELARX_VERITY_DIR` (a file system with fs-verity).
    #[tokio::test]
    async fn an_image_that_measures_differently_is_refused() {
        let Some(dir) = std::env::var_os("VELARX_VERITY_DIR") else {
            return eprintln!("VELARX_VERITY_DIR not set: skipped");
        };
        let tmp = tempfile::tempdir_in(dir).unwrap();
        let d = driver(tmp.path()).await;
        let (_, mut record, layer) = a_layer(&d, "an image");
        velarx_storage::VerityMode::On
            .manager()
            .unwrap()
            .enable(&layer.image)
            .unwrap();
        let real = velarx_storage::composefs_digest_of(Algorithm::Sha256, b"an image");
        let other = format!("sha256:{}", "ab".repeat(32));
        // not enforced: the digest the record has
        record.erofs = Some(other.clone());
        let e = d
            .measured_image("1234", 100, &layer, &record, None)
            .unwrap_err()
            .to_string();
        assert!(
            e.contains("has the fs-verity digest") && e.contains("expected"),
            "{e}"
        );
        // enforced: the lists of the manifest, whatever the record says
        record.erofs = Some(real.clone());
        let accepted = [other];
        let e = d
            .measured_image(
                "1234",
                100,
                &layer,
                &record,
                Some(Enforced {
                    accepted: &accepted,
                    chain: None,
                    layer: 1,
                }),
            )
            .unwrap_err()
            .to_string();
        assert!(
            e.contains("has the fs-verity digest") && e.contains("expected"),
            "{e}"
        );
        // and the image the record names is taken
        record.erofs = Some(real.clone());
        let (_, digest) = d
            .measured_image("1234", 100, &layer, &record, None)
            .unwrap();
        assert_eq!(digest, Some(real));
    }

    /// An image of a layer that is not recorded, or not there, is said with
    /// the remedy of today's message, through the trait and as the error of
    /// the engine.
    #[tokio::test]
    async fn a_missing_image_of_a_layer_says_its_remedy() {
        let tmp = tempfile::tempdir().unwrap();
        let d = driver(tmp.path()).await;
        let toc = Toc {
            version: 1,
            entries: vec![entry("etc", TocEntryType::Dir), file("etc/f", 1)],
            tar_split_digest: None,
        };
        let key = LayerKey::Whole(format!("sha256:{}", "ab".repeat(32)).parse().unwrap());
        let layer = |erofs: Option<String>| LayerRecord {
            stream_size: Some(0),
            key,
            blob: None,
            diff_id: None,
            other_diff_id: None,
            size: 1,
            toc: None,
            status: "ready".into(),
            created_at: String::new(),
            registry_ref: None,
            erofs,
            owners: None,
        };
        // not recorded
        let e = d.layer_images("1234", &[layer(None)]).unwrap_err();
        assert_eq!(
            e.to_string(),
            format!(
                "image 1234: the EROFS image of the layer {key} is not recorded: {}",
                Remedy::Repair.text(false)
            )
        );
        assert_eq!(e.remedy(), Some(Remedy::Repair));
        assert!(matches!(ImageError::from(e), ImageError::Storage(_)));
        // recorded, and not there
        let recorded = layer(Some("sha256:00".into()));
        let e = d
            .layer_images("", std::slice::from_ref(&recorded))
            .unwrap_err();
        assert_eq!(
            e.to_string(),
            format!(
                "the EROFS image of the layer {key} is not there: {}",
                Remedy::Repair.text(false)
            )
        );
        let Err(e) = d.image_view("", &[recorded]) else {
            panic!("no view of an image that is not there")
        };
        assert!(e
            .to_string()
            .ends_with("is not there: `velarx system check --repair` makes it again"));
        // made: found
        let made = d.make_images(vec![(key, toc)]).await.unwrap();
        let ready = layer(Some(made[&key].image_digest.clone()));
        assert_eq!(d.layer_images("", &[ready]).unwrap().len(), 1);
    }

    /// What the collection of the driver keeps is what it is told, and the
    /// usage counts the files.
    #[tokio::test]
    async fn a_collection_keeps_what_it_is_told() {
        let tmp = tempfile::tempdir().unwrap();
        let d = driver(tmp.path()).await;
        let toc = Toc {
            version: 1,
            entries: vec![entry("etc", TocEntryType::Dir), file("etc/f", 1)],
            tar_split_digest: None,
        };
        let key = LayerKey::Whole(format!("sha256:{}", "cd".repeat(32)).parse().unwrap());
        d.make_images(vec![(key, toc)]).await.unwrap();
        let path = cfs::layer_image_path(d.store.root(), &key.file_stem());
        assert_eq!(d.usage().unwrap().artifacts.0, 2);
        let kept = d
            .collect(&Keep {
                layers: vec![key],
                images: vec![],
                ..Keep::default()
            })
            .unwrap();
        assert_eq!((kept.bytes_freed, kept.errors.len()), (0, 0));
        assert!(path.is_file());
        // a profile of an image that is kept is kept, and a leftover is not
        let profile = cfs::profile_path(d.store.root(), "img");
        std::fs::write(&profile, b"[]").unwrap();
        let stale = cfs::profile_path(d.store.root(), "gone");
        std::fs::write(&stale, b"[]").unwrap();
        let kept = d
            .collect(&Keep {
                layers: vec![key],
                images: vec!["img".into()],
                ..Keep::default()
            })
            .unwrap();
        assert_eq!(kept.bytes_freed, 2);
        assert!(profile.is_file() && !stale.exists());
        d.remove_image("img").unwrap();
        assert!(!profile.exists());
        let gone = d.collect(&Keep::default()).unwrap();
        assert!(gone.bytes_freed > 0 && gone.errors.is_empty());
        assert!(!path.exists());
        assert_eq!(d.usage().unwrap().artifacts, (0, 0));
    }

    /// The graph driver podman and Docker report, and the data of a
    /// container's root file system, are the driver's.
    #[tokio::test]
    async fn graph_driver_names_and_data_are_the_drivers() {
        let dir = tempfile::tempdir().unwrap();
        let d = driver_for_tests(dir.path()).await;
        assert_eq!((d.name(), d.graph_name()), ("composefs", "overlay"));
        let w = Writable::new("c1", "/var/b/c1");
        assert_eq!(
            d.graph_data(&w),
            [
                ("UpperDir", "/var/b/c1/overlay/upper"),
                ("WorkDir", "/var/b/c1/overlay/work"),
                ("MergedDir", "/var/b/c1/rootfs"),
            ]
            .map(|(k, v)| (k.to_string(), v.to_string()))
        );
        // (the kind of the configuration is the one the factory makes)
        for kind in velarx_config::StorageDriverKind::ALL {
            let parts = || crate::storage_driver::DriverParts {
                db: d.db.clone(),
                store: d.store.clone(),
                staging_dir: dir.path().join("staging"),
                fsverity: VerityMode::Off,
            };
            match crate::storage_driver::open_local(
                *kind,
                parts(),
                &crate::storage_driver::DriverOptions::new(options_for_tests(dir.path())),
            ) {
                Some(made) => assert_eq!(kind.name(), made.name()),
                // (a driver of another process is connected to, and needs its
                // service)
                None => {
                    let e = crate::storage_driver::open(
                        *kind,
                        parts(),
                        &crate::storage_driver::DriverOptions::new(options_for_tests(dir.path())),
                    )
                    .map(|_| ())
                    .unwrap_err();
                    assert!(e.to_string().contains("[storage.varlink]"), "{e}");
                }
            }
        }
    }

    #[tokio::test]
    async fn leftovers_are_old_temporary_files_and_objects_no_row_names() {
        let dir = tempfile::tempdir().unwrap();
        let d = driver_for_tests(dir.path()).await;
        let objects = dir.path().join("objects");
        let name = |c: char| c.to_string().repeat(62);
        for (sub, file) in [
            ("ab", name('a')),
            ("ab", name('b')),
            ("ab", ".tmp-x".into()),
        ] {
            std::fs::create_dir_all(objects.join(sub)).unwrap();
            std::fs::write(objects.join(sub).join(file), "x").unwrap();
        }
        let cfs = dir.path().join("composefs");
        std::fs::create_dir_all(&cfs).unwrap();
        std::fs::write(cfs.join(".tmp1"), "x").unwrap();
        // (the image of a probe of file-backed EROFS a crash left)
        std::fs::write(cfs.join(format!("{PROBE_PREFIX}x.erofs")), "x").unwrap();
        std::fs::write(cfs.join("layer-a.v3.erofs"), "x").unwrap();
        let recorded: HashSet<String> = [format!("fsverity-sha256-12:ab{}", name('a'))].into();
        let mut found = objects::objects(&objects, &recorded, Duration::from_secs(0)).unwrap();
        found
            .stray
            .extend(d.leftovers(Duration::from_secs(0)).await.unwrap());
        found.stray.sort();
        assert_eq!(found.orphans, [objects.join("ab").join(name('b'))]);
        let strays: Vec<_> = found
            .stray
            .iter()
            .map(|(p, why)| {
                (
                    p.file_name().unwrap().to_str().unwrap().to_string(),
                    why.as_str(),
                )
            })
            .collect();
        assert_eq!(
            strays,
            [
                (
                    format!("{PROBE_PREFIX}x.erofs"),
                    "a temporary file of the composefs images"
                ),
                (
                    ".tmp1".to_string(),
                    "a temporary file of the composefs images"
                ),
                (".tmp-x".to_string(), "a temporary file in the objects"),
            ]
        );
        // (a file that changed within the grace period may be being written)
        let found = objects::objects(&objects, &recorded, Duration::from_secs(3600)).unwrap();
        assert!(found.orphans.is_empty() && found.stray.is_empty());
        assert!(d
            .leftovers(Duration::from_secs(3600))
            .await
            .unwrap()
            .is_empty());
    }

    #[test]
    fn names_of_objects() {
        use objects::is_hex;
        assert!(is_hex("ab", 2));
        assert!(!is_hex("AB", 2));
        assert!(!is_hex("abc", 2));
        assert!(is_hex(&"0".repeat(62), 62));
    }

    /// The writable layer is where bundles have had it since the first
    /// release (`overlay/upper`, `overlay/work`, the merged `rootfs`), made
    /// as before: both directories, again without harm, and a size limit
    /// (no limits yet) is refused rather than ignored.
    #[tokio::test]
    async fn the_writable_layer_is_the_overlay_of_the_bundle() {
        let tmp = tempfile::tempdir().unwrap();
        let d: Arc<dyn StorageDriver> = Arc::new(driver(tmp.path()).await);
        let bundle = tmp.path().join("bundles/abc");
        let w = Writable::new("abc", &bundle);
        assert_eq!((w.id(), w.bundle()), ("abc", bundle.as_path()));
        let p = d.writable_paths(&w);
        assert_eq!(p.upper, bundle.join("overlay/upper"));
        assert_eq!(p.work, Some(bundle.join("overlay/work")));
        assert_eq!(p.merged, bundle.join("rootfs"));
        // nothing there yet: no size, nothing to remove
        assert_eq!(d.writable_size(&w).unwrap(), 0);
        d.writable_remove(&w).unwrap();

        d.writable_create(&w, None, &WritableOptions::default(), None)
            .unwrap();
        assert!(p.upper.is_dir() && p.work.as_ref().unwrap().is_dir());
        let (me_u, me_g) = {
            let m = std::fs::metadata(&p.upper).unwrap();
            (m.uid(), m.gid())
        };
        // the owner is set when there is one (this process owns it already)
        d.writable_create(&w, Some((me_u, me_g)), &WritableOptions::default(), None)
            .unwrap();
        let err = d
            .writable_create(
                &w,
                None,
                &WritableOptions {
                    size_limit: Some(1 << 20),
                },
                None,
            )
            .unwrap_err();
        assert!(matches!(err.kind, DriverErrorKind::Unsupported));
        // the size is that of the files (nothing is followed)
        std::fs::create_dir_all(p.upper.join("etc")).unwrap();
        std::fs::write(p.upper.join("etc/a"), b"12345").unwrap();
        std::fs::write(p.upper.join("b"), b"123").unwrap();
        std::os::unix::fs::symlink("/etc", p.upper.join("link")).unwrap();
        assert_eq!(d.writable_size(&w).unwrap(), 8);
        // the work of another container is not touched
        let other = Writable::new("def", bundle.with_file_name("def"));
        d.writable_create(&other, None, &WritableOptions::default(), None)
            .unwrap();
        d.writable_remove(&w).unwrap();
        d.writable_remove(&w).unwrap();
        assert!(!p.upper.exists() && !p.work.as_ref().unwrap().exists());
        assert!(d.writable_paths(&other).upper.is_dir());
    }

    /// The root of a process is the container's when the last mount of `/`
    /// is an overlay with the container's upper directory, as the kernel
    /// writes the table: escaped, whatever is in the path, and no other
    /// mount, container or path that only looks like it matches.
    #[tokio::test]
    async fn the_root_of_a_container_is_found_in_the_mount_table() {
        let tmp = tempfile::tempdir().unwrap();
        let d: Arc<dyn StorageDriver> = Arc::new(driver(tmp.path()).await);
        let table = |upper: &str| {
            format!(
                "22 1 0:21 / /proc rw,nosuid - proc proc rw\n\
                 23 1 0:57 / / rw,relatime - overlay overlay \
                 rw,lowerdir+=/x/layers/1,lowerdir+=/x/layers/2,upperdir={upper},\
                 workdir=/x/work,userxattr\n\
                 24 23 0:58 / /dev rw - tmpfs tmpfs rw,size=64k\n"
            )
        };
        let on = |bundle: &str, mountinfo: &str| {
            root_is_overlay_of(
                mountinfo,
                &d.writable_paths(&Writable::new("c", bundle)).upper,
            )
        };
        let plain = "/var/lib/velarx/bundles/aa11";
        assert!(on(plain, &table(&format!("{plain}/overlay/upper"))));
        // a line as the kernel writes it (a quoted SELinux context with a
        // comma in it, the layers added one by one, a data directory)
        let real = format!(
            "7379 7294 0:136 / / rw,relatime - overlay none \
             rw,context=\"system_u:object_r:container_file_t:s0:c433,c487\",\
             lowerdir+=/run/velarx/mon/b90a/fs/image-mapped-7a78/layer1,\
             datadir+=/data/velarx/objects,upperdir={plain}/overlay/upper,\
             workdir={plain}/overlay/work,redirect_dir=nofollow,uuid=on,userxattr\n"
        );
        assert!(on(plain, &real));
        // a root that is another container's, or a prefix or an extension
        // of the path, or the work directory: not the container's
        for other in [
            "/var/lib/velarx/bundles/bb22/overlay/upper",
            "/var/lib/velarx/bundles/aa11/overlay/upper2",
            "/var/lib/velarx/bundles/aa11/overlay/uppe",
            "/var/lib/velarx/bundles/aa11x/overlay/upper",
            "/var/lib/velarx/bundles/aa1/overlay/upper",
            "/var/lib/velarx/bundles/aa11/overlay/work",
            "/var/lib/velarx/bundles/aa11/overlay/upper/sub",
            "/var/lib/velarx/bundles/aa11//overlay/uppers",
        ] {
            assert!(!on(plain, &table(other)), "{other}");
        }
        // the options are matched whole: a lower directory that names the
        // upper one is not the upper one
        let tricky = format!(
            "23 1 0:57 / / rw - overlay overlay rw,lowerdir=/not/upperdir={plain}/overlay/upper,\
             upperdir=/else/upper\n"
        );
        assert!(!on(plain, &tricky));
        // spaces, tabs, newlines and backslashes are escaped by the kernel,
        // and in the options of a mount commas and equal signs too
        // (`seq_show_option`): an escaped comma does not split the option
        let odd = "/var/lib/x y/bun\tdles/a\\b/c,upperdir=/d\ne";
        let escaped = "/var/lib/x\\040y/bun\\011dles/a\\134b/c\\054upperdir\\075/d\\012e";
        assert!(on(odd, &table(&format!("{escaped}/overlay/upper"))));
        assert!(!on("/d\ne", &table(&format!("{escaped}/overlay/upper"))));
        // an unescaped look-alike (a space is the field separator of the
        // table, and what is written is the octal)
        assert!(!on(odd, &table(&format!("{odd}/overlay/upperx"))));
        assert!(!on(odd, &table("/var/lib/x/overlay/upper")));
        // the last mount of `/` decides, and it must be an overlay
        let stacked = format!(
            "1 0 0:1 / / rw - overlay o rw,upperdir={plain}/overlay/upper\n\
             2 1 0:2 / / rw - tmpfs t rw,upperdir={plain}/overlay/upper\n"
        );
        assert!(!on(plain, &stacked));
        let stacked = format!(
            "1 0 0:1 / / rw - tmpfs t rw\n\
             2 1 0:2 / / rw - overlay o rw,upperdir={plain}/overlay/upper\n"
        );
        assert!(on(plain, &stacked));
        // an overlay that is not at `/` is not the root
        let elsewhere = format!(
            "1 0 0:1 / / rw - tmpfs t rw\n\
             2 1 0:2 / /mnt rw - overlay o rw,upperdir={plain}/overlay/upper\n"
        );
        assert!(!on(plain, &elsewhere));
        assert!(!on(plain, ""));
    }

    /// The driver reads the mount table in the directory of the process in
    /// `/proc`: this process is not a container's, and a process that is
    /// gone is an error (its pid was not checked).
    #[tokio::test]
    async fn the_root_of_a_process_is_read_in_its_proc_directory() {
        let tmp = tempfile::tempdir().unwrap();
        let d: Arc<dyn StorageDriver> = Arc::new(driver(tmp.path()).await);
        let w = Writable::new("c", tmp.path().join("bundles/c"));
        assert!(!d.is_root_of(&w, Path::new("/proc/self")).unwrap());
        let proc_dir = tmp.path().join("proc");
        let err = d.is_root_of(&w, &proc_dir).unwrap_err().into_io();
        assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
        std::fs::create_dir(&proc_dir).unwrap();
        let upper = d.writable_paths(&w).upper;
        std::fs::write(
            proc_dir.join("mountinfo"),
            format!(
                "1 0 0:1 / / rw - overlay overlay rw,upperdir={},workdir=/w\n",
                upper.display()
            ),
        )
        .unwrap();
        assert!(d.is_root_of(&w, &proc_dir).unwrap());
    }

    fn set_xattr(path: &Path, name: &str, value: &[u8]) -> bool {
        rustix::fs::lsetxattr(path, name, value, rustix::fs::XattrFlags::empty()).is_ok()
    }

    /// An upper directory with a new file, a directory, a hard link, a
    /// sparse file and a file of the engine, and the image below it
    /// (`etc/old`, its data in the driver's store, `etc/gone`, `opt/x`).
    /// Where the file system has user xattrs (the second value), also the
    /// overlay's marks: `etc/gone` deleted (a whiteout),
    /// `opt` made again (opaque) and `etc/old` chmodded with its data left
    /// below (`metacopy`).
    async fn upper_with_changes(
        tmp: &Path,
    ) -> (Arc<dyn StorageDriver>, Writable, Arc<dyn ImageTree>, bool) {
        let d: Arc<dyn StorageDriver> = Arc::new(driver(tmp).await);
        let w = Writable::new("c", tmp.join("bundles/c"));
        d.writable_create(&w, None, &WritableOptions::default(), None)
            .unwrap();
        let upper = d.writable_paths(&w).upper;
        std::fs::create_dir_all(upper.join("etc/sub")).unwrap();
        std::fs::write(upper.join("etc/new"), "new file").unwrap();
        std::fs::write(upper.join("etc/hosts"), "engine").unwrap();
        std::fs::write(upper.join("etc/sub/f"), "in a directory").unwrap();
        std::fs::hard_link(upper.join("etc/new"), upper.join("etc/sub/link")).unwrap();
        let sparse = std::fs::File::create(upper.join("sparse")).unwrap();
        sparse.set_len(1 << 20).unwrap();
        std::os::unix::fs::FileExt::write_at(&sparse, b"x", (1 << 20) - 1).unwrap();
        let mut marks = true;
        // (a whiteout is what the kernel writes: a character device 0:0,
        // which needs no privilege)
        marks &= rustix::fs::mknodat(
            rustix::fs::CWD,
            upper.join("etc/gone"),
            rustix::fs::FileType::CharacterDevice,
            rustix::fs::Mode::empty(),
            rustix::fs::makedev(0, 0),
        )
        .is_ok();
        std::fs::create_dir_all(upper.join("opt")).unwrap();
        std::fs::write(upper.join("opt/y"), "y").unwrap();
        marks &= set_xattr(&upper.join("opt"), "user.overlay.opaque", b"y");
        std::fs::write(upper.join("etc/old"), "").unwrap();
        std::fs::set_permissions(
            upper.join("etc/old"),
            std::os::unix::fs::PermissionsExt::from_mode(0o600),
        )
        .unwrap();
        marks &= set_xattr(&upper.join("etc/old"), "user.overlay.metacopy", b"");
        if !marks {
            for p in ["etc/gone", "etc/old", "opt/y"] {
                let _ = std::fs::remove_file(upper.join(p));
            }
            std::fs::remove_dir(upper.join("opt")).unwrap();
        }
        // the data of etc/old is in the store the driver reads
        let store = FileStore::new(tmp.join("objects")).unwrap();
        let digest = store.put(Algorithm::Sha256, b"old content").unwrap();
        let mut old = entry("etc/old", TocEntryType::Reg);
        (old.mode, old.size, old.fsverity) = (0o644, 11, velarx_storage::to_toc(&digest));
        let toc = Toc {
            version: 1,
            entries: vec![
                entry("etc", TocEntryType::Dir),
                entry("opt", TocEntryType::Dir),
                old,
                entry("etc/gone", TocEntryType::Reg),
                entry("opt/x", TocEntryType::Reg),
            ],
            tar_split_digest: None,
        };
        let image = velarx_fuse::layer_erofs::layer_image(&toc.entries)
            .unwrap()
            .image;
        let view = ImageView::new(vec![
            velarx_fuse::erofs_tree::Layer::open(Box::new(image)).unwrap()
        ]);
        (d, w, Arc::new(view), marks)
    }

    /// `diff` and `changes` give what the code they wrap gave: the same
    /// bytes, in the same order, for the same upper directory.
    #[tokio::test]
    async fn diff_and_changes_are_the_walk_of_the_upper_directory() {
        let tmp = tempfile::tempdir().unwrap();
        let (d, w, lower, marks) = upper_with_changes(tmp.path()).await;
        let opts = DiffOptions {
            exclude: dirtar::ENGINE_FILES.iter().map(|s| s.to_string()).collect(),
            ..Default::default()
        };
        // what the walk gave before the driver: the directory, the options,
        // the image below
        let store = Arc::new(FileStore::new(tmp.path().join("objects")).unwrap());
        let walk = opts.walk(Some(Arc::new(dirtar::Lower {
            tree: lower.clone(),
            objects: store,
        })));
        let upper = d.writable_paths(&w).upper;
        let fd = open_dir(&upper).unwrap();
        let mut expected = Vec::new();
        dirtar::write(rustix::fd::AsFd::as_fd(&fd), &walk, &mut expected).unwrap();
        let mut got = Vec::new();
        d.diff(&w, Some(lower.clone()), &opts, &mut got).unwrap();
        assert_eq!(got, expected);
        let names: Vec<String> = tar::Archive::new(got.as_slice())
            .entries()
            .unwrap()
            .map(|e| e.unwrap().path().unwrap().to_string_lossy().into_owned())
            .collect();
        assert!(names.contains(&"etc/new".to_string()));
        assert!(names.contains(&"etc/sub/link".to_string()));
        assert!(!names.contains(&"etc/hosts".to_string()));
        if marks {
            // the overlay's marks: a whiteout, an opaque directory, and the
            // data of a metadata only file from the image below
            assert!(names.contains(&"etc/.wh.gone".to_string()));
            assert!(names.contains(&"opt/.wh..wh..opq".to_string()));
            let mut a = tar::Archive::new(got.as_slice());
            let mut old = a
                .entries()
                .unwrap()
                .map(|e| e.unwrap())
                .find(|e| e.path().unwrap().to_str() == Some("etc/old"))
                .unwrap();
            assert_eq!(old.header().mode().unwrap() & 0o7777, 0o600);
            let mut data = String::new();
            std::io::Read::read_to_string(&mut old, &mut data).unwrap();
            assert_eq!(data, "old content");
            // without the image below, a metadata only file is not understood
            assert!(d.diff(&w, None, &opts, &mut Vec::new()).is_err());
        } else {
            // nothing needs the image below: without it, the same
            let mut plain = Vec::new();
            d.diff(&w, None, &opts, &mut plain).unwrap();
            assert_eq!(plain, expected);
        }

        let list = d.changes(&w, Some(lower), &opts).unwrap();
        let direct = dirtar::changes(rustix::fd::AsFd::as_fd(&fd), &walk).unwrap();
        assert_eq!(list, direct);
        assert!(list.contains(&("/etc".to_string(), Change::Modified)));
        assert!(list.contains(&("/etc/new".to_string(), Change::Added)));
        assert!(!list.iter().any(|(p, _)| p == "/etc/hosts"));
        if marks {
            assert!(list.contains(&("/etc/gone".to_string(), Change::Deleted)));
            assert!(list.contains(&("/etc/old".to_string(), Change::Modified)));
            assert!(list.contains(&("/opt/y".to_string(), Change::Added)));
        }
    }

    /// What `diff` writes, `apply` writes into another layer: the same
    /// layer comes out of it.
    #[tokio::test]
    async fn apply_writes_what_diff_wrote() {
        let tmp = tempfile::tempdir().unwrap();
        let (d, w, lower, marks) = upper_with_changes(tmp.path()).await;
        // (a whiteout apply makes has the time of the moment, as the
        // overlay's whiteouts: a fixed time keeps the tars of the two from
        // differing across a second; the times apply keeps are
        // velarx_wire::cp's tests)
        let opts = DiffOptions {
            mtime: dirtar::Mtime::Fixed(1),
            ..DiffOptions::default()
        };
        let mut tar = Vec::new();
        d.diff(&w, Some(lower.clone()), &opts, &mut tar).unwrap();
        let other = Writable::new("d", tmp.path().join("bundles/d"));
        d.writable_create(&other, None, &WritableOptions::default(), None)
            .unwrap();
        d.apply(&other, &opts, &mut tar.as_slice()).unwrap();
        let mut again = Vec::new();
        d.diff(&other, Some(lower), &opts, &mut again).unwrap();
        assert_eq!(again, tar);
        let upper = d.writable_paths(&other).upper;
        assert_eq!(std::fs::read(upper.join("etc/new")).unwrap(), b"new file");
        if marks {
            // the whiteout is the overlay's again, and the data came along
            assert_eq!(
                std::fs::read(upper.join("etc/old")).unwrap(),
                b"old content"
            );
            let list = d.changes(&other, None, &opts).unwrap();
            assert!(list.contains(&("/etc/gone".to_string(), Change::Deleted)));
        }
        // a layer that was never made has no changes to apply to
        let none = Writable::new("e", tmp.path().join("bundles/e"));
        assert!(!d.writable_exists(&none).unwrap());
        assert!(d.apply(&none, &opts, &mut tar.as_slice()).is_err());
    }

    /// The squash reads the changes as a directory: the upper directory
    /// itself, or (for a driver that has none) the extraction of the tar of
    /// `diff`: both are walked to the same layer.
    #[tokio::test]
    async fn the_changes_as_a_directory_are_the_same_layer_by_either_way() {
        let tmp = tempfile::tempdir().unwrap();
        let (d, w, lower, _) = upper_with_changes(tmp.path()).await;
        let upper = d.writable_paths(&w).upper;
        let diff = super::super::WritableDiff::new(d, w, Some(lower));
        let walk = dirtar::Options {
            exclude: dirtar::ENGINE_FILES.iter().map(|s| s.to_string()).collect(),
            mtime: dirtar::Mtime::Fixed(1),
            ..Default::default()
        };
        let scratch = tmp.path().join("scratch");
        let tar_of = |c: &super::super::ChangesDir| {
            let fd = open_dir(&c.path).unwrap();
            let mut out = Vec::new();
            dirtar::write(rustix::fd::AsFd::as_fd(&fd), &c.walk, &mut out).unwrap();
            out
        };
        let direct = diff.directory(&walk, &scratch).unwrap();
        assert_eq!(direct.path, upper);
        let via_tar = diff.directory_of_tar(&walk, &scratch).unwrap();
        assert!(via_tar.path.starts_with(&scratch));
        assert_ne!(via_tar.path, direct.path);
        let expected = tar_of(&direct);
        assert!(!expected.is_empty());
        assert!(
            tar_of(&via_tar) == expected,
            "the directories give another layer"
        );
        // the directory made for it goes with it
        let made = via_tar.path.clone();
        drop(via_tar);
        assert!(!made.exists());
    }

    /// The squash of a driver without an overlay upper (`overlay_upper`
    /// false) reads the extraction of the tar of `diff`, and it is the same
    /// layer, byte for byte, as the walk of the upper directory: whiteouts,
    /// an opaque directory, a metadata only file whose data is below, hard
    /// links, a sparse file, xattrs, a symlink, modes, the ids the container
    /// sees through its mapping, the times of the files kept or fixed.
    #[tokio::test]
    async fn a_driver_without_an_overlay_upper_squashes_to_the_same_layer() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let (cfs, w, lower, marks) = upper_with_changes(tmp.path()).await;
        let upper = cfs.writable_paths(&w).upper;
        // more than `upper_with_changes` has
        std::os::unix::fs::symlink("../etc/new", upper.join("etc/sub/sym")).unwrap();
        let xattr = set_xattr(&upper.join("etc/sub/f"), "user.test", b"value");
        std::fs::set_permissions(upper.join("etc/sub"), PermissionsExt::from_mode(0o751)).unwrap();
        std::fs::set_permissions(upper.join("etc/new"), PermissionsExt::from_mode(0o4755)).unwrap();
        // The times of the upper, long before the copy is made (the copy of
        // a test made in the same second as the upper would agree with it
        // whatever it did): the symlink, the whiteout, and the directories
        // after what they hold, as the container left them.
        let stamp = rustix::fs::Timestamps {
            last_access: rustix::fs::Timespec {
                tv_sec: 1_000_000_000,
                tv_nsec: 0,
            },
            last_modification: rustix::fs::Timespec {
                tv_sec: 1_000_000_000,
                tv_nsec: 0,
            },
        };
        for p in ["etc/sub/sym", "etc/gone", "etc/sub", "etc", "opt", ""] {
            if upper.join(p).symlink_metadata().is_ok() {
                rustix::fs::utimensat(
                    rustix::fs::CWD,
                    upper.join(p),
                    &stamp,
                    rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
                )
                .unwrap();
            }
        }
        let me = rustix::process::geteuid().as_raw();
        let mut uid_map = vec![dirtar::IdRange {
            container: 0,
            host: me,
            size: 1,
        }];
        if me == 0 {
            // a file of a mapped id other than root's
            uid_map.push(dirtar::IdRange {
                container: 1,
                host: 100_000,
                size: 1000,
            });
            std::os::unix::fs::lchown(upper.join("etc/sub/f"), Some(100_005), Some(0)).unwrap();
        }
        let gid_map = vec![dirtar::IdRange {
            container: 0,
            host: rustix::process::getegid().as_raw(),
            size: 1,
        }];
        let mut caps = cfs.capabilities().clone();
        caps.overlay_upper = false;
        let no_upper: Arc<dyn StorageDriver> = Arc::new(
            crate::storage_driver::watching::Watching::new(cfs.clone(), caps),
        );
        assert!(!no_upper.capabilities().overlay_upper);
        let scratch = tmp.path().join("scratch");
        for mtime in [dirtar::Mtime::Keep, dirtar::Mtime::Fixed(1)] {
            let walk = dirtar::Options {
                exclude: dirtar::ENGINE_FILES.iter().map(|s| s.to_string()).collect(),
                uid_map: uid_map.clone(),
                gid_map: gid_map.clone(),
                mtime,
                ..Default::default()
            };
            let tar_of = |c: &super::super::ChangesDir| {
                let fd = open_dir(&c.path).unwrap();
                let mut out = Vec::new();
                dirtar::write(rustix::fd::AsFd::as_fd(&fd), &c.walk, &mut out).unwrap();
                out
            };
            let direct =
                super::super::WritableDiff::new(cfs.clone(), w.clone(), Some(lower.clone()));
            let via =
                super::super::WritableDiff::new(no_upper.clone(), w.clone(), Some(lower.clone()));
            let a = direct.directory(&walk, &scratch).unwrap();
            assert_eq!(a.path, upper, "an overlay's upper is read in place");
            let b = via.directory(&walk, &scratch).unwrap();
            assert!(b.path.starts_with(&scratch), "{}", b.path.display());
            let (ta, tb) = (tar_of(&a), tar_of(&b));
            let names = |t: &[u8]| -> Vec<String> {
                tar::Archive::new(t)
                    .entries()
                    .unwrap()
                    .map(|e| e.unwrap().path().unwrap().to_string_lossy().into_owned())
                    .collect()
            };
            let na = names(&ta);
            for want in [
                "etc/new",
                "etc/sub/link",
                "etc/sub/sym",
                "etc/sub/f",
                "sparse",
            ] {
                assert!(na.iter().any(|n| n == want), "{want} not in {na:?}");
            }
            if marks {
                for want in ["etc/.wh.gone", "opt/.wh..wh..opq", "etc/old"] {
                    assert!(na.iter().any(|n| n == want), "{want} not in {na:?}");
                }
            }
            assert_eq!(na, names(&tb), "{mtime:?}");
            assert!(ta == tb, "{mtime:?}: the directories give another layer");
            // what the tar says: a hard link, the sparse file's size, the
            // xattr, the ids of the container
            let mut ar = tar::Archive::new(&ta[..]);
            for e in ar.entries().unwrap() {
                let mut e = e.unwrap();
                let p = e.path().unwrap().to_string_lossy().into_owned();
                let h = e.header().clone();
                match p.as_str() {
                    "etc/sub/link" => {
                        assert_eq!(h.entry_type(), tar::EntryType::Link);
                    }
                    "etc/sub/f" => {
                        if me == 0 {
                            assert_eq!(h.uid().unwrap(), 6);
                        }
                        if xattr {
                            let pax: Vec<_> = e
                                .pax_extensions()
                                .unwrap()
                                .into_iter()
                                .flatten()
                                .map(|x| x.unwrap().key().unwrap().to_string())
                                .collect();
                            assert!(pax.iter().any(|k| k == "SCHILY.xattr.user.test"), "{pax:?}");
                        }
                    }
                    "etc/new" => {
                        assert_eq!((h.uid().unwrap(), h.mode().unwrap() & 0o7777), (0, 0o4755));
                    }
                    _ => {}
                }
            }
            let made = b.path.clone();
            drop(b);
            assert!(!made.exists(), "the extraction goes with the result");
        }
    }

    /// The view of a stopped container shows its upper directory over the
    /// image.
    #[tokio::test]
    async fn the_view_of_a_stopped_container_reads_the_layer() {
        let tmp = tempfile::tempdir().unwrap();
        let (d, w, lower, marks) = upper_with_changes(tmp.path()).await;
        let store = FileStore::new(tmp.path().join("objects")).unwrap();
        let translate = velarx_fuse::IdTranslate::default();
        let layers: Vec<String> = Vec::new();
        let view = d
            .stopped_view(
                &w,
                TreeSource {
                    tree: &*lower,
                    layers: &layers,
                    objects: &store,
                    verity: store.verity(),
                    fetcher: None,
                    translate: &translate,
                },
            )
            .unwrap();
        let (st, _) = view.stat("/etc/new").unwrap();
        assert_eq!(st.size, 8);
        assert!(view.stat("/etc/sub").unwrap().0.is_dir);
        assert!(view.stat("/nothing").is_err());
        if marks {
            // what the overlay would show: the whiteout hides the image's
            // file, the opaque directory the image's directory
            assert!(view.stat("/etc/gone").is_err());
            assert!(view.stat("/opt/x").is_err());
            assert!(view.stat("/opt/y").is_ok());
        }
        let none = Writable::new("e", tmp.path().join("bundles/e"));
        let err = d
            .stopped_view(
                &none,
                TreeSource {
                    tree: &*lower,
                    layers: &layers,
                    objects: &store,
                    verity: store.verity(),
                    fetcher: None,
                    translate: &translate,
                },
            )
            .err()
            .expect("no layer, no view");
        assert!(matches!(err.kind, DriverErrorKind::Io(_)));
    }
}
