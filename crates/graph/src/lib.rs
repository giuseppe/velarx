// SPDX-License-Identifier: Apache-2.0
//! The storage driver: what holds the content of the images of the store and
//! makes the root file system of a container from it.
//!
//! A [`StorageDriver`] owns the whole on-disk layout of image content: how a
//! layer is pulled (stored, deduplicated, made durable), what artifacts it
//! gets, how it is read back as the tar stream of its diff id (push, save),
//! how an image is read without a container (`image_view`, an
//! [`ImageTree`]), how the root file system of a container is described
//! (`mounts`: the driver makes the mount or describes it, the monitor attaches
//! it, the engine never mounts), how the changes of a container's layer are read, and how it is
//! checked,
//! repaired, collected and measured.  The design is in the tracker (the
//! storage driver abstraction).  What every driver must pass is the
//! conformance suite (`conformance`, a feature of this package): a new
//! driver registers itself with a factory (`conformance`).
//!
//! The drivers are those of `velarx_config::StorageDriverKind`: the default
//! `ComposefsDriver` (name `composefs`: the objects named by their fs-verity
//! digest, a table of contents and a tar-split for each layer, one
//! reproducible EROFS image for each layer made at pull time, and the
//! overlay, the kernel's for root and FUSE for the rest, the monitor makes of
//! them), `vfs` (`crates/vfs`, podman's driver of that name: a full copy of
//! the layers for each container).
//!
//! What stays in the engine (`services::image` and friends), whatever the
//! driver: the registry transport and the fetchers, the manifests and
//! configurations by digest, the database of images, tags and names (and the
//! generic columns of the layers), signatures and policy, pull policy, the
//! annotations of a sealed image, the wire protocols of the store service and of the peers,
//! the sharing policy, and the check of the diff ids a driver reports against
//! the configuration of the image.
//!
//! What a driver can do is said by its [`Capabilities`]; the engine negotiates
//! with them (`negotiate`): an option a driver lacks (images mounted in a
//! container, a user namespace, an unprivileged engine, a size limit, enforced
//! digests, lazy images) is refused up front with what to do, never replaced by
//! another behaviour without a word.  The capabilities do not assume overlay,
//! EROFS or fs-verity at run time: a driver which translates the ids as it
//! copies the layers for a container (`IdmapWay::AtCopy`), or whose verity is
//! checked only at pull (`VerityEnforcement::PullOnly`), is described by them.
//!
//! The trait holds the groups the engine routes through it today (layers,
//! images, the writable layer of a container, maintenance, availability).
//! The writable layer is named by [`Writable`] and answered by
//! [`StorageDriver::writable_create`], `writable_paths`, `writable_size`,
//! `writable_remove` and `is_root_of`: the engine builds no path of the
//! upper and work directories and reads no mount table of a container's
//! process itself.  What a container changed in the layer is read through
//! the driver too: [`StorageDriver::diff`] (the tar stream of the layer, for
//! `commit`, a build step and the rootfs diff of a checkpoint),
//! `changes` (the list of `container diff`), `apply` (the restore of that
//! rootfs diff), `stopped_view` (the layer over its image, for `cp`, `export`
//! and the working directory of a stopped container) and `writable_exists`.
//! The engine's part is [`DiffOptions`] (what to leave out, the id maps, the
//! times) and the walk that is the same for every driver (hard links, ids,
//! the tar); the driver's is how its layer says what changed, which for
//! `composefs` is the overlay's whiteouts, opaque directories, metadata only
//! files and redirects (the last two need the image below, an
//! [`ImageTree`]).  `upper` is the directory the container's own files are in
//! (the engine writes its `/etc/hosts` there at create, the stats measure its
//! file system): the upper directory of an overlay, or, for a driver that
//! copies the layers, the whole root file system (`WritablePaths::work` is
//! none when the layer needs no mount).  What reads the changes as a
//! directory, the squash of `commit --squash` and of a build, asks
//! [`WritableDiff::directory`]: the upper directory itself when
//! `Capabilities::overlay_upper` says it is an overlay's, else the tar of
//! `diff` extracted into a directory of the overlay's form.  `stopped_view`
//! gives a [`StoppedView`] of the layout the driver says (`overlay`: the
//! layer over the image, `directory`: the whole root, where a 0:0 device is a
//! device); the merged tree is still the bundle's `rootfs` the engine names.
//! The plan is the driver's: `velarx_fuse::plan::RootfsPlan`, one kind per
//! way to make the root file system (`Directory`, `MountFd`), in the
//! bundle file `rootfs.json`; [`StorageDriver::mounts`] answers a [`Rootfs`] for
//! the root and each image mount, the plan and,
//! for `MountFd`, the detached mount the engine hands to the monitor (new at
//! every call: the monitor uses it once).  The engine reads and writes the
//! files of a root through [`StorageDriver::writable_root`], a directory
//! descriptor, not through `WritablePaths::upper`.  The performance rules stay: no driver call
//! per file at run time (`mounts` gets layer records without their table
//! of contents, so its cost cannot depend on the number of files), the EROFS of
//! a layer is made once at pull and reused, a pull makes durable with one
//! barrier.
//!
//! The pull is the driver's: [`StorageDriver::pull`] gets a [`PullFeed`], the
//! engine's side of the network (the registry, the peers, the merge of the
//! ranges, the checks), says what it wants of each layer and receives the
//! bytes ([`Incoming`]); [`feed`] has the flow, and the pull of the drivers
//! that keep their store in this process.
//!
//! What the engine does itself, whatever the driver, is not in the trait: the
//! stream of a layer's diff id (`velarx_graph::objects::open_layer`, the
//! engine's tar-split over [`StorageDriver::read_objects`]), the owners of the
//! files of the layers, the digest of the merged image of a sealed manifest,
//! the objects of the store service and the scan of the objects for leftovers.
//! What the engine records of a layer is [`LayerArtifact`] (the columns `erofs`
//! and `owners`, which the engine still reads for the digests a start checks).
//! `docs/STORAGE.md` describes the interface.

use async_trait::async_trait;
use std::collections::HashMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use velarx_content::layer::dirtar::{self, Change, IdRange, Mtime};
use velarx_content::layer::holes::HoleWrite;
use velarx_db::{ImageRecord, LayerKey, LayerRecord};
use velarx_fuse::plan::RootfsPlan;
use velarx_fuse::view::ImageTree;
use velarx_storage::FileStore;
use velarx_types::digest::Digest;
use velarx_types::ImageError;

mod blocking;
pub mod cpview;
pub mod directory;
pub mod feed;
pub mod imagecopy;
pub mod negotiate;
pub mod objects;
pub mod prefs;
pub mod unused;
pub use blocking::blocking;
pub use cpview::StoppedView;
pub use feed::{
    is_pull_id, new_pull_id, prove_by_read_back, prove_with, to_fetch, CheckId, Checked,
    ContentFeed, FeedLayer, FilesIncoming, Identities, InProcess, Incoming, LayerDone, LayerIndex,
    LocalContent, PullFeed, Pulled, SessionIncoming, Settled, Settlement, StagedFeed, StoreContent,
    Verdict, Wanted,
};
pub use imagecopy::TreeSource;
pub use prefs::Prefs;

pub mod forward;

#[cfg(any(test, feature = "conformance"))]
pub mod conformance;

/// What a driver is made from.
pub struct DriverParts {
    pub db: velarx_db::Database,
    pub store: Arc<FileStore>,
    pub staging_dir: PathBuf,
    pub fsverity: velarx_storage::VerityMode,
}

/// What enforces the fs-verity digests of what a container runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerityEnforcement {
    /// Checked when the content is stored (at pull), and nothing more is
    /// promised afterwards (best effort).
    PullOnly,
    /// Checked when a file is opened, by the file system server (FUSE).
    OnOpen,
    /// By the kernel (`verity=` of the overlay, on mounts of root).
    Kernel,
}

/// How a container with a user namespace gets the layers owned by its ids.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdmapWay {
    /// The driver hands over one mount whose files carry the ids of the
    /// image, and the monitor puts the container's mapping on the clone it
    /// attaches ([`IdmapDone::Mount`]): for a driver whose mount of a
    /// container is made in constant time and a chown of it would not be
    /// (a snapshot, a remote clone).  Needs root of the initial user
    /// namespace and a file system that takes idmapped mounts.
    MonitorMount,
    /// The driver idmaps its own mounts (the lowers of an overlay) and
    /// hands over the result ([`IdmapDone::Applied`]).
    DriverMount,
    /// The ids are translated while the files are copied into the root file
    /// system of the container, when it is created: that copy is the
    /// container's own, so the image is never mapped by itself and nothing
    /// is kept for a mapping.
    AtCopy,
    /// A file system server translates the ids.
    Translate,
}

/// What a driver does for one purpose of a mount, a container's root or an
/// image mounted in it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MountCaps {
    /// How user namespaces are supported, in the order the driver prefers.
    /// Empty: a mapping is not supported.
    pub idmap: Prefs<IdmapWay>,
}

/// What a driver can do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Capabilities {
    /// Containers of an image whose content is partly missing (`--lazy`).
    pub lazy: bool,
    /// Answers content lookups (sha256 of files and chunks), layer indexes
    /// and profiles for the store service, so that peers can be served.
    /// A driver without it serves nothing to peers.
    pub serve_content: bool,
    /// Works for an unprivileged engine.
    pub rootless: bool,
    /// What enforces the fs-verity digests (`PullOnly`: only when the
    /// content is stored), in the order the
    /// driver prefers.
    pub verity: Prefs<VerityEnforcement>,
    /// Uses the read-only `additional_image_stores` of the same driver.
    pub shared_stores: bool,
    /// The driver's layers are chained: a layer is made on its parent (a
    /// snapshot of the parent layer), so what it holds depends on the whole
    /// stack below it, not on the layer alone.  Such a driver keys its
    /// layers on the chain id ([`LayerRef::chain_id`], [`FeedLayer::chain_id`]
    /// and [`Keep::chains`]) and needs the whole ordered layer list of an
    /// image in `pull`.  The engine then asks `has_layers` and collects per
    /// chain, a layer at two places being two layers.  False (content keyed:
    /// the artifact of a layer depends on the layer only, shareable between
    /// images and reproducible) for composefs and vfs, which ignore the
    /// chain ids.
    pub layer_chain: bool,
    /// The most layers (and data-only layers) of one container.
    pub max_layers: Option<usize>,
    /// The writable layer is the upper directory of an overlay: the files the
    /// container wrote, in place, and its deletions as the overlay's marks
    /// (`WritablePaths::upper`).  The squash, which reads the changes as a
    /// directory, reads it as it is; for any other driver the changes of
    /// `diff` are made a directory first.
    pub overlay_upper: bool,
    /// `WritableOptions::size_limit` is supported.  A driver without it
    /// answers `Unsupported` to a limit that is asked for, and the engine
    /// refuses the request up front.
    pub writable_size_limit: bool,
    /// The root file system of a container.
    pub root: MountCaps,
    /// The images mounted in a container (`--mount type=image`); none: the
    /// driver has no such mount and `negotiate` refuses it up front.
    pub volume: Option<MountCaps>,
}

/// What the engine records with a layer of what the driver made of it (the
/// columns `layers.erofs` and `layers.owners` today; the stage that gives
/// drivers tables of their own writes them through the driver's transaction).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LayerArtifact {
    /// The digest the driver's image of the layer has (composefs: the
    /// fs-verity digest of its EROFS image): the identity of what it made.
    pub image_digest: String,
    /// The owners of the files, `[[uids], [gids]]` as JSON.
    pub owners: String,
}

/// What kind of problem a check found with what a driver made of an image.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProblemKind {
    ArtifactMissing,
    ArtifactUnreadable,
    ArtifactWritable,
    ArtifactIdMismatch,
    ArtifactDiffers,
    ArtifactSealMismatch,
    AnnotationMissing,
    AnnotationMismatch,
    IdentityMissing,
    TocMissing,
    TocDiffers,
    ObjectMissing,
    ObjectDiffers,
}

impl ProblemKind {
    /// Every kind.
    pub const ALL: [ProblemKind; 13] = [
        ProblemKind::ArtifactMissing,
        ProblemKind::ArtifactUnreadable,
        ProblemKind::ArtifactWritable,
        ProblemKind::ArtifactIdMismatch,
        ProblemKind::ArtifactDiffers,
        ProblemKind::ArtifactSealMismatch,
        ProblemKind::AnnotationMissing,
        ProblemKind::AnnotationMismatch,
        ProblemKind::IdentityMissing,
        ProblemKind::TocMissing,
        ProblemKind::TocDiffers,
        ProblemKind::ObjectMissing,
        ProblemKind::ObjectDiffers,
    ];

    /// The name of the kind: what `system check` reports.
    pub fn as_str(self) -> &'static str {
        match self {
            ProblemKind::ArtifactMissing => "artifact_missing",
            ProblemKind::ArtifactUnreadable => "artifact_unreadable",
            ProblemKind::ArtifactWritable => "artifact_writable",
            ProblemKind::ArtifactIdMismatch => "artifact_id_mismatch",
            ProblemKind::ArtifactDiffers => "artifact_differs",
            ProblemKind::ArtifactSealMismatch => "artifact_seal_mismatch",
            ProblemKind::AnnotationMissing => "annotation_missing",
            ProblemKind::AnnotationMismatch => "annotation_mismatch",
            ProblemKind::IdentityMissing => "identity_missing",
            ProblemKind::TocMissing => "toc_missing",
            ProblemKind::TocDiffers => "toc_differs",
            ProblemKind::ObjectMissing => "object_missing",
            ProblemKind::ObjectDiffers => "object_differs",
        }
    }
}

/// A problem a check found with what a driver made of an image.
#[derive(Debug, Clone)]
pub struct Problem {
    pub kind: ProblemKind,
    pub message: String,
    /// The layer it is about, when it is about one.
    pub layer: Option<LayerKey>,
    /// The file it is about, when the driver has one.
    pub path: Option<PathBuf>,
    /// Making the artifacts again mends it (not a manifest that states
    /// another digest).
    pub repair: bool,
}

/// What a scan of the driver's own artifacts found that nothing accounts for
/// and that has been unchanged for the grace period.  The files of the
/// engine's own object store are the engine's to scan.
#[derive(Debug, Clone, Default)]
pub struct Leftovers {
    /// Temporary files, with why each is one.
    pub stray: Vec<(PathBuf, String)>,
    /// Content files no row of the database names.
    pub orphans: Vec<PathBuf>,
}

/// What a collection keeps: the driver removes the rest of what it holds.
#[derive(Debug, Clone, Default)]
pub struct Keep {
    /// The layers the store has (those of the images, and so of the live
    /// containers, which are made of images: a layer in use is always named
    /// here).
    pub layers: Vec<LayerKey>,
    /// The chain ids of the layers of the images the store has (every
    /// prefix of the stack of an image, each once), for a driver whose
    /// layers are chained (`Capabilities::layer_chain`): it keeps a chain
    /// named here and removes the others, whatever keys it holds them
    /// under.  Empty for any other driver (the engine fills it only for a
    /// chained one: it costs the reading of every image's configuration).
    /// `layers` is filled in every case.
    pub chains: Vec<Digest>,
    /// The images the store has, by id.
    pub images: Vec<String>,
    /// The containers that exist, by id: whatever the driver holds for them
    /// (their writable layer, a root it made) is kept, whether the layers
    /// they were made of are named or not.  A collection never removes the
    /// writable layer of a container.
    pub containers: Vec<String>,
    /// The pulls in progress, by id: whatever the driver holds for them (a
    /// staging area, a startup profile) is kept until they end.
    pub pulls: Vec<String>,
    /// What the driver finds that none of the above names (the staging area
    /// of a pull whose engine crashed, a root of a container the engine
    /// never recorded) is kept while it has changed within this time: a
    /// create or a pull of another process is not recorded until it ends.
    /// The engine does not call a collection while a create, a pull or a
    /// commit of the same store is between its first call to the driver and
    /// the record of its result (it holds the store's shared lock, and a
    /// collection holds it exclusively), so this only covers what a crash
    /// left.
    pub grace: std::time::Duration,
}

/// What keeps layers from being used while they are removed
/// ([`UnusedLayers::hold`]): dropped, it lets them go.
pub type Hold = Vec<Box<dyn std::any::Any + Send>>;

/// The answer of [`StorageDriver::lock_unused_layers`]: the layers a mount or
/// a server uses, and the hold on the others.
#[derive(Default)]
pub struct UnusedLayers {
    /// The layers something uses (an image mounted by a kernel that holds its
    /// lock, an image server that serves it): the collection keeps them and
    /// their files.  A use the driver cannot see (a kernel mount that holds
    /// no lock) is not in it.
    pub in_use: std::collections::HashSet<LayerKey>,
    /// What keeps the other layers from being taken while they are removed;
    /// dropped when the collection is done with them.
    pub hold: Hold,
}

/// What a collection of a driver removed.
#[derive(Debug, Clone, Default)]
pub struct Collected {
    pub bytes_freed: u64,
    pub errors: Vec<String>,
}

/// What the driver holds on the disk for itself: (files, bytes) of what it
/// makes of the content (the images of the layers).  The content of the
/// images is the engine's and it measures it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Usage {
    /// What the driver makes of the content (the images of the layers).
    pub artifacts: (u64, u64),
}

/// Who put the container's id mapping on a mount: what the engine reads in
/// the answer to know whether the files show the ids of the container.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdmapDone {
    /// No mapping was asked (the container has no user namespace of its own).
    None,
    /// The driver delivers the container's ids itself (the copy was made
    /// with them, a file system server translates them, its lowers are
    /// idmapped): the monitor puts nothing on the mount.
    Applied,
    /// The mount carries the ids of the image, and the monitor puts the
    /// mapping on the clone it attaches (`MountFd { idmap: true }`).  Only
    /// asked for when [`MountRequest::idmap_mount`] is true.
    Mount,
}

pub use velarx_fuse::plan::VerityDone;

/// Whether the SELinux label that was asked for is on the mount.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LabelDone {
    /// The driver did nothing about the label (or none was asked): the engine
    /// labels the files of the root through [`StorageDriver::writable_root`]
    /// when one was asked.
    None,
    /// The mount carries the label as its `context=`.
    MountContext,
    /// The driver labelled the files itself.
    Files,
}

/// What a mount is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Purpose {
    /// The root file system of the container.
    Root,
    /// The image mounted in the container as the `index`-th `--mount
    /// type=image` (counted from 0 in the order of the container's mounts).
    Volume { index: u32 },
}

/// Whether the digests of what is mounted are enforced.
#[derive(Debug, Clone, Copy)]
pub enum VerityAsk<'a> {
    Off,
    /// `--security-opt verity=enforce`, `[storage] fsverity_require` or
    /// `composefs_digests = "require"`.  `accepted` is, for each layer of the
    /// request in order, the fs-verity digests the engine accepts of its
    /// EROFS image (the manifest's, checked): what a driver that measures
    /// compares its images with.
    Enforce {
        accepted: &'a [Vec<String>],
        /// The chain of trust of the image, as far as the engine checked it
        /// (none: the debug log does not follow it): a driver that measures
        /// the images says the link of each layer it measured, and the one
        /// that broke, on it, where it makes the check.
        chain: Option<&'a velarx_wire::chain::Chain>,
    },
}

impl VerityAsk<'_> {
    pub fn enforced(&self) -> bool {
        matches!(self, VerityAsk::Enforce { .. })
    }
}

/// One mount of a container, its root file system or an image mounted in it:
/// the same fields for both.
#[derive(Clone)]
pub struct MountRequest<'a> {
    /// The container the mount belongs to: every mount does, a root is its
    /// writable layer and a volume is removed with it.
    pub container: &'a Writable,
    pub purpose: Purpose,
    pub image: &'a ImageRecord,
    /// The layers of the image, without their tables of contents.
    pub layers: &'a [LayerRecord],
    /// The user namespace of the container, if it has one of its own (none:
    /// the container runs with the ids of the engine, and nothing is mapped).
    pub mapping: Option<&'a velarx_fuse::IdTranslate>,
    /// How the owners of the files of the image are shown by a driver that
    /// serves the files itself (a FUSE file system): the mapping of the
    /// container's user namespace when it has one, else the identity of the
    /// ids the engine has.  A driver that mounts with the kernel (`mapping`)
    /// does not read it.
    pub translate: Option<&'a velarx_fuse::IdTranslate>,
    /// The monitor can put the mapping on the mount (the engine is root of
    /// the initial user namespace) and there is a mapping: the driver may
    /// answer [`IdmapDone::Mount`].  False otherwise, and then it never does.
    pub idmap_mount: bool,
    /// The SELinux context of the mount of the container (`context=`).
    pub label: Option<&'a str>,
    pub verity: VerityAsk<'a>,
    /// The root of a container whose changes are thrown away (`--rm`): its
    /// upper is not synced.  Never set for a volume.
    pub volatile: bool,
}

/// What the descriptors and plans of a container are asked of at a start.
pub struct MountsRequest<'a> {
    /// The root file system (none: a container of a directory the user gave,
    /// `--rootfs`, which has no image root; its image mounts are asked all the
    /// same).
    pub root: Option<MountRequest<'a>>,
    /// The image mounts, in the order of their index.
    pub volumes: Vec<MountRequest<'a>>,
}

/// What [`StorageDriver::mounts`] answers: the root file system when it was
/// asked, and the volumes in the order they were asked.
#[derive(Debug, Default)]
pub struct Mounts {
    pub root: Option<Rootfs>,
    pub volumes: Vec<Rootfs>,
}

/// What a mount is going to be, as the driver says it when it makes what it
/// keeps for the container ([`StorageDriver::writable_create`],
/// [`StorageDriver::image_volume_create`]): the engine writes the plan of the
/// bundle from it, with no descriptor made.  The driver answers the same plan
/// at every start.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Planned {
    pub plan: RootfsPlan,
    pub idmap: IdmapDone,
    pub label: LabelDone,
}

/// What a mount is made as: the plan the monitor executes, and the
/// descriptor it names, if it names one.
///
/// `fd` is `Some` exactly when the plan is [`RootfsPlan::MountFd`]: the
/// detached mount, which the engine hands to the monitor at the spawn
/// (`SpawnOptions::rootfs_fds`).  A monitor uses its descriptor once, so the
/// engine asks the driver again at **every** start, restart of the engine and
/// restore ([`StorageDriver::mounts`]), and never keeps a descriptor: each
/// call gives a new one (a plan with no descriptor, `None`, is the same plan
/// every time).
///
/// The descriptor is the driver's gift: it makes a **new** mount for each
/// answer, closes every copy of it it holds after it has handed it over, and
/// never hands the same mount twice.  The monitor attaches a clone of it, and
/// a mount the driver kept would pin the superblock (and the server of a FUSE
/// one) after the container has stopped.
#[derive(Debug)]
pub struct Rootfs {
    pub plan: RootfsPlan,
    pub fd: Option<std::os::fd::OwnedFd>,
    /// Who put the container's id mapping on it.
    pub idmap: IdmapDone,
    /// Whether the label that was asked is on it.
    pub label: LabelDone,
    /// What enforces the digests of what is mounted.  Not
    /// [`VerityDone::None`] exactly for a [`RootfsPlan::MountFd`] when the
    /// request was [`VerityAsk::Enforce`] (the engine refuses a mount that
    /// carries none then; the other kinds of plan are measured by the
    /// monitor).
    pub verity: VerityDone,
    /// With `verity` not `None`: the fs-verity digest the driver measured on
    /// the EROFS image of each layer of the request, in the order of the
    /// layers, each one of the digests the request accepted for it.  The
    /// engine checks that, and says the links of the chain of trust from it.
    pub measured: Vec<String>,
    /// A process that serves the mount (a file system server), as a pidfd.
    /// The engine refuses an
    /// answer that has one until it can place the process with the monitor.
    pub server: Option<std::os::fd::OwnedFd>,
}

impl Rootfs {
    /// The mount without its descriptor.
    pub fn planned(&self) -> Planned {
        Planned {
            plan: self.plan.clone(),
            idmap: self.idmap,
            label: self.label,
        }
    }
}

impl From<RootfsPlan> for Rootfs {
    /// A plan that names no descriptor (`Directory`), and no
    /// mapping or label done.
    fn from(plan: RootfsPlan) -> Self {
        Self {
            plan,
            fd: None,
            idmap: IdmapDone::None,
            label: LabelDone::None,
            verity: VerityDone::None,
            measured: Vec::new(),
            server: None,
        }
    }
}

/// The writable layer of one container: what the driver is asked to make,
/// find, measure and remove.  It names the container and its bundle; where
/// the layer is, and what it is made of, is the driver's to say
/// ([`StorageDriver::writable_paths`]): the engine never builds those paths.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Writable {
    id: String,
    bundle: PathBuf,
}

impl Writable {
    /// The writable layer of the container `id`, whose bundle is `bundle`.
    pub fn new(id: impl Into<String>, bundle: impl Into<PathBuf>) -> Self {
        Self {
            id: id.into(),
            bundle: bundle.into(),
        }
    }

    /// The id of the container.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// The bundle of the container.
    pub fn bundle(&self) -> &Path {
        &self.bundle
    }
}

/// Where the writable layer of a container is, as the driver lays it out
/// (for the monitor's mount, the files the engine writes into the container
/// at create, and the file system the stats measure).  The paths are those of
/// the host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WritablePaths {
    /// The directory the container's own files are in: the files the
    /// container wrote (the upper directory of an overlay), or the whole root
    /// file system (a driver that copies the layers).
    pub upper: PathBuf,
    /// The scratch directory of the mount (the work directory of an
    /// overlay); none for a driver whose layer needs no mount.
    pub work: Option<PathBuf>,
    /// Where the merged root file system is mounted.
    pub merged: PathBuf,
}

/// What a writable layer is made with (`CreateReadWrite`'s `StorageOpt` of
/// containers/storage).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WritableOptions {
    /// The most bytes the layer may hold (`--storage-opt size=`; the
    /// quota itself is a driver's own mechanism).  A driver that has none
    /// refuses a limit that is asked for: an explicit request is never
    /// silently weakened.  None: no limit (all the engine asks today).
    pub size_limit: Option<u64>,
}

/// How the changes of a writable layer are read, whatever the driver: the
/// generic part of what `commit`, `diff`, a build step and a checkpoint ask
/// (what the driver adds is how the layer says what changed).
#[derive(Debug, Clone, Default)]
pub struct DiffOptions {
    /// Paths (`/etc/hosts`, the mount points of a RUN) that are not
    /// changes.
    pub exclude: Vec<String>,
    /// The mappings of the user namespace of the container: the files get
    /// the ids the container sees (and `apply` does the opposite).  Empty:
    /// the ids are used as they are.
    pub uid_map: Vec<IdRange>,
    pub gid_map: Vec<IdRange>,
    /// The times of the files of the layer.
    pub mtime: Mtime,
    /// When the layer has an entry for the root (`./`).
    pub root: dirtar::Root,
}

impl From<&dirtar::Options> for DiffOptions {
    /// The generic part of the options of a walk (`lower` is the driver's).
    fn from(o: &dirtar::Options) -> Self {
        Self {
            exclude: o.exclude.clone(),
            uid_map: o.uid_map.clone(),
            gid_map: o.gid_map.clone(),
            mtime: o.mtime,
            root: o.root,
        }
    }
}

impl DiffOptions {
    /// The maps of the user namespace, as the extraction of a layer takes
    /// them (`apply`, the squash of a driver without an overlay upper).
    pub fn id_maps(&self) -> velarx_wire::cp::IdMaps {
        let ranges = |r: &[IdRange]| r.iter().map(|r| (r.container, r.host, r.size)).collect();
        velarx_wire::cp::IdMaps {
            uids: ranges(&self.uid_map),
            gids: ranges(&self.gid_map),
        }
    }

    /// The owner of what an extraction makes where the archive's owner is
    /// not mapped: the root of the container as the host sees it.
    pub fn root_owner(&self) -> (u32, u32) {
        self.id_maps().to_host(0, 0).unwrap_or((0, 0))
    }

    /// The options of a walk of a directory, with the image below it when the
    /// overlay needs it.
    pub fn walk(&self, lower: Option<Arc<dirtar::Lower>>) -> dirtar::Options {
        dirtar::Options {
            lower,
            exclude: self.exclude.clone(),
            uid_map: self.uid_map.clone(),
            gid_map: self.gid_map.clone(),
            mtime: self.mtime,
            root: self.root,
            ..Default::default()
        }
    }
}

/// The changes of the writable layer of a container, as the engine asks for
/// them: the driver that reads the layer, the layer, and the image below it
/// (what the driver may need to tell what changed).  The options of a walk
/// are given by each call (a build step adds its mount points, a build its
/// times).
#[derive(Clone)]
pub struct WritableDiff {
    driver: Arc<dyn StorageDriver>,
    writable: Writable,
    lower: Option<Arc<dyn ImageTree>>,
}

impl WritableDiff {
    pub fn new(
        driver: Arc<dyn StorageDriver>,
        writable: Writable,
        lower: Option<Arc<dyn ImageTree>>,
    ) -> Self {
        Self {
            driver,
            writable,
            lower,
        }
    }

    /// The changes as the tar stream of a layer ([`StorageDriver::diff`]).
    pub fn write(&self, walk: &dirtar::Options, out: &mut dyn HoleWrite) -> std::io::Result<()> {
        self.driver
            .diff(&self.writable, self.lower.clone(), &walk.into(), out)
            .map_err(DriverError::into_io)
    }

    /// The list of the changes, sorted by path ([`StorageDriver::changes`]).
    pub fn changes(&self, walk: &dirtar::Options) -> std::io::Result<Vec<(String, Change)>> {
        self.driver
            .changes(&self.writable, self.lower.clone(), &walk.into())
            .map_err(DriverError::into_io)
    }

    /// Write the layer `tar` into the writable layer
    /// ([`StorageDriver::apply`]).
    pub fn apply(&self, walk: &dirtar::Options, tar: &mut dyn Read) -> std::io::Result<()> {
        self.driver
            .apply(&self.writable, &walk.into(), tar)
            .map_err(DriverError::into_io)
    }

    /// The changes as a directory in the overlay's form (whiteouts, opaque
    /// directories), for what reads them as a directory itself: `commit
    /// --squash` and the squash of a build (`squash::Upper`, `squash::merge`).
    /// The upper directory of an overlay is that directory already; for a
    /// driver whose layer is not one, the tar of [`StorageDriver::diff`] is
    /// extracted into a directory of `scratch`, the way `apply` writes a
    /// layer, and it is removed with the result.
    pub fn directory(&self, walk: &dirtar::Options, scratch: &Path) -> std::io::Result<ChangesDir> {
        if self.driver.capabilities().overlay_upper {
            let upper = self.driver.writable_paths(&self.writable).upper;
            let lower = self.lower.clone().map(|tree| {
                Arc::new(dirtar::Lower {
                    tree,
                    objects: Arc::new(DriverObjects::new(self.driver.clone())),
                })
            });
            let mut o = walk.clone();
            o.lower = lower;
            return Ok(ChangesDir {
                path: upper,
                walk: o,
                _scratch: None,
            });
        }
        self.directory_of_tar(walk, scratch)
    }

    /// The changes made a directory by extracting their tar (what `directory`
    /// does for a driver that has no upper directory).
    pub fn directory_of_tar(
        &self,
        walk: &dirtar::Options,
        scratch: &Path,
    ) -> std::io::Result<ChangesDir> {
        use velarx_content::layer::holes::SparseFile;
        std::fs::create_dir_all(scratch)?;
        let dir = tempfile::tempdir_in(scratch)?;
        let mut tar = SparseFile::new(tempfile::tempfile_in(scratch)?);
        self.write(walk, &mut tar)?;
        let tar = tar.finish()?;
        let opts = DiffOptions::from(walk);
        let (maps, root) = (opts.id_maps(), opts.root_owner());
        let fd = rustix::fs::openat(
            rustix::fs::CWD,
            dir.path(),
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )?;
        // (a plain root, the one a container has when the tar has no entry
        // for it: the entry replaces these; a walk that gives no root has
        // no use for it)
        if walk.root != dirtar::Root::Never {
            rustix::fs::fchmod(&fd, rustix::fs::Mode::from_raw_mode(0o755))?;
            rustix::fs::fchown(
                &fd,
                Some(rustix::fs::Uid::from_raw(root.0)),
                Some(rustix::fs::Gid::from_raw(root.1)),
            )?;
        }
        let ex = velarx_wire::cp::ExtractOptions {
            archive_owners: Some(maps),
            owner: Some(root),
            overlay_upper: true,
            layer: true,
            ..Default::default()
        };
        velarx_wire::cp::extract(tar, rustix::fd::AsFd::as_fd(&fd), &ex)?;
        let mut o = walk.clone();
        // (the tar says what changed: nothing is compared with the image
        // again)
        o.lower = None;
        Ok(ChangesDir {
            path: dir.path().to_path_buf(),
            walk: o,
            _scratch: Some(dir),
        })
    }
}

/// A directory of the changes of a writable layer in the overlay's form, and
/// the options to walk it.  What was made for it is removed when it is
/// dropped.
pub struct ChangesDir {
    pub path: PathBuf,
    pub walk: dirtar::Options,
    _scratch: Option<tempfile::TempDir>,
}

impl ChangesDir {
    /// A directory of changes that is not the driver's (a build step's).
    pub fn of(path: PathBuf, walk: dirtar::Options) -> Self {
        Self {
            path,
            walk,
            _scratch: None,
        }
    }
}

/// What mends an artifact that is missing or wrong, a volume that is gone or a
/// layer the store does not have: the words of the message end with it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Remedy {
    /// The image is pulled again.
    PullAgain,
    /// `velarx system check --repair` makes the artifacts again from what the
    /// driver keeps.
    Repair,
    /// The container is removed and created again: what it wrote in its
    /// writable layer is lost with it.
    RecreateContainer,
}

impl Remedy {
    /// The words a message ends with; `many`: it is about several artifacts.
    pub fn text(self, many: bool) -> &'static str {
        match (self, many) {
            (Remedy::PullAgain, _) => "pull the image again",
            (Remedy::Repair, false) => "`velarx system check --repair` makes it again",
            (Remedy::Repair, true) => "`velarx system check --repair` makes them again",
            (Remedy::RecreateContainer, _) => {
                "remove the container and create it again (what it wrote is lost with it)"
            }
        }
    }
}

/// Why a driver failed.  The message is what the user reads (it carries the
/// remedy where there is one); the kind is what the engine matches on.
#[derive(Debug, thiserror::Error)]
#[error("{message}")]
pub struct DriverError {
    pub driver: String,
    pub kind: DriverErrorKind,
    /// The layer it is about.
    pub layer: Option<String>,
    message: String,
}

/// The kinds of error of a driver.  `Contradicted`, `DigestEnforced` and
/// `Refused` are verdicts of the engine.
#[derive(Debug)]
pub enum DriverErrorKind {
    /// An artifact is not there or not recorded; `remedy` mends it.
    Missing { remedy: Remedy },
    /// An artifact is not the one recorded or cannot be read; `remedy`
    /// mends it.
    Corrupt { remedy: Remedy },
    /// The driver cannot do what was asked (a capability it lacks).
    Unsupported,
    /// What was made again is not what the pull recorded.
    Contradicted,
    /// The digests of the artifacts are enforced and cannot be.
    DigestEnforced,
    /// Something the driver was asked for is not there (a pull).
    NotFound,
    /// The call conflicts with one in progress (two creations of one
    /// container's root, a collection while another engine process commits):
    /// it is made again later.
    Busy,
    /// The host refuses the SELinux label that was asked for the files of an
    /// image mount (this user may not put it on a file, or the policy
    /// refuses it): another label, or none, is asked.
    LabelRefused,
    /// An operation of the file system failed.
    Io(std::io::Error),
    /// The engine's own verdict (a check it handed to the driver), passed
    /// through unchanged.
    Refused(Box<ImageError>),
    /// Anything else the driver could not do.
    Storage,
}

impl DriverError {
    fn new(driver: &str, kind: DriverErrorKind, layer: Option<&LayerKey>, message: String) -> Self {
        Self {
            driver: driver.to_owned(),
            kind,
            layer: layer.map(ToString::to_string),
            message,
        }
    }

    /// An artifact that is not there, with its remedy at the end of the
    /// message.
    pub fn missing(
        driver: &str,
        layer: Option<&LayerKey>,
        what: impl std::fmt::Display,
        remedy: Remedy,
    ) -> Self {
        Self::new(
            driver,
            DriverErrorKind::Missing { remedy },
            layer,
            format!("{what}: {}", remedy.text(false)),
        )
    }

    /// Artifacts that cannot be read or are not the recorded ones.
    pub fn corrupt(driver: &str, what: impl std::fmt::Display, remedy: Remedy) -> Self {
        Self::new(
            driver,
            DriverErrorKind::Corrupt { remedy },
            None,
            format!("{what}: {}", remedy.text(true)),
        )
    }

    pub fn storage(driver: &str, message: impl Into<String>) -> Self {
        Self::new(driver, DriverErrorKind::Storage, None, message.into())
    }

    pub fn of(driver: &str, kind: DriverErrorKind, message: impl Into<String>) -> Self {
        Self::new(driver, kind, None, message.into())
    }

    pub fn io(driver: &str, e: std::io::Error) -> Self {
        let message = e.to_string();
        Self::new(driver, DriverErrorKind::Io(e), None, message)
    }

    /// The host refuses the SELinux label asked for the files of a copy.
    pub fn label_refused(driver: &str, what: impl std::fmt::Display) -> Self {
        Self::new(
            driver,
            DriverErrorKind::LabelRefused,
            None,
            what.to_string(),
        )
    }

    /// The engine's verdict, which came back through the driver.
    pub fn refused(driver: &str, e: ImageError) -> Self {
        let message = e.to_string();
        Self::new(driver, DriverErrorKind::Refused(Box::new(e)), None, message)
    }

    /// The text the user reads.
    pub fn message(&self) -> &str {
        &self.message
    }

    /// The remedy the message ends with, if it has one.
    pub fn remedy(&self) -> Option<Remedy> {
        match self.kind {
            DriverErrorKind::Missing { remedy } | DriverErrorKind::Corrupt { remedy } => {
                Some(remedy)
            }
            _ => None,
        }
    }

    /// As the I/O error it is (or wraps), for the callers of streams.
    pub fn into_io(self) -> std::io::Error {
        match self.kind {
            DriverErrorKind::Io(e) => e,
            _ => std::io::Error::other(self.message),
        }
    }
}

impl From<DriverError> for ImageError {
    fn from(e: DriverError) -> Self {
        match e.kind {
            DriverErrorKind::Missing { .. }
            | DriverErrorKind::Corrupt { .. }
            | DriverErrorKind::Unsupported
            | DriverErrorKind::Busy
            | DriverErrorKind::LabelRefused
            | DriverErrorKind::Storage => ImageError::Storage(e.message),
            DriverErrorKind::Contradicted => ImageError::Contradicted(e.message),
            DriverErrorKind::DigestEnforced => ImageError::ComposefsDigest(e.message),
            DriverErrorKind::NotFound => ImageError::NotFound(e.message),
            DriverErrorKind::Io(e) => ImageError::Io(e),
            DriverErrorKind::Refused(e) => *e,
        }
    }
}

/// The result of a driver call.
pub type DriverResult<T> = Result<T, DriverError>;

/// A range of the bytes of one stored object: the read-back of
/// [`StorageDriver::read_objects`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectRange {
    /// The key of the object, as the table of contents of a layer names it
    /// (its fs-verity digest, `fsverity-sha256-12:HEX`).  A key that is no
    /// object's name is `Missing`, whatever else it says.
    pub key: String,
    /// The first byte.
    pub offset: u64,
    /// How many bytes.  The object must have them all: a range that ends past
    /// the end of the object is `Corrupt` (the engine's index says the object
    /// has them), never a short read.
    pub length: u64,
}

impl ObjectRange {
    /// The whole object `key` of `size` bytes.
    pub fn whole(key: impl Into<String>, size: u64) -> Self {
        Self {
            key: key.into(),
            offset: 0,
            length: size,
        }
    }
}

/// What [`StorageDriver::read_objects`] gives the bytes to.
pub trait ObjectSink {
    /// The next bytes of the range `range` (its index in the request): the
    /// bytes of each range come in order and the ranges in the order asked,
    /// each in pieces of any size.  An error ends the read.
    fn data(&mut self, range: usize, bytes: &[u8]) -> std::io::Result<()>;
}

impl<F: FnMut(usize, &[u8]) -> std::io::Result<()>> ObjectSink for F {
    fn data(&mut self, range: usize, bytes: &[u8]) -> std::io::Result<()> {
        self(range, bytes)
    }
}

/// The object `key` of `size` bytes as an unnamed temporary file, read with
/// `read` (a [`StorageDriver::read_objects`]): the default of
/// [`StorageDriver::open_object`] for a driver whose bytes are not local
/// files.
pub fn spool_object(
    driver: &str,
    key: &str,
    size: u64,
    read: impl FnOnce(&[ObjectRange], &mut dyn ObjectSink) -> DriverResult<()>,
) -> DriverResult<std::fs::File> {
    let file = tempfile::tempfile().map_err(|e| DriverError::io(driver, e))?;
    spool_object_into(driver, key, size, file, read)
}

/// [`spool_object`] into `file` (empty, open for reading and writing): a
/// driver that has a directory on disk spools there, not in `TMPDIR`, which
/// may be a tmpfs (memory) and smaller than an object.
pub fn spool_object_into(
    driver: &str,
    key: &str,
    size: u64,
    file: std::fs::File,
    read: impl FnOnce(&[ObjectRange], &mut dyn ObjectSink) -> DriverResult<()>,
) -> DriverResult<std::fs::File> {
    use std::io::{Seek, Write};
    struct Spool(std::fs::File, u64);
    impl ObjectSink for Spool {
        fn data(&mut self, range: usize, bytes: &[u8]) -> std::io::Result<()> {
            if range == 0 {
                self.1 += bytes.len() as u64;
                self.0.write_all(bytes)?;
            }
            Ok(())
        }
    }
    let mut spool = Spool(file, 0);
    // (a second range, the byte after the last: an object of exactly `size`
    // bytes has none, and the read of it is corrupt; one that has it is
    // longer than its index says)
    let probe = ObjectRange {
        key: key.to_string(),
        offset: size,
        length: 1,
    };
    match read(&[ObjectRange::whole(key, size), probe], &mut spool) {
        Ok(()) => {
            return Err(DriverError::corrupt(
                driver,
                format!("the object {key} has more than the {size} bytes its index says"),
                Remedy::PullAgain,
            ))
        }
        Err(e) if matches!(e.kind, DriverErrorKind::Corrupt { .. }) && spool.1 == size => {}
        Err(e) => return Err(e),
    }
    spool.0.rewind().map_err(|e| DriverError::io(driver, e))?;
    Ok(spool.0)
}

/// The objects a driver holds, as what reads a layer back from its table of
/// contents takes them ([`velarx_storage::ObjectOpener`]): every read goes
/// through the driver ([`StorageDriver::open_object`]), never to a path of
/// the engine's own store.
#[derive(Clone)]
pub struct DriverObjects {
    driver: Arc<dyn StorageDriver>,
}

impl DriverObjects {
    pub fn new(driver: Arc<dyn StorageDriver>) -> Self {
        Self { driver }
    }
}

impl velarx_storage::ObjectOpener for DriverObjects {
    fn ordered(
        &self,
        order: &mut dyn FnMut() -> Vec<(String, u64)>,
    ) -> Option<Arc<dyn velarx_storage::ObjectOpener>> {
        self.driver.objects_in_order(order)
    }

    fn object_file(&self, key: &str, size: u64) -> std::io::Result<std::fs::File> {
        self.driver.open_object(key, size).map_err(|e| {
            let kind = match e.kind {
                DriverErrorKind::Missing { .. } | DriverErrorKind::NotFound => {
                    std::io::ErrorKind::NotFound
                }
                DriverErrorKind::Corrupt { .. } => std::io::ErrorKind::InvalidData,
                _ => return e.into_io(),
            };
            std::io::Error::new(kind, e.message().to_string())
        })
    }
}

/// A layer the engine asks the driver about ([`StorageDriver::has_layers`]):
/// the key the driver stores it under, the diff id its image's
/// configuration states for it, and its chain id.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct LayerRef {
    pub key: LayerKey,
    pub diff_id: Digest,
    /// The OCI ChainID of the layer as the top of its stack, computed by the
    /// engine from the diff ids of the image (`velarx_types::chain_ids`).
    /// A chained driver (`Capabilities::layer_chain`) holds a layer under
    /// it; the others ignore it.
    pub chain_id: Digest,
}

/// A storage driver.  See the module documentation.
///
/// The methods that work on files are `async` where they cross onto the
/// blocking pool (they take it themselves, as the code they replace did);
/// the others are plain calls.
#[async_trait]
pub trait StorageDriver: Send + Sync + 'static {
    /// The name of the driver (`[storage] driver` when there is a choice).
    fn name(&self) -> &str;

    /// The name `info` and `inspect` report as the graph driver in the
    /// surfaces of podman and Docker, which tools key on: the name of the
    /// driver in podman's terms (`overlay` for composefs, which in podman is
    /// an option of the overlay driver).
    fn graph_name(&self) -> &str;

    fn capabilities(&self) -> &Capabilities;

    /// What `inspect` of a container reports as `GraphDriver.Data`, as
    /// (name, value) pairs.
    fn graph_data(&self, w: &Writable) -> Vec<(String, String)>;

    /// What the driver reports of itself, as (name, value) pairs.
    fn status(&self) -> Vec<(String, String)>;

    // layers

    /// Pull `layers` from `feed` into the store, durable (two barriers in
    /// process, the engine takes none),
    /// and return the layers pulled with what the driver recorded of each
    /// (what the engine records with them).  The driver says what it wants
    /// of each layer and receives the bytes ([`Incoming`]: a layer the store
    /// partly has is asked for in part, as it always was: partial pulls are
    /// inherent, there is no capability for them); the engine's network
    /// code, the merge of the ranges by their cost, and the checks of every
    /// chunk and of the diff id are the feed's.
    ///
    /// `layers` is the **whole ordered layer list of the image**, the layers
    /// the driver already has included (`FeedLayer::stored`: nothing to fetch
    /// for those, and nothing of them in `Pulled`).  A content keyed driver
    /// (composefs, vfs) fetches the layers that are not stored, each content
    /// once, as it always did; a chained driver (`Capabilities::layer_chain`)
    /// needs the rest: the parent of a layer is the chain id of the one before
    /// it in the list, present or not.
    ///
    /// `settled` is the engine's check of the layers after every layer is
    /// staged and proven and before the driver publishes: it may refuse the
    /// pull (nothing of the layers is visible then, and `has_layers` reports
    /// none of them), and it
    /// hands the driver the identities of the layers, which the driver
    /// stores and records as they are (a driver that made another is
    /// `Contradicted`), and the verdict for the engine, sealed with the id
    /// of the check, which the driver returns in `Pulled::verdict` as it got
    /// it.  A lazy layer's artifacts wait in the staging area until its
    /// completion.  See [`feed`].
    async fn pull(
        &self,
        feed: &Arc<dyn PullFeed>,
        layers: &[FeedLayer],
        settled: Settled,
    ) -> DriverResult<Pulled>;

    /// Which of `layers` the driver has: one answer for each layer asked,
    /// in the order asked (`result[i]` is about `layers[i]`, and the lengths
    /// are equal), true for a layer that is **committed and complete** (what
    /// a pull committed and the engine settled, or a lazy layer's
    /// completion).  A content keyed driver answers the same for equal keys
    /// (and diff ids); a chained one answers for the place of each layer in
    /// its stack.  This is the layer-level "already
    /// stored" question of a pull, answered by the driver and not by the
    /// engine's look at the store: the engine fetches nothing at all of a
    /// layer the driver has (not even its table of contents).
    ///
    /// A layer that is only staged (its pull is not committed: an interrupted
    /// or lazy one), unknown, committed with another diff id than the one
    /// asked (a key is the layer of one content: a layer is the one asked
    /// only when it was proven against that diff id), or committed without
    /// what the engine needs to read it back later (its tar-split: a layer
    /// that push and archives cannot rebuild is pulled again) is not
    /// reported, nor is a layer only a read-only image store has (the images
    /// of this store refer to its layers, whose files it keeps).  A layer in
    /// doubt is fetched again (the pull repairs the store), never reported.
    ///
    /// The answer is one call for a whole pull (the layers of an image,
    /// every one once), with no work of its own for a layer: the drivers of
    /// the engine's files answer from their records, not from the bytes (the
    /// bytes are what `check` reads).  A per-layer artifact that can be made
    /// again from what the layer keeps (the EROFS image of a composefs layer,
    /// from its table of contents) is not looked at either, so a lost one does
    /// not show here by itself: it is made again by `repair` (`system check
    /// --repair`).  A create or an image mount that finds one lost marks the
    /// layer incomplete (the engine clears its tar-split), and then the layer
    /// is not reported: the next pull fetches it again and makes the artifact
    /// (the objects the store has are not downloaded again).  For a chained driver
    /// (`Capabilities::layer_chain`) a layer is held under its chain id: the
    /// same content at two places of a stack is two layers, held or not each
    /// by itself.  The engine still checks that the layers it is told of
    /// have the index it records an image from, whatever the driver says.
    async fn has_layers(&self, layers: &[LayerRef]) -> DriverResult<Vec<bool>>;

    /// Make the artifacts of `layers` again from what the driver keeps (a
    /// repair; the driver reads the tables of contents it needs itself) and
    /// return them for the engine to record, which it checks against the
    /// identities it makes from the tables of contents.  Made again without
    /// harm when they are there: the call is idempotent.
    async fn repair(&self, layers: &[LayerRef]) -> DriverResult<HashMap<LayerKey, LayerArtifact>>;

    /// Make the artifacts of the staged layers of the pull `pull` again:
    /// they must be the ones the pull recorded.
    async fn remake_staged(&self, pull: &str) -> DriverResult<()>;

    /// Read back the bytes of stored objects: each range of each object, by
    /// the key the table of contents of a layer names it by, is given to
    /// `sink` in order.  This is how the engine reads what a driver stores
    /// (it never opens a path of the driver's own): the tar of a layer is
    /// rebuilt from the engine's index (the table of contents and the
    /// tar-split) and these bytes, for push, save and export; peers are
    /// served from them; one file of an image is read for `cp`.  The engine
    /// checks what it needs of the bytes (the diff id of a layer, the key of
    /// a file it copies): a driver is trusted to store, not to be right.
    /// Called on a thread that may block.
    ///
    /// An object that is not there, or a key that is no object's name, is
    /// `Missing` with the remedy [`Remedy::PullAgain`]; an object that has fewer
    /// bytes than a range wants, or that is not a regular file, is
    /// `Corrupt`.  Nothing is given to `sink` for a range after the first
    /// error.
    fn read_objects(&self, ranges: &[ObjectRange], sink: &mut dyn ObjectSink) -> DriverResult<()>;

    /// The object `key`, which the index says has `size` bytes, as a regular
    /// file that holds exactly them (what reads it with a file's calls: the
    /// stream of a layer, the copy of a file out of an image, holes seen).
    /// The default reads it with [`StorageDriver::read_objects`] into an
    /// unnamed temporary file, which is right for a driver whose bytes are
    /// not local files; a driver that has them as files returns the file
    /// itself, opened as safely as `read_objects` does, with no copy.  The
    /// errors are those of `read_objects`.
    fn open_object(&self, key: &str, size: u64) -> DriverResult<std::fs::File> {
        spool_object(self.name(), key, size, |ranges, sink| {
            self.read_objects(ranges, sink)
        })
    }

    /// The objects of a reader that will take `order` (key and size, each
    /// once) in that order, as [`velarx_storage::ObjectOpener`] reads them
    /// (`ordered`), when that is cheaper than [`StorageDriver::open_object`]
    /// for each.  The default
    /// is `None`: the reader opens each object, a driver of local files
    /// opens them with no copy.  `order` is called only if the driver uses it.
    fn objects_in_order(
        &self,
        _order: &mut dyn FnMut() -> Vec<(String, u64)>,
    ) -> Option<Arc<dyn velarx_storage::ObjectOpener>> {
        None
    }

    /// Forget what the driver keeps of a removed image (its startup profile;
    /// the artifacts of its layers go with the layers, at a collection).
    fn remove_image(&self, image_id: &str) -> DriverResult<()>;

    // images

    /// Make what the driver keeps for the image mounted in a container as
    /// its `--mount type=image` number `req.purpose` when the container is
    /// created (a per-container copy of the image; nothing for a driver
    /// whose mount is made of the layers at each start), and say what the
    /// mount is ([`Planned`]: the kind of plan and who maps the ids, with no
    /// descriptor made: the engine writes the plan of the bundle from it and
    /// counts the descriptors a start will pass).  Made again without harm
    /// when it is there.  Costs what a copy costs: this is create time, the
    /// start only calls [`StorageDriver::mounts`].  The volume is removed by
    /// [`StorageDriver::writable_remove`].
    ///
    /// A driver whose `Capabilities::volume` is `None` answers `Unsupported`
    /// (the engine does not ask it: `negotiate` refuses the mount first), and a
    /// request whose purpose is not a volume is a `Storage` error.
    fn image_volume_create(&self, _req: &MountRequest<'_>) -> DriverResult<Planned> {
        let name = self.name();
        Err(DriverError::of(
            name,
            DriverErrorKind::Unsupported,
            format!("the storage driver {name} does not mount images in containers (--mount type=image): use the composefs driver, or copy the files in with --volume"),
        ))
    }

    /// The root file system of a container and the images mounted in it, as
    /// the monitor mounts them for this start: **the only source of mount
    /// descriptors**.  Called at every start, restart of the engine and
    /// restore (never kept: a monitor uses a descriptor once), costs
    /// O(layers), never O(files).  [`Rootfs::fd`] is new at each call, and
    /// `Some` exactly for a [`RootfsPlan::MountFd`] plan; only a root may
    /// answer a `Directory` plan, and a volume a `MountFd` one.  [`Rootfs::idmap`] says who put the mapping that was asked:
    /// `None` when none was, `Mount` only when `idmap_mount` was.
    /// [`Rootfs::label`] says whether the label that was asked is on the
    /// mount.  The root is answered when it was asked, and the volumes in the
    /// order asked; a volume that was never made is `Missing` with the remedy
    /// [`Remedy::RecreateContainer`].
    fn mounts(&self, req: &MountsRequest<'_>) -> DriverResult<Mounts>;

    /// The root file system of the image as its containers see it, read
    /// without mounting a lookup at a time.
    fn image_view(
        &self,
        image_id: &str,
        layers: &[LayerRecord],
    ) -> DriverResult<Arc<dyn ImageTree>>;

    // the writable layer of a container
    //
    // These are plain calls that touch the disk (the callers are on the
    // blocking pool, or do it for a few files).

    /// Make the writable layer of a container, owned by `owner` (the uid and
    /// gid of the root of its user namespace, as the host sees them) when it
    /// has one: the root of the merged tree is the root of the layer.  It is
    /// made again without harm when it is there.  A `size_limit` that
    /// `Capabilities::writable_size_limit` does not allow is `Unsupported`
    /// and leaves no layer.
    ///
    /// `base` is the root file system of the container asked as a mount
    /// request (none: a container of a directory the user gave, `--rootfs`;
    /// its container is `w`).  A driver whose layer is an overlay's upper
    /// directory makes nothing of the image; one that copies the layers makes
    /// its copy of them here (not at pull, not at run: the cost of a
    /// container that is made), with the ids of the user namespace of
    /// `base.mapping`; with no image its layer is an empty directory.  The
    /// answer is what the root will be ([`Planned`], none when there was no
    /// `base`), made with no descriptor.
    fn writable_create(
        &self,
        w: &Writable,
        owner: Option<(u32, u32)>,
        opts: &WritableOptions,
        base: Option<&MountRequest<'_>>,
    ) -> DriverResult<Option<Planned>>;

    /// Where the writable layer is (it need not exist yet).  The engine
    /// reads `upper` only for a driver whose layer is an overlay's upper
    /// directory (`Capabilities::overlay_upper`: the monitor's overlay); it
    /// reaches the files of the root through [`StorageDriver::writable_root`].
    fn writable_paths(&self, w: &Writable) -> WritablePaths;

    /// The root of the writable layer as a directory descriptor: the root
    /// file system as the container sees it, for what the engine writes into
    /// it itself (the user files at create, the label).  The engine opens
    /// everything below it relative to the descriptor, beneath it, and follows
    /// no link (`openat2` with `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS`), so a
    /// path of the host is never resolved again while it is used.
    ///
    /// A directory (`O_PATH` or not) or a detached mount, `O_CLOEXEC`, that
    /// stays valid when the directory it is open on is renamed.  Every call
    /// gives a descriptor of its own.  An error for a layer that was never made
    /// or is removed (`writable_exists` is false).  Costs nothing for a driver
    /// whose layer is a directory of this host (an `open` of it).
    fn writable_root(&self, w: &Writable) -> DriverResult<std::os::fd::OwnedFd>;

    /// The bytes of the files the container wrote (their sizes, nothing is
    /// followed; zero when there are none, and for a layer that was never
    /// made or is removed: the reads of the layer's changes are errors then,
    /// its size is not).  An error is what the driver could not measure at
    /// all; what it could not read of the layer counts as nothing.
    fn writable_size(&self, w: &Writable) -> DriverResult<u64>;

    /// Remove the writable layer and what the driver keeps with it, the
    /// container's image volumes included; nothing is an error when it is not
    /// there.
    fn writable_remove(&self, w: &Writable) -> DriverResult<()>;

    /// Whether the container has a writable layer made (a container that was
    /// never set up has none: it has no changes, and a commit of it makes no
    /// layer).
    fn writable_exists(&self, w: &Writable) -> DriverResult<bool>;

    /// The changes of the writable layer against the image `lower` below it
    /// (none: the container was never set up with an image), as the tar
    /// stream of a layer (`commit`, a build step, the rootfs diff of a
    /// checkpoint): a deletion is a `.wh.` entry, a directory that hides the
    /// image's is opaque, hard links and the ids the container sees are
    /// resolved, the holes of the files are holes of the stream, and the
    /// same layer gives the same stream.  Called on a thread that may block.
    /// How the layer says what changed (the overlay's whiteouts and opaque
    /// directories, metadata only files and redirects that need `lower`) is
    /// the driver's.
    fn diff(
        &self,
        w: &Writable,
        lower: Option<Arc<dyn ImageTree>>,
        opts: &DiffOptions,
        out: &mut dyn HoleWrite,
    ) -> DriverResult<()>;

    /// The same changes as a list of paths (`container diff`, the changes
    /// API), sorted by path; a path that is in the image `lower` is modified,
    /// else added.
    fn changes(
        &self,
        w: &Writable,
        lower: Option<Arc<dyn ImageTree>>,
        opts: &DiffOptions,
    ) -> DriverResult<Vec<(String, Change)>>;

    /// Write the layer `tar` (what `diff` makes: its whiteouts, opaque
    /// directories and hard links) into the writable layer, its ids
    /// translated to the host's by the maps of `opts` (the restore of a
    /// checkpoint's rootfs diff).  Nothing else of `opts` is read.
    fn apply(&self, w: &Writable, opts: &DiffOptions, tar: &mut dyn Read) -> DriverResult<()>;

    /// The file system of a container that does not run, as its writable
    /// layer over the image it reads (`cp`, `export`, the working directory
    /// of a container): the layer is read as the driver's mount would show
    /// it, and what is written goes to the layer.
    fn stopped_view<'a>(
        &self,
        w: &Writable,
        image: TreeSource<'a>,
    ) -> DriverResult<StoppedView<'a>>;

    /// Whether the root of the process whose directory in `/proc` is
    /// `proc_dir` (`/proc/PID`) is the root file system of the container of
    /// `w`: how the engine tells that a pid is the container's (security
    /// relevant: a process of another container, or one that took a reused
    /// pid, must not match).  The driver reads what tells it there: an
    /// overlay the mount of its `root`, a plain directory the inode of it.
    /// The caller has pinned the process (a pidfd) before, and checks that
    /// it still runs after.
    ///
    /// The engine asks this only for a root the monitor recorded nothing of
    /// (an overlay): for a root that is a mount descriptor or a directory
    /// plan it compares the process's root with the one the monitor attached
    /// (`velarx_wire::monitor::rootid`), since a driver may make a new mount at
    /// every start, and a later `mounts` is another one.
    fn is_root_of(&self, w: &Writable, proc_dir: &Path) -> DriverResult<bool>;

    // maintenance

    /// What is wrong with what the driver made of the layers of `image`;
    /// `full` reads it and compares it with what the tables of contents
    /// make.
    async fn check(
        &self,
        image: &ImageRecord,
        layers: &[LayerRecord],
        full: bool,
    ) -> DriverResult<Vec<Problem>>;

    /// The files of the driver's own artifacts that nothing accounts for and
    /// that have not changed for `grace` (a pull that runs may be writing
    /// one), with why each is one.  The objects of the engine's store are the
    /// engine's to scan.
    async fn leftovers(&self, grace: std::time::Duration) -> DriverResult<Vec<(PathBuf, String)>>;

    /// Remove what the driver holds that is not of what `keep` names, and
    /// what an interrupted pull left.
    fn collect(&self, keep: &Keep) -> DriverResult<Collected>;

    /// Which of `layers` something uses right now (a kernel mount of the
    /// image of the layer, an image server that serves it), found without
    /// waiting and without a race with a mount: for the others it takes
    /// what a new use would have to take first and gives it back in
    /// [`UnusedLayers::hold`], so the caller removes them with no mount made
    /// meanwhile.  A failure to tell is an error: a layer is never taken for
    /// unused when it is not known to be.  A driver that mounts nothing uses
    /// none.
    fn lock_unused_layers(&self, layers: &[LayerKey]) -> DriverResult<UnusedLayers> {
        let _ = layers;
        Ok(UnusedLayers::default())
    }

    /// What the driver holds on the disk for itself (the engine measures the
    /// content of the images).
    fn usage(&self) -> DriverResult<Usage>;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The remedy of today's messages is in the text the user reads and is
    /// said by the error; the kinds map to the errors of the engine they
    /// were before the trait.
    #[test]
    fn errors_keep_their_remedy_and_their_engine_kind() {
        let key: LayerKey = LayerKey::Whole(format!("sha256:{}", "ab".repeat(32)).parse().unwrap());
        let e = DriverError::missing(
            "composefs",
            Some(&key),
            format!("image 1234: the EROFS image of the layer {key} is not there"),
            Remedy::Repair,
        );
        assert_eq!(e.remedy(), Some(Remedy::Repair));
        assert_eq!(e.layer.as_deref(), Some(key.to_string().as_str()));
        assert!(e
            .to_string()
            .ends_with("`velarx system check --repair` makes it again"));
        match ImageError::from(e) {
            ImageError::Storage(m) => assert!(m.contains("is not there")),
            other => panic!("{other:?}"),
        }
        let e = DriverError::corrupt(
            "composefs",
            "the EROFS images cannot be read",
            Remedy::Repair,
        );
        assert!(e.message().ends_with("makes them again"));
        assert!(matches!(ImageError::from(e), ImageError::Storage(_)));
        assert!(matches!(
            ImageError::from(DriverError::of("d", DriverErrorKind::Contradicted, "x")),
            ImageError::Contradicted(_)
        ));
        assert!(matches!(
            ImageError::from(DriverError::of("d", DriverErrorKind::DigestEnforced, "x")),
            ImageError::ComposefsDigest(_)
        ));
        assert!(matches!(
            ImageError::from(DriverError::of("d", DriverErrorKind::NotFound, "x")),
            ImageError::NotFound(_)
        ));
        // the engine's own verdict comes back as it went
        let verdict = ImageError::Manifest("the manifest says no".into());
        let e = DriverError::refused("composefs", verdict);
        assert!(
            matches!(ImageError::from(e), ImageError::Manifest(m) if m == "the manifest says no")
        );
        // an I/O error stays one
        let e = DriverError::io("composefs", std::io::Error::from_raw_os_error(2));
        assert!(matches!(&e.kind, DriverErrorKind::Io(_)));
        assert_eq!(e.into_io().raw_os_error(), Some(2));
    }
}
