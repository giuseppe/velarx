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
//! the layers for each container) and `varlink` (a driver in a program of its
//! own behind `org.velarx.Storage`, such as `velarx-storage-server`).
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
//! `docs/STORAGE.md` has the whole interface, with the wire call or the
//! engine-side form of every method.

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
pub mod keep;
pub mod longcall;
pub mod negotiate;
pub mod objects;
pub mod prefs;
pub mod stores;
pub mod unused;
pub use blocking::blocking;
pub use cpview::StoppedView;
pub use feed::{
    is_pull_id, new_pull_id, prove_by_read_back, prove_with, to_fetch, CheckId, Checked,
    ContentFeed, FeedLayer, FilesIncoming, Identities, InProcess, Incoming, LayerIndex,
    LocalContent, PullFeed, Pulled, PulledLayer, SessionIncoming, Settled, Settlement, StagedFeed,
    StoreContent, Verdict, Wanted,
};
pub use imagecopy::TreeSource;
pub use prefs::Prefs;
pub use stores::{StoreId, StoreInfo};

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

/// The limits of the interface that the engine applies to a driver, and that
/// a driver states in `GetInfo` (`limits`).  A request that would exceed one
/// is split by the engine, never sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// The most bytes of one message (the JSON of a call or a reply).
    pub message: usize,
    /// The most descriptors of one message.
    pub fds: usize,
    /// The most layers one `Fetch` asks for.
    pub wants: usize,
    /// The most ranges of one `ReadObjects`.
    pub ranges: usize,
}

impl Limits {
    /// The limits of version 1 of the interface.
    pub const V1: Limits = Limits {
        message: velarx_wire::varlink::MAX_MESSAGE,
        fds: velarx_wire::varlink::MAX_FDS,
        wants: 4096,
        ranges: 4096,
    };
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
    /// The limits of the calls the engine makes to it.
    pub limits: Limits,
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

    /// The name of the kind: what `system check` reports and the wire carries.
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

    /// The kind a name stands for.  A name this build does not know is an
    /// error that names it (a `Storage` one), never a protocol error: a
    /// driver of a later version may have more kinds.
    pub fn from_wire(driver: &str, name: &str) -> DriverResult<Self> {
        Self::ALL
            .into_iter()
            .find(|k| k.as_str() == name)
            .ok_or_else(|| {
                DriverError::unknown_value(driver, "the problem kind", format!("{name:?}"))
            })
    }
}

/// A problem a check found with what a driver made of an image.
#[derive(Debug, Clone)]
pub struct Problem {
    pub kind: ProblemKind,
    pub message: String,
    /// The layer it is about, when it is about one.
    pub layer: Option<LayerKey>,
    /// The file it is about, when the driver has one (a remote store has
    /// none to name).
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

/// What still needs the copy of its own files that a driver with a lazy phase
/// keeps of the layers of an image that was pulled lazily
/// ([`StorageDriver::release_engine_copies`]).
#[derive(Debug, Clone, Default)]
pub struct EngineHeld {
    /// The containers that exist, by id: one whose root the driver serves
    /// itself needs the copy of the layers of its image for as long as it
    /// exists.
    pub containers: Vec<String>,
    /// The layers of the pulls in progress: a container can still be made on
    /// them.
    pub layers: Vec<LayerKey>,
    /// The files those layers name (by fs-verity digest).
    pub files: std::collections::HashSet<String>,
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

impl MountsRequest<'_> {
    /// The container the mounts are of (none when nothing is asked): the
    /// one `Mounts` call of the wire names.  Mounts of two containers in one
    /// request are an error, never sent as the first one's.
    pub fn container(&self, driver: &str) -> DriverResult<Option<&Writable>> {
        let mut all = self.root.iter().chain(&self.volumes).map(|m| m.container);
        let Some(first) = all.next() else {
            return Ok(None);
        };
        match all.find(|w| w.id() != first.id() || w.bundle() != first.bundle()) {
            Some(other) => Err(DriverError::storage(
                driver,
                format!(
                    "one request asks for mounts of the containers {} and {}",
                    first.id(),
                    other.id()
                ),
            )),
            None => Ok(Some(first)),
        }
    }
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
    /// [`VerityDone::None`] only from a driver of the engine's own process
    /// (a driver reached over the wire never claims it: the engine cannot
    /// check what it did), and exactly for a [`RootfsPlan::MountFd`] when the
    /// request was [`VerityAsk::Enforce`] (the engine refuses a mount that
    /// carries none then; the other kinds of plan are measured by the
    /// monitor).
    pub verity: VerityDone,
    /// With `verity` not `None`: the fs-verity digest the driver measured on
    /// the EROFS image of each layer of the request, in the order of the
    /// layers, each one of the digests the request accepted for it.  The
    /// engine checks that, and says the links of the chain of trust from it.
    pub measured: Vec<String>,
    /// A process that serves the mount (a file system server), as a pidfd:
    /// in-process drivers only, never on the wire.  The engine refuses an
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

/// The descriptors of the reply of a call that hands over several mounts,
/// given to the mounts by the position each says it has among the descriptors
/// of the reply (the wire's `Mounted.fd`): a position that is out of the
/// reply, used twice, or a descriptor no mount names, is an error (a reply
/// that numbers its mounts wrongly is refused, never guessed at).
pub fn assign_fds(
    driver: &str,
    positions: &[Option<usize>],
    fds: Vec<std::os::fd::OwnedFd>,
) -> DriverResult<Vec<Option<std::os::fd::OwnedFd>>> {
    let mut slots: Vec<Option<std::os::fd::OwnedFd>> = fds.into_iter().map(Some).collect();
    let total = slots.len();
    let mut out = Vec::with_capacity(positions.len());
    for (n, p) in positions.iter().enumerate() {
        let Some(p) = p else {
            out.push(None);
            continue;
        };
        let fd = slots.get_mut(*p).ok_or_else(|| {
            DriverError::storage(
                driver,
                format!("mount {n} names the descriptor {p}, and the reply has {total}"),
            )
        })?;
        out.push(Some(fd.take().ok_or_else(|| {
            DriverError::storage(driver, format!("the descriptor {p} is named by two mounts"))
        })?));
    }
    if let Some(left) = slots.iter().position(Option::is_some) {
        return Err(DriverError::storage(
            driver,
            format!("the descriptor {left} of the reply is named by no mount"),
        ));
    }
    Ok(out)
}

/// The writable layer of one container: what the driver is asked to make,
/// find, measure and remove.  It names the container and its bundle; where
/// the layer is, and what it is made of, is the driver's to say
/// ([`StorageDriver::writable_paths`]): the engine never builds those paths.
/// What it takes to remove the writable layer of a container without the
/// driver: the monitor of an `--rm` container does it from its own thread.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum WritableRelease {
    /// It goes with the bundle (composefs, vfs); `pin`: the pin of the lazy
    /// phase of the engine, which goes with it
    InBundle { pin: Option<PathBuf> },
    /// The storage service holds it: `RemoveRoot` of the store `store`
    /// through `socket`, and then the pin of the container (the lazy phase of
    /// the engine) when there is one
    Service {
        socket: PathBuf,
        timeout_secs: u64,
        store: String,
        pin: Option<PathBuf>,
    },
}

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
}

impl From<&dirtar::Options> for DiffOptions {
    /// The generic part of the options of a walk (`lower` is the driver's).
    fn from(o: &dirtar::Options) -> Self {
        Self {
            exclude: o.exclude.clone(),
            uid_map: o.uid_map.clone(),
            gid_map: o.gid_map.clone(),
            mtime: o.mtime,
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
        // again; the root of the directory is not the container's)
        o.lower = None;
        o.root = dirtar::Root::Never;
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
/// layer the store does not have: the words of the message end with it, and
/// the wire carries its name (`pull_again`, `repair`, `recreate_container`).
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

    /// The name of the remedy on the wire.
    pub fn wire_name(self) -> &'static str {
        match self {
            Remedy::PullAgain => "pull_again",
            Remedy::Repair => "repair",
            Remedy::RecreateContainer => "recreate_container",
        }
    }

    /// The remedy a wire name stands for; none for a name this build does not
    /// know (the error is then a plain `Storage` one, see
    /// [`DriverError::from_wire`]).
    pub fn from_wire_name(name: &str) -> Option<Self> {
        [Remedy::PullAgain, Remedy::Repair, Remedy::RecreateContainer]
            .into_iter()
            .find(|r| r.wire_name() == name)
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

/// The kinds of error of a driver.  A remote driver sends `Missing`,
/// `Corrupt`, `Unsupported`, `NotFound`, `Busy`, `LabelRefused`, `Unavailable` (its own
/// backend does not answer) and `Storage` (the last one for every error name
/// the client does not know); `Unavailable` (connect refused, the socket
/// gone), `TimedOut` and `ProtocolMismatch` are also what the client makes of
/// a failed transport;
/// `Contradicted`, `DigestEnforced` and `Refused` are verdicts of the engine
/// and a driver never sends them.
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
    /// The backend cannot be reached (connection refused, socket gone): the
    /// storage service is started.
    Unavailable,
    /// The backend did not answer within the deadline (`[storage.varlink]
    /// timeout_secs`).
    TimedOut,
    /// The backend speaks another version of the interface: one side is
    /// upgraded.
    ProtocolMismatch,
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

    /// The backend does not answer the connection.
    pub fn unavailable(driver: &str, what: impl std::fmt::Display) -> Self {
        Self::new(
            driver,
            DriverErrorKind::Unavailable,
            None,
            format!("{what}: start the storage service"),
        )
    }

    /// The backend did not answer `call` within `secs` seconds.
    pub fn timed_out(driver: &str, call: &str, secs: u64) -> Self {
        Self::new(
            driver,
            DriverErrorKind::TimedOut,
            None,
            format!("the storage service did not answer {call} in {secs} s: raise `[storage.varlink] timeout_secs`, or look at why the service is slow"),
        )
    }

    /// The backend speaks `theirs`, this build `ours`.
    pub fn protocol_mismatch(driver: &str, theirs: &str, ours: &str) -> Self {
        Self::new(
            driver,
            DriverErrorKind::ProtocolMismatch,
            None,
            format!("the storage service speaks {theirs} and velarx {ours}: upgrade the driver or velarx so that both speak the same"),
        )
    }

    /// A value of an enum in a reply that this build does not know (a driver
    /// of a later minor version): a `Storage` error that names it, never a
    /// protocol error.  The engine asks only for what it can take, so a driver
    /// that answers another value says it cannot do what was asked.
    pub fn unknown_value(driver: &str, what: &str, value: impl std::fmt::Display) -> Self {
        Self::storage(
            driver,
            format!("the storage service answered {what} {value}, which this version of velarx does not know"),
        )
    }

    /// The error a remote driver sent, by the name it gave it: `missing` and
    /// `corrupt` with their `remedy` (a name this build does not know is
    /// none: `Repair` is not assumed), `unsupported`, `not_found`, `busy`,
    /// `unavailable` (the driver's own backend does not answer) and `failed`.
    /// Any other name, and one the engine alone gives (`contradicted`,
    /// `digest_enforced`, `refused`), is a `Storage` error that names it.
    pub fn from_wire(
        driver: &str,
        name: &str,
        reason: &str,
        layer: Option<&str>,
        remedy: Option<&str>,
    ) -> Self {
        let remedy = remedy.and_then(Remedy::from_wire_name);
        let kind = match (name, remedy) {
            ("missing", Some(remedy)) => DriverErrorKind::Missing { remedy },
            ("corrupt", Some(remedy)) => DriverErrorKind::Corrupt { remedy },
            ("unsupported", _) => DriverErrorKind::Unsupported,
            ("not_found", _) => DriverErrorKind::NotFound,
            ("busy", _) => DriverErrorKind::Busy,
            ("unavailable", _) => DriverErrorKind::Unavailable,
            ("label_refused", _) => DriverErrorKind::LabelRefused,
            ("storage" | "failed", _) => DriverErrorKind::Storage,
            _ => {
                return Self {
                    driver: driver.to_owned(),
                    kind: DriverErrorKind::Storage,
                    layer: layer.map(str::to_string),
                    message: format!("{reason} (the storage service answered {name:?})"),
                }
            }
        };
        Self {
            driver: driver.to_owned(),
            kind,
            layer: layer.map(str::to_string),
            message: reason.to_string(),
        }
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
            | DriverErrorKind::Unavailable
            | DriverErrorKind::TimedOut
            | DriverErrorKind::ProtocolMismatch
            | DriverErrorKind::Storage => ImageError::Storage(e.message),
            DriverErrorKind::Contradicted => ImageError::Contradicted(e.message),
            DriverErrorKind::DigestEnforced => ImageError::ComposefsDigest(e.message),
            DriverErrorKind::NotFound => ImageError::NotFound(e.message),
            DriverErrorKind::Io(e) => ImageError::Io(e),
            DriverErrorKind::Refused(e) => *e,
        }
    }
}

/// The error of a driver that keeps one store, the engine's own, asked to list
/// or drop one by name.
fn single_store(driver: &str) -> DriverError {
    DriverError::of(
        driver,
        DriverErrorKind::Unsupported,
        format!(
            "the storage driver {driver} keeps the one store of this graph root, which is removed with it, not by name"
        ),
    )
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

/// [`StorageDriver::read_objects`] for any number of ranges: the list is split
/// in calls of at most `max` ranges (`Limits::ranges`, which a message of a
/// remote driver is bounded by), made in order, and `sink` gets the index of
/// the range in the whole list, the ranges in the order asked.
pub fn read_objects_in_batches(
    driver: &dyn StorageDriver,
    ranges: &[ObjectRange],
    sink: &mut dyn ObjectSink,
) -> DriverResult<()> {
    let max = driver.capabilities().limits.ranges;
    batches(ranges, max, sink, |batch, sink| {
        driver.read_objects(batch, sink)
    })
}

fn batches(
    ranges: &[ObjectRange],
    max: usize,
    sink: &mut dyn ObjectSink,
    mut call: impl FnMut(&[ObjectRange], &mut dyn ObjectSink) -> DriverResult<()>,
) -> DriverResult<()> {
    for (n, batch) in ranges.chunks(max.max(1)).enumerate() {
        let first = n * max.max(1);
        let mut shifted = |range: usize, bytes: &[u8]| sink.data(first + range, bytes);
        call(batch, &mut shifted)?;
    }
    Ok(())
}

/// The object `key` of `size` bytes as an unnamed temporary file, read with
/// `read` (a [`StorageDriver::read_objects`]): the default of
/// [`StorageDriver::open_object`] for a driver whose bytes are not local
/// files, and what a client of a driver in another process reads a staged
/// object with.
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

    /// Pull `layers` from `feed` into the store, durable with one barrier,
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
    /// layer the driver has (not even its table of contents), and a driver
    /// that is not the engine's files (a program behind a socket) says what
    /// it has by key and diff id.
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

    /// Read back the bytes of stored objects: at most `Limits::ranges` ranges
    /// in one call (the engine splits a longer list with
    /// [`read_objects_in_batches`]); each range of each object, by
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
    /// for each: a driver whose bytes are behind a socket reads the next
    /// objects of the list with one [`StorageDriver::read_objects`] (up to
    /// its limits) and hands them over as they are asked for.  The default
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

    /// Whether the objects of the layers are files of the engine's own file
    /// store (`composefs`, `vfs`).  A driver of another process keeps its
    /// own, which the engine cannot find or check by a path: `system check`
    /// leaves them to the driver's `check`.
    fn holds_objects(&self) -> bool {
        true
    }

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

    /// How the layer is removed without this driver (see
    /// [`WritableRelease`]): with the bundle, unless the driver says
    /// otherwise.
    fn writable_release(&self, _w: &Writable) -> WritableRelease {
        WritableRelease::InBundle { pin: None }
    }

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
    /// overlay its `mountinfo`, a plain directory the inode of its `root`.
    /// The caller has pinned the process (a pidfd) before, and checks that
    /// it still runs after.
    ///
    /// The engine asks this only for a root the monitor recorded nothing of
    /// (an overlay): for a root that is a mount descriptor or a directory
    /// plan it compares the process's root with the one the monitor attached
    /// (`velarx_wire::monitor::rootid`), since a driver may make a new mount at
    /// every start, and a later `mounts` is another one.  The method has no
    /// wire call.
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
    /// engine's to scan: a remote driver has no file the engine could name.
    async fn leftovers(&self, grace: std::time::Duration) -> DriverResult<Vec<(PathBuf, String)>>;

    /// Remove what the driver holds that is not of what `keep` names, and
    /// what an interrupted pull left.
    fn collect(&self, keep: &Keep) -> DriverResult<Collected>;

    /// Drop the driver's own copy of the files of `layers` (every layer it
    /// holds a copy of) that nothing in `held` needs: the
    /// objects and the images of the layers it made while their image was
    /// being pulled, which a driver in another process has itself once the
    /// layers are in it.  A copy is dropped only when no container whose root
    /// the driver serves, and no pull in progress, names the layer; a file a
    /// layer that stays names too stays.  The caller holds the store lock
    /// exclusive (no create is between its first call to the driver and its
    /// row), and calls it again for what an interrupted call left: it can be
    /// repeated from any point.  A driver with no copy of its own has nothing
    /// to release.
    async fn release_engine_copies(
        &self,
        layers: &[LayerKey],
        held: &EngineHeld,
    ) -> DriverResult<Collected> {
        let _ = (layers, held);
        Ok(Collected::default())
    }

    /// Which of `layers` something uses right now (a kernel mount of the
    /// image of the layer, an image server that serves it), found without
    /// waiting and without a race with a mount: for the others it takes
    /// what a new use would have to take first and gives it back in
    /// [`UnusedLayers::hold`], so the caller removes them with no mount made
    /// meanwhile.  A failure to tell is an error: a layer is never taken for
    /// unused when it is not known to be.  A driver that mounts nothing (or
    /// whose layers are in another process, which keeps its own) uses none.
    fn lock_unused_layers(&self, layers: &[LayerKey]) -> DriverResult<UnusedLayers> {
        let _ = layers;
        Ok(UnusedLayers::default())
    }

    /// What the driver holds on the disk for itself (the engine measures the
    /// content of the images).
    fn usage(&self) -> DriverResult<Usage>;

    /// The stores the driver holds, for the one that serves several (a driver
    /// in another process, which keeps the data of every engine that connects):
    /// each with what it takes and when an
    /// engine last opened it, so that an administrator can find a store that
    /// no engine opens any more (a graph root that was deleted, and with it the
    /// file that names the store: [`StoreId`]).  A driver isolates the stores
    /// by the pair (peer uid, store), and lists those of the caller's uid.  The
    /// driver of a single store, the engine's own, has nothing to list:
    /// `Unsupported`.
    fn list_stores(&self) -> DriverResult<Vec<StoreInfo>> {
        Err(single_store(self.name()))
    }

    /// Remove a store and everything the driver holds under it (layers, roots,
    /// image mounts, staging) and the record that it exists.  Idempotent: a
    /// store that is not there is dropped.  The caller must be sure no engine
    /// uses it (a driver refuses a store with a pull or a container in
    /// progress as `busy`).  `Unsupported` for a driver of a single store.
    fn drop_store(&self, store: &str) -> DriverResult<()> {
        let _ = store;
        Err(single_store(self.name()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// More ranges than a call takes are split in calls of at most the limit,
    /// made in order, and the sink gets the index of each range in the whole
    /// list.
    #[test]
    fn many_ranges_are_read_in_calls_of_the_limit() {
        let ranges: Vec<ObjectRange> = (0..10_000)
            .map(|n| ObjectRange {
                key: format!("k{n}"),
                offset: n,
                length: 1,
            })
            .collect();
        let mut sizes = Vec::new();
        let mut got = Vec::new();
        let mut sink = |range: usize, bytes: &[u8]| {
            got.push((range, bytes.to_vec()));
            Ok(())
        };
        batches(&ranges, 4096, &mut sink, |batch, sink| {
            sizes.push(batch.len());
            for (i, r) in batch.iter().enumerate() {
                // (the bytes of a range say which range it is)
                sink.data(i, r.key.as_bytes())
                    .map_err(|e| DriverError::io("d", e))?;
            }
            Ok(())
        })
        .unwrap();
        assert_eq!(sizes, [4096, 4096, 1808]);
        assert_eq!(got.len(), 10_000);
        for (n, (range, bytes)) in got.iter().enumerate() {
            assert_eq!((*range, bytes.as_slice()), (n, format!("k{n}").as_bytes()));
        }
        // an error ends the read at the call that has it
        let mut calls = 0;
        let e = batches(&ranges, 4096, &mut |_: usize, _: &[u8]| Ok(()), |_, _| {
            calls += 1;
            Err(DriverError::storage("d", "gone"))
        });
        assert!(e.is_err() && calls == 1);
        // nothing asked, nothing called
        batches(&[], 4096, &mut |_: usize, _: &[u8]| Ok(()), |_, _| panic!()).unwrap();
    }

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

    /// A remote driver's errors: the names the engine knows give their kind
    /// and remedy; any other name is a `Storage` error that says it; the
    /// verdicts of the engine are never taken from a driver.
    #[test]
    fn wire_errors_map_to_kinds_and_unknown_names_to_storage() {
        let e = DriverError::from_wire(
            "r",
            "missing",
            "gone",
            Some("sha256:ab"),
            Some("recreate_container"),
        );
        assert_eq!(e.remedy(), Some(Remedy::RecreateContainer));
        assert_eq!(e.layer.as_deref(), Some("sha256:ab"));
        let e = DriverError::from_wire("r", "corrupt", "bad", None, Some("repair"));
        assert!(matches!(
            e.kind,
            DriverErrorKind::Corrupt {
                remedy: Remedy::Repair
            }
        ));
        // a remedy this build does not know does not make a Missing one
        let e = DriverError::from_wire("r", "missing", "gone", None, Some("reboot"));
        assert!(matches!(e.kind, DriverErrorKind::Storage), "{e:?}");
        assert!(e.message().contains("\"missing\""), "{e}");
        assert!(matches!(
            DriverError::from_wire("r", "busy", "x", None, None).kind,
            DriverErrorKind::Busy
        ));
        // (the driver's own backend does not answer)
        assert!(matches!(
            DriverError::from_wire("r", "unavailable", "x", None, None).kind,
            DriverErrorKind::Unavailable
        ));
        for engine_only in [
            "contradicted",
            "digest_enforced",
            "refused",
            "something_new",
        ] {
            let e = DriverError::from_wire("r", engine_only, "x", None, None);
            assert!(matches!(e.kind, DriverErrorKind::Storage), "{engine_only}");
            assert!(e.message().contains(engine_only), "{e}");
        }
        for r in [Remedy::PullAgain, Remedy::Repair, Remedy::RecreateContainer] {
            assert_eq!(Remedy::from_wire_name(r.wire_name()), Some(r));
        }
        assert!(Remedy::RecreateContainer.text(false).contains("lost"));
    }

    /// The failures of the transport say what to do, each its own.
    #[test]
    fn transport_failures_say_their_remedy() {
        let e = DriverError::unavailable("r", "connect /run/s.sock: refused");
        assert!(matches!(e.kind, DriverErrorKind::Unavailable));
        assert!(e.message().ends_with("start the storage service"));
        let e = DriverError::timed_out("r", "Collect", 30);
        assert!(matches!(e.kind, DriverErrorKind::TimedOut));
        assert!(e.message().contains("Collect") && e.message().contains("timeout_secs"));
        let e = DriverError::protocol_mismatch("r", "org.velarx.Storage.2", "org.velarx.Storage.1");
        assert!(matches!(e.kind, DriverErrorKind::ProtocolMismatch));
        assert!(e.message().contains(".2") && e.message().contains("upgrade"));
        for e in [
            DriverError::unavailable("r", "x"),
            DriverError::timed_out("r", "x", 1),
            DriverError::protocol_mismatch("r", "a", "b"),
        ] {
            assert!(matches!(ImageError::from(e), ImageError::Storage(_)));
        }
    }

    /// An unknown problem kind from a driver is a `Storage` error that names
    /// it; the known ones round-trip.
    #[test]
    fn problem_kinds_round_trip_and_unknown_ones_are_named() {
        for k in ProblemKind::ALL {
            assert_eq!(ProblemKind::from_wire("r", k.as_str()).unwrap(), k);
        }
        let e = ProblemKind::from_wire("r", "new_kind").unwrap_err();
        assert!(matches!(e.kind, DriverErrorKind::Storage));
        assert!(e.message().contains("new_kind"));
    }

    fn fd() -> std::os::fd::OwnedFd {
        std::os::fd::OwnedFd::from(std::fs::File::open("/dev/null").unwrap())
    }

    /// The container of a `Mounts` call is the one every mount names; mounts
    /// of two containers are refused, whichever comes first.
    #[test]
    fn a_mounts_request_is_of_one_container() {
        let image = ImageRecord {
            id: "img".into(),
            manifest_digest: Digest::empty(velarx_types::digest::Algorithm::Sha256),
            config_digest: Digest::empty(velarx_types::digest::Algorithm::Sha256),
            manifest: "{}".into(),
            config: "{}".into(),
            created_at: String::new(),
            is_lazy: false,
        };
        let (a, b) = (Writable::new("a", "/b/a"), Writable::new("b", "/b/b"));
        let other_bundle = Writable::new("a", "/elsewhere/a");
        let m = |w: &'static Writable, purpose| MountRequest {
            container: w,
            purpose,
            image: &image,
            layers: &[],
            mapping: None,
            translate: None,
            idmap_mount: false,
            label: None,
            verity: VerityAsk::Off,
            volatile: false,
        };
        // (leaked: the requests borrow them for the test)
        let (a, b, other_bundle): (&'static Writable, &'static Writable, &'static Writable) = (
            Box::leak(Box::new(a)),
            Box::leak(Box::new(b)),
            Box::leak(Box::new(other_bundle)),
        );
        let vol = |n| Purpose::Volume { index: n };
        let none = MountsRequest {
            root: None,
            volumes: vec![],
        };
        assert!(none.container("d").unwrap().is_none());
        let one = MountsRequest {
            root: Some(m(a, Purpose::Root)),
            volumes: vec![m(a, vol(0)), m(a, vol(1))],
        };
        assert_eq!(one.container("d").unwrap().unwrap().id(), "a");
        let volumes_only = MountsRequest {
            root: None,
            volumes: vec![m(b, vol(0))],
        };
        assert_eq!(volumes_only.container("d").unwrap().unwrap().id(), "b");
        for mixed in [
            MountsRequest {
                root: Some(m(a, Purpose::Root)),
                volumes: vec![m(a, vol(0)), m(b, vol(1))],
            },
            MountsRequest {
                root: None,
                volumes: vec![m(b, vol(0)), m(a, vol(1))],
            },
            MountsRequest {
                root: Some(m(a, Purpose::Root)),
                volumes: vec![m(other_bundle, vol(0))],
            },
        ] {
            let e = mixed.container("d").unwrap_err();
            assert!(e.message().contains("one request asks"), "{e}");
        }
    }

    /// The descriptors of a reply go to the mounts that name them, and a
    /// reply that numbers them wrongly is refused.
    #[test]
    fn descriptors_go_to_the_mounts_that_name_them() {
        use std::os::fd::AsRawFd;
        let (a, b) = (fd(), fd());
        let (ra, rb) = (a.as_raw_fd(), b.as_raw_fd());
        // (the second mount is a directory: it names none; the third has the
        // descriptor the first has not)
        let out = assign_fds("r", &[Some(1), None, Some(0)], vec![a, b]).unwrap();
        assert_eq!(out[0].as_ref().unwrap().as_raw_fd(), rb);
        assert!(out[1].is_none());
        assert_eq!(out[2].as_ref().unwrap().as_raw_fd(), ra);
        let e = assign_fds("r", &[Some(0), Some(0)], vec![fd(), fd()]).unwrap_err();
        assert!(e.message().contains("two mounts"), "{e}");
        let e = assign_fds("r", &[Some(2)], vec![fd()]).unwrap_err();
        assert!(e.message().contains("names the descriptor 2"), "{e}");
        let e = assign_fds("r", &[Some(0)], vec![fd(), fd()]).unwrap_err();
        assert!(e.message().contains("named by no mount"), "{e}");
        assert!(assign_fds("r", &[None], vec![]).unwrap()[0].is_none());
    }

    /// Every method of the trait has a wire call or a stated engine-side form
    /// in the table of `docs/STORAGE.md`, and the table names no method the
    /// trait lacks.
    #[test]
    fn every_method_of_the_trait_is_in_the_interface_table() {
        let source = include_str!("lib.rs");
        let trait_text = &source[source.find("pub trait StorageDriver").unwrap()..];
        let trait_text = &trait_text[..trait_text.find("\n}\n").unwrap()];
        let methods: Vec<&str> = trait_text
            .lines()
            .filter_map(|l| {
                let l = l.strip_prefix("    ")?;
                let l = l.strip_prefix("async ").unwrap_or(l);
                let name = l.strip_prefix("fn ")?;
                Some(&name[..name.find(['(', '<'])?])
            })
            .collect();
        assert!(methods.len() > 25, "{methods:?}");
        let doc = include_str!("../../../docs/STORAGE.md");
        let table = &doc[doc.find("### Trait method to wire call").unwrap()..];
        let table = &table[..table.find("What is not in the trait").unwrap()];
        for m in &methods {
            assert!(
                table.contains(&format!("`{m}`")),
                "docs/STORAGE.md does not say what the varlink client does for `{m}`"
            );
        }
        // and what the table names is a method
        for row in table.lines().filter(|l| l.starts_with("| `")) {
            let cell = row.trim_start_matches('|').split('|').next().unwrap();
            for name in cell.split(',').map(|n| n.trim().trim_matches('`')) {
                assert!(
                    methods.contains(&name),
                    "the table names `{name}`, which is no method of the trait"
                );
            }
        }
    }
}
