// SPDX-License-Identifier: Apache-2.0
//! The varlink interface `org.velarx.Storage`, as the two ends of a socket
//! speak it: the types, the limits and the errors.  The text of the
//! definition (`interfaces/org.velarx.Storage.varlink`) is made from these
//! types and the methods of [`super::interface`] by a test, as the one of
//! `org.velarx.Fetcher` is; `docs/STORAGE.md` is the description of the
//! rules (version 1).
//!
//! A storage driver is a program behind a listening unix socket.  The engine
//! is its client: one connection for each call, and a connection with no
//! reply for `[storage.varlink] timeout_secs` is failed.  Everything the
//! driver says is untrusted, but a driver is trusted to store (as the OCI
//! runtime is): what the engine needs to be right about it, it checks (the
//! diff id of a layer by reading it back, the key of a file it copies).
//!
//! Nothing here reads or writes a socket.

use serde::de::IntoDeserializer;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::BTreeMap;
use zlink::introspect;

/// The varlink interface.
pub const INTERFACE: &str = "org.velarx.Storage";

/// The version of the protocol: the engine refuses another one (exact match,
/// no negotiation; a capability is a word of `GetInfo`).
pub const PROTO: u32 = 1;

/// The most objects one `Fetch` of the feed asks for: `max_wants` of the limits.
pub const MAX_WANTS: u64 = 4096;

/// The most ranges of one `ReadObjects`: `max_ranges` of the limits.
pub const MAX_RANGES: u64 = 4096;

/// The most bytes of one message (the JSON of a call or of a reply).
pub const MAX_MESSAGE: usize = velarx_wire::varlink::MAX_MESSAGE;

/// The most descriptors of one message.
pub const MAX_FDS: usize = velarx_wire::varlink::MAX_FDS;

/// The most bytes of the keep set of a `Collect` (its sealed memory file).
pub const MAX_KEEP: u64 = 1 << 30;

/// A value of an enum in a message, or the name of one this build does not
/// know: a driver of a later minor version may answer more values, and that
/// is a `Storage` error that names the value, never a protocol error (the
/// unknown-value rule of `docs/STORAGE.md`).  On the wire it is the enum.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Open<E> {
    Known(E),
    Unknown(String),
}

impl<E> Open<E> {
    /// The value, or the name that is not known.
    pub fn known(self) -> Result<E, String> {
        match self {
            Open::Known(e) => Ok(e),
            Open::Unknown(name) => Err(name),
        }
    }
}

impl<E> From<E> for Open<E> {
    fn from(e: E) -> Self {
        Open::Known(e)
    }
}

impl<E: Serialize> Serialize for Open<E> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match self {
            Open::Known(e) => e.serialize(s),
            Open::Unknown(name) => s.serialize_str(name),
        }
    }
}

impl<'de, E: Deserialize<'de>> Deserialize<'de> for Open<E> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let name = String::deserialize(d)?;
        let by_name: Result<E, serde::de::value::Error> =
            E::deserialize(name.as_str().into_deserializer());
        Ok(match by_name {
            Ok(e) => Open::Known(e),
            Err(_) => Open::Unknown(name),
        })
    }
}

impl<E: introspect::Type> introspect::Type for Open<E> {
    const TYPE: &'static zlink::idl::Type<'static> = E::TYPE;
}

/// A layer as the engine names it to the driver: the key the driver stores it
/// under, the diff id of its image's configuration, and its OCI chain id
/// (computed by the engine; a driver whose layers are not chained ignores it).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, introspect::CustomType)]
pub struct LayerRef {
    /// `sha256:HEX` (a layer pulled whole) or `toc:sha256:HEX` (through its
    /// table of contents); `sha512:` in place of `sha256:` for an image of
    /// that algorithm
    pub key: String,
    /// The diff id of the layer, `sha256:HEX` or `sha512:HEX`
    pub diff_id: String,
    /// The OCI ChainID of the layer as the top of its stack
    pub chain_id: String,
}

/// A layer of the image a pull is for: all of the image's layers, in order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, introspect::CustomType)]
pub struct PullLayer {
    pub key: String,
    pub diff_id: String,
    pub chain_id: String,
    /// The chain id of the layer below it, none for the first
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent: Option<String>,
    /// The driver has the layer (`HasLayers` said so for this place of the
    /// stack): it is in the list so that every layer knows its parent, and
    /// nothing of it is fetched
    pub stored: bool,
}

/// A range of the bytes of one stored object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, introspect::CustomType)]
pub struct Range {
    /// The key of the object, as the table of contents of a layer names it
    /// (its fs-verity digest)
    pub key: String,
    /// The first byte
    pub offset: u64,
    /// How many bytes: the object must have them all
    pub length: u64,
}

/// A range of ids: the ids from `container_id` of the container are those
/// from `host_id` on the host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, introspect::CustomType)]
pub struct IdMap {
    pub container_id: u32,
    pub host_id: u32,
    pub size: u32,
}

/// The user namespace of the container.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, introspect::CustomType)]
pub struct Mapping {
    pub uid: Vec<IdMap>,
    pub gid: Vec<IdMap>,
    /// An owner no range maps is shown as the root of the container (else
    /// the image does not start)
    pub squash: bool,
}

/// The uid and gid, as the host sees them, of the root of the container's
/// user namespace.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, introspect::CustomType)]
pub struct Owner {
    pub uid: u32,
    pub gid: u32,
}

/// What the engine asks of a mount, the same for a root and for an image
/// mounted in the container.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, introspect::CustomType)]
pub struct MountAsk {
    /// The user namespace of the container, none: the ids of the engine
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mapping: Option<Mapping>,
    /// The monitor can put the mapping on the mount (the engine is root of
    /// the initial user namespace): the driver may answer `idmap: mount`.
    /// False: it never does
    pub idmap_mount: bool,
    /// The SELinux context of the mount of the container
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// The digests the engine accepts for the image of each layer, in order
    /// (the digests are enforced): a driver that cannot check them answers
    /// `Unsupported`
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verity: Option<Vec<Accepted>>,
}

/// The fs-verity digests the engine accepts for the image of one layer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, introspect::CustomType)]
pub struct Accepted {
    pub digests: Vec<String>,
}

/// An image mount of the container: its index among the `--mount
/// type=image` of the container, counted from 0, and what is asked of it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, introspect::CustomType)]
pub struct VolumeAsk {
    pub index: u32,
    pub ask: MountAsk,
}

/// What a mount is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, introspect::CustomType)]
#[serde(rename_all = "snake_case")]
#[zlink(rename_all = "snake_case")]
pub enum MountKind {
    /// A directory that the driver made for the container beneath the work
    /// directory of the store: `path`.  A root only
    Directory,
    /// A detached mount (`open_tree(OPEN_TREE_CLONE)` or `fsmount`), one
    /// mount, its root: the descriptor `fd` of the reply
    MountFd,
}

/// Who put the container's id mapping on the mount.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, introspect::CustomType)]
#[serde(rename_all = "snake_case")]
#[zlink(rename_all = "snake_case")]
pub enum Idmap {
    /// No mapping was asked
    None,
    /// The driver delivers the container's ids itself (the copy was made
    /// with them, a server translates them, its lowers are idmapped)
    Applied,
    /// The mount carries the ids of the image, and the monitor puts the
    /// mapping on the clone it attaches; only when `idmap_mount` was asked
    Mount,
}

/// Whether the SELinux label that was asked is on the mount.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, introspect::CustomType)]
#[serde(rename_all = "snake_case")]
#[zlink(rename_all = "snake_case")]
pub enum Label {
    /// The driver did nothing about it (or none was asked): the engine
    /// labels the files of a root, and refuses an image mount, when one was
    /// asked
    None,
    /// The mount carries it as its `context=`
    MountContext,
    /// The driver labelled the files as it made them
    Files,
}

/// What a mount is, as the driver says it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, introspect::CustomType)]
pub struct Mounted {
    pub kind: Open<MountKind>,
    /// With `mount_fd` in the reply of `Mounts`: the position of the
    /// descriptor among those of the reply.  Every mount that has one says
    /// which it is; a position used twice, outside the reply, or a
    /// descriptor no mount names, is a refused reply.  Never with a
    /// `CreateRoot` or `CreateImageVolume`, which hand over none
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fd: Option<u32>,
    /// With `directory`: the path of the directory relative to the `workdir`
    /// of `CreateRoot` (plain names: no `/` first, no `.`, `..` or empty
    /// one).  The work directory is the base the monitor checks and opens
    /// without following a link, and the directory is resolved beneath it:
    /// a root is never anywhere else on the host
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    pub idmap: Open<Idmap>,
    pub label: Open<Label>,
}

/// The words of `GetInfo`'s `capabilities` this build knows.
pub mod word {
    /// Answers content lookups, so that peers can be served
    pub const SERVE_CONTENT: &str = "serve_content";
    /// Works for an unprivileged engine
    pub const ROOTLESS: &str = "rootless";
    /// Uses the read-only additional image stores of the same driver
    pub const SHARED_STORES: &str = "shared_stores";
    /// The layers are chained
    pub const LAYER_CHAIN: &str = "layer_chain";
    /// A size limit of the writable layer is supported
    pub const SIZE_LIMIT: &str = "size_limit";
    /// Answers `HasObjects` and applies the `copy` events of a `Fetch` of the feed
    pub const OBJECTS: &str = "objects";
    /// Digests are checked when the content is stored; nothing more is promised
    pub const VERITY_PULL_ONLY: &str = "verity_pull_only";
    /// Digests are checked when a file is opened, by a file system server
    pub const VERITY_ON_OPEN: &str = "verity_on_open";
    /// Digests are enforced by the kernel
    pub const VERITY_KERNEL: &str = "verity_kernel";
}

/// How a container with a user namespace gets the layers owned by its ids.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, introspect::CustomType)]
#[serde(rename_all = "snake_case")]
#[zlink(rename_all = "snake_case")]
pub enum IdmapWay {
    /// One mount whose files carry the ids of the image, the monitor puts
    /// the mapping on the clone it attaches (needs root of the initial user
    /// namespace)
    MonitorMount,
    /// The driver idmaps its own mounts
    DriverMount,
    /// The ids are translated as the files are copied for the container
    AtCopy,
    /// A file system server translates them
    Translate,
}

/// What a driver does for one purpose of a mount.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, introspect::CustomType)]
pub struct MountCaps {
    /// How user namespaces are supported, in the order the driver prefers;
    /// empty: a mapping is not supported
    pub idmap: Vec<Open<IdmapWay>>,
}

/// The mounts a driver makes: how the root of a container and the images
/// mounted in it get their owners.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, introspect::CustomType)]
pub struct MountWays {
    /// The root file system of a container
    pub root: MountCaps,
    /// The images mounted in a container; none: no image mounts
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub volume: Option<MountCaps>,
}

/// What `GetInfo` answers: the shared five fields of
/// [`velarx_proto::info::Info`], and the mounts, which are lists and not
/// words.
///
/// Capability words: `serve_content` (answers content lookups, so that peers
/// can be served), `rootless`, `shared_stores` (uses the read-only additional
/// image stores of the same driver), `layer_chain` (the layers are chained:
/// the driver keeps them by chain id and the engine fills the chain records of
/// `Collect`), `size_limit` (a size limit of the writable layer is supported),
/// `objects` (answers `HasObjects` and applies the `copy` events of a `Fetch`
/// of the feed) and what enforces the fs-verity digests, in the order the
/// driver prefers: `verity_pull_only`, `verity_on_open`, `verity_kernel`.
/// Limits: `max_message` and `max_fds` of one message, `max_wants` (layers a
/// `Fetch` of the feed asks for), `max_ranges` (of a `ReadObjects`) and
/// `max_layers` (of one container; none: no limit).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, introspect::Type)]
pub struct Info {
    /// What the driver calls itself, for the logs and the messages
    pub name: String,
    /// The version of the driver (its package's)
    pub version: String,
    /// The version of the protocol: the engine refuses another one
    pub proto: u32,
    /// Words; a client ignores those it does not know
    pub capabilities: Vec<String>,
    /// Named limits; a client ignores those it does not know
    pub limits: BTreeMap<String, u64>,
    pub mounts: MountWays,
}

impl Info {
    /// Whether the driver says this capability word.
    pub fn can(&self, word: &str) -> bool {
        self.capabilities.iter().any(|w| w == word)
    }

    /// The five fields every `GetInfo` has.
    pub fn shared(&self) -> velarx_proto::info::Info {
        velarx_proto::info::Info {
            name: self.name.clone(),
            version: self.version.clone(),
            proto: self.proto,
            capabilities: self.capabilities.clone(),
            limits: self.limits.clone(),
        }
    }
}

/// What a long call tells while it goes.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, introspect::CustomType)]
pub struct Progress {
    /// What the driver is at, for the person who waits
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub done: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total: Option<u64>,
}

/// What `HasLayers` answers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, introspect::Type)]
pub struct HasReply {
    /// One for each layer asked, in the order asked (the same layer at two
    /// places of a stack is two questions): true for a layer that is
    /// committed and complete
    pub have: Vec<bool>,
}

/// What `HasObjects` answers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, introspect::Type)]
pub struct ObjectsReply {
    /// One for each object asked, in the order asked: true for an object the
    /// driver has committed and can read now
    pub have: Vec<bool>,
}

/// What a reply of `BeginPull` is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, introspect::CustomType)]
#[serde(rename_all = "snake_case")]
#[zlink(rename_all = "snake_case")]
pub enum PullEventKind {
    /// The pull goes on (`continues`); sent at least every `timeout_secs / 2`,
    /// also while the driver's own calls to the feed run
    Progress,
    /// Every object the driver needs is staged: the last reply
    Staged,
}

/// A reply of `BeginPull`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, introspect::Type)]
pub struct PullEvent {
    pub kind: Open<PullEventKind>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub progress: Option<Progress>,
}

/// A reply of `ReadObjects`: range `index` is next, its bytes follow on the
/// pipe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, introspect::Type)]
pub struct Read {
    /// The index of the range among those asked: in the order asked
    pub index: u64,
    /// How many bytes the object has (a driver that tells it lets the engine
    /// see an object longer than its index)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
}

/// What `CreateRoot` tells while it goes, and answers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, introspect::Type)]
pub struct Created {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub progress: Option<Progress>,
    /// In the last reply: what the root will be, with no descriptor (none
    /// without an image)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root: Option<Mounted>,
}

/// What `CreateImageVolume` tells while it goes, and answers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, introspect::Type)]
pub struct VolumeCreated {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub progress: Option<Progress>,
    /// In the last reply: what the volume will be, with no descriptor
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub volume: Option<Mounted>,
}

/// What `Mounts` answers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, introspect::Type)]
pub struct MountsReply {
    /// When it was asked
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root: Option<Mounted>,
    /// In the order asked
    pub volumes: Vec<Mounted>,
}

/// What `Size` answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, introspect::Type)]
pub struct SizeReply {
    /// The bytes of the files the container wrote
    pub bytes: u64,
}

/// What `Exists` answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, introspect::Type)]
pub struct ExistsReply {
    pub exists: bool,
}

/// What a call that returns nothing answers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, introspect::Type)]
pub struct Ack {}

/// What a check found wrong with what a driver made of an image.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, introspect::CustomType)]
#[serde(rename_all = "snake_case")]
#[zlink(rename_all = "snake_case")]
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

/// A problem a check found.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, introspect::CustomType)]
pub struct Problem {
    pub kind: Open<ProblemKind>,
    pub message: String,
    /// The layer it is about
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub layer: Option<String>,
    /// The file it is about, when the driver has one to name
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// Making the artifacts again mends it
    pub repair: bool,
}

/// What `Check` tells while it goes, and answers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, introspect::Type)]
pub struct Checked {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub progress: Option<Progress>,
    /// In the last reply
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub problems: Option<Vec<Problem>>,
}

/// The users and groups that own the files of a layer.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, introspect::CustomType)]
pub struct Owners {
    pub uids: Vec<u32>,
    pub gids: Vec<u32>,
}

/// What a driver made of a layer, for the engine to record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, introspect::CustomType)]
pub struct Artifact {
    /// The layer
    pub key: String,
    /// The digest the driver's image of the layer has (composefs: the
    /// fs-verity digest of its EROFS image); the engine records it as the
    /// identity of what the driver made
    pub image_digest: String,
    pub owners: Owners,
}

/// What `Repair` tells while it goes, and answers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, introspect::Type)]
pub struct Repaired {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub progress: Option<Progress>,
    /// In the last reply: made again from what the driver keeps, and
    /// answered for the engine to check against the identities it makes from
    /// the tables of contents
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifacts: Option<Vec<Artifact>>,
}

/// What `Usage` answers: of the driver's own artifacts (the objects are the
/// engine's).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, introspect::Type)]
pub struct UsageReply {
    pub files: u64,
    pub bytes: u64,
}

/// A name and a value the driver reports of itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, introspect::CustomType)]
pub struct Pair {
    pub name: String,
    pub value: String,
}

/// What `Status` answers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, introspect::Type)]
pub struct StatusReply {
    pub pairs: Vec<Pair>,
}

/// A store the driver holds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, introspect::CustomType)]
pub struct StoreEntry {
    /// The id of the store: 32 hex digits
    pub store: String,
    /// What it takes on the driver's disk
    pub bytes: u64,
    /// When an engine last opened it (seconds since the epoch), none if the
    /// driver does not know
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_open: Option<i64>,
}

/// What `ListStores` answers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, introspect::Type)]
pub struct StoresReply {
    pub stores: Vec<StoreEntry>,
}

/// What `Collect` tells while it goes, and answers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, introspect::Type)]
pub struct Collection {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub progress: Option<Progress>,
    /// In the last reply
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bytes_freed: Option<u64>,
    /// In the last reply: what could not be removed, one line each
    #[serde(default)]
    pub errors: Vec<String>,
}

/// What mends an artifact that is missing or wrong.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, introspect::CustomType)]
#[serde(rename_all = "snake_case")]
#[zlink(rename_all = "snake_case")]
pub enum Remedy {
    /// The image is pulled again
    PullAgain,
    /// The artifacts are made again from what the driver keeps (`Repair`)
    Repair,
    /// The container is removed and created again: what it wrote in its
    /// writable layer is lost with it
    RecreateContainer,
}

/// Why a call failed.  An error name the engine does not know is a `Storage`
/// error that carries the name in its message.  `Unavailable`, `TimedOut`
/// and `ProtocolMismatch` of the engine are what its client makes of a
/// transport that failed; `Contradicted`, `DigestEnforced` and `Refused` are
/// verdicts of the engine, and a driver never sends them.
#[derive(Debug, Clone, PartialEq, zlink::ReplyError, introspect::ReplyError)]
#[zlink(interface = "org.velarx.Storage")]
pub enum StorageError {
    /// An artifact is not there or not recorded; `remedy` mends it, and the
    /// message ends with it
    Missing {
        reason: String,
        layer: Option<String>,
        remedy: Remedy,
    },
    /// An artifact is not the one recorded or cannot be read; `remedy` mends
    /// it (`recreate_container` loses what the container wrote in its
    /// writable layer, and the message says so)
    Corrupt {
        reason: String,
        layer: Option<String>,
        remedy: Remedy,
    },
    /// The driver cannot do what was asked: a capability it lacks
    Unsupported { reason: String },
    /// Something the call names is not there: a pull, a container
    NotFound { reason: String },
    /// The call conflicts with one in progress (two `CreateRoot` of one
    /// container, a `Collect` during a `Commit` of another process): it is
    /// made again later
    Busy { reason: String },
    /// The host refuses the SELinux label asked for the files of an image
    /// mount: another label, or none, is asked
    LabelRefused { reason: String },
    /// The driver's own backend does not answer (an object store, a
    /// service): the storage service is started
    Unavailable { reason: String },
    /// The driver tried and failed
    Failed { reason: String },
}

impl std::fmt::Display for StorageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Missing { reason, .. } => write!(f, "missing: {reason}"),
            Self::Corrupt { reason, .. } => write!(f, "corrupt: {reason}"),
            Self::Unsupported { reason } => write!(f, "unsupported: {reason}"),
            Self::NotFound { reason } => write!(f, "not found: {reason}"),
            Self::Busy { reason } => write!(f, "busy: {reason}"),
            Self::LabelRefused { reason } => write!(f, "label refused: {reason}"),
            Self::Unavailable { reason } => write!(f, "unavailable: {reason}"),
            Self::Failed { reason } => write!(f, "failed: {reason}"),
        }
    }
}

impl std::error::Error for StorageError {}
