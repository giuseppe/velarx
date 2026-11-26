// SPDX-License-Identifier: Apache-2.0
//! The varlink interface `org.velarx.Engine`, as the two ends of a socket
//! speak it.
//!
//! The engine is the process that owns the storage, the database and the
//! containers.  Its frontends (the REST API and the
//! CRI) own a protocol of their own and nothing else: they decode what a
//! client sent into the typed arguments of a call, and encode the reply.
//! All they share with the engine is this module.
//!
//! * Version: [`GetInfo`](EngineProxy::get_info) says the version of the
//!   engine, [`crate::PROTO`] and the digest of this interface ([`crate::DIGEST`]); a
//!   frontend refuses an engine that is not of its build
//!   ([`crate::connect::check`]).  Binaries are installed together; there is
//!   no compatibility code.
//! * Names: `NounVerb` (`ContainerInspect`, `ImageList`).  A method whose
//!   name starts with `Podman` answers the documents of podman's or
//!   Docker's API for velarx-api and is not the engine's own surface (it
//!   leaves when velarx-api shapes those documents itself).
//! * Types: whatever a frontend decides on is typed.  The documents of the
//!   REST API (a container's inspect, a list of images) are the
//!   engine's own shaping and cross as `object` (`serde_json::Value`): the
//!   frontend passes them to its client.  Small documents are in the reply;
//!   a large one is a pipe the engine fills ([`Documents`]), because
//!   varlink messages are built in memory on both sides.
//! * Descriptors: bulk data never goes through the JSON.  Whatever is
//!   file-like crosses as a descriptor in the message (SCM_RIGHTS), named in
//!   the JSON by its position among the descriptors of the message: real
//!   files, pipes, sockets and ptys, except secrets: credentials, signing
//!   keys and secret data are a sealed memory file (`F_SEAL_SEAL |
//!   F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE`), at most 1 MiB, never in
//!   a message and never in a pipe.  A call that
//!   passes descriptors is sent alone on its connection.
//! * Uploads and downloads (an archive, an image, the body of a request):
//!   a pipe of frames, a length (4 bytes, big endian, at most
//!   [`crate::build::MAX_CONTEXT_FRAME`]) and that many bytes each, ended by
//!   an empty frame.  A pipe that ends before the empty frame was cut (the
//!   writer failed or went away): it is never taken for the whole.
//! * Errors: [`EngineError`], a name for each condition; the frontends map
//!   them to their own codes.
//!
//! The interface definition file `interfaces/org.velarx.Engine.varlink`
//! is generated from these types (see the test of the engine that checks
//! it); it is licensed Apache-2.0 only so that frontends in other languages
//! can use it.
#![allow(
    clippy::too_many_arguments,
    reason = "the macros of zlink make a function of every method of the interface, with one parameter for each field of the call"
)]

use crate::health::OnFailure;
use crate::pod::{PodAction, PodResources, RestartPolicy};
use crate::retry::Retry;
use crate::system::{
    CgroupManager, CheckSpec, Collected, DiskUsageInspected, HealthReport, StoresListed,
    SystemChecked, SystemInspected, SystemPruned, VersionInspected,
};
use crate::wait::WaitCondition;
use crate::workload::{
    ArtifactInspected, ArtifactListed, BuildPruned, Committed, ContainerInspected, ContainerListed,
    CriuStatistics, EventListed, ExecInspected, ExecSpec, HealthChecked, ImageCompleted,
    ImageHistoryListed, ImageInspected, ImageListed, ImagePruneListed, ImageRemoved,
    ImageTreeInspected, ImagesRemoved, ManifestListRecord, ManifestRemoved, MetricDescriptorListed,
    NetworkCreated, NetworkInspected, NetworkListed, NetworkSpec, PodInspected, PodListed,
    PodLogListed, PodMetricsListed, Pruned, Pulled, PullingAnswer, PullsListed, Pushed, Reclaimed,
    RegistryDigested, RemoteImage, Scopes, SecretInspected, SecretListed, StatsListed,
    VolumeInspected, VolumeListed, VolumeSpec, VolumesPruned,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::os::fd::OwnedFd;
use zlink::introspect;

/// The varlink interface.
pub const INTERFACE: &str = "org.velarx.Engine";

/// The most bytes of the body of a pod create (`PodCreate`).
pub const MAX_POD_SPEC: usize = 1 << 20;

/// The most bytes of the spec of a container (`ContainerCreate`).
pub const MAX_CONTAINER_SPEC: usize = 4 << 20;

/// The most bytes of JSON the arguments of a call have (the names, the
/// filters, the labels, the options...).  zlink builds a message in memory,
/// serializing it again each time its buffer grows (it doubles), and the
/// engine reads the whole message before it parses it.  So anything larger
/// than a few kB crosses as a descriptor (a pipe, `#[zlink(fds)]`) and never as a string or an array
/// argument; the frontends check this limit before they call
/// (`velarx-api`, `check_args`), and a test fails for a method that has an
/// unbounded argument and does not.
pub const MAX_ARG_BYTES: usize = 32 * 1024;

/// The most filters of a call.
pub const MAX_FILTERS: usize = 64;

/// What `GetInfo` answers.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, introspect::Type)]
pub struct InfoReply {
    /// What the engine calls itself
    pub name: String,
    /// The version of the engine (the package's)
    pub version: String,
    /// The version of the protocol (a client of another one calls
    /// `Restart`)
    pub interface: u32,
    /// The FNV-1a (64 bits, hexadecimal) of the text of the definition
    /// file the engine serves
    pub digest: String,
    /// The engine runs as root of the host
    pub rootful: bool,
}

/// What `Restart` answers: the engine starts again from the binary
/// installed (it was not the one that runs).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, introspect::Type)]
pub struct Restarted {
    pub restarted: bool,
}

/// What a call that returns nothing answers.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, introspect::Type)]
pub struct Ack {}

/// A filter of a list: the key and its values (`label`: `["a=b"]`).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, introspect::CustomType)]
pub struct Filter {
    pub key: String,
    pub values: Vec<String>,
}

/// A JSON array of documents the engine shaped for a podman client: in
/// `inline` when it is small, else in the pipe the reply carries (its
/// descriptor is `fd`, `length` bytes of JSON, ended by the end of the pipe).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, introspect::Type)]
pub struct Documents {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inline: Option<Vec<serde_json::Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fd: Option<u32>,
    #[serde(default)]
    pub length: u64,
}

/// One document the engine shaped for a podman client: in `inline` when it
/// is small, else in the pipe the reply carries (as [`Documents`]).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, introspect::Type)]
pub struct Document {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inline: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fd: Option<u32>,
}

/// A stream the engine opens: the reply carries the read end of a pipe
/// (descriptor 0) the engine writes to until the stream ends, and closes.
/// It ends when the reader closes its end: the engine stops producing, and
/// when the engine ends it the reader sees the end of the pipe.  Nothing
/// times a stream out (a follow may be idle for hours); a document is not a
/// stream, and is dropped when its reader stalls ([`Documents`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, introspect::Type)]
pub struct Stream {
    /// With `ContainerLogs`: the container has a terminal (the pipe has
    /// multiplexed frames all the same).  False for the other methods
    #[serde(default)]
    pub tty: bool,
}

/// What a request for the logs of a container asks.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, introspect::CustomType)]
pub struct LogOptions {
    /// The standard output (neither: both)
    pub stdout: bool,
    /// The standard error
    pub stderr: bool,
    /// What the container outputs from now on follows
    pub follow: bool,
    /// Each line begins with its time (RFC 3339, nanoseconds)
    pub timestamps: bool,
    /// The last lines; none: all of them
    pub tail: Option<i64>,
    /// Only the lines from this time (nanoseconds since the epoch); none: no
    /// limit
    pub since_ns: Option<i64>,
    /// Only the lines until this time (nanoseconds since the epoch); none: no
    /// limit
    pub until_ns: Option<i64>,
}

/// What a request for the logs of a pod asks.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, introspect::CustomType)]
pub struct PodLogOptions {
    /// The containers (names or ids) to read; none: all of the pod
    pub containers: Vec<String>,
    /// The lines follow until the containers have exited
    pub follow: bool,
    /// The last lines of each container; none: all of them
    pub tail: Option<i64>,
    pub since_ns: Option<i64>,
    pub until_ns: Option<i64>,
}

/// Where an attach or exec session is: what a reply says.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, introspect::CustomType)]
#[serde(rename_all = "snake_case")]
#[zlink(rename_all = "snake_case")]
pub enum SessionPhase {
    /// The first reply: the session is taken (the client may be answered
    /// before the container runs: a container that waits for the attach to
    /// start has no streams yet)
    Accepted,
    /// The descriptors of the process's streams
    Streams,
    /// The last reply: how it ended
    Ended,
}

/// What a client is told about a session when it is taken.  The
/// reply carries, when `logs` is set, the pipe of the log so far (the bytes
/// the client is sent first, framed as the rest), at the position `logs`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, introspect::CustomType)]
pub struct SessionOpened {
    /// Names the session in `SessionCloseStdin` and `SessionDetach`
    pub session: String,
    /// The stream has no frames (a terminal)
    #[serde(default)]
    pub tty: bool,
    /// The input of the client is the process's
    #[serde(default)]
    pub stdin: bool,
    /// The output the client is sent
    #[serde(default)]
    pub stdout: bool,
    #[serde(default)]
    pub stderr: bool,
    /// The position of the log so far among the descriptors of the reply
    #[serde(default)]
    pub logs: Option<u32>,
    /// The bytes of the keys that end the session for the client (the
    /// process goes on); none: no keys
    #[serde(default)]
    pub detach_keys: Vec<u8>,
    /// The end of the client's input is not the end of the process's (an
    /// attach of the CRI only)
    #[serde(default)]
    pub keep_open: bool,
}

/// The streams of a process, by position among the descriptors of the reply
/// (one-way stream sockets, or the pipe of the input).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, introspect::CustomType)]
pub struct SessionStreams {
    pub stdin: Option<u32>,
    pub stdout: Option<u32>,
    pub stderr: Option<u32>,
}

/// A reply of `ContainerAttach` and `ExecStart`, called with `more`: the
/// session is taken (`opened`), the streams of the process (`streams`), and
/// the end (`exit`, what the engine says as errors of the process in
/// `message`).  The frontend copies between its client and the streams
/// (Docker's frames, raw with a terminal): nothing of the session passes
/// through the engine.  When the frontend closes the connection (its client
/// is gone) the process goes on.  No timeout applies.  An exec
/// session of `detach` has one reply, the last.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, introspect::CustomType)]
pub struct SessionReply {
    pub phase: SessionPhase,
    #[serde(default)]
    pub opened: Option<SessionOpened>,
    #[serde(default)]
    pub streams: Option<SessionStreams>,
    /// The status of the process, when the engine knows it
    #[serde(default)]
    pub exit: Option<i64>,
    /// Errors of the process (the runtime's, or the monitor's), for the
    /// client's output
    #[serde(default)]
    pub message: Option<String>,
}

/// What a request to attach to a container asks.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, introspect::CustomType)]
pub struct AttachOptions {
    pub stdout: bool,
    pub stderr: bool,
    /// The log so far is sent first
    pub logs: bool,
    /// What the container outputs from now on is sent
    pub stream: bool,
    pub stdin: bool,
    /// As the client wrote them
    pub detach_keys: Option<String>,
    /// The input of the container is closed when this client goes away
    #[serde(default)]
    pub stdin_once: bool,
    /// The end of the input of this client is not the end of the
    /// container's: it stays open for the next attach (the CRI's attach of
    /// a container without `stdin_once`)
    #[serde(default)]
    pub stdin_keep_open: bool,
    /// The container waits for this attach to start (`ContainerStartAttached`)
    #[serde(default)]
    pub start: bool,
    /// The size of the terminal of the client, in characters (none: not
    /// known)
    #[serde(default)]
    pub height: Option<i64>,
    #[serde(default)]
    pub width: Option<i64>,
}

/// `NetworkRemove` answers: the name of the network removed and podman's
/// warnings of the stops of its containers that needed the kill.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, introspect::Type)]
pub struct NetworkRemoved {
    pub name: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

/// `VolumeRemove` answers: podman's warnings of the stops of the containers
/// that used the volume that needed the kill.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, introspect::Type)]
pub struct VolumeRemoved {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

/// `PodRun` answers: the pod's id and the errors of its containers; nothing
/// was done (the pod is already as asked) when `changed` is false.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, introspect::Type)]
pub struct PodRan {
    pub changed: bool,
    pub id: String,
    pub errors: Vec<String>,
}

/// `PodRemove` answers: the pod's id, the ids of the containers removed and
/// podman's warnings of the stops that needed the kill.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, introspect::Type)]
pub struct PodRemoved {
    pub id: String,
    pub removed: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

/// What a runtime handler of the CRI (an OCI runtime of the engine) can do,
/// from the `features` of its runtime.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, introspect::Type)]
pub struct RuntimeHandlerSupport {
    /// The name of the runtime (the default one's too)
    pub name: String,
    /// It makes mounts read-only recursively (`rro`)
    pub recursive_read_only_mounts: bool,
    /// It makes user namespaces and ID-mapped mounts
    pub user_namespaces: bool,
}

/// What `RuntimeInspect` answers.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, introspect::Type)]
pub struct RuntimeInfo {
    /// What the engine calls itself
    pub name: String,
    /// The version of the engine
    pub version: String,
    /// The version of the podman API the engine speaks
    pub api_version: String,
    pub cgroup_manager: CgroupManager,
    /// The OCI runtime containers run with by default
    pub oci_runtime: String,
    /// The names of the other OCI runtimes a container can be made with
    pub oci_runtimes: Vec<String>,
    /// What the default runtime and the others can do
    pub handler_support: Vec<RuntimeHandlerSupport>,
    /// The cgroup controllers the containers can have (`hugetlb`...)
    pub cgroup_controllers: Vec<String>,
    /// The image of the infra container of a pod that names none: the
    /// configured one, else the local pause image
    pub infra_image: String,
}

/// When a pull fetches the image (none: `always`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, introspect::CustomType)]
#[serde(rename_all = "snake_case")]
#[zlink(rename_all = "snake_case")]
pub enum PullPolicy {
    /// When the store has no image of the name
    Missing,
    /// Never: the image of the store, or an error
    Never,
    /// Every time
    Always,
    /// When the registry has another image than the store
    Newer,
}

impl PullPolicy {
    /// The policy of podman's word (`missing`, `never`, `always`,
    /// `newer`).
    pub fn of_word(word: &str) -> Option<Self> {
        match word {
            "missing" => Some(Self::Missing),
            "never" => Some(Self::Never),
            "always" => Some(Self::Always),
            "newer" => Some(Self::Newer),
            _ => None,
        }
    }
}

/// The format of the manifests a push writes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, introspect::CustomType)]
#[serde(rename_all = "snake_case")]
#[zlink(rename_all = "snake_case")]
pub enum ManifestFormat {
    Oci,
    /// Docker's: refused (`NotSupported`)
    DockerV2s2,
}

impl ManifestFormat {
    /// The format of podman's word (`oci`; Docker's `docker`, `v2s1` and
    /// `v2s2` are one value the engine refuses).
    pub fn of_word(word: &str) -> Result<Self, String> {
        match word {
            "oci" => Ok(Self::Oci),
            "docker" | "v2s1" | "v2s2" => Ok(Self::DockerV2s2),
            _ => Err(format!(
                "unknown format {word:?}. Choose on of the supported formats: 'oci'"
            )),
        }
    }

    /// The word the engine checks the format by.
    pub fn word(self) -> &'static str {
        match self {
            Self::Oci => "oci",
            Self::DockerV2s2 => "v2s2",
        }
    }
}

/// How the layers of a push are compressed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, introspect::CustomType)]
#[serde(rename_all = "snake_case")]
#[zlink(rename_all = "snake_case")]
pub enum LayerCompression {
    Gzip,
    ZstdChunked,
    None,
}

impl LayerCompression {
    /// The compression of podman's word (`gzip`, `zstd:chunked` or `zstd`,
    /// `none` or `uncompressed`).
    pub fn of_word(word: &str) -> Option<Self> {
        match word {
            "gzip" => Some(Self::Gzip),
            "zstd:chunked" | "zstd" => Some(Self::ZstdChunked),
            "none" | "uncompressed" => Some(Self::None),
            _ => None,
        }
    }

    /// `--compression-format` / `compressionFormat` of a build: a word
    /// podman knows.  The layers of a build are stored uncompressed, so it
    /// changes nothing; the compression is a push's.
    pub fn check_for_build(word: &str) -> Result<(), String> {
        Self::of_word(word)
            .map(drop)
            .ok_or_else(|| format!("invalid compression `{word}`"))
    }
}

/// What `StorageInspect` answers: the file system of the storage.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, introspect::Type)]
pub struct StorageUsage {
    pub mountpoint: String,
    pub images_bytes: u64,
    pub containers_bytes: u64,
    /// The inodes in use on the file system of the storage; none when the
    /// engine cannot tell
    pub inodes_used: Option<u64>,
}

/// What `NetworkCheck` answers: what the plugins of a CNI network say
/// of it.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, introspect::Type)]
pub struct NetworkStatus {
    pub ready: bool,
    /// Why it is not ready
    pub message: String,
}

/// An id.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, introspect::Type)]
pub struct Id {
    pub id: String,
}

/// `RegistryLogin` answers: why the registry refused, if it did.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, introspect::Type)]
pub struct LoginReply {
    /// What the registry (or the connection) said; none: logged in
    pub failure: Option<String>,
    /// The failure is the registry's refusal of the credentials
    pub unauthorized: bool,
}

/// What a call that may have nothing to do answers (`ContainerStart`,
/// `ContainerStop`, `ContainerInit`): `changed` is false when the object
/// was as asked already.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, introspect::Type)]
pub struct Changed {
    pub changed: bool,
}

/// `ContainerStop` answers: whether the container was running, and podman's
/// warning when the stop signal did not stop it in time.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, introspect::Type)]
pub struct Stopped {
    pub changed: bool,
    pub warning: Option<String>,
}

/// `ContainerStartAttached` answers: the container, and whether it was
/// started (it did not run).  The monitor waits for the client to attach
/// (`ContainerAttach` with `start`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, introspect::Type)]
pub struct StartedAttached {
    pub id: String,
    pub changed: bool,
}

/// A container `ContainerRemove` removed, with what named it in the call.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, introspect::CustomType)]
pub struct RemovedContainer {
    pub id: String,
    /// The name or the id the call gave, as it gave it
    pub named: String,
}

/// `ContainerRemove` answers: the containers removed, those that depended on
/// the one named first, and podman's warnings of the stops that needed the
/// kill.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, introspect::Type)]
pub struct Removed {
    pub removed: Vec<RemovedContainer>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

/// A reply of `ContainerWait`.  Called with `more`, the first reply has
/// neither field: the engine follows the container from then on (a client
/// may start it, its exit is not missed); the last reply has both.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize, introspect::Type)]
pub struct Waited {
    /// The exit code; -1 for a condition that is no exit (`running`)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status_code: Option<i64>,
    /// The condition that was met, one of those of the call
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub condition: Option<WaitCondition>,
}

/// What `ContainerCheckpoint` asks of CRIU and of the archive.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, introspect::CustomType)]
pub struct CheckpointFlags {
    /// The container goes on after the checkpoint
    pub leave_running: bool,
    /// Make an image of this name of the checkpoint
    pub create_image: Option<String>,
    pub tcp_established: bool,
    pub file_locks: bool,
    /// The container's own checkpoint is kept next to the archive
    pub keep: bool,
    /// Leave the root file system out of the archive
    pub ignore_rootfs: bool,
    /// Leave the volumes out of the archive
    pub ignore_volumes: bool,
    /// Absent: zstd
    pub compress: Option<Compression>,
    /// Read the statistics CRIU writes
    pub print_stats: bool,
    /// Dump the memory only, the container goes on (`--pre-checkpoint`)
    pub pre_checkpoint: bool,
    /// Checkpoint on top of the pre-checkpoint (`--with-previous`)
    pub with_previous: bool,
}

/// How an archive is compressed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, introspect::CustomType)]
#[serde(rename_all = "snake_case")]
#[zlink(rename_all = "snake_case")]
pub enum Compression {
    Zstd,
    Gzip,
    None,
}

impl Compression {
    /// The word of the option (`--compress`).
    pub fn word(self) -> &'static str {
        match self {
            Self::Zstd => "zstd",
            Self::Gzip => "gzip",
            Self::None => "none",
        }
    }

    /// The compression a word of [`Compression::word`] names.
    pub fn of_word(word: &str) -> Option<Self> {
        [Self::Zstd, Self::Gzip, Self::None]
            .into_iter()
            .find(|c| c.word() == word)
    }
}

/// `ContainerCheckpoint` answers: the container, and with `print_stats`
/// the microseconds the runtime took and what CRIU reports.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, introspect::Type)]
pub struct Checkpointed {
    pub id: String,
    pub runtime_checkpoint_duration: i64,
    #[serde(default)]
    pub criu_statistics: Option<CriuStatistics>,
}

/// A restore answers: the container, and with `print_stats` the
/// microseconds the runtime took and what CRIU reports.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, introspect::Type)]
pub struct Restored {
    pub id: String,
    /// None for a restore that is only staged
    #[serde(default)]
    pub runtime_restore_duration: Option<i64>,
    #[serde(default)]
    pub criu_statistics: Option<CriuStatistics>,
}

/// What a restore asks of CRIU, and what an import asks of the container it
/// makes.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, introspect::CustomType)]
pub struct RestoreFlags {
    pub tcp_established: bool,
    /// The established TCP connections are closed
    pub tcp_close: bool,
    pub file_locks: bool,
    /// The checkpoint stays after the restore
    pub keep: bool,
    /// The name of the container an import makes
    pub name: Option<String>,
    /// Leave the changes of the root file system of the archive out
    pub ignore_rootfs: bool,
    /// The container an import makes has not the static IP addresses of the
    /// archive
    pub ignore_static_ip: bool,
    /// The container an import makes has not the static MAC addresses of the
    /// archive
    pub ignore_static_mac: bool,
    /// The descriptor of the archive of a pre-checkpoint the archive of an
    /// import builds on
    pub previous: Option<u32>,
    /// The pod the container an import makes joins
    pub pod: Option<String>,
    /// The ports (`-p` specifications) the container an import makes
    /// publishes, instead of those of the archive
    pub publish: Vec<String>,
    /// Read the statistics CRIU writes
    pub print_stats: bool,
    /// The digests typed on the command that restores, which the images of
    /// the container are held to (as for `container_start`)
    pub verify_image: Vec<String>,
}

/// `PodmanContainerCreate` answers: the container and what was dropped
/// of the request.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, introspect::Type)]
pub struct ContainerCreated {
    pub id: String,
    pub warnings: Vec<String>,
}

/// `ContainerPrune` answers: the containers removed and the bytes their
/// writable layers had.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, introspect::Type)]
pub struct ContainersPruned {
    pub removed: Vec<String>,
    pub space: u64,
}

/// What is at a path of a container.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, introspect::Type)]
pub struct PathStat {
    /// The last component of the path asked (`/` for the root)
    pub name: String,
    pub size: i64,
    /// The Unix `st_mode`: the type and the permissions
    pub mode: u32,
    pub mtime_ns: i64,
    /// The path it resolves to in the container
    pub link_target: String,
    pub is_dir: bool,
}

/// A change of a container or an image to a file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, introspect::CustomType)]
pub struct FileChange {
    pub path: String,
    pub kind: ChangeKind,
}

/// What a change did to a file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, introspect::CustomType)]
#[serde(rename_all = "snake_case")]
#[zlink(rename_all = "snake_case")]
pub enum ChangeKind {
    Modified,
    Added,
    Deleted,
}

/// What `ContainerDiff` compares.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, introspect::CustomType)]
#[serde(rename_all = "snake_case")]
#[zlink(rename_all = "snake_case")]
pub enum DiffType {
    /// The container of the name, else the image
    All,
    Container,
    Image,
}

/// `CheckpointShare` answers: the reference of the checkpoint shared (its
/// manifest and its key), which `ContainerRestore` takes, and the
/// bytes of its archive.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, introspect::Type)]
pub struct CheckpointShared {
    pub reference: String,
    pub size: u64,
}

/// `ContainerTop` answers: the processes of a container, a row of values
/// of `titles` each.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, introspect::Type)]
pub struct Processes {
    pub titles: Vec<String>,
    pub processes: Vec<Vec<String>>,
}

/// `ContainerDiff` answers.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, introspect::Type)]
pub struct Changes {
    pub changes: Vec<FileChange>,
}

/// `ContainerMount` answers: where the root of the container is.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, introspect::Type)]
pub struct Mounted {
    pub path: String,
}

/// `ContainerMountList` answers: where the root of each container mounted
/// is, by its id.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, introspect::Type)]
pub struct MountedList {
    pub mounts: BTreeMap<String, String>,
}

/// The platform a request names: Docker's `platform` (`os/arch[/variant]`,
/// or the JSON of a push), else `os`, `arch` and `variant` (the host's for
/// what is not given).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, introspect::CustomType)]
pub struct PlatformSpec {
    pub platform: Option<String>,
    pub os: Option<String>,
    pub arch: Option<String>,
    pub variant: Option<String>,
}

/// What a pull asks.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, introspect::CustomType)]
pub struct PullSpec {
    /// A docker reference, `oci:DIR[:REF]`, `oci-archive:FILE[:REF]`,
    /// `docker-archive:FILE[:REF]`, `dir:DIR`, `rootfs:DIR` (a root file
    /// system), `docker-daemon:IMAGE` (read from the socket of `[pull]
    /// docker_socket`), `archive:FILE` (a load: every image of an archive of
    /// either kind) or `SCHEME://...` of a `[[transports]]`
    pub source: String,
    /// The path of `source` as a descriptor the client opened (a file, a
    /// directory, or the read end of a pipe of frames, which the engine
    /// spools); absent: the engine opens the path (podman's local routes)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_fd: Option<u32>,
    /// An artifact, into the artifact store
    #[serde(default)]
    pub artifact: bool,
    /// A short name is Docker Hub's when `[api] compat_api_enforce_docker_hub`
    /// says so (as Docker's clients mean it), not of the search registries
    pub docker_hub: bool,
    /// Absent: always
    pub policy: Option<PullPolicy>,
    /// Every tag of the repository
    pub all_tags: bool,
    /// How a pull that fails on the way is tried again
    pub retry: Retry,
    pub platform: PlatformSpec,
    pub tls_verify: bool,
    /// Only the metadata: the files are fetched when they are read
    pub lazy: bool,
    /// The fetchers of this pull, in the order they are asked (`--sources`);
    /// absent: `[pull] sources`
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sources: Option<Vec<String>>,
}

/// A layer of an image that cannot be pulled lazily, and why: `no_toc`,
/// `no_ranges`, `unsupported`, `unreachable`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, introspect::CustomType)]
pub struct NotLazyLayer {
    /// Its position in the manifest, from 0
    pub index: u32,
    pub digest: String,
    pub media_type: String,
    pub reason: crate::transfer::NotLazy,
}

/// What a push asks.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, introspect::CustomType)]
pub struct PushSpec {
    /// What is pushed: one image, manifest list or artifact; several only to
    /// an archive (`oci-archive:`, `oci:`), each with its names (a save)
    pub images: Vec<String>,
    /// `images` name artifacts
    pub artifact: bool,
    pub tag: Option<String>,
    /// Absent: the name of the image (or its repository with `tag`)
    pub destination: Option<String>,
    /// The instance of a manifest list
    pub platform: PlatformSpec,
    /// Every instance of a manifest list
    pub all: bool,
    /// Every tag of the repository of the image
    pub all_tags: bool,
    pub tls_verify: bool,
    /// Absent: the layers keep theirs
    pub compression: Option<LayerCompression>,
    /// The level of the layers compressed
    pub compression_level: Option<i32>,
    /// More instances of a manifest list, in these compressions
    pub add_compression: Vec<LayerCompression>,
    /// How a push that fails on the way is tried again
    pub retry: Retry,
    pub format: Option<ManifestFormat>,
    /// Sign the manifests pushed with this key: the sealed memory file
    /// (the JSON of `SigningKey`) the call carries at this position
    pub signing: Option<u32>,
    /// The helper pushers of this push, in the order they are asked
    /// (`--sinks`): names of `[[sinks.external]]`; the destination's own
    /// pusher always follows them, chosen by the scheme of the destination
    /// and never named here; absent: `[push] sinks`
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sinks: Option<Vec<String>>,
    /// The destination is a path the client opened (`destination` is its
    /// text, `oci:PATH[:TAG]`, `dir:PATH` or `oci-archive:FILE[:TAG]`): the
    /// position of its descriptor among those of the call
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub destination_fd: Option<u32>,
}

/// A device in an update: named by its path, or by its numbers (a path
/// that is no block device is refused), with the weight or the rate it is
/// given.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, introspect::CustomType)]
pub struct UpdateDevice {
    pub path: Option<String>,
    pub major: Option<u64>,
    pub minor: Option<u64>,
    /// The weight (10 to 1000) or the rate in bytes or operations a second
    pub value: u64,
}

/// The block IO limits an update sets.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, introspect::CustomType)]
pub struct UpdateBlockIo {
    /// 10 to 1000
    pub weight: Option<u64>,
    pub weight_devices: Vec<UpdateDevice>,
    pub read_bps: Vec<UpdateDevice>,
    pub write_bps: Vec<UpdateDevice>,
    pub read_iops: Vec<UpdateDevice>,
    pub write_iops: Vec<UpdateDevice>,
}

/// The health check an update changes (podman's `GetNewHealthCheckConfig`):
/// what is not given stays; the times are nanoseconds, 0 turns the timer
/// off.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, introspect::CustomType)]
pub struct UpdateHealth {
    /// No health check
    pub none: bool,
    pub cmd: Option<String>,
    pub interval: Option<u64>,
    pub retries: Option<u32>,
    pub timeout: Option<u64>,
    pub start_period: Option<u64>,
    pub startup_cmd: Option<String>,
    pub startup_interval: Option<u64>,
    pub startup_retries: Option<u32>,
    pub startup_timeout: Option<u64>,
    pub startup_success: Option<u32>,
    pub log_destination: Option<String>,
    pub max_log_count: Option<u32>,
    pub max_log_size: Option<u32>,
    pub on_failure: Option<OnFailure>,
}

/// The health members of podman's update as podman gives them (the
/// `--health-*` flags of `update`, the `health_*` members of libpod's
/// body): the times are Go's durations or `disable`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct PodmanHealthUpdate {
    pub no_healthcheck: bool,
    pub health_cmd: Option<String>,
    pub health_interval: Option<String>,
    pub health_retries: Option<u64>,
    pub health_timeout: Option<String>,
    pub health_start_period: Option<String>,
    pub health_startup_cmd: Option<String>,
    pub health_startup_interval: Option<String>,
    pub health_startup_retries: Option<u64>,
    pub health_startup_timeout: Option<String>,
    pub health_startup_success: Option<u64>,
    pub health_log_destination: Option<String>,
    pub health_max_log_count: Option<u64>,
    pub health_max_log_size: Option<u64>,
    pub health_on_failure: Option<String>,
}

impl PodmanHealthUpdate {
    /// The change of the health check it asks for, none when it says
    /// nothing; podman's error for a time that is no duration.
    pub fn spec(self) -> Result<Option<UpdateHealth>, String> {
        let time = |t: Option<String>| -> Result<Option<u64>, String> {
            match t.as_deref() {
                None => Ok(None),
                Some("disable") => Ok(Some(0)),
                Some(t) => crate::duration::parse_go_duration_ns(t)
                    .and_then(|n| u64::try_from(n).ok())
                    .map(Some)
                    .ok_or_else(|| format!("time: invalid duration {t:?}")),
            }
        };
        let count = |n: Option<u64>| n.map(|n| u32::try_from(n).unwrap_or(u32::MAX));
        let health = UpdateHealth {
            none: self.no_healthcheck,
            cmd: self.health_cmd,
            interval: time(self.health_interval)?,
            retries: count(self.health_retries),
            timeout: time(self.health_timeout)?,
            start_period: time(self.health_start_period)?,
            startup_cmd: self.health_startup_cmd,
            startup_interval: time(self.health_startup_interval)?,
            startup_retries: count(self.health_startup_retries),
            startup_timeout: time(self.health_startup_timeout)?,
            startup_success: count(self.health_startup_success),
            log_destination: self.health_log_destination,
            max_log_count: count(self.health_max_log_count),
            max_log_size: count(self.health_max_log_size),
            on_failure: self
                .health_on_failure
                .map(|a| {
                    OnFailure::parse(&a).ok_or_else(|| format!("invalid on-failure action {a:?}"))
                })
                .transpose()?,
        };
        Ok((health != UpdateHealth::default()).then_some(health))
    }
}

/// What an update of a container changes: what is not given stays.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, introspect::CustomType)]
pub struct UpdateSpec {
    pub memory: Option<i64>,
    pub memory_reservation: Option<i64>,
    pub memory_swap: Option<i64>,
    pub cpu_quota: Option<i64>,
    pub cpu_period: Option<u64>,
    pub cpu_shares: Option<u64>,
    pub cpuset_cpus: Option<String>,
    pub cpuset_mems: Option<String>,
    pub pids_limit: Option<i64>,
    pub block_io: UpdateBlockIo,
    /// Rules that allow, after those of the container
    pub device_rules: Vec<crate::request::DeviceRule>,
    /// `NAME=VALUE` set, and names unset, in the environment of the next
    /// start
    pub env: Vec<String>,
    pub unset_env: Vec<String>,
    pub restart: Option<RestartPolicy>,
    /// The rlimits of the next start, which replace the container's; an
    /// empty list is the host's
    pub ulimits: Option<Vec<crate::request::Ulimit>>,
    pub health: Option<UpdateHealth>,
}

/// What a commit of the REST API asks.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, introspect::CustomType)]
pub struct CommitSpec {
    pub container: String,
    /// A short `repo` is of Docker Hub when `[api] compat_api_enforce_docker_hub`
    /// says so (as Docker's clients mean it), else of `localhost`
    pub docker_hub: bool,
    pub format: Option<String>,
    pub repo: Option<String>,
    pub tag: Option<String>,
    pub author: Option<String>,
    pub comment: Option<String>,
    pub changes: Vec<String>,
    pub pause: bool,
    pub include_volumes: bool,
    pub squash: bool,
    /// `sha256` or `sha512`: the algorithm of the digests of the new image
    /// (none: that of the image of the container)
    pub digest: Option<String>,
}

/// What an import of the REST API asks.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, introspect::CustomType)]
pub struct ImportSpec {
    /// A short `repo` is of Docker Hub, as `CommitSpec.docker_hub`
    pub docker_hub: bool,
    /// Where the tar is (else it is the upload)
    pub url: Option<String>,
    pub changes: Vec<String>,
    pub message: Option<String>,
    pub platform: PlatformSpec,
    /// libpod's name of the image
    pub reference: Option<String>,
    /// Docker's repository and tag of it
    pub repo: Option<String>,
    pub tag: Option<String>,
    /// `sha256` or `sha512`: the algorithm of the digests of the new image
    /// (none: the engine's `[build] digest`)
    pub digest: Option<String>,
}

/// The names a call answers.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, introspect::Type)]
pub struct Names {
    pub names: Vec<String>,
}

/// `ImageSearch` answers.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, introspect::Type)]
pub struct SearchHits {
    pub hits: Vec<SearchHit>,
}

/// What adding a file to an artifact asks.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, introspect::CustomType)]
pub struct ArtifactAddSpec {
    pub name: String,
    /// The title of the file in the artifact
    pub file_name: String,
    /// To an artifact of the name that is there
    pub append: bool,
    /// The artifact of the name that is there is replaced
    pub replace: bool,
    pub artifact_type: Option<String>,
    pub file_type: Option<String>,
    pub annotations: BTreeMap<String, String>,
    /// `sha256` or `sha512`: the algorithm of the digests of a new artifact
    /// (none: the engine's `[build] digest`); an artifact that is appended to
    /// keeps its own
    pub digest: Option<String>,
}

/// How an image is an instance of a manifest list: what is not empty
/// replaces what the image has.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, introspect::CustomType)]
pub struct InstanceSpec {
    pub annotations: BTreeMap<String, String>,
    pub architecture: String,
    pub os: String,
    pub os_version: String,
    pub variant: String,
    pub features: Vec<String>,
    pub os_features: Vec<String>,
}

/// What adding an artifact to a manifest list asks.  The call carries one
/// descriptor for each of `titles`, in their order: a regular file open for
/// reading, its content.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, introspect::CustomType)]
pub struct ManifestArtifactSpec {
    /// The titles of the files
    pub titles: Vec<String>,
    /// Absent: the unknown artifact type; empty: no type
    pub artifact_type: Option<String>,
    pub layer_type: String,
    pub config_type: String,
    /// The content of the configuration (a JSON document); empty: none
    pub config: String,
    /// No title annotation on the layers
    pub exclude_titles: bool,
    pub annotations: BTreeMap<String, String>,
    /// An image of a registry the artifact is about
    pub subject: String,
    /// How the artifact is an instance of the list
    pub instance: InstanceSpec,
}

/// The most files an artifact of a manifest list is made of in one call.
pub const MAX_ARTIFACT_FILES: usize = 64;

// (decoded through their members: a derived visitor is made again for
// each deserializer of the method enum of the service)
crate::members::deserialize_request_members! {
    InstanceSpec { annotations, architecture, os, os_version, variant, features, os_features }
    ManifestArtifactSpec {
        titles, artifact_type, layer_type, config_type, config, exclude_titles, annotations,
        subject, instance,
    }
}

/// The options of `generate systemd` (none: the default).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, introspect::CustomType)]
pub struct SystemdSpec {
    pub use_name: bool,
    pub no_header: bool,
    pub restart_policy: Option<String>,
    pub restart_sec: Option<u32>,
    pub start_timeout: Option<u32>,
    pub stop_timeout: Option<u32>,
    pub container_prefix: Option<String>,
    pub pod_prefix: Option<String>,
    pub separator: Option<String>,
    pub wants: Vec<String>,
    pub after: Vec<String>,
    pub requires: Vec<String>,
    pub env: Vec<String>,
}

/// The text a call answers (YAML, a unit).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, introspect::Type)]
pub struct Text {
    pub text: String,
}

/// The units of `SystemdGenerate`, by the name of their service.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, introspect::Type)]
pub struct Units {
    pub units: BTreeMap<String, String>,
}

/// What a registry has for a search.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, introspect::CustomType)]
pub struct SearchHit {
    /// The registry searched
    pub index: String,
    /// The repository, with its registry
    pub name: String,
    pub description: String,
    pub stars: u64,
    pub official: bool,
    pub automated: bool,
    /// The tag (a search of the tags of a repository)
    pub tag: String,
}

/// Why a call failed: a name for each condition, never a
/// status of another protocol.  The frontends map the names to their own
/// codes, one table each (HTTP statuses for the podman API, gRPC codes for
/// the CRI, the messages and exit codes of the command line).  `cause` is a
/// short reason that stays the same for a condition (a podman client matches
/// it in the message: the engine uses podman's words), `message` the whole
/// text; a `cause` is empty when the engine refused the call before any of
/// its operations ran.  Nobody decides by the words of either: the
/// condition is what a caller reads.
#[derive(Debug, Clone, PartialEq, zlink::ReplyError, introspect::ReplyError)]
#[zlink(interface = "org.velarx.Engine")]
pub enum EngineError {
    /// The container is not there
    NoSuchContainer { cause: String, message: String },
    /// The image is not there
    NoSuchImage { cause: String, message: String },
    /// The pod is not there
    NoSuchPod { cause: String, message: String },
    /// The network is not there
    NoSuchNetwork { cause: String, message: String },
    /// The volume is not there
    NoSuchVolume { cause: String, message: String },
    /// The secret is not there
    NoSuchSecret { cause: String, message: String },
    /// The exec session is not there
    NoSuchExecSession { cause: String, message: String },
    /// Another object is not there (an artifact, a manifest list)
    NoSuchObject { cause: String, message: String },
    /// The name is taken: the object exists already
    Conflict { cause: String, message: String },
    /// The object is in a state that does not allow this (running, paused,
    /// in use, has dependents)
    InvalidState { cause: String, message: String },
    /// The container has no checkpoint to restore
    NoCheckpoint { cause: String, message: String },
    /// An image reference the engine refuses before it looks for the image
    /// (a capital in the repository, an id of the wrong length)
    InvalidReference { cause: String, message: String },
    /// The image has several names: removing it by its ID needs `force`
    NeedsForce { cause: String, message: String },
    /// An argument, a descriptor or the content of a pipe the engine does
    /// not take
    InvalidArgument { cause: String, message: String },
    /// The name given to an object (a volume) is not one the engine takes
    InvalidName { cause: String, message: String },
    /// The bytes of an upload are not a tar archive (or a compressed one)
    InvalidArchive { cause: String, message: String },
    /// An argument, an upload or a document over its limit
    TooLarge { cause: String, message: String },
    /// The engine or a registry refused the caller
    PermissionDenied { cause: String, message: String },
    /// A registry wants credentials, or refused those it was given
    Unauthorized { cause: String, message: String },
    /// The engine does not do this
    NotSupported { cause: String, message: String },
    /// The storage or a quota is full
    NoSpace { cause: String, message: String },
    /// A connection the engine made for the call failed (to a port of a
    /// container)
    Unreachable { cause: String, message: String },
    /// The engine cannot answer now (too many connections, stopping)
    Unavailable { cause: String, message: String },
    /// The container could not be started: the runtime refused it, or what
    /// it runs with (its user, its working directory) is not there
    NotStarted { cause: String, message: String },
    /// The container could not be started: the command it runs is not there
    CommandNotFound { cause: String, message: String },
    /// A rootless container needs pasta for its network, and the engine
    /// finds none, or none of the release needed (`--network none` needs no pasta)
    NoPasta { cause: String, message: String },
    /// The content a party gave is not what it claims (a digest, a size, a
    /// table of contents): `party` is the fetcher, pusher or transport that
    /// gave it, `object` the digest or key; nothing else was asked
    InvalidContent {
        cause: String,
        message: String,
        party: String,
        object: String,
    },
    /// No source could give what the call needs: `party` the last one asked;
    /// `transient`: the call may succeed if made again
    SourceUnavailable {
        cause: String,
        message: String,
        party: String,
        transient: bool,
    },
    /// `lazy` was asked for an image that the list of fetchers of the pull cannot serve
    /// lazily: its `layers` and why.  Nothing was created.
    ImageNotLazy {
        cause: String,
        message: String,
        image: String,
        layers: Vec<NotLazyLayer>,
    },
    /// A layer is refused because its table of contents contradicts its
    /// tar stream: trying again gives the same
    Contradicted { cause: String, message: String },
    /// Anything else: the engine tried and failed
    Failed { cause: String, message: String },
}

/// A condition of [`EngineError`] without its texts: what a caller matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Condition {
    NoSuchContainer,
    NoSuchImage,
    NoSuchPod,
    NoSuchNetwork,
    NoSuchVolume,
    NoSuchSecret,
    NoSuchExecSession,
    NoSuchObject,
    Conflict,
    InvalidState,
    NoCheckpoint,
    InvalidReference,
    NeedsForce,
    InvalidArgument,
    InvalidName,
    InvalidArchive,
    TooLarge,
    PermissionDenied,
    Unauthorized,
    NotSupported,
    NoSpace,
    Unreachable,
    Unavailable,
    NotStarted,
    CommandNotFound,
    NoPasta,
    InvalidContent,
    SourceUnavailable,
    ImageNotLazy,
    Contradicted,
    Failed,
}

impl Condition {
    /// Every condition, in the order of the interface.
    pub const ALL: [Condition; 31] = [
        Self::NoSuchContainer,
        Self::NoSuchImage,
        Self::NoSuchPod,
        Self::NoSuchNetwork,
        Self::NoSuchVolume,
        Self::NoSuchSecret,
        Self::NoSuchExecSession,
        Self::NoSuchObject,
        Self::Conflict,
        Self::InvalidState,
        Self::NoCheckpoint,
        Self::InvalidReference,
        Self::NeedsForce,
        Self::InvalidArgument,
        Self::InvalidName,
        Self::InvalidArchive,
        Self::TooLarge,
        Self::PermissionDenied,
        Self::Unauthorized,
        Self::NotSupported,
        Self::NoSpace,
        Self::Unreachable,
        Self::Unavailable,
        Self::NotStarted,
        Self::CommandNotFound,
        Self::NoPasta,
        Self::InvalidContent,
        Self::SourceUnavailable,
        Self::ImageNotLazy,
        Self::Contradicted,
        Self::Failed,
    ];

    /// The name of the condition, as the interface has it on the wire.
    pub fn name(self) -> &'static str {
        match self {
            Self::NoSuchContainer => "NoSuchContainer",
            Self::NoSuchImage => "NoSuchImage",
            Self::NoSuchPod => "NoSuchPod",
            Self::NoSuchNetwork => "NoSuchNetwork",
            Self::NoSuchVolume => "NoSuchVolume",
            Self::NoSuchSecret => "NoSuchSecret",
            Self::NoSuchExecSession => "NoSuchExecSession",
            Self::NoSuchObject => "NoSuchObject",
            Self::Conflict => "Conflict",
            Self::InvalidState => "InvalidState",
            Self::NoCheckpoint => "NoCheckpoint",
            Self::InvalidReference => "InvalidReference",
            Self::NeedsForce => "NeedsForce",
            Self::InvalidArgument => "InvalidArgument",
            Self::InvalidName => "InvalidName",
            Self::InvalidArchive => "InvalidArchive",
            Self::TooLarge => "TooLarge",
            Self::PermissionDenied => "PermissionDenied",
            Self::Unauthorized => "Unauthorized",
            Self::NotSupported => "NotSupported",
            Self::NoSpace => "NoSpace",
            Self::Unreachable => "Unreachable",
            Self::Unavailable => "Unavailable",
            Self::NotStarted => "NotStarted",
            Self::CommandNotFound => "CommandNotFound",
            Self::NoPasta => "NoPasta",
            Self::InvalidContent => "InvalidContent",
            Self::SourceUnavailable => "SourceUnavailable",
            Self::ImageNotLazy => "ImageNotLazy",
            Self::Contradicted => "Contradicted",
            Self::Failed => "Failed",
        }
    }

    /// The condition named `name` (as [`Condition::name`] has it).
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|c| c.name() == name)
    }

    /// The HTTP status of podman's API for the condition:
    /// the one table the frontends and the command line read.
    pub fn status(self) -> u16 {
        match self {
            Self::NoSuchContainer
            | Self::NoSuchImage
            | Self::NoSuchPod
            | Self::NoSuchNetwork
            | Self::NoSuchVolume
            | Self::NoSuchSecret
            | Self::NoSuchExecSession
            | Self::NoSuchObject
            | Self::InvalidReference => 404,
            Self::Conflict | Self::InvalidState | Self::NoCheckpoint => 409,
            Self::InvalidArgument
            | Self::InvalidName
            | Self::InvalidArchive
            | Self::ImageNotLazy => 400,
            Self::TooLarge => 413,
            Self::PermissionDenied => 403,
            Self::Unauthorized => 401,
            Self::NotSupported => 501,
            Self::NoSpace => 507,
            Self::Unreachable => 502,
            Self::Unavailable => 503,
            Self::NotStarted
            | Self::CommandNotFound
            | Self::NoPasta
            | Self::InvalidContent
            | Self::SourceUnavailable
            | Self::Contradicted
            | Self::NeedsForce
            | Self::Failed => 500,
        }
    }
}

pub use crate::RESTARTING;

/// The cause of the `Unavailable` that refuses a hold: the engine is about to
/// exit.  The descriptor of the hold stays open in the engine until it does.
pub const STOPPING: &str = "stopping";

impl EngineError {
    /// A request the engine does not take: its argument, a descriptor or
    /// the content of a pipe.
    pub fn invalid(message: String) -> Self {
        Self::InvalidArgument {
            cause: String::new(),
            message,
        }
    }

    /// The engine tried and failed.
    pub fn failed(message: String) -> Self {
        Self::Failed {
            cause: String::new(),
            message,
        }
    }

    /// The engine cannot answer now.
    pub fn unavailable(message: String) -> Self {
        Self::Unavailable {
            cause: String::new(),
            message,
        }
    }

    /// The cause and the message, whatever the condition.
    pub fn parts(&self) -> (&str, &str) {
        match self {
            Self::NoSuchContainer { cause, message }
            | Self::NoSuchImage { cause, message }
            | Self::NoSuchPod { cause, message }
            | Self::NoSuchNetwork { cause, message }
            | Self::NoSuchVolume { cause, message }
            | Self::NoSuchSecret { cause, message }
            | Self::NoSuchExecSession { cause, message }
            | Self::NoSuchObject { cause, message }
            | Self::Conflict { cause, message }
            | Self::InvalidState { cause, message }
            | Self::NoCheckpoint { cause, message }
            | Self::InvalidReference { cause, message }
            | Self::NeedsForce { cause, message }
            | Self::InvalidArgument { cause, message }
            | Self::InvalidName { cause, message }
            | Self::InvalidArchive { cause, message }
            | Self::TooLarge { cause, message }
            | Self::PermissionDenied { cause, message }
            | Self::Unauthorized { cause, message }
            | Self::NotSupported { cause, message }
            | Self::NoSpace { cause, message }
            | Self::Unreachable { cause, message }
            | Self::Unavailable { cause, message }
            | Self::NotStarted { cause, message }
            | Self::CommandNotFound { cause, message }
            | Self::NoPasta { cause, message }
            | Self::InvalidContent { cause, message, .. }
            | Self::SourceUnavailable { cause, message, .. }
            | Self::ImageNotLazy { cause, message, .. }
            | Self::Contradicted { cause, message }
            | Self::Failed { cause, message } => (cause, message),
        }
    }

    /// The condition, without its texts.
    pub fn condition(&self) -> Condition {
        match self {
            Self::NoSuchContainer { .. } => Condition::NoSuchContainer,
            Self::NoSuchImage { .. } => Condition::NoSuchImage,
            Self::NoSuchPod { .. } => Condition::NoSuchPod,
            Self::NoSuchNetwork { .. } => Condition::NoSuchNetwork,
            Self::NoSuchVolume { .. } => Condition::NoSuchVolume,
            Self::NoSuchSecret { .. } => Condition::NoSuchSecret,
            Self::NoSuchExecSession { .. } => Condition::NoSuchExecSession,
            Self::NoSuchObject { .. } => Condition::NoSuchObject,
            Self::Conflict { .. } => Condition::Conflict,
            Self::InvalidState { .. } => Condition::InvalidState,
            Self::NoCheckpoint { .. } => Condition::NoCheckpoint,
            Self::InvalidReference { .. } => Condition::InvalidReference,
            Self::NeedsForce { .. } => Condition::NeedsForce,
            Self::InvalidArgument { .. } => Condition::InvalidArgument,
            Self::InvalidName { .. } => Condition::InvalidName,
            Self::InvalidArchive { .. } => Condition::InvalidArchive,
            Self::TooLarge { .. } => Condition::TooLarge,
            Self::PermissionDenied { .. } => Condition::PermissionDenied,
            Self::Unauthorized { .. } => Condition::Unauthorized,
            Self::NotSupported { .. } => Condition::NotSupported,
            Self::NoSpace { .. } => Condition::NoSpace,
            Self::Unreachable { .. } => Condition::Unreachable,
            Self::Unavailable { .. } => Condition::Unavailable,
            Self::NotStarted { .. } => Condition::NotStarted,
            Self::CommandNotFound { .. } => Condition::CommandNotFound,
            Self::NoPasta { .. } => Condition::NoPasta,
            Self::InvalidContent { .. } => Condition::InvalidContent,
            Self::SourceUnavailable { .. } => Condition::SourceUnavailable,
            Self::ImageNotLazy { .. } => Condition::ImageNotLazy,
            Self::Contradicted { .. } => Condition::Contradicted,
            Self::Failed { .. } => Condition::Failed,
        }
    }

    /// The name of the condition, as the interface has it on the wire.
    pub fn name(&self) -> &'static str {
        self.condition().name()
    }

    /// The message: what a person reads.
    pub fn message(&self) -> &str {
        self.parts().1
    }

    /// The HTTP status of podman's API for the condition:
    /// the one table the frontends and the command line read.
    pub fn status(&self) -> u16 {
        self.condition().status()
    }

    /// The error of `condition` with its texts.
    pub fn of(condition: Condition, cause: String, message: String) -> Self {
        match condition {
            Condition::NoSuchContainer => Self::NoSuchContainer { cause, message },
            Condition::NoSuchImage => Self::NoSuchImage { cause, message },
            Condition::NoSuchPod => Self::NoSuchPod { cause, message },
            Condition::NoSuchNetwork => Self::NoSuchNetwork { cause, message },
            Condition::NoSuchVolume => Self::NoSuchVolume { cause, message },
            Condition::NoSuchSecret => Self::NoSuchSecret { cause, message },
            Condition::NoSuchExecSession => Self::NoSuchExecSession { cause, message },
            Condition::NoSuchObject => Self::NoSuchObject { cause, message },
            Condition::Conflict => Self::Conflict { cause, message },
            Condition::InvalidState => Self::InvalidState { cause, message },
            Condition::NoCheckpoint => Self::NoCheckpoint { cause, message },
            Condition::InvalidReference => Self::InvalidReference { cause, message },
            Condition::NeedsForce => Self::NeedsForce { cause, message },
            Condition::InvalidArgument => Self::InvalidArgument { cause, message },
            Condition::InvalidName => Self::InvalidName { cause, message },
            Condition::InvalidArchive => Self::InvalidArchive { cause, message },
            Condition::TooLarge => Self::TooLarge { cause, message },
            Condition::PermissionDenied => Self::PermissionDenied { cause, message },
            Condition::Unauthorized => Self::Unauthorized { cause, message },
            Condition::NotSupported => Self::NotSupported { cause, message },
            Condition::NoSpace => Self::NoSpace { cause, message },
            Condition::Unreachable => Self::Unreachable { cause, message },
            Condition::Unavailable => Self::Unavailable { cause, message },
            Condition::NotStarted => Self::NotStarted { cause, message },
            Condition::CommandNotFound => Self::CommandNotFound { cause, message },
            Condition::NoPasta => Self::NoPasta { cause, message },
            // (by its name alone: the party is not known)
            Condition::InvalidContent => Self::InvalidContent {
                cause,
                message,
                party: String::new(),
                object: String::new(),
            },
            Condition::SourceUnavailable => Self::SourceUnavailable {
                cause,
                message,
                party: String::new(),
                transient: false,
            },
            // (by its name alone: its layers are not known)
            Condition::ImageNotLazy => Self::ImageNotLazy {
                cause,
                message,
                image: String::new(),
                layers: Vec::new(),
            },
            Condition::Contradicted => Self::Contradicted { cause, message },
            Condition::Failed => Self::Failed { cause, message },
        }
    }

    /// The condition named `name` (as [`EngineError::name`] has it).
    pub fn from_name(name: &str, cause: String, message: String) -> Option<Self> {
        Condition::from_name(name).map(|c| Self::of(c, cause, message))
    }

    /// The condition an HTTP status (podman's API, the inverse of
    /// [`EngineError::status`]) names: a 404 is `missing` (the `NoSuch...`
    /// condition of the kind of object), a 409 is of the state of the object
    /// with `state`, else of a name that is taken; a status that is none of
    /// the table is `Failed`.
    pub fn from_status(
        status: u16,
        state: bool,
        missing: Condition,
        cause: String,
        message: String,
    ) -> Self {
        let condition = match status {
            404 => missing,
            400 => Condition::InvalidArgument,
            401 => Condition::Unauthorized,
            403 => Condition::PermissionDenied,
            409 if state => Condition::InvalidState,
            409 => Condition::Conflict,
            413 => Condition::TooLarge,
            501 => Condition::NotSupported,
            502 => Condition::Unreachable,
            // (a limit of the engine: too many builds, signals)
            429 | 503 => Condition::Unavailable,
            507 => Condition::NoSpace,
            _ => Condition::Failed,
        };
        Self::of(condition, cause, message)
    }

    /// [`EngineError::status`] of a condition by its name on the wire (not
    /// prefixed by the interface); `None` for a name this build does not know.
    /// A `NoSuch...` name of a newer build is a 404.
    pub fn status_of_name(name: &str) -> Option<u16> {
        match Condition::from_name(name) {
            Some(c) => Some(c.status()),
            None if name.starts_with("NoSuch") => Some(404),
            None => None,
        }
    }
}

impl std::fmt::Display for EngineError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unavailable { message, .. } => write!(f, "unavailable: {message}"),
            other => f.write_str(other.message()),
        }
    }
}

impl std::error::Error for EngineError {}

/// The calls of the interface, as a client makes them.
#[zlink::proxy("org.velarx.Engine")]
pub trait EngineProxy {
    /// Who the engine is.
    async fn get_info(&mut self) -> zlink::Result<Result<InfoReply, EngineError>>;

    /// Nothing: the engine answers.
    async fn ping(&mut self) -> zlink::Result<Result<Ack, EngineError>>;

    /// Start again from the binary installed when it is not the one that
    /// runs (with `running`, from the one that runs, whatever is
    /// installed); whether it does.
    async fn restart(
        &mut self,
        running: Option<bool>,
    ) -> zlink::Result<Result<Restarted, EngineError>>;

    /// The health of the engine and of its parts.
    async fn health(&mut self) -> zlink::Result<Result<HealthReport, EngineError>>;

    /// The build of the engine and the kernel it runs on.
    async fn version_inspect(&mut self) -> zlink::Result<Result<VersionInspected, EngineError>>;

    /// What the engine is and what it runs on.
    async fn system_inspect(&mut self) -> zlink::Result<Result<SystemInspected, EngineError>>;

    /// What the images, the containers and the volumes use of the disk;
    /// with `store`, the files of the store too.
    async fn disk_usage_inspect(
        &mut self,
        store: bool,
    ) -> zlink::Result<Result<DiskUsageInspected, EngineError>>;

    /// Remove what is not in use (podman's `system prune`), then collect
    /// the garbage of the store.
    async fn system_prune(
        &mut self,
        all: bool,
        volumes: bool,
        build: bool,
        filters: Vec<Filter>,
    ) -> zlink::Result<Result<SystemPruned, EngineError>>;

    /// Check the store (and repair it, as `spec` asks).
    async fn system_check(
        &mut self,
        spec: CheckSpec,
    ) -> zlink::Result<Result<SystemChecked, EngineError>>;

    /// Collect the garbage of the store.
    async fn system_collect(
        &mut self,
        dry_run: bool,
        files: bool,
        layers: bool,
    ) -> zlink::Result<Result<Collected, EngineError>>;

    /// The stores the storage service holds for the engine's user, and with
    /// `drop` one of them dropped first (not the engine's own).
    async fn system_stores(
        &mut self,
        drop: Option<String>,
    ) -> zlink::Result<Result<StoresListed, EngineError>>;

    /// The engine a frontend started (no service manager does) lives while
    /// the other end of the socket this call carries is open, besides the
    /// frontend that started it: a frontend that finds the engine already
    /// there holds it, so that it is not left without one when the first
    /// frontend goes.
    async fn hold(
        &mut self,
        #[zlink(fds)] lifeline: Vec<OwnedFd>,
    ) -> zlink::Result<Result<Ack, EngineError>>;

    /// `HEAD|GET /containers/{name}/exists`: the container is there.
    async fn container_exists(&mut self, name: &str) -> zlink::Result<Result<Ack, EngineError>>;

    /// `POST /containers/{name}/init`: ready to start, not started.
    async fn container_init(&mut self, name: &str) -> zlink::Result<Result<Changed, EngineError>>;

    /// `POST /containers/{name}/start`.  `verify_image`: the digests typed
    /// on the command that starts it, which an enforced start holds the images
    /// of the container to; `service`: the start of a service that has no
    /// command line (the CRI, the start at boot): the engine goes by the
    /// record of the container; `run`: the digests are those of the references
    /// of a `run`, not of `--verify-image`, and a container that does not
    /// enforce the digests does not refuse them.
    async fn container_start(
        &mut self,
        name: &str,
        verify_image: Vec<String>,
        service: Option<bool>,
        run: Option<bool>,
    ) -> zlink::Result<Result<Changed, EngineError>>;

    /// Start a container with its monitor waiting for the client to attach
    /// (`run`, `start --attach`, then `container_attach` with `start`).
    /// `verify_image`,
    /// `service` and `run` as for `container_start`.
    async fn container_start_attached(
        &mut self,
        name: &str,
        verify_image: Vec<String>,
        service: Option<bool>,
        run: Option<bool>,
    ) -> zlink::Result<Result<StartedAttached, EngineError>>;

    /// `POST /containers/{name}/stop`: `timeout` seconds (none: the
    /// container's own); `ignore`: one that is not there is stopped;
    /// `service`: a stop of the service manager (a shutdown), not of a user,
    /// so that an `unless-stopped` container starts again at the next boot.
    async fn container_stop(
        &mut self,
        name: &str,
        timeout: Option<u64>,
        ignore: bool,
        service: Option<bool>,
    ) -> zlink::Result<Result<Stopped, EngineError>>;

    /// `POST /containers/{name}/kill`: a signal by name or number (SIGKILL
    /// if absent).
    async fn container_kill(
        &mut self,
        name: &str,
        signal: Option<&str>,
    ) -> zlink::Result<Result<Ack, EngineError>>;

    /// `POST /containers/{name}/restart`
    async fn container_restart(
        &mut self,
        name: &str,
        timeout: Option<u64>,
        verify_image: Vec<String>,
    ) -> zlink::Result<Result<Ack, EngineError>>;

    /// `POST /containers/{name}/pause` and `/unpause`.  `lease`: seconds
    /// after which the engine unpauses the container itself when nobody
    /// did (a client that pauses for a cut and may end before it resumes).
    async fn container_pause(
        &mut self,
        name: &str,
        pause: bool,
        lease: Option<u64>,
    ) -> zlink::Result<Result<Ack, EngineError>>;

    /// `POST /containers/{name}/rename`
    async fn container_rename(
        &mut self,
        name: &str,
        new_name: &str,
    ) -> zlink::Result<Result<Ack, EngineError>>;

    /// `DELETE /containers/{name}`: a running one with `force`, stopped with
    /// `timeout` seconds (none: its own)
    async fn container_remove(
        &mut self,
        name: &str,
        force: bool,
        volumes: bool,
        ignore: bool,
        depend: bool,
        timeout: Option<u64>,
    ) -> zlink::Result<Result<Removed, EngineError>>;

    /// Wait until the container meets one of `conditions` (none: its
    /// exit): the command line's `wait`, libpod's and Docker's
    /// `POST /containers/{name}/wait`.  `interval_ns` is podman's interval
    /// (0: its default; negative is refused); the engine follows the
    /// container's events and needs none.  With `more`, a first reply comes
    /// once the wait is armed (see [`Waited`]).  The wait ends when the
    /// connection is closed.
    #[zlink(more)]
    async fn container_wait(
        &mut self,
        name: &str,
        conditions: Vec<WaitCondition>,
        interval_ns: i64,
    ) -> zlink::Result<
        impl zlink::futures_util::Stream<Item = zlink::Result<Result<Waited, EngineError>>>,
    >;

    /// `GET /images/{name}/exists`: the image (or a manifest list) is there.
    async fn image_exists(&mut self, name: &str) -> zlink::Result<Result<Ack, EngineError>>;

    /// `POST /images/{name}/tag`: `repo` as the API got it, qualified by the
    /// engine (a short one of Docker Hub with `docker_hub`, as
    /// `CommitSpec`'s).
    async fn image_tag(
        &mut self,
        name: &str,
        repo: &str,
        tag: &str,
        docker_hub: bool,
    ) -> zlink::Result<Result<Ack, EngineError>>;

    /// Take names from an image: `names` (a name without a registry is
    /// localhost's, without a tag `latest`; `NAME@DIGEST` of the image is
    /// none to take), every one if none.
    async fn image_untag(
        &mut self,
        name: &str,
        names: Vec<String>,
    ) -> zlink::Result<Result<Ack, EngineError>>;

    /// `DELETE /images/{name}`: with `force` the containers that use it go
    /// too, but those that run with `spare_running` (the image is then
    /// refused); `noprune`: its parents stay; `manifest_list`: the name is
    /// a manifest list's, which goes.
    async fn image_remove(
        &mut self,
        name: &str,
        force: bool,
        spare_running: bool,
        noprune: bool,
        ignore: bool,
        manifest_list: bool,
    ) -> zlink::Result<Result<ImageRemoved, EngineError>>;

    /// Remove the directories of RUN --mount=type=cache no build step uses:
    /// the bytes they took.
    async fn build_cache_prune(&mut self) -> zlink::Result<Result<Reclaimed, EngineError>>;

    /// Remove the unused images (all, else the dangling ones; with `all`
    /// the manifest lists too) that the filters select (`label`, `label!`,
    /// `until`): what was removed, one a reply.
    #[zlink(more)]
    async fn image_prune(
        &mut self,
        all: bool,
        filters: Vec<Filter>,
    ) -> zlink::Result<
        impl zlink::futures_util::Stream<Item = zlink::Result<Result<ImagePruneListed, EngineError>>>,
    >;

    /// Create a network; with `ignore_if_exists`, one of the name asked
    /// for is the answer (`changed` false).
    async fn network_create(
        &mut self,
        spec: &NetworkSpec,
        ignore_if_exists: bool,
    ) -> zlink::Result<Result<NetworkCreated, EngineError>>;

    /// A network.
    async fn network_inspect(
        &mut self,
        name: &str,
    ) -> zlink::Result<Result<NetworkInspected, EngineError>>;

    /// The networks the filters select, one a reply.
    #[zlink(more)]
    async fn network_list(
        &mut self,
        filters: Vec<Filter>,
    ) -> zlink::Result<
        impl zlink::futures_util::Stream<Item = zlink::Result<Result<NetworkListed, EngineError>>>,
    >;

    async fn network_exists(&mut self, name: &str) -> zlink::Result<Result<Ack, EngineError>>;

    /// `DELETE /networks/{name}`: with `force` the containers that use it
    /// go first, stopped with `timeout` seconds (none: their own)
    async fn network_remove(
        &mut self,
        name: &str,
        force: bool,
        timeout: Option<u64>,
    ) -> zlink::Result<Result<NetworkRemoved, EngineError>>;

    /// Remove the networks no container uses that the filters select:
    /// their names.
    async fn network_prune(
        &mut self,
        filters: Vec<Filter>,
    ) -> zlink::Result<Result<Pruned, EngineError>>;

    /// `POST /networks/{name}/update`: DNS servers added and removed
    async fn network_update(
        &mut self,
        name: &str,
        add_dns_servers: Vec<String>,
        remove_dns_servers: Vec<String>,
    ) -> zlink::Result<Result<Ack, EngineError>>;

    /// `POST /networks/{name}/connect`
    async fn network_connect(
        &mut self,
        name: &str,
        container: &str,
        ip: Option<&str>,
        ip6: Option<&str>,
        mac: Option<&str>,
        aliases: Vec<String>,
    ) -> zlink::Result<Result<Ack, EngineError>>;

    /// Apply the firewall rules of the networks of a running container
    /// again: its id, empty when `if_configured` and it has nothing to
    /// apply them to.
    async fn network_reload(
        &mut self,
        container: &str,
        if_configured: bool,
    ) -> zlink::Result<Result<Id, EngineError>>;

    /// `POST /networks/{name}/disconnect`
    async fn network_disconnect(
        &mut self,
        name: &str,
        container: &str,
        force: bool,
    ) -> zlink::Result<Result<Ack, EngineError>>;

    /// Create a volume; with `ignore_if_exists`, one of the name asked for
    /// is the answer.
    async fn volume_create(
        &mut self,
        spec: &VolumeSpec,
        ignore_if_exists: bool,
    ) -> zlink::Result<Result<VolumeInspected, EngineError>>;

    /// A volume.
    async fn volume_inspect(
        &mut self,
        name: &str,
    ) -> zlink::Result<Result<VolumeInspected, EngineError>>;

    /// The volumes the filters select, one a reply.
    #[zlink(more)]
    async fn volume_list(
        &mut self,
        filters: Vec<Filter>,
    ) -> zlink::Result<
        impl zlink::futures_util::Stream<Item = zlink::Result<Result<VolumeListed, EngineError>>>,
    >;

    async fn volume_exists(&mut self, name: &str) -> zlink::Result<Result<Ack, EngineError>>;

    async fn volume_rename(
        &mut self,
        name: &str,
        new_name: &str,
    ) -> zlink::Result<Result<Ack, EngineError>>;

    /// Remove a volume: with `force`, the containers that use it go first,
    /// given `timeout` seconds to stop (none if absent).
    async fn volume_remove(
        &mut self,
        name: &str,
        force: bool,
        timeout: Option<u64>,
    ) -> zlink::Result<Result<VolumeRemoved, EngineError>>;

    /// Remove the volumes no container uses that the filters select: their
    /// names and the bytes they had (with `dry_run`, only those).
    async fn volume_prune(
        &mut self,
        filters: Vec<Filter>,
        dry_run: bool,
    ) -> zlink::Result<Result<VolumesPruned, EngineError>>;

    /// Mount what the options of a volume ask for: where its content is.
    async fn volume_mount(&mut self, name: &str) -> zlink::Result<Result<Mounted, EngineError>>;

    /// Unmount what `VolumeMount` mounted.
    async fn volume_unmount(&mut self, name: &str) -> zlink::Result<Result<Ack, EngineError>>;

    /// `POST /secrets/create`: the data of the secret (at most 512 kB) is one
    /// descriptor, the sealed memory file the call carries as `data`.
    async fn secret_create(
        &mut self,
        name: &str,
        driver: Option<&str>,
        driver_opts: BTreeMap<String, String>,
        labels: BTreeMap<String, String>,
        replace: bool,
        ignore: bool,
        data: u32,
        #[zlink(fds)] fds: Vec<OwnedFd>,
    ) -> zlink::Result<Result<Id, EngineError>>;

    /// The secrets the filters select, one a reply.
    #[zlink(more)]
    async fn secret_list(
        &mut self,
        filters: Vec<Filter>,
    ) -> zlink::Result<
        impl zlink::futures_util::Stream<Item = zlink::Result<Result<SecretListed, EngineError>>>,
    >;

    /// A secret; with `show_data`, its data is the sealed memory file the
    /// reply carries.
    #[zlink(return_fds)]
    async fn secret_inspect(
        &mut self,
        name: &str,
        show_data: bool,
    ) -> zlink::Result<(Result<SecretInspected, EngineError>, Vec<OwnedFd>)>;

    async fn secret_exists(&mut self, name: &str) -> zlink::Result<Result<Ack, EngineError>>;

    /// `DELETE /secrets/{name}`; `all`: every secret
    async fn secret_remove(
        &mut self,
        name: &str,
        all: bool,
    ) -> zlink::Result<Result<Ack, EngineError>>;

    /// Create a pod: the pod to create is a typed document
    /// ([`crate::pod::PodSpec`] as JSON, at most [`MAX_POD_SPEC`] bytes), the
    /// content of a pipe: the call carries its read end as the descriptor
    /// `spec` names, the caller writes to the other end and closes it (read
    /// to its end).  A frontend decodes
    /// the request of its protocol (podman's PodSpecGenerator, the CRI's
    /// sandbox) into the spec; a pod without a name gets one.
    async fn pod_create(
        &mut self,
        spec: u32,
        #[zlink(fds)] fds: Vec<OwnedFd>,
    ) -> zlink::Result<Result<Id, EngineError>>;

    async fn pod_exists(&mut self, name: &str) -> zlink::Result<Result<Ack, EngineError>>;

    /// `POST /pods/{name}/update`: replace the limits of the cgroup of the
    /// pod (what bounds all its containers) with `resources`; the id of the
    /// pod
    async fn pod_update(
        &mut self,
        name: &str,
        resources: PodResources,
    ) -> zlink::Result<Result<Id, EngineError>>;

    /// Start, stop, kill, pause, unpause or restart the containers of a pod:
    /// `timeout` (seconds) is of a stop or a restart, `signal` of a kill.
    /// `verify_image`: of a start or a restart, the digests typed on the
    /// command, which the images of the containers are held to (each enforced
    /// image made from a digest is named by one, each digest names one);
    /// `service`: the start of a service that has no command line (the CRI):
    /// the engine goes by the records of the containers.
    async fn pod_run(
        &mut self,
        name: &str,
        op: PodAction,
        timeout: Option<u64>,
        signal: Option<&str>,
        verify_image: Vec<String>,
        service: Option<bool>,
    ) -> zlink::Result<Result<PodRan, EngineError>>;

    /// `DELETE /pods/{name}`: with `force` its running containers stop with
    /// `timeout` seconds (none: their own)
    async fn pod_remove(
        &mut self,
        name: &str,
        force: bool,
        timeout: Option<u64>,
    ) -> zlink::Result<Result<PodRemoved, EngineError>>;

    /// The processes of the containers of a pod that run, as `ps` shows
    /// them with `ps_args`.
    async fn pod_top(
        &mut self,
        name: &str,
        ps_args: Vec<String>,
    ) -> zlink::Result<Result<Processes, EngineError>>;

    /// Remove the pods none of whose containers runs: their ids.
    async fn pod_prune(&mut self) -> zlink::Result<Result<Pruned, EngineError>>;

    /// `GET /manifests/{name}/exists`
    async fn manifest_exists(&mut self, name: &str) -> zlink::Result<Result<Ack, EngineError>>;

    /// Remove a manifest list (its instances stay).
    async fn manifest_remove(
        &mut self,
        name: &str,
    ) -> zlink::Result<Result<ManifestRemoved, EngineError>>;

    /// The artifacts of the store, one a reply.
    #[zlink(more)]
    async fn artifact_list(
        &mut self,
    ) -> zlink::Result<
        impl zlink::futures_util::Stream<Item = zlink::Result<Result<ArtifactListed, EngineError>>>,
    >;

    /// An artifact of the store.
    async fn artifact_inspect(
        &mut self,
        name: &str,
    ) -> zlink::Result<Result<ArtifactInspected, EngineError>>;

    /// Remove an artifact: its digest.
    async fn artifact_remove(&mut self, name: &str) -> zlink::Result<Result<Id, EngineError>>;

    /// The logs of a container: the lines `opts` selects, then those that
    /// follow; the multiplexed frames of the pipe the reply carries.
    #[zlink(return_fds)]
    async fn container_logs(
        &mut self,
        name: &str,
        opts: LogOptions,
    ) -> zlink::Result<(Result<Stream, EngineError>, Vec<OwnedFd>)>;

    /// The logs of the containers of a pod, merged by time, one line a
    /// reply, and a last reply without one; a follow is answered first
    /// without a line, once it was taken.
    #[zlink(more)]
    async fn pod_logs(
        &mut self,
        name: &str,
        opts: PodLogOptions,
    ) -> zlink::Result<
        impl zlink::futures_util::Stream<Item = zlink::Result<Result<PodLogListed, EngineError>>>,
    >;

    /// `POST /exec/{id}/resize`
    async fn exec_resize(
        &mut self,
        id: &str,
        height: i64,
        width: i64,
        running: bool,
    ) -> zlink::Result<Result<Ack, EngineError>>;

    /// Remove an exec session; `force`: also one whose command runs.
    async fn exec_remove(
        &mut self,
        id: &str,
        force: bool,
    ) -> zlink::Result<Result<Ack, EngineError>>;

    /// `POST /exec/{id}/kill`
    async fn exec_kill(
        &mut self,
        id: &str,
        signal: &str,
    ) -> zlink::Result<Result<Ack, EngineError>>;

    /// `POST /containers/{name}/attach`, called with `more`: see
    /// [`SessionReply`].  The replies carry descriptors, the streams of the
    /// process; with `opts.logs` the first one carries the pipe of the log
    /// so far, which the client is sent first.
    #[zlink(more, return_fds)]
    async fn container_attach(
        &mut self,
        name: &str,
        opts: AttachOptions,
    ) -> zlink::Result<
        impl zlink::futures_util::Stream<
            Item = zlink::Result<(Result<SessionReply, EngineError>, Vec<OwnedFd>)>,
        >,
    >;

    /// The input of the session `session` ends once what the client wrote
    /// is read: the process's input is closed.  Called on a connection of
    /// its own (the one of the session is read by the frontend); answered
    /// once the monitor was told.
    async fn session_close_stdin(
        &mut self,
        session: &str,
    ) -> zlink::Result<Result<Ack, EngineError>>;

    /// The client of the session `session` typed the detach keys: the
    /// session goes on without it.  Answered once the monitor was told.
    async fn session_detach(&mut self, session: &str) -> zlink::Result<Result<Ack, EngineError>>;

    /// `POST /containers/{name}/resize`
    async fn container_resize(
        &mut self,
        name: &str,
        height: i64,
        width: i64,
    ) -> zlink::Result<Result<Ack, EngineError>>;

    /// Build an image from the spec ([`crate::buildspec::BuildSpec`], JSON)
    /// that the descriptor `spec` names (the read end of a pipe) holds: the engine reads it to its end, at
    /// most `MAX_BUILD_SPEC` bytes.  `context`: the build context, as
    /// the descriptor the client opened: a pipe, a tar in frames the
    /// frontend streams from its client (never held in memory; the call
    /// ends when it was all read and unpacked), or a directory, which the build
    /// reads in place, through the descriptor (nothing is copied: COPY and
    /// ADD, the digests their steps are cached under, the Containerfile and
    /// the ignore files are looked up below it, no link followed out of it;
    /// a file that changes meanwhile is read as it is when a step reads it).
    /// A source of `RUN --mount` from it, and the context an SBOM scanner
    /// mounts, is a copy that the confined worker makes for the step (the
    /// kernel does not clone a mount of the client's mount namespace for the
    /// runtime);
    /// absent the spec names where the context is: a
    /// `remote` one, or `local_dir`, a directory of the host of the engine
    /// (podman's local route).  After
    /// the pipes the call names come, in this order, the socket of the
    /// broker of the ssh agents when the spec names agents, and the standard
    /// input of the client when the spec has `stdin`; `access` names the
    /// credentials (a sealed memory file).  With `sections` the context pipe
    /// carries the main context and the named contexts of a multipart body,
    /// each as its name, its content in frames and the empty frame (see
    /// `crate::build`).  The reply is the progress as a stream: a
    /// `BuildEvent` as JSON each line, the last one `complete` or `error`
    /// (the frontends lay them out for podman's and Docker's clients).  The
    /// build stops when the reader of the stream closes it, except for the
    /// command line's (the `client` of the spec), which goes on.
    #[zlink(return_fds)]
    async fn image_build(
        &mut self,
        spec: u32,
        context: Option<u32>,
        sections: bool,
        access: Option<u32>,
        #[zlink(fds)] pipes: Vec<OwnedFd>,
    ) -> zlink::Result<(Result<Stream, EngineError>, Vec<OwnedFd>)>;

    /// Answer the question of a build for credentials (a `BuildEvent` of the
    /// kind `credentials` with this `ask`).  `answer` is one descriptor, the sealed memory
    /// file with the answer (JSON: the credentials by `REGISTRY` or
    /// `REGISTRY/REPOSITORY`, the object `auths` of a `RegistryAccess`).
    /// `NoSuchObject` when no build asks it.
    async fn image_build_answer(
        &mut self,
        ask: &str,
        answer: u32,
        #[zlink(fds)] fds: Vec<OwnedFd>,
    ) -> zlink::Result<Result<Ack, EngineError>>;

    /// Remove the build cache nothing uses (the images of its steps, the
    /// directories of `RUN --mount=type=cache`): the ids of the images and
    /// the bytes freed.
    async fn build_prune(&mut self) -> zlink::Result<Result<BuildPruned, EngineError>>;

    /// `POST /auth`: log in to the registry at `host`; the credentials are
    /// the pipe of the call, as `ImageSearch`'s, never in the message.
    async fn registry_login(
        &mut self,
        host: &str,
        access: Option<u32>,
        #[zlink(fds)] fds: Vec<OwnedFd>,
    ) -> zlink::Result<Result<LoginReply, EngineError>>;

    /// The descriptors of the metrics of pods, one a reply.
    #[zlink(more)]
    async fn metric_descriptor_list(
        &mut self,
    ) -> zlink::Result<
        impl zlink::futures_util::Stream<
            Item = zlink::Result<Result<MetricDescriptorListed, EngineError>>,
        >,
    >;

    /// The metrics of the pods that run (of `name` only, with a name), one
    /// pod a reply.
    #[zlink(more)]
    async fn pod_metrics_list(
        &mut self,
        name: Option<&str>,
    ) -> zlink::Result<
        impl zlink::futures_util::Stream<Item = zlink::Result<Result<PodMetricsListed, EngineError>>>,
    >;

    /// `POST /libpod/containers/{name}/connect`, `/libpod/pods/{name}/connect`
    /// (`pod`): a TCP connection to `port` on the loopback of the network
    /// namespace of the container, or of the infra container of the pod, made
    /// inside it; the reply carries the connected socket (descriptor 0).
    #[zlink(return_fds)]
    async fn port_connect(
        &mut self,
        pod: bool,
        name: &str,
        port: u16,
    ) -> zlink::Result<(Result<Ack, EngineError>, Vec<OwnedFd>)>;

    /// Open the log file of a container again (the CRI's `ReopenContainerLog`)
    async fn container_log_reopen(&mut self, name: &str)
        -> zlink::Result<Result<Ack, EngineError>>;

    /// Who the engine is for the CRI: its version and the runtimes it has.
    async fn runtime_inspect(&mut self) -> zlink::Result<Result<RuntimeInfo, EngineError>>;

    /// Create a container from the [`crate::request::CreateContainerRequest`]
    /// the pipe `spec` names carries (JSON, read to its end), the one
    /// creation record of the command line and the CRI: its id.
    async fn container_create(
        &mut self,
        spec: u32,
        #[zlink(fds)] fds: Vec<OwnedFd>,
    ) -> zlink::Result<Result<Id, EngineError>>;

    /// Create a container as another was made (podman's `container
    /// clone`): the request of the original again, under `new_name`
    /// (`NAME-clone` without), with `image` and `pod` when given.  Its id.
    async fn container_clone(
        &mut self,
        name: &str,
        new_name: Option<&str>,
        image: Option<&str>,
        pod: Option<&str>,
    ) -> zlink::Result<Result<Id, EngineError>>;

    /// A container; with `size`, the size of its changes, and of them and
    /// its image.
    async fn container_inspect(
        &mut self,
        name: &str,
        size: bool,
    ) -> zlink::Result<Result<ContainerInspected, EngineError>>;

    /// The OCI configuration of a container (its `config.json`), once it is
    /// created: a document (about 23 kB with the default seccomp profile).
    #[zlink(return_fds)]
    async fn container_runtime_spec(
        &mut self,
        name: &str,
    ) -> zlink::Result<(Result<Document, EngineError>, Vec<OwnedFd>)>;

    /// The containers the filters (podman's of `ps`) select, the infra
    /// containers of the pods too, the newest first, one a reply: those
    /// that run, all with `all`, the `limit` newest (-1: all); with `size`
    /// the size of their changes, with `namespace` the namespaces of their
    /// processes.
    #[zlink(more)]
    async fn container_list(
        &mut self,
        filters: Vec<Filter>,
        all: bool,
        size: bool,
        namespace: bool,
        limit: i64,
    ) -> zlink::Result<
        impl zlink::futures_util::Stream<Item = zlink::Result<Result<ContainerListed, EngineError>>>,
    >;

    /// A pod, with what its infra container says of its network.
    async fn pod_inspect(&mut self, name: &str)
        -> zlink::Result<Result<PodInspected, EngineError>>;

    /// The pods the filters select, one a reply.
    #[zlink(more)]
    async fn pod_list(
        &mut self,
        filters: Vec<Filter>,
    ) -> zlink::Result<
        impl zlink::futures_util::Stream<Item = zlink::Result<Result<PodListed, EngineError>>>,
    >;

    /// An image.
    async fn image_inspect(
        &mut self,
        name: &str,
    ) -> zlink::Result<Result<ImageInspected, EngineError>>;

    /// The images the filters select (podman's of `images`), the oldest
    /// first, one a reply: with `all` the intermediate images of the builds
    /// too, with `manifest_lists` the manifest lists too.
    #[zlink(more)]
    async fn image_list(
        &mut self,
        filters: Vec<Filter>,
        all: bool,
        manifest_lists: bool,
    ) -> zlink::Result<
        impl zlink::futures_util::Stream<Item = zlink::Result<Result<ImageListed, EngineError>>>,
    >;

    /// The steps of the history of an image, the newest first, one a reply.
    #[zlink(more)]
    async fn image_history(
        &mut self,
        name: &str,
    ) -> zlink::Result<
        impl zlink::futures_util::Stream<Item = zlink::Result<Result<ImageHistoryListed, EngineError>>>,
    >;

    /// Pull what `spec.source` names: an image of a registry, the images of
    /// a path (`oci:`, `oci-archive:`, `docker-archive:`, `dir:`, a load
    /// with `archive:`) or of a transport of `[[transports]]`, or with
    /// `spec.artifact` an artifact.  Without more, the reply is what was
    /// pulled once it is in the store (with more, the progress comes before
    /// it).  The credentials and certificates of a client are the JSON of a
    /// `RegistryAccess` in the sealed memory file the call carries as the
    /// descriptor `access` (none: no credentials); the path of a pull from a
    /// path is the descriptor `spec.source_fd` names (a file, a directory,
    /// or the read end of a pipe of frames, which the engine spools).
    async fn image_pull(
        &mut self,
        spec: PullSpec,
        access: Option<u32>,
        #[zlink(fds)] fds: Vec<OwnedFd>,
    ) -> zlink::Result<Result<Pulled, EngineError>>;

    /// [`EngineProxy::image_pull`] with more: the replies as they come, the
    /// progress and then what was pulled.
    #[zlink(rename = "ImagePull", more)]
    async fn image_pull_progress(
        &mut self,
        spec: PullSpec,
        access: Option<u32>,
        #[zlink(fds)] fds: Vec<OwnedFd>,
    ) -> zlink::Result<
        impl zlink::futures_util::Stream<Item = zlink::Result<Result<Pulled, EngineError>>>,
    >;

    /// Samples of what the containers named use (none: those that run, all
    /// with `all`), a container a reply and one without at the end of a
    /// sample; with `stream` again every `interval_ms`.
    #[zlink(more)]
    async fn container_stats(
        &mut self,
        names: Vec<String>,
        all: bool,
        size: bool,
        stream: bool,
        interval_ms: Option<u64>,
    ) -> zlink::Result<
        impl zlink::futures_util::Stream<Item = zlink::Result<Result<StatsListed, EngineError>>>,
    >;

    /// The events of `filters`, from `since_ns` to `until_ns` with
    /// `follow` (else those kept), one a reply, and a last one without; a
    /// follow is answered first without an event, once it was taken.
    #[zlink(more)]
    async fn event_list(
        &mut self,
        filters: Vec<Filter>,
        since_ns: Option<i64>,
        until_ns: Option<i64>,
        follow: bool,
    ) -> zlink::Result<
        impl zlink::futures_util::Stream<Item = zlink::Result<Result<EventListed, EngineError>>>,
    >;

    /// What the registry has for `name`, without pulling it.
    async fn image_remote_inspect(
        &mut self,
        name: &str,
        tls_verify: bool,
    ) -> zlink::Result<Result<RemoteImage, EngineError>>;

    /// Create an exec session in the container `name`: its id.
    async fn exec_create(
        &mut self,
        name: &str,
        spec: ExecSpec,
    ) -> zlink::Result<Result<Id, EngineError>>;

    /// Start an exec session, called with `more` (see [`SessionReply`]; the
    /// replies carry descriptors, the streams of the command), whose only reply is the last one with `detach` (the command runs on
    /// its own); with `input` the client can send the input of the command;
    /// `height` and `width` (characters, 0: not known) are the size of the
    /// terminal.  The call carries `preserved`, descriptors the command gets as
    /// 3, 4, ..., but in the slots of `preserve_holes` (slot 0 is 3), where
    /// it gets none (a `/dev/null` stands in).
    #[zlink(more, return_fds)]
    async fn exec_start(
        &mut self,
        id: &str,
        input: bool,
        detach: bool,
        height: i64,
        width: i64,
        preserve_holes: Vec<u32>,
        #[zlink(fds)] preserved: Vec<OwnedFd>,
    ) -> zlink::Result<
        impl zlink::futures_util::Stream<
            Item = zlink::Result<(Result<SessionReply, EngineError>, Vec<OwnedFd>)>,
        >,
    >;

    /// An exec session.
    async fn exec_inspect(&mut self, id: &str)
        -> zlink::Result<Result<ExecInspected, EngineError>>;

    /// What the images and the containers use of the storage.
    async fn storage_inspect(&mut self) -> zlink::Result<Result<StorageUsage, EngineError>>;

    /// Whether the plugins of the CNI network `network` (`cni:NAME`) say it
    /// is ready.
    async fn network_check(
        &mut self,
        network: &str,
    ) -> zlink::Result<Result<NetworkStatus, EngineError>>;

    /// The content of a volume, a tar archive: the reply carries the
    /// frames of a download (descriptor 0).
    #[zlink(return_fds)]
    async fn volume_export(
        &mut self,
        name: &str,
    ) -> zlink::Result<(Result<Ack, EngineError>, Vec<OwnedFd>)>;

    /// Share the checkpoint archive (of `ContainerCheckpoint`) the
    /// pipe the call carries holds with the other nodes.
    async fn checkpoint_share(
        &mut self,
        #[zlink(fds)] archive: Vec<OwnedFd>,
    ) -> zlink::Result<Result<CheckpointShared, EngineError>>;

    /// Stop sharing the checkpoint of `reference` (its manifest, the public
    /// part of a reference).
    async fn checkpoint_unshare(
        &mut self,
        reference: &str,
    ) -> zlink::Result<Result<Ack, EngineError>>;

    /// Extract the tar archive of the upload (the frames the pipe carries)
    /// into a volume.
    async fn volume_import(
        &mut self,
        name: &str,
        #[zlink(fds)] archive: Vec<OwnedFd>,
    ) -> zlink::Result<Result<Ack, EngineError>>;

    /// Create a container from the document of a podman client the pipe
    /// `spec` names carries (JSON, read to its end): libpod's SpecGenerator, or with
    /// `docker` Docker's configuration (`name`, `platform`: its query).
    async fn podman_container_create(
        &mut self,
        docker: bool,
        name: Option<&str>,
        platform: Option<&str>,
        spec: u32,
        #[zlink(fds)] fds: Vec<OwnedFd>,
    ) -> zlink::Result<Result<ContainerCreated, EngineError>>;

    /// Remove the containers that do not run and the filters select.
    async fn container_prune(
        &mut self,
        filters: Vec<Filter>,
    ) -> zlink::Result<Result<ContainersPruned, EngineError>>;

    /// Change the limits, the environment, the restart policy, the rlimits
    /// and the health check of a container: its id.
    async fn container_amend(
        &mut self,
        name: &str,
        spec: UpdateSpec,
    ) -> zlink::Result<Result<Id, EngineError>>;

    /// Run the health check of a container that runs now: its health after
    /// it.
    async fn container_healthcheck(
        &mut self,
        name: &str,
    ) -> zlink::Result<Result<HealthChecked, EngineError>>;

    /// Checkpoint a container.  `archive`, a descriptor the client opened,
    /// is where the archive goes: an empty regular file open for writing
    /// (not for appending), or the write end of a pipe, to which the engine
    /// writes the frames of a download; the client chooses the file and the
    /// engine creates none.  Without it the checkpoint is kept with the
    /// container, for a restore in place.
    async fn container_checkpoint(
        &mut self,
        name: &str,
        flags: CheckpointFlags,
        archive: Option<u32>,
        #[zlink(fds)] fds: Vec<OwnedFd>,
    ) -> zlink::Result<Result<Checkpointed, EngineError>>;

    /// Restore a container.  `name` alone: from its own checkpoint.  With
    /// `archive` (a descriptor the client opened: a regular file open for
    /// reading, or the read end of a pipe of frames) or `reference` (the
    /// checkpoint a node shares, from the content sources) a new container
    /// made of the archive, named by `flags.name`.  With `stage` the archive
    /// is staged in the container `name`, which was never started: its start
    /// restores it.
    async fn container_restore(
        &mut self,
        name: Option<&str>,
        flags: RestoreFlags,
        archive: Option<u32>,
        reference: Option<&str>,
        stage: bool,
        #[zlink(fds)] fds: Vec<OwnedFd>,
    ) -> zlink::Result<Result<Restored, EngineError>>;

    /// What is at `path` in a container (relative: in its working
    /// directory) and, with `content`, its tar archive: the frames of a
    /// download.
    #[zlink(return_fds)]
    async fn container_archive_get(
        &mut self,
        name: &str,
        path: &str,
        content: bool,
    ) -> zlink::Result<(Result<PathStat, EngineError>, Vec<OwnedFd>)>;

    /// Extract the tar archive of the upload into the directory `path` of a
    /// container: the first components of its entries renamed (`rename`),
    /// the files given to the user of the container (`chown`), a directory
    /// and what is not one replacing each other (`overwrite_dir_non_dir`).
    async fn container_archive_put(
        &mut self,
        name: &str,
        path: &str,
        rename: BTreeMap<String, String>,
        chown: bool,
        overwrite_dir_non_dir: bool,
        #[zlink(fds)] archive: Vec<OwnedFd>,
    ) -> zlink::Result<Result<Ack, EngineError>>;

    /// The root file system of a container as a tar archive: the frames of
    /// a download.
    #[zlink(return_fds)]
    async fn container_export(
        &mut self,
        name: &str,
    ) -> zlink::Result<(Result<Ack, EngineError>, Vec<OwnedFd>)>;

    /// The changes of a container to the files of its image, or of an image
    /// to those of its parent (`diff_type`: none is `all`; `parent` another
    /// image to compare with).
    async fn container_diff(
        &mut self,
        name: &str,
        diff_type: Option<DiffType>,
        parent: Option<&str>,
    ) -> zlink::Result<Result<Changes, EngineError>>;

    /// The processes of a container that runs, as `ps` shows them with
    /// `ps_args`: podman's descriptors (`pid`, `user`, `args`...; none:
    /// podman's default ones), or the arguments of ps.
    async fn container_top(
        &mut self,
        name: &str,
        ps_args: Vec<String>,
    ) -> zlink::Result<Result<Processes, EngineError>>;

    /// Mount the root of a container that runs: where.
    async fn container_mount(&mut self, name: &str) -> zlink::Result<Result<Mounted, EngineError>>;

    /// Unmount the root of a container.
    async fn container_unmount(&mut self, name: &str) -> zlink::Result<Result<Ack, EngineError>>;

    /// The containers whose root is mounted.
    async fn container_mount_list(&mut self) -> zlink::Result<Result<MountedList, EngineError>>;

    /// Search registries for `term` (`filters`: `key=value`).  The
    /// credentials are the JSON of `velarx_registry::auth::RegistryAccess`
    /// in the sealed memory file the call carries as `access` (none: no credentials).
    async fn image_search(
        &mut self,
        term: &str,
        limit: u32,
        filters: Vec<String>,
        list_tags: bool,
        tls_verify: Option<bool>,
        access: Option<u32>,
        #[zlink(fds)] fds: Vec<OwnedFd>,
    ) -> zlink::Result<Result<SearchHits, EngineError>>;

    /// The names a pull of `name` would try.
    async fn image_resolve(&mut self, name: &str) -> zlink::Result<Result<Names, EngineError>>;

    /// The layers of an image, the images they are the top layer of, and
    /// the images built on it.
    async fn image_tree(
        &mut self,
        name: &str,
    ) -> zlink::Result<Result<ImageTreeInspected, EngineError>>;

    /// Remove images (every one with `all`): libpod's report.
    async fn image_remove_many(
        &mut self,
        names: Vec<String>,
        force: bool,
        ignore: bool,
        noprune: bool,
        all: bool,
        manifest_list: bool,
    ) -> zlink::Result<Result<ImagesRemoved, EngineError>>;

    /// Where the credentials of the completion of a lazily pulled image go:
    /// the endpoints of its layers that were pulled with credentials.
    async fn image_credential_scopes(
        &mut self,
        name: &str,
    ) -> zlink::Result<Result<Scopes, EngineError>>;

    /// Where the credentials of a pull of `reference` (the registry and its
    /// mirrors) or of a push (`push`: the registry) go.
    async fn registry_credential_scopes(
        &mut self,
        reference: &str,
        push: bool,
    ) -> zlink::Result<Result<Scopes, EngineError>>;

    /// The pulls in progress: images whose layers are not all in the store
    /// (`images` lists only complete ones).
    async fn image_pulls(&mut self) -> zlink::Result<Result<PullsListed, EngineError>>;

    /// Whether a pull in progress has the name or the id `name`.
    async fn image_pulling(
        &mut self,
        name: &str,
    ) -> zlink::Result<Result<PullingAnswer, EngineError>>;

    /// Fetch what a lazily pulled image lacks and prove its layers; the
    /// credentials as `ImageSearch`'s.
    async fn image_complete(
        &mut self,
        name: &str,
        access: Option<u32>,
        #[zlink(fds)] fds: Vec<OwnedFd>,
    ) -> zlink::Result<Result<ImageCompleted, EngineError>>;

    /// The digest of the manifest the registry has for `reference` now (of
    /// `platform`, else this host's, for a manifest list); the credentials
    /// as `ImageSearch`'s.
    async fn registry_digest(
        &mut self,
        reference: &str,
        tls_verify: bool,
        platform: Option<&str>,
        access: Option<u32>,
        #[zlink(fds)] fds: Vec<OwnedFd>,
    ) -> zlink::Result<Result<RegistryDigested, EngineError>>;

    /// Create an image from a tar: the upload, or what `spec.url` has.
    async fn image_import(
        &mut self,
        spec: ImportSpec,
        #[zlink(fds)] archive: Vec<OwnedFd>,
    ) -> zlink::Result<Result<Id, EngineError>>;

    /// The changes of a container as a new image; the pipe `changes` names
    /// carries the settings of its configuration (JSON, a Docker container
    /// configuration, read to its end; none: no pipe).  Without more, the reply
    /// is the id of the image (with more, the progress comes before it).
    async fn container_commit(
        &mut self,
        spec: CommitSpec,
        changes: Option<u32>,
        #[zlink(fds)] fds: Vec<OwnedFd>,
    ) -> zlink::Result<Result<Committed, EngineError>>;

    /// [`EngineProxy::container_commit`] with more: the replies as they
    /// come, the progress and then the id of the image.
    #[zlink(rename = "ContainerCommit", more)]
    async fn container_commit_progress(
        &mut self,
        spec: CommitSpec,
        changes: Option<u32>,
        #[zlink(fds)] fds: Vec<OwnedFd>,
    ) -> zlink::Result<
        impl zlink::futures_util::Stream<Item = zlink::Result<Result<Committed, EngineError>>>,
    >;

    /// Add a file to an artifact: the digest of the artifact.  Exactly one
    /// of `file`, the position of a descriptor the client opened (a regular
    /// file, or the read end of a pipe of frames, an upload), and `path`, a
    /// file on the host of the engine that the engine opens as its own user
    /// (podman's local API).
    async fn artifact_add(
        &mut self,
        spec: ArtifactAddSpec,
        file: Option<u32>,
        path: Option<&str>,
        #[zlink(fds)] fds: Vec<OwnedFd>,
    ) -> zlink::Result<Result<Id, EngineError>>;

    /// A tar of the blobs of an artifact (those of `digest` or `title`),
    /// named by their titles (by their digests with `by_digest`): the
    /// frames of a download.
    #[zlink(return_fds)]
    async fn artifact_extract(
        &mut self,
        name: &str,
        digest: Option<&str>,
        title: Option<&str>,
        by_digest: bool,
    ) -> zlink::Result<(Result<Ack, EngineError>, Vec<OwnedFd>)>;

    /// Make a manifest list of `images`: with `amend` a list of the name
    /// that is there is taken; `all` takes every instance of the lists among
    /// the images; `instance` says how the images are instances;
    /// `annotations` are those of the index and `subject` its subject;
    /// `digest` (`sha256` or `sha512`) is the algorithm of the digest of the
    /// list (none: the engine's `[build] digest`).
    /// The credentials are one descriptor, the sealed memory file `access` names.
    #[allow(
        clippy::too_many_arguments,
        reason = "one parameter for each field of the varlink call"
    )]
    async fn manifest_create(
        &mut self,
        name: &str,
        images: Vec<String>,
        amend: bool,
        all: bool,
        tls_verify: bool,
        annotations: BTreeMap<String, String>,
        instance: InstanceSpec,
        subject: Option<String>,
        digest: Option<String>,
        access: Option<u32>,
        #[zlink(fds)] fds: Vec<OwnedFd>,
    ) -> zlink::Result<Result<Id, EngineError>>;

    /// A manifest list, of the store or of its registry, as OCI's index.
    /// The credentials as `ManifestCreate`'s.
    async fn manifest_inspect(
        &mut self,
        name: &str,
        tls_verify: bool,
        access: Option<u32>,
        #[zlink(fds)] fds: Vec<OwnedFd>,
    ) -> zlink::Result<Result<ManifestListRecord, EngineError>>;

    /// Add images to a list: its id.  The credentials as
    /// `ManifestCreate`'s.
    #[allow(
        clippy::too_many_arguments,
        reason = "one parameter for each field of the varlink call"
    )]
    async fn manifest_add_images(
        &mut self,
        name: &str,
        images: Vec<String>,
        all: bool,
        instance: InstanceSpec,
        tls_verify: bool,
        access: Option<u32>,
        #[zlink(fds)] fds: Vec<OwnedFd>,
    ) -> zlink::Result<Result<Id, EngineError>>;

    /// Remove the instance `digest` from a list: its id.
    async fn manifest_remove_instance(
        &mut self,
        name: &str,
        digest: &str,
    ) -> zlink::Result<Result<Id, EngineError>>;

    /// Annotate an instance of a list (an image or a digest; none: the
    /// list), set the annotations of the index and its subject: its id.
    async fn manifest_annotate(
        &mut self,
        name: &str,
        instance: Option<String>,
        spec: InstanceSpec,
        index_annotations: BTreeMap<String, String>,
        subject: Option<String>,
    ) -> zlink::Result<Result<Id, EngineError>>;

    /// Add an artifact made of files to a list: its digest.  The call carries
    /// one descriptor for each of the titles of the spec (at most 64), and
    /// the credentials as the sealed memory file `access` names.
    async fn manifest_add_artifact(
        &mut self,
        name: &str,
        spec: ManifestArtifactSpec,
        tls_verify: bool,
        access: Option<u32>,
        #[zlink(fds)] pipes: Vec<OwnedFd>,
    ) -> zlink::Result<Result<Id, EngineError>>;

    /// The systemd units of a container or a pod.
    async fn systemd_generate(
        &mut self,
        name: &str,
        spec: SystemdSpec,
    ) -> zlink::Result<Result<Units, EngineError>>;

    /// Push images, a manifest list or an artifact: without more, the reply is what
    /// was pushed (with more, where the push goes and the progress of its
    /// blobs come before it).  The credentials as `ImageSearch`'s.
    async fn image_push(
        &mut self,
        spec: PushSpec,
        access: Option<u32>,
        #[zlink(fds)] fds: Vec<OwnedFd>,
    ) -> zlink::Result<Result<Pushed, EngineError>>;

    /// [`EngineProxy::image_push`] with more: the replies as they come,
    /// where the push goes, the progress and then what was pushed.
    #[zlink(rename = "ImagePush", more)]
    async fn image_push_progress(
        &mut self,
        spec: PushSpec,
        access: Option<u32>,
        #[zlink(fds)] fds: Vec<OwnedFd>,
    ) -> zlink::Result<
        impl zlink::futures_util::Stream<Item = zlink::Result<Result<Pushed, EngineError>>>,
    >;
}

#[cfg(test)]
mod status_tests {
    use super::{Condition as C, EngineError as E};

    #[test]
    fn a_condition_has_one_status_by_value_or_by_name() {
        for (c, status) in [
            (C::NoSuchPod, 404),
            (C::Conflict, 409),
            (C::InvalidState, 409),
            (C::TooLarge, 413),
            (C::Unavailable, 503),
            (C::NotStarted, 500),
            (C::Failed, 500),
        ] {
            let e = E::of(c, String::new(), String::new());
            assert_eq!(e.status(), status, "{}", c.name());
            assert_eq!(E::status_of_name(c.name()), Some(status), "{}", c.name());
        }
        assert_eq!(E::status_of_name("NoSuchAnything"), Some(404));
        assert_eq!(E::status_of_name("Unknown"), None);
    }

    /// Every condition has its row in the table, and a variant of the error:
    /// the name, the statuses and the error come back to the condition.
    #[test]
    fn every_condition_has_a_status() {
        let mut statuses = Vec::new();
        for c in C::ALL {
            let e = E::of(c, "c".into(), "m".into());
            assert_eq!(e.condition(), c);
            assert_eq!(e.parts(), ("c", "m"));
            assert_eq!(C::from_name(c.name()), Some(c));
            assert_eq!(
                E::from_name(c.name(), "c".into(), "m".into()),
                Some(e.clone())
            );
            let state = c == C::InvalidState;
            // (a status chooses among the conditions that share it)
            if !matches!(
                c,
                C::NoCheckpoint
                    | C::InvalidReference
                    | C::NeedsForce
                    | C::InvalidName
                    | C::InvalidArchive
                    | C::NotStarted
                    | C::CommandNotFound
                    | C::NoPasta
                    | C::InvalidContent
                    | C::SourceUnavailable
                    | C::ImageNotLazy
                    | C::Contradicted
            ) {
                let back = E::from_status(e.status(), state, c, "c".into(), "m".into());
                assert_eq!(back.condition(), c, "{}", c.name());
            }
            statuses.push(e.status());
        }
        assert_eq!(
            statuses,
            [
                404, 404, 404, 404, 404, 404, 404, 404, 409, 409, 409, 404, 500, 400, 400, 400,
                413, 403, 401, 501, 507, 502, 503, 500, 500, 500, 500, 500, 400, 500, 500
            ]
        );
    }
}

#[cfg(test)]
mod health_update_tests {
    use super::*;

    #[test]
    fn podmans_words_are_typed_once_at_the_boundary() {
        let spec = |a: &str| {
            PodmanHealthUpdate {
                health_on_failure: Some(a.into()),
                ..Default::default()
            }
            .spec()
        };
        assert_eq!(
            spec("restart").unwrap().unwrap().on_failure,
            Some(OnFailure::Restart)
        );
        assert_eq!(
            spec("none").unwrap().unwrap().on_failure,
            Some(OnFailure::None)
        );
        assert_eq!(
            spec("explode").unwrap_err(),
            "invalid on-failure action \"explode\""
        );
    }
}
