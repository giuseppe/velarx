// SPDX-License-Identifier: Apache-2.0
//! The engine as a whole as typed records, the engine's own surface (not
//! the documents of podman's API, which `velarx-shape` lays out of them):
//! its build (`VersionInspect`), what it is and what it runs on
//! (`SystemInspect`), what the store uses
//! (`DiskUsageInspect`), what a prune removed (`SystemPrune`), what a check
//! of the store found (`SystemCheck`), what a collection freed
//! (`SystemCollect`), the stores of a storage service (`SystemStores`) and
//! its health (`Health`).  They are types of the
//! interface definition; times are nanoseconds since the epoch, 0 for a
//! time that is not set; sizes are bytes.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Who makes the cgroups of the containers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "proxy", derive(zlink::introspect::CustomType))]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "proxy", zlink(rename_all = "snake_case"))]
pub enum CgroupManager {
    Systemd,
    #[default]
    Cgroupfs,
}

/// The engine: its build.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "proxy", derive(zlink::introspect::CustomType))]
#[serde(default)]
pub struct VersionRecord {
    /// Of the package
    pub version: String,
    /// The git commit it was built of
    pub commit: String,
    /// When it was built (0: not known)
    pub built_ns: i64,
    pub os: String,
    /// The architecture as Rust names it (`x86_64`, `aarch64`)
    pub arch: String,
    /// The release of the kernel
    pub kernel: String,
}

/// `VersionInspect` answers.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "proxy", derive(zlink::introspect::Type))]
pub struct VersionInspected {
    pub version: VersionRecord,
}

/// An executable of the host the engine uses: where, the package it came
/// from (rpm or dpkg), the first line of its `--version` (empty when it is
/// not there).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "proxy", derive(zlink::introspect::CustomType))]
#[serde(default)]
pub struct HostTool {
    pub path: String,
    pub package: String,
    pub version: String,
}

/// An OCI runtime the containers can be made with.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "proxy", derive(zlink::introspect::CustomType))]
#[serde(default)]
pub struct RuntimePath {
    pub name: String,
    pub path: String,
    /// The document its `features` prints, as `OciRuntimeRecord` has it
    pub features: String,
}

/// The OCI runtime of the containers by default.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "proxy", derive(zlink::introspect::CustomType))]
#[serde(default)]
pub struct OciRuntimeRecord {
    pub name: String,
    pub path: String,
    pub package: String,
    /// The first line of its `--version`
    pub version: String,
    /// The document its `features` prints (the runtime-spec features), as
    /// it prints it: both podman's and Docker's documents carry it as
    /// text; empty when it has none
    pub features: String,
}

/// Whether a rootless user's units run, and run at boot.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "proxy", derive(zlink::introspect::CustomType))]
#[serde(default)]
pub struct SystemdRecord {
    /// The user's manager answers
    pub user_manager: bool,
    /// Lingering is on: the manager and its units run at boot
    pub linger: bool,
    /// What does not work because of it (empty: nothing)
    pub warning: String,
}

/// A pool of the subnets of new networks (`[[network.subnet_pools]]`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "proxy", derive(zlink::introspect::CustomType))]
#[serde(default)]
pub struct SubnetPool {
    pub base: String,
    /// The prefix length of each subnet
    pub size: u64,
}

/// The shares of the CPU time of the host since its boot, in percent.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "proxy", derive(zlink::introspect::CustomType))]
#[serde(default)]
pub struct CpuUtilization {
    pub user_percent: f64,
    pub system_percent: f64,
    pub idle_percent: f64,
}

/// The host the engine runs on, and what it runs the containers with.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "proxy", derive(zlink::introspect::CustomType))]
#[serde(default)]
pub struct HostRecord {
    pub hostname: String,
    pub cpus: u64,
    pub mem_total: u64,
    pub mem_free: u64,
    pub mem_available: u64,
    pub swap_total: u64,
    pub swap_free: u64,
    /// How long the host has run
    pub uptime_ns: i64,
    pub cgroup_manager: CgroupManager,
    /// 1 or 2
    pub cgroup_version: u64,
    /// The cgroup controllers the containers can have
    pub cgroup_controllers: Vec<String>,
    pub cpu_utilization: CpuUtilization,
    /// The platforms (`linux/arm64`) the host runs through the binfmt_misc
    /// handlers of QEMU
    pub emulated_architectures: Vec<String>,
    /// The UID mappings of the user namespace of a rootless engine (none for
    /// root)
    pub uid_mappings: Vec<crate::pod::IdMapping>,
    /// The GID mappings of the user namespace of a rootless engine (none for
    /// root)
    pub gid_mappings: Vec<crate::pod::IdMapping>,
    /// The engine runs in a user namespace
    pub rootless: bool,
    pub selinux: bool,
    /// Where the events are kept (`file`, `journald`, `memory`...)
    pub event_logger: String,
    /// The log driver of a container that does not choose one
    pub log_driver: String,
    /// The monitor of the containers (podman's conmon)
    pub monitor_path: String,
    /// The executable of the engine
    pub engine_path: String,
    /// The CDI spec directories
    pub cdi_spec_dirs: Vec<String>,
    /// The CDI devices in the spec directories
    pub cdi_devices: Vec<String>,
    /// The errors of the CDI spec files
    pub cdi_errors: Vec<String>,
    pub pasta: HostTool,
    pub slirp4netns: HostTool,
    pub oci_runtime: OciRuntimeRecord,
    /// The other runtimes a container can be made with (`[runtimes]` of
    /// the configuration, those that are there)
    pub runtimes: Vec<RuntimePath>,
    /// The kernel passes the reads of FUSE through
    pub fuse_passthrough: bool,
    /// Users may make user namespaces
    pub userns: bool,
    /// The user's systemd manager, of a rootless engine
    pub systemd: Option<SystemdRecord>,
}

/// The store of the engine.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "proxy", derive(zlink::introspect::CustomType))]
#[serde(default)]
pub struct StoreRecord {
    /// The configuration file of the engine (the default one when it read
    /// none)
    pub config_file: String,
    /// The root of the storage (podman's graph root)
    pub graph_root: String,
    /// The inodes of its file system (none when it cannot be asked)
    pub graph_root_inodes: Option<u64>,
    /// The inodes of its file system in use (none when it cannot be asked)
    pub graph_root_inodes_used: Option<u64>,
    /// The bytes of its file system
    pub graph_root_allocated: u64,
    /// The bytes of its file system that are used
    pub graph_root_used: u64,
    /// The state of the engine (podman's run root)
    pub run_root: String,
    /// The root of what the engine keeps
    pub root_dir: String,
    pub volume_path: String,
    pub containers: u64,
    pub running: u64,
    pub paused: u64,
    pub stopped: u64,
    pub images: u64,
    /// The storage driver of the store, by its own name (`composefs`)
    pub storage_driver: String,
    /// The graph driver as podman and Docker report it (`overlay` for
    /// composefs), which tools key on
    pub graph_driver: String,
    /// What the driver reports of itself
    pub graph_status: std::collections::BTreeMap<String, String>,
}

/// What `SystemInspect` answers: the engine, its host and its store.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "proxy", derive(zlink::introspect::CustomType))]
#[serde(default)]
pub struct SystemRecord {
    pub version: VersionRecord,
    pub host: HostRecord,
    pub store: StoreRecord,
    /// The registries a short name is searched in
    pub search_registries: Vec<String>,
    pub subnet_pools: Vec<SubnetPool>,
}

/// `SystemInspect` answers.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "proxy", derive(zlink::introspect::Type))]
pub struct SystemInspected {
    pub system: SystemRecord,
}

/// What an image uses of the store.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "proxy", derive(zlink::introspect::CustomType))]
#[serde(default)]
pub struct ImageUsage {
    pub id: String,
    pub names: Vec<String>,
    /// `NAME@DIGEST` of each name, the digest of its manifest
    pub digests: Vec<String>,
    pub created_ns: i64,
    /// Its metadata and its layers
    pub size: u64,
    /// What no other image shares of it
    pub unique_size: u64,
    /// The containers of it
    pub containers: u64,
}

/// What a container uses of the store.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "proxy", derive(zlink::introspect::CustomType))]
#[serde(default)]
pub struct ContainerUsage {
    pub id: String,
    pub name: String,
    pub image_id: String,
    /// The command it runs (without the entrypoint)
    pub command: Vec<String>,
    /// The volumes it mounts
    pub volumes: u64,
    /// What it wrote
    pub rw_size: u64,
    /// That and its image
    pub size: u64,
    pub created_ns: i64,
    pub state: crate::workload::RunState,
}

/// What a volume uses.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "proxy", derive(zlink::introspect::CustomType))]
#[serde(default)]
pub struct VolumeUsage {
    pub name: String,
    pub mountpoint: String,
    pub created_ns: i64,
    pub labels: BTreeMap<String, String>,
    /// The containers that mount it
    pub links: u64,
    pub size: u64,
}

/// Files of the store: how many, their size, what a collection would free
/// of them now (none when it cannot tell).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "proxy", derive(zlink::introspect::CustomType))]
#[serde(default)]
pub struct StoreUsage {
    pub count: u64,
    pub size: u64,
    pub reclaimable: Option<u64>,
}

/// What the images, the containers and the volumes use of the disk.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "proxy", derive(zlink::introspect::CustomType))]
#[serde(default)]
pub struct DiskUsageRecord {
    /// With `store`: the storage driver, by its own name, that holds
    /// `objects` and `composefs`
    pub driver: String,
    pub images: Vec<ImageUsage>,
    pub containers: Vec<ContainerUsage>,
    pub volumes: Vec<VolumeUsage>,
    /// All the images, a layer they share counted once
    pub images_size: u64,
    /// What removing the images no container uses frees
    pub images_reclaimable: u64,
    /// With `store`: the files of the layers, by their fs-verity digest
    pub objects: Option<StoreUsage>,
    /// With `store`: the EROFS images of the layers and of the images
    pub composefs: Option<StoreUsage>,
    /// With `store`: the pulls in progress (`staging/lazy`): how many, and
    /// the bytes of their staging area (the files fetched, the tables and
    /// the EROFS images of their layers), all of it reclaimable when every
    /// pull left is cancelled
    pub pulling: Option<StoreUsage>,
}

/// `DiskUsageInspect` answers.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "proxy", derive(zlink::introspect::Type))]
pub struct DiskUsageInspected {
    pub usage: DiskUsageRecord,
}

/// A volume a prune removed.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "proxy", derive(zlink::introspect::CustomType))]
#[serde(default)]
pub struct PrunedVolume {
    pub name: String,
    /// The bytes it had
    pub size: u64,
}

/// What `SystemPrune` removed.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "proxy", derive(zlink::introspect::CustomType))]
#[serde(default)]
pub struct SystemPruneReport {
    pub pods: Vec<String>,
    pub containers: Vec<String>,
    pub networks: Vec<String>,
    pub volumes: Vec<PrunedVolume>,
    pub images: Vec<crate::workload::PrunedImage>,
    /// The bytes the prune freed: what the volumes and the writable layers
    /// of the containers removed had, the metadata of the images removed
    /// and their layers the store no longer has, each once (a layer an
    /// image left, a container or a pull holds is not counted; podman counts
    /// each image whole)
    pub reclaimed: u64,
}

/// `SystemPrune` answers.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "proxy", derive(zlink::introspect::Type))]
pub struct SystemPruned {
    pub report: SystemPruneReport,
}

/// What `SystemCheck` checks.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "proxy", derive(zlink::introspect::CustomType))]
#[serde(default)]
pub struct CheckSpec {
    /// Skip what reads the content of the files and of the images.
    pub quick: bool,
    /// Fix what is derivable from the store, remove the images that are
    /// damaged and not in use (podman's `--repair`).
    pub repair: bool,
    /// With `repair`: also remove the containers that use a damaged image,
    /// then the image (podman's `--force`, `repair_lossy`).  A running
    /// container is left alone.
    pub repair_lossy: bool,
    /// Stop starting the check of another image after this many
    /// milliseconds (none: check them all).
    pub timeout_ms: Option<u64>,
    /// A file of the store that nothing accounts for is a leftover once it
    /// has been unchanged for this many milliseconds (podman's `--max`;
    /// none: `check_leftover_age_secs` of the configuration).
    pub max_age_ms: Option<u64>,
}

/// What was done about a problem the check found.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "proxy", derive(zlink::introspect::CustomType))]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "proxy", zlink(rename_all = "snake_case"))]
pub enum CheckAction {
    /// Nothing: the check does not repair, or the problem cannot be
    /// repaired here.
    #[default]
    None,
    /// Repaired.
    Repaired,
    /// The image was removed: its damage cannot be repaired without
    /// pulling it again.
    ImageRemoved,
    /// The image is damaged and containers use it: it was left alone.
    ImageInUse,
}

/// A problem of the store, of an image if it has one.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "proxy", derive(zlink::introspect::CustomType))]
#[serde(default)]
pub struct CheckProblem {
    /// The id of the image the problem is of (none: of the store).
    pub image: Option<String>,
    /// A name of that image.
    pub name: Option<String>,
    pub kind: String,
    pub message: String,
    pub path: Option<String>,
    pub action: CheckAction,
}

/// Whether a finding of this kind is damage to the store.  A file without
/// the fs-verity that the store requires is whole (`no_verity`), and so is
/// a volume whose directory is intact and whose row or mode is not what
/// it says.
pub fn kind_damages(kind: &str) -> bool {
    !matches!(
        kind,
        "no_verity"
            | "orphan_volume"
            | "stale_volume_row"
            | "volume_row_mismatch"
            | "unfinished_volume_removal"
            | "stale_volume_temp"
            | "volume_mode"
    )
}

impl CheckProblem {
    /// Whether the store is still not as it should be because of it.
    pub fn open(&self) -> bool {
        matches!(self.action, CheckAction::None | CheckAction::ImageInUse)
    }
}

/// A container that `repair_lossy` removed.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "proxy", derive(zlink::introspect::CustomType))]
#[serde(default)]
pub struct CheckRemovedContainer {
    pub id: String,
    pub name: String,
}

/// What a check of the store found and did.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "proxy", derive(zlink::introspect::CustomType))]
#[serde(default)]
pub struct CheckReport {
    pub images_total: u64,
    pub images_checked: u64,
    /// Not reached before `timeout_ms` ran out.
    pub images_unchecked: u64,
    pub files_checked: u64,
    pub bytes_read: u64,
    pub elapsed_ms: u64,
    pub problems: Vec<CheckProblem>,
    /// The containers `repair_lossy` removed, with their images.
    pub removed_containers: Vec<CheckRemovedContainer>,
}

impl CheckReport {
    /// Nothing is broken now (what was repaired or removed counts as
    /// fine).
    pub fn ok(&self) -> bool {
        !self.problems.iter().any(CheckProblem::open)
    }
}

/// `SystemCheck` answers.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "proxy", derive(zlink::introspect::Type))]
pub struct SystemChecked {
    pub report: CheckReport,
}

/// What a collection of the garbage of the store removed (or, for a dry
/// run, would remove).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "proxy", derive(zlink::introspect::CustomType))]
#[serde(default)]
pub struct GcReport {
    pub files_removed: u64,
    pub layers_removed: u64,
    /// Leases of pulls that are gone
    pub leases_removed: u64,
    /// Staging directories of pulls that are gone
    pub staging_removed: u64,
    pub bytes_freed: u64,
    /// What failed on the way (the rest was collected)
    pub errors: Vec<String>,
    pub dry_run: bool,
}

/// `SystemCollect` answers.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "proxy", derive(zlink::introspect::Type))]
pub struct Collected {
    pub report: GcReport,
}

/// A store of the storage service (`[storage] driver = "varlink"`) of the
/// engine's user.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "proxy", derive(zlink::introspect::CustomType))]
#[serde(default)]
pub struct ServiceStore {
    /// The id of the store (32 hex digits)
    pub store: String,
    /// What the store takes on the service's disk
    pub size: u64,
    /// When an engine last opened it (0: the service does not know)
    pub last_open_ns: i64,
    /// The store of this engine, which is not dropped
    pub current: bool,
}

/// `SystemStores` answers.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "proxy", derive(zlink::introspect::CustomType))]
#[serde(default)]
pub struct StoresReport {
    /// The stores the service holds for the engine's user, after the drop
    pub stores: Vec<ServiceStore>,
    /// The store this call dropped
    pub dropped: Option<String>,
}

/// `SystemStores` answers.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "proxy", derive(zlink::introspect::Type))]
pub struct StoresListed {
    pub report: StoresReport,
}

/// The health of a part of the engine.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "proxy", derive(zlink::introspect::CustomType))]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "proxy", zlink(rename_all = "snake_case"))]
pub enum ComponentStatus {
    #[default]
    Healthy,
    Degraded,
    Unhealthy,
}

/// A part of the engine (its database, its storage, its runtime).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "proxy", derive(zlink::introspect::CustomType))]
#[serde(default)]
pub struct ComponentHealth {
    pub name: String,
    pub status: ComponentStatus,
    /// Why it is not healthy
    pub message: Option<String>,
}

/// What `Health` answers: the health of the engine and of its parts.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "proxy", derive(zlink::introspect::Type))]
pub struct HealthReport {
    pub overall: ComponentStatus,
    pub components: Vec<ComponentHealth>,
}
