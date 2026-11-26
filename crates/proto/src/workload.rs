// SPDX-License-Identifier: Apache-2.0
//! The containers, pods, images, exec sessions, volumes, networks and
//! secrets of the engine as typed records, the engine's own surface (not
//! the documents of podman's API, which `velarx-shape` lays out of them):
//! the engine fills them (`ContainerInspect`, `ContainerList`, `PodInspect`,
//! `PodList`, `ImageInspect`, `ImageList`, `ContainerStats`, `ExecInspect`,
//! `VolumeInspect`, `VolumeList`, `NetworkInspect`, `NetworkList`,
//! `SecretInspect`, `SecretList`, the metrics) and reads the specs
//! (`ExecCreate`, `VolumeCreate`, `NetworkCreate`;
//! `ContainerCreate` takes the command line's request, `crate::request`).
//! They are types of the interface definition: a record is the field of a
//! reply, a list is a `more` call with one record a reply.
//! Times are nanoseconds since the epoch, 0 for a time that is not set;
//! sizes are bytes.

use crate::health::{Health, Healthcheck};
use crate::members::{deserialize_members, deserialize_request_members};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// What a pod is, of the states of its containers.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "proxy", derive(zlink::introspect::CustomType))]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "proxy", zlink(rename_all = "snake_case"))]
pub enum PodStatus {
    /// Never started
    #[default]
    Created,
    /// All its containers run
    Running,
    /// Some of its containers run
    Degraded,
    /// Its containers are paused, none runs
    Paused,
    /// None of its containers runs
    Exited,
}

impl PodStatus {
    /// Some of its containers run.
    pub fn is_running(self) -> bool {
        matches!(self, Self::Running | Self::Degraded)
    }
}

/// A container of a pod.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "proxy", derive(zlink::introspect::CustomType))]
#[serde(default)]
pub struct PodMember {
    pub id: String,
    pub name: String,
    pub state: RunState,
    /// The times its restart policy restarted it
    pub restart_count: i64,
    /// An init container (`--init-ctr`): it runs to its end at the start of
    /// the pod, and does not count in its status
    pub init: bool,
}

/// A pod.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "proxy", derive(zlink::introspect::CustomType))]
#[serde(default)]
pub struct PodRecord {
    pub id: String,
    pub name: String,
    pub created_ns: i64,
    pub status: PodStatus,
    pub infra_id: String,
    /// Its containers, the infra container first
    pub members: Vec<PodMember>,
    /// The networks it is on (the default one when its spec names none)
    pub networks: Vec<String>,
    /// It is in the network namespace of the host
    pub host_network: bool,
    /// Of the infra container, which `PodInspect` reads (`PodList` leaves
    /// it empty): its addresses
    pub ips: Vec<String>,
    /// Of the infra container, which `PodInspect` reads (`PodList` leaves
    /// it false): it is in the IPC namespace of the host
    pub host_ipc: bool,
    /// Of the infra container, which `PodInspect` reads (`PodList` leaves
    /// it false): it is in the PID namespace of the host
    pub host_pid: bool,
    /// Of the infra container, which `PodInspect` reads (`PodList` leaves
    /// it empty): its process
    pub infra_pid: i64,
    /// Of the infra container, which `PodInspect` reads (`PodList` leaves
    /// it empty): the OCI runtime it runs with
    pub oci_runtime: String,
    /// Of the infra container, which `PodInspect` reads (`PodList` leaves
    /// it empty): the path of its network namespace (when it has one of its
    /// own)
    pub netns_path: String,
    /// The cgroup of the pod, relative to the cgroup file system, as
    /// `PodInspect` reads it (`PodList` leaves it empty; empty without one)
    pub cgroup_path: String,
    /// What it was made with
    pub spec: crate::pod::PodSpec,
    /// The devices of its spec, as the nodes of the host are
    pub devices: Vec<DeviceNode>,
}

/// A device of the host given to a container (podman's `LinuxDevice`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "proxy", derive(zlink::introspect::CustomType))]
#[serde(default)]
pub struct DeviceNode {
    /// Its path in the container
    pub path: String,
    /// `c` or `b`; empty when the host has no such node
    pub kind: String,
    pub major: u64,
    pub minor: u64,
    pub file_mode: u64,
}

/// A device of the host in a container.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "proxy", derive(zlink::introspect::CustomType))]
#[serde(default, deny_unknown_fields)]
pub struct DeviceSpec {
    pub host_path: String,
    pub container_path: String,
    pub permissions: String,
}

/// The limits of a container; 0 or empty is no limit.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "proxy", derive(zlink::introspect::CustomType))]
#[serde(default, deny_unknown_fields)]
pub struct Resources {
    /// Bytes
    pub memory_limit: i64,
    /// Memory and swap together, in bytes
    pub memory_swap: i64,
    /// Microseconds
    pub cpu_period: i64,
    /// Microseconds of CPU time per `cpu_period`
    pub cpu_quota: i64,
    pub cpu_shares: i64,
    pub cpuset_cpus: String,
    pub cpuset_mems: String,
    pub oom_score_adj: i64,
    /// cgroup v2 files and their values
    pub unified: BTreeMap<String, String>,
    pub hugepage_limits: Vec<HugepageLimit>,
}

/// The most bytes of huge pages of a size (`2MB`, `1GB`) a container may
/// use.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "proxy", derive(zlink::introspect::CustomType))]
#[serde(default)]
pub struct HugepageLimit {
    pub page_size: String,
    pub limit: u64,
}

/// Where a container is in its life (podman's states).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "proxy", derive(zlink::introspect::CustomType))]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "proxy", zlink(rename_all = "snake_case"))]
pub enum RunState {
    /// Made, never started
    #[default]
    Created,
    /// Made in the OCI runtime (`init`), not started
    Initialized,
    Running,
    Paused,
    /// Running, its stop under way
    Stopping,
    /// Ran and ended (or failed to start: `started_ns` is then 0)
    Exited,
    Unknown,
}

impl RunState {
    /// The word podman's JSON and the filters of its API use.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Created => "created",
            Self::Initialized => "initialized",
            Self::Running => "running",
            Self::Paused => "paused",
            Self::Stopping => "stopping",
            Self::Exited => "exited",
            Self::Unknown => "unknown",
        }
    }
}

impl std::fmt::Display for RunState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What a mount of a container is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "proxy", derive(zlink::introspect::CustomType))]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "proxy", zlink(rename_all = "snake_case"))]
pub enum MountKind {
    /// A directory or a file of the host
    #[default]
    Bind,
    /// A volume, or a directory of one
    Volume,
    Tmpfs,
    /// An image (or a directory of it)
    Image,
}

/// A mount a container was made with (not the files the engine binds at
/// start, `/etc/hosts`...).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "proxy", derive(zlink::introspect::CustomType))]
#[cfg_attr(feature = "proxy", zlink(rename = "MountSpec"))]
#[serde(default)]
pub struct ContainerMount {
    pub kind: MountKind,
    /// Of a volume: its name
    pub name: String,
    /// The create named the volume (not a path)
    pub named: bool,
    /// A path of the host; the ID of the image mounted; empty for a tmpfs
    pub source: String,
    /// Where in the container, as the create wrote it
    pub destination: String,
    /// Of an image: the directory of it mounted
    pub sub_path: String,
    pub options: Vec<String>,
    pub read_only: bool,
    /// Of a bind mount: the propagation (`rprivate` unless asked)
    pub propagation: String,
}

/// `ContainerHealthcheck` answers: the health of the container after the
/// check, its result last in the log.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "proxy", derive(zlink::introspect::Type))]
pub struct HealthChecked {
    pub health: Health,
}

/// What CRIU reports of a dump or a restore (`stats-dump`,
/// `stats-restore`), under podman's names: the times are microseconds,
/// the counts are pages; a value that is zero is not written (podman's
/// `omitempty`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "proxy", derive(zlink::introspect::CustomType))]
#[serde(default)]
pub struct CriuStatistics {
    /// Time to freeze the processes
    #[serde(skip_serializing_if = "is_zero")]
    pub freezing_time: u32,
    /// Time the processes did not run
    #[serde(skip_serializing_if = "is_zero")]
    pub frozen_time: u32,
    /// Time to extract the memory pages
    #[serde(skip_serializing_if = "is_zero")]
    pub memdump_time: u32,
    /// Time to write the memory pages
    #[serde(skip_serializing_if = "is_zero")]
    pub memwrite_time: u32,
    #[serde(skip_serializing_if = "is_zero")]
    pub pages_scanned: u64,
    #[serde(skip_serializing_if = "is_zero")]
    pub pages_written: u64,
    /// Restore: pages compared
    #[serde(skip_serializing_if = "is_zero")]
    pub pages_compared: u64,
    /// Restore: copy-on-write pages skipped
    #[serde(skip_serializing_if = "is_zero")]
    pub pages_skipped_cow: u64,
    /// Restore: time to fork the processes
    #[serde(skip_serializing_if = "is_zero")]
    pub forking_time: u32,
    /// Restore: time to restore
    #[serde(skip_serializing_if = "is_zero")]
    pub restore_time: u32,
    /// Restore: pages restored
    #[serde(skip_serializing_if = "is_zero")]
    pub pages_restored: u64,
}

fn is_zero<T: Default + PartialEq>(v: &T) -> bool {
    *v == T::default()
}

/// podman's report of a checkpoint (what `--print-stats` lists).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct CheckpointReport {
    #[serde(rename = "Id")]
    pub id: String,
    pub runtime_checkpoint_duration: i64,
    pub criu_statistics: Option<CriuStatistics>,
}

/// podman's report of a restore.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct RestoreReport {
    #[serde(rename = "Id")]
    pub id: String,
    pub runtime_restore_duration: i64,
    pub criu_statistics: Option<CriuStatistics>,
}

/// The checkpoint of a container and its last restore.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "proxy", derive(zlink::introspect::CustomType))]
#[serde(default)]
pub struct CheckpointState {
    /// Its images are there, to restore
    pub checkpointed: bool,
    pub checkpointed_ns: i64,
    /// The directory of the images
    pub path: String,
    /// The log of the dump, in the directory of the images
    pub log_path: String,
    pub restored: bool,
    pub restored_ns: i64,
}

/// The user a process runs as: its ids and its supplementary groups.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "proxy", derive(zlink::introspect::CustomType))]
#[serde(default)]
pub struct ProcessUser {
    pub uid: i64,
    pub gid: i64,
    pub additional_gids: Vec<i64>,
}

/// What a container runs, and how.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "proxy", derive(zlink::introspect::CustomType))]
#[serde(default)]
pub struct ProcessConfig {
    pub entrypoint: Vec<String>,
    pub command: Vec<String>,
    /// `KEY=VALUE`, in order
    pub env: Vec<String>,
    pub work_dir: String,
    pub user: String,
    /// The user the process runs as, from the specification the container
    /// was made with (none: it has not got one yet)
    pub resolved_user: Option<ProcessUser>,
    pub hostname: String,
    pub domainname: String,
    /// What a stop sends first (the container's, its image's; empty:
    /// SIGTERM)
    pub stop_signal: String,
    /// The same, by number
    pub stop_signal_number: i64,
    /// Seconds a stop waits before the kill
    pub stop_timeout: i64,
    /// Octal
    pub umask: String,
    /// systemd mode
    pub systemd: bool,
    /// An init process runs the command
    pub init: bool,
    /// Its health check, with where its results go and how many are kept
    pub healthcheck: Option<Healthcheck>,
    /// The command line that made it (none: the API made it)
    pub create_command: Vec<String>,
    /// An entry of its user is added to its /etc/passwd when it lacks one
    pub passwd: bool,
    /// How it tells systemd it is ready (`container`, `conmon`, `ignore`,
    /// `healthy`)
    pub sdnotify_mode: String,
}

/// A limit of a resource of the processes of a container.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "proxy", derive(zlink::introspect::CustomType))]
#[serde(default)]
pub struct Ulimit {
    /// As given (`nofile`, `RLIMIT_NOFILE`)
    pub name: String,
    pub soft: i64,
    pub hard: i64,
}

/// The namespaces, cgroup, log, policies and security of a container.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "proxy", derive(zlink::introspect::CustomType))]
#[serde(default)]
pub struct HostSettings {
    /// The mode of the cgroup namespace (`private`, `host`, `container:ID`...)
    pub cgroupns_mode: String,
    /// The mode of the IPC namespace (`private`, `host`, `container:ID`...)
    pub ipc_mode: String,
    /// The mode of the PID namespace (`private`, `host`, `container:ID`...)
    pub pid_mode: String,
    /// The mode of the UTS namespace (`private`, `host`, `container:ID`...)
    pub uts_mode: String,
    /// Empty: the user namespace of the engine
    pub userns_mode: String,
    /// `systemd` or `cgroupfs`
    pub cgroup_manager: String,
    /// The parent asked for (empty: the default)
    pub cgroup_parent: String,
    /// `--cgroups`: `enabled` (or empty), `disabled`, `no-conmon`, `split`
    pub cgroups: String,
    /// `k8s-file`, `journald`, `none`...
    pub log_driver: String,
    pub log_options: BTreeMap<String, String>,
    /// The size a log file is rotated at (`max-size`; 0: none)
    pub log_max_size: i64,
    /// Empty: none
    pub restart_policy: String,
    pub restart_retries: i64,
    pub auto_remove: bool,
    /// With `auto_remove`: its image is removed too, unless another
    /// container uses it
    pub auto_remove_image: bool,
    pub cap_add: Vec<String>,
    pub cap_drop: Vec<String>,
    pub group_add: Vec<String>,
    pub no_new_privileges: bool,
    /// Empty: the default profile
    pub seccomp_profile: String,
    pub apparmor_profile: String,
    pub read_only_rootfs: bool,
    /// Bytes of /dev/shm
    pub shm_size: i64,
    /// The OCI runtime asked for (empty: the default)
    pub runtime: String,
    pub ulimits: Vec<Ulimit>,
    /// 0: no limit
    pub pids_limit: i64,
    pub blkio_weight: i64,
    pub memory_reservation: i64,
    /// The OOM killer leaves it alone
    pub oom_kill_disable: bool,
    /// The file its /etc/hosts is made of (empty: the engine's)
    pub hosts_file: String,
    /// The devices of the host it has
    pub devices: Vec<DeviceSpec>,
    /// The read rate limits (bytes per second) of the block devices, by their
    /// paths
    pub blkio_device_read_bps: Vec<DeviceLimit>,
    /// The write rate limits (bytes per second) of the block devices, by their
    /// paths
    pub blkio_device_write_bps: Vec<DeviceLimit>,
    /// The read rate limits (operations per second) of the block devices, by
    /// their paths
    pub blkio_device_read_iops: Vec<DeviceLimit>,
    /// The write rate limits (operations per second) of the block devices, by
    /// their paths
    pub blkio_device_write_iops: Vec<DeviceLimit>,
    /// The weights of the block devices, by their paths
    pub blkio_weight_device: Vec<DeviceLimit>,
    /// What the OCI configuration of the container gives its process (an
    /// inspect fills them, a list does not): the SELinux label of the
    /// process and of its files (empty: not confined), the AppArmor
    /// profile, the effective and the bounding capabilities (`CAP_CHOWN`)
    pub process_label: String,
    pub mount_label: String,
    pub process_apparmor: String,
    pub effective_caps: Vec<String>,
    pub bounding_caps: Vec<String>,
}

/// A limit (a rate, a weight) of a block device of a container.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "proxy", derive(zlink::introspect::CustomType))]
#[serde(default)]
pub struct DeviceLimit {
    pub path: String,
    pub value: u64,
}

/// A port of a container on the host.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "proxy", derive(zlink::introspect::CustomType))]
#[serde(default)]
pub struct ContainerPort {
    pub container_port: i64,
    /// 0: any free one
    pub host_port: i64,
    /// Empty: every address
    pub host_ip: String,
    /// `tcp`, `udp` or `sctp`
    pub protocol: String,
    /// The ports from these on (1: one)
    pub range: i64,
}

/// An interface of a container on a network.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "proxy", derive(zlink::introspect::CustomType))]
#[serde(default)]
pub struct ContainerInterface {
    pub network: String,
    pub network_id: String,
    pub ip: String,
    pub prefix_len: i64,
    pub ip6: String,
    pub prefix6_len: i64,
    /// Empty when it is no route of the container (an internal network)
    pub gateway: String,
    pub gateway6: String,
    pub mac: String,
    pub aliases: Vec<String>,
}

/// The network of a container.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "proxy", derive(zlink::introspect::CustomType))]
#[serde(default)]
pub struct ContainerNetwork {
    /// `bridge` (the default network), `host`, `none`, `pasta`,
    /// `container:ID`, `ns:PATH`, or the name of the first network
    pub mode: String,
    /// The networks it is on
    pub networks: Vec<String>,
    /// Its interfaces on them, once it runs
    pub interfaces: Vec<ContainerInterface>,
    /// The ports published, as asked
    pub ports: Vec<ContainerPort>,
    /// The ports bound, the free host ports picked (none: not known)
    pub bound_ports: Vec<ContainerPort>,
    /// The ports exposed (`80/tcp`)
    pub exposed: Vec<String>,
    pub publish_all: bool,
    /// The address asked for
    pub mac_address: String,
    /// Its network namespace, while it runs in one of its own
    pub sandbox_key: String,
    pub dns: Vec<String>,
    pub dns_search: Vec<String>,
    pub dns_options: Vec<String>,
    /// `NAME:IP`
    pub extra_hosts: Vec<String>,
}

/// The files of a container on the host.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
#[cfg_attr(feature = "proxy", derive(zlink::introspect::CustomType))]
pub struct ContainerPaths {
    /// The directory of its OCI bundle
    pub bundle: String,
    pub oci_config: String,
    pub resolv_conf: String,
    pub hostname: String,
    /// Empty: no /etc/hosts is made
    pub hosts: String,
    /// The pid file of its monitor
    pub monitor_pid_file: String,
    /// The pid file of its process
    pub pid_file: String,
    /// The file of its log, for a driver that writes one
    pub log: String,
    /// The graph driver as podman and Docker report it (`overlay` for
    /// composefs)
    pub graph_driver: String,
    /// What the driver says of the root file system (`GraphDriver.Data`)
    pub graph_data: BTreeMap<String, String>,
}

/// A container: what `ContainerInspect` and `ContainerList` answer.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "proxy", derive(zlink::introspect::CustomType))]
#[serde(default)]
pub struct ContainerRecord {
    pub id: String,
    pub name: String,
    pub pid: i64,
    pub pod_id: String,
    pub pod_name: String,
    /// The image as podman names it (with its tag), else its ID
    pub image: String,
    pub image_id: String,
    /// The digest of the manifest of its image
    pub image_digest: String,
    /// The image the create named
    pub image_ref: String,
    pub labels: BTreeMap<String, String>,
    pub annotations: BTreeMap<String, String>,
    pub created_ns: i64,
    pub started_ns: i64,
    pub finished_ns: i64,
    pub state: RunState,
    pub exit_code: i32,
    pub oom_killed: bool,
    /// Killed at the end of its time limit (`--timeout`)
    pub timed_out: bool,
    /// Stopped by a user (stop, kill): its restart policy does not start it
    pub stopped_by_user: bool,
    pub restart_count: i64,
    pub should_start_on_boot: bool,
    pub error: String,
    pub is_infra: bool,
    /// Of its monitor, while it runs
    pub monitor_pid: i64,
    pub health: Option<Health>,
    pub checkpoint: CheckpointState,
    pub tty: bool,
    pub stdin: bool,
    pub privileged: bool,
    /// The name of its OCI runtime
    pub oci_runtime: String,
    pub process: ProcessConfig,
    pub host: HostSettings,
    pub resources: Resources,
    pub network: ContainerNetwork,
    pub mounts: Vec<ContainerMount>,
    pub paths: ContainerPaths,
    /// The cgroup of its process while it runs (`/proc/PID/cgroup`)
    pub cgroup_path: String,
    /// Bytes of its changes (when asked)
    pub size_rw: Option<i64>,
    /// Bytes of its changes and its image (when asked)
    pub size_root_fs: Option<i64>,
    /// The namespaces of its process (`Cgroup`, `Ipc`, `Mnt`, `Net`,
    /// `Pidns`, `Uts`, `User`), when asked
    pub namespaces: BTreeMap<String, String>,
}

/// A sample of what a container uses.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "proxy", derive(zlink::introspect::CustomType))]
#[serde(default)]
pub struct StatsRecord {
    pub id: String,
    pub name: String,
    /// It runs: a container that does not has only zeros
    pub running: bool,
    /// When the sample was read
    pub time_ns: i64,
    /// When the container started (0: it does not run)
    pub started_ns: i64,
    /// The CPU time of the container
    pub cpu_nano: u64,
    /// The user part of the CPU time of the container
    pub cpu_user_nano: u64,
    /// The system part of the CPU time of the container
    pub cpu_system_nano: u64,
    /// The CPU use in % (100 a CPU) since the sample before in the call,
    /// since its start for the first
    pub cpu_percent: f64,
    /// The CPU time of the host (all its CPUs) when the sample was read
    pub host_cpu_nano: u64,
    pub online_cpus: u64,
    /// The periods of the CPU quota that elapsed
    pub cpu_periods: u64,
    /// The periods of the CPU quota that were throttled
    pub cpu_throttled_periods: u64,
    /// The time throttled
    pub cpu_throttled_nano: u64,
    pub mem_usage: u64,
    /// Usage less the page cache that is reclaimed at once
    pub mem_working_set: u64,
    pub mem_anon: u64,
    /// The page cache
    pub mem_file: u64,
    pub mem_swap: u64,
    /// Its limit, the memory of the host when it has none
    pub mem_limit: u64,
    pub page_faults: u64,
    pub major_page_faults: u64,
    /// Bytes of the files the container wrote (asked for with `size`)
    pub rw_bytes: Option<u64>,
    /// Inodes of the files the container wrote (asked for with `size`)
    pub rw_inodes: Option<u64>,
    /// Bytes read from block devices
    pub block_read: u64,
    /// Bytes written to block devices
    pub block_write: u64,
    /// The interfaces of its network namespace but the loopback
    pub networks: Vec<InterfaceStats>,
    pub pids: u64,
    /// `memory.swap.max`, 0 for no limit
    pub swap_limit: u64,
    /// The pressure stall information of its cgroup
    pub pressure: crate::pod::Pressure,
}

/// The counters of a network interface of a container.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "proxy", derive(zlink::introspect::CustomType))]
#[serde(default)]
pub struct InterfaceStats {
    pub name: String,
    pub rx_bytes: u64,
    pub rx_packets: u64,
    pub rx_errors: u64,
    pub rx_dropped: u64,
    pub tx_bytes: u64,
    pub tx_packets: u64,
    pub tx_errors: u64,
    pub tx_dropped: u64,
}

/// The configuration an image gives its containers (the `config` of its
/// OCI configuration).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "proxy", derive(zlink::introspect::CustomType))]
pub struct ImageConfigRecord {
    pub user: String,
    /// `PORT/PROTOCOL`
    pub exposed_ports: Vec<String>,
    /// `NAME=VALUE`
    pub env: Vec<String>,
    pub entrypoint: Vec<String>,
    pub cmd: Vec<String>,
    /// The paths of its volumes
    pub volumes: Vec<String>,
    pub working_dir: String,
    pub labels: BTreeMap<String, String>,
    pub stop_signal: String,
    pub args_escaped: bool,
    /// The instructions a build on the image runs (Docker's)
    pub on_build: Vec<String>,
    /// The shell of the instructions of a build (Docker's)
    pub shell: Vec<String>,
    /// Docker's health check of the image
    pub healthcheck: Option<ImageHealthcheck>,
}

/// The health check an image gives its containers (Docker's).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "proxy", derive(zlink::introspect::CustomType))]
pub struct ImageHealthcheck {
    /// `CMD-SHELL cmd`, `CMD arg...` or `NONE`
    pub test: Vec<String>,
    /// 0: not set
    pub interval_ns: i64,
    pub timeout_ns: i64,
    pub start_period_ns: i64,
    pub start_interval_ns: i64,
    pub retries: i64,
}

/// A step of the history of an image (of its configuration), and in the
/// replies of `ImageHistory` what that step made.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "proxy", derive(zlink::introspect::CustomType))]
pub struct ImageHistoryEntry {
    /// 0: the configuration says no time
    pub created_ns: i64,
    pub created_by: String,
    pub author: String,
    pub comment: String,
    /// The step made no layer
    pub empty_layer: bool,
    /// `ImageHistory`: the id of the image for its last step, else empty
    pub id: String,
    /// `ImageHistory`: the size of the layer the step made
    pub size: u64,
    /// `ImageHistory`: the names of the image, on its last step
    pub tags: Vec<String>,
}

/// The fs-verity digests a manifest states for the EROFS image of a layer.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "proxy", derive(zlink::introspect::CustomType))]
pub struct ComposefsLayer {
    /// The digest of the layer in the manifest
    pub layer: String,
    /// `sha256:<hex>` or `sha512:<hex>`, as the annotation lists them
    pub digests: Vec<String>,
}

/// An image, or (in `ImageList` with `manifest_lists`) a manifest list.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "proxy", derive(zlink::introspect::CustomType))]
pub struct ImageRecord {
    /// The digest of its configuration, without its algorithm (64 hex
    /// digits for a sha256, 128 for a sha512; of a manifest list: its id)
    pub id: String,
    /// `registry/repository:tag`, the newest first
    pub names: Vec<String>,
    /// `registry/repository@digest`: the names a pull by digest gave it,
    /// the newest first (podman's names with a digest)
    pub digest_names: Vec<String>,
    /// Every name it had, the last one given first
    pub names_history: Vec<String>,
    /// `registry/repository@digest` of its names
    pub digests: Vec<String>,
    /// The digest of its manifest
    pub digest: String,
    /// The bytes of its manifest, configuration and uncompressed layers
    pub size: u64,
    /// The time its configuration says it was made at (0: none)
    pub created_ns: i64,
    /// When it came into the store
    pub stored_ns: i64,
    /// `ImageList`: the id of the image a build made it on (empty: none)
    pub parent_id: String,
    /// `ImageList`: a build made other images on it
    pub has_children: bool,
    /// `ImageList`: how many containers use it
    pub containers: u64,
    /// Of an additional, read-only image store
    pub read_only: bool,
    pub manifest_list: bool,
    /// `ImageList`: a pull in progress (`ImagePulls`), whose files are
    /// fetched as they are read; listed for the filter `lazy` alone
    pub lazy: bool,
    pub os: String,
    pub architecture: String,
    pub variant: String,
    pub author: String,
    /// The comment of its configuration, else of the first step of its
    /// history
    pub comment: String,
    /// The labels of its configuration
    pub labels: BTreeMap<String, String>,
    /// The annotations of its manifest
    pub annotations: BTreeMap<String, String>,
    /// The media type of its manifest
    pub manifest_type: String,
    /// The size of its manifest in bytes
    pub manifest_size: u64,
    pub config: ImageConfigRecord,
    pub history: Vec<ImageHistoryEntry>,
    /// The digests of its uncompressed layers (`rootfs.diff_ids`), the
    /// lowest first
    pub layers: Vec<String>,
    /// `ImageInspect`: the layers whose descriptors state the digest of
    /// their EROFS image, the lowest first
    pub composefs: Vec<ComposefsLayer>,
    /// The graph driver as podman and Docker report it (`overlay` for
    /// composefs)
    pub graph_driver: String,
}

/// The command `ExecCreate` runs in a container.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "proxy", derive(zlink::introspect::CustomType))]
#[serde(default, deny_unknown_fields)]
pub struct ExecSpec {
    /// The program and its arguments
    pub command: Vec<String>,
    /// Added to the environment of the container
    pub env: BTreeMap<String, String>,
    /// Empty: the container's
    pub work_dir: String,
    /// Empty: the container's
    pub user: String,
    pub tty: bool,
    pub stdin: bool,
    pub stdout: bool,
    pub stderr: bool,
    pub privileged: bool,
    /// The keys that detach a client with a terminal from the command
    /// (`ctrl-p,ctrl-q`); empty: those
    pub detach_keys: String,
    /// Kill the command after this many milliseconds; none: never
    pub timeout_ms: Option<i64>,
    /// The reason a command could not be run is not written to its output
    /// but kept in the `error` of the record (the command line reports it
    /// as its own error, with status 125)
    pub errors_apart: bool,
}

/// An exec session.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
#[cfg_attr(feature = "proxy", derive(zlink::introspect::CustomType))]
pub struct ExecRecord {
    pub id: String,
    pub container_id: String,
    pub running: bool,
    /// Once the command ended
    pub exit_code: Option<i64>,
    /// 0 before it started
    pub pid: i64,
    /// What it was made with (the environment and the timeout are not
    /// told again)
    pub command: Vec<String>,
    pub user: String,
    pub tty: bool,
    pub stdin: bool,
    pub stdout: bool,
    pub stderr: bool,
    pub privileged: bool,
    pub detach_keys: String,
    /// Why the command could not be run or followed to its end, for a
    /// session made with `errors_apart`
    pub error: Option<String>,
}

/// A metric (cAdvisor's names): its name, help text, whether it only grows,
/// and the names of its labels.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "proxy", derive(zlink::introspect::CustomType))]
pub struct MetricDescriptor {
    pub name: String,
    pub help: String,
    pub counter: bool,
    pub labels: Vec<String>,
}

/// A value of a metric.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "proxy", derive(zlink::introspect::CustomType))]
pub struct MetricSample {
    pub name: String,
    /// The values of the labels of the descriptor, in its order
    pub labels: Vec<String>,
    pub value: f64,
}

/// The metrics of a container of a pod.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "proxy", derive(zlink::introspect::CustomType))]
pub struct ContainerMetrics {
    pub id: String,
    pub name: String,
    pub samples: Vec<MetricSample>,
}

/// The metrics of a pod that runs.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "proxy", derive(zlink::introspect::CustomType))]
pub struct PodMetrics {
    pub id: String,
    pub name: String,
    /// When the samples were read
    pub time_ns: i64,
    /// Of the pod: the network of its namespace
    pub samples: Vec<MetricSample>,
    pub containers: Vec<ContainerMetrics>,
    /// Of the cgroup of the pod, when it has one of its own (a pod with
    /// limits)
    pub usage: Option<crate::pod::PodUsage>,
}

/// `ContainerInspect` answers.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "proxy", derive(zlink::introspect::Type))]
pub struct ContainerInspected {
    pub container: ContainerRecord,
}

/// A reply of `ContainerList`: a container, none in the one reply of an
/// empty list.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "proxy", derive(zlink::introspect::Type))]
pub struct ContainerListed {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub container: Option<ContainerRecord>,
}

/// `PodInspect` answers.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "proxy", derive(zlink::introspect::Type))]
pub struct PodInspected {
    pub pod: PodRecord,
}

/// A reply of `PodList` (as [`ContainerListed`]).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "proxy", derive(zlink::introspect::Type))]
pub struct PodListed {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pod: Option<PodRecord>,
}

/// `ImageInspect` answers.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "proxy", derive(zlink::introspect::Type))]
pub struct ImageInspected {
    pub image: ImageRecord,
}

/// A reply of `ImageList` (as [`ContainerListed`]).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "proxy", derive(zlink::introspect::Type))]
pub struct ImageListed {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image: Option<ImageRecord>,
}

/// `ImageRemove` answers: the names untagged, the ids removed and podman's
/// warnings of the stops of its containers that needed the kill.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "proxy", derive(zlink::introspect::Type))]
pub struct ImageRemoved {
    pub untagged: Vec<String>,
    pub deleted: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

/// `ImageRemoveMany` answers, libpod's report.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "proxy", derive(zlink::introspect::Type))]
pub struct ImagesRemoved {
    pub deleted: Vec<String>,
    pub untagged: Vec<String>,
    pub exit_code: i32,
    pub errors: Vec<String>,
    /// podman's warnings of the stops of their containers that needed the
    /// kill
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

/// An image (or a manifest list) a prune removed.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "proxy", derive(zlink::introspect::CustomType))]
#[serde(default)]
pub struct PrunedImage {
    pub id: String,
    /// The bytes its removal freed: its record and the layers no other image,
    /// no container and no pull holds, each once, sized as `system df` sizes
    /// them (0: a manifest list).  podman reports the size of the whole image.
    pub size: u64,
}

/// A reply of `ImagePrune` (as [`ContainerListed`]).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "proxy", derive(zlink::introspect::Type))]
pub struct ImagePruneListed {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image: Option<PrunedImage>,
}

/// A layer of an image in `ImageTree`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "proxy", derive(zlink::introspect::CustomType))]
#[serde(default)]
pub struct ImageTreeLayer {
    /// Its digest uncompressed (else of its blob)
    pub id: String,
    pub size: u64,
    /// The names of the images it is the top layer of
    pub top_of: Vec<String>,
}

/// An image built on the one of `ImageTree`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "proxy", derive(zlink::introspect::CustomType))]
#[serde(default)]
pub struct ImageTreeChild {
    pub id: String,
    pub names: Vec<String>,
}

/// The layers of an image and the images built on it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "proxy", derive(zlink::introspect::CustomType))]
#[serde(default)]
pub struct ImageTreeRecord {
    pub id: String,
    pub names: Vec<String>,
    pub size: u64,
    /// The lowest first
    pub layers: Vec<ImageTreeLayer>,
    pub children: Vec<ImageTreeChild>,
}

/// `ImageTree` answers.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "proxy", derive(zlink::introspect::Type))]
pub struct ImageTreeInspected {
    pub tree: ImageTreeRecord,
}

/// An image a pull put in the store, with the names it was given.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "proxy", derive(zlink::introspect::CustomType))]
#[serde(default)]
pub struct PulledImage {
    pub id: String,
    pub names: Vec<String>,
}

/// Where credentials go: `registry/repository` (or `registry`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "proxy", derive(zlink::introspect::Type))]
pub struct Scopes {
    pub scopes: Vec<String>,
}

/// What one source of a transfer moved: `name` is a fetcher or pusher of
/// the walk as configured, or `store` for what was there already.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "proxy", derive(zlink::introspect::CustomType))]
#[serde(default)]
pub struct BySource {
    pub name: String,
    pub bytes: u64,
    pub files: u64,
}

impl BySource {
    /// The bytes and files the entries of `name` of `list` moved.
    pub fn sum_of(list: &[BySource], name: &str) -> (u64, u64) {
        list.iter()
            .filter(|s| s.name == name)
            .fold((0, 0), |(b, f), s| (b + s.bytes, f + s.files))
    }

    /// Count `bytes` and `files` in the entry of `name` of `list` (made when
    /// there is none and something moved).
    pub fn add_to(list: &mut Vec<BySource>, name: &str, bytes: u64, files: u64) {
        if bytes == 0 && files == 0 {
            return;
        }
        match list.iter_mut().find(|s| s.name == name) {
            Some(s) => {
                s.bytes = s.bytes.saturating_add(bytes);
                s.files += files;
            }
            None => list.push(BySource {
                name: name.to_string(),
                bytes,
                files,
            }),
        }
    }
}

/// What a transfer (a pull, a completion) moved, and from where.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "proxy", derive(zlink::introspect::CustomType))]
#[serde(default)]
pub struct TransferStats {
    /// By source, in the order they were first seen
    pub by_source: Vec<BySource>,
    /// The layers that were in the store already
    pub layers_cached: u64,
    pub duration_ms: u64,
}

/// The source of what a pull took from the registry fetcher.
pub const SOURCE_REGISTRY: &str = "registry";
/// The source of what a pull found in the store already.
pub const SOURCE_STORE: &str = "store";

impl TransferStats {
    /// Count `bytes` and `files` as moved by the source `name`.
    pub fn add(&mut self, name: &str, bytes: u64, files: u64) {
        BySource::add_to(&mut self.by_source, name, bytes, files);
    }

    /// The bytes and files the source `name` moved (none: nothing).
    pub fn from(&self, name: &str) -> (u64, u64) {
        BySource::sum_of(&self.by_source, name)
    }
}

/// Where a pull in progress is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "proxy", derive(zlink::introspect::CustomType))]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "proxy", zlink(rename_all = "snake_case"))]
pub enum PullState {
    Queued,
    Running,
    WaitingForSpace,
    NeedsCredentials,
    Failed,
    Cancelled,
    /// It should run and no process completes it
    Stalled,
}

impl PullState {
    /// The word `image pulls` shows.
    pub fn word(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Running => "running",
            Self::WaitingForSpace => "waiting-for-space",
            Self::NeedsCredentials => "needs-credentials",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
            Self::Stalled => "stalled",
        }
    }
}

/// A pull in progress (`ImagePulls`): an image whose layers are not all in
/// the store yet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "proxy", derive(zlink::introspect::Type))]
pub struct PullListed {
    /// The image id
    pub id: String,
    /// `repository:tag` and `repository@digest`
    pub names: Vec<String>,
    pub state: PullState,
    /// Why it failed, or the last error that was retried (empty: none)
    pub error: String,
    /// Whole percent of the bytes fetched
    pub percent: u64,
    pub bytes_done: u64,
    pub bytes_total: u64,
    pub layers_done: u64,
    pub layers_total: u64,
    /// The containers made on it
    pub containers: u64,
    /// RFC 3339
    pub started_at: String,
}

/// `ImagePulls` answers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "proxy", derive(zlink::introspect::Type))]
pub struct PullsListed {
    pub pulls: Vec<PullListed>,
}

/// `ImagePulling` answers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "proxy", derive(zlink::introspect::Type))]
pub struct PullingAnswer {
    pub pulling: bool,
}

/// `ImageComplete` answers.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "proxy", derive(zlink::introspect::Type))]
pub struct ImageCompleted {
    pub stats: TransferStats,
}

/// `RegistryDigest` answers.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "proxy", derive(zlink::introspect::Type))]
pub struct RegistryDigested {
    pub digest: String,
}

/// A reply of `ContainerCommit`: the progress of the layer (with more), or
/// in the last reply the id of the image.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "proxy", derive(zlink::introspect::Type))]
pub struct Committed {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub progress: Option<TransferProgress>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
}

/// A reply of `ImageHistory` (as [`ContainerListed`]).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "proxy", derive(zlink::introspect::Type))]
pub struct ImageHistoryListed {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entry: Option<ImageHistoryEntry>,
}

/// A reply of `ContainerStats`: a record, none at the end of a sample.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "proxy", derive(zlink::introspect::Type))]
pub struct StatsListed {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stats: Option<StatsRecord>,
}

/// `ExecInspect` answers.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "proxy", derive(zlink::introspect::Type))]
pub struct ExecInspected {
    pub exec: ExecRecord,
}

/// A reply of `MetricDescriptorList` (as [`ContainerListed`]).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "proxy", derive(zlink::introspect::Type))]
pub struct MetricDescriptorListed {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub descriptor: Option<MetricDescriptor>,
}

/// A reply of `PodMetricsList` (as [`ContainerListed`]).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "proxy", derive(zlink::introspect::Type))]
pub struct PodMetricsListed {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pod: Option<PodMetrics>,
}

/// How far a pull is: of a layer (its digest), or of the image with none.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "proxy", derive(zlink::introspect::CustomType))]
#[serde(default)]
pub struct TransferProgress {
    pub layer: String,
    pub status: TransferStatus,
    /// The text of a `phase` or a `warning`
    pub message: String,
    pub current_bytes: u64,
    pub total_bytes: u64,
    pub complete: bool,
}

/// What a pull does now.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "proxy", derive(zlink::introspect::CustomType))]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "proxy", zlink(rename_all = "snake_case"))]
pub enum TransferStatus {
    /// The layer is being fetched
    #[default]
    Downloading,
    /// The layer is in the store already
    Exists,
    /// The layer (or, without one, the image) is in the store
    Complete,
    /// What the pull does now for the image as a whole (`message`)
    Phase,
    /// What the person who pulls should know (`message`)
    Warning,
}

/// A reply of `ImagePull`: the progress (with more), or in the last reply
/// what was pulled.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "proxy", derive(zlink::introspect::Type))]
pub struct Pulled {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub progress: Option<TransferProgress>,
    /// The id of the image asked for
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// The images pulled (every tag of `all_tags`, every image of an
    /// archive), the last the one asked for
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub images: Option<Vec<PulledImage>>,
    /// What the (last) pull fetched, and from where
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stats: Option<TransferStats>,
    /// The image of the store was the answer (the policy): nothing was
    /// pulled
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub present: Option<bool>,
}

/// A tag `ImagePush` pushed with `all_tags`, and the digest of its
/// manifest.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "proxy", derive(zlink::introspect::CustomType))]
#[serde(default)]
pub struct PushedTag {
    pub tag: String,
    pub digest: String,
}

/// The private key of a push that signs, and the passphrase of it, as the
/// client read them from its files: the JSON of the sealed memory file
/// `PushSpec.signing` names (never in a message).
#[derive(Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct SigningKey {
    /// The PEM of the private key
    pub key: String,
    /// Its passphrase (empty: none)
    pub passphrase: String,
}

impl std::fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SigningKey(<redacted>)")
    }
}

impl Drop for SigningKey {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.key);
        zeroize::Zeroize::zeroize(&mut self.passphrase);
    }
}

/// What a push pushed.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "proxy", derive(zlink::introspect::CustomType))]
#[serde(default)]
pub struct PushedImage {
    /// The digest of the manifest pushed (none with `all_tags`)
    pub digest: String,
    /// The size of the manifest
    pub size: u64,
    /// The blobs sent
    pub blobs_uploaded: u64,
    /// The blobs mounted from another repository
    pub blobs_mounted: u64,
    /// The blobs already there
    pub blobs_existing: u64,
    /// How the destination resolves the manifest by each name and by its
    /// digest
    pub placed: Vec<crate::transfer::Placed>,
    /// With `all_tags`, every tag pushed
    pub tags: Vec<PushedTag>,
}

/// A reply of `ImagePush`: where the push goes (the first reply), the
/// progress of its blobs, and in the last reply what was pushed.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "proxy", derive(zlink::introspect::Type))]
pub struct Pushed {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub destination: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub progress: Option<TransferProgress>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pushed: Option<PushedImage>,
}

/// Something that happened to an object of the engine.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "proxy", derive(zlink::introspect::CustomType))]
#[serde(default)]
pub struct Event {
    pub time_ns: i64,
    /// What it is about
    pub kind: EventKind,
    /// What happened (`create`, `start`, `died`, `remove`, `pull`...)
    pub action: String,
    pub id: String,
    pub name: String,
    /// The image of a container
    pub image: String,
    /// The labels of a container and what the action tells (`exitCode`...)
    pub attributes: BTreeMap<String, String>,
}

/// The kind of object an event is about.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "proxy", derive(zlink::introspect::CustomType))]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "proxy", zlink(rename_all = "snake_case"))]
pub enum EventKind {
    Container,
    Pod,
    Image,
    Volume,
    Network,
    Secret,
    Artifact,
    Machine,
    /// The engine
    #[default]
    System,
}

impl EventKind {
    /// Every kind.
    pub const ALL: [EventKind; 9] = [
        Self::Container,
        Self::Pod,
        Self::Image,
        Self::Volume,
        Self::Network,
        Self::Secret,
        Self::Artifact,
        Self::Machine,
        Self::System,
    ];

    /// Its word (podman's `Type` of an event).
    pub fn word(self) -> &'static str {
        match self {
            Self::Container => "container",
            Self::Pod => "pod",
            Self::Image => "image",
            Self::Volume => "volume",
            Self::Network => "network",
            Self::Secret => "secret",
            Self::Artifact => "artifact",
            Self::Machine => "machine",
            Self::System => "system",
        }
    }

    /// The kind of a word of [`EventKind::word`].
    pub fn of_word(word: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|k| k.word() == word)
    }
}

/// A reply of `Events`: an event, none in the last reply of events that end.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "proxy", derive(zlink::introspect::Type))]
pub struct EventListed {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event: Option<Event>,
}

/// A line of the logs of a pod.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "proxy", derive(zlink::introspect::CustomType))]
#[serde(default)]
pub struct PodLogLine {
    /// The name of the container the line came from
    pub container_name: String,
    /// The id of the container the line came from
    pub container_id: String,
    /// Its place among the containers of the pod (the infra container is
    /// the first)
    pub container_index: i64,
    /// How many containers' logs the answer has
    pub containers: i64,
    pub time_ns: i64,
    pub stream: LogStream,
    pub message: String,
}

/// The stream a line of a log was written to.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "proxy", derive(zlink::introspect::CustomType))]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "proxy", zlink(rename_all = "snake_case"))]
pub enum LogStream {
    #[default]
    Stdout,
    Stderr,
}

/// A reply of `PodLogs`: a line, none in the reply that says the engine
/// took a follow and in the last reply.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "proxy", derive(zlink::introspect::Type))]
pub struct PodLogListed {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub line: Option<PodLogLine>,
}

/// A descriptor of OCI's: a blob or a manifest.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "proxy", derive(zlink::introspect::CustomType))]
pub struct ManifestDescriptor {
    pub media_type: String,
    pub digest: String,
    pub size: u64,
    /// Empty: none
    pub artifact_type: String,
    pub annotations: BTreeMap<String, String>,
    /// The content of a small blob, base64 (empty: none)
    pub data: String,
}

/// An instance of a manifest list.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "proxy", derive(zlink::introspect::CustomType))]
pub struct ManifestInstance {
    pub media_type: String,
    pub digest: String,
    pub size: u64,
    pub artifact_type: String,
    pub annotations: BTreeMap<String, String>,
    pub platform: Option<ImagePlatform>,
}

/// A manifest list (OCI's index) of the store or of a registry.  What a
/// registry serves for a name can be an image manifest: its `config` and
/// `layers`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "proxy", derive(zlink::introspect::Type))]
pub struct ManifestListRecord {
    /// The id of a list of the store; empty: one of a registry
    pub id: String,
    pub schema_version: i64,
    pub media_type: String,
    pub artifact_type: String,
    pub subject: Option<ManifestDescriptor>,
    pub annotations: BTreeMap<String, String>,
    pub manifests: Vec<ManifestInstance>,
    pub config: Option<ManifestDescriptor>,
    pub layers: Vec<ManifestDescriptor>,
}

/// An artifact of the store: its manifest.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "proxy", derive(zlink::introspect::CustomType))]
pub struct ArtifactRecord {
    pub name: String,
    /// The digest of its manifest
    pub digest: String,
    pub schema_version: i64,
    pub media_type: String,
    pub artifact_type: String,
    pub config: Option<ManifestDescriptor>,
    pub layers: Vec<ManifestDescriptor>,
    pub subject: Option<ManifestDescriptor>,
    pub annotations: BTreeMap<String, String>,
}

/// What `ArtifactInspect` answers.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "proxy", derive(zlink::introspect::Type))]
pub struct ArtifactInspected {
    pub artifact: ArtifactRecord,
}

/// A reply of `ArtifactList` (as [`ContainerListed`]).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "proxy", derive(zlink::introspect::Type))]
pub struct ArtifactListed {
    pub artifact: Option<ArtifactRecord>,
}

/// What `ManifestRemove` removed.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "proxy", derive(zlink::introspect::Type))]
pub struct ManifestRemoved {
    pub id: String,
    /// The names it had
    pub names: Vec<String>,
}

/// A platform of an image of a registry.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "proxy", derive(zlink::introspect::CustomType))]
pub struct ImagePlatform {
    pub architecture: String,
    pub os: String,
    pub os_version: String,
    pub os_features: Vec<String>,
    pub variant: String,
    pub features: Vec<String>,
}

/// What `ImageRemoteInspect` answers: the manifest or index a registry has
/// for a name, and the platforms of its instances.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "proxy", derive(zlink::introspect::Type))]
pub struct RemoteImage {
    pub media_type: String,
    pub digest: String,
    pub size: u64,
    pub platforms: Vec<ImagePlatform>,
}

/// What `VolumeCreate` makes.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "proxy", derive(zlink::introspect::CustomType))]
#[serde(default, deny_unknown_fields)]
pub struct VolumeSpec {
    /// Empty: a name of the engine's
    pub name: String,
    /// Empty or `local`: the only driver
    pub driver: String,
    pub labels: BTreeMap<String, String>,
    /// The options of the driver (`type`, `device`, `o`, `copy`, `uid`,
    /// `gid`...)
    pub options: BTreeMap<String, String>,
}

/// A volume.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "proxy", derive(zlink::introspect::CustomType))]
pub struct VolumeRecord {
    pub name: String,
    pub driver: String,
    /// Where its content is on the host
    pub mountpoint: String,
    pub created_ns: i64,
    pub labels: BTreeMap<String, String>,
    pub options: BTreeMap<String, String>,
    pub scope: String,
    /// The user id of the owner it was created with
    pub uid: i64,
    /// The group id of the owner it was created with
    pub gid: i64,
    /// Made for a container (`-v /path`, the `VOLUME` of an image)
    pub anonymous: bool,
    /// The content of the image is copied in at its first use
    pub needs_copy_up: bool,
    /// Its owner becomes the user of its first container
    pub needs_chown: bool,
}

/// `VolumeCreate` and `VolumeInspect` answer.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "proxy", derive(zlink::introspect::Type))]
pub struct VolumeInspected {
    pub volume: VolumeRecord,
}

/// A reply of `VolumeList` (as [`ContainerListed`]).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "proxy", derive(zlink::introspect::Type))]
pub struct VolumeListed {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub volume: Option<VolumeRecord>,
}

/// The first and the last address of a range of leases.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "proxy", derive(zlink::introspect::CustomType))]
pub struct LeaseRange {
    pub start: String,
    pub end: String,
}

/// What `NetworkCreate` makes, from either API or the command line.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "proxy", derive(zlink::introspect::CustomType))]
pub struct NetworkSpec {
    pub name: String,
    /// Empty: `bridge`
    pub driver: String,
    pub subnet: Option<String>,
    pub gateway: Option<String>,
    pub subnet6: Option<String>,
    pub gateway6: Option<String>,
    /// IPv6, with a subnet picked when none is given
    pub ipv6: bool,
    pub lease: Option<LeaseRange>,
    pub dns_enabled: bool,
    pub dns_servers: Vec<String>,
    pub labels: BTreeMap<String, String>,
    pub internal: bool,
    /// The bridge (its name of the engine's when absent)
    pub interface: Option<String>,
    /// The IP address management driver: absent or `host-local`, the
    /// only one
    pub ipam_driver: Option<String>,
    /// The options of the driver (`mtu`, `parent`, `mode`)
    pub options: BTreeMap<String, String>,
    /// Static routes added in the containers of the network
    pub routes: Vec<NetworkRoute>,
}

/// A static route of a network.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "proxy", derive(zlink::introspect::CustomType))]
#[serde(default)]
pub struct NetworkRoute {
    /// CIDR
    pub destination: String,
    pub gateway: String,
    pub metric: Option<u32>,
}

/// The driver of a network.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "proxy", derive(zlink::introspect::CustomType))]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "proxy", zlink(rename_all = "snake_case"))]
pub enum NetworkDriver {
    /// A bridge of the engine's, with NAT to the host's networks
    #[default]
    Bridge,
    /// The network of the host
    Host,
    /// Only a loopback
    None,
    /// Made by a network provider
    Overlay,
    /// The LAN of a parent interface
    Macvlan,
}

impl NetworkDriver {
    /// podman's word.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Bridge => "bridge",
            Self::Host => "host",
            Self::None => "none",
            Self::Overlay => "overlay",
            Self::Macvlan => "macvlan",
        }
    }
}

/// A subnet of a network.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "proxy", derive(zlink::introspect::CustomType))]
#[serde(default)]
pub struct NetworkSubnet {
    /// CIDR
    pub subnet: String,
    /// Empty: none
    pub gateway: String,
    /// The addresses the containers are given, all of the subnet if absent
    pub lease_range: Option<LeaseRange>,
}

/// A container on a network.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "proxy", derive(zlink::introspect::CustomType))]
pub struct NetworkMember {
    pub id: String,
    pub name: String,
    pub running: bool,
    /// The MAC address of its interface on the network, empty when it has
    /// none (it does not run, or the driver keeps no interface)
    pub mac_address: String,
    /// Its IPv4 address, `ADDRESS/PREFIX`, empty when it has none
    pub ipv4: String,
    /// Its IPv6 address, the same way
    pub ipv6: String,
}

/// A network.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "proxy", derive(zlink::introspect::CustomType))]
#[serde(default)]
pub struct NetworkRecord {
    pub name: String,
    pub id: String,
    pub driver: NetworkDriver,
    /// The bridge, or the parent of a macvlan network; empty for the
    /// other drivers
    pub interface: String,
    pub created_ns: i64,
    /// One IPv4 and one IPv6 at most
    pub subnets: Vec<NetworkSubnet>,
    pub ipv6_enabled: bool,
    pub internal: bool,
    pub dns_enabled: bool,
    /// The servers of the names that are not containers
    pub dns_servers: Vec<String>,
    pub labels: BTreeMap<String, String>,
    /// The options of the driver
    pub options: BTreeMap<String, String>,
    /// The options of the IP address management (`driver`)
    pub ipam_options: BTreeMap<String, String>,
    /// The static routes of the containers
    pub routes: Vec<NetworkRoute>,
    /// The network of the configuration, which is not removed (Docker
    /// names it `bridge`)
    pub builtin: bool,
    /// The containers on it
    pub containers: Vec<NetworkMember>,
}

/// `NetworkCreate` answers: the network, and whether it was made (false:
/// it was there, with `ignore_if_exists`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "proxy", derive(zlink::introspect::Type))]
pub struct NetworkCreated {
    pub changed: bool,
    pub network: NetworkRecord,
}

/// `NetworkInspect` answers.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "proxy", derive(zlink::introspect::Type))]
pub struct NetworkInspected {
    pub network: NetworkRecord,
}

/// A reply of `NetworkList` (as [`ContainerListed`]).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "proxy", derive(zlink::introspect::Type))]
pub struct NetworkListed {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<NetworkRecord>,
}

/// A secret.  Its data is no field of the definition: `SecretInspect`
/// with `show_data` carries it in a pipe, never in the JSON of a message.
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "proxy", derive(zlink::introspect::CustomType))]
#[serde(default)]
pub struct SecretRecord {
    pub id: String,
    pub name: String,
    pub driver: String,
    pub driver_options: BTreeMap<String, String>,
    pub labels: BTreeMap<String, String>,
    pub created_ns: i64,
    pub updated_ns: i64,
    #[serde(skip)]
    #[cfg_attr(feature = "proxy", zlink(skip))]
    pub data: Option<Vec<u8>>,
}

impl std::fmt::Debug for SecretRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretRecord")
            .field("id", &self.id)
            .field("name", &self.name)
            .field("driver", &self.driver)
            .field("driver_options", &self.driver_options)
            .field("labels", &self.labels)
            .field("created_ns", &self.created_ns)
            .field("updated_ns", &self.updated_ns)
            .field("data", &self.data.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

/// `SecretInspect` answers: the secret, and with `show_data` its data as
/// the sealed memory file the reply carries (descriptor `data`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "proxy", derive(zlink::introspect::Type))]
pub struct SecretInspected {
    pub secret: SecretRecord,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<u32>,
}

/// A reply of `SecretList` (as [`ContainerListed`]).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "proxy", derive(zlink::introspect::Type))]
pub struct SecretListed {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret: Option<SecretRecord>,
}

/// What a prune removed (or, for a dry run, would remove): the names.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "proxy", derive(zlink::introspect::Type))]
pub struct Pruned {
    pub removed: Vec<String>,
}

/// What `VolumePrune` removed (or, for a dry run, would remove).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "proxy", derive(zlink::introspect::Type))]
pub struct VolumesPruned {
    pub removed: Vec<crate::system::PrunedVolume>,
}

/// What `BuildPrune` removed.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "proxy", derive(zlink::introspect::Type))]
pub struct BuildPruned {
    /// The ids of the images of the cache that went
    pub ids: Vec<String>,
    /// The bytes freed
    pub space: u64,
}

/// What a prune freed, in bytes.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "proxy", derive(zlink::introspect::Type))]
pub struct Reclaimed {
    pub space: u64,
}

// The replies a frontend lays out as podman's documents: decoded through
// `Members`, not by a derived visitor (see `crate::members`).
deserialize_members! {
    ExecRecord {
        id, container_id, running, exit_code, pid, command, user, tty, stdin, stdout, stderr,
        privileged, detach_keys, error,
    }
    ImagePlatform { architecture, os, os_version, os_features, variant, features }
    RemoteImage { media_type, digest, size, platforms }
    ImageHealthcheck {
        test, interval_ns, timeout_ns, start_period_ns, start_interval_ns, retries,
    }
    ImageHistoryEntry {
        created_ns, created_by, author, comment, empty_layer, id, size, tags,
    }
    ComposefsLayer { layer, digests }
    ImageConfigRecord {
        user, exposed_ports, env, entrypoint, cmd, volumes, working_dir, labels, stop_signal,
        args_escaped, on_build, shell, healthcheck,
    }
    ImageRecord {
        id, names, digest_names, names_history, digests, digest, size, created_ns, stored_ns,
        parent_id, has_children, containers, read_only, manifest_list, lazy, os, architecture,
        variant, author, comment, labels, annotations, manifest_type, manifest_size, config, history,
        layers, composefs, graph_driver,
    }
    VolumeRecord {
        name, driver, mountpoint, created_ns, labels, options, scope, uid, gid, anonymous,
        needs_copy_up, needs_chown,
    }
    ContainerPaths {
        bundle, oci_config, resolv_conf, hostname, hosts, monitor_pid_file, pid_file, log,
        graph_driver, graph_data,
    }
    NetworkMember { id, name, running, mac_address, ipv4, ipv6 }
    ManifestDescriptor { media_type, digest, size, artifact_type, annotations, data }
    ManifestInstance { media_type, digest, size, artifact_type, annotations, platform }
    ManifestListRecord {
        id, schema_version, media_type, artifact_type, subject, annotations, manifests, config,
        layers,
    }
    ArtifactRecord {
        name, digest, schema_version, media_type, artifact_type, config, layers, subject,
        annotations,
    }
    ArtifactListed { artifact }
    BuildPruned { ids, space }
}

// The replies that are no document of podman's: a member that is missing is
// an error.
deserialize_request_members! {
    ArtifactInspected { artifact }
    ManifestRemoved { id, names }
}
