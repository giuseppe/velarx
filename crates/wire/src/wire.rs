// SPDX-License-Identifier: Apache-2.0
//! What the client and the engine share of the services: the requests
//! they exchange and their limits.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// The largest secret.
pub const SECRET_MAX_SIZE: usize = 512_000;

/// The platform and annotations of the instances a change adds or edits.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct InstanceOptions {
    pub annotations: BTreeMap<String, String>,
    pub arch: Option<String>,
    pub os: Option<String>,
    pub os_version: Option<String>,
    pub variant: Option<String>,
    pub features: Vec<String>,
    pub os_features: Vec<String>,
}

/// A request of `velarx manifest` to the native API: what each command
/// takes (the others are left empty).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct ManifestRequest {
    pub images: Vec<String>,
    /// Every instance of a list given as an image (create, add), every
    /// instance pushed (push).
    pub all: bool,
    /// create: an existing list is taken.
    pub amend: bool,
    pub instance: InstanceOptions,
    pub index_annotations: BTreeMap<String, String>,
    /// annotate: the subject of the index.
    pub subject: Option<String>,
    /// push: where to (the name of the list if none).
    pub destination: Option<String>,
    pub compression_format: Option<String>,
    /// push: the level of the layers compressed in `compression_format`.
    pub compression_level: Option<i32>,
    /// push: each instance in these compressions too.
    pub add_compression: Vec<String>,
    /// push: the manifest type, oci (the only one).
    pub format: Option<String>,
    /// push: sign the list and its instances with this key.
    pub sign: Option<velarx_proto::workload::SigningKey>,
    /// push: the pushers, in the order they are asked (`--sinks`); none:
    /// `[push] sinks`.
    pub sinks: Option<Vec<String>>,
    /// remove: the instance.
    pub digest: Option<String>,
    /// create: `sha256` or `sha512`, the algorithm of the digest of the list
    /// (none: `[build] digest`).
    pub algorithm: Option<String>,
    pub tls_verify: bool,
    pub access: velarx_registry::auth::RegistryAccess,
}

impl Default for ManifestRequest {
    fn default() -> Self {
        Self {
            images: Vec::new(),
            all: false,
            amend: false,
            instance: InstanceOptions::default(),
            index_annotations: BTreeMap::new(),
            subject: None,
            destination: None,
            compression_format: None,
            compression_level: None,
            add_compression: Vec::new(),
            format: None,
            sign: None,
            sinks: None,
            digest: None,
            algorithm: None,
            tls_verify: true,
            access: Default::default(),
        }
    }
}

/// What `checkpoint` takes (podman's `container checkpoint`).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CheckpointOptions {
    /// The container goes on after the checkpoint
    #[serde(default)]
    pub leave_running: bool,
    /// Established TCP connections are checkpointed
    #[serde(default)]
    pub tcp_established: bool,
    /// File locks are checkpointed
    #[serde(default)]
    pub file_locks: bool,
    /// Make an image of this name of the checkpoint (podman's checkpoint
    /// image: the archive is the one file of its layer)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub create_image: Option<String>,
    /// Write the checkpoint to this archive (an absolute path, written by
    /// the engine), podman's layout
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub export: Option<std::path::PathBuf>,
    /// The compression of the archive: zstd (the default), gzip or none
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compress: Option<String>,
    /// Leave the changes of the root file system out of the archive
    #[serde(default)]
    pub ignore_rootfs: bool,
    /// The container has volumes, which are not in the archive
    #[serde(default)]
    pub ignore_volumes: bool,
    /// Keep the images of CRIU after the export
    #[serde(default)]
    pub keep: bool,
    /// Read the statistics CRIU writes
    #[serde(default)]
    pub print_stats: bool,
    /// Dump the memory only, into `pre-checkpoint`: the container goes on
    #[serde(default)]
    pub pre_checkpoint: bool,
    /// Checkpoint on top of the images of `pre-checkpoint`
    #[serde(default)]
    pub with_previous: bool,
}

/// What `restore` takes (podman's `container restore`).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RestoreOptions {
    #[serde(default)]
    pub tcp_established: bool,
    /// Restore with the established TCP connections closed
    #[serde(default)]
    pub tcp_close: bool,
    #[serde(default)]
    pub file_locks: bool,
    /// Keep the checkpoint after the restore (else it is removed)
    #[serde(default)]
    pub keep: bool,
    /// The archive of a pre-checkpoint (`checkpoint --pre-checkpoint
    /// --export`) the archive of `import` builds on
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub import_previous: Option<std::path::PathBuf>,
    /// Make a new container from this archive (`checkpoint --export`, an
    /// absolute path read by the engine) and restore it
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub import: Option<std::path::PathBuf>,
    /// The name of the container made from the archive
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Leave the changes of the root file system of the archive out
    #[serde(default)]
    pub ignore_rootfs: bool,
    /// The container is made without the static addresses of the archive
    #[serde(default)]
    pub ignore_static_ip: bool,
    #[serde(default)]
    pub ignore_static_mac: bool,
    /// The pod the container an import makes joins
    #[serde(default)]
    pub pod: Option<String>,
    /// The ports (`-p` specifications) the container an import makes
    /// publishes, instead of those of the archive
    #[serde(default)]
    pub publish: Vec<String>,
    /// Read the statistics CRIU writes
    #[serde(default)]
    pub print_stats: bool,
    /// The digests (`sha256:...` or `sha512:...`) typed on the command that restores, which
    /// the restore holds the images of the container to as `start
    /// --verify-image` does
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub verify_image: Vec<String>,
}

/// What is known of the checkpoint of a container.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct CheckpointRecord {
    /// The images are there, to restore
    #[serde(default)]
    pub checkpointed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checkpointed_at: Option<String>,
    #[serde(default)]
    pub restored: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub restored_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<std::path::PathBuf>,
    /// The container (made by an import)
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub id: String,
    /// The images are those of an archive staged in a container that was
    /// never started: its start restores them
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub restore_on_start: bool,
    /// What the call that made this record measured (not kept): the
    /// microseconds the runtime took and, with `print_stats`, CRIU's
    /// statistics
    #[serde(skip)]
    pub runtime_duration: i64,
    #[serde(skip)]
    pub criu_statistics: Option<velarx_proto::workload::CriuStatistics>,
}

use velarx_proto::workload::{CheckpointReport, RestoreReport};

impl From<&CheckpointRecord> for CheckpointReport {
    fn from(r: &CheckpointRecord) -> Self {
        Self {
            id: r.id.clone(),
            runtime_checkpoint_duration: r.runtime_duration,
            criu_statistics: r.criu_statistics.clone(),
        }
    }
}

impl From<&CheckpointRecord> for RestoreReport {
    fn from(r: &CheckpointRecord) -> Self {
        Self {
            id: r.id.clone(),
            runtime_restore_duration: r.runtime_duration,
            criu_statistics: r.criu_statistics.clone(),
        }
    }
}

/// Log stream type
/// Container statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerStats {
    /// Container name
    pub name: Option<String>,
    /// Container ID
    pub id: String,

    /// CPU usage percentage (0-100 * num_cpus)
    pub cpu_percent: f64,
    /// Total CPU usage in nanoseconds
    pub cpu_usage_ns: u64,
    /// User CPU time in nanoseconds
    pub cpu_user_ns: u64,
    /// System CPU time in nanoseconds
    pub cpu_system_ns: u64,
    /// Enforcement periods of the quota that elapsed, and those throttled
    #[serde(default)]
    pub cpu_periods: u64,
    pub cpu_throttled_periods: u64,
    /// Total throttled time in nanoseconds
    pub cpu_throttled_ns: u64,

    /// Current memory usage in bytes
    pub memory_usage: u64,
    /// Memory limit in bytes (None if unlimited)
    pub memory_limit: Option<u64>,
    /// Memory usage percentage (0-100)
    pub memory_percent: f64,
    /// Anonymous memory in bytes
    pub memory_anon: u64,
    /// File-backed memory (page cache) in bytes
    pub memory_file: u64,
    /// Swap usage in bytes
    pub memory_swap: u64,
    /// `memory.swap.max` (None if unlimited)
    #[serde(default)]
    pub memory_swap_limit: Option<u64>,
    /// Usage without the page cache that can be reclaimed at once
    /// (`memory.current` less `inactive_file`), what an eviction compares
    #[serde(default)]
    pub memory_working_set: u64,
    #[serde(default)]
    pub page_faults: u64,
    #[serde(default)]
    pub major_page_faults: u64,

    /// Bytes read from block devices
    pub io_read_bytes: u64,
    /// Bytes written to block devices
    pub io_write_bytes: u64,

    /// Number of processes/threads
    pub pids: u32,
    /// PIDs limit (None if unlimited)
    pub pids_limit: Option<u32>,
    /// The counters of the network interfaces of the container but the
    /// loopback, by name (none when it has no network namespace of its own
    /// or is not running)
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub networks: std::collections::BTreeMap<String, NetworkCounters>,
    #[serde(default)]
    pub pressure: velarx_proto::pod::Pressure,
}

/// The counters of one network interface, as `/proc/PID/net/dev` has them.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkCounters {
    pub rx_bytes: u64,
    pub rx_packets: u64,
    pub rx_errors: u64,
    pub rx_dropped: u64,
    pub tx_bytes: u64,
    pub tx_packets: u64,
    pub tx_errors: u64,
    pub tx_dropped: u64,
}

impl NetworkCounters {
    /// The interfaces of the text of `/proc/PID/net/dev` but the loopback.
    /// A line that does not have the 16 counters is left out, and told.
    pub fn parse_net_dev(text: &str) -> std::collections::BTreeMap<String, Self> {
        let mut out = std::collections::BTreeMap::new();
        // two header lines, then "  name: rx(8 fields) tx(8 fields)"
        for line in text.lines().skip(2) {
            let Some((name, counters)) = line.split_once(':') else {
                continue;
            };
            let name = name.trim();
            if name == "lo" {
                continue;
            }
            let v = counters
                .split_whitespace()
                .map(str::parse)
                .collect::<Result<Vec<u64>, _>>();
            let v = match v {
                Ok(v) if v.len() >= 16 => v,
                _ => {
                    tracing::debug!("Left out the counters of {name}: {:?}", counters.trim());
                    continue;
                }
            };
            out.insert(
                name.to_string(),
                Self {
                    rx_bytes: v[0],
                    rx_packets: v[1],
                    rx_errors: v[2],
                    rx_dropped: v[3],
                    tx_bytes: v[8],
                    tx_packets: v[9],
                    tx_errors: v[10],
                    tx_dropped: v[11],
                },
            );
        }
        out
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TopResult {
    pub titles: Vec<String>,
    pub processes: Vec<Vec<String>>,
}

/// Where the log of a container is.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogLocation {
    pub driver: LogDriver,
    /// The log file, for the `k8s-file` driver
    pub path: std::path::PathBuf,
    /// The directory of the allowlist the file is below
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_dir: Option<std::path::PathBuf>,
}

/// Where the output of a container goes.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum LogDriver {
    /// The CRI format, in a file.
    #[default]
    K8sFile,
    /// The systemd journal.
    Journald,
    /// Discard the output.
    None,
    /// The container writes to the standard streams of the monitor.
    Passthrough,
    /// syslog, on /dev/log.
    Syslog,
}

impl LogDriver {
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "k8s-file" | "json-file" => Self::K8sFile,
            "journald" => Self::Journald,
            "none" => Self::None,
            "passthrough" => Self::Passthrough,
            "syslog" => Self::Syslog,
            _ => return None,
        })
    }

    /// A list of drivers, `k8s-file,syslog`: the container logs to all of
    /// them; the first is the one `logs` reads.  Each comes once; none and
    /// passthrough come alone.
    pub fn parse_list(s: &str) -> Result<Vec<Self>, String> {
        let mut out = Vec::new();
        for name in s.split(',').map(str::trim) {
            let d = Self::parse(name).ok_or_else(|| {
                format!(
                    "unknown log driver `{name}` (k8s-file, journald, syslog, none, passthrough)"
                )
            })?;
            if out.contains(&d) {
                return Err(format!("the log driver `{name}` comes twice"));
            }
            out.push(d);
        }
        if out.len() > 1
            && out
                .iter()
                .any(|d| matches!(d, Self::None | Self::Passthrough))
        {
            return Err("the log drivers none and passthrough go alone".into());
        }
        Ok(out)
    }
}

/// Log entry from a pod container
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PodLogEntry {
    /// Name of the container this log came from
    pub container_name: String,
    /// Its ID
    #[serde(default)]
    pub container_id: String,
    /// Its place among the containers of the pod (the infra container is
    /// the first), which gives it its color
    #[serde(default)]
    pub container_index: usize,
    /// How many containers' logs there are in this answer
    #[serde(default)]
    pub containers: usize,
    /// Timestamp of the log entry
    pub timestamp: String,
    /// Stream (stdout or stderr)
    pub stream: String,
    /// Log message content
    pub message: String,
}

pub use velarx_proto::workload::{
    ContainerMetrics, MetricDescriptor as Descriptor, MetricSample as Sample, PodMetrics,
};
