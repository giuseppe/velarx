// SPDX-License-Identifier: Apache-2.0
//! The specification of a pod, as the engine keeps it and as a frontend asks
//! for it: a type of the interface definition.  The frontends decode the
//! request of their protocol (podman's PodSpecGenerator, the CRI's sandbox
//! config, the options of `pod create`) into it; `PodCreate` carries it as
//! JSON in the pipe of the call.  The types are the engine's own
//! (`velarx_core::services` re-exports them), so the document in the
//! database and the one on the wire are the same.

pub use crate::modes::{CgroupMode, CgroupsMode, UsernsChoice};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Restart policy
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "proxy", derive(zlink::introspect::CustomType))]
pub struct RestartPolicy {
    /// Policy name: no, on-failure, always, unless-stopped
    pub name: String,
    /// Maximum retry count for on-failure
    #[serde(default)]
    pub maximum_retry_count: u32,
}

/// A range of IDs of a user namespace: `size` IDs from `container_id`
/// are those from `host_id` on the host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "proxy", derive(zlink::introspect::CustomType))]
pub struct IdMapping {
    pub container_id: u32,
    pub host_id: u32,
    pub size: u32,
}

impl std::fmt::Display for IdMapping {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}:{}", self.container_id, self.host_id, self.size)
    }
}

/// Pod DNS configuration
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "proxy", derive(zlink::introspect::CustomType))]
pub struct PodDnsConfig {
    pub servers: Vec<String>,
    pub searches: Vec<String>,
    pub options: Vec<String>,
}

/// Pod security context: of its infra container
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "proxy", derive(zlink::introspect::CustomType))]
pub struct PodSecurityContext {
    /// Run all containers as this user
    pub run_as_user: Option<u32>,
    /// Run all containers as this group
    pub run_as_group: Option<u32>,
    /// Supplemental groups for all containers
    pub supplemental_groups: Vec<u32>,
}

/// What `PodRun` does to the containers of a pod.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "proxy", derive(zlink::introspect::CustomType))]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "proxy", zlink(rename_all = "snake_case"))]
pub enum PodAction {
    Start,
    Stop,
    Kill,
    Pause,
    Unpause,
    Restart,
}

impl PodAction {
    /// Every action.
    pub const ALL: [PodAction; 6] = [
        Self::Start,
        Self::Stop,
        Self::Kill,
        Self::Pause,
        Self::Unpause,
        Self::Restart,
    ];

    /// Its word (the path of podman's route).
    pub fn word(self) -> &'static str {
        match self {
            Self::Start => "start",
            Self::Stop => "stop",
            Self::Kill => "kill",
            Self::Pause => "pause",
            Self::Unpause => "unpause",
            Self::Restart => "restart",
        }
    }

    /// The action of a word.
    pub fn of_word(word: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|a| a.word() == word)
    }
}

/// What a pod does when all its containers exited.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "proxy", derive(zlink::introspect::CustomType))]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "proxy", zlink(rename_all = "snake_case"))]
pub enum PodExitPolicy {
    /// It stays, its infra container runs
    #[default]
    Continue,
    /// It stops
    Stop,
}

impl PodExitPolicy {
    /// podman's word.
    pub fn word(self) -> &'static str {
        match self {
            Self::Continue => "continue",
            Self::Stop => "stop",
        }
    }
}

/// Port mapping for pod
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "proxy", derive(zlink::introspect::CustomType))]
pub struct PodPortMapping {
    pub container_port: u16,
    pub host_port: Option<u16>,
    pub host_ip: Option<String>,
    pub protocol: String,
}

/// What the cgroup of a pod has used: the numbers of the pod itself, with
/// its infra container and whatever its members leave, not the sum of the
/// members.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "proxy", derive(zlink::introspect::CustomType))]
#[serde(default)]
pub struct PodUsage {
    /// `cpu.stat` usage, in nanoseconds
    pub cpu_usage_ns: u64,
    /// `memory.current`, in bytes
    pub memory_usage: u64,
    /// `memory.current` without the page cache that is at once reclaimable
    pub memory_working_set: u64,
    /// Anonymous memory (`anon` of `memory.stat`), in bytes
    pub memory_rss: u64,
    /// `memory.max`, 0 for no limit
    pub memory_limit: u64,
    /// `memory.swap.current`
    pub swap_usage: u64,
    /// `memory.swap.max` (0 for no limit)
    pub swap_limit: u64,
    pub pressure: Pressure,
}

/// A line of a pressure file of a cgroup (`cpu.pressure`...): the share of
/// the time (percent) in which tasks waited for the resource, averaged over
/// 10, 60 and 300 seconds, and the whole time they waited, in microseconds.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "proxy", derive(zlink::introspect::CustomType))]
#[serde(default)]
pub struct PsiData {
    pub total_us: u64,
    pub avg10: f64,
    pub avg60: f64,
    pub avg300: f64,
}

/// The pressure of a resource: `some` while at least one task waited,
/// `full` while all of them did.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "proxy", derive(zlink::introspect::CustomType))]
#[serde(default)]
pub struct Psi {
    pub some: PsiData,
    pub full: PsiData,
}

impl Psi {
    /// The text of a pressure file; None when it has no `some` line.
    pub fn parse(text: &str) -> Option<Self> {
        let mut out = Self::default();
        let mut some = false;
        for line in text.lines() {
            let mut words = line.split_whitespace();
            let data = match words.next() {
                Some("some") => {
                    some = true;
                    &mut out.some
                }
                Some("full") => &mut out.full,
                _ => continue,
            };
            for w in words {
                let Some((k, v)) = w.split_once('=') else {
                    continue;
                };
                match k {
                    "avg10" => data.avg10 = v.parse().unwrap_or(0.0),
                    "avg60" => data.avg60 = v.parse().unwrap_or(0.0),
                    "avg300" => data.avg300 = v.parse().unwrap_or(0.0),
                    "total" => data.total_us = v.parse().unwrap_or(0),
                    _ => {}
                }
            }
        }
        some.then_some(out)
    }
}

/// The pressure stall information of a cgroup, of each resource whose file
/// it has (a kernel without PSI has none).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "proxy", derive(zlink::introspect::CustomType))]
#[serde(default)]
pub struct Pressure {
    pub cpu: Option<Psi>,
    pub memory: Option<Psi>,
    pub io: Option<Psi>,
}

impl Pressure {
    /// The pressure files of the cgroup directory `dir`.
    pub fn read(dir: &std::path::Path) -> Self {
        let psi = |name: &str| {
            std::fs::read_to_string(dir.join(name))
                .ok()
                .and_then(|t| Psi::parse(&t))
        };
        Self {
            cpu: psi("cpu.pressure"),
            memory: psi("memory.pressure"),
            io: psi("io.pressure"),
        }
    }
}

/// The limits of the cgroup of a pod, the parent of the cgroups of all its
/// containers (the infra container included): what bounds their sum.  A
/// field that is not set is no limit (an update replaces the limits whole).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "proxy", derive(zlink::introspect::CustomType))]
#[serde(default)]
pub struct PodResources {
    /// `memory.max`, in bytes
    pub memory: Option<i64>,
    /// Memory and swap together (the OCI `memory.swap`), in bytes
    pub memory_swap: Option<i64>,
    /// CPU shares (`cpu.weight` is made of them)
    pub cpu_shares: Option<u64>,
    /// `cpu.max`: microseconds of CPU time per `cpu_period`
    pub cpu_quota: Option<i64>,
    /// The length of the period of the quota in microseconds
    pub cpu_period: Option<u64>,
    /// `cpuset.cpus`
    pub cpuset_cpus: Option<String>,
    /// `cpuset.mems`
    pub cpuset_mems: Option<String>,
    /// The block IO weight, 10 to 1000 (`--blkio-weight`; 0 is none)
    pub blkio_weight: Option<u16>,
    /// `--blkio-weight-device`: the weight of each device
    pub blkio_weight_device: Vec<PodDeviceLimit>,
    /// `--device-read-bps`: bytes per second
    pub device_read_bps: Vec<PodDeviceLimit>,
    /// `--device-write-bps`: bytes per second
    pub device_write_bps: Vec<PodDeviceLimit>,
}

/// A limit of a block device of the pod's cgroup: the device is the one of
/// the OCI `major` and `minor` (the command line gives a path, which the
/// CLI looks up).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "proxy", derive(zlink::introspect::CustomType))]
#[serde(default)]
pub struct PodDeviceLimit {
    pub major: u32,
    pub minor: u32,
    /// The weight, or the rate in bytes per second
    pub value: u64,
    /// The path of the device as the pod was given it (else the engine names
    /// it from the kernel's name); only what `pod inspect` shows
    pub path: String,
}

impl PodResources {
    /// Whether no limit is set.
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }

    /// The limits of podman's `resource_limits` (OCI `LinuxResources`) and
    /// the pod's own `cpu_period` and `cpu_quota`: the memory limit and
    /// swap, the CPU shares, quota, period and cpusets.  What a pod cannot
    /// limit (pids, block IO, huge pages, the rest) is an error when it is
    /// set, not dropped.
    pub fn from_podman(
        limits: Option<&serde_json::Value>,
        cpu_period: Option<u64>,
        cpu_quota: Option<i64>,
    ) -> Result<Option<Self>, String> {
        use serde_json::Value;
        fn set(v: &Value) -> bool {
            match v {
                Value::Null => false,
                Value::Bool(b) => *b,
                Value::Number(n) => n.as_f64().is_some_and(|n| n != 0.0),
                Value::String(s) => !s.is_empty(),
                Value::Array(a) => a.iter().any(set),
                Value::Object(o) => o.values().any(set),
            }
        }
        // [{"major": 7, "minor": 0, <key>: 5}]
        fn devices(v: &Value, key: &str, what: &str) -> Result<Vec<PodDeviceLimit>, String> {
            let bad = || format!("`{what}` is not a list of {{major, minor, {key}}}");
            let num = |e: &Value, k: &str| e.get(k).and_then(Value::as_u64).ok_or_else(bad);
            v.as_array()
                .ok_or_else(bad)?
                .iter()
                .map(|e| {
                    Ok(PodDeviceLimit {
                        major: u32::try_from(num(e, "major")?).map_err(|_| bad())?,
                        minor: u32::try_from(num(e, "minor")?).map_err(|_| bad())?,
                        value: num(e, key)?,
                        path: String::new(),
                    })
                })
                .collect()
        }
        let mut r = Self::default();
        let empty = serde_json::Map::new();
        let top = limits.and_then(Value::as_object).unwrap_or(&empty);
        for (group, value) in top {
            let Some(fields) = value.as_object() else {
                if set(value) {
                    return Err(format!(
                        "resource limits `{group}` of a pod are not supported"
                    ));
                }
                continue;
            };
            for (key, v) in fields {
                if !set(v) {
                    continue;
                }
                let int = || {
                    v.as_i64()
                        .ok_or_else(|| format!("`{group}.{key}` is not a number"))
                };
                let text = || {
                    v.as_str()
                        .map(str::to_string)
                        .ok_or_else(|| format!("`{group}.{key}` is not a string"))
                };
                match (group.as_str(), key.as_str()) {
                    ("memory", "limit") => r.memory = Some(int()?),
                    ("memory", "swap") => r.memory_swap = Some(int()?),
                    ("cpu", "shares") => {
                        r.cpu_shares = Some(u64::try_from(int()?).map_err(|e| e.to_string())?)
                    }
                    ("cpu", "quota") => r.cpu_quota = Some(int()?),
                    ("cpu", "period") => {
                        r.cpu_period = Some(u64::try_from(int()?).map_err(|e| e.to_string())?)
                    }
                    ("cpu", "cpus") => r.cpuset_cpus = Some(text()?),
                    ("cpu", "mems") => r.cpuset_mems = Some(text()?),
                    ("blockIO", "weight") => {
                        r.blkio_weight = Some(u16::try_from(int()?).map_err(|e| e.to_string())?)
                    }
                    ("blockIO", "weightDevice") => {
                        r.blkio_weight_device = devices(v, "weight", "blockIO.weightDevice")?
                    }
                    ("blockIO", "throttleReadBpsDevice") => {
                        r.device_read_bps = devices(v, "rate", "blockIO.throttleReadBpsDevice")?
                    }
                    ("blockIO", "throttleWriteBpsDevice") => {
                        r.device_write_bps = devices(v, "rate", "blockIO.throttleWriteBpsDevice")?
                    }
                    _ => {
                        return Err(format!(
                            "resource limits `{group}.{key}` of a pod are not supported"
                        ))
                    }
                }
            }
        }
        if let Some(p) = cpu_period.filter(|p| *p != 0) {
            r.cpu_period = Some(p);
        }
        if let Some(q) = cpu_quota.filter(|q| *q != 0) {
            r.cpu_quota = Some(q);
        }
        r.check()?;
        Ok((!r.is_empty()).then_some(r))
    }

    /// The values are ones a cgroup can have; `0` and `-1` are no limit.
    pub fn check(&self) -> Result<(), String> {
        let bad = |what: &str| Err(format!("invalid pod resources: {what}"));
        if self.memory.is_some_and(|m| m < -1) {
            return bad("a negative memory limit");
        }
        if self.memory_swap.is_some_and(|m| m < -1) {
            return bad("a negative memory and swap limit");
        }
        if let (Some(m), Some(s)) = (self.memory.filter(|m| *m > 0), self.memory_swap) {
            if s > 0 && s < m {
                return bad("the memory and swap limit is below the memory limit");
            }
        }
        if self.memory.is_none_or(|m| m <= 0) && self.memory_swap.is_some_and(|s| s > 0) {
            return bad("a swap limit needs a memory limit");
        }
        if self
            .cpu_shares
            .is_some_and(|s| s != 0 && !(2..=262_144).contains(&s))
        {
            return bad("CPU shares are from 2 to 262144");
        }
        if self.cpu_quota.is_some_and(|q| q < -1) {
            return bad("a negative CPU quota");
        }
        if self
            .cpu_period
            .is_some_and(|p| p != 0 && !(1_000..=1_000_000).contains(&p))
        {
            return bad("a CPU period is from 1000 to 1000000 microseconds");
        }
        for (name, list) in [
            ("weight", &self.blkio_weight_device),
            ("read rate", &self.device_read_bps),
            ("write rate", &self.device_write_bps),
        ] {
            for d in list {
                if (name == "weight" && d.value != 0 && !(10..=1000).contains(&d.value))
                    || (name != "weight" && d.value > i64::MAX as u64)
                {
                    return bad(&format!("the {name} of the device {}:{}", d.major, d.minor));
                }
            }
        }
        if self
            .blkio_weight
            .is_some_and(|w| w != 0 && !(10..=1000).contains(&w))
        {
            return bad("the block IO weight is from 10 to 1000");
        }
        for set in [&self.cpuset_cpus, &self.cpuset_mems].into_iter().flatten() {
            if !set
                .bytes()
                .all(|b| b.is_ascii_digit() || b == b',' || b == b'-')
            {
                return bad("a cpuset is a list of numbers and ranges");
            }
        }
        Ok(())
    }
}

/// What `PodCreate` makes.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "proxy", derive(zlink::introspect::CustomType))]
#[serde(default)]
pub struct PodSpec {
    pub name: String,
    pub hostname: Option<String>,
    pub networks: Vec<String>,
    pub dns: PodDnsConfig,
    pub add_hosts: Vec<String>,
    pub security_context: PodSecurityContext,
    pub ports: Vec<PodPortMapping>,
    pub labels: BTreeMap<String, String>,
    pub annotations: BTreeMap<String, String>,
    /// Share PID namespace among containers
    pub share_pid: bool,
    /// Share IPC namespace among containers
    pub share_ipc: bool,
    /// Share network namespace among containers (`--share net`: on by
    /// default, always off without an infra container)
    pub share_net: bool,
    /// Share UTS namespace among containers
    pub share_uts: bool,
    /// Share cgroup namespace among containers
    pub share_cgroup: bool,
    /// The pod is in the PID namespace of the host: its infra container and
    /// its members use it (there is none to share)
    #[serde(default)]
    pub host_pid: bool,
    /// The same for the IPC namespace of the host
    #[serde(default)]
    pub host_ipc: bool,
    /// The user namespace of the infra container (`--userns`), which the
    /// members join
    pub userns: Option<UsernsChoice>,
    /// `--uidmap` of the pod's user namespace
    #[serde(default)]
    pub uid_mappings: Vec<IdMapping>,
    /// `--gidmap` of the pod's user namespace
    #[serde(default)]
    pub gid_mappings: Vec<IdMapping>,
    /// Infra container image
    pub infra_image: Option<String>,
    /// Infra container command
    pub infra_command: Option<Vec<String>>,
    /// Name of the infra container (default `<first 12 characters of the pod id>-infra`)
    #[serde(default)]
    pub infra_name: Option<String>,
    /// What the pod does when all its containers exit
    #[serde(default)]
    pub exit_policy: PodExitPolicy,
    /// `--infra-conmon-pidfile`: the pid file of the infra container's
    /// monitor (Quadlet's `Type=forking` pod units)
    #[serde(default)]
    pub infra_conmon_pidfile: Option<String>,
    /// `--sysctl`: of the namespaces the pod shares (set on its infra)
    #[serde(default)]
    pub sysctls: BTreeMap<String, String>,
    /// `--shm-size`: of the infra, and of the members that set none
    #[serde(default)]
    pub shm_size: Option<u64>,
    /// `--volume`: mounted in the infra and in every member
    #[serde(default)]
    pub volumes: Vec<String>,
    /// `--restart`: of the members that set none
    #[serde(default)]
    pub restart_policy: Option<RestartPolicy>,
    /// The OCI runtime of the infra container and of the members that ask for
    /// none (`oci_runtime` of the pod create, the CRI's runtime handler)
    #[serde(default)]
    pub runtime: Option<String>,
    /// `--cgroup-parent`: of the infra and of the members that set none
    #[serde(default)]
    pub cgroup_parent: Option<String>,
    /// `--cgroups`: the mode of the infra container ("" the default,
    /// `enabled`, `scope`, `split`: the default of the engine service); in a pod made `disabled` the members are too
    #[serde(default, skip_serializing_if = "CgroupsMode::is_unset")]
    pub cgroups: CgroupsMode,
    /// `scope` of the infra container and of every member, chosen
    /// from `cgroups` when the pod is made (none for a pod without cgroups);
    /// the engine's, not an option: a `PodCreate` that sets it is refused
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "crate::modes::cgroup_mode_word"
    )]
    pub cgroup_mode: Option<CgroupMode>,
    /// The limits of the cgroup of the pod
    #[serde(default)]
    pub resources: Option<PodResources>,
    /// `--security-opt`: of the infra container
    #[serde(default)]
    pub security_opts: Vec<String>,
    /// `--oom-score-adj` of the infra container
    #[serde(default)]
    pub infra_oom_score_adj: Option<i32>,
    /// `--read-only` of the infra container
    #[serde(default)]
    pub infra_read_only: bool,
    /// `--privileged` of the infra container
    #[serde(default)]
    pub infra_privileged: bool,
    /// `--ip`: the address of the pod (its infra) on its network
    #[serde(default)]
    pub ip: Option<String>,
    /// `--ip6`: its IPv6 address
    #[serde(default)]
    pub ip6: Option<String>,
    /// The annotations of the pod, for the CNI plugins of its network only
    /// (the bandwidth ones and the `io.kubernetes.cri.pod-annotations`
    /// capability); they are not annotations of the infra container
    #[serde(default)]
    pub cni_annotations: BTreeMap<String, String>,
    /// The subnets the node gives its pods (the pod CIDR of a kubelet), for
    /// the CNI plugins that ask for `ipRanges`
    #[serde(default)]
    pub cni_ip_ranges: Vec<String>,
    /// Its MAC address on its network (podman's `--mac-address`)
    #[serde(default)]
    pub mac: Option<String>,
    /// `--network-alias`: its names on its networks
    #[serde(default)]
    pub network_aliases: Vec<String>,
    /// `--device` as typed (`HOST[:CONTAINER][:PERMISSIONS]`, or a CDI name;
    /// `--gpus` makes `nvidia.com/gpu=` ones): of the infra container and the
    /// members
    #[serde(default)]
    pub devices: Vec<String>,
    /// `--volumes-from` as typed, for the inspect: the volumes of those
    /// containers are in `volumes`
    #[serde(default)]
    pub volumes_from: Vec<String>,
    /// `--hosts-file`: the base of /etc/hosts of the pod (a path, `none`
    /// or `image`)
    #[serde(default)]
    pub hosts_file: Option<String>,
    /// `--no-hosts`: the pod leaves the /etc/hosts of the images alone
    #[serde(default)]
    pub no_hosts: bool,
    /// `--no-hostname`: no /etc/hostname
    #[serde(default)]
    pub no_hostname: bool,
    /// `--uts host`: the pod is in the UTS namespace of the host (its
    /// infra container and its members use it; there is none to share)
    #[serde(default)]
    pub host_uts: bool,
    /// `--infra=false`: the pod has no infra container, so its members
    /// share no namespace; the pod only groups their cgroup, their name and
    /// their lifecycle
    #[serde(default)]
    pub no_infra: bool,
    /// `--share-parent=false`: the members are not in the cgroup of the
    /// pod
    #[serde(default)]
    pub no_share_parent: bool,
    /// `--shm-size-systemd`: of the infra and of the members that set none
    #[serde(default)]
    pub shm_size_systemd: Option<u64>,
    /// `--subuidname`: the user namespace of the pod is made of the ranges of
    /// this user of /etc/subuid
    #[serde(default)]
    pub subuidname: Option<String>,
    /// `--subgidname`: the user namespace of the pod is made of the ranges of
    /// this user of /etc/subgid
    #[serde(default)]
    pub subgidname: Option<String>,
    /// The command line that made the pod (podman's `CreateCommand`)
    #[serde(default)]
    pub create_command: Vec<String>,
}

// (with the service only: the engine reads the documents; the thin client of
// velarx, which has the types, links none of this)
#[cfg(feature = "service")]
impl PodSpec {
    /// The spec a `PodCreate` document describes.  A field the type does
    /// not have is refused (a frontend and an engine of the same interface
    /// agree on the fields; one that is not known would be lost silently),
    /// and so are the values a pod cannot have.
    pub fn from_document(bytes: &[u8]) -> Result<Self, String> {
        let value: serde_json::Value = serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
        let spec: Self = serde_json::from_value(value.clone()).map_err(|e| e.to_string())?;
        let known = serde_json::to_value(&spec).map_err(|e| e.to_string())?;
        if let Some(path) = unknown_field(&value, &known, "") {
            return Err(format!("unknown field `{path}`"));
        }
        // (the scope the engine resolves from `cgroups` and keeps
        // with the pod: `cgroups` asks for one, there is no other knob)
        if let Some(mode) = spec.cgroup_mode {
            return Err(format!(
                "`cgroup_mode` is not an option: `cgroups` = \"{mode}\" asks for it"
            ));
        }
        spec.check()?;
        Ok(spec)
    }

    /// The values of the spec are ones a pod can have.
    pub fn check(&self) -> Result<(), String> {
        if let Some(p) = &self.restart_policy {
            if !matches!(
                p.name.as_str(),
                "no" | "always" | "on-failure" | "unless-stopped"
            ) {
                return Err(format!("invalid restart policy: \"{}\"", p.name));
            }
        }
        if self.no_infra {
            let exclusive = |opt: &str| {
                Err(format!(
                    "NoInfra and {opt} are mutually exclusive pod options: invalid pod spec"
                ))
            };
            if self.infra_command.is_some() {
                return exclusive("InfraCommand");
            }
            if self.infra_image.is_some() {
                return exclusive("InfraImage");
            }
            if self.infra_name.is_some() {
                return exclusive("InfraName");
            }
            // (podman's words, its spelling of the second too)
            if !self.networks.is_empty() {
                return Err("NoInfra and network modes cannot be used together".into());
            }
            if self.ip.is_some()
                || self.ip6.is_some()
                || self.mac.is_some()
                || !self.network_aliases.is_empty()
            {
                return Err("cannot set networks options without infra container".into());
            }
            if !self.dns.options.is_empty() {
                return exclusive("DNSOption");
            }
            if !self.dns.searches.is_empty() {
                return Err(
                    "NoInfo and DNSSearch are mutually exclusive pod options: invalid pod spec"
                        .into(),
                );
            }
            if !self.dns.servers.is_empty() {
                return exclusive("DNSServer");
            }
            if !self.add_hosts.is_empty() {
                return exclusive("HostAdd");
            }
            if self.hosts_file.is_some() {
                return exclusive("HostsFile");
            }
            if self.no_hosts {
                return Err("cannot specify --no-hosts without an infra container".into());
            }
            if !self.ports.is_empty() {
                return Err(
                    "you must have an infra container to publish port bindings to the host".into(),
                );
            }
        }
        if self.no_hosts && !self.add_hosts.is_empty() {
            return Err("--no-hosts and --add-host cannot be set together".into());
        }
        if self.no_hosts && self.hosts_file.is_some() {
            return Err("--no-hosts and --hosts-file cannot be set together".into());
        }
        if self.no_share_parent && self.share_cgroup {
            return Err(
                "cannot define the pod as the cgroup parent at the same time as joining the infra container's cgroupNS: invalid argument"
                    .into(),
            );
        }
        if self.ports.iter().any(|p| p.container_port == 0) {
            return Err("a port mapping without a container port".into());
        }
        if let Some(r) = &self.resources {
            r.check()?;
        }
        Ok(())
    }
}

/// The first field of `input` (its path) that the typed value `known` made
/// of it does not have: one the type does not know.
#[cfg(feature = "service")]
fn unknown_field(input: &serde_json::Value, known: &serde_json::Value, at: &str) -> Option<String> {
    use serde_json::Value;
    match (input, known) {
        (Value::Object(input), Value::Object(known)) => input.iter().find_map(|(key, value)| {
            let path = if at.is_empty() {
                key.clone()
            } else {
                format!("{at}.{key}")
            };
            match known.get(key) {
                None => Some(path),
                Some(k) => unknown_field(value, k, &path),
            }
        }),
        (Value::Array(input), Value::Array(known)) => input
            .iter()
            .zip(known)
            .enumerate()
            .find_map(|(i, (v, k))| unknown_field(v, k, &format!("{at}[{i}]"))),
        _ => None,
    }
}

#[cfg(all(test, feature = "service"))]
mod tests {
    #[test]
    fn a_pod_without_infra_takes_none_of_its_options() {
        let spec = PodSpec {
            no_infra: true,
            ..Default::default()
        };
        assert!(spec.check().is_ok());
        for (spec, word) in [
            (
                PodSpec {
                    infra_image: Some("x".into()),
                    ..spec.clone()
                },
                "InfraImage",
            ),
            (
                PodSpec {
                    add_hosts: vec!["a:1.1.1.1".into()],
                    ..spec.clone()
                },
                "HostAdd",
            ),
            (
                PodSpec {
                    networks: vec!["n".into()],
                    ..spec.clone()
                },
                "network modes",
            ),
        ] {
            let e = spec.check().unwrap_err();
            assert!(e.contains(word), "{e}");
        }
    }

    use super::*;

    #[test]
    fn a_pressure_file_is_its_some_and_full_lines() {
        let p = Psi::parse(
            "some avg10=1.50 avg60=0.25 avg300=0.00 total=12345\n\
             full avg10=0.10 avg60=0.00 avg300=0.00 total=99\n",
        )
        .unwrap();
        assert_eq!(p.some.avg10, 1.5);
        assert_eq!(p.some.avg60, 0.25);
        assert_eq!(p.some.total_us, 12345);
        assert_eq!(p.full.total_us, 99);
        // (cpu.pressure of a kernel before 5.13 has no full line)
        let some = Psi::parse("some avg10=0.00 avg60=0.00 avg300=0.00 total=7\n").unwrap();
        assert_eq!((some.some.total_us, some.full), (7, PsiData::default()));
        assert_eq!(Psi::parse(""), None);
    }

    #[test]
    fn a_document_is_a_spec_with_known_fields_and_values() {
        let spec = PodSpec::from_document(
            br#"{"name":"p","labels":{"any":"x"},"ports":[{"container_port":80,"host_port":8080,"host_ip":null,"protocol":"tcp"}],"restart_policy":{"name":"always"}}"#,
        )
        .unwrap();
        assert_eq!(spec.name, "p");
        assert_eq!(spec.ports[0].host_port, Some(8080));
        let infra = PodSpec::from_document(
            br#"{"infra_oom_score_adj":-998,"infra_read_only":true,"infra_privileged":true}"#,
        )
        .unwrap();
        assert_eq!(infra.infra_oom_score_adj, Some(-998));
        assert!(infra.infra_read_only && infra.infra_privileged);
        let cni = PodSpec::from_document(
            br#"{"cni_annotations":{"kubernetes.io/egress-bandwidth":"1M"},"cni_ip_ranges":["10.1.0.0/24"]}"#,
        )
        .unwrap();
        assert_eq!(cni.cni_annotations["kubernetes.io/egress-bandwidth"], "1M");
        assert_eq!(cni.cni_ip_ranges, ["10.1.0.0/24"]);
        // the document the engine keeps reads back
        let again = serde_json::to_vec(&spec).unwrap();
        assert_eq!(PodSpec::from_document(&again).unwrap().name, "p");
        for (doc, error) in [
            (&br#"{"name":"p","bogus":1}"#[..], "unknown field `bogus`"),
            (
                br#"{"dns":{"servers":[],"searches":[],"options":[],"nameservers":[]}}"#,
                "unknown field `dns.nameservers`",
            ),
            (
                br#"{"ports":[{"container_port":1,"protocol":"tcp","extra":0}]}"#,
                "unknown field `ports[0].extra`",
            ),
            (
                br#"{"exit_policy":"never"}"#,
                "unknown variant `never`, expected `continue` or `stop`",
            ),
            (
                br#"{"restart_policy":{"name":"sometimes"}}"#,
                "invalid restart policy: \"sometimes\"",
            ),
            (
                br#"{"ports":[{"container_port":0,"protocol":"tcp"}]}"#,
                "a port mapping without a container port",
            ),
            (
                br#"{"cgroup_mode":"scope"}"#,
                "`cgroup_mode` is not an option: `cgroups` = \"scope\" asks for it",
            ),
        ] {
            assert_eq!(PodSpec::from_document(doc).unwrap_err(), error);
        }
        // the limits of the cgroup of the pod
        let limited = PodSpec::from_document(
            br#"{"resources":{"memory":1048576,"memory_swap":2097152,"cpu_shares":512,"cpuset_cpus":"0-3"}}"#,
        )
        .unwrap();
        let r = limited.resources.unwrap();
        assert_eq!((r.memory, r.cpu_shares), (Some(1 << 20), Some(512)));
        for doc in [
            &br#"{"resources":{"memory":-5}}"#[..],
            br#"{"resources":{"memory":100,"memory_swap":50}}"#,
            br#"{"resources":{"cpu_shares":1}}"#,
            br#"{"resources":{"cpu_period":5}}"#,
            br#"{"resources":{"cpuset_cpus":"0;rm"}}"#,
            br#"{"resources":{"memory_swap":50}}"#,
            br#"{"resources":{"pids":3}}"#,
        ] {
            assert!(
                PodSpec::from_document(doc).is_err(),
                "{:?}",
                String::from_utf8_lossy(doc)
            );
        }
        assert!(PodSpec::from_document(b"[1]").is_err());
        assert!(PodSpec::from_document(br#"{"name":7}"#).is_err());
    }

    #[test]
    fn podmans_limits_are_the_pods_and_the_rest_is_refused() {
        let v = |t: &str| serde_json::from_str::<serde_json::Value>(t).unwrap();
        let r = PodResources::from_podman(
            Some(&v(r#"{"memory":{"limit":100,"swap":200,"reservation":0},"cpu":{"shares":2,"cpus":"1","quota":0}}"#)),
            Some(50_000),
            Some(10_000),
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            r,
            PodResources {
                memory: Some(100),
                memory_swap: Some(200),
                cpu_shares: Some(2),
                cpu_quota: Some(10_000),
                cpu_period: Some(50_000),
                cpuset_cpus: Some("1".into()),
                cpuset_mems: None,
                ..Default::default()
            }
        );
        // the block IO limits, the devices by their numbers
        let io = PodResources::from_podman(
            Some(&v(
                r#"{"blockIO":{"weight":50,"weightDevice":[{"major":7,"minor":0,"weight":20}],
                "throttleReadBpsDevice":[{"major":7,"minor":0,"rate":1048576}],
                "throttleWriteBpsDevice":[{"major":8,"minor":16,"rate":2}]}}"#,
            )),
            None,
            None,
        )
        .unwrap()
        .unwrap();
        let dev = |major, minor, value| PodDeviceLimit {
            major,
            minor,
            value,
            path: String::new(),
        };
        assert_eq!(io.blkio_weight, Some(50));
        assert_eq!(io.blkio_weight_device, [dev(7, 0, 20)]);
        assert_eq!(io.device_read_bps, [dev(7, 0, 1 << 20)]);
        assert_eq!(io.device_write_bps, [dev(8, 16, 2)]);
        // the IOPS ones and a device that is no list are refused
        for bad in [
            r#"{"blockIO":{"throttleReadIOPSDevice":[{"major":7,"minor":0,"rate":1}]}}"#,
            r#"{"blockIO":{"weightDevice":[{"major":7,"weight":20}]}}"#,
            r#"{"blockIO":{"weightDevice":[{"major":7,"minor":0,"weight":2}]}}"#,
        ] {
            assert!(
                PodResources::from_podman(Some(&v(bad)), None, None).is_err(),
                "{bad}"
            );
        }
        // the empty objects podman sends are no limits
        assert_eq!(
            PodResources::from_podman(Some(&v(r#"{"cpu":{},"memory":{"limit":0}}"#)), None, None),
            Ok(None)
        );
        assert_eq!(PodResources::from_podman(None, Some(0), Some(0)), Ok(None));
        for bad in [
            r#"{"pids":{"limit":4}}"#,
            r#"{"memory":{"reservation":4}}"#,
            r#"{"blockIO":{"weight":4}}"#,
            r#"{"hugepageLimits":[{"pageSize":"2MB","limit":1}]}"#,
            r#"{"memory":{"limit":"a lot"}}"#,
            r#"{"cpu":{"shares":-3}}"#,
        ] {
            assert!(
                PodResources::from_podman(Some(&v(bad)), None, None).is_err(),
                "{bad}"
            );
        }
    }
}
