// SPDX-License-Identifier: Apache-2.0
//! The engine as a whole as records: what it is and runs on, what the
//! store uses, the prune of what is not in use, the check and the
//! collection of the store, the login to a registry.

use super::call::Filters;
use super::convert;
use super::error::{ApiError, ApiResult};
use super::images::image_id;
use crate::api::AppState;
use serde_json::Value;
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use velarx_db::{ContainerRecord, RecordState};
use velarx_proto::system::{
    CgroupManager, CheckReport, CheckSpec, ContainerUsage, CpuUtilization, DiskUsageRecord,
    GcReport, HostRecord, HostTool, ImageUsage, OciRuntimeRecord, PrunedVolume, RuntimePath,
    ServiceStore, StoreRecord, StoreUsage, StoresReport, SubnetPool, SystemPruneReport,
    SystemRecord, SystemdRecord, VersionRecord, VolumeUsage,
};

const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The string of a file of the host, off the async threads: the file is
/// small but the read is synchronous.
async fn proc_string(path: &'static str) -> String {
    tokio::fs::read_to_string(path)
        .await
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}

/// The strings of files of the host, all of them in one turn of the
/// blocking pool (a file that cannot be read is empty).
async fn proc_strings(paths: &[&'static str]) -> Vec<String> {
    let paths = paths.to_vec();
    tokio::task::spawn_blocking(move || {
        paths
            .iter()
            .map(|p| {
                std::fs::read_to_string(p)
                    .map(|s| s.trim().to_string())
                    .unwrap_or_default()
            })
            .collect()
    })
    .await
    .unwrap_or_default()
}

/// The values of the `/proc` files the host record is filled from
/// (`hostname`, `/proc/stat`, `meminfo`, `uptime`, the ID maps) read in one
/// turn of the blocking pool.
struct Proc {
    hostname: String,
    stat: String,
    meminfo: String,
    uptime: String,
    uid_map: String,
    gid_map: String,
}

impl Proc {
    /// Every file the host record looks at.
    async fn read() -> Self {
        const FILES: &[&str] = &[
            "/proc/sys/kernel/hostname",
            "/proc/stat",
            "/proc/meminfo",
            "/proc/uptime",
            "/proc/self/uid_map",
            "/proc/self/gid_map",
        ];
        let mut read = proc_strings(FILES).await;
        let mut read = read.drain(..);
        let mut next = || read.next().unwrap_or_default();
        Proc {
            hostname: next(),
            stat: next(),
            meminfo: next(),
            uptime: next(),
            uid_map: next(),
            gid_map: next(),
        }
    }

    /// podman's `cpuUtilization`: the shares of the CPU time since the boot
    /// (`/proc/stat`), in percent with two decimals.
    fn cpu_utilization(&self) -> CpuUtilization {
        cpu_utilization_of(&self.stat)
    }

    /// Bytes of a `/proc/meminfo` entry.
    fn meminfo(&self, key: &str) -> u64 {
        meminfo_of(&self.meminfo, key)
    }

    /// How long the host has run, in nanoseconds.
    fn uptime_ns(&self) -> i64 {
        let secs: f64 = self
            .uptime
            .split_whitespace()
            .next()
            .and_then(|s| s.parse().ok())
            .unwrap_or(0.0);
        (secs * 1e9) as i64
    }
}

fn cpu_utilization_of(stat: &str) -> CpuUtilization {
    let v: Vec<f64> = stat
        .lines()
        .find_map(|l| l.strip_prefix("cpu "))
        .unwrap_or_default()
        .split_whitespace()
        .filter_map(|n| n.parse().ok())
        .collect();
    // user nice system idle iowait irq softirq steal
    let total: f64 = v.iter().take(8).sum();
    let share = |n: f64| {
        if total > 0.0 {
            (n / total * 10000.0).round() / 100.0
        } else {
            0.0
        }
    };
    let at = |i: usize| v.get(i).copied().unwrap_or(0.0);
    CpuUtilization {
        user_percent: share(at(0) + at(1)),
        system_percent: share(at(2) + at(5) + at(6)),
        idle_percent: share(at(3) + at(4)),
    }
}

fn meminfo_of(text: &str, key: &str) -> u64 {
    text.lines()
        .find_map(|l| {
            let rest = l.strip_prefix(key)?.strip_prefix(':')?;
            rest.split_whitespace().next()?.parse::<u64>().ok()
        })
        .map_or(0, |kb| kb * 1024)
}

fn cpus() -> usize {
    std::thread::available_parallelism().map_or(1, |n| n.get())
}

/// The platforms of the binfmt_misc handlers of QEMU the host has
/// (podman's `emulatedArchitectures`), in one turn of the blocking pool:
/// a directory walk with a read in it.
async fn emulated_architectures() -> Vec<String> {
    tokio::task::spawn_blocking(emulated_architectures_sync)
        .await
        .unwrap_or_default()
}

fn emulated_architectures_sync() -> Vec<String> {
    const QEMU: &[(&str, &str)] = &[
        ("aarch64", "arm64"),
        ("aarch64_be", "arm64be"),
        ("arm", "arm"),
        ("i386", "386"),
        ("loongarch64", "loong64"),
        ("mips", "mips"),
        ("mips64", "mips64"),
        ("ppc", "ppc"),
        ("ppc64", "ppc64"),
        ("ppc64le", "ppc64le"),
        ("riscv32", "riscv32"),
        ("riscv64", "riscv64"),
        ("s390x", "s390x"),
        ("x86_64", "amd64"),
    ];
    let own = velarx_shape::system::go_arch(std::env::consts::ARCH);
    let mut out: Vec<String> = std::fs::read_dir("/proc/sys/fs/binfmt_misc")
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| {
            let name = e.file_name().into_string().ok()?;
            let (_, go) = QEMU
                .iter()
                .find(|(q, _)| name.strip_prefix("qemu-") == Some(q))?;
            let text = std::fs::read_to_string(e.path()).ok()?;
            (text.lines().next() == Some("enabled") && *go != own).then(|| format!("linux/{go}"))
        })
        .collect();
    out.sort();
    out.dedup();
    out
}

/// The ID mappings of the user namespace the engine runs in, rootless
/// (podman's `idMappings`); none for root.
fn id_mappings(map: &str) -> ApiResult<Vec<velarx_proto::pod::IdMapping>> {
    if !rootless()? {
        return Ok(Vec::new());
    }
    Ok(velarx_base::idmap::parse_proc_map(map)
        .iter()
        .map(|m| velarx_proto::pod::IdMapping {
            container_id: m.container_id,
            host_id: m.host_id,
            size: m.size,
        })
        .collect())
}

/// The bytes of the file system of `path`: its size and what is used.
fn space_of(path: &std::path::Path) -> (u64, u64) {
    match rustix::fs::statvfs(path) {
        Ok(st) => (
            st.f_blocks.saturating_mul(st.f_frsize),
            st.f_blocks
                .saturating_sub(st.f_bfree)
                .saturating_mul(st.f_frsize),
        ),
        Err(_) => (0, 0),
    }
}

/// The cgroup controllers the containers can have (podman's
/// `cgroupControllers`): those of the cgroup the engine makes them in, else
/// of the root cgroup (root) or of the user's manager (rootless), which
/// delegates them.
async fn cgroup_controllers(state: &AppState) -> ApiResult<Vec<String>> {
    let read = |path: String| async move {
        tokio::fs::read_to_string(path)
            .await
            .unwrap_or_default()
            .split_whitespace()
            .map(str::to_string)
            .collect::<Vec<String>>()
    };
    Ok(match state.container_service.cgroup_manager.as_ref() {
        // the manager reads the cgroup tree itself, synchronously
        Some(m) => tokio::task::spawn_blocking({
            let m = m.clone();
            move || m.controllers()
        })
        .await
        .unwrap_or_default(),
        None => {
            let dir = if rootless()? {
                let uid = rustix::process::getuid().as_raw();
                format!("/sys/fs/cgroup/user.slice/user-{uid}.slice/user@{uid}.service")
            } else {
                "/sys/fs/cgroup".to_string()
            };
            read(format!("{dir}/cgroup.controllers")).await
        }
    })
}

fn rootless() -> Result<bool, velarx_base::ids::IdsError> {
    velarx_runtime::userns::rootless::in_user_namespace()
}

/// When this binary was built: the build time it was given (RFC 3339),
/// else the time of the executable.
fn build_time() -> Option<chrono::DateTime<chrono::Utc>> {
    if let Ok(t) = chrono::DateTime::parse_from_rfc3339(velarx_base::buildinfo::time()) {
        return Some(t.with_timezone(&chrono::Utc));
    }
    let modified = std::env::current_exe()
        .ok()?
        .metadata()
        .ok()?
        .modified()
        .ok()?;
    Some(chrono::DateTime::<chrono::Utc>::from(modified))
}

/// The build of the engine.
pub(crate) async fn version_record() -> VersionRecord {
    VersionRecord {
        version: VERSION.to_string(),
        commit: velarx_base::buildinfo::commit().to_string(),
        built_ns: build_time()
            .and_then(|t| t.timestamp_nanos_opt())
            .unwrap_or(0),
        os: std::env::consts::OS.to_string(),
        arch: std::env::consts::ARCH.to_string(),
        kernel: proc_string("/proc/sys/kernel/osrelease").await,
    }
}

/// The containers by state and the images.
async fn counts(state: &AppState, store: &mut StoreRecord) -> ApiResult<()> {
    let list = state.db.list_containers(true).await?;
    store.containers = list.len() as u64;
    store.images = state.image_service.list().await?.len() as u64;
    for r in &list {
        match r.state {
            RecordState::Running => store.running += 1,
            RecordState::Paused => store.paused += 1,
            _ => store.stopped += 1,
        }
    }
    Ok(())
}

/// The `features` of the OCI runtime at `path` (the JSON of the runtime-spec
/// features): asked once by the runtime layer that decides on them too;
/// empty when it has none.
pub(crate) async fn runtime_features(path: &Path) -> String {
    let path = path.to_path_buf();
    // (the runtime is run and waited for: not on the executor)
    tokio::task::spawn_blocking(move || {
        velarx_runtime::container::runtime_features(&path).to_string()
    })
    .await
    .unwrap_or_default()
}

/// What the OCI runtime says of itself: its version line and its
/// `features` (the JSON of the runtime-spec features), asked once.
async fn runtime_details(state: &AppState) -> &'static (String, String) {
    static DETAILS: tokio::sync::OnceCell<(String, String)> = tokio::sync::OnceCell::const_new();
    let path = state
        .container_service
        .runtime()
        .runtime_path()
        .to_path_buf();
    DETAILS
        .get_or_init(|| async move {
            let run = |arg: &'static str| {
                let path = path.clone();
                async move {
                    let out = tokio::time::timeout(
                        std::time::Duration::from_secs(5),
                        tokio::process::Command::new(&path).arg(arg).output(),
                    )
                    .await;
                    match out {
                        Ok(Ok(o)) if o.status.success() => {
                            String::from_utf8_lossy(&o.stdout).into_owned()
                        }
                        _ => String::new(),
                    }
                }
            };
            let version = run("--version")
                .await
                .lines()
                .next()
                .unwrap_or("")
                .to_string();
            let features = runtime_features(&path).await;
            (version, features)
        })
        .await
}

/// An executable of the host: its path, the package it came from (rpm or
/// dpkg) and the first line of `--version`, asked once.
async fn host_tool(name: &'static str) -> HostTool {
    use std::sync::{LazyLock, Mutex};
    static TOOLS: LazyLock<Mutex<HashMap<&'static str, HostTool>>> = LazyLock::new(Mutex::default);
    if let Some(v) = TOOLS.lock().ok().and_then(|m| m.get(name).cloned()) {
        return v;
    }
    let path = std::env::var_os("PATH")
        .map(|p| {
            std::env::split_paths(&p)
                .map(|d| d.join(name))
                .find(|p| p.is_file())
        })
        .unwrap_or_default();
    let run = |cmd: &str, args: Vec<String>| {
        let cmd = cmd.to_string();
        async move {
            match tokio::time::timeout(
                std::time::Duration::from_secs(5),
                tokio::process::Command::new(cmd).args(args).output(),
            )
            .await
            {
                Ok(Ok(o)) if o.status.success() => String::from_utf8_lossy(&o.stdout)
                    .lines()
                    .next()
                    .unwrap_or("")
                    .trim()
                    .to_string(),
                _ => String::new(),
            }
        }
    };
    let tool = match &path {
        Some(p) => {
            let p = p.to_string_lossy().to_string();
            let mut package = run("rpm", vec!["-qf".into(), p.clone()]).await;
            if package.is_empty() {
                package = run("dpkg", vec!["-S".into(), p.clone()]).await;
            }
            HostTool {
                version: run(&p, vec!["--version".into()]).await,
                path: p,
                package,
            }
        }
        None => HostTool::default(),
    };
    if let Ok(mut m) = TOOLS.lock() {
        m.insert(name, tool.clone());
    }
    tool
}

/// The inodes of the file system of `path` and those in use, none when it
/// cannot be asked.
fn inodes_of(path: &std::path::Path) -> (Option<u64>, Option<u64>) {
    match rustix::fs::statvfs(path) {
        Ok(st) => (
            Some(st.f_files),
            Some(st.f_files.saturating_sub(st.f_ffree)),
        ),
        Err(e) => {
            tracing::warn!("statvfs {}: {e}", path.display());
            (None, None)
        }
    }
}

/// What the engine is and what it runs on: `SystemInspect`.
pub(crate) async fn system_record(state: &AppState) -> ApiResult<SystemRecord> {
    let cfg = &state.config;
    let proc = Proc::read().await;
    let driver = state.image_service.storage();
    let mut store = StoreRecord {
        storage_driver: cfg.storage.driver_kind().name().to_string(),
        graph_driver: driver.graph_name().to_string(),
        graph_status: driver.status().into_iter().collect(),
        config_file: match &cfg.source {
            Some(source) => source.clone(),
            None => velarx_config::DefaultDirs::current()?.config_file,
        }
        .to_string_lossy()
        .to_string(),
        graph_root: cfg.storage.root.to_string_lossy().to_string(),
        run_root: cfg.server.state_dir.to_string_lossy().to_string(),
        root_dir: cfg.server.root_dir.to_string_lossy().to_string(),
        volume_path: cfg
            .server
            .root_dir
            .join("volumes")
            .to_string_lossy()
            .to_string(),
        ..Default::default()
    };
    (store.graph_root_inodes, store.graph_root_inodes_used) = inodes_of(&cfg.storage.root);
    (store.graph_root_allocated, store.graph_root_used) = space_of(&cfg.storage.root);
    counts(state, &mut store).await?;
    let (rt_version, rt_features) = runtime_details(state).await;
    let rt_name = velarx_runtime::container::runtime_name();
    let rt_path = state
        .container_service
        .runtime()
        .runtime_path()
        .to_string_lossy()
        .to_string();
    // those of [runtimes] that are there
    let mut runtimes = Vec::new();
    for name in cfg.runtimes.keys() {
        if let Some(Ok(path)) = cfg.configured_runtime(name) {
            runtimes.push(RuntimePath {
                name: name.clone(),
                features: runtime_features(&path).await,
                path: path.to_string_lossy().to_string(),
            });
        }
    }
    let server = state.server_service.info().await?;
    let host = HostRecord {
        hostname: proc.hostname.clone(),
        cpus: cpus() as u64,
        mem_total: proc.meminfo("MemTotal"),
        mem_free: proc.meminfo("MemFree"),
        mem_available: proc.meminfo("MemAvailable"),
        swap_total: proc.meminfo("SwapTotal"),
        swap_free: proc.meminfo("SwapFree"),
        uptime_ns: proc.uptime_ns(),
        cgroup_manager: match cfg.server.cgroup_manager {
            velarx_config::CgroupDriver::Systemd => CgroupManager::Systemd,
            velarx_config::CgroupDriver::Cgroupfs => CgroupManager::Cgroupfs,
        },
        cgroup_version: 2,
        cgroup_controllers: cgroup_controllers(state).await?,
        cpu_utilization: proc.cpu_utilization(),
        emulated_architectures: emulated_architectures().await,
        uid_mappings: id_mappings(&proc.uid_map)?,
        gid_mappings: id_mappings(&proc.gid_map)?,
        rootless: rootless()?,
        selinux: velarx_runtime::container::selinux::enabled(),
        event_logger: state.podman.events.logger_name().to_string(),
        log_driver: cfg.containers.effective_log_driver().to_string(),
        monitor_path: velarx_base::spawn::binary().to_string_lossy().to_string(),
        engine_path: std::env::current_exe()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_default(),
        cdi_spec_dirs: server.cdi.spec_dirs,
        cdi_devices: server.cdi.devices,
        cdi_errors: server.cdi.errors,
        pasta: host_tool("pasta").await,
        slirp4netns: host_tool("slirp4netns").await,
        oci_runtime: OciRuntimeRecord {
            name: rt_name,
            path: rt_path,
            package: host_tool("crun").await.package,
            version: rt_version.clone(),
            features: rt_features.clone(),
        },
        runtimes,
        fuse_passthrough: server.fuse_passthrough,
        userns: server.userns_support,
        systemd: server.systemd.map(|s| SystemdRecord {
            user_manager: s.user_manager,
            linger: s.linger,
            warning: s.warning.unwrap_or_default(),
        }),
    };
    Ok(SystemRecord {
        version: version_record().await,
        host,
        store,
        search_registries: state.image_service.search_registries(),
        subnet_pools: cfg
            .network
            .subnet_pools
            .iter()
            .map(|p| SubnetPool {
                base: p.base.clone(),
                size: u64::from(p.size),
            })
            .collect(),
    })
}

/// Size of the regular files under `path`, on its file system, without
/// following symbolic links (as containers/storage's directory.Size: the
/// entries of the directories count too).
pub(super) fn dir_usage(path: &std::path::Path) -> i64 {
    velarx_base::tree::usage(
        path,
        &velarx_base::tree::Measure {
            one_fs: true,
            listed_depth: Some(32),
            lenient: true,
        },
    )
    .map_or(0, |u| {
        i64::try_from(u.file_bytes.saturating_add(u.dir_bytes)).unwrap_or(i64::MAX)
    })
}

pub(crate) struct Df {
    containers: Vec<ContainerRecord>,
    images: Vec<(velarx_db::ImageRecord, i64, Vec<String>)>,
    volumes: Vec<velarx_core::services::Volume>,
    /// The layers of each image (by its id): digest and size, and the
    /// size of its own metadata (manifest, configuration).
    layers: HashMap<String, (i64, Vec<(String, i64)>)>,
    /// What each container wrote (its upper directory), by its id.
    rw: HashMap<String, i64>,
    /// podman's state of each container (`exited`, not the record's
    /// `stopped`), by its id.
    states: HashMap<String, velarx_proto::workload::RunState>,
}

impl Df {
    /// The size of an image that no other image shares (podman's
    /// UniqueSize): its metadata and the layers only it has.
    fn unique_size(&self, id: &str) -> i64 {
        let Some((meta, layers)) = self.layers.get(id) else {
            return 0;
        };
        let shared = |digest: &str| {
            self.layers
                .iter()
                .any(|(other, (_, l))| other != id && l.iter().any(|(d, _)| d == digest))
        };
        meta + layers
            .iter()
            .filter(|(d, _)| !shared(d))
            .map(|(_, n)| n)
            .sum::<i64>()
    }

    /// The size of all the images, a layer they share counted once
    /// (podman's ImagesSize, the "raw" size).
    fn images_size(&self) -> i64 {
        let mut seen = std::collections::HashSet::new();
        let mut total = 0;
        for (meta, layers) in self.layers.values() {
            total += meta;
            for (d, n) in layers {
                if seen.insert(d.clone()) {
                    total += n;
                }
            }
        }
        total
    }

    fn rw_size(&self, id: &str) -> i64 {
        self.rw.get(id).copied().unwrap_or(0)
    }
}

fn mounted_volumes(c: &ContainerRecord) -> Vec<String> {
    serde_json::from_str::<velarx_runtime::container::ContainerConfig>(&c.config)
        .map(|cfg| {
            cfg.mounts
                .iter()
                .filter(|m| m.mount_type.as_deref() == Some("volume") || m.volume.is_some())
                .map(|m| m.volume.clone().unwrap_or_else(|| m.source.clone()))
                .collect()
        })
        .unwrap_or_default()
}

async fn df_collect(state: &AppState) -> ApiResult<Df> {
    let mut containers = state.db.list_containers(true).await?;
    // (podman's: the oldest first)
    containers.sort_by_key(|c| convert::record_time_ns(&c.created_at));
    let mut states = HashMap::new();
    for c in &containers {
        states.insert(c.id.clone(), super::lifecycle::status(state, c).await.state);
    }
    let mut images = Vec::new();
    let mut by_image = HashMap::new();
    for rec in state.image_service.list().await? {
        // (an image removed since the list is left out)
        let Some(rows) = super::images::Rows::read(&state.db, &rec)
            .await
            .map_err(|e| ApiError::internal(format!("computing the disk usage: {}", e.message)))?
        else {
            continue;
        };
        let layers = rows.layers;
        let meta = i64::try_from(rec.metadata_size()).unwrap_or(i64::MAX);
        let mut size = meta;
        let mut sized = Vec::new();
        for l in &layers {
            let n = super::images::layer_size(l)?;
            size += n;
            sized.push((l.key.to_string(), n));
        }
        by_image.insert(rec.id.clone(), (meta, sized));
        let names = rows.names;
        images.push((rec, size, names));
    }
    let volumes = state.volume_service.list().await?;
    let mut rw = HashMap::new();
    for c in &containers {
        let upper = state.container_service.writable_paths(&c.id).upper;
        rw.insert(
            c.id.clone(),
            tokio::task::spawn_blocking(move || dir_usage(&upper))
                .await
                .map_err(|e| {
                    ApiError::internal(format!("computing the disk usage (a container): {e}"))
                })?,
        );
    }
    Ok(Df {
        containers,
        images,
        volumes,
        layers: by_image,
        rw,
        states,
    })
}

fn container_name(c: &ContainerRecord) -> String {
    c.name
        .clone()
        .unwrap_or_else(|| c.id.chars().take(12).collect())
}

fn image_users(df: &Df, rec: &velarx_db::ImageRecord) -> usize {
    df.containers
        .iter()
        .filter(|c| c.image_id == rec.id)
        .count()
}

fn volume_links(df: &Df, name: &str) -> usize {
    df.containers
        .iter()
        .filter(|c| mounted_volumes(c).iter().any(|v| v == name))
        .count()
}

/// The command of a container as `df` lists it: its command, without the
/// entrypoint (podman's `ctr.Command()`).
fn command_of(c: &velarx_db::ContainerRecord) -> ApiResult<Vec<String>> {
    super::lifecycle::config_of(c)
        .map(|cfg| cfg.command)
        .map_err(|e| e.in_context(format!("container {}", c.id)))
}

impl Df {
    /// What removing the images no container uses frees: their metadata
    /// and the layers no used image has, each counted once.
    fn reclaimable_images(&self) -> i64 {
        let mut keep = std::collections::HashSet::new();
        for (rec, _, _) in &self.images {
            if image_users(self, rec) > 0 {
                if let Some((_, layers)) = self.layers.get(&rec.id) {
                    keep.extend(layers.iter().map(|(d, _)| d.clone()));
                }
            }
        }
        let mut total = 0;
        for (rec, _, _) in &self.images {
            if image_users(self, rec) > 0 {
                continue;
            }
            let Some((meta, layers)) = self.layers.get(&rec.id) else {
                continue;
            };
            total += meta;
            for (d, n) in layers {
                if keep.insert(d.clone()) {
                    total += n;
                }
            }
        }
        total
    }
}

/// When the image was made (its configuration says), else when it was
/// stored.
fn image_created_ns(rec: &velarx_db::ImageRecord) -> i64 {
    serde_json::from_str::<Value>(&rec.config)
        .ok()
        .and_then(|c| c["created"].as_str().map(convert::record_time_ns))
        .filter(|ns| *ns > 0)
        .unwrap_or_else(|| convert::record_time_ns(&rec.created_at))
}

/// What the images, the containers and the volumes use of the disk
/// (`DiskUsageInspect`); with `store`, the files of the store too: the
/// objects (and what a collection would free of them now) and the
/// composefs images.
pub(crate) async fn disk_usage(state: &AppState, store: bool) -> ApiResult<DiskUsageRecord> {
    let d = df_collect(state).await?;
    let size = |v: i64| v.max(0) as u64;
    // the walks of the volume mountpoints, in one turn of the blocking pool
    let mountpoints: Vec<std::path::PathBuf> =
        d.volumes.iter().map(|v| v.mountpoint.clone()).collect();
    let volume_sizes = tokio::task::spawn_blocking(move || {
        mountpoints
            .iter()
            .map(|p| dir_usage(p))
            .collect::<Vec<i64>>()
    })
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?;
    let images = d
        .images
        .iter()
        .map(|(rec, n, names)| ImageUsage {
            id: image_id(rec),
            names: names.clone(),
            digests: names
                .iter()
                .map(|n| super::images::repo_digest(n, &rec.manifest_digest.to_string()))
                .collect(),
            created_ns: image_created_ns(rec),
            size: size(*n),
            unique_size: size(d.unique_size(&rec.id)),
            containers: image_users(&d, rec) as u64,
        })
        .collect();
    let containers = d
        .containers
        .iter()
        .map(|c| {
            let image = d.images.iter().find(|(r, _, _)| r.id == c.image_id);
            Ok(ContainerUsage {
                id: c.id.clone(),
                name: container_name(c),
                image_id: image.map_or_else(|| c.image_id.clone(), |(r, _, _)| image_id(r)),
                command: command_of(c)?,
                volumes: mounted_volumes(c).len() as u64,
                rw_size: size(d.rw_size(&c.id)),
                size: size(image.map_or(0, |(_, s, _)| *s) + d.rw_size(&c.id)),
                created_ns: convert::record_time_ns(&c.created_at),
                state: d
                    .states
                    .get(&c.id)
                    .copied()
                    .unwrap_or_else(|| super::cinfo::run_state_of(c.state)),
            })
        })
        .collect::<ApiResult<Vec<_>>>()?;
    let volumes = d
        .volumes
        .iter()
        .enumerate()
        .map(|(n, v)| VolumeUsage {
            name: v.name.clone(),
            mountpoint: v.mountpoint.to_string_lossy().to_string(),
            created_ns: convert::record_time_ns(&v.created_at),
            labels: v.labels.clone().into_iter().collect(),
            links: volume_links(&d, &v.name) as u64,
            size: size(volume_sizes[n]),
        })
        .collect();
    let (objects, composefs, pulling) = if store {
        let driver = state.image_service.storage().clone();
        let files = state.image_service.file_store().root().to_path_buf();
        let (objects, composefs) = tokio::task::spawn_blocking(move || {
            driver.usage().map(|usage| {
                (
                    velarx_core::storage_driver::objects::files_usage(&files),
                    usage.artifacts,
                )
            })
        })
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?
        .map_err(|e| ApiError::internal(e.to_string()))?;
        // what a collection would free now, if nothing holds the store
        let freed = collector(state)?
            .collect(velarx_core::services::GcOptions {
                dry_run: true,
                wait: false,
                ..Default::default()
            })
            .await
            .ok()
            .filter(|r| !r.skipped)
            .map(|r| r.bytes_freed);
        // the pulls in progress: the staging area of lazy pulls (a pull
        // that was cancelled goes with the next collection)
        let area = state.image_service.staging_area();
        let pulling = tokio::task::spawn_blocking(move || {
            let pulls = area.pulls();
            let cancelled = |p: &velarx_content::pull::staged::PullEntry| {
                p.state.state == velarx_content::pull::staged::PullState::Cancelled
            };
            let live = pulls.iter().filter(|p| !cancelled(p)).count() as u64;
            let size = velarx_core::storage_driver::objects::files_usage(area.root()).1;
            StoreUsage {
                count: live,
                size,
                // (what a cancelled pull fetched is in the pool, which the
                // pulls share: all of it is reclaimable only when no pull
                // is left that is not cancelled)
                reclaimable: Some(if live == 0 { size } else { 0 }),
            }
        })
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;
        (
            Some(StoreUsage {
                count: objects.0,
                size: objects.1,
                reclaimable: freed,
            }),
            Some(StoreUsage {
                count: composefs.0,
                size: composefs.1,
                reclaimable: None,
            }),
            Some(pulling),
        )
    } else {
        (None, None, None)
    };
    Ok(DiskUsageRecord {
        driver: state.image_service.storage().name().to_string(),
        images,
        containers,
        volumes,
        images_size: size(d.images_size()),
        images_reclaimable: size(d.reclaimable_images()),
        objects,
        composefs,
        pulling,
    })
}

/// What a system prune removed.
#[derive(Default)]
struct Pruned {
    pods: Vec<String>,
    containers: Vec<String>,
    networks: Vec<String>,
    /// Name and size.
    volumes: Vec<(String, i64)>,
    /// Id and size.
    images: Vec<(String, i64)>,
    /// The bytes of the volumes and of the writable layers of the containers
    /// removed, and what the removal of each image freed.
    reclaimed: i64,
}

/// The pods, containers, networks, volumes (with `with_volumes`) and images
/// (`all`: the unused ones too) that are not in use, removed; then the
/// garbage of the store is collected: what no image references any more and
/// the leftovers of pulls that died.
async fn prune_unused(
    state: &std::sync::Arc<AppState>,
    all: bool,
    with_volumes: bool,
    build: bool,
    filters: &Filters,
) -> ApiResult<Pruned> {
    // (before anything is removed)
    if let Some(k) = filters
        .keys()
        .find(|k| !matches!(*k, "label" | "label!" | "until"))
    {
        return Err(ApiError::bad_request(format!("invalid filter {k:?}")));
    }
    filters.check_prune_until()?;
    // the pods none of whose containers runs, as `pod prune` removes them:
    // by what their containers are, under the operation lock of the pod
    // (not by the state a start recorded, which a start or stop running
    // meanwhile has not settled yet)
    let mut out = Pruned {
        pods: super::pods::prune_of(state).await?,
        ..Default::default()
    };

    // (podman's --build: the containers of builds that are gone, whatever
    // their state)
    if build {
        out.containers = state
            .build_service
            .prune_containers()
            .await
            .map_err(|e| ApiError::internal(e.to_string()))?;
    }
    let (containers, written) = super::containers::prune_of(state, filters).await?;
    out.containers.extend(containers);
    out.reclaimed = out
        .reclaimed
        .saturating_add(i64::try_from(written).unwrap_or(i64::MAX));

    out.networks = super::networks::prune_of(state, filters).await?;

    // (the holder of a rootless bridge namespace whose last container went
    // without its cleanup)
    state
        .network_service
        .engine()
        .release_rootless_netns_if_unused()
        .await;

    if with_volumes {
        for (name, size) in super::volumes::prune_of(state, filters, false).await? {
            out.reclaimed = out.reclaimed.saturating_add(size);
            out.volumes.push((name, size));
        }
    }

    let image_filters = filters.image_prune()?;
    // (what each removal freed: its record and the layers it released)
    for (id, freed) in state.image_service.prune(all, &image_filters).await? {
        let freed = i64::try_from(freed).unwrap_or(i64::MAX);
        out.reclaimed = out.reclaimed.saturating_add(freed);
        out.images.push((id, freed));
    }
    Ok(out)
}

/// The garbage collector of the store of the daemon.
fn collector(state: &AppState) -> ApiResult<velarx_core::services::GcService> {
    let files = state
        .config
        .storage
        .file_store()
        .map_err(|e| ApiError::internal(format!("cannot open the file store: {e}")))?;
    Ok(velarx_core::services::GcService::new(
        state.db.clone(),
        std::sync::Arc::new(files),
        &state.config.storage,
        state.image_service.storage().clone(),
    ))
}

/// `SystemPrune`: what is not in use removed, then the garbage of the
/// store collected.
pub(crate) async fn prune_of(
    state: &Arc<AppState>,
    all: bool,
    with_volumes: bool,
    build: bool,
    filters: &Filters,
) -> ApiResult<SystemPruneReport> {
    let out = prune_unused(state, all, with_volumes, build, filters).await?;
    let collector = collector(state)?;
    let gc = collector
        .collect(velarx_core::services::GcOptions::default())
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;
    state.image_service.forget_collected(&gc).await;
    // (the layers the collection released that the removal of an image had
    // to leave, a pull held them: each layer is released once, so it is
    // counted once, here or by the removal)
    let reclaimed = out
        .reclaimed
        .saturating_add(i64::try_from(gc.layers_size).unwrap_or(i64::MAX));
    // Everything removed, with nothing selected: the storage service of the
    // `varlink` driver drops the store (`system reset` does not exist: this is
    // the command that removes it all, after which the graph root is deleted
    // by hand).
    if all
        && with_volumes
        && filters.0.is_empty()
        && state.config.storage.driver_kind() == velarx_config::StorageDriverKind::Varlink
    {
        let id = velarx_core::storage_driver::StoreId::of_root(&state.config.storage.root)
            .map_err(|e| ApiError::internal(format!("the id of the store: {e}")))?;
        if collector.drop_emptied_store(&id).await.map_err(|e| {
            ApiError::internal(format!("the storage service keeps the store {id}: {e}"))
        })? {
            tracing::info!("The storage service dropped the store {id}");
        }
    }
    let size = |v: i64| v.max(0) as u64;
    Ok(SystemPruneReport {
        pods: out.pods,
        containers: out.containers,
        networks: out.networks,
        volumes: out
            .volumes
            .into_iter()
            .map(|(name, n)| PrunedVolume {
                name,
                size: size(n),
            })
            .collect(),
        images: out
            .images
            .into_iter()
            .map(|(id, n)| velarx_proto::workload::PrunedImage {
                id: convert::strip_sha256(&id).to_string(),
                size: size(n),
            })
            .collect(),
        reclaimed: size(reclaimed),
    })
}

/// The checker of the store; `grace` is how long a leftover must be
/// unchanged to be taken for one (the configuration's by default).
fn checker(
    state: &AppState,
    grace: Option<std::time::Duration>,
) -> ApiResult<velarx_core::services::CheckService> {
    let files = state
        .config
        .storage
        .file_store()
        .map_err(|e| ApiError::internal(format!("cannot open the file store: {e}")))?;
    Ok(velarx_core::services::CheckService::new(
        state.db.clone(),
        state.image_service.clone(),
        std::sync::Arc::new(files),
        state.config.storage.staging_dir(),
    )
    .with_grace(grace.unwrap_or(std::time::Duration::from_secs(
        state.config.storage.check_leftover_age_secs,
    )))
    .with_containers(state.container_service.clone()))
}

/// `SystemCheck`: the checker takes the lock of the store it needs.
pub(crate) async fn check_of(state: &AppState, spec: &CheckSpec) -> ApiResult<CheckReport> {
    let checker = checker(state, spec.max_age_ms.map(std::time::Duration::from_millis))?;
    let report = checker
        .check(spec)
        .await
        .map_err(|e| ApiError::internal(format!("Check failed: {e}")))?;
    if spec.repair {
        // (a holder of the rootless bridge namespace that nothing uses)
        state
            .network_service
            .engine()
            .release_rootless_netns_if_unused()
            .await;
    }
    Ok(report)
}

/// `SystemCollect`: collect what the store keeps for nothing.
pub(crate) async fn collect_of(
    state: &AppState,
    dry_run: bool,
    files: bool,
    layers: bool,
) -> ApiResult<GcReport> {
    use velarx_core::services::GcOptions;
    let options = GcOptions {
        dry_run,
        collect_files: files,
        collect_layers: layers,
        wait: true,
    };
    let report = collector(state)?
        .collect(options)
        .await
        .map_err(|e| ApiError::internal(format!("Garbage collection failed: {e}")))?;
    state.image_service.forget_collected(&report).await;
    Ok(GcReport {
        files_removed: report.files_removed as u64,
        layers_removed: report.layers_removed as u64,
        leases_removed: report.leases_removed as u64,
        staging_removed: report.staging_removed as u64,
        bytes_freed: report.bytes_freed,
        errors: report.errors,
        dry_run,
    })
}

/// `SystemStores`: the stores the storage service holds for the engine's
/// user, after `drop` (a store that is not this engine's) was dropped.
pub(crate) async fn stores_of(state: &AppState, drop: Option<&str>) -> ApiResult<StoresReport> {
    if state.config.storage.driver_kind() != velarx_config::StorageDriverKind::Varlink {
        return Err(ApiError::not_implemented(
            "the storage driver keeps one store: only [storage] driver = \"varlink\" has a service with several",
        ));
    }
    // (the id the engine opened its store with, read and never made here: a
    // listing must not make a new id, and with the file gone the store of
    // this engine cannot be told from the others, so nothing is dropped)
    let own = velarx_core::storage_driver::StoreId::of_root_as_made(&state.config.storage.root);
    let collector = collector(state)?;
    if let Some(id) = drop {
        let own = own.as_ref().map_err(|e| {
            ApiError::internal(format!(
                "cannot drop the store {id}: the id of the store of this engine is not known ({}: {e})",
                velarx_core::storage_driver::StoreId::path(&state.config.storage.root).display()
            ))
        })?;
        collector
            .drop_other_store(own, id)
            .await
            .map_err(|e| ApiError::internal(format!("cannot drop the store {id}: {e}")))?;
    }
    let mut stores: Vec<ServiceStore> = collector
        .stores()
        .await
        .map_err(|e| ApiError::internal(format!("cannot list the stores: {e}")))?
        .into_iter()
        .map(|s| ServiceStore {
            current: own.as_ref().is_ok_and(|o| s.store == o.as_str()),
            store: s.store,
            size: s.bytes,
            last_open_ns: s.last_open.map_or(0, |t| t.saturating_mul(1_000_000_000)),
        })
        .collect();
    stores.sort_by(|a, b| a.store.cmp(&b.store));
    Ok(StoresReport {
        stores,
        dropped: drop.map(str::to_string),
    })
}

/// Log in to the registry at `host`: the requests and the answers of the
/// registry are in a confined pull worker when the pulls are confined.  The
/// failure is what the registry (or the connection) said.
pub(crate) async fn login_of(
    state: &AppState,
    host: &str,
    access: &velarx_registry::auth::RegistryAccess,
) -> velarx_types::ImageResult<()> {
    state.image_service.login(host, access).await
}

#[cfg(test)]
mod df_tests {
    use super::*;

    #[test]
    fn the_size_of_a_directory_counts_its_files_and_entries_not_beyond_a_depth() {
        let d = tempfile::tempdir().unwrap();
        let mut deep = d.path().to_path_buf();
        std::fs::write(deep.join("f"), "12345").unwrap();
        std::os::unix::fs::symlink("/", deep.join("l")).unwrap();
        for i in 1..=34 {
            deep.push("d");
            std::fs::create_dir(&deep).unwrap();
            // (the directories below the 32nd are not listed)
            let size = if i >= 33 { 1 << 20 } else { 1 };
            std::fs::write(deep.join("f"), vec![0u8; size]).unwrap();
        }
        let used = dir_usage(d.path());
        assert!((5 + 32..1 << 20).contains(&used), "{used}");
        assert_eq!(dir_usage(&d.path().join("nothing")), 0);
    }

    /// A store whose layers lack a column fails the disk usage: no image
    /// shown with the size of its manifest and configuration alone.
    #[tokio::test]
    async fn a_store_of_another_shape_fails_the_disk_usage() {
        use crate::api::podman::test_store;
        let dir = tempfile::tempdir().unwrap();
        let state = test_store::state_in(dir.path()).await;
        test_store::image(&state, "img-a").await;
        assert_eq!(df_collect(&state).await.unwrap().images.len(), 1);
        test_store::alter(&state, "ALTER TABLE layers DROP COLUMN diff_id_other");
        let Err(e) = df_collect(&state).await else {
            panic!("the disk usage of a store of another shape must fail");
        };
        assert!(
            e.message
                .starts_with("computing the disk usage: reading an image (its layers)"),
            "{}",
            e.message
        );
    }

    /// A container whose configuration cannot be read is not left out of the
    /// disk usage, nor shown without its command.
    #[tokio::test]
    async fn a_container_that_cannot_be_read_fails_the_disk_usage_naming_it() {
        use crate::api::podman::test_store;
        let dir = tempfile::tempdir().unwrap();
        let state = test_store::state_in(dir.path()).await;
        test_store::image(&state, "img-a").await;
        test_store::container(&state, "c9", "img-a", "not json").await;
        let Err(e) = disk_usage(&state, false).await else {
            panic!("a container that cannot be read must fail the disk usage");
        };
        assert!(e.message.starts_with("container c9: "), "{}", e.message);
    }

    #[test]
    fn shared_layers_count_once() {
        let l = |d: &str, n: i64| (d.to_string(), n);
        let d = Df {
            containers: Vec::new(),
            images: Vec::new(),
            volumes: Vec::new(),
            layers: HashMap::from([
                ("base".to_string(), (10, vec![l("a", 1000)])),
                ("child".to_string(), (20, vec![l("a", 1000), l("b", 300)])),
            ]),
            rw: HashMap::from([("c1".to_string(), 7)]),
            states: HashMap::new(),
        };
        // the base has nothing of its own but its metadata
        assert_eq!(d.unique_size("base"), 10);
        assert_eq!(d.unique_size("child"), 320);
        assert_eq!(d.unique_size("nosuch"), 0);
        assert_eq!(d.images_size(), 10 + 20 + 1000 + 300);
        assert_eq!((d.rw_size("c1"), d.rw_size("c2")), (7, 0));
    }
}
