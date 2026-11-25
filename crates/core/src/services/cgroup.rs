// SPDX-License-Identifier: Apache-2.0
use super::container::valid_container_id;
use std::collections::HashMap;
use std::fs;
use std::io::{self};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use thiserror::Error;
use tracing::{debug, info};
use velarx_base::spawn::DAEMON_CGROUP;
use velarx_limit_core::{
    cpu_max, io_weight_of_blkio, limit_of, swap_max, weight_of_shares, CpuMax, Limit, Swap,
};
use velarx_proto::pod::PodResources;

#[derive(Error, Debug)]
pub enum CgroupError {
    #[error("IO error: {0}")]
    Io(#[from] io::Error),
    #[error("cgroup not found: {0}")]
    NotFound(String),
    #[error("{0}")]
    NotV2(String),
    #[error("invalid cgroup path: {0}")]
    InvalidPath(String),
}

pub type CgroupResult<T> = Result<T, CgroupError>;

/// The leaf of a container cgroup with the container's processes (the
/// runtime makes it); its monitor is in [`RUNTIME_CGROUP`] next to it.
pub const CONTAINER_CGROUP: &str = "container";

/// The leaf of a container cgroup with the processes of its monitor (the
/// runtime side of it, as the `runtime` of a command's split cgroup).
pub const RUNTIME_CGROUP: &str = "runtime";

/// Cgroup manager for container resource isolation (`cgroup_manager =
/// "cgroupfs"`, the default of the server): the layout of `--cgroups=split`,
/// the default of the server
///
/// # Cgroup Layout
///
/// ```text
/// $PARENT_CGROUP/              # the daemon's cgroup (Delegate=yes of its unit)
/// ├── engine/                  # the daemon (isolated from the containers)
/// ├── pulls/<id>/              # the pull workers (crates/registry-lib/src/net/cgroup.rs)
/// ├── $CTR_ID/                 # a standalone container (full 64-char SHA256 ID)
/// │   ├── runtime/             # its velarx-monitor
/// │   └── container/           # its processes, where the runtime applies the limits
/// └── $POD_ID/                 # a pod
///     └── $CTR_ID/             # a container of the pod (infra container too)
///         ├── runtime/
///         └── container/
/// ```
///
/// A cgroup whose controllers are enabled for its children has no process of
/// its own (cgroup v2, "no internal processes"): that is why the daemon
/// leaves `$PARENT_CGROUP` for `engine/`, and why a container has its
/// monitor and its processes in leaves, `$CTR_ID` giving them the controllers.
/// `systemctl status` of the unit shows all of it, with the accounting of the
/// whole unit at the top and of each container at `$CTR_ID`.
///
/// # How It Works
///
/// 1. On startup, the daemon reads its current cgroup from `/proc/self/cgroup`
/// 2. If already in the daemon's subcgroup (from restart), it uses the parent
/// 3. Creates `$PARENT_CGROUP/engine/` and moves the daemon process there
/// 4. Containers are created as siblings: `$PARENT_CGROUP/$CONTAINER_ID/`
/// 5. The OCI runtime (crun) receives the cgroup path relative to
///    `/sys/fs/cgroup`, `.../$CTR_ID/container`: the limits are its
/// 6. The monitor is started INTO `$CTR_ID/runtime` (`clone3`), the empty
///    directories go with the container, and at the start of the daemon
///
/// # Controller Delegation
///
/// The parent cgroup must have controller delegation enabled (e.g., via systemd's
/// `Delegate=yes` or by running in a scope with `delegate` property). The daemon
/// enables controllers (`+cpu +cpuset +memory +io +pids`) in the subtree control
/// file for resource management.
pub struct CgroupManager {
    /// Base path for cgroup v2 unified hierarchy (/sys/fs/cgroup)
    base_path: PathBuf,
    /// The parent cgroup path (where daemon, containers, and pods are siblings)
    /// This is the cgroup path we were in when we started, before moving to engine/
    parent_cgroup: PathBuf,
    /// The relative path from cgroup root (for OCI spec cgroupsPath)
    parent_cgroup_relative: String,
    /// Held while cgroups are made or removed: a start and the removal of a
    /// pod do not meet.
    starts: Mutex<()>,
    /// The limits of the cgroups of the pods that have any, by pod id: the
    /// cgroup of a pod goes when its last container's does, and is made
    /// again with its limits by the next start of a member.
    pods: Mutex<HashMap<String, PodResources>>,
}

/// The cgroup the daemon manages, from the cgroup `raw` it is in
/// (`/proc/self/cgroup`, `0::/...`): the daemon's own subcgroup of a
/// previous run is left.  Relative to the hierarchy, no leading slash.
fn managed_cgroup(raw: &str) -> &str {
    let rel = raw.trim().trim_start_matches('/');
    match rel.strip_suffix(DAEMON_CGROUP) {
        Some(p) if p.is_empty() || p.ends_with('/') => p.trim_end_matches('/'),
        _ => rel,
    }
}

/// Write `value` to the file `name` of the cgroup `dir`.  A file the cgroup
/// does not have (its controller is not enabled) is an error unless the
/// value is the default `reset` it has anyway.
fn write_limit(dir: &Path, name: &str, value: &str, reset: &str) -> io::Result<()> {
    use std::io::Write;
    // (the file is the cgroup's: one that is not there is not made)
    let written = fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(dir.join(name))
        .and_then(|mut f| f.write_all(format!("{value}\n").as_bytes()));
    match written {
        Err(e) if e.kind() == io::ErrorKind::NotFound && value == reset => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Err(io::Error::other(format!(
            "{name} cannot be set: the cgroup {} has no such controller",
            dir.display()
        ))),
        Err(e) => Err(io::Error::new(
            e.kind(),
            format!("set {name} of {}: {e}", dir.display()),
        )),
        Ok(()) => Ok(()),
    }
}

/// The error of a limit that is no limit (a pod's are checked when it is
/// made, so a record that has one is damaged).
fn invalid_limit(what: &str, value: i64) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        format!("the {what} limit {value} of the pod is not one"),
    )
}

/// Write the limits of a pod to its cgroup `dir`; what is not set is the
/// default of the cgroup (no limit).
fn write_pod_limits(dir: &Path, l: &PodResources) -> io::Result<()> {
    let (memory, swap) = (l.memory.unwrap_or(0), l.memory_swap.unwrap_or(0));
    let memory_max = match limit_of(memory) {
        Limit::Bytes(m) => m.to_string(),
        Limit::Unset | Limit::Unlimited => "max".to_string(),
        Limit::Invalid => return Err(invalid_limit("memory", memory)),
    };
    // (the OCI limit counts memory and swap together, cgroup v2's only the
    // swap)
    let swap_max = match swap_max(memory, swap) {
        Swap::Unlimited => "max".to_string(),
        Swap::Max(s) => s.to_string(),
        Swap::Invalid => return Err(invalid_limit("memory and swap", swap)),
    };
    write_limit(dir, "memory.max", &memory_max, "max")?;
    write_limit(dir, "memory.swap.max", &swap_max, "max")?;
    let weight = match weight_of_shares(l.cpu_shares.unwrap_or(0)) {
        0 => 100,
        w => w,
    };
    write_limit(dir, "cpu.weight", &weight.to_string(), "100")?;
    let quota = l.cpu_quota.unwrap_or(0);
    let max = match cpu_max(quota, l.cpu_period.unwrap_or(0)) {
        CpuMax::Quota { quota, period } => format!("{quota} {period}"),
        CpuMax::Unlimited => "max 100000".to_string(),
        CpuMax::Invalid => return Err(invalid_limit("CPU quota", quota)),
    };
    write_limit(dir, "cpu.max", &max, "max 100000")?;
    write_limit(
        dir,
        "cpuset.cpus",
        l.cpuset_cpus.as_deref().unwrap_or(""),
        "",
    )?;
    write_limit(
        dir,
        "cpuset.mems",
        l.cpuset_mems.as_deref().unwrap_or(""),
        "",
    )?;
    write_io_limits(dir, l)
}

/// The block IO files of the cgroup `dir`: what is set there goes first
/// (the weights and rates of devices an earlier call set), then the limits
/// are written as podman's runtime does: the weight to `io.bfq.weight` when
/// the cgroup has it (else a converted one to `io.weight`), the rates to
/// `io.max`.
fn write_io_limits(dir: &Path, l: &PodResources) -> io::Result<()> {
    // the devices a file has a line for (`MAJOR:MINOR value...`) get the
    // default back
    let reset = |name: &str, default: &str| -> io::Result<()> {
        let text = fs::read_to_string(dir.join(name)).unwrap_or_default();
        for line in text.lines().filter(|l| !l.starts_with("default")) {
            if let Some((dev, _)) = line.split_once(' ').filter(|(_, v)| v.trim() != default) {
                let text = format!("{dev} {default}");
                write_limit(dir, name, &text, &text)?;
            }
        }
        Ok(())
    };
    reset("io.max", "rbps=max wbps=max riops=max wiops=max")?;
    reset("io.weight", "default")?;
    reset("io.bfq.weight", "default")?;
    let bfq = dir.join("io.bfq.weight").exists();
    let weight = l.blkio_weight.filter(|w| *w > 0);
    // (the default weight of the file that is not used is back at 100)
    for (file, w) in [
        (
            "io.weight",
            weight
                .filter(|_| !bfq)
                .map(|w| io_weight_of_blkio(u64::from(w))),
        ),
        ("io.bfq.weight", weight.filter(|_| bfq).map(u64::from)),
    ] {
        let w = w.unwrap_or(100);
        write_limit(dir, file, &format!("default {w}"), "default 100")?;
    }
    for d in l.blkio_weight_device.iter().filter(|d| d.value > 0) {
        let (file, w) = if bfq {
            ("io.bfq.weight", d.value)
        } else {
            ("io.weight", io_weight_of_blkio(d.value))
        };
        write_limit(dir, file, &format!("{}:{} {w}", d.major, d.minor), "").map_err(|e| {
            if e.kind() == io::ErrorKind::Unsupported {
                io::Error::other(format!(
                    "the weight of the device {}:{} needs its I/O scheduler to be BFQ: {e}",
                    d.major, d.minor
                ))
            } else {
                e
            }
        })?;
    }
    for (key, list) in [("rbps", &l.device_read_bps), ("wbps", &l.device_write_bps)] {
        for d in list.iter().filter(|d| d.value > 0) {
            let line = format!("{}:{} {key}={}", d.major, d.minor, d.value);
            write_limit(dir, "io.max", &line, "")?;
        }
    }
    Ok(())
}

impl CgroupManager {
    /// Create a new cgroup manager
    ///
    /// This reads the current cgroup from /proc/self/cgroup and uses it as the parent.
    /// Call `init_daemon_cgroup()` to create the daemon subcgroup and move the process there.
    pub fn new() -> CgroupResult<Self> {
        let base_path = PathBuf::from("/sys/fs/cgroup");

        velarx_base::cgroup::require_v2().map_err(CgroupError::NotV2)?;

        let (parent_cgroup, parent_cgroup_relative) = Self::get_current_cgroup(&base_path)?;

        info!(
            "CgroupManager::new() - parent_cgroup={:?}, parent_cgroup_relative={}",
            parent_cgroup, parent_cgroup_relative
        );

        Ok(Self {
            base_path,
            parent_cgroup,
            parent_cgroup_relative,
            starts: Mutex::default(),
            pods: Mutex::default(),
        })
    }

    /// The cgroup that is managed, from /proc/self/cgroup: if the daemon is
    /// already in its subcgroup (a previous run), its parent, so that the
    /// containers are created as siblings.
    fn get_current_cgroup(base_path: &Path) -> CgroupResult<(PathBuf, String)> {
        let raw = velarx_base::cgroup::of_process(None)?;
        let rel = managed_cgroup(&raw);
        info!("The daemon is in the cgroup '{raw}', manages '{rel}'");
        Ok(if rel.is_empty() {
            (base_path.to_path_buf(), "/".to_string())
        } else {
            (base_path.join(rel), format!("/{rel}"))
        })
    }

    /// Initialize the daemon cgroup and move the current process there
    ///
    /// Creates $CURRENT_CGROUP/engine/ and moves the current process to it.
    /// This ensures the daemon runs in its own cgroup, separate from containers.
    pub fn init_daemon_cgroup(&mut self) -> CgroupResult<()> {
        let daemon_cgroup = self.parent_cgroup.join(DAEMON_CGROUP);

        info!(
            "Initializing daemon cgroup: parent={:?}, parent_relative={}, daemon_cgroup={:?}",
            self.parent_cgroup, self.parent_cgroup_relative, daemon_cgroup
        );

        if !daemon_cgroup.exists() {
            fs::create_dir_all(&daemon_cgroup)?;
            debug!("Created daemon cgroup at {:?}", daemon_cgroup);
        }

        // First: `subtree_control` cannot change while the cgroup has processes.
        let procs_file = daemon_cgroup.join("cgroup.procs");
        let pid = std::process::id();
        fs::write(&procs_file, pid.to_string())?;
        info!("Moved daemon process (PID {}) to {:?}", pid, daemon_cgroup);

        self.enable_controllers(&self.parent_cgroup)?;

        info!(
            "Container cgroups will be created under {}",
            self.parent_cgroup_relative
        );
        self.sweep();

        Ok(())
    }

    /// The cgroup path of a container for the OCI spec (`linux.cgroupsPath`),
    /// relative to /sys/fs/cgroup: `<parent>/[<pod>/]<id>/container`.  The
    /// parent is the cgroup of the daemon, or the `--cgroup-parent` (an
    /// absolute path, checked by the caller).
    pub fn container_cgroup_path(
        &self,
        parent: Option<&str>,
        pod: Option<&str>,
        container_id: &str,
    ) -> String {
        let parent = parent.unwrap_or(&self.parent_cgroup_relative);
        let mut path = parent.trim_end_matches('/').to_string();
        if let Some(pod) = pod.filter(|p| valid_container_id(p)) {
            path = format!("{path}/{pod}");
        }
        path = format!("{path}/{container_id}/{CONTAINER_CGROUP}");
        debug!("container_cgroup_path of {container_id}: {path}");
        path
    }

    /// Make the cgroups a container needs before its monitor starts: the
    /// directories of `cgroups_path` (a path of [`Self::container_cgroup_path`])
    /// with the controllers enabled for their children while they are
    /// empty, and `runtime` next to the `container` the runtime makes.
    /// The directory of the monitor.
    pub fn prepare_container(&self, cgroups_path: &str) -> io::Result<PathBuf> {
        let dir = Self::container_dir(cgroups_path)
            .ok_or_else(|| io::Error::other(format!("not a container cgroup: {cgroups_path}")))?;
        let _starts = self.starts.lock().unwrap_or_else(|e| e.into_inner());
        let cur = self.make_dirs(dir)?;
        // the cgroup of a pod made again keeps the limits of the pod
        if let Some(pod) = Path::new(dir)
            .parent()
            .and_then(|p| p.file_name())
            .and_then(|n| n.to_str())
            .filter(|n| valid_container_id(n))
        {
            let pods = self.pods.lock().unwrap_or_else(|e| e.into_inner());
            if let (Some(limits), Some(pod_dir)) = (pods.get(pod), cur.parent()) {
                // (a member does not start outside the limits of its pod)
                write_pod_limits(pod_dir, limits).map_err(|e| {
                    io::Error::new(e.kind(), format!("the limits of the pod {pod}: {e}"))
                })?;
            }
        }
        let monitor = cur.join(RUNTIME_CGROUP);
        match fs::create_dir(&monitor) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e),
        }
        Ok(monitor)
    }

    /// Make the directories of the cgroup `dir` (relative to the hierarchy)
    /// that are not there, with the controllers enabled for their children
    /// while they are empty.  The directory the first one is made in, when
    /// it is not the root of the hierarchy, gets the controllers it has
    /// enabled for its children too: it is the cgroup parent (the kubelet's
    /// cgroup of a pod, made with none for its children), which runc and
    /// crun also enable them in.  The directories above it are not touched.
    fn make_dirs(&self, dir: &str) -> io::Result<PathBuf> {
        let mut cur = self.base_path.clone();
        let mut made = false;
        for part in dir.trim_start_matches('/').split('/') {
            cur.push(part);
            match fs::create_dir(&cur) {
                Ok(()) => {
                    if !made {
                        made = true;
                        if let Some(parent) = cur.parent().filter(|p| *p != self.base_path) {
                            super::cgroups_mode::enable_controllers(parent);
                        }
                    }
                    super::cgroups_mode::enable_controllers(&cur)
                }
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e),
            }
        }
        Ok(cur)
    }

    /// The cgroup of the pod `pod` for the OCI spec's path rules, relative to
    /// /sys/fs/cgroup: `<parent>/<pod>`, the parent of the cgroups of all its
    /// containers ([`Self::container_cgroup_path`]).  The parent is the
    /// cgroup of the daemon, or the pod's `--cgroup-parent` (an absolute
    /// path).
    pub fn pod_cgroup_path(&self, parent: Option<&str>, pod: &str) -> io::Result<String> {
        if !valid_container_id(pod) {
            return Err(io::Error::other(format!("not a pod id: {pod}")));
        }
        let parent = parent.unwrap_or(&self.parent_cgroup_relative);
        Ok(format!("{}/{pod}", parent.trim_end_matches('/')))
    }

    /// Make the cgroup of the pod `pod` with `limits` (the pod is made, or
    /// updated): the directories, the controllers, the files of the limits;
    /// they are applied again whenever the cgroup is made again.  An empty
    /// `limits` takes the limits of the pod away.
    pub fn set_pod_limits(
        &self,
        parent: Option<&str>,
        pod: &str,
        limits: &PodResources,
    ) -> io::Result<()> {
        let path = self.pod_cgroup_path(parent, pod)?;
        let valid = path.starts_with('/') && path.split('/').all(|c| c != "." && c != "..");
        if !valid {
            return Err(io::Error::other(format!("invalid cgroup path {path}")));
        }
        // (the starts' lock first, as a start and the end of a monitor take
        // it: the cgroup of the pod is not removed while its limits change)
        let _starts = self.starts.lock().unwrap_or_else(|e| e.into_inner());
        let mut pods = self.pods.lock().unwrap_or_else(|e| e.into_inner());
        if limits.is_empty() {
            // (an empty cgroup of the pod is not worth making)
            if pods.remove(pod).is_some() {
                let dir = self.base_path.join(path.trim_start_matches('/'));
                if dir.exists() {
                    write_pod_limits(&dir, limits)?;
                }
            }
            return Ok(());
        }
        let dir = self.make_dirs(&path)?;
        write_pod_limits(&dir, limits)?;
        pods.insert(pod.to_string(), limits.clone());
        Ok(())
    }

    /// Forget the limits of the pod `pod` and remove its cgroup, which is
    /// empty when its containers are gone (one that is not stays).
    pub fn remove_pod(&self, parent: Option<&str>, pod: &str) {
        // (a start that is making the cgroups of its container below the
        // one of the pod holds this: the removal waits for it)
        let _starts = self.starts.lock().unwrap_or_else(|e| e.into_inner());
        self.pods
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(pod);
        if let Some(dir) = self.pod_cgroup_dir(parent, pod) {
            let _ = fs::remove_dir(dir);
        }
    }

    /// Where the cgroup of the pod is, when the pod is in the tree of this
    /// manager.
    fn pod_cgroup_dir(&self, parent: Option<&str>, pod: &str) -> Option<std::path::PathBuf> {
        let path = self.pod_cgroup_path(parent, pod).ok()?;
        (!path.contains("/../")).then(|| self.base_path.join(path.trim_start_matches('/')))
    }

    /// Wait until the cgroup of the pod is gone, at most `limit`: the last of
    /// its containers' cgroups goes when its monitor ends, and then the
    /// monitor's cleanup removes the cgroup of the pod; the removal of the pod
    /// returns after that.  The directory that is still there after
    /// `limit` (a process of the pod that does not end), if any.
    pub fn wait_pod_removed(
        &self,
        parent: Option<&str>,
        pod: &str,
        limit: std::time::Duration,
    ) -> std::io::Result<Option<std::path::PathBuf>> {
        let Some(dir) = self.pod_cgroup_dir(parent, pod) else {
            return Ok(None);
        };
        Ok((dir.exists() && !velarx_sys::watch::wait_removed(&dir, limit)?).then_some(dir))
    }

    /// Remember the limits of a pod the engine knew before this run: its
    /// cgroup is made with them when a container starts.
    pub fn remember_pod(&self, pod: &str, limits: &PodResources) {
        if valid_container_id(pod) && !limits.is_empty() {
            self.pods
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .insert(pod.to_string(), limits.clone());
        }
    }

    /// What the monitor of the container with `cgroups_path` leaves and
    /// removes at its end (`velarx_runtime::settle::cgroup`).
    pub fn plan_of(
        &self,
        cgroups_path: &str,
    ) -> Option<velarx_runtime::settle::cgroup::CgroupPlan> {
        let dir = self
            .base_path
            .join(Self::container_dir(cgroups_path)?.trim_start_matches('/'));
        let pod_dir = dir
            .parent()
            .filter(|p| {
                p.file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(valid_container_id)
            })
            .map(Path::to_path_buf);
        // (the cgroup that holds the container or its pod: the monitor
        // leaves for it, a common ancestor it may write)
        let parent = pod_dir.as_deref().unwrap_or(&dir).parent()?.to_path_buf();
        Some(velarx_runtime::settle::cgroup::CgroupPlan {
            parent,
            dir,
            pod_dir,
        })
    }

    /// Remove the empty cgroups of a container (and of its pod, if it was
    /// the last one in it): what is not empty stays.
    pub fn remove_container(&self, cgroups_path: &str) {
        let _starts = self.starts.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(plan) = self.plan_of(cgroups_path) {
            velarx_runtime::settle::cgroup::remove_dirs(&plan.dir, plan.pod_dir.as_deref());
        }
    }

    /// `<dir>/container` of a container's path: `<dir>`.
    fn container_dir(cgroups_path: &str) -> Option<&str> {
        let dir = cgroups_path
            .strip_suffix(CONTAINER_CGROUP)?
            .strip_suffix('/')?;
        let id = dir.rsplit('/').next()?;
        (cgroups_path.starts_with('/') && valid_container_id(id) && !cgroups_path.contains("/../"))
            .then_some(dir)
    }

    /// Remove the empty cgroups of containers and pods that are gone (the
    /// daemon was down, or a monitor was killed): `rmdir` takes only a
    /// cgroup with no process and no child, so a live one stays.
    fn sweep(&self) {
        use velarx_base::walk::{Visit, Walk};
        /// Down to the directories of a container: its cgroups are at most
        /// this deep (a pod, the container, its monitor and what is in them).
        const DEPTH: usize = 4;
        struct Empty;
        impl Visit for Empty {
            type Dir = ();

            fn entry(
                &mut self,
                _: std::os::fd::BorrowedFd<'_>,
                name: &std::ffi::OsStr,
                st: &rustix::fs::Stat,
                depth: usize,
                _: &mut (),
            ) -> io::Result<Option<()>> {
                if rustix::fs::FileType::from_raw_mode(st.st_mode)
                    != rustix::fs::FileType::Directory
                {
                    return Ok(None);
                }
                let name = name.to_string_lossy();
                // (the first level is the containers and pods; below them
                // only what the engine makes)
                let ours = valid_container_id(&name)
                    || (depth > 0 && (name == CONTAINER_CGROUP || name == RUNTIME_CGROUP));
                Ok((ours && depth < DEPTH).then_some(()))
            }

            // (`rmdir` takes only a cgroup with no process and no child)
            fn leave(
                &mut self,
                parent: std::os::fd::BorrowedFd<'_>,
                _: &mut (),
                name: &std::ffi::OsStr,
                dir: std::os::fd::OwnedFd,
                _: (),
            ) -> io::Result<()> {
                drop(dir);
                let _ = rustix::fs::unlinkat(parent, name, rustix::fs::AtFlags::REMOVEDIR);
                Ok(())
            }
        }
        let Ok(root) = velarx_base::tree::open_root(&self.parent_cgroup) else {
            return;
        };
        let _ = Walk {
            max_depth: DEPTH,
            sorted: false,
            skip_gone: true,
            lenient: true,
        }
        .run(root, (), &mut Empty);
    }

    /// Enable controllers in a cgroup subtree
    fn enable_controllers(&self, cgroup_path: &Path) -> CgroupResult<()> {
        let controllers_file = cgroup_path.join("cgroup.subtree_control");

        if !controllers_file.exists() {
            return Ok(());
        }

        // The first controller that cannot be enabled fails: the limits
        // the container asks for need it
        for (name, written) in velarx_base::cgroup::enable_controllers(cgroup_path)? {
            debug!("Enabling controller {name} at {:?}", cgroup_path);
            written?;
        }
        Ok(())
    }

    /// The controllers the cgroups of the containers and pods can have: those
    /// of the cgroup the daemon manages.
    pub fn controllers(&self) -> Vec<String> {
        fs::read_to_string(self.parent_cgroup.join("cgroup.controllers"))
            .unwrap_or_default()
            .split_whitespace()
            .map(str::to_string)
            .collect()
    }

    /// The directory of the cgroup process `pid` is in.
    pub fn cgroup_dir_of_pid(&self, pid: i32) -> CgroupResult<PathBuf> {
        Ok(self.base_path.join(relative_cgroup_of(pid)?))
    }
}

/// The cgroup of process `pid` relative to the hierarchy, no leading slash.
fn relative_cgroup_of(pid: i32) -> CgroupResult<String> {
    let rel = velarx_base::cgroup::of_process(Some(pid))?;
    let rel = rel.trim_start_matches('/');
    if rel.split('/').any(|c| c == "..") {
        return Err(CgroupError::NotFound(format!("the cgroup of {pid}")));
    }
    Ok(rel.to_string())
}

/// The directory of the cgroup a container was made in, from its
/// `linux.cgroupsPath`: a path of the hierarchy (`/a/b/container`) is that
/// directory; a systemd one (`slice:prefix:name`) is the scope
/// `prefix-name.scope` the manager made, found in the cgroup of its process
/// `pid` (which may have moved below it: systemd as the payload).
pub fn container_dir(cgroups_path: &str, pid: i32) -> CgroupResult<PathBuf> {
    let not_found = || CgroupError::NotFound(format!("the cgroup {cgroups_path}"));
    if cgroups_path.starts_with('/') {
        if cgroups_path.split('/').any(|c| c == "..") {
            return Err(not_found());
        }
        return Ok(velarx_base::cgroup::dir(cgroups_path));
    }
    let mut parts = cgroups_path.splitn(3, ':');
    let (Some(_slice), Some(prefix), Some(name)) = (parts.next(), parts.next(), parts.next())
    else {
        return Err(not_found());
    };
    let unit = format!("{prefix}-{name}.scope");
    let rel = relative_cgroup_of(pid)?;
    let end = rel
        .split('/')
        .position(|c| c == unit)
        .ok_or_else(not_found)?;
    let scope: Vec<&str> = rel.split('/').take(end + 1).collect();
    Ok(velarx_base::cgroup::dir(&scope.join("/")))
}

/// The processes of the cgroup `dir` and of the cgroups below it.
pub fn procs_below(dir: &Path) -> Vec<String> {
    use std::io::Read;
    use velarx_base::walk::{Visit, Walk};
    struct Procs(Vec<String>);
    impl Visit for Procs {
        type Dir = ();

        fn enter(
            &mut self,
            dir: std::os::fd::BorrowedFd<'_>,
            _: &[std::ffi::OsString],
            _: &mut (),
        ) -> io::Result<()> {
            if let Ok(fd) = rustix::fs::openat(
                dir,
                "cgroup.procs",
                rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::empty(),
            ) {
                let mut text = String::new();
                if fs::File::from(fd).read_to_string(&mut text).is_ok() {
                    self.0.extend(text.lines().map(str::to_string));
                }
            }
            Ok(())
        }

        fn entry(
            &mut self,
            _: std::os::fd::BorrowedFd<'_>,
            _: &std::ffi::OsStr,
            st: &rustix::fs::Stat,
            _: usize,
            _: &mut (),
        ) -> io::Result<Option<()>> {
            Ok(
                (rustix::fs::FileType::from_raw_mode(st.st_mode)
                    == rustix::fs::FileType::Directory)
                    .then_some(()),
            )
        }
    }
    let Ok(root) = velarx_base::tree::open_root(dir) else {
        return Vec::new();
    };
    let mut out = Procs(Vec::new());
    // (what a cgroup tree holds is small: whatever it holds is read)
    let _ = Walk {
        max_depth: velarx_base::tree::MAX_DEPTH,
        sorted: false,
        skip_gone: true,
        lenient: true,
    }
    .run(root, (), &mut out);
    out.0
}

/// The resource usage of the cgroup at `cgroup_path`.
pub fn stats_at(cgroup_path: &Path) -> CgroupResult<CgroupStats> {
    let mut stats = CgroupStats {
        memory_usage: read_cgroup_value(cgroup_path, "memory.current")?,
        ..CgroupStats::default()
    };

    let memory_max = read_cgroup_value(cgroup_path, "memory.max")?;
    stats.memory_limit = if memory_max == u64::MAX {
        None
    } else {
        Some(memory_max)
    };

    stats.memory_swap_usage = read_cgroup_value(cgroup_path, "memory.swap.current").unwrap_or(0);
    let swap_max = read_cgroup_value(cgroup_path, "memory.swap.max").unwrap_or(u64::MAX);
    stats.memory_swap_limit = if swap_max == u64::MAX {
        None
    } else {
        Some(swap_max)
    };

    let memory_high = read_cgroup_value(cgroup_path, "memory.high").unwrap_or(u64::MAX);
    stats.memory_high = if memory_high == u64::MAX {
        None
    } else {
        Some(memory_high)
    };

    if let Ok(mem_stat) = fs::read_to_string(cgroup_path.join("memory.stat")) {
        for line in mem_stat.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                let value: u64 = parts[1].parse().unwrap_or(0);
                match parts[0] {
                    "anon" => stats.memory_anon = value,
                    "file" => stats.memory_file = value,
                    "kernel" => stats.memory_kernel = value,
                    "inactive_file" => stats.memory_inactive_file = value,
                    "file_mapped" => stats.memory_mapped_file = value,
                    "pgfault" => stats.page_faults = value,
                    "pgmajfault" => stats.major_page_faults = value,
                    _ => {}
                }
            }
        }
    }

    if let Ok(cpu_stat) = fs::read_to_string(cgroup_path.join("cpu.stat")) {
        for line in cpu_stat.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                let value: u64 = parts[1].parse().unwrap_or(0);
                match parts[0] {
                    "usage_usec" => stats.cpu_usage_usec = value,
                    "user_usec" => stats.cpu_user_usec = value,
                    "system_usec" => stats.cpu_system_usec = value,
                    "nr_periods" => stats.cpu_periods = value,
                    "nr_throttled" => stats.cpu_throttled_periods = value,
                    "throttled_usec" => stats.cpu_throttled_usec = value,
                    _ => {}
                }
            }
        }
    }

    stats.memory_peak = read_cgroup_value(cgroup_path, "memory.peak").unwrap_or(0);
    if let Ok(events) = fs::read_to_string(cgroup_path.join("memory.events")) {
        for line in events.lines() {
            let mut parts = line.split_whitespace();
            match (parts.next(), parts.next().and_then(|v| v.parse().ok())) {
                (Some("max"), Some(v)) => stats.memory_limit_hits = v,
                (Some("oom_kill"), Some(v)) => stats.oom_kills = v,
                _ => {}
            }
        }
    }
    stats.cpu_weight = fs::read_to_string(cgroup_path.join("cpu.weight"))
        .ok()
        .and_then(|w| w.trim().parse().ok());

    if let Ok(cpu_max) = fs::read_to_string(cgroup_path.join("cpu.max")) {
        let parts: Vec<&str> = cpu_max.split_whitespace().collect();
        if parts.len() >= 2 {
            if parts[0] != "max" {
                stats.cpu_quota = parts[0].parse().ok();
            }
            stats.cpu_period = parts[1].parse().ok();
        }
    }

    if let Ok(io_stat) = fs::read_to_string(cgroup_path.join("io.stat")) {
        for line in io_stat.lines() {
            // Format: "MAJ:MIN rbytes=X wbytes=Y rios=Z wios=W ..."
            for part in line.split_whitespace() {
                if let Some(value) = part.strip_prefix("rbytes=") {
                    stats.io_read_bytes += value.parse::<u64>().unwrap_or(0);
                } else if let Some(value) = part.strip_prefix("wbytes=") {
                    stats.io_write_bytes += value.parse::<u64>().unwrap_or(0);
                } else if let Some(value) = part.strip_prefix("rios=") {
                    stats.io_read_ops += value.parse::<u64>().unwrap_or(0);
                } else if let Some(value) = part.strip_prefix("wios=") {
                    stats.io_write_ops += value.parse::<u64>().unwrap_or(0);
                }
            }
        }
    }

    stats.pids_current = read_cgroup_value(cgroup_path, "pids.current")? as u32;
    let pids_max = read_cgroup_value(cgroup_path, "pids.max").unwrap_or(u64::MAX);
    stats.pids_limit = if pids_max == u64::MAX {
        None
    } else {
        Some(pids_max as u32)
    };
    stats.pressure = velarx_proto::pod::Pressure::read(cgroup_path);

    Ok(stats)
}

/// Read a numeric value from a cgroup file
fn read_cgroup_value(cgroup_path: &Path, file: &str) -> CgroupResult<u64> {
    let file_path = cgroup_path.join(file);
    if !file_path.exists() {
        return Ok(0);
    }

    let content = fs::read_to_string(&file_path)?;
    let value = content.trim();

    if value == "max" {
        return Ok(u64::MAX);
    }

    value
        .parse()
        .map_err(|_| CgroupError::InvalidPath(format!("cannot parse value from {:?}", file_path)))
}

/// Statistics from a container's cgroup
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct CgroupStats {
    /// Current memory usage in bytes
    pub memory_usage: u64,
    /// Memory limit in bytes (None if unlimited)
    pub memory_limit: Option<u64>,
    /// Memory usage including swap
    pub memory_swap_usage: u64,
    /// Memory + swap limit (None if unlimited)
    pub memory_swap_limit: Option<u64>,
    /// Anonymous memory usage
    pub memory_anon: u64,
    /// File-backed memory usage (page cache)
    pub memory_file: u64,
    /// Kernel memory usage
    pub memory_kernel: u64,
    /// Memory high watermark (soft limit)
    pub memory_high: Option<u64>,
    /// Page cache that can be reclaimed at once (`inactive_file`)
    pub memory_inactive_file: u64,
    /// Page cache mapped by processes (`file_mapped`)
    pub memory_mapped_file: u64,
    /// Page faults and major ones
    pub page_faults: u64,
    pub major_page_faults: u64,
    /// The most memory the cgroup used (`memory.peak`)
    pub memory_peak: u64,
    /// Times the limit was hit (`memory.events` max) and processes killed
    /// by the OOM killer (`oom_kill`)
    pub memory_limit_hits: u64,
    pub oom_kills: u64,
    /// `cpu.weight` (1 to 10000)
    pub cpu_weight: Option<u64>,
    /// Enforcement periods that elapsed
    pub cpu_periods: u64,

    /// Total CPU usage in microseconds
    pub cpu_usage_usec: u64,
    /// User CPU time in microseconds
    pub cpu_user_usec: u64,
    /// System CPU time in microseconds
    pub cpu_system_usec: u64,
    /// Number of periods where CPU was throttled
    pub cpu_throttled_periods: u64,
    /// Total time throttled in microseconds
    pub cpu_throttled_usec: u64,
    /// CPU quota (None if unlimited)
    pub cpu_quota: Option<i64>,
    /// CPU period in microseconds
    pub cpu_period: Option<u64>,

    /// Bytes read from block devices
    pub io_read_bytes: u64,
    /// Bytes written to block devices
    pub io_write_bytes: u64,
    /// Read operations count
    pub io_read_ops: u64,
    /// Write operations count
    pub io_write_ops: u64,

    /// Number of processes/threads
    pub pids_current: u32,
    /// PIDs limit (None if unlimited)
    pub pids_limit: Option<u32>,

    /// The pressure files of the cgroup
    pub pressure: velarx_proto::pod::Pressure,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_processes_of_a_cgroup_are_those_of_it_and_of_the_cgroups_below() {
        let dir = tempfile::tempdir().unwrap();
        let t = dir.path();
        fs::create_dir_all(t.join("a/b")).unwrap();
        fs::create_dir_all(t.join("c")).unwrap();
        fs::write(t.join("cgroup.procs"), "1\n2\n").unwrap();
        fs::write(t.join("a/cgroup.procs"), "3\n").unwrap();
        fs::write(t.join("a/b/cgroup.procs"), "4\n5\n").unwrap();
        let mut pids = procs_below(t);
        pids.sort();
        assert_eq!(pids, ["1", "2", "3", "4", "5"]);
        assert!(procs_below(&t.join("nothing")).is_empty());
    }

    const A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const P: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

    #[test]
    fn the_managed_cgroup_is_the_one_above_the_daemons() {
        assert_eq!(managed_cgroup("/"), "");
        assert_eq!(managed_cgroup("/engine"), "");
        assert_eq!(managed_cgroup("/initial/cgroup"), "initial/cgroup");
        assert_eq!(managed_cgroup("/initial/cgroup/engine\n"), "initial/cgroup");
        // only the daemon's own directory is left, not a name that ends the same
        assert_eq!(managed_cgroup("/a/not-engine"), "a/not-engine");
        assert_eq!(
            managed_cgroup(
                "/user.slice/user-1000.slice/user@1000.service/app.slice/velarx.service"
            ),
            "user.slice/user-1000.slice/user@1000.service/app.slice/velarx.service"
        );
    }

    #[test]
    fn the_stats_of_a_cgroup_tell_the_working_set_and_the_events() {
        let dir = tempfile::tempdir().unwrap();
        let cg = dir.path().join("u");
        fs::create_dir_all(&cg).unwrap();
        for (f, v) in [
            ("memory.current", "1000\n"),
            ("memory.max", "max\n"),
            ("memory.peak", "1500\n"),
            (
                "memory.stat",
                "anon 400\nfile 600\ninactive_file 250\nfile_mapped 50\npgfault 77\npgmajfault 3\n",
            ),
            ("memory.events", "low 0\nhigh 0\nmax 4\noom 1\noom_kill 2\n"),
            (
                "cpu.stat",
                "usage_usec 10\nnr_periods 9\nnr_throttled 2\nthrottled_usec 5\n",
            ),
            ("cpu.weight", "39\n"),
            ("pids.current", "3\n"),
        ] {
            fs::write(cg.join(f), v).unwrap();
        }
        let s = stats_at(&cg).unwrap();
        assert_eq!(
            (s.memory_usage, s.memory_inactive_file, s.memory_mapped_file),
            (1000, 250, 50)
        );
        assert_eq!((s.page_faults, s.major_page_faults), (77, 3));
        assert_eq!(
            (s.memory_peak, s.memory_limit_hits, s.oom_kills),
            (1500, 4, 2)
        );
        assert_eq!((s.cpu_periods, s.cpu_throttled_periods), (9, 2));
        assert_eq!((s.cpu_weight, s.memory_limit), (Some(39), None));
    }

    fn manager(root: &Path, rel: &str) -> CgroupManager {
        fs::create_dir_all(root.join(rel.trim_start_matches('/'))).unwrap();
        CgroupManager {
            base_path: root.to_path_buf(),
            parent_cgroup: root.join(rel.trim_start_matches('/')),
            parent_cgroup_relative: rel.to_string(),
            starts: Mutex::default(),
            pods: Mutex::default(),
        }
    }

    #[test]
    fn the_controllers_of_a_cgroup_the_kubelet_made_are_enabled_for_the_container() {
        // /kubepods/burstable/podx: the kubelet made it, with the controllers
        // enabled along its path but none for its own children
        let dir = tempfile::tempdir().unwrap();
        let cm = manager(dir.path(), "/");
        let pod = dir.path().join("kubepods/burstable/podx");
        fs::create_dir_all(&pod).unwrap();
        for d in ["kubepods", "kubepods/burstable", "kubepods/burstable/podx"] {
            let d = dir.path().join(d);
            fs::write(d.join("cgroup.controllers"), "cpu memory\n").unwrap();
            fs::write(d.join("cgroup.subtree_control"), "").unwrap();
        }
        let made = cm.make_dirs("/kubepods/burstable/podx/sandbox").unwrap();
        assert_eq!(made, pod.join("sandbox"));
        // (each write of the fake file replaces the one before: the last)
        assert_eq!(
            fs::read_to_string(pod.join("cgroup.subtree_control")).unwrap(),
            "+memory"
        );
        // the cgroups above the pod's are not written to
        for d in ["kubepods", "kubepods/burstable"] {
            let d = dir.path().join(d);
            assert_eq!(
                fs::read_to_string(d.join("cgroup.subtree_control")).unwrap(),
                ""
            );
        }
        // nor is the pod's again when a directory below it is there already
        fs::write(pod.join("cgroup.subtree_control"), "").unwrap();
        cm.make_dirs("/kubepods/burstable/podx/sandbox/ctr")
            .unwrap();
        assert_eq!(
            fs::read_to_string(pod.join("cgroup.subtree_control")).unwrap(),
            ""
        );
    }

    #[test]
    fn the_root_of_the_hierarchy_is_not_written_to() {
        let dir = tempfile::tempdir().unwrap();
        let cm = manager(dir.path(), "/");
        fs::write(dir.path().join("cgroup.controllers"), "cpu memory\n").unwrap();
        fs::write(dir.path().join("cgroup.subtree_control"), "").unwrap();
        cm.make_dirs("/top").unwrap();
        assert_eq!(
            fs::read_to_string(dir.path().join("cgroup.subtree_control")).unwrap(),
            ""
        );
    }

    #[test]
    fn container_paths() {
        let dir = tempfile::tempdir().unwrap();
        let cm = manager(dir.path(), "/u/velarx.service");
        assert_eq!(
            cm.container_cgroup_path(None, None, A),
            format!("/u/velarx.service/{A}/container")
        );
        assert_eq!(
            cm.container_cgroup_path(None, Some(P), A),
            format!("/u/velarx.service/{P}/{A}/container")
        );
        assert_eq!(
            cm.container_cgroup_path(Some("/x/y/"), None, A),
            format!("/x/y/{A}/container")
        );
        let root = manager(dir.path(), "/");
        assert_eq!(
            root.container_cgroup_path(None, None, A),
            format!("/{A}/container")
        );
    }

    #[test]
    fn a_container_gets_a_monitor_and_is_removed_with_its_pod() {
        let dir = tempfile::tempdir().unwrap();
        let cm = manager(dir.path(), "/u/s.service");
        let a = cm.container_cgroup_path(None, Some(P), A);
        let b = cm.container_cgroup_path(None, Some(P), B);
        let root = dir.path().join("u/s.service");
        assert_eq!(
            cm.prepare_container(&a).unwrap(),
            root.join(P).join(A).join("runtime")
        );
        cm.prepare_container(&b).unwrap();
        // preparing twice, as a restart does
        cm.prepare_container(&a).unwrap();

        cm.remove_container(&a);
        assert!(!root.join(P).join(A).exists());
        assert!(root.join(P).join(B).join("runtime").exists());
        assert!(root.join(P).exists(), "the pod has another container");
        cm.remove_container(&b);
        assert!(!root.join(P).exists());
        assert!(root.exists(), "the daemon's own cgroup stays");
        // nothing of it to remove again
        cm.remove_container(&b);
    }

    #[test]
    fn what_is_not_a_container_path_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let cm = manager(dir.path(), "/u");
        assert!(cm.prepare_container("/u/not-an-id/container").is_err());
        assert!(cm.prepare_container(&format!("/u/{A}")).is_err());
        assert!(cm
            .prepare_container(&format!("/u/../{A}/container"))
            .is_err());
        assert!(!dir.path().join("u/not-an-id").exists());
    }

    /// The files a cgroup with the controllers has, with the default
    /// values the kernel gives them.
    fn controller_files(dir: &Path) {
        for (f, v) in [
            ("memory.max", "max"),
            ("memory.swap.max", "max"),
            ("cpu.weight", "100"),
            ("cpu.max", "max 100000"),
            ("cpuset.cpus", ""),
            ("cpuset.mems", ""),
            ("io.max", ""),
            ("io.weight", "default 100\n"),
        ] {
            fs::write(dir.join(f), v).unwrap();
        }
    }

    fn read(dir: &Path, f: &str) -> String {
        fs::read_to_string(dir.join(f)).unwrap().trim().to_string()
    }

    #[test]
    fn the_limits_of_a_pod_are_its_cgroups_files() {
        let dir = tempfile::tempdir().unwrap();
        controller_files(dir.path());
        let l = PodResources {
            memory: Some(100 << 20),
            memory_swap: Some(150 << 20),
            cpu_shares: Some(1024),
            cpu_quota: Some(50_000),
            cpu_period: Some(200_000),
            cpuset_cpus: Some("0-1".into()),
            cpuset_mems: Some("0".into()),
            ..Default::default()
        };
        write_pod_limits(dir.path(), &l).unwrap();
        assert_eq!(read(dir.path(), "memory.max"), (100u64 << 20).to_string());
        // (the limit counts memory and swap together, the file the swap)
        assert_eq!(
            read(dir.path(), "memory.swap.max"),
            (50u64 << 20).to_string()
        );
        assert_eq!(read(dir.path(), "cpu.weight"), "100");
        assert_eq!(read(dir.path(), "cpu.max"), "50000 200000");
        assert_eq!(read(dir.path(), "cpuset.cpus"), "0-1");
        assert_eq!(read(dir.path(), "cpuset.mems"), "0");
        // none is the default of the cgroup
        write_pod_limits(dir.path(), &PodResources::default()).unwrap();
        assert_eq!(read(dir.path(), "memory.max"), "max");
        assert_eq!(read(dir.path(), "memory.swap.max"), "max");
        assert_eq!(read(dir.path(), "cpu.weight"), "100");
        assert_eq!(read(dir.path(), "cpu.max"), "max 100000");
        assert_eq!(read(dir.path(), "cpuset.cpus"), "");
    }

    /// The block IO files: the weight (converted for `io.weight`, as is for
    /// `io.bfq.weight`), the rates of a device, and the devices of an earlier
    /// call set back to their defaults.
    #[test]
    fn the_block_io_limits_are_the_files_of_the_io_controller() {
        use velarx_proto::pod::PodDeviceLimit;
        let dev = |value| PodDeviceLimit {
            major: 7,
            minor: 0,
            value,
            path: String::new(),
        };
        let dir = tempfile::tempdir().unwrap();
        controller_files(dir.path());
        let l = PodResources {
            blkio_weight: Some(50),
            blkio_weight_device: vec![dev(200)],
            device_read_bps: vec![dev(1 << 20)],
            device_write_bps: vec![dev(2 << 20)],
            ..Default::default()
        };
        write_pod_limits(dir.path(), &l).unwrap();
        // (the kernel keeps one line a device: the files here keep the last
        // write, which is what a later reset reads)
        assert_eq!(read(dir.path(), "io.weight"), "7:0 1920");
        assert_eq!(read(dir.path(), "io.max"), "7:0 wbps=2097152");
        // with BFQ the values are the weights as they are
        fs::write(dir.path().join("io.bfq.weight"), "default 100\n").unwrap();
        write_pod_limits(dir.path(), &l).unwrap();
        assert_eq!(read(dir.path(), "io.bfq.weight"), "7:0 200");
        // none: the devices are back at their defaults
        fs::write(
            dir.path().join("io.max"),
            "7:0 rbps=1 wbps=max riops=max wiops=max\n",
        )
        .unwrap();
        fs::write(dir.path().join("io.weight"), "default 4\n7:0 4\n").unwrap();
        write_pod_limits(dir.path(), &PodResources::default()).unwrap();
        assert_eq!(
            read(dir.path(), "io.max"),
            "7:0 rbps=max wbps=max riops=max wiops=max"
        );
        assert_eq!(read(dir.path(), "io.weight"), "default 100");
        // a cgroup without the controller cannot have them
        let none = tempfile::tempdir().unwrap();
        let e = write_pod_limits(none.path(), &l).unwrap_err();
        assert!(e.to_string().contains("io."), "{e}");
    }

    #[test]
    fn a_limit_the_cgroup_cannot_take_is_an_error_a_default_is_not() {
        let dir = tempfile::tempdir().unwrap();
        // no controller at all: nothing to set, nothing to say
        write_pod_limits(dir.path(), &PodResources::default()).unwrap();
        let l = PodResources {
            memory: Some(1 << 30),
            ..Default::default()
        };
        let e = write_pod_limits(dir.path(), &l).unwrap_err();
        assert!(e.to_string().contains("memory.max"), "{e}");
    }

    #[test]
    fn the_cgroup_of_a_pod_is_made_with_its_limits_and_again_with_a_member() {
        let dir = tempfile::tempdir().unwrap();
        let cm = manager(dir.path(), "/u/s.service");
        let root = dir.path().join("u/s.service");
        let l = PodResources {
            memory: Some(1 << 30),
            ..Default::default()
        };
        assert!(cm.pod_cgroup_path(None, "not-an-id").is_err());
        assert_eq!(
            cm.pod_cgroup_path(None, P).unwrap(),
            format!("/u/s.service/{P}")
        );
        // (the files the kernel makes in a new cgroup)
        let made = root.join(P);
        fs::create_dir_all(&made).unwrap();
        controller_files(&made);
        cm.set_pod_limits(None, P, &l).unwrap();
        assert_eq!(read(&made, "memory.max"), (1u64 << 30).to_string());
        // the cgroup went with its last container; a member makes it again
        // with the limits
        fs::remove_dir_all(&made).unwrap();
        let a = cm.container_cgroup_path(None, Some(P), A);
        // (no kernel here: the file the limits would be in is not there, and
        // the start is refused rather than made without them)
        let e = cm.prepare_container(&a).unwrap_err();
        assert!(e.to_string().contains("memory.max"), "{e}");
        controller_files(&made);
        cm.prepare_container(&a).unwrap();
        assert_eq!(read(&made, "memory.max"), (1u64 << 30).to_string());
        // an update replaces them, empty ones take them away
        let l2 = PodResources {
            memory: Some(2 << 30),
            ..Default::default()
        };
        cm.set_pod_limits(None, P, &l2).unwrap();
        assert_eq!(read(&made, "memory.max"), (2u64 << 30).to_string());
        cm.set_pod_limits(None, P, &PodResources::default())
            .unwrap();
        assert_eq!(read(&made, "memory.max"), "max");
        fs::remove_dir_all(made.join(A)).unwrap();
        // gone with the pod: a member no longer gets limits
        cm.set_pod_limits(None, P, &l).unwrap();
        cm.remove_pod(None, P);
        fs::write(made.join("memory.max"), "max").unwrap();
        cm.prepare_container(&a).unwrap();
        assert_eq!(read(&made, "memory.max"), "max");
        // a path that leaves the hierarchy is refused
        assert!(cm.set_pod_limits(Some("/a/../b"), P, &l).is_err());
        assert!(cm.set_pod_limits(Some("rel"), P, &l).is_err());
    }

    #[test]
    fn the_sweep_removes_only_what_is_empty_and_ours() {
        let dir = tempfile::tempdir().unwrap();
        let cm = manager(dir.path(), "/u");
        let root = dir.path().join("u");
        for p in [
            format!("{A}/runtime"),
            format!("{A}/container"),
            format!("{P}/{B}/runtime"),
            "pulls/1".to_string(),
            "engine".to_string(),
        ] {
            fs::create_dir_all(root.join(p)).unwrap();
        }
        // a cgroup of something else in a container's directory is not ours
        fs::create_dir_all(root.join(format!("{A}/other"))).unwrap();
        cm.sweep();
        assert!(root.join(A).join("other").exists());
        assert!(!root.join(A).join("runtime").exists());
        assert!(!root.join(P).exists());
        assert!(root.join("pulls/1").exists());
        assert!(root.join("engine").exists());
    }
}
