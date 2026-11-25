// SPDX-License-Identifier: Apache-2.0
use oci_spec::runtime::{
    LinuxBuilder, LinuxCpuBuilder, LinuxIdMappingBuilder, LinuxMemoryBuilder,
    LinuxNamespaceBuilder, LinuxNamespaceType, LinuxPidsBuilder, LinuxResourcesBuilder, Mount,
    MountBuilder, ProcessBuilder, RootBuilder, Spec, SpecBuilder, UserBuilder,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{self};
use std::io;
use std::path::{Path, PathBuf};
use thiserror::Error;
use velarx_confine_core as confine_core;
use velarx_proto::health::Healthcheck;
use velarx_wire::monitor::proto::RestartSettings;
use velarx_wire::request::{CgroupsMode, NetworkMode};

pub use velarx_wire::request::{IdMapping, ImageMountConfig, MountConfig, OverlayMountConfig};

#[derive(Error, Debug)]
pub enum RuntimeError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("OCI spec error: {0}")]
    OciSpec(String),
    #[error("container not found: {0}")]
    NotFound(String),
    #[error("{0}")]
    Runtime(String),
    /// The container could not be started: the runtime refused it, or what
    /// it runs with is not there (its user, its working directory);
    /// `command_missing`: the command it runs is not there.
    #[error("{message}")]
    NotStarted {
        command_missing: bool,
        message: String,
    },
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Ids(#[from] velarx_base::ids::IdsError),
}

pub type RuntimeResult<T> = Result<T, RuntimeError>;

/// Extension trait for converting OCI spec builder results to RuntimeResult
trait OciResultExt<T> {
    fn oci(self) -> RuntimeResult<T>;
}

impl<T, E: std::fmt::Display> OciResultExt<T> for Result<T, E> {
    fn oci(self) -> RuntimeResult<T> {
        self.map_err(|e| RuntimeError::OciSpec(e.to_string()))
    }
}

/// Helper to build a Linux namespace
fn build_namespace(typ: LinuxNamespaceType) -> RuntimeResult<oci_spec::runtime::LinuxNamespace> {
    LinuxNamespaceBuilder::default().typ(typ).build().oci()
}

/// Helper to build a Linux namespace with a path
fn build_namespace_with_path(
    typ: LinuxNamespaceType,
    path: String,
) -> RuntimeResult<oci_spec::runtime::LinuxNamespace> {
    LinuxNamespaceBuilder::default()
        .typ(typ)
        .path(path)
        .build()
        .oci()
}

/// The user a process runs as, as a specification says it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpecUser {
    pub uid: u32,
    pub gid: u32,
    pub additional_gids: Vec<u32>,
}

impl SpecUser {
    /// The user of `process.user` of an OCI specification (none: it has
    /// no user).
    pub fn of_spec(spec: &serde_json::Value) -> Option<Self> {
        let user = spec.get("process")?.get("user")?;
        let id = |v: &serde_json::Value| u32::try_from(v.as_u64()?).ok();
        Some(Self {
            uid: id(user.get("uid")?)?,
            gid: id(user.get("gid")?)?,
            additional_gids: user
                .get("additionalGids")
                .and_then(|g| g.as_array())
                .map(|a| a.iter().filter_map(id).collect())
                .unwrap_or_default(),
        })
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ContainerConfig {
    pub id: String,
    pub name: Option<String>,
    pub image: String,
    pub command: Vec<String>,
    pub entrypoint: Vec<String>,
    pub working_dir: String,
    pub env: Vec<String>,
    pub labels: HashMap<String, String>,
    pub hostname: String,
    /// The OCI runtime of the container when it is not the default one: its
    /// path (resolved when the container was made) and the name it was asked
    /// for with
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_name: Option<String>,
    /// `--user`, else the `User` of the image
    pub user: String,
    /// `--group-add`
    #[serde(default)]
    pub group_add: Vec<String>,
    /// `user` resolved in the root file system at create time
    #[serde(default)]
    pub process_user: Option<super::userspec::ResolvedUser>,
    /// The user of the process in the specification the container runs with,
    /// read from the final one (after the CDI edits and the hooks that
    /// change it), which `process_user` is not
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spec_user: Option<SpecUser>,
    /// `--umask`
    #[serde(default)]
    pub umask: Option<u32>,
    /// The other create options that shape the spec
    #[serde(default)]
    pub options: velarx_wire::options::CreateOptions,
    /// The SELinux settings (none: SELinux is disabled)
    #[serde(default)]
    pub selinux: Option<super::selinux::SelinuxConfig>,
    /// `--requires`: the ids of the containers started before this one
    #[serde(default)]
    pub requires: Vec<String>,
    pub mounts: Vec<MountConfig>,
    pub read_only_rootfs: bool,
    pub privileged: bool,
    pub cap_add: Vec<String>,
    pub cap_drop: Vec<String>,
    /// Capabilities in every set of the process, the ambient one too
    #[serde(default)]
    pub cap_ambient: Vec<String>,
    /// Only the group of the user and `group_add`, not the groups of the
    /// image's /etc/group
    #[serde(default)]
    pub groups_strict: bool,
    pub userns_mode: UsernsMode,
    /// The user namespace as requested (`auto`, `keep-id`, `container:web`...)
    #[serde(default)]
    pub userns: String,
    /// The namespace to join, for `container:ID` and `ns:PATH`
    #[serde(default)]
    pub userns_path: Option<String>,
    pub uid_mappings: Vec<IdMapping>,
    pub gid_mappings: Vec<IdMapping>,
    pub tty: bool,
    pub stdin_open: bool,
    /// Security options
    #[serde(default)]
    pub security_opt: SecurityConfig,
    /// Resource limits
    #[serde(default)]
    pub resources: Option<ResourceConfig>,
    /// PID limit
    #[serde(default)]
    pub pids_limit: Option<i64>,
    /// OOM score adjustment
    #[serde(default)]
    pub oom_score_adj: Option<i32>,
    /// Sysctls
    #[serde(default)]
    pub sysctls: HashMap<String, String>,
    /// Network mode: "bridge", "host", "none", or "container:<id>"
    #[serde(default)]
    pub network_mode: NetworkMode,
    /// Network names to connect to (supports multiple networks)
    #[serde(default)]
    pub networks: Vec<String>,
    /// Network namespace path (for container:id mode)
    #[serde(default)]
    pub network_namespace_path: Option<String>,
    /// The signal `stop` sends first (name or number; empty: SIGTERM)
    #[serde(default)]
    pub stop_signal: String,
    /// The log driver (empty: the default of the daemon) and its options
    #[serde(default)]
    pub log_driver: String,
    #[serde(default)]
    pub log_opts: HashMap<String, String>,
    /// Kill the container after it ran for this many seconds
    #[serde(default)]
    pub timeout: Option<u64>,
    /// Seconds a stop gives the container before it kills it
    #[serde(default)]
    pub stop_timeout: Option<u32>,
    #[serde(default)]
    pub healthcheck: Option<Healthcheck>,
    #[serde(default, with = "velarx_proto::health::stored_restart")]
    pub restart_policy: Option<RestartSettings>,
    /// Why the container cannot start (a `--workdir` the image lacks): it
    /// is made, as podman's, and the start says so.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start_error: Option<String>,
    /// The user or group the image has no entry for: the container is made
    /// as podman's, and the start says so.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_error: Option<String>,
    /// `container`, `conmon`, `healthy` or `ignore`: what to do with the
    /// sd_notify protocol.  The socket of the service manager is the
    /// `NOTIFY_SOCKET` of the monitor's own environment, never a path that a
    /// request names.
    #[serde(default)]
    pub sdnotify: String,
    /// `--cgroups`: enabled (or empty), disabled, no-conmon or split
    #[serde(default)]
    pub cgroups: CgroupsMode,
    /// `--cgroups=scope|unit`: `scope` or `unit`, as it was resolved when the
    /// container was made (none without cgroups of the engine's choice;
    /// the word is `scope` or `unit`, empty for none)
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "velarx_wire::request::cgroup_mode_word"
    )]
    pub cgroup_mode: Option<velarx_wire::request::CgroupMode>,
    /// Made by `run --no-monitor`: its first monitor is the process that
    /// ran it (later starts get a monitor process).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub no_monitor: bool,
    /// Cgroup path for the container (relative path for OCI spec linux.cgroupsPath)
    #[serde(default)]
    pub cgroups_path: Option<String>,
    /// Automatically remove container on exit
    #[serde(default)]
    pub auto_remove: bool,
    /// `--rmi`: and its image, unless another container uses it
    #[serde(default)]
    pub auto_remove_image: bool,
    /// The overlay of the root file system is mounted `volatile` (also for
    /// `auto_remove`): a container that is thrown away.
    #[serde(default)]
    pub volatile: bool,
    /// `--pidfile`: the file with the pid of the init process (absolute)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pid_file: Option<String>,
    /// `--conmon-pidfile`: the file with the pid of the monitor (absolute)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conmon_pid_file: Option<String>,
    /// `--cidfile`: the file with the ID of the container (absolute); it goes
    /// with the container
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cid_file: Option<String>,
    /// `--rootfs`: the directory that is the root file system
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rootfs: Option<RootfsDir>,
    /// The digest the image was named by (`NAME@sha256:...`), kept with what
    /// the container took from the configuration of that image: the root of
    /// the chain an enforced start verifies
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pinned: Option<PinnedImage>,
}

impl ContainerConfig {
    /// The container is thrown away (podman's `Volatile`: `--rm`, and what
    /// the engine asks for, as a build step): its root overlay is mounted
    /// `volatile`.
    pub fn throw_away(&self) -> bool {
        self.auto_remove || self.volatile
    }

    /// The containers this one needs to run before it starts: those it
    /// requires (`--requires`) and those whose pid, ipc, uts, cgroup,
    /// network or user namespace it joins (`container:ID`), as named.
    pub fn dependencies(&self) -> Vec<&str> {
        let o = &self.options;
        let userns = match &self.userns_mode {
            UsernsMode::Container(target) => Some(target.as_str()),
            _ => None,
        };
        let network = match &self.network_mode {
            NetworkMode::Container(target) => Some(target.as_str()),
            _ => None,
        };
        let namespaces = [&o.pid_ns, &o.ipc_ns, &o.uts_ns, &o.cgroup_ns]
            .into_iter()
            .filter_map(|ns| ns.strip_prefix("container:"));
        self.requires
            .iter()
            .map(String::as_str)
            .chain(namespaces)
            .chain(userns)
            .chain(network)
            .collect()
    }
}

/// The image of a container named by a digest: the digest as the user typed
/// it, and what the container took from the configuration of the image.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PinnedImage {
    /// The manifest, or the index the platform manifest was chosen from
    pub digest: velarx_types::digest::Digest,
    /// The settings whose value the image decided
    #[serde(default)]
    pub taken: TakenSettings,
}

/// The settings of a container that have the value the configuration of the
/// image gave (a setting the request changed is not here).  An enforced start
/// takes each of them from the configuration of the image, hashed, and
/// refuses a container that does not have it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TakenSettings {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entrypoint: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cmd: Option<Vec<String>>,
    /// The entries of `Env` that the container has as they are
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub env: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub working_dir: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stop_signal: Option<String>,
    /// The command of the `Healthcheck`
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub healthcheck: Option<Vec<String>>,
    /// The `Volumes` that have a mount in the container
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub volumes: Vec<String>,
}

/// A directory that is the root file system of a container (`--rootfs
/// PATH[:O]`): used as it is, or under an overlay whose upper layer is the
/// container's.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RootfsDir {
    pub path: std::path::PathBuf,
    #[serde(default)]
    pub overlay: bool,
    /// `idmap` or `idmap=uids=..;gids=..` as given
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idmap: Option<String>,
    /// The mappings of the idmapped mount (ids of the directory, ids of the
    /// parent namespace), once worked out
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub uid_mappings: Vec<IdMapping>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub gid_mappings: Vec<IdMapping>,
}

impl RootfsDir {
    /// `PATH`, or `PATH:OPTIONS` with the options separated by commas: `O`,
    /// `idmap` or `idmap=uids=A-B-C;gids=A-B-C`.
    pub fn parse(spec: &str) -> Result<Self, String> {
        let (path, opts) = match spec.rsplit_once(':') {
            Some((p, o)) if !o.is_empty() && !o.contains('/') => (p, o),
            _ => (spec, ""),
        };
        let (mut overlay, mut idmap) = (false, None);
        for o in opts.split(',').filter(|o| !o.is_empty()) {
            match o {
                "O" => overlay = true,
                o if o == "idmap" || o.starts_with("idmap=") => idmap = Some(o.to_string()),
                o => return Err(format!("the rootfs option `{o}` is not supported")),
            }
        }
        let path = std::path::Path::new(path);
        if !path.is_absolute() {
            return Err(format!(
                "the rootfs {} must be an absolute path",
                path.display()
            ));
        }
        let path =
            std::fs::canonicalize(path).map_err(|e| format!("rootfs {}: {e}", path.display()))?;
        if !path.is_dir() {
            return Err(format!("rootfs {} is not a directory", path.display()));
        }
        Ok(Self {
            path,
            overlay,
            idmap,
            uid_mappings: Vec::new(),
            gid_mappings: Vec::new(),
        })
    }

    /// The passwd and group files of the directory, looked up in it.
    pub fn users(&self) -> Result<(Vec<u8>, Vec<u8>), super::userspec::UserError> {
        Ok((self.file("etc/passwd")?, self.file("etc/group")?))
    }

    /// A file of the directory, looked up in it, as the files of a user are
    /// read: empty when it is missing, an error when it is no regular file,
    /// larger than 16 MiB or cannot be read.
    pub fn file(&self, rel: &str) -> Result<Vec<u8>, super::userspec::UserError> {
        super::userspec::read_in_root(&self.path, rel)
    }
}

#[cfg(test)]
mod rootfs_dir_tests {
    use super::RootfsDir;

    #[test]
    fn path_and_options() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().to_str().unwrap();
        let plain = RootfsDir::parse(p).unwrap();
        assert!(!plain.overlay);
        assert!(RootfsDir::parse(&format!("{p}:O")).unwrap().overlay);
        let mapped = RootfsDir::parse(&format!("{p}:O,idmap=uids=0-1-2;gids=0-3-4")).unwrap();
        assert!(mapped.overlay);
        assert_eq!(mapped.idmap.as_deref(), Some("idmap=uids=0-1-2;gids=0-3-4"));
        assert_eq!(
            RootfsDir::parse(&format!("{p}:idmap"))
                .unwrap()
                .idmap
                .as_deref(),
            Some("idmap")
        );
        assert!(RootfsDir::parse(&format!("{p}:Z")).is_err());
        assert!(RootfsDir::parse("relative/dir").is_err());
        assert!(RootfsDir::parse(&format!("{p}/missing")).is_err());
    }

    #[test]
    fn users_are_looked_up_inside_the_directory() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("etc")).unwrap();
        std::fs::write(dir.path().join("etc/passwd"), "root:x:0:0::/root:/bin/sh\n").unwrap();
        // an absolute link leads to the directory's own file, not the host's
        std::os::unix::fs::symlink("/etc/passwd", dir.path().join("etc/group")).unwrap();
        let d = RootfsDir::parse(dir.path().to_str().unwrap()).unwrap();
        let (passwd, group) = d.users().unwrap();
        assert!(passwd.starts_with(b"root:"));
        assert_eq!(group, passwd);
    }

    /// The files of a directory are read as those of a container are: a
    /// missing one is empty, one that is no regular file or is larger than
    /// 16 MiB is an error, and no byte is cut or changed.
    #[test]
    fn files_of_the_directory_are_read_whole_or_refused() {
        let dir = tempfile::tempdir().unwrap();
        let etc = dir.path().join("etc");
        std::fs::create_dir(&etc).unwrap();
        let latin1 = b"a:x:1:1:caf\xe9:/:/bin/sh\n";
        std::fs::write(etc.join("passwd"), latin1).unwrap();
        std::fs::File::create(etc.join("group"))
            .unwrap()
            .set_len((16 << 20) + 1)
            .unwrap();
        rustix::fs::mkfifoat(rustix::fs::CWD, etc.join("hosts"), rustix::fs::Mode::RUSR).unwrap();
        let d = RootfsDir::parse(dir.path().to_str().unwrap()).unwrap();
        assert_eq!(d.file("etc/passwd").unwrap(), latin1);
        assert!(d.file("etc/none").unwrap().is_empty());
        assert!(d.file("etc/group").is_err());
        assert!(d.file("etc/hosts").is_err());
        assert!(d.users().is_err());
    }
}

/// Security configuration
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SecurityConfig {
    /// Seccomp profile (path or JSON, empty = default, "unconfined" = disabled)
    #[serde(default)]
    pub seccomp: String,
    /// AppArmor profile (empty = default, "unconfined" = disabled)
    #[serde(default)]
    pub apparmor: String,
    /// SELinux label
    #[serde(default)]
    pub selinux_label: String,
    /// No new privileges
    #[serde(default)]
    pub no_new_privileges: bool,
    /// Masked paths
    #[serde(default)]
    pub mask_paths: Vec<String>,
    /// Read-only paths (instead of the default ones)
    #[serde(default)]
    pub readonly_paths: Vec<String>,
    /// Paths taken out of the masked and read-only ones (`ALL`: all)
    #[serde(default)]
    pub unmask_paths: Vec<String>,
    /// Options of the /proc mount
    #[serde(default)]
    pub proc_opts: Option<String>,
    /// A compiled seccomp filter (base64), used instead of the profile
    #[serde(default)]
    pub seccomp_bpf: Option<String>,
    /// The AppArmor profile resolved at create time (none: not confined)
    #[serde(default)]
    pub apparmor_profile: Option<String>,
    /// `--security-opt signature=require`: every start of the container
    /// checks that its image has a valid signature
    #[serde(default)]
    pub signature_require: bool,
    /// `--security-opt signature=check`: every start of the container
    /// judges its image by the signature policy of then
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub signature_check: bool,
    /// `--security-opt verity=enforce`: kept with the container, applied at
    /// every start
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub verity_enforce: bool,
    /// `--security-opt verity=off`: kept with the container
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub verity_off: bool,
}

/// Resource configuration
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ResourceConfig {
    /// Memory limit in bytes
    pub memory: Option<i64>,
    /// Memory + swap limit in bytes (-1 for unlimited)
    pub memory_swap: Option<i64>,
    /// Memory reservation (soft limit) in bytes
    pub memory_reservation: Option<i64>,
    /// CPU shares (relative weight)
    pub cpu_shares: Option<u64>,
    /// CPU quota in microseconds per period
    pub cpu_quota: Option<i64>,
    /// CPU period in microseconds
    pub cpu_period: Option<u64>,
    /// CPUset CPUs (e.g., "0,2" or "0-3")
    pub cpuset_cpus: Option<String>,
    /// CPUset memory nodes (NUMA nodes)
    pub cpuset_mems: Option<String>,
    /// Shared memory size (shm-size) in bytes
    #[serde(default)]
    pub shm_size: Option<u64>,
    /// Cgroup v2 arbitrary configuration (KEY=VALUE pairs)
    #[serde(default)]
    pub cgroup_conf: Option<std::collections::HashMap<String, String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub enum UsernsMode {
    #[default]
    Host,
    Private,
    Custom,
    /// Automatically choose: use Private if rootless with subuid available, else Host
    Auto,
    /// Share user namespace with another container
    Container(String),
    /// Join the user namespace at a path
    Path(String),
}

impl UsernsMode {}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ContainerState {
    Created,
    Running,
    Paused,
    Stopped,
}

impl ContainerState {
    pub fn as_str(&self) -> &'static str {
        match self {
            ContainerState::Created => "created",
            ContainerState::Running => "running",
            ContainerState::Paused => "paused",
            ContainerState::Stopped => "stopped",
        }
    }
}

#[derive(Debug, Clone)]
pub struct ContainerStatus {
    pub state: ContainerState,
    pub pid: Option<i32>,
}

pub struct OciRuntime {
    pub runtime_path: PathBuf,
    pub state_dir: PathBuf,
    /// The options of this runtime alone (`[runtimes.NAME] args` of the name
    /// it was asked for with)
    pub own_args: Vec<String>,
}

/// Options for every call of the OCI runtime, set once at startup.
static RUNTIME_ARGS: std::sync::OnceLock<Vec<String>> = std::sync::OnceLock::new();

/// The options of the runtimes of `[runtimes]` that have their own, by name
/// (two names may be the same program with other options).
static RUNTIME_OWN_ARGS: std::sync::OnceLock<std::collections::HashMap<String, Vec<String>>> =
    std::sync::OnceLock::new();

/// The name of `[runtimes]` the configuration gives the default runtime.
static RUNTIME_NAME: std::sync::OnceLock<String> = std::sync::OnceLock::new();

/// The options of the runtime of `[runtimes]` named `name`.
fn own_args_of(name: Option<&str>) -> Vec<String> {
    name.and_then(|n| RUNTIME_OWN_ARGS.get()?.get(n))
        .cloned()
        .unwrap_or_default()
}

/// The OCI runtime the configuration names, set once at startup: a restart
/// of the server (an `exec` again) reads the configuration again.
static RUNTIME: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();

/// Options to pass to the runtime before its command (`--cgroup-manager`...).
pub fn set_runtime_args(args: Vec<String>) {
    let _ = RUNTIME_ARGS.set(args);
}

fn runtime_args() -> &'static [String] {
    RUNTIME_ARGS.get().map_or(&[], |v| v.as_slice())
}

/// What the runtime says of itself with `features` (the OCI runtime-spec
/// features document): the part the engine reads.  Unknown members are
/// ignored.
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Features {
    #[serde(default)]
    potentially_unsafe_config_annotations: Vec<String>,
}

/// How long `features` of a runtime may take.
const RUNTIME_FEATURES_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// The standard output of the runtime at `path` called with `args`, when
/// it succeeds in time and `valid` accepts it, else empty; none when it
/// does not start, fails, or takes longer than [`RUNTIME_FEATURES_TIMEOUT`]
/// (it is asked again).  It is asked once for the file at `path`
/// as it is (its device, inode and time: a runtime replaced in place is
/// asked again; for a wrapper, the wrapper's file).
fn runtime_output(
    path: &Path,
    args: &[&str],
    valid: impl FnOnce(&str) -> Option<String>,
) -> Option<std::sync::Arc<str>> {
    use std::os::unix::fs::MetadataExt;
    type Key = (PathBuf, Vec<String>, u64, u64, i64, i64);
    static KNOWN: std::sync::Mutex<Vec<(Key, std::sync::Arc<str>)>> =
        std::sync::Mutex::new(Vec::new());
    let meta = fs::metadata(path).ok()?;
    let key: Key = (
        path.to_path_buf(),
        args.iter().map(|a| a.to_string()).collect(),
        meta.dev(),
        meta.ino(),
        meta.mtime(),
        meta.mtime_nsec(),
    );
    let known = || {
        let known = KNOWN.lock().unwrap_or_else(|e| e.into_inner());
        known
            .iter()
            .find(|(k, _)| *k == key)
            .map(|(_, t)| t.clone())
    };
    if let Some(text) = known() {
        return Some(text);
    }
    // (not under the lock: a slow runtime holds up no other)
    let out = runtime_stdout(path, args)?;
    let text: std::sync::Arc<str> = valid(&out).unwrap_or_default().into();
    let mut all = KNOWN.lock().unwrap_or_else(|e| e.into_inner());
    if !all.iter().any(|(k, _)| *k == key) {
        all.push((key, text.clone()));
    }
    Some(text)
}

/// The `features` document (JSON) of the OCI runtime at `path`; empty when
/// the runtime has none: a JSON document of the shape of the features, or
/// nothing.  A runtime that does not answer within 5 s has none this time
/// and is asked again the next time.
pub fn runtime_features(path: &Path) -> std::sync::Arc<str> {
    features_output(path).unwrap_or_default()
}

fn features_output(path: &Path) -> Option<std::sync::Arc<str>> {
    runtime_output(path, &["features"], |out| {
        serde_json::from_str::<serde_json::Value>(out)
            .ok()
            .filter(|v| serde_json::from_value::<Features>(v.clone()).is_ok())
            .map(|v| v.to_string())
    })
}

/// Whether the OCI runtime at `path` has crun's own command line and
/// annotations: the global `--cgroup-manager`, `create --config` and
/// `create --no-new-keyring`, and the `run.oci.*` annotations.  The
/// `features` of a runtime do not list them; crun and the runtimes built on
/// it (krun) allow the annotations of the prefix `run.oci.` in
/// `potentiallyUnsafeConfigAnnotations`, and runc and youki do not, so that
/// is what says it.  A runtime with no `features` has none of them.
pub fn has_crun_options(path: &Path) -> bool {
    let probe = || {
        features_output(path).map(|text| {
            serde_json::from_str::<Features>(&text).is_ok_and(|f| {
                f.potentially_unsafe_config_annotations
                    .iter()
                    .any(|a| a == "run.oci.")
            })
        })
    };
    // (kept in the run root: a command is a process of its own)
    let kept = crate::monitor::features::run_root()
        .zip(crate::monitor::features::file_key(path))
        .map(|(run, key)| {
            crate::monitor::features::cached(run, "crun-options", &key, || Ok(probe()))
        });
    kept.unwrap_or_else(|| Ok(probe()))
        .unwrap_or_else(|_| probe())
        .unwrap_or(false)
}

/// The standard output of `path ARGS` when it succeeds in time; none when
/// it cannot be run, fails, or takes longer than [`RUNTIME_FEATURES_TIMEOUT`].
fn runtime_stdout(path: &Path, args: &[&str]) -> Option<String> {
    let mut command = std::process::Command::new(path);
    velarx_base::ids::scrub_runtime_dir(&mut command).ok()?;
    command.args(args);
    velarx_sys::pipe::output_within(command, RUNTIME_FEATURES_TIMEOUT)
}

/// Whether the OCI runtime at `path` takes `create --no-new-keyring`: crun
/// and the runtimes built on it, and runc and youki, which have the option
/// too (their `create --help` lists it).
pub fn has_no_new_keyring(path: &Path) -> bool {
    has_crun_options(path)
        || runtime_output(path, &["create", "--help"], |out| {
            out.contains("--no-new-keyring").then(|| "yes".to_string())
        })
        .is_some_and(|text| !text.is_empty())
}

/// The options `args` as the runtime `path` gets them: without crun's
/// `--cgroup-manager` (the daemon adds it itself) when it does not have it.
pub fn args_for_runtime(path: &Path, args: &[String]) -> Vec<String> {
    // (the runtime is asked only when there is something to leave out)
    let has = args
        .iter()
        .any(|a| a == "--cgroup-manager" || a.starts_with("--cgroup-manager="));
    if !has || has_crun_options(path) {
        return args.to_vec();
    }
    let mut out = Vec::with_capacity(args.len());
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if a == "--cgroup-manager" {
            it.next();
        } else if !a.starts_with("--cgroup-manager=") {
            out.push(a.clone());
        }
    }
    out
}

impl OciRuntime {
    pub fn new(state_dir: PathBuf) -> RuntimeResult<Self> {
        let runtime_path = which_runtime()?;
        fs::create_dir_all(&state_dir)?;
        Ok(Self {
            runtime_path,
            state_dir,
            own_args: own_args_of(RUNTIME_NAME.get().map(String::as_str)),
        })
    }

    /// The OCI runtime at `runtime_path` that was asked for by `name` (of
    /// `[runtimes]`, or a path), with the state directory of this one.
    pub fn with_runtime(&self, runtime_path: PathBuf, name: Option<&str>) -> Self {
        Self {
            runtime_path,
            state_dir: self.state_dir.clone(),
            own_args: own_args_of(name),
        }
    }

    /// The options that go before the command of every call of this
    /// runtime: those of every runtime, then its own.
    pub fn args(&self) -> Vec<String> {
        let mut args = runtime_args().to_vec();
        args.extend(self.own_args.iter().cloned());
        args
    }

    /// A call of this runtime, its options given, with the soft limit of
    /// open files the engine's user gave (a `delete` runs the `poststop`
    /// hooks), as the monitor's calls have it.
    pub fn command(&self) -> io::Result<tokio::process::Command> {
        let mut cmd = tokio::process::Command::new(&self.runtime_path);
        velarx_base::hardening::restore_open_files(
            cmd.as_std_mut(),
            velarx_base::hardening::original_open_files(),
        );
        velarx_base::ids::scrub_runtime_dir(cmd.as_std_mut()).map_err(io::Error::other)?;
        cmd.args(args_for_runtime(&self.runtime_path, &self.args()));
        Ok(cmd)
    }

    pub fn state_dir(&self) -> &Path {
        &self.state_dir
    }

    pub fn runtime_path(&self) -> &Path {
        &self.runtime_path
    }

    /// What this runtime says before its messages (`crun`, `runc`).
    pub fn name(&self) -> String {
        runtime_name_of(&self.runtime_path)
    }

    /// The spec of a container, typed (for tests and tools).
    pub fn generate_spec(
        &self,
        config: &ContainerConfig,
        rootfs_path: &Path,
    ) -> RuntimeResult<Spec> {
        let v = self.generate_spec_json(config, rootfs_path)?;
        serde_json::from_value(v).map_err(|e| RuntimeError::OciSpec(e.to_string()))
    }

    /// The spec of a container as the runtime reads it.  The engine writes
    /// this one: deserializing the typed spec would add 1.5 MB of code to
    /// the daemon.
    pub fn generate_spec_json(
        &self,
        config: &ContainerConfig,
        rootfs_path: &Path,
    ) -> RuntimeResult<serde_json::Value> {
        let mut args = config.command.clone();
        if !config.entrypoint.is_empty() {
            let mut full_args = config.entrypoint.clone();
            full_args.extend(args);
            args = full_args;
        }

        if args.is_empty() {
            args = vec!["/bin/sh".to_string()];
        }

        // the defaults (PATH...) are in the environment the create made
        let mut env = config.env.clone();

        let cwd = if config.working_dir.is_empty() {
            "/"
        } else {
            config.working_dir.as_str()
        };
        let user = match &config.process_user {
            Some(u) => u.clone(),
            None => super::userspec::resolve_user_in_root(
                rootfs_path,
                &config.user,
                &config.group_add,
                config.groups_strict,
            )
            .map_err(|e| RuntimeError::Runtime(e.to_string()))?,
        };
        if !env.iter().any(|e| e.starts_with("HOME=")) {
            env.push(format!("HOME={}", user.home_or(cwd)));
        }
        let capabilities = super::caps::build_capabilities_with_ambient(
            config.privileged,
            &config.cap_add,
            &config.cap_drop,
            &config.cap_ambient,
            user.uid == 0,
        )
        .map_err(RuntimeError::Runtime)?;
        let seccomp = super::seccomp::SeccompMode::from_security_opt(&config.security_opt.seccomp)
            .map_err(|e| RuntimeError::Runtime(e.to_string()))?;
        let confine = confinement(config, &seccomp);
        let mut annotations = HashMap::new();
        if let Some(bpf) = &config.security_opt.seccomp_bpf {
            annotations.insert("run.oci.seccomp_bpf_data".to_string(), bpf.clone());
        }
        if user.keep_groups {
            annotations.insert("run.oci.keep_original_groups".to_string(), "1".to_string());
        }

        let process = ProcessBuilder::default()
            .terminal(config.tty)
            .user(
                UserBuilder::default()
                    .uid(user.uid)
                    .gid(user.gid)
                    .additional_gids(user.additional_gids.clone())
                    .umask(config.umask.unwrap_or(0o022))
                    .build()
                    .oci()?,
            )
            .args(args)
            .env(env)
            .cwd(cwd.to_string())
            .capabilities(capabilities.clone())
            .no_new_privileges(confine.no_new_privileges)
            .build()
            .oci()?;

        let root = RootBuilder::default()
            .path(rootfs_path.to_string_lossy().to_string())
            .readonly(config.read_only_rootfs)
            .build()
            .oci()?;

        let mut mounts = default_mounts();
        let host_sysfs = sysfs_is_a_host_bind(config);
        for m in mounts.iter_mut() {
            match m.destination().to_str() {
                // no sysfs of its own (the kernel refuses it): the host's
                // /sys, read-only unless privileged, as podman binds it
                // (`canMountSys`); /sys/kernel is masked
                Some("/sys") if host_sysfs => {
                    *m = MountBuilder::default()
                        .destination("/sys")
                        .typ("bind".to_string())
                        .source("/sys")
                        .options(
                            [
                                "rprivate",
                                "nosuid",
                                "noexec",
                                "nodev",
                                if confine.sys_readonly { "ro" } else { "rw" },
                                "rbind",
                            ]
                            .map(String::from)
                            .to_vec(),
                        )
                        .build()
                        .oci()?;
                }
                // a privileged container can write to /sys
                Some("/sys") if !confine.sys_readonly => {
                    let opts = m.options().clone().unwrap_or_default();
                    m.set_options(Some(opts.into_iter().filter(|o| o != "ro").collect()));
                }
                // the terminals belong to the group `tty` (5), as podman's:
                // where the container's user namespace maps it
                Some("/dev/pts") if gid_5_is_mapped(config) => {
                    let mut opts = m.options().clone().unwrap_or_default();
                    opts.push("gid=5".to_string());
                    m.set_options(Some(opts));
                }
                Some("/proc") => {
                    if let Some(extra) = &config.security_opt.proc_opts {
                        let mut opts = m.options().clone().unwrap_or_default();
                        opts.extend(extra.split(',').filter(|o| !o.is_empty()).map(String::from));
                        m.set_options(Some(opts));
                    }
                }
                _ => {}
            }
        }
        for m in &config.mounts {
            let mut builder = MountBuilder::default()
                .destination(m.target.clone())
                .source(m.source.clone())
                .options(m.options.clone());
            if let Some(ref typ) = m.mount_type {
                builder = builder.typ(typ.clone());
            }
            let mount = builder.build().oci()?;
            mounts.push(mount);
        }

        let mut namespaces = vec![
            build_namespace(LinuxNamespaceType::Pid)?,
            build_namespace(LinuxNamespaceType::Ipc)?,
            build_namespace(LinuxNamespaceType::Uts)?,
            build_namespace(LinuxNamespaceType::Mount)?,
        ];

        tracing::trace!("generate_spec: network_mode = {:?}", config.network_mode);
        let mut own_netns = true;
        match &config.network_mode {
            NetworkMode::Host => {
                tracing::info!("Using host network mode - not adding network namespace");
                own_netns = false;
            }
            NetworkMode::Off => {
                // (`none`: a namespace of its own, empty)
                namespaces.push(build_namespace(LinuxNamespaceType::Network)?);
            }
            NetworkMode::Container(_) => {
                if let Some(ref ns_path) = config.network_namespace_path {
                    own_netns = false;
                    namespaces.push(build_namespace_with_path(
                        LinuxNamespaceType::Network,
                        ns_path.clone(),
                    )?);
                } else {
                    // (the target does not run yet: the engine puts the path
                    // of its namespace in the spec when this container
                    // starts, and refuses the start if there is none)
                    namespaces.push(build_namespace(LinuxNamespaceType::Network)?);
                }
            }
            _ => match config.network_namespace_path {
                // A namespace the network setup pins (a shareable one).
                Some(ref ns_path) => namespaces.push(build_namespace_with_path(
                    LinuxNamespaceType::Network,
                    ns_path.clone(),
                )?),
                None => namespaces.push(build_namespace(LinuxNamespaceType::Network)?),
            },
        }

        let mut linux_builder = LinuxBuilder::default().namespaces(namespaces.clone());

        if config.userns_mode == UsernsMode::Private || config.userns_mode == UsernsMode::Custom {
            namespaces.push(build_namespace(LinuxNamespaceType::User)?);

            let uid_mappings: Vec<_> = config
                .uid_mappings
                .iter()
                .map(|m| {
                    LinuxIdMappingBuilder::default()
                        .container_id(m.container_id)
                        .host_id(m.host_id)
                        .size(m.size)
                        .build()
                })
                .collect::<Result<Vec<_>, _>>()
                .oci()?;

            let gid_mappings: Vec<_> = config
                .gid_mappings
                .iter()
                .map(|m| {
                    LinuxIdMappingBuilder::default()
                        .container_id(m.container_id)
                        .host_id(m.host_id)
                        .size(m.size)
                        .build()
                })
                .collect::<Result<Vec<_>, _>>()
                .oci()?;

            linux_builder = linux_builder
                .namespaces(namespaces)
                .uid_mappings(uid_mappings)
                .gid_mappings(gid_mappings);
        } else if let (UsernsMode::Container(_) | UsernsMode::Path(_), Some(path)) =
            (&config.userns_mode, &config.userns_path)
        {
            // The mappings are those of the namespace: the runtime must not
            // write them again.
            namespaces.push(build_namespace_with_path(
                LinuxNamespaceType::User,
                path.clone(),
            )?);
            linux_builder = linux_builder.namespaces(namespaces);
        }

        let mut resources_out: Option<oci_spec::runtime::LinuxResources> = None;
        if let Some(resources) = &config.resources {
            let mut resources_builder = LinuxResourcesBuilder::default();

            let mut cpu_builder = LinuxCpuBuilder::default();
            let mut has_cpu = false;

            if let Some(shares) = resources.cpu_shares {
                cpu_builder = cpu_builder.shares(shares);
                has_cpu = true;
            }
            if let Some(quota) = resources.cpu_quota {
                cpu_builder = cpu_builder.quota(quota);
                has_cpu = true;
            }
            if let Some(period) = resources.cpu_period {
                cpu_builder = cpu_builder.period(period);
                has_cpu = true;
            }
            if let Some(ref cpus) = resources.cpuset_cpus {
                cpu_builder = cpu_builder.cpus(cpus.clone());
                has_cpu = true;
            }
            if let Some(ref mems) = resources.cpuset_mems {
                cpu_builder = cpu_builder.mems(mems.clone());
                has_cpu = true;
            }

            if has_cpu {
                let cpu = cpu_builder.build().oci()?;
                resources_builder = resources_builder.cpu(cpu);
            }

            let has_memory = resources.memory.is_some()
                || resources.memory_swap.is_some()
                || resources.memory_reservation.is_some();

            if has_memory {
                let mut memory_builder = LinuxMemoryBuilder::default();
                if let Some(mem) = resources.memory {
                    memory_builder = memory_builder.limit(mem);
                }
                if let Some(swap) = resources.memory_swap {
                    memory_builder = memory_builder.swap(swap);
                }
                if let Some(reservation) = resources.memory_reservation {
                    memory_builder = memory_builder.reservation(reservation);
                }
                let memory = memory_builder.build().oci()?;
                resources_builder = resources_builder.memory(memory);
            }

            if let Some(pids) = config.pids_limit {
                let pids_config = LinuxPidsBuilder::default().limit(pids).build().oci()?;
                resources_builder = resources_builder.pids(pids_config);
            }

            resources_out = Some(resources_builder.build().oci()?);
        } else if let Some(pids) = config.pids_limit {
            let pids_config = LinuxPidsBuilder::default().limit(pids).build().oci()?;
            resources_out = Some(
                LinuxResourcesBuilder::default()
                    .pids(pids_config)
                    .build()
                    .oci()?,
            );
        }
        // The device cgroup: without a list the runtime installs no device
        // program, and a container with CAP_MKNOD could make and open the
        // block devices of the host.  Podman's defaults; a privileged
        // container has every device.
        if confine.deny_all_devices {
            let mut resources = resources_out.take().unwrap_or_default();
            resources.set_devices(Some(default_device_cgroup()?));
            resources_out = Some(resources);
        }
        if let Some(resources) = resources_out {
            linux_builder = linux_builder.resources(resources);
        }

        if !matches!(confine.seccomp, confine_core::Filter::None) {
            let bounding: std::collections::HashSet<String> = capabilities
                .bounding()
                .iter()
                .flatten()
                .map(|c| super::caps::capability_name(*c))
                .collect();
            if let Some(filter) = seccomp
                .to_oci(&bounding)
                .map_err(|e| RuntimeError::Runtime(e.to_string()))?
            {
                linux_builder = linux_builder.seccomp(filter);
            }
        }

        let (masked, readonly) = masked_and_readonly_paths(config, &confine);
        linux_builder = linux_builder.masked_paths(masked).readonly_paths(readonly);

        let mut sysctls = config.sysctls.clone();
        // ping without CAP_NET_RAW, as podman's default_sysctls
        if own_netns && !sysctls.contains_key("net.ipv4.ping_group_range") {
            sysctls.insert("net.ipv4.ping_group_range".into(), "0 0".into());
        }
        linux_builder = linux_builder.sysctl(sysctls);

        if let Some(ref cgroups_path) = config.cgroups_path {
            tracing::info!("Setting OCI spec linux.cgroupsPath to: {}", cgroups_path);
            linux_builder = linux_builder.cgroups_path(cgroups_path.clone());
        } else {
            // No cgroup of its own: the container stays in its monitor's
            // (a rootless daemon, the engine in a unit).
            tracing::debug!("No linux.cgroupsPath for the container");
        }

        let linux = linux_builder.build().oci()?;

        let spec = SpecBuilder::default()
            .version("1.0.2")
            .root(root)
            .process(process)
            .hostname(if config.hostname.is_empty() {
                config.id.clone()
            } else {
                config.hostname.clone()
            })
            .mounts(mounts)
            .linux(linux)
            .annotations(annotations)
            .build()
            .oci()?;

        let mut v = serde_json::to_value(&spec)?;
        if let Some(s) = config
            .selinux
            .as_ref()
            .filter(|_| super::selinux::enabled())
        {
            let (process, mount) =
                super::selinux::labels(s, config.privileged, super::selinux::Contexts::host());
            if let Some(p) = process {
                v["process"]["selinuxLabel"] = serde_json::json!(p);
            }
            if let Some(m) = mount {
                v["linux"]["mountLabel"] = serde_json::json!(m);
            }
        }
        if let Some(p) = &config.security_opt.apparmor_profile {
            v["process"]["apparmorProfile"] = serde_json::json!(p);
        }
        if let Some(mut adj) = config.oom_score_adj {
            // lowering it needs CAP_SYS_RESOURCE of the host: a rootless
            // container gets the current one instead
            if crate::userns::rootless::in_user_namespace()? {
                let current: i32 = std::fs::read_to_string("/proc/self/oom_score_adj")
                    .ok()
                    .and_then(|v| v.trim().parse().ok())
                    .unwrap_or(0);
                if adj < current {
                    tracing::warn!(
                        "Requested oom_score_adj={adj} is lower than the current one, changing to {current}"
                    );
                    adj = current;
                }
            }
            v["process"]["oomScoreAdj"] = serde_json::json!(adj);
        }
        velarx_wire::options::apply(
            &mut v,
            &config.options,
            crate::userns::rootless::in_user_namespace()?,
        )?;
        // no cgroup is made for the container: nothing of the spec names one
        // (a device rule or a limit is applied to a cgroup)
        if config.cgroups == CgroupsMode::Disabled {
            if let Some(linux) = v["linux"].as_object_mut() {
                linux.remove("resources");
                linux.remove("cgroupsPath");
            }
        }
        Ok(v)
    }

    /// Send the signal number `sig` to the init of a container.
    pub async fn kill_signal(&self, id: &str, sig: i32) -> RuntimeResult<()> {
        let output = self
            .command()?
            .arg("--root")
            .arg(&self.state_dir)
            .args(["kill", id, &sig.to_string()])
            .output()
            .await?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if stderr.contains("does not exist") || stderr.contains("not running") {
                return Ok(());
            }
            return Err(RuntimeError::Runtime(format!(
                "Failed to kill container: {}",
                stderr
            )));
        }
        Ok(())
    }

    /// Thaw a paused container.
    pub async fn resume(&self, id: &str) -> RuntimeResult<()> {
        let output = self
            .command()?
            .arg("--root")
            .arg(&self.state_dir)
            .args(["resume", id])
            .output()
            .await?;
        if !output.status.success() {
            return Err(RuntimeError::Runtime(format!(
                "resume: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            )));
        }
        Ok(())
    }

    /// Delete the container `id` of the runtime, which removes its own state:
    /// with `force` a container it does not know is no error (a monitor
    /// deletes its container when it ends).
    /// Whether the runtime still keeps the container `id`: its directory
    /// in the state directory (`--root`) of the runtime, where crun, runc,
    /// youki and krun keep the state of a container until its `delete`.
    pub fn keeps(&self, id: &str) -> bool {
        !id.is_empty() && !id.contains('/') && self.state_dir.join(id).exists()
    }

    pub async fn delete(&self, id: &str, force: bool) -> RuntimeResult<()> {
        let mut args = vec!["--root", self.state_dir.to_str().unwrap(), "delete"];
        if force {
            args.push("--force");
        }
        args.push(id);

        let output = match self.command() {
            Ok(mut command) => command.args(&args).output().await,
            Err(e) => Err(e),
        };
        let output = match output {
            Ok(output) => output,
            // (a runtime that is not installed any more holds no container:
            // the removal of what it made goes on)
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e.into()),
        };

        if !output.status.success() {
            return Err(RuntimeError::Runtime(format!(
                "Failed to delete container: {}",
                String::from_utf8_lossy(&output.stderr)
            )));
        }
        Ok(())
    }

    pub async fn state(&self, id: &str) -> RuntimeResult<ContainerStatus> {
        let output = self
            .command()?
            .args(["--root", self.state_dir.to_str().unwrap(), "state", id])
            .output()
            .await?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if stderr.contains("does not exist") || status_file_is_gone(&stderr) {
                return Err(RuntimeError::NotFound(id.to_string()));
            }
            return Err(RuntimeError::Runtime(format!(
                "Failed to get state: {}",
                stderr
            )));
        }

        #[derive(Deserialize)]
        struct OciState {
            status: String,
            pid: Option<i32>,
        }

        let state: OciState = serde_json::from_slice(&output.stdout)?;

        let container_state = match state.status.as_str() {
            "created" => ContainerState::Created,
            "running" => ContainerState::Running,
            "paused" => ContainerState::Paused,
            "stopped" => ContainerState::Stopped,
            _ => ContainerState::Stopped,
        };

        Ok(ContainerStatus {
            state: container_state,
            pid: state.pid,
        })
    }
}

/// Whether the answer of `state` says that the file with the state of the
/// container is not there: its directory is made before the file and
/// removed after it, so a container that another process is creating or
/// removing is seen without it (crun: "open `.../status`: No such file or
/// directory").  Such a container has no state to report yet, or any more.
fn status_file_is_gone(stderr: &str) -> bool {
    stderr
        .lines()
        .any(|l| l.contains("/status`") && l.trim_end().ends_with("No such file or directory"))
}

/// The OCI runtime the server runs its containers with: the one `--runtime`,
/// or `[server] runtime` names (`Config::default_runtime`), set once at startup; crun, where it is
/// installed, when nothing names one.
pub fn set_runtime_from_config(config: &velarx_config::Config) -> RuntimeResult<()> {
    let _ = RUNTIME_OWN_ARGS.set(config.runtime_args_by_name());
    if let Some(name) = config.default_runtime() {
        let path = config.find_runtime(name).map_err(RuntimeError::Runtime)?;
        let _ = RUNTIME.set(path);
        let _ = RUNTIME_NAME.set(name.to_string());
    }
    Ok(())
}

/// The OCI runtime of the server: the one the configuration names, else
/// crun where it is installed.
pub fn which_runtime() -> RuntimeResult<PathBuf> {
    if let Some(runtime) = RUNTIME.get() {
        return Ok(runtime.clone());
    }
    for path in &["/usr/bin/crun", "/usr/local/bin/crun", "/bin/crun"] {
        let p = PathBuf::from(path);
        if p.exists() {
            return Ok(p);
        }
    }
    Err(RuntimeError::Runtime("crun not found".to_string()))
}

/// The name of the OCI runtime in messages: that of the configured one,
/// else crun.
pub fn runtime_name() -> String {
    which_runtime()
        .ok()
        .and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
        .unwrap_or_else(|| "crun".into())
}

/// The name of the runtime at `path` in messages: its file name.
pub fn runtime_name_of(path: &Path) -> String {
    path.file_name()
        .map_or_else(runtime_name, |n| n.to_string_lossy().into_owned())
}

/// The message of a line runc or youki log on their standard error
/// (`time="..." level=error msg="exec failed: ..."`), unquoted; podman shows
/// the message alone.
fn logged_message(line: &str) -> Option<String> {
    let quoted = line.strip_prefix("time=\"")?.split_once(" msg=\"")?.1;
    let mut msg = String::new();
    let mut chars = quoted.chars();
    while let Some(c) = chars.next() {
        match c {
            '"' => return Some(msg),
            '\\' => match chars.next()? {
                'n' => msg.push('\n'),
                't' => msg.push('\t'),
                c => msg.push(c),
            },
            c => msg.push(c),
        }
    }
    None
}

/// The same for the runtime called `name`: a container made with another
/// runtime of `[runtimes]` has its own name in the message.
pub fn oci_error_for(name: &str, message: &str) -> String {
    oci_failure(name, message).0
}

/// [`oci_error_for`] as the error of a container that could not be started:
/// the one place the words of the runtime are read.
pub fn not_started_for(name: &str, message: &str) -> RuntimeError {
    let (message, command_missing) = oci_failure(name, message);
    RuntimeError::NotStarted {
        command_missing,
        message,
    }
}

/// The message of [`oci_error_for`], and whether the runtime says the
/// command it was to run is not there.
fn oci_failure(name: &str, message: &str) -> (String, bool) {
    let logged: Vec<String> = message.lines().filter_map(logged_message).collect();
    let m = if logged.is_empty() {
        message.trim()
    } else {
        &logged.join("\n")
    };
    let m = m.strip_prefix(&format!("{name}: ")).unwrap_or(m);
    let lower = m.to_lowercase();
    let (cause, command_missing) =
        if lower.contains("permission denied") || lower.contains("operation not permitted") {
            ("OCI permission denied", false)
        } else if lower.contains("no such file or directory") || lower.contains("not found") {
            (
                "OCI runtime attempted to invoke a command that was not found",
                true,
            )
        } else {
            (
                "OCI runtime error",
                lower.contains("executable path is empty"),
            )
        };
    (format!("{name}: {m}: {cause}"), command_missing)
}

fn default_mounts() -> Vec<Mount> {
    vec![
        MountBuilder::default()
            .destination("/proc")
            .typ("proc".to_string())
            .source("proc".to_string())
            .options(vec![
                "nosuid".to_string(),
                "noexec".to_string(),
                "nodev".to_string(),
            ])
            .build()
            .unwrap(),
        MountBuilder::default()
            .destination("/dev")
            .typ("tmpfs".to_string())
            .source("tmpfs".to_string())
            .options(vec![
                "nosuid".to_string(),
                "strictatime".to_string(),
                "mode=755".to_string(),
                "size=65536k".to_string(),
            ])
            .build()
            .unwrap(),
        MountBuilder::default()
            .destination("/dev/pts")
            .typ("devpts".to_string())
            .source("devpts".to_string())
            .options(vec![
                "nosuid".to_string(),
                "noexec".to_string(),
                "newinstance".to_string(),
                "ptmxmode=0666".to_string(),
                "mode=0620".to_string(),
            ])
            .build()
            .unwrap(),
        MountBuilder::default()
            .destination("/dev/shm")
            .typ("tmpfs".to_string())
            .source("shm".to_string())
            .options(vec![
                "nosuid".to_string(),
                "noexec".to_string(),
                "nodev".to_string(),
                "mode=1777".to_string(),
                "size=65536k".to_string(),
            ])
            .build()
            .unwrap(),
        MountBuilder::default()
            .destination("/dev/mqueue")
            .typ("mqueue".to_string())
            .source("mqueue".to_string())
            .options(vec![
                "nosuid".to_string(),
                "noexec".to_string(),
                "nodev".to_string(),
            ])
            .build()
            .unwrap(),
        MountBuilder::default()
            .destination("/sys")
            .typ("sysfs".to_string())
            .source("sysfs".to_string())
            .options(vec![
                "nosuid".to_string(),
                "noexec".to_string(),
                "nodev".to_string(),
                "ro".to_string(),
            ])
            .build()
            .unwrap(),
    ]
}

/// Whether gid 5 is a group of the container's user namespace: mounting
/// devpts with `gid=5` fails where it is not.  A namespace that is joined
/// is not known to map it.
fn gid_5_is_mapped(config: &ContainerConfig) -> bool {
    let covers = |inside: u64, size: u64| inside <= 5 && 5 < inside.saturating_add(size);
    if !config.gid_mappings.is_empty() {
        return config
            .gid_mappings
            .iter()
            .any(|m| covers(u64::from(m.container_id), u64::from(m.size)));
    }
    if matches!(
        config.userns_mode,
        UsernsMode::Container(_) | UsernsMode::Path(_)
    ) {
        return false;
    }
    // (the namespace of the engine: the initial one has the identity map)
    fs::read_to_string("/proc/self/gid_map").is_ok_and(|map| {
        map.lines().any(|l| {
            let mut f = l.split_whitespace().map(|w| w.parse::<u64>().ok());
            matches!((f.next(), f.next(), f.next()), (Some(Some(i)), Some(_), Some(Some(n))) if covers(i, n))
        })
    })
}

/// podman's masked paths (containers/common `DefaultMaskedPaths`), with the
/// thermal throttle directories of the CPUs.
pub fn default_masked_paths() -> Vec<String> {
    let mut paths: Vec<String> = [
        "/proc/acpi",
        "/proc/kcore",
        "/proc/keys",
        "/proc/latency_stats",
        "/proc/sched_debug",
        "/proc/scsi",
        "/proc/timer_list",
        "/proc/timer_stats",
        "/sys/devices/virtual/powercap",
        "/sys/firmware",
        "/sys/fs/selinux",
        "/proc/interrupts",
    ]
    .map(String::from)
    .to_vec();
    if let Ok(dir) = fs::read_dir("/sys/devices/system/cpu") {
        let mut cpus: Vec<String> = dir
            .flatten()
            .filter_map(|e| e.file_name().into_string().ok())
            .filter(|n| {
                n.strip_prefix("cpu")
                    .is_some_and(|i| !i.is_empty() && i.bytes().all(|b| b.is_ascii_digit()))
            })
            .map(|n| format!("/sys/devices/system/cpu/{n}/thermal_throttle"))
            .filter(|p| Path::new(p).exists())
            .collect();
        cpus.sort();
        paths.extend(cpus);
    }
    paths
}

/// podman's read-only paths.
pub fn default_readonly_paths() -> Vec<String> {
    [
        "/proc/asound",
        "/proc/bus",
        "/proc/fs",
        "/proc/irq",
        "/proc/sys",
        "/proc/sysrq-trigger",
    ]
    .map(String::from)
    .to_vec()
}

/// The device cgroup of a container that is not privileged (podman's):
/// everything denied, then the devices of `/dev` a container needs, and
/// mknod of any device (useless without access to it).
fn default_device_cgroup() -> RuntimeResult<Vec<oci_spec::runtime::LinuxDeviceCgroup>> {
    use oci_spec::runtime::{LinuxDeviceCgroupBuilder, LinuxDeviceType};
    let rule =
        |typ: Option<LinuxDeviceType>, major: Option<i64>, minor: Option<i64>, access: &str| {
            let mut b = LinuxDeviceCgroupBuilder::default()
                .allow(true)
                .access(access);
            if let Some(t) = typ {
                b = b.typ(t);
            }
            if let Some(m) = major {
                b = b.major(m);
            }
            if let Some(m) = minor {
                b = b.minor(m);
            }
            b.build().oci()
        };
    let c = Some(LinuxDeviceType::C);
    Ok(vec![
        LinuxDeviceCgroupBuilder::default()
            .allow(false)
            .access("rwm")
            .build()
            .oci()?,
        rule(c, None, None, "m")?,
        rule(Some(LinuxDeviceType::B), None, None, "m")?,
        rule(c, Some(1), Some(3), "rwm")?,    // null
        rule(c, Some(1), Some(5), "rwm")?,    // zero
        rule(c, Some(1), Some(7), "rwm")?,    // full
        rule(c, Some(1), Some(8), "rwm")?,    // random
        rule(c, Some(1), Some(9), "rwm")?,    // urandom
        rule(c, Some(5), Some(0), "rwm")?,    // tty
        rule(c, Some(5), Some(1), "rwm")?,    // console
        rule(c, Some(5), Some(2), "rwm")?,    // ptmx
        rule(c, Some(136), None, "rwm")?,     // pts
        rule(c, Some(10), Some(200), "rwm")?, // net/tun
    ])
}

/// Whether the container cannot have a sysfs of its own: it is in the
/// network namespace of the host and in a user namespace (rootless, or
/// `--userns`), which does not own that network namespace, so the kernel
/// refuses the mount and /sys is a bind of the host's.
fn sysfs_is_a_host_bind(config: &ContainerConfig) -> bool {
    let host_net = config.network_mode.is_host() || config.networks.iter().any(|n| n == "host");
    let own_userns = !rustix::process::geteuid().is_root()
        || crate::userns::rootless::in_user_namespace().unwrap_or(true)
        || !matches!(config.userns_mode, UsernsMode::Host);
    host_net && own_userns
}

/// What `--privileged`, an unconfined seccomp profile, `unmask=` and a host
/// `/sys` turn off (`velarx-confine-core`).
fn confinement(
    config: &ContainerConfig,
    seccomp: &super::seccomp::SeccompMode,
) -> confine_core::Decision {
    use super::seccomp::SeccompMode;
    let so = &config.security_opt;
    confine_core::decide(&confine_core::Request {
        privileged: config.privileged,
        seccomp: match seccomp {
            SeccompMode::Default => confine_core::Seccomp::Default,
            SeccompMode::Unconfined => confine_core::Seccomp::Unconfined,
            SeccompMode::Custom(_) => confine_core::Seccomp::Custom,
        },
        unmask_all: so.unmask_paths.iter().any(|p| p == "ALL"),
        unmask_some: so.unmask_paths.iter().any(|p| p != "ALL"),
        host_sysfs: sysfs_is_a_host_bind(config),
        no_new_privileges: so.no_new_privileges,
    })
}

/// The masked and read-only paths of a container: the defaults the decision
/// keeps (podman's: a list given does not replace them, /proc/sys would be
/// writable) and `mask=` and the read-only paths asked for, which `unmask=`
/// does not take out.
fn masked_and_readonly_paths(
    config: &ContainerConfig,
    confine: &confine_core::Decision,
) -> (Vec<String>, Vec<String>) {
    use confine_core::Paths;
    let so = &config.security_opt;
    let defaults = |paths: Paths, all: Vec<String>| match paths {
        Paths::Default => all,
        Paths::Without => all
            .into_iter()
            .filter(|p| !so.unmask_paths.contains(p))
            .collect(),
        Paths::None => Vec::new(),
    };
    let mut masked = defaults(confine.masked, default_masked_paths());
    // The /sys of a container in the network namespace of the host that has
    // a user namespace is a bind of the host's, whose /sys/kernel is the
    // host's debugfs, tracing and security files; podman masks it as it
    // makes the bind (`canMountSys`).
    if confine.mask_sys_kernel {
        masked.push("/sys/kernel".to_string());
    }
    let mut readonly = defaults(confine.readonly, default_readonly_paths());
    for (list, asked) in [
        (&mut masked, &so.mask_paths),
        (&mut readonly, &so.readonly_paths),
    ] {
        for p in asked {
            if !list.contains(p) {
                list.push(p.clone());
            }
        }
    }
    (masked, readonly)
}

#[cfg(test)]
mod tests {
    #[test]
    fn the_user_of_a_spec_is_read_from_the_spec() {
        let spec = serde_json::json!({"process": {"user":
            {"uid": 1000, "gid": 100, "additionalGids": [100, 44]}}});
        assert_eq!(
            SpecUser::of_spec(&spec),
            Some(SpecUser {
                uid: 1000,
                gid: 100,
                additional_gids: vec![100, 44]
            })
        );
        let plain = serde_json::json!({"process": {"user": {"uid": 0, "gid": 0}}});
        assert_eq!(SpecUser::of_spec(&plain).unwrap().additional_gids.len(), 0);
        assert_eq!(SpecUser::of_spec(&serde_json::json!({})), None);
    }

    use super::*;

    /// A container needs those it requires and those whose namespaces it
    /// joins, not those whose it only shares by path or host.
    #[test]
    fn a_container_depends_on_the_containers_whose_namespaces_it_joins() {
        let mut config = ContainerConfig {
            requires: vec!["r".into()],
            ..Default::default()
        };
        assert_eq!(config.dependencies(), ["r"]);
        config.options.pid_ns = "container:p".into();
        config.options.ipc_ns = "host".into();
        config.options.uts_ns = "container:u".into();
        config.options.cgroup_ns = "/proc/1/ns/cgroup".into();
        config.userns_mode = UsernsMode::Container("x".into());
        config.network_mode = NetworkMode::Container("n".into());
        assert_eq!(config.dependencies(), ["r", "p", "u", "x", "n"]);
    }

    /// A container the runtime keeps has its directory in the state
    /// directory of the runtime until its delete.
    #[test]
    fn the_runtime_keeps_a_container_until_its_delete() {
        let dir = tempfile::tempdir().unwrap();
        let rt = OciRuntime {
            runtime_path: PathBuf::from("/nonexistent/crun"),
            state_dir: dir.path().to_path_buf(),
            own_args: Vec::new(),
        };
        assert!(!rt.keeps("c1"));
        fs::create_dir(dir.path().join("c1")).unwrap();
        assert!(rt.keeps("c1"));
        assert!(!rt.keeps("") && !rt.keeps("../c1"));
    }
    use velarx_base::testing::write_script;

    /// The cgroup mode is stored as its word, and as no word for none.
    #[test]
    fn the_cgroup_mode_is_stored_as_its_word() {
        use velarx_wire::request::CgroupMode;
        let stored = |mode| {
            let config = ContainerConfig {
                cgroup_mode: mode,
                ..Default::default()
            };
            serde_json::to_value(config).unwrap()
        };
        let read = |mut json: serde_json::Value, word: Option<&str>| {
            if let Some(word) = word {
                json["cgroup_mode"] = word.into();
            }
            serde_json::from_value::<ContainerConfig>(json)
        };
        let scope = stored(Some(CgroupMode::Scope));
        assert_eq!(scope["cgroup_mode"], "scope");
        assert_eq!(
            read(scope, None).unwrap().cgroup_mode,
            Some(CgroupMode::Scope)
        );
        let none = stored(None);
        assert!(none.get("cgroup_mode").is_none());
        assert_eq!(read(none.clone(), None).unwrap().cgroup_mode, None);
        assert_eq!(read(none.clone(), Some("")).unwrap().cgroup_mode, None);
        assert!(read(none, Some("x")).is_err());
    }

    /// A call of the runtime by the engine (a `delete` runs the `poststop`
    /// hooks) has the limit of open files the engine's user gave, not the
    /// raised one of the engine.
    #[test]
    fn a_call_of_the_runtime_has_the_limit_of_open_files_of_the_user() {
        velarx_base::testing::in_child(|| {
            rustix::process::setrlimit(
                rustix::process::Resource::Nofile,
                rustix::process::Rlimit {
                    current: Some(256),
                    maximum: Some(4096),
                },
            )
            .unwrap();
            velarx_base::hardening::raise_open_files().unwrap();
            let dir = tempfile::tempdir().unwrap();
            let runtime = dir.path().join("crun");
            let said = dir.path().join("limits");
            write_script(
                &runtime,
                &format!("echo $(ulimit -Sn) $(ulimit -Hn) > {}", said.display()),
            );
            let config: velarx_config::Config = toml::from_str(&format!(
                "[server]\nruntime = \"crun\"\n[runtimes]\ncrun = {runtime:?}\n"
            ))
            .unwrap();
            set_runtime_from_config(&config).unwrap();
            let rt = OciRuntime::new(dir.path().join("state")).unwrap();
            let r = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            r.block_on(rt.delete("c1", true)).unwrap();
            assert_eq!(std::fs::read_to_string(&said).unwrap(), "256 4096\n");
        });
    }

    #[test]
    fn a_container_whose_status_file_is_gone_is_not_found() {
        velarx_base::testing::in_child(|| {
            let dir = tempfile::tempdir().unwrap();
            let runtime = dir.path().join("crun");
            // (what crun answers for a container another process removes)
            write_script(
                &runtime,
                "echo \"open \\`$2/c1/status\\`: No such file or directory\" >&2; exit 1",
            );
            let config: velarx_config::Config = toml::from_str(&format!(
                "[server]\nruntime = \"crun\"\n[runtimes]\ncrun = {runtime:?}\n"
            ))
            .unwrap();
            set_runtime_from_config(&config).unwrap();
            let rt = OciRuntime::new(dir.path().join("state")).unwrap();
            let r = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            assert!(matches!(
                r.block_on(rt.state("c1")),
                Err(RuntimeError::NotFound(_))
            ));
        });
        assert!(!status_file_is_gone(
            "Failed to get state: permission denied"
        ));
        assert!(!status_file_is_gone(
            "open `/x/config.json`: No such file or directory"
        ));
    }

    #[test]
    fn only_a_container_thrown_away_is_volatile() {
        let mut c = ContainerConfig::default();
        assert!(!c.throw_away());
        // (a restart policy does not make it one: podman, `--restart` apart)
        c.restart_policy = Some(RestartSettings {
            policy: velarx_wire::monitor::proto::RestartPolicy::Always,
            max_retries: 0,
        });
        assert!(!c.throw_away());
        c.auto_remove = true;
        assert!(c.throw_away());
        c.auto_remove = false;
        c.volatile = true;
        assert!(c.throw_away());
    }

    #[test]
    fn the_options_of_a_runtime_table_go_to_that_runtime_only() {
        velarx_base::testing::in_child(|| {
            let dir = tempfile::tempdir().unwrap();
            let runsc = dir.path().join("runsc");
            let runc = dir.path().join("runc");
            write_script(&runsc, "echo '--cgroup-manager'");
            std::fs::File::create(&runc).unwrap();
            // (runsc-kvm is the same program with options of its own)
            let config: velarx_config::Config = toml::from_str(&format!(
                "[server]\nruntime = \"runsc\"\n[runtimes]\nrunc = {runc:?}\n\
                 [runtimes.runsc]\npath = {runsc:?}\nargs = [\"--rootless\"]\n\
                 [runtimes.runsc-kvm]\npath = {runsc:?}\nargs = [\"--platform=kvm\"]\n"
            ))
            .unwrap();
            set_runtime_from_config(&config).unwrap();
            set_runtime_args(vec!["--debug".into()]);
            let default = OciRuntime::new(dir.path().join("state")).unwrap();
            assert_eq!(default.runtime_path(), runsc);
            assert_eq!(default.args(), ["--debug", "--rootless"]);
            let kvm = default.with_runtime(runsc.clone(), Some("runsc-kvm"));
            assert_eq!(kvm.args(), ["--debug", "--platform=kvm"]);
            let cmd = kvm.command().unwrap();
            let args: Vec<_> = cmd.as_std().get_args().collect();
            assert_eq!(args, ["--debug", "--platform=kvm"]);
            assert_eq!(
                default.with_runtime(runc.clone(), Some("runc")).args(),
                ["--debug"]
            );
            // (a path names no table)
            assert_eq!(default.with_runtime(runsc, None).args(), ["--debug"]);
        });
    }

    #[test]
    fn the_runtime_of_the_configuration_takes_the_place_of_crun() {
        velarx_base::testing::in_child(|| {
            let dir = tempfile::tempdir().unwrap();
            let runtime = dir.path().join("runc");
            std::fs::File::create(&runtime).unwrap();
            let config: velarx_config::Config =
                toml::from_str(&format!("[server]\nruntime = {:?}\n", runtime)).unwrap();
            set_runtime_from_config(&config).unwrap();
            let rt = OciRuntime::new(dir.path().join("state")).unwrap();
            assert_eq!(rt.runtime_path(), runtime);
            assert_eq!(rt.runtime_path().file_name().unwrap(), "runc");
            assert_eq!(runtime_name(), "runc");
        });
    }

    use velarx_base::testing::{write_runtime, CRUN_FEATURES, KRUN_FEATURES, RUNC_FEATURES};

    #[test]
    fn crun_options_are_there_when_the_features_allow_the_run_oci_annotations() {
        let dir = tempfile::tempdir().unwrap();
        let has = |name: &str, features: Option<&str>| {
            let path = dir.path().join(name);
            write_runtime(&path, features);
            has_crun_options(&path)
        };
        // the real documents of this host; the file name says nothing
        assert!(has("runc", Some(CRUN_FEATURES)));
        assert!(has("krun", Some(KRUN_FEATURES)));
        assert!(!has("crun", Some(RUNC_FEATURES)));
        // a fake runtime that lists the prefix, and one that does not
        assert!(has(
            "with",
            Some(
                r#"{"ociVersionMax":"1.3.0","unknown":[1],"potentiallyUnsafeConfigAnnotations":["x","run.oci."]}"#
            )
        ));
        assert!(!has(
            "without",
            Some(r#"{"potentiallyUnsafeConfigAnnotations":["bundle","run.oci.crun."]}"#)
        ));
        // a feature that is not listed is missing; so is a runtime with no
        // usable `features`
        assert!(!has("nolist", Some("{}")));
        assert!(!has("nocommand", None));
        assert!(!has("silent", Some("")));
        assert!(!has("invalid", Some("{not json")));
        assert!(!has(
            "wrongshape",
            Some(r#"{"potentiallyUnsafeConfigAnnotations":"run.oci."}"#)
        ));
        assert!(!has_crun_options(&dir.path().join("missing")));
        // a runtime that fails after it printed the document has none
        let failing = dir.path().join("failing");
        write_script(
            &failing,
            "echo '{\"potentiallyUnsafeConfigAnnotations\":[\"run.oci.\"]}'; exit 3",
        );
        assert!(!has_crun_options(&failing));
    }

    #[test]
    fn no_new_keyring_is_there_for_crun_options_and_for_a_create_that_lists_it() {
        let dir = tempfile::tempdir().unwrap();
        let path = |name: &str, script: &str| {
            let path = dir.path().join(name);
            write_script(&path, script);
            path
        };
        // (runc and youki: no run.oci. annotations, the option in `create --help`)
        let runc = path(
            "runc",
            "case \"$*\" in features) echo '{}' ;; \"create --help\") echo '--no-new-keyring  do not' ;; esac",
        );
        assert!(!has_crun_options(&runc));
        assert!(has_no_new_keyring(&runc));
        let bare = path("bare", "case \"$*\" in features) echo '{}' ;; esac");
        assert!(!has_no_new_keyring(&bare));
        write_runtime(&dir.path().join("crun"), Some(CRUN_FEATURES));
        assert!(has_no_new_keyring(&dir.path().join("crun")));
        assert!(!has_no_new_keyring(&dir.path().join("missing")));
    }

    #[test]
    fn the_features_are_asked_once_and_again_for_a_replaced_runtime() {
        let dir = tempfile::tempdir().unwrap();
        let asked = dir.path().join("asked");
        let path = dir.path().join("rt");
        write_script(
            &path,
            &format!(
                "echo \"$*\" >> {}; echo '{{\"potentiallyUnsafeConfigAnnotations\":[\"run.oci.\"]}}'",
                asked.display()
            ),
        );
        assert!(has_crun_options(&path));
        assert!(has_crun_options(&path));
        assert_eq!(
            &*runtime_features(&path),
            r#"{"potentiallyUnsafeConfigAnnotations":["run.oci."]}"#
        );
        assert_eq!(std::fs::read_to_string(&asked).unwrap(), "features\n");
        // replaced at the same path
        std::fs::remove_file(&path).unwrap();
        write_runtime(&path, Some(RUNC_FEATURES));
        assert!(!has_crun_options(&path));
    }

    #[test]
    fn a_runtime_that_does_not_answer_its_features_has_none() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hangs");
        // (exec: the sleep is the child that is killed)
        write_script(&path, "exec sleep 30");
        let t = std::time::Instant::now();
        assert!(!has_crun_options(&path));
        assert!(t.elapsed() < std::time::Duration::from_secs(10));
        // (and is asked again the next time)
        write_runtime(&path, Some(CRUN_FEATURES));
        assert!(has_crun_options(&path));
    }

    #[test]
    fn the_cgroup_manager_goes_only_to_a_runtime_with_crun_options() {
        let dir = tempfile::tempdir().unwrap();
        let script = |name: &str, features: Option<&str>| {
            let path = dir.path().join(name);
            write_runtime(&path, features);
            path
        };
        // (the names say nothing)
        let crunlike = script("runc", Some(CRUN_FEATURES));
        let runclike = script("crun", Some(RUNC_FEATURES));
        let nofeatures = script("youki", None);
        let args: Vec<String> = ["--log-level", "warn", "--cgroup-manager", "disabled"]
            .iter()
            .map(|a| a.to_string())
            .collect();
        assert_eq!(args_for_runtime(&crunlike, &args), args);
        for without in [&runclike, &nofeatures] {
            assert_eq!(args_for_runtime(without, &args), ["--log-level", "warn"]);
            assert_eq!(
                args_for_runtime(
                    without,
                    &[
                        "--cgroup-manager=systemd".to_string(),
                        "--debug".to_string()
                    ]
                ),
                ["--debug"]
            );
        }
    }

    #[test]
    fn a_runtime_that_is_not_there_is_refused() {
        let config: velarx_config::Config =
            toml::from_str("[server]\nruntime = \"/no/such/runtime\"\n").unwrap();
        assert!(set_runtime_from_config(&config).is_err());
    }

    #[test]
    fn the_message_names_the_runtime_of_the_container() {
        assert_eq!(
            oci_error_for("runc", "exec failed: executable file not found in $PATH"),
            "runc: exec failed: executable file not found in $PATH: OCI runtime attempted to invoke a command that was not found"
        );
        assert_eq!(runtime_name_of(Path::new("/usr/local/bin/youki")), "youki");
    }

    /// runc's log line on its standard error is its message alone, as
    /// podman shows it (it reads runc's log).
    #[test]
    fn runc_s_logged_line_is_its_message() {
        assert_eq!(
            oci_error_for(
                "runc",
                "time=\"2026-10-31T15:46:57+01:00\" level=error msg=\"exec failed: unable to start container process: exec: \\\"x\\\": executable file not found in $PATH\"\n"
            ),
            "runc: exec failed: unable to start container process: exec: \"x\": executable file not found in $PATH: OCI runtime attempted to invoke a command that was not found"
        );
        assert_eq!(
            oci_error_for(
                "runc",
                "time=\"2026-10-31T15:46:57+01:00\" level=error msg=\"exec failed: unable to start container process: exec: \\\"/etc\\\": is a directory\""
            ),
            "runc: exec failed: unable to start container process: exec: \"/etc\": is a directory: OCI runtime error"
        );
        // (not a log line: as it is)
        assert_eq!(logged_message("msg=\"x\""), None);
    }

    #[test]
    fn a_container_that_did_not_start_says_whether_its_command_is_missing() {
        let missing = |name: &str, m: &str| match not_started_for(name, m) {
            RuntimeError::NotStarted {
                command_missing, ..
            } => command_missing,
            e => panic!("{e}"),
        };
        assert!(missing(
            "crun",
            "executable file `x` not found in $PATH: No such file or directory"
        ));
        assert!(missing(
            "runc",
            "exec failed: executable file not found in $PATH"
        ));
        assert!(missing("crun", "executable path is empty"));
        assert!(!missing(
            "crun",
            "the path `/etc` is not a regular file: Operation not permitted"
        ));
        assert!(!missing("crun", "OOM: the memory limit could be too low"));
        // (the words of the runtime in the message of a failure that is not about the command)
        assert!(!missing(
            "crun",
            "mount of the volume `executable-file-not-found`: Permission denied"
        ));
    }

    #[test]
    fn the_runtime_failures_are_podman_s_words() {
        assert_eq!(
            oci_error_for("crun", "the path `/etc` is not a regular file: Operation not permitted"),
            "crun: the path `/etc` is not a regular file: Operation not permitted: OCI permission denied"
        );
        assert_eq!(
            oci_error_for("crun", "crun: executable file `x` not found in $PATH: No such file or directory"),
            "crun: executable file `x` not found in $PATH: No such file or directory: OCI runtime attempted to invoke a command that was not found"
        );
        assert_eq!(
            oci_error_for("crun", "OOM: the memory limit could be too low\n"),
            "crun: OOM: the memory limit could be too low: OCI runtime error"
        );
    }

    mod resource_config_tests {
        use super::*;

        #[test]
        fn test_resource_config_default() {
            let config = ResourceConfig::default();

            assert!(config.memory.is_none(), "memory should default to None");
            assert!(
                config.memory_swap.is_none(),
                "memory_swap should default to None"
            );
            assert!(
                config.memory_reservation.is_none(),
                "memory_reservation should default to None"
            );
            assert!(
                config.cpu_shares.is_none(),
                "cpu_shares should default to None"
            );
            assert!(
                config.cpu_quota.is_none(),
                "cpu_quota should default to None"
            );
            assert!(
                config.cpu_period.is_none(),
                "cpu_period should default to None"
            );
            assert!(
                config.cpuset_cpus.is_none(),
                "cpuset_cpus should default to None"
            );
            assert!(
                config.cpuset_mems.is_none(),
                "cpuset_mems should default to None"
            );
        }

        #[test]
        fn test_resource_config_with_memory() {
            let config = ResourceConfig {
                memory: Some(536870912),             // 512MB
                memory_swap: Some(1073741824),       // 1GB
                memory_reservation: Some(268435456), // 256MB
                ..Default::default()
            };

            assert_eq!(config.memory, Some(536870912));
            assert_eq!(config.memory_swap, Some(1073741824));
            assert_eq!(config.memory_reservation, Some(268435456));
            assert!(config.cpu_shares.is_none());
        }

        #[test]
        fn test_resource_config_with_cpu() {
            let config = ResourceConfig {
                cpu_shares: Some(1024),
                cpu_quota: Some(150000), // 1.5 CPUs with 100000 period
                cpu_period: Some(100000),
                cpuset_cpus: Some("0,1".to_string()),
                cpuset_mems: Some("0".to_string()),
                ..Default::default()
            };

            assert_eq!(config.cpu_shares, Some(1024));
            assert_eq!(config.cpu_quota, Some(150000));
            assert_eq!(config.cpu_period, Some(100000));
            assert_eq!(config.cpuset_cpus, Some("0,1".to_string()));
            assert_eq!(config.cpuset_mems, Some("0".to_string()));
            assert!(config.memory.is_none());
        }

        #[test]
        fn test_resource_config_clone() {
            let config = ResourceConfig {
                memory: Some(536870912),
                cpu_shares: Some(512),
                ..Default::default()
            };

            let cloned = config.clone();
            assert_eq!(config.memory, cloned.memory);
            assert_eq!(config.cpu_shares, cloned.cpu_shares);
        }

        #[test]
        fn test_resource_config_serialization() {
            let config = ResourceConfig {
                memory: Some(536870912),
                memory_swap: Some(-1), // unlimited
                cpu_shares: Some(1024),
                cpu_quota: Some(200000),
                cpu_period: Some(100000),
                cpuset_cpus: Some("0-3".to_string()),
                cpuset_mems: Some("0,1".to_string()),
                memory_reservation: Some(268435456),
                shm_size: Some(67108864),
                cgroup_conf: None,
            };

            let json = serde_json::to_string(&config).expect("Failed to serialize ResourceConfig");
            let deserialized: ResourceConfig =
                serde_json::from_str(&json).expect("Failed to deserialize ResourceConfig");

            assert_eq!(config.memory, deserialized.memory);
            assert_eq!(config.memory_swap, deserialized.memory_swap);
            assert_eq!(config.memory_reservation, deserialized.memory_reservation);
            assert_eq!(config.cpu_shares, deserialized.cpu_shares);
            assert_eq!(config.cpu_quota, deserialized.cpu_quota);
            assert_eq!(config.cpu_period, deserialized.cpu_period);
            assert_eq!(config.cpuset_cpus, deserialized.cpuset_cpus);
            assert_eq!(config.cpuset_mems, deserialized.cpuset_mems);
        }
    }

    mod cpu_quota_calculation_tests {
        // quota = cpus * period

        const DEFAULT_CPU_PERIOD: u64 = 100000;

        fn calculate_cpu_quota(cpus: f64, period: u64) -> i64 {
            (cpus * period as f64) as i64
        }

        #[test]
        fn test_cpu_quota_one_and_half_cpus() {
            let quota = calculate_cpu_quota(1.5, DEFAULT_CPU_PERIOD);
            assert_eq!(quota, 150000, "--cpus=1.5 should give quota 150000");
        }

        #[test]
        fn test_cpu_quota_two_cpus() {
            let quota = calculate_cpu_quota(2.0, DEFAULT_CPU_PERIOD);
            assert_eq!(quota, 200000, "--cpus=2 should give quota 200000");
        }

        #[test]
        fn test_cpu_quota_half_cpu() {
            let quota = calculate_cpu_quota(0.5, DEFAULT_CPU_PERIOD);
            assert_eq!(quota, 50000, "--cpus=0.5 should give quota 50000");
        }

        #[test]
        fn test_cpu_quota_quarter_cpu() {
            let quota = calculate_cpu_quota(0.25, DEFAULT_CPU_PERIOD);
            assert_eq!(quota, 25000, "--cpus=0.25 should give quota 25000");
        }

        #[test]
        fn test_cpu_quota_four_cpus() {
            let quota = calculate_cpu_quota(4.0, DEFAULT_CPU_PERIOD);
            assert_eq!(quota, 400000, "--cpus=4 should give quota 400000");
        }

        #[test]
        fn test_cpu_quota_custom_period() {
            let custom_period = 10000u64;
            let quota = calculate_cpu_quota(2.0, custom_period);
            assert_eq!(
                quota, 20000,
                "--cpus=2 with period=10000 should give quota 20000"
            );
        }
    }

    mod memory_size_parsing_tests {
        // suffixes k, m, g, in either case

        fn parse_memory_size(s: &str) -> Option<i64> {
            let s = s.trim().to_lowercase();
            let (num_str, multiplier) = if s.ends_with("g") || s.ends_with("gb") {
                (
                    s.trim_end_matches("gb").trim_end_matches("g"),
                    1024i64 * 1024 * 1024,
                )
            } else if s.ends_with("m") || s.ends_with("mb") {
                (
                    s.trim_end_matches("mb").trim_end_matches("m"),
                    1024i64 * 1024,
                )
            } else if s.ends_with("k") || s.ends_with("kb") {
                (s.trim_end_matches("kb").trim_end_matches("k"), 1024i64)
            } else if s.ends_with("b") {
                (s.trim_end_matches("b"), 1i64)
            } else {
                (s.as_str(), 1i64)
            };
            let num: i64 = num_str.parse().ok()?;
            Some(num * multiplier)
        }

        #[test]
        fn test_parse_memory_512m() {
            let result = parse_memory_size("512m");
            assert_eq!(result, Some(536870912), "512m should equal 536870912 bytes");
        }

        #[test]
        fn test_parse_memory_1g() {
            let result = parse_memory_size("1g");
            assert_eq!(result, Some(1073741824), "1g should equal 1073741824 bytes");
        }

        #[test]
        fn test_parse_memory_1024k() {
            let result = parse_memory_size("1024k");
            assert_eq!(
                result,
                Some(1048576),
                "1024k should equal 1048576 bytes (1MB)"
            );
        }

        #[test]
        fn test_parse_memory_case_insensitive_uppercase_m() {
            let result = parse_memory_size("512M");
            assert_eq!(
                result,
                Some(536870912),
                "512M (uppercase) should equal 536870912 bytes"
            );
        }

        #[test]
        fn test_parse_memory_case_insensitive_uppercase_g() {
            let result = parse_memory_size("1G");
            assert_eq!(
                result,
                Some(1073741824),
                "1G (uppercase) should equal 1073741824 bytes"
            );
        }

        #[test]
        fn test_parse_memory_case_insensitive_uppercase_k() {
            let result = parse_memory_size("1024K");
            assert_eq!(
                result,
                Some(1048576),
                "1024K (uppercase) should equal 1048576 bytes"
            );
        }

        #[test]
        fn test_parse_memory_with_gb_suffix() {
            let result = parse_memory_size("2gb");
            assert_eq!(
                result,
                Some(2 * 1024 * 1024 * 1024),
                "2gb should equal 2147483648 bytes"
            );
        }

        #[test]
        fn test_parse_memory_with_mb_suffix() {
            let result = parse_memory_size("256mb");
            assert_eq!(
                result,
                Some(256 * 1024 * 1024),
                "256mb should equal 268435456 bytes"
            );
        }

        #[test]
        fn test_parse_memory_with_kb_suffix() {
            let result = parse_memory_size("512kb");
            assert_eq!(result, Some(512 * 1024), "512kb should equal 524288 bytes");
        }

        #[test]
        fn test_parse_memory_bytes_only() {
            let result = parse_memory_size("1048576");
            assert_eq!(result, Some(1048576), "1048576 should equal 1048576 bytes");
        }

        #[test]
        fn test_parse_memory_with_b_suffix() {
            let result = parse_memory_size("1024b");
            assert_eq!(result, Some(1024), "1024b should equal 1024 bytes");
        }

        #[test]
        fn test_parse_memory_with_whitespace() {
            let result = parse_memory_size("  512m  ");
            assert_eq!(
                result,
                Some(536870912),
                "512m with whitespace should parse correctly"
            );
        }

        #[test]
        fn test_parse_memory_invalid_returns_none() {
            let result = parse_memory_size("invalid");
            assert_eq!(result, None, "invalid input should return None");
        }
    }

    mod oci_spec_resource_tests {
        use super::*;
        use std::path::PathBuf;
        use tempfile::TempDir;

        fn create_test_runtime() -> (OciRuntime, TempDir) {
            let temp_dir = TempDir::new().expect("Failed to create temp dir");
            let runtime = OciRuntime {
                runtime_path: PathBuf::from("/usr/bin/crun"),
                state_dir: temp_dir.path().to_path_buf(),
                own_args: Vec::new(),
            };
            (runtime, temp_dir)
        }

        fn create_test_config() -> ContainerConfig {
            ContainerConfig {
                id: "test-container".to_string(),
                name: Some("test".to_string()),
                image: "alpine".to_string(),
                command: vec!["/bin/sh".to_string()],
                entrypoint: vec![],
                working_dir: "/".to_string(),
                env: vec![],
                labels: HashMap::new(),
                hostname: "test".to_string(),
                runtime: None,
                runtime_name: None,
                user: "0".to_string(),
                group_add: vec![],
                process_user: None,
                spec_user: None,
                umask: None,
                options: Default::default(),
                selinux: None,
                requires: vec![],
                mounts: vec![],
                read_only_rootfs: false,
                privileged: false,
                cap_add: vec![],
                cap_drop: vec![],
                cap_ambient: vec![],
                groups_strict: false,
                userns_mode: UsernsMode::Host,
                userns: String::new(),
                userns_path: None,
                uid_mappings: vec![],
                gid_mappings: vec![],
                tty: false,
                stdin_open: false,
                security_opt: SecurityConfig::default(),
                resources: None,
                pids_limit: None,
                oom_score_adj: None,
                sysctls: HashMap::new(),
                network_mode: NetworkMode::Bridge(None),
                networks: vec![],
                network_namespace_path: None,
                stop_signal: String::new(),
                log_driver: String::new(),
                log_opts: HashMap::new(),
                timeout: None,
                stop_timeout: None,
                healthcheck: None,
                restart_policy: None,
                start_error: None,
                user_error: None,
                sdnotify: String::new(),
                cgroups: CgroupsMode::Unset,
                cgroup_mode: None,
                no_monitor: false,
                cgroups_path: None,
                auto_remove: false,
                auto_remove_image: false,
                volatile: false,
                pid_file: None,
                conmon_pid_file: None,
                cid_file: None,
                rootfs: None,
                pinned: None,
            }
        }

        #[test]
        fn test_spec_with_memory_limits() {
            let (runtime, _temp_dir) = create_test_runtime();
            let rootfs = _temp_dir.path().to_path_buf();

            let mut config = create_test_config();
            config.resources = Some(ResourceConfig {
                memory: Some(536870912),             // 512MB
                memory_swap: Some(1073741824),       // 1GB
                memory_reservation: Some(268435456), // 256MB
                ..Default::default()
            });

            let spec = runtime.generate_spec(&config, &rootfs);
            assert!(spec.is_ok(), "generate_spec should succeed");

            let spec = spec.unwrap();
            let linux = spec.linux().as_ref().expect("Linux config should exist");
            let resources = linux.resources().as_ref().expect("Resources should exist");
            let memory = resources
                .memory()
                .as_ref()
                .expect("Memory config should exist");

            assert_eq!(
                memory.limit(),
                Some(536870912),
                "Memory limit should be 512MB"
            );
            assert_eq!(memory.swap(), Some(1073741824), "Memory swap should be 1GB");
            assert_eq!(
                memory.reservation(),
                Some(268435456),
                "Memory reservation should be 256MB"
            );
        }

        #[test]
        fn test_spec_with_cpu_limits() {
            let (runtime, _temp_dir) = create_test_runtime();
            let rootfs = _temp_dir.path().to_path_buf();

            let mut config = create_test_config();
            config.resources = Some(ResourceConfig {
                cpu_shares: Some(1024),
                cpu_quota: Some(150000),  // 1.5 CPUs
                cpu_period: Some(100000), // 100ms
                cpuset_cpus: Some("0,1".to_string()),
                cpuset_mems: Some("0".to_string()),
                ..Default::default()
            });

            let spec = runtime.generate_spec(&config, &rootfs);
            assert!(spec.is_ok(), "generate_spec should succeed");

            let spec = spec.unwrap();
            let linux = spec.linux().as_ref().expect("Linux config should exist");
            let resources = linux.resources().as_ref().expect("Resources should exist");
            let cpu = resources.cpu().as_ref().expect("CPU config should exist");

            assert_eq!(cpu.shares(), Some(1024), "CPU shares should be 1024");
            assert_eq!(cpu.quota(), Some(150000), "CPU quota should be 150000");
            assert_eq!(cpu.period(), Some(100000), "CPU period should be 100000");
            assert_eq!(
                cpu.cpus().as_deref(),
                Some("0,1"),
                "CPUset CPUs should be 0,1"
            );
            assert_eq!(cpu.mems().as_deref(), Some("0"), "CPUset mems should be 0");
        }

        #[test]
        fn the_host_sysfs_bind_has_no_sys_kernel() {
            let masked = |f: &dyn Fn(&mut ContainerConfig)| {
                let mut config = create_test_config();
                // (a user namespace of its own: the sysfs is a bind of the host's)
                config.userns_mode = UsernsMode::Private;
                f(&mut config);
                masked_and_readonly_paths(
                    &config,
                    &confinement(&config, &crate::container::seccomp::SeccompMode::Default),
                )
                .0
            };
            let sys_kernel = |m: &[String]| m.iter().any(|p| p == "/sys/kernel");
            assert!(sys_kernel(&masked(&|c| c.network_mode = NetworkMode::Host)));
            assert!(sys_kernel(&masked(&|c| c.networks = vec!["host".into()])));
            assert!(!sys_kernel(&masked(
                &|c| c.network_mode = NetworkMode::Bridge(None)
            )));
            assert!(!sys_kernel(&masked(&|c| {
                c.network_mode = NetworkMode::Host;
                c.privileged = true;
            })));
            let unmasked = masked(&|c| {
                c.network_mode = NetworkMode::Host;
                c.security_opt.unmask_paths = vec!["/sys/kernel".into()];
            });
            // no unmask opens it, as in podman: it is not a default path
            assert!(sys_kernel(&unmasked));
            let all = masked(&|c| {
                c.network_mode = NetworkMode::Host;
                c.security_opt.unmask_paths = vec!["ALL".into()];
            });
            assert_eq!(all, ["/sys/kernel"]);
        }

        #[test]
        fn a_host_network_in_a_user_namespace_binds_the_hosts_sys() {
            let (runtime, tmp) = create_test_runtime();
            let sys = |f: &dyn Fn(&mut ContainerConfig)| {
                let mut config = create_test_config();
                config.userns_mode = UsernsMode::Private;
                f(&mut config);
                let spec = runtime.generate_spec(&config, tmp.path()).unwrap();
                let m = spec
                    .mounts()
                    .as_ref()
                    .unwrap()
                    .iter()
                    .find(|m| m.destination() == Path::new("/sys"))
                    .unwrap()
                    .clone();
                (m.typ().clone().unwrap(), m.options().clone().unwrap())
            };
            let (typ, opts) = sys(&|c| c.network_mode = NetworkMode::Bridge(None));
            assert_eq!(typ, "sysfs");
            assert!(opts.contains(&"ro".to_string()), "{opts:?}");
            let (typ, opts) = sys(&|c| c.network_mode = NetworkMode::Host);
            assert_eq!(typ, "bind");
            assert!(
                opts.contains(&"rbind".into()) && opts.contains(&"ro".into()),
                "{opts:?}"
            );
            // (privileged: the bind is writable, a sysfs mount would fail)
            let (typ, opts) = sys(&|c| {
                c.network_mode = NetworkMode::Host;
                c.privileged = true;
            });
            assert_eq!(typ, "bind");
            assert!(
                opts.contains(&"rw".into()) && !opts.contains(&"ro".into()),
                "{opts:?}"
            );
        }

        #[test]
        fn the_terminals_have_the_group_tty_where_it_is_mapped() {
            let pts = |f: &dyn Fn(&mut ContainerConfig)| {
                let (runtime, dir) = create_test_runtime();
                let mut config = create_test_config();
                f(&mut config);
                let spec = runtime.generate_spec(&config, dir.path()).unwrap();
                spec.mounts()
                    .iter()
                    .flatten()
                    .find(|m| m.destination().to_str() == Some("/dev/pts"))
                    .and_then(|m| m.options().clone())
                    .unwrap_or_default()
            };
            let map = |c: u32, h: u32, n: u32| IdMapping {
                container_id: c,
                host_id: h,
                size: n,
            };
            let with = |maps: Vec<IdMapping>| {
                move |c: &mut ContainerConfig| {
                    c.userns_mode = UsernsMode::Private;
                    c.gid_mappings = maps.clone();
                }
            };
            let gid5 = "gid=5".to_string();
            assert!(pts(&with(vec![map(0, 100000, 65536)])).contains(&gid5));
            assert!(!pts(&with(vec![map(0, 1000, 1)])).contains(&gid5));
            assert!(pts(&with(vec![map(0, 1000, 1), map(1, 100000, 10)])).contains(&gid5));
            assert!(!pts(&|c| c.userns_mode = UsernsMode::Container("x".into())).contains(&gid5));
        }

        #[test]
        fn test_spec_with_pids_limit() {
            let (runtime, _temp_dir) = create_test_runtime();
            let rootfs = _temp_dir.path().to_path_buf();

            let mut config = create_test_config();
            config.pids_limit = Some(100);

            let spec = runtime.generate_spec(&config, &rootfs);
            assert!(spec.is_ok(), "generate_spec should succeed");

            let spec = spec.unwrap();
            let linux = spec.linux().as_ref().expect("Linux config should exist");
            let resources = linux.resources().as_ref().expect("Resources should exist");
            let pids = resources.pids().as_ref().expect("Pids config should exist");

            assert_eq!(pids.limit(), 100, "Pids limit should be 100");
        }

        #[test]
        fn test_spec_with_pids_limit_and_resources() {
            let (runtime, _temp_dir) = create_test_runtime();
            let rootfs = _temp_dir.path().to_path_buf();

            let mut config = create_test_config();
            config.resources = Some(ResourceConfig {
                memory: Some(536870912), // 512MB
                ..Default::default()
            });
            config.pids_limit = Some(200);

            let spec = runtime.generate_spec(&config, &rootfs);
            assert!(spec.is_ok(), "generate_spec should succeed");

            let spec = spec.unwrap();
            let linux = spec.linux().as_ref().expect("Linux config should exist");
            let resources = linux.resources().as_ref().expect("Resources should exist");

            let memory = resources
                .memory()
                .as_ref()
                .expect("Memory config should exist");
            assert_eq!(
                memory.limit(),
                Some(536870912),
                "Memory limit should be 512MB"
            );

            let pids = resources.pids().as_ref().expect("Pids config should exist");
            assert_eq!(pids.limit(), 200, "Pids limit should be 200");
        }

        #[test]
        fn test_the_devices_are_denied_but_the_defaults() {
            let (runtime, _temp_dir) = create_test_runtime();
            let rootfs = _temp_dir.path().to_path_buf();
            let mut config = create_test_config();
            let spec = runtime.generate_spec(&config, &rootfs).unwrap();
            let devices = spec.linux().as_ref().unwrap().resources().as_ref().unwrap();
            let devices = devices.devices().as_ref().expect("a device cgroup");
            assert!(!devices[0].allow() && devices[0].typ().is_none());
            assert_eq!(devices[0].access().as_deref(), Some("rwm"));
            // No block device but mknod, and /dev/null.
            assert!(devices.iter().all(|d| !d.allow()
                || d.typ() != Some(oci_spec::runtime::LinuxDeviceType::B)
                || d.access().as_deref() == Some("m")));
            assert!(devices
                .iter()
                .any(|d| d.allow() && d.major() == Some(1) && d.minor() == Some(3)));

            config.privileged = true;
            let spec = runtime.generate_spec(&config, &rootfs).unwrap();
            let resources = spec.linux().as_ref().unwrap().resources().as_ref();
            // No rule at all: the runtime installs no device program.
            assert!(resources
                .and_then(|r| r.devices().as_ref())
                .is_none_or(|d| d.is_empty()));
        }

        #[test]
        fn test_spec_without_cgroups_names_no_cgroup() {
            let (runtime, _temp_dir) = create_test_runtime();
            let rootfs = _temp_dir.path().to_path_buf();

            let mut config = create_test_config();
            let linux = |c: &ContainerConfig| {
                runtime.generate_spec_json(c, &rootfs).unwrap()["linux"].clone()
            };
            // (the device rules of an unprivileged container are a resource)
            assert!(linux(&config).get("resources").is_some());
            config.cgroups = CgroupsMode::Disabled;
            config.cgroups_path = Some("/x/y".into());
            let l = linux(&config);
            assert!(l.get("resources").is_none(), "{l}");
            assert!(l.get("cgroupsPath").is_none(), "{l}");
        }

        #[test]
        fn test_spec_without_resources() {
            let (runtime, _temp_dir) = create_test_runtime();
            let rootfs = _temp_dir.path().to_path_buf();

            let config = create_test_config();

            let spec = runtime.generate_spec(&config, &rootfs);
            assert!(spec.is_ok(), "generate_spec should succeed");

            let spec = spec.unwrap();
            let linux = spec.linux().as_ref().expect("Linux config should exist");

            if let Some(resources) = linux.resources() {
                assert!(
                    resources.memory().is_none(),
                    "Memory should not be set without resources config"
                );
                assert!(
                    resources.cpu().is_none(),
                    "CPU should not be set without resources config"
                );
            }
        }

        #[test]
        fn test_spec_with_all_resources() {
            let (runtime, _temp_dir) = create_test_runtime();
            let rootfs = _temp_dir.path().to_path_buf();

            let mut config = create_test_config();
            config.resources = Some(ResourceConfig {
                memory: Some(1073741824),            // 1GB
                memory_swap: Some(2147483648),       // 2GB
                memory_reservation: Some(536870912), // 512MB
                cpu_shares: Some(2048),
                cpu_quota: Some(200000),  // 2 CPUs
                cpu_period: Some(100000), // 100ms
                cpuset_cpus: Some("0-3".to_string()),
                cpuset_mems: Some("0,1".to_string()),
                shm_size: None,
                cgroup_conf: None,
            });
            config.pids_limit = Some(500);

            let spec = runtime.generate_spec(&config, &rootfs);
            assert!(spec.is_ok(), "generate_spec should succeed");

            let spec = spec.unwrap();
            let linux = spec.linux().as_ref().expect("Linux config should exist");
            let resources = linux.resources().as_ref().expect("Resources should exist");

            let memory = resources
                .memory()
                .as_ref()
                .expect("Memory config should exist");
            assert_eq!(memory.limit(), Some(1073741824));
            assert_eq!(memory.swap(), Some(2147483648));
            assert_eq!(memory.reservation(), Some(536870912));

            let cpu = resources.cpu().as_ref().expect("CPU config should exist");
            assert_eq!(cpu.shares(), Some(2048));
            assert_eq!(cpu.quota(), Some(200000));
            assert_eq!(cpu.period(), Some(100000));
            assert_eq!(cpu.cpus().as_deref(), Some("0-3"));
            assert_eq!(cpu.mems().as_deref(), Some("0,1"));

            let pids = resources.pids().as_ref().expect("Pids config should exist");
            assert_eq!(pids.limit(), 500);
        }

        #[test]
        fn test_spec_with_unlimited_memory_swap() {
            let (runtime, _temp_dir) = create_test_runtime();
            let rootfs = _temp_dir.path().to_path_buf();

            let mut config = create_test_config();
            config.resources = Some(ResourceConfig {
                memory: Some(536870912), // 512MB
                memory_swap: Some(-1),   // Unlimited swap
                ..Default::default()
            });

            let spec = runtime.generate_spec(&config, &rootfs);
            assert!(spec.is_ok(), "generate_spec should succeed");

            let spec = spec.unwrap();
            let linux = spec.linux().as_ref().expect("Linux config should exist");
            let resources = linux.resources().as_ref().expect("Resources should exist");
            let memory = resources
                .memory()
                .as_ref()
                .expect("Memory config should exist");

            assert_eq!(
                memory.swap(),
                Some(-1),
                "Memory swap -1 should mean unlimited"
            );
        }

        /// The confinement of every combination of the options that decide
        /// it, as the spec of the engine has it today.
        #[test]
        fn the_confinement_of_every_combination_of_options() {
            use crate::container::seccomp::SeccompMode;
            let (runtime, tmp) = create_test_runtime();
            let profile = r#"{"defaultAction":"SCMP_ACT_ERRNO"}"#;
            let default_masked = default_masked_paths();
            let default_readonly = default_readonly_paths();
            let sorted = |mut v: Vec<String>| {
                v.sort();
                v
            };
            for flags in 0..2u32.pow(5) {
                let (privileged, host_sysfs, nnp, read_only, root) = (
                    flags & 1 != 0,
                    flags & 2 != 0,
                    flags & 4 != 0,
                    flags & 8 != 0,
                    flags & 16 != 0,
                );
                for seccomp in ["", "unconfined", profile] {
                    // unmask=, mask=, the read-only paths asked for
                    let lists: [(&[&str], &[&str], &[&str]); 6] = [
                        (&[], &[], &[]),
                        (&["/proc/kcore", "/proc/sys"], &[], &[]),
                        // what is asked for stays, whatever is unmasked
                        (
                            &["/proc/kcore", "/proc/sys"],
                            &["/proc/kcore"],
                            &["/proc/sys"],
                        ),
                        (&["ALL"], &[], &[]),
                        (&["ALL"], &["/x"], &["/y"]),
                        (&["/sys/kernel"], &[], &[]),
                    ];
                    for (unmask, mask, ro) in lists {
                        let mut config = create_test_config();
                        config.privileged = privileged;
                        config.read_only_rootfs = read_only;
                        config.user = if root { "0" } else { "1000" }.into();
                        config.userns_mode = UsernsMode::Private;
                        if host_sysfs {
                            config.network_mode = NetworkMode::Host;
                        }
                        config.security_opt.no_new_privileges = nnp;
                        config.security_opt.seccomp = seccomp.into();
                        let owned = |v: &[&str]| v.iter().map(|p| p.to_string()).collect();
                        config.security_opt.unmask_paths = owned(unmask);
                        config.security_opt.mask_paths = owned(mask);
                        config.security_opt.readonly_paths = owned(ro);
                        let what = format!(
                            "privileged {privileged} seccomp {seccomp:?} unmask {unmask:?} mask {mask:?} \
                             host sysfs {host_sysfs} nnp {nnp} read-only {read_only} root {root}"
                        );
                        let spec = runtime.generate_spec(&config, tmp.path()).unwrap();
                        let linux = spec.linux().as_ref().unwrap();

                        // the device cgroup: all denied first, but for a
                        // privileged container
                        let devices = linux.resources().as_ref().and_then(|r| r.devices().clone());
                        match (privileged, devices) {
                            (false, Some(d)) => assert!(
                                !d[0].allow() && d[0].typ().is_none(),
                                "deny all first: {what}"
                            ),
                            (true, d) => assert!(d.is_none_or(|d| d.is_empty()), "{what}"),
                            (false, None) => panic!("no device rules: {what}"),
                        }

                        // seccomp: the default profile is not for a
                        // privileged container, an explicit one is for all
                        let mode = SeccompMode::from_security_opt(seccomp).unwrap();
                        let filtered = match mode {
                            SeccompMode::Unconfined => false,
                            SeccompMode::Default => !privileged,
                            SeccompMode::Custom(_) => true,
                        };
                        assert_eq!(linux.seccomp().is_some(), filtered, "seccomp: {what}");

                        // the paths: none for a privileged container, the
                        // defaults less those unmasked, none for ALL
                        // and what was asked for, unmasked or not
                        let kept = |defaults: &[String], asked: &[&str]| -> Vec<String> {
                            let mut v: Vec<String> = if privileged || unmask == ["ALL"] {
                                Vec::new()
                            } else {
                                defaults
                                    .iter()
                                    .filter(|p| !unmask.contains(&p.as_str()))
                                    .cloned()
                                    .collect()
                            };
                            for p in asked {
                                if !v.iter().any(|q| q == p) {
                                    v.push(p.to_string());
                                }
                            }
                            v
                        };
                        let mut masked = kept(&default_masked, mask);
                        // (whatever is unmasked, `ALL` and the path itself
                        // too: the mask is not one of the defaults, as in
                        // podman)
                        if !privileged && host_sysfs {
                            masked.push("/sys/kernel".into());
                        }
                        assert_eq!(
                            sorted(linux.masked_paths().clone().unwrap_or_default()),
                            sorted(masked),
                            "masked: {what}"
                        );
                        assert_eq!(
                            sorted(linux.readonly_paths().clone().unwrap_or_default()),
                            sorted(kept(&default_readonly, ro)),
                            "read-only: {what}"
                        );

                        // the rest is what was asked
                        let process = spec.process().as_ref().unwrap();
                        assert_eq!(process.no_new_privileges(), Some(nnp), "{what}");
                        assert_eq!(spec.root().as_ref().unwrap().readonly(), Some(read_only));
                        let sys = spec
                            .mounts()
                            .iter()
                            .flatten()
                            .find(|m| m.destination() == Path::new("/sys"))
                            .unwrap();
                        let opts = sys.options().clone().unwrap();
                        assert_eq!(
                            sys.typ().as_deref(),
                            Some(if host_sysfs { "bind" } else { "sysfs" }),
                            "{what}"
                        );
                        assert_eq!(
                            opts.contains(&"ro".to_string()),
                            !privileged,
                            "/sys: {what}"
                        );
                        assert_eq!(opts.contains(&"rw".to_string()), privileged && host_sysfs);
                    }
                }
            }
        }
    }
}
