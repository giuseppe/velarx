// SPDX-License-Identifier: Apache-2.0
use crate::container::{
    ContainerConfig, IdMapping, MountConfig, OciRuntime, ResourceConfig, SecurityConfig, UsernsMode,
};
use crate::network::provider::Providers;
use crate::services::cgroup::CgroupManager;
use crate::services::network::NetworkManager;
use crate::services::{ImageService, MountSpec, SignatureJudging, VolumeError, VolumeService};
use crate::storage_driver::{Writable, WritableOptions};
use crate::userns::{UserNamespaceManager, UsernsRequest};
use futures::StreamExt;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::Read;
use std::os::fd::AsFd;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use thiserror::Error;
use tracing::{debug, info, warn};
use velarx_base::idmap::UsernsSpec;
use velarx_db::{ContainerRecord, Database, LayerRecord, RecordState};
use velarx_wire::request::NetworkMode;
use velarx_wire::request::*;
pub use velarx_wire::wire::{ContainerStats, TopResult};

mod bundle;
mod commit;
mod create;
mod mounts;
mod options;
mod stats;
mod top;
pub use bundle::*;
pub use commit::*;
use mounts::*;
use options::*;
pub use top::*;

#[derive(Error, Debug)]
pub enum ContainerError {
    #[error("container not found: {0}")]
    NotFound(String),
    #[error("{0}")]
    AlreadyExists(String),
    #[error("container not running: {0}")]
    NotRunning(String),
    #[error("container {0} lost its monitor: exec and attach are unavailable until it is restarted (stop and kill still work)")]
    MonitorLost(String),
    /// Its monitor is of another version of velarx (it outlived an
    /// upgrade): it is followed until it ends, nothing else is asked of it.
    #[error("container {id}: {reason}")]
    MonitorVersion { id: String, reason: String },
    #[error("container already running: {0}")]
    AlreadyRunning(String),
    #[error("image not found: {0}")]
    ImageNotFound(String),
    #[error("{0}")]
    Runtime(#[from] crate::container::RuntimeError),
    #[error(transparent)]
    Database(#[from] velarx_types::DbError),
    #[error("image error: {0}")]
    Image(#[from] velarx_types::ImageError),
    #[error("userns error: {0}")]
    Userns(#[from] crate::userns::UsernsError),
    #[error("{0}")]
    Volume(#[from] VolumeError),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("{0}")]
    Ids(#[from] velarx_base::ids::IdsError),
    #[error("lazy image error: {0}")]
    LazyImage(String),
    #[error("not supported: {0}")]
    Unsupported(String),
    #[error("{0}")]
    Network(#[from] velarx_netkernel::error::NetworkError),
    #[error("{0}")]
    InvalidArgument(String),
    /// Every pick of a SELinux level was taken by a container created at
    /// the same time.
    #[error("cannot pick a free SELinux level: {0} picks in a row were taken by containers created at the same time; try again")]
    LevelsTaken(u32),
    /// The container has no checkpoint to restore
    #[error("{0}")]
    NoCheckpoint(String),
    /// The log driver of the container keeps no log to read (or attach to):
    /// what is said, and podman's cause of it
    #[error("{message}")]
    NoLogs { message: String, cause: String },
}

/// How many runtimes a listing asks at once.
const REFRESH_AT_ONCE: usize = 16;

/// podman's cause of a read or an attach of a container that logs nothing.
pub const NOT_LOGGING: &str = "this container is not logging output";

/// The mounts every container gets from the engine: a working directory on
/// them is the runtime's to judge.
const ENGINE_MOUNTS: &[&str] = &[
    "/dev",
    "/proc",
    "/sys",
    "/etc/hosts",
    "/etc/hostname",
    "/etc/resolv.conf",
    "/run/.containerenv",
];

/// The names podman accepts for a container.
fn valid_container_name(name: &str) -> bool {
    let mut chars = name.chars();
    chars.next().is_some_and(|c| c.is_ascii_alphanumeric())
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
}

impl ContainerError {
    /// The container cannot start: what it runs with (its user, its working
    /// directory) is not there.
    pub fn not_started(message: String) -> Self {
        Self::Runtime(crate::container::RuntimeError::NotStarted {
            command_missing: false,
            message,
        })
    }

    /// The condition of the engine's interface the error is, when its status
    /// does not say it.
    pub fn condition(&self) -> Option<velarx_proto::engine::Condition> {
        use velarx_proto::engine::Condition;
        match self {
            Self::Runtime(crate::container::RuntimeError::NotStarted {
                command_missing, ..
            }) => Some(if *command_missing {
                Condition::CommandNotFound
            } else {
                Condition::NotStarted
            }),
            Self::Network(velarx_netkernel::error::NetworkError::UnsupportedProtocol(_)) => {
                Some(Condition::NotStarted)
            }
            Self::Network(
                velarx_netkernel::error::NetworkError::NoPasta { .. }
                | velarx_netkernel::error::NetworkError::OldPasta { .. },
            ) => Some(Condition::NoPasta),
            Self::NoCheckpoint(_) => Some(Condition::NoCheckpoint),
            Self::Unsupported(_) => Some(Condition::NotSupported),
            _ => None,
        }
    }
}

impl From<crate::container::userspec::UserError> for ContainerError {
    fn from(e: crate::container::userspec::UserError) -> Self {
        use crate::container::userspec::UserError as U;
        match e {
            U::NoUser(_) | U::NoGroup(_) | U::NoHostUser(_) => Self::not_started(e.to_string()),
            e => Self::InvalidArgument(e.to_string()),
        }
    }
}

pub type ContainerResult<T> = Result<T, ContainerError>;

/// An id as the engine makes them: 64 lowercase hexadecimal digits.
pub fn valid_container_id(id: &str) -> bool {
    id.len() == 64 && id.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// The ID of a new container or pod: 256 random bits.  Commands in several
/// processes of one store make containers of the same image at the same
/// time, so nothing they share (the image, the clock) can make the ID.
pub fn new_id() -> String {
    let mut bits = [0u8; 32];
    let mut filled = 0;
    // (the kernel's pool gives up to 256 bytes at once once it is ready;
    // only a wait for it at boot can be interrupted)
    while filled < bits.len() {
        match rustix::rand::getrandom(&mut bits[filled..], rustix::rand::GetRandomFlags::empty()) {
            Ok(n) => filled += n,
            Err(rustix::io::Errno::INTR) => {}
            Err(e) => panic!("getrandom: {e}"),
        }
    }
    hex::encode(bits)
}

/// Remove the anonymous volumes of a container that is gone, unless another
/// container uses them.
pub(crate) async fn remove_anonymous_volumes(volumes: &VolumeService, config: &ContainerConfig) {
    for name in config.mounts.iter().filter_map(|m| m.volume.as_deref()) {
        match volumes.get(name).await {
            Ok(v) if v.state.anonymous => {
                if let Err(e) = volumes.remove(name, false).await {
                    debug!("The anonymous volume {name} stays: {e}");
                }
            }
            _ => {}
        }
    }
}

/// Check if any of the configured networks match the given mode (for ContainerConfig)
pub(crate) fn config_has_network_mode(config: &ContainerConfig, mode: &NetworkMode) -> bool {
    NetworkMode::has(&config.networks, &config.network_mode, mode)
}

/// The configuration stored with a container.  A record whose configuration
/// does not parse is an error: a default one would stop the container with
/// the wrong signal, use the wrong runtime or forget its restart policy.
pub(crate) fn stored_config(rec: &ContainerRecord) -> ContainerResult<ContainerConfig> {
    serde_json::from_str(&rec.config).map_err(|e| {
        ContainerError::InvalidArgument(format!(
            "the configuration of container {} is not valid: {e}",
            rec.id
        ))
    })
}

/// A runtime of the containers: its path and the name it was asked for with.
type RuntimeKey = (PathBuf, Option<String>);

pub struct ContainerService {
    pub(crate) db: Database,
    pub(crate) runtime: Arc<OciRuntime>,
    /// The other OCI runtimes in use (`[runtimes]`), by path and name
    other_runtimes: std::sync::Mutex<std::collections::HashMap<RuntimeKey, Arc<OciRuntime>>>,
    pub(crate) image_service: Arc<ImageService>,
    pub(crate) userns_manager: Arc<UserNamespaceManager>,
    pub(crate) lifecycle: super::lifecycle::Lifecycle,
    pub root_dir: PathBuf,
    pub(crate) state_dir: PathBuf,
    pub cgroup_manager: Option<Arc<CgroupManager>>,
    pub(crate) network_manager: Arc<NetworkManager>,
    /// The network providers of the configuration
    pub(crate) network_providers: Providers,
    pub(crate) containers_config: velarx_config::ContainersConfig,
    /// `[containers] base_hosts_file`: the file whose entries the
    /// /etc/hosts of the containers starts with.
    base_hosts_file: Option<PathBuf>,
    /// The configuration monitors serve rootless root file systems with.
    pub(crate) monitor_env: Option<Box<velarx_config::Config>>,
    /// The monitors of the containers are started by the process that
    /// supervises them (the caller's cgroup and output), not by the server.
    pub(crate) caller_supervised: bool,
    pub(crate) volume_service: Arc<VolumeService>,
    /// How this process starts monitors.
    pub(crate) supervision: super::supervise::Supervision,
    /// The slices of the pods that have limits (systemd cgroup parent).
    pub(crate) pod_slices: Arc<velarx_runtime::pods::slice::Slices>,
    /// The `--cgroups` mode of a container that asks for none
    /// (`[containers] cgroups` of the configuration, `cgroups_mode::conf_default`).
    pub(crate) default_cgroups: CgroupsMode,
    /// The `scope` or `unit` of a container that asks for none (`[containers]
    /// cgroups`).
    pub(crate) default_scope: bool,
}

/// What a [`ContainerService`] is made of.
pub struct ContainerParts {
    pub db: Database,
    pub image_service: Arc<ImageService>,
    pub userns_manager: Arc<UserNamespaceManager>,
    pub root_dir: PathBuf,
    pub state_dir: PathBuf,
    pub cgroup_manager: Option<Arc<CgroupManager>>,
    pub network_providers: Providers,
    pub volume_service: Arc<VolumeService>,
}

/// The annotations podman records of `--security-opt` (what inspect's
/// `HostConfig.SecurityOpt` shows): `io.podman.annotations.label`, the
/// `label=` values joined with `,label=`, and `io.podman.annotations.apparmor`.
/// (`seccomp=` is not: the client sends the profile, not its path.)
pub fn podman_security_annotations(opts: &[String]) -> Vec<(String, String)> {
    let given = |key: &str| -> Vec<&str> {
        opts.iter()
            .filter_map(|o| o.split_once(['=', ':']))
            .filter(|(k, v)| *k == key && *v != "nested")
            .map(|(_, v)| v)
            .collect()
    };
    [
        ("label", given("label").join(",label=")),
        (
            "apparmor",
            given("apparmor")
                .last()
                .copied()
                .unwrap_or_default()
                .to_string(),
        ),
    ]
    .into_iter()
    .filter(|(_, v)| !v.is_empty())
    .map(|(k, v)| (format!("io.podman.annotations.{k}"), v))
    .collect()
}

impl ContainerService {
    /// How the signature policy judges the image of a container: the
    /// configuration (`[containers] image_signature`) or the request
    /// (`--security-opt signature=`).  A request for less than the
    /// configuration is an error.
    pub(crate) fn signature_judging(
        &self,
        base: &velarx_proto::request::SecurityOptions,
        opts: &[String],
    ) -> ContainerResult<SignatureJudging> {
        let mut so = base.clone();
        for o in opts {
            so.apply(o).map_err(ContainerError::InvalidArgument)?;
        }
        let configured = self.containers_config.image_signature == "require";
        match (so.signature.as_deref(), configured) {
            (Some("check"), true) => Err(ContainerError::InvalidArgument(
                "--security-opt signature=check: [containers] image_signature is \"require\", \
                 a container cannot ask for less"
                    .into(),
            )),
            (_, true) => Ok(SignatureJudging::Require(
                "[containers] image_signature is \"require\"",
            )),
            (Some("require"), false) => Ok(SignatureJudging::Require(
                "--security-opt signature=require",
            )),
            (Some("check"), false) => Ok(SignatureJudging::Check),
            _ => Ok(SignatureJudging::Policy),
        }
    }

    pub fn new(parts: ContainerParts) -> ContainerResult<Self> {
        let ContainerParts {
            db,
            image_service,
            userns_manager,
            root_dir,
            state_dir,
            cgroup_manager,
            network_providers,
            volume_service,
        } = parts;
        // (absolute: the OCI runtime takes no relative path)
        let state_dir = if state_dir.is_absolute() {
            state_dir
        } else {
            std::env::current_dir()?.join(&state_dir)
        };
        let root_dir = if root_dir.is_absolute() {
            root_dir
        } else {
            std::env::current_dir()?.join(&root_dir)
        };

        let runtime_state_dir = state_dir.join("containers");
        fs::create_dir_all(&runtime_state_dir)?;

        let runtime = Arc::new(OciRuntime::new(runtime_state_dir)?);
        let network_manager = Arc::new(NetworkManager::new());

        Ok(Self {
            db,
            runtime,
            other_runtimes: Default::default(),
            image_service,
            userns_manager,
            lifecycle: Default::default(),
            root_dir,
            state_dir,
            cgroup_manager,
            network_manager,
            network_providers,
            containers_config: Default::default(),
            base_hosts_file: None,
            monitor_env: None,
            caller_supervised: false,
            volume_service,
            supervision: Default::default(),
            pod_slices: Default::default(),
            default_cgroups: CgroupsMode::Unset,
            default_scope: false,
        })
    }

    /// Use the `[containers]` section of the configuration.
    /// The configuration of the daemon, for the monitors that serve the
    /// root file system of rootless containers.
    /// The monitors are started by the caller, in its cgroup and with its
    /// output (the engine without the server).
    pub fn with_caller_supervised(mut self, yes: bool) -> Self {
        self.caller_supervised = yes;
        self
    }

    pub fn with_monitor_env(mut self, config: velarx_config::Config) -> Self {
        self.monitor_env = Some(Box::new(config));
        self
    }

    /// The `--cgroups` mode of the containers that ask for none, from
    /// `[containers] cgroups` of the configuration (`conf`).
    pub fn with_default_cgroups(mut self, conf: &str) -> Self {
        self.default_cgroups = super::cgroups_mode::conf_default(conf);
        self.default_scope = super::cgroups_mode::conf_scope(conf);
        self
    }

    /// The `--cgroups` mode of the containers that ask for none.
    pub fn default_cgroups(&self) -> CgroupsMode {
        self.default_cgroups
    }

    pub fn with_containers_config(mut self, config: velarx_config::ContainersConfig) -> Self {
        self.containers_config = config;
        self
    }

    /// The entries of `path` start the /etc/hosts of every container
    /// (`[containers] base_hosts_file`); "" is the host's /etc/hosts, "none"
    /// no file.
    pub fn with_base_hosts_file(mut self, path: &str) -> Self {
        self.base_hosts_file = match path {
            "none" => None,
            "" => Some(PathBuf::from("/etc/hosts")),
            p => Some(PathBuf::from(p)),
        };
        self
    }

    /// The network setup of the containers (bridge networks, pasta).
    pub fn network_manager(&self) -> &Arc<NetworkManager> {
        &self.network_manager
    }

    /// Get a reference to the OCI runtime
    pub fn runtime(&self) -> Arc<OciRuntime> {
        Arc::clone(&self.runtime)
    }

    /// The OCI runtime a client asks for by `name` (`oci_runtime`,
    /// `HostConfig.Runtime`, a CRI runtime handler): see `client_runtime`.
    pub fn find_runtime(&self, name: &str) -> Result<PathBuf, String> {
        client_runtime(
            name,
            self.runtime.runtime_path(),
            self.monitor_env.as_deref(),
        )
    }

    /// The OCI runtime at `path` asked for by `name`: another than the
    /// default one, kept.
    pub(crate) fn runtime_at(&self, path: &Path, name: Option<&str>) -> Arc<OciRuntime> {
        let mut others = self
            .other_runtimes
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        Arc::clone(
            others
                .entry((path.to_path_buf(), name.map(str::to_string)))
                .or_insert_with(|| Arc::new(self.runtime.with_runtime(path.to_path_buf(), name))),
        )
    }

    /// The OCI runtime a container was made with.
    pub(crate) fn runtime_for(&self, config: &ContainerConfig) -> Arc<OciRuntime> {
        match &config.runtime {
            Some(path) => self.runtime_at(path, config.runtime_name.as_deref()),
            None => Arc::clone(&self.runtime),
        }
    }

    /// The OCI runtime of the container of a record.
    pub fn runtime_for_record(
        &self,
        rec: &velarx_db::ContainerRecord,
    ) -> ContainerResult<Arc<OciRuntime>> {
        Ok(self.runtime_for(&stored_config(rec)?))
    }

    /// The state of a container that is not stopped, as the OCI runtime has
    /// it (paused or resumed), also in the database.  A container said to
    /// run whose process and monitor are both gone (the monitor was killed)
    /// gets what the monitor would have given it (`reconcile`: its exit, an
    /// `--rm` container its removal).  False when that removed it.  Only a
    /// container the record says is alive can be in another state than the
    /// record's: the runtime is not asked for any other (a created container
    /// is not in it).  The state the runtime gave, when it was asked and had
    /// the container, is in `runtime`.
    async fn refresh_state(
        self: &Arc<Self>,
        container: &mut ContainerRecord,
        runtime: &mut Option<crate::container::ContainerStatus>,
    ) -> ContainerResult<bool> {
        *runtime = None;
        if !container.state.is_alive() {
            return Ok(true);
        }
        // (a container the runtime does not know has ended; when the runtime
        // cannot be asked, whether it did is not known: the record stays as
        // it is, and a listing is not refused for one container)
        let status = match self
            .runtime_for_record(container)?
            .state(&container.id)
            .await
        {
            Ok(s) => Some(s),
            Err(crate::container::RuntimeError::NotFound(_)) => None,
            Err(e) => {
                warn!(
                    "Cannot ask the runtime for the state of container {}: {e}",
                    container.id
                );
                return Ok(true);
            }
        };
        let ended = status
            .as_ref()
            .is_none_or(|s| s.state == crate::container::ContainerState::Stopped);
        if ended
            && crate::services::lifecycle::monitor_alive(&self.mon_dir(&container.id)).is_none()
        {
            self.reconcile(&container.id).await?;
            return match self.db.get_container(&container.id).await {
                Ok(now) => {
                    *container = now;
                    Ok(true)
                }
                Err(velarx_types::DbError::NotFound(_)) => Ok(false),
                Err(e) => Err(e.into()),
            };
        }
        let Some(status) = status else {
            return Ok(true);
        };
        if let Some(runtime_state) = paused_or_resumed(container.state, &status.state) {
            container.state = runtime_state;
            self.db
                .update_container_state(&container.id, runtime_state, status.pid, None, None, None)
                .await?;
        }
        *runtime = Some(status);
        Ok(true)
    }

    pub async fn list(self: &Arc<Self>, all: bool) -> ContainerResult<Vec<ContainerRecord>> {
        Ok(self
            .list_observed(all)
            .await?
            .into_iter()
            .map(|(container, _)| container)
            .collect())
    }

    /// The containers of [`Self::list`], each with the state the OCI runtime
    /// gave for it on the way (see [`Self::inspect_observed`]).
    pub async fn list_observed(
        self: &Arc<Self>,
        all: bool,
    ) -> ContainerResult<Vec<(ContainerRecord, Option<crate::container::ContainerStatus>)>> {
        let mut containers = match all {
            true => self.observed(self.db.list_containers(true).await?).await,
            false => self.list_alive_observed().await?,
        };
        if !all {
            containers.retain(|(c, _)| c.state == RecordState::Running);
        }
        Ok(containers)
    }

    /// The containers the record says are alive (running or paused), as
    /// [`Self::list_observed`] gives them, the paused ones too.  Nothing
    /// else is looked at: a stopped container cannot run without a write.
    pub async fn list_alive_observed(
        self: &Arc<Self>,
    ) -> ContainerResult<Vec<(ContainerRecord, Option<crate::container::ContainerStatus>)>> {
        Ok(self.observed(self.db.list_alive_containers().await?).await)
    }

    /// `listed` with the state each is in refreshed (see [`Self::refresh_state`]).
    async fn observed(
        self: &Arc<Self>,
        listed: Vec<ContainerRecord>,
    ) -> Vec<(ContainerRecord, Option<crate::container::ContainerStatus>)> {
        // (the runtimes are asked together, each once: the listing takes
        // the time of the slowest, not the sum)
        let refreshed: Vec<_> = futures::stream::iter(listed)
            .map(|mut container| async move {
                let mut runtime = None;
                let refreshed = self.refresh_state(&mut container, &mut runtime).await;
                (container, runtime, refreshed)
            })
            .buffered(REFRESH_AT_ONCE)
            .collect()
            .await;
        let mut containers = Vec::with_capacity(refreshed.len());
        for (container, runtime, refreshed) in refreshed {
            // (one container that cannot be looked at, its configuration not
            // valid, is listed as it is recorded: the listing of the others
            // is not refused for it)
            match refreshed {
                Ok(true) => containers.push((container, runtime)),
                Ok(false) => {}
                Err(e) => {
                    warn!("Cannot look at container {}: {e}", container.id);
                    containers.push((container, None));
                }
            }
        }

        containers
    }

    /// Prune (remove) all stopped containers
    /// Returns the list of pruned container IDs and space reclaimed
    pub async fn prune(self: &Arc<Self>) -> ContainerResult<(Vec<String>, u64)> {
        let containers = self.db.list_containers(true).await?;
        let mut pruned = Vec::new();
        let mut space_reclaimed = 0u64;

        for container in containers {
            if container.state.has_ended() {
                let size = self.calculate_container_size(&container.id);

                match self.delete(&container.id, false).await {
                    Ok(()) => {
                        pruned.push(container.id.clone());
                        space_reclaimed += size;
                    }
                    Err(e) => {
                        warn!("Failed to prune container {}: {}", container.id, e);
                    }
                }
            }
        }

        info!(
            "Pruned {} stopped containers, reclaimed {} bytes",
            pruned.len(),
            space_reclaimed
        );
        Ok((pruned, space_reclaimed))
    }

    pub async fn inspect(self: &Arc<Self>, id: &str) -> ContainerResult<ContainerRecord> {
        Ok(self.inspect_observed(id).await?.0)
    }

    /// The container as [`Self::inspect`] gives it, with the state the OCI
    /// runtime gave for it on the way (none: it was not asked, or had no such
    /// container), so that a caller that needs the process too does not ask
    /// the runtime a second time.
    pub async fn inspect_observed(
        self: &Arc<Self>,
        id: &str,
    ) -> ContainerResult<(ContainerRecord, Option<crate::container::ContainerStatus>)> {
        let mut container = self.db.get_container(id).await?;
        let mut runtime = None;
        if !self.refresh_state(&mut container, &mut runtime).await? {
            return Err(velarx_types::DbError::NotFound(id.to_string()).into());
        }
        Ok((container, runtime))
    }

    /// Pause a container
    pub async fn pause(&self, id: &str) -> ContainerResult<()> {
        self.set_paused(id, true).await
    }

    /// Unpause a container
    pub async fn unpause(&self, id: &str) -> ContainerResult<()> {
        self.set_paused(id, false).await
    }

    async fn set_paused(&self, id: &str, pause: bool) -> ContainerResult<()> {
        // (the lease is the container's, whatever the name asked)
        let id = self.db.get_container(id).await?.id;
        let id = id.as_str();
        let _lock = self.pause_lock(id).await?;
        self.runtime_freeze(id, pause).await?;
        self.set_pause_lease(id, None).await?;
        self.notify_action_of(id, if pause { "pause" } else { "unpause" }, Vec::new())
            .await;
        Ok(())
    }

    /// Why the container `id` cannot be paused: it has no cgroup of its own
    /// to freeze; none when it has one (or is not there).
    pub async fn no_freezer_of(&self, id: &str) -> ContainerResult<Option<String>> {
        let container = match self.db.get_container(id).await {
            Ok(c) => c,
            Err(velarx_types::DbError::NotFound(_)) => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        Ok(no_freezer(&container.id, &stored_config(&container)?))
    }

    /// `pause` or `resume` through the monitor of the container, which
    /// runs the OCI runtime.
    async fn runtime_freeze(&self, id: &str, pause: bool) -> ContainerResult<()> {
        let container = self.db.get_container(id).await?;
        let config = stored_config(&container)?;
        if let Some(why) = no_freezer(&container.id, &config) {
            return Err(ContainerError::Unsupported(why));
        }
        self.freeze(&container.id, pause).await?;
        info!(
            "{} of container {} done",
            if pause { "pause" } else { "resume" },
            container.id
        );
        Ok(())
    }

    /// Rename a container
    pub async fn rename(&self, id: &str, new_name: &str) -> ContainerResult<()> {
        let container = self.db.get_container(id).await?;

        self.db.rename_container(&container.id, new_name).await?;

        info!("Renamed container {} to {}", container.id, new_name);
        let old = container.name.clone().unwrap_or_default();
        let mut renamed = container.clone();
        renamed.name = Some(new_name.to_string());
        self.notify_action(&renamed, "rename", vec![("renamed".into(), old)]);
        Ok(())
    }
}

/// Whether a container is in a cgroup of its own, whose usage is its own:
/// not one of `--cgroups=disabled`.
pub fn has_own_cgroup(rec: &ContainerRecord) -> bool {
    serde_json::from_str::<ContainerConfig>(&rec.config)
        .map(|c| c.cgroups != CgroupsMode::Disabled)
        .unwrap_or(true)
}

/// The freezer is a cgroup's: a container in its monitor's has none.
fn no_freezer(id: &str, config: &ContainerConfig) -> Option<String> {
    config.cgroups_path.is_none().then(|| {
        format!(
            "container {id} has no cgroup of its own to freeze: it runs in the cgroup of its \
             monitor (a container made with no API server, outside a systemd scope)"
        )
    })
}

#[cfg(test)]
mod tests {

    #[test]
    fn a_container_of_cgroups_disabled_has_no_cgroup_of_its_own() {
        let rec = |cgroups: &str| ContainerRecord {
            id: "c".into(),
            name: None,
            image_id: "i".into(),
            config: serde_json::to_string(&ContainerConfig {
                cgroups: cgroups.parse().unwrap(),
                ..Default::default()
            })
            .unwrap(),
            state: RecordState::Running,
            pid: None,
            created_at: String::new(),
            started_at: None,
            finished_at: None,
            exit_code: None,
        };
        assert!(has_own_cgroup(&rec("")));
        assert!(has_own_cgroup(&rec("split")));
        assert!(!has_own_cgroup(&rec("disabled")));
    }
    use super::*;

    #[test]
    fn the_conditions_a_container_error_names() {
        use crate::container::userspec::UserError;
        use velarx_proto::engine::Condition;
        let no_user = ContainerError::from(UserError::NoUser("x".into()));
        assert_eq!(no_user.condition(), Some(Condition::NotStarted));
        let no_host = ContainerError::from(UserError::NoHostUser("x".into()));
        assert_eq!(no_host.condition(), Some(Condition::NotStarted));
        // (an invalid specification is the caller's, whatever its words)
        let umask = ContainerError::from(UserError::Umask("no matching entries in".into()));
        assert_eq!(umask.condition(), None);
        let command = ContainerError::Runtime(crate::container::not_started_for(
            "crun",
            "executable file `x` not found in $PATH: No such file or directory",
        ));
        assert_eq!(command.condition(), Some(Condition::CommandNotFound));
        let sctp = ContainerError::Network(
            velarx_netkernel::error::NetworkError::UnsupportedProtocol("sctp".into()),
        );
        assert_eq!(sctp.condition(), Some(Condition::NotStarted));
        let pasta = ContainerError::Network(velarx_netkernel::error::NetworkError::NoPasta {
            searched: "/usr/bin".into(),
            minimum: "2026_10_02",
        });
        assert_eq!(pasta.condition(), Some(Condition::NoPasta));
        let old = ContainerError::Network(velarx_netkernel::error::NetworkError::OldPasta {
            path: "/usr/bin/pasta".into(),
            said: "pasta 2025_01_21.4f2c8e7".into(),
            minimum: "2026_10_02",
        });
        assert_eq!(old.condition(), Some(Condition::NoPasta));
        assert_eq!(sctp.to_string(), "can't forward protocol: sctp");
        let words = ContainerError::InvalidArgument(
            "crun: x: OCI runtime attempted to invoke a command that was not found".into(),
        );
        assert_eq!(words.condition(), None);
        assert_eq!(
            ContainerError::NoCheckpoint("c".into()).condition(),
            Some(Condition::NoCheckpoint)
        );
        assert_eq!(
            ContainerError::InvalidArgument("the container c has no checkpoint to restore".into())
                .condition(),
            None
        );
    }

    #[test]
    fn the_security_options_podman_records() {
        let a = podman_security_annotations(&[
            "label=type:spc_t".into(),
            "label=level:s0:c1,c2".into(),
            "label=nested".into(),
            "apparmor=unconfined".into(),
            "no-new-privileges".into(),
        ]);
        assert_eq!(
            a,
            [
                (
                    "io.podman.annotations.label".to_string(),
                    "type:spc_t,label=level:s0:c1,c2".to_string()
                ),
                (
                    "io.podman.annotations.apparmor".to_string(),
                    "unconfined".to_string()
                ),
            ]
        );
        assert!(podman_security_annotations(&[]).is_empty());
    }

    #[test]
    fn a_client_asks_only_for_a_runtime_of_the_engine() {
        let dir = tempfile::tempdir().unwrap();
        let kata = dir.path().join("kata-runtime");
        std::fs::write(&kata, "").unwrap();
        let config: velarx_config::Config = toml::from_str(&format!(
            "[runtimes]\nkata = {:?}\ngone = [\"/no/such/a\", \"/no/such/b\"]\n",
            kata
        ))
        .unwrap();
        let crun = Path::new("/usr/bin/crun");
        let pick = |name: &str| client_runtime(name, crun, Some(&config));
        assert_eq!(pick(""), Ok(crun.to_path_buf()));
        assert_eq!(pick("crun"), Ok(crun.to_path_buf()));
        assert_eq!(pick("/usr/bin/crun"), Ok(crun.to_path_buf()));
        assert_eq!(pick("kata"), Ok(kata.clone()));
        // a runtime of the table that is not there says so
        let e = pick("gone").unwrap_err();
        assert!(e.contains("/no/such/a, /no/such/b"), "{e}");
        // neither a path (even that of a runtime of the table) nor a name
        // in PATH
        for name in [kata.to_str().unwrap(), "/bin/sh", "sh", "runc", "../crun"] {
            let e = pick(name).unwrap_err();
            assert!(e.contains("are crun, gone, kata"), "{name}: {e}");
        }
        assert!(client_runtime("runc", crun, None).is_err());
    }

    #[test]
    fn only_a_named_volume_is_one_mount_whatever_its_options() {
        let m = |volume: Option<&str>, options: &[&str]| MountConfig {
            source: "/s".into(),
            target: "/x".into(),
            volume: volume.map(str::to_string),
            options: options.iter().map(|o| o.to_string()).collect(),
            ..Default::default()
        };
        let same =
            |a: &MountConfig, b: &MountConfig| same_mount(a).unwrap() == same_mount(b).unwrap();
        assert!(same(&m(Some("v"), &[]), &m(Some("v"), &["ro"])));
        assert!(!same(&m(Some("v"), &[]), &m(Some("w"), &[])));
        assert!(same(&m(None, &["ro"]), &m(None, &["ro"])));
        assert!(!same(&m(None, &[]), &m(None, &["ro"])));
    }

    #[test]
    fn a_working_directory_is_in_the_image_or_on_a_mount() {
        let view = |entries: serde_json::Value| {
            let toc: velarx_storage::Toc =
                serde_json::from_value(serde_json::json!({"version": 1, "entries": entries}))
                    .unwrap();
            velarx_fuse::view::ImageView::new(vec![velarx_fuse::erofs_tree::Layer::open(Box::new(
                velarx_fuse::layer_erofs::layer_image(&toc.entries)
                    .unwrap()
                    .image,
            ))
            .unwrap()])
        };
        let image = view(serde_json::json!([
            {"name": "usr/", "type": "dir"},
            {"name": "usr/lib/", "type": "dir"}
        ]));
        let layers = Some(&image as &dyn velarx_fuse::view::ImageTree);
        let mut config = ContainerConfig::default();
        assert!(check_workdir("/usr/lib", &config, &[], layers, "c").is_ok());
        let e = check_workdir("/i/do/not/exist", &config, &[], layers, "c").unwrap_err();
        assert_eq!(
            e.to_string(),
            "workdir \"/i/do/not/exist\" does not exist on container c"
        );
        // a mount, or a tmpfs, is there before the runtime looks
        assert!(check_workdir("/data/x", &config, &["/data".into()], layers, "c").is_ok());
        config.mounts.push(MountConfig {
            target: "/vol".into(),
            ..MountConfig::default()
        });
        assert!(check_workdir("/vol/sub/dir", &config, &[], layers, "c").is_ok());
        config.mounts.push(MountConfig {
            target: "/below/file".into(),
            ..MountConfig::default()
        });
        assert!(check_workdir("/below", &config, &[], layers, "c").is_ok());
        // the engine's own mounts (podman: `--workdir /dev/shm` runs)
        assert!(check_workdir("/dev/shm", &config, &[], layers, "c").is_ok());
        assert!(check_workdir("/proc/self", &config, &[], layers, "c").is_ok());
        assert!(check_workdir("/devices", &config, &[], layers, "c").is_err());
        // a file is not a directory
        let file = view(serde_json::json!([
            {"name": "usr/", "type": "dir"},
            {"name": "usr/f", "type": "reg"}
        ]));
        let e = check_workdir("/usr/f", &config, &[], Some(&file), "c").unwrap_err();
        assert_eq!(
            e.to_string(),
            "workdir \"/usr/f\" exists on container c, but is not a directory"
        );
    }

    #[test]
    fn a_working_directory_is_looked_up_in_a_mounted_image_inside_it() {
        let (image, outside) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        fs::create_dir_all(image.path().join("usr/lib")).unwrap();
        fs::create_dir_all(outside.path().join("elsewhere")).unwrap();
        fs::write(image.path().join("usr/f"), "x").unwrap();
        std::os::unix::fs::symlink("usr/lib", image.path().join("lib")).unwrap();
        std::os::unix::fs::symlink("/usr/lib", image.path().join("abs")).unwrap();
        std::os::unix::fs::symlink(outside.path(), image.path().join("host")).unwrap();
        std::os::unix::fs::symlink("/proc/self/cwd", image.path().join("magic")).unwrap();
        std::os::unix::fs::symlink("../../../../../..", image.path().join("up")).unwrap();
        rustix::fs::mkfifoat(
            rustix::fs::CWD,
            image.path().join("fifo"),
            rustix::fs::Mode::RUSR,
        )
        .unwrap();
        let root = rustix::fs::open(
            image.path(),
            rustix::fs::OFlags::PATH | rustix::fs::OFlags::DIRECTORY | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .unwrap();
        let view = velarx_fuse::MountedImage::new(root).unwrap();
        let tree = Some(&view as &dyn velarx_fuse::view::ImageTree);
        let config = ContainerConfig::default();
        let check = |dir: &str| check_workdir(dir, &config, &[], tree, "c");
        assert!(check("/usr/lib").is_ok());
        // the links of the image lead to its directories, as the kernel
        // follows them in the root of the container
        assert!(check("/lib").is_ok());
        assert!(check("/abs").is_ok());
        assert!(check("/up/usr/lib").is_ok());
        // ... and not to the host or to /proc
        assert!(check("/host/elsewhere").is_err());
        assert!(check("/host").is_err());
        assert!(check("/magic").is_err());
        // a file and a FIFO are no directories
        assert!(check("/usr/f")
            .unwrap_err()
            .to_string()
            .ends_with("but is not a directory"));
        assert!(check("/fifo")
            .unwrap_err()
            .to_string()
            .ends_with("but is not a directory"));
    }

    #[test]
    fn the_ids_of_new_containers_never_repeat() {
        // (made in the same instant by processes that share the store)
        let ids: std::collections::HashSet<String> = (0..10_000).map(|_| new_id()).collect();
        assert_eq!(ids.len(), 10_000);
        assert!(ids.iter().all(|id| valid_container_id(id)));
    }

    #[test]
    fn publish_all_maps_every_exposed_port() {
        let mut req = CreateContainerRequest {
            expose: vec!["9000-9001/udp".into(), "53/sctp".into()],
            ports: vec![PortMapping {
                container_port: 80,
                host_port: Some(8080),
                host_ip: String::new(),
                protocol: "tcp".into(),
            }],
            ..Default::default()
        };
        let image = ["80/tcp".to_string(), "443".to_string()];
        publish_exposed(&mut req, image.iter()).unwrap();
        let got: Vec<(u16, Option<u16>, &str)> = req
            .ports
            .iter()
            .map(|p| (p.container_port, p.host_port, p.protocol.as_str()))
            .collect();
        // 80 keeps its mapping, SCTP is not published
        assert_eq!(
            got,
            [
                (80, Some(8080), "tcp"),
                (443, None, "tcp"),
                (9000, None, "udp"),
                (9001, None, "udp")
            ]
        );
        for bad in ["x/tcp", "0", "10-5", "80/icmp"] {
            let mut req = CreateContainerRequest::default();
            let e = [bad.to_string()];
            assert!(publish_exposed(&mut req, e.iter()).is_err(), "{bad}");
        }
    }

    #[test]
    fn the_runtime_tells_only_pauses() {
        use crate::container::ContainerState as Oci;
        let pause = |record, runtime| paused_or_resumed(record, &runtime);
        assert_eq!(
            pause(RecordState::Running, Oci::Paused),
            Some(RecordState::Paused)
        );
        assert_eq!(
            pause(RecordState::Paused, Oci::Running),
            Some(RecordState::Running)
        );
        // the exit is the monitor's to record, with its code
        assert_eq!(pause(RecordState::Running, Oci::Stopped), None);
        // a state read before a start does not undo it
        assert_eq!(pause(RecordState::Running, Oci::Created), None);
        assert_eq!(pause(RecordState::Initialized, Oci::Created), None);
        assert_eq!(pause(RecordState::Created, Oci::Running), None);
    }

    #[test]
    fn override_config_of_a_commit() {
        use crate::services::ConfigEdit;
        let o = serde_json::json!({
            "Entrypoint": ["/bin/crash"],
            "Labels": {"for": "ever"},
            "Env": ["A=1", "B"],
            "User": "",
        });
        let edits = override_edits(&o);
        assert!(edits.contains(&ConfigEdit::Set(
            "Entrypoint".into(),
            serde_json::json!(["/bin/crash"])
        )));
        // the command goes with an entrypoint given alone
        assert!(edits.contains(&ConfigEdit::Unset("Cmd".into())));
        assert!(edits.contains(&ConfigEdit::Env(vec![
            ("A".into(), "1".into()),
            ("B".into(), String::new())
        ])));
        assert!(!edits
            .iter()
            .any(|e| matches!(e, ConfigEdit::Set(k, _) if k == "User")));
        assert!(override_edits(&serde_json::json!({})).is_empty());
    }

    #[test]
    fn hosts_file_is_the_bundle_file() {
        let d = tempfile::tempdir().unwrap();
        let b = d.path();
        assert!(hosts_file(b).is_none());
        let m = bundle_file_mount(b, ETC_HOSTS, b"new", "/etc/hosts", false).unwrap();
        assert!(m.engine);
        assert_eq!(m.source, b.join(ETC_HOSTS).to_string_lossy());
        assert_eq!(m.options, ["rbind", "rprivate"]);
        assert_eq!(hosts_file(b), Some((b.to_path_buf(), ETC_HOSTS)));
        // a link out of the bundle is not followed
        std::fs::remove_file(b.join(ETC_HOSTS)).unwrap();
        std::os::unix::fs::symlink("/etc/passwd", b.join(ETC_HOSTS)).unwrap();
        assert!(open_beneath(b, ETC_HOSTS, rustix::fs::OFlags::RDONLY).is_err());
    }

    #[test]
    fn security_options() {
        let mut so = SecurityOptions::default();
        for o in [
            "no-new-privileges",
            "seccomp=/p.json",
            "apparmor=unconfined",
            "label=type:spc_t",
            "label=level:s0:c1,c2",
            "label=disable",
            "label=files",
            "mask=/a:/b",
            "unmask=/proc/kcore",
            "proc-opts=hidepid=2",
        ] {
            so.apply(o).unwrap();
        }
        assert!(so.no_new_privileges);
        assert_eq!(so.seccomp_profile.as_deref(), Some("/p.json"));
        assert!(so.apparmor_unconfined);
        assert_eq!(so.selinux_type.as_deref(), Some("spc_t"));
        assert_eq!(so.selinux_level.as_deref(), Some("s0:c1,c2"));
        assert_eq!(so.selinux_label.as_deref(), Some("disable"));
        assert!(so.selinux_files);
        assert_eq!(so.mask_paths, ["/a", "/b"]);
        assert_eq!(so.unmask_paths, ["/proc/kcore"]);
        assert_eq!(so.proc_opts.as_deref(), Some("hidepid=2"));
        so.apply("no-new-privileges:false").unwrap();
        assert!(!so.no_new_privileges);
        so.apply("seccomp=unconfined").unwrap();
        assert!(so.seccomp_unconfined && so.seccomp_profile.is_none());
        so.apply("systempaths=unconfined").unwrap();
        assert_eq!(so.unmask_paths.last().map(String::as_str), Some("ALL"));
        so.apply("seccomp-bpf=/f.bpf").unwrap();
        assert_eq!(so.seccomp_bpf.as_deref(), Some("/f.bpf"));
        so.apply("signature=check").unwrap();
        assert_eq!(so.signature.as_deref(), Some("check"));
        so.apply("signature=require").unwrap();
        // (a later one cannot loosen it)
        so.apply("signature=check").unwrap();
        assert_eq!(so.signature.as_deref(), Some("require"));
        let e = so.apply("label=nested").unwrap_err();
        assert!(e.contains("label=nested is not supported"), "{e}");
        for bad in ["signature", "signature=on", "signature="] {
            let e = so.apply(bad).unwrap_err();
            assert!(e.contains("must be \"check\" or \"require\""), "{e}");
        }
        let d = tempfile::tempdir().unwrap();
        let f = d.path().join("f.bpf");
        fs::write(&f, [6u8, 0, 0, 0, 0, 0, 0xff, 0x7f]).unwrap();
        assert_eq!(
            read_bpf_filter(f.to_str().unwrap()).unwrap(),
            "BgAAAAAA/38="
        );
        fs::write(&f, [6u8, 0, 0]).unwrap();
        assert!(read_bpf_filter(f.to_str().unwrap()).is_err());
        fs::write(&f, []).unwrap();
        assert!(read_bpf_filter(f.to_str().unwrap()).is_err());
        so.apply("verity=enforce").unwrap();
        assert!(so.verity_enforce);
        let e = SecurityOptions::default().apply("verity=on").unwrap_err();
        assert_eq!(
            e,
            "invalid --security-opt verity value \"on\", must be \"enforce\" or \"off\""
        );
        assert!(SecurityOptions::default().apply("verity").is_err());
        // off is its own option, and contradicts enforce in either order
        let mut off = SecurityOptions::default();
        off.apply("verity=off").unwrap();
        assert!(off.verity_off && !off.verity_enforce);
        let e = off.apply("verity=enforce").unwrap_err();
        assert!(e.contains("contradict"), "{e}");
        assert!(so.apply("verity=off").unwrap_err().contains("contradict"));
        for bad in [
            "seccomp-bpf=relative.bpf",
            "bogus",
            "seccomp",
            "seccomp=",
            "no-new-privileges=maybe",
            "label=foo:bar",
            "mask=relative",
            "mask=ALL",
            "unmask=",
            "systempaths=confined",
        ] {
            assert!(SecurityOptions::default().apply(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn sysctls() {
        let req = CreateContainerRequest::default();
        let map = |v: &[(&str, &str)]| -> std::collections::BTreeMap<String, String> {
            v.iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect()
        };
        let ok = validate_sysctls(
            &map(&[
                ("net/ipv4/ip_forward", "1"),
                ("kernel.shmmax", "1"),
                ("fs.mqueue.msg_max", "9"),
            ]),
            &req,
        )
        .unwrap();
        assert_eq!(ok.get("net.ipv4.ip_forward").map(String::as_str), Some("1"));
        assert_eq!(ok.len(), 3);
        for bad in ["kernel.panic", "vm.swappiness", "kernel.hostname", "net"] {
            assert!(
                validate_sysctls(&map(&[(bad, "1")]), &req).is_err(),
                "{bad}"
            );
        }
        let host = CreateContainerRequest {
            network_mode: NetworkMode::parse("host"),
            ipc_mode: "host".parse().unwrap(),
            ..Default::default()
        };
        assert!(validate_sysctls(&map(&[("net.ipv4.ip_forward", "1")]), &host).is_err());
        assert!(validate_sysctls(&map(&[("kernel.sem", "1")]), &host).is_err());
        assert!(validate_sysctls(&map(&[("fs.mqueue.msg_max", "1")]), &host).is_err());
        let mut joined = CreateContainerRequest {
            network_mode: NetworkMode::parse("container:web"),
            ipc_mode: "ns:/run/ipcns".parse().unwrap(),
            ..Default::default()
        };
        assert!(validate_sysctls(&map(&[("net.ipv4.ip_forward", "1")]), &joined).is_err());
        assert!(validate_sysctls(&map(&[("kernel.sem", "1")]), &joined).is_err());
        joined.network_mode = NetworkMode::parse("ns:/run/netns/x");
        joined.ipc_mode = "container:db".parse().unwrap();
        assert!(validate_sysctls(&map(&[("net.ipv4.ip_forward", "1")]), &joined).is_err());
        assert!(validate_sysctls(&map(&[("kernel.shmmax", "1")]), &joined).is_err());
    }

    /// A container with no network keeps the resolv.conf of its image (no
    /// default name servers are written for it), as podman's.
    #[test]
    fn a_container_with_no_network_keeps_the_resolv_conf_of_its_image() {
        let with = |mode: &str, networks: &[&str]| CreateContainerRequest {
            network_mode: NetworkMode::parse(mode),
            networks: networks.iter().map(|n| n.to_string()).collect(),
            ..Default::default()
        };
        assert!(keeps_image_resolv_conf(&with("none", &[])));
        assert!(keeps_image_resolv_conf(&with("bridge", &["none"])));
        for mode in [
            "",
            "host",
            "pasta",
            "bridge",
            "provider:overlay",
            "container:x",
        ] {
            assert!(!keeps_image_resolv_conf(&with(mode, &[])), "{mode}");
        }
    }

    #[test]
    fn dns_settings_need_a_resolver_of_their_own() {
        let with = |mode: &str, networks: &[&str]| CreateContainerRequest {
            network_mode: NetworkMode::parse(mode),
            networks: networks.iter().map(|n| n.to_string()).collect(),
            dns: vec!["10.1.1.1".into()],
            ..Default::default()
        };
        assert_eq!(options::dns_conflict(&with("none", &[])), Some("none"));
        assert_eq!(
            options::dns_conflict(&with("container:infra", &[])),
            Some("container")
        );
        for ok in [with("", &[]), with("host", &[]), with("pasta", &[])] {
            assert_eq!(options::dns_conflict(&ok), None, "{}", ok.network_mode);
        }
        // (the command line sets both)
        assert_eq!(
            options::dns_conflict(&with("container:infra", &["container:infra"])),
            Some("container")
        );
        let mut search = with("container:infra", &[]);
        search.dns.clear();
        search.dns_search = vec!["x.test".into()];
        assert_eq!(options::dns_conflict(&search), Some("container"));
        search.dns_search.clear();
        assert_eq!(options::dns_conflict(&search), None);
    }

    #[test]
    fn zone_files() {
        for bad in [
            "",
            "/etc/passwd",
            "../x",
            "a/../b",
            "a//b",
            "a b",
            "Europe/./Rome",
        ] {
            assert!(read_zoneinfo(bad).is_err(), "{bad}");
        }
        if Path::new("/usr/share/zoneinfo/UTC").exists() {
            assert!(read_zoneinfo("UTC").unwrap().starts_with(b"TZif"));
            assert!(read_zoneinfo("Not/AZone").is_err());
        }
    }

    #[test]
    fn users() {
        assert_eq!(effective_user("", "bin"), "bin");
        assert_eq!(effective_user("", ""), "");
        assert_eq!(effective_user("0", "bin"), "0");
        assert_eq!(effective_user(":7", "bin:bin"), "bin:7");
        assert_eq!(effective_user(":7", ""), "0:7");
    }

    #[test]
    fn user_entries_are_mounted_from_the_bundle() {
        let bundle = tempfile::tempdir().unwrap();
        let passwd = b"root:x:0:0:root:/root:/bin/sh\n";
        let group = b"root:x:0:\n";
        let mut config = ContainerConfig {
            user: "4242:4243".into(),
            working_dir: "/srv".into(),
            mounts: vec![MountConfig {
                source: "/data".into(),
                target: "/data".into(),
                mount_type: Some("bind".into()),
                ..Default::default()
            }],
            ..Default::default()
        };
        let req = CreateContainerRequest::default();
        let user = resolve_container_user(passwd, group, &config, &req, None).unwrap();
        add_user_files(
            &mut config,
            bundle.path(),
            user,
            Some(("Europe/Berlin", b"TZif2")),
            None,
        )
        .unwrap();
        let u = config.process_user.clone().unwrap();
        assert_eq!((u.uid, u.gid), (4242, 4243));
        let targets: Vec<&str> = config.mounts.iter().map(|m| m.target.as_str()).collect();
        assert_eq!(
            targets,
            ["/etc/passwd", "/etc/group", "/etc/localtime", "/data"]
        );
        assert!(fs::read_to_string(bundle.path().join("passwd"))
            .unwrap()
            .ends_with("4242:*:4242:4243:container user:/srv:/bin/sh\n"));
        assert_eq!(fs::read(bundle.path().join("localtime")).unwrap(), b"TZif2");
        assert!(config.mounts[2].options.contains(&"ro".to_string()));

        // no entries without a user, or with --passwd=false
        let config = ContainerConfig::default();
        let user = resolve_container_user(passwd, group, &config, &req, None).unwrap();
        assert!(user.passwd.is_none() && user.group.is_none());
        let config = ContainerConfig {
            user: "4242".into(),
            ..Default::default()
        };
        let no_passwd = CreateContainerRequest {
            no_passwd: true,
            ..Default::default()
        };
        let user = resolve_container_user(passwd, group, &config, &no_passwd, None).unwrap();
        assert!(user.passwd.is_none());
        // keep-id: the names of the host
        let host = |uid| HostUser {
            uid,
            gid: 0,
            name: "me",
            group: "us",
        };
        let user = resolve_container_user(passwd, group, &config, &req, Some(&host(4242))).unwrap();
        assert_eq!(
            user.passwd.as_deref(),
            Some(&b"root:x:0:0:root:/root:/bin/sh\nme:*:4242:0::/:/bin/sh\n"[..])
        );
        // another user is given: the host user has its entry too
        let user = resolve_container_user(passwd, group, &config, &req, Some(&host(1000))).unwrap();
        assert_eq!(
            user.passwd.as_deref(),
            Some(
                &b"root:x:0:0:root:/root:/bin/sh\nme:*:1000:0::/:/bin/sh\n4242:*:4242:0:container user:/:/bin/sh\n"[..]
            )
        );
        // an unknown name fails
        let config = ContainerConfig {
            user: "nosuch".into(),
            ..Default::default()
        };
        assert!(matches!(
            resolve_container_user(passwd, group, &config, &req, None),
            Err(crate::container::userspec::UserError::NoUser(_))
        ));
    }

    #[test]
    fn a_stored_configuration_that_does_not_parse_is_an_error() {
        let rec = |config: &str| ContainerRecord {
            id: "c".into(),
            name: None,
            image_id: "i".into(),
            config: config.into(),
            state: RecordState::Running,
            ..Default::default()
        };
        // (not a default one: it would stop the container with the wrong
        // signal and forget its runtime and its restart policy)
        let err = stored_config(&rec("{")).unwrap_err().to_string();
        assert!(err.contains("configuration of container c"), "{err}");
        let own = ContainerConfig {
            stop_signal: "SIGUSR1".into(),
            ..Default::default()
        };
        let stored = rec(&serde_json::to_string(&own).unwrap());
        assert_eq!(stored_config(&stored).unwrap().stop_signal, "SIGUSR1");
    }

    #[test]
    fn only_a_user_the_image_lacks_is_made_later() {
        let (passwd, group) = (b"root:x:0:0::/root:/bin/sh\n", b"root:x:0:\n");
        let req = CreateContainerRequest::default();
        let asks = |user: &str| ContainerConfig {
            user: user.into(),
            ..Default::default()
        };
        // a name the image has no entry for: the container is made as
        // root and the start tells why not
        let (user, why) =
            resolve_container_user_later(passwd, group, &asks("nosuch"), &req, None).unwrap();
        assert_eq!(user.user.uid, 0);
        assert!(why.unwrap().contains("nosuch"));
        // a user that is no user is refused at once
        assert!(resolve_container_user_later(passwd, group, &asks("root:"), &req, None).is_err());
    }

    #[test]
    fn container_ids_are_the_engines_form() {
        assert!(valid_container_id(&"a".repeat(64)));
        assert!(valid_container_id(&"0123456789abcdef".repeat(4)));
        for bad in [
            "/etc",
            "../x",
            "-x",
            "",
            &"A".repeat(64),
            &"a".repeat(63),
            &"a".repeat(65),
        ] {
            assert!(!valid_container_id(bad), "{bad}");
        }
    }
}
