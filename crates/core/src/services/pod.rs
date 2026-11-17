// SPDX-License-Identifier: Apache-2.0
//! Pod management service
//!
//! A pod is a group of containers that share network, IPC, and optionally PID namespaces.
//! This is similar to Kubernetes pods or Podman pods.

use crate::services::cgroups_mode::PodCgroup;
use crate::services::container::ContainerService;
use crate::services::podlogs;
use crate::services::{CgroupMode, CgroupsMode, NetworkMode, NsMode, UsernsChoice};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use thiserror::Error;
use tracing::{info, warn};
use velarx_runtime::pods::slice as podslice;
pub use velarx_wire::wire::PodLogEntry;

#[derive(Error, Debug)]
pub enum PodError {
    #[error("pod not found: {0}")]
    NotFound(String),
    #[error("adding pod to state: name \"{0}\" is in use: pod already exists")]
    AlreadyExists(String),
    #[error("container error: {0}")]
    Container(String),
    /// The container of the pod cannot be made: its image is not there.
    #[error("container error: {0}")]
    ImageNotFound(String),
    #[error(transparent)]
    Database(#[from] velarx_types::DbError),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("pod is running")]
    Running,
    #[error("invalid state: {0}")]
    InvalidState(String),
    #[error("invalid config provided: {0}")]
    InvalidConfig(String),
    /// What `pod logs` refuses, in podman's words
    #[error("{0}")]
    Logs(String),
    #[error("{0}")]
    Ids(#[from] velarx_base::ids::IdsError),
}

pub type PodResult<T> = Result<T, PodError>;

/// Why a pod cannot have limits.
const NO_POD_CGROUP: &str =
    "the resources of a pod are the limits of its cgroup, which the engine \
     makes only in the cgroup tree of the server (cgroup_manager cgroupfs or systemd, with a \
     cgroup it owns)";

pub use velarx_wire::request::INIT_TYPE_ANNOTATION;

/// What an init container of a pod does at the start of the pod.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InitKind {
    /// Runs at the first start of the pod and is removed once it succeeded
    Once,
    /// Runs at each start of the pod
    Always,
}

impl InitKind {
    /// `once` or `always`.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "once" => Some(Self::Once),
            "always" => Some(Self::Always),
            _ => None,
        }
    }
}

/// Whether the container of `rec` is an init container of its pod, and what
/// kind.
pub fn init_kind(rec: &velarx_db::ContainerRecord) -> Option<InitKind> {
    let config: crate::container::ContainerConfig = serde_json::from_str(&rec.config).ok()?;
    config
        .options
        .annotations
        .get(INIT_TYPE_ANNOTATION)
        .and_then(|t| InitKind::parse(t))
}

pub use velarx_proto::pod::{
    PodDnsConfig, PodPortMapping, PodResources, PodSecurityContext, PodSpec,
};
use velarx_runtime::pods::store::{settled_state, MemberRun, PodStore, StoreError};
pub use velarx_runtime::pods::store::{Pod, PodState};

impl From<StoreError> for PodError {
    fn from(e: StoreError) -> Self {
        match e {
            StoreError::NotFound(id) => PodError::NotFound(id),
            StoreError::AlreadyExists(name) => PodError::AlreadyExists(name),
            StoreError::Io(e) => PodError::Io(e),
        }
    }
}

/// The blocking calls of the store, off the async threads.
trait StoreBlocking {
    async fn lock_blocking(&self, id: &str, kind: &'static str) -> PodResult<std::fs::File>;
    async fn lock_pod_blocking(&self, id: &str) -> PodResult<std::fs::File>;
    async fn modify_blocking<R: Send + 'static>(
        &self,
        id: &str,
        f: impl FnOnce(&mut Pod) -> R + Send + 'static,
    ) -> PodResult<R>;
    async fn list_blocking(&self) -> PodResult<Vec<Pod>>;
    async fn remove_blocking(&self, id: &str) -> PodResult<()>;
    async fn add_blocking(&self, pod: &Pod) -> PodResult<()>;
}

impl StoreBlocking for PodStore {
    async fn lock_blocking(&self, id: &str, kind: &'static str) -> PodResult<std::fs::File> {
        let (store, id) = (self.clone(), id.to_string());
        tokio::task::spawn_blocking(move || store.lock_file(&id, kind))
            .await
            .map_err(|e| PodError::Io(std::io::Error::other(e)))?
            .map_err(Into::into)
    }

    async fn lock_pod_blocking(&self, id: &str) -> PodResult<std::fs::File> {
        self.lock_blocking(id, "lock").await
    }

    async fn modify_blocking<R: Send + 'static>(
        &self,
        id: &str,
        f: impl FnOnce(&mut Pod) -> R + Send + 'static,
    ) -> PodResult<R> {
        let (store, id) = (self.clone(), id.to_string());
        tokio::task::spawn_blocking(move || store.modify(&id, f))
            .await
            .map_err(|e| PodError::Io(std::io::Error::other(e)))?
            .map_err(Into::into)
    }

    async fn list_blocking(&self) -> PodResult<Vec<Pod>> {
        let store = self.clone();
        tokio::task::spawn_blocking(move || store.list())
            .await
            .map_err(|e| PodError::Io(std::io::Error::other(e)))?
            .map_err(Into::into)
    }

    async fn remove_blocking(&self, id: &str) -> PodResult<()> {
        let (store, id) = (self.clone(), id.to_string());
        tokio::task::spawn_blocking(move || store.remove(&id))
            .await
            .map_err(|e| PodError::Io(std::io::Error::other(e)))?
            .map_err(Into::into)
    }

    async fn add_blocking(&self, pod: &Pod) -> PodResult<()> {
        let (store, pod) = (self.clone(), pod.clone());
        tokio::task::spawn_blocking(move || store.add(&pod))
            .await
            .map_err(|e| PodError::Io(std::io::Error::other(e)))?
            .map_err(Into::into)
    }
}

/// Pod service for managing pods
pub struct PodService {
    container_service: Arc<ContainerService>,
    store: PodStore,
}

fn invalid(m: String) -> PodError {
    PodError::InvalidConfig(m)
}

/// The pod of `pods` named `key`, else the one whose ID starts with it
/// (podman's: a prefix of one ID, as `pod ps` shows it).
fn find_pod(pods: Vec<Pod>, key: &str) -> PodResult<Pod> {
    if let Some(pod) = pods.iter().find(|p| p.name == key) {
        return Ok(pod.clone());
    }
    if velarx_types::digest::is_hex_id(key) {
        let mut found = pods.into_iter().filter(|p| p.id.starts_with(key));
        if let Some(pod) = found.next() {
            if found.next().is_some() {
                return Err(PodError::InvalidConfig(format!(
                    "more than one result for pod ID {key}"
                )));
            }
            return Ok(pod);
        }
    }
    Err(PodError::NotFound(key.to_string()))
}

/// Whether the pod of `spec` was made with `--cgroups=scope`.
fn scope_mode(spec: &PodSpec) -> bool {
    spec.cgroup_mode == Some(CgroupMode::Scope)
}

/// The `--cgroups` of a pod are words of `run`; a pod
/// made with `--cgroups=disabled` has no cgroup: what would make one is an
/// error, as for a container.
fn check_disabled_pod(spec: &PodSpec) -> PodResult<()> {
    if spec.cgroups != CgroupsMode::Disabled {
        return Ok(());
    }
    if spec.cgroup_parent.is_some() {
        return Err(invalid(
            "cannot set cgroup parent if not creating cgroups".to_string(),
        ));
    }
    if spec.resources.is_some() {
        return Err(invalid(
            "cannot set the resources of a pod without cgroups: --cgroups=disabled makes no \
             cgroup to apply them to"
                .to_string(),
        ));
    }
    Ok(())
}

/// The `--cgroups` mode of a member of a pod of `spec` (`default`:
/// the configuration's, for one that sets none): the members of a pod made
/// `disabled` are disabled too, and cannot ask for a cgroup (there is no
/// cgroup of the pod to put it below: podman refuses it as well).  A member
/// that is disabled in a pod with cgroups is in no cgroup of its own.
fn member_cgroups(
    req: &mut crate::services::CreateContainerRequest,
    spec: &PodSpec,
    default: CgroupsMode,
) -> PodResult<()> {
    if spec.cgroups == CgroupsMode::Disabled {
        if !matches!(req.cgroups, CgroupsMode::Unset | CgroupsMode::Disabled) {
            return Err(invalid(format!(
                "--cgroups={}: the pod {} was made with --cgroups=disabled, its containers have \
                 no cgroup",
                req.cgroups, spec.name
            )));
        }
        req.cgroups = CgroupsMode::Disabled;
    } else if req.cgroups.is_unset() {
        req.cgroups = default;
    }
    // (the members are where the pod is: one cgroup mode for all)
    if spec.cgroups == CgroupsMode::Split && req.cgroups == CgroupsMode::Scope {
        return Err(invalid(format!(
            "--cgroups=scope: the pod {} was made with --cgroups=split, which its containers \
             share",
            spec.name
        )));
    }
    if let Some(pod_mode) = spec.cgroup_mode {
        let (value, asked) = req.cgroups.split();
        if let Some(asked) = asked.filter(|a| *a != pod_mode) {
            return Err(invalid(format!(
                "--cgroups={asked}: the pod {} was made with --cgroups={pod_mode}, which its \
                 containers share",
                spec.name
            )));
        }
        req.cgroups = value;
        req.cgroup_mode = Some(pod_mode);
    }
    Ok(())
}

/// The `--cgroups` mode of the pod `id_or_name` (a name, an id or a prefix
/// of one) of the
/// directory of the pods `dir`, read from its file: for the engine of a
/// command, before it has services.
pub fn stored_pod_cgroups(dir: &Path, id_or_name: &str) -> Option<CgroupsMode> {
    // (found as the pod service finds it: a name, else a prefix of one ID)
    find_pod(PodStore::read_all(dir).ok()?, id_or_name)
        .ok()
        .map(|p| p.spec.cgroups)
}

/// What a member of a pod of `spec` takes from the pod: its volumes, and
/// the restart policy, cgroup parent and /dev/shm size it sets none of.
fn apply_pod_defaults(req: &mut crate::services::CreateContainerRequest, spec: &PodSpec) {
    for v in &spec.volumes {
        if !req.volumes.contains(v) {
            req.volumes.push(v.clone());
        }
    }
    if req.restart_policy.is_none() {
        req.restart_policy = spec.restart_policy.clone();
    }
    if req.runtime.is_none() {
        req.runtime = spec.runtime.clone();
    }
    // (a split container is in its unit's cgroup, a disabled one in no
    // cgroup of its own, not in the pod's)
    if req.cgroup_parent.is_none()
        && !matches!(req.cgroups, CgroupsMode::Split | CgroupsMode::Disabled)
    {
        req.cgroup_parent = spec.cgroup_parent.clone();
    }
    if req.shm_size.is_none() {
        req.shm_size = spec.shm_size;
    }
    if req.shm_size_systemd.is_none() {
        req.shm_size_systemd = spec.shm_size_systemd;
    }
    for d in &spec.devices {
        let device = velarx_wire::request::DeviceMapping::parse(d);
        if !req
            .devices
            .iter()
            .any(|r| r.path_in_container == device.path_in_container)
        {
            req.devices.push(device);
        }
    }
    req.no_hosts |= spec.no_hosts;
    req.no_hostname |= spec.no_hostname;
    if req.hosts_file.is_none() {
        req.hosts_file = spec.hosts_file.clone();
    }
}

/// The infra container of a pod on the host network is in the host's network
/// namespace: the OCI spec reads the `network_mode` for that (a `host` in the
/// list of networks alone leaves the container a namespace of its own, which
/// is then where a connection to a port of the pod is made).
fn infra_host_network(req: &mut crate::services::CreateContainerRequest, spec: &PodSpec) {
    if spec.networks.iter().any(|n| n == "host") {
        req.network_mode = NetworkMode::Host;
        req.networks.clear();
    }
}

/// The namespaces of the infra container `infra` that a member of a pod
/// of `spec` joins.  A member cannot ask for another one of its own where
/// the pod shares the namespace.
fn apply_shares(
    req: &mut crate::services::CreateContainerRequest,
    spec: &PodSpec,
    infra: &str,
) -> PodResult<()> {
    let join = NsMode::Container(infra.to_string());
    let share = |kind: &str, shared: bool, mode: &mut NsMode| -> PodResult<()> {
        if !shared {
            return Ok(());
        }
        match mode {
            NsMode::Default | NsMode::Pod | NsMode::Private => {
                *mode = join.clone();
                Ok(())
            }
            m if *m == join => Ok(()),
            m => Err(PodError::InvalidConfig(format!(
                "the {kind} namespace `{m}` cannot be used: the pod shares its {kind} namespace"
            ))),
        }
    };
    // a pod on the host network has no namespace to join (and one of the
    // host cannot be joined by a process of a user namespace): its members
    // use the host's like its infra container
    if spec.share_net && spec.networks.iter().any(|n| n == "host") {
        match &req.network_mode {
            NetworkMode::Unset
            | NetworkMode::Pod
            | NetworkMode::Private
            | NetworkMode::Default
            | NetworkMode::Host => req.network_mode = NetworkMode::Host,
            m => {
                return Err(PodError::InvalidConfig(format!(
                    "the network namespace `{m}` cannot be used: the pod is on the host network"
                )))
            }
        }
    } else if spec.share_net {
        let join = NetworkMode::Container(infra.to_string());
        match &req.network_mode {
            NetworkMode::Unset | NetworkMode::Pod | NetworkMode::Private | NetworkMode::Default => {
                req.network_mode = join
            }
            m if *m == join => {}
            m => {
                return Err(PodError::InvalidConfig(format!(
                    "the network namespace `{m}` cannot be used: the pod shares its network \
                     namespace"
                )))
            }
        }
    }
    if spec.share_net && (!req.networks.is_empty() || !req.ports.is_empty()) {
        return Err(PodError::InvalidConfig(
            "networks and published ports are those of the pod: set them on the pod".into(),
        ));
    }
    // a pod in the IPC or PID namespace of the host has none to join (a
    // process of a user namespace cannot join the host's): its members use the
    // host's like its infra container
    let in_host = |kind: &str, mode: &mut NsMode| -> PodResult<()> {
        match mode {
            NsMode::Default | NsMode::Pod | NsMode::Private | NsMode::Host => {
                *mode = NsMode::Host;
                Ok(())
            }
            m => Err(PodError::InvalidConfig(format!(
                "the {kind} namespace `{m}` cannot be used: the pod is in the host's"
            ))),
        }
    };
    if spec.host_ipc {
        in_host("ipc", &mut req.ipc_mode)?;
    } else {
        share("ipc", spec.share_ipc, &mut req.ipc_mode)?;
    }
    if spec.host_uts {
        in_host("uts", &mut req.uts_mode)?;
    } else {
        share("uts", spec.share_uts, &mut req.uts_mode)?;
    }
    if spec.host_pid {
        in_host("pid", &mut req.pid_mode)?;
    } else {
        share("pid", spec.share_pid, &mut req.pid_mode)?;
    }
    share("cgroup", spec.share_cgroup, &mut req.cgroupns_mode)?;
    Ok(())
}

/// The `/dev` name the kernel gives a block device.
fn block_device_path(major: u32, minor: u32) -> Option<String> {
    let uevent = std::fs::read_to_string(format!("/sys/dev/block/{major}:{minor}/uevent")).ok()?;
    uevent
        .lines()
        .find_map(|l| l.strip_prefix("DEVNAME="))
        .map(|n| format!("/dev/{n}"))
}

/// The limits of block devices that came as numbers only (the engine API
/// gives no path) get the kernel's name of the device, which `pod inspect`
/// shows; a device that is gone has none.
fn name_block_devices(r: &mut PodResources) {
    for d in r
        .blkio_weight_device
        .iter_mut()
        .chain(&mut r.device_read_bps)
        .chain(&mut r.device_write_bps)
        .filter(|d| d.path.is_empty())
    {
        d.path = block_device_path(d.major, d.minor).unwrap_or_default();
    }
}

/// The name of a pod created without one: `pod-` and 12 hex digits.
pub fn generated_pod_name() -> String {
    let id = velarx_base::random::token();
    format!("pod-{}", &id[..12])
}

/// The containers of a pod a log follow reads, as the pod has them each time.
/// The slice that is the cgroup of the pod `pod_id`, when its containers
/// are scopes in a slice and the pod was made with limits (a pod without
/// has no cgroup of its own: its containers are in the parent).
pub(crate) fn slice_of(
    container_service: &ContainerService,
    pod_id: &str,
    spec: &PodSpec,
) -> PodResult<Option<String>> {
    let Some(parent) = spec.cgroup_parent.as_deref() else {
        return Ok(None);
    };
    if spec.resources.is_none()
        || !matches!(
            container_service.pod_cgroup(Some(parent), scope_mode(spec))?,
            PodCgroup::Slice
        )
    {
        return Ok(None);
    }
    podslice::slice_name(parent, pod_id)
        .map(Some)
        .map_err(PodError::InvalidConfig)
}

/// What the monitor of a member of `pod` applies its exit policy with.
pub(crate) fn plan_of(cs: &ContainerService, pod: &Pod) -> velarx_runtime::pods::exit::PodPlan {
    velarx_runtime::pods::exit::PodPlan {
        slice: slice_of(cs, &pod.id, &pod.spec).ok().flatten(),
        id: pod.id.clone(),
        pods_dir: cs.root_dir.join("pods"),
        mon_root: cs.state_dir.join("mon"),
    }
}

/// The pod the container `id` is a member of.
pub(crate) fn pod_of(cs: &ContainerService, id: &str) -> Option<Pod> {
    PodStore {
        dir: cs.root_dir.join("pods"),
    }
    .list()
    .ok()?
    .into_iter()
    .find(|p| {
        p.container_ids
            .iter()
            .chain(&p.infra_container_id)
            .any(|c| c == id)
    })
}

struct PodMembers {
    service: Arc<PodService>,
    pod_id: String,
    filter: Vec<String>,
}

impl podlogs::Observe for PodMembers {
    async fn members(&self) -> Option<Vec<podlogs::Member>> {
        let service = &self.service;
        let pod = service.get(&self.pod_id).await.ok()?;
        let mut members = Vec::new();
        for (index, t) in service
            .log_targets(&pod, &self.filter)
            .await
            .into_iter()
            .enumerate()
        {
            members.push(podlogs::Member {
                index,
                active: service.container_service.is_active(&t.id).await,
                journal: t.loc.driver == crate::monitor::config::LogDriver::Journald,
                id: t.id,
                name: t.name,
                path: t.loc.path,
                allow_dir: t.loc.allow_dir,
            });
        }
        Some(members)
    }
}

/// A pod a container is made for: held by its operation lock until this
/// is dropped.
#[derive(Debug)]
pub struct JoinedPod {
    id: String,
    _lock: std::fs::File,
}

impl JoinedPod {
    /// The id of the pod.
    pub fn id(&self) -> &str {
        &self.id
    }
}

impl PodService {
    /// The pods of `root_dir/pods`.
    pub fn new(container_service: Arc<ContainerService>, root_dir: PathBuf) -> Self {
        let service = Self {
            container_service,
            store: PodStore {
                dir: root_dir.join("pods"),
            },
        };
        // the cgroups of the pods that have limits are made again with them
        if let Some(cm) = &service.container_service.cgroup_manager {
            for pod in service.stored_pods() {
                if let Some(r) = &pod.spec.resources {
                    cm.remember_pod(&pod.id, r);
                }
            }
        }
        for pod in service.stored_pods() {
            service.remember_slice(&pod.id, &pod.spec);
        }
        service
    }

    /// Tell the container service the slice of the pod and its limits (for
    /// a member that starts alone).
    fn remember_slice(&self, pod_id: &str, spec: &PodSpec) {
        if let (Ok(Some(name)), Some(limits)) = (self.slice_of(pod_id, spec), &spec.resources) {
            self.container_service
                .pod_slices
                .remember(&name, pod_id, limits);
        }
    }

    /// The cgroup of `spec`'s pod `pod_id` with its limits, made before the
    /// containers: the limits the pod cannot have are an error here.
    fn make_cgroup(&self, pod_id: &str, spec: &PodSpec) -> PodResult<()> {
        let Some(limits) = spec.resources.as_ref().filter(|r| !r.is_empty()) else {
            return Ok(());
        };
        limits.check().map_err(PodError::InvalidConfig)?;
        let parent = spec.cgroup_parent.as_deref();
        match self
            .container_service
            .pod_cgroup(parent, scope_mode(spec))?
        {
            PodCgroup::Tree(cm) => cm
                .set_pod_limits(parent, pod_id, limits)
                .map_err(|e| PodError::InvalidConfig(format!("the cgroup of the pod: {e}"))),
            PodCgroup::Slice => {
                let name = self.slice_of(pod_id, spec)?.ok_or_else(|| {
                    PodError::InvalidConfig("the pod has no cgroup parent for its slice".into())
                })?;
                podslice::start(&name, pod_id, limits).map_err(PodError::InvalidConfig)?;
                self.container_service
                    .pod_slices
                    .remember(&name, pod_id, limits);
                Ok(())
            }
            PodCgroup::None => Err(PodError::InvalidConfig(NO_POD_CGROUP.into())),
        }
    }

    /// The slice that is the cgroup of the pod `pod_id`, when its containers
    /// are scopes in a slice and the pod was made with limits (a pod without
    /// has no cgroup of its own: its containers are in the parent).
    fn slice_of(&self, pod_id: &str, spec: &PodSpec) -> PodResult<Option<String>> {
        slice_of(&self.container_service, pod_id, spec)
    }

    /// The cgroup of the pod, relative to the cgroup file system (empty
    /// without one: a pod made disabled, or where no cgroup is made for pods).
    pub fn cgroup_path(&self, pod: &Pod) -> PodResult<String> {
        let spec = &pod.spec;
        if spec.cgroups == CgroupsMode::Disabled {
            return Ok(String::new());
        }
        let parent = spec.cgroup_parent.as_deref();
        Ok(
            match self
                .container_service
                .pod_cgroup(parent, scope_mode(spec))?
            {
                PodCgroup::Tree(cm) => cm
                    .pod_cgroup_path(parent, &pod.id)
                    .map(|p| format!("/{}", p.trim_start_matches('/')))
                    .unwrap_or_default(),
                PodCgroup::Slice => match self.slice_of(&pod.id, spec) {
                    Ok(Some(name)) => podslice::cgroup_path(&name)?,
                    Err(PodError::Ids(e)) => return Err(e.into()),
                    Ok(None) | Err(_) => String::new(),
                },
                PodCgroup::None => String::new(),
            },
        )
    }

    /// Remove the cgroup or the slice of `spec`'s pod `pod_id`; a pod made
    /// disabled has none, and nothing is touched for it.
    fn remove_cgroup(&self, pod_id: &str, spec: &PodSpec) {
        if spec.cgroups == CgroupsMode::Disabled {
            return;
        }
        if let Some(cm) = &self.container_service.cgroup_manager {
            cm.remove_pod(spec.cgroup_parent.as_deref(), pod_id);
        }
        match self.slice_of(pod_id, spec) {
            Ok(Some(name)) => {
                self.container_service.pod_slices.forget(&name);
                if let Err(e) = podslice::stop(&name) {
                    warn!("The slice {name} of the pod {pod_id} was not stopped: {e}");
                }
            }
            Ok(None) => {}
            Err(e) => warn!("The slice of the pod {pod_id} is not known, not stopped: {e}"),
        }
    }

    /// Replace the limits of the cgroup of the pod (what bounds all its
    /// containers): none takes them away.  The id of the pod.
    pub async fn update_resources(
        &self,
        id_or_name: &str,
        resources: PodResources,
    ) -> PodResult<String> {
        let mut pod = self.get(id_or_name).await?;
        let mut resources = resources;
        name_block_devices(&mut resources);
        resources.check().map_err(PodError::InvalidConfig)?;
        // (a pod made disabled has no cgroup: nothing is made or asked for)
        if pod.spec.cgroups == CgroupsMode::Disabled {
            pod.spec.resources = Some(resources).filter(|r| !r.is_empty());
            check_disabled_pod(&pod.spec)?;
            return Ok(pod.id);
        }
        let parent = pod.spec.cgroup_parent.as_deref();
        match self
            .container_service
            .pod_cgroup(parent, scope_mode(&pod.spec))?
        {
            PodCgroup::Tree(cm) => cm
                .set_pod_limits(parent, &pod.id, &resources)
                .map_err(|e| PodError::InvalidConfig(format!("the cgroup of the pod: {e}")))?,
            PodCgroup::Slice => match self.slice_of(&pod.id, &pod.spec)? {
                Some(name) => {
                    podslice::update(&name, &resources).map_err(PodError::InvalidConfig)?
                }
                None if !resources.is_empty() => {
                    return Err(PodError::InvalidConfig(
                        "the pod was made without limits: its containers are in the slice of \
                         its cgroup parent, it has no cgroup of its own to limit"
                            .into(),
                    ))
                }
                None => {}
            },
            PodCgroup::None if !resources.is_empty() => {
                return Err(PodError::InvalidConfig(NO_POD_CGROUP.into()))
            }
            PodCgroup::None => {}
        }
        // (the slice of a pod made with limits stays when they are taken
        // away: its containers are in it)
        let slice = pod.spec.resources.is_some()
            && matches!(
                self.container_service
                    .pod_cgroup(pod.spec.cgroup_parent.as_deref(), scope_mode(&pod.spec))?,
                PodCgroup::Slice
            );
        let resources = Some(resources).filter(|r| slice || !r.is_empty());
        let mut spec = pod.spec;
        spec.resources = resources.clone();
        self.remember_slice(&pod.id, &spec);
        self.store
            .modify_blocking(&pod.id, move |p| p.spec.resources = resources)
            .await?;
        Ok(pod.id)
    }

    /// Create a new pod
    pub async fn create(&self, spec: PodSpec) -> PodResult<String> {
        // a pod without a name gets one, as with podman
        let mut spec = spec;
        if spec.name.is_empty() {
            spec.name = generated_pod_name();
        }
        spec.resources = spec.resources.filter(|r| !r.is_empty());
        if let Some(r) = &mut spec.resources {
            name_block_devices(r);
        }
        spec.check().map_err(PodError::InvalidConfig)?;
        if spec.no_infra {
            // (no namespace to share without the infra container)
            spec.share_pid = false;
            spec.share_ipc = false;
            spec.share_net = false;
            spec.share_uts = false;
            spec.share_cgroup = false;
        }
        // (`[containers] cgroups` of the configuration; the pod keeps the mode it
        // was made with)
        if spec.cgroups.is_unset() {
            spec.cgroups = self.container_service.default_cgroups();
        }
        check_disabled_pod(&spec)?;
        // (a command's split is the cgroup of its unit, which a pod does not
        // share; the server splits its own, where the pods are)
        if spec.cgroups == CgroupsMode::Split && self.container_service.caller_supervised {
            return Err(invalid(
                "pod create --cgroups=split: a command splits the cgroup of its systemd \
                 unit for its container, not for a pod (the engine service has pods)"
                    .to_string(),
            ));
        }
        self.container_service
            .resolve_cgroups(
                &mut spec.cgroups,
                &mut spec.cgroup_mode,
                spec.cgroup_parent.as_deref(),
            )
            .map_err(PodError::InvalidConfig)?;
        // (the slice a server's pod of `--cgroups=scope` gets when it asks
        // for none is no path of the cgroupfs manager to check: `pod clone`
        // sends it back)
        let scopes_in_slice = self
            .container_service
            .pod_scopes_in_slice(scope_mode(&spec))?;
        let default_slice = crate::services::cgroups_mode::default_slice()?;
        if !(scopes_in_slice && spec.cgroup_parent.as_deref() == Some(default_slice)) {
            self.container_service
                .check_parent_kind(spec.cgroup_parent.as_deref())
                .map_err(PodError::InvalidConfig)?;
        }
        // (the server's pod of `--cgroups=scope`: its containers are
        // scopes in the manager's default slice, or in a slice of the pod's
        // own with its limits, as podman's)
        // (a command's pod without limits keeps its members' scopes: it has
        // no slice of its own to make)
        if scopes_in_slice
            && spec.cgroup_parent.is_none()
            && (spec.resources.is_some() || !self.container_service.caller_supervised)
        {
            spec.cgroup_parent = Some(default_slice.to_string());
        }
        if self.get_pod_by_name(&spec.name).await.is_ok() {
            return Err(PodError::AlreadyExists(spec.name.clone()));
        }

        let pod_id = super::container::new_id();

        info!("Creating pod {} ({})", spec.name, pod_id);

        self.make_cgroup(&pod_id, &spec)?;

        let infra_container_id = if spec.no_infra {
            None
        } else {
            match self.create_infra_container(&pod_id, &spec).await {
                Ok(id) => Some(id),
                Err(e) => {
                    self.remove_cgroup(&pod_id, &spec);
                    return Err(e);
                }
            }
        };

        let pod = Pod {
            id: pod_id.clone(),
            name: spec.name.clone(),
            state: PodState::Created,
            infra_container_id,
            container_ids: Vec::new(),
            spec,
            created_at: chrono::Utc::now().to_rfc3339(),
            started_at: None,
            exit_code: None,
            removing: false,
        };

        if let Err(e) = self.store.add_blocking(&pod).await {
            // (a pod of that name was made meanwhile, or the disk failed)
            if let Some(infra) = &pod.infra_container_id {
                if let Err(d) = self.container_service.delete(infra, true).await {
                    warn!("The infra container of the pod {pod_id} was not removed: {d}");
                }
            }
            self.remove_cgroup(&pod_id, &pod.spec);
            return Err(e);
        }

        Ok(pod_id)
    }

    /// The image of the infra container: the pod's, else the configured
    /// one, pulled when missing; else the local pause image.
    async fn infra_image(&self, spec: &PodSpec) -> PodResult<String> {
        let images = &self.container_service.image_service;
        let image = super::infra_image_name([
            spec.infra_image.as_deref(),
            self.container_service
                .containers_config
                .infra_image
                .as_deref(),
        ]);
        if image == super::pause_image_name() {
            return images
                .pause_image()
                .await
                .map_err(|e| PodError::Container(format!("the pause image: {e}")));
        }
        // (an image that is not there is pulled; a store that cannot be
        // read is an error, not a missing image)
        match images.get(&image).await {
            Ok(_) => return Ok(image),
            Err(velarx_types::ImageError::NotFound(_)) => {}
            Err(e) => return Err(PodError::Container(format!("the infra image {image}: {e}"))),
        }
        info!("Pulling the infra image {}", image);
        let (tx, mut rx) = tokio::sync::mpsc::channel(16);
        let drain = tokio::spawn(async move { while rx.recv().await.is_some() {} });
        let pulled = images.pull(&image, false, tx).await;
        let _ = drain.await;
        pulled.map_err(|e| PodError::Container(format!("pull the infra image {image}: {e}")))?;
        Ok(image)
    }

    /// Whether the image `name` has an entrypoint or a command.
    async fn image_has_command(&self, name: &str) -> bool {
        let Ok(image) = self.container_service.image_service.get(name).await else {
            return false;
        };
        serde_json::from_str::<velarx_types::OciConfig>(&image.config)
            .map(|c| {
                c.config.entrypoint.as_ref().is_some_and(|e| !e.is_empty())
                    || c.config.cmd.as_ref().is_some_and(|c| !c.is_empty())
            })
            .unwrap_or(false)
    }

    /// Create the infrastructure (pause) container
    async fn create_infra_container(&self, pod_id: &str, spec: &PodSpec) -> PodResult<String> {
        use crate::services::CreateContainerRequest;

        let infra_image = self.infra_image(spec).await?;
        // The image says what runs (`/catatonit -P`, `/pause`); an image
        // that says nothing runs `/pause`, as with podman.
        let configured = &self.container_service.containers_config;
        let mut infra_command = spec
            .infra_command
            .clone()
            // The configured command goes with the configured image.
            .or_else(|| {
                configured
                    .infra_image
                    .as_ref()
                    .filter(|i| **i == infra_image)
                    .and(configured.infra_command.clone())
            })
            .unwrap_or_default();
        if infra_command.is_empty() && !self.image_has_command(&infra_image).await {
            infra_command = vec!["/pause".to_string()];
        }

        let infra_name = spec
            .infra_name
            .clone()
            .unwrap_or_else(|| format!("{}-infra", &pod_id[..pod_id.len().min(12)]));

        let mut req = CreateContainerRequest {
            name: Some(infra_name),
            // (its cgroup is below the pod's like its members')
            pod: Some(pod_id.to_string()),
            image: infra_image.to_string(),
            conmon_pidfile: spec.infra_conmon_pidfile.clone(),
            // (the infra command replaces the entrypoint of the image, as podman's)
            entrypoint: infra_command,
            hostname: spec.hostname.clone().unwrap_or_else(|| spec.name.clone()),
            ..CreateContainerRequest::default()
        };
        if spec.host_pid {
            req.pid_mode = NsMode::Host;
        }
        if spec.host_ipc {
            req.ipc_mode = NsMode::Host;
        } else if spec.share_ipc {
            // (its /dev/shm is the members')
            req.ipc_mode = NsMode::Shareable;
        }
        if spec.host_uts {
            // (the host's name, which a container of its namespace cannot set)
            if spec.hostname.is_some() {
                return Err(PodError::InvalidConfig(
                    "cannot set hostname when running in the host UTS namespace: invalid configuration"
                        .into(),
                ));
            }
            req.uts_mode = NsMode::Host;
            req.hostname = String::new();
        }
        req.runtime = spec.runtime.clone();
        // (the pod's mode; "" takes the configuration's like any container)
        req.cgroups = spec.cgroups;
        req.networks = spec.networks.clone();
        infra_host_network(&mut req, spec);
        req.dns = spec.dns.servers.clone();
        req.dns_search = spec.dns.searches.clone();
        req.dns_options = spec.dns.options.clone();
        req.add_hosts = spec.add_hosts.clone();
        req.ports = spec
            .ports
            .iter()
            .map(|p| crate::services::PortMapping {
                container_port: p.container_port,
                host_port: p.host_port,
                host_ip: p.host_ip.clone().unwrap_or_default(),
                protocol: p.protocol.clone(),
            })
            .collect();
        // The infra container holds the network namespace of the pod: it
        // takes it from the pool when the pod opts in.
        let shareable = crate::network::engine::SHAREABLE_ANNOTATION;
        if let Some(v) = spec.annotations.get(shareable) {
            req.annotations.insert(shareable.to_string(), v.clone());
        }
        for key in crate::network::engine::CNI_POD_KEYS {
            if let Some(v) = spec.labels.get(key) {
                req.annotations.insert(key.to_string(), v.clone());
            }
        }
        req.labels
            .insert("io.velarx.pod.id".to_string(), pod_id.to_string());
        req.labels
            .insert("io.velarx.pod.name".to_string(), spec.name.clone());
        req.labels
            .insert("io.velarx.infra.container".to_string(), "true".to_string());

        let sc = &spec.security_context;
        req.user = match (sc.run_as_user, sc.run_as_group) {
            (Some(uid), Some(gid)) => format!("{uid}:{gid}"),
            (Some(uid), None) => uid.to_string(),
            // the user of the image, with this group
            (None, Some(gid)) => format!(":{gid}"),
            (None, None) => String::new(),
        };
        req.group_add = sc.supplemental_groups.iter().map(u32::to_string).collect();

        if let Some(userns) = &spec.userns {
            req.userns_mode = userns.clone();
        }
        req.uid_mappings = spec.uid_mappings.clone();
        req.gid_mappings = spec.gid_mappings.clone();
        req.sysctls = spec.sysctls.clone().into_iter().collect();
        req.shm_size = spec.shm_size;
        req.volumes = spec.volumes.clone();
        req.cgroup_parent = self
            .slice_of(pod_id, spec)?
            .or_else(|| spec.cgroup_parent.clone());
        req.cgroup_mode = spec.cgroup_mode;
        req.security_opts = spec.security_opts.clone();
        req.oom_score_adj = spec.infra_oom_score_adj;
        req.read_only_rootfs = spec.infra_read_only;
        req.privileged = spec.infra_privileged;
        req.ip_address = spec.ip.clone();
        req.ip6_address = spec.ip6.clone();
        req.mac_address = spec.mac.clone();
        req.devices = spec
            .devices
            .iter()
            .map(|d| velarx_wire::request::DeviceMapping::parse(d))
            .collect();
        req.hosts_file = spec.hosts_file.clone();
        req.no_hosts = spec.no_hosts;
        req.no_hostname = spec.no_hostname;
        req.shm_size_systemd = spec.shm_size_systemd;
        req.subuidname = spec.subuidname.clone();
        req.subgidname = spec.subgidname.clone();
        req.network_aliases = spec.network_aliases.clone();
        req.cni_annotations = spec.cni_annotations.clone();
        req.cni_ip_ranges = spec.cni_ip_ranges.clone();

        let container_id = self
            .container_service
            .create(req)
            .await
            .map_err(|e| match e {
                crate::services::ContainerError::ImageNotFound(_) => {
                    PodError::ImageNotFound(e.to_string())
                }
                e => PodError::Container(e.to_string()),
            })?;

        info!(
            "Created infra container {} for pod {}",
            container_id, pod_id
        );

        Ok(container_id)
    }

    /// Take the operation lock of the pod `id`: the start, stop, kill,
    /// pause, restart and removal of a pod hold it, so that two of them on
    /// one pod (of this process or another) run one after the other.  The
    /// lock is released when the returned file is dropped.
    pub async fn lock_operation(&self, id: &str) -> PodResult<std::fs::File> {
        self.store.lock_blocking(id, "op.lock").await
    }

    /// Get a pod by ID or name
    pub async fn get(&self, id_or_name: &str) -> PodResult<Pod> {
        if let Ok(pod) = self.get_pod_by_id(id_or_name).await {
            return Ok(pod);
        }
        find_pod(self.list().await?, id_or_name)
    }

    async fn get_pod_by_id(&self, id: &str) -> PodResult<Pod> {
        // (an ID is a file name of the directory, never a path)
        if !velarx_types::digest::is_hex_id(id) {
            return Err(PodError::NotFound(id.to_string()));
        }
        let pod_path = self.store.dir.join(format!("{}.json", id));
        if !pod_path.exists() {
            return Err(PodError::NotFound(id.to_string()));
        }

        let content = std::fs::read_to_string(&pod_path)?;
        let pod: Pod = serde_json::from_str(&content)
            .map_err(|e| PodError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, e)))?;

        Ok(pod)
    }

    async fn get_pod_by_name(&self, name: &str) -> PodResult<Pod> {
        let pods = self.list().await?;
        for pod in pods {
            if pod.name == name {
                return Ok(pod);
            }
        }
        Err(PodError::NotFound(name.to_string()))
    }

    /// The pods on disk, the ones that read.
    fn stored_pods(&self) -> Vec<Pod> {
        self.store.list().unwrap_or_default()
    }

    /// List all pods
    pub async fn list(&self) -> PodResult<Vec<Pod>> {
        self.store.list_blocking().await
    }

    /// Make the cgroup slice of a pod that has limits ready for its start
    /// (it goes with a reboot of the manager).
    pub fn ensure_slice(&self, pod: &Pod) -> PodResult<()> {
        if let (Some(limits), Some(name)) = (
            pod.spec.resources.as_ref(),
            self.slice_of(&pod.id, &pod.spec)?,
        ) {
            podslice::start(&name, &pod.id, limits).map_err(PodError::InvalidConfig)?;
        }
        Ok(())
    }

    /// Take a container out of the list of the members of a pod (it was
    /// removed).
    pub async fn forget_container(&self, pod_id: &str, container_id: &str) -> PodResult<()> {
        let id = self.get(pod_id).await?.id;
        let gone = container_id.to_string();
        self.store
            .modify_blocking(&id, move |p| p.container_ids.retain(|c| *c != gone))
            .await
    }

    /// Record the state of a pod after a start, stop, kill, pause or unpause
    /// of its containers (by the pod or by one of them): what the members
    /// are now, `ended` when none runs.  The members are looked at under the
    /// lock of the pod, and the lock is not held while they change, so the
    /// last change to complete is followed by a settling that sees it: a
    /// start that lands while a stop settles is never overwritten by the
    /// stop.
    pub async fn settle(&self, id: &str, ended: PodState) -> PodResult<()> {
        let _lock = self.store.lock_pod_blocking(id).await?;
        let pod = self.get_pod_by_id(id).await?;
        let mut runs = Vec::new();
        for c in pod.container_ids.iter().chain(&pod.infra_container_id) {
            runs.push(self.member_run(c).await);
        }
        let now = chrono::Utc::now().to_rfc3339();
        self.store
            .modify_blocking(id, move |p| {
                p.state = settled_state(&runs, ended, &p.state);
                if p.state == PodState::Running && p.started_at.is_none() {
                    p.started_at = Some(now);
                }
            })
            .await
    }

    /// [`PodService::settle`] for the pod a container is a member of, if
    /// any (the container started, stopped, was killed or paused on its own).
    pub async fn settle_member(&self, container_id: &str) {
        let Ok(pods) = self.list().await else {
            return;
        };
        let Some(pod) = pods.into_iter().find(|p| {
            p.container_ids
                .iter()
                .chain(&p.infra_container_id)
                .any(|c| c == container_id)
        }) else {
            return;
        };
        if let Err(e) = self.settle(&pod.id, PodState::Stopped).await {
            warn!("Cannot record the state of the pod {}: {}", pod.name, e);
        }
    }

    async fn member_run(&self, id: &str) -> MemberRun {
        match self.container_service.activity_of(id).await {
            (_, true) => MemberRun::Paused,
            (true, false) => MemberRun::Running,
            (false, false) => MemberRun::Idle,
        }
    }

    /// Stop a pod
    pub async fn stop(&self, id_or_name: &str, timeout: u32) -> PodResult<()> {
        let pod = self.get(id_or_name).await?;

        if pod.state == PodState::Stopped || pod.state == PodState::Exited {
            return Ok(());
        }

        info!("Stopping pod {}", pod.name);

        for container_id in pod.container_ids.iter().rev() {
            if let Err(e) = self.container_service.stop(container_id, timeout).await {
                warn!("Error stopping container {}: {}", container_id, e);
            }
        }

        if let Some(infra_id) = &pod.infra_container_id {
            if let Err(e) = self.container_service.stop(infra_id, timeout).await {
                warn!("Error stopping infra container: {}", e);
            }
        }

        // A start that came meanwhile is not overwritten: the pod is
        // stopped if none of its containers runs.
        self.settle(&pod.id, PodState::Stopped).await?;
        self.stop_slice(&pod.id).await
    }

    /// The slice of a stopped pod is gone (the next start makes it again with
    /// its limits); a pod that runs, or has no slice, keeps it.
    pub async fn stop_slice(&self, id: &str) -> PodResult<()> {
        let pod = self.get_pod_by_id(id).await?;
        if pod.state != PodState::Stopped {
            return Ok(());
        }
        if let Some(name) = self.slice_of(&pod.id, &pod.spec)? {
            // (a member that a start of its own put in it meanwhile, with
            // no lock of the pod, keeps it: the manager would stop it too)
            if podslice::populated(&name)? {
                return Ok(());
            }
            if let Err(e) = podslice::stop(&name) {
                warn!(
                    "The slice {name} of the pod {} was not stopped: {e}",
                    pod.id
                );
            }
        }
        Ok(())
    }

    /// Remove a pod
    pub async fn remove(&self, id_or_name: &str, force: bool) -> PodResult<()> {
        let pod = self.get(id_or_name).await?;

        if pod.state == PodState::Running && !force {
            return Err(PodError::Running);
        }

        info!("Removing pod {}", pod.name);
        // From here no container joins the pod (a `run --pod` meanwhile is
        // refused): the members are removed until none is left.
        self.store
            .modify_blocking(&pod.id, |p| p.removing = true)
            .await?;

        // (those gone already are no error)
        let gone = |e: &crate::services::ContainerError| {
            matches!(
                e,
                crate::services::ContainerError::NotFound(_)
                    | crate::services::ContainerError::Database(velarx_types::DbError::NotFound(_))
            )
        };
        let mut infra = pod.infra_container_id.clone();
        loop {
            let members = self.get(&pod.id).await?.container_ids;
            if members.is_empty() {
                break;
            }
            for container_id in &members {
                match self.container_service.delete(container_id, force).await {
                    Err(e) if !gone(&e) => {
                        warn!("Error removing container {}: {}", container_id, e)
                    }
                    _ => {}
                }
            }
            // (the pod forgets them, removed or not: the removal ends)
            self.store
                .modify_blocking(&pod.id, move |p| {
                    p.container_ids.retain(|c| !members.contains(c))
                })
                .await?;
        }

        if let Some(infra_id) = infra.take() {
            match self.container_service.delete(&infra_id, force).await {
                Err(e) if !gone(&e) => warn!("Error removing infra container: {}", e),
                _ => {}
            }
        }

        self.remove_cgroup(&pod.id, &pod.spec);
        // (the answer is after the cgroup is gone: the cgroups of the
        // containers go when their monitors end)
        if let (Some(cm), true) = (
            self.container_service.cgroup_manager.clone(),
            pod.spec.cgroups != CgroupsMode::Disabled,
        ) {
            let (parent, id) = (pod.spec.cgroup_parent.clone(), pod.id.clone());
            let left = tokio::task::spawn_blocking(move || {
                cm.wait_pod_removed(parent.as_deref(), &id, std::time::Duration::from_secs(10))
            })
            .await;
            // (podman reports the cgroup it cannot remove; the pod goes all
            // the same)
            match left {
                Ok(Ok(Some(dir))) => warn!(
                    "The cgroup of the pod {} is not empty 10 seconds after its containers \
                     were removed, it stays: {}",
                    pod.name,
                    dir.display()
                ),
                Ok(Ok(None)) => {}
                Ok(Err(e)) => warn!(
                    "Cannot wait for the cgroup of the pod {} to go: {e}",
                    pod.name
                ),
                Err(e) => warn!(
                    "Cannot wait for the cgroup of the pod {} to go: {e}",
                    pod.name
                ),
            }
        }

        self.store.remove_blocking(&pod.id).await?;

        Ok(())
    }

    /// The pod is being removed: no container is added to it from now on.
    pub async fn begin_removal(&self, id_or_name: &str) -> PodResult<()> {
        let id = self.get(id_or_name).await?.id;
        self.store.modify_blocking(&id, |p| p.removing = true).await
    }

    /// The removal of the pod failed: it takes containers again.
    pub async fn cancel_removal(&self, id_or_name: &str) -> PodResult<()> {
        let id = self.get(id_or_name).await?.id;
        self.store
            .modify_blocking(&id, |p| p.removing = false)
            .await
    }

    /// Add a container to a pod (refused while it is removed)
    pub async fn add_container(&self, pod_id: &str, container_id: &str) -> PodResult<()> {
        let id = self.get(pod_id).await?.id;
        let container_id = container_id.to_string();
        self.store
            .modify_blocking(&id, move |p| {
                if p.removing {
                    return Err(PodError::InvalidState(format!(
                        "pod {} is being removed",
                        p.name
                    )));
                }
                if !p.container_ids.contains(&container_id) {
                    p.container_ids.push(container_id);
                }
                Ok(())
            })
            .await?
    }

    /// Make a container of the pod `req.pod` join the namespaces the pod
    /// shares (those of its infra container): the network, IPC, UTS, PID
    /// and cgroup namespaces it was created with.  Returns the pod, held
    /// by its operation lock until the caller has added the container to
    /// it (or failed to make it): the removal of the pod, which holds the
    /// lock, comes before the container joins (the pod is then gone: the
    /// create is refused) or after it (the container goes with the pod),
    /// never in the middle of its creation.
    pub async fn prepare_member(
        &self,
        req: &mut crate::services::CreateContainerRequest,
    ) -> PodResult<Option<JoinedPod>> {
        let Some(name) = req.pod.clone().filter(|p| !p.is_empty()) else {
            return Ok(None);
        };
        let id = self.get(&name).await?.id;
        // (a pod removed meanwhile has no lock: the pod of that name, if
        // one was made again, is another one)
        let gone = |e| match e {
            PodError::NotFound(_) => PodError::NotFound(name.clone()),
            e => e,
        };
        let lock = self.lock_operation(&id).await.map_err(gone)?;
        // (what the operation before this one left)
        let pod = self.get_pod_by_id(&id).await.map_err(gone)?;
        if pod.removing {
            return Err(PodError::InvalidState(format!(
                "pod {} is being removed",
                pod.name
            )));
        }
        let infra = pod.infra_container_id.clone();
        if infra.is_none() && !pod.spec.no_infra {
            return Err(PodError::InvalidConfig(format!(
                "the pod {} has no infra container to share namespaces with",
                pod.name
            )));
        }
        req.pod = Some(pod.id.clone());
        if let Some(infra) = &infra {
            apply_shares(req, &pod.spec, infra)?;
        }
        // the user namespace of a pod is its infra container's
        if let Some(infra) = infra
            .as_ref()
            .filter(|_| pod.spec.userns.as_ref().is_some_and(|u| !u.is_host()))
        {
            let join = UsernsChoice::Container(infra.clone());
            let own = !req.userns_mode.is_host() && req.userns_mode != join;
            if own
                || !req.uidmap.is_empty()
                || !req.gidmap.is_empty()
                || !req.uid_mappings.is_empty()
                || !req.gid_mappings.is_empty()
                || req.subuidname.is_some()
                || req.subgidname.is_some()
            {
                return Err(PodError::InvalidConfig(
                    "the pod has a user namespace: its containers cannot have one of their own"
                        .into(),
                ));
            }
            req.userns_mode = join;
        }
        if pod.spec.share_uts {
            // /etc/hostname says what the shared namespace has
            let pod_hostname = pod
                .spec
                .hostname
                .clone()
                .unwrap_or_else(|| pod.spec.name.clone());
            if !req.hostname.is_empty() && req.hostname != pod_hostname {
                return Err(PodError::InvalidConfig(
                    // (podman's words)
                    "cannot set hostname when joining the pod UTS namespace: invalid configuration"
                        .into(),
                ));
            }
            req.hostname = pod_hostname;
        }
        if pod.spec.host_uts && !req.hostname.is_empty() {
            return Err(PodError::InvalidConfig(
                "cannot set hostname when running in the host UTS namespace: invalid configuration"
                    .into(),
            ));
        }
        member_cgroups(req, &pod.spec, self.container_service.default_cgroups())?;
        apply_pod_defaults(req, &pod.spec);
        // (in the slice of the pod when it has one)
        if req.cgroup_parent.is_some() && req.cgroup_parent == pod.spec.cgroup_parent {
            if let Some(slice) = self.slice_of(&pod.id, &pod.spec)? {
                req.cgroup_parent = Some(slice);
            }
        }
        if let Some(infra) = infra {
            // started after it (podman starts the infra container first)
            if !req.requires.contains(&infra) {
                req.requires.push(infra.clone());
            }
            // the containers of a pod share the SELinux label of its infra
            req.selinux_share_with = Some(infra);
        }
        // (not in the cgroup of the pod: the id is still the pod's)
        if pod.spec.no_share_parent {
            req.pod = None;
        }
        Ok(Some(JoinedPod {
            id: pod.id,
            _lock: lock,
        }))
    }

    /// The containers of the pod whose logs `filter` selects (all of them
    /// when it is empty), the infra container first, as `podman pod logs`
    /// takes them.
    async fn log_targets(&self, pod: &Pod, filter: &[String]) -> Vec<LogTarget> {
        let mut candidates: Vec<(String, String)> = Vec::new();
        for id in pod.infra_container_id.iter().chain(&pod.container_ids) {
            if let Ok(info) = self.container_service.inspect(id).await {
                candidates.push((id.clone(), info.name.unwrap_or_else(|| id.clone())));
            }
        }
        let mut targets = Vec::new();
        for (id, name) in candidates {
            if !filter.is_empty() && !filter.iter().any(|f| *f == name || *f == id) {
                continue;
            }
            let Ok(loc) = self.container_service.log_location(&id).await else {
                continue;
            };
            targets.push(LogTarget { id, name, loc });
        }
        targets
    }

    /// Whether the logs of `targets` can be read, as podman refuses: a
    /// container named by `filter` that is not in the pod (`pod_arg` is the
    /// pod as the user wrote it), one whose log driver keeps no log.
    fn check_log_targets(pod_arg: &str, filter: &[String], targets: &[LogTarget]) -> PodResult<()> {
        use crate::monitor::config::LogDriver;
        if let Some(f) = filter
            .iter()
            .find(|f| !targets.iter().any(|t| *f == &t.name || *f == &t.id))
        {
            return Err(PodError::Logs(format!(
                "container {f} is not in pod {pod_arg}: no such container"
            )));
        }
        for t in targets {
            let why = match t.loc.driver {
                LogDriver::K8sFile | LogDriver::Journald => continue,
                LogDriver::None => "the 'none' log driver, cannot read logs: this container is not logging output",
                LogDriver::Passthrough => "the 'passthrough' log driver, cannot read logs: this container is not logging output",
                LogDriver::Syslog => "the 'syslog' log driver, cannot read logs: the logs are in syslog",
            };
            return Err(PodError::Logs(format!("this container is using {why}")));
        }
        Ok(())
    }

    /// `--since` or `--until` (`what`) of the logs of a pod.
    pub fn log_time(what: &str, spec: Option<&str>) -> PodResult<Option<i64>> {
        velarx_wire::monitor::logfmt::parse_pod_log_time(
            what,
            spec,
            velarx_wire::monitor::logfmt::now_ns(),
        )
        .map_err(PodError::Logs)
    }

    /// Get aggregated logs from all containers in a pod
    ///
    /// Returns the log entries of the containers (those `containers_filter`
    /// names, else all, the infra container included) sorted by time.
    /// `tail` is the number of lines at the end of the log of each
    /// container (0: none).
    pub async fn logs(
        &self,
        id_or_name: &str,
        since_ns: Option<i64>,
        until_ns: Option<i64>,
        tail: Option<u64>,
        containers_filter: &[String],
    ) -> PodResult<Vec<PodLogEntry>> {
        let pod = self.get(id_or_name).await?;
        let targets = self.log_targets(&pod, containers_filter).await;
        Self::check_log_targets(id_or_name, containers_filter, &targets)?;
        let mut all_entries = Vec::new();
        if tail == Some(0) {
            return Ok(all_entries);
        }
        let containers = targets.len();
        for (index, t) in targets.into_iter().enumerate() {
            let entries = self
                .container_service
                .get_logs(&t.id, since_ns, until_ns, tail)
                .await
                .map_err(|e| PodError::Logs(format!("reading the log of {}: {e}", t.name)))?;
            for entry in entries {
                all_entries.push(PodLogEntry {
                    container_name: t.name.clone(),
                    container_id: t.id.clone(),
                    container_index: index,
                    containers,
                    timestamp: entry.timestamp.clone().unwrap_or_default(),
                    stream: format!("{:?}", entry.stream).to_lowercase(),
                    message: entry.message.clone(),
                });
            }
        }
        all_entries.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));
        Ok(all_entries)
    }

    /// A notice for every change of a container: those this process sees
    /// (the monitors it follows) and the changes of the database (the others).
    fn changes_of_containers(&self) -> PodResult<tokio::sync::broadcast::Receiver<()>> {
        let (tx, rx) = tokio::sync::broadcast::channel(16);
        let mut notices = self.container_service.subscribe_notices();
        let mut db = self
            .container_service
            .db
            .watch_changes()
            .map_err(|e| PodError::Logs(format!("watching the containers: {e}")))?;
        tokio::spawn(async move {
            loop {
                let db_changed = async {
                    if db.changed().await.is_err() {
                        std::future::pending::<()>().await;
                    }
                };
                tokio::select! {
                    n = notices.recv() => {
                        if matches!(n, Err(tokio::sync::broadcast::error::RecvError::Closed)) {
                            break;
                        }
                    }
                    _ = db_changed => {}
                }
                // (gone with the last following)
                if tx.send(()).is_err() {
                    break;
                }
            }
        });
        Ok(rx)
    }

    /// Follow the logs of the containers of a pod (those `containers_filter`
    /// names, else all), like `logs` but going on until they have all
    /// exited (the infra container too: it runs as long as the pod does) and
    /// their logs are read.  As with podman, a container that joins the pod
    /// meanwhile is not followed.
    pub async fn follow_logs(
        self: &Arc<Self>,
        id_or_name: &str,
        since_ns: Option<i64>,
        until_ns: Option<i64>,
        tail: Option<u64>,
        containers_filter: &[String],
    ) -> PodResult<podlogs::Following> {
        use crate::services::podlogs;
        let pod = self.get(id_or_name).await?;
        // (the notices first: nothing that happens next is missed; and the
        // changes of the database: what another process follows)
        let changes = self.changes_of_containers()?;
        let targets = self.log_targets(&pod, containers_filter).await;
        Self::check_log_targets(id_or_name, containers_filter, &targets)?;
        // The exits are notices of the monitors this process follows: those
        // of the members another process started and nobody follows are
        // followed too (the engine of a command follows only what it
        // started).
        for t in &targets {
            let _ = self.container_service.follow(&t.id).await;
        }
        let observe = PodMembers {
            service: Arc::clone(self),
            pod_id: pod.id.clone(),
            filter: containers_filter.to_vec(),
        };
        Ok(podlogs::follow(
            observe,
            changes,
            podlogs::FollowOptions {
                since_ns,
                until_ns,
                tail: tail.map(|n| n as usize),
                window: self.container_service.log_follow_window(),
                journalctl: PathBuf::from("journalctl"),
                containers: targets.len(),
            },
        ))
    }
}

/// A container whose log `pod logs` reads.
struct LogTarget {
    id: String,
    name: String,
    loc: crate::services::LogLocation,
}

#[cfg(test)]
mod tests {
    use crate::services::{CgroupMode, CgroupsMode};

    fn mode(text: &str) -> CgroupsMode {
        text.parse().unwrap()
    }

    #[test]
    fn a_pod_made_disabled_makes_no_cgroup() {
        let spec = |f: &dyn Fn(&mut super::PodSpec)| {
            let mut s = super::PodSpec {
                name: "p".into(),
                cgroups: CgroupsMode::Disabled,
                ..Default::default()
            };
            f(&mut s);
            s
        };
        assert!(super::check_disabled_pod(&spec(&|_| {})).is_ok());
        let parent = super::check_disabled_pod(&spec(&|s| s.cgroup_parent = Some("x".into())));
        assert!(parent.unwrap_err().to_string().contains("cgroup parent"));
        let limits = super::check_disabled_pod(&spec(&|s| {
            s.resources = Some(velarx_proto::pod::PodResources {
                memory: Some(1 << 20),
                ..Default::default()
            })
        }));
        assert!(limits.unwrap_err().to_string().contains("without cgroups"));
        // a pod with cgroups may have both
        assert!(super::check_disabled_pod(&spec(&|s| {
            s.cgroups = CgroupsMode::Unset;
            s.cgroup_parent = Some("x".into());
        }))
        .is_ok());
    }

    #[test]
    fn the_cgroups_mode_of_a_member() {
        let member = |pod: &str, asked: &str, default: &str| {
            let spec = super::PodSpec {
                name: "p".into(),
                cgroups: mode(pod),
                ..Default::default()
            };
            let mut req = crate::services::CreateContainerRequest {
                cgroups: mode(asked),
                ..Default::default()
            };
            super::member_cgroups(&mut req, &spec, mode(default)).map(|()| req.cgroups)
        };
        // the members of a disabled pod are disabled, and cannot ask for a
        // cgroup
        assert_eq!(member("disabled", "", "").unwrap(), CgroupsMode::Disabled);
        assert_eq!(
            member("disabled", "disabled", "").unwrap(),
            CgroupsMode::Disabled
        );
        for other in ["enabled", "no-conmon", "split"] {
            assert!(member("disabled", other, "").is_err(), "{other}");
        }
        // a pod of a mode: its members share it, another one is refused
        let in_scope = |m: &str| {
            let spec = super::PodSpec {
                name: "p".into(),
                cgroup_mode: Some(CgroupMode::Scope),
                ..Default::default()
            };
            let mut req = crate::services::CreateContainerRequest {
                cgroups: mode(m),
                ..Default::default()
            };
            super::member_cgroups(&mut req, &spec, CgroupsMode::Unset)
                .map(|()| (req.cgroups, req.cgroup_mode))
        };
        assert_eq!(
            in_scope("").unwrap(),
            (CgroupsMode::Unset, Some(CgroupMode::Scope))
        );
        assert_eq!(
            in_scope("scope").unwrap(),
            (CgroupsMode::Enabled, Some(CgroupMode::Scope))
        );
        // (a member of a pod of scopes in the pod's tree, or the reverse)
        assert!(member("split", "scope", "").is_err());
        // a pod with cgroups: the member's own, else the configuration's
        assert_eq!(member("", "", "").unwrap(), CgroupsMode::Unset);
        assert_eq!(member("", "", "disabled").unwrap(), CgroupsMode::Disabled);
        assert_eq!(
            member("", "enabled", "disabled").unwrap(),
            CgroupsMode::Enabled
        );
        assert_eq!(
            member("enabled", "disabled", "").unwrap(),
            CgroupsMode::Disabled
        );
        // and a disabled member there takes no cgroup parent of the pod
        let spec = super::PodSpec {
            cgroup_parent: Some("p.slice".into()),
            ..Default::default()
        };
        let mut req = crate::services::CreateContainerRequest::default();
        super::member_cgroups(&mut req, &spec, CgroupsMode::Disabled).unwrap();
        super::apply_pod_defaults(&mut req, &spec);
        assert_eq!(req.cgroup_parent, None);
    }

    #[test]
    fn the_cgroups_mode_of_a_stored_pod() {
        let d = tempfile::tempdir().unwrap();
        let write = |id: &str, name: &str, cgroups: CgroupsMode| {
            let pod = super::Pod {
                id: id.into(),
                name: name.into(),
                state: super::PodState::Created,
                infra_container_id: None,
                container_ids: Vec::new(),
                spec: super::PodSpec {
                    name: name.into(),
                    cgroups,
                    ..Default::default()
                },
                created_at: String::new(),
                started_at: None,
                exit_code: None,
                removing: false,
            };
            std::fs::write(
                d.path().join(format!("{id}.json")),
                serde_json::to_string(&pod).unwrap(),
            )
            .unwrap();
        };
        write("aaaa", "web", CgroupsMode::Disabled);
        write("bbbb", "db", CgroupsMode::Unset);
        assert_eq!(
            super::stored_pod_cgroups(d.path(), "aaaa"),
            Some(CgroupsMode::Disabled)
        );
        assert_eq!(
            super::stored_pod_cgroups(d.path(), "web"),
            Some(CgroupsMode::Disabled)
        );
        assert_eq!(
            super::stored_pod_cgroups(d.path(), "db"),
            Some(CgroupsMode::Unset)
        );
        // a prefix of the ID, as `--pod` takes it
        assert_eq!(
            super::stored_pod_cgroups(d.path(), "aa"),
            Some(CgroupsMode::Disabled)
        );
        assert_eq!(super::stored_pod_cgroups(d.path(), "none"), None);
        assert_eq!(super::stored_pod_cgroups(d.path(), "../x"), None);
    }

    #[test]
    fn pod_create_takes_the_modes_of_run() {
        let spec = |m: CgroupsMode| super::PodSpec {
            cgroups: m,
            ..Default::default()
        };
        super::check_disabled_pod(&spec(CgroupsMode::Disabled)).unwrap();
        // split and scope are enabled with a placement
        super::check_disabled_pod(&spec(CgroupsMode::Split)).unwrap();
        super::check_disabled_pod(&spec(CgroupsMode::Scope)).unwrap();
    }

    #[test]
    fn a_member_without_cgroups_takes_no_cgroup_parent() {
        let spec = super::PodSpec {
            cgroup_parent: Some("p.slice".into()),
            ..Default::default()
        };
        for (mode, parent) in [("", Some("p.slice")), ("disabled", None), ("split", None)] {
            let mut req = crate::services::CreateContainerRequest {
                cgroups: self::mode(mode),
                ..Default::default()
            };
            super::apply_pod_defaults(&mut req, &spec);
            assert_eq!(req.cgroup_parent.as_deref(), parent, "{mode}");
        }
    }

    fn target(name: &str, driver: crate::monitor::config::LogDriver) -> LogTarget {
        LogTarget {
            id: format!("{name}0000"),
            name: name.to_string(),
            loc: crate::services::LogLocation {
                driver,
                path: PathBuf::from("/x"),
                allow_dir: None,
            },
        }
    }

    #[test]
    fn pod_logs_refuses_as_podman_does() {
        use crate::monitor::config::LogDriver;
        let targets = vec![
            target("infra", LogDriver::K8sFile),
            target("a", LogDriver::Journald),
        ];
        assert!(PodService::check_log_targets("p", &[], &targets).is_ok());
        assert!(PodService::check_log_targets("p", &["a".into()], &targets).is_ok());
        let e = PodService::check_log_targets("p", &["nope".into()], &targets).unwrap_err();
        assert_eq!(
            e.to_string(),
            "container nope is not in pod p: no such container"
        );
        let none = vec![
            target("a", LogDriver::K8sFile),
            target("n", LogDriver::None),
        ];
        let e = PodService::check_log_targets("p", &[], &none).unwrap_err();
        assert_eq!(
            e.to_string(),
            "this container is using the 'none' log driver, cannot read logs: \
             this container is not logging output"
        );
    }

    #[test]
    fn pod_logs_times_are_checked_with_podman_s_words() {
        assert_eq!(PodService::log_time("since", None).unwrap(), None);
        let e = PodService::log_time("since", Some("garbage")).unwrap_err();
        assert_eq!(
            e.to_string(),
            "parsing --since \"garbage\": unable to interpret time value"
        );
        assert!(PodService::log_time("until", Some("1h")).unwrap().is_some());
    }

    use super::*;
    use std::collections::BTreeMap;

    fn shared_net_pod(networks: &[&str]) -> PodSpec {
        PodSpec {
            share_net: true,
            networks: networks.iter().map(|n| n.to_string()).collect(),
            ..PodSpec::default()
        }
    }

    #[test]
    fn the_members_of_a_pod_join_its_network_namespace() {
        let mut req = crate::services::CreateContainerRequest::default();
        apply_shares(&mut req, &shared_net_pod(&[]), "infra").unwrap();
        assert_eq!(req.network_mode, NetworkMode::Container("infra".into()));
    }

    #[test]
    fn the_infra_container_of_a_host_network_pod_is_in_the_host_namespace() {
        let mut req = crate::services::CreateContainerRequest {
            networks: vec!["host".to_string()],
            ..Default::default()
        };
        infra_host_network(&mut req, &shared_net_pod(&["host"]));
        assert_eq!(req.network_mode, NetworkMode::Host);
        assert!(req.networks.is_empty());
        let mut req = crate::services::CreateContainerRequest {
            networks: vec!["net1".to_string()],
            ..Default::default()
        };
        infra_host_network(&mut req, &shared_net_pod(&["net1"]));
        assert_eq!(req.network_mode, NetworkMode::Unset);
        assert_eq!(req.networks, ["net1"]);
    }

    #[test]
    fn the_members_of_a_host_network_pod_use_the_host_namespace() {
        let pod = shared_net_pod(&["host"]);
        for asked in ["", "pod", "host"] {
            let mut req = crate::services::CreateContainerRequest {
                network_mode: NetworkMode::parse(asked),
                ..Default::default()
            };
            apply_shares(&mut req, &pod, "infra").unwrap();
            assert_eq!(req.network_mode, NetworkMode::Host, "asked {asked:?}");
        }
        let mut req = crate::services::CreateContainerRequest {
            network_mode: NetworkMode::Off,
            ..Default::default()
        };
        assert!(apply_shares(&mut req, &pod, "infra").is_err());
    }

    #[test]
    fn the_members_of_a_host_pid_and_ipc_pod_use_the_host_namespaces() {
        let pod = PodSpec {
            host_pid: true,
            host_ipc: true,
            share_ipc: false,
            ..PodSpec::default()
        };
        for asked in ["", "pod", "default", "private", "host"] {
            let mut req = crate::services::CreateContainerRequest {
                pid_mode: asked.parse().unwrap(),
                ipc_mode: asked.parse().unwrap(),
                ..Default::default()
            };
            apply_shares(&mut req, &pod, "infra").unwrap();
            assert_eq!((req.pid_mode, req.ipc_mode), (NsMode::Host, NsMode::Host));
        }
        let mut req = crate::services::CreateContainerRequest {
            pid_mode: NsMode::Container("other".into()),
            ..Default::default()
        };
        assert!(apply_shares(&mut req, &pod, "infra").is_err());
        // a pod that shares its PID namespace is joined, not the host's
        // (`pod` and `default` ask for it as podman's words)
        let shared = PodSpec {
            share_pid: true,
            ..PodSpec::default()
        };
        for asked in ["", "pod", "default", "private"] {
            let mut req = crate::services::CreateContainerRequest {
                pid_mode: asked.parse().unwrap(),
                ..Default::default()
            };
            apply_shares(&mut req, &shared, "infra").unwrap();
            assert_eq!(req.pid_mode, NsMode::Container("infra".into()), "{asked}");
        }
    }

    #[test]
    fn test_pod_spec_default() {
        let spec = PodSpec {
            name: "test".to_string(),
            hostname: None,
            networks: vec![],
            dns: PodDnsConfig::default(),
            add_hosts: vec![],
            security_context: PodSecurityContext::default(),
            ports: vec![],
            labels: BTreeMap::new(),
            annotations: BTreeMap::new(),
            share_pid: false,
            share_ipc: true,
            share_net: true,
            share_uts: true,
            share_cgroup: false,
            userns: None,
            infra_image: None,
            infra_command: None,
            infra_name: None,
            exit_policy: Default::default(),
            infra_conmon_pidfile: None,
            ..Default::default()
        };

        assert_eq!(spec.name, "test");
        assert!(spec.hostname.is_none());
        assert!(spec.labels.is_empty());
    }

    #[test]
    fn test_pod_state_equality() {
        assert_eq!(PodState::Created, PodState::Created);
        assert_eq!(PodState::Running, PodState::Running);
        assert_eq!(PodState::Stopped, PodState::Stopped);
        assert_eq!(PodState::Paused, PodState::Paused);

        assert_ne!(PodState::Created, PodState::Running);
        assert_ne!(PodState::Running, PodState::Stopped);
    }

    #[test]
    fn test_pod_error_messages() {
        let err = PodError::NotFound("pod123".to_string());
        assert!(err.to_string().contains("pod123"));

        let err = PodError::AlreadyExists("existing".to_string());
        assert!(err.to_string().contains("existing"));

        let err = PodError::Running;
        assert!(err.to_string().to_lowercase().contains("running"));
    }

    #[test]
    fn test_pod_spec_serialization() {
        let mut labels = BTreeMap::new();
        labels.insert("app".to_string(), "test".to_string());

        let spec = PodSpec {
            name: "my-pod".to_string(),
            hostname: Some("pod-host".to_string()),
            networks: vec![],
            dns: PodDnsConfig::default(),
            add_hosts: vec![],
            security_context: PodSecurityContext::default(),
            ports: vec![],
            labels,
            annotations: BTreeMap::new(),
            share_pid: false,
            share_ipc: true,
            share_net: true,
            share_uts: true,
            share_cgroup: false,
            userns: None,
            infra_image: Some("k8s.gcr.io/pause:3.5".to_string()),
            infra_command: None,
            infra_name: None,
            exit_policy: Default::default(),
            infra_conmon_pidfile: None,
            ..Default::default()
        };

        let json = serde_json::to_string(&spec).unwrap();
        let parsed: PodSpec = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.name, "my-pod");
        assert_eq!(parsed.hostname, Some("pod-host".to_string()));
        assert_eq!(parsed.labels.get("app"), Some(&"test".to_string()));
        assert!(parsed.share_ipc);
    }

    fn stored(id: &str, name: &str) -> Pod {
        Pod {
            id: id.into(),
            name: name.into(),
            state: PodState::Created,
            infra_container_id: None,
            container_ids: Vec::new(),
            spec: PodSpec::default(),
            created_at: String::new(),
            started_at: None,
            exit_code: None,
            removing: false,
        }
    }

    #[test]
    fn a_pod_is_found_by_its_name_or_a_prefix_of_its_id() {
        let pods = || {
            vec![
                stored("abc123", "one"),
                stored("abd456", "abc"),
                stored("ff00", "two"),
            ]
        };
        assert_eq!(find_pod(pods(), "two").unwrap().id, "ff00");
        // (a name wins over a prefix)
        assert_eq!(find_pod(pods(), "abc").unwrap().id, "abd456");
        assert_eq!(find_pod(pods(), "abc1").unwrap().name, "one");
        assert_eq!(find_pod(pods(), "ff").unwrap().name, "two");
        assert!(matches!(
            find_pod(pods(), "ab"),
            Err(PodError::InvalidConfig(m)) if m.contains("more than one")
        ));
        for missing in ["", "abe", "../ff00", "zz"] {
            assert!(
                matches!(find_pod(pods(), missing), Err(PodError::NotFound(_))),
                "{missing}"
            );
        }
        assert!(
            !velarx_types::digest::is_hex_id("../pods/x")
                && !velarx_types::digest::is_hex_id("")
                && velarx_types::digest::is_hex_id("0aF")
        );
    }

    #[test]
    fn test_pod_serialization() {
        let pod = Pod {
            id: "abc123".to_string(),
            name: "test-pod".to_string(),
            state: PodState::Running,
            infra_container_id: Some("infra123".to_string()),
            container_ids: vec!["c1".to_string(), "c2".to_string()],
            spec: PodSpec {
                name: "test-pod".to_string(),
                hostname: None,
                networks: vec![],
                dns: PodDnsConfig::default(),
                add_hosts: vec![],
                security_context: PodSecurityContext::default(),
                ports: vec![],
                labels: BTreeMap::new(),
                annotations: BTreeMap::new(),
                share_pid: false,
                share_ipc: true,
                share_net: true,
                share_uts: true,
                share_cgroup: false,
                userns: None,
                infra_image: None,
                infra_command: None,
                infra_name: None,
                exit_policy: Default::default(),
                infra_conmon_pidfile: None,
                ..Default::default()
            },
            created_at: "2024-01-01T00:00:00Z".to_string(),
            started_at: None,
            exit_code: None,
            removing: false,
        };

        let json = serde_json::to_string(&pod).unwrap();
        assert!(json.contains("abc123"));
        assert!(json.contains("test-pod"));
        assert!(json.contains("Running") || json.contains("running"));
    }

    #[test]
    fn test_pod_state_display() {
        assert_eq!(PodState::Created.to_string(), "created");
        assert_eq!(PodState::Running.to_string(), "running");
        assert_eq!(PodState::Stopped.to_string(), "stopped");
    }
}
