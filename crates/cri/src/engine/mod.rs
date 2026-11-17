// SPDX-License-Identifier: Apache-2.0
//! What the CRI needs from the engine, in the engine's own terms (pods,
//! containers, images), not in the CRI's. The frontend is a wrapper: every
//! feature it lacks is a method that this trait does not have, or one that
//! answers `EngineError::Unsupported` with the reason (the gap list of the
//! tracker is made of those).
//!
//! `Varlink` is the engine as a client of `org.velarx.Engine` on its socket:
//! the only way the frontend reaches it.

pub mod checkpoint;
pub mod varlink;

use std::collections::BTreeMap;
use std::future::Future;
use tokio::io::{AsyncRead, AsyncWrite};
use velarx_proto::engine::{NetworkStatus, RuntimeInfo, StorageUsage, UpdateSpec};
use velarx_proto::request::CreateContainerRequest;
use velarx_proto::workload::{
    ContainerRecord, ImageRecord, MetricDescriptor, PodMetrics, PodRecord, Resources, StatsRecord,
};

#[derive(Debug, thiserror::Error)]
pub enum EngineError {
    #[error("not found: {0}")]
    NotFound(String),
    #[error("{0}")]
    Conflict(String),
    #[error("{0}")]
    Invalid(String),
    #[error("not supported by the engine: {0}")]
    Unsupported(String),
    #[error("{0}")]
    Precondition(String),
    #[error("{0}")]
    Denied(String),
    #[error("{0}")]
    Unauthenticated(String),
    #[error("{0}")]
    Exhausted(String),
    #[error("the engine is not available: {0}")]
    Unavailable(String),
    /// A party gave content that is not what it claims
    #[error("{0}")]
    DataLoss(String),
    #[error("{0}")]
    DeadlineExceeded(String),
    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, EngineError>;

/// What an answer found: `None` for an object that is not there, any other
/// error as it is.
pub fn found<T>(answer: Result<T>) -> Result<Option<T>> {
    match answer {
        Ok(v) => Ok(Some(v)),
        Err(EngineError::NotFound(_)) => Ok(None),
        Err(e) => Err(e),
    }
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Port {
    pub host_ip: String,
    pub host_port: u16,
    pub container_port: u16,
    pub protocol: String,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct IdRange {
    pub container_id: u32,
    pub host_id: u32,
    pub size: u32,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum NsMode {
    #[default]
    Private,
    Host,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct PodCreate {
    pub name: String,
    pub hostname: String,
    pub labels: BTreeMap<String, String>,
    pub dns_servers: Vec<String>,
    pub dns_searches: Vec<String>,
    pub dns_options: Vec<String>,
    pub ports: Vec<Port>,
    pub cgroup_parent: String,
    /// The OCI runtime of the pod (the runtime handler); empty: the default
    pub runtime: String,
    pub sysctls: BTreeMap<String, String>,
    pub net: NsMode,
    /// The network of the pod as the engine names it, when it is not the
    /// engine's default (`cni:NAME`)
    pub network: String,
    /// The annotations of the sandbox and the pod CIDR of the node, for the
    /// plugins of a CNI `network`
    pub cni_annotations: BTreeMap<String, String>,
    pub cni_ip_ranges: Vec<String>,
    /// The image of the infra container; empty: the engine's `infra_image`
    pub infra_image: String,
    pub share_pid: bool,
    pub host_pid: bool,
    pub host_ipc: bool,
    pub userns_auto: bool,
    pub uid_map: Vec<IdRange>,
    pub gid_map: Vec<IdRange>,
    /// How the infra container runs
    pub infra: InfraSecurity,
    /// The limits of the cgroup of the pod, the parent of the cgroups of all
    /// its containers (the sandbox's resources plus its overhead)
    pub resources: Resources,
}

/// The security context and the OOM score of a pod's infra container.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct InfraSecurity {
    pub run_as_user: Option<u32>,
    pub run_as_group: Option<u32>,
    pub supplemental_groups: Vec<u32>,
    pub read_only_rootfs: bool,
    pub privileged: bool,
    /// `--security-opt` forms: `seccomp=`, `apparmor=`, `label=`
    pub security_opts: Vec<String>,
    pub oom_score_adj: Option<i32>,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct ExecSpec {
    pub cmd: Vec<String>,
    pub tty: bool,
    pub stdin: bool,
    pub stdout: bool,
    pub stderr: bool,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct ExecResult {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub exit_code: i32,
}

pub trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}

/// An exec session whose stdio is a byte stream: the output is framed
/// (`stdout`/`stderr` with an 8 byte header) unless a terminal is used.
pub struct ExecStream {
    pub id: String,
    pub framed: bool,
    pub io: Box<dyn Io>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct EngineEvent {
    /// What the event is about: `container` or `pod`
    pub object: String,
    /// The id of the container, or of the pod
    pub container_id: String,
    pub pod_id: String,
    pub action: String,
    pub time_ns: i64,
    /// the attributes of the event: the labels of the container, and more
    pub attributes: BTreeMap<String, String>,
}

pub trait Engine: Send + Sync + 'static {
    fn version(&self) -> impl Future<Output = Result<RuntimeInfo>> + Send;

    fn pod_create(&self, spec: &PodCreate) -> impl Future<Output = Result<String>> + Send;
    fn pod_start(&self, id: &str) -> impl Future<Output = Result<()>> + Send;
    fn pod_stop(&self, id: &str, timeout_secs: u32) -> impl Future<Output = Result<()>> + Send;
    fn pod_remove(&self, id: &str) -> impl Future<Output = Result<()>> + Send;
    fn pod_inspect(&self, id: &str) -> impl Future<Output = Result<PodRecord>> + Send;
    fn pod_list(&self) -> impl Future<Output = Result<Vec<PodRecord>>> + Send;
    /// Replace the limits of the cgroup of the pod.
    fn pod_update(
        &self,
        id: &str,
        resources: &Resources,
    ) -> impl Future<Output = Result<()>> + Send;

    /// Create a container from the engine's creation record (the command
    /// line's).
    fn container_create(
        &self,
        req: &CreateContainerRequest,
    ) -> impl Future<Output = Result<String>> + Send;
    fn container_start(&self, id: &str) -> impl Future<Output = Result<()>> + Send;
    fn container_stop(
        &self,
        id: &str,
        timeout_secs: u32,
    ) -> impl Future<Output = Result<()>> + Send;
    fn container_remove(&self, id: &str) -> impl Future<Output = Result<()>> + Send;
    fn container_inspect(&self, id: &str) -> impl Future<Output = Result<ContainerRecord>> + Send;
    /// The OCI configuration of a created container (`config.json`).
    fn container_runtime_spec(
        &self,
        id: &str,
    ) -> impl Future<Output = Result<serde_json::Value>> + Send;
    fn container_list(&self) -> impl Future<Output = Result<Vec<ContainerRecord>>> + Send;
    /// Change the limits of a container as `spec` says.
    fn container_amend(
        &self,
        id: &str,
        spec: UpdateSpec,
    ) -> impl Future<Output = Result<()>> + Send;
    /// The stats of the containers `ids`, an error for one of them the
    /// answer; none named: of every container that runs, best effort (one
    /// that ended meanwhile or cannot be sampled is left out).
    fn container_stats(
        &self,
        ids: &[String],
    ) -> impl Future<Output = Result<Vec<StatsRecord>>> + Send;
    fn container_checkpoint(
        &self,
        id: &str,
        location: &str,
    ) -> impl Future<Output = Result<()>> + Send;
    /// Checkpoint `containers` (all running) at one instant into the empty
    /// directory `output`; `manifest` is written last, as the file that says
    /// what is in it.
    fn pod_checkpoint(
        &self,
        containers: &[String],
        output: &str,
        manifest: &[u8],
    ) -> impl Future<Output = Result<()>> + Send;
    /// The manifest of the pod checkpoint in the directory `path`.
    fn pod_checkpoint_manifest(&self, path: &str) -> impl Future<Output = Result<Vec<u8>>> + Send;
    /// Stage the archive `archive` of the directory `path` in the container
    /// `id`, which was never started: its start restores it.
    fn container_restore_staged(
        &self,
        id: &str,
        path: &str,
        archive: &str,
    ) -> impl Future<Output = Result<()>> + Send;
    fn container_reopen_log(&self, id: &str) -> impl Future<Output = Result<()>> + Send;

    fn exec_sync(
        &self,
        id: &str,
        cmd: &[String],
        timeout_secs: u64,
    ) -> impl Future<Output = Result<ExecResult>> + Send;
    fn exec_open(
        &self,
        id: &str,
        spec: &ExecSpec,
    ) -> impl Future<Output = Result<ExecStream>> + Send;
    fn exec_exit_code(&self, exec_id: &str) -> impl Future<Output = Result<i32>> + Send;
    fn exec_resize(
        &self,
        exec_id: &str,
        width: u16,
        height: u16,
    ) -> impl Future<Output = Result<()>> + Send;
    /// Kill the process of the exec session: its client went away.
    fn exec_kill(&self, exec_id: &str) -> impl Future<Output = Result<()>> + Send;
    /// With `stdin_once` the input of the container is closed when this
    /// attach ends; without, it stays open for the next one.
    fn attach_open(
        &self,
        id: &str,
        stdin: bool,
        stdin_once: bool,
        tty: bool,
    ) -> impl Future<Output = Result<ExecStream>> + Send;

    fn image_list(&self) -> impl Future<Output = Result<Vec<ImageRecord>>> + Send;
    fn image_inspect(&self, id: &str) -> impl Future<Output = Result<ImageRecord>> + Send;
    fn image_pull(
        &self,
        reference: &str,
        access: Option<&velarx_registry::auth::RegistryAccess>,
    ) -> impl Future<Output = Result<String>> + Send;
    fn image_remove(&self, id: &str) -> impl Future<Output = Result<()>> + Send;
    fn store_usage(&self) -> impl Future<Output = Result<StorageUsage>> + Send;

    /// Whether the plugins of the CNI network NETWORK (`cni:NAME`) say it is
    /// ready (the STATUS verb); a network with no configuration is not.
    fn network_status(&self, network: &str) -> impl Future<Output = Result<NetworkStatus>> + Send;

    /// Container events from now on, until the receiver is dropped.
    fn events(
        &self,
    ) -> impl Future<Output = Result<tokio::sync::mpsc::Receiver<EngineEvent>>> + Send;

    /// The metrics `pod_metrics` gives.
    fn metric_descriptors(&self) -> impl Future<Output = Result<Vec<MetricDescriptor>>> + Send;
    /// The metrics of the pods that run and their containers.
    fn pod_metrics(&self) -> impl Future<Output = Result<Vec<PodMetrics>>> + Send;

    /// A connection to a port of the network namespace of a pod.
    fn pod_dial(&self, id: &str, port: u16) -> impl Future<Output = Result<Box<dyn Io>>> + Send;
}
