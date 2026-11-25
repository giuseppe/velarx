// SPDX-License-Identifier: Apache-2.0
//! The engine as a client of `org.velarx.Engine` on its socket: a typed call
//! for each operation the CRI needs, a connection of its own for each (a
//! connection that passes descriptors carries one call at a time).  At most
//! [`MAX_CALLS`] calls are in progress at once (the engine refuses the
//! connections of a process above its own limit): the others wait for one
//! to end.
//!
//! The streams of exec and attach are the descriptors of the session
//! replies of `ContainerAttach`/`ExecStart`, the events the records of
//! `EventList` (`more`), the
//! connection to a port of a pod a socket the engine connected inside the
//! namespace of the pod.

use super::*;
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};
use velarx_limit_core::{limit_of, Limit};
use velarx_proto::connect::{self, ConnectError};
use velarx_proto::engine::{self as wire, AttachOptions, EngineProxy, MAX_FILTERS};
use velarx_proto::modes::{CgroupsMode, UsernsChoice};
use velarx_proto::pod::PodAction;
use velarx_proto::pod::{IdMapping, PodPortMapping, PodResources, PodSpec};
use velarx_proto::workload as records;

#[derive(Clone)]
pub struct Varlink {
    /// How the engine is reached (`org.velarx.Engine`): its socket, by its
    /// path or through the connector of a confined process
    dial: std::sync::Arc<connect::Dial>,
    /// Told when the engine can no longer be reached on its socket: the
    /// process confines itself to the directory the socket was in at its
    /// start, so the one that serves ends and is started again by whoever
    /// runs it.
    gone: std::sync::Arc<tokio::sync::Notify>,
    checkpoints: Option<std::sync::Arc<super::checkpoint::Checkpoints>>,
    calls: std::sync::Arc<tokio::sync::Semaphore>,
    /// The connections checked and not in use (see `connect::Idle`)
    idle: connect::Idle,
}

/// The most calls in progress at once: below the engine's limit of
/// connections of one client process (`[services] max_per_client`, 192 by
/// default), so that a burst of the kubelet waits for a connection rather than
/// being refused.
pub const MAX_CALLS: usize = 30;

/// A connection to the engine, counted in [`MAX_CALLS`] while it lives.
type EngineCall = connect::Held;

/// Where this frontend's socket goes by default: next to the sockets of the
/// engine, `/run/velarx/cri.sock` or `$XDG_RUNTIME_DIR/velarx/cri.sock`.
pub fn default_cri_socket() -> std::result::Result<PathBuf, velarx_base::dirs::DirsError> {
    Ok(velarx_base::dirs::DefaultDirs::current()?
        .run
        .join("cri.sock"))
}

/// The socket of the engine as the command line has it: the rootful
/// `/run/velarx/engine/engine.sock`, or `$XDG_RUNTIME_DIR/velarx/engine/engine.sock`.
pub fn default_engine_socket() -> std::result::Result<PathBuf, velarx_base::dirs::DirsError> {
    Ok(velarx_base::dirs::DefaultDirs::current()?
        .run
        .join("engine/engine.sock"))
}

/// A connect error that means the engine is not there (any more) at the
/// socket the process may reach: nothing listens, the socket is gone, or the
/// confinement no longer lets the process through to it (its directory was
/// removed and made again).
fn engine_unreachable(e: &std::io::Error) -> bool {
    use std::io::ErrorKind::{ConnectionRefused, NotFound, PermissionDenied};
    matches!(e.kind(), NotFound | ConnectionRefused | PermissionDenied)
}

fn other(e: impl std::fmt::Display) -> EngineError {
    EngineError::Other(e.to_string())
}

/// A call that did not get an answer: the connection broke or the engine
/// said something else.
fn protocol(e: zlink::Error) -> EngineError {
    EngineError::Other(format!("the engine: {e}"))
}

/// The error of the engine as the CRI has it: the names of the conditions
/// are the codes of gRPC.
pub(super) fn refused(e: wire::EngineError) -> EngineError {
    use wire::EngineError as E;
    match e {
        E::NoSuchContainer { message, .. }
        | E::NoSuchImage { message, .. }
        | E::NoSuchPod { message, .. }
        | E::NoSuchNetwork { message, .. }
        | E::NoSuchVolume { message, .. }
        | E::NoSuchSecret { message, .. }
        | E::NoSuchExecSession { message, .. }
        | E::NoSuchObject { message, .. } => EngineError::NotFound(message),
        E::Conflict { message, .. } => EngineError::Conflict(message),
        E::InvalidState { message, .. }
        | E::NoCheckpoint { message, .. }
        | E::NoPasta { message, .. }
        | E::ImageNotLazy { message, .. } => EngineError::Precondition(message),
        E::InvalidArgument { message, .. }
        | E::InvalidName { message, .. }
        | E::InvalidArchive { message, .. }
        | E::InvalidReference { message, .. } => EngineError::Invalid(message),
        E::TooLarge { message, .. } | E::NoSpace { message, .. } => EngineError::Exhausted(message),
        E::PermissionDenied { message, .. } => EngineError::Denied(message),
        E::Unauthorized { message, .. } => EngineError::Unauthenticated(message),
        E::NotSupported { message, .. } => EngineError::Unsupported(message),
        E::Unreachable { message, .. }
        | E::Unavailable { message, .. }
        | E::SourceUnavailable { message, .. } => EngineError::Unavailable(message),
        E::InvalidContent { message, .. } | E::Contradicted { message, .. } => {
            EngineError::DataLoss(message)
        }
        E::NotStarted { message, .. }
        | E::NeedsForce { message, .. }
        | E::CommandNotFound { message, .. }
        | E::Failed { message, .. } => EngineError::Other(message),
    }
}

/// A call of the engine on a connection of its own: its answer, or the
/// error as the CRI has it.  The size of the arguments is not checked
/// (`call!` does).
macro_rules! raw_call {
    ($self:ident . $method:ident ( $($arg:expr),* $(,)? )) => {{
        let mut conn = $self.conn().await?;
        let reply = conn.$method($($arg),*).await.map_err(protocol)?;
        conn.answered();
        reply.map_err(refused)
    }};
}

/// [`raw_call`] with the size of the arguments checked: a call is a message
/// zlink builds in memory, and a large one costs much more than its bytes
/// (`MAX_ARG_BYTES`).
macro_rules! call {
    ($self:ident . $method:ident ( $($arg:expr),* $(,)? )) => {{
        check_args(stringify!($method), &($(&$arg,)*))?;
        raw_call!($self.$method($($arg),*))
    }};
}

/// A call whose reply carries descriptors: the reply and its descriptors.
macro_rules! raw_fds_call {
    ($self:ident . $method:ident ( $($arg:expr),* $(,)? )) => {{
        let mut conn = $self.conn().await?;
        let (reply, fds) = conn.$method($($arg),*).await.map_err(protocol)?;
        (reply.map_err(refused)?, fds)
    }};
}

/// A list (a `more` call of the proxy): its records, `take` gets one out of
/// a reply (none in the one reply of an empty list); the size of the
/// arguments checked.
macro_rules! list_call {
    ($self:ident . $method:ident ( $($arg:expr),* $(,)? ), $take:expr) => {{
        check_args(stringify!($method), &($(&$arg,)*))?;
        let mut conn = $self.conn().await?;
        let replies = conn.$method($($arg),*).await.map_err(protocol)?;
        let listed = connect::records(replies, $take).await.map_err(protocol)?;
        conn.answered();
        listed.map_err(refused)
    }};
}

/// [`raw_fds_call`] with the size of the arguments checked.
macro_rules! fds_call {
    ($self:ident . $method:ident ( $($arg:expr),* $(,)? )) => {{
        check_args(stringify!($method), &($(&$arg,)*))?;
        raw_fds_call!($self.$method($($arg),*))
    }};
}

/// The arguments of a call are at most `MAX_ARG_BYTES` of JSON.
pub(super) fn check_args<T: serde::Serialize + ?Sized>(method: &str, args: &T) -> Result<()> {
    match connect::args_too_large(method, args) {
        Some(message) => Err(EngineError::Invalid(message)),
        None => Ok(()),
    }
}

/// The most bytes of a document of the engine the frontend reads.
const MAX_DOCUMENT: u64 = 16 << 20;

/// The document of a reply: inline, or the content of the pipe it carries,
/// read to its end.
async fn document(doc: wire::Document, fds: Vec<OwnedFd>) -> Result<serde_json::Value> {
    use tokio::io::AsyncReadExt;
    let Some(i) = doc.fd else {
        return Ok(doc.inline.unwrap_or_default());
    };
    let fd = connect::take_fd(fds, i)
        .ok_or_else(|| EngineError::Other("the reply has no pipe for its document".into()))?;
    let pipe = tokio::net::unix::pipe::Receiver::from_owned_fd(fd).map_err(other)?;
    let mut bytes = Vec::new();
    pipe.take(MAX_DOCUMENT + 1)
        .read_to_end(&mut bytes)
        .await
        .map_err(other)?;
    if bytes.len() as u64 > MAX_DOCUMENT {
        return Err(EngineError::Exhausted(format!(
            "a document is larger than {MAX_DOCUMENT}"
        )));
    }
    serde_json::from_slice(&bytes).map_err(other)
}

fn pipe_with(bytes: Vec<u8>) -> Result<(u64, OwnedFd)> {
    let length = bytes.len() as u64;
    let read = connect::filled_pipe(bytes).map_err(other)?;
    Ok((length, read))
}

fn json_pipe(v: &impl serde::Serialize) -> Result<(u64, OwnedFd)> {
    pipe_with(serde_json::to_vec(v).map_err(other)?)
}

impl Varlink {
    pub fn new(socket: impl Into<PathBuf>) -> Self {
        Self::reached(connect::Dial::Path(socket.into()))
    }

    /// The engine reached the way `dial` says.
    pub fn reached(dial: connect::Dial) -> Self {
        Self {
            dial: std::sync::Arc::new(dial),
            gone: Default::default(),
            checkpoints: None,
            calls: std::sync::Arc::new(tokio::sync::Semaphore::new(MAX_CALLS)),
            idle: connect::Idle::default(),
        }
    }

    /// The archives of the checkpoints are written in this directory, by the
    /// engine.
    pub fn with_checkpoints(mut self, checkpoints: super::checkpoint::Checkpoints) -> Self {
        self.checkpoints = Some(std::sync::Arc::new(checkpoints));
        self
    }

    pub fn checkpoints(&self) -> Option<&super::checkpoint::Checkpoints> {
        self.checkpoints.as_deref()
    }

    fn checkpoint_dir(&self) -> Result<&super::checkpoint::Checkpoints> {
        self.checkpoints().ok_or_else(|| {
            EngineError::Unsupported("the checkpoint directory is not available".into())
        })
    }

    /// Notified when the socket of the engine no longer takes connections
    /// (the engine ended, its directory was made again).
    pub fn engine_gone(&self) -> std::sync::Arc<tokio::sync::Notify> {
        self.gone.clone()
    }

    pub fn socket(&self) -> &Path {
        self.dial.socket()
    }

    /// A connection to the engine, checked: its user and its version, once
    /// fewer than [`MAX_CALLS`] are open.  The engine starts when the
    /// connection reaches its socket (the service manager does it).
    async fn conn(&self) -> Result<EngineCall> {
        let permit = self.calls.clone().acquire_owned().await.map_err(other)?;
        self.idle
            .hold(&self.dial, permit)
            .await
            .map_err(|e| match e {
                ConnectError::Unreachable { source, .. } if engine_unreachable(&source) => {
                    tracing::error!("the engine is gone: {}: {source}", self.socket().display());
                    self.gone.notify_one();
                    EngineError::Unavailable(format!("{}: {source}", self.socket().display()))
                }
                e => EngineError::Unavailable(e.to_string()),
            })
    }

    /// Run a command in a container and wait for it: what it wrote, and
    /// how it ended.
    async fn exec_run(&self, id: &str, cmd: &[String]) -> Result<(String, tokio::net::UnixStream)> {
        let spec = records::ExecSpec {
            command: cmd.to_vec(),
            stdout: true,
            stderr: true,
            ..Default::default()
        };
        let exec = call!(self.exec_create(id, spec))?.id;
        let session = self.session_of_exec(&exec, false).await?;
        let socket = velarx_proto::stream::connect(session, false).map_err(other)?;
        Ok((exec, socket))
    }

    /// The session of the exec session `exec`.
    async fn session_of_exec(
        &self,
        exec: &str,
        input: bool,
    ) -> Result<velarx_proto::stream::Session> {
        let (exec, conn) = (exec.to_string(), self.conn().await?);
        let opened = velarx_proto::session_call!(
            conn,
            exec_start(&exec, input, false, 0, 0, Vec::new(), Vec::new())
        )
        .await;
        self.session(opened)
    }

    /// The session a call opened.
    fn session(
        &self,
        opened: std::result::Result<
            (velarx_proto::stream::Item, velarx_proto::stream::Replies),
            velarx_proto::stream::OpenError,
        >,
    ) -> Result<velarx_proto::stream::Session> {
        use velarx_proto::stream::OpenError;
        let (first, replies) = opened.map_err(|e| match e {
            OpenError::Engine(e) => refused(e),
            OpenError::Protocol(e) => protocol(e),
        })?;
        let engine = self.clone();
        velarx_proto::stream::Session::of_first(first, replies, move |name, what| {
            let engine = engine.clone();
            async move {
                engine
                    .session_control(&name, what)
                    .await
                    .map_err(|e| std::io::Error::other(e.to_string()))
            }
        })
        .map_err(other)?
        .ok_or_else(|| EngineError::Other("the engine opened no streams".into()))
    }

    /// What the client of a session tells the engine, on a connection of
    /// its own.
    async fn session_control(
        &self,
        session: &str,
        what: velarx_proto::stream::Control,
    ) -> Result<()> {
        use velarx_proto::stream::Control;
        match what {
            Control::CloseStdin => call!(self.session_close_stdin(session)),
            Control::Detach => call!(self.session_detach(session)),
        }
        .map(|_| ())
    }

    fn stream(session: velarx_proto::stream::Session, id: String) -> Result<ExecStream> {
        let framed = !session.tty();
        let io = velarx_proto::stream::connect(session, true).map_err(other)?;
        Ok(ExecStream {
            id,
            framed,
            io: Box::new(io),
        })
    }
}

/// A byte limit of the CRI's resources: 0 and -1 are no limit, another
/// number below 1 is refused.
pub fn byte_limit(what: &str, v: i64) -> Result<Option<i64>> {
    match limit_of(v) {
        Limit::Unset | Limit::Unlimited => Ok(None),
        Limit::Bytes(b) => Ok(Some(b as i64)),
        Limit::Invalid => Err(EngineError::Invalid(format!(
            "the {what} limit {v} is not a number of bytes, 0 or -1"
        ))),
    }
}

/// The resources of a pod from the CRI's: what is not set is no limit.
pub fn pod_resources(r: &Resources) -> Result<PodResources> {
    Ok(PodResources {
        memory: byte_limit("memory", r.memory_limit)?,
        memory_swap: byte_limit("memory and swap", r.memory_swap)?,
        cpu_shares: u64::try_from(r.cpu_shares).ok().filter(|s| *s > 0),
        cpu_quota: (r.cpu_quota != 0).then_some(r.cpu_quota),
        cpu_period: u64::try_from(r.cpu_period).ok().filter(|p| *p > 0),
        cpuset_cpus: Some(r.cpuset_cpus.clone()).filter(|c| !c.is_empty()),
        cpuset_mems: Some(r.cpuset_mems.clone()).filter(|m| !m.is_empty()),
        ..Default::default()
    })
}

/// The spec of a pod the engine creates.
pub fn pod_spec(s: &PodCreate) -> Result<PodSpec> {
    let id_map = |m: &[IdRange]| -> Vec<IdMapping> {
        m.iter()
            .map(|r| IdMapping {
                container_id: r.container_id,
                host_id: r.host_id,
                size: r.size,
            })
            .collect()
    };
    let mut spec = PodSpec {
        name: s.name.clone(),
        hostname: Some(s.hostname.clone()).filter(|h| !h.is_empty()),
        labels: s.labels.clone().into_iter().collect(),
        runtime: Some(s.runtime.clone()).filter(|r| !r.is_empty()),
        share_net: true,
        share_uts: true,
        share_ipc: !s.host_ipc,
        share_pid: s.share_pid,
        host_ipc: s.host_ipc,
        cgroup_parent: Some(s.cgroup_parent.clone()).filter(|c| !c.is_empty()),
        // (the kubelet manages the cgroups of a pod: `[containers] cgroups`
        // of the configuration is not the CRI's.  With the kubelet's systemd
        // driver, a slice, every container is a scope of its own below the
        // parent, as containerd's and CRI-O's are, never a cgroup of the
        // engine service's tree.  The path of its cgroupfs driver is the
        // parent of the cgroups made there, and a sandbox with no parent (a
        // hand-written one) is the engine's default)
        cgroups: if s.cgroup_parent.ends_with(".slice") {
            CgroupsMode::Scope
        } else {
            CgroupsMode::Enabled
        },
        sysctls: s.sysctls.clone().into_iter().collect(),
        cni_annotations: s.cni_annotations.clone(),
        cni_ip_ranges: s.cni_ip_ranges.clone(),
        infra_image: Some(s.infra_image.clone()).filter(|i| !i.is_empty()),
        security_opts: s.infra.security_opts.clone(),
        infra_oom_score_adj: s.infra.oom_score_adj,
        infra_read_only: s.infra.read_only_rootfs,
        infra_privileged: s.infra.privileged,
        ..PodSpec::default()
    };
    spec.dns.servers = s.dns_servers.clone();
    spec.dns.searches = s.dns_searches.clone();
    spec.dns.options = s.dns_options.clone();
    spec.ports = s
        .ports
        .iter()
        .map(|p| PodPortMapping {
            container_port: p.container_port,
            host_port: (p.host_port != 0).then_some(p.host_port),
            host_ip: Some(p.host_ip.clone()).filter(|h| !h.is_empty()),
            protocol: if p.protocol.is_empty() {
                "tcp".into()
            } else {
                p.protocol.clone()
            },
        })
        .collect();
    if s.net == NsMode::Host {
        spec.networks = vec!["host".into()];
    } else if !s.network.is_empty() {
        spec.networks = vec![s.network.clone()];
    }
    if s.host_pid {
        spec.host_pid = true;
        spec.share_pid = false;
    }
    if s.userns_auto {
        spec.userns = Some(UsernsChoice::Auto(None));
    }
    if !s.uid_map.is_empty() || !s.gid_map.is_empty() {
        spec.uid_mappings = id_map(&s.uid_map);
        spec.gid_mappings = id_map(&s.gid_map);
        // mappings of its own: a private user namespace
        spec.userns.get_or_insert(UsernsChoice::Private);
        if spec.gid_mappings.is_empty() {
            spec.gid_mappings = spec.uid_mappings.clone();
        } else if spec.uid_mappings.is_empty() {
            spec.uid_mappings = spec.gid_mappings.clone();
        }
    }
    spec.security_context.run_as_user = s.infra.run_as_user;
    spec.security_context.run_as_group = s.infra.run_as_group;
    spec.security_context.supplemental_groups = s.infra.supplemental_groups.clone();
    let limits = pod_resources(&s.resources)?;
    spec.resources = (!limits.is_empty()).then_some(limits);
    Ok(spec)
}

/// The most of the standard output, and of the standard error, of an
/// `ExecSync` that is kept, as containerd and CRI-O keep: the rest is read
/// and dropped, so that a command that writes without end costs no memory.
const EXEC_SYNC_MAX: usize = 16 << 20;

/// The standard output and the standard error in the multiplexed stream `r`
/// (`stdcopy`) to its end, each cut at `max` bytes.
async fn exec_output(
    mut r: impl tokio::io::AsyncRead + Unpin,
    max: usize,
) -> std::io::Result<(Vec<u8>, Vec<u8>)> {
    use tokio::io::AsyncReadExt;
    let (mut raw, mut out, mut err) = (Vec::new(), Vec::new(), Vec::new());
    let mut chunk = vec![0u8; 64 * 1024];
    loop {
        let n = r.read(&mut chunk).await?;
        if n == 0 {
            return Ok((out, err));
        }
        raw.extend_from_slice(&chunk[..n]);
        demux(&mut raw, &mut out, &mut err);
        out.truncate(max);
        err.truncate(max);
    }
}

/// The frames of the multiplexed stream (`stdcopy`) in `buf`, the rest kept.
pub fn demux(buf: &mut Vec<u8>, out: &mut Vec<u8>, err: &mut Vec<u8>) {
    let mut at = 0;
    while buf.len() - at >= 8 {
        let n = u32::from_be_bytes([buf[at + 4], buf[at + 5], buf[at + 6], buf[at + 7]]) as usize;
        if buf.len() - at - 8 < n {
            break;
        }
        let data = &buf[at + 8..at + 8 + n];
        match buf[at] {
            2 => err.extend_from_slice(data),
            _ => out.extend_from_slice(data),
        }
        at += 8 + n;
    }
    buf.drain(..at);
}

/// An event of the engine's stream, a line of JSON.
fn event_of(ev: records::Event) -> EngineEvent {
    EngineEvent {
        object: ev.kind.word().to_string(),
        container_id: if ev.id.is_empty() { ev.name } else { ev.id },
        pod_id: ev.attributes.get("podId").cloned().unwrap_or_default(),
        action: ev.action,
        time_ns: ev.time_ns,
        attributes: ev.attributes,
    }
}

impl Engine for Varlink {
    async fn version(&self) -> Result<RuntimeInfo> {
        call!(self.runtime_inspect())
    }

    async fn pod_create(&self, s: &PodCreate) -> Result<String> {
        let (_, spec) = json_pipe(&pod_spec(s)?)?;
        // (the document is the one descriptor, read to its end)
        Ok(raw_call!(self.pod_create(0, vec![spec]))?.id)
    }

    async fn pod_update(&self, id: &str, r: &Resources) -> Result<()> {
        call!(self.pod_update(id, pod_resources(r)?)).map(|_| ())
    }

    async fn pod_start(&self, id: &str) -> Result<()> {
        self.pod_run(id, PodAction::Start, None).await
    }

    async fn pod_stop(&self, id: &str, timeout: u32) -> Result<()> {
        self.pod_run(id, PodAction::Stop, Some(u64::from(timeout)))
            .await
    }

    async fn pod_remove(&self, id: &str) -> Result<()> {
        call!(self.pod_remove(id, true, Some(0))).map(|_| ())
    }

    async fn pod_inspect(&self, id: &str) -> Result<PodRecord> {
        Ok(call!(self.pod_inspect(id))?.pod)
    }

    async fn pod_list(&self) -> Result<Vec<PodRecord>> {
        list_call!(
            self.pod_list(Vec::<wire::Filter>::new()),
            |r: records::PodListed| r.pod
        )
    }

    async fn container_create(&self, c: &CreateContainerRequest) -> Result<String> {
        let (_, spec) = json_pipe(c)?;
        Ok(raw_call!(self.container_create(0, vec![spec]))?.id)
    }

    async fn container_start(&self, id: &str) -> Result<()> {
        call!(self.container_start(id, Vec::<String>::new(), Some(true), None::<bool>)).map(|_| ())
    }

    async fn container_stop(&self, id: &str, timeout: u32) -> Result<()> {
        call!(self.container_stop(id, Some(u64::from(timeout)), false, None::<bool>)).map(|_| ())
    }

    async fn container_remove(&self, id: &str) -> Result<()> {
        call!(self.container_remove(id, true, true, false, false, Some(0))).map(|_| ())
    }

    async fn container_inspect(&self, id: &str) -> Result<ContainerRecord> {
        Ok(call!(self.container_inspect(id, false))?.container)
    }

    async fn container_runtime_spec(&self, id: &str) -> Result<serde_json::Value> {
        let (doc, fds) = fds_call!(self.container_runtime_spec(id));
        document(doc, fds).await
    }

    async fn container_list(&self) -> Result<Vec<ContainerRecord>> {
        list_call!(
            self.container_list(Vec::<wire::Filter>::new(), true, false, false, -1),
            |r: records::ContainerListed| r.container
        )
    }

    async fn container_amend(&self, id: &str, spec: wire::UpdateSpec) -> Result<()> {
        check_args("container_amend", &(id, &spec))?;
        raw_call!(self.container_amend(id, spec)).map(|_| ())
    }

    async fn container_stats(&self, ids: &[String]) -> Result<Vec<StatsRecord>> {
        if ids.is_empty() {
            return list_call!(
                self.container_stats(Vec::<String>::new(), false, true, false, None::<u64>),
                |r: records::StatsListed| r.stats
            );
        }
        let mut all = Vec::new();
        for chunk in ids.chunks(MAX_FILTERS) {
            let some: Vec<_> = list_call!(
                self.container_stats(chunk.to_vec(), false, true, false, None::<u64>),
                |r: records::StatsListed| r.stats
            )?;
            all.extend(some);
        }
        Ok(all)
    }

    async fn container_checkpoint(&self, id: &str, location: &str) -> Result<()> {
        self.checkpoint_dir()?.checkpoint(id, location).await
    }

    async fn pod_checkpoint(
        &self,
        containers: &[String],
        output: &str,
        manifest: &[u8],
    ) -> Result<()> {
        self.checkpoint_dir()?
            .checkpoint_pod(containers, output, manifest)
            .await
    }

    async fn pod_checkpoint_manifest(&self, path: &str) -> Result<Vec<u8>> {
        self.checkpoint_dir()?.read_pod_manifest(path)
    }

    async fn container_restore_staged(&self, id: &str, path: &str, archive: &str) -> Result<()> {
        self.checkpoint_dir()?
            .restore_staged(id, path, archive)
            .await
    }

    async fn container_reopen_log(&self, id: &str) -> Result<()> {
        call!(self.container_log_reopen(id)).map(|_| ())
    }

    async fn exec_sync(&self, id: &str, cmd: &[String], timeout: u64) -> Result<ExecResult> {
        let (exec, mut socket) = self.exec_run(id, cmd).await?;
        // (the engine ends the stream when the command ends; this end stays
        // open until then; the command of a timeout is killed)
        let read = async { exec_output(&mut socket, EXEC_SYNC_MAX).await.map_err(other) };
        let (stdout, stderr) = if timeout > 0 {
            match tokio::time::timeout(std::time::Duration::from_secs(timeout), read).await {
                Ok(r) => r?,
                Err(_) => {
                    if let Err(e) = Engine::exec_kill(self, &exec).await {
                        tracing::debug!("cannot kill the exec session {exec}: {e}");
                    }
                    return Err(EngineError::DeadlineExceeded(format!(
                        "exec timed out after {timeout} seconds"
                    )));
                }
            }
        } else {
            read.await?
        };
        let exit_code = self.exec_exit_code(&exec).await?;
        Ok(ExecResult {
            stdout,
            stderr,
            exit_code,
        })
    }

    async fn exec_open(&self, id: &str, spec: &ExecSpec) -> Result<ExecStream> {
        let typed = records::ExecSpec {
            command: spec.cmd.clone(),
            tty: spec.tty,
            stdin: spec.stdin,
            stdout: spec.stdout,
            stderr: spec.stderr,
            ..Default::default()
        };
        let exec = call!(self.exec_create(id, typed))?.id;
        let session = self.session_of_exec(&exec, true).await?;
        Self::stream(session, exec)
    }

    async fn exec_exit_code(&self, exec_id: &str) -> Result<i32> {
        let exec = call!(self.exec_inspect(exec_id))?.exec;
        // (the engine records it before it ends the stream: none is an
        // error, never a success)
        let code = exec.exit_code.ok_or_else(|| {
            EngineError::Other(format!("the exec session {exec_id} has no exit status"))
        })?;
        i32::try_from(code).map_err(|_| {
            EngineError::Other(format!("the exec session {exec_id} exited with {code}"))
        })
    }

    async fn exec_kill(&self, exec_id: &str) -> Result<()> {
        call!(self.exec_kill(exec_id, "KILL")).map(|_| ())
    }

    async fn exec_resize(&self, exec_id: &str, width: u16, height: u16) -> Result<()> {
        call!(self.exec_resize(exec_id, i64::from(height), i64::from(width), true)).map(|_| ())
    }

    async fn attach_open(
        &self,
        id: &str,
        stdin: bool,
        stdin_once: bool,
        _tty: bool,
    ) -> Result<ExecStream> {
        let opts = AttachOptions {
            stdout: true,
            stderr: true,
            logs: false,
            stream: true,
            stdin,
            detach_keys: None,
            stdin_once,
            stdin_keep_open: !stdin_once,
            ..Default::default()
        };
        let (name, conn) = (id.to_string(), self.conn().await?);
        let opened = velarx_proto::session_call!(conn, container_attach(&name, opts)).await;
        Self::stream(self.session(opened)?, String::new())
    }

    async fn image_list(&self) -> Result<Vec<ImageRecord>> {
        list_call!(
            self.image_list(Vec::<wire::Filter>::new(), false, false),
            |r: records::ImageListed| r.image
        )
    }

    async fn image_inspect(&self, id: &str) -> Result<ImageRecord> {
        Ok(call!(self.image_inspect(id))?.image)
    }

    async fn image_pull(
        &self,
        reference: &str,
        access: Option<&velarx_registry::auth::RegistryAccess>,
    ) -> Result<String> {
        let spec = wire::PullSpec {
            source: reference.to_string(),
            tls_verify: true,
            ..Default::default()
        };
        check_args("image_pull", &(&spec,))?;
        // (the credentials go in a sealed memory file, never in a message)
        let (access, fds) = match access.filter(|a| !a.is_empty()) {
            Some(access) => {
                let bytes = zeroize::Zeroizing::new(
                    serde_json::to_vec(access).map_err(|e| EngineError::Other(e.to_string()))?,
                );
                let file = velarx_base::sealed::sealed_memory(&bytes)
                    .map_err(|e| EngineError::Other(format!("the credentials: {e}")))?;
                (Some(0), vec![file])
            }
            None => (None, Vec::new()),
        };
        raw_call!(self.image_pull(spec, access, fds))?
            .id
            .ok_or_else(|| EngineError::Other("the engine pulled no image".into()))
    }

    async fn image_remove(&self, id: &str) -> Result<()> {
        call!(self.image_remove(id, true, false, false, false, false)).map(|_| ())
    }

    async fn store_usage(&self) -> Result<StorageUsage> {
        call!(self.storage_inspect())
    }

    async fn network_status(&self, network: &str) -> Result<NetworkStatus> {
        check_args("network_check", &(network,))?;
        let mut conn = self.conn().await?;
        match conn.network_check(network).await.map_err(protocol)? {
            Ok(status) => Ok(status),
            Err(wire::EngineError::NoSuchNetwork { message, .. }) => Ok(NetworkStatus {
                ready: false,
                message,
            }),
            Err(e) => Err(refused(e)),
        }
    }

    async fn events(&self) -> Result<tokio::sync::mpsc::Receiver<EngineEvent>> {
        let filters = vec![wire::Filter {
            key: "type".into(),
            values: vec!["container".into(), "pod".into()],
        }];
        let mut conn = self.conn().await?;
        let (tx, mut rx) = tokio::sync::mpsc::channel::<records::EventListed>(64);
        tokio::spawn(async move {
            // (the stream counts as a call while it lasts: `conn` holds it)
            let replies = match conn.event_list(filters, None, None, true).await {
                Ok(replies) => replies,
                Err(e) => return tracing::warn!("the events of the engine ended: {e}"),
            };
            match connect::replies_to(replies, tx).await {
                Ok(Ok(())) => {}
                Ok(Err(e)) => tracing::warn!("the events of the engine ended: {e}"),
                Err(e) => tracing::warn!("the events of the engine ended: {e}"),
            }
        });
        let (out, events) = tokio::sync::mpsc::channel(64);
        tokio::spawn(async move {
            // (a reader that went away ends the stream at once: the
            // connection and the call it counts as are given back)
            loop {
                let listed = tokio::select! {
                    listed = rx.recv() => listed,
                    () = out.closed() => return,
                };
                let Some(listed) = listed else { return };
                let Some(ev) = listed.event else { continue };
                if out.send(event_of(ev)).await.is_err() {
                    return;
                }
            }
        });
        Ok(events)
    }

    async fn pod_dial(&self, id: &str, port: u16) -> Result<Box<dyn Io>> {
        // the engine connects in the namespace of the pod and passes the
        // socket: the frontend relays between it and the stream of the client
        let (_, mut fds) = fds_call!(self.port_connect(true, id, port));
        if fds.is_empty() {
            return Err(EngineError::Other(
                "the engine connected a port with no socket".into(),
            ));
        }
        let tcp = std::net::TcpStream::from(fds.swap_remove(0));
        tcp.set_nonblocking(true).map_err(other)?;
        Ok(Box::new(
            tokio::net::TcpStream::from_std(tcp).map_err(other)?,
        ))
    }

    async fn metric_descriptors(&self) -> Result<Vec<MetricDescriptor>> {
        list_call!(
            self.metric_descriptor_list(),
            |r: records::MetricDescriptorListed| r.descriptor
        )
    }

    async fn pod_metrics(&self) -> Result<Vec<PodMetrics>> {
        list_call!(
            self.pod_metrics_list(None::<&str>),
            |r: records::PodMetricsListed| r.pod
        )
    }
}

impl Varlink {
    /// Start, stop... the pod; the errors of its containers are the error.
    async fn pod_run(&self, id: &str, op: PodAction, timeout: Option<u64>) -> Result<()> {
        let ran = call!(self.pod_run(
            id,
            op,
            timeout,
            None::<&str>,
            Vec::<String>::new(),
            Some(true)
        ))?;
        if ran.errors.is_empty() {
            Ok(())
        } else {
            Err(EngineError::Other(ran.errors.join("; ")))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn demux_frames() {
        let mut buf = vec![
            1, 0, 0, 0, 0, 0, 0, 3, b'a', b'b', b'c', 2, 0, 0, 0, 0, 0, 0, 2, b'x',
        ];
        let (mut o, mut e) = (Vec::new(), Vec::new());
        demux(&mut buf, &mut o, &mut e);
        assert_eq!(o, b"abc");
        assert!(e.is_empty());
        assert_eq!(buf.len(), 9);
        buf.push(b'y');
        demux(&mut buf, &mut o, &mut e);
        assert_eq!(e, b"xy");
        assert!(buf.is_empty());
    }

    #[tokio::test]
    async fn the_output_of_an_exec_sync_is_cut() {
        let frame = |stream: u8, data: &[u8]| {
            let mut f = vec![stream, 0, 0, 0];
            f.extend((data.len() as u32).to_be_bytes());
            f.extend_from_slice(data);
            f
        };
        let mut stream = Vec::new();
        for _ in 0..300 {
            stream.extend(frame(1, &[b'o'; 10_000]));
        }
        stream.extend(frame(2, b"err"));
        let (out, err) = exec_output(&stream[..], 1 << 20).await.unwrap();
        assert_eq!(out.len(), 1 << 20);
        assert_eq!(err, b"err");
        let (out, err) = exec_output(&stream[..], 4 << 20).await.unwrap();
        assert_eq!(out.len(), 3_000_000);
        assert_eq!(err, b"err");
    }

    /// Whether the frontend was told that the engine is gone.
    fn told(engine: &Varlink) -> bool {
        use futures::FutureExt;
        engine.engine_gone().notified().now_or_never().is_some()
    }

    #[tokio::test]
    async fn an_engine_that_cannot_be_reached_is_told() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("engine").join("engine.sock");
        let engine = Varlink::new(&socket);
        // (the directory of the socket is not there: made again after the
        // process confined itself to the one it had)
        assert!(matches!(
            engine.version().await,
            Err(EngineError::Unavailable(_))
        ));
        assert!(told(&engine), "no socket");
        // a socket nobody listens on
        std::fs::create_dir(socket.parent().unwrap()).unwrap();
        drop(std::os::unix::net::UnixListener::bind(&socket).unwrap());
        let engine = Varlink::new(&socket);
        assert!(engine.version().await.is_err());
        assert!(told(&engine), "refused");
    }

    #[test]
    fn the_names_of_the_engine_are_the_codes_of_the_cri() {
        let named = |e: wire::EngineError| refused(e);
        let words = || (String::from("cause"), String::from("words"));
        let (cause, message) = words();
        assert!(matches!(
            named(wire::EngineError::NoSuchContainer { cause, message }),
            EngineError::NotFound(m) if m == "words"
        ));
        let (cause, message) = words();
        assert!(matches!(
            named(wire::EngineError::Conflict { cause, message }),
            EngineError::Conflict(_)
        ));
        let (cause, message) = words();
        assert!(matches!(
            named(wire::EngineError::InvalidState { cause, message }),
            EngineError::Precondition(_)
        ));
        let (cause, message) = words();
        assert!(matches!(
            named(wire::EngineError::InvalidArgument { cause, message }),
            EngineError::Invalid(_)
        ));
        let (cause, message) = words();
        assert!(matches!(
            named(wire::EngineError::NotSupported { cause, message }),
            EngineError::Unsupported(_)
        ));
        assert!(matches!(
            named(wire::EngineError::unavailable("x".into())),
            EngineError::Unavailable(_)
        ));
        let (cause, message) = words();
        assert!(matches!(
            named(wire::EngineError::InvalidContent {
                cause,
                message,
                party: "registry".into(),
                object: "sha256:x".into(),
            }),
            EngineError::DataLoss(_)
        ));
        let (cause, message) = words();
        assert!(matches!(
            named(wire::EngineError::SourceUnavailable {
                cause,
                message,
                party: "registry".into(),
                transient: true,
            }),
            EngineError::Unavailable(_)
        ));
        let (cause, message) = words();
        assert!(matches!(
            named(wire::EngineError::Unauthorized { cause, message }),
            EngineError::Unauthenticated(_)
        ));
        let (cause, message) = words();
        assert!(matches!(
            named(wire::EngineError::NoSpace { cause, message }),
            EngineError::Exhausted(_)
        ));
    }

    #[test]
    fn a_pod_is_a_spec_of_the_engine() {
        let mut create = PodCreate {
            name: "p".into(),
            hostname: "h".into(),
            ports: vec![Port {
                host_ip: String::new(),
                host_port: 8080,
                container_port: 80,
                protocol: String::new(),
            }],
            host_ipc: true,
            host_pid: true,
            share_pid: true,
            net: NsMode::Host,
            userns_auto: true,
            uid_map: vec![IdRange {
                container_id: 0,
                host_id: 1000,
                size: 10,
            }],
            resources: Resources {
                memory_limit: 1 << 20,
                cpu_period: 100_000,
                cpu_quota: 50_000,
                ..Default::default()
            },
            ..Default::default()
        };
        let spec = pod_spec(&create).unwrap();
        assert_eq!(spec.hostname.as_deref(), Some("h"));
        assert_eq!(spec.networks, ["host"]);
        assert!(spec.host_ipc && !spec.share_ipc);
        assert!(spec.host_pid && !spec.share_pid);
        assert_eq!(spec.userns, Some(UsernsChoice::Auto(None)));
        assert_eq!(
            spec.gid_mappings.len(),
            1,
            "the maps of one kind are the other's"
        );
        assert_eq!(spec.ports[0].protocol, "tcp");
        assert_eq!(spec.ports[0].host_port, Some(8080));
        let limits = spec.resources.expect("limits");
        assert_eq!(limits.memory, Some(1 << 20));
        assert_eq!(limits.cpu_period, Some(100_000));
        // a memory below -1 is refused, not made no limit; 0 and -1 are none
        for (v, ok) in [(-2, false), (i64::MIN, false), (-1, true), (0, true)] {
            let r = Resources {
                memory_limit: v,
                ..Default::default()
            };
            assert_eq!(pod_resources(&r).is_ok(), ok, "memory {v}");
            let r = Resources {
                memory_swap: v,
                ..Default::default()
            };
            assert_eq!(pod_resources(&r).is_ok(), ok, "swap {v}");
        }
        // (not the configuration's mode: the engine's default without a parent)
        assert_eq!(spec.cgroups, CgroupsMode::Enabled);
        // the systemd driver's slice: scopes below it
        create.cgroup_parent = "kubepods-burstable-pod1.slice".into();
        assert_eq!(pod_spec(&create).unwrap().cgroups, CgroupsMode::Scope);
        // the cgroupfs driver's path is the parent of the cgroups made there
        create.cgroup_parent = "/kubepods/pod1".into();
        assert_eq!(pod_spec(&create).unwrap().cgroups, CgroupsMode::Enabled);
        create.cgroup_parent = String::new();
        assert_eq!(pod_spec(&create).unwrap().cgroups, CgroupsMode::Enabled);
        // the engine takes it
        let bytes = serde_json::to_vec(&pod_spec(&create).unwrap()).unwrap();
        PodSpec::from_document(&bytes).unwrap();
    }
}
