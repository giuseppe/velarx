// SPDX-License-Identifier: Apache-2.0
//! The engine as a varlink service: `org.velarx.Engine` on `engine.sock`
//! (`velarx varlink`).
//!
//! The service is what the frontends call (the REST API,
//! later the CRI): one method decodes its arguments, runs the operation of
//! the services that the command line and the API server already use, and
//! encodes the answer.  The types and the client side are in
//! [`velarx_proto::engine`]; the definition file generated from them is
//! `interfaces/org.velarx.Engine.varlink` (a test keeps it current).
//!
//! The zlink servers are not `Send`, so the connections are served by a
//! thread of their own (a runtime that runs one thread and a `LocalSet`);
//! the work of a call runs on the runtime of the engine ([`Engine::run`]),
//! and the thread only reads and writes sockets.
//!
//! * Who may connect: `SO_PEERCRED` of every connection is checked (the
//!   user of the engine and root; the socket's mode decides for root's
//!   engine).  Whoever may connect can do what a client of the API can do.
//! * Documents: the replies shaped for podman are `object`s in the JSON.
//!   A small one is in the reply, a large one is the content of a pipe
//!   ([`documents`]).

use crate::api::podman::error::{ApiError, Kind as ErrorKind};
use crate::api::podman::stream::{JsonLines, PipeSink};
use crate::api::podman::{self, ContainerListQuery, Filters};
use crate::api::AppState;
use serde_json::Value;
use std::collections::BTreeMap;
use std::future::Future;
use std::io;
use std::os::fd::OwnedFd;
use std::sync::Arc;
use tracing::{debug, warn};
use velarx_content::activation::{self, Activity, IdleExit};
use velarx_proto::build::MAX_FRAME;
use velarx_proto::buildspec::{
    BuildClient, BuildContextKind, BuildContextSpec, BuildEntitlement, BuildEvent, BuildEventKind,
    BuildFlags, BuildOutput, BuildOutputKind, BuildPair, BuildPull, BuildSecretKind,
    BuildSecretSpec, BuildSpec, BuildStream, SbomFlags,
};
use velarx_proto::descriptors::Descriptors;
use velarx_proto::engine::{
    Ack, ArtifactAddSpec, AttachOptions, ChangeKind, Changed, Changes, CheckpointFlags,
    CheckpointShared, Checkpointed, CommitSpec, Compression, Condition, ContainerCreated,
    ContainersPruned, DiffType, Document, Documents, EngineError, FileChange, Filter, Id,
    ImportSpec, InfoReply, InstanceSpec, LayerCompression, LogOptions, LoginReply,
    ManifestArtifactSpec, ManifestFormat, Mounted, MountedList, Names, NetworkRemoved,
    NetworkStatus, NotLazyLayer, PathStat, PlatformSpec, PodLogOptions, PodRan, PodRemoved,
    Processes, PullPolicy, PullSpec, PushSpec, Removed, RemovedContainer, Restarted, RestoreFlags,
    Restored, RuntimeInfo, SearchHit, SearchHits, SessionOpened, SessionPhase, SessionReply,
    SessionStreams, StartedAttached, Stopped, StorageUsage, Stream, SystemdSpec, Units,
    UpdateBlockIo, UpdateDevice, UpdateHealth, UpdateSpec, VolumeRemoved, Waited,
    MAX_CONTAINER_SPEC, MAX_FILTERS, MAX_POD_SPEC,
};
use velarx_proto::health::{
    Health, HealthResult, HealthStatus, Healthcheck, OnFailure, StartupHealthcheck,
};
use velarx_proto::pod::{
    IdMapping, PodAction, PodDeviceLimit, PodDnsConfig, PodExitPolicy, PodPortMapping,
    PodResources, PodSecurityContext, PodSpec, PodUsage, RestartPolicy,
};
use velarx_proto::pod::{Pressure, Psi, PsiData};
use velarx_proto::request as req;
use velarx_proto::retry::Retry;
use velarx_proto::system::{
    CgroupManager, CheckAction, CheckProblem, CheckRemovedContainer, CheckReport, CheckSpec,
    Collected, ComponentHealth, ComponentStatus, ContainerUsage, CpuUtilization,
    DiskUsageInspected, DiskUsageRecord, GcReport, HealthReport, HostRecord, HostTool, ImageUsage,
    OciRuntimeRecord, PrunedVolume, RuntimePath, ServiceStore, StoreRecord, StoreUsage,
    StoresListed, StoresReport, SubnetPool, SystemChecked, SystemInspected, SystemPruneReport,
    SystemPruned, SystemRecord, SystemdRecord, VersionInspected, VersionRecord, VolumeUsage,
};
use velarx_proto::transfer::{NotLazy, Placed};
use velarx_proto::wait::WaitCondition;
use velarx_proto::workload::{
    ArtifactInspected, ArtifactListed, ArtifactRecord, BuildPruned, BySource, CheckpointState,
    Committed, ComposefsLayer, ContainerInspected, ContainerInterface, ContainerListed,
    ContainerMetrics, ContainerMount, ContainerNetwork, ContainerPaths, ContainerPort,
    ContainerRecord, CriuStatistics, DeviceLimit, DeviceNode, DeviceSpec, Event as EventRecord,
    EventKind, EventListed, ExecInspected, ExecRecord, ExecSpec, HealthChecked, HostSettings,
    HugepageLimit, ImageCompleted, ImageConfigRecord, ImageHealthcheck, ImageHistoryEntry,
    ImageHistoryListed, ImageInspected, ImageListed, ImagePlatform, ImagePruneListed, ImageRecord,
    ImageRemoved, ImageTreeChild, ImageTreeInspected, ImageTreeLayer, ImageTreeRecord,
    ImagesRemoved, InterfaceStats, LeaseRange, LogStream, ManifestDescriptor, ManifestInstance,
    ManifestListRecord, ManifestRemoved, MetricDescriptor, MetricDescriptorListed, MetricSample,
    MountKind, NetworkCreated, NetworkDriver, NetworkInspected, NetworkListed, NetworkMember,
    NetworkRecord, NetworkRoute, NetworkSpec, NetworkSubnet, PodInspected, PodListed, PodLogLine,
    PodLogListed, PodMember, PodMetrics, PodMetricsListed, PodRecord, PodStatus, ProcessConfig,
    ProcessUser, Pruned, PrunedImage, PullState, Pulled, PulledImage, PullingAnswer, PullsListed,
    Pushed, PushedImage, PushedTag, Reclaimed, RegistryDigested, RemoteImage, Resources, RunState,
    Scopes, SecretInspected, SecretListed, SecretRecord, StatsListed, StatsRecord,
    TransferProgress, TransferStats, TransferStatus, Ulimit, VolumeInspected, VolumeListed,
    VolumeRecord, VolumeSpec, VolumesPruned,
};
use velarx_proto::{DIGEST, INLINE_MAX, PROTO};

/// The frontends that hold an engine a frontend started (no service manager
/// starts it): each passed the end of a socket with `Hold` and keeps the
/// other.  The engine lives while the frontend that started it does, and
/// while any of these does; a hold also keeps an engine that leaves when
/// idle from leaving.  Once the engine decided to stop ([`Holds::none`]
/// returned) it takes no more holds: a frontend that comes then is refused
/// and starts the engine again.
#[derive(Clone, Default)]
pub struct Holds(Arc<HoldsInner>);

impl std::ops::Deref for Holds {
    type Target = HoldsInner;

    fn deref(&self) -> &HoldsInner {
        &self.0
    }
}

/// What the clones of [`Holds`] share.
pub struct HoldsInner {
    /// How many hold the engine, and whether it stopped taking holds
    state: tokio::sync::watch::Sender<(usize, bool)>,
    /// The connections of the service, when it is served
    activity: std::sync::OnceLock<Arc<Activity>>,
    /// A copy of the end of each hold, for a restart of the engine, which
    /// executes the program again: the hold goes on, its frontend sees
    /// nothing
    kept: std::sync::Mutex<Vec<(u64, OwnedFd)>>,
    next: std::sync::atomic::AtomicU64,
}

/// The ends of the holds refused because the engine stops: open until the
/// process exits (or executes a new engine), which their frontends wait
/// for.  Not a field of [`Holds`]: those are dropped when the service ends,
/// before the process has finished with the store.
static LATE: std::sync::Mutex<Vec<std::os::unix::net::UnixStream>> =
    std::sync::Mutex::new(Vec::new());

/// The most refused hold ends kept open at once: a client that opens
/// connections while the engine stops cannot exhaust its descriptors, the
/// excess is closed (the refusal it sees is the same).
const MAX_LATE: usize = 64;

/// Keep `stream` open in `late` unless `cap` ends are kept already.
fn keep_late(
    late: &mut Vec<std::os::unix::net::UnixStream>,
    stream: std::os::unix::net::UnixStream,
    cap: usize,
) -> bool {
    if late.len() >= cap {
        return false;
    }
    late.push(stream);
    true
}

impl Default for HoldsInner {
    fn default() -> Self {
        Self {
            state: tokio::sync::watch::channel((0, false)).0,
            activity: std::sync::OnceLock::new(),
            kept: std::sync::Mutex::default(),
            next: std::sync::atomic::AtomicU64::new(0),
        }
    }
}

/// The variable that names the descriptors of the holds a restarted engine
/// gets: their numbers, separated by commas.
pub const HOLD_FDS_ENV: &str = "VELARX_HOLD_FDS";

/// The most holds at once.
const MAX_HOLDS: usize = 64;

/// A hold, counted while it lives (and the service busy while it lives).
struct Hold {
    holds: Holds,
    id: u64,
    _busy: Option<activation::Busy>,
}

impl Drop for Hold {
    fn drop(&mut self) {
        let id = self.id;
        self.holds
            .kept
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .retain(|(i, _)| *i != id);
        self.holds.state.send_modify(|(n, _)| *n -= 1);
    }
}

/// Why a hold is refused.
#[derive(Debug, PartialEq)]
enum NoHold {
    Stopping,
    TooMany,
    Failed(String),
}

impl std::fmt::Display for NoHold {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Stopping => f.write_str("the engine is stopping"),
            Self::TooMany => write!(f, "at most {MAX_HOLDS} holds"),
            Self::Failed(why) => f.write_str(why),
        }
    }
}

impl Holds {
    /// Count a hold whose end is `keep` (a copy, for a restart).
    fn add(&self, keep: OwnedFd) -> Result<Hold, NoHold> {
        let mut refused = None;
        self.state.send_if_modified(|(n, stopping)| {
            refused = if *stopping {
                Some(NoHold::Stopping)
            } else if *n >= MAX_HOLDS {
                Some(NoHold::TooMany)
            } else {
                None
            };
            if refused.is_none() {
                *n += 1;
            }
            refused.is_none()
        });
        match refused {
            Some(why) => Err(why),
            None => {
                let id = self.next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                self.kept
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .push((id, keep));
                Ok(Hold {
                    holds: self.clone(),
                    id,
                    _busy: self.activity.get().map(activation::Busy::new),
                })
            }
        }
    }

    /// Copies of the ends of the holds, to pass to the engine that executes
    /// this program again.
    pub fn fds(&self) -> io::Result<Vec<OwnedFd>> {
        self.kept
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .map(|(_, fd)| Ok(rustix::io::fcntl_dupfd_cloexec(fd, 10)?))
            .collect()
    }

    /// Hold the engine with `fd`, the end of a hold a previous engine
    /// process had; on the runtime that is current.
    pub fn adopt(&self, fd: OwnedFd) {
        if let Err(e) = self.watch(fd) {
            warn!("cannot keep a hold across the restart: {e}");
        }
    }

    /// Count the hold of the socket `fd` while the other end is open.  A
    /// refusal because the engine stops keeps `fd` open: its frontend sees
    /// it hang up when the engine has exited.
    fn watch(&self, fd: OwnedFd) -> Result<(), NoHold> {
        use tokio::io::AsyncReadExt;
        let keep =
            rustix::io::fcntl_dupfd_cloexec(&fd, 10).map_err(|e| NoHold::Failed(e.to_string()))?;
        let stream = std::os::unix::net::UnixStream::from(fd);
        let hold = match self.add(keep) {
            Ok(hold) => hold,
            Err(NoHold::Stopping) => {
                keep_late(
                    &mut LATE.lock().unwrap_or_else(|e| e.into_inner()),
                    stream,
                    MAX_LATE,
                );
                return Err(NoHold::Stopping);
            }
            Err(why) => return Err(why),
        };
        stream
            .set_nonblocking(true)
            .map_err(|e| NoHold::Failed(e.to_string()))?;
        let mut stream =
            tokio::net::UnixStream::from_std(stream).map_err(|e| NoHold::Failed(e.to_string()))?;
        tokio::spawn(async move {
            let _hold = hold;
            let mut byte = [0u8; 1];
            // (nothing is ever sent: a read returns when it is closed)
            while stream.read(&mut byte).await.is_ok_and(|n| n > 0) {}
        });
        Ok(())
    }

    /// Something running for a frontend (a stream), that keeps the engine
    /// from leaving when idle until it is dropped.
    fn busy(&self) -> Option<activation::Busy> {
        self.activity.get().map(activation::Busy::new)
    }

    /// The service of these holds: a hold keeps it from leaving when idle.
    fn served_by(&self, activity: &Arc<Activity>) {
        let _ = self.activity.set(activity.clone());
    }

    /// How many hold the engine.
    pub fn count(&self) -> usize {
        self.state.borrow().0
    }

    /// Return once `n` hold the engine (at once when they do).
    pub async fn wait_count(&self, n: usize) {
        let _ = self
            .state
            .subscribe()
            .wait_for(|(held, _)| *held == n)
            .await;
    }

    /// Return when no frontend holds the engine; from then on it takes no
    /// more holds (the engine stops: one that came now would be lost).
    pub async fn none(&self) {
        let mut rx = self.state.subscribe();
        loop {
            let _ = rx.wait_for(|(n, _)| *n == 0).await;
            // (a hold may come between the wait and here)
            let stopped = self.state.send_if_modified(|(n, stopping)| {
                *stopping = *n == 0;
                *stopping
            });
            if stopped {
                return;
            }
        }
    }
}

/// The holds a previous process of this engine passed on
/// ([`HOLD_FDS_ENV`]).
///
/// Call it once, early, before anything else adopts descriptors.
pub fn take_hold_fds(startup: &velarx_sys::fd::Startup) -> Vec<OwnedFd> {
    use std::os::fd::IntoRawFd;
    // (the variable is ours, but the environment is not to be trusted:
    // numbers of digits only, at most MAX_HOLDS, each descriptor checked)
    let numbers: Vec<i32> = std::env::var(HOLD_FDS_ENV)
        .unwrap_or_default()
        .split(',')
        .filter(|v| !v.is_empty() && v.len() <= 9 && v.bytes().all(|b| b.is_ascii_digit()))
        .filter_map(|v| v.parse::<i32>().ok())
        .filter(|fd| *fd > 2)
        .take(MAX_HOLDS)
        .collect();
    std::env::remove_var(HOLD_FDS_ENV);
    numbers
        .into_iter()
        .filter_map(|fd| {
            // (a number that is no descriptor is not ours to close; one
            // that is no hold is not taken, nor closed, nor passed to a child)
            let owned = startup.adopt(fd)?;
            if rustix::io::fcntl_setfd(&owned, rustix::io::FdFlags::CLOEXEC).is_ok()
                && is_hold_socket(std::os::fd::AsFd::as_fd(&owned))
            {
                Some(owned)
            } else {
                let _ = owned.into_raw_fd();
                None
            }
        })
        .collect()
}

/// Whether `fd` may be the end of a hold: a connected unix stream socket
/// (not a listener) whose peer is a user that may hold the engine.
fn is_hold_socket(fd: std::os::fd::BorrowedFd<'_>) -> bool {
    use rustix::net::sockopt;
    matches!(
        sockopt::socket_type(fd),
        Ok(rustix::net::SocketType::STREAM)
    ) && matches!(sockopt::socket_domain(fd), Ok(d) if d == rustix::net::AddressFamily::UNIX)
        && matches!(sockopt::socket_acceptconn(fd), Ok(false))
        && sockopt::socket_peercred(fd).is_ok_and(|c| velarx_base::ipc::trusted_uid(c.uid.as_raw()))
}

/// The service of one engine process.
#[derive(Clone)]
pub struct Engine {
    state: Arc<AppState>,
    holds: Holds,
    /// Where the work of the calls runs
    runtime: tokio::runtime::Handle,
    /// The calls that change something and are in progress
    calls: Arc<Mutating>,
    /// The pauses that end by themselves
    leases: Arc<PauseLeases>,
    /// The attach and exec sessions in progress
    sessions: Arc<Sessions>,
    /// The engine of one command, served from its process for the length of
    /// the command: what a service keeps in its memory goes with it
    in_process: bool,
}

/// The calls in progress that change something: a restart waits for them
/// (the reads and the waits end with their connection).
#[derive(Default)]
pub struct Mutating {
    count: std::sync::atomic::AtomicUsize,
    /// Why new calls are refused (0: they are not)
    refusing: std::sync::atomic::AtomicU8,
    done: tokio::sync::Notify,
}

/// Why the engine takes no more calls that change something.
#[derive(Clone, Copy)]
enum Refusing {
    Restart = 1,
    Stop = 2,
}

/// A call that changes something, counted while it lives (and the engine
/// busy: it does not leave idle while the work of a call whose client went
/// away goes on).
pub struct Mutation(Arc<Mutating>, #[allow(dead_code)] Option<activation::Busy>);

impl Mutation {
    /// The call counted once more, for the part of it that sends the reply:
    /// the engine does not stop before the reply is written (the service
    /// thread ends the poll that writes it first).
    fn also(&self) -> Mutation {
        self.0
            .count
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Mutation(self.0.clone(), None)
    }
}

impl Drop for Mutation {
    fn drop(&mut self) {
        if self
            .0
            .count
            .fetch_sub(1, std::sync::atomic::Ordering::SeqCst)
            == 1
        {
            self.0.done.notify_waiters();
        }
    }
}

impl Mutating {
    /// Count a call that changes something, unless the engine is about to
    /// restart: such a call is refused, its client asks again of the engine
    /// that comes next.
    fn enter(self: &Arc<Self>, busy: Option<activation::Busy>) -> Result<Mutation, EngineError> {
        use std::sync::atomic::Ordering::SeqCst;
        self.count.fetch_add(1, SeqCst);
        let mutation = Mutation(self.clone(), busy);
        match self.refusing.load(SeqCst) {
            0 => Ok(mutation),
            n => Err(EngineError::unavailable(
                if n == Refusing::Restart as u8 {
                    velarx_proto::engine::RESTARTING
                } else {
                    "the engine is stopping: ask again"
                }
                .to_string(),
            )),
        }
    }

    /// Count a call that is not refused whatever the state (the restart
    /// that makes the engine refuse the others): a drain waits for it.
    fn count_always(self: &Arc<Self>) -> Mutation {
        self.count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Mutation(self.clone(), None)
    }

    /// Refuse new calls that change something (they are told why): the
    /// engine restarts (`restarting`) or stops.
    pub fn refuse_new(&self, restarting: bool) {
        let why = if restarting {
            Refusing::Restart
        } else {
            Refusing::Stop
        };
        self.refusing
            .store(why as u8, std::sync::atomic::Ordering::SeqCst);
    }

    /// Refuse new calls that change something and wait until those in
    /// progress finished, at most `limit`.  Returns how many are left.
    pub async fn drain(self: &Arc<Self>, limit: std::time::Duration) -> usize {
        use std::sync::atomic::Ordering::SeqCst;
        if self.refusing.load(SeqCst) == 0 {
            self.refuse_new(false);
        }
        let finished = async {
            loop {
                let changed = self.done.notified();
                tokio::pin!(changed);
                // (registered before the count is read: no wakeup is lost)
                changed.as_mut().enable();
                if self.count.load(SeqCst) == 0 {
                    return;
                }
                changed.await;
            }
        };
        let _ = tokio::time::timeout(limit, finished).await;
        self.count.load(SeqCst)
    }
}

/// The pauses of containers that the engine ends if their client does not:
/// a client that froze containers for a cut and died before it thawed them.
#[derive(Default)]
struct PauseLeases {
    next: std::sync::atomic::AtomicU64,
    armed: std::sync::Mutex<std::collections::HashMap<String, (u64, tokio::task::AbortHandle)>>,
}

impl PauseLeases {
    /// Run `end` after `after`, unless the lease of `name` was cancelled or
    /// replaced by then.  With `replace` false a lease of `name` armed
    /// already is kept, and `end` dropped (what this engine armed is as
    /// recent as what the database had when it was read, or more).
    fn arm(
        self: &Arc<Self>,
        name: &str,
        after: std::time::Duration,
        replace: bool,
        end: impl Future<Output = ()> + Send + 'static,
    ) {
        let mut armed = self.armed.lock().unwrap_or_else(|e| e.into_inner());
        if !replace && armed.contains_key(name) {
            return;
        }
        let token = self.next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let (leases, key) = (self.clone(), name.to_string());
        let task = tokio::spawn(async move {
            tokio::time::sleep(after).await;
            let mine = {
                let mut armed = leases.armed.lock().unwrap_or_else(|e| e.into_inner());
                armed.get(&key).is_some_and(|(t, _)| *t == token) && armed.remove(&key).is_some()
            };
            if mine {
                end.await;
            }
        });
        if let Some((_, old)) = armed.insert(name.to_string(), (token, task.abort_handle())) {
            old.abort();
        }
    }

    /// The pause of `name` was ended by someone: no timer is left.
    fn cancel(&self, name: &str) {
        if let Some((_, task)) = self
            .armed
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(name)
        {
            task.abort();
        }
    }

    /// End the pause of the container `id` after `after`, if its lease
    /// recorded in the database is still the one for `until`.  With
    /// `replace` false (the leases read from the database) a lease this
    /// engine armed for `id` is kept as it is.
    fn arm_pause(
        self: &Arc<Self>,
        state: &Arc<AppState>,
        id: String,
        until: i64,
        after: std::time::Duration,
        replace: bool,
        busy: Option<activation::Busy>,
    ) {
        let state = state.clone();
        let name = id.clone();
        self.arm(&id, after, replace, async move {
            let _busy = busy;
            // (made before the first try: a change after it is not missed)
            let mut changes = state.db.watch_changes();
            loop {
                match podman::container_end_pause_lease(&state, &name, until).await {
                    // (the end waits for the pause lock: a commit or a
                    // checkpoint that holds it delays the resume)
                    Ok(podman::LeaseEnd::Resumed) => match now_ms().saturating_sub(until) {
                        late if late >= 1000 => warn!(
                            "The lease of the pause of {name} ended: resumed {late} ms after \
                             its deadline"
                        ),
                        _ => warn!("The lease of the pause of {name} ended: resumed"),
                    },
                    Ok(podman::LeaseEnd::Gone) => {
                        debug!("The pause of {name} was ended before its lease")
                    }
                    // The lease stays in the database: tried again once it
                    // changes (another write went through).
                    Ok(podman::LeaseEnd::Unrecorded(e)) => {
                        warn!(
                            "Cannot end the lease of the pause of {name} ({e}): tried again at \
                             the next change of the database"
                        );
                        if next_change(&mut changes).await {
                            continue;
                        }
                    }
                    Err(e) => debug!("The lease of the pause of {name} ended: {e:?}"),
                }
                return;
            }
        });
    }
}

/// Until the next change of the database (a write of this process or
/// another): false when that cannot be watched (an error told already).
async fn next_change(changes: &mut std::io::Result<velarx_db::ChangeWatch>) -> bool {
    match changes {
        Ok(watch) => match watch.changed().await {
            Ok(()) => true,
            Err(e) => {
                warn!("Cannot watch the database: {e}");
                false
            }
        },
        Err(e) => {
            warn!("Cannot watch the database: {e}");
            false
        }
    }
}

/// Milliseconds since the epoch.
fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as i64)
}

impl Engine {
    /// Arm again the leases of the pauses that were recorded before the
    /// engine started (a restart, or a crash): the containers they paused
    /// are unpaused at their deadline, at once when it passed.  When the
    /// database cannot be read now the engine goes on, and they are read
    /// again at its next change (another write went through): the task that
    /// waits for it, then.
    pub async fn rearm_pause_leases(&self) -> Option<tokio::task::JoinHandle<()>> {
        // (made before the first read: a change after it is not missed)
        let mut changes = self.state.db.watch_changes();
        if self.arm_recorded_leases().await {
            return None;
        }
        let engine = self.clone();
        let busy = self.holds.busy();
        Some(tokio::spawn(async move {
            let _busy = busy;
            while next_change(&mut changes).await {
                if engine.arm_recorded_leases().await {
                    return;
                }
            }
        }))
    }

    /// Arm the leases the database has: false when it cannot be read.
    async fn arm_recorded_leases(&self) -> bool {
        let leases = match self.state.container_service.pause_leases().await {
            Ok(leases) => leases,
            Err(e) => {
                warn!(
                    "Cannot read the leases of the pauses ({e}): read again at the next change \
                     of the database"
                );
                return false;
            }
        };
        for (id, until) in leases {
            let after = std::time::Duration::from_millis(
                u64::try_from(until.saturating_sub(now_ms())).unwrap_or(0),
            );
            let busy = self.holds.busy();
            self.leases
                .arm_pause(&self.state, id, until, after, false, busy);
        }
        true
    }

    pub fn new(state: Arc<AppState>, holds: Holds) -> Self {
        Self {
            state,
            holds,
            runtime: tokio::runtime::Handle::current(),
            calls: Arc::default(),
            leases: Arc::default(),
            sessions: Arc::default(),
            in_process: false,
        }
    }

    /// This engine serves one command from its process (see
    /// the `in_process` field): the events its memory keeps go
    /// with the command, so it reads none when no backend keeps them.
    pub fn in_process(mut self) -> Self {
        self.in_process = true;
        self
    }

    /// The engine restarts: from here on it takes no connection (the one
    /// that comes waits for the engine that follows, it is not served and
    /// cut by this one) and no call that changes something.  Before the
    /// restart is answered.
    async fn stop_serving(&self) {
        self.calls.refuse_new(true);
        if let Some(activity) = self.holds.activity.get() {
            activity.stop_accepting().await;
        }
    }

    /// The daemon is asked to start again (`upgraded`: from the binary
    /// installed), then the engine takes no more connections.  In this
    /// order: the daemon sees the service stop accepting, it ends once the
    /// connections do, and must find the restart asked, not an engine that
    /// left.
    async fn restart_now(&self, upgraded: bool) {
        if upgraded {
            self.state.server_service.restart_upgraded();
        } else {
            let timeout = self
                .state
                .config
                .server
                .shutdown_timeout_secs
                .min(u64::from(u32::MAX)) as u32;
            self.state.server_service.restart(timeout).await;
        }
        self.stop_serving().await;
    }

    /// The calls in progress that change something.
    pub fn mutating(&self) -> Arc<Mutating> {
        self.calls.clone()
    }

    /// Run `work` on the runtime of the engine, off the thread that serves
    /// the sockets.  It is spawned here, not when the answer is awaited: the
    /// future of a call then holds a handle, not `work` (the dispatch of the
    /// service has the futures of all the calls in its frame, on the stack
    /// of the service thread: holding `work` made it 83 kB and the frames
    /// of a call more than 1 MiB in a debug build).
    fn run<T, Fut>(
        &self,
        work: impl FnOnce(Arc<AppState>) -> Fut,
    ) -> impl Future<Output = Result<T, EngineError>>
    where
        T: Send + 'static,
        Fut: Future<Output = T> + Send + 'static,
    {
        self.run_fut(work(self.state.clone()))
    }

    /// [`Engine::run`] for work that is made of more than the state.
    fn run_fut<T: Send + 'static>(
        &self,
        work: impl Future<Output = T> + Send + 'static,
    ) -> impl Future<Output = Result<T, EngineError>> {
        let admitted = self.calls.enter(self.holds.busy()).map(|counted| {
            let replying = counted.also();
            // (counted until the work ended, whoever waits for it)
            let task = self.runtime.spawn(async move {
                let done = work.await;
                drop(counted);
                done
            });
            (task, replying)
        });
        async move {
            let (task, replying) = admitted?;
            let done = task
                .await
                .map_err(|e| EngineError::failed(format!("the call stopped: {e}")));
            // (the reply follows in the same turn of the service thread)
            drop(replying);
            done
        }
    }
}

impl Engine {
    /// Run an operation of the API on the engine's runtime: its answer, or
    /// the error a podman client sees.
    fn api<T, Fut>(
        &self,
        kind: ErrorKind,
        work: impl FnOnce(Arc<AppState>) -> Fut,
    ) -> impl Future<Output = Result<T, EngineError>>
    where
        T: Send + 'static,
        Fut: Future<Output = crate::api::podman::error::ApiResult<T>> + Send + 'static,
    {
        self.api_fut(kind, work(self.state.clone()))
    }

    /// [`Engine::api`] for work that is made of more than the state.
    fn api_fut<T: Send + 'static>(
        &self,
        kind: ErrorKind,
        work: impl Future<Output = crate::api::podman::error::ApiResult<T>> + Send + 'static,
    ) -> impl Future<Output = Result<T, EngineError>> {
        let answer = self.run_fut(work);
        async move { answer.await?.map_err(|e| api_error(e, kind)) }
    }
}

impl Engine {
    /// [`Engine::api`] for a call that reads or waits: its work stops when
    /// the call is dropped (the client closed the connection).
    fn api_cancelled<T, Fut>(
        &self,
        kind: ErrorKind,
        work: impl FnOnce(Arc<AppState>) -> Fut,
    ) -> impl Future<Output = Result<T, EngineError>>
    where
        T: Send + 'static,
        Fut: Future<Output = crate::api::podman::error::ApiResult<T>> + Send + 'static,
    {
        let mut task = Cancelled {
            task: self.runtime.spawn(work(self.state.clone())),
        };
        async move {
            (&mut task.task)
                .await
                .map_err(|e| EngineError::failed(format!("the call stopped: {e}")))?
                .map_err(|e| api_error(e, kind))
        }
    }
}

impl Engine {
    /// Open a stream: a pipe whose write end `produce` gets, on the runtime
    /// of the engine; the reply carries the read end.  The engine counts as
    /// busy while the stream lasts.  It ends when `produce` returns or the
    /// reader closes its end (`produce` is to notice that when it waits, see
    /// [`Sink::gone`]); a pipe nobody reads does not cost a task for ever,
    /// and nothing times a stream out (a follow may be idle for hours).
    fn open_stream<F, Fut>(
        &self,
        tty: bool,
        produce: F,
    ) -> Result<(Stream, Vec<OwnedFd>), EngineError>
    where
        F: FnOnce(PipeSink) -> Fut,
        Fut: Future<Output = ()> + Send + 'static,
    {
        let failed =
            |e: &dyn std::fmt::Display| EngineError::failed(format!("cannot open a stream: {e}"));
        let (read, write) =
            rustix::pipe::pipe_with(rustix::pipe::PipeFlags::CLOEXEC).map_err(|e| failed(&e))?;
        let _guard = self.runtime.enter();
        let sink = PipeSink::new(write, self.holds.busy()).map_err(|e| failed(&e))?;
        self.runtime.spawn(produce(sink));
        Ok((Stream { tty }, vec![read]))
    }
}

impl Engine {
    /// The reply of a download: the frames of what `opened` gives, written
    /// to a pipe the reply carries (the engine counts as busy meanwhile).
    fn download(
        &self,
        opened: Result<crate::api::ops::ByteStream, EngineError>,
    ) -> Result<(Ack, Vec<OwnedFd>), EngineError> {
        let stream = opened?;
        let (sink, read) = self.reply_pipe()?;
        self.runtime.spawn(write_frames(stream, sink));
        Ok((Ack {}, vec![read]))
    }

    /// What the client named as the path of a pull: a file or a directory it
    /// opened, or the frames of an upload (the read end of a pipe).
    fn pull_target(&self, fd: OwnedFd) -> Result<podman::images::pull::PullTarget, EngineError> {
        use podman::images::pull::PullTarget;
        let kind = rustix::fs::fstat(&fd)
            .map_err(|e| EngineError::invalid(format!("the source: {e}")))?
            .st_mode;
        let kind = rustix::fs::FileType::from_raw_mode(kind);
        match kind {
            rustix::fs::FileType::RegularFile | rustix::fs::FileType::Directory => {
                Ok(PullTarget::Fd(fd))
            }
            rustix::fs::FileType::Fifo => {
                Ok(PullTarget::Upload(self.upload(vec![fd], "the source")?))
            }
            _ => Err(EngineError::invalid(
                "the source is a file, a directory or the read end of a pipe".into(),
            )),
        }
    }

    /// The bytes of an archive the client named: a regular file open for
    /// reading, read as it is, or the frames of the read end of a pipe.
    fn archive_stream(&self, fd: OwnedFd) -> Result<crate::api::ops::ByteStream, EngineError> {
        let kind = rustix::fs::FileType::from_raw_mode(
            rustix::fs::fstat(&fd)
                .map_err(|e| EngineError::invalid(format!("the archive: {e}")))?
                .st_mode,
        );
        match kind {
            rustix::fs::FileType::Fifo => self.upload(vec![fd], "the archive"),
            rustix::fs::FileType::RegularFile => {
                let file = tokio::fs::File::from_std(std::fs::File::from(fd));
                Ok(Box::pin(futures::stream::unfold(
                    file,
                    |mut file| async move {
                        use tokio::io::AsyncReadExt;
                        let mut buf = vec![0u8; 256 * 1024];
                        match file.read(&mut buf).await {
                            Ok(0) => None,
                            Ok(n) => {
                                buf.truncate(n);
                                Some((Ok(bytes::Bytes::from(buf)), file))
                            }
                            Err(e) => Some((Err(e), file)),
                        }
                    },
                )))
            }
            _ => Err(EngineError::invalid(
                "the archive is a regular file or the read end of a pipe".into(),
            )),
        }
    }

    /// The upload a call carries: the frames of its one pipe.
    fn upload(
        &self,
        fds: Vec<OwnedFd>,
        what: &str,
    ) -> Result<crate::api::ops::ByteStream, EngineError> {
        let bad = |reason: String| EngineError::invalid(reason);
        let Ok([fd]) = <[OwnedFd; 1]>::try_from(fds) else {
            return Err(bad(format!(
                "{what} is one descriptor, the read end of a pipe"
            )));
        };
        let _guard = self.runtime.enter();
        let pipe = tokio::net::unix::pipe::Receiver::from_owned_fd(fd)
            .map_err(|e| bad(format!("{what}: {e}")))?;
        Ok(podman::build::PipeSource(Some(pipe)).into_stream(what.to_string()))
    }
}

impl Engine {
    /// The replies of an exec start: those of its session, one (the last)
    /// for a command that runs on its own; `input`: the client can send
    /// input.
    fn exec_streams(
        &self,
        started: Result<podman::exec::ExecStart, EngineError>,
        input: bool,
    ) -> SessionReplies {
        match started {
            Ok(podman::exec::ExecStart::Detached) => {
                let reply = SessionReply {
                    phase: SessionPhase::Ended,
                    opened: None,
                    streams: None,
                    exit: None,
                    message: None,
                };
                Box::pin(futures::stream::once(std::future::ready((
                    Ok(zlink::Reply::new(Some(reply)).set_continues(Some(false))),
                    Vec::new(),
                ))))
            }
            Ok(podman::exec::ExecStart::Attached(run)) => {
                let opened = run.opened(input);
                self.open_session(opened, move |out, _, busy| run.drive(out, input, busy))
            }
            Err(e) => session_failed(e),
        }
    }
}

/// The names of the sessions in progress, for `SessionCloseStdin` and
/// `SessionDetach`: what each is told goes to its engine end.
#[derive(Default)]
pub struct Sessions {
    open: std::sync::Mutex<std::collections::HashMap<String, velarx_proto::stream::Controls>>,
}

/// A session in the list of its engine, until it is dropped.
struct Listed(Arc<Sessions>, String);

impl Drop for Listed {
    fn drop(&mut self) {
        self.0.open.lock().expect("sessions").remove(&self.1);
    }
}

impl Sessions {
    /// A call of the frontend to the session `name`, answered once the
    /// session dealt with it (one that ended is not an error: there is
    /// nothing left to do).
    async fn tell(
        &self,
        name: &str,
        what: velarx_proto::stream::Control,
    ) -> Result<(), EngineError> {
        let controls = self.open.lock().expect("sessions").get(name).cloned();
        match controls {
            Some(c) => {
                velarx_proto::stream::call(&c, what).await;
                Ok(())
            }
            None => Err(EngineError::invalid(format!("no session {name}"))),
        }
    }
}

/// The replies of a session.
type SessionReplies = std::pin::Pin<
    Box<
        dyn futures::Stream<
                Item = (
                    Result<zlink::Reply<SessionReply>, EngineError>,
                    Vec<OwnedFd>,
                ),
            > + Send,
    >,
>;

/// A call of a session that failed: its one reply.
fn session_failed(e: EngineError) -> SessionReplies {
    Box::pin(futures::stream::once(std::future::ready((
        Err(e),
        Vec::new(),
    ))))
}

/// The replies of a `more` call.
type Replies<T> =
    std::pin::Pin<Box<dyn futures::Stream<Item = Result<zlink::Reply<T>, EngineError>> + Send>>;

/// The replies of a list: one record each, the last with `continues:
/// false`; an empty list is one reply without a record.  A list is asked for
/// with `more`.
fn list_replies<R: Send + 'static, T: Send + 'static>(
    more: bool,
    method: &str,
    listed: Result<Vec<R>, EngineError>,
    wrap: fn(Option<R>) -> T,
) -> Replies<T> {
    use futures::stream;
    let one = |reply| -> Replies<T> { Box::pin(stream::once(std::future::ready(reply))) };
    if !more {
        return one(Err(EngineError::InvalidArgument {
            cause: "expected more".into(),
            message: format!("{method} answers one record a reply: call it with more"),
        }));
    }
    match listed {
        Err(e) => one(Err(e)),
        Ok(list) if list.is_empty() => one(Ok(
            zlink::Reply::new(Some(wrap(None))).set_continues(Some(false))
        )),
        Ok(list) => {
            let last = list.len() - 1;
            Box::pin(stream::iter(list.into_iter().enumerate().map(
                move |(i, record)| {
                    Ok(zlink::Reply::new(Some(wrap(Some(record)))).set_continues(Some(i < last)))
                },
            )))
        }
    }
}

/// The events of a request as the records of the interface, to the
/// replies of `EventList`.
struct EventRecords(tokio::sync::mpsc::Sender<EventRecord>);

impl podman::events::EventOut for EventRecords {
    async fn send(&mut self, ev: &podman::events::Event) -> bool {
        self.0.send(ev.record()).await.is_ok()
    }

    async fn while_there<T>(&self, f: impl Future<Output = T>) -> Option<T> {
        tokio::select! {
            v = f => Some(v),
            () = self.0.closed() => None,
        }
    }
}

/// A line of the logs of a pod as the interface has it.
fn pod_log_line(e: velarx_wire::wire::PodLogEntry) -> PodLogLine {
    PodLogLine {
        container_name: e.container_name,
        container_id: e.container_id,
        container_index: i64::try_from(e.container_index).unwrap_or(i64::MAX),
        containers: i64::try_from(e.containers).unwrap_or(i64::MAX),
        time_ns: velarx_wire::monitor::logfmt::parse_rfc3339_ns(&e.timestamp).unwrap_or(0),
        stream: if e.stream == "stderr" {
            LogStream::Stderr
        } else {
            LogStream::Stdout
        },
        message: e.message,
    }
}

/// The options of a checkpoint, of the flags of a call.
fn checkpoint_options(flags: CheckpointFlags) -> velarx_wire::wire::CheckpointOptions {
    velarx_wire::wire::CheckpointOptions {
        leave_running: flags.leave_running,
        create_image: flags.create_image,
        tcp_established: flags.tcp_established,
        file_locks: flags.file_locks,
        export: None,
        compress: flags.compress.map(|c| c.word().to_string()),
        ignore_rootfs: flags.ignore_rootfs,
        ignore_volumes: flags.ignore_volumes,
        keep: flags.keep,
        print_stats: flags.print_stats,
        pre_checkpoint: flags.pre_checkpoint,
        with_previous: flags.with_previous,
    }
}

/// What a restore answers, of podman's report.
fn restored(r: velarx_proto::workload::RestoreReport) -> Restored {
    Restored {
        id: r.id,
        runtime_restore_duration: Some(r.runtime_restore_duration),
        criu_statistics: r.criu_statistics,
    }
}

/// The options of a restore, of the flags of a call.
fn restore_options(flags: RestoreFlags) -> velarx_wire::wire::RestoreOptions {
    velarx_wire::wire::RestoreOptions {
        import_previous: None,
        tcp_established: flags.tcp_established,
        tcp_close: flags.tcp_close,
        file_locks: flags.file_locks,
        keep: flags.keep,
        import: None,
        name: flags.name.filter(|n| !n.is_empty()),
        ignore_rootfs: flags.ignore_rootfs,
        ignore_static_ip: flags.ignore_static_ip,
        ignore_static_mac: flags.ignore_static_mac,
        pod: flags.pod,
        publish: flags.publish,
        print_stats: flags.print_stats,
        verify_image: flags.verify_image,
    }
}

/// The request of the command line an `ArtifactAdd` is.
fn artifact_add_request(spec: ArtifactAddSpec) -> crate::client::ArtifactAdd {
    crate::client::ArtifactAdd {
        name: spec.name,
        file_name: spec.file_name,
        append: spec.append,
        replace: spec.replace,
        artifact_type: spec.artifact_type,
        file_type: spec.file_type,
        annotations: key_value_words(spec.annotations),
        digest: spec.digest,
    }
}

/// The most bytes of the credentials of a call (certificates included).
const MAX_ACCESS: usize = 1 << 20;

/// Whether the descriptor is a directory.
fn is_directory(fd: &OwnedFd) -> std::io::Result<bool> {
    let st = rustix::fs::fstat(fd)?;
    Ok(rustix::fs::FileType::from_raw_mode(st.st_mode) == rustix::fs::FileType::Directory)
}

fn invalid_fds(e: String) -> EngineError {
    EngineError::invalid(e)
}

/// The bytes of the secret a call names by the position `at` among its
/// descriptors, a sealed memory file of at most `max` bytes: a pipe, or a
/// file that can still change, is refused.  The error says nothing of what
/// the bytes are.
fn take_sealed(
    fds: &mut Descriptors,
    at: Option<u32>,
    max: usize,
    what: &str,
) -> Result<Option<zeroize::Zeroizing<Vec<u8>>>, EngineError> {
    let Some(file) = fds.take_opt(what, at).map_err(invalid_fds)? else {
        return Ok(None);
    };
    let bytes = velarx_base::sealed::read_sealed_whole(&std::fs::File::from(file), max as u64)
        .map_err(|why| EngineError::invalid(format!("{what} {why}")))?;
    Ok(Some(zeroize::Zeroizing::new(bytes)))
}

/// The credentials a call names as `access`: the JSON of a `RegistryAccess`
/// in a sealed memory file, none without one.
fn registry_access_in(
    fds: &mut Descriptors,
    access: Option<u32>,
) -> Result<velarx_registry::auth::RegistryAccess, EngineError> {
    let Some(bytes) = take_sealed(fds, access, MAX_ACCESS, "the credentials")? else {
        return Ok(Default::default());
    };
    // (the error says nothing of what the credentials are)
    serde_json::from_slice(&bytes)
        .map_err(|_| EngineError::invalid("the credentials are not a registry access".into()))
}

/// The key a push signs with: the JSON of a [`SigningKey`] in the sealed
/// memory file named at `at`.
fn signing_key_in(
    fds: &mut Descriptors,
    at: Option<u32>,
) -> Result<Option<velarx_proto::workload::SigningKey>, EngineError> {
    let Some(bytes) = take_sealed(fds, at, MAX_ACCESS, "the signing key")? else {
        return Ok(None);
    };
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(|_| EngineError::invalid("the signing key is not a key and a passphrase".into()))
}

/// [`registry_access_in`] of a call whose only descriptor is that.
fn registry_access_of(
    fds: Vec<OwnedFd>,
    access: Option<u32>,
) -> Result<velarx_registry::auth::RegistryAccess, EngineError> {
    let mut fds = Descriptors::new(fds);
    let access = registry_access_in(&mut fds, access)?;
    fds.finish().map_err(invalid_fds)?;
    Ok(access)
}

/// The document the pipe a call names by the position `at` carries, read to
/// its end: at most `max` bytes (no more is read or allocated whatever the
/// caller writes), within [`PIPE_TIMEOUT`].  Any other descriptor is refused.
async fn document_of(
    fds: Vec<OwnedFd>,
    at: u32,
    max: usize,
    what: &str,
) -> Result<Vec<u8>, EngineError> {
    let mut fds = Descriptors::new(fds);
    let fd = fds.take(what, at).map_err(invalid_fds)?;
    fds.finish().map_err(invalid_fds)?;
    read_pipe(fd, max, what).await
}

/// What the pipe `fd` carries, to its end: at most `max` bytes (no more is
/// read or allocated whatever the caller writes), within [`PIPE_TIMEOUT`].
async fn read_pipe(fd: OwnedFd, max: usize, what: &str) -> Result<Vec<u8>, EngineError> {
    read_pipe_within(fd, max, what, PIPE_TIMEOUT).await
}

async fn read_pipe_within(
    fd: OwnedFd,
    max: usize,
    what: &str,
    within: std::time::Duration,
) -> Result<Vec<u8>, EngineError> {
    use tokio::io::AsyncReadExt;
    let bad = |reason: String| EngineError::invalid(reason);
    let mut reader = tokio::net::unix::pipe::Receiver::from_owned_fd(fd)
        .map_err(|e| bad(format!("{what}: {e}")))?;
    let mut bytes = Vec::new();
    tokio::time::timeout(
        within,
        (&mut reader).take(max as u64 + 1).read_to_end(&mut bytes),
    )
    .await
    .map_err(|_| bad(format!("{what} did not arrive in time")))?
    .map_err(|e| bad(format!("{what}: {e}")))?;
    if bytes.len() > max {
        return Err(bad(format!("{what} is at most {max} bytes")));
    }
    Ok(bytes)
}

/// The JSON document of a client the pipe of a call carries (none without
/// one), as the API server read a request body.
async fn json_document(fds: Vec<OwnedFd>, at: Option<u32>) -> Result<Option<Value>, EngineError> {
    let Some(at) = at else {
        Descriptors::new(fds).finish().map_err(invalid_fds)?;
        return Ok(None);
    };
    let bytes = document_of(
        fds,
        at,
        podman::call::MAX_JSON_BODY,
        "the document of the request",
    )
    .await?;
    // (a request without a body is an empty document)
    if bytes.is_empty() {
        return Ok(None);
    }
    podman::call::json_value_of(&bytes).map_err(|e| api_error(e, ErrorKind::None))
}

/// The binary installed at the path of the one that runs, when it is
/// another file (an upgrade replaced it): what a restart into the new
/// version executes.
pub fn installed_binary() -> Option<std::path::PathBuf> {
    use std::os::unix::fs::MetadataExt;
    let link = std::fs::read_link("/proc/self/exe").ok()?;
    let text = link.to_string_lossy();
    let path = std::path::PathBuf::from(text.strip_suffix(" (deleted)").unwrap_or(&text));
    let running = std::fs::metadata("/proc/self/exe").ok()?;
    let installed = std::fs::metadata(&path).ok()?;
    ((running.dev(), running.ino()) != (installed.dev(), installed.ino())).then_some(path)
}

/// At most [`MAX_FILTERS`] names in a call.
fn bounded(names: &[String]) -> Result<(), EngineError> {
    if names.len() > MAX_FILTERS {
        return Err(EngineError::invalid(format!(
            "at most {MAX_FILTERS} names in a call"
        )));
    }
    Ok(())
}

impl Engine {
    /// Open a session for a frontend: its first reply (`opened`, given its
    /// name; with a `logs` the pipe of the log so far comes with it), and the replies of `drive`, which hands over the
    /// streams of the process once the monitor made them and follows the
    /// session; it ends with the process or when the frontend closes its
    /// connection.  The engine counts as busy meanwhile.  Nothing times it
    /// out, and nothing of the session passes through the engine.
    fn open_session<F, Fut>(
        &self,
        mut opened: velarx_proto::engine::SessionOpened,
        drive: F,
    ) -> SessionReplies
    where
        F: FnOnce(
            velarx_proto::stream::Out,
            Option<tokio::net::unix::pipe::Sender>,
            Option<activation::Busy>,
        ) -> Fut,
        Fut: Future<Output = ()> + Send + 'static,
    {
        use futures::StreamExt;
        let failed = |e: &dyn std::fmt::Display| {
            session_failed(EngineError::failed(format!("cannot open the streams: {e}")))
        };
        let mut raw = [0u8; 16];
        if let Err(e) = rustix::rand::getrandom(&mut raw, rustix::rand::GetRandomFlags::empty()) {
            return failed(&e);
        }
        let name: String = raw.iter().map(|b| format!("{b:02x}")).collect();
        opened.session.clone_from(&name);
        let _guard = self.runtime.enter();
        let mut log = None;
        let mut theirs = None;
        if opened.logs.is_some() {
            let made = rustix::pipe::pipe_with(rustix::pipe::PipeFlags::CLOEXEC)
                .map_err(std::io::Error::from)
                .and_then(|(r, w)| {
                    tokio::net::unix::pipe::Sender::from_owned_fd(w).map(|w| (r, w))
                });
            match made {
                Ok((r, w)) => (theirs, log) = (Some(r), Some(w)),
                Err(e) => return failed(&e),
            }
        }
        let (out, replies, controls) = velarx_proto::stream::out(opened, theirs);
        self.sessions
            .open
            .lock()
            .expect("sessions")
            .insert(name.clone(), controls);
        let listed = Listed(self.sessions.clone(), name);
        let running = drive(out, log, self.holds.busy());
        self.runtime.spawn(async move {
            running.await;
            drop(listed);
        });
        Box::pin(
            tokio_stream::wrappers::ReceiverStream::new(replies).map(|(reply, fds)| {
                let last = reply.phase == SessionPhase::Ended;
                (
                    Ok(zlink::Reply::new(Some(reply)).set_continues(Some(!last))),
                    fds,
                )
            }),
        )
    }
}

/// The reply of a call that carries descriptors: the error has none.
fn with_fds<T>(
    result: Result<(T, Vec<OwnedFd>), EngineError>,
) -> (Result<T, EngineError>, Vec<OwnedFd>) {
    match result {
        Ok((reply, fds)) => (Ok(reply), fds),
        Err(e) => (Err(e), Vec::new()),
    }
}

/// The most bytes of the answer of a build to a question for credentials.
const MAX_BUILD_ANSWER: usize = 1 << 20;

impl Engine {
    /// A build of the command line: its progress is lines of events.
    /// The build goes on if the reader goes away.
    async fn cli_build(
        &self,
        spec: velarx_proto::buildspec::BuildSpec,
        access: velarx_registry::auth::RegistryAccess,
        context: podman::build::PipeSource,
        broker: Option<OwnedFd>,
        stdin: Option<OwnedFd>,
    ) -> Result<(Stream, Vec<OwnedFd>), EngineError> {
        let state = self.state.clone();
        let request = crate::client::BuildImageRequest::from_spec(spec, access)
            .map_err(EngineError::invalid)?;
        let upload = context.into_stream("the build context".into());
        let mut build = crate::api::ops::image::prepare_build(&state, request, upload)
            .await
            .map_err(|e| op_error(ErrorKind::Image, e))?;
        if let Some(broker) = broker {
            let ids = build.ssh.clone();
            build = build.with_agents(Arc::new(crate::api::ops::image::BrokerAgents {
                ids,
                broker: Arc::new(tokio::sync::Mutex::new(broker)),
            }));
        }
        if let Some(stdin) = stdin {
            build = build.with_stdin(stdin);
        }
        let events = podman::build::cli_events(state, build);
        self.open_stream(false, move |w| write_events(events, w))
    }

    /// A pipe the engine writes an answer to (it counts as busy while it
    /// does), and the read end for the reply.
    fn reply_pipe(&self) -> Result<(PipeSink, OwnedFd), EngineError> {
        let failed =
            |e: &dyn std::fmt::Display| EngineError::failed(format!("cannot open a pipe: {e}"));
        let (read, write) =
            rustix::pipe::pipe_with(rustix::pipe::PipeFlags::CLOEXEC).map_err(|e| failed(&e))?;
        let _guard = self.runtime.enter();
        let sink = PipeSink::new(write, self.holds.busy()).map_err(|e| failed(&e))?;
        Ok((sink, read))
    }
}

/// The bytes of a download as frames, ended by the empty frame: a download
/// that failed or stopped has no end, and the reader takes it for cut.
async fn write_frames(mut stream: crate::api::ops::ByteStream, mut sink: PipeSink) {
    use futures::StreamExt;
    use podman::stream::Sink;
    use tokio::io::AsyncWriteExt;
    loop {
        let next = tokio::select! {
            next = stream.next() => next,
            () = sink.gone() => return,
        };
        match next {
            Some(Ok(chunk)) => {
                for part in chunk.chunks(MAX_FRAME) {
                    let mut frame = Vec::with_capacity(4 + part.len());
                    frame.extend_from_slice(&(part.len() as u32).to_be_bytes());
                    frame.extend_from_slice(part);
                    if sink.write_all(&frame).await.is_err() {
                        return;
                    }
                }
            }
            Some(Err(e)) => {
                debug!("a download ended with an error: {e}");
                return;
            }
            None => {
                let _ = sink.write_all(&0u32.to_be_bytes()).await;
                return;
            }
        }
    }
}

/// The events of an operation as text, until they end or the reader goes.
async fn write_events(mut events: tokio::sync::mpsc::Receiver<String>, mut sink: PipeSink) {
    use podman::stream::Sink;
    use tokio::io::AsyncWriteExt;
    loop {
        let next = tokio::select! {
            next = events.recv() => next,
            () = sink.gone() => return,
        };
        match next {
            Some(text) => {
                if sink.write_all(text.as_bytes()).await.is_err() {
                    return;
                }
            }
            None => return,
        }
    }
}

/// The spec of a build, from the pipe `fd` of the call, read to its end.
async fn build_spec(fd: OwnedFd) -> Result<velarx_proto::buildspec::BuildSpec, EngineError> {
    let bytes = read_pipe(fd, velarx_proto::build::MAX_BUILD_SPEC, "a build spec").await?;
    serde_json::from_slice(&bytes).map_err(|e| EngineError::invalid(format!("a build spec: {e}")))
}

/// A task that ends when this is dropped.
struct Cancelled<T> {
    task: tokio::task::JoinHandle<T>,
}

impl<T> Drop for Cancelled<T> {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// The most seconds the content of a pipe a call carries takes to arrive.
const PIPE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

/// The most labels or options of a call.
const MAX_PAIRS: usize = 1024;

fn map_of<M: FromIterator<(String, String)>>(
    map: BTreeMap<String, String>,
) -> Result<M, EngineError> {
    if map.len() > MAX_PAIRS {
        return Err(EngineError::invalid(format!(
            "at most {MAX_PAIRS} labels or options in a call"
        )));
    }
    Ok(map.into_iter().collect())
}

/// `KEY=VALUE` of each entry of a map.
fn key_value_words(map: BTreeMap<String, String>) -> Vec<String> {
    map.into_iter().map(|(k, v)| format!("{k}={v}")).collect()
}

/// The data of a secret from the sealed memory file of the call: its size
/// is checked before anything is read (no more than a secret is allocated),
/// and the data never goes into an error.
fn secret_data(fds: Vec<OwnedFd>, at: u32) -> Result<zeroize::Zeroizing<Vec<u8>>, EngineError> {
    use velarx_wire::wire::SECRET_MAX_SIZE;
    let mut fds = Descriptors::new(fds);
    let file = std::fs::File::from(fds.take("the secret data", at).map_err(invalid_fds)?);
    fds.finish().map_err(invalid_fds)?;
    let size = file.metadata().map_or(0, |m| m.len());
    if size > SECRET_MAX_SIZE as u64 {
        return Err(api_error(
            ApiError::new(
                413,
                format!("the secret is larger than {SECRET_MAX_SIZE} bytes"),
            ),
            ErrorKind::Secret,
        ));
    }
    velarx_base::sealed::read_sealed_whole(&file, SECRET_MAX_SIZE as u64)
        .map(zeroize::Zeroizing::new)
        .map_err(|why| EngineError::invalid(format!("the secret data {why}")))
}

/// The error of an operation of the podman shaping, by the name of its
/// condition.
pub(crate) fn api_error(mut e: ApiError, kind: ErrorKind) -> EngineError {
    let shown = e.kind_or(kind);
    let state = e.is_invalid_state();
    let condition = e.condition();
    let not_lazy = e.take_not_lazy();
    let transfer = e.take_transfer();
    let (status, cause, message) = e.finish(kind);
    if let Some((image, layers)) = not_lazy {
        let layers = layers
            .into_iter()
            .map(|l| NotLazyLayer {
                index: l.index,
                digest: l.digest,
                media_type: l.media_type,
                reason: l.reason,
            })
            .collect();
        return EngineError::ImageNotLazy {
            cause,
            message,
            image,
            layers,
        };
    }
    if let Some((party, object, transient)) = transfer {
        return match condition {
            Some(Condition::InvalidContent) => EngineError::InvalidContent {
                cause,
                message,
                party,
                object,
            },
            _ => EngineError::SourceUnavailable {
                cause,
                message,
                party,
                transient,
            },
        };
    }
    match condition {
        Some(c) => EngineError::of(c, cause, message),
        None => named(status.as_u16(), state, shown, cause, message),
    }
}

/// The condition the status of an operation (chosen for podman's API, as
/// the operations still are) names, about an object of `kind`; a 409 is
/// of the state of the object with `state`, else of a name that is taken.
fn named(status: u16, state: bool, kind: ErrorKind, cause: String, message: String) -> EngineError {
    let missing = match kind {
        ErrorKind::Container => Condition::NoSuchContainer,
        ErrorKind::Image => Condition::NoSuchImage,
        ErrorKind::Pod => Condition::NoSuchPod,
        ErrorKind::Network => Condition::NoSuchNetwork,
        ErrorKind::Volume => Condition::NoSuchVolume,
        ErrorKind::Secret => Condition::NoSuchSecret,
        ErrorKind::Exec => Condition::NoSuchExecSession,
        ErrorKind::Artifact | ErrorKind::None => Condition::NoSuchObject,
    };
    EngineError::from_status(status, state, missing, cause, message)
}

/// The error of an operation of the command line about an object of
/// `kind`, by the name of its condition.
fn op_error(kind: ErrorKind, e: crate::api::ops::Error) -> EngineError {
    match e.condition {
        Some(c) => EngineError::of(c, String::new(), e.message),
        None => named(e.status.as_u16(), e.state, kind, String::new(), e.message),
    }
}

fn filters_of(filters: Vec<Filter>) -> Result<Filters, EngineError> {
    if filters.len() > MAX_FILTERS {
        return Err(EngineError::invalid(format!(
            "at most {MAX_FILTERS} filters in a call"
        )));
    }
    Ok(Filters(
        filters.into_iter().map(|f| (f.key, f.values)).collect(),
    ))
}

/// The reply of a secret: its data, when it has it, as a sealed memory file
/// that goes with the reply.
fn secret_reply(mut secret: SecretRecord) -> Result<(SecretInspected, Vec<OwnedFd>), EngineError> {
    let Some(data) = secret.data.take() else {
        return Ok((SecretInspected { secret, data: None }, Vec::new()));
    };
    let data = zeroize::Zeroizing::new(data);
    let file = velarx_base::sealed::sealed_memory(&data)
        .map_err(|e| EngineError::failed(format!("cannot pass the data of the secret: {e}")))?;
    Ok((
        SecretInspected {
            secret,
            data: Some(0),
        },
        vec![file],
    ))
}

/// The reply that carries `values`: inline when small, else the content of
/// a pipe (the read end goes with the reply, the engine fills the other end
/// from the runtime and closes it, so the reader sees the end of the
/// document).
pub fn documents(values: Vec<Value>) -> Result<(Documents, Vec<OwnedFd>), EngineError> {
    let failed =
        |e: &dyn std::fmt::Display| EngineError::failed(format!("cannot encode the document: {e}"));
    let bytes = serde_json::to_vec(&values).map_err(|e| failed(&e))?;
    if bytes.len() <= INLINE_MAX {
        return Ok((
            Documents {
                inline: Some(values),
                fd: None,
                length: bytes.len() as u64,
            },
            Vec::new(),
        ));
    }
    let (read, write) =
        rustix::pipe::pipe_with(rustix::pipe::PipeFlags::CLOEXEC).map_err(|e| failed(&e))?;
    // (the whole document in the pipe when the system lets it: the writer
    // does not wait for the reader)
    let _ = rustix::pipe::fcntl_setpipe_size(&write, 1 << 20);
    let length = bytes.len() as u64;
    fill_pipe(write, bytes).map_err(|e| failed(&e))?;
    Ok((
        Documents {
            inline: None,
            fd: Some(0),
            length,
        },
        vec![read],
    ))
}

/// The reply that carries `value`: inline when small, else the content of a
/// pipe, as [`documents`].
pub fn document(value: Value) -> Result<(Document, Vec<OwnedFd>), EngineError> {
    let failed =
        |e: &dyn std::fmt::Display| EngineError::failed(format!("cannot encode the document: {e}"));
    let bytes = serde_json::to_vec(&value).map_err(|e| failed(&e))?;
    if bytes.len() <= INLINE_MAX {
        return Ok((
            Document {
                inline: Some(value),
                fd: None,
            },
            Vec::new(),
        ));
    }
    let (read, write) =
        rustix::pipe::pipe_with(rustix::pipe::PipeFlags::CLOEXEC).map_err(|e| failed(&e))?;
    let _ = rustix::pipe::fcntl_setpipe_size(&write, 1 << 20);
    fill_pipe(write, bytes).map_err(|e| failed(&e))?;
    Ok((
        Document {
            inline: None,
            fd: Some(0),
        },
        vec![read],
    ))
}

/// The reply that carries the JSON `bytes`: inline when small, else the
/// content of a pipe, as [`document`].
fn document_of_bytes(bytes: Vec<u8>) -> Result<(Document, Vec<OwnedFd>), EngineError> {
    let failed =
        |e: &dyn std::fmt::Display| EngineError::failed(format!("cannot encode the document: {e}"));
    if bytes.len() <= INLINE_MAX {
        let value = serde_json::from_slice(&bytes).map_err(|e| failed(&e))?;
        return Ok((
            Document {
                inline: Some(value),
                fd: None,
            },
            Vec::new(),
        ));
    }
    let (read, write) =
        rustix::pipe::pipe_with(rustix::pipe::PipeFlags::CLOEXEC).map_err(|e| failed(&e))?;
    let _ = rustix::pipe::fcntl_setpipe_size(&write, 1 << 20);
    fill_pipe(write, bytes).map_err(|e| failed(&e))?;
    Ok((
        Document {
            inline: None,
            fd: Some(0),
        },
        vec![read],
    ))
}

/// How long a client may stop reading a document from its pipe: the engine
/// holds the whole document in memory until it is written, so one that stops
/// reading would pin it for ever.  It is the time without progress, not the
/// time of the whole document: a slow reader that reads gets all of it.
const DOCUMENT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

/// Write `bytes` to the pipe `write` from a task, and close it; when the
/// reader takes nothing for [`DOCUMENT_TIMEOUT`] the document is dropped (the
/// reader sees the pipe end before its length).
fn fill_pipe(write: OwnedFd, bytes: Vec<u8>) -> io::Result<()> {
    fill_pipe_within(write, bytes, DOCUMENT_TIMEOUT)
}

fn fill_pipe_within(write: OwnedFd, bytes: Vec<u8>, stall: std::time::Duration) -> io::Result<()> {
    use tokio::io::AsyncWriteExt;
    let mut sender = tokio::net::unix::pipe::Sender::from_owned_fd(write)?;
    tokio::spawn(async move {
        // (a reader that went away or does not read is not a failure of the
        // engine)
        let mut rest = &bytes[..];
        while !rest.is_empty() {
            match tokio::time::timeout(stall, sender.write(rest)).await {
                Ok(Ok(n)) => rest = &rest[n..],
                Ok(Err(e)) => {
                    debug!("a document was not read to the end: {e}");
                    return;
                }
                Err(_) => {
                    debug!("a document was not read for {stall:?}: dropped");
                    return;
                }
            }
        }
    });
    Ok(())
}

mod service {
    #![allow(missing_docs)]
    use super::*;

    #[zlink::service(
        interface = "org.velarx.Engine",
        description = |_| velarx_proto::interfaces::engine(),
        vendor = "org.velarx",
        product = "velarx",
        version = env!("CARGO_PKG_VERSION"),
        url = env!("CARGO_PKG_REPOSITORY"),
        types = [
            Filter, RemovedContainer, LeaseRange, NetworkRoute, NetworkSpec, NetworkDriver, NetworkSubnet, NetworkMember, NetworkRecord, SecretRecord, LogOptions, PodLogOptions, PodLogLine, LogStream, ImagePlatform, InstanceSpec, ManifestArtifactSpec, ManifestDescriptor, ManifestInstance, ArtifactRecord,
            AttachOptions, SessionPhase, SessionOpened, SessionStreams, SessionReply, CheckpointFlags, CriuStatistics, PodResources, PodDeviceLimit, RestoreFlags, FileChange, SearchHit, PlatformSpec, PullSpec, NotLazyLayer, PushSpec, CommitSpec, ImportSpec, ArtifactAddSpec, Retry, SystemdSpec, UpdateSpec, UpdateDevice, UpdateBlockIo, UpdateHealth, Compression, PodAction, DeviceSpec, Resources, HugepageLimit, MountKind, ContainerMount, HealthStatus, HealthResult, Health, StartupHealthcheck, Healthcheck, OnFailure, CheckpointState, ProcessConfig, ProcessUser, Ulimit, HostSettings, DeviceLimit, ContainerPort, ContainerInterface, ContainerNetwork, ContainerPaths, ContainerRecord, RunState, PodStatus, PodMember, DeviceNode, PodRecord, PodSpec, PodExitPolicy, PodDnsConfig, PodSecurityContext, PodPortMapping, IdMapping, RestartPolicy, ImageConfigRecord, ImageHealthcheck, ImageHistoryEntry, ComposefsLayer, ImageRecord, PrunedImage, ImageTreeLayer, ImageTreeChild, ImageTreeRecord, PulledImage, BySource, TransferStats, PushedTag, PushedImage, Placed, PullState, NotLazy, StatsRecord, InterfaceStats, Pressure, Psi, PsiData, ExecSpec, ExecRecord, MetricDescriptor, MetricSample, ContainerMetrics, PodUsage, PodMetrics, TransferProgress, EventRecord, WaitCondition, VolumeSpec, VolumeRecord, ChangeKind, DiffType, CgroupManager, PullPolicy, ManifestFormat, LayerCompression, TransferStatus, EventKind, VersionRecord, HostTool, RuntimePath, OciRuntimeRecord, SystemdRecord, SubnetPool, CpuUtilization, HostRecord, StoreRecord, SystemRecord, ImageUsage, ContainerUsage, VolumeUsage, StoreUsage, DiskUsageRecord, PrunedVolume, SystemPruneReport, CheckSpec, CheckAction, CheckProblem, CheckRemovedContainer, CheckReport, GcReport, ServiceStore, StoresReport, ComponentStatus, ComponentHealth, BuildSpec, BuildEvent, BuildEventKind, BuildStream, BuildClient, BuildPair, BuildEntitlement, BuildPull, BuildSecretKind, BuildSecretSpec, BuildContextKind, BuildContextSpec, BuildOutputKind, BuildOutput, BuildFlags, SbomFlags, req::BuildRun, req::CreateContainerRequest, req::SecurityOptions, req::ResourceLimits, req::HugepageLimit, req::WeightDevice, req::ThrottleDevice, req::PortMapping, req::Ulimit, req::LogConfig, req::DeviceMapping, req::MountConfig, req::BindMountRequest, req::ImageMountRequest, req::OverlayMountConfig, req::ImageMountConfig, req::SecretRef, req::DeviceNumbers, req::DeviceRule, req::Owner
        ]
    )]
    impl Engine {
        /// The engine lives while the other end of the socket this call
        /// carries is open (an engine a frontend started, with no service
        /// manager, is held by the other frontends that use it).
        /// The call carries one descriptor, the end of a connected unix
        /// socket whose other end the frontend keeps.
        async fn hold(&self, #[zlink(fds)] lifeline: Vec<OwnedFd>) -> Result<Ack, EngineError> {
            let bad = |reason: &str| EngineError::invalid(reason.into());
            let Ok([fd]) = <[OwnedFd; 1]>::try_from(lifeline) else {
                return Err(bad("a hold is one descriptor, a socket"));
            };
            let _guard = self.runtime.enter();
            self.holds.watch(fd).map_err(|why| match why {
                NoHold::Stopping => EngineError::Unavailable {
                    cause: velarx_proto::engine::STOPPING.into(),
                    message: why.to_string(),
                },
                _ => bad(&format!("the hold: {why}")),
            })?;
            Ok(Ack {})
        }

        /// Who the engine is.
        async fn get_info(&self) -> Result<InfoReply, EngineError> {
            Ok(InfoReply {
                name: "velarx".into(),
                version: env!("CARGO_PKG_VERSION").into(),
                interface: PROTO,
                digest: DIGEST.into(),
                rootful: velarx_base::ids::rootful()
                    .map_err(|e| EngineError::failed(e.to_string()))?,
            })
        }

        /// Start again from the binary installed when it is not the one
        /// that runs (an upgrade replaced it): the containers, the holds
        /// and the socket go on, the connections end.  The reply says whether
        /// it restarts.  A
        /// frontend of another version calls it when `GetInfo` is not its
        /// own, then connects again; called without arguments it has this
        /// meaning in every version of the engine, as `GetInfo` has.  With
        /// `running` the binary that runs starts again whatever is
        /// installed, and reads its configuration again (`velarx system
        /// restart`, as `SIGHUP`).
        async fn restart(&self, running: Option<bool>) -> Restarted {
            // (counted: the shutdown waits for its reply like for any call)
            let _counted = self.calls.count_always();
            if running == Some(true) {
                self.restart_now(false).await;
                return Restarted { restarted: true };
            }
            let restarted = installed_binary().is_some();
            if restarted {
                self.restart_now(true).await;
            }
            Restarted { restarted }
        }

        /// The health of the engine and of its parts (its database, its
        /// storage, its runtime).
        async fn health(&self) -> Result<HealthReport, EngineError> {
            self.run(|state| async move { state.server_service.health().await })
                .await
        }

        /// Nothing: the engine answers.
        async fn ping(&self) -> Ack {
            Ack {}
        }

        /// The container is there.
        async fn container_exists(&self, name: String) -> Result<Ack, EngineError> {
            self.api(ErrorKind::Container, |state| async move {
                podman::lifecycle_resolve(&state, &name)
                    .await
                    .map(|_| Ack {})
            })
            .await
        }

        /// Ready to start, not started; `changed` is false for one that
        /// is initialized or runs already.
        async fn container_init(&self, name: String) -> Result<Changed, EngineError> {
            self.api(ErrorKind::Container, |state| async move {
                podman::container_init(&state, &name)
                    .await
                    .map(|changed| Changed { changed })
            })
            .await
        }

        /// Start a container; `changed` is false for one that runs
        /// already.
        async fn container_start(
            &self,
            name: String,
            verify_image: Vec<String>,
            service: Option<bool>,
            run: Option<bool>,
        ) -> Result<Changed, EngineError> {
            let check = start_check(verify_image, service, run)?;
            self.api(ErrorKind::Container, |state| async move {
                podman::container_start(&state, &name, &check)
                    .await
                    .map(|changed| Changed { changed })
            })
            .await
        }

        /// Start a container with its monitor waiting for the client to
        /// attach (`run`, `start --attach`): `changed` is false for one that
        /// runs already.
        async fn container_start_attached(
            &self,
            name: String,
            verify_image: Vec<String>,
            service: Option<bool>,
            run: Option<bool>,
        ) -> Result<StartedAttached, EngineError> {
            let check = start_check(verify_image, service, run)?;
            self.api(ErrorKind::Container, |state| async move {
                podman::container_start_attached(&state, &name, &check)
                    .await
                    .map(|(id, _, changed)| StartedAttached { id, changed })
            })
            .await
        }

        /// Stop a container; `changed` is false for one that does not
        /// run, `warning` is podman's when the stop signal did not stop it
        /// in time.  `service`: a stop of the service manager (a shutdown),
        /// not of a user, so that an `unless-stopped` container starts
        /// again at the next boot.
        async fn container_stop(
            &self,
            name: String,
            timeout: Option<u64>,
            ignore: bool,
            service: Option<bool>,
        ) -> Result<Stopped, EngineError> {
            self.api(ErrorKind::Container, |state| async move {
                podman::container_stop(&state, &name, timeout, ignore, service.unwrap_or(false))
                    .await
                    .map(|(changed, warning)| Stopped { changed, warning })
            })
            .await
        }

        /// Send a signal to a container.
        async fn container_kill(
            &self,
            name: String,
            signal: Option<String>,
        ) -> Result<Ack, EngineError> {
            self.api(ErrorKind::Container, |state| async move {
                podman::container_kill(&state, &name, signal.as_deref())
                    .await
                    .map(|_| Ack {})
            })
            .await
        }

        /// Stop and start a container.
        async fn container_restart(
            &self,
            name: String,
            timeout: Option<u64>,
            verify_image: Vec<String>,
        ) -> Result<Ack, EngineError> {
            let check = start_check(verify_image, None, None)?;
            self.api(ErrorKind::Container, |state| async move {
                podman::container_restart(&state, &name, timeout, &check)
                    .await
                    .map(|_| Ack {})
            })
            .await
        }

        /// Pause a container, or unpause it.  With `lease` (seconds) a pause
        /// ends by itself when nobody unpaused the container by then: the
        /// engine stays up until it does.
        async fn container_pause(
            &self,
            name: String,
            pause: bool,
            lease: Option<u64>,
        ) -> Result<Ack, EngineError> {
            let leases = self.leases.clone();
            let busy = lease.and(self.holds.busy());
            self.api(ErrorKind::Container, |state| async move {
                // (a lease is the container's, whatever name the calls use:
                // a later unpause by ID ends it, and it never ends the pause
                // of another container that took the name)
                let Some(secs) = lease.filter(|_| pause) else {
                    let id = podman::lifecycle_resolve(&state, &name).await?.id;
                    let done = podman::container_pause(&state, &id, pause).await;
                    // (the pause is not the lease's now, or never was)
                    leases.cancel(&id);
                    done?;
                    return Ok(Ack {});
                };
                let after = std::time::Duration::from_secs(secs);
                let until =
                    now_ms().saturating_add(i64::try_from(after.as_millis()).unwrap_or(i64::MAX));
                let id = podman::container_pause_leased(&state, &name, until).await?;
                leases.arm_pause(&state, id, until, after, true, busy);
                Ok(Ack {})
            })
            .await
        }

        /// Rename a container.
        async fn container_rename(
            &self,
            name: String,
            new_name: String,
        ) -> Result<Ack, EngineError> {
            self.api(ErrorKind::Container, |state| async move {
                podman::container_rename(&state, &name, &new_name)
                    .await
                    .map(|_| Ack {})
            })
            .await
        }

        /// Remove a container, and those that depend on it with `depend`;
        /// a running one with `force`, stopped with its stop signal and
        /// `timeout` seconds to obey it before the kill (none: its own).
        /// `warnings`: podman's, of the stops the kill was needed for.
        async fn container_remove(
            &self,
            name: String,
            force: bool,
            volumes: bool,
            ignore: bool,
            depend: bool,
            timeout: Option<u64>,
        ) -> Result<Removed, EngineError> {
            let leases = self.leases.clone();
            self.api(ErrorKind::Container, |state| async move {
                let opts = podman::RemoveOptions {
                    force,
                    volumes,
                    ignore,
                    depend,
                    timeout,
                };
                let (removed, warnings) = podman::container_remove(&state, &name, &opts).await?;
                // (a removed container's lease, and the engine's hold for
                // it, go with it)
                for (id, _) in &removed {
                    leases.cancel(id);
                }
                Ok(Removed {
                    removed: removed
                        .into_iter()
                        .map(|(id, named)| RemovedContainer { id, named })
                        .collect(),
                    warnings,
                })
            })
            .await
        }

        /// Wait until a container meets one of `conditions` (none: its
        /// exit): the exit code and the condition met.  With `more`, a first
        /// reply without them says the wait is armed: an exit after it is
        /// not missed.  The wait ends when the client closes the connection.
        #[zlink(more)]
        async fn container_wait(
            &self,
            more: bool,
            name: String,
            conditions: Vec<WaitCondition>,
            interval_ns: i64,
        ) -> impl futures::Stream<Item = Result<zlink::Reply<Waited>, EngineError>> + Unpin
        {
            let failed = |e| -> Replies<Waited> {
                Box::pin(futures::stream::once(std::future::ready(Err(e))))
            };
            if conditions.len() > WaitCondition::ALL.len() {
                return failed(EngineError::invalid(format!(
                    "at most {} conditions in a wait",
                    WaitCondition::ALL.len()
                )));
            }
            let (tx, rx) = tokio::sync::mpsc::channel(2);
            let state = self.state.clone();
            let busy = self.holds.busy();
            self.runtime.spawn(async move {
                let _busy = busy;
                let armed = tx.clone();
                let wait = crate::api::ops::wait::wait(
                    &state,
                    &name,
                    &conditions,
                    interval_ns,
                    move || {
                        if more {
                            let _ = armed.try_send(Ok(Waited::default()));
                        }
                    },
                );
                // (the client that closes the connection drops the replies,
                // and ends the wait and its subscriptions)
                let reply = tokio::select! {
                    met = wait => met
                        .map(|m| Waited {
                            status_code: Some(i64::from(m.code)),
                            condition: Some(m.condition),
                        })
                        .map_err(|e| api_error(e, ErrorKind::Container)),
                    () = tx.closed() => return,
                };
                let _ = tx.send(reply).await;
            });
            Box::pin(futures::stream::unfold(rx, |mut rx| async move {
                let item = rx.recv().await?;
                let armed = matches!(&item, Ok(w) if w.status_code.is_none());
                let reply = item.map(|w| zlink::Reply::new(Some(w)).set_continues(Some(armed)));
                Some((reply, rx))
            }))
        }

        /// The image is there.
        async fn image_exists(&self, name: String) -> Result<Ack, EngineError> {
            self.api(ErrorKind::Image, |state| async move {
                podman::image_exists(&state, &name).await.map(|_| Ack {})
            })
            .await
        }

        /// Give an image a name.
        async fn image_tag(
            &self,
            name: String,
            repo: String,
            tag: String,
            docker_hub: bool,
        ) -> Result<Ack, EngineError> {
            self.api(ErrorKind::Image, |state| async move {
                podman::image_tag(&state, !docker_hub, &name, &repo, &tag)
                    .await
                    .map(|_| Ack {})
            })
            .await
        }

        /// Take names (or every name) from an image.
        async fn image_untag(&self, name: String, names: Vec<String>) -> Result<Ack, EngineError> {
            self.api(ErrorKind::Image, |state| async move {
                podman::images::untag_of(&state, &name, &names)
                    .await
                    .map(|_| Ack {})
            })
            .await
        }

        /// Remove an image: with `force` the containers that use it go too,
        /// but those that run with `spare_running` (the image is then
        /// refused); `noprune`: its parents stay; `manifest_list`: the name
        /// is a manifest list's, which goes.
        async fn image_remove(
            &self,
            name: String,
            force: bool,
            spare_running: bool,
            noprune: bool,
            ignore: bool,
            manifest_list: bool,
        ) -> Result<ImageRemoved, EngineError> {
            self.api(ErrorKind::Image, |state| async move {
                let opts = podman::ImageRemoveOptions {
                    force,
                    spare_running,
                    noprune,
                    ignore,
                    manifest_list,
                };
                podman::image_remove(&state, &name, &opts).await.map(
                    |(untagged, deleted, warnings)| ImageRemoved {
                        untagged,
                        deleted,
                        warnings,
                    },
                )
            })
            .await
        }

        /// Remove the unused images (all, else the dangling ones; with
        /// `all` the manifest lists too) that the filters select: what was
        /// removed, one a reply.
        #[zlink(more)]
        async fn image_prune(
            &self,
            more: bool,
            all: bool,
            filters: Vec<Filter>,
        ) -> impl futures::Stream<Item = Result<zlink::Reply<ImagePruneListed>, EngineError>> + Unpin
        {
            let pruned = match filters_of(filters) {
                Ok(filters) => {
                    let filters: Vec<String> = filters
                        .0
                        .iter()
                        .flat_map(|(k, vs)| vs.iter().map(move |v| format!("{k}={v}")))
                        .collect();
                    self.api(ErrorKind::Image, |state| async move {
                        podman::images::prune_of(&state, all, &filters).await
                    })
                    .await
                }
                Err(e) => Err(e),
            };
            list_replies(more, "ImagePrune", pruned, |image| ImagePruneListed {
                image,
            })
        }

        /// Remove the directories of RUN --mount=type=cache no build step
        /// uses: the bytes they took.
        async fn build_cache_prune(&self) -> Result<Reclaimed, EngineError> {
            self.api(ErrorKind::Image, |state| async move {
                podman::images::prune_build_cache_of(&state).await
            })
            .await
            .map(|space| Reclaimed { space })
        }

        /// Create a network; with `ignore_if_exists`, one of the name asked
        /// for is the answer (`changed` false).
        async fn network_create(
            &self,
            spec: NetworkSpec,
            ignore_if_exists: bool,
        ) -> Result<NetworkCreated, EngineError> {
            self.api(ErrorKind::Network, |state| async move {
                podman::networks::create_of(&state, &spec, ignore_if_exists).await
            })
            .await
            .map(|(changed, network)| NetworkCreated { changed, network })
        }

        /// A network, by name, id or unique prefix of an id (`podman` and
        /// `bridge` are the network of the configuration).
        async fn network_inspect(&self, name: String) -> Result<NetworkInspected, EngineError> {
            self.api(ErrorKind::Network, |state| async move {
                podman::networks::inspect_of(&state, &name).await
            })
            .await
            .map(|network| NetworkInspected { network })
        }

        /// The networks the filters select (podman's filters of `network
        /// ls`), one a reply.
        #[zlink(more)]
        async fn network_list(
            &self,
            more: bool,
            filters: Vec<Filter>,
        ) -> impl futures::Stream<Item = Result<zlink::Reply<NetworkListed>, EngineError>> + Unpin
        {
            let listed = match filters_of(filters) {
                Ok(filters) => {
                    self.api(ErrorKind::Network, |state| async move {
                        podman::networks::list_of(&state, &filters).await
                    })
                    .await
                }
                Err(e) => Err(e),
            };
            list_replies(more, "NetworkList", listed, |network| NetworkListed {
                network,
            })
        }

        /// The network is there.
        async fn network_exists(&self, name: String) -> Result<Ack, EngineError> {
            self.api(ErrorKind::Network, |state| async move {
                podman::networks::exists_of(&state, &name)
                    .await
                    .map(|_| Ack {})
            })
            .await
        }

        /// Remove a network; with `force` the containers that use it go
        /// first, stopped with `timeout` seconds (none: their own).
        /// `warnings`: podman's, of the stops the kill was needed for.
        async fn network_remove(
            &self,
            name: String,
            force: bool,
            timeout: Option<u64>,
        ) -> Result<NetworkRemoved, EngineError> {
            self.api(ErrorKind::Network, |state| async move {
                podman::networks::remove_of(&state, &name, force, timeout)
                    .await
                    .map(|(name, warnings)| NetworkRemoved { name, warnings })
            })
            .await
        }

        /// Remove the networks no container uses that the filters select
        /// (podman's filters of `network prune`): their names.
        async fn network_prune(&self, filters: Vec<Filter>) -> Result<Pruned, EngineError> {
            let filters = filters_of(filters)?;
            self.api(ErrorKind::Network, |state| async move {
                podman::networks::prune_of(&state, &filters).await
            })
            .await
            .map(|removed| Pruned { removed })
        }

        /// Change the DNS servers of a network.
        async fn network_update(
            &self,
            name: String,
            add_dns_servers: Vec<String>,
            remove_dns_servers: Vec<String>,
        ) -> Result<Ack, EngineError> {
            self.api(ErrorKind::Network, |state| async move {
                podman::networks::update_of(&state, &name, &add_dns_servers, &remove_dns_servers)
                    .await
                    .map(|_| Ack {})
            })
            .await
        }

        /// Connect a container to a network.
        async fn network_connect(
            &self,
            name: String,
            container: String,
            ip: Option<String>,
            ip6: Option<String>,
            mac: Option<String>,
            aliases: Vec<String>,
        ) -> Result<Ack, EngineError> {
            self.api(ErrorKind::Network, |state| async move {
                podman::networks::connect_of(&state, &name, &container, ip, ip6, mac, &aliases)
                    .await
                    .map(|_| Ack {})
            })
            .await
        }

        /// Apply the firewall rules of the networks of a running container
        /// again.
        async fn network_reload(
            &self,
            container: String,
            if_configured: bool,
        ) -> Result<Id, EngineError> {
            self.api(ErrorKind::Container, |state| async move {
                podman::networks::reload_of(&state, &container, if_configured)
                    .await
                    .map(|id| Id { id })
            })
            .await
        }

        /// Disconnect a container from a network.
        async fn network_disconnect(
            &self,
            name: String,
            container: String,
            force: bool,
        ) -> Result<Ack, EngineError> {
            self.api(ErrorKind::Network, |state| async move {
                podman::networks::disconnect_of(&state, &name, &container, force)
                    .await
                    .map(|_| Ack {})
            })
            .await
        }

        /// Create a volume; with `ignore_if_exists`, one of the name asked
        /// for is the answer.
        async fn volume_create(
            &self,
            spec: VolumeSpec,
            ignore_if_exists: bool,
        ) -> Result<VolumeInspected, EngineError> {
            self.api(ErrorKind::Volume, |state| async move {
                podman::volumes::create_of(&state, &spec, ignore_if_exists).await
            })
            .await
            .map(|volume| VolumeInspected { volume })
        }

        /// The volumes the filters select (podman's filters of `volume ls`),
        /// one a reply.
        #[zlink(more)]
        async fn volume_list(
            &self,
            more: bool,
            filters: Vec<Filter>,
        ) -> impl futures::Stream<Item = Result<zlink::Reply<VolumeListed>, EngineError>> + Unpin
        {
            let listed = match filters_of(filters) {
                Ok(filters) => {
                    self.api(ErrorKind::Volume, |state| async move {
                        podman::volumes::list_of(&state, &filters).await
                    })
                    .await
                }
                Err(e) => Err(e),
            };
            list_replies(more, "VolumeList", listed, |volume| VolumeListed { volume })
        }

        /// A volume.
        async fn volume_inspect(&self, name: String) -> Result<VolumeInspected, EngineError> {
            self.api(ErrorKind::Volume, |state| async move {
                podman::volumes::inspect_of(&state, &name).await
            })
            .await
            .map(|volume| VolumeInspected { volume })
        }

        /// The volume is there.
        async fn volume_exists(&self, name: String) -> Result<Ack, EngineError> {
            self.api(ErrorKind::Volume, |state| async move {
                podman::volumes::exists_of(&state, &name)
                    .await
                    .map(|_| Ack {})
            })
            .await
        }

        /// Give a volume another name.
        async fn volume_rename(&self, name: String, new_name: String) -> Result<Ack, EngineError> {
            self.api(ErrorKind::Volume, |state| async move {
                podman::volumes::rename_of(&state, &name, &new_name)
                    .await
                    .map(|_| Ack {})
            })
            .await
        }

        /// Remove a volume; with `force` the containers that use it go
        /// first, given `timeout` seconds to stop (none: their own).
        /// `warnings`: podman's, of the stops the kill was needed for.
        async fn volume_remove(
            &self,
            name: String,
            force: bool,
            timeout: Option<u64>,
        ) -> Result<VolumeRemoved, EngineError> {
            self.api(ErrorKind::Volume, |state| async move {
                podman::volumes::remove_of(&state, &name, force, timeout)
                    .await
                    .map(|warnings| VolumeRemoved { warnings })
            })
            .await
        }

        /// Remove the volumes no container uses that the filters select
        /// (podman's filters of `volume prune`): their names and the bytes
        /// they had.  With `dry_run`, only those: nothing is removed.
        async fn volume_prune(
            &self,
            filters: Vec<Filter>,
            dry_run: bool,
        ) -> Result<VolumesPruned, EngineError> {
            let filters = filters_of(filters)?;
            self.api(ErrorKind::Volume, |state| async move {
                podman::volumes::prune_of(&state, &filters, dry_run).await
            })
            .await
            .map(|removed| VolumesPruned {
                removed: removed
                    .into_iter()
                    .map(|(name, size)| PrunedVolume {
                        name,
                        size: size.max(0) as u64,
                    })
                    .collect(),
            })
        }

        /// Mount what the options of a volume ask for (a device, a file
        /// system): where its content is.
        async fn volume_mount(&self, name: String) -> Result<Mounted, EngineError> {
            self.api(ErrorKind::Volume, |state| async move {
                podman::volumes::mount_of(&state, &name).await
            })
            .await
            .map(|path| Mounted { path })
        }

        /// Unmount what `VolumeMount` mounted.
        async fn volume_unmount(&self, name: String) -> Result<Ack, EngineError> {
            self.api(ErrorKind::Volume, |state| async move {
                podman::volumes::unmount_of(&state, &name).await
            })
            .await
            .map(|()| Ack {})
        }

        /// Create a secret.
        #[allow(
            clippy::too_many_arguments,
            reason = "one parameter for each field of the varlink call"
        )]
        /// The data of the secret (at most 512,000 bytes) is one descriptor, the sealed
        /// memory file `data` names.
        async fn secret_create(
            &self,
            name: String,
            driver: Option<String>,
            driver_opts: BTreeMap<String, String>,
            labels: BTreeMap<String, String>,
            replace: bool,
            ignore: bool,
            data: u32,
            #[zlink(fds)] fds: Vec<OwnedFd>,
        ) -> Result<Id, EngineError> {
            let data = secret_data(fds, data)?;
            let opts = velarx_core::services::CreateSecretOptions {
                driver,
                driver_opts: map_of(driver_opts)?,
                labels: map_of(labels)?,
                replace,
                ignore,
            };
            self.api(ErrorKind::Secret, |state| async move {
                podman::secrets::create_of(&state, &name, opts, &data)
                    .await
                    .map(|id| Id { id })
            })
            .await
        }

        /// The secrets the filters select (podman's filters of `secret
        /// ls`), one a reply.
        #[zlink(more)]
        async fn secret_list(
            &self,
            more: bool,
            filters: Vec<Filter>,
        ) -> impl futures::Stream<Item = Result<zlink::Reply<SecretListed>, EngineError>> + Unpin
        {
            let listed = match filters_of(filters) {
                Ok(filters) => {
                    self.api(ErrorKind::Secret, |state| async move {
                        podman::secrets::list_of(&state, &filters).await
                    })
                    .await
                }
                Err(e) => Err(e),
            };
            list_replies(more, "SecretList", listed, |secret| SecretListed { secret })
        }

        /// A secret.  With `show_data`, its data is the sealed memory file
        /// `data` names among the descriptors of the reply: it never crosses
        /// in the JSON of the reply.
        #[zlink(return_fds)]
        async fn secret_inspect(
            &self,
            name: String,
            show_data: bool,
        ) -> (Result<SecretInspected, EngineError>, Vec<OwnedFd>) {
            let shown = self
                .api(ErrorKind::Secret, |state| async move {
                    podman::secrets::inspect_of(&state, &name, show_data).await
                })
                .await;
            with_fds(shown.and_then(secret_reply))
        }

        /// The secret is there.
        async fn secret_exists(&self, name: String) -> Result<Ack, EngineError> {
            self.api(ErrorKind::Secret, |state| async move {
                podman::secrets::exists_of(&state, &name)
                    .await
                    .map(|_| Ack {})
            })
            .await
        }

        /// Remove a secret, or every secret.
        async fn secret_remove(&self, name: String, all: bool) -> Result<Ack, EngineError> {
            self.api(ErrorKind::Secret, |state| async move {
                if all {
                    podman::secrets::remove_all_of(&state).await
                } else {
                    podman::secrets::remove_of(&state, &name).await
                }
                .map(|_| Ack {})
            })
            .await
        }

        /// Create a pod: its id.
        /// The call carries one descriptor, the read end of a pipe that
        /// `spec` names: the `PodSpec` as JSON, read to its end (at most 1 MiB).
        async fn pod_create(
            &self,
            spec: u32,
            #[zlink(fds)] fds: Vec<OwnedFd>,
        ) -> Result<Id, EngineError> {
            let spec = document_of(fds, spec, MAX_POD_SPEC, "a pod spec").await?;
            let spec = velarx_core::services::PodSpec::from_document(&spec)
                // (podman's words of a spec it refuses, as they are)
                .map_err(EngineError::invalid)?;
            self.api(ErrorKind::Pod, |state| async move {
                podman::pods::create_spec(&state, spec)
                    .await
                    .map(|id| Id { id })
            })
            .await
        }

        /// The pod is there.
        async fn pod_exists(&self, name: String) -> Result<Ack, EngineError> {
            self.api(ErrorKind::Pod, |state| async move {
                podman::pods::exists_of(&state, &name).await.map(|_| Ack {})
            })
            .await
        }

        /// Replace the limits of the cgroup of a pod.
        async fn pod_update(
            &self,
            name: String,
            resources: PodResources,
        ) -> Result<Id, EngineError> {
            self.api(ErrorKind::Pod, |state| async move {
                podman::pods::update_of(&state, &name, resources)
                    .await
                    .map(|id| Id { id })
            })
            .await
        }

        /// Start, stop, kill, pause, unpause or restart a pod.
        async fn pod_run(
            &self,
            name: String,
            op: PodAction,
            timeout: Option<u64>,
            signal: Option<String>,
            verify_image: Vec<String>,
            service: Option<bool>,
        ) -> Result<PodRan, EngineError> {
            // (a start of the service manager has no command line: the
            // engine goes by the records)
            let verify = match start_check(verify_image, service, None)? {
                velarx_core::services::StartCheck::User { digests, .. } => Some(digests),
                _ => None,
            };
            self.api(ErrorKind::Pod, |state| async move {
                podman::pods::run_named(&state, &name, op, timeout, signal.as_deref(), verify)
                    .await
                    .map(|ran| match ran {
                        Some((id, errors)) => PodRan {
                            changed: true,
                            id,
                            errors,
                        },
                        None => PodRan {
                            changed: false,
                            id: String::new(),
                            errors: Vec::new(),
                        },
                    })
            })
            .await
        }

        /// Remove a pod and its containers; with `force` the running ones
        /// stop with `timeout` seconds (none: their own).  `warnings`:
        /// podman's, of the stops the kill was needed for.
        async fn pod_remove(
            &self,
            name: String,
            force: bool,
            timeout: Option<u64>,
        ) -> Result<PodRemoved, EngineError> {
            self.api(ErrorKind::Pod, |state| async move {
                podman::pods::remove_named(&state, &name, force, timeout)
                    .await
                    .map(|(id, removed, warnings)| PodRemoved {
                        id,
                        removed,
                        warnings,
                    })
            })
            .await
        }

        /// The processes of the containers of a pod that run, as `ps` shows
        /// them with `ps_args`: podman's descriptors (`pid`, `user`,
        /// `args`...; none: podman's default ones), or the arguments of ps.
        async fn pod_top(
            &self,
            name: String,
            ps_args: Vec<String>,
        ) -> Result<Processes, EngineError> {
            bounded(&ps_args)?;
            self.api(ErrorKind::Pod, |state| async move {
                podman::pods::processes_of(&state, &name, &ps_args)
                    .await
                    .map(|top| Processes {
                        titles: top.titles,
                        processes: top.processes,
                    })
            })
            .await
        }

        /// Remove the pods none of whose containers runs: their ids.
        async fn pod_prune(&self) -> Result<Pruned, EngineError> {
            self.api(ErrorKind::Pod, |state| async move {
                podman::pods::prune_of(&state).await
            })
            .await
            .map(|removed| Pruned { removed })
        }

        /// The manifest list is there.
        async fn manifest_exists(&self, name: String) -> Result<Ack, EngineError> {
            self.api(ErrorKind::Image, |state| async move {
                podman::manifests::exists_of(&state, &name)
                    .await
                    .map(|_| Ack {})
            })
            .await
        }

        /// Remove a manifest list (its instances stay): its id and names.
        async fn manifest_remove(&self, name: String) -> Result<ManifestRemoved, EngineError> {
            self.api(ErrorKind::Image, |state| async move {
                podman::manifests::remove_of(&state, &name).await
            })
            .await
        }

        /// The artifacts of the store, one a reply.
        #[zlink(more)]
        async fn artifact_list(
            &self,
            more: bool,
        ) -> impl futures::Stream<Item = Result<zlink::Reply<ArtifactListed>, EngineError>> + Unpin
        {
            let listed = self
                .api(ErrorKind::Artifact, |state| async move {
                    podman::artifacts::list_of(&state).await
                })
                .await;
            list_replies(more, "ArtifactList", listed, |artifact| ArtifactListed {
                artifact,
            })
        }

        /// An artifact of the store.
        async fn artifact_inspect(&self, name: String) -> Result<ArtifactInspected, EngineError> {
            self.api(ErrorKind::Artifact, |state| async move {
                podman::artifacts::inspect_of(&state, &name).await
            })
            .await
            .map(|artifact| ArtifactInspected { artifact })
        }

        /// Remove an artifact: its digest.
        async fn artifact_remove(&self, name: String) -> Result<Id, EngineError> {
            self.api(ErrorKind::Artifact, |state| async move {
                podman::artifacts::remove_one(&state, name)
                    .await
                    .map(|id| Id { id })
            })
            .await
        }

        /// The logs of a container: the lines `opts` selects (neither
        /// stream: both), then those that follow.
        /// The reply carries the read end of a pipe (descriptor 0): the
        /// multiplexed frames of the log (one byte for the stream, three
        /// zero bytes, the length, the data); `tty` says the container has
        /// a terminal.
        #[zlink(return_fds)]
        async fn container_logs(
            &self,
            name: String,
            opts: LogOptions,
        ) -> (Result<Stream, EngineError>, Vec<OwnedFd>) {
            let q = podman::containers::LogsQuery {
                stdout: opts.stdout,
                stderr: opts.stderr,
                follow: opts.follow,
                timestamps: opts.timestamps,
                tail: opts.tail,
                since_ns: opts.since_ns,
                until_ns: opts.until_ns,
            };
            let prepared = self
                .api(ErrorKind::Container, |state| async move {
                    podman::containers::logs_of(&state, &name, q).await
                })
                .await
                .and_then(|run| {
                    let tty = run.tty;
                    self.open_stream(tty, move |w| run.run(w, true))
                });
            with_fds(prepared)
        }

        /// The logs of the containers of a pod (`opts.containers`: those
        /// named, else all, the infra container first), merged by time, one
        /// line a reply and a last reply without one.  A follow is
        /// answered first with a reply without a line once the engine took
        /// it, and goes on until the containers have exited and their logs
        /// were read, or the client closes the connection.
        #[zlink(more)]
        async fn pod_logs(
            &self,
            more: bool,
            name: String,
            opts: PodLogOptions,
        ) -> impl futures::Stream<Item = Result<zlink::Reply<PodLogListed>, EngineError>> + Unpin
        {
            use futures::StreamExt;
            let failed = |e| -> Replies<PodLogListed> {
                Box::pin(futures::stream::once(std::future::ready(Err(e))))
            };
            if !more {
                return failed(EngineError::InvalidArgument {
                    cause: "expected more".into(),
                    message: "PodLogs answers one line a reply: call it with more".into(),
                });
            }
            if opts.containers.len() > MAX_PAIRS {
                return failed(EngineError::invalid(format!(
                    "at most {MAX_PAIRS} containers in a call"
                )));
            }
            let follow = opts.follow;
            let state = self.state.clone();
            let q = crate::api::ops::pod::LogsQuery {
                since_ns: opts.since_ns,
                until_ns: opts.until_ns,
                tail: opts.tail.and_then(|n| u64::try_from(n).ok()),
                containers: opts.containers,
            };
            let (tx, rx) = tokio::sync::mpsc::channel(64);
            let kept: Result<(), EngineError> = if follow {
                match crate::api::ops::pod::follow_logs(&state, &name, &q).await {
                    Ok(lines) => {
                        // (the task ends when the client goes: the stream is
                        // dropped, and with it the receiver)
                        let busy = self.holds.busy();
                        self.runtime.spawn(async move {
                            let _busy = busy;
                            let mut lines = Box::pin(lines);
                            loop {
                                let next = tokio::select! {
                                    next = lines.next() => next,
                                    () = tx.closed() => break,
                                };
                                let Some(entry) = next else { break };
                                if tx.send(pod_log_line(entry)).await.is_err() {
                                    break;
                                }
                            }
                        });
                        Ok(())
                    }
                    Err(e) => Err(op_error(ErrorKind::Pod, e)),
                }
            } else {
                match crate::api::ops::pod::logs(&state, &name, &q).await {
                    Ok(entries) => {
                        self.runtime.spawn(async move {
                            for entry in entries {
                                if tx.send(pod_log_line(entry)).await.is_err() {
                                    break;
                                }
                            }
                        });
                        Ok(())
                    }
                    Err(e) => Err(op_error(ErrorKind::Pod, e)),
                }
            };
            if let Err(e) = kept {
                return failed(e);
            }
            let reply = |line: Option<PodLogLine>,
                         continues: bool|
             -> Result<zlink::Reply<PodLogListed>, EngineError> {
                Ok(zlink::Reply::new(Some(PodLogListed { line })).set_continues(Some(continues)))
            };
            let taken = futures::stream::iter(follow.then(|| reply(None, true)));
            let lines = futures::stream::unfold(rx, move |mut rx| async move {
                let line = rx.recv().await?;
                Some((reply(Some(line), true), rx))
            });
            let end = futures::stream::once(std::future::ready(reply(None, false)));
            Box::pin(taken.chain(lines).chain(end))
        }

        /// The events, one a reply: those of `filters`
        /// (`container`, `pod`, `image`, `volume`, `network`, `type`,
        /// `event`, `label`), from `since_ns` (none: from now) to `until_ns`
        /// (none: for ever) when `follow`, else those kept, and the last
        /// reply without one.  A follow is answered first with a reply
        /// without an event once the engine took it: the events after that
        /// reply are sent.  A follow ends when the client closes the
        /// connection.
        #[zlink(more)]
        async fn event_list(
            &self,
            more: bool,
            filters: Vec<Filter>,
            since_ns: Option<i64>,
            until_ns: Option<i64>,
            follow: bool,
        ) -> impl futures::Stream<Item = Result<zlink::Reply<EventListed>, EngineError>> + Unpin
        {
            use futures::StreamExt;
            let failed = |e| -> Replies<EventListed> {
                Box::pin(futures::stream::once(std::future::ready(Err(e))))
            };
            if !more {
                return failed(EngineError::InvalidArgument {
                    cause: "expected more".into(),
                    message: "Events answers one event a reply: call it with more".into(),
                });
            }
            if self.in_process && self.state.config.server.effective_events_logger() == "none" {
                return failed(EngineError::InvalidArgument {
                    cause: "events".into(),
                    message: "cannot read events with the \"none\" backend".into(),
                });
            }
            let filters = match filters_of(filters) {
                Ok(f) => f,
                Err(e) => return failed(e),
            };
            let q = podman::events::EventsQuery {
                filters,
                stream: follow,
                follow_kept: self.in_process,
            };
            let prepared = self
                .api(ErrorKind::None, |state| async move {
                    podman::events::events_of(&state, q, since_ns, until_ns).await
                })
                .await;
            let run = match prepared {
                Ok(run) => run,
                Err(e) => return failed(e),
            };
            let (tx, rx) = tokio::sync::mpsc::channel(64);
            // (a follow that cannot read the events kept any more ends with
            // the error, after the events it sent)
            let (fail, failed_with) = tokio::sync::oneshot::channel();
            // (the task ends when the client goes: the stream is dropped,
            // and with it the receiver)
            self.runtime.spawn(async move {
                if let Err(e) = run.deliver(EventRecords(tx)).await {
                    let _ = fail.send(e);
                }
            });
            let reply = |event: Option<EventRecord>,
                         continues: bool|
             -> Result<zlink::Reply<EventListed>, EngineError> {
                Ok(zlink::Reply::new(Some(EventListed { event })).set_continues(Some(continues)))
            };
            // a follow is answered at once without an event: the call was
            // taken, what happens after it is sent
            let taken = futures::stream::iter(follow.then(|| reply(None, true)));
            let events = futures::stream::unfold(rx, move |mut rx| async move {
                let event = rx.recv().await?;
                Some((reply(Some(event), true), rx))
            });
            let end = futures::stream::once(async move {
                match failed_with.await {
                    Ok(e) => Err(api_error(e, ErrorKind::None)),
                    Err(_) => reply(None, false),
                }
            });
            Box::pin(taken.chain(events).chain(end))
        }

        /// Resize the terminal of an exec session: `height` and `width` in
        /// characters; `running`: only once the command runs.
        async fn exec_resize(
            &self,
            id: String,
            height: i64,
            width: i64,
            running: bool,
        ) -> Result<Ack, EngineError> {
            self.api(ErrorKind::Exec, |state| async move {
                podman::exec::resize_of(&state, &id, height, width, running)
                    .await
                    .map(|()| Ack {})
            })
            .await
        }

        /// Remove an exec session; `force`: also one whose command runs.
        async fn exec_remove(&self, id: String, force: bool) -> Result<Ack, EngineError> {
            self.api(ErrorKind::Exec, |state| async move {
                podman::exec::remove_of(&state, &id, force).map(|()| Ack {})
            })
            .await
        }

        /// Send the signal `signal` (a name or a number) to the command of an
        /// exec session.
        async fn exec_kill(&self, id: String, signal: String) -> Result<Ack, EngineError> {
            self.api(ErrorKind::Exec, |state| async move {
                podman::exec::kill_of(&state, &id, &signal).map(|()| Ack {})
            })
            .await
        }

        /// Attach to a container, called with `more` (see `SessionReply`):
        /// the replies carry descriptors, the streams of the process; with
        /// `opts.logs` the first one carries the pipe of the log so far,
        /// which the client is sent first.
        #[zlink(more, return_fds)]
        async fn container_attach(
            &self,
            more: bool,
            name: String,
            opts: AttachOptions,
        ) -> impl futures::Stream<
            Item = (
                Result<zlink::Reply<SessionReply>, EngineError>,
                Vec<OwnedFd>,
            ),
        > + Unpin {
            if !more {
                return session_failed(EngineError::invalid(
                    "an attach answers more than once: call it with more".into(),
                ));
            }
            let q = podman::containers::AttachQuery {
                stdout: opts.stdout,
                stderr: opts.stderr,
                logs: opts.logs,
                stream: opts.stream,
                stdin: opts.stdin,
                detach_keys: opts.detach_keys,
                stdin_once: opts.stdin_once,
                stdin_keep_open: opts.stdin_keep_open,
                start: opts.start,
                size: opts
                    .height
                    .zip(opts.width)
                    .map(|(h, w)| (h.clamp(0, 65535) as u16, w.clamp(0, 65535) as u16))
                    .filter(|(h, w)| *h > 0 && *w > 0),
            };
            let planned = self
                .api(ErrorKind::Container, |state| async move {
                    podman::containers::attach_of(&state, &name, q).await
                })
                .await;
            match planned {
                Ok(plan) => {
                    let opened = plan.opened();
                    self.open_session(opened, move |out, log, busy| plan.drive(out, log, busy))
                }
                Err(e) => session_failed(e),
            }
        }

        /// The input of the session `session` ends once what the client
        /// wrote is read: the process's input is closed.  Called on a
        /// connection of its own; answered once the monitor was told.
        async fn session_close_stdin(&self, session: String) -> Result<Ack, EngineError> {
            self.sessions
                .tell(&session, velarx_proto::stream::Control::CloseStdin)
                .await
                .map(|()| Ack {})
        }

        /// The client of the session `session` typed the detach keys: the
        /// session goes on without it.  Answered once the monitor was told.
        async fn session_detach(&self, session: String) -> Result<Ack, EngineError> {
            self.sessions
                .tell(&session, velarx_proto::stream::Control::Detach)
                .await
                .map(|()| Ack {})
        }

        /// Resize the terminal of a container: `height` and `width` in
        /// characters.
        async fn container_resize(
            &self,
            name: String,
            height: i64,
            width: i64,
        ) -> Result<Ack, EngineError> {
            self.api(ErrorKind::Container, |state| async move {
                podman::containers::resize_of(&state, &name, height, width)
                    .await
                    .map(|()| Ack {})
            })
            .await
        }

        /// Build an image from the spec the descriptor `spec` names (the read end
        /// of a pipe) holds, read to its end.  `context`: the build context, the descriptor the
        /// client opened: a pipe, a tar in frames (with `sections`, the
        /// sections of a multipart body: the main context and the named
        /// ones), or a directory, which the build
        /// reads in place, through the descriptor (nothing is copied: COPY and
        /// ADD, the digests their steps are cached under, the Containerfile and
        /// the ignore files are looked up below it, no link followed out of it;
        /// a file that changes meanwhile is read as it is when a step reads it).
        /// A source of `RUN --mount` from it, and the context an SBOM scanner
        /// mounts, is a copy that the confined worker makes for the step (the
        /// kernel does not clone a mount of the client's mount namespace for the
        /// runtime); a directory carries no `sections`, agent or input;
        /// absent, the spec says where it is: `remote`, or `local_dir`, a
        /// directory of the host of the engine (podman's local route), which
        /// the engine opens as its own user.  After the pipes the call names come the socket of the
        /// broker of the ssh agents when the spec names agents, and the
        /// standard input of the client when the spec has `stdin`; the
        /// credentials are the sealed memory file `access` names.
        /// The reply carries the read end of a pipe: the progress, a
        /// `BuildEvent` each line.
        #[zlink(return_fds)]
        async fn image_build(
            &self,
            spec: u32,
            context: Option<u32>,
            sections: bool,
            access: Option<u32>,
            #[zlink(fds)] pipes: Vec<OwnedFd>,
        ) -> (Result<Stream, EngineError>, Vec<OwnedFd>) {
            with_fds(
                async {
                    let refused = |m: &str| EngineError::invalid(m.into());
                    let mut named = Descriptors::new(pipes);
                    let spec = named.take("the spec", spec).map_err(invalid_fds)?;
                    let context = named
                        .take_opt("the context", context)
                        .map_err(invalid_fds)?;
                    let access = registry_access_in(&mut named, access)?;
                    let spec = build_spec(spec).await?;
                    let mut pipes = named.rest().into_iter();
                    let broker = if spec.ssh.is_empty() {
                        None
                    } else {
                        let fd = pipes.next().ok_or_else(|| {
                            refused("a build with ssh agents carries the socket of their broker")
                        })?;
                        Some(fd)
                    };
                    let stdin = if spec.stdin {
                        let fd = pipes.next().ok_or_else(|| {
                            refused("a build with --stdin carries the standard input")
                        })?;
                        Some(fd)
                    } else {
                        None
                    };
                    if pipes.next().is_some() {
                        return Err(refused("a build carries no pipe but those of its call"));
                    }
                    if spec.stdin && spec.client != velarx_proto::buildspec::BuildClient::Cli {
                        return Err(refused(
                            "only the command line gives its standard input to a build",
                        ));
                    }
                    if sections && context.is_none() {
                        return Err(refused("sections are the content of a context"));
                    }
                    // A directory of the host: no context is sent.
                    if spec.local_dir.is_some() || spec.containerfile_host.is_some() {
                        if context.is_some() || broker.is_some() || stdin.is_some() {
                            return Err(refused(
                                "a build of a directory of the host carries no context, agent or input",
                            ));
                        }
                        let run = self
                            .api(ErrorKind::Image, |state| async move {
                                podman::build::local_build_of(&state, spec, access).await
                            })
                            .await?;
                        return self.open_stream(false, move |w| run.run(JsonLines::new(w)));
                    }
                    // A directory the client opened: the engine reads what
                    // the descriptor is, no path.
                    let context = match context {
                        Some(fd) if is_directory(&fd).map_err(|e| EngineError::failed(format!("the build context: {e}")))? => {
                            if sections {
                                return Err(refused("sections are the content of a stream, not a directory"));
                            }
                            if broker.is_some() || stdin.is_some() {
                                return Err(refused(
                                    "a build of a directory carries no agent or input",
                                ));
                            }
                            let run = self
                                .api(ErrorKind::Image, |state| async move {
                                    podman::build::dir_build_of(&state, spec, access, fd).await
                                })
                                .await?;
                            return self.open_stream(false, move |w| run.run(JsonLines::new(w)));
                        }
                        other => other,
                    };
                    let source = match context {
                        Some(fd) => match tokio::net::unix::pipe::Receiver::from_owned_fd(fd) {
                            Ok(r) => podman::build::PipeSource(Some(r)),
                            Err(e) => {
                                return Err(EngineError::failed(format!("the build context: {e}")));
                            }
                        },
                        None => podman::build::PipeSource(None),
                    };
                    if spec.client == velarx_proto::buildspec::BuildClient::Cli {
                        return Box::pin(self.cli_build(spec, access, source, broker, stdin)).await;
                    }
                    let run = self
                        .api(ErrorKind::Image, |state| async move {
                            Box::pin(podman::build::build_of(
                                &state, spec, access, source, sections,
                            ))
                            .await
                        })
                        .await?;
                    self.open_stream(false, move |w| run.run(JsonLines::new(w)))
                }
                .await,
            )
        }

        /// Answer the question of a build for credentials (its event
        /// `credentials` with this `ask`).  `answer` names one descriptor, the sealed memory
        /// file with the answer (JSON: the credentials by `REGISTRY` or
        /// `REGISTRY/REPOSITORY`).
        /// `NoSuchObject` when no build waits for that answer (it was
        /// answered, or the build ended).
        async fn image_build_answer(
            &self,
            ask: String,
            answer: u32,
            #[zlink(fds)] fds: Vec<OwnedFd>,
        ) -> Result<Ack, EngineError> {
            let mut fds = Descriptors::new(fds);
            let bytes = take_sealed(&mut fds, Some(answer), MAX_BUILD_ANSWER, "the answer")?
                .unwrap_or_default();
            fds.finish().map_err(invalid_fds)?;
            // (not serde's words: they quote what they could not read)
            let answer = serde_json::from_slice(&bytes).map_err(|_| {
                EngineError::invalid("the answer is not the credentials by registry".into())
            })?;
            if self.state.build_asks.answer(&ask, answer) {
                Ok(Ack {})
            } else {
                Err(EngineError::NoSuchObject {
                    cause: String::new(),
                    message: "no build asks for credentials".into(),
                })
            }
        }

        /// The build cache nothing uses is removed: the ids of the images
        /// and the bytes freed.
        async fn build_prune(&self) -> Result<BuildPruned, EngineError> {
            self.api(ErrorKind::None, |state| async move {
                podman::build::build_prune_of(&state).await
            })
            .await
        }

        /// Open the log file of a container again.
        async fn container_log_reopen(&self, name: String) -> Result<Ack, EngineError> {
            self.api(ErrorKind::Container, |state| async move {
                podman::containers::log_reopen_of(&state, &name).await
            })
            .await
            .map(|()| Ack {})
        }

        /// A connection to a port of the loopback of a container or a pod.
        /// The reply carries one descriptor, the connected socket.
        #[zlink(return_fds)]
        async fn port_connect(
            &self,
            pod: bool,
            name: String,
            port: u16,
        ) -> (Result<Ack, EngineError>, Vec<OwnedFd>) {
            let kind = if pod {
                ErrorKind::Pod
            } else {
                ErrorKind::Container
            };
            let connected = self
                .api(kind, |state| async move {
                    podman::connect_port(&state, kind, &name, port).await
                })
                .await;
            with_fds(connected.map(|fd| (Ack {}, vec![fd])))
        }

        /// The build of the engine and the kernel it runs on (what
        /// `SystemInspect` says of it, without the rest).
        async fn version_inspect(&self) -> Result<VersionInspected, EngineError> {
            self.run_fut(async move {
                VersionInspected {
                    version: podman::system::version_record().await,
                }
            })
            .await
        }

        /// What the engine is and what it runs on: its build, its host
        /// (the CPUs, the memory, the cgroups, the runtimes, the tools it
        /// uses) and its store.
        async fn system_inspect(&self) -> Result<SystemInspected, EngineError> {
            self.api(ErrorKind::None, |state| async move {
                podman::system::system_record(&state).await
            })
            .await
            .map(|system| SystemInspected { system })
        }

        /// What the images, the containers and the volumes use of the
        /// disk; with `store`, the files of the store too (the objects and
        /// what a collection would free of them now, the composefs
        /// images).
        async fn disk_usage_inspect(&self, store: bool) -> Result<DiskUsageInspected, EngineError> {
            self.api(ErrorKind::None, |state| async move {
                podman::system::disk_usage(&state, store).await
            })
            .await
            .map(|usage| DiskUsageInspected { usage })
        }

        /// Remove what is not in use (`system prune`): the pods
        /// that do not run, the containers that do not run (`build`: the
        /// containers of builds that are gone too), the networks no
        /// container uses, the volumes with `volumes`, the dangling images
        /// (all those no container uses with `all`), as the filters
        /// (`label`, `label!`, `until`) select; then the garbage of the
        /// store is collected.
        async fn system_prune(
            &self,
            all: bool,
            volumes: bool,
            build: bool,
            filters: Vec<Filter>,
        ) -> Result<SystemPruned, EngineError> {
            let filters = filters_of(filters)?;
            self.api(ErrorKind::None, |state| async move {
                podman::system::prune_of(&state, all, volumes, build, &filters).await
            })
            .await
            .map(|report| SystemPruned { report })
        }

        /// Check the store, and repair it as `spec` asks (podman's `system
        /// check`).
        async fn system_check(&self, spec: CheckSpec) -> Result<SystemChecked, EngineError> {
            self.api(ErrorKind::None, |state| async move {
                podman::system::check_of(&state, &spec).await
            })
            .await
            .map(|report| SystemChecked { report })
        }

        /// Collect the garbage of the store: the files (`files`) and the
        /// layers (`layers`) no image and no container uses, the leftovers
        /// of pulls that are gone; with `dry_run`, only what would go.
        async fn system_collect(
            &self,
            dry_run: bool,
            files: bool,
            layers: bool,
        ) -> Result<Collected, EngineError> {
            self.api(ErrorKind::None, |state| async move {
                podman::system::collect_of(&state, dry_run, files, layers).await
            })
            .await
            .map(|report| Collected { report })
        }

        /// The stores the storage service holds for the engine's user, with
        /// `drop` one of them dropped first (not the engine's own).
        async fn system_stores(&self, drop: Option<String>) -> Result<StoresListed, EngineError> {
            self.api(ErrorKind::None, |state| async move {
                podman::system::stores_of(&state, drop.as_deref()).await
            })
            .await
            .map(|report| StoresListed { report })
        }

        /// Log in to a registry.  The credentials are one descriptor, the
        /// sealed memory file `access` names.
        async fn registry_login(
            &self,
            host: String,
            access: Option<u32>,
            #[zlink(fds)] fds: Vec<OwnedFd>,
        ) -> Result<LoginReply, EngineError> {
            let access = registry_access_of(fds, access)?;
            self.run(|state| async move {
                let failure = podman::registry_login(&state, &host, &access).await.err();
                LoginReply {
                    unauthorized: failure
                        .as_ref()
                        .is_some_and(velarx_types::ImageError::is_refusal),
                    failure: failure
                        .as_ref()
                        .map(velarx_content::pull::net::origin::failure_text),
                }
            })
            .await
        }

        /// The descriptors of the metrics of pods, one a reply.
        #[zlink(more)]
        async fn metric_descriptor_list(
            &self,
            more: bool,
        ) -> impl futures::Stream<Item = Result<zlink::Reply<MetricDescriptorListed>, EngineError>> + Unpin
        {
            let listed = Ok(podman::metric_descriptors());
            list_replies(more, "MetricDescriptorList", listed, |descriptor| {
                MetricDescriptorListed { descriptor }
            })
        }

        /// The metrics of the pods that run (of `name` only, with a name),
        /// one pod a reply.
        #[zlink(more)]
        async fn pod_metrics_list(
            &self,
            more: bool,
            name: Option<String>,
        ) -> impl futures::Stream<Item = Result<zlink::Reply<PodMetricsListed>, EngineError>> + Unpin
        {
            let listed = self
                .api(ErrorKind::Pod, |state| async move {
                    podman::pods_metrics(&state, name.as_deref()).await
                })
                .await;
            list_replies(more, "PodMetricsList", listed, |pod| PodMetricsListed {
                pod,
            })
        }

        /// What the registry has for a name, without pulling it.
        async fn image_remote_inspect(
            &self,
            name: String,
            tls_verify: bool,
        ) -> Result<RemoteImage, EngineError> {
            self.api_cancelled(ErrorKind::Image, |state| async move {
                podman::image_distribution(&state, &name, tls_verify).await
            })
            .await
        }

        /// Who the engine is for the CRI: its version and the runtimes it has.
        async fn runtime_inspect(&self) -> Result<RuntimeInfo, EngineError> {
            self.api(ErrorKind::None, |state| async move {
                podman::workload::runtime_info(&state).await
            })
            .await
        }

        /// Create a container (the one creation record of the command line
        /// and the CRI): its id.
        /// The call carries one descriptor, the read end of a pipe that
        /// `spec` names: the request as JSON, read to its end (at most 4 MiB).
        async fn container_create(
            &self,
            spec: u32,
            #[zlink(fds)] fds: Vec<OwnedFd>,
        ) -> Result<Id, EngineError> {
            let request = document_of(fds, spec, MAX_CONTAINER_SPEC, "a container request").await?;
            let request: velarx_proto::request::CreateContainerRequest =
                serde_json::from_slice(&request)
                    .map_err(|e| EngineError::invalid(format!("a container request: {e}")))?;
            self.api(ErrorKind::Container, |state| async move {
                crate::api::ops::container::create(&state, request)
                    .await
                    .map(|id| Id { id })
                    .map_err(|e| match e.no_such {
                        // (the CRI tells a missing image from a container)
                        Some(kind) => ApiError::no_such(kind, e.message),
                        None => match e.condition {
                            Some(c) => {
                                ApiError::new(e.status.as_u16(), e.message).with_condition(c)
                            }
                            None => ApiError::new(e.status.as_u16(), e.message),
                        },
                    })
            })
            .await
        }

        /// Create a container as another was made: the request of the
        /// original again, under `new_name` (`NAME-clone` without), with
        /// `image` and `pod` when given.  Its id.
        async fn container_clone(
            &self,
            name: String,
            new_name: Option<String>,
            image: Option<String>,
            pod: Option<String>,
        ) -> Result<Id, EngineError> {
            self.api(ErrorKind::Container, |state| async move {
                crate::api::ops::container::clone(&state, &name, new_name, image, pod)
                    .await
                    .map(|id| Id { id })
                    .map_err(|e| ApiError::new(e.status.as_u16(), e.message))
            })
            .await
        }

        /// A container; with `size`, the size of its changes, and of them
        /// and its image.
        async fn container_inspect(
            &self,
            name: String,
            size: bool,
        ) -> Result<ContainerInspected, EngineError> {
            self.api(ErrorKind::Container, |state| async move {
                podman::containers::inspect_of(&state, &name, size).await
            })
            .await
            .map(|container| ContainerInspected { container })
        }

        /// The OCI configuration of a container (its `config.json`), once it
        /// is created.
        /// The document is in `inline`, or when it is large the content of the
        /// pipe the reply carries (descriptor `fd`, `length` bytes of JSON).
        #[zlink(return_fds)]
        async fn container_runtime_spec(
            &self,
            name: String,
        ) -> (Result<Document, EngineError>, Vec<OwnedFd>) {
            let spec = self
                .api(ErrorKind::Container, |state| async move {
                    podman::workload::runtime_spec(&state, &name).await
                })
                .await
                .and_then(|spec| document_of_bytes(spec.into_bytes()));
            with_fds(spec)
        }

        /// The containers the filters (podman's of `ps`) select, the infra
        /// containers of the pods too, the newest first, one a reply: those
        /// that run, all with `all`, the `limit` newest (-1: all); with
        /// `size` the size of their changes, with `namespace` the
        /// namespaces of their processes.
        #[zlink(more)]
        async fn container_list(
            &self,
            more: bool,
            filters: Vec<Filter>,
            all: bool,
            size: bool,
            namespace: bool,
            limit: i64,
        ) -> impl futures::Stream<Item = Result<zlink::Reply<ContainerListed>, EngineError>> + Unpin
        {
            let listed = match filters_of(filters) {
                Ok(filters) => {
                    self.api(ErrorKind::Container, |state| async move {
                        let q = ContainerListQuery {
                            all,
                            size,
                            namespace,
                            limit,
                            filters,
                        };
                        podman::container_list(&state, q).await
                    })
                    .await
                }
                Err(e) => Err(e),
            };
            list_replies(more, "ContainerList", listed, |container| ContainerListed {
                container,
            })
        }

        /// A pod, with what its infra container says of its network.
        async fn pod_inspect(&self, name: String) -> Result<PodInspected, EngineError> {
            self.api(ErrorKind::Pod, |state| async move {
                podman::pods::inspect_of(&state, &name).await
            })
            .await
            .map(|pod| PodInspected { pod })
        }

        /// The pods the filters select (podman's filters of `pod ps`), one
        /// a reply.
        #[zlink(more)]
        async fn pod_list(
            &self,
            more: bool,
            filters: Vec<Filter>,
        ) -> impl futures::Stream<Item = Result<zlink::Reply<PodListed>, EngineError>> + Unpin
        {
            let listed = match filters_of(filters) {
                Ok(filters) => {
                    self.api(ErrorKind::Pod, |state| async move {
                        podman::pods::list_of(&state, &filters).await
                    })
                    .await
                }
                Err(e) => Err(e),
            };
            list_replies(more, "PodList", listed, |pod| PodListed { pod })
        }

        /// An image.
        async fn image_inspect(&self, name: String) -> Result<ImageInspected, EngineError> {
            self.api(ErrorKind::Image, |state| async move {
                podman::images::inspect_of(&state, &name).await
            })
            .await
            .map(|image| ImageInspected { image })
        }

        /// The images the filters select (podman's filters of `images`),
        /// the oldest first, one a reply: with `all` the intermediate images
        /// of the builds too, with `manifest_lists` the manifest lists too.
        #[zlink(more)]
        async fn image_list(
            &self,
            more: bool,
            filters: Vec<Filter>,
            all: bool,
            manifest_lists: bool,
        ) -> impl futures::Stream<Item = Result<zlink::Reply<ImageListed>, EngineError>> + Unpin
        {
            let listed = match filters_of(filters) {
                Ok(filters) => {
                    self.api(ErrorKind::Image, |state| async move {
                        podman::images::list_of(&state, &filters, all, manifest_lists).await
                    })
                    .await
                }
                Err(e) => Err(e),
            };
            list_replies(more, "ImageList", listed, |image| ImageListed { image })
        }

        /// The steps of the history of an image, the newest first, one a
        /// reply.
        #[zlink(more)]
        async fn image_history(
            &self,
            more: bool,
            name: String,
        ) -> impl futures::Stream<Item = Result<zlink::Reply<ImageHistoryListed>, EngineError>> + Unpin
        {
            let listed = self
                .api(ErrorKind::Image, |state| async move {
                    podman::images::history_of(&state, &name).await
                })
                .await;
            list_replies(more, "ImageHistory", listed, |entry| ImageHistoryListed {
                entry,
            })
        }

        /// Pull an image.  With more: the progress, one a reply, then what
        /// was pulled (the last reply); without, what was pulled once it is
        /// in the store.  The pull stops when the client closes the
        /// connection.
        /// The credentials are one descriptor, the sealed memory file `access` names.
        #[zlink(more)]
        async fn image_pull(
            &self,
            more: bool,
            spec: PullSpec,
            access: Option<u32>,
            #[zlink(fds)] fds: Vec<OwnedFd>,
        ) -> impl futures::Stream<Item = Result<zlink::Reply<Pulled>, EngineError>> + Unpin
        {
            use futures::StreamExt;
            let opened = (|| {
                let mut fds = Descriptors::new(fds);
                let access = registry_access_in(&mut fds, access)?;
                let target = match spec.source_fd {
                    None => None,
                    Some(at) => {
                        let fd = fds.take("the source", at).map_err(invalid_fds)?;
                        Some(self.pull_target(fd)?)
                    }
                };
                fds.finish().map_err(invalid_fds)?;
                Ok::<_, EngineError>((access, target))
            })();
            let (access, target) = match opened {
                Ok(a) => a,
                Err(e) => {
                    let failed: Replies<Pulled> =
                        Box::pin(futures::stream::once(async move { Err(e) }));
                    return failed;
                }
            };
            let (tx, rx) = tokio::sync::mpsc::channel(64);
            let pulled = self.api_cancelled(ErrorKind::Image, move |state| async move {
                let p = &spec.platform;
                let args = podman::images::pull::PullArgs {
                    source: spec.source,
                    target,
                    artifact: spec.artifact,
                    docker_hub: spec.docker_hub,
                    policy: spec.policy,
                    all_tags: spec.all_tags,
                    retry: spec.retry,
                    platform: podman::images::pull::platform_of(
                        p.platform.as_deref(),
                        p.os.as_deref(),
                        p.arch.as_deref(),
                        p.variant.as_deref(),
                    ),
                    tls_verify: spec.tls_verify,
                    lazy: spec.lazy,
                    access,
                    sources: spec.sources,
                };
                podman::images::pull::pull_images(&state, args, tx).await
            });
            let progress = futures::stream::unfold(rx, |mut rx| async move {
                let p = rx.recv().await?;
                let reply = Pulled {
                    progress: Some(podman::images::pull::progress_record(p)),
                    id: None,
                    images: None,
                    stats: None,
                    present: None,
                };
                Some((
                    Ok(zlink::Reply::new(Some(reply)).set_continues(Some(true))),
                    rx,
                ))
            })
            .filter(move |_| std::future::ready(more));
            let end = futures::stream::once(async move {
                pulled.await.map(|done| {
                    zlink::Reply::new(Some(Pulled {
                        progress: None,
                        id: done.images.last().map(|i| i.id.clone()),
                        images: Some(done.images),
                        stats: done.stats,
                        present: Some(done.present),
                    }))
                    .set_continues(Some(false))
                })
            });
            let replies: Replies<Pulled> = Box::pin(progress.chain(end));
            replies
        }

        /// Samples of what the containers `names` use (none: those that
        /// run; with `all` all of them, those that do not run with zeros;
        /// a container named that does not run has zeros), a container a
        /// reply and a reply without one at the end of a sample; `size`:
        /// with what they wrote.  With `stream` another sample follows
        /// every `interval_ms` milliseconds (5 seconds if absent), its CPU
        /// use since the one before, until the client closes the
        /// connection (or the containers named are gone).
        #[zlink(more)]
        async fn container_stats(
            &self,
            more: bool,
            names: Vec<String>,
            all: bool,
            size: bool,
            stream: bool,
            interval_ms: Option<u64>,
        ) -> impl futures::Stream<Item = Result<zlink::Reply<StatsListed>, EngineError>> + Unpin
        {
            let failed = |e| -> Replies<StatsListed> {
                Box::pin(futures::stream::once(std::future::ready(Err(e))))
            };
            if !more {
                return failed(EngineError::InvalidArgument {
                    cause: "expected more".into(),
                    message: "ContainerStats answers a container a reply: call it with more".into(),
                });
            }
            if let Err(e) = bounded(&names) {
                return failed(e);
            }
            let mut sampler = podman::stats::Sampler::new(&self.state, names, all, size);
            let sampled = self
                .api_fut(ErrorKind::Container, async move {
                    let first = sampler.sample().await?;
                    Ok((first, sampler))
                })
                .await;
            let (first, mut sampler) = match sampled {
                Ok(sampled) => sampled,
                Err(e) => return failed(e),
            };
            let reply = |stats: Option<StatsRecord>,
                         continues: bool|
             -> Result<zlink::Reply<StatsListed>, EngineError> {
                Ok(zlink::Reply::new(Some(StatsListed { stats })).set_continues(Some(continues)))
            };
            let sample = move |records: Vec<StatsRecord>, more: bool| {
                records
                    .into_iter()
                    .map(move |s| reply(Some(s), true))
                    .chain(std::iter::once(reply(None, more)))
            };
            if !stream {
                return Box::pin(futures::stream::iter(sample(first, false)));
            }
            let every = std::time::Duration::from_millis(interval_ms.unwrap_or(5000).max(1));
            let (tx, rx) = tokio::sync::mpsc::channel(64);
            // (the task ends when the client goes: the stream is dropped,
            // and with it the receiver)
            self.runtime.spawn(async move {
                let mut records = first;
                loop {
                    for r in sample(records, true) {
                        if tx.send(r).await.is_err() {
                            return;
                        }
                    }
                    tokio::select! {
                        () = tokio::time::sleep(every) => {}
                        () = tx.closed() => return,
                    }
                    records = match sampler.sample().await {
                        Ok(r) => r,
                        // (the containers named are gone)
                        Err(_) => break,
                    };
                }
                let _ = tx.send(reply(None, false)).await;
            });
            Box::pin(futures::stream::unfold(rx, |mut rx| async move {
                rx.recv().await.map(|r| (r, rx))
            }))
        }

        /// Create an exec session in the container `name`: its id.
        async fn exec_create(&self, name: String, spec: ExecSpec) -> Result<Id, EngineError> {
            self.api(ErrorKind::Container, |state| async move {
                podman::exec::create_of(&state, &name, &spec)
                    .await
                    .map(|id| Id { id })
            })
            .await
        }

        /// Start an exec session, called with `more` (see `SessionReply`;
        /// the replies carry descriptors, the streams of the command),
        /// whose only reply is the last one with `detach` (the command runs
        /// on its own); with `input` the client can send the input of the
        /// command; `height` and `width` (characters, 0: not known) are the
        /// size of the terminal.  The call carries `preserved`, descriptors
        /// the command gets as 3, 4, ..., but in the slots of
        /// `preserve_holes` (slot 0 is 3), where it gets none (a `/dev/null`
        /// stands in).
        #[allow(
            clippy::too_many_arguments,
            reason = "one parameter for each field of the varlink call"
        )]
        #[zlink(more, return_fds)]
        async fn exec_start(
            &self,
            more: bool,
            #[zlink(fds)] preserved: Vec<OwnedFd>,
            id: String,
            input: bool,
            detach: bool,
            height: i64,
            width: i64,
            preserve_holes: Vec<u32>,
        ) -> impl futures::Stream<
            Item = (
                Result<zlink::Reply<SessionReply>, EngineError>,
                Vec<OwnedFd>,
            ),
        > + Unpin {
            if !more {
                return session_failed(EngineError::invalid(
                    "an exec session answers more than once: call it with more".into(),
                ));
            }
            let started = self
                .api(ErrorKind::Exec, |state| async move {
                    podman::exec::start_of(
                        &state,
                        &id,
                        detach,
                        (height, width),
                        preserved,
                        preserve_holes,
                    )
                    .await
                })
                .await;
            self.exec_streams(started, input)
        }

        /// An exec session.
        async fn exec_inspect(&self, id: String) -> Result<ExecInspected, EngineError> {
            self.api(ErrorKind::Exec, |state| async move {
                podman::exec::record_of(&state, &id)
            })
            .await
            .map(|exec| ExecInspected { exec })
        }

        /// What the images and the containers use of the storage.
        async fn storage_inspect(&self) -> Result<StorageUsage, EngineError> {
            self.api(ErrorKind::None, |state| async move {
                podman::workload::storage_usage(&state).await
            })
            .await
        }

        /// Whether the plugins of the CNI network `network` (`cni:NAME`)
        /// say it is ready.
        async fn network_check(&self, network: String) -> Result<NetworkStatus, EngineError> {
            self.api(ErrorKind::Network, |state| async move {
                podman::workload::network_status(&state, &network).await
            })
            .await
        }

        /// The content of a volume, a tar archive.
        /// The reply carries the read end of a pipe (descriptor 0): the
        /// frames of a download.
        #[zlink(return_fds)]
        async fn volume_export(&self, name: String) -> (Result<Ack, EngineError>, Vec<OwnedFd>) {
            let opened = self
                .api(ErrorKind::Volume, |state| async move {
                    podman::volumes::export_of(&state, &name).await
                })
                .await;
            with_fds(self.download(opened))
        }

        /// Extract the tar archive of the upload into a volume.
        /// The call carries one descriptor, the read end of a pipe: the
        /// upload, as frames.
        async fn volume_import(
            &self,
            name: String,
            #[zlink(fds)] archive: Vec<OwnedFd>,
        ) -> Result<Ack, EngineError> {
            let input = self.upload(archive, "the archive")?;
            self.api(ErrorKind::Volume, |state| async move {
                podman::volumes::import_of(&state, &name, input)
                    .await
                    .map(|()| Ack {})
            })
            .await
        }

        /// Create a container from the document of a podman client the pipe
        /// carries: libpod's SpecGenerator, or Docker's configuration with
        /// `docker` (`name` and `platform` are of Docker's query).
        /// The call carries one descriptor, the read end of a pipe that
        /// `spec` names: the document of the request as JSON, read to its end.
        async fn podman_container_create(
            &self,
            docker: bool,
            name: Option<String>,
            platform: Option<String>,
            spec: u32,
            #[zlink(fds)] fds: Vec<OwnedFd>,
        ) -> Result<ContainerCreated, EngineError> {
            let body = json_document(fds, Some(spec)).await?;
            self.api(ErrorKind::Container, |state| async move {
                podman::containers::create_document_of(
                    &state,
                    docker,
                    name.as_deref(),
                    platform.as_deref(),
                    body,
                )
                .await
                .map(|(id, warnings)| ContainerCreated { id, warnings })
            })
            .await
        }

        /// Remove the containers that do not run and the filters select.
        async fn container_prune(
            &self,
            filters: Vec<Filter>,
        ) -> Result<ContainersPruned, EngineError> {
            let filters = filters_of(filters)?;
            self.api(ErrorKind::Container, |state| async move {
                podman::containers::prune_of(&state, &filters)
                    .await
                    .map(|(removed, space)| ContainersPruned { removed, space })
            })
            .await
        }

        /// Change the limits, the environment, the restart policy, the
        /// rlimits and the health check of a container: its id.
        async fn container_amend(&self, name: String, spec: UpdateSpec) -> Result<Id, EngineError> {
            self.api(ErrorKind::Container, |state| async move {
                podman::containers::amend_of(&state, &name, &spec)
                    .await
                    .map(|id| Id { id })
            })
            .await
        }

        /// Run the health check of a container that runs now: its health
        /// after it (the result last in its log).
        async fn container_healthcheck(&self, name: String) -> Result<HealthChecked, EngineError> {
            self.api(ErrorKind::Container, |state| async move {
                podman::containers::healthcheck_of(&state, &name).await
            })
            .await
            .map(|health| HealthChecked { health })
        }

        /// Checkpoint a container.  `archive` names a descriptor the client
        /// opened: an empty regular file open for writing (not appending), in
        /// which the engine writes the archive, or the write end of a pipe,
        /// to which it writes the frames of a download.  Without it the
        /// checkpoint is kept with the container for a restore in place.
        async fn container_checkpoint(
            &self,
            name: String,
            flags: CheckpointFlags,
            archive: Option<u32>,
            #[zlink(fds)] fds: Vec<OwnedFd>,
        ) -> Result<Checkpointed, EngineError> {
            let mut fds = Descriptors::new(fds);
            let archive = fds.take_opt("the archive", archive).map_err(invalid_fds)?;
            fds.finish().map_err(invalid_fds)?;
            let opts = checkpoint_options(flags);
            let Some(archive) = archive else {
                return self
                    .api(ErrorKind::Container, |state| async move {
                        podman::containers::checkpoint_kept_of(&state, &name, &opts)
                            .await
                            .map(|r| Checkpointed {
                                id: r.id,
                                runtime_checkpoint_duration: r.runtime_checkpoint_duration,
                                criu_statistics: r.criu_statistics,
                            })
                    })
                    .await;
            };
            let kind = rustix::fs::FileType::from_raw_mode(
                rustix::fs::fstat(&archive)
                    .map_err(|e| EngineError::invalid(format!("the archive: {e}")))?
                    .st_mode,
            );
            let done = |r: velarx_proto::workload::CheckpointReport| Checkpointed {
                id: r.id,
                runtime_checkpoint_duration: r.runtime_checkpoint_duration,
                criu_statistics: r.criu_statistics,
            };
            match kind {
                rustix::fs::FileType::RegularFile => {
                    self.api(ErrorKind::Container, |state| async move {
                        podman::containers::checkpoint_into(
                            &state,
                            &name,
                            opts,
                            std::fs::File::from(archive),
                        )
                        .await
                        .map(done)
                    })
                    .await
                }
                rustix::fs::FileType::Fifo => {
                    let (report, stream) = self
                        .api(ErrorKind::Container, |state| async move {
                            podman::containers::checkpoint_export_of(&state, &name, opts).await
                        })
                        .await?;
                    let _guard = self.runtime.enter();
                    let sink = PipeSink::new(archive, self.holds.busy())
                        .map_err(|e| EngineError::failed(format!("the archive: {e}")))?;
                    write_frames(stream, sink).await;
                    Ok(done(report))
                }
                _ => Err(EngineError::invalid(
                    "the archive is a regular file or the write end of a pipe".into(),
                )),
            }
        }

        /// Restore a container: `name` alone from its own checkpoint; with
        /// `archive` (a descriptor the client opened: a regular file open
        /// for reading, or the read end of a pipe of frames) or `reference` (one a node shares) a new container
        /// made of the archive; with `stage` the archive is staged in the
        /// container `name`, which was never started.
        async fn container_restore(
            &self,
            name: Option<String>,
            flags: RestoreFlags,
            archive: Option<u32>,
            reference: Option<String>,
            stage: bool,
            #[zlink(fds)] fds: Vec<OwnedFd>,
        ) -> Result<Restored, EngineError> {
            let mut fds = Descriptors::new(fds);
            let archive = fds.take_opt("the archive", archive).map_err(invalid_fds)?;
            let previous = fds
                .take_opt("the archive of the pre-checkpoint", flags.previous)
                .map_err(invalid_fds)?;
            fds.finish().map_err(invalid_fds)?;
            let reference = reference.filter(|r| !r.is_empty());
            let name = name.filter(|n| !n.is_empty());
            match (name, archive, reference, stage) {
                (Some(name), None, None, false) => {
                    self.api(ErrorKind::Container, |state| async move {
                        podman::containers::restore_of(&state, &name, &restore_options(flags))
                            .await
                            .map(restored)
                    })
                    .await
                }
                (Some(name), Some(archive), None, true) => {
                    self.api(ErrorKind::Container, |state| async move {
                        podman::containers::restore_stage_from(
                            &state,
                            &name,
                            flags.ignore_rootfs,
                            std::fs::File::from(archive),
                        )
                        .await
                        .map(|id| Restored {
                            id,
                            runtime_restore_duration: None,
                            criu_statistics: None,
                        })
                    })
                    .await
                }
                (None, archive, reference, false) if archive.is_some() || reference.is_some() => {
                    let input = match archive {
                        Some(archive) => self.archive_stream(archive)?,
                        None => Box::pin(futures::stream::empty()),
                    };
                    let previous = previous.map(|p| self.archive_stream(p)).transpose()?;
                    self.api(ErrorKind::None, |state| async move {
                        let reference = reference
                            .map(|r| velarx_core::services::checkpoint::Reference::parse(&r))
                            .transpose()
                            .map_err(ApiError::bad_request)?;
                        podman::containers::restore_import_of(
                            &state,
                            restore_options(flags),
                            reference,
                            input,
                            previous,
                        )
                        .await
                        .map(restored)
                    })
                    .await
                }
                _ => Err(EngineError::invalid(
                    "a restore names a container alone, a container and an archive to stage, \
                     or an archive or a reference for a new one"
                        .into(),
                )),
            }
        }

        /// What is at `path` in a container and, with `content`, its tar
        /// archive.
        /// With `content` the reply carries the read end of a pipe
        /// (descriptor 0): the frames of a download.
        #[zlink(return_fds)]
        async fn container_archive_get(
            &self,
            name: String,
            path: String,
            content: bool,
        ) -> (Result<PathStat, EngineError>, Vec<OwnedFd>) {
            let got = self
                .api(ErrorKind::Container, |state| async move {
                    podman::archive::archive_get_of(&state, &name, &path, content).await
                })
                .await;
            with_fds(got.and_then(|(stat, tar)| match tar {
                None => Ok((stat, Vec::new())),
                Some(tar) => self.download(Ok(tar)).map(|(Ack {}, fds)| (stat, fds)),
            }))
        }

        /// Extract the tar archive of the upload into the directory `path`
        /// of a container.
        /// The call carries one descriptor, the read end of a pipe: the
        /// upload, as frames.
        async fn container_archive_put(
            &self,
            name: String,
            path: String,
            rename: BTreeMap<String, String>,
            chown: bool,
            overwrite_dir_non_dir: bool,
            #[zlink(fds)] archive: Vec<OwnedFd>,
        ) -> Result<Ack, EngineError> {
            let rename = map_of(rename)?;
            let input = self.upload(archive, "the archive")?;
            self.api(ErrorKind::Container, |state| async move {
                if path.is_empty() {
                    return Err(ApiError::bad_request("missing the path"));
                }
                let opts = podman::archive::PutOptions {
                    rename,
                    chown,
                    overwrite_dir_non_dir,
                };
                podman::archive::archive_put_of(&state, &name, &path, opts, input)
                    .await
                    .map(|()| Ack {})
            })
            .await
        }

        /// The root file system of a container as a tar archive.
        /// The reply carries the read end of a pipe (descriptor 0): the
        /// frames of a download.
        #[zlink(return_fds)]
        async fn container_export(&self, name: String) -> (Result<Ack, EngineError>, Vec<OwnedFd>) {
            let opened = self
                .api(ErrorKind::Container, |state| async move {
                    podman::archive::export_of(&state, &name).await
                })
                .await;
            with_fds(self.download(opened))
        }

        /// The changes of a container to the files of its image, or of an
        /// image to its parent's.
        async fn container_diff(
            &self,
            name: String,
            diff_type: Option<DiffType>,
            parent: Option<String>,
        ) -> Result<Changes, EngineError> {
            use velarx_content::layer::dirtar::Change;
            let (containers, images) = match diff_type.unwrap_or(DiffType::All) {
                DiffType::All => (true, true),
                DiffType::Container => (true, false),
                DiffType::Image => (false, true),
            };
            self.api(ErrorKind::Container, |state| async move {
                podman::archive::changes_of(&state, &name, containers, images, parent.as_deref())
                    .await
                    .map(|list| Changes {
                        changes: list
                            .into_iter()
                            .map(|(path, change)| FileChange {
                                path,
                                kind: match change {
                                    Change::Modified => ChangeKind::Modified,
                                    Change::Added => ChangeKind::Added,
                                    Change::Deleted => ChangeKind::Deleted,
                                },
                            })
                            .collect(),
                    })
            })
            .await
        }

        /// Share the checkpoint archive (of `ContainerCheckpoint`)
        /// the pipe the call carries holds with the other nodes.
        /// The call carries one descriptor, the read end of a pipe: the
        /// archive.
        async fn checkpoint_share(
            &self,
            #[zlink(fds)] archive: Vec<OwnedFd>,
        ) -> Result<CheckpointShared, EngineError> {
            let input = self.upload(archive, "the archive")?;
            self.run(|state| async move {
                crate::api::ops::container::share_checkpoint(&state, input).await
            })
            .await?
            .map(|(reference, size)| CheckpointShared { reference, size })
            .map_err(|e| op_error(ErrorKind::Container, e))
        }

        /// Stop sharing the checkpoint of `reference` (its manifest, the
        /// public part of a reference).
        async fn checkpoint_unshare(&self, reference: String) -> Result<Ack, EngineError> {
            self.run(|state| async move {
                crate::api::ops::container::unshare_checkpoint(&state, &reference).await
            })
            .await?
            .map(|()| Ack {})
            .map_err(|e| op_error(ErrorKind::Container, e))
        }

        /// The processes of a container that runs, as `ps` shows them with
        /// `ps_args`: podman's descriptors (`pid`, `user`, `args`...; none:
        /// podman's default ones), or the arguments of ps.
        async fn container_top(
            &self,
            name: String,
            ps_args: Vec<String>,
        ) -> Result<Processes, EngineError> {
            bounded(&ps_args)?;
            self.api(ErrorKind::Container, |state| async move {
                podman::containers::processes_of(&state, &name, &ps_args)
                    .await
                    .map(|(_, top)| Processes {
                        titles: top.titles,
                        processes: top.processes,
                    })
            })
            .await
        }

        /// Mount the root of a container that runs: where.
        async fn container_mount(&self, name: String) -> Result<Mounted, EngineError> {
            self.api(ErrorKind::Container, |state| async move {
                podman::archive::mount_of(&state, &name)
                    .await
                    .map(|path| Mounted {
                        path: path.to_string_lossy().into_owned(),
                    })
            })
            .await
        }

        /// Unmount the root of a container.
        async fn container_unmount(&self, name: String) -> Result<Ack, EngineError> {
            self.api(ErrorKind::Container, |state| async move {
                podman::archive::unmount_of(&state, &name)
                    .await
                    .map(|()| Ack {})
            })
            .await
        }

        /// Search registries for `term`.
        /// The credentials are one descriptor, the sealed memory file `access` names.
        #[allow(
            clippy::too_many_arguments,
            reason = "one parameter for each field of the varlink call"
        )]
        async fn image_search(
            &self,
            term: String,
            limit: u32,
            filters: Vec<String>,
            list_tags: bool,
            tls_verify: Option<bool>,
            access: Option<u32>,
            #[zlink(fds)] fds: Vec<OwnedFd>,
        ) -> Result<SearchHits, EngineError> {
            if filters.len() > MAX_FILTERS {
                return Err(EngineError::invalid(format!(
                    "at most {MAX_FILTERS} filters in a call"
                )));
            }
            let access = registry_access_of(fds, access)?;
            self.api_cancelled(ErrorKind::None, |state| async move {
                let limit = match limit {
                    n @ 1..=1000 => n as usize,
                    _ => 0,
                };
                podman::images::search_of(
                    &state, &term, limit, &filters, list_tags, tls_verify, access,
                )
                .await
                .map(|hits| SearchHits { hits })
            })
            .await
        }

        /// The names a pull of `name` would try.
        async fn image_resolve(&self, name: String) -> Result<Names, EngineError> {
            self.api(ErrorKind::Image, |state| async move {
                podman::images::resolve_of(&state, &name).map(|names| Names { names })
            })
            .await
        }

        /// The layers of an image, the images they are the top layer of,
        /// and the images built on it.
        async fn image_tree(&self, name: String) -> Result<ImageTreeInspected, EngineError> {
            self.api(ErrorKind::Image, |state| async move {
                podman::images::commit::tree_of(&state, &name)
                    .await
                    .map(|tree| ImageTreeInspected { tree })
            })
            .await
        }

        /// Remove images: libpod's report.
        async fn image_remove_many(
            &self,
            names: Vec<String>,
            force: bool,
            ignore: bool,
            noprune: bool,
            all: bool,
            manifest_list: bool,
        ) -> Result<ImagesRemoved, EngineError> {
            bounded(&names)?;
            self.api(ErrorKind::Image, |state| async move {
                let opts = podman::images::RemoveManyOptions {
                    force,
                    ignore,
                    noprune,
                    all,
                    manifest_list,
                };
                podman::images::remove_many_of(&state, names, opts).await
            })
            .await
        }

        /// Where the credentials of the completion of a lazily pulled image
        /// go.
        async fn image_credential_scopes(&self, name: String) -> Result<Scopes, EngineError> {
            self.api(ErrorKind::Image, |state| async move {
                podman::images::pull::credential_scopes_of(&state, &name)
                    .await
                    .map(|scopes| Scopes { scopes })
            })
            .await
        }

        /// Where the credentials of a pull or a push of `reference` go.
        async fn registry_credential_scopes(
            &self,
            reference: String,
            push: bool,
        ) -> Result<Scopes, EngineError> {
            self.api(ErrorKind::Image, |state| async move {
                podman::images::pull::registry_scopes_of(&state, &reference, push)
                    .map(|scopes| Scopes { scopes })
            })
            .await
        }

        /// The pulls in progress: images whose layers are not all in the
        /// store (`images` lists only complete ones).
        async fn image_pulls(&self) -> Result<PullsListed, EngineError> {
            self.api(ErrorKind::Image, |state| async move {
                podman::images::pull::pulls_of(&state).await
            })
            .await
        }

        /// Whether a pull in progress has the name or the id `name`.
        async fn image_pulling(&self, name: String) -> Result<PullingAnswer, EngineError> {
            use velarx_content::pull::staged::PullState;
            self.api(ErrorKind::Image, |state| async move {
                let entry = state.image_service.pulling(&name);
                // (a cancelled pull is none: `image_pulls` does not list it)
                Ok(PullingAnswer {
                    pulling: entry.is_some_and(|e| e.state.state != PullState::Cancelled),
                })
            })
            .await
        }

        /// Fetch what a lazily pulled image lacks and prove its layers.
        /// The credentials are one descriptor, the sealed memory file `access` names.
        async fn image_complete(
            &self,
            name: String,
            access: Option<u32>,
            #[zlink(fds)] fds: Vec<OwnedFd>,
        ) -> Result<ImageCompleted, EngineError> {
            let access = registry_access_of(fds, access)?;
            self.api_cancelled(ErrorKind::Image, |state| async move {
                podman::images::pull::complete_of(&state, &name, access)
                    .await
                    .map(|stats| ImageCompleted { stats })
            })
            .await
        }

        /// The digest of the manifest the registry has for `reference` now.
        /// The credentials are one descriptor, the sealed memory file `access` names.
        async fn registry_digest(
            &self,
            reference: String,
            tls_verify: bool,
            platform: Option<String>,
            access: Option<u32>,
            #[zlink(fds)] fds: Vec<OwnedFd>,
        ) -> Result<RegistryDigested, EngineError> {
            let access = registry_access_of(fds, access)?;
            self.api_cancelled(ErrorKind::Image, |state| async move {
                podman::images::pull::registry_digest_of(
                    &state, &reference, tls_verify, platform, access,
                )
                .await
                .map(|digest| RegistryDigested { digest })
            })
            .await
        }

        /// Create an image from a tar: the upload, or what `spec.url` has.
        /// The call carries the tar as the upload (one descriptor, the read
        /// end of a pipe of frames), none with `spec.url`.
        async fn image_import(
            &self,
            spec: ImportSpec,
            #[zlink(fds)] archive: Vec<OwnedFd>,
        ) -> Result<Id, EngineError> {
            let input = if archive.is_empty() {
                Box::pin(futures::stream::empty())
            } else {
                self.upload(archive, "the archive")?
            };
            self.api(ErrorKind::None, |state| async move {
                let p = &spec.platform;
                let args = podman::images::archive::ImportArgs {
                    docker_hub: spec.docker_hub,
                    url: spec.url.filter(|u| !u.is_empty() && u != "-"),
                    changes: spec.changes,
                    message: spec.message,
                    platform: podman::images::archive::import_platform_of(
                        p.platform.as_deref(),
                        p.os.as_deref(),
                        p.arch.as_deref(),
                        p.variant.as_deref(),
                    )?,
                    reference: spec.reference,
                    repo: spec.repo,
                    tag: spec.tag,
                    digest: spec.digest,
                };
                podman::images::archive::import_of(&state, args, input)
                    .await
                    .map(|id| Id { id })
            })
            .await
        }

        /// The changes of a container as a new image.  With more: the
        /// progress of its layer, one a reply, then the id of the image (the
        /// last reply); without, the id.  The commit goes on when the client
        /// goes.
        /// The call carries a descriptor when `changes` names one: the read
        /// end of a pipe with the settings of the configuration (JSON, read
        /// to its end).
        #[zlink(more)]
        async fn container_commit(
            &self,
            more: bool,
            spec: CommitSpec,
            changes: Option<u32>,
            #[zlink(fds)] config: Vec<OwnedFd>,
        ) -> impl futures::Stream<Item = Result<zlink::Reply<Committed>, EngineError>> + Unpin
        {
            use futures::StreamExt;
            let override_config = match json_document(config, changes).await {
                Ok(c) => c,
                Err(e) => {
                    let failed: Replies<Committed> =
                        Box::pin(futures::stream::once(async move { Err(e) }));
                    return failed;
                }
            };
            let (tx, rx) = tokio::sync::mpsc::channel(64);
            let committed = self.api(ErrorKind::Container, move |state| async move {
                let args = podman::images::commit::CommitArgs {
                    container: spec.container,
                    docker_hub: spec.docker_hub,
                    format: spec.format,
                    repo: spec.repo,
                    tag: spec.tag,
                    author: spec.author,
                    comment: spec.comment,
                    changes: spec.changes,
                    pause: spec.pause,
                    include_volumes: spec.include_volumes,
                    squash: spec.squash,
                    override_config,
                    digest: spec.digest,
                };
                podman::images::commit::commit_of(&state, args, more.then_some(tx)).await
            });
            let progress = futures::stream::unfold(rx, |mut rx| async move {
                let p = rx.recv().await?;
                let reply = Committed {
                    progress: Some(podman::images::pull::progress_record(p)),
                    id: None,
                };
                Some((
                    Ok(zlink::Reply::new(Some(reply)).set_continues(Some(true))),
                    rx,
                ))
            });
            let end = futures::stream::once(async move {
                committed.await.map(|id| {
                    zlink::Reply::new(Some(Committed {
                        progress: None,
                        id: Some(id),
                    }))
                    .set_continues(Some(false))
                })
            });
            let replies: Replies<Committed> = Box::pin(progress.chain(end));
            replies
        }

        /// Add a file to an artifact.  Exactly one of `file`, the position
        /// of the descriptor the client opened (a regular file, or the read
        /// end of a pipe: the upload, as frames), and `path`, a file of the
        /// host of the engine, which the engine opens as its own user, for
        /// whoever calls it: the socket of the engine is as trusted as that
        /// user (root for a rootful engine), and so is a frontend that passes
        /// a client's path.
        async fn artifact_add(
            &self,
            spec: ArtifactAddSpec,
            file: Option<u32>,
            path: Option<String>,
            #[zlink(fds)] fds: Vec<OwnedFd>,
        ) -> Result<Id, EngineError> {
            let mut fds = Descriptors::new(fds);
            let source = match (file, path) {
                (Some(at), None) => {
                    let fd = fds.take("the file", at).map_err(invalid_fds)?;
                    let kind = rustix::fs::FileType::from_raw_mode(
                        rustix::fs::fstat(&fd)
                            .map_err(|e| EngineError::invalid(format!("the file: {e}")))?
                            .st_mode,
                    );
                    match kind {
                        rustix::fs::FileType::RegularFile => {
                            podman::artifacts::Source::Open(std::fs::File::from(fd))
                        }
                        rustix::fs::FileType::Fifo => {
                            podman::artifacts::Source::Body(self.upload(vec![fd], "the file")?)
                        }
                        _ => {
                            return Err(EngineError::invalid(
                                "the file is a regular file or the read end of a pipe".into(),
                            ))
                        }
                    }
                }
                (None, Some(path)) => {
                    let path = podman::artifacts::local_file(&path)
                        .map_err(|e| api_error(e, ErrorKind::Artifact))?;
                    podman::artifacts::Source::Local(path)
                }
                _ => {
                    return Err(EngineError::invalid(
                        "an artifact add takes a file or a path, one of them".into(),
                    ))
                }
            };
            fds.finish().map_err(invalid_fds)?;
            self.api(ErrorKind::Artifact, |state| async move {
                let req = artifact_add_request(spec);
                podman::artifacts::add_of(&state, &req, source)
                    .await
                    .map(|id| Id { id })
            })
            .await
        }

        /// A tar of the blobs of an artifact (those of `digest` or `title`),
        /// named by their titles (by their digests with `by_digest`).
        /// The reply carries the read end of a pipe (descriptor 0): the
        /// frames of a download.
        #[zlink(return_fds)]
        async fn artifact_extract(
            &self,
            name: String,
            digest: Option<String>,
            title: Option<String>,
            by_digest: bool,
        ) -> (Result<Ack, EngineError>, Vec<OwnedFd>) {
            let opened = self
                .api(ErrorKind::Artifact, |state| async move {
                    let filter = velarx_core::services::artifact::BlobFilter {
                        digest: digest.filter(|d| !d.is_empty()),
                        title: title.filter(|t| !t.is_empty()),
                    };
                    let tar =
                        podman::artifacts::extract_of(&state, &name, filter, by_digest).await?;
                    let all: crate::api::ops::ByteStream = Box::pin(futures::stream::once(
                        std::future::ready(Ok(bytes::Bytes::from(tar))),
                    ));
                    Ok(all)
                })
                .await;
            with_fds(self.download(opened))
        }

        /// Make a manifest list of images.  `digest` (`sha256` or `sha512`)
        /// is the algorithm of the digest of the list (none: the engine's
        /// `[build] digest`).
        /// The credentials are one descriptor, the sealed memory file `access` names.
        #[allow(
            clippy::too_many_arguments,
            reason = "one parameter for each field of the varlink call"
        )]
        async fn manifest_create(
            &self,
            name: String,
            images: Vec<String>,
            amend: bool,
            all: bool,
            tls_verify: bool,
            annotations: BTreeMap<String, String>,
            instance: InstanceSpec,
            subject: Option<String>,
            digest: Option<String>,
            access: Option<u32>,
            #[zlink(fds)] fds: Vec<OwnedFd>,
        ) -> Result<Id, EngineError> {
            bounded(&images)?;
            let annotations = map_of(annotations)?;
            let access = registry_access_of(fds, access)?;
            self.api(ErrorKind::Image, |state| async move {
                let o = podman::manifests::CreateOptions {
                    amend,
                    all,
                    tls_verify,
                    annotations,
                    instance,
                    subject,
                    digest,
                };
                podman::manifests::create_of(&state, &name, images, o, access)
                    .await
                    .map(|id| Id { id })
            })
            .await
        }

        /// A manifest list, of the store or of its registry, as OCI's index.
        /// The credentials are one descriptor, the sealed memory file `access` names.
        async fn manifest_inspect(
            &self,
            name: String,
            tls_verify: bool,
            access: Option<u32>,
            #[zlink(fds)] fds: Vec<OwnedFd>,
        ) -> Result<ManifestListRecord, EngineError> {
            let access = registry_access_of(fds, access)?;
            self.api_cancelled(ErrorKind::Image, |state| async move {
                podman::manifests::inspect_of(&state, &name, tls_verify, access).await
            })
            .await
        }

        /// Add images to a list: its id.
        /// The credentials are one descriptor, the sealed memory file `access` names.
        #[allow(
            clippy::too_many_arguments,
            reason = "one parameter for each field of the varlink call"
        )]
        async fn manifest_add_images(
            &self,
            name: String,
            images: Vec<String>,
            all: bool,
            instance: InstanceSpec,
            tls_verify: bool,
            access: Option<u32>,
            #[zlink(fds)] fds: Vec<OwnedFd>,
        ) -> Result<Id, EngineError> {
            bounded(&images)?;
            let access = registry_access_of(fds, access)?;
            self.api_cancelled(ErrorKind::Image, |state| async move {
                podman::manifests::add_images_of(
                    &state, &name, images, all, instance, tls_verify, access,
                )
                .await
                .map(|id| Id { id })
            })
            .await
        }

        /// Remove the instance `digest` from a list: its id.
        async fn manifest_remove_instance(
            &self,
            name: String,
            digest: String,
        ) -> Result<Id, EngineError> {
            self.api(ErrorKind::Image, |state| async move {
                podman::manifests::remove_instance_of(&state, &name, &digest)
                    .await
                    .map(|id| Id { id })
            })
            .await
        }

        /// Annotate an instance of a list (an image or a digest; none: the
        /// list), set the annotations of the index and its subject: its id.
        async fn manifest_annotate(
            &self,
            name: String,
            instance: Option<String>,
            spec: InstanceSpec,
            index_annotations: BTreeMap<String, String>,
            subject: Option<String>,
        ) -> Result<Id, EngineError> {
            let index_annotations = map_of(index_annotations)?;
            self.api(ErrorKind::Image, |state| async move {
                podman::manifests::annotate_of(
                    &state,
                    &name,
                    instance.as_deref(),
                    spec,
                    &index_annotations,
                    subject.as_deref(),
                )
                .await
                .map(|id| Id { id })
            })
            .await
        }

        /// Add an artifact made of files to a list: its digest.
        /// The call carries the sealed memory file of the credentials `access`
        /// names and one descriptor for each title of the spec (at most 64): a
        /// regular file open for reading.
        async fn manifest_add_artifact(
            &self,
            name: String,
            spec: ManifestArtifactSpec,
            tls_verify: bool,
            access: Option<u32>,
            #[zlink(fds)] pipes: Vec<OwnedFd>,
        ) -> Result<Id, EngineError> {
            if spec.titles.len() > velarx_proto::engine::MAX_ARTIFACT_FILES {
                return Err(EngineError::invalid(format!(
                    "at most {} files in an artifact",
                    velarx_proto::engine::MAX_ARTIFACT_FILES
                )));
            }
            let mut named = Descriptors::new(pipes);
            let access = registry_access_in(&mut named, access)?;
            let files = named.rest();
            if files.len() != spec.titles.len() {
                return Err(EngineError::invalid(
                    "an artifact has a descriptor for each of its titles".into(),
                ));
            }
            // (each is opened again by its path in /proc, with the rights of
            // the engine: only a regular file the caller opened for reading,
            // not a descriptor of a path (O_PATH) nor one opened for writing
            // only; a pipe or a socket would wait for its writer)
            for (title, f) in spec.titles.iter().zip(&files) {
                use rustix::fs::{FileType, OFlags};
                let regular = rustix::fs::fstat(f)
                    .is_ok_and(|st| FileType::from_raw_mode(st.st_mode) == FileType::RegularFile);
                let readable = rustix::fs::fcntl_getfl(f).is_ok_and(|fl| {
                    !fl.contains(OFlags::PATH) && (fl & OFlags::RWMODE) != OFlags::WRONLY
                });
                if !regular || !readable {
                    return Err(EngineError::invalid(format!(
                        "the descriptor of the file {title} is not a regular file open for reading"
                    )));
                }
            }
            self.api(ErrorKind::Image, |state| async move {
                podman::manifests::add_artifact_of(&state, &name, spec, files, tls_verify, access)
                    .await
                    .map(|id| Id { id })
            })
            .await
        }

        /// The systemd units of a container or a pod.
        async fn systemd_generate(
            &self,
            name: String,
            spec: SystemdSpec,
        ) -> Result<Units, EngineError> {
            self.api(ErrorKind::None, |state| async move {
                let o = podman::systemd::options_of(podman::systemd::Asked {
                    use_name: spec.use_name,
                    no_header: spec.no_header,
                    restart_policy: spec.restart_policy,
                    restart_sec: spec.restart_sec,
                    start_timeout: spec.start_timeout,
                    stop_timeout: spec.stop_timeout,
                    container_prefix: spec.container_prefix,
                    pod_prefix: spec.pod_prefix,
                    separator: spec.separator,
                    wants: spec.wants,
                    after: spec.after,
                    requires: spec.requires,
                    env: spec.env,
                })?;
                podman::systemd::generate_of(&state, &name, &o)
                    .await
                    .map(|units| Units {
                        units: units.into_iter().collect(),
                    })
            })
            .await
        }

        /// Push an image (or a manifest list).  With more: where the push
        /// goes (the first reply), the progress of its blobs, one a reply,
        /// then what was pushed (the last reply); without, what was pushed.
        /// The push stops when the client closes the connection.
        /// The credentials are one descriptor, the sealed memory file `access` names.
        #[zlink(more)]
        async fn image_push(
            &self,
            more: bool,
            spec: PushSpec,
            access: Option<u32>,
            #[zlink(fds)] fds: Vec<OwnedFd>,
        ) -> impl futures::Stream<Item = Result<zlink::Reply<Pushed>, EngineError>> + Unpin
        {
            use futures::StreamExt;
            let failed = |e: EngineError| -> Replies<Pushed> {
                Box::pin(futures::stream::once(async move { Err(e) }))
            };
            let mut named = Descriptors::new(fds);
            let access = match registry_access_in(&mut named, access) {
                Ok(a) => a,
                Err(e) => return failed(e),
            };
            let destination = match named.take_opt("the destination", spec.destination_fd) {
                Ok(d) => d,
                Err(e) => return failed(invalid_fds(e)),
            };
            let sign = match signing_key_in(&mut named, spec.signing) {
                Ok(k) => k,
                Err(e) => return failed(e),
            };
            if let Err(e) = named.finish() {
                return failed(invalid_fds(e));
            }
            let (tx, rx) = tokio::sync::mpsc::channel(64);
            let prepared = self
                .api(ErrorKind::Image, |state| async move {
                    let p = &spec.platform;
                    let args = podman::images::push::PushArgs {
                        images: spec.images,
                        artifact: spec.artifact,
                        tag: spec.tag.filter(|t| !t.is_empty()),
                        destination: spec.destination.filter(|d| !d.is_empty()),
                        platform: podman::images::push::push_platform_of(
                            p.platform.as_deref(),
                            p.os.as_deref(),
                            p.arch.as_deref(),
                            p.variant.as_deref(),
                        )?,
                        all: spec.all,
                        all_tags: spec.all_tags,
                        tls_verify: spec.tls_verify,
                        access,
                        compression: spec.compression,
                        compression_level: spec.compression_level,
                        add_compression: spec.add_compression,
                        retry: spec.retry,
                        format: spec.format,
                        sign,
                        sinks: spec.sinks,
                        path: destination,
                    };
                    podman::images::push::push_prepare(&state, args, tx).await
                })
                .await;
            let job = match prepared {
                Ok(job) => job,
                Err(e) => return failed(e),
            };
            let destination = job.destination.clone();
            let pushed =
                self.api_cancelled(
                    ErrorKind::Image,
                    |state| async move { job.run(&state).await },
                );
            let start =
                futures::stream::once(std::future::ready(Ok(zlink::Reply::new(Some(Pushed {
                    destination: Some(destination.clone()),
                    progress: None,
                    pushed: None,
                }))
                .set_continues(Some(true)))))
                .filter(move |_| std::future::ready(more));
            let progress = futures::stream::unfold(rx, |mut rx| async move {
                let p = rx.recv().await?;
                let reply = Pushed {
                    destination: None,
                    progress: Some(podman::images::pull::progress_record(p)),
                    pushed: None,
                };
                Some((
                    Ok(zlink::Reply::new(Some(reply)).set_continues(Some(true))),
                    rx,
                ))
            })
            .filter(move |_| std::future::ready(more));
            let end = futures::stream::once(async move {
                pushed.await.map(|pushed| {
                    zlink::Reply::new(Some(Pushed {
                        destination: Some(destination),
                        progress: None,
                        pushed: Some(pushed),
                    }))
                    .set_continues(Some(false))
                })
            });
            let replies: Replies<Pushed> = Box::pin(start.chain(progress).chain(end));
            replies
        }

        /// The containers whose root is mounted.
        async fn container_mount_list(&self) -> Result<MountedList, EngineError> {
            self.api(ErrorKind::Container, |state| async move {
                podman::archive::show_mounted_of(&state)
                    .await
                    .map(|list| MountedList {
                        mounts: list
                            .into_iter()
                            .map(|(id, path)| (id, path.to_string_lossy().into_owned()))
                            .collect(),
                    })
            })
            .await
        }
    }

    /// The interface as the macro described it (the binary serves the file).
    #[cfg(test)]
    pub(super) fn description() -> String {
        format!("{}", __Engine_INTERFACE_0)
    }
}

/// The text of the interface definition (`interfaces/org.velarx.Engine.varlink`),
/// made from the types and the methods above.
#[cfg(test)]
pub fn definition() -> String {
    format!(
        "# SPDX-License-Identifier: Apache-2.0\n\
         #\n\
         # The interface org.velarx.Engine: the engine of velarx as a varlink service,\n\
         # for its frontends (the REST API, the CRI, the command line)\n\
         # and for programs in other languages.  Generated\n\
         # from the Rust types of the engine (crates/proto, src/engine_service.rs) by the\n\
         # test `engine_service::tests::the_interface_file_is_current`:\n\
         # VELARX_WRITE_INTERFACES=1 cargo test --lib engine_service writes it.\n\
         #\n\
         # Names: mostly NounVerb (ContainerList, ImageRemove).  A method named\n\
         # Podman... takes the document of podman's or Docker's API for velarx-api.\n\
         #\n\
         # Descriptors cross in the SCM_RIGHTS of the message, named in the JSON by\n\
         # their position among the descriptors of the message; the comment of a\n\
         # method says what its call and its reply carry.  An upload or a download\n\
         # is a pipe of frames (a length, 4 bytes big endian, and that many bytes)\n\
         # ended by an empty frame: a pipe that ends before the empty frame was cut\n\
         # (the writer failed or went away), never the whole.\n\
         #\n\
         # Records that continue: the comment of a method that answers with more\n\
         # says \"one a reply\" (or the like).  It is called with `more`, answers one\n\
         # record in each reply, and `continues` is false in the last reply.\n\
         #\n\
         # Versions: GetInfo and Restart have this definition in every version.  A\n\
         # client calls GetInfo on each connection and uses the engine only when\n\
         # `interface` is its own, `version` is its own and `digest` is the FNV-1a\n\
         # (64 bits, hexadecimal) of this file; else it calls Restart, which starts\n\
         # the engine again from the binary installed after an upgrade, and\n\
         # connects again.  There is no compatibility between versions.\n\
         #\n\
         # Cancellation: closing the connection stops a call that reads or waits (lists,\n\
         # events, a wait, a pull); a call that changes something finishes once it\n\
         # started.  Limits: 256 connections, 192 of one process and 10 seconds\n\
         # for the first call of a connection (the defaults of `[services]` of\n\
         # config.toml); 32 KiB of arguments (what is larger is a pipe).\n\
         # Who may call: a peer of the same user or root (SO_PEERCRED); any\n\
         # accepted peer may make every call.\n\
         \n{}\n",
        service::description()
    )
}

/// Whether any user the socket lets in may connect (the engine of root).
fn any_uid(_: u32) -> bool {
    true
}

/// The users that may use the engine's socket: its own and root, and for
/// the engine of root whoever the mode of the socket lets in.
pub fn trusted() -> Result<fn(u32) -> bool, velarx_base::ids::IdsError> {
    Ok(if velarx_base::ids::rootful()? {
        any_uid
    } else {
        velarx_base::ipc::trusted_uid
    })
}

/// The engine served from a thread of its own.
pub struct Server {
    /// Dropped to stop serving
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    /// Told when the service left (idle) or stopped
    ended: Option<tokio::sync::oneshot::Receiver<()>>,
    /// The connections, and what holds the engine
    pub activity: Arc<Activity>,
}

impl Server {
    /// Return when the service left: it was idle for `idle.after`, with no
    /// container held.  Never, after [`Server::stop`].
    pub async fn left(&mut self) {
        match self.ended.as_mut() {
            Some(ended) => {
                let _ = ended.await;
                self.ended = None;
            }
            None => std::future::pending().await,
        }
    }

    /// Stop serving: the connections end.
    pub fn stop(&mut self) {
        self.stop = None;
    }

    /// Return once the thread of the service has ended (after
    /// [`Server::stop`], or when it left): what it held, the engine and
    /// the descriptors of its state, is dropped then.
    pub async fn ended(&mut self) {
        if let Some(ended) = self.ended.take() {
            let _ = ended.await;
        }
    }
}

/// The stack of the thread that serves the connections: the dispatch of the
/// methods (the macro's match of all of them) takes 1.5 MiB of a debug
/// build's stack, near the 2 MiB of a thread by default; a call that spawns
/// its work then overflowed it.
const SERVICE_STACK: usize = 8 << 20;

/// Serve `engine` on `listener` from a thread of its own, until the
/// service leaves (`idle`: after that long with no connection and nothing
/// held) or [`Server::stop`].
pub fn spawn(
    engine: Engine,
    listener: std::os::unix::net::UnixListener,
    idle: Option<IdleExit>,
) -> io::Result<Server> {
    spawn_on(engine, idle, move || {
        listener.set_nonblocking(true)?;
        Ok(tokio::net::UnixListener::from_std(listener)?.into())
    })
}

/// Serve `engine` from a thread of its own to this process only, until
/// [`Server::stop`]: each connection is one end of a socket pair sent on
/// the channel returned (no socket a name leads to: no other process, user
/// or container that shares the network namespace can connect to it).
pub fn spawn_in_process(
    engine: Engine,
) -> io::Result<(
    Server,
    tokio::sync::mpsc::UnboundedSender<std::os::unix::net::UnixStream>,
)> {
    let (hand, handed) = tokio::sync::mpsc::unbounded_channel();
    let server = spawn_on(engine, None, move || {
        Ok(activation::Connections::Handed(handed))
    })?;
    Ok((server, hand))
}

/// Serve `engine` on the connections `connections` makes in the runtime of
/// the thread of the service.
fn spawn_on(
    engine: Engine,
    idle: Option<IdleExit>,
    connections: impl FnOnce() -> io::Result<activation::Connections> + Send + 'static,
) -> io::Result<Server> {
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let (done, ended) = tokio::sync::oneshot::channel();
    let activity = Activity::new(activation::Limits::of(&engine.state.config.services));
    engine.holds.served_by(&activity);
    let served = activity.clone();
    std::thread::Builder::new()
        .name("engine-service".into())
        .stack_size(SERVICE_STACK)
        .spawn(move || {
            let result = (|| -> io::Result<()> {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()?;
                let local = tokio::task::LocalSet::new();
                local.block_on(&runtime, async move {
                    let connections = connections()?;
                    let trusted = trusted().map_err(io::Error::other)?;
                    tokio::select! {
                        () = activation::serve_varlink_on(
                            connections, idle, trusted, served, "engine", engine,
                        ) => {}
                        // (the guard was dropped: the sender is gone)
                        _ = stopped => {}
                    }
                    Ok(())
                })
            })();
            if let Err(e) = result {
                warn!("engine service: {e}");
            }
            let _ = done.send(());
        })?;
    Ok(Server {
        stop: Some(stop),
        ended: Some(ended),
        activity,
    })
}

/// The check of a start the varlink methods ask for: a command of a user with
/// the digests typed on it (`run`: those of its references), or (`service`)
/// the start of a service that has no command line to give them, such as the
/// CRI or the start at boot.
fn start_check(
    verify_image: Vec<String>,
    service: Option<bool>,
    run: Option<bool>,
) -> Result<velarx_core::services::StartCheck, EngineError> {
    use velarx_core::services::StartCheck;
    if service.unwrap_or(false) {
        if !verify_image.is_empty() {
            return Err(EngineError::invalid(
                "--verify-image: a start of the service manager goes by the digests recorded in the container, it takes none"
                    .to_string(),
            ));
        }
        return Ok(StartCheck::Engine);
    }
    Ok(StartCheck::User {
        digests: velarx_core::services::verify_image_digests(&verify_image)
            .map_err(|e| EngineError::invalid(e.to_string()))?,
        option: !run.unwrap_or(false),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon::{build_services, Role};
    use std::io::Read;
    use std::path::Path;
    use velarx_config::Config;
    use velarx_db::RecordState;
    use velarx_proto::connect::{self, connect_checked};
    use velarx_proto::engine::EngineProxy;

    /// A start of the service manager (`ContainerStart`, `PodRun` with
    /// `service`) goes by the records: digests given to it are refused, not
    /// dropped.
    #[test]
    fn a_start_of_the_service_manager_takes_no_digest() {
        use velarx_core::services::StartCheck;
        let digests = vec![format!("sha256:{}", "a".repeat(64))];
        let e = start_check(digests.clone(), Some(true), None).unwrap_err();
        assert!(e.message().contains("it takes none"), "{e:?}");
        assert!(matches!(
            start_check(Vec::new(), Some(true), None),
            Ok(StartCheck::Engine)
        ));
        assert!(matches!(
            start_check(digests, None, None),
            Ok(StartCheck::User { option: true, .. })
        ));
    }

    /// A session is named by the name its first reply gave, while it is
    /// listed: an unknown name is an error, a session that ended answers
    /// with nothing left to do, a dropped one is gone.
    #[tokio::test]
    async fn a_session_is_told_by_its_name_while_it_is_listed() {
        use velarx_proto::stream::Control;
        let sessions = Arc::new(Sessions::default());
        let e = sessions.tell("nosuch", Control::Detach).await.unwrap_err();
        assert!(matches!(e, EngineError::InvalidArgument { .. }), "{e:?}");
        let opened = velarx_proto::engine::SessionOpened {
            session: "abc".into(),
            tty: false,
            stdin: true,
            stdout: true,
            stderr: true,
            logs: None,
            detach_keys: Vec::new(),
            keep_open: false,
        };
        let (out, _replies, controls) = velarx_proto::stream::out(opened, None);
        sessions.open.lock().unwrap().insert("abc".into(), controls);
        let listed = Listed(sessions.clone(), "abc".into());
        // (the engine end is gone: the session ended)
        drop(out);
        sessions.tell("abc", Control::CloseStdin).await.unwrap();
        drop(listed);
        let e = sessions.tell("abc", Control::Detach).await.unwrap_err();
        assert!(matches!(e, EngineError::InvalidArgument { .. }), "{e:?}");
    }

    /// A lease ends the pause by itself, unless the pause was ended or the
    /// lease replaced before.
    #[tokio::test]
    async fn a_lease_resumes_unless_it_was_cancelled_or_replaced() {
        use std::time::Duration;
        let leases = Arc::new(PauseLeases::default());
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let ended = |what: &'static str| {
            let tx = tx.clone();
            async move {
                tx.send(what).unwrap();
            }
        };
        leases.arm(
            "cancelled",
            Duration::from_millis(10),
            true,
            ended("cancelled"),
        );
        leases.arm(
            "replaced",
            Duration::from_millis(10),
            true,
            ended("replaced old"),
        );
        leases.arm(
            "replaced",
            Duration::from_millis(40),
            true,
            ended("replaced new"),
        );
        leases.arm("expires", Duration::from_millis(20), true, ended("expires"));
        leases.cancel("cancelled");
        assert_eq!(rx.recv().await, Some("expires"));
        assert_eq!(rx.recv().await, Some("replaced new"));
        assert!(rx.try_recv().is_err());
        assert!(leases.armed.lock().unwrap().is_empty());
    }

    /// A lease read again from the database does not replace the timer
    /// this engine armed for the container (a later pause's lease, or the
    /// same one): its end stays the armed one.
    #[tokio::test]
    async fn a_lease_read_again_keeps_the_armed_one() {
        use std::time::Duration;
        let leases = Arc::new(PauseLeases::default());
        let token = |leases: &PauseLeases| leases.armed.lock().unwrap()["c1"].0;
        leases.arm("c1", Duration::from_secs(3600), true, async {});
        let armed = token(&leases);
        let (tx, mut rx) = tokio::sync::oneshot::channel::<()>();
        leases.arm("c1", Duration::ZERO, false, async move {
            let _ = tx.send(());
        });
        assert_eq!(token(&leases), armed);
        // (the end that was not armed is dropped)
        assert!(matches!(
            rx.try_recv(),
            Err(tokio::sync::oneshot::error::TryRecvError::Closed)
        ));
        leases.arm("c2", Duration::from_secs(3600), false, async {});
        assert!(leases.armed.lock().unwrap().contains_key("c2"));
        leases.cancel("c1");
        leases.cancel("c2");
    }

    /// A container record "c1" named `leased` (of an image "i").
    async fn insert_leased(state: &AppState) {
        state
            .db
            .insert_image(&velarx_db::ImageRecord {
                id: "i".into(),
                manifest_digest: velarx_types::digest::Digest::of(
                    velarx_types::digest::Algorithm::Sha256,
                    b"m",
                ),
                config_digest: velarx_types::digest::Digest::of(
                    velarx_types::digest::Algorithm::Sha256,
                    b"c",
                ),
                manifest: "{}".into(),
                config: "{}".into(),
                created_at: "2026-01-01T00:00:00Z".into(),
                is_lazy: false,
            })
            .await
            .unwrap();
        state
            .db
            .insert_container(&velarx_db::ContainerRecord {
                id: "c1".into(),
                name: Some("leased".into()),
                image_id: "i".into(),
                config: serde_json::to_string(&velarx_runtime::container::ContainerConfig {
                    id: "c1".into(),
                    ..Default::default()
                })
                .unwrap(),
                state: RecordState::Created,
                pid: None,
                created_at: "2026-01-01T00:00:00Z".into(),
                started_at: None,
                finished_at: None,
                exit_code: None,
            })
            .await
            .unwrap();
    }

    /// The leases of the pauses survive a database that cannot be read: at
    /// the start of the engine (which goes on) they are read and armed again
    /// at the next change of the database, and a lease whose end cannot be
    /// read stays recorded for another try.
    #[tokio::test]
    async fn leases_that_cannot_be_read_are_read_again_at_the_next_change() {
        let dir = tempfile::tempdir().unwrap();
        let engine = engine_in(dir.path()).await;
        let state = engine.state.clone();
        insert_leased(&state).await;
        let until = now_ms() + 3_600_000;
        state.db.set_pause_lease("c1", Some(until)).await.unwrap();
        // (a database that fails the reads of the leases)
        let rename = |from: &'static str, to: &'static str| {
            state.db.conn().call(move |c| {
                c.execute(&format!("ALTER TABLE {from} RENAME TO {to}"), [])?;
                Ok(())
            })
        };
        rename("container_ext", "hidden").await.unwrap();
        let ended = podman::container_end_pause_lease(&state, "c1", until)
            .await
            .unwrap();
        assert!(
            matches!(ended, podman::LeaseEnd::Unrecorded(_)),
            "{ended:?}"
        );
        let waiting = engine
            .rearm_pause_leases()
            .await
            .expect("a wait for a change");
        assert!(engine.leases.armed.lock().unwrap().is_empty());
        rename("hidden", "container_ext").await.unwrap();
        state
            .db
            .update_container_state("c1", RecordState::Created, None, None, None, None)
            .await
            .unwrap();
        waiting.await.unwrap();
        assert!(engine.leases.armed.lock().unwrap().contains_key("c1"));
        assert_eq!(
            state.container_service.pause_lease("c1").await.unwrap(),
            Some(until)
        );
        engine.leases.cancel("c1");
    }

    /// The removal of a container cancels the lease of its pause (its
    /// timer, and the engine's hold for it).
    #[test]
    fn a_removed_container_takes_its_lease_with_it() {
        on_service_stack(a_removed_container_takes_its_lease_with_it_here);
    }

    async fn a_removed_container_takes_its_lease_with_it_here() {
        let dir = tempfile::tempdir().unwrap();
        let engine = engine_in(dir.path()).await;
        let state = engine.state.clone();
        insert_leased(&state).await;
        let leases = engine.leases.clone();
        leases.arm("c1", std::time::Duration::from_secs(3600), true, async {});
        let local = tokio::task::LocalSet::new();
        local
            .run_until(async {
                let socket = dir.path().join("engine.sock");
                let listener = tokio::net::UnixListener::bind(&socket).unwrap();
                tokio::task::spawn_local(activation::serve_varlink(
                    listener,
                    None,
                    |_| true,
                    activation::Limits::default(),
                    "engine test",
                    engine,
                ));
                let mut conn = connect_checked(&socket).await.unwrap();
                let removed = conn
                    .container_remove("leased", true, false, false, false, None)
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(removed.removed.len(), 1);
            })
            .await;
        assert!(leases.armed.lock().unwrap().is_empty());
    }

    /// The call that restarts the engine is counted though it makes the
    /// engine refuse the others, and the refused hold ends kept open while it
    /// stops are bounded.
    #[tokio::test]
    async fn restart_is_counted_and_late_holds_are_bounded() {
        let calls = Arc::new(Mutating::default());
        calls.refuse_new(true);
        let restart = calls.count_always();
        assert_eq!(calls.drain(std::time::Duration::from_millis(30)).await, 1);
        drop(restart);
        assert_eq!(calls.drain(std::time::Duration::from_millis(30)).await, 0);

        let mut late = Vec::new();
        let kept = (0..10)
            .filter(|_| {
                let (a, _b) = std::os::unix::net::UnixStream::pair().unwrap();
                keep_late(&mut late, a, 4)
            })
            .count();
        assert_eq!((kept, late.len()), (4, 4));
    }

    /// A restart waits for the calls that change something and refuses new
    /// ones; a read does not hold it.
    #[tokio::test]
    async fn a_restart_waits_for_the_calls_that_change_something() {
        use std::time::Duration;
        let dir = tempfile::tempdir().unwrap();
        let engine = engine_in(dir.path()).await;
        let calls = engine.mutating();
        let release = Arc::new(tokio::sync::Notify::new());
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let slow = engine.run_fut({
            let release = release.clone();
            async move {
                started_tx.send(()).unwrap();
                release.notified().await;
                7
            }
        });
        started_rx.await.unwrap();
        // a read that lasts: not waited for
        let _read = engine.api_cancelled(ErrorKind::None, |_| async {
            std::future::pending::<crate::api::podman::error::ApiResult<()>>().await
        });
        calls.refuse_new(true);
        let draining = tokio::spawn({
            let calls = calls.clone();
            async move { calls.drain(Duration::from_secs(60)).await }
        });
        // (refused as soon as the drain started)
        let refused = loop {
            match engine.run_fut(async { 1 }).await {
                Err(e) => break e,
                Ok(_) => tokio::task::yield_now().await,
            }
        };
        assert!(format!("{refused:?}").contains("restarting"), "{refused:?}");
        assert!(!draining.is_finished());
        release.notify_one();
        assert_eq!(slow.await.unwrap(), 7);
        assert_eq!(draining.await.unwrap(), 0);
        let late = Arc::new(Mutating::default());
        let held = late.enter(None).unwrap();
        assert_eq!(late.drain(Duration::from_millis(30)).await, 1, "the limit");
        drop(held);
    }

    /// `Restart` is answered when the engine takes no connection any more:
    /// a client that connects after the answer waits for the engine that
    /// follows, it is not served (and cut) by this one, the connection of
    /// the call ends once answered; and a call that changes something is
    /// refused with the reason.
    /// Once a stopped service has ended, its thread holds nothing of the
    /// engine: the descriptors of the state are closed before a restart
    /// places the ones it passes on (a close there after the placing took
    /// away a hold of another frontend).
    #[tokio::test]
    async fn a_stopped_service_has_let_its_engine_go() {
        let dir = tempfile::tempdir().unwrap();
        let engine = engine_in(dir.path()).await;
        let state = engine.state.clone();
        let held = Arc::strong_count(&state);
        let listener =
            std::os::unix::net::UnixListener::bind(dir.path().join("engine.sock")).unwrap();
        let mut server = spawn(engine, listener, None).unwrap();
        server.stop();
        server.ended().await;
        assert_eq!(Arc::strong_count(&state), held - 1);
    }

    #[tokio::test]
    async fn restart_is_answered_when_the_engine_takes_no_connection() {
        let dir = tempfile::tempdir().unwrap();
        let engine = engine_in(dir.path()).await;
        let activity = Activity::new(activation::Limits::default());
        engine.holds.served_by(&activity);
        let calls = engine.mutating();
        let restart = engine.state.server_service.restart_signal();
        let asked = restart.notified();
        tokio::pin!(asked);
        asked.as_mut().enable();
        tokio::task::LocalSet::new()
            .run_until(async {
                let socket = dir.path().join("engine.sock");
                let listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
                // (the socket stays open for the engine that follows)
                let _kept = listener.try_clone().unwrap();
                listener.set_nonblocking(true).unwrap();
                let listener = tokio::net::UnixListener::from_std(listener).unwrap();
                tokio::task::spawn_local(activation::serve_varlink_on(
                    listener,
                    None,
                    |_| true,
                    activity.clone(),
                    "engine test",
                    engine.clone(),
                ));
                let mut conn = connect_checked(&socket).await.unwrap();
                assert!(activity.accepting());
                let answer = conn.restart(Some(true)).await.unwrap().unwrap();
                assert!(answer.restarted);
                // (answered: the listener is closed)
                assert!(!activity.accepting());
                asked.await;
                let waiting = tokio::net::UnixStream::connect(&socket).await.unwrap();
                for _ in 0..20 {
                    tokio::task::yield_now().await;
                }
                // (the connection of the call ends once answered: the next
                // call of its client goes to the engine that follows)
                tokio::time::timeout(std::time::Duration::from_secs(10), activity.wait_idle())
                    .await
                    .expect("no connection is served");
                assert!(!velarx_sys::fd::peer_silent(conn.read().read_half()));
                drop(waiting);
                let refused = engine.run_fut(async { 1 }).await.unwrap_err();
                assert!(
                    format!("{refused:?}").contains(velarx_proto::engine::RESTARTING),
                    "{refused:?}"
                );
                assert_eq!(calls.drain(std::time::Duration::from_secs(5)).await, 0);
            })
            .await;
    }

    /// A restart is asked before the engine stops accepting connections:
    /// the daemon that sees the service stop finds it asked.
    #[tokio::test]
    async fn a_restart_is_asked_before_the_service_stops_accepting() {
        let dir = tempfile::tempdir().unwrap();
        let engine = engine_in(dir.path()).await;
        // (an activity nothing serves: it never stops accepting)
        let activity = Activity::new(activation::Limits::default());
        engine.holds.served_by(&activity);
        for upgraded in [false, true] {
            let asked = engine.state.server_service.restart_signal();
            let asked = asked.notified();
            tokio::pin!(asked);
            asked.as_mut().enable();
            let restarting = tokio::spawn({
                let engine = engine.clone();
                async move { engine.restart_now(upgraded).await }
            });
            asked.await;
            assert!(activity.accepting(), "asked while it accepts still");
            assert!(!restarting.is_finished());
            restarting.abort();
        }
        assert!(engine.state.server_service.upgrading());
    }

    /// A call that changes something keeps the engine from leaving idle
    /// while its work goes on after its client went away.
    #[tokio::test]
    async fn a_call_that_changes_something_keeps_the_service_busy() {
        let dir = tempfile::tempdir().unwrap();
        let engine = engine_in(dir.path()).await;
        let activity = Activity::new(activation::Limits::default());
        engine.holds.served_by(&activity);
        let release = Arc::new(tokio::sync::Notify::new());
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let slow = engine.run_fut({
            let release = release.clone();
            async move {
                started_tx.send(()).unwrap();
                release.notified().await;
            }
        });
        started_rx.await.unwrap();
        assert_eq!(activity.active(), 1);
        release.notify_one();
        slow.await.unwrap();
        assert_eq!(
            engine
                .mutating()
                .drain(std::time::Duration::from_secs(5))
                .await,
            0
        );
        assert_eq!(activity.active(), 0);
    }

    /// A hold the stopping engine refuses comes with the means to wait for
    /// the engine to have exited: its end of the hold stays open until the
    /// process ends, and hangs up with it.
    #[tokio::test]
    async fn a_stopping_engine_says_when_it_has_exited() {
        use std::os::fd::AsFd;
        let dir = tempfile::tempdir().unwrap();
        let engine = engine_in(dir.path()).await;
        let holds = engine.holds.clone();
        tokio::task::LocalSet::new()
            .run_until(async {
                let socket = dir.path().join("engine.sock");
                let listener = tokio::net::UnixListener::bind(&socket).unwrap();
                tokio::task::spawn_local(activation::serve_varlink(
                    listener,
                    None,
                    |_| true,
                    activation::Limits::default(),
                    "engine test",
                    engine,
                ));
                holds.none().await;
                let Err(connect::ConnectError::Stopping { gone }) = connect::hold(&socket).await
                else {
                    panic!("a stopping engine takes no hold");
                };
                let hung_up = |s: &std::os::unix::net::UnixStream| {
                    let mut fds = [rustix::event::PollFd::new(s, rustix::event::PollFlags::IN)];
                    rustix::event::poll(&mut fds, Some(&rustix::time::Timespec::default()))
                        .unwrap();
                    !fds[0].revents().is_empty()
                };
                let _ = gone.as_fd();
                assert!(!hung_up(&gone), "the engine has not exited");
                // (the exit of the process closes what the engine holds)
                LATE.lock().unwrap().clear();
                let waited = tokio::task::spawn_blocking(move || connect::wait_gone(&gone));
                tokio::time::timeout(std::time::Duration::from_secs(10), waited)
                    .await
                    .expect("the wait ends with the engine")
                    .unwrap();
            })
            .await;
    }

    /// The text a service sends for `GetInterfaceDescription` (the file,
    /// embedded) is what the descriptors of the types and methods say.
    #[test]
    fn the_description_served_is_what_the_types_say() {
        assert_eq!(velarx_proto::interfaces::engine(), service::description());
    }

    /// The file is made from the types: when they change it changes.
    /// `VELARX_WRITE_INTERFACES=1` writes it.
    #[test]
    fn the_interface_file_is_current() {
        let path =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("interfaces/org.velarx.Engine.varlink");
        let text = definition();
        if std::env::var_os("VELARX_WRITE_INTERFACES").is_some() {
            std::fs::write(&path, &text).unwrap();
        }
        let on_disk = std::fs::read_to_string(&path).unwrap_or_default();
        assert!(
            on_disk == text,
            "{} is not what the types make; run VELARX_WRITE_INTERFACES=1 cargo test --lib \
             engine_service and commit it",
            path.display()
        );
        for method in ["GetInfo", "Ping", "ContainerList", "ImageList"] {
            assert!(text.contains(&format!("method {method}(")), "{method}");
        }
        assert!(text.contains("error Failed ("), "{text}");
        assert!(!text.contains("error Api"), "{text}");
    }

    /// A record with documented fields.
    #[derive(zlink::introspect::CustomType)]
    #[allow(dead_code)]
    struct Documented {
        /// The first
        first: String,
        /// The second,
        /// on two lines
        second: Option<i64>,
        third: bool,
    }

    /// The comment of a field is written directly above that field, a field
    /// a line, and not after the comma of the field before it.
    #[test]
    fn a_comment_sits_directly_above_its_own_field() {
        use zlink::introspect::CustomType;
        assert_eq!(
            Documented::CUSTOM_TYPE.to_string(),
            "# A record with documented fields.\ntype Documented (\n\t# The first\n\tfirst: string,\n\t# The second,\n\t\
             # on two lines\n\tsecond: ?int,\n\tthird: bool\n)"
        );
    }

    /// In every interface file a comment is the first thing on its line,
    /// and the one before a field is followed by that field; the types,
    /// methods and errors of a file have names of their own (they share one
    /// namespace, and other parsers, varlinkctl's, refuse a file where a
    /// type and a method have the same name).
    #[test]
    fn the_comments_of_every_interface_file_sit_above_what_they_document() {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("interfaces");
        let mut files = 0;
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            let text = std::fs::read_to_string(&path).unwrap();
            files += 1;
            let mut names = std::collections::HashSet::new();
            for line in text.lines() {
                let mut words = line.split([' ', '(']);
                if let (Some("type" | "method" | "error"), Some(name)) =
                    (words.next(), words.next())
                {
                    assert!(names.insert(name), "{}: {name} twice", path.display());
                }
            }
            let mut pending = false;
            for (n, line) in text.lines().enumerate() {
                let at = format!("{}:{}: {line}", path.display(), n + 1);
                let code = line.trim_start();
                if code.starts_with('#') {
                    pending = true;
                    continue;
                }
                assert!(!code.contains(" #"), "a comment after code: {at}");
                if pending && !code.is_empty() {
                    // (the comment of a type, a method or an error is
                    // above its keyword; that of a field above `name: type`)
                    assert!(
                        code.starts_with("type ")
                            || code.starts_with("method ")
                            || code.starts_with("error ")
                            || code.starts_with("interface ")
                            || (line.starts_with('\t') && code.contains(": "))
                            || (line.starts_with('\t')
                                && code
                                    .trim_end_matches(',')
                                    .chars()
                                    .all(|c| c.is_ascii_alphanumeric() || c == '_')),
                        "a comment above something that is not an item: {at}"
                    );
                }
                pending = false;
            }
        }
        assert!(files >= 6, "{files} files");
    }

    /// The methods of the definition: their comment (the lines of `#`
    /// before them) and their parameters, by name.
    fn idl_methods(text: &str) -> Vec<(String, String, Vec<String>)> {
        let mut out = Vec::new();
        let mut comment = String::new();
        for line in text.lines() {
            if let Some(c) = line.strip_prefix('#') {
                comment.push_str(c);
                comment.push('\n');
                continue;
            }
            if let Some(rest) = line.strip_prefix("method ") {
                let (name, rest) = rest.split_once('(').unwrap();
                let inputs = &rest[..rest.find(") ->").unwrap()];
                let params = inputs
                    .split(',')
                    .filter_map(|p| p.split_once(':'))
                    .map(|(n, _)| n.trim().rsplit(' ').next().unwrap().to_string())
                    .collect();
                out.push((name.to_string(), std::mem::take(&mut comment), params));
            } else if !line.starts_with(char::is_whitespace) {
                comment.clear();
            }
        }
        out
    }

    /// The methods of a Rust trait or impl in `source`: the name in the
    /// definition (the one its `rename` attribute gives, if any), whether it
    /// passes descriptors, its parameters (not the descriptors, not `more`).
    fn rust_methods(source: &str) -> Vec<(String, bool, Vec<String>)> {
        // (the attributes of a method end the text before its `async fn`)
        let attributes = |part: &str| {
            let fds = part.lines().rev().take(4).any(|l| l.contains("return_fds"));
            let renamed = part.lines().rev().take(4).find_map(|l| {
                let (_, rest) = l.split_once("zlink(rename = \"")?;
                Some(rest[..rest.find('"')?].to_string())
            });
            (fds, renamed)
        };
        let mut out = Vec::new();
        let (mut fds, mut renamed) = (false, None);
        for (i, part) in source.split("async fn ").enumerate() {
            if i == 0 {
                (fds, renamed) = attributes(part);
                continue;
            }
            let Some((name, rest)) = part.split_once('(') else {
                continue;
            };
            let Some(end) = rest.find("->") else {
                continue;
            };
            let args = rest[..end].trim_end().trim_end_matches(')');
            let mut params = Vec::new();
            let mut takes = fds;
            for arg in args.split(',') {
                let arg = arg.trim();
                if arg.contains("zlink(fds)") {
                    takes = true;
                    continue;
                }
                if let Some((n, _)) = arg.split_once(':') {
                    let n = n.trim();
                    if n != "more" {
                        params.push(n.to_string());
                    }
                }
            }
            let camel: String = renamed.take().unwrap_or_else(|| {
                name.split('_')
                    .map(|w| {
                        let mut c = w.chars();
                        c.next()
                            .map(|f| f.to_ascii_uppercase().to_string() + c.as_str())
                            .unwrap_or_default()
                    })
                    .collect()
            });
            out.push((camel, takes, params));
            (fds, renamed) = attributes(part);
        }
        out
    }

    /// The definition is a contract a client in another language can use:
    /// no rustdoc in its comments, every method documented, the methods
    /// that pass descriptors say so; and the client side of the interface
    /// (`EngineProxy`) has the methods and the parameters the engine serves.
    #[test]
    fn the_interface_file_is_a_contract() {
        let text = definition();
        let mut wrong = Vec::new();
        for line in text.lines().filter(|l| l.contains("[`")) {
            wrong.push(format!("rustdoc: {line}"));
        }
        let served = idl_methods(&text);
        assert!(served.len() > 90, "{}", served.len());
        let source = include_str!("engine_service.rs");
        let service = &source[source.find("mod service {").unwrap()..];
        let service = &service[..service
            .find("\n    /// The interface as the macro described it")
            .unwrap()];
        let rust = rust_methods(service);
        for (name, comment, _) in &served {
            if comment.trim().is_empty() {
                wrong.push(format!("{name} has no comment"));
            }
            let (_, takes, _) = rust.iter().find(|(n, _, _)| n == name).unwrap();
            if *takes && !comment.contains("descriptor") {
                wrong.push(format!("{name} does not say its descriptors"));
            }
        }
        let proxy = include_str!("../crates/proto/src/engine.rs");
        let proxy = &proxy[proxy.find("pub trait EngineProxy").unwrap()..];
        let proxied = rust_methods(proxy);
        for (name, _, _) in &served {
            if !proxied.iter().any(|(p, _, _)| p == name) {
                wrong.push(format!("the proxy has no {name}"));
            }
        }
        // (a method the proxy calls both ways, `ImagePull` with and without
        // more, is there twice under its name)
        for (name, _, params) in proxied {
            match served.iter().find(|(n, _, _)| *n == name) {
                None => wrong.push(format!(
                    "the proxy has {name}, which the engine does not serve"
                )),
                Some((_, _, served_params)) if *served_params != params => wrong.push(format!(
                    "the parameters of {name}: {params:?} in the proxy, {served_params:?} served"
                )),
                Some(_) => {}
            }
        }
        // every type a field names is defined (a type the macro was not
        // told of is named but not described)
        let defined: Vec<&str> = text
            .lines()
            .filter_map(|l| l.strip_prefix("type "))
            .filter_map(|l| l.split([' ', '(']).next())
            .collect();
        for named in named_types(&text) {
            if !defined.contains(&named.as_str()) {
                wrong.push(format!("the type {named} is named but not defined"));
            }
        }
        assert!(wrong.is_empty(), "{}", wrong.join("\n"));
    }

    /// The types the fields and the parameters of a definition name (after
    /// `: `, through `?`, `[]` and `[string]`).
    fn named_types(text: &str) -> std::collections::BTreeSet<String> {
        let mut out = std::collections::BTreeSet::new();
        for line in text.lines().filter(|l| !l.starts_with('#')) {
            let mut rest = line;
            while let Some(at) = rest.find(": ") {
                let mut t = &rest[at + 2..];
                loop {
                    let shorter = t
                        .strip_prefix('?')
                        .or_else(|| t.strip_prefix("[]"))
                        .or_else(|| t.strip_prefix("[string]"));
                    match shorter {
                        Some(s) => t = s,
                        None => break,
                    }
                }
                let name: String = t
                    .chars()
                    .take_while(|c| c.is_ascii_alphanumeric())
                    .collect();
                if name.starts_with(|c: char| c.is_ascii_uppercase()) {
                    out.insert(name);
                }
                rest = &rest[at + 2..];
            }
        }
        out
    }

    #[test]
    fn the_named_types_are_found() {
        let text = "type A (b: ?[]B, c: [string]C, d: string, e: ?int)\n# x: Nope\nmethod M(f: F) -> (g: []G)";
        assert_eq!(
            named_types(text).into_iter().collect::<Vec<_>>(),
            ["B", "C", "F", "G"]
        );
    }

    /// A small document is in the reply, a large one in a pipe the engine
    /// fills: the bytes are those of the array, whole.
    #[tokio::test]
    async fn a_document_is_inline_when_small_and_a_pipe_when_large() {
        let small: Vec<Value> = (0..3).map(|i| serde_json::json!({"Id": i})).collect();
        let (docs, fds) = documents(small.clone()).unwrap();
        assert_eq!(docs.inline.as_ref(), Some(&small));
        assert!(fds.is_empty() && docs.fd.is_none());
        assert_eq!(
            docs.length,
            serde_json::to_vec(&small).unwrap().len() as u64
        );

        let large: Vec<Value> = (0..4000)
            .map(|i| serde_json::json!({"Id": format!("{i:064}"), "Names": ["x"]}))
            .collect();
        let want = serde_json::to_vec(&large).unwrap();
        assert!(want.len() > INLINE_MAX);
        let (docs, fds) = documents(large).unwrap();
        assert!(docs.inline.is_none());
        assert_eq!((docs.fd, docs.length), (Some(0), want.len() as u64));
        let read = fds.into_iter().next().unwrap();
        let got = tokio::task::spawn_blocking(move || {
            let mut out = Vec::new();
            std::fs::File::from(read).read_to_end(&mut out).unwrap();
            out
        })
        .await
        .unwrap();
        assert_eq!(got, want, "the pipe holds the array and ends");
    }

    #[test]
    fn filters_are_bounded() {
        let many = vec![Filter::default(); MAX_FILTERS + 1];
        assert!(matches!(
            filters_of(many),
            Err(EngineError::InvalidArgument { .. })
        ));
        let ok = filters_of(vec![Filter {
            key: "label".into(),
            values: vec!["a".into()],
        }])
        .unwrap();
        assert_eq!(ok.get("label"), ["a".to_string()]);
    }

    /// The engine with services in a directory of its own.
    async fn engine_in(dir: &Path) -> Engine {
        engine_with(dir, |_| {}).await
    }

    async fn engine_with(dir: &Path, tune: impl FnOnce(&mut Config)) -> Engine {
        let mut config = Config::default();
        tune(&mut config);
        config.server.state_dir = dir.join("run");
        config.server.root_dir = dir.join("root");
        config.server.socket = dir.join("run/velarx.sock");
        config.storage.root = dir.join("storage");
        config.storage.gc_interval_secs = 0;
        // (an import reads its tar through the origin of a path, which is
        // not next to the test executable)
        config.pull.dir_path = velarx_base::testing::built_binary("velarx-dir");
        let state = build_services(Arc::new(config), &dir.join("config.toml"), &Role::Server)
            .await
            .unwrap();
        Engine::new(state, Holds::default())
    }

    /// The work of a call that waits stops when the call is dropped (its
    /// client closed the connection), and that of one that changes
    /// something goes on.
    #[tokio::test]
    async fn a_call_that_waits_stops_with_its_client() {
        struct Tell(Option<tokio::sync::oneshot::Sender<()>>);
        impl Drop for Tell {
            fn drop(&mut self) {
                if let Some(tx) = self.0.take() {
                    let _ = tx.send(());
                }
            }
        }
        let dir = tempfile::tempdir().unwrap();
        let engine = engine_in(dir.path()).await;
        let (tx, rx) = tokio::sync::oneshot::channel();
        let (started, running) = tokio::sync::oneshot::channel();
        let call = engine.api_cancelled(ErrorKind::None, |_| async move {
            let _tell = Tell(Some(tx));
            let _ = started.send(());
            std::future::pending::<crate::api::podman::error::ApiResult<()>>().await
        });
        running.await.unwrap();
        drop(call);
        // (the task was aborted: its guard went)
        assert_eq!(rx.await, Ok(()));
        // the other kind of call is not stopped
        let (tx, mut rx) = tokio::sync::oneshot::channel();
        let (started, running) = tokio::sync::oneshot::channel();
        let call = engine.api(ErrorKind::None, |_| async move {
            let _tell = Tell(Some(tx));
            let _ = started.send(());
            std::future::pending::<crate::api::podman::error::ApiResult<()>>().await
        });
        running.await.unwrap();
        drop(call);
        tokio::task::yield_now().await;
        assert!(rx.try_recv().is_err());
    }

    /// A stream is a pipe: what the engine emits arrives, nothing times it
    /// out while idle, and it ends (the task, and the engine's busy mark)
    /// when the reader closes its end, with nothing written to notice it.
    #[tokio::test]
    async fn a_stream_ends_when_its_reader_goes_away() {
        use tokio::io::AsyncBufReadExt;
        let dir = tempfile::tempdir().unwrap();
        let engine = engine_in(dir.path()).await;
        let activity = Activity::new(activation::Limits::default());
        engine.holds.served_by(&activity);
        let (reply, mut fds) = with_fds(engine.open_stream(false, move |w| async move {
            let mut out = JsonLines::new(w);
            let mut n = 0;
            while out.send(&serde_json::json!({"n": n})).await {
                n += 1;
                // (idle: only the end of the reader stops it)
                let idle = tokio::time::sleep(std::time::Duration::from_secs(3600));
                if out.while_there(idle).await.is_none() {
                    return;
                }
            }
        }));
        assert_eq!(reply.unwrap(), Stream { tty: false });
        assert_eq!(activity.active(), 1, "a stream keeps the engine busy");
        let read = tokio::net::unix::pipe::Receiver::from_owned_fd(fds.remove(0)).unwrap();
        let mut lines = tokio::io::BufReader::new(read);
        let mut line = String::new();
        lines.read_line(&mut line).await.unwrap();
        assert_eq!(line, "{\"n\":0}\n");
        // (it waits an hour for the next: the reader leaves)
        drop(lines);
        tokio::time::timeout(std::time::Duration::from_secs(5), activity.wait_idle())
            .await
            .expect("the stream outlived its reader");
    }

    /// The streams of a process are the replies of a session the frontend
    /// gets (and the log of an attach a pipe): the engine is busy while the
    /// session lasts, and the session sees its client leave, idle or not.
    #[tokio::test]
    async fn a_session_is_replies_that_end_with_its_client() {
        use futures::StreamExt;
        use tokio::io::AsyncReadExt;
        use velarx_proto::stream::Event;
        let dir = tempfile::tempdir().unwrap();
        let engine = engine_in(dir.path()).await;
        let activity = Activity::new(activation::Limits::default());
        engine.holds.served_by(&activity);
        let opened = |logs: bool| velarx_proto::engine::SessionOpened {
            session: String::new(),
            tty: false,
            stdin: true,
            stdout: true,
            stderr: true,
            logs: logs.then_some(0),
            detach_keys: Vec::new(),
            keep_open: false,
        };
        let mut replies = engine.open_session(opened(true), |out, log, busy| async move {
            let _busy = busy;
            use tokio::io::AsyncWriteExt;
            log.unwrap().write_all(b"log").await.unwrap();
            assert_eq!(out.event().await, Event::Gone);
        });
        let (first, mut fds) = replies.next().await.unwrap();
        let first = first.unwrap();
        let reply = first.parameters().unwrap();
        assert_eq!(reply.phase, SessionPhase::Accepted);
        assert!(reply.opened.as_ref().unwrap().logs.is_some());
        assert_eq!(fds.len(), 1, "the log");
        assert_eq!(activity.active(), 1);
        let mut log = Vec::new();
        tokio::net::unix::pipe::Receiver::from_owned_fd(fds.pop().unwrap())
            .unwrap()
            .read_to_end(&mut log)
            .await
            .unwrap();
        assert_eq!(log, b"log");
        // (the frontend closes the connection: the replies are dropped, and
        // the client is gone)
        drop(replies);
        tokio::time::timeout(std::time::Duration::from_secs(5), activity.wait_idle())
            .await
            .expect("the session outlived its client");
        let mut replies = engine.open_session(opened(false), |_, log, _| async move {
            assert!(log.is_none());
        });
        let (first, fds) = replies.next().await.unwrap();
        assert!(first
            .unwrap()
            .parameters()
            .unwrap()
            .opened
            .as_ref()
            .unwrap()
            .logs
            .is_none());
        assert!(fds.is_empty());
        // (the session ended without a word: the last reply says so)
        let (last, _) = replies.next().await.unwrap();
        assert_eq!(
            last.unwrap().parameters().unwrap().phase,
            SessionPhase::Ended
        );
    }

    /// The future that serves a connection is small: a call holds the
    /// handle of the work it spawned, not the work (see [`Engine::run`]).
    /// With the work in it, it was 83 kB in a debug build, and the frames of
    /// the dispatch overflowed the 2 MiB stack of the service thread.
    #[tokio::test]
    async fn the_future_of_a_connection_is_small() {
        let dir = tempfile::tempdir().unwrap();
        let engine = engine_in(dir.path()).await;
        let (a, _b) = tokio::net::UnixStream::pair().unwrap();
        let stream = zlink::tokio::unix::Stream::try_from(a).unwrap();
        let server = zlink::Server::new(zlink::ReadyListener::new(stream), engine);
        let served = server.run();
        let size = std::mem::size_of_val(&served);
        assert!(
            size < 16 * 1024,
            "the future of a connection is {size} bytes"
        );
    }

    /// The runtime directory the engine makes is private, so the engine's
    /// socket can be bound next to the API's after any command made it.
    #[tokio::test]
    async fn the_runtime_directory_is_private_for_the_engine_socket() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let _engine = engine_in(dir.path()).await;
        let run = dir.path().join("run");
        let mode = std::fs::metadata(&run).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o700);
        let bound = activation::connect_or_bind(&run.join("engine.sock")).unwrap();
        assert!(bound.is_err(), "nothing served it: bound here");
    }

    /// A frontend's calls against the service on a socket: the version is
    /// checked, the lists of an empty store are empty, a bad filter is an
    /// error as podman's, and more filters than allowed are refused.
    /// A method without parameters is called with `"parameters": {}` or
    /// without them, as is one whose parameters are all optional (varlink
    /// allows both, clients in other languages send either); a call that
    /// does not match its method is answered `InvalidParameter`, not cut.
    #[tokio::test]
    async fn a_call_is_taken_with_either_form_of_no_parameters() {
        let dir = tempfile::tempdir().unwrap();
        let engine = engine_in(dir.path()).await;
        let local = tokio::task::LocalSet::new();
        local
            .run_until(async {
                let socket = dir.path().join("engine.sock");
                let listener = tokio::net::UnixListener::bind(&socket).unwrap();
                tokio::task::spawn_local(activation::serve_varlink(
                    listener,
                    None,
                    |_| true,
                    activation::Limits::default(),
                    "engine test",
                    engine,
                ));
                let answers = tokio::task::spawn_blocking(move || {
                    use std::io::{BufRead, Write};
                    let calls = [
                        r#"{"method":"org.velarx.Engine.GetInfo","parameters":{}}"#,
                        r#"{"method":"org.velarx.Engine.GetInfo"}"#,
                        r#"{"method":"org.velarx.Engine.PodMetricsList","more":true}"#,
                        r#"{"method":"org.velarx.Engine.PodMetricsList","parameters":{},"more":true}"#,
                        r#"{"method":"org.velarx.Engine.ContainerInspect","parameters":{"name":3}}"#,
                    ];
                    calls
                        .iter()
                        .map(|call| {
                            let mut conn = std::os::unix::net::UnixStream::connect(&socket).unwrap();
                            conn.write_all(call.as_bytes()).unwrap();
                            conn.write_all(b"\0").unwrap();
                            let mut answer = Vec::new();
                            std::io::BufReader::new(conn).read_until(0, &mut answer).unwrap();
                            answer.pop();
                            serde_json::from_slice::<Value>(&answer).unwrap()
                        })
                        .collect::<Vec<_>>()
                })
                .await
                .unwrap();
                for answer in &answers[..2] {
                    assert_eq!(answer["parameters"]["name"], "velarx", "{answer}");
                }
                for answer in &answers[2..4] {
                    assert!(answer.get("error").is_none(), "{answer}");
                }
                assert_eq!(
                    answers[4]["error"], "org.varlink.service.InvalidParameter",
                    "{}",
                    answers[4]
                );
            })
            .await;
    }

    /// Run `test` on a thread with the stack of the service thread, as the
    /// connections of the engine are served (a test thread has 2 MiB).
    fn on_service_stack<F: Future<Output = ()> + 'static>(
        test: impl FnOnce() -> F + Send + 'static,
    ) {
        let joined = std::thread::Builder::new()
            .stack_size(SERVICE_STACK)
            .spawn(move || {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap()
                    .block_on(test())
            })
            .unwrap()
            .join();
        if let Err(panic) = joined {
            std::panic::resume_unwind(panic);
        }
    }

    /// The engine tries a pull that fails on the way again as the spec says
    /// (no client does): a fetcher that drops every connection
    /// is asked the same number of times at each try, and `count` more
    /// times with `retry`.
    #[test]
    fn a_pull_that_fails_on_the_way_is_tried_again_by_the_engine() {
        on_service_stack(|| async {
            let dir = tempfile::tempdir().unwrap();
            // (a fetcher that notes it was started and leaves: every
            // connection to it is dropped)
            let (fetcher, started) = (dir.path().join("fetcher"), dir.path().join("started"));
            velarx_base::testing::write_script(
                &fetcher,
                &format!("echo >> {}\nexit 0", started.display()),
            );
            let engine = engine_with(dir.path(), |c| c.pull.registry_path = Some(fetcher)).await;
            let local = tokio::task::LocalSet::new();
            local
                .run_until(async {
                    let socket = dir.path().join("engine.sock");
                    let listener = tokio::net::UnixListener::bind(&socket).unwrap();
                    tokio::task::spawn_local(activation::serve_varlink(
                        listener,
                        None,
                        |_| true,
                        activation::Limits::default(),
                        "engine test",
                        engine,
                    ));
                    let connections =
                        || std::fs::read_to_string(&started).map_or(0, |text| text.lines().count());
                    let mut conn = connect_checked(&socket).await.expect("the version matches");
                    let mut asked = Vec::new();
                    for count in [0, 2] {
                        let before = connections();
                        let spec = PullSpec {
                            source: "registry.invalid/app:v1".into(),
                            tls_verify: false,
                            retry: Retry {
                                count,
                                delay_ms: Some(0),
                            },
                            ..Default::default()
                        };
                        let reply = conn.image_pull(spec, None, Vec::new()).await.unwrap();
                        assert!(reply.is_err(), "{reply:?}");
                        asked.push(connections() - before);
                    }
                    assert!(asked[0] > 0, "{asked:?}");
                    assert_eq!(asked[1], 3 * asked[0], "tries: {asked:?}");
                })
                .await;
        });
    }

    #[test]
    fn the_service_answers_a_frontend_over_a_socket() {
        on_service_stack(the_service_answers_a_frontend_over_a_socket_here);
    }

    async fn the_service_answers_a_frontend_over_a_socket_here() {
        let dir = tempfile::tempdir().unwrap();
        let engine = engine_in(dir.path()).await;
        let local = tokio::task::LocalSet::new();
        local
            .run_until(async {
                let socket = dir.path().join("engine.sock");
                let listener = tokio::net::UnixListener::bind(&socket).unwrap();
                tokio::task::spawn_local(activation::serve_varlink(
                    listener,
                    None,
                    |_| true,
                    activation::Limits::default(),
                    "engine test",
                    engine,
                ));
                let mut conn = connect_checked(&socket).await.expect("the version matches");
                let info = conn.get_info().await.unwrap().unwrap();
                assert_eq!((info.interface, info.name.as_str()), (PROTO, "velarx"));
                conn.ping().await.unwrap().unwrap();
                // a connection of its own is not shared with this one
                let mut other = connect::connect(&socket).await.unwrap();
                other.ping().await.unwrap().unwrap();

                // the files of an artifact are regular files open for
                // reading: not a pipe, nor a descriptor of a path
                {
                    let (pipe, _writer) = rustix::pipe::pipe().unwrap();
                    let file = dir.path().join("f");
                    std::fs::write(&file, b"x").unwrap();
                    let path = rustix::fs::open(
                        &file,
                        rustix::fs::OFlags::PATH | rustix::fs::OFlags::CLOEXEC,
                        rustix::fs::Mode::empty(),
                    )
                    .unwrap();
                    for fd in [pipe, path] {
                        let spec = ManifestArtifactSpec {
                            titles: vec!["f".into()],
                            ..Default::default()
                        };
                        match conn
                            .manifest_add_artifact("l", spec, true, None, vec![fd])
                            .await
                            .unwrap()
                        {
                            Err(EngineError::InvalidArgument { message, .. }) => assert!(
                                message.contains("not a regular file open for reading"),
                                "{message}"
                            ),
                            other => panic!("{other:?}"),
                        }
                    }
                }

                {
                    use futures::StreamExt;
                    for manifest_lists in [true, false] {
                        let replies: Vec<_> = conn
                            .image_list(vec![], false, manifest_lists)
                            .await
                            .unwrap()
                            .collect()
                            .await;
                        let [one] = replies.as_slice() else {
                            panic!("{replies:?}");
                        };
                        assert_eq!(one.as_ref().unwrap().as_ref().unwrap().image, None);
                    }
                    let replies: Vec<_> = conn
                        .image_list(
                            vec![Filter {
                                key: "nonsense".into(),
                                values: vec!["x".into()],
                            }],
                            false,
                            true,
                        )
                        .await
                        .unwrap()
                        .collect()
                        .await;
                    match replies.into_iter().next().unwrap().unwrap() {
                        Err(EngineError::InvalidArgument { message, .. }) => {
                            assert!(message.contains("invalid image filter"), "{message}");
                        }
                        other => panic!("{other:?}"),
                    }
                }
                {
                    use futures::StreamExt;
                    let replies: Vec<_> = conn
                        .container_list(
                            vec![Filter::default(); MAX_FILTERS + 1],
                            false,
                            false,
                            false,
                            -1,
                        )
                        .await
                        .unwrap()
                        .collect()
                        .await;
                    assert!(matches!(
                        replies.into_iter().next().unwrap().unwrap(),
                        Err(EngineError::InvalidArgument { .. })
                    ));
                }

                // the records of the CRI: empty lists, a name for what is not there
                // (a list is one reply without a record when it is empty)
                {
                    use futures::StreamExt;
                    let replies: Vec<_> = conn
                        .container_list(vec![], true, false, false, -1)
                        .await
                        .unwrap()
                        .collect()
                        .await;
                    assert_eq!(replies.len(), 1);
                    let only = replies.into_iter().next().unwrap().unwrap().unwrap();
                    assert_eq!(only.container, None);
                }
                let listed = connect::records(conn.pod_list(vec![]).await.unwrap(), Some)
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(listed, [PodListed { pod: None }], "PodList");
                let listed = connect::records(
                    conn.image_list(vec![], false, true).await.unwrap(),
                    Some,
                )
                .await
                .unwrap()
                .unwrap();
                assert_eq!(listed, [ImageListed { image: None }], "ImageList");
                let listed = connect::records(
                    conn.container_list(vec![], true, false, false, -1)
                        .await
                        .unwrap(),
                    Some,
                )
                .await
                .unwrap()
                .unwrap();
                assert_eq!(listed, [ContainerListed { container: None }], "ContainerList");
                let listed = connect::records(
                    conn.container_stats(vec![], false, false, false, None)
                        .await
                        .unwrap(),
                    Some,
                )
                .await
                .unwrap()
                .unwrap();
                assert_eq!(listed, [StatsListed { stats: None }]);
                let listed = connect::records(
                    conn.metric_descriptor_list().await.unwrap(),
                    Some,
                )
                .await
                .unwrap()
                .unwrap();
                assert!(listed.len() > 3 && listed.iter().all(|d| d.descriptor.is_some()));
                // (a list is asked for with more)
                let call = zlink::Call::new(serde_json::json!({
                    "method": "org.velarx.Engine.PodList",
                    "parameters": {"filters": []}
                }));
                conn.send_call(&call, Vec::new()).await.unwrap();
                let (reply, _) = conn
                    .receive_reply::<serde_json::Value, EngineError>()
                    .await
                    .unwrap();
                assert!(matches!(reply, Err(EngineError::InvalidArgument { .. })), "{reply:?}");
                // (the binary of the engine is the one installed)
                let reply = conn.restart(None).await.unwrap().unwrap();
                assert!(!reply.restarted);
                let reply = conn.container_inspect("nosuch", false).await.unwrap();
                assert!(matches!(reply, Err(EngineError::NoSuchContainer { .. })), "{reply:?}");
                let reply = conn.pod_inspect("nosuch").await.unwrap();
                assert!(matches!(reply, Err(EngineError::NoSuchPod { .. })), "{reply:?}");
                let reply = conn.image_inspect("nosuch").await.unwrap();
                assert!(matches!(reply, Err(EngineError::NoSuchImage { .. })), "{reply:?}");
                // (a reference refused before the lookup is its own condition, with
                // podman's status; a name that holds its words is an image that is not there)
                let reply = conn.image_inspect("Upper/Case").await.unwrap();
                assert!(matches!(reply, Err(EngineError::InvalidReference { .. })), "{reply:?}");
                let reply = conn
                    .image_inspect("localhost/repository-name-must-be-lowercase")
                    .await
                    .unwrap();
                assert!(matches!(reply, Err(EngineError::NoSuchImage { .. })), "{reply:?}");
                // (a container named so is a container that is not there)
                let reply = conn.container_inspect("no such container", false).await.unwrap();
                assert!(matches!(reply, Err(EngineError::NoSuchContainer { .. })), "{reply:?}");
                let spec = VolumeSpec {
                    name: "not/a/volume".into(),
                    ..Default::default()
                };
                let reply = conn.volume_create(&spec, false).await.unwrap();
                assert!(matches!(reply, Err(EngineError::InvalidName { .. })), "{reply:?}");
                let reply = conn
                    .exec_create("nosuch", ExecSpec::default())
                    .await
                    .unwrap();
                assert!(matches!(reply, Err(EngineError::NoSuchContainer { .. })), "{reply:?}");
                let reply = conn.exec_inspect("nosuch").await.unwrap();
                assert!(matches!(reply, Err(EngineError::NoSuchExecSession { .. })), "{reply:?}");
                let reply = conn.network_check("nosuch").await.unwrap();
                assert!(matches!(reply, Err(EngineError::InvalidArgument { .. })), "{reply:?}");
                let info = conn.runtime_inspect().await.unwrap().unwrap();
                assert_eq!(info.name, "velarx");
                assert!(!info.api_version.is_empty());
                let usage = conn.storage_inspect().await.unwrap().unwrap();
                assert!(!usage.mountpoint.is_empty());
                // a spec is JSON in a pipe, and what is not a spec is refused
                let junk = b"{\"image\": 1}".to_vec();
                let read = connect::filled_pipe(junk).unwrap();
                let reply = conn.container_create(0, vec![read]).await.unwrap();
                assert!(matches!(reply, Err(EngineError::InvalidArgument { .. })), "{reply:?}");
                let spec = serde_json::to_vec(&velarx_proto::request::CreateContainerRequest {
                    name: Some("c".into()),
                    image: "localhost/nosuch:1".into(),
                    ..Default::default()
                })
                .unwrap();
                let read = connect::filled_pipe(spec).unwrap();
                let reply = conn.container_create(0, vec![read]).await.unwrap();
                assert!(matches!(reply, Err(EngineError::NoSuchImage { .. })), "{reply:?}");
                // an answer no build asked for; one that is not credentials
                // (what it held is not repeated)
                let answer = b"{\"r.io\": {\"username\": \"u\", \"password\": \"p\"}}".to_vec();
                let file = velarx_base::sealed::sealed_memory(&answer).unwrap();
                let reply = conn.image_build_answer("1", 0, vec![file]).await.unwrap();
                assert!(matches!(reply, Err(EngineError::NoSuchObject { .. })), "{reply:?}");
                let answer = b"{\"r.io\": \"hunter2\"}".to_vec();
                let file = velarx_base::sealed::sealed_memory(&answer).unwrap();
                let reply = conn.image_build_answer("1", 0, vec![file]).await.unwrap();
                assert!(matches!(reply, Err(EngineError::InvalidArgument { .. })), "{reply:?}");
                assert!(!format!("{reply:?}").contains("hunter2"), "{reply:?}");

                // a build context that is a directory: it carries no sections,
                // no spec that names another place for it; one that is a
                // regular file is neither a directory nor a pipe
                let dir = rustix::fs::open(
                    ".",
                    rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::DIRECTORY,
                    rustix::fs::Mode::empty(),
                )
                .unwrap();
                let body = serde_json::to_vec(&velarx_proto::buildspec::BuildSpec::default()).unwrap();
                let (reply, _) = conn
                    .image_build(
                        0,
                        Some(1),
                        true,
                        None,
                        vec![connect::filled_pipe(body.clone()).unwrap(), dir.try_clone().unwrap()],
                    )
                    .await
                    .unwrap();
                assert!(matches!(reply, Err(EngineError::InvalidArgument { .. })), "{reply:?}");
                let named = serde_json::to_vec(&velarx_proto::buildspec::BuildSpec {
                    local_dir: Some("/".into()),
                    ..Default::default()
                })
                .unwrap();
                let (reply, _) = conn
                    .image_build(
                        0,
                        Some(1),
                        false,
                        None,
                        vec![connect::filled_pipe(named).unwrap(), dir],
                    )
                    .await
                    .unwrap();
                assert!(matches!(reply, Err(EngineError::InvalidArgument { .. })), "{reply:?}");
                let file = std::fs::File::open("/dev/null").unwrap();
                let (reply, _) = conn
                    .image_build(
                        0,
                        Some(1),
                        false,
                        None,
                        vec![connect::filled_pipe(body).unwrap(), file.into()],
                    )
                    .await
                    .unwrap();
                assert!(reply.is_err(), "{reply:?}");

                // a wait of what is not there; events that end; a pull that
                // fails, with more and without
                for (interval, refused) in [(-1, "InvalidArgument"), (0, "NoSuchContainer")] {
                    let replies = conn
                        .container_wait("nosuch", vec![], interval)
                        .await
                        .unwrap();
                    let mut replies = std::pin::pin!(replies);
                    let reply = futures::StreamExt::next(&mut replies).await.unwrap().unwrap();
                    assert!(
                        format!("{reply:?}").starts_with(&format!("Err({refused}")),
                        "{reply:?}"
                    );
                }
                let listed = connect::records(
                    conn.event_list(vec![], None, None, false).await.unwrap(),
                    Some,
                )
                .await
                .unwrap()
                .unwrap();
                assert_eq!(listed.last(), Some(&EventListed { event: None }));
                let nonsense = Filter {
                    key: "nonsense".into(),
                    values: vec![],
                };
                let listed = connect::records(
                    conn.event_list(vec![nonsense], None, None, false)
                        .await
                        .unwrap(),
                    Some,
                )
                .await
                .unwrap();
                assert!(matches!(listed, Err(EngineError::InvalidArgument { .. })), "{listed:?}");
                let spec = PullSpec {
                    source: "not a reference!".into(),
                    ..Default::default()
                };
                let reply = conn.image_pull(spec, None, Vec::new()).await.unwrap();
                assert!(matches!(reply, Err(EngineError::InvalidArgument { .. })), "{reply:?}");
                let spec = PullSpec {
                    source: "not a reference!".into(),
                    ..Default::default()
                };
                let listed = connect::records(
                    conn.image_pull_progress(spec, None, Vec::new())
                        .await
                        .unwrap(),
                    Some,
                )
                .await
                .unwrap();
                assert!(matches!(listed, Err(EngineError::InvalidArgument { .. })), "{listed:?}");

                // a checkpoint writes in the empty regular file it carries, or
                // the frames in the pipe
                let flags = CheckpointFlags::default();
                let reply = conn
                    .container_checkpoint("nosuch", flags.clone(), Some(0), vec![])
                    .await
                    .unwrap();
                assert!(matches!(reply, Err(EngineError::InvalidArgument { .. })));
                let (_read, write) =
                    rustix::pipe::pipe_with(rustix::pipe::PipeFlags::CLOEXEC).unwrap();
                let reply = conn
                    .container_checkpoint("nosuch", flags.clone(), Some(0), vec![write])
                    .await
                    .unwrap();
                assert!(
                    matches!(reply, Err(EngineError::NoSuchContainer { .. })),
                    "a pipe is the frames of a download: {reply:?}"
                );
                let directory = std::fs::File::open("/").unwrap();
                let reply = conn
                    .container_checkpoint("nosuch", flags.clone(), Some(0), vec![directory.into()])
                    .await
                    .unwrap();
                assert!(
                    matches!(&reply, Err(EngineError::InvalidArgument { message, .. }) if message.contains("regular file")),
                    "{reply:?}"
                );
                let reply = conn
                    .container_checkpoint("nosuch", flags.clone(), None, vec![])
                    .await
                    .unwrap();
                assert!(
                    // (rootless: CRIU needs root, which is said first)
                    matches!(reply, Err(EngineError::NoSuchContainer { .. }) | Err(EngineError::NotSupported { .. })),
                    "in place: {reply:?}"
                );
                let dir = tempfile::tempdir().unwrap();
                let named = dir.path().join("a.tar");
                std::fs::write(&named, b"x").unwrap();
                let full = std::fs::OpenOptions::new().write(true).open(&named).unwrap();
                let reply = conn
                    .container_checkpoint("nosuch", flags.clone(), Some(0), vec![full.into()])
                    .await
                    .unwrap();
                assert!(
                    matches!(&reply, Err(EngineError::InvalidArgument { message, .. }) if message.contains("not empty")),
                    "{reply:?}"
                );
                std::fs::write(&named, b"").unwrap();
                let read_only = std::fs::File::open(&named).unwrap();
                let reply = conn
                    .container_checkpoint("nosuch", flags.clone(), Some(0), vec![read_only.into()])
                    .await
                    .unwrap();
                assert!(
                    matches!(&reply, Err(EngineError::InvalidArgument { message, .. }) if message.contains("for writing")),
                    "{reply:?}"
                );
                let empty = std::fs::OpenOptions::new().write(true).open(&named).unwrap();
                let reply = conn
                    .container_checkpoint("nosuch", flags, Some(0), vec![empty.into()])
                    .await
                    .unwrap();
                assert!(
                    matches!(reply, Err(EngineError::NoSuchContainer { .. })),
                    "{reply:?}"
                );
            })
            .await;
    }

    /// `ContainerWait` called with `more`: a first reply once the wait is
    /// armed, then the condition met; the wait of a caller that closed the
    /// connection ends, and its subscriptions with it.
    #[tokio::test]
    async fn a_wait_is_armed_then_met_and_ends_with_its_caller() {
        use velarx_proto::wait::WaitCondition as W;
        let dir = tempfile::tempdir().unwrap();
        let engine = engine_in(dir.path()).await;
        let state = engine.state.clone();
        state
            .db
            .insert_image(&velarx_db::ImageRecord {
                id: "i".into(),
                manifest_digest: velarx_types::digest::Digest::of(
                    velarx_types::digest::Algorithm::Sha256,
                    b"m",
                ),
                config_digest: velarx_types::digest::Digest::of(
                    velarx_types::digest::Algorithm::Sha256,
                    b"c",
                ),
                manifest: "{}".into(),
                config: "{}".into(),
                created_at: "2026-01-01T00:00:00Z".into(),
                is_lazy: false,
            })
            .await
            .unwrap();
        state
            .db
            .insert_container(&velarx_db::ContainerRecord {
                id: "c1".into(),
                name: Some("waited".into()),
                image_id: "i".into(),
                config: serde_json::to_string(&velarx_runtime::container::ContainerConfig {
                    id: "c1".into(),
                    ..Default::default()
                })
                .unwrap(),
                state: RecordState::Created,
                pid: None,
                created_at: "2026-01-01T00:00:00Z".into(),
                started_at: None,
                finished_at: None,
                exit_code: None,
            })
            .await
            .unwrap();
        #[derive(serde::Serialize, Debug)]
        struct Parameters {
            name: &'static str,
            conditions: Vec<W>,
            interval_ns: i64,
        }
        #[derive(serde::Serialize, Debug)]
        struct MethodCall {
            method: &'static str,
            parameters: Parameters,
        }
        let call = |conditions| {
            zlink::Call::new(MethodCall {
                method: "org.velarx.Engine.ContainerWait",
                parameters: Parameters {
                    name: "waited",
                    conditions,
                    interval_ns: 0,
                },
            })
            .set_more(true)
        };
        let local = tokio::task::LocalSet::new();
        local
            .run_until(async {
                let socket = dir.path().join("engine.sock");
                let listener = tokio::net::UnixListener::bind(&socket).unwrap();
                tokio::task::spawn_local(activation::serve_varlink(
                    listener,
                    None,
                    |_| true,
                    activation::Limits::default(),
                    "engine test",
                    engine,
                ));
                let mut conn = connect_checked(&socket).await.unwrap();
                conn.send_call(&call(vec![W::NextExit]), vec![])
                    .await
                    .unwrap();
                let (armed, _) = conn
                    .read_mut()
                    .receive_reply::<Waited, EngineError>()
                    .await
                    .unwrap();
                let armed = armed.unwrap();
                assert_eq!(armed.continues(), Some(true));
                assert_eq!(armed.into_parameters(), Some(Waited::default()));
                // (another process records the run that follows)
                state
                    .db
                    .update_container_state(
                        "c1",
                        RecordState::Exited,
                        None,
                        Some("2026-01-01T00:00:01Z".into()),
                        Some("2026-01-01T00:00:02Z".into()),
                        Some(7),
                    )
                    .await
                    .unwrap();
                let (met, _) = conn
                    .read_mut()
                    .receive_reply::<Waited, EngineError>()
                    .await
                    .unwrap();
                let met = met.unwrap();
                assert_eq!(met.continues(), Some(false));
                assert_eq!(
                    met.into_parameters(),
                    Some(Waited {
                        status_code: Some(7),
                        condition: Some(W::NextExit),
                    })
                );

                // a caller that closes the connection ends the wait and its
                // subscriptions
                let mut conn = connect_checked(&socket).await.unwrap();
                conn.send_call(&call(vec![W::Removed]), vec![])
                    .await
                    .unwrap();
                let (armed, _) = conn
                    .read_mut()
                    .receive_reply::<Waited, EngineError>()
                    .await
                    .unwrap();
                assert_eq!(armed.unwrap().continues(), Some(true));
                assert_eq!(state.podman.change_watchers(), 1);
                drop(conn);
                state.podman.unwatched().await;
                let mut conn = connect_checked(&socket).await.unwrap();
                conn.ping().await.unwrap().unwrap();
            })
            .await;
    }

    /// The document of a pipe a call carries is what it holds to its end,
    /// never more than the most.
    #[tokio::test]
    async fn the_content_of_a_pipe_is_all_of_it_and_bounded() {
        use std::io::Write;
        let pipe = |data: &[u8]| {
            let (read, write) = rustix::pipe::pipe_with(rustix::pipe::PipeFlags::CLOEXEC).unwrap();
            std::fs::File::from(write).write_all(data).unwrap();
            read
        };
        assert_eq!(read_pipe(pipe(b"{}"), 8, "x").await.unwrap(), b"{}");
        assert_eq!(read_pipe(pipe(b""), 8, "x").await.unwrap(), b"");
        let e = read_pipe(pipe(b"{}{}{}{}{}"), 8, "x").await.unwrap_err();
        assert!(matches!(e, EngineError::InvalidArgument { .. }), "{e:?}");
        // (a writer that never closes: the call does not wait past the time)
        let (read, _write) = rustix::pipe::pipe_with(rustix::pipe::PipeFlags::CLOEXEC).unwrap();
        let short = std::time::Duration::from_millis(100);
        let e = read_pipe_within(read, 8, "x", short).await.unwrap_err();
        assert!(format!("{e:?}").contains("in time"), "{e:?}");
    }

    /// The engine of this process is not served to the users the check
    /// refuses: a rootless engine trusts its own user and root.
    #[test]
    fn the_peers_of_a_rootless_engine_are_its_user_and_root() {
        if velarx_base::ids::rootful().unwrap() {
            return;
        }
        let trusted = trusted().unwrap();
        let me = rustix::process::geteuid().as_raw();
        assert!(trusted(me) && trusted(0));
        assert!(!trusted(me + 1));
    }

    /// The memory file of a secret is read whole; one too large is refused
    /// before anything is read; one that can still change, or a pipe, is
    /// refused; and no error carries the data.
    #[test]
    fn secret_data_is_bounded_and_never_in_an_error() {
        use std::io::Write;
        use velarx_wire::wire::SECRET_MAX_SIZE;
        let sealed = |data: &[u8]| vec![velarx_base::sealed::sealed_memory(data).unwrap()];
        let ok = secret_data(sealed(b"hunter"), 0).unwrap();
        assert_eq!(&ok[..], b"hunter");
        match secret_data(sealed(&vec![0u8; SECRET_MAX_SIZE + 1]), 0) {
            Err(EngineError::TooLarge { message, .. }) => {
                assert!(message.contains("larger than"), "{message}");
            }
            other => panic!("{other:?}"),
        }
        // a memory file that is not sealed, and a pipe
        let open = rustix::fs::memfd_create("open", rustix::fs::MemfdFlags::CLOEXEC).unwrap();
        std::fs::File::from(open.try_clone().unwrap())
            .write_all(b"hunter2")
            .unwrap();
        let (read, write) = rustix::pipe::pipe_with(rustix::pipe::PipeFlags::CLOEXEC).unwrap();
        std::fs::File::from(write).write_all(b"hunter2").unwrap();
        for fd in [open, read] {
            let e = format!("{:?}", secret_data(vec![fd], 0).unwrap_err());
            assert!(!e.contains("hunter"), "{e}");
            assert!(matches!(
                secret_data(vec![], 0),
                Err(EngineError::InvalidArgument { .. })
            ));
        }
    }

    /// The credentials of a call are a sealed memory file: a pipe, or a memory
    /// file that can still change, is refused as `InvalidArgument`.
    #[test]
    fn credentials_that_are_not_a_sealed_memory_file_are_refused() {
        use std::io::Write;
        let json = b"{\"creds\":{\"username\":\"u\",\"password\":\"p\"}}";
        let access = registry_access_of(
            vec![velarx_base::sealed::sealed_memory(json).unwrap()],
            Some(0),
        )
        .unwrap();
        assert_eq!(access.creds.unwrap().username, "u");
        assert!(registry_access_of(Vec::new(), None).unwrap().is_empty());
        let open = rustix::fs::memfd_create("open", rustix::fs::MemfdFlags::CLOEXEC).unwrap();
        std::fs::File::from(open.try_clone().unwrap())
            .write_all(json)
            .unwrap();
        let (read, write) = rustix::pipe::pipe_with(rustix::pipe::PipeFlags::CLOEXEC).unwrap();
        std::fs::File::from(write).write_all(json).unwrap();
        for fd in [open, read] {
            let e = registry_access_of(vec![fd], Some(0)).unwrap_err();
            assert!(matches!(e, EngineError::InvalidArgument { .. }), "{e:?}");
            assert!(!format!("{e:?}").contains("\"p\""), "{e:?}");
        }
        // a descriptor nobody names is refused too
        let two = vec![
            velarx_base::sealed::sealed_memory(json).unwrap(),
            velarx_base::sealed::sealed_memory(json).unwrap(),
        ];
        assert!(registry_access_of(two, Some(0)).is_err());
    }

    /// A client that stops reading does not pin a document: it is dropped
    /// after the time given, and the reader sees the pipe end early.
    #[tokio::test]
    async fn a_document_nobody_reads_is_dropped() {
        use std::io::Read;
        let (read, write) = rustix::pipe::pipe_with(rustix::pipe::PipeFlags::CLOEXEC).unwrap();
        // (more than a pipe holds: the writer must wait for the reader)
        let bytes = vec![b'x'; 4 << 20];
        let sent = bytes.len();
        fill_pipe_within(write, bytes, std::time::Duration::from_millis(300)).unwrap();
        // the reader comes once the writer gave up: its end of the pipe is
        // closed (a hang-up, which poll reports with no event asked for)
        let got = tokio::task::spawn_blocking(move || {
            let mut fds = [rustix::event::PollFd::new(
                &read,
                rustix::event::PollFlags::empty(),
            )];
            let limit = rustix::time::Timespec {
                tv_sec: 30,
                tv_nsec: 0,
            };
            assert_eq!(
                rustix::event::poll(&mut fds, Some(&limit)),
                Ok(1),
                "the writer gave up"
            );
            assert!(fds[0].revents().contains(rustix::event::PollFlags::HUP));
            let mut out = Vec::new();
            std::fs::File::from(read).read_to_end(&mut out).unwrap();
            out.len()
        })
        .await
        .unwrap();
        assert!(
            got < sent,
            "{got} of {sent} bytes: the document was dropped"
        );
    }

    /// A reader that is slow but reads gets the whole document, even when
    /// it takes longer than the time a reader may stop for.
    #[tokio::test]
    async fn a_slow_reader_gets_the_whole_document() {
        use std::io::Read;
        let (read, write) = rustix::pipe::pipe_with(rustix::pipe::PipeFlags::CLOEXEC).unwrap();
        let bytes = vec![b'x'; 1 << 20];
        let sent = bytes.len();
        let stall = std::time::Duration::from_millis(300);
        fill_pipe_within(write, bytes, stall).unwrap();
        let started = std::time::Instant::now();
        let got = tokio::task::spawn_blocking(move || {
            let mut file = std::fs::File::from(read);
            let mut buf = vec![0u8; 64 << 10];
            let mut got = 0;
            loop {
                match file.read(&mut buf).unwrap() {
                    0 => return got,
                    n => got += n,
                }
                // (a slow reader)
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
        })
        .await
        .unwrap();
        assert_eq!(got, sent);
        assert!(started.elapsed() > stall * 2, "{:?}", started.elapsed());
    }

    fn spare() -> OwnedFd {
        rustix::fs::open(
            "/dev/null",
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .unwrap()
    }

    /// Once the engine decided to stop (no hold left), it takes no more
    /// holds: a frontend that comes then starts an engine of its own.
    #[tokio::test]
    async fn no_hold_once_the_engine_stops() {
        let holds = Holds::default();
        let hold = holds.add(spare()).unwrap();
        let waiting = tokio::spawn({
            let holds = holds.clone();
            async move { holds.none().await }
        });
        tokio::task::yield_now().await;
        assert!(!waiting.is_finished());
        // a second one while the first holds is taken
        let second = holds.add(spare()).unwrap();
        drop(hold);
        tokio::task::yield_now().await;
        assert!(!waiting.is_finished());
        drop(second);
        tokio::time::timeout(std::time::Duration::from_secs(5), waiting)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(holds.add(spare()).err(), Some(NoHold::Stopping));
        assert_eq!(holds.count(), 0);
    }

    /// A hold keeps the service busy: an engine that leaves when idle does
    /// not while a frontend holds it.
    #[test]
    fn a_hold_keeps_the_service_busy() {
        let holds = Holds::default();
        let activity = Activity::new(activation::Limits::default());
        holds.served_by(&activity);
        let hold = holds.add(spare()).unwrap();
        assert_eq!(activity.active(), 1);
        drop(hold);
        assert_eq!(activity.active(), 0);
    }

    /// A frontend that finds the engine already there holds it: it counts
    /// while the socket the call carried is open, and no more.
    #[tokio::test]
    async fn a_hold_counts_while_its_socket_is_open() {
        let dir = tempfile::tempdir().unwrap();
        let engine = engine_in(dir.path()).await;
        let holds = engine.holds.clone();
        tokio::task::LocalSet::new()
            .run_until(async {
                let socket = dir.path().join("engine.sock");
                let listener = tokio::net::UnixListener::bind(&socket).unwrap();
                tokio::task::spawn_local(activation::serve_varlink(
                    listener,
                    None,
                    |_| true,
                    activation::Limits::default(),
                    "engine test",
                    engine,
                ));
                assert_eq!(holds.count(), 0);
                let first = connect::hold(&socket).await.unwrap();
                let second = connect::hold(&socket).await.unwrap();
                assert_eq!(holds.count(), 2);
                drop(first);
                tokio::time::timeout(std::time::Duration::from_secs(5), holds.wait_count(1))
                    .await
                    .expect("a closed hold is released");
                // none() returns once the last is gone
                let waiting = tokio::spawn({
                    let holds = holds.clone();
                    async move { holds.none().await }
                });
                tokio::task::yield_now().await;
                assert!(!waiting.is_finished());
                drop(second);
                tokio::time::timeout(std::time::Duration::from_secs(5), waiting)
                    .await
                    .expect("none() returns when the last hold is gone")
                    .unwrap();
                assert_eq!(holds.count(), 0);
            })
            .await;
    }

    /// Only a connected unix stream socket of a trusted peer is taken as a
    /// hold from the environment of a restart.
    #[test]
    fn only_connected_unix_stream_sockets_are_holds() {
        use std::os::fd::AsFd;
        let (a, _b) = std::os::unix::net::UnixStream::pair().unwrap();
        assert!(is_hold_socket(a.as_fd()));
        let (d, _e) = std::os::unix::net::UnixDatagram::pair().unwrap();
        assert!(!is_hold_socket(d.as_fd()));
        let dir = tempfile::tempdir().unwrap();
        let l = std::os::unix::net::UnixListener::bind(dir.path().join("s")).unwrap();
        assert!(!is_hold_socket(l.as_fd()));
        let t = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let c = std::net::TcpStream::connect(t.local_addr().unwrap()).unwrap();
        assert!(!is_hold_socket(c.as_fd()));
        assert!(!is_hold_socket(spare().as_fd()));
    }

    /// A restart of the engine passes its holds on: the copies of their
    /// ends hold the new process for as long as the frontends do.
    #[tokio::test]
    async fn the_holds_go_on_in_the_next_process() {
        let before = Holds::default();
        let (ours, theirs) = std::os::unix::net::UnixStream::pair().unwrap();
        before.watch(theirs.into()).unwrap();
        let kept = before.fds().unwrap();
        assert_eq!(kept.len(), 1);
        let after = Holds::default();
        for fd in kept {
            after.adopt(fd);
        }
        assert_eq!(after.count(), 1);
        drop(ours);
        tokio::time::timeout(std::time::Duration::from_secs(5), after.none())
            .await
            .expect("a hold ends with its frontend");
        assert_eq!(after.count(), 0);
    }
    /// The engine serving a socket for the blocking client of the command
    /// line: `run` gets the path of the socket and runs in a thread of its
    /// own (the service is not `Send`).
    async fn with_client<T: Send + 'static>(
        dir: &Path,
        run: impl FnOnce(std::path::PathBuf) -> T + Send + 'static,
    ) -> T {
        let engine = engine_in(dir).await;
        let local = tokio::task::LocalSet::new();
        let socket = dir.join("engine.sock");
        local
            .run_until(async move {
                let listener = tokio::net::UnixListener::bind(&socket).unwrap();
                tokio::task::spawn_local(activation::serve_varlink(
                    listener,
                    None,
                    |_| true,
                    activation::Limits::default(),
                    "engine test",
                    engine,
                ));
                tokio::task::spawn_blocking(move || run(socket))
                    .await
                    .unwrap()
            })
            .await
    }

    /// The blocking client of the command line against the service: an
    /// upload (an image, a volume), a download (a volume), documents,
    /// errors as the API's, arguments too large for the message, the
    /// progress of an operation that fails.
    // (on the stack of the service thread, which serves the calls here
    // as in the engine: the dispatch outgrows a test thread's 2 MiB in a
    // debug build)
    #[test]
    fn the_blocking_client_uses_the_engine() {
        on_service_stack(the_blocking_client_uses_the_engine_here);
    }

    async fn the_blocking_client_uses_the_engine_here() {
        use crate::client::EngineClient;
        let dir = tempfile::tempdir().unwrap();
        with_client(dir.path(), |socket| {
            let client = EngineClient::new(&socket).unwrap();
            assert!(client.list_images(false, &[]).unwrap().is_empty());
            assert!(client
                .list_containers(true, &[], false, false)
                .unwrap()
                .is_empty());
            let e = client.inspect_image("nosuch").unwrap_err();
            assert!(e.is_not_found(), "{e}");
            let system = client.system_inspect().unwrap();
            assert_eq!(system.version.version, env!("CARGO_PKG_VERSION"));
            assert!(system.host.cpus > 0 && !system.store.graph_root.is_empty());
            let usage = client.disk_usage(false).unwrap();
            assert!(usage.images.is_empty() && usage.objects.is_none());
            assert!(client.disk_usage(true).unwrap().objects.is_some());
            let report = client
                .system_check(&velarx_proto::system::CheckSpec {
                    quick: true,
                    ..Default::default()
                })
                .unwrap();
            assert!(report.ok(), "{report:?}");
            let collected = client.system_collect(true, true, true).unwrap();
            assert!(collected.dry_run && collected.errors.is_empty());
            let e = client
                .system_prune(false, false, false, &["bogus=1".into()])
                .unwrap_err();
            assert!(e.to_string().contains("invalid filter"), "{e}");
            let health = client.health().unwrap();
            assert!(!health.components.is_empty());

            let tar_of = |name: &str, content: &[u8]| {
                let mut b = tar::Builder::new(Vec::new());
                let mut h = tar::Header::new_gnu();
                h.set_size(content.len() as u64);
                h.set_mode(0o644);
                h.set_cksum();
                b.append_data(&mut h, name, content).unwrap();
                b.into_inner().unwrap()
            };

            // an image from a tar: the upload crosses as frames
            let rootfs = tar_of("hello", b"hello world");
            let id = client
                .import_image(
                    Some("localhost/native:1"),
                    &[],
                    None,
                    None,
                    None,
                    Box::new(move |w| w.write_all(&rootfs)),
                )
                .unwrap();
            let images = client.list_images(false, &[]).unwrap();
            assert_eq!(images.len(), 1);
            assert_eq!(client.inspect_image(&id).unwrap().id, images[0].id);
            client
                .tag_image("localhost/native:1", "localhost/native:2")
                .unwrap();
            client
                .untag_image("localhost/native:2", &["localhost/native:2".into()])
                .unwrap();
            assert!(client.inspect_image("localhost/native:2").is_err());
            assert!(client.inspect_image("localhost/native:1").is_ok());

            // a volume: created with labels too large for a message, filled
            // by an upload, read back by a download
            let big = "x".repeat(100_000);
            client
                .create_volume(
                    &velarx_proto::workload::VolumeSpec {
                        name: "v1".into(),
                        labels: [("big".to_string(), big.clone())].into(),
                        ..Default::default()
                    },
                    false,
                )
                .unwrap();
            assert_eq!(client.inspect_volume("v1").unwrap().labels["big"], big);
            let data = tar_of("file", &vec![7u8; 3 << 20]);
            let sent = data.clone();
            client
                .import_volume("v1", Box::new(move |w| w.write_all(&sent)))
                .unwrap();
            let mut got = Vec::new();
            client
                .export_volume("v1")
                .unwrap()
                .read_to_end(&mut got)
                .unwrap();
            let mut archive = tar::Archive::new(&got[..]);
            let files: Vec<_> = archive
                .entries()
                .unwrap()
                .map(|e| {
                    let e = e.unwrap();
                    (e.path().unwrap().to_string_lossy().into_owned(), e.size())
                })
                .filter(|(p, _)| p.ends_with("file"))
                .collect();
            assert_eq!(files.len(), 1, "{files:?}");
            assert_eq!(files[0].1, 3 << 20);
            let e = client.inspect_volume("nosuch").unwrap_err();
            assert!(e.is_not_found(), "{e}");
            // a dry run of `VolumePrune` says what each volume has, and
            // removes nothing
            let dry = tokio::runtime::Handle::current()
                .block_on(async {
                    let mut conn = connect_checked(&socket).await.unwrap();
                    conn.volume_prune(Vec::new(), true).await
                })
                .unwrap()
                .unwrap();
            assert_eq!(dry.removed.len(), 1, "{dry:?}");
            assert_eq!(dry.removed[0].name, "v1");
            assert!(dry.removed[0].size >= 3 << 20, "{dry:?}");
            assert_eq!(client.list_volumes(&[]).unwrap().len(), 1);
            // a prune says what the volume had: in its own entry and in the
            // space it reclaimed
            let report = client.system_prune(false, true, false, &[]).unwrap();
            assert_eq!(
                report
                    .volumes
                    .iter()
                    .map(|v| v.name.as_str())
                    .collect::<Vec<_>>(),
                ["v1"]
            );
            assert!(report.volumes[0].size >= 3 << 20, "{report:?}");
            assert_eq!(report.reclaimed, report.volumes[0].size);
            assert!(client.list_volumes(&[]).unwrap().is_empty());

            // an image prune says what the removal freed: the record and
            // the layer of the image, as `system df` sizes them (nothing
            // shares them), and nothing the second time
            let usage = client.disk_usage(false).unwrap();
            assert_eq!(usage.images.len(), 1);
            assert!(usage.images[0].size > 0);
            let pruned = client.prune_images(true, &[]).unwrap();
            assert_eq!(pruned.len(), 1, "{pruned:?}");
            assert_eq!(pruned[0].size, usage.images[0].size, "{pruned:?}");
            assert!(client.prune_images(true, &[]).unwrap().is_empty());
            assert!(client.disk_usage(false).unwrap().images.is_empty());

            // an upload that fails is the caller's error
            let e = client
                .import_volume(
                    "v1",
                    Box::new(|_| Err(std::io::Error::other("the file went"))),
                )
                .unwrap_err();
            assert!(
                e.to_string().contains("the file went") || e.is_not_found(),
                "{e}"
            );

            // the progress of an operation that fails: its error
            let e = client
                .pull_image_progress(
                    "NOT A REFERENCE",
                    &crate::client::PullOptions {
                        tls_verify: true,
                        platform: None,
                        access: &Default::default(),
                        retry: Default::default(),
                        sources: None,
                    },
                    &mut |_| {},
                )
                .unwrap_err();
            assert!(matches!(e, crate::client::ClientError::Api { .. }), "{e}");

            // podman's views and the secrets, typed calls
            let version = client.version_inspect().unwrap();
            assert_eq!(version.version, env!("CARGO_PKG_VERSION"));
            assert!(!client.exists(crate::client::Kind::Volume, "v1").unwrap());
            let secret = crate::client::SecretCreate {
                name: "s1".into(),
                labels: [("a".to_string(), "b".to_string())].into(),
                ..Default::default()
            };
            client.secret_create(&secret, b"hidden").unwrap();
            assert!(client.secret_exists("s1").unwrap());
            let shown = client.secret_inspect("s1", true).unwrap();
            assert_eq!(shown.data.as_deref(), Some(&b"hidden"[..]));
            assert_eq!(shown.labels["a"], "b");
            assert!(!format!("{shown:?}").contains("hidden"), "{shown:?}");
            assert_eq!(client.secret_inspect("s1", false).unwrap().data, None);
            assert_eq!(client.secret_list(&[]).unwrap().len(), 1);
            assert!(client
                .secret_list(&["name=other".into()])
                .unwrap()
                .is_empty());
            client.secret_remove("s1").unwrap();
            assert!(!client.secret_exists("s1").unwrap());
            let e = client.secret_remove("s1").unwrap_err();
            assert!(e.is_not_found(), "{e}");
        })
        .await;
    }

    /// A client of another version is refused before anything runs.
    // (on the stack of the service thread, which serves the calls here
    // as in the engine: the dispatch outgrows a test thread's 2 MiB in a
    // debug build)
    #[test]
    fn the_blocking_client_refuses_an_engine_of_another_build() {
        on_service_stack(the_blocking_client_refuses_an_engine_of_another_build_here);
    }

    async fn the_blocking_client_refuses_an_engine_of_another_build_here() {
        use velarx_wire::varlink::Conn;
        let dir = tempfile::tempdir().unwrap();
        with_client(dir.path(), |socket| {
            let mut conn = Conn::connect(&socket).unwrap();
            conn.call_bare("org.velarx.Engine.GetInfo").unwrap();
            let info = conn.reply::<Value>().unwrap().parameters;
            assert_eq!(info["digest"], DIGEST);
            // a method that is not one
            conn.call_bare("org.velarx.Engine.NoSuch").unwrap();
            let e = conn.reply::<Value>().unwrap_err();
            assert!(e.to_string().contains("MethodNotFound"), "{e}");
        })
        .await;
    }
}
