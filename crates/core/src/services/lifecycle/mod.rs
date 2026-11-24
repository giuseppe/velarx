// SPDX-License-Identifier: Apache-2.0
//! The life of a container as an engine sees it: it starts a monitor
//! process for the container and hands it over.  The monitor looks after
//! the container: its log, its restart policy, its health checks, and the
//! record of what happens to it, which it writes to the store itself
//! (`velarx_runtime::settle`), with the release of its network and the
//! removal of an `--rm` container.  A process may observe the monitor of a
//! container (the engine service does, for its clients), which records
//! nothing, and finds the monitor that died without a word: it does what the
//! monitor would have done, with the same functions.

use super::container::{ContainerError, ContainerResult, ContainerService};
use crate::container::ContainerConfig;
use crate::monitor::config::MonitorConfig;
use std::collections::HashMap;
use std::io;
use std::os::fd::{AsFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::task::AbortHandle;
use tracing::{debug, info, warn};
use velarx_db::{ContainerRecord, RecordState};
use velarx_runtime::settle::{record::event_details, rfc3339};
use velarx_wire::monitor::client;
use velarx_wire::monitor::proto::{self, Event, ExitInfo, RunState};
pub use velarx_wire::monitor::sys::{parse_signal, signal_name};

mod adopt;
mod attach;
mod chain_rule;
pub(in crate::services) mod conn;
mod control;
use conn::MonitorConn;
mod exit;
mod pause;
pub(in crate::services) mod root_fd;
mod settle;
mod start;
mod stop;
pub use attach::*;
pub(in crate::services) use start::mount_label;
pub use start::{pod_digests_refusal, verify_image_digests, MemberImage, StartCheck};
pub use stop::Stop;

/// The most the monitor waits for the client of `run`: its attach starts the
/// container, and only a client that never comes makes the monitor start it
/// at this bound.
const ATTACH_WAIT: Duration = Duration::from_secs(30);

/// How long the creation of a container by the runtime may take.
const CREATE_TIMEOUT: Duration = Duration::from_secs(150);

/// Something that happened to a container.
#[derive(Debug, Clone)]
pub enum ContainerNotice {
    /// It exited; sent before an `--rm` container is removed.
    Exited {
        id: String,
        code: i32,
        /// It was killed at the end of its time limit (`--timeout`).
        timed_out: bool,
        /// Its name, image (as it was asked) and labels: it may be gone by
        /// the time the notice is read.
        name: String,
        image: String,
        labels: Vec<(String, String)>,
        /// Its restart policy starts it again.
        restarting: bool,
    },
    /// The status of its health checks changed.
    Health {
        id: String,
        status: velarx_proto::health::HealthStatus,
    },
    /// The kernel killed a process of it for lack of memory.
    Oom { id: String },
    /// The restart policy started it again.
    Restarted { id: String },
    /// A stop of it began or ended (its monitor says `stopping` between).
    Stopping { id: String },
    /// A user (any API, the engine) acted on it: podman's event `action`
    /// (create, init, start, stop, kill, pause, unpause, restart, rename,
    /// remove), with its attributes (its labels first, as podman's events
    /// carry them).
    Action {
        id: String,
        name: String,
        image: String,
        action: &'static str,
        attributes: Vec<(String, String)>,
    },
    /// An image went with a container (`--rmi`): the names it lost, and
    /// whether the image itself was removed (else only the name).  The
    /// monitor tells it (`Settled`) to the processes that observe it.
    Image(velarx_wire::monitor::iface::ImageChange),
    /// A monitor told it to a process that observes it: the monitor
    /// recorded it (and wrote its event) already.
    Seen(Box<ContainerNotice>),
}

/// The daemon's view of its monitors.
pub struct Lifecycle {
    /// Fired when a container exits.
    pub exited: tokio::sync::Notify,
    /// Where the events are kept: the monitors write the events of their
    /// containers there, and so does the engine for the exits it records.
    events: std::sync::OnceLock<velarx_wire::events::log::EventLog>,
    /// What happens to the containers, for the clients that want to tell.
    notices: tokio::sync::broadcast::Sender<ContainerNotice>,
    /// The tasks that follow the events of each monitor.
    watchers: Arc<Mutex<HashMap<String, AbortHandle>>>,
    /// The containers whose monitor is gone while they run: this process
    /// follows their process (no exec, attach or health checks).
    orphans: Mutex<std::collections::HashSet<String>>,
    /// The exit code of the last exit of each container whose monitor said
    /// it exited and has not said it settled: the removal notice has it.
    exit_codes: Mutex<HashMap<String, (i32, String, String)>>,
    /// The containers whose monitor is of another version of velarx (it
    /// outlived an upgrade), and what it is: this process follows the
    /// monitor until it ends, and asks it nothing.
    foreign: Mutex<HashMap<String, String>>,
    /// Cleanups under way, which a process that exits waits for.
    pending: Arc<Pending>,
    /// Counts the changes of the set of the containers this process follows
    /// (one starts to be followed, or the task that follows it ended)
    pub(super) followed: Arc<tokio::sync::watch::Sender<u64>>,
}

/// Counts a change of the followed containers when it is dropped: the end
/// of a task that follows one (also when it is aborted).  The task is not
/// finished yet when it drops this: it takes itself out of the followed
/// ones first, so that whoever the count wakes does not find it there.
pub(super) struct FollowedEnd {
    followed: Arc<tokio::sync::watch::Sender<u64>>,
    watchers: Arc<Mutex<HashMap<String, AbortHandle>>>,
    id: String,
}

impl Drop for FollowedEnd {
    fn drop(&mut self) {
        if let Some(task) = tokio::task::try_id() {
            let mut w = self.watchers.lock().unwrap_or_else(|p| p.into_inner());
            // (not the task that follows it now, if another replaced it)
            if w.get(&self.id).is_some_and(|h| h.id() == task) {
                w.remove(&self.id);
            }
        }
        self.followed.send_modify(|n| *n += 1);
    }
}

#[derive(Default)]
struct Pending {
    count: std::sync::atomic::AtomicUsize,
    settled: tokio::sync::Notify,
}

/// One cleanup under way, until it is dropped (also when it panics).
struct PendingGuard(Arc<Pending>);

impl Drop for PendingGuard {
    fn drop(&mut self) {
        use std::sync::atomic::Ordering;
        if self.0.count.fetch_sub(1, Ordering::SeqCst) == 1 {
            self.0.settled.notify_waiters();
        }
    }
}

impl Default for Lifecycle {
    fn default() -> Self {
        Self {
            exited: Default::default(),
            events: Default::default(),
            notices: tokio::sync::broadcast::channel(64).0,
            watchers: Default::default(),
            orphans: Default::default(),
            exit_codes: Default::default(),
            foreign: Default::default(),
            pending: Default::default(),
            followed: Arc::new(tokio::sync::watch::channel(0).0),
        }
    }
}

impl Lifecycle {
    fn set_orphan(&self, id: &str, orphan: bool) {
        let mut o = self.orphans.lock().unwrap_or_else(|p| p.into_inner());
        if orphan {
            o.insert(id.to_string());
        } else {
            o.remove(id);
        }
    }

    fn set_foreign(&self, id: &str, why: Option<String>) {
        let mut f = self.foreign.lock().unwrap_or_else(|p| p.into_inner());
        match why {
            Some(w) => {
                f.insert(id.to_string(), w);
            }
            None => {
                f.remove(id);
            }
        }
    }

    fn watch(&self, id: &str, handle: AbortHandle) {
        if let Some(old) = self.watchers.lock().unwrap().insert(id.to_string(), handle) {
            old.abort();
        }
        self.followed.send_modify(|n| *n += 1);
    }

    /// Counted when dropped: put it in the task that follows a container.
    pub(super) fn followed_end(&self, id: &str) -> FollowedEnd {
        FollowedEnd {
            followed: self.followed.clone(),
            watchers: self.watchers.clone(),
            id: id.to_string(),
        }
    }

    /// The containers whose monitors this process follows.
    pub(super) fn watched(&self) -> Vec<String> {
        self.watchers
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, h)| !h.is_finished())
            .map(|(id, _)| id.clone())
            .collect()
    }

    pub(super) fn is_watched(&self, id: &str) -> bool {
        self.watchers
            .lock()
            .unwrap()
            .get(id)
            .is_some_and(|h| !h.is_finished())
    }

    /// One cleanup under way until the guard is dropped: [`Self::settle`]
    /// waits for it.
    fn hold(&self) -> PendingGuard {
        self.pending
            .count
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        PendingGuard(Arc::clone(&self.pending))
    }

    /// Wait for the cleanups under way.
    pub(super) async fn settle(&self) {
        loop {
            let settled = self.pending.settled.notified();
            tokio::pin!(settled);
            settled.as_mut().enable();
            if self.pending.count.load(std::sync::atomic::Ordering::SeqCst) == 0 {
                return;
            }
            settled.await;
        }
    }

    pub(super) fn unwatch(&self, id: &str) {
        if let Some(h) = self.watchers.lock().unwrap().remove(id) {
            h.abort();
            self.followed.send_modify(|n| *n += 1);
        }
    }
}

/// Wait for the end of the child `pid` that nothing else waits for, and
/// collect it.
async fn reap(pid: u32) {
    use rustix::process::{pidfd_open, waitid, PidfdFlags, WaitId, WaitIdOptions};
    let Some(pid) = rustix::process::Pid::from_raw(pid as i32) else {
        return;
    };
    let Ok(fd) = pidfd_open(pid, PidfdFlags::NONBLOCK) else {
        return;
    };
    let Ok(fd) = velarx_sys::fd::register(
        fd,
        tokio::io::Interest::READABLE | tokio::io::Interest::WRITABLE,
    ) else {
        return;
    };
    if fd.readable().await.is_ok() {
        let _ = waitid(
            WaitId::PidFd(std::os::fd::AsFd::as_fd(fd.get_ref())),
            WaitIdOptions::EXITED,
        );
    }
}

/// Wait for the end of the process of the pidfd `fd`.
async fn ended(fd: std::os::fd::OwnedFd) -> io::Result<()> {
    drop(
        velarx_sys::fd::register(
            fd,
            tokio::io::Interest::READABLE | tokio::io::Interest::WRITABLE,
        )?
        .readable()
        .await?,
    );
    Ok(())
}

/// The monitor in the run directory `dir` of a container, if it lives:
/// the monitor holds a lock on a file of the directory for its life, which
/// the kernel drops when it ends however it ends (a pid from a file could
/// name a process that took the number later).
pub(in crate::services) fn monitor_alive(
    dir: &Path,
) -> Option<velarx_runtime::monitor::LiveMonitor> {
    velarx_runtime::monitor::live_monitor(dir)
}

/// Whether the error of a look for the monitor of a directory says there is
/// none (no socket, nobody on it, its process gone) and not a failure.  A
/// monitor that ends while a call is made to it (the container exited, and
/// it ends as it answers) closes the connection: the call is read as the
/// monitor being gone.
pub(in crate::services) fn no_monitor(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::NotFound
            | io::ErrorKind::ConnectionRefused
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::BrokenPipe
            | io::ErrorKind::UnexpectedEof
    ) || e.raw_os_error() == Some(rustix::io::Errno::SRCH.raw_os_error())
}

fn io_error(e: io::Error) -> ContainerError {
    ContainerError::Io(e)
}

/// The directory the results of the health checks of a container are also
/// written to (`--health-log-destination`), opened for its monitor: `None`
/// when they stay with the monitor's own record.  A directory that cannot be
/// opened is logged, and the container has no file of results.
fn health_log_dir(config: &ContainerConfig) -> Option<PathBuf> {
    config.healthcheck.as_ref()?.log_dir().map(PathBuf::from)
}

/// [`health_log_dir`], opened.
fn open_health_log_dir(config: &ContainerConfig) -> Option<std::os::fd::OwnedFd> {
    let path = health_log_dir(config)?;
    match rustix::fs::open(
        &path,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::DIRECTORY | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    ) {
        Ok(fd) => Some(fd),
        Err(e) => {
            warn!(
                "The health log directory {} cannot be opened: {e}",
                path.display()
            );
            None
        }
    }
}

/// The health check of a container for its monitor: none when it has no
/// command.
fn health_config(config: &ContainerConfig) -> Option<velarx_proto::health::Healthcheck> {
    config.healthcheck.clone().filter(|h| h.command().is_some())
}

/// The signal and the timeout (seconds) that stop a container: those of its
/// config (the create options, else the image's `StopSignal`), else
/// SIGTERM and 10 s.
pub fn stop_settings(config: &ContainerConfig) -> (i32, u32) {
    (
        parse_signal(&config.stop_signal).unwrap_or(libc::SIGTERM),
        config.stop_timeout.unwrap_or(10),
    )
}

/// The SELinux label of the socket a container in `--sdnotify=container`
/// mode sends to: its own process label.
fn notify_label(config: &ContainerConfig) -> Option<String> {
    use crate::container::selinux;
    if config.sdnotify != "container" {
        return None;
    }
    let s = config.selinux.as_ref().filter(|_| selinux::enabled())?;
    selinux::labels(s, config.privileged, selinux::Contexts::host()).0
}

/// With the `passthrough` log driver the container writes to the output of
/// this process, and SELinux replaces what the container's process may not
/// use with /dev/null when it starts: a file of the user's opened to write
/// (`user_home_t`, `user_tmp_t` without appending) is not one `container_t`
/// may write, and the output would be lost without a word.  The policy is
/// asked about standard output and error with the container's own label.
fn warn_withheld_output(config: &ContainerConfig) {
    use crate::container::selinux;
    let Some(process) = config
        .selinux
        .as_ref()
        .filter(|_| selinux::enabled())
        .and_then(|s| selinux::labels(s, config.privileged, selinux::Contexts::host()).0)
    else {
        return;
    };
    let mut seen = Vec::new();
    for (what, fd) in [
        ("standard output", std::io::stdout().as_fd()),
        ("standard error", std::io::stderr().as_fd()),
    ] {
        // (standard error is most of the time the same as standard output)
        let Ok(st) = rustix::fs::fstat(fd) else {
            continue;
        };
        if seen.contains(&(st.st_dev, st.st_ino)) {
            continue;
        }
        seen.push((st.st_dev, st.st_ino));
        if selinux::keeps(&process, fd) == Some(false) {
            let label = selinux::fd_label(fd).unwrap_or_default();
            tracing::warn!("{}", withheld_output(what, &label, &process));
        }
    }
}

fn withheld_output(what: &str, label: &str, process: &str) -> String {
    let typ = process.split(':').nth(2).unwrap_or(process);
    format!(
        "the SELinux policy does not let {typ} write to the {what} of this command \
         (labelled {label}): with --log-driver=passthrough the container gets /dev/null \
         instead of it and its output is lost.  Send the output to a pipe or a terminal, \
         or run the container with --security-opt label=disable"
    )
}

pub use crate::monitor::MONITOR_PID_FILE;

/// The file of a container's monitor directory with the cgroup of its
/// processes, when the server made cgroups for it (to remove them with it).
const CGROUP_FILE: &str = "cgroup";

/// Whether the mounts of the container must reach the host (a shared root
/// propagation, a `shared`/`rshared` volume): its monitor then mounts in
/// the namespace it was started in, so that it stays a peer.
pub(crate) fn mounts_reach_the_host(config: &ContainerConfig) -> bool {
    let shared = |o: &str| matches!(o, "shared" | "rshared");
    config
        .options
        .rootfs_propagation
        .as_deref()
        .is_some_and(shared)
        || config
            .mounts
            .iter()
            .any(|m| m.options.iter().any(|o| shared(o)))
}

impl ContainerService {
    /// Whether the container runs, or its monitor waits to start it again.
    pub async fn is_active(&self, id: &str) -> bool {
        self.activity_of(id).await.0
    }

    /// Whether the container is active (see [`Self::is_active`]) and whether
    /// it is paused, from one look at its record.
    pub async fn activity_of(&self, id: &str) -> (bool, bool) {
        let Ok(rec) = self.db.get_container(id).await else {
            return (false, false);
        };
        match rec.state {
            RecordState::Paused => return (true, true),
            RecordState::Running => return (true, false),
            _ => {}
        }
        let active = self
            .monitor_status(&rec.id)
            .await
            .is_some_and(|s| s.restarting.is_some() || s.state == RunState::Running);
        (active, false)
    }

    /// What the monitor of the container says of its run, if it has one
    /// that answers.  Between two runs of its restart policy the record may
    /// lag the monitor (it says `running` when the run already ended, or
    /// `stopped` when the next run already started): the monitor knows.
    pub async fn monitor_status(&self, id: &str) -> Option<proto::Status> {
        let dir = self.mon_dir(id);
        tokio::task::spawn_blocking(move || client::status(&dir))
            .await
            .ok()
            .and_then(Result::ok)
    }

    /// Change the extra state of a container in one transaction: the
    /// commands, the monitors and the engine change it at once.
    pub(crate) async fn update_ext(
        &self,
        id: &str,
        f: impl FnOnce(&mut velarx_db::ContainerExt) + Send + 'static,
    ) -> ContainerResult<()> {
        Ok(self.db.update_container_ext(id, f).await?)
    }

    /// Run the health check of a running container now: the state of its
    /// checks afterwards.
    pub async fn run_health_check(
        &self,
        id: &str,
    ) -> ContainerResult<velarx_wire::monitor::proto::Health> {
        let container = self.db.get_container(id).await?;
        if container.state != RecordState::Running {
            return Err(ContainerError::NotRunning(id.to_string()));
        }
        self.check_monitor(&container.id)?;
        let dir = self.mon_dir(&container.id);
        tokio::task::spawn_blocking(move || client::run_health_check(&dir))
            .await
            .map_err(|e| io_error(io::Error::other(e)))?
            .map_err(io_error)
    }

    /// What the monitor learned about the container.  The health of a
    /// running container is asked of its monitor, which runs the checks: its
    /// monitor writes a change of the status, not each check.
    pub async fn container_ext(&self, id: &str) -> ContainerResult<velarx_db::ContainerExt> {
        let container = self.db.get_container(id).await?;
        let ext = self.db.get_container_ext(&container.id).await?;
        self.ext_with_health(&container, ext).await
    }

    /// [`Self::container_ext`] of each of `containers` (records in hand,
    /// by id): the rows in one query, the monitors asked together.  A
    /// container whose ext cannot be given has the default.
    pub async fn container_exts(
        &self,
        containers: &[&ContainerRecord],
    ) -> ContainerResult<HashMap<String, velarx_db::ContainerExt>> {
        let ids: Vec<String> = containers.iter().map(|c| c.id.clone()).collect();
        let rows = self.db.get_container_exts(&ids).await?;
        let mut out = HashMap::with_capacity(containers.len());
        for chunk in containers.chunks(16) {
            out.extend(
                futures::future::join_all(chunk.iter().map(|c| self.ext_of(c, &rows))).await,
            );
        }
        Ok(out)
    }

    async fn ext_of(
        &self,
        container: &ContainerRecord,
        rows: &HashMap<String, velarx_db::ContainerExt>,
    ) -> (String, velarx_db::ContainerExt) {
        let row = rows.get(&container.id).cloned().unwrap_or_default();
        let ext = self.ext_with_health(container, row).await;
        (container.id.clone(), ext.unwrap_or_default())
    }

    /// The row of a container with the health its monitor reports, when it
    /// has a check and runs (and the row brought up to date).
    async fn ext_with_health(
        &self,
        container: &ContainerRecord,
        mut ext: velarx_db::ContainerExt,
    ) -> ContainerResult<velarx_db::ContainerExt> {
        if container.state.is_alive()
            && serde_json::from_str::<ContainerConfig>(&container.config)
                .is_ok_and(|c| c.healthcheck.is_some())
        {
            let dir = self.mon_dir(&container.id);
            let health = tokio::task::spawn_blocking(move || client::status(&dir))
                .await
                .ok()
                .and_then(Result::ok)
                .and_then(|s| s.health)
                .and_then(|h| serde_json::to_string(&h).ok());
            if health.is_some() && health != ext.health {
                ext.health = health.clone();
                self.update_ext(&container.id, move |e| e.health = health)
                    .await?;
            }
        }
        Ok(ext)
    }
}

/// The exit file a monitor leaves in its run directory.  None when there is
/// none; one that cannot be read or parsed is logged (the exit it holds is
/// lost, the caller goes on without it).
pub fn read_exit_file(dir: &Path) -> Option<ExitInfo> {
    let path = dir.join(proto::EXIT_FILE);
    let data = match std::fs::read(&path) {
        Ok(data) => data,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return None,
        Err(e) => {
            warn!("Cannot read the exit file {}: {e}", path.display());
            return None;
        }
    };
    match serde_json::from_slice(&data) {
        Ok(info) => Some(info),
        Err(e) => {
            warn!("The exit file {} is not valid: {e}", path.display());
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A monitor that ends while it is called (the connection is reset or
    /// closed) is gone; another failure is a failure.
    #[test]
    fn a_monitor_that_ends_in_a_call_is_gone() {
        use io::ErrorKind as K;
        for kind in [
            K::NotFound,
            K::ConnectionRefused,
            K::ConnectionReset,
            K::BrokenPipe,
            K::UnexpectedEof,
        ] {
            assert!(no_monitor(&io::Error::from(kind)), "{kind:?}");
        }
        assert!(!no_monitor(&io::Error::from(K::PermissionDenied)));
        assert!(!no_monitor(&io::Error::from(K::TimedOut)));
    }

    #[test]
    fn an_exit_file_that_is_absent_or_corrupt_is_none() {
        let d = tempfile::tempdir().unwrap();
        assert!(read_exit_file(d.path()).is_none());
        std::fs::write(d.path().join(proto::EXIT_FILE), b"{not json").unwrap();
        assert!(read_exit_file(d.path()).is_none());
        std::fs::write(
            d.path().join(proto::EXIT_FILE),
            br#"{"code": 3, "finished_ns": 5}"#,
        )
        .unwrap();
        assert_eq!(read_exit_file(d.path()).unwrap().code, 3);
    }

    #[test]
    fn the_absence_of_a_monitor_is_told_from_a_failure() {
        assert!(no_monitor(&io::Error::from(io::ErrorKind::NotFound)));
        assert!(no_monitor(&io::Error::from(
            io::ErrorKind::ConnectionRefused
        )));
        assert!(!no_monitor(&io::Error::from(
            io::ErrorKind::PermissionDenied
        )));
    }

    #[test]
    fn the_warning_names_the_output_and_the_fix() {
        let w = withheld_output(
            "standard output",
            "unconfined_u:object_r:user_tmp_t:s0",
            "system_u:system_r:container_t:s0:c1,c2",
        );
        assert!(w.contains("write to the standard output") && w.contains("user_tmp_t"));
        assert!(w.contains("let container_t ") && w.contains("label=disable"));
    }

    #[test]
    fn events_carry_the_image_asked_and_the_labels() {
        let cfg = ContainerConfig {
            image: "quay.io/libpod/testimage:20241011".into(),
            labels: [
                ("b".to_string(), "2".to_string()),
                ("a".to_string(), "1".to_string()),
            ]
            .into(),
            ..Default::default()
        };
        let mut rec = ContainerRecord {
            id: "c".into(),
            name: Some("n".into()),
            image_id: "6953980e4692".into(),
            config: serde_json::to_string(&cfg).unwrap(),
            state: RecordState::Running,
            ..Default::default()
        };
        let (image, labels) = event_details(&rec);
        assert_eq!(image, "quay.io/libpod/testimage:20241011");
        assert_eq!(
            labels,
            vec![("a".into(), "1".into()), ("b".into(), "2".into())]
        );
        // a configuration that does not parse: the id, no labels
        rec.config = "{".into();
        assert_eq!(
            event_details(&rec),
            ("6953980e4692".to_string(), Vec::new())
        );
    }

    #[test]
    fn the_stop_settings_come_from_the_config_or_the_defaults() {
        let mut c = ContainerConfig::default();
        assert_eq!(stop_settings(&c), (libc::SIGTERM, 10));
        c.stop_signal = "SIGUSR1".into();
        c.stop_timeout = Some(3);
        assert_eq!(stop_settings(&c), (libc::SIGUSR1, 3));
        c.stop_signal = "bogus".into();
        assert_eq!(stop_settings(&c).0, libc::SIGTERM);
    }
}
