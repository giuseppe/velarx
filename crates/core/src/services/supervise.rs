// SPDX-License-Identifier: Apache-2.0
//! Who supervises a container's monitor, and what happens when nobody does.
//!
//! The engine service and the engine of a command start monitors the same
//! way (the engine run by a systemd unit, `velarx container run`, in the
//! unit's cgroup, with the unit's `NOTIFY_SOCKET`).  The monitor is on its
//! own once the container runs: it looks after the container, records what
//! happens to it in the database and the events, releases its network and
//! removes an `--rm` container.
//!
//! The service observes the monitors (to tell its clients); a process that
//! finds a monitor that died without a word does what the monitor would
//! have done (`reconcile`).

use super::container::{ContainerError, ContainerResult, ContainerService};
use std::ffi::OsString;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use tracing::debug;
use velarx_wire::monitor::client;

/// How the monitors of this process are started.
#[derive(Debug, Clone, Default)]
pub struct Supervision {
    /// `NOTIFY_SOCKET` of the monitors: the service manager of the unit that
    /// runs this process.  The API server has none to give.
    pub notify_socket: Option<OsString>,
    /// This engine's command line up to its command (`velarx --config
    /// PATH`): what units run (generate systemd).
    pub engine_command: Option<Vec<OsString>>,
    /// The lock of the store (`storage.lock`), held shared while a container
    /// is made: the garbage collection of another process waits.
    pub store_lock: Option<std::path::PathBuf>,
    /// The sockets of the unit's socket activation (`LISTEN_FDS`), which the
    /// containers this process starts get as their descriptors 3, 4, ...
    pub listen_fds: Vec<Arc<std::os::fd::OwnedFd>>,
    /// Which of `listen_fds` the container does not get (`run --preserve-fd`
    /// with gaps).
    pub preserve_holes: Vec<u32>,
    /// The cgroup of the caller, split for `--cgroups=split`
    /// (`cgroups_mode::split_own_cgroup`): its containers go below it.
    pub split_cgroup: Option<String>,
    /// The containers of the server get transient scopes through systemd
    /// (`cgroup_manager = "systemd"`); for the engine of a command, whether
    /// a manager answers, asked the first time a container needs to know
    /// (a container with `--cgroups=disabled` never does: nothing connects
    /// to the manager for it).
    pub systemd_cgroups: SystemdCgroups,
    /// `run --no-monitor`: the process this engine split from runs the
    /// monitor of the container it makes (`monitor::inproc`).
    pub in_process: Option<Arc<crate::monitor::inproc::Handoff>>,
    /// This process observes the monitors it starts or finds, to tell its
    /// clients what happens (the engine service).
    pub observe: bool,
}

/// Whether a systemd manager makes the scopes of the containers: known, or
/// probed once, when first asked (the probe connects to the manager).
#[derive(Clone)]
pub struct SystemdCgroups {
    answer: Arc<std::sync::OnceLock<bool>>,
    probe: fn() -> Result<bool, velarx_base::ids::IdsError>,
}

impl SystemdCgroups {
    /// An answer known in advance.
    pub fn known(yes: bool) -> Self {
        let answer = std::sync::OnceLock::new();
        let _ = answer.set(yes);
        Self {
            answer: Arc::new(answer),
            probe: || Ok(false),
        }
    }

    /// The answer of `probe`, run the first time [`Self::get`] is called.
    pub fn probe(probe: fn() -> Result<bool, velarx_base::ids::IdsError>) -> Self {
        Self {
            answer: Arc::new(std::sync::OnceLock::new()),
            probe,
        }
    }

    pub fn get(&self) -> Result<bool, velarx_base::ids::IdsError> {
        if let Some(answer) = self.answer.get() {
            return Ok(*answer);
        }
        let answer = (self.probe)()?;
        Ok(*self.answer.get_or_init(|| answer))
    }

    /// Whether the probe ran (or the answer was known).
    pub fn asked(&self) -> bool {
        self.answer.get().is_some()
    }
}

impl Default for SystemdCgroups {
    fn default() -> Self {
        Self::known(false)
    }
}

impl std::fmt::Debug for SystemdCgroups {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.answer.get() {
            Some(a) => write!(f, "{a}"),
            None => f.write_str("not asked yet"),
        }
    }
}

impl ContainerService {
    pub fn with_supervision(mut self, supervision: Supervision) -> Self {
        self.supervision = supervision;
        self
    }

    /// A running container whose monitor is gone without a word gets what
    /// the monitor would have given it: its exit (from the exit file, else
    /// unseen) is recorded, the container followed to its end when its
    /// process runs on.  A monitor of another version is waited for.  True
    /// when that removed the container (`--rm`).
    ///
    /// Boxed: recording an exit can restart the container, which can stop it
    /// again, and the type of that future would contain itself.
    pub(crate) fn reconcile<'a>(
        self: &'a Arc<Self>,
        id: &'a str,
    ) -> Pin<Box<dyn Future<Output = ContainerResult<bool>> + Send + 'a>> {
        Box::pin(async move {
            let container = match self.db.get_container(id).await {
                Ok(c) => c,
                Err(velarx_types::DbError::NotFound(_)) => return Ok(false),
                Err(e) => return Err(e.into()),
            };
            // A container in the created state may have a monitor that waits
            // for the process that creates it: it is not ours to take.
            if !container.state.is_alive() || self.lifecycle.is_watched(&container.id) {
                return Ok(false);
            }
            let dir = self.mon_dir(&container.id);
            let status_dir = dir.clone();
            let status = tokio::task::spawn_blocking(move || client::core_status(&status_dir))
                .await
                .map_err(|e| ContainerError::Io(std::io::Error::other(e)))?;
            match status {
                Ok(_) => return Ok(false),
                Err(e)
                    if matches!(
                        client::monitor_error(&e),
                        Some(client::MonitorError::Version { .. })
                    ) =>
                {
                    let pid_dir = dir.clone();
                    if let Ok(Ok(pidfd)) =
                        tokio::task::spawn_blocking(move || client::monitor_pidfd(&pid_dir)).await
                    {
                        self.follow_foreign(container.id.clone(), pidfd, e.to_string());
                        return Ok(false);
                    }
                }
                _ => {}
            }
            // (a monitor that is ending, its socket gone while its record
            // command works, is not lost: it records the exit)
            if super::lifecycle::monitor_alive(&dir).is_some() {
                return Ok(false);
            }
            debug!("The monitor of {} does not answer", container.id);
            self.monitor_lost(&container).await?;
            Ok(matches!(
                self.db.get_container(&container.id).await,
                Err(velarx_types::DbError::NotFound(_))
            ))
        })
    }

    /// The store, held shared (see `Supervision::store_lock`): what a request
    /// makes for a container before its create (the secrets it resolves) is
    /// made under it too, so that [`Self::sweep_unowned`] never takes it for
    /// what a crash left.  The create takes it again (flock: one more shared
    /// holder never waits for a shared one).
    pub async fn lock_store(&self) -> std::io::Result<Option<velarx_storage::StorageLock>> {
        match &self.supervision.store_lock {
            Some(path) => velarx_storage::StorageLock::shared(path).await.map(Some),
            None => Ok(None),
        }
    }

    /// Observe the monitor of a container in this process (its notices
    /// become this process's); an error if there is no such container.
    pub async fn follow(self: &Arc<Self>, id: &str) -> ContainerResult<()> {
        let container = self.db.get_container(id).await?;
        if container.state.is_alive() && !self.lifecycle.is_watched(&container.id) {
            self.observe(&container).await?;
        }
        Ok(())
    }

    /// A count that changes when the containers this process follows
    /// change (one is followed, or the following of one ended): `followed`
    /// is asked again then.
    pub fn subscribe_followed(&self) -> tokio::sync::watch::Receiver<u64> {
        self.lifecycle.followed.subscribe()
    }

    /// The running (or paused) containers whose monitors this process
    /// observes: their processes are there, in the engine's unit with
    /// `--cgroups=split`, which a stop of the unit would take with it.
    pub async fn followed(&self) -> Vec<String> {
        let mut ids = Vec::new();
        for id in self.lifecycle.watched() {
            if matches!(self.db.get_container(&id).await, Ok(c) if c.state.is_alive()) {
                ids.push(id);
            }
        }
        ids
    }

    /// Observe the running containers that this process does not yet (the
    /// service: those a command started).
    pub async fn observe_unobserved(self: &Arc<Self>) -> ContainerResult<()> {
        for c in self.db.list_containers(true).await? {
            if c.state.is_alive() && !self.lifecycle.is_watched(&c.id) {
                self.observe(&c).await?;
            }
        }
        Ok(())
    }

    /// Wait for the cleanups under way (removals of `--rm` containers).
    pub async fn settle(&self) {
        self.lifecycle.settle().await;
    }
}

#[cfg(test)]
mod tests {
    use super::SystemdCgroups;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static PROBES: AtomicUsize = AtomicUsize::new(0);

    #[test]
    fn the_manager_is_asked_once_and_only_when_needed() {
        let s = SystemdCgroups::probe(|| {
            PROBES.fetch_add(1, Ordering::SeqCst);
            Ok(true)
        });
        let copy = s.clone();
        // (a container with --cgroups=disabled never asks)
        assert!(!s.asked());
        assert_eq!(PROBES.load(Ordering::SeqCst), 0);
        assert!(copy.get().unwrap());
        assert!(s.get().unwrap() && s.asked());
        assert_eq!(PROBES.load(Ordering::SeqCst), 1);
        let known = SystemdCgroups::known(false);
        assert!(known.asked() && !known.get().unwrap());
        assert!(!SystemdCgroups::default().get().unwrap());
    }
}
