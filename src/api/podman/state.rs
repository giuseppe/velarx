// SPDX-License-Identifier: Apache-2.0
//! State of the API that is not in the services: the exit codes of removed
//! containers and the exec sessions.

use super::events::EventHub;
use std::collections::HashMap;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};
use tokio::sync::watch;

/// How long the exit code of a removed container is kept: a client waits
/// for the exit after the start, possibly once the container is gone.
const EXIT_KEEP: Duration = Duration::from_secs(5 * 60);

/// How long an exec session is kept once its command ended (podman's
/// default `exit_command_delay`, which Docker's cleanup of exec sessions
/// mimics).
const EXEC_KEEP: Duration = Duration::from_secs(5 * 60);

/// Output of a container as the clients get it.
#[derive(Debug, Clone)]
pub struct Chunk {
    pub stream: u8,
    pub data: Arc<Vec<u8>>,
}

#[derive(Default)]
pub struct PodmanState {
    pub events: EventHub,
    pub(super) secrets: tokio::sync::OnceCell<Arc<velarx_core::services::SecretStore>>,
    pub(super) artifacts:
        tokio::sync::OnceCell<Arc<velarx_core::services::artifact::ArtifactStore>>,
    exits: StdMutex<HashMap<String, (i32, Instant)>>,
    /// The clients attached to a container that was not started yet (a
    /// Docker client attaches, then starts).
    attachers: Attachers,
    execs: StdMutex<HashMap<String, Arc<super::exec::Session>>>,
    changed: Changes,
    /// The last walks of the files a container wrote, by container.
    upper_usage: StdMutex<HashMap<String, (Instant, UpperUsage)>>,
}

/// The count of the changes in the state of the containers.
struct Changes(watch::Sender<u64>);

impl Default for Changes {
    fn default() -> Self {
        Self(watch::channel(0).0)
    }
}

/// The bytes a container wrote to its upper directory, and the files.
type UpperUsage = (i64, i64);

fn lock<T>(m: &StdMutex<T>) -> std::sync::MutexGuard<'_, T> {
    match m.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    }
}

type Attachers = Arc<StdMutex<HashMap<String, Vec<Arc<AttachWait>>>>>;

/// A client that attached to a container that waits to be started.
#[derive(Default)]
pub struct AttachWait {
    cancelled: std::sync::atomic::AtomicBool,
    /// The monitor of the container waits for the client.
    ready: std::sync::atomic::AtomicBool,
    /// The size of the terminal the client asked for before the start.
    size: StdMutex<Option<(u16, u16)>>,
}

impl AttachWait {
    /// The size of the terminal the client asked for, if it did.
    pub fn size(&self) -> Option<(u16, u16)> {
        *lock(&self.size)
    }

    /// The monitor of the container waits for this client to attach.
    pub fn ready(&self) -> bool {
        self.ready.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// The start of the container failed: the attach ends.
    pub fn cancelled(&self) -> bool {
        self.cancelled.load(std::sync::atomic::Ordering::SeqCst)
    }
}

/// Until it is dropped, a client waits for the start of a container.
pub struct AttachWaiter {
    all: Attachers,
    id: String,
    pub wait: Arc<AttachWait>,
}

impl Drop for AttachWaiter {
    fn drop(&mut self) {
        let mut all = lock(&self.all);
        if let Some(list) = all.get_mut(&self.id) {
            list.retain(|w| !Arc::ptr_eq(w, &self.wait));
            if list.is_empty() {
                all.remove(&self.id);
            }
        }
    }
}

impl PodmanState {
    /// A client attaches to the container `id`, which is not started yet:
    /// its start gives the monitor the time to wait for the client.
    pub fn attach_waiter(&self, id: &str) -> AttachWaiter {
        let wait = Arc::new(AttachWait::default());
        lock(&self.attachers)
            .entry(id.to_string())
            .or_default()
            .push(wait.clone());
        AttachWaiter {
            all: self.attachers.clone(),
            id: id.to_string(),
            wait,
        }
    }

    /// Whether a client waits to attach to the container `id` when it starts.
    pub fn has_attach_waiter(&self, id: &str) -> bool {
        lock(&self.attachers).contains_key(id)
    }

    /// The terminal of the container `id`, which is not started, gets this
    /// size when the clients that wait for it attach.
    pub fn set_attach_size(&self, id: &str, rows: u16, cols: u16) {
        for w in lock(&self.attachers).get(id).into_iter().flatten() {
            *lock(&w.size) = Some((rows, cols));
        }
    }

    /// The monitor of the container `id` waits for the clients that wait for
    /// its start.
    pub fn ready_attach_waiters(&self, id: &str) {
        for w in lock(&self.attachers).get(id).into_iter().flatten() {
            w.ready.store(true, std::sync::atomic::Ordering::SeqCst);
        }
        self.notify_changed();
    }

    /// The start of the container `id` failed: the clients that wait for it
    /// are done.
    pub fn cancel_attach_waiters(&self, id: &str) {
        for w in lock(&self.attachers).get(id).into_iter().flatten() {
            w.cancelled.store(true, std::sync::atomic::Ordering::SeqCst);
        }
        self.notify_changed();
    }
    pub fn record_exit(&self, id: &str, code: i32) {
        let mut exits = lock(&self.exits);
        let now = Instant::now();
        exits.retain(|_, (_, t)| now.duration_since(*t) < EXIT_KEEP);
        exits.insert(id.to_string(), (code, now));
    }

    /// The exit code of a container that is gone (by id or id prefix).
    pub fn exit_of(&self, id: &str) -> Option<i32> {
        if id.is_empty() {
            return None;
        }
        let mut exits = lock(&self.exits);
        let now = Instant::now();
        exits.retain(|_, (_, t)| now.duration_since(*t) < EXIT_KEEP);
        exits
            .iter()
            .find(|(k, _)| k.starts_with(id))
            .map(|(_, (c, _))| *c)
    }

    pub fn exec_session(&self, id: &str) -> Option<Arc<super::exec::Session>> {
        lock(&self.execs).get(id).cloned()
    }

    /// Keep a new session; those whose command ended more than
    /// [`EXEC_KEEP`] ago go (podman's exit command delay: a client that did
    /// not remove its session does not keep it forever).
    pub fn add_exec_session(&self, s: Arc<super::exec::Session>) {
        let id = s.id().to_string();
        let mut execs = lock(&self.execs);
        execs.retain(|_, s| !s.ended_before(EXEC_KEEP));
        execs.insert(id, s);
    }

    pub fn remove_exec_session(&self, id: &str) {
        lock(&self.execs).remove(id);
    }

    /// The walk of the files a container wrote, when it is younger than `ttl`.
    pub fn upper_usage(&self, id: &str, ttl: Duration) -> Option<(i64, i64)> {
        lock(&self.upper_usage)
            .get(id)
            .filter(|(at, _)| at.elapsed() < ttl)
            .map(|(_, v)| *v)
    }

    /// Keep a walk; the walks older than `ttl` (of containers that are gone
    /// too) are dropped.
    pub fn set_upper_usage(&self, id: &str, v: (i64, i64), ttl: Duration) {
        let mut cache = lock(&self.upper_usage);
        cache.retain(|_, (at, _)| at.elapsed() < ttl);
        cache.insert(id.to_string(), (Instant::now(), v));
    }

    /// Something changed in the state of the containers.
    pub fn notify_changed(&self) {
        self.changed.0.send_modify(|v| *v = v.wrapping_add(1));
    }

    pub fn subscribe_changes(&self) -> watch::Receiver<u64> {
        self.changed.0.subscribe()
    }

    /// How many follow the changes.
    #[cfg(test)]
    pub fn change_watchers(&self) -> usize {
        self.changed.0.receiver_count()
    }

    /// Until nobody follows the changes.
    #[cfg(test)]
    pub async fn unwatched(&self) {
        self.changed.0.closed().await
    }
}
