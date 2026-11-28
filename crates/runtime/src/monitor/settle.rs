// SPDX-License-Identifier: Apache-2.0
//! What happens to the container is recorded by the monitor itself: its
//! health results, restarts and exit go to the store and to the events, its
//! network is released and an `--rm` container removed, by threads of the
//! monitor, with no engine alive (`crate::settle`).
//!
//! * `settle-record`: one thread for the events while the container runs
//!   (health, out of memory, restarts), in order.  It opens the store when a
//!   job comes and closes it after [`IDLE`] without one, so that a monitor
//!   that is idle holds no database.
//! * `settle-exit`: the end of the container for good: its network, then the
//!   exit with its `died` event.
//! * `settle-remove`: the files and rows of an `--rm` container, once the
//!   monitor released what it mounted.
//!
//! The main thread polls, forks the runtime and never waits for SQLite, a
//! lock or the kernel's network code: a job reports by writing to an eventfd
//! that the poll loop watches.
//!
//! The last job of a container writes the log of the store back after it
//! reported (`Store::write_back`), and the monitor waits for it as the last
//! thing it does ([`Settler::wait_ended`]): the engine that waits for the
//! end of the container is told first and goes on, and the process that
//! closes the store last (the one that checkpoints it, under the lock of
//! the file that every other process waits for) is this one, not the
//! command the user waits for.

use super::confine;
use crate::settle::{self, SettlePlan};
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::path::PathBuf;
use std::sync::mpsc;
use std::sync::Arc;
use std::time::{Duration, Instant};
use velarx_db::sync::Store;
use velarx_netkernel::netns::Netns;
use velarx_proto::health::Health;
use velarx_wire::monitor::proto::{Event, ExitInfo};

/// How long the whole end of a container may take: a service manager that
/// stops the unit waits for the monitor.
pub const LIMIT: Duration = Duration::from_secs(60);

/// How long the store stays open without a job.
const IDLE: Duration = Duration::from_secs(2);

/// The most jobs waiting for the record thread.
const QUEUE_MAX: usize = 256;

/// The stack of a job thread.
const STACK: usize = 512 * 1024;

enum RecordJob {
    Health(Health),
    Oom,
    Restarting(ExitInfo, u32),
    Started {
        pid: i32,
        ns: i64,
        count: u32,
    },
    /// Answered once every job before it was applied
    Barrier(mpsc::Sender<()>),
}

enum Done {
    /// The exit is settled; `removable`: the container's row is there for the
    /// removal to go on
    Exit {
        recorded: bool,
        removable: bool,
        /// Why the exit job stopped short
        failure: Option<String>,
    },
    Removed(settle::remove::Removal),
}

pub struct Settler {
    plan: Option<Arc<SettlePlan>>,
    record: Option<mpsc::SyncSender<RecordJob>>,
    /// The record thread ended (it could not confine itself): no other one
    /// is started
    record_gone: bool,
    wake: Arc<OwnedFd>,
    results: mpsc::Receiver<Done>,
    results_tx: mpsc::Sender<Done>,
    /// Each job thread sends once when it is over, after the store is
    /// written back and closed
    ended: mpsc::Receiver<()>,
    ended_tx: mpsc::Sender<()>,
    /// The job threads that were started and did not say they ended
    running: usize,
    netns: Option<Arc<OwnedFd>>,
    /// The mount namespace the monitor started in, where the mounts of the
    /// engine are
    outer_mnt: Option<Arc<OwnedFd>>,
    /// The exit job runs, or ran
    started: Option<Instant>,
    exit_info: Option<ExitInfo>,
    /// The container goes with its exit, and its anonymous volumes with it
    remove: bool,
    volumes: bool,
    /// The exit is in the store
    recorded: bool,
    /// What the removal came to
    removal: Option<settle::remove::Removal>,
    /// Why the exit job stopped short
    exit_failure: Option<String>,
    /// `settle-exit` finished
    exit_settled: bool,
    removable: bool,
    removing: bool,
    done: bool,
}

fn eventfd() -> std::io::Result<OwnedFd> {
    Ok(rustix::event::eventfd(
        0,
        rustix::event::EventfdFlags::CLOEXEC | rustix::event::EventfdFlags::NONBLOCK,
    )?)
}

impl Settler {
    /// A settler for `plan`; none: nothing is recorded (what is told is
    /// done at once).
    pub fn new(plan: Option<SettlePlan>) -> std::io::Result<Self> {
        let (results_tx, results) = mpsc::channel();
        let (ended_tx, ended) = mpsc::channel();
        Ok(Self {
            plan: plan.map(Arc::new),
            record: None,
            record_gone: false,
            wake: Arc::new(eventfd()?),
            results,
            results_tx,
            ended,
            ended_tx,
            running: 0,
            netns: None,
            outer_mnt: None,
            started: None,
            exit_info: None,
            remove: false,
            volumes: false,
            recorded: false,
            removal: None,
            exit_failure: None,
            exit_settled: false,
            removable: false,
            removing: false,
            done: false,
        })
    }

    /// The monitor has no plan: nothing is recorded, nothing is removed.
    pub fn plan_absent(&self) -> bool {
        self.plan.is_none()
    }

    pub fn plan(&self) -> Option<&SettlePlan> {
        self.plan.as_deref()
    }

    pub fn enabled(&self) -> bool {
        self.plan.is_some()
    }

    /// The namespace the monitor holds for its container: its network is
    /// released through it.
    pub fn set_netns(&mut self, netns: Option<Arc<OwnedFd>>) {
        self.netns = netns;
    }

    /// The mount namespace the monitor was started in, opened before it made
    /// its own: the unmounts of the jobs are made there.
    pub fn set_outer_mnt(&mut self, outer: Option<OwnedFd>) {
        self.outer_mnt = outer.map(Arc::new);
    }

    /// What the poll loop watches: readable when a job reported.
    pub fn fd(&self) -> BorrowedFd<'_> {
        self.wake.as_fd()
    }

    /// An event of the container: the health results, the kills for lack of
    /// memory and the restarts are recorded, in order; the others are not
    /// the record thread's.
    pub fn push(&mut self, event: &Event) {
        let job = match event {
            Event::Health(h) => RecordJob::Health(h.clone()),
            Event::Oom => RecordJob::Oom,
            Event::Restarting {
                exit,
                restart_count,
            } => RecordJob::Restarting(exit.clone(), *restart_count),
            Event::Started {
                pid,
                started_ns,
                restart_count,
                restarted: true,
            } => RecordJob::Started {
                pid: *pid,
                ns: *started_ns,
                count: *restart_count,
            },
            _ => return,
        };
        let Some(plan) = self.plan.clone() else {
            return;
        };
        if self.record.is_none() && !self.record_gone {
            self.record = start_record(plan);
        }
        if let Some(tx) = &self.record {
            // (a queue that is full drops what comes: the monitor never waits
            // for the store; health results are the ones that come in bulk)
            match tx.try_send(job) {
                Ok(()) => {}
                Err(mpsc::TrySendError::Full(_)) => {
                    super::server::diag("the record queue is full: an event is dropped");
                }
                // (the thread ended: it said why; the engine's next command
                // reconciles what is not recorded)
                Err(mpsc::TrySendError::Disconnected(_)) => {
                    self.record = None;
                    self.record_gone = true;
                }
            }
        }
    }

    /// The container exited for good: its network is released and the exit
    /// recorded.  The monitor goes on once [`Self::exit_settled`].
    pub fn start_exit(&mut self, info: Option<ExitInfo>, remove: bool, volumes: bool) {
        let Some(plan) = self.plan.clone() else {
            return;
        };
        if self.started.is_some() {
            return;
        }
        self.started = Some(Instant::now());
        self.exit_info = info.clone();
        self.remove = remove;
        self.volumes = volumes;
        if self.record.is_none() && !self.record_gone {
            self.record = start_record(plan.clone());
        }
        let (info, netns, outer, tx, wake, record, ended) = (
            info,
            self.netns.clone(),
            self.outer_mnt.clone(),
            self.results_tx.clone(),
            self.wake.clone(),
            self.record.clone(),
            self.ended_tx.clone(),
        );
        let spawned = std::thread::Builder::new()
            .name("settle-exit".into())
            .stack_size(STACK)
            .spawn(move || {
                let mut store = None;
                let done = exit_job(
                    &plan,
                    info.as_ref(),
                    netns,
                    outer.as_deref(),
                    record,
                    &mut store,
                );
                // (a removal follows when the container is there to remove)
                let last = !matches!(&done, Done::Exit { removable: true, .. } if remove);
                let _ = tx.send(done);
                let _ = rustix::io::write(&*wake, &1u64.to_ne_bytes());
                end_job(store, last, &ended);
            });
        match spawned {
            Ok(_) => self.running += 1,
            Err(e) => {
                super::server::diag(&format!("cannot start the exit job: {e}"));
                self.exit_settled = true;
                self.done = true;
            }
        }
    }

    /// The deadline of the whole end of the container.
    pub fn exit_deadline(&self) -> Option<Instant> {
        self.started.map(|s| s + LIMIT).filter(|_| !self.done)
    }

    /// The monitor read the eventfd: take what the jobs said.
    pub fn reap(&mut self) {
        let mut buf = [0u8; 8];
        let _ = rustix::io::read(&*self.wake, &mut buf);
        while let Ok(done) = self.results.try_recv() {
            match done {
                Done::Exit {
                    recorded,
                    removable,
                    failure,
                } => {
                    if !recorded && self.exit_info.is_some() {
                        super::server::diag("the exit is not in the store");
                    }
                    self.exit_failure = failure;
                    self.exit_settled = true;
                    self.recorded = recorded;
                    self.removable = removable;
                    if !(removable && self.remove) {
                        self.done = true;
                    }
                }
                Done::Removed(r) => {
                    if let Some(why) = &r.failure {
                        super::server::diag(&format!("the container is not removed: {why}"));
                    }
                    self.removal = Some(r);
                    self.done = true;
                }
            }
        }
    }

    /// The exit job finished (the monitor may go on with the runtime and the
    /// removal).
    pub fn exit_settled(&self) -> bool {
        self.exit_settled
    }

    /// The container goes with its exit and its row is there.
    pub fn wants_removal(&self) -> bool {
        self.exit_settled && self.removable && !self.removing && self.remove
    }

    /// The container goes now: its removal starts when its exit is settled
    /// (it may be settled already: the monitor was going to end).  False when
    /// the removal is under way or done.
    pub fn request_removal(&mut self, volumes: bool) -> bool {
        if self.removing {
            return false;
        }
        self.remove = true;
        self.volumes |= volumes;
        // (an exit that was settled without removal is not the end any more)
        if self.exit_settled && self.removable {
            self.done = false;
        }
        true
    }

    /// The removal is under way.
    pub fn removing(&self) -> bool {
        self.removing
    }

    /// What the exit for good came to, once it did.
    pub fn settled(&self) -> Option<velarx_wire::monitor::proto::Settled> {
        use velarx_proto::transfer::{Failure, FailureClass};
        use velarx_wire::monitor::proto::Settled;
        // (no plan: nothing is recorded, what is told is done at once)
        if self.plan.is_none() {
            return Some(Settled {
                recorded: true,
                removed: false,
                image: None,
                failure: None,
            });
        }
        if !self.done && !self.deadline_passed() {
            return None;
        }
        let removal = self.removal.as_ref();
        let failure = match (removal, self.exit_settled) {
            (Some(r), _) => r.failure.clone(),
            (None, true) => self.exit_failure.clone(),
            (None, false) => Some(format!(
                "the exit was not settled within {} s",
                LIMIT.as_secs()
            )),
        };
        Some(Settled {
            recorded: self.recorded,
            removed: removal.is_some_and(|r| r.removed),
            image: removal.and_then(|r| r.image.clone()),
            failure: failure.map(|reason| Failure {
                class: FailureClass::Transient,
                reason,
            }),
        })
    }

    fn deadline_passed(&self) -> bool {
        self.started.is_some_and(|s| Instant::now() >= s + LIMIT)
    }

    /// Remove the container's files and rows (the monitor released its mounts
    /// and the runtime forgot the container).
    pub fn start_removal(&mut self) {
        let Some(plan) = self.plan.clone() else {
            return;
        };
        self.removing = true;
        let code = self.exit_info.as_ref().map(|i| i.code);
        let volumes = self.volumes;
        let (outer, tx, wake, ended) = (
            self.outer_mnt.clone(),
            self.results_tx.clone(),
            self.wake.clone(),
            self.ended_tx.clone(),
        );
        let spawned = std::thread::Builder::new()
            .name("settle-remove".into())
            .stack_size(STACK)
            .spawn(move || {
                let mut store = None;
                let done = remove_job(&plan, code, volumes, outer.as_deref(), &mut store);
                let _ = tx.send(Done::Removed(done));
                let _ = rustix::io::write(&*wake, &1u64.to_ne_bytes());
                end_job(store, true, &ended);
            });
        match spawned {
            Ok(_) => self.running += 1,
            Err(e) => {
                super::server::diag(&format!("cannot start the removal: {e}"));
                self.done = true;
            }
        }
    }

    /// The exit job runs, or its result is not taken yet: it starts the
    /// CNI plugins and waits for them, so the monitor must not reap them
    /// as strays.  (The removal job starts no process.)
    pub fn spawning(&self) -> bool {
        self.started.is_some() && !self.exit_settled
    }

    /// What the end of the container came to; the monitor tells its clients
    /// once this is true (or the deadline passed).
    pub fn exit_done(&self, now: Instant) -> bool {
        if self.plan.is_none() || self.started.is_none() {
            return true;
        }
        self.done || self.started.is_some_and(|s| now >= s + LIMIT)
    }

    /// Wait for the job threads to end: what they write back to the store
    /// after they reported is on disk before the monitor goes.  Bounded by
    /// the deadline of the whole end ([`LIMIT`] from the exit), not by one of
    /// its own: a job that is stuck past it is left behind, as it is by the
    /// clients.
    pub fn wait_ended(&mut self) {
        let Some(deadline) = self.started.map(|s| s + LIMIT) else {
            return;
        };
        while self.running > 0 {
            let left = deadline.saturating_duration_since(Instant::now());
            match self.ended.recv_timeout(left) {
                Ok(()) => self.running -= 1,
                Err(_) => break,
            }
        }
    }

    /// The monitor ends: the record thread ends with its queue, and what
    /// it has is applied first.
    pub fn finish(&mut self) {
        if let Some(tx) = self.record.take() {
            let (b, wait) = mpsc::channel();
            if tx.send(RecordJob::Barrier(b)).is_ok() {
                let _ = wait.recv_timeout(LIMIT);
            }
        }
    }
}

/// Make this thread run in the mount namespace `outer`, where what the engine
/// mounted is: its own fs struct first, as `setns` of a mount namespace needs.
fn join_mounts(outer: Option<&OwnedFd>) {
    let Some(outer) = outer else {
        return;
    };
    let joined = velarx_sys::ns::unshare(rustix::thread::UnshareFlags::FS).and_then(|()| {
        rustix::thread::move_into_link_name_space(
            outer.as_fd(),
            Some(rustix::thread::LinkNameSpaceType::Mount),
        )
        .map_err(std::io::Error::from)
    });
    if let Err(e) = joined {
        super::server::diag(&format!(
            "cannot join the mount namespace of the engine: {e}"
        ));
    }
}

fn start_record(plan: Arc<SettlePlan>) -> Option<mpsc::SyncSender<RecordJob>> {
    let (tx, rx) = mpsc::sync_channel(QUEUE_MAX);
    let spawned = std::thread::Builder::new()
        .name("settle-record".into())
        .stack_size(STACK)
        .spawn(move || record_thread(&plan, &rx));
    match spawned {
        Ok(_) => Some(tx),
        Err(e) => {
            super::server::diag(&format!("cannot start the record thread: {e}"));
            None
        }
    }
}

/// What the threads that record reach, from the plan.
fn recording_of(plan: &SettlePlan) -> confine::Recording {
    use velarx_wire::events::log::EventLog;
    let parent = |p: &std::path::Path| p.parent().map(std::path::Path::to_path_buf);
    confine::Recording {
        store_dir: parent(&plan.db).unwrap_or_else(|| plan.db.clone()),
        events_dir: match &plan.events {
            EventLog::File { path, .. } => parent(path),
            _ => None,
        },
        journal: matches!(plan.events, EventLog::Journald { .. }),
        mon_dir: parent(&plan.start_lock).unwrap_or_else(|| plan.start_lock.clone()),
    }
}

fn record_thread(plan: &SettlePlan, rx: &mpsc::Receiver<RecordJob>) {
    // (the directory of the lock files is made before the thread confines
    // itself: it may make files there, no directory)
    if let Some(dir) = plan.start_lock.parent() {
        if let Err(e) = std::fs::create_dir_all(dir) {
            super::server::diag(&format!("cannot make the directory of the locks: {e}"));
        }
    }
    if let Err(e) = confine::record_thread(&recording_of(plan)) {
        super::server::diag(&format!(
            "the record thread is not confined, it does not run: {e}"
        ));
        return;
    }
    let mut store: Option<Store> = None;
    loop {
        let job = match rx.recv_timeout(IDLE) {
            Ok(job) => job,
            // (idle: no database held)
            Err(mpsc::RecvTimeoutError::Timeout) => {
                store = None;
                match rx.recv() {
                    Ok(job) => job,
                    Err(_) => return,
                }
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => return,
        };
        if let RecordJob::Barrier(b) = job {
            let _ = b.send(());
            continue;
        }
        if store.is_none() {
            match Store::open(&plan.db) {
                Ok(s) => store = Some(s),
                Err(e) => {
                    super::server::diag(&format!("cannot open the store: {e}"));
                    continue;
                }
            }
        }
        let Some(s) = store.as_ref() else {
            continue;
        };
        // (under the lock of the container's start, as the exit: what a start
        // or a removal of the engine writes is not interleaved)
        let _lock = match settle::lock::exclusive(&plan.start_lock) {
            Ok(l) => l,
            Err(e) => {
                super::server::diag(&format!("cannot lock the container: {e}"));
                continue;
            }
        };
        let done = match job {
            RecordJob::Health(h) => settle::record::health(s, plan, &h),
            RecordJob::Oom => settle::record::oom(s, plan),
            RecordJob::Restarting(info, n) => settle::record::restarting(s, plan, &info, n),
            RecordJob::Started { pid, ns, count } => {
                settle::record::started(s, plan, pid, ns, count)
            }
            RecordJob::Barrier(_) => continue,
        };
        if let Err(e) = done {
            super::server::diag(&format!("cannot record: {e}"));
        }
    }
}

/// What the thread of the end of a container reaches, from the plan.
fn releasing_of(plan: &SettlePlan) -> confine::Releasing {
    let state_dir = plan
        .network
        .as_ref()
        .map_or_else(|| plan.removal.mon_dir.clone(), |d| d.state_dir.clone());
    let mut unix_dirs: Vec<PathBuf> = ["/run/dbus", "/run/systemd"]
        .into_iter()
        .map(PathBuf::from)
        .collect();
    if let Some(xdg) = std::env::var_os("XDG_RUNTIME_DIR") {
        unix_dirs.push(PathBuf::from(xdg).join("systemd"));
    }
    unix_dirs.push(state_dir.join("networks"));
    if let Some(d) = &plan.network {
        unix_dirs.extend(
            d.providers
                .iter()
                .filter_map(|p| p.socket.parent().map(std::path::Path::to_path_buf)),
        );
    }
    // (the monitors of the other members answer on their sockets)
    unix_dirs.extend(plan.pod.as_ref().map(|p| p.mon_root.clone()));
    confine::Releasing {
        pods_dir: plan.pod.as_ref().map(|p| p.pods_dir.clone()),
        recording: recording_of(plan),
        state_dir,
        network_lock: velarx_netkernel::bridge::shared_lock(),
        unix_dirs,
    }
}

/// The end of a job thread, after it reported: the store it used is written
/// back when this was the last job (see the module), and closed.
fn end_job(store: Option<Store>, last: bool, ended: &mpsc::Sender<()>) {
    if let Some(store) = store {
        if last {
            if let Err(e) = store.write_back() {
                super::server::diag(&format!("cannot write the store back: {e}"));
            }
        }
        drop(store);
    }
    let _ = ended.send(());
}

/// The exit job.  `keep` gets the store it used, still open, for the thread
/// to write it back once it has reported.
fn exit_job(
    plan: &SettlePlan,
    info: Option<&ExitInfo>,
    netns: Option<Arc<OwnedFd>>,
    outer: Option<&OwnedFd>,
    record: Option<mpsc::SyncSender<RecordJob>>,
    keep: &mut Option<Store>,
) -> Done {
    // What came before the exit is applied first.
    if let Some(tx) = record {
        let (b, wait) = mpsc::channel();
        if tx.send(RecordJob::Barrier(b)).is_ok() {
            let _ = wait.recv_timeout(LIMIT);
        }
    }
    join_mounts(outer);
    let failed = |what: &str, e: &dyn std::fmt::Display| {
        let why = format!("{what}: {e}");
        super::server::diag(&why);
        Done::Exit {
            recorded: false,
            removable: false,
            failure: Some(why),
        }
    };
    // What a start writes comes first: under the lock of the container's
    // start, as the engine's.
    let _lock = match settle::lock::exclusive(&plan.start_lock) {
        Ok(l) => l,
        Err(e) => return failed("cannot lock the container", &e),
    };
    let store = match Store::open(&plan.db) {
        Ok(s) => s,
        Err(e) => return failed("cannot open the store", &e),
    };
    let held = netns.and_then(|fd| fd.try_clone().ok()).map(Netns::from);
    let exiting = match settle::exit::begin(&store, plan, info, held) {
        Ok(x) => x,
        Err(e) => return failed("the exit is not settled", &e),
    };
    // (what a confined thread may not do is done: the mounts, the pool's
    // bind mount, the CNI plugins)
    if let Err(e) = confine::exit_thread(&releasing_of(plan)) {
        return failed(
            "the exit thread is not confined, the exit is left to the engine",
            &e,
        );
    }
    let done = match settle::exit::finish(&store, plan, exiting) {
        Ok(exited) => {
            if let Some(why) = &exited.network_failure {
                super::server::diag(&format!("the network is not released: {why}"));
            }
            if let Some(why) = &exited.pod_failure {
                super::server::diag(why);
            }
            Done::Exit {
                recorded: exited.recorded,
                removable: exited.known,
                failure: None,
            }
        }
        Err(e) => failed("the exit is not settled", &e),
    };
    *keep = Some(store);
    done
}

/// What the thread that removes a container reaches, from the plan.
fn removing_of(plan: &SettlePlan, volumes: &[settle::remove::Volume]) -> confine::Removing {
    let r = &plan.removal;
    let mut trees = vec![
        r.bundle.clone(),
        r.mon_dir.clone(),
        r.log_dir.clone(),
        r.secrets_dir.clone(),
    ];
    trees.extend(r.public_rootfs.clone());
    for v in volumes {
        trees.push(v.mountpoint.clone());
        trees.extend(v.own_dir.clone());
    }
    let mut file_dirs: Vec<PathBuf> = r
        .named_files
        .iter()
        .chain(r.api_record.iter())
        .chain(r.lock_files.iter())
        .filter_map(|f| f.parent().map(std::path::Path::to_path_buf))
        .collect();
    file_dirs.sort();
    file_dirs.dedup();
    confine::Removing {
        recording: recording_of(plan),
        trees,
        file_dirs,
        root: rustix::process::geteuid().is_root(),
    }
}

/// The removal job.  `keep` gets the store it used, as for [`exit_job`].
fn remove_job(
    plan: &SettlePlan,
    code: Option<i32>,
    volumes: bool,
    outer: Option<&OwnedFd>,
    keep: &mut Option<Store>,
) -> settle::remove::Removal {
    let failed = |why: String| {
        super::server::diag(&why);
        settle::remove::Removal {
            removed: false,
            failure: Some(why),
            image: None,
        }
    };
    join_mounts(outer);
    let store = match Store::open(&plan.db) {
        Ok(s) => s,
        Err(e) => return failed(format!("cannot open the store: {e}")),
    };
    let _lock = match settle::lock::exclusive(&plan.start_lock) {
        Ok(l) => l,
        Err(e) => return failed(format!("cannot lock the container: {e}")),
    };
    let done = match settle::remove::prepare(&store, plan, volumes) {
        Ok(settle::remove::Prepare::Go(prepared)) => {
            if let Err(e) = confine::remove_thread(&removing_of(plan, prepared.volumes())) {
                return failed(format!(
                    "the removal thread is not confined, the container is left to the engine: {e}"
                ));
            }
            settle::remove::finish(&store, plan, *prepared, code)
        }
        Ok(settle::remove::Prepare::Gone) => settle::remove::Removal {
            removed: true,
            failure: None,
            image: None,
        },
        Ok(settle::remove::Prepare::Kept) => settle::remove::Removal {
            removed: false,
            failure: None,
            image: None,
        },
        Err(e) => failed(format!("cannot remove the container: {e}")),
    };
    *keep = Some(store);
    done
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::settle::RemovalPlan;
    use velarx_wire::events::log::EventLog;

    fn plan(dir: &std::path::Path) -> SettlePlan {
        SettlePlan {
            id: "c1".into(),
            db: dir.join("missing.db"),
            start_lock: dir.join("c1.lock"),
            storage_lock: dir.join("storage.lock"),
            events: EventLog::File {
                path: dir.join("events"),
                max_size: 0,
            },
            network: None,
            removal: RemovalPlan {
                bundle: dir.join("bundle"),
                mon_dir: dir.join("mon"),
                log_dir: dir.join("log"),
                secrets_dir: dir.join("secrets"),
                public_rootfs: None,
                named_files: Vec::new(),
                api_record: None,
                volumes_dir: dir.join("volumes"),
                volumes_lock: dir.join("volumes.lock"),
                lock_files: Vec::new(),
            },
            image: None,
            pod: None,
            cgroup: None,
        }
    }

    #[test]
    fn the_exit_job_spawns_until_its_result_is_taken() {
        let dir = tempfile::tempdir().unwrap();
        let mut settler = Settler::new(Some(plan(dir.path()))).unwrap();
        assert!(!settler.spawning());
        // (the job waits for the lock of the start: it is running)
        let lock = settle::lock::exclusive(&dir.path().join("c1.lock")).unwrap();
        settler.start_exit(None, false, false);
        assert!(settler.spawning());
        drop(lock);
        settler.wait_ended();
        assert!(settler.spawning(), "the result is not taken yet");
        settler.reap();
        assert!(settler.exit_settled());
        assert!(!settler.spawning());
    }
}
