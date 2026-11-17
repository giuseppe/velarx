// SPDX-License-Identifier: Apache-2.0
//! Following the logs of the containers of a pod, as `podman pod logs -f`
//! does: the containers are those of the pod when the following starts (one
//! that joins later is not followed), the log of each is followed by a
//! thread of its own until the container exits, and the lines they read are
//! merged into one stream.  The following ends with the last container,
//! the infra container included: it runs as long as the pod does.
//!
//! The lines of a container keep their order.  Across containers they are
//! ordered by the time in their log.  The lines are read by threads of their
//! own, so a line with an earlier time can arrive after one with a later
//! time; to put them in order a line that arrives is held back for the
//! window (`[containers] log_follow_window_ms`) at most: once a line has
//! waited that long, the queued line with the earliest time is given.  The
//! window is an upper bound on the wait, not a guarantee of order: a line
//! that arrives later than the window, after a line with a later time was
//! given, comes out of order (after it).  The history that is read when the
//! following starts is merged without waiting for the window.

use rustix::fd::OwnedFd;
use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::io;
use std::path::PathBuf;
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant};
use tokio::sync::{broadcast, mpsc, Notify};
use tracing::warn;
use velarx_wire::monitor::logfmt::{self, ReadOptions, Record, Stream};

/// The longest line given as one: a longer one is cut in pieces, each a line
/// of its own.
pub const MAX_LINE: usize = 256 * 1024;

/// The most a container may have queued before its reader waits for the
/// consumer.
const QUEUE_BYTES: usize = 4 * 1024 * 1024;

/// A line of a log, with the container it comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub container: String,
    pub container_id: String,
    /// Its place among the containers of the pod (the infra container is
    /// the first)
    pub index: usize,
    pub ts_ns: i64,
    pub stream: Stream,
    pub message: String,
}

/// Where a lane is in its log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// It reads what the log held when the following started.
    History,
    Live,
    Done,
}

/// How the reading of a log ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum End {
    /// It was told to stop (or the time limit came).
    Stopped,
    /// There was no log (the container never ran).
    Missing,
    Failed,
}

struct Queued {
    /// It was read from what the log held when the following started: it
    /// does not wait for the window.
    history: bool,
    ts_ns: i64,
    seq: u64,
    arrived: Instant,
    stream: Stream,
    message: String,
}

struct Lane {
    name: String,
    id: String,
    index: usize,
    phase: Phase,
    end: Option<End>,
    queue: VecDeque<Queued>,
    bytes: usize,
    history_queued: usize,
}

/// The lines of the logs of several containers, put in order.
pub struct Merger {
    lanes: Vec<Lane>,
    window: Duration,
    seq: u64,
    /// The latest time of a line seen, which a line without one takes.
    latest_ns: i64,
}

impl Merger {
    pub fn new(window: Duration) -> Self {
        Self {
            lanes: Vec::new(),
            window,
            seq: 0,
            latest_ns: 0,
        }
    }

    /// A container to merge the lines of; its number.
    pub fn add_lane(&mut self, name: &str, id: &str, index: usize, history: bool) -> usize {
        self.lanes.push(Lane {
            name: name.to_string(),
            id: id.to_string(),
            index,
            phase: if history { Phase::History } else { Phase::Live },
            end: None,
            queue: VecDeque::new(),
            bytes: 0,
            history_queued: 0,
        });
        self.lanes.len() - 1
    }

    /// A line of the container `lane`; `ts_ns` is its time, if it has one.
    pub fn push(
        &mut self,
        lane: usize,
        ts_ns: Option<i64>,
        stream: Stream,
        message: String,
        now: Instant,
    ) {
        let ts_ns = ts_ns.unwrap_or(self.latest_ns);
        self.latest_ns = self.latest_ns.max(ts_ns);
        self.seq += 1;
        let l = &mut self.lanes[lane];
        l.bytes += message.len() + 1;
        let history = l.phase == Phase::History;
        l.history_queued += usize::from(history);
        l.queue.push_back(Queued {
            history,
            ts_ns,
            seq: self.seq,
            arrived: now,
            stream,
            message,
        });
    }

    /// The container has given what its log held.
    pub fn caught_up(&mut self, lane: usize) {
        let l = &mut self.lanes[lane];
        if l.phase == Phase::History {
            l.phase = Phase::Live;
        }
    }

    /// The container has no more lines.
    pub fn finish(&mut self, lane: usize, end: End) {
        let l = &mut self.lanes[lane];
        l.phase = Phase::Done;
        l.end = Some(end);
    }

    pub fn end_of(&self, lane: usize) -> Option<End> {
        self.lanes[lane].end
    }

    pub fn is_done(&self, lane: usize) -> bool {
        self.lanes[lane].phase == Phase::Done
    }

    /// The bytes queued for the container.
    pub fn queued(&self, lane: usize) -> usize {
        self.lanes[lane].bytes
    }

    /// Every container is done and everything was taken.
    pub fn finished(&self) -> bool {
        self.lanes
            .iter()
            .all(|l| l.phase == Phase::Done && l.queue.is_empty())
    }

    /// The containers still reading what their logs held.
    fn reading_history(&self) -> bool {
        self.lanes.iter().any(|l| l.phase == Phase::History)
    }

    /// The first line, by time, of the front of the queues.
    fn first(&self) -> Option<usize> {
        self.lanes
            .iter()
            .enumerate()
            .filter_map(|(i, l)| l.queue.front().map(|q| (q.ts_ns, q.seq, i)))
            .min()
            .map(|(_, _, i)| i)
    }

    fn take(&mut self, lane: usize) -> Entry {
        let l = &mut self.lanes[lane];
        let q = l.queue.pop_front().expect("a queued line");
        l.bytes = l.bytes.saturating_sub(q.message.len() + 1);
        l.history_queued -= usize::from(q.history);
        Entry {
            container: l.name.clone(),
            container_id: l.id.clone(),
            index: l.index,
            ts_ns: q.ts_ns,
            stream: q.stream,
            message: q.message,
        }
    }

    /// Whether a container that reads its history has nothing queued: the
    /// next line may be before any other.
    fn waits_for_history(&self) -> bool {
        self.lanes
            .iter()
            .any(|l| l.phase == Phase::History && l.queue.is_empty())
    }

    /// The next line that may be given.  While the history is read, that is
    /// the first line once each container has one queued (a merge of the
    /// logs); then the first line once a line waited for the window.
    pub fn pop(&mut self, now: Instant) -> Option<Entry> {
        if self.waits_for_history() {
            return None;
        }
        let first = self.first()?;
        let ripe = self
            .lanes
            .iter()
            .filter_map(|l| l.queue.front())
            .any(|q| q.history || now >= q.arrived + self.window);
        if self.reading_history() || ripe {
            return Some(self.take(first));
        }
        None
    }

    /// When a line will be ripe, if `pop` waits for that.
    pub fn deadline(&self) -> Option<Instant> {
        if self.reading_history() || self.lanes.iter().any(|l| l.history_queued > 0) {
            return None;
        }
        self.lanes
            .iter()
            .filter_map(|l| l.queue.front())
            .map(|q| q.arrived + self.window)
            .min()
    }

    /// Everything queued, in order.
    pub fn drain(&mut self) -> Vec<Entry> {
        let mut out = Vec::new();
        while let Some(i) = self.first() {
            out.push(self.take(i));
        }
        out
    }
}

/// The lines of the two streams of a log, put together from its records.
#[derive(Default)]
struct Lines {
    pending: [Option<(i64, Vec<u8>)>; 2],
}

impl Lines {
    /// The lines this record ends (or that it fills past `MAX_LINE`).
    fn push(&mut self, rec: &Record) -> Vec<(i64, Stream, String)> {
        let slot = &mut self.pending[rec.stream as usize];
        let (ts, mut buf) = slot.take().unwrap_or((rec.ts_ns, Vec::new()));
        buf.extend_from_slice(&rec.content);
        let mut out = Vec::new();
        while buf.len() > MAX_LINE {
            let mut cut = MAX_LINE;
            // (not in the middle of a character)
            while cut > 0 && (buf[cut] & 0xC0) == 0x80 {
                cut -= 1;
            }
            if cut == 0 {
                cut = MAX_LINE;
            }
            let rest = buf.split_off(cut);
            out.push((ts, rec.stream, text(&buf)));
            buf = rest;
        }
        if rec.partial {
            *slot = Some((ts, buf));
        } else {
            out.push((ts, rec.stream, text(&buf)));
        }
        out
    }

    /// The lines left open at the end of the log.
    fn rest(&mut self) -> Vec<(i64, Stream, String)> {
        let mut out = Vec::new();
        for (i, slot) in self.pending.iter_mut().enumerate() {
            if let Some((ts, buf)) = slot.take() {
                if !buf.is_empty() {
                    let stream = if i == 0 {
                        Stream::Stdout
                    } else {
                        Stream::Stderr
                    };
                    out.push((ts, stream, text(&buf)));
                }
            }
        }
        out
    }
}

fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

/// What the readers and the consumer share.
struct Shared {
    inner: Mutex<Inner>,
    /// The readers wait here for room in their queue.
    space: Condvar,
    /// The consumer waits here for lines.
    ready: Notify,
}

struct Inner {
    merger: Merger,
    closed: bool,
}

impl Shared {
    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Queue a line; false when nobody takes the lines any more.
    fn push(&self, lane: usize, ts_ns: i64, stream: Stream, message: String) -> bool {
        let mut g = self.lock();
        while g.merger.queued(lane) >= QUEUE_BYTES && !g.closed {
            g = self.space.wait(g).unwrap_or_else(|p| p.into_inner());
        }
        if g.closed {
            return false;
        }
        g.merger
            .push(lane, Some(ts_ns), stream, message, Instant::now());
        drop(g);
        self.ready.notify_one();
        true
    }

    fn caught_up(&self, lane: usize) {
        self.lock().merger.caught_up(lane);
        self.ready.notify_one();
    }

    fn finish(&self, lane: usize, end: End) {
        self.lock().merger.finish(lane, end);
        self.ready.notify_one();
    }

    fn close(&self) {
        self.lock().closed = true;
        self.space.notify_all();
    }
}

/// The readers alive, for who wants to know that none is left.
#[derive(Default)]
pub struct Watchers {
    count: Mutex<usize>,
    idle: Condvar,
}

impl Watchers {
    pub fn count(&self) -> usize {
        *self.count.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Wait until no reader is left; false at the timeout.
    pub fn wait_idle(&self, timeout: Duration) -> bool {
        let g = self.count.lock().unwrap_or_else(|p| p.into_inner());
        let (g, _) = self
            .idle
            .wait_timeout_while(g, timeout, |c| *c > 0)
            .unwrap_or_else(|p| p.into_inner());
        *g == 0
    }

    fn enter(self: &Arc<Self>) -> WatcherGuard {
        *self.count.lock().unwrap_or_else(|p| p.into_inner()) += 1;
        WatcherGuard(self.clone())
    }
}

struct WatcherGuard(Arc<Watchers>);

impl Drop for WatcherGuard {
    fn drop(&mut self) {
        let mut c = self.0.count.lock().unwrap_or_else(|p| p.into_inner());
        *c -= 1;
        if *c == 0 {
            self.0.idle.notify_all();
        }
    }
}

/// A container of the pod, as the daemon sees it now.
#[derive(Debug, Clone)]
pub struct Member {
    pub id: String,
    pub index: usize,
    pub name: String,
    pub path: PathBuf,
    pub allow_dir: Option<PathBuf>,
    /// It runs (or its monitor waits to start it again).
    pub active: bool,
    /// Its log is in the systemd journal (`journalctl` reads it).
    pub journal: bool,
}

/// What tells the containers of the pod.
pub trait Observe: Send + Sync + 'static {
    /// The containers of the pod now; `None` when the pod is gone.
    fn members(&self) -> impl Future<Output = Option<Vec<Member>>> + Send;
}

#[derive(Clone)]
pub struct FollowOptions {
    pub since_ns: Option<i64>,
    pub until_ns: Option<i64>,
    /// The last lines of what the log of each container held (0: none)
    pub tail: Option<usize>,
    /// The longest a line is held back to be put in order with the lines of
    /// the other containers; a line that arrives later comes out of order
    pub window: Duration,
    /// The program that reads the journal
    pub journalctl: PathBuf,
    /// How many containers there are to follow
    pub containers: usize,
}

/// The lines being followed.
pub struct Following {
    pub rx: mpsc::Receiver<Entry>,
    pub watchers: Arc<Watchers>,
    /// How many containers are followed
    pub containers: usize,
}

/// One reader.
struct Reader {
    lane: usize,
    /// It ran when the following started: a log that is not there yet is
    /// then a matter of moments, else the container is not followed.
    running: bool,
    /// Dropped to tell the reader to read what is left and stop.
    stop: Option<OwnedFd>,
}

/// Follow the logs of the containers `observe` tells, until they all
/// exited and their logs were read, `until_ns` came or the receiver of the
/// lines is dropped.  `changes` tells when something happened to the
/// containers (they started, exited, were added or removed).
pub fn follow<T: Clone + Send + 'static, O: Observe>(
    observe: O,
    changes: broadcast::Receiver<T>,
    opts: FollowOptions,
) -> Following {
    let (tx, rx) = mpsc::channel(256);
    let containers = opts.containers;
    let watchers = Arc::new(Watchers::default());
    let shared = Arc::new(Shared {
        inner: Mutex::new(Inner {
            merger: Merger::new(opts.window),
            closed: false,
        }),
        space: Condvar::new(),
        ready: Notify::new(),
    });
    let ctl = Controller {
        observe,
        shared,
        watchers: watchers.clone(),
        opts,
        readers: HashMap::new(),
        started_ns: logfmt::now_ns(),
    };
    tokio::spawn(ctl.run(changes, tx));
    Following {
        rx,
        watchers,
        containers,
    }
}

struct Controller<O> {
    observe: O,
    shared: Arc<Shared>,
    watchers: Arc<Watchers>,
    opts: FollowOptions,
    readers: HashMap<String, Reader>,
    started_ns: i64,
}

impl<O> Drop for Controller<O> {
    fn drop(&mut self) {
        // (the readers stop: their descriptors close, and none waits)
        self.shared.close();
    }
}

impl<O: Observe> Controller<O> {
    fn spawn_reader(&mut self, m: &Member, initial: bool) {
        // (a journal has no mark for the end of what it held: its lines wait
        // for the window like the live ones)
        let lane =
            self.shared
                .lock()
                .merger
                .add_lane(&m.name, &m.id, m.index, initial && !m.journal);
        let (stop_r, stop_w) = match rustix::pipe::pipe_with(rustix::pipe::PipeFlags::CLOEXEC) {
            Ok(p) => p,
            Err(e) => {
                warn!("Cannot follow the log of {}: {}", m.name, e);
                self.shared.finish(lane, End::Failed);
                return;
            }
        };
        let since_ns = if initial {
            self.opts.since_ns
        } else {
            // what the container logged before is not for this following
            Some(
                self.opts
                    .since_ns
                    .map_or(self.started_ns, |s| s.max(self.started_ns)),
            )
        };
        let read = ReadOptions {
            since_ns,
            until_ns: self.opts.until_ns,
            tail: if initial { self.opts.tail } else { None },
            // (a container that does not run: what its log holds, no more)
            follow: m.active,
            allow_dir: m.allow_dir.clone(),
        };
        let guard = self.watchers.enter();
        let (shared, path, name) = (self.shared.clone(), m.path.clone(), m.name.clone());
        let journal = m
            .journal
            .then(|| (self.opts.journalctl.clone(), m.id.clone()));
        let spawned = std::thread::Builder::new()
            .name(format!("podlog-{}", m.name))
            .spawn(move || {
                let _guard = guard;
                let end = match journal {
                    Some((program, id)) => {
                        read_journal_lane(&shared, lane, &program, &id, &read, &stop_r)
                    }
                    None => read_lane(&shared, lane, &path, &read, &stop_r),
                };
                if end == End::Failed {
                    warn!("The log of {} cannot be followed", name);
                }
                shared.finish(lane, end);
            });
        if let Err(e) = spawned {
            warn!("Cannot follow the log of {}: {}", m.name, e);
            self.shared.finish(lane, End::Failed);
            return;
        }
        self.readers.insert(
            m.id.clone(),
            Reader {
                lane,
                running: m.active,
                stop: Some(stop_w),
            },
        );
    }

    /// Follow the containers of the pod when the following starts; later,
    /// only start again to follow one that was running and whose log was not
    /// there yet, and let go of those that are gone.  Whether the containers followed have all
    /// exited (`None` when the pod is gone).
    async fn reconcile(&mut self, initial: bool) -> Option<bool> {
        let members = self.observe.members().await?;
        for m in &members {
            match self.readers.get(&m.id) {
                None if initial => self.spawn_reader(m, true),
                None => {}
                Some(r) => {
                    // a container that had no log when it was looked at,
                    // and runs now
                    let missing = {
                        let g = self.shared.lock();
                        g.merger.end_of(r.lane) == Some(End::Missing)
                    };
                    if missing && m.active && r.running {
                        self.spawn_reader(m, false);
                    }
                }
            }
        }
        for (id, r) in self.readers.iter_mut() {
            if !members.iter().any(|m| &m.id == id) {
                r.stop = None;
            }
        }
        // (only a container that ran when the following started keeps it
        // going)
        Some(
            members
                .iter()
                .filter(|m| self.readers.get(&m.id).is_some_and(|r| r.running))
                .all(|m| !m.active),
        )
    }

    fn stop_all(&mut self) {
        for r in self.readers.values_mut() {
            r.stop = None;
        }
    }

    async fn run<T: Clone>(mut self, changes: broadcast::Receiver<T>, tx: mpsc::Sender<Entry>) {
        let mut changes = Some(changes);
        let mut ending = self.reconcile(true).await.is_none_or(|exited| exited);
        if ending {
            self.stop_all();
        }
        let until = self.opts.until_ns.map(|u| {
            let left = u.saturating_sub(logfmt::now_ns()).max(0) as u64;
            tokio::time::Instant::now() + Duration::from_nanos(left)
        });
        loop {
            // what can be given
            loop {
                let entry = {
                    let mut g = self.shared.lock();
                    let e = g.merger.pop(Instant::now());
                    if e.is_some() {
                        self.shared.space.notify_all();
                    }
                    e
                };
                let Some(e) = entry else {
                    break;
                };
                if tx.send(e).await.is_err() {
                    return;
                }
            }
            let (finished, deadline) = {
                let g = self.shared.lock();
                (g.merger.finished(), g.merger.deadline())
            };
            if ending && finished {
                break;
            }
            enum Wake {
                Ready,
                Window,
                Limit,
                Changed,
                NoMoreChanges,
            }
            let sleep = async {
                match deadline {
                    Some(d) => tokio::time::sleep_until(tokio::time::Instant::from_std(d)).await,
                    None => std::future::pending().await,
                }
            };
            let limit = async {
                match until {
                    Some(u) if !ending => tokio::time::sleep_until(u).await,
                    _ => std::future::pending().await,
                }
            };
            let change = async {
                match changes.as_mut() {
                    Some(c) => match c.recv().await {
                        Err(broadcast::error::RecvError::Closed) => Wake::NoMoreChanges,
                        _ => Wake::Changed,
                    },
                    None => std::future::pending().await,
                }
            };
            let wake = tokio::select! {
                _ = tx.closed() => return,
                _ = self.shared.ready.notified() => Wake::Ready,
                _ = sleep => Wake::Window,
                _ = limit => Wake::Limit,
                w = change => w,
            };
            match wake {
                Wake::Ready | Wake::Window => {}
                Wake::Limit => {
                    ending = true;
                    self.stop_all();
                }
                Wake::NoMoreChanges => {
                    // nobody tells what happens to the containers
                    changes = None;
                    ending = true;
                    self.stop_all();
                }
                Wake::Changed => {
                    if !ending && self.reconcile(false).await != Some(false) {
                        ending = true;
                        self.stop_all();
                    }
                }
            }
        }
        // the end: what is queued, in order
        let rest = {
            let mut g = self.shared.lock();
            g.merger.drain()
        };
        for e in rest {
            if tx.send(e).await.is_err() {
                return;
            }
        }
    }
}

/// Read the log into the queue of `lane` until it is told to stop.
fn read_lane(
    shared: &Shared,
    lane: usize,
    path: &std::path::Path,
    read: &ReadOptions,
    stop: &OwnedFd,
) -> End {
    let mut lines = Lines::default();
    let mut gone = false;
    let result = logfmt::read_logs_with(
        path,
        read,
        Some(stop),
        &mut |rec| {
            for (ts, stream, message) in lines.push(rec) {
                if !shared.push(lane, ts, stream, message) {
                    gone = true;
                    return Err(io::Error::from(io::ErrorKind::BrokenPipe));
                }
            }
            Ok(())
        },
        &mut || shared.caught_up(lane),
    );
    if !gone {
        for (ts, stream, message) in lines.rest() {
            if !shared.push(lane, ts, stream, message) {
                break;
            }
        }
    }
    match result {
        Ok(()) => End::Stopped,
        Err(_) if gone => End::Stopped,
        Err(e) if e.kind() == io::ErrorKind::NotFound => End::Missing,
        Err(e) => {
            warn!("Cannot read the log {}: {}", path.display(), e);
            End::Failed
        }
    }
}

/// Read the journal for the container `id` into the queue of `lane` until
/// it is told to stop: `journalctl --follow` gives the entries as they
/// come; once told to stop, what came after the last one is read from the
/// cursor.
fn read_journal_lane(
    shared: &Shared,
    lane: usize,
    program: &std::path::Path,
    id: &str,
    read: &ReadOptions,
    stop: &OwnedFd,
) -> End {
    use std::os::fd::AsFd;
    use velarx_wire::monitor::journal::Query;
    // (the entries of this user's monitors only, as podman's)
    let Ok(uid) = velarx_base::ids::host_uid() else {
        return End::Failed;
    };
    let query = Query {
        program: program.to_path_buf(),
        id: id.to_string(),
        uid,
        since_ns: read.since_ns,
        until_ns: read.until_ns,
        tail: read.tail,
    };
    let mut give = |l: logfmt::JournalLine| {
        let ts = logfmt::parse_rfc3339_ns(&l.timestamp);
        let stream = if l.stderr {
            Stream::Stderr
        } else {
            Stream::Stdout
        };
        shared.push(lane, ts.unwrap_or_else(logfmt::now_ns), stream, l.message)
    };
    match query.follow().and_then(|f| f.run(stop.as_fd(), &mut give)) {
        Ok(()) => End::Stopped,
        Err(e) => {
            warn!("Cannot read the journal with {}: {e}", program.display());
            End::Failed
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(base: Instant, ms: u64) -> Instant {
        base + Duration::from_millis(ms)
    }

    fn texts(v: &[Entry]) -> Vec<String> {
        v.iter()
            .map(|e| format!("{}:{}", e.container, e.message))
            .collect()
    }

    #[test]
    fn history_is_merged_by_time() {
        let t0 = Instant::now();
        let mut m = Merger::new(Duration::from_millis(100));
        let a = m.add_lane("a", "ida", 0, true);
        let b = m.add_lane("b", "idb", 0, true);
        for (ts, s) in [(1, "a1"), (4, "a2"), (6, "a3")] {
            m.push(a, Some(ts), Stream::Stdout, s.into(), t0);
        }
        // b has nothing yet: nothing can be given
        assert!(m.pop(t0).is_none());
        for (ts, s) in [(2, "b1"), (3, "b2"), (5, "b3")] {
            m.push(b, Some(ts), Stream::Stdout, s.into(), t0);
        }
        m.caught_up(a);
        m.caught_up(b);
        assert_eq!(
            texts(&m.drain()),
            ["a:a1", "b:b1", "b:b2", "a:a2", "b:b3", "a:a3"]
        );
    }

    #[test]
    fn live_lines_wait_for_the_window_and_are_ordered() {
        let t0 = Instant::now();
        let mut m = Merger::new(Duration::from_millis(100));
        let a = m.add_lane("a", "ida", 0, false);
        let b = m.add_lane("b", "idb", 0, false);
        // b's line is older but arrives after
        m.push(a, Some(20), Stream::Stdout, "late".into(), at(t0, 0));
        assert!(m.pop(at(t0, 50)).is_none());
        m.push(b, Some(10), Stream::Stdout, "early".into(), at(t0, 60));
        assert_eq!(m.deadline(), Some(at(t0, 100)));
        assert!(m.pop(at(t0, 99)).is_none());
        assert_eq!(m.pop(at(t0, 100)).unwrap().message, "early");
        assert_eq!(m.pop(at(t0, 100)).unwrap().message, "late");
        assert!(m.pop(at(t0, 500)).is_none());
    }

    #[test]
    fn the_lines_of_a_container_keep_their_order() {
        let t0 = Instant::now();
        let mut m = Merger::new(Duration::from_millis(10));
        let a = m.add_lane("a", "ida", 0, false);
        let b = m.add_lane("b", "idb", 0, false);
        // a's second line has an earlier time than its first (stdout and
        // stderr are put together by the time their line began)
        m.push(a, Some(30), Stream::Stdout, "a-first".into(), t0);
        m.push(a, Some(5), Stream::Stderr, "a-second".into(), t0);
        m.push(b, Some(10), Stream::Stdout, "b".into(), t0);
        let out = m.drain();
        assert_eq!(texts(&out), ["b:b", "a:a-first", "a:a-second"]);
    }

    #[test]
    fn a_container_that_joins_late_is_merged_in() {
        let t0 = Instant::now();
        let mut m = Merger::new(Duration::from_millis(10));
        let a = m.add_lane("a", "ida", 0, false);
        m.push(a, Some(1), Stream::Stdout, "a1".into(), t0);
        assert_eq!(m.pop(at(t0, 20)).unwrap().message, "a1");
        let b = m.add_lane("b", "idb", 0, false);
        m.push(b, Some(2), Stream::Stdout, "b1".into(), at(t0, 30));
        m.push(a, Some(3), Stream::Stdout, "a2".into(), at(t0, 30));
        assert_eq!(texts(&m.drain()), ["b:b1", "a:a2"]);
        m.finish(a, End::Stopped);
        m.finish(b, End::Stopped);
        assert!(m.finished());
    }

    #[test]
    fn a_line_without_a_time_follows_the_ones_before() {
        let t0 = Instant::now();
        let mut m = Merger::new(Duration::from_millis(10));
        let a = m.add_lane("a", "ida", 0, false);
        let b = m.add_lane("b", "idb", 0, false);
        m.push(a, Some(50), Stream::Stdout, "a".into(), t0);
        m.push(b, None, Stream::Stdout, "b".into(), t0);
        m.push(a, Some(60), Stream::Stdout, "a2".into(), t0);
        assert_eq!(texts(&m.drain()), ["a:a", "b:b", "a:a2"]);
    }

    fn rec(ts: i64, stream: Stream, partial: bool, content: &[u8]) -> Record {
        Record {
            ts_ns: ts,
            stream,
            partial,
            content: content.to_vec(),
        }
    }

    #[test]
    fn partial_records_make_one_line_and_the_open_one_is_kept_for_the_end() {
        let mut l = Lines::default();
        assert!(l.push(&rec(1, Stream::Stdout, true, b"hel")).is_empty());
        assert!(l.push(&rec(2, Stream::Stderr, false, b"err")).len() == 1);
        let done = l.push(&rec(3, Stream::Stdout, false, b"lo"));
        assert_eq!(done, vec![(1, Stream::Stdout, "hello".to_string())]);
        assert!(l.push(&rec(4, Stream::Stdout, true, b"tail")).is_empty());
        assert_eq!(l.rest(), vec![(4, Stream::Stdout, "tail".to_string())]);
        assert!(l.rest().is_empty());
    }

    #[test]
    fn a_huge_line_is_cut_in_pieces_at_characters() {
        let mut l = Lines::default();
        // 'é' is 2 bytes: the pieces must not split it
        let huge: Vec<u8> = "é".repeat(MAX_LINE).into_bytes();
        let mut got = Vec::new();
        for chunk in huge.chunks(16 * 1024) {
            got.extend(l.push(&rec(1, Stream::Stdout, true, chunk)));
        }
        got.extend(l.push(&rec(1, Stream::Stdout, false, b"")));
        assert!(got.len() >= 2);
        assert!(got.iter().all(|(_, _, s)| s.len() <= MAX_LINE));
        assert!(got.iter().all(|(_, _, s)| !s.contains('\u{fffd}')));
        let total: usize = got.iter().map(|(_, _, s)| s.len()).sum();
        assert_eq!(total, huge.len());
    }
}
