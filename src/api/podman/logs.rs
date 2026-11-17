// SPDX-License-Identifier: Apache-2.0
//! The container log: one file in the k8s-file format, `<time> <stream>
//! <F|P> <data>` per record, where `P` is the start of a line that a later
//! record of the same stream finishes (`F`).

use super::convert::time_string;
use super::stream::{STDERR, STDOUT};
use std::collections::VecDeque;
use std::io;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::path::{Path, PathBuf};
#[cfg(test)]
use tokio::io::AsyncWriteExt;
use velarx_wire::monitor::logfmt::Follower;
use velarx_wire::monitor::logsel::{Class, Pos, Snapshot};

pub const LOG_FILE: &str = "container.log";

pub fn log_path(dir: &Path) -> PathBuf {
    dir.join(LOG_FILE)
}

#[cfg(test)]
pub struct LogWriter {
    file: tokio::fs::File,
}

#[cfg(test)]
impl std::fmt::Debug for LogWriter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("LogWriter")
    }
}

#[cfg(test)]
impl LogWriter {
    pub async fn open(dir: &Path) -> io::Result<Self> {
        tokio::fs::create_dir_all(dir).await?;
        let file = tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(log_path(dir))
            .await?;
        Ok(Self { file })
    }

    /// Append `data` of `stream`, read at `ts_ns`.
    pub async fn append(&mut self, stream: u8, data: &[u8], ts_ns: i64) -> io::Result<()> {
        let name = if stream == STDERR { "stderr" } else { "stdout" };
        let ts = time_string(ts_ns);
        let mut out = Vec::with_capacity(data.len() + 64);
        let mut rest = data;
        while !rest.is_empty() {
            let (line, flag, next) = match rest.iter().position(|&b| b == b'\n') {
                Some(i) => (&rest[..i], 'F', &rest[i + 1..]),
                None => (rest, 'P', &rest[rest.len()..]),
            };
            out.extend_from_slice(format!("{ts} {name} {flag} ").as_bytes());
            out.extend_from_slice(line);
            out.push(b'\n');
            rest = next;
        }
        self.file.write_all(&out).await?;
        // tokio writes in the background: readers must see the data
        self.file.flush().await
    }
}

/// A line of the log, or a piece of one (see [`LINE_CAP`]).
#[derive(Debug, PartialEq, Eq)]
pub struct Line {
    pub ts_ns: i64,
    pub stream: u8,
    pub data: Vec<u8>,
    /// The line ends with a newline (else the log ends in the middle of it,
    /// or the line goes on in the next piece).
    pub complete: bool,
    /// The piece continues a line begun in the one before: no time in front.
    pub cont: bool,
}

/// The longest piece of a line given at once: a longer line (a container
/// can print a line of any length) comes in pieces of this size, the next
/// ones with `cont` set.
pub const LINE_CAP: usize = velarx_wire::monitor::logsel::LINE_CAP;

/// Lines of the other stream that wait for the line begun before them
/// (see [`select_lines`]) are let go beyond these.
const READY_MAX_LINES: usize = 1024;
const READY_MAX_BYTES: usize = 4 * LINE_CAP;

#[derive(Debug, Default, Clone)]
pub struct Select {
    pub tail: Option<usize>,
    pub since_ns: i64,
    pub until_ns: i64,
    pub stdout: bool,
    pub stderr: bool,
}

struct Rec<'a> {
    ts_ns: i64,
    stream: u8,
    slot: usize,
    /// Anything but `F` starts or goes on with a line.
    partial: bool,
    content: &'a [u8],
}

/// A record of the log, if it is one.
fn parse_rec(raw: &[u8]) -> Option<Rec<'_>> {
    if raw.is_empty() {
        return None;
    }
    let mut f = raw.splitn(4, |&b| b == b' ');
    let (ts, name, flag) = (f.next()?, f.next()?, f.next()?);
    let content = f.next().unwrap_or(&[]);
    let (stream, slot) = match name {
        b"stdout" => (STDOUT, 0),
        b"stderr" => (STDERR, 1),
        _ => return None,
    };
    let ts_ns = std::str::from_utf8(ts)
        .ok()
        .and_then(velarx_proto::time::parse_rfc3339)
        .unwrap_or(0);
    Some(Rec {
        ts_ns,
        stream,
        slot,
        partial: flag != b"F",
        content,
    })
}

struct Open {
    ts_ns: i64,
    data: Vec<u8>,
    cont: bool,
}

/// Joins the records into lines and puts the lines in the order of their
/// start, keeping what it holds bounded.
struct Joiner<'a> {
    sel: &'a Select,
    open: [Option<Open>; 2],
    /// Finished lines that wait for a line begun before them, by start
    /// (then by finish).
    ready: Vec<Line>,
    ready_bytes: usize,
    /// The last `n` lines selected (a tail).
    ring: Option<(usize, VecDeque<Line>)>,
    out: &'a mut dyn FnMut(Line) -> bool,
    stopped: bool,
}

impl Joiner<'_> {
    fn give(&mut self, l: Line) {
        if self.stopped {
            return;
        }
        if !selected_start(self.sel, l.ts_ns) {
            return;
        }
        match &mut self.ring {
            Some((n, ring)) => {
                if ring.len() == *n {
                    ring.pop_front();
                }
                ring.push_back(l);
            }
            None => self.stopped = !(self.out)(l),
        }
    }

    fn release(&mut self, bound: i64) {
        let len = self.ready.len();
        let mut n = 0;
        let mut bytes = self.ready_bytes;
        while n < len {
            let force = len - n > READY_MAX_LINES || bytes > READY_MAX_BYTES;
            if self.ready[n].ts_ns > bound && !force {
                break;
            }
            bytes -= self.ready[n].data.len();
            n += 1;
        }
        self.ready_bytes = bytes;
        let released: Vec<Line> = self.ready.drain(..n).collect();
        for l in released {
            self.give(l);
        }
    }

    fn finished(&mut self, l: Line) {
        // (it goes after the lines of the same start: the stable order)
        let at = self.ready.partition_point(|r| r.ts_ns <= l.ts_ns);
        self.ready_bytes += l.data.len();
        self.ready.insert(at, l);
        let bound = self
            .open
            .iter()
            .flatten()
            .map(|o| o.ts_ns)
            .min()
            .unwrap_or(i64::MAX);
        self.release(bound);
    }

    /// Feed a raw line of the log; false: nothing more is wanted.
    fn feed(&mut self, raw: &[u8]) -> bool {
        let Some(rec) = parse_rec(raw) else {
            return !self.stopped;
        };
        let wanted = if rec.stream == STDOUT {
            self.sel.stdout
        } else {
            self.sel.stderr
        };
        if !wanted {
            return !self.stopped;
        }
        // (the times grow: nothing after the end is wanted, once the lines
        // begun before it are finished)
        if self.sel.until_ns != 0
            && rec.ts_ns > self.sel.until_ns
            && self.open.iter().all(Option::is_none)
        {
            return false;
        }
        let mut cur = self.open[rec.slot].take().unwrap_or(Open {
            ts_ns: rec.ts_ns,
            data: Vec::new(),
            cont: false,
        });
        cur.data.extend_from_slice(rec.content);
        if !rec.partial {
            self.finished(Line {
                ts_ns: cur.ts_ns,
                stream: rec.stream,
                data: cur.data,
                complete: true,
                cont: cur.cont,
            });
        } else if cur.data.len() >= LINE_CAP {
            // a line of any length is given in pieces
            let piece = Line {
                ts_ns: cur.ts_ns,
                stream: rec.stream,
                data: std::mem::take(&mut cur.data),
                complete: false,
                cont: cur.cont,
            };
            cur.cont = true;
            self.open[rec.slot] = Some(cur);
            self.finished(piece);
        } else {
            self.open[rec.slot] = Some(cur);
            // (what waited for this line may go now)
            let bound = self
                .open
                .iter()
                .flatten()
                .map(|o| o.ts_ns)
                .min()
                .unwrap_or(i64::MAX);
            self.release(bound);
        }
        !self.stopped
    }

    /// The end of the log: the lines still open are its last.  Which of
    /// them are selected (a line that goes on in what is read later).
    fn finish(&mut self) -> [Option<bool>; 2] {
        let sel = self.sel;
        let open = [0, 1].map(|slot| {
            self.open[slot]
                .as_ref()
                .map(|o| selected_start(sel, o.ts_ns))
        });
        for slot in 0..2 {
            if let Some(o) = self.open[slot].take() {
                let l = Line {
                    ts_ns: o.ts_ns,
                    stream: if slot == 0 { STDOUT } else { STDERR },
                    data: o.data,
                    complete: false,
                    cont: o.cont,
                };
                let at = self.ready.partition_point(|r| r.ts_ns <= l.ts_ns);
                self.ready_bytes += l.data.len();
                self.ready.insert(at, l);
            }
        }
        self.release(i64::MAX);
        if let Some((_, ring)) = self.ring.take() {
            for l in ring {
                if self.stopped {
                    break;
                }
                self.stopped = !(self.out)(l);
            }
        }
        open
    }
}

/// A line that begins at `ts_ns` is in the times `sel` asks for.
fn selected_start(sel: &Select, ts_ns: i64) -> bool {
    ts_ns >= sel.since_ns && (sel.until_ns == 0 || ts_ns <= sel.until_ns)
}

/// Give the lines of the log in `snap` that `sel` selects to `out` (which
/// returns false when nothing more is wanted), in the order of the start
/// of the lines, as `parse` and `select` did, but streaming:
///
/// * the memory held is a chunk of the files, the lines `tail` asks for and
///   the lines that wait for an earlier line to finish (at most
///   `READY_MAX_LINES` or `READY_MAX_BYTES`: beyond, they are given out
///   of order);
/// * a line longer than [`LINE_CAP`] is given in pieces;
/// * the times of the records are taken to grow along the log; a tail
///   without `since` and `until` is found from the end of the log, so a log
///   whose times go back is not ordered by them over the tail's start.
pub fn select_lines(
    snap: &Snapshot,
    sel: &Select,
    out: &mut dyn FnMut(Line) -> bool,
) -> io::Result<()> {
    select_open(snap, sel, out).map(drop)
}

/// [`select_lines`] that tells which of the lines left open at the end of
/// the snapshot are selected (the lane of a line not finished).
fn select_open(
    snap: &Snapshot,
    sel: &Select,
    out: &mut dyn FnMut(Line) -> bool,
) -> io::Result<[Option<bool>; 2]> {
    if sel.tail == Some(0) {
        return Ok([None, None]);
    }
    let mut class = |raw: &[u8]| {
        let r = parse_rec(raw)?;
        let wanted = if r.stream == STDOUT {
            sel.stdout
        } else {
            sel.stderr
        };
        wanted.then_some(Class {
            lane: r.slot,
            end: !r.partial,
        })
    };
    let mut start = Pos::START;
    if let Some(n) = sel.tail {
        if sel.since_ns <= 0 && sel.until_ns == 0 {
            // (two more than asked: the line that goes on past the start,
            // and the one still open)
            start = snap.locate(n as u64 + 2, &mut class, false, true)?;
        }
    }
    let mut j = Joiner {
        sel,
        open: [None, None],
        ready: Vec::new(),
        ready_bytes: 0,
        ring: sel.tail.map(|n| (n, VecDeque::new())),
        out,
        stopped: false,
    };
    snap.lines_from(&start, true, &mut |raw| Ok(j.feed(raw)))?;
    Ok(j.finish())
}

/// The lines a thread of the pool selected, as it goes (in batches: a
/// channel message for each line is slower than the selection).
pub struct Lines {
    rx: tokio::sync::mpsc::Receiver<Vec<Line>>,
    batch: std::vec::IntoIter<Line>,
    /// A following: dropped with the lines, it wakes the thread that waits
    /// for the log to grow.
    _cancel: Option<OwnedFd>,
}

impl Lines {
    /// No lines.
    pub fn none() -> Lines {
        let (_, rx) = tokio::sync::mpsc::channel(1);
        Lines {
            rx,
            batch: Vec::new().into_iter(),
            _cancel: None,
        }
    }

    pub async fn next(&mut self) -> Option<Line> {
        loop {
            if let Some(l) = self.batch.next() {
                return Some(l);
            }
            self.batch = self.rx.recv().await?.into_iter();
        }
    }
}

/// Select the lines of `snap` in a thread of the pool.
pub fn spawn_select(snap: Snapshot, sel: Select) -> Lines {
    let (tx, rx) = tokio::sync::mpsc::channel(4);
    tokio::task::spawn_blocking(move || {
        let mut out = Batcher {
            tx,
            batch: Vec::new(),
            bytes: 0,
        };
        if select_lines(&snap, &sel, &mut |l| out.push(l)).is_ok() {
            out.flush();
        }
    });
    Lines {
        rx,
        batch: Vec::new().into_iter(),
        _cancel: None,
    }
}

/// Batches of lines for a [`Lines`].
struct Batcher {
    tx: tokio::sync::mpsc::Sender<Vec<Line>>,
    batch: Vec<Line>,
    bytes: usize,
}

impl Batcher {
    const BATCH_BYTES: usize = 128 * 1024;
    const BATCH_LINES: usize = 512;

    /// false: nobody reads the lines any more.
    fn push(&mut self, l: Line) -> bool {
        self.bytes += l.data.len();
        self.batch.push(l);
        self.bytes < Self::BATCH_BYTES && self.batch.len() < Self::BATCH_LINES || self.flush()
    }

    fn flush(&mut self) -> bool {
        self.bytes = 0;
        self.batch.is_empty()
            || self
                .tx
                .blocking_send(std::mem::take(&mut self.batch))
                .is_ok()
    }
}

/// The lines of the records appended to the log after the snapshot, as a
/// reader that went on with it would give them.
struct Live<'a> {
    sel: &'a Select,
    /// For each stream, whether the line begun and not finished is selected.
    open: [Option<bool>; 2],
}

impl Live<'_> {
    /// Give the record `raw` to `out`; an error: the lines are over (the
    /// times asked for, or nobody reads them).
    fn feed(&mut self, raw: &[u8], out: &mut dyn FnMut(Line) -> bool) -> io::Result<()> {
        let Some(rec) = parse_rec(raw) else {
            return Ok(());
        };
        let wanted = if rec.stream == STDOUT {
            self.sel.stdout
        } else {
            self.sel.stderr
        };
        if !wanted {
            return Ok(());
        }
        let cont = self.open[rec.slot].is_some();
        let selected = match self.open[rec.slot] {
            Some(s) => s,
            None => {
                if self.sel.until_ns != 0
                    && rec.ts_ns > self.sel.until_ns
                    && self.open.iter().all(Option::is_none)
                {
                    return Err(io::ErrorKind::TimedOut.into());
                }
                selected_start(self.sel, rec.ts_ns)
            }
        };
        self.open[rec.slot] = rec.partial.then_some(selected);
        if selected && (!rec.content.is_empty() || !rec.partial) {
            let line = Line {
                ts_ns: rec.ts_ns,
                stream: rec.stream,
                data: rec.content.to_vec(),
                complete: !rec.partial,
                cont,
            };
            if !out(line) {
                return Err(io::ErrorKind::BrokenPipe.into());
            }
        }
        Ok(())
    }
}

/// Follow the log at `path`: the lines of its snapshot that `sel` selects,
/// then, as the monitor appends them, the lines that follow, until `exit`
/// is readable (the container is gone; what it wrote last is given), `until`
/// of the selection comes or the lines are dropped.  The thread reads the
/// file: it neither depends on who writes the log nor holds anyone up.
pub fn spawn_follow(
    path: PathBuf,
    allow_dir: Option<PathBuf>,
    sel: Select,
    exit: impl AsFd + Send + 'static,
) -> io::Result<Lines> {
    let slot = FollowSlot::take()?;
    let (cancel_r, cancel_w) = rustix::pipe::pipe_with(rustix::pipe::PipeFlags::CLOEXEC)?;
    let (tx, rx) = tokio::sync::mpsc::channel(4);
    let mut follower = match Follower::open(&path, allow_dir.as_deref()) {
        Ok(f) => Some(f),
        // (nothing was ever written: the lines end at once)
        Err(e) if e.kind() == io::ErrorKind::NotFound => None,
        // (the limits of inotify: the error names the one reached)
        Err(e) if e.kind() == io::ErrorKind::QuotaExceeded => {
            return Err(io::Error::new(io::ErrorKind::ResourceBusy, e.to_string()))
        }
        Err(e) if e.raw_os_error() == Some(rustix::io::Errno::MFILE.raw_os_error()) => {
            return Err(io::Error::new(
                io::ErrorKind::ResourceBusy,
                format!("no file descriptor left: {e}"),
            ))
        }
        Err(e) => return Err(e),
    };
    std::thread::Builder::new()
        .name("logfollow".into())
        .spawn(move || {
            let _slot = slot;
            let Some(follower) = follower.as_mut() else {
                return;
            };
            if let Err(e) = follow_thread(follower, &sel, &exit, &cancel_r, tx) {
                if !matches!(
                    e.kind(),
                    io::ErrorKind::BrokenPipe | io::ErrorKind::TimedOut
                ) {
                    tracing::warn!("cannot follow the log {}: {e}", path.display());
                }
            }
        })?;
    Ok(Lines {
        rx,
        batch: Vec::new().into_iter(),
        _cancel: Some(cancel_w),
    })
}

/// The end of a container, told to all the followers of its log with one
/// connection to its monitor (a monitor serves a few clients at once, and a
/// follower needs no connection of its own).
struct Exit {
    /// Readable for good once the container ended: nobody reads it.
    ended: std::sync::Arc<OwnedFd>,
    done: std::sync::Arc<std::sync::atomic::AtomicBool>,
    /// The connection to the monitor (a copy): readable once it told the
    /// end, before the task that waits for it ran.
    conn: OwnedFd,
    /// Ends the task that waits for the end, when the last follower goes.
    stop: std::sync::Arc<tokio::sync::Notify>,
}

impl Drop for Exit {
    fn drop(&mut self) {
        self.stop.notify_one();
    }
}

impl Exit {
    /// The container has not ended yet (one that ended is of an earlier
    /// run: a follower of the next one needs a watch of its own).
    fn running(&self) -> bool {
        !self.done.load(std::sync::atomic::Ordering::Acquire)
            && !velarx_wire::monitor::proto::wait_fd(&self.conn, rustix::event::PollFlags::IN, 0)
                .unwrap_or(true)
    }
}

/// A descriptor that is readable once the container ended.
pub struct ExitWatch(std::sync::Arc<Exit>);

impl AsFd for ExitWatch {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.0.ended.as_fd()
    }
}

type Exits = std::collections::HashMap<PathBuf, std::sync::Weak<Exit>>;

/// Watch the end of the container whose monitor is in `dir`; the followers
/// of one run share the connection to the monitor.  Needs a tokio runtime.
pub async fn watch_exit(dir: &Path) -> io::Result<ExitWatch> {
    static EXITS: std::sync::LazyLock<std::sync::Mutex<Exits>> =
        std::sync::LazyLock::new(Default::default);
    let known = |dir: &Path| {
        let map = EXITS.lock().unwrap_or_else(|e| e.into_inner());
        map.get(dir)
            .and_then(std::sync::Weak::upgrade)
            .filter(|e| e.running())
    };
    if let Some(exit) = known(dir) {
        return Ok(ExitWatch(exit));
    }
    let path = dir.to_path_buf();
    let conn = tokio::task::spawn_blocking(move || velarx_wire::monitor::client::watch_exit(&path))
        .await
        .map_err(io::Error::other)??;
    let ended = std::sync::Arc::new(rustix::event::eventfd(
        0,
        rustix::event::EventfdFlags::CLOEXEC | rustix::event::EventfdFlags::NONBLOCK,
    )?);
    let copy = conn.try_clone()?;
    let conn = velarx_sys::fd::register(conn, tokio::io::Interest::READABLE)?;
    let exit = std::sync::Arc::new(Exit {
        ended: ended.clone(),
        done: Default::default(),
        conn: copy,
        stop: Default::default(),
    });
    let (done, stop) = (exit.done.clone(), exit.stop.clone());
    {
        // (one watcher: a follower that came meanwhile has made its own)
        let mut map = EXITS.lock().unwrap_or_else(|e| e.into_inner());
        map.retain(|_, w| w.strong_count() > 0);
        if let Some(other) = map
            .get(dir)
            .and_then(std::sync::Weak::upgrade)
            .filter(|e| e.running())
        {
            return Ok(ExitWatch(other));
        }
        map.insert(dir.to_path_buf(), std::sync::Arc::downgrade(&exit));
    }
    tokio::spawn(async move {
        tokio::select! {
            // (readable, or an error: the monitor is gone either way)
            _ = conn.readable() => {
                done.store(true, std::sync::atomic::Ordering::Release);
                let _ = rustix::io::write(&*ended, &1u64.to_ne_bytes());
            }
            () = stop.notified() => {}
        }
    });
    Ok(ExitWatch(exit))
}

/// How many logs the engine follows at most at once: each takes a thread
/// and a few descriptors (the engine has one inotify instance for all of
/// them).
pub const MAX_FOLLOWERS: usize = 1024;

/// The descriptors a follower holds: the directory of the log, the file
/// it reads, its wake-up, the end of the container and the cancel pipe.
const FOLLOWER_FDS: u64 = 8;

/// How many followers there can be now: [`MAX_FOLLOWERS`], fewer when the
/// limit of open files does not leave the descriptors for them (the other
/// calls of the engine need theirs).
fn follower_limit() -> usize {
    let open = rustix::process::getrlimit(rustix::process::Resource::Nofile)
        .current
        .unwrap_or(u64::MAX);
    MAX_FOLLOWERS.min((open.saturating_sub(512) / FOLLOWER_FDS) as usize)
}

static FOLLOWERS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// One of the places for followers, given back when dropped.
struct FollowSlot;

impl FollowSlot {
    /// `ResourceBusy` when all are taken.
    fn take() -> io::Result<Self> {
        use std::sync::atomic::Ordering;
        // (taken, then given back when there was none: FollowSlot's drop)
        let slot = FollowSlot;
        let limit = follower_limit();
        if FOLLOWERS.fetch_add(1, Ordering::AcqRel) < limit {
            return Ok(slot);
        }
        Err(io::Error::new(
            io::ErrorKind::ResourceBusy,
            format!("too many logs followed at once (at most {limit})"),
        ))
    }
}

impl Drop for FollowSlot {
    fn drop(&mut self) {
        FOLLOWERS.fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
    }
}

fn follow_thread(
    follower: &mut Follower,
    sel: &Select,
    exit: &dyn AsFd,
    cancel: &OwnedFd,
    tx: tokio::sync::mpsc::Sender<Vec<Line>>,
) -> io::Result<()> {
    let gone = || io::Error::from(io::ErrorKind::BrokenPipe);
    let mut out = Batcher {
        tx,
        batch: Vec::new(),
        bytes: 0,
    };
    let snap = follower.snapshot()?;
    let open = select_open(&snap, sel, &mut |l| out.push(l))?;
    drop(snap);
    if !out.flush() {
        return Err(gone());
    }
    let mut live = Live { sel, open };
    loop {
        let result = follower.pump(&mut |raw| live.feed(raw, &mut |l| out.push(l)));
        if !out.flush() {
            return Err(gone());
        }
        result?;
        let timeout = match sel.until_ns {
            0 => -1,
            u => {
                let left = u.saturating_sub(velarx_wire::monitor::logfmt::now_ns());
                if left <= 0 {
                    return Ok(());
                }
                (left / 1_000_000 + 1).min(i32::MAX as i64) as i32
            }
        };
        match follower.wait(&[cancel, exit], timeout)? {
            Some(0) => return Ok(()),
            Some(_) => {
                // the container is gone: what it wrote last
                let result = follower.pump(&mut |raw| live.feed(raw, &mut |l| out.push(l)));
                if !out.flush() {
                    return Err(gone());
                }
                return result;
            }
            None => {}
        }
    }
}

/// The bytes of a line for the client.
pub fn render(l: &Line, timestamps: bool) -> Vec<u8> {
    let mut b = Vec::with_capacity(l.data.len() + 40);
    if timestamps && !l.cont {
        b.extend_from_slice(time_string(l.ts_ns).as_bytes());
        b.push(b' ');
    }
    b.extend_from_slice(&l.data);
    if l.complete {
        b.push(b'\n');
    }
    b
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lines_of(log: &[u8], sel: &Select) -> Vec<Line> {
        let dir = tempfile::tempdir_in("/var/tmp").unwrap();
        std::fs::write(log_path(dir.path()), log).unwrap();
        let snap = Snapshot::open(&log_path(dir.path()), None).unwrap();
        let mut out = Vec::new();
        select_lines(&snap, sel, &mut |l| {
            out.push(l);
            true
        })
        .unwrap();
        out
    }

    fn all() -> Select {
        Select {
            stdout: true,
            stderr: true,
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn partial_lines_are_joined() {
        let dir = tempfile::tempdir_in("/var/tmp").unwrap();
        let mut w = LogWriter::open(dir.path()).await.unwrap();
        w.append(STDOUT, b"ab", 1_000_000_000).await.unwrap();
        w.append(STDERR, b"err\n", 1_500_000_000).await.unwrap();
        w.append(STDOUT, b"c\nd", 2_000_000_000).await.unwrap();
        let log = std::fs::read(log_path(dir.path())).unwrap();
        let lines = lines_of(&log, &all());
        assert_eq!(lines.len(), 3);
        assert_eq!(lines[0].data, b"abc");
        assert_eq!(lines[0].stream, STDOUT);
        assert_eq!(lines[1].data, b"err");
        assert_eq!(lines[1].stream, STDERR);
        assert_eq!(lines[2].data, b"d");
        assert!(!lines[2].complete);
        assert_eq!(render(&lines[0], false), b"abc\n");
        assert_eq!(render(&lines[2], false), b"d");
        assert!(render(&lines[0], true).starts_with(b"1970-01-01T00:00:01Z abc"));
    }

    fn rec(sec: u32, stream: &str, flag: char, data: &str) -> String {
        format!("1970-01-01T00:00:{sec:02}Z {stream} {flag} {data}\n")
    }

    #[test]
    fn selection() {
        let mut log = String::new();
        log += &rec(1, "stdout", 'F', "a");
        log += &rec(2, "stderr", 'F', "b");
        log += &rec(3, "stdout", 'F', "c");
        log += &rec(4, "stdout", 'F', "d");
        let text = |sel: &Select| -> Vec<String> {
            lines_of(log.as_bytes(), sel)
                .into_iter()
                .map(|l| String::from_utf8(l.data).unwrap())
                .collect()
        };
        let s = Select {
            tail: Some(1),
            ..all()
        };
        assert_eq!(text(&s), ["d"]);
        let s = Select {
            tail: Some(3),
            ..all()
        };
        assert_eq!(text(&s), ["b", "c", "d"]);
        let s = Select {
            tail: Some(10),
            ..all()
        };
        assert_eq!(text(&s), ["a", "b", "c", "d"]);
        let s = Select {
            tail: Some(0),
            ..all()
        };
        assert!(text(&s).is_empty());
        // one stream
        let s = Select {
            stdout: true,
            tail: Some(2),
            ..Default::default()
        };
        assert_eq!(text(&s), ["c", "d"]);
        // since and until (inclusive), with a tail
        let s = Select {
            since_ns: 2_000_000_000,
            until_ns: 3_000_000_000,
            ..all()
        };
        assert_eq!(text(&s), ["b", "c"]);
        let s = Select {
            since_ns: 2_000_000_000,
            tail: Some(2),
            ..all()
        };
        assert_eq!(text(&s), ["c", "d"]);
    }

    #[test]
    fn garbage_is_skipped() {
        assert!(lines_of(b"not a record\n\nx y\n", &all()).is_empty());
    }

    #[test]
    fn lines_are_ordered_by_start() {
        // stdout begins a line at 1, stderr finishes lines at 2 and 3, then
        // stdout finishes: the line of stdout comes first
        let mut log = String::new();
        log += &rec(1, "stdout", 'P', "so");
        log += &rec(2, "stderr", 'F', "e1");
        log += &rec(3, "stderr", 'F', "e2");
        log += &rec(4, "stdout", 'F', "me");
        let got: Vec<_> = lines_of(log.as_bytes(), &all())
            .into_iter()
            .map(|l| String::from_utf8(l.data).unwrap())
            .collect();
        assert_eq!(got, ["some", "e1", "e2"]);
        // the same through a tail that starts in the middle
        let s = Select {
            tail: Some(2),
            ..all()
        };
        let got: Vec<_> = lines_of(log.as_bytes(), &s)
            .into_iter()
            .map(|l| String::from_utf8(l.data).unwrap())
            .collect();
        assert_eq!(got, ["e1", "e2"]);
    }

    #[test]
    fn lines_beyond_the_window_go_out_of_order_but_are_all_given() {
        // a prompt without newline on stdout, then more lines of stderr
        // than the window holds before stdout ends its line
        let n = READY_MAX_LINES + 500;
        let mut log = rec(1, "stdout", 'P', "prompt: ");
        for i in 0..n {
            log += &rec(2, "stderr", 'F', &format!("e{i}"));
        }
        log += &rec(3, "stdout", 'F', "yes");
        let got: Vec<_> = lines_of(log.as_bytes(), &all())
            .into_iter()
            .map(|l| String::from_utf8(l.data).unwrap())
            .collect();
        assert_eq!(got.len(), n + 1);
        // the first lines of stderr went before, in their order; the rest
        // waited for the line of stdout that began before them
        let at = got.iter().position(|l| l == "prompt: yes").unwrap();
        assert_eq!(at, n - READY_MAX_LINES);
        let errs: Vec<_> = got.iter().filter(|l| l.starts_with('e')).collect();
        assert!(errs.iter().enumerate().all(|(i, l)| **l == format!("e{i}")));
    }

    #[test]
    fn unfinished_lines_close_the_log() {
        let mut log = String::new();
        log += &rec(1, "stdout", 'F', "a");
        log += &rec(2, "stdout", 'P', "b");
        log += &rec(3, "stderr", 'P', "c");
        let got = lines_of(log.as_bytes(), &all());
        assert_eq!(got.len(), 3);
        assert!(!got[1].complete && !got[2].complete);
        let s = Select {
            tail: Some(2),
            ..all()
        };
        let got = lines_of(log.as_bytes(), &s);
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].data, b"b");
        assert_eq!(got[1].data, b"c");
    }

    #[test]
    fn a_huge_line_comes_in_pieces() {
        // 10 MiB in records of 16 KiB, then a short line
        let chunk = "x".repeat(16 * 1024);
        let mut log = String::new();
        for _ in 0..640 {
            log += &rec(1, "stdout", 'P', &chunk);
        }
        log += &rec(1, "stdout", 'F', "end");
        log += &rec(2, "stdout", 'F', "next");
        let got = lines_of(log.as_bytes(), &all());
        assert!(got.len() > 10, "{}", got.len());
        let n: usize = got.iter().map(|l| l.data.len()).sum();
        assert_eq!(n, 640 * 16 * 1024 + 3 + 4);
        assert!(got.iter().all(|l| l.data.len() <= LINE_CAP + 16 * 1024));
        assert!(!got[0].cont && got[1].cont);
        assert!(!got[0].complete);
        let last = &got[got.len() - 2];
        assert!(last.complete && last.cont && last.data.ends_with(b"end"));
        assert_eq!(got.last().unwrap().data, b"next");
        // a tail of one line is the last
        let s = Select {
            tail: Some(1),
            ..all()
        };
        let got = lines_of(log.as_bytes(), &s);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].data, b"next");
        // timestamps only on the first piece
        let got = lines_of(log.as_bytes(), &all());
        assert!(render(&got[0], true).starts_with(b"1970-"));
        assert_eq!(render(&got[1], true).len(), got[1].data.len());
    }

    #[test]
    fn rotated_and_compressed_files() {
        use flate2::{write::GzEncoder, Compression};
        use std::io::Write;
        let dir = tempfile::tempdir_in("/var/tmp").unwrap();
        let path = log_path(dir.path());
        let gz = |s: &str| {
            let mut e = GzEncoder::new(Vec::new(), Compression::fast());
            e.write_all(s.as_bytes()).unwrap();
            e.finish().unwrap()
        };
        // .2.gz: 1..3, the line "four" begins in .1 and ends in the log
        let mut old = String::new();
        for i in 1..=3 {
            old += &rec(i, "stdout", 'F', &format!("l{i}"));
        }
        std::fs::write(format!("{}.2.gz", path.display()), gz(&old)).unwrap();
        let mut mid = String::new();
        mid += &rec(4, "stdout", 'F', "l4");
        mid += &rec(5, "stdout", 'P', "fo");
        std::fs::write(format!("{}.1", path.display()), mid).unwrap();
        let mut cur = String::new();
        cur += &rec(6, "stderr", 'F', "e6");
        cur += &rec(7, "stdout", 'F', "ur");
        std::fs::write(&path, cur).unwrap();
        let snap = Snapshot::open(&path, None).unwrap();
        let run = |sel: &Select| -> Vec<String> {
            let mut out = Vec::new();
            select_lines(&snap, sel, &mut |l| {
                out.push(String::from_utf8(l.data).unwrap());
                true
            })
            .unwrap();
            out
        };
        assert_eq!(run(&all()), ["l1", "l2", "l3", "l4", "four", "e6"]);
        for n in 1..=7usize {
            let all_lines = run(&all());
            let t = run(&Select {
                tail: Some(n),
                ..all()
            });
            let want = &all_lines[all_lines.len().saturating_sub(n)..];
            assert_eq!(t, want, "tail {n}");
        }
    }

    fn hwm_kb() -> u64 {
        let status = std::fs::read_to_string("/proc/self/status").unwrap();
        status
            .lines()
            .find_map(|l| l.strip_prefix("VmHWM:"))
            .and_then(|v| v.trim().trim_end_matches("kB").trim().parse().ok())
            .unwrap()
    }

    /// Select in the ways of the engine and the CLI from the log in `dir`;
    /// the peak memory after the tail and after everything.
    fn suite(dir: &std::path::Path, big: bool) -> (u64, u64) {
        let path = log_path(dir);
        let snap = Snapshot::open(&path, None).unwrap();
        let count = |sel: &Select| {
            let mut n = 0usize;
            select_lines(&snap, sel, &mut |_| {
                n += 1;
                true
            })
            .unwrap();
            n
        };
        let s = Select {
            tail: Some(10),
            ..all()
        };
        assert_eq!(count(&s), 10);
        let after_tail = hwm_kb();
        // since/until: a window of the log, streamed
        let s = Select {
            since_ns: 1_000_000_000_000,
            until_ns: 1_000_000_000_000 + 999_000_000,
            ..all()
        };
        assert!(count(&s) > 100);
        let s = Select {
            since_ns: 1_000_000_000_000,
            tail: Some(5),
            ..all()
        };
        assert_eq!(count(&s), 5);
        // all of it
        let n = count(&all());
        assert!(n > if big { 400_000 } else { 1_000 }, "{n}");
        // the records of the CLI: a tail and all
        let mut recs = 0usize;
        let opts = velarx_wire::monitor::logfmt::ReadOptions {
            tail: Some(10),
            ..Default::default()
        };
        velarx_wire::monitor::logfmt::read_logs(&path, &opts, None, &mut |_| {
            recs += 1;
            Ok(())
        })
        .unwrap();
        assert_eq!(recs, 10);
        let opts = velarx_wire::monitor::logfmt::ReadOptions::default();
        velarx_wire::monitor::logfmt::read_logs(&path, &opts, None, &mut |_| {
            recs += 1;
            Ok(())
        })
        .unwrap();
        (after_tail, hwm_kb())
    }

    fn write_log(dir: &std::path::Path, size: u64) {
        use std::io::Write;
        let mut f = std::io::BufWriter::new(std::fs::File::create(log_path(dir)).unwrap());
        let body = "y".repeat(100);
        let mut bytes = 0u64;
        let mut i = 0u64;
        // 1 ms apart, a line of stderr now and then, 100 bytes of text each
        while bytes < size {
            let line = format!(
                "{} {} F {body}\n",
                velarx_wire::monitor::logfmt::format_rfc3339_ns(
                    1_000_000_000_000 + i as i64 * 1_000_000
                ),
                if i.is_multiple_of(7) {
                    "stderr"
                } else {
                    "stdout"
                }
            );
            f.write_all(line.as_bytes()).unwrap();
            bytes += line.len() as u64;
            i += 1;
        }
        f.flush().unwrap();
    }

    /// The child of `selection_memory_is_bounded`: after a run on a small
    /// log (the code is paged in), say how much the peak grew on the big one.
    fn measure(dir: &std::path::Path) {
        let small = tempfile::tempdir_in("/var/tmp").unwrap();
        write_log(small.path(), 1 << 20);
        suite(small.path(), false);
        let base = hwm_kb();
        let (tail, total) = suite(dir, true);
        // (the counters of the kernel are per CPU and read approximately:
        // under load a reading can be a few MiB off, either way)
        println!(
            "MEM tail_kb={} total_kb={}",
            tail.saturating_sub(base),
            total.saturating_sub(base)
        );
    }

    /// A log much larger than the memory it may take: the peak of a
    /// process that selects from it stays near its start.
    #[test]
    fn selection_memory_is_bounded() {
        if let Some(dir) = std::env::var_os("VELARX_LOGSEL_CHILD") {
            measure(std::path::Path::new(&dir));
            return;
        }
        let dir = tempfile::tempdir_in("/var/tmp").unwrap();
        write_log(dir.path(), 64 << 20);
        let exe = std::env::current_exe().unwrap();
        let out = std::process::Command::new(exe)
            .args([
                "--exact",
                "api::podman::logs::tests::selection_memory_is_bounded",
                "--nocapture",
                "--test-threads=1",
            ])
            .env("VELARX_LOGSEL_CHILD", dir.path())
            .output()
            .unwrap();
        let text = String::from_utf8_lossy(&out.stdout);
        assert!(
            out.status.success(),
            "{text}{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let line = text.lines().find(|l| l.contains("MEM tail_kb")).unwrap();
        let kb = |key: &str| -> u64 {
            let v = line.split(key).nth(1).unwrap();
            v.split_whitespace().next().unwrap().parse().unwrap()
        };
        // (the log is 64 MiB: the old selection took 3 times that; the
        // margin is for the approximate counters, see `measure`)
        assert!(kb("tail_kb=") < 8 * 1024, "{line}");
        assert!(kb("total_kb=") < 16 * 1024, "{line}");
    }

    /// The selection the engine had before (the whole log in memory), the
    /// oracle of `selection_is_the_old_one`.
    fn old_select(log: &[u8], s: &Select) -> Vec<(i64, u8, Vec<u8>, bool)> {
        let mut lines: Vec<(i64, u8, Vec<u8>, bool)> = Vec::new();
        let mut pending: [Option<(i64, Vec<u8>)>; 2] = [None, None];
        for rec in log.split(|&b| b == b'\n') {
            if rec.is_empty() {
                continue;
            }
            let mut f = rec.splitn(4, |&b| b == b' ');
            let (Some(ts), Some(name), Some(flag)) = (f.next(), f.next(), f.next()) else {
                continue;
            };
            let content = f.next().unwrap_or(&[]);
            let (stream, slot) = match name {
                b"stdout" => (STDOUT, 0),
                b"stderr" => (STDERR, 1),
                _ => continue,
            };
            let ts_ns = std::str::from_utf8(ts)
                .ok()
                .and_then(velarx_proto::time::parse_rfc3339)
                .unwrap_or(0);
            let (start, mut data) = pending[slot].take().unwrap_or((ts_ns, Vec::new()));
            data.extend_from_slice(content);
            if flag == b"F" {
                lines.push((start, stream, data, true));
            } else {
                pending[slot] = Some((start, data));
            }
        }
        for (slot, stream) in [(0, STDOUT), (1, STDERR)] {
            if let Some((ts_ns, data)) = pending[slot].take() {
                lines.push((ts_ns, stream, data, false));
            }
        }
        lines.sort_by_key(|l| l.0);
        let mut out: Vec<_> = lines
            .into_iter()
            .filter(|l| {
                (l.1 == STDOUT && s.stdout || l.1 == STDERR && s.stderr)
                    && l.0 >= s.since_ns
                    && (s.until_ns == 0 || l.0 <= s.until_ns)
            })
            .collect();
        if let Some(n) = s.tail {
            if out.len() > n {
                out.drain(..out.len() - n);
            }
        }
        out
    }

    #[test]
    fn selection_is_the_old_one() {
        let mut seed = 0x2545_f491_4f6c_dd1du64;
        let mut rnd = |n: u64| {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed % n
        };
        for round in 0..300 {
            // the times grow (with repeats), the streams interleave, lines
            // are split in records, the log may end in the middle of a line
            let mut log = String::new();
            let mut t = 1u64;
            let records = rnd(60) + (round % 3) * 40;
            for k in 0..records {
                t += rnd(3);
                let stream = if rnd(3) == 0 { "stderr" } else { "stdout" };
                let flag = if rnd(3) == 0 { 'P' } else { 'F' };
                log += &format!(
                    "1970-01-01T00:{:02}:{:02}Z {stream} {flag} r{k}\n",
                    t / 60,
                    t % 60
                );
            }
            let sel = Select {
                tail: (rnd(3) != 0).then(|| rnd(12) as usize),
                since_ns: if rnd(3) == 0 {
                    rnd(t + 1) as i64 * 1_000_000_000
                } else {
                    0
                },
                until_ns: if rnd(3) == 0 {
                    rnd(t + 1) as i64 * 1_000_000_000
                } else {
                    0
                },
                stdout: rnd(4) != 0,
                stderr: rnd(4) != 0,
            };
            let got: Vec<_> = lines_of(log.as_bytes(), &sel)
                .into_iter()
                .map(|l| (l.ts_ns, l.stream, l.data, l.complete))
                .collect();
            assert_eq!(got, old_select(log.as_bytes(), &sel), "{sel:?}\n{log}");
        }
    }

    /// The same comparison with the log in rotated files (the oldest
    /// compressed or not, a rotated file cut before its last newline), with
    /// many records at the same time and lines that cross the rotations.
    #[test]
    fn selection_across_rotated_files_is_the_old_one() {
        use flate2::{write::GzEncoder, Compression};
        use std::io::Write;
        let mut seed = 0x9e37_79b9_7f4a_7c15u64;
        let mut rnd = |n: u64| {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed % n
        };
        for round in 0..300 {
            let mut recs: Vec<String> = Vec::new();
            let mut t = 1u64;
            for k in 0..rnd(80) + 1 {
                // (one in two records at the time of the one before)
                t += rnd(2);
                let stream = if rnd(3) == 0 { "stderr" } else { "stdout" };
                let flag = if rnd(3) == 0 { 'P' } else { 'F' };
                recs.push(format!(
                    "1970-01-01T00:{:02}:{:02}Z {stream} {flag} r{k}\r\n",
                    t / 60,
                    t % 60
                ));
            }
            let log: String = recs.concat();
            let mut cuts = [rnd(recs.len() as u64 + 1), rnd(recs.len() as u64 + 1)];
            cuts.sort();
            let (a, b) = (cuts[0] as usize, cuts[1] as usize);
            let parts = [&recs[..a], &recs[a..b], &recs[b..]].map(|p| p.concat());
            let dir = tempfile::tempdir_in("/var/tmp").unwrap();
            let path = log_path(dir.path());
            let cut = |s: &str, drop_nl: bool| -> Vec<u8> {
                let s = if drop_nl {
                    s.strip_suffix('\n').unwrap_or(s)
                } else {
                    s
                };
                s.as_bytes().to_vec()
            };
            let oldest = cut(&parts[0], rnd(3) == 0);
            if rnd(2) == 0 {
                let mut e = GzEncoder::new(Vec::new(), Compression::fast());
                e.write_all(&oldest).unwrap();
                std::fs::write(format!("{}.2.gz", path.display()), e.finish().unwrap()).unwrap();
            } else {
                std::fs::write(format!("{}.2", path.display()), oldest).unwrap();
            }
            std::fs::write(format!("{}.1", path.display()), cut(&parts[1], rnd(3) == 0)).unwrap();
            std::fs::write(&path, &parts[2]).unwrap();
            let sel = Select {
                tail: (rnd(3) != 0).then(|| rnd(12) as usize),
                since_ns: if rnd(4) == 0 {
                    rnd(t + 1) as i64 * 1_000_000_000
                } else {
                    0
                },
                until_ns: if rnd(4) == 0 {
                    rnd(t + 1) as i64 * 1_000_000_000
                } else {
                    0
                },
                stdout: rnd(5) != 0,
                stderr: rnd(5) != 0,
            };
            let snap = Snapshot::open(&path, None).unwrap();
            let mut got = Vec::new();
            select_lines(&snap, &sel, &mut |l| {
                got.push((l.ts_ns, l.stream, l.data, l.complete));
                true
            })
            .unwrap();
            assert_eq!(
                got,
                old_select(log.as_bytes(), &sel),
                "round {round} {sel:?} cuts {a} {b}\n{log}"
            );
        }
    }

    /// What a follower of the log gets (stdout and stderr texts) while a
    /// thread writes `total` lines of each kind to a log that rotates: it
    /// starts when `start` of them are written, the writer goes on.
    async fn followed(sel: Select, start: usize, total: usize) -> (String, String) {
        use velarx_wire::monitor::logfmt::{Limits, LogWriter, Stream};
        let dir = tempfile::tempdir_in("/var/tmp").unwrap();
        let path = log_path(dir.path());
        let limits = Limits {
            max_size: 3000,
            max_files: 1000,
            global_max: 0,
            compress: false,
        };
        let mut w = LogWriter::open(&path, limits).unwrap();
        let write = |w: &mut LogWriter, i: usize| {
            // (every third line comes in two writes: a partial record)
            if i.is_multiple_of(3) {
                w.write(Stream::Stdout, format!("out {i} ").as_bytes())
                    .unwrap();
                w.write(Stream::Stdout, b"end\n").unwrap();
            } else {
                w.write(Stream::Stdout, format!("out {i} end\n").as_bytes())
                    .unwrap();
            }
            w.write(Stream::Stderr, format!("err {i}\n").as_bytes())
                .unwrap();
        };
        for i in 0..start {
            write(&mut w, i);
        }
        let (exit_r, exit_w) = rustix::pipe::pipe().unwrap();
        let (go_tx, go_rx) = std::sync::mpsc::channel::<()>();
        let writer = std::thread::spawn(move || {
            for i in start..total {
                write(&mut w, i);
                if i == start + 1 {
                    // (one writes after the follower is there)
                    go_tx.send(()).ok();
                }
            }
            drop(exit_w);
        });
        go_rx.recv().unwrap();
        let mut lines = spawn_follow(path, None, sel, exit_r).unwrap();
        let (mut out, mut err) = (String::new(), String::new());
        while let Some(l) = lines.next().await {
            let text = String::from_utf8(render(&l, false)).unwrap();
            if l.stream == STDOUT {
                out += &text;
            } else {
                err += &text;
            }
        }
        writer.join().unwrap();
        (out, err)
    }

    fn expect(from: usize, total: usize) -> (String, String) {
        let out = (from..total).map(|i| format!("out {i} end\n")).collect();
        let err = (from..total).map(|i| format!("err {i}\n")).collect();
        (out, err)
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_follower_gets_every_line_once_while_the_log_is_written_and_rotated() {
        for start in [0, 1, 50, 400] {
            assert!(
                followed(all(), start, 1500).await == expect(0, 1500),
                "starting at {start}"
            );
        }
    }

    /// Many followers of one log are threads of the process with one
    /// inotify instance for all; while the log is quiet they wake nothing,
    /// and each gets the line written next.
    #[tokio::test(flavor = "multi_thread")]
    async fn many_followers_share_one_inotify_instance_and_sleep_while_idle() {
        use velarx_wire::monitor::logfmt::{Limits, LogWriter, Stream};
        let instances = || {
            std::fs::read_dir("/proc/self/fd")
                .unwrap()
                .filter_map(|e| std::fs::read_link(e.ok()?.path()).ok())
                .filter(|l| l.to_string_lossy().contains("inotify"))
                .count()
        };
        // the context switches of each thread of a follower
        let switches = || -> std::collections::HashMap<String, u64> {
            std::fs::read_dir("/proc/self/task")
                .unwrap()
                .filter_map(|t| {
                    let t = t.ok()?.path();
                    if std::fs::read_to_string(t.join("comm")).ok()?.trim() != "logfollow" {
                        return None;
                    }
                    let st = std::fs::read_to_string(t.join("status")).ok()?;
                    let n = st
                        .lines()
                        .filter(|l| l.contains("ctxt_switches"))
                        .filter_map(|l| l.split_whitespace().nth(1)?.parse::<u64>().ok())
                        .sum();
                    Some((t.file_name()?.to_string_lossy().into_owned(), n))
                })
                .collect()
        };
        let dir = tempfile::tempdir_in("/var/tmp").unwrap();
        let path = log_path(dir.path());
        let mut w = LogWriter::open(&path, Limits::default()).unwrap();
        w.write(Stream::Stdout, b"first\n").unwrap();
        let (exit_r, _exit_w) = rustix::pipe::pipe().unwrap();
        let mut lines =
            vec![spawn_follow(path.clone(), None, all(), exit_r.try_clone().unwrap()).unwrap()];
        let before = instances();
        for _ in 1..500 {
            lines.push(
                spawn_follow(path.clone(), None, all(), exit_r.try_clone().unwrap()).unwrap(),
            );
        }
        // (other tests of the process may make an instance meanwhile; the
        // followers would have made 499)
        assert!(instances() < before + 20, "{} instances", instances());
        for l in &mut lines {
            let first = l.next().await.unwrap();
            assert_eq!(first.data, b"first");
        }
        // (the threads wait: most do nothing for two seconds; a few belong
        // to the other tests of the process, which write their logs)
        let before_idle = switches();
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        let after = switches();
        let woken = before_idle
            .iter()
            .filter(|(t, n)| after.get(*t).is_some_and(|m| m != *n))
            .count();
        assert!(
            woken < 20,
            "{woken} of {} followers woke while idle",
            after.len()
        );
        w.write(Stream::Stdout, b"second\n").unwrap();
        for l in &mut lines {
            assert_eq!(l.next().await.unwrap().data, b"second");
        }
    }

    /// `until` ends a follow of a container that goes on: at the first
    /// record after it, or when it passes while the log is quiet.
    #[tokio::test(flavor = "multi_thread")]
    async fn until_ends_a_live_follow() {
        use velarx_wire::monitor::logfmt::{now_ns, Limits, LogWriter, Stream};
        let dir = tempfile::tempdir_in("/var/tmp").unwrap();
        let path = log_path(dir.path());
        let mut w = LogWriter::open(&path, Limits::default()).unwrap();
        for i in 0..5 {
            w.write(Stream::Stdout, format!("a {i}\n").as_bytes())
                .unwrap();
        }
        // (the container never ends during the test)
        let (exit_r, _exit_w) = rustix::pipe::pipe().unwrap();
        let (exit2_r, _exit2_w) = rustix::pipe::pipe().unwrap();
        let until = now_ns();
        let sel = Select {
            until_ns: until,
            ..all()
        };
        let mut lines = spawn_follow(path.clone(), None, sel, exit_r).unwrap();
        // a record after `until`: the lines end before it
        w.write(Stream::Stdout, b"b 0\n").unwrap();
        let mut got = String::new();
        while let Some(l) = lines.next().await {
            got += &String::from_utf8(render(&l, false)).unwrap();
        }
        assert_eq!(got, "a 0\na 1\na 2\na 3\na 4\n");

        // nothing written: the follow ends when `until` passes
        let since = now_ns();
        let sel = Select {
            since_ns: since,
            until_ns: since + 50_000_000,
            ..all()
        };
        let mut lines = spawn_follow(path, None, sel, exit2_r).unwrap();
        let mut n = 0;
        while lines.next().await.is_some() {
            n += 1;
        }
        assert_eq!(n, 0);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_follower_with_a_tail_gets_the_end_of_the_log_and_what_follows() {
        let sel = Select {
            tail: Some(4),
            ..all()
        };
        let (out, err) = followed(sel, 100, 300).await;
        // (the writer goes on while the snapshot is taken: it ends 4 lines
        // before where it was, at the earliest)
        let nums = |text: &str| -> Vec<usize> {
            text.lines()
                .map(|l| l.split(' ').nth(1).unwrap().parse().unwrap())
                .collect()
        };
        for text in [&out, &err] {
            let n = nums(text);
            assert!(n[0] >= 98, "{:?}", &n[..3]);
            assert!(n.windows(2).all(|w| w[1] == w[0] + 1), "{:?}", &n[..3]);
            assert_eq!(n.last(), Some(&299));
        }
    }
}
