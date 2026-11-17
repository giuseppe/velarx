// SPDX-License-Identifier: Apache-2.0
//! The upload limit of the node: one pacer for the whole serving path, on
//! every transport.
//!
//! What the node may send is a credit, granted before the bytes are read, so
//! that what has been read from a store is what may be sent and a request
//! that has to wait holds nothing but its place in a queue.  The credit comes
//! at the rate of the limit, in pieces of at most [`Pacer::piece`] bytes
//! (what the link carries in a moment, so that one wait is short), to the
//! callers in turn: each has a piece's worth of bytes in its turn, however
//! many requests it has and whatever their size (deficit round robin), so a
//! caller with many requests, or with large ones, takes no more than one
//! with one small request at a time.
//!
//! The grants are made by a task that exists while somebody waits: it sleeps
//! until the link is free (a timer, not a poll) and wakes the next waiter.
//! A waiter that has gone (a cancelled request, a closed stream) is skipped
//! and charged nothing.  A task that is gone before its queue is empty (the
//! runtime shuts down) lets its waiters go: nobody waits for ever.

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::oneshot;
use tokio::time::Instant;

/// The most a piece of credit is, at any rate (the size the files are read
/// in).
const MAX_PIECE: u64 = crate::serve::PIECE as u64;

/// The least a piece of credit is: below it a grant is not worth a wake-up.
const MIN_PIECE: u64 = 4 << 10;

/// The least lateness of the timer carried to the next grant: it ticks in
/// milliseconds, longer than a piece of 1 MiB takes at 10 Gbit/s.
const LATE: Duration = Duration::from_millis(10);

/// Whom the credit is shared between: the address a caller asks from (what
/// costs nothing to change, an identity, does not give a share).
pub type Who = IpAddr;

struct Waiter {
    bytes: u64,
    tx: oneshot::Sender<()>,
}

/// The waiters of one caller, and the bytes it may still have in its turn.
#[derive(Default)]
struct Share {
    waiters: VecDeque<Waiter>,
    deficit: u64,
}

#[derive(Default)]
struct Queue {
    /// When the link is free
    free_at: Option<Instant>,
    shares: HashMap<Who, Share>,
    /// The callers that wait, in turn: the first has the turn
    turns: VecDeque<Who>,
    /// Whether the first has had its piece's worth for this turn
    started: bool,
    /// Whether a task makes the grants
    granting: bool,
}

/// What a pacer holds now.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PacerState {
    /// The limit, bytes a second (0: none)
    pub bytes_per_sec: u64,
    /// The callers waiting for credit, and the requests of them
    pub waiting_callers: usize,
    pub waiting_requests: usize,
}

/// Spreads what a node sends over time, at the rate of the limit.
pub struct Pacer {
    bytes_per_sec: u64,
    queue: Arc<Mutex<Queue>>,
}

impl Pacer {
    /// A pacer of `bytes_per_sec` (0: no limit).
    pub fn new(bytes_per_sec: u64) -> Self {
        Self {
            bytes_per_sec,
            queue: Default::default(),
        }
    }

    /// The limit and who waits for credit now.
    pub fn state(&self) -> PacerState {
        let q = self.queue.lock().unwrap_or_else(|e| e.into_inner());
        PacerState {
            bytes_per_sec: self.bytes_per_sec,
            waiting_callers: q.shares.len(),
            waiting_requests: q.shares.values().map(|s| s.waiters.len()).sum(),
        }
    }

    /// The most a grant is: a piece the link carries in an eighth of a
    /// second, between 4 KiB and 1 MiB; 1 MiB with no limit.
    pub fn piece(&self) -> u64 {
        match self.bytes_per_sec {
            0 => MAX_PIECE,
            rate => (rate / 8).clamp(MIN_PIECE, MAX_PIECE),
        }
    }

    /// Ask for the credit to send `bytes` (more than [`Pacer::piece`] is
    /// asked as a piece): granted when the link is free and it is the turn
    /// of `who`.  Must be called within the runtime, with a limit and bytes.
    fn ask(&self, who: Who, bytes: u64) -> oneshot::Receiver<()> {
        let (tx, rx) = oneshot::channel();
        let mut queue = self.queue.lock().unwrap_or_else(|e| e.into_inner());
        let share = queue.shares.entry(who).or_default();
        let first = share.waiters.is_empty();
        share.waiters.push_back(Waiter {
            bytes: bytes.min(self.piece()),
            tx,
        });
        if first {
            queue.turns.push_back(who);
        }
        let start = !queue.granting;
        queue.granting = true;
        drop(queue);
        // (outside the lock: a runtime that shuts down drops the task at
        // once, and the task takes the lock when it goes)
        if start {
            let task = Granting {
                queue: self.queue.clone(),
                ended: false,
            };
            let (rate, quantum) = (self.bytes_per_sec, self.piece());
            tokio::runtime::Handle::current().spawn(task.run(rate, quantum));
        }
        rx
    }

    /// Wait for the credit to send `bytes`, a piece at a time; whether it
    /// came.  The first piece must come by `first_by` (when given), else
    /// nothing is had (false); once a piece has come, the others come as
    /// the turns go (what a request may wait for them is bounded by the
    /// requests the node serves at a time, a piece of each).  Nothing waits
    /// when there is no limit or no bytes: an answer that carries no data
    /// (busy, absent, a probe) is never delayed.
    pub async fn pace(&self, who: Who, bytes: u64, first_by: Option<Instant>) -> bool {
        if self.bytes_per_sec == 0 || bytes == 0 {
            return true;
        }
        let mut left = bytes;
        let mut first = true;
        while left > 0 {
            let n = left.min(self.piece());
            let credit = self.ask(who, n);
            match first_by.filter(|_| first) {
                // (the waiter that has gone is not charged)
                Some(by) => {
                    if tokio::time::timeout_at(by, credit).await.is_err() {
                        return false;
                    }
                }
                // (a pacer that is gone has nothing to wait for)
                None => {
                    let _ = credit.await;
                }
            }
            first = false;
            left -= n;
        }
        true
    }
}

/// The task that makes the grants: when it goes before its queue is empty
/// (the runtime shuts down, or it panicked), the waiters are let go.
struct Granting {
    queue: Arc<Mutex<Queue>>,
    ended: bool,
}

impl Drop for Granting {
    fn drop(&mut self) {
        if self.ended {
            return;
        }
        let mut q = self.queue.lock().unwrap_or_else(|e| e.into_inner());
        q.granting = false;
        q.shares.clear();
        q.turns.clear();
        q.started = false;
    }
}

impl Granting {
    /// Make the grants, one when the link is free, to the callers in turn,
    /// until nobody waits.
    async fn run(mut self, bytes_per_sec: u64, quantum: u64) {
        loop {
            let wait = {
                let mut q = self.queue.lock().unwrap_or_else(|e| e.into_inner());
                let now = Instant::now();
                match q.free_at.filter(|t| *t > now) {
                    Some(free) if !q.turns.is_empty() => Some(free),
                    _ if grant(&mut q, now, bytes_per_sec, quantum) => None,
                    _ => {
                        // nobody waits: a new waiter starts a new task
                        q.granting = false;
                        self.ended = true;
                        return;
                    }
                }
            };
            if let Some(t) = wait {
                tokio::time::sleep_until(t).await;
            }
        }
    }
}

/// Grant the next waiter of the caller whose turn it is; false when nobody
/// waits.  A caller has a piece's worth of bytes in a turn (a waiter asks
/// for no more), then goes behind the others; one that has nobody waiting
/// any more leaves the turns, with what it had left.
fn grant(q: &mut Queue, now: Instant, bytes_per_sec: u64, quantum: u64) -> bool {
    while let Some(who) = q.turns.front().copied() {
        let share = q
            .shares
            .get_mut(&who)
            .expect("a caller in turn has a share");
        // (a waiter that has gone is skipped, and not charged)
        while share.waiters.front().is_some_and(|w| w.tx.is_closed()) {
            share.waiters.pop_front();
        }
        let Some(bytes) = share.waiters.front().map(|w| w.bytes) else {
            q.shares.remove(&who);
            q.turns.pop_front();
            q.started = false;
            continue;
        };
        if !q.started {
            share.deficit += quantum;
            q.started = true;
        }
        if bytes > share.deficit {
            // its turn is over
            q.turns.rotate_left(1);
            q.started = false;
            continue;
        }
        let waiter = share.waiters.pop_front().expect("a waiter");
        let granted = waiter.tx.send(()).is_ok();
        if granted {
            share.deficit -= bytes;
        }
        if share.waiters.is_empty() {
            q.shares.remove(&who);
            q.turns.pop_front();
            q.started = false;
        }
        if granted {
            let took = Duration::from_nanos(bytes.saturating_mul(1_000_000_000) / bytes_per_sec);
            // The time of the grant is the time the link was free when the
            // timer woke late (so the rate holds), not when it was idle (no
            // more than one piece goes at once).  Late is up to a piece's
            // time (or [`LATE`]), not the grant's: the timer ticks in
            // milliseconds, longer than a chunk of 50 KiB takes at 1 Gbit/s,
            // and a lateness lost at each grant held such chunks to a third
            // of the limit.
            let slack = Duration::from_nanos(quantum * 1_000_000_000 / bytes_per_sec).max(LATE);
            let from = q
                .free_at
                .filter(|free| now.saturating_duration_since(*free) < slack)
                .unwrap_or(now);
            q.free_at = Some(from + took);
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    const RATE: u64 = 1_000_000;

    fn who(n: u8) -> Who {
        std::net::Ipv4Addr::new(10, 0, 0, n).into()
    }

    /// The limit is the node's, whoever asks and however many ask: the credit
    /// of all the callers together comes at the rate (a piece is an eighth
    /// of a second of it).
    #[tokio::test(start_paused = true)]
    async fn the_limit_holds_for_all_the_callers_together() {
        let pacer = Arc::new(Pacer::new(RATE));
        assert_eq!(pacer.piece(), RATE / 8);
        let start = Instant::now();
        let mut tasks = Vec::new();
        for caller in 0..3 {
            for _ in 0..4 {
                let pacer = pacer.clone();
                tasks.push(tokio::spawn(async move {
                    pacer.pace(who(caller), 2 * RATE / 8, None).await;
                }));
            }
        }
        for t in tasks {
            t.await.unwrap();
        }
        // 24 pieces: the first at once, one every eighth of a second
        assert_eq!(start.elapsed(), Duration::from_millis(23 * 125));
    }

    /// Chunks smaller than what the link carries in a tick of the timer (a
    /// millisecond) still go at the rate: 2000 chunks of 52 KiB at 1 Gbit/s
    /// take 0.85 s, not a tick each (2 s, a third of the limit before); at
    /// 10 Gbit/s too, where even a piece takes less than a tick.
    #[tokio::test(start_paused = true)]
    async fn small_chunks_go_at_the_rate() {
        const CHUNK: u64 = 52 << 10;
        for rate in [125_000_000, 1_250_000_000] {
            let pacer = Arc::new(Pacer::new(rate));
            let start = Instant::now();
            let mut tasks = Vec::new();
            for caller in 0..4 {
                let pacer = pacer.clone();
                tasks.push(tokio::spawn(async move {
                    for _ in 0..500 {
                        pacer.pace(who(caller), CHUNK, None).await;
                    }
                }));
            }
            for t in tasks {
                t.await.unwrap();
            }
            let ideal = Duration::from_nanos(2000 * CHUNK * 1_000_000_000 / rate);
            let took = start.elapsed();
            assert!(took <= ideal * 11 / 10, "{took:?} for {ideal:?} at {rate}");
            // (no more than the slack ahead of the rate)
            let slack = Duration::from_nanos(pacer.piece() * 1_000_000_000 / rate).max(LATE);
            assert!(took + slack >= ideal, "{took:?}: faster than {ideal:?}");
        }
    }

    /// A caller with many waiting takes no more than one with one: the
    /// callers come in turn.
    #[tokio::test(start_paused = true)]
    async fn the_callers_come_in_turn() {
        let pacer = Arc::new(Pacer::new(RATE));
        let start = Instant::now();
        let when = Arc::new(Mutex::new(Vec::new()));
        let mut tasks = Vec::new();
        for (caller, name) in std::iter::repeat_n((1, "busy"), 8).chain([(2, "other")]) {
            // (asked now, in this order, waited for in tasks)
            let credit = pacer.ask(who(caller), RATE / 8);
            let when = when.clone();
            tasks.push(tokio::spawn(async move {
                let _ = credit.await;
                when.lock().unwrap().push((name, start.elapsed()));
            }));
        }
        for t in tasks {
            t.await.unwrap();
        }
        let when = when.lock().unwrap();
        let other = when.iter().find(|(n, _)| *n == "other").unwrap().1;
        assert_eq!(other, Duration::from_millis(125), "the second to be served");
        assert_eq!(when.last().unwrap().1, Duration::from_millis(8 * 125));
    }

    /// The turns share bytes, not grants: a caller that asks for small
    /// pieces (the chunks of small files) gets as many bytes in a turn as
    /// one that asks for whole pieces, not one small grant for each piece
    /// of the other.
    #[tokio::test(start_paused = true)]
    async fn the_turns_share_bytes_not_grants() {
        let pacer = Arc::new(Pacer::new(RATE));
        let piece = pacer.piece();
        let small = piece / 8;
        let start = Instant::now();
        let mut big = Vec::new();
        for _ in 0..4 {
            big.push(pacer.ask(who(1), piece));
        }
        let mut tiny = Vec::new();
        for _ in 0..16 {
            tiny.push(pacer.ask(who(2), small));
        }
        // the first big piece at once, then the small ones a piece's worth
        // (8) in their turn, then a big one, then the other 8 small ones
        let mut done = Vec::new();
        for credit in tiny {
            credit.await.unwrap();
            done.push(start.elapsed());
        }
        // (the timers of tokio wake on the millisecond after)
        let small_takes = Duration::from_micros(15_625);
        let near =
            |at: Duration, want: Duration| at >= want && at - want < Duration::from_millis(1);
        let want = Duration::from_millis(125) + 7 * small_takes;
        assert!(near(done[7], want), "{:?} {want:?}", done[7]);
        let want = Duration::from_millis(3 * 125) + 7 * small_takes;
        assert!(near(done[15], want), "{:?} {want:?}", done[15]);
        drop(big);
    }

    /// An answer without data waits for nothing, with any debt of the link.
    #[tokio::test(start_paused = true)]
    async fn an_answer_without_data_does_not_wait() {
        let pacer = Pacer::new(RATE);
        let debt: Vec<_> = (0..8).map(|_| pacer.ask(who(1), RATE / 8)).collect();
        let start = Instant::now();
        assert!(pacer.pace(who(2), 0, None).await);
        assert!(pacer.pace(who(2), 0, Some(start)).await);
        assert_eq!(start.elapsed(), Duration::ZERO);
        drop(debt);
        // no limit, no wait for any data, and no task
        let free = Pacer::new(0);
        assert!(free.pace(who(1), u64::MAX, Some(start)).await);
        assert_eq!(start.elapsed(), Duration::ZERO);
        assert!(!free.queue.lock().unwrap().granting);
    }

    /// A request that goes while it waits (cancelled, closed) is not
    /// charged: the ones behind it do not wait for it.
    #[tokio::test(start_paused = true)]
    async fn a_waiter_that_has_gone_is_not_charged() {
        let pacer = Pacer::new(RATE);
        let start = Instant::now();
        let first = pacer.ask(who(1), RATE / 8);
        let gone: Vec<_> = (0..16).map(|_| pacer.ask(who(2), RATE / 8)).collect();
        let last = pacer.ask(who(3), RATE / 8);
        first.await.unwrap();
        drop(gone);
        last.await.unwrap();
        assert_eq!(start.elapsed(), Duration::from_millis(125));
    }

    /// The first piece that does not come in time is not had, and not
    /// charged: the one after it has the link at once.
    #[tokio::test(start_paused = true)]
    async fn a_first_piece_not_in_time_is_not_had() {
        let pacer = Arc::new(Pacer::new(RATE));
        let start = Instant::now();
        let debt: Vec<_> = (0..4).map(|_| pacer.ask(who(1), RATE / 8)).collect();
        let by = start + Duration::from_millis(100);
        assert!(!pacer.pace(who(2), RATE, Some(by)).await);
        assert_eq!(start.elapsed(), Duration::from_millis(100));
        drop(debt);
        // (the link is free again when the piece granted at once is sent)
        assert!(
            pacer
                .pace(who(3), RATE / 8, Some(by + Duration::from_millis(100)))
                .await
        );
        assert_eq!(start.elapsed(), Duration::from_millis(125));
    }

    /// A timer that wakes late does not slow the link down: the next grant
    /// is counted from when the link was free, not from the wake-up.
    #[tokio::test(start_paused = true)]
    async fn a_late_wake_up_does_not_lower_the_rate() {
        let pacer = Pacer::new(RATE);
        let start = Instant::now();
        let mut q = pacer.queue.lock().unwrap();
        q.free_at = Some(start);
        let (tx, _rx) = oneshot::channel();
        q.shares
            .entry(who(1))
            .or_default()
            .waiters
            .push_back(Waiter {
                bytes: RATE / 8,
                tx,
            });
        q.turns.push_back(who(1));
        let late = start + Duration::from_millis(3);
        assert!(grant(&mut q, late, RATE, pacer.piece()));
        assert_eq!(q.free_at, Some(start + Duration::from_millis(125)));
        // an idle link gives no more than one piece at once
        let (tx, _rx2) = oneshot::channel();
        q.shares
            .entry(who(1))
            .or_default()
            .waiters
            .push_back(Waiter {
                bytes: RATE / 8,
                tx,
            });
        q.turns.push_back(who(1));
        let idle = start + Duration::from_secs(10);
        assert!(grant(&mut q, idle, RATE, pacer.piece()));
        assert_eq!(q.free_at, Some(idle + Duration::from_millis(125)));
    }

    /// What waits is the places of the requests, a few bytes each: nothing
    /// grows with the bytes asked, and the queue is empty when all is
    /// granted (the task that grants ends).
    #[tokio::test(start_paused = true)]
    async fn nothing_is_left_when_all_is_granted() {
        let pacer = Pacer::new(RATE);
        assert!(pacer.pace(who(1), 3 * RATE, None).await);
        let q = pacer.queue.lock().unwrap();
        assert!(q.shares.is_empty() && q.turns.is_empty() && !q.granting);
    }

    /// A runtime that shuts down while a request of the blocking pool waits
    /// for its credit lets it go: the shutdown does not wait for ever.
    #[test]
    fn a_shutdown_lets_the_waiters_go() {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_time()
            .build()
            .unwrap();
        let pacer = Arc::new(Pacer::new(RATE));
        let (asked, waiting) = std::sync::mpsc::channel();
        let p = pacer.clone();
        runtime.spawn_blocking(move || {
            asked.send(()).unwrap();
            // a minute of credit
            tokio::runtime::Handle::current().block_on(p.pace(who(1), 60 * RATE, None))
        });
        waiting.recv().unwrap();
        // (dropping a runtime waits for its blocking pool)
        let (dropped, done) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            drop(runtime);
            dropped.send(()).unwrap();
        });
        done.recv_timeout(Duration::from_secs(30))
            .expect("the runtime shut down");
        let q = pacer.queue.lock().unwrap();
        assert!(q.shares.is_empty() && !q.granting);
        drop(q);
        // and a request that asks after the shutdown does not wait either
        let handle = {
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(1)
                .build()
                .unwrap();
            runtime.handle().clone()
        };
        let (asked, done) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            asked
                .send(handle.block_on(pacer.pace(who(1), RATE, None)))
                .unwrap();
        });
        let had = done.recv_timeout(Duration::from_secs(30));
        assert_eq!(had, Ok(true), "the request went");
    }
}
