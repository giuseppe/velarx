// SPDX-License-Identifier: Apache-2.0
//! The network between the simulated nodes: latency, bandwidth, partitions.  Nothing is real: a message is a delay, and a message that is
//! lost is a future that never completes (the sender's own timeout is what
//! ends the wait, as on a real network).

use crate::entropy::Entropy;
use std::sync::Mutex;
use std::time::Duration;
use tokio::time::Instant;

/// One way, and a random part of it up to the jitter.
const LATENCY: Duration = Duration::from_millis(1);
const JITTER: Duration = Duration::from_micros(300);

/// A line of a node, one way: bytes leave it one after another at `rate`.
#[derive(Debug, Clone, Copy)]
struct Pipe {
    /// Bytes a second; 0: no limit
    rate: u64,
    /// When the bytes before are all through
    free_at: Option<Instant>,
}

impl Pipe {
    /// Send `bytes`: when they are through.
    fn through(&mut self, bytes: u64) -> Instant {
        let now = Instant::now();
        if self.rate == 0 {
            return now;
        }
        let start = self.free_at.map_or(now, |t| t.max(now));
        let done = start + Duration::from_secs_f64(bytes as f64 / self.rate as f64);
        self.free_at = Some(done);
        done
    }
}

struct Node {
    up: Pipe,
    down: Pipe,
    /// The side of a partition the node is on (0: the first)
    side: u32,
    alive: bool,
}

#[derive(Default)]
struct State {
    nodes: Vec<Node>,
}

/// The network.
pub struct Net {
    state: Mutex<State>,
    entropy: Entropy,
}

/// The index that names the registry in the calls of the network.
pub const REGISTRY: usize = usize::MAX;

/// The line of the node (or the registry) `i`: the registry is the first.
fn line(i: usize) -> usize {
    if i == REGISTRY {
        0
    } else {
        i + 1
    }
}

/// A message that did not arrive.
#[derive(Debug, PartialEq, Eq)]
pub struct Lost;

impl Net {
    pub(super) fn new(entropy: Entropy) -> Self {
        Self {
            state: Mutex::default(),
            entropy,
        }
    }

    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// A node: its index is that of the nodes before it plus one; the first
    /// call makes the registry.
    pub(super) fn add(&self, up: u64, down: u64) -> usize {
        let mut s = self.state();
        s.nodes.push(Node {
            up: Pipe {
                rate: up,
                free_at: None,
            },
            down: Pipe {
                rate: down,
                free_at: None,
            },
            side: 0,
            alive: true,
        });
        s.nodes.len().saturating_sub(2)
    }

    /// What the node writes at, bytes a second (0: no limit).
    pub fn set_up(&self, node: usize, rate: u64) {
        self.state().nodes[line(node)].up.rate = rate;
    }

    /// Cut the nodes in `side` off the others: none of them reaches a node
    /// outside, and the other way round.
    pub fn partition(&self, side: &[usize]) {
        let mut s = self.state();
        for n in &mut s.nodes {
            n.side = 0;
        }
        for &i in side {
            s.nodes[line(i)].side = 1;
        }
    }

    /// Mend the partition.
    pub fn heal(&self) {
        for n in &mut self.state().nodes {
            n.side = 0;
        }
    }

    pub(super) fn set_alive(&self, node: usize, alive: bool) {
        self.state().nodes[line(node)].alive = alive;
    }

    /// Whether a message from `a` to `b` can arrive at all.
    pub fn reachable(&self, a: usize, b: usize) -> bool {
        let (a, b) = (line(a), line(b));
        let s = self.state();
        s.nodes[a].alive && s.nodes[b].alive && s.nodes[a].side == s.nodes[b].side
    }

    /// `bytes` from `a` to `b`: when they arrive (through the line of `a`
    /// and the line of `b`, one after another), or [`Lost`].  Nothing waits
    /// for a lost message here: the caller gives up when it chooses.
    pub async fn send(&self, a: usize, b: usize, bytes: u64) -> Result<(), Lost> {
        let (a, b) = (line(a), line(b));
        let arrive = {
            let mut s = self.state();
            if !(s.nodes[a].alive && s.nodes[b].alive && s.nodes[a].side == s.nodes[b].side) {
                return Err(Lost);
            }
            let sent = s.nodes[a].up.through(bytes);
            let latency = LATENCY + JITTER.mul_f64(self.entropy.unit());
            s.nodes[b].down.through_after(sent + latency, bytes)
        };
        tokio::time::sleep_until(arrive).await;
        // (a node that went down while the message was on its way)
        let s = self.state();
        if s.nodes[a].side == s.nodes[b].side && s.nodes[b].alive {
            Ok(())
        } else {
            Err(Lost)
        }
    }

    /// Wait for a message that is lost for ever.
    pub async fn lost() -> ! {
        std::future::pending().await
    }
}

impl Pipe {
    /// Like [`Pipe::through`], for bytes that reach the line at `at`.
    fn through_after(&mut self, at: Instant, bytes: u64) -> Instant {
        if self.rate == 0 {
            return at;
        }
        let start = self.free_at.map_or(at, |t| t.max(at));
        let done = start + Duration::from_secs_f64(bytes as f64 / self.rate as f64);
        self.free_at = Some(done);
        done
    }
}
