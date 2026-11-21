// SPDX-License-Identifier: Apache-2.0
//! What this node has learned of its peers while fetching from them.
//!
//! Asking a peer costs a round trip, and asking the wrong one costs it for
//! nothing.  The node remembers, from the requests it made:
//!
//! * which peers served chunks of a layer (they are asked first, with no
//!   lookup of the DHT), and which answered with nothing (they are not asked
//!   again for a while: a layer nobody has goes to the registry at once);
//! * how long each peer takes to answer, to rank the peers and to know how
//!   long to wait before asking a second one (hedging);
//! * the filter each peer told of the layers it holds ([`crate::filter`]): the
//!   peers whose filter says "maybe" for a layer are asked for it, the ones
//!   whose filter says "no" are not (and not probed), the others have no
//!   filter that is believed.  This is the only table of who holds what that
//!   a peer told.
//!
//! Only what a peer proved is recorded (the caller checks the bytes against
//! their digests first).  Everything is bounded and expires.
//!
//! It also counts, for `velarx p2p status`, what each peer was asked and
//! sent: requests, failures, the chunks and bytes that matched their
//! digests, and the time of the answers.

use crate::entropy::Entropy;
use crate::filter::{self, Received, Refused, Said};
use crate::gossip::GossipMessage;
use libp2p::PeerId;
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::Duration;
use tokio::time::Instant;

/// How long a peer that served a layer is believed to have it.
pub const HAS_TTL: Duration = Duration::from_secs(600);
/// How long a peer that had nothing of a layer is not asked for it again.
pub const MISS_TTL: Duration = Duration::from_secs(60);
/// How long the round-trip time of a peer is kept without a new sample.
pub const RTT_TTL: Duration = Duration::from_secs(1800);
/// Layers remembered, and peers for each of them, and peers in all.
pub const MAX_LAYERS: usize = 1024;
pub const MAX_PEERS_PER_LAYER: usize = 32;
pub const MAX_PEERS: usize = 1024;

/// Bounds of the wait before a second peer is asked, and the wait when the
/// peer was never measured.
pub const HEDGE_MIN: Duration = Duration::from_millis(50);
pub const HEDGE_MAX: Duration = Duration::from_secs(2);
pub const HEDGE_UNKNOWN: Duration = Duration::from_millis(200);
/// How long a peer whose request failed is not asked again.
pub const FAILED_TTL: Duration = Duration::from_secs(60);
/// Times the usual answer time of a peer that is waited for.
const HEDGE_FACTOR: u32 = 3;

#[derive(Clone, Copy)]
struct Entry {
    served: Option<Instant>,
    missed: Option<Instant>,
}

struct Layer {
    touched: Instant,
    peers: HashMap<PeerId, Entry>,
}

#[derive(Clone, Copy)]
struct Timing {
    /// Smoothed time of a request that was answered.
    rtt: Duration,
    at: Instant,
    /// Requests that failed or timed out since the last answer.
    failures: u32,
    /// When the last of them did (an answer that is no chunks does not renew it)
    failed_at: Instant,
}

impl Timing {
    /// The failures (since it last answered) after which a peer ranks last.
    const FAILING: u32 = 1;
}

#[derive(Default)]
struct Inner {
    layers: HashMap<String, Layer>,
    peers: HashMap<PeerId, Timing>,
}

/// What is believed of a layer and a peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Belief {
    pub layer: String,
    pub peer: PeerId,
    /// The peer has the layer (it served it lately), else it lacks it (it did
    /// not when asked lately)
    pub has: bool,
    /// How long ago that was learnt
    pub age: Duration,
}

/// What this node fetched from a peer, since the service started.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Traffic {
    /// Requests made to it
    pub requests: u64,
    /// Requests that failed or timed out
    pub failures: u64,
    /// Requests it had no room to answer
    pub busy: u64,
    /// Chunks it sent that matched their digests, and their bytes
    pub chunks: u64,
    pub bytes: u64,
    /// The time of the requests it answered, in all
    pub answer_time: Duration,
    /// When it was last asked
    last: Option<Instant>,
}

impl Traffic {
    /// The average time of an answer, when it answered.
    pub fn average(&self) -> Option<Duration> {
        let answered = self
            .requests
            .saturating_sub(self.failures)
            .saturating_sub(self.busy);
        (answered > 0).then(|| self.answer_time / answered.min(u32::MAX as u64) as u32)
    }
}

/// The filters of the peers, and the bytes they take.
#[derive(Default)]
struct Filters {
    peers: HashMap<PeerId, Received>,
}

/// What the filters of the peers say of a layer, among the peers that have
/// one that is believed.
#[derive(Debug, Default, Clone)]
pub struct Filtered {
    pub maybe: HashSet<PeerId>,
    pub no: HashSet<PeerId>,
}

/// What this node knows of the filter of a peer.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct FilterInfo {
    /// The keys the peer said it put in it, and its bytes
    pub keys: u32,
    pub bytes: usize,
    pub version: u64,
    /// The rate at which it says "maybe" to a layer that is not in it, from
    /// its fill
    pub estimated_fpr: f64,
    pub age: Duration,
    /// "Maybe" that was right (the peer served the layer), and wrong
    pub hits: u64,
    pub false_positives: u64,
    /// Updates of the peer that were refused
    pub refused: u64,
    pub last_refused: Option<Refused>,
    /// Whether it is believed (it is not when it expired, was refused or was
    /// wrong most of the time)
    pub believed: bool,
    /// Whether a message of the peer is missing from it (lost, late, or of
    /// another run of the peer): it then says no "no" till a whole one
    pub behind: bool,
}

/// The totals of what the filters said, since the service started.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FilterTotals {
    /// Peers whose filter is believed now
    pub peers: u64,
    pub hits: u64,
    pub false_positives: u64,
    pub refused: u64,
}

pub struct Knowledge {
    inner: Mutex<Inner>,
    filters: Mutex<Filters>,
    hits: AtomicU64,
    false_positives: AtomicU64,
    refused: AtomicU64,
    /// What orders peers that rank the same
    entropy: Entropy,
    /// Not forgotten with the rest: it is what was done, not what is believed.
    traffic: Mutex<HashMap<PeerId, Traffic>>,
}

impl Default for Knowledge {
    fn default() -> Self {
        Self {
            inner: Mutex::default(),
            filters: Mutex::default(),
            hits: AtomicU64::new(0),
            false_positives: AtomicU64::new(0),
            refused: AtomicU64::new(0),
            entropy: Entropy::default(),
            traffic: Mutex::default(),
        }
    }
}

impl Knowledge {
    /// Knowledge whose ties between peers are broken by `entropy`.
    pub fn with_entropy(entropy: Entropy) -> Self {
        Self {
            entropy,
            ..Self::default()
        }
    }

    fn filters(&self) -> std::sync::MutexGuard<'_, Filters> {
        self.filters.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// A filter message of `peer`: what it holds replaces or grows what was
    /// kept.  A message that is refused leaves the peer with no filter.
    pub fn filter_received(&self, peer: PeerId, msg: &GossipMessage) -> Result<(), Refused> {
        let now = Instant::now();
        let mut filters = self.filters();
        let held = filters
            .peers
            .entry(peer)
            .or_insert_with(|| Received::new(now));
        let result = match msg {
            GossipMessage::LayerFilter(full) => held.full(full, now),
            GossipMessage::LayerFilterDelta(delta) => held.delta(delta, now),
            _ => Ok(()),
        };
        if result.is_err() {
            self.refused.fetch_add(1, Ordering::Relaxed);
        }
        result
    }

    /// The filter of `peer` goes with its connection.
    pub fn filter_gone(&self, peer: &PeerId) {
        let mut filters = self.filters();
        filters.peers.remove(peer);
    }

    /// What the filters say of `layer`: the peers that may hold it and the
    /// ones that do not; the others have no filter that is believed.
    pub fn filtered(&self, layer: &str) -> Filtered {
        let (key, now) = (filter::key_of(layer), Instant::now());
        let mut out = Filtered::default();
        for (peer, held) in &self.filters().peers {
            match held.says(key, now) {
                Said::Maybe => out.maybe.insert(*peer),
                Said::No => out.no.insert(*peer),
                Said::Unknown => false,
            };
        }
        out
    }

    /// The filter of each peer that sent one, by peer.
    pub fn filter_infos(&self) -> HashMap<PeerId, FilterInfo> {
        let now = Instant::now();
        self.filters()
            .peers
            .iter()
            .map(|(peer, held)| {
                let info = FilterInfo {
                    keys: held.bloom().map_or(0, |b| b.keys()),
                    bytes: held.bytes(),
                    version: held.version(),
                    estimated_fpr: held.bloom().map_or(0.0, |b| b.estimated_fpr()),
                    age: held.age(now),
                    hits: held.hits,
                    false_positives: held.false_positives,
                    refused: held.refused,
                    last_refused: held.last_refused,
                    believed: held.believed(now),
                    behind: held.behind(),
                };
                (*peer, info)
            })
            .collect()
    }

    /// The layers `peer` says it put in its filter.
    pub fn filter_keys(&self, peer: &PeerId) -> u32 {
        self.filters()
            .peers
            .get(peer)
            .and_then(|h| h.bloom())
            .map_or(0, |b| b.keys())
    }

    /// What the filters said, in all.
    pub fn filter_totals(&self) -> FilterTotals {
        let now = Instant::now();
        FilterTotals {
            peers: self
                .filters()
                .peers
                .values()
                .filter(|h| h.believed(now))
                .count() as u64,
            hits: self.hits.load(Ordering::Relaxed),
            false_positives: self.false_positives.load(Ordering::Relaxed),
            refused: self.refused.load(Ordering::Relaxed),
        }
    }

    /// `peer` was asked for `layer`, and held it or did not: when its filter
    /// said "maybe" that was a hit or a false positive.
    fn filter_outcome(&self, layer: &str, peer: &PeerId, held: bool) {
        let key = filter::key_of(layer);
        if let Some(r) = self.filters().peers.get_mut(peer) {
            if r.bloom().is_some_and(|b| b.contains(key)) {
                let (count, total) = if held {
                    (&mut r.hits, &self.hits)
                } else {
                    (&mut r.false_positives, &self.false_positives)
                };
                *count += 1;
                total.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// `peer` answered a request with chunks of `layer`, in `took`.
    pub fn served(&self, layer: Option<&str>, peer: PeerId, took: Duration) {
        self.served_at(layer, peer, took, Instant::now())
    }

    pub fn served_at(&self, layer: Option<&str>, peer: PeerId, took: Duration, now: Instant) {
        self.answered_at(layer, peer, took, now, true)
    }

    /// `peer` said, in `took`, that it has a chunk of `layer`: as
    /// [`Self::served`] for what is believed of the layer and its time, but a
    /// word does not undo failures (it ranks last until it serves).
    pub fn said_has(&self, layer: Option<&str>, peer: PeerId, took: Duration) {
        self.answered_at(layer, peer, took, Instant::now(), false)
    }

    fn answered_at(
        &self,
        layer: Option<&str>,
        peer: PeerId,
        took: Duration,
        now: Instant,
        served: bool,
    ) {
        let mut inner = self.lock();
        inner.timing(peer, now, |t| {
            // (only chunks that were right undo failures: saying it has a
            // chunk costs a peer nothing)
            if served {
                t.failures = 0;
            }
            t.rtt = match t.rtt {
                // a first sample, or one after a long silence, is the value
                d if d.is_zero() || now.saturating_duration_since(t.at) > RTT_TTL => took,
                d => (d * 7 + took) / 8,
            };
            t.at = now;
        });
        if let Some(layer) = layer {
            inner.entry(layer, peer, now, |e| {
                e.served = Some(now);
                e.missed = None;
            });
            drop(inner);
            if served {
                self.filter_outcome(layer, &peer, true);
            }
        }
    }

    /// `peer` answered, and had none of the chunks asked of it.
    pub fn missed(&self, layer: Option<&str>, peer: PeerId) {
        self.missed_at(layer, peer, Instant::now())
    }

    pub fn missed_at(&self, layer: Option<&str>, peer: PeerId, now: Instant) {
        if let Some(layer) = layer {
            self.filter_outcome(layer, &peer, false);
            // a peer that has served the layer has some of it: it may lack
            // this chunk and not the next
            self.lock().entry(layer, peer, now, |e| {
                if !e.served_live(now) {
                    e.missed = Some(now);
                }
            });
        }
    }

    /// Whether a request to `peer` failed or timed out in the last
    /// [`FAILED_TTL`] and it has not served since: it is not asked again by
    /// the groups of a pull (one that does not answer would make each of
    /// them wait for its timeout).
    pub fn failing(&self, peer: &PeerId) -> bool {
        self.failing_at(peer, Instant::now())
    }

    pub fn failing_at(&self, peer: &PeerId, now: Instant) -> bool {
        self.lock().peers.get(peer).is_some_and(|t| {
            t.failures > 0 && now.saturating_duration_since(t.failed_at) < FAILED_TTL
        })
    }

    /// A request to `peer` failed or timed out.
    pub fn failed(&self, peer: PeerId) {
        self.failed_at(peer, Instant::now())
    }

    pub fn failed_at(&self, peer: PeerId, now: Instant) {
        self.lock().timing(peer, now, |t| {
            t.failures = t.failures.saturating_add(1);
            t.failed_at = now;
            t.at = now;
        });
    }

    /// The peers believed to have chunks of `layer`: they served it lately
    /// and did not miss since.  The quickest first.
    pub fn providers(&self, layer: &str) -> Vec<PeerId> {
        self.providers_at(layer, Instant::now())
    }

    pub fn providers_at(&self, layer: &str, now: Instant) -> Vec<PeerId> {
        let mut inner = self.lock();
        let Some(l) = inner.layers.get_mut(layer) else {
            return Vec::new();
        };
        l.peers.retain(|_, e| e.live(now));
        let mut found: Vec<PeerId> = l
            .peers
            .iter()
            .filter(|(_, e)| e.has(now))
            .map(|(p, _)| *p)
            .collect();
        if l.peers.is_empty() {
            inner.layers.remove(layer);
        }
        found.sort();
        self.entropy.shuffle(&mut found);
        inner.rank(&mut found, now);
        found
    }

    /// Whether `peer` had nothing of `layer` when it was asked lately.
    pub fn lacks(&self, layer: &str, peer: &PeerId) -> bool {
        self.lacks_at(layer, peer, Instant::now())
    }

    pub fn lacks_at(&self, layer: &str, peer: &PeerId, now: Instant) -> bool {
        self.lock()
            .layers
            .get(layer)
            .and_then(|l| l.peers.get(peer))
            .is_some_and(|e| e.lacking(now))
    }

    /// `peers` quickest first; the ones that were never measured go first, to
    /// be measured (a peer is not ignored for good because another was asked
    /// before it), the ones that keep failing last.
    /// Peers that rank the same are in a random order (what spreads the
    /// nodes over the peers that none has measured).
    pub fn rank(&self, peers: &mut [PeerId]) {
        peers.sort();
        self.entropy.shuffle(peers);
        self.lock().rank(peers, Instant::now())
    }

    /// A number below `n`, from the entropy of the node.
    pub fn below(&self, n: usize) -> usize {
        self.entropy.below(n)
    }

    /// How long to wait for `peer` before a second one is asked.
    pub fn hedge_delay(&self, peer: &PeerId) -> Duration {
        self.hedge_delay_at(peer, Instant::now())
    }

    pub fn hedge_delay_at(&self, peer: &PeerId, now: Instant) -> Duration {
        match self.lock().peers.get(peer) {
            Some(t) if now.saturating_duration_since(t.at) <= RTT_TTL && !t.rtt.is_zero() => {
                (t.rtt * HEDGE_FACTOR).clamp(HEDGE_MIN, HEDGE_MAX)
            }
            _ => HEDGE_UNKNOWN,
        }
    }

    /// The smoothed answer time of `peer`, if measured.
    pub fn rtt(&self, peer: &PeerId) -> Option<Duration> {
        self.lock()
            .peers
            .get(peer)
            .map(|t| t.rtt)
            .filter(|d| !d.is_zero())
    }

    /// A request to `peer` was answered in `took`, with `chunks` chunks of
    /// `bytes` bytes that matched their digests (`None`: it failed).
    pub fn count(&self, peer: PeerId, took: Duration, answer: Option<(u64, u64)>) {
        self.traffic_of(peer, |t| match answer {
            Some((chunks, bytes)) => {
                t.chunks += chunks;
                t.bytes += bytes;
                t.answer_time += took;
            }
            None => t.failures += 1,
        });
    }

    /// A request to `peer` was refused for want of room: it is not a failure
    /// of the peer, nor does it say what the peer has.
    pub fn busy(&self, peer: PeerId) {
        self.traffic_of(peer, |t| t.busy += 1);
    }

    /// A request to `peer` was made, and `update` tells how it came out.
    fn traffic_of(&self, peer: PeerId, update: impl FnOnce(&mut Traffic)) {
        let now = Instant::now();
        let mut traffic = self.traffic.lock().unwrap_or_else(|e| e.into_inner());
        if traffic.len() >= MAX_PEERS && !traffic.contains_key(&peer) {
            if let Some(oldest) = traffic.iter().min_by_key(|(_, t)| t.last).map(|(p, _)| *p) {
                traffic.remove(&oldest);
            }
        }
        let t = traffic.entry(peer).or_default();
        t.requests += 1;
        t.last = Some(now);
        update(t);
    }

    /// What was fetched from each peer, the most bytes first.
    pub fn traffic(&self) -> Vec<(PeerId, Traffic)> {
        let mut all: Vec<(PeerId, Traffic)> = self
            .traffic
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .map(|(p, t)| (*p, *t))
            .collect();
        all.sort_by_key(|(p, t)| (std::cmp::Reverse(t.bytes), p.to_bytes()));
        all
    }

    /// Forget everything (a node that starts from nothing again).
    pub fn forget(&self) {
        *self.lock() = Inner::default();
        *self.filters() = Filters::default();
    }

    /// What is believed of the layers: for each (layer, peer) kept, whether
    /// the peer has the layer or lacks it, and since when.  Only `layer`'s,
    /// when given.  The oldest records are the ones that expire first.
    pub fn beliefs(&self, layer: Option<&str>) -> Vec<Belief> {
        let now = Instant::now();
        let inner = self.lock();
        let mut out = Vec::new();
        for (name, l) in inner
            .layers
            .iter()
            .filter(|(n, _)| layer.is_none_or(|w| w == n.as_str()))
        {
            for (peer, e) in &l.peers {
                let since = |at: Option<Instant>| at.map(|a| now.saturating_duration_since(a));
                if e.lacking(now) {
                    out.push(Belief {
                        layer: name.clone(),
                        peer: *peer,
                        has: false,
                        age: since(e.missed).unwrap_or_default(),
                    });
                } else if e.served_live(now) {
                    out.push(Belief {
                        layer: name.clone(),
                        peer: *peer,
                        has: true,
                        age: since(e.served).unwrap_or_default(),
                    });
                }
            }
        }
        out.sort_by(|a, b| (&a.layer, a.peer).cmp(&(&b.layer, b.peer)));
        out
    }

    /// The layers `peer` is believed to have, and to lack.
    pub fn layers_of(&self, peer: &PeerId) -> (usize, usize) {
        let now = Instant::now();
        let inner = self.lock();
        inner
            .layers
            .values()
            .filter_map(|l| l.peers.get(peer))
            .fold((0, 0), |(has, lacks), e| {
                if e.lacking(now) {
                    (has, lacks + 1)
                } else if e.served_live(now) {
                    (has + 1, lacks)
                } else {
                    (has, lacks)
                }
            })
    }

    /// The requests of `peer` that failed one after the other, when it was
    /// last measured.
    pub fn failures_of(&self, peer: &PeerId) -> u32 {
        self.lock().peers.get(peer).map_or(0, |t| t.failures)
    }

    /// Layers and peers remembered: for the tests and the logs.
    pub fn sizes(&self) -> (usize, usize) {
        let inner = self.lock();
        (inner.layers.len(), inner.peers.len())
    }
}

impl Entry {
    fn served_live(&self, now: Instant) -> bool {
        self.served
            .is_some_and(|at| now.saturating_duration_since(at) < HAS_TTL)
    }

    fn has(&self, now: Instant) -> bool {
        self.served_live(now) && !self.lacking(now)
    }

    fn lacking(&self, now: Instant) -> bool {
        self.missed
            .is_some_and(|at| now.saturating_duration_since(at) < MISS_TTL)
    }

    fn live(&self, now: Instant) -> bool {
        self.served_live(now) || self.lacking(now)
    }
}

impl Inner {
    fn timing(&mut self, peer: PeerId, now: Instant, update: impl FnOnce(&mut Timing)) {
        if self.peers.len() >= MAX_PEERS && !self.peers.contains_key(&peer) {
            self.peers
                .retain(|_, t| now.saturating_duration_since(t.at) < RTT_TTL);
            if self.peers.len() >= MAX_PEERS {
                if let Some(oldest) = self.peers.iter().min_by_key(|(_, t)| t.at).map(|(p, _)| *p) {
                    self.peers.remove(&oldest);
                }
            }
        }
        update(self.peers.entry(peer).or_insert(Timing {
            rtt: Duration::ZERO,
            at: now,
            failures: 0,
            failed_at: now,
        }));
    }

    fn entry(&mut self, layer: &str, peer: PeerId, now: Instant, update: impl FnOnce(&mut Entry)) {
        if self.layers.len() >= MAX_LAYERS && !self.layers.contains_key(layer) {
            self.layers.retain(|_, l| {
                l.peers.retain(|_, e| e.live(now));
                !l.peers.is_empty()
            });
            if self.layers.len() >= MAX_LAYERS {
                if let Some(oldest) = self
                    .layers
                    .iter()
                    .min_by_key(|(_, l)| l.touched)
                    .map(|(k, _)| k.clone())
                {
                    self.layers.remove(&oldest);
                }
            }
        }
        let l = self.layers.entry(layer.to_string()).or_insert(Layer {
            touched: now,
            peers: HashMap::new(),
        });
        l.touched = now;
        if l.peers.len() >= MAX_PEERS_PER_LAYER && !l.peers.contains_key(&peer) {
            l.peers.retain(|_, e| e.live(now));
            if l.peers.len() >= MAX_PEERS_PER_LAYER {
                return;
            }
        }
        update(l.peers.entry(peer).or_insert(Entry {
            served: None,
            missed: None,
        }));
    }

    /// What orders `peer`: the ones that keep failing last, then the
    /// quickest, the ones never measured (or not lately) first.
    fn key(&self, peer: &PeerId, now: Instant) -> (u8, Duration) {
        match self.peers.get(peer) {
            Some(t) if t.failures >= Timing::FAILING => (1, Duration::ZERO),
            Some(t) if !t.rtt.is_zero() && now.saturating_duration_since(t.at) <= RTT_TTL => {
                (0, t.rtt)
            }
            _ => (0, Duration::ZERO),
        }
    }

    fn rank(&self, peers: &mut [PeerId], now: Instant) {
        peers.sort_by_key(|p| self.key(p, now));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn what_is_believed_of_a_layer_is_told_for_the_peers_that_have_it_and_lack_it() {
        let k = Knowledge::default();
        let (a, b, c) = (peer(), peer(), peer());
        let t0 = Instant::now();
        k.served_at(Some(L), a, Duration::from_millis(5), t0);
        k.missed_at(Some(L), b, t0);
        k.served_at(Some("sha256:other"), c, Duration::from_millis(5), t0);
        let beliefs = k.beliefs(Some(L));
        assert_eq!(beliefs.len(), 2);
        assert!(beliefs.iter().any(|x| x.peer == a && x.has));
        assert!(beliefs.iter().any(|x| x.peer == b && !x.has));
        assert_eq!(k.beliefs(None).len(), 3);
        assert_eq!(k.layers_of(&a), (1, 0));
        assert_eq!(k.layers_of(&b), (0, 1));
        assert_eq!(k.layers_of(&peer()), (0, 0));
    }
    /// A peer asked after its filter said maybe is a hit when it serves the
    /// layer and a false positive when it has none of it.
    #[test]
    fn what_a_peer_that_was_said_to_have_a_layer_does_is_counted() {
        let layer = format!("sha256:{}", "7".repeat(64));
        let mut told = filter::Advertiser::new(filter::Config::default(), Entropy::seeded(1));
        told.add(std::slice::from_ref(&layer));
        let (k, a, b) = (Knowledge::default(), PeerId::random(), PeerId::random());
        for p in [a, b] {
            k.filter_received(p, &told.full().unwrap()).unwrap();
        }
        k.served(Some(&layer), a, Duration::from_millis(1));
        k.missed(Some(&layer), b);
        let infos = k.filter_infos();
        assert_eq!((infos[&a].hits, infos[&a].false_positives), (1, 0));
        assert_eq!((infos[&b].hits, infos[&b].false_positives), (0, 1));
        let totals = k.filter_totals();
        assert_eq!((totals.hits, totals.false_positives), (1, 1));
    }

    #[test]
    fn peers_that_rank_the_same_are_in_the_order_of_the_entropy() {
        let peers: Vec<PeerId> = (0..30).map(|_| peer()).collect();
        let order = |seed| {
            let k = Knowledge::with_entropy(Entropy::seeded(seed));
            // (however they come)
            let mut p = peers.clone();
            p.reverse();
            k.rank(&mut p);
            p
        };
        assert_eq!(order(5), order(5));
        assert_ne!(order(5), order(6));
        // a peer that was measured goes before the ones that were not, the
        // ones that keep failing last, whatever the order of the rest
        let k = Knowledge::with_entropy(Entropy::seeded(1));
        k.served(None, peers[3], Duration::from_millis(5));
        let mut p = peers.clone();
        k.failed(peers[0]);
        k.failed(peers[0]);
        k.rank(&mut p);
        assert_eq!(*p.last().unwrap(), peers[0]);
        assert!(p.iter().position(|x| *x == peers[3]) > Some(0));
    }

    fn peer() -> PeerId {
        PeerId::random()
    }

    const L: &str = "sha256:layer";

    #[test]
    fn a_peer_that_served_a_layer_is_a_provider_until_the_entry_expires() {
        let k = Knowledge::default();
        let (a, t0) = (peer(), Instant::now());
        k.served_at(Some(L), a, Duration::from_millis(10), t0);
        assert_eq!(k.providers_at(L, t0 + Duration::from_secs(1)), [a]);
        assert!(k
            .providers_at(L, t0 + HAS_TTL + Duration::from_secs(1))
            .is_empty());
        assert_eq!(k.sizes().0, 0, "the layer went with its last peer");
        assert!(k.providers_at("sha256:other", t0).is_empty());
    }

    #[test]
    fn a_miss_of_a_peer_that_served_the_layer_keeps_it_a_provider() {
        let k = Knowledge::default();
        let (a, t0) = (peer(), Instant::now());
        k.served_at(Some(L), a, Duration::from_millis(10), t0);
        k.missed_at(Some(L), a, t0 + Duration::from_secs(1));
        assert_eq!(k.providers_at(L, t0 + Duration::from_secs(2)), [a]);
        assert!(!k.lacks_at(L, &a, t0 + Duration::from_secs(2)));
    }

    #[test]
    fn a_failing_peer_ranks_last_until_it_serves_whatever_it_says() {
        let k = Knowledge::default();
        let (failing, other) = (peer(), peer());
        let t0 = Instant::now();
        k.served_at(Some("l"), other, Duration::from_millis(9), t0);
        k.failed(failing);
        // (it says it has a chunk of another layer, quickly)
        k.answered_at(Some("m"), failing, Duration::from_micros(1), t0, false);
        let mut peers = [failing, other];
        k.lock().rank(&mut peers, t0);
        assert_eq!(peers, [other, failing]);
        // it serves: it is believed again
        k.served_at(Some("m"), failing, Duration::from_micros(1), t0);
        k.lock().rank(&mut peers, t0);
        assert_eq!(peers, [failing, other]);
    }

    #[test]
    fn a_miss_lasts_until_it_expires_or_the_peer_serves() {
        let k = Knowledge::default();
        let (a, t0) = (peer(), Instant::now());
        k.missed_at(Some(L), a, t0);
        assert!(k.lacks_at(L, &a, t0 + Duration::from_secs(2)));
        assert!(!k.lacks_at(L, &a, t0 + MISS_TTL + Duration::from_secs(2)));
        k.missed_at(Some(L), a, t0 + Duration::from_secs(5));
        k.served_at(
            Some(L),
            a,
            Duration::from_millis(10),
            t0 + Duration::from_secs(6),
        );
        assert!(!k.lacks_at(L, &a, t0 + Duration::from_secs(7)));
        assert_eq!(k.providers_at(L, t0 + Duration::from_secs(7)), [a]);
    }

    #[test]
    fn a_peer_with_nothing_of_a_layer_it_never_served_is_known_to_lack_it() {
        let k = Knowledge::default();
        let (a, t0) = (peer(), Instant::now());
        k.missed_at(Some(L), a, t0);
        assert!(k.lacks_at(L, &a, t0 + Duration::from_secs(1)));
        assert!(k.providers_at(L, t0).is_empty());
        assert!(!k.lacks_at("sha256:other", &a, t0));
    }

    #[test]
    fn providers_come_quickest_first_and_the_failing_last() {
        let k = Knowledge::default();
        let (a, b, c, d) = (peer(), peer(), peer(), peer());
        let t0 = Instant::now();
        k.served_at(Some(L), a, Duration::from_millis(80), t0);
        k.served_at(Some(L), b, Duration::from_millis(5), t0);
        k.served_at(Some(L), c, Duration::from_millis(30), t0);
        assert_eq!(k.providers_at(L, t0), [b, c, a]);
        // an unmeasured peer is tried first, a failing one last
        let mut all = [a, b, d];
        k.rank(&mut all);
        assert_eq!(all, [d, b, a]);
        k.failed(b);
        k.failed(b);
        let mut all = [b, a, d];
        k.rank(&mut all);
        assert_eq!(all, [d, a, b]);
        // an answer clears the failures
        k.served_at(None, b, Duration::from_millis(5), Instant::now());
        let mut all = [a, b];
        k.rank(&mut all);
        assert_eq!(all, [b, a]);
    }

    #[test]
    fn a_word_of_a_failing_peer_does_not_renew_its_failing_window() {
        let k = Knowledge::default();
        let (a, t0) = (peer(), Instant::now());
        k.failed_at(a, t0);
        assert!(k.failing_at(&a, t0 + Duration::from_secs(1)));
        // after the window a probe says it has the chunk: not failing again
        let later = t0 + FAILED_TTL + Duration::from_secs(1);
        k.answered_at(Some(L), a, Duration::from_millis(5), later, false);
        assert!(!k.failing_at(&a, later));
    }

    #[test]
    fn the_hedge_delay_follows_the_peer_within_bounds() {
        let k = Knowledge::default();
        let (a, b, c, t0) = (peer(), peer(), peer(), Instant::now());
        assert_eq!(k.hedge_delay_at(&a, t0), HEDGE_UNKNOWN);
        k.served_at(None, a, Duration::from_millis(100), t0);
        assert_eq!(k.hedge_delay_at(&a, t0), Duration::from_millis(300));
        k.served_at(None, b, Duration::from_micros(100), t0);
        assert_eq!(k.hedge_delay_at(&b, t0), HEDGE_MIN);
        k.served_at(None, c, Duration::from_secs(30), t0);
        assert_eq!(k.hedge_delay_at(&c, t0), HEDGE_MAX);
        // an old measure is not believed
        assert_eq!(
            k.hedge_delay_at(&a, t0 + RTT_TTL + HEDGE_MAX),
            HEDGE_UNKNOWN
        );
    }

    #[test]
    fn forgetting_empties_the_tables() {
        let k = Knowledge::default();
        let a = peer();
        k.served(Some(L), a, Duration::from_millis(1));
        k.forget();
        assert_eq!(k.sizes(), (0, 0));
        assert!(k.providers(L).is_empty());
        assert_eq!(k.hedge_delay(&a), HEDGE_UNKNOWN);
    }

    #[test]
    fn what_each_peer_was_asked_and_sent_is_counted() {
        let k = Knowledge::default();
        let (a, b) = (peer(), peer());
        k.count(a, Duration::from_millis(10), Some((2, 100)));
        k.count(a, Duration::from_millis(30), Some((0, 0)));
        k.count(a, Duration::from_secs(10), None);
        k.count(b, Duration::from_millis(5), Some((1, 1000)));
        let t = k.traffic();
        assert_eq!(t[0].0, b);
        let a_t = t[1].1;
        assert_eq!(
            (a_t.requests, a_t.failures, a_t.chunks, a_t.bytes),
            (3, 1, 2, 100)
        );
        assert_eq!(a_t.average(), Some(Duration::from_millis(20)));
        assert_eq!(Traffic::default().average(), None);
        // kept when the rest is forgotten, and bounded
        k.forget();
        assert_eq!(k.traffic().len(), 2);
        for _ in 0..MAX_PEERS + 5 {
            k.count(peer(), Duration::ZERO, None);
        }
        assert!(k.traffic().len() <= MAX_PEERS);
    }

    #[test]
    fn the_time_is_smoothed() {
        let k = Knowledge::default();
        let (a, t0) = (peer(), Instant::now());
        k.served_at(None, a, Duration::from_millis(80), t0);
        k.served_at(None, a, Duration::from_millis(160), t0);
        assert_eq!(k.rtt(&a), Some(Duration::from_millis(90)));
    }

    #[test]
    fn the_layers_and_the_peers_are_bounded() {
        let k = Knowledge::default();
        let t0 = Instant::now();
        let first = peer();
        k.served_at(Some("sha256:first"), first, Duration::from_millis(1), t0);
        for i in 0..MAX_LAYERS + 10 {
            k.served_at(
                Some(&format!("sha256:{i}")),
                first,
                Duration::from_millis(1),
                t0 + Duration::from_millis(i as u64 + 1),
            );
        }
        assert!(k.sizes().0 <= MAX_LAYERS, "{:?}", k.sizes());
        // the oldest layer went
        assert!(k.providers_at("sha256:first", t0).is_empty());
        for _ in 0..MAX_PEERS + 10 {
            k.served_at(Some(L), peer(), Duration::from_millis(1), t0);
        }
        let inner = k.lock();
        assert!(inner.peers.len() <= MAX_PEERS);
        assert!(inner.layers[L].peers.len() <= MAX_PEERS_PER_LAYER);
    }
}
