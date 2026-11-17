// SPDX-License-Identifier: Apache-2.0
//! Keeping a node among peers.
//!
//! The bootstrap peers are what a node knows of the swarm when it starts.
//! A peer that is full refuses it, a peer may be down or restarting, and a
//! node that dialed them once stays alone for ever.  So while the node has
//! fewer than `min_peers` connections a timer is armed: when it fires the
//! bootstrap peers are dialed again and the timer is armed for a longer time
//! (twice, up to a bound, with jitter so that a thousand nodes refused at
//! the same moment do not come back at the same moment).  Connections
//! opening and closing tell the state when to arm it; nothing polls.

use crate::entropy::Entropy;
use libp2p::Multiaddr;
use std::time::Duration;
use tokio::time::Instant;

/// The delays between the attempts: the first is `min`, each is twice the one
/// before up to `max`, and what is waited is between half of that and all of
/// it (the jitter, `unit` is a number in `0..1`).
#[derive(Debug, Clone)]
pub struct Backoff {
    min: Duration,
    max: Duration,
    attempt: u32,
    entropy: Entropy,
}

impl Backoff {
    pub fn new(min: Duration, max: Duration) -> Self {
        Self {
            min,
            max: max.max(min),
            attempt: 0,
            entropy: Entropy::system(),
        }
    }

    /// The same, with the jitter from `entropy`.
    pub fn with_entropy(mut self, entropy: Entropy) -> Self {
        self.entropy = entropy;
        self
    }

    /// The time to wait for the next attempt, jittered.
    fn wait(&mut self) -> Duration {
        let unit = self.entropy.unit();
        self.next(unit)
    }

    /// The time to wait for the next attempt.
    fn next(&mut self, unit: f64) -> Duration {
        let full = self
            .min
            .saturating_mul(1u32.checked_shl(self.attempt).unwrap_or(u32::MAX))
            .min(self.max);
        self.attempt = self.attempt.saturating_add(1);
        full.mul_f64(0.5 + 0.5 * unit.clamp(0.0, 1.0))
    }

    fn reset(&mut self) {
        self.attempt = 0;
    }
}

/// Whether and when the bootstrap peers are dialed again.
pub struct Bootstrap {
    addresses: Vec<Multiaddr>,
    min_peers: usize,
    backoff: Backoff,
    /// When the next attempt is due, while the node has too few peers
    deadline: Option<Instant>,
}

impl Bootstrap {
    /// The bootstrap peers at `addresses`, to keep `min_peers` connections
    /// to.  The first attempt is made by the caller; the next is due after
    /// the first delay.
    pub fn new(
        addresses: Vec<Multiaddr>,
        min_peers: usize,
        backoff: Backoff,
        now: Instant,
    ) -> Self {
        let mut this = Self {
            addresses,
            min_peers,
            backoff,
            deadline: None,
        };
        this.connections(0, now);
        this
    }

    /// The connected peers are now `connected`: arm the timer when there are
    /// too few.
    pub fn connections(&mut self, connected: usize, now: Instant) {
        if self.addresses.is_empty() || connected >= self.min_peers || self.deadline.is_some() {
            return;
        }
        self.deadline = Some(now + self.backoff.wait());
    }

    /// The bootstrap peers.
    pub fn addresses(&self) -> &[Multiaddr] {
        &self.addresses
    }

    /// When the next attempt is due; `None` while there is nothing to do.
    pub fn deadline(&self) -> Option<Instant> {
        self.deadline
    }

    /// Whether a node with `connected` peers should ask them for others: it
    /// has no more than `min_peers` (a peer that took it for an exchange
    /// only is one of them, and is gone soon).
    pub fn wants_peers(&self, connected: usize) -> bool {
        connected <= self.min_peers
    }

    /// The timer fired with `connected` peers: the addresses to dial, and the
    /// timer armed again, or, when the node is among enough peers for the
    /// whole delay, disarmed and the delays start again.
    pub fn fired(&mut self, connected: usize, now: Instant) -> &[Multiaddr] {
        self.deadline = None;
        if connected >= self.min_peers {
            self.backoff.reset();
            return &[];
        }
        self.connections(connected, now);
        &self.addresses
    }
}

/// The places a node lends past `max_incoming`, at most at a time
/// ([`Exchange::CONNECTIONS`]), as a number the transport's limit is made of.
pub const LENT_PLACES: u32 = 16;

/// What became of a connection a peer made to the node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Place {
    /// One of the `max_incoming`, kept
    Member,
    /// Past `max_incoming`, for a short time: to ask which peers the node
    /// knows
    Lent,
    /// No place for it: closed at once
    Refused,
}

/// The connections a node takes past `max_incoming`, each for a short
/// time: long enough for the newcomer to ask the node which peers it knows
/// (the exchange of peers, then a Kademlia walk), not to stay.  A node that
/// a full peer refused outright learnt nothing and stayed alone however
/// often it came back; one taken this way joins the swarm through the peers it
/// was told.
///
/// A place is lent for [`Exchange::TIME`] at most, and freed
/// [`Exchange::RELEASE`] after the newcomer was answered ([`Exchange::served`]),
/// so a place is back within a second or two for the next newcomer.
///
/// A lent place is never taken back for another newcomer before its time is
/// over: it is also the whole of the connection a puller that dials a full
/// provider has, and the pulls it was cut from went to the registry.
pub struct Exchange<C> {
    max_incoming: usize,
    incoming: std::collections::HashSet<C>,
    lent: Vec<Lent<C>>,
}

struct Lent<C> {
    id: C,
    /// When its time is over
    until: Instant,
}

impl<C: PartialEq + Eq + std::hash::Hash + Copy> Exchange<C> {
    /// The connections taken past `max_incoming` at a time, at most.
    pub const CONNECTIONS: u32 = LENT_PLACES;
    /// How long one is kept at most.
    pub const TIME: Duration = Duration::from_secs(3);
    /// How long one is kept after the newcomer was answered: what it asks of
    /// the Kademlia walk comes with the question for peers.
    pub const RELEASE: Duration = Duration::from_secs(1);

    pub fn new(max_incoming: usize) -> Self {
        Self {
            max_incoming,
            incoming: Default::default(),
            lent: Vec::new(),
        }
    }

    /// A connection made to the node is established.
    pub fn incoming(&mut self, id: C, now: Instant) -> Place {
        if self.incoming.len() < self.max_incoming {
            self.incoming.insert(id);
            return Place::Member;
        }
        if self.lent.len() >= Self::CONNECTIONS as usize {
            return Place::Refused;
        }
        self.lent.push(Lent {
            id,
            until: now + Self::TIME,
        });
        Place::Lent
    }

    /// The connection `id` is closed.
    pub fn closed(&mut self, id: C) {
        if !self.incoming.remove(&id) {
            self.lent.retain(|l| l.id != id);
        }
    }

    /// The newcomer of the lent connection `id` was answered: it is closed
    /// soon (not later than its time was).
    pub fn served(&mut self, id: C, now: Instant) {
        if let Some(l) = self.lent.iter_mut().find(|l| l.id == id) {
            l.until = l.until.min(now + Self::RELEASE);
        }
    }

    /// When the first lent place is to be taken back; `None` while none is
    /// lent.
    pub fn deadline(&self) -> Option<Instant> {
        self.lent.iter().map(|l| l.until).min()
    }

    /// The lent connections whose time is over at `now`, to close.
    pub fn expired(&mut self, now: Instant) -> Vec<C> {
        let over: Vec<C> = self
            .lent
            .iter()
            .filter(|l| l.until <= now)
            .map(|l| l.id)
            .collect();
        self.lent.retain(|l| l.until > now);
        over
    }

    /// The lent connections.
    pub fn lent(&self) -> usize {
        self.lent.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn a_seeded_node_waits_the_same_times_again_and_another_seed_other_times() {
        let waits = |seed| {
            let mut b = Backoff::new(S, 60 * S).with_entropy(Entropy::seeded(seed));
            (0..6).map(|_| b.wait()).collect::<Vec<_>>()
        };
        assert_eq!(waits(1), waits(1));
        assert_ne!(waits(1), waits(2));
        assert!(waits(1).iter().all(|d| *d > Duration::ZERO && *d <= 60 * S));
    }

    const S: Duration = Duration::from_secs(1);

    type Lends = Exchange<u32>;

    #[test]
    fn connections_past_the_maximum_are_taken_for_an_exchange_only() {
        let t0 = Instant::now();
        let mut e = Lends::new(2);
        assert_eq!(e.incoming(1, t0), Place::Member);
        assert_eq!(e.incoming(2, t0), Place::Member);
        assert_eq!(e.deadline(), None);
        // full: the third is for the exchange
        assert_eq!(e.incoming(3, t0), Place::Lent);
        assert_eq!(e.incoming(4, t0 + S), Place::Lent);
        assert_eq!(e.deadline(), Some(t0 + Lends::TIME));
        // one that went by itself is not closed again
        e.closed(3);
        assert_eq!(e.deadline(), Some(t0 + S + Lends::TIME));
        assert!(e.expired(t0 + Lends::TIME).is_empty());
        assert_eq!(e.expired(t0 + S + Lends::TIME), [4]);
        assert_eq!(e.deadline(), None);
        // a place that is free is taken to stay
        e.closed(1);
        assert_eq!(e.incoming(5, t0), Place::Member);
        assert_eq!(e.incoming(6, t0), Place::Lent);
    }

    #[test]
    fn a_place_is_freed_soon_after_the_newcomer_was_answered() {
        let t0 = Instant::now();
        let mut e = Lends::new(0);
        assert_eq!(e.incoming(1, t0), Place::Lent);
        assert_eq!(e.incoming(2, t0), Place::Lent);
        e.served(1, t0 + S / 2);
        assert_eq!(e.deadline(), Some(t0 + S / 2 + Lends::RELEASE));
        assert_eq!(e.expired(t0 + S / 2 + Lends::RELEASE), [1]);
        // (never later than the time it had: the answer of a late newcomer
        // does not extend it)
        e.served(2, t0 + Lends::TIME);
        assert_eq!(e.deadline(), Some(t0 + Lends::TIME));
        // (and one that is not lent is not touched)
        e.served(9, t0);
    }

    #[test]
    fn the_delays_double_up_to_the_bound_and_are_jittered() {
        let mut b = Backoff::new(S, 10 * S);
        // (full jitter 0 is half, 1 is all of it)
        let delays: Vec<_> = (0..6).map(|_| b.next(1.0)).collect();
        assert_eq!(delays, [S, 2 * S, 4 * S, 8 * S, 10 * S, 10 * S]);
        let mut b = Backoff::new(S, 10 * S);
        assert_eq!(b.next(0.0), S / 2);
        assert_eq!(b.next(0.0), S);
        b.reset();
        assert_eq!(b.next(0.5), S - S / 4);
        // a shift past the width of the counter is the bound, not a panic
        let mut b = Backoff::new(S, 10 * S);
        b.attempt = u32::MAX;
        assert_eq!(b.next(1.0), 10 * S);
    }

    fn addr() -> Multiaddr {
        "/ip4/10.0.0.1/tcp/4001".parse().unwrap()
    }

    #[test]
    fn a_node_with_too_few_peers_dials_again_and_one_with_enough_does_not() {
        let t0 = Instant::now();
        let mut b = Bootstrap::new(vec![addr()], 2, Backoff::new(S, 8 * S), t0);
        let first = b.deadline().expect("armed at the start");
        assert!(first > t0 && first <= t0 + S);
        // still alone: the addresses again, and the next time is later
        assert_eq!(b.fired(0, first), [addr()]);
        let second = b.deadline().expect("armed again");
        assert!(second > first + S / 2 && second <= first + 2 * S);
        // one peer is not enough
        assert_eq!(b.fired(1, second), [addr()]);
        assert!(b.deadline().is_some());
        // two are: nothing to dial, nothing armed
        let at = b.deadline().unwrap();
        assert!(b.fired(2, at).is_empty());
        assert_eq!(b.deadline(), None);
        // the connections falling again arm it, from the first delay
        b.connections(1, at);
        let again = b.deadline().expect("armed by the loss");
        assert!(again <= at + S);
    }

    #[test]
    fn the_timer_is_not_moved_by_connections_coming_and_going() {
        let t0 = Instant::now();
        let mut b = Bootstrap::new(vec![addr()], 3, Backoff::new(S, 8 * S), t0);
        let armed = b.deadline();
        for n in [1, 0, 2, 0] {
            b.connections(n, t0 + S / 10);
            assert_eq!(b.deadline(), armed);
        }
    }

    /// `min_peers = 0`: the first dial is the only one.
    #[test]
    fn without_a_minimum_nothing_is_armed() {
        let b = Bootstrap::new(vec![addr()], 0, Backoff::new(S, 8 * S), Instant::now());
        assert_eq!(b.deadline(), None);
    }

    #[test]
    fn nothing_is_armed_without_bootstrap_peers() {
        let b = Bootstrap::new(Vec::new(), 3, Backoff::new(S, 8 * S), Instant::now());
        assert_eq!(b.deadline(), None);
    }
}
