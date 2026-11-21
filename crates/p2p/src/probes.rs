// SPDX-License-Identifier: Apache-2.0
//! What a node asks the peers whether they have a chunk: the rounds of a layer
//! are shared by its groups, and a peer is asked only so many at once.
//!
//! A pull runs up to four groups of a layer at once, and a node pulls many
//! layers at once.  Each group that found no peer asks a round of probes
//! (up to `query_peers`, 8) and a second one when that gave nothing: without
//! sharing, 4 groups probe 4 x 16 times for one layer.  Here the groups of a
//! layer share each round (the first asks, the others use its answer, also
//! a recent one), and a node has at most [`PER_PEER`] probes in flight to one
//! peer ([`InFlight`]), whatever the number of layers: the others wait for a
//! place within the time of their round.

use crate::shared::Keep;
use libp2p::PeerId;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// How long the answer of a round is used by groups that come later.  What
/// the peers said is also in what the node knows of them (`Knowledge`, for
/// minutes): this is only for the groups that ask before that is read.
pub const ROUND_TTL: Duration = Duration::from_secs(5);

/// The QUIC streams of chunk requests a node has open to one peer at most:
/// what a connection carries at a time (`streams_per_connection` of the QUIC limits).  A
/// request takes a stream for each of its lanes (`quic_streams` of the
/// settings, at most one a chunk): two requests of four lanes, or eight of
/// one chunk.
pub const STREAMS_PER_PEER: usize = 8;

/// The probes a node has in flight to one peer at most: the slots a peer
/// answers probes in ([`crate::PROBE_SLOTS`]).  A probe beyond them would be
/// answered "no room" (or wait on the peer's side); it waits for a place
/// here instead, within the time its round waits for answers.  The load a
/// node puts on a peer is bounded this way, not by a rate of the node: a
/// node that pulls 50 layers from 40 peers asks each about ten times, a
/// few at a time, and every layer gets its round.
pub const PER_PEER: usize = crate::PROBE_SLOTS;

/// What the peers asked said of a chunk.
#[derive(Clone, Default)]
pub struct Probed {
    /// The peers that were asked
    pub asked: Vec<PeerId>,
    pub has: Vec<PeerId>,
    pub no: Vec<PeerId>,
    pub busy: Vec<PeerId>,
}

impl Keep for Probed {
    /// What the peers said for a few seconds, if any said: a round in which
    /// all had no room or did not answer (in time) says nothing.  A peer
    /// with no room is not kept (it has
    /// room soon, and is not one without the chunk).
    fn keep(&self) -> Option<(Self, Duration)> {
        if self.has.is_empty() && self.no.is_empty() {
            return None;
        }
        let mut kept = self.clone();
        kept.asked.retain(|p| !kept.busy.contains(p));
        kept.busy.clear();
        Some((kept, ROUND_TTL))
    }
}

type Places = Mutex<HashMap<PeerId, Arc<Semaphore>>>;

/// The places of the questions in flight to each peer, so many a peer.  A
/// peer has an entry while a question to it is in flight or waits.
pub struct InFlight {
    places: Places,
    per_peer: usize,
}

impl Default for InFlight {
    /// [`PER_PEER`] a peer: the probes.
    fn default() -> Self {
        Self::new(PER_PEER)
    }
}

/// A place of a probe to a peer: let go (and the entry of the peer with the
/// last one) when it is dropped, also while it waits.
pub struct Place<'a> {
    places: &'a Places,
    peer: PeerId,
    of: Option<Arc<Semaphore>>,
    permit: Option<OwnedSemaphorePermit>,
}

impl Drop for Place<'_> {
    fn drop(&mut self) {
        drop(self.permit.take());
        let Some(of) = self.of.take() else { return };
        // (the places of a peer are handed out and counted under the lock:
        // the map's and this one are the only two when nobody else holds
        // or waits for one)
        let mut places = self.places.lock().unwrap_or_else(|e| e.into_inner());
        if places
            .get(&self.peer)
            .is_some_and(|p| Arc::ptr_eq(p, &of) && Arc::strong_count(&of) <= 2)
        {
            places.remove(&self.peer);
        }
    }
}

impl InFlight {
    pub fn new(per_peer: usize) -> Self {
        Self {
            places: Places::default(),
            per_peer,
        }
    }

    /// A place for a question to `peer`, when one of its places is free.
    pub async fn place(&self, peer: PeerId) -> Place<'_> {
        self.places(peer, 1).await
    }

    /// `n` places for a question to `peer` (at most all of its places), when
    /// so many are free.
    pub async fn places(&self, peer: PeerId, n: usize) -> Place<'_> {
        let of = self
            .places
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .entry(peer)
            .or_insert_with(|| Arc::new(Semaphore::new(self.per_peer)))
            .clone();
        let mut place = Place {
            places: &self.places,
            peer,
            of: Some(of.clone()),
            permit: None,
        };
        // (never closed)
        let n = n.clamp(1, self.per_peer) as u32;
        place.permit = of.acquire_many_owned(n).await.ok();
        place
    }

    /// The places of `peer` in use: how loaded it is by the questions of
    /// this node.
    pub fn load(&self, peer: &PeerId) -> usize {
        self.places
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(peer)
            .map_or(0, |p| self.per_peer.saturating_sub(p.available_permits()))
    }

    #[cfg(test)]
    fn peers(&self) -> usize {
        self.places.lock().unwrap().len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_peer_has_so_many_probes_in_flight_and_its_entry_goes_with_the_last() {
        let inflight = InFlight::default();
        let (a, b) = (PeerId::random(), PeerId::random());
        let mut held = Vec::new();
        for _ in 0..PER_PEER {
            held.push(inflight.place(a).await);
        }
        // (one more for `a` waits; another peer does not)
        let mut more = Box::pin(inflight.place(a));
        assert!(futures::poll!(more.as_mut()).is_pending());
        let other = inflight.place(b).await;
        drop(other);
        assert_eq!(inflight.peers(), 1);
        held.pop();
        let more = more.await;
        drop(held);
        drop(more);
        assert_eq!(inflight.peers(), 0);
        // (one that waits and goes away leaves nothing either)
        let mut held = Vec::new();
        for _ in 0..PER_PEER {
            held.push(inflight.place(a).await);
        }
        let mut waiting = Box::pin(inflight.place(a));
        assert!(futures::poll!(waiting.as_mut()).is_pending());
        drop(waiting);
        drop(held);
        assert_eq!(inflight.peers(), 0);
    }

    #[test]
    fn a_round_that_said_nothing_is_not_kept_and_no_room_is_not_kept_as_an_answer() {
        let (a, b, c) = (PeerId::random(), PeerId::random(), PeerId::random());
        let nothing = Probed {
            asked: vec![a, b],
            busy: vec![a, b],
            ..Default::default()
        };
        assert!(nothing.keep().is_none());
        let some = Probed {
            asked: vec![a, b, c],
            has: vec![c],
            busy: vec![a],
            no: vec![b],
        };
        let (kept, ttl) = some.keep().expect("a round that said something");
        assert_eq!(ttl, ROUND_TTL);
        assert!(kept.busy.is_empty() && !kept.asked.contains(&a));
        assert_eq!((kept.has, kept.no), (vec![c], vec![b]));
    }
}
