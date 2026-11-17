// SPDX-License-Identifier: Apache-2.0
//! What the node counted of how it found who has what: the answers to the
//! probes of a chunk, the lookups of the DHT, the dials of the providers it
//! named.  They are in the status of the service.

use crate::control::{DialsRefused, Lookups};
use crate::dial_filter::Refusal;
use crate::{P2PError, P2PResult, Presence};
use libp2p::PeerId;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};

#[derive(Default)]
pub(crate) struct Counters {
    probes_has: AtomicU64,
    probes_lacks: AtomicU64,
    probes_busy: AtomicU64,
    probes_failed: AtomicU64,
    dht_found: AtomicU64,
    dht_empty: AtomicU64,
    dht_failed: AtomicU64,
    dials: AtomicU64,
    dials_failed: AtomicU64,
    refused_loopback: AtomicU64,
    refused_link_local: AtomicU64,
    refused_multicast: AtomicU64,
    refused_unspecified: AtomicU64,
    refused_reserved: AtomicU64,
    refused_own_interface: AtomicU64,
    refused_unsupported: AtomicU64,
    exchange_answered: AtomicU64,
    exchange_dials: AtomicU64,
}

impl Counters {
    pub(crate) fn probe(&self, answer: &P2PResult<Presence>) {
        let counter = match answer {
            Ok(Presence::Has) => &self.probes_has,
            Ok(Presence::Lacks) => &self.probes_lacks,
            Ok(Presence::Busy) => &self.probes_busy,
            Err(_) => &self.probes_failed,
        };
        counter.fetch_add(1, Relaxed);
    }

    pub(crate) fn lookup(&self, answer: &Result<Vec<PeerId>, P2PError>) {
        let counter = match answer {
            Ok(found) if !found.is_empty() => &self.dht_found,
            Ok(_) => &self.dht_empty,
            Err(_) => &self.dht_failed,
        };
        counter.fetch_add(1, Relaxed);
    }

    /// A provider the DHT named that was not connected is dialed: counted by
    /// the swarm, which decides it (the dial of an answer of the DHT is made
    /// before its asker looks, and may connect before it does).
    pub(crate) fn dial_started(&self) {
        self.dials.fetch_add(1, Relaxed);
    }

    /// The dial of [`Self::dial_started`] did not connect.
    pub(crate) fn dial_failed(&self) {
        self.dials_failed.fetch_add(1, Relaxed);
    }

    /// A question for peers was answered with some (`peer_exchange`).
    pub(crate) fn exchange_answered(&self) {
        self.exchange_answered.fetch_add(1, Relaxed);
    }

    /// A peer learnt from an answer is dialed.
    pub(crate) fn exchange_dialed(&self) {
        self.exchange_dials.fetch_add(1, Relaxed);
    }

    /// A dial the filter refused (`dial_filter`), by its reason.
    pub(crate) fn dial_refused(&self, reason: Refusal) {
        let counter = match reason {
            Refusal::Loopback => &self.refused_loopback,
            Refusal::LinkLocal => &self.refused_link_local,
            Refusal::Multicast => &self.refused_multicast,
            Refusal::Unspecified => &self.refused_unspecified,
            Refusal::Reserved => &self.refused_reserved,
            Refusal::OwnInterface => &self.refused_own_interface,
            Refusal::Unsupported => &self.refused_unsupported,
        };
        counter.fetch_add(1, Relaxed);
    }

    /// The counts.
    pub(crate) fn snapshot(&self) -> Lookups {
        Lookups {
            probes_has: self.probes_has.load(Relaxed),
            probes_lacks: self.probes_lacks.load(Relaxed),
            probes_busy: self.probes_busy.load(Relaxed),
            probes_failed: self.probes_failed.load(Relaxed),
            dht_found: self.dht_found.load(Relaxed),
            dht_empty: self.dht_empty.load(Relaxed),
            dht_failed: self.dht_failed.load(Relaxed),
            dials: self.dials.load(Relaxed),
            dials_failed: self.dials_failed.load(Relaxed),
            exchange_answered: self.exchange_answered.load(Relaxed),
            exchange_dials: self.exchange_dials.load(Relaxed),
            dials_refused: DialsRefused {
                loopback: self.refused_loopback.load(Relaxed),
                link_local: self.refused_link_local.load(Relaxed),
                multicast: self.refused_multicast.load(Relaxed),
                unspecified: self.refused_unspecified.load(Relaxed),
                reserved: self.refused_reserved.load(Relaxed),
                own_interface: self.refused_own_interface.load(Relaxed),
                unsupported: self.refused_unsupported.load(Relaxed),
            },
            // (what the filters said is the knowledge's)
            ..Default::default()
        }
    }
}
