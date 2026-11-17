// SPDX-License-Identifier: Apache-2.0
//! Why a pull asked the peers it did: a bounded ring of the recent decisions
//! of the source of the pulls.
//!
//! Each call that asks the peers for something (a group of chunks, the index
//! of a layer, a startup profile) makes one record: who was considered and
//! why (served it lately, its filter said maybe, said it has the chunk, the DHT named
//! it, only connected), what the probes answered, what each request to a
//! peer came to, and why what the peers did not give was left to the next
//! source (the engine's list ends at the registry).  The decision code notes
//! what it does where it does it ([`note`]); nothing is computed for a record
//! that is not made.

use libp2p::PeerId;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// The records kept.
pub const KEEP: usize = 256;
/// The events of one record, at most (the others are counted).
const MAX_EVENTS: usize = 96;

/// What was asked of the peers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Chunks,
    Index,
    Profile,
}

impl Kind {
    pub fn name(self) -> &'static str {
        match self {
            Kind::Chunks => "chunks",
            Kind::Index => "index",
            Kind::Profile => "profile",
        }
    }
}

/// Why a peer was one to ask.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Why {
    /// It served the layer lately
    Served,
    /// Its filter said it may hold the layer
    Filter,
    /// It has no filter that is believed, and said it has the chunk when
    /// asked
    Probed,
    /// It had no room to say
    Busy,
    /// The DHT named it as a provider
    Dht,
    /// Connected, and not known to lack the layer
    Connected,
}

impl Why {
    pub fn name(self) -> &'static str {
        match self {
            Why::Served => "served-it",
            Why::Filter => "filter-said-maybe",
            Why::Probed => "said-it-has-it",
            Why::Busy => "had-no-room-to-say",
            Why::Dht => "dht",
            Why::Connected => "connected",
        }
    }
}

/// What came of asking a peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// It sent this many chunks that matched, of this many bytes
    Sent(u64, u64),
    /// It sent none that matched: it does not have them
    Lacks,
    /// It had no room to answer
    Busy,
    /// There is no QUIC (UDP) path to it, and why: it was not asked
    NoPath(String),
    /// The request failed
    Failed(String),
}

impl Outcome {
    pub fn name(&self) -> &'static str {
        match self {
            Outcome::Sent(..) => "sent",
            Outcome::Lacks => "lacks",
            Outcome::Busy => "busy",
            Outcome::NoPath(_) => "no-quic-path",
            Outcome::Failed(_) => "failed",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// The peers to ask, in order, with the reason each is one
    Candidates(Vec<(PeerId, Why)>),
    /// What a peer answered the question whether it has the chunk
    Probe { peer: PeerId, answer: &'static str },
    /// What the filters of the connected peers said of the layer: peers that
    /// may hold it (asked), peers that do not (neither asked nor probed),
    /// and peers with no filter that is believed (probed)
    Filters {
        maybe: usize,
        no: usize,
        unknown: usize,
    },
    /// The group is spread over these peers
    Striped(Vec<PeerId>),
    /// A request to a peer
    Asked {
        peer: PeerId,
        outcome: Outcome,
        took: Duration,
    },
    /// The peers gave this node much less than they have given it before:
    /// the rest was left to the next source
    Slow { rate: u64, best: u64 },
    /// What the peers did not give: left to the next source, and why
    Unsent { items: usize, reason: &'static str },
}

/// One call that asked the peers.
#[derive(Debug, Clone)]
pub struct Record {
    pub id: u64,
    /// Seconds since the epoch (for the reader; the decisions do not use it)
    pub at: u64,
    pub kind: Kind,
    /// The layer the chunks belong to, when it was named
    pub layer: Option<String>,
    /// The first digest asked for (the chunk, the layer or the image)
    pub first: String,
    pub items: usize,
    pub events: Vec<Event>,
    /// Events that did not fit
    pub dropped: usize,
}

/// The ring.
#[derive(Default)]
pub struct Decisions {
    ring: Mutex<VecDeque<Arc<Mutex<Record>>>>,
    next: AtomicU64,
}

/// A record being made; events are added through [`note`].
#[derive(Clone)]
pub struct Log(Arc<Mutex<Record>>);

tokio::task_local! {
    static CURRENT: Log;
}

impl Decisions {
    /// Start a record.
    pub fn start(&self, kind: Kind, layer: Option<&str>, first: &str, items: usize) -> Log {
        let record = Arc::new(Mutex::new(Record {
            id: self.next.fetch_add(1, Ordering::Relaxed) + 1,
            at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_secs()),
            kind,
            layer: layer.map(str::to_string),
            first: first.to_string(),
            items,
            events: Vec::new(),
            dropped: 0,
        }));
        let mut ring = self.ring.lock().unwrap_or_else(|e| e.into_inner());
        if ring.len() >= KEEP {
            ring.pop_front();
        }
        ring.push_back(record.clone());
        Log(record)
    }

    /// The records about `target` (a digest, or the start of one, at least
    /// 8 characters: a layer, a chunk or an image), the last first; all when
    /// there is none.  Each digest of `also` (the layers of the image
    /// `target` names) is a target too.
    pub fn about(&self, target: &str, also: &[String]) -> Vec<Record> {
        // (a layer is named `sha256:HEX` or `toc:sha256:HEX`: the digest
        // is what is compared)
        let bare = |s: &str| s.rsplit(':').next().unwrap_or(s).to_string();
        let targets: Vec<String> = std::iter::once(target)
            .chain(also.iter().map(String::as_str))
            .map(bare)
            .collect();
        let matches = |d: &str| {
            let d = bare(d);
            targets
                .iter()
                .any(|t| !t.is_empty() && (d == *t || (t.len() >= 8 && d.contains(t.as_str()))))
        };
        let ring = self.ring.lock().unwrap_or_else(|e| e.into_inner());
        ring.iter()
            .rev()
            .map(|r| r.lock().unwrap_or_else(|e| e.into_inner()).clone())
            .filter(|r| {
                target.is_empty() || matches(&r.first) || r.layer.as_deref().is_some_and(matches)
            })
            .collect()
    }

    pub fn len(&self) -> usize {
        self.ring.lock().unwrap_or_else(|e| e.into_inner()).len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Log {
    /// The number of the record.
    pub fn id(&self) -> u64 {
        self.0.lock().unwrap_or_else(|e| e.into_inner()).id
    }

    /// Why what the peers did not give was not given, from what the record
    /// says of the peers that were asked.
    pub fn reason(&self) -> &'static str {
        let r = self.0.lock().unwrap_or_else(|e| e.into_inner());
        if r.events.iter().any(|e| matches!(e, Event::Slow { .. })) {
            return "the peers are much slower than they were";
        }
        let asked: Vec<&Outcome> = r
            .events
            .iter()
            .filter_map(|e| match e {
                Event::Asked { outcome, .. } => Some(outcome),
                _ => None,
            })
            .collect();
        let candidates = r
            .events
            .iter()
            .any(|e| matches!(e, Event::Candidates(p) if !p.is_empty()));
        if asked.is_empty() {
            return if candidates {
                "no peer answered"
            } else {
                "no peer to ask"
            };
        }
        let all = |f: fn(&Outcome) -> bool| asked.iter().all(|o| f(o));
        if all(|o| matches!(o, Outcome::Busy)) {
            "every peer asked had no room"
        } else if all(|o| matches!(o, Outcome::Lacks)) {
            "the peers asked do not have it"
        } else if all(|o| matches!(o, Outcome::NoPath(_))) {
            "no QUIC (UDP) path to any peer asked"
        } else if all(|o| matches!(o, Outcome::Failed(_) | Outcome::NoPath(_))) {
            "every request failed"
        } else {
            "the peers asked did not send all of it"
        }
    }

    pub(crate) fn add(&self, event: Event) {
        let mut r = self.0.lock().unwrap_or_else(|e| e.into_inner());
        if r.events.len() >= MAX_EVENTS {
            r.dropped += 1;
        } else {
            r.events.push(event);
        }
    }

    /// Run `work` with this record as the one the decisions note into.
    pub async fn scope<F: std::future::Future>(self, work: F) -> F::Output {
        CURRENT.scope(self, work).await
    }
}

/// Note an event in the record of the call being served; `event` is not
/// run when there is none.
pub fn note(event: impl FnOnce() -> Event) {
    let _ = CURRENT.try_with(|log| log.add(event()));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn events_go_to_the_record_of_the_call_and_nowhere_else() {
        let d = Decisions::default();
        // (no call: nothing is made)
        note(|| unreachable!("no record, no event"));
        let log = d.start(Kind::Chunks, Some("sha256:aaaaaaaa"), "sha256:bbbbbbbb", 3);
        let peer = PeerId::random();
        log.clone()
            .scope(async {
                note(|| Event::Candidates(vec![(peer, Why::Served)]));
                note(|| Event::Unsent {
                    items: 3,
                    reason: "x",
                });
            })
            .await;
        let all = d.about("", &[]);
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].events.len(), 2);
        assert_eq!(all[0].items, 3);
    }

    #[tokio::test]
    async fn the_ring_is_bounded_and_a_target_picks_records_by_layer_or_chunk() {
        let d = Decisions::default();
        for i in 0..KEEP + 10 {
            d.start(
                Kind::Chunks,
                Some(&format!("sha256:layer{i:04}")),
                "sha256:chunk",
                1,
            );
        }
        assert_eq!(d.len(), KEEP);
        assert_eq!(d.about("", &[]).len(), KEEP);
        // the last first
        assert_eq!(
            d.about("", &[])[0].layer.as_deref(),
            Some("sha256:layer0265")
        );
        assert_eq!(d.about("layer0100", &[]).len(), 1);
        assert_eq!(d.about("sha256:chunk", &[]).len(), KEEP);
        // an image names its layers
        let layers = vec![
            "sha256:layer0200".to_string(),
            "sha256:layer0201".to_string(),
        ];
        assert_eq!(d.about("an-image", &layers).len(), 2);
        assert!(d.about("nothing-like-it", &[]).is_empty());
    }

    #[tokio::test]
    async fn a_record_keeps_a_bounded_number_of_events_and_counts_the_rest() {
        let d = Decisions::default();
        let log = d.start(Kind::Chunks, None, "sha256:x", 1);
        log.clone()
            .scope(async {
                for _ in 0..MAX_EVENTS + 5 {
                    note(|| Event::Unsent {
                        items: 1,
                        reason: "r",
                    });
                }
            })
            .await;
        let r = &d.about("", &[])[0];
        assert_eq!((r.events.len(), r.dropped), (MAX_EVENTS, 5));
    }
}
