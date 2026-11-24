// SPDX-License-Identifier: Apache-2.0
//! What every scenario must leave true of the decision log of each node,
//! whatever the scenario is about: the rules of asking the peers of a group.
//!
//! The log (`explain`) records, per group, the candidates found and each
//! request as it ended, in the order it ended.  It has no clock and does not
//! say what the knowledge table believed when a peer was asked, so what is
//! checked is what the order of the requests of one group shows:
//!
//! * a group asks at most [`MAX_ASKED`] peers;
//! * a peer is asked again only after it answered busy, and a request that
//!   may have brought chunks (of any peer) ended since; so a peer whose
//!   request failed is not asked again in the group (the failing window is
//!   longer than a group lasts).
//!
//! The group counts the chunks that came since a peer said busy, also those
//! of a request that ended as failed; the log says how many a request sent
//! only when it ended well, so a failed request counts as progress (the
//! weakest rule that is true).
//!
//! Not checked: that no peer is asked while the table says it is failing
//! (the table's state at the time of the request is not in the log), and the
//! groups that spread over several peers (`Striped`), whose peers are asked
//! for one part after the other by design.

use crate::explain::{Event, Outcome, Record};
use crate::provider::MAX_ASKED;
use crate::sim::World;
use libp2p::PeerId;
use std::collections::HashMap;

/// Panic when a node of `world` has a group in its log that broke a rule.
pub(super) fn decisions(world: &World) {
    for node in world.nodes() {
        for record in node.live().source.decisions().about("", &[]) {
            if let Some(broken) = broken(&record) {
                panic!(
                    "node {} broke a rule of asking the peers: {broken}\n{record:#?}",
                    node.index
                );
            }
        }
    }
}

/// The rule the group `record` broke, if one.
fn broken(record: &Record) -> Option<String> {
    if record.events.iter().any(|e| matches!(e, Event::Striped(_))) {
        return None;
    }
    // for each peer asked: the number of requests that may have brought
    // chunks when it answered busy the last time, or None when it was asked
    // otherwise
    let mut busy: HashMap<PeerId, Option<usize>> = HashMap::new();
    let mut sent = 0;
    for event in &record.events {
        let Event::Asked { peer, outcome, .. } = event else {
            continue;
        };
        if let Some(before) = busy.get(peer) {
            match before {
                Some(at) if *at < sent => {}
                _ => return Some(format!("{peer} was asked again with no room made")),
            }
        }
        busy.insert(*peer, matches!(outcome, Outcome::Busy).then_some(sent));
        if matches!(outcome, Outcome::Sent(..) | Outcome::Failed(_)) {
            sent += 1;
        }
    }
    (busy.len() > MAX_ASKED).then(|| format!("{} peers were asked", busy.len()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn asked(peer: PeerId, outcome: Outcome) -> Event {
        Event::Asked {
            peer,
            outcome,
            took: Duration::ZERO,
        }
    }

    fn group(events: Vec<Event>) -> Record {
        Record {
            id: 1,
            at: 0,
            kind: crate::explain::Kind::Chunks,
            layer: None,
            first: String::new(),
            items: 1,
            events,
            dropped: 0,
        }
    }

    #[test]
    fn a_busy_peer_is_asked_again_after_progress_and_not_before() {
        let (a, b) = (PeerId::random(), PeerId::random());
        let after_chunks = group(vec![
            asked(a, Outcome::Busy),
            asked(b, Outcome::Sent(1, 1)),
            asked(a, Outcome::Sent(1, 1)),
        ]);
        assert_eq!(broken(&after_chunks), None);
        // (a request that failed may have brought chunks first)
        let after_failure = group(vec![
            asked(a, Outcome::Busy),
            asked(b, Outcome::Failed("x".into())),
            asked(a, Outcome::Busy),
        ]);
        assert_eq!(broken(&after_failure), None);
        let no_progress = group(vec![
            asked(a, Outcome::Busy),
            asked(b, Outcome::Lacks),
            asked(a, Outcome::Sent(1, 1)),
        ]);
        assert!(broken(&no_progress).is_some());
        let after_failed = group(vec![
            asked(a, Outcome::Failed("x".into())),
            asked(b, Outcome::Sent(1, 1)),
            asked(a, Outcome::Sent(1, 1)),
        ]);
        assert!(broken(&after_failed).is_some());
    }

    #[test]
    fn a_group_asks_at_most_the_peers_it_may() {
        let peers = |n: usize| -> Vec<Event> {
            (0..n)
                .map(|_| asked(PeerId::random(), Outcome::Lacks))
                .collect()
        };
        assert_eq!(broken(&group(peers(MAX_ASKED))), None);
        assert!(broken(&group(peers(MAX_ASKED + 1))).is_some());
    }

    #[test]
    fn a_group_spread_over_peers_is_not_checked() {
        let a = PeerId::random();
        let striped = group(vec![
            Event::Striped(vec![a]),
            asked(a, Outcome::Sent(1, 1)),
            asked(a, Outcome::Sent(1, 1)),
        ]);
        assert_eq!(broken(&striped), None);
    }
}
