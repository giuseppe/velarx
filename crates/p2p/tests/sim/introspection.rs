// SPDX-License-Identifier: Apache-2.0
//! What a node can say of what it did: why it asked the peers it did, what it
//! believes of them, and what it admitted.

use crate::common::*;
use velarx_p2p::explain::{Event, Outcome, Why};
use velarx_p2p::sim::{self, Behavior, NodeConfig};

#[test]
fn a_node_says_why_a_pull_went_to_the_registry() {
    sim::run(1, |world| async move {
        let image = one_layer("why", 31, 8);
        let layer = image.layers[0].digest.clone();
        let busy = world.add_node(NodeConfig {
            behavior: Behavior::Busy,
            ..Default::default()
        });
        let asker = world.add_node(NodeConfig {
            bootstrap: vec![busy.index],
            ..Default::default()
        });
        settle(30).await;
        // the one peer it has says it has no room, to a probe and to a request
        busy.announce_falsely(std::slice::from_ref(&layer)).await;
        settle(2).await;
        let r = pull(&asker, &image).await;
        assert_eq!((r.peer_chunks, r.registry_chunks), (0, 8));
        let decisions = asker.live().source.decisions().about(&layer, &[]);
        assert_eq!(decisions.len(), 1, "one group asked the peers");
        let events = &decisions[0].events;
        // it was a candidate because its filter said maybe, was asked, had
        // no room, and what was left went on
        assert!(
            events
                .iter()
                .any(|e| matches!(e, Event::Candidates(c) if c == &[(busy.id(), Why::Filter)])),
            "{events:?}"
        );
        assert!(events.iter().any(|e| matches!(e, Event::Asked { peer, outcome: Outcome::Busy, .. } if *peer == busy.id())), "{events:?}");
        assert!(
            matches!(
                events.last(),
                Some(Event::Unsent {
                    items: 8,
                    reason: "every peer asked had no room"
                })
            ),
            "{events:?}"
        );
        // and it did not take the busy peer for one without the layer
        assert!(asker
            .live()
            .source
            .knowledge()
            .beliefs(Some(&layer))
            .iter()
            .all(|b| b.has));
    });
}

#[test]
fn a_node_says_what_it_believes_of_its_peers() {
    sim::run(1, |world| async move {
        let image = one_layer("who", 32, 16);
        let layer = image.layers[0].digest.clone();
        let seed = world.add_node(NodeConfig::default());
        let others: Vec<_> = (0..3)
            .map(|_| {
                world.add_node(NodeConfig {
                    bootstrap: vec![seed.index],
                    ..Default::default()
                })
            })
            .collect();
        seed_image(&world, seed.index, &image).await;
        settle(30).await;
        pull(&others[0], &image).await;
        // the first one has it now, the second asked it and found it there
        let beliefs = others[0].live().source.knowledge().beliefs(Some(&layer));
        assert!(
            beliefs.iter().any(|b| b.peer == seed.id() && b.has),
            "{beliefs:?}"
        );
        // what it tells: a filter of the one layer it holds, whole to each
        // peer that connected and the layer in an update
        let own = seed.live().advertisement.with(|a| a.own());
        assert_eq!(own.keys, 1);
        assert!(
            own.sent.fulls >= 1 && own.bytes > 0 && own.estimated_fpr < 0.01,
            "{own:?}"
        );
    });
}
