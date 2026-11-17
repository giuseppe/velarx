// SPDX-License-Identifier: Apache-2.0
//! What the peers hold against a node binds it only if it is the same node
//! after a restart.

use crate::common::*;
use std::sync::atomic::Ordering::Relaxed;
use velarx_p2p::sim::{self, Behavior, NodeConfig};

/// A peer that sends wrong bytes is not asked again for a while (three
/// strikes, a quarter of an hour).  Restarted with its identity it is still
/// that peer and is still not asked; restarted with a new identity it is a
/// new peer the asker believes again, and asks, and gets wrong bytes from
/// again: the cost the identity file avoids for the node whose store was
/// damaged.
fn asked_after_the_restart(seed: u64, new_identity: bool) -> (u64, u64) {
    sim::run(seed, |world| async move {
        let first = seed_node(&world);
        let honest = join(&world, 6, &first);
        let wrong = world.add_node(NodeConfig {
            bootstrap: vec![first.index],
            behavior: Behavior::Corrupt,
            ..Default::default()
        });
        let asker = world.add_node(NodeConfig {
            bootstrap: vec![first.index, wrong.index],
            ..Default::default()
        });
        settle(60).await;
        // the asker bans the peer after a few pulls (each gives it a strike)
        let mut pulled = 0;
        while !asker.live().strikes.banned(&wrong.id()) {
            assert!(pulled < 10, "the peer with wrong bytes was never banned");
            let image = one_layer(&format!("banned-{pulled}"), 40 + pulled, 8);
            seed_image(&world, honest[0].index, &image).await;
            seed_image(&world, wrong.index, &image).await;
            wrong
                .announce_falsely(std::slice::from_ref(&image.layers[0].digest))
                .await;
            settle(1).await;
            let r = pull(&asker, &image).await;
            assert_eq!(r.wrong, 0, "wrong bytes were accepted");
            pulled += 1;
        }
        let id = wrong.id();
        world.crash(wrong.index);
        if new_identity {
            world.restart_with_new_identity(wrong.index)
        } else {
            world.restart(wrong.index)
        }
        assert_eq!(wrong.id() == id, !new_identity);
        // (it joins again through the bootstrap peer, and is told of the
        // layers of the next pulls: it says it has them all)
        settle(60).await;
        let before = wrong.live().counters.served.load(Relaxed);
        let mut asked = 0;
        for i in 0..4 {
            let image = one_layer(&format!("after-{i}"), 80 + i, 8);
            seed_image(&world, honest[0].index, &image).await;
            seed_image(&world, wrong.index, &image).await;
            wrong
                .announce_falsely(std::slice::from_ref(&image.layers[0].digest))
                .await;
            settle(1).await;
            let r = pull(&asker, &image).await;
            assert_eq!(r.wrong, 0, "wrong bytes were accepted");
            asked = wrong.live().counters.served.load(Relaxed) - before;
        }
        eprintln!(
            "seed {seed}, new identity {new_identity}: banned after {pulled} pulls, \
             asked {asked} times after the restart"
        );
        (pulled, asked)
    })
}

#[test]
fn a_banned_peer_that_restarts_with_its_identity_is_still_banned() {
    for seed in sim::seeds(&[1, 2]) {
        let (_, asked) = asked_after_the_restart(seed, false);
        assert_eq!(
            asked, 0,
            "seed {seed}: a banned peer was asked after its restart"
        );
    }
}

/// The control: with a new identity the same peer is asked again, so the
/// scenario above shows what the identity does.
#[test]
fn a_peer_that_restarts_with_a_new_identity_is_asked_again() {
    for seed in sim::seeds(&[1, 2]) {
        let (_, asked) = asked_after_the_restart(seed, true);
        assert!(asked > 0, "seed {seed}: the scenario shows nothing");
    }
}
