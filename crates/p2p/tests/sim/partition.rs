// SPDX-License-Identifier: Apache-2.0
//! A swarm cut in two, and mended.

use crate::common::*;
use std::time::Duration;
use velarx_p2p::sim;

#[test]
fn a_partition_does_not_hang_a_pull_and_the_swarm_is_one_again_after_it_heals() {
    for seed in sim::seeds(&[1, 2]) {
        sim::run(seed, |world| async move {
            let first = seed_node(&world);
            let nodes = join(&world, 99, &first);
            settle(120).await;
            let during = one_layer("before", 11, 16);
            let after = one_layer("after", 12, 16);
            seed_image(&world, nodes[5].index, &during).await;
            settle(10).await;
            // fifty nodes, the bootstrap peer and the holder not among them
            world.partition(&(50..100).collect::<Vec<_>>());
            settle(120).await;
            assert_eq!(components(&world), [50, 50]);
            // a node of the far side wants what only the near side has: the
            // peers it asks are not there, the registry is
            let t0 = tokio::time::Instant::now();
            let r = pull(&nodes[60], &during).await;
            eprintln!(
                "seed {seed}: during the partition: peers {} registry {} in {:?}",
                r.peer_chunks,
                r.registry_chunks,
                t0.elapsed()
            );
            assert_eq!((r.peer_chunks, r.registry_chunks, r.wrong), (0, 16, 0));
            assert!(
                t0.elapsed() < Duration::from_secs(60),
                "the pull waited {:?}",
                t0.elapsed()
            );
            world.heal();
            let healed = tokio::time::Instant::now();
            let mut parts = components(&world);
            while parts.len() > 1 {
                assert!(
                    healed.elapsed() < Duration::from_secs(900),
                    "after 15 minutes: {parts:?}"
                );
                settle(30).await;
                parts = components(&world);
            }
            eprintln!(
                "seed {seed}: one swarm again {:?} after the heal",
                healed.elapsed()
            );
            seed_image(&world, nodes[5].index, &after).await;
            settle(10).await;
            let r = pull(&nodes[70], &after).await;
            assert_eq!(
                (r.peer_chunks, r.registry_chunks),
                (16, 0),
                "after the heal the far side still goes to the registry"
            );
        });
    }
}
