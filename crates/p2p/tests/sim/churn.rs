// SPDX-License-Identifier: Apache-2.0
//! Nodes that stop and come back with new identities (state wiped), all the
//! time.

use crate::common::*;
use std::time::Duration;
use velarx_p2p::sim;

#[test]
fn a_swarm_that_loses_a_twentieth_of_its_nodes_every_twenty_seconds_stays_one_and_serves() {
    for seed in sim::seeds(&[1, 2]) {
        sim::run(seed, |world| async move {
            let first = seed_node(&world);
            let nodes = join(&world, 199, &first);
            settle(120).await;
            let image = one_layer("churn", 13, 16);
            seed_image(&world, nodes[3].index, &image).await;
            settle(10).await;
            let entropy = velarx_p2p::entropy::Entropy::seeded(seed);
            // ten nodes stop (not the bootstrap peer, not the holder) and
            // come back ten seconds later under new identities
            for _ in 0..24 {
                let down: Vec<usize> = (0..10).map(|_| 5 + entropy.below(190)).collect();
                for &i in &down {
                    world.crash(i + 1)
                }
                tokio::time::sleep(Duration::from_secs(10)).await;
                for &i in &down {
                    world.restart_with_new_identity(i + 1)
                }
                tokio::time::sleep(Duration::from_secs(10)).await;
            }
            settle(180).await;
            let degrees = world.degrees();
            let alone = degrees.iter().filter(|d| **d == 0).count();
            let parts = components(&world);
            let askers: Vec<_> = nodes
                .iter()
                .step_by(10)
                .filter(|n| n.index != nodes[3].index)
                .collect();
            // (each at a time of its own in the next minute)
            let image = &image;
            let pulls = askers.iter().map(|n| {
                let delay = Duration::from_millis(entropy.below(60_000) as u64);
                async move {
                    tokio::time::sleep(delay).await;
                    pull(n, image).await
                }
            });
            let reports = futures::future::join_all(pulls).await;
            let from_peers = reports.iter().filter(|r| r.registry_chunks == 0).count();
            eprintln!(
                "seed {seed}: degrees {:?}, alone {alone}, components {:?}; {from_peers} of {} pulls came entirely from peers",
                spread(degrees),
                &parts[..parts.len().min(4)],
                reports.len()
            );
            assert_eq!(alone, 0);
            assert_eq!(parts, [200], "the swarm is in parts");
            assert!(
                from_peers * 10 >= reports.len() * 9,
                "only {from_peers} of {} came from peers",
                reports.len()
            );
        });
    }
}
