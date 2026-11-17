// SPDX-License-Identifier: Apache-2.0
//! A layer that one node holds is found by nodes that are not its neighbours.

use crate::common::*;
use std::sync::Arc;
use std::time::Duration;
use velarx_p2p::sim::{self, Node, NodeConfig, Puller};

#[test]
fn a_layer_one_node_holds_is_found_in_a_swarm_of_400() {
    for seed in sim::seeds(&[1, 2]) {
        sim::run(seed, |world| async move {
            let first = seed_node(&world);
            let nodes = join(&world, 399, &first);
            settle(120).await;
            let image = one_layer("one-holder", 7, 16);
            let holder = &nodes[200];
            seed_image(&world, holder.index, &image).await;
            // (the record is in the DHT after a few seconds)
            settle(30).await;
            let neighbours = holder.connected();
            // a hundred nodes that are not neighbours of the holder ask,
            // each at a time of its own in the next minute
            let entropy = velarx_p2p::entropy::Entropy::seeded(seed);
            let askers: Vec<_> = nodes
                .iter()
                .filter(|n| n.index != holder.index && !neighbours.contains(&n.id()))
                .step_by(3)
                .take(100)
                .cloned()
                .collect();
            let image = &image;
            let pulls = askers.iter().map(|n| {
                let delay = Duration::from_millis(entropy.below(60_000) as u64);
                async move {
                    tokio::time::sleep(delay).await;
                    pull(n, image).await
                }
            });
            let reports = futures::future::join_all(pulls).await;
            let found = reports.iter().filter(|r| r.registry_chunks == 0).count();
            eprintln!(
                "seed {seed}: {found} of {} nodes that are not neighbours of the holder got the layer from peers; DHT lookups {}",
                reports.len(),
                world.dht.lookups()
            );
            // before the DHT's providers were dialed, 24 of 100 (the neighbours)
            assert!(
                found * 10 >= reports.len() * 9,
                "only {found} of {} found the layer",
                reports.len()
            );
            assert!(world.dht.lookups() > 0, "the DHT was never asked");
            assert!(reports.iter().all(|r| r.wrong == 0));
        });
    }
}

/// The groups of one layer under way at the same time ask the DHT once, not
/// each for itself: whoever comes while the walk runs waits for its answer.
#[test]
fn the_groups_of_a_layer_share_one_lookup_of_the_dht() {
    for seed in sim::seeds(&[1, 2]) {
        sim::run(seed, |world| async move {
            let first = seed_node(&world);
            let nodes = join(&world, 119, &first);
            settle(120).await;
            let image = one_layer("shared", 8, 32);
            // (a node with room to dial)
            let asker = world.add_node(NodeConfig {
                bootstrap: vec![first.index],
                max_outgoing: 80,
                ..Default::default()
            });
            settle(60).await;
            // (a holder that is not one of its peers)
            let holder = not_a_neighbour(&nodes, &asker);
            seed_image(&world, holder.index, &image).await;
            settle(30).await;
            assert!(!asker.connected().contains(&holder.id()));
            let asker = &asker;
            // eight groups of four chunks, all at once
            let puller = Puller {
                group_items: 4,
                groups_at_once: 8,
                ..Puller::default()
            };
            let before = world.dht.lookups();
            let r = puller.pull(asker, &image).await;
            let lookups = world.dht.lookups() - before;
            eprintln!(
                "seed {seed}: {lookups} lookups for 8 groups; from peers {} from the registry {}",
                r.peer_chunks, r.registry_chunks
            );
            assert_eq!(lookups, 1, "each group walked the DHT for itself");
            assert_eq!(
                r.registry_chunks, 0,
                "the holder the DHT named was not used"
            );
            assert_eq!(r.wrong, 0);
        });
    }
}

/// A walk that the cap of 3 seconds cut off is kept as an empty answer for a
/// moment: the groups that come after it do not walk again, and the layer
/// comes from the registry.
#[test]
fn a_lookup_cut_off_by_the_cap_is_not_asked_again_by_each_group() {
    for seed in sim::seeds(&[1, 2]) {
        sim::run(seed, |world| async move {
            let first = seed_node(&world);
            let nodes = join(&world, 119, &first);
            settle(120).await;
            let image = one_layer("slow-dht", 9, 32);
            // (a node with room to dial)
            let asker = world.add_node(NodeConfig {
                bootstrap: vec![first.index],
                max_outgoing: 80,
                ..Default::default()
            });
            settle(60).await;
            // (a holder that is not one of its peers)
            let holder = not_a_neighbour(&nodes, &asker);
            seed_image(&world, holder.index, &image).await;
            settle(30).await;
            // a walk of 3000 trips (about 12 s) takes far more than the cap
            *world.dht.lookup_trips.lock().unwrap() = 3000;
            assert!(!asker.connected().contains(&holder.id()));
            let asker = &asker;
            let puller = Puller {
                group_items: 4,
                groups_at_once: 4,
                ..Puller::default()
            };
            let before = world.dht.lookups();
            let r = puller.pull(asker, &image).await;
            let lookups = world.dht.lookups() - before;
            eprintln!(
                "seed {seed}: {lookups} lookups for 8 groups; from peers {} from the registry {} in {:?}",
                r.peer_chunks, r.registry_chunks, r.took()
            );
            assert_eq!(r.chunks, 32);
            assert!(
                r.took() >= Duration::from_secs(3),
                "the walk was not cut off"
            );
            assert_eq!(lookups, 1, "the groups walked the DHT again after the cap");
        });
    }
}

/// A node of `nodes` (from the middle on) that `asker` is not connected to.
fn not_a_neighbour<'a>(nodes: &'a [Arc<Node>], asker: &Node) -> &'a Arc<Node> {
    let neighbours = asker.connected();
    nodes[nodes.len() / 2..]
        .iter()
        .chain(&nodes[..nodes.len() / 2])
        .find(|n| !neighbours.contains(&n.id()))
        .expect("the asker is connected to every node")
}
