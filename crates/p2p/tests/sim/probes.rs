// SPDX-License-Identifier: Apache-2.0
//! What a node asks the peers that told it no filter of their layers whether
//! they have a chunk: the groups of a layer share what is asked, and the node
//! asks only so many a second whatever the number of layers.  (Peers that
//! tell a filter are not probed: `filter.rs`.)

use crate::common::*;
use std::sync::atomic::Ordering::Relaxed;
use std::sync::Arc;
use velarx_p2p::sim::{self, Image, Node, NodeConfig, Puller};

/// A node that tells no filter of its layers, so the peers probe it.
fn no_filter(bootstrap: Option<usize>, store_latency: std::time::Duration) -> NodeConfig {
    NodeConfig {
        filter: velarx_p2p::filter::Config {
            advertise: false,
            ..Default::default()
        },
        store_latency,
        bootstrap: bootstrap.into_iter().collect(),
        ..Default::default()
    }
}

/// A swarm of `n` honest nodes (none tells a filter), two of which hold
/// `image`; the node that pulls is another one.
fn swarm(world: &Arc<velarx_p2p::sim::World>, n: usize) -> (Arc<Node>, Vec<Arc<Node>>) {
    let first = world.add_node(no_filter(None, std::time::Duration::ZERO));
    let nodes: Vec<Arc<Node>> = (0..n)
        .map(|_| world.add_node(no_filter(Some(first.index), std::time::Duration::ZERO)))
        .collect();
    (nodes[n - 1].clone(), nodes)
}

/// Every probe that reached a node of the swarm.
fn probes(nodes: &[Arc<Node>]) -> u64 {
    nodes
        .iter()
        .map(|n| n.live().counters.probed.load(Relaxed))
        .sum()
}

/// The four groups of a layer that the engine runs at once find no filter
/// that names a holder, and each would ask a round of probes (8 peers) and a second
/// one: with the round shared, the layer costs the first round and the
/// second at most, not four times as many.
#[test]
fn the_groups_of_a_layer_share_the_probes() {
    for seed in sim::seeds(&[1, 2]) {
        sim::run(seed, |world| async move {
            let image = one_layer("probes", 5, 128);
            let (victim, nodes) = swarm(&world, 40);
            seed_image(&world, nodes[3].index, &image).await;
            seed_image(&world, nodes[9].index, &image).await;
            settle(60).await;
            let before = probes(&nodes);
            let r = Puller {
                group_items: 8,
                groups_at_once: 4,
                ..Default::default()
            }
            .pull(&victim, &image)
            .await;
            let sent = probes(&nodes) - before;
            eprintln!(
                "seed {seed}: {sent} probes for 16 groups of a layer; chunks from peers {} registry {}",
                r.peer_chunks, r.registry_chunks
            );
            assert_eq!((r.chunks, r.wrong), (128, 0));
            assert_eq!(r.registry_chunks, 0, "the holders gave the layer");
            // two rounds of 8 at most: what the first group asks, the other
            // three took
            assert!(
                sent <= 16,
                "{sent} probes for one layer: groups probed alone"
            );
        });
    }
}

/// A node that pulls 50 layers at once asks the swarm for each of them: no
/// peer is asked more than `probes::PER_PEER` questions at once (the slots a
/// peer answers them in) when the peers tell no filter, and not more
/// streams of requests than `probes::STREAMS_PER_PEER` when they do (a peer
/// is not told "no room" by the requests of one node, each spread over the
/// lanes of `quic_streams`), every layer gets its answer, and
/// the layers come from the two holders.  (A peer takes 50 ms to answer, so
/// that what it is asked at once shows.)
#[test]
fn a_node_pulling_many_layers_asks_a_peer_so_many_at_once() {
    for (seed, filters) in sim::seeds(&[1, 2])
        .into_iter()
        .flat_map(|s| [(s, false), (s, true)])
    {
        sim::run(seed, |world| async move {
            let image = Image::new("many", 6, 50, 4, 64 << 10);
            let latency = std::time::Duration::from_millis(50);
            let first = world.add_node(NodeConfig {
                store_latency: latency,
                ..no_filter(None, latency)
            });
            let nodes: Vec<Arc<Node>> = (0..40)
                .map(|_| {
                    let mut cfg = no_filter(Some(first.index), latency);
                    cfg.filter.advertise = filters;
                    world.add_node(cfg)
                })
                .collect();
            let victim = nodes[39].clone();
            for layer in &image.layers {
                world.seed_layer(nodes[3].index, layer).await;
                world.seed_layer(nodes[9].index, layer).await;
            }
            settle(60).await;
            let before = probes(&nodes);
            let t0 = tokio::time::Instant::now();
            let r = Puller {
                layers_at_once: 50,
                ..Default::default()
            }
            .pull(&victim, &image)
            .await;
            let took = t0.elapsed();
            let sent = probes(&nodes) - before;
            let most = nodes
                .iter()
                .map(|n| n.live().counters.probing_most.load(Relaxed))
                .max()
                .unwrap_or(0);
            let refused: u64 = nodes
                .iter()
                .map(|n| n.live().counters.refused.load(Relaxed))
                .sum();
            eprintln!(
                "seed {seed}, filters {filters}: {sent} probes for 50 layers in {took:?}, at most {most} at once to a peer, {refused} requests with no room; chunks from peers {} registry {}",
                r.peer_chunks, r.registry_chunks
            );
            assert_eq!((r.chunks, r.wrong), (200, 0));
            assert!(
                most as usize <= velarx_p2p::probes::PER_PEER,
                "{most} probes at once to one peer"
            );
            if filters {
                assert_eq!(sent, 0, "a peer with a filter was probed");
                assert_eq!(refused, 0, "a request was told there is no room");
                assert_eq!(r.registry_chunks, 0);
            } else {
                assert!(
                    r.peer_chunks >= 150,
                    "{} of 200 chunks from the registry though two peers held them all",
                    r.registry_chunks
                );
            }
        });
    }
}
