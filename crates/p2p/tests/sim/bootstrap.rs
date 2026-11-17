// SPDX-License-Identifier: Apache-2.0
//! A node that the one bootstrap peer cannot hold still joins the swarm.

use crate::common::*;
use velarx_p2p::sim::{self, NodeConfig};

/// `n` nodes name one bootstrap node (which holds 100 connections and lends
/// 16 more for an exchange); the numbers after five minutes.
fn converge(n: usize, seed: u64, min_peers: usize) -> (usize, (usize, usize, usize), Vec<usize>) {
    sim::run(seed, |world| async move {
        let first = seed_node(&world);
        let nodes: Vec<_> = (0..n)
            .map(|_| {
                world.add_node(NodeConfig {
                    bootstrap: vec![first.index],
                    min_peers,
                    ..Default::default()
                })
            })
            .collect();
        settle(300).await;
        let degrees = world.degrees();
        let alone = degrees.iter().filter(|d| **d == 0).count();
        let mut parts = components(&world);
        parts.truncate(3);
        eprintln!(
            "{} nodes, min_peers {min_peers}, seed {seed}: alone {alone}, degrees {:?}, components {parts:?}",
            nodes.len() + 1,
            spread(degrees.clone()),
        );
        (alone, spread(degrees), parts)
    })
}

#[test]
fn one_bootstrap_node_brings_160_400_and_1000_nodes_into_one_swarm() {
    for seed in sim::seeds(&[1, 2]) {
        for n in [159, 399, 999] {
            let (alone, (min, median, _), parts) = converge(n, seed, 4);
            assert_eq!(alone, 0, "{n}: nodes with no peer at all (seed {seed})");
            assert_eq!(parts, [n + 1], "{n}: the swarm is in parts (seed {seed})");
            assert!(min >= 4, "{n}: a node with {min} peers (seed {seed})");
            assert!(
                median >= 20,
                "{n}: the median node has {median} peers (seed {seed})"
            );
        }
    }
}

/// The control: with the retry off a node that the bootstrap node refuses
/// when it is full is alone for ever, and the scenario sees it.
#[test]
fn without_the_retry_the_nodes_a_full_bootstrap_node_refuses_stay_alone() {
    let (alone, _, parts) = converge(399, 1, 0);
    assert!(alone > 100, "{alone} nodes alone, components {parts:?}");
}
