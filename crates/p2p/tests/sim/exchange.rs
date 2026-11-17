// SPDX-License-Identifier: Apache-2.0
//! Peers learnt from the peers a node has: a node a full bootstrap peer
//! refuses joins through what it is told.

use crate::common::*;
use velarx_p2p::peer_exchange::MAX_DIALS;
use velarx_p2p::sim::{self, NodeConfig};

/// `n` nodes name one bootstrap node, which holds 100 connections and lends 16
/// more for an exchange; none of them walks the DHT (`kad` off: only what the
/// peers tell it brings a node to others); the numbers after five minutes.
fn converge(n: usize, seed: u64, exchange: bool) -> (usize, usize, Vec<usize>) {
    sim::run(seed, |world| async move {
        let first = world.add_node(NodeConfig {
            kad: false,
            exchange,
            ..Default::default()
        });
        for _ in 0..n {
            world.add_node(NodeConfig {
                bootstrap: vec![first.index],
                kad: false,
                exchange,
                ..Default::default()
            });
        }
        settle(300).await;
        let degrees = world.degrees();
        let alone = degrees.iter().filter(|d| **d == 0).count();
        let (min, median, _) = spread(degrees);
        let mut parts = components(&world);
        parts.truncate(3);
        eprintln!(
            "{} nodes, exchange {exchange}, seed {seed}: alone {alone}, min degree {min}, \
             median {median}, components {parts:?}",
            n + 1
        );
        (alone, median, parts)
    })
}

#[test]
fn what_the_peers_tell_alone_brings_400_nodes_into_one_swarm() {
    for seed in sim::seeds(&[1, 2]) {
        let (alone, median, parts) = converge(399, seed, true);
        assert_eq!(alone, 0, "nodes with no peer at all (seed {seed})");
        assert_eq!(parts, [400], "the swarm is in parts (seed {seed})");
        assert!(
            median >= 8,
            "the median node has {median} peers (seed {seed})"
        );
    }
}

/// The control: without the exchange (and without Kademlia) the nodes the
/// bootstrap node refuses come back to it for ever.
#[test]
fn without_it_the_nodes_the_bootstrap_node_refuses_stay_alone() {
    let (alone, _, parts) = converge(399, 1, false);
    assert!(alone > 100, "{alone} nodes alone, components {parts:?}");
}

/// A newcomer dials the peers of one answer, not of an answer of every peer it
/// meets while those dials are under way: the peers it is dialing count as
/// peers it will have.  (Asking each peer it identified while it had few
/// made it dial eight for each, four times what it asked for, and fill its
/// outgoing connections, with no room left for the holders the DHT names.)
#[test]
fn a_newcomer_dials_the_peers_of_one_answer_not_of_each_peer_it_meets() {
    for seed in sim::seeds(&[1, 2]) {
        sim::run(seed, |world| async move {
            let first = world.add_node(NodeConfig {
                kad: false,
                ..Default::default()
            });
            for _ in 0..60 {
                world.add_node(NodeConfig {
                    bootstrap: vec![first.index],
                    kad: false,
                    ..Default::default()
                });
            }
            settle(120).await;
            let newcomer = world.add_node(NodeConfig {
                bootstrap: vec![first.index],
                kad: false,
                ..Default::default()
            });
            settle(60).await;
            let peers = newcomer.connections();
            eprintln!("seed {seed}: the newcomer has {peers} peers");
            assert!(peers > 4, "the newcomer has {peers} peers");
            assert!(
                peers <= 1 + MAX_DIALS,
                "the newcomer has {peers} peers: it dialed for more than one answer"
            );
        });
    }
}
