// SPDX-License-Identifier: Apache-2.0
//! A rollout: one image to many nodes, the registry as the first source.

use crate::common::*;
use std::time::Duration;
use velarx_p2p::sim::{self, Image, NodeConfig};

const REGISTRY_RATE: u64 = 8 << 20;

fn node(bootstrap: Option<usize>) -> NodeConfig {
    NodeConfig {
        up: 12 << 20,
        down: 12 << 20,
        bootstrap: bootstrap.into_iter().collect(),
        ..Default::default()
    }
}

/// N nodes start the pull of one image at the same moment: nobody has it, so
/// the peers cannot do much, and they must not do harm.
#[test]
fn a_rollout_started_at_once_costs_the_registry_no_more_than_without_peers() {
    for seed in sim::seeds(&[1]) {
        for n in [50usize, 200] {
            sim::run(seed, |world| async move {
                let image = Image::new("rollout", 3, 4, 16, 64 << 10);
                world.set_registry_rate(REGISTRY_RATE);
                let first = world.add_node(node(None));
                let nodes: Vec<_> = (0..n)
                    .map(|_| world.add_node(node(Some(first.index))))
                    .collect();
                settle(120).await;
                let t0 = tokio::time::Instant::now();
                let reports =
                    futures::future::join_all(nodes.iter().map(|n| pull(n, &image))).await;
                let took = t0.elapsed();
                let registry: u64 = reports.iter().map(|r| r.registry_bytes).sum();
                let peers: u64 = reports.iter().map(|r| r.peer_bytes).sum();
                let without = image.bytes() * n as u64;
                let alone = Duration::from_secs_f64(without as f64 / REGISTRY_RATE as f64);
                eprintln!(
                    "{n} nodes at once: registry {} MiB, peers {} MiB (without peers: registry {} MiB); done in {took:?} (registry alone {alone:?})",
                    registry >> 20, peers >> 20, without >> 20
                );
                assert!(
                    reports.iter().all(|r| r.chunks == 64 && r.wrong == 0),
                    "every node has the image"
                );
                assert!(
                    registry <= without,
                    "the registry gave more than it would without peers"
                );
                assert!(
                    took <= alone.mul_f64(1.1),
                    "peers slowed the rollout: {took:?} for {alone:?}"
                );
            });
        }
    }
}

/// The same image in waves: what the first wave has, the next ones take from
/// it, and the registry sees a part of the load.
#[test]
fn a_rollout_in_waves_is_served_by_the_nodes_that_have_the_image() {
    for seed in sim::seeds(&[1]) {
        sim::run(seed, |world| async move {
            let image = Image::new("rollout", 3, 4, 16, 64 << 10);
            world.set_registry_rate(REGISTRY_RATE);
            let first = world.add_node(node(None));
            let nodes: Vec<_> = (0..200)
                .map(|_| world.add_node(node(Some(first.index))))
                .collect();
            settle(120).await;
            let mut fractions = Vec::new();
            for wave in nodes.chunks(50) {
                let reports = futures::future::join_all(wave.iter().map(|n| pull(n, &image))).await;
                let registry: u64 = reports.iter().map(|r| r.registry_bytes).sum();
                let total = image.bytes() * wave.len() as u64;
                fractions.push(registry as f64 / total as f64);
                settle(30).await;
            }
            eprintln!("share of each wave that came from the registry: {fractions:.2?}");
            assert!(
                fractions[0] > 0.9,
                "the first wave has nobody to ask: {fractions:?}"
            );
            assert!(
                *fractions.last().unwrap() < 0.1,
                "the last wave still went to the registry: {fractions:?}"
            );
        });
    }
}
