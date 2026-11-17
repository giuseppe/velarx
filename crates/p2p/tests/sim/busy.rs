// SPDX-License-Identifier: Apache-2.0
//! A seed with no room is not a seed without the layer.

use crate::common::*;
use std::time::Duration;
use velarx_p2p::sim::{self, Behavior, NodeConfig};

fn node(bootstrap: Option<usize>) -> NodeConfig {
    NodeConfig {
        store_latency: Duration::from_millis(300),
        bootstrap: bootstrap.into_iter().collect(),
        ..Default::default()
    }
}

#[test]
fn a_seed_that_had_no_room_is_asked_again_and_not_taken_for_one_without_the_layer() {
    for seed in sim::seeds(&[1, 2]) {
        sim::run(seed, |world| async move {
            let image = one_layer("hot", 5, 32);
            let layer = image.layers[0].digest.clone();
            let seed_node = world.add_node(node(None));
            let herd: Vec<_> = (0..30)
                .map(|_| world.add_node(node(Some(seed_node.index))))
                .collect();
            seed_image(&world, seed_node.index, &image).await;
            settle(60).await;
            // the seed answers every request and probe "no room"
            seed_node.set_behavior(Behavior::Busy);
            let reports = futures::future::join_all(herd.iter().map(|n| pull(n, &image))).await;
            let lacking = herd
                .iter()
                .filter(|n| n.live().source.knowledge().lacks(&layer, &seed_node.id()))
                .count();
            let registry: usize = reports.iter().map(|r| r.registry_chunks).sum();
            eprintln!("seed {seed}: chunks from the registry {registry}; nodes that think the seed lacks the layer: {lacking}");
            assert!(reports.iter().all(|r| r.wrong == 0 && r.chunks == 32));
            assert_eq!(
                lacking, 0,
                "a busy seed was remembered as one without the layer"
            );
            // once it has room the seed serves again: the nodes that were
            // told "no room" have not forgotten it
            seed_node.set_behavior(Behavior::Honest);
            let again = one_layer("again", 6, 32);
            seed_image(&world, seed_node.index, &again).await;
            settle(65).await;
            let reports =
                futures::future::join_all(herd[..8].iter().map(|n| pull(n, &again))).await;
            let registry: usize = reports.iter().map(|r| r.registry_chunks).sum();
            assert!(reports.iter().all(|r| r.wrong == 0));
            assert!(
                registry * 4 <= 8 * 32,
                "after the load the seed still gave little: {registry} of 256 chunks from the registry"
            );
        });
    }
}
