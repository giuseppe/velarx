// SPDX-License-Identifier: Apache-2.0
//! The same seed is the same run: what makes a failure something to debug.

use crate::common::*;
use velarx_p2p::sim::{self, Behavior, NodeConfig};

/// A small swarm, a pull among liars, a crash: the whole trace and what it
/// came to.
fn run(seed: u64) -> (Vec<String>, Vec<usize>, usize) {
    sim::run(seed, |world| async move {
        let image = one_layer("repeat", 5, 16);
        let first = seed_node(&world);
        let nodes = join(&world, 30, &first);
        nodes[4].set_behavior(Behavior::Corrupt);
        nodes[5].set_behavior(Behavior::Silent);
        settle(60).await;
        seed_image(&world, nodes[7].index, &image).await;
        let extra = world.add_node(NodeConfig {
            bootstrap: vec![first.index],
            ..Default::default()
        });
        settle(30).await;
        world.crash(9);
        let r = pull(&extra, &image).await;
        settle(120).await;
        (
            world.trace.tail(100_000),
            world.degrees(),
            r.registry_chunks,
        )
    })
}

#[test]
fn a_seed_repeats_the_run_to_the_last_event_and_another_seed_does_not() {
    let (a, b, c) = (run(42), run(42), run(43));
    assert!(!a.0.is_empty());
    assert_eq!(a, b, "the same seed gave two runs");
    assert_ne!(a.0, c.0, "two seeds gave the same run");
}
