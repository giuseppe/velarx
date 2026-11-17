// SPDX-License-Identifier: Apache-2.0
//! The upload limit of a node is shared between those it serves.

use crate::common::*;
use std::time::Duration;
use velarx_p2p::provider::Transport;
use velarx_p2p::sim::{self, Behavior, Image, NodeConfig};
use velarx_p2p::Serving;

/// A seed with an upload limit serves a peer that pulls a big image and,
/// meanwhile, one that pulls a small one: the small one has its turns of
/// the credit beside the many requests of the big one, and is not left to
/// wait until the big one is done (it is not sent to the registry either).
#[test]
fn a_peer_that_asks_little_is_not_held_behind_one_that_asks_much() {
    for seed in sim::seeds(&[1, 2]) {
        sim::run(seed, |world| async move {
            // 8 MiB at 1 MB/s, and 256 KiB
            let big = Image::new("big", 41, 4, 32, 64 << 10);
            let small = Image::new("small", 42, 1, 4, 64 << 10);
            let seed_node = world.add_node(NodeConfig {
                serving: Serving {
                    upload_limit_mbit: 8,
                    ..Serving::default()
                },
                ..Default::default()
            });
            let heavy = world.add_node(NodeConfig {
                bootstrap: vec![seed_node.index],
                ..Default::default()
            });
            let light = world.add_node(NodeConfig {
                bootstrap: vec![seed_node.index],
                ..Default::default()
            });
            seed_image(&world, seed_node.index, &big).await;
            seed_image(&world, seed_node.index, &small).await;
            settle(30).await;
            // (the small pull a second after the big one)
            let (b, r) = tokio::join!(pull(&heavy, &big), async {
                settle(1).await;
                pull(&light, &small).await
            });
            eprintln!(
                "seed {seed}: the small pull took {:?} ({} chunks from the seed, {} from the registry); \
                 the big one {:?} ({} from the seed)",
                r.took(),
                r.peer_chunks,
                r.registry_chunks,
                b.took(),
                b.peer_chunks
            );
            assert!(
                b.took() > Duration::from_secs(5),
                "the upload limit did not hold the big pull: the scenario shows nothing"
            );
            assert_eq!(
                (r.peer_chunks, r.registry_chunks),
                (4, 0),
                "the small pull did not get its share of the seed"
            );
            assert!(
                r.took() < Duration::from_secs(2),
                "the small pull waited {:?} behind the big one",
                r.took()
            );
        });
    }
}

/// A node at its upload limit has all its QUIC slots held by requests that
/// wait for credit: the question whether it has a chunk carries no data and
/// is still answered (not "busy"), so the askers know where the layer is.
#[test]
fn a_node_at_its_upload_limit_still_answers_the_question_whether_it_has_a_chunk() {
    for seed in sim::seeds(&[1, 2]) {
        sim::run(seed, |world| async move {
            let big = Image::new("limit", 43, 1, 32, 64 << 10);
            let node = |bootstrap: Option<usize>, serving: Serving| NodeConfig {
                serving,
                // (the askers give nothing to each other: the seed is the one
                // that is asked)
                behavior: if bootstrap.is_some() {
                    Behavior::Busy
                } else {
                    Behavior::Honest
                },
                bootstrap: bootstrap.into_iter().collect(),
                ..Default::default()
            };
            // 1 Mbit/s: 2 MiB of chunks take 16 s to send
            let seed_node = world.add_node(node(
                None,
                Serving {
                    upload_limit_mbit: 1,
                    quic_slots: 8,
                    ..Serving::default()
                },
            ));
            let askers: Vec<_> = (0..24)
                .map(|_| world.add_node(node(Some(seed_node.index), Serving::default())))
                .collect();
            let prober = world.add_node(node(Some(seed_node.index), Serving::default()));
            seed_image(&world, seed_node.index, &big).await;
            settle(30).await;
            let digest = big.layers[0].chunks[0].0.clone();
            let (_, (full, probes)) = tokio::join!(
                futures::future::join_all(askers.iter().map(|n| pull(n, &big))),
                async {
                    // (while the requests of the askers wait for credit:
                    // they leave a seed this slow for the registry after a
                    // few seconds)
                    let (mut probes, mut full) = (Vec::new(), false);
                    for _ in 0..4 {
                        settle(1).await;
                        full |= seed_node.quic_slots_free() == 0;
                        probes.push(prober.transport().probe(seed_node.id(), &digest).await);
                    }
                    (full, probes)
                }
            );
            let busy = probes
                .iter()
                .filter(|p| matches!(p, Ok(velarx_p2p::Presence::Busy)))
                .count();
            eprintln!(
                "seed {seed}: slots all held {full}; of {} probes {busy} busy",
                probes.len()
            );
            assert!(
                full,
                "the slots were never full: the scenario shows nothing"
            );
            assert!(
                probes
                    .iter()
                    .all(|p| matches!(p, Ok(velarx_p2p::Presence::Has))),
                "the probes of a node at its upload limit: {probes:?}"
            );
        });
    }
}
