// SPDX-License-Identifier: Apache-2.0
//! A peer that cannot be reached over UDP is a member and not a data peer:
//! it is told once, it costs a pull the time of one connection attempt and
//! not of one for each request, the pull goes on to the peers that have a
//! path and then to the registry, and nothing is taken from it.

use crate::common::*;
use std::time::Duration;
use velarx_p2p::provider::Transport;
use velarx_p2p::sim::{self, NodeConfig};
use velarx_p2p::P2PError;

/// Holders behind a firewall that drops UDP, announcing the layer: the
/// asker gets nothing from them, takes the chunks from the registry, is
/// told (its status, its explanation) that they have no path, and the pull
/// is not held up by them for longer than the connection attempt.
#[test]
fn holders_without_a_udp_path_are_passed_over_for_the_registry() {
    for seed in sim::seeds(&[1, 2]) {
        sim::run(seed, |world| async move {
            let image = one_layer("udp", 21, 32);
            let layer = image.layers[0].digest.clone();
            let first = world.add_node(NodeConfig {
                udp: false,
                ..Default::default()
            });
            let holders: Vec<_> = (0..3)
                .map(|_| {
                    world.add_node(NodeConfig {
                        udp: false,
                        announce: true,
                        bootstrap: vec![first.index],
                        ..Default::default()
                    })
                })
                .collect();
            let asker = world.add_node(NodeConfig {
                bootstrap: vec![first.index],
                ..Default::default()
            });
            for h in &holders {
                seed_image(&world, h.index, &image).await;
            }
            settle(60).await;
            let without = asker.transport().without_quic().await;
            let r = pull(&asker, &image).await;
            eprintln!(
                "seed {seed}: {without} peers without a path; chunks from peers {}, from the registry {}, in {:?}",
                r.peer_chunks,
                r.registry_chunks,
                r.took()
            );
            assert!(
                without >= 3,
                "the status counts {without} peers without a path"
            );
            assert_eq!((r.peer_chunks, r.registry_chunks, r.wrong), (0, 32, 0));
            // (one attempt of 3 s to each peer that is asked, together: not
            // one for each of the 32 chunks)
            assert!(
                r.took() < Duration::from_secs(30),
                "the pull took {:?}",
                r.took()
            );
            assert!(considered(&asker, &layer, holders[0].id()));
            // the error names the peer and says why
            let e = asker
                .transport()
                .fetch(
                    holders[0].id(),
                    &[(image.layers[0].chunks[0].0.clone(), None)],
                )
                .await
                .unwrap_err();
            assert!(
                matches!(&e, P2PError::NoQuicPath { peer, .. } if *peer == holders[0].id()),
                "{e}"
            );
        });
    }
}

/// One holder has no path and another has: the chunks come from the one
/// that has, with nothing from the registry.
#[test]
fn a_holder_with_a_path_serves_beside_one_without() {
    for seed in sim::seeds(&[1, 2]) {
        sim::run(seed, |world| async move {
            let image = one_layer("udp2", 22, 32);
            let first = seed_node(&world);
            let blocked = world.add_node(NodeConfig {
                udp: false,
                announce: true,
                bootstrap: vec![first.index],
                ..Default::default()
            });
            let open = world.add_node(NodeConfig {
                announce: true,
                bootstrap: vec![first.index],
                ..Default::default()
            });
            let asker = world.add_node(NodeConfig {
                bootstrap: vec![first.index],
                ..Default::default()
            });
            seed_image(&world, blocked.index, &image).await;
            seed_image(&world, open.index, &image).await;
            settle(60).await;
            let r = pull(&asker, &image).await;
            eprintln!(
                "seed {seed}: chunks from peers {}, from the registry {}",
                r.peer_chunks, r.registry_chunks
            );
            assert_eq!(
                (r.peer_chunks, r.registry_chunks, r.wrong),
                (32, 0, 0),
                "the holder with a path did not serve what the one without could not"
            );
        });
    }
}
