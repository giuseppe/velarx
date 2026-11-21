// SPDX-License-Identifier: Apache-2.0
//! A peer whose store is damaged sends what it holds: the asker's checks
//! refuse it.

use crate::common::*;
use velarx_p2p::explain::{Event, Outcome};
use velarx_p2p::sim::{self, NodeConfig};

/// A peer that announced a layer whose chunks in its store are not what
/// they are named by sends them as it holds them: the asker's check of each
/// chunk refuses them, and the chunks come from the other peer that has it.
#[test]
fn the_chunks_of_a_damaged_store_are_refused_by_the_asker() {
    for seed in sim::seeds(&[1, 2]) {
        {
            sim::run(seed, |world| async move {
                let image = one_layer("damaged", 31, 32);
                let layer = image.layers[0].digest.clone();
                let damaged = world.add_node(NodeConfig {
                    announce: true,
                    ..Default::default()
                });
                // (the holder tells no filter: the damaged peer, whose
                // filter names the layer, is asked first)
                let holder = world.add_node(NodeConfig {
                    bootstrap: vec![damaged.index],
                    filter: velarx_p2p::filter::Config {
                        advertise: false,
                        ..Default::default()
                    },
                    ..Default::default()
                });
                let asker = world.add_node(NodeConfig {
                    bootstrap: vec![damaged.index, holder.index],
                    ..Default::default()
                });
                settle(30).await;
                seed_image(&world, holder.index, &image).await;
                seed_image(&world, damaged.index, &image).await;
                damaged.store.damage(&image.layers[0]);
                settle(5).await;
                let r = pull(&asker, &image).await;
                // (what each request to the damaged peer came to)
                let outcomes: Vec<Outcome> = asker
                    .live()
                    .source
                    .decisions()
                    .about(&layer, &[])
                    .iter()
                    .flat_map(|d| d.events.clone())
                    .filter_map(|e| match e {
                        Event::Asked { peer, outcome, .. } if peer == damaged.id() => Some(outcome),
                        _ => None,
                    })
                    .collect();
                eprintln!(
                    "seed {seed}: the requests to the damaged peer came to {outcomes:?}; \
                     chunks from peers {}, from the registry {}",
                    r.peer_chunks, r.registry_chunks
                );
                assert!(
                    !outcomes.is_empty(),
                    "the damaged peer was not asked: the scenario shows nothing"
                );
                // (it sent none that matched)
                assert!(
                    outcomes.iter().all(|o| matches!(o, Outcome::Lacks)),
                    "a damaged chunk was taken: {outcomes:?}"
                );
                assert_eq!(r.wrong, 0);
                assert_eq!(
                    (r.peer_chunks, r.registry_chunks),
                    (32, 0),
                    "the chunks did not come from the peer that has them"
                );
            });
        }
    }
}
