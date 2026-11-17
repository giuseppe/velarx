// SPDX-License-Identifier: Apache-2.0
//! What the nodes know of each other's layers: the probes a pull makes in a
//! swarm of a thousand nodes.

use crate::common::*;
use sha2::Digest as _;
use std::sync::atomic::Ordering::Relaxed;
use std::sync::Arc;
use velarx_p2p::sim::{self, Image, Node, Puller};

/// A pull in a swarm of 1000 nodes of which 12 hold the image: how many
/// probes the swarm answered, and where the chunks came from.
#[test]
fn a_pull_in_a_swarm_of_1000_asks_the_holders_not_the_peers() {
    for (seed, held) in sim::seeds(&[1, 2, 3])
        .into_iter()
        .flat_map(|s| [(s, true), (s, false)])
    {
        sim::run(seed, |world| async move {
            let image = Image::new("thousand", 11, 4, 32, 64 << 10);
            let first = seed_node(&world);
            let nodes: Vec<Arc<Node>> = join(&world, 999, &first);
            settle(180).await;
            let victim = nodes[500].clone();
            let neighbours = victim.connected();
            // (a few of the holders are neighbours of the victim, as in a
            // swarm where the image is on 1% of the nodes)
            let mut holders = 0;
            for n in nodes.iter().filter(|n| n.index != victim.index).step_by(83) {
                if held {
                    seed_image(&world, n.index, &image).await;
                    holders += 1;
                }
            }
            let near = nodes
                .iter()
                .filter(|n| neighbours.contains(&n.id()))
                .filter(|n| n.store.has_layer(&image.layers[0].digest))
                .count();
            settle(60).await;
            let probed = |nodes: &[Arc<Node>]| -> u64 {
                nodes
                    .iter()
                    .map(|n| n.live().counters.probed.load(Relaxed))
                    .sum()
            };
            let before = probed(&nodes);
            let r = Puller::default().pull(&victim, &image).await;
            let groups = image.layers.len() * 32usize.div_ceil(Puller::default().group_items);
            let sent = probed(&nodes) - before;
            eprintln!(
                "seed {seed}: {sent} probes for {groups} groups of {} layers ({holders} holders, {near} of them neighbours, {} peers); chunks from peers {} registry {} in {:?}",
                image.layers.len(),
                neighbours.len(),
                r.peer_chunks,
                r.registry_chunks,
                r.took()
            );
            assert_eq!((r.chunks, r.wrong), (128, 0));
            // (what the filters said is the answer: no peer is probed, and
            // a layer nobody holds goes to the registry at once)
            assert_eq!(sent, 0, "a peer with a filter was probed");
            assert_eq!(
                r.registry_chunks == 0,
                held,
                "{held}: {}",
                r.registry_chunks
            );
        });
    }
}

/// A swarm of `n` nodes, two of which hold `image`, and the node that pulls.
async fn swarm(
    world: &Arc<velarx_p2p::sim::World>,
    n: usize,
    image: &Image,
) -> (Arc<Node>, Vec<Arc<Node>>) {
    let first = seed_node(world);
    let nodes = join(world, n, &first);
    seed_image(world, nodes[3].index, image).await;
    seed_image(world, nodes[9].index, image).await;
    settle(60).await;
    (nodes[n - 1].clone(), nodes)
}

/// A holder that says it holds nothing is not asked, which costs the swarm
/// nothing but that one holder; the other holder gives the layers.
#[test]
fn a_holder_that_claims_nothing_is_not_asked_and_the_layers_come_from_another() {
    for seed in sim::seeds(&[1, 2]) {
        sim::run(seed, |world| async move {
            let image = Image::new("nothing", 23, 4, 32, 64 << 10);
            let (victim, nodes) = swarm(&world, 40, &image).await;
            let (silent, other) = (&nodes[3], &nodes[9]);
            // (an empty filter under a version after the one it told)
            let mut empty = velarx_p2p::filter::Advertiser::new(
                Default::default(),
                velarx_p2p::entropy::Entropy::seeded(5),
            );
            silent.live().advertisement.with(|a| {
                let _ = a.remove(&a.not_in(&[]));
            });
            let message = silent.live().advertisement.with(|a| a.update());
            silent.tell_all(message.or_else(|| empty.full()).unwrap());
            settle(5).await;
            let served = |n: &Arc<Node>| n.live().counters.served.load(Relaxed);
            let r = Puller::default().pull(&victim, &image).await;
            eprintln!(
                "seed {seed}: served by the silent holder {}, by the other {}; chunks from peers {} registry {}",
                served(silent),
                served(other),
                r.peer_chunks,
                r.registry_chunks
            );
            assert_eq!((r.chunks, r.wrong), (128, 0));
            if victim.connected().contains(&silent.id()) {
                assert_eq!(
                    served(silent),
                    0,
                    "a peer that said it holds nothing was asked"
                );
            }
        });
    }
}

/// A node that pulls 50 layers tells its peers once, not 50 times.
#[test]
fn a_node_that_pulls_many_layers_sends_one_update() {
    sim::run(1, |world| async move {
        let image = Image::new("storm", 24, 50, 2, 16 << 10);
        let first = seed_node(&world);
        let nodes = join(&world, 6, &first);
        settle(60).await;
        // an honest node completes 50 layers within a second: its peers are
        // told once (a delta of 50 keys or the filter, not 50 messages)
        let honest = &nodes[5];
        let before = honest.live().advertisement.with(|a| a.own().sent);
        for layer in &image.layers {
            world.seed_layer(honest.index, layer).await;
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        settle(10).await;
        let sent = honest.live().advertisement.with(|a| a.own().sent);
        eprintln!(
            "50 layers in half a second: {} messages ({} bytes) for {} peers",
            sent.fulls + sent.deltas - before.fulls - before.deltas,
            sent.bytes - before.bytes,
            honest.connected().len()
        );
        assert!(sent.fulls + sent.deltas - before.fulls - before.deltas <= 2);
    });
}

/// What the filters say of a layer that nobody holds is "maybe" as often as
/// the rate they were sized for says, and never "no" for one that is held;
/// and what they take.
#[test]
fn the_filters_say_maybe_to_a_layer_nobody_holds_at_the_rate_they_are_sized_for() {
    sim::run(1, |world| async move {
        let first = seed_node(&world);
        let nodes = join(&world, 60, &first);
        settle(120).await;
        // every node holds 2000 layers of its own
        let layer = |node: usize, i: usize| {
            format!(
                "sha256:{}",
                hex::encode(sha2::Sha256::digest(format!("{node}/{i}").as_bytes()))
            )
        };
        for n in &nodes {
            let held: Vec<String> = (0..2000).map(|i| layer(n.index, i)).collect();
            n.live().advertisement.add(&held);
        }
        settle(30).await;
        let victim = &nodes[30];
        let peers = victim.connected().len();
        let knowledge = victim.live().source.knowledge().clone();
        let total = knowledge.filter_infos().len();
        let held = nodes
            .iter()
            .filter(|n| victim.connected().contains(&n.id()))
            .map(|n| (n.id(), n.index))
            .collect::<Vec<_>>();
        // no false negative: what a peer holds is a "maybe" from it
        for (id, index) in &held {
            for i in (0..2000).step_by(97) {
                assert!(knowledge.filtered(&layer(*index, i)).maybe.contains(id));
            }
        }
        // the rate: layers nobody holds
        let tests = 3000;
        let maybes: usize = (0..tests)
            .map(|i| knowledge.filtered(&layer(100_000, i)).maybe.len())
            .sum();
        let rate = maybes as f64 / (tests * total) as f64;
        let bytes: usize = knowledge.filter_infos().values().map(|f| f.bytes).sum();
        eprintln!(
            "{total} filters of {peers} peers, 2000 layers each: measured rate {rate:.4} (configured 0.01); {} bytes a peer; {bytes} bytes in all",
            bytes / total
        );
        assert!(rate > 0.001 && rate <= 0.015, "{rate}");
    });
}

/// The bytes a node sends to each peer follow the layers it holds.
#[test]
fn what_a_node_sends_for_its_filter_follows_its_layers() {
    let sized = |layers: usize| {
        let mut a = velarx_p2p::filter::Advertiser::new(
            Default::default(),
            velarx_p2p::entropy::Entropy::seeded(1),
        );
        let held: Vec<String> = (0..layers)
            .map(|i: usize| {
                format!(
                    "sha256:{}",
                    hex::encode(sha2::Sha256::digest(i.to_le_bytes()))
                )
            })
            .collect();
        a.add(&held);
        a.update();
        a.own().bytes
    };
    let config = velarx_p2p::filter::Config::default();
    for layers in [500usize, 5000, 50_000] {
        let one = sized(layers);
        eprintln!(
            "{layers} layers: {one} bytes a peer; 150 peers {} KiB, 1000 peers {} KiB, 10000 peers {} KiB",
            (one * 150) >> 10,
            (one * 1000) >> 10,
            (one * 10_000) >> 10,
        );
        assert!(one <= config.max_bytes);
    }
}
