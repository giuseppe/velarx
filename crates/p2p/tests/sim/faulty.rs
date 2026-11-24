// SPDX-License-Identifier: Apache-2.0
//! Peers that stay silent, are slow or send wrong bytes (a damaged store): what
//! a node accepts is still right, and the layer comes from a peer that has it.

use crate::common::*;
use std::time::Duration;
use velarx_p2p::sim::{self, Behavior, NodeConfig};

/// A peer that says it has the layer and never answers does not hold a
/// pull that another peer can serve.
#[test]
fn a_provider_that_never_answers_is_passed_over_for_one_that_does() {
    for seed in sim::seeds(&[1]) {
        sim::run(seed, |world| async move {
            let image = one_layer("silent", 21, 32);
            let layer = image.layers[0].digest.clone();
            let announcing = || NodeConfig {
                announce: true,
                ..Default::default()
            };
            let silent = world.add_node(NodeConfig {
                behavior: Behavior::Silent,
                ..announcing()
            });
            let holder = world.add_node(NodeConfig {
                bootstrap: vec![silent.index],
                ..announcing()
            });
            let asker = world.add_node(NodeConfig {
                bootstrap: vec![silent.index],
                ..announcing()
            });
            settle(30).await;
            seed_image(&world, holder.index, &image).await;
            silent.announce_falsely(&[layer]).await;
            settle(5).await;
            let t0 = tokio::time::Instant::now();
            let r = pull(&asker, &image).await;
            eprintln!(
                "seed {seed}: the silent peer was passed over: peers {} registry {} in {:?}",
                r.peer_chunks,
                r.registry_chunks,
                t0.elapsed()
            );
            assert_eq!(r.registry_chunks, 0, "the honest peer was not used");
            assert!(
                t0.elapsed() < Duration::from_secs(5),
                "waited {:?} for the silent peer",
                t0.elapsed()
            );
        });
    }
}

/// Peers that claim a layer and answer with bytes that are not its chunks:
/// the chunks that are kept are right, and the layer comes from the honest
/// peer that has it, not from the registry.
#[test]
fn chunks_a_peer_sends_that_are_not_the_chunks_are_not_kept() {
    for seed in sim::seeds(&[1, 2]) {
        sim::run(seed, |world| async move {
            let image = one_layer("wrong", 23, 32);
            let layer = image.layers[0].digest.clone();
            let hub = world.add_node(NodeConfig::default());
            let liars: Vec<_> = (0..3)
                .map(|_| {
                    world.add_node(NodeConfig {
                        bootstrap: vec![hub.index],
                        behavior: Behavior::Corrupt,
                        ..Default::default()
                    })
                })
                .collect();
            // (the holder tells no filter: the liars, whose filters name the
            // layer, are asked first)
            let holder = world.add_node(NodeConfig {
                bootstrap: vec![hub.index],
                filter: velarx_p2p::filter::Config {
                    advertise: false,
                    ..Default::default()
                },
                ..Default::default()
            });
            // (it has these four peers and no others)
            let known: Vec<usize> = liars.iter().chain([&holder]).map(|n| n.index).collect();
            let asker = world.add_node(NodeConfig {
                bootstrap: known,
                max_outgoing: 4,
                ..Default::default()
            });
            settle(30).await;
            seed_image(&world, holder.index, &image).await;
            // (the liars have the chunks, and send them damaged)
            for l in &liars {
                seed_image(&world, l.index, &image).await;
            }
            for l in &liars {
                l.announce_falsely(std::slice::from_ref(&layer)).await;
            }
            settle(5).await;
            let r = pull(&asker, &image).await;
            let asked_liar = asker.live().source.decisions().about(&layer, &[]).iter().any(|d| {
                d.events.iter().any(|e| matches!(e, velarx_p2p::explain::Event::Asked { peer, .. } if liars.iter().any(|l| l.id() == *peer)))
            });
            eprintln!(
                "seed {seed}: wrong {} peers {} registry {} (a liar was asked: {asked_liar})",
                r.wrong, r.peer_chunks, r.registry_chunks
            );
            assert!(asked_liar, "no liar was asked: the scenario shows nothing");
            assert_eq!(r.wrong, 0);
            assert_eq!(r.chunks, 32);
            // the liars that announced the layer are asked first and sent
            // damaged chunks: each is replaced by the next candidate, and the
            // honest holder gives the layer
            assert!(
                asker.connected().contains(&holder.id()),
                "the holder is not a peer of the asker: the scenario shows nothing"
            );
            assert!(
                considered(&asker, &layer, holder.id()),
                "the honest holder was never a candidate"
            );
            assert_eq!(
                (r.peer_chunks, r.registry_chunks),
                (32, 0),
                "the holder did not give the layer"
            );
        });
    }
}

/// An honest holder that is slow (each answer takes 600 ms) beside a peer
/// that never answers: the pull takes about its time, and what is learnt of
/// it is its own time, not the time the asker spent on other peers.
#[test]
fn a_slow_honest_holder_is_not_punished_for_being_slow() {
    for seed in sim::seeds(&[1, 2]) {
        sim::run(seed, |world| async move {
            let image = one_layer("slowholder", 33, 32);
            let layer = image.layers[0].digest.clone();
            let hub = world.add_node(NodeConfig::default());
            let silent = world.add_node(NodeConfig {
                bootstrap: vec![hub.index],
                behavior: Behavior::Silent,
                ..Default::default()
            });
            let holder = world.add_node(NodeConfig {
                bootstrap: vec![hub.index],
                announce: true,
                behavior: Behavior::Slow(Duration::from_millis(600)),
                ..Default::default()
            });
            let asker = world.add_node(NodeConfig {
                bootstrap: vec![hub.index, silent.index, holder.index],
                announce: true,
                ..Default::default()
            });
            settle(30).await;
            seed_image(&world, holder.index, &image).await;
            settle(10).await;
            let t0 = tokio::time::Instant::now();
            let r = pull(&asker, &image).await;
            let took = t0.elapsed();
            let k = asker.live().source.knowledge().clone();
            let rtt = k.rtt(&holder.id());
            eprintln!(
                "seed {seed}: peers {} registry {} took {took:?}, the holder's time {rtt:?}, lacks {}",
                r.peer_chunks,
                r.registry_chunks,
                k.lacks(&layer, &holder.id())
            );
            assert_eq!((r.peer_chunks, r.registry_chunks), (32, 0));
            assert!(!k.lacks(&layer, &holder.id()));
            assert!(
                rtt.is_some_and(|t| t < Duration::from_millis(1200)),
                "the holder's time is taken as {rtt:?}"
            );
            assert!(took < Duration::from_millis(1500), "took {took:?}");
        });
    }
}

/// The chunks `from..to` of the one layer of `image`, as a layer with its
/// digest: what a pull asks of the peers in one group.
fn part(image: &sim::Image, from: usize, to: usize) -> sim::Image {
    let mut part = image.clone();
    part.layers[0].chunks = image.layers[0].chunks[from..to].to_vec();
    part
}

/// A peer that served a layer and then sends only wrong bytes is failing:
/// the next group does not take it as a candidate, and gets the layer from
/// the holder.
#[test]
fn a_peer_that_served_and_now_sends_wrong_bytes_is_failing() {
    for seed in sim::seeds(&[1, 2]) {
        sim::run(seed, |world| async move {
            let image = one_layer("turned", 41, 96);
            let layer = image.layers[0].digest.clone();
            let turning = world.add_node(NodeConfig {
                announce: true,
                ..Default::default()
            });
            // (the holder tells no filter: the other peer, whose filter
            // names the layer, is asked first)
            let holder = world.add_node(NodeConfig {
                bootstrap: vec![turning.index],
                filter: velarx_p2p::filter::Config {
                    advertise: false,
                    ..Default::default()
                },
                ..Default::default()
            });
            let asker = world.add_node(NodeConfig {
                bootstrap: vec![turning.index, holder.index],
                ..Default::default()
            });
            settle(30).await;
            seed_image(&world, holder.index, &image).await;
            seed_image(&world, turning.index, &image).await;
            settle(5).await;
            // the first group: the peer serves it
            let r = pull(&asker, &part(&image, 0, 32)).await;
            assert_eq!((r.wrong, r.peer_chunks), (0, 32));
            let k = asker.live().source.knowledge().clone();
            assert!(k.providers(&layer).contains(&turning.id()));
            // it turns bad: the second group is asked of it first, and
            // comes from the holder
            turning.set_behavior(Behavior::Corrupt);
            let r = pull(&asker, &part(&image, 32, 64)).await;
            assert_eq!((r.wrong, r.peer_chunks), (0, 32));
            // (the group whose first candidate is the peer that turned bad)
            let events = asker.live().source.decisions().about(&layer, &[]);
            let second = &events
                .iter()
                .find(|d| {
                    matches!(&d.events[0], velarx_p2p::explain::Event::Candidates(c)
                    if c[0].0 == turning.id())
                })
                .expect("a group that began with the peer")
                .events;
            assert!(
                matches!(&second[0], velarx_p2p::explain::Event::Candidates(c)
                    if c[0] == (turning.id(), velarx_p2p::explain::Why::Served)),
                "the peer that served was not the first candidate: {second:?}"
            );
            let wrong = k
                .traffic()
                .into_iter()
                .find(|(p, _)| *p == turning.id())
                .map_or(0, |(_, t)| t.wrong);
            eprintln!("seed {seed}: the bad peer sent {wrong} wrong chunks");
            assert!(wrong > 0, "the peer sent no wrong bytes: nothing shown");
            // it is failing: still believed to have the layer, but not
            // asked by the next group
            assert!(k.failing(&turning.id()));
            let r = pull(&asker, &part(&image, 64, 96)).await;
            assert_eq!((r.wrong, r.peer_chunks), (0, 32));
            // (the last group made, the first listed)
            let third = &asker.live().source.decisions().about(&layer, &[])[0];
            assert!(
                !third.events.iter().any(|e| matches!(e,
                    velarx_p2p::explain::Event::Candidates(c)
                        if c.iter().any(|(p, _)| *p == turning.id()))),
                "the peer that sent wrong bytes was a candidate of the next group: {third:?}"
            );
        });
    }
}
