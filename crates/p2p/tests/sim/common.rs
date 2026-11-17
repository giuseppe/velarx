// SPDX-License-Identifier: Apache-2.0
//! What the scenarios share: building a swarm and reading it.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::Arc;
use velarx_p2p::sim::{Node, NodeConfig, World};

/// A node that is the one the others name, with the defaults of the service.
pub fn seed_node(world: &Arc<World>) -> Arc<Node> {
    world.add_node(NodeConfig::default())
}

/// `n` nodes that name `bootstrap` only.
pub fn join(world: &Arc<World>, n: usize, bootstrap: &Arc<Node>) -> Vec<Arc<Node>> {
    (0..n)
        .map(|_| {
            world.add_node(NodeConfig {
                bootstrap: vec![bootstrap.index],
                ..Default::default()
            })
        })
        .collect()
}

/// The sizes of the groups of nodes that are up and connected to each other,
/// the biggest first.
pub fn components(world: &Arc<World>) -> Vec<usize> {
    let nodes: Vec<Arc<Node>> = world.nodes().into_iter().filter(|n| n.is_up()).collect();
    let by_id: BTreeMap<_, _> = nodes.iter().map(|n| (n.id(), n.index)).collect();
    let mut seen = BTreeSet::new();
    let mut sizes = Vec::new();
    for start in &nodes {
        if seen.contains(&start.index) {
            continue;
        }
        let mut size = 0;
        let mut queue = VecDeque::from([start.index]);
        seen.insert(start.index);
        while let Some(i) = queue.pop_front() {
            size += 1;
            let node = world.node(i).expect("a node");
            for peer in node.connected() {
                if let Some(&j) = by_id.get(&peer) {
                    if seen.insert(j) {
                        queue.push_back(j);
                    }
                }
            }
        }
        sizes.push(size);
    }
    sizes.sort_by(|a, b| b.cmp(a));
    sizes
}

/// min, median and max of the numbers.
pub fn spread(mut v: Vec<usize>) -> (usize, usize, usize) {
    v.sort();
    (v[0], v[v.len() / 2], v[v.len() - 1])
}

use std::time::Duration;
use velarx_p2p::sim::{Image, PullReport, Puller};

/// An image of one layer of `chunks` chunks of 64 KiB.
pub fn one_layer(name: &str, seed: u64, chunks: usize) -> Image {
    Image::new(name, seed, 1, chunks, 64 << 10)
}

/// Give `image` to the node `index` as if it had pulled it, and let the
/// peers learn of it (the DHT publishes in a few seconds).
pub async fn seed_image(world: &Arc<World>, index: usize, image: &Image) {
    for layer in &image.layers {
        world.seed_layer(index, layer).await;
    }
}

/// `node` pulls `image`.
pub async fn pull(node: &Arc<Node>, image: &Image) -> PullReport {
    Puller::default().pull(node, image).await
}

pub async fn settle(secs: u64) {
    tokio::time::sleep(Duration::from_secs(secs)).await;
}

/// Whether a pull of `node` took `peer` as a candidate for chunks of `layer`
/// or asked it for some (what the node's `explain` records).
pub fn considered(node: &Arc<Node>, layer: &str, peer: libp2p::PeerId) -> bool {
    use velarx_p2p::explain::Event;
    node.live()
        .source
        .decisions()
        .about(layer, &[])
        .iter()
        .flat_map(|d| d.events.iter())
        .any(|e| match e {
            Event::Candidates(peers) => peers.iter().any(|(p, _)| *p == peer),
            Event::Asked { peer: p, .. } => *p == peer,
            _ => false,
        })
}
