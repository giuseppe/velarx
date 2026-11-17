// SPDX-License-Identifier: Apache-2.0
//! A pull, as the engine makes it: the chunks of each layer in groups, the
//! groups asked of the peers at the same time, what the peers did not give
//! from the registry, a layer that is complete served to the others.  The
//! engine's own walker is not here (it is in another crate and works on files);
//! what is asked of the peers, and how, is the service's.

use super::content::{Image, Layer};
use super::net::REGISTRY;
use super::node::Node;
use crate::provider::{Item, Sink};
use async_trait::async_trait;
use futures::StreamExt;
use std::collections::HashMap;
use std::sync::atomic::Ordering::Relaxed;
use std::sync::Arc;
use tokio::time::Instant;

/// How the engine pulls: the chunks of a group, the groups and the layers
/// under way at the same time.
#[derive(Debug, Clone, Copy)]
pub struct Puller {
    pub group_items: usize,
    pub groups_at_once: usize,
    pub layers_at_once: usize,
}

impl Default for Puller {
    fn default() -> Self {
        Self {
            group_items: 32,
            groups_at_once: 4,
            layers_at_once: 3,
        }
    }
}

/// What a pull came to.
#[derive(Debug, Clone)]
pub struct PullReport {
    pub started: Instant,
    pub finished: Instant,
    pub chunks: usize,
    /// Chunks and bytes that came from peers, and from the registry
    pub peer_chunks: usize,
    pub peer_bytes: u64,
    pub registry_chunks: usize,
    pub registry_bytes: u64,
    /// Chunks the peers' source passed on that were not what they were
    /// named by (never, when the checks hold)
    pub wrong: usize,
}

impl PullReport {
    pub fn took(&self) -> std::time::Duration {
        self.finished - self.started
    }
}

/// What the peers' source delivers, checked a second time: a chunk that is
/// not what it is named by is counted, and not kept.
#[derive(Default)]
struct Collect {
    got: HashMap<String, Vec<u8>>,
    wrong: usize,
}

#[async_trait]
impl Sink for Collect {
    async fn put(&mut self, digest: &str, data: &[u8]) -> Result<(), String> {
        if !crate::limits::names(digest, data) {
            self.wrong += 1;
            return Err(format!("{digest} is not what it says"));
        }
        self.got.insert(digest.to_string(), data.to_vec());
        Ok(())
    }
}

impl Puller {
    /// Pull `image` to `node`.
    pub async fn pull(&self, node: &Arc<Node>, image: &Image) -> PullReport {
        let started = Instant::now();
        let totals = futures::stream::iter(image.layers.iter())
            .map(|layer| self.layer(node, layer))
            .buffer_unordered(self.layers_at_once.max(1))
            .collect::<Vec<_>>()
            .await;
        let mut report = PullReport {
            started,
            finished: Instant::now(),
            chunks: 0,
            peer_chunks: 0,
            peer_bytes: 0,
            registry_chunks: 0,
            registry_bytes: 0,
            wrong: 0,
        };
        for (peer_chunks, peer_bytes, registry_chunks, registry_bytes, wrong) in totals {
            report.wrong += wrong;
            report.chunks += peer_chunks + registry_chunks;
            report.peer_chunks += peer_chunks;
            report.peer_bytes += peer_bytes;
            report.registry_chunks += registry_chunks;
            report.registry_bytes += registry_bytes;
        }
        node.world().trace(node.index, || {
            format!(
                "pulled {}: {} chunks from peers ({} bytes), {} from the registry ({} bytes) in {:?}",
                image.name,
                report.peer_chunks,
                report.peer_bytes,
                report.registry_chunks,
                report.registry_bytes,
                report.took()
            )
        });
        report
    }

    /// One layer: (chunks and bytes from peers, chunks and bytes from the
    /// registry).
    async fn layer(&self, node: &Arc<Node>, layer: &Layer) -> (usize, u64, usize, u64, usize) {
        let items: Vec<Item> = layer
            .chunks
            .iter()
            .map(|(d, data)| Item {
                digest: d.clone(),
                size: Some(data.len() as u64),
            })
            .collect();
        let live = node.live();
        let groups: Vec<&[Item]> = items.chunks(self.group_items.max(1)).collect();
        let parts = futures::stream::iter(groups)
            .map(|group| async {
                let mut sink = Collect::default();
                let _ = live
                    .source
                    .fetch_group(group, Some(&layer.digest), &mut sink)
                    .await;
                let peer_bytes: u64 = sink.got.values().map(|d| d.len() as u64).sum();
                let peer_chunks = sink.got.len();
                // what the peers did not give comes from the registry
                let missing: Vec<&Item> = group
                    .iter()
                    .filter(|i| !sink.got.contains_key(&i.digest))
                    .collect();
                let bytes: u64 = missing.iter().filter_map(|i| i.size).sum();
                if !missing.is_empty() {
                    let world = node.world();
                    world.registry.requests.fetch_add(1, Relaxed);
                    world.trace(node.index, || {
                        format!(
                            "{} chunks of {} from the registry",
                            missing.len(),
                            crate::limits::short(&layer.digest)
                        )
                    });
                    if world.net.send(REGISTRY, node.index, bytes).await.is_ok() {
                        world.registry.bytes.fetch_add(bytes, Relaxed);
                    }
                }
                (peer_chunks, peer_bytes, missing.len(), bytes, sink.wrong)
            })
            .buffer_unordered(self.groups_at_once.max(1))
            .collect::<Vec<_>>()
            .await;
        node.complete_layer(layer).await;
        parts.into_iter().fold((0, 0, 0, 0, 0), |a, p| {
            (a.0 + p.0, a.1 + p.1, a.2 + p.2, a.3 + p.3, a.4 + p.4)
        })
    }
}
