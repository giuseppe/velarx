// SPDX-License-Identifier: Apache-2.0
//! What the simulated nodes hold: chunks with real digests, layers and
//! images made from a seed, and the stores that serve them.

use crate::entropy::Entropy;
use crate::ChunkProvider;
use sha2::{Digest as _, Sha256};
use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, RwLock};

/// A layer: its digest and its chunks, each named by the sha256 of its bytes.
#[derive(Debug, Clone)]
pub struct Layer {
    pub digest: String,
    pub chunks: Vec<(String, Arc<Vec<u8>>)>,
}

impl Layer {
    /// A layer of `chunks` chunks of `bytes` bytes of the bytes of `entropy`.
    pub fn new(entropy: &Entropy, chunks: usize, bytes: usize) -> Self {
        let chunks: Vec<(String, Arc<Vec<u8>>)> = (0..chunks)
            .map(|_| {
                let mut data = vec![0u8; bytes];
                for part in data.chunks_mut(8) {
                    let word = entropy.below(usize::MAX).to_le_bytes();
                    part.copy_from_slice(&word[..part.len()]);
                }
                (sha256(&data), Arc::new(data))
            })
            .collect();
        let mut all = Sha256::new();
        for (d, _) in &chunks {
            all.update(d.as_bytes());
        }
        Self {
            digest: format!("sha256:{}", hex::encode(all.finalize())),
            chunks,
        }
    }

    /// The bytes of its chunks.
    pub fn bytes(&self) -> u64 {
        self.chunks.iter().map(|(_, d)| d.len() as u64).sum()
    }
}

/// An image: the layers a pull fetches.
#[derive(Debug, Clone)]
pub struct Image {
    pub name: String,
    pub layers: Vec<Layer>,
}

impl Image {
    /// An image of `layers` layers of `chunks` chunks of `bytes` bytes.
    pub fn new(name: &str, seed: u64, layers: usize, chunks: usize, bytes: usize) -> Self {
        let entropy = Entropy::seeded(seed);
        Self {
            name: name.to_string(),
            layers: (0..layers)
                .map(|_| Layer::new(&entropy, chunks, bytes))
                .collect(),
        }
    }

    pub fn bytes(&self) -> u64 {
        self.layers.iter().map(Layer::bytes).sum()
    }
}

fn sha256(data: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(data)))
}

/// The store of a node: the chunks of the layers it holds, in memory.
#[derive(Default)]
pub struct MemStore {
    chunks: RwLock<HashMap<String, Arc<Vec<u8>>>>,
    layers: RwLock<BTreeMap<String, Vec<String>>>,
}

impl MemStore {
    pub fn add(&self, layer: &Layer) {
        let mut chunks = self.chunks.write().unwrap_or_else(|e| e.into_inner());
        for (d, data) in &layer.chunks {
            chunks.insert(d.clone(), data.clone());
        }
        self.layers
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .insert(
                layer.digest.clone(),
                layer.chunks.iter().map(|(d, _)| d.clone()).collect(),
            );
    }

    pub fn has_layer(&self, layer: &str) -> bool {
        self.layers
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .contains_key(layer)
    }

    /// The layers held, in order.
    pub fn layers(&self) -> Vec<String> {
        self.layers
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .keys()
            .cloned()
            .collect()
    }

    pub fn chunk(&self, digest: &str) -> Option<Arc<Vec<u8>>> {
        self.chunks
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(digest)
            .cloned()
    }

    /// Spoil the first byte of each chunk of `layer` the store holds: what a
    /// disk that went bad gives (the node finds out when it reads them).
    pub fn damage(&self, layer: &Layer) {
        let mut chunks = self.chunks.write().unwrap_or_else(|e| e.into_inner());
        for (digest, _) in &layer.chunks {
            if let Some(data) = chunks.get_mut(digest) {
                let mut spoiled = data.as_ref().clone();
                if let Some(b) = spoiled.first_mut() {
                    *b ^= 0xff;
                }
                *data = Arc::new(spoiled);
            }
        }
    }

    /// The size of a chunk held.
    pub fn size_of(&self, digest: &str) -> Option<u64> {
        self.chunk(digest).map(|d| d.len() as u64)
    }
}

impl ChunkProvider for MemStore {
    fn get_chunk(&self, digest: &str) -> std::io::Result<Option<Vec<u8>>> {
        Ok(self.chunk(digest).map(|d| d.as_ref().clone()))
    }
}
