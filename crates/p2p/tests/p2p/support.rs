// SPDX-License-Identifier: Apache-2.0
//! What the test modules of this binary share: digests, a chunk provider, a
//! swarm key and the address of a node.

use std::collections::HashMap;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::Duration;
use velarx_p2p::{ChunkProvider, P2PNode};
use velarx_types::digest::{Algorithm, Digest};

pub fn digest_of(data: &[u8]) -> String {
    Digest::of(Algorithm::Sha256, data).to_string()
}

/// Chunks by digest.
pub struct Chunks(pub HashMap<String, Vec<u8>>);

impl ChunkProvider for Chunks {
    fn get_chunk(&self, digest: &str) -> std::io::Result<Option<Vec<u8>>> {
        Ok(self.0.get(digest).cloned())
    }
}

/// A swarm key `name` in `dir`, as the daemon writes it (0600).
pub fn key(dir: &Path, name: &str) -> PathBuf {
    let path = dir.join(name);
    velarx_p2p::control::generate_swarm_key(&path).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    path
}

/// The first address the node listens on (it has none until its transport
/// is up: the status tells when it has).
pub async fn address(node: &P2PNode) -> libp2p::Multiaddr {
    let mut status = node.status_updates();
    let up = tokio::time::timeout(
        Duration::from_secs(10),
        status.wait_for(|s| !s.listen_addresses.is_empty()),
    )
    .await
    .expect("the node does not listen")
    .expect("the node ended");
    up.listen_addresses[0].clone()
}

/// Whether `a` is connected to `b` now (what was decided before is in the
/// status: no wait for something not to happen).
pub fn connected_now(a: &P2PNode, b: &P2PNode) -> bool {
    a.status_updates().borrow().connected.contains(&b.peer_id())
}

/// Whether `a` is connected to `b` within `within`: the status tells when it
/// is.
pub async fn connected_within(a: &P2PNode, b: &P2PNode, within: Duration) -> bool {
    let peer = b.peer_id();
    let mut status = a.status_updates();
    tokio::time::timeout(within, status.wait_for(|s| s.connected.contains(&peer)))
        .await
        .is_ok_and(|r| r.is_ok())
}

/// Whether `a` knows the QUIC endpoint of `b` within `within` (it learns it
/// from `b` once connected): the status tells when it does.
pub async fn quic_known_within(a: &P2PNode, b: &P2PNode, within: Duration) -> bool {
    let peer = b.peer_id();
    let mut status = a.status_updates();
    tokio::time::timeout(within, status.wait_for(|s| s.quic_peers.contains(&peer)))
        .await
        .is_ok_and(|r| r.is_ok())
}

/// The chunks `digests` that `a` fetches from `b` over QUIC, once `a` knows
/// the endpoint of `b` (the status tells when it does).
pub async fn fetch(
    a: &P2PNode,
    b: &P2PNode,
    digests: &[String],
) -> velarx_p2p::P2PResult<Vec<(String, Vec<u8>)>> {
    assert!(
        quic_known_within(a, b, Duration::from_secs(5)).await,
        "identify did not tell the QUIC endpoint"
    );
    let items: Vec<(String, Option<u64>)> = digests.iter().map(|d| (d.clone(), None)).collect();
    a.fetch(b.peer_id(), &items).await
}

/// Whether `holds` holds of what `node` heard from its peers within
/// `within`: checked again each time the gossip tables changed, not polled.
pub async fn heard_within<F, Fut>(node: &P2PNode, within: Duration, mut holds: F) -> bool
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let mut changes = node.gossip().changes();
    tokio::time::timeout(within, async {
        loop {
            // (seen before the check: a change during it wakes the wait)
            changes.borrow_and_update();
            if holds().await {
                return;
            }
            if changes.changed().await.is_err() {
                return std::future::pending().await;
            }
        }
    })
    .await
    .is_ok()
}
