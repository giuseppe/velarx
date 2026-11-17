// SPDX-License-Identifier: Apache-2.0
//! The simulated node as the transport of the real peer code: what
//! `P2PNode` is to a swarm, this is to the simulated network.

use super::node::Node;
use crate::provider::Transport;
use crate::{P2PError, P2PResult, Presence};
use async_trait::async_trait;
use libp2p::PeerId;
use std::io;
use std::sync::{Arc, Weak};
use std::time::Duration;
use tokio::time::Instant;

/// How long a probe, and a dial, wait: those of the node.
const PROBE_TIMEOUT: Duration = Duration::from_secs(3);
const DIAL_LIMIT: Duration = Duration::from_secs(10);
/// How long a node asks the DHT, at most (as `NodePeers` would).
const LOOKUP_LIMIT: Duration = Duration::from_secs(3);
/// How long a connection to a peer is waited for, and how long a node then
/// leaves it alone (`quic`).
const CONNECT: Duration = Duration::from_secs(3);
const RETRY_AFTER: Duration = Duration::from_secs(30);

pub struct SimTransport {
    node: Weak<Node>,
}

impl SimTransport {
    pub(super) fn new(node: Weak<Node>) -> Self {
        Self { node }
    }

    fn me(&self) -> Arc<Node> {
        self.node.upgrade().expect("the node is alive")
    }

    /// A message of `bytes` from `a` to `b`; one that is lost never arrives
    /// (the caller's timeout ends the wait).
    async fn hop(a: &Node, b: &Node, bytes: u64) {
        if a.world().net.send(a.index, b.index, bytes).await.is_err() {
            super::net::Net::lost().await
        }
    }
}

#[async_trait]
impl Transport for SimTransport {
    async fn connected(&self) -> Vec<PeerId> {
        self.me().connected()
    }

    async fn find_providers(&self, layer: &str) -> Vec<PeerId> {
        let me = self.me();
        let live = me.live();
        let world = me.world();
        live.providers
            .lookup(layer, async {
                tokio::time::timeout(LOOKUP_LIMIT, world.dht.lookup(&me, layer))
                    .await
                    .unwrap_or_default()
            })
            .await
    }

    async fn connect_provider(&self, peer: PeerId) -> bool {
        let me = self.me();
        let Some(target) = me.world().node_of(peer) else {
            return false;
        };
        matches!(
            tokio::time::timeout(DIAL_LIMIT, me.world().dial(&me, &target)).await,
            Ok(true)
        )
    }

    fn streams_of(&self, chunks: usize) -> usize {
        crate::lanes_of(chunks, self.me().cfg.quic_streams)
    }

    /// A stream for each lane, as `P2PNode::fetch` asks: what came is kept,
    /// with nothing the failure of a lane is the answer.
    async fn fetch(
        &self,
        peer: PeerId,
        items: &[(String, Option<u64>)],
    ) -> P2PResult<Vec<(String, Vec<u8>)>> {
        let (me, target) = self.path(peer).await?;
        if items.is_empty() {
            return Ok(Vec::new());
        }
        let idle = crate::quic::Limits::default().idle;
        let lanes = crate::lanes(items, me.cfg.quic_streams);
        let answers = futures::future::join_all(lanes.into_iter().map(|lane| {
            let (a, b) = (me.clone(), target.clone());
            let digests: Vec<String> = lane.into_iter().map(|(d, _)| d).collect();
            let asked = 60 + 40 * digests.len() as u64;
            async move {
                tokio::time::timeout(idle, async move {
                    Self::hop(&a, &b, asked).await;
                    b.answer_quic(&a, &digests).await
                })
                .await
                .unwrap_or_else(|_| Err(io::Error::new(io::ErrorKind::TimedOut, "no answer")))
            }
        }))
        .await;
        crate::lanes_answer(peer, items, answers)
    }

    async fn without_quic(&self) -> usize {
        let me = self.me();
        let world = me.world();
        me.connected()
            .into_iter()
            .filter(|p| world.node_of(*p).is_none_or(|t| !t.cfg.udp) || !me.cfg.udp)
            .count()
    }

    async fn probe(&self, peer: PeerId, digest: &str) -> P2PResult<Presence> {
        let (me, target) = self.path(peer).await?;
        let (a, b, digest) = (me.clone(), target.clone(), digest.to_string());
        tokio::time::timeout(PROBE_TIMEOUT, async move {
            Self::hop(&a, &b, 100).await;
            let answer = b.answer_probe(&digest).await;
            Self::hop(&b, &a, 100).await;
            answer
        })
        .await
        .map_err(|_| P2PError::Timeout)?
        .map_err(|e| crate::quic_error(peer, e))
    }

    async fn request_index(
        &self,
        peer: PeerId,
        layer: &str,
        max: u64,
    ) -> P2PResult<Option<Vec<u8>>> {
        self.index(peer, layer, false, max).await
    }

    async fn request_profile(
        &self,
        peer: PeerId,
        image: &str,
        max: u64,
    ) -> P2PResult<Option<Vec<u8>>> {
        self.index(peer, image, true, max).await
    }
}

impl SimTransport {
    /// The node that is asked, when there is a QUIC path to it: both ends
    /// reach each other over UDP.  The first attempt to one that does not
    /// takes the time of the connect, the next ones (for a while) none.
    async fn path(&self, peer: PeerId) -> P2PResult<(Arc<Node>, Arc<Node>)> {
        let me = self.me();
        let world = me.world();
        let target = world.node_of(peer).ok_or(P2PError::NotConnected)?;
        if !me.connected().contains(&peer) {
            return Err(P2PError::NotConnected);
        }
        if me.cfg.udp && target.cfg.udp {
            return Ok((me, target));
        }
        let live = me.live();
        let lately = live
            .quic_failed
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&peer)
            .is_some_and(|at| at.elapsed() < RETRY_AFTER);
        if !lately {
            tokio::time::sleep(CONNECT).await;
            let mut failed = live.quic_failed.lock().unwrap_or_else(|e| e.into_inner());
            failed.retain(|_, at| at.elapsed() < RETRY_AFTER);
            failed.insert(peer, Instant::now());
        }
        Err(P2PError::NoQuicPath {
            peer,
            reason: "no answer over UDP (blocked, or no QUIC endpoint there)".into(),
        })
    }

    /// An index or a profile over QUIC.
    async fn index(
        &self,
        peer: PeerId,
        name: &str,
        profile: bool,
        max: u64,
    ) -> P2PResult<Option<Vec<u8>>> {
        let (me, target) = self.path(peer).await?;
        let (a, b, name) = (me.clone(), target.clone(), name.to_string());
        let found = tokio::time::timeout(Duration::from_secs(10), async move {
            Self::hop(&a, &b, 100).await;
            let answer = b.answer_index(&a, &name, profile).await;
            Self::hop(&b, &a, 100).await;
            answer
        })
        .await
        .map_err(|_| P2PError::Timeout)?
        .map_err(|e| crate::quic_error(peer, e))?;
        Ok(found.filter(|d| d.len() as u64 <= max))
    }
}
