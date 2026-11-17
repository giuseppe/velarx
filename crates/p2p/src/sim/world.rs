// SPDX-License-Identifier: Apache-2.0
//! The world of a run: the nodes, the network, the DHT, the registry, and
//! the trace.

use super::content::Layer;
use super::net::Net;
use super::node::{Conn, Dir, Node, NodeConfig};
use crate::bootstrap::{Place, LENT_PLACES};
use libp2p::{Multiaddr, PeerId};
use std::collections::{BTreeMap, VecDeque};
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::time::Instant;

/// How long a dial to a node that cannot be reached takes to fail.
const DIAL_FAILS: Duration = Duration::from_secs(5);

/// The records of the DHT: who provides what, when it was published, and how
/// long a lookup takes.  A model of Kademlia as far as the decisions need it:
/// a record is found after it is published (the time a swarm takes) and a
/// lookup costs a few round trips.
pub struct Dht {
    records: Mutex<BTreeMap<String, Vec<(PeerId, Instant)>>>,
    /// How long a record takes to be found after it is published
    pub publish_delay: Mutex<Duration>,
    /// The round trips of a lookup
    pub lookup_trips: Mutex<u32>,
    lookups: AtomicU64,
}

impl Dht {
    fn new() -> Self {
        Self {
            records: Mutex::default(),
            publish_delay: Mutex::new(Duration::from_secs(5)),
            lookup_trips: Mutex::new(4),
            lookups: AtomicU64::new(0),
        }
    }

    pub fn publish(&self, key: &str, peer: PeerId) {
        let visible =
            Instant::now() + *self.publish_delay.lock().unwrap_or_else(|e| e.into_inner());
        let mut records = self.records.lock().unwrap_or_else(|e| e.into_inner());
        let providers = records.entry(key.to_string()).or_default();
        if !providers.iter().any(|(p, _)| *p == peer) {
            providers.push((peer, visible));
        }
    }

    /// The providers of `key` that are found, at most 20 (the peers kept for
    /// a key), after the lookup.
    pub async fn lookup(&self, from: &Arc<Node>, key: &str) -> Vec<PeerId> {
        self.lookups.fetch_add(1, Relaxed);
        let trips = *self.lookup_trips.lock().unwrap_or_else(|e| e.into_inner());
        // (each trip is to a peer some way off; a walk goes round the peers
        // that do not answer, so a trip is to one that is there)
        let world = from.world();
        for _ in 0..trips {
            let far = (0..8)
                .map(|_| from.live().entropy.below(world.len().max(1)))
                .find(|&far| world.net.reachable(from.index, far));
            let Some(far) = far else {
                super::net::Net::lost().await
            };
            if world.net.send(from.index, far, 120).await.is_err()
                || world.net.send(far, from.index, 300).await.is_err()
            {
                super::net::Net::lost().await
            }
        }
        let now = Instant::now();
        self.records
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(key)
            .map(|p| {
                p.iter()
                    .filter(|(_, at)| *at <= now)
                    .map(|(p, _)| *p)
                    .take(20)
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn lookups(&self) -> u64 {
        self.lookups.load(Relaxed)
    }
}

/// The registry the pulls fall back to: a line of its own, and what it gave.
pub struct Registry {
    pub(super) index: usize,
    pub bytes: AtomicU64,
    pub requests: AtomicU64,
}

/// What happened, in the order it did, bounded: the last events of a run are
/// what a failure shows.
pub struct Trace {
    start: Instant,
    events: Mutex<VecDeque<String>>,
}

impl Trace {
    const KEEP: usize = 4000;

    fn new() -> Self {
        Self {
            start: Instant::now(),
            events: Mutex::default(),
        }
    }

    pub fn push(&self, node: usize, what: String) {
        let at = self.start.elapsed();
        let mut events = self.events.lock().unwrap_or_else(|e| e.into_inner());
        if events.len() >= Self::KEEP {
            events.pop_front();
        }
        events.push_back(format!(
            "{:>9.3}s  node {node:>4}  {what}",
            at.as_secs_f64()
        ));
    }

    /// The last `n` events.
    pub fn tail(&self, n: usize) -> Vec<String> {
        let events = self.events.lock().unwrap_or_else(|e| e.into_inner());
        events
            .iter()
            .skip(events.len().saturating_sub(n))
            .cloned()
            .collect()
    }
}

pub struct World {
    pub seed: u64,
    pub net: Net,
    pub dht: Dht,
    pub registry: Registry,
    pub trace: Trace,
    nodes: Mutex<Vec<Arc<Node>>>,
}

/// The `generation`th identity of the node `index`: the same for the same
/// seed.
pub fn peer_id(seed: u64, index: usize, generation: u64) -> PeerId {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(seed.to_le_bytes());
    h.update((index as u64).to_le_bytes());
    h.update(generation.to_le_bytes());
    let secret: [u8; 32] = h.finalize().into();
    let key = libp2p::identity::Keypair::ed25519_from_bytes(secret).expect("a key of 32 bytes");
    key.public().to_peer_id()
}

impl World {
    pub(super) fn new(seed: u64) -> Arc<Self> {
        let net = Net::new(crate::entropy::Entropy::seeded(seed ^ 0x6e65_7400));
        // The registry is a node of the network: its line is the bandwidth
        // of the registry.
        net.add(0, 0);
        let index = super::net::REGISTRY;
        Arc::new(Self {
            seed,
            net,
            dht: Dht::new(),
            registry: Registry {
                index,
                bytes: AtomicU64::new(0),
                requests: AtomicU64::new(0),
            },
            trace: Trace::new(),
            nodes: Mutex::default(),
        })
    }

    /// Set what the registry uploads at, bytes a second (0: no limit).
    pub fn set_registry_rate(&self, rate: u64) {
        self.net.set_up(self.registry.index, rate);
    }

    /// A new node: it starts at once.
    pub fn add_node(self: &Arc<Self>, cfg: NodeConfig) -> Arc<Node> {
        let index = {
            let nodes = self.nodes.lock().unwrap_or_else(|e| e.into_inner());
            nodes.len()
        };
        let line = self.net.add(cfg.up, cfg.down);
        debug_assert_eq!(line, index);
        let node = Node::new(self, index, cfg);
        self.nodes
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(node.clone());
        node
    }

    pub fn len(&self) -> usize {
        self.nodes.lock().unwrap_or_else(|e| e.into_inner()).len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn node(&self, index: usize) -> Option<Arc<Node>> {
        self.nodes
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(index)
            .cloned()
    }

    pub fn nodes(&self) -> Vec<Arc<Node>> {
        self.nodes.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// The node that has `peer` as its identity now.
    pub fn node_of(&self, peer: PeerId) -> Option<Arc<Node>> {
        self.nodes
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .find(|n| n.id() == peer)
            .cloned()
    }

    /// The address the node `index` is dialed at: its own (`NodeConfig::ip`).
    pub fn address_of(&self, index: usize) -> Multiaddr {
        let ip = self.node(index).map_or_else(
            || IpAddr::from([10, (index >> 16) as u8, (index >> 8) as u8, index as u8]),
            |n| n.ip,
        );
        format!("/ip4/{ip}/tcp/4001").parse().expect("an address")
    }

    /// The node an address names.
    pub fn node_at(&self, address: &Multiaddr) -> Option<Arc<Node>> {
        let ip = address.iter().find_map(|p| match p {
            libp2p::multiaddr::Protocol::Ip4(ip) => Some(IpAddr::V4(ip)),
            _ => None,
        })?;
        self.nodes
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .find(|n| n.ip == ip)
            .cloned()
    }

    /// A short name of a peer for the trace.
    pub fn label(&self, peer: PeerId) -> String {
        self.node_of(peer)
            .map_or_else(|| peer.to_string(), |n| format!("n{}", n.index))
    }

    pub fn trace(&self, node: usize, what: impl FnOnce() -> String) {
        self.trace.push(node, what());
    }

    /// `a` connects to `b`: the handshake, the limits of `b`, what the two
    /// learn of each other.  Whether they are connected when it is over.
    pub async fn dial(self: &Arc<Self>, a: &Arc<Node>, b: &Arc<Node>) -> bool {
        if a.index == b.index {
            return false;
        }
        let (la, lb) = (a.live(), b.live());
        if la
            .conns
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .contains_key(&lb.id)
        {
            return true;
        }
        let outgoing = la
            .conns
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .filter(|c| c.dir == Dir::Out)
            .count();
        if outgoing >= a.cfg.max_outgoing as usize {
            return false;
        }
        // (the transport, the encryption and the multiplexer: three round
        // trips)
        for _ in 0..3 {
            if self.net.send(a.index, b.index, 200).await.is_err()
                || self.net.send(b.index, a.index, 200).await.is_err()
            {
                tokio::time::sleep(DIAL_FAILS).await;
                self.trace(a.index, || format!("dial n{} fails", b.index));
                return false;
            }
        }
        let now = Instant::now();
        let passing = {
            // (a node is dialed twice at once: the second is the first)
            let mut theirs = lb.conns.lock().unwrap_or_else(|e| e.into_inner());
            if theirs.contains_key(&la.id) {
                return true;
            }
            let incoming = theirs.values().filter(|c| c.dir == Dir::In).count();
            if incoming >= b.cfg.max_incoming as usize + LENT_PLACES as usize {
                drop(theirs);
                self.trace(a.index, || format!("n{} is full: refused", b.index));
                return false;
            }
            let place = lb
                .exchange
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .incoming(la.id, now);
            let passing = match place {
                Place::Refused => {
                    drop(theirs);
                    self.trace(a.index, || {
                        format!("n{} has no place for it: refused", b.index)
                    });
                    return false;
                }
                Place::Member => false,
                Place::Lent => true,
            };
            theirs.insert(
                la.id,
                Conn {
                    dir: Dir::In,
                    passing,
                },
            );
            passing
        };
        // (a peer being dialed for an answer is a peer now)
        la.exchange_dialing
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&lb.id);
        let count_a = {
            let mut ours = la.conns.lock().unwrap_or_else(|e| e.into_inner());
            ours.insert(
                lb.id,
                Conn {
                    dir: Dir::Out,
                    passing: false,
                },
            );
            ours.len()
        };
        la.known
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(lb.id);
        lb.known
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(la.id);
        self.trace(a.index, || {
            format!(
                "connected to n{}{}",
                b.index,
                if passing {
                    " (for an exchange only)"
                } else {
                    ""
                }
            )
        });
        lb.wake.notify_one();
        la.wake.notify_one();
        // (what each can tell of the other: where it is connected to)
        for (mine, other) in [(&la, b), (&lb, a)] {
            mine.peers
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .0
                .learn(other.id(), &[other.ip], &[self.address_of(other.index)]);
        }
        if !passing {
            // (a new peer learns the layers at once)
            for (me, other) in [(a, b), (b, a)] {
                if let Some(filter) = me.live().advertisement.with(|a| a.full()) {
                    let (me, to) = (me.clone(), other.id());
                    tokio::spawn(async move { me.tell(to, vec![filter]).await });
                }
            }
        }
        if la
            .bootstrap
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .wants_peers(count_a)
        {
            if a.cfg.kad {
                a.kad_bootstrap();
            }
            if a.cfg.exchange && a.wants_peers() {
                a.ask_for_peers(b);
            }
        }
        true
    }

    /// `a` dials the peer `peer` at `address`, as the node does for what a
    /// peer told it: the handshake proves the identity, so an address where
    /// another peer is (or none) is no connection, though the dial reached
    /// it.
    pub async fn dial_named(
        self: &Arc<Self>,
        a: &Arc<Node>,
        peer: PeerId,
        address: &Multiaddr,
    ) -> bool {
        let Some(target) = self.node_at(address) else {
            return false;
        };
        if target.id() != peer {
            // (the transport and the encryption: the key is not the one named)
            for _ in 0..2 {
                if self.net.send(a.index, target.index, 200).await.is_err()
                    || self.net.send(target.index, a.index, 200).await.is_err()
                {
                    return false;
                }
            }
            return false;
        }
        self.dial(a, &target).await
    }

    /// `node` closes its connection to `peer` (both sides see it).
    pub fn disconnect(&self, node: &Arc<Node>, peer: PeerId) {
        let live = node.live();
        let Some(other) = self.node_of(peer) else {
            return;
        };
        let theirs = other.live();
        for (mine, remote_id, local) in [(&live, peer, &theirs), (&theirs, live.id, &live)] {
            let removed = mine
                .conns
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(&remote_id);
            if removed.is_none() {
                continue;
            }
            mine.peers
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .0
                .forget(&remote_id);
            mine.exchange
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .closed(remote_id);
            let gossip = mine.gossip.clone();
            tokio::spawn(async move { gossip.remove_peer(&remote_id).await });
            let count = mine.conns.lock().unwrap_or_else(|e| e.into_inner()).len();
            mine.bootstrap
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .connections(count, Instant::now());
            mine.wake.notify_one();
            let _ = local;
        }
    }

    /// Give `layer` to the node `index` as if it had pulled it.
    pub async fn seed_layer(&self, index: usize, layer: &Layer) {
        let node = self.node(index).expect("a node");
        node.complete_layer(layer).await;
    }

    /// The numbers of connections of the nodes that are up.
    pub fn degrees(&self) -> Vec<usize> {
        self.nodes()
            .iter()
            .filter(|n| n.is_up())
            .map(|n| n.connected().len())
            .collect()
    }
}

impl World {
    /// Cut the nodes `side` off the others.  The connections across stay
    /// until the pings of the two ends fail, about a minute later, as they
    /// do on a real network (a model of libp2p's ping).
    pub fn partition(self: &Arc<Self>, side: &[usize]) {
        self.net.partition(side);
        let world = self.clone();
        tokio::spawn(async move {
            tokio::time::sleep(crate::PING_INTERVAL + crate::PING_TIMEOUT * 2).await;
            world.close_unreachable();
        });
    }

    /// Mend the partition.
    pub fn heal(&self) {
        self.net.heal();
    }

    /// Close the connections that cannot carry a message any more.
    fn close_unreachable(&self) {
        for node in self.nodes() {
            for peer in node.connected_all() {
                if let Some(other) = self.node_of(peer) {
                    if !self.net.reachable(node.index, other.index) {
                        self.disconnect(&node, peer);
                    }
                }
            }
        }
    }

    /// Stop the node `index`: its connections close, nothing reaches it.
    pub fn crash(&self, index: usize) {
        if let Some(node) = self.node(index) {
            node.stop();
        }
    }

    /// Start the node `index` again, with its identity (the service keeps
    /// it in a file) and no memory of the peers (its store is kept).
    pub fn restart(&self, index: usize) {
        if let Some(node) = self.node(index) {
            node.start(false);
        }
    }

    /// Start the node `index` again with a new identity: what a node whose
    /// identity file was removed does, and what a member does that wants
    /// the peers to forget it.
    pub fn restart_with_new_identity(&self, index: usize) {
        if let Some(node) = self.node(index) {
            node.start(true);
        }
    }
}
