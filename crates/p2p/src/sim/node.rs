// SPDX-License-Identifier: Apache-2.0
//! One simulated node: the real decision code of a node (the source of its
//! pulls, its knowledge of the peers, its gossip tables, what it admits to
//! serve, its bootstrap timer) on the simulated network.

use super::content::{Layer, MemStore};
use super::World;
use crate::bootstrap::{Backoff, Bootstrap, Exchange};
use crate::dial_filter::{DialFilter, Rules};
use crate::entropy::Entropy;
use crate::gossip::{GossipDiscovery, GossipMessage};
use crate::peer_exchange::{self, Directory, Pacing};
use crate::provider::{NodePeers, PeerSource, Policy};
use crate::serve::{Admission, Serving};
use libp2p::PeerId;
use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;
use tokio::sync::{Notify, Semaphore};
use tokio::task::JoinHandle;
use tokio::time::Instant;

/// How a node behaves toward the others.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Behavior {
    /// As the real service does
    Honest,
    /// Answers every request that it has no room
    Busy,
    /// Takes every request and never answers
    Silent,
    /// Answers requests for chunks with bytes that are not the chunks
    Corrupt,
    /// Honest, but each answer takes this much longer
    Slow(Duration),
}

/// What a node is like.  The defaults are those of a node of the service.
#[derive(Debug, Clone)]
pub struct NodeConfig {
    pub max_incoming: u32,
    pub max_outgoing: u32,
    pub min_peers: usize,
    pub backoff: (Duration, Duration),
    pub serving: Serving,
    pub policy: Policy,
    /// Reachable over UDP, so that a QUIC connection can be made to and
    /// from it; false: a member for discovery with no data path
    pub udp: bool,
    /// Tell the peers its images and the DHT its layers (`announce_images`)
    pub announce: bool,
    /// The filter of the layers it tells the peers
    pub filter: crate::filter::Config,
    /// The streams a request for chunks is spread over (`quic_streams`)
    pub quic_streams: usize,
    /// What the node writes and reads at, bytes a second (0: no limit)
    pub up: u64,
    pub down: u64,
    /// How long its store takes to read the chunks of a request
    pub store_latency: Duration,
    /// Its address (by default one of its own)
    pub ip: Option<IpAddr>,
    /// The nodes it is told of at its start
    pub bootstrap: Vec<usize>,
    /// Walk the DHT for peers when it has few (the model of Kademlia) and
    /// ask its peers for others (`peer_exchange`)
    pub kad: bool,
    pub exchange: bool,
    pub behavior: Behavior,
}

impl Default for NodeConfig {
    fn default() -> Self {
        let real = crate::P2PConfig::default();
        Self {
            max_incoming: real.max_incoming,
            max_outgoing: real.max_outgoing,
            min_peers: real.min_peers,
            backoff: real.bootstrap_backoff,
            serving: real.serving,
            policy: Policy::default(),
            udp: true,
            announce: real.announce_images,
            filter: real.filter,
            quic_streams: real.quic_streams,
            up: 0,
            down: 0,
            store_latency: Duration::ZERO,
            ip: None,
            bootstrap: Vec::new(),
            kad: true,
            exchange: true,
            behavior: Behavior::Honest,
        }
    }
}

/// How a connection came about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dir {
    In,
    Out,
}

pub(super) struct Conn {
    pub dir: Dir,
    /// Taken past `max_incoming` for the exchange of peers only
    pub passing: bool,
}

/// What a node loses when it stops: everything but its store.
pub struct Live {
    pub id: PeerId,
    pub(super) conns: Mutex<BTreeMap<PeerId, Conn>>,
    /// The peers it knows an address of (its routing table)
    pub(super) known: Mutex<BTreeSet<PeerId>>,
    pub(super) bootstrap: Mutex<Bootstrap>,
    pub(super) exchange: Mutex<Exchange<PeerId>>,
    /// What it can tell of its peers, and when it asked and answered each
    pub(super) peers: Mutex<(Directory, Pacing)>,
    /// The peers learnt of an answer it is dialing (counted as peers it will
    /// have, as the node does)
    pub(super) exchange_dialing: Mutex<BTreeSet<PeerId>>,
    /// Where it may dial
    pub(super) filter: DialFilter,
    dial_counters: Arc<crate::stats::Counters>,
    pub gossip: Arc<GossipDiscovery>,
    /// The layers it holds and the filter that tells the peers
    pub advertisement: Arc<crate::filter::Advertisement>,
    pub admission: Arc<Admission>,
    pub(super) quic_slots: Arc<Semaphore>,
    pub source: Arc<PeerSource>,
    pub(super) providers: crate::shared::ProviderCache,
    pub(super) quic_failed: Mutex<std::collections::HashMap<PeerId, Instant>>,
    pub(super) wake: Notify,
    pub(super) behavior: Mutex<Behavior>,
    pub counters: Counters,
    pub(super) entropy: Entropy,
}

/// What a node did, to read in a scenario.
#[derive(Default)]
pub struct Counters {
    /// Requests answered with data, and the bytes
    pub served: std::sync::atomic::AtomicU64,
    pub served_bytes: std::sync::atomic::AtomicU64,
    /// Requests refused for want of room
    pub refused: std::sync::atomic::AtomicU64,
    /// Questions whether it has a chunk that reached it, answered or not
    pub probed: std::sync::atomic::AtomicU64,
    /// Such questions it was answering at once, now and at most
    pub probing: std::sync::atomic::AtomicU64,
    pub probing_most: std::sync::atomic::AtomicU64,
}

pub struct Node {
    pub index: usize,
    pub ip: IpAddr,
    pub cfg: NodeConfig,
    pub store: Arc<MemStore>,
    world: Weak<World>,
    live: Mutex<Arc<Live>>,
    task: Mutex<Option<JoinHandle<()>>>,
    /// The task that sends the updates of the filter
    filter_task: Mutex<Option<JoinHandle<()>>>,
    epoch: std::sync::atomic::AtomicU64,
    /// Which identity the node has: it changes only when the node is
    /// started with a new one, as a service whose identity file is gone
    identity: std::sync::atomic::AtomicU64,
}

impl Node {
    pub(super) fn new(world: &Arc<World>, index: usize, cfg: NodeConfig) -> Arc<Self> {
        let ip = node_ip(&cfg, index);
        let node = Arc::new_cyclic(|me| Self {
            index,
            ip,
            live: Mutex::new(Live::build(me, world, index, &cfg, 0, 0)),
            cfg,
            store: Arc::default(),
            world: Arc::downgrade(world),
            task: Mutex::new(None),
            filter_task: Mutex::new(None),
            epoch: std::sync::atomic::AtomicU64::new(1),
            identity: std::sync::atomic::AtomicU64::new(0),
        });
        node.spawn();
        node
    }

    pub fn world(&self) -> Arc<World> {
        self.world.upgrade().expect("the world is alive")
    }

    pub fn live(&self) -> Arc<Live> {
        self.live.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// The node as the transport of its own requests: what a scenario calls
    /// to make a node ask like a peer (a probe).
    pub fn transport(self: &Arc<Self>) -> super::SimTransport {
        super::SimTransport::new(Arc::downgrade(self))
    }

    pub fn id(&self) -> PeerId {
        self.live().id
    }

    /// Start the node again after it stopped: the same identity (the service
    /// keeps it in a file) or, `new_identity`, a new one (the file is gone),
    /// and new state, the store kept.
    pub(super) fn start(self: &Arc<Self>, new_identity: bool) {
        let world = self.world();
        let epoch = self
            .epoch
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let identity = if new_identity {
            self.identity
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                + 1
        } else {
            self.identity.load(std::sync::atomic::Ordering::Relaxed)
        };
        let live = Live::build(
            &Arc::downgrade(self),
            &world,
            self.index,
            &self.cfg,
            epoch,
            identity,
        );
        *self.live.lock().unwrap_or_else(|e| e.into_inner()) = live;
        self.spawn();
    }

    fn spawn(self: &Arc<Self>) {
        let world = self.world();
        world.net.set_alive(self.index, true);
        let (me, live) = (self.clone(), self.live());
        // (a node that starts holds what its store holds: the service
        // follows the store service, whose snapshot says it)
        live.advertisement.add(&self.store.layers());
        let task = tokio::spawn(async move { me.run(live.clone()).await });
        *self.task.lock().unwrap_or_else(|e| e.into_inner()) = Some(task);
        let (me, live) = (Arc::downgrade(self), self.live());
        let never = std::future::pending::<()>();
        let sender = tokio::spawn(crate::filter::run(
            live.advertisement.clone(),
            self.cfg.filter.interval,
            never,
            move |msg| {
                let me = me.upgrade();
                async move {
                    if let Some(me) = me {
                        for peer in me.connected() {
                            let (me, msg) = (me.clone(), vec![msg.clone()]);
                            tokio::spawn(async move { me.tell(peer, msg).await });
                        }
                    }
                    true
                }
            },
        ));
        if let Some(old) = self
            .filter_task
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .replace(sender)
        {
            old.abort();
        }
    }

    /// Stop the node: its connections are gone, nothing reaches it.
    pub fn stop(self: &Arc<Self>) {
        let world = self.world();
        world.net.set_alive(self.index, false);
        if let Some(task) = self.task.lock().unwrap_or_else(|e| e.into_inner()).take() {
            task.abort();
        }
        if let Some(task) = self
            .filter_task
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
        {
            task.abort();
        }
        let live = self.live();
        let peers: Vec<PeerId> = live
            .conns
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .keys()
            .copied()
            .collect();
        world.trace(self.index, || {
            format!("stops, {} connections close", peers.len())
        });
        for peer in peers {
            world.disconnect(self, peer);
        }
    }

    pub fn is_up(&self) -> bool {
        self.task
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .is_some_and(|t| !t.is_finished())
    }

    pub fn set_behavior(&self, behavior: Behavior) {
        *self
            .live()
            .behavior
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = behavior;
    }

    /// The dials this node refused, by reason.
    pub fn dials_refused(&self) -> crate::control::DialsRefused {
        self.live().dial_counters.snapshot().dials_refused
    }

    pub fn behavior(&self) -> Behavior {
        *self
            .live()
            .behavior
            .lock()
            .unwrap_or_else(|e| e.into_inner())
    }

    /// The peers it is connected to (not those it only lent a place to).
    pub fn connected(&self) -> Vec<PeerId> {
        self.live()
            .conns
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .filter(|(_, c)| !c.passing)
            .map(|(p, _)| *p)
            .collect()
    }

    /// Everything it is connected to, those lent included.
    pub(super) fn connected_all(&self) -> Vec<PeerId> {
        self.live()
            .conns
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .keys()
            .copied()
            .collect()
    }

    /// The QUIC slots that are free now.
    pub fn quic_slots_free(&self) -> usize {
        self.live().quic_slots.available_permits()
    }

    /// How many connections it has, those lent included.
    pub fn connections(&self) -> usize {
        self.live()
            .conns
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .len()
    }

    /// The node holds `layer` now: its chunks are served, the DHT has a
    /// record, and its filter takes the layer (the peers are told within
    /// the interval of the filter).
    pub async fn complete_layer(self: &Arc<Self>, layer: &Layer) {
        self.store.add(layer);
        let world = self.world();
        let live = self.live();
        world.dht.publish(&layer.digest, live.id);
        live.advertisement.add(std::slice::from_ref(&layer.digest));
    }

    /// Tell every peer a filter that says this node holds `layers`, whether
    /// it does or not (a node whose store lost them says so until it finds out).
    pub async fn announce_falsely(self: &Arc<Self>, layers: &[String]) {
        let mut told = crate::filter::Advertiser::new(
            self.cfg.filter,
            crate::entropy::Entropy::seeded(self.index as u64 ^ 0x11e5),
        );
        told.add(layers);
        if let Some(filter) = told.full() {
            self.tell_all(filter);
        }
    }

    /// Tell every peer `message`, as it came from this node.
    pub fn tell_all(self: &Arc<Self>, message: GossipMessage) {
        for peer in self.connected() {
            let (me, msg) = (self.clone(), vec![message.clone()]);
            tokio::spawn(async move { me.tell(peer, msg).await });
        }
    }

    /// Tell `peer` what the gossip says (its messages arrive after the
    /// trip).
    pub(super) async fn tell(self: &Arc<Self>, peer: PeerId, messages: Vec<GossipMessage>) {
        let world = self.world();
        let Some(other) = world.node_of(peer) else {
            return;
        };
        let bytes = 64
            + messages
                .iter()
                .map(|m| serde_json::to_vec(m).map_or(0, |v| v.len() as u64))
                .sum::<u64>();
        if world
            .net
            .send(self.index, other.index, bytes)
            .await
            .is_err()
        {
            return;
        }
        let from = self.id();
        let theirs = other.live();
        for message in messages {
            theirs.gossip.handle_gossip_message(from, message).await;
        }
    }

    /// The loop of the node: the timers of the bootstrap and of the lent
    /// connections, armed by the connections coming and going, not polled.
    async fn run(self: Arc<Self>, live: Arc<Live>) {
        let world = self.world();
        // (the first dial, then again while it has too few peers)
        let first = live
            .bootstrap
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .addresses()
            .to_vec();
        self.dial_all(&first);
        let mut kad_at = Instant::now() + KAD_INTERVAL;
        loop {
            let wake = live.wake.notified();
            tokio::pin!(wake);
            wake.as_mut().enable();
            let (boot, lent) = (
                live.bootstrap
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .deadline(),
                live.exchange
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .deadline(),
            );
            tokio::select! {
                biased;
                _ = &mut wake => {}
                _ = sleep_until(boot) => {
                    let connected = live.conns.lock().unwrap_or_else(|e| e.into_inner()).len();
                    let due: Vec<_> = live
                        .bootstrap
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .fired(connected, Instant::now())
                        .to_vec();
                    world.trace(self.index, || format!("{connected} peers: the bootstrap peers again"));
                    self.dial_all(&due);
                    if connected > 0 {
                        if self.cfg.kad {
                            self.kad_bootstrap();
                        }
                        self.ask_some_peers();
                    }
                }
                _ = sleep_until(Some(kad_at)) => {
                    kad_at = Instant::now() + KAD_INTERVAL;
                    if self.cfg.kad {
                        self.kad_bootstrap();
                    }
                }
                _ = sleep_until(lent) => {
                    let over = live
                        .exchange
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .expired(Instant::now());
                    for peer in over {
                        world.trace(self.index, || format!("the exchange with {} is over", world.label(peer)));
                        world.disconnect(&self, peer);
                    }
                }
            }
        }
    }

    /// Dial the nodes at `addresses` that it is not connected to.
    fn dial_all(self: &Arc<Self>, addresses: &[libp2p::Multiaddr]) {
        let world = self.world();
        for address in addresses {
            let Some(target) = world.node_at(address) else {
                continue;
            };
            if self.connected_to(target.index) {
                continue;
            }
            let me = self.clone();
            tokio::spawn(async move { world_dial(&me, &target).await });
        }
    }

    fn connected_to(&self, index: usize) -> bool {
        let world = self.world();
        let Some(other) = world.node(index) else {
            return false;
        };
        self.live()
            .conns
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .contains_key(&other.id())
    }

    /// Ask a few of the peers it is connected to, at random, which others they
    /// know.
    fn ask_some_peers(self: &Arc<Self>) {
        if !self.cfg.exchange || !self.wants_peers() {
            return;
        }
        let world = self.world();
        let live = self.live();
        let mut members = self.connected();
        members.sort();
        live.entropy.shuffle(&mut members);
        for peer in members.into_iter().take(peer_exchange::ASKED_PEERS) {
            if let Some(other) = world.node_of(peer) {
                self.ask_for_peers(&other);
            }
        }
    }

    /// Whether the node asks for peers: with few, counting those it is
    /// dialing for an answer (`Exchanging::wants_peers` of the node).
    pub(super) fn wants_peers(&self) -> bool {
        let live = self.live();
        let connected = live.conns.lock().unwrap_or_else(|e| e.into_inner()).len();
        let dialing = live
            .exchange_dialing
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .len();
        let wants = live
            .bootstrap
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .wants_peers(connected + dialing);
        wants
    }

    /// Ask `other` which peers it knows, and dial some of what it tells: the
    /// real rules of `peer_exchange` (what it tells, what is learnt from
    /// it, how often) on the simulated network.
    pub(super) fn ask_for_peers(self: &Arc<Self>, other: &Arc<Node>) {
        let (me, other) = (self.clone(), other.clone());
        tokio::spawn(async move {
            let world = me.world();
            let (mine, theirs) = (me.live(), other.live());
            let now = Instant::now();
            if !mine
                .peers
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .1
                .may_ask(theirs.id, now)
            {
                return;
            }
            if world.net.send(me.index, other.index, 60).await.is_err() {
                return;
            }
            let behavior = other.behavior();
            // (a newcomer that was answered has what it came for)
            theirs
                .exchange
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .served(mine.id, now);
            theirs.wake.notify_one();
            let told = match behavior {
                Behavior::Silent => super::net::Net::lost().await,
                _ => {
                    let theirs_state = theirs.peers.lock().unwrap_or_else(|e| e.into_inner());
                    let members: BTreeSet<PeerId> = other.connected().into_iter().collect();
                    theirs_state.0.answer(
                        &mine.id,
                        |p| members.contains(p),
                        &theirs.filter,
                        &theirs.entropy,
                    )
                }
            };
            if world
                .net
                .send(other.index, me.index, 100 + 120 * told.len() as u64)
                .await
                .is_err()
            {
                return;
            }
            let connected: BTreeSet<PeerId> = me.connected_all().into_iter().collect();
            let learned = peer_exchange::accepted(
                &told,
                &mine.id,
                &mine.filter,
                |p| connected.contains(p),
                peer_exchange::MAX_DIALS,
            );
            world.trace(me.index, || {
                format!(
                    "{} named {} peers, {} to dial",
                    world.label(other.id()),
                    told.len(),
                    learned.len()
                )
            });
            let dials: Vec<_> = learned
                .into_iter()
                .map(|(peer, addresses)| {
                    let me = me.clone();
                    let dialing = &mine.exchange_dialing;
                    dialing
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .insert(peer);
                    async move {
                        for address in addresses {
                            if me.world().dial_named(&me, peer, &address).await {
                                break;
                            }
                        }
                        // (connected, it was no longer counted: see `World::dial`)
                        dialing
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .remove(&peer);
                    }
                })
                .collect();
            futures::future::join_all(dials).await;
        });
    }

    /// What Kademlia does for a node with few peers, and every few minutes
    /// for all: ask a few peers it knows which others they know (connecting
    /// to the ones it is not connected to; one that does not answer is
    /// forgotten), and connect to some of what they tell.  A model: the walk
    /// of the real thing is libp2p's, not decided here.
    pub(super) fn kad_bootstrap(self: &Arc<Self>) {
        let me = self.clone();
        tokio::spawn(async move {
            let world = me.world();
            let live = me.live();
            let entropy = live.entropy.clone();
            // (the peers it is connected to first: a lent connection is for
            // this, and what is kept of the others is a table of addresses)
            let mut peers: Vec<PeerId> = live
                .conns
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .keys()
                .copied()
                .collect();
            let mut known: Vec<PeerId> = live
                .known
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .iter()
                .copied()
                .filter(|p| !peers.contains(p))
                .collect();
            peers.sort();
            entropy.shuffle(&mut peers);
            entropy.shuffle(&mut known);
            peers.extend(known);
            let mut learned: Vec<PeerId> = Vec::new();
            let mut asked = 0;
            for peer in peers {
                if asked >= KAD_ASKED {
                    break;
                }
                let Some(other) = world.node_of(peer) else {
                    live.known
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .remove(&peer);
                    continue;
                };
                if !world.dial(&me, &other).await {
                    live.known
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .remove(&peer);
                    continue;
                }
                asked += 1;
                // a round trip to the peer
                if world.net.send(me.index, other.index, 100).await.is_err() {
                    continue;
                }
                let mut theirs: Vec<PeerId> = other
                    .live()
                    .known
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .iter()
                    .copied()
                    .filter(|p| *p != live.id)
                    .collect();
                entropy.shuffle(&mut theirs);
                theirs.truncate(KAD_ANSWER);
                if world
                    .net
                    .send(other.index, me.index, 100 + 40 * theirs.len() as u64)
                    .await
                    .is_err()
                {
                    continue;
                }
                learned.extend(theirs);
            }
            learned.sort();
            learned.dedup();
            live.known
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .extend(learned.iter().copied());
            let dials = learned
                .into_iter()
                .filter_map(|p| world.node_of(p))
                .take(KAD_DIALS);
            let handles: Vec<_> = dials
                .map(|target| {
                    let me = me.clone();
                    async move { world_dial(&me, &target).await }
                })
                .collect();
            futures::future::join_all(handles).await;
        });
    }
}

/// The address of the node `index`: its own, or one of the network.
fn node_ip(cfg: &NodeConfig, index: usize) -> IpAddr {
    cfg.ip
        .unwrap_or_else(|| IpAddr::from([10, (index >> 16) as u8, (index >> 8) as u8, index as u8]))
}

/// The peers a node asks which others they know, and how many each tells, and
/// how many it then dials: the shape of a Kademlia bootstrap.
const KAD_ASKED: usize = 3;
const KAD_ANSWER: usize = 20;
const KAD_DIALS: usize = 20;
/// How often a node walks the DHT again by itself (libp2p's automatic
/// bootstrap).
const KAD_INTERVAL: Duration = Duration::from_secs(300);

async fn sleep_until(at: Option<Instant>) {
    match at {
        Some(at) => tokio::time::sleep_until(at).await,
        None => std::future::pending().await,
    }
}

async fn world_dial(me: &Arc<Node>, target: &Arc<Node>) -> bool {
    me.world().dial(me, target).await
}

impl Live {
    fn build(
        me: &Weak<Node>,
        world: &Arc<World>,
        index: usize,
        cfg: &NodeConfig,
        epoch: u64,
        identity: u64,
    ) -> Arc<Self> {
        let ip = node_ip(cfg, index);
        let dial_counters: Arc<crate::stats::Counters> = Arc::default();
        let id = super::peer_id(world.seed, index, identity);
        let entropy = Entropy::seeded(world.seed ^ ((index as u64) << 20) ^ (epoch << 8) ^ 0x5eed);
        let knowledge = Arc::new(crate::knowledge::Knowledge::with_entropy(entropy.clone()));
        let bootstrap_addresses = cfg.bootstrap.iter().map(|&i| world.address_of(i)).collect();
        Arc::new(Self {
            id,
            conns: Mutex::default(),
            known: Mutex::default(),
            bootstrap: Mutex::new(Bootstrap::new(
                bootstrap_addresses,
                cfg.min_peers,
                Backoff::new(cfg.backoff.0, cfg.backoff.1).with_entropy(entropy.clone()),
                Instant::now(),
            )),
            exchange: Mutex::new(Exchange::new(cfg.max_incoming as usize)),
            peers: Mutex::default(),
            exchange_dialing: Default::default(),
            filter: DialFilter::with_own(
                Rules::default(),
                &[],
                dial_counters.clone(),
                Box::new(move || vec![ip]),
            ),
            dial_counters,
            gossip: Arc::new(
                if cfg.announce {
                    GossipDiscovery::announcing()
                } else {
                    GossipDiscovery::new()
                }
                .with_knowledge(knowledge.clone()),
            ),
            advertisement: crate::filter::Advertisement::new(
                cfg.filter,
                Entropy::seeded(world.seed ^ ((index as u64) << 20) ^ (epoch << 8) ^ 0xf11),
            ),
            admission: Arc::new(Admission::new(&cfg.serving)),
            quic_slots: Arc::new(Semaphore::new(cfg.serving.quic_slots)),
            source: Arc::new(
                PeerSource::with_peers(Arc::new(NodePeers(Arc::new(
                    super::transport::SimTransport::new(me.clone()),
                ))))
                .with_policy(cfg.policy)
                .with_knowledge(knowledge),
            ),
            providers: Default::default(),
            quic_failed: Mutex::default(),
            wake: Notify::new(),
            behavior: Mutex::new(cfg.behavior),
            counters: Counters::default(),
            entropy,
        })
    }
}
