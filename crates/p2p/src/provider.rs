// SPDX-License-Identifier: Apache-2.0
//! How the P2P service asks the peers.
//!
//! To the engine the service is one more fetcher (`org.velarx.Fetcher`,
//! [`crate::staging`]) on its own socket: it stages what
//! the peers have.  To the peers it is a server of the chunks of the
//! store, which it asks for through the store service.  It tells the peers
//! the layers it holds as a filter ([`crate::filter`]) and their filters say
//! whom to ask for a layer; the peers that have none are asked one digest at
//! a time.

use super::entropy::Entropy;
use super::explain::{note, Decisions, Event, Kind, Outcome, Why};
use super::knowledge::{Filtered, Knowledge};
use super::limits::{short, MAX_ITEM_BYTES, MAX_REQUEST_DIGESTS};
use super::probes::{self, Probed};
use super::shared::Shared;
use super::{P2PNode, Presence};
use async_trait::async_trait;
use libp2p::PeerId;
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, warn};
use velarx_content::fetcher::fetch::Urgency;

/// Providers asked for a chunk, in turn
const MAX_PROVIDERS: usize = 3;

/// How long the peers have to answer the question whether they have a chunk
/// (the answers that came by then count).
const QUERY_WAIT: Duration = Duration::from_secs(2);

/// An error of the node asking a peer, as the source of a pull tells it.
fn peer_error(e: crate::P2PError) -> PeerError {
    match e {
        crate::P2PError::Busy => PeerError::Busy,
        crate::P2PError::NoQuicPath { reason, .. } => PeerError::NoQuic(reason),
        e => PeerError::Failed(e.to_string()),
    }
}

/// Why a peer did not send the chunks asked of it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerError {
    /// It had no room to answer: it may well have the chunks, and is not
    /// at fault
    Busy,
    /// There is no QUIC (UDP) path to it: it is not asked for data, and the
    /// reason says why (it is a member for discovery all the same)
    NoQuic(String),
    /// The request failed
    Failed(String),
}

impl std::fmt::Display for PeerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Busy => f.write_str("the peer has no room to answer"),
            Self::NoQuic(why) => write!(f, "no QUIC (UDP) path: {why}"),
            Self::Failed(e) => f.write_str(e),
        }
    }
}

impl From<String> for PeerError {
    fn from(e: String) -> Self {
        Self::Failed(e)
    }
}

/// How the peers are reached: the node, or a fake in the tests.
#[async_trait]
pub trait Peers: Send + Sync + 'static {
    /// The peers that are connected.
    async fn connected(&self) -> Vec<PeerId>;
    /// The providers of the layer the DHT names (connected to first).
    async fn layer_providers(&self, layer: &str) -> Vec<PeerId>;
    /// The chunks of `items` that `peer` has, unchecked, into `out` as each
    /// arrives, asked as `urgency` says.
    async fn request(
        &self,
        peer: PeerId,
        items: &[(String, Option<u64>)],
        urgency: Urgency,
        out: super::ChunkTx,
    ) -> Result<(), PeerError>;
    /// The index of a layer, if the peer has one of at most `max` bytes.
    async fn index(
        &self,
        peer: PeerId,
        layer: &str,
        max: u64,
    ) -> Result<Option<Vec<u8>>, PeerError>;
    /// How many of the connected peers have no QUIC path: members for
    /// discovery, not asked for data.
    async fn without_quic(&self) -> usize {
        0
    }
    /// Whether `peer` has the chunk `digest` (it would serve it).
    async fn has(&self, peer: PeerId, digest: &str) -> Result<Presence, String>;
    /// The streams a request for `chunks` chunks opens to a peer.
    /// This node holds files of `layer` now (a pull stages them): tell the
    /// peers.
    async fn holding(&self, _layer: &str) {}

    /// The connected peers whose certificate names another zone than this
    /// node's: asked after the ones of its own zone.
    async fn far(&self) -> HashSet<PeerId> {
        HashSet::new()
    }

    fn streams(&self, _chunks: usize) -> usize {
        1
    }
    /// The bytes of chunks read from the peers so far, as they come: what
    /// tells a slow answer from none before it is complete.
    fn received(&self) -> u64 {
        0
    }
    /// The startup profile of an image, if the peer has one of at most
    /// `max` bytes.
    async fn profile(
        &self,
        peer: PeerId,
        image: &str,
        max: u64,
    ) -> Result<Option<Vec<u8>>, PeerError>;
}

/// What the peers are asked through: the node (QUIC, the DHT), or the
/// simulated network of the simulator.
#[async_trait]
pub trait Transport: Send + Sync + 'static {
    /// The peers connected.
    async fn connected(&self) -> Vec<PeerId>;
    /// The peers that provide `layer` by the DHT.
    async fn find_providers(&self, layer: &str) -> Vec<PeerId>;
    /// Connect to a provider the DHT named; whether it is connected.
    async fn connect_provider(&self, peer: PeerId) -> bool;
    /// This node holds files of `layer` now: tell the peers.
    async fn holding(&self, _layer: &str) {}
    /// The connected peers of another zone than this node's.
    async fn far(&self) -> HashSet<PeerId> {
        HashSet::new()
    }
    /// The streams a request for `chunks` chunks is spread over.
    fn streams_of(&self, _chunks: usize) -> usize {
        1
    }
    /// The bytes of chunks read from the peers so far, as they come.
    fn received(&self) -> u64 {
        0
    }
    /// The chunks over QUIC, unchecked, into `out` as each arrives; an error
    /// when there is no QUIC path to the peer (there is no other way to fetch
    /// from it).
    async fn fetch_into(
        &self,
        peer: PeerId,
        items: &[(String, Option<u64>)],
        urgency: Urgency,
        out: super::ChunkTx,
    ) -> super::P2PResult<()>;
    /// How many of the connected peers have no QUIC path: members for
    /// discovery, not asked for data.
    async fn without_quic(&self) -> usize {
        0
    }
    async fn probe(&self, peer: PeerId, digest: &str) -> super::P2PResult<Presence>;
    async fn request_index(
        &self,
        peer: PeerId,
        layer: &str,
        max: u64,
    ) -> super::P2PResult<Option<Vec<u8>>>;
    async fn request_profile(
        &self,
        peer: PeerId,
        image: &str,
        max: u64,
    ) -> super::P2PResult<Option<Vec<u8>>>;
}

#[async_trait]
impl Transport for P2PNode {
    async fn connected(&self) -> Vec<PeerId> {
        self.peers().await.into_iter().map(|p| p.peer_id).collect()
    }

    fn streams_of(&self, chunks: usize) -> usize {
        P2PNode::streams_of(self, chunks)
    }

    fn received(&self) -> u64 {
        self.quic.as_ref().map_or(0, |q| q.received())
    }

    async fn holding(&self, layer: &str) {
        let _ = self.announce_layers(vec![layer.to_string()]).await;
    }

    async fn far(&self) -> HashSet<PeerId> {
        P2PNode::far(self).await
    }

    async fn find_providers(&self, layer: &str) -> Vec<PeerId> {
        P2PNode::find_providers(self, layer).await
    }

    async fn connect_provider(&self, peer: PeerId) -> bool {
        P2PNode::connect_provider(self, peer).await
    }

    async fn fetch_into(
        &self,
        peer: PeerId,
        items: &[(String, Option<u64>)],
        urgency: Urgency,
        out: super::ChunkTx,
    ) -> super::P2PResult<()> {
        P2PNode::fetch_into(self, peer, items, urgency, out).await
    }

    async fn without_quic(&self) -> usize {
        P2PNode::without_quic(self).await
    }

    async fn probe(&self, peer: PeerId, digest: &str) -> super::P2PResult<Presence> {
        P2PNode::probe(self, peer, digest).await
    }

    async fn request_index(
        &self,
        peer: PeerId,
        layer: &str,
        max: u64,
    ) -> super::P2PResult<Option<Vec<u8>>> {
        P2PNode::request_index(self, peer, layer, max).await
    }

    async fn request_profile(
        &self,
        peer: PeerId,
        image: &str,
        max: u64,
    ) -> super::P2PResult<Option<Vec<u8>>> {
        P2PNode::request_profile(self, peer, image, max).await
    }
}

/// The peers as `T` reaches them: over QUIC, the only way data goes.
pub struct NodePeers<T: Transport = P2PNode>(pub Arc<T>);

#[async_trait]
impl<T: Transport> Peers for NodePeers<T> {
    async fn connected(&self) -> Vec<PeerId> {
        self.0.connected().await
    }

    async fn layer_providers(&self, layer: &str) -> Vec<PeerId> {
        let providers = self.0.find_providers(layer).await;
        // The providers the DHT named that are not connected are dialed,
        // few and at once; the ones that connected are the answer too.
        let connected: HashSet<PeerId> = self.connected().await.into_iter().collect();
        let (mut found, away): (Vec<PeerId>, Vec<PeerId>) =
            providers.into_iter().partition(|p| connected.contains(p));
        let dialed = futures::future::join_all(
            away.into_iter()
                .take(super::MAX_DIALED)
                .map(|p| async move { self.0.connect_provider(p).await.then_some(p) }),
        )
        .await;
        found.extend(dialed.into_iter().flatten());
        found
    }

    async fn request(
        &self,
        peer: PeerId,
        items: &[(String, Option<u64>)],
        urgency: Urgency,
        out: super::ChunkTx,
    ) -> Result<(), PeerError> {
        self.0
            .fetch_into(peer, items, urgency, out)
            .await
            .map_err(peer_error)
    }

    async fn index(
        &self,
        peer: PeerId,
        layer: &str,
        max: u64,
    ) -> Result<Option<Vec<u8>>, PeerError> {
        self.0
            .request_index(peer, layer, max)
            .await
            .map_err(peer_error)
    }

    async fn profile(
        &self,
        peer: PeerId,
        image: &str,
        max: u64,
    ) -> Result<Option<Vec<u8>>, PeerError> {
        self.0
            .request_profile(peer, image, max)
            .await
            .map_err(peer_error)
    }

    async fn has(&self, peer: PeerId, digest: &str) -> Result<Presence, String> {
        self.0.probe(peer, digest).await.map_err(|e| e.to_string())
    }

    async fn holding(&self, layer: &str) {
        self.0.holding(layer).await
    }

    async fn far(&self) -> HashSet<PeerId> {
        self.0.far().await
    }

    fn streams(&self, chunks: usize) -> usize {
        self.0.streams_of(chunks)
    }

    fn received(&self) -> u64 {
        self.0.received()
    }
    async fn without_quic(&self) -> usize {
        self.0.without_quic().await
    }
}

/// Whether `text` is a startup profile: one with at least one digest, as
/// the file system that uses it reads it (`velarx_fuse::profile::parse`).
fn looks_like_a_profile(text: &[u8]) -> bool {
    !velarx_fuse::profile::parse(text, 1).is_empty()
}

/// Chunks of fewer bytes than this are hashed where they arrive; bigger ones
/// on a blocking thread.
const CHECK_INLINE_BYTES: usize = 64 << 10;

/// The chunks of one request hashed at the same time, as they arrive.
const CHECKS_AT_ONCE: usize = 4;

/// The chunk, and whether its bytes have the digest it was asked by (hashed
/// once: this is the check of the bytes of the peers).  A check that did not
/// end (the runtime shuts down) failed.
async fn checked(wanted: String, data: Vec<u8>) -> (String, Vec<u8>, bool) {
    if data.len() <= CHECK_INLINE_BYTES {
        let matches = crate::limits::names(&wanted, &data);
        return (wanted, data, matches);
    }
    let digest = wanted.clone();
    tokio::task::spawn_blocking(move || {
        let matches = crate::limits::names(&wanted, &data);
        (wanted, data, matches)
    })
    .await
    .unwrap_or((digest, Vec::new(), false))
}

/// What a fetch asks for: a digest, and its size if the asker knows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Item {
    pub digest: String,
    pub size: Option<u64>,
}

/// Where the verified chunks go: the answer to the pull engine.
#[async_trait]
pub trait Sink: Send {
    async fn put(&mut self, digest: &str, data: &[u8]) -> Result<(), String>;

    /// What was put since the last flush is passed on.
    async fn flush(&mut self) -> Result<(), String> {
        Ok(())
    }
}

/// How the peers are asked.
#[derive(Debug, Clone, Copy)]
pub struct Policy {
    /// Ask a second peer when the first is slow
    pub hedge: bool,
    /// How long to wait for a peer before that; None: from how long it
    /// usually takes (`Knowledge::hedge_delay`)
    pub hedge_delay: Option<Duration>,
    /// The peers that have the layer a big group is spread over (0 or 1:
    /// one at a time)
    pub stripe_peers: usize,
    /// The connected peers asked at once whether they have a chunk when
    /// none is known to (0: none is asked, the chunks are asked of the
    /// first ones)
    pub query_peers: usize,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            hedge: true,
            hedge_delay: None,
            stripe_peers: 3,
            query_peers: 8,
        }
    }
}

/// The bytes of a part of a group that is spread over several peers: what
/// a peer is asked for at a time.
pub const STRIPE_BYTES: u64 = 2 << 20;
/// A group is spread when it is at least this big (two parts).
pub const STRIPE_MIN_BYTES: u64 = 2 * STRIPE_BYTES;
/// The parts a peer is asked for at the same time, so that it never waits
/// for the next request.
const STRIPE_DEPTH: usize = 2;
/// The chunks of a part, at most.
const STRIPE_ITEMS: usize = 64;
/// A part is asked of a second peer only when the first took this many times
/// as long as the quickest peer of the group takes for a request: when every
/// peer is slow alike, the bottleneck is this node's own link, and asking
/// more of them only sends the same bytes twice over it.
const LATE_FACTOR: u32 = 3;
/// The bytes asked twice (hedged) that were not needed, and the hedges under
/// way, are at most this share of the bytes asked, and one part.
const HEDGED_SHARE: u64 = 8;

/// The parts of a group for striping: the items in order, cut at
/// [`STRIPE_BYTES`] (a chunk of unknown size counts as none) or
/// [`STRIPE_ITEMS`]; `None` when the group is too small to be spread.
fn stripe_parts(items: &[Item]) -> Option<Vec<Vec<usize>>> {
    let total: u64 = items.iter().filter_map(|i| i.size).sum();
    if total < STRIPE_MIN_BYTES || items.len() < 2 {
        return None;
    }
    let mut parts: Vec<Vec<usize>> = Vec::new();
    let mut bytes = 0u64;
    for (i, item) in items.iter().enumerate() {
        let size = item.size.unwrap_or(0);
        match parts.last_mut() {
            Some(part) if bytes + size <= STRIPE_BYTES && part.len() < STRIPE_ITEMS => {
                part.push(i);
                bytes += size;
            }
            _ => {
                parts.push(vec![i]);
                bytes = size;
            }
        }
    }
    (parts.len() > 1).then_some(parts)
}

/// A group that has been waiting this long may be given up when the peers
/// are slow.
const SLOW_AFTER: Duration = Duration::from_secs(5);
/// The peers are slow when they give this node, over a few seconds, less
/// than this share of the most they have given it.
const SLOW_SHARE: f64 = 4.0;
/// ... and that most is at least this many bytes a second.  A swarm that
/// was never as quick (it is slow or mute from the first byte on) is slow
/// when it gave this node less than a quarter of this since the group began
/// (as the bytes come, not only whole answers): it is slower than any
/// registry.
const SLOW_FLOOR: f64 = (4 << 20) as f64;
/// The most is halved every so long.
const BEST_HALF_LIFE: Duration = Duration::from_secs(600);
/// The rate is taken over this long.
const RATE_WINDOW: Duration = Duration::from_secs(5);

/// What the peers give this node, all its groups together: the rate over
/// the last seconds, and the most it was.  A swarm that gives much less
/// than it did (a seed that every node of a rollout asks, peers that are
/// slow) is not waited for: the registry is quicker.
#[derive(Default)]
struct Rate {
    state: std::sync::Mutex<RateState>,
}

#[derive(Default)]
struct RateState {
    /// The bytes of the answers taken, and of the chunks read as they come
    /// (what tells a slow answer from none before it is complete): the
    /// bytes given are the larger
    bytes: u64,
    received: u64,
    /// The bytes given at the last seconds
    points: std::collections::VecDeque<(tokio::time::Instant, u64)>,
    best: f64,
    best_at: Option<tokio::time::Instant>,
}

impl RateState {
    /// The rate over the window, if it is all there (the first point is
    /// about [`RATE_WINDOW`] old), and the most it was, aged.  The most
    /// is raised by what is measured.
    fn roll(&mut self) -> Option<(f64, f64)> {
        let now = tokio::time::Instant::now();
        if self
            .points
            .back()
            .is_none_or(|(t, _)| now.saturating_duration_since(*t) >= Duration::from_secs(1))
        {
            self.points.push_back((now, self.given()));
        }
        while self
            .points
            .get(1)
            .is_some_and(|(t, _)| now.saturating_duration_since(*t) >= RATE_WINDOW)
        {
            self.points.pop_front();
        }
        // (a point from before a pause is no start of a window)
        if self.points.front().is_some_and(|(t, _)| {
            now.saturating_duration_since(*t) > RATE_WINDOW + Duration::from_secs(1)
        }) {
            self.points.pop_front();
        }
        let aged = self.best_at.map_or(0.0, |t| {
            0.5f64
                .powf(now.saturating_duration_since(t).as_secs_f64() / BEST_HALF_LIFE.as_secs_f64())
        });
        let (t, before) = *self.points.front()?;
        let span = now.saturating_duration_since(t);
        if span < RATE_WINDOW - Duration::from_secs(1) {
            return None;
        }
        let rate = (self.given() - before) as f64 / span.as_secs_f64();
        if rate >= self.best * aged {
            self.best = rate;
            self.best_at = Some(now);
            return Some((rate, rate));
        }
        Some((rate, self.best * aged))
    }

    fn given(&self) -> u64 {
        self.bytes.max(self.received)
    }
}

impl Rate {
    fn add(&self, n: u64) {
        let mut s = self.state.lock().unwrap_or_else(|e| e.into_inner());
        s.bytes += n;
        s.roll();
    }

    /// The rate of the last seconds and the most it was, with `received`
    /// bytes of chunks read so far.
    fn sample(&self, received: u64) -> Option<(f64, f64)> {
        let mut s = self.state.lock().unwrap_or_else(|e| e.into_inner());
        s.received = s.received.max(received);
        s.roll()
    }

    /// The bytes given so far.
    fn total(&self) -> u64 {
        self.state.lock().unwrap_or_else(|e| e.into_inner()).given()
    }
}

/// When a group began, and what the peers had given the node by then.
struct Began {
    at: tokio::time::Instant,
    given: u64,
}

/// What the peers have, as a content source.
pub struct PeerSource {
    pub(crate) peers: Arc<dyn Peers>,
    knowledge: Arc<Knowledge>,
    decisions: Arc<Decisions>,
    policy: Policy,
    /// The rounds of probes of the layers, shared by their groups
    rounds: Shared<Probed>,
    /// The probes in flight to each peer
    inflight: probes::InFlight,
    /// The requests for chunks in flight to each peer
    requested: Arc<probes::InFlight>,
    /// The places of those that nobody waits for: at most half of a peer's,
    /// the rest is always there for a request that is waited for
    unwaited: Arc<probes::InFlight>,
    /// The files this node staged, which it gives to the peers
    pub(crate) staged: Arc<crate::staged::Staged>,
    /// What the peers give this node
    rate: Rate,
}

impl PeerSource {
    pub fn new(node: Arc<P2PNode>) -> Self {
        let knowledge = node.knowledge().clone();
        Self::with_peers(Arc::new(NodePeers(node))).with_knowledge(knowledge)
    }

    pub fn with_peers(peers: Arc<dyn Peers>) -> Self {
        Self {
            peers,
            knowledge: Arc::new(Knowledge::default()),
            decisions: Arc::default(),
            policy: Policy::default(),
            rounds: Shared::default(),
            inflight: probes::InFlight::default(),
            requested: Arc::new(probes::InFlight::new(probes::STREAMS_PER_PEER)),
            unwaited: Arc::new(probes::InFlight::new(probes::STREAMS_PER_PEER / 2)),
            staged: Arc::default(),
            rate: Rate::default(),
        }
    }

    /// The same, keeping the files it stages in `staged` (what the node
    /// gives the peers).
    pub fn with_staged(mut self, staged: Arc<crate::staged::Staged>) -> Self {
        self.staged = staged;
        self
    }

    /// The same, with what is known of the peers taking its choices among
    /// equals from `entropy`.
    pub fn with_entropy(mut self, entropy: Entropy) -> Self {
        self.knowledge = Arc::new(Knowledge::with_entropy(entropy));
        self
    }

    /// The same, with the knowledge the node keeps what its peers tell in.
    pub fn with_knowledge(mut self, knowledge: Arc<Knowledge>) -> Self {
        self.knowledge = knowledge;
        self
    }

    pub fn with_policy(mut self, policy: Policy) -> Self {
        self.policy = policy;
        self
    }

    pub fn knowledge(&self) -> &Arc<Knowledge> {
        &self.knowledge
    }

    /// The recent decisions of the source: whom it asked and why.
    pub fn decisions(&self) -> &Arc<Decisions> {
        &self.decisions
    }

    /// What to tell an engine that nothing came from the peers (`what`: that
    /// none has it) when some of the peers connected could not be asked at
    /// all: they have no QUIC (UDP) path, which is not the same as having
    /// nothing, and an operator has to look at the network, not the store.
    pub(crate) async fn nobody(&self, what: &str) -> String {
        let (without, connected) = (
            self.peers.without_quic().await,
            self.peers.connected().await.len(),
        );
        match (without, connected) {
            (0, _) => what.to_string(),
            (n, c) if n >= c => format!(
                "no QUIC (UDP) path to any of the {c} connected peers (UDP blocked, or no QUIC \
                 endpoint advertised): {what}"
            ),
            (n, c) => format!("{what} ({n} of {c} connected peers have no QUIC (UDP) path)"),
        }
    }

    /// A group begins now.
    fn begin(&self) -> Began {
        self.rate.sample(self.peers.received());
        Began {
            at: tokio::time::Instant::now(),
            given: self.rate.total(),
        }
    }

    /// Whether the group `began` is to be given up: it waited
    /// [`SLOW_AFTER`] and the peers give this node less than a quarter of
    /// what they have given it at best, or they were never that quick and
    /// gave it less than a quarter of [`SLOW_FLOOR`] since the group began.
    fn slow(&self, began: &Began) -> bool {
        // (sampled from the start of the group, so that the window is full
        // when the group has waited long enough)
        let sample = self.rate.sample(self.peers.received());
        let waited = began.at.elapsed();
        if waited < SLOW_AFTER {
            return false;
        }
        let (rate, best) = match sample {
            Some((rate, best)) if best >= SLOW_FLOOR && rate * SLOW_SHARE < best => (rate, best),
            Some((_, best)) if best >= SLOW_FLOOR => return false,
            _ => {
                let since = (self.rate.total() - began.given) as f64 / waited.as_secs_f64();
                if since * SLOW_SHARE >= SLOW_FLOOR {
                    return false;
                }
                (since, sample.map_or(0.0, |(_, best)| best))
            }
        };
        note(|| Event::Slow {
            rate: rate as u64,
            best: best as u64,
        });
        true
    }

    /// A group was given up with requests still under way to `peers`: they
    /// did not answer in time, so the groups after it do not wait for them.
    fn skip(&self, peers: &[PeerId]) {
        for peer in peers {
            self.knowledge.failed(*peer);
        }
    }
}

/// What one request to one peer came to, after its chunks (each was handed
/// to the group as it arrived).
struct Attempt {
    request: u64,
    peer: PeerId,
    took: Duration,
    result: Result<(), PeerError>,
}

/// A chunk a peer sent, the request it came with, and whether its bytes
/// have the digest it was asked by.
struct Received {
    request: u64,
    peer: PeerId,
    digest: String,
    data: Vec<u8>,
    matches: bool,
}

/// What the requests of a group send back to it as they go: the chunks as
/// each arrives, and for each request under way how many of its chunks
/// matched and their bytes.
struct Answers {
    tx: tokio::sync::mpsc::Sender<Received>,
    rx: tokio::sync::mpsc::Receiver<Received>,
    valid: std::collections::HashMap<u64, (usize, u64)>,
    requests: u64,
}

impl Answers {
    fn new() -> Self {
        let (tx, rx) = tokio::sync::mpsc::channel(super::CHUNKS_IN_FLIGHT);
        Self {
            tx,
            rx,
            valid: Default::default(),
            requests: 0,
        }
    }
}

/// What an attempt came to for the group that asked.
enum Taken {
    /// It sent this many chunks that matched
    Sent(usize),
    /// The request failed
    Failed,
    /// The peer had no room: it is asked again when something completed
    Busy,
}

/// The peers a group asks at most, hedges and replacements included.
const MAX_ASKED: usize = 8;
/// The rounds of probes a group makes at most (`Policy::query_peers` each).
const PROBE_ROUNDS: usize = 2;

/// Where the candidates of a group come from.  The sources take turns, each
/// with at most so many peers at a time, so that the peers asked together
/// are not all of one origin (a filter is a peer's word: many identities can
/// give it, and one that lies costs the others nothing).
const SOURCES: [(Source, usize); 5] = [
    (Source::Served, 3),
    (Source::Filter, 3),
    (Source::Probed, 3),
    (Source::Dht, 3),
    (Source::Connected, 3),
];

#[derive(Clone, Copy)]
enum Source {
    /// The peers that served the layer lately
    Served,
    /// The connected peers whose filter says they may hold the layer
    Filter,
    /// The connected peers with no filter that is believed, that say they
    /// have the first chunk when asked
    Probed,
    /// The providers the DHT names (connected to by the lookup)
    Dht,
    /// Every connected peer
    Connected,
}

/// A search for the next peers of a group: what the group asked, given back
/// with the peers found.
type Search<'a> =
    std::pin::Pin<Box<dyn std::future::Future<Output = (Asked, Vec<(PeerId, Why)>)> + Send + 'a>>;

/// What a group has asked of the peers, and where it goes on when the ones
/// asked do not give.
#[derive(Default)]
struct Asked {
    /// The peers taken as candidates
    taken: HashSet<PeerId>,
    /// The peers that said they lack the chunk, or were asked whether they
    /// have it
    denied: HashSet<PeerId>,
    probed: HashSet<PeerId>,
    rounds: usize,
    dht: bool,
    /// What the filters said was noted
    said: bool,
    /// The source whose turn it is
    turn: usize,
    /// No source has a peer left
    done: bool,
}

impl Asked {
    /// Whether another peer may be asked.
    fn more(&self) -> bool {
        !self.done && self.taken.len() < MAX_ASKED
    }
}

impl PeerSource {
    /// The next peers to ask for the chunks of `layer`, the best first, when
    /// the ones asked did not give or are slow: never a peer of `got` or
    /// one known to have none of the layer.  Each source in its
    /// turn, the first that has a peer gives it (see [`SOURCES`]): the peers
    /// that served the layer lately (no lookup), the ones whose filter says
    /// they may hold it, the connected peers that have no filter that is
    /// believed and say they have the first chunk (asked at the same time
    /// for no longer than [`QUERY_WAIT`], those with no room after the ones
    /// that said yes), the providers the DHT names (connected to by the
    /// lookup), every connected peer.  A peer whose filter says it does not
    /// hold the layer is none of these but the first (it served the layer
    /// after the filter).  Nothing is asked of a source while the peers of the ones
    /// before it give.
    async fn more(&self, layer: Option<&str>, first: &str, got: &mut Asked) -> Vec<(PeerId, Why)> {
        if !got.more() {
            return Vec::new();
        }
        let room = MAX_ASKED - got.taken.len();
        for i in 0..SOURCES.len() {
            let at = (got.turn + i) % SOURCES.len();
            let (source, most) = SOURCES[at];
            let mut found = self.from(source, layer, first, got).await;
            found.truncate(most.min(room));
            if found.is_empty() {
                continue;
            }
            got.turn = (at + 1) % SOURCES.len();
            got.taken.extend(found.iter().map(|(p, _)| *p));
            debug!(
                candidates = ?found
                    .iter()
                    .map(|(p, w)| format!("{p} {}", w.name()))
                    .collect::<Vec<_>>(),
                "candidates"
            );
            note(|| Event::Candidates(found.clone()));
            return found;
        }
        got.done = true;
        Vec::new()
    }

    /// [`Self::more`] as a future that owns what the group asked, to be
    /// polled beside the requests under way.
    fn search<'a>(&'a self, layer: Option<&'a str>, first: &'a str, mut got: Asked) -> Search<'a> {
        Box::pin(async move {
            let found = self.more(layer, first, &mut got).await;
            (got, found)
        })
    }

    /// The peers `source` has for the group, that it can ask and has not.
    async fn from(
        &self,
        source: Source,
        layer: Option<&str>,
        first: &str,
        got: &mut Asked,
    ) -> Vec<(PeerId, Why)> {
        let mut connected: HashSet<PeerId> = self.peers.connected().await.into_iter().collect();
        let far = self.peers.far().await;
        // (what the filters of the peers say of the layer: no peer is
        // probed or asked that says it does not hold it)
        let filtered = layer
            .map(|l| self.knowledge.filtered(l))
            .unwrap_or_default();
        let usable = |got: &Asked, connected: &HashSet<PeerId>, p: &PeerId| {
            connected.contains(p)
                && !got.taken.contains(p)
                && !got.denied.contains(p)
                && !self.knowledge.failing(p)
                && !layer.is_some_and(|l| self.knowledge.lacks(l, p))
        };
        let mut found: Vec<(PeerId, Why)> = Vec::new();
        let mut add = |got: &Asked, connected: &HashSet<PeerId>, more: Vec<PeerId>, why: Why| {
            for p in more {
                if usable(got, connected, &p) && !found.iter().any(|(f, _)| *f == p) {
                    found.push((p, why));
                }
            }
        };
        match source {
            Source::Served => {
                let served = layer
                    .map(|l| self.knowledge.providers(l))
                    .unwrap_or_default();
                add(got, &connected, served, Why::Served);
            }
            Source::Filter => {
                if !std::mem::replace(&mut got.said, true) && layer.is_some() {
                    note(|| Event::Filters {
                        maybe: filtered.maybe.len(),
                        no: filtered.no.len(),
                        unknown: connected
                            .len()
                            .saturating_sub(filtered.maybe.len() + filtered.no.len()),
                    });
                }
                let mut maybe: Vec<PeerId> = filtered.maybe.iter().copied().collect();
                self.knowledge.rank(&mut maybe);
                add(got, &connected, maybe, Why::Filter);
            }
            Source::Probed => {
                if got.rounds < PROBE_ROUNDS {
                    let mut ask: Vec<PeerId> = connected
                        .iter()
                        .copied()
                        .filter(|p| {
                            usable(got, &connected, p)
                                && !got.probed.contains(p)
                                && !filtered.no.contains(p)
                                && !filtered.maybe.contains(p)
                        })
                        .collect();
                    self.knowledge.rank(&mut ask);
                    ask.sort_by_key(|p| far.contains(p));
                    ask.truncate(self.policy.query_peers);
                    if !ask.is_empty() {
                        // (the groups of a layer share each round: the first
                        // asks, the others take its answer)
                        let key = format!("{}\n{}", layer.unwrap_or(first), got.rounds);
                        let Probed {
                            asked,
                            has,
                            no,
                            busy,
                        } = self
                            .rounds
                            .lookup(&key, self.query(&ask, layer, first))
                            .await;
                        got.rounds += 1;
                        got.probed.extend(asked);
                        got.denied.extend(no);
                        add(got, &connected, has, Why::Probed);
                        // (a peer with no room is not one without the chunk:
                        // it comes after the ones that said it has it)
                        add(got, &connected, busy, Why::Busy);
                    }
                }
            }
            Source::Dht => {
                if let (Some(layer), false) = (layer, got.dht) {
                    got.dht = true;
                    let mut providers = self.peers.layer_providers(layer).await;
                    debug!(
                        layer = %short(layer),
                        providers = providers.len(),
                        "providers of the layer from the DHT"
                    );
                    // (the lookup connected to the ones that were not)
                    connected.extend(providers.iter().copied());
                    providers.retain(|p| !filtered.no.contains(p));
                    add(got, &connected, providers, Why::Dht);
                }
            }
            Source::Connected => {
                let mut every: Vec<PeerId> = connected
                    .iter()
                    .copied()
                    .filter(|p| !filtered.no.contains(p))
                    .collect();
                self.knowledge.rank(&mut every);
                add(got, &connected, every, Why::Connected);
            }
        }
        // (the peers of this node's zone first, then the ones this node asks
        // for the least at the moment: the groups of a pull do not all pile
        // on the one that answers quickest; each group in its order; a peer
        // with no room stays after the ones that have it)
        found.sort_by_key(|(p, why)| (far.contains(p), *why == Why::Busy, self.requested.load(p)));
        found
    }

    /// What `peers` say of the chunk `digest`, asked at the same time: what
    /// they answer is remembered for the layer (the ones that have it are
    /// asked first by the next groups of the pull, the ones that have not
    /// are not asked again for a while).  A peer with no room to answer is
    /// neither: nothing is remembered of it.  A peer that does not answer in
    /// [`QUERY_WAIT`] is in none.  A peer has at most [`probes::PER_PEER`]
    /// probes of this node in flight: the others wait for a place within
    /// that time (one not sent by then is not asked, and nothing is
    /// remembered of it).
    async fn query(&self, peers: &[PeerId], layer: Option<&str>, digest: &str) -> Probed {
        let mut probed = Probed {
            asked: peers.to_vec(),
            ..Default::default()
        };
        let inflight = &self.inflight;
        let mut running: futures::stream::FuturesUnordered<_> = peers
            .iter()
            .map(|&peer| {
                let source = self.peers.clone();
                let digest = digest.to_string();
                let span = tracing::debug_span!("probe", %peer, chunk = short(&digest));
                tracing::Instrument::instrument(
                    async move {
                        let _place = inflight.place(peer).await;
                        let started = tokio::time::Instant::now();
                        let answer = source.has(peer, &digest).await;
                        (peer, started.elapsed(), answer)
                    },
                    span,
                )
            })
            .collect();
        // (who answered, and why the rest were not waited for)
        let mut seen: Vec<PeerId> = Vec::new();
        let mut left = "no answer in time";
        let deadline = tokio::time::sleep(QUERY_WAIT);
        tokio::pin!(deadline);
        loop {
            tokio::select! {
                // (an answer that is in counts before a timer that fired
                // with it)
                biased;
                answer = futures::StreamExt::next(&mut running) => match answer {
                    Some((peer, took, Ok(Presence::Has))) => {
                        note(|| Event::Probe { peer, answer: "has it" });
                        seen.push(peer);
                        self.knowledge.said_has(layer, peer, took);
                        probed.has.push(peer);
                        if probed.has.len() >= MAX_PROVIDERS {
                            left = "not waited for: enough had said they have it";
                            break;
                        }
                    }
                    Some((peer, _, Ok(Presence::Lacks))) => {
                        note(|| Event::Probe { peer, answer: "does not have it" });
                        seen.push(peer);
                        self.knowledge.missed(layer, peer);
                        probed.no.push(peer);
                    }
                    Some((peer, _, Ok(Presence::Busy))) => {
                        note(|| Event::Probe { peer, answer: "had no room to say" });
                        seen.push(peer);
                        probed.busy.push(peer)
                    }
                    Some((peer, _, Err(e))) => {
                        note(|| Event::Probe { peer, answer: "failed" });
                        seen.push(peer);
                        debug!("P2P: {peer} did not say whether it has {}: {e}", short(digest));
                    }
                    None => break,
                },
                _ = &mut deadline => break,
            }
        }
        for peer in probed.asked.iter().filter(|p| !seen.contains(p)) {
            note(|| Event::Probe {
                peer: *peer,
                answer: left,
            });
        }
        probed
    }

    fn ask(
        &self,
        answers: &mut Answers,
        peer: PeerId,
        urgency: Urgency,
        items: Vec<(String, Option<u64>)>,
    ) -> impl std::future::Future<Output = Attempt> + Send + 'static {
        let peers = self.peers.clone();
        let requested = self.requested.clone();
        let unwaited = (urgency < Urgency::Wait).then(|| self.unwaited.clone());
        let streams = self.peers.streams(items.len());
        let request = answers.requests;
        answers.requests += 1;
        let group = answers.tx.clone();
        let span = tracing::debug_span!(
            "chunk_request",
            %peer,
            chunks = items.len(),
            first = items.first().map_or("", |(d, _)| short(d))
        );
        tracing::Instrument::instrument(
            async move {
                // (a peer answers so many streams of this node at a time:
                // the others wait for a place, which is not the peer's time)
                let _unwaited = match &unwaited {
                    Some(unwaited) => Some(unwaited.places(peer, streams).await),
                    None => None,
                };
                let _place = requested.places(peer, streams).await;
                let started = tokio::time::Instant::now();
                let (out, mut chunks) = tokio::sync::mpsc::channel(super::CHUNKS_IN_FLIGHT);
                // (the chunks are checked as they arrive, several at a time,
                // and handed on in the order they came)
                let mut checks = futures::StreamExt::buffered(
                    futures::StreamExt::map(
                        futures::stream::poll_fn(move |cx| chunks.poll_recv(cx)),
                        |(digest, data)| checked(digest, data),
                    ),
                    CHECKS_AT_ONCE,
                );
                let (result, ()) =
                    futures::join!(peers.request(peer, &items, urgency, out), async {
                        while let Some((digest, data, matches)) =
                            futures::StreamExt::next(&mut checks).await
                        {
                            let sent = group
                                .send(Received {
                                    request,
                                    peer,
                                    digest,
                                    data,
                                    matches,
                                })
                                .await;
                            // (the group is done: nobody takes what is left)
                            if sent.is_err() {
                                break;
                            }
                        }
                    });
                Attempt {
                    request,
                    peer,
                    took: started.elapsed(),
                    result,
                }
            },
            span,
        )
    }

    /// The connected peers whose filter says they may hold a layer, the
    /// quickest first.
    async fn maybe_of(&self, filtered: &Filtered) -> Vec<PeerId> {
        let connected: HashSet<PeerId> = self.peers.connected().await.into_iter().collect();
        let mut maybe: Vec<PeerId> = filtered
            .maybe
            .iter()
            .copied()
            .filter(|p| connected.contains(p))
            .collect();
        self.knowledge.rank(&mut maybe);
        maybe
    }

    /// The index of the layer `item` from the first of its providers, not
    /// one of `not`, that has one `well_formed`, and that provider.  It is
    /// not named by its digest: the puller proves it; when a peer sends one
    /// that is not an index the next provider is asked.
    pub(crate) async fn fetch_index(
        &self,
        item: &Item,
        toc: bool,
        not: &[PeerId],
        well_formed: &(dyn Fn(&[u8]) -> bool + Sync),
        out: &mut dyn Sink,
    ) -> Result<Option<PeerId>, String> {
        if !crate::limits::is_digest(&item.digest) {
            return Ok(None);
        }
        let log = self
            .decisions
            .start(Kind::Index, Some(&item.digest), &item.digest, 1);
        let span = tracing::info_span!("pull_index", group = log.id(), layer = short(&item.digest));
        tracing::Instrument::instrument(
            log.scope(self.ask_index(item, toc, not, well_formed, out)),
            span,
        )
        .await
    }

    async fn ask_index(
        &self,
        item: &Item,
        toc: bool,
        not: &[PeerId],
        well_formed: &(dyn Fn(&[u8]) -> bool + Sync),
        out: &mut dyn Sink,
    ) -> Result<Option<PeerId>, String> {
        let max = item
            .size
            .unwrap_or(MAX_ITEM_BYTES as u64)
            .min(MAX_ITEM_BYTES as u64);
        let mut why = Why::Served;
        // (the layer a peer announces: by its blob, or by its table of
        // contents, which the digest asked for is the checksum of)
        let layer = match toc {
            true => velarx_types::LayerKey::Toc(item.digest.parse().map_err(|_| "a digest")?)
                .to_string(),
            false => item.digest.clone(),
        };
        let mut providers = self.knowledge.providers(&layer);
        providers.retain(|p| !not.contains(p));
        let filtered = self.knowledge.filtered(&layer);
        if providers.is_empty() {
            why = Why::Filter;
            providers = self.maybe_of(&filtered).await;
            providers.retain(|p| !not.contains(p));
        }
        if providers.is_empty() {
            why = Why::Connected;
            providers = self.peers.connected().await;
            providers.retain(|p| !filtered.no.contains(p) && !not.contains(p));
        }
        providers.truncate(MAX_PROVIDERS);
        note(|| Event::Candidates(providers.iter().map(|p| (*p, why)).collect()));
        for provider in providers {
            let started = tokio::time::Instant::now();
            match self.peers.index(provider, &item.digest, max).await {
                Ok(Some(index)) if !well_formed(&index) => {
                    note(|| Event::Asked {
                        peer: provider,
                        outcome: Outcome::Failed("not an index".into()),
                        took: started.elapsed(),
                    });
                    self.knowledge.failed(provider);
                    self.knowledge.count(provider, started.elapsed(), None);
                }
                Ok(Some(index)) => {
                    let took = started.elapsed();
                    note(|| Event::Asked {
                        peer: provider,
                        outcome: Outcome::Sent(1, index.len() as u64),
                        took,
                    });
                    self.knowledge
                        .count(provider, took, Some((1, index.len() as u64)));
                    self.knowledge.served(Some(&layer), provider, took);
                    out.put(&item.digest, &index).await?;
                    return Ok(Some(provider));
                }
                Ok(None) => {
                    note(|| Event::Asked {
                        peer: provider,
                        outcome: Outcome::Lacks,
                        took: started.elapsed(),
                    });
                    self.knowledge.missed(Some(&layer), provider);
                }
                // (it may have the index: nothing is recorded of the layer)
                Err(PeerError::Busy) => {
                    note(|| Event::Asked {
                        peer: provider,
                        outcome: Outcome::Busy,
                        took: started.elapsed(),
                    });
                    self.knowledge.busy(provider);
                }
                Err(PeerError::NoQuic(why)) => {
                    note(|| Event::Asked {
                        peer: provider,
                        outcome: Outcome::NoPath(why.clone()),
                        took: started.elapsed(),
                    });
                    debug!(
                        "P2P: the index of {} from {}: no QUIC path: {why}",
                        short(&item.digest),
                        provider
                    )
                }
                Err(PeerError::Failed(e)) => {
                    note(|| Event::Asked {
                        peer: provider,
                        outcome: Outcome::Failed(e.clone()),
                        took: started.elapsed(),
                    });
                    self.knowledge.count(provider, started.elapsed(), None);
                    debug!(
                        "P2P: the index of {} from {}: {}",
                        short(&item.digest),
                        provider,
                        e
                    )
                }
            }
        }
        note(|| Event::Unsent {
            items: 1,
            reason: "no peer sent an index",
        });
        Ok(None)
    }

    /// The startup profile of each image of `items` (by its id as a
    /// digest) from the first peer that has one that looks like a profile:
    /// the peers that served or whose filter names `layer` (a layer of the image)
    /// first, then the others, at most [`MAX_PROVIDERS`].  Only the members
    /// of the swarm can be asked; what they send is bounded and only an
    /// order of files the asker fetches and checks anyway.
    pub(crate) async fn fetch_profiles(
        &self,
        items: &[Item],
        layer: Option<&str>,
        out: &mut dyn Sink,
    ) -> Result<(), String> {
        for item in items.iter().take(MAX_REQUEST_DIGESTS) {
            if !crate::limits::is_digest(&item.digest) {
                continue;
            }
            let log = self.decisions.start(Kind::Profile, layer, &item.digest, 1);
            let span = tracing::info_span!(
                "pull_profile",
                group = log.id(),
                image = short(&item.digest)
            );
            tracing::Instrument::instrument(log.scope(self.fetch_profile(item, layer, out)), span)
                .await?;
        }
        Ok(())
    }

    async fn fetch_profile(
        &self,
        item: &Item,
        layer: Option<&str>,
        out: &mut dyn Sink,
    ) -> Result<(), String> {
        let max = item
            .size
            .unwrap_or(velarx_content::fetcher::fetch::PROFILE_MAX_BYTES)
            .min(velarx_content::fetcher::fetch::PROFILE_MAX_BYTES);
        let mut peers: Vec<(PeerId, Why)> = Vec::new();
        let mut filtered = Filtered::default();
        if let Some(layer) = layer {
            peers.extend(
                self.knowledge
                    .providers(layer)
                    .into_iter()
                    .map(|p| (p, Why::Served)),
            );
            filtered = self.knowledge.filtered(layer);
            peers.extend(
                self.maybe_of(&filtered)
                    .await
                    .into_iter()
                    .map(|p| (p, Why::Filter)),
            );
        }
        let mut every = self.peers.connected().await;
        every.retain(|p| !filtered.no.contains(p));
        self.knowledge.rank(&mut every);
        peers.extend(every.into_iter().map(|p| (p, Why::Connected)));
        let mut asked = HashSet::new();
        peers.retain(|(p, _)| asked.insert(*p));
        peers.truncate(MAX_PROVIDERS);
        note(|| Event::Candidates(peers.clone()));
        for (peer, _) in peers {
            let started = tokio::time::Instant::now();
            match self.peers.profile(peer, &item.digest, max).await {
                Ok(Some(profile)) if looks_like_a_profile(&profile) => {
                    let took = started.elapsed();
                    note(|| Event::Asked {
                        peer,
                        outcome: Outcome::Sent(1, profile.len() as u64),
                        took,
                    });
                    self.knowledge
                        .count(peer, took, Some((1, profile.len() as u64)));
                    debug!(
                        "P2P: the startup profile of {} from {} ({} bytes)",
                        short(&item.digest),
                        peer,
                        profile.len()
                    );
                    out.put(&item.digest, &profile).await?;
                    return Ok(());
                }
                Ok(_) => note(|| Event::Asked {
                    peer,
                    outcome: Outcome::Lacks,
                    took: started.elapsed(),
                }),
                Err(PeerError::Busy) => {
                    note(|| Event::Asked {
                        peer,
                        outcome: Outcome::Busy,
                        took: started.elapsed(),
                    });
                    self.knowledge.busy(peer);
                }
                Err(PeerError::NoQuic(why)) => {
                    note(|| Event::Asked {
                        peer,
                        outcome: Outcome::NoPath(why.clone()),
                        took: started.elapsed(),
                    });
                    debug!(
                        "P2P: the profile of {} from {}: no QUIC path: {why}",
                        short(&item.digest),
                        peer
                    )
                }
                Err(PeerError::Failed(e)) => {
                    note(|| Event::Asked {
                        peer,
                        outcome: Outcome::Failed(e.clone()),
                        took: started.elapsed(),
                    });
                    debug!(
                        "P2P: the profile of {} from {}: {}",
                        short(&item.digest),
                        peer,
                        e
                    )
                }
            }
        }
        note(|| Event::Unsent {
            items: 1,
            reason: "no peer sent a profile",
        });
        Ok(())
    }

    /// The chunks of a group from the best peer, and from a second one when
    /// the first is slow or has not everything: the first valid answer of
    /// each chunk is the one that is passed on, the requests still under way
    /// are dropped when nothing is left to get.
    pub(crate) async fn fetch_group(
        &self,
        items: &[Item],
        layer: Option<&str>,
        out: &mut dyn Sink,
    ) -> Result<(), String> {
        self.fetch_group_as(items, layer, Urgency::Wait, out).await
    }

    /// [`PeerSource::fetch_group`], asked of the peers as `urgency` says.
    pub(crate) async fn fetch_group_as(
        &self,
        items: &[Item],
        layer: Option<&str>,
        urgency: Urgency,
        out: &mut dyn Sink,
    ) -> Result<(), String> {
        let Some(first) = items.first() else {
            return Ok(());
        };
        let log = self
            .decisions
            .start(Kind::Chunks, layer, &first.digest, items.len());
        let mut sent = vec![false; items.len()];
        let span = tracing::info_span!(
            "pull_group",
            group = log.id(),
            layer = layer.map(short).unwrap_or(""),
            chunks = items.len()
        );
        let result = tracing::Instrument::instrument(
            log.clone()
                .scope(self.fetch_group_of(items, layer, urgency, &mut sent, out)),
            span.clone(),
        )
        .await;
        let missing = sent.iter().filter(|s| !**s).count();
        if missing > 0 {
            let reason = log.reason();
            log.add(Event::Unsent {
                items: missing,
                reason,
            });
            // (the engine goes on to its next source)
            tracing::info!(parent: &span, missing, reason, "left to the next source");
        }
        result
    }

    async fn fetch_group_of(
        &self,
        items: &[Item],
        layer: Option<&str>,
        urgency: Urgency,
        sent: &mut [bool],
        out: &mut dyn Sink,
    ) -> Result<(), String> {
        if let Some(layer) = layer.filter(|_| self.policy.stripe_peers > 1) {
            if self.fetch_striped(items, layer, urgency, sent, out).await? {
                return Ok(());
            }
        }
        if sent.iter().all(|s| *s) {
            return Ok(());
        }
        let first = &items[0].digest;
        // The next peers are looked for beside the requests under way (a
        // round of probes or a walk of the DHT takes seconds): an answer that
        // comes meanwhile is taken at once, and timed by when it came.  The
        // search owns what the group asked while it runs.
        let mut got: Option<Asked> = None;
        let mut searching = Some(self.search(layer, first, Asked::default()));
        // (whether it was started because the one asked last is slow: what
        // it finds is asked at once then)
        let mut hedged = false;
        let mut next: std::collections::VecDeque<PeerId> = Default::default();
        let mut running: futures::stream::FuturesUnordered<_> = Default::default();
        let mut answers = Answers::new();
        let mut waiting_for: Option<PeerId> = None;
        // the peers whose requests are under way
        let mut asking: Vec<PeerId> = Vec::new();
        // The peers that had no room, and how many chunks were in by then:
        // when more came since (a request completed, and the peer may have
        // room now) they are asked again, once the others were
        let mut busy: Vec<PeerId> = Vec::new();
        let mut in_when_busy = 0usize;
        let may_search = |got: &Option<Asked>| got.as_ref().is_some_and(Asked::more);
        let began = self.begin();
        let started = began.at;
        let mut tick = tokio::time::interval(Duration::from_secs(1));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        // (the hedge delay runs from the last event, not from a tick)
        let mut since = started;
        let mut ticked = false;

        loop {
            if !std::mem::take(&mut ticked) {
                since = tokio::time::Instant::now();
            }
            let remaining: Vec<(String, Option<u64>)> = (0..items.len())
                .filter(|&i| !sent[i])
                .map(|i| (items[i].digest.clone(), items[i].size))
                .collect();
            if remaining.is_empty() {
                return Ok(());
            }
            // a peer is asked when nobody is, or when the last one asked is
            // slow
            if running.is_empty() {
                if next.is_empty() && searching.is_none() {
                    if let Some(asked) = got.take_if(|g| g.more()) {
                        searching = Some(self.search(layer, first, asked));
                        hedged = false;
                    }
                }
                if next.is_empty() && searching.is_none() {
                    let in_now = sent.iter().filter(|s| **s).count();
                    if !busy.is_empty() && in_now > in_when_busy {
                        next.extend(busy.drain(..));
                    }
                }
                match next.pop_front() {
                    Some(peer) => {
                        running.push(self.ask(&mut answers, peer, urgency, remaining.clone()));
                        asking.push(peer);
                        waiting_for = Some(peer);
                    }
                    // (nobody left to ask)
                    None if searching.is_none() => return Ok(()),
                    None => {}
                }
            }
            let hedge = match (self.policy.hedge, waiting_for) {
                (true, Some(peer))
                    if !running.is_empty()
                        && searching.is_none()
                        && (!next.is_empty() || may_search(&got)) =>
                {
                    let delay = self
                        .policy
                        .hedge_delay
                        .unwrap_or_else(|| self.knowledge.hedge_delay(&peer));
                    // each request beside the first waits twice as long as
                    // the one before it (at most the longest hedge delay): a
                    // swarm that is slow everywhere is not asked the same
                    // chunks eight times at once
                    let spaced = delay.saturating_mul(1 << (running.len() - 1).min(5));
                    Some(spaced.min(delay.max(super::knowledge::HEDGE_MAX)))
                }
                _ => None,
            };
            let attempt = tokio::select! {
                // (an answer that is in counts before a timer that fired
                // with it)
                biased;
                // (the chunks of an answer are taken before it is done with)
                Some(received) = answers.rx.recv() => {
                    self.accept(items, sent, &mut answers, received, out).await?;
                    continue;
                }
                attempt = futures::StreamExt::next(&mut running), if !running.is_empty() => attempt,
                _ = tick.tick() => {
                    if self.slow(&began) {
                        self.skip(&asking);
                        return Ok(());
                    }
                    ticked = true;
                    continue;
                }
                (asked, found) = async { searching.as_mut().expect("a search").await },
                    if searching.is_some() => {
                    searching = None;
                    got = Some(asked);
                    next.extend(found.into_iter().map(|(p, _)| p));
                    if hedged && !running.is_empty() {
                        if let Some(peer) = next.pop_front() {
                            debug!("P2P: asking {peer} too, the one asked last is slow");
                            running.push(self.ask(&mut answers, peer, urgency, remaining));
                            asking.push(peer);
                            waiting_for = Some(peer);
                        }
                    }
                    continue;
                }
                _ = tokio::time::sleep_until(since + hedge.unwrap_or_default()),
                    if hedge.is_some() => {
                    if let Some(peer) = next.pop_front() {
                        debug!("P2P: asking {peer} too, {:?} passed without an answer", hedge);
                        running.push(self.ask(&mut answers, peer, urgency, remaining));
                        asking.push(peer);
                        waiting_for = Some(peer);
                    } else if let Some(asked) = got.take() {
                        searching = Some(self.search(layer, first, asked));
                        hedged = true;
                    }
                    continue;
                }
            };
            let Some(attempt) = attempt else {
                continue;
            };
            let peer = attempt.peer;
            asking.retain(|p| *p != peer);
            if let Taken::Busy = self
                .settle(items, sent, layer, &mut answers, attempt, out)
                .await?
            {
                if !busy.contains(&peer) {
                    busy.push(peer);
                }
                in_when_busy = sent.iter().filter(|s| **s).count();
            }
        }
    }

    /// The peers that have chunks of `layer`, for striping: the ones that
    /// served it lately, then the ones whose filter says maybe (no walk of the
    /// DHT), the best first, at most `stripe_peers`; never the ones known
    /// to have none of it.
    async fn holders(&self, layer: &str) -> Vec<PeerId> {
        let connected: HashSet<PeerId> = self.peers.connected().await.into_iter().collect();
        let usable = |p: &PeerId| {
            connected.contains(p) && !self.knowledge.failing(p) && !self.knowledge.lacks(layer, p)
        };
        let mut found: Vec<PeerId> = self
            .knowledge
            .providers(layer)
            .into_iter()
            .filter(|p| usable(p))
            .collect();
        if found.len() < self.policy.stripe_peers {
            let maybe = self.maybe_of(&self.knowledge.filtered(layer)).await;
            for p in maybe {
                if usable(&p) && !found.contains(&p) {
                    found.push(p);
                }
            }
        }
        let far = self.peers.far().await;
        found.sort_by_key(|p| (far.contains(p), self.requested.load(p)));
        found.truncate(self.policy.stripe_peers);
        found
    }

    /// The chunks of a big group from several peers that have the layer at
    /// once (false when it is not big, or fewer than two have it): the group
    /// is cut in parts in order, each peer takes the next
    /// part when it is done with one (at most [`STRIPE_DEPTH`] at a time),
    /// so the quicker peers take more and the first chunks come first.
    /// When no part is left to take, a part that a peer is slow with (it
    /// has not answered after the hedge delay) is asked of an idle peer too,
    /// once.  What a peer did not have is asked of the others; a peer that
    /// fails, lies or has nothing is not asked again here.  What is still
    /// missing at the end is left to the caller (`sent`).
    async fn fetch_striped(
        &self,
        items: &[Item],
        layer: &str,
        urgency: Urgency,
        sent: &mut [bool],
        out: &mut dyn Sink,
    ) -> Result<bool, String> {
        let Some(parts) = stripe_parts(items) else {
            return Ok(false);
        };
        let holders = self.holders(layer).await;
        if holders.len() < 2 {
            return Ok(false);
        }
        struct Part {
            items: Vec<usize>,
            /// The peers asked for it, and when the first was
            asked: Vec<PeerId>,
            since: Option<tokio::time::Instant>,
            running: usize,
            /// What stops the requests under way for it
            stops: Vec<futures::future::AbortHandle>,
            /// The bytes asked twice, when it was
            hedged: u64,
        }
        let mut parts: Vec<Part> = parts
            .into_iter()
            .map(|items| Part {
                items,
                asked: Vec::new(),
                since: None,
                running: 0,
                stops: Vec::new(),
                hedged: 0,
            })
            .collect();
        let mut queue: std::collections::VecDeque<usize> = (0..parts.len()).collect();
        let mut active: Vec<PeerId> = holders;
        let mut busy: std::collections::HashMap<PeerId, usize> = Default::default();
        let mut running: futures::stream::FuturesUnordered<_> = Default::default();
        let mut answers = Answers::new();
        // the bytes asked, and those of them asked twice
        let (mut asked_bytes, mut hedged_bytes) = (0u64, 0u64);
        let began = self.begin();
        let mut tick = tokio::time::interval(Duration::from_secs(1));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        note(|| Event::Striped(active.clone()));
        debug!(
            "P2P: {} chunks of {} spread over {} peers",
            items.len(),
            short(layer),
            active.len()
        );
        loop {
            // what is still under way is dropped when nothing is left
            if sent.iter().all(|s| *s) {
                return Ok(false);
            }
            // every idle peer takes the next part it was not asked for, or
            // hedges a slow one
            let mut next_hedge: Option<tokio::time::Instant> = None;
            for peer in active.clone() {
                while busy.get(&peer).copied().unwrap_or(0) < STRIPE_DEPTH {
                    let open = |p: &Part| p.items.iter().any(|&i| !sent[i]);
                    let pick = queue
                        .iter()
                        .position(|&n| !parts[n].asked.contains(&peer) && open(&parts[n]));
                    let n = match pick {
                        Some(at) => queue.remove(at).expect("a queued part"),
                        None if self.policy.hedge => {
                            let now = tokio::time::Instant::now();
                            let bytes_of = |p: &Part| -> u64 {
                                p.items
                                    .iter()
                                    .filter(|&&i| !sent[i])
                                    .filter_map(|&i| items[i].size)
                                    .sum()
                            };
                            let slow = (0..parts.len()).find(|&n| {
                                let p = &parts[n];
                                p.running > 0
                                    && p.asked.len() == 1
                                    && !p.asked.contains(&peer)
                                    && open(p)
                                    && hedged_bytes + bytes_of(p)
                                        <= (asked_bytes / HEDGED_SHARE).max(STRIPE_BYTES)
                                    && {
                                        // (late for the group: a multiple of what
                                        // the quickest peer of it takes, not of what
                                        // this peer takes, which is long for a peer
                                        // that is slow and the same for all of them
                                        // when this node's link is the limit)
                                        let wait = self.policy.hedge_delay.unwrap_or_else(|| {
                                            active
                                                .iter()
                                                .filter_map(|p| self.knowledge.rtt(p))
                                                .min()
                                                .map_or(super::knowledge::HEDGE_UNKNOWN, |r| {
                                                    (r * LATE_FACTOR)
                                                        .max(super::knowledge::HEDGE_MIN)
                                                })
                                        });
                                        let due = p.since.expect("asked") + wait;
                                        if due > now {
                                            next_hedge =
                                                Some(next_hedge.map_or(due, |h| h.min(due)));
                                        }
                                        due <= now
                                    }
                            });
                            match slow {
                                Some(n) => {
                                    debug!("P2P: asking {peer} too for a part a peer is slow with");
                                    let bytes = bytes_of(&parts[n]);
                                    hedged_bytes += bytes;
                                    parts[n].hedged = bytes;
                                    n
                                }
                                None => break,
                            }
                        }
                        None => break,
                    };
                    let part = &mut parts[n];
                    let wanted: Vec<(String, Option<u64>)> = part
                        .items
                        .iter()
                        .filter(|&&i| !sent[i])
                        .map(|&i| (items[i].digest.clone(), items[i].size))
                        .collect();
                    part.asked.push(peer);
                    part.since.get_or_insert_with(tokio::time::Instant::now);
                    part.running += 1;
                    if part.asked.len() == 1 {
                        asked_bytes += part
                            .items
                            .iter()
                            .filter(|&&i| !sent[i])
                            .filter_map(|&i| items[i].size)
                            .sum::<u64>();
                    }
                    *busy.entry(peer).or_default() += 1;
                    let (ask, stop) =
                        futures::future::abortable(self.ask(&mut answers, peer, urgency, wanted));
                    part.stops.push(stop);
                    running.push(futures::FutureExt::map(ask, move |a| (n, peer, a.ok())));
                }
            }
            if running.is_empty() {
                return Ok(false);
            }
            let wake = next_hedge;
            let (n, peer, attempt) = tokio::select! {
                // (an answer that is in counts before a timer that fired
                // with it, and the chunks of an answer before it is done with)
                biased;
                Some(received) = answers.rx.recv() => {
                    self.accept(items, sent, &mut answers, received, out).await?;
                    continue;
                }
                done = futures::StreamExt::next(&mut running) => match done {
                    Some(done) => done,
                    None => continue,
                },
                _ = tick.tick() => {
                    if self.slow(&began) {
                        let under_way: Vec<PeerId> = busy
                            .iter()
                            .filter(|(_, n)| **n > 0)
                            .map(|(p, _)| *p)
                            .collect();
                        self.skip(&under_way);
                        return Ok(true);
                    }
                    continue;
                }
                _ = async { tokio::time::sleep_until(wake.unwrap_or_else(tokio::time::Instant::now)).await },
                    if wake.is_some() => continue,
            };
            if let Some(b) = busy.get_mut(&peer) {
                *b = b.saturating_sub(1);
            }
            parts[n].running -= 1;
            // (a request stopped because the part came from another peer)
            let Some(attempt) = attempt else {
                continue;
            };
            let taken = self
                .settle(items, sent, Some(layer), &mut answers, attempt, out)
                .await?;
            // (a hedge that was needed, the first peer being slow, is not
            // counted against the budget: the bytes asked twice that count
            // are the ones that were not)
            if parts[n].asked.first() != Some(&peer) {
                hedged_bytes = hedged_bytes.saturating_sub(std::mem::take(&mut parts[n].hedged));
            }
            // the other peers asked for a part that is in are stopped: the
            // bytes still on their way are not wanted
            if parts[n].items.iter().all(|&i| sent[i]) {
                for stop in parts[n].stops.drain(..) {
                    stop.abort();
                }
            }
            // a peer that failed, sent wrong bytes, had no room or had nothing of what
            // it was asked is not asked again here (a busy one is by the
            // next group: it is not remembered as without the layer)
            if !matches!(taken, Taken::Sent(valid) if valid > 0) {
                active.retain(|p| *p != peer);
            }
            // what it did not send is for the others, when nobody else has
            // it under way
            let part = &parts[n];
            if part.running == 0
                && part.items.iter().any(|&i| !sent[i])
                && active.iter().any(|p| !part.asked.contains(p))
                && !queue.contains(&n)
            {
                queue.push_front(n);
            }
        }
    }

    /// Take a chunk a peer sent (checked) and, when it is one of `items`
    /// that was not sent yet (the first valid answer of each chunk), pass it
    /// on.
    async fn accept(
        &self,
        items: &[Item],
        sent: &mut [bool],
        answers: &mut Answers,
        received: Received,
        out: &mut dyn Sink,
    ) -> Result<(), String> {
        let Received {
            request,
            peer,
            digest: wanted,
            data,
            matches,
        } = received;
        if !matches {
            warn!(
                "P2P chunk mismatch from {}: the bytes sent for {} are not it",
                peer,
                short(&wanted),
            );
            return Ok(());
        }
        let mut asked = false;
        for (i, item) in items.iter().enumerate() {
            if item.digest == wanted && item.size.is_none_or(|s| s == data.len() as u64) {
                asked = true;
                if !sent[i] {
                    out.put(&wanted, &data).await?;
                    sent[i] = true;
                }
            }
        }
        if asked {
            let (n, bytes) = answers.valid.entry(request).or_default();
            *n += 1;
            *bytes += data.len() as u64;
        }
        // (what is in the pipe is passed on together)
        if answers.rx.is_empty() {
            out.flush().await?;
        }
        Ok(())
    }

    /// Learn from what `attempt` came to: the chunks it sent that are still
    /// waiting are taken first, then how many of the chunks asked it sent
    /// right, or that it failed or had no room.
    async fn settle(
        &self,
        items: &[Item],
        sent: &mut [bool],
        layer: Option<&str>,
        answers: &mut Answers,
        attempt: Attempt,
        out: &mut dyn Sink,
    ) -> Result<Taken, String> {
        while let Ok(received) = answers.rx.try_recv() {
            self.accept(items, sent, answers, received, out).await?;
        }
        let Attempt {
            request,
            peer,
            took,
            result,
        } = attempt;
        let (n, bytes) = answers.valid.remove(&request).unwrap_or_default();
        match result {
            Ok(()) => {}
            // (it may have the chunks: nothing is recorded of the layer, and
            // the peer is no worse for it)
            Err(PeerError::Busy) => {
                debug!(%peer, outcome = "busy", "chunk request");
                note(|| Event::Asked {
                    peer,
                    outcome: Outcome::Busy,
                    took,
                });
                self.knowledge.busy(peer);
                return Ok(Taken::Busy);
            }
            // (a peer that cannot be reached over UDP: asked, ranked last,
            // another peer is asked)
            Err(PeerError::NoQuic(why)) => {
                debug!(%peer, outcome = "no-quic-path", "chunk request: {why}");
                note(|| Event::Asked {
                    peer,
                    outcome: Outcome::NoPath(why),
                    took,
                });
                self.knowledge.failed(peer);
                return Ok(Taken::Failed);
            }
            Err(PeerError::Failed(e)) => {
                warn!(%peer, outcome = "error", "P2P chunk request error from provider: {e}");
                note(|| Event::Asked {
                    peer,
                    outcome: Outcome::Failed(e.clone()),
                    took,
                });
                self.knowledge.failed(peer);
                self.knowledge.count(peer, took, None);
                return Ok(Taken::Failed);
            }
        }
        out.flush().await?;
        // a peer that sent valid chunks has the layer, even when another
        // was quicker with them
        self.knowledge.count(peer, took, Some((n as u64, bytes)));
        self.rate.add(bytes);
        note(|| Event::Asked {
            peer,
            outcome: match n {
                0 => Outcome::Lacks,
                n => Outcome::Sent(n as u64, bytes),
            },
            took,
        });
        debug!(
            %peer,
            outcome = if n == 0 { "not-have" } else { "have" },
            chunks = n,
            "chunk request"
        );
        if n == 0 {
            self.knowledge.missed(layer, peer);
        } else {
            self.knowledge.served(layer, peer, took);
        }
        Ok(Taken::Sent(n))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest_of(data: &[u8]) -> String {
        velarx_types::digest::Digest::of(velarx_types::digest::Algorithm::Sha256, data).to_string()
    }
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;
    use tokio::time::Instant;

    #[derive(Clone)]
    struct Behaviour {
        delay: Duration,
        /// What it answers: the chunks it has, or an error
        reply: Result<Vec<(String, Vec<u8>)>, String>,
    }

    #[derive(Default)]
    struct Fake {
        peers: Mutex<HashMap<PeerId, Behaviour>>,
        asked: Mutex<Vec<PeerId>>,
        answered: AtomicUsize,
        lookups: AtomicUsize,
        /// Peers that answer only what they are asked, and how many chunks
        /// each request asked
        honest: Mutex<std::collections::HashSet<PeerId>>,
        sizes: Mutex<Vec<(PeerId, usize)>>,
        /// The bytes of the answers as they come (an eighth of an answer
        /// each eighth of its delay)
        received: std::sync::atomic::AtomicU64,
        /// The profile each peer gives, and who was asked for one
        profiles: Mutex<HashMap<PeerId, Vec<u8>>>,
        profile_asked: Mutex<Vec<PeerId>>,
        /// The index each peer gives, and who was asked for one
        indexes: Mutex<HashMap<PeerId, Vec<u8>>>,
        index_asked: Mutex<Vec<PeerId>>,
        /// Who says it has the chunks asked about (None: the peers cannot
        /// be asked), and who was asked
        holders: Mutex<Option<std::collections::HashSet<PeerId>>>,
        probed: Mutex<Vec<PeerId>>,
        /// The peers with no room, and how many requests each answers busy
        /// before it has room (probes are answered busy meanwhile)
        busy: Mutex<HashMap<PeerId, usize>>,
        /// Peers that are not connected: the lookup of the DHT names them
        /// and connects to them
        away: Mutex<Vec<PeerId>>,
        /// Peers with no QUIC path: nothing can be asked of them
        no_path: Mutex<std::collections::HashSet<PeerId>>,
        /// Peers of another zone
        far: Mutex<std::collections::HashSet<PeerId>>,
    }

    impl Fake {
        fn peer(&self, delay_ms: u64, reply: Result<Vec<(String, Vec<u8>)>, String>) -> PeerId {
            let id = PeerId::random();
            self.peers.lock().unwrap().insert(
                id,
                Behaviour {
                    delay: Duration::from_millis(delay_ms),
                    reply,
                },
            );
            id
        }
    }

    #[async_trait]
    impl Peers for Arc<Fake> {
        async fn connected(&self) -> Vec<PeerId> {
            let away = self.away.lock().unwrap();
            self.peers
                .lock()
                .unwrap()
                .keys()
                .filter(|p| !away.contains(p))
                .copied()
                .collect()
        }

        async fn layer_providers(&self, _: &str) -> Vec<PeerId> {
            self.lookups.fetch_add(1, Ordering::SeqCst);
            std::mem::take(&mut self.away.lock().unwrap())
        }

        async fn request(
            &self,
            peer: PeerId,
            items: &[(String, Option<u64>)],
            _: Urgency,
            out: crate::ChunkTx,
        ) -> Result<(), PeerError> {
            self.asked.lock().unwrap().push(peer);
            if self.no_path.lock().unwrap().contains(&peer) {
                return Err(PeerError::NoQuic("it advertises no QUIC endpoint".into()));
            }
            if let Some(left) = self.busy.lock().unwrap().get_mut(&peer) {
                if *left > 0 {
                    *left -= 1;
                    return Err(PeerError::Busy);
                }
            }
            self.sizes.lock().unwrap().push((peer, items.len()));
            let b = self.peers.lock().unwrap().get(&peer).cloned().unwrap();
            let reply = match b.reply {
                Ok(r) if self.honest.lock().unwrap().contains(&peer) => Ok(r
                    .into_iter()
                    .filter(|(d, _)| items.iter().any(|(w, _)| w == d))
                    .collect::<Vec<_>>()),
                r => r,
            };
            let bytes: u64 = reply.iter().flatten().map(|(_, d)| d.len() as u64).sum();
            for _ in 0..8 {
                tokio::time::sleep(b.delay / 8).await;
                self.received.fetch_add(bytes / 8, Ordering::SeqCst);
            }
            self.answered.fetch_add(1, Ordering::SeqCst);
            for chunk in reply.map_err(PeerError::Failed)? {
                let _ = out.send(chunk).await;
            }
            Ok(())
        }

        fn received(&self) -> u64 {
            self.received.load(Ordering::SeqCst)
        }

        async fn without_quic(&self) -> usize {
            self.no_path.lock().unwrap().len()
        }

        async fn far(&self) -> HashSet<PeerId> {
            self.far.lock().unwrap().clone()
        }

        async fn index(&self, peer: PeerId, _: &str, _: u64) -> Result<Option<Vec<u8>>, PeerError> {
            self.index_asked.lock().unwrap().push(peer);
            if self.no_path.lock().unwrap().contains(&peer) {
                return Err(PeerError::NoQuic("it advertises no QUIC endpoint".into()));
            }
            if let Some(left) = self.busy.lock().unwrap().get_mut(&peer) {
                if *left > 0 {
                    *left -= 1;
                    return Err(PeerError::Busy);
                }
            }
            Ok(self.indexes.lock().unwrap().get(&peer).cloned())
        }

        async fn has(&self, peer: PeerId, _: &str) -> Result<Presence, String> {
            self.probed.lock().unwrap().push(peer);
            if self.busy.lock().unwrap().get(&peer).is_some_and(|n| *n > 0) {
                return Ok(Presence::Busy);
            }
            match &*self.holders.lock().unwrap() {
                Some(holders) => Ok(if holders.contains(&peer) {
                    Presence::Has
                } else {
                    Presence::Lacks
                }),
                None => Err("no".into()),
            }
        }

        async fn profile(
            &self,
            peer: PeerId,
            _: &str,
            max: u64,
        ) -> Result<Option<Vec<u8>>, PeerError> {
            self.profile_asked.lock().unwrap().push(peer);
            if let Some(left) = self.busy.lock().unwrap().get_mut(&peer) {
                if *left > 0 {
                    *left -= 1;
                    return Err(PeerError::Busy);
                }
            }
            Ok(self
                .profiles
                .lock()
                .unwrap()
                .get(&peer)
                .filter(|p| p.len() as u64 <= max)
                .cloned())
        }
    }

    #[derive(Default)]
    struct Collect(Vec<(String, Vec<u8>)>);

    #[async_trait]
    impl Sink for Collect {
        async fn put(&mut self, digest: &str, data: &[u8]) -> Result<(), String> {
            self.0.push((digest.to_string(), data.to_vec()));
            Ok(())
        }
    }

    const LAYER: &str = "sha256:1111111111111111111111111111111111111111111111111111111111111111";

    fn chunks(n: usize) -> Vec<(String, Vec<u8>)> {
        (0..n)
            .map(|i| {
                let data = format!("chunk {i}").into_bytes();
                (digest_of(&data), data)
            })
            .collect()
    }

    fn items(c: &[(String, Vec<u8>)]) -> Vec<Item> {
        c.iter()
            .map(|(d, data)| Item {
                digest: d.clone(),
                size: Some(data.len() as u64),
            })
            .collect()
    }

    fn source(fake: &Arc<Fake>, hedge_ms: Option<u64>) -> PeerSource {
        PeerSource::with_peers(Arc::new(fake.clone())).with_policy(Policy {
            hedge: hedge_ms.is_some(),
            hedge_delay: hedge_ms.map(Duration::from_millis),
            ..Policy::default()
        })
    }

    /// What the filters of `peers` say: they hold `layer`.
    fn tell_maybe(s: &PeerSource, peers: &[PeerId], layer: &str) {
        for peer in peers {
            let mut told = crate::filter::Advertiser::new(
                crate::filter::Config::default(),
                Entropy::seeded(1),
            );
            told.add(&[layer.to_string()]);
            s.knowledge()
                .filter_received(*peer, &told.full().unwrap())
                .unwrap();
        }
    }

    fn digests_of(c: &Collect) -> Vec<String> {
        let mut d: Vec<String> = c.0.iter().map(|(d, _)| d.clone()).collect();
        d.sort();
        d
    }

    fn sorted(c: &[(String, Vec<u8>)]) -> Vec<String> {
        let mut d: Vec<String> = c.iter().map(|(d, _)| d.clone()).collect();
        d.sort();
        d
    }

    fn querying(fake: &Arc<Fake>, query_peers: usize) -> PeerSource {
        PeerSource::with_peers(Arc::new(fake.clone())).with_policy(Policy {
            query_peers,
            ..Policy::default()
        })
    }

    /// No filter says who holds the layer: the peers are asked whether they have the
    /// chunk, the chunks are asked of the one that says yes, and what they
    /// said is remembered, so the next group asks nobody.
    #[tokio::test]
    async fn the_peers_are_asked_when_no_filter_says_and_the_answers_are_kept() {
        let fake = Arc::new(Fake::default());
        let c = chunks(4);
        let others: Vec<PeerId> = (0..11).map(|_| fake.peer(0, Ok(Vec::new()))).collect();
        let holder = fake.peer(0, Ok(c.clone()));
        *fake.holders.lock().unwrap() = Some([holder].into());
        let s = querying(&fake, 16);
        let mut out = Collect::default();
        s.fetch_group(&items(&c[..2]), Some(LAYER), &mut out)
            .await
            .unwrap();
        assert_eq!(digests_of(&out), sorted(&c[..2]));
        assert_eq!(fake.probed.lock().unwrap().len(), 12);
        assert_eq!(fake.asked.lock().unwrap().first(), Some(&holder));
        assert!(!fake
            .asked
            .lock()
            .unwrap()
            .iter()
            .any(|p| others.contains(p)));
        assert_eq!(s.knowledge().providers(LAYER), [holder]);
        assert!(others.iter().all(|p| s.knowledge().lacks(LAYER, p)));
        // the next group of the pull asks nobody again
        let mut out = Collect::default();
        s.fetch_group(&items(&c[2..]), Some(LAYER), &mut out)
            .await
            .unwrap();
        assert_eq!(digests_of(&out), sorted(&c[2..]));
        assert_eq!(fake.probed.lock().unwrap().len(), 12);
    }

    /// The decision of a group says whom it considered and why, what each
    /// answered, and what each request came to.
    #[tokio::test]
    async fn the_decision_of_a_group_says_whom_it_asked_and_what_came_of_it() {
        use crate::explain::{Event, Kind, Outcome, Why};
        let fake = Arc::new(Fake::default());
        let c = chunks(2);
        let others: Vec<PeerId> = (0..3).map(|_| fake.peer(0, Ok(Vec::new()))).collect();
        let holder = fake.peer(0, Ok(c.clone()));
        *fake.holders.lock().unwrap() = Some([holder].into());
        let s = querying(&fake, 8);
        let mut out = Collect::default();
        s.fetch_group(&items(&c), Some(LAYER), &mut out)
            .await
            .unwrap();
        let records = s.decisions().about(LAYER, &[]);
        assert_eq!(records.len(), 1);
        let r = &records[0];
        assert_eq!((r.kind, r.items), (Kind::Chunks, 2));
        assert_eq!(r.layer.as_deref(), Some(LAYER));
        // all four were asked whether they have the chunk
        let probes: Vec<_> = r
            .events
            .iter()
            .filter_map(|e| match e {
                Event::Probe { peer, answer } => Some((*peer, *answer)),
                _ => None,
            })
            .collect();
        assert_eq!(probes.len(), 4);
        assert!(probes.contains(&(holder, "has it")));
        assert!(others
            .iter()
            .all(|p| probes.contains(&(*p, "does not have it"))));
        // the one that said yes is the first candidate, for that reason
        let candidates = r
            .events
            .iter()
            .find_map(|e| match e {
                Event::Candidates(c) => Some(c.clone()),
                _ => None,
            })
            .expect("candidates");
        assert_eq!(candidates[0], (holder, Why::Probed));
        // and it sent both
        assert!(r.events.iter().any(|e| matches!(e,
            Event::Asked { peer, outcome: Outcome::Sent(2, _), .. } if *peer == holder)));
        assert!(!r.events.iter().any(|e| matches!(e, Event::Unsent { .. })));
    }

    /// What the peers did not give is left to the next source, with the reason.
    #[tokio::test]
    async fn the_decision_says_why_what_the_peers_did_not_give_went_to_the_next_source() {
        use crate::explain::Event;
        // nobody connected
        let fake = Arc::new(Fake::default());
        let c = chunks(2);
        let s = querying(&fake, 8);
        let mut out = Collect::default();
        s.fetch_group(&items(&c), Some(LAYER), &mut out)
            .await
            .unwrap();
        let r = &s.decisions().about("", &[])[0];
        assert!(matches!(
            r.events.last(),
            Some(Event::Unsent {
                items: 2,
                reason: "no peer to ask"
            })
        ));
        // a seed that has no room: the registry is not because it lacks them
        let fake = Arc::new(Fake::default());
        let seed = fake.peer(0, Ok(c.clone()));
        *fake.holders.lock().unwrap() = Some([seed].into());
        fake.busy.lock().unwrap().insert(seed, 1);
        let s = querying(&fake, 8);
        let mut out = Collect::default();
        s.fetch_group(&items(&c), Some(LAYER), &mut out)
            .await
            .unwrap();
        let r = &s.decisions().about(LAYER, &[])[0];
        assert!(
            matches!(
                r.events.last(),
                Some(Event::Unsent {
                    items: 2,
                    reason: "every peer asked had no room"
                })
            ),
            "{:?}",
            r.events
        );
        // peers that have none of it
        let fake = Arc::new(Fake::default());
        for _ in 0..2 {
            fake.peer(0, Ok(Vec::new()));
        }
        let s = querying(&fake, 0);
        let mut out = Collect::default();
        s.fetch_group(&items(&c), Some(LAYER), &mut out)
            .await
            .unwrap();
        let r = &s.decisions().about(LAYER, &[])[0];
        assert!(
            matches!(
                r.events.last(),
                Some(Event::Unsent {
                    items: 2,
                    reason: "the peers asked do not have it"
                })
            ),
            "{:?}",
            r.events
        );
    }

    /// Everybody says no: no chunk is asked of anybody, the walk goes on to the next fetcher.
    #[tokio::test]
    async fn no_chunk_is_asked_of_peers_that_said_they_have_none() {
        let fake = Arc::new(Fake::default());
        let c = chunks(2);
        for _ in 0..4 {
            fake.peer(0, Ok(c.clone()));
        }
        *fake.holders.lock().unwrap() = Some(Default::default());
        let s = querying(&fake, 8);
        for layer in [Some(LAYER), None] {
            let mut out = Collect::default();
            s.fetch_group(&items(&c), layer, &mut out).await.unwrap();
            assert!(out.0.is_empty());
        }
        assert!(fake.asked.lock().unwrap().is_empty());
    }

    /// A provider the DHT names that was not connected (the lookup connects
    /// to it) is asked for the chunks by the group that looked it up, not
    /// only by the next one.
    #[tokio::test]
    async fn a_provider_the_dht_connected_to_is_asked_at_once() {
        let fake = Arc::new(Fake::default());
        let c = chunks(2);
        let far = fake.peer(0, Ok(c.clone()));
        let near = fake.peer(0, Ok(Vec::new()));
        fake.away.lock().unwrap().push(far);
        *fake.holders.lock().unwrap() = Some([far].into());
        let s = querying(&fake, 8);
        let mut out = Collect::default();
        s.fetch_group(&items(&c), Some(LAYER), &mut out)
            .await
            .unwrap();
        assert_eq!(*fake.probed.lock().unwrap(), [near]);
        assert_eq!(fake.lookups.load(Ordering::SeqCst), 1);
        assert_eq!(digests_of(&out), sorted(&c));
        assert_eq!(*fake.asked.lock().unwrap(), [far]);
    }

    /// A peer with no room says so: it is not taken for one without the
    /// layer (it is asked again by the next group), and the chunks are not
    /// recorded as missing.
    #[tokio::test]
    async fn a_busy_peer_is_not_one_that_has_none() {
        let fake = Arc::new(Fake::default());
        let c = chunks(2);
        let seed = fake.peer(0, Ok(c.clone()));
        *fake.holders.lock().unwrap() = Some([seed].into());
        // it has no room for the probe, nor for the request that follows
        fake.busy.lock().unwrap().insert(seed, 1);
        let s = querying(&fake, 8);
        let mut out = Collect::default();
        s.fetch_group(&items(&c), Some(LAYER), &mut out)
            .await
            .unwrap();
        assert!(out.0.is_empty());
        assert_eq!(*fake.asked.lock().unwrap(), [seed]);
        assert!(!s.knowledge().lacks(LAYER, &seed));
        let t = s.knowledge().traffic();
        assert_eq!((t[0].1.busy, t[0].1.failures), (1, 0));
        // the next group asks it again and has its chunks
        let mut out = Collect::default();
        s.fetch_group(&items(&c), Some(LAYER), &mut out)
            .await
            .unwrap();
        assert_eq!(digests_of(&out), sorted(&c));
        assert_eq!(s.knowledge().providers(LAYER), [seed]);
    }

    /// A peer with no room is asked again in the same group once something
    /// came in (a completion, not a wait): here the other peer sends the
    /// first chunk, and the busy one then has room for the rest.
    #[tokio::test]
    async fn a_busy_peer_is_asked_again_when_something_completed() {
        let fake = Arc::new(Fake::default());
        let c = chunks(2);
        let busy = fake.peer(0, Ok(c[1..].to_vec()));
        let other = fake.peer(0, Ok(c[..1].to_vec()));
        fake.honest.lock().unwrap().insert(busy);
        fake.honest.lock().unwrap().insert(other);
        fake.busy.lock().unwrap().insert(busy, 1);
        let s = PeerSource::with_peers(Arc::new(fake.clone())).with_policy(Policy {
            hedge: false,
            query_peers: 0,
            ..Policy::default()
        });
        // (the peers are asked in the order they rank: the busy one first)
        s.knowledge()
            .served(Some(LAYER), busy, Duration::from_millis(1));
        s.knowledge()
            .served(Some(LAYER), other, Duration::from_millis(9));
        let mut out = Collect::default();
        s.fetch_group(&items(&c), Some(LAYER), &mut out)
            .await
            .unwrap();
        assert_eq!(digests_of(&out), sorted(&c));
        assert_eq!(*fake.asked.lock().unwrap(), [busy, other, busy]);
    }

    /// How many peers are asked at once is bounded, and 0 asks none (the
    /// chunks are asked of the first peers as before).
    #[tokio::test]
    async fn the_questions_to_the_peers_are_bounded() {
        let fake = Arc::new(Fake::default());
        let c = chunks(2);
        for _ in 0..20 {
            fake.peer(0, Ok(c.clone()));
        }
        *fake.holders.lock().unwrap() = Some(Default::default());
        let mut out = Collect::default();
        querying(&fake, 4)
            .fetch_group(&items(&c), Some(LAYER), &mut out)
            .await
            .unwrap();
        assert_eq!(fake.probed.lock().unwrap().len(), 4);
        fake.probed.lock().unwrap().clear();
        let mut out = Collect::default();
        querying(&fake, 0)
            .fetch_group(&items(&c), Some(LAYER), &mut out)
            .await
            .unwrap();
        assert!(fake.probed.lock().unwrap().is_empty());
        assert_eq!(out.0.len(), 2, "the first peers have the chunks");
    }

    /// What the groups of a layer ask at the same time is asked once: each
    /// peer is asked one question for the four groups, and what the peers
    /// said is the answer of all.
    #[tokio::test]
    async fn the_groups_that_ask_at_the_same_time_share_the_probes() {
        let fake = Arc::new(Fake::default());
        let c = chunks(4);
        let holder = fake.peer(0, Ok(c.clone()));
        for _ in 0..5 {
            fake.peer(0, Ok(Vec::new()));
        }
        *fake.holders.lock().unwrap() = Some([holder].into());
        let source = querying(&fake, 8);
        let mut got: Vec<Asked> = (0..4).map(|_| Asked::default()).collect();
        let found = futures::future::join_all(
            got.iter_mut()
                .map(|g| source.from(Source::Probed, Some(LAYER), "sha256:first", g)),
        )
        .await;
        assert_eq!(
            fake.probed.lock().unwrap().len(),
            6,
            "one probe for each peer"
        );
        for (found, g) in found.iter().zip(&got) {
            assert_eq!(
                found.iter().map(|(p, _)| *p).collect::<Vec<_>>(),
                vec![holder]
            );
            assert_eq!(g.probed.len(), 6);
            assert_eq!(g.rounds, 1);
        }
    }

    /// A round whose peers had no room is not kept: the next group asks
    /// again, and a peer with no room is not one that lacks the chunk.
    #[tokio::test]
    async fn an_answer_of_no_room_is_not_kept_for_the_next_group() {
        let fake = Arc::new(Fake::default());
        let c = chunks(2);
        let busy = fake.peer(0, Ok(c.clone()));
        fake.busy.lock().unwrap().insert(busy, 1);
        *fake.holders.lock().unwrap() = Some([busy].into());
        let source = querying(&fake, 8);
        let mut first = Asked::default();
        let found = source
            .from(Source::Probed, Some(LAYER), "sha256:first", &mut first)
            .await;
        assert_eq!(found, vec![(busy, Why::Busy)]);
        assert!(!source.knowledge.lacks(LAYER, &busy));
        // (it has room now: the next group asks it, not the answer of the last)
        fake.busy.lock().unwrap().clear();
        let mut next = Asked::default();
        let found = source
            .from(Source::Probed, Some(LAYER), "sha256:first", &mut next)
            .await;
        assert_eq!(found, vec![(busy, Why::Probed)]);
        assert_eq!(fake.probed.lock().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn a_slow_peer_is_hedged_and_the_quick_answer_wins() {
        let fake = Arc::new(Fake::default());
        let c = chunks(4);
        let slow = fake.peer(3000, Ok(c.clone()));
        let quick = fake.peer(10, Ok(c.clone()));
        // the slow one is the better ranked
        let s = source(&fake, Some(40));
        s.knowledge().served(None, slow, Duration::from_millis(1));
        s.knowledge().served(None, quick, Duration::from_millis(5));
        let mut out = Collect::default();
        let started = Instant::now();
        s.fetch_group(&items(&c), Some(LAYER), &mut out)
            .await
            .unwrap();
        assert!(started.elapsed() < Duration::from_millis(1000));
        assert_eq!(digests_of(&out), sorted(&c));
        let asked = fake.asked.lock().unwrap().clone();
        assert_eq!(asked, [slow, quick]);
        // the loser was dropped, not waited for
        assert_eq!(fake.answered.load(Ordering::SeqCst), 1);
    }

    /// A hedge delay longer than the second the group looks at the rate
    /// every is waited for once, not started again at each look.
    #[tokio::test(start_paused = true)]
    async fn a_hedge_delay_longer_than_a_second_fires() {
        let fake = Arc::new(Fake::default());
        let c = chunks(4);
        let slow = fake.peer(60_000, Ok(c.clone()));
        let quick = fake.peer(10, Ok(c.clone()));
        let s = source(&fake, Some(1500));
        s.knowledge().served(None, slow, Duration::from_millis(1));
        s.knowledge().served(None, quick, Duration::from_millis(5));
        let mut out = Collect::default();
        let started = Instant::now();
        s.fetch_group(&items(&c), Some(LAYER), &mut out)
            .await
            .unwrap();
        assert_eq!(digests_of(&out), sorted(&c));
        assert_eq!(fake.asked.lock().unwrap().clone(), [slow, quick]);
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "{:?}",
            started.elapsed()
        );
    }

    /// A peer that sends a chunk, and the next one only when the one before
    /// it was passed on.
    struct Trickle {
        peer: PeerId,
        chunks: Vec<(String, Vec<u8>)>,
        passed: Arc<tokio::sync::Notify>,
    }

    #[async_trait]
    impl Peers for Trickle {
        async fn connected(&self) -> Vec<PeerId> {
            vec![self.peer]
        }
        async fn layer_providers(&self, _: &str) -> Vec<PeerId> {
            Vec::new()
        }
        async fn request(
            &self,
            _: PeerId,
            _: &[(String, Option<u64>)],
            _: Urgency,
            out: crate::ChunkTx,
        ) -> Result<(), PeerError> {
            for (at, chunk) in self.chunks.iter().enumerate() {
                if at > 0 {
                    self.passed.notified().await;
                }
                let _ = out.send(chunk.clone()).await;
            }
            Ok(())
        }
        async fn index(&self, _: PeerId, _: &str, _: u64) -> Result<Option<Vec<u8>>, PeerError> {
            Ok(None)
        }
        async fn has(&self, _: PeerId, _: &str) -> Result<Presence, String> {
            Ok(Presence::Has)
        }
        async fn profile(&self, _: PeerId, _: &str, _: u64) -> Result<Option<Vec<u8>>, PeerError> {
            Ok(None)
        }
    }

    struct Passing(Collect, Arc<tokio::sync::Notify>);

    #[async_trait]
    impl Sink for Passing {
        async fn put(&mut self, digest: &str, data: &[u8]) -> Result<(), String> {
            self.0.put(digest, data).await?;
            self.1.notify_one();
            Ok(())
        }
    }

    /// The chunks of an answer are checked and passed on as each arrives,
    /// not when the answer is complete.
    #[tokio::test]
    async fn a_chunk_is_passed_on_before_its_answer_is_complete() {
        let c = chunks(4);
        let passed = Arc::new(tokio::sync::Notify::new());
        let peers = Trickle {
            peer: PeerId::random(),
            chunks: c.clone(),
            passed: passed.clone(),
        };
        let s = PeerSource::with_peers(Arc::new(peers));
        let mut out = Passing(Collect::default(), passed);
        tokio::time::timeout(
            Duration::from_secs(10),
            s.fetch_group(&items(&c), Some(LAYER), &mut out),
        )
        .await
        .expect("a chunk waited for the end of its answer")
        .unwrap();
        assert_eq!(digests_of(&out.0), sorted(&c));
    }

    /// A peer that holds back its answer to a request nobody waits for,
    /// and answers the others.
    struct Holding(PeerId, Vec<(String, Vec<u8>)>);

    #[async_trait]
    impl Peers for Holding {
        async fn connected(&self) -> Vec<PeerId> {
            vec![self.0]
        }
        async fn layer_providers(&self, _: &str) -> Vec<PeerId> {
            Vec::new()
        }
        async fn request(
            &self,
            _: PeerId,
            items: &[(String, Option<u64>)],
            urgency: Urgency,
            out: crate::ChunkTx,
        ) -> Result<(), PeerError> {
            if urgency < Urgency::Wait {
                std::future::pending::<()>().await;
            }
            for chunk in self
                .1
                .iter()
                .filter(|(d, _)| items.iter().any(|(i, _)| i == d))
            {
                let _ = out.send(chunk.clone()).await;
            }
            Ok(())
        }
        async fn index(&self, _: PeerId, _: &str, _: u64) -> Result<Option<Vec<u8>>, PeerError> {
            Ok(None)
        }
        async fn has(&self, _: PeerId, _: &str) -> Result<Presence, String> {
            Ok(Presence::Has)
        }
        async fn profile(&self, _: PeerId, _: &str, _: u64) -> Result<Option<Vec<u8>>, PeerError> {
            Ok(None)
        }
    }

    /// The requests nobody waits for take at most half of the places of a
    /// peer: however many are under way, one that is waited for has a place.
    #[tokio::test]
    async fn a_request_waited_for_has_a_place_beside_the_background() {
        let c = chunks(9);
        let s = Arc::new(PeerSource::with_peers(Arc::new(Holding(
            PeerId::random(),
            c.clone(),
        ))));
        let mut background = Vec::new();
        for chunk in &c[..8] {
            let (s, items) = (s.clone(), items(std::slice::from_ref(chunk)));
            background.push(tokio::spawn(async move {
                s.fetch_group_as(
                    &items,
                    Some(LAYER),
                    Urgency::Background,
                    &mut Collect::default(),
                )
                .await
            }));
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
        let mut out = Collect::default();
        // (a request that waits gives up on a peer after seconds: one that
        // had a place is answered at once)
        tokio::time::timeout(
            Duration::from_secs(1),
            s.fetch_group_as(&items(&c[8..]), Some(LAYER), Urgency::OnDemand, &mut out),
        )
        .await
        .expect("the background took every place")
        .unwrap();
        assert_eq!(digests_of(&out), sorted(&c[8..]));
        for b in background {
            b.abort();
        }
    }

    #[tokio::test]
    async fn two_answers_for_the_same_chunks_are_passed_on_once() {
        let fake = Arc::new(Fake::default());
        let c = chunks(5);
        let a = fake.peer(80, Ok(c.clone()));
        fake.peer(0, Ok(c[..3].to_vec()));
        let s = source(&fake, Some(1));
        s.knowledge().served(None, a, Duration::from_millis(1));
        let mut out = Collect::default();
        s.fetch_group(&items(&c), Some(LAYER), &mut out)
            .await
            .unwrap();
        // the quick peer has three, the slow one all five: three are not
        // passed on twice
        assert_eq!(out.0.len(), 5, "{:?}", digests_of(&out));
        assert_eq!(digests_of(&out), sorted(&c));
    }

    #[tokio::test]
    async fn a_peer_whose_chunks_another_sent_first_is_not_taken_for_lacking_the_layer() {
        let fake = Arc::new(Fake::default());
        let c = chunks(5);
        // the first asked answers last, with chunks the second already sent
        let late = fake.peer(150, Ok(c[..3].to_vec()));
        let quick = fake.peer(0, Ok(c[..3].to_vec()));
        let rest = fake.peer(300, Ok(c[3..].to_vec()));
        let s = source(&fake, Some(1));
        s.knowledge().served(None, late, Duration::from_millis(1));
        s.knowledge().served(None, quick, Duration::from_millis(5));
        s.knowledge().served(None, rest, Duration::from_millis(10));
        let mut out = Collect::default();
        s.fetch_group(&items(&c), Some(LAYER), &mut out)
            .await
            .unwrap();
        assert_eq!(digests_of(&out), sorted(&c));
        assert_eq!(fake.asked.lock().unwrap().clone(), [late, quick, rest]);
        assert_eq!(fake.answered.load(Ordering::SeqCst), 3);
        assert!(!s.knowledge().lacks(LAYER, &late));
        assert!(s.knowledge().providers(LAYER).contains(&late));
    }

    #[tokio::test]
    async fn a_known_provider_that_is_slow_is_hedged_with_another_peer() {
        let fake = Arc::new(Fake::default());
        let c = chunks(2);
        let known = fake.peer(3000, Ok(c.clone()));
        let other = fake.peer(0, Ok(c.clone()));
        let s = source(&fake, Some(40));
        s.knowledge()
            .served(Some(LAYER), known, Duration::from_millis(1));
        let mut out = Collect::default();
        let started = Instant::now();
        s.fetch_group(&items(&c), Some(LAYER), &mut out)
            .await
            .unwrap();
        assert!(started.elapsed() < Duration::from_millis(1000));
        assert_eq!(fake.asked.lock().unwrap().clone(), [known, other]);
        assert_eq!(digests_of(&out), sorted(&c));
    }

    #[tokio::test]
    async fn a_second_peer_is_not_asked_when_hedging_is_off_or_the_first_is_quick() {
        let fake = Arc::new(Fake::default());
        let c = chunks(2);
        let slow = fake.peer(200, Ok(c.clone()));
        let other = fake.peer(0, Ok(c.clone()));
        let off = source(&fake, None);
        off.knowledge().served(None, slow, Duration::from_millis(1));
        off.knowledge()
            .served(None, other, Duration::from_millis(5));
        let mut out = Collect::default();
        let started = Instant::now();
        off.fetch_group(&items(&c), Some(LAYER), &mut out)
            .await
            .unwrap();
        assert!(started.elapsed() >= Duration::from_millis(200));
        assert_eq!(fake.asked.lock().unwrap().clone(), [slow]);
        assert_eq!(out.0.len(), 2);

        // hedging on, but the answer comes before the wait is over
        fake.asked.lock().unwrap().clear();
        let on = source(&fake, Some(2000));
        on.knowledge().served(None, other, Duration::from_millis(1));
        on.knowledge().served(None, slow, Duration::from_millis(5));
        let mut out = Collect::default();
        on.fetch_group(&items(&c), Some(LAYER), &mut out)
            .await
            .unwrap();
        assert_eq!(fake.asked.lock().unwrap().clone(), [other]);
    }

    /// A peer with no QUIC path is not asked for data: the request is a typed
    /// failure naming why, the chunks come from the next peer, the peer is
    /// not taken for one that lies nor for one without the layer, and the
    /// explanation says there was no path.
    #[tokio::test]
    async fn a_peer_with_no_quic_path_is_passed_over_for_the_next_peer() {
        use crate::explain::{Event, Outcome};
        let fake = Arc::new(Fake::default());
        let c = chunks(3);
        let blocked = fake.peer(0, Ok(c.clone()));
        let good = fake.peer(0, Ok(c.clone()));
        fake.no_path.lock().unwrap().insert(blocked);
        let s = source(&fake, None);
        s.knowledge()
            .served(None, blocked, Duration::from_micros(1));
        s.knowledge().served(None, good, Duration::from_micros(2));
        let mut out = Collect::default();
        s.fetch_group(&items(&c), Some(LAYER), &mut out)
            .await
            .unwrap();
        assert_eq!(fake.asked.lock().unwrap().clone(), [blocked, good]);
        assert_eq!(digests_of(&out), sorted(&c));
        assert!(!s.knowledge().lacks(LAYER, &blocked));
        let asked: Vec<Outcome> = s
            .decisions()
            .about(LAYER, &[])
            .iter()
            .flat_map(|d| d.events.clone())
            .filter_map(|e| match e {
                Event::Asked { peer, outcome, .. } if peer == blocked => Some(outcome),
                _ => None,
            })
            .collect();
        assert!(
            matches!(&asked[..], [Outcome::NoPath(why)] if why.contains("no QUIC")),
            "{asked:?}"
        );
    }

    /// What is told to the engine when nothing came: with no path to any of
    /// the peers connected the reason says so (the network, not the store, is
    /// to be looked at); with some, how many; with none, only that no peer
    /// has it.
    #[tokio::test]
    async fn nothing_from_peers_with_no_quic_path_is_told_as_that() {
        let fake = Arc::new(Fake::default());
        let (a, b) = (fake.peer(0, Ok(Vec::new())), fake.peer(0, Ok(Vec::new())));
        let s = source(&fake, None);
        assert_eq!(s.nobody("no peer has it").await, "no peer has it");
        fake.no_path.lock().unwrap().insert(a);
        assert_eq!(
            s.nobody("no peer has it").await,
            "no peer has it (1 of 2 connected peers have no QUIC (UDP) path)"
        );
        fake.no_path.lock().unwrap().insert(b);
        let all = s.nobody("no peer has it").await;
        assert!(
            all.starts_with("no QUIC (UDP) path to any of the 2 connected peers"),
            "{all}"
        );
    }

    /// A peer whose request failed (a silent one: after its timeout) is not
    /// asked again by the groups that come after, which go on to the next
    /// source at once.
    #[tokio::test]
    async fn a_peer_whose_request_failed_is_not_asked_by_the_next_groups() {
        let fake = Arc::new(Fake::default());
        let c = chunks(6);
        let silent = fake.peer(0, Err("QUIC read: timed out".into()));
        let s = source(&fake, None);
        s.knowledge().served(None, silent, Duration::from_micros(1));
        for group in [&c[..3], &c[3..]] {
            let mut out = Collect::default();
            s.fetch_group(&items(group), Some(LAYER), &mut out)
                .await
                .unwrap();
            assert!(out.0.is_empty());
        }
        assert_eq!(fake.asked.lock().unwrap().clone(), [silent]);
    }

    #[tokio::test]
    async fn a_peer_that_fails_or_lies_is_replaced_at_once() {
        let fake = Arc::new(Fake::default());
        let c = chunks(3);
        let failing = fake.peer(0, Err("boom".into()));
        let liar = fake.peer(
            0,
            Ok(c.iter()
                .map(|(d, _)| (d.clone(), b"lies".to_vec()))
                .collect()),
        );
        let good = fake.peer(0, Ok(c.clone()));
        let s = source(&fake, None);
        s.knowledge()
            .served(None, failing, Duration::from_micros(1));
        s.knowledge().served(None, liar, Duration::from_micros(2));
        s.knowledge().served(None, good, Duration::from_micros(3));
        let mut out = Collect::default();
        s.fetch_group(&items(&c), Some(LAYER), &mut out)
            .await
            .unwrap();
        assert_eq!(fake.asked.lock().unwrap().clone(), [failing, liar, good]);
        assert_eq!(digests_of(&out), sorted(&c));
        assert!(out.0.iter().all(|(d, data)| digest_of(data) == *d));
    }

    /// Peers that whose filter says they hold the layer and fail, lie or say nothing
    /// are replaced by the next sources, not by the registry: the three
    /// the filters name are not all there is.
    #[tokio::test]
    async fn a_group_goes_on_to_other_peers_when_the_ones_the_filters_name_give_nothing() {
        let fake = Arc::new(Fake::default());
        let c = chunks(3);
        let bad: Vec<PeerId> = (0..6)
            .map(|i| match i % 3 {
                0 => fake.peer(0, Err("boom".into())),
                1 => fake.peer(
                    0,
                    Ok(c.iter()
                        .map(|(d, _)| (d.clone(), b"lies".to_vec()))
                        .collect()),
                ),
                _ => fake.peer(0, Ok(Vec::new())),
            })
            .collect();
        let good = fake.peer(0, Ok(c.clone()));
        *fake.holders.lock().unwrap() = Some([good].into());
        let s = querying(&fake, 8);
        tell_maybe(&s, &bad, LAYER);
        let mut out = Collect::default();
        s.fetch_group(&items(&c), Some(LAYER), &mut out)
            .await
            .unwrap();
        assert_eq!(
            digests_of(&out),
            sorted(&c),
            "the peer that has it was not used"
        );
        let asked = fake.asked.lock().unwrap().clone();
        assert!(asked.contains(&good));
        // (bounded, and not all of one origin: the filters' come first)
        assert!(asked.len() <= MAX_ASKED, "{} peers asked", asked.len());
        assert!(asked[..2].iter().all(|p| bad.contains(p)));
    }

    /// A group asks at most [`MAX_ASKED`] peers, however many fail: the
    /// rest of its chunks go to the next source of the engine, not to a
    /// thousand peers one after the other.
    #[tokio::test]
    async fn a_group_asks_at_most_so_many_peers() {
        let fake = Arc::new(Fake::default());
        let c = chunks(2);
        let bad: Vec<PeerId> = (0..30).map(|_| fake.peer(0, Err("boom".into()))).collect();
        let s = querying(&fake, 8);
        tell_maybe(&s, &bad, LAYER);
        let mut out = Collect::default();
        s.fetch_group(&items(&c), Some(LAYER), &mut out)
            .await
            .unwrap();
        assert!(out.0.is_empty());
        assert_eq!(fake.asked.lock().unwrap().len(), MAX_ASKED);
    }

    /// When every peer is slow, the hedges are spaced (each waits twice as
    /// long as the one before it): a group does not ask its eight peers for
    /// the same chunks at once.  Ten peers that all answer in 3 s, hedged
    /// after 200 ms: asked at 0, 0.2, 0.6, 1.4 s and 3 s (not every 200 ms).
    #[tokio::test(start_paused = true)]
    async fn a_swarm_that_is_slow_everywhere_is_not_asked_eight_times_at_once() {
        let fake = Arc::new(Fake::default());
        let c = chunks(2);
        let slow: Vec<PeerId> = (0..10).map(|_| fake.peer(3000, Ok(c.clone()))).collect();
        let s = source(&fake, Some(200));
        tell_maybe(&s, &slow, LAYER);
        let mut out = Collect::default();
        s.fetch_group(&items(&c), Some(LAYER), &mut out)
            .await
            .unwrap();
        assert_eq!(digests_of(&out), sorted(&c));
        let asked = fake.asked.lock().unwrap().len();
        assert!((2..=5).contains(&asked), "{asked} peers asked");
    }

    /// The chunk a peer sent wrong bytes for is taken from the next peer.
    #[tokio::test]
    async fn a_chunk_of_wrong_bytes_is_taken_from_the_next_peer() {
        let fake = Arc::new(Fake::default());
        let c = chunks(1);
        let liar = fake.peer(0, Ok(vec![(c[0].0.clone(), b"lies".to_vec())]));
        let good = fake.peer(0, Ok(c.clone()));
        let s = source(&fake, None);
        tell_maybe(&s, &[liar, good], LAYER);
        s.knowledge()
            .served(Some(LAYER), liar, Duration::from_micros(1));
        s.knowledge()
            .served(Some(LAYER), good, Duration::from_micros(2));
        let mut out = Collect::default();
        s.fetch_group(&items(&c), Some(LAYER), &mut out)
            .await
            .unwrap();
        assert_eq!(fake.asked.lock().unwrap().clone(), [liar, good]);
        assert_eq!(digests_of(&out), sorted(&c));
    }

    #[tokio::test]
    async fn only_what_was_asked_for_and_the_right_size_is_passed_on() {
        let fake = Arc::new(Fake::default());
        let c = chunks(2);
        let extra = chunks(4).pop().unwrap();
        let mut reply = c.clone();
        reply.push(extra.clone());
        // the right bytes for a digest, but not the size the TOC says
        let mut it = items(&c);
        it[1].size = Some(999);
        fake.peer(0, Ok(reply));
        let s = source(&fake, None);
        let mut out = Collect::default();
        s.fetch_group(&it, Some(LAYER), &mut out).await.unwrap();
        assert_eq!(digests_of(&out), vec![c[0].0.clone()]);
    }

    #[tokio::test]
    async fn the_next_request_uses_what_the_last_one_taught() {
        let fake = Arc::new(Fake::default());
        let c = chunks(3);
        let has = fake.peer(0, Ok(c.clone()));
        let _empty = fake.peer(0, Ok(Vec::new()));
        // no filter names the layer: every connected peer is tried
        let s = source(&fake, None);
        for _ in 0..3 {
            let mut out = Collect::default();
            s.fetch_group(&items(&c), Some(LAYER), &mut out)
                .await
                .unwrap();
            assert_eq!(out.0.len(), 3);
        }
        let asked = fake.asked.lock().unwrap().clone();
        // after the first round the one that serves it is asked, alone
        assert!(asked.len() <= 4, "{asked:?}");
        assert_eq!(asked.iter().rev().take(2).collect::<Vec<_>>(), [&has, &has]);
        assert_eq!(s.knowledge().providers(LAYER), [has]);
        // and the lookup of the layer was done once, with the first round
        assert_eq!(fake.lookups.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn a_layer_nobody_has_goes_to_the_registry_without_asking_again() {
        let fake = Arc::new(Fake::default());
        let c = chunks(2);
        let a = fake.peer(0, Ok(Vec::new()));
        let b = fake.peer(0, Ok(Vec::new()));
        let s = source(&fake, None);
        let layer = Some(LAYER);
        let mut out = Collect::default();
        s.fetch_group(&items(&c), layer, &mut out).await.unwrap();
        assert!(out.0.is_empty());
        assert_eq!(fake.asked.lock().unwrap().len(), 2);
        // now both are known to have none: nothing is asked
        let mut out = Collect::default();
        s.fetch_group(&items(&c), layer, &mut out).await.unwrap();
        assert_eq!(fake.asked.lock().unwrap().len(), 2);
        // another layer is not affected
        let mut out = Collect::default();
        s.fetch_group(&items(&c), Some("sha256:other"), &mut out)
            .await
            .unwrap();
        assert_eq!(fake.asked.lock().unwrap().len(), 4);
        assert!(s.knowledge().lacks(LAYER, &a) && s.knowledge().lacks(LAYER, &b));
    }

    /// `n` chunks of 1 MiB.
    fn big_chunks(n: usize) -> Vec<(String, Vec<u8>)> {
        (0..n)
            .map(|i| {
                let data = vec![i as u8; 1 << 20];
                (digest_of(&data), data)
            })
            .collect()
    }

    /// Two peers that served the layer and answer only what they are asked.
    fn two_holders(
        fake: &Arc<Fake>,
        s: &PeerSource,
        a: (u64, Vec<(String, Vec<u8>)>),
        b: (u64, Vec<(String, Vec<u8>)>),
    ) -> (PeerId, PeerId) {
        let a = fake.peer(a.0, Ok(a.1));
        let b = fake.peer(b.0, Ok(b.1));
        fake.honest.lock().unwrap().extend([a, b]);
        s.knowledge()
            .served(Some(LAYER), a, Duration::from_millis(1));
        s.knowledge()
            .served(Some(LAYER), b, Duration::from_millis(2));
        (a, b)
    }

    #[test]
    fn a_group_is_cut_in_parts_only_when_it_is_big() {
        let c = big_chunks(9);
        let parts = stripe_parts(&items(&c)).unwrap();
        // two chunks of 1 MiB a part, in order
        assert_eq!(
            parts,
            [vec![0, 1], vec![2, 3], vec![4, 5], vec![6, 7], vec![8]]
        );
        assert!(stripe_parts(&items(&c[..3])).is_none());
        assert!(stripe_parts(&items(&chunks(100))).is_none());
        // many small chunks: bounded by count too
        let mut many = items(&chunks(200));
        for i in &mut many {
            i.size = Some(64 << 10);
        }
        let parts = stripe_parts(&many).unwrap();
        assert!(parts.iter().all(|p| p.len() <= STRIPE_ITEMS));
        assert_eq!(parts.iter().map(Vec::len).sum::<usize>(), 200);
    }

    #[tokio::test]
    async fn a_big_group_is_spread_over_the_peers_that_have_the_layer() {
        let fake = Arc::new(Fake::default());
        let c = big_chunks(8);
        let s = source(&fake, None);
        let (a, b) = two_holders(&fake, &s, (50, c.clone()), (50, c.clone()));
        let mut out = Collect::default();
        let started = Instant::now();
        s.fetch_group(&items(&c), Some(LAYER), &mut out)
            .await
            .unwrap();
        assert_eq!(out.0.len(), 8, "each once");
        assert_eq!(digests_of(&out), sorted(&c));
        let sizes = fake.sizes.lock().unwrap().clone();
        // four parts of two chunks, two for each peer, at the same time
        assert_eq!(sizes.len(), 4, "{sizes:?}");
        assert!(sizes.iter().all(|(_, n)| *n == 2));
        assert_eq!(sizes.iter().filter(|(p, _)| *p == a).count(), 2);
        assert_eq!(sizes.iter().filter(|(p, _)| *p == b).count(), 2);
        assert!(started.elapsed() < Duration::from_millis(1000));
        let t = s.knowledge().traffic();
        assert!(t.iter().all(|(_, t)| t.bytes == 4 << 20 && t.requests == 2));
    }

    #[tokio::test]
    async fn what_a_peer_of_the_stripe_lacks_comes_from_another() {
        let fake = Arc::new(Fake::default());
        let c = big_chunks(8);
        let s = source(&fake, None);
        // `a` has the first half only
        two_holders(&fake, &s, (0, c[..4].to_vec()), (20, c.clone()));
        let mut out = Collect::default();
        s.fetch_group(&items(&c), Some(LAYER), &mut out)
            .await
            .unwrap();
        assert_eq!(digests_of(&out), sorted(&c));
        assert_eq!(out.0.len(), 8);
    }

    #[tokio::test]
    async fn a_part_a_peer_of_the_stripe_is_slow_with_is_asked_of_another() {
        let fake = Arc::new(Fake::default());
        let c = big_chunks(6);
        let s = source(&fake, Some(30));
        two_holders(&fake, &s, (3000, c.clone()), (10, c.clone()));
        let mut out = Collect::default();
        let started = Instant::now();
        s.fetch_group(&items(&c), Some(LAYER), &mut out)
            .await
            .unwrap();
        assert!(started.elapsed() < Duration::from_millis(1500));
        assert_eq!(digests_of(&out), sorted(&c));
        assert_eq!(out.0.len(), 6);
    }

    /// Peers that are all slow (the node's own link is the bottleneck) are
    /// not asked for the same parts twice: what is asked twice is a part,
    /// and a small share of what is asked.
    #[tokio::test]
    async fn the_parts_asked_twice_are_a_small_share() {
        let fake = Arc::new(Fake::default());
        let c = big_chunks(6);
        let s = source(&fake, Some(10));
        two_holders(&fake, &s, (100, c.clone()), (100, c.clone()));
        let mut out = Collect::default();
        s.fetch_group(&items(&c), Some(LAYER), &mut out)
            .await
            .unwrap();
        assert_eq!(digests_of(&out), sorted(&c));
        // three parts of 2 MiB, and one of them once more
        assert_eq!(fake.sizes.lock().unwrap().len(), 4);
    }

    /// A part is asked of another peer when the first took much longer than
    /// the parts the others have answered, not when it is merely slower
    /// than its hedge delay.
    #[tokio::test]
    async fn a_part_is_hedged_when_it_is_late_for_the_group() {
        let fake = Arc::new(Fake::default());
        let c = big_chunks(8);
        let s = source(&fake, Some(10));
        // (the quick peer answers each part in 60 ms; the other peer, asked
        // first, takes 400 ms for its part)
        let (slow, quick) = two_holders(&fake, &s, (400, c.clone()), (60, c.clone()));
        let mut out = Collect::default();
        let started = Instant::now();
        s.fetch_group(&items(&c), Some(LAYER), &mut out)
            .await
            .unwrap();
        assert_eq!(digests_of(&out), sorted(&c));
        let sizes = fake.sizes.lock().unwrap().clone();
        assert!(started.elapsed() < Duration::from_millis(400), "{sizes:?}");
        assert!(sizes.iter().any(|(p, _)| *p == quick) && sizes.iter().any(|(p, _)| *p == slow));
    }

    /// The peers of the zone of this node are asked before the others, the
    /// others when they give nothing.
    #[tokio::test]
    async fn the_peers_of_the_zone_are_asked_first() {
        let fake = Arc::new(Fake::default());
        let c = chunks(2);
        let s = source(&fake, None);
        let quick_far = fake.peer(1, Ok(c.clone()));
        let near = fake.peer(30, Ok(c.clone()));
        fake.far.lock().unwrap().insert(quick_far);
        s.knowledge()
            .served(Some(LAYER), quick_far, Duration::from_millis(1));
        s.knowledge()
            .served(Some(LAYER), near, Duration::from_millis(20));
        let mut out = Collect::default();
        s.fetch_group(&items(&c), Some(LAYER), &mut out)
            .await
            .unwrap();
        assert_eq!(fake.asked.lock().unwrap()[0], near);
        assert_eq!(digests_of(&out), sorted(&c));
    }

    /// A group is asked of a peer this node is not asking for much at the
    /// moment before the peer it asks for more, even when that answers
    /// quicker.
    #[tokio::test]
    async fn a_peer_this_node_is_asking_less_is_asked_first() {
        let fake = Arc::new(Fake::default());
        let c = chunks(2);
        let s = source(&fake, None);
        let quick = fake.peer(1, Ok(c.clone()));
        let idle = fake.peer(1, Ok(c.clone()));
        s.knowledge()
            .served(Some(LAYER), quick, Duration::from_millis(1));
        s.knowledge()
            .served(Some(LAYER), idle, Duration::from_millis(20));
        let _busy = s.requested.places(quick, 4).await;
        let mut out = Collect::default();
        s.fetch_group(&items(&c), Some(LAYER), &mut out)
            .await
            .unwrap();
        assert_eq!(fake.asked.lock().unwrap()[0], idle);
    }

    /// A swarm that gives this node a quarter of what it gave before is not
    /// waited for: after a few seconds the group is left to the registry.
    #[tokio::test(start_paused = true)]
    async fn a_group_the_peers_are_much_slower_with_than_before_is_left_to_the_registry() {
        let fake = Arc::new(Fake::default());
        let c = big_chunks(8);
        let s = source(&fake, None);
        let peer = fake.peer(500, Ok(c.clone()));
        fake.honest.lock().unwrap().insert(peer);
        s.knowledge()
            .served(Some(LAYER), peer, Duration::from_millis(1));
        // 8 MiB in half a second: 16 MiB/s, for ten seconds
        for _ in 0..20 {
            let mut out = Collect::default();
            s.fetch_group(&items(&c), Some(LAYER), &mut out)
                .await
                .unwrap();
            assert_eq!(out.0.len(), 8);
        }
        // now it takes a minute
        fake.peers.lock().unwrap().get_mut(&peer).unwrap().delay = Duration::from_secs(60);
        let mut out = Collect::default();
        let started = Instant::now();
        s.fetch_group(&items(&c), Some(LAYER), &mut out)
            .await
            .unwrap();
        assert!(out.0.is_empty());
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "{:?}",
            started.elapsed()
        );
        let seen = s.decisions().about("", &[]);
        assert!(
            seen.iter()
                .any(|r| r.events.iter().any(|e| matches!(e, Event::Slow { .. }))),
            "the decision says why"
        );
    }

    /// A peer that never answers, from the first request on (nothing was ever
    /// given, so there is no rate to compare with): the group is left to the
    /// registry after a few seconds, and the groups after it do not ask the
    /// peer at all.
    #[tokio::test(start_paused = true)]
    async fn a_peer_that_never_answers_costs_one_group_a_few_seconds() {
        let fake = Arc::new(Fake::default());
        let c = big_chunks(8);
        let s = source(&fake, None);
        let mute = fake.peer(3_600_000, Ok(c.clone()));
        s.knowledge()
            .served(Some(LAYER), mute, Duration::from_millis(1));
        let started = Instant::now();
        let mut out = Collect::default();
        s.fetch_group(&items(&c), Some(LAYER), &mut out)
            .await
            .unwrap();
        assert!(out.0.is_empty());
        assert!(
            started.elapsed() < SLOW_AFTER + Duration::from_secs(2),
            "{:?}",
            started.elapsed()
        );
        let again = Instant::now();
        s.fetch_group(&items(&c), Some(LAYER), &mut out)
            .await
            .unwrap();
        assert!(
            again.elapsed() < Duration::from_secs(1),
            "{:?}",
            again.elapsed()
        );
        assert_eq!(fake.asked.lock().unwrap().len(), 1, "asked once");
    }

    /// A swarm that is slow but steady from the first byte (a slow link: 16
    /// MiB in 8 s, half the floor) is not given up while its answer comes at
    /// a quarter of the floor.
    #[tokio::test(start_paused = true)]
    async fn a_slow_link_from_the_first_byte_is_not_given_up() {
        let fake = Arc::new(Fake::default());
        let c = big_chunks(16);
        let s = source(&fake, None);
        let peer = fake.peer(8000, Ok(c.clone()));
        fake.honest.lock().unwrap().insert(peer);
        s.knowledge()
            .served(Some(LAYER), peer, Duration::from_millis(1));
        for _ in 0..2 {
            let mut out = Collect::default();
            s.fetch_group(&items(&c), Some(LAYER), &mut out)
                .await
                .unwrap();
            assert_eq!(out.0.len(), 16);
        }
    }

    /// The rate is of the last seconds: after a pause it says nothing until
    /// there is a window again, not the bytes of the old pull over the pause.
    #[tokio::test(start_paused = true)]
    async fn the_rate_is_not_measured_across_a_pause() {
        let rate = Rate::default();
        for _ in 0..10 {
            rate.add(16 << 20);
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
        assert!(rate.sample(0).is_some_and(|(r, _)| r > 1e7));
        tokio::time::sleep(Duration::from_secs(60)).await;
        assert_eq!(rate.sample(0), None);
        for _ in 0..6 {
            rate.add(16 << 20);
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
        assert!(rate.sample(0).is_some_and(|(r, _)| r > 1e7));
    }

    #[tokio::test]
    async fn a_small_group_or_one_holder_is_not_spread() {
        let fake = Arc::new(Fake::default());
        let s = source(&fake, None);
        let c = chunks(4);
        two_holders(&fake, &s, (0, c.clone()), (0, c.clone()));
        let mut out = Collect::default();
        s.fetch_group(&items(&c), Some(LAYER), &mut out)
            .await
            .unwrap();
        assert_eq!(fake.sizes.lock().unwrap().clone().len(), 1);
        // striping off
        let big = big_chunks(8);
        let fake = Arc::new(Fake::default());
        let off = PeerSource::with_peers(Arc::new(fake.clone())).with_policy(Policy {
            stripe_peers: 1,
            ..Policy::default()
        });
        two_holders(&fake, &off, (0, big.clone()), (0, big.clone()));
        let mut out = Collect::default();
        off.fetch_group(&items(&big), Some(LAYER), &mut out)
            .await
            .unwrap();
        assert_eq!(
            fake.sizes.lock().unwrap().clone(),
            [(fake.asked.lock().unwrap()[0], 8)]
        );
    }

    /// A profile is what the file system that reads it takes: its entries
    /// are objects of the store.  A list of plain digests is none (that file
    /// system drops every entry), though they are digests.
    #[test]
    fn a_profile_is_one_the_file_system_reads() {
        let object =
            velarx_storage::fsverity_digest_of(velarx_types::digest::Algorithm::Sha256, b"x");
        let good = serde_json::json!({"v": 1, "files": [object]}).to_string();
        assert!(looks_like_a_profile(good.as_bytes()));
        let plain = serde_json::json!({"v": 1, "files": [digest_of(b"x")]}).to_string();
        assert!(!looks_like_a_profile(plain.as_bytes()));
        assert!(!looks_like_a_profile(br#"{"v":2,"files":[]}"#));
    }

    #[tokio::test]
    async fn a_profile_comes_from_the_first_peer_that_has_one_that_looks_right() {
        let fake = Arc::new(Fake::default());
        let s = source(&fake, None);
        let (garbage, empty, good) = (
            fake.peer(0, Ok(Vec::new())),
            fake.peer(0, Ok(Vec::new())),
            fake.peer(0, Ok(Vec::new())),
        );
        // (the entries of a profile are the objects of the store, as the
        // file system that reads it takes them)
        let object =
            velarx_storage::fsverity_digest_of(velarx_types::digest::Algorithm::Sha256, b"x");
        let doc = serde_json::json!({"v": 1, "files": [object]}).to_string();
        {
            let mut p = fake.profiles.lock().unwrap();
            p.insert(garbage, b"not a profile".to_vec());
            p.insert(empty, br#"{"v":1,"files":["x"]}"#.to_vec());
            p.insert(good, doc.clone().into_bytes());
        }
        // the peers of the layer first
        s.knowledge()
            .served(Some(LAYER), garbage, Duration::from_millis(1));
        s.knowledge()
            .served(Some(LAYER), empty, Duration::from_millis(2));
        s.knowledge()
            .served(Some(LAYER), good, Duration::from_millis(3));
        let image = Item {
            digest: digest_of(b"image"),
            size: Some(1 << 20),
        };
        let mut out = Collect::default();
        s.fetch_profiles(std::slice::from_ref(&image), Some(LAYER), &mut out)
            .await
            .unwrap();
        assert_eq!(out.0, [(image.digest.clone(), doc.into_bytes())]);
        assert_eq!(
            fake.profile_asked.lock().unwrap().clone(),
            [garbage, empty, good]
        );
        // bounded by what is asked
        let small = Item {
            size: Some(4),
            ..image
        };
        let mut out = Collect::default();
        s.fetch_profiles(&[small], Some(LAYER), &mut out)
            .await
            .unwrap();
        assert!(out.0.is_empty());
    }

    /// A peer that has no room to give an index or a profile is not a peer
    /// without one: it is told so by the explanation, counted busy, nothing
    /// is recorded of the layer, and the next peer is asked.
    #[tokio::test]
    async fn a_peer_with_no_room_for_an_index_or_a_profile_is_not_one_without() {
        let fake = Arc::new(Fake::default());
        let s = source(&fake, None);
        let (busy, has) = (fake.peer(0, Ok(Vec::new())), fake.peer(0, Ok(Vec::new())));
        fake.busy.lock().unwrap().insert(busy, 2);
        let object =
            velarx_storage::fsverity_digest_of(velarx_types::digest::Algorithm::Sha256, b"x");
        let doc = serde_json::json!({"v": 1, "files": [object]}).to_string();
        fake.profiles
            .lock()
            .unwrap()
            .insert(has, doc.clone().into_bytes());
        fake.indexes
            .lock()
            .unwrap()
            .insert(has, b"an index".to_vec());
        s.knowledge()
            .served(Some(LAYER), busy, Duration::from_millis(1));
        s.knowledge()
            .served(Some(LAYER), has, Duration::from_millis(2));
        let item = Item {
            digest: digest_of(b"image"),
            size: Some(1 << 20),
        };
        let outcomes = |s: &PeerSource, about: &str| -> Vec<(PeerId, Outcome)> {
            s.decisions()
                .about(about, &[])
                .iter()
                .flat_map(|d| d.events.clone())
                .filter_map(|e| match e {
                    Event::Asked { peer, outcome, .. } => Some((peer, outcome)),
                    _ => None,
                })
                .collect()
        };
        let mut out = Collect::default();
        s.fetch_profiles(std::slice::from_ref(&item), Some(LAYER), &mut out)
            .await
            .unwrap();
        assert_eq!(out.0, [(item.digest.clone(), doc.into_bytes())]);
        let told = outcomes(&s, &item.digest);
        assert_eq!(told[0], (busy, Outcome::Busy), "{told:?}");
        // (the index of a layer: asked of the peers that served it)
        let layer = Item {
            digest: digest_of(b"a layer"),
            size: Some(1 << 20),
        };
        for (peer, rtt) in [(busy, 1), (has, 2)] {
            s.knowledge()
                .served(Some(&layer.digest), peer, Duration::from_millis(rtt));
        }
        let mut out = Collect::default();
        s.fetch_index(&layer, false, &[], &|_| true, &mut out)
            .await
            .unwrap();
        assert_eq!(out.0, [(layer.digest.clone(), b"an index".to_vec())]);
        let told = outcomes(&s, &layer.digest);
        assert_eq!(told[0], (busy, Outcome::Busy), "{told:?}");
        assert!(!s.knowledge().lacks(LAYER, &busy));
    }

    /// When a peer sends an index that is not one the next provider is
    /// asked.
    #[tokio::test]
    async fn a_lying_index_is_passed_over_for_the_next_provider() {
        let fake = Arc::new(Fake::default());
        let (liar, honest) = (fake.peer(0, Ok(vec![])), fake.peer(0, Ok(vec![])));
        fake.indexes
            .lock()
            .unwrap()
            .insert(liar, b"garbage".to_vec());
        fake.indexes
            .lock()
            .unwrap()
            .insert(honest, b"an index".to_vec());
        let s = source(&fake, None);
        let layer = Item {
            digest: digest_of(b"a layer"),
            size: Some(1 << 20),
        };
        for (peer, rtt) in [(liar, 1), (honest, 2)] {
            s.knowledge()
                .served(Some(&layer.digest), peer, Duration::from_millis(rtt));
        }
        let mut out = Collect::default();
        let given = s
            .fetch_index(
                &layer,
                false,
                &[],
                &|bytes| bytes.starts_with(b"an "),
                &mut out,
            )
            .await
            .unwrap();
        assert_eq!(out.0, [(layer.digest.clone(), b"an index".to_vec())]);
        assert_eq!(given, Some(honest));
        assert_eq!(*fake.index_asked.lock().unwrap(), [liar, honest]);
        // (what each sent is in the traffic of the status)
        let traffic: HashMap<PeerId, (u64, u64, u64)> = (s.knowledge().traffic().into_iter())
            .map(|(p, t)| (p, (t.requests, t.failures, t.bytes)))
            .collect();
        assert_eq!(traffic[&honest], (1, 0, 8));
        assert_eq!(traffic[&liar], (1, 1, 0));
        // (a provider the puller refused the index of is not asked)
        let mut out = Collect::default();
        let given = s
            .fetch_index(&layer, false, &[honest], &|_| true, &mut out)
            .await
            .unwrap();
        assert_eq!((given, out.0.len()), (Some(liar), 1));
        assert_eq!(*fake.index_asked.lock().unwrap(), [liar, honest, liar]);
    }

    /// A table of contents is taken from a peer only when it has the
    /// checksum of the layer's descriptor and its tar-split the digest the
    /// table names: the table recompressed (what a node keeps as its view)
    /// or another tar-split is passed over for the next peer, and with no
    /// right one the layer is left to the next fetcher.
    #[tokio::test]
    async fn a_wrong_table_of_contents_from_a_peer_is_not_taken() {
        use velarx_content::pull::index;
        let tarsplit = b"a tar-split".to_vec();
        let toc = format!(
            r#"{{"version":1,"entries":[],"tarSplitDigest":"{}"}}"#,
            digest_of(&tarsplit)
        );
        let toc_z = zstd::encode_all(toc.as_bytes(), 19).unwrap();
        let checksum: velarx_types::digest::Digest = digest_of(&toc_z).parse().unwrap();
        let wrong = [
            index::encode(toc.as_bytes(), &tarsplit).unwrap(),
            index::encode_compressed(&toc_z, b"another tar-split").unwrap(),
        ];
        let right = index::encode_compressed(&toc_z, &tarsplit).unwrap();
        for honest in [true, false] {
            let fake = Arc::new(Fake::default());
            let mut peers = Vec::new();
            for bytes in wrong.iter().chain(honest.then_some(&right)) {
                let peer = fake.peer(0, Ok(vec![]));
                fake.indexes.lock().unwrap().insert(peer, bytes.clone());
                peers.push(peer);
            }
            let s = source(&fake, None);
            let key = velarx_types::LayerKey::Toc(checksum).to_string();
            for (rtt, peer) in peers.iter().enumerate() {
                s.knowledge()
                    .served(Some(&key), *peer, Duration::from_millis(rtt as u64 + 1));
            }
            let got = s
                .index_of(&checksum, true, index::json_cap(1 << 20), &[])
                .await
                .map(|(index, _)| index);
            assert_eq!(got, honest.then(|| (toc_z.clone(), tarsplit.clone())));
            assert_eq!(*fake.index_asked.lock().unwrap(), peers);
        }
    }

    /// The `Probe` of a layer without a table of contents carries the index
    /// a peer has for its blob (not lazy: `no_toc`), unless its tar-split is
    /// not the one its table names; a zstd:chunked layer is answered as it
    /// was, from the index of its checksum.
    #[tokio::test]
    async fn a_probe_of_a_whole_layer_carries_its_index() {
        use velarx_content::fetcher::fetch::{Blob, NotLazy, TocSource};
        use velarx_content::pull::index;
        use velarx_content::serve_fetch::{Out, Scope, StagingFetcher};
        let tarsplit = b"a tar-split".to_vec();
        let toc = format!(
            r#"{{"version":1,"entries":[],"tarSplitDigest":"{}"}}"#,
            digest_of(&tarsplit)
        );
        let toc_z = zstd::encode_all(toc.as_bytes(), 19).unwrap();
        let right = index::encode_compressed(&toc_z, &tarsplit).unwrap();
        let wrong = index::encode_compressed(&toc_z, b"another tar-split").unwrap();
        let checksum = digest_of(&toc_z);
        let blob = |checksum: Option<&str>| Blob {
            digest: digest_of(b"a layer"),
            size: 1 << 20,
            media_type: "application/vnd.oci.image.layer.v1.tar+zstd".into(),
            annotations: checksum.map(|c| {
                [
                    (
                        "io.github.containers.zstd-chunked.manifest-checksum".to_string(),
                        c.to_string(),
                    ),
                    (
                        "io.github.containers.zstd-chunked.manifest-position".to_string(),
                        "1:2:3:1".to_string(),
                    ),
                ]
                .into()
            }),
        };
        let scope = Scope {
            verity: false,
            source: None,
            tls_verify: None,
            target: None,
            access: None,
            idle: Duration::from_secs(30),
            kept: Arc::default(),
        };
        // (the blob, the index its peer has, the key the peer served it by,
        // and what the probe says)
        let blob_key = blob(None).digest;
        let cases = [
            (blob(None), &right, blob_key.clone(), true, false),
            (blob(None), &wrong, blob_key.clone(), false, false),
            (
                blob(Some(&checksum)),
                &right,
                velarx_types::LayerKey::Toc(checksum.parse().unwrap()).to_string(),
                true,
                true,
            ),
        ];
        for (blob, index, key, carried, lazy) in cases {
            let fake = Arc::new(Fake::default());
            let peer = fake.peer(0, Ok(vec![]));
            fake.indexes.lock().unwrap().insert(peer, index.clone());
            let s = source(&fake, None);
            s.knowledge()
                .served(Some(&key), peer, Duration::from_millis(1));
            let (tx, mut rx) = tokio::sync::mpsc::channel(4);
            s.probe(&scope, vec![blob], false, &Out::new(tx))
                .await
                .unwrap();
            let (reply, fds) = rx.recv().await.unwrap();
            assert_eq!(reply.toc == TocSource::Carried, carried, "{key}");
            assert_eq!(reply.on_demand, carried && lazy);
            assert_eq!(fds.len(), if carried { 2 } else { 0 });
            if carried && !lazy {
                assert_eq!(reply.reason, Some(NotLazy::NoToc));
            }
            if !carried {
                assert_eq!(reply.reason, Some(NotLazy::Unreachable));
            }
        }
    }

    /// The index of a whole layer that did not replay (`again`) is asked of
    /// the other peers, the one that gave it is not asked again in the
    /// scope; another scope (another pull) asks it.
    #[tokio::test]
    async fn a_probe_again_passes_over_the_peer_that_gave_the_index() {
        use velarx_content::fetcher::fetch::{Blob, TocSource};
        use velarx_content::pull::index;
        use velarx_content::serve_fetch::{Out, Scope, StagingFetcher};
        let tarsplit = b"a tar-split".to_vec();
        let toc = format!(
            r#"{{"version":1,"entries":[],"tarSplitDigest":"{}"}}"#,
            digest_of(&tarsplit)
        );
        let toc_z = zstd::encode_all(toc.as_bytes(), 19).unwrap();
        let index = index::encode_compressed(&toc_z, &tarsplit).unwrap();
        let blob = Blob {
            digest: digest_of(b"a layer"),
            size: 1 << 20,
            media_type: "application/vnd.oci.image.layer.v1.tar+gzip".into(),
            annotations: None,
        };
        let fake = Arc::new(Fake::default());
        let (first, second) = (fake.peer(0, Ok(vec![])), fake.peer(0, Ok(vec![])));
        for peer in [first, second] {
            fake.indexes.lock().unwrap().insert(peer, index.clone());
        }
        let s = source(&fake, None);
        for (peer, rtt) in [(first, 1), (second, 2)] {
            s.knowledge()
                .served(Some(&blob.digest), peer, Duration::from_millis(rtt));
        }
        let scope = || Scope {
            verity: false,
            source: None,
            tls_verify: None,
            target: None,
            access: None,
            idle: Duration::from_secs(30),
            kept: Arc::default(),
        };
        async fn carried(s: &PeerSource, scope: &Scope, blob: &Blob, again: bool) -> bool {
            let (tx, mut rx) = tokio::sync::mpsc::channel(4);
            s.probe(scope, vec![blob.clone()], again, &Out::new(tx))
                .await
                .unwrap();
            rx.recv().await.unwrap().0.toc == TocSource::Carried
        }
        let (one, other) = (scope(), scope());
        assert!(carried(&s, &one, &blob, false).await);
        assert!(carried(&s, &one, &blob, true).await);
        assert!(!carried(&s, &one, &blob, true).await, "both were refused");
        assert!(carried(&s, &other, &blob, false).await);
        assert_eq!(*fake.index_asked.lock().unwrap(), [first, second, first]);
    }
}
