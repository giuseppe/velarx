// SPDX-License-Identifier: Apache-2.0
//! The peer-to-peer service (`velarx-p2p`), the only code of velarx that
//! links libp2p and QUIC: nodes find each other and tell which layers they
//! have over libp2p (Kademlia DHT, mDNS, identify, gossip), the control and
//! the discovery; chunks, files, layer indexes, startup profiles and the
//! question whether a peer has a chunk move over QUIC (UDP) and over nothing
//! else ([`quic`]): a peer with no QUIC path is a member and not a data
//! peer.  The engine knows it through
//! `velarx_content::fetcher` only (a source of the pulls, by its socket),
//! and it reads the store through `velarx_core::store_service`.  Its
//! control is [`control`], its settings [`settings`].  The overlay network
//! of the containers is here too: its packets travel between the nodes, and
//! the engine reaches it as a network provider
//! (`velarx_runtime::network::provider`).

pub mod authority;
pub mod bootstrap;
pub mod ca;
pub mod cli;
pub mod control;
pub mod dial_filter;
pub mod directory;
pub mod dns_server;
pub mod dns_sockets;
pub mod entropy;
pub mod explain;
pub mod filter;
pub mod fuzzing;
mod gossip;
pub mod identity;
mod key;
pub mod knowledge;
mod limits;
mod overlay_gossip;
pub mod overlay_helper;
pub mod overlay_router;
pub mod overlay_service;
mod pacer;
pub mod peer_exchange;
pub mod probes;
mod protocol;
pub mod provider;
pub mod quic;
pub mod sandbox;
mod serve;
mod shared;
pub use pacer::PacerState;
pub use serve::{AdmissionState, Serving, ServingState, PROBE_SLOTS};
pub mod service;
pub mod settings;
#[cfg(feature = "sim")]
pub mod sim;
pub mod staged;
pub mod staging;
mod stats;
pub mod store;
pub mod tun_overlay;
pub mod tun_tunnel;

pub use gossip::*;
pub use limits::MAX_REQUEST_DIGESTS;
pub use overlay_gossip::*;
pub use protocol::*;

use futures::StreamExt;
use libp2p::kad::store::RecordStore as _;
use libp2p::{
    connection_limits,
    core::transport::upgrade::Version,
    identify, kad,
    mdns::tokio::Behaviour as Mdns,
    noise, ping, pnet,
    request_response::{self, ProtocolSupport},
    swarm::{
        behaviour::toggle::Toggle, Config as SwarmConfig, ConnectionId, NetworkBehaviour,
        SwarmEvent,
    },
    tcp, yamux, Multiaddr, PeerId, StreamProtocol, Swarm, Transport,
};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tokio::sync::{mpsc, oneshot, watch, RwLock};
use tracing::{debug, info, warn};
use velarx_content::fetcher::fetch::Urgency;
use velarx_storage::ChunkFile;

/// What a node serves its peers with.  A digest the provider does not have
/// is `Ok(None)`; a store that cannot be read is an error, which a peer is
/// told as one (not as a chunk that is not here).
pub trait ChunkProvider: Send + Sync + 'static {
    /// Get chunk data by digest
    fn get_chunk(&self, digest: &str) -> std::io::Result<Option<Vec<u8>>>;
    /// The index of the layer `layer` ([`velarx_content::pull::index`])
    fn get_index(&self, _layer: &str) -> std::io::Result<Option<Vec<u8>>> {
        Ok(None)
    }
    /// The startup profile of the image `image` (`sha256:` and its id)
    /// ([`velarx_content::fetcher::Kind::Profile`])
    fn get_profile(&self, _image: &str) -> std::io::Result<Option<Vec<u8>>> {
        Ok(None)
    }
    /// The records of the signatures of `reference` (a `repository:tag` or a
    /// manifest digest) (`GetSignatures`)
    fn get_signatures(&self, _reference: &str) -> std::io::Result<Option<Vec<u8>>> {
        Ok(None)
    }
    /// The files that hold `digests`, for those it can hand over; empty when
    /// it cannot (the bytes come from `get_chunk` then).  Blocking.
    fn open_chunks(&self, _digests: &[String]) -> std::io::Result<Vec<Option<ChunkFile>>> {
        Ok(Vec::new())
    }
    /// The store has `layers` (or lost them): what the provider kept of
    /// them for the peers, besides the store, is not needed.
    fn release(&self, _layers: &[String]) {}
}

#[derive(Error, Debug)]
pub enum P2PError {
    #[error("transport error: {0}")]
    Transport(String),
    #[error("not connected")]
    NotConnected,
    /// A request over QUIC failed after the connection was made
    #[error("QUIC request to the peer failed: {0}")]
    Quic(String),
    /// No QUIC (UDP) path to the peer: it is a member for discovery, and not
    /// asked for data
    #[error("no QUIC (UDP) path to {peer}: {reason}")]
    NoQuicPath { peer: PeerId, reason: String },
    /// The peer could not read its store: it may have what was asked for
    #[error("the peer could not read its store")]
    StoreFailed,
    #[error("timeout")]
    Timeout,
    /// The peer had no room to answer (it may have what was asked for)
    #[error("the peer has no room to answer")]
    Busy,
    #[error("container {0} is not in the overlay")]
    UnknownContainer(String),
    #[error("invalid private key: {0}")]
    InvalidPrivateKey(String),
    #[error(
        "no swarm key and no certificate authority: the P2P network is private. Generate a \
         key with `velarx-p2p generate-key <path>`, copy it to every node, and set \
         `private_key_path` in the settings of the source in config.toml or \
         VELARX_P2P_SWARM_KEY in the environment; or make an authority (`velarx-p2p ca \
         init`) and set `ca_path` and `certificate_path`"
    )]
    MissingSwarmKey,
}

pub type P2PResult<T> = Result<T, P2PError>;

/// How long a peer has to say whether it has a chunk
const PROBE_TIMEOUT: Duration = Duration::from_secs(3);

/// Providers the DHT named that are dialed for one lookup, at most.
const MAX_DIALED: usize = 3;

/// The most a walk of the DHT is waited for.
pub const LOOKUP_LIMIT: Duration = Duration::from_secs(3);

/// After the first providers of a walk, how long it is waited for more (a
/// record may name a node that left: the others come from later peers),
/// and how many are enough.
const LOOKUP_GATHER: Duration = Duration::from_millis(500);
const LOOKUP_ENOUGH: usize = 8;

/// How long a dial of a provider is waited for at most: the swarm tells when
/// it ended, this is for one that hangs.
const DIAL_LIMIT: Duration = Duration::from_secs(10);

/// What a peer answered to the question whether it has a chunk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Presence {
    /// It has it
    Has,
    /// It does not have it
    Lacks,
    /// It has no room to answer now: nothing is known of the chunk
    Busy,
}

/// How often a connection is pinged, and how long the answer is waited
/// for: two missed answers in a row end the connection (libp2p does not
/// report the first), a peer that went silent goes within about a minute
/// (a timeout, an interval, a timeout).
const PING_INTERVAL: Duration = Duration::from_secs(30);
const PING_TIMEOUT: Duration = Duration::from_secs(10);

/// How long a peer has to take a gossip message
const GOSSIP_TIMEOUT: Duration = Duration::from_secs(10);

/// What a node of a swarm is for.  The overlay network of the containers is
/// a swarm of its own (`velarx-p2p overlay`): its nodes carry the packets of
/// the containers and the gossip of their subnets and names, and nothing of
/// the content (no chunks, no layer filters, no DHT records, no QUIC), so
/// they do not compete.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Role {
    /// The layers and chunks of the store
    #[default]
    Content,
    /// The IP packets of the containers
    Overlay,
}

impl Role {
    /// The name of the Kademlia protocol: the nodes of one role find each
    /// other and not those of the other.
    fn kademlia_protocol(self) -> StreamProtocol {
        StreamProtocol::new(match self {
            Role::Content => "/velarx/kad/1.0.0",
            Role::Overlay => "/velarx/overlay-kad/1.0.0",
        })
    }
}

// The code the derive generates trips unreachable_code, a lint that
// cannot be allowed on the struct, only on the module around it.
mod behaviour {
    #![allow(unreachable_code)]
    use super::*;

    /// Combined network behaviour for Velarx
    #[derive(NetworkBehaviour)]
    pub(crate) struct VelarxBehaviour {
        /// Bounds the connections peers can open
        pub(crate) connection_limits: connection_limits::Behaviour,
        /// Kademlia DHT for content discovery
        pub(crate) kademlia: kad::Behaviour<kad::store::MemoryStore>,
        /// mDNS for local peer discovery
        pub(crate) mdns: Toggle<Mdns>,
        /// Identify protocol for peer identification
        pub(crate) identify: identify::Behaviour,
        /// Liveness: a peer that does not answer a ping loses its connection
        pub(crate) ping: ping::Behaviour,
        /// Request-response for what the peers tell each other
        pub(crate) gossip: request_response::Behaviour<GossipCodec>,
        /// Request-response for TUN tunnel packets (the overlay role)
        pub(crate) tun_tunnel: Toggle<request_response::Behaviour<tun_tunnel::TunPacketCodec>>,
    }
}
use behaviour::*;

#[derive(Debug, Clone)]
pub struct PeerStats {
    pub peer_id: PeerId,
    pub addresses: Vec<Multiaddr>,
}

#[derive(Debug, Clone)]
pub struct P2PStatus {
    pub peer_id: PeerId,
    pub listen_addresses: Vec<Multiaddr>,
    /// The peers with a connection to this node
    pub connected: std::collections::BTreeSet<PeerId>,
    /// The peers whose QUIC endpoint is known (their identify told it)
    pub quic_peers: std::collections::BTreeSet<PeerId>,
    pub provider_records: usize,
}

#[derive(Debug, Clone, Default)]
pub struct P2PStats {
    /// The chunks, indexes and profiles served over QUIC
    pub chunks_sent: u64,
    /// The bytes of the answers served over QUIC
    pub bytes_sent: u64,
}

/// Configuration for P2P node
#[derive(Clone)]
pub struct P2PConfig {
    /// What the node is for
    pub role: Role,
    /// Addresses to listen on
    pub listen_addrs: Vec<String>,
    /// Bootstrap peers to connect to
    pub bootstrap_peers: Vec<String>,
    /// Enable mDNS discovery
    pub enable_mdns: bool,
    /// How long a connection that nothing uses is kept.  A connection is
    /// what makes a peer a member of this node's tables (its layers, its
    /// overlay routes), and is not worth closing while the peer answers
    /// pings: the default is a day.
    pub idle_timeout: Duration,
    /// Maximum incoming connections
    pub max_incoming: u32,
    /// Maximum outgoing connections
    pub max_outgoing: u32,
    /// Where the node may dial beyond the defaults (`dial_filter`)
    pub dial: dial_filter::Rules,
    /// The connections the node keeps up: with fewer the bootstrap peers
    /// are dialed again (0: only at the start)
    pub min_peers: usize,
    /// The time to the first new attempt to reach the bootstrap peers, which
    /// doubles with each attempt up to the second
    pub bootstrap_backoff: (Duration, Duration),
    /// What the node serves to the peers, at most
    pub serving: Serving,
    /// The key pair of the node, so that it is the same peer after a
    /// restart (`identity::load_or_create`); none: a new one for this run
    pub identity: Option<libp2p::identity::Keypair>,
    /// The certificate authority of the swarm: peers are admitted by their
    /// certificates (QUIC handshake, libp2p upgrade) and not by the swarm key
    /// ([`authority`]); the key, if there is one, is only an outer layer of
    /// the TCP transport
    pub authority: Option<Arc<authority::Authority>>,
    /// Path to private network key file (for restricted networks)
    pub private_key_path: Option<PathBuf>,
    /// Private network key content (alternative to private_key_path)
    /// This takes precedence over private_key_path if set
    pub private_key: Option<String>,
    /// The UDP port of the QUIC endpoint, which carries all the data (0: any);
    /// none: the port of the first TCP listen address
    pub quic_port: Option<u16>,
    /// The QUIC streams a request for chunks to one peer is spread over
    pub quic_streams: usize,
    /// Tell the peers the images this node has (they can then list them)
    /// and publish its layers in the DHT; off: the peers can only test a
    /// layer in the filter or ask for one digest at a time
    pub announce_images: bool,
    /// The filter of the layers this node holds, told to the peers
    pub filter: filter::Config,
}

impl Default for P2PConfig {
    fn default() -> Self {
        Self {
            role: Role::default(),
            listen_addrs: vec!["/ip4/0.0.0.0/tcp/0".to_string()],
            bootstrap_peers: Vec::new(),
            enable_mdns: true,
            idle_timeout: Duration::from_secs(24 * 3600),
            max_incoming: 100,
            max_outgoing: 50,
            min_peers: 4,
            bootstrap_backoff: (Duration::from_secs(1), Duration::from_secs(60)),
            serving: Serving::default(),
            identity: None,
            authority: None,
            dial: dial_filter::Rules::default(),
            private_key_path: None,
            private_key: None,
            quic_port: None,
            quic_streams: 4,
            announce_images: false,
            filter: filter::Config::default(),
        }
    }
}

enum P2PCommand {
    /// Announce content availability via DHT
    Announce { key: Vec<u8> },
    /// Stop providing content in the DHT
    Withdraw { key: Vec<u8> },
    /// Find providers for content
    GetProviders {
        key: Vec<u8>,
        tx: mpsc::Sender<P2PResult<Vec<PeerId>>>,
    },
    /// Dial a peer by address
    DialPeer { addr: Multiaddr },
    /// Connect to a peer the DHT named, at the addresses the swarm knows of
    /// it; `done` is told whether it is connected
    DialProvider {
        peer: PeerId,
        done: oneshot::Sender<bool>,
    },
    /// Broadcast a gossip message to all connected peers
    BroadcastGossip { msg: GossipMessage },
    /// Ask every connected peer for its images; `done` is told when each
    /// answered (or its request failed)
    QueryImages { done: oneshot::Sender<()> },
    /// Ask a connected peer which peers it knows, and dial some of them;
    /// told how many were dialed
    AskPeers {
        peer: PeerId,
        done: oneshot::Sender<usize>,
    },
    /// Send a TUN packet to a peer
    SendTunPacket {
        peer: PeerId,
        packet: tun_tunnel::TunPacket,
    },
    /// Set the TUN packet handler callback
    SetTunPacketHandler {
        handler: Arc<dyn Fn(PeerId, tun_tunnel::TunPacket) + Send + Sync>,
    },
    /// Close every connection of these peers (their certificates are no
    /// longer valid)
    Disconnect { peers: Vec<PeerId> },
    /// Shutdown the node
    Shutdown,
}

pub struct P2PNode {
    peer_id: PeerId,
    cmd_tx: mpsc::Sender<P2PCommand>,
    status: watch::Receiver<P2PStatus>,
    peer_stats: Arc<RwLock<HashMap<PeerId, PeerStats>>>,
    config: P2PConfig,
    /// What the peers told: the images and, in its `knowledge`, the filters
    /// of their layers
    gossip: Arc<GossipDiscovery>,
    /// What the peers told of their overlay: the subnets and the names (the
    /// overlay role)
    overlay: Arc<overlay_gossip::OverlayGossip>,
    /// The layers this node holds, and the filter that tells the peers
    advertisement: Arc<filter::Advertisement>,
    /// The answers of the DHT for a while: a pull asks for the
    /// providers of the same layer for each group of its chunks
    providers: shared::ProviderCache,
    /// The QUIC endpoint of the chunks, what it serves, the QUIC addresses
    /// of the peers (they advertise them as listen addresses, identify
    /// tells), and the peers it failed with lately
    quic: Option<Arc<quic::Quic>>,
    chunk_provider: quic::SharedProvider,
    quic_addrs: Arc<std::sync::RwLock<HashMap<PeerId, Vec<std::net::SocketAddr>>>>,
    /// What the probes, the DHT lookups and the dials came to
    counters: Arc<stats::Counters>,
    /// What the node admits to serve
    admission: Arc<serve::Admission>,
    /// The task of the swarm: `shutdown` returns once it ended
    swarm_task: std::sync::Mutex<Option<tokio::task::JoinHandle<()>>>,
}

/// The streams a request for `chunks` chunks is spread over with
/// `quic_streams` (the settings): one a chunk at most, 8 at most.
pub fn lanes_of(chunks: usize, quic_streams: usize) -> usize {
    quic_streams.clamp(1, 8).min(chunks).max(1)
}

/// Where the chunks a peer sends go, each with its digest, as it arrives.
pub type ChunkTx = tokio::sync::mpsc::Sender<(String, Vec<u8>)>;

/// The chunks that can wait for the one that takes them: the peers' answers
/// are not read faster than they are used.
pub const CHUNKS_IN_FLIGHT: usize = 16;

/// What the lanes of a request to `peer` came to (how many chunks each sent
/// on its way), as one answer: what came is kept, the rest is for another
/// peer; with nothing, the failure of QUIC comes first, then the store, then
/// no room.
pub fn lanes_answer(peer: PeerId, answers: Vec<std::io::Result<usize>>) -> P2PResult<()> {
    let (mut found, mut failures) = (0, Vec::new());
    for answer in answers {
        match answer {
            Ok(n) => found += n,
            Err(e) => failures.push(e),
        }
    }
    // (the lanes that failed while another brought chunks)
    for e in failures.iter().filter(|_| found > 0) {
        debug!("P2P: a stream to {peer} failed: {e}");
    }
    if found == 0 {
        let rank =
            |e: &std::io::Error| u8::from(quic::store_failed(e)) + 2 * u8::from(quic::no_room(e));
        if let Some(e) = failures.into_iter().min_by_key(rank) {
            return Err(quic_error(peer, e));
        }
    }
    Ok(())
}

/// `digests` spread over the streams of one request ([`lanes_of`]), each
/// answered at the same time.
pub fn lanes(
    digests: &[(String, Option<u64>)],
    quic_streams: usize,
) -> Vec<Vec<(String, Option<u64>)>> {
    let n = lanes_of(digests.len(), quic_streams);
    (0..n)
        .map(|lane| digests.iter().skip(lane).step_by(n).cloned().collect())
        .collect()
}

impl P2PNode {
    /// The swarm key of the configuration: its content if given, else the
    /// file.  There is no node without one or without an authority: they
    /// keep strangers out of the network.  With an authority the key is
    /// optional and only filters the TCP transport.
    fn swarm_key(config: &P2PConfig) -> P2PResult<(Option<pnet::PreSharedKey>, quic::Auth)> {
        use std::str::FromStr;

        let (content, origin) = match (&config.private_key, &config.private_key_path) {
            (Some(content), _) => (content.clone(), "the environment".to_string()),
            (None, Some(path)) => (
                key::read_key_file(path).map_err(|e| P2PError::InvalidPrivateKey(e.to_string()))?,
                format!("{}", path.display()),
            ),
            (None, None) => {
                return match &config.authority {
                    Some(authority) => Ok((None, quic::Auth::Authority(authority.clone()))),
                    None => Err(P2PError::MissingSwarmKey),
                }
            }
        };
        let key = pnet::PreSharedKey::from_str(&content)
            .map_err(|e| P2PError::InvalidPrivateKey(format!("invalid swarm key: {e}")))?;
        // (the fingerprint would confirm a guess of the key offline)
        debug!("Loaded the swarm key from {origin}");
        let auth = match &config.authority {
            Some(authority) => quic::Auth::Authority(authority.clone()),
            None => quic::Auth::Key(quic::auth_key(&content)),
        };
        Ok((Some(key), auth))
    }

    /// Create a new P2P node with custom configuration
    pub async fn with_config(config: P2PConfig) -> P2PResult<Self> {
        let (psk, quic_auth) = Self::swarm_key(&config)?;
        let authority = config.authority.clone();
        // (the bytes of the bodies read from peers: the gossip and the lists of
        // a handshake)
        let budget = protocol::Budget::new(limits::MAX_LISTS_BYTES);
        // (a node with no authority never takes a list: no message of lists)
        let most = if authority.is_some() {
            limits::MAX_LISTS_BYTES
        } else {
            limits::MAX_GOSSIP_BYTES
        };
        let gossip_budget = budget.clone();
        let listen = multiaddrs("listen address", &config.listen_addrs)?;
        let bootstrap = multiaddrs("bootstrap peer", &config.bootstrap_peers)?;
        let idle_timeout = config.idle_timeout;
        let limits = connection_limits::ConnectionLimits::default()
            // (past max_incoming a few, for a moment: bootstrap::Exchange,
            // which also closes at once a connection it has no place for)
            .with_max_established_incoming(Some(
                config.max_incoming.saturating_add(bootstrap::LENT_PLACES),
            ))
            .with_max_established_outgoing(Some(
                config.max_outgoing.saturating_add(bootstrap::LENT_PLACES),
            ));
        let enable_mdns = config.enable_mdns;
        let role = config.role;
        // What the node dials is decided here, for every source of an address
        let counters: Arc<stats::Counters> = Arc::default();
        let dial = Arc::new(dial_filter::DialFilter::new(
            config.dial.clone(),
            &bootstrap,
            counters.clone(),
        ));

        // The QUIC endpoint of the chunks; its address is told to the peers
        // as a listen address (`/udp/PORT/quic-v1`) with the identify protocol
        let chunk_provider = quic::SharedProvider::default();
        // (what is served is bounded by one admission)
        let admission = Arc::new(serve::Admission::new(&config.serving));
        let quic_at = std::net::SocketAddr::new(quic_bind_ip(&listen), quic_port(&config, &listen));
        let quic = match config.role {
            Role::Content => Some(
                quic::Quic::bind_filtered(
                    quic_at,
                    chunk_provider.clone(),
                    quic_auth,
                    quic::Limits::of(&config.serving),
                    admission.clone(),
                    dial.clone(),
                )
                .map_err(|e| {
                    P2PError::Transport(format!(
                        "no QUIC endpoint for the data at UDP {quic_at}: {e} (the port of the \
                         first TCP listen address unless quic_port names another)"
                    ))
                })?,
            ),
            Role::Overlay => None,
        };

        let identity = config
            .identity
            .clone()
            .unwrap_or_else(libp2p::identity::Keypair::generate_ed25519);
        let dial_for_transport = dial.clone();
        let mut swarm = libp2p::SwarmBuilder::with_existing_identity(identity)
            .with_tokio()
            .with_other_transport(
                move |key| -> Result<_, Box<dyn std::error::Error + Send + Sync>> {
                    let noise_config = authority::Credentialed::new(
                        noise::Config::new(key)?,
                        authority.clone().map(|a| (a, budget)),
                    );
                    let base_transport = dial_filter::Filtered::new(
                        tcp::tokio::Transport::new(tcp::Config::default().nodelay(true)),
                        dial_for_transport,
                    );
                    // Peers that do not know the key never get to the handshake
                    // (with an authority and no key, every peer does, and the
                    // certificate is asked for after Noise)
                    let upgraded = base_transport
                        .and_then(move |socket, _| async move {
                            match psk {
                                Some(psk) => pnet::PnetConfig::new(psk)
                                    .handshake(socket)
                                    .await
                                    .map(futures::future::Either::Left),
                                None => Ok(futures::future::Either::Right(socket)),
                            }
                        })
                        .upgrade(Version::V1Lazy)
                        .authenticate(noise_config)
                        .multiplex(yamux::Config::default());
                    Ok(upgraded)
                },
            )
            .map_err(|e| P2PError::Transport(e.to_string()))?
            .with_behaviour(
                |key| -> Result<_, Box<dyn std::error::Error + Send + Sync>> {
                    let peer_id = key.public().to_peer_id();

                    let store_config = kad::store::MemoryStoreConfig {
                        max_provided_keys: 100_000,
                        ..Default::default()
                    };
                    let store = kad::store::MemoryStore::with_config(peer_id, store_config);

                    let mut kademlia_config = kad::Config::new(role.kademlia_protocol());
                    kademlia_config.set_query_timeout(Duration::from_secs(60));
                    let mut kademlia = kad::Behaviour::with_config(peer_id, store, kademlia_config);
                    kademlia.set_mode(Some(kad::Mode::Server));

                    let mdns = if enable_mdns {
                        Toggle::from(Some(Mdns::new(Default::default(), peer_id)?))
                    } else {
                        Toggle::from(None)
                    };

                    let identify = identify::Behaviour::new(identify::Config::new(
                        "/velarx/1.0.0".to_string(),
                        key.public(),
                    ));
                    let ping = ping::Behaviour::new(
                        ping::Config::new()
                            .with_interval(PING_INTERVAL)
                            .with_timeout(PING_TIMEOUT),
                    );

                    let gossip = request_response::Behaviour::with_codec(
                        GossipCodec::new(gossip_budget, most),
                        [(GOSSIP_PROTOCOL, ProtocolSupport::Full)],
                        request_response::Config::default().with_request_timeout(GOSSIP_TIMEOUT),
                    );

                    let tun_tunnel = (role == Role::Overlay).then(|| {
                        request_response::Behaviour::new(
                            [(tun_tunnel::TUN_PROTOCOL, ProtocolSupport::Full)],
                            request_response::Config::default()
                                .with_request_timeout(Duration::from_secs(5)),
                        )
                    });

                    Ok(VelarxBehaviour {
                        connection_limits: connection_limits::Behaviour::new(limits),
                        kademlia,
                        mdns,
                        identify,
                        ping,
                        gossip,
                        tun_tunnel: tun_tunnel.into(),
                    })
                },
            )
            .map_err(|e| P2PError::Transport(format!("behaviour error: {e}")))?
            .with_swarm_config(|c: SwarmConfig| c.with_idle_connection_timeout(idle_timeout))
            .build();

        let peer_id = *swarm.local_peer_id();

        for addr in &listen {
            swarm.listen_on(addr.clone()).map_err(|e| {
                // (libp2p says nothing of an error of the socket itself:
                // it is the source)
                let mut why = e.to_string();
                let mut source = std::error::Error::source(&e);
                while let Some(s) = source {
                    let text = s.to_string();
                    if !why.ends_with(&text) {
                        if !why.is_empty() {
                            why.push_str(": ");
                        }
                        why.push_str(&text);
                    }
                    source = s.source();
                }
                P2PError::Transport(format!("failed to listen on {addr}: {why}"))
            })?;
        }

        // Connect to the bootstrap peers; the node dials them again while
        // it has too few peers
        dial_all(&mut swarm, &bootstrap);
        let (backoff_min, backoff_max) = config.bootstrap_backoff;
        let bootstrap = bootstrap::Bootstrap::new(
            bootstrap,
            config.min_peers,
            bootstrap::Backoff::new(backoff_min, backoff_max),
            tokio::time::Instant::now(),
        );

        let (status_tx, status) = watch::channel(P2PStatus {
            peer_id,
            listen_addresses: Vec::new(),
            connected: Default::default(),
            quic_peers: Default::default(),
            provider_records: 0,
        });

        let peer_stats: Arc<RwLock<HashMap<PeerId, PeerStats>>> =
            Arc::new(RwLock::new(HashMap::new()));

        let (cmd_tx, cmd_rx) = mpsc::channel(100);

        let peer_stats_clone = peer_stats.clone();

        // Create gossip discovery service, and the filter of the layers the
        // node tells its peers (sent when it changes, by a task of its own)
        let knowledge = Arc::new(knowledge::Knowledge::default());
        let gossip = Arc::new(
            if config.announce_images {
                GossipDiscovery::announcing()
            } else {
                GossipDiscovery::new()
            }
            .with_knowledge(knowledge),
        );
        let advertisement = filter::Advertisement::new(config.filter, entropy::Entropy::system());
        if role == Role::Content {
            let (ad, cmd_tx) = (advertisement.clone(), cmd_tx.clone());
            let closed = cmd_tx.clone();
            tokio::spawn(filter::run(
                ad,
                config.filter.interval,
                async move { closed.closed().await },
                move |msg| {
                    let cmd_tx = cmd_tx.clone();
                    async move {
                        cmd_tx
                            .send(P2PCommand::BroadcastGossip { msg })
                            .await
                            .is_ok()
                    }
                },
            ));
        }

        let gossip_clone = gossip.clone();
        let advertisement_clone = advertisement.clone();
        let quic_addrs: Arc<std::sync::RwLock<HashMap<PeerId, Vec<std::net::SocketAddr>>>> =
            Arc::default();
        let quic_addrs_clone = quic_addrs.clone();
        let quic_clone = quic.clone();
        let overlay = Arc::<overlay_gossip::OverlayGossip>::default();
        let overlay_clone = (role == Role::Overlay).then(|| overlay.clone());
        let counters_clone = counters.clone();
        if let Some(authority) = config.authority.clone() {
            let cmd_tx = cmd_tx.clone();
            tokio::spawn(async move {
                // (the peers that connect later are told in the handshake)
                let mut told = authority.news();
                loop {
                    tokio::select! {
                        _ = tokio::time::sleep(authority.sweep_interval()) => {}
                        _ = cmd_tx.closed() => return,
                    }
                    let a = authority.clone();
                    let Ok(failing) = tokio::task::spawn_blocking(move || a.sweep()).await else {
                        return;
                    };
                    if !failing.is_empty() {
                        let peers = failing.into_iter().map(|(p, _)| p).collect();
                        if cmd_tx.send(P2PCommand::Disconnect { peers }).await.is_err() {
                            return;
                        }
                    }
                    // a newer list, read from the file or from a peer, is
                    // told to the peers connected already (they tell theirs)
                    let news = authority.news();
                    if news != told {
                        told = news;
                        let msg = GossipMessage::Revocations {
                            lists: authority.lists_text(),
                        };
                        if cmd_tx
                            .send(P2PCommand::BroadcastGossip { msg })
                            .await
                            .is_err()
                        {
                            return;
                        }
                    }
                }
            });
        }
        let swarm_authority = config.authority.clone();
        let swarm_task = tokio::spawn(async move {
            run_swarm(SwarmTask {
                swarm,
                cmd_rx,
                status: status_tx,
                peer_stats: peer_stats_clone,
                gossip: gossip_clone,
                advertisement: advertisement_clone,
                quic_addrs: quic_addrs_clone,
                quic: quic_clone,
                overlay: overlay_clone,
                bootstrap,
                exchange: bootstrap::Exchange::new(config.max_incoming as usize),
                walks: bootstrap::Exchange::new(config.max_outgoing as usize),
                counters: counters_clone,
                dial,
                authority: swarm_authority,
            })
            .await;
        });

        Ok(Self {
            peer_id,
            status,
            peer_stats,
            config,
            gossip,
            overlay,
            advertisement,
            providers: shared::ProviderCache::default(),
            quic,
            chunk_provider,
            quic_addrs,
            counters,
            admission,
            swarm_task: std::sync::Mutex::new(Some(swarm_task)),
            cmd_tx,
        })
    }

    pub fn peer_id(&self) -> PeerId {
        self.peer_id
    }

    /// The authority that admits the peers, if the swarm has one.
    pub fn authority(&self) -> Option<&Arc<authority::Authority>> {
        self.config.authority.as_ref()
    }

    /// The layers we hold: the filter that tells the peers is updated (sent
    /// within the interval of `filter.interval`), and when this node
    /// announces (`announce_images`) the DHT gets a provider record of each.
    pub async fn announce_layers(&self, digests: Vec<String>) -> P2PResult<usize> {
        let count = digests.len();
        // (a layer told again is not walked to the DHT again: the records
        // are renewed by the node)
        let new = self.advertisement.add(&digests);
        if !self.gossip.is_announcing() {
            return Ok(count);
        }
        info!("Announcing {} layers to the DHT", new.len());
        for digest in &new {
            let key = digest.as_bytes().to_vec();
            if let Err(e) = self.cmd_tx.send(P2PCommand::Announce { key }).await {
                warn!("Failed to announce layer {}: {}", digest, e);
            }
        }
        Ok(count)
    }

    /// The store service changed what it has of `layers`: the provider need
    /// not keep files of them.
    pub fn release_staged(&self, layers: &[String]) {
        if let Some(provider) = self.chunk_provider.get() {
            provider.release(layers);
        }
    }

    /// Stop telling the peers layers the store does not have any more
    /// (removed images): the filter is made again without them, and the
    /// provider records of the DHT are not renewed.
    pub async fn withdraw_layers(&self, digests: &[String]) {
        for digest in self.advertisement.remove(digests) {
            if !self.gossip.is_announcing() {
                continue;
            }
            let key = digest.as_bytes().to_vec();
            if let Err(e) = self.cmd_tx.send(P2PCommand::Withdraw { key }).await {
                warn!("Failed to withdraw layer {}: {}", digest, e);
            }
        }
    }

    /// Withdraw every layer told that `keep` does not have.
    pub async fn withdraw_layers_not_in(&self, keep: &[String]) {
        let stale = self.advertisement.with(|a| a.not_in(keep));
        self.withdraw_layers(&stale).await;
    }

    /// Whether this node tells its peers the filter of its layers.
    pub fn advertises(&self) -> bool {
        self.config.filter.advertise
    }

    /// The filter this node tells its peers, as it is.
    pub fn advertised(&self) -> filter::Own {
        self.advertisement.with(|a| a.own())
    }

    /// The providers of `digest` the DHT names (what peers announced is
    /// `find_providers_gossip`: a peer's word and the DHT's are two sources).
    /// One walk at a time for a key, whoever asks: the others wait for its
    /// answer, which is kept (a walk cut off at [`LOOKUP_LIMIT`] is kept as an
    /// empty answer).
    pub async fn find_providers(&self, digest: &str) -> Vec<PeerId> {
        self.providers
            .lookup(digest, async {
                let (tx, rx) = mpsc::channel(LOOKUP_ENOUGH);
                let key = digest.as_bytes().to_vec();
                // (a walk that takes longer is not waited for: it is
                // answered empty, and kept so for a moment)
                let found = match self.cmd_tx.send(P2PCommand::GetProviders { key, tx }).await {
                    Ok(()) => gather_providers(rx, LOOKUP_LIMIT, LOOKUP_GATHER).await,
                    Err(_) => Err(P2PError::NotConnected),
                };
                self.counters.lookup(&found);
                debug!(
                    layer = %limits::short(digest),
                    providers = found.as_ref().map_or(0, |p| p.len()),
                    "DHT lookup of the providers of a layer"
                );
                found.unwrap_or_default()
            })
            .await
    }

    /// What the peers told of their overlay (the overlay role)
    pub fn overlay(&self) -> &Arc<overlay_gossip::OverlayGossip> {
        &self.overlay
    }

    /// Get access to the gossip discovery service
    pub fn gossip(&self) -> &Arc<GossipDiscovery> {
        &self.gossip
    }

    /// What the peers told of their layers (and what this node learnt of
    /// them): shared with the source of the pulls.
    pub fn knowledge(&self) -> &Arc<knowledge::Knowledge> {
        self.gossip.knowledge()
    }

    /// Send `msg` to all the connected peers.
    async fn tell(&self, msg: GossipMessage) {
        let _ = self.cmd_tx.send(P2PCommand::BroadcastGossip { msg }).await;
    }

    /// Tell the peers the images we have, when this node announces.
    pub async fn announce_images(&self, images: Vec<ImageInfo>) {
        self.gossip.set_images(images).await;
        if let Some(msg) = self.gossip.get_image_announce_message().await {
            self.tell(msg).await;
        }
    }

    /// Get only remote images from peers
    pub async fn get_remote_images(&self) -> Vec<(PeerId, ImageInfo)> {
        self.gossip.get_remote_images().await
    }

    /// Query connected peers for their images
    pub async fn query_peer_images(&self) -> P2PResult<()> {
        let (done, answered) = oneshot::channel();
        self.cmd_tx
            .send(P2PCommand::QueryImages { done })
            .await
            .map_err(|_| P2PError::NotConnected)?;
        // Every peer answers or its request fails: that is the end of the
        // wait.  The limit is for a peer that hangs, not the normal case.
        let _ = tokio::time::timeout(IMAGE_QUERY_LIMIT, answered).await;
        Ok(())
    }

    /// Connect to `peer`, a provider the DHT named (its addresses are the
    /// ones the swarm learned with the answer), unless it is connected
    /// already; the connection limits of the node apply.  Whether it is
    /// connected when the dial ended.  Many callers for one peer share one
    /// dial.
    pub async fn connect_provider(&self, peer: PeerId) -> bool {
        let (done, ended) = oneshot::channel();
        if self
            .cmd_tx
            .send(P2PCommand::DialProvider { peer, done })
            .await
            .is_err()
        {
            return false;
        }
        // (the swarm tells when the dial ended: the limit is for a dial
        // that hangs)
        let connected = matches!(tokio::time::timeout(DIAL_LIMIT, ended).await, Ok(Ok(true)));
        debug!(%peer, connected, "dial of a provider the DHT named");
        connected
    }

    /// Dial a peer by address
    pub async fn dial(&self, addr: Multiaddr) -> P2PResult<()> {
        self.cmd_tx
            .send(P2PCommand::DialPeer { addr })
            .await
            .map_err(|_| P2PError::NotConnected)?;
        Ok(())
    }

    /// Ask the connected peer `peer` which peers it knows now (the node does
    /// it by itself when it has few peers, at most once in a while for each
    /// peer) and dial those the filter allows, at most
    /// [`peer_exchange::MAX_DIALS`].  How many were dialed.
    pub async fn ask_for_peers(&self, peer: PeerId) -> P2PResult<usize> {
        let (done, told) = oneshot::channel();
        self.cmd_tx
            .send(P2PCommand::AskPeers { peer, done })
            .await
            .map_err(|_| P2PError::NotConnected)?;
        told.await.map_err(|_| P2PError::NotConnected)
    }

    /// Whether `peer` has the chunk `digest` (it would serve it), asked over
    /// QUIC in one short stream: the question the pulls ask the peers when
    /// none told what it has.  The answer is a hint, and not a proof: the
    /// chunk is checked when it is fetched.  A peer with no room to answer is
    /// [`Presence::Busy`]: it was not asked in vain, and it did not say it
    /// lacks the chunk.
    pub async fn probe(&self, peer: PeerId, digest: &str) -> P2PResult<Presence> {
        let answer = async {
            let (quic, addr) = self.quic_path(peer).await?;
            match tokio::time::timeout(PROBE_TIMEOUT, quic.has(addr, digest)).await {
                Ok(answer) => answer.map_err(|e| quic_error(peer, e)),
                Err(_) => Err(P2PError::Timeout),
            }
        }
        .await;
        self.counters.probe(&answer);
        debug!(
            %peer,
            chunk = %limits::short(digest),
            outcome = match &answer {
                Ok(Presence::Has) => "has",
                Ok(Presence::Lacks) => "lacks",
                Ok(Presence::Busy) => "busy",
                Err(_) => "error",
            },
            "probe"
        );
        answer
    }

    /// The index of the layer `layer` from `peer` over QUIC, if it has one
    /// of at most `max` bytes.  Not checked but for its transfer: it is not
    /// named by its digest, the puller proves it.
    pub async fn request_index(
        &self,
        peer: PeerId,
        layer: &str,
        max: u64,
    ) -> P2PResult<Option<Vec<u8>>> {
        let (quic, addr) = self.quic_path(peer).await?;
        quic.index(addr, layer, max)
            .await
            .map_err(|e| quic_error(peer, e))
    }

    /// The startup profile of the image `image` (its id with the algorithm of
    /// its manifest digest, `sha256:` or `sha512:`) from `peer` over QUIC, if
    /// it has one of at most `max` bytes.  Not checked but for its size: the
    /// asker uses it only as an order of files it fetches and checks.
    pub async fn request_profile(
        &self,
        peer: PeerId,
        image: &str,
        max: u64,
    ) -> P2PResult<Option<Vec<u8>>> {
        let (quic, addr) = self.quic_path(peer).await?;
        quic.profile(addr, image, max)
            .await
            .map_err(|e| quic_error(peer, e))
    }

    /// The records of the signatures of `reference` (a `repository:tag` or a
    /// manifest digest) from `peer` over QUIC, if it has any, in at most
    /// `max` bytes.  Not checked: the asker judges the signatures.
    pub async fn request_signatures(
        &self,
        peer: PeerId,
        reference: &str,
        max: u64,
    ) -> P2PResult<Option<Vec<u8>>> {
        let (quic, addr) = self.quic_path(peer).await?;
        quic.signatures(addr, reference, max)
            .await
            .map_err(|e| quic_error(peer, e))
    }

    /// Check if connected to a specific peer
    pub async fn is_connected_to(&self, peer_id: &PeerId) -> bool {
        self.status.borrow().connected.contains(peer_id)
    }

    /// What the probes, the DHT lookups and the dials of this node came to.
    pub async fn lookups(&self) -> control::Lookups {
        let filters = self.gossip.knowledge().filter_totals();
        control::Lookups {
            filter_peers: filters.peers,
            filter_hits: filters.hits,
            filter_false_positives: filters.false_positives,
            filter_refused: filters.refused,
            ..self.counters.snapshot()
        }
    }

    pub fn status(&self) -> P2PStatus {
        self.status.borrow().clone()
    }

    /// The status as it changes: a node tells when it listens, when a
    /// peer connects, when the QUIC endpoint of a peer is known and when a
    /// peer is gone, so that nobody has to ask again (`wait_for` of the
    /// receiver returns when a condition holds).  What the peers told is in
    /// [`GossipDiscovery::changes`].
    pub fn status_updates(&self) -> watch::Receiver<P2PStatus> {
        self.status.clone()
    }

    pub async fn peers(&self) -> Vec<PeerStats> {
        self.peer_stats.read().await.values().cloned().collect()
    }

    /// Get aggregate P2P network statistics
    pub async fn get_stats(&self) -> P2PStats {
        P2PStats {
            chunks_sent: self.quic().served(),
            bytes_sent: self.quic().served_bytes(),
        }
    }

    /// Stop the node and return once its swarm task ended.
    pub async fn shutdown(&self) -> P2PResult<()> {
        if let Some(quic) = &self.quic {
            quic.close();
        }
        self.cmd_tx
            .send(P2PCommand::Shutdown)
            .await
            .map_err(|_| P2PError::NotConnected)?;
        // (the swarm and what it owns are gone when this returns)
        let task = self
            .swarm_task
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take();
        if let Some(task) = task {
            let _ = task.await;
        }
        Ok(())
    }

    /// Set the chunk provider for serving chunks to peers
    pub fn set_chunk_provider(&self, provider: Arc<dyn ChunkProvider>) -> P2PResult<()> {
        self.chunk_provider
            .set(provider)
            .map_err(|_| P2PError::Transport("the chunk provider is set already".into()))?;
        info!("Chunk provider set for P2P node");
        Ok(())
    }

    /// The connected peers whose certificate names a zone other than the one
    /// of this node's certificate (none when this node names none).
    pub async fn far(&self) -> std::collections::HashSet<PeerId> {
        let Some(authority) = self.authority() else {
            return std::collections::HashSet::new();
        };
        let Some(own) = authority.this_node().zone else {
            return std::collections::HashSet::new();
        };
        self.peers()
            .await
            .into_iter()
            .map(|p| p.peer_id)
            .filter(|p| {
                authority
                    .who(p)
                    .is_none_or(|w| w.zone.as_ref() != Some(&own))
            })
            .collect()
    }

    /// The QUIC endpoint of the chunks: a node of the content role has one.
    fn quic(&self) -> &Arc<quic::Quic> {
        self.quic
            .as_ref()
            .expect("a content node has a QUIC endpoint")
    }

    /// The QUIC endpoint to ask `peer` at, or why there is no path to it:
    /// it advertised no QUIC endpoint (yet), the endpoint is not at an
    /// address it is connected from or to ([`quic_target`]), or no connection
    /// to it could be made lately (UDP blocked).  A peer without a path is
    /// still a member, for discovery; it is not asked for data.
    async fn quic_path(&self, peer: PeerId) -> P2PResult<(&Arc<quic::Quic>, std::net::SocketAddr)> {
        let no_path = |reason: &str| P2PError::NoQuicPath {
            peer,
            reason: reason.to_string(),
        };
        let quic = self
            .quic
            .as_ref()
            .ok_or_else(|| no_path("this node has no QUIC endpoint"))?;
        let advertised = self
            .quic_addrs
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(&peer)
            .cloned()
            .ok_or_else(|| no_path("it advertises no QUIC (UDP) endpoint"))?;
        let connected = self
            .peer_stats
            .read()
            .await
            .get(&peer)
            .map(peer_ips)
            .unwrap_or_default();
        let addr = quic_target(&advertised, &connected).ok_or_else(|| {
            no_path("its QUIC endpoint is not at an address it is connected from")
        })?;
        match quic.avoided(addr) {
            Some(why) => Err(no_path(&why)),
            None => {
                // (the one this address is certified as, whatever the
                // connections of the peer were when it was identified)
                quic.expect(addr, peer);
                Ok((quic, addr))
            }
        }
    }

    /// Why `peer` is not asked for data, when it is not: there is no QUIC
    /// path to it ([`P2PNode::quic_path`]).
    pub async fn no_quic_path(&self, peer: PeerId) -> Option<String> {
        match self.quic_path(peer).await {
            Err(P2PError::NoQuicPath { reason, .. }) => Some(reason),
            _ => None,
        }
    }

    /// How many of the connected peers have no QUIC path.
    pub async fn without_quic(&self) -> usize {
        let connected: Vec<PeerId> = self.status.borrow().connected.iter().copied().collect();
        let mut without = 0;
        for peer in connected {
            without += usize::from(self.no_quic_path(peer).await.is_some());
        }
        without
    }

    /// The streams a request for `chunks` chunks is spread over.
    pub fn streams_of(&self, chunks: usize) -> usize {
        lanes_of(chunks, self.config.quic_streams)
    }

    /// What the node is serving now: the slots and who waits for the upload
    /// credit.
    pub fn serving_state(&self) -> serve::ServingState {
        serve::ServingState {
            quic_slots: self.quic().slots(),
            admission: self.admission.state(),
        }
    }

    /// The chunks `digests` from `peer` over QUIC, unchecked, as they come
    /// into `out`, asked as `urgency` says.  The digests are spread over
    /// [`P2PConfig::quic_streams`] streams, answered at the same time, and
    /// those of a big request over extra connections too
    /// ([`quic::Quic::vias`]).  A
    /// peer that could not read its store for any of them is an error
    /// ([`P2PError::StoreFailed`]), a peer with no room for any is
    /// [`P2PError::Busy`]; with no QUIC path to it the error says so
    /// ([`P2PError::NoQuicPath`]), and the pull asks another peer.
    pub async fn fetch_into(
        &self,
        peer: PeerId,
        digests: &[(String, Option<u64>)],
        urgency: Urgency,
        out: ChunkTx,
    ) -> P2PResult<()> {
        let (quic, addr) = self.quic_path(peer).await?;
        if digests.is_empty() {
            return Ok(());
        }
        let parts = lanes(digests, self.config.quic_streams);
        let bytes = digests.iter().filter_map(|(_, size)| *size).sum();
        let vias = quic.vias(addr, bytes, urgency, parts.len());
        // (a task each: the lanes are read on as many threads; they end
        // with this call)
        let mut running = tokio::task::JoinSet::new();
        for (part, via) in parts.into_iter().zip(vias) {
            let (quic, out) = (quic.clone(), out.clone());
            running.spawn(tracing::Instrument::in_current_span(async move {
                quic.fetch_into(addr, &part, urgency, out, via).await
            }));
        }
        let answers = running.join_all().await;
        lanes_answer(peer, answers)
    }

    /// Send a TUN packet to a specific peer (fire-and-forget)
    pub async fn send_tun_packet(
        &self,
        peer: PeerId,
        packet: tun_tunnel::TunPacket,
    ) -> P2PResult<()> {
        self.cmd_tx
            .send(P2PCommand::SendTunPacket { peer, packet })
            .await
            .map_err(|_| P2PError::NotConnected)?;
        Ok(())
    }

    /// Set the handler for incoming TUN packets
    pub async fn set_tun_packet_handler<F>(&self, handler: F) -> P2PResult<()>
    where
        F: Fn(PeerId, tun_tunnel::TunPacket) + Send + Sync + 'static,
    {
        self.cmd_tx
            .send(P2PCommand::SetTunPacketHandler {
                handler: Arc::new(handler),
            })
            .await
            .map_err(|_| P2PError::NotConnected)?;
        Ok(())
    }

    /// Broadcast our TUN overlay network presence to all connected peers
    /// This is used for the TUN-based overlay that tunnels IP packets over libp2p streams
    pub async fn announce_tun_overlay(&self, node_subnet: ipnet::Ipv4Net) -> P2PResult<()> {
        let msg = self.overlay.set_subnet(node_subnet);
        self.tell(msg).await;
        info!("Announced TUN overlay: subnet={}", node_subnet);
        Ok(())
    }

    /// Add a DNS record for a container and announce it to peers
    pub async fn add_dns_record(&self, record: DnsRecord) -> P2PResult<()> {
        self.overlay.add_dns_record(record).await;

        // Broadcast DNS records to all connected peers
        let msg = self.overlay.get_dns_announce_message().await;
        self.tell(msg).await;

        Ok(())
    }

    /// Remove a DNS record by container ID
    pub async fn remove_dns_record_by_container_id(&self, container_id: &str) -> P2PResult<()> {
        self.overlay
            .remove_dns_record_by_container_id(container_id)
            .await;

        // Broadcast updated DNS records to all connected peers
        let msg = self.overlay.get_dns_announce_message().await;
        self.tell(msg).await;

        Ok(())
    }
}

/// `texts` as multiaddresses: one that is none is an error, not an address
/// the node does without.
fn multiaddrs(what: &str, texts: &[String]) -> P2PResult<Vec<Multiaddr>> {
    texts
        .iter()
        .map(|t| {
            t.parse::<Multiaddr>()
                .map_err(|e| P2PError::Transport(format!("the {what} `{t}`: {e}")))
        })
        .collect()
}

/// The address the QUIC endpoint binds: the host of `listen_addrs`, so that a
/// node told to listen on one address (the loopback, one LAN address) opens
/// nothing on the other interfaces; all interfaces when one of them is the
/// unspecified address, or none names a host: `::` (IPv6 and IPv4, as a
/// socket of Linux is by default) when `::` is listed, else `0.0.0.0`.  The
/// endpoint is one socket: with several hosts it binds the first one, and
/// the peers that reach the node by another address have no QUIC path to it
/// (the node is then no data peer for them).
fn quic_bind_ip(listen_addrs: &[Multiaddr]) -> std::net::IpAddr {
    let any = std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED);
    let (mut first, mut unspecified) = (None, None);
    for ip in listen_addrs.iter().filter_map(ip_of) {
        if ip.is_unspecified() {
            // (`::` takes both families, `0.0.0.0` only IPv4)
            if unspecified.is_none_or(|u: std::net::IpAddr| u.is_ipv4()) {
                unspecified = Some(ip);
            }
        } else {
            first.get_or_insert(ip);
        }
    }
    unspecified.or(first).unwrap_or(any)
}

/// The UDP port of the QUIC endpoint: the one configured, else the port of the
/// first TCP listen address (so that one number is opened for both).
fn quic_port(config: &P2PConfig, listen: &[Multiaddr]) -> u16 {
    config.quic_port.unwrap_or_else(|| {
        listen
            .iter()
            .flat_map(|a| a.iter())
            .find_map(|p| match p {
                libp2p::multiaddr::Protocol::Tcp(port) => Some(port),
                _ => None,
            })
            .unwrap_or(0)
    })
}

/// Where the QUIC endpoint of a peer is reached: the address it advertises
/// for an IP address it is connected from or to, else that IP address with
/// the port it advertises (behind a NAT the peer does not know the address
/// it is seen at).  Never an address only the peer names: what it
/// advertises cannot make this node send to a third host.  An IPv6
/// link-local address is not one: a multiaddress has no interface for it.
fn quic_target(
    advertised: &[std::net::SocketAddr],
    connected: &[std::net::IpAddr],
) -> Option<std::net::SocketAddr> {
    let usable = |ip: &std::net::IpAddr| match ip {
        std::net::IpAddr::V4(ip) => {
            !ip.is_unspecified() && !ip.is_broadcast() && !ip.is_multicast()
        }
        std::net::IpAddr::V6(ip) => {
            !ip.is_unspecified() && !ip.is_multicast() && !ip.is_unicast_link_local()
        }
    };
    let connected: Vec<std::net::IpAddr> = connected.iter().copied().filter(usable).collect();
    if let Some(same) = advertised.iter().find(|a| connected.contains(&a.ip())) {
        return Some(*same);
    }
    connected.iter().find_map(|ip| {
        advertised
            .iter()
            .find(|a| a.is_ipv4() == ip.is_ipv4())
            .map(|a| std::net::SocketAddr::new(*ip, a.port()))
    })
}

/// The QUIC addresses of a peer [`quic_target`] may have chosen through
/// `gone`, the IP address of a connection that closed, when no connection
/// of the peer is from or to it any more (`connected`): that address with
/// each port the peer advertises.  A connection to one is not kept: it
/// would hold a place at the peer, kept alive, for a peer this node is no
/// longer connected to that way.
fn quic_targets_gone(
    advertised: &[std::net::SocketAddr],
    gone: Option<std::net::IpAddr>,
    connected: &[std::net::IpAddr],
) -> Vec<std::net::SocketAddr> {
    let Some(ip) = gone.filter(|ip| !connected.contains(ip)) else {
        return Vec::new();
    };
    let mut ports: Vec<u16> = advertised
        .iter()
        .filter(|a| a.is_ipv4() == ip.is_ipv4())
        .map(|a| a.port())
        .collect();
    ports.sort_unstable();
    ports.dedup();
    ports
        .into_iter()
        .map(|port| std::net::SocketAddr::new(ip, port))
        .collect()
}

/// What a failed request to `peer` over QUIC says: no path to it, its store
/// failed, it had no room, or the request failed.
pub(crate) fn quic_error(peer: PeerId, e: std::io::Error) -> P2PError {
    if let Some(reason) = quic::no_path(&e) {
        P2PError::NoQuicPath {
            peer,
            reason: reason.to_string(),
        }
    } else if quic::store_failed(&e) {
        P2PError::StoreFailed
    } else if quic::no_room(&e) {
        P2PError::Busy
    } else {
        P2PError::Quic(e.to_string())
    }
}

fn peer_ips(stats: &PeerStats) -> Vec<std::net::IpAddr> {
    stats.addresses.iter().filter_map(ip_of).collect()
}

/// The IP address of a multiaddress.
fn ip_of(addr: &Multiaddr) -> Option<std::net::IpAddr> {
    addr.iter().find_map(|p| match p {
        libp2p::multiaddr::Protocol::Ip4(ip) => Some(std::net::IpAddr::V4(ip)),
        libp2p::multiaddr::Protocol::Ip6(ip) => Some(std::net::IpAddr::V6(ip)),
        _ => None,
    })
}

/// Whether a connection failed where a peer with another swarm key ends: in
/// the negotiation of the secure channel (its bytes are not those of this
/// swarm's private network) or in its handshake.  A hint: the error is
/// looked for by type in the chain of its causes.
fn on_key(error: &(dyn std::error::Error + 'static)) -> bool {
    let mut next = Some(error);
    while let Some(e) = next {
        if e.is::<pnet::PnetError>()
            || e.is::<noise::Error>()
            || e.is::<libp2p::core::upgrade::NegotiationError>()
        {
            return true;
        }
        if let Some(inner) = e
            .downcast_ref::<std::io::Error>()
            .and_then(std::io::Error::get_ref)
        {
            if on_key(inner) {
                return true;
            }
        }
        next = e.source();
    }
    false
}

fn transport_on_key(error: &libp2p::core::transport::TransportError<std::io::Error>) -> bool {
    match error {
        libp2p::core::transport::TransportError::Other(e) => on_key(e),
        libp2p::core::transport::TransportError::MultiaddrNotSupported(_) => false,
    }
}

fn dial_failed_on_key(error: &libp2p::swarm::DialError) -> bool {
    match error {
        libp2p::swarm::DialError::Transport(all) => all.iter().any(|(_, e)| transport_on_key(e)),
        _ => false,
    }
}

fn listen_failed_on_key(error: &libp2p::swarm::ListenError) -> bool {
    match error {
        libp2p::swarm::ListenError::Transport(e) => transport_on_key(e),
        _ => false,
    }
}

fn key_hint(on_key: bool) -> &'static str {
    if on_key {
        " (possible swarm key mismatch)"
    } else {
        ""
    }
}

/// How the QUIC endpoint of a node is advertised: a listen address
/// `/ip/ADDRESS/udp/PORT/quic-v1`, for each address the node listens on
/// that the endpoint can be reached at.
fn quic_advertised(bound: std::net::SocketAddr, listen: &Multiaddr) -> Option<Multiaddr> {
    use libp2p::multiaddr::Protocol;
    let ip = ip_of(listen)?;
    // (`::` is reached over IPv4 too)
    let reachable = if bound.ip().is_unspecified() {
        bound.is_ipv6() || ip.is_ipv4()
    } else {
        bound.ip() == ip
    };
    reachable.then(|| {
        Multiaddr::from(ip)
            .with(Protocol::Udp(bound.port()))
            .with(Protocol::QuicV1)
    })
}

/// The QUIC endpoints a peer advertises :
/// the addresses of the form `/ip/ADDRESS/udp/PORT/quic-v1`.
fn quic_addresses(listen: &[Multiaddr]) -> Vec<std::net::SocketAddr> {
    use libp2p::multiaddr::Protocol;
    listen
        .iter()
        .filter_map(|a| {
            let mut parts = a.iter();
            let ip = match parts.next()? {
                Protocol::Ip4(ip) => std::net::IpAddr::V4(ip),
                Protocol::Ip6(ip) => std::net::IpAddr::V6(ip),
                _ => return None,
            };
            match (parts.next(), parts.next(), parts.next()) {
                (Some(Protocol::Udp(port)), Some(Protocol::QuicV1), None) if port != 0 => {
                    Some(std::net::SocketAddr::new(ip, port))
                }
                _ => None,
            }
        })
        .collect()
}

/// Whether libp2p of this node can dial the address (a TCP one): the QUIC
/// endpoint is not a libp2p transport.
fn dialable(addr: &Multiaddr) -> bool {
    !addr
        .iter()
        .any(|p| matches!(p, libp2p::multiaddr::Protocol::QuicV1))
}

/// An answer of `chunks` chunks and `bytes` bytes was sent to `peer`: counted
/// for a peer that is connected.  A peer that disconnected while its answer
/// was read is not made a peer again by it (it would be listed, and read as
/// connected, until the node ended).
/// The questions for the providers of a digest that wait for the DHT.
type PendingProviders<Q = kad::QueryId> = HashMap<Q, mpsc::Sender<P2PResult<Vec<PeerId>>>>;

/// The walk of the DHT for the question `id` reported `found`: each batch
/// of providers goes to who asked (the walk reports every peer that
/// answered, the ones that know no provider too, and goes on), and its end
/// (an empty batch) or its failure forgets the question.  True when the
/// asker left: the walk is to be stopped.
fn answer_providers<Q: std::hash::Hash + Eq>(
    pending: &mut PendingProviders<Q>,
    id: Q,
    found: kad::GetProvidersResult,
) -> bool {
    let (answer, last) = match found {
        Ok(kad::GetProvidersOk::FoundProviders { providers, .. }) if providers.is_empty() => {
            return false
        }
        Ok(kad::GetProvidersOk::FoundProviders { providers, .. }) => {
            (Ok(providers.into_iter().collect()), false)
        }
        Ok(kad::GetProvidersOk::FinishedWithNoAdditionalRecord { .. }) => (Ok(Vec::new()), true),
        Err(kad::GetProvidersError::Timeout { .. }) => (Err(P2PError::Timeout), true),
    };
    let Some(tx) = pending.get(&id) else {
        return false;
    };
    // (an asker that is full is reading: the batch is dropped)
    let gone = matches!(
        tx.try_send(answer),
        Err(mpsc::error::TrySendError::Closed(_))
    );
    if last || gone {
        pending.remove(&id);
    }
    gone && !last
}

/// The providers the batches of a walk name: the first ones are waited for
/// up to `limit`, more for `gather` after them, until the walk ends or
/// [`LOOKUP_ENOUGH`] are known.  The receiver is dropped at the end, which
/// stops the walk.
async fn gather_providers(
    mut rx: mpsc::Receiver<P2PResult<Vec<PeerId>>>,
    limit: Duration,
    gather: Duration,
) -> P2PResult<Vec<PeerId>> {
    let mut until = tokio::time::Instant::now() + limit;
    let mut found: Vec<PeerId> = Vec::new();
    loop {
        let batch = match tokio::time::timeout_at(until, rx.recv()).await {
            Ok(Some(Ok(batch))) if !batch.is_empty() => batch,
            Ok(Some(Ok(_))) => return Ok(found),
            Ok(Some(Err(e))) if found.is_empty() => return Err(e),
            Ok(None) | Err(_) if found.is_empty() => return Err(P2PError::NotConnected),
            _ => return Ok(found),
        };
        if found.is_empty() {
            until = until.min(tokio::time::Instant::now() + gather);
        }
        for peer in batch {
            if !found.contains(&peer) {
                found.push(peer);
            }
        }
        if found.len() >= LOOKUP_ENOUGH {
            return Ok(found);
        }
    }
}

/// Connect to `peer`, a provider the DHT named, unless it is connected or
/// being dialed (the dials of one peer are one, whoever made it: the walks
/// of the DHT dial the peers they ask too); `done` is told when it is
/// known whether it connected.  The limits of the swarm apply.
fn dial_provider(
    swarm: &mut Swarm<VelarxBehaviour>,
    dialing: &mut HashMap<PeerId, Vec<oneshot::Sender<bool>>>,
    counters: &stats::Counters,
    peer: PeerId,
    done: Option<oneshot::Sender<bool>>,
) {
    if swarm.is_connected(&peer) {
        if let Some(done) = done {
            let _ = done.send(true);
        }
        return;
    }
    if let Some(waiting) = dialing.get_mut(&peer) {
        waiting.extend(done);
        return;
    }
    let opts = libp2p::swarm::dial_opts::DialOpts::peer_id(peer)
        .condition(libp2p::swarm::dial_opts::PeerCondition::DisconnectedAndNotDialing)
        .build();
    match swarm.dial(opts) {
        // (a dial of the peer that another part of the swarm made, the
        // DHT's walk for one, is waited for the same)
        Ok(()) | Err(libp2p::swarm::DialError::DialPeerConditionFalse(_)) => {
            counters.dial_started();
            dialing.insert(peer, done.into_iter().collect());
        }
        Err(e) => {
            debug!("Cannot dial the provider {}: {}", peer, e);
            counters.dial_started();
            counters.dial_failed();
            if let Some(done) = done {
                let _ = done.send(false);
            }
        }
    }
}

/// What the task of the swarm runs on.
struct SwarmTask {
    swarm: Swarm<VelarxBehaviour>,
    cmd_rx: mpsc::Receiver<P2PCommand>,
    status: watch::Sender<P2PStatus>,
    peer_stats: Arc<RwLock<HashMap<PeerId, PeerStats>>>,
    gossip: Arc<GossipDiscovery>,
    /// The filter of our layers, told to each peer that connects
    advertisement: Arc<filter::Advertisement>,
    quic_addrs: Arc<std::sync::RwLock<HashMap<PeerId, Vec<std::net::SocketAddr>>>>,
    /// The QUIC endpoint of the chunks (the content role)
    quic: Option<Arc<quic::Quic>>,
    /// Where the peers' overlay announcements go (the overlay role)
    overlay: Option<Arc<overlay_gossip::OverlayGossip>>,
    /// Dials the bootstrap peers again when there are too few peers
    bootstrap: bootstrap::Bootstrap,
    /// The connections taken past `max_incoming`, for a moment
    exchange: bootstrap::Exchange<ConnectionId>,
    /// The same for the connections the node makes past `max_outgoing`
    walks: bootstrap::Exchange<ConnectionId>,
    /// The dials of the providers are counted where they are decided
    counters: Arc<stats::Counters>,
    /// Where the node may dial, for the peers it learns of
    dial: Arc<dial_filter::DialFilter>,
    /// What admits the peers, if the swarm has an authority
    authority: Option<Arc<authority::Authority>>,
}

/// What the node knows of its peers to tell others, and when it asked and
/// answered each (`peer_exchange`).
#[derive(Default)]
struct Exchanging {
    directory: peer_exchange::Directory,
    pacing: peer_exchange::Pacing,
    /// The questions in flight: whom, and who waits for the number dialed
    asked: HashMap<request_response::OutboundRequestId, (PeerId, Option<oneshot::Sender<usize>>)>,
    /// The peers learnt of an answer that are being dialed: a node with few
    /// peers counts them as peers it will have, so that it does not ask every
    /// peer it identifies meanwhile and dial eight for each (filling its
    /// outgoing connections, and leaving no room to dial what the DHT names)
    dialing: std::collections::HashSet<PeerId>,
}

impl Exchanging {
    /// Whether a node with `connected` peers asks for others: with few, and
    /// counting those it is dialing for an answer.
    fn wants_peers(&self, bootstrap: &bootstrap::Bootstrap, connected: usize) -> bool {
        bootstrap.wants_peers(connected + self.dialing.len())
    }
}

/// Ask `peer` which peers it knows, if it was not asked lately (`force`: in
/// any case, for the caller that asked the node to) and tell `done` how
/// many were dialed when it answers.
fn ask_peers(
    swarm: &mut Swarm<VelarxBehaviour>,
    exchanging: &mut Exchanging,
    peer: PeerId,
    done: Option<oneshot::Sender<usize>>,
    force: bool,
) {
    let now = tokio::time::Instant::now();
    if (!force && !exchanging.pacing.may_ask(peer, now)) || !swarm.is_connected(&peer) {
        if let Some(done) = done {
            let _ = done.send(0);
        }
        return;
    }
    let id = swarm
        .behaviour_mut()
        .gossip
        .send_request(&peer, GossipMessage::PeerQuery);
    exchanging.asked.insert(id, (peer, done));
}

/// Dial the peers an answer named that the node is not connected to (noted
/// in `dialing` until the dial ends).
fn dial_learned(
    swarm: &mut Swarm<VelarxBehaviour>,
    counters: &stats::Counters,
    dial: &dial_filter::DialFilter,
    answer: &[peer_exchange::PeerAddress],
    want: usize,
    dialing: &mut std::collections::HashSet<PeerId>,
) -> usize {
    let me = *swarm.local_peer_id();
    let learned = peer_exchange::accepted(answer, &me, dial, |p| swarm.is_connected(p), want);
    let mut dialed = 0;
    for (peer, addresses) in learned {
        let opts = libp2p::swarm::dial_opts::DialOpts::peer_id(peer)
            .addresses(addresses)
            .condition(libp2p::swarm::dial_opts::PeerCondition::DisconnectedAndNotDialing)
            .build();
        if swarm.dial(opts).is_ok() {
            counters.exchange_dialed();
            dialing.insert(peer);
            dialed += 1;
        }
    }
    dialed
}

/// Dial the bootstrap peers `addresses`.
fn dial_all(swarm: &mut Swarm<VelarxBehaviour>, addresses: &[Multiaddr]) {
    for addr in addresses {
        if let Err(e) = swarm.dial(addr.clone()) {
            warn!("Failed to dial bootstrap peer {}: {}", addr, e);
        }
    }
}

async fn run_swarm(task: SwarmTask) {
    let SwarmTask {
        mut swarm,
        mut cmd_rx,
        status,
        peer_stats,
        gossip,
        advertisement,
        quic_addrs,
        quic,
        overlay,
        mut bootstrap,
        mut exchange,
        mut walks,
        counters,
        dial,
        authority,
    } = task;
    let entropy = entropy::Entropy::system();
    // The address the QUIC endpoint is bound to
    let quic_bound = quic.as_ref().map(|q| q.local_addr());
    let mut exchanging = Exchanging::default();
    // The connection each peer that is lent a place has
    let mut lent_to: HashMap<PeerId, ConnectionId> = HashMap::new();
    let mut pending_providers: PendingProviders = HashMap::new();
    // The providers being dialed, and who waits for each
    let mut dialing: HashMap<PeerId, Vec<oneshot::Sender<bool>>> = HashMap::new();
    // The questions for the images in flight: the one each belongs to
    let mut image_requests: HashMap<request_response::OutboundRequestId, u64> = HashMap::new();
    // The messages of our filter not answered yet: one that fails while the
    // peer is still connected is followed by the whole filter (what was lost
    // may have been a delta, which nothing after it would repair), once:
    // whether a message is that whole filter
    let mut filter_sent: HashMap<request_response::OutboundRequestId, bool> = HashMap::new();
    // The questions for the images in progress: the answers still to come
    // and who to tell when there are none.
    let mut image_queries: std::collections::HashMap<u64, (usize, oneshot::Sender<()>)> =
        std::collections::HashMap::new();
    let mut next_query = 0u64;
    let mut tun_packet_handler: Option<Arc<dyn Fn(PeerId, tun_tunnel::TunPacket) + Send + Sync>> =
        None;
    // The packets of the overlay sent and not answered, and the peer of each
    let mut tun_sent = tun_tunnel::Sent::<request_response::OutboundRequestId>::default();

    loop {
        tokio::select! {
            // Too few peers for a while: the bootstrap peers again
            _ = async {
                match bootstrap.deadline() {
                    Some(at) => tokio::time::sleep_until(at).await,
                    None => std::future::pending().await,
                }
            } => {
                let connected = swarm.connected_peers().count();
                let known = peer_stats.read().await.values()
                    .flat_map(|s| s.addresses.clone()).collect::<Vec<_>>();
                let due: Vec<Multiaddr> = bootstrap
                    .fired(connected, tokio::time::Instant::now())
                    .iter()
                    // (not the ones the node is connected to)
                    .filter(|a| !known.contains(a))
                    .filter(|a| {
                        !a.iter().any(|p| matches!(p,
                            libp2p::multiaddr::Protocol::P2p(id) if swarm.is_connected(&id)))
                    })
                    .cloned()
                    .collect();
                if !due.is_empty() {
                    debug!("{connected} peers: dialing the bootstrap peers again");
                    dial_all(&mut swarm, &due);
                }
                if connected > 0 {
                    // (what the peers know of others)
                    let _ = swarm.behaviour_mut().kademlia.bootstrap();
                    // and a few of them, at random, which they are connected to
                    // (unless what it is dialing of earlier answers is enough)
                    let mut members: Vec<PeerId> = status.borrow().connected.iter().copied().collect();
                    members.sort();
                    entropy.shuffle(&mut members);
                    let asked = if exchanging.wants_peers(&bootstrap, connected) {
                        peer_exchange::ASKED_PEERS
                    } else {
                        0
                    };
                    for peer in members.into_iter().take(asked) {
                        ask_peers(&mut swarm, &mut exchanging, peer, None, false);
                    }
                }
            }
            // A newcomer a full node took for a moment has asked what it
            // wanted to know
            _ = async {
                match exchange.deadline() {
                    Some(at) => tokio::time::sleep_until(at).await,
                    None => std::future::pending().await,
                }
            } => {
                for id in exchange.expired(tokio::time::Instant::now()) {
                    swarm.close_connection(id);
                }
            }
            // The connections of a walk past max_outgoing are closed
            _ = async {
                match walks.deadline() {
                    Some(at) => tokio::time::sleep_until(at).await,
                    None => std::future::pending().await,
                }
            } => {
                for id in walks.expired(tokio::time::Instant::now()) {
                    swarm.close_connection(id);
                }
            }
            event = swarm.select_next_some() => {
                match event {
                    SwarmEvent::NewListenAddr { address, .. } => {
                        info!("Listening on {}", address);
                        // What a provider record of the DHT says of the
                        // node is its external addresses (or nothing): the
                        // one libp2p dials, and the QUIC endpoint, which
                        // is reachable at the addresses of the node and
                        // told to the peers as a listen address of its own
                        swarm.add_external_address(address.clone());
                        if let Some(quic_addr) = quic_bound.and_then(|b| quic_advertised(b, &address)) {
                            swarm.add_external_address(quic_addr);
                        }
                        status.send_modify(|s| s.listen_addresses.push(address));
                    }
                    SwarmEvent::ExpiredListenAddr { address, .. } => {
                        swarm.remove_external_address(&address);
                        if let Some(quic_addr) = quic_bound.and_then(|b| quic_advertised(b, &address)) {
                            swarm.remove_external_address(&quic_addr);
                        }
                        status.send_modify(|s| s.listen_addresses.retain(|a| *a != address));
                    }
                    SwarmEvent::ConnectionEstablished { peer_id, connection_id, endpoint, .. } => {
                        debug!("Connected to {}", peer_id);
                        exchanging.dialing.remove(&peer_id);
                        // (its certificate was judged in the upgrade; a sweep
                        // that dropped it since, or a closing that raced
                        // with this connection, leaves it unknown: closed)
                        if authority.as_ref().is_some_and(|a| !a.established(&peer_id)) {
                            debug!("{peer_id}: its certificate is not known any more, the connection is closed");
                            swarm.close_connection(connection_id);
                            continue;
                        }
                        // (one past max_incoming is closed soon: it is told
                        // nothing of the layers; or at once: no place for it)
                        let place = if endpoint.is_listener() {
                            exchange.incoming(connection_id, tokio::time::Instant::now())
                        } else {
                            // (a walk of the DHT dials the peers it asks, and
                            // a connection past max_outgoing is for the walk)
                            walks.incoming(connection_id, tokio::time::Instant::now())
                        };
                        if place == bootstrap::Place::Refused {
                            debug!("{peer_id}: no place for it, the lent ones are taken");
                            swarm.close_connection(connection_id);
                            continue;
                        }
                        let passing = place == bootstrap::Place::Lent;
                        if passing {
                            lent_to.insert(peer_id, connection_id);
                        }
                        // (where a peer is connected from or to is known
                        // before it is one of the connected: its network
                        // is asked for then)
                        {
                            let addr = endpoint.get_remote_address().clone();
                            let mut ps = peer_stats.write().await;
                            let stats = ps.entry(peer_id).or_insert_with(|| PeerStats {
                                peer_id,
                                addresses: Vec::new(),
                            });
                            if !stats.addresses.contains(&addr) {
                                stats.addresses.push(addr);
                            }
                        }
                        // a new peer learns the layers we have at once (a
                        // connection that is not lent is where it becomes
                        // one of the connected, whichever it is of its
                        // connections)
                        if !passing && !status.borrow().connected.contains(&peer_id) {
                            if let Some(msg) = advertisement.with(|a| a.full()) {
                                filter_sent.insert(swarm.behaviour_mut().gossip.send_request(&peer_id, msg), false);
                            }
                            // (and the overlay's subnet and names, which it
                            // would not hear of before the next change)
                            if let Some(overlay) = &overlay {
                                for msg in overlay.hello().await {
                                    swarm.behaviour_mut().gossip.send_request(&peer_id, msg);
                                }
                            }
                            status.send_modify(|s| {
                                s.connected.insert(peer_id);
                            });
                        }
                        // (told once the peer is one of the connected)
                        for done in dialing.remove(&peer_id).into_iter().flatten() {
                            let _ = done.send(true);
                        }
                    }
                    SwarmEvent::ConnectionClosed { peer_id, connection_id, endpoint, num_established, .. } => {
                        debug!("Connection to {} closed, {} left", peer_id, num_established);
                        exchange.closed(connection_id);
                        walks.closed(connection_id);
                        lent_to.retain(|_, c| *c != connection_id);
                        // (the address of that connection is no longer one
                        // the peer is reached at)
                        let left = match peer_stats.write().await.get_mut(&peer_id) {
                            Some(stats) => {
                                let addr = endpoint.get_remote_address();
                                stats.addresses.retain(|a| a != addr);
                                peer_ips(stats)
                            }
                            None => Vec::new(),
                        };
                        // (nor is a QUIC endpoint of the peer at that address
                        // one to keep a connection to: one that is not
                        // advertised, its endpoint seen through a NAT, is
                        // forgotten here, the advertised ones below)
                        let advertised = quic_addrs
                            .read()
                            .unwrap_or_else(|e| e.into_inner())
                            .get(&peer_id)
                            .cloned()
                            .unwrap_or_default();
                        for addr in quic_targets_gone(
                            &advertised,
                            ip_of(endpoint.get_remote_address()),
                            &left,
                        ) {
                            quic.iter().for_each(|q| q.forget(addr));
                        }
                        // A peer is gone with its last connection: what
                        // the others carry (its layers, its QUIC
                        // addresses, its statistics) is kept till then
                        if num_established == 0 {
                            if let Some(authority) = &authority {
                                authority.disconnected(&peer_id);
                            }
                            let gone = quic_addrs
                                .write()
                                .unwrap_or_else(|e| e.into_inner())
                                .remove(&peer_id);
                            for addr in gone.into_iter().flatten() {
                                quic.iter().for_each(|q| q.forget(addr));
                            }
                            status.send_modify(|s| {
                                s.connected.remove(&peer_id);
                                s.quic_peers.remove(&peer_id);
                            });
                            gossip.remove_peer(&peer_id).await;
                            if let Some(overlay) = &overlay {
                                overlay.remove_peer(&peer_id).await;
                            }
                            exchanging.directory.forget(&peer_id);
                            peer_stats.write().await.remove(&peer_id);
                            bootstrap.connections(
                                swarm.connected_peers().count(),
                                tokio::time::Instant::now(),
                            );
                        }
                    }
                    SwarmEvent::Behaviour(VelarxBehaviourEvent::Kademlia(
                        kad::Event::OutboundQueryProgressed { id, result, step, .. }
                    )) => {
                        // A bootstrap is the walk to the node itself and then one
                        // for each of up to 255 buckets, each dialing a score of
                        // peers (and past max_outgoing, again and again): the
                        // first is what a node needs to be known
                        if matches!(result, kad::QueryResult::Bootstrap(_)) && !step.last {
                            if let Some(mut walk) = swarm.behaviour_mut().kademlia.query_mut(&id) {
                                walk.finish();
                            }
                        }
                        match result {
                            kad::QueryResult::GetProviders(found) => {
                                // The addresses of the providers are the query's, and only
                                // while it runs: the ones that are not connected are dialed
                                // now (a few), for the asker that uses them.
                                if let (Ok(kad::GetProvidersOk::FoundProviders { providers, .. }), true) =
                                    (&found, pending_providers.contains_key(&id))
                                {
                                    for peer in providers.iter().take(MAX_DIALED) {
                                        dial_provider(&mut swarm, &mut dialing, &counters, *peer, None);
                                    }
                                }
                                if answer_providers(&mut pending_providers, id, found) {
                                    if let Some(mut query) = swarm.behaviour_mut().kademlia.query_mut(&id) {
                                        query.finish();
                                    }
                                }
                            }
                            kad::QueryResult::StartProviding(Ok(_)) => {
                                debug!("Successfully started providing");
                                let held = swarm.behaviour_mut().kademlia.store_mut().provided().count();
                                status.send_modify(|s| s.provider_records = held);
                            }
                            _ => {}
                        }
                    }
                    SwarmEvent::Behaviour(VelarxBehaviourEvent::Mdns(
                        libp2p::mdns::Event::Discovered(peers)
                    )) => {
                        for (peer_id, addr) in peers {
                            debug!("mDNS discovered {} at {}", peer_id, addr);
                            swarm.behaviour_mut().kademlia.add_address(&peer_id, addr.clone());
                            // Dial the peer to establish connection for chunk transfer
                            if !swarm.is_connected(&peer_id) {
                                if let Err(e) = swarm.dial(addr.clone()) {
                                    debug!("Failed to dial mDNS peer {} at {}: {}", peer_id, addr, e);
                                }
                            }
                        }
                    }
                    SwarmEvent::Behaviour(VelarxBehaviourEvent::Identify(
                        identify::Event::Received { peer_id, info, .. }
                    )) => {
                        debug!("Identified {} as {:?}", peer_id, info.protocols);
                        // (the addresses it is connected from or to)
                        let ips_of_peer = peer_stats
                            .read()
                            .await
                            .get(&peer_id)
                            .map(peer_ips)
                            .unwrap_or_default();
                        // The QUIC endpoint of the peer is one of its listen addresses
                        let quic_peer = quic_addresses(&info.listen_addrs);
                        if !quic_peer.is_empty() {
                            // the connection of the chunks is made before they are asked
                            if let Some(addr) = quic_target(&quic_peer, &ips_of_peer) {
                                if let Some(quic) = &quic {
                                    quic.expect(addr, peer_id);
                                    quic.warm(addr);
                                }
                            }
                            quic_addrs
                                .write()
                                .unwrap_or_else(|e| e.into_inner())
                                .insert(peer_id, quic_peer);
                            status.send_modify(|s| {
                                s.quic_peers.insert(peer_id);
                            });
                        }
                        let listen_of_peer = info.listen_addrs.clone();
                        for addr in info
                            .listen_addrs
                            .into_iter()
                            .filter(dialable)
                        {
                            swarm.behaviour_mut().kademlia.add_address(&peer_id, addr);
                        }
                        // (what this peer says of where it listens, as far as the
                        // connection tells it is so: what is told to others)
                        exchanging.directory.learn(peer_id, &ips_of_peer, &listen_of_peer);
                        // a node with few peers asks them for others (one
                        // that a full peer took for a moment learns them so)
                        let connected = swarm.connected_peers().count();
                        if bootstrap.wants_peers(connected) {
                            let _ = swarm.behaviour_mut().kademlia.bootstrap();
                            if exchanging.wants_peers(&bootstrap, connected) {
                                ask_peers(&mut swarm, &mut exchanging, peer_id, None, false);
                            }
                        }
                    }
                    SwarmEvent::Behaviour(VelarxBehaviourEvent::Gossip(
                        request_response::Event::Message { peer, message, .. }
                    )) => {
                        match message {
                            request_response::Message::Request { request, channel, .. } => {
                                // Only a node that announces its images answers
                                // a question for them
                                let reply = match request {
                                    GossipMessage::ImageQuery => gossip.image_reply().await,
                                    // (the peers this node is connected to and has
                                    // identified, a few)
                                    GossipMessage::PeerQuery => {
                                        let now = tokio::time::Instant::now();
                                        let connected = status.borrow().connected.clone();
                                        let told = exchanging.directory.answer(
                                            &peer,
                                            |p| connected.contains(p),
                                            &dial,
                                            &entropy,
                                        );
                                        if !told.is_empty() {
                                            counters.exchange_answered();
                                        }
                                        // (a newcomer that was answered has what it came
                                        // for: its place is freed soon)
                                        if let Some(id) = lent_to.get(&peer) {
                                            exchange.served(*id, now);
                                        }
                                        GossipReply { peers: Some(told), ..Default::default() }
                                    }
                                    GossipMessage::Revocations { lists } => {
                                        if let Some(authority) = &authority {
                                            authority.adopt(&lists.join("\n"));
                                        }
                                        GossipReply::default()
                                    }
                                    request => {
                                        match &overlay {
                                            Some(overlay) => overlay.handle_gossip_message(peer, request).await,
                                            None => gossip.handle_gossip_message(peer, request).await,
                                        }
                                        GossipReply::default()
                                    }
                                };
                                let _ = swarm.behaviour_mut().gossip.send_response(channel, reply);
                            }
                            request_response::Message::Response { request_id, response } => {
                                filter_sent.remove(&request_id);
                                // The answer to our question: the peers of the peer
                                if let Some((from, done)) = exchanging.asked.remove(&request_id) {
                                    let named = response.peers.unwrap_or_default();
                                    let dialed = dial_learned(
                                        &mut swarm,
                                        &counters,
                                        &dial,
                                        &named,
                                        peer_exchange::MAX_DIALS,
                                        &mut exchanging.dialing,
                                    );
                                    debug!("{from} named {} peers, {dialed} dialed", named.len());
                                    if let Some(done) = done {
                                        let _ = done.send(dialed);
                                    }
                                // The answer to our question: the images of the peer
                                } else if let Some(query) = image_requests.remove(&request_id) {
                                    if let Some(images) = response.images {
                                        debug!("Received {} images of {}", images.len(), peer);
                                        gossip
                                            .handle_gossip_message(peer, GossipMessage::ImageAnnounce { images })
                                            .await;
                                    }
                                    answered(&mut image_queries, query);
                                }
                            }
                        }
                    }
                    SwarmEvent::Behaviour(VelarxBehaviourEvent::Gossip(
                        request_response::Event::OutboundFailure { request_id, peer, error, .. }
                    )) => {
                        debug!("Gossip to {} failed: {:?}", peer, error);
                        // (not again for the whole filter sent after a
                        // failure: the next refresh sends it)
                        if filter_sent.remove(&request_id) == Some(false)
                            && swarm.is_connected(&peer)
                            && !matches!(error, request_response::OutboundFailure::UnsupportedProtocols)
                        {
                            if let Some(msg) = advertisement.with(|a| a.full()) {
                                debug!("The filter is told {peer} whole again");
                                filter_sent.insert(swarm.behaviour_mut().gossip.send_request(&peer, msg), true);
                            }
                        }
                        if let Some((_, Some(done))) = exchanging.asked.remove(&request_id) {
                            let _ = done.send(0);
                        }
                        if let Some(query) = image_requests.remove(&request_id) {
                            answered(&mut image_queries, query);
                        }
                    }
                    SwarmEvent::Behaviour(VelarxBehaviourEvent::Gossip(
                        request_response::Event::InboundFailure { peer, error, .. }
                    )) => {
                        debug!("Gossip of {} failed: {:?}", peer, error);
                    }
                    SwarmEvent::Behaviour(VelarxBehaviourEvent::Gossip(
                        request_response::Event::ResponseSent { .. }
                    )) => {}
                    // A peer that does not answer its pings is gone
                    SwarmEvent::Behaviour(VelarxBehaviourEvent::Ping(ping::Event {
                        peer, connection, result: Err(e), ..
                    })) => {
                        debug!("Ping to {} failed, closing the connection: {}", peer, e);
                        swarm.close_connection(connection);
                    }
                    SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
                        let hint = key_hint(dial_failed_on_key(&error));
                        if let Some(peer) = peer_id {
                            exchanging.dialing.remove(&peer);
                            if let Some(waiting) = dialing.remove(&peer) {
                                counters.dial_failed();
                                for done in waiting {
                                    let _ = done.send(false);
                                }
                            }
                            debug!("Failed to connect to peer {}: {}{}", peer, error, hint);
                        } else {
                            debug!("Outgoing connection failed: {}{}", error, hint);
                        }
                    }
                    SwarmEvent::IncomingConnectionError { error, send_back_addr, .. } => {
                        let hint = key_hint(listen_failed_on_key(&error));
                        debug!(
                            "Incoming connection from {} failed: {}{}",
                            send_back_addr, error, hint
                        );
                    }
                    SwarmEvent::Behaviour(VelarxBehaviourEvent::TunTunnel(
                        request_response::Event::Message { peer, message, .. }
                    )) => {
                        match message {
                            request_response::Message::Request { request, channel, .. } => {
                                debug!("Received TUN packet from {}: {} bytes", peer, request.data.len());
                                if let Some(ref handler) = tun_packet_handler {
                                    handler(peer, request);
                                }
                                // Send empty response (fire-and-forget)
                                if let Some(tunnel) = swarm.behaviour_mut().tun_tunnel.as_mut() {
                                    let _ = tunnel.send_response(channel, tun_tunnel::TunResponse);
                                }
                            }
                            request_response::Message::Response { request_id, .. } => {
                                tun_sent.done(&request_id);
                            }
                        }
                    }
                    SwarmEvent::Behaviour(VelarxBehaviourEvent::TunTunnel(
                        request_response::Event::OutboundFailure { peer, request_id, error, .. }
                    )) => {
                        tun_sent.done(&request_id);
                        debug!("TUN tunnel send to {} failed: {:?}", peer, error);
                    }
                    SwarmEvent::Behaviour(VelarxBehaviourEvent::TunTunnel(
                        request_response::Event::InboundFailure { error, .. }
                    )) => {
                        debug!("TUN tunnel inbound failed: {:?}", error);
                    }
                    SwarmEvent::Behaviour(VelarxBehaviourEvent::TunTunnel(
                        request_response::Event::ResponseSent { .. }
                    )) => {
                    }
                    _ => {}
                }
            }
            cmd = cmd_rx.recv() => {
                match cmd {
                    Some(P2PCommand::Announce { key }) => {
                        let record_key = kad::RecordKey::new(&key);
                        if let Err(e) = swarm.behaviour_mut().kademlia.start_providing(record_key) {
                            warn!("Failed to start providing: {:?}", e);
                        }
                    }
                    Some(P2PCommand::Withdraw { key }) => {
                        swarm.behaviour_mut().kademlia.stop_providing(&kad::RecordKey::new(&key));
                        let held = swarm.behaviour_mut().kademlia.store_mut().provided().count();
                        status.send_modify(|s| s.provider_records = held);
                    }
                    Some(P2PCommand::GetProviders { key, tx }) => {
                        let record_key = kad::RecordKey::new(&key);
                        // (a peer that does not answer would hold the walk
                        // until its request times out: it is not asked)
                        let silent: Vec<PeerId> = swarm
                            .connected_peers()
                            .filter(|p| gossip.knowledge().failing(p))
                            .copied()
                            .collect();
                        for peer in silent {
                            swarm.behaviour_mut().kademlia.remove_peer(&peer);
                        }
                        // (the walks nobody waits for end: an asker that is asked
                        // again starts a new one each time, each dialing peers)
                        pending_providers.retain(|id, tx| {
                            let waited = !tx.is_closed();
                            if !waited {
                                if let Some(mut walk) = swarm.behaviour_mut().kademlia.query_mut(id) {
                                    walk.finish();
                                }
                            }
                            waited
                        });
                        let query_id = swarm.behaviour_mut().kademlia.get_providers(record_key);
                        pending_providers.insert(query_id, tx);
                    }
                    Some(P2PCommand::DialPeer { addr }) => {
                        if let Err(e) = swarm.dial(addr.clone()) {
                            warn!("Failed to dial {}: {}", addr, e);
                        }
                    }
                    Some(P2PCommand::DialProvider { peer, done }) => {
                        dial_provider(&mut swarm, &mut dialing, &counters, peer, Some(done));
                    }
                    Some(P2PCommand::BroadcastGossip { msg }) => {
                        let peers: Vec<PeerId> = swarm.connected_peers().cloned().collect();
                        let of_filter = matches!(
                            msg,
                            GossipMessage::LayerFilter(_) | GossipMessage::LayerFilterDelta(_)
                        );
                        for peer_id in &peers {
                            let id = swarm.behaviour_mut().gossip.send_request(peer_id, msg.clone());
                            if of_filter {
                                filter_sent.insert(id, false);
                            }
                        }
                        debug!("Broadcast gossip message to {} peers", peers.len());
                    }
                    Some(P2PCommand::AskPeers { peer, done }) => {
                        ask_peers(&mut swarm, &mut exchanging, peer, Some(done), true);
                    }
                    Some(P2PCommand::QueryImages { done }) => {
                        let mut asked = 0;
                        next_query += 1;
                        for peer_id in swarm.connected_peers().cloned().collect::<Vec<_>>() {
                            let id = swarm.behaviour_mut().gossip.send_request(&peer_id, GossipMessage::ImageQuery);
                            image_requests.insert(id, next_query);
                            asked += 1;
                        }
                        if asked == 0 {
                            let _ = done.send(());
                        } else {
                            image_queries.insert(next_query, (asked, done));
                        }
                    }
                    Some(P2PCommand::SendTunPacket { peer, packet }) => {
                        // Send TUN packet to peer (fire-and-forget); one that
                        // finds the peer or the node with that many sent and
                        // not answered is dropped, as a network drops what
                        // it cannot carry (the library queues all of them)
                        if let (true, Some(tunnel)) = (
                            tun_sent.may_send(&peer),
                            swarm.behaviour_mut().tun_tunnel.as_mut(),
                        ) {
                            let id = tunnel.send_request(&peer, packet);
                            tun_sent.sent(id, peer);
                        }
                    }
                    Some(P2PCommand::SetTunPacketHandler { handler }) => {
                        info!("TUN packet handler set for P2P node");
                        tun_packet_handler = Some(handler);
                    }
                    Some(P2PCommand::Disconnect { peers }) => {
                        for peer in peers {
                            let _ = swarm.disconnect_peer_id(peer);
                        }
                    }
                    Some(P2PCommand::Shutdown) | None => {
                        info!("Shutting down P2P node");

                        break;
                    }
                }
            }
        }
    }
}

/// How long a question for the images of the peers is waited for at most:
/// each peer answers (or fails) well before, the limit is for one that does
/// not.
const IMAGE_QUERY_LIMIT: Duration = Duration::from_secs(2);

/// An answer to the question `query` (if one asked) came, or failed: the
/// asker is told when it was the last.
fn answered(queries: &mut HashMap<u64, (usize, oneshot::Sender<()>)>, query: u64) {
    if let Some((left, _)) = queries.get_mut(&query) {
        *left -= 1;
        if *left == 0 {
            if let Some((_, done)) = queries.remove(&query) {
                let _ = done.send(());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A query of the DHT that failed answers the asker with an error and
    /// forgets the question.
    #[tokio::test]
    async fn a_failed_provider_query_is_an_error_for_the_asker() {
        let mut pending = PendingProviders::<u32>::new();
        let (tx, mut rx) = mpsc::channel(1);
        let id = 7;
        pending.insert(id, tx);
        let failed = Err(kad::GetProvidersError::Timeout {
            key: kad::RecordKey::new(&b"k"),
            closest_peers: Vec::new(),
        });
        assert!(!answer_providers(&mut pending, id, failed));
        assert!(pending.is_empty(), "the question is kept");
        assert!(matches!(rx.recv().await, Some(Err(P2PError::Timeout))));
    }

    /// The walk of the DHT reports each peer that answered, also one that
    /// knows no provider, and each batch of providers: the asker gets all of
    /// them, not the first (a stale record of a node that left comes first,
    /// the holder later), and the walk stops when the asker left.
    #[tokio::test(start_paused = true)]
    async fn the_asker_gathers_the_batches_of_the_walk() {
        let mut pending = PendingProviders::<u32>::new();
        let (tx, rx) = mpsc::channel(LOOKUP_ENOUGH);
        pending.insert(7, tx);
        let key = kad::RecordKey::new(&b"k");
        let found = |providers| {
            Ok(kad::GetProvidersOk::FoundProviders {
                key: key.clone(),
                providers,
            })
        };
        let (stale, holder) = (PeerId::random(), PeerId::random());
        let asker = tokio::spawn(gather_providers(rx, LOOKUP_LIMIT, LOOKUP_GATHER));
        assert!(!answer_providers(
            &mut pending,
            7,
            found(Default::default())
        ));
        assert!(pending.contains_key(&7), "the question was answered empty");
        assert!(!answer_providers(&mut pending, 7, found([stale].into())));
        tokio::time::sleep(LOOKUP_GATHER / 2).await;
        assert!(!answer_providers(
            &mut pending,
            7,
            found([holder, stale].into())
        ));
        assert_eq!(asker.await.unwrap().unwrap(), [stale, holder]);
        // the asker is gone: the walk is to be stopped, the question forgotten
        assert!(answer_providers(&mut pending, 7, found([holder].into())));
        assert!(pending.is_empty());
        // the end of a walk ends the gathering at once
        let (tx, rx) = mpsc::channel(LOOKUP_ENOUGH);
        pending.insert(8, tx);
        let asker = tokio::spawn(gather_providers(rx, LOOKUP_LIMIT, LOOKUP_GATHER));
        assert!(!answer_providers(&mut pending, 8, found([holder].into())));
        let end = Ok(kad::GetProvidersOk::FinishedWithNoAdditionalRecord {
            closest_peers: Vec::new(),
        });
        assert!(!answer_providers(&mut pending, 8, end));
        assert!(pending.is_empty());
        let started = tokio::time::Instant::now();
        assert_eq!(asker.await.unwrap().unwrap(), [holder]);
        assert!(started.elapsed() < LOOKUP_GATHER);
        // nothing at all within the limit: no answer
        let (_tx, rx) = mpsc::channel(LOOKUP_ENOUGH);
        assert!(gather_providers(rx, LOOKUP_LIMIT, LOOKUP_GATHER)
            .await
            .is_err());
    }

    /// The asker of a question for the images is told with the last answer.
    #[test]
    fn a_question_is_done_with_its_last_answer() {
        let mut queries = std::collections::HashMap::new();
        let (done, mut told) = oneshot::channel();
        queries.insert(7, (2, done));
        answered(&mut queries, 7);
        assert!(told.try_recv().is_err());
        answered(&mut queries, 7);
        assert!(told.try_recv().is_ok());
        assert!(queries.is_empty());
        answered(&mut queries, 7);
    }

    /// A node told to listen on one address opens its QUIC endpoint there
    /// too, not on every interface.
    #[test]
    fn the_quic_endpoint_binds_the_listen_address() {
        let ip =
            |s: &[&str]| quic_bind_ip(&s.iter().map(|a| a.parse().unwrap()).collect::<Vec<_>>());
        let any: std::net::IpAddr = "0.0.0.0".parse().unwrap();
        assert_eq!(
            ip(&["/ip4/127.0.0.1/tcp/4001"]),
            "127.0.0.1".parse::<std::net::IpAddr>().unwrap()
        );
        assert_eq!(
            ip(&["/ip4/192.168.0.5/tcp/4001", "/ip4/10.0.0.5/tcp/4001"]),
            "192.168.0.5".parse::<std::net::IpAddr>().unwrap()
        );
        assert_eq!(
            ip(&["/ip6/::1/tcp/4001"]),
            "::1".parse::<std::net::IpAddr>().unwrap()
        );
        assert_eq!(ip(&["/ip4/0.0.0.0/tcp/4001"]), any);
        // (an IPv6 node, or one of both families, is reached over IPv6 too)
        let any6: std::net::IpAddr = "::".parse().unwrap();
        assert_eq!(ip(&["/ip6/::/tcp/4001"]), any6);
        assert_eq!(ip(&["/ip4/127.0.0.1/tcp/4001", "/ip6/::/tcp/4001"]), any6);
        assert_eq!(ip(&["/ip6/::/tcp/4001", "/ip4/0.0.0.0/tcp/4001"]), any6);
        assert_eq!(ip(&["/ip4/0.0.0.0/tcp/4001", "/ip6/::/tcp/4001"]), any6);
        assert_eq!(ip(&[]), any);
    }

    /// A QUIC connection made to the address a peer is connected from
    /// (behind a NAT, not the one it advertises) is forgotten when no
    /// connection of the peer is from that address any more, and only then.
    #[test]
    fn a_quic_target_goes_with_the_last_connection_from_its_address() {
        let advertised: Vec<std::net::SocketAddr> = vec![
            "10.0.0.5:4001".parse().unwrap(),
            "[fd00::5]:4001".parse().unwrap(),
            "10.0.0.5:4002".parse().unwrap(),
        ];
        let public: std::net::IpAddr = "203.0.113.7".parse().unwrap();
        assert_eq!(
            quic_target(&advertised, &[public]),
            Some("203.0.113.7:4001".parse().unwrap())
        );
        assert_eq!(
            quic_targets_gone(&advertised, Some(public), &[]),
            [
                "203.0.113.7:4001".parse().unwrap(),
                "203.0.113.7:4002".parse().unwrap()
            ]
        );
        // (another connection from it is left: kept)
        assert!(quic_targets_gone(&advertised, Some(public), &[public]).is_empty());
        assert!(quic_targets_gone(&advertised, None, &[]).is_empty());
    }

    /// The endpoint of a node that listens on the loopback is bound there.
    #[tokio::test]
    async fn a_loopback_node_has_its_quic_endpoint_on_the_loopback() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("swarm.key");
        crate::control::generate_swarm_key(&path).unwrap();
        let node = P2PNode::with_config(local_config(Some(&path)))
            .await
            .unwrap();
        let addr = node.quic().local_addr();
        assert!(addr.ip().is_loopback(), "{addr}");
        node.shutdown().await.unwrap();
    }

    /// `shutdown` returns once the swarm task ended: the receiver of its
    /// commands, which it owns, is gone.
    #[tokio::test]
    async fn shutdown_returns_once_the_swarm_task_ended() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("swarm.key");
        crate::control::generate_swarm_key(&path).unwrap();
        let node = P2PNode::with_config(local_config(Some(&path)))
            .await
            .unwrap();
        node.shutdown().await.unwrap();
        assert!(node.cmd_tx.is_closed());
    }

    /// A connection that failed in the secure channel's negotiation or
    /// handshake (what a peer of another swarm key meets) is told from the
    /// others by the type of its error, wherever it sits in the chain.
    #[test]
    fn a_failure_of_the_secure_channel_is_a_key_hint() {
        use libp2p::core::transport::TransportError;
        use libp2p::core::upgrade::NegotiationError;
        use libp2p::swarm::DialError;
        let refused = || std::io::Error::from(std::io::ErrorKind::ConnectionRefused);
        let dial = |e: std::io::Error| {
            DialError::Transport(vec![(
                "/ip4/127.0.0.1/tcp/1".parse().unwrap(),
                TransportError::Other(e),
            )])
        };
        // (as the transport reports them: an error inside an io error)
        let handshake = std::io::Error::other(noise::Error::Io(std::io::Error::from(
            std::io::ErrorKind::ConnectionReset,
        )));
        let negotiation = std::io::Error::other(std::io::Error::other(NegotiationError::Failed));
        assert!(dial_failed_on_key(&dial(handshake)));
        assert!(dial_failed_on_key(&dial(negotiation)));
        assert!(!dial_failed_on_key(&dial(refused())));
        // the word is not what tells: a refused connection that says it
        let words = std::io::Error::other("PnetError in the handshake");
        assert!(!dial_failed_on_key(&dial(words)));
        assert!(!dial_failed_on_key(&DialError::NoAddresses));
        let listen =
            |e: std::io::Error| libp2p::swarm::ListenError::Transport(TransportError::Other(e));
        assert!(listen_failed_on_key(&listen(std::io::Error::other(
            NegotiationError::Failed
        ))));
        assert!(!listen_failed_on_key(&listen(refused())));
        assert_eq!(key_hint(false), "");
    }

    /// The QUIC endpoint of a node is a listen address of its own, for each
    /// address it listens on that the endpoint can be reached at, and what a
    /// peer advertises is read back: the address and the port, nothing else.
    #[test]
    fn the_quic_endpoint_is_advertised_as_a_listen_address() {
        let listen: Multiaddr = "/ip4/192.0.2.7/tcp/4001".parse().unwrap();
        let any = |port| std::net::SocketAddr::from(([0, 0, 0, 0], port));
        let advertised = quic_advertised(any(5000), &listen).unwrap();
        assert_eq!(advertised.to_string(), "/ip4/192.0.2.7/udp/5000/quic-v1");
        assert_eq!(
            quic_addresses(&[listen.clone(), advertised.clone()]),
            vec!["192.0.2.7:5000".parse().unwrap()]
        );
        // bound to one address: only that one; an IPv4 socket is no IPv6 address
        let lo = std::net::SocketAddr::from(([127, 0, 0, 1], 5000));
        assert!(quic_advertised(lo, &listen).is_none());
        let loopback: Multiaddr = "/ip4/127.0.0.1/tcp/4001".parse().unwrap();
        assert!(quic_advertised(lo, &loopback).is_some());
        let v6: Multiaddr = "/ip6/2001:db8::1/tcp/4001".parse().unwrap();
        assert!(quic_advertised(any(5000), &v6).is_none());
        assert_eq!(
            quic_advertised(std::net::SocketAddr::from(([0u16; 8], 5000)), &v6)
                .unwrap()
                .to_string(),
            "/ip6/2001:db8::1/udp/5000/quic-v1"
        );
        // (`::` takes IPv4 too)
        assert_eq!(
            quic_advertised(std::net::SocketAddr::from(([0u16; 8], 5000)), &listen)
                .unwrap()
                .to_string(),
            "/ip4/192.0.2.7/udp/5000/quic-v1"
        );
        // what is read back: no port 0, no extra parts, no other protocol
        for odd in [
            "/ip4/192.0.2.7/udp/0/quic-v1",
            "/ip4/192.0.2.7/udp/5000",
            "/ip4/192.0.2.7/udp/5000/quic-v1/p2p/12D3KooWD3eckifWpRn9wQpMG9R9hX3sD158z7EqHWmweQAJU5SA",
            "/dns4/example.org/udp/5000/quic-v1",
        ] {
            assert!(quic_addresses(&[odd.parse().unwrap()]).is_empty(), "{odd}");
        }
        // and the others are not dialed by libp2p
        assert!(dialable(&listen) && !dialable(&advertised));
    }

    /// The QUIC endpoint of a peer is reached at an address it is connected
    /// from or to: the one it advertises for it, else that address with the
    /// port it advertises; never an address only the peer names.
    #[test]
    fn the_quic_endpoint_is_reached_at_an_address_of_the_connection() {
        let sa = |s: &str| s.parse::<std::net::SocketAddr>().unwrap();
        let ip = |s: &str| s.parse::<std::net::IpAddr>().unwrap();
        let advertised = [sa("192.0.2.7:5000"), sa("198.51.100.7:5001")];
        assert_eq!(
            quic_target(&advertised, &[ip("198.51.100.7")]),
            Some(sa("198.51.100.7:5001"))
        );
        // behind a NAT: the address it is seen at, its port
        assert_eq!(
            quic_target(&advertised, &[ip("203.0.113.1")]),
            Some(sa("203.0.113.1:5000"))
        );
        // what it names that it is not connected at is not asked: a third
        // host, an IPv6 address for an IPv4 peer
        let elsewhere = [sa("169.254.169.254:80"), sa("[2001:db8::1]:5000")];
        assert_eq!(
            quic_target(&elsewhere, &[ip("203.0.113.1")]),
            Some(sa("203.0.113.1:80"))
        );
        assert_eq!(quic_target(&elsewhere[1..], &[ip("203.0.113.1")]), None);
        assert_eq!(quic_target(&advertised, &[]), None);
        // a link-local IPv6 address has no interface in a multiaddress
        assert_eq!(quic_target(&[sa("[fe80::1]:5000")], &[ip("fe80::1")]), None);
        assert_eq!(
            quic_target(
                &[sa("[2001:db8::1]:5000")],
                &[ip("fe80::1"), ip("2001:db8::1")]
            ),
            Some(sa("[2001:db8::1]:5000"))
        );
    }

    #[tokio::test]
    async fn test_p2p_config_default() {
        let config = P2PConfig::default();
        assert!(config.enable_mdns);
        assert_eq!(config.idle_timeout, Duration::from_secs(24 * 3600));
    }

    fn local_config(key: Option<&std::path::Path>) -> P2PConfig {
        P2PConfig {
            dial: crate::dial_filter::Rules::on_one_host(),
            listen_addrs: vec!["/ip4/127.0.0.1/tcp/0".to_string()],
            enable_mdns: false,
            private_key_path: key.map(PathBuf::from),
            ..Default::default()
        }
    }

    /// An address that is no multiaddress is an error of the node, not an
    /// address it skips.
    #[tokio::test]
    async fn test_a_node_refuses_an_address_it_cannot_parse() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("swarm.key");
        crate::control::generate_swarm_key(&path).unwrap();
        for config in [
            P2PConfig {
                dial: crate::dial_filter::Rules::on_one_host(),
                listen_addrs: vec!["/ip4/127.0.0.1/tcpx/1".into()],
                ..local_config(Some(&path))
            },
            P2PConfig {
                dial: crate::dial_filter::Rules::on_one_host(),
                bootstrap_peers: vec!["not an address".into()],
                ..local_config(Some(&path))
            },
        ] {
            let err = P2PNode::with_config(config).await.err().unwrap();
            assert!(matches!(err, P2PError::Transport(_)), "{err}");
        }
    }

    /// The peer id of a node is its identity's: a node that starts again with
    /// the identity of the file is the same peer, one without is a new one.
    #[tokio::test]
    async fn a_node_started_again_with_its_identity_is_the_same_peer() {
        let dir = tempfile::tempdir().unwrap();
        let key = dir.path().join("swarm.key");
        crate::control::generate_swarm_key(&key).unwrap();
        let file = dir.path().join("p2p/identity.key");
        let start = |identity| {
            let config = P2PConfig {
                dial: crate::dial_filter::Rules::on_one_host(),
                identity,
                ..local_config(Some(&key))
            };
            async move { P2PNode::with_config(config).await.unwrap().peer_id() }
        };
        let first = start(Some(identity::load_or_create(&file).unwrap())).await;
        let again = start(Some(identity::load_or_create(&file).unwrap())).await;
        assert_eq!(first, again);
        // (none: this run's own)
        assert_ne!(start(None).await, start(None).await);
        assert_ne!(start(None).await, first);
    }

    #[tokio::test]
    async fn test_a_node_does_not_start_without_a_swarm_key() {
        let err = P2PNode::with_config(local_config(None))
            .await
            .err()
            .unwrap();
        assert!(matches!(err, P2PError::MissingSwarmKey));
        let message = err.to_string();
        assert!(message.contains("generate-key"), "{message}");
        assert!(message.contains("VELARX_P2P_SWARM_KEY"), "{message}");
    }

    #[tokio::test]
    async fn test_a_node_refuses_a_key_that_others_can_read() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("swarm.key");
        crate::control::generate_swarm_key(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let err = P2PNode::with_config(local_config(Some(&path)))
            .await
            .err()
            .unwrap();
        assert!(matches!(err, P2PError::InvalidPrivateKey(_)), "{err}");
        assert!(err.to_string().contains("0644"), "{err}");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let node = P2PNode::with_config(local_config(Some(&path)))
            .await
            .unwrap();
        node.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn test_a_node_refuses_a_malformed_key() {
        let config = P2PConfig {
            dial: crate::dial_filter::Rules::on_one_host(),
            private_key: Some("not a key".to_string()),
            ..local_config(None)
        };
        let err = P2PNode::with_config(config).await.err().unwrap();
        assert!(matches!(err, P2PError::InvalidPrivateKey(_)));
    }
}
