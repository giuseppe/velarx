// SPDX-License-Identifier: Apache-2.0
//! The varlink interface `org.velarx.P2p`, the control of the service
//! (`velarx-p2p`), and the client its commands use (`velarx-p2p status`).
//! The service's control socket serves:
//!
//! * `GetInfo`: the version and the protocol;
//! * `Status`, `PeerList`, `Stats`: what the node is, who it is connected
//!   to (one peer a reply, `more`: its state and what was fetched from it)
//!   and what it moved;
//! * `Advertised`, `Serving`, `BeliefList`: what the node tells the peers,
//!   what it is serving and has admitted (slots, credit), and what
//!   it believes of each peer and layer;
//! * `Explain`: why the pulls asked the peers they did (a bounded ring of
//!   recent decisions, one a reply);
//! * `ImageList`: the images of the other nodes, one a reply (`more`).
//!
//! Every blob that comes from a peer is untrusted and is verified by its
//! digest by whoever uses it, as one from a registry.

use serde::{Deserialize, Serialize};
use std::io;
use std::path::{Path, PathBuf};
use thiserror::Error;
use velarx_core::store_service::ImageInfo;
use velarx_proto::info::Info;
use zlink::{introspect, proxy};

/// The version of the protocol: a client refuses another one.
pub const PROTO: u32 = 1;

/// What the pulls of this node fetched from a peer.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, introspect::CustomType)]
pub struct PeerTraffic {
    /// The peer, by its libp2p id
    pub peer_id: String,
    /// The requests sent to it
    pub requests: u64,
    /// Those that failed
    pub failures: u64,
    /// What it sent: the chunks that matched their digests, the indexes of
    /// layers and the startup profiles
    pub chunks_received: u64,
    /// The bytes of those
    pub bytes_received: u64,
    /// The chunks it sent that did not match their digests (dropped)
    pub chunks_wrong: u64,
    /// The average time of an answer, in milliseconds
    pub average_ms: Option<f64>,
    /// The smoothed time of an answer that ranks the peers, in milliseconds
    pub rtt_ms: Option<f64>,
    /// The requests it had no room to answer (not counted as failures)
    pub busy: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, introspect::Type)]
pub struct Status {
    /// The id of this node
    pub peer_id: String,
    /// Its multiaddresses
    pub listen_addresses: Vec<String>,
    pub connected_peers: u64,
    /// Of those, the peers with no QUIC (UDP) path: members for discovery,
    /// not asked for data (`PeerList` says why, one by one)
    pub connected_without_quic: u64,
    pub provider_records: u64,
    /// What the pulls of this node fetched from each peer
    pub peers: Vec<PeerTraffic>,
    /// What this node served its peers: the chunks, indexes and profiles,
    /// and the bytes of its answers
    pub chunks_sent: u64,
    pub bytes_sent: u64,
    /// How the questions of who has what were answered
    pub lookups: Lookups,
    /// What the certificate of this node says of it (`name`, `zone`, `role`),
    /// when the swarm has an authority
    pub certificate: Option<Certificate>,
    /// The peers that were not admitted for their certificate (none, not
    /// valid, revoked, not allowed...) since the service started; the log
    /// says who and why
    pub admission_refused: u64,
}

/// What the certificate of a node says of it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, introspect::CustomType)]
pub struct Certificate {
    pub name: String,
    pub zone: Option<String>,
    /// `both`, `serve` or `pull`
    pub role: String,
}

impl From<crate::authority::Admitted> for Certificate {
    fn from(who: crate::authority::Admitted) -> Self {
        Self {
            name: who.name,
            zone: who.zone,
            role: who.role.to_string(),
        }
    }
}

/// What the probes of a chunk, the lookups of the DHT and the dials of the
/// providers it named came to, since the service started.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, introspect::CustomType,
)]
pub struct Lookups {
    /// Peers whose filter of layers is believed now
    pub filter_peers: u64,
    /// Peers asked for a layer after their filter said maybe, that held it,
    /// and that did not (false positives)
    pub filter_hits: u64,
    pub filter_false_positives: u64,
    /// Filters and updates of peers that were refused
    pub filter_refused: u64,
    /// Peers that said they have the chunk asked about
    pub probes_has: u64,
    /// Peers that said they do not
    pub probes_lacks: u64,
    /// Peers with no room to answer: nothing is known of them
    pub probes_busy: u64,
    /// Probes that failed or timed out
    pub probes_failed: u64,
    /// Lookups of the DHT that found providers
    pub dht_found: u64,
    /// Lookups of the DHT that found none
    pub dht_empty: u64,
    /// Lookups of the DHT that failed
    pub dht_failed: u64,
    /// Providers of the DHT that were dialed, and the dials that failed
    pub dials: u64,
    pub dials_failed: u64,
    /// Dials of any address that the filter of the node refused, by reason
    pub dials_refused: DialsRefused,
    /// Questions of peers for the peers this node knows that it answered
    /// with some, and peers it learnt from such an answer that it dialed
    pub exchange_answered: u64,
    pub exchange_dials: u64,
}

/// The dials refused for the address they were to, by the reason
/// (`dial_allow` of p2p.toml).
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, introspect::CustomType,
)]
pub struct DialsRefused {
    pub loopback: u64,
    pub link_local: u64,
    pub multicast: u64,
    pub unspecified: u64,
    pub reserved: u64,
    /// An address of an interface of this node
    pub own_interface: u64,
    /// Not an IP address and a TCP port (a name, an address in an address,
    /// port 0)
    pub unsupported: u64,
}

/// A connected peer.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, introspect::CustomType)]
pub struct Peer {
    /// Its libp2p id
    pub peer_id: String,
    /// The multiaddresses it is reached at
    pub addresses: Vec<String>,
    /// Why it is not asked for data: there is no QUIC (UDP) path to it
    /// (no endpoint advertised, or no connection could be made lately);
    /// none when there is one.  It is still a member, for discovery.
    pub no_quic_path: Option<String>,
    /// The filter of the layers it told, when it told one
    pub filter: Option<PeerFilter>,
    /// The layers this node believes it has (it served them lately), and
    /// lacks (it did not when asked lately)
    pub believed_has: u64,
    pub believed_lacks: u64,
    /// What its certificate says of it, when the swarm has an authority
    pub certificate: Option<Certificate>,
    /// What the pulls of this node fetched from it
    pub traffic: Option<PeerTraffic>,
}

/// The filter of the layers a peer told this node.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, introspect::CustomType)]
pub struct PeerFilter {
    /// The layers it says it put in it, its bytes and its version
    pub keys: u64,
    pub bytes: u64,
    pub version: u64,
    /// The rate at which it says maybe to a layer that is not in it, from
    /// its fill (not from what the peer says)
    pub estimated_fpr: f64,
    /// Seconds since its last update
    pub age_secs: u64,
    /// Whether it is believed: not refused, not expired and not wrong most
    /// of the time it said maybe
    pub believed: bool,
    /// Whether an update of the peer is missing from it (lost, late, or of
    /// another run of the peer): it then says "maybe" or nothing, no "no",
    /// till the peer's next whole filter
    pub behind: bool,
    /// Peers asked after it said maybe that held the layer, and that did not
    pub hits: u64,
    pub false_positives: u64,
    /// Its updates that were refused, and why the last was
    pub refused: u64,
    pub last_refused: Option<String>,
}

/// What a node tells the peers of the layers it holds: a filter (unless
/// `advertise_layers` is off), and with `announce_images` its images and
/// provider records of the DHT.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, introspect::Type)]
pub struct Advertised {
    /// Whether it tells the peers its images and the DHT its layers
    /// (`announce_images`)
    pub announcing: bool,
    /// Whether it tells the peers the filter of its layers
    pub filter: bool,
    /// The layers in the filter
    pub layers: u64,
    /// The filter: its bytes, hashes and version, and the rate at which it
    /// says maybe to a layer that is not in it, from its fill
    pub filter_bytes: u64,
    pub filter_hashes: u64,
    pub filter_version: u64,
    pub estimated_fpr: f64,
    /// What it sent the peers of it: whole filters, deltas, and their bytes
    /// (a message to each peer counts once)
    pub fulls_sent: u64,
    pub deltas_sent: u64,
    pub bytes_sent: u64,
    /// The images it tells
    pub images: u64,
    /// The provider records of the DHT it has published
    pub dht_records: u64,
}

/// The requests answered at a time, and the most.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, introspect::CustomType)]
pub struct Slots {
    pub used: u64,
    pub total: u64,
}

/// What the node is serving and has admitted.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, introspect::Type)]
pub struct Serving {
    /// The requests being answered over QUIC, and the most at a time
    pub quic_slots: Slots,
    /// The upload limit in bytes a second (0: none), and who waits for its
    /// credit
    pub upload_bytes_per_sec: u64,
    pub upload_waiting_callers: u64,
    pub upload_waiting_requests: u64,
}

/// What this node believes of a layer and a peer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, introspect::CustomType)]
pub struct Belief {
    pub layer: String,
    pub peer_id: String,
    /// The peer has the layer (it served it lately); else it lacks it (it
    /// did not when asked lately)
    pub has: bool,
    /// How long ago that was learnt, in seconds
    pub age_secs: u64,
}

/// A reply of `BeliefList`: a belief, none in the only reply of an empty
/// list.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, introspect::Type)]
pub struct BeliefListed {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub belief: Option<Belief>,
}

/// One thing a pull did when it asked the peers.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, introspect::CustomType)]
pub struct Step {
    /// `candidate` (a peer to ask, in order), `filters` (what the filters
    /// of the connected peers said of the layer: maybe, no, none), `probe`
    /// (what a peer with no filter said when asked whether it has the
    /// chunk), `striped` (a peer the group is spread over), `asked` (what
    /// a request to it came to) or `unsent` (what was left to the next
    /// source)
    pub what: String,
    pub peer_id: Option<String>,
    /// Why it is a candidate, what it answered, the outcome of the
    /// request, or why what is left was not given
    pub detail: String,
    pub took_ms: Option<f64>,
    /// The chunks the request gave, or the chunks left
    pub chunks: Option<u64>,
    pub bytes: Option<u64>,
}

/// A call that asked the peers for something, and what came of it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, introspect::CustomType)]
pub struct Decision {
    /// Its number, in the order the node made them
    pub id: u64,
    /// When, as seconds since the epoch
    pub at: u64,
    /// `chunks`, `index` or `profile`
    pub kind: String,
    /// The layer the chunks belong to, when it was named
    pub layer: Option<String>,
    /// The first digest asked for
    pub first: String,
    /// The chunks asked for
    pub items: u64,
    pub steps: Vec<Step>,
    /// Steps that did not fit in the record
    pub dropped: u64,
    /// What came of it in a line
    pub summary: String,
}

/// A reply of `Explain`: a decision, none in the only reply of an empty
/// list.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, introspect::Type)]
pub struct DecisionListed {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision: Option<Decision>,
}

/// A reply of `PeerList`: a peer, none in the only reply of an empty list.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, introspect::Type)]
pub struct PeerListed {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peer: Option<Peer>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, introspect::Type)]
pub struct Stats {
    /// The chunks, indexes and profiles the node served over QUIC
    pub chunks_sent: u64,
    /// The bytes of its answers
    pub bytes_sent: u64,
}

/// An image of another node
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, introspect::CustomType)]
pub struct RemoteImage {
    /// The node that has it
    pub peer_id: String,
    /// The image, as the store service of that node tells it
    pub image: ImageInfo,
}

/// A reply of `ImageList`: an image, none in the only reply of an empty
/// list.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, introspect::Type)]
pub struct ImageListed {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image: Option<RemoteImage>,
}

/// Why a call failed.
#[derive(Debug, Clone, PartialEq, zlink::ReplyError, introspect::ReplyError)]
#[zlink(interface = "org.velarx.P2p")]
pub enum P2pError {
    /// A call the service does not take (a list called without `more`)
    InvalidArgument { reason: String },
    /// The service cannot answer now (it is not connected to its network)
    Unavailable { reason: String },
}

impl std::fmt::Display for P2pError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidArgument { reason } => write!(f, "invalid argument: {reason}"),
            Self::Unavailable { reason } => write!(f, "unavailable: {reason}"),
        }
    }
}

impl std::error::Error for P2pError {}

/// The calls of the service, as a client makes them.
#[proxy("org.velarx.P2p")]
pub trait P2pProxy {
    async fn get_info(&mut self) -> zlink::Result<Result<Info, P2pError>>;
    async fn status(&mut self) -> zlink::Result<Result<Status, P2pError>>;
    #[zlink(more)]
    async fn peer_list(
        &mut self,
    ) -> zlink::Result<impl futures::Stream<Item = zlink::Result<Result<PeerListed, P2pError>>>>;
    async fn stats(&mut self) -> zlink::Result<Result<Stats, P2pError>>;
    async fn advertised(&mut self) -> zlink::Result<Result<Advertised, P2pError>>;
    async fn serving(&mut self) -> zlink::Result<Result<Serving, P2pError>>;
    #[zlink(more)]
    async fn belief_list(
        &mut self,
        layer: Option<&str>,
    ) -> zlink::Result<impl futures::Stream<Item = zlink::Result<Result<BeliefListed, P2pError>>>>;
    #[zlink(more)]
    async fn explain(
        &mut self,
        target: &str,
    ) -> zlink::Result<impl futures::Stream<Item = zlink::Result<Result<DecisionListed, P2pError>>>>;
    #[zlink(more)]
    async fn image_list(
        &mut self,
        query: bool,
    ) -> zlink::Result<impl futures::Stream<Item = zlink::Result<Result<ImageListed, P2pError>>>>;
}

#[derive(Error, Debug)]
pub enum P2pClientError {
    #[error("the service does not answer on {}", .socket.display())]
    Unreachable {
        socket: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("{0}")]
    Service(#[from] P2pError),
    #[error("{0}")]
    Protocol(String),
}

pub type P2pClientResult<T> = Result<T, P2pClientError>;

fn protocol(e: zlink::Error) -> P2pClientError {
    P2pClientError::Protocol(e.to_string())
}

/// A client of the service on `socket`: one connection for each call, its
/// `GetInfo` checked first.
#[derive(Debug, Clone)]
pub struct P2pClient {
    socket: PathBuf,
}

/// A connection to the service, its `GetInfo` checked.
macro_rules! connected {
    ($self:ident) => {{
        let mut conn = velarx_content::activation::connect(&$self.socket)
            .await
            .map_err(|source| P2pClientError::Unreachable {
                socket: $self.socket.clone(),
                source,
            })?;
        let info = conn
            .get_info()
            .await
            .map_err(protocol)?
            .map_err(P2pClientError::Service)?;
        velarx_proto::info::check("org.velarx.P2p", &info, PROTO).map_err(|e| {
            P2pClientError::Protocol(format!("the service on {}: {e}", $self.socket.display()))
        })?;
        conn
    }};
}

macro_rules! call {
    ($self:ident . $method:ident ( $($arg:expr),* )) => {{
        let mut conn = connected!($self);
        conn.$method($($arg),*)
            .await
            .map_err(protocol)?
            .map_err(P2pClientError::Service)
    }};
}

/// The records of a list call, all of them.
macro_rules! list {
    ($self:ident . $method:ident ( $($arg:expr),* ), $field:ident) => {{
        use futures::StreamExt;
        let mut conn = connected!($self);
        let replies = conn.$method($($arg),*).await.map_err(protocol)?;
        futures::pin_mut!(replies);
        let mut out = Vec::new();
        while let Some(reply) = replies.next().await {
            out.extend(reply.map_err(protocol)?.map_err(P2pClientError::Service)?.$field);
        }
        Ok(out)
    }};
}

impl P2pClient {
    pub fn new(socket: &Path) -> Self {
        Self {
            socket: socket.to_path_buf(),
        }
    }

    pub async fn status(&self) -> P2pClientResult<Status> {
        call!(self.status())
    }

    pub async fn peers(&self) -> P2pClientResult<Vec<Peer>> {
        list!(self.peer_list(), peer)
    }

    pub async fn stats(&self) -> P2pClientResult<Stats> {
        call!(self.stats())
    }

    pub async fn advertised(&self) -> P2pClientResult<Advertised> {
        call!(self.advertised())
    }

    pub async fn serving(&self) -> P2pClientResult<Serving> {
        call!(self.serving())
    }

    /// What the node believes of the layers and the peers (of `layer` only,
    /// when given).
    pub async fn beliefs(&self, layer: Option<&str>) -> P2pClientResult<Vec<Belief>> {
        list!(self.belief_list(layer), belief)
    }

    /// Why the pulls asked the peers they did: the recent decisions about
    /// `target` (a digest, or the start of one; an image's layers are given
    /// by the caller), the last first; all when `target` is empty.
    pub async fn explain(&self, target: &str) -> P2pClientResult<Vec<Decision>> {
        list!(self.explain(target), decision)
    }

    /// Images of the other nodes; asks them to refresh first when `query`.
    pub async fn remote_images(&self, query: bool) -> P2pClientResult<Vec<RemoteImage>> {
        list!(self.image_list(query), image)
    }
}

/// The decisions as text for a reader: for each, what was asked, the peers
/// considered and why, what they answered, and what was left to the next
/// source.
pub fn render_decisions(decisions: &[Decision]) -> String {
    use std::fmt::Write;
    let short = |s: &str| s.chars().take(23).collect::<String>();
    let who = |s: &Option<String>| {
        s.as_deref().map_or(String::new(), |p| {
            p.chars()
                .rev()
                .take(8)
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .collect()
        })
    };
    let mut out = String::new();
    if decisions.is_empty() {
        out.push_str("no pull has asked the peers for that\n");
    }
    for d in decisions {
        let _ = writeln!(
            out,
            "decision {}: {} of {} ({} asked){}",
            d.id,
            d.kind,
            short(&d.first),
            d.items,
            d.layer
                .as_deref()
                .map_or(String::new(), |l| format!(", layer {}", short(l)))
        );
        for s in &d.steps {
            let mut line = format!("    {:<9}", s.what);
            if s.peer_id.is_some() {
                let _ = write!(line, " ...{}", who(&s.peer_id));
            }
            let _ = write!(line, " {}", s.detail);
            if let Some(n) = s.chunks {
                let _ = write!(line, ", {n} chunks");
            }
            if let Some(b) = s.bytes {
                let _ = write!(line, ", {b} bytes");
            }
            if let Some(ms) = s.took_ms {
                let _ = write!(line, ", {ms} ms");
            }
            out.push_str(line.trim_end());
            out.push('\n');
        }
        if d.dropped > 0 {
            let _ = writeln!(out, "    ({} more steps not kept)", d.dropped);
        }
        let _ = writeln!(out, "  => {}", d.summary);
    }
    out
}

/// Write a new private network (swarm) key, as `velarx-p2p generate-key`
/// does: readable by its owner only, and an existing file is never replaced.
pub fn generate_swarm_key(path: &Path) -> io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    let mut key = [0u8; 32];
    rustix::rand::getrandom(&mut key, rustix::rand::GetRandomFlags::empty())?;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    write!(
        file,
        "/key/swarm/psk/1.0.0/\n/base16/\n{}",
        hex::encode(key)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn step(what: &str, peer: Option<&str>, detail: &str) -> Step {
        Step {
            what: what.into(),
            peer_id: peer.map(Into::into),
            detail: detail.into(),
            took_ms: None,
            chunks: None,
            bytes: None,
        }
    }

    #[test]
    fn the_decisions_read_as_what_was_asked_who_was_considered_and_what_was_left() {
        let mut asked = step("asked", Some("12D3KooWabcdefgh"), "sent");
        asked.chunks = Some(4);
        asked.bytes = Some(4096);
        asked.took_ms = Some(1.5);
        let d = Decision {
            id: 3,
            at: 0,
            kind: "chunks".into(),
            layer: Some("sha256:0123456789abcdef0123456789abcdef".into()),
            first: "sha256:fedcba9876543210fedcba9876543210".into(),
            items: 6,
            steps: vec![
                step("candidate", Some("12D3KooWabcdefgh"), "said-it-has-it"),
                asked,
                step("unsent", None, "the peers asked did not send all of it"),
            ],
            dropped: 0,
            summary: "2 of 6 left to the next source: the peers asked did not send all of it"
                .into(),
        };
        let text = render_decisions(&[d]);
        assert!(
            text.starts_with("decision 3: chunks of sha256:fedcba9876543210"),
            "{text}"
        );
        assert!(
            text.contains("candidate ...abcdefgh said-it-has-it"),
            "{text}"
        );
        assert!(
            text.contains("asked     ...abcdefgh sent, 4 chunks, 4096 bytes, 1.5 ms"),
            "{text}"
        );
        assert!(text.contains("=> 2 of 6 left to the next source"), "{text}");
        assert_eq!(
            render_decisions(&[]),
            "no pull has asked the peers for that\n"
        );
    }
}
