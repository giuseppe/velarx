// SPDX-License-Identifier: Apache-2.0
//! The data between peers, over QUIC and nothing else: chunks, files, the
//! indexes of layers, startup profiles, and the question whether a peer has a
//! chunk.
//!
//! The control traffic of the swarm (gossip, the DHT, commands) stays on the
//! libp2p connections, which only the members of the swarm can make.  A peer
//! that cannot be connected to over UDP is a member and not a data peer
//! ([`NoPath`]): there is no other way to ask it for data.  The
//! QUIC endpoint has a certificate of its own, that the client does not check
//! (the chunks are named by their digests and checked by the one that asks),
//! so the swarm key is proved on each connection instead, by both ends: each
//! sends on a unidirectional stream of its own `SHQ2` and HMAC-SHA256, keyed
//! by a hash of the swarm key, of the TLS exporter of the connection (with
//! the label of its side).  The exporter is different for every connection,
//! so a proof cannot be replayed on another one and a man in the middle that
//! makes two connections cannot pass it on.  The server serves no request
//! before the client's proof, the client asks nothing before the server's:
//! a peer without the key learns neither content nor what is asked.  A wrong proof
//! closes the connection.
//!
//! In a swarm with a certificate authority ([`Auth::Authority`],
//! [`crate::authority`]) none of that applies: the handshake is mutual TLS,
//! both ends present the certificate of their node (for the key of its
//! libp2p identity), a peer without a valid one fails before any stream, and
//! the certificate of the peer at an address must be of the peer a libp2p
//! connection said was there ([`Quic::expect`]).
//! What QUIC gives over the TCP connection of libp2p: one handshake, many
//! streams that do not wait for each other, and no head-of-line blocking
//! when a packet is lost.  A connection is made as soon as the peer's
//! endpoint is known ([`Quic::warm`]) and kept while both ends live, so a
//! request is one round trip.
//!
//! A request is a bidirectional stream: an operation (u8), a count (u16),
//! that many algorithm bytes (1 for a sha256, 2 for a sha512) and then the
//! raw bytes of the digests (32 or 64 each), then for an index its largest
//! size (u64).  The server answers each digest in order with a
//! byte, 1 and a length (u64) and that many bytes, or 0 (not here), or 2
//! (no room in this answer: ask again), or 3 (the server could not read
//! its store).
//! * chunks ([`OP_CHUNKS`]): at most [`MAX_REQUEST_DIGESTS`].  What is sent is
//!   hashed as it is sent, and its last piece goes only when the whole chunk
//!   has its digest.  A chunk whose store file does not match it (or cannot
//!   be read) is answered 3 before its first piece; after it, the stream is
//!   reset with the code 3, and the peer takes that chunk and the rest of
//!   the answer for another peer.  After the first chunk, the answer holds at most
//!   [`MAX_RESPONSE_PAYLOAD`] bytes: the rest is answered with 2.
//! * the question whether a chunk is here ([`OP_PROBE`]): one digest, one byte
//!   back (1, 0, or 2: no room), no data and no credit; it has places of its
//!   own ([`Admission::probe_slot`]).
//! * the index of a layer ([`OP_INDEX`], [`velarx_content::pull::index`]): one digest,
//!   the layer's; not named by its own digest, the puller proves it.
//! * the startup profile of an image ([`OP_PROFILE`],
//!   [`velarx_content::fetcher::Kind::Profile`]): as an index, by the image's id as a
//!   digest, at most [`velarx_content::fetcher::fetch::PROFILE_MAX_BYTES`].
//!
//! Resources: connections, streams per connection and requests at the same
//! time are bounded, and what the server accepts to receive is small
//! (requests are); a peer that does not prove the swarm key, does not send
//! its request or does not read for [`Limits::grace`] is dropped.  The slot
//! of a request is taken before any file is opened.

use super::limits::{MAX_ITEM_BYTES, MAX_REQUEST_DIGESTS, MAX_RESPONSE_PAYLOAD};
use super::serve::{self, Admission, Caller, Serving, WAVE};
use crate::{ChunkProvider, Presence};
use quinn::{ClientConfig, Endpoint, ServerConfig, TransportConfig};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use sha2::{Digest as _, Sha256};
use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tracing::{debug, info, warn};
use velarx_storage::ChunkFile;
use velarx_types::digest::{Algorithm, Digest, Kind};

const ALPN: &[u8] = b"velarx-chunks/4";
const MAGIC: &[u8; 4] = b"SHQ2";
pub const OP_CHUNKS: u8 = 1;
pub const OP_INDEX: u8 = 2;
pub const OP_PROFILE: u8 = 3;
pub const OP_PROBE: u8 = 4;
const ABSENT: u8 = 0;
const HERE: u8 = 1;
const NO_ROOM: u8 = 2;
/// The server could not read its store: not the same as having no chunk.
const FAILED: u8 = 3;

/// What a peer answers when it could not read its store: the peer and the
/// connection work, the chunk is neither absent nor here.  The asker asks
/// another peer, does not take it for a miss, and keeps using QUIC.
#[derive(Debug)]
pub struct StoreFailed;

impl std::fmt::Display for StoreFailed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("the peer could not read its store")
    }
}

impl std::error::Error for StoreFailed {}

fn store_failure() -> io::Error {
    io::Error::other(StoreFailed)
}

/// Whether `e` is the answer of a peer that could not read its store (and
/// not a failure of QUIC).
pub fn store_failed(e: &io::Error) -> bool {
    e.get_ref().is_some_and(|inner| inner.is::<StoreFailed>())
}

/// The answer of a peer that had no room for any of the chunks asked: it
/// may have them, and QUIC worked.
#[derive(Debug)]
pub struct NoRoom;

impl std::fmt::Display for NoRoom {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("the peer has no room to answer")
    }
}

impl std::error::Error for NoRoom {}

/// Whether `e` is the answer of a peer that had no room for the chunks (and
/// not a failure of QUIC, nor an answer that it lacks them).
pub fn no_room(e: &io::Error) -> bool {
    e.get_ref().is_some_and(|inner| inner.is::<NoRoom>())
}

/// There is no QUIC path to the peer: no connection could be made to it (UDP
/// blocked, no endpoint there, a wrong proof), or the node may not dial it.
/// The peer is not asked for data until a new attempt, and the reason says
/// what an operator can look at.
#[derive(Debug)]
pub struct NoPath(pub String);

impl std::fmt::Display for NoPath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for NoPath {}

/// Why there is no QUIC path, when `e` says there is none (and not a failure
/// of a request over one).
pub fn no_path(e: &io::Error) -> Option<&str> {
    e.get_ref()
        .and_then(|inner| inner.downcast_ref::<NoPath>())
        .map(|n| n.0.as_str())
}

fn path_missing(why: String) -> io::Error {
    io::Error::other(NoPath(why))
}

/// The time to make a connection, and to get the server's proof.
const CONNECT: Duration = Duration::from_secs(3);

/// How long an address that could not be connected to is left alone: the
/// requests that wait for it, and the ones that come meanwhile, are told
/// at once (one attempt of [`CONNECT`] seconds, not one for each).
const RETRY_AFTER: Duration = Duration::from_secs(30);
const EXPORTER_LABEL: &[u8] = b"EXPORTER-velarx-chunks";
const CLIENT: &[u8] = b"client";
const SERVER: &[u8] = b"server";

/// What a node bounds in what it serves.
#[derive(Clone, Copy)]
pub struct Limits {
    /// Requests answered at the same time, for all peers.
    pub serving: usize,
    /// Connections open.
    pub connections: usize,
    /// Requests of one connection answered at the same time.
    pub streams_per_connection: usize,
    /// The time the client waits for a chunk; a request gets half of it to
    /// have a slot, and is told "no room" otherwise.
    pub idle: Duration,
    /// The time a peer gets to prove the swarm key, to send its request and
    /// to take each piece of an answer.
    pub grace: Duration,
    /// The window of a connection (bytes): what the node sends a peer that
    /// it has not acknowledged yet, at most, and what it lets a peer send it
    /// on one stream that it has not read yet (four times that on all the
    /// streams of a connection).  A connection moves a window a round trip.
    pub window: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            serving: 64,
            connections: 256,
            streams_per_connection: 8,
            idle: Duration::from_secs(30),
            grace: Duration::from_secs(10),
            window: 8 << 20,
        }
    }
}

impl Limits {
    /// The limits the settings name.
    pub fn of(serving: &Serving) -> Self {
        Self {
            serving: serving.quic_slots,
            connections: serving.quic_connections,
            window: serving.quic_window_mib << 20,
            ..Self::default()
        }
    }
}

/// How the endpoint knows who is a member: the swarm key (each end proves it
/// on the connection), or a certificate authority (mutual TLS in the
/// handshake, [`crate::authority`]).
#[derive(Clone)]
pub enum Auth {
    Key([u8; 32]),
    Authority(Arc<crate::authority::Authority>),
}

impl From<[u8; 32]> for Auth {
    fn from(key: [u8; 32]) -> Self {
        Auth::Key(key)
    }
}

impl From<Arc<crate::authority::Authority>> for Auth {
    fn from(authority: Arc<crate::authority::Authority>) -> Self {
        Auth::Authority(authority)
    }
}

/// The key of the proofs: a hash of the swarm key, so that the key itself is
/// not used for anything else.
pub fn auth_key(swarm_key: &str) -> [u8; 32] {
    Sha256::new()
        .chain_update(b"velarx-chunks/1 ")
        .chain_update(swarm_key.trim().as_bytes())
        .finalize()
        .into()
}

fn hmac(key: &[u8; 32], message: &[u8]) -> [u8; 32] {
    use hmac::{Hmac, KeyInit, Mac};
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(key)
        .unwrap_or_else(|_| unreachable!("an HMAC takes a key of any length"));
    mac.update(message);
    mac.finalize().into_bytes().into()
}

/// The proof of the side `side` of `connection`.
fn proof(key: &[u8; 32], connection: &quinn::Connection, side: &[u8]) -> io::Result<[u8; 32]> {
    let mut exporter = [0u8; 32];
    connection
        .export_keying_material(&mut exporter, EXPORTER_LABEL, side)
        .map_err(|_| io::Error::other("no TLS exporter"))?;
    Ok(hmac(key, &exporter))
}

fn same(a: &[u8; 32], b: &[u8; 32]) -> bool {
    a.iter().zip(b).fold(0, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn denied() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "the proof of the swarm key is wrong",
    )
}

/// Send our proof on a stream of our own.
async fn send_proof(
    connection: &quinn::Connection,
    key: &[u8; 32],
    side: &[u8],
    idle: Duration,
) -> io::Result<()> {
    let mut message = MAGIC.to_vec();
    message.extend_from_slice(&proof(key, connection, side)?);
    let mut send = tokio::time::timeout(idle, connection.open_uni())
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "QUIC proof"))?
        .map_err(other)?;
    write(&mut send, &message, idle).await?;
    send.finish().map_err(other)
}

/// Check the proof of the other side, `side`, within `idle`.
async fn check_proof(
    connection: &quinn::Connection,
    key: &[u8; 32],
    side: &[u8],
    idle: Duration,
) -> io::Result<()> {
    let expected = proof(key, connection, side)?;
    let mut recv = tokio::time::timeout(idle, connection.accept_uni())
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "no QUIC proof"))?
        .map_err(other)?;
    let mut message = [0u8; 36];
    read(&mut recv, &mut message, idle).await?;
    let mut given = [0u8; 32];
    given.copy_from_slice(&message[4..]);
    if &message[..4] != MAGIC || !same(&given, &expected) {
        return Err(denied());
    }
    Ok(())
}

/// What the node serves chunks from; set when the service is ready.
pub type SharedProvider = Arc<OnceLock<Arc<dyn ChunkProvider>>>;

/// A connection to a peer, made once at a time.
type Slot = Arc<tokio::sync::Mutex<Option<quinn::Connection>>>;

pub struct Quic {
    endpoint: Endpoint,
    port: u16,
    /// The address the endpoint was bound to
    addr: SocketAddr,
    connections: Mutex<HashMap<SocketAddr, Slot>>,
    /// The addresses no connection could be made to, when and why
    unreachable: Mutex<HashMap<SocketAddr, (tokio::time::Instant, String)>>,
    served: Arc<std::sync::atomic::AtomicU64>,
    /// The bytes of chunks read from the peers so far, as they come
    received: Arc<std::sync::atomic::AtomicU64>,
    /// The requests the server answers at the same time, and its slots
    slots: Arc<Semaphore>,
    serving: usize,
    auth: Auth,
    /// The peer a libp2p connection says is at an address: the certificate
    /// there must be its
    expected: Mutex<HashMap<SocketAddr, libp2p::PeerId>>,
    idle: Duration,
    /// Where the node may connect to
    dial: Arc<crate::dial_filter::DialFilter>,
    #[cfg(test)]
    held: Arc<Held>,
}

/// The bytes of chunks the server has read from its store and not yet
/// written to their streams: now, at the most, and the pieces written (what
/// the upload limit bounds; measured by the tests).
#[cfg(test)]
struct Held {
    now: std::sync::atomic::AtomicU64,
    most: std::sync::atomic::AtomicU64,
    written: tokio::sync::watch::Sender<u64>,
}

#[cfg(test)]
impl Default for Held {
    fn default() -> Self {
        Self {
            now: Default::default(),
            most: Default::default(),
            written: tokio::sync::watch::channel(0).0,
        }
    }
}

#[cfg(test)]
impl Held {
    fn read(&self, n: u64) {
        use std::sync::atomic::Ordering::SeqCst;
        let now = self.now.fetch_add(n, SeqCst) + n;
        self.most.fetch_max(now, SeqCst);
    }

    fn written(&self, n: u64) {
        self.now.fetch_sub(n, std::sync::atomic::Ordering::SeqCst);
        self.written.send_modify(|w| *w += 1);
    }
}

fn other<E: std::fmt::Display>(e: E) -> io::Error {
    io::Error::other(e.to_string())
}

/// The byte that says what a digest on the wire is: its algorithm (1 for
/// SHA-256, 2 for SHA-512), and with the bit [`FSVERITY`] set the fs-verity
/// digest (blocks of 4096 bytes) of a file in that algorithm, the name of an
/// object, which is a different digest than the hash of the same bytes.
fn digest_byte(d: &Digest) -> io::Result<u8> {
    let alg = match d.alg() {
        Algorithm::Sha256 => 1,
        Algorithm::Sha512 => 2,
    };
    match d.kind() {
        Kind::Content(_) => Ok(alg),
        Kind::FsVerity { log_block: 12, .. } => Ok(alg | FSVERITY),
        Kind::FsVerity { .. } => Err(io::ErrorKind::InvalidInput.into()),
    }
}

/// The bit of the byte of a digest that says it is an fs-verity digest.
const FSVERITY: u8 = 0x80;

fn kind_of(byte: u8) -> io::Result<Kind> {
    let alg = match byte & !FSVERITY {
        1 => Algorithm::Sha256,
        2 => Algorithm::Sha512,
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "an unknown digest algorithm",
            ))
        }
    };
    Ok(match byte & FSVERITY {
        0 => Kind::Content(alg),
        _ => Kind::FsVerity { alg, log_block: 12 },
    })
}

/// The digests as they cross: the byte of each, then the raw bytes of each.
/// A digest is a hash of content or an fs-verity digest, as the text says
/// ([`Digest::parse_key`]).
fn digests_wire<'a>(digests: impl Iterator<Item = &'a str> + Clone) -> io::Result<Vec<u8>> {
    let parsed: Vec<Digest> = digests
        .map(|d| Digest::parse_key(d).map_err(|_| io::ErrorKind::InvalidInput))
        .collect::<Result<_, _>>()?;
    let mut out: Vec<u8> = parsed.iter().map(digest_byte).collect::<io::Result<_>>()?;
    for d in &parsed {
        out.extend_from_slice(d.raw());
    }
    Ok(out)
}

/// The number of digests the head of a request (its operation, then the
/// count, big endian) says it carries: one at least, at most
/// [`MAX_REQUEST_DIGESTS`].
fn digests_count(head: [u8; 3]) -> io::Result<usize> {
    let count = u16::from_be_bytes([head[1], head[2]]) as usize;
    if count == 0 || count > MAX_REQUEST_DIGESTS {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "too many digests",
        ));
    }
    Ok(count)
}

/// The kinds of the digests of a request, a byte each, and how many bytes
/// their raw digests take.
fn kinds_of(bytes: &[u8]) -> io::Result<(Vec<Kind>, usize)> {
    let kinds: Vec<Kind> = bytes
        .iter()
        .copied()
        .map(kind_of)
        .collect::<io::Result<_>>()?;
    let raw = kinds.iter().map(|k| k.alg().len()).sum();
    Ok((kinds, raw))
}

/// The digests of `kinds`, their bytes in `raw` (as long as [`kinds_of`]
/// says), as text.
fn digests_of(kinds: Vec<Kind>, raw: &[u8]) -> io::Result<Vec<String>> {
    let mut at = 0;
    kinds
        .into_iter()
        .map(|kind| {
            let n = kind.alg().len();
            let bytes = raw
                .get(at..at + n)
                .ok_or_else(|| io::Error::from(io::ErrorKind::UnexpectedEof))?;
            let d = Digest::with_kind(kind, bytes).map_err(other)?;
            at += n;
            Ok(d.to_string())
        })
        .collect()
}

/// The `count` digests a request carries, as text.
async fn read_digests(
    recv: &mut quinn::RecvStream,
    count: usize,
    idle: Duration,
) -> io::Result<Vec<String>> {
    let mut kinds = vec![0u8; count];
    read(recv, &mut kinds, idle).await?;
    let (kinds, len) = kinds_of(&kinds)?;
    let mut raw = vec![0u8; len];
    read(recv, &mut raw, idle).await?;
    digests_of(kinds, &raw)
}

/// The operation and the digests of a request as the server reads them
/// from its stream ([`digests_count`], [`kinds_of`], [`digests_of`]), from
/// the bytes `data`: what the fuzz target of the request runs
/// ([`crate::fuzzing`]).  Never more is allocated than `data` holds.
pub fn parse_request(data: &[u8]) -> io::Result<(u8, Vec<String>)> {
    let eof = || io::Error::from(io::ErrorKind::UnexpectedEof);
    let head: [u8; 3] = data.get(..3).ok_or_else(eof)?.try_into().map_err(other)?;
    let count = digests_count(head)?;
    let rest = &data[3..];
    let (kinds, len) = kinds_of(rest.get(..count).ok_or_else(eof)?)?;
    let raw = rest[count..].get(..len).ok_or_else(eof)?;
    Ok((head[0], digests_of(kinds, raw)?))
}

/// The answer to a request for chunks, read chunk by chunk.
pub struct Reply {
    _send: quinn::SendStream,
    recv: quinn::RecvStream,
    asked: Vec<(String, Option<u64>)>,
    next: usize,
    payload: u64,
    later: Vec<(String, Option<u64>)>,
    /// Whether the peer could not read its store for one of the chunks
    failed: bool,
    idle: Duration,
    received: Arc<std::sync::atomic::AtomicU64>,
}

impl Reply {
    /// The next chunk the peer has, with its bytes (not yet checked
    /// against its digest); `None` at the end.  A chunk of another size
    /// than the one asked is an error, before its bytes are read.  An
    /// answer the peer ended because its store failed while it sent a chunk
    /// ends there: that chunk and the rest are for another peer.
    pub async fn next(&mut self) -> io::Result<Option<(String, Vec<u8>)>> {
        match self.answered().await {
            Err(e) if store_failed(&e) => {
                self.failed = true;
                self.next = self.asked.len();
                Ok(None)
            }
            answered => answered,
        }
    }

    async fn answered(&mut self) -> io::Result<Option<(String, Vec<u8>)>> {
        while self.next < self.asked.len() {
            let (digest, size) = &self.asked[self.next];
            self.next += 1;
            let mut status = [0u8; 1];
            read(&mut self.recv, &mut status, self.idle).await?;
            match status[0] {
                ABSENT => continue,
                NO_ROOM => {
                    self.later.push((digest.clone(), *size));
                    continue;
                }
                HERE => {}
                // (that chunk is for another peer; the others still come)
                FAILED => {
                    self.failed = true;
                    continue;
                }
                _ => return Err(io::Error::new(io::ErrorKind::InvalidData, "a bad answer")),
            }
            let mut len = [0u8; 8];
            read(&mut self.recv, &mut len, self.idle).await?;
            let len = u64::from_be_bytes(len);
            if len > MAX_ITEM_BYTES as u64
                || size.is_some_and(|s| s != len)
                || (self.payload > 0 && self.payload + len > MAX_RESPONSE_PAYLOAD as u64)
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "a chunk of another size than the one asked, or too many bytes",
                ));
            }
            let mut data = vec![0u8; len as usize];
            for piece in data.chunks_mut(READ_PIECE) {
                read(&mut self.recv, piece, self.idle).await?;
                self.received
                    .fetch_add(piece.len() as u64, std::sync::atomic::Ordering::Relaxed);
            }
            self.payload += len;
            return Ok(Some((digest.clone(), data)));
        }
        Ok(None)
    }

    /// What the server had no room for in this answer, to ask for again.
    pub fn later(self) -> Vec<(String, Option<u64>)> {
        self.later
    }
}

impl Quic {
    /// Bind `addr` (port 0: any) and serve the chunks of `provider` to the
    /// peers that prove they know the swarm key `auth` ([`auth_key`]).
    #[cfg(test)]
    pub fn bind(
        addr: SocketAddr,
        provider: SharedProvider,
        auth: impl Into<Auth>,
    ) -> io::Result<Arc<Self>> {
        Self::bind_with(addr, provider, auth, Limits::default(), Arc::default())
    }

    /// [`Quic::bind`] with the limits and the admission of the node; the
    /// endpoint connects to any address its caller names.
    pub fn bind_with(
        addr: SocketAddr,
        provider: SharedProvider,
        auth: impl Into<Auth>,
        limits: Limits,
        admission: Arc<Admission>,
    ) -> io::Result<Arc<Self>> {
        let dial = Arc::new(crate::dial_filter::DialFilter::allow_all());
        Self::bind_filtered(addr, provider, auth, limits, admission, dial)
    }

    /// [`Quic::bind_with`], and the endpoint connects only where `dial`
    /// lets the node.
    pub fn bind_filtered(
        addr: SocketAddr,
        provider: SharedProvider,
        auth: impl Into<Auth>,
        limits: Limits,
        admission: Arc<Admission>,
        dial: Arc<crate::dial_filter::DialFilter>,
    ) -> io::Result<Arc<Self>> {
        let auth = auth.into();
        let builder = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(other)?;
        let mut crypto = match &auth {
            // (a certificate of its own that the client does not check: the
            // proofs are what authenticates)
            Auth::Key(_) => {
                let key = rcgen::generate_simple_self_signed(vec!["velarx".to_string()])
                    .map_err(other)?;
                let cert = key.cert.der().clone();
                let private =
                    PrivateKeyDer::from(PrivatePkcs8KeyDer::from(key.signing_key.serialize_der()));
                builder
                    .with_no_client_auth()
                    .with_single_cert(vec![cert], private)
                    .map_err(other)?
            }
            Auth::Authority(authority) => builder
                .with_client_cert_verifier(authority.verifier())
                .with_cert_resolver(authority.resolver()),
        };
        crypto.alpn_protocols = vec![ALPN.to_vec()];
        let mut server = ServerConfig::with_crypto(Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(crypto).map_err(other)?,
        ));
        server.transport_config(Arc::new(server_transport(&limits)));
        let mut endpoint = Endpoint::server(server, addr)?;

        let client = client_config(client_transport_of(&limits), &auth)?;
        endpoint.set_default_client_config(client);

        let addr = endpoint.local_addr()?;
        let port = addr.port();
        let this = Arc::new(Self {
            endpoint: endpoint.clone(),
            port,
            addr,
            connections: Mutex::new(HashMap::new()),
            unreachable: Mutex::default(),
            served: Arc::default(),
            slots: Arc::new(Semaphore::new(limits.serving)),
            serving: limits.serving,
            auth: auth.clone(),
            expected: Mutex::default(),
            idle: limits.idle,
            dial,
            received: Arc::default(),
            #[cfg(test)]
            held: Arc::default(),
        });
        let server = Arc::new(Server {
            provider,
            slots: this.slots.clone(),
            served: this.served.clone(),
            auth,
            limits,
            connections: Arc::new(Semaphore::new(limits.connections)),
            admission,
            #[cfg(test)]
            held: this.held.clone(),
        });
        tokio::spawn(async move {
            while let Some(incoming) = endpoint.accept().await {
                let ip = serve::prefix(incoming.remote_address().ip());
                let Some(admitted) = server.admit() else {
                    debug!("QUIC connection from {ip} refused: all places are taken");
                    incoming.refuse();
                    continue;
                };
                let server = server.clone();
                tokio::spawn(async move {
                    let _admitted = admitted;
                    let connection = match incoming.await {
                        Ok(connection) => connection,
                        Err(e) => {
                            debug!("QUIC handshake from {ip} failed: {e}");
                            return;
                        }
                    };
                    server.connection(connection, ip).await;
                });
            }
        });
        Ok(this)
    }

    /// The requests being answered, and the most at a time.
    pub fn slots(&self) -> (usize, usize) {
        (
            self.serving.saturating_sub(self.slots.available_permits()),
            self.serving,
        )
    }

    /// The chunks served so far.
    pub fn served(&self) -> u64 {
        self.served.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Stop serving and close the connections: the endpoint answers nothing
    /// more and lets go of its socket.
    pub fn close(&self) {
        self.endpoint.close(0u32.into(), b"shutdown");
    }

    /// The UDP port the endpoint listens on.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// The address the endpoint listens on.
    pub fn local_addr(&self) -> SocketAddr {
        self.addr
    }

    /// Ask the peer at `addr` for the chunks `digests` (with their sizes,
    /// when known): what it has comes in the order asked.
    pub async fn request(
        self: &Arc<Self>,
        addr: SocketAddr,
        digests: &[(String, Option<u64>)],
    ) -> io::Result<Reply> {
        if digests.is_empty() || digests.len() > MAX_REQUEST_DIGESTS {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let mut head = Vec::with_capacity(3 + digests.len() * 65);
        head.push(OP_CHUNKS);
        head.extend_from_slice(&(digests.len() as u16).to_be_bytes());
        head.extend_from_slice(&digests_wire(digests.iter().map(|(d, _)| d.as_str()))?);
        let (send, recv) = self.open(addr, &head).await?;
        Ok(Reply {
            _send: send,
            recv,
            asked: digests.to_vec(),
            next: 0,
            payload: 0,
            later: Vec::new(),
            failed: false,
            idle: self.idle,
            received: self.received.clone(),
        })
    }

    /// The bytes of chunks read from the peers so far, a piece at a time as
    /// they come (not only when an answer is complete).
    pub fn received(&self) -> u64 {
        self.received.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// The chunks `digests` the peer at `addr` has, with their bytes (not
    /// yet checked against their digests), in as many requests as it takes.
    /// A peer that could not read its store for any of them and sent none
    /// is an error ([`store_failed`]), not an answer without chunks; so is
    /// one that sent none and had no room for some ([`no_room`]).
    pub async fn fetch(
        self: &Arc<Self>,
        addr: SocketAddr,
        digests: &[(String, Option<u64>)],
    ) -> io::Result<Vec<(String, Vec<u8>)>> {
        if digests.is_empty() || digests.len() > MAX_REQUEST_DIGESTS {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let mut found = Vec::new();
        let mut asked = digests.to_vec();
        let (mut failed, mut busy) = (false, false);
        // an answer that brings nothing ends it
        while !asked.is_empty() {
            let before = found.len();
            let mut reply = self.request(addr, &asked).await?;
            while let Some(chunk) = reply.next().await? {
                found.push(chunk);
            }
            failed |= reply.failed;
            let later = reply.later();
            if found.len() == before {
                busy = !later.is_empty();
                break;
            }
            asked = later;
        }
        match (found.is_empty(), failed, busy) {
            (true, true, _) => Err(store_failure()),
            (true, false, true) => Err(io::Error::other(NoRoom)),
            _ => Ok(found),
        }
    }

    /// The index of the layer `layer` from the peer at `addr`, if it has
    /// one of at most `max` bytes.  Not checked: the puller proves it.
    pub async fn index(
        self: &Arc<Self>,
        addr: SocketAddr,
        layer: &str,
        max: u64,
    ) -> io::Result<Option<Vec<u8>>> {
        self.one(OP_INDEX, addr, layer, max.min(MAX_ITEM_BYTES as u64))
            .await
    }

    /// The startup profile of the image `image` (`sha256:` and its id) from
    /// the peer at `addr`, if it has one of at most `max` bytes.  Not
    /// checked: the asker uses it only as an order of files it checks.
    pub async fn profile(
        self: &Arc<Self>,
        addr: SocketAddr,
        image: &str,
        max: u64,
    ) -> io::Result<Option<Vec<u8>>> {
        self.one(
            OP_PROFILE,
            addr,
            image,
            max.min(velarx_content::fetcher::fetch::PROFILE_MAX_BYTES),
        )
        .await
    }

    /// The one item named by `digest` of the operation `op` (an index, a
    /// profile), at most `max` bytes.
    async fn one(
        self: &Arc<Self>,
        op: u8,
        addr: SocketAddr,
        layer: &str,
        max: u64,
    ) -> io::Result<Option<Vec<u8>>> {
        let mut head = vec![op, 0, 1];
        head.extend_from_slice(&digests_wire(std::iter::once(layer))?);
        head.extend_from_slice(&max.to_be_bytes());
        let (_send, mut recv) = self.open(addr, &head).await?;
        let mut status = [0u8; 1];
        read(&mut recv, &mut status, self.idle).await?;
        if status[0] == ABSENT {
            return Ok(None);
        }
        if status[0] == FAILED {
            return Err(store_failure());
        }
        // (it may have one: nothing is known of it)
        if status[0] == NO_ROOM {
            return Err(io::Error::other(NoRoom));
        }
        let mut len = [0u8; 8];
        read(&mut recv, &mut len, self.idle).await?;
        let len = u64::from_be_bytes(len);
        if status[0] != HERE || len == 0 || len > max {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "a bad index"));
        }
        let mut data = vec![0u8; len as usize];
        read(&mut recv, &mut data, self.idle).await?;
        Ok(Some(data))
    }

    /// Whether the peer at `addr` has the chunk `digest` (it would serve
    /// it): one short stream, one byte back.  A hint, not a proof.
    pub async fn has(self: &Arc<Self>, addr: SocketAddr, digest: &str) -> io::Result<Presence> {
        let mut head = vec![OP_PROBE, 0, 1];
        head.extend_from_slice(&digests_wire(std::iter::once(digest))?);
        let (_send, mut recv) = self.open(addr, &head).await?;
        let mut status = [0u8; 1];
        read(&mut recv, &mut status, self.idle).await?;
        match status[0] {
            HERE => Ok(Presence::Has),
            ABSENT => Ok(Presence::Lacks),
            NO_ROOM => Ok(Presence::Busy),
            FAILED => Err(store_failure()),
            _ => Err(io::Error::new(io::ErrorKind::InvalidData, "a bad answer")),
        }
    }

    /// A stream to the peer at `addr` with the request `head` sent; a
    /// connection that has gone is made again once.
    async fn open(
        self: &Arc<Self>,
        addr: SocketAddr,
        head: &[u8],
    ) -> io::Result<(quinn::SendStream, quinn::RecvStream)> {
        for attempt in 0..2 {
            let connection = self.connection(addr).await?;
            // (a peer that holds all the streams it allows, its requests
            // stuck, gives no place for another: that is no wait for ever)
            let opened = tokio::time::timeout(self.idle, async {
                let (mut send, recv) = connection.open_bi().await.map_err(other)?;
                write(&mut send, head, self.idle).await?;
                send.finish().map_err(other)?;
                Ok::<_, io::Error>((send, recv))
            })
            .await
            .unwrap_or_else(|_| Err(io::Error::new(io::ErrorKind::TimedOut, "QUIC open")));
            match opened {
                Ok(streams) => return Ok(streams),
                Err(e) if attempt == 0 && connection.close_reason().is_some() => {
                    debug!("QUIC connection to {addr} was closed: {e}");
                }
                Err(e) => return Err(e),
            }
        }
        Err(io::ErrorKind::ConnectionAborted.into())
    }

    /// Make the connection to the peer at `addr` now, so that the first
    /// request does not wait for it.
    pub fn warm(self: &Arc<Self>, addr: SocketAddr) {
        let this = self.clone();
        tokio::spawn(async move {
            // (a failed attempt is logged where it is made)
            let _ = this.connection(addr).await;
        });
    }

    /// Close the connection to the peer at `addr`, if there is one.
    pub fn forget(&self, addr: SocketAddr) {
        self.expected
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&addr);
        let slot = self
            .connections
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&addr);
        if let Some(slot) = slot {
            if let Ok(connection) = slot.try_lock() {
                if let Some(c) = connection.as_ref() {
                    c.close(0u32.into(), b"gone");
                }
            }
        }
    }

    /// The connection to `addr`, made (and both proofs exchanged) if there
    /// is none alive.
    async fn connection(self: &Arc<Self>, addr: SocketAddr) -> io::Result<quinn::Connection> {
        let slot = self
            .connections
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .entry(addr)
            .or_default()
            .clone();
        let mut slot = slot.lock_owned().await;
        if let Some(c) = slot.as_ref().filter(|c| c.close_reason().is_none()) {
            return Ok(c.clone());
        }
        // (told at once what the attempt of the one in front of this one
        // came to, or of a while ago)
        if let Some(why) = self.avoided(addr) {
            return Err(path_missing(why));
        }
        // The attempt is the node's, not the asker's: an asker that stops
        // waiting (a round of probes ends before `CONNECT`) does not cut it
        // short, so what it comes to is kept for the others, and a blocked
        // peer costs one attempt, not one for each round.
        let this = self.clone();
        tokio::spawn(async move {
            match this.connect(addr).await {
                Ok(connection) => {
                    this.unreachable
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .remove(&addr);
                    *slot = Some(connection.clone());
                    Ok(connection)
                }
                Err(e) => {
                    let why = e.to_string();
                    // (once an attempt: at most one an address in RETRY_AFTER)
                    info!(
                        "No QUIC (UDP) path to {addr}: {why}.  The peer is a member for \
                         discovery and is not asked for data"
                    );
                    // (what is past its time is forgotten, so the map holds
                    // only the addresses tried lately)
                    {
                        let mut unreachable =
                            this.unreachable.lock().unwrap_or_else(|e| e.into_inner());
                        unreachable.retain(|_, (at, _)| at.elapsed() < RETRY_AFTER);
                        unreachable.insert(addr, (tokio::time::Instant::now(), why.clone()));
                    }
                    Err(path_missing(why))
                }
            }
        })
        .await
        .map_err(other)?
    }

    /// Why no connection is made to `addr` now, when one failed lately, and
    /// when it is tried again.
    pub fn avoided(&self, addr: SocketAddr) -> Option<String> {
        let unreachable = self.unreachable.lock().unwrap_or_else(|e| e.into_inner());
        let (at, why) = unreachable.get(&addr)?;
        let left = RETRY_AFTER
            .checked_sub(at.elapsed())
            .filter(|left| !left.is_zero())?;
        Some(format!(
            "{why} ({} s ago; tried again in {} s)",
            at.elapsed().as_secs(),
            left.as_secs()
        ))
    }

    /// What the handshake proved of the peer at `addr`: it is the peer a
    /// libp2p connection said was there ([`Quic::expect`]).
    fn certified(
        &self,
        authority: &crate::authority::Authority,
        addr: SocketAddr,
        connection: &quinn::Connection,
    ) -> io::Result<()> {
        let who = authority
            .admitted_quic(connection)
            .map_err(|e| io::Error::new(io::ErrorKind::PermissionDenied, e.to_string()))?;
        let expected = self
            .expected
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&addr)
            .copied();
        match expected {
            Some(peer) if peer != who.peer_id => Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                crate::authority::Error::WrongPeer(Box::new((who.peer_id, peer))).to_string(),
            )),
            _ => Ok(()),
        }
    }

    /// The peer that is at `addr`, as the libp2p connection says: a QUIC
    /// connection there is made only to a node with its certificate.
    pub fn expect(&self, addr: SocketAddr, peer: libp2p::PeerId) {
        self.expected
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(addr, peer);
    }

    /// One attempt to connect to `addr`, and the proofs.
    async fn connect(&self, addr: SocketAddr) -> io::Result<quinn::Connection> {
        // (the same filter as the TCP transport's: where the node dials is
        // not for a peer to say)
        if let Err(refused) = self.dial.check_ip(addr.ip()) {
            return Err(io::Error::new(io::ErrorKind::PermissionDenied, refused));
        }
        let connecting = self.endpoint.connect(addr, "velarx").map_err(other)?;
        let connection = tokio::time::timeout(CONNECT, connecting)
            .await
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    "no answer over UDP (blocked, or no QUIC endpoint there)",
                )
            })?
            .map_err(other)?;
        let proved = match &self.auth {
            Auth::Key(key) => {
                async {
                    send_proof(&connection, key, CLIENT, CONNECT).await?;
                    check_proof(&connection, key, SERVER, CONNECT).await
                }
                .await
            }
            // (admitted by the handshake: the peer is the one expected)
            Auth::Authority(authority) => self.certified(authority, addr, &connection),
        };
        if let Err(e) = proved {
            // (the server may have checked this end's proof first, and
            // closed: that is a wrong proof too, not a lost connection)
            let refused = matches!(
                connection.close_reason(),
                Some(quinn::ConnectionError::ApplicationClosed(c)) if c.error_code == 1u32.into()
            );
            connection.close(1u32.into(), b"not a member of the swarm");
            return Err(match refused {
                true => io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "the proof of the swarm key is wrong (the peer refused it)",
                ),
                false => e,
            });
        }
        Ok(connection)
    }
}

/// What a client connects with: the certificates of the servers are not
/// checked (the digests and the proofs are).
fn client_config(transport: TransportConfig, auth: &Auth) -> io::Result<ClientConfig> {
    let builder = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .map_err(other)?
    .dangerous();
    let mut verify = match auth {
        Auth::Key(_) => builder
            .with_custom_certificate_verifier(Arc::new(AnyCert))
            .with_no_client_auth(),
        Auth::Authority(authority) => builder
            .with_custom_certificate_verifier(authority.verifier())
            .with_client_cert_resolver(authority.resolver()),
    };
    verify.alpn_protocols = vec![ALPN.to_vec()];
    let mut client = ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(verify).map_err(other)?,
    ));
    client.transport_config(Arc::new(transport));
    Ok(client)
}

/// What the client side of a connection accepts: the answers, large, and
/// the server's proof.
#[cfg(test)]
fn client_transport() -> TransportConfig {
    client_transport_of(&Limits::default())
}

fn client_transport_of(limits: &Limits) -> TransportConfig {
    let mut t = common_transport();
    t.max_concurrent_bidi_streams(0u32.into());
    t.max_concurrent_uni_streams(1u32.into());
    // what the peer may have sent that is not read yet, for each stream and
    // for all of them: the chunks of an answer are read as they come, a
    // window is the path's bandwidth times its delay (`Limits::window`)
    t.stream_receive_window(window(limits.window));
    t.receive_window(window(limits.window.saturating_mul(4)));
    // (the requests are a few bytes)
    t.send_window(64 << 10);
    t
}

/// What the server side accepts: the client's proof and its requests,
/// small.
fn server_transport(limits: &Limits) -> TransportConfig {
    let mut t = common_transport();
    let streams = u32::try_from(limits.streams_per_connection).unwrap_or(u32::MAX);
    t.max_concurrent_bidi_streams(streams.into());
    t.max_concurrent_uni_streams(1u32.into());
    t.receive_window((1u32 << 20).into());
    t.stream_receive_window((64u32 << 10).into());
    // What the node holds of a connection that does not take what it was
    // sent is what it sent and was not acknowledged: bounded here, whatever
    // window the peer advertises (at the default of quinn, 64 MiB for each
    // of 256 connections).  Also the bandwidth of a connection: a window a
    // round trip, with the default of 8 MiB 67 Gbit/s at 1 ms, 6.7 Gbit/s
    // at 10 ms (`quic_window_mib`).
    t.send_window(limits.window);
    t
}

/// A window of `bytes` as quinn takes it (the settings bound it far below
/// what it can hold).
fn window(bytes: u64) -> quinn::VarInt {
    quinn::VarInt::from_u64(bytes).unwrap_or(quinn::VarInt::MAX)
}

fn common_transport() -> TransportConfig {
    let mut t = TransportConfig::default();
    // a peer that acknowledges nothing for 6 s (stopped, paused, gone from
    // the network) loses its connection, and the requests on it fail then,
    // not after the 30 s a request waits for a byte; a live peer answers the
    // keep-alive pings even while it has no slot for a request
    t.max_idle_timeout(Some(Duration::from_secs(6).try_into().expect("a timeout")));
    t.keep_alive_interval(Some(Duration::from_secs(2)));
    // the congestion controller is quinn's default, Cubic: its BBR is 20
    // times slower on a 10 ms round trip without loss (measured)
    // (datagrams are not used: nothing is buffered for them, either way)
    t.datagram_receive_buffer_size(None);
    t.datagram_send_buffer_size(0);
    // jitter swaps neighbouring packets and a late packet is not a lost one:
    // a loss is told by time (2 round trips, the widest window of TCP's RACK)
    t.packet_threshold(1000);
    t.time_threshold(2.0);
    t
}

const READ_PIECE: usize = 1 << 20;

/// Fills `buf`; `idle` is for a piece of it, not for all of it (a slow seed
/// that keeps sending is not one that is silent).
async fn read(recv: &mut quinn::RecvStream, buf: &mut [u8], idle: Duration) -> io::Result<()> {
    for piece in buf.chunks_mut(READ_PIECE) {
        match tokio::time::timeout(idle, recv.read_exact(piece)).await {
            Err(_) => return Err(io::Error::new(io::ErrorKind::TimedOut, "QUIC read")),
            Ok(Ok(())) => {}
            // the store of the server failed while it answered
            Ok(Err(quinn::ReadExactError::ReadError(quinn::ReadError::Reset(code))))
                if code == quinn::VarInt::from(FAILED) =>
            {
                return Err(store_failure())
            }
            Ok(Err(e)) => return Err(other(e)),
        }
    }
    Ok(())
}

async fn write(send: &mut quinn::SendStream, buf: &[u8], idle: Duration) -> io::Result<()> {
    tokio::time::timeout(idle, send.write_all(buf))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "QUIC write"))?
        .map_err(other)
}

/// The state of the serving side.
struct Server {
    provider: SharedProvider,
    slots: Arc<Semaphore>,
    served: Arc<std::sync::atomic::AtomicU64>,
    auth: Auth,
    limits: Limits,
    connections: Arc<Semaphore>,
    /// What each address may ask for, and what all may take
    admission: Arc<Admission>,
    #[cfg(test)]
    held: Arc<Held>,
}

impl Server {
    /// The place of a connection among the connections; none when they are
    /// all taken.
    fn admit(&self) -> Option<OwnedSemaphorePermit> {
        self.connections.clone().try_acquire_owned().ok()
    }

    /// The proofs, then the streams of a connection from `ip` (its prefix),
    /// as long as the peer keeps it.
    async fn connection(self: &Arc<Self>, connection: quinn::Connection, ip: IpAddr) {
        let each = self.limits.grace;
        let proved = match &self.auth {
            Auth::Key(key) => {
                async {
                    send_proof(&connection, key, SERVER, each).await?;
                    check_proof(&connection, key, CLIENT, each).await
                }
                .await
            }
            // (admitted by the handshake)
            Auth::Authority(authority) => authority
                .admitted_quic(&connection)
                .map(|_| ())
                .map_err(|e| io::Error::new(io::ErrorKind::PermissionDenied, e.to_string())),
        };
        if let Err(e) = proved {
            debug!("QUIC connection from {}: {e}", connection.remote_address());
            connection.close(1u32.into(), b"not a member of the swarm");
            return;
        }
        let streams = Arc::new(Semaphore::new(self.limits.streams_per_connection));
        loop {
            let Ok(permit) = streams.clone().acquire_owned().await else {
                return;
            };
            // a connection that has gone (the peer's keep-alive stopped)
            // ends this
            let Ok((send, recv)) = connection.accept_bi().await else {
                return;
            };
            let server = self.clone();
            // (what is asked, the bytes and the wait for credit are
            // recorded when the request is known and answered)
            let span = tracing::debug_span!(
                "serve",
                what = tracing::field::Empty,
                digest = tracing::field::Empty,
                chunks = tracing::field::Empty,
                outcome = tracing::field::Empty,
                bytes = tracing::field::Empty,
                credit_ms = tracing::field::Empty,
            );
            tokio::spawn(tracing::Instrument::instrument(
                async move {
                    let _permit = permit;
                    let span = tracing::Span::current();
                    match server.serve(send, recv, ip).await {
                        Ok(()) => {
                            span.record("outcome", "answered");
                            debug!("answered");
                        }
                        Err(e) => {
                            span.record("outcome", "failed");
                            debug!("QUIC request from {ip}: {e}");
                        }
                    };
                },
                span,
            ));
        }
    }

    /// Answer the request of a stream.
    async fn serve(
        &self,
        mut send: quinn::SendStream,
        mut recv: quinn::RecvStream,
        ip: IpAddr,
    ) -> io::Result<()> {
        let idle = self.limits.grace;
        let invalid = |what: &str| io::Error::new(io::ErrorKind::InvalidData, what.to_string());
        let mut head = [0u8; 3];
        read(&mut recv, &mut head, idle).await?;
        let count = digests_count(head)?;
        let digests = read_digests(&mut recv, count, idle).await?;
        let span = tracing::Span::current();
        span.record(
            "what",
            match head[0] {
                OP_INDEX => "index",
                OP_PROFILE => "profile",
                OP_PROBE => "probe",
                _ => "chunks",
            },
        );
        span.record("digest", crate::limits::short(&digests[0]));
        span.record("chunks", digests.len());
        let provider = self
            .provider
            .get()
            .cloned()
            .ok_or_else(|| io::Error::other("no chunk provider"))?;
        let mut answer = Answer::new(&mut send, &self.admission, Caller::new(ip), &self.limits);
        match head[0] {
            OP_CHUNKS => {
                self.chunks(&mut answer, &provider, &digests).await?;
            }
            OP_PROBE if count == 1 => self.probe(&mut answer, &provider, &digests[0]).await?,
            OP_INDEX | OP_PROFILE if count == 1 => {
                let mut max = [0u8; 8];
                read(&mut recv, &mut max, idle).await?;
                let max = match head[0] {
                    OP_INDEX => u64::from_be_bytes(max).min(MAX_ITEM_BYTES as u64),
                    _ => u64::from_be_bytes(max)
                        .min(velarx_content::fetcher::fetch::PROFILE_MAX_BYTES),
                };
                self.index(&mut answer, &provider, head[0], &digests[0], max)
                    .await?
            }
            _ => return Err(invalid("not a request")),
        }
        let span = tracing::Span::current();
        span.record("bytes", answer.sent);
        span.record("credit_ms", answer.credit.as_millis() as u64);
        answer.end().await
    }

    /// Answer a question whether the chunk `digest` is here: one byte, the
    /// same two answers a request for the chunk gets, and no more digests
    /// than one (nothing a peer can list or search with).  It carries no data
    /// and waits for no credit: it has places of its own, so that requests
    /// that wait for the upload limit cannot make a node answer "no room" to
    /// the question whether it has a chunk.
    async fn probe(
        &self,
        answer: &mut Answer<'_>,
        provider: &Arc<dyn ChunkProvider>,
        digest: &str,
    ) -> io::Result<()> {
        let Some(_slot) = self.admission.probe_slot() else {
            return answer.write(&[NO_ROOM]).await;
        };
        let (p, d) = (provider.clone(), digest.to_string());
        let here = tokio::task::spawn_blocking(move || serve::has(p.as_ref(), &d))
            .await
            .map_err(other)?;
        match here {
            Ok(true) => answer.write(&[HERE]).await,
            Ok(false) => answer.write(&[ABSENT]).await,
            Err(e) => {
                warn!("QUIC: the store cannot tell whether it has a chunk: {e}");
                answer.write(&[FAILED]).await
            }
        }
    }

    /// Answer a request for an index or a profile (`op`).
    async fn index(
        &self,
        answer: &mut Answer<'_>,
        provider: &Arc<dyn ChunkProvider>,
        op: u8,
        layer: &str,
        max: u64,
    ) -> io::Result<()> {
        let idle = self.limits.idle;
        // (with no slot or no credit in time, the node has no
        // room: the asker is told so, not that there is no such index, which
        // it would remember)
        // (the slot is kept while the index is sent: it is held in memory
        // until the peer has taken it)
        let _slot;
        let index = {
            _slot = match tokio::time::timeout_at(answer.due(idle), self.slots.acquire()).await {
                Ok(slot) => slot.map_err(other)?,
                Err(_) => return answer.write(&[NO_ROOM]).await,
            };
            let (p, l) = (provider.clone(), layer.to_string());
            let index = tokio::task::spawn_blocking(move || match op {
                OP_PROFILE => p.get_profile(&l),
                _ => p.get_index(&l),
            })
            .await
            .map_err(other)?;
            match index {
                Ok(index) => Some(index.filter(|i| !i.is_empty() && i.len() as u64 <= max)),
                Err(e) => {
                    warn!("QUIC: the store cannot give an index: {e}");
                    return answer.write(&[FAILED]).await;
                }
            }
        };
        match index.flatten() {
            Some(index) => {
                // sent a piece at a time, each after its credit; the first
                // when the next byte is due, else there is no room
                let piece = self.admission.piece() as usize;
                let first_by = answer.due(idle);
                if !answer
                    .pace(index.len().min(piece) as u64, Some(first_by))
                    .await
                {
                    return answer.write(&[NO_ROOM]).await;
                }
                let mut head = Vec::with_capacity(9);
                head.push(HERE);
                head.extend_from_slice(&(index.len() as u64).to_be_bytes());
                answer.write(&head).await?;
                for (i, part) in index.chunks(piece).enumerate() {
                    if i > 0 {
                        answer.pace(part.len() as u64, None).await;
                    }
                    answer.write(part).await?;
                }
                Ok(())
            }
            None => answer.write(&[ABSENT]).await,
        }
    }

    /// Answer `digests`, wave by wave: the files of a wave are asked of
    /// the provider at once, under one slot.
    async fn chunks(
        &self,
        answer: &mut Answer<'_>,
        provider: &Arc<dyn ChunkProvider>,
        digests: &[String],
    ) -> io::Result<()> {
        let idle = self.limits.idle;
        let mut payload = 0u64;
        let mut full = false;
        for wave in digests.chunks(WAVE) {
            if full {
                answer.write(&vec![NO_ROOM; wave.len()]).await?;
                continue;
            }
            // the slot first: a file is opened only inside one.  No slot
            // when the next byte is due ([`Answer::due`]) is "no room" for
            // the rest (busy: the asker tries another peer), before the
            // client takes the silence for a failure of QUIC
            let slot = match tokio::time::timeout_at(answer.due(idle), self.slots.acquire()).await {
                Ok(slot) => slot.map_err(other)?,
                Err(_) => {
                    full = true;
                    answer.write(&vec![NO_ROOM; wave.len()]).await?;
                    continue;
                }
            };
            let opened = {
                let (p, w) = (provider.clone(), wave.to_vec());
                tokio::task::spawn_blocking(move || serve::open_wave(p.as_ref(), &w))
                    .await
                    .map_err(other)?
            };
            // (a provider that hands over files has none for what it lacks:
            // the bytes are asked of one that hands over none)
            let by_bytes = matches!(opened, Ok(None));
            let opened = match opened {
                Ok(Some(files)) => files.into_iter().map(Ok).collect::<Vec<_>>(),
                Ok(None) => wave.iter().map(|_| Ok(None)).collect(),
                Err(e) => {
                    warn!("QUIC: the store cannot open {} chunks: {e}", wave.len());
                    wave.iter().map(|_| Err(())).collect()
                }
            };
            for (digest, file) in wave.iter().zip(opened) {
                let sent = match file {
                    _ if full => Sent::No,
                    Ok(file) => {
                        self.chunk(
                            answer,
                            provider,
                            digest,
                            (file, by_bytes),
                            &mut payload,
                            &mut full,
                        )
                        .await?
                    }
                    Err(()) => Sent::Failed,
                };
                match sent {
                    Sent::Yes => {
                        self.served
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    }
                    Sent::No => answer.write(&[if full { NO_ROOM } else { ABSENT }]).await?,
                    Sent::Failed => answer.write(&[FAILED]).await?,
                }
            }
            drop(slot);
        }
        Ok(())
    }

    /// Send the chunk `digest` when it is there and fits the answer; whether
    /// it was sent, is not to be sent, or the store could not give it.  A
    /// chunk that does not fit, or whose first credit of the upload limit
    /// does not come in time, marks the answer `full`.
    ///
    /// The credit comes before the bytes are read, a piece at a time: what
    /// has been read is what may be sent.  A file is read, hashed and sent a
    /// piece at a time, once, and its last piece goes only when the whole
    /// chunk has its digest: a store file that does not (or that cannot be
    /// read) is never complete at the peer.  Before its first piece is sent
    /// it is answered "failed"; after, the stream is reset with that code:
    /// the peer drops the chunk and takes the rest of the answer for another
    /// peer, without taking this one for a liar or QUIC for broken.
    async fn chunk(
        &self,
        answer: &mut Answer<'_>,
        provider: &Arc<dyn ChunkProvider>,
        digest: &str,
        (file, by_bytes): (Option<ChunkFile>, bool),
        payload: &mut u64,
        full: &mut bool,
    ) -> io::Result<Sent> {
        // too large is absent, no room is for another answer
        let mut fits = |len: u64| {
            let room = *payload == 0 || *payload + len <= MAX_RESPONSE_PAYLOAD as u64;
            *full |= !room;
            room && len <= MAX_ITEM_BYTES as u64
        };
        let (len, source) = match file {
            Some(c) => {
                let Some(verifier) = serve::Verifier::new(digest) else {
                    return Ok(Sent::No);
                };
                let file = Arc::new(c.file);
                (
                    c.len,
                    Source::File(file, c.offset, Some(Box::new(verifier))),
                )
            }
            // not held by a provider that hands over files
            None if !by_bytes => return Ok(Sent::No),
            // a provider that hands over bytes, not a file: read to tell
            // their size, and checked
            None => {
                let (p, d) = (provider.clone(), digest.to_string());
                let data = tokio::task::spawn_blocking(move || serve::read_checked(p.as_ref(), &d))
                    .await
                    .map_err(other)?;
                match data {
                    Ok(Some(data)) => (data.len() as u64, Source::Bytes(data)),
                    Ok(None) => return Ok(Sent::No),
                    Err(e) => {
                        warn!("QUIC: the store cannot give {digest}: {e}");
                        return Ok(Sent::Failed);
                    }
                }
            }
        };
        // (an empty file has no piece to carry its head: it is absent)
        if len == 0 || !fits(len) {
            return Ok(Sent::No);
        }
        // The first credit, when the next byte is due (the time for the
        // slot counts too): past that it is "no room" (the asker tries
        // another peer), before the client takes the silence for a failure
        // of QUIC.
        let piece = self.admission.piece();
        let first_by = answer.due(self.limits.idle);
        if !answer.pace(len.min(piece), Some(first_by)).await {
            *full = true;
            return Ok(Sent::No);
        }
        let mut source = source;
        let mut at = 0;
        while at < len {
            let n = (len - at).min(piece);
            if at > 0 {
                answer.pace(n, None).await;
            }
            let read;
            let bytes: &[u8] = match &mut source {
                Source::Bytes(data) => &data[at as usize..(at + n) as usize],
                Source::File(file, offset, verifier) => {
                    let (f, offset) = (file.clone(), *offset + at);
                    let mut hashing = verifier.take().expect("a verifier");
                    let last = at + n == len;
                    let (got, hashed) = tokio::task::spawn_blocking(move || {
                        use std::os::unix::fs::FileExt;
                        let mut buf = vec![0u8; n as usize];
                        let got = f.read_exact_at(&mut buf, offset).map(|_| buf);
                        if let Ok(buf) = &got {
                            hashing.update(buf);
                        }
                        (got, hashing)
                    })
                    .await
                    .map_err(other)?;
                    let got = match got {
                        Ok(buf) if !last => {
                            *verifier = Some(hashed);
                            Ok(buf)
                        }
                        Ok(buf) if (*hashed).finish() => Ok(buf),
                        Ok(_) => Err(serve::corrupt(digest)),
                        Err(e) => Err(e),
                    };
                    read = match got {
                        Ok(buf) => {
                            #[cfg(test)]
                            self.held.read(n);
                            buf
                        }
                        Err(e) => {
                            warn!("QUIC: the store cannot give {digest}: {e}");
                            if at == 0 {
                                return Ok(Sent::Failed);
                            }
                            answer.store_failed();
                            return Err(e);
                        }
                    };
                    &read
                }
            };
            if at == 0 {
                let mut head = Vec::with_capacity(9);
                head.push(HERE);
                head.extend_from_slice(&len.to_be_bytes());
                answer.write(&head).await?;
            }
            answer.write(bytes).await?;
            #[cfg(test)]
            if matches!(source, Source::File(..)) {
                self.held.written(n);
            }
            at += n;
        }
        *payload += len;
        Ok(Sent::Yes)
    }
}

/// Where the bytes of a chunk being sent come from: a file of the store
/// (from an offset, hashed as it is read), or bytes the provider handed
/// over (checked).
enum Source {
    File(Arc<std::fs::File>, u64, Option<Box<serve::Verifier>>),
    Bytes(Vec<u8>),
}

/// The answer to one request as it is written: at the node's upload limit.
/// The time for a slot, the store or the credit of the upload limit is waited
/// for before a write; a peer that does not take a write in `grace` is left,
/// and the slot of the request is free.
struct Answer<'a> {
    send: &'a mut quinn::SendStream,
    admission: &'a Admission,
    who: Caller,
    grace: Duration,
    /// When the peer last had a byte of the answer (or sent its request)
    answered: tokio::time::Instant,
    /// The bytes written, and the time spent waiting for credit
    sent: u64,
    credit: Duration,
}

impl<'a> Answer<'a> {
    fn new(
        send: &'a mut quinn::SendStream,
        admission: &'a Admission,
        who: Caller,
        limits: &Limits,
    ) -> Self {
        Self {
            send,
            admission,
            who,
            grace: limits.grace,
            answered: tokio::time::Instant::now(),
            sent: 0,
            credit: Duration::ZERO,
        }
    }

    /// When what the server waits for before its next byte (a slot, the
    /// first credit of a chunk) must have come: half the time `idle` the
    /// peer waits for a byte, from the last one it had, so that it is told
    /// "no room" before it takes the silence for a failure of QUIC.
    fn due(&self, idle: Duration) -> tokio::time::Instant {
        self.answered + idle / 2
    }

    /// Wait for the credit to send `bytes`, before they are read; whether
    /// it came (its first piece by `first_by`, when given).
    async fn pace(&mut self, bytes: u64, first_by: Option<tokio::time::Instant>) -> bool {
        let start = tokio::time::Instant::now();
        let paced = self.admission.pace(&self.who, bytes, first_by).await;
        self.credit += start.elapsed();
        paced
    }

    /// The store failed while a chunk was being sent: the answer ends with
    /// a reset of the stream, with the code that says so.
    fn store_failed(&mut self) {
        let _ = self.send.reset(quinn::VarInt::from(FAILED));
    }

    /// Write `buf`, for which the credit was waited for.
    async fn write(&mut self, buf: &[u8]) -> io::Result<()> {
        self.sent += buf.len() as u64;
        let written = write(self.send, buf, self.grace).await;
        self.answered = tokio::time::Instant::now();
        written
    }

    /// The answer is complete: the peer takes what is still on its way in
    /// the time it has left (it reads everything before it closes the
    /// stream).
    async fn end(self) -> io::Result<()> {
        self.send.finish().map_err(other)?;
        let _ = tokio::time::timeout(self.grace, self.send.stopped()).await;
        Ok(())
    }
}

/// What became of a chunk the server was to send.
enum Sent {
    Yes,
    No,
    Failed,
}

/// Accepts any certificate: the chunks are checked against their digests.
#[derive(Debug)]
struct AnyCert;

impl rustls::client::danger::ServerCertVerifier for AnyCert {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::serve::Admission;

    const KEY: [u8; 32] = [7; 32];

    struct Chunks(HashMap<String, Vec<u8>>);

    impl ChunkProvider for Chunks {
        fn get_chunk(&self, digest: &str) -> std::io::Result<Option<Vec<u8>>> {
            Ok(self.0.get(digest).cloned())
        }
    }

    fn digest_of(data: &[u8]) -> String {
        velarx_types::digest::Digest::of(velarx_types::digest::Algorithm::Sha256, data).to_string()
    }

    #[tokio::test]
    async fn chunks_come_in_order_and_the_missing_are_left_out() {
        let (a, b) = (vec![1u8; 100_000], vec![2u8; 10]);
        let (da, db) = (digest_of(&a), digest_of(&b));
        let missing = digest_of(b"not there");
        let provider = served(Arc::new(Chunks(
            [(da.clone(), a.clone()), (db.clone(), b.clone())].into(),
        )));
        let server = Quic::bind("127.0.0.1:0".parse().unwrap(), provider, KEY).unwrap();
        let client = Quic::bind("127.0.0.1:0".parse().unwrap(), Arc::default(), KEY).unwrap();
        let addr: SocketAddr = ([127, 0, 0, 1], server.port()).into();
        let found = client
            .fetch(
                addr,
                &[(db.clone(), Some(10)), (missing, None), (da.clone(), None)],
            )
            .await
            .unwrap();
        assert_eq!(found, vec![(db.clone(), b), (da, a)]);
        // the same connection serves the next request
        let again = client
            .fetch(addr, &[(digest_of(&[2u8; 10]), None)])
            .await
            .unwrap();
        assert_eq!(again.len(), 1);
        // a chunk of another size than asked is refused unread
        assert!(client.fetch(addr, &[(db, Some(11))]).await.is_err());
    }

    /// The QUIC endpoint connects where the filter of the node lets it, as
    /// the TCP transport does: what a peer advertises is not enough.
    #[tokio::test]
    async fn a_connection_to_an_address_the_filter_refuses_is_not_made() {
        use crate::dial_filter::{DialFilter, Refusal, Rules};
        let digest = digest_of(b"x");
        let server = Quic::bind("127.0.0.1:0".parse().unwrap(), Arc::default(), KEY).unwrap();
        let counters = Arc::<crate::stats::Counters>::default();
        let bind = |rules| {
            Quic::bind_filtered(
                "127.0.0.1:0".parse().unwrap(),
                Arc::default(),
                KEY,
                Limits::default(),
                Arc::default(),
                Arc::new(DialFilter::with_own(
                    rules,
                    &[],
                    counters.clone(),
                    Box::new(Vec::new),
                )),
            )
            .unwrap()
        };
        let addr: SocketAddr = ([127, 0, 0, 1], server.port()).into();
        let strict = bind(Rules::default());
        let e = strict
            .fetch(addr, &[(digest.clone(), None)])
            .await
            .unwrap_err();
        assert!(
            no_path(&e).is_some_and(|why| why.contains(&Refusal::Loopback.to_string())),
            "{e}"
        );
        assert_eq!(counters.snapshot().dials_refused.loopback, 1);
        // (and warming a connection is the same dial)
        strict.warm(addr);
        // allowed, it connects: the server has no provider, which it says
        let open = bind(Rules::on_one_host());
        let e = open.fetch(addr, &[(digest, None)]).await.unwrap_err();
        assert!(no_path(&e).is_none(), "{e}");
    }

    #[tokio::test]
    async fn a_server_without_a_provider_or_a_bad_request_gives_nothing() {
        let server = Quic::bind("127.0.0.1:0".parse().unwrap(), Arc::default(), KEY).unwrap();
        let client = Quic::bind("127.0.0.1:0".parse().unwrap(), Arc::default(), KEY).unwrap();
        let addr: SocketAddr = ([127, 0, 0, 1], server.port()).into();
        assert!(client
            .fetch(addr, &[(digest_of(b"x"), None)])
            .await
            .is_err());
        assert!(client.fetch(addr, &[]).await.is_err());
        // nothing listens on this port
        let dead: SocketAddr = ([127, 0, 0, 1], 9).into();
        assert!(client
            .fetch(dead, &[(digest_of(b"x"), None)])
            .await
            .is_err());
    }

    fn bind_with(provider: SharedProvider, limits: Limits) -> (Arc<Quic>, SocketAddr) {
        let server = Quic::bind_with(
            "127.0.0.1:0".parse().unwrap(),
            provider,
            KEY,
            limits,
            Arc::default(),
        )
        .unwrap();
        let addr = ([127, 0, 0, 1], server.port()).into();
        (server, addr)
    }

    /// A slot with `provider` set.
    fn served(provider: Arc<dyn ChunkProvider>) -> SharedProvider {
        let slot = SharedProvider::default();
        assert!(slot.set(provider).is_ok());
        slot
    }

    fn chunks(items: &[Vec<u8>]) -> (SharedProvider, Vec<String>) {
        let map: HashMap<String, Vec<u8>> =
            items.iter().map(|d| (digest_of(d), d.clone())).collect();
        let digests = items.iter().map(|d| digest_of(d)).collect();
        (served(Arc::new(Chunks(map))), digests)
    }

    #[tokio::test]
    async fn a_peer_without_the_swarm_key_gets_nothing() {
        let (provider, digests) = chunks(&[vec![1u8; 1000]]);
        let (server, addr) = bind_with(provider, Limits::default());
        let stranger = Quic::bind("127.0.0.1:0".parse().unwrap(), Arc::default(), [8; 32]).unwrap();
        assert!(stranger
            .fetch(addr, &[(digests[0].clone(), None)])
            .await
            .is_err());
        assert_eq!(server.served(), 0);
        let member = Quic::bind("127.0.0.1:0".parse().unwrap(), Arc::default(), KEY).unwrap();
        assert_eq!(
            member
                .fetch(addr, &[(digests[0].clone(), None)])
                .await
                .unwrap()
                .len(),
            1
        );
    }

    use crate::authority::tests::{Node, Swarm};
    use crate::authority::Role;

    fn certified(node: &Node) -> Arc<Quic> {
        certified_serving(node, Arc::default())
    }

    fn certified_serving(node: &Node, provider: SharedProvider) -> Arc<Quic> {
        Quic::bind("127.0.0.1:0".parse().unwrap(), provider, node.authority()).unwrap()
    }

    #[tokio::test]
    async fn a_certificate_of_the_authority_is_what_admits_a_peer() {
        let swarm = Swarm::new();
        let (provider, digests) = chunks(&[vec![1u8; 1000]]);
        let server = certified_serving(&swarm.node("server", None, Role::Both), provider);
        let addr = server.local_addr();
        let asked = [(digests[0].clone(), None)];
        let member = certified(&swarm.node("member", Some("z"), Role::Both));
        assert_eq!(member.fetch(addr, &asked).await.unwrap().len(), 1);
        // (the server knows who it served, by the certificate)
        assert_eq!(server.served(), 1);
        // the swarm key is not a credential of an authority
        let keyed = Quic::bind("127.0.0.1:0".parse().unwrap(), Arc::default(), KEY).unwrap();
        assert!(keyed.fetch(addr, &asked).await.is_err());
        // nor is a certificate of another authority
        let other = certified(&Swarm::new().node("other", None, Role::Both));
        let err = other.fetch(addr, &asked).await.unwrap_err();
        assert!(no_path(&err).is_some(), "{err}");
        assert_eq!(server.served(), 1);
    }

    #[tokio::test]
    async fn a_node_with_an_authority_asks_nothing_of_a_server_with_the_key() {
        let swarm = Swarm::new();
        let (provider, digests) = chunks(&[vec![1u8; 1000]]);
        let (server, addr) = bind_with(provider, Limits::default());
        let member = certified(&swarm.node("member", None, Role::Both));
        assert!(member
            .fetch(addr, &[(digests[0].clone(), None)])
            .await
            .is_err());
        assert_eq!(server.served(), 0);
    }

    #[tokio::test]
    async fn the_role_of_a_certificate_says_who_asks_and_who_is_asked() {
        let swarm = Swarm::new();
        let (provider, digests) = chunks(&[vec![1u8; 1000]]);
        let asked = [(digests[0].clone(), None)];
        let seed = certified_serving(&swarm.node("seed", None, Role::Serve), provider.clone());
        let leech = certified_serving(&swarm.node("leech", None, Role::Pull), provider);
        let both = certified(&swarm.node("both", None, Role::Both));
        assert_eq!(
            both.fetch(seed.local_addr(), &asked).await.unwrap().len(),
            1
        );
        assert_eq!(
            leech.fetch(seed.local_addr(), &asked).await.unwrap().len(),
            1
        );
        // a seed does not ask, a node that only pulls is not asked
        assert!(seed.fetch(leech.local_addr(), &asked).await.is_err());
        assert!(both.fetch(leech.local_addr(), &asked).await.is_err());
        assert!(seed.fetch(both.local_addr(), &asked).await.is_err());
    }

    #[tokio::test]
    async fn the_peer_at_an_address_must_be_the_one_expected() {
        let swarm = Swarm::new();
        let (provider, digests) = chunks(&[vec![1u8; 1000]]);
        let asked = [(digests[0].clone(), None)];
        let server_node = swarm.node("server", None, Role::Both);
        let server = certified_serving(&server_node, provider);
        let client = certified(&swarm.node("client", None, Role::Both));
        client.expect(server.local_addr(), libp2p::PeerId::random());
        let err = client.fetch(server.local_addr(), &asked).await.unwrap_err();
        assert!(
            no_path(&err).is_some_and(|why| why.contains("not of")),
            "{err}"
        );
        client.forget(server.local_addr());
        assert!(client.expected.lock().unwrap().is_empty());
        let client = certified(&swarm.node("client2", None, Role::Both));
        client.expect(server.local_addr(), server_node.key.public().to_peer_id());
        assert_eq!(
            client
                .fetch(server.local_addr(), &asked)
                .await
                .unwrap()
                .len(),
            1
        );
    }

    #[tokio::test]
    async fn a_revoked_peer_is_cut_off_and_cannot_come_back() {
        let swarm = Swarm::new();
        let (provider, digests) = chunks(&[vec![1u8; 1000]]);
        let asked = [(digests[0].clone(), None)];
        let mut server_node = swarm.node("server", None, Role::Both);
        let revoked = swarm.dir.path().join("revoked");
        crate::ca::revoke(&swarm.ca(), &[]).unwrap();
        std::fs::copy(swarm.ca().join("revoked"), &revoked).unwrap();
        server_node.config.revocation_path = Some(revoked.clone());
        let authority = server_node.authority();
        let server =
            Quic::bind("127.0.0.1:0".parse().unwrap(), provider, authority.clone()).unwrap();
        let member = swarm.node("member", None, Role::Both);
        let client = certified(&member);
        assert_eq!(
            client
                .fetch(server.local_addr(), &asked)
                .await
                .unwrap()
                .len(),
            1
        );
        crate::ca::revoke(&swarm.ca(), &[member.key.public().to_peer_id()]).unwrap();
        std::fs::copy(swarm.ca().join("revoked"), &revoked).unwrap();
        let dropped = authority.sweep();
        assert_eq!(dropped.len(), 1);
        // (the connection was closed by the sweep, and a new one is refused)
        assert!(client.fetch(server.local_addr(), &asked).await.is_err());
        assert_eq!(server.served(), 1);
    }

    /// The proofs are HMAC-SHA256 as the crate computes it (a vector made
    /// with another implementation).
    #[test]
    fn the_proof_is_a_hmac_sha256() {
        let key: [u8; 32] = std::array::from_fn(|i| i as u8);
        assert_eq!(
            hex::encode(hmac(&key, b"exporter message")),
            "1ec4da4c789c5cf386057201d3b9d4952162fc54da505815d4a1de3b3e13f282"
        );
    }

    /// `chunks` chunks of 4 MiB, asked for in one request.
    fn big(chunks: u8) -> (SharedProvider, Vec<(String, Option<u64>)>) {
        let items: Vec<Vec<u8>> = (0..chunks).map(|i| vec![i; 4 << 20]).collect();
        let (provider, digests) = self::chunks(&items);
        (provider, digests.into_iter().map(|d| (d, None)).collect())
    }

    /// `n` requests of `asked` from a client that has a window of 64 KiB for
    /// each answer and reads the first bytes of each, and nothing more: the
    /// server is writing the rest and holds its slot.  What keeps them open.
    async fn stalled(
        addr: SocketAddr,
        asked: &[(String, Option<u64>)],
        n: usize,
    ) -> (Endpoint, quinn::Connection, Vec<quinn::RecvStream>) {
        let (endpoint, connection) = member(addr).await;
        let mut held = Vec::new();
        for _ in 0..n {
            let (mut send, mut recv) = connection.open_bi().await.unwrap();
            send.write_all(&chunks_request(asked)).await.unwrap();
            let mut first = [0u8; 9];
            recv.read_exact(&mut first).await.unwrap();
            assert_eq!(first[0], HERE);
            held.push(recv);
        }
        (endpoint, connection, held)
    }

    /// A member's connection to `addr` with a window of 64 KiB for each
    /// answer: what it does not read stays at the server.
    async fn member(addr: SocketAddr) -> (Endpoint, quinn::Connection) {
        let mut transport = client_transport();
        transport.stream_receive_window((64u32 << 10).into());
        let endpoint = Endpoint::client(([127, 0, 0, 1], 0).into()).unwrap();
        let connection = endpoint
            .connect_with(
                client_config(transport, &Auth::Key(KEY)).unwrap(),
                addr,
                "velarx",
            )
            .unwrap()
            .await
            .unwrap();
        send_proof(&connection, &KEY, CLIENT, CONNECT)
            .await
            .unwrap();
        check_proof(&connection, &KEY, SERVER, CONNECT)
            .await
            .unwrap();
        (endpoint, connection)
    }

    /// A UDP relay between a client and a server that stops passing on the
    /// packets of the server when it is told to: a peer whose packets are
    /// lost for good, and that acknowledges nothing the server sends.
    struct Relay {
        addr: SocketAddr,
        mute: Arc<std::sync::atomic::AtomicBool>,
        task: tokio::task::JoinHandle<()>,
    }

    impl Drop for Relay {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    async fn relay(server: SocketAddr) -> Relay {
        use std::sync::atomic::Ordering::Relaxed;
        let front = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let back = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        back.connect(server).await.unwrap();
        let addr = front.local_addr().unwrap();
        let mute = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let muted = mute.clone();
        let task = tokio::spawn(async move {
            let (mut up, mut down) = ([0u8; 65535], [0u8; 65535]);
            let mut client = None;
            loop {
                tokio::select! {
                    Ok((n, from)) = front.recv_from(&mut up) => {
                        client = Some(from);
                        let _ = back.send(&up[..n]).await;
                    }
                    Ok(n) = back.recv(&mut down) => {
                        if let (Some(client), false) = (client, muted.load(Relaxed)) {
                            let _ = front.send_to(&down[..n], client).await;
                        }
                    }
                }
            }
        });
        Relay { addr, mute, task }
    }

    /// What a node holds for a connection of a peer that advertises the
    /// largest windows and takes nothing (not even acknowledges) is what
    /// `Limits::window` allows, not what the peer's windows do: the peer asks
    /// for 16 MiB and gets 8 into the node's buffers, not all of it (at the
    /// default of quinn, 64 MiB for each connection).
    #[tokio::test]
    async fn what_a_peer_that_acknowledges_nothing_makes_the_server_hold_is_bounded() {
        let dir = tempfile::tempdir().unwrap();
        let data = vec![7u8; 1 << 20];
        let path = dir.path().join("chunk");
        std::fs::write(&path, &data).unwrap();
        let provider = served(Arc::new(OneFile(
            std::fs::File::open(&path).unwrap(),
            data.len() as u64,
        )));
        let (server, addr) = bind_with(provider, Limits::default());
        let relay = relay(addr).await;
        // (the windows of a client of the node: the largest it has)
        let mut transport = client_transport();
        transport.receive_window(u32::MAX.into());
        transport.stream_receive_window(u32::MAX.into());
        let endpoint = Endpoint::client(([127, 0, 0, 1], 0).into()).unwrap();
        let connection = endpoint
            .connect_with(
                client_config(transport, &Auth::Key(KEY)).unwrap(),
                relay.addr,
                "velarx",
            )
            .unwrap()
            .await
            .unwrap();
        send_proof(&connection, &KEY, CLIENT, CONNECT)
            .await
            .unwrap();
        check_proof(&connection, &KEY, SERVER, CONNECT)
            .await
            .unwrap();
        // from here on nothing of the server reaches it
        relay.mute.store(true, std::sync::atomic::Ordering::Relaxed);
        let mut written = server.held.written.subscribe();
        let (mut send, _recv) = connection.open_bi().await.unwrap();
        let digest = digest_of(&data);
        let asked: Vec<(String, Option<u64>)> = (0..16).map(|_| (digest.clone(), None)).collect();
        send.write_all(&chunks_request(&asked)).await.unwrap();
        // the node writes until its buffer is full: some pieces are written
        written.wait_for(|w| *w >= 4).await.unwrap();
        // and not the sixteen: the wait for them ends with the time
        let all = tokio::time::timeout(Duration::from_millis(500), written.wait_for(|w| *w >= 16))
            .await
            .is_ok();
        let pieces = *written.borrow();
        assert!(
            !all,
            "the node wrote all {pieces} MiB to a peer that took none"
        );
        let window = Limits::default().window;
        assert!(
            pieces << 20 <= window + (1 << 20),
            "{pieces} MiB written, the window is {} MiB",
            window >> 20
        );
    }

    fn chunks_request(asked: &[(String, Option<u64>)]) -> Vec<u8> {
        let mut head = vec![OP_CHUNKS];
        head.extend_from_slice(&(asked.len() as u16).to_be_bytes());
        head.extend_from_slice(&digests_wire(asked.iter().map(|(d, _)| d.as_str())).unwrap());
        head
    }

    #[tokio::test]
    async fn streams_that_make_no_progress_are_closed_and_free_their_slots() {
        let (provider, asked) = big(8);
        // (a second to wait for a slot that is twenty: a slot that is free
        // in time is free because the stream was closed for its rate)
        let limits = Limits {
            serving: 2,
            idle: Duration::from_secs(20),
            grace: Duration::from_millis(300),
            ..Limits::default()
        };
        let (_server, addr) = bind_with(provider, limits);
        let held = stalled(addr, &asked, 2).await;
        let other = Quic::bind("127.0.0.1:0".parse().unwrap(), Arc::default(), KEY).unwrap();
        let found = tokio::time::timeout(Duration::from_secs(10), other.fetch(addr, &asked[..1]))
            .await
            .expect("a slot was freed for the one that reads")
            .unwrap();
        assert_eq!(found.len(), 1);
        drop(held);
    }

    /// A request that finds no slot for half the time the client waits is
    /// answered "no room" (busy), not left to time out: a time out is a
    /// failure of QUIC, which makes the asker leave QUIC to the peer.  The
    /// 8 s the server says nothing are longer than the idle time of the
    /// connection, which the keep-alive pings keep.
    #[tokio::test]
    async fn a_request_with_no_slot_in_time_is_told_no_room() {
        let (provider, asked) = big(2);
        let limits = Limits {
            serving: 1,
            idle: Duration::from_secs(16),
            grace: Duration::from_secs(60),
            ..Limits::default()
        };
        let (_server, addr) = bind_with(provider, limits);
        // the only slot is held by an answer nobody reads
        let held = stalled(addr, &asked, 1).await;
        let other = Quic::bind("127.0.0.1:0".parse().unwrap(), Arc::default(), KEY).unwrap();
        let busy = tokio::time::timeout(Duration::from_secs(20), other.fetch(addr, &asked[..1]))
            .await
            .expect("answered, not left to the client's limit")
            .unwrap_err();
        assert!(no_room(&busy), "{busy}");
        drop(held);
    }

    /// A connection that makes the connection and proves nothing is dropped
    /// when the time for the proof is out, not when the connection is idle.
    #[tokio::test]
    async fn a_connection_that_proves_nothing_is_closed_when_the_proof_is_due() {
        let limits = Limits {
            idle: Duration::from_secs(60),
            grace: Duration::from_millis(300),
            ..Limits::default()
        };
        let (_server, addr) = bind_with(served(Arc::new(Panics)), limits);
        let stranger = Quic::bind("127.0.0.1:0".parse().unwrap(), Arc::default(), KEY).unwrap();
        let connection = stranger
            .endpoint
            .connect(addr, "velarx")
            .unwrap()
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(10), connection.closed())
            .await
            .expect("the server closes a connection that did not prove the key");
    }

    struct OneFile(std::fs::File, u64);

    impl ChunkProvider for OneFile {
        fn get_chunk(&self, _: &str) -> std::io::Result<Option<Vec<u8>>> {
            Ok(None)
        }
        fn open_chunks(&self, digests: &[String]) -> std::io::Result<Vec<Option<ChunkFile>>> {
            Ok(digests
                .iter()
                .map(|_| {
                    Some(ChunkFile {
                        file: self.0.try_clone().ok()?,
                        offset: 0,
                        len: self.1,
                    })
                })
                .collect())
        }
    }

    /// An empty file is answered as absent: the statuses of the chunks
    /// after it keep their places.
    #[tokio::test]
    async fn an_empty_chunk_does_not_shift_the_answers_after_it() {
        let (provider, d) = chunks(&[Vec::new(), b"after".to_vec()]);
        let (_server, addr) = bind_with(provider, Limits::default());
        let client = Quic::bind("127.0.0.1:0".parse().unwrap(), Arc::default(), KEY).unwrap();
        let found = client
            .fetch(addr, &[(d[0].clone(), None), (d[1].clone(), None)])
            .await
            .unwrap();
        assert_eq!(found, [(d[1].clone(), b"after".to_vec())]);
    }

    /// A provider that hands over files and has none of what is asked is not
    /// asked again for each digest, one by one.
    #[tokio::test]
    async fn what_a_provider_of_files_lacks_costs_no_second_lookup() {
        struct Nothing(std::sync::atomic::AtomicUsize);
        impl ChunkProvider for Nothing {
            fn get_chunk(&self, _: &str) -> std::io::Result<Option<Vec<u8>>> {
                self.0.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                Ok(None)
            }
            fn open_chunks(&self, d: &[String]) -> std::io::Result<Vec<Option<ChunkFile>>> {
                Ok(d.iter().map(|_| None).collect())
            }
        }
        let provider = Arc::new(Nothing(Default::default()));
        let (_server, addr) = bind_with(served(provider.clone()), Limits::default());
        let client = Quic::bind("127.0.0.1:0".parse().unwrap(), Arc::default(), KEY).unwrap();
        let asked: Vec<_> = (0..20u8).map(|i| (digest_of(&[i]), None)).collect();
        assert!(client.fetch(addr, &asked).await.unwrap().is_empty());
        assert_eq!(provider.0.load(std::sync::atomic::Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn a_file_that_does_not_match_its_digest_is_not_served() {
        let dir = tempfile::tempdir().unwrap();
        let good = vec![5u8; 3 << 20];
        let path = dir.path().join("chunk");
        std::fs::write(&path, &good).unwrap();
        let provider = |file: &std::path::Path, len| -> SharedProvider {
            served(Arc::new(OneFile(std::fs::File::open(file).unwrap(), len)))
        };
        let client = Quic::bind("127.0.0.1:0".parse().unwrap(), Arc::default(), KEY).unwrap();
        let (_s, addr) = bind_with(provider(&path, good.len() as u64), Limits::default());
        let found = client
            .fetch(addr, &[(digest_of(&good), None)])
            .await
            .unwrap();
        assert_eq!(found, vec![(digest_of(&good), good.clone())]);

        // A store file that does not hold the chunk: the asker is told
        // the store of the peer failed (it asks another peer, and keeps
        // the peer and QUIC: not "absent", not a broken stream), never gets
        // the bytes as the chunk, and the server serves nothing.  The last
        // piece is held back until the whole chunk is hashed, so the
        // damage in it is found before the chunk is complete at the peer.
        let mut bad = good.clone();
        bad[(3 << 20) - 1] ^= 1;
        std::fs::write(&path, &bad).unwrap();
        let (s, addr) = bind_with(provider(&path, bad.len() as u64), Limits::default());
        let failed = client
            .fetch(addr, &[(digest_of(&good), None)])
            .await
            .unwrap_err();
        assert!(store_failed(&failed), "{failed}");
        assert_eq!(s.served(), 0);
        // the same for a chunk of one piece, before any of it is sent; the
        // chunks after it are still answered
        let small = vec![6u8; 1000];
        let mut bad = small.clone();
        bad[999] ^= 1;
        std::fs::write(&path, &bad).unwrap();
        let (s, addr) = bind_with(provider(&path, bad.len() as u64), Limits::default());
        let mut reply = client
            .request(addr, &[(digest_of(&small), None), (digest_of(&bad), None)])
            .await
            .unwrap();
        assert_eq!(reply.next().await.unwrap(), Some((digest_of(&bad), bad)));
        assert!(reply.failed);
        assert_eq!(s.served(), 1);
    }

    #[tokio::test]
    async fn an_answer_holds_a_bounded_number_of_bytes() {
        let size = MAX_RESPONSE_PAYLOAD / 2 + 1;
        let items: Vec<Vec<u8>> = (0..3u8).map(|i| vec![i; size]).collect();
        let (provider, digests) = chunks(&items);
        let (_server, addr) = bind_with(provider, Limits::default());
        let client = Quic::bind("127.0.0.1:0".parse().unwrap(), Arc::default(), KEY).unwrap();
        let asked: Vec<(String, Option<u64>)> = digests.iter().map(|d| (d.clone(), None)).collect();
        let mut reply = client.request(addr, &asked).await.unwrap();
        assert!(reply.next().await.unwrap().is_some());
        assert!(reply.next().await.unwrap().is_none());
        assert_eq!(reply.later(), asked[1..].to_vec());
        // what had no room is asked for again
        let found = client.fetch(addr, &asked).await.unwrap();
        assert_eq!(found.len(), 3);
    }

    struct Indexes(Arc<std::sync::atomic::AtomicUsize>);

    impl ChunkProvider for Indexes {
        fn get_chunk(&self, _: &str) -> std::io::Result<Option<Vec<u8>>> {
            Ok(None)
        }
        fn get_index(&self, layer: &str) -> std::io::Result<Option<Vec<u8>>> {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(Some(format!("index of {layer}").into_bytes()))
        }
        fn get_profile(&self, image: &str) -> std::io::Result<Option<Vec<u8>>> {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(Some(format!("profile of {image}").into_bytes()))
        }
    }

    #[tokio::test]
    async fn the_profile_of_an_image_is_bounded() {
        let asked = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let provider = served(Arc::new(Indexes(asked.clone())));
        let (_server, addr) = bind_with(provider, Limits::default());
        let client = Quic::bind("127.0.0.1:0".parse().unwrap(), Arc::default(), KEY).unwrap();
        let image = digest_of(b"image");
        let profile = client.profile(addr, &image, 1000).await.unwrap().unwrap();
        assert_eq!(profile, format!("profile of {image}").into_bytes());
        assert_eq!(client.profile(addr, &image, 10).await.unwrap(), None);
        // a profile and an index are not the same thing
        let index = client.index(addr, &image, 1000).await.unwrap().unwrap();
        assert_eq!(index, format!("index of {image}").into_bytes());
    }

    /// A server whose store cannot be read says so: the client gets an
    /// error (and asks another peer), not "no such chunk".
    #[tokio::test]
    async fn a_store_that_cannot_be_read_is_an_error_to_the_client() {
        struct Broken;
        impl ChunkProvider for Broken {
            fn get_chunk(&self, _: &str) -> io::Result<Option<Vec<u8>>> {
                Err(io::Error::other("gone"))
            }
            fn get_index(&self, _: &str) -> io::Result<Option<Vec<u8>>> {
                Err(io::Error::other("gone"))
            }
            fn open_chunks(&self, _: &[String]) -> io::Result<Vec<Option<ChunkFile>>> {
                Err(io::Error::other("gone"))
            }
        }
        let provider = served(Arc::new(Broken));
        let (_server, addr) = bind_with(provider, Limits::default());
        let client = Quic::bind("127.0.0.1:0".parse().unwrap(), Arc::default(), KEY).unwrap();
        let layer = digest_of(b"layer");
        let failed = client.index(addr, &layer, 1000).await.unwrap_err();
        assert!(store_failed(&failed), "{failed}");
        let failed = client
            .fetch(addr, &[(layer.clone(), None)])
            .await
            .unwrap_err();
        assert!(store_failed(&failed), "{failed}");
        let failed = client.has(addr, &layer).await.unwrap_err();
        assert!(store_failed(&failed), "{failed}");
        // a QUIC failure is not one
        assert!(!store_failed(&io::Error::from(io::ErrorKind::TimedOut)));
    }

    #[tokio::test]
    async fn the_index_of_a_layer_is_bounded() {
        let asked = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let provider = served(Arc::new(Indexes(asked.clone())));
        let (_server, addr) = bind_with(provider, Limits::default());
        let client = Quic::bind("127.0.0.1:0".parse().unwrap(), Arc::default(), KEY).unwrap();
        let layer = digest_of(b"layer");
        let index = client.index(addr, &layer, 1000).await.unwrap().unwrap();
        assert_eq!(index, format!("index of {layer}").into_bytes());
        // larger than asked: not sent
        assert_eq!(client.index(addr, &layer, 10).await.unwrap(), None);
        assert!(client.index(addr, "not a digest", 1000).await.is_err());
    }

    struct Panics;

    impl ChunkProvider for Panics {
        fn get_chunk(&self, digest: &str) -> std::io::Result<Option<Vec<u8>>> {
            panic!("asked for {digest}")
        }
    }

    #[tokio::test]
    async fn a_client_asks_nothing_of_a_server_without_the_swarm_key() {
        let provider = served(Arc::new(Panics));
        let (_stranger, addr) = {
            let s = Quic::bind_with(
                "127.0.0.1:0".parse().unwrap(),
                provider,
                [9; 32],
                Limits::default(),
                Arc::default(),
            )
            .unwrap();
            let addr = SocketAddr::from(([127, 0, 0, 1], s.port()));
            (s, addr)
        };
        let client = Quic::bind("127.0.0.1:0".parse().unwrap(), Arc::default(), KEY).unwrap();
        let e = client
            .fetch(addr, &[(digest_of(b"secret"), None)])
            .await
            .unwrap_err();
        assert!(
            no_path(&e).is_some_and(|why| why.contains("proof of the swarm key")),
            "{e}"
        );
        assert!(client.index(addr, &digest_of(b"layer"), 10).await.is_err());
    }

    /// A member's connection on which it sends whatever it likes.
    async fn raw(addr: SocketAddr) -> (Arc<Quic>, quinn::Connection) {
        let client = Quic::bind("127.0.0.1:0".parse().unwrap(), Arc::default(), KEY).unwrap();
        let c = client.connection(addr).await.unwrap();
        (client, c)
    }

    #[tokio::test]
    async fn garbage_requests_end_their_stream_only() {
        let (provider, digests) = chunks(&[vec![3u8; 5000]]);
        let (_server, addr) = bind_with(provider, Limits::default());
        let (_client, connection) = raw(addr).await;
        let mut x = 0x9e3779b97f4a7c15u64;
        let mut heads: Vec<Vec<u8>> = vec![
            vec![],
            vec![OP_CHUNKS],
            vec![OP_CHUNKS, 0, 0],
            vec![OP_CHUNKS, 0xff, 0xff],
            vec![OP_CHUNKS, 0, 2, 1, 2, 3],
            vec![OP_INDEX, 0, 2],
            vec![OP_INDEX, 0, 1],
            vec![7, 0, 1],
        ];
        for _ in 0..64 {
            let len = (x % 200) as usize;
            let mut h = Vec::with_capacity(len);
            for _ in 0..len {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                h.push(x as u8);
            }
            heads.push(h);
        }
        for head in heads {
            let (mut send, mut recv) = connection.open_bi().await.unwrap();
            let _ = send.write_all(&head).await;
            let _ = send.finish();
            let _ = tokio::time::timeout(Duration::from_secs(5), recv.read_to_end(1 << 24)).await;
        }
        let client = Quic::bind("127.0.0.1:0".parse().unwrap(), Arc::default(), KEY).unwrap();
        let found = client
            .fetch(addr, &[(digests[0].clone(), None)])
            .await
            .unwrap();
        assert_eq!(found.len(), 1);
        assert!(connection.close_reason().is_none());
    }

    /// A server that proves the key and then answers `answer` to any
    /// request.
    fn lying_server(answer: Vec<u8>) -> SocketAddr {
        let key = rcgen::generate_simple_self_signed(vec!["velarx".to_string()]).unwrap();
        let cert = key.cert.der().clone();
        let private =
            PrivateKeyDer::from(PrivatePkcs8KeyDer::from(key.signing_key.serialize_der()));
        let mut crypto = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert], private)
        .unwrap();
        crypto.alpn_protocols = vec![ALPN.to_vec()];
        let server = ServerConfig::with_crypto(Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(crypto).unwrap(),
        ));
        let liar = Endpoint::server(server, "127.0.0.1:0".parse().unwrap()).unwrap();
        let liar_addr = liar.local_addr().unwrap();
        tokio::spawn(async move {
            while let Some(incoming) = liar.accept().await {
                let answer = answer.clone();
                tokio::spawn(async move {
                    let c = incoming.await.unwrap();
                    send_proof(&c, &KEY, SERVER, CONNECT).await.unwrap();
                    check_proof(&c, &KEY, CLIENT, CONNECT).await.unwrap();
                    while let Ok((mut send, mut recv)) = c.accept_bi().await {
                        let _ = recv.read_to_end(1 << 20).await;
                        let _ = send.write_all(&answer).await;
                        let _ = send.finish();
                        let _ = send.stopped().await;
                    }
                });
            }
        });
        liar_addr
    }

    #[tokio::test]
    async fn what_a_server_answers_is_bounded_before_it_is_read() {
        let d = digest_of(b"x");
        let client = Quic::bind("127.0.0.1:0".parse().unwrap(), Arc::default(), KEY).unwrap();
        let mut huge = vec![1u8];
        huge.extend_from_slice(&u64::MAX.to_be_bytes());
        let mut over = vec![1u8];
        over.extend_from_slice(&((MAX_ITEM_BYTES as u64) + 1).to_be_bytes());
        let mut short = vec![1u8];
        short.extend_from_slice(&100u64.to_be_bytes());
        short.extend_from_slice(&[0u8; 10]);
        for (answer, ok) in [
            (huge, false),
            (over, false),
            (short, false),
            (vec![3u8], false),
            (vec![], false),
            (vec![0u8], true),
        ] {
            let addr = lying_server(answer.clone());
            let r = client.fetch(addr, &[(d.clone(), None)]).await;
            assert_eq!(r.is_ok(), ok, "{answer:?}: {r:?}");
            if let Ok(found) = r {
                assert!(found.is_empty());
            }
            let r = client.index(addr, &d, 1000).await;
            assert_eq!(r.is_ok(), ok, "{answer:?}: {r:?}");
        }
        // whatever it answers, an answer ends, in an error or not
        let mut x = 0x2545f4914f6cdd1du64;
        for _ in 0..16 {
            let len = (x % 64) as usize;
            let mut answer = Vec::with_capacity(len);
            for _ in 0..len {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                answer.push((x % 4) as u8);
            }
            let addr = lying_server(answer);
            let asked = [(d.clone(), None), (digest_of(b"y"), Some(3))];
            let r = tokio::time::timeout(Duration::from_secs(10), client.fetch(addr, &asked)).await;
            assert!(r.is_ok());
            let r = tokio::time::timeout(Duration::from_secs(10), client.index(addr, &d, 64)).await;
            assert!(r.is_ok());
        }
        // a server that never has room ends the asking, and says so: it is
        // not one without the chunk
        let addr = lying_server(vec![NO_ROOM]);
        let busy = tokio::time::timeout(
            Duration::from_secs(10),
            client.fetch(addr, &[(d.clone(), None)]),
        )
        .await
        .unwrap()
        .unwrap_err();
        assert!(no_room(&busy) && !store_failed(&busy), "{busy}");
        // (one that lacks it is an answer without chunks)
        let addr = lying_server(vec![ABSENT]);
        let found = client.fetch(addr, &[(d.clone(), None)]).await.unwrap();
        assert!(found.is_empty());
        // sizes asked are the sizes read
        let mut five = vec![1u8];
        five.extend_from_slice(&5u64.to_be_bytes());
        five.extend_from_slice(b"12345");
        let addr = lying_server(five);
        assert!(client.fetch(addr, &[(d.clone(), Some(4))]).await.is_err());
        let found = client.fetch(addr, &[(d.clone(), Some(5))]).await.unwrap();
        assert_eq!(found, vec![(d, b"12345".to_vec())]);
    }

    #[test]
    fn digests_cross_with_their_algorithm_and_kind() {
        let sha256 = digest_of(b"abc");
        let sha512 = Digest::of(Algorithm::Sha512, b"abc").to_string();
        let object256 = velarx_storage::fsverity_digest_of(Algorithm::Sha256, b"abc");
        let object512 = velarx_storage::fsverity_digest_of(Algorithm::Sha512, b"abc");
        let all = [
            sha256.as_str(),
            sha512.as_str(),
            object256.as_str(),
            object512.as_str(),
        ];
        let wire = digests_wire(all.into_iter()).unwrap();
        assert_eq!(wire.len(), 4 + 32 + 64 + 32 + 64);
        // (SHA-256 is 1, SHA-512 is 2, with the bit of the fs-verity ones)
        assert_eq!(&wire[..4], &[1, 2, 0x81, 0x82]);
        assert_eq!(&wire[4..36], Digest::of(Algorithm::Sha256, b"abc").raw());
        for bad in [
            "",
            "sha256:",
            "sha256:zz",
            "../x",
            "sha512:00",
            "sha384:00",
            "fsverity-sha256-12:00",
            "fsverity-sha256-16:00",
        ] {
            assert!(digests_wire(std::iter::once(bad)).is_err(), "{bad}");
        }
        assert!(kind_of(0).is_err() && kind_of(3).is_err() && kind_of(0x80).is_err());
        assert!(kind_of(0x83).is_err() && kind_of(0xff).is_err());
        // read back as the same texts: a hash of the bytes and the
        // fs-verity digest of them are never one for the other, nor are
        // the two algorithms
        let back: Vec<String> = {
            let kinds: Vec<Kind> = wire[..4].iter().map(|b| kind_of(*b).unwrap()).collect();
            let mut at = 4;
            kinds
                .into_iter()
                .map(|k| {
                    let n = k.alg().len();
                    let d = Digest::with_kind(k, &wire[at..at + n]).unwrap();
                    at += n;
                    d.to_string()
                })
                .collect()
        };
        assert_eq!(back, all.map(str::to_string));
    }

    /// A server with `serving` as its settings.
    fn bind_serving(provider: SharedProvider, serving: &Serving) -> (Arc<Quic>, SocketAddr) {
        let server = Quic::bind_with(
            "127.0.0.1:0".parse().unwrap(),
            provider,
            KEY,
            Limits::of(serving),
            Arc::new(Admission::new(serving)),
        )
        .unwrap();
        let addr = ([127, 0, 0, 1], server.port()).into();
        (server, addr)
    }

    /// A UDP relay to `to` that holds every datagram for a random time up to
    /// `jitter`, as a path with a little jitter does: neighbours swap places.
    /// Returns the address to dial.
    async fn jittery_relay(to: SocketAddr, jitter: Duration) -> SocketAddr {
        use rand::Rng;
        let front = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let back = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let addr = front.local_addr().unwrap();
        let client = Arc::new(std::sync::Mutex::new(None::<SocketAddr>));
        let (f, b, c) = (front.clone(), back.clone(), client.clone());
        tokio::spawn(async move {
            let mut buf = vec![0u8; 2048];
            loop {
                let (n, from) = f.recv_from(&mut buf).await.unwrap();
                *c.lock().unwrap() = Some(from);
                let (b, data) = (b.clone(), buf[..n].to_vec());
                let wait = rand::thread_rng().gen_range(Duration::ZERO..jitter);
                tokio::spawn(async move {
                    tokio::time::sleep(wait).await;
                    let _ = b.send_to(&data, to).await;
                });
            }
        });
        tokio::spawn(async move {
            let mut buf = vec![0u8; 2048];
            loop {
                let (n, _) = back.recv_from(&mut buf).await.unwrap();
                let (front, data) = (front.clone(), buf[..n].to_vec());
                let to = client.lock().unwrap().unwrap();
                let wait = rand::thread_rng().gen_range(Duration::ZERO..jitter);
                tokio::spawn(async move {
                    tokio::time::sleep(wait).await;
                    let _ = front.send_to(&data, to).await;
                });
            }
        });
        addr
    }

    /// Jitter that swaps neighbouring packets is not loss: a fetch over a
    /// path with 2 ms of it must not crawl (it did, 15 times slower in a debug
    /// build, with the packet threshold of 3 of the loss detection).
    #[tokio::test]
    async fn reordered_packets_are_not_taken_for_lost() {
        let (provider, digests) = chunks(&[vec![9u8; 16 << 20]]);
        let (_server, server_addr) = bind_with(provider, Limits::default());
        let addr = jittery_relay(server_addr, Duration::from_millis(2)).await;
        let client = Quic::bind("127.0.0.1:0".parse().unwrap(), Arc::default(), KEY).unwrap();
        let start = tokio::time::Instant::now();
        let found = client
            .fetch(addr, &[(digests[0].clone(), None)])
            .await
            .unwrap();
        assert_eq!(found.len(), 1);
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "{:?}",
            start.elapsed()
        );
    }

    /// Five requests of 256 KiB at a limit of 1 MB/s, four of them from one
    /// address and one from another: they take no less than the limit needs
    /// in all (the streams share it), and the one request of the other
    /// address is not behind the four (they come in turn).
    #[tokio::test]
    async fn the_upload_limit_is_for_all_streams_and_the_addresses_come_in_turn() {
        let items: Vec<Vec<u8>> = (0..5u8).map(|i| vec![i; 256 << 10]).collect();
        let (provider, digests) = chunks(&items);
        let serving = Serving {
            upload_limit_mbit: 8,
            ..Serving::default()
        };
        let (_server, addr) = bind_serving(provider, &serving);
        let busy = Quic::bind("127.0.0.1:0".parse().unwrap(), Arc::default(), KEY).unwrap();
        let other = Quic::bind("127.0.0.2:0".parse().unwrap(), Arc::default(), KEY).unwrap();
        let start = tokio::time::Instant::now();
        let mut tasks = tokio::task::JoinSet::new();
        for (n, digest) in digests.iter().enumerate() {
            let (client, digest) = (
                if n < 4 { busy.clone() } else { other.clone() },
                digest.clone(),
            );
            tasks.spawn(async move {
                let found = client.fetch(addr, &[(digest, None)]).await.unwrap();
                assert_eq!(found.len(), 1);
                (n, start.elapsed())
            });
        }
        let mut done = Vec::new();
        while let Some(t) = tasks.join_next().await {
            done.push(t.unwrap());
        }
        let last = done.iter().map(|d| d.1).max().unwrap();
        let alone = done.iter().find(|d| d.0 == 4).unwrap().1;
        // (1.25 MiB at 1 MB/s, less the first piece, that goes at once)
        assert!(last >= Duration::from_millis(1100), "{last:?}");
        assert!(
            alone < last - Duration::from_millis(200),
            "{alone:?} {last:?}"
        );
    }

    /// A chunk that takes longer than the idle time to arrive, at the pace
    /// of a rate-limited seed, is fetched: the time is for a piece of it, not
    /// for the chunk.
    #[tokio::test]
    async fn a_chunk_slower_than_the_idle_time_is_fetched_whole() {
        let (provider, digests) = chunks(&[vec![5u8; 4 << 20]]);
        let serving = Serving {
            upload_limit_mbit: 8,
            ..Serving::default()
        };
        let (_server, addr) = bind_serving(provider, &serving);
        let client = Quic::bind_with(
            "127.0.0.1:0".parse().unwrap(),
            Arc::default(),
            KEY,
            Limits {
                idle: Duration::from_secs(2),
                ..Limits::default()
            },
            Arc::default(),
        )
        .unwrap();
        let start = tokio::time::Instant::now();
        let found = client
            .fetch(addr, &[(digests[0].clone(), None)])
            .await
            .unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].1.len(), 4 << 20);
        assert!(
            start.elapsed() > Duration::from_secs(2),
            "{:?}",
            start.elapsed()
        );
    }

    /// The slot of an index is kept while it is sent: what is in memory for
    /// the peers reading is bounded by the slots.
    #[tokio::test]
    async fn an_index_holds_its_slot_while_it_is_sent() {
        struct Big;
        impl ChunkProvider for Big {
            fn get_chunk(&self, _: &str) -> std::io::Result<Option<Vec<u8>>> {
                Ok(None)
            }
            fn get_index(&self, _: &str) -> std::io::Result<Option<Vec<u8>>> {
                Ok(Some(vec![4u8; 3 << 20]))
            }
        }
        let serving = Serving {
            quic_slots: 1,
            upload_limit_mbit: 8,
            ..Serving::default()
        };
        let limits = Limits {
            idle: Duration::from_millis(300),
            ..Limits::of(&serving)
        };
        let server = Quic::bind_with(
            "127.0.0.1:0".parse().unwrap(),
            served(Arc::new(Big)),
            KEY,
            limits,
            Arc::new(Admission::new(&serving)),
        )
        .unwrap();
        let addr: SocketAddr = ([127, 0, 0, 1], server.port()).into();
        let client = Quic::bind("127.0.0.1:0".parse().unwrap(), Arc::default(), KEY).unwrap();
        let layer = digest_of(b"layer");
        let slow = tokio::spawn({
            let client = client.clone();
            async move { client.index(addr, &layer, 4 << 20).await }
        });
        tokio::time::sleep(Duration::from_millis(500)).await;
        let busy = client
            .fetch(addr, &[(digest_of(b"x"), None)])
            .await
            .unwrap_err();
        assert!(no_room(&busy), "{busy}");
        assert_eq!(slow.await.unwrap().unwrap().map(|i| i.len()), Some(3 << 20));
    }

    /// What the server has read and not yet sent is bounded by the credit
    /// of the upload limit, not by the requests that wait nor by the size of
    /// their chunks: 64 requests (the slots) for chunks of 1 MiB, from three
    /// addresses, at 2 MB/s, hold no more than the few pieces granted and
    /// not yet written (a request that read a piece before its credit would
    /// hold 64 pieces, one that read its chunk 64 MiB).
    #[tokio::test]
    async fn what_is_read_and_not_sent_is_bounded_by_the_credit() {
        let dir = tempfile::tempdir().unwrap();
        let data = vec![7u8; 1 << 20];
        let path = dir.path().join("chunk");
        std::fs::write(&path, &data).unwrap();
        let provider = served(Arc::new(OneFile(
            std::fs::File::open(&path).unwrap(),
            data.len() as u64,
        )));
        let serving = Serving {
            upload_limit_mbit: 16,
            ..Serving::default()
        };
        let (server, addr) = bind_serving(provider, &serving);
        let piece = Admission::new(&serving).piece();
        let limits = Limits::of(&serving);
        let mut written = server.held.written.subscribe();
        // 8 connections of 8 streams, from three addresses
        let mut tasks = tokio::task::JoinSet::new();
        let mut clients = Vec::new();
        for c in 0..limits.serving / limits.streams_per_connection {
            let ip = std::net::Ipv4Addr::new(127, 0, 0, 1 + (c % 3) as u8);
            let client = Quic::bind((ip, 0).into(), Arc::default(), KEY).unwrap();
            for _ in 0..limits.streams_per_connection {
                let (client, digest) = (client.clone(), digest_of(&data));
                tasks.spawn(async move { client.fetch(addr, &[(digest, None)]).await });
            }
            clients.push(client);
        }
        // a second of the limit has been sent
        written.wait_for(|w| *w >= 8).await.unwrap();
        let most = server.held.most.load(std::sync::atomic::Ordering::SeqCst);
        // (a piece is granted every eighth of a second, and written as soon
        // as it is read)
        assert!(most <= 4 * piece, "{most} bytes held, a piece is {piece}");
        tasks.abort_all();
    }

    /// A request whose first credit does not come in half the time the client
    /// waits for a byte is told there is no room, not left in silence.
    #[tokio::test]
    async fn a_request_with_no_credit_in_time_is_told_no_room() {
        let dir = tempfile::tempdir().unwrap();
        let data = vec![5u8; 3 << 20];
        let path = dir.path().join("chunk");
        std::fs::write(&path, &data).unwrap();
        let provider = served(Arc::new(OneFile(
            std::fs::File::open(&path).unwrap(),
            data.len() as u64,
        )));
        let serving = Serving {
            upload_limit_mbit: 8,
            ..Serving::default()
        };
        let (_server, addr) = {
            let limits = Limits {
                idle: Duration::from_millis(40),
                ..Limits::of(&serving)
            };
            let server = Quic::bind_with(
                "127.0.0.1:0".parse().unwrap(),
                provider,
                KEY,
                limits,
                Arc::new(Admission::new(&serving)),
            )
            .unwrap();
            let addr: SocketAddr = ([127, 0, 0, 1], server.port()).into();
            (server, addr)
        };
        let (_endpoint, connection) = member(addr).await;
        let asked = vec![(digest_of(&data), None)];
        // the first has the link (its answer starts when it has its credit)
        let (mut send, mut recv) = connection.open_bi().await.unwrap();
        send.write_all(&chunks_request(&asked)).await.unwrap();
        let mut first = [0u8; 9];
        recv.read_exact(&mut first).await.unwrap();
        assert_eq!(first[0], HERE);
        // the second waits for a piece of the first, an eighth of a second
        let (mut send2, mut recv2) = connection.open_bi().await.unwrap();
        send2.write_all(&chunks_request(&asked)).await.unwrap();
        let mut answer = [0u8; 1];
        recv2.read_exact(&mut answer).await.unwrap();
        assert_eq!(answer[0], NO_ROOM);
    }

    /// An index whose first credit does not come in half the time the
    /// client waits is answered absent (the protocol of the indexes has no
    /// busy), not left in silence; one that has its credit comes in pieces.
    #[tokio::test]
    async fn an_index_with_no_credit_in_time_is_told_no_room() {
        struct FileAndIndex(std::fs::File, u64);
        impl ChunkProvider for FileAndIndex {
            fn get_chunk(&self, _: &str) -> std::io::Result<Option<Vec<u8>>> {
                Ok(None)
            }
            fn open_chunks(&self, digests: &[String]) -> std::io::Result<Vec<Option<ChunkFile>>> {
                OneFile(self.0.try_clone()?, self.1).open_chunks(digests)
            }
            fn get_index(&self, _: &str) -> std::io::Result<Option<Vec<u8>>> {
                Ok(Some(vec![4u8; 300_000]))
            }
        }
        let dir = tempfile::tempdir().unwrap();
        let data = vec![5u8; 3 << 20];
        let path = dir.path().join("chunk");
        std::fs::write(&path, &data).unwrap();
        let provider = served(Arc::new(FileAndIndex(
            std::fs::File::open(&path).unwrap(),
            data.len() as u64,
        )));
        let serving = Serving {
            upload_limit_mbit: 8,
            ..Serving::default()
        };
        let limits = Limits {
            idle: Duration::from_millis(40),
            ..Limits::of(&serving)
        };
        let bind = || {
            let server = Quic::bind_with(
                "127.0.0.1:0".parse().unwrap(),
                provider.clone(),
                KEY,
                limits,
                Arc::new(Admission::new(&serving)),
            )
            .unwrap();
            let addr: SocketAddr = ([127, 0, 0, 1], server.port()).into();
            (server, addr)
        };
        let layer = digest_of(b"layer");
        // alone, it comes, in pieces of an eighth of a second
        let (_alone, addr) = bind();
        let client = Quic::bind("127.0.0.1:0".parse().unwrap(), Arc::default(), KEY).unwrap();
        let index = client.index(addr, &layer, 1 << 20).await.unwrap();
        assert_eq!(index, Some(vec![4u8; 300_000]));
        // behind a chunk that has the link, there is no room: not "none"
        let (_behind, addr) = bind();
        let (_endpoint, connection) = member(addr).await;
        let (mut send, mut recv) = connection.open_bi().await.unwrap();
        send.write_all(&chunks_request(&[(digest_of(&data), None)]))
            .await
            .unwrap();
        let mut first = [0u8; 9];
        recv.read_exact(&mut first).await.unwrap();
        assert_eq!(first[0], HERE);
        let e = client.index(addr, &layer, 1 << 20).await.unwrap_err();
        assert!(no_room(&e), "{e}");
    }

    /// The time a request waits for the credit of the upload limit is not
    /// the time a peer takes: a peer that reads at once is not cut off for
    /// the node's wait, however long, with a grace it would not meet if it
    /// were counted.
    #[tokio::test]
    async fn the_wait_for_credit_does_not_count_against_the_grace() {
        let (provider, digests) = chunks(&[vec![9u8; 400 << 10]]);
        let serving = Serving {
            upload_limit_mbit: 2,
            ..Serving::default()
        };
        let limits = Limits {
            grace: Duration::from_millis(300),
            ..Limits::of(&serving)
        };
        let server = Quic::bind_with(
            "127.0.0.1:0".parse().unwrap(),
            provider,
            KEY,
            limits,
            Arc::new(Admission::new(&serving)),
        )
        .unwrap();
        let addr: SocketAddr = ([127, 0, 0, 1], server.port()).into();
        // a peer that reads at once, through a window smaller than a piece:
        // each write waits for it a little (what is counted), and for the
        // credit of the next piece long (what is not)
        let mut transport = client_transport();
        transport.stream_receive_window((8u32 << 10).into());
        let endpoint = Endpoint::client(([127, 0, 0, 1], 0).into()).unwrap();
        let connection = endpoint
            .connect_with(
                client_config(transport, &Auth::Key(KEY)).unwrap(),
                addr,
                "velarx",
            )
            .unwrap()
            .await
            .unwrap();
        send_proof(&connection, &KEY, CLIENT, CONNECT)
            .await
            .unwrap();
        check_proof(&connection, &KEY, SERVER, CONNECT)
            .await
            .unwrap();
        let start = tokio::time::Instant::now();
        let (mut send, mut recv) = connection.open_bi().await.unwrap();
        send.write_all(&chunks_request(&[(digests[0].clone(), None)]))
            .await
            .unwrap();
        let answer = recv.read_to_end(1 << 20).await.unwrap();
        assert_eq!(answer.len(), 9 + (400 << 10), "the whole chunk");
        assert_eq!(answer[0], HERE);
        // (400 KiB at 250 kB/s: five times the grace)
        assert!(start.elapsed() > Duration::from_millis(1300));
    }

    /// One request of `head` on a connection of a member, and the bytes
    /// the server answers with (none when it ends the stream).
    async fn answer_to(connection: &quinn::Connection, head: &[u8]) -> Vec<u8> {
        let (mut send, mut recv) = connection.open_bi().await.unwrap();
        let _ = send.write_all(head).await;
        let _ = send.finish();
        match tokio::time::timeout(Duration::from_secs(5), recv.read_to_end(1 << 20)).await {
            Ok(Ok(bytes)) => bytes,
            _ => Vec::new(),
        }
    }

    /// A question whether a chunk is here: yes or no for one full digest, one
    /// byte either way and no bytes of the chunk; whatever could walk the
    /// inventory (more digests, none, a digest of no algorithm) is no question.
    #[tokio::test]
    async fn a_probe_answers_for_one_digest_and_lists_nothing() {
        let (provider, d) = chunks(&[b"one".to_vec(), b"two".to_vec()]);
        let (_server, addr) = bind_with(provider, Limits::default());
        let client = Quic::bind("127.0.0.1:0".parse().unwrap(), Arc::default(), KEY).unwrap();
        assert_eq!(client.has(addr, &d[0]).await.unwrap(), Presence::Has);
        let missing = digest_of(b"missing");
        assert_eq!(client.has(addr, &missing).await.unwrap(), Presence::Lacks);
        // (not a digest: nothing is sent)
        assert!(client.has(addr, "../../etc/passwd").await.is_err());
        let (_member, connection) = raw(addr).await;
        let one = |digest: &str| {
            let mut head = vec![OP_PROBE, 0, 1];
            head.extend(digests_wire(std::iter::once(digest)).unwrap());
            head
        };
        assert_eq!(answer_to(&connection, &one(&d[0])).await, [HERE]);
        assert_eq!(answer_to(&connection, &one(&missing)).await, [ABSENT]);
        let mut two = vec![OP_PROBE, 0, 2];
        two.extend(digests_wire([d[0].as_str(), d[1].as_str()].into_iter()).unwrap());
        let mut bad = one(&d[0]);
        // (the byte of the algorithm)
        bad[3] = 9;
        for head in [
            two,
            vec![OP_PROBE, 0, 0],
            bad,
            vec![OP_PROBE, 0, 1, 1, 2, 3],
        ] {
            assert!(answer_to(&connection, &head).await.is_empty(), "{head:?}");
        }
        // the connection is still good
        assert_eq!(answer_to(&connection, &one(&d[1])).await, [HERE]);
    }

    /// The bytes of a request read as the server reads them from its stream:
    /// what a client sends comes back, and a head that claims more than it
    /// carries, none or too many digests, or a digest of no algorithm is
    /// refused (the fuzz target runs the same function).
    #[test]
    fn a_request_reads_as_the_server_reads_it() {
        let (a, b) = (digest_of(b"a"), digest_of(b"b"));
        let mut two = vec![OP_CHUNKS, 0, 2];
        two.extend(digests_wire([a.as_str(), b.as_str()].into_iter()).unwrap());
        assert_eq!(
            parse_request(&two).unwrap(),
            (OP_CHUNKS, vec![a.clone(), b])
        );
        let mut probe = vec![OP_PROBE, 0, 1];
        probe.extend(digests_wire(std::iter::once(a.as_str())).unwrap());
        assert_eq!(parse_request(&probe).unwrap(), (OP_PROBE, vec![a]));
        let mut bad = probe.clone();
        bad[3] = 9;
        let too_many = (MAX_REQUEST_DIGESTS as u16 + 1).to_be_bytes();
        for wrong in [
            &[][..],
            &[OP_PROBE, 0][..],
            &[OP_PROBE, 0, 0][..],
            &[OP_CHUNKS, too_many[0], too_many[1]][..],
            &two[..two.len() - 1],
            &bad[..],
        ] {
            assert!(parse_request(wrong).is_err(), "{wrong:?}");
        }
    }

    /// A request for more chunks than the limit gets nothing, one for as many
    /// as the limit is answered, and the connection goes on.
    #[tokio::test]
    async fn a_request_for_too_many_chunks_gets_nothing() {
        let (provider, d) = chunks(&[b"one".to_vec()]);
        let (_server, addr) = bind_with(provider, Limits::default());
        let (_member, connection) = raw(addr).await;
        let request = |n: usize| {
            let mut head = vec![OP_CHUNKS];
            head.extend((n as u16).to_be_bytes());
            head.extend(digests_wire(std::iter::repeat_n(d[0].as_str(), n)).unwrap());
            head
        };
        // (each digest is answered, here the same chunk each time)
        let fine = answer_to(&connection, &request(MAX_REQUEST_DIGESTS)).await;
        assert!(!fine.is_empty());
        assert!(answer_to(&connection, &request(MAX_REQUEST_DIGESTS + 1))
            .await
            .is_empty());
        assert!(!answer_to(&connection, &request(1)).await.is_empty());
    }

    /// A chunk larger than a peer may take is not served, whether the store
    /// hands over a file or bytes: it is absent, not an error.
    #[tokio::test]
    async fn a_chunk_larger_than_a_peer_may_take_is_not_served() {
        let big = vec![7u8; MAX_ITEM_BYTES + 1];
        let digest = digest_of(&big);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("chunk");
        std::fs::write(&path, &big).unwrap();
        let by_bytes = served(Arc::new(Chunks([(digest.clone(), big.clone())].into())));
        let by_file = served(Arc::new(OneFile(
            std::fs::File::open(&path).unwrap(),
            big.len() as u64,
        )));
        let client = Quic::bind("127.0.0.1:0".parse().unwrap(), Arc::default(), KEY).unwrap();
        for provider in [by_bytes, by_file] {
            let (_server, addr) = bind_with(provider, Limits::default());
            assert!(client
                .fetch(addr, &[(digest.clone(), None)])
                .await
                .unwrap()
                .is_empty());
        }
    }

    /// What has no data never asks for the credit of the upload limit: an
    /// absent chunk, and a probe, are answered at once at a node that may
    /// send nothing more for a long time, and a chunk that needs credit is
    /// told "no room".
    #[tokio::test(start_paused = true)]
    async fn answers_without_data_ask_for_no_credit() {
        let (provider, d) = chunks(&[vec![1u8; 1 << 20]]);
        let serving = Serving {
            // 1 Mbit/s: a chunk of 1 MiB takes 8 s of credit
            upload_limit_mbit: 1,
            ..Serving::default()
        };
        let server = Quic::bind_with(
            "127.0.0.1:0".parse().unwrap(),
            provider,
            KEY,
            Limits::of(&serving),
            Arc::new(Admission::new(&serving)),
        )
        .unwrap();
        let addr: SocketAddr = ([127, 0, 0, 1], server.port()).into();
        let client = Quic::bind("127.0.0.1:0".parse().unwrap(), Arc::default(), KEY).unwrap();
        let started = tokio::time::Instant::now();
        assert!(client
            .fetch(addr, &[(digest_of(b"absent"), None)])
            .await
            .unwrap()
            .is_empty());
        assert_eq!(client.has(addr, &d[0]).await.unwrap(), Presence::Has);
        assert_eq!(
            client.has(addr, &digest_of(b"absent")).await.unwrap(),
            Presence::Lacks
        );
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    /// A peer that cannot be connected to is told so at once to every
    /// request that waits for the attempt, and to those that come for a
    /// while: one attempt of [`CONNECT`], not one for each request; it is
    /// tried again after [`RETRY_AFTER`].
    #[tokio::test(start_paused = true)]
    async fn a_peer_that_cannot_be_connected_to_is_one_attempt_not_many() {
        // (a UDP port nobody answers on: the packets of the handshake are
        // lost, as a firewall that drops them does)
        let silent = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = silent.local_addr().unwrap();
        let client = Quic::bind("127.0.0.1:0".parse().unwrap(), Arc::default(), KEY).unwrap();
        let digest = digest_of(b"x");
        let started = tokio::time::Instant::now();
        let results = futures::future::join_all((0..8).map(|_| client.has(addr, &digest))).await;
        for e in results.into_iter().map(Result::unwrap_err) {
            assert!(no_path(&e).is_some_and(|why| why.contains("UDP")), "{e}");
        }
        assert!(started.elapsed() < 2 * CONNECT, "{:?}", started.elapsed());
        // (the ones that come meanwhile are told at once)
        let again = tokio::time::Instant::now();
        let e = client.has(addr, &digest).await.unwrap_err();
        assert!(no_path(&e).is_some());
        assert!(again.elapsed() < Duration::from_millis(100));
        assert!(client.avoided(addr).is_some());
        // after a while it is tried again
        tokio::time::advance(RETRY_AFTER).await;
        assert!(client.avoided(addr).is_none());
        let e = client.has(addr, &digest).await.unwrap_err();
        assert!(no_path(&e).is_some());
        drop(silent);
    }

    /// An asker that stops waiting before the attempt ends (a round of
    /// probes that is over before [`CONNECT`]) does not cut the attempt
    /// short: the next asker is told what it came to, and makes no attempt
    /// of its own.
    #[tokio::test(start_paused = true)]
    async fn an_asker_that_stops_waiting_does_not_start_the_attempt_over() {
        let silent = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = silent.local_addr().unwrap();
        let client = Quic::bind("127.0.0.1:0".parse().unwrap(), Arc::default(), KEY).unwrap();
        let digest = digest_of(b"x");
        let started = tokio::time::Instant::now();
        let gave_up = tokio::time::timeout(CONNECT / 3, client.has(addr, &digest)).await;
        assert!(gave_up.is_err(), "{gave_up:?}");
        let e = client.has(addr, &digest).await.unwrap_err();
        assert!(
            no_path(&e).is_some_and(|why| why.contains("tried again in")),
            "{e}"
        );
        assert!(
            started.elapsed() < CONNECT + CONNECT / 3,
            "{:?}",
            started.elapsed()
        );
        drop(silent);
    }

    /// A provider whose store is stuck (it never answers).
    struct Mute;
    impl ChunkProvider for Mute {
        fn get_chunk(&self, _: &str) -> std::io::Result<Option<Vec<u8>>> {
            std::thread::sleep(Duration::from_secs(60));
            Ok(None)
        }
    }

    /// A request to a peer whose store is stuck ends after the idle time, not
    /// after a multiple of it.
    #[tokio::test]
    async fn a_mute_peer_is_given_up_after_the_idle_time() {
        let (_server, addr) = bind_with(served(Arc::new(Mute)), Limits::default());
        let client = Quic::bind_with(
            "127.0.0.1:0".parse().unwrap(),
            Arc::default(),
            KEY,
            Limits {
                idle: Duration::from_secs(2),
                ..Limits::default()
            },
            Arc::default(),
        )
        .unwrap();
        let asked: Vec<_> = (0..4u8).map(|i| (digest_of(&[i]), None)).collect();
        for _ in 0..20 {
            let started = tokio::time::Instant::now();
            assert!(client.fetch(addr, &asked).await.is_err());
            assert!(
                started.elapsed() < Duration::from_secs(4),
                "{:?}",
                started.elapsed()
            );
        }
    }

    /// A peer whose QUIC endpoint comes up after a failed attempt is used
    /// after the time the failure is remembered.
    #[tokio::test(start_paused = true)]
    async fn a_path_that_appears_later_is_used() {
        let (provider, d) = chunks(&[b"one".to_vec()]);
        let silent = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = silent.local_addr().unwrap();
        let client = Quic::bind("127.0.0.1:0".parse().unwrap(), Arc::default(), KEY).unwrap();
        assert!(client.has(addr, &d[0]).await.is_err());
        // the firewall opens: a server is there now
        drop(silent);
        let server =
            Quic::bind_with(addr, provider, KEY, Limits::default(), Arc::default()).unwrap();
        assert_eq!(server.local_addr(), addr);
        // (remembered for a while: no attempt meanwhile)
        assert!(client.has(addr, &d[0]).await.is_err());
        tokio::time::advance(RETRY_AFTER).await;
        assert_eq!(client.has(addr, &d[0]).await.unwrap(), Presence::Has);
    }
}
