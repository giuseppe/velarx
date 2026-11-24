// SPDX-License-Identifier: Apache-2.0
//! Who may be a member of the swarm when it has a certificate authority:
//! per-node certificates signed by the CA of the swarm.
//!
//! A node has one key, the ed25519 key of its identity file
//! ([`crate::identity`]), which is also its libp2p peer id.  Its certificate is
//! an X.509 certificate **for that key**, signed by the CA: the TLS key of the
//! QUIC endpoint, the Noise key of libp2p and the certified key are one, so
//! the peer id is the hash of the key the certificate names and needs no
//! second binding.  The certificate says, besides the key and its validity, a
//! name, a zone (optional) and a role (`both`, `serve`, `pull`), as URI
//! alternative names (`velarx:name:NAME`, `velarx:zone:ZONE`,
//! `velarx:role:ROLE`).
//!
//! * QUIC: mutual TLS.  [`Authority::verifier`] is both the server and the
//!   client certificate verifier of the endpoint: a peer without a valid
//!   certificate fails in the handshake, before any stream.
//! * libp2p: [`Credentialed`] wraps the Noise upgrade; after Noise has
//!   proved the peer id both ends exchange their certificate, and the
//!   connection exists only if the certificate verifies and its key hashes
//!   to the peer id Noise proved; then, both admitted, the revocation lists
//!   they hold.
//! * Revocation: a list signed by the CA ([`RevocationList`]) of peer ids,
//!   read from `revocation_path` when it changes and passed along on the
//!   libp2p handshake (a newer list of the same CA replaces the older).  A
//!   sweep ([`Authority::sweep`]) closes the connections of a peer that was
//!   revoked or whose certificate expired.
//! * Rotation: the certificate and CA files are read again when they
//!   change; any number of CAs are trusted at once.
//!
//! Nothing falls back to the swarm key: a node with an authority admits
//! certificates and nothing else.  Every refusal is a typed [`Error`].

use libp2p::identity::{self, Keypair, PeerId};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::sign::CertifiedKey;
use rustls::{server::ParsedCertificate, SignatureScheme};
use rustls::{CertificateError, DigitallySignedStruct, DistinguishedName, RootCertStore};
use std::collections::{HashMap, HashSet};
use std::io::{self, Read};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};
use velarx_revoke_core::{Held, Part};

const MAX_CERT_WIRE: usize = 8 << 10;
/// How long the exchange of certificates on a connection may take.
const EXCHANGE: Duration = Duration::from_secs(10);
/// The first line of a revocation list.
pub const LIST_HEADER: &str = "velarx-revocations/1";
/// The DER of an ed25519 SubjectPublicKeyInfo, before its 32 bytes.
const ED25519_SPKI: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];
/// The PKCS#8 (version 1) of an ed25519 key, before its 32 bytes of seed.
const ED25519_PKCS8: [u8; 16] = [
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
];

/// Why a peer or a file was not accepted.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("the peer has no certificate")]
    NoCertificate,
    #[error("a certificate that cannot be read: {0}")]
    Malformed(String),
    #[error("the certificate is not signed by a certificate authority of this swarm")]
    UnknownAuthority,
    #[error("the certificate has expired")]
    Expired,
    #[error("the certificate is not valid yet")]
    NotYetValid,
    #[error("the peer {0} was revoked")]
    Revoked(PeerId),
    #[error("the certificate is for the key of {}, not of {}", .0.0, .0.1)]
    WrongPeer(Box<(PeerId, PeerId)>),
    #[error("the node {0:?} is not in the allow-list")]
    NotAllowed(String),
    #[error("a node with the role {role} {what}")]
    Role { role: Role, what: &'static str },
    #[error(
        "the revocation list was not read for {0} s: no peer is admitted until it is \
         (revocation_max_age_secs)"
    )]
    RevocationStale(u64),
}

impl Error {
    fn into_tls(self) -> rustls::Error {
        rustls::Error::InvalidCertificate(CertificateError::Other(rustls::OtherError(Arc::new(
            self,
        ))))
    }
}

/// What a node may do in the swarm, by its certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Role {
    /// Ask for data and serve it
    #[default]
    Both,
    /// A seed: serves, and is not served (its connections as a client are
    /// refused)
    Serve,
    /// Asks and is not asked (it is refused as a server)
    Pull,
}

impl Role {
    pub fn name(self) -> &'static str {
        match self {
            Role::Both => "both",
            Role::Serve => "serve",
            Role::Pull => "pull",
        }
    }
}

impl std::fmt::Display for Role {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

impl std::str::FromStr for Role {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        match s {
            "both" => Ok(Role::Both),
            "serve" => Ok(Role::Serve),
            "pull" => Ok(Role::Pull),
            other => Err(format!("the role is both, serve or pull, not {other:?}")),
        }
    }
}

/// What a node's certificate says of it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Admitted {
    pub peer_id: PeerId,
    pub name: String,
    pub zone: Option<String>,
    pub role: Role,
}

/// Which end of a connection a certificate is judged as.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Usage {
    /// It asks (a QUIC client)
    Asks,
    /// It is asked (a QUIC server)
    Serves,
    /// The control connection of libp2p: no role applies
    Control,
}

/// What the settings name.
#[derive(Debug, Clone, Default)]
pub struct Config {
    /// The certificates of the authorities (PEM, one or more)
    pub ca_path: PathBuf,
    /// The certificate of this node (PEM)
    pub certificate_path: PathBuf,
    /// The revocation lists (optional)
    pub revocation_path: Option<PathBuf>,
    /// No peer is admitted when the list was not read for this long (0: off)
    pub revocation_max_age: Duration,
    /// Only these names and peers; both empty: every certificate
    pub allow_names: Vec<String>,
    pub allow_peers: Vec<PeerId>,
    /// How often the files are read again and the peers judged again
    pub sweep: Duration,
}

// the key and the certificate

/// The PKCS#8 of the ed25519 key of `key`.
pub fn pkcs8_of(key: &Keypair) -> io::Result<Vec<u8>> {
    let ed = key
        .clone()
        .try_into_ed25519()
        .map_err(|_| io::Error::other("the identity of the node is not an ed25519 key"))?;
    let mut der = ED25519_PKCS8.to_vec();
    der.extend_from_slice(ed.secret().as_ref());
    Ok(der)
}

/// The raw ed25519 key of a SubjectPublicKeyInfo.
fn raw_key(spki: &[u8]) -> Result<[u8; 32], Error> {
    if spki.len() != 44 || spki[..12] != ED25519_SPKI {
        return Err(Error::Malformed(
            "the key of the certificate is not an ed25519 key".into(),
        ));
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&spki[12..]);
    Ok(key)
}

/// The peer id of a raw ed25519 key.
pub fn peer_of(raw: &[u8; 32]) -> Result<PeerId, Error> {
    let key = identity::ed25519::PublicKey::try_from_bytes(raw)
        .map_err(|e| Error::Malformed(format!("not an ed25519 key: {e}")))?;
    Ok(identity::PublicKey::from(key).to_peer_id())
}

/// One DER element: tag, content, rest.
fn tlv(b: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, b) = b.split_first()?;
    let (&first, b) = b.split_first()?;
    let (len, b) = if first < 0x80 {
        (first as usize, b)
    } else {
        let n = (first & 0x7f) as usize;
        if n == 0 || n > 3 || b.len() < n {
            return None;
        }
        let len = b[..n].iter().fold(0usize, |a, &x| (a << 8) | x as usize);
        (len, &b[n..])
    };
    (b.len() >= len).then(|| (tag, &b[..len], &b[len..]))
}

/// The URIs of the subject alternative names of a certificate.
fn uris_of(cert: &[u8]) -> Option<Vec<String>> {
    let (_, cert, _) = tlv(cert)?;
    let (_, mut tbs, _) = tlv(cert)?;
    let mut out = Vec::new();
    while let Some((tag, content, rest)) = tlv(tbs) {
        tbs = rest;
        if tag != 0xa3 {
            continue;
        }
        let (_, mut extensions, _) = tlv(content)?;
        while let Some((_, extension, rest)) = tlv(extensions) {
            extensions = rest;
            let (_, oid, after) = tlv(extension)?;
            // subjectAltName, 2.5.29.17
            if oid != [0x55, 0x1d, 0x11] {
                continue;
            }
            let (mut tag, mut value, mut after) = tlv(after)?;
            if tag == 0x01 {
                (tag, value, after) = tlv(after)?;
            }
            let _ = (tag, after);
            let (_, mut names, _) = tlv(value)?;
            while let Some((tag, name, rest)) = tlv(names) {
                names = rest;
                if tag == 0x86 {
                    out.push(String::from_utf8(name.to_vec()).ok()?);
                }
            }
        }
    }
    Some(out)
}

fn describe(spki: &[u8], cert: &[u8]) -> Result<Admitted, Error> {
    let peer_id = peer_of(&raw_key(spki)?)?;
    let uris =
        uris_of(cert).ok_or_else(|| Error::Malformed("the extensions cannot be read".into()))?;
    let (mut name, mut zone, mut role) = (None, None, Role::Both);
    for uri in &uris {
        if let Some(n) = uri.strip_prefix("velarx:name:") {
            name = Some(n.to_string());
        } else if let Some(z) = uri.strip_prefix("velarx:zone:") {
            zone = Some(z.to_string());
        } else if let Some(r) = uri.strip_prefix("velarx:role:") {
            role = r.parse().map_err(Error::Malformed)?;
        }
    }
    let name = name.ok_or_else(|| Error::Malformed("the certificate has no name".into()))?;
    Ok(Admitted {
        peer_id,
        name,
        zone,
        role,
    })
}

/// The key of a certificate, and what it says of the node (no chain is
/// checked: for tools that show a file).
pub fn read_certificate(
    der: &CertificateDer<'_>,
) -> Result<([u8; 32], Result<Admitted, Error>), Error> {
    let parsed = ParsedCertificate::try_from(der).map_err(|e| Error::Malformed(e.to_string()))?;
    let spki = parsed.subject_public_key_info();
    Ok((
        raw_key(spki.as_ref())?,
        describe(spki.as_ref(), der.as_ref()),
    ))
}

/// The certificates of a PEM text.
pub fn pem_certificates(text: &str) -> Result<Vec<CertificateDer<'static>>, Error> {
    use base64::Engine;
    let mut out = Vec::new();
    let mut body: Option<String> = None;
    for line in text.lines().map(str::trim) {
        match (line, &mut body) {
            ("-----BEGIN CERTIFICATE-----", None) => body = Some(String::new()),
            ("-----END CERTIFICATE-----", Some(b)) => {
                let der = base64::engine::general_purpose::STANDARD
                    .decode(b.as_bytes())
                    .map_err(|e| Error::Malformed(format!("a certificate in PEM: {e}")))?;
                out.push(CertificateDer::from(der));
                body = None;
            }
            (l, Some(b)) if !l.starts_with("-----") => b.push_str(l),
            _ => {}
        }
    }
    if body.is_some() || out.is_empty() {
        return Err(Error::Malformed("no complete certificate in PEM".into()));
    }
    Ok(out)
}

/// A certificate in PEM.
pub fn pem_certificate(der: &[u8]) -> String {
    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD.encode(der);
    let mut out = String::from("-----BEGIN CERTIFICATE-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).unwrap_or_default());
        out.push('\n');
    }
    out.push_str("-----END CERTIFICATE-----\n");
    out
}

// revocation lists

/// A list of revoked peers, signed by a CA.  Text, one item a line:
///
/// ```text
/// velarx-revocations/1
/// issuer HEX-OF-THE-KEY-OF-THE-CA
/// number 3
/// issued UNIX-TIME
/// revoke PEER-ID
/// signature HEX
/// ```
///
/// The signature covers every line before its own.  A list of the same
/// issuer with a higher number replaces the older: it holds every peer
/// revoked so far.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevocationList {
    pub issuer: [u8; 32],
    pub number: u64,
    pub issued: u64,
    pub peers: Vec<PeerId>,
    text: String,
}

impl RevocationList {
    /// The list `peers` of the CA `ca`.
    pub fn sign(
        ca: &identity::ed25519::Keypair,
        number: u64,
        issued: u64,
        peers: &[PeerId],
    ) -> Self {
        let issuer = ca.public().to_bytes();
        let mut text = format!(
            "{LIST_HEADER}\nissuer {}\nnumber {number}\nissued {issued}\n",
            hex::encode(issuer)
        );
        for peer in peers {
            text.push_str(&format!("revoke {peer}\n"));
        }
        let signature = hex::encode(ca.sign(text.as_bytes()));
        text.push_str(&format!("signature {signature}\n"));
        Self {
            issuer,
            number,
            issued,
            peers: peers.to_vec(),
            text,
        }
    }

    /// The text of the list, with its signature.
    pub fn text(&self) -> &str {
        &self.text
    }

    /// One list of `text`, if its signature is of one of `authorities`.
    pub fn parse(text: &str, authorities: &[[u8; 32]]) -> Result<Self, Error> {
        let bad = |what: &str| Error::Malformed(format!("a revocation list: {what}"));
        let (body, signature) = text
            .trim_end()
            .rsplit_once("\nsignature ")
            .ok_or_else(|| bad("no signature"))?;
        let signature = hex::decode(signature.trim()).map_err(|_| bad("the signature"))?;
        let signed = format!("{body}\n");
        let mut lines = signed.lines();
        if lines.next() != Some(LIST_HEADER) {
            return Err(bad("not a list of this version"));
        }
        let field = |line: Option<&str>, name: &str| -> Result<String, Error> {
            line.and_then(|l| l.strip_prefix(name))
                .and_then(|l| l.strip_prefix(' '))
                .map(str::to_string)
                .ok_or_else(|| bad(&format!("no {name}")))
        };
        let issuer = hex::decode(field(lines.next(), "issuer")?).map_err(|_| bad("the issuer"))?;
        let issuer: [u8; 32] = issuer.try_into().map_err(|_| bad("the issuer"))?;
        let number = field(lines.next(), "number")?
            .parse()
            .map_err(|_| bad("the number"))?;
        let issued = field(lines.next(), "issued")?
            .parse()
            .map_err(|_| bad("the time"))?;
        let mut peers = Vec::new();
        for line in lines {
            let peer = line
                .strip_prefix("revoke ")
                .and_then(|p| p.split_whitespace().next())
                .ok_or_else(|| bad("a line that is not a revocation"))?;
            peers.push(peer.parse().map_err(|_| bad("a peer id"))?);
        }
        if !authorities.contains(&issuer) {
            return Err(Error::UnknownAuthority);
        }
        let key =
            identity::ed25519::PublicKey::try_from_bytes(&issuer).map_err(|_| bad("the issuer"))?;
        if !key.verify(signed.as_bytes(), &signature) {
            return Err(bad("the signature is wrong"));
        }
        Ok(Self {
            issuer,
            number,
            issued,
            peers,
            text: format!("{signed}signature {}\n", hex::encode(signature)),
        })
    }

    /// The lists of a text that holds several, one after the other; those
    /// that are not valid are skipped (`ignored` counts them).
    pub fn parse_all(text: &str, authorities: &[[u8; 32]]) -> (Vec<Self>, usize) {
        let mut lists = Vec::new();
        let mut ignored = 0;
        let (before, parts) = Self::split(text);
        // (a file that is not lists at all, or text before the first: not
        // valid either, so that a wrong file is not taken for "no revocations")
        if !before.trim().is_empty() {
            debug!("Text that is not a revocation list was skipped");
            ignored += 1;
        }
        for part in parts {
            match Self::parse(part, authorities) {
                Ok(list) => lists.push(list),
                Err(e) => {
                    debug!("A revocation list was skipped: {e}");
                    ignored += 1;
                }
            }
        }
        (lists, ignored)
    }

    /// The text before the first list, and the text of each list.
    fn split(text: &str) -> (&str, Vec<&str>) {
        let mut starts: Vec<usize> = text
            .match_indices(LIST_HEADER)
            .filter(|(i, _)| *i == 0 || text.as_bytes()[i - 1] == b'\n')
            .map(|(i, _)| i)
            .collect();
        let first = starts.first().copied().unwrap_or(text.len());
        starts.push(text.len());
        let parts = starts.windows(2).map(|p| &text[p[0]..p[1]]).collect();
        (&text[..first], parts)
    }

    /// The issuer and the number a list says it has, not checked.
    fn head(text: &str) -> Option<([u8; 32], u64)> {
        let mut lines = text.lines().skip(1);
        let issuer = hex::decode(lines.next()?.strip_prefix("issuer ")?).ok()?;
        let number = lines.next()?.strip_prefix("number ")?.parse().ok()?;
        Some((issuer.try_into().ok()?, number))
    }
}

// the authority

/// A file that is read again when it changes.
#[derive(Debug)]
struct Watched {
    path: PathBuf,
    stamp: Option<(i64, i64, u64, u64)>,
}

impl Watched {
    fn new(path: &Path) -> Self {
        Self {
            path: path.to_path_buf(),
            stamp: None,
        }
    }

    /// The content when the file changed since the last time (`None`:
    /// unchanged), an error when it cannot be read.
    fn changed(&mut self) -> io::Result<Option<String>> {
        let mut file = std::fs::File::open(&self.path)
            .map_err(|e| io::Error::new(e.kind(), format!("{}: {e}", self.path.display())))?;
        let meta = file.metadata()?;
        let stamp = (meta.mtime(), meta.mtime_nsec(), meta.len(), meta.ino());
        if self.stamp == Some(stamp) {
            return Ok(None);
        }
        let mut text = String::new();
        file.read_to_string(&mut text)?;
        self.stamp = Some(stamp);
        Ok(Some(text))
    }
}

struct State {
    roots: RootCertStore,
    /// The keys of the authorities, for the signatures of the lists
    keys: Vec<[u8; 32]>,
    lists: HashMap<[u8; 32], RevocationList>,
    revoked: HashSet<PeerId>,
    own: Arc<CertifiedKey>,
    own_info: Admitted,
    /// The last time the list could be read (or none is configured)
    lists_read: Instant,
    /// How many times a newer list was taken (to tell the peers of it)
    news: u64,
}

/// A part of a text of lists, judged: the issuer and the number it says, and
/// the list if its signature is of an authority.
type Judged = ([u8; 32], u64, Option<RevocationList>);

impl State {
    /// The number the core knows an authority by.
    fn id(&self, issuer: &[u8; 32]) -> Option<u64> {
        self.keys.iter().position(|k| k == issuer).map(|i| i as u64)
    }

    /// The lists held, for the core.
    fn held(&self) -> Vec<Held> {
        let held = self.lists.values();
        held.filter_map(|l| {
            Some(Held {
                issuer: self.id(&l.issuer)?,
                number: l.number,
            })
        })
        .collect()
    }
}

struct Entry {
    cert: CertificateDer<'static>,
    who: Admitted,
    libp2p: bool,
    quic: Vec<quinn::Connection>,
}

struct Files {
    ca: Watched,
    cert: Watched,
    lists: Option<Watched>,
    /// The last reading of the lists was valid (an unchanged file that was
    /// not does not count as read for `revocation_max_age`)
    lists_good: bool,
}

/// The certificates the node admits: see the module documentation.
pub struct Authority {
    config: Config,
    pkcs8: Vec<u8>,
    this: PeerId,
    state: RwLock<State>,
    files: Mutex<Files>,
    book: Mutex<HashMap<PeerId, Entry>>,
    refused: tokio::sync::watch::Sender<u64>,
}

impl std::fmt::Debug for Authority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Authority").finish_non_exhaustive()
    }
}

fn algorithms() -> &'static [&'static dyn rustls::pki_types::SignatureVerificationAlgorithm] {
    rustls::crypto::ring::default_provider()
        .signature_verification_algorithms
        .all
}

impl Authority {
    /// The authority of `config` for the node with the key `identity`.  A
    /// file that cannot be read, a certificate that is not for this key or
    /// is not valid now, a list that is not valid: the node does not start.
    pub fn load(config: Config, identity: &Keypair) -> anyhow::Result<Arc<Self>> {
        let pkcs8 = pkcs8_of(identity)?;
        let this = identity.public().to_peer_id();
        let mut files = Files {
            ca: Watched::new(&config.ca_path),
            cert: Watched::new(&config.certificate_path),
            lists: config.revocation_path.as_deref().map(Watched::new),
            lists_good: true,
        };
        let ca = files.ca.changed()?.unwrap_or_default();
        let cert = files.cert.changed()?.unwrap_or_default();
        let (roots, keys) = Self::roots(&ca)?;
        let (own, own_info) = Self::own(&cert, &pkcs8, &roots, this)?;
        let mut state = State {
            roots,
            keys,
            lists: HashMap::new(),
            revoked: HashSet::new(),
            own,
            own_info,
            lists_read: Instant::now(),
            news: 0,
        };
        if let Some(watched) = files.lists.as_mut() {
            let text = watched.changed()?.unwrap_or_default();
            let (lists, ignored) = RevocationList::parse_all(&text, &state.keys);
            if ignored > 0 {
                anyhow::bail!(
                    "{}: {ignored} revocation list(s) are not valid (not signed by an authority \
                     of ca_path, or damaged)",
                    watched.path.display()
                );
            }
            Self::adopt_into(&mut state, lists.into_iter().map(Self::signed).collect());
        }
        info!(
            "This node is {:?} ({}), certified by {} authority(ies); {} peer(s) revoked",
            state.own_info.name,
            state.own_info.role,
            state.keys.len(),
            state.revoked.len()
        );
        Ok(Arc::new(Self {
            config,
            pkcs8,
            this,
            state: RwLock::new(state),
            files: Mutex::new(files),
            book: Mutex::default(),
            refused: tokio::sync::watch::channel(0).0,
        }))
    }

    fn roots(pem: &str) -> anyhow::Result<(RootCertStore, Vec<[u8; 32]>)> {
        let mut roots = RootCertStore::empty();
        let mut keys = Vec::new();
        for der in pem_certificates(pem)? {
            let parsed = ParsedCertificate::try_from(&der)
                .map_err(|e| anyhow::anyhow!("an authority certificate: {e}"))?;
            keys.push(raw_key(parsed.subject_public_key_info().as_ref())?);
            roots
                .add(der)
                .map_err(|e| anyhow::anyhow!("an authority certificate: {e}"))?;
        }
        Ok((roots, keys))
    }

    /// The certified key of this node from its certificate.
    fn own(
        pem: &str,
        pkcs8: &[u8],
        roots: &RootCertStore,
        mine: PeerId,
    ) -> anyhow::Result<(Arc<CertifiedKey>, Admitted)> {
        let der = pem_certificates(pem)?
            .into_iter()
            .next()
            .ok_or(Error::NoCertificate)?;
        // (the allow-list names the peers this node admits, not itself)
        let who = Self::verify_chain(
            roots,
            &der,
            &[],
            UnixTime::now(),
            Usage::Control,
            &HashSet::new(),
            &Config::default(),
        )?;
        if who.peer_id != mine {
            return Err(Error::WrongPeer(Box::new((who.peer_id, mine))).into());
        }
        let key = rustls::crypto::ring::sign::any_supported_type(&PrivateKeyDer::Pkcs8(
            PrivatePkcs8KeyDer::from(pkcs8.to_vec()),
        ))?;
        Ok((Arc::new(CertifiedKey::new(vec![der], key)), who))
    }

    /// The chain, the validity, the revocations, the allow-list and the role
    /// of a certificate.
    fn verify_chain(
        roots: &RootCertStore,
        end: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
        usage: Usage,
        revoked: &HashSet<PeerId>,
        config: &Config,
    ) -> Result<Admitted, Error> {
        let parsed =
            ParsedCertificate::try_from(end).map_err(|e| Error::Malformed(e.to_string()))?;
        rustls::client::verify_server_cert_signed_by_trust_anchor(
            &parsed,
            roots,
            intermediates,
            now,
            algorithms(),
        )
        .map_err(|e| match e {
            rustls::Error::InvalidCertificate(
                CertificateError::Expired | CertificateError::ExpiredContext { .. },
            ) => Error::Expired,
            rustls::Error::InvalidCertificate(
                CertificateError::NotValidYet | CertificateError::NotValidYetContext { .. },
            ) => Error::NotYetValid,
            rustls::Error::InvalidCertificate(
                CertificateError::UnknownIssuer | CertificateError::BadSignature,
            ) => Error::UnknownAuthority,
            other => Error::Malformed(other.to_string()),
        })?;
        let who = describe(parsed.subject_public_key_info().as_ref(), end.as_ref())?;
        if revoked.contains(&who.peer_id) {
            return Err(Error::Revoked(who.peer_id));
        }
        if (!config.allow_names.is_empty() || !config.allow_peers.is_empty())
            && !config.allow_peers.contains(&who.peer_id)
            && !config.allow_names.contains(&who.name)
        {
            return Err(Error::NotAllowed(who.name));
        }
        match (usage, who.role) {
            (Usage::Asks, Role::Serve) => Err(Error::Role {
                role: Role::Serve,
                what: "that only serves does not ask",
            }),
            (Usage::Serves, Role::Pull) => Err(Error::Role {
                role: Role::Pull,
                what: "that only pulls is not asked",
            }),
            _ => Ok(who),
        }
    }

    fn signed(list: RevocationList) -> Judged {
        (list.issuer, list.number, Some(list))
    }

    /// Adopt what `velarx_revoke_core` picks of the lists judged (the
    /// issuer and number a part says, and the list when its signature held):
    /// the numbers adopted.
    fn adopt_into(state: &mut State, judged: Vec<Judged>) -> Vec<u64> {
        let (mut parts, mut lists) = (Vec::new(), Vec::new());
        for (issuer, number, list) in judged {
            // (what a part says of itself counts only when its signature held)
            let (issuer, number) = list
                .as_ref()
                .map_or((issuer, number), |l| (l.issuer, l.number));
            if let Some(issuer) = state.id(&issuer) {
                let verified = list.is_some();
                parts.push(Part {
                    issuer,
                    number,
                    verified,
                });
                lists.push(list);
            }
        }
        let mut numbers = Vec::new();
        for i in velarx_revoke_core::adopt(&state.held(), &parts) {
            if let Some(list) = lists[i].take() {
                numbers.push(list.number);
                state.lists.insert(list.issuer, list);
            }
        }
        if !numbers.is_empty() {
            state.news += numbers.len() as u64;
            state.revoked = state
                .lists
                .values()
                .flat_map(|l| l.peers.iter().copied())
                .collect();
        }
        numbers
    }

    /// The identity of a certificate presented on a connection, judged now.
    pub fn verify(
        &self,
        end: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
        usage: Usage,
    ) -> Result<Admitted, Error> {
        self.judge(end, intermediates, now, usage)
            .map_err(|e| self.refuse(None, e))
    }

    /// [`Self::verify`] without counting a refusal.
    fn judge(
        &self,
        end: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
        usage: Usage,
    ) -> Result<Admitted, Error> {
        let state = self.state.read().unwrap_or_else(|e| e.into_inner());
        let max_age = self.config.revocation_max_age;
        if !max_age.is_zero()
            && self.config.revocation_path.is_some()
            && state.lists_read.elapsed() > max_age
        {
            return Err(Error::RevocationStale(state.lists_read.elapsed().as_secs()));
        }
        Self::verify_chain(
            &state.roots,
            end,
            intermediates,
            now,
            usage,
            &state.revoked,
            &self.config,
        )
    }

    /// Count a refusal and log it.
    fn refuse(&self, peer: Option<&PeerId>, e: Error) -> Error {
        self.refused.send_modify(|n| *n += 1);
        let from = peer.map(|p| format!(" ({p})")).unwrap_or_default();
        warn!("A peer was not admitted{from}: {e}");
        e
    }

    /// The peers refused so far (any transport).
    pub fn refused(&self) -> u64 {
        *self.refused.borrow()
    }

    /// The peers revoked by the lists the node holds.
    pub fn revoked_count(&self) -> usize {
        self.state
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .revoked
            .len()
    }

    /// The count of the peers refused, told when it changes.
    pub fn refusals(&self) -> tokio::sync::watch::Receiver<u64> {
        self.refused.subscribe()
    }

    /// How often the files are read again and the peers judged again.
    pub fn sweep_interval(&self) -> Duration {
        self.config.sweep
    }

    /// The peer id of this node (its certificate is for it).
    pub fn peer_id(&self) -> PeerId {
        self.this
    }

    /// What a node is told of itself.
    pub fn this_node(&self) -> Admitted {
        self.state
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .own_info
            .clone()
    }

    /// What the certificate of `peer` said, while it is connected.
    pub fn who(&self, peer: &PeerId) -> Option<Admitted> {
        self.book
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(peer)
            .map(|e| e.who.clone())
    }

    fn own_key(&self) -> Arc<CertifiedKey> {
        self.state
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .own
            .clone()
    }

    /// How many times a newer list was taken: when it changed, the peers are
    /// told the lists ([`Self::lists_text`]).
    pub fn news(&self) -> u64 {
        self.state.read().unwrap_or_else(|e| e.into_inner()).news
    }

    /// The lists held, to tell a peer.
    pub fn lists_text(&self) -> Vec<String> {
        self.state
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .lists
            .values()
            .map(|l| l.text().to_string())
            .collect()
    }

    /// The lists a peer sent (one text, one list after the other): of each
    /// authority the newest list that is signed by it, when newer than the
    /// one held, whatever else the text holds.  A list can be checked only
    /// when it says an authority of this node and a number newer than the
    /// one held, and at most two of each authority are: one text costs at
    /// most twice the authorities in signature checks, and junk that claims
    /// one authority cannot use up the checks of another.  (An honest peer
    /// sends one list of each authority; a peer that fills the checks with
    /// junk before them sends no list, which it may as well do.)
    pub fn adopt(&self, text: &str) -> bool {
        // (the signatures are checked before the lock that the handshakes
        // wait for is taken)
        let (keys, held) = {
            let state = self.state.read().unwrap_or_else(|e| e.into_inner());
            (state.keys.clone(), state.held())
        };
        let mut judged = Vec::new();
        let mut checks = vec![0; keys.len()];
        for part in RevocationList::split(text).1 {
            let Some((issuer, number)) = RevocationList::head(part) else {
                continue;
            };
            let asked = keys.iter().position(|k| *k == issuer);
            if let Some(id) = asked.filter(|id| {
                checks[*id] < 2 && velarx_revoke_core::newer(&held, *id as u64, number)
            }) {
                checks[id] += 1;
                judged.push((issuer, number, RevocationList::parse(part, &keys).ok()));
            }
            if judged.len() == 2 * keys.len() {
                break;
            }
        }
        if judged.is_empty() {
            return false;
        }
        let mut state = self.state.write().unwrap_or_else(|e| e.into_inner());
        let numbers = Self::adopt_into(&mut state, judged);
        for number in &numbers {
            info!(
                "A newer revocation list (number {number}) came from a peer: {} peer(s) revoked",
                state.revoked.len()
            );
        }
        !numbers.is_empty()
    }

    /// Remember a peer admitted on libp2p.
    fn remember(&self, who: Admitted, cert: CertificateDer<'static>, libp2p: bool) {
        let mut book = self.book.lock().unwrap_or_else(|e| e.into_inner());
        let entry = book.entry(who.peer_id).or_insert_with(|| Entry {
            cert: cert.clone(),
            who: who.clone(),
            libp2p: false,
            quic: Vec::new(),
        });
        entry.cert = cert;
        entry.who = who;
        entry.libp2p |= libp2p;
    }

    /// A libp2p connection of `peer` is established: false when its
    /// certificate is not known (any more), and it must be closed.
    pub fn established(&self, peer: &PeerId) -> bool {
        match self
            .book
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get_mut(peer)
        {
            Some(e) => {
                e.libp2p = true;
                true
            }
            None => false,
        }
    }

    /// The libp2p connections of `peer` are all closed.
    pub fn disconnected(&self, peer: &PeerId) {
        if let Some(e) = self
            .book
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get_mut(peer)
        {
            e.libp2p = false;
        }
    }

    /// A QUIC connection admitted by the handshake: the identity it proved,
    /// from the certificates of the connection.
    pub fn admitted_quic(&self, connection: &quinn::Connection) -> Result<Admitted, Error> {
        let chain = connection
            .peer_identity()
            .and_then(|i| i.downcast::<Vec<CertificateDer<'static>>>().ok())
            .ok_or(Error::NoCertificate)?;
        let end = chain.first().ok_or(Error::NoCertificate)?;
        // (verified by the handshake: this reads what it said)
        let parsed =
            ParsedCertificate::try_from(end).map_err(|e| Error::Malformed(e.to_string()))?;
        let who = describe(parsed.subject_public_key_info().as_ref(), end.as_ref())?;
        let mut book = self.book.lock().unwrap_or_else(|e| e.into_inner());
        let entry = book.entry(who.peer_id).or_insert_with(|| Entry {
            cert: end.clone(),
            who: who.clone(),
            libp2p: false,
            quic: Vec::new(),
        });
        entry.cert = end.clone();
        entry.quic.retain(|c| c.close_reason().is_none());
        entry.quic.push(connection.clone());
        Ok(who)
    }

    /// Read the files again where they changed, then judge every admitted
    /// peer again (revoked, expired): the QUIC connections of those that
    /// fail are closed, and they are returned, for their libp2p connections.
    pub fn sweep(&self) -> Vec<(PeerId, Error)> {
        self.reload();
        let state = self.state.read().unwrap_or_else(|e| e.into_inner());
        let now = UnixTime::now();
        let mut book = self.book.lock().unwrap_or_else(|e| e.into_inner());
        let mut failing = Vec::new();
        for (peer, entry) in book.iter_mut() {
            entry.quic.retain(|c| c.close_reason().is_none());
            let usage = Usage::Control;
            if let Err(e) = Self::verify_chain(
                &state.roots,
                &entry.cert,
                &[],
                now,
                usage,
                &state.revoked,
                &self.config,
            ) {
                for c in &entry.quic {
                    c.close(2u32.into(), b"the certificate is not valid any more");
                }
                failing.push((*peer, e));
            }
        }
        for (peer, e) in &failing {
            warn!("The peer {peer} is dropped: {e}");
            book.remove(peer);
        }
        book.retain(|_, e| e.libp2p || !e.quic.is_empty());
        failing
    }

    /// Read again what changed: the authorities, the certificate of this
    /// node, the lists.  A file that cannot be read keeps what was loaded.
    fn reload(&self) {
        let mut files = self.files.lock().unwrap_or_else(|e| e.into_inner());
        let ca = files.ca.changed();
        // (a list that no authority could sign when it was read is read
        // again when the authorities change)
        if let (Ok(Some(_)), Some(lists)) = (&ca, files.lists.as_mut()) {
            lists.stamp = None;
        }
        let cert = files.cert.changed();
        let lists = files.lists.as_mut().map(|w| w.changed());
        let mut state = self.state.write().unwrap_or_else(|e| e.into_inner());
        match ca {
            Ok(Some(text)) => match Self::roots(&text) {
                Ok((roots, keys)) => {
                    info!("The authorities were read again: {} of them", keys.len());
                    state.roots = roots;
                    state.keys = keys;
                }
                Err(e) => {
                    warn!(
                        "{}: {e}; the authorities stay as they were",
                        self.config.ca_path.display()
                    );
                    files.ca.stamp = None;
                }
            },
            Ok(None) => {}
            Err(e) => warn!("The authorities cannot be read: {e}; they stay as they were"),
        }
        let cert_text = match cert {
            Ok(Some(text)) => Some(text),
            Ok(None) => None,
            Err(e) => {
                warn!("The certificate of this node cannot be read: {e}; the old one is kept");
                None
            }
        };
        if let Some(text) = cert_text {
            match Self::own(&text, &self.pkcs8, &state.roots, self.this) {
                Ok((own, info)) => {
                    info!(
                        "The certificate of this node was read again ({:?})",
                        info.name
                    );
                    state.own = own;
                    state.own_info = info;
                }
                Err(e) => {
                    warn!(
                        "{}: {e}; the old certificate is kept",
                        self.config.certificate_path.display()
                    );
                    files.cert.stamp = None;
                }
            }
        }
        match lists {
            Some(Ok(None)) => {
                // (unchanged: read when the last reading was valid)
                if files.lists_good {
                    state.lists_read = Instant::now();
                }
            }
            Some(Ok(Some(text))) => {
                let (found, ignored) = RevocationList::parse_all(&text, &state.keys);
                // (a file that is not valid is not a reading of the
                // list: revocation_max_age goes on counting)
                files.lists_good = ignored == 0;
                if ignored > 0 {
                    warn!("{ignored} revocation list(s) of the file are not valid and were skipped; the file does not count as read");
                } else {
                    state.lists_read = Instant::now();
                }
                let judged = found.into_iter().map(Self::signed).collect();
                for number in Self::adopt_into(&mut state, judged) {
                    info!(
                        "The revocation list (number {number}) was read: {} peer(s) revoked",
                        state.revoked.len()
                    );
                }
            }
            Some(Err(e)) => warn!("The revocation list cannot be read: {e}; the last one is kept"),
            None => state.lists_read = Instant::now(),
        }
    }

    /// The verifier of both ends of the QUIC handshake.
    pub fn verifier(self: &Arc<Self>) -> Arc<Verifier> {
        Arc::new(Verifier(self.clone()))
    }

    /// The certificate this node presents, as the TLS stack asks for it.
    pub fn resolver(self: &Arc<Self>) -> Arc<Resolver> {
        Arc::new(Resolver(self.clone()))
    }

    /// The identity to give a connection to a peer whose libp2p certificate
    /// was verified (see [`Credentialed`]).
    fn admit_control(
        &self,
        peer: PeerId,
        cert: &CertificateDer<'static>,
    ) -> Result<Admitted, Error> {
        let who = self
            .judge(cert, &[], UnixTime::now(), Usage::Control)
            .map_err(|e| self.refuse(Some(&peer), e))?;
        if who.peer_id != peer {
            return Err(self.refuse(Some(&peer), Error::WrongPeer(Box::new((who.peer_id, peer)))));
        }
        Ok(who)
    }

    /// The lists an admitted peer sent are taken (when newer), and the peer
    /// judged again against them.
    fn admit_lists(
        &self,
        who: Admitted,
        cert: CertificateDer<'static>,
        lists: &[String],
    ) -> Result<Admitted, Error> {
        self.adopt(&lists.join("\n"));
        let revoked = self
            .state
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .revoked
            .contains(&who.peer_id);
        if revoked {
            return Err(self.refuse(Some(&who.peer_id), Error::Revoked(who.peer_id)));
        }
        self.remember(who.clone(), cert, true);
        Ok(who)
    }
}

// TLS

/// Judges the certificates of both ends of a QUIC connection.
#[derive(Debug)]
pub struct Verifier(Arc<Authority>);

impl ServerCertVerifier for Verifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        self.0
            .verify(end_entity, intermediates, now, Usage::Serves)
            .map(|_| ServerCertVerified::assertion())
            .map_err(Error::into_tls)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
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
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

impl ClientCertVerifier for Verifier {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        self.0
            .verify(end_entity, intermediates, now, Usage::Asks)
            .map(|_| ClientCertVerified::assertion())
            .map_err(Error::into_tls)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        ServerCertVerifier::verify_tls12_signature(self, message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        ServerCertVerifier::verify_tls13_signature(self, message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        ServerCertVerifier::supported_verify_schemes(self)
    }
}

/// Gives the TLS stack the certificate of this node, the one of the moment
/// (a certificate placed since the start is used by the next handshake).
#[derive(Debug)]
pub struct Resolver(Arc<Authority>);

impl rustls::server::ResolvesServerCert for Resolver {
    fn resolve(&self, _: rustls::server::ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.0.own_key())
    }
}

impl rustls::client::ResolvesClientCert for Resolver {
    fn resolve(&self, _: &[&[u8]], _: &[SignatureScheme]) -> Option<Arc<CertifiedKey>> {
        Some(self.0.own_key())
    }

    fn has_certs(&self) -> bool {
        true
    }
}

// libp2p

/// What goes wrong in the upgrade of a libp2p connection.
#[derive(Debug, thiserror::Error)]
pub enum UpgradeError {
    #[error("{0}")]
    Noise(#[from] libp2p::noise::Error),
    #[error("the exchange of certificates: {0}")]
    Io(#[from] io::Error),
    #[error("{0}")]
    Refused(#[from] Error),
}

/// The Noise upgrade of libp2p, and then the exchange of certificates: the
/// connection exists only for a peer whose certificate verifies for the peer
/// id Noise proved.  Without an authority it is the Noise upgrade.
#[derive(Clone)]
pub struct Credentialed {
    noise: libp2p::noise::Config,
    authority: Option<Arc<Authority>>,
}

impl Credentialed {
    pub fn new(noise: libp2p::noise::Config, authority: Option<Arc<Authority>>) -> Self {
        Self { noise, authority }
    }
}

impl libp2p::core::upgrade::UpgradeInfo for Credentialed {
    type Info = <libp2p::noise::Config as libp2p::core::upgrade::UpgradeInfo>::Info;
    type InfoIter = <libp2p::noise::Config as libp2p::core::upgrade::UpgradeInfo>::InfoIter;

    fn protocol_info(&self) -> Self::InfoIter {
        self.noise.protocol_info()
    }
}

/// The lists this node holds, each with its length, as one part.
fn lists_part(authority: &Authority) -> Vec<u8> {
    let mut lists = Vec::new();
    for text in authority.lists_text() {
        lists.extend_from_slice(&(text.len() as u32).to_be_bytes());
        lists.extend_from_slice(text.as_bytes());
    }
    lists
}

async fn write_part<S: futures::AsyncWrite + Unpin>(io: &mut S, data: &[u8]) -> io::Result<()> {
    use futures::AsyncWriteExt;
    io.write_all(&(data.len() as u32).to_be_bytes()).await?;
    io.write_all(data).await?;
    io.flush().await
}

async fn read_part<S: futures::AsyncRead + Unpin>(io: &mut S, max: usize) -> io::Result<Vec<u8>> {
    use futures::AsyncReadExt;
    let mut len = [0u8; 4];
    io.read_exact(&mut len).await?;
    let len = u32::from_be_bytes(len) as usize;
    if len > max {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "a certificate or a list that is too large",
        ));
    }
    let mut data = Vec::new();
    io.take(len as u64).read_to_end(&mut data).await?;
    if data.len() != len {
        return Err(io::ErrorKind::UnexpectedEof.into());
    }
    Ok(data)
}

/// Two steps: the certificates, each judged by the other end; then, between
/// two admitted peers only, the revocation lists (no list is sent to
/// or read from a peer that was not admitted).
async fn exchange<S>(authority: &Authority, peer: PeerId, io: &mut S) -> Result<(), UpgradeError>
where
    S: futures::AsyncRead + futures::AsyncWrite + Unpin,
{
    let deadline = tokio::time::Instant::now() + EXCHANGE;
    let own = authority.own_key();
    let cert = own.cert.first().map(|c| c.to_vec()).unwrap_or_default();
    let theirs = async {
        write_part(io, &cert).await?;
        read_part(io, MAX_CERT_WIRE).await
    };
    // (a peer that sends no certificate, or something else, or too late:
    // it has none; what it sent is in the debug log)
    let cert = match tokio::time::timeout_at(deadline, theirs).await {
        Ok(Ok(cert)) if !cert.is_empty() => cert,
        Ok(Ok(_)) => return Err(authority.refuse(Some(&peer), Error::NoCertificate).into()),
        Ok(Err(e)) => {
            debug!("The certificate of {peer} could not be read: {e}");
            return Err(authority.refuse(Some(&peer), Error::NoCertificate).into());
        }
        Err(_) => {
            debug!("No certificate from {peer} in {EXCHANGE:?}");
            return Err(authority.refuse(Some(&peer), Error::NoCertificate).into());
        }
    };
    let cert = CertificateDer::from(cert);
    let who = authority.admit_control(peer, &cert)?;
    let ours = lists_part(authority);
    let theirs = async {
        write_part(io, &ours).await?;
        read_part(io, crate::limits::MAX_LISTS_BYTES).await
    };
    // (an end that refused this node closes here)
    let lists = match tokio::time::timeout_at(deadline, theirs).await {
        Ok(result) => result?,
        Err(_) => {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "no revocation lists from the peer",
            )
            .into())
        }
    };
    let mut texts = Vec::new();
    let mut rest = lists.as_slice();
    while rest.len() >= 4 {
        let n = u32::from_be_bytes([rest[0], rest[1], rest[2], rest[3]]) as usize;
        let Some(text) = rest.get(4..4 + n) else {
            break;
        };
        if let Ok(text) = std::str::from_utf8(text) {
            texts.push(text.to_string());
        }
        rest = &rest[4 + n..];
    }
    authority.admit_lists(who, cert, &texts)?;
    Ok(())
}

macro_rules! upgrade {
    ($trait:ident, $method:ident) => {
        impl<T> libp2p::core::upgrade::$trait<T> for Credentialed
        where
            T: futures::AsyncRead + futures::AsyncWrite + Unpin + Send + 'static,
        {
            type Output = (PeerId, libp2p::noise::Output<T>);
            type Error = UpgradeError;
            type Future = futures::future::BoxFuture<'static, Result<Self::Output, Self::Error>>;

            fn $method(self, socket: T, info: Self::Info) -> Self::Future {
                Box::pin(async move {
                    let (peer, mut io) =
                        libp2p::core::upgrade::$trait::$method(self.noise, socket, info).await?;
                    if let Some(authority) = &self.authority {
                        exchange(authority, peer, &mut io).await?;
                    }
                    Ok((peer, io))
                })
            }
        }
    };
}

upgrade!(InboundConnectionUpgrade, upgrade_inbound);
upgrade!(OutboundConnectionUpgrade, upgrade_outbound);

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::ca;

    /// An authority in `dir/ca` and a node certified by it.
    pub(crate) struct Swarm {
        pub dir: tempfile::TempDir,
    }

    pub(crate) struct Node {
        pub key: Keypair,
        pub config: Config,
    }

    impl Swarm {
        pub fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            ca::init(&dir.path().join("ca"), 365).unwrap();
            Self { dir }
        }

        pub fn ca(&self) -> PathBuf {
            self.dir.path().join("ca")
        }

        pub fn node(&self, name: &str, zone: Option<&str>, role: Role) -> Node {
            let key = Keypair::generate_ed25519();
            let request = ca::request(&key);
            let (pem, _) = ca::sign(&self.ca(), &request, name, zone, role, 30).unwrap();
            let certificate_path = self.dir.path().join(format!("{name}.crt"));
            std::fs::write(&certificate_path, pem).unwrap();
            Node {
                key,
                config: Config {
                    ca_path: self.ca().join("ca.crt"),
                    certificate_path,
                    ..Config::default()
                },
            }
        }
    }

    impl Node {
        pub fn authority(&self) -> Arc<Authority> {
            Authority::load(self.config.clone(), &self.key).unwrap()
        }

        pub fn der(&self) -> CertificateDer<'static> {
            let text = std::fs::read_to_string(&self.config.certificate_path).unwrap();
            pem_certificates(&text).unwrap().remove(0)
        }
    }

    fn days(n: u64) -> UnixTime {
        UnixTime::since_unix_epoch(Duration::from_secs(UnixTime::now().as_secs() + n * 86400))
    }

    #[test]
    fn a_node_is_what_its_certificate_says() {
        let swarm = Swarm::new();
        let a = swarm.node("rack1-a", Some("zone-1"), Role::Serve);
        let authority = a.authority();
        let me = authority.this_node();
        assert_eq!(me.peer_id, a.key.public().to_peer_id());
        assert_eq!(me.name, "rack1-a");
        assert_eq!(me.zone.as_deref(), Some("zone-1"));
        assert_eq!(me.role, Role::Serve);
        let b = swarm.node("b", None, Role::Both);
        let who = authority
            .verify(&b.der(), &[], UnixTime::now(), Usage::Control)
            .unwrap();
        assert_eq!(who.peer_id, b.key.public().to_peer_id());
        assert_eq!(
            (who.name.as_str(), who.zone, who.role),
            ("b", None, Role::Both)
        );
    }

    #[test]
    fn a_certificate_for_another_key_is_not_this_nodes() {
        let swarm = Swarm::new();
        let a = swarm.node("a", None, Role::Both);
        let err = Authority::load(a.config.clone(), &Keypair::generate_ed25519()).unwrap_err();
        assert!(err.to_string().contains("not of"), "{err}");
    }

    #[test]
    fn a_certificate_of_another_authority_is_refused() {
        let ours = Swarm::new();
        let theirs = Swarm::new();
        let a = ours.node("a", None, Role::Both);
        let stranger = theirs.node("stranger", None, Role::Both);
        let err = a
            .authority()
            .verify(&stranger.der(), &[], UnixTime::now(), Usage::Control)
            .unwrap_err();
        assert_eq!(err, Error::UnknownAuthority);
    }

    #[test]
    fn a_certificate_is_valid_for_its_time_only() {
        let swarm = Swarm::new();
        let a = swarm.node("a", None, Role::Both);
        let b = swarm.node("b", None, Role::Both);
        let authority = a.authority();
        assert!(authority
            .verify(&b.der(), &[], days(29), Usage::Control)
            .is_ok());
        assert_eq!(
            authority
                .verify(&b.der(), &[], days(31), Usage::Control)
                .unwrap_err(),
            Error::Expired
        );
        let before =
            UnixTime::since_unix_epoch(Duration::from_secs(UnixTime::now().as_secs() - 3600));
        assert_eq!(
            authority
                .verify(&b.der(), &[], before, Usage::Control)
                .unwrap_err(),
            Error::NotYetValid
        );
        assert!(authority.refused() >= 2);
    }

    #[test]
    fn a_node_whose_certificate_has_expired_does_not_start() {
        let swarm = Swarm::new();
        let a = swarm.node("a", None, Role::Both);
        // (a node that is told so by its clock, ten years on)
        let roots = Authority::roots(&std::fs::read_to_string(&a.config.ca_path).unwrap())
            .unwrap()
            .0;
        let err = Authority::verify_chain(
            &roots,
            &a.der(),
            &[],
            days(3650),
            Usage::Control,
            &HashSet::new(),
            &a.config,
        )
        .unwrap_err();
        assert_eq!(err, Error::Expired);
    }

    #[test]
    fn roles_say_who_may_ask_and_who_may_be_asked() {
        let swarm = Swarm::new();
        let a = swarm.node("a", None, Role::Both);
        let seed = swarm.node("seed", None, Role::Serve);
        let leech = swarm.node("leech", None, Role::Pull);
        let authority = a.authority();
        let now = UnixTime::now();
        assert!(authority
            .verify(&seed.der(), &[], now, Usage::Serves)
            .is_ok());
        assert!(authority
            .verify(&leech.der(), &[], now, Usage::Asks)
            .is_ok());
        assert!(authority
            .verify(&seed.der(), &[], now, Usage::Control)
            .is_ok());
        assert!(matches!(
            authority.verify(&seed.der(), &[], now, Usage::Asks),
            Err(Error::Role {
                role: Role::Serve,
                ..
            })
        ));
        assert!(matches!(
            authority.verify(&leech.der(), &[], now, Usage::Serves),
            Err(Error::Role {
                role: Role::Pull,
                ..
            })
        ));
    }

    #[test]
    fn an_allow_list_names_the_nodes_that_may_join() {
        let swarm = Swarm::new();
        let (b, c) = (
            swarm.node("b", None, Role::Both),
            swarm.node("c", None, Role::Both),
        );
        let mut a = swarm.node("a", None, Role::Both);
        a.config.allow_names = vec!["a".into(), "b".into()];
        let authority = a.authority();
        let now = UnixTime::now();
        assert!(authority.verify(&b.der(), &[], now, Usage::Control).is_ok());
        assert_eq!(
            authority
                .verify(&c.der(), &[], now, Usage::Control)
                .unwrap_err(),
            Error::NotAllowed("c".into())
        );
        let mut a = swarm.node("a2", None, Role::Both);
        a.config.allow_names = vec!["a2".into()];
        a.config.allow_peers = vec![c.key.public().to_peer_id()];
        let authority = a.authority();
        assert!(authority.verify(&c.der(), &[], now, Usage::Control).is_ok());
        assert!(authority
            .verify(&b.der(), &[], now, Usage::Control)
            .is_err());
    }

    #[test]
    fn a_revoked_peer_is_refused_and_a_list_only_grows() {
        let swarm = Swarm::new();
        let mut a = swarm.node("a", None, Role::Both);
        let b = swarm.node("b", None, Role::Both);
        let c = swarm.node("c", None, Role::Both);
        let revoked = swarm.dir.path().join("revoked");
        a.config.revocation_path = Some(revoked.clone());
        // (no file yet: the node does not start, as the operator said it has one)
        assert!(Authority::load(a.config.clone(), &a.key).is_err());
        let b_id = b.key.public().to_peer_id();
        let list = ca::revoke(&swarm.ca(), &[b_id]).unwrap();
        assert_eq!(list.number, 1);
        std::fs::copy(swarm.ca().join("revoked"), &revoked).unwrap();
        let authority = a.authority();
        let now = UnixTime::now();
        assert_eq!(
            authority
                .verify(&b.der(), &[], now, Usage::Control)
                .unwrap_err(),
            Error::Revoked(b_id)
        );
        assert!(authority.verify(&c.der(), &[], now, Usage::Control).is_ok());
        let second = ca::revoke(&swarm.ca(), &[c.key.public().to_peer_id()]).unwrap();
        assert_eq!((second.number, second.peers.len()), (2, 2));
        // an older list does not replace the newer
        let text = std::fs::read_to_string(swarm.ca().join("revoked")).unwrap();
        assert!(authority.adopt(&text));
        assert!(!authority.adopt(list.text()));
        assert!(authority
            .verify(&c.der(), &[], now, Usage::Control)
            .is_err());
    }

    /// A text that holds a genuine newer list and junk that claims the same
    /// issuer with the highest number must not hide the genuine one: a
    /// relayer that adds junk does not mask a revocation.
    #[test]
    fn junk_in_a_text_does_not_hide_a_genuine_newer_list() {
        let swarm = Swarm::new();
        let mut a = swarm.node("a", None, Role::Both);
        let b = swarm.node("b", None, Role::Both);
        let c = swarm.node("c", None, Role::Both);
        let revoked = swarm.dir.path().join("revoked");
        a.config.revocation_path = Some(revoked.clone());
        ca::revoke(&swarm.ca(), &[b.key.public().to_peer_id()]).unwrap();
        std::fs::copy(swarm.ca().join("revoked"), &revoked).unwrap();
        let c_id = c.key.public().to_peer_id();
        let genuine = ca::revoke(&swarm.ca(), &[c_id]).unwrap();
        assert_eq!(genuine.number, 2);
        let forged = genuine
            .text()
            .replace("number 2", "number 18446744073709551615");
        let unsigned = forged.replace("signature ", "ignored ");
        for junk in [&forged, &unsigned] {
            for text in [
                format!("{junk}{}", genuine.text()),
                format!("{}{junk}", genuine.text()),
            ] {
                // (a node that holds the first list only)
                let authority = a.authority();
                assert!(authority.adopt(&text), "the genuine list is adopted");
                assert_eq!(authority.revoked_count(), 2);
                assert_eq!(
                    authority
                        .verify(&c.der(), &[], UnixTime::now(), Usage::Control)
                        .unwrap_err(),
                    Error::Revoked(c_id)
                );
            }
        }
    }

    /// A text costs at most twice the authorities in signature checks: the
    /// parts after that are not looked at.
    #[test]
    fn a_text_costs_a_bounded_number_of_signature_checks() {
        let swarm = Swarm::new();
        let a = swarm.node("a", None, Role::Both);
        let b = swarm.node("b", None, Role::Both);
        let genuine = ca::revoke(&swarm.ca(), &[b.key.public().to_peer_id()]).unwrap();
        let forged = genuine.text().replace("number 1", "number 7");
        let authority = a.authority();
        let text = format!("{forged}{forged}{}", genuine.text());
        assert!(!authority.adopt(&text));
        let text = format!("{forged}{}{forged}", genuine.text());
        assert!(authority.adopt(&text));
    }

    /// The checks are counted for each authority: junk that claims one does
    /// not use up the checks of another.
    #[test]
    fn junk_of_one_authority_does_not_starve_another() {
        let first = Swarm::new();
        let second = Swarm::new();
        let a = first.node("a", None, Role::Both);
        let victim = second.node("victim", None, Role::Both);
        let authority = a.authority();
        let bundle = format!(
            "{}{}",
            std::fs::read_to_string(first.ca().join("ca.crt")).unwrap(),
            std::fs::read_to_string(second.ca().join("ca.crt")).unwrap()
        );
        std::fs::write(&a.config.ca_path, bundle).unwrap();
        authority.sweep();
        let own = ca::revoke(&first.ca(), &[a.key.public().to_peer_id()]).unwrap();
        let junk = own.text().replace("number 1", "number 7");
        let genuine = ca::revoke(&second.ca(), &[victim.key.public().to_peer_id()]).unwrap();
        let text = format!("{junk}{junk}{junk}{junk}{}", genuine.text());
        assert!(authority.adopt(&text));
        assert_eq!(authority.revoked_count(), 1);
    }

    #[test]
    fn a_long_list_is_signed_adopted_and_handed_over_whole() {
        let swarm = Swarm::new();
        let mut a = swarm.node("a", None, Role::Both);
        let b = swarm.node("b", None, Role::Both);
        let revoked = swarm.dir.path().join("revoked");
        a.config.revocation_path = Some(revoked.clone());
        let b_id = b.key.public().to_peer_id();
        let mut peers: Vec<PeerId> = (0..20_000)
            .map(|_| Keypair::generate_ed25519().public().to_peer_id())
            .collect();
        peers.push(b_id);
        let list = ca::revoke(&swarm.ca(), &peers).unwrap();
        assert!(list.text().len() > 1 << 20);
        std::fs::copy(swarm.ca().join("revoked"), &revoked).unwrap();
        let authority = a.authority();
        assert_eq!(
            authority
                .verify(&b.der(), &[], UnixTime::now(), Usage::Control)
                .unwrap_err(),
            Error::Revoked(b_id)
        );
        let part = lists_part(&authority);
        assert!(part.len() > list.text().len());
    }

    #[test]
    fn a_list_must_be_signed_by_an_authority_of_the_node() {
        let ours = Swarm::new();
        let theirs = Swarm::new();
        let a = ours.node("a", None, Role::Both);
        let victim = ours.node("victim", None, Role::Both);
        let forged = ca::revoke(&theirs.ca(), &[victim.key.public().to_peer_id()]).unwrap();
        let authority = a.authority();
        assert!(!authority.adopt(forged.text()));
        assert!(authority
            .verify(&victim.der(), &[], UnixTime::now(), Usage::Control)
            .is_ok());
        // a damaged list does not parse either
        let own = ca::revoke(&ours.ca(), &[victim.key.public().to_peer_id()]).unwrap();
        let keys = authority.state.read().unwrap().keys.clone();
        let tampered = own.text().replace("number 1", "number 9");
        assert!(RevocationList::parse(&tampered, &keys).is_err());
        assert!(RevocationList::parse(own.text(), &keys).is_ok());
    }

    #[test]
    fn the_sweep_drops_a_peer_when_it_is_revoked_and_when_the_files_change() {
        let swarm = Swarm::new();
        let mut a = swarm.node("a", None, Role::Both);
        let b = swarm.node("b", None, Role::Both);
        let revoked = swarm.dir.path().join("revoked");
        ca::revoke(&swarm.ca(), &[]).unwrap();
        std::fs::copy(swarm.ca().join("revoked"), &revoked).unwrap();
        a.config.revocation_path = Some(revoked.clone());
        let authority = a.authority();
        let b_id = b.key.public().to_peer_id();
        authority.remember(
            authority
                .verify(&b.der(), &[], UnixTime::now(), Usage::Control)
                .unwrap(),
            b.der(),
            true,
        );
        assert_eq!(authority.who(&b_id).unwrap().name, "b");
        assert!(authority.sweep().is_empty());
        // the operator revokes b and puts the list in place
        ca::revoke(&swarm.ca(), &[b_id]).unwrap();
        std::fs::copy(swarm.ca().join("revoked"), &revoked).unwrap();
        let dropped = authority.sweep();
        assert_eq!(dropped.len(), 1);
        assert_eq!(dropped[0].0, b_id);
        assert_eq!(dropped[0].1, Error::Revoked(b_id));
        assert!(authority.who(&b_id).is_none());
    }

    #[test]
    fn a_new_certificate_file_is_presented_after_the_sweep() {
        let swarm = Swarm::new();
        let a = swarm.node("a", None, Role::Both);
        let authority = a.authority();
        assert_eq!(authority.this_node().name, "a");
        // (renewed: signed again for the same key, with another name and role)
        let request = ca::request(&a.key);
        let (pem, _) = ca::sign(&swarm.ca(), &request, "a-renewed", None, Role::Serve, 60).unwrap();
        std::fs::write(&a.config.certificate_path, pem).unwrap();
        authority.sweep();
        assert_eq!(authority.this_node().name, "a-renewed");
        assert_eq!(authority.this_node().role, Role::Serve);
        // a certificate for another key is not taken
        let other = swarm.node("other", None, Role::Both);
        std::fs::copy(&other.config.certificate_path, &a.config.certificate_path).unwrap();
        authority.sweep();
        assert_eq!(authority.this_node().name, "a-renewed");
    }

    #[test]
    fn a_second_authority_is_trusted_beside_the_first() {
        let first = Swarm::new();
        let second = Swarm::new();
        let a = first.node("a", None, Role::Both);
        let b = second.node("b", None, Role::Both);
        let authority = a.authority();
        assert!(authority
            .verify(&b.der(), &[], UnixTime::now(), Usage::Control)
            .is_err());
        let bundle = format!(
            "{}{}",
            std::fs::read_to_string(first.ca().join("ca.crt")).unwrap(),
            std::fs::read_to_string(second.ca().join("ca.crt")).unwrap()
        );
        std::fs::write(&a.config.ca_path, bundle).unwrap();
        authority.sweep();
        assert!(authority
            .verify(&b.der(), &[], UnixTime::now(), Usage::Control)
            .is_ok());
    }

    #[test]
    fn a_stale_revocation_list_admits_nobody() {
        let swarm = Swarm::new();
        let mut a = swarm.node("a", None, Role::Both);
        let b = swarm.node("b", None, Role::Both);
        ca::revoke(&swarm.ca(), &[]).unwrap();
        let revoked = swarm.dir.path().join("revoked");
        std::fs::copy(swarm.ca().join("revoked"), &revoked).unwrap();
        a.config.revocation_path = Some(revoked);
        a.config.revocation_max_age = Duration::from_secs(10);
        let authority = a.authority();
        authority.state.write().unwrap().lists_read = Instant::now() - Duration::from_secs(100);
        assert!(matches!(
            authority.verify(&b.der(), &[], UnixTime::now(), Usage::Control),
            Err(Error::RevocationStale(_))
        ));
        authority.sweep();
        assert!(authority
            .verify(&b.der(), &[], UnixTime::now(), Usage::Control)
            .is_ok());
    }

    #[test]
    fn the_allow_list_is_of_the_peers_and_not_of_the_node_itself() {
        let swarm = Swarm::new();
        let seed = swarm.node("seed", None, Role::Serve);
        let mut a = swarm.node("a", None, Role::Pull);
        a.config.allow_names = vec!["seed".into()];
        let authority = a.authority();
        let now = UnixTime::now();
        assert!(authority
            .verify(&seed.der(), &[], now, Usage::Serves)
            .is_ok());
        let other = swarm.node("other", None, Role::Both);
        assert!(authority
            .verify(&other.der(), &[], now, Usage::Control)
            .is_err());
    }

    #[test]
    fn a_file_that_is_not_revocation_lists_is_not_taken_for_none() {
        let swarm = Swarm::new();
        let mut a = swarm.node("a", None, Role::Both);
        let revoked = swarm.dir.path().join("revoked");
        std::fs::write(&revoked, "-----BEGIN CERTIFICATE-----\nnot a list\n").unwrap();
        a.config.revocation_path = Some(revoked.clone());
        a.config.revocation_max_age = Duration::from_secs(10);
        assert!(Authority::load(a.config.clone(), &a.key).is_err());
        assert_eq!(RevocationList::parse_all("", &[]).1, 0);
        assert_eq!(RevocationList::parse_all("\n \n", &[]).1, 0);
        // a good list, then a bad file in its place: not a reading
        ca::revoke(&swarm.ca(), &[]).unwrap();
        std::fs::copy(swarm.ca().join("revoked"), &revoked).unwrap();
        let authority = a.authority();
        std::fs::write(&revoked, "garbage\n").unwrap();
        let old = Instant::now() - Duration::from_secs(100);
        authority.state.write().unwrap().lists_read = old;
        authority.sweep();
        // (and not when it is read again unchanged either)
        authority.sweep();
        let b = swarm.node("b", None, Role::Both);
        assert!(matches!(
            authority.verify(&b.der(), &[], UnixTime::now(), Usage::Control),
            Err(Error::RevocationStale(_))
        ));
        std::fs::copy(swarm.ca().join("revoked"), &revoked).unwrap();
        authority.sweep();
        assert!(authority
            .verify(&b.der(), &[], UnixTime::now(), Usage::Control)
            .is_ok());
    }

    /// During a rotation a list that comes before the certificate of its
    /// authority is read again when that arrives.
    #[test]
    fn a_list_that_came_before_its_authority_is_read_when_it_arrives() {
        let ours = Swarm::new();
        let next = Swarm::new();
        let mut a = ours.node("a", None, Role::Both);
        let authorities = ours.dir.path().join("authorities.crt");
        let old = std::fs::read_to_string(ours.ca().join("ca.crt")).unwrap();
        std::fs::write(&authorities, &old).unwrap();
        a.config.ca_path = authorities.clone();
        let revoked = ours.dir.path().join("revoked");
        ca::revoke(&ours.ca(), &[]).unwrap();
        std::fs::copy(ours.ca().join("revoked"), &revoked).unwrap();
        a.config.revocation_path = Some(revoked.clone());
        let authority = a.authority();
        // the list of the next authority is deployed first
        ca::revoke(&next.ca(), &[PeerId::random()]).unwrap();
        std::fs::copy(next.ca().join("revoked"), &revoked).unwrap();
        authority.sweep();
        assert_eq!(authority.revoked_count(), 0);
        let both = old + &std::fs::read_to_string(next.ca().join("ca.crt")).unwrap();
        std::fs::write(&authorities, both).unwrap();
        authority.sweep();
        assert_eq!(authority.revoked_count(), 1);
    }

    #[test]
    fn a_libp2p_connection_of_a_peer_not_admitted_is_not_established() {
        let swarm = Swarm::new();
        let a = swarm.node("a", None, Role::Both);
        let b = swarm.node("b", None, Role::Both);
        let authority = a.authority();
        let b_id = b.key.public().to_peer_id();
        assert!(!authority.established(&b_id));
        let who = authority.admit_control(b_id, &b.der()).unwrap();
        // (the certificate of b, from another peer: refused)
        assert!(matches!(
            authority.admit_control(PeerId::random(), &b.der()),
            Err(Error::WrongPeer(_))
        ));
        authority.admit_lists(who, b.der(), &[]).unwrap();
        // (the last connection closed while a new one was being upgraded)
        authority.disconnected(&b_id);
        assert!(authority.established(&b_id));
        assert!(authority.sweep().is_empty());
        assert!(authority.who(&b_id).is_some());
    }

    #[test]
    fn a_list_an_admitted_peer_brings_is_applied_to_it_too() {
        let swarm = Swarm::new();
        let a = swarm.node("a", None, Role::Both);
        let b = swarm.node("b", None, Role::Both);
        let authority = a.authority();
        let b_id = b.key.public().to_peer_id();
        let who = authority.admit_control(b_id, &b.der()).unwrap();
        let list = ca::revoke(&swarm.ca(), &[b_id]).unwrap();
        assert_eq!(
            authority
                .admit_lists(who, b.der(), &[list.text().to_string()])
                .unwrap_err(),
            Error::Revoked(b_id)
        );
        assert!(authority.who(&b_id).is_none());
    }

    #[test]
    fn the_request_proves_the_key() {
        let swarm = Swarm::new();
        let key = Keypair::generate_ed25519();
        let other = Keypair::generate_ed25519();
        let request = ca::request(&key);
        // the key of another node under the proof of this one
        let forged = request.replace(
            &hex::encode(key.public().encode_protobuf()),
            &hex::encode(other.public().encode_protobuf()),
        );
        let err = ca::sign(&swarm.ca(), &forged, "x", None, Role::Both, 1).unwrap_err();
        assert!(err.to_string().contains("proof"), "{err}");
    }

    #[test]
    fn show_says_what_a_file_holds() {
        let swarm = Swarm::new();
        let a = swarm.node("a", Some("z"), Role::Pull);
        let text = ca::show(&a.config.certificate_path).unwrap();
        assert!(text.contains("node a:") && text.contains("zone z") && text.contains("role pull"));
        assert!(ca::show(&swarm.ca().join("ca.crt"))
            .unwrap()
            .contains("authority"));
        ca::revoke(&swarm.ca(), &[a.key.public().to_peer_id()]).unwrap();
        assert!(ca::show(&swarm.ca().join("revoked"))
            .unwrap()
            .contains("1 peer(s) revoked"));
    }
}
