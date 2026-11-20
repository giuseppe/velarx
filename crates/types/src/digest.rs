// SPDX-License-Identifier: Apache-2.0
//! The digest of a piece of content: `sha256:<64 hex>` or `sha512:<128 hex>`.
//!
//! Every digest the engine names, reads or writes is a [`Digest`]: it carries
//! its algorithm, so it is checked with that algorithm and no other, and the
//! API has no default algorithm.  A digest is also either a plain hash of the
//! bytes (an OCI digest) or the root of an fs-verity Merkle tree (the name of
//! an object of the store): [`Kind`] says which.  Both are written
//! `sha256:<hex>` in the places that predate the distinction (the annotation
//! `io.containers.composefs.digest`); the text `fsverity-sha256-12:<hex>`
//! is the explicit form of the second, read by [`Digest::parse_fsverity`]
//! only: where an OCI digest is read ([`Digest::parse`], serde, the
//! database) it is no digest.

use sha2::{Digest as _, Sha256, Sha512};
use std::fmt;
use std::str::FromStr;

/// The algorithms digests are made with.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "lowercase")]
pub enum Algorithm {
    Sha256,
    Sha512,
}

/// Whether `s` is an id or a prefix of one: hexadecimal digits only (any
/// case), at least one.
pub fn is_hex_id(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_hexdigit())
}

impl Algorithm {
    pub const ALL: [Algorithm; 2] = [Algorithm::Sha256, Algorithm::Sha512];

    /// The name in the text of a digest.
    pub fn name(self) -> &'static str {
        match self {
            Self::Sha256 => "sha256",
            Self::Sha512 => "sha512",
        }
    }

    /// The length of a digest in bytes.
    pub fn len(self) -> usize {
        match self {
            Self::Sha256 => 32,
            Self::Sha512 => 64,
        }
    }

    /// Never: an algorithm has digests of at least one byte.
    pub fn is_empty(self) -> bool {
        false
    }

    /// The algorithm a command that makes images was asked for (`--digest`,
    /// `[build] digest`): `sha256` or `sha512`, any other word refused by
    /// name.
    pub fn for_creation(name: &str) -> Result<Self, String> {
        Self::from_name(name).map_err(|_| {
            format!("unknown digest algorithm `{name}`: the digests of a new image are sha256 or sha512")
        })
    }

    /// The registered algorithm called `name`.
    pub fn from_name(name: &str) -> Result<Self, DigestError> {
        match name {
            "sha256" => Ok(Self::Sha256),
            "sha512" => Ok(Self::Sha512),
            _ => Err(DigestError::UnknownAlgorithm(name.to_string())),
        }
    }
}

impl fmt::Display for Algorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

impl FromStr for Algorithm {
    type Err = DigestError;

    fn from_str(s: &str) -> Result<Self, DigestError> {
        Self::from_name(s)
    }
}

/// What a digest is the digest of.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Kind {
    /// The hash of the bytes, as the OCI image specification says.
    Content(Algorithm),
    /// The root of the fs-verity Merkle tree of a file, without salt, with
    /// blocks of `1 << log_block` bytes: the name of an object of the store.
    FsVerity { alg: Algorithm, log_block: u8 },
}

impl Kind {
    pub fn alg(self) -> Algorithm {
        match self {
            Self::Content(alg) | Self::FsVerity { alg, .. } => alg,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DigestError {
    #[error("digest {0:?} has no algorithm: expected ALGORITHM:HEX")]
    NoAlgorithm(String),
    #[error("digest algorithm {0:?} is not supported (sha256, sha512)")]
    UnknownAlgorithm(String),
    #[error("{alg} digest {value:?} has {got} hex characters, expected {want}")]
    Length {
        alg: Algorithm,
        value: String,
        got: usize,
        want: usize,
    },
    #[error("digest {0:?} is not lowercase hexadecimal")]
    NotHex(String),
    #[error("image id {0:?} has {1} hex characters, expected 64 (sha256) or 128 (sha512)")]
    IdLength(String, usize),
    #[error(
        "fs-verity digest kind {0:?} is not supported (fsverity-sha256-12, fsverity-sha512-12)"
    )]
    UnknownKind(String),
}

/// A digest: its kind (so its algorithm) and its bytes.  Two digests are
/// equal when their kinds and bytes are (so when their texts are); the order
/// is that of the kind (sha256 before sha512, content before fs-verity),
/// then of the bytes.
#[derive(Clone, Copy)]
pub struct Digest {
    kind: Kind,
    raw: [u8; 64],
}

impl Digest {
    /// The digest of `data` with `alg`.
    pub fn of(alg: Algorithm, data: &[u8]) -> Self {
        let mut w = DigestWriter::new(alg);
        w.update(data);
        w.finalize()
    }

    /// The digest of what `reader` gives.
    pub fn of_reader(alg: Algorithm, mut reader: impl std::io::Read) -> std::io::Result<Self> {
        let mut w = DigestWriter::new(alg);
        std::io::copy(&mut reader, &mut w)?;
        Ok(w.finalize())
    }

    /// The digest of the first `limit` bytes of `file` at most (fewer when it
    /// ends before), read by position: the offset of the file is not looked
    /// at or moved.  Also the number of bytes hashed.
    pub fn of_file_at(
        alg: Algorithm,
        file: &std::fs::File,
        limit: u64,
    ) -> std::io::Result<(Self, u64)> {
        use std::os::unix::fs::FileExt;
        let mut w = DigestWriter::new(alg);
        let mut buf = vec![0u8; 256 * 1024];
        let mut at = 0u64;
        while at < limit {
            let want = buf
                .len()
                .min(usize::try_from(limit - at).unwrap_or(usize::MAX));
            let n = match file.read_at(&mut buf[..want], at) {
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                r => r?,
            };
            if n == 0 {
                break;
            }
            w.update(&buf[..n]);
            at += n as u64;
        }
        Ok((w.finalize(), at))
    }

    /// The digest of the empty content.
    pub fn empty(alg: Algorithm) -> Self {
        Self::of(alg, b"")
    }

    /// The content digest with the bytes `raw`.
    pub fn from_bytes(alg: Algorithm, raw: &[u8]) -> Result<Self, DigestError> {
        Self::with_kind(Kind::Content(alg), raw)
    }

    /// The digest of kind `kind` with the bytes `raw`.
    pub fn with_kind(kind: Kind, raw: &[u8]) -> Result<Self, DigestError> {
        if raw.len() != kind.alg().len() {
            return Err(DigestError::Length {
                alg: kind.alg(),
                value: hex::encode(raw),
                got: raw.len() * 2,
                want: kind.alg().len() * 2,
            });
        }
        let mut buf = [0u8; 64];
        buf[..raw.len()].copy_from_slice(raw);
        Ok(Self { kind, raw: buf })
    }

    /// The fs-verity digest (blocks of 4096 bytes, no salt) of algorithm
    /// `alg` with the bytes `raw`: the name of an object of the store.
    pub fn fsverity(alg: Algorithm, raw: &[u8]) -> Result<Self, DigestError> {
        Self::with_kind(Kind::FsVerity { alg, log_block: 12 }, raw)
    }

    /// The content digest `alg` with the hex digits `hex`.
    pub fn from_hex(alg: Algorithm, hex: &str) -> Result<Self, DigestError> {
        Self::from_hex_kind(Kind::Content(alg), hex)
    }

    fn from_hex_kind(kind: Kind, digits: &str) -> Result<Self, DigestError> {
        let alg = kind.alg();
        if digits.len() != alg.len() * 2 {
            return Err(DigestError::Length {
                alg,
                value: digits.to_string(),
                got: digits.len(),
                want: alg.len() * 2,
            });
        }
        let mut buf = [0u8; 64];
        let nibble = |b: u8| match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'a'..=b'f' => Some(b - b'a' + 10),
            _ => None,
        };
        let (pairs, _) = digits.as_bytes().as_chunks::<2>();
        for (byte, [hi, lo]) in buf.iter_mut().zip(pairs) {
            let (Some(hi), Some(lo)) = (nibble(*hi), nibble(*lo)) else {
                return Err(DigestError::NotHex(digits.to_string()));
            };
            *byte = hi << 4 | lo;
        }
        Ok(Self { kind, raw: buf })
    }

    /// The digest an image id is the hex of: 64 digits are a sha256, 128 a
    /// sha512.
    pub fn from_id(id: &str) -> Result<Self, DigestError> {
        let alg = Algorithm::ALL
            .into_iter()
            .find(|a| a.len() * 2 == id.len())
            .ok_or_else(|| DigestError::IdLength(id.to_string(), id.len()))?;
        Self::from_hex(alg, id)
    }

    /// The same bytes as an fs-verity digest of 4096-byte blocks: the form in
    /// which `io.containers.composefs.digest` and the TOC write them.
    pub fn as_fsverity(&self) -> Self {
        Self {
            kind: Kind::FsVerity {
                alg: self.alg(),
                log_block: 12,
            },
            raw: self.raw,
        }
    }

    pub fn kind(&self) -> Kind {
        self.kind
    }

    pub fn alg(&self) -> Algorithm {
        self.kind.alg()
    }

    pub fn is_fsverity(&self) -> bool {
        matches!(self.kind, Kind::FsVerity { .. })
    }

    pub fn raw(&self) -> &[u8] {
        &self.raw[..self.alg().len()]
    }

    /// The hex digits, with no algorithm.
    pub fn hex(&self) -> String {
        self.hex_in(&mut [0; 128]).to_string()
    }

    /// The hex digits in `buf`, written at once (`hex::encode` pushes them
    /// one by one: half the time of a pull that names the files of a big
    /// table).
    fn hex_in<'a>(&self, buf: &'a mut [u8; 128]) -> &'a str {
        let raw = self.raw();
        let digits = &mut buf[..raw.len() * 2];
        hex::encode_to_slice(raw, digits).expect("two digits a byte");
        std::str::from_utf8(digits).expect("hex digits")
    }

    /// The first 12 hex digits: what the short image ids show.
    pub fn short(&self) -> String {
        self.hex()[..12].to_string()
    }

    /// The text `<alg>:<hex>`, whatever the kind: what the formats that do
    /// not tell the kinds apart write.
    pub fn plain(&self) -> String {
        format!("{}:{}", self.alg(), self.hex())
    }

    /// A name for a file or a lock that is not shared with any digest of
    /// another kind or algorithm.
    pub fn file_name(&self) -> String {
        match self.kind {
            Kind::Content(alg) => format!("{alg}-{}", self.hex()),
            Kind::FsVerity { alg, log_block } => {
                format!("fsverity-{alg}-{log_block}-{}", self.hex())
            }
        }
    }

    /// Whether `data` has this content digest, computed with its
    /// algorithm.  An fs-verity digest is not the hash of the bytes: never.
    pub fn verify(&self, data: &[u8]) -> bool {
        !self.is_fsverity() && Self::of(self.alg(), data).raw() == self.raw()
    }

    /// Parse a content digest `<alg>:<hex>`: lowercase hex, the exact length.
    pub fn parse(text: &str) -> Result<Self, DigestError> {
        text.parse()
    }

    /// Parse the key of a file of a pull: the hash of its content
    /// (`sha256:HEX`, `sha512:HEX`) or the fs-verity digest of it
    /// (`fsverity-<alg>-12:HEX`, the name of its object).  The two are
    /// different digests of the same bytes, never one for the other: the
    /// kind of the result says which the text was.
    pub fn parse_key(text: &str) -> Result<Self, DigestError> {
        match text.starts_with("fsverity-") {
            true => Self::parse_fsverity(text),
            false => Self::parse(text),
        }
    }

    /// Parse the explicit text of an fs-verity digest,
    /// `fsverity-<alg>-12:<hex>`.
    pub fn parse_fsverity(text: &str) -> Result<Self, DigestError> {
        let (name, digits) = text
            .split_once(':')
            .ok_or_else(|| DigestError::NoAlgorithm(text.to_string()))?;
        let kind = name
            .strip_prefix("fsverity-")
            .ok_or_else(|| DigestError::UnknownKind(name.to_string()))?;
        let (alg, block) = kind
            .split_once('-')
            .ok_or_else(|| DigestError::UnknownKind(name.to_string()))?;
        let alg =
            Algorithm::from_name(alg).map_err(|_| DigestError::UnknownKind(name.to_string()))?;
        if block != "12" {
            return Err(DigestError::UnknownKind(name.to_string()));
        }
        Self::from_hex_kind(Kind::FsVerity { alg, log_block: 12 }, digits)
    }
}

impl FromStr for Digest {
    type Err = DigestError;

    fn from_str(text: &str) -> Result<Self, DigestError> {
        let (name, digits) = text
            .split_once(':')
            .ok_or_else(|| DigestError::NoAlgorithm(text.to_string()))?;
        // (an fs-verity digest is no OCI digest: Digest::parse_fsverity)
        Self::from_hex(Algorithm::from_name(name)?, digits)
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut buf = [0; 128];
        let hex = self.hex_in(&mut buf);
        match self.kind {
            Kind::Content(alg) => write!(f, "{alg}:{hex}"),
            Kind::FsVerity { alg, log_block } => write!(f, "fsverity-{alg}-{log_block}:{hex}"),
        }
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Digest({self})")
    }
}

impl PartialEq for Digest {
    fn eq(&self, other: &Self) -> bool {
        self.kind == other.kind && self.raw() == other.raw()
    }
}

impl Eq for Digest {}

impl std::hash::Hash for Digest {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.kind.hash(state);
        self.raw().hash(state);
    }
}

impl PartialOrd for Digest {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Digest {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        (self.kind, self.raw()).cmp(&(other.kind, other.raw()))
    }
}

impl serde::Serialize for Digest {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> serde::Deserialize<'de> for Digest {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let text = <std::borrow::Cow<'de, str>>::deserialize(d)?;
        text.parse().map_err(serde::de::Error::custom)
    }
}

#[cfg(feature = "sqlite")]
impl rusqlite::types::ToSql for Digest {
    fn to_sql(&self) -> rusqlite::Result<rusqlite::types::ToSqlOutput<'_>> {
        Ok(self.to_string().into())
    }
}

#[cfg(feature = "sqlite")]
impl rusqlite::types::FromSql for Digest {
    fn column_result(value: rusqlite::types::ValueRef<'_>) -> rusqlite::types::FromSqlResult<Self> {
        value
            .as_str()?
            .parse()
            .map_err(|e| rusqlite::types::FromSqlError::Other(Box::new(e)))
    }
}

impl TryFrom<&str> for Digest {
    type Error = DigestError;

    fn try_from(text: &str) -> Result<Self, DigestError> {
        text.parse()
    }
}

impl TryFrom<String> for Digest {
    type Error = DigestError;

    fn try_from(text: String) -> Result<Self, DigestError> {
        text.parse()
    }
}

impl From<Digest> for String {
    fn from(d: Digest) -> String {
        d.to_string()
    }
}

/// A streaming hasher of one algorithm; as a writer it hashes what it is
/// given.
#[derive(Clone)]
pub enum DigestWriter {
    Sha256(Sha256),
    Sha512(Sha512),
}

impl DigestWriter {
    pub fn new(alg: Algorithm) -> Self {
        match alg {
            Algorithm::Sha256 => Self::Sha256(Sha256::new()),
            Algorithm::Sha512 => Self::Sha512(Sha512::new()),
        }
    }

    /// A hasher for the algorithm of `digest`, to check content against it.
    pub fn for_digest(digest: &Digest) -> Self {
        Self::new(digest.alg())
    }

    pub fn alg(&self) -> Algorithm {
        match self {
            Self::Sha256(_) => Algorithm::Sha256,
            Self::Sha512(_) => Algorithm::Sha512,
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        match self {
            Self::Sha256(h) => h.update(data),
            Self::Sha512(h) => h.update(data),
        }
    }

    pub fn finalize(self) -> Digest {
        let (alg, bytes) = match self {
            Self::Sha256(h) => (Algorithm::Sha256, h.finalize().to_vec()),
            Self::Sha512(h) => (Algorithm::Sha512, h.finalize().to_vec()),
        };
        Digest::from_bytes(alg, &bytes).expect("a hash has the length of its algorithm")
    }
}

impl std::io::Write for DigestWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.update(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// What takes in the bytes of a stream to hash them.
pub trait Absorb {
    fn absorb(&mut self, data: &[u8]);
}

impl Absorb for DigestWriter {
    fn absorb(&mut self, data: &[u8]) {
        self.update(data);
    }
}

/// A hash computed on a thread of its own: what it is given is gathered into
/// pieces and handed over, so the thread that reads or writes the bytes does
/// not wait for the hash of them (the hash of a long stream costs about as
/// much as reading it), and the hashes of the same bytes run side by side.
/// The hasher comes back with [`Offloaded::finish`], to be finalized.
pub struct Offloaded<H: Absorb + Send + 'static> {
    /// The pieces to hash (none once the last was handed over)
    pieces: Option<std::sync::mpsc::SyncSender<Vec<u8>>>,
    /// The pieces the thread has hashed, to fill again
    spent: std::sync::mpsc::Receiver<Vec<u8>>,
    gathering: Vec<u8>,
    thread: Option<std::thread::JoinHandle<H>>,
    /// The hasher itself, when no thread could be made: it hashes here
    inline: Option<H>,
}

impl<H: Absorb + Send + 'static> Offloaded<H> {
    /// The size of a piece.
    const PIECE: usize = 256 << 10;
    /// How many pieces wait for the thread.
    const WAITING: usize = 8;

    /// A hash on a thread of its own; when none can be made (a limit on the
    /// tasks of the process or the user), it is computed by `update`.
    pub fn new(hasher: H) -> Self {
        let (pieces, work) = std::sync::mpsc::sync_channel::<Vec<u8>>(Self::WAITING);
        let (back, spent) = std::sync::mpsc::channel();
        let (give, take) = std::sync::mpsc::channel::<H>();
        let thread = std::thread::Builder::new()
            .name("hash".into())
            .spawn(move || {
                let Ok(mut hasher) = take.recv() else {
                    unreachable!("the hasher is given as soon as the thread exists")
                };
                for mut piece in work {
                    hasher.absorb(&piece);
                    piece.clear();
                    let _ = back.send(piece);
                }
                hasher
            });
        let Ok(thread) = thread else {
            return Self::here(hasher);
        };
        // (the thread is waiting for it: the receiver is alive)
        let _ = give.send(hasher);
        Self {
            pieces: Some(pieces),
            spent,
            gathering: Vec::with_capacity(Self::PIECE),
            thread: Some(thread),
            inline: None,
        }
    }

    /// A hash computed by `update` itself.
    fn here(hasher: H) -> Self {
        Self {
            pieces: None,
            spent: std::sync::mpsc::channel().1,
            gathering: Vec::new(),
            thread: None,
            inline: Some(hasher),
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        if let Some(hasher) = &mut self.inline {
            hasher.absorb(data);
            return;
        }
        self.gathering.extend_from_slice(data);
        if self.gathering.len() >= Self::PIECE {
            self.hand_over();
        }
    }

    fn hand_over(&mut self) {
        let next = self
            .spent
            .try_recv()
            .unwrap_or_else(|_| Vec::with_capacity(Self::PIECE));
        let piece = std::mem::replace(&mut self.gathering, next);
        if let Some(pieces) = &self.pieces {
            // (a thread that is gone has panicked: `finish` says so)
            let _ = pieces.send(piece);
        }
    }

    pub fn finish(mut self) -> H {
        if let Some(hasher) = self.inline.take() {
            return hasher;
        }
        self.hand_over();
        self.pieces = None;
        self.thread
            .take()
            .expect("the thread is joined once")
            .join()
            .expect("the hash thread does not panic")
    }
}

/// The algorithm of the image whose manifest (or index) is `body`, as its
/// own descriptors say: that of its configuration, or that of the manifests
/// of an index when they all have one.  sha256 for anything else (a body
/// that is no manifest is refused when it is read).  The id of an image
/// follows it: a manifest fetched by a tag from a registry that addresses
/// manifests by sha256 is named by its sha512 when its configuration is one.
pub fn image_algorithm(body: &[u8]) -> Algorithm {
    #[derive(serde::Deserialize)]
    struct Named {
        digest: String,
    }
    #[derive(serde::Deserialize)]
    struct Own {
        config: Option<Named>,
        #[serde(default)]
        manifests: Vec<Named>,
    }
    let alg = |d: &Named| d.digest.parse::<Digest>().ok().map(|d| d.alg());
    let Ok(own) = serde_json::from_slice::<Own>(body) else {
        return Algorithm::Sha256;
    };
    let found = match &own.config {
        Some(config) => alg(config),
        None => {
            let mut algs = own.manifests.iter().map(alg);
            match algs.next().flatten() {
                Some(first) if algs.all(|a| a == Some(first)) => Some(first),
                _ => None,
            }
        }
    };
    found.unwrap_or(Algorithm::Sha256)
}

/// An id or a digest without its algorithm: `abc` for `sha512:abc`.
pub fn without_algorithm(text: &str) -> &str {
    text.strip_prefix("sha256:")
        .or_else(|| text.strip_prefix("sha512:"))
        .unwrap_or(text)
}

/// The TOC field `fsverity` of zstd:chunked layers: `<alg>-12:<hex>`.
pub fn parse_toc_fsverity(text: &str) -> Option<Digest> {
    let (kind, digits) = text.split_once(':')?;
    let alg = Algorithm::from_name(kind.strip_suffix("-12")?).ok()?;
    Digest::from_hex_kind(Kind::FsVerity { alg, log_block: 12 }, digits).ok()
}

/// The value of `io.containers.composefs.digest`: `<alg>:<hex>` of an
/// fs-verity digest with 4096-byte blocks.  Anything else is none.
pub fn parse_composefs_annotation(text: &str) -> Option<Digest> {
    Digest::parse(text)
        .ok()
        .filter(|d| !d.is_fsverity())
        .map(|d| d.as_fsverity())
}

/// A reader or a writer that hashes and counts what goes through it.
pub struct Hashing<T> {
    pub inner: T,
    pub hasher: DigestWriter,
    /// The bytes that went through.
    pub size: u64,
}

impl<T> Hashing<T> {
    pub fn new(alg: Algorithm, inner: T) -> Self {
        Self {
            inner,
            hasher: DigestWriter::new(alg),
            size: 0,
        }
    }

    /// Count and hash `data` as if it went through (a reader that skips holes
    /// counts and hashes their zeros through here).
    pub fn account(&mut self, data: &[u8]) {
        self.hasher.update(data);
        self.size += data.len() as u64;
    }
}

impl<R: std::io::Read> std::io::Read for Hashing<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.account(&buf[..n]);
        Ok(n)
    }
}

impl<W: std::io::Write> std::io::Write for Hashing<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.account(&buf[..n]);
        Ok(n)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_offloaded_hash_is_the_hash_of_what_it_was_given() {
        let data: Vec<u8> = (0..3_000_000u32).map(|i| (i % 251) as u8).collect();
        for alg in [Algorithm::Sha256, Algorithm::Sha512] {
            let mut h = Offloaded::new(DigestWriter::new(alg));
            for piece in data.chunks(100_003) {
                h.update(piece);
            }
            assert_eq!(h.finish().finalize(), Digest::of(alg, &data));
        }
        assert_eq!(
            Offloaded::new(DigestWriter::new(Algorithm::Sha256))
                .finish()
                .finalize(),
            Digest::empty(Algorithm::Sha256)
        );
    }

    #[test]
    fn a_hash_without_a_thread_is_computed_in_place() {
        let data: Vec<u8> = (0..1_000_000u32).map(|i| (i % 241) as u8).collect();
        let mut h = Offloaded::here(DigestWriter::new(Algorithm::Sha256));
        for piece in data.chunks(65_537) {
            h.update(piece);
        }
        assert_eq!(h.finish().finalize(), Digest::of(Algorithm::Sha256, &data));
    }

    #[test]
    fn hashing_counts_and_hashes_what_goes_through() {
        use std::io::{Read, Write};
        let data = b"the quick brown fox";
        let mut r = Hashing::new(Algorithm::Sha256, &data[..]);
        let mut sink = Vec::new();
        r.read_to_end(&mut sink).unwrap();
        assert_eq!(sink, data);
        assert_eq!(r.size, data.len() as u64);
        assert_eq!(r.hasher.finalize(), Digest::of(Algorithm::Sha256, data));
        let mut w = Hashing::new(Algorithm::Sha512, Vec::new());
        w.write_all(data).unwrap();
        w.flush().unwrap();
        assert_eq!((w.size, w.inner.as_slice()), (data.len() as u64, &data[..]));
        assert_eq!(w.hasher.finalize(), Digest::of(Algorithm::Sha512, data));
    }

    #[test]
    fn a_file_is_hashed_by_position_up_to_a_limit() {
        use std::io::{Seek, SeekFrom, Write};
        let mut f = tempfile::tempfile().unwrap();
        f.write_all(&[7u8; 1000]).unwrap();
        f.seek(SeekFrom::Start(500)).unwrap();
        let alg = Algorithm::Sha256;
        let (d, n) = Digest::of_file_at(alg, &f, u64::MAX).unwrap();
        assert_eq!((d, n), (Digest::of(alg, &[7u8; 1000]), 1000));
        let (d, n) = Digest::of_file_at(alg, &f, 300).unwrap();
        assert_eq!((d, n), (Digest::of(alg, &[7u8; 300]), 300));
        assert_eq!(Digest::of_file_at(alg, &f, 0).unwrap().1, 0);
        // (the offset of the file was not moved)
        assert_eq!(f.stream_position().unwrap(), 500);
    }

    #[test]
    fn a_creation_names_sha256_or_sha512_and_nothing_else() {
        assert_eq!(Algorithm::for_creation("sha256"), Ok(Algorithm::Sha256));
        assert_eq!(Algorithm::for_creation("sha512"), Ok(Algorithm::Sha512));
        for bad in [
            "",
            "SHA256",
            "sha384",
            "md5",
            "sha256:",
            "fsverity-sha256-12",
        ] {
            let e = Algorithm::for_creation(bad).unwrap_err();
            assert!(
                e.contains(&format!("`{bad}`")) && e.contains("sha256 or sha512"),
                "{bad}: {e}"
            );
        }
    }

    const EMPTY256: &str =
        "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    const EMPTY512: &str = "sha512:cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e";
    const ABC256: &str = "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    const ABC512: &str = "sha512:ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f";

    #[test]
    fn known_vectors() {
        assert_eq!(Digest::empty(Algorithm::Sha256).to_string(), EMPTY256);
        assert_eq!(Digest::empty(Algorithm::Sha512).to_string(), EMPTY512);
        assert_eq!(Digest::of(Algorithm::Sha256, b"abc").to_string(), ABC256);
        assert_eq!(Digest::of(Algorithm::Sha512, b"abc").to_string(), ABC512);
    }

    #[test]
    fn round_trip() {
        for text in [EMPTY256, EMPTY512, ABC256, ABC512] {
            let d: Digest = text.parse().unwrap();
            assert_eq!(d.to_string(), text);
            assert_eq!(d.plain(), text);
            let json = serde_json::to_string(&d).unwrap();
            assert_eq!(json, format!("\"{text}\""));
            assert_eq!(serde_json::from_str::<Digest>(&json).unwrap(), d);
        }
        let v = Digest::parse_fsverity(&format!("fsverity-sha512-12:{}", &EMPTY512[7..])).unwrap();
        assert!(v.is_fsverity());
        assert_eq!(
            v.to_string(),
            format!("fsverity-sha512-12:{}", &EMPTY512[7..])
        );
        assert_ne!(v, EMPTY512.parse().unwrap());
        assert_eq!(v.plain(), EMPTY512);
    }

    #[test]
    fn a_key_is_a_content_digest_or_an_fsverity_one() {
        let hex = &EMPTY256[7..];
        let content = Digest::parse_key(EMPTY256).unwrap();
        let object = Digest::parse_key(&format!("fsverity-sha256-12:{hex}")).unwrap();
        assert!(!content.is_fsverity() && object.is_fsverity());
        assert_ne!(content, object);
        assert_eq!(
            Digest::parse_key(EMPTY512).unwrap().alg(),
            Algorithm::Sha512
        );
        let hex512 = &EMPTY512[7..];
        assert_eq!(
            Digest::parse_key(&format!("fsverity-sha512-12:{hex512}"))
                .unwrap()
                .to_string(),
            format!("fsverity-sha512-12:{hex512}")
        );
        // the digits tell the algorithm, in either kind
        for bad in [
            format!("fsverity-sha512-12:{hex}"),
            format!("fsverity-sha256-12:{hex512}"),
            format!("fsverity-sha256-16:{hex}"),
            format!("fsverity-sha384-12:{hex}"),
            format!("fsverity-sha256:{hex}"),
            format!("sha512:{hex}"),
            String::new(),
        ] {
            assert!(Digest::parse_key(&bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn refusals() {
        let ok = |s: &str| s.parse::<Digest>().is_ok();
        assert!(ok(EMPTY256) && ok(EMPTY512));
        assert!(!ok(""));
        assert!(!ok("sha256"));
        assert!(!ok("sha256:"));
        assert!(!ok("sha256:abc"));
        assert!(!ok(&EMPTY256.to_uppercase()));
        // (the digits are read in pairs: a bad digit in either place)
        assert!(!ok(&format!("{}g{}", &EMPTY256[..20], &EMPTY256[21..])));
        assert!(!ok(&format!("{}g{}", &EMPTY256[..21], &EMPTY256[22..])));
        assert!(!ok(&format!("{}é{}", &EMPTY256[..20], &EMPTY256[22..])));
        assert!(!ok(&EMPTY256.replace("e3b0", "E3b0")));
        assert!(!ok(&format!("sha512:{}", &EMPTY256[7..])));
        assert!(!ok(&format!("sha256:{}", &EMPTY512[7..])));
        assert!(!ok(&format!("blake3:{}", &EMPTY256[7..])));
        assert!(!ok(&format!("sha384:{}", "0".repeat(96))));
        assert!(!ok(&format!("sha256:../../etc/{}", "0".repeat(49))));
        assert!(!ok(&format!("sha256:{}\u{e9}", "0".repeat(62))));
        assert!(!ok(&format!("fsverity-sha256-13:{}", &EMPTY256[7..])));
        assert!(!ok(&format!("fsverity-md5-12:{}", &EMPTY256[7..])));
        // the fs-verity text is no OCI digest, and has its own parser
        let verity = format!("fsverity-sha256-12:{}", &EMPTY256[7..]);
        assert!(!ok(&verity));
        assert!(serde_json::from_str::<Digest>(&format!("\"{verity}\"")).is_err());
        assert!(Digest::parse_fsverity(&verity).is_ok());
        for bad in [
            EMPTY256.to_string(),
            format!("fsverity-sha256-13:{}", &EMPTY256[7..]),
            format!("fsverity-sha512-12:{}", &EMPTY256[7..]),
            format!("fsverity-blake3-12:{}", &EMPTY256[7..]),
        ] {
            assert!(Digest::parse_fsverity(&bad).is_err(), "{bad}");
        }
        assert!(!ok(&format!("{EMPTY256}\n")));
    }

    #[test]
    fn errors_name_the_value() {
        let e = "blake3:00".parse::<Digest>().unwrap_err().to_string();
        assert!(e.contains("blake3") && e.contains("sha512"), "{e}");
        let e = "sha512:00".parse::<Digest>().unwrap_err().to_string();
        assert!(e.contains("128"), "{e}");
    }

    #[test]
    fn verify_uses_the_algorithm_of_the_digest() {
        let d512: Digest = ABC512.parse().unwrap();
        assert!(d512.verify(b"abc"));
        assert!(!d512.verify(b"abd"));
        let d256: Digest = ABC256.parse().unwrap();
        assert!(d256.verify(b"abc") && !d256.verify(b"abd"));
        // the same bytes as an fs-verity digest are not the hash of the data
        assert!(!d256.as_fsverity().verify(b"abc"));
        assert!(!d512.as_fsverity().verify(b"abc"));
    }

    #[test]
    fn writer_and_reader_agree() {
        use std::io::Write;
        let mut w = DigestWriter::new(Algorithm::Sha512);
        w.write_all(b"a").unwrap();
        w.write_all(b"bc").unwrap();
        assert_eq!(w.finalize().to_string(), ABC512);
        let d = Digest::of_reader(Algorithm::Sha256, &b"abc"[..]).unwrap();
        assert_eq!(d.to_string(), ABC256);
    }

    #[test]
    fn order_and_hash() {
        let a: Digest = ABC256.parse().unwrap();
        let b: Digest = ABC512.parse().unwrap();
        let set: std::collections::BTreeSet<_> = [b, a, a].into_iter().collect();
        assert_eq!(set.len(), 2);
        assert_eq!(set.iter().next(), Some(&a));
        let h: std::collections::HashSet<_> = [a, b].into_iter().collect();
        assert!(h.contains(&a) && h.contains(&b));
    }

    #[test]
    fn file_names_do_not_collide() {
        let c: Digest = EMPTY256.parse().unwrap();
        let v = c.as_fsverity();
        assert_ne!(c.file_name(), v.file_name());
        assert_ne!(c.file_name(), Digest::empty(Algorithm::Sha512).file_name());
        assert_eq!(c.short().len(), 12);
    }

    #[test]
    fn an_image_id_is_the_hex_of_its_digest() {
        for text in [ABC256, ABC512] {
            let d: Digest = text.parse().unwrap();
            assert_eq!(Digest::from_id(&d.hex()).unwrap(), d);
        }
        let e = Digest::from_id("abc").unwrap_err().to_string();
        assert!(e.contains("64 (sha256) or 128 (sha512)"), "{e}");
        assert!(Digest::from_id(&"a".repeat(96)).is_err());
        assert!(Digest::from_id(&"A".repeat(64)).is_err());
    }

    #[test]
    fn boundary_forms() {
        let hex256 = &EMPTY256[7..];
        let hex512 = &EMPTY512[7..];
        let t = parse_toc_fsverity(&format!("sha256-12:{hex256}")).unwrap();
        assert!(t.is_fsverity() && t.alg() == Algorithm::Sha256);
        let t = parse_toc_fsverity(&format!("sha512-12:{hex512}")).unwrap();
        assert_eq!(t.alg(), Algorithm::Sha512);
        assert!(parse_toc_fsverity(&format!("sha256-16:{hex256}")).is_none());
        assert!(parse_toc_fsverity(&format!("sha512-12:{hex256}")).is_none());
        assert_eq!(
            parse_composefs_annotation(EMPTY512).unwrap().alg(),
            Algorithm::Sha512
        );
        assert!(parse_composefs_annotation(&format!("sha512:{hex256}")).is_none());
        assert!(parse_composefs_annotation("sha384:00").is_none());
    }
}
