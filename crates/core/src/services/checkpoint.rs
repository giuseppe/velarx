// SPDX-License-Identifier: Apache-2.0
//! Checkpoints shared between nodes: the archive of `container
//! checkpoint --export` cut in pieces, each encrypted with a key of its
//! own share and named by the digest of what is encrypted, and a manifest
//! that lists them, encrypted the same way and named by its digest.  The
//! key is only in the reference (`sha256:HEX:SIZE:KEY`): a node that serves
//! or relays the pieces learns nothing of the process memory they hold.
//!
//! A node that shares an archive keeps the pieces in `storage/shared`
//! (0700, its files 0600; outside the store and its collection), serves
//! those of the live shares as any content by digest, and announces them;
//! another node restores it by its reference: the manifest and the pieces
//! come from its content sources (a peer source, a directory) like the
//! chunks of a pull, each checked against its digest and size and
//! authenticated by its decryption, the archive against the digest the
//! manifest gives.  It is trusted no more for that: it goes to `restore
//! --import`, which extracts an archive of any origin within its limits.

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use velarx_types::digest::{Algorithm, Digest, DigestWriter};

/// The algorithm of the digests of a checkpoint a node shares.
const ALG: Algorithm = Algorithm::Sha256;

/// The size of the pieces of an archive, before encryption.
pub const PIECE: u64 = 4 * 1024 * 1024;

/// What the encryption adds to a piece (the tag of ChaCha20-Poly1305).
const TAG: usize = 16;

/// The largest manifest.
const MAX_MANIFEST: u64 = 1024 * 1024;

/// The nonce of the manifest; a piece's is its index.
const MANIFEST_NONCE: u64 = u64::MAX;

fn nonce(index: u64) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[4..].copy_from_slice(&index.to_be_bytes());
    n
}

fn seal(key: &[u8; 32], index: u64, data: &[u8]) -> io::Result<Vec<u8>> {
    ChaCha20Poly1305::new(Key::from_slice(key))
        .encrypt(Nonce::from_slice(&nonce(index)), data)
        .map_err(|_| io::Error::other("a piece that does not seal"))
}

fn open(key: &[u8; 32], index: u64, data: &[u8]) -> Result<Vec<u8>, String> {
    if data.len() < TAG {
        return Err("a piece shorter than its tag".into());
    }
    ChaCha20Poly1305::new(Key::from_slice(key))
        .decrypt(Nonce::from_slice(&nonce(index)), data)
        .map_err(|_| "a piece that does not decrypt with the key of the reference".to_string())
}

/// The version of the manifest: 1 until the first release.
const MANIFEST_VERSION: u32 = 1;

/// The list of the pieces of an archive.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    pub version: u32,
    /// The digest of the whole archive (in clear)
    pub archive: Digest,
    pub size: u64,
    /// The encrypted pieces, in order
    pub pieces: Vec<Piece>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Piece {
    pub digest: Digest,
    pub size: u64,
}

impl Manifest {
    /// Whether the manifest is one this node can take: its pieces make its
    /// size, no larger than an archive may be.
    fn check(&self) -> Result<(), String> {
        if self.version != MANIFEST_VERSION {
            return Err(format!("a manifest of version {}", self.version));
        }
        if self.size == 0 || self.size > super::CHECKPOINT_UPLOAD_MAX {
            return Err(format!("an archive of {} bytes", self.size));
        }
        let mut total = 0u64;
        for p in &self.pieces {
            if p.size <= TAG as u64 || p.size > PIECE + TAG as u64 {
                return Err("a piece of the manifest is not one".into());
            }
            total = total.saturating_add(p.size - TAG as u64);
        }
        if total != self.size {
            return Err("the pieces of the manifest do not make its size".into());
        }
        Ok(())
    }
}

/// What names a shared checkpoint: the digest and the size of its
/// manifest, and the key of its share, `ALGORITHM:HEX:SIZE:KEY`.
#[derive(Clone, PartialEq, Eq)]
pub struct Reference {
    pub manifest: Digest,
    pub size: u64,
    key: [u8; 32],
}

impl std::fmt::Debug for Reference {
    // the key is not for logs
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Reference({}:{})", self.manifest, self.size)
    }
}

impl Reference {
    pub fn parse(s: &str) -> Result<Self, String> {
        let bad =
            || "not the reference of a shared checkpoint (ALGORITHM:HEX:SIZE:KEY)".to_string();
        let mut parts = s.rsplitn(3, ':');
        let (key, size, d) = (parts.next(), parts.next(), parts.next());
        let (Some(key), Some(size), Some(d)) = (key, size, d) else {
            return Err(bad());
        };
        let size: u64 = size.parse().map_err(|_| bad())?;
        let key: [u8; 32] = hex::decode(key)
            .ok()
            .and_then(|k| k.try_into().ok())
            .ok_or_else(bad)?;
        let manifest: Digest = d.parse().map_err(|_| bad())?;
        if size == 0 || size > MAX_MANIFEST {
            return Err(bad());
        }
        Ok(Self {
            manifest,
            size,
            key,
        })
    }

    /// The manifest, without the key: what may be logged.
    pub fn public(&self) -> String {
        format!("{}:{}", self.manifest, self.size)
    }
}

impl std::fmt::Display for Reference {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}:{}:{}",
            self.manifest,
            self.size,
            hex::encode(self.key)
        )
    }
}

/// What this node keeps of a share: its reference, and the manifest in
/// clear (its pieces, to serve and to remove).
#[derive(Serialize, Deserialize)]
struct Record {
    reference: String,
    manifest: Manifest,
}

/// The checkpoints this node shares: the encrypted pieces and manifests by
/// digest (`content/HEX`), and a record of each share (`shares/HEX`).
pub struct SharedCheckpoints {
    root: PathBuf,
    content: PathBuf,
    shares: PathBuf,
    /// The digests of the live shares, kept by a holder that is told when
    /// the shares change ([`Self::cached`]); none: read from the disk
    cache: Option<Cache>,
}

/// The live digests, read once, until [`SharedCheckpoints::invalidate`].
#[derive(Default)]
struct Cache {
    live: std::sync::Mutex<Option<Arc<std::collections::HashSet<Digest>>>>,
    /// Counts the invalidations: a read that started before one is not kept
    generation: std::sync::atomic::AtomicU64,
    /// How many times the records were read to fill it
    #[cfg(test)]
    reads: std::sync::atomic::AtomicUsize,
}

/// A share and an unshare of this process do not cross on a piece.
static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// A file of `dir`, 0600, written whole, then renamed into place.
fn write_private(dir: &Path, name: &str, data: &[u8]) -> io::Result<()> {
    let mut tmp = tempfile::Builder::new()
        .prefix(".tmp-")
        .permissions(std::fs::Permissions::from_mode(0o600))
        .tempfile_in(dir)?;
    tmp.as_file()
        .set_permissions(std::fs::Permissions::from_mode(0o600))?;
    tmp.write_all(data)?;
    tmp.as_file().sync_all()?;
    tmp.persist(dir.join(name)).map_err(|e| e.error)?;
    Ok(())
}

fn private_dir(p: &Path) -> io::Result<()> {
    std::fs::create_dir_all(p)?;
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o700))
}

impl SharedCheckpoints {
    /// The shared checkpoints of the store `storage_root`.
    pub fn new(storage_root: &Path) -> io::Result<Self> {
        let root = storage_root.join("shared");
        let this = Self {
            content: root.join("content"),
            shares: root.join("shares"),
            root,
            cache: None,
        };
        for d in [&this.root, &this.content, &this.shares] {
            if !d.is_dir() {
                private_dir(d)?;
            }
        }
        Ok(this)
    }

    /// These shared checkpoints, which keep what [`Self::open`] needs of
    /// the records instead of reading them all for each piece.  For a holder
    /// that calls [`Self::invalidate`] whenever the shares directory changes
    /// (another process shares and unshares too); this process's own shares
    /// and unshares do it themselves.
    pub fn cached(mut self) -> Self {
        self.cache = Some(Cache::default());
        self
    }

    /// Forget what was kept of the records: the shares changed.
    pub fn invalidate(&self) {
        if let Some(cache) = &self.cache {
            cache
                .generation
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            *cache.live.lock().unwrap_or_else(|e| e.into_inner()) = None;
        }
    }

    /// The digests of the live shares: kept, if this is a cached holder.
    fn live(&self) -> Arc<std::collections::HashSet<Digest>> {
        use std::sync::atomic::Ordering;
        let Some(cache) = &self.cache else {
            return Arc::new(self.read_live());
        };
        if let Some(live) = cache.live.lock().unwrap_or_else(|e| e.into_inner()).clone() {
            return live;
        }
        let generation = cache.generation.load(Ordering::SeqCst);
        let live = Arc::new(self.read_live());
        #[cfg(test)]
        cache.reads.fetch_add(1, Ordering::SeqCst);
        let mut kept = cache.live.lock().unwrap_or_else(|e| e.into_inner());
        // (not if the shares changed while they were read)
        if cache.generation.load(Ordering::SeqCst) == generation {
            *kept = Some(live.clone());
        }
        live
    }

    /// The shared checkpoints of the store, when the daemon starts: the
    /// modes are set again (0700, 0600), and what an interrupted share
    /// left is removed (work directories, pieces of no share).  Not while
    /// shares may be in progress.
    pub fn open_at_start(storage_root: &Path) -> io::Result<Self> {
        let this = Self::new(storage_root)?;
        let _guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        for d in [&this.root, &this.content, &this.shares] {
            private_dir(d)?;
        }
        this.sweep()?;
        Ok(this)
    }

    /// The modes of what is there, and no piece without its share.
    fn sweep(&self) -> io::Result<()> {
        // the work directories of shares that did not finish
        for e in std::fs::read_dir(&self.root)?.flatten() {
            if e.file_name().to_string_lossy().starts_with(".tmp-") {
                let _ = velarx_base::tree::remove_dir_all(e.path());
            }
        }
        let live: std::collections::HashSet<String> =
            self.read_live().iter().map(Digest::file_name).collect();
        for dir in [&self.content, &self.shares] {
            for e in std::fs::read_dir(dir)?.flatten() {
                let name = e.file_name().to_string_lossy().into_owned();
                let meta = e.path().symlink_metadata()?;
                if !meta.is_file() || name.starts_with(".tmp-") {
                    let _ = if meta.is_dir() {
                        velarx_base::tree::remove_dir_all(e.path())
                    } else {
                        std::fs::remove_file(e.path())
                    };
                    continue;
                }
                if *dir == self.content && !live.contains(&name) {
                    std::fs::remove_file(e.path())?;
                    continue;
                }
                if meta.permissions().mode() & 0o777 != 0o600 {
                    std::fs::set_permissions(e.path(), std::fs::Permissions::from_mode(0o600))?;
                }
            }
        }
        Ok(())
    }

    /// The records of the shares.
    fn records(&self) -> Vec<Record> {
        let Ok(dir) = std::fs::read_dir(&self.shares) else {
            return Vec::new();
        };
        dir.flatten()
            .filter(|e| !e.file_name().to_string_lossy().starts_with(".tmp-"))
            .filter_map(|e| serde_json::from_slice(&std::fs::read(e.path()).ok()?).ok())
            .collect()
    }

    /// The digests of the live shares, as the records say.
    fn read_live(&self) -> std::collections::HashSet<Digest> {
        let mut live = std::collections::HashSet::new();
        for r in self.records() {
            if let Ok(reference) = Reference::parse(&r.reference) {
                live.insert(reference.manifest);
            }
            live.extend(r.manifest.pieces.into_iter().map(|p| p.digest));
        }
        live
    }

    fn content_path(&self, d: &Digest) -> PathBuf {
        self.content.join(d.file_name())
    }

    /// Share the archive at `archive`: its encrypted pieces and manifest,
    /// and the digests to announce.  Nothing is left of a share that fails.
    pub fn share(&self, archive: &Path) -> io::Result<(Reference, Vec<String>)> {
        let mut key = [0u8; 32];
        velarx_base::random::fill(&mut key);
        // everything in a directory of its own until the manifest is made
        let work = tempfile::Builder::new()
            .prefix(".tmp-")
            .tempdir_in(&self.root)?;
        std::fs::set_permissions(work.path(), std::fs::Permissions::from_mode(0o700))?;
        let mut file = File::open(archive)?;
        let mut whole = DigestWriter::new(ALG);
        let mut pieces = Vec::new();
        let mut size = 0u64;
        let mut buf = vec![0u8; PIECE as usize];
        loop {
            let mut n = 0;
            while n < buf.len() {
                let r = file.read(&mut buf[n..])?;
                if r == 0 {
                    break;
                }
                n += r;
            }
            if n == 0 {
                break;
            }
            whole.update(&buf[..n]);
            size += n as u64;
            if size > super::CHECKPOINT_UPLOAD_MAX {
                return Err(io::Error::other("the archive is too large to share"));
            }
            let sealed = seal(&key, pieces.len() as u64, &buf[..n])?;
            let d = Digest::of(ALG, &sealed);
            write_private(work.path(), &d.file_name(), &sealed)?;
            pieces.push(Piece {
                digest: d,
                size: sealed.len() as u64,
            });
        }
        let manifest = Manifest {
            version: MANIFEST_VERSION,
            archive: whole.finalize(),
            size,
            pieces,
        };
        manifest.check().map_err(io::Error::other)?;
        let sealed = seal(&key, MANIFEST_NONCE, &serde_json::to_vec(&manifest)?)?;
        let m = Digest::of(ALG, &sealed);
        write_private(work.path(), &m.file_name(), &sealed)?;
        let reference = Reference {
            manifest: m,
            size: sealed.len() as u64,
            key,
        };
        let record = serde_json::to_vec(&Record {
            reference: reference.to_string(),
            manifest: manifest.clone(),
        })?;

        let _guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut digests = vec![reference.manifest];
        digests.extend(manifest.pieces.iter().map(|p| p.digest));
        for d in &digests {
            let to = self.content_path(d);
            if !to.exists() {
                std::fs::rename(work.path().join(d.file_name()), &to)?;
            }
        }
        // the share exists once its record does
        write_private(&self.shares, &reference.manifest.file_name(), &record)?;
        self.invalidate();
        Ok((reference, digests.iter().map(Digest::to_string).collect()))
    }

    /// The file of a piece or a manifest of a live share, and its size.  The
    /// shares are read from the disk, not from what this process knows (the
    /// daemon, another process, shares and unshares), unless the holder keeps
    /// them and is told of the changes ([`Self::cached`]).
    pub fn open(&self, d: &str) -> Option<(File, u64)> {
        let d: Digest = d.parse().ok()?;
        let d = &d;
        if !self.live().contains(d) {
            return None;
        }
        // (the file itself, never what a link names; checked once open)
        let file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(self.content_path(d))
            .ok()?;
        let meta = file.metadata().ok()?;
        if !meta.is_file() || meta.len() > velarx_storage::MAX_SERVED_BYTES as u64 {
            return None;
        }
        Some((file, meta.len()))
    }

    /// The manifests and the pieces of the live shares, as the disk has
    /// them: to announce.
    pub fn announced(&self) -> (Vec<String>, Vec<String>) {
        let mut manifests = Vec::new();
        let mut digests = std::collections::HashSet::new();
        for r in self.records() {
            if let Ok(reference) = Reference::parse(&r.reference) {
                digests.insert(reference.manifest);
                manifests.push(reference.manifest.to_string());
            }
            digests.extend(r.manifest.pieces.into_iter().map(|p| p.digest));
        }
        (
            manifests,
            digests.into_iter().map(|d| d.to_string()).collect(),
        )
    }

    /// The directory of the records of the shares: it changes when a
    /// checkpoint is shared or unshared.
    pub fn shares_dir(&self) -> &Path {
        &self.shares
    }

    /// The references of the checkpoints this node shares.
    pub fn list(&self) -> Vec<Reference> {
        self.records()
            .iter()
            .filter_map(|r| Reference::parse(&r.reference).ok())
            .collect()
    }

    /// Stop sharing the checkpoint whose manifest is `manifest` (a digest):
    /// its manifest, and the pieces no other share has.  False when it is not
    /// shared.
    pub fn unshare_manifest(&self, manifest: &str) -> io::Result<bool> {
        let Ok(manifest) = manifest.parse::<Digest>() else {
            return Ok(false);
        };
        let _guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let record = self.shares.join(manifest.file_name());
        let Ok(data) = std::fs::read(&record) else {
            return Ok(false);
        };
        let gone: Record = serde_json::from_slice(&data)?;
        std::fs::remove_file(&record)?;
        self.invalidate();
        let kept = self.read_live();
        for d in std::iter::once(manifest).chain(gone.manifest.pieces.into_iter().map(|p| p.digest))
        {
            if !kept.contains(&d) {
                match std::fs::remove_file(self.content_path(&d)) {
                    Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(e),
                    _ => {}
                }
            }
        }
        Ok(true)
    }
}

/// Where the blobs of a shared checkpoint come from: the fetchers of
/// `[pull] sources` before the registry
/// ([`crate::services::image::ImageService::source_blob`]).
#[async_trait::async_trait]
pub trait Blobs: Sync {
    /// The blob `digest` of `size` bytes, checked against its digest; none
    /// when nobody has it.
    async fn blob(&self, digest: &Digest, size: u64) -> Option<Vec<u8>>;
}

#[async_trait::async_trait]
impl Blobs for crate::services::image::ImageService {
    async fn blob(&self, digest: &Digest, size: u64) -> Option<Vec<u8>> {
        self.source_blob(digest, size).await
    }
}

/// Fetch the archive of the shared checkpoint `reference` from `blobs` into
/// the file `dest` (made 0600): the manifest, its pieces (each checked
/// against its digest and size, and decrypted with the key of the
/// reference), the whole against the digest of the manifest.
pub async fn fetch(blobs: &dyn Blobs, reference: &Reference, dest: &Path) -> Result<(), String> {
    let sealed = blobs
        .blob(&reference.manifest, reference.size)
        .await
        .ok_or_else(|| format!("no source has the manifest {}", reference.public()))?;
    let json = open(&reference.key, MANIFEST_NONCE, &sealed)?;
    let manifest: Manifest =
        serde_json::from_slice(&json).map_err(|e| format!("the manifest: {e}"))?;
    manifest.check()?;

    let file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(dest)
        .map_err(|e| e.to_string())?;
    let mut at = 0u64;
    let mut places = Vec::with_capacity(manifest.pieces.len());
    for (i, p) in manifest.pieces.iter().enumerate() {
        places.push((i as u64, at));
        at += p.size - TAG as u64;
    }
    // (the file has its size: the zeros of the pieces stay holes)
    file.set_len(at).map_err(|e| e.to_string())?;
    for (p, (piece, offset)) in manifest.pieces.iter().zip(places) {
        let data = blobs.blob(&p.digest, p.size).await.ok_or_else(|| {
            format!(
                "no source has the piece {} of the {} pieces of the checkpoint",
                piece + 1,
                manifest.pieces.len()
            )
        })?;
        let clear = open(&reference.key, piece, &data)?;
        velarx_storage::write_at_sparse(&file, &clear, offset).map_err(|e| e.to_string())?;
    }
    file.sync_all().map_err(|e| e.to_string())?;
    drop(file);
    let path = dest.to_path_buf();
    let alg = manifest.archive.alg();
    let actual = tokio::task::spawn_blocking(move || -> io::Result<Digest> {
        Digest::of_reader(alg, File::open(&path)?)
    })
    .await
    .map_err(|e| e.to_string())?
    .map_err(|e| e.to_string())?;
    if actual != manifest.archive {
        return Err(format!(
            "the archive has the digest {actual}, not {}",
            manifest.archive
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sha(data: &[u8]) -> Digest {
        Digest::of(Algorithm::Sha256, data)
    }

    fn key_hex() -> String {
        "ab".repeat(32)
    }

    /// A piece opens with its key and index and with nothing else: a
    /// changed byte, another key and another index all fail.
    #[test]
    fn a_sealed_piece_opens_only_as_it_was_sealed() {
        let mut key = [0u8; 32];
        velarx_base::random::fill(&mut key);
        let sealed = seal(&key, 3, b"the bytes of a piece").unwrap();
        assert_eq!(sealed.len(), 20 + TAG);
        assert_eq!(open(&key, 3, &sealed).unwrap(), b"the bytes of a piece");
        assert!(open(&key, 4, &sealed).is_err());
        assert!(open(&[0u8; 32], 3, &sealed).is_err());
        let mut bad = sealed.clone();
        bad[0] ^= 1;
        assert!(open(&key, 3, &bad).is_err());
        assert!(open(&key, 3, &sealed[..TAG - 1]).is_err());
    }

    /// The cipher is ChaCha20-Poly1305 (RFC 8439, no associated data): the
    /// bytes of a piece sealed under the key 00..1f and the nonce of the
    /// index 3 (computed apart from this code: the ChaCha20 stream of
    /// openssl and a Poly1305 of the tag); AES-256-GCM seals them to other
    /// bytes.
    #[test]
    fn a_piece_is_sealed_with_chacha20_poly1305() {
        let key: [u8; 32] = std::array::from_fn(|i| i as u8);
        let known = "f42d799b5033d014fb6f936c9b86b6330eb92fa2505bcdabae019e6769219b39bca3ce42";
        let sealed = seal(&key, 3, b"the bytes of a piece").unwrap();
        let hex: String = sealed.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex, known);
        let bytes: Vec<u8> = (0..known.len() / 2)
            .map(|i| u8::from_str_radix(&known[2 * i..2 * i + 2], 16).unwrap())
            .collect();
        assert_eq!(open(&key, 3, &bytes).unwrap(), b"the bytes of a piece");
    }

    #[test]
    fn references_are_parsed() {
        let d = sha(b"m").to_string();
        let s = format!("{d}:42:{}", key_hex());
        let r = Reference::parse(&s).unwrap();
        assert_eq!((r.manifest.to_string(), r.size), (d.clone(), 42));
        assert_eq!(r.to_string(), s);
        assert_eq!(r.public(), format!("{d}:42"));
        assert!(!format!("{r:?}").contains(&key_hex()));
        for bad in [
            String::new(),
            format!("{d}:42"),
            format!("{d}:0:{}", key_hex()),
            format!("{d}:x:{}", key_hex()),
            format!("{d}:42:abcd"),
            format!("sha256:zz:42:{}", key_hex()),
            format!("{d}:{}:{}", MAX_MANIFEST + 1, key_hex()),
        ] {
            assert!(Reference::parse(&bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn manifests_are_checked() {
        let ok = Manifest {
            version: MANIFEST_VERSION,
            archive: sha(b"a"),
            size: 3,
            pieces: vec![
                Piece {
                    digest: sha(b"x"),
                    size: 1 + TAG as u64,
                },
                Piece {
                    digest: sha(b"y"),
                    size: 2 + TAG as u64,
                },
            ],
        };
        assert!(ok.check().is_ok());
        let mut bad = ok.clone();
        bad.size = 4;
        assert!(bad.check().is_err());
        let mut bad = ok.clone();
        bad.pieces[0].size = TAG as u64;
        assert!(bad.check().is_err());
        let mut bad = ok.clone();
        bad.version = 2;
        assert!(bad.check().is_err());
        let mut bad = ok;
        bad.archive = sha(b"b");
        assert!(bad.check().is_ok());
    }

    #[test]
    fn pieces_are_sealed_with_their_index() {
        let key = [7u8; 32];
        let s = seal(&key, 3, b"memory").unwrap();
        assert!(!s.windows(6).any(|w| w == b"memory"));
        assert_eq!(open(&key, 3, &s).unwrap(), b"memory");
        assert!(open(&key, 4, &s).is_err());
        assert!(open(&[8u8; 32], 3, &s).is_err());
        let mut tampered = s.clone();
        tampered[0] ^= 1;
        assert!(open(&key, 3, &tampered).is_err());
        assert!(open(&key, 3, &s[..TAG - 1]).is_err());
    }

    fn mode(p: &Path) -> u32 {
        p.symlink_metadata().unwrap().permissions().mode() & 0o777
    }

    /// The bytes of a piece the share gives.
    fn read(shared: &SharedCheckpoints, d: &str) -> Option<Vec<u8>> {
        let (mut file, len) = shared.open(d)?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).ok()?;
        assert_eq!(bytes.len() as u64, len);
        Some(bytes)
    }

    #[test]
    fn archives_are_shared_private_and_unshared() {
        let dir = tempfile::tempdir().unwrap();
        let shared = SharedCheckpoints::new(dir.path()).unwrap();
        let mut data = vec![7u8; (PIECE + 10) as usize];
        data[0] = 1;
        let a = dir.path().join("a.tar");
        std::fs::write(&a, &data).unwrap();
        let (r, digests) = shared.share(&a).unwrap();
        assert_eq!(digests.len(), 3);
        assert_eq!(shared.list(), vec![r.clone()]);
        // 0700 and 0600, and no byte of the archive in clear
        assert_eq!(mode(&dir.path().join("shared")), 0o700);
        for d in &digests {
            let p = shared.content_path(&d.parse().unwrap());
            assert_eq!(mode(&p), 0o600);
            let bytes = std::fs::read(&p).unwrap();
            assert!(!bytes.windows(64).any(|w| w.iter().all(|&b| b == 7)));
            assert_eq!(read(&shared, d).unwrap(), bytes);
        }
        // nothing but the pieces of live shares is served
        assert!(read(&shared, &sha(b"other").to_string()).is_none());
        // a second archive; the pieces of the first go with it
        let b = dir.path().join("b.tar");
        std::fs::write(&b, b"another archive").unwrap();
        let (r2, d2) = shared.share(&b).unwrap();
        assert!(shared.unshare_manifest(&r.manifest.to_string()).unwrap());
        assert!(!shared.unshare_manifest(&r.manifest.to_string()).unwrap());
        for d in &digests {
            assert!(read(&shared, d).is_none());
            assert!(!shared.content_path(&d.parse().unwrap()).exists());
        }
        assert!(read(&shared, &d2[0]).is_some());
        assert_eq!(shared.list(), vec![r2]);
    }

    /// A holder that keeps the records reads them once for many pieces,
    /// again after `invalidate` (another process shared), and never keeps
    /// what it read while the shares changed.
    #[test]
    fn a_cached_holder_reads_the_records_once_until_invalidated() {
        use std::sync::atomic::Ordering;
        let dir = tempfile::tempdir().unwrap();
        let shared = SharedCheckpoints::new(dir.path()).unwrap().cached();
        let other = SharedCheckpoints::new(dir.path()).unwrap();
        let reads = || shared.cache.as_ref().unwrap().reads.load(Ordering::SeqCst);
        let a = dir.path().join("a.tar");
        std::fs::write(&a, b"first").unwrap();
        let (r1, first) = other.share(&a).unwrap();
        for _ in 0..20 {
            assert!(read(&shared, &first[0]).is_some());
        }
        assert_eq!(reads(), 1, "20 lookups, one read of the records");

        // shared by another process: unseen until told
        std::fs::write(&a, b"second").unwrap();
        let (_, second) = other.share(&a).unwrap();
        assert!(read(&shared, &second[0]).is_none());
        shared.invalidate();
        assert!(read(&shared, &second[0]).is_some());
        assert_eq!(reads(), 2);

        // unshared by another process: told, so no longer given
        assert!(read(&shared, &first[0]).is_some());
        assert!(other.unshare_manifest(&r1.manifest.to_string()).unwrap());
        shared.invalidate();
        assert!(read(&shared, &first[0]).is_none());
        assert!(read(&shared, &second[0]).is_some());

        // its own shares need no telling
        std::fs::write(&a, b"third").unwrap();
        let (_, third) = shared.share(&a).unwrap();
        assert!(read(&shared, &third[0]).is_some());
    }

    #[test]
    fn what_an_interrupted_share_left_is_swept() {
        let dir = tempfile::tempdir().unwrap();
        let shared = SharedCheckpoints::new(dir.path()).unwrap();
        let a = dir.path().join("a.tar");
        std::fs::write(&a, b"archive").unwrap();
        let (r, digests) = shared.share(&a).unwrap();
        // a piece of no share, a work directory, a wrong mode
        let orphan = shared.content.join(sha(b"orphan").file_name());
        std::fs::write(&orphan, b"orphan").unwrap();
        std::fs::create_dir(shared.root.join(".tmp-x")).unwrap();
        std::fs::set_permissions(
            shared.content_path(&digests[0].parse().unwrap()),
            std::fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        std::fs::set_permissions(shared.root.clone(), std::fs::Permissions::from_mode(0o755))
            .unwrap();
        // opening it for a request leaves a share in progress alone
        let shared = SharedCheckpoints::new(dir.path()).unwrap();
        assert!(shared.root.join(".tmp-x").exists());
        assert!(orphan.exists());
        // the start sweeps
        let shared = SharedCheckpoints::open_at_start(dir.path()).unwrap();
        assert!(!orphan.exists());
        assert!(!shared.root.join(".tmp-x").exists());
        assert_eq!(
            mode(&shared.content_path(&digests[0].parse().unwrap())),
            0o600
        );
        assert_eq!(mode(&shared.root), 0o700);
        assert_eq!(shared.list(), vec![r]);
    }
}
