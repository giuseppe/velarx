// SPDX-License-Identifier: Apache-2.0
//! OCI artifacts: manifests whose layers are files, kept apart from
//! the images in an OCI image layout of their own, as podman's libartifact
//! keeps them (`index.json`, `blobs/ALGORITHM/...`, each name an
//! `org.opencontainers.image.ref.name` annotation of its manifest).
//!
//! Writers hold an exclusive lock of the store, readers a shared one; the
//! index is replaced by a rename, the blobs are staged in the store and
//! renamed to their digest once it is checked.

use serde_json::{json, Value};
use std::collections::HashSet;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use velarx_types::digest::{Algorithm, Digest, DigestWriter};

pub const MANIFEST_MEDIA_TYPE: &str = "application/vnd.oci.image.manifest.v1+json";
pub const EMPTY_MEDIA_TYPE: &str = "application/vnd.oci.empty.v1+json";
/// The digest of `{}`, the empty config of artifacts.
pub const EMPTY_DIGEST: &str =
    "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a";
pub const ANNOTATION_TITLE: &str = "org.opencontainers.image.title";
pub const ANNOTATION_CREATED: &str = "org.opencontainers.image.created";
pub const ANNOTATION_REF_NAME: &str = "org.opencontainers.image.ref.name";
/// The largest manifest read from the store or a registry.
pub const MANIFEST_MAX: u64 = 4 << 20;

#[derive(Debug, thiserror::Error)]
pub enum ArtifactError {
    #[error("{0}: artifact does not exist")]
    NotFound(String),
    #[error("{0}: artifact already exists")]
    AlreadyExists(String),
    #[error("{0}")]
    Invalid(String),
    #[error("artifact store: {0}")]
    Io(#[from] io::Error),
}

pub type ArtifactResult<T> = Result<T, ArtifactError>;

/// An artifact of the store.
#[derive(Debug, Clone)]
pub struct Artifact {
    pub name: String,
    /// The digest of its manifest
    pub digest: Digest,
    pub manifest: Value,
}

impl Artifact {
    /// podman's JSON of an artifact (`artifact inspect`).
    pub fn to_json(&self) -> Value {
        json!({"Manifest": self.manifest, "Name": self.name, "Digest": self.digest})
    }

    pub fn layers(&self) -> &[Value] {
        self.manifest["layers"]
            .as_array()
            .map_or(&[], Vec::as_slice)
    }
}

/// A file written in the store under a temporary name, with its digest.
pub struct StagedBlob {
    file: tempfile::NamedTempFile,
    pub digest: Digest,
    pub size: u64,
    /// The media type its first bytes tell
    pub sniffed: &'static str,
}

/// A blob being written in pieces, hashed as it goes.
pub struct BlobWriter {
    file: tempfile::NamedTempFile,
    hasher: DigestWriter,
    size: u64,
}

impl BlobWriter {
    pub fn write(&mut self, data: &[u8]) -> io::Result<()> {
        self.hasher.update(data);
        self.size += data.len() as u64;
        self.file.write_all(data)
    }
}

/// A file to add: what it is staged as, its title, its media type (else the
/// one its bytes tell).
pub struct NewLayer {
    pub blob: StagedBlob,
    pub title: String,
    pub media_type: Option<String>,
}

#[derive(Debug, Default, Clone)]
pub struct AddOptions {
    pub append: bool,
    pub replace: bool,
    /// The `artifactType` of the manifest
    pub artifact_type: Option<String>,
    /// Annotations of each file added
    pub annotations: Vec<(String, String)>,
    /// The algorithm of the digests of a new artifact (its manifest, its
    /// empty configuration; the files are staged with it).  None: SHA-256.
    /// An artifact that is appended to keeps the one it has: a different
    /// one asked for is refused.
    pub alg: Option<Algorithm>,
}

/// The blobs of an artifact a command selects: one by digest or title, else
/// all of them.
#[derive(Debug, Default, Clone)]
pub struct BlobFilter {
    pub digest: Option<String>,
    pub title: Option<String>,
}

/// A blob of an artifact, where it is in the store and the name a mount or
/// an extract gives it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlobPath {
    pub path: PathBuf,
    pub name: String,
    pub digest: Digest,
}

pub struct ArtifactStore {
    dir: PathBuf,
}

/// The name of an artifact as the store keeps it: registry/repository:tag.
pub fn normalize_name(name: &str) -> ArtifactResult<String> {
    let r = velarx_types::ImageReference::parse(name)
        .map_err(|e| ArtifactError::Invalid(format!("{name}: {e}")))?;
    if r.digest.is_some() {
        return Err(ArtifactError::Invalid(format!(
            "{name}: an artifact is named by a tag, not a digest"
        )));
    }
    r.validate()
        .map_err(|e| ArtifactError::Invalid(e.to_string()))?;
    Ok(format!(
        "{}/{}:{}",
        r.registry,
        r.repository,
        r.tag.as_deref().unwrap_or("latest")
    ))
}

/// The name a blob gets when it is extracted or mounted: its title, else
/// its digest with `-` for `:`; a title with a path separator is refused
/// (it could write out of the target).
pub fn blob_name(title: &str, digest: &str) -> ArtifactResult<String> {
    let name = if title.is_empty() {
        digest.replace(':', "-")
    } else {
        title.to_string()
    };
    if name.contains('/') || name == "." || name == ".." || name.contains('\0') {
        return Err(ArtifactError::Invalid(format!(
            "invalid name: {name:?} cannot contain a path separator"
        )));
    }
    Ok(name)
}

/// What the first bytes of a file tell of its type, as Go's
/// http.DetectContentType says it for text and for the rest.
fn sniff(head: &[u8]) -> &'static str {
    let text = std::str::from_utf8(head)
        .map(|_| true)
        // (a character cut at the end of the head is no binary)
        .unwrap_or_else(|e| e.error_len().is_none());
    let binary = head
        .iter()
        .any(|b| matches!(b, 0..=8 | 0x0b | 0x0e..=0x1a | 0x1c..=0x1f));
    if text && !binary {
        "text/plain; charset=utf-8"
    } else {
        "application/octet-stream"
    }
}

impl ArtifactStore {
    /// The store in `dir`, made if it is not there.
    pub fn open(dir: &Path) -> ArtifactResult<Self> {
        fs::create_dir_all(dir.join("blobs").join(Algorithm::Sha256.name()))?;
        let layout = dir.join("oci-layout");
        if !layout.exists() {
            write_atomic(dir, &layout, br#"{"imageLayoutVersion":"1.0.0"}"#)?;
        }
        let index = dir.join("index.json");
        if !index.exists() {
            write_atomic(
                dir,
                &index,
                br#"{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[]}"#,
            )?;
        }
        Ok(Self {
            dir: dir.to_path_buf(),
        })
    }

    fn lock(&self, exclusive: bool) -> ArtifactResult<File> {
        use rustix::fs::FlockOperation;
        let f = fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(self.dir.join("lock"))?;
        let op = if exclusive {
            FlockOperation::LockExclusive
        } else {
            FlockOperation::LockShared
        };
        velarx_sys::flock::flock_retrying(&f, op)?;
        Ok(f)
    }

    /// Where the blob `digest` is.
    pub fn blob_path(&self, digest: &Digest) -> ArtifactResult<PathBuf> {
        Ok(self
            .dir
            .join("blobs")
            .join(digest.alg().name())
            .join(digest.hex()))
    }

    /// The blob `digest` opened for reading, `size` bytes: no link is
    /// followed, in the store or out of it, and what is read is the file
    /// that was opened whatever is renamed meanwhile.
    pub fn open_blob(&self, digest: &Digest, size: u64) -> ArtifactResult<File> {
        use rustix::fs::{Mode, OFlags};
        use velarx_sys::fs::{open_beneath, Beneath, BeneathError};
        let path = self.blob_path(digest)?;
        let rel = path.strip_prefix(&self.dir).unwrap_or(&path);
        let dir = rustix::fs::open(
            &self.dir,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(io::Error::from)?;
        let not_the_blob =
            || ArtifactError::Invalid(format!("the blob {digest} is not a file of {size} bytes"));
        let file = match open_beneath(std::os::fd::AsFd::as_fd(&dir), rel, Beneath::File) {
            Ok(fd) => File::from(fd),
            Err(BeneathError::NotRegular) => return Err(not_the_blob()),
            Err(e) => return Err(io::Error::from(e).into()),
        };
        if file.metadata()?.len() != size {
            return Err(not_the_blob());
        }
        Ok(file)
    }

    fn read_index(&self) -> ArtifactResult<Value> {
        let data = fs::read(self.dir.join("index.json"))?;
        serde_json::from_slice(&data)
            .map_err(|e| ArtifactError::Invalid(format!("the index of the store: {e}")))
    }

    fn write_index(&self, index: &Value) -> ArtifactResult<()> {
        let data = serde_json::to_vec(index).map_err(io::Error::other)?;
        write_atomic(&self.dir, &self.dir.join("index.json"), &data)?;
        Ok(())
    }

    fn read_manifest(&self, digest: &Digest) -> ArtifactResult<Value> {
        let path = self.blob_path(digest)?;
        let mut data = Vec::new();
        File::open(&path)?
            .take(MANIFEST_MAX)
            .read_to_end(&mut data)?;
        serde_json::from_slice(&data)
            .map_err(|e| ArtifactError::Invalid(format!("the manifest {digest}: {e}")))
    }

    fn entries(&self, index: &Value) -> Vec<(String, Digest)> {
        index["manifests"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|m| {
                let name = m["annotations"][ANNOTATION_REF_NAME].as_str()?;
                let digest = m["digest"].as_str()?.parse().ok()?;
                Some((name.to_string(), digest))
            })
            .collect()
    }

    fn list_unlocked(&self) -> ArtifactResult<Vec<Artifact>> {
        let index = self.read_index()?;
        let mut out = Vec::new();
        for (name, digest) in self.entries(&index) {
            let manifest = self.read_manifest(&digest)?;
            out.push(Artifact {
                name,
                digest,
                manifest,
            });
        }
        Ok(out)
    }

    /// The artifacts of the store.
    pub fn list(&self) -> ArtifactResult<Vec<Artifact>> {
        let _lock = self.lock(false)?;
        self.list_unlocked()
    }

    /// The artifact named `name`, or whose digest (full, or a prefix of
    /// its hex of 3 characters at least) is `name`.
    fn find(&self, all: &[Artifact], name: &str) -> ArtifactResult<Artifact> {
        if let Ok(n) = normalize_name(name) {
            if let Some(a) = all.iter().find(|a| a.name == n) {
                return Ok(a.clone());
            }
        }
        // (`ALGORITHM:` in front names the algorithm of the digest)
        let (alg, hex) = match name.split_once(':') {
            Some((alg, hex)) => (Algorithm::from_name(alg).ok(), hex),
            None => (None, name),
        };
        let typed_ok = alg.is_some() || !name.contains(':');
        if typed_ok && hex.len() >= 3 && hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            let mut hits = all.iter().filter(|a| {
                a.digest.hex().starts_with(hex) && alg.is_none_or(|alg| a.digest.alg() == alg)
            });
            if let (Some(a), None) = (hits.next(), hits.next()) {
                return Ok(a.clone());
            }
        }
        // (named as podman names it: registry/repository:tag)
        Err(ArtifactError::NotFound(
            normalize_name(name).unwrap_or_else(|_| name.to_string()),
        ))
    }

    pub fn get(&self, name: &str) -> ArtifactResult<Artifact> {
        let _lock = self.lock(false)?;
        let all = self.list_unlocked()?;
        self.find(&all, name)
    }

    /// Write what `reader` gives in the store under a temporary name.
    pub fn stage(&self, mut reader: impl Read, alg: Algorithm) -> ArtifactResult<StagedBlob> {
        let mut file = tempfile::Builder::new()
            .prefix(".staged-")
            .tempfile_in(&self.dir)?;
        let mut hasher = DigestWriter::new(alg);
        let mut head = Vec::with_capacity(512);
        let mut size = 0u64;
        let mut buf = vec![0u8; 64 << 10];
        loop {
            let n = match reader.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e.into()),
            };
            hasher.update(&buf[..n]);
            if head.len() < 512 {
                let take = (512 - head.len()).min(n);
                head.extend_from_slice(&buf[..take]);
            }
            file.write_all(&buf[..n])?;
            size += n as u64;
        }
        file.as_file().sync_all()?;
        Ok(StagedBlob {
            file,
            digest: hasher.finalize(),
            size,
            sniffed: sniff(&head),
        })
    }

    /// The staged blob under its digest; it must be `expected` if given.
    fn commit_blob(&self, blob: StagedBlob, expected: Option<&Digest>) -> ArtifactResult<Digest> {
        if let Some(e) = expected {
            if *e != blob.digest {
                return Err(ArtifactError::Invalid(format!(
                    "the blob is {} where {e} was expected",
                    blob.digest
                )));
            }
        }
        let dest = self.blob_path(&blob.digest)?;
        if !dest.exists() {
            if let Some(dir) = dest.parent() {
                fs::create_dir_all(dir)?;
            }
            // readable by the containers that mount it, whoever they run as
            use std::os::unix::fs::PermissionsExt;
            blob.file
                .as_file()
                .set_permissions(fs::Permissions::from_mode(0o644))?;
            blob.file
                .persist(&dest)
                .map_err(|e| ArtifactError::Io(e.error))?;
        }
        Ok(blob.digest)
    }

    fn put_small_blob(&self, data: &[u8], alg: Algorithm) -> ArtifactResult<(Digest, u64)> {
        let blob = self.stage(data, alg)?;
        let size = blob.size;
        Ok((self.commit_blob(blob, None)?, size))
    }

    /// Point `name` at the manifest `manifest` (its bytes), the entry it
    /// had replaced; the blobs no manifest uses any more go.
    fn set_entry(&self, name: &str, manifest: &[u8], alg: Algorithm) -> ArtifactResult<Digest> {
        let (digest, size) = self.put_small_blob(manifest, alg)?;
        let mut index = self.read_index()?;
        let entry = json!({
            "mediaType": MANIFEST_MEDIA_TYPE,
            "digest": digest,
            "size": size,
            "annotations": {ANNOTATION_REF_NAME: name},
        });
        let list = index["manifests"].as_array_mut();
        let Some(list) = list else {
            return Err(ArtifactError::Invalid(
                "the index of the store has no manifests".into(),
            ));
        };
        list.retain(|m| m["annotations"][ANNOTATION_REF_NAME].as_str() != Some(name));
        list.push(entry);
        self.write_index(&index)?;
        self.collect_garbage()?;
        Ok(digest)
    }

    /// Add `layers` as the artifact `name`: a new one, or with `append`
    /// the files added to it, or with `replace` in its place.
    pub fn add(
        &self,
        name: &str,
        layers: Vec<NewLayer>,
        opts: &AddOptions,
    ) -> ArtifactResult<Digest> {
        if opts.append && opts.replace {
            return Err(ArtifactError::Invalid(
                "--append and --replace options cannot be used together".into(),
            ));
        }
        if layers.is_empty() {
            return Err(ArtifactError::Invalid(
                "an artifact needs at least one file".into(),
            ));
        }
        let name = normalize_name(name)?;
        let _lock = self.lock(true)?;
        let all = self.list_unlocked()?;
        let existing = all.iter().find(|a| a.name == name);
        let alg = match (existing.filter(|_| opts.append), opts.alg) {
            (Some(a), Some(want)) if a.digest.alg() != want => {
                return Err(ArtifactError::Invalid(format!(
                    "{name}: the artifact has {} digests, not {want}",
                    a.digest.alg()
                )))
            }
            (Some(a), _) => a.digest.alg(),
            (None, want) => want.unwrap_or(Algorithm::Sha256),
        };
        if let Some(l) = layers.iter().find(|l| l.blob.digest.alg() != alg) {
            return Err(ArtifactError::Invalid(format!(
                "{}: the file is digested with {}, the artifact {name} with {alg}",
                l.title,
                l.blob.digest.alg()
            )));
        }
        let mut manifest = match (existing, opts.append, opts.replace) {
            (Some(a), true, _) => a.manifest.clone(),
            (None, true, _) => return Err(ArtifactError::NotFound(name)),
            (Some(_), false, false) => return Err(ArtifactError::AlreadyExists(name)),
            _ => {
                // (as podman's: the annotations of a new artifact are those of
                // its manifest too)
                let mut annotations = serde_json::Map::new();
                for (k, v) in &opts.annotations {
                    annotations.insert(k.clone(), json!(v));
                }
                annotations.insert(
                    ANNOTATION_CREATED.into(),
                    json!(chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Nanos, true)),
                );
                let mut m = json!({
                    "schemaVersion": 2,
                    "mediaType": MANIFEST_MEDIA_TYPE,
                    "config": {"mediaType": EMPTY_MEDIA_TYPE, "digest": Digest::of(alg, b"{}"), "size": 2, "data": "e30="},
                    "layers": [],
                    "annotations": annotations,
                });
                if let Some(t) = &opts.artifact_type {
                    m["artifactType"] = json!(t);
                }
                m
            }
        };
        if opts.append && opts.artifact_type.is_some() {
            return Err(ArtifactError::Invalid(
                "--type cannot be changed with --append".into(),
            ));
        }
        // the empty config, for the layout to be whole
        self.put_small_blob(b"{}", alg)?;
        let mut titles: HashSet<String> = manifest["layers"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|l| {
                l["annotations"][ANNOTATION_TITLE]
                    .as_str()
                    .map(str::to_string)
            })
            .collect();
        let mut new = Vec::new();
        for l in layers {
            if !titles.insert(l.title.clone()) {
                return Err(ArtifactError::Invalid(format!(
                    "{}: file already exists in artifact {name}",
                    l.title
                )));
            }
            blob_name(&l.title, &l.blob.digest.to_string())?;
            let media_type = l
                .media_type
                .clone()
                .unwrap_or_else(|| l.blob.sniffed.to_string());
            let size = l.blob.size;
            let digest = self.commit_blob(l.blob, None)?;
            let mut annotations = serde_json::Map::new();
            for (k, v) in &opts.annotations {
                annotations.insert(k.clone(), json!(v));
            }
            annotations.insert(ANNOTATION_TITLE.into(), json!(l.title));
            new.push(json!({
                "mediaType": media_type,
                "digest": digest,
                "size": size,
                "annotations": annotations,
            }));
        }
        match manifest["layers"].as_array_mut() {
            Some(list) => list.extend(new),
            None => manifest["layers"] = Value::Array(new),
        }
        let bytes = serde_json::to_vec(&manifest).map_err(io::Error::other)?;
        self.set_entry(&name, &bytes, alg)
    }

    /// Keep the manifest `bytes` (pulled; it must have `digest`) and the
    /// blobs it names, which must be in the store, as `name`.
    pub fn put_pulled(&self, name: &str, digest: &Digest, bytes: &[u8]) -> ArtifactResult<Digest> {
        let name = normalize_name(name)?;
        let manifest: Value = serde_json::from_slice(bytes)
            .map_err(|e| ArtifactError::Invalid(format!("the manifest of {name}: {e}")))?;
        for l in manifest["layers"].as_array().into_iter().flatten() {
            let text = l["digest"].as_str().unwrap_or_default();
            let d: Digest = text
                .parse()
                .map_err(|e| ArtifactError::Invalid(format!("the manifest of {name}: {e}")))?;
            if !self.blob_path(&d)?.exists() {
                return Err(ArtifactError::Invalid(format!(
                    "the blob {d} of {name} is not in the store"
                )));
            }
        }
        let _lock = self.lock(true)?;
        let got = self.set_entry(&name, bytes, digest.alg())?;
        if got != *digest {
            return Err(ArtifactError::Invalid(format!(
                "the manifest of {name} is {got} where {digest} was expected"
            )));
        }
        Ok(got)
    }

    /// A blob written in pieces (a pull), kept by `BlobWriter::finish`.
    pub fn begin_blob(&self, alg: Algorithm) -> ArtifactResult<BlobWriter> {
        let file = tempfile::Builder::new()
            .prefix(".staged-")
            .tempfile_in(&self.dir)?;
        Ok(BlobWriter {
            file,
            hasher: DigestWriter::new(alg),
            size: 0,
        })
    }

    /// Keep what `w` was given under `digest`, which it must have.
    pub fn finish_blob(&self, w: BlobWriter, digest: &Digest) -> ArtifactResult<()> {
        let BlobWriter { file, hasher, size } = w;
        file.as_file().sync_all()?;
        let blob = StagedBlob {
            file,
            digest: hasher.finalize(),
            size,
            sniffed: "application/octet-stream",
        };
        self.commit_blob(blob, Some(digest))?;
        Ok(())
    }

    /// Whether the store has the blob `digest`.
    pub fn has_blob(&self, digest: &Digest) -> bool {
        self.blob_path(digest).is_ok_and(|p| p.exists())
    }

    /// The bytes of the manifest of `a`, as they are kept (and pushed).
    pub fn manifest_bytes(&self, a: &Artifact) -> ArtifactResult<Vec<u8>> {
        let mut data = Vec::new();
        File::open(self.blob_path(&a.digest)?)?
            .take(MANIFEST_MAX)
            .read_to_end(&mut data)?;
        Ok(data)
    }

    /// Remove the artifact `name`; its digest.
    pub fn remove(&self, name: &str) -> ArtifactResult<Digest> {
        let _lock = self.lock(true)?;
        let all = self.list_unlocked()?;
        let a = self.find(&all, name)?;
        let mut index = self.read_index()?;
        if let Some(list) = index["manifests"].as_array_mut() {
            list.retain(|m| {
                m["annotations"][ANNOTATION_REF_NAME].as_str() != Some(a.name.as_str())
            });
        }
        self.write_index(&index)?;
        self.collect_garbage()?;
        Ok(a.digest)
    }

    /// Remove the blobs that no manifest of the index uses (the lock is
    /// held), and the staged files a writer that died left.
    fn collect_garbage(&self) -> ArtifactResult<()> {
        let index = self.read_index()?;
        let mut keep = HashSet::new();
        for (_, digest) in self.entries(&index) {
            let m = self.read_manifest(&digest)?;
            keep.insert(digest);
            if let Some(c) = m["config"]["digest"].as_str().and_then(|c| c.parse().ok()) {
                keep.insert(c);
            }
            for l in m["layers"].as_array().into_iter().flatten() {
                if let Some(d) = l["digest"].as_str().and_then(|d| d.parse().ok()) {
                    keep.insert(d);
                }
            }
        }
        for alg in Algorithm::ALL {
            let dir = match fs::read_dir(self.dir.join("blobs").join(alg.name())) {
                Ok(dir) => dir,
                Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
                Err(e) => return Err(e.into()),
            };
            for e in dir {
                let e = e?;
                let name = e.file_name();
                let kept =
                    Digest::from_hex(alg, &name.to_string_lossy()).is_ok_and(|d| keep.contains(&d));
                if !kept {
                    let _ = fs::remove_file(e.path());
                }
            }
        }
        Ok(())
    }

    /// The blobs of `artifact` that `filter` selects, with their names.
    pub fn blob_paths(
        &self,
        artifact: &Artifact,
        filter: &BlobFilter,
    ) -> ArtifactResult<Vec<BlobPath>> {
        if filter.digest.is_some() && filter.title.is_some() {
            return Err(ArtifactError::Invalid(
                "--digest and --title cannot be used together".into(),
            ));
        }
        let mut out = Vec::new();
        let mut names = HashSet::new();
        for l in artifact.layers() {
            let text = l["digest"].as_str().unwrap_or_default();
            let digest: Digest = text.parse().map_err(|e| {
                ArtifactError::Invalid(format!("the layer {text:?} of {}: {e}", artifact.name))
            })?;
            let title = l["annotations"][ANNOTATION_TITLE]
                .as_str()
                .unwrap_or_default();
            if filter
                .digest
                .as_ref()
                .is_some_and(|d| *d != digest.to_string())
                || filter.title.as_ref().is_some_and(|t| t != title)
            {
                continue;
            }
            // (with a digest the blob is named by it, as podman)
            let name = if filter.digest.is_some() {
                blob_name("", &digest.to_string())?
            } else {
                blob_name(title, &digest.to_string())?
            };
            if !names.insert(name.clone()) {
                return Err(ArtifactError::Invalid(format!(
                    "annotation {ANNOTATION_TITLE:?}:{title:?} is used in multiple different layers within artifact"
                )));
            }
            out.push(BlobPath {
                path: self.blob_path(&digest)?,
                name,
                digest,
            });
        }
        if out.is_empty() {
            let what = match (&filter.digest, &filter.title) {
                (Some(d), _) => format!("no blob with the digest {d:?}"),
                (_, Some(t)) => format!("no blob with the title {t:?}"),
                _ => "no blob".to_string(),
            };
            return Err(ArtifactError::NotFound(format!(
                "{}: {what}",
                artifact.name
            )));
        }
        Ok(out)
    }
}

/// `--mount type=artifact,src=NAME,dst=PATH[,title=T|digest=D][,name=N]`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ArtifactMountSpec {
    pub source: String,
    pub dest: String,
    pub title: Option<String>,
    pub digest: Option<String>,
    pub name: Option<String>,
}

impl ArtifactMountSpec {
    pub fn filter(&self) -> BlobFilter {
        BlobFilter {
            digest: self.digest.clone(),
            title: self.title.clone(),
        }
    }
}

/// The artifact mount of a `--mount` argument; None for the other types.
pub fn parse_artifact_mount(arg: &str) -> ArtifactResult<Option<ArtifactMountSpec>> {
    let mut spec = ArtifactMountSpec::default();
    let mut artifact = false;
    for part in arg.split(',').filter(|p| !p.is_empty()) {
        let (k, v) = part.split_once('=').unwrap_or((part, ""));
        match k {
            "type" => {
                if v != "artifact" {
                    return Ok(None);
                }
                artifact = true;
            }
            "src" | "source" => spec.source = v.to_string(),
            "dst" | "destination" | "target" => spec.dest = v.to_string(),
            "title" => spec.title = Some(v.to_string()),
            "digest" => spec.digest = Some(v.to_string()),
            "name" => spec.name = Some(v.to_string()),
            other => {
                return Err(ArtifactError::Invalid(format!(
                    "unknown option {other:?} of an artifact mount"
                )))
            }
        }
    }
    if !artifact {
        return Ok(None);
    }
    if spec.source.is_empty() {
        return Err(ArtifactError::Invalid("an artifact mount needs src".into()));
    }
    if !spec.dest.starts_with('/') {
        return Err(ArtifactError::Invalid(
            "an artifact mount needs an absolute dst".into(),
        ));
    }
    if spec.title.is_some() && spec.digest.is_some() {
        return Err(ArtifactError::Invalid(
            "an artifact mount takes title or digest, not both".into(),
        ));
    }
    if let Some(n) = &spec.name {
        blob_name(n, "")?;
    }
    Ok(Some(spec))
}

/// Where each blob goes in the container, as podman mounts them: on `dst`
/// itself when it is a file (`dest_is_dir` Some(false)), or when it is not
/// in the image and there is one blob; else in the directory `dst`, by
/// their names (`name-INDEX` with a name and several blobs).
pub fn mount_targets(
    spec: &ArtifactMountSpec,
    blobs: &[BlobPath],
    dest_is_dir: Option<bool>,
) -> ArtifactResult<Vec<(PathBuf, String)>> {
    let dest_is_file = match dest_is_dir {
        Some(dir) => !dir,
        None => blobs.len() == 1,
    };
    if dest_is_file && blobs.len() > 1 {
        return Err(ArtifactError::Invalid(format!(
            "artifact {:?} contains more than one blob and container path {:?} is a file",
            spec.source, spec.dest
        )));
    }
    let mut out = Vec::new();
    for (i, b) in blobs.iter().enumerate() {
        let target = if dest_is_file {
            spec.dest.clone()
        } else {
            let file = match &spec.name {
                Some(n) if blobs.len() > 1 => format!("{n}-{i}"),
                Some(n) => n.clone(),
                None => b.name.clone(),
            };
            format!("{}/{file}", spec.dest.trim_end_matches('/'))
        };
        out.push((b.path.clone(), target));
    }
    Ok(out)
}

/// Write `data` to `path` through a temporary file of `dir` and a rename.
fn write_atomic(dir: &Path, path: &Path, data: &[u8]) -> io::Result<()> {
    let mut tmp = tempfile::Builder::new().prefix(".tmp-").tempfile_in(dir)?;
    tmp.write_all(data)?;
    tmp.as_file().sync_all()?;
    tmp.persist(path).map_err(|e| e.error)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn layer(store: &ArtifactStore, title: &str, data: &[u8]) -> NewLayer {
        NewLayer {
            blob: store.stage(data, Algorithm::Sha256).unwrap(),
            title: title.into(),
            media_type: None,
        }
    }

    /// An artifact of `--digest sha512` has SHA-512 digests everywhere (its
    /// manifest, its empty configuration, its files); one that is appended to
    /// keeps its own and refuses a file of the other algorithm and a
    /// different one asked for.
    #[test]
    fn a_sha512_artifact_has_sha512_digests_and_keeps_them_when_appended_to() {
        let d = tempfile::tempdir().unwrap();
        let s = ArtifactStore::open(d.path()).unwrap();
        let big = |title: &str, data: &[u8]| NewLayer {
            blob: s.stage(data, Algorithm::Sha512).unwrap(),
            title: title.into(),
            media_type: None,
        };
        let new = AddOptions {
            alg: Some(Algorithm::Sha512),
            ..Default::default()
        };
        let digest = s
            .add("localhost/t/b", vec![big("one", b"one\n")], &new)
            .unwrap();
        assert_eq!(digest.alg(), Algorithm::Sha512);
        let a = s.get("localhost/t/b").unwrap();
        assert_eq!(a.digest, digest);
        assert_eq!(
            a.manifest["config"]["digest"],
            Digest::of(Algorithm::Sha512, b"{}").to_string()
        );
        assert_eq!(
            a.layers()[0]["digest"],
            Digest::of(Algorithm::Sha512, b"one\n").to_string()
        );
        assert!(d.path().join("blobs/sha512").join(digest.hex()).is_file());
        assert!(!d
            .path()
            .join("blobs/sha256")
            .read_dir()
            .unwrap()
            .any(|e| { e.unwrap().file_name().len() == 128 }));
        // appended: the artifact's own algorithm, asked for or not
        let append = AddOptions {
            append: true,
            ..Default::default()
        };
        let next = s
            .add("localhost/t/b", vec![big("two", b"two\n")], &append)
            .unwrap();
        assert_eq!(next.alg(), Algorithm::Sha512);
        let same = AddOptions {
            append: true,
            alg: Some(Algorithm::Sha512),
            ..Default::default()
        };
        s.add("localhost/t/b", vec![big("three", b"3")], &same)
            .unwrap();
        let other = AddOptions {
            append: true,
            alg: Some(Algorithm::Sha256),
            ..Default::default()
        };
        let e = s
            .add("localhost/t/b", vec![layer(&s, "four", b"4")], &other)
            .unwrap_err()
            .to_string();
        assert!(e.contains("has sha512 digests, not sha256"), "{e}");
        // a file of the other algorithm does not go into it
        let e = s
            .add("localhost/t/b", vec![layer(&s, "five", b"5")], &append)
            .unwrap_err()
            .to_string();
        assert!(
            e.contains("digested with sha256") && e.contains("sha512"),
            "{e}"
        );
        assert_eq!(s.get("localhost/t/b").unwrap().layers().len(), 3);
        // a sha256 artifact stays what it is by default
        let plain = s
            .add(
                "localhost/t/c",
                vec![layer(&s, "x", b"x")],
                &AddOptions::default(),
            )
            .unwrap();
        assert_eq!(plain.alg(), Algorithm::Sha256);
        assert_eq!(
            s.get("localhost/t/c").unwrap().manifest["config"]["digest"],
            EMPTY_DIGEST
        );
    }

    #[test]
    fn names_and_blob_names() {
        assert_eq!(
            normalize_name("localhost/a/b").unwrap(),
            "localhost/a/b:latest"
        );
        assert_eq!(normalize_name("quay.io/x/y:v1").unwrap(), "quay.io/x/y:v1");
        assert_eq!(
            normalize_name("foo").unwrap(),
            "docker.io/library/foo:latest"
        );
        assert!(normalize_name("quay.io/x/y@sha256:abc").is_err());
        assert!(normalize_name("Bad/Name").is_err());
        assert_eq!(blob_name("f.txt", "sha256:aa").unwrap(), "f.txt");
        assert_eq!(blob_name("", "sha256:aa").unwrap(), "sha256-aa");
        assert!(blob_name("../x", "sha256:aa").is_err());
        assert!(blob_name("..", "sha256:aa").is_err());
        assert_eq!(sniff(b"hello\n"), "text/plain; charset=utf-8");
        assert_eq!(sniff(b"\x00\x01\x02"), "application/octet-stream");
    }

    #[test]
    fn add_list_append_replace_remove() {
        let d = tempfile::tempdir().unwrap();
        let s = ArtifactStore::open(d.path()).unwrap();
        let opts = AddOptions {
            artifact_type: Some("application/x-test".into()),
            annotations: vec![("k".into(), "v".into())],
            ..Default::default()
        };
        let d1 = s
            .add("localhost/t/a", vec![layer(&s, "one.txt", b"one\n")], &opts)
            .unwrap();
        let a = s.get("localhost/t/a").unwrap();
        assert_eq!(a.digest, d1);
        assert_eq!(a.manifest["artifactType"], "application/x-test");
        assert_eq!(a.layers().len(), 1);
        assert_eq!(a.layers()[0]["annotations"]["k"], "v");
        assert_eq!(a.manifest["annotations"]["k"], "v");
        assert_eq!(a.layers()[0]["mediaType"], "text/plain; charset=utf-8");
        let created = a.manifest["annotations"][ANNOTATION_CREATED].clone();
        // by a prefix of its digest
        assert_eq!(s.get(&d1.hex()[..8]).unwrap().name, "localhost/t/a:latest");
        assert!(matches!(
            s.add(
                "localhost/t/a",
                vec![layer(&s, "x", b"x")],
                &AddOptions::default()
            ),
            Err(ArtifactError::AlreadyExists(_))
        ));
        let append = AddOptions {
            append: true,
            ..Default::default()
        };
        s.add(
            "localhost/t/a",
            vec![layer(&s, "two.bin", b"\x00\x01")],
            &append,
        )
        .unwrap();
        let a = s.get("localhost/t/a").unwrap();
        assert_eq!(a.layers().len(), 2);
        assert_eq!(a.manifest["annotations"][ANNOTATION_CREATED], created);
        assert_eq!(a.layers()[1]["mediaType"], "application/octet-stream");
        // a title twice is refused
        assert!(s
            .add("localhost/t/a", vec![layer(&s, "one.txt", b"z")], &append)
            .is_err());
        let both = AddOptions {
            append: true,
            replace: true,
            ..Default::default()
        };
        let e = s
            .add("localhost/t/a", vec![layer(&s, "y", b"y")], &both)
            .unwrap_err();
        assert!(e
            .to_string()
            .contains("--append and --replace options cannot be used together"));
        let replace = AddOptions {
            replace: true,
            ..Default::default()
        };
        s.add("localhost/t/a", vec![layer(&s, "three", b"3")], &replace)
            .unwrap();
        assert_eq!(s.get("localhost/t/a").unwrap().layers().len(), 1);
        // the blobs of the files replaced went
        let blobs = fs::read_dir(d.path().join("blobs/sha256")).unwrap().count();
        assert_eq!(blobs, 3, "the empty config, the file and the manifest");
        assert_eq!(s.list().unwrap().len(), 1);
        s.remove("localhost/t/a").unwrap();
        assert!(matches!(
            s.get("localhost/t/a"),
            Err(ArtifactError::NotFound(_))
        ));
        assert_eq!(
            fs::read_dir(d.path().join("blobs/sha256")).unwrap().count(),
            0
        );
        // no staged file is left
        assert!(fs::read_dir(d.path()).unwrap().all(|e| !e
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".staged-")));
    }

    #[test]
    fn artifact_mounts() {
        assert_eq!(
            parse_artifact_mount("type=bind,src=/a,dst=/b").unwrap(),
            None
        );
        let m = parse_artifact_mount("type=artifact,src=localhost/a,dst=/data,title=t")
            .unwrap()
            .unwrap();
        assert_eq!(
            (m.source.as_str(), m.dest.as_str(), m.title.as_deref()),
            ("localhost/a", "/data", Some("t"))
        );
        assert!(parse_artifact_mount("type=artifact,dst=/d").is_err());
        assert!(parse_artifact_mount("type=artifact,src=a,dst=rel").is_err());
        assert!(
            parse_artifact_mount("type=artifact,src=a,dst=/d,title=t,digest=sha256:aa").is_err()
        );
        assert!(parse_artifact_mount("type=artifact,src=a,dst=/d,ro").is_err());
        assert!(parse_artifact_mount("type=artifact,src=a,dst=/d,name=../x").is_err());
        let b = |n: &str| BlobPath {
            path: PathBuf::from(format!("/s/{n}")),
            name: n.into(),
            digest: Digest::empty(Algorithm::Sha256),
        };
        let one = [b("f")];
        let two = [b("f"), b("g")];
        let spec = |name: Option<&str>| ArtifactMountSpec {
            source: "a".into(),
            dest: "/d".into(),
            name: name.map(str::to_string),
            ..Default::default()
        };
        let t = |v: Vec<(PathBuf, String)>| v.into_iter().map(|(_, t)| t).collect::<Vec<_>>();
        // not in the image: one blob is the file, several go in the directory
        assert_eq!(t(mount_targets(&spec(None), &one, None).unwrap()), ["/d"]);
        assert_eq!(
            t(mount_targets(&spec(None), &two, None).unwrap()),
            ["/d/f", "/d/g"]
        );
        // a directory of the image
        assert_eq!(
            t(mount_targets(&spec(None), &one, Some(true)).unwrap()),
            ["/d/f"]
        );
        assert_eq!(
            t(mount_targets(&spec(Some("n")), &one, Some(true)).unwrap()),
            ["/d/n"]
        );
        assert_eq!(
            t(mount_targets(&spec(Some("n")), &two, None).unwrap()),
            ["/d/n-0", "/d/n-1"]
        );
        // a file of the image
        assert_eq!(
            t(mount_targets(&spec(None), &one, Some(false)).unwrap()),
            ["/d"]
        );
        assert!(mount_targets(&spec(None), &two, Some(false)).is_err());
    }

    #[test]
    fn blob_paths_are_filtered() {
        let d = tempfile::tempdir().unwrap();
        let s = ArtifactStore::open(&d.path().join("store")).unwrap();
        s.add(
            "localhost/t/m",
            vec![layer(&s, "a.txt", b"A"), layer(&s, "b.txt", b"B")],
            &AddOptions::default(),
        )
        .unwrap();
        let a = s.get("localhost/t/m").unwrap();
        let by_digest = BlobFilter {
            digest: a.layers()[0]["digest"].as_str().map(str::to_string),
            ..Default::default()
        };
        let p = s.blob_paths(&a, &by_digest).unwrap();
        assert_eq!(p.len(), 1);
        assert!(p[0].name.starts_with("sha256-"));
        let none = BlobFilter {
            title: Some("nosuch".into()),
            ..Default::default()
        };
        assert!(matches!(
            s.blob_paths(&a, &none),
            Err(ArtifactError::NotFound(_))
        ));
    }
}
