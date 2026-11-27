// SPDX-License-Identifier: Apache-2.0
//! Image archives (oci-archive and docker-archive): reading them as a source
//! of blobs for the pull engine, and writing the first from the store.
//!
//! An archive is treated like a registry: it is indexed once (every regular
//! file with the position of its content and its digest), the manifests are
//! read from `index.json`, and the blobs are
//! served by digest.  Everything else is a normal pull: the digests of the
//! blobs and the diff ids are checked against the configuration.
//!
//! A docker-archive (`docker save`, `podman save`'s default) has a
//! `manifest.json` instead: the configuration and the layers are members
//! named in it, not blobs by digest.  The members are indexed and hashed all
//! the same, and an OCI manifest is synthesised from them (the digests of
//! the members are those of the descriptors, so the image id is the digest
//! of the configuration member, as everywhere; the digest of the manifest is
//! the one of the synthesised bytes, as in podman, which synthesises one
//! too).  What Velarx writes stays OCI.

pub mod guard;

use crate::pull::tar::{Kind, TarReader};
use serde::Deserialize;
use std::collections::HashMap;
use std::fs::File;
use std::io::{self, BufReader, Read, Seek, SeekFrom};
use std::os::unix::fs::FileExt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use velarx_types::digest::{Algorithm, Digest, DigestWriter};

/// Members of an archive accepted.
const MAX_MEMBERS: usize = 1024 * 1024;

/// Images of a docker-archive's `manifest.json`, and layers and names of one.
const MAX_DOCKER_ITEMS: usize = 1024;

/// Links followed to find a member.
const MAX_LINKS: usize = 16;

/// Size of the reads of the archive.
const IO_SIZE: usize = 1024 * 1024;

/// Largest manifest, index or configuration read from an archive.
pub const MAX_METADATA: u64 = 4 * 1024 * 1024;

pub const LAYER: &str = "application/vnd.oci.image.layer.v1.tar";
const LAYER_GZIP: &str = "application/vnd.oci.image.layer.v1.tar+gzip";
const LAYER_ZSTD: &str = "application/vnd.oci.image.layer.v1.tar+zstd";
pub(crate) const OCI_MANIFEST: &str = "application/vnd.oci.image.manifest.v1+json";
pub(crate) const OCI_CONFIG: &str = "application/vnd.oci.image.config.v1+json";

fn invalid(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.into())
}

/// A Docker format: `Unsupported`, which the callers tell from a file that
/// is no archive.
fn refused(e: velarx_types::ImageError) -> io::Error {
    io::Error::new(io::ErrorKind::Unsupported, e.to_string())
}

fn not_found(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::NotFound, msg.into())
}

#[derive(Debug, Clone)]
enum Member {
    Regular {
        offset: u64,
        size: u64,
        /// Its sha256: a docker-archive names no blob by digest, so the
        /// content is what finds it.  A directory is not read to hash its
        /// files: the name of a blob is its digest, which the reader checks
        /// (none for another file).
        digest: Option<Digest>,
    },
    /// The normalized path the link leads to.
    Link(String),
}

/// A regular file of the archive.
#[derive(Debug, Clone, Copy)]
pub struct ArchiveFile<'a> {
    /// Its normalized name
    pub name: &'a str,
    pub offset: u64,
    pub size: u64,
    pub digest: Option<&'a Digest>,
}

/// An image of an archive.
#[derive(Debug, Clone)]
pub struct ArchiveImage {
    /// A manifest (or an index).
    pub manifest: Vec<u8>,
    /// Its digest, which the bytes have.
    pub digest: Digest,
    /// What it is: an OCI manifest or an index.
    pub media_type: String,
    /// The names it has in the archive, as written there.
    pub names: Vec<String>,
    /// Other names a selector takes it by (the `ref.name` of a layout whose
    /// entry has the full name of `io.containerd.image.name` too)
    pub aliases: Vec<String>,
}

pub struct Archive {
    backing: Backing,
    members: Vec<(String, Member)>,
}

/// Where the content of the members is.
enum Backing {
    /// A tar: the members are at their offsets
    Tar(Arc<File>),
    /// A directory (an OCI layout, a `dir:`): a member is the file of its
    /// name, opened beneath the directory
    Tree(File),
    /// Blobs that are parts of files, each member with its file ([`Archive::blobs`])
    Blobs(HashMap<String, Arc<File>>),
}

/// The content of one member, read at positions of it.
pub struct Section {
    file: Arc<File>,
    offset: u64,
    size: u64,
}

impl Section {
    pub fn size(&self) -> u64 {
        self.size
    }

    pub fn read_exact_at(&self, buf: &mut [u8], at: u64) -> io::Result<()> {
        let end = at.checked_add(buf.len() as u64).filter(|e| *e <= self.size);
        if end.is_none() {
            return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
        }
        self.file.read_exact_at(buf, self.offset + at)
    }

    /// The content, read in order.
    pub fn reader(self) -> SectionReader {
        SectionReader {
            section: self,
            at: 0,
        }
    }
}

/// A [`Section`] as a `Read`.
pub struct SectionReader {
    section: Section,
    at: u64,
}

impl SectionReader {
    pub fn size(&self) -> u64 {
        self.section.size
    }
}

impl Read for SectionReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let left = self.section.size - self.at;
        let want = buf.len().min(usize::try_from(left).unwrap_or(usize::MAX));
        if want == 0 {
            return Ok(0);
        }
        let n = self
            .section
            .file
            .read_at(&mut buf[..want], self.section.offset + self.at)?;
        self.at += n as u64;
        Ok(n)
    }
}

/// Counts what is read, to know where the content of an entry is.
struct Counting<R> {
    inner: R,
    count: Arc<AtomicU64>,
}

impl<R: Read> Read for Counting<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.count.fetch_add(n as u64, Ordering::Relaxed);
        Ok(n)
    }
}

/// Normalize `path`: no empty or `.` components, `..` removes the previous
/// one and never goes above the root.
fn normalize(path: &str) -> String {
    let mut parts: Vec<&str> = Vec::new();
    for part in path.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            p => parts.push(p),
        }
    }
    parts.join("/")
}

/// Where a link of the archive leads: hard links are relative to the root,
/// symbolic links to the directory of the link.
fn link_target(name: &str, target: &str, hard: bool) -> String {
    if hard || target.starts_with('/') {
        return normalize(target);
    }
    match name.rsplit_once('/') {
        Some((dir, _)) => normalize(&format!("{dir}/{target}")),
        None => normalize(target),
    }
}

pub fn sniff_layer_media_type(head: &[u8]) -> &'static str {
    use velarx_tarsplit::decompress::{sniff, Kind};
    match sniff(head) {
        Kind::Gzip => LAYER_GZIP,
        Kind::Zstd => LAYER_ZSTD,
        Kind::None => LAYER,
    }
}

impl Archive {
    /// Open the archive in `file` (a tar, maybe compressed with gzip or
    /// zstd).  A compressed archive is decompressed to a file without a name
    /// in the directory `dir`, and refused when it inflates to more
    /// than `limit` bytes: the bytes are counted as they are written.
    pub fn open(file: File, dir: &File, limit: impl Fn(u64) -> u64) -> io::Result<Self> {
        let mut head = [0u8; 4];
        let n = file.read_at(&mut head, 0)?;
        let compressed = sniff_layer_media_type(&head[..n]) != LAYER;
        let file = if compressed {
            let size = file.metadata()?.len();
            let limit = limit(size);
            let mut input = file;
            input.seek(SeekFrom::Start(0))?;
            let out = crate::pull::unnamed::unnamed_file_at(dir)?;
            let reader = BufReader::new(input);
            let mut decoder = velarx_tarsplit::decompress::Decoder::new(
                velarx_tarsplit::decompress::sniff(&head),
                reader,
            )?;
            // (the zeros of the tar are holes of the file)
            let copied =
                velarx_storage::copy_sparse(&mut (&mut decoder).take(limit + 1), &out, |_| {})?;
            if copied > limit {
                return Err(invalid(format!(
                    "the archive is larger than {limit} bytes once decompressed"
                )));
            }
            out
        } else {
            file
        };
        let mut archive = Self {
            backing: Backing::Tar(Arc::new(file)),
            members: Vec::new(),
        };
        archive.index()?;
        Ok(archive)
    }

    /// The layout or the `dir:` directory `dir` (open): its regular files
    /// are the members, and below `blobs/ALGORITHM/` the blobs, a blob
    /// named by its digest.  Nothing is read to index it, and a name never
    /// goes outside the directory: a member is opened beneath it, no link
    /// followed.
    pub fn tree(dir: File) -> io::Result<Self> {
        use rustix::fs::{Dir, FileType, Mode, OFlags};
        let entries = |dir: &File| -> io::Result<Vec<(String, FileType, u64)>> {
            let mut out = Vec::new();
            for entry in Dir::read_from(dir)? {
                let entry = entry?;
                let name = entry.file_name().to_string_lossy().into_owned();
                if name == "." || name == ".." {
                    continue;
                }
                if out.len() >= MAX_MEMBERS {
                    return Err(invalid("too many files in the directory"));
                }
                let stat = rustix::fs::statat(
                    dir,
                    entry.file_name(),
                    rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
                )?;
                out.push((
                    name,
                    FileType::from_raw_mode(stat.st_mode),
                    stat.st_size as u64,
                ));
            }
            Ok(out)
        };
        let subdir = |dir: &File, name: &str| -> io::Result<File> {
            Ok(File::from(rustix::fs::openat(
                dir,
                name,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )?))
        };
        let mut members: Vec<(String, Member)> = Vec::new();
        for (name, kind, size) in entries(&dir)? {
            match kind {
                FileType::RegularFile => {
                    // (a `dir:` names its blobs by the hex of their digest)
                    let digest = Algorithm::ALL
                        .into_iter()
                        .find_map(|alg| Digest::from_hex(alg, &name).ok());
                    members.push((
                        name,
                        Member::Regular {
                            offset: 0,
                            size,
                            digest,
                        },
                    ));
                }
                FileType::Directory if name == "blobs" => {
                    let blobs = subdir(&dir, &name)?;
                    for (alg_name, kind, _) in entries(&blobs)? {
                        let (FileType::Directory, Some(alg)) = (
                            kind,
                            Algorithm::ALL
                                .into_iter()
                                .find(|a| a.to_string() == alg_name),
                        ) else {
                            continue;
                        };
                        let by_alg = subdir(&blobs, &alg_name)?;
                        for (hex, kind, size) in entries(&by_alg)? {
                            if kind != FileType::RegularFile {
                                continue;
                            }
                            if members.len() >= MAX_MEMBERS {
                                return Err(invalid("too many files in the directory"));
                            }
                            members.push((
                                format!("blobs/{alg_name}/{hex}"),
                                Member::Regular {
                                    offset: 0,
                                    size,
                                    digest: Digest::from_hex(alg, &hex).ok(),
                                },
                            ));
                        }
                    }
                }
                _ => {}
            }
        }
        Ok(Self {
            backing: Backing::Tree(dir),
            members,
        })
    }

    /// The content of the member `f`.
    pub fn section(&self, f: &ArchiveFile<'_>) -> io::Result<Section> {
        match &self.backing {
            Backing::Tar(file) => Ok(Section {
                file: file.clone(),
                offset: f.offset,
                size: f.size,
            }),
            Backing::Blobs(files) => Ok(Section {
                file: files[f.name].clone(),
                offset: f.offset,
                size: f.size,
            }),
            Backing::Tree(dir) => {
                use rustix::fs::{Mode, OFlags, ResolveFlags};
                let fd = velarx_sys::fs::openat2_retry(
                    std::os::fd::AsFd::as_fd(dir),
                    f.name,
                    OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NONBLOCK,
                    Mode::empty(),
                    ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
                )?;
                let file = File::from(fd);
                let meta = file.metadata()?;
                if !meta.is_file() {
                    return Err(invalid(format!(
                        "`{}` is not a file",
                        f.name.escape_debug()
                    )));
                }
                Ok(Section {
                    size: meta.len().min(f.size),
                    file: Arc::new(file),
                    offset: 0,
                })
            }
        }
    }

    /// An archive of blobs that are parts of files, each with its file, its
    /// digest, where it starts and its size.
    pub fn blobs(blobs: &[(&File, Digest, u64, u64)]) -> io::Result<Self> {
        let mut members = Vec::new();
        let mut files = HashMap::new();
        for &(file, digest, offset, size) in blobs {
            let name = format!("blobs/{}/{}", digest.alg(), digest.hex());
            files.insert(name.clone(), Arc::new(file.try_clone()?));
            members.push((
                name,
                Member::Regular {
                    offset,
                    size,
                    digest: Some(digest),
                },
            ));
        }
        Ok(Self {
            backing: Backing::Blobs(files),
            members,
        })
    }

    fn index(&mut self) -> io::Result<()> {
        let Backing::Tar(file) = &self.backing else {
            return Ok(());
        };
        let mut input = file.try_clone()?;
        input.seek(SeekFrom::Start(0))?;
        let count = Arc::new(AtomicU64::new(0));
        let mut tar = TarReader::new(Counting {
            inner: BufReader::with_capacity(IO_SIZE, input),
            count: count.clone(),
        });
        let mut buf = vec![0u8; IO_SIZE];
        while let Some(h) = tar
            .next_entry()
            .map_err(|e| invalid(format!("invalid image archive: {e}")))?
        {
            let hard = h.kind == Kind::Hardlink;
            if !matches!(h.kind, Kind::Regular | Kind::Symlink | Kind::Hardlink) {
                continue;
            }
            if self.members.len() >= MAX_MEMBERS {
                return Err(invalid("too many files in the archive"));
            }
            let name = normalize(&h.path);
            if h.kind != Kind::Regular {
                let target = h.link.as_deref().unwrap_or("");
                self.members
                    .push((name.clone(), Member::Link(link_target(&name, target, hard))));
                continue;
            }
            let offset = count.load(Ordering::Relaxed);
            let mut hasher = DigestWriter::new(Algorithm::Sha256);
            let mut left = h.size;
            while left > 0 {
                let want = buf.len().min(usize::try_from(left).unwrap_or(usize::MAX));
                let n = tar.read(&mut buf[..want])?;
                hasher.update(&buf[..n]);
                left -= n as u64;
            }
            self.members.push((
                name,
                Member::Regular {
                    offset,
                    size: h.size,
                    digest: Some(hasher.finalize()),
                },
            ));
        }
        Ok(())
    }

    /// The file called `name`; the last entry of that name wins, as on
    /// extraction, and links are followed inside the archive.
    pub fn find(&self, name: &str) -> Option<ArchiveFile<'_>> {
        let mut path = normalize(name);
        for _ in 0..=MAX_LINKS {
            let (name, member) = self.members.iter().rev().find(|(n, _)| *n == path)?;
            match member {
                Member::Regular {
                    offset,
                    size,
                    digest,
                } => {
                    return Some(ArchiveFile {
                        name,
                        offset: *offset,
                        size: *size,
                        digest: digest.as_ref(),
                    })
                }
                Member::Link(target) => path = target.clone(),
            }
        }
        None
    }

    /// A file with this sha256.
    pub fn find_digest(&self, wanted: &Digest) -> Option<ArchiveFile<'_>> {
        self.members.iter().find_map(|(name, m)| match m {
            Member::Regular {
                offset,
                size,
                digest: Some(digest),
            } if digest == wanted => Some(ArchiveFile {
                name,
                offset: *offset,
                size: *size,
                digest: Some(digest),
            }),
            _ => None,
        })
    }

    /// The file of the blob `wanted`.  A sha256 is found by the content of
    /// the members; the archive hashes nothing else when it is indexed, so
    /// a blob of another algorithm is the member `blobs/ALGORITHM/HEX` of an
    /// OCI layout, whose content the reader checks against `wanted` (or a
    /// member made with its digest, `single`).
    pub fn find_blob(&self, wanted: &Digest) -> Option<ArchiveFile<'_>> {
        // (a member whose digest is known, as the archive of one blob that a
        // commit makes has, in any algorithm)
        let known = self.find_digest(wanted);
        match wanted.alg() {
            Algorithm::Sha256 => known,
            alg => known.or_else(|| self.find(&format!("blobs/{alg}/{}", wanted.hex()))),
        }
    }

    fn read_file(&self, f: &ArchiveFile<'_>, max: u64, what: &str) -> io::Result<Vec<u8>> {
        if f.size > max {
            return Err(invalid(format!("{what} in the archive is too large")));
        }
        let section = self.section(f)?;
        let mut data = vec![0u8; section.size() as usize];
        section.read_exact_at(&mut data, 0)?;
        Ok(data)
    }

    /// The content of a blob, if the archive has it.
    pub fn blob(&self, wanted: &Digest, max: u64) -> io::Result<Vec<u8>> {
        let f = self
            .find_blob(wanted)
            .ok_or_else(|| not_found(format!("the blob {wanted} is not in the archive")))?;
        let data = self.read_file(&f, max, &wanted.to_string())?;
        if !wanted.verify(&data) {
            return Err(invalid(format!(
                "the blob {wanted} of the archive has another {}",
                wanted.alg()
            )));
        }
        Ok(data)
    }

    /// The content of a blob, read in order; the caller checks it against
    /// `wanted` as it reads.
    pub fn blob_reader(&self, wanted: &Digest) -> io::Result<SectionReader> {
        let f = self
            .find_blob(wanted)
            .ok_or_else(|| not_found(format!("the blob {wanted} is not in the archive")))?;
        Ok(self.section(&f)?.reader())
    }

    /// The images of the archive.
    pub fn images(&self) -> io::Result<Vec<ArchiveImage>> {
        let images = if let Some(f) = self.find("index.json") {
            self.oci_images(&self.read_file(&f, MAX_METADATA, "index.json")?)?
        } else if let Some(f) = self.find("manifest.json") {
            self.docker_images(&self.read_file(&f, MAX_METADATA, "manifest.json")?)?
        } else {
            return Err(invalid("not an image archive: no index.json"));
        };
        if images.is_empty() {
            return Err(not_found("no image in the archive"));
        }
        Ok(images)
    }

    /// The image of a `dir:` directory: its `manifest.json` (one manifest,
    /// no list), named by the digest of its bytes, in the algorithm of the
    /// image.
    pub fn dir_image(&self) -> io::Result<ArchiveImage> {
        let f = self
            .find("manifest.json")
            .ok_or_else(|| not_found("no manifest.json in the directory"))?;
        let manifest = self.read_file(&f, MAX_METADATA, "manifest.json")?;
        if let Some(refusal) = velarx_types::docker::docker_manifest(&manifest) {
            return Err(io::Error::new(io::ErrorKind::Unsupported, refusal));
        }
        let v: serde_json::Value = serde_json::from_slice(&manifest)
            .map_err(|e| invalid(format!("manifest.json is no manifest: {e}")))?;
        if v.get("manifests").is_some() {
            return Err(invalid("dir: of a manifest list is not supported"));
        }
        Ok(ArchiveImage {
            digest: Digest::of(velarx_types::digest::image_algorithm(&manifest), &manifest),
            media_type: v
                .get("mediaType")
                .and_then(|m| m.as_str())
                .map_or_else(|| OCI_MANIFEST.to_string(), str::to_string),
            manifest,
            names: Vec::new(),
            aliases: Vec::new(),
        })
    }

    /// docker-archive: `manifest.json` lists the images with their
    /// configuration, layers and names; an OCI manifest is made of each.
    fn docker_images(&self, data: &[u8]) -> io::Result<Vec<ArchiveImage>> {
        let entries: Vec<DockerEntry> = serde_json::from_slice(data)
            .map_err(|e| invalid(format!("invalid manifest.json: {e}")))?;
        if entries.len() > MAX_DOCKER_ITEMS {
            return Err(invalid("too many images in manifest.json"));
        }
        let mut out = Vec::new();
        for entry in entries {
            if entry.layers.len() > MAX_DOCKER_ITEMS || entry.repo_tags.len() > MAX_DOCKER_ITEMS {
                return Err(invalid("too many layers or names in manifest.json"));
            }
            let config = self.docker_member(&entry.config)?;
            let mut layers = Vec::new();
            for name in &entry.layers {
                let layer = self.docker_member(name)?;
                let mut head = [0u8; 4];
                let n = self.section(&layer)?.reader().read(&mut head)?;
                layers.push(serde_json::json!({
                    "mediaType": sniff_layer_media_type(&head[..n]),
                    "digest": layer.digest.ok_or_else(|| invalid("a member of a directory has no digest"))?,
                    "size": layer.size,
                }));
            }
            let manifest = serde_json::to_vec(&serde_json::json!({
                "schemaVersion": 2,
                "mediaType": OCI_MANIFEST,
                "config": {
                    "mediaType": OCI_CONFIG,
                    "digest": config.digest.ok_or_else(|| invalid("a member of a directory has no digest"))?,
                    "size": config.size,
                },
                "layers": layers,
            }))
            .map_err(|e| invalid(e.to_string()))?;
            let mut names: Vec<String> = Vec::new();
            for name in entry.repo_tags {
                if !names.contains(&name) {
                    names.push(name);
                }
            }
            out.push(ArchiveImage {
                digest: Digest::of(Algorithm::Sha256, &manifest),
                media_type: OCI_MANIFEST.to_string(),
                manifest,
                names,
                aliases: Vec::new(),
            });
        }
        Ok(out)
    }

    /// The regular file a docker-archive's `manifest.json` names: a name
    /// that is absolute or goes up with `..` is refused (it would be
    /// looked up as if it had been resolved from the root of the archive),
    /// and so is one that is no file of the archive (links are followed
    /// inside it only).
    fn docker_member(&self, name: &str) -> io::Result<ArchiveFile<'_>> {
        if name.is_empty() || name.starts_with('/') || name.split('/').any(|p| p == "..") {
            return Err(invalid(format!(
                "invalid member name `{}` in manifest.json",
                name.escape_debug()
            )));
        }
        // (a member its own manifest.json names: the archive is not what
        // it claims)
        self.find(name).ok_or_else(|| {
            invalid(format!(
                "`{}` of manifest.json is not in the archive",
                name.escape_debug()
            ))
        })
    }

    /// oci-archive: `index.json` lists the manifests (or indexes) by digest,
    /// with their names in the annotations.
    fn oci_images(&self, data: &[u8]) -> io::Result<Vec<ArchiveImage>> {
        let index: serde_json::Value = serde_json::from_slice(data)
            .map_err(|e| invalid(format!("invalid index.json: {e}")))?;
        let manifests = index
            .get("manifests")
            .and_then(|v| v.as_array())
            .ok_or_else(|| invalid("invalid index.json: no manifests"))?;
        let mut out = Vec::new();
        for d in manifests {
            let text = d.get("digest").and_then(|v| v.as_str()).unwrap_or("");
            let wanted: Digest = text
                .parse()
                .map_err(|e| invalid(format!("invalid digest `{text}` in index.json: {e}")))?;
            if let Some(m) = d.get("mediaType").and_then(|v| v.as_str()) {
                velarx_types::docker::refuse_media_type(m).map_err(refused)?;
            }
            let blob = self.blob(&wanted, MAX_METADATA)?;
            velarx_types::docker::refuse_manifest(&blob).map_err(refused)?;
            let media_type = d
                .get("mediaType")
                .and_then(|v| v.as_str())
                .filter(|m| m.contains("manifest") || m.contains("index"))
                .map(str::to_string)
                .or_else(|| sniff_manifest(&blob))
                .ok_or_else(|| invalid(format!("unsupported manifest {wanted} in the archive")))?;
            let annotations = d.get("annotations");
            let named = |k: &str| annotations.and_then(|a| a.get(k)?.as_str());
            let name = named("io.containerd.image.name")
                .or_else(|| named("org.opencontainers.image.ref.name"));
            let alias = named("org.opencontainers.image.ref.name").filter(|r| Some(*r) != name);
            out.push(ArchiveImage {
                digest: wanted,
                media_type,
                manifest: blob,
                names: name.map(|n| vec![n.to_string()]).unwrap_or_default(),
                aliases: alias.map(|n| vec![n.to_string()]).unwrap_or_default(),
            });
        }
        Ok(out)
    }
}

/// An image of the `manifest.json` of a docker-archive.
#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct DockerEntry {
    config: String,
    /// (`null` for an image with no name)
    #[serde(default, deserialize_with = "null_is_empty")]
    repo_tags: Vec<String>,
    #[serde(default, deserialize_with = "null_is_empty")]
    layers: Vec<String>,
}

fn null_is_empty<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Vec<String>, D::Error> {
    Ok(Option::<Vec<String>>::deserialize(d)?.unwrap_or_default())
}

/// The media type of a manifest or an index that does not say.
fn sniff_manifest(data: &[u8]) -> Option<String> {
    let v: serde_json::Value = serde_json::from_slice(data).ok()?;
    if v.get("manifests").is_some() {
        Some("application/vnd.oci.image.index.v1+json".into())
    } else if v.get("layers").is_some() {
        Some(OCI_MANIFEST.into())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn tar_with(entries: &[(&str, &[u8])], links: &[(&str, &str, bool)]) -> Vec<u8> {
        let mut b = tar::Builder::new(Vec::new());
        for (name, data) in entries {
            let mut h = tar::Header::new_gnu();
            h.set_size(data.len() as u64);
            h.set_mode(0o644);
            b.append_data(&mut h, name, *data).unwrap();
        }
        for (name, target, hard) in links {
            let mut h = tar::Header::new_gnu();
            h.set_entry_type(if *hard {
                tar::EntryType::Link
            } else {
                tar::EntryType::Symlink
            });
            h.set_size(0);
            b.append_link(&mut h, name, target).unwrap();
        }
        b.into_inner().unwrap()
    }

    fn open(data: &[u8]) -> io::Result<Archive> {
        let dir = tempfile::tempdir().unwrap();
        let mut f = tempfile::tempfile().unwrap();
        f.write_all(data).unwrap();
        Archive::open(f, &File::open(dir.path()).unwrap(), |_| 1 << 40)
    }

    fn open_limited(data: &[u8], floor: u64) -> io::Result<Archive> {
        let dir = tempfile::tempdir().unwrap();
        let mut f = tempfile::tempfile().unwrap();
        f.write_all(data).unwrap();
        Archive::open(f, &File::open(dir.path()).unwrap(), |size| {
            crate::pull::inflate_limit(size as i64, 128, floor, 1 << 40)
        })
    }

    #[test]
    fn test_a_compressed_bomb_is_cut_at_the_limit() {
        let zeros = vec![0u8; 8 << 20];
        let tar = tar_with(&[("bomb", &zeros)], &[]);
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
        gz.write_all(&tar).unwrap();
        let gz = gz.finish().unwrap();
        let zst = zstd::encode_all(&tar[..], 19).unwrap();
        for bomb in [gz, zst] {
            assert!(bomb.len() < 64 * 1024, "{}", bomb.len());
            let e = open_limited(&bomb, 1 << 20).err().unwrap();
            assert!(e.to_string().contains("once decompressed"), "{e}");
            let a = open_limited(&bomb, 16 << 20).unwrap();
            assert!(a.find("bomb").is_some());
        }
    }

    #[test]
    fn test_index_digests_offsets_and_links() {
        let tar = tar_with(
            &[
                ("a/one", b"first"),
                ("b/two", b"second"),
                ("a/one", b"later"),
            ],
            &[("c/link", "../a/one", false), ("d/hard", "b/two", true)],
        );
        let a = open(&tar).unwrap();
        // The last entry of the name wins.
        let one = a.find("a/one").unwrap();
        assert_eq!(one.digest, Some(&crate::sha256(b"later")));
        assert_eq!(a.find("./a//one").unwrap().digest, one.digest);
        assert_eq!(a.find("c/link").unwrap().digest, one.digest);
        assert_eq!(
            a.find("d/hard").unwrap().digest,
            Some(&crate::sha256(b"second"))
        );
        assert!(a.find("missing").is_none());
        assert_eq!(a.blob(&crate::sha256(b"first"), 100).unwrap(), b"first");
        assert!(a.blob(&crate::sha256(b"first"), 2).is_err());
        assert!(a.blob(&crate::sha256(b"unknown"), 100).is_err());
    }

    #[test]
    fn test_links_cannot_loop_or_leave() {
        let tar = tar_with(
            &[],
            &[
                ("a", "b", false),
                ("b", "a", false),
                ("c", "../../../etc/passwd", false),
            ],
        );
        let a = open(&tar).unwrap();
        assert!(a.find("a").is_none());
        assert!(a.find("c").is_none());
    }

    #[test]
    fn test_compressed_archives_are_decompressed() {
        let tar = tar_with(&[("x", b"content")], &[]);
        let gz = {
            let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
            e.write_all(&tar).unwrap();
            e.finish().unwrap()
        };
        for data in [gz, zstd::encode_all(&tar[..], 3).unwrap()] {
            let a = open(&data).unwrap();
            assert_eq!(
                a.find("x").unwrap().digest,
                Some(&crate::sha256(b"content"))
            );
        }
    }

    /// A docker-archive as podman writes it: the layer is a member named
    /// by its digest, the one in the directory of the layer is a link to it.
    fn docker_archive(manifest: &serde_json::Value, layer: &[u8], config: &[u8]) -> Vec<u8> {
        let mut b = tar::Builder::new(Vec::new());
        let mut add = |name: &str, data: &[u8]| {
            let mut h = tar::Header::new_gnu();
            h.set_size(data.len() as u64);
            h.set_mode(0o444);
            b.append_data(&mut h, name, data).unwrap();
        };
        add("cfg.json", config);
        add("l1.tar", layer);
        add("dir/VERSION", b"1.0");
        let mut h = tar::Header::new_gnu();
        h.set_entry_type(tar::EntryType::Symlink);
        h.set_size(0);
        b.append_link(&mut h, "dir/layer.tar", "../l1.tar").unwrap();
        let mut h = tar::Header::new_gnu();
        h.set_size(0);
        h.set_mode(0o444);
        let data = serde_json::to_vec(manifest).unwrap();
        h.set_size(data.len() as u64);
        b.append_data(&mut h, "manifest.json", &data[..]).unwrap();
        b.into_inner().unwrap()
    }

    #[test]
    fn test_a_docker_archive_is_read_as_an_oci_image() {
        let config =
            br#"{"architecture":"amd64","os":"linux","rootfs":{"type":"layers","diff_ids":[]}}"#;
        let layer = tar_with(&[("f", b"x")], &[]);
        let gz = {
            let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
            e.write_all(&layer).unwrap();
            e.finish().unwrap()
        };
        let manifest = serde_json::json!([
            {"Config": "cfg.json", "RepoTags": ["localhost/a:v1", "b:2", "b:2"],
             "Layers": ["dir/layer.tar", "./l1.tar"]},
            {"Config": "cfg.json", "RepoTags": null, "Layers": []},
        ]);
        let a = open(&docker_archive(&manifest, &layer, config)).unwrap();
        let images = a.images().unwrap();
        assert_eq!(images.len(), 2);
        assert_eq!(images[0].names, ["localhost/a:v1", "b:2"]);
        assert!(images[1].names.is_empty());
        let m: serde_json::Value = serde_json::from_slice(&images[0].manifest).unwrap();
        assert_eq!(m["mediaType"], OCI_MANIFEST);
        assert_eq!(m["config"]["mediaType"], OCI_CONFIG);
        // the image id: the digest of the configuration member
        assert_eq!(m["config"]["digest"], crate::sha256_text(config));
        assert_eq!(m["config"]["size"], config.len());
        assert_eq!(m["layers"].as_array().unwrap().len(), 2);
        for l in m["layers"].as_array().unwrap() {
            assert_eq!(l["mediaType"], LAYER);
            assert_eq!(l["digest"], crate::sha256_text(&layer));
            assert_eq!(l["size"], layer.len());
        }
        // the blobs are served by digest, as from an oci-archive
        assert_eq!(a.blob(&crate::sha256(config), 1 << 20).unwrap(), config);
        assert_eq!(a.blob(&crate::sha256(&layer), 1 << 20).unwrap(), layer);
        assert!(images[1].manifest != images[0].manifest);
        // a compressed layer is told by its bytes
        let manifest = serde_json::json!([{"Config": "cfg.json", "Layers": ["l1.tar"]}]);
        let a = open(&docker_archive(&manifest, &gz, config)).unwrap();
        let m: serde_json::Value =
            serde_json::from_slice(&a.images().unwrap()[0].manifest).unwrap();
        assert_eq!(m["layers"][0]["mediaType"], LAYER_GZIP);
        assert_eq!(m["layers"][0]["digest"], crate::sha256_text(&gz));
    }

    #[test]
    fn test_a_hostile_docker_archive_is_refused() {
        let config =
            br#"{"architecture":"amd64","os":"linux","rootfs":{"type":"layers","diff_ids":[]}}"#;
        let layer = tar_with(&[("f", b"x")], &[]);
        let images = |manifest: serde_json::Value| {
            open(&docker_archive(&manifest, &layer, config))
                .unwrap()
                .images()
        };
        // names that leave the archive, though the members they lead to are there
        for bad in ["../l1.tar", "dir/../../l1.tar", "/l1.tar", "", "dir/.."] {
            let e =
                images(serde_json::json!([{"Config": "cfg.json", "Layers": [bad]}])).unwrap_err();
            assert_eq!(e.kind(), io::ErrorKind::InvalidData, "{bad}: {e}");
            let e = images(serde_json::json!([{"Config": bad, "Layers": []}])).unwrap_err();
            assert_eq!(e.kind(), io::ErrorKind::InvalidData, "{bad}: {e}");
        }
        // members that are not there, or are no files
        for bad in ["nothing.tar", "dir", "dir/VERSION/x"] {
            let e = images(serde_json::json!([{"Config": "cfg.json", "Layers": [bad]}]));
            assert!(e.is_err(), "{bad}");
        }
        // (a member its manifest.json names and the archive lacks)
        assert_eq!(
            images(serde_json::json!([{"Config": "gone.json", "Layers": []}]))
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
        // a loop of links, a link out of the archive
        let mut b = tar::Builder::new(Vec::new());
        for (name, target) in [
            ("a.tar", "b.tar"),
            ("b.tar", "a.tar"),
            ("c.tar", "../../etc/passwd"),
        ] {
            let mut h = tar::Header::new_gnu();
            h.set_entry_type(tar::EntryType::Symlink);
            h.set_size(0);
            b.append_link(&mut h, name, target).unwrap();
        }
        let mut h = tar::Header::new_gnu();
        let manifest = serde_json::to_vec(&serde_json::json!([
            {"Config": "a.tar", "Layers": ["c.tar"]}
        ]))
        .unwrap();
        h.set_size(manifest.len() as u64);
        b.append_data(&mut h, "manifest.json", &manifest[..])
            .unwrap();
        let a = open(&b.into_inner().unwrap()).unwrap();
        assert!(a.images().is_err());
        // a manifest.json that is no list of images, or too large, or lists too much
        for bad in [
            serde_json::json!({"Config": "cfg.json"}),
            serde_json::json!([{"Layers": []}]),
            serde_json::json!([{"Config": 1}]),
            serde_json::json!([{"Config": "cfg.json", "Layers": vec!["l1.tar"; MAX_DOCKER_ITEMS + 1]}]),
            serde_json::json!(vec![
                serde_json::json!({"Config": "cfg.json"});
                MAX_DOCKER_ITEMS + 1
            ]),
        ] {
            assert!(images(bad.clone()).is_err(), "{bad}");
        }
        let big = vec![b' '; MAX_METADATA as usize + 1];
        let mut tar = tar_with(&[("manifest.json", &big)], &[]);
        assert!(open(&tar).unwrap().images().is_err());
        tar = tar_with(&[("manifest.json", b"[]")], &[]);
        let e = open(&tar).unwrap().images().unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::NotFound, "no image: {e}");
    }

    #[test]
    fn test_a_docker_archive_with_an_oci_layout_is_read_as_one() {
        // a Docker 25 `docker save` has both: the layout wins
        let manifest = br#"{"schemaVersion":2,"config":{"mediaType":"x","digest":"sha256:00","size":1},"layers":[]}"#;
        let d = crate::sha256(manifest);
        let index = serde_json::to_vec(&serde_json::json!({
            "schemaVersion": 2,
            "manifests": [{"mediaType": OCI_MANIFEST, "digest": d, "size": manifest.len()}]
        }))
        .unwrap();
        let blob = format!("blobs/sha256/{}", d.hex());
        let tar = tar_with(
            &[
                ("index.json", &index),
                ("manifest.json", b"[{\"Config\":\"nothing\"}]"),
                (&blob, manifest),
            ],
            &[],
        );
        assert_eq!(open(&tar).unwrap().images().unwrap()[0].manifest, manifest);
    }

    #[test]
    fn test_a_sha512_oci_archive_is_read_and_its_blobs_are_checked_by_sha512() {
        let manifest = format!(
            r#"{{"schemaVersion":2,"config":{{"mediaType":"x","digest":"sha512:{}","size":1}},"layers":[]}}"#,
            "0".repeat(128)
        );
        let manifest = manifest.as_bytes();
        let d = Digest::of(Algorithm::Sha512, manifest);
        let index = |digest: &Digest| {
            serde_json::to_vec(&serde_json::json!({
                "schemaVersion": 2,
                "manifests": [{"mediaType": OCI_MANIFEST, "digest": digest, "size": manifest.len()}]
            }))
            .unwrap()
        };
        let blob = format!("blobs/sha512/{}", d.hex());
        let tar = tar_with(&[("index.json", &index(&d)), (&blob, manifest)], &[]);
        let a = open(&tar).unwrap();
        let images = a.images().unwrap();
        assert_eq!(
            (images[0].manifest.as_slice(), images[0].digest),
            (manifest, d)
        );
        assert_eq!(a.blob(&d, 1 << 20).unwrap(), manifest);
        // content that is not the sha512 its member is named by
        let tar = tar_with(&[("index.json", &index(&d)), (&blob, b"other")], &[]);
        let e = open(&tar).unwrap().images().unwrap_err();
        assert!(e.to_string().contains("another sha512"), "{e}");
    }

    #[test]
    fn test_docker_schema_2_in_an_oci_layout_is_read_and_foreign_layers_are_refused() {
        let schema2 = br#"{"schemaVersion":2,"mediaType":"application/vnd.docker.distribution.manifest.v2+json","config":{"mediaType":"application/vnd.docker.container.image.v1+json","digest":"sha256:00","size":1},"layers":[{"mediaType":"application/vnd.docker.image.rootfs.diff.tar.gzip","digest":"sha256:00","size":1}]}"#;
        let foreign =
            String::from_utf8_lossy(schema2).replace("rootfs.diff", "rootfs.foreign.diff");
        // the descriptor of the index names the Docker type, so does the
        // manifest it points to, and a Docker 25 `docker save` has both
        // files
        for (docker, ok) in [(&schema2[..], true), (foreign.as_bytes(), false)] {
            let d = crate::sha256(docker);
            let blob = format!("blobs/sha256/{}", d.hex());
            for mt in [
                "application/vnd.docker.distribution.manifest.v2+json",
                OCI_MANIFEST,
            ] {
                let index = serde_json::to_vec(&serde_json::json!({
                    "schemaVersion": 2,
                    "manifests": [{"mediaType": mt, "digest": d, "size": docker.len()}]
                }))
                .unwrap();
                let tar = tar_with(
                    &[
                        ("index.json", &index),
                        ("manifest.json", b"[]"),
                        (&blob, docker),
                    ],
                    &[],
                );
                let images = open(&tar).unwrap().images();
                if ok {
                    assert_eq!(images.unwrap()[0].manifest, docker, "{mt}");
                } else {
                    let e = images.unwrap_err();
                    assert_eq!(e.kind(), io::ErrorKind::Unsupported, "{mt}");
                    assert!(e.to_string().contains("rootfs.foreign.diff"), "{e}");
                }
            }
        }
    }

    #[test]
    fn test_oci_archive_images_and_errors() {
        let manifest = br#"{"schemaVersion":2,"config":{"mediaType":"x","digest":"sha256:00","size":1},"layers":[]}"#;
        let d = crate::sha256(manifest);
        let index = serde_json::to_vec(&serde_json::json!({
            "schemaVersion": 2,
            "manifests": [{"mediaType": OCI_MANIFEST, "digest": d, "size": manifest.len(),
                           "annotations": {"org.opencontainers.image.ref.name": "v3"}}]
        }))
        .unwrap();
        let blob = format!("blobs/sha256/{}", d.hex());
        let tar = tar_with(&[("index.json", &index), (&blob, manifest)], &[]);
        let images = open(&tar).unwrap().images().unwrap();
        assert_eq!(images[0].manifest, manifest);
        assert_eq!(images[0].names, ["v3"]);

        // The manifest the index names must be in the archive.
        let tar = tar_with(&[("index.json", &index)], &[]);
        assert!(open(&tar).unwrap().images().is_err());
        // Neither index nor manifest.
        assert!(open(&tar_with(&[("x", b"y")], &[]))
            .unwrap()
            .images()
            .is_err());
        // Not a tar.
        assert!(open(b"definitely not a tar archive at all").is_err());
        // Garbage JSON.
        let tar = tar_with(&[("index.json", b"{")], &[]);
        assert!(open(&tar).unwrap().images().is_err());
    }
}
