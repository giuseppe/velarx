// SPDX-License-Identifier: Apache-2.0
//! `velarx-dir --origin`: the origin of a pull whose source is a path (an OCI
//! layout `oci:DIR`, a `dir:` directory, an `oci-archive:`, a
//! `docker-archive:` or an `archive:` of either kind), a confined process of
//! its own for the one pull.  The engine opens the path and hands the
//! descriptor in `Open(target)`; the process confines itself there (it reads
//! what it was handed, writes beneath the staging it was handed, executes
//! nothing and opens no socket) and only then reads the untrusted bytes: the
//! tar, the compression, the index and the manifests of the archive never
//! reach the engine's process.
//!
//! It serves:
//!
//! * `GetManifest("")`: the index of the images the selector of the source
//!   (`Open(source)`: the scheme and the selector, `oci-archive:NAME`, never
//!   the path) takes, as an OCI index; each name an image has in the archive
//!   is the annotation `org.opencontainers.image.ref.name` of a descriptor
//!   (a docker-archive's manifests are made of its `manifest.json`);
//! * `GetManifest(digest)` and `GetBlob`;
//! * `Unpack` of every layer (an archive carries no table of contents): the
//!   files of the layer staged by the object contract, the claim of the table
//!   and the tar-split.
//!
//! All of it is a claim: the engine checks the digests of the manifests and
//! of the configurations, and replays the layers against the diff ids.

use crate::archive::{Archive, ArchiveImage, MAX_METADATA};
use crate::fetcher::fetch::{Failure, FailureClass, FetchEvent as Event, FetcherError};
use crate::list::HelperSettings;
use crate::origin::{path_source, PathScheme};
use crate::serve_fetch::{beating, Described, LayerScope, Out, Scope, StagingFetcher, UnpackCall};
use async_trait::async_trait;
use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::sync::Arc;
use velarx_types::digest::{Digest, DigestWriter};
use velarx_types::ImageReference;

const OCI_INDEX: &str = "application/vnd.oci.image.index.v1+json";
const REF_NAME: &str = "org.opencontainers.image.ref.name";

/// What confines the process once its origin is open: the scheme and the
/// origin (the directory, or the file).  It runs on the thread that serves
/// `Open`, and the process has no other thread then.
pub type Confine = Box<dyn Fn(PathScheme, &File) -> Result<(), String> + Send + Sync>;

/// What the process read of its origin, once, at the first call.
struct Read_ {
    archive: Arc<Archive>,
    /// The index of the images the selector takes
    index: Vec<u8>,
    /// Their manifests (a docker-archive's are made, not members), by digest
    manifests: HashMap<String, (Vec<u8>, String)>,
}

/// The fetcher of the origin of a path.
pub struct DirOrigin {
    confine: Confine,
    settings: HelperSettings,
    /// The staging of the layers of the store: where a compressed archive
    /// is decompressed to
    staging: Arc<File>,
    read: tokio::sync::OnceCell<Arc<Read_>>,
}

fn invalid(reason: impl Into<String>) -> FetcherError {
    FetcherError::Failed {
        failure: Failure {
            class: FailureClass::Invalid,
            reason: reason.into(),
        },
    }
}

/// An error of reading the archive: a Docker format is what the engine
/// refuses by name, what is not an archive is invalid content.
fn read_error(e: std::io::Error) -> FetcherError {
    match e.kind() {
        std::io::ErrorKind::Unsupported => FetcherError::NotSupported {
            feature: e.to_string(),
        },
        // (an archive cut short is not what it claims)
        std::io::ErrorKind::InvalidData | std::io::ErrorKind::UnexpectedEof => {
            invalid(e.to_string())
        }
        std::io::ErrorKind::NotFound => FetcherError::not_found(e.to_string()),
        std::io::ErrorKind::StorageFull | std::io::ErrorKind::QuotaExceeded => {
            FetcherError::no_space(e.to_string())
        }
        _ => FetcherError::failed(e.to_string()),
    }
}

/// Whether `name` is `tag`, as the same reference.
fn same_name(name: &str, tag: &str) -> bool {
    name == tag
        || matches!(
            (ImageReference::parse(name), ImageReference::parse(tag)),
            (Ok(a), Ok(b)) if a.full_name() == b.full_name()
        )
}

/// `tag` qualified with its registry, as the engine names a bare name of an
/// archive local: the name a layout gives its image.
fn qualified(tag: &str) -> String {
    match ImageReference::parse(tag) {
        Ok(r) if r.digest.is_none() => format!(
            "{}/{}:{}",
            r.registry,
            r.repository,
            r.tag.as_deref().unwrap_or("latest")
        ),
        _ => tag.to_string(),
    }
}

fn listed(images: &[ArchiveImage]) -> String {
    images
        .iter()
        .map(|i| i.names.first().map_or("(no name)", String::as_str))
        .collect::<Vec<_>>()
        .join(", ")
}

/// The images `scheme` and `selector` take of `images`, with the names each
/// has: an archive loaded takes all of them; the others the one image that is
/// named, or that there is.
fn select(
    mut images: Vec<ArchiveImage>,
    scheme: PathScheme,
    selector: Option<&str>,
) -> Result<Vec<ArchiveImage>, FetcherError> {
    let what = format!("{}:{}", scheme.name(), selector.unwrap_or(""));
    match scheme {
        PathScheme::Archive | PathScheme::Dir => Ok(images),
        PathScheme::Oci | PathScheme::OciArchive => {
            let chosen: Vec<usize> = (0..images.len())
                .filter(|&i| {
                    selector.is_none_or(|t| {
                        images[i]
                            .names
                            .iter()
                            .chain(&images[i].aliases)
                            .any(|n| same_name(n, t))
                    })
                })
                .collect();
            let one = match chosen.as_slice() {
                [one] => *one,
                [] if selector.is_some() => {
                    return Err(invalid(format!(
                        "{what}: no image named `{}` (it has: {})",
                        selector.unwrap_or_default(),
                        listed(&images)
                    )))
                }
                [] => return Err(invalid(format!("{what}: no image"))),
                _ => {
                    return Err(invalid(format!(
                        "{what}: {} images ({}): name one, as in {}:NAME",
                        chosen.len(),
                        listed(&images),
                        scheme.name()
                    )))
                }
            };
            let mut image = images.swap_remove(one);
            if scheme == PathScheme::Oci {
                // (a layout: the image is named after the TAG of
                // `oci:PATH:TAG`, and is unnamed without one, whatever the
                // entry says)
                image.names = selector.map(qualified).into_iter().collect();
            }
            Ok(vec![image])
        }
        PathScheme::DockerArchive => {
            let one = match selector {
                Some(n) if n.starts_with('@') => {
                    let i = n[1..]
                        .parse::<usize>()
                        .map_err(|_| invalid(format!("{what}: invalid source index {n}")))?;
                    if i >= images.len() {
                        return Err(invalid(format!(
                            "{what}: invalid source index {n}, only {} manifest items available",
                            images.len()
                        )));
                    }
                    i
                }
                // (the first entry that has the reference, as containers/image)
                Some(reference) => images
                    .iter()
                    .position(|i| i.names.iter().any(|n| same_name(n, reference)))
                    .ok_or_else(|| {
                        invalid(format!(
                            "{what}: no image named `{reference}` (it has: {})",
                            images
                                .iter()
                                .map(|i| if i.names.is_empty() {
                                    "(no name)".to_string()
                                } else {
                                    i.names.join(", ")
                                })
                                .collect::<Vec<_>>()
                                .join("; ")
                        ))
                    })?,
                None if images.len() == 1 => 0,
                None => {
                    return Err(invalid(format!(
                        "{what}: expected 1 image in manifest.json, got {} ({}): name one, as in docker-archive:FILE:REF or docker-archive:FILE:@N",
                        images.len(),
                        listed(&images)
                    )))
                }
            };
            Ok(vec![images.swap_remove(one)])
        }
    }
}

impl DirOrigin {
    /// The origin of a path, which it learns from `Open`; `confine` is what
    /// restricts the process then.
    pub fn new(confine: Confine, settings: HelperSettings, staging: Arc<File>) -> Arc<Self> {
        Arc::new(Self {
            confine,
            settings,
            staging,
            read: tokio::sync::OnceCell::new(),
        })
    }

    /// What the origin holds, read at the first call (after the process
    /// confined itself).
    async fn read(&self, scope: &Scope) -> Result<Arc<Read_>, FetcherError> {
        self.read
            .get_or_try_init(|| async {
                let (scheme, selector) =
                    scope
                        .source
                        .as_deref()
                        .and_then(path_source)
                        .ok_or_else(|| FetcherError::InvalidArgument {
                            reason: "the source of a path is its scheme and its selector".into(),
                        })?;
                let target = scope
                    .target
                    .as_ref()
                    .ok_or_else(|| FetcherError::InvalidArgument {
                        reason: "the origin of a path needs a target".into(),
                    })?
                    .try_clone()
                    .map_err(|e| FetcherError::failed(e.to_string()))?;
                let (staging, s) = (self.staging.clone(), &self.settings);
                let (ratio, floor, max) = (
                    s.max_inflate_ratio.max(1),
                    s.inflate_floor_mib * 1024 * 1024,
                    s.max_archive_gib.max(1) * 1024 * 1024 * 1024,
                );
                tokio::task::spawn_blocking(move || {
                    read_origin(
                        scheme,
                        selector.as_deref(),
                        target,
                        &staging,
                        (ratio, floor, max),
                    )
                })
                .await
                .map_err(|e| FetcherError::failed(e.to_string()))?
                .map(Arc::new)
            })
            .await
            .cloned()
    }
}

/// Read the origin: the archive, and the index of the images the selector
/// takes.
fn read_origin(
    scheme: PathScheme,
    selector: Option<&str>,
    target: File,
    staging: &File,
    (ratio, floor, max): (u64, u64, u64),
) -> Result<Read_, FetcherError> {
    let meta = target
        .metadata()
        .map_err(|e| FetcherError::failed(e.to_string()))?;
    // (`archive:` is either kind: a load of a layout directory or of a tar)
    if scheme != PathScheme::Archive && meta.is_dir() != scheme.is_directory() {
        return Err(FetcherError::InvalidArgument {
            reason: format!(
                "the origin of {}: is {}",
                scheme.name(),
                if scheme.is_directory() {
                    "not a directory"
                } else {
                    "a directory, not a file"
                }
            ),
        });
    }
    let archive = if meta.is_dir() {
        Archive::tree(target)
    } else {
        Archive::open(target, staging, |size| {
            crate::pull::inflate_limit(i64::try_from(size).unwrap_or(i64::MAX), ratio, floor, max)
        })
    }
    .map_err(read_error)?;
    let images = if scheme == PathScheme::Dir {
        vec![archive.dir_image().map_err(read_error)?]
    } else {
        archive.images().map_err(|e| {
            // (a docker-archive read as an OCI one, and the other way round,
            // is said so)
            let message = e.to_string();
            if e.kind() == std::io::ErrorKind::InvalidData && message.contains("no index.json") {
                if archive.find("manifest.json").is_some() {
                    return FetcherError::NotSupported {
                        feature: velarx_types::docker::archive_refusal(),
                    };
                }
                return invalid("no index.json: this is no OCI archive");
            }
            read_error(e)
        })?
    };
    let images = select(images, scheme, selector)?;
    let mut manifests = HashMap::new();
    let mut descriptors = Vec::new();
    for image in &images {
        manifests.insert(
            image.digest.to_string(),
            (image.manifest.clone(), image.media_type.clone()),
        );
        let descriptor = |name: Option<&str>| {
            let mut d = serde_json::json!({
                "mediaType": image.media_type,
                "digest": image.digest,
                "size": image.manifest.len(),
            });
            if let Some(name) = name {
                d["annotations"] = serde_json::json!({ REF_NAME: name });
            }
            d
        };
        if image.names.is_empty() {
            descriptors.push(descriptor(None));
        }
        for name in &image.names {
            descriptors.push(descriptor(Some(name)));
        }
    }
    let index = serde_json::to_vec(&serde_json::json!({
        "schemaVersion": 2,
        "mediaType": OCI_INDEX,
        "manifests": descriptors,
    }))
    .map_err(|e| FetcherError::failed(e.to_string()))?;
    Ok(Read_ {
        archive: Arc::new(archive),
        index,
        manifests,
    })
}

/// A sealed memory file with `bytes`.
fn sealed(bytes: &[u8]) -> Result<File, FetcherError> {
    velarx_base::sealed::sealed_memory(bytes)
        .map(File::from)
        .map_err(|e| FetcherError::failed(e.to_string()))
}

/// What reads a blob and counts and hashes what it gave.
struct Hashing<R> {
    inner: R,
    hasher: DigestWriter,
    bytes: u64,
    /// The bytes read so far, for the beats
    count: Arc<std::sync::atomic::AtomicU64>,
}

impl<R: Read> Read for Hashing<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.hasher.update(&buf[..n]);
        self.bytes += n as u64;
        self.count
            .store(self.bytes, std::sync::atomic::Ordering::Relaxed);
        Ok(n)
    }
}

#[async_trait]
impl StagingFetcher for DirOrigin {
    fn described(&self) -> Described {
        Described {
            name: "dir".into(),
            capabilities: vec!["metadata".into(), "unpack".into(), "origin".into()],
            max_objects: 1,
        }
    }

    async fn opened(&self, scope: &Scope) -> Result<(), FetcherError> {
        let (scheme, _) = scope
            .source
            .as_deref()
            .and_then(path_source)
            .ok_or_else(|| FetcherError::NotSupported {
                feature: scope.source.clone().unwrap_or_default(),
            })?;
        let target = scope
            .target
            .as_ref()
            .ok_or_else(|| FetcherError::InvalidArgument {
                reason: "the origin of a path needs a target".into(),
            })?;
        (self.confine)(scheme, target)
            .map_err(|e| FetcherError::failed(format!("cannot confine: {e}")))
    }

    async fn get_manifest(
        &self,
        scope: &Scope,
        reference: &str,
        max: u64,
    ) -> Result<(File, Option<String>), FetcherError> {
        let read = self.read(scope).await?;
        if reference.is_empty() {
            return Ok((sealed(&read.index)?, Some(OCI_INDEX.to_string())));
        }
        if let Some((bytes, media_type)) = read.manifests.get(reference) {
            return Ok((sealed(bytes)?, Some(media_type.clone())));
        }
        let digest: Digest = reference
            .parse()
            .map_err(|_| FetcherError::unavailable(format!("{reference}: not here")))?;
        let archive = read.archive.clone();
        let bytes =
            tokio::task::spawn_blocking(move || archive.blob(&digest, max.min(MAX_METADATA)))
                .await
                .map_err(|e| FetcherError::failed(e.to_string()))?
                .map_err(|e| match e.kind() {
                    std::io::ErrorKind::NotFound => {
                        FetcherError::unavailable(format!("{reference}: not here"))
                    }
                    _ => read_error(e),
                })?;
        Ok((sealed(&bytes)?, None))
    }

    async fn get_blob(
        &self,
        scope: &Scope,
        blob: &crate::fetcher::fetch::Blob,
    ) -> Result<File, FetcherError> {
        let read = self.read(scope).await?;
        let digest: Digest = blob
            .digest
            .parse()
            .map_err(|_| FetcherError::InvalidArgument {
                reason: "not the digest of a blob".into(),
            })?;
        let (archive, size) = (read.archive.clone(), blob.size);
        let bytes = tokio::task::spawn_blocking(move || archive.blob(&digest, size))
            .await
            .map_err(|e| FetcherError::failed(e.to_string()))?
            .map_err(|e| match e.kind() {
                std::io::ErrorKind::NotFound => {
                    FetcherError::unavailable(format!("{}: not here", blob.digest))
                }
                _ => read_error(e),
            })?;
        if bytes.len() as u64 != blob.size {
            return Err(invalid(format!(
                "the blob {} has {} bytes, the descriptor says {}",
                blob.digest,
                bytes.len(),
                blob.size
            )));
        }
        sealed(&bytes)
    }

    async fn unpack(
        &self,
        scope: &Scope,
        layer: &LayerScope,
        call: UnpackCall,
        out: &Out<Event>,
    ) -> Result<(), FetcherError> {
        let read = self.read(scope).await?;
        let Some(blob) = &layer.blob else {
            return Err(FetcherError::unavailable(
                "the blob of the layer is not known",
            ));
        };
        let digest: Digest = blob
            .digest
            .parse()
            .map_err(|_| FetcherError::InvalidArgument {
                reason: "not the digest of a blob".into(),
            })?;
        if digest.to_string() != layer.layer {
            return Err(FetcherError::InvalidArgument {
                reason: "the blob is not the layer's".into(),
            });
        }
        let staging = layer
            .staging
            .try_clone()
            .map_err(|e| FetcherError::failed(e.to_string()))?;
        let s = &self.settings;
        let cap = crate::pull::inflate_limit(
            i64::try_from(blob.size).unwrap_or(i64::MAX),
            s.max_inflate_ratio.max(1),
            s.inflate_floor_mib * 1024 * 1024,
            s.max_file_bytes,
        );
        let (archive, verity, size) = (read.archive.clone(), scope.verity, blob.size);
        let mut handing = crate::unpack::Files::new(out.clone());
        let count = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let counted = count.clone();
        let work = tokio::task::spawn_blocking(move || {
            let section = archive.blob_reader(&digest)?;
            if section.size() != size {
                return Err(ImageFailure::Invalid(format!(
                    "layer {digest} has {} bytes, its descriptor says {size}",
                    section.size()
                )));
            }
            let mut hashing = Hashing {
                inner: section,
                hasher: DigestWriter::for_digest(&digest),
                bytes: 0,
                count: counted,
            };
            let mut head = [0u8; 4];
            let mut got = 0;
            while got < head.len() {
                let n = hashing.read(&mut head[got..]).map_err(ImageFailure::Io)?;
                if n == 0 {
                    break;
                }
                got += n;
            }
            let kind = velarx_tarsplit::decompress::sniff(&head[..got]);
            let input = std::io::Cursor::new(head[..got].to_vec()).chain(&mut hashing);
            let decoder =
                velarx_tarsplit::decompress::Decoder::new(kind, std::io::BufReader::new(input))
                    .map_err(ImageFailure::Io)?;
            // (what inflates past the cap is cut: a bomb ends the layer)
            let limited = LimitedRead::new(decoder, cap);
            let (toc, tarsplit) =
                crate::unpack::unpack_tar(limited, &staging, (digest.alg(), verity), &mut handing)
                    .map_err(ImageFailure::Image)?;
            // (the tar ends before the blob does: the rest is read, for the
            // hash of the blob)
            std::io::copy(&mut hashing, &mut std::io::sink()).map_err(ImageFailure::Io)?;
            let read = hashing.hasher.finalize();
            if read != digest {
                return Err(ImageFailure::Image(
                    velarx_types::ImageError::DigestMismatch {
                        expected: digest.to_string(),
                        actual: read.to_string(),
                    },
                ));
            }
            crate::unpack::put_claim(&staging, &toc, &tarsplit).map_err(ImageFailure::Image)
        });
        tokio::pin!(work);
        let idle = scope.idle;
        let beat = || Event::progress(None, count.load(std::sync::atomic::Ordering::Relaxed));
        let done = tokio::select! {
            d = beating(out, idle, beat, &mut work) => d,
            _ = call.cancel.cancelled() => return Ok(()),
        };
        let unpacked = done.map_err(|e| FetcherError::failed(e.to_string()))?;
        match unpacked {
            Ok(()) => {
                let _ = out.send(Event::progress(None, size)).await;
                Ok(())
            }
            Err(ImageFailure::Invalid(reason)) => Err(invalid(reason)),
            // (a layer its manifest names that the archive lacks: what the
            // archive holds is not what it claims)
            Err(ImageFailure::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => {
                Err(invalid(e.to_string()))
            }
            Err(ImageFailure::Io(e)) => Err(read_error(e)),
            // (the staging cannot be written: not what the archive holds)
            Err(ImageFailure::Image(velarx_types::ImageError::Io(e))) => Err(read_error(e)),
            Err(ImageFailure::Image(e)) => Err(invalid(e.to_string())),
        }
    }
}

/// What failed in the unpacking of a layer.
enum ImageFailure {
    Invalid(String),
    Io(std::io::Error),
    Image(velarx_types::ImageError),
}

impl From<std::io::Error> for ImageFailure {
    fn from(e: std::io::Error) -> Self {
        ImageFailure::Io(e)
    }
}

/// A reader that fails after `left` bytes: what a layer may inflate to.
struct LimitedRead<R> {
    inner: R,
    left: u64,
}

impl<R: Read> LimitedRead<R> {
    fn new(inner: R, max: u64) -> Self {
        Self { inner, left: max }
    }
}

impl<R: Read> Read for LimitedRead<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        if n as u64 > self.left {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "the layer is larger than the limit once uncompressed ([pull] max_inflate_ratio, inflate_floor_mib, max_layer_gib)",
            ));
        }
        self.left -= n as u64;
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn image(n: u8, names: &[&str]) -> ArchiveImage {
        let manifest = vec![n];
        ArchiveImage {
            digest: crate::sha256(&manifest),
            media_type: "application/vnd.oci.image.manifest.v1+json".into(),
            manifest,
            names: names.iter().map(|s| s.to_string()).collect(),
            aliases: Vec::new(),
        }
    }

    fn names(images: &[ArchiveImage]) -> String {
        images
            .iter()
            .map(|i| i.names.join(" "))
            .collect::<Vec<_>>()
            .join(";")
    }

    fn chosen(
        images: Vec<ArchiveImage>,
        scheme: PathScheme,
        selector: Option<&str>,
    ) -> Result<String, String> {
        select(images, scheme, selector)
            .map(|i| names(&i))
            .map_err(|e| e.to_string())
    }

    #[test]
    fn a_docker_archive_gives_the_named_or_indexed_image() {
        let archive = || {
            vec![
                image(1, &["localhost/a:v1", "docker.io/library/b:2"]),
                image(2, &[]),
                image(3, &["reg.io/x/y:3"]),
            ]
        };
        let docker = |selector| chosen(archive(), PathScheme::DockerArchive, selector);
        // no selector with several images: the message says what the archive
        // has and how to name one
        let e = docker(None).unwrap_err();
        assert!(
            e.contains("expected 1 image in manifest.json, got 3") && e.contains("localhost/a:v1"),
            "{e}"
        );
        assert!(e.contains("FILE:@N") && e.contains("(no name)"), "{e}");
        // a reference: one of the RepoTags, as the same reference
        for tag in ["localhost/a:v1", "b:2", "@0"] {
            assert_eq!(
                docker(Some(tag)).unwrap(),
                "localhost/a:v1 docker.io/library/b:2",
                "{tag}"
            );
        }
        assert_eq!(docker(Some("reg.io/x/y:3")).unwrap(), "reg.io/x/y:3");
        // @N: the N-th entry of manifest.json, the first is @0
        assert_eq!(docker(Some("@1")).unwrap(), "");
        let e = docker(Some("@3")).unwrap_err();
        assert!(e.contains("only 3 manifest items available"), "{e}");
        let e = docker(Some("@x")).unwrap_err();
        assert!(e.contains("invalid source index"), "{e}");
        let e = docker(Some("nope")).unwrap_err();
        assert!(e.contains("no image named `nope`"), "{e}");
        // the first entry that has the reference is taken
        let twice = vec![
            image(1, &["localhost/a:v1"]),
            image(2, &["localhost/a:v1", "localhost/a:v2"]),
        ];
        assert_eq!(
            chosen(twice, PathScheme::DockerArchive, Some("localhost/a:v1")).unwrap(),
            "localhost/a:v1"
        );
        assert_eq!(
            chosen(vec![image(1, &["v1"])], PathScheme::DockerArchive, None).unwrap(),
            "v1"
        );
    }

    #[test]
    fn an_oci_origin_gives_the_image_named_or_the_only_one() {
        let two = || vec![image(1, &["v1"]), image(2, &["v2"])];
        for scheme in [PathScheme::Oci, PathScheme::OciArchive] {
            let e = chosen(two(), scheme, Some("v3")).unwrap_err();
            assert!(
                e.contains("no image named `v3`") && e.contains("v1, v2"),
                "{e}"
            );
            let e = chosen(two(), scheme, None).unwrap_err();
            assert!(e.contains("2 images") && e.contains(":NAME"), "{e}");
            assert!(chosen(vec![image(1, &[])], scheme, None).is_ok());
            assert!(chosen(Vec::new(), scheme, None).is_err());
        }
        assert_eq!(chosen(two(), PathScheme::Archive, None).unwrap(), "v1;v2");
    }

    #[test]
    fn a_layout_names_the_image_after_the_tag_and_an_archive_keeps_its_names() {
        let one = || vec![image(1, &["v1"])];
        assert_eq!(
            chosen(one(), PathScheme::Oci, Some("v1")).unwrap(),
            "docker.io/library/v1:latest"
        );
        assert_eq!(
            chosen(one(), PathScheme::Oci, None).unwrap(),
            "",
            "a layout without a tag names nothing, whatever the entry says"
        );
        assert_eq!(
            chosen(one(), PathScheme::OciArchive, Some("v1")).unwrap(),
            "v1"
        );
    }

    #[test]
    fn a_name_matches_as_the_same_reference() {
        assert!(same_name("alpine:3", "docker.io/library/alpine:3"));
        assert!(same_name("v1", "v1"));
        assert!(!same_name("alpine:3", "alpine:4"));
    }
}
