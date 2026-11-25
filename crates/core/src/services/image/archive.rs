// SPDX-License-Identifier: Apache-2.0
//! Image archives and imports on top of the pull engine.

use super::pull::Incoming;
use super::*;
use velarx_content::archive::Archive;
use velarx_content::pull::net::Net;
use velarx_content::pull::Source;
use velarx_types::digest::DigestWriter;

/// An image that was loaded.
#[derive(Debug, Clone, Serialize)]
pub struct LoadedImage {
    pub id: String,
    pub names: Vec<String>,
}

/// `name` as a stored reference; names that are not valid are dropped, and
/// the ones without a registry are on docker.io.
pub(super) fn archive_tag(name: &str, image_id: &str) -> Option<(String, ImageTag)> {
    let r = ImageReference::parse(name).ok()?;
    r.validate().ok()?;
    if r.digest.is_some() {
        return None;
    }
    Some((
        r.full_name(),
        ImageTag {
            repository: r.name(),
            tag: r.tag.clone()?,
            image_id: image_id.to_string(),
        },
    ))
}

/// A name as written in an archive: one without a registry is local, as
/// podman loads it (`v1` is `localhost/v1:latest`).
pub(super) fn archive_name(name: &str) -> String {
    let first = name.split('/').next().unwrap_or("");
    if name.contains('/') && velarx_base::reference::is_registry_domain(first) {
        name.to_string()
    } else {
        format!("localhost/{name}")
    }
}

/// The name of a stored tag, with its registry, as archives spell it.
pub(super) fn qualified_name(t: &ImageTag) -> String {
    let first = t.repository.split('/').next().unwrap_or("");
    if velarx_base::reference::is_registry_domain(first) {
        format!("{}:{}", t.repository, t.tag)
    } else {
        format!("docker.io/{}:{}", t.repository, t.tag)
    }
}

impl ImageService {
    /// The names to write the images `references` with.
    pub async fn save_names(
        &self,
        references: &[String],
    ) -> ImageResult<Vec<(String, Vec<String>)>> {
        if references.is_empty() {
            return Err(ImageError::NotFound("no image to save".into()));
        }
        let mut named = Vec::with_capacity(references.len());
        for reference in references {
            let image = self.get(reference).await?;
            let tags = self.db.get_tags_for_image(&image.id).await?;
            named.push((
                reference.clone(),
                requested_names(reference, &[&image.id, &image.config_digest.hex()], &tags),
            ));
        }
        Ok(named)
    }

    /// A file for a tarball received: it has no name (`O_TMPFILE`), so it
    /// counts against the quota from the first byte and goes with a
    /// failure.
    pub fn spool(&self) -> std::io::Result<File> {
        std::fs::create_dir_all(&self.staging_dir)?;
        velarx_content::pull::unnamed::unnamed_file(&self.staging_dir)
    }

    /// The file at `url` (http or https), in a spool file: what podman
    /// import takes from a URL.  A connection that stalls for a minute
    /// fails.
    pub async fn download(&self, url: &str) -> ImageResult<File> {
        use std::io::Write;
        // (the fetcher parses the URL)
        if !(url.starts_with("http://") || url.starts_with("https://")) {
            return Err(ImageError::Storage(format!(
                "unsupported URL `{}`: http or https",
                printable(url)
            )));
        }
        // The request and the bytes of the server: in a confined worker;
        // this process only stores the body.
        let limit = self.pull_config.max_layer_gib.max(1) * 1024 * 1024 * 1024;
        let file = self.spool()?;
        // (the zeros of what comes are holes of the file)
        let mut out = velarx_storage::SparseWriter::new(file.try_clone()?);
        self.url_fetcher()?
            .fetch(url, limit, &mut |chunk| out.write_all(chunk))
            .await
            .map_err(|e| {
                ImageError::Storage(format!(
                    "downloading {}: {}",
                    printable(url),
                    printable(&e.to_string())
                ))
            })?;
        out.finish()?;
        Ok(file)
    }

    /// The `[pull]` configuration: the confinement of the workers that
    /// download URLs too.
    pub fn pull_config(&self) -> &velarx_config::PullConfig {
        &self.pull_config
    }

    /// What downloads URLs: the registry fetcher process (this one makes
    /// no request).
    pub fn url_fetcher(&self) -> ImageResult<velarx_content::pull::net::origin::OriginUrls> {
        let origin = self.origin()?;
        Ok(velarx_content::pull::net::origin::OriginUrls::new(
            origin.clone(),
            self.staging_area().root().to_path_buf(),
        ))
    }

    /// Create an image from the tar of a root file system in `input`.
    pub async fn import_tar(
        &self,
        input: File,
        name: Option<&str>,
        changes: &[String],
        message: Option<&str>,
    ) -> ImageResult<String> {
        self.import_tar_for(input, name, changes, message, None, None)
            .await
    }

    /// [`Self::import_tar`] for an image of `platform` (this host's by
    /// default): what its configuration says, nothing is checked.
    /// `digest`: `sha256` or `sha512`, the algorithm of every digest of the
    /// image (the layer, its diff id, the configuration, the manifest);
    /// none: `[build] digest`.
    pub async fn import_tar_for(
        &self,
        input: File,
        name: Option<&str>,
        changes: &[String],
        message: Option<&str>,
        platform: Option<&velarx_registry::target::Platform>,
        digest: Option<&str>,
    ) -> ImageResult<String> {
        let alg = self.creation_algorithm(digest)?;
        self.check_digest_algorithm(alg)?;
        let tag = match name.filter(|n| !n.is_empty()) {
            Some(n) => Some(local_reference(n)?),
            None => None,
        };
        let max = self.pull_config.max_layer_gib.max(1) * 1024 * 1024 * 1024;
        let staging = self.staging_dir.clone();
        let (archive, layer, diff_id) = tokio::task::spawn_blocking(move || -> ImageResult<_> {
            std::fs::create_dir_all(&staging)?;
            let mut input = input;
            let mut size = input.metadata()?.len();
            // nothing is an empty file system, as for Docker: the end of a
            // tar archive alone
            if size == 0 {
                let mut empty = velarx_content::pull::unnamed::unnamed_file(&staging)?;
                std::io::Write::write_all(&mut empty, &[0u8; 1024])?;
                input = empty;
                size = 1024;
            }
            let mut head = [0u8; 4];
            let n = std::os::unix::fs::FileExt::read_at(&input, &mut head, 0)?;
            let mut media_type = velarx_content::archive::sniff_layer_media_type(&head[..n]);
            // The blob digest, and the diff id once it is decompressed.
            let mut blob = Digest::of_file_at(alg, &input, size)?.0;
            // (a tar is its own diff id)
            let (mut diff_id, sparse) =
                if media_type == velarx_content::archive::LAYER && size <= max {
                    let mut ar = tar::Archive::new(std::io::BufReader::new(at_start(&input)?));
                    // (an archive the tar crate cannot read is the layer's
                    // to refuse)
                    let sparse = ar
                        .entries_with_seek()
                        .and_then(velarx_wire::sparse::any_sparse)
                        .unwrap_or(false);
                    (blob, sparse)
                } else {
                    diff_id(&input, media_type, max, alg)?
                };
            // A layer has no sparse file: the tar of the import, its sparse
            // files written whole (as podman's import does), the zeros of
            // the holes holes of the file that holds the tar.
            if sparse {
                let (expanded, digest) =
                    expand_sparse(decoded(&input, media_type)?, &staging, max, alg)
                        .map_err(|e| ImageError::Layer(format!("the archive: {e}")))?;
                input = expanded;
                size = input.metadata()?.len();
                media_type = velarx_content::archive::LAYER;
                blob = digest;
                diff_id = digest;
            }
            let archive = Archive::single(input, blob, size);
            Ok((
                archive,
                OciDescriptor {
                    media_type: media_type.to_string(),
                    digest: blob,
                    size: size as i64,
                    annotations: HashMap::new(),
                },
                diff_id,
            ))
        })
        .await
        .map_err(|e| ImageError::Layer(e.to_string()))??;

        let now = chrono::Utc::now().to_rfc3339();
        let host = velarx_registry::target::Platform::host();
        let p = platform.unwrap_or(&host);
        let mut config = serde_json::json!({
            "created": now,
            "architecture": p.arch,
            "os": p.os,
            "config": {},
            "rootfs": {"type": "layers", "diff_ids": [diff_id]},
            "history": [{
                "created": now,
                "created_by": format!(
                    "/bin/sh -c #(nop) ADD file:{} in / ",
                    diff_id.hex()
                ),
                "comment": message.unwrap_or(""),
            }],
        });
        if let Some(v) = &p.variant {
            config["variant"] = serde_json::json!(v);
        }
        for change in changes {
            changes::apply(&mut config, change).map_err(ImageError::Manifest)?;
        }
        let config_bytes = serde_json::to_vec(&config)?;
        let config_digest = Digest::of(alg, &config_bytes);
        let manifest = OciManifest {
            schema_version: 2,
            media_type: Some("application/vnd.oci.image.manifest.v1+json".into()),
            config: OciDescriptor {
                media_type: "application/vnd.oci.image.config.v1+json".into(),
                digest: config_digest,
                size: config_bytes.len() as i64,
                annotations: HashMap::new(),
            },
            layers: vec![layer],
            annotations: HashMap::new(),
        };
        let manifest_bytes = serde_json::to_vec(&manifest)?;
        let manifest_digest = Digest::of(alg, &manifest_bytes);
        let image_id = self
            .db
            .image_id_for(&manifest_digest, &manifest_digest)
            .await?;
        let tags: Vec<ImageTag> = tag
            .iter()
            .filter_map(|t| archive_tag(t, &image_id).map(|(_, t)| t))
            .collect();
        let incoming = Incoming {
            config: serde_json::from_slice(&config_bytes)?,
            manifest,
            manifest_bytes: Bytes::from(manifest_bytes),
            manifest_digest,
            config_bytes: Bytes::from(config_bytes),
            source: Some(Source::Archive(Arc::new(archive))),
            via: None,
            made: Vec::new(),
            registry_ref: None,
            tags,
            digest_names: Vec::new(),
            lazy: false,
            sources: None,
            reach: Default::default(),
            seal: false,
            states: true,
            hold: None,
            pulled: Vec::new(),
            access: None,
            indexes: Vec::new(),
            recorded: Vec::new(),
        };
        let (progress, mut rx) = mpsc::channel(8);
        tokio::spawn(async move { while rx.recv().await.is_some() {} });
        let net = Net::offline();
        let result = self
            .install(net, incoming, progress, std::time::Instant::now())
            .await?;
        Ok(result.id)
    }
}

/// `file` from its start.
fn at_start(file: &File) -> std::io::Result<File> {
    use std::io::{Seek, SeekFrom};
    let mut input = file.try_clone()?;
    input.seek(SeekFrom::Start(0))?;
    Ok(input)
}

/// The tar in `file`, decompressed.
fn decoded(file: &File, media_type: &str) -> std::io::Result<Box<dyn std::io::Read>> {
    let reader = std::io::BufReader::new(at_start(file)?);
    use velarx_content::decompress::{Decoder, Kind};
    let kind = if media_type.ends_with("gzip") {
        Kind::Gzip
    } else if media_type.ends_with("zstd") {
        Kind::Zstd
    } else {
        Kind::None
    };
    Ok(Box::new(Decoder::new(kind, reader)?))
}

/// The tar `input` with its sparse entries made regular files, in a file
/// without a name in `dir` whose zeros are holes, and its digest.
fn expand_sparse(
    input: impl std::io::Read,
    dir: &std::path::Path,
    max: u64,
    alg: Algorithm,
) -> std::io::Result<(File, Digest)> {
    let file = velarx_content::pull::unnamed::unnamed_file(dir)?;
    let out = HashedOut {
        out: velarx_storage::SparseWriter::new(&file),
        hasher: DigestWriter::new(alg),
    };
    let out = velarx_wire::sparse::expand(input, out, max)?;
    out.out.finish()?;
    let digest = out.hasher.finalize();
    Ok((file, digest))
}

/// What is written, hashed.
struct HashedOut<W> {
    out: W,
    hasher: DigestWriter,
}

impl<W: std::io::Write> std::io::Write for HashedOut<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.hasher.update(buf);
        self.out.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.out.flush()
    }
}

/// The digest of the tar in `file` once decompressed, at most `max` bytes,
/// and whether it has a sparse entry (seen in the same pass).
fn diff_id(file: &File, media_type: &str, max: u64, alg: Algorithm) -> ImageResult<(Digest, bool)> {
    use std::io::Read;
    /// The bytes read, hashed and counted.
    struct Hashed<R> {
        inner: R,
        hasher: DigestWriter,
        total: u64,
        max: u64,
    }
    impl<R: Read> Read for Hashed<R> {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            if self.total > self.max {
                return Err(std::io::Error::other("too large"));
            }
            let n = self.inner.read(buf)?;
            self.total += n as u64;
            if self.total > self.max {
                return Err(std::io::Error::other("too large"));
            }
            self.hasher.update(&buf[..n]);
            Ok(n)
        }
    }
    let mut hashed = Hashed {
        inner: decoded(file, media_type)?,
        hasher: DigestWriter::new(alg),
        total: 0,
        max,
    };
    // (an archive the tar crate cannot read is the layer's to refuse)
    let sparse = tar::Archive::new(&mut hashed)
        .entries()
        .and_then(velarx_wire::sparse::any_sparse)
        .unwrap_or(false);
    let rest = std::io::copy(&mut hashed, &mut std::io::sink());
    if hashed.total > max {
        return Err(ImageError::Layer(format!(
            "the archive is larger than {max} bytes once uncompressed"
        )));
    }
    rest?;
    Ok((hashed.hasher.finalize(), sparse))
}

/// A name for an imported image: without a registry it is `localhost/`.
pub(super) fn local_reference(name: &str) -> ImageResult<String> {
    let r = ImageReference::parse(name)?;
    if r.digest.is_some() {
        return Err(ImageError::Manifest(format!(
            "cannot import as `{name}`: a digest"
        )));
    }
    let first = name.split('/').next().unwrap_or("");
    let has_registry = name.contains('/') && velarx_base::reference::is_registry_domain(first);
    Ok(if has_registry {
        name.to_string()
    } else {
        format!("localhost/{name}")
    })
}

/// The names to save an image with: the one that was asked for, or all of
/// them if the reference is not one of them (podman and Docker save the
/// requested name only; an id gives an unnamed image).
fn requested_names(reference: &str, ids: &[&str], tags: &[ImageTag]) -> Vec<String> {
    // by an id (velarx's, or the config digest the APIs show): no name
    let hex = velarx_types::digest::without_algorithm(reference);
    if hex.len() >= 3 && ids.iter().any(|id| id.starts_with(hex)) {
        return Vec::new();
    }
    let all: Vec<(String, String)> = tags
        .iter()
        .map(|t| (qualified_name(t), format!("{}:{}", t.repository, t.tag)))
        .collect();
    let wanted = ImageReference::parse(reference)
        .ok()
        .map(|r| format!("{}:{}", r.name(), r.tag.unwrap_or_else(|| "latest".into())));
    let chosen: Vec<String> = all
        .iter()
        .filter(|(_, short)| Some(short) == wanted.as_ref())
        .map(|(q, _)| q.clone())
        .collect();
    if chosen.is_empty() {
        all.into_iter().map(|(q, _)| q).collect()
    } else {
        chosen
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tag(repository: &str, tag: &str) -> ImageTag {
        ImageTag {
            repository: repository.into(),
            tag: tag.into(),
            image_id: "abcdef012345".into(),
        }
    }

    /// The tar of an import with a sparse entry (old GNU format) whose file
    /// has `real` bytes: a few at the start and the end, a hole between.
    fn sparse_tar(real: u64) -> Vec<u8> {
        let octal = |v: u64| {
            let mut b = [0u8; 12];
            b[..11].copy_from_slice(format!("{v:011o}").as_bytes());
            b
        };
        let mut h = tar::Header::new_gnu();
        h.set_path("hole").unwrap();
        h.set_entry_type(tar::EntryType::GNUSparse);
        h.set_size(1024);
        h.set_mode(0o644);
        {
            let g = h.as_gnu_mut().unwrap();
            g.realsize = octal(real);
            for (i, (off, len)) in [(0, 512), (real - 512, 512), (real, 0)].iter().enumerate() {
                g.sparse[i].offset = octal(*off);
                g.sparse[i].numbytes = octal(*len);
            }
        }
        h.set_cksum();
        let mut out = h.as_bytes().to_vec();
        out.extend([b'h'; 512]);
        out.extend([b't'; 512]);
        out.extend([0u8; 1024]);
        out
    }

    /// The tar of an import with a hole of 256 MiB takes the blocks of its
    /// data, not of its zeros, and its digest is that of the tar with the
    /// zeros.
    #[test]
    fn the_tar_of_an_import_keeps_the_holes_of_a_sparse_entry() {
        use std::os::unix::fs::{FileExt, MetadataExt};
        let real = 256 << 20;
        let dir = tempfile::tempdir().unwrap();
        let tar = sparse_tar(real);
        assert!(tar.len() < 4096);
        let (file, digest) =
            expand_sparse(&tar[..], dir.path(), real * 2, Algorithm::Sha256).unwrap();
        let size = file.metadata().unwrap().len();
        assert!(size > real);
        // (a file system that has no holes is not tested)
        let probe = tempfile::tempfile_in(dir.path()).unwrap();
        probe.set_len(1 << 20).unwrap();
        if probe.metadata().unwrap().blocks() == 0 {
            let blocks = file.metadata().unwrap().blocks();
            assert!(blocks * 512 < 1 << 20, "{blocks} blocks of 512 bytes");
        }
        // the content is that of a regular file
        let mut head = [0u8; 4];
        file.read_exact_at(&mut head, 512).unwrap();
        assert_eq!(&head, b"hhhh");
        let mut tail = [0u8; 4];
        file.read_exact_at(&mut tail, 512 + real - 4).unwrap();
        assert_eq!(&tail, b"tttt");
        let mut middle = [1u8; 4];
        file.read_exact_at(&mut middle, 512 + real / 2).unwrap();
        assert_eq!(middle, [0; 4]);
        // (the digest of what a reader gives)
        let mut hasher = DigestWriter::new(Algorithm::Sha256);
        let mut at = 0;
        let mut buf = vec![0u8; 1 << 20];
        while at < size {
            let n = file.read_at(&mut buf, at).unwrap();
            hasher.update(&buf[..n]);
            at += n as u64;
        }
        assert_eq!(digest, hasher.finalize());
    }

    #[test]
    fn test_requested_names() {
        let tags = [tag("library/alpine", "3"), tag("localhost:5000/a/b", "x")];
        assert_eq!(
            requested_names("alpine:3", &["abcdef012345"], &tags),
            ["docker.io/library/alpine:3"]
        );
        assert_eq!(
            requested_names("localhost:5000/a/b:x", &["abcdef012345"], &tags),
            ["localhost:5000/a/b:x"]
        );
        assert!(requested_names("abcdef", &["abcdef012345"], &tags).is_empty());
        assert!(requested_names("sha256:abcdef012345", &["abcdef012345"], &tags).is_empty());
        // Not one of the names: all of them.
        assert_eq!(requested_names("other", &["abcdef012345"], &tags).len(), 2);
        // the config digest's id names no image either
        assert!(requested_names("9876fe", &["abcdef012345", "9876fedcba"], &tags).is_empty());
    }

    #[test]
    fn a_name_of_an_archive_without_a_registry_is_local() {
        assert_eq!(archive_name("v1"), "localhost/v1");
        assert_eq!(archive_name("a/b:2"), "localhost/a/b:2");
        assert_eq!(
            archive_name("docker.io/library/v1:latest"),
            "docker.io/library/v1:latest"
        );
        assert_eq!(archive_name("localhost/a:v1"), "localhost/a:v1");
        assert_eq!(archive_name("reg:5000/a:v1"), "reg:5000/a:v1");
    }

    #[test]
    fn test_archive_names() {
        let (full, t) = archive_tag("localhost/a:v1", "id").unwrap();
        assert_eq!(
            (full.as_str(), t.repository.as_str()),
            ("localhost/a:v1", "localhost/a")
        );
        assert_eq!(
            archive_tag("alpine", "id").unwrap().1.repository,
            "library/alpine"
        );
        assert!(archive_tag("Bad Name", "id").is_none());
        assert!(archive_tag("a@sha256:00", "id").is_none());
    }

    #[test]
    fn test_local_reference() {
        assert_eq!(local_reference("img").unwrap(), "localhost/img");
        assert_eq!(local_reference("me/img:2").unwrap(), "localhost/me/img:2");
        assert_eq!(local_reference("reg.io/me/img").unwrap(), "reg.io/me/img");
        assert!(local_reference("img@sha256:00").is_err());
    }
}
