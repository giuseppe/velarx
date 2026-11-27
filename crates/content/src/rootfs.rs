// SPDX-License-Identifier: Apache-2.0
//! `rootfs:PATH`: a root file system as the image of one layer.  A
//! directory is walked in the order of a canonical tar (what the layer of a
//! commit is made of), the tar is the layer and the diff id, and the
//! configuration has nothing that changes from one run to the other: the
//! same directory is the same image.  A file is the tar of the layer (what
//! `import` takes): an empty file is an empty tar, a gzip or zstd tar is the
//! blob as it is with the diff id of what it inflates to, and a tar with a
//! sparse entry is written again with the entry whole.

use crate::archive::{
    sniff_layer_media_type, Archive, ArchiveImage, LAYER, OCI_CONFIG, OCI_MANIFEST,
};
use crate::layer::dirtar;
use crate::layer::holes::SparseFile;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::os::fd::AsFd;
use std::os::unix::fs::FileExt;
use velarx_tarsplit::decompress::{Decoder, Kind};
use velarx_types::digest::{Algorithm, Digest, DigestWriter};

/// A layer: the file that holds it, its media type, the digest of its blob
/// and its diff id.
struct Layer {
    file: File,
    media_type: &'static str,
    blob: Digest,
    diff_id: Digest,
}

/// The image of `target` (open, a directory or a tar): the layer of a
/// directory is written in a file without a name in `staging`, and so is
/// whatever of a file has to be made again.  `inflate` is the most a layer of
/// the given size may inflate to, and `max` the most a layer may be once its
/// sparse files are written whole.
pub fn image(
    target: &File,
    staging: &File,
    alg: Algorithm,
    inflate: impl Fn(u64) -> u64,
    max: u64,
) -> io::Result<(Archive, ArchiveImage)> {
    let layer = if target.metadata()?.is_dir() {
        directory(target, staging, alg)?
    } else {
        tarball(target, staging, alg, inflate, max)?
    };
    let size = layer.file.metadata()?.len();
    let config = serde_json::to_vec(&serde_json::json!({
        "architecture": velarx_registry::target::host_arch(),
        "os": "linux",
        "config": {},
        "rootfs": {"type": "layers", "diff_ids": [layer.diff_id]},
    }))
    .map_err(io::Error::other)?;
    let config_digest = Digest::of(alg, &config);
    let manifest = serde_json::to_vec(&serde_json::json!({
        "schemaVersion": 2,
        "mediaType": OCI_MANIFEST,
        "config": {
            "mediaType": OCI_CONFIG,
            "digest": config_digest,
            "size": config.len(),
        },
        "layers": [{"mediaType": layer.media_type, "digest": layer.blob, "size": size}],
    }))
    .map_err(io::Error::other)?;
    let image = ArchiveImage {
        digest: Digest::of(alg, &manifest),
        media_type: OCI_MANIFEST.to_string(),
        manifest,
        names: Vec::new(),
        aliases: Vec::new(),
    };
    let config_file = File::from(velarx_base::sealed::sealed_memory(&config)?);
    let archive = Archive::blobs(&[
        (&layer.file, layer.blob, 0, size),
        (&config_file, config_digest, 0, config.len() as u64),
    ])?;
    Ok((archive, image))
}

/// The layer of the directory `dir`.
fn directory(dir: &File, staging: &File, alg: Algorithm) -> io::Result<Layer> {
    let mut tar = SparseFile::new(crate::pull::unnamed::unnamed_file_at(staging)?);
    let opts = dirtar::Options {
        root: dirtar::Root::Always,
        ..Default::default()
    };
    dirtar::write(dir.as_fd(), &opts, &mut tar)?;
    let file = tar.finish()?;
    let size = file.metadata()?.len();
    let (digest, _) = Digest::of_file_at(alg, &file, size)?;
    Ok(Layer {
        file,
        media_type: LAYER,
        blob: digest,
        diff_id: digest,
    })
}

/// The layer of the tar `input`, as a layer of its own blob: nothing is an
/// empty file system, as for Docker (the end of a tar alone), and a layer
/// has no sparse file, as podman's import makes it (the sparse files are
/// written whole, the zeros of the holes holes of the file that holds the
/// tar).
fn tarball(
    input: &File,
    staging: &File,
    alg: Algorithm,
    inflate: impl Fn(u64) -> u64,
    max: u64,
) -> io::Result<Layer> {
    let mut input = input.try_clone()?;
    let mut size = input.metadata()?.len();
    if size == 0 {
        input = crate::pull::unnamed::unnamed_file_at(staging)?;
        input.write_all_at(&[0u8; 1024], 0)?;
        size = 1024;
    }
    let mut head = [0u8; 4];
    let n = input.read_at(&mut head, 0)?;
    let mut media_type = sniff_layer_media_type(&head[..n]);
    let limit = inflate(size);
    let mut blob = Digest::of_file_at(alg, &input, size)?.0;
    // (a tar is its own diff id)
    let (mut diff_id, sparse) = if media_type == LAYER && size <= limit {
        let mut ar = tar::Archive::new(io::BufReader::new(at_start(&input)?));
        // (an archive the tar crate cannot read is the layer's to refuse)
        let sparse = ar
            .entries_with_seek()
            .and_then(velarx_wire::sparse::any_sparse)
            .unwrap_or(false);
        (blob, sparse)
    } else {
        diff_id(&input, media_type, limit, alg)?
    };
    if sparse {
        let (expanded, digest) = expand_sparse(decoded(&input, media_type)?, staging, max, alg)?;
        input = expanded;
        media_type = LAYER;
        blob = digest;
        diff_id = digest;
    }
    Ok(Layer {
        file: input,
        media_type,
        blob,
        diff_id,
    })
}

/// `file` from its start.
fn at_start(file: &File) -> io::Result<File> {
    let mut input = file.try_clone()?;
    input.seek(SeekFrom::Start(0))?;
    Ok(input)
}

/// The tar in `file`, decompressed.
fn decoded(file: &File, media_type: &str) -> io::Result<Box<dyn Read>> {
    let reader = io::BufReader::new(at_start(file)?);
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
    input: impl Read,
    dir: &File,
    max: u64,
    alg: Algorithm,
) -> io::Result<(File, Digest)> {
    let file = crate::pull::unnamed::unnamed_file_at(dir)?;
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

impl<W: io::Write> io::Write for HashedOut<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.hasher.update(buf);
        self.out.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.out.flush()
    }
}

/// The digest of the tar in `file` once decompressed, at most `max` bytes,
/// and whether it has a sparse entry (seen in the same pass).
fn diff_id(file: &File, media_type: &str, max: u64, alg: Algorithm) -> io::Result<(Digest, bool)> {
    /// The bytes read, hashed and counted.
    struct Hashed<R> {
        inner: R,
        hasher: DigestWriter,
        total: u64,
        max: u64,
    }
    impl<R: Read> Read for Hashed<R> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if self.total > self.max {
                return Err(io::Error::other("too large"));
            }
            let n = self.inner.read(buf)?;
            self.total += n as u64;
            if self.total > self.max {
                return Err(io::Error::other("too large"));
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
    let rest = io::copy(&mut hashed, &mut io::sink());
    if hashed.total > max {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("the archive is larger than {max} bytes once uncompressed"),
        ));
    }
    rest?;
    Ok((hashed.hasher.finalize(), sparse))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::os::unix::fs::MetadataExt;

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

    /// A tar of one regular file.
    fn plain_tar() -> Vec<u8> {
        let mut b = tar::Builder::new(Vec::new());
        let mut h = tar::Header::new_gnu();
        h.set_size(3);
        h.set_mode(0o644);
        h.set_cksum();
        b.append_data(&mut h, "f", &b"abc"[..]).unwrap();
        b.into_inner().unwrap()
    }

    fn gzip(data: &[u8]) -> Vec<u8> {
        let mut z = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        z.write_all(data).unwrap();
        z.finish().unwrap()
    }

    fn file_with(dir: &tempfile::TempDir, bytes: &[u8]) -> File {
        let mut file = tempfile::tempfile_in(dir.path()).unwrap();
        file.write_all(bytes).unwrap();
        file
    }

    /// The layer of the one image `image` makes of `bytes`: its descriptor
    /// and the diff id of its configuration.
    fn layer_of(
        bytes: &[u8],
        alg: Algorithm,
        limit: u64,
    ) -> io::Result<(Archive, serde_json::Value, String)> {
        let dir = tempfile::tempdir().unwrap();
        let (archive, image) = image(
            &file_with(&dir, bytes),
            &File::open(dir.path()).unwrap(),
            alg,
            |_| limit,
            1 << 30,
        )?;
        let manifest: serde_json::Value = serde_json::from_slice(&image.manifest).unwrap();
        let config: Digest = manifest["config"]["digest"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap();
        let config: serde_json::Value =
            serde_json::from_slice(&archive.blob(&config, 1 << 20).unwrap()).unwrap();
        let diff = config["rootfs"]["diff_ids"][0]
            .as_str()
            .unwrap()
            .to_string();
        Ok((archive, manifest["layers"][0].clone(), diff))
    }

    /// An empty file is the end of a tar alone, as an empty file system.
    #[test]
    fn an_empty_file_is_an_empty_tar() {
        let (_, layer, diff) = layer_of(b"", Algorithm::Sha256, 1 << 30).unwrap();
        let empty = Digest::of(Algorithm::Sha256, &[0u8; 1024]);
        assert_eq!(layer["size"], 1024);
        assert_eq!(layer["mediaType"], LAYER);
        assert_eq!(layer["digest"], empty.to_string());
        assert_eq!(diff, empty.to_string());
    }

    /// A compressed tar is the blob as given, and its diff id is the digest
    /// of what it inflates to.
    #[test]
    fn a_compressed_tar_is_the_blob_and_its_diff_id_is_the_tar() {
        let tar = plain_tar();
        let gz = gzip(&tar);
        for alg in [Algorithm::Sha256, Algorithm::Sha512] {
            let (archive, layer, diff) = layer_of(&gz, alg, 1 << 30).unwrap();
            assert_eq!(
                layer["mediaType"],
                "application/vnd.oci.image.layer.v1.tar+gzip"
            );
            assert_eq!(layer["digest"], Digest::of(alg, &gz).to_string());
            assert_eq!(layer["size"], gz.len());
            assert_eq!(diff, Digest::of(alg, &tar).to_string());
            let blob = Digest::of(alg, &gz);
            assert_eq!(archive.blob(&blob, 1 << 20).unwrap(), gz);
        }
        // a tar is its own diff id
        let (_, layer, diff) = layer_of(&tar, Algorithm::Sha256, 1 << 30).unwrap();
        assert_eq!(layer["mediaType"], LAYER);
        assert_eq!(layer["digest"], diff);
    }

    /// What inflates past the limit is refused.
    #[test]
    fn a_tar_that_inflates_past_the_limit_is_refused() {
        let gz = gzip(&vec![0u8; 1 << 20]);
        let e = layer_of(&gz, Algorithm::Sha256, 1 << 16).err().unwrap();
        assert_eq!(e.kind(), io::ErrorKind::InvalidData, "{e}");
    }

    /// A tar with a sparse entry is written again with the entry whole,
    /// whatever its compression, and is the layer (uncompressed) with the
    /// digest of what was written; a hole is no bytes of the tar, so the
    /// inflate limit of the tar is not the limit of the file.
    #[test]
    fn a_tar_with_a_sparse_entry_is_written_again_whole() {
        let tar = sparse_tar(1 << 20);
        for bytes in [tar.clone(), gzip(&tar)] {
            let (archive, layer, diff) = layer_of(&bytes, Algorithm::Sha256, 1 << 16).unwrap();
            assert_eq!(layer["mediaType"], LAYER);
            assert_eq!(layer["digest"], diff);
            assert!(layer["size"].as_u64().unwrap() > 1 << 20);
            let blob: Digest = diff.parse().unwrap();
            assert_eq!(archive.blob_reader(&blob).unwrap().size(), layer["size"]);
        }
    }

    /// A sparse entry is written whole within the most a layer may be: one
    /// that would be larger is refused, however small its tar.
    #[test]
    fn a_sparse_entry_larger_than_a_layer_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let tar = sparse_tar(1 << 20);
        let e = image(
            &file_with(&dir, &tar),
            &File::open(dir.path()).unwrap(),
            Algorithm::Sha256,
            |_| 1 << 30,
            1 << 19,
        )
        .err()
        .unwrap();
        assert_eq!(e.kind(), io::ErrorKind::InvalidData, "{e}");
    }

    /// The tar of an import with a hole of 256 MiB takes the blocks of its
    /// data, not of its zeros, and its digest is that of the tar with the
    /// zeros.
    #[test]
    fn the_tar_of_an_import_keeps_the_holes_of_a_sparse_entry() {
        let real = 256 << 20;
        let dir = tempfile::tempdir().unwrap();
        let tar = sparse_tar(real);
        assert!(tar.len() < 4096);
        let (file, digest) = expand_sparse(
            &tar[..],
            &File::open(dir.path()).unwrap(),
            real * 2,
            Algorithm::Sha256,
        )
        .unwrap();
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
}
