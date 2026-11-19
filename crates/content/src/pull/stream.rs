// SPDX-License-Identifier: Apache-2.0
//! Layers that are fetched whole: gzip, zstd or uncompressed tarballs, and
//! zstd:chunked layers that cannot be pulled by ranges.
//!
//! The blob is streamed through three stages that run at the same time:
//!
//! 1. the network task hashes the compressed bytes (the digest of the blob),
//! 2. a thread inflates them and hashes the tar stream (the diff id),
//! 3. a thread parses the tar headers and writes the files to the staging
//!    session, hashing each one.
//!
//! Every digest is computed once, as the bytes go by.  Nothing is recorded
//! unless the digest of the blob and the diff id match, and the table of
//! contents comes from the verified tar headers.

use super::entry::{self, MAX_ENTRIES};
use super::net::Net;
use super::sink::Sink;
use super::tar::{Kind, TarReader};
use super::tarsplit::Recorder;
use super::{LayerReport, PullCtx, Source};
use bytes::Bytes;
use futures::StreamExt;
use std::io::{self, Read};
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::debug;
use velarx_proto::transfer::FailureClass;
use velarx_storage::{Toc, TocEntry, TOC_VERSION};
use velarx_types::digest::{Algorithm, Digest, DigestWriter};
use velarx_types::{ImageError, ImageResult, OciDescriptor};

/// Size of the frames of the uncompressed stream.
pub const FRAME_SIZE: usize = 1024 * 1024;

/// Files up to this size are kept in memory, hashed and written under their
/// final name: no temporary file, no rename.
const SMALL_FILE: u64 = 256 * 1024;

/// Frames in flight between two stages.
pub const CHANNEL_DEPTH: usize = 4;

pub type Frame = io::Result<Bytes>;

/// A `Read` over a channel of frames.
pub struct ChannelReader {
    rx: mpsc::Receiver<Frame>,
    current: Bytes,
}

impl ChannelReader {
    pub fn new(rx: mpsc::Receiver<Frame>) -> Self {
        Self {
            rx,
            current: Bytes::new(),
        }
    }
}

impl Read for ChannelReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        while self.current.is_empty() {
            match self.rx.blocking_recv() {
                Some(Ok(b)) => self.current = b,
                Some(Err(e)) => return Err(e),
                None => return Ok(0),
            }
        }
        let n = buf.len().min(self.current.len());
        buf[..n].copy_from_slice(&self.current[..n]);
        bytes::Buf::advance(&mut self.current, n);
        Ok(n)
    }
}

/// What the decompression stage found.
pub struct Stream {
    /// None if the stream was not hashed.
    pub diff_id: Option<Digest>,
    pub size: u64,
    /// The stream is the bytes of the blob (it is not compressed): the
    /// digest of the blob is the one of the stream, hashed once.
    pub plain: bool,
}

fn read_frame<R: Read>(r: &mut R, buf: &mut Vec<u8>) -> io::Result<()> {
    buf.clear();
    buf.resize(FRAME_SIZE, 0);
    let mut filled = 0;
    while filled < FRAME_SIZE {
        let n = r.read(&mut buf[filled..])?;
        if n == 0 {
            break;
        }
        filled += n;
    }
    buf.truncate(filled);
    Ok(())
}

/// Stage 2: decompress, hash the tar stream with `diff_alg` if there is one,
/// hand out the frames.  A stream that is not compressed is not hashed when
/// `blob_alg` (the algorithm the network stage hashes the blob with) is
/// `diff_alg`: they are the same bytes, and the one hash is both digests.
pub fn decompress(
    compressed: mpsc::Receiver<Frame>,
    frames: mpsc::Sender<Frame>,
    max_size: u64,
    diff_alg: Option<Algorithm>,
    blob_alg: Option<Algorithm>,
) -> io::Result<Stream> {
    let mut input = ChannelReader::new(compressed);
    let mut head = [0u8; 4];
    let mut got = 0;
    while got < head.len() {
        let n = input.read(&mut head[got..])?;
        if n == 0 {
            break;
        }
        got += n;
    }
    let input = io::Cursor::new(head[..got].to_vec()).chain(input);
    let kind = velarx_tarsplit::decompress::sniff(&head[..got]);
    let plain = matches!(kind, velarx_tarsplit::decompress::Kind::None)
        && diff_alg.is_some()
        && diff_alg == blob_alg;
    let mut reader = velarx_tarsplit::decompress::Decoder::new(kind, io::BufReader::new(input))?;

    let mut stream = frames_of(&mut reader, &frames, max_size, diff_alg.filter(|_| !plain))?;
    stream.plain = plain;
    Ok(stream)
}

/// The frames of the tar stream `reader`, hashed with `diff_alg` if there
/// is one, handed out (the decompression and a made layer end here).
fn frames_of<R: Read>(
    reader: &mut R,
    frames: &mpsc::Sender<Frame>,
    max_size: u64,
    diff_alg: Option<Algorithm>,
) -> io::Result<Stream> {
    let mut hasher = diff_alg.map(DigestWriter::new);
    let mut size = 0u64;
    let mut buf = Vec::new();
    loop {
        read_frame(reader, &mut buf)?;
        if buf.is_empty() {
            break;
        }
        size += buf.len() as u64;
        if size > max_size {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("the layer is larger than {max_size} bytes once uncompressed ([pull] max_inflate_ratio, inflate_floor_mib, max_layer_gib)"),
            ));
        }
        if let Some(h) = &mut hasher {
            h.update(&buf);
        }
        if frames
            .blocking_send(Ok(Bytes::copy_from_slice(&buf)))
            .is_err()
        {
            // The parser stopped; its error is the one to report.
            break;
        }
    }
    Ok(Stream {
        diff_id: hasher.map(DigestWriter::finalize),
        size,
        plain: false,
    })
}

pub use crate::pull::entry::FileUse;

#[derive(Clone)]
pub struct Ingested {
    pub toc: Arc<Toc>,
    pub files: Vec<FileUse>,
    pub report: LayerReport,
    pub diff_id: Digest,
    /// The zstd compressed tar-split of the layer.
    pub tarsplit: bytes::Bytes,
    /// The blob came from a local source: its files are the user's, not
    /// proven public by the pull
    pub from_local_source: bool,
}

/// A regular file written to the session.
pub(super) struct StagedFile {
    /// What the file is known by from now on: the hash of its content in
    /// the algorithm of its layer, or its fs-verity digest when the store (or
    /// the session) has the file already
    pub(super) key: String,
    /// The hash of its content, in the algorithm of its layer
    pub(super) content: String,
    /// Whether the file was written: it was not if the store has it
    pub(super) added: bool,
}

/// Write the content of a regular file to the session.  Both digests of the
/// content are made in the one pass over its bytes: its hash in `alg` (the
/// algorithm of the digests of its layer), which the layer knows it by, and
/// its fs-verity digest, which the store names it by; a file the store has is
/// not kept, and is known by the digest the store has it by.  A `copy` is
/// staged as what the store had: not told nor given.
pub(super) fn stage_file<R: Read>(
    session: &dyn Sink,
    alg: Algorithm,
    entry: &mut R,
    size: u64,
    copy: bool,
) -> io::Result<StagedFile> {
    if let Some((key, added)) = session.put_reader(alg, entry, size, copy)? {
        return Ok(StagedFile {
            content: key.clone(),
            key,
            added,
        });
    }
    if size <= SMALL_FILE {
        let mut data = vec![0u8; size as usize];
        entry.read_exact(&mut data)?;
        let content = Digest::of(alg, &data).to_string();
        let verity = velarx_storage::fsverity_digest_of(alg, &data);
        let (key, added) = session.put_measured(&content, &verity, &data, copy)?;
        return Ok(StagedFile {
            key,
            content,
            added,
        });
    }
    let (file, path) = session.create_temp()?;
    let path = path.ok_or_else(|| {
        io::Error::other(
            "a layer fetched whole is written to files that have a name: the sink has none",
        )
    })?;
    let mut hasher = DigestWriter::new(alg);
    let mut verity = velarx_storage::VerityHasher::new(alg);
    let mut buf = vec![0u8; 256 * 1024];
    let mut left = size;
    let result = (|| -> io::Result<()> {
        // a sparse file keeps its holes, which cost no disk
        let mut out = velarx_storage::SparseWriter::new(&file);
        while left > 0 {
            let want = buf.len().min(left as usize);
            let n = entry.read(&mut buf[..want])?;
            if n == 0 {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
            hasher.update(&buf[..n]);
            verity.update(&buf[..n]);
            out.write(&buf[..n])?;
            left -= n as u64;
        }
        out.finish().map(|_| ())
    })();
    drop(file);
    if let Err(e) = result {
        let _ = std::fs::remove_file(&path);
        return Err(e);
    }
    let content = hasher.finalize().to_string();
    let (key, added) = session.adopt_measured(&path, &content, &verity.finish(), size, copy)?;
    Ok(StagedFile {
        key,
        content,
        added,
    })
}

/// Stage 3: parse the tar stream, stage the files, build the entries.
pub(super) fn parse(
    frames: mpsc::Receiver<Frame>,
    alg: Algorithm,
    session: &dyn Sink,
    report: &mut LayerReport,
    copy: bool,
) -> io::Result<(Vec<TocEntry>, Vec<FileUse>, Vec<u8>)> {
    let mut tar = TarReader::with_sink(ChannelReader::new(frames), Recorder::new()?);
    let mut entries: Vec<TocEntry> = Vec::new();
    let mut files: Vec<FileUse> = Vec::new();
    while let Some(h) = tar.next_entry()? {
        if entries.len() >= MAX_ENTRIES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("the layer has too many entries (more than {MAX_ENTRIES})"),
            ));
        }
        // (an empty file is no file of the store)
        let mut verity = None;
        let file_digest = if h.kind == Kind::Regular && h.size == 0 {
            Some(Digest::empty(alg).to_string())
        } else if h.kind == Kind::Regular {
            let staged = stage_file(session, alg, &mut tar, h.size, copy)?;
            if staged.added {
                report.fetched_files += 1;
            } else {
                report.reused_files += 1;
            }
            files.push(FileUse {
                digest: staged.key.clone(),
                size: h.size,
            });
            verity = velarx_storage::to_toc(&staged.key);
            Some(staged.content)
        } else {
            None
        };
        let mut e = entry::from_header(&h, file_digest.as_deref())?;
        // (a file the store has is named by its object)
        e.fsverity = verity;
        entries.push(e);
    }
    // The rest of the stream (the zero blocks) is part of the tar-split.
    let (_, recorder) = tar.finish()?;
    Ok((entries, files, recorder.finish()?.compressed))
}

/// Download a layer, stage its files and build its table of contents.
pub async fn ingest(
    ctx: &PullCtx,
    source: Option<&Source>,
    layer: &OciDescriptor,
    expected_diff_id: &Digest,
    progress: impl Fn(u64),
) -> ImageResult<Ingested> {
    match source {
        // (a layer a build made was read once, as it was made:
        // `made::from_walk`)
        None => Err(ImageError::Layer(format!(
            "the layer {} was made here: it is not read again",
            layer.digest
        ))),
        Some(Source::Registry(_)) => {
            match &ctx.net {
                Net::Offline => Err(ImageError::transfer_of(
                    "registry",
                    layer.digest.to_string(),
                    FailureClass::Failed,
                    "the layer is not in the image's source, and no registry is reachable",
                )),
                // (a pull through the fetchers unpacks its layers there:
                // `chunked::pull_whole`)
                Net::Origin(_) => Err(ImageError::transfer_of(
                    "registry",
                    layer.digest.to_string(),
                    FailureClass::Failed,
                    "the layer is pulled through the fetchers",
                )),
            }
        }
        Some(Source::Path) => Err(ImageError::transfer_of(
            "dir",
            layer.digest.to_string(),
            FailureClass::Failed,
            "the layer is pulled through the fetchers",
        )),
        Some(Source::Archive(archive)) => {
            let body = archive
                .blob_stream(&layer.digest)
                .map_err(|e| ImageError::Layer(e.to_string()))?;
            ingest_stream(ctx, body, layer, expected_diff_id, progress, false).await
        }
    }
}

/// Stage the files of a layer, and build its table of contents, from the
/// pieces of the blob.
async fn ingest_stream<S>(
    ctx: &PullCtx,
    body: S,
    layer: &OciDescriptor,
    expected_diff_id: &Digest,
    progress: impl Fn(u64),
    copy: bool,
) -> ImageResult<Ingested>
where
    S: futures::Stream<Item = ImageResult<Bytes>> + Unpin,
{
    ingest_feed(ctx, body, layer, expected_diff_id, progress, copy).await
}

async fn ingest_feed<S>(
    ctx: &PullCtx,
    mut body: S,
    layer: &OciDescriptor,
    expected_diff_id: &Digest,
    progress: impl Fn(u64),
    copy: bool,
) -> ImageResult<Ingested>
where
    S: futures::Stream<Item = ImageResult<Bytes>> + Unpin,
{
    let (ctx_tx, ctx_rx) = mpsc::channel::<Frame>(CHANNEL_DEPTH * 2);
    let (frames_tx, frames_rx) = mpsc::channel::<Frame>(CHANNEL_DEPTH);
    let max_size = ctx.limits.inflate_cap(layer.size);
    let diff_alg = expected_diff_id.alg();
    let blob_alg = layer.digest.alg();
    let inflate = tokio::task::spawn_blocking(move || {
        decompress(ctx_rx, frames_tx, max_size, Some(diff_alg), Some(blob_alg))
    });
    let session = ctx.sink.clone();
    // (the files of a layer pulled whole are known by the hash of their
    // content in the algorithm of its blob, the digest that names the layer)
    let layer_alg = layer.digest.alg();
    let parser = tokio::task::spawn_blocking(move || {
        let mut report = LayerReport::default();
        parse(frames_rx, layer_alg, &*session, &mut report, copy).map(|(e, f, t)| (e, f, t, report))
    });

    // Stage 1: the network.
    let mut blob_hasher = DigestWriter::for_digest(&layer.digest);
    let mut compressed = 0u64;
    let mut network_error = None;
    while let Some(chunk) = body.next().await {
        match chunk {
            Ok(chunk) => {
                compressed += chunk.len() as u64;
                if layer.size >= 0 && compressed > layer.size as u64 {
                    network_error = Some(ImageError::transfer_of(
                        "registry",
                        layer.digest.to_string(),
                        FailureClass::Invalid,
                        format!("larger than the {} bytes of its descriptor", layer.size),
                    ));
                    break;
                }
                blob_hasher.update(&chunk);
                progress(compressed);
                if ctx_tx.send(Ok(chunk)).await.is_err() {
                    break;
                }
            }
            Err(e) => {
                let _ = ctx_tx
                    .send(Err(io::Error::new(
                        io::ErrorKind::ConnectionAborted,
                        e.to_string(),
                    )))
                    .await;
                network_error = Some(e);
                break;
            }
        }
    }
    drop(ctx_tx);

    let stream = inflate
        .await
        .map_err(|e| ImageError::Layer(format!("decompression task: {e}")))?;
    let parsed = parser
        .await
        .map_err(|e| ImageError::Layer(format!("tar task: {e}")))?;
    if let Some(e) = network_error {
        return Err(e);
    }
    // The first stage's error is the cause of the second one's.
    // (the system failing, a full disk, is this machine's; the rest the
    // layer's)
    let stream = stream.map_err(super::chunked::io_fail)?;
    let (entries, files, tarsplit, mut report) = parsed.map_err(super::chunked::io_fail)?;

    // The digest of the blob: computed here, or reported by the worker that
    // downloaded it.  The tar stream is hashed here either way, and it is
    // that digest that binds the layer to the configuration.
    let actual = blob_hasher.finalize();
    if actual == layer.digest && layer.size >= 0 && compressed != layer.size as u64 {
        return Err(ImageError::Layer(format!(
            "layer {} has {compressed} bytes, its descriptor says {}",
            layer.digest, layer.size
        )));
    }
    if actual != layer.digest || (layer.size >= 0 && compressed != layer.size as u64) {
        return Err(ImageError::DigestMismatch {
            expected: layer.digest.to_string(),
            actual: actual.to_string(),
        });
    }
    // (a layer that is not compressed: the blob's digest, checked above, is
    // the stream's)
    let diff_id = stream
        .diff_id
        .or_else(|| stream.plain.then_some(actual))
        .ok_or_else(|| ImageError::Layer("the layer was not hashed".into()))?;
    if diff_id != *expected_diff_id {
        return Err(ImageError::DigestMismatch {
            expected: expected_diff_id.to_string(),
            actual: diff_id.to_string(),
        });
    }
    debug!(
        "Layer {}: {} entries, {} bytes inflated from {}",
        layer.digest,
        entries.len(),
        stream.size,
        compressed
    );
    report.fetched_bytes = compressed;
    Ok(Ingested {
        toc: Arc::new(Toc {
            version: TOC_VERSION,
            entries,
            tar_split_digest: Some(Digest::of(layer.digest.alg(), &tarsplit).to_string()),
        }),
        files,
        report,
        diff_id,
        tarsplit: tarsplit.into(),
        from_local_source: copy,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pull::testnames::{digest_names, is_digest_name, Names};
    use crate::pull::{Limits, PullCtx};
    use std::collections::HashMap;
    use std::sync::Arc;

    async fn ctx(dir: &std::path::Path) -> PullCtx {
        let store = Arc::new(velarx_storage::FileStore::new(dir.join("objects")).unwrap());
        let session = super::super::session::Session::create(&dir.join("staging"), store).unwrap();
        let db = velarx_db::Database::open_in_memory().await.unwrap();
        let limits = Limits::from_config(&velarx_config::PullConfig::default());
        PullCtx::new(super::super::net::Net::offline(), session, db, limits)
    }

    /// A layer: a tar of one file, gzipped; its blob and its diff id in `blob`
    /// and `diff` (their algorithms are the descriptor's and the
    /// configuration's).
    fn layer_of(blob: Algorithm, diff: Algorithm) -> (Vec<u8>, OciDescriptor, Digest) {
        use std::io::Write;
        let mut tar = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.set_size(5);
        header.set_mode(0o644);
        header.set_entry_type(tar::EntryType::Regular);
        tar.append_data(&mut header, "f", &b"hello"[..]).unwrap();
        let tar = tar.into_inner().unwrap();
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gz.write_all(&tar).unwrap();
        let gz = gz.finish().unwrap();
        let layer = OciDescriptor {
            media_type: "application/vnd.oci.image.layer.v1.tar+gzip".into(),
            digest: Digest::of(blob, &gz),
            size: gz.len() as i64,
            annotations: Default::default(),
        };
        (gz, layer, Digest::of(diff, &tar))
    }

    async fn ingest_bytes(
        ctx: &PullCtx,
        gz: Vec<u8>,
        layer: &OciDescriptor,
        diff: &Digest,
    ) -> ImageResult<Ingested> {
        let body = futures::stream::iter(vec![Ok::<_, ImageError>(Bytes::from(gz))]);
        ingest_stream(ctx, body, layer, diff, |_| {}, false).await
    }

    /// A layer that is not compressed is its own stream: one hash is the
    /// digest of the blob and the diff id, and a layer whose bytes are not
    /// its diff id is refused all the same.
    #[tokio::test]
    async fn test_an_uncompressed_layer_has_one_digest_for_blob_and_stream() {
        for alg in [Algorithm::Sha256, Algorithm::Sha512] {
            let dir = tempfile::tempdir().unwrap();
            let ctx = ctx(dir.path()).await;
            let (gz, _, _) = layer_of(alg, alg);
            let mut tar = Vec::new();
            std::io::Read::read_to_end(&mut flate2::read::GzDecoder::new(&gz[..]), &mut tar)
                .unwrap();
            let layer = OciDescriptor {
                media_type: "application/vnd.oci.image.layer.v1.tar".into(),
                digest: Digest::of(alg, &tar),
                size: tar.len() as i64,
                annotations: Default::default(),
            };
            let diff = layer.digest;
            let done = ingest_bytes(&ctx, tar.clone(), &layer, &diff)
                .await
                .unwrap();
            assert_eq!(done.diff_id, diff);
            let other = Digest::of(alg, b"another stream");
            assert!(matches!(
                ingest_bytes(&ctx, tar, &layer, &other).await,
                Err(ImageError::DigestMismatch { .. })
            ));
        }
    }

    /// The blob and the diff id are checked with the algorithm of their own
    /// digests, whichever, and a wrong one is refused with the algorithm it
    /// was asked in.
    #[tokio::test]
    async fn test_a_layer_is_verified_with_the_algorithms_of_its_digests() {
        for (blob, diff) in [
            (Algorithm::Sha256, Algorithm::Sha256),
            (Algorithm::Sha512, Algorithm::Sha512),
            (Algorithm::Sha256, Algorithm::Sha512),
            (Algorithm::Sha512, Algorithm::Sha256),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let ctx = ctx(dir.path()).await;
            let (gz, layer, diff_id) = layer_of(blob, diff);
            let done = ingest_bytes(&ctx, gz.clone(), &layer, &diff_id)
                .await
                .unwrap();
            assert_eq!(done.diff_id, diff_id, "{blob} {diff}");
            // the blob is not the digest it is named by
            let mut other = layer.clone();
            other.digest = Digest::of(blob, b"other");
            let e = ingest_bytes(&ctx, gz.clone(), &other, &diff_id)
                .await
                .err()
                .unwrap();
            assert!(
                matches!(&e, ImageError::DigestMismatch { expected, .. } if *expected == other.digest.to_string()),
                "{blob} {diff}: {e}"
            );
            // the tar is not the diff id
            let wrong = Digest::of(diff, b"other");
            let e = ingest_bytes(&ctx, gz.clone(), &layer, &wrong)
                .await
                .err()
                .unwrap();
            assert!(
                matches!(&e, ImageError::DigestMismatch { expected, .. } if *expected == wrong.to_string()),
                "{blob} {diff}: {e}"
            );
            // a digest of the other algorithm for the same bytes is no pass
            let across = Digest::of(
                if diff == Algorithm::Sha256 {
                    Algorithm::Sha512
                } else {
                    Algorithm::Sha256
                },
                b"x",
            );
            assert!(ingest_bytes(&ctx, gz, &layer, &across).await.is_err());
        }
    }

    /// The files of a layer: a gzipped tar of `files` (name, content), its
    /// descriptor and its diff id.
    fn layer_with(files: &[(&str, &[u8])]) -> (Vec<u8>, OciDescriptor, Digest) {
        layer_of_files(files, Algorithm::Sha256)
    }

    /// [`layer_with`], its blob and diff id in `alg`.
    fn layer_of_files(files: &[(&str, &[u8])], alg: Algorithm) -> (Vec<u8>, OciDescriptor, Digest) {
        use std::io::Write;
        let mut tar = tar::Builder::new(Vec::new());
        for (name, data) in files {
            let mut header = tar::Header::new_gnu();
            header.set_size(data.len() as u64);
            header.set_mode(0o644);
            header.set_entry_type(tar::EntryType::Regular);
            tar.append_data(&mut header, name, *data).unwrap();
        }
        let tar = tar.into_inner().unwrap();
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        gz.write_all(&tar).unwrap();
        let gz = gz.finish().unwrap();
        let layer = OciDescriptor {
            media_type: "application/vnd.oci.image.layer.v1.tar+gzip".into(),
            digest: Digest::of(alg, &gz),
            size: gz.len() as i64,
            annotations: Default::default(),
        };
        (gz, layer, Digest::of(alg, &tar))
    }

    /// Bytes that do not compress, so that a file larger than `SMALL_FILE`
    /// is a temporary file.
    fn noise(len: usize, seed: u8) -> Vec<u8> {
        (0..len)
            .map(|i| {
                (i as u32)
                    .wrapping_mul(2654435761)
                    .wrapping_add(seed as u32 * 97) as u8
            })
            .collect()
    }

    fn verity(data: &[u8]) -> String {
        velarx_storage::fsverity_digest_of(Algorithm::Sha256, data)
    }

    /// The layer as the pull records it.
    fn layer_done(layer: &OciDescriptor, ingested: Ingested) -> crate::pull::LayerDone {
        crate::pull::LayerDone {
            key: velarx_types::LayerKey::Whole(layer.digest),
            blob: layer.digest,
            diff_id: ingested.diff_id,
            size: layer.size,
            toc: ingested.toc,
            files: ingested.files,
            chunks: Vec::new(),
            report: ingested.report,
            tarsplit: ingested.tarsplit,
            lazy: false,
            proven: true,
            blob_checked: true,
            checked: Default::default(),
        }
    }

    fn session_of(ctx: &PullCtx) -> Arc<super::super::session::Session> {
        ctx.sink.clone().session().unwrap()
    }

    /// A second pull of a layer read whole stages nothing the store has: the
    /// files are reused, keyed by their fs-verity digest, and the table of
    /// contents they make is settled with no file of the pull's.
    #[tokio::test]
    async fn test_a_second_pull_of_a_stream_layer_reuses_the_files_of_the_store() {
        let dir = tempfile::tempdir().unwrap();
        let big = noise(300 * 1024, 1);
        let small = b"a small file".to_vec();
        let files: [(&str, &[u8]); 3] = [("big", &big), ("small", &small), ("again", &small)];
        let (gz, layer, diff) = layer_with(&files);

        let first = ctx(dir.path()).await;
        let done = ingest_bytes(&first, gz.clone(), &layer, &diff)
            .await
            .unwrap();
        assert_eq!(
            (done.report.fetched_files, done.report.reused_files),
            (2, 1),
            "the first pull fetches each content once"
        );
        let committed = session_of(&first).commit(None).unwrap();
        assert_eq!(committed.len(), 2);
        let store = session_of(&first).store().root().to_path_buf();

        let second = ctx(dir.path()).await;
        let done = ingest_bytes(&second, gz, &layer, &diff).await.unwrap();
        let report = &done.report;
        assert_eq!(
            (report.fetched_files, report.reused_files),
            (0, 3),
            "{report:?}"
        );
        let session = session_of(&second);
        assert_eq!(session.staged_totals(), (0, 0));
        assert_eq!(session.temp_files().len(), 0, "no temporary file is left");
        let keys: Vec<&str> = done.files.iter().map(|f| f.digest.as_str()).collect();
        assert_eq!(keys, [verity(&big), verity(&small), verity(&small)]);
        for key in keys {
            assert!(session.store().contains_local(key), "{key}");
        }
        // the table of contents names them by the fs-verity digest
        let named: Vec<Option<String>> = done.toc.entries.iter().map(|e| e.verity()).collect();
        assert_eq!(
            named,
            [
                Some(verity(&big)),
                Some(verity(&small)),
                Some(verity(&small))
            ]
        );
        // (nothing is committed: the layer settles with what the store has)
        let mut done = layer_done(&layer, done);
        done.settle(&HashMap::new(), session.store()).unwrap();
        assert_eq!(done.toc.entries[0].verity(), Some(verity(&big)));
        assert!(session.commit(None).unwrap().is_empty());
        let _ = store;
    }

    /// The same for a layer whose digests are SHA-512: its files are the
    /// SHA-512 objects of the store, which a SHA-256 object of the same
    /// content is not.
    #[tokio::test]
    async fn test_a_sha512_layer_is_reused_by_its_sha512_objects() {
        let dir = tempfile::tempdir().unwrap();
        let big = noise(300 * 1024, 9);
        let small = b"small".to_vec();
        let (gz, layer, diff) =
            layer_of_files(&[("big", &big), ("small", &small)], Algorithm::Sha512);
        let first = ctx(dir.path()).await;
        // (the store has the SHA-256 objects of the files)
        let sha256 = session_of(&first)
            .store()
            .put(Algorithm::Sha256, &big)
            .unwrap();
        let done = ingest_bytes(&first, gz.clone(), &layer, &diff)
            .await
            .unwrap();
        assert_eq!(
            (done.report.fetched_files, done.report.reused_files),
            (2, 0)
        );
        session_of(&first).commit(None).unwrap();
        let second = ctx(dir.path()).await;
        let done = ingest_bytes(&second, gz, &layer, &diff).await.unwrap();
        assert_eq!(
            (done.report.fetched_files, done.report.reused_files),
            (0, 2)
        );
        let sha512 = |d: &[u8]| velarx_storage::fsverity_digest_of(Algorithm::Sha512, d);
        let keys: Vec<&str> = done.files.iter().map(|f| f.digest.as_str()).collect();
        assert_eq!(keys, [sha512(&big), sha512(&small)]);
        assert_ne!(keys[0], sha256);
    }

    /// A layer of every kind of entry: the sizes around `SMALL_FILE`, an
    /// empty file, a file of zeros (holes where it is written), a hard link,
    /// a symbolic link, a directory and a content twice.
    fn layer_of_every_kind() -> (Vec<u8>, OciDescriptor, Digest) {
        use std::io::Write;
        let small = SMALL_FILE as usize;
        let mut zeros = vec![0u8; 1 << 20];
        zeros[4096] = 1;
        let files: [(&str, Vec<u8>); 6] = [
            ("d/big", noise(small + 1, 11)),
            ("d/at-the-limit", noise(small, 12)),
            ("d/under-the-limit", noise(small - 1, 13)),
            ("d/empty", Vec::new()),
            ("d/zeros", zeros),
            ("d/twice", noise(small + 1, 11)),
        ];
        let mut tar = tar::Builder::new(Vec::new());
        let mut dir = tar::Header::new_gnu();
        dir.set_entry_type(tar::EntryType::Directory);
        dir.set_mode(0o755);
        dir.set_size(0);
        tar.append_data(&mut dir, "d/", std::io::empty()).unwrap();
        for (name, data) in &files {
            let mut header = tar::Header::new_gnu();
            header.set_size(data.len() as u64);
            header.set_mode(0o644);
            header.set_entry_type(tar::EntryType::Regular);
            tar.append_data(&mut header, name, &data[..]).unwrap();
        }
        for (kind, name, target) in [
            (tar::EntryType::Link, "d/hard", "d/big"),
            (tar::EntryType::Symlink, "d/soft", "big"),
        ] {
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(kind);
            header.set_mode(0o777);
            header.set_size(0);
            tar.append_link(&mut header, name, target).unwrap();
        }
        let tar = tar.into_inner().unwrap();
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        gz.write_all(&tar).unwrap();
        let gz = gz.finish().unwrap();
        let layer = OciDescriptor {
            media_type: "application/vnd.oci.image.layer.v1.tar+gzip".into(),
            digest: Digest::of(Algorithm::Sha256, &gz),
            size: gz.len() as i64,
            annotations: Default::default(),
        };
        (gz, layer, Digest::of(Algorithm::Sha256, &tar))
    }

    /// Pull `gz` into the store of `dir` and record it as the pull does:
    /// committed, then settled with what the commit stored.
    async fn pull_and_settle(
        dir: &std::path::Path,
        gz: &[u8],
        layer: &OciDescriptor,
        diff: &Digest,
    ) -> crate::pull::LayerDone {
        let ctx = ctx(dir).await;
        let done = ingest_bytes(&ctx, gz.to_vec(), layer, diff).await.unwrap();
        let session = session_of(&ctx);
        let committed: HashMap<String, velarx_storage::Object> = session
            .commit(None)
            .unwrap()
            .into_iter()
            .map(|c| (c.digest, c.object))
            .collect();
        let mut done = layer_done(layer, done);
        done.settle(&committed, session.store()).unwrap();
        done
    }

    /// A layer whose files the store has is recorded as the pull of an
    /// empty store records it: the same table of contents (fs-verity
    /// digests included), files, diff id and tar-split; only the report
    /// says that the files were reused.
    #[tokio::test]
    async fn test_a_layer_the_store_has_is_recorded_as_a_cold_pull_records_it() {
        let (gz, layer, diff) = layer_of_every_kind();
        let cold_dir = tempfile::tempdir().unwrap();
        let cold = pull_and_settle(cold_dir.path(), &gz, &layer, &diff).await;
        let warm_dir = tempfile::tempdir().unwrap();
        pull_and_settle(warm_dir.path(), &gz, &layer, &diff).await;
        let warm = pull_and_settle(warm_dir.path(), &gz, &layer, &diff).await;

        // (big and twice are one file; empty is none)
        assert_eq!(
            (cold.report.fetched_files, cold.report.reused_files),
            (4, 1)
        );
        assert_eq!(
            (warm.report.fetched_files, warm.report.reused_files),
            (0, 5)
        );
        assert_eq!(warm.diff_id, cold.diff_id);
        assert_eq!(
            serde_json::to_value(&*warm.toc).unwrap(),
            serde_json::to_value(&*cold.toc).unwrap()
        );
        assert_eq!(warm.tarsplit, cold.tarsplit);
        let files = |d: &crate::pull::LayerDone| -> Vec<(String, u64)> {
            d.files.iter().map(|f| (f.digest.clone(), f.size)).collect()
        };
        assert_eq!(files(&warm), files(&cold));
        assert!(files(&cold)
            .iter()
            .all(|(d, _)| d.starts_with("fsverity-sha256-12:")));
        // every regular file with content is named by its object
        let named = cold
            .toc
            .entries
            .iter()
            .filter(|e| e.entry_type == velarx_storage::TocEntryType::Reg && e.size > 0)
            .all(|e| e.verity().is_some() && e.digest.is_some());
        assert!(named);
    }

    /// A layer that shares a file with a stored one fetches only the others.
    #[tokio::test]
    async fn test_a_layer_sharing_files_with_a_stored_one_fetches_the_rest() {
        let dir = tempfile::tempdir().unwrap();
        let shared = noise(300 * 1024, 2);
        let own = noise(300 * 1024, 3);
        let tiny = b"tiny".to_vec();
        let (gz, layer, diff) = layer_with(&[("shared", &shared), ("tiny", &tiny)]);
        let first = ctx(dir.path()).await;
        ingest_bytes(&first, gz, &layer, &diff).await.unwrap();
        session_of(&first).commit(None).unwrap();

        let (gz, layer, diff) = layer_with(&[
            ("shared", &shared),
            ("own", &own),
            ("tiny", &tiny),
            ("new", b"new small"),
        ]);
        let second = ctx(dir.path()).await;
        let done = ingest_bytes(&second, gz, &layer, &diff).await.unwrap();
        assert_eq!(
            (done.report.fetched_files, done.report.reused_files),
            (2, 2),
            "{:?}",
            done.report
        );
        let session = session_of(&second);
        assert_eq!(session.staged_totals().0, 2);
        let mut done = layer_done(&layer, done);
        let committed: HashMap<String, velarx_storage::Object> = session
            .commit(None)
            .unwrap()
            .into_iter()
            .map(|c| (c.digest, c.object))
            .collect();
        assert_eq!(committed.len(), 2);
        done.settle(&committed, session.store()).unwrap();
        let keys: Vec<&str> = done.files.iter().map(|f| f.digest.as_str()).collect();
        assert_eq!(
            keys,
            [
                verity(&shared),
                verity(&own),
                verity(&tiny),
                verity(b"new small")
            ]
        );
    }

    /// A layer that fails (a stream that stops, a wrong diff id, a wrong
    /// blob) leaves no file named by a digest, in the staging area nor in
    /// the store: what was read waits under names no lookup finds, and the
    /// store has nothing.
    #[tokio::test]
    async fn test_a_layer_that_fails_leaves_no_file_named_by_a_digest() {
        let big = noise(300 * 1024, 4);
        let more = noise(800 * 1024, 5);
        let tail = noise(1536 * 1024, 8);
        // (a frame of the stream is a mebibyte: the first files are whole
        // in the first one, the last is cut)
        let (gz, layer, diff) = layer_with(&[
            ("big", &big),
            ("small", b"a small file"),
            ("more", &more),
            ("tail", &tail),
        ]);
        let wrong_diff = Digest::of(Algorithm::Sha256, b"not the tar");
        let mut wrong_blob = layer.clone();
        wrong_blob.digest = Digest::of(Algorithm::Sha256, b"not the blob");
        let cut = gz.len() * 3 / 4;
        for (what, bytes, lost, layer, diff) in [
            (
                "a stream that stops",
                gz[..cut].to_vec(),
                true,
                layer.clone(),
                diff,
            ),
            (
                "a wrong diff id",
                gz.clone(),
                false,
                layer.clone(),
                wrong_diff,
            ),
            ("a wrong blob digest", gz.clone(), false, wrong_blob, diff),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let ctx = ctx(dir.path()).await;
            let mut pieces = vec![Ok::<_, ImageError>(Bytes::from(bytes))];
            if lost {
                pieces.push(Err(ImageError::transfer(
                    "registry",
                    FailureClass::Transient,
                    "the connection was lost",
                )));
            }
            let body = futures::stream::iter(pieces);
            let result = ingest_stream(&ctx, body, &layer, &diff, |_| {}, false).await;
            assert!(result.is_err(), "{what}");
            let session = session_of(&ctx);
            assert!(
                session.staged_totals().0 >= 2,
                "{what}: it read the first files"
            );
            assert_eq!(
                digest_names(dir.path()),
                Vec::<std::path::PathBuf>::new(),
                "{what}"
            );
            assert!(!session.store().contains_local(&verity(&big)), "{what}");
        }
    }

    /// While a layer is pulled nothing in the staging area, nor in the
    /// store, appears under a name made of a digest: a process that looks a
    /// file up by its digest finds nothing it cannot trust; a name is given
    /// by the commit, after fs-verity.
    #[tokio::test]
    async fn test_no_name_of_a_digest_appears_while_a_layer_is_pulled() {
        let dir = tempfile::tempdir().unwrap();
        let big = noise(300 * 1024, 6);
        let more = noise(400 * 1024, 7);
        let (gz, layer, diff) = layer_with(&[
            ("big", &big),
            ("small", b"a small file"),
            ("more", &more),
            ("again", &big),
        ]);
        let ctx = ctx(dir.path()).await;
        let session = session_of(&ctx);
        let temp_dirs = session.temp_dirs();
        let mut watched: Vec<&std::path::Path> = temp_dirs.iter().map(|d| d.as_path()).collect();
        let staging = dir.path().join("staging");
        watched.extend([staging.as_path(), session.store().root()]);
        let names = Names::watching(&watched);
        let body = futures::stream::iter(
            gz.chunks(16 * 1024)
                .map(|c| Ok::<_, ImageError>(Bytes::copy_from_slice(c)))
                .collect::<Vec<_>>(),
        );
        ingest_stream(&ctx, body, &layer, &diff, |_| {}, false)
            .await
            .unwrap();
        assert_eq!(session.staged_totals().0, 3);
        let (seen, _) = names.finish();
        let named: Vec<&String> = seen.iter().filter(|n| is_digest_name(n)).collect();
        assert!(
            named.is_empty(),
            "named by a digest while pulling: {named:?}"
        );
        // (it did watch: the temporary files were made)
        assert!(seen.iter().any(|n| n.starts_with("tmp-")), "{seen:?}");
        assert_eq!(digest_names(dir.path()), Vec::<std::path::PathBuf>::new());
        session.commit(None).unwrap();
        let in_store = digest_names(session.store().root());
        assert_eq!(in_store.len(), 3, "{in_store:?}");
        assert_eq!(
            digest_names(session.dir()),
            Vec::<std::path::PathBuf>::new()
        );
    }
}
