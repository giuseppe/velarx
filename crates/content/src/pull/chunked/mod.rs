// SPDX-License-Identifier: Apache-2.0
//! Partial pulls of zstd:chunked layers.
//!
//! The table of contents and the tar-split are fetched with range requests
//! and checked against the manifest annotations.  From the table of contents
//! the pull plans which files it needs: the ones already in the store (or
//! with the content of an earlier file) are not fetched, the chunks another
//! file of the store already holds are read from there, and the compressed
//! ranges of the others are requested, several requests at a time.
//!
//! Every chunk is decompressed with a bound on its size, checked against its
//! digest and written at its offset in a staged file, which is hashed as its
//! chunks arrive; the file digest must be the one of the table of contents.
//! The diff id is computed by replaying the tar-split with the staged files
//! while the download goes on, and the table of contents that is recorded is
//! built from the tar headers of that verified stream, so the metadata of
//! the files (modes, owners, extended attributes, links) can only be what the
//! image configuration vouches for.

use super::entry::{self, MAX_ENTRIES};

use super::ranges::{Learnt, MAX_RANGES_PER_REQUEST, MAX_RANGE_HEADER};
use super::stream::FileUse;
use super::tar::{normalize_path, Kind, TarReader};
use super::tarsplit::{self, ContentFile, ContentIndex, Contents, Entries, Replay};
use super::{LayerReport, PullCtx};
use crate::fetcher::{BlobRange, ChunkId, ChunkRef};
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{self, BufRead, Read};
use std::ops::Range;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use tracing::debug;
use velarx_db::ChunkLocation as ChunkLocationRecord;
use velarx_proto::transfer::FailureClass;
use velarx_registry::target::Target;
use velarx_storage::{canonical, Toc, TocEntry, TocEntryType, TOC_VERSION};
use velarx_types::digest::{Algorithm, Digest, DigestWriter, Offloaded};
use velarx_types::{ImageError, ImageResult, LayerKey, OciDescriptor};

const ANNOTATION_PREFIXES: [&str; 2] = [
    "io.github.containers.zstd-chunked.",
    "io.containers.zstd-chunked.",
];

/// Largest compressed TOC or tar-split fetched, and largest TOC once
/// decompressed.
pub const MAX_METADATA_COMPRESSED: u64 = 64 * 1024 * 1024;
pub const MAX_TOC_JSON: u64 = 128 * 1024 * 1024;
pub const MAX_TARSPLIT: u64 = 512 * 1024 * 1024;

/// Zeros a layer may hold in sparse holes (they are hashed, not stored).
const MAX_ZEROS: u64 = 4 * 1024 * 1024 * 1024;

/// A range request carries at least this much unless the layer has less.
const MIN_BATCH_BYTES: u64 = 2 * 1024 * 1024;
const MAX_BATCH_BYTES: u64 = 32 * 1024 * 1024;
/// The TOC and the tar-split of a layer are fetched in one request when no
/// more than this lies between them and both are no larger than the second
/// limit (a fetcher keeps a blob that is not a layer in memory).
pub const METADATA_GAP: u64 = 64 * 1024;
pub const METADATA_TOGETHER: u64 = 8 * 1024 * 1024;

/// Times a request is retried after an error.
pub(crate) const RETRIES: usize = 3;

pub struct Pulled {
    pub toc: Toc,
    pub files: Vec<FileUse>,
    pub chunks: Vec<ChunkLocationRecord>,
    pub report: LayerReport,
    pub diff_id: Digest,
    /// The verified zstd compressed tar-split.
    pub tarsplit: bytes::Bytes,
    /// The table as the registry sent it, of a layer pulled by its table
    /// ([`Metadata::toc_z`])
    pub toc_z: Option<bytes::Bytes>,
}

/// The positions of the metadata in the blob.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Info {
    pub toc: (u64, u64, u64),
    pub checksum: Digest,
    pub tarsplit: Option<(u64, u64, u64)>,
}

fn annotation<'a>(layer: &'a OciDescriptor, name: &str) -> Option<&'a String> {
    ANNOTATION_PREFIXES
        .iter()
        .find_map(|p| layer.annotations.get(&format!("{p}{name}")))
}

fn parse_numbers<const N: usize>(s: &str) -> Option<[u64; N]> {
    let mut out = [0u64; N];
    let mut parts = s.split(':');
    for slot in out.iter_mut() {
        let p = parts.next()?;
        if p.is_empty() || !p.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        *slot = p.parse().ok()?;
    }
    parts.next().is_none().then_some(out)
}

/// The zstd:chunked metadata of a layer, if it has any.  A descriptor with
/// any zstd:chunked annotation says that the layer has a table of contents,
/// which it is pulled by or not at all: annotations that do not name one
/// this can read (on a layer that is not zstd, without the position or the
/// checksum of the table, of another kind of table) are an error, never a
/// layer to read as a stream.
pub fn parse_info(layer: &OciDescriptor) -> ImageResult<Option<Info>> {
    if !layer
        .annotations
        .keys()
        .any(|k| ANNOTATION_PREFIXES.iter().any(|p| k.starts_with(p)))
    {
        return Ok(None);
    }
    let refused = |why: &str| {
        ImageError::Manifest(format!(
            "layer {}: its zstd:chunked annotations {why}",
            layer.digest
        ))
    };
    if crate::layer::writer::Compression::from_media_type(&layer.media_type)
        != Some(crate::layer::writer::Compression::ZstdChunked)
    {
        return Err(refused(&format!(
            "are on a layer of type {}",
            layer.media_type
        )));
    }
    let (Some(position), Some(checksum)) = (
        annotation(layer, "manifest-position"),
        annotation(layer, "manifest-checksum"),
    ) else {
        return Err(refused(
            "do not give both the position and the checksum of its table of contents",
        ));
    };
    let toc = parse_numbers::<4>(position).ok_or_else(|| {
        ImageError::Manifest(format!(
            "invalid zstd:chunked manifest position `{position}`"
        ))
    })?;
    if toc[3] != 1 {
        return Err(ImageError::Manifest(format!(
            "unknown zstd:chunked manifest type {}",
            toc[3]
        )));
    }
    let checksum: Digest = checksum.parse().map_err(|e| {
        ImageError::Manifest(format!(
            "invalid zstd:chunked manifest checksum `{checksum}`: {e}"
        ))
    })?;
    let tarsplit = match annotation(layer, "tarsplit-position") {
        Some(p) => {
            let t = parse_numbers::<3>(p).ok_or_else(|| {
                ImageError::Manifest(format!("invalid zstd:chunked tar-split position `{p}`"))
            })?;
            Some((t[0], t[1], t[2]))
        }
        None => None,
    };
    Ok(Some(Info {
        toc: (toc[0], toc[1], toc[2]),
        checksum,
        tarsplit,
    }))
}

fn fail(msg: impl Into<String>) -> ImageError {
    ImageError::Layer(msg.into())
}

/// `e`, an error of the pull of `layer` by its table of contents, as one
/// that names the layer.
pub fn naming(layer: &Digest, e: ImageError) -> ImageError {
    let named = |m: &str| m.contains(&layer.to_string());
    match e {
        ImageError::Layer(m) if !named(&m) => ImageError::Layer(format!("layer {layer}: {m}")),
        ImageError::Registry(m) if !named(&m) => {
            ImageError::Registry(format!("layer {layer}: {m}"))
        }
        ImageError::Contradicted(m) if !named(&m) => {
            ImageError::Contradicted(format!("layer {layer}: {m}"))
        }
        ImageError::DigestMismatch { expected, actual } => ImageError::Contradicted(format!(
            "layer {layer}: digest mismatch: expected {expected}, got {actual}"
        )),
        ImageError::Transfer {
            party,
            object: None,
            failure,
        } => ImageError::Transfer {
            party,
            object: Some(layer.to_string()),
            failure,
        },
        e => e,
    }
}

/// Whether `e` says that what the descriptor vouches for (the TOC, and the
/// tar-split, chunks and files it names) is not what the registry gives, or
/// that the view of the TOC is not the diff id of the configuration.
pub fn refuses(e: &ImageError) -> bool {
    match e {
        ImageError::Transfer { failure, .. } => {
            failure.class == velarx_proto::transfer::FailureClass::Invalid
        }
        e => matches!(
            e,
            ImageError::DigestMismatch { .. } | ImageError::Contradicted(_)
        ),
    }
}

/// A failure of a file of the stage.  The system failing (no space, an I/O
/// error: it gave an errno) is this machine's; what the stage says itself (a
/// file it does not have) is the layer's.
pub fn io_fail(e: io::Error) -> ImageError {
    match e.raw_os_error() {
        Some(_) => ImageError::Io(e),
        None => ImageError::Layer(e.to_string()),
    }
}

/// The bytes of a layer that are not a stream of the kind they should be.
fn data_fail(e: io::Error) -> ImageError {
    ImageError::Layer(e.to_string())
}

/// The compressed TOC and tar-split of `layer`: what the fetchers of the
/// pull find (`Probe`).  Not verified yet.
pub(super) async fn metadata(
    ctx: &PullCtx,
    layer: &OciDescriptor,
) -> ImageResult<(Vec<u8>, Vec<u8>)> {
    let staged = ctx
        .staged
        .as_ref()
        .ok_or_else(|| fail("no fetcher for the layer"))?;
    staged
        .probe(layer, false)
        .await?
        .ok_or_else(|| fail("no fetcher gave its table of contents"))
}

/// The verified table of contents and tar-split of a layer pulled by ranges
/// (what the feed of a pull shows a driver of the layer): fetched now.  None
/// for a layer that is not zstd:chunked.
pub async fn layer_index(ctx: &PullCtx, layer: &OciDescriptor) -> ImageResult<Option<Metadata>> {
    let Some(info) = parse_info(layer)? else {
        return Ok(None);
    };
    let by_table = async {
        let (toc_z, ts_z) = metadata(ctx, layer).await?;
        verified(
            &info,
            toc_z,
            ts_z,
            layer.digest,
            ctx.limits.max_layer_bytes,
            false,
        )
        .await
    };
    by_table
        .await
        .map(Some)
        .map_err(|e| naming(&layer.digest, e))
}

/// [`verify_metadata`] of what the fetchers found, or [`verified_table`]
/// for a `lazy` layer (the table is what it is served by), whose completion
/// replays the tar-split before the layer is committed.
pub(super) async fn verified(
    info: &Info,
    toc_z: Vec<u8>,
    ts_z: Vec<u8>,
    layer: Digest,
    max_tar: u64,
    lazy: bool,
) -> ImageResult<Metadata> {
    let info = info.clone();
    tokio::task::spawn_blocking(move || match lazy {
        true => verified_table(&info, &toc_z, ts_z, &layer, (max_tar, false)),
        false => verify_metadata(&info, &toc_z, ts_z, &layer, max_tar),
    })
    .await
    .map_err(|e| fail(e.to_string()))?
}

/// Decompress at most `max` bytes, and exactly `expected` if it is known.
fn decompress_bounded(data: &[u8], max: u64, expected: u64, what: &str) -> ImageResult<Vec<u8>> {
    let dec = super::zstd_decoder(data).map_err(data_fail)?;
    let mut out = Vec::with_capacity(expected.min(max) as usize);
    dec.take(max + 1).read_to_end(&mut out).map_err(data_fail)?;
    if out.len() as u64 > max {
        return Err(fail(format!("the {what} is too large")));
    }
    if expected != 0 && out.len() as u64 != expected {
        return Err(fail(format!(
            "the {what} has {} bytes, the annotation says {expected}",
            out.len()
        )));
    }
    Ok(out)
}

/// The table of contents `json` is, its entries parsed on all the threads:
/// the document is scanned once for the extent of each entry (the parser
/// tells where they are, there is no second reading of the format), and the
/// entries, which are most of the work, are read apart.
fn parse_toc(json: &[u8]) -> serde_json::Result<Toc> {
    use rayon::prelude::*;
    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Raw<'a> {
        version: i32,
        #[serde(borrow)]
        entries: Vec<&'a serde_json::value::RawValue>,
        tar_split_digest: Option<String>,
    }
    let raw: Raw = serde_json::from_slice(json)?;
    Ok(Toc {
        version: raw.version,
        entries: raw
            .entries
            .par_iter()
            .with_min_len(256)
            .map(|e| serde_json::from_str(e.get()))
            .collect::<serde_json::Result<_>>()?,
        tar_split_digest: raw.tar_split_digest,
    })
}

/// The verified TOC and the compressed tar-split of a layer.
#[derive(Clone)]
pub struct Metadata {
    /// The table as the descriptor vouches for it; `stored` itself for a
    /// layer that is not pulled by [`verify_metadata`] (a lazy layer is
    /// served by what it is stored by).
    pub toc: Arc<Toc>,
    /// What the layer is stored by: the entries of the table as a layer
    /// keeps them ([`super::lazy::toc_view`]); the table itself for a
    /// canonical layer.
    pub stored: Arc<Toc>,
    /// The table as the registry sent it (compressed, the bytes its
    /// descriptor's checksum covers): kept with the layer for the peers,
    /// which check it against the same descriptor.
    pub toc_z: bytes::Bytes,
    pub tarsplit_z: bytes::Bytes,
    pub tarsplit_size: u64,
}

/// The error of a table of contents of version 2 that is not one: the
/// descriptor vouches for it, so the layer is not pulled another way.
fn invalid_canonical(layer: &Digest, reason: impl std::fmt::Display) -> ImageError {
    ImageError::Contradicted(format!(
        "layer {layer}: invalid zstd:chunked version 2 table of contents: {reason}"
    ))
}

/// The table of contents (and the tar-split, which a layer with a table of
/// version 2 has not) that a descriptor vouches for, checked against what
/// it says, and for a tar of at most `max_tar` bytes.  The table of a layer is the one of a canonical tar when its
/// `version` is 2, whatever the annotations say: it must be one, and then
/// it is all the layer has.  A layer with a table is pulled by it or not at
/// all: one that has no tar-split and no table of version 2, or whose table
/// gives a file no fs-verity digest, is an error naming the layer.  The
/// tar-split must describe the entries of the table
/// ([`super::lazy::replay`]).
pub fn verify_metadata(
    info: &Info,
    toc_z: &[u8],
    ts_z: Vec<u8>,
    layer: &Digest,
    max_tar: u64,
) -> ImageResult<Metadata> {
    let meta = verified_table(info, toc_z, ts_z, layer, (max_tar, true))?;
    super::lazy::replay(&meta.stored, meta.tarsplit_z.clone(), layer)?;
    Ok(meta)
}

/// [`verify_metadata`] but the replay: every byte is checked against the
/// digests the descriptor vouches for (the tar-split against the one the
/// table gives).  The table is kept as it was vouched for beside the one
/// the layer is stored by when `keep` (the stored one is made in place from
/// the table otherwise).
fn verified_table(
    info: &Info,
    toc_z: &[u8],
    ts_z: Vec<u8>,
    layer: &Digest,
    (max_tar, keep): (u64, bool),
) -> ImageResult<Metadata> {
    // (what the descriptor vouches for: bytes that are not it are not a
    // layer to pull another way, see `pull`)
    let actual = Digest::of(info.checksum.alg(), toc_z);
    if actual != info.checksum {
        return Err(ImageError::DigestMismatch {
            expected: info.checksum.to_string(),
            actual: actual.to_string(),
        });
    }
    // (the bytes are those the descriptor vouches for: what is wrong with
    // them is wrong again on every try)
    vouched_metadata(info, toc_z, ts_z, layer, (max_tar, keep)).map_err(|e| match e {
        ImageError::Layer(m) => ImageError::Contradicted(format!("layer {layer}: {m}")),
        e => e,
    })
}

/// [`verify_metadata`] of a table that is the bytes of its checksum.
fn vouched_metadata(
    info: &Info,
    toc_z: &[u8],
    ts_z: Vec<u8>,
    layer: &Digest,
    (max_tar, keep): (u64, bool),
) -> ImageResult<Metadata> {
    let json = decompress_bounded(toc_z, MAX_TOC_JSON, info.toc.2, "TOC")?;
    let toc = parse_toc(&json).map_err(|e| fail(format!("invalid TOC: {e}")))?;
    drop(json);
    if let Some(problem) = entry::toc_problem(&toc.entries) {
        return Err(fail(problem));
    }
    if toc.is_canonical() {
        if info.tarsplit.is_some() || toc.tar_split_digest.is_some() {
            return Err(invalid_canonical(layer, "the layer has a tar-split"));
        }
        canonical::validate_within(&toc.entries, max_tar)
            .map_err(|e| invalid_canonical(layer, e))?;
        let toc = Arc::new(toc);
        return Ok(Metadata {
            stored: toc.clone(),
            toc,
            toc_z: bytes::Bytes::copy_from_slice(toc_z),
            tarsplit_z: bytes::Bytes::new(),
            tarsplit_size: 0,
        });
    }
    let Some(tarsplit) = info.tarsplit else {
        return Err(ImageError::Contradicted(format!(
            "layer {layer}: its table of contents has no tar-split and is not of version 2"
        )));
    };
    if let Some(e) = super::lazy::without_verity(&toc) {
        return Err(ImageError::Contradicted(format!(
            "layer {layer}: its table of contents has no fs-verity digest for `{}`",
            e.name
        )));
    }
    if let Some((_, reason)) = velarx_storage::size_conflict(&toc.entries) {
        return Err(fail(reason));
    }
    let mut files = toc
        .entries
        .iter()
        .filter(|e| e.entry_type == TocEntryType::Reg);
    if files
        .try_fold(0u64, |sum, e| sum.checked_add(e.size))
        .is_none_or(|sum| sum > max_tar)
    {
        return Err(fail(format!(
            "the files of the layer are more than {max_tar} bytes"
        )));
    }
    let expected = toc
        .tar_split_digest
        .as_deref()
        .ok_or_else(|| fail("the TOC has no tar-split digest"))?;
    let expected: Digest = expected.parse().map_err(|e| {
        fail(format!(
            "invalid tar-split digest `{expected}` in the TOC: {e}"
        ))
    })?;
    let actual = Digest::of(expected.alg(), &ts_z);
    if actual != expected {
        return Err(ImageError::DigestMismatch {
            expected: expected.to_string(),
            actual: actual.to_string(),
        });
    }
    let ts_z = bytes::Bytes::from(ts_z);
    let vouched = keep.then(|| Arc::new(toc.clone()));
    let stored = Arc::new(super::lazy::toc_view(toc, info.checksum.alg(), layer)?);
    Ok(Metadata {
        toc: vouched.unwrap_or_else(|| stored.clone()),
        stored,
        toc_z: bytes::Bytes::copy_from_slice(toc_z),
        tarsplit_z: ts_z,
        tarsplit_size: tarsplit.2,
    })
}

#[derive(Debug)]
struct ChunkPlan {
    job: usize,
    file_off: u64,
    size: u64,
    /// Digest of the decompressed chunk; `None` for a file in one chunk
    /// without a chunk digest, which the file digest covers.
    digest: Option<Digest>,
    comp: Range<u64>,
}

#[derive(Debug)]
struct FileJob {
    /// What the file is known by (`TocEntry::content_key`).
    digest: String,
    size: u64,
    /// Zero-filled holes: offset and length.
    holes: Vec<(u64, u64)>,
    chunks: Range<usize>,
}

#[derive(Debug)]
pub(crate) struct Plan {
    /// The algorithm of the digests of the layer: of the files and chunks
    /// the TOC names, and of the fs-verity digests of the objects.
    alg: Algorithm,
    jobs: Vec<FileJob>,
    chunks: Vec<ChunkPlan>,
    /// Digests of files the layer has that need no fetch.
    skipped: Vec<(String, u64)>,
    skipped_compressed: u64,
    skipped_files: u64,
    zeros: u64,
    planned: u64,
}

#[cfg(test)]
impl Default for Plan {
    fn default() -> Self {
        Self::new(Algorithm::Sha256)
    }
}

impl Plan {
    /// An empty plan for a layer whose digests are made with `alg`.
    fn new(alg: Algorithm) -> Self {
        Self {
            alg,
            jobs: Vec::new(),
            chunks: Vec::new(),
            skipped: Vec::new(),
            skipped_compressed: 0,
            skipped_files: 0,
            zeros: 0,
            planned: 0,
        }
    }
}

/// The digest `text` of a file or a chunk of the TOC of a layer of `alg`
/// digests: a layer has the digests of one algorithm (the one of its key),
/// so a digest of the other is refused by name.
fn layer_digest(name: &str, text: &str, alg: Algorithm) -> ImageResult<Digest> {
    let digest: Digest = text
        .parse()
        .map_err(|e| fail(format!("invalid digest for `{name}`: {e}")))?;
    if digest.alg() != alg {
        return Err(unsupported(format!(
            "`{name}` has the {} digest {digest}, and the digests of the layer are {alg} (a layer has the digests of one algorithm)",
            digest.alg(),
        )));
    }
    Ok(digest)
}

/// Why a layer cannot be pulled by ranges.
fn unsupported(msg: impl Into<String>) -> ImageError {
    ImageError::Layer(msg.into())
}

/// The largest compressed form of `size` bytes accepted: what zstd needs
/// for data it cannot compress, and some framing.  A chunk whose compressed
/// range is larger is refused before anything of it is fetched (the bytes
/// are buffered before they are decompressed).
pub fn compressed_bound(size: u64) -> u64 {
    size.saturating_add(size / 64).saturating_add(1 << 20)
}

/// Where the chunks of the files of a verified table of contents are in the
/// layer's own objects: for each chunk with a digest (a file in one chunk
/// that its file digest covers has none), the object it is in (the key the
/// table gives the file), the offset in it and its size.  What a driver with
/// files of its own is recorded to have, so that a later pull can have it copy
/// a chunk it holds instead of fetching it.  A chunk of zeros is a hole and
/// has no place; each digest is recorded once.
pub fn located_chunks(toc: &Toc) -> Vec<ChunkLocationRecord> {
    located_chunks_where(toc, |_| true)
}

/// [`located_chunks`] of the regular files at the entries `keep` takes: those
/// whose bytes were checked chunk by chunk against the table (a table's word
/// for the chunks of an object nobody checked them in is no place to copy
/// from).
pub fn located_chunks_where(toc: &Toc, keep: impl Fn(usize) -> bool) -> Vec<ChunkLocationRecord> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for i in 0..toc.entries.len() {
        if !keep(i) {
            continue;
        }
        let Some(file) = TocChunks::of(&toc.entries, i) else {
            continue;
        };
        for c in file.records() {
            if seen.insert(c.chunk_digest) {
                out.push(c);
            }
        }
    }
    out
}

/// A chunk of a regular file of a table of contents: where it is in the
/// file, its size, its digest; a chunk of zeros is a hole and has no place.
struct TocChunk {
    offset: u64,
    size: u64,
    digest: Digest,
    zeros: bool,
}

/// The chunks a table of contents gives a regular file with content, in
/// order, when they cover it exactly, each with a digest; and the key of
/// the object the file is.
struct TocChunks {
    key: String,
    chunks: Vec<TocChunk>,
}

impl TocChunks {
    /// The chunks of the regular file at `i` of `entries` (followed by its
    /// chunk entries), `None` when it has none or they do not cover it.
    fn of(entries: &[TocEntry], i: usize) -> Option<Self> {
        let e = entries.get(i)?;
        if e.entry_type != TocEntryType::Reg || e.size == 0 || e.chunk_digest.is_none() {
            return None;
        }
        let key = e.content_key()?;
        let mut chunks = Vec::new();
        let mut file_off = 0u64;
        let mut j = i;
        loop {
            let c = &entries[j];
            let size = match (j == i, c.chunk_size) {
                (true, 0) => e.size,
                _ => c.chunk_size,
            };
            let digest = c
                .chunk_digest
                .as_deref()
                .and_then(|d| d.parse::<Digest>().ok())?;
            let end = file_off.checked_add(size)?;
            if size == 0 || end > e.size {
                return None;
            }
            chunks.push(TocChunk {
                offset: file_off,
                size,
                digest,
                zeros: c.is_zeros_chunk(),
            });
            file_off = end;
            j += 1;
            if j >= entries.len() || entries[j].entry_type != TocEntryType::Chunk {
                break;
            }
        }
        (file_off == e.size).then_some(Self { key, chunks })
    }

    /// The places of the chunks that are not holes.
    fn records(self) -> impl Iterator<Item = ChunkLocationRecord> {
        let key = self.key;
        self.chunks
            .into_iter()
            .filter(|c| !c.zeros)
            .map(move |c| ChunkLocationRecord {
                chunk_digest: c.digest,
                file_digest: key.clone(),
                offset: c.offset,
                size: c.size,
            })
    }
}

/// Plan the chunks of the file at `i` of the TOC, followed by its chunk
/// entries.  The compressed range of a chunk goes from its offset to the
/// offset of the next chunk, or to the end of the file for the last one.
/// `blob_size`: the blob the offsets are of (none: the table is not of a blob
/// and has no offsets, as that of a layer without a table of contents).
fn plan_file(
    plan: &mut Plan,
    entries: &[TocEntry],
    i: usize,
    blob_size: Option<i64>,
    max_chunk: u64,
) -> ImageResult<()> {
    let e = &entries[i];
    let digest_str = e.content_key().unwrap_or_default();
    let alg = plan.alg;
    let placed = blob_size.is_some();
    if let Some(size) = blob_size {
        if e.end_offset <= e.offset || (size >= 0 && e.end_offset > size as u64) {
            return Err(fail(format!("invalid offsets for `{}`", e.name)));
        }
    }
    let job = plan.jobs.len();
    let first = plan.chunks.len();
    let mut holes = Vec::new();

    let mut last = i;
    while last + 1 < entries.len() && entries[last + 1].entry_type == TocEntryType::Chunk {
        last += 1;
    }

    if e.chunk_digest.is_none() {
        if last > i {
            return Err(fail(format!(
                "chunks without a chunk digest for `{}`",
                e.name
            )));
        }
        if e.size > max_chunk {
            return Err(unsupported(format!(
                "`{}` is too big to be fetched as a chunk",
                e.name
            )));
        }
        if placed && e.end_offset - e.offset > compressed_bound(e.size) {
            return Err(fail(format!(
                "the compressed range of `{}` is too big",
                e.name
            )));
        }
        plan.chunks.push(ChunkPlan {
            job,
            file_off: 0,
            size: e.size,
            // (when the TOC gives the hash of the file it is the one of the
            // chunk)
            digest: e
                .digest
                .as_deref()
                .map(|d| layer_digest(&e.name, d, alg))
                .transpose()?,
            comp: e.offset..e.end_offset,
        });
    } else {
        let mut file_off = 0u64;
        for j in i..=last {
            let c = &entries[j];
            let size = if j == i {
                if c.chunk_size != 0 {
                    c.chunk_size
                } else {
                    e.size
                }
            } else {
                c.chunk_size
            };
            let chunk_off = if j == i { 0 } else { c.chunk_offset };
            // The compressed bytes of a chunk end where those of the next
            // entry begin (a zeros chunk has a small frame of its own).
            let end = if j == last {
                e.end_offset
            } else {
                entries[j + 1].offset
            };
            if chunk_off != file_off || size == 0 || size > e.size - file_off {
                return Err(fail(format!("invalid chunks for `{}`", e.name)));
            }
            let chunk_digest = c
                .chunk_digest
                .clone()
                .ok_or_else(|| fail(format!("chunk without a digest for `{}`", e.name)))?;
            let chunk_digest = layer_digest(&e.name, &chunk_digest, alg)?;
            // (a hole is not held in memory: it is bounded by MAX_ZEROS)
            if size > max_chunk && !c.is_zeros_chunk() {
                return Err(unsupported(format!("a chunk of `{}` is too big", e.name)));
            }
            if c.is_zeros_chunk() {
                plan.zeros += size;
                if plan.zeros > MAX_ZEROS {
                    return Err(unsupported("the layer has too many zeros"));
                }
                holes.push((file_off, size));
            } else {
                if placed && (c.offset < e.offset || end <= c.offset || end > e.end_offset) {
                    return Err(fail(format!("invalid chunk offsets for `{}`", e.name)));
                }
                if placed && end - c.offset > compressed_bound(size) {
                    return Err(fail(format!(
                        "the compressed range of a chunk of `{}` is too big",
                        e.name
                    )));
                }
                plan.chunks.push(ChunkPlan {
                    job,
                    file_off,
                    size,
                    digest: Some(chunk_digest),
                    comp: c.offset..end,
                });
            }
            file_off += size;
        }
        if file_off != e.size {
            return Err(fail(format!("chunks do not cover `{}`", e.name)));
        }
    }
    plan.jobs.push(FileJob {
        digest: digest_str,
        size: e.size,
        holes,
        chunks: first..plan.chunks.len(),
    });
    Ok(())
}

/// [`make_plan`] on the blocking pool: asking the store for a file may copy
/// it from a read-only store.  The TOC comes back with the plan.
pub(super) async fn plan_blocking(
    have: super::Have,
    toc: Arc<Toc>,
    alg: Algorithm,
    blob_size: i64,
    limits: &super::Limits,
) -> ImageResult<Plan> {
    let (max_chunk, cap) = (limits.max_chunk_bytes, limits.inflate_cap(blob_size));
    // (a table the plan refuses is refused again on every try)
    tokio::task::spawn_blocking(move || {
        make_plan(&toc, alg, blob_size, max_chunk, cap, &*have).map_err(|e| match e {
            ImageError::Layer(m) => ImageError::Contradicted(m),
            e => e,
        })
    })
    .await
    .map_err(|e| fail(format!("planning the layer: {e}")))?
}

pub(crate) fn make_plan(
    toc: &Toc,
    alg: Algorithm,
    blob_size: i64,
    max_chunk: u64,
    cap: u64,
    have: &dyn Fn(&str, u64) -> bool,
) -> ImageResult<Plan> {
    let mut plan = Plan::new(alg);
    let mut seen: HashSet<String> = HashSet::new();
    for (i, e) in toc.entries.iter().enumerate() {
        if e.entry_type != TocEntryType::Reg || e.size == 0 {
            continue;
        }
        // (an fs-verity digest of the other algorithm than the layer's is
        // refused by name; a value that is none is another writer's)
        if let Some(d) = e.fsverity {
            if d.alg() != alg {
                return Err(unsupported(format!(
                    "`{}` has the {} fs-verity digest {}-12:{}, and the digests of the layer are {alg} (a layer has the digests of one algorithm)",
                    e.name,
                    d.alg(),
                    d.alg(),
                    d.hex()
                )));
            }
        }
        let key = e
            .content_key()
            .ok_or_else(|| fail(format!("TOC entry `{}` has no valid digest", e.name)))?;
        // (the key is a content digest or an object name: of the layer's
        // algorithm either way)
        match Digest::parse_fsverity(&key) {
            Ok(object) if object.alg() == alg => {}
            Ok(object) => {
                return Err(unsupported(format!(
                "`{}` has the {} fs-verity digest {key}, and the digests of the layer are {alg}",
                e.name,
                object.alg()
            )))
            }
            Err(_) => {
                layer_digest(&e.name, &key, alg)?;
            }
        }
        let d = key.as_str();
        // The content of an earlier entry, or already available.
        let first = seen.insert(key.clone());
        let available = have(d, e.size);
        if !first || available {
            plan.skipped_files += 1;
            plan.skipped_compressed += e.end_offset.saturating_sub(e.offset);
            if available {
                plan.skipped.push((d.to_string(), e.size));
            }
            continue;
        }
        // (the holes are bounded on their own: no byte of them is fetched)
        let zeros = plan.zeros;
        plan_file(&mut plan, &toc.entries, i, Some(blob_size), max_chunk)?;
        plan.planned += e.size - (plan.zeros - zeros);
        if plan.planned > cap {
            return Err(unsupported("the files to fetch are too big for the layer"));
        }
    }
    Ok(plan)
}

/// Group the chunks that need the network in ranges and batches.
#[derive(Clone)]
pub struct Batch {
    pub ranges: Vec<Range<u64>>,
    /// For each range, the chunks it holds, in order.
    pub members: Vec<Vec<usize>>,
}

/// What of a batch has not arrived: its chunks that are not `claimed`, each
/// range (`comp` is the compressed range of a chunk) from its first such
/// chunk to its last.  None when all are.
pub(crate) fn unclaimed(
    b: &Batch,
    comp: impl Fn(usize) -> Range<u64>,
    claimed: impl Fn(usize) -> bool,
) -> Option<Batch> {
    let mut rest = Batch {
        ranges: Vec::new(),
        members: Vec::new(),
    };
    for m in &b.members {
        let left: Vec<usize> = m.iter().copied().filter(|&i| !claimed(i)).collect();
        let (Some(&first), Some(&last)) = (left.first(), left.last()) else {
            continue;
        };
        rest.ranges.push(comp(first).start..comp(last).end);
        rest.members.push(left);
    }
    (!rest.ranges.is_empty()).then_some(rest)
}

/// What a request for the ranges of a blob is given: the tries of `fetch`
/// for a batch.  A server that takes fewer ranges than the batch has is
/// asked half of them, and the limit is remembered for `host`; what arrived
/// before an error (the chunks `claimed`) is not asked again, and the
/// request is tried [`RETRIES`] times in a row that brought nothing, unless
/// `stopped` says the pull is over.  A server that answers with the whole
/// blob ([`RangesError::WholeBlob`]) is for the caller to ask once, whole.
pub async fn fetch_with_tries<F, Fut>(
    batch: Batch,
    host: &str,
    digest: &(dyn std::fmt::Display + Sync),
    comp: impl Fn(usize) -> Range<u64>,
    claimed: impl Fn(usize) -> bool,
    stopped: impl Fn() -> bool,
    mut fetch: F,
) -> Result<(), crate::pull::ranges::RangesError>
where
    Fut: std::future::Future<Output = Result<(), crate::pull::ranges::RangesError>>,
    F: FnMut(Batch) -> Fut,
{
    use crate::pull::ranges::{self, RangesError};
    // (each batch with the tries in a row that brought nothing)
    let mut work: std::collections::VecDeque<(Batch, usize)> =
        std::collections::VecDeque::from([(batch, 0)]);
    while let Some((b, failed)) = work.pop_front() {
        match fetch(b.clone()).await {
            Ok(()) => {}
            Err(RangesError::Rejected(status)) => {
                if b.ranges.len() == 1 {
                    return Err(RangesError::Other(ImageError::transfer(
                        "registry",
                        FailureClass::Unavailable,
                        format!("the registry refuses range requests: {status}"),
                    )));
                }
                let mid = b.ranges.len() / 2;
                ranges::lower_limit(host, mid);
                let (mut ranges, mut members) = (b.ranges, b.members);
                let rest = Batch {
                    ranges: ranges.split_off(mid),
                    members: members.split_off(mid),
                };
                work.push_front((rest, failed));
                work.push_front((Batch { ranges, members }, failed));
            }
            Err(RangesError::WholeBlob) => return Err(RangesError::WholeBlob),
            Err(RangesError::Other(e)) => {
                let Some(rest) = unclaimed(&b, &comp, &claimed) else {
                    continue;
                };
                let failed = if rest.chunks() < b.chunks() {
                    1
                } else {
                    failed + 1
                };
                if failed >= RETRIES || stopped() {
                    return Err(RangesError::Other(e));
                }
                debug!("Retrying a range request of {digest}: {e}");
                work.push_front((rest, failed));
            }
        }
    }
    Ok(())
}

impl Batch {
    pub(crate) fn bytes(&self) -> u64 {
        self.ranges.iter().map(|r| r.end - r.start).sum()
    }

    pub(crate) fn chunks(&self) -> usize {
        self.members.iter().map(Vec::len).sum()
    }
}

/// The requests of the chunks `remote`: their ranges merged by cost
/// ([`super::merge`]), then in batches of about the same size within the
/// limits of a request, those the registry taught us included (`learnt`).
pub fn make_batches(
    chunks: &[Range<u64>],
    remote: &[usize],
    concurrency: usize,
    learnt: Learnt,
) -> Vec<Batch> {
    let mut order: Vec<usize> = remote.to_vec();
    order.sort_by_key(|&i| (chunks[i].start, i));
    if order.is_empty() {
        return Vec::new();
    }
    let per_request = learnt
        .per_request
        .unwrap_or(MAX_RANGES_PER_REQUEST)
        .clamp(1, MAX_RANGES_PER_REQUEST);

    let comps: Vec<Range<u64>> = order.iter().map(|&i| chunks[i].clone()).collect();
    let policy = super::merge::Policy {
        request_cost: super::merge::REQUEST_COST,
        per_request,
        parallel: concurrency.max(1),
        min_batch: MIN_BATCH_BYTES,
    };
    let mut ranges: Vec<(Range<u64>, Vec<usize>)> = Vec::new();
    match super::merge::merge(&comps, &policy) {
        Ok((merged, map)) => {
            ranges = merged.into_iter().map(|r| (r, Vec::new())).collect();
            for (k, &i) in order.iter().enumerate() {
                ranges[map[k]].1.push(i);
            }
        }
        // chunks that overlap (a TOC that says so): each on its own, as
        // before; the request refuses them
        Err(e) => {
            debug!("The ranges are not merged: {e:?}");
            for i in order {
                ranges.push((chunks[i].clone(), vec![i]));
            }
        }
    }

    let total: u64 = ranges.iter().map(|(r, _)| r.end - r.start).sum();
    let target = (total / (concurrency.max(1) as u64 * 2)).clamp(MIN_BATCH_BYTES, MAX_BATCH_BYTES);
    let mut batches: Vec<Batch> = Vec::new();
    let mut cur = Batch {
        ranges: Vec::new(),
        members: Vec::new(),
    };
    let mut header = "bytes=".len();
    for (r, m) in ranges {
        let item = format!("{}-{},", r.start, r.end - 1).len();
        if !cur.ranges.is_empty()
            && (cur.bytes() >= target
                || cur.ranges.len() >= per_request
                || header + item > MAX_RANGE_HEADER)
        {
            batches.push(std::mem::replace(
                &mut cur,
                Batch {
                    ranges: Vec::new(),
                    members: Vec::new(),
                },
            ));
            header = "bytes=".len();
        }
        header += item;
        cur.ranges.push(r);
        cur.members.push(m);
    }
    if !cur.ranges.is_empty() {
        batches.push(cur);
    }
    batches
}

struct Opened {
    name: String,
    size: u64,
    digest: String,
    /// The copy of the file the engine made when the fetcher handed it over
    /// (the first time the file is opened): the replay reads the copy,
    /// which no one but the engine holds, and the commit links it
    copy: Option<(PathBuf, String)>,
    /// The content of the file was hashed as it was copied and is the
    /// digest it is known by: the replay does not hash it again
    verified: bool,
}

/// A file a fetcher handed over, as the engine holds it: where, its size,
/// and the fs-verity digest of its blocks.
pub(crate) struct Copied {
    path: PathBuf,
    size: u64,
    verity: String,
}

/// The fs-verity digest of a file being copied: of a long one, hashed beside
/// the copy.
enum Merkle {
    Here(velarx_storage::VerityHasher),
    Beside(Offloaded<velarx_storage::VerityHasher>),
}

impl Merkle {
    fn new(alg: Algorithm, size: u64) -> Self {
        let hasher = velarx_storage::VerityHasher::new(alg);
        match size >= OFFLOAD_FROM {
            true => Self::Beside(Offloaded::new(hasher)),
            false => Self::Here(hasher),
        }
    }

    fn update(&mut self, data: &[u8]) {
        match self {
            Self::Here(h) => h.update(data),
            Self::Beside(h) => h.update(data),
        }
    }

    fn finish(self) -> String {
        match self {
            Self::Here(h) => h.finish(),
            Self::Beside(h) => h.finish().finish(),
        }
    }
}

/// The files a fetcher hands over while it unpacks a layer, taken in as they
/// come by as many threads as the pull has workers, so that they are ready
/// when the replay needs them.  A fetcher may hold another descriptor of what
/// it hands over, so a file the kernel does not measure is copied, the
/// content and the fs-verity digest hashed as it is written, and each file is
/// known by the digest of the bytes the engine read: what the fetcher says of
/// it is not asked.
pub struct Intake {
    to: Arc<CopiesTo>,
    alg: Algorithm,
    /// The files in the making: one permit for each thread
    room: Arc<tokio::sync::Semaphore>,
    threads: u32,
    taken: Arc<Mutex<Taken>>,
}

#[derive(Default)]
struct Taken {
    files: HashMap<String, Copied>,
    failed: Option<io::Error>,
}

impl Intake {
    /// The intake of the files of a layer whose blob is named in `alg`, for
    /// `threads` at a time, copied to temporary files of `sink`.
    pub fn new(sink: Arc<dyn super::sink::Sink>, alg: Algorithm, threads: usize) -> Self {
        Self::to(CopiesTo::Sink(sink), alg, threads)
    }

    /// [`Intake::new`] with the copies made in `dir`, a directory of the
    /// engine's: for a sink whose files are a storage driver's.
    pub fn in_dir(dir: PathBuf, alg: Algorithm, threads: usize) -> Self {
        Self::to(CopiesTo::Dir(dir, AtomicU64::new(0)), alg, threads)
    }

    fn to(to: CopiesTo, alg: Algorithm, threads: usize) -> Self {
        let threads = u32::try_from(threads.max(1)).unwrap_or(u32::MAX >> 4);
        Self {
            to: Arc::new(to),
            alg,
            room: Arc::new(tokio::sync::Semaphore::new(threads as usize)),
            threads,
            taken: Arc::default(),
        }
    }

    /// Take in `file`, as soon as a thread is free.  The error of a file that
    /// could not be taken in, which the files before it had.
    pub async fn give(&self, file: File) -> io::Result<()> {
        if let Some(e) = self.lock().failed.take() {
            return Err(e);
        }
        let permit = self
            .room
            .clone()
            .acquire_owned()
            .await
            .map_err(io::Error::other)?;
        let (to, alg, taken) = (self.to.clone(), self.alg, self.taken.clone());
        tokio::task::spawn_blocking(move || {
            let made = take_in(file, alg, &to, true);
            let mut taken = taken.lock().unwrap_or_else(|e| e.into_inner());
            match made {
                Ok((Some(key), copy)) => match taken.files.entry(key) {
                    std::collections::hash_map::Entry::Vacant(v) => {
                        v.insert(copy);
                    }
                    // (the content is held: this one is one file too many)
                    std::collections::hash_map::Entry::Occupied(_) => {
                        let _ = std::fs::remove_file(&copy.path);
                    }
                },
                Ok((None, _)) => unreachable!("the content was asked for"),
                Err(e) => {
                    taken.failed.get_or_insert(e);
                }
            }
            drop(permit);
        });
        Ok(())
    }

    /// The files taken in, by the digest of their content, once every file
    /// handed over is.
    pub(crate) async fn finish(&self) -> io::Result<HashMap<String, Copied>> {
        let _all = self
            .room
            .acquire_many(self.threads)
            .await
            .map_err(io::Error::other)?;
        let mut taken = self.lock();
        match taken.failed.take() {
            Some(e) => Err(e),
            None => Ok(std::mem::take(&mut taken.files)),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Taken> {
        self.taken.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// Where an intake makes its copies.
enum CopiesTo {
    /// Temporary files of the sink
    Sink(Arc<dyn super::sink::Sink>),
    /// Files of a directory of the engine's, numbered
    Dir(PathBuf, AtomicU64),
}

impl CopiesTo {
    fn create_temp(&self) -> io::Result<(File, PathBuf)> {
        match self {
            Self::Sink(sink) => match sink.create_temp()? {
                (file, Some(path)) => Ok((file, path)),
                (_, None) => Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "the files of this sink have no names",
                )),
            },
            Self::Dir(dir, n) => {
                use std::os::unix::fs::OpenOptionsExt;
                let path = dir.join(n.fetch_add(1, Ordering::Relaxed).to_string());
                let file = std::fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                    .open(&path)?;
                Ok((file, path))
            }
        }
    }

    fn link_temp(&self, file: &File) -> io::Result<PathBuf> {
        match self {
            Self::Sink(sink) => sink.link_temp(file),
            Self::Dir(dir, n) => {
                let path = dir.join(n.fetch_add(1, Ordering::Relaxed).to_string());
                super::session::link_unnamed(file, &path)?;
                Ok(path)
            }
        }
    }
}

/// Take in the file `file` a fetcher handed over: where the engine holds it
/// and, when `content` asks for it, the digest of its content in `alg`.  A
/// file the kernel measures cannot change: it is linked, and read only for
/// the digest of its content; any other is copied to a file of `to`, and its
/// digests are those of the bytes written.  Anything but a regular file (a
/// pipe would block the read, a device has no end) is the fetcher's error.
fn take_in(
    file: File,
    alg: Algorithm,
    to: &CopiesTo,
    content: bool,
) -> io::Result<(Option<String>, Copied)> {
    let meta = file.metadata()?;
    if !meta.file_type().is_file() {
        return Err(io::Error::other("a handed file is not a regular file"));
    }
    let size = meta.len();
    let mut hash = content.then(|| match size >= OFFLOAD_FROM {
        true => Content::Beside(Offloaded::new(DigestWriter::new(alg))),
        false => Content::Here(DigestWriter::new(alg)),
    });
    let mut from = Read::take(FromStart { file: &file, at: 0 }, size + 1);
    if let Some(verity) = super::commit::measure(&file, alg) {
        let path = to.link_temp(&file)?;
        let size = match &mut hash {
            Some(h) => io::copy(&mut from, h)?,
            None => size,
        };
        let content = hash.map(|h| h.finalize().to_string());
        return Ok((content, Copied { path, size, verity }));
    }
    let (to, path) = to.create_temp()?;
    let mut verity = Merkle::new(alg, size);
    let copied = velarx_storage::copy_sparse(from, &to, |piece| {
        verity.update(piece);
        if let Some(h) = &mut hash {
            h.update(piece);
        }
    });
    // (the disk starts on it now, not on all of them at the barrier of the
    // commit)
    super::session::start_writeback(&to);
    match copied {
        Ok(size) => Ok((
            hash.map(|h| h.finalize().to_string()),
            Copied {
                path,
                size,
                verity: verity.finish(),
            },
        )),
        Err(e) => {
            let _ = std::fs::remove_file(&path);
            Err(e)
        }
    }
}

/// Take in the file `file`, which a fetcher handed over as the file `key` of
/// a layer (`name` in the layer, when the table gives it): it is copied to a
/// file of `sink` and must be what `key` names (its fs-verity digest, or the
/// hash of its content: only the digest that `key` is one of is computed);
/// the sink then knows it by the digest it computed.
pub(crate) fn take_handed(
    file: File,
    (key, name): (&str, Option<&str>),
    sink: &Arc<dyn super::sink::Sink>,
) -> ImageResult<()> {
    let want = Digest::parse_key(key)
        .map_err(|_| ImageError::Layer(format!("{key} is not the digest of a file")))?;
    let (content, copied) = take_in(
        file,
        want.alg(),
        &CopiesTo::Sink(sink.clone()),
        !want.is_fsverity(),
    )
    .map_err(io_fail)?;
    let (read, kind) = match &content {
        Some(content) => (content, "content digest"),
        None => (&copied.verity, "fs-verity digest"),
    };
    if read != key {
        let _ = std::fs::remove_file(&copied.path);
        return Err(ImageError::Contradicted(format!(
            "`{}` is not the {kind} of its name {key}",
            name.unwrap_or(key)
        )));
    }
    sink.adopt_measured(&copied.path, key, &copied.verity, copied.size)?;
    Ok(())
}

/// A file a fetcher handed over, read from its start at positions of its own:
/// the offset of the descriptor is the fetcher's too, which could move it
/// while the engine reads, and a file of fs-verity, which is linked, would be
/// known by the digest of its bytes in another order.
struct FromStart<'a> {
    file: &'a File,
    at: u64,
}

impl Read for FromStart<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = std::os::unix::fs::FileExt::read_at(self.file, buf, self.at)?;
        self.at += n as u64;
        Ok(n)
    }
}

/// The files of a replay that say which one they opened last: the replay
/// takes it once it read its content, to check it against the archive.
trait Opens: Contents {
    /// The file opened last, not taken yet.
    fn opened(&mut self) -> &mut Option<Opened>;
}

pub(crate) struct Replayed {
    pub diff_id: Digest,
    pub entries: Vec<TocEntry>,
    pub files: Vec<FileUse>,
    /// The files the fetcher handed over, which the engine took in before
    /// the replay read them: by their key, the copy, its size and its
    /// fs-verity digest
    pub copies: HashMap<String, (PathBuf, u64, String)>,
}

/// The stream of a replay, hashed beside the replay: its diff id.
struct Streamed<T> {
    inner: T,
    hasher: Offloaded<DigestWriter>,
}

impl<R: Read> Read for Streamed<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.hasher.update(&buf[..n]);
        Ok(n)
    }
}

/// The size from which the hash of a file is made on a thread of its own: a
/// thread costs more than the hash of a small file, and a layer has thousands.
const OFFLOAD_FROM: u64 = 1 << 20;

/// The hash of the content of one file of a replay.
enum Content {
    Here(DigestWriter),
    Beside(Offloaded<DigestWriter>),
}

impl Content {
    fn update(&mut self, data: &[u8]) {
        match self {
            Self::Here(h) => h.update(data),
            Self::Beside(h) => h.update(data),
        }
    }

    fn finalize(self) -> Digest {
        match self {
            Self::Here(h) => h.finalize(),
            Self::Beside(h) => h.finish().finalize(),
        }
    }
}

impl io::Write for Content {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.update(data);
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// The size of the pieces a file too big to be asked of a peer whole is cut
/// in, for a layer that has no table of contents: a peer that has the layer
/// has the file by them.
const PIECE: u64 = 4 << 20;

/// The digests of the pieces of a file, as its content is read.
struct Pieces {
    alg: Algorithm,
    hasher: DigestWriter,
    filled: u64,
    done: Vec<(u64, Digest)>,
}

impl Pieces {
    fn new(alg: Algorithm) -> Self {
        Self {
            alg,
            hasher: DigestWriter::new(alg),
            filled: 0,
            done: Vec::new(),
        }
    }

    fn update(&mut self, mut data: &[u8]) {
        while !data.is_empty() {
            let (now, rest) = data.split_at(data.len().min((PIECE - self.filled) as usize));
            self.hasher.update(now);
            self.filled += now.len() as u64;
            data = rest;
            if self.filled == PIECE {
                self.close();
            }
        }
    }

    fn close(&mut self) {
        let hasher = std::mem::replace(&mut self.hasher, DigestWriter::new(self.alg));
        self.done
            .push((std::mem::take(&mut self.filled), hasher.finalize()));
    }

    /// The pieces, in order, with their sizes.
    fn finish(mut self) -> Vec<(u64, Digest)> {
        if self.filled > 0 {
            self.close();
        }
        self.done
    }
}

impl velarx_types::digest::Absorb for Pieces {
    fn absorb(&mut self, data: &[u8]) {
        self.update(data);
    }
}

/// Cut the entry of a file in `pieces`: the first is the file's own chunk,
/// and the entries that follow it are the others, as a table of contents
/// has the chunks of a file.
fn cut(file: &mut TocEntry, pieces: Vec<(u64, Digest)>) -> Vec<TocEntry> {
    let mut pieces = pieces.into_iter();
    if let Some((size, digest)) = pieces.next() {
        file.chunk_size = size;
        file.chunk_digest = Some(digest.to_string());
    }
    let mut offset = file.chunk_size;
    pieces
        .map(|(size, digest)| {
            let chunk = TocEntry {
                chunk_digest: Some(digest.to_string()),
                chunk_size: size,
                chunk_offset: offset,
                ..TocEntry::new(file.name.clone(), TocEntryType::Chunk)
            };
            offset += size;
            chunk
        })
        .collect()
}

/// Replay a tar-split over the files of `source`: the table of contents is
/// a fetcher's claim (of a layer it unpacked), not one the descriptor names:
/// the content of each file is hashed here and must be the digest the claim
/// names it by, and the table is what the verified headers and those hashes
/// say.
fn replay_of(
    input: impl BufRead + Send,
    source: impl Opens,
    alg: Algorithm,
    diff_alg: Algorithm,
) -> ImageResult<Replayed> {
    let stream = Streamed {
        inner: Replay::new(Entries::new(input), source),
        hasher: Offloaded::new(DigestWriter::new(diff_alg)),
    };
    let mut tar = TarReader::new(stream);
    let mut buf = vec![0u8; 1 << 20];
    let mut entries = Vec::new();
    let mut files = Vec::new();
    let mut copies = HashMap::new();
    while let Some(h) = tar.next_entry().map_err(data_fail)? {
        if entries.len() >= MAX_ENTRIES {
            return Err(fail("the layer has too many entries"));
        }
        let mut cut_in = None;
        let digest = if h.kind == Kind::Regular {
            if h.size == 0 {
                Some(Digest::empty(alg).to_string())
            } else {
                // (nothing is open yet: the first read below opens this
                // file, so a file whose copy was verified is all the bytes
                // whose hash is skipped)
                if tar.get_mut().inner.contents_mut().opened().is_some() {
                    return Err(fail("tar-split does not match the archive"));
                }
                // Large reads: the files are read again from the disk
                // (the page cache), a syscall and a hash call per piece.
                let mut left = h.size;
                // (the hash of a long file runs beside the read of it; a
                // file that was hashed as it was copied is not hashed again)
                let mut content = None;
                // (and so do the pieces of a file too big to be served whole)
                let mut pieces = (h.size > velarx_storage::MAX_SERVED_BYTES as u64)
                    .then(|| Offloaded::new(Pieces::new(alg)));
                while left > 0 {
                    let want = buf.len().min(usize::try_from(left).unwrap_or(usize::MAX));
                    let n = tar.read(&mut buf[..want]).map_err(io_fail)?;
                    if n == 0 {
                        return Err(fail("the archive ends in a file"));
                    }
                    if left == h.size {
                        let verified = tar
                            .get_mut()
                            .inner
                            .contents_mut()
                            .opened()
                            .as_ref()
                            .is_some_and(|o| o.verified);
                        content = (!verified).then(|| match h.size >= OFFLOAD_FROM {
                            true => Content::Beside(Offloaded::new(DigestWriter::new(alg))),
                            false => Content::Here(DigestWriter::new(alg)),
                        });
                    }
                    if let Some(c) = &mut content {
                        c.update(&buf[..n]);
                    }
                    if let Some(p) = &mut pieces {
                        p.update(&buf[..n]);
                    }
                    left -= n as u64;
                }
                cut_in = pieces.map(|p| p.finish().finish());
                let mut opened = tar
                    .get_mut()
                    .inner
                    .contents_mut()
                    .opened()
                    .take()
                    .ok_or_else(|| fail("tar-split does not match the archive"))?;
                let path = normalize_path(&h.path).unwrap_or_default();
                if opened.name != path || opened.size != h.size {
                    return Err(fail(format!(
                        "the tar-split file entry `{}` does not match the archive entry `{path}`",
                        opened.name
                    )));
                }
                // (every file is the digest of its content it is known by,
                // never an object: the object the store gave for it is the
                // pull's to name)
                if Digest::parse_fsverity(&opened.digest).is_ok() {
                    return Err(ImageError::Contradicted(format!(
                        "`{path}` is known by {}, which is no digest of a content",
                        opened.digest
                    )));
                }
                let read = match content {
                    Some(c) => c.finalize().to_string(),
                    None => opened.digest.clone(),
                };
                if read != opened.digest {
                    return Err(ImageError::Contradicted(format!(
                        "`{path}` is {read}, not the {} the fetcher said",
                        opened.digest
                    )));
                }
                if let Some((path, verity)) = opened.copy.take() {
                    copies.insert(opened.digest.clone(), (path, h.size, verity));
                }
                files.push(FileUse {
                    digest: opened.digest.clone(),
                    size: h.size,
                });
                Some(read)
            }
        } else {
            None
        };
        let mut e = entry::from_header(&h, digest.as_deref()).map_err(data_fail)?;
        let chunks = cut_in.map(|pieces| cut(&mut e, pieces));
        entries.push(e);
        entries.extend(chunks.into_iter().flatten());
    }
    let mut rest = tar.into_inner();
    io::copy(&mut rest, &mut io::sink()).map_err(io_fail)?;
    if rest.inner.contents_mut().opened().is_some() {
        return Err(fail("tar-split has files the archive does not"));
    }
    Ok(Replayed {
        diff_id: rest.hasher.finish().finalize(),
        entries,
        files,
        copies,
    })
}

/// Pull a zstd:chunked layer by its table of contents, whose descriptor
/// vouches for it: the metadata of the layer is the table's, every file is
/// checked against it, and the layer is never pulled another way.  Whatever
/// fails is an error that names the layer: bytes that are not what the
/// descriptor vouches for, a table the layer or the configuration
/// contradicts, a registry that gives no range of the blob.  (A registry
/// that cannot serve ranges gives the blob whole, as the transport of
/// the ranges: the files are still those of the table.)
pub async fn pull(
    ctx: &PullCtx,
    target: &Target,
    layer: &OciDescriptor,
    info: &Info,
    expected_diff_id: &Digest,
    progress: impl Fn(u64) + Send + Sync + 'static,
) -> ImageResult<Pulled> {
    pull_by_table(ctx, target, layer, info, expected_diff_id, progress)
        .await
        .map_err(|e| naming(&layer.digest, e))
}

async fn pull_by_table(
    ctx: &PullCtx,
    target: &Target,
    layer: &OciDescriptor,
    info: &Info,
    expected_diff_id: &Digest,
    progress: impl Fn(u64) + Send + Sync + 'static,
) -> ImageResult<Pulled> {
    let started = std::time::Instant::now();
    // (what a fetcher found is verified below, as what the registry gives
    // is)
    let (toc_z, ts_z) = metadata(ctx, layer).await?;
    debug!(
        "Layer {}: metadata fetched after {:?}",
        layer.digest,
        started.elapsed()
    );
    let metadata_bytes = (toc_z.len() + ts_z.len()) as u64;
    let meta = verified(
        info,
        toc_z,
        ts_z,
        layer.digest,
        ctx.limits.max_layer_bytes,
        false,
    )
    .await?;

    debug!(
        "Layer {}: metadata verified after {:?}",
        layer.digest,
        started.elapsed()
    );
    complete_layer(
        ctx,
        Some(target),
        layer,
        meta,
        metadata_bytes,
        expected_diff_id,
        progress,
    )
    .await
}

/// Fetch what the store lacks of a layer whose metadata is known and check
/// the layer against `expected_diff_id` by replaying its tar-split.  This is
/// what ends a lazy pull too: the files fetched on demand are in the store.
pub async fn complete_layer(
    ctx: &PullCtx,
    target: Option<&Target>,
    layer: &OciDescriptor,
    meta: Metadata,
    metadata_bytes: u64,
    expected_diff_id: &Digest,
    progress: impl Fn(u64) + Send + Sync + 'static,
) -> ImageResult<Pulled> {
    let started = std::time::Instant::now();
    // The files the store lacks are brought by the fetcher into
    // the layer's staging and given to the session: the plan then finds
    // them there, and the replay checks them with the rest.
    let mut metadata_bytes = metadata_bytes;
    // (a sink of the engine's store takes the files as they are; the files
    // of a storage driver are copied to their places and measured there)
    let staged_sink = !ctx.sink.proves_in_fetch() || ctx.sink.clone().session().is_some();
    let mut ctx = std::borrow::Cow::Borrowed(ctx);
    let mut sourced = super::staged_fetch::Walked::default();
    let mut staged_files = (0u64, 0u64);
    if let (Some(staged), Some(_), true) = (&ctx.staged, target, staged_sink) {
        // (an eager pull holds the lease of the layer since before its plan of
        // what the store has, so that another engine that pulled it is
        // waited for; a lazy pull holds none: the staging it keeps is the
        // lazy pull's)
        let staging = staged.open_layer(layer).await?;
        // (the plan of the files the store lacks, with its checks of the
        // table: what the fetcher is asked for)
        let alg = LayerKey::expected(layer).digest().alg();
        let plan = plan_blocking(
            ctx.have_fn(),
            meta.toc.clone(),
            alg,
            layer.size,
            &ctx.limits,
        )
        .await?;
        let keys: Vec<String> = plan.jobs.iter().map(|j| j.digest.clone()).collect();
        if !keys.is_empty() {
            // (a file another layer of the pull fetches is waited for, not
            // asked for again; what that layer failed to bring is fetched
            // here)
            let (claim, theirs) = ctx.fetching.claim(keys.clone());
            // (what the fetchers stage for this layer is fetched, not
            // reused: the plan of the check below finds it there)
            let mine: HashSet<&str> = claim.keys().iter().map(String::as_str).collect();
            staged_files = (
                mine.len() as u64,
                plan.chunks
                    .iter()
                    .filter(|c| mine.contains(plan.jobs[c.job].digest.as_str()))
                    .map(|c| c.comp.end - c.comp.start)
                    .sum(),
            );
            drop(mine);
            if !claim.keys().is_empty() {
                let reuse = reuse_hints(&ctx, &plan, staging.dir()).await?;
                sourced = staged
                    .fetch_files(
                        &staging,
                        layer,
                        &meta.toc,
                        (claim.keys().to_vec(), &reuse),
                        (&ctx.sink, &ctx.workers),
                        &progress,
                    )
                    .await?;
            }
            claim.done();
            let mut left = Vec::new();
            for (key, rx) in theirs {
                if !super::fetched_by_another(rx).await {
                    left.push(key);
                }
            }
            if !left.is_empty() {
                staged_files.0 += left.len() as u64;
                let more = staged
                    .fetch_files(
                        &staging,
                        layer,
                        &meta.toc,
                        (left, &Default::default()),
                        (&ctx.sink, &ctx.workers),
                        &progress,
                    )
                    .await?;
                sourced.add(more);
            }
            metadata_bytes += sourced.bytes;
            // (what was given is there: the plan of the check fetches
            // nothing more; of a session, only what it holds of the size
            // this table gives: what another layer fetched under the same
            // key may be another size)
            let (have, given) = (ctx.have_fn(), keys.into_iter().collect::<HashSet<_>>());
            let had: super::Have = match ctx.sink.clone().session() {
                Some(session) => Arc::new(move |key: &str, size| session.holds(key, size)),
                None => Arc::new(move |key: &str, size| given.contains(key) || have(key, size)),
            };
            ctx = std::borrow::Cow::Owned(ctx.into_owned().with_have(had));
        }
    }
    let verified = verify_layer(
        &ctx,
        layer,
        meta,
        (metadata_bytes, started),
        expected_diff_id,
    )
    .await;
    // (the layer's staging goes with this call: its fetchers forget it)
    if let (Some(staged), Some(_), true) = (&ctx.staged, target, staged_sink) {
        staged.forget(&layer.digest.to_string()).await;
    }
    let mut pulled = verified?;
    // (what the fetchers but the registry fetcher staged)
    for s in std::mem::take(&mut sourced.sources) {
        pulled.report.sources.push(s);
    }
    let report = &mut pulled.report;
    report.fetched_files += staged_files.0;
    report.reused_files = report.reused_files.saturating_sub(staged_files.0);
    report.reused_bytes = report.reused_bytes.saturating_sub(staged_files.1);
    Ok(pulled)
}

/// Pull `layer`, which has no table of contents: from the index of the
/// sources and the files the store lacks ([`unpack_by_index`]; when the
/// index does not replay, once more from the index of another source), else
/// from the origin ([`unpack_whole`]); give the files the replay used to the
/// session: those the store has are not taken again.  Also whether the
/// layer was not from the origin, whose workers hashed the blob.
/// `registry_only`: only the origin is asked (the store has a layer of the
/// blob for another diff id: the blob, hashed, says which is right).
pub async fn pull_whole(
    ctx: &PullCtx,
    registry_only: bool,
    layer: &OciDescriptor,
    expected_diff_id: &Digest,
    progress: impl Fn(u64) + Send + Sync + 'static,
) -> ImageResult<(Pulled, bool)> {
    no_table(layer)?;
    let mut by_index = None;
    for again in [false, true].into_iter().filter(|_| !registry_only) {
        match unpack_by_index(ctx, layer, expected_diff_id, again, &progress).await {
            Ok(unpacked) => {
                by_index = unpacked;
                break;
            }
            // (a failure of this end is no reason to pass over the source
            // of the index: the origin is asked)
            Err(e) if of_this_end(&e) => {
                debug!("Layer {}: not from its sources: {e}", layer.digest);
                break;
            }
            Err(e) => debug!("Layer {}: not from its sources: {e}", layer.digest),
        }
    }
    let by_registry = by_index.is_none();
    let unpacked = match by_index {
        Some(unpacked) => unpacked,
        None => unpack_whole(ctx, layer, expected_diff_id, progress).await?,
    };
    let Unpacked { mut ingested, .. } = unpacked;
    let sink = ctx.sink.clone();
    let files: Vec<String> = ingested.files.iter().map(|f| f.digest.clone()).collect();
    let stored = std::mem::take(&mut ingested.stored);
    let mut copies = std::mem::take(&mut ingested.copies);
    let (objects, kept, reused) = tokio::task::spawn_blocking(move || {
        let (mut objects, mut kept, mut reused) = (HashMap::new(), 0u64, 0u64);
        for key in files {
            // (a file of two names counts once more, as the store's)
            if objects.contains_key(&key) {
                reused += 1;
                continue;
            }
            if let Some(object) = stored.get(&key) {
                objects.insert(key, Some(object.clone()));
                reused += 1;
                continue;
            }
            // (the engine took in the file when it was handed over: the file
            // is what it holds, and it is already named by what it computed)
            let Some((path, size, verity)) = copies.remove(&key) else {
                return Err(ImageError::Layer(format!("{key} was not handed over")));
            };
            let (known, added) = sink.adopt_measured(&path, &key, &verity, size)?;
            match (known == key, added) {
                (true, true) => {
                    kept += 1;
                    objects.insert(key, None);
                }
                (true, false) => {
                    reused += 1;
                    objects.insert(key, None);
                }
                // (the sink has the object: the file is its one)
                (false, _) => {
                    reused += 1;
                    objects.insert(key, Some(known));
                }
            }
        }
        Ok::<_, ImageError>((objects, kept, reused))
    })
    .await
    .map_err(|e| fail(format!("the files of a layer: {e}")))??;
    if let Some(staged) = &ctx.staged {
        staged.forget(&layer.digest.to_string()).await;
    }
    // (a file the store has is its object)
    let mut toc = Arc::unwrap_or_clone(ingested.toc);
    for e in &mut toc.entries {
        if let Some(Some(object)) = e.digest.as_ref().and_then(|d| objects.get(d)) {
            e.fsverity = velarx_storage::to_toc(object);
        }
    }
    // (and the files of the layer it has are known by their object)
    let mut files = ingested.files;
    for f in &mut files {
        if let Some(Some(object)) = objects.get(&f.digest) {
            f.digest = object.clone();
        }
    }
    // (the pieces of the big files, where a peer finds them)
    let chunks = located_chunks_where(&toc, |i| {
        toc.entries[i].size > velarx_storage::MAX_SERVED_BYTES as u64
    });
    let mut report = ingested.report;
    report.fetched_files = kept + ingested.fetched;
    report.reused_files = reused.saturating_sub(ingested.fetched);
    Ok((
        Pulled {
            toc,
            files,
            chunks,
            report,
            diff_id: ingested.diff_id,
            tarsplit: ingested.tarsplit,
            toc_z: None,
        },
        by_registry,
    ))
}

/// A layer with no table of contents, checked: the stream recreated from
/// the tar-split and the files hashes to the diff id, each file is the
/// digest it is known by, and the table of contents is what the verified
/// headers say.
pub struct Unpacked {
    pub ingested: Whole,
    /// The staging of the layer: the copies of a sink with no files of the
    /// engine's are in it, and last as long as it does
    pub staging: Arc<super::staged_fetch::LayerStaging>,
}

/// A layer read whole and checked ([`Unpacked`]).
pub struct Whole {
    pub toc: Arc<Toc>,
    pub files: Vec<FileUse>,
    pub report: LayerReport,
    pub diff_id: Digest,
    pub tarsplit: bytes::Bytes,
    /// The files the origin handed over, as the engine holds them
    /// ([`Replayed::copies`])
    pub copies: HashMap<String, (PathBuf, u64, String)>,
    /// The files the replay read from the store or the pull's session, by
    /// their key: the object each is
    pub stored: HashMap<String, String>,
    /// Those of `stored` that the sources brought
    pub fetched: u64,
}

/// An error unless `layer` is one without a table of contents: the only
/// layers that are read as a tar stream.  The stream of a layer with a table
/// may describe another filesystem than the table the manifest vouches for.
pub fn no_table(layer: &OciDescriptor) -> ImageResult<()> {
    match parse_info(layer)? {
        Some(_) => Err(ImageError::Contradicted(format!(
            "layer {}: it is zstd:chunked, which is pulled by its table of contents or not at all, and the source gives none",
            layer.digest
        ))),
        None => Ok(()),
    }
}

/// Pull `layer`, which has no table of contents, from the origin and
/// check it ([`Unpacked`]): it hands over every file.
pub async fn unpack_whole(
    ctx: &PullCtx,
    layer: &OciDescriptor,
    expected_diff_id: &Digest,
    progress: impl Fn(u64) + Send + Sync + 'static,
) -> ImageResult<Unpacked> {
    no_table(layer)?;
    let staged = ctx
        .staged
        .as_ref()
        .ok_or_else(|| fail("no fetcher for the layer"))?;
    let staging = staged.open_layer_as(LayerKey::Whole(layer.digest)).await?;
    let alg = LayerKey::expected(layer).digest().alg();
    // (a sink of a storage driver has no file of the engine's for a copy:
    // the copies are made in the staging of the layer, and go with it)
    let intake = match ctx.sink.clone().session() {
        Some(_) => Intake::new(ctx.sink.clone(), alg, ctx.limits.workers),
        None => {
            let dir = staging
                .path()
                .join(format!("copies-{}", velarx_base::random::token()));
            std::fs::create_dir(&dir)?;
            Intake::in_dir(dir, alg, ctx.limits.workers)
        }
    };
    let whole = match staged
        .fetch_whole(&staging, layer, &progress, &intake)
        .await
    {
        Ok(whole) => whole,
        Err(e) => {
            // (the files handed over until then are still being taken in)
            let _ = intake.finish().await;
            return Err(e);
        }
    };
    let tarsplit = bytes::Bytes::from(whole.tarsplit);
    let handed = intake.finish().await?;
    let (replayed, stored, toc) =
        replay_claim(whole.toc, (handed, None), &tarsplit, alg, expected_diff_id).await?;
    let fetched_files = replayed.files.len() as u64;
    let ingested = Whole {
        toc: Arc::new(toc),
        report: LayerReport {
            fetched_bytes: whole.bytes,
            fetched_files,
            ..LayerReport::default()
        },
        files: replayed.files,
        diff_id: replayed.diff_id,
        tarsplit,
        copies: replayed.copies,
        stored,
        fetched: 0,
    };
    Ok(Unpacked { ingested, staging })
}

/// Replay the claim `toc`: the stream recreated from `tarsplit` and the
/// files `handed` over or, with `store`, those of the pull's session and the
/// store by the object the claim says each is, which must hash to
/// `expected_diff_id`.  Also the files read from the store, by their key,
/// and the table of contents of the stream.
async fn replay_claim(
    mut toc: Toc,
    (handed, store): (HashMap<String, Copied>, Option<Arc<dyn super::sink::Sink>>),
    tarsplit: &bytes::Bytes,
    alg: Algorithm,
    expected_diff_id: &Digest,
) -> ImageResult<(Replayed, HashMap<String, String>, Toc)> {
    let (z, diff_alg) = (tarsplit.clone(), expected_diff_id.alg());
    let (mut replayed, stored, tar_split_digest) =
        tokio::task::spawn_blocking(move || -> ImageResult<_> {
            let store = store.map(|sink| {
                let hints = toc
                    .entries
                    .iter()
                    .filter_map(|e| Some((e.digest.clone()?, e.verity()?)))
                    .collect();
                (sink, hints)
            });
            for e in &mut toc.entries {
                e.fsverity = None;
            }
            let mut source = StagedFiles {
                index: tarsplit::content_index(&toc),
                store,
                handed,
                used: HashSet::new(),
                stored: HashMap::new(),
                last: None,
            };
            let input = tarsplit::decoder(z.clone(), MAX_TARSPLIT).map_err(data_fail)?;
            let replayed = replay_of(input, &mut source, alg, diff_alg)?;
            Ok((replayed, source.stored, Digest::of(alg, &z)))
        })
        .await
        .map_err(|e| fail(format!("the replay of the layer: {e}")))??;
    if replayed.diff_id != *expected_diff_id {
        return Err(ImageError::DigestMismatch {
            expected: expected_diff_id.to_string(),
            actual: replayed.diff_id.to_string(),
        });
    }
    let toc = Toc {
        version: TOC_VERSION,
        entries: std::mem::take(&mut replayed.entries),
        tar_split_digest: Some(tar_split_digest.to_string()),
    };
    Ok((replayed, stored, toc))
}

/// Whether `e` is a failure of this end (its disk, its store), not of what
/// the sources sent.
fn of_this_end(e: &ImageError) -> bool {
    match e {
        ImageError::Io(_) | ImageError::Storage(_) | ImageError::Database(_) => true,
        ImageError::Transfer { failure, .. } => failure.class == FailureClass::NoSpace,
        _ => false,
    }
}

/// Pull `layer`, which has no table of contents, from the index a source
/// gives for its blob (the table and tar-split another node recorded: a
/// claim) and the files of it the store lacks, which the sources before
/// the origin bring into a scratch area.  The stream recreated from the
/// tar-split and the files must hash to the diff id, each file to the
/// digest the claim gives it: nothing of the claim is named before that,
/// and a claim that is wrong is an error, for the origin.  None: no source
/// has an index.  `again`: the index the last call had was wrong.
async fn unpack_by_index(
    ctx: &PullCtx,
    layer: &OciDescriptor,
    expected_diff_id: &Digest,
    again: bool,
    progress: &(dyn Fn(u64) + Send + Sync),
) -> ImageResult<Option<Unpacked>> {
    let Some(staged) = ctx.staged.as_ref() else {
        return Ok(None);
    };
    let Some((toc_z, ts_z)) = staged.probe(layer, again).await? else {
        return Ok(None);
    };
    let (have, cap) = (ctx.have_fn(), ctx.limits.inflate_cap(layer.size));
    let json_cap = super::index::json_cap(layer.size);
    let (claimed, tarsplit, missing) = tokio::task::spawn_blocking(move || {
        let bad = |why: &str| ImageError::Contradicted(format!("the index of the layer: {why}"));
        let (toc, tarsplit) =
            super::index::decode_parts(&toc_z, ts_z, json_cap).map_err(|e| bad(&e))?;
        if toc.is_canonical() {
            return Err(bad("a canonical table has no tar-split to replay"));
        }
        if let Some(problem) = super::entry::toc_problem(&toc.entries) {
            return Err(bad(problem));
        }
        // (what the claim makes this pull fetch is bounded, before anything
        // is asked: by what a layer of this blob may inflate to), and the
        // files the store, the session of the pull and its parent lack
        let (mut total, mut seen, mut missing) = (0u64, HashSet::new(), Vec::new());
        for e in &toc.entries {
            if e.entry_type != TocEntryType::Reg || e.size == 0 {
                continue;
            }
            let (Some(_), Some(object)) = (&e.digest, e.verity()) else {
                return Err(bad("a file without its digests"));
            };
            total = total.saturating_add(e.size);
            if seen.insert(object.clone()) && !have(&object, e.size) {
                missing.push(object);
            }
        }
        if total > cap {
            return Err(bad("the files are larger than the layer may be"));
        }
        Ok((toc, tarsplit, missing))
    })
    .await
    .map_err(|e| fail(format!("planning the layer: {e}")))??;
    let staging = staged.open_layer_as(LayerKey::Whole(layer.digest)).await?;
    let scratch = ctx.sink.clone().scratch()?;
    let walked = match missing.is_empty() {
        true => Default::default(),
        false => {
            staged
                .fetch_from_sources(
                    &staging,
                    layer,
                    &claimed,
                    missing,
                    (&scratch, &ctx.workers),
                    progress,
                )
                .await?
        }
    };
    let alg = LayerKey::expected(layer).digest().alg();
    let tarsplit = bytes::Bytes::from(tarsplit);
    let (replayed, stored, toc) = replay_claim(
        claimed,
        (HashMap::new(), Some(scratch.clone())),
        &tarsplit,
        alg,
        expected_diff_id,
    )
    .await?;
    let (sink, objects) = (
        ctx.sink.clone(),
        stored.values().cloned().collect::<Vec<_>>(),
    );
    let moved = tokio::task::spawn_blocking(move || {
        let keep: HashSet<&str> = objects.iter().map(String::as_str).collect();
        scratch
            .transfer_into(&*sink, &keep)
            .map(|moved| moved.len() as u64)
    })
    .await
    .map_err(|e| fail(format!("the files of a layer: {e}")))??;
    let ingested = Whole {
        toc: Arc::new(toc),
        report: LayerReport {
            sources: walked.sources,
            ..LayerReport::default()
        },
        files: replayed.files,
        diff_id: replayed.diff_id,
        tarsplit,
        copies: HashMap::new(),
        stored,
        fetched: moved,
    };
    Ok(Some(Unpacked { ingested, staging }))
}

/// The files for a replay of a claim, by their key: those the origin handed
/// over, each read from the engine's own copy of it; with `store`, the others
/// from the pull's session (the sources' files are in a scratch area of it)
/// and the store, by the object the claim says each is (`stored`: those
/// taken so).
struct StagedFiles {
    index: ContentIndex,
    store: Option<(Arc<dyn super::sink::Sink>, HashMap<String, String>)>,
    /// What the intake holds, by the key of each file
    handed: HashMap<String, Copied>,
    /// The files opened, by their key (a file of two names is one copy)
    used: HashSet<String>,
    stored: HashMap<String, String>,
    last: Option<Opened>,
}

impl Opens for &mut StagedFiles {
    fn opened(&mut self) -> &mut Option<Opened> {
        &mut self.last
    }
}

impl Contents for &mut StagedFiles {
    fn open(&mut self, name: &str, size: u64) -> io::Result<Box<dyn Read + Send>> {
        let ContentFile {
            name: norm,
            key: digest,
            ..
        } = self.index.take(name, size)?;
        let invalid = |e: String| io::Error::new(io::ErrorKind::InvalidData, e);
        if let Some(copy) = self.handed.get(&digest) {
            if copy.size != size {
                return Err(invalid(format!("invalid content for `{norm}`")));
            }
            let reader = File::open(&copy.path)?;
            let copy = self
                .used
                .insert(digest.clone())
                .then(|| (copy.path.clone(), copy.verity.clone()));
            self.last = Some(Opened {
                name: norm,
                size,
                digest,
                copy,
                verified: true,
            });
            return Ok(Box::new(reader));
        }
        let stored = self.store.as_ref().and_then(|(sink, hints)| {
            let object = hints.get(&digest)?;
            let file = File::open(sink.content_path(object)?).ok()?;
            Some((object.clone(), file))
        });
        let Some((object, file)) = stored else {
            return Err(invalid(format!("`{norm}` was not handed over")));
        };
        if file.metadata()?.len() != size {
            return Err(invalid(format!("invalid content for `{norm}`")));
        }
        self.stored.insert(digest.clone(), object);
        self.last = Some(Opened {
            name: norm,
            size,
            digest,
            copy: None,
            verified: false,
        });
        Ok(Box::new(file))
    }
}

/// The layer whose files are in the staging or the store, by its verified
/// table of contents: the plan finds every file there.  The stream is not
/// replayed, and no diff id is claimed for it (`expected_diff_id` is what
/// the image says).
async fn verify_layer(
    ctx: &PullCtx,
    layer: &OciDescriptor,
    meta: Metadata,
    (metadata_bytes, started): (u64, std::time::Instant),
    expected_diff_id: &Digest,
) -> ImageResult<Pulled> {
    let alg = LayerKey::expected(layer).digest().alg();
    let plan = plan_blocking(
        ctx.have_fn(),
        meta.toc.clone(),
        alg,
        layer.size,
        &ctx.limits,
    )
    .await?;
    let plan_alg = plan.alg;
    // A layer with a table of contents is not replayed: the table is the
    // verified one, each file is checked against its entry by the commit
    // (the kernel's fs-verity measure, or one read of its content), and no
    // diff id is claimed for the stream before a recreation of it checks
    // one.  The fetchers staged every file the store lacks before this
    // plan, which finds them there: a file left is neither staged nor in the
    // store.
    if !plan.jobs.is_empty() {
        return Err(fail(format!(
            "{} files of the layer are neither staged nor in the store",
            plan.jobs.len()
        )));
    }
    debug!(
        "Layer {}: planned after {:?}",
        layer.digest,
        started.elapsed()
    );
    // (the entries are those of the verified table, as a lazy layer records
    // them)
    let toc = if meta.toc.is_canonical() {
        (*meta.stored).clone()
    } else {
        Toc {
            tar_split_digest: Some(Digest::of(plan_alg, &meta.tarsplit_z).to_string()),
            ..(*meta.stored).clone()
        }
    };
    let files = FileUse::of_toc(&toc);
    // (the places of the chunks the verified table gives, of every file of
    // the layer: the staged ones and those the store had, each checked as
    // the file it is; whoever copies a chunk from a place checks its bytes)
    let chunks = located_chunks(&toc);
    let diff_id = *expected_diff_id;
    let report = LayerReport {
        fetched_bytes: metadata_bytes,
        fetched_files: 0,
        reused_bytes: plan.skipped_compressed,
        reused_files: plan.skipped_files,
        sources: Vec::new(),
    };
    Ok(Pulled {
        toc,
        files,
        chunks,
        report,
        diff_id,
        tarsplit: meta.tarsplit_z,
        toc_z: Some(meta.toc_z),
    })
}

/// The chunks of `plan` that the store (or the storage driver of the sink)
/// holds, by their place in the plan: the object each is in and where.
async fn store_chunks(ctx: &PullCtx, plan: &Plan) -> ImageResult<Vec<(usize, (String, u64))>> {
    let sink = ctx.sink.clone();
    let wanted: Vec<Digest> = plan
        .chunks
        .iter()
        .filter_map(|c| c.digest)
        .collect::<HashSet<_>>()
        .into_iter()
        .collect();
    let known = ctx
        .db
        .get_chunk_locations_batch(&wanted)
        .await
        .map_err(|e| fail(e.to_string()))?;
    // (the objects the chunks are in, once each: the files of the store, or
    // what a storage driver says it holds)
    let sources: Vec<String> = known
        .values()
        .map(|l| l.file_digest.clone())
        .collect::<HashSet<_>>()
        .into_iter()
        .collect();
    let held: HashSet<String> = if sources.is_empty() {
        HashSet::new()
    } else {
        let sink = sink.clone();
        tokio::task::spawn_blocking(move || {
            sink.held(&sources).map(|held| {
                sources
                    .into_iter()
                    .zip(held)
                    .filter_map(|(k, h)| h.then_some(k))
                    .collect()
            })
        })
        .await
        .map_err(|e| fail(format!("the objects held: {e}")))?
        .map_err(io_fail)?
    };
    Ok(plan
        .chunks
        .iter()
        .enumerate()
        .filter_map(|(i, c)| {
            let loc = known.get(c.digest.as_ref()?)?;
            (loc.size == c.size
                && loc.offset.checked_add(loc.size).is_some()
                && held.contains(&loc.file_digest)
                // (a file is not made of its own bytes)
                && loc.file_digest != plan.jobs[c.job].digest)
                .then(|| (i, (loc.file_digest.clone(), loc.offset)))
        })
        .collect())
}

/// The reuse hints of the fetch of the files of `plan`: each chunk the
/// store holds, in a file of the store open for reading, which a fetcher
/// may take instead of fetching it (it checks the bytes).  None for a sink
/// whose objects the engine cannot open (a storage driver's).
async fn reuse_hints(
    ctx: &PullCtx,
    plan: &Plan,
    dir: &std::fs::File,
) -> ImageResult<super::staged_fetch::Reuses> {
    let places = store_chunks(ctx, plan).await?;
    let mut hints = super::staged_fetch::Reuses::default();
    let mut opened: HashMap<String, Option<std::fs::File>> = HashMap::new();
    for (i, (object, offset)) in places {
        let from = opened
            .entry(object.clone())
            .or_insert_with(|| ctx.sink.open_object(&object).ok());
        let (Some(from), c) = (from.as_ref(), &plan.chunks[i]) else {
            continue;
        };
        let Some(chunk) = c.digest else { continue };
        // (a chunk that cannot be copied is fetched)
        if let Err(e) = hints.hint(
            dir,
            &plan.jobs[c.job].digest,
            chunk.to_string(),
            from,
            (offset, c.size),
        ) {
            debug!("A chunk of {object} is fetched: {e}");
        }
    }
    hints.sealed().map_err(ImageError::Io)
}

/// The chunk `i` of the plan as the fetchers know it: named by its file and
/// its index in it, with where it is in the blob.  A chunk without a digest
/// (a file of one chunk, covered by the file digest) has an empty one: only
/// the registry is asked for it.
pub(crate) fn chunk_ref(plan: &Plan, i: usize) -> ChunkRef {
    let c = &plan.chunks[i];
    let job = &plan.jobs[c.job];
    ChunkRef {
        id: ChunkId {
            file: job.digest.clone(),
            index: (i - job.chunks.start) as u32,
        },
        digest: c.digest.map(|d| d.to_string()).unwrap_or_default(),
        size: c.size,
        offset: c.file_off,
        blob: Some(BlobRange {
            offset: c.comp.start,
            length: c.comp.end - c.comp.start,
        }),
    }
}

/// The chunks of one regular file of a table of contents, as the
/// fetchers know them, and its holes (zeros, fetched from nobody).
#[derive(Debug, Clone)]
pub struct FileChunks {
    /// What the file is known by: its fs-verity digest
    pub digest: String,
    pub size: u64,
    pub chunks: Vec<ChunkRef>,
    /// Offset and length of each run of zeros
    pub holes: Vec<(u64, u64)>,
}

/// The chunks of the regular file at `at` of `toc`, with the checks of a
/// pull (offsets inside the blob of `blob_size` bytes, none for a table
/// that is not of a blob; chunks of at most `max_chunk` bytes that cover
/// the file): what a process that fetches the files of a lazy layer one by
/// one asks the fetchers for.  Pure: it reads neither a store nor the
/// network.
pub fn file_chunks(
    toc: &Toc,
    alg: Algorithm,
    at: usize,
    blob_size: Option<i64>,
    max_chunk: u64,
) -> ImageResult<FileChunks> {
    let e = toc
        .entries
        .get(at)
        .filter(|e| e.entry_type == TocEntryType::Reg && e.size > 0)
        .ok_or_else(|| fail(format!("entry {at} of the table is no regular file")))?;
    let mut plan = Plan::new(alg);
    plan_file(&mut plan, &toc.entries, at, blob_size, max_chunk)?;
    let job = &plan.jobs[0];
    Ok(FileChunks {
        digest: e.content_key().unwrap_or_default(),
        size: job.size,
        chunks: job.chunks.clone().map(|i| chunk_ref(&plan, i)).collect(),
        holes: job.holes.clone(),
    })
}

#[cfg(test)]
mod index_tests;
#[cfg(test)]
mod tests;
