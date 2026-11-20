// SPDX-License-Identifier: Apache-2.0
//! Layer blobs from tar streams: plain, gzip or zstd:chunked.
//!
//! The zstd:chunked format of containers/storage: zstd frames for the tar
//! headers between two files and one frame for each chunk of a file (cut by
//! a rolling checksum, so that an edit of a file changes few chunks), then
//! skippable frames with the zstd compressed TOC, the tar-split and the
//! footer.  The output only depends on the tar stream: the same stream gives
//! the same blob, so a layer can be regenerated from its tar-split and the
//! files of the store with the digest it had.

use crate::pull::entry;
use crate::pull::tar::{Header, Kind, Sink, TarReader};
use crate::pull::tarsplit;
use std::collections::BTreeMap;
use std::io::{self, Read, Write};
use velarx_storage::{
    canonical, Toc, TocEntry, TocEntryType, TocVerityHasher, TOC_VERSION, TOC_VERSION_CANONICAL,
};
use velarx_types::digest::{Algorithm, Digest, DigestWriter, Hashing};

use zstd::stream::raw::{Encoder as RawEncoder, InBuffer, Operation, OutBuffer};

const ZSTD_LEVEL: i32 = 3;
const GZIP_LEVEL: u32 = 6;
const OUT_BUFFER: usize = 128 * 1024;

/// A chunk ends when the low `CHUNK_BITS` bits of the rolling checksum are
/// all set: 64 KiB on average, as in containers/storage.  A run of at least
/// `HOLE_THRESHOLD` zeros is a chunk of its own.
const CHUNK_BITS: u32 = 16;
const HOLE_THRESHOLD: usize = 1024;

/// Whether the TOC also gives the sha256 `digest` of each regular file,
/// besides its `fsverity` digest: containers/storage identifies files by
/// it, velarx does not need it.
const TOC_SHA256_DIGEST: bool = true;

/// Zeros that are fed to the hashes and the compressor a megabyte at a time
/// (not in the binary).
static ZEROS: std::sync::LazyLock<Vec<u8>> = std::sync::LazyLock::new(|| vec![0; 1 << 20]);

/// `len` zeros, in pieces.
fn zeros(len: u64) -> impl Iterator<Item = &'static [u8]> {
    let mut left = len;
    std::iter::from_fn(move || {
        if left == 0 {
            return None;
        }
        let n = left.min(ZEROS.len() as u64);
        left -= n;
        Some(&ZEROS[..n as usize])
    })
}

const ROLLSUM_WINDOW: usize = 64;
const ROLLSUM_CHAR_OFFSET: u32 = 31;

const MEDIA_TYPE_PLAIN: &str = "application/vnd.oci.image.layer.v1.tar";
const MEDIA_TYPE_GZIP: &str = "application/vnd.oci.image.layer.v1.tar+gzip";
const MEDIA_TYPE_ZSTD: &str = "application/vnd.oci.image.layer.v1.tar+zstd";

pub const ANNOTATION_PREFIX: &str = "io.github.containers.zstd-chunked.";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Compression {
    None,
    Gzip,
    ZstdChunked,
}

impl Compression {
    /// `gzip`, `zstd:chunked` (or `zstd`), `none` (or `uncompressed`).
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "gzip" => Some(Self::Gzip),
            "zstd:chunked" | "zstd" => Some(Self::ZstdChunked),
            "none" | "uncompressed" => Some(Self::None),
            _ => None,
        }
    }

    /// The compression a layer of this media type has; none for a type of
    /// layer that is not known (a layer is not taken for uncompressed because
    /// its type is not understood).
    pub fn from_media_type(media_type: &str) -> Option<Self> {
        match media_type {
            "application/vnd.oci.image.layer.v1.tar"
            | "application/vnd.oci.image.layer.nondistributable.v1.tar"
            | "application/vnd.docker.image.rootfs.diff.tar" => Some(Self::None),
            "application/vnd.oci.image.layer.v1.tar+gzip"
            | "application/vnd.oci.image.layer.nondistributable.v1.tar+gzip"
            | "application/vnd.docker.image.rootfs.diff.tar.gzip" => Some(Self::Gzip),
            "application/vnd.oci.image.layer.v1.tar+zstd"
            | "application/vnd.oci.image.layer.nondistributable.v1.tar+zstd" => {
                Some(Self::ZstdChunked)
            }
            _ => None,
        }
    }

    /// Check a compression level of `--compression-level` against what
    /// this compression takes (gzip 0-9, zstd 1-20, as podman); a level of
    /// no compression is nothing.
    pub fn check_level(self, level: i32) -> Result<(), String> {
        let range = match self {
            Self::None => return Ok(()),
            Self::Gzip => 0..=9,
            Self::ZstdChunked => 1..=20,
        };
        if range.contains(&level) {
            Ok(())
        } else {
            Err(format!(
                "invalid compression level {level} for {}: {}-{}",
                self.name(),
                range.start(),
                range.end()
            ))
        }
    }

    /// Check the `--compression-level` of a push that asks for
    /// `compression` (none: each layer keeps its own, which a level would
    /// change, so it is refused).
    pub fn check_level_of(compression: Option<Self>, level: Option<i32>) -> Result<(), String> {
        match (compression, level) {
            (_, None) => Ok(()),
            (None, Some(_)) => {
                Err("a compression level needs a compression format (--compression-format)".into())
            }
            (Some(c), Some(l)) => c.check_level(l),
        }
    }

    /// The name `parse` takes.
    pub fn name(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Gzip => "gzip",
            Self::ZstdChunked => "zstd:chunked",
        }
    }

    pub fn media_type(self) -> &'static str {
        match self {
            Self::None => MEDIA_TYPE_PLAIN,
            Self::Gzip => MEDIA_TYPE_GZIP,
            Self::ZstdChunked => MEDIA_TYPE_ZSTD,
        }
    }
}

/// A layer that was written.
#[derive(Debug, Clone)]
pub struct Written {
    /// Digest and size of the blob.
    pub digest: Digest,
    pub size: u64,
    pub diff_id: Digest,
    pub media_type: &'static str,
    /// The zstd:chunked annotations of the layer descriptor.
    pub annotations: BTreeMap<String, String>,
}

struct Rollsum {
    s1: u32,
    s2: u32,
    window: [u8; ROLLSUM_WINDOW],
    offset: usize,
}

impl Rollsum {
    fn new() -> Self {
        Self {
            s1: ROLLSUM_WINDOW as u32 * ROLLSUM_CHAR_OFFSET,
            s2: ROLLSUM_WINDOW as u32 * (ROLLSUM_WINDOW as u32 - 1) * ROLLSUM_CHAR_OFFSET,
            window: [0; ROLLSUM_WINDOW],
            offset: 0,
        }
    }

    fn roll(&mut self, ch: u8) {
        let drop = u32::from(self.window[self.offset]);
        self.s1 = self.s1.wrapping_add(u32::from(ch)).wrapping_sub(drop);
        self.s2 = self.s2.wrapping_add(self.s1).wrapping_sub(
            (ROLLSUM_WINDOW as u32).wrapping_mul(drop.wrapping_add(ROLLSUM_CHAR_OFFSET)),
        );
        self.window[self.offset] = ch;
        self.offset = (self.offset + 1) & (ROLLSUM_WINDOW - 1);
    }

    /// The same as `roll(0)` `n` times: the sums do not change once the
    /// window is all zeros.
    fn roll_zeros(&mut self, n: u64) {
        let rolled = n.min(ROLLSUM_WINDOW as u64);
        for _ in 0..rolled {
            self.roll(0);
        }
        self.offset = (self.offset + (n - rolled) as usize) & (ROLLSUM_WINDOW - 1);
    }

    fn on_split(&self) -> bool {
        let mask = (1u32 << CHUNK_BITS) - 1;
        self.s2 & mask == mask
    }
}

/// The output: counts and hashes what goes through (not a stream that is
/// not compressed: it is the tar stream, which is hashed already).
struct Out<W: Write> {
    inner: W,
    hasher: Option<DigestWriter>,
    size: u64,
}

impl<W: Write> Write for Out<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.inner.write_all(buf)?;
        if let Some(h) = &mut self.hasher {
            h.update(buf);
        }
        self.size += buf.len() as u64;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// The compressed stream.  zstd output is cut in frames.
enum Backend<W: Write> {
    Plain(Out<W>),
    Gzip(flate2::write::GzEncoder<Out<W>>),
    Zstd {
        encoder: RawEncoder<'static>,
        out: Out<W>,
        buffer: Vec<u8>,
        frame_open: bool,
    },
}

impl<W: Write> Backend<W> {
    fn new(
        alg: Algorithm,
        compression: Compression,
        level: Option<i32>,
        out: W,
    ) -> io::Result<Self> {
        let out = Out {
            inner: out,
            hasher: (compression != Compression::None).then(|| DigestWriter::new(alg)),
            size: 0,
        };
        Ok(match compression {
            Compression::None => Self::Plain(out),
            Compression::Gzip => Self::Gzip(flate2::write::GzEncoder::new(
                out,
                flate2::Compression::new(level.map_or(GZIP_LEVEL, |l| l.clamp(0, 9) as u32)),
            )),
            Compression::ZstdChunked => Self::Zstd {
                encoder: RawEncoder::new(level.unwrap_or(ZSTD_LEVEL))?,
                out,
                buffer: vec![0; OUT_BUFFER],
                frame_open: false,
            },
        })
    }

    /// Bytes of the blob written so far.
    fn size(&self) -> u64 {
        match self {
            Self::Plain(o) => o.size,
            Self::Gzip(g) => g.get_ref().size,
            Self::Zstd { out, .. } => out.size,
        }
    }

    fn feed(&mut self, data: &[u8]) -> io::Result<()> {
        if data.is_empty() {
            return Ok(());
        }
        match self {
            Self::Plain(o) => o.write_all(data),
            Self::Gzip(g) => g.write_all(data),
            Self::Zstd {
                encoder,
                out,
                buffer,
                frame_open,
            } => {
                *frame_open = true;
                let mut input = InBuffer::around(data);
                while input.pos() < data.len() {
                    let mut output = OutBuffer::around(&mut buffer[..]);
                    encoder.run(&mut input, &mut output)?;
                    out.write_all(output.as_slice())?;
                }
                Ok(())
            }
        }
    }

    /// End the zstd frame in progress, if any.
    fn end_frame(&mut self) -> io::Result<()> {
        let Self::Zstd {
            encoder,
            out,
            buffer,
            frame_open,
        } = self
        else {
            return Ok(());
        };
        if !std::mem::take(frame_open) {
            return Ok(());
        }
        loop {
            let mut output = OutBuffer::around(&mut buffer[..]);
            let left = encoder.finish(&mut output, true)?;
            out.write_all(output.as_slice())?;
            if left == 0 {
                return Ok(());
            }
        }
    }

    /// Finish the compressed stream; the blob is only complete after that.
    fn finish(self) -> io::Result<Out<W>> {
        match self {
            Self::Plain(o) => Ok(o),
            Self::Gzip(g) => g.finish(),
            Self::Zstd { out, .. } => Ok(out),
        }
    }

    /// A skippable frame (zstd:chunked metadata).
    fn skippable(&mut self, data: &[u8]) -> io::Result<()> {
        let Self::Zstd { out, .. } = self else {
            return Err(io::Error::other(
                "skippable frame in a stream that is not zstd",
            ));
        };
        let len = u32::try_from(data.len())
            .map_err(|_| io::Error::other("a skippable frame is larger than 4 GiB"))?;
        out.write_all(&0x184D_2A50u32.to_le_bytes())?;
        out.write_all(&len.to_le_bytes())?;
        out.write_all(data)
    }
}

/// The digests of a regular file the TOC gives.
struct FileHashes {
    verity: TocVerityHasher,
    sha256: Option<DigestWriter>,
}

impl FileHashes {
    fn new(alg: Algorithm, sha256: bool) -> Self {
        Self {
            verity: TocVerityHasher::new(alg),
            sha256: sha256.then(|| DigestWriter::new(alg)),
        }
    }

    fn update(&mut self, data: &[u8]) {
        self.verity.update(data);
        if let Some(h) = &mut self.sha256 {
            h.update(data);
        }
    }

    /// The `fsverity` and `digest` of the entry.
    fn finish(self) -> (Digest, Option<String>) {
        (
            self.verity.finish(),
            self.sha256.map(|h| h.finalize().to_string()),
        )
    }
}

struct Chunk {
    /// Position in the file and size.
    offset: u64,
    size: u64,
    /// Position of its frame in the blob.
    blob_offset: u64,
    zeros: bool,
    digest: String,
}

/// The tar stream without its contents, a digest for each entry: what the
/// writer of a canonical layer compares with the one of its table of
/// contents (see [`canonical::skeleton`]).
struct Skeleton {
    hasher: DigestWriter,
    entries: Vec<Digest>,
}

impl Skeleton {
    fn new() -> Self {
        Self {
            hasher: DigestWriter::new(Algorithm::Sha256),
            entries: Vec::new(),
        }
    }

    fn end_part(&mut self) {
        let done = std::mem::replace(&mut self.hasher, DigestWriter::new(Algorithm::Sha256));
        self.entries.push(done.finalize());
    }

    /// What the table of contents `entries` says the skeleton is.
    fn of(entries: &[TocEntry]) -> io::Result<Vec<Digest>> {
        let mut skeleton = Self::new();
        let mut part = 0;
        canonical::skeleton(entries, |i, bytes| {
            while part < i {
                skeleton.end_part();
                part += 1;
            }
            skeleton.hasher.update(bytes);
        })?;
        skeleton.end_part();
        Ok(skeleton.entries)
    }
}

/// Compresses the stream as the tar reader reports it, and builds the TOC and
/// the tar-split (none for a canonical layer, whose `skeleton` is kept).
struct Writer<W: Write> {
    /// The algorithm of every digest the layer has.
    alg: Algorithm,
    compression: Compression,
    backend: Option<Backend<W>>,
    toc: Vec<TocEntry>,
    split: Option<tarsplit::Writer<Vec<u8>>>,
    skeleton: Option<Skeleton>,

    /// The entry in progress: its TOC entry if it has one, and whether it is
    /// a regular file with content.
    current: Option<usize>,
    regular: bool,
    size: u64,
    sha256_digest: bool,
    /// Whether the TOC gives the `fsverity` digest of the files
    fsverity: bool,
    file_hashes: FileHashes,
    file_offset: u64,
    file_blob_offset: u64,

    rollsum: Rollsum,
    chunk_hasher: DigestWriter,
    chunk_start: u64,
    chunk_len: u64,
    chunk_blob_offset: u64,
    chunk_zeros: bool,
    in_hole: bool,
    /// Zeros after the last byte that is not, not in a chunk yet.
    pending_zeros: usize,
    chunks: Vec<Chunk>,
}

impl<W: Write> Writer<W> {
    fn new(
        compression: Compression,
        level: Option<i32>,
        out: W,
        alg: Algorithm,
        sha256_digest: bool,
        fsverity: bool,
        canonical: bool,
    ) -> io::Result<Self> {
        let chunked = compression == Compression::ZstdChunked;
        Ok(Self {
            alg,
            compression,
            backend: Some(Backend::new(alg, compression, level, out)?),
            toc: Vec::new(),
            split: (chunked && !canonical).then(|| tarsplit::Writer::new(Vec::new())),
            skeleton: (chunked && canonical).then(Skeleton::new),
            current: None,
            regular: false,
            size: 0,
            sha256_digest,
            fsverity,
            file_hashes: FileHashes::new(alg, sha256_digest),
            file_offset: 0,
            file_blob_offset: 0,
            rollsum: Rollsum::new(),
            chunk_hasher: DigestWriter::new(alg),
            chunk_start: 0,
            chunk_len: 0,
            chunk_blob_offset: 0,
            chunk_zeros: false,
            in_hole: false,
            pending_zeros: 0,
            chunks: Vec::new(),
        })
    }

    fn backend(&mut self) -> io::Result<&mut Backend<W>> {
        self.backend
            .as_mut()
            .ok_or_else(|| io::Error::other("the layer was finished"))
    }

    fn chunked(&self) -> bool {
        self.compression == Compression::ZstdChunked
    }

    fn start_chunk(&mut self, zeros: bool) -> io::Result<()> {
        self.chunk_zeros = zeros;
        self.chunk_start = self.file_offset;
        self.chunk_len = 0;
        self.chunk_blob_offset = self.backend()?.size();
        self.chunk_hasher = DigestWriter::new(self.alg);
        Ok(())
    }

    /// The first chunk of a file is the file so far: its digest is the one
    /// of the file's sha256 at its end, not hashed twice.
    fn first_chunk_of_file_digest(&self) -> bool {
        self.chunks.is_empty() && self.file_hashes.sha256.is_some()
    }

    fn close_chunk(&mut self) -> io::Result<()> {
        if self.chunk_len == 0 {
            return Ok(());
        }
        self.backend()?.end_frame()?;
        let digest = match &self.file_hashes.sha256 {
            Some(file) if self.chunks.is_empty() => file.clone().finalize().to_string(),
            _ => {
                let fresh = DigestWriter::new(self.alg);
                std::mem::replace(&mut self.chunk_hasher, fresh)
                    .finalize()
                    .to_string()
            }
        };
        self.chunks.push(Chunk {
            offset: self.chunk_start,
            size: self.chunk_len,
            blob_offset: self.chunk_blob_offset,
            zeros: self.chunk_zeros,
            digest,
        });
        Ok(())
    }

    /// Bytes of the file, in a chunk: every byte of a file of a chunked
    /// layer comes here, in order.
    fn add_to_chunk(&mut self, data: &[u8]) -> io::Result<()> {
        if let Some(h) = &mut self.file_hashes.sha256 {
            h.update(data);
        }
        if !self.first_chunk_of_file_digest() {
            self.chunk_hasher.update(data);
        }
        self.backend()?.feed(data)?;
        self.chunk_len += data.len() as u64;
        self.file_offset += data.len() as u64;
        Ok(())
    }

    /// Bytes that are not in a hole: a new chunk starts after each boundary
    /// of the rolling checksum.
    fn chunk_bytes(&mut self, mut data: &[u8]) -> io::Result<()> {
        while !data.is_empty() {
            let mut used = 0;
            let mut split = false;
            while used < data.len() {
                self.rollsum.roll(data[used]);
                used += 1;
                if self.rollsum.on_split() {
                    split = true;
                    break;
                }
            }
            let (head, rest) = data.split_at(used);
            self.add_to_chunk(head)?;
            data = rest;
            if split {
                self.close_chunk()?;
                self.start_chunk(false)?;
            }
        }
        Ok(())
    }

    fn flush_pending_zeros(&mut self) -> io::Result<()> {
        let zeros = [0u8; HOLE_THRESHOLD];
        let n = std::mem::take(&mut self.pending_zeros);
        self.chunk_bytes(&zeros[..n])
    }

    /// Zeros of the hole in progress: the rolling checksum sees them but
    /// they cannot end the chunk.
    fn hole_bytes(&mut self, len: u64) -> io::Result<()> {
        self.rollsum.roll_zeros(len);
        for z in zeros(len) {
            self.add_to_chunk(z)?;
        }
        Ok(())
    }

    fn chunk_data(&mut self, data: &[u8]) -> io::Result<()> {
        let mut i = 0;
        while i < data.len() {
            let mut j = i;
            if self.in_hole {
                while j < data.len() && data[j] == 0 {
                    j += 1;
                }
                if j > i {
                    self.hole_bytes((j - i) as u64)?;
                }
                if j < data.len() {
                    self.in_hole = false;
                    self.close_chunk()?;
                    self.start_chunk(false)?;
                }
                i = j;
                continue;
            }
            if data[i] == 0 {
                while j < data.len() && data[j] == 0 {
                    j += 1;
                }
                if self.pending_zeros + (j - i) < HOLE_THRESHOLD {
                    self.pending_zeros += j - i;
                    i = j;
                    continue;
                }
                // The zeros so far are the beginning of the hole.
                self.close_chunk()?;
                self.start_chunk(true)?;
                self.in_hole = true;
                let n = std::mem::take(&mut self.pending_zeros) + (j - i);
                self.hole_bytes(n as u64)?;
                i = j;
                continue;
            }
            if self.pending_zeros > 0 {
                self.flush_pending_zeros()?;
            }
            while j < data.len() && data[j] != 0 {
                j += 1;
            }
            self.chunk_bytes(&data[i..j])?;
            i = j;
        }
        Ok(())
    }

    /// The TOC entry of a header.  The names are the ones of the tar
    /// headers: containers/storage checks the TOC against the tar-split.
    fn toc_entry(alg: Algorithm, h: &Header) -> io::Result<TocEntry> {
        let empty = Digest::empty(alg).to_string();
        let placeholder = (h.kind == Kind::Regular).then_some(empty.as_str());
        let mut e = entry::from_header(h, placeholder)?;
        e.name = h.path.clone();
        if e.link_name.is_some() {
            e.link_name = h.link.clone();
        }
        e.digest = None;
        e.chunk_digest = None;
        e.chunk_size = 0;
        Ok(e)
    }

    fn end_file_chunks(&mut self) -> io::Result<()> {
        if self.pending_zeros > 0 {
            self.flush_pending_zeros()?;
        }
        self.in_hole = false;
        self.close_chunk()?;
        let blob_size = self.backend()?.size();
        let Some(index) = self.current else {
            return Ok(());
        };
        let chunks = std::mem::take(&mut self.chunks);
        let e = &mut self.toc[index];
        e.offset = self.file_blob_offset;
        e.end_offset = blob_size;
        // A file in a single chunk has no chunk information, like in
        // containers/storage.
        if chunks.len() > 1 {
            let name = e.name.clone();
            let first = &chunks[0];
            e.chunk_size = first.size;
            e.chunk_digest = Some(first.digest.clone());
            e.chunk_type = first.zeros.then(|| "zeros".to_string());
            for c in &chunks[1..] {
                self.toc.push(TocEntry {
                    offset: c.blob_offset,
                    chunk_digest: Some(c.digest.clone()),
                    chunk_size: c.size,
                    chunk_offset: c.offset,
                    chunk_type: c.zeros.then(|| "zeros".to_string()),
                    ..TocEntry::new(name.clone(), TocEntryType::Chunk)
                });
            }
        }
        Ok(())
    }

    /// The table of contents, as the JSON that goes in the blob.  The
    /// table of a canonical layer is parsed back and must have the tar that
    /// was written: the same skeleton.  Anything else is a bug of the writer,
    /// and no layer is made of it.
    fn toc_json(&mut self, toc: &Toc) -> io::Result<Vec<u8>> {
        let json = serde_json::to_vec(toc).map_err(io::Error::other)?;
        let Some(mut written) = self.skeleton.take() else {
            return Ok(json);
        };
        written.end_part();
        let back: Toc = serde_json::from_slice(&json).map_err(io::Error::other)?;
        let fail = |what: String| {
            io::Error::other(format!(
                "zstd:chunked version 2 self-check: the tar rebuilt from the table of contents \
                 differs from the written one: {what}"
            ))
        };
        canonical::validate(&back.entries).map_err(|e| fail(e.to_string()))?;
        let rebuilt = Skeleton::of(&back.entries)?;
        let at = (0..written.entries.len().max(rebuilt.len()))
            .find(|&i| written.entries.get(i) != rebuilt.get(i));
        if let Some(i) = at {
            let name = back
                .entries
                .iter()
                .filter(|e| e.entry_type != TocEntryType::Chunk)
                .nth(i)
                .map_or("the end of the stream", |e| e.name.as_str());
            return Err(fail(format!("entry {i} (`{name}`)")));
        }
        Ok(json)
    }

    /// Write the TOC, the tar-split (a canonical layer has none) and the
    /// footer; their annotations.
    fn write_chunked_metadata(
        &mut self,
        annotations: &mut BTreeMap<String, String>,
    ) -> io::Result<()> {
        let canonical = self.skeleton.is_some();
        let (ts_z, ts_len) = match self.split.take() {
            Some(split) => {
                let (ts, _) = split.finish()?;
                (zstd::bulk::compress(&ts, ZSTD_LEVEL)?, ts.len())
            }
            None if canonical => (Vec::new(), 0),
            None => return Err(io::Error::other("no tar-split")),
        };
        let toc = Toc {
            version: if canonical {
                TOC_VERSION_CANONICAL
            } else {
                TOC_VERSION
            },
            entries: std::mem::take(&mut self.toc),
            tar_split_digest: (!canonical).then(|| Digest::of(self.alg, &ts_z).to_string()),
        };
        let toc_json = self.toc_json(&toc)?;
        let toc_z = zstd::bulk::compress(&toc_json, ZSTD_LEVEL)?;

        let backend = self.backend()?;
        let toc_offset = backend.size() + 8;
        backend.skippable(&toc_z)?;
        let ts_offset = if canonical { 0 } else { backend.size() + 8 };
        if !canonical {
            backend.skippable(&ts_z)?;
        }

        let mut footer = Vec::with_capacity(64);
        for v in [
            toc_offset,
            toc_z.len() as u64,
            toc_json.len() as u64,
            1,
            ts_offset,
            ts_z.len() as u64,
            ts_len as u64,
        ] {
            footer.extend(v.to_le_bytes());
        }
        footer.extend(b"GNUlInUx");
        backend.skippable(&footer)?;

        annotations.insert(
            format!("{ANNOTATION_PREFIX}manifest-checksum"),
            Digest::of(self.alg, &toc_z).to_string(),
        );
        annotations.insert(
            format!("{ANNOTATION_PREFIX}manifest-position"),
            format!("{toc_offset}:{}:{}:1", toc_z.len(), toc_json.len()),
        );
        if canonical {
            annotations.insert(
                format!("{ANNOTATION_PREFIX}version"),
                TOC_VERSION_CANONICAL.to_string(),
            );
        } else {
            annotations.insert(
                format!("{ANNOTATION_PREFIX}tarsplit-position"),
                format!("{ts_offset}:{}:{ts_len}", ts_z.len()),
            );
        }
        Ok(())
    }
}

impl<W: Write> Sink for Writer<W> {
    fn segment(&mut self, data: &[u8]) -> io::Result<()> {
        if let Some(s) = &mut self.split {
            s.segment(data)?;
        }
        if let Some(s) = &mut self.skeleton {
            s.hasher.update(data);
        }
        self.backend()?.feed(data)
    }

    fn file_begin(&mut self, h: &Header) -> io::Result<()> {
        if let Some(s) = &mut self.split {
            s.file_begin(&h.path)?;
        }
        self.toc.push(Self::toc_entry(self.alg, h)?);
        self.current = Some(self.toc.len() - 1);
        self.regular = h.kind == Kind::Regular;
        self.size = h.size;
        self.file_offset = 0;
        self.chunks.clear();
        if !self.regular {
            return Ok(());
        }
        self.file_hashes = FileHashes::new(self.alg, self.sha256_digest);
        if h.size == 0 || !self.chunked() {
            return Ok(());
        }
        self.backend()?.end_frame()?;
        self.file_blob_offset = self.backend()?.size();
        self.rollsum = Rollsum::new();
        self.in_hole = false;
        self.pending_zeros = 0;
        self.start_chunk(false)
    }

    fn file_data(&mut self, data: &[u8]) -> io::Result<()> {
        if let Some(s) = &mut self.split {
            s.file_data(data)?;
        }
        if !self.chunked() {
            self.file_hashes.update(data);
            self.file_offset += data.len() as u64;
            return self.backend()?.feed(data);
        }
        self.file_hashes.verity.update(data);
        self.chunk_data(data)
    }

    fn file_end(&mut self) -> io::Result<()> {
        if let Some(s) = &mut self.split {
            s.file_end()?;
        }
        if let Some(s) = &mut self.skeleton {
            if self.regular && self.size > 0 {
                s.hasher.update(&self.size.to_le_bytes());
            }
            s.end_part();
        }
        if !self.regular {
            return Ok(());
        }
        // (the last chunk takes the zeros that are pending: the digest of
        // the file is of them too)
        if self.chunked() && self.size > 0 {
            self.end_file_chunks()?;
        }
        let hashes = std::mem::replace(&mut self.file_hashes, FileHashes::new(self.alg, false));
        if let (Some(index), true) = (self.current, self.size > 0) {
            // containers/storage leaves the digest of empty files out; no
            // object is stored for them
            let (verity, sha256) = hashes.finish();
            let e = &mut self.toc[index];
            e.fsverity = self.fsverity.then_some(verity);
            e.digest = sha256;
        }
        Ok(())
    }
}

/// Write the layer blob of the tar stream `tar` to `out`.  Nothing of the
/// output is valid unless this returns.  Every digest of the layer (blob,
/// diff id, chunks, TOC) is of the algorithm `alg`.
pub fn write_layer<R: Read, W: Write>(
    tar: R,
    alg: Algorithm,
    compression: Compression,
    out: W,
) -> io::Result<Written> {
    write_layer_level(tar, alg, compression, None, out)
}

/// [`write_layer`] at a compression level of its own (`None`: the default
/// of the compression), checked with [`Compression::check_level`] before.
pub fn write_layer_level<R: Read, W: Write>(
    tar: R,
    alg: Algorithm,
    compression: Compression,
    level: Option<i32>,
    out: W,
) -> io::Result<Written> {
    write_layer_with(
        tar,
        alg,
        compression,
        level,
        out,
        Table {
            sha256_digest: TOC_SHA256_DIGEST,
            fsverity: true,
            canonical: false,
        },
    )
}

/// [`write_layer_level`] for a stream that is the canonical tar of a layer
/// ([`canonical`]): a zstd:chunked blob of it has a table of contents of
/// version 2 and no tar-split.  The table is checked against what was
/// written before the blob is complete; a stream that is not canonical is an
/// error.  The other compressions are the stream compressed.
pub fn write_canonical_layer<R: Read, W: Write>(
    tar: R,
    alg: Algorithm,
    compression: Compression,
    level: Option<i32>,
    out: W,
) -> io::Result<Written> {
    write_layer_with(
        tar,
        alg,
        compression,
        level,
        out,
        Table {
            sha256_digest: TOC_SHA256_DIGEST,
            fsverity: true,
            canonical: true,
        },
    )
}

/// [`write_layer`] for a TOC that gives the sha256 `digest` of each file and
/// no `fsverity` digest, as a layer made by containers/storage has it: its
/// files are named by the hash of their content.
pub fn write_layer_sha256_keyed<R: Read, W: Write>(
    tar: R,
    alg: Algorithm,
    compression: Compression,
    out: W,
) -> io::Result<Written> {
    write_layer_with(
        tar,
        alg,
        compression,
        None,
        out,
        Table {
            sha256_digest: true,
            fsverity: false,
            canonical: false,
        },
    )
}

/// What the table of contents of a layer gives.
#[derive(Clone, Copy)]
struct Table {
    /// the sha256 `digest` of each file
    sha256_digest: bool,
    /// the `fsverity` digest of each file
    fsverity: bool,
    /// the layer is a canonical tar: no tar-split
    canonical: bool,
}

fn write_layer_with<R: Read, W: Write>(
    tar: R,
    alg: Algorithm,
    compression: Compression,
    level: Option<i32>,
    out: W,
    table: Table,
) -> io::Result<Written> {
    let Table {
        sha256_digest,
        fsverity,
        canonical,
    } = table;
    let hashing = Hashing::new(alg, tar);
    let mut reader = TarReader::with_sink(
        hashing,
        Writer::new(
            compression,
            level,
            out,
            alg,
            sha256_digest,
            fsverity,
            canonical,
        )?,
    );
    let mut buf = vec![0u8; 64 * 1024];
    while reader.next_entry()?.is_some() {
        while reader.read(&mut buf)? != 0 {}
    }
    let (hashing, mut writer) = reader.finish()?;
    let mut annotations = BTreeMap::new();
    if compression == Compression::ZstdChunked {
        writer.backend()?.end_frame()?;
        writer.write_chunked_metadata(&mut annotations)?;
    }
    let out = writer
        .backend
        .take()
        .ok_or_else(|| io::Error::other("the layer was finished"))?
        .finish()?;
    let diff_id = hashing.hasher.finalize();
    Ok(Written {
        // (a layer that is not compressed is its stream)
        digest: out.hasher.map_or_else(|| diff_id, DigestWriter::finalize),
        size: out.size,
        diff_id,
        media_type: compression.media_type(),
        annotations,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pull::tarsplit::{decoder, Entries, Item};
    use rand::{Rng, SeedableRng};
    use velarx_storage::Toc;

    fn sample_tar() -> Vec<u8> {
        let mut rng = rand::rngs::StdRng::seed_from_u64(7);
        let mut random = vec![0u8; 400_000];
        rng.fill(&mut random[..]);
        let mut holey = vec![1u8; 5000];
        holey.extend(vec![0u8; 20_000]);
        holey.extend(vec![2u8; 5000]);
        let mut b = tar::Builder::new(Vec::new());
        let mut add = |name: &str, kind: tar::EntryType, data: &[u8]| {
            let mut h = tar::Header::new_gnu();
            h.set_entry_type(kind);
            h.set_size(data.len() as u64);
            h.set_mode(0o644);
            h.set_uid(10);
            h.set_gid(20);
            h.set_mtime(1_700_000_000);
            b.append_data(&mut h, name, data).unwrap();
        };
        add("etc/", tar::EntryType::Directory, b"");
        add("etc/small", tar::EntryType::Regular, b"hello\n");
        add("etc/empty", tar::EntryType::Regular, b"");
        add("usr/random", tar::EntryType::Regular, &random);
        add("usr/holey", tar::EntryType::Regular, &holey);
        let mut h = tar::Header::new_gnu();
        h.set_entry_type(tar::EntryType::Symlink);
        h.set_size(0);
        b.append_link(&mut h, "etc/link", "small").unwrap();
        let mut h = tar::Header::new_gnu();
        h.set_entry_type(tar::EntryType::Link);
        h.set_size(0);
        b.append_link(&mut h, "etc/hard", "etc/small").unwrap();
        let mut tar = b.into_inner().unwrap();
        tar.extend(vec![0u8; 3072]);
        tar
    }

    fn write(tar: &[u8], c: Compression) -> (Vec<u8>, Written) {
        let mut out = Vec::new();
        let w = write_layer(tar, Algorithm::Sha256, c, &mut out).unwrap();
        (out, w)
    }

    #[test]
    fn test_every_compression_gives_back_the_stream() {
        let tar = sample_tar();
        for c in [
            Compression::None,
            Compression::Gzip,
            Compression::ZstdChunked,
        ] {
            let (blob, w) = write(&tar, c);
            assert_eq!(w.digest, crate::sha256(&blob));
            assert_eq!(w.size, blob.len() as u64);
            assert_eq!(w.diff_id, crate::sha256(&tar));
            let mut back = Vec::new();
            match c {
                Compression::None => back = blob.clone(),
                Compression::Gzip => {
                    flate2::read::GzDecoder::new(&blob[..])
                        .read_to_end(&mut back)
                        .unwrap();
                }
                Compression::ZstdChunked => {
                    zstd::stream::read::Decoder::new(&blob[..])
                        .unwrap()
                        .read_to_end(&mut back)
                        .unwrap();
                }
            }
            // Skippable frames carry no data: the stream is the tar.
            assert_eq!(back, tar, "{c:?}");
            assert_eq!(w.annotations.is_empty(), c != Compression::ZstdChunked);
        }
    }

    #[test]
    fn test_a_compression_level_changes_the_blob_not_the_stream() {
        let tar = sample_tar();
        for (c, low, high) in [(Compression::Gzip, 1, 9), (Compression::ZstdChunked, 1, 19)] {
            let mut fast = Vec::new();
            let mut best = Vec::new();
            let f =
                write_layer_level(&tar[..], Algorithm::Sha256, c, Some(low), &mut fast).unwrap();
            let b =
                write_layer_level(&tar[..], Algorithm::Sha256, c, Some(high), &mut best).unwrap();
            assert_ne!(f.digest, b.digest, "{c:?}");
            assert_eq!(f.diff_id, b.diff_id);
            let (default, _) = write(&tar, c);
            let mut same = Vec::new();
            write_layer_level(&tar[..], Algorithm::Sha256, c, None, &mut same).unwrap();
            assert_eq!(same, default);
        }
        assert!(Compression::Gzip.check_level(9).is_ok());
        assert!(Compression::Gzip.check_level(10).is_err());
        assert!(Compression::ZstdChunked.check_level(0).is_err());
        assert!(Compression::ZstdChunked.check_level(20).is_ok());
        assert!(Compression::None.check_level(42).is_ok());
        assert!(Compression::check_level_of(None, None).is_ok());
        assert!(Compression::check_level_of(None, Some(3)).is_err());
        assert!(Compression::check_level_of(Some(Compression::Gzip), Some(3)).is_ok());
    }

    #[test]
    fn test_output_is_deterministic() {
        let tar = sample_tar();
        for c in [Compression::Gzip, Compression::ZstdChunked] {
            assert_eq!(write(&tar, c).0, write(&tar, c).0);
        }
    }

    fn frame_at(blob: &[u8], offset: u64) -> Vec<u8> {
        let mut dec = zstd::stream::read::Decoder::new(&blob[offset as usize..])
            .unwrap()
            .single_frame();
        let mut out = Vec::new();
        dec.read_to_end(&mut out).unwrap();
        out
    }

    #[test]
    fn test_the_root_of_a_layer_is_in_its_toc() {
        let mut b = tar::Builder::new(Vec::new());
        let mut h = tar::Header::new_gnu();
        h.set_entry_type(tar::EntryType::Directory);
        h.set_mode(0o700);
        h.set_uid(5);
        h.set_mtime(1_700_000_000);
        h.set_size(0);
        b.append_data(&mut h, "./", &b""[..]).unwrap();
        let mut h = tar::Header::new_gnu();
        h.set_mode(0o644);
        h.set_size(1);
        b.append_data(&mut h, "./f", &b"x"[..]).unwrap();
        let tar = b.into_inner().unwrap();
        let (blob, w) = write(&tar, Compression::ZstdChunked);
        let a = |k: &str| w.annotations[&format!("{ANNOTATION_PREFIX}{k}")].clone();
        let pos: Vec<u64> = a("manifest-position")
            .split(':')
            .map(|n| n.parse().unwrap())
            .collect();
        let toc_z = &blob[pos[0] as usize..(pos[0] + pos[1]) as usize];
        let toc: Toc = serde_json::from_slice(&zstd::decode_all(toc_z).unwrap()).unwrap();
        let names: Vec<_> = toc.entries.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, ["./", "f"]);
        let root = &toc.entries[0];
        assert_eq!(
            (root.mode, root.uid, root.mtime()),
            (0o700, 5, (1_700_000_000, 0))
        );
    }

    #[test]
    fn test_chunked_layer_has_a_valid_toc_tarsplit_and_footer() {
        let tar = sample_tar();
        let (blob, w) = write(&tar, Compression::ZstdChunked);
        let a = |k: &str| w.annotations[&format!("{ANNOTATION_PREFIX}{k}")].clone();

        // The footer is the last skippable frame and says where the rest is.
        let footer = &blob[blob.len() - 64..];
        assert_eq!(&footer[56..], b"GNUlInUx");
        let le = |i: usize| u64::from_le_bytes(footer[i * 8..i * 8 + 8].try_into().unwrap());
        assert_eq!(
            a("manifest-position"),
            format!("{}:{}:{}:1", le(0), le(1), le(2))
        );
        assert_eq!(
            a("tarsplit-position"),
            format!("{}:{}:{}", le(4), le(5), le(6))
        );

        let toc_z = &blob[le(0) as usize..(le(0) + le(1)) as usize];
        assert_eq!(crate::sha256_text(toc_z), a("manifest-checksum"));
        let toc: Toc = serde_json::from_slice(&zstd::decode_all(toc_z).unwrap()).unwrap();
        let ts_z = &blob[le(4) as usize..(le(4) + le(5)) as usize];
        assert_eq!(
            toc.tar_split_digest.as_deref(),
            Some(crate::sha256_text(ts_z).as_str())
        );

        // The tar-split names every entry; its files are the ones of the TOC.
        let items: Vec<Item> = Entries::new(decoder(ts_z.to_vec(), 1 << 30).unwrap())
            .collect::<Result<_, _>>()
            .unwrap();
        let files = items
            .iter()
            .filter(|i| matches!(i, Item::File { .. }))
            .count();
        assert_eq!(files, 7);

        // Every chunk is a frame of its own, with the digest the TOC gives.
        let random = toc.find_by_name("usr/random").unwrap();
        let chunks = toc.get_file_chunks("usr/random");
        assert!(chunks.len() > 2, "{} chunks", chunks.len());
        let mut data = Vec::new();
        for c in &chunks {
            let bytes = frame_at(&blob, c.offset);
            assert_eq!(
                c.chunk_digest.as_deref(),
                Some(crate::sha256_text(&bytes).as_str())
            );
            assert_eq!(bytes.len() as u64, c.chunk_size);
            assert_eq!(c.chunk_offset, data.len() as u64);
            data.extend(bytes);
        }
        assert_eq!(
            random.digest.as_deref(),
            Some(crate::sha256_text(&data).as_str())
        );
        assert_eq!(random.size, data.len() as u64);
        assert_eq!(
            random.verity(),
            Some(velarx_storage::fsverity_digest_of(
                velarx_types::digest::Algorithm::Sha256,
                &data
            ))
        );

        // Runs of zeros are chunks of their own.
        let holey = toc.get_file_chunks("usr/holey");
        assert_eq!(holey.len(), 3);
        assert!(!holey[0].is_zeros_chunk() && holey[1].is_zeros_chunk());
        assert_eq!(holey[1].chunk_size, 20_000);
        for c in &holey {
            let bytes = frame_at(&blob, c.offset);
            assert_eq!(
                c.chunk_digest.as_deref(),
                Some(crate::sha256_text(&bytes).as_str())
            );
            assert_eq!(bytes.len() as u64, c.chunk_size);
        }
        assert_eq!(frame_at(&blob, holey[1].offset), vec![0u8; 20_000]);

        // Empty files have no digest, one-chunk files no chunk information.
        assert_eq!(toc.find_by_name("etc/empty").unwrap().digest, None);
        assert_eq!(toc.find_by_name("etc/empty").unwrap().fsverity, None);
        // a hard link is the file it names; fs-verity is of the content,
        // holes or not
        assert_eq!(toc.find_by_name("etc/hard").unwrap().fsverity, None);
        let mut dense = vec![1u8; 5000];
        dense.extend(vec![0u8; 20_000]);
        dense.extend(vec![2u8; 5000]);
        assert_eq!(
            toc.find_by_name("usr/holey").unwrap().verity(),
            Some(velarx_storage::fsverity_digest_of(
                velarx_types::digest::Algorithm::Sha256,
                &dense
            ))
        );
        let small = toc.find_by_name("etc/small").unwrap();
        assert_eq!(small.chunk_digest, None);
        assert_eq!(
            small.digest.as_deref(),
            Some(crate::sha256_text(b"hello\n").as_str())
        );
        assert_eq!(frame_at(&blob, small.offset), b"hello\n");
        assert_eq!(
            toc.find_by_name("etc/link").unwrap().link_name.as_deref(),
            Some("small")
        );
    }

    /// The digests of a file that ends with zeros too few for a chunk of
    /// their own (they wait for the next byte) are of those zeros too.
    #[test]
    fn test_the_digests_of_a_file_that_ends_with_zeros() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(3);
        let mut random = vec![0u8; 300_000];
        rng.fill(&mut random[..]);
        random.extend(vec![0u8; 700]);
        let mut small = b"short".to_vec();
        small.extend(vec![0u8; 500]);
        let mut b = tar::Builder::new(Vec::new());
        for (name, data) in [("random", &random), ("small", &small)] {
            let mut h = tar::Header::new_gnu();
            h.set_size(data.len() as u64);
            h.set_mode(0o644);
            b.append_data(&mut h, name, &data[..]).unwrap();
        }
        let tar = b.into_inner().unwrap();
        let (blob, w) = write(&tar, Compression::ZstdChunked);
        let a = &w.annotations[&format!("{ANNOTATION_PREFIX}manifest-position")];
        let v: Vec<usize> = a.split(':').take(2).map(|n| n.parse().unwrap()).collect();
        let toc: Toc =
            serde_json::from_slice(&zstd::decode_all(&blob[v[0]..v[0] + v[1]]).unwrap()).unwrap();
        for (name, data) in [("random", &random), ("small", &small)] {
            let e = toc.find_by_name(name).unwrap();
            assert_eq!(
                e.digest.as_deref(),
                Some(crate::sha256_text(data).as_str()),
                "{name}"
            );
            let mut content = Vec::new();
            for c in toc.get_file_chunks(name) {
                let bytes = frame_at(&blob, c.offset);
                if let Some(d) = &c.chunk_digest {
                    assert_eq!(d, &crate::sha256_text(&bytes), "{name}");
                }
                content.extend(bytes);
            }
            assert_eq!(&content, data, "{name}");
        }
        assert!(toc.get_file_chunks("random").len() > 1);
    }

    /// A layer written for sha512 has no sha256 digest anywhere: the blob,
    /// the diff id, the chunks, the files, the TOC and the tar-split.
    #[test]
    fn test_a_sha512_layer_has_only_sha512_digests() {
        let tar = sample_tar();
        for c in [
            Compression::None,
            Compression::Gzip,
            Compression::ZstdChunked,
        ] {
            let mut out = Vec::new();
            let w = write_layer(&tar[..], Algorithm::Sha512, c, &mut out).unwrap();
            assert_eq!(w.digest, Digest::of(Algorithm::Sha512, &out), "{c:?}");
            assert_eq!(w.diff_id, Digest::of(Algorithm::Sha512, &tar), "{c:?}");
            if c != Compression::ZstdChunked {
                continue;
            }
            let a = |k: &str| w.annotations[&format!("{ANNOTATION_PREFIX}{k}")].clone();
            let [off, len]: [usize; 2] = {
                let v: Vec<usize> = a("manifest-position")
                    .split(':')
                    .take(2)
                    .map(|n| n.parse().unwrap())
                    .collect();
                [v[0], v[1]]
            };
            let toc_z = &out[off..off + len];
            assert_eq!(
                a("manifest-checksum"),
                Digest::of(Algorithm::Sha512, toc_z).to_string()
            );
            let toc: Toc = serde_json::from_slice(&zstd::decode_all(toc_z).unwrap()).unwrap();
            assert!(toc
                .tar_split_digest
                .as_deref()
                .unwrap()
                .starts_with("sha512:"));
            let mut regular = 0;
            for e in &toc.entries {
                for d in [&e.digest, &e.chunk_digest].into_iter().flatten() {
                    assert!(d.starts_with("sha512:") && d.len() == 7 + 128, "{d}");
                }
                if let Some(v) = &e.fsverity {
                    regular += 1;
                    assert_eq!(v.alg(), Algorithm::Sha512);
                }
            }
            assert!(regular > 0);
        }
    }

    /// Without the sha256 of the files the layer only differs by the TOC.
    #[test]
    fn test_the_sha256_of_files_can_be_left_out() {
        let tar = sample_tar();
        let mut out = Vec::new();
        let w = write_layer_with(
            &tar[..],
            Algorithm::Sha256,
            Compression::ZstdChunked,
            None,
            &mut out,
            Table {
                sha256_digest: false,
                fsverity: true,
                canonical: false,
            },
        )
        .unwrap();
        assert_eq!(w.diff_id, crate::sha256(&tar));
        let a = &w.annotations[&format!("{ANNOTATION_PREFIX}manifest-position")];
        let [off, len]: [usize; 2] = {
            let v: Vec<usize> = a.split(':').take(2).map(|n| n.parse().unwrap()).collect();
            [v[0], v[1]]
        };
        let toc: Toc =
            serde_json::from_slice(&zstd::decode_all(&out[off..off + len]).unwrap()).unwrap();
        let small = toc.find_by_name("etc/small").unwrap();
        assert_eq!(small.digest, None);
        assert_eq!(
            small.verity(),
            Some(velarx_storage::fsverity_digest_of(
                velarx_types::digest::Algorithm::Sha256,
                b"hello\n"
            ))
        );
    }

    /// A layer made as containers/storage makes it names its files by the
    /// sha256 of their content only.
    #[test]
    fn test_a_layer_can_be_written_with_sha256_keys_only() {
        let tar = sample_tar();
        let mut out = Vec::new();
        let w = write_layer_sha256_keyed(
            &tar[..],
            Algorithm::Sha256,
            Compression::ZstdChunked,
            &mut out,
        )
        .unwrap();
        assert_eq!(w.diff_id, crate::sha256(&tar));
        let a = &w.annotations[&format!("{ANNOTATION_PREFIX}manifest-position")];
        let [off, len]: [usize; 2] = {
            let v: Vec<usize> = a.split(':').take(2).map(|n| n.parse().unwrap()).collect();
            [v[0], v[1]]
        };
        let toc: Toc =
            serde_json::from_slice(&zstd::decode_all(&out[off..off + len]).unwrap()).unwrap();
        let small = toc.find_by_name("etc/small").unwrap();
        assert_eq!(small.verity(), None);
        assert_eq!(small.digest, Some(crate::sha256(b"hello\n").to_string()));
    }

    /// The tar of the files.
    fn tar_of(files: &[(&str, Vec<u8>)]) -> Vec<u8> {
        let mut b = tar::Builder::new(Vec::new());
        for (name, data) in files {
            let mut h = tar::Header::new_gnu();
            h.set_size(data.len() as u64);
            h.set_mode(0o644);
            h.set_mtime(1_700_000_000);
            b.append_data(&mut h, name, &data[..]).unwrap();
        }
        let mut tar = b.into_inner().unwrap();
        tar.extend(vec![0u8; 1024]);
        tar
    }

    /// Files of data, of zeros and of both.
    fn files_with_zeros() -> Vec<(&'static str, Vec<u8>)> {
        let mut rng = rand::rngs::StdRng::seed_from_u64(11);
        let mut random = vec![0u8; 300_000];
        rng.fill(&mut random[..]);
        let mut mixed = random[..70_000].to_vec();
        mixed.extend(vec![0u8; 400]);
        mixed.extend(&random[..10]);
        mixed.extend(vec![0u8; 300 + 100_000 + 700]);
        mixed.extend(&random[..5000]);
        mixed.extend(vec![0u8; 3 * 4096 + 17]);
        let mut starts_with_a_hole = vec![0u8; 200_000];
        starts_with_a_hole.extend(&random[..1000]);
        let mut short_zeros = vec![1u8; 100];
        short_zeros.extend(vec![0u8; 1023]);
        short_zeros.extend(vec![2u8; 100]);
        let mut ends_with_a_hole = vec![1u8; 4096];
        ends_with_a_hole.extend(vec![0u8; 1 << 20]);
        vec![
            ("a/mixed", mixed),
            ("a/all-holes", vec![0u8; 3 << 20]),
            ("a/starts-with-a-hole", starts_with_a_hole),
            ("a/small", vec![0u8; 700]),
            ("a/random", random),
            ("a/short-zeros", short_zeros),
            ("a/ends-with-a-hole", ends_with_a_hole),
        ]
    }

    /// The window of the rolling checksum that is all zeros does not change.
    #[test]
    fn test_rolling_zeros() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(5);
        for n in [0u64, 1, 63, 64, 65, 1000, 12_345] {
            let mut slow = Rollsum::new();
            for _ in 0..rng.gen_range(0..300) {
                slow.roll(rng.gen());
            }
            let mut fast = Rollsum {
                window: slow.window,
                ..slow
            };
            for _ in 0..n {
                slow.roll(0);
            }
            fast.roll_zeros(n);
            assert_eq!(
                (fast.s1, fast.s2, fast.offset),
                (slow.s1, slow.s2, slow.offset)
            );
            assert_eq!(fast.window, slow.window);
            for b in [1u8, 7, 0, 200] {
                slow.roll(b);
                fast.roll(b);
                assert_eq!((fast.s1, fast.s2), (slow.s1, slow.s2));
            }
        }
    }

    /// The layers of a fixed stream have the digests they always had: a
    /// layer is made again from its tar-split and its files (a push) with
    /// the digest it was written with, by this build or an earlier one.
    #[test]
    fn test_the_digests_of_a_fixed_stream_do_not_change() {
        let tar = sample_tar();
        let expected = [
            (
                Compression::None,
                "sha256:f538dcba64cbf635bcecda1775ddfdd65fd5063f1de64333e76b638251f758d1",
            ),
            (
                Compression::Gzip,
                "sha256:b0d590cd08e178e86b9497f0feb11873d306f1fb60548976ebd4259f67c667fb",
            ),
            (
                Compression::ZstdChunked,
                "sha256:48eb46208ddd41b3e44048b34739c5a67f3ce24e23b649e64d47299df2c57f3e",
            ),
        ];
        for (c, digest) in expected {
            if !same_zstd(c) {
                continue;
            }
            assert_eq!(write(&tar, c).1.digest.to_string(), digest, "{c:?}");
        }
    }

    /// Whether the digests of `c` can be checked: the zstd output, and so
    /// the digest, depends on the version of the system libzstd, and the
    /// digests were made with 1.5.7.
    fn same_zstd(c: Compression) -> bool {
        const MADE_WITH: u32 = 10507;
        let v = zstd::zstd_safe::version_number();
        if matches!(c, Compression::ZstdChunked) && v != MADE_WITH {
            eprintln!("skipped: the zstd digests were made with libzstd {MADE_WITH}, this is {v}");
            return false;
        }
        true
    }

    /// The same for files of zeros and zero runs (chunks of zeros, a first
    /// chunk that is the whole file, zeros that end a file).
    #[test]
    fn test_the_digests_of_a_fixed_stream_of_zeros_do_not_change() {
        let tar = tar_of(&files_with_zeros());
        let expected = [
            (
                Compression::None,
                "sha256:a7042883ac557a8f1ae59fbf419fe187fc94a730b8b79808e5c796501cc46ef6",
            ),
            (
                Compression::Gzip,
                "sha256:fb9104714ea380c7ee89cbc004c835bd5ae90f6f880038c5c733bd623b430461",
            ),
            (
                Compression::ZstdChunked,
                "sha256:685ee85d234640e242db968376f5eee4bdc4a22daeec2c0933361882f3dfb3b0",
            ),
        ];
        for (c, digest) in expected {
            if !same_zstd(c) {
                continue;
            }
            assert_eq!(write(&tar, c).1.digest.to_string(), digest, "{c:?}");
        }
    }

    #[test]
    fn test_hostile_streams_are_errors() {
        let mut out = Vec::new();
        assert!(write_layer(
            &b"not a tar archive"[..],
            Algorithm::Sha256,
            Compression::Gzip,
            &mut out
        )
        .is_err());
        let mut truncated = sample_tar();
        truncated.truncate(2000);
        assert!(write_layer(
            &truncated[..],
            Algorithm::Sha256,
            Compression::ZstdChunked,
            &mut out
        )
        .is_err());
    }

    fn canonical_entry(name: &str, kind: TocEntryType, size: u64) -> TocEntry {
        TocEntry {
            mode: if kind == TocEntryType::Dir {
                0o755
            } else {
                0o644
            },
            size,
            mod_time: Some("2024-05-06T07:08:09.5Z".to_string()),
            ..TocEntry::new(name.to_string(), kind)
        }
    }

    /// The canonical tar of a root, a directory, files of all sorts of
    /// sizes (one with holes), a symbolic link, a hard link and an xattr.
    fn canonical_tar(extra: impl FnOnce(&mut Vec<TocEntry>)) -> Vec<u8> {
        use TocEntryType::*;
        let mut entries = vec![
            canonical_entry("./", Dir, 0),
            canonical_entry("./etc/", Dir, 0),
            canonical_entry("./etc/empty", Reg, 0),
            canonical_entry("./etc/hard", Hardlink, 0),
            canonical_entry("./etc/holey", Reg, 30_000),
            canonical_entry("./etc/link", Symlink, 0),
            canonical_entry("./etc/random", Reg, 400_000),
            canonical_entry("./etc/small", Reg, 6),
        ];
        entries[3].link_name = Some("./etc/empty".into());
        // (a hard link has the metadata of its target)
        entries[3].mode = 0o644;
        entries[5].link_name = Some("small".into());
        entries[7].xattrs.insert(
            "user.k".into(),
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, b"a\nb"),
        );
        extra(&mut entries);
        let mut rng = rand::rngs::StdRng::seed_from_u64(9);
        let mut tar = Vec::new();
        canonical::write(&entries, &mut tar, |e, out| {
            let mut data = vec![0u8; e.size as usize];
            if e.name == "./etc/random" {
                rng.fill(&mut data[..]);
            } else if e.name == "./etc/small" {
                data.copy_from_slice(b"hello\n");
            } else if e.name == "./etc/holey" {
                data[..5000].fill(1);
                data[25_000..].fill(2);
            }
            out.write_all(&data)
        })
        .unwrap();
        tar
    }

    fn toc_of(blob: &[u8], w: &Written) -> (Toc, Vec<u8>) {
        let a = |k: &str| &w.annotations[&format!("{ANNOTATION_PREFIX}{k}")];
        let pos: Vec<usize> = a("manifest-position")
            .split(':')
            .map(|n| n.parse().unwrap())
            .collect();
        let toc_z = &blob[pos[0]..pos[0] + pos[1]];
        let toc = serde_json::from_slice(&zstd::decode_all(toc_z).unwrap()).unwrap();
        (toc, blob[blob.len() - 64..].to_vec())
    }

    #[test]
    fn test_a_canonical_layer_has_a_version_2_table_and_no_tar_split() {
        let tar = canonical_tar(|_| {});
        let mut blob = Vec::new();
        let w = write_canonical_layer(
            &tar[..],
            Algorithm::Sha256,
            Compression::ZstdChunked,
            None,
            &mut blob,
        )
        .unwrap();
        assert_eq!(w.diff_id, crate::sha256(&tar));
        assert_eq!(w.digest, crate::sha256(&blob));
        let key = |k: &str| format!("{ANNOTATION_PREFIX}{k}");
        assert_eq!(w.annotations[&key("version")], "2");
        assert!(!w.annotations.contains_key(&key("tarsplit-position")));
        let (toc, footer) = toc_of(&blob, &w);
        assert!(toc.is_canonical());
        assert!(toc.tar_split_digest.is_none());
        // the footer has the type 1 and no tar-split
        assert_eq!(footer[24..32], 1u64.to_le_bytes());
        assert!(footer[32..56].iter().all(|&b| b == 0));
        assert_eq!(&footer[56..], b"GNUlInUx");
        // the names are the exact ones of the tar and the root is there
        let names: Vec<_> = toc
            .entries
            .iter()
            .filter(|e| e.entry_type != TocEntryType::Chunk)
            .map(|e| e.name.as_str())
            .collect();
        assert_eq!(names[..2], ["./", "./etc/"]);
        canonical::validate(&toc.entries).unwrap();
        // the blob is the tar for every reader of zstd
        let mut back = Vec::new();
        zstd::stream::read::Decoder::new(&blob[..])
            .unwrap()
            .read_to_end(&mut back)
            .unwrap();
        assert_eq!(back, tar);
        // the same stream gives the same blob
        let mut again = Vec::new();
        write_canonical_layer(
            &tar[..],
            Algorithm::Sha256,
            Compression::ZstdChunked,
            None,
            &mut again,
        )
        .unwrap();
        assert_eq!(again, blob);
        // the tar rebuilt from the table and the contents is the tar
        let mut contents = std::collections::HashMap::new();
        for e in tar::Archive::new(&tar[..]).entries().unwrap() {
            let mut e = e.unwrap();
            let mut data = Vec::new();
            e.read_to_end(&mut data).unwrap();
            let path = e.path().unwrap().to_string_lossy().into_owned();
            contents.insert(
                path.trim_start_matches("./")
                    .trim_end_matches('/')
                    .to_string(),
                data,
            );
        }
        let mut rebuilt = Vec::new();
        canonical::write(&toc.entries, &mut rebuilt, |e, out| {
            out.write_all(&contents[e.name.trim_start_matches("./")])
        })
        .unwrap();
        assert_eq!(rebuilt, tar);
    }

    #[test]
    fn test_the_other_compressions_of_a_canonical_layer_are_its_tar_compressed() {
        let tar = canonical_tar(|_| {});
        for c in [Compression::None, Compression::Gzip] {
            let mut blob = Vec::new();
            let w = write_canonical_layer(&tar[..], Algorithm::Sha256, c, None, &mut blob).unwrap();
            assert_eq!(w.diff_id, crate::sha256(&tar));
            assert!(w.annotations.is_empty());
        }
    }

    #[test]
    fn test_a_stream_that_is_not_canonical_is_not_written_as_version_2() {
        let err = |tar: &[u8]| {
            write_canonical_layer(
                tar,
                Algorithm::Sha256,
                Compression::ZstdChunked,
                None,
                io::sink(),
            )
            .unwrap_err()
            .to_string()
        };
        assert!(err(&sample_tar()).contains("self-check"));
        // an xattr the table cannot keep (the entry of a table that has
        // more than the tar reader reads, or the tar crate's own extra):
        // the table would not say what the tar says
        let tar = canonical_tar(|entries| {
            entries[0].xattrs.insert(
                "user.big".into(),
                base64::Engine::encode(
                    &base64::engine::general_purpose::STANDARD,
                    vec![1u8; 66_000],
                ),
            );
        });
        let e = err(&tar);
        assert!(e.contains("self-check") && e.contains("`./`"), "{e}");
    }

    #[test]
    fn test_what_the_canonical_rules_allow_the_writer_reads() {
        let tar = canonical_tar(|entries| {
            for i in 0..1024 {
                entries[0].xattrs.insert(
                    format!("user.{i:04}"),
                    base64::Engine::encode(&base64::engine::general_purpose::STANDARD, b"v"),
                );
            }
            let mut long = canonical_entry(
                &format!("./etc/zz{}", "z".repeat(4080)),
                TocEntryType::Symlink,
                0,
            );
            long.link_name = Some("x".repeat(4096));
            entries.push(long);
        });
        write_canonical_layer(
            &tar[..],
            Algorithm::Sha256,
            Compression::ZstdChunked,
            None,
            io::sink(),
        )
        .unwrap();
    }

    #[test]
    fn test_parse_compression() {
        assert_eq!(
            Compression::parse("zstd:chunked"),
            Some(Compression::ZstdChunked)
        );
        assert_eq!(Compression::parse("gzip"), Some(Compression::Gzip));
        assert_eq!(Compression::parse("uncompressed"), Some(Compression::None));
        assert_eq!(Compression::parse("lz4"), None);
        // a type that is not known is not taken for an uncompressed layer
        assert_eq!(
            Compression::from_media_type("application/x-layer+lz4"),
            None
        );
        assert_eq!(
            Compression::from_media_type("application/vnd.oci.image.layer.v1.tar"),
            Some(Compression::None)
        );
        assert_eq!(
            Compression::from_media_type("application/vnd.oci.image.layer.v1.tar+zstd"),
            Some(Compression::ZstdChunked)
        );
        assert_eq!(
            Compression::from_media_type("application/vnd.docker.image.rootfs.diff.tar.gzip"),
            Some(Compression::Gzip)
        );
    }
}
