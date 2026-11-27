// SPDX-License-Identifier: Apache-2.0
//! The stream of a layer: the frames of its tar (`decompress` inflates what
//! a worker received and hashes the tar, the diff id), and the staging of a
//! regular file of a layer made here (`stage_file`).

use super::sink::Sink;
use super::LayerReport;
use bytes::Bytes;
use std::io::{self, Read};
use std::sync::Arc;
use tokio::sync::mpsc;
use velarx_storage::Toc;
use velarx_types::digest::{Algorithm, Digest, DigestWriter};

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
/// not kept, and is known by the digest the store has it by.
pub(super) fn stage_file<R: Read>(
    session: &dyn Sink,
    alg: Algorithm,
    entry: &mut R,
    size: u64,
) -> io::Result<StagedFile> {
    if let Some((key, added)) = session.put_reader(alg, entry, size)? {
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
        let (key, added) = session.put_measured(&content, &verity, &data)?;
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
    let (key, added) = session.adopt_measured(&path, &content, &verity.finish(), size)?;
    Ok(StagedFile {
        key,
        content,
        added,
    })
}
