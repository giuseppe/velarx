// SPDX-License-Identifier: Apache-2.0
//! A layer read whole and unpacked into the staging directory of its layer:
//! what a fetcher does for `Unpack` (the registry fetcher from the stream its
//! workers decompressed, the directory fetcher as an origin from the blob of
//! an archive).  Each regular file is staged by the object contract (named by
//! the digest of its content in the algorithm of the blob, fs-verity enabled
//! before the name when the scope says verity); the table of contents of what
//! went by and its tar-split are a claim, which the engine replays and checks
//! against the diff id.

use crate::fetcher::fetch::{TARSPLIT, TOC_CLAIM};
use crate::pull::chunked::io_fail;
use crate::pull::entry::{from_header, MAX_ENTRIES};
use crate::pull::tar::{Kind as TarKind, TarReader};
use crate::stager::{put_named, StageError, Unnamed};
use std::fs::File;
use std::io::Read;
use std::os::fd::AsFd;
use velarx_storage::Toc;
use velarx_types::digest::{Algorithm, Digest};
use velarx_types::ImageError;

/// A staging failure as the error of the layer: what the content
/// contradicts is `Contradicted`.
pub fn stage_error(path: &str, e: StageError) -> ImageError {
    match e {
        StageError::BadChunk { .. } | StageError::Wrong(_) | StageError::TooLarge(_) => {
            ImageError::Contradicted(format!("`{path}`: {e}"))
        }
        StageError::Io(e) => ImageError::Io(e),
        e => ImageError::Layer(format!("`{path}`: {e}")),
    }
}

/// Unpack the tar stream `reader` into the staging directory `staging`: each
/// regular file by the object contract, named by the digest in `alg` of its
/// content; the table of contents of what went by and the compressed
/// tar-split.
pub fn unpack_tar<R: Read>(
    reader: R,
    staging: &File,
    alg: Algorithm,
    verity: bool,
) -> Result<(Toc, Vec<u8>), ImageError> {
    let recorder = crate::pull::tarsplit::Recorder::new().map_err(io_fail)?;
    let mut tar = TarReader::with_sink(reader, recorder);
    let mut entries = Vec::new();
    let mut buf = vec![0u8; 256 * 1024];
    while let Some(h) = tar.next_entry().map_err(io_fail)? {
        if entries.len() >= MAX_ENTRIES {
            return Err(ImageError::Layer(format!(
                "the layer has too many entries (more than {MAX_ENTRIES})"
            )));
        }
        let digest = match (h.kind == TarKind::Regular, h.size) {
            (true, 0) => Some(Digest::empty(alg)),
            (true, size) => {
                let file = Unnamed::begin(staging.as_fd(), size)
                    .map_err(io_fail)?
                    .hashed(alg);
                let mut at = 0u64;
                while at < size {
                    let want = buf
                        .len()
                        .min(usize::try_from(size - at).unwrap_or(usize::MAX));
                    let n = tar.read(&mut buf[..want]).map_err(io_fail)?;
                    if n == 0 {
                        return Err(ImageError::Layer("the archive ends in a file".into()));
                    }
                    file.write_chunk(at, &buf[..n], None)
                        .map_err(|e| stage_error(&h.path, e))?;
                    at += n as u64;
                }
                let (d, _) = file
                    .finish_written(staging.as_fd(), verity)
                    .map_err(|e| stage_error(&h.path, e))?;
                Some(d)
            }
            _ => None,
        };
        let digest = digest.map(|d| d.to_string());
        if let Some(e) = from_header(&h, digest.as_deref()).map_err(io_fail)? {
            entries.push(e);
        }
    }
    let (_, recorder) = tar.finish().map_err(io_fail)?;
    let tarsplit = recorder.finish().map_err(io_fail)?.compressed;
    let toc = Toc {
        version: velarx_storage::TOC_VERSION,
        entries,
        tar_split_digest: None,
    };
    Ok((toc, tarsplit))
}

/// Give the table of contents `toc` and the tar-split their names in the
/// staging of the layer, last: the names say the layer was unpacked
/// (`indexed`).
pub fn put_claim(staging: &File, toc: &Toc, tarsplit: &[u8]) -> Result<(), ImageError> {
    let claim = serde_json::to_vec(toc)?;
    put_named(staging.as_fd(), TOC_CLAIM, &claim)
        .and_then(|()| put_named(staging.as_fd(), TARSPLIT, tarsplit))
        .map_err(|e| stage_error("the index of the layer", e))
}
