// SPDX-License-Identifier: Apache-2.0
//! The rules of the chunks of a file, checked on every answer of `check`.
//! They are stated by what the chunks mean, in wide integers that cannot
//! overflow, not by how `check` walks them: an answer is `Ok` exactly when
//! every statement below holds, and a refusal names a statement that does
//! not.  "Exactly" is for `before` within the caps, which the walk keeps
//! (it skips the others): `check` judges this file, so with `before` over a
//! cap and a file that adds nothing to it, it accepts.  That never happens
//! in a pull, which passes zero, or the totals an earlier `check` returned.
//!
//! What a file accepted is: its chunks tile `[0, size)` in order, each of at
//! least one byte, with no gap and no overlap; the holes of the layer and
//! the data of the layer are within their caps, and a chunk of data within
//! its own; and, for a file that is placed, the compressed range of each
//! chunk (from its offset to the next one, the last to the end of the range
//! of the file) lies in the range of the file, the ranges follow each other
//! and do not overlap, and the range of a chunk of data has a byte and is
//! within the bound of its size.

use super::*;

/// The chunks tile the file: each begins where the ones before it end, has
/// a byte, and all of them end where the file ends.
fn tiles(file: &File, chunks: &[Chunk]) -> bool {
    let mut end = 0u128;
    for c in chunks {
        if c.file_off as u128 != end || c.size == 0 {
            return false;
        }
        end += c.size as u128;
    }
    end == file.size as u128
}

/// The bytes of the chunks that are (or are not) holes.
fn bytes(chunks: &[Chunk], zeros: bool) -> u128 {
    let mut sum = 0u128;
    for c in chunks {
        if c.zeros == zeros {
            sum += c.size as u128;
        }
    }
    sum
}

/// The compressed range of the chunk `j`, as numbers that may not be a range.
fn range(file: &File, chunks: &[Chunk], j: usize) -> (u128, u128) {
    let end = match chunks.get(j + 1) {
        Some(next) => next.comp_off,
        None => file.comp_end,
    };
    (chunks[j].comp_off as u128, end as u128)
}

/// The compressed range of every chunk is in the range of the file.
fn in_the_file(file: &File, chunks: &[Chunk]) -> bool {
    (0..chunks.len()).all(|j| {
        let (from, to) = range(file, chunks, j);
        file.comp_start as u128 <= from && from <= to && to <= file.comp_end as u128
    })
}

/// The ranges follow each other: no range of a chunk begins before another
/// one before it ends.  Each range ends where the next begins, so this
/// follows from `in_the_file` (each begins no later than it ends); it is
/// stated on its own, as what the rule means, and checked as such.
fn in_order(file: &File, chunks: &[Chunk]) -> bool {
    (0..chunks.len()).all(|j| {
        (j + 1..chunks.len()).all(|k| range(file, chunks, j).1 <= range(file, chunks, k).0)
    })
}

/// Each chunk of data has a compressed byte.
fn data_has_bytes(file: &File, chunks: &[Chunk]) -> bool {
    (0..chunks.len()).all(|j| {
        let (from, to) = range(file, chunks, j);
        chunks[j].zeros || from < to
    })
}

/// The range of a chunk of data is at most the size of the chunk, with a
/// sixty-fourth more, and a mebibyte.
fn within_the_bound(file: &File, chunks: &[Chunk]) -> bool {
    (0..chunks.len()).all(|j| {
        let (from, to) = range(file, chunks, j);
        let size = chunks[j].size as u128;
        chunks[j].zeros || to < from || to - from <= size + size / 64 + (1 << 20)
    })
}

/// A chunk of data is bigger than the cap of a chunk.
fn too_big(chunks: &[Chunk], caps: &Caps) -> bool {
    chunks.iter().any(|c| !c.zeros && c.size > caps.chunk)
}

/// Checks the answer of `check` for a file; a rule that fails panics with
/// its words and the input.
pub fn verify(
    file: &File,
    chunks: &[Chunk],
    caps: &Caps,
    before: &Totals,
    answer: Result<Totals, Refusal>,
) {
    let what = || format!("{file:?} {chunks:?} {caps:?} {before:?}: {answer:?}");
    let zeros = before.zeros as u128 + bytes(chunks, true);
    let planned = before.planned as u128 + bytes(chunks, false);
    let tiled = tiles(file, chunks);
    let ranged = !file.placed || (in_the_file(file, chunks) && in_order(file, chunks));
    let have_bytes = !file.placed || data_has_bytes(file, chunks);
    let bounded = !file.placed || within_the_bound(file, chunks);
    let valid = tiled
        && !too_big(chunks, caps)
        && zeros <= caps.zeros as u128
        && planned <= caps.planned as u128
        && ranged
        && have_bytes
        && bounded;

    match answer {
        // Everything holds, and the layer has what the chunks add to it.
        Ok(totals) => {
            assert!(valid, "accepted what is not valid: {}", what());
            assert_eq!(totals.zeros as u128, zeros, "zeros: {}", what());
            assert_eq!(totals.planned as u128, planned, "planned: {}", what());
        }
        // Nothing is refused for nothing, and the reason is one that holds.
        Err(why) => {
            assert!(!valid, "refused what is valid: {}", what());
            let holds = match why {
                Refusal::NotTiled => !tiled,
                Refusal::ChunkTooBig => too_big(chunks, caps),
                Refusal::TooManyZeros => zeros > caps.zeros as u128,
                Refusal::TooMuchData => planned > caps.planned as u128,
                Refusal::Misplaced => file.placed && !(ranged && have_bytes),
                Refusal::CompressedTooBig => file.placed && !bounded,
            };
            assert!(holds, "refused for what does not hold: {}", what());
        }
    }
}
