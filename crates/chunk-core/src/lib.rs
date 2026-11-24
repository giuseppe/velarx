// SPDX-License-Identifier: Apache-2.0
//! The chunks a table of contents gives a regular file of a zstd:chunked
//! layer, judged before anything is fetched.  The table comes from an image
//! nobody vouched for, so what a pull does with it is decided here, on
//! numbers: the chunks must tile the file exactly, each chunk of data must
//! lie in the compressed range of the file, in order, in a space the size of
//! its bytes can fill, and the pull must stay within its limits.
//!
//! A chunk of data is fetched, a chunk of zeros is a hole: it is written
//! and hashed, not fetched.  The compressed range of a chunk goes from its
//! offset to the offset of the chunk after it, or to the end of the range
//! of the file for the last one; so the offsets of the chunks, holes
//! included, are in order.  What stays in the shell: the digests, the names,
//! the table, and the plan it builds of what is accepted.
//!
//! Written to be translated (tools/verify): plain integers and slices,
//! index loops, no closure, no iterator adapter, no return inside a loop.
//! That `check` returns for every input, and what it accepts and refuses,
//! is proved in Lean (tools/verify/chunk-core).

/// A chunk of the file, as the table says it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Chunk {
    /// Where its bytes begin in the file.
    pub file_off: u64,
    /// How many bytes it has.
    pub size: u64,
    /// Where its compressed bytes begin in the layer.
    pub comp_off: u64,
    /// A hole.
    pub zeros: bool,
}

/// The file the chunks are of.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct File {
    pub size: u64,
    /// The compressed range of the file, `comp_start..comp_end`.  A file
    /// that is not `placed` is of a table that is not of a blob, and has no
    /// offsets: they are not looked at.
    pub comp_start: u64,
    pub comp_end: u64,
    pub placed: bool,
}

/// What a pull holds: the most bytes of a chunk of data, of holes in the
/// layer, and of data to fetch in the layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Caps {
    pub chunk: u64,
    pub zeros: u64,
    pub planned: u64,
}

/// What the files of a layer before this one hold: the bytes of holes and
/// the bytes of data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Totals {
    pub zeros: u64,
    pub planned: u64,
}

/// Why the chunks of a file are refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// A chunk of no bytes, a gap, an overlap, or bytes past the file or
    /// short of it.
    NotTiled,
    /// A chunk of data of more than `Caps::chunk` bytes.
    ChunkTooBig,
    /// The holes of the layer would have more than `Caps::zeros` bytes.
    TooManyZeros,
    /// The data of the layer would have more than `Caps::planned` bytes.
    TooMuchData,
    /// A chunk begins before the compressed range of the file, or before
    /// the chunk before it (the last ends where the range of the file
    /// does), or a chunk of data has no compressed byte.
    Misplaced,
    /// The compressed range of a chunk of data is more than
    /// [`compressed_bound`] of its size.
    CompressedTooBig,
}

/// The largest compressed form of `size` bytes accepted: what zstd needs
/// for data it cannot compress, and some framing.  A chunk whose compressed
/// range is larger is refused before anything of it is fetched (the bytes
/// are buffered before they are decompressed).
pub fn compressed_bound(size: u64) -> u64 {
    size.saturating_add(size / 64).saturating_add(1 << 20)
}

/// `total` and `more` as one sum, if it is at most `cap`.
fn within(total: u64, more: u64, cap: u64) -> Option<u64> {
    match total.checked_add(more) {
        Some(sum) if sum <= cap => Some(sum),
        _ => None,
    }
}

impl Totals {
    /// A layer with no file yet.
    pub const ZERO: Totals = Totals {
        zeros: 0,
        planned: 0,
    };
}

/// The compressed range of the chunk `j` of the file: from its offset to
/// the offset of the chunk after it, or to the end of the range of the
/// file for the last one.  It is a range only for chunks that `check`
/// accepts.
pub fn comp_range(file: &File, chunks: &[Chunk], j: usize) -> (u64, u64) {
    let end = if j + 1 < chunks.len() {
        chunks[j + 1].comp_off
    } else {
        file.comp_end
    };
    (chunks[j].comp_off, end)
}

/// The tiling, the limits, and the compressed ranges of the chunks of `file`
/// (the limits `caps` hold for the layer, of which the files before this one
/// hold `before`): the totals of the layer with this file, or why not.
pub fn check(
    file: &File,
    chunks: &[Chunk],
    caps: &Caps,
    before: &Totals,
) -> Result<Totals, Refusal> {
    let mut totals = *before;
    let mut refusal = None;
    // The bytes of the file the chunks so far tile.
    let mut tiled = 0u64;
    let mut j = 0;
    while j < chunks.len() && refusal.is_none() {
        let c = &chunks[j];
        if c.file_off != tiled || c.size == 0 || c.size > file.size - tiled {
            refusal = Some(Refusal::NotTiled);
        } else if c.zeros {
            match within(totals.zeros, c.size, caps.zeros) {
                Some(sum) => totals.zeros = sum,
                None => refusal = Some(Refusal::TooManyZeros),
            }
        } else if c.size > caps.chunk {
            refusal = Some(Refusal::ChunkTooBig);
        } else {
            match within(totals.planned, c.size, caps.planned) {
                Some(sum) => totals.planned = sum,
                None => refusal = Some(Refusal::TooMuchData),
            }
        }
        if refusal.is_none() {
            tiled += c.size;
        }
        j += 1;
    }
    if refusal.is_none() && tiled != file.size {
        refusal = Some(Refusal::NotTiled);
    }
    if refusal.is_none() && file.placed {
        j = 0;
        while j < chunks.len() && refusal.is_none() {
            let (from, end) = comp_range(file, chunks, j);
            if from < file.comp_start || end < from {
                refusal = Some(Refusal::Misplaced);
            } else if !chunks[j].zeros {
                if end == from {
                    refusal = Some(Refusal::Misplaced);
                } else if end - from > compressed_bound(chunks[j].size) {
                    refusal = Some(Refusal::CompressedTooBig);
                }
            }
            j += 1;
        }
    }
    match refusal {
        Some(why) => Err(why),
        None => Ok(totals),
    }
}

#[cfg(test)]
mod rules;

#[cfg(test)]
mod walk;
