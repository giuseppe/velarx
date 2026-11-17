// SPDX-License-Identifier: Apache-2.0
//! What is served to a peer: the limit and the bytes of a chunk in a file.

/// The most a chunk (or file) served to a peer may weigh.
pub const MAX_SERVED_BYTES: usize = 16 * 1024 * 1024;

/// The bytes of a chunk in a file: `len` bytes of `file` from `offset`.
#[derive(Debug)]
pub struct ChunkFile {
    pub file: std::fs::File,
    pub offset: u64,
    pub len: u64,
}
