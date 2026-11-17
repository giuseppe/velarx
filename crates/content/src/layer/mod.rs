// SPDX-License-Identifier: Apache-2.0
//! Layers as tar streams, rebuilt from the store.
//!
//! A layer is kept as its table of contents, the files of the store and its
//! tar-split.  Replaying the tar-split with those files gives the exact
//! uncompressed stream, whose digest is the diff id.  `dirtar` makes the
//! stream of the changes in a directory (commit, build).

pub mod dirtar;
pub mod holes;
pub mod reproduce;
pub mod writer;
