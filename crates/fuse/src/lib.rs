// SPDX-License-Identifier: Apache-2.0
//! The images of the layers (`layer_erofs`), made at the pull, and what reads
//! them: the FUSE file system of the monitors that serves them rootless with
//! the ids of a container (`erofs_tree`, `idtranslate`, `image_fs`), and the
//! lookups of the engine in the root file system they make (`view`).  The
//! tree of the tables of contents (`merged`) is what the builds read.

pub mod canonical;
pub mod composefs;
pub mod detached;
pub mod erofs_read;
pub mod erofs_tree;
mod idtranslate;
mod image_fs;
#[cfg(test)]
mod inline_tests;
pub mod layer_erofs;
mod merged;
mod merged_view;
pub mod mounted;
pub mod plan;
pub mod profile;
mod tree;
pub mod verity;
pub mod view;

pub use idtranslate::IdTranslate;
pub use image_fs::*;
pub use merged::*;
pub use merged_view::MergedView;
pub use mounted::MountedImage;

use std::path::PathBuf;
use std::time::Duration;
use thiserror::Error;

/// Callback trait for fetching files on demand during lazy pull.
/// This is implemented by ImageService to connect FUSE to actual data sources.
///
/// IMPORTANT: This trait is called from a sync context (FUSE thread) but needs
/// to perform async operations. The implementation must handle the sync/async
/// bridge internally.
pub trait LazyFileFetcher: Send + Sync + 'static {
    /// Fetch a file by its digest, blocking until complete or `timeout`
    /// (none: until it is, or the fetch fails).
    /// Returns the path to the fetched file in the FileStore.
    fn fetch_file_blocking(
        &self,
        file_digest: &str,
        layer_digest: &str,
        timeout: Option<Duration>,
    ) -> Result<PathBuf, String>;

    /// A thread that will fetch (a `fetch` worker of a mount) starts: what it
    /// does first, before any fetch (the image server confines it).  An
    /// error ends the thread: it fetches nothing.
    fn thread_started(&self) -> Result<(), String> {
        Ok(())
    }
}

#[derive(Error, Debug)]
pub enum FuseError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("mount error: {0}")]
    Mount(String),
}

pub type FuseResult<T> = Result<T, FuseError>;
