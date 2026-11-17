// SPDX-License-Identifier: Apache-2.0
//! Fetchers: the processes that bring the content of images into the
//! staging directories of a store (`org.velarx.Fetcher`, `interfaces/org.velarx.Fetcher.varlink`).
//! [`fetch`] has the types of the interface, [`fetch_client`] the engine's
//! typed client; [`proto`] the types of `org.velarx.Registry` the registry
//! fetcher serves besides.

pub mod fetch;
pub mod fetch_client;
pub mod proto;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::Notify;

/// A chunk of a file: the digest of the file and the index of the chunk in
/// the list of the chunks of the file.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ChunkId {
    pub file: String,
    pub index: u32,
}

/// Where the compressed bytes of a chunk are in the blob of its layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlobRange {
    pub offset: u64,
    pub length: u64,
}

/// A chunk as the table of contents gives it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChunkRef {
    pub id: ChunkId,
    /// Digest of the uncompressed bytes; empty when the table of contents
    /// has none for the chunk, which then only the origin can serve (the
    /// digest of the file covers it)
    pub digest: String,
    /// Their number
    pub size: u64,
    /// Where they go in the file
    pub offset: u64,
    /// A hint for the fetchers that read blobs; a wrong one gives wrong
    /// bytes, which fail the check
    pub blob: Option<BlobRange>,
}

/// A request is cancelled by whoever made it; the fetcher drops the work.
#[derive(Clone, Default)]
pub struct Cancel {
    inner: Arc<CancelState>,
}

#[derive(Default)]
struct CancelState {
    cancelled: AtomicBool,
    notify: Notify,
}

impl Cancel {
    pub fn cancel(&self) {
        self.inner.cancelled.store(true, Ordering::Release);
        self.inner.notify.notify_waiters();
    }

    pub fn is_cancelled(&self) -> bool {
        self.inner.cancelled.load(Ordering::Acquire)
    }

    /// Resolves when the request is cancelled.
    pub async fn cancelled(&self) {
        loop {
            let notified = self.inner.notify.notified();
            if self.is_cancelled() {
                return;
            }
            notified.await;
        }
    }
}
