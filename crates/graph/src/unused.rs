// SPDX-License-Identifier: Apache-2.0
//! Asking a driver which layers nothing uses, a batch at a time.
//!
//! [`StorageDriver::lock_unused_layers`] holds a descriptor for each layer it
//! finds unused, until the caller is done with the layer.  Every caller that
//! removes many layers goes through [`unused_batches`], so that none holds
//! more than [`LOCK_BATCH`] of them at once: a removal of more layers than the
//! limit of open files goes in turns instead of failing with `EMFILE`, and
//! every such path answers for a layer in use the same way.

use crate::{DriverResult, Hold, StorageDriver};
use velarx_db::LayerKey;

/// The most layers a caller holds the lock of at once: far below the soft
/// limit of open files a shell gives (1024), so that the removal of any number
/// of layers is never refused for want of descriptors.
pub const LOCK_BATCH: usize = 256;

/// Up to [`LOCK_BATCH`] items, split by what the driver found.  The layers of
/// `unused` cannot be taken by a mount or a server until this is dropped (the
/// hold of the driver): the caller removes them, drops the batch, and only
/// then asks for the next.
pub struct UnusedBatch<T> {
    /// The items nothing uses (and those that name no layer).
    pub unused: Vec<T>,
    /// The items a mount or a server uses: the caller keeps them.
    pub in_use: Vec<T>,
    _hold: Hold,
}

/// The batches of `items`, in order ([`unused_batches`]).
pub struct UnusedBatches<'a, T, K> {
    driver: &'a dyn StorageDriver,
    items: std::vec::IntoIter<T>,
    key: K,
}

/// Ask `driver` which of `items` something uses ([`LayerKey`] of each by
/// `key`; an item that names no layer is unused), [`LOCK_BATCH`] at a time.  A
/// failure to tell is the error of its batch: the caller stops, nothing is
/// removed on a guess.
pub fn unused_batches<T, K: Fn(&T) -> Option<LayerKey>>(
    driver: &dyn StorageDriver,
    items: Vec<T>,
    key: K,
) -> UnusedBatches<'_, T, K> {
    UnusedBatches {
        driver,
        items: items.into_iter(),
        key,
    }
}

impl<T, K: Fn(&T) -> Option<LayerKey>> Iterator for UnusedBatches<'_, T, K> {
    type Item = DriverResult<UnusedBatch<T>>;

    fn next(&mut self) -> Option<Self::Item> {
        let items: Vec<T> = self.items.by_ref().take(LOCK_BATCH).collect();
        if items.is_empty() {
            return None;
        }
        let keys: Vec<LayerKey> = items.iter().filter_map(&self.key).collect();
        let found = match self.driver.lock_unused_layers(&keys) {
            Ok(f) => f,
            Err(e) => return Some(Err(e)),
        };
        let (mut unused, mut in_use) = (Vec::new(), Vec::new());
        for item in items {
            match (self.key)(&item) {
                Some(k) if found.in_use.contains(&k) => in_use.push(item),
                _ => unused.push(item),
            }
        }
        Some(Ok(UnusedBatch {
            unused,
            in_use,
            _hold: found.hold,
        }))
    }
}
