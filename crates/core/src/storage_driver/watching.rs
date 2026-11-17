// SPDX-License-Identifier: Apache-2.0
//! A driver that wraps another and changes or watches what the tests need: its
//! capabilities are the ones it is given (composefs as a driver whose
//! writable layer is not an overlay's upper, what a copy-based driver says),
//! and every `collect` is recorded.

use super::*;
use std::sync::{Arc, Mutex};
use velarx_graph::forward_storage_driver;

pub(crate) struct Watching {
    inner: Arc<dyn StorageDriver>,
    caps: Capabilities,
    /// What each collection was told to keep, in order.
    pub(crate) collected: Mutex<Vec<Keep>>,
    /// The stores it was told to drop (it answers as a driver of stores
    /// does: done).
    pub(crate) dropped: Mutex<Vec<String>>,
}

impl Watching {
    pub(crate) fn new(inner: Arc<dyn StorageDriver>, caps: Capabilities) -> Self {
        Self {
            inner,
            caps,
            collected: Mutex::new(Vec::new()),
            dropped: Mutex::new(Vec::new()),
        }
    }
}

forward_storage_driver! {
    impl StorageDriver for Watching {
        inner: inner;
        forward: [name graph_name graph_data status pull has_layers repair remake_staged read_objects open_object objects_in_order remove_image image_volume_create mounts image_view holds_objects leftovers check writable_create writable_paths writable_root writable_size writable_remove writable_release writable_exists diff changes apply stopped_view is_root_of usage list_stores release_engine_copies lock_unused_layers];
        fn capabilities(&self) -> &Capabilities {
            &self.caps
        }
        fn collect(&self, keep: &Keep) -> DriverResult<Collected> {
            self.collected
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(keep.clone());
            self.inner.collect(keep)
        }
        fn drop_store(&self, store: &str) -> DriverResult<()> {
            self.dropped.lock().unwrap().push(store.to_string());
            Ok(())
        }
    }
}
