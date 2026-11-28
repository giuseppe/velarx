// SPDX-License-Identifier: Apache-2.0
//! The storage driver of the engine: the trait, its types and the
//! conformance suite are the package `velarx-graph` (re-exported here, so
//! the engine names them as it always did); this module holds the drivers
//! that depend on the engine's services and the one place that makes a
//! driver of a kind.
//!
//! `composefs` stays here for now.  What ties it to the engine is small: the
//! annotations of a sealed image it reads (`services::image::seal`'s
//! `LAYER_EROFS_ANNOTATION`, `layer_digests` and `expected`, functions of the
//! manifest alone), helpers the engine's tests take from it (`driver_for_tests`); the other
//! way, the engine calls `composefs::canonical_image_of` (the sealing of
//! images).  Moving that helper with the driver makes it a package of its own; no other driver
//! needs that (a driver of another package depends on `velarx-graph` and the
//! packages below it, never on `velarx-core`).

use std::sync::Arc;

pub use velarx_graph::*;

pub mod composefs;
#[cfg(test)]
pub(crate) mod watching;
pub use composefs::{ComposefsDriver, ComposefsOptions, ImageServer};
pub use velarx_vfs::{VfsDriver, VfsOptions};

/// The options of the drivers (each reads its own).
#[derive(Debug, Clone)]
pub struct DriverOptions {
    pub composefs: ComposefsOptions,
    pub vfs: VfsOptions,
}

impl DriverOptions {
    /// The options of the drivers of a store: the composefs driver's, the
    /// others' as they are without a configuration.
    pub fn new(composefs: ComposefsOptions) -> Self {
        Self {
            composefs,
            vfs: VfsOptions::default(),
        }
    }
}

/// What the driver `kind` can do, without opening it.
pub fn local_capabilities(kind: velarx_config::StorageDriverKind) -> &'static Capabilities {
    use velarx_config::StorageDriverKind;
    match kind {
        StorageDriverKind::Composefs => ComposefsDriver::capabilities_of(),
        StorageDriverKind::Vfs => VfsDriver::capabilities_of(),
    }
}

/// The driver `kind` of the store made of `parts`.  This is the one place
/// that knows which driver is which: a driver added to `StorageDriverKind`
/// stops this from compiling until it is made here.
pub fn open(
    kind: velarx_config::StorageDriverKind,
    parts: DriverParts,
    options: &DriverOptions,
) -> Arc<dyn StorageDriver> {
    use velarx_config::StorageDriverKind;
    match kind {
        StorageDriverKind::Composefs => Arc::new(ComposefsDriver::new(
            parts.db,
            parts.store,
            parts.staging_dir,
            parts.fsverity,
            options.composefs.clone(),
        )),
        StorageDriverKind::Vfs => Arc::new(VfsDriver::new(parts).with_options(options.vfs.clone())),
    }
}
