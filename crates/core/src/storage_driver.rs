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

/// The options of the drivers (each reads its own).
#[derive(Debug, Clone)]
pub struct DriverOptions {
    pub composefs: ComposefsOptions,
}

impl DriverOptions {
    /// The options of the drivers of a store.
    pub fn new(composefs: ComposefsOptions) -> Self {
        Self { composefs }
    }
}

/// What the driver can do, without opening it.
pub fn local_capabilities() -> &'static Capabilities {
    ComposefsDriver::capabilities_of()
}

/// The driver of the store made of `parts`.
pub fn open(parts: DriverParts, options: &DriverOptions) -> Arc<dyn StorageDriver> {
    Arc::new(ComposefsDriver::new(
        parts.db,
        parts.store,
        parts.staging_dir,
        parts.fsverity,
        options.composefs.clone(),
    ))
}
