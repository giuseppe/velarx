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
pub mod lazy_phase;
#[cfg(test)]
pub(crate) mod watching;
pub use composefs::{ComposefsDriver, ComposefsOptions, ImageServer};
pub use lazy_phase::LazyPhase;
pub use velarx_vfs::{VfsDriver, VfsOptions};

/// The options of the drivers (each reads its own).
#[derive(Debug, Clone)]
pub struct DriverOptions {
    pub composefs: ComposefsOptions,
    pub vfs: VfsOptions,
    /// The `varlink` driver's service and the graph root its store id and work
    /// directory are in; none: that driver cannot be opened.
    pub varlink: Option<VarlinkOptions>,
}

impl DriverOptions {
    /// The options of the drivers of a store: the composefs driver's, the
    /// others' as they are without a configuration.
    pub fn new(composefs: ComposefsOptions) -> Self {
        Self {
            composefs,
            vfs: VfsOptions::default(),
            varlink: None,
        }
    }
}

/// What opens the `varlink` driver: `[storage.varlink]` and the graph root
/// (`[storage] root`).
#[derive(Debug, Clone)]
pub struct VarlinkOptions {
    pub config: velarx_config::VarlinkStorage,
    pub graph_root: std::path::PathBuf,
}

impl VarlinkOptions {
    /// The options `[storage]` says, none for a configuration without
    /// `[storage.varlink]`.
    pub fn of(storage: &velarx_config::StorageConfig) -> Option<Self> {
        storage.varlink.as_ref().map(|config| Self {
            config: config.clone(),
            graph_root: storage.root.clone(),
        })
    }
}

/// What the driver `kind` can do when it is a part of this process, without
/// opening it; none for the `varlink` driver, which is a program of its own.
pub fn local_capabilities(kind: velarx_config::StorageDriverKind) -> Option<&'static Capabilities> {
    use velarx_config::StorageDriverKind;
    match kind {
        StorageDriverKind::Composefs => Some(ComposefsDriver::capabilities_of()),
        StorageDriverKind::Vfs => Some(VfsDriver::capabilities_of()),
        StorageDriverKind::Varlink => None,
    }
}

/// The driver `kind` of the store made of `parts` when it is a part of this
/// process (`composefs`, `vfs`); none for the `varlink` driver, a program of
/// its own that [`open`] connects to.  This and `open` are the one place that
/// knows which driver is which: a driver added to `StorageDriverKind` stops
/// this from compiling until it is made here.
pub fn open_local(
    kind: velarx_config::StorageDriverKind,
    parts: DriverParts,
    options: &DriverOptions,
) -> Option<Arc<dyn StorageDriver>> {
    use velarx_config::StorageDriverKind;
    match kind {
        StorageDriverKind::Composefs => Some(Arc::new(ComposefsDriver::new(
            parts.db,
            parts.store,
            parts.staging_dir,
            parts.fsverity,
            options.composefs.clone(),
        ))),
        StorageDriverKind::Vfs => Some(Arc::new(
            VfsDriver::new(parts).with_options(options.vfs.clone()),
        )),
        StorageDriverKind::Varlink => None,
    }
}

/// The driver `kind` of the store made of `parts`.  The `varlink` driver
/// connects to its service now: one that is not there, or speaks another
/// version, is the error.
pub fn open(
    kind: velarx_config::StorageDriverKind,
    parts: DriverParts,
    options: &DriverOptions,
) -> DriverResult<Arc<dyn StorageDriver>> {
    use velarx_config::StorageDriverKind;
    match kind {
        StorageDriverKind::Composefs | StorageDriverKind::Vfs => open_local(kind, parts, options)
            .ok_or_else(|| DriverError::storage("storage", "the driver is not in this process")),
        StorageDriverKind::Varlink => open_service(parts, options),
    }
}

/// The `varlink` driver: the service, and the engine's own `composefs` driver
/// that runs an image while it is pulled lazily ([`LazyPhase`]).
fn open_service(
    parts: DriverParts,
    options: &DriverOptions,
) -> DriverResult<Arc<dyn StorageDriver>> {
    let varlink = options.varlink.as_ref().ok_or_else(|| {
        DriverError::storage(
            "varlink",
            "the storage driver varlink needs [storage.varlink] socket = \"/path\"",
        )
    })?;
    let service = Arc::new(open_varlink(varlink)?);
    // (the files of the layers are the service's: the database reads them
    // from it)
    parts.db.clone().with_layer_files(service.clone());
    let local = Arc::new(ComposefsDriver::new(
        parts.db,
        parts.store,
        parts.staging_dir,
        parts.fsverity,
        options.composefs.clone(),
    ));
    Ok(Arc::new(LazyPhase::new(
        service as Arc<dyn StorageDriver>,
        local,
    )))
}

/// The `varlink` driver at the socket of `options`: the store id of the graph
/// root, `GetInfo` with its version checked, and the name the configuration
/// expects the service to give.
fn open_varlink(options: &VarlinkOptions) -> DriverResult<velarx_storage_client::VarlinkDriver> {
    let socket =
        options.config.socket.clone().ok_or_else(|| {
            DriverError::storage("varlink", "[storage.varlink] socket is required")
        })?;
    let driver = velarx_storage_client::VarlinkDriver::open(velarx_storage_client::Options {
        link: velarx_storage_client::Link {
            socket: socket.clone(),
            timeout: std::time::Duration::from_secs(options.config.timeout_secs),
        },
        graph_root: options.graph_root.clone(),
    })?;
    match &options.config.name {
        Some(expected) if driver.name() != expected => Err(DriverError::storage(
            driver.name(),
            format!(
                "the storage service on {} calls itself {:?}, and `[storage.varlink] name = {expected:?}` expects another service: check the socket",
                socket.display(),
                driver.name()
            ),
        )),
        _ => Ok(driver),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use velarx_config::StorageDriverKind;

    async fn parts(dir: &std::path::Path) -> DriverParts {
        DriverParts {
            db: velarx_db::Database::open_in_memory().await.unwrap(),
            store: Arc::new(velarx_storage::FileStore::new(dir.join("objects")).unwrap()),
            staging_dir: dir.join("staging"),
            fsverity: velarx_storage::VerityMode::Off,
        }
    }

    fn options(dir: &std::path::Path) -> DriverOptions {
        DriverOptions::new(composefs::options_for_tests(dir))
    }

    fn varlink(socket: std::path::PathBuf, root: &std::path::Path) -> DriverOptions {
        DriverOptions {
            varlink: Some(VarlinkOptions {
                config: velarx_config::VarlinkStorage {
                    socket: Some(socket),
                    timeout_secs: 2,
                    name: None,
                },
                graph_root: root.to_path_buf(),
            }),
            ..options(root)
        }
    }

    /// The `varlink` driver is connected to when it is opened: a socket that
    /// is not there is `Unavailable` and says to start the service (not a
    /// wait), the id of the store is made first, and a driver that has no
    /// `[storage.varlink]` says so.
    #[tokio::test]
    async fn the_varlink_driver_is_unavailable_when_its_service_is_not_there() {
        let tmp = tempfile::tempdir().unwrap();
        let kind = StorageDriverKind::Varlink;
        let e = open(kind, parts(tmp.path()).await, &options(tmp.path()))
            .map(|_| ())
            .unwrap_err();
        assert!(e.to_string().contains("[storage.varlink]"), "{e}");
        assert!(open_local(kind, parts(tmp.path()).await, &options(tmp.path())).is_none());
        let socket = tmp.path().join("none.sock");
        let started = std::time::Instant::now();
        let e = open(
            kind,
            parts(tmp.path()).await,
            &varlink(socket.clone(), tmp.path()),
        )
        .map(|_| ())
        .unwrap_err();
        assert!(matches!(e.kind, DriverErrorKind::Unavailable), "{e:?}");
        let words = e.to_string();
        assert!(
            words.contains(&socket.display().to_string())
                && words.contains("start the storage service"),
            "{words}"
        );
        assert!(started.elapsed() < std::time::Duration::from_secs(2));
    }
}
