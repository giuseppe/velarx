// SPDX-License-Identifier: Apache-2.0
//! What of a container survives a reboot, and where.
//!
//! The state directory (`/run/velarx`, `$XDG_RUNTIME_DIR/velarx`) is a
//! tmpfs that a boot empties: it keeps what the processes of the running
//! containers need (the monitors' run directories, the runtime's state,
//! the networks).  The data of a container lives under the root directory
//! (`root_dir`): its bundle (configuration, layers, the upper directory of
//! its overlay with its own changes), its log and its secrets; volumes and
//! pods too.

use super::container::ContainerService;
use std::path::PathBuf;

impl ContainerService {
    /// The bundle of a container.
    pub fn bundle_dir(&self, id: &str) -> PathBuf {
        self.root_dir.join("bundles").join(id)
    }

    /// The writable layer of a container, as the storage driver is asked
    /// about it.
    pub fn writable(&self, id: &str) -> crate::storage_driver::Writable {
        crate::storage_driver::Writable::new(id, self.bundle_dir(id))
    }

    /// The storage driver of the store.
    pub fn storage(&self) -> &std::sync::Arc<dyn crate::storage_driver::StorageDriver> {
        self.image_service.storage()
    }

    /// Where the writable layer of a container is.
    pub fn writable_paths(&self, id: &str) -> crate::storage_driver::WritablePaths {
        self.storage().writable_paths(&self.writable(id))
    }

    /// The directory that holds the bundles.
    pub(crate) fn bundles_dir(&self) -> PathBuf {
        self.root_dir.join("bundles")
    }

    /// The files of the secrets of a container, which go with it.
    pub fn secrets_dir_of(&self, id: &str) -> PathBuf {
        self.root_dir.join("secrets").join(id)
    }

    /// Where the secrets of the containers are, for a check of a path.
    pub(crate) fn secrets_dir(&self) -> PathBuf {
        self.root_dir.join("secrets")
    }

    /// The directory of the logs of a container.
    pub fn log_dir(&self, id: &str) -> PathBuf {
        self.root_dir.join("logs").join(id)
    }
}
