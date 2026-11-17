// SPDX-License-Identifier: Apache-2.0
//! What the engine does for its callers: the operations (`ops`), the
//! REST routes it serves for the frontend that forwards them
//! (`podman`), and the state they share.  The HTTP is the frontend's
//! (`velarx-api`); the engine is served over varlink (`engine_service`).
pub mod build_credentials;
pub mod ops;
pub mod podman;
pub mod status;

use std::sync::Arc;
use velarx_config::Config;
use velarx_core::services::{
    BuildService, ContainerService, ImageService, PodService, ServerService, VolumeService,
};
use velarx_db::Database;
use velarx_runtime::network::NetworkService;
use velarx_runtime::userns::UserNamespaceManager;

/// The file work of a handler, in one turn of the blocking pool: one turn
/// for a request, not one for each file.
pub use velarx_runtime::off_thread;

/// Run `work`, which blocks, from an async thread that cannot await it (the
/// helper lives in velarx-graph, for the storage drivers that call it too).
pub use velarx_core::storage_driver::blocking;

pub struct AppState {
    pub config: Arc<Config>,
    pub db: Database,
    pub image_service: Arc<ImageService>,
    pub container_service: Arc<ContainerService>,
    pub network_service: Arc<NetworkService>,
    pub userns_manager: Arc<UserNamespaceManager>,
    pub server_service: Arc<ServerService>,
    pub volume_service: Arc<VolumeService>,
    pub build_service: Arc<BuildService>,
    pub pod_service: Arc<PodService>,
    pub podman: podman::PodmanState,
    pub build_asks: Arc<build_credentials::Asks>,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `off_thread` gives back the answer of its work (the tests of
    /// `blocking` are in velarx-graph, with it).
    #[test]
    fn off_thread_answers() {
        let many = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .build()
            .unwrap();
        let off = many.block_on(off_thread(|| Ok(6)));
        assert_eq!(off.unwrap(), 6);
    }
}
