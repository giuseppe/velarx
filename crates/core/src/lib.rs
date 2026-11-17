// SPDX-License-Identifier: Apache-2.0
//! The core of the engine: the services (containers, images, builds, pods,
//! volumes, networks ...), the container runtime, the monitor of a container,
//! the networks, the user namespaces, the CDI devices and the store service.
//! The frontends (the command line, the API server, the daemon) are above.

pub mod image_fetch;
pub mod services;
pub mod storage_driver;
pub mod store_service;
#[cfg(test)]
mod testing;

// (the runtime is a package of its own, below the services: an edit of the
// services does not rebuild it; its modules keep their paths here)
pub(crate) use velarx_runtime::{cdi, container, monitor, network, off_thread, userns};
