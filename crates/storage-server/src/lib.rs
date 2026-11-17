// SPDX-License-Identifier: Apache-2.0
//! The reference server of `org.velarx.Storage`: the vfs storage driver
//! (`velarx-vfs`) behind a unix socket.
//!
//! It is the other end of `velarx_storage_client::VarlinkDriver`: each call of
//! the interface is mapped to the method of the driver it came from, the pull
//! is driven through `org.velarx.StorageFeed` (the server is the client of the
//! feed the engine serves on the descriptor `BeginPull` hands over), and the
//! store of each pair of the uid of the peer and the id of the store is a
//! directory of its own under the root of the server.  The server plays the
//! engine's part for its own store: it records the layers it was told to
//! commit in a database of the store, which the vfs driver reads, and
//! collects what the keep set does not name.  It shares with vfs everything
//! that makes the files of a container (the copy of the layers, the
//! mounts, the checks) and stores no more than vfs does.
//!
//! What it deliberately lacks: lazy images (the engine runs an image that is
//! being pulled lazily from its own files, and gives the server its layers
//! complete), a size limit of the writable
//! layer, layers with no table of contents (the engine refuses them before
//! `BeginPull`), copies of chunks between objects (`copy` events), and
//! several users' stores in one process beyond the isolation by the uid of
//! the peer.

#[cfg(feature = "conformance")]
pub mod conformance;
mod feed;
mod pull;
mod roots;
mod service;
mod store;

pub use service::{parse_idle, Config, Running, Server, DEFAULT_IDLE_SECS};
