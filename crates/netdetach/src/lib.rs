// SPDX-License-Identifier: Apache-2.0
//! The release of the network of a container.
//!
//! The setup of a container's network is the engine's (`velarx-runtime`).
//! What undoes it when the container ends is here, with the rows of the
//! database it reads, so that the engine and the monitor of the container run
//! the very same code: the monitor releases the network itself, with no
//! engine alive.  Blocking, no async runtime; the database is reached through
//! `velarx_db::sync::Access`.

pub mod def;
pub mod input;
pub mod pool;
pub mod provider;
pub mod rootless;
pub mod spec;
pub mod teardown;
