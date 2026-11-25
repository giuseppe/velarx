// SPDX-License-Identifier: Apache-2.0
//! What the packages split off the engine (`velarx-signature`...) and the
//! engine itself share, and that changes rarely.

pub mod atomic_file;
pub mod buildinfo;
pub mod cdi;
pub mod cgroup;
pub mod conf;
pub mod dirs;
pub mod docker;
pub mod entitlement;
pub mod hardening;
pub mod host;
pub mod idmap;
pub mod ids;
pub mod ipc;
pub mod push_path;
pub mod random;
pub mod reference;
pub mod sealed;
pub mod spawn;
pub mod sync;
pub mod testing;
pub mod trace;
pub mod tree;
pub mod walk;

#[cfg(test)]
#[path = "../build-support/version.rs"]
mod build_version;
