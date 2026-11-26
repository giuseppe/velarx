// SPDX-License-Identifier: Apache-2.0
//! The registry fetcher, `velarx-registry`: the process that makes the
//! requests to the registries for velarx and serves `org.velarx.Registry`
//! beside the fetcher interface.  The interface `org.velarx.Fetcher`, its
//! types, its clients and its serving end are in `velarx_content`; this
//! crate is what links an HTTP client: the registry as a fetcher
//! (`registry`, `registry_fetch`), what its confinement reaches (`confine`,
//! the confinement itself is `velarx_sandbox::fetch`) and the requests of
//! its confined workers (`net`).  Only `velarx-registry` depends on it.

pub mod confine;
pub mod net;
pub mod registry;
pub mod registry_fetch;
pub mod registry_push;
mod signatures;

/// The sha256 digest of `data`, for the tests.
#[cfg(test)]
pub(crate) fn sha256(data: &[u8]) -> velarx_types::digest::Digest {
    velarx_types::digest::Digest::of(velarx_types::digest::Algorithm::Sha256, data)
}
