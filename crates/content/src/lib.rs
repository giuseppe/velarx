// SPDX-License-Identifier: Apache-2.0
//! How the content of images gets into the store, without a network client:
//! the pull (sessions, the walker of the fetchers, chunked and lazy layers,
//! the client of the registry fetcher), the interface of the fetchers and
//! its serving end (`serve_fetch`, `stager`, a directory as a fetcher), the
//! layers (tar and EROFS writers, the
//! merged views) and the image archives.  The requests to the registries
//! are made by the fetcher process (`velarx-registry`).

pub mod activation;
pub mod archive;
/// Telling gzip and zstd by the first bytes and reading them, the window of zstd capped.
pub use velarx_tarsplit::decompress;
pub mod dir_fetch;
pub mod dir_origin;
pub mod dir_push;
#[cfg(any(test, feature = "test-support"))]
pub mod fakes;
pub mod fetcher;
pub mod idle;
pub mod imagefetch;
#[cfg(test)]
mod interface_tests;
pub mod layer;
pub mod list;
pub mod origin;
pub mod pull;
pub mod push;
pub mod pusher;
pub mod serve_fetch;
pub mod serve_push;
pub mod serve_registry;
pub mod shared;
pub mod stager;
pub mod unpack;

/// The sha256 digest of `data`, for the tests.
#[cfg(test)]
pub(crate) fn sha256(data: &[u8]) -> velarx_types::digest::Digest {
    velarx_types::digest::Digest::of(velarx_types::digest::Algorithm::Sha256, data)
}

/// The sha256 digest of `data` as text, for the tests.
#[cfg(test)]
pub(crate) fn sha256_text(data: &[u8]) -> String {
    sha256(data).to_string()
}

/// The object name (the fs-verity digest in SHA-256) of `data`, for the tests.
#[cfg(test)]
pub(crate) fn verity_text(data: &[u8]) -> String {
    velarx_storage::fsverity_digest_of(velarx_types::digest::Algorithm::Sha256, data)
}
