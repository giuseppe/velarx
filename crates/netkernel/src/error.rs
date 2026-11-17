// SPDX-License-Identifier: Apache-2.0
//! What the network code says went wrong.

use thiserror::Error;

#[derive(Error, Debug)]
pub enum NetworkError {
    #[error("unable to find network with name or ID {0}: network not found")]
    NotFound(String),
    #[error("{0}")]
    AlreadyExists(String),
    /// Another thing than a network is missing.
    #[error("{0}")]
    Missing(String),
    /// The network is used by containers.
    #[error("{0}")]
    Busy(String),
    #[error("{0}")]
    Netlink(String),
    #[error("CNI: {0}")]
    Cni(String),
    #[error("interface not found: {0}")]
    InterfaceNotFound(String),
    #[error(transparent)]
    Database(#[from] velarx_types::DbError),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid configuration: {0}")]
    InvalidConfig(String),
    /// A rootless container needs pasta, and none is in the directories
    /// searched (the `$PATH` of the engine).
    #[error(
        "cannot find `pasta` (searched: {searched}): rootless containers need pasta \
         (package passt) {minimum} or later for their network; `--network none` runs without one"
    )]
    NoPasta {
        searched: String,
        minimum: &'static str,
    },
    /// The pasta found is older than the release needed, or its
    /// `--version` names no release (what it said is kept).
    #[error(
        "`{path}` is not pasta {minimum} or later (its `--version`: `{said}`): rootless \
         containers need pasta (package passt) {minimum} or later for their network; \
         `--network none` runs without one"
    )]
    OldPasta {
        path: String,
        said: String,
        minimum: &'static str,
    },
    /// A published port of a protocol the engine does not forward (podman's
    /// words for it).
    #[error("can't forward protocol: {0}")]
    UnsupportedProtocol(String),
    /// A record of the database that cannot be read (not what a request
    /// asked for, which is [`NetworkError::InvalidConfig`]).
    #[error("{0}")]
    Unreadable(String),
    /// A running container is connected to the network already.
    #[error("network is already connected")]
    AlreadyConnected,
    /// The rootless network namespace was released before it was entered.
    #[error("the rootless network namespace is gone")]
    RootlessNetnsGone,
}

pub type NetworkResult<T> = Result<T, NetworkError>;
