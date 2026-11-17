// SPDX-License-Identifier: Apache-2.0
//! The types of `org.velarx.Registry`, the repository calls (`Tags`,
//! `Search`, `Login`, `Download`) the registry fetcher serves besides
//! `org.velarx.Fetcher` ([`super::fetch`]), on the same socket: a fetcher of
//! another kind does not have them to refuse.

use serde::{Deserialize, Serialize};
use std::os::fd::OwnedFd;
use velarx_proto::info::Info;
pub use velarx_proto::transfer::{Failure, FailureClass};
use zlink::introspect;

/// The varlink interface.
pub const INTERFACE: &str = "org.velarx.Registry";

/// The number `GetInfo` reports.
pub const PROTO: u32 = 1;

/// The most bytes of the credentials, certificates and auth files a call
/// carries.
pub const MAX_ACCESS: u64 = 1 << 20;

/// The most items (tags, hits) of the answer of `Tags` and `Search`: the
/// limit `max_answer` of `GetInfo`.
pub const MAX_ANSWER: u64 = 1 << 20;

/// The most bytes of a text argument (a repository, a search term, a
/// reference, a media type): the arguments of a call stay far below the
/// 32 kB cap of the engine's interface.
pub const MAX_TEXT: usize = 255;

/// The repository a call of `org.velarx.Registry` is about, how it is
/// reached and who it is reached as.  No secret is in the message: the
/// credentials, certificates and auth file contents are the JSON of a
/// `RegistryAccess` in the sealed memory file `access`, a descriptor of the
/// call.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, introspect::CustomType)]
pub struct Remote {
    /// `registry/name`, with no tag or digest
    pub repository: String,
    /// Whether TLS is verified (default: yes); when the asker says no for a
    /// registry that registries.conf does not mark insecure, only the
    /// credentials of the call are used
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_verify: Option<bool>,
    /// The credentials: the position of a sealed memory file among the
    /// descriptors of the call; none: the fetcher's own
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub access: Option<u32>,
}

/// A repository a search found.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, introspect::CustomType)]
pub struct Hit {
    pub name: String,
    pub description: String,
    pub stars: u64,
    pub official: bool,
    pub automated: bool,
}

/// What `Tags` answers: one `tag` a reply, then a last reply without one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, introspect::Type)]
pub struct Tagged {
    pub tag: Option<String>,
}

/// What `Search` answers: one `hit` a reply, then a last reply without one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, introspect::Type)]
pub struct Found {
    pub hit: Option<Hit>,
}

/// What `Download` answers: the body is in the file the call carried.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, introspect::Type)]
pub struct Downloaded {
    pub length: u64,
    pub media_type: Option<String>,
    /// The Last-Modified the server said
    pub modified: Option<String>,
}

/// What a call that returns nothing answers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, introspect::Type)]
pub struct Ack {}

/// Why a call of `org.velarx.Registry` failed.
#[derive(Debug, Clone, PartialEq, zlink::ReplyError, introspect::ReplyError)]
#[zlink(interface = "org.velarx.Registry")]
pub enum RegistryError {
    /// A request the registry fetcher does not take: a text too long, a
    /// descriptor that is not what the call says, a URL that is not http or
    /// https
    InvalidArgument { reason: String },
    /// The body of a `Download` is larger than `max`
    TooLarge { max: u64 },
    /// The call failed: what kind, and why
    Failed { failure: Failure },
}

impl RegistryError {
    /// A request that is wrong in itself.
    pub fn bad(reason: impl Into<String>) -> Self {
        Self::InvalidArgument {
            reason: reason.into(),
        }
    }

    /// This fetcher does not serve the call (it serves no registry).
    pub fn unavailable(reason: impl Into<String>) -> Self {
        Self::Failed {
            failure: Failure {
                class: FailureClass::Unavailable,
                reason: reason.into(),
            },
        }
    }

    /// It tried and failed for good.
    pub fn failed(reason: impl Into<String>) -> Self {
        Self::Failed {
            failure: Failure {
                class: FailureClass::Failed,
                reason: reason.into(),
            },
        }
    }

    /// The failure of a `Failed`.
    pub fn failure(&self) -> Option<&Failure> {
        match self {
            Self::Failed { failure } => Some(failure),
            _ => None,
        }
    }
}

impl std::fmt::Display for RegistryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidArgument { reason } => write!(f, "invalid argument: {reason}"),
            Self::TooLarge { max } => write!(f, "larger than {max} bytes"),
            Self::Failed { failure } => write!(f, "{:?}: {}", failure.class, failure.reason),
        }
    }
}

impl std::error::Error for RegistryError {}

/// The calls of the interface, as a client makes them.  The descriptors of
/// a call are `fds`; `Remote::access` and `file` are positions in it.
#[zlink::proxy("org.velarx.Registry")]
pub trait RegistryProxy {
    /// Who serves the interface and what it can do.
    async fn get_info(&mut self) -> zlink::Result<Result<Info, RegistryError>>;

    /// The tags of the repository, every page of them.
    #[zlink(more)]
    async fn tags(
        &mut self,
        #[zlink(fds)] fds: Vec<OwnedFd>,
        remote: Remote,
        max: u64,
    ) -> zlink::Result<impl futures::Stream<Item = zlink::Result<Result<Tagged, RegistryError>>>>;

    /// A search of the registry of `remote` for `needle`.
    #[zlink(more)]
    async fn search(
        &mut self,
        #[zlink(fds)] fds: Vec<OwnedFd>,
        remote: Remote,
        needle: String,
        limit: u64,
    ) -> zlink::Result<impl futures::Stream<Item = zlink::Result<Result<Found, RegistryError>>>>;

    /// Whether the registry takes the credentials of `remote`.
    async fn login(
        &mut self,
        #[zlink(fds)] fds: Vec<OwnedFd>,
        remote: &Remote,
    ) -> zlink::Result<Result<Ack, RegistryError>>;

    /// An http or https GET of `url` into the file at position `file`.
    async fn download(
        &mut self,
        #[zlink(fds)] fds: Vec<OwnedFd>,
        url: &str,
        max: u64,
        file: u32,
    ) -> zlink::Result<Result<Downloaded, RegistryError>>;
}
