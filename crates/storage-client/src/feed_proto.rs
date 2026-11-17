// SPDX-License-Identifier: Apache-2.0
//! The varlink interface `org.velarx.StorageFeed`: what the engine offers a
//! storage driver during a pull.
//!
//! The pull is driven by the driver.  `BeginPull` of `org.velarx.Storage`
//! hands it, as the descriptor 0 of the call, the end of a socket pair on
//! which the engine serves this interface for that pull only; the driver is
//! its client.  It reads the index of each layer (`Index`), works out what it
//! lacks against its own store, and asks for **sets** of missing files with
//! `Fetch` (the engine merges the ranges by cost, fetches from the sources
//! and peers first, verifies every chunk, and writes the bytes into files the
//! driver gave).  The engine holds the credentials: no URL, repository or
//! digest of a blob is ever accepted from the driver.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use velarx_proto::transfer::{Failure, FailureClass};
use zlink::introspect;

/// The varlink interface.
pub const INTERFACE: &str = "org.velarx.StorageFeed";

/// The version of the protocol: the same as `org.velarx.Storage`'s.
pub const PROTO: u32 = super::proto::PROTO;

/// The most objects one `Fetch` asks for.
pub const MAX_WANTS: usize = 4096;

/// The most `Fetch` calls at the same time, connections made with `Connect`
/// included.
pub const MAX_FETCHES: u32 = 8;

/// The most files one `Fetch` carries: the pack file and up to 15 files of
/// one object each.
pub const MAX_FILES: usize = super::proto::MAX_FDS;

/// The most bytes one `Fetch` may ask the engine to write: the incoming files
/// are of this size, at most.
pub const MAX_FETCH_BYTES: u64 = 1 << 30;

/// A layer of the pull that the driver has to bring in.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, introspect::CustomType)]
pub struct FeedLayer {
    /// The key of the layer, as `BeginPull` names it
    pub key: String,
    pub diff_id: String,
    /// The bytes of its table of contents (the first file of `Index`)
    pub toc_length: u64,
    /// The bytes of its compressed tar-split (the second file of `Index`)
    pub tarsplit_length: u64,
    /// The entries of the table of contents
    pub entries: u64,
    /// The bytes of the files of the layer
    pub size: u64,
}

/// A file the driver lacks: its key in the table of contents and its size.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, introspect::CustomType)]
pub struct Want {
    pub key: String,
    pub size: u64,
    /// The position among the files of the call of one that holds this object
    /// alone, from offset 0.  Without it the object goes into the pack file
    /// (the file 0)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file: Option<u32>,
}

/// Bytes of a file the message carries: `length` bytes from `offset`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, introspect::CustomType)]
pub struct Region {
    /// The position of the file among the descriptors of the message it is
    /// about: the call, for the events of a `Fetch`
    pub fd: u32,
    pub offset: u64,
    pub length: u64,
}

/// Bytes `[at, at + region.length)` of the object `want` of the call, in a region
/// of a file the message carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, introspect::CustomType)]
pub struct Piece {
    /// The position of the object among the wants of the call
    pub want: u32,
    pub at: u64,
    pub region: Region,
}

/// Bytes of the object `want` that another object of the driver holds: the
/// driver copies them itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, introspect::CustomType)]
pub struct Copy {
    pub want: u32,
    pub at: u64,
    /// The key of the object the bytes are in
    pub from: String,
    pub from_offset: u64,
    pub length: u64,
}

/// A hole of the object `want`: `length` bytes of zeros from `at`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, introspect::CustomType)]
pub struct Zeros {
    pub want: u32,
    pub at: u64,
    pub length: u64,
}

/// A file the engine hands over for the object `want`: the object, complete
/// and verified by the engine, is the file the message carries, which the
/// driver keeps its own way.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, introspect::CustomType)]
pub struct Handed {
    /// The position of the object among the wants of the call
    pub want: u32,
    /// The position of the file among the descriptors of this message
    pub fd: u32,
    /// The fs-verity digest of the object, which the engine verified
    pub verity: String,
}

/// What an event of a `Fetch` tells.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, introspect::CustomType)]
#[serde(rename_all = "snake_case")]
#[zlink(rename_all = "snake_case")]
pub enum EventKind {
    /// `pieces`: bytes are in the regions
    Ready,
    /// `handed`: the objects are whole and verified, in the files the
    /// message carries
    Staged,
    /// `copies`: the driver copies them from its own objects
    Copy,
    /// `zeros`: holes
    Zeros,
    /// `wants`: objects that are whole, their keys verified
    Complete,
    /// `wants` could not be fetched, `failure` says why
    Failed,
    /// An event this side does not know: it is ignored
    #[serde(other)]
    Unknown,
}

/// What an event of a `Fetch` tells.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, introspect::CustomType)]
pub struct FetchEvent {
    pub kind: EventKind,
    #[serde(default)]
    pub pieces: Vec<Piece>,
    #[serde(default)]
    pub copies: Vec<Copy>,
    #[serde(default)]
    pub handed: Vec<Handed>,
    #[serde(default)]
    pub zeros: Vec<Zeros>,
    /// With `complete` and `failed`: the wants, by position in the call
    #[serde(default)]
    pub wants: Vec<u32>,
    /// With `failed`: why
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure: Option<Failure>,
}

/// What a reply of `Fetch` carries: an event, and no record in the last
/// reply, which has `continues: false`.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, introspect::Type)]
pub struct Fetched {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event: Option<FetchEvent>,
}

/// What `GetInfo` answers: the five fields every `GetInfo` has
/// ([`velarx_proto::info::Info`]; `limits` has `max_wants`, `max_fetches`,
/// the most calls at the same time, `Connect` included, and
/// `max_fetch_bytes`, the most bytes a `Fetch` may ask for), and the pull.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, introspect::Type)]
pub struct FeedInfo {
    pub name: String,
    pub version: String,
    /// The version of the protocol
    pub proto: u32,
    pub capabilities: Vec<String>,
    pub limits: BTreeMap<String, u64>,
    /// The pull, as `BeginPull` names it
    pub pull: String,
    /// The layers the driver has to bring in: those of the pull that are not
    /// stored, each once
    pub layers: Vec<FeedLayer>,
}

impl FeedInfo {
    /// The five fields every `GetInfo` has.
    pub fn shared(&self) -> velarx_proto::info::Info {
        velarx_proto::info::Info {
            name: self.name.clone(),
            version: self.version.clone(),
            proto: self.proto,
            capabilities: self.capabilities.clone(),
            limits: self.limits.clone(),
        }
    }
}

/// What a call that returns nothing answers.
pub use super::proto::Ack;

/// Why a call of the feed failed.
#[derive(Debug, Clone, PartialEq, zlink::ReplyError, introspect::ReplyError)]
#[zlink(interface = "org.velarx.StorageFeed")]
pub enum FeedError {
    /// A layer that is not one of the pull
    UnknownLayer { layer: String },
    /// A key that is not in the table of contents of the layer, or whose
    /// size is not the one it states
    UnknownObject { key: String },
    /// A file of the call that is not an empty regular file open for
    /// writing, on a file system whose writes may block (FUSE, a network file
    /// system), or that the wants name wrongly
    BadFile { reason: String },
    /// The budget of the pull (twice the planned bytes of the layer), the
    /// wants of a call, the calls at the same time
    TooMuch { reason: String },
    /// The engine tried and failed, or cannot place the bytes
    Failed { failure: Failure },
}

impl FeedError {
    /// A failure of no class in particular.
    pub fn failed(reason: impl Into<String>) -> Self {
        Self::Failed {
            failure: Failure {
                class: FailureClass::Failed,
                reason: reason.into(),
            },
        }
    }
}

impl std::fmt::Display for FeedError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownLayer { layer } => write!(f, "unknown layer: {layer}"),
            Self::UnknownObject { key } => write!(f, "unknown object: {key}"),
            Self::BadFile { reason } => write!(f, "bad file: {reason}"),
            Self::TooMuch { reason } => write!(f, "too much: {reason}"),
            Self::Failed { failure } => {
                write!(f, "failed ({:?}): {}", failure.class, failure.reason)
            }
        }
    }
}

impl std::error::Error for FeedError {}

/// The calls of the interface, as a client makes them: the one place a method
/// of it is named.
pub mod request {
    use super::{Ack, FeedInfo, Fetched, Want, INTERFACE};
    use serde::Serialize;
    use velarx_wire::varlink::Method;

    macro_rules! method {
        ($ty:ident $(<$l:lifetime>)?, $name:literal, $reply:ty $(, $more:ident)?) => {
            impl$(<$l>)? Method for $ty$(<$l>)? {
                const INTERFACE: &'static str = INTERFACE;
                const NAME: &'static str = $name;
                $(const $more: bool = true;)?
                type Reply = $reply;
            }
        };
    }

    #[derive(Serialize)]
    pub struct GetInfo {}
    method!(GetInfo, "GetInfo", FeedInfo);

    #[derive(Serialize)]
    pub struct Connect {}
    method!(Connect, "Connect", Ack);

    #[derive(Serialize)]
    pub struct Index<'a> {
        pub layer: &'a str,
    }
    method!(Index<'a>, "Index", Ack);

    #[derive(Serialize)]
    pub struct Release<'a> {
        pub layer: &'a str,
    }
    method!(Release<'a>, "Release", Ack);

    #[derive(Serialize)]
    pub struct Fetch<'a> {
        pub layer: &'a str,
        pub wants: &'a [Want],
    }
    method!(Fetch<'a>, "Fetch", Fetched, MORE);

    /// Every request and its parameters, as the contract test reads them.
    #[cfg(test)]
    pub(crate) fn served() -> Vec<(&'static str, Vec<String>)> {
        fn of<M: Method>(m: &M) -> (&'static str, Vec<String>) {
            let value = serde_json::to_value(m).expect("a request serializes");
            (
                M::NAME,
                value
                    .as_object()
                    .map(|o| o.keys().cloned().collect())
                    .unwrap_or_default(),
            )
        }
        vec![
            of(&GetInfo {}),
            of(&Connect {}),
            of(&Index { layer: "l" }),
            of(&Release { layer: "l" }),
            of(&Fetch {
                layer: "l",
                wants: &[],
            }),
        ]
    }

    #[cfg(test)]
    mod tests {
        use std::collections::BTreeSet;

        #[test]
        fn every_served_method_has_one_request_with_its_parameters() {
            let definition = include_str!("../../../interfaces/org.velarx.StorageFeed.varlink");
            let described = velarx_wire::varlink::described_methods(definition);
            let served = super::served();
            for (name, params) in &described {
                let found: Vec<_> = served.iter().filter(|(n, _)| n == name).collect();
                assert_eq!(found.len(), 1, "{name} has {} request types", found.len());
                let have: BTreeSet<_> = found[0].1.iter().cloned().collect();
                let want: BTreeSet<_> = params.iter().cloned().collect();
                assert_eq!(have, want, "the fields of the request {name}");
            }
            assert_eq!(described.len(), served.len());
        }
    }
}
