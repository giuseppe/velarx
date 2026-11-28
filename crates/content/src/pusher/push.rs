// SPDX-License-Identifier: Apache-2.0
//! The varlink interface of pushers: a process that places the objects of
//! an image at a destination.  A pusher answers only for itself and knows
//! nothing of the others: the engine walks its ordered list of them.  The
//! types of the wire; the serving end is `crate::serve_push`.

use serde::{Deserialize, Serialize};
use std::os::fd::OwnedFd;
use velarx_proto::info::Info;
pub use velarx_proto::transfer::{Failure, FailureClass, Placed};
use zlink::introspect;

/// The varlink interface.
pub const INTERFACE: &str = "org.velarx.Pusher";

/// The number `GetInfo` reports.
pub const PROTO: u32 = 1;

/// The most descriptors of one message.
pub const MAX_FDS: usize = 16;

/// The most objects of a `Put` whatever the pusher says: a descriptor each,
/// and none left for anything else.
pub const MAX_OBJECTS: usize = MAX_FDS - 1;

/// The most bytes of the credentials in a sealed memory file.
pub const MAX_ACCESS: u64 = 1 << 20;

/// The most bytes of a manifest that `Commit` takes.
pub const MAX_MANIFEST: u64 = 4 * 1024 * 1024;

/// The most repositories a hint names for one object.
pub const MAX_KNOWN_AT: usize = 16;

/// What an object is for the image.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, introspect::CustomType)]
#[serde(rename_all = "snake_case")]
#[zlink(rename_all = "snake_case")]
pub enum Role {
    Config,
    Layer,
    Blob,
    Manifest,
    /// (also what a value this side does not know is read as)
    #[serde(other)]
    Unknown,
}

/// An object the engine wants at the destination.  Its digest is the one
/// the engine computed, never one a pusher made.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, introspect::CustomType)]
pub struct Object {
    pub digest: String,
    pub size: u64,
    pub media_type: String,
    pub role: Role,
    /// Places of the destination it can be linked from (a hint: a pusher
    /// that cannot link ignores it)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub known_at: Option<Vec<String>>,
}

/// What a pusher has of an object, before anything is regenerated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, introspect::CustomType)]
#[serde(rename_all = "snake_case")]
#[zlink(rename_all = "snake_case")]
pub enum Have {
    /// The destination has it
    Present,
    /// This pusher linked it from where a hint said it is (a cross-repository
    /// mount): the destination has it now
    Linked,
    /// This pusher can place it and needs its bytes
    Needed,
    /// Not this pusher's to place
    Unavailable,
    /// (what a value this side does not know is read as)
    #[serde(other)]
    Unknown,
}

/// What an event of a `Put` tells.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, introspect::CustomType)]
#[serde(rename_all = "snake_case")]
#[zlink(rename_all = "snake_case")]
pub enum EventKind {
    /// `objects` are at the destination, this pusher put them there
    Placed,
    /// `objects` were at the destination already
    Present,
    /// `objects` are at the destination, linked from another repository
    Linked,
    /// This pusher does not place `objects`
    Unavailable,
    /// It tried and failed for `objects`: `failure`
    Failed,
    /// `bytes` of the one object of `objects` are sent so far by this call
    Progress,
    /// (what an event this side does not know is read as: ignored)
    #[serde(other)]
    Unknown,
}

/// What this pusher has of one object of a `Probe`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, introspect::CustomType)]
pub struct Probed {
    /// The position of the object in the call
    pub index: u32,
    pub have: Have,
    pub failure: Option<Failure>,
}

/// What a `Probe` answers: one `probed` a reply, then a last reply without
/// one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, introspect::Type)]
pub struct ProbeReply {
    pub probed: Option<Probed>,
}

/// What an event of a `Put` carries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, introspect::CustomType)]
pub struct PutEvent {
    pub kind: EventKind,
    /// Positions in the call
    pub objects: Vec<u32>,
    pub failure: Option<Failure>,
    pub bytes: Option<u64>,
}

impl PutEvent {
    pub fn of(kind: EventKind) -> Self {
        Self {
            kind,
            objects: Vec::new(),
            failure: None,
            bytes: None,
        }
    }

    /// `objects` failed with `failure`.
    pub fn failed(objects: Vec<u32>, failure: Failure) -> Self {
        Self {
            objects,
            failure: Some(failure),
            ..Self::of(EventKind::Failed)
        }
    }

    /// `bytes` of `object` are sent so far.
    pub fn progress(object: Option<u32>, bytes: u64) -> Self {
        Self {
            objects: object.into_iter().collect(),
            bytes: Some(bytes),
            ..Self::of(EventKind::Progress)
        }
    }
}

/// What a `Put` answers: one `event` a reply, then a last reply without one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, introspect::Type)]
pub struct PutReply {
    pub event: Option<PutEvent>,
}

/// What `Commit` answers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, introspect::Type)]
pub struct CommitReply {
    /// The digest the destination says the manifest has
    pub digest: String,
    /// One for each name and one for the digest
    pub placed: Vec<Placed>,
}

/// What a call that returns nothing answers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, introspect::Type)]
pub struct Ack {}

/// Why a call failed.
#[derive(Debug, Clone, PartialEq, zlink::ReplyError, introspect::ReplyError)]
#[zlink(interface = "org.velarx.Pusher")]
pub enum PusherError {
    InvalidArgument {
        reason: String,
    },
    /// A call before `Open`, an `Open` twice
    NotScoped {
        reason: String,
    },
    /// A call this connection may not make
    Refused {
        reason: String,
    },
    /// A destination of a kind this pusher does not do
    NotSupported {
        feature: String,
    },
    /// No connection for this client now (its limit)
    Busy {
        reason: String,
    },
    /// `Commit`: the destination does not have these objects
    ObjectsMissing {
        digests: Vec<String>,
    },
    /// The call failed: what kind, and why
    Failed {
        failure: Failure,
    },
}

impl PusherError {
    fn with(class: FailureClass, reason: impl Into<String>) -> Self {
        Self::Failed {
            failure: Failure {
                class,
                reason: reason.into(),
            },
        }
    }

    /// This pusher does not serve the call (it does not own its
    /// destination, or serves none).
    pub fn unavailable(reason: impl Into<String>) -> Self {
        Self::with(FailureClass::Unavailable, reason)
    }

    /// It tried and failed for good.
    pub fn failed(reason: impl Into<String>) -> Self {
        Self::with(FailureClass::Failed, reason)
    }

    /// The failure of a `Failed`.
    pub fn failure(&self) -> Option<&Failure> {
        match self {
            Self::Failed { failure } => Some(failure),
            _ => None,
        }
    }
}

impl std::fmt::Display for PusherError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidArgument { reason } => write!(f, "invalid argument: {reason}"),
            Self::NotScoped { reason } => write!(f, "not scoped: {reason}"),
            Self::Refused { reason } => write!(f, "refused: {reason}"),
            Self::NotSupported { feature } => write!(f, "not supported: {feature}"),
            Self::Busy { reason } => write!(f, "busy: {reason}"),
            Self::ObjectsMissing { digests } => {
                write!(f, "the destination does not have {}", digests.join(", "))
            }
            Self::Failed { failure } => write!(f, "{:?}: {}", failure.class, failure.reason),
        }
    }
}

impl std::error::Error for PusherError {}

mod proxy {
    #![allow(clippy::too_many_arguments, missing_docs)]
    use super::*;

    /// The calls of the interface, as a client makes them.  The descriptors
    /// of a call are `fds`; the fields that name them are positions in it.
    #[zlink::proxy("org.velarx.Pusher")]
    pub trait PusherProxy {
        /// Who the pusher is and what it can do.
        async fn get_info(&mut self) -> zlink::Result<Result<Info, PusherError>>;

        /// Give the connection its scope; once, before anything but
        /// `GetInfo`.
        async fn open(
            &mut self,
            #[zlink(fds)] fds: Vec<OwnedFd>,
            destination: &str,
            tls_verify: Option<bool>,
            target: Option<u32>,
            access: Option<u32>,
            idle_ms: u64,
        ) -> zlink::Result<Result<Ack, PusherError>>;

        /// Another connection with the scope of this one.
        #[zlink(return_fds)]
        async fn connect(&mut self) -> zlink::Result<(Result<Ack, PusherError>, Vec<OwnedFd>)>;

        /// What do you have, or what can you link, of these objects?
        #[zlink(more)]
        async fn probe(
            &mut self,
            objects: Vec<Object>,
        ) -> zlink::Result<
            impl futures::Stream<Item = zlink::Result<Result<ProbeReply, PusherError>>>,
        >;

        /// Place the objects; `files` the position of each one's data file.
        #[zlink(more)]
        async fn put(
            &mut self,
            #[zlink(fds)] fds: Vec<OwnedFd>,
            objects: Vec<Object>,
            files: Vec<u32>,
        ) -> zlink::Result<impl futures::Stream<Item = zlink::Result<Result<PutReply, PusherError>>>>;

        /// Put the manifest in `file` as each of `names`.
        async fn commit(
            &mut self,
            #[zlink(fds)] fds: Vec<OwnedFd>,
            manifest: &Object,
            file: u32,
            names: &[String],
        ) -> zlink::Result<Result<CommitReply, PusherError>>;

        /// The destination has the manifest `digest` by `names` now.
        async fn committed(
            &mut self,
            manifest: &Object,
            digest: &str,
            names: &[String],
        ) -> zlink::Result<Result<Ack, PusherError>>;

        /// The end of the scope.
        async fn finish(&mut self) -> zlink::Result<Result<Ack, PusherError>>;
    }
}

pub use proxy::PusherProxy;

#[cfg(test)]
mod tests {
    use super::*;

    /// An event of a kind this side does not know is read as one to ignore.
    #[test]
    fn an_event_of_an_unknown_kind_is_read_as_unknown() {
        let kind: EventKind = serde_json::from_str("\"resumed\"").unwrap();
        assert_eq!(kind, EventKind::Unknown);
        let have: Have = serde_json::from_str("\"mirrored\"").unwrap();
        assert_eq!(have, Have::Unknown);
    }
}
