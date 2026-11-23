// SPDX-License-Identifier: Apache-2.0
//! The varlink interface of fetchers: a process that brings the content of
//! images into the staging directories of a store.  A fetcher answers
//! only for itself and knows nothing of the others: the engine walks its
//! ordered list of fetchers.  The types of the wire; the serving
//! end is `crate::serve_fetch`.

use serde::{Deserialize, Serialize};
use std::os::fd::OwnedFd;
use velarx_proto::info::Info;
pub use velarx_proto::transfer::{Failure, FailureClass};
use zlink::introspect;

/// The varlink interface.
pub const INTERFACE: &str = "org.velarx.Fetcher";

/// The number `GetInfo` reports.
pub const PROTO: u32 = 1;

/// The most descriptors of one message.
pub const MAX_FDS: usize = 16;

/// The most bytes of the credentials in a sealed memory file.
pub const MAX_ACCESS: u64 = 1 << 20;

/// The largest startup profile a node gives or takes (`GetProfile`):
/// thousands of digests, small next to the files they name.
pub const PROFILE_MAX_BYTES: u64 = 512 * 1024;

/// The most bytes of the records `GetSignatures` gives or takes.
pub const SIGNATURES_MAX_BYTES: u64 = 1 << 20;

/// The capability words.
pub const CAPABILITIES: [&str; 9] = [
    "objects", "unpack", "metadata", "lazy", "sha512", "reuse", "origin", "handover", "table",
];

/// How much a request is waited for.  It orders a fetcher's work.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Serialize,
    Deserialize,
    introspect::CustomType,
)]
#[serde(rename_all = "snake_case")]
#[zlink(rename_all = "snake_case")]
pub enum Urgency {
    /// The rest of an image that already runs
    Background = 0,
    /// A guess
    Ahead = 1,
    /// A command waits for the image
    Wait = 2,
    /// A process of a container is blocked on it
    OnDemand = 3,
}

impl TryFrom<u8> for Urgency {
    type Error = u8;

    /// The urgency of its byte on the wire (`urgency as u8`).
    fn try_from(byte: u8) -> Result<Self, u8> {
        Ok(match byte {
            0 => Self::Background,
            1 => Self::Ahead,
            2 => Self::Wait,
            3 => Self::OnDemand,
            _ => return Err(byte),
        })
    }
}

/// A blob of the image, as the manifest the engine hashed describes it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, introspect::CustomType)]
pub struct Blob {
    pub digest: String,
    pub size: u64,
    pub media_type: String,
    /// The annotations of its descriptor in the manifest (where a table of
    /// contents is, for zstd:chunked and eStargz)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub annotations: Option<std::collections::BTreeMap<String, String>>,
}

impl Blob {
    /// The checksum of the zstd:chunked table of contents its descriptor
    /// names: none for a layer without one.
    pub fn toc_checksum(&self) -> Option<velarx_types::digest::Digest> {
        velarx_types::layer::chunked_checksum(&self.descriptor()?)
    }

    /// Whether its descriptor names a binary table: a layer that is pulled
    /// by it, which only a fetcher that announces `table` is asked for.
    pub fn has_table(&self) -> bool {
        self.descriptor().is_some_and(|d| {
            velarx_types::layer::chunked_annotation(&d, "table-checksum").is_some()
        })
    }

    fn descriptor(&self) -> Option<velarx_types::OciDescriptor> {
        Some(velarx_types::OciDescriptor {
            media_type: self.media_type.clone(),
            digest: self.digest.parse().ok()?,
            size: i64::try_from(self.size).ok()?,
            annotations: self
                .annotations
                .iter()
                .flatten()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
        })
    }
}

/// A chunk the store of the engine holds: `length` bytes at `offset` of
/// the descriptor `fd` of the message (a file with no name the engine made
/// of the chunks it hints, read-only; never a file of the store).  A
/// fetcher may take a chunk of a file it writes whose sha256 is `chunk`
/// from there instead of fetching it, after it checked those bytes against
/// `chunk` as it checks every chunk; it may also ignore the hint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, introspect::CustomType)]
pub struct Reuse {
    pub chunk: String,
    pub fd: u32,
    pub offset: u64,
    pub length: u64,
}

/// How the table of contents of a layer comes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, introspect::CustomType)]
#[serde(rename_all = "lowercase")]
#[zlink(rename_all = "lowercase")]
pub enum TocSource {
    /// The blob has one (zstd:chunked, eStargz): the reply carries it (the
    /// table, then the tar-split)
    Carried,
    /// It has none: the layer is unpacked whole (`Unpack`), which
    /// gives the files, a table and a tar-split in one pass
    Unpack,
    /// This fetcher cannot bring the layer at all (also what a value this
    /// side does not know is read as)
    #[serde(other)]
    None,
}

pub use velarx_proto::transfer::NotLazy;

/// What a `Probe` asks a fetcher to carry for a layer with a table of
/// contents.  A fetcher may carry more than it is asked for.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, introspect::CustomType,
)]
#[serde(rename_all = "lowercase")]
#[zlink(rename_all = "lowercase")]
pub enum Parts {
    /// The table of contents: a lazy start, which does not need the
    /// tar-split
    Toc,
    /// The tar-split: the completion of a lazy pull
    Tarsplit,
    /// Both (also what a value this side does not know is read as)
    #[default]
    #[serde(other)]
    All,
}

/// The table of contents a fetcher made of a layer it unpacked whole (a
/// claim the engine checks), in the layer's staging directory.
pub const TOC_CLAIM: &str = "toc.claim";
/// The compressed tar-split of a layer a fetcher unpacked whole, in the
/// layer's staging directory.
pub const TARSPLIT: &str = "tarsplit";

/// What an event of a `Fetch` tells.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, introspect::CustomType)]
#[serde(rename_all = "snake_case")]
#[zlink(rename_all = "snake_case")]
pub enum EventKind {
    /// `objects` have their names in `files/` of the layer's staging, or,
    /// with `files`, are the descriptors of the reply
    Staged,
    /// This fetcher does not have `objects`
    Unavailable,
    /// It tried and failed for `objects`: `failure`
    Failed,
    /// `bytes` of the one object of `objects` are written so far by this
    /// call (of the blob of the layer, for a call with no objects)
    Progress,
    /// (what an event this side does not know is read as: ignored)
    #[serde(other)]
    Unknown,
}

/// What this fetcher can do for one layer of a `Probe`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, introspect::CustomType)]
pub struct Probed {
    /// The position of the layer in the call
    pub layer: u32,
    pub toc: TocSource,
    /// Its files can be fetched one by one, on demand
    pub on_demand: bool,
    /// Why not, when `on_demand` is false
    pub reason: Option<NotLazy>,
    /// With `toc` carried: the table of contents and the tar-split, as the
    /// `parts` of the probe ask, sealed memory files among the descriptors of
    /// this reply (a layer whose table of contents has `"version": 2` has no
    /// tar-split).  For a layer with no
    /// table of contents, with `no_toc`: the index another node recorded, a
    /// claim the engine replays and checks
    pub toc_file: Option<u32>,
    pub tarsplit_file: Option<u32>,
}

/// What a `Probe` answers: one `probed` a reply, then a last reply without
/// one.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, introspect::Type)]
pub struct ProbeReply {
    pub probed: Option<Probed>,
}

/// A record of `GetSignatures`: the signatures made for the manifest
/// `digest`, each the base64 of a signature blob (the blob of a lookaside
/// storage).  Untrusted: the engine judges the signatures.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedRecord {
    pub digest: String,
    pub signatures: Vec<String>,
}

impl SignedRecord {
    /// `records` with those of one digest made one, each signature once.
    pub fn merged(records: impl IntoIterator<Item = SignedRecord>) -> Vec<SignedRecord> {
        let mut by_digest = std::collections::BTreeMap::<_, std::collections::BTreeSet<_>>::new();
        for record in records {
            by_digest
                .entry(record.digest)
                .or_default()
                .extend(record.signatures);
        }
        by_digest
            .into_iter()
            .map(|(digest, signatures)| SignedRecord {
                digest,
                signatures: signatures.into_iter().collect(),
            })
            .collect()
    }

    /// The JSON of `records` merged, those with no signature left out;
    /// None when no record is left or it is longer than `max`.
    pub fn encoded(records: impl IntoIterator<Item = SignedRecord>, max: u64) -> Option<Vec<u8>> {
        let mut records = Self::merged(records);
        records.retain(|r| !r.signatures.is_empty());
        let bytes = serde_json::to_vec(&records).ok()?;
        (!records.is_empty() && bytes.len() as u64 <= max).then_some(bytes)
    }
}

/// What `GetManifest` answers: the manifest is in the sealed memory file
/// `file` of the reply.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, introspect::Type)]
pub struct Manifest {
    pub file: u32,
    pub media_type: Option<String>,
}

/// What `GetBlob`, `GetProfile` and `GetSignatures` answer: the item is in the sealed memory
/// file `file` of the reply.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, introspect::Type)]
pub struct Item {
    pub file: u32,
}

/// What an event of a `Fetch` carries.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, introspect::CustomType)]
pub struct FetchEvent {
    pub kind: EventKind,
    /// Positions in the call
    pub objects: Vec<u32>,
    pub failure: Option<Failure>,
    pub bytes: Option<u64>,
    /// With `staged`: the object at each position of `objects` is the
    /// complete file with no name at this position among the descriptors of
    /// the reply (a call that asked for `handover`)
    pub files: Option<Vec<u32>>,
}

impl FetchEvent {
    pub fn of(kind: EventKind) -> Self {
        Self {
            kind,
            objects: Vec::new(),
            failure: None,
            bytes: None,
            files: None,
        }
    }

    /// `kind` for `object` of the call.
    pub fn at(kind: EventKind, object: u32) -> Self {
        Self {
            objects: vec![object],
            ..Self::of(kind)
        }
    }

    /// `object` failed with `failure`.
    pub fn failed(objects: Vec<u32>, failure: Failure) -> Self {
        Self {
            objects,
            failure: Some(failure),
            ..Self::of(EventKind::Failed)
        }
    }

    /// `bytes` of `object` are written so far.
    pub fn progress(object: Option<u32>, bytes: u64) -> Self {
        Self {
            objects: object.into_iter().collect(),
            bytes: Some(bytes),
            ..Self::of(EventKind::Progress)
        }
    }
}

/// What a `Fetch` answers: one event a reply, then a last reply without one.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, introspect::Type)]
pub struct FetchReply {
    pub event: Option<FetchEvent>,
}

/// What an `Unpack` answers: the bytes of the blob read so far, or files of
/// the layer, or nothing in the last reply.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, introspect::Type)]
pub struct UnpackReply {
    pub bytes: Option<u64>,
    /// Complete files of the layer, each the position of a descriptor of the
    /// reply
    pub files: Option<Vec<u32>>,
}

/// What a call that returns nothing answers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, introspect::Type)]
pub struct Ack {}

/// Why a call failed.
#[derive(Debug, Clone, PartialEq, zlink::ReplyError, introspect::ReplyError)]
#[zlink(interface = "org.velarx.Fetcher")]
pub enum FetcherError {
    InvalidArgument {
        reason: String,
    },
    /// A call before `Open`, an `Open` twice
    NotScoped {
        reason: String,
    },
    /// A call this connection may not make; a file that is not of the layer;
    /// a layer that was not told (`Layer`) or was forgotten (`Forget`)
    Refused {
        reason: String,
    },
    /// A word of `requires` that is not known
    NotSupported {
        feature: String,
    },
    /// The answer of a `GetManifest`, `GetBlob` or `GetProfile` is larger
    /// than `max`
    TooLarge {
        max: u64,
    },
    /// No connection for this client now (its limit): asked again after
    /// one of its own calls ended, not a fetcher that failed
    Busy {
        reason: String,
    },
    /// Not a directory of a file system that has what the scope asks for
    BadStaging {
        reason: String,
    },
    /// The call failed: what kind, and why
    Failed {
        failure: Failure,
    },
}

impl FetcherError {
    fn with(class: FailureClass, reason: impl Into<String>) -> Self {
        Self::Failed {
            failure: Failure {
                class,
                reason: reason.into(),
            },
        }
    }

    /// This fetcher does not have the item: the engine asks the next one.
    pub fn unavailable(reason: impl Into<String>) -> Self {
        Self::with(FailureClass::Unavailable, reason)
    }

    /// The origin says the item does not exist.
    pub fn not_found(reason: impl Into<String>) -> Self {
        Self::with(FailureClass::NotFound, reason)
    }

    pub fn unauthorized(reason: impl Into<String>) -> Self {
        Self::with(FailureClass::Unauthorized, reason)
    }

    pub fn forbidden(reason: impl Into<String>) -> Self {
        Self::with(FailureClass::Forbidden, reason)
    }

    /// It tried and failed for good.
    pub fn failed(reason: impl Into<String>) -> Self {
        Self::with(FailureClass::Failed, reason)
    }

    /// No space where the bytes go.
    pub fn no_space(reason: impl Into<String>) -> Self {
        Self::with(FailureClass::NoSpace, reason)
    }

    /// The failure of an `Failed`.
    pub fn failure(&self) -> Option<&Failure> {
        match self {
            Self::Failed { failure } => Some(failure),
            _ => None,
        }
    }
}

impl std::fmt::Display for FetcherError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidArgument { reason } => write!(f, "invalid argument: {reason}"),
            Self::NotScoped { reason } => write!(f, "not scoped: {reason}"),
            Self::Refused { reason } => write!(f, "refused: {reason}"),
            Self::NotSupported { feature } => write!(f, "not supported: {feature}"),
            Self::BadStaging { reason } => write!(f, "bad staging directory: {reason}"),
            Self::TooLarge { max } => write!(f, "larger than {max} bytes"),
            Self::Busy { reason } => write!(f, "busy: {reason}"),
            Self::Failed { failure } => write!(f, "{:?}: {}", failure.class, failure.reason),
        }
    }
}

impl std::error::Error for FetcherError {}

mod proxy {
    #![allow(clippy::too_many_arguments, missing_docs)]
    use super::*;

    /// The calls of the interface, as a client makes them.  The descriptors of
    /// a call are `fds`, and the fields that name them are positions in it.
    #[zlink::proxy("org.velarx.Fetcher")]
    pub trait FetcherProxy {
        /// Who the fetcher is and what it can do.
        async fn get_info(&mut self) -> zlink::Result<Result<Info, FetcherError>>;

        /// Give the connection its scope; once, before anything but `GetInfo`.
        async fn open(
            &mut self,
            #[zlink(fds)] fds: Vec<OwnedFd>,
            verity: bool,
            source: Option<&str>,
            tls_verify: Option<bool>,
            target: Option<u32>,
            access: Option<u32>,
            idle_ms: u64,
            requires: &[String],
        ) -> zlink::Result<Result<Ack, FetcherError>>;

        /// Another connection with the scope of this one.
        #[zlink(return_fds)]
        async fn connect(&mut self) -> zlink::Result<(Result<Ack, FetcherError>, Vec<OwnedFd>)>;

        /// Replace the credentials of the scope.
        async fn renew(
            &mut self,
            #[zlink(fds)] fds: Vec<OwnedFd>,
            access: u32,
        ) -> zlink::Result<Result<Ack, FetcherError>>;

        /// Tell this fetcher of a layer.
        async fn layer(
            &mut self,
            #[zlink(fds)] fds: Vec<OwnedFd>,
            layer: &str,
            staging: u32,
            blob: Option<&Blob>,
            toc: Option<u32>,
        ) -> zlink::Result<Result<Ack, FetcherError>>;

        /// Forget the layer.
        async fn forget(&mut self, layer: &str) -> zlink::Result<Result<Ack, FetcherError>>;

        /// The manifest or index `reference` names.
        #[zlink(return_fds)]
        async fn get_manifest(
            &mut self,
            reference: &str,
            max: u64,
        ) -> zlink::Result<(Result<Manifest, FetcherError>, Vec<OwnedFd>)>;

        /// A small blob.
        #[zlink(return_fds)]
        async fn get_blob(
            &mut self,
            blob: &Blob,
        ) -> zlink::Result<(Result<Item, FetcherError>, Vec<OwnedFd>)>;

        /// The startup profile of the image `image`.
        #[zlink(return_fds)]
        async fn get_profile(
            &mut self,
            image: &str,
            max: u64,
        ) -> zlink::Result<(Result<Item, FetcherError>, Vec<OwnedFd>)>;

        /// The signatures of the manifest or tag `reference` names.
        #[zlink(return_fds)]
        async fn get_signatures(
            &mut self,
            reference: &str,
            max: u64,
        ) -> zlink::Result<(Result<Item, FetcherError>, Vec<OwnedFd>)>;

        /// What can this fetcher do for `layers`?
        #[zlink(more, return_fds)]
        async fn probe(
            &mut self,
            layers: Vec<Blob>,
            again: Option<bool>,
            parts: Option<Parts>,
        ) -> zlink::Result<
            impl futures::Stream<Item = zlink::Result<(Result<ProbeReply, FetcherError>, Vec<OwnedFd>)>>,
        >;

        /// Read the whole blob of `layer`, hand over its files and give
        /// `toc.claim` and `tarsplit` names in its staging.
        #[zlink(more, return_fds)]
        async fn unpack(
            &mut self,
            layer: String,
            urgency: Urgency,
        ) -> zlink::Result<
            impl futures::Stream<
                Item = zlink::Result<(Result<UnpackReply, FetcherError>, Vec<OwnedFd>)>,
            >,
        >;

        /// Bring files of `layer` into its staging directory.
        #[zlink(more, return_fds)]
        async fn fetch(
            &mut self,
            #[zlink(fds)] fds: Vec<OwnedFd>,
            layer: String,
            objects: Vec<String>,
            urgency: Urgency,
            reuse: Option<Vec<Reuse>>,
            handover: Option<bool>,
        ) -> zlink::Result<
            impl futures::Stream<Item = zlink::Result<(Result<FetchReply, FetcherError>, Vec<OwnedFd>)>>,
        >;
    }
}

pub use proxy::FetcherProxy;

#[cfg(test)]
mod unknown_tests {
    use super::*;

    /// An event of a kind this side does not know is read, as one to ignore.
    #[test]
    fn an_event_of_an_unknown_kind_is_read_as_unknown() {
        let kind: EventKind = serde_json::from_str("\"resumed\"").unwrap();
        assert_eq!(kind, EventKind::Unknown);
    }
}
