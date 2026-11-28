// SPDX-License-Identifier: Apache-2.0
//! Why a transfer failed, and what the party that reads it does next: one
//! taxonomy for every interface that moves objects (Fetcher, Pusher,
//! Registry, ImageFetch).

use serde::{Deserialize, Serialize};
#[cfg(feature = "proxy")]
use zlink::introspect;

/// What kind of failure, for the party that reads it: what to do next.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "proxy", derive(introspect::CustomType))]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "proxy", zlink(rename_all = "snake_case"))]
pub enum FailureClass {
    /// This party does not have the item or cannot serve it now; nothing
    /// is wrong: the engine asks the next one
    Unavailable,
    /// It tried and failed in a way that may pass (a timeout, a cut
    /// connection, a server error): the engine asks the next one; the
    /// call may be tried again
    Transient,
    /// What it brought, or what it was handed, is not what it claims (a
    /// digest, a size, a table of contents): the operation fails and names
    /// this party; nobody else is asked
    Invalid,
    /// The origin says the item does not exist; from a party that is not
    /// the origin it is read as `unavailable`
    NotFound,
    /// Credentials missing or refused: the engine may `Renew` and ask again
    Unauthorized,
    /// The credentials were taken and do not allow it
    Forbidden,
    /// No space where the bytes go
    NoSpace,
    /// It tried and failed for good (also what a value this side does not
    /// know is read as)
    #[serde(other)]
    Failed,
}

/// Why something failed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "proxy", derive(introspect::CustomType))]
pub struct Failure {
    pub class: FailureClass,
    pub reason: String,
}

/// How the destination of a push resolves a manifest by one name: what the
/// Pusher answers to `Commit`, and what an engine says of the push.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "proxy", derive(introspect::CustomType))]
pub struct Placed {
    /// A name of the call; absent: the manifest's own digest
    pub name: Option<String>,
    pub accepted: bool,
    /// The destination's answer when it refused it
    pub reason: Option<String>,
}

/// Why a layer cannot be served on demand (the Fetcher's answer to `Probe`,
/// and the engine's `ImageNotLazy`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "proxy", derive(introspect::CustomType))]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "proxy", zlink(rename_all = "snake_case"))]
pub enum NotLazy {
    /// The blob has no table of contents (gzip, plain zstd)
    NoToc,
    /// The origin does not serve ranges of the blob
    NoRanges,
    /// This fetcher cannot reach the layer
    Unreachable,
    /// A compression or media type the fetcher does not read (also what a
    /// value this side does not know is read as)
    #[serde(other)]
    Unsupported,
}

impl NotLazy {
    /// The word of the wire.
    pub fn word(self) -> &'static str {
        match self {
            Self::NoToc => "no_toc",
            Self::NoRanges => "no_ranges",
            Self::Unreachable => "unreachable",
            Self::Unsupported => "unsupported",
        }
    }
}

/// What the walker of a list of parties does with a failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    /// Ask the next party
    Next,
    /// The operation fails, naming this party
    Fail,
}

/// The step after a failure of this class from a helper (a fetcher or
/// pusher that is not the origin of the object) or from the origin.
pub fn next(class: FailureClass, is_origin: bool) -> Step {
    use FailureClass::*;
    match class {
        Unavailable | Transient | NotFound | Failed if !is_origin => Step::Next,
        Unavailable | Transient | NotFound | Failed | Unauthorized | Invalid | Forbidden
        | NoSpace => Step::Fail,
    }
}

impl FailureClass {
    /// The word of the wire.
    pub fn word(self) -> &'static str {
        match self {
            Self::Unavailable => "unavailable",
            Self::Transient => "transient",
            Self::Invalid => "invalid",
            Self::NotFound => "not_found",
            Self::Unauthorized => "unauthorized",
            Self::Forbidden => "forbidden",
            Self::NoSpace => "no_space",
            Self::Failed => "failed",
        }
    }

    /// Whether a call that failed like this may succeed when made again.
    pub fn is_transient(self) -> bool {
        self == FailureClass::Transient
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use FailureClass::*;

    #[test]
    fn the_word_of_a_class_is_its_name_on_the_wire() {
        for c in [
            Unavailable,
            Transient,
            Invalid,
            NotFound,
            Unauthorized,
            Forbidden,
            NoSpace,
            Failed,
        ] {
            assert_eq!(
                serde_json::to_string(&c).unwrap(),
                format!("\"{}\"", c.word())
            );
        }
    }

    #[test]
    fn the_table_of_the_walk() {
        let helper = [
            (Unavailable, Step::Next),
            (Transient, Step::Next),
            (Invalid, Step::Fail),
            (NotFound, Step::Next),
            (Unauthorized, Step::Fail),
            (Forbidden, Step::Fail),
            (NoSpace, Step::Fail),
            (Failed, Step::Next),
        ];
        for (class, step) in helper {
            assert_eq!(next(class, false), step, "{class:?} from a helper");
            let origin = if step == Step::Next { Step::Fail } else { step };
            assert_eq!(next(class, true), origin, "{class:?} from the origin");
        }
    }

    #[test]
    fn a_class_this_side_does_not_know_is_failed() {
        let f: Failure = serde_json::from_str(r#"{"class":"brand_new","reason":"x"}"#).unwrap();
        assert_eq!(f.class, Failed);
        let f: Failure = serde_json::from_str(r#"{"class":"no_space","reason":"x"}"#).unwrap();
        assert_eq!(f.class, NoSpace);
    }
}
