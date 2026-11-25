// SPDX-License-Identifier: Apache-2.0
use thiserror::Error;
use velarx_proto::transfer::{Failure, FailureClass};

#[derive(Error, Debug)]
pub enum ImageError {
    #[error("registry error: {}", printable(.0))]
    Registry(String),
    /// The registry did not take the credentials it was given.
    #[error("registry error: {}", printable(.0))]
    Unauthorized(String),
    /// The registry refused the request for lack of permission (403): the
    /// credentials were taken, they do not allow it.
    #[error("registry error: {}", printable(.0))]
    Forbidden(String),
    /// The registry could not be reached (it did not answer, or not as a
    /// registry).
    #[error("registry error: {}", printable(.0))]
    Unreachable(String),
    /// The registry does not have what was asked (404).
    #[error("registry error: {}", printable(.0))]
    RegistryNotFound(String),
    /// A party of a transfer (a fetcher, a pusher, a transport, the store)
    /// failed, and how: what the walk of the engine did with it is in
    /// `velarx_proto::transfer::next`.  `party` is the name as configured
    /// (`registry`, `dir`, a `[[sources.external]]` name, a `[[transports]]`
    /// scheme) or `store`; `object` a digest, or the key of a file in a
    /// table of contents.
    #[error("{}", transfer_text(.party, .object.as_deref(), &.failure.reason))]
    Transfer {
        party: String,
        object: Option<String>,
        failure: Failure,
    },
    #[error("manifest error: {}", printable(.0))]
    Manifest(String),
    #[error("layer error: {}", printable(.0))]
    Layer(String),
    #[error("digest mismatch: expected {}, got {}", printable(.expected), printable(.actual))]
    DigestMismatch { expected: String, actual: String },
    /// A zstd:chunked layer is refused for its table of contents, which its
    /// descriptor vouches for: the registry gave other bytes than the
    /// table says, the table lies about the blob, or it cannot be used.
    /// Trying again would give the same.
    #[error("the layer is refused: {}", printable(.0))]
    Contradicted(String),
    #[error("not found: {}", printable(.0))]
    NotFound(String),
    /// The image is being pulled: it is not an image of the store until its
    /// layers are all in it.
    #[error("{}", printable(.0))]
    Pulling(String),
    /// The fs-verity digest a manifest states for the EROFS image of a layer
    /// is not the one of the image velarx made, or is not a digest, or is
    /// missing where `[storage] composefs_digests` requires it.
    #[error("composefs digest: {}", printable(.0))]
    ComposefsDigest(String),
    /// A reference podman refuses before it looks for it, with its words.
    #[error("{}", printable(.0))]
    Invalid(String),
    /// (its text says "database error")
    #[error("{}", printable(&.0.to_string()))]
    Database(#[from] crate::db::DbError),
    #[error("IO error: {}", printable(&.0.to_string()))]
    Io(#[from] std::io::Error),
    /// The ids of this process could not be read.
    #[error("{}", printable(&.0.to_string()))]
    Ids(#[from] velarx_base::ids::IdsError),
    #[error("HTTP error: {}", printable(&.0.text))]
    Http(HttpError),
    #[error("JSON error: {}", printable(&.0.to_string()))]
    Json(#[from] serde_json::Error),
    #[error("storage error: {}", printable(.0))]
    Storage(String),
    /// What an additional image store has cannot change.
    #[error("{}", printable(.0))]
    ReadOnly(String),
    /// An image in a Docker format, which velarx does not support.
    #[error("{}", printable(.0))]
    DockerFormat(String),
    /// A lazy pull was asked for an image whose `layers` the list of fetchers of the
    /// pull cannot serve lazily; nothing of it was created.
    #[error("{}", printable(&not_lazy_text(.image, .layers)))]
    NotLazy {
        image: String,
        layers: Vec<NotLazyLayer>,
    },
    /// The image has more layers than the storage driver mounts: the overlay
    /// of a container takes `overlay` layers altogether, data-only layers
    /// among them: the objects of each of the `stores` and, for a lazy pull,
    /// the directory of the files fetched for each layer.  Nothing of the
    /// image was created.
    #[error(
        "image {image} has {layers} layers, more than the {limit} that {} here (the overlay of a container takes {overlay} layers altogether, {stores} of them for the objects of the stores{})",
        if *.lazy { "a lazy pull can mount" } else { "can be mounted" },
        if *.lazy { ", and a lazy image two for each of its layers: the layer and the files fetched for it; pull it without --lazy" } else { "" }
    )]
    TooManyLayers {
        image: String,
        layers: usize,
        limit: usize,
        overlay: usize,
        stores: usize,
        lazy: bool,
    },
    /// The process may not have as many open files as mounting the image
    /// takes, and the hard limit is below that: only a higher hard limit
    /// mends it.  Nothing of the image was created.
    #[error(
        "image {image}: mounting it needs {needed} open files ({} for each of its {layers} layers and {} for the engine), more than the hard limit of {hard}: raise the hard limit of open files (`ulimit -Hn`, `LimitNOFILE=` of the unit)",
        velarx_base::hardening::OPEN_FILES_PER_LAYER,
        velarx_base::hardening::OPEN_FILES_BASE
    )]
    NoOpenFiles {
        image: String,
        layers: usize,
        needed: u64,
        hard: u64,
    },
}

/// A layer of an image that cannot be pulled lazily, and why: `no_toc`,
/// `no_ranges`, `unsupported` or `unreachable`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct NotLazyLayer {
    /// Its position in the manifest, from 0
    pub index: u32,
    pub digest: String,
    pub media_type: String,
    pub reason: velarx_proto::transfer::NotLazy,
}

/// What a person reads of [`ImageError::NotLazy`].
pub fn not_lazy_text(image: &str, layers: &[NotLazyLayer]) -> String {
    use velarx_proto::transfer::NotLazy as Why;
    let why = |l: &NotLazyLayer| match l.reason {
        Why::NoToc => format!("{} has no table of contents", l.media_type),
        Why::NoRanges => "its registry does not serve ranges of the blob".to_string(),
        Why::Unsupported => format!("{} is not read lazily", l.media_type),
        Why::Unreachable => "no fetcher of the list reaches it".to_string(),
    };
    let each: Vec<String> = layers
        .iter()
        .map(|l| format!("layer {} ({}): {}", l.index + 1, l.digest, why(l)))
        .collect();
    format!(
        "{image} cannot be pulled lazily: {}.  Pull it without --lazy",
        each.join("; ")
    )
}

/// A TLS failure that clients of podman tell by Go's words.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsError {
    /// The certificate of the server is not signed by an authority that is
    /// trusted (Go: `x509: certificate signed by unknown authority`).
    UnknownAuthority,
}

impl TlsError {
    /// Go's words for it.
    pub fn go_words(self) -> &'static str {
        match self {
            TlsError::UnknownAuthority => "x509: certificate signed by unknown authority",
        }
    }
}

/// The TLS failure in the causes of `err`: the error of the TLS library,
/// by its type.  What went wrong with the certificate is in its text only
/// (native-tls keeps the verification result for its `Display`), so the
/// text of that one error is read, and no other.
#[cfg(feature = "http")]
fn tls_error_of(err: &(dyn std::error::Error + 'static)) -> Option<TlsError> {
    const UNKNOWN_AUTHORITY: [&str; 2] = [
        "self-signed certificate",
        "unable to get local issuer certificate",
    ];
    let mut source = Some(err);
    while let Some(cause) = source {
        if let Some(tls) = cause.downcast_ref::<native_tls::Error>() {
            let text = tls.to_string();
            return (text.contains("certificate verify failed")
                && UNKNOWN_AUTHORITY.iter().any(|w| text.contains(w)))
            .then_some(TlsError::UnknownAuthority);
        }
        source = cause.source();
    }
    None
}

/// A request over HTTP that failed: its text (its causes, and Go's words
/// for a TLS failure that podman's clients match), the TLS failure that
/// caused it, and the error of the HTTP client for the code that made the
/// request.  The HTTP client is only in the processes that make requests
/// (the `http` feature makes this from its error); the others only read
/// the text.
#[derive(Debug)]
pub struct HttpError {
    text: String,
    tls: Option<TlsError>,
    /// The connection (or its TLS handshake) did not come up in time
    connect_timeout: bool,
    cause: Box<dyn std::error::Error + Send + Sync>,
}

impl HttpError {
    /// Whether the connection to the server did not come up in time: a
    /// server that is not there, which a try again does not bring.
    pub fn is_connect_timeout(&self) -> bool {
        self.connect_timeout
    }

    /// The error of the HTTP client.
    pub fn cause(&self) -> &(dyn std::error::Error + Send + Sync + 'static) {
        &*self.cause
    }
}

#[cfg(feature = "http")]
impl From<reqwest::Error> for ImageError {
    fn from(err: reqwest::Error) -> Self {
        let tls = tls_error_of(&err);
        let mut text = error_chain(&err);
        if let Some(tls) = tls {
            text = format!("{text}: {}", tls.go_words());
        }
        ImageError::Http(HttpError {
            text,
            tls,
            connect_timeout: err.is_connect() && err.is_timeout(),
            cause: Box::new(err),
        })
    }
}

/// What a person reads of a failure of a party.
fn transfer_text(party: &str, object: Option<&str>, reason: &str) -> String {
    match object {
        Some(object) => format!(
            "{}: {}: {}",
            printable(party),
            printable(object),
            printable(reason)
        ),
        None => format!("{}: {}", printable(party), printable(reason)),
    }
}

impl ImageError {
    /// A failure of `party` of the class `class`.
    pub fn transfer(
        party: impl Into<String>,
        class: FailureClass,
        reason: impl Into<String>,
    ) -> Self {
        ImageError::Transfer {
            party: party.into(),
            object: None,
            failure: Failure {
                class,
                reason: reason.into(),
            },
        }
    }

    /// The same, about an object (a digest, or the key of a file).
    pub fn transfer_of(
        party: impl Into<String>,
        object: impl Into<String>,
        class: FailureClass,
        reason: impl Into<String>,
    ) -> Self {
        ImageError::Transfer {
            party: party.into(),
            object: Some(object.into()),
            failure: Failure {
                class,
                reason: reason.into(),
            },
        }
    }

    /// The words of the error for a message that names the party that
    /// failed: what the registry's own variants say, without their
    /// `registry error:`.
    pub fn reason(&self) -> String {
        match self {
            ImageError::Registry(t)
            | ImageError::Unauthorized(t)
            | ImageError::Forbidden(t)
            | ImageError::Unreachable(t)
            | ImageError::RegistryNotFound(t) => printable(t),
            e => e.to_string(),
        }
    }

    /// The class of the failure of a party, when this is one.
    pub fn class(&self) -> Option<FailureClass> {
        match self {
            ImageError::Transfer { failure, .. } => Some(failure.class),
            _ => None,
        }
    }

    /// The TLS failure that made a request fail, if one did.
    pub fn tls_error(&self) -> Option<TlsError> {
        match self {
            ImageError::Http(e) => e.tls,
            _ => None,
        }
    }

    /// The status podman answers with for a failure of the registry
    /// (its HTTPStatusFromRegistryError): by the kind of the error.
    pub fn registry_status(&self) -> u16 {
        match self {
            ImageError::Unauthorized(_) => 401,
            ImageError::Forbidden(_) => 403,
            ImageError::RegistryNotFound(_) => 404,
            ImageError::Transfer { failure, .. } => match failure.class {
                FailureClass::Unauthorized => 401,
                FailureClass::Forbidden => 403,
                FailureClass::NotFound => 404,
                FailureClass::NoSpace => 507,
                _ => 500,
            },
            _ => 500,
        }
    }

    /// Whether a transfer that failed with this may succeed when it is
    /// tried again: the registry or the network failed on the way.  Not a
    /// refusal, a missing image, a format velarx refuses, a bad manifest,
    /// bytes that are not the digest they should be, a certificate that is
    /// not trusted, or this machine failing (a full disk: what
    /// `ImageError::Io` mostly is, by the kind of the system's error), or
    /// a server that did not answer the connection in time.
    pub fn is_transient(&self) -> bool {
        use std::io::ErrorKind as K;
        match self {
            ImageError::Registry(_) | ImageError::Unreachable(_) | ImageError::Layer(_) => true,
            ImageError::Transfer { failure, .. } => failure.class.is_transient(),
            ImageError::Io(e) => matches!(
                e.kind(),
                K::ConnectionRefused
                    | K::ConnectionReset
                    | K::ConnectionAborted
                    | K::NotConnected
                    | K::BrokenPipe
                    | K::TimedOut
                    | K::UnexpectedEof
                    | K::HostUnreachable
                    | K::NetworkUnreachable
                    | K::NetworkDown
            ),
            ImageError::Http(e) => e.tls.is_none() && !e.connect_timeout,
            _ => false,
        }
    }

    /// Whether the registry refused the credentials or what they allow
    /// (401, 403).
    pub fn is_refusal(&self) -> bool {
        match self {
            ImageError::Transfer { failure, .. } => {
                matches!(
                    failure.class,
                    FailureClass::Unauthorized | FailureClass::Forbidden
                )
            }
            _ => matches!(self, ImageError::Unauthorized(_) | ImageError::Forbidden(_)),
        }
    }
}

/// Text that comes from a registry or an image (error bodies, file names)
/// ends up in messages shown on a terminal: control characters, which could
/// carry escape sequences, are made visible.
pub fn printable(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_control() { '\u{fffd}' } else { c })
        .collect()
}

/// An error with the causes that explain it ("error sending request" alone
/// does not say whether it was DNS, TCP or TLS).
#[cfg(feature = "http")]
fn error_chain(err: &dyn std::error::Error) -> String {
    let mut msg = err.to_string();
    let mut source = err.source();
    while let Some(cause) = source {
        msg.push_str(": ");
        msg.push_str(&cause_text(cause));
        source = cause.source();
    }
    msg
}

/// The text of a cause; the system's errors in the words podman's messages
/// have (Go's: `connection refused`, not `Connection refused (os error
/// 111)`), which scripts match.
#[cfg(feature = "http")]
fn cause_text(cause: &(dyn std::error::Error + 'static)) -> String {
    let text = cause.to_string();
    let Some(code) = cause
        .downcast_ref::<std::io::Error>()
        .and_then(std::io::Error::raw_os_error)
    else {
        return text;
    };
    let words = text
        .strip_suffix(&format!(" (os error {code})"))
        .unwrap_or(&text);
    let mut chars = words.chars();
    match chars.next() {
        Some(first) => first.to_lowercase().chain(chars).collect(),
        None => text,
    }
}

pub type ImageResult<T> = Result<T, ImageError>;

#[cfg(test)]
mod printable_tests {
    use super::*;

    #[cfg(feature = "http")]
    #[test]
    fn the_errors_of_the_system_are_in_gos_words() {
        #[derive(Debug)]
        struct Connect(std::io::Error);
        impl std::fmt::Display for Connect {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("tcp connect error")
            }
        }
        impl std::error::Error for Connect {
            fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
                Some(&self.0)
            }
        }
        // (ECONNREFUSED)
        let refused = Connect(std::io::Error::from_raw_os_error(111));
        assert_eq!(
            error_chain(&refused),
            "tcp connect error: connection refused"
        );
        // (an error that is not the system's keeps its words)
        let other = Connect(std::io::Error::other("Bad Thing"));
        assert_eq!(error_chain(&other), "tcp connect error: Bad Thing");
    }

    #[test]
    fn errors_show_no_control_characters() {
        let evil = "a\u{1b}[2Jb\nc";
        for e in [
            ImageError::NotFound(evil.into()),
            ImageError::Storage(evil.into()),
            ImageError::Io(std::io::Error::other(evil)),
            ImageError::Registry(evil.into()),
        ] {
            let s = e.to_string();
            assert!(!s.chars().any(char::is_control), "{s:?}");
        }
    }
}

#[cfg(test)]
mod status_tests {
    use super::*;

    /// The REST status of a registry failure comes from the kind of the
    /// error, whatever its words.
    #[test]
    fn registry_status_follows_the_kind() {
        let words = "UNAUTHORIZED 404 Not Found DENIED";
        assert_eq!(
            ImageError::Unauthorized(words.into()).registry_status(),
            401
        );
        assert_eq!(ImageError::Forbidden(words.into()).registry_status(), 403);
        assert_eq!(
            ImageError::RegistryNotFound(words.into()).registry_status(),
            404
        );
        assert_eq!(ImageError::Registry(words.into()).registry_status(), 500);
        assert!(ImageError::Forbidden(String::new()).is_refusal());
        assert!(!ImageError::RegistryNotFound(String::new()).is_refusal());
    }

    #[test]
    fn the_reason_of_a_registry_failure_does_not_say_registry_error() {
        let e = ImageError::Unauthorized("denied\n".into());
        assert_eq!(e.to_string(), "registry error: denied\u{fffd}");
        assert_eq!(e.reason(), "denied\u{fffd}");
        let e = ImageError::Layer("short".into());
        assert_eq!(e.reason(), e.to_string());
    }

    /// A transfer is tried again after what the registry or the network
    /// did on the way, and after nothing the user must mend.
    #[test]
    fn a_failure_on_the_way_is_transient_and_a_refusal_is_not() {
        for e in [
            ImageError::Registry("503".into()),
            ImageError::Unreachable("no route".into()),
            ImageError::Io(std::io::ErrorKind::ConnectionReset.into()),
            ImageError::Io(std::io::ErrorKind::UnexpectedEof.into()),
            ImageError::Layer("short".into()),
        ] {
            assert!(e.is_transient(), "{e}");
        }
        for e in [
            // (this machine: a full disk (ENOSPC), a file system that fails)
            ImageError::Io(std::io::Error::from_raw_os_error(28)),
            ImageError::Io(std::io::ErrorKind::StorageFull.into()),
            ImageError::Io(std::io::Error::other("no space")),
            ImageError::DigestMismatch {
                expected: "a".into(),
                actual: "b".into(),
            },
            ImageError::Unauthorized("401".into()),
            ImageError::Forbidden("403".into()),
            ImageError::RegistryNotFound("404".into()),
            ImageError::NotFound("x".into()),
            ImageError::Manifest("bad".into()),
            ImageError::DockerFormat("v1".into()),
            ImageError::Contradicted("toc".into()),
        ] {
            assert!(!e.is_transient(), "{e}");
        }
    }

    /// A failure of a party is read by its class, not by its words.
    #[test]
    fn a_transfer_is_read_by_its_class() {
        let by = |c| ImageError::transfer("dir", c, "UNAUTHORIZED 404 words");
        assert_eq!(by(FailureClass::Unauthorized).registry_status(), 401);
        assert_eq!(by(FailureClass::Forbidden).registry_status(), 403);
        assert_eq!(by(FailureClass::NotFound).registry_status(), 404);
        assert_eq!(by(FailureClass::NoSpace).registry_status(), 507);
        assert_eq!(by(FailureClass::Invalid).registry_status(), 500);
        assert!(by(FailureClass::Transient).is_transient());
        for c in [
            FailureClass::Unavailable,
            FailureClass::Invalid,
            FailureClass::NotFound,
            FailureClass::Failed,
        ] {
            assert!(!by(c).is_transient(), "{c:?}");
        }
        assert!(by(FailureClass::Forbidden).is_refusal());
        let e = ImageError::transfer_of("dir", "sha256:x", FailureClass::Invalid, "bad");
        assert_eq!(e.to_string(), "dir: sha256:x: bad");
    }
}
