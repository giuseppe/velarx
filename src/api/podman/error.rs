// SPDX-License-Identifier: Apache-2.0
//! podman's error responses: `{"cause", "message", "response"}`.

use crate::api::status::StatusCode;
use velarx_proto::engine::Condition;

/// The kind of object a route works on: it gives the "cause" of a not found
/// error, which podman clients match in the message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    None,
    Container,
    Image,
    Exec,
    Pod,
    Volume,
    Network,
    Secret,
    Artifact,
}

impl Kind {
    pub fn not_found_cause(self) -> &'static str {
        match self {
            Kind::Container => "no such container",
            // storage's ErrImageUnknown, the cause podman gives
            Kind::Image => "image not known",
            Kind::Exec => "no such exec session",
            Kind::Pod => "no such pod",
            Kind::Volume => "no such volume",
            Kind::Network => "network not found",
            Kind::Secret => "no such secret",
            Kind::Artifact => "artifact does not exist",
            Kind::None => "no such object",
        }
    }
}

#[derive(Debug)]
pub struct ApiError {
    pub status: StatusCode,
    cause: Option<String>,
    kind: Option<Kind>,
    /// A 409 because of the state of the object (running, in use), not of
    /// a name that is taken
    state: bool,
    /// The condition of the engine's interface, when the status does not
    /// name it (a container that could not start)
    condition: Option<Condition>,
    /// The image and the layers of an `ImageNotLazy`
    not_lazy: Option<Box<(String, Vec<velarx_types::NotLazyLayer>)>>,
    /// The party, the object and whether the call may succeed when made
    /// again, of an `InvalidContent` or a `SourceUnavailable`
    transfer: Option<Box<(String, String, bool)>>,
    pub message: String,
}

pub type ApiResult<T> = Result<T, ApiError>;

impl ApiError {
    pub fn new(status: u16, message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
            cause: None,
            kind: None,
            state: false,
            condition: None,
            not_lazy: None,
            transfer: None,
            message: message.into(),
        }
    }

    /// The error is of `condition`, which has its own status.
    pub fn with_condition(mut self, condition: Condition) -> Self {
        self.status = StatusCode::from_u16(condition.status()).unwrap_or(self.status);
        self.condition = Some(condition);
        self
    }

    /// The image and the layers of an `ImageNotLazy`, taken once.
    pub fn take_not_lazy(&mut self) -> Option<(String, Vec<velarx_types::NotLazyLayer>)> {
        self.not_lazy.take().map(|b| *b)
    }

    /// The party, the object and `transient` of a `SourceUnavailable` or an
    /// `InvalidContent`, taken once.
    pub fn take_transfer(&mut self) -> Option<(String, String, bool)> {
        self.transfer.take().map(|b| *b)
    }

    /// The error of a failure of a party of a transfer (a pull, a push), by
    /// its class: the one table of `velarx_proto::transfer`.  `pushing`: an
    /// object the origin does not have is not an image that is not there.
    /// None for an error that is not one.
    pub fn of_transfer(e: &velarx_types::ImageError, context: &str, pushing: bool) -> Option<Self> {
        use velarx_proto::transfer::FailureClass as C;
        let velarx_types::ImageError::Transfer {
            party,
            object,
            failure,
        } = e
        else {
            return None;
        };
        let message = format!("{context}{e}");
        let said = |condition: Condition, transient: bool| Self {
            transfer: Some(Box::new((
                party.clone(),
                object.clone().unwrap_or_default(),
                transient,
            ))),
            ..Self::internal(message.clone()).with_condition(condition)
        };
        Some(match failure.class {
            C::NotFound if !pushing => Self::no_such(Kind::Image, message),
            C::NotFound => Self::internal(message),
            C::Invalid => said(Condition::InvalidContent, false),
            C::Unavailable => said(Condition::SourceUnavailable, false),
            C::Transient => said(Condition::SourceUnavailable, true),
            _ => Self::new(e.registry_status(), message),
        })
    }

    /// The condition the error was given by [`ApiError::with_condition`].
    pub fn condition(&self) -> Option<Condition> {
        self.condition
    }

    pub fn bad_request(message: impl Into<String>) -> Self {
        Self::new(400, message)
    }

    pub fn internal(message: impl Into<String>) -> Self {
        Self::new(500, message)
    }

    /// A 409: the name is taken, the object exists already.
    pub fn conflict(message: impl Into<String>) -> Self {
        Self::new(409, message)
    }

    /// A 409: the object is in a state that does not allow this (running,
    /// paused, in use, has dependents).
    pub fn invalid_state(message: impl Into<String>) -> Self {
        Self {
            state: true,
            ..Self::new(409, message)
        }
    }

    /// The object is in a state that does not allow this
    /// ([`ApiError::invalid_state`]).
    pub fn is_invalid_state(&self) -> bool {
        self.state
    }

    pub fn not_implemented(message: impl Into<String>) -> Self {
        Self::new(501, message)
    }

    /// A 404 for the kind of the route.
    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new(404, message)
    }

    /// A 404 for an object of another kind than the route's (the image of a
    /// container create).
    pub fn no_such(kind: Kind, message: impl Into<String>) -> Self {
        Self {
            kind: Some(kind),
            ..Self::new(404, message)
        }
    }

    /// A database error of the operation `op`: a 404 for what is not there,
    /// else a 500 that names the operation and keeps the SQL error as the
    /// cause.  An error of the shape of the database (a column or a table
    /// that is missing) says the store is of another build.
    pub fn db(op: &str, e: velarx_types::DbError) -> Self {
        if e.is_not_found() {
            return Self::not_found(format!("{op}: {e}"));
        }
        let text = e.to_string();
        if text.contains("no such column") || text.contains("no such table") {
            Self::internal(format!(
                "{op}: {text}: the store was made by another build: remove it"
            ))
        } else {
            Self::internal(format!("{op}: {text}"))
        }
    }

    /// A lookup as an option: an object that is not there (a 404) is `None`,
    /// any other error stays one.
    pub fn found<T>(r: Result<T, impl Into<ApiError>>) -> ApiResult<Option<T>> {
        match r {
            Ok(v) => Ok(Some(v)),
            Err(e) => {
                let e = e.into();
                if e.status == StatusCode::NOT_FOUND {
                    Ok(None)
                } else {
                    Err(e)
                }
            }
        }
    }

    pub fn with_cause(mut self, cause: impl Into<String>) -> Self {
        self.cause = Some(cause.into());
        self
    }

    /// The error with `context` before its message: the status and the
    /// cause stay.
    pub fn in_context(mut self, context: impl std::fmt::Display) -> Self {
        self.message = format!("{context}: {}", self.message);
        self
    }

    /// The kind of object the error is about, else the route's.
    pub fn kind_or(&self, route_kind: Kind) -> Kind {
        self.kind.unwrap_or(route_kind)
    }

    /// The status, the cause and the message of the error of a route of
    /// `route_kind`, as a podman client sees them.
    pub fn finish(self, route_kind: Kind) -> (StatusCode, String, String) {
        let cause = match (&self.cause, self.status) {
            (Some(c), _) => c.clone(),
            (None, StatusCode::NOT_FOUND) => self
                .kind
                .unwrap_or(route_kind)
                .not_found_cause()
                .to_string(),
            (None, _) => self.message.clone(),
        };
        // The podman client matches the cause in the message.
        let message = if self.message.contains(&cause) {
            self.message
        } else {
            format!("{}: {}", self.message, cause)
        };
        (self.status, cause, message)
    }
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.status.as_u16(), self.message)
    }
}

impl From<std::io::Error> for ApiError {
    fn from(e: std::io::Error) -> Self {
        let status = match e.kind() {
            std::io::ErrorKind::NotFound => 404,
            std::io::ErrorKind::AlreadyExists => 409,
            std::io::ErrorKind::InvalidInput => 400,
            _ => 500,
        };
        Self::new(status, e.to_string())
    }
}

impl From<velarx_base::ids::IdsError> for ApiError {
    fn from(e: velarx_base::ids::IdsError) -> Self {
        Self::internal(e.to_string())
    }
}

impl From<velarx_base::dirs::DirsError> for ApiError {
    fn from(e: velarx_base::dirs::DirsError) -> Self {
        Self::internal(e.to_string())
    }
}

impl From<serde_json::Error> for ApiError {
    fn from(e: serde_json::Error) -> Self {
        Self::bad_request(format!("decode request: {e}"))
    }
}

impl From<velarx_types::transport::TransportError> for ApiError {
    fn from(e: velarx_types::transport::TransportError) -> Self {
        Self::bad_request(e.to_string())
    }
}

impl From<velarx_types::DbError> for ApiError {
    fn from(e: velarx_types::DbError) -> Self {
        if e.is_not_found() {
            Self::not_found(e.to_string())
        } else {
            Self::internal(e.to_string())
        }
    }
}

impl From<velarx_core::services::ContainerError> for ApiError {
    fn from(e: velarx_core::services::ContainerError) -> Self {
        use velarx_core::services::ContainerError as E;
        if let Some(condition) = e.condition() {
            return Self::new(500, e.to_string()).with_condition(condition);
        }
        match e {
            E::NotFound(_) => Self::new(404, e.to_string()),
            E::ImageNotFound(_) => Self::no_such(Kind::Image, e.to_string()),
            E::AlreadyExists(_) => Self::new(409, e.to_string()),
            E::InvalidArgument(_) => Self::bad_request(e.to_string()),
            E::MonitorLost(_) | E::MonitorVersion { .. } => Self::invalid_state(e.to_string()),
            E::NotRunning(_) | E::AlreadyRunning(_) | E::InvalidState(_) => {
                Self::invalid_state(e.to_string()).with_cause("container state improper")
            }
            E::Database(velarx_types::DbError::NotFound(_)) => Self::new(404, e.to_string()),
            E::Network(n) => n.into(),
            E::NoLogs { message, cause } => Self::internal(message).with_cause(cause),
            _ => Self::internal(e.to_string()),
        }
    }
}

impl From<velarx_types::ImageError> for ApiError {
    fn from(e: velarx_types::ImageError) -> Self {
        use velarx_types::ImageError as E;
        if let Some(error) = Self::of_transfer(&e, "", false) {
            return error;
        }
        match e {
            E::NotFound(_) | E::Pulling(_) => Self::no_such(Kind::Image, e.to_string()),
            E::ReadOnly(_) => Self::invalid_state(e.to_string()),
            E::DockerFormat(_) => Self::not_implemented(e.to_string()),
            E::NotLazy { image, layers } => Self {
                not_lazy: Some(Box::new((image.clone(), layers.clone()))),
                ..Self::bad_request(velarx_types::not_lazy_text(&image, &layers))
                    .with_condition(Condition::ImageNotLazy)
            },
            // (why, as the cause: the command turns it back into the refusal)
            E::Contradicted(ref why) => Self::internal(e.to_string())
                .with_cause(why.clone())
                .with_condition(Condition::Contradicted),
            // (an image this engine cannot mount, too many layers for the
            // overlay or for the open files the process may have: what the
            // client sent is refused, nothing failed inside)
            E::TooManyLayers { .. } | E::NoOpenFiles { .. } => {
                Self::new(413, e.to_string()).with_condition(Condition::TooLarge)
            }
            _ => Self::internal(e.to_string()),
        }
    }
}

impl From<velarx_core::services::VolumeError> for ApiError {
    fn from(e: velarx_core::services::VolumeError) -> Self {
        use velarx_core::services::VolumeError as E;
        match &e {
            E::NotFound(name) => {
                return Self::no_such(Kind::Volume, format!("no volume with name {name:?} found"))
            }
            E::AlreadyExists(_) => return Self::conflict(e.to_string()),
            E::InUse(_) => return Self::invalid_state(e.to_string()),
            E::InvalidName(_) => {
                return Self::bad_request(e.to_string()).with_condition(Condition::InvalidName)
            }
            _ => {}
        }
        Self::internal(e.to_string())
    }
}

impl From<velarx_core::services::PodError> for ApiError {
    fn from(e: velarx_core::services::PodError) -> Self {
        use velarx_core::services::PodError as E;
        use velarx_types::DbError;
        let msg = e.to_string();
        match e {
            E::InvalidConfig(_) => Self::bad_request(msg),
            E::NotFound(_) | E::Database(DbError::NotFound(_)) => Self::no_such(Kind::Pod, msg),
            E::AlreadyExists(_) | E::Database(DbError::AlreadyExists(_)) => Self::conflict(msg),
            E::ImageNotFound(_) => Self::no_such(Kind::Image, msg),
            _ => Self::internal(msg),
        }
    }
}

impl From<velarx_netkernel::error::NetworkError> for ApiError {
    fn from(e: velarx_netkernel::error::NetworkError) -> Self {
        use velarx_netkernel::error::NetworkError as E;
        use velarx_types::DbError;
        let msg = e.to_string();
        match e {
            E::NotFound(_) | E::Missing(_) | E::Database(DbError::NotFound(_)) => {
                Self::not_found(msg)
            }
            E::AlreadyExists(_) | E::Database(DbError::AlreadyExists(_)) => Self::conflict(msg),
            E::Busy(_) => Self::invalid_state(msg).with_cause("network is being used"),
            E::AlreadyConnected => Self::new(403, msg.clone()).with_cause(msg),
            E::InvalidConfig(_) => Self::bad_request(msg),
            E::NoPasta { .. } | E::OldPasta { .. } => {
                Self::internal(msg).with_condition(Condition::NoPasta)
            }
            _ => Self::internal(msg),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use velarx_core::services::ContainerError;

    /// A missing pasta, or one older than the release needed, is the same
    /// condition whether it comes from the container service or from the
    /// network service: `NoPasta`, 500.
    #[test]
    fn a_missing_pasta_is_the_condition_no_pasta() {
        use velarx_netkernel::error::NetworkError as N;
        let errors = || {
            [
                N::NoPasta {
                    searched: "/usr/bin".into(),
                    minimum: "2026_10_02",
                },
                N::OldPasta {
                    path: "/usr/bin/pasta".into(),
                    said: "pasta 2025_01_21.4f2c8e7".into(),
                    minimum: "2026_10_02",
                },
            ]
        };
        for (a, b) in errors().into_iter().zip(errors()) {
            let from_container: ApiError = ContainerError::Network(a).into();
            let from_network: ApiError = b.into();
            for e in [from_container, from_network] {
                assert_eq!(e.condition(), Some(Condition::NoPasta));
                assert_eq!(e.status.as_u16(), 500);
            }
        }
    }

    /// The status of an error is told by its kind, not by its words: an
    /// error that says "not found" of something else is no 404.
    #[test]
    fn the_status_is_of_the_kind_of_the_error() {
        use velarx_core::services::{PodError, VolumeError};
        use velarx_types::DbError;
        let status = |e: ApiError| e.status.as_u16();
        assert_eq!(status(DbError::NotFound("container c".into()).into()), 404);
        let no_rows = tokio_rusqlite::Error::Rusqlite(rusqlite::Error::QueryReturnedNoRows);
        assert_eq!(status(DbError::Sqlite(no_rows).into()), 404);
        let other = || DbError::Sqlite(tokio_rusqlite::Error::Other("a file not found".into()));
        assert_eq!(status(other().into()), 500);
        assert_eq!(status(ContainerError::Database(other()).into()), 500);
        let gone = || DbError::NotFound("container c".into());
        assert_eq!(status(ContainerError::Database(gone()).into()), 404);
        let io = std::io::Error::other("the device was not found");
        assert_eq!(status(VolumeError::Io(io).into()), 500);
        assert_eq!(
            status(PodError::Container("network n not found".into()).into()),
            500
        );
        assert_eq!(status(PodError::Database(gone()).into()), 404);
        assert_eq!(
            status(PodError::ImageNotFound("image not found: i".into()).into()),
            404
        );
        let taken = PodError::Database(DbError::AlreadyExists("name p".into()));
        assert_eq!(status(taken.into()), 409);
    }

    #[test]
    fn a_container_that_logs_nothing_gives_podmans_cause() {
        let e = ApiError::from(ContainerError::NoLogs {
            message:
                "the 'none' log driver, cannot read logs: this container is not logging output"
                    .into(),
            cause: "this container is not logging output".into(),
        });
        let (status, cause, message) = e.finish(Kind::Container);
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(cause, "this container is not logging output");
        assert!(message.starts_with("the 'none' log driver"), "{message}");
    }

    /// A failure of a party is the error of its class: what content a party
    /// gave that is not its claim and a source that cannot give it carry the
    /// party; an object the origin lacks is a missing image to a pull and a
    /// plain failure to a push.
    #[test]
    fn a_transfer_failure_is_the_error_of_its_class() {
        use velarx_proto::transfer::FailureClass as C;
        let of = |c, pushing| {
            let e = velarx_types::ImageError::transfer_of("dir", "sha256:x", c, "words");
            ApiError::of_transfer(&e, "", pushing).unwrap()
        };
        let mut e = of(C::Invalid, false);
        assert_eq!(e.condition(), Some(Condition::InvalidContent));
        assert_eq!(
            e.take_transfer(),
            Some(("dir".into(), "sha256:x".into(), false))
        );
        let mut e = of(C::Transient, false);
        assert_eq!(e.condition(), Some(Condition::SourceUnavailable));
        assert_eq!(e.take_transfer().map(|t| t.2), Some(true));
        let mut e = of(C::Unavailable, false);
        assert_eq!(e.take_transfer().map(|t| t.2), Some(false));
        assert_eq!(of(C::NotFound, false).status.as_u16(), 404);
        assert_eq!(of(C::NotFound, true).status.as_u16(), 500);
        assert_eq!(of(C::Unauthorized, false).status.as_u16(), 401);
        assert_eq!(of(C::NoSpace, false).status.as_u16(), 507);
        assert_eq!(of(C::Failed, false).status.as_u16(), 500);
    }
}
