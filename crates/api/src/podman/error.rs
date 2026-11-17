// SPDX-License-Identifier: Apache-2.0
//! podman's error responses: `{"cause", "message", "response"}`.

use axum::body::Body;
use axum::http::{header, StatusCode};
use axum::response::Response;
use serde_json::json;

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
    /// The condition the engine named
    condition: Option<velarx_proto::engine::Condition>,
    pub message: String,
}

pub type ApiResult<T = Response> = Result<T, ApiError>;

impl ApiError {
    pub fn new(status: u16, message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
            cause: None,
            kind: None,
            condition: None,
            message: message.into(),
        }
    }

    /// The error is of `condition`, which the engine named.
    pub fn with_condition(mut self, condition: velarx_proto::engine::Condition) -> Self {
        self.condition = Some(condition);
        self
    }

    /// The engine named this condition.
    pub fn is(&self, wanted: velarx_proto::engine::Condition) -> bool {
        self.condition == Some(wanted)
    }

    pub fn bad_request(message: impl Into<String>) -> Self {
        Self::new(400, message)
    }

    pub fn internal(message: impl Into<String>) -> Self {
        Self::new(500, message)
    }

    pub fn conflict(message: impl Into<String>) -> Self {
        Self::new(409, message)
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

    /// An error the engine shaped: the status, cause and message are its.
    pub fn from_engine(status: u16, cause: String, message: String) -> Self {
        Self {
            cause: Some(cause),
            ..Self::new(status, message)
        }
    }

    /// podman answers every failure of a removal or a stop that is not a
    /// missing object with a 500 (a state, a dependent or a use the engine
    /// tells apart): the engine's condition is kept in the message only.
    pub fn as_podman_failure(self) -> Self {
        match self.status.as_u16() {
            400 | 409 => self.with_status(StatusCode::INTERNAL_SERVER_ERROR),
            _ => self,
        }
    }

    pub fn with_status(mut self, status: StatusCode) -> Self {
        self.status = status;
        self
    }

    pub fn with_cause(mut self, cause: impl Into<String>) -> Self {
        self.cause = Some(cause.into());
        self
    }

    /// podman's answer when the logs of the container `name` cannot be
    /// read (its log driver keeps none...): the reason is the cause.
    pub fn logs_failed(self, name: &str) -> Self {
        if self.status != StatusCode::INTERNAL_SERVER_ERROR {
            return self;
        }
        let cause = self.cause.clone().unwrap_or_else(|| self.message.clone());
        Self {
            message: format!(
                "failed to obtain logs for Container '{name}': {}",
                self.message
            ),
            cause: Some(cause),
            ..self
        }
    }

    pub fn into_response(self, route_kind: Kind) -> Response {
        let (status, cause, message) = self.finish(route_kind);
        error_response(status, &cause, &message)
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

pub fn error_response(status: StatusCode, cause: &str, message: &str) -> Response {
    let mut body = json!({
        "cause": cause,
        "message": message,
        "response": status.as_u16(),
    })
    .to_string();
    body.push('\n');
    let mut res = Response::new(Body::from(body));
    *res.status_mut() = status;
    res.headers_mut().insert(
        header::CONTENT_TYPE,
        header::HeaderValue::from_static("application/json"),
    );
    res
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

impl From<serde_json::Error> for ApiError {
    fn from(e: serde_json::Error) -> Self {
        Self::bad_request(format!("decode request: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn engine_conditions_are_podmans_500_for_a_removal() {
        for (from, to) in [(409, 500), (400, 500), (404, 404), (503, 503)] {
            let e = ApiError::new(from, "x").as_podman_failure();
            assert_eq!(e.status.as_u16(), to);
        }
    }

    #[test]
    fn the_logs_that_cannot_be_read_are_said_in_podmans_words() {
        let e = ApiError::internal(
            "this container is using the 'passthrough' log driver, cannot read logs: \
             this container is not logging output",
        )
        .with_cause("this container is not logging output")
        .logs_failed("pt");
        assert_eq!(
            e.message,
            "failed to obtain logs for Container 'pt': this container is using the \
             'passthrough' log driver, cannot read logs: this container is not logging output"
        );
        assert_eq!(
            e.cause.as_deref(),
            Some("this container is not logging output")
        );
        // (an error with no cause of its own is its own cause: no part of
        // its text is taken for one)
        let e = ApiError::internal("journal: the file: cannot be read").logs_failed("pt");
        assert_eq!(
            e.cause.as_deref(),
            Some("journal: the file: cannot be read")
        );
        // (a container that is not there is not a failure to read)
        let e = ApiError::new(404, "no container").logs_failed("pt");
        assert_eq!(e.message, "no container");
    }
}
