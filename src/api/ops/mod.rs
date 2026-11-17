// SPDX-License-Identifier: Apache-2.0
//! The operations of the API: what a route does, with typed requests and
//! answers.  The routes of the API server are adapters of them (they read
//! the request, call the operation, write its answer), and so is the engine
//! service (`crate::engine_service`), which a command with no engine service
//! serves from its own process.

use crate::api::status::StatusCode;
use bytes::Bytes;
use std::pin::Pin;

pub mod container;
pub mod image;
pub mod pod;
/// podman's views of the objects.
pub mod wait;

/// The error of an operation: the status of the API and its message.
#[derive(Debug)]
pub struct Error {
    pub status: StatusCode,
    pub message: String,
    /// The `code` of velarx's error answer.
    pub code: u32,
    /// A 409 because of the state of the object (running, in use), not of
    /// a name that is taken
    pub state: bool,
    /// A 404 of another kind of object than the one asked about (the image
    /// of a container that is created)
    pub no_such: Option<super::podman::error::Kind>,
    /// The condition of the engine's interface, when the status does not
    /// name it (a container that could not start)
    pub condition: Option<velarx_proto::engine::Condition>,
}

pub type Result<T> = std::result::Result<T, Error>;

impl Error {
    pub fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
            code: 10,
            state: false,
            no_such: None,
            condition: None,
        }
    }

    /// The error is of `condition`, which has its own status.
    pub fn with_condition(mut self, condition: Option<velarx_proto::engine::Condition>) -> Self {
        if let Some(c) = condition {
            self.status = StatusCode::from_u16(c.status()).unwrap_or(self.status);
        }
        self.condition = condition;
        self
    }

    /// A 409: the object is in a state that does not allow this (running,
    /// paused, in use, has dependents).
    pub fn invalid_state(message: impl Into<String>) -> Self {
        Self {
            state: true,
            ..Self::new(StatusCode::CONFLICT, message)
        }
    }

    /// The error with the status `status`, a 409 of the state of the object
    /// when `state`.
    pub fn with_state(mut self, state: bool) -> Self {
        self.state = state && self.status == StatusCode::CONFLICT;
        self
    }

    pub fn with_code(mut self, code: u32) -> Self {
        self.code = code;
        self
    }

    pub fn internal(message: impl std::fmt::Display) -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, message.to_string())
    }

    pub fn bad_request(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, message)
    }

    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, message)
    }

    /// An error of the REST API, as a route of `kind` says it.
    pub fn podman(e: super::podman::error::ApiError, kind: super::podman::error::Kind) -> Self {
        let state = e.is_invalid_state();
        let condition = e.condition();
        let (status, _, message) = e.finish(kind);
        Self::new(status, message)
            .with_state(state)
            .with_condition(condition)
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

/// The bytes an operation reads (an archive, a context) or writes, as they
/// come.
pub type ByteStream = Pin<Box<dyn futures::Stream<Item = std::io::Result<Bytes>> + Send>>;
