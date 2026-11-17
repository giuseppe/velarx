// SPDX-License-Identifier: Apache-2.0
//! The status of an answer of the API: a number, with the names of the ones
//! the operations give.  The HTTP server (velarx-api) is the one that
//! knows HTTP.

/// An HTTP status code (100 to 599).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StatusCode(u16);

impl StatusCode {
    pub const BAD_REQUEST: Self = Self(400);
    pub const FORBIDDEN: Self = Self(403);
    pub const NOT_FOUND: Self = Self(404);
    pub const CONFLICT: Self = Self(409);
    pub const PAYLOAD_TOO_LARGE: Self = Self(413);
    pub const INTERNAL_SERVER_ERROR: Self = Self(500);
    pub const NOT_IMPLEMENTED: Self = Self(501);
    pub const INSUFFICIENT_STORAGE: Self = Self(507);

    /// The status `code`, None when it is not a status code.
    pub fn from_u16(code: u16) -> Option<Self> {
        (100..600).contains(&code).then_some(Self(code))
    }

    pub fn as_u16(self) -> u16 {
        self.0
    }
}

impl PartialEq<u16> for StatusCode {
    fn eq(&self, other: &u16) -> bool {
        self.0 == *other
    }
}

impl std::fmt::Display for StatusCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}
