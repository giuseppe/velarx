// SPDX-License-Identifier: Apache-2.0
//! The error type of the signature modules.

use thiserror::Error;

#[derive(Error, Debug)]
pub enum SignatureError {
    #[error("invalid signature format: {0}")]
    InvalidFormat(String),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Ids(#[from] velarx_base::ids::IdsError),
}

pub type SignatureResult<T> = Result<T, SignatureError>;
