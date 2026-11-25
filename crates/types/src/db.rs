// SPDX-License-Identifier: Apache-2.0
use thiserror::Error;

#[derive(Error, Debug)]
pub enum DbError {
    /// Said with the words of SQLite or of the check that refused the
    /// database (not tokio_rusqlite's `Rusqlite("...")`), and with no source:
    /// the text already has it, and a chain would say it again.
    #[cfg(feature = "sqlite")]
    #[error("database error: {}", inner(.0))]
    Sqlite(tokio_rusqlite::Error),
    #[error("not found: {0}")]
    NotFound(String),
    #[error("already exists: {0}")]
    AlreadyExists(String),
    /// The SELinux level a new container was given is taken by another
    /// container that was recorded since it was chosen.
    #[error("the SELinux level {0} is taken by another container")]
    LevelTaken(String),
}

impl DbError {
    /// Whether what was asked for is not there: [`DbError::NotFound`], or
    /// the lookup of one row that found none.
    pub fn is_not_found(&self) -> bool {
        match self {
            Self::NotFound(_) => true,
            #[cfg(feature = "sqlite")]
            Self::Sqlite(tokio_rusqlite::Error::Rusqlite(rusqlite::Error::QueryReturnedNoRows)) => {
                true
            }
            _ => false,
        }
    }
}

#[cfg(feature = "sqlite")]
impl From<tokio_rusqlite::Error> for DbError {
    fn from(e: tokio_rusqlite::Error) -> Self {
        Self::Sqlite(e)
    }
}

#[cfg(feature = "sqlite")]
fn inner(e: &tokio_rusqlite::Error) -> String {
    match e {
        tokio_rusqlite::Error::Rusqlite(e) => e.to_string(),
        tokio_rusqlite::Error::Other(e) => e.to_string(),
        e => e.to_string(),
    }
}

pub type DbResult<T> = Result<T, DbError>;
