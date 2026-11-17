// SPDX-License-Identifier: Apache-2.0
//! The calls of the registry fetcher (`org.velarx.Registry`): the tags, a
//! search, a login and a download.  Served beside the fetcher interface on
//! the socket of `velarx-registry` ([`crate::serve_fetch`]); a fetcher that
//! is not the registry's answers them `Failed` of class `unavailable`.
//!
//! A call names its repository and carries its own credentials (the JSON of
//! a `RegistryAccess` in a sealed memory file, the descriptor `Remote::access`
//! names): it has no scope.  `Tags` and `Search` answer one item a reply.

use crate::fetcher::proto::{Downloaded, Hit, RegistryError, Remote, MAX_ACCESS, MAX_TEXT};
use crate::fetcher::Cancel;
use crate::serve_fetch::Out;
use async_trait::async_trait;
use std::fs::File;
use velarx_proto::descriptors::Descriptors;
use velarx_types::digest::Digest;

/// A call about a repository of a registry.
pub struct RemoteCall {
    pub remote: Remote,
    /// The JSON of a `RegistryAccess`, when the call carried it
    pub access: Option<zeroize::Zeroizing<Vec<u8>>>,
    pub cancel: Cancel,
}

/// What the registry fetcher does besides bringing content.  The calls run
/// on the runtime of the service.
#[async_trait]
pub trait RegistryCalls: Send + Sync + 'static {
    /// The tags of a repository, every page of them, one to `out` each, at
    /// most `max`.
    async fn tags(
        &self,
        call: RemoteCall,
        max: u64,
        out: &Out<String>,
    ) -> Result<(), RegistryError>;

    /// A search of the registry for `needle` (the v1 search where the
    /// registry has one, else its catalog; the fetcher decides), one hit to
    /// `out` each, at most `limit`.
    async fn search(
        &self,
        call: RemoteCall,
        needle: String,
        limit: u64,
        out: &Out<Hit>,
    ) -> Result<(), RegistryError>;

    /// Whether the registry takes the credentials of the call.
    async fn login(&self, call: RemoteCall) -> Result<(), RegistryError>;

    /// The body of `url`, at most `max` bytes, into `file` (a file with no
    /// name the engine made).
    async fn download(
        &self,
        url: &str,
        max: u64,
        file: File,
        cancel: Cancel,
    ) -> Result<Downloaded, RegistryError>;
}

fn bad(reason: impl Into<String>) -> RegistryError {
    RegistryError::bad(reason)
}

/// A call that is wrong in itself.
pub fn bad_call(reason: impl Into<String>) -> RegistryError {
    RegistryError::bad(reason)
}

/// A call whose task stopped.
pub fn stopped(e: tokio::task::JoinError) -> RegistryError {
    RegistryError::failed(format!("the fetcher stopped: {e}"))
}

/// Cancels the call it holds when it is dropped: the asker went.
pub struct Cancelling(pub Cancel);

impl Drop for Cancelling {
    fn drop(&mut self) {
        self.0.cancel();
    }
}

/// What a fetcher that does not serve a registry answers.
pub fn not_a_registry() -> RegistryError {
    RegistryError::unavailable("this fetcher does not serve a registry")
}

pub fn checked_digest(digest: &str) -> Result<Digest, RegistryError> {
    digest.parse().map_err(|_| {
        bad(format!(
            "not a digest: {:?}",
            digest.chars().take(80).collect::<String>()
        ))
    })
}

/// A tag or a digest: what names a manifest.
pub fn checked_reference(reference: &str) -> Result<(), RegistryError> {
    // (a tag has at most 128 characters, a digest 135; the first character
    // of a tag is never `.` or `-`: no `.` or `..`
    // for a path of the registry's API)
    let tag = reference
        .bytes()
        .next()
        .is_some_and(|b| b.is_ascii_alphanumeric() || b == b'_')
        && reference.len() <= 135
        && reference
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-' | b':'));
    if tag {
        Ok(())
    } else {
        Err(bad(format!(
            "not a tag or a digest: {:?}",
            reference.chars().take(80).collect::<String>()
        )))
    }
}

/// A text argument: not empty, at most [`MAX_TEXT`] bytes, no control
/// character.
pub fn checked_text(what: &str, text: &str) -> Result<(), RegistryError> {
    if text.is_empty() || text.len() > MAX_TEXT || text.chars().any(char::is_control) {
        return Err(bad(format!(
            "{what} is empty, too long or has a control character"
        )));
    }
    Ok(())
}

/// The repository of a call: `registry/name`, with no tag or digest.
pub fn checked_remote(remote: &Remote) -> Result<(), RegistryError> {
    checked_text("the repository", &remote.repository)?;
    let name = &remote.repository;
    let last = name.rsplit('/').next().unwrap_or(name);
    let chars = name.bytes().all(|b| {
        b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_' | b'/' | b':' | b'[' | b']')
    });
    if !chars || name.contains('@') || last.contains(':') && name.contains('/') {
        return Err(bad(format!(
            "not a repository: {:?}",
            name.chars().take(80).collect::<String>()
        )));
    }
    Ok(())
}

/// The access file of a call: the descriptor `remote.access` names.  A sealed
/// memory file (at most [`MAX_ACCESS`] bytes): a file that something else can
/// still change is refused.  Read once and not kept.
fn take_access(
    fds: &mut Descriptors,
    at: Option<u32>,
) -> Result<Option<zeroize::Zeroizing<Vec<u8>>>, RegistryError> {
    let Some(fd) = fds.take_opt("the access file", at).map_err(bad)? else {
        return Ok(None);
    };
    let file = File::from(fd);
    velarx_base::sealed::read_sealed_whole(&file, MAX_ACCESS)
        .map(|bytes| Some(zeroize::Zeroizing::new(bytes)))
        .map_err(|what| bad(format!("the access file {what}")))
}

/// No descriptor is left over: a call carries what its fields name.
pub fn none_left(fds: Descriptors) -> Result<(), RegistryError> {
    fds.finish().map_err(bad)
}

/// What a call about `remote` carries besides a data file: its access file.
pub fn remote_call(fds: &mut Descriptors, remote: Remote) -> Result<RemoteCall, RegistryError> {
    checked_remote(&remote)?;
    let access = take_access(fds, remote.access)?;
    Ok(RemoteCall {
        remote,
        access,
        cancel: Cancel::default(),
    })
}
