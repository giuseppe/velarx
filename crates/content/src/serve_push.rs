// SPDX-License-Identifier: Apache-2.0
//! The serving end of the pusher interface (`org.velarx.Pusher`): what a
//! pusher implements ([`Pushing`]) and the checks of the calls that are the
//! same for every pusher.  The scope of a connection (`Open`) and
//! the connections for other calls (`Connect`) are served by the endpoint of
//! [`crate::serve_fetch`], on the same socket: a process that serves a
//! fetcher serves a pusher with it, and a pusher that is not one answers
//! `Failed` of class `unavailable`.
//!
//! What a pusher has to tell the engine (an object is placed, a failure,
//! progress) is a reply of the call the engine made (`Probe`, `Put`).

use crate::fetcher::Cancel;
use crate::pusher::push::{
    CommitReply, EventKind, Have, Object, Probed, PusherError, PutEvent, MAX_KNOWN_AT, MAX_MANIFEST,
};
use crate::serve_fetch::{Described, Out};
use async_trait::async_trait;
use std::fs::File;
use std::sync::Arc;
use velarx_types::digest::Digest;

/// What `Open` gave the connection.
#[derive(Debug)]
pub struct PushScope {
    /// What the destination's transport names: `registry/name` for a
    /// registry, the text of an external transport otherwise
    pub destination: String,
    pub tls_verify: Option<bool>,
    /// The JSON of a `RegistryAccess`, from a sealed memory file
    pub access: Option<zeroize::Zeroizing<Vec<u8>>>,
    /// The destination the client opened (a directory, or a file open for
    /// writing), for a transport that has one
    pub target: Option<File>,
    /// The most this connection's calls stay silent: a call with replies to
    /// come says something at least every half of it
    pub idle: std::time::Duration,
    /// What the pusher derived from the scope (its connections), made once
    /// and gone with the scope
    pub kept: std::sync::OnceLock<Arc<dyn std::any::Any + Send + Sync>>,
}

/// A `Put`: the objects and, in the same order, their bytes.
pub struct PutCall {
    pub objects: Vec<Object>,
    /// A regular file open for reading only for each object, which the
    /// engine keeps as it is until the call ends
    pub data: Vec<File>,
    /// Cancelled when the client goes away
    pub cancel: Cancel,
}

/// A `Commit`: the manifest and the names to put it as.
pub struct CommitCall {
    pub manifest: Object,
    pub body: Vec<u8>,
    /// The tags; none: by its digest
    pub names: Vec<String>,
}

/// A `Committed`: the destination has the manifest `digest` by `names`.
pub struct CommittedCall {
    pub manifest: Object,
    pub digest: String,
    pub names: Vec<String>,
}

/// What a pusher does.  The defaults are those of a pusher that places
/// nothing: nothing is available.
#[async_trait]
pub trait Pushing: Send + Sync + 'static {
    fn described(&self) -> Described;

    /// The scope is open: what a pusher does with its destination before
    /// the first call (a pusher of a path confines its process here).
    async fn opened(&self, _scope: &PushScope) -> Result<(), PusherError> {
        Ok(())
    }

    /// What do you have, or what can you link, of these objects?  One reply
    /// for each, in any order.
    async fn probe(
        &self,
        _scope: &PushScope,
        objects: Vec<Object>,
        out: &Out<Probed>,
    ) -> Result<(), PusherError> {
        for (index, _) in objects.iter().enumerate() {
            out.send(Probed {
                index: index as u32,
                have: Have::Unavailable,
                failure: None,
            })
            .await
            .map_err(gone)?;
        }
        Ok(())
    }

    /// Place the objects, each in exactly one of `placed`, `present`,
    /// `linked`, `unavailable`, `failed`.
    async fn put(
        &self,
        _scope: &PushScope,
        call: PutCall,
        out: &Out<PutEvent>,
    ) -> Result<(), PusherError> {
        if !call.objects.is_empty() {
            out.send(PutEvent {
                objects: (0..call.objects.len() as u32).collect(),
                ..PutEvent::of(EventKind::Unavailable)
            })
            .await
            .map_err(gone)?;
        }
        Ok(())
    }

    /// Put the manifest, as each of the names and by its digest: only the
    /// pusher that owns its destination (the last of the list) does.
    async fn commit(
        &self,
        _scope: &PushScope,
        _call: CommitCall,
    ) -> Result<CommitReply, PusherError> {
        Err(PusherError::unavailable(
            "this pusher does not own its destination",
        ))
    }

    /// The destination has the manifest now (what a pusher that is not the
    /// origin needs to act: a referrers or announce sink); the default takes
    /// note of nothing.
    async fn committed(&self, _scope: &PushScope, _call: CommittedCall) -> Result<(), PusherError> {
        Ok(())
    }

    /// The end of the scope: after the origin finished, and no commit comes.
    async fn finish(&self, _scope: &PushScope) -> Result<(), PusherError> {
        Ok(())
    }
}

fn gone(_: crate::serve_fetch::Gone) -> PusherError {
    PusherError::failed("the asker is gone")
}

/// What a process that serves no pusher answers.
pub fn not_a_pusher() -> PusherError {
    PusherError::unavailable("this process does not serve a pusher")
}

pub(crate) fn bad(reason: impl Into<String>) -> PusherError {
    PusherError::InvalidArgument {
        reason: reason.into(),
    }
}

/// The most bytes of a text of an object (a media type, a repository, a
/// name).
const MAX_TEXT: usize = 255;

/// An object as the engine says it: a digest of the two algorithms, a
/// media type and hints of a sane size.
pub fn checked_object(object: &Object) -> Result<(), PusherError> {
    object.digest.parse::<Digest>().map_err(|_| {
        bad(format!(
            "not a digest: {:?}",
            object.digest.chars().take(80).collect::<String>()
        ))
    })?;
    if object.media_type.len() > MAX_TEXT || object.media_type.chars().any(char::is_control) {
        return Err(bad("the media type is too long or has a control character"));
    }
    if let Some(known) = &object.known_at {
        if known.len() > MAX_KNOWN_AT
            || known
                .iter()
                .any(|r| r.is_empty() || r.len() > MAX_TEXT || r.chars().any(char::is_control))
        {
            return Err(bad("the hints are too many or not repositories"));
        }
    }
    Ok(())
}

/// A name the manifest is put as: a tag, or the name of an image
/// (`[registry/]repository[:tag]`) for a pusher that writes a path.  A
/// pusher of a registry takes tags only ([`checked_tag`]).
pub fn checked_name(name: &str) -> Result<(), PusherError> {
    let image = name.len() <= 255
        && !name.starts_with('/')
        && name
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..")
        && name.bytes().all(|b| {
            b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-' | b'+' | b'/' | b':')
        });
    if image {
        Ok(())
    } else {
        Err(bad(format!(
            "not a name: {:?}",
            name.chars().take(80).collect::<String>()
        )))
    }
}

/// A tag the manifest is put as.
pub fn checked_tag(name: &str) -> Result<(), PusherError> {
    let tag = name
        .bytes()
        .next()
        .is_some_and(|b| b.is_ascii_alphanumeric() || b == b'_')
        && name.len() <= 128
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-' | b'+'));
    if tag {
        Ok(())
    } else {
        Err(bad(format!(
            "not a tag: {:?}",
            name.chars().take(80).collect::<String>()
        )))
    }
}

/// The manifest of a `Commit`: the bytes of its data file, a regular file
/// open for reading only of exactly `size` bytes.
pub fn read_manifest(data: &File, size: u64) -> Result<Vec<u8>, PusherError> {
    use std::os::unix::fs::FileExt;
    if size == 0 || size > MAX_MANIFEST {
        return Err(bad("a manifest has no bytes or too many"));
    }
    let mut body = vec![0u8; size as usize];
    data.read_exact_at(&mut body, 0)
        .map_err(|_| bad("the data file is shorter than the manifest"))?;
    Ok(body)
}

/// A data file of a call: a regular file open for reading only (the
/// pusher cannot change what the engine sends, nor grow its file), of at
/// least `size` bytes.
pub fn checked_data(file: File, size: u64) -> Result<File, PusherError> {
    let read_only = rustix::fs::fcntl_getfl(&file)
        .is_ok_and(|f| !f.intersects(rustix::fs::OFlags::WRONLY | rustix::fs::OFlags::RDWR));
    let meta = file.metadata().ok();
    let regular = meta.as_ref().is_some_and(|m| m.is_file());
    if !read_only || !regular {
        return Err(bad(
            "a data file is not a regular file open for reading only",
        ));
    }
    if meta.is_none_or(|m| m.len() < size) {
        return Err(bad("a data file is shorter than its object"));
    }
    Ok(file)
}

/// A text argument: not empty, at most 255 bytes, no control character.
pub fn checked_text(what: &str, text: &str) -> Result<(), PusherError> {
    if text.is_empty() || text.len() > MAX_TEXT || text.chars().any(char::is_control) {
        return Err(bad(format!(
            "{what} is empty, too long or has a control character"
        )));
    }
    Ok(())
}

/// The objects of a call: at most `most`, each as [`checked_object`] says.
pub fn checked_objects(objects: &[Object], most: usize) -> Result<(), PusherError> {
    if objects.len() > most {
        return Err(bad(format!("at most {most} objects a call")));
    }
    objects.iter().try_for_each(checked_object)
}

#[cfg(test)]
mod name_tests {
    use super::*;

    #[test]
    fn a_name_is_a_tag_or_the_name_of_an_image_and_a_registry_takes_tags() {
        for ok in ["latest", "v1.2-rc_1", "host:5000/lib/app:v1", "quay.io/a/b"] {
            assert!(checked_name(ok).is_ok(), "{ok}");
        }
        for bad in ["", "/etc", "a//b", "a/../b", "a b", "a\nb", "a/./b"] {
            assert!(checked_name(bad).is_err(), "{bad:?}");
        }
        assert!(checked_tag("latest").is_ok());
        assert!(checked_tag("host/app:v1").is_err());
        assert!(checked_tag(".hidden").is_err());
    }
}
