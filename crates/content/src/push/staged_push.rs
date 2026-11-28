// SPDX-License-Identifier: Apache-2.0
//! The walker of a push: the engine's ordered list of pushers (`[push]
//! sinks`, the destination's own pusher last), and what the engine asks of
//! them for each object of an image.  The sibling of `StagedFetch`: a pusher
//! answers only for itself and knows nothing of the others; this is the one
//! that asks the next.
//!
//! * One scope per pusher; the credentials go to the one that owns the
//!   destination (the origin), and to a sink only when its definition says
//!   so.
//! * `probe` asks what the destination has, before anything is
//!   regenerated; `put` places the bytes of an object.  For each object the
//!   first pusher that answers `present`, `linked` or `placed` wins;
//!   `unavailable` goes to the next, `failed` trips the pusher for the rest
//!   of the push and goes to the next (a failure of the origin ends the
//!   push, with the kind of refusal the registry gave).
//! * What a pusher that is not the origin says it did is confirmed by the
//!   origin before it is believed (a `Probe`, no bytes, no hashing): a
//!   claim the origin does not bear out distrusts that pusher for the object,
//!   and the object goes back to the walk.
//! * `commit` is the origin's alone; a `ObjectsMissing` names the objects the
//!   destination lacks, and gives them back to the walk as the lie of
//!   whoever placed them.
//!
//! Every digest named is the one the engine computed; nothing of what a
//! pusher says is trusted without the origin.

use crate::fetcher::fetch_client::{CallError, FetchConn};
use crate::idle::{is_silent, silent};
use crate::pull::staged_fetch::CONNECTED;
use crate::pusher::push::{CommitReply, EventKind, Have, Object, PusherError, MAX_OBJECTS};
use crate::pusher::push_client::PushScoping;
use std::collections::HashMap;
use std::fs::File;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use tracing::debug;
use velarx_proto::transfer::Failure;
use velarx_proto::transfer::{next, FailureClass, Step};
use velarx_types::{ImageError, ImageResult};

/// A pusher of `[push] sinks`, as the engine connected to it.
pub struct PushLink {
    /// Its name in `[push] sinks`
    pub name: String,
    pub conn: FetchConn,
    /// It may be given the credentials of the destination (it places
    /// objects in a registry)
    pub credentials: bool,
    /// The push named it: that it cannot be used is an error, not a sink
    /// left out
    pub required: bool,
    /// How long it may be silent in a call: no reply for this long ends the
    /// call with an error that names it (`[[sinks.external]]
    /// idle_timeout_secs`)
    pub idle: std::time::Duration,
}

/// What the pushers of a push are told of the destination: the helpers and
/// the origin may hear different things (a path is for the origin only).
pub struct Destinations {
    pub helpers: String,
    pub origin: String,
    pub tls_verify: Option<bool>,
    /// How long the origin may be silent in a call
    pub idle: std::time::Duration,
    /// The origin is a pusher of the configuration that the push does not
    /// start (`[[transports]]`): the name the configuration gives it
    /// (what the errors name, not what it says of itself).  None: the
    /// origin is the registry's or the directory's, which the engine runs
    /// and whose transport waits
    pub external_origin: Option<String>,
}

/// One pusher of the list of a push: the connection that has its scope.
struct Sink {
    name: String,
    /// Calls with replies to come go on connections it gives
    control: tokio::sync::Mutex<FetchConn>,
    max_objects: usize,
    /// It is the origin of the push: the last, whatever the others
    /// announce.  The failure of the origin is the failure of the push
    origin: bool,
    /// How long a helper may be silent in a call (the origin may be, as long
    /// as its transport waits)
    idle: Option<std::time::Duration>,
    /// The push named it: its silence is the push's failure
    required: bool,
}

/// How an object got to the destination.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum How {
    /// It was there
    Present,
    /// A pusher linked it from another repository
    Linked,
    /// A pusher put its bytes there
    Placed,
}

/// Who put an object at the destination.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Found {
    /// The place in the list
    pub sink: usize,
    pub how: How,
}

/// What a pusher answered for one object of a call.
enum Answer {
    Done(How),
    No,
    Failed(Failure),
}

/// The error of a call to the origin: one that got no reply for the idle
/// time of an origin the configuration names (`external`) is that
/// transport silent, naming it.
fn origin_error(party: &str, external: bool, e: CallError) -> ImageError {
    if external && is_silent(&e) {
        return ImageError::transfer(party, FailureClass::Transient, e.to_string());
    }
    image_error(party, e)
}

/// What the error of a call to the pusher `party` is, as an error of the
/// image.
pub fn image_error(party: &str, e: CallError) -> ImageError {
    match e {
        CallError::Pusher(PusherError::Failed { failure }) => {
            ImageError::transfer(party, failure.class, failure.reason)
        }
        CallError::Pusher(PusherError::Busy { reason }) => {
            ImageError::transfer(party, FailureClass::Unavailable, reason)
        }
        e @ CallError::Pusher(_) => {
            ImageError::transfer(party, FailureClass::Failed, e.to_string())
        }
        e @ CallError::NoMethod => {
            ImageError::transfer(party, FailureClass::Unavailable, e.to_string())
        }
        e => ImageError::transfer(party, FailureClass::Transient, e.to_string()),
    }
}

/// What a pusher said it could not do for an object.
fn failure_error(party: &str, failure: Failure) -> ImageError {
    ImageError::transfer(party, failure.class, failure.reason)
}

/// The pushers of a push, and what the walk has learnt of them.
pub struct StagedPush {
    /// In the order of `[push] sinks`, the origin last
    sinks: Vec<Sink>,
    /// The pushers this push does not ask again (a failure), and why
    broken: Vec<AtomicBool>,
    why: Vec<Mutex<Option<String>>>,
    /// The pusher that placed each object, by digest (not the origin): the
    /// one a commit that lacks the object names
    placed: Mutex<HashMap<String, usize>>,
}

impl StagedPush {
    /// Open the scope of a push to `destination` on each pusher: on `before`
    /// (in order), with the credentials only where they are allowed, then on
    /// the origin `end` with the credentials `access` (the JSON of a
    /// `RegistryAccess`).  A pusher of `before` that is not there or refuses
    /// the scope is left out.
    pub async fn open(
        before: Vec<PushLink>,
        mut end: FetchConn,
        destinations: Destinations,
        access: Option<&[u8]>,
        target: Option<std::os::fd::OwnedFd>,
    ) -> ImageResult<Arc<Self>> {
        let sealed = || {
            access
                .map(velarx_base::sealed::sealed_memory)
                .transpose()
                .map_err(ImageError::Io)
        };
        let mut sinks = Vec::new();
        for PushLink {
            name,
            mut conn,
            credentials,
            required,
            idle,
        } in before
        {
            let opened = tokio::time::timeout(idle, async {
                let info = conn.push_get_info().await?;
                let fd = if credentials {
                    sealed().map_err(|e| CallError::Protocol(e.to_string()))?
                } else {
                    None
                };
                conn.push_open(PushScoping {
                    destination: &destinations.helpers,
                    tls_verify: destinations.tls_verify,
                    target: None,
                    access: fd,
                    idle,
                })
                .await?;
                Ok::<_, CallError>(info)
            });
            match opened.await.unwrap_or_else(|_| Err(silent(idle))) {
                Ok(info) => sinks.push(Sink {
                    name,
                    control: tokio::sync::Mutex::new(conn),
                    max_objects: (info.limit("max_objects").unwrap_or(1) as usize).max(1),
                    origin: false,
                    idle: Some(idle),
                    required,
                }),
                Err(e) if required => {
                    return Err(ImageError::transfer(
                        name,
                        FailureClass::Unavailable,
                        e.to_string(),
                    ))
                }
                Err(e) => debug!("The pusher {name} is left out of the push: {e}"),
            }
        }
        let access = sealed()?;
        let opening = async {
            let info = end.push_get_info().await?;
            end.push_open(PushScoping {
                destination: &destinations.origin,
                tls_verify: destinations.tls_verify,
                target,
                access,
                idle: destinations.idle,
            })
            .await?;
            Ok::<_, CallError>(info)
        };
        let (info, name, idle) = match &destinations.external_origin {
            Some(name) => {
                let idle = destinations.idle;
                let opened = tokio::time::timeout(idle, opening)
                    .await
                    .unwrap_or_else(|_| Err(silent(idle)));
                let info = opened.map_err(|e| origin_error(name, true, e))?;
                (info, name.clone(), Some(idle))
            }
            None => {
                let info = opening.await.map_err(|e| image_error("registry", e))?;
                let name = info.name.clone();
                (info, name, None)
            }
        };
        sinks.push(Sink {
            name,
            control: tokio::sync::Mutex::new(end),
            max_objects: (info.limit("max_objects").unwrap_or(1) as usize).max(1),
            origin: true,
            idle,
            required: true,
        });
        let n = sinks.len();
        Ok(Arc::new(Self {
            sinks,
            broken: (0..n).map(|_| AtomicBool::default()).collect(),
            why: (0..n).map(|_| Mutex::default()).collect(),
            placed: Mutex::default(),
        }))
    }

    /// The names of the pushers of the push, in the order they are asked.
    pub fn sinks(&self) -> Vec<&str> {
        self.sinks.iter().map(|s| s.name.as_str()).collect()
    }

    /// Why the pusher at `at` is not asked any more by this push, if it is
    /// not.
    pub fn broken(&self, at: usize) -> Option<String> {
        self.why[at]
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// `call`, which ends with an error when the pusher at `at` (a helper)
    /// says nothing for its idle time.
    async fn within<T>(
        &self,
        at: usize,
        call: impl std::future::Future<Output = Result<T, CallError>>,
    ) -> Result<T, CallError> {
        match self.sinks[at].idle {
            Some(idle) => crate::idle::within(idle, call).await,
            None => call.await,
        }
    }

    /// The error of the push when the helper at `at`, which the push named,
    /// fell silent: the push fails naming it (one of `[push] sinks` is left
    /// out like any other that failed).
    fn hung(&self, at: usize, e: &CallError) -> Option<ImageError> {
        (is_silent(e) && self.sinks[at].required).then(|| {
            ImageError::transfer(
                self.sinks[at].name.clone(),
                FailureClass::Transient,
                e.to_string(),
            )
        })
    }

    /// The error of the push for the call `e` to the pusher at `at`, which
    /// is the origin: the silence of an external transport names it.
    fn origin_fail(&self, at: usize, e: CallError) -> ImageError {
        let sink = &self.sinks[at];
        origin_error(&sink.name, sink.idle.is_some(), e)
    }

    fn usable(&self, at: usize) -> bool {
        !self.broken[at].load(Ordering::Relaxed)
    }

    /// `at` failed or said what is not so: this push does not ask it again.
    fn trip(&self, at: usize, why: &str) {
        debug!(
            "The pusher {} is not asked again by this push: {why}",
            self.sinks[at].name
        );
        self.broken[at].store(true, Ordering::Relaxed);
        self.why[at]
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get_or_insert_with(|| why.to_string());
    }

    fn lost(&self, at: usize, e: &CallError) {
        // (no connection for now is not a pusher that failed)
        if matches!(e, CallError::Pusher(PusherError::Busy { .. })) {
            return;
        }
        self.trip(at, &e.to_string());
    }

    /// A connection for one call, and its place among those of the
    /// process: held while the connection is used.
    async fn connection(
        &self,
        at: usize,
    ) -> Result<(FetchConn, tokio::sync::OwnedSemaphorePermit), CallError> {
        let permit = CONNECTED
            .clone()
            .acquire_owned()
            .await
            .map_err(|e| CallError::Protocol(e.to_string()))?;
        // (the idle time is the pusher's silence: the wait for the control
        // connection, which other calls hold, is no part of it)
        let mut control = self.sinks[at].control.lock().await;
        let conn = self.within(at, control.push_connect()).await?;
        drop(control);
        Ok((conn, permit))
    }

    /// What each pusher answers for the objects `objects` asked of it: a
    /// call for each batch of at most what the pusher takes.  `ask` makes the
    /// call for the objects at the places `batch` of `objects`.
    async fn walk<F, Fut>(&self, objects: &[Object], ask: F) -> ImageResult<Vec<Option<Found>>>
    where
        F: Fn(usize, Vec<usize>) -> Fut,
        Fut: std::future::Future<Output = Result<Vec<Answer>, CallError>>,
    {
        let mut found: Vec<Option<Found>> = vec![None; objects.len()];
        {
            for (at, sink) in self.sinks.iter().enumerate() {
                if !self.usable(at) {
                    continue;
                }
                let pending: Vec<usize> =
                    (0..objects.len()).filter(|&k| found[k].is_none()).collect();
                for batch in pending.chunks(sink.max_objects.min(MAX_OBJECTS)) {
                    let answers = match ask(at, batch.to_vec()).await {
                        Ok(a) => a,
                        Err(e) if sink.origin => return Err(self.origin_fail(at, e)),
                        Err(e) => {
                            if let Some(hung) = self.hung(at, &e) {
                                return Err(hung);
                            }
                            self.lost(at, &e);
                            break;
                        }
                    };
                    let mut failed = None;
                    for (&k, answer) in batch.iter().zip(answers) {
                        match answer {
                            Answer::Done(how) => found[k] = Some(Found { sink: at, how }),
                            Answer::No => {}
                            // (the table of the walk: what a helper that is
                            // not at fault for the object may be passed over
                            // for the next pusher; nothing else is)
                            Answer::Failed(failure) => match next(failure.class, sink.origin) {
                                Step::Next => {
                                    failed.get_or_insert(failure.reason);
                                }
                                Step::Fail => {
                                    return Err(failure_error(&sink.name, failure));
                                }
                            },
                        }
                    }
                    // (what it placed is believed no less for what it failed
                    // to place: the origin confirms it)
                    if let Some(reason) = failed {
                        self.trip(at, &reason);
                        break;
                    }
                }
            }
        }
        self.confirm(objects, &found).await?;
        Ok(found)
    }

    /// What the pushers that are not the origin say is at the destination
    /// is asked of the origin (a `Probe`: no bytes).  A claim it does not
    /// bear out ends the push with an error that names the pusher and the
    /// object: the transfer completed and its result is not valid, which no
    /// other pusher is asked to mend.
    async fn confirm(&self, objects: &[Object], found: &[Option<Found>]) -> ImageResult<()> {
        let origin = self.sinks.len() - 1;
        let claimed: Vec<usize> = (0..objects.len())
            .filter(|&k| found[k].is_some_and(|f| f.sink != origin))
            .collect();
        for batch in claimed.chunks(self.sinks[origin].max_objects.min(MAX_OBJECTS)) {
            let answers = self
                .probe_at(origin, objects, batch)
                .await
                .map_err(|e| self.origin_fail(origin, e))?;
            for (&k, answer) in batch.iter().zip(answers) {
                let Some(Found { sink, how }) = found[k] else {
                    continue;
                };
                if !matches!(answer, Answer::Done(How::Present | How::Linked)) {
                    return Err(ImageError::transfer_of(
                        self.sinks[sink].name.clone(),
                        objects[k].digest.clone(),
                        FailureClass::Invalid,
                        "the destination does not have it",
                    ));
                }
                if how == How::Placed {
                    self.placed
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .insert(objects[k].digest.clone(), sink);
                }
            }
        }
        Ok(())
    }

    /// `Probe` of the pusher at `at` for the objects of `objects` at `batch`.
    async fn probe_at(
        &self,
        at: usize,
        objects: &[Object],
        batch: &[usize],
    ) -> Result<Vec<Answer>, CallError> {
        let asked: Vec<Object> = batch.iter().map(|&k| objects[k].clone()).collect();
        let (mut conn, _permit) = self.connection(at).await?;
        let mut replies = self.within(at, conn.push_probe(&asked)).await?;
        let mut answers: Vec<Option<Answer>> = (0..asked.len()).map(|_| None).collect();
        while let Some((reply, fds)) = self.within(at, replies.probed()).await? {
            let slot = answers.get_mut(reply.index as usize);
            if !fds.is_empty() || slot.as_ref().is_none_or(|s| s.is_some()) {
                return Err(CallError::Protocol(
                    "a reply of Probe for an object not asked, or twice".into(),
                ));
            }
            if let Some(slot) = slot {
                *slot = Some(match reply.have {
                    Have::Present => Answer::Done(How::Present),
                    Have::Linked => Answer::Done(How::Linked),
                    // (what it can place is not what it has: the bytes
                    // are asked of it by `put`)
                    Have::Needed | Have::Unavailable | Have::Unknown => Answer::No,
                });
            }
        }
        answers
            .into_iter()
            .map(|a| a.ok_or_else(|| CallError::Protocol("Probe left an object unanswered".into())))
            .collect()
    }

    /// What the destination has of `objects`, before anything is
    /// regenerated: for each, who has it or can link it, or none (it is
    /// needed).
    pub async fn probe(&self, objects: &[Object]) -> ImageResult<Vec<Option<Found>>> {
        self.walk(objects, |at, batch| async move {
            self.probe_at(at, objects, &batch).await
        })
        .await
    }

    /// Place the objects `objects` at the destination, `data[k]` the bytes
    /// of `objects[k]`: for each, who put it there.  `progress` is told the
    /// bytes of an object sent so far (its place in `objects`).  An object
    /// no pusher took is an error.
    pub async fn put(
        &self,
        objects: &[Object],
        data: &[&File],
        progress: &(dyn Fn(usize, u64) + Send + Sync),
    ) -> ImageResult<Vec<Found>> {
        let found = self
            .walk(objects, |at, batch| async move {
                self.put_at(at, objects, data, &batch, progress).await
            })
            .await?;
        found
            .into_iter()
            .zip(objects)
            .map(|(f, o)| {
                f.ok_or_else(|| {
                    ImageError::transfer_of(
                        self.sinks[self.sinks.len() - 1].name.clone(),
                        o.digest.clone(),
                        FailureClass::Failed,
                        "no pusher placed it at the destination",
                    )
                })
            })
            .collect()
    }

    async fn put_at(
        &self,
        at: usize,
        objects: &[Object],
        data: &[&File],
        batch: &[usize],
        progress: &(dyn Fn(usize, u64) + Send + Sync),
    ) -> Result<Vec<Answer>, CallError> {
        let asked: Vec<Object> = batch.iter().map(|&k| objects[k].clone()).collect();
        let files: Vec<&File> = batch.iter().map(|&k| data[k]).collect();
        let (mut conn, _permit) = self.connection(at).await?;
        let mut replies = self.within(at, conn.push_put(&asked, &files)).await?;
        let mut answers: Vec<Option<Answer>> = (0..asked.len()).map(|_| None).collect();
        while let Some((event, fds)) = self.within(at, replies.event()).await? {
            if !fds.is_empty() {
                return Err(CallError::Protocol("an event of Put with a file".into()));
            }
            let how = match event.kind {
                EventKind::Placed => Some(Answer::Done(How::Placed)),
                EventKind::Present => Some(Answer::Done(How::Present)),
                EventKind::Linked => Some(Answer::Done(How::Linked)),
                EventKind::Unavailable => Some(Answer::No),
                EventKind::Failed => {
                    Some(Answer::Failed(event.failure.clone().unwrap_or(Failure {
                        class: FailureClass::Failed,
                        reason: "the pusher failed".into(),
                    })))
                }
                EventKind::Progress => {
                    if let ([i], Some(bytes)) = (event.objects.as_slice(), event.bytes) {
                        if let Some(&k) = batch.get(*i as usize) {
                            progress(k, bytes);
                        }
                    }
                    None
                }
                // (an event this side does not know: ignored)
                EventKind::Unknown => None,
            };
            let Some(answer) = how else { continue };
            for i in &event.objects {
                let answer = match &answer {
                    Answer::Done(h) => Answer::Done(*h),
                    Answer::No => Answer::No,
                    Answer::Failed(f) => Answer::Failed(f.clone()),
                };
                match answers.get_mut(*i as usize) {
                    Some(slot @ None) => *slot = Some(answer),
                    _ => {
                        return Err(CallError::Protocol(
                            "an event of Put for an object not asked, or twice".into(),
                        ))
                    }
                }
            }
        }
        answers
            .into_iter()
            .map(|a| a.ok_or_else(|| CallError::Protocol("Put left an object unanswered".into())))
            .collect()
    }

    /// The error of a commit that lacks the blobs `digests`: it names the
    /// pusher that placed the first (the origin, if none other did).
    fn blob_unknown(&self, digests: &[String]) -> ImageError {
        let placed = self.placed.lock().unwrap_or_else(|e| e.into_inner());
        let digest = digests.first().cloned().unwrap_or_default();
        let sink = placed.get(&digest).copied().unwrap_or(self.sinks.len() - 1);
        ImageError::transfer_of(
            self.sinks[sink].name.clone(),
            digest,
            FailureClass::Invalid,
            "the manifest names it and the destination does not have it",
        )
    }

    /// Put the manifest that `body` holds as each of `names` (tags; none:
    /// by its digest), by the origin: the digest it says the manifest has,
    /// and its refusal of the digest as a name, if any.
    pub async fn commit(
        &self,
        manifest: &Object,
        names: &[String],
        body: &File,
    ) -> ImageResult<CommitReply> {
        let origin = self.sinks.len() - 1;
        let (mut conn, _permit) = self
            .connection(origin)
            .await
            .map_err(|e| self.origin_fail(origin, e))?;
        let reply = match self
            .within(origin, conn.push_commit(manifest, names, body))
            .await
        {
            Ok(reply) => reply,
            Err(CallError::Pusher(PusherError::ObjectsMissing { digests })) => {
                return Err(self.blob_unknown(&digests))
            }
            Err(e) => return Err(self.origin_fail(origin, e)),
        };
        drop(conn);
        // The destination has the manifest: the helpers are told, so they
        // can act (their answer does not matter to the push).
        for (at, _) in self.sinks[..origin].iter().enumerate() {
            if !self.usable(at) {
                continue;
            }
            let told = async {
                let (mut conn, _permit) = self.connection(at).await?;
                self.within(at, conn.push_committed(manifest, &reply.digest, names))
                    .await
            };
            if let Err(e) = told.await {
                if let Some(hung) = self.hung(at, &e) {
                    return Err(hung);
                }
                self.lost(at, &e);
            }
        }
        Ok(reply)
    }

    /// Put the manifest `body` of the media type `media_type` as each of
    /// `names` (none: by its digest, in the algorithm `alg`): what the origin
    /// says, with the digest the engine computed.
    pub async fn put_manifest(
        &self,
        media_type: &str,
        body: &[u8],
        alg: velarx_types::digest::Algorithm,
        names: &[String],
    ) -> ImageResult<CommitReply> {
        let ours = velarx_types::digest::Digest::of(alg, body);
        let manifest = Object {
            digest: ours.to_string(),
            size: body.len() as u64,
            media_type: media_type.to_string(),
            role: crate::pusher::push::Role::Manifest,
            known_at: None,
        };
        let file = velarx_base::sealed::sealed_memory(body)
            .map(File::from)
            .map_err(ImageError::Io)?;
        let reply = self.commit(&manifest, names, &file).await?;
        if reply.digest != manifest.digest {
            return Err(ImageError::DigestMismatch {
                expected: manifest.digest,
                actual: reply.digest,
            });
        }
        Ok(reply)
    }

    /// The end of the push: the origin finishes what it writes, then the
    /// helpers are told that no commit comes.
    pub async fn finish(&self) -> ImageResult<()> {
        let origin = self.sinks.len() - 1;
        let mut control = self.sinks[origin].control.lock().await;
        let ended = self.within(origin, control.push_finish()).await;
        drop(control);
        ended.map_err(|e| self.origin_fail(origin, e))?;
        for (at, sink) in self.sinks[..origin].iter().enumerate() {
            if !self.usable(at) {
                continue;
            }
            let mut control = sink.control.lock().await;
            let said = self.within(at, control.push_finish()).await;
            drop(control);
            if let Err(e) = said {
                if let Some(hung) = self.hung(at, &e) {
                    return Err(hung);
                }
                self.lost(at, &e);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pusher::push::{Placed, Probed, PutEvent, Role};
    use crate::serve_fetch::{Described, LocalFetcher, Out, StagingFetcher};
    use crate::serve_push::{CommitCall, CommittedCall, PushScope, Pushing, PutCall};
    use async_trait::async_trait;
    use std::io::Write;

    /// What a scripted pusher does with an object (by its digest).
    #[derive(Clone, Copy)]
    enum Put {
        Placed,
        Present,
        Unavailable,
        Fail(FailureClass),
    }

    /// A pusher that answers by a script and records what it was asked.
    #[derive(Default)]
    struct Script {
        origin: bool,
        probe: Mutex<HashMap<String, Have>>,
        put: Mutex<HashMap<String, Put>>,
        /// The blobs a commit says the destination lacks (once)
        lacks: Mutex<Vec<String>>,
        asked: Mutex<Vec<String>>,
        /// The commits it was told or asked for (the manifest's digest), and
        /// whether it was told the end
        committed: Mutex<Vec<String>>,
        finished: AtomicBool,
    }

    impl Script {
        fn new(origin: bool) -> Arc<Self> {
            Arc::new(Self {
                origin,
                ..Default::default()
            })
        }

        fn probing(self: &Arc<Self>, body: &[u8], have: Have) -> Arc<Self> {
            self.probe
                .lock()
                .unwrap()
                .insert(crate::sha256_text(body), have);
            self.clone()
        }

        fn putting(self: &Arc<Self>, body: &[u8], what: Put) -> Arc<Self> {
            self.put
                .lock()
                .unwrap()
                .insert(crate::sha256_text(body), what);
            self.clone()
        }

        fn asked(&self) -> Vec<String> {
            self.asked.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl Pushing for Script {
        fn described(&self) -> Described {
            Described {
                name: if self.origin { "origin" } else { "sink" }.into(),
                capabilities: Vec::new(),
                max_objects: 2,
            }
        }

        async fn probe(
            &self,
            _scope: &PushScope,
            objects: Vec<Object>,
            out: &Out<Probed>,
        ) -> Result<(), PusherError> {
            for (index, o) in objects.iter().enumerate() {
                self.asked
                    .lock()
                    .unwrap()
                    .push(format!("probe {}", o.digest));
                let have = self
                    .probe
                    .lock()
                    .unwrap()
                    .get(&o.digest)
                    .copied()
                    .unwrap_or(Have::Unavailable);
                let _ = out
                    .send(Probed {
                        index: index as u32,
                        have,
                        failure: None,
                    })
                    .await;
            }
            Ok(())
        }

        async fn put(
            &self,
            _scope: &PushScope,
            call: PutCall,
            out: &Out<PutEvent>,
        ) -> Result<(), PusherError> {
            for (index, o) in call.objects.iter().enumerate() {
                self.asked.lock().unwrap().push(format!("put {}", o.digest));
                let what = self
                    .put
                    .lock()
                    .unwrap()
                    .get(&o.digest)
                    .copied()
                    .unwrap_or(Put::Placed);
                let objects = vec![index as u32];
                let _ = out
                    .send(PutEvent {
                        objects: objects.clone(),
                        bytes: Some(o.size),
                        ..PutEvent::of(EventKind::Progress)
                    })
                    .await;
                let event = match what {
                    Put::Placed => PutEvent {
                        objects,
                        ..PutEvent::of(EventKind::Placed)
                    },
                    Put::Present => PutEvent {
                        objects,
                        ..PutEvent::of(EventKind::Present)
                    },
                    Put::Unavailable => PutEvent {
                        objects,
                        ..PutEvent::of(EventKind::Unavailable)
                    },
                    Put::Fail(class) => PutEvent::failed(
                        objects,
                        Failure {
                            class,
                            reason: "it failed".into(),
                        },
                    ),
                };
                let _ = out.send(event).await;
            }
            Ok(())
        }

        async fn commit(
            &self,
            _scope: &PushScope,
            call: CommitCall,
        ) -> Result<CommitReply, PusherError> {
            let lacks = std::mem::take(&mut *self.lacks.lock().unwrap());
            if !lacks.is_empty() {
                return Err(PusherError::ObjectsMissing { digests: lacks });
            }
            self.committed
                .lock()
                .unwrap()
                .push(call.manifest.digest.clone());
            Ok(CommitReply {
                digest: call.manifest.digest,
                placed: vec![Placed {
                    name: None,
                    accepted: true,
                    reason: None,
                }],
            })
        }

        async fn committed(
            &self,
            _scope: &PushScope,
            call: CommittedCall,
        ) -> Result<(), PusherError> {
            self.committed.lock().unwrap().push(call.digest);
            Ok(())
        }

        async fn finish(&self, _scope: &PushScope) -> Result<(), PusherError> {
            self.finished.store(true, Ordering::Relaxed);
            Ok(())
        }
    }

    struct Api(Arc<Script>);

    #[async_trait]
    impl StagingFetcher for Api {
        fn described(&self) -> Described {
            Described {
                name: "api".into(),
                capabilities: Vec::new(),
                max_objects: 1,
            }
        }

        fn pusher(&self) -> Option<Arc<dyn Pushing>> {
            Some(self.0.clone())
        }
    }

    fn local(script: &Arc<Script>) -> LocalFetcher {
        LocalFetcher::start(
            Arc::new(Api(script.clone())),
            crate::activation::Limits::default(),
        )
        .unwrap()
    }

    fn conn(local: &LocalFetcher) -> FetchConn {
        FetchConn::new(local.connect().unwrap()).unwrap()
    }

    /// The walker over `sinks` and the `origin`.
    async fn push_over(
        sinks: &[&Arc<Script>],
        origin: &Arc<Script>,
    ) -> (Arc<StagedPush>, Vec<LocalFetcher>) {
        let mut locals: Vec<LocalFetcher> = sinks.iter().map(|s| local(s)).collect();
        let end = local(origin);
        let before = locals
            .iter()
            .zip(sinks)
            .enumerate()
            .map(|(i, (l, _))| PushLink {
                name: format!("sink{i}"),
                conn: conn(l),
                credentials: false,
                required: false,
                idle: std::time::Duration::from_secs(60),
            })
            .collect();
        let staged = StagedPush::open(
            before,
            conn(&end),
            Destinations {
                helpers: "registry.example/name".into(),
                origin: "registry.example/name".into(),
                tls_verify: None,
                idle: crate::pull::staged_fetch::TEST_IDLE,
                external_origin: None,
            },
            Some(b"{}"),
            None,
        )
        .await
        .unwrap();
        locals.push(end);
        (staged, locals)
    }

    fn object(body: &[u8]) -> Object {
        Object {
            digest: crate::sha256_text(body),
            size: body.len() as u64,
            media_type: "application/octet-stream".into(),
            role: Role::Layer,
            known_at: None,
        }
    }

    fn file_of(body: &[u8]) -> File {
        let mut file = tempfile::tempfile().unwrap();
        file.write_all(body).unwrap();
        file
    }

    #[tokio::test]
    async fn the_first_pusher_that_has_an_object_wins_and_the_origin_confirms_it() {
        let sink = Script::new(false).probing(b"a", Have::Present);
        let origin = Script::new(true)
            .probing(b"a", Have::Present)
            .probing(b"b", Have::Linked);
        let (staged, _keep) = push_over(&[&sink], &origin).await;
        assert_eq!(staged.sinks(), ["sink0", "origin"]);
        let found = staged
            .probe(&[object(b"a"), object(b"b"), object(b"c")])
            .await
            .unwrap();
        assert_eq!(
            found,
            [
                Some(Found {
                    sink: 0,
                    how: How::Present
                }),
                Some(Found {
                    sink: 1,
                    how: How::Linked
                }),
                None
            ]
        );
        // (the origin was asked about "a" only to confirm the sink's word)
        assert_eq!(origin.asked().len(), 3);
        assert!(sink
            .asked()
            .contains(&format!("probe {}", object(b"c").digest)));
    }

    /// Rule 3: a pusher that says the destination has an object the
    /// origin cannot confirm ends the push, naming the pusher and the
    /// object: no other pusher is asked to mend it.
    #[tokio::test]
    async fn a_claim_the_origin_does_not_bear_out_fails_the_push_naming_the_pusher() {
        let sink = Script::new(false).probing(b"a", Have::Present);
        let origin = Script::new(true);
        let (staged, _keep) = push_over(&[&sink], &origin).await;
        let e = staged.probe(&[object(b"a")]).await.unwrap_err();
        match &e {
            ImageError::Transfer {
                party,
                object: Some(o),
                failure,
            } => {
                assert_eq!(party, "sink0");
                assert_eq!(*o, object(b"a").digest);
                assert_eq!(failure.class, FailureClass::Invalid);
            }
            e => panic!("not an invalid transfer: {e}"),
        }
        // (the origin was not asked for the bytes)
        assert!(!origin.asked().iter().any(|a| a.starts_with("put ")));
    }

    /// Rule 1: a pusher that does not place an object (unavailable) is
    /// passed over for the next one.
    #[tokio::test]
    async fn a_pusher_that_does_not_place_an_object_leaves_it_to_the_next() {
        let sink = Script::new(false).putting(b"a", Put::Unavailable);
        let origin = Script::new(true);
        let (staged, _keep) = push_over(&[&sink], &origin).await;
        let found = staged
            .put(&[object(b"a")], &[&file_of(b"a")], &|_, _| {})
            .await
            .unwrap();
        assert_eq!(found[0].sink, 1);
    }

    #[tokio::test]
    async fn a_pusher_that_fails_is_skipped_and_the_next_places_the_object() {
        let sink = Script::new(false).putting(b"a", Put::Fail(FailureClass::Failed));
        let origin = Script::new(true);
        let (staged, _keep) = push_over(&[&sink], &origin).await;
        let seen = Mutex::new(Vec::new());
        let found = staged
            .put(&[object(b"a")], &[&file_of(b"a")], &|k, bytes| {
                seen.lock().unwrap().push((k, bytes))
            })
            .await
            .unwrap();
        assert_eq!(
            found,
            [Found {
                sink: 1,
                how: How::Placed
            }]
        );
        assert!(staged.broken(0).is_some());
        assert!(seen.lock().unwrap().contains(&(0, 1)));
        // the next object does not go to the pusher that failed
        staged
            .put(&[object(b"b")], &[&file_of(b"b")], &|_, _| {})
            .await
            .unwrap();
        assert_eq!(sink.asked().len(), 1);
    }

    #[tokio::test]
    async fn what_a_pusher_places_is_confirmed_by_the_origin() {
        let sink = Script::new(false);
        let origin = Script::new(true).probing(b"a", Have::Present);
        let (staged, _keep) = push_over(&[&sink], &origin).await;
        let found = staged
            .put(&[object(b"a")], &[&file_of(b"a")], &|_, _| {})
            .await
            .unwrap();
        assert_eq!(
            found,
            [Found {
                sink: 0,
                how: How::Placed
            }]
        );
        // Rule 3: a pusher that says it placed an object the origin lacks
        // fails the push, naming it and the object
        let liar = Script::new(false);
        let origin = Script::new(true);
        let (staged, _keep) = push_over(&[&liar], &origin).await;
        let e = staged
            .put(&[object(b"a")], &[&file_of(b"a")], &|_, _| {})
            .await
            .unwrap_err();
        assert!(
            matches!(&e, ImageError::Transfer { party, failure, .. } if party == "sink0" && failure.class == FailureClass::Invalid),
            "{e}"
        );
        assert!(!origin.asked().iter().any(|a| a.starts_with("put ")));
    }

    #[tokio::test]
    async fn the_origin_that_refuses_ends_the_push_with_the_kind_of_its_refusal() {
        let origin = Script::new(true)
            .putting(b"a", Put::Fail(FailureClass::Unauthorized))
            .putting(b"b", Put::Unavailable)
            .putting(b"c", Put::Present);
        let (staged, _keep) = push_over(&[], &origin).await;
        let e = staged
            .put(&[object(b"a")], &[&file_of(b"a")], &|_, _| {})
            .await
            .unwrap_err();
        assert!(e.class() == Some(FailureClass::Unauthorized), "{e}");
        // nobody has it and nobody takes it
        let e = staged
            .put(&[object(b"b")], &[&file_of(b"b")], &|_, _| {})
            .await
            .unwrap_err();
        assert!(e.to_string().contains("no pusher placed"), "{e}");
        let found = staged
            .put(&[object(b"c")], &[&file_of(b"c")], &|_, _| {})
            .await
            .unwrap();
        assert_eq!(found[0].how, How::Present);
    }

    #[tokio::test]
    async fn a_connection_that_is_lost_leaves_the_pusher_out_and_the_origin_goes_on() {
        let sink = Script::new(false);
        let origin = Script::new(true).probing(b"a", Have::Present);
        let (staged, mut locals) = push_over(&[&sink], &origin).await;
        // the pusher of the first place goes away
        locals.remove(0);
        let found = staged.probe(&[object(b"a")]).await.unwrap();
        assert_eq!(found[0].map(|f| f.sink), Some(1));
        assert!(staged.broken(0).is_some());
    }

    /// Rule 1 holds for every pusher but the last, whatever it is: one that
    /// can commit and is placed before the destination's own is a helper,
    /// and its failure goes to the next.
    #[tokio::test]
    async fn a_helper_that_can_commit_is_no_more_than_a_helper() {
        let helper = Script::new(true).putting(b"a", Put::Fail(FailureClass::Failed));
        let origin = Script::new(true);
        let (staged, _keep) = push_over(&[&helper], &origin).await;
        let found = staged
            .put(&[object(b"a")], &[&file_of(b"a")], &|_, _| {})
            .await
            .unwrap();
        assert_eq!(found[0].sink, 1);
        assert!(staged.broken(0).is_some());
        // the helper that is lost is no failure of the push either
        let helper = Script::new(true);
        let origin = Script::new(true).probing(b"a", Have::Present);
        let (staged, mut locals) = push_over(&[&helper], &origin).await;
        locals.remove(0);
        assert!(staged.probe(&[object(b"a")]).await.is_ok());
    }

    /// Every pusher that is not the origin is told of the commit (`Committed`)
    /// and of the end, after the origin put the manifest: one that can
    /// commit is no more than a helper.
    #[tokio::test]
    async fn the_helpers_are_told_of_the_commit_and_the_end() {
        let helper = Script::new(false);
        let committing = Script::new(true);
        let origin = Script::new(true);
        let (staged, _keep) = push_over(&[&helper, &committing], &origin).await;
        let manifest = object(b"{}");
        staged
            .commit(&manifest, &["latest".into()], &file_of(b"{}"))
            .await
            .unwrap();
        assert_eq!(
            origin.committed.lock().unwrap().as_slice(),
            std::slice::from_ref(&manifest.digest)
        );
        assert_eq!(
            helper.committed.lock().unwrap().as_slice(),
            std::slice::from_ref(&manifest.digest)
        );
        assert_eq!(
            committing.committed.lock().unwrap().as_slice(),
            std::slice::from_ref(&manifest.digest)
        );
        staged.finish().await.unwrap();
        assert!(origin.finished.load(Ordering::Relaxed));
        assert!(helper.finished.load(Ordering::Relaxed));
        assert!(committing.finished.load(Ordering::Relaxed));
    }

    /// Rule 3: a manifest that names a blob the destination does not have
    /// fails the push, naming the pusher that placed the blob.
    #[tokio::test]
    async fn a_commit_that_lacks_a_blob_fails_naming_the_pusher_that_placed_it() {
        let sink = Script::new(false);
        let origin = Script::new(true).probing(b"a", Have::Present);
        let (staged, _keep) = push_over(&[&sink], &origin).await;
        staged
            .put(&[object(b"a")], &[&file_of(b"a")], &|_, _| {})
            .await
            .unwrap();
        let manifest = object(b"{}");
        origin.lacks.lock().unwrap().push(object(b"a").digest);
        let e = staged
            .commit(&manifest, &["latest".into()], &file_of(b"{}"))
            .await
            .unwrap_err();
        match &e {
            ImageError::Transfer {
                party,
                object: Some(o),
                failure,
            } => {
                assert_eq!(party, "sink0");
                assert_eq!(*o, object(b"a").digest);
                assert_eq!(failure.class, FailureClass::Invalid);
            }
            e => panic!("not an invalid transfer: {e}"),
        }
        // (the origin put it: it is the origin that is named)
        let origin = Script::new(true);
        let (staged, _keep) = push_over(&[], &origin).await;
        staged
            .put(&[object(b"a")], &[&file_of(b"a")], &|_, _| {})
            .await
            .unwrap();
        origin.lacks.lock().unwrap().push(object(b"a").digest);
        let e = staged
            .commit(&manifest, &["latest".into()], &file_of(b"{}"))
            .await
            .unwrap_err();
        assert!(
            matches!(&e, ImageError::Transfer { party, failure, .. } if party == "origin" && failure.class == FailureClass::Invalid),
            "{e}"
        );
        let reply = staged
            .commit(&manifest, &["latest".into()], &file_of(b"{}"))
            .await
            .unwrap();
        assert_eq!(reply.digest, manifest.digest);
        staged.finish().await.unwrap();
    }
}
