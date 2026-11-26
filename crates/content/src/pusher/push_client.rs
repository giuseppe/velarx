// SPDX-License-Identifier: Apache-2.0
//! The typed client of the pusher interface ([`super::push`]): the calls
//! of `org.velarx.Pusher` on a [`FetchConn`], the connection the engine
//! has to a process that serves it (the same socket as the fetcher
//! interface), made with [`PusherProxy`].  A call made with `more`
//! (`Probe`, `Put`) holds the connection until its last reply; another
//! connection with the same scope comes from [`FetchConn::push_connect`].
//!
//! Nothing a pusher answers is trusted here: what a pusher that is not the
//! origin says it placed is confirmed by the walker.

use super::push::{CommitReply, Object, ProbeReply, PusherProxy, PutReply, INTERFACE, PROTO};
use crate::fetcher::fetch_client::{done, done_fds, replies, zerr, CallError, FetchConn, Replies};
use std::fs::File;
use std::os::fd::OwnedFd;
use std::sync::atomic::Ordering;
use velarx_proto::info::Info;

/// What the scope of a connection to a pusher is (`Open`).
pub struct PushScoping<'a> {
    /// What the destination's transport names
    pub destination: &'a str,
    pub tls_verify: Option<bool>,
    /// The destination the client opened (a directory, or a file open for
    /// writing)
    pub target: Option<OwnedFd>,
    /// The credentials, a sealed memory file
    pub access: Option<OwnedFd>,
    /// The most a call stays silent
    pub idle: std::time::Duration,
    /// Words the pusher has to announce
    pub requires: &'a [String],
}

impl Replies<'_, ProbeReply> {
    /// The next object of a `Probe`; none after the last reply, which has
    /// none.
    pub async fn probed(
        &mut self,
    ) -> Result<Option<(super::push::Probed, Vec<OwnedFd>)>, CallError> {
        Ok(self
            .next_with(|r| r.probed.is_none())
            .await?
            .and_then(|(r, fds)| r.probed.map(|p| (p, fds))))
    }
}

impl Replies<'_, PutReply> {
    /// The next event of a `Put`; none after the last reply, which has none.
    pub async fn event(
        &mut self,
    ) -> Result<Option<(super::push::PutEvent, Vec<OwnedFd>)>, CallError> {
        Ok(self
            .next_with(|r| r.event.is_none())
            .await?
            .and_then(|(r, fds)| r.event.map(|e| (e, fds))))
    }
}

/// The calls of `org.velarx.Pusher`.
impl FetchConn {
    /// Who the pusher is and what it can do.
    pub async fn push_get_info(&mut self) -> Result<Info, CallError> {
        let (conn, busy) = self.begin().await?;
        let info = done(PusherProxy::get_info(conn).await);
        busy.store(false, Ordering::Release);
        let info = info?;
        velarx_proto::info::check(INTERFACE, &info, PROTO)
            .map_err(|e| CallError::Protocol(e.to_string()))?;
        Ok(info)
    }

    /// Give the connection its scope.
    pub async fn push_open(&mut self, scope: PushScoping<'_>) -> Result<(), CallError> {
        let PushScoping {
            destination,
            tls_verify,
            target,
            access,
            idle,
            requires,
        } = scope;
        let mut fds = Vec::new();
        let mut position = |fd: Option<OwnedFd>| {
            fd.map(|fd| {
                fds.push(fd);
                fds.len() as u32 - 1
            })
        };
        let (target, access) = (position(target), position(access));
        let (conn, busy) = self.begin().await?;
        let got = PusherProxy::open(
            conn,
            fds,
            destination,
            tls_verify,
            target,
            access,
            idle.as_millis() as u64,
            requires,
        )
        .await;
        busy.store(false, Ordering::Release);
        done(got).map(|_| ())
    }

    /// Another connection with the scope of this one.
    pub async fn push_connect(&mut self) -> Result<FetchConn, CallError> {
        let (conn, busy) = self.begin().await?;
        let got = PusherProxy::connect(conn).await;
        busy.store(false, Ordering::Release);
        let (_, fds) = done_fds(got)?;
        let fd = fds
            .into_iter()
            .next()
            .ok_or_else(|| CallError::Protocol("Connect carried no connection".into()))?;
        Ok(self.handed(fd)?)
    }

    /// Replace the credentials of the scope.
    pub async fn push_renew(&mut self, access: OwnedFd) -> Result<(), CallError> {
        let (conn, busy) = self.begin().await?;
        let got = PusherProxy::renew(conn, vec![access], 0).await;
        busy.store(false, Ordering::Release);
        done(got).map(|_| ())
    }

    /// What the pusher has of `objects`: a reply for each.
    pub async fn push_probe(
        &mut self,
        objects: &[Object],
    ) -> Result<Replies<'_, ProbeReply>, CallError> {
        let (conn, busy) = self.begin().await?;
        match PusherProxy::probe(conn, objects.to_vec()).await {
            Ok(stream) => Ok(replies(stream, &busy)),
            Err(e) => {
                busy.store(false, Ordering::Release);
                Err(zerr(e))
            }
        }
    }

    /// Place `objects`; `data` has the file of each, in order.
    pub async fn push_put(
        &mut self,
        objects: &[Object],
        data: &[&File],
    ) -> Result<Replies<'_, PutReply>, CallError> {
        let mut fds = Vec::with_capacity(data.len());
        for file in data {
            fds.push(OwnedFd::from(velarx_sys::fd::reopen_read_only(file)?));
        }
        let files = (0..fds.len() as u32).collect();
        let (conn, busy) = self.begin().await?;
        match PusherProxy::put(conn, fds, objects.to_vec(), files).await {
            Ok(stream) => Ok(replies(stream, &busy)),
            Err(e) => {
                busy.store(false, Ordering::Release);
                Err(zerr(e))
            }
        }
    }

    /// Put the manifest that `body` holds as each of `names`.
    pub async fn push_commit(
        &mut self,
        manifest: &Object,
        names: &[String],
        body: &File,
    ) -> Result<CommitReply, CallError> {
        let fds = vec![OwnedFd::from(velarx_sys::fd::reopen_read_only(body)?)];
        let (conn, busy) = self.begin().await?;
        let got = PusherProxy::commit(conn, fds, manifest, 0, names).await;
        busy.store(false, Ordering::Release);
        done(got)
    }

    /// Tell the pusher that the destination has the manifest `digest` by
    /// `names` now.
    pub async fn push_committed(
        &mut self,
        manifest: &Object,
        digest: &str,
        names: &[String],
    ) -> Result<(), CallError> {
        let (conn, busy) = self.begin().await?;
        let got = PusherProxy::committed(conn, manifest, digest, names).await;
        busy.store(false, Ordering::Release);
        done(got).map(|_| ())
    }

    /// The end of the scope.
    pub async fn push_finish(&mut self) -> Result<(), CallError> {
        let (conn, busy) = self.begin().await?;
        let got = PusherProxy::finish(conn).await;
        busy.store(false, Ordering::Release);
        done(got).map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fetcher::fetch_client::FetchConn;
    use crate::pusher::push::{EventKind, Have, Placed, Probed, PusherError, PutEvent, Role};
    use crate::serve_fetch::{Described, LocalFetcher, Out, StagingFetcher};
    use crate::serve_push::{CommitCall, PushScope, Pushing, PutCall};
    use async_trait::async_trait;
    use std::io::Write;
    use std::sync::{Arc, Mutex};
    use velarx_proto::transfer::{Failure, FailureClass};

    /// A pusher that answers by the media type of the object: `present`,
    /// `linked`, `needed`; it places what it is given unless the media type
    /// is `fail`, and records what it was asked.
    #[derive(Default)]
    struct Fake {
        placed: Mutex<Vec<(String, Vec<u8>)>>,
        committed: Mutex<Vec<(String, Vec<String>)>>,
        finished: Mutex<u32>,
        access: Mutex<Option<Vec<u8>>>,
    }

    #[async_trait]
    impl Pushing for Fake {
        fn described(&self) -> Described {
            Described {
                name: "fake".into(),
                capabilities: vec!["origin".into(), "link".into()],
                max_objects: 4,
            }
        }

        async fn probe(
            &self,
            scope: &PushScope,
            objects: Vec<Object>,
            out: &Out<Probed>,
        ) -> Result<(), PusherError> {
            *self.access.lock().unwrap() = scope.access.as_ref().map(|a| a.to_vec());
            // (in the opposite order: a reply names its object)
            for (index, o) in objects.iter().enumerate().rev() {
                let have = match o.media_type.as_str() {
                    "present" => Have::Present,
                    "linked" => Have::Linked,
                    "needed" => Have::Needed,
                    _ => Have::Unavailable,
                };
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
            use std::io::Read;
            for (index, (object, mut data)) in call.objects.iter().zip(call.data).enumerate() {
                let at = vec![index as u32];
                if object.media_type == "fail" {
                    let _ = out
                        .send(PutEvent::failed(
                            at,
                            Failure {
                                class: FailureClass::NoSpace,
                                reason: "full".into(),
                            },
                        ))
                        .await;
                    continue;
                }
                let mut bytes = Vec::new();
                data.read_to_end(&mut bytes).unwrap();
                let _ = out
                    .send(PutEvent {
                        objects: at.clone(),
                        bytes: Some(bytes.len() as u64),
                        ..PutEvent::of(EventKind::Progress)
                    })
                    .await;
                self.placed
                    .lock()
                    .unwrap()
                    .push((object.digest.clone(), bytes));
                let _ = out
                    .send(PutEvent {
                        objects: at,
                        ..PutEvent::of(EventKind::Placed)
                    })
                    .await;
            }
            Ok(())
        }

        async fn commit(
            &self,
            _scope: &PushScope,
            call: CommitCall,
        ) -> Result<CommitReply, PusherError> {
            if call.manifest.media_type == "unknown-blob" {
                return Err(PusherError::ObjectsMissing {
                    digests: vec![crate::sha256_text(b"gone")],
                });
            }
            self.committed
                .lock()
                .unwrap()
                .push((call.manifest.digest.clone(), call.names));
            Ok(CommitReply {
                digest: call.manifest.digest,
                placed: vec![Placed {
                    name: None,
                    accepted: true,
                    reason: None,
                }],
            })
        }

        async fn finish(&self, _scope: &PushScope) -> Result<(), PusherError> {
            *self.finished.lock().unwrap() += 1;
            Ok(())
        }
    }

    struct WithPusher(Arc<Fake>);

    #[async_trait]
    impl StagingFetcher for WithPusher {
        fn described(&self) -> Described {
            Described {
                name: "with-pusher".into(),
                capabilities: Vec::new(),
                max_objects: 1,
            }
        }

        fn pusher(&self) -> Option<Arc<dyn Pushing>> {
            Some(self.0.clone())
        }
    }

    struct Nothing;

    #[async_trait]
    impl StagingFetcher for Nothing {
        fn described(&self) -> Described {
            Described {
                name: "nothing".into(),
                capabilities: Vec::new(),
                max_objects: 1,
            }
        }
    }

    fn started(api: Arc<dyn StagingFetcher>) -> (LocalFetcher, FetchConn) {
        let local = LocalFetcher::start(api, crate::activation::Limits::default()).unwrap();
        let conn = FetchConn::new(local.connect().unwrap()).unwrap();
        (local, conn)
    }

    fn object(body: &[u8], media_type: &str) -> Object {
        Object {
            digest: crate::sha256_text(body),
            size: body.len() as u64,
            media_type: media_type.into(),
            role: Role::Blob,
            known_at: None,
        }
    }

    fn file_of(body: &[u8]) -> File {
        let mut file = tempfile::tempfile().unwrap();
        file.write_all(body).unwrap();
        file
    }

    fn access() -> OwnedFd {
        velarx_base::sealed::sealed_memory(br#"{"credentials":"x"}"#).unwrap()
    }

    fn refusal<T: std::fmt::Debug>(got: Result<T, CallError>) -> PusherError {
        match got {
            Err(CallError::Pusher(e)) => e,
            other => panic!("not a refusal of the pusher: {other:?}"),
        }
    }

    /// The scope of a connection, as the engine gives it.
    async fn opened(
        conn: &mut FetchConn,
        destination: &str,
        access: Option<OwnedFd>,
        requires: &[String],
    ) -> Result<(), CallError> {
        conn.push_open(PushScoping {
            destination,
            tls_verify: None,
            target: None,
            access,
            idle: std::time::Duration::from_secs(60),
            requires,
        })
        .await
    }

    async fn probed(conn: &mut FetchConn, objects: &[Object]) -> Vec<Have> {
        let mut replies = conn.push_probe(objects).await.unwrap();
        let mut have = vec![Have::Unknown; objects.len()];
        while let Some((reply, fds)) = replies.probed().await.unwrap() {
            assert!(fds.is_empty());
            have[reply.index as usize] = reply.have;
        }
        have
    }

    #[tokio::test]
    async fn a_pusher_is_scoped_probed_given_the_bytes_and_commits() {
        let fake = Arc::new(Fake::default());
        let (_local, mut conn) = started(Arc::new(WithPusher(fake.clone())));
        let info = conn.push_get_info().await.unwrap();
        assert_eq!(info.name, "fake");
        assert_eq!(info.proto, 1);
        assert_eq!(info.limit("max_objects"), Some(4));
        opened(
            &mut conn,
            "registry.example/name",
            Some(access()),
            &["origin".to_string()],
        )
        .await
        .unwrap();
        let objects = [
            object(b"a", "present"),
            object(b"b", "needed"),
            object(b"c", "linked"),
            object(b"d", "other"),
        ];
        assert_eq!(
            probed(&mut conn, &objects).await,
            [Have::Present, Have::Needed, Have::Linked, Have::Unavailable]
        );
        assert_eq!(
            fake.access.lock().unwrap().as_deref(),
            Some(&br#"{"credentials":"x"}"#[..]),
            "the credentials are the scope's"
        );
        // two objects placed, one failed
        let put = [
            object(b"one", "needed"),
            object(b"two", "fail"),
            object(b"three", "needed"),
        ];
        let files = [file_of(b"one"), file_of(b"two"), file_of(b"three")];
        let mut replies = conn
            .push_put(&put, &files.iter().collect::<Vec<_>>())
            .await
            .unwrap();
        let mut events = Vec::new();
        while let Some((event, _)) = replies.event().await.unwrap() {
            events.push((
                event.kind,
                event.objects,
                event.failure.map(|f| f.class),
                event.bytes,
            ));
        }
        drop(replies);
        assert_eq!(
            events,
            [
                (EventKind::Progress, vec![0], None, Some(3)),
                (EventKind::Placed, vec![0], None, None),
                (
                    EventKind::Failed,
                    vec![1],
                    Some(FailureClass::NoSpace),
                    None
                ),
                (EventKind::Progress, vec![2], None, Some(5)),
                (EventKind::Placed, vec![2], None, None),
            ]
        );
        let placed = fake.placed.lock().unwrap().clone();
        assert_eq!(placed.len(), 2);
        assert_eq!(placed[1].1, b"three");
        let manifest = object(b"{}", "application/vnd.oci.image.manifest.v1+json");
        let reply = conn
            .push_commit(&manifest, &["latest".to_string()], &file_of(b"{}"))
            .await
            .unwrap();
        assert_eq!(reply.digest, manifest.digest);
        assert_eq!(fake.committed.lock().unwrap().len(), 1);
        conn.push_finish().await.unwrap();
        assert_eq!(*fake.finished.lock().unwrap(), 1);
    }

    #[tokio::test]
    async fn a_commit_that_the_destination_cannot_take_says_which_blobs_it_lacks() {
        let (_local, mut conn) = started(Arc::new(WithPusher(Arc::default())));
        opened(&mut conn, "registry.example/name", None, &[])
            .await
            .unwrap();
        let manifest = object(b"{}", "unknown-blob");
        let e = refusal(conn.push_commit(&manifest, &[], &file_of(b"{}")).await);
        assert_eq!(
            e,
            PusherError::ObjectsMissing {
                digests: vec![crate::sha256_text(b"gone")]
            }
        );
    }

    #[tokio::test]
    async fn the_scope_is_given_once_and_before_the_calls_that_need_it() {
        let (_local, mut conn) = started(Arc::new(WithPusher(Arc::default())));
        assert!(matches!(
            refusal(conn.push_finish().await),
            PusherError::NotScoped { .. }
        ));
        opened(&mut conn, "registry.example/name", None, &[])
            .await
            .unwrap();
        assert!(matches!(
            refusal(opened(&mut conn, "registry.example/name", None, &[]).await),
            PusherError::NotScoped { .. }
        ));
        // (a word that is not known)
        let (_local, mut other) = started(Arc::new(WithPusher(Arc::default())));
        assert_eq!(
            refusal(opened(&mut other, "x/y", None, &["teleport".to_string()]).await),
            PusherError::NotSupported {
                feature: "teleport".into()
            }
        );
    }

    #[tokio::test]
    async fn the_descriptors_of_a_call_are_what_its_method_says() {
        let (_local, mut conn) = started(Arc::new(WithPusher(Arc::default())));
        // credentials that something else can still change are refused
        let loose = OwnedFd::from(file_of(b"{}"));
        assert!(matches!(
            refusal(opened(&mut conn, "registry.example/name", Some(loose), &[]).await),
            PusherError::InvalidArgument { .. }
        ));
        opened(&mut conn, "registry.example/name", None, &[])
            .await
            .unwrap();
        let objects = [object(b"a", "needed"), object(b"b", "needed")];
        // a data file for each object and no other
        let one = file_of(b"a");
        let mut replies = conn.push_put(&objects, &[&one]).await.unwrap();
        let e = match replies.event().await {
            Err(CallError::Pusher(e)) => e,
            other => panic!("{other:?}"),
        };
        assert!(matches!(e, PusherError::InvalidArgument { .. }));
        drop(replies);
        // too many objects for the pusher
        let many: Vec<Object> = (0..5).map(|i| object(&[i], "needed")).collect();
        let e = match conn.push_probe(&many).await.unwrap().probed().await {
            Err(CallError::Pusher(e)) => e,
            other => panic!("{other:?}"),
        };
        assert!(matches!(e, PusherError::InvalidArgument { .. }));
        // a data file shorter than its object
        let short = [object(b"abc", "needed")];
        let data = file_of(b"a");
        let e = match conn.push_put(&short, &[&data]).await.unwrap().event().await {
            Err(CallError::Pusher(e)) => e,
            other => panic!("{other:?}"),
        };
        assert!(matches!(e, PusherError::InvalidArgument { .. }));
        // an object that is not named by a digest
        let mut bad = object(b"a", "needed");
        bad.digest = "latest".into();
        let e = match conn.push_probe(&[bad]).await.unwrap().probed().await {
            Err(CallError::Pusher(e)) => e,
            other => panic!("{other:?}"),
        };
        assert!(matches!(e, PusherError::InvalidArgument { .. }));
    }

    #[tokio::test]
    async fn another_connection_has_the_scope() {
        let fake = Arc::new(Fake::default());
        let (_local, mut conn) = started(Arc::new(WithPusher(fake)));
        opened(&mut conn, "registry.example/name", Some(access()), &[])
            .await
            .unwrap();
        let mut shared = conn.push_connect().await.unwrap();
        let objects = [object(b"a", "present")];
        assert_eq!(probed(&mut shared, &objects).await, [Have::Present]);
    }

    #[tokio::test]
    async fn new_credentials_replace_those_of_the_scope() {
        let fake = Arc::new(Fake::default());
        let (_local, mut conn) = started(Arc::new(WithPusher(fake.clone())));
        opened(&mut conn, "registry.example/name", Some(access()), &[])
            .await
            .unwrap();
        let objects = [object(b"a", "present")];
        probed(&mut conn, &objects).await;
        let new = velarx_base::sealed::sealed_memory(br#"{"credentials":"y"}"#).unwrap();
        conn.push_renew(new).await.unwrap();
        probed(&mut conn, &objects).await;
        assert_eq!(
            fake.access.lock().unwrap().as_deref(),
            Some(&br#"{"credentials":"y"}"#[..])
        );
    }

    #[tokio::test]
    async fn a_fetcher_that_is_no_pusher_is_unavailable() {
        let (_local, mut conn) = started(Arc::new(Nothing));
        assert!(matches!(
            refusal(conn.push_get_info().await),
            PusherError::Failed { .. }
        ));
        assert!(matches!(
            refusal(opened(&mut conn, "x/y", None, &[]).await),
            PusherError::Failed { .. }
        ));
    }

    /// Closing the connection of a `Put` cancels it: the pusher's `cancel`
    /// is reached, and the call ends without any further reply.  Each `Put`
    /// runs on a connection of its own, so this is all cancellation there is.
    #[tokio::test]
    async fn closing_the_connection_of_a_put_cancels_it() {
        struct Waits {
            running: Arc<tokio::sync::Notify>,
            cancelled: Arc<tokio::sync::Notify>,
        }
        #[async_trait]
        impl Pushing for Waits {
            fn described(&self) -> Described {
                Described {
                    name: "waits".into(),
                    capabilities: Vec::new(),
                    max_objects: 3,
                }
            }

            async fn put(
                &self,
                _scope: &PushScope,
                call: PutCall,
                _out: &Out<PutEvent>,
            ) -> Result<(), PusherError> {
                self.running.notify_one();
                call.cancel.cancelled().await;
                self.cancelled.notify_one();
                Ok(())
            }
        }
        struct Api(Arc<Waits>);
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
        let waits = Arc::new(Waits {
            running: Arc::new(tokio::sync::Notify::new()),
            cancelled: Arc::new(tokio::sync::Notify::new()),
        });
        let (_local, mut conn) = started(Arc::new(Api(waits.clone())));
        opened(&mut conn, "x/y", None, &[]).await.unwrap();
        let o = object(b"a", "needed");
        let data = file_of(b"a");
        let mut other = conn.push_connect().await.unwrap();
        {
            let _replies = other
                .push_put(std::slice::from_ref(&o), &[&data])
                .await
                .unwrap();
            waits.running.notified().await;
        }
        // (the replies are not read: only the close can end the call)
        drop(other);
        // the pusher's `cancel` is reached by the close alone
        waits.cancelled.notified().await;
    }

    #[tokio::test]
    async fn a_pusher_that_implements_nothing_has_nothing() {
        struct Empty;
        #[async_trait]
        impl Pushing for Empty {
            fn described(&self) -> Described {
                Described {
                    name: "empty".into(),
                    capabilities: Vec::new(),
                    max_objects: 3,
                }
            }
        }
        struct Api;
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
                Some(Arc::new(Empty))
            }
        }
        let (_local, mut conn) = started(Arc::new(Api));
        opened(&mut conn, "x/y", None, &[]).await.unwrap();
        let objects = [object(b"a", "needed"), object(b"b", "needed")];
        assert_eq!(
            probed(&mut conn, &objects).await,
            [Have::Unavailable, Have::Unavailable]
        );
        let files = [file_of(b"a"), file_of(b"b")];
        let mut replies = conn
            .push_put(&objects, &files.iter().collect::<Vec<_>>())
            .await
            .unwrap();
        let (first, _) = replies.event().await.unwrap().unwrap();
        assert_eq!(first.kind, EventKind::Unavailable);
        assert_eq!(first.objects, [0, 1]);
        // (the last reply has no event)
        assert!(replies.event().await.unwrap().is_none());
        drop(replies);
        // (it does not own its destination: it commits nothing; told of a
        // commit, it takes note of nothing)
        let manifest = object(b"{}", "m");
        let e = refusal(conn.push_commit(&manifest, &[], &file_of(b"{}")).await);
        assert!(
            matches!(e, PusherError::Failed { ref failure } if failure.class == FailureClass::Unavailable)
        );
        conn.push_committed(&manifest, &manifest.digest, &[])
            .await
            .unwrap();
    }
}
