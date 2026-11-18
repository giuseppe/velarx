// SPDX-License-Identifier: Apache-2.0
//! The typed client of the fetcher interface ([`super::fetch`]):
//! one connection, one call at a time, made with the proxies of the
//! interfaces ([`FetcherProxy`], [`RegistryProxy`]).  A call made with `more`
//! (`Probe`, `Unpack`, `Fetch`, `Tags`, `Search`) holds the connection until
//! its last reply; another connection with the same scope comes from
//! [`FetchConn::connect`].
//!
//! Nothing of what a fetcher answers is trusted here: the caller hashes what
//! `GetManifest`, `GetBlob`, `GetProfile` and `Probe` return and measures
//! what `Fetch` staged.

use super::fetch::{
    Blob, FetchEvent, FetchReply, FetcherError, FetcherProxy, ProbeReply, Probed, Reuse,
    UnpackReply, Urgency, INTERFACE, PROTO,
};
use super::proto::{
    Downloaded, Found, Hit, RegistryError, RegistryProxy, Remote, Tagged, MAX_ANSWER,
};
use crate::pusher::push::PusherError;
use futures::{Stream, StreamExt};
use std::fs::File;
use std::io;
use std::os::fd::OwnedFd;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use velarx_proto::info::Info;
use zlink::Connection;

type Conn = Connection<zlink::tokio::unix::Stream>;

/// Why a call failed.
#[derive(Debug, thiserror::Error)]
pub enum CallError {
    #[error("the fetcher: {0}")]
    Io(#[from] io::Error),
    #[error("the fetcher broke the protocol: {0}")]
    Protocol(String),
    #[error("the fetcher: {0}")]
    Fetcher(#[from] FetcherError),
    #[error("the registry fetcher: {0}")]
    Registry(#[from] RegistryError),
    #[error("the pusher: {0}")]
    Pusher(#[from] PusherError),
}

pub(crate) fn zerr(e: zlink::Error) -> CallError {
    match e {
        zlink::Error::Io(e) => CallError::Io(e),
        zlink::Error::UnexpectedEof => CallError::Io(io::ErrorKind::UnexpectedEof.into()),
        e => CallError::Protocol(e.to_string()),
    }
}

/// What the scope of a connection is (`Open`).
pub struct Scoping<'a> {
    /// fs-verity is enabled on a file before it has its name
    pub verity: bool,
    /// What the origin's transport names; none for a fetcher that is not the
    /// origin
    pub source: Option<&'a str>,
    pub tls_verify: Option<bool>,
    /// The origin the client opened, for an origin that is a path
    pub target: Option<OwnedFd>,
    /// The credentials, a sealed memory file
    pub access: Option<OwnedFd>,
    /// The most a call stays silent
    pub idle: std::time::Duration,
    /// Words the fetcher has to announce
    pub requires: &'a [String],
}

impl Scoping<'static> {
    /// The scope of a connection that is not the origin of anything and
    /// holds no credential: nothing but how long it may be silent.
    pub fn bare(idle: std::time::Duration) -> Self {
        Self {
            verity: false,
            source: None,
            tls_verify: None,
            target: None,
            access: None,
            idle,
            requires: &[],
        }
    }
}

/// A connection to a fetcher.
pub struct FetchConn {
    conn: Conn,
    /// A call has replies to come (or was dropped before they were read):
    /// the next call reads and drops them first
    busy: Arc<AtomicBool>,
}

/// A reply of a typed call: its record or its error, and its descriptors.
type Answer<R> = zlink::Result<(Result<R, CallError>, Vec<OwnedFd>)>;

/// The replies of a typed call made with `more`: one record a reply, then
/// a last reply with none.  Dropped before the last, it leaves the
/// connection `busy`: the next call reads the rest first.
pub struct Replies<'a, R> {
    stream: Pin<Box<dyn Stream<Item = Answer<R>> + Send + 'a>>,
    busy: Arc<AtomicBool>,
}

impl<R> Replies<'_, R> {
    /// The next reply and its descriptors; `is_last` tells a reply that has
    /// no record, which ends the call and is not given.
    pub(crate) async fn next_with(
        &mut self,
        is_last: impl Fn(&R) -> bool,
    ) -> Result<Option<(R, Vec<OwnedFd>)>, CallError> {
        if !self.busy.load(Ordering::Acquire) {
            return Ok(None);
        }
        match self.stream.next().await {
            Some(Ok((Ok(reply), fds))) if is_last(&reply) => {
                self.busy.store(false, Ordering::Release);
                let _ = fds;
                Ok(None)
            }
            Some(Ok((Ok(reply), fds))) => Ok(Some((reply, fds))),
            Some(Ok((Err(e), _))) => {
                self.busy.store(false, Ordering::Release);
                Err(e)
            }
            Some(Err(e)) => {
                self.busy.store(false, Ordering::Release);
                Err(zerr(e))
            }
            None => {
                self.busy.store(false, Ordering::Release);
                Err(CallError::Protocol(
                    "the replies ended with no last reply".into(),
                ))
            }
        }
    }
}

impl Replies<'_, FetchReply> {
    /// The next event of a `Fetch` and its descriptors; none after the last
    /// reply, which has no event.
    pub async fn event(&mut self) -> Result<Option<(FetchEvent, Vec<OwnedFd>)>, CallError> {
        Ok(self
            .next_with(|r| r.event.is_none())
            .await?
            .and_then(|(r, fds)| r.event.map(|e| (e, fds))))
    }
}

impl Replies<'_, ProbeReply> {
    /// The next layer of a `Probe` and its descriptors; none after the last
    /// reply, which has none.
    pub async fn probed(&mut self) -> Result<Option<(Probed, Vec<OwnedFd>)>, CallError> {
        Ok(self
            .next_with(|r| r.probed.is_none())
            .await?
            .and_then(|(r, fds)| r.probed.map(|p| (p, fds))))
    }
}

/// What an `Unpack` tells.
pub enum Unpacking {
    /// The bytes of the blob read so far
    Bytes(u64),
    /// Complete files of the layer, regular files with no name
    Files(Vec<File>),
}

impl Replies<'_, UnpackReply> {
    /// The next thing an `Unpack` tells; none after the last reply.
    pub async fn unpacking(&mut self) -> Result<Option<Unpacking>, CallError> {
        let Some((reply, fds)) = self
            .next_with(|r| r.bytes.is_none() && r.files.is_none())
            .await?
        else {
            return Ok(None);
        };
        let Some(places) = reply.files else {
            return Ok(Some(Unpacking::Bytes(reply.bytes.unwrap_or(0))));
        };
        let mut fds: Vec<Option<OwnedFd>> = fds.into_iter().map(Some).collect();
        let files = places
            .iter()
            .map(|&at| {
                let fd = fds
                    .get_mut(at as usize)
                    .and_then(Option::take)
                    .ok_or_else(|| {
                        CallError::Protocol(format!(
                            "a file is descriptor {at}, and the reply has {}",
                            fds.len()
                        ))
                    })?;
                readable_file(fd).ok_or_else(|| {
                    CallError::Protocol(format!(
                        "descriptor {at} is not a regular file open for reading"
                    ))
                })
            })
            .collect::<Result<_, _>>()?;
        Ok(Some(Unpacking::Files(files)))
    }
}

/// `fd` as a file the engine reads: a regular file open for reading.  A pipe
/// or a socket could keep a read waiting forever, and a descriptor with no
/// read access (`O_PATH`, write-only) reads nothing: either is the fetcher's
/// failure, not the engine's.
fn readable_file(fd: OwnedFd) -> Option<File> {
    use rustix::fs::{FileType, OFlags};
    let regular = FileType::from_raw_mode(rustix::fs::fstat(&fd).ok()?.st_mode).is_file();
    let flags = rustix::fs::fcntl_getfl(&fd).ok()?;
    let readable = !flags.contains(OFlags::PATH) && !flags.contains(OFlags::WRONLY);
    (regular && readable).then(|| File::from(fd))
}

impl Replies<'_, Tagged> {
    /// The next tag; none after the last reply.
    pub async fn tag(&mut self) -> Result<Option<String>, CallError> {
        Ok(self
            .next_with(|r| r.tag.is_none())
            .await?
            .and_then(|(r, _)| r.tag))
    }
}

impl Replies<'_, Found> {
    /// The next hit; none after the last reply.
    pub async fn hit(&mut self) -> Result<Option<Hit>, CallError> {
        Ok(self
            .next_with(|r| r.hit.is_none())
            .await?
            .and_then(|(r, _)| r.hit))
    }
}

/// The error of a reply: the call's own.
pub(crate) fn done<T, E: Into<CallError>>(
    got: zlink::Result<Result<T, E>>,
) -> Result<T, CallError> {
    got.map_err(zerr)?.map_err(Into::into)
}

/// [`done`] of a reply with descriptors.
pub(crate) fn done_fds<T, E: Into<CallError>>(
    got: zlink::Result<(Result<T, E>, Vec<OwnedFd>)>,
) -> Result<(T, Vec<OwnedFd>), CallError> {
    let (reply, fds) = got.map_err(zerr)?;
    Ok((reply.map_err(Into::into)?, fds))
}

/// The descriptor of a reply at the position its field names.
fn file_at(mut fds: Vec<OwnedFd>, at: u32, what: &str) -> Result<File, CallError> {
    if (at as usize) < fds.len() {
        Ok(File::from(fds.swap_remove(at as usize)))
    } else {
        Err(CallError::Protocol(format!(
            "{what} is descriptor {at}, and the reply has {}",
            fds.len()
        )))
    }
}

/// A call whose outcome is a stream of replies with a record, each of the
/// type of the stream.
pub(crate) fn replies<'a, R: Send + 'a, E: Into<CallError> + Send + 'a>(
    stream: impl Stream<Item = zlink::Result<Result<R, E>>> + Send + 'a,
    busy: &Arc<AtomicBool>,
) -> Replies<'a, R> {
    Replies {
        stream: Box::pin(stream.map(|item| item.map(|r| (r.map_err(Into::into), Vec::new())))),
        busy: busy.clone(),
    }
}

/// [`replies`] of a call whose replies carry descriptors.
fn replies_fds<'a, R: Send + 'a, E: Into<CallError> + Send + 'a>(
    stream: impl Stream<Item = zlink::Result<(Result<R, E>, Vec<OwnedFd>)>> + Send + 'a,
    busy: &Arc<AtomicBool>,
) -> Replies<'a, R> {
    Replies {
        stream: Box::pin(stream.map(|item| item.map(|(r, fds)| (r.map_err(Into::into), fds)))),
        busy: busy.clone(),
    }
}

impl FetchConn {
    /// A connection on a socket (one end of a pair, or connected).
    pub fn new(stream: std::os::unix::net::UnixStream) -> io::Result<Self> {
        stream.set_nonblocking(true)?;
        let stream = tokio::net::UnixStream::from_std(stream)?;
        let stream = zlink::tokio::unix::Stream::try_from(stream).map_err(io::Error::other)?;
        Ok(Self {
            conn: Connection::new(stream),
            busy: Arc::default(),
        })
    }

    /// A connection to the socket at `path`, served by this user or by
    /// root (`SO_PEERCRED`): a process of another user is refused, naming
    /// the socket.
    pub async fn connect_checked(path: &std::path::Path) -> io::Result<Self> {
        let stream = tokio::net::UnixStream::connect(path).await?;
        let cred = stream.peer_cred()?;
        if !velarx_proto::trusted_uid(cred.uid()) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "{} is served by uid {}, which is neither this user nor root",
                    path.display(),
                    cred.uid()
                ),
            ));
        }
        Self::new(stream.into_std()?)
    }

    /// Read and drop the replies a call left that was dropped before its
    /// last, so the connection serves the next call instead of failing it.
    async fn drained(&mut self) -> Result<(), CallError> {
        while self.busy.load(Ordering::Acquire) {
            let received = self
                .conn
                .read_mut()
                .receive_reply::<serde::de::IgnoredAny, serde::de::IgnoredAny>()
                .await;
            match received {
                // (the last reply of the call ends it; an error is its last)
                Ok((Ok(reply), _)) if reply.continues() == Some(true) => {}
                Ok(_) => self.busy.store(false, Ordering::Release),
                Err(e) => {
                    self.busy.store(false, Ordering::Release);
                    return Err(zerr(e));
                }
            }
        }
        Ok(())
    }

    /// The connection to make a typed call on, and the mark that the call
    /// is in flight: set when the call leaves, cleared when its last reply
    /// is read (a future that is dropped leaves it set).
    pub(crate) async fn begin(&mut self) -> Result<(&mut Conn, Arc<AtomicBool>), CallError> {
        self.drained().await?;
        self.busy.store(true, Ordering::Release);
        Ok((&mut self.conn, self.busy.clone()))
    }

    /// Who the fetcher is and what it can do.
    pub async fn get_info(&mut self) -> Result<Info, CallError> {
        let (conn, busy) = self.begin().await?;
        let info = done(FetcherProxy::get_info(conn).await);
        busy.store(false, Ordering::Release);
        let info = info?;
        velarx_proto::info::check(INTERFACE, &info, PROTO)
            .map_err(|e| CallError::Protocol(e.to_string()))?;
        Ok(info)
    }

    /// Give the connection its scope.
    pub async fn open(&mut self, scope: Scoping<'_>) -> Result<(), CallError> {
        let Scoping {
            verity,
            source,
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
        let got = conn
            .open(
                fds,
                verity,
                source,
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
    pub async fn connect(&mut self) -> Result<FetchConn, CallError> {
        let (conn, busy) = self.begin().await?;
        let got = conn.connect().await;
        busy.store(false, Ordering::Release);
        let (_, fds) = done_fds(got)?;
        let fd = fds
            .into_iter()
            .next()
            .ok_or_else(|| CallError::Protocol("Connect carried no connection".into()))?;
        Ok(FetchConn::new(std::os::unix::net::UnixStream::from(fd))?)
    }

    /// Replace the credentials of the scope.
    pub async fn renew(&mut self, access: OwnedFd) -> Result<(), CallError> {
        let (conn, busy) = self.begin().await?;
        let got = conn.renew(vec![access], 0).await;
        busy.store(false, Ordering::Release);
        done(got).map(|_| ())
    }

    /// Tell the fetcher of a layer: its staging directory, its table of
    /// contents as the engine verified it.
    pub async fn layer(
        &mut self,
        layer: &str,
        blob: Option<&Blob>,
        staging: &File,
        toc: Option<OwnedFd>,
    ) -> Result<(), CallError> {
        let mut fds = vec![OwnedFd::from(staging.try_clone()?)];
        let toc_at = toc.map(|fd| {
            fds.push(fd);
            1
        });
        let (conn, busy) = self.begin().await?;
        let got = conn.layer(fds, layer, 0, blob, toc_at).await;
        busy.store(false, Ordering::Release);
        done(got).map(|_| ())
    }

    /// Forget the layer.
    pub async fn forget(&mut self, layer: &str) -> Result<(), CallError> {
        let (conn, busy) = self.begin().await?;
        let got = conn.forget(layer).await;
        busy.store(false, Ordering::Release);
        done(got).map(|_| ())
    }

    /// The manifest or index `reference` names, at most `max` bytes: the
    /// sealed memory file of the reply, and its media type.
    pub async fn get_manifest(
        &mut self,
        reference: &str,
        max: u64,
    ) -> Result<(File, Option<String>), CallError> {
        let (conn, busy) = self.begin().await?;
        let got = conn.get_manifest(reference, max).await;
        busy.store(false, Ordering::Release);
        let (manifest, fds) = done_fds(got)?;
        Ok((file_at(fds, manifest.file, reference)?, manifest.media_type))
    }

    /// A small blob: the sealed memory file of the reply.
    pub async fn get_blob(&mut self, blob: &Blob) -> Result<File, CallError> {
        let (conn, busy) = self.begin().await?;
        let got = conn.get_blob(blob).await;
        busy.store(false, Ordering::Release);
        let (item, fds) = done_fds(got)?;
        file_at(fds, item.file, &blob.digest)
    }

    /// The startup profile of `image`: the sealed memory file of the reply.
    pub async fn get_profile(&mut self, image: &str, max: u64) -> Result<File, CallError> {
        let (conn, busy) = self.begin().await?;
        let got = conn.get_profile(image, max).await;
        busy.store(false, Ordering::Release);
        let (item, fds) = done_fds(got)?;
        file_at(fds, item.file, image)
    }

    /// What the fetcher can do for `layers`.
    pub async fn probe(&mut self, layers: &[Blob]) -> Result<Replies<'_, ProbeReply>, CallError> {
        let (conn, busy) = self.begin().await?;
        match conn.probe(layers.to_vec()).await {
            Ok(stream) => Ok(replies_fds(stream, &busy)),
            Err(e) => {
                busy.store(false, Ordering::Release);
                Err(zerr(e))
            }
        }
    }

    /// Read the whole blob of `layer`, a layer with no table of contents,
    /// and have its files, `toc.claim` and `tarsplit` named in its staging:
    /// the replies carry the bytes of the blob read so far, the last none.
    /// A failure is the error of the call.
    pub async fn unpack(
        &mut self,
        layer: &str,
        urgency: Urgency,
    ) -> Result<Replies<'_, UnpackReply>, CallError> {
        let (conn, busy) = self.begin().await?;
        match conn.unpack(layer.to_string(), urgency).await {
            Ok(stream) => Ok(replies_fds(stream, &busy)),
            Err(e) => {
                busy.store(false, Ordering::Release);
                Err(zerr(e))
            }
        }
    }

    /// Bring the files `objects` of `layer` into its staging directory.
    /// `reuse`: chunks of the store the files may take, in the files of
    /// `sources` (at most [`MAX_FDS`]); a hint names its file by position.
    ///
    /// [`MAX_FDS`]: super::fetch::MAX_FDS
    pub async fn fetch(
        &mut self,
        layer: &str,
        objects: &[String],
        urgency: Urgency,
        (reuse, sources): (&[Reuse], Vec<OwnedFd>),
    ) -> Result<Replies<'_, FetchReply>, CallError> {
        let (conn, busy) = self.begin().await?;
        let reuse = (!reuse.is_empty()).then_some(reuse);
        match conn
            .fetch(
                sources,
                layer.to_string(),
                objects.to_vec(),
                urgency,
                reuse.map(<[Reuse]>::to_vec),
            )
            .await
        {
            Ok(stream) => Ok(replies(stream, &busy)),
            Err(e) => {
                busy.store(false, Ordering::Release);
                Err(zerr(e))
            }
        }
    }
}

/// The repository calls of the registry fetcher (`org.velarx.Registry`): the
/// repository and the credentials of a call are its own, not those of a
/// scope.
impl FetchConn {
    /// The tags of `remote`, every page of them.
    pub async fn tags(
        &mut self,
        remote: &Remote,
        access: Option<&Access>,
    ) -> Result<Vec<String>, CallError> {
        let (conn, busy) = self.begin().await?;
        let mut tags = match RegistryProxy::tags(
            conn,
            Access::fds(access),
            remote.clone(),
            MAX_ANSWER,
        )
        .await
        {
            Ok(stream) => replies(stream, &busy),
            Err(e) => {
                busy.store(false, Ordering::Release);
                return Err(zerr(e));
            }
        };
        let mut all = Vec::new();
        while let Some(tag) = tags.tag().await? {
            all.push(tag);
        }
        Ok(all)
    }

    /// A search of the registry of `remote` for `needle`: at most `limit`
    /// hits.
    pub async fn search(
        &mut self,
        remote: &Remote,
        access: Option<&Access>,
        (needle, limit): (&str, u64),
    ) -> Result<Vec<Hit>, CallError> {
        let (conn, busy) = self.begin().await?;
        let mut hits = match RegistryProxy::search(
            conn,
            Access::fds(access),
            remote.clone(),
            needle.to_string(),
            limit,
        )
        .await
        {
            Ok(stream) => replies(stream, &busy),
            Err(e) => {
                busy.store(false, Ordering::Release);
                return Err(zerr(e));
            }
        };
        let mut all = Vec::new();
        while let Some(hit) = hits.hit().await? {
            all.push(hit);
        }
        Ok(all)
    }

    /// Whether the registry of `remote` takes the credentials of `access`.
    pub async fn login(&mut self, remote: &Remote, access: &Access) -> Result<(), CallError> {
        let (conn, busy) = self.begin().await?;
        let got = RegistryProxy::login(conn, Access::fds(Some(access)), remote).await;
        busy.store(false, Ordering::Release);
        done(got).map(|_| ())
    }

    /// The body of `url`, at most `max` bytes, written into `dest` (a file
    /// of the engine, with no name, open for writing).
    pub async fn download(
        &mut self,
        url: &str,
        max: u64,
        dest: &File,
    ) -> Result<Downloaded, CallError> {
        let fds = vec![OwnedFd::from(dest.try_clone()?)];
        let (conn, busy) = self.begin().await?;
        let got = RegistryProxy::download(conn, fds, url, max, 0).await;
        busy.store(false, Ordering::Release);
        done(got)
    }
}

/// The credentials, certificates and auth files of a call: the JSON of a
/// `RegistryAccess` in a sealed memory file (it is never on a disk), passed
/// with the call and read once by the fetcher.  No message carries a
/// secret.
#[derive(Clone)]
pub struct Access {
    file: Arc<File>,
}

impl std::fmt::Debug for Access {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Access(a sealed memory file)")
    }
}

impl Access {
    /// The file for `access` (none: it has nothing).
    pub fn new(access: &velarx_registry::auth::RegistryAccess) -> io::Result<Option<Self>> {
        if access.is_empty() {
            return Ok(None);
        }
        let json = serde_json::to_vec(access).map_err(io::Error::other)?;
        if json.len() as u64 > super::fetch::MAX_ACCESS {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "the credentials and certificates are too large to pass",
            ));
        }
        let fd = velarx_base::sealed::sealed_memory(&json)?;
        Ok(Some(Self {
            file: Arc::new(File::from(fd)),
        }))
    }

    /// The files a call carries for `access`.
    pub(crate) fn files(access: Option<&Access>) -> Vec<File> {
        access
            .and_then(|a| a.file.try_clone().ok())
            .into_iter()
            .collect()
    }
}

impl Access {
    /// The descriptors a call carries for `access`.
    pub fn fds(access: Option<&Access>) -> Vec<OwnedFd> {
        Self::files(access).into_iter().map(OwnedFd::from).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The name of the variable that makes this test binary serve one
    /// connection on the socket it names, then end (the child of the test
    /// below, which runs as another user).
    const SERVE_ON: &str = "VELARX_TEST_SERVE_ONE_ON";

    #[test]
    fn the_server_of_another_user_for_the_test_below() {
        let Some(path) = std::env::var_os(SERVE_ON) else {
            return;
        };
        let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        std::fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(0o666))
            .unwrap();
        // (the parent reads this line, then connects once)
        println!("{SERVING}");
        std::io::Write::flush(&mut std::io::stdout()).unwrap();
        let _ = listener.accept();
    }

    /// The line the server of another user writes once it listens.
    const SERVING: &str = "velarx-test-serving";

    #[tokio::test]
    async fn a_socket_served_by_another_user_is_refused_and_named() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(
            dir.path(),
            std::os::unix::fs::PermissionsExt::from_mode(0o777),
        )
        .unwrap();
        let socket = dir.path().join("other.sock");
        let me = std::env::current_exe().unwrap();
        // (the test needs a user namespace with the ids of /etc/subuid: a
        // host without one fails it, as it fails the other confinement tests)
        let mut child = std::process::Command::new("unshare")
            .args([
                "--user",
                "--map-users=auto",
                "--map-groups=auto",
                "--setuid",
                "1",
                "--setgid",
                "1",
            ])
            .arg(&me)
            .args([
                "--exact",
                "fetcher::fetch_client::tests::the_server_of_another_user_for_the_test_below",
                "--nocapture",
            ])
            .env(SERVE_ON, &socket)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .expect("unshare");
        let out = child.stdout.take().unwrap();
        let serving = tokio::task::spawn_blocking(move || {
            use std::io::BufRead;
            std::io::BufReader::new(out)
                .lines()
                .map_while(Result::ok)
                .any(|line| line == SERVING)
        })
        .await
        .unwrap();
        assert!(
            serving,
            "no server of another user (a user namespace with the ids of /etc/subuid)"
        );
        let err = FetchConn::connect_checked(&socket).await.err().unwrap();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        assert!(err.to_string().contains(socket.to_str().unwrap()), "{err}");
        let _ = child.kill();
        let _ = child.wait();
    }

    /// A call with `more` ends with a reply that has no record and
    /// `continues: false`; one that ends otherwise (a last reply with no
    /// parameters at all) is a fetcher that broke the protocol.
    #[tokio::test]
    async fn a_call_with_more_ends_with_an_empty_record_and_nothing_else_is_accepted() {
        use zlink::Reply;
        let (ours, theirs) = std::os::unix::net::UnixStream::pair().unwrap();
        theirs.set_nonblocking(true).unwrap();
        let server = tokio::spawn(async move {
            let stream = zlink::tokio::unix::Stream::try_from(
                tokio::net::UnixStream::from_std(theirs).unwrap(),
            )
            .unwrap();
            let mut conn = zlink::Connection::new(stream);
            // (the first call is answered as the interface says, the second
            // with a last reply that has no parameters)
            for last in [Some(ProbeReply { probed: None }), None] {
                let (_call, _fds) = conn
                    .read_mut()
                    .receive_call::<serde_json::Value>()
                    .await
                    .unwrap();
                let reply = Reply::new(last).set_continues(Some(false));
                conn.send_reply(&reply, Vec::new()).await.unwrap();
            }
        });
        let mut conn = FetchConn::new(ours).unwrap();
        let mut replies = conn.probe(&[]).await.unwrap();
        assert!(replies.probed().await.unwrap().is_none());
        drop(replies);
        let mut replies = conn.probe(&[]).await.unwrap();
        let broken = replies.probed().await.unwrap_err();
        assert!(matches!(broken, CallError::Protocol(_)), "{broken:?}");
        server.await.unwrap();
    }
}
