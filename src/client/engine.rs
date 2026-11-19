// SPDX-License-Identifier: Apache-2.0
//! The client of a running engine, which the command line and the thin
//! client ask for each operation over the varlink interface
//! `org.velarx.Engine`: every operation is a typed method of the interface.
//! What is large crosses in pipes: an upload is frames written as the command
//! produces it, a download frames read as they come, and the progress of a
//! build the lines of its events.

use super::*;
use std::io::{BufRead, Read, Write};
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use velarx_proto::build::MAX_FRAME;
use velarx_proto::buildspec::{BuildEvent as BuildEventRecord, BuildEventKind, BuildStream};
use velarx_proto::engine::{
    ArtifactAddSpec, AttachOptions, ChangeKind, CheckpointFlags, CommitSpec, Compression,
    Condition, DiffType, EngineError, EngineProxy, Filter, ImportSpec, InstanceSpec,
    LayerCompression, LogOptions, PlatformSpec, PodLogOptions, PullSpec, PushSpec, SessionReply,
    UpdateSpec, Waited,
};
use velarx_proto::pod::{PodAction, PodSpec};
use velarx_proto::workload::{
    ArtifactListed, ArtifactRecord, Committed, ContainerListed, ContainerRecord, ExecSpec,
    ImageHistoryEntry, ImageRecord, ImageRemoved, ImagesRemoved, LogStream, ManifestRemoved,
    NetworkRecord, NetworkSpec, PodListed, PodLogLine, PodLogListed, PodRecord, PrunedImage,
    PushedImage, SecretRecord, StatsListed, TransferStats, VolumeRecord, VolumeSpec,
};
use velarx_proto::workload::{
    EventListed, ImageHistoryListed, ImageListed, ImagePruneListed, NetworkListed, Pulled,
    PulledImage, Pushed, SecretListed, VolumeListed,
};
use velarx_wire::varlink::CallError;

/// A client of the engine on a socket.
#[derive(Clone)]
pub struct EngineClient {
    endpoint: Endpoint,
    /// The connection of the last call that was answered in full, checked,
    /// for the next one (a command makes several calls; the engine checks
    /// the version of the connection once).
    kept: std::sync::Arc<std::sync::Mutex<Option<Link>>>,
}

/// A connection to the engine.
struct Link {
    conn: Proxy,
}

impl Link {
    /// Whether nothing came on the connection: an end of file or a hangup
    /// (the engine stopped or restarted) says it is not to be used.  Never
    /// waits.
    fn still_open(&self) -> bool {
        velarx_sys::fd::peer_silent(&self.conn.read().read_half().0)
    }
}

/// Where the engine is: a socket in the file system, or (the engine of the
/// process of the command) the service of this process, which takes one end
/// of a socket pair for each connection: no other process can connect to it.
#[derive(Clone)]
enum Endpoint {
    Path(PathBuf),
    InProcess(tokio::sync::mpsc::UnboundedSender<std::os::unix::net::UnixStream>),
}

impl Endpoint {
    fn connect(&self) -> std::io::Result<std::os::unix::net::UnixStream> {
        use std::os::unix::net::UnixStream;
        match self {
            Endpoint::Path(path) => UnixStream::connect(path),
            Endpoint::InProcess(hand) => {
                let (ours, theirs) = UnixStream::pair()?;
                hand.send(theirs).map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::ConnectionRefused,
                        "the service has ended",
                    )
                })?;
                Ok(ours)
            }
        }
    }
}

impl std::fmt::Display for Endpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Endpoint::Path(path) => write!(f, "{}", path.display()),
            Endpoint::InProcess(_) => write!(f, "the engine service of this command"),
        }
    }
}

/// The frames of a download, as the bytes they hold.  A pipe that ends
/// before the empty frame is a download that was cut: a read error.
struct Frames {
    pipe: std::fs::File,
    left: usize,
    done: bool,
}

impl Read for Frames {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let cut = || {
            std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "the engine stopped before the end of the data",
            )
        };
        if self.done || buf.is_empty() {
            return Ok(0);
        }
        if self.left == 0 {
            let mut head = [0u8; 4];
            self.pipe.read_exact(&mut head).map_err(|_| cut())?;
            self.left = u32::from_be_bytes(head) as usize;
            if self.left == 0 {
                self.done = true;
                return Ok(0);
            }
            if self.left > MAX_FRAME {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "a frame of the engine is too long",
                ));
            }
        }
        let n = buf.len().min(self.left);
        let got = self.pipe.read(&mut buf[..n])?;
        if got == 0 {
            return Err(cut());
        }
        self.left -= got;
        Ok(got)
    }
}

/// What writes the frames of an upload to the pipe of the call.
struct FrameWriter {
    pipe: std::fs::File,
}

impl Write for FrameWriter {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        let part = &data[..data.len().min(MAX_FRAME)];
        if part.is_empty() {
            return Ok(0);
        }
        let mut frame = Vec::with_capacity(4 + part.len());
        frame.extend_from_slice(&(part.len() as u32).to_be_bytes());
        frame.extend_from_slice(part);
        self.pipe.write_all(&frame)?;
        Ok(part.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// The interface the engine serves.
const INTERFACE: &str = "org.velarx.Engine";

/// The warnings of a reply (podman's, of a stop that needed the kill), said
/// on the standard error.
fn warn_all(warnings: &[String]) {
    for w in warnings {
        warn(w);
    }
}

/// A warning said as podman's logs say it: `time="..." level=warning msg="..."`.
pub fn warn(message: &str) {
    eprintln!(
        "time=\"{}\" level=warning msg={message:?}",
        chrono::Local::now().format("%Y-%m-%dT%H:%M:%S%:z")
    );
}

/// The name of an error of the engine without its interface.
fn error_name(error: &str) -> &str {
    error
        .strip_prefix(INTERFACE)
        .and_then(|n| n.strip_prefix('.'))
        .unwrap_or(error)
}

/// The error of a call, as the command line has it: the one table of the
/// command line from the names of the engine's conditions
/// to the codes its commands tell apart.
#[inline(never)]
fn client_error(e: CallError) -> ClientError {
    match e {
        // (the engine went away during the call: it stopped or crashed; the
        // call is not sent again, whatever it was)
        CallError::Io(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
            ClientError::Connection("the engine closed the connection before it answered".into())
        }
        CallError::Io(e) => ClientError::Connection(e.to_string()),
        CallError::Protocol(m) => ClientError::Request(m),
        CallError::Remote {
            error,
            reason: message,
        } => {
            let name = error_name(&error);
            match EngineError::status_of_name(name) {
                Some(503) => ClientError::Connection(message),
                Some(status) => ClientError::Api {
                    status,
                    message,
                    condition: Condition::from_name(name),
                },
                None => ClientError::Request(format!("{name}: {message}")),
            }
        }
    }
}

/// How many times a call the engine refused because it restarts is asked
/// again, and how long before each time: the refusal comes before any work,
/// on a connection the engine took before it began to restart; the next
/// connection waits in the queue of the socket for the engine that follows.
const RESTART_RETRIES: u32 = 5;

fn restart_backoff(n: u32) -> std::time::Duration {
    std::time::Duration::from_millis(50 << n.saturating_sub(1).min(5))
}

/// Whether the engine refused the call before doing anything of it, for
/// now (`Unavailable`: it restarts, or has too many connections).
fn restarting(e: &CallError) -> bool {
    matches!(e, CallError::Remote { error, .. } if error_name(error) == "Unavailable")
}

/// How long before a call refused as `Unavailable` is asked again, the
/// `refused`th time.  None at all for a refusal because the engine restarts: the
/// next connection waits in the queue of the socket for the engine that
/// follows, the wait is the engine's.
fn refusal_backoff(e: &CallError, refused: u32) -> std::time::Duration {
    match e {
        CallError::Remote { reason, .. } if reason == velarx_proto::RESTARTING => {
            std::time::Duration::ZERO
        }
        _ => restart_backoff(refused),
    }
}

/// A connection to the engine for the typed proxy.
type Proxy = velarx_proto::zlink::Connection<Blocking>;

/// A call of [`EngineClient::written`], given the read end of its pipe.
type WrittenCall<'a> = dyn FnMut(&mut Proxy, Vec<OwnedFd>) -> Result<(), CallError> + Send + 'a;

/// Whether the engine on `conn` is of this version; if not, what it is.
/// A reply that is not an `InfoReply` is of another version too (one whose
/// `GetInfo` answers other members), asked to start again as the others.
fn check(conn: &mut Proxy) -> ClientResult<Result<(), String>> {
    let info = match ready(conn.get_info()).map_err(client_error)? {
        Err(
            velarx_proto::zlink::Error::Json(_) | velarx_proto::zlink::Error::MissingParameters,
        ) => {
            return Ok(Err("of another version".into()));
        }
        reply => answered(reply).map_err(client_error)?,
    };
    if info.interface != velarx_proto::PROTO
        || info.version != env!("CARGO_PKG_VERSION")
        || info.digest != velarx_proto::DIGEST
    {
        return Ok(Err(info.version));
    }
    Ok(Ok(()))
}

/// A call with its trace points.
fn trace_call<T>(method: &str, call: impl FnOnce() -> T) -> T {
    let tracing = velarx_base::trace::enabled();
    if tracing {
        velarx_base::trace::point(&format!("client request {method}"));
    }
    let reply = call();
    if tracing {
        velarx_base::trace::point(&format!("client response {method}"));
    }
    reply
}

fn pipe() -> ClientResult<(OwnedFd, OwnedFd)> {
    rustix::pipe::pipe_with(rustix::pipe::PipeFlags::CLOEXEC)
        .map_err(|e| ClientError::Request(format!("cannot make a pipe: {e}")))
}

impl EngineClient {
    pub fn new(socket_path: &Path) -> ClientResult<Self> {
        if !socket_path.exists() {
            return Err(ClientError::DaemonNotRunning(socket_path.to_path_buf()));
        }
        Ok(Self {
            endpoint: Endpoint::Path(socket_path.to_path_buf()),
            kept: Default::default(),
        })
    }

    /// The client of the engine service of this process, which takes the
    /// connections sent to `hand`.
    pub fn in_process(
        hand: tokio::sync::mpsc::UnboundedSender<std::os::unix::net::UnixStream>,
    ) -> Self {
        Self {
            endpoint: Endpoint::InProcess(hand),
            kept: Default::default(),
        }
    }

    /// A connection to the engine, of its version.  An engine of another
    /// version is asked to start again from the binary installed (after an
    /// upgrade the old one runs) and connected to again, as the frontends
    /// do (`velarx_proto::connect::connect_checked`).
    fn connect(&self) -> ClientResult<Link> {
        let kept = self
            .kept
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        if let Some(link) = kept.filter(Link::still_open) {
            return Ok(link);
        }
        let mut link = self.open()?;
        // (the engine of the process is of its own version)
        if matches!(self.endpoint, Endpoint::InProcess(_)) {
            return Ok(link);
        }
        let Err(theirs) = check(&mut link.conn)? else {
            return Ok(link);
        };
        let restarted = ask(link.conn.restart(None)).ok().map(|r| r.restarted);
        if restarted != Some(false) {
            drop(link);
            // (the engine starts again with its socket; a connection the
            // old one took ends at once, and is made again)
            for _ in 0..3 {
                let mut link = self.open()?;
                match check(&mut link.conn) {
                    Ok(Ok(())) => return Ok(link),
                    Ok(Err(_)) => break,
                    Err(ClientError::Connection(_) | ClientError::Request(_)) => continue,
                    Err(e) => return Err(e),
                }
            }
        }
        let what = if restarted == Some(false) {
            "the engine runs the binary installed, this one is another"
        } else {
            "restart the engine"
        };
        Err(ClientError::Connection(format!(
            "this is velarx {} and the engine is {theirs}: {what} (the binaries are installed \
             together)",
            env!("CARGO_PKG_VERSION"),
        )))
    }

    /// Keep the connection of a call the engine answered in full for the
    /// next call.
    fn keep(&self, link: Link) {
        *self
            .kept
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(link);
    }

    /// A connection to the engine, not checked: the typed proxy on its
    /// socket.
    fn open(&self) -> ClientResult<Link> {
        self.open_trusting(velarx_base::ipc::trusted_uid)
    }

    /// [`Self::open`], for a server of the users `trusted` accepts (this
    /// user and root, as the frontends of the engine accept it): the path
    /// of the socket may be one another user can listen on.
    fn open_trusting(&self, trusted: fn(u32) -> bool) -> ClientResult<Link> {
        let stream = self
            .endpoint
            .connect()
            .map_err(|e| ClientError::Connection(format!("{}: {e}", self.endpoint)))?;
        velarx_base::ipc::check_client(&stream, trusted).map_err(|e| {
            ClientError::Connection(format!(
                "{}: the engine is served by another user ({e})",
                self.endpoint
            ))
        })?;
        let other = stream.try_clone().map_err(|e| client_error(e.into()))?;
        Ok(Link {
            conn: velarx_proto::zlink::Connection::new(Blocking {
                read: stream,
                write: other,
            }),
        })
    }
}

/// The parameters of a start for `verify`: `verify_image`, `service`, `run`.
fn start_parameters(verify: Verify<'_>) -> (&[String], Option<bool>, Option<bool>) {
    match verify {
        Verify::Option(digests) => (digests, None, None),
        Verify::Run(digests) => (digests, None, Some(true)),
        Verify::Service => (&[], Some(true), None),
    }
}

/// The socket of a connection to the engine for the typed proxy: the stream
/// of a connection that was checked, read and written with blocking calls,
/// so that every future of the proxy is ready when it is first polled
/// ([`ask`]).
#[derive(Debug)]
struct Blocking {
    read: std::os::unix::net::UnixStream,
    write: std::os::unix::net::UnixStream,
}

#[derive(Debug)]
struct BlockingRead(std::os::unix::net::UnixStream);

#[derive(Debug)]
struct BlockingWrite(std::os::unix::net::UnixStream);

impl velarx_proto::zlink::connection::socket::Socket for Blocking {
    type ReadHalf = BlockingRead;
    type WriteHalf = BlockingWrite;

    fn split(self) -> (BlockingRead, BlockingWrite) {
        (BlockingRead(self.read), BlockingWrite(self.write))
    }
}

impl velarx_proto::zlink::connection::socket::ReadHalf for BlockingRead {
    async fn read(
        &mut self,
        buf: &mut [u8],
    ) -> velarx_proto::zlink::Result<velarx_proto::zlink::connection::socket::ReadResult> {
        // (the descriptors of a reply come with its first bytes)
        Ok(velarx_proto::zlink::unix_utils::recvmsg(&self.0, buf)?)
    }
}

impl velarx_proto::zlink::connection::socket::WriteHalf for BlockingWrite {
    async fn write(
        &mut self,
        buf: &[u8],
        fds: &[impl AsFd],
        _credentials: Option<&velarx_proto::zlink::connection::PassedCredentials>,
    ) -> velarx_proto::zlink::Result<()> {
        use rustix::net::{sendmsg, SendAncillaryBuffer, SendAncillaryMessage, SendFlags};
        if fds.is_empty() {
            return Ok(self.0.write_all(buf)?);
        }
        // (the descriptors cross with the first byte of the call)
        let borrowed: Vec<BorrowedFd<'_>> = fds.iter().map(AsFd::as_fd).collect();
        let mut sent = 0;
        while sent < buf.len() {
            // (as many as the kernel takes in a message: an artifact has one
            // for each of its files)
            let mut space = [std::mem::MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(253))];
            let mut control = SendAncillaryBuffer::new(&mut space);
            if sent == 0 && !control.push(SendAncillaryMessage::ScmRights(&borrowed)) {
                return Err(std::io::Error::other("too many descriptors for a call").into());
            }
            match sendmsg(
                &self.0,
                &[std::io::IoSlice::new(&buf[sent..])],
                &mut control,
                SendFlags::NOSIGNAL,
            ) {
                Ok(n) => sent += n,
                Err(rustix::io::Errno::INTR) => {}
                Err(e) => return Err(std::io::Error::from(e).into()),
            }
        }
        Ok(())
    }
}

/// What a future of the typed proxy on a [`Blocking`] socket answers: the
/// futures of the proxy end at their first poll, because the socket does not
/// wait.
fn ready<F: std::future::Future>(call: F) -> Result<F::Output, CallError> {
    let mut call = std::pin::pin!(call);
    let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
    match call.as_mut().poll(&mut cx) {
        std::task::Poll::Ready(reply) => Ok(reply),
        std::task::Poll::Pending => Err(CallError::Protocol("the call did not end".into())),
    }
}

/// The error of a call of the proxy: one of the connection (the engine
/// went before it answered too) or of the protocol.
#[inline(never)]
fn call_error(e: velarx_proto::zlink::Error) -> CallError {
    match e {
        velarx_proto::zlink::Error::Io(e) => CallError::Io(e),
        velarx_proto::zlink::Error::UnexpectedEof => {
            CallError::Io(std::io::ErrorKind::UnexpectedEof.into())
        }
        e => CallError::Protocol(e.to_string()),
    }
}

/// The reply of a call of the typed proxy: the error of the engine is
/// [`CallError::Remote`], one of the connection or of a reply that is not
/// the type of the method (a member missing) is not.  The one place the
/// engine's errors are mapped; [`client_error`] gives them their codes.
fn answered<T>(reply: velarx_proto::zlink::Result<Result<T, EngineError>>) -> Result<T, CallError> {
    match reply {
        Ok(Ok(reply)) => Ok(reply),
        Ok(Err(e)) => Err(engine_error(e)),
        Err(e) => Err(call_error(e)),
    }
}

/// An error of the engine as [`CallError::Remote`] (one copy for every type
/// of reply).
#[inline(never)]
fn engine_error(e: EngineError) -> CallError {
    CallError::Remote {
        error: format!("{INTERFACE}.{}", e.name()),
        reason: e.message().to_string(),
    }
}

/// The answer to a call of the typed proxy.
fn ask<T>(
    call: impl std::future::Future<Output = velarx_proto::zlink::Result<Result<T, EngineError>>>,
) -> Result<T, CallError> {
    answered(ready(call)?)
}

/// [`ask`] of a call whose reply carries descriptors.
fn ask_fds<T>(
    call: impl std::future::Future<
        Output = velarx_proto::zlink::Result<(Result<T, EngineError>, Vec<OwnedFd>)>,
    >,
) -> Result<(T, Vec<OwnedFd>), CallError> {
    let (reply, fds) = ready(call)?.map_err(call_error)?;
    Ok((answered(Ok(reply))?, fds))
}

/// The replies of a call with `more` to `each` as they come, until it
/// returns false (the stream, and the connection with it, is dropped by
/// the caller) or they end.
fn ask_each<S, T>(
    call: impl std::future::Future<Output = velarx_proto::zlink::Result<S>>,
    each: impl FnMut(T) -> bool,
) -> Result<(), CallError>
where
    S: velarx_proto::zlink::futures_util::Stream<
        Item = velarx_proto::zlink::Result<Result<T, EngineError>>,
    >,
{
    let stream = ready(call)?.map_err(call_error)?;
    each_reply(stream, each)
}

/// The replies of a stream of a call with `more`.
fn each_reply<S, T>(stream: S, mut each: impl FnMut(T) -> bool) -> Result<(), CallError>
where
    S: velarx_proto::zlink::futures_util::Stream<
        Item = velarx_proto::zlink::Result<Result<T, EngineError>>,
    >,
{
    use velarx_proto::zlink::futures_util::StreamExt;
    let mut stream = std::pin::pin!(stream);
    while let Some(reply) = ready(stream.next())? {
        if !each(answered(reply)?) {
            break;
        }
    }
    Ok(())
}

/// Write the upload of a call to its pipe once the call is sent: the
/// frames, then the empty one that says it is whole; the error that kept it
/// from being.
fn upload_to(upload: Option<(OwnedFd, Upload<'_>)>) -> Option<std::io::Error> {
    let (pipe, body) = upload?;
    let mut out = FrameWriter {
        pipe: std::fs::File::from(pipe),
    };
    let mut buffered = std::io::BufWriter::with_capacity(256 * 1024, &mut out);
    let written = body(&mut buffered).and_then(|()| buffered.flush());
    drop(buffered);
    match written {
        Ok(()) => out.pipe.write_all(&0u32.to_be_bytes()).err(),
        Err(e) => Some(e),
    }
}

/// The options of a request for the logs of a pod.
fn pod_log_options(
    since: Option<&str>,
    until: Option<&str>,
    tail: Option<u64>,
    containers: &[String],
    follow: bool,
) -> ClientResult<PodLogOptions> {
    use velarx_wire::monitor::logfmt::{now_ns, parse_pod_log_time};
    let now = now_ns();
    let time =
        |what, spec| parse_pod_log_time(what, spec, now).map_err(|m| ClientError::api(400, m));
    Ok(PodLogOptions {
        containers: containers.to_vec(),
        follow,
        tail: tail.map(|t| i64::try_from(t).unwrap_or(i64::MAX)),
        since_ns: time("since", since)?,
        until_ns: time("until", until)?,
    })
}

/// A line of the logs of a pod as the command line has it.
fn pod_log_entry(l: PodLogLine) -> PodLogEntry {
    PodLogEntry {
        container_name: l.container_name,
        container_id: l.container_id,
        container_index: usize::try_from(l.container_index).unwrap_or(0),
        containers: usize::try_from(l.containers).unwrap_or(0),
        timestamp: velarx_wire::monitor::logfmt::format_rfc3339_ns(l.time_ns),
        stream: match l.stream {
            LogStream::Stdout => "stdout",
            LogStream::Stderr => "stderr",
        }
        .to_string(),
        message: l.message,
    }
}

/// What the command of an `ExecStart` with no input writes, its output to
/// `out` and its errors to `err`, each as it comes.  `replies` are those of
/// the session (`velarx_proto::stream`): the descriptors of its streams,
/// which are read to their ends, and the end, once the status of the
/// command is recorded, with what the engine says as errors of the
/// command.  The error of a writer is given back as it is (`Err(Ok(e))`),
/// that of the session and the streams as `Err(Err(e))`.
fn exec_output<S>(
    replies: S,
    out: &mut dyn std::io::Write,
    err: &mut dyn std::io::Write,
) -> Result<Result<(), Result<std::io::Error, std::io::Error>>, CallError>
where
    S: velarx_proto::zlink::futures_util::Stream<
        Item = velarx_proto::zlink::Result<(Result<SessionReply, EngineError>, Vec<OwnedFd>)>,
    >,
{
    use rustix::event::{poll, PollFd, PollFlags};
    use rustix::io::Errno;
    use velarx_proto::engine::SessionPhase;
    use velarx_proto::zlink::futures_util::StreamExt;
    // (a chunk goes to its reader at once)
    let put = |w: &mut dyn std::io::Write, data: &[u8]| -> std::io::Result<()> {
        w.write_all(data)?;
        w.flush()
    };
    let mut replies = std::pin::pin!(replies);
    while let Some(reply) = ready(replies.next())? {
        let (reply, fds) = reply.map_err(call_error)?;
        let reply = answered(Ok(reply))?;
        match reply.phase {
            SessionPhase::Accepted => {}
            SessionPhase::Streams => {
                let streams = reply.streams.unwrap_or_default();
                let mut fds: Vec<Option<OwnedFd>> = fds.into_iter().map(Some).collect();
                // (the descriptor, and whether it is the errors)
                let mut streams: Vec<(OwnedFd, bool)> =
                    [(streams.stdout, false), (streams.stderr, true)]
                        .into_iter()
                        .filter_map(|(at, errors)| {
                            let fd = fds.get_mut(at? as usize)?.take()?;
                            // (the engine's end is non blocking: so is this one,
                            // its description)
                            rustix::fs::fcntl_setfl(&fd, rustix::fs::OFlags::empty()).ok()?;
                            Some((fd, errors))
                        })
                        .collect();
                let mut buf = vec![0u8; 32 * 1024];
                while !streams.is_empty() {
                    let mut ready: Vec<PollFd<'_>> = streams
                        .iter()
                        .map(|(fd, _)| PollFd::new(fd, PollFlags::IN))
                        .collect();
                    match poll(&mut ready, None) {
                        Err(Errno::INTR) => continue,
                        Err(e) => return Ok(Err(Err(e.into()))),
                        Ok(_) => {}
                    }
                    let ready: Vec<bool> = ready.iter().map(|p| !p.revents().is_empty()).collect();
                    let mut ready = ready.into_iter();
                    // (a stream at its end, or that cannot be read, goes)
                    let mut failed = None;
                    streams.retain(|(fd, errors)| {
                        if !ready.next().unwrap_or(false) || failed.is_some() {
                            return true;
                        }
                        match rustix::io::read(fd, &mut buf) {
                            Ok(0) => false,
                            Ok(n) => {
                                let w: &mut dyn std::io::Write =
                                    if *errors { &mut *err } else { &mut *out };
                                if let Err(e) = put(w, &buf[..n]) {
                                    failed = Some(e);
                                }
                                true
                            }
                            Err(Errno::INTR | Errno::AGAIN) => true,
                            Err(_) => false,
                        }
                    });
                    if let Some(e) = failed {
                        return Ok(Err(Ok(e)));
                    }
                }
            }
            SessionPhase::Ended => {
                // what the engine says after the output (the status is
                // recorded)
                if let Some(text) = reply.message {
                    if let Err(e) = put(err, text.as_bytes()) {
                        return Ok(Err(Ok(e)));
                    }
                }
                return Ok(Ok(()));
            }
        }
    }
    Ok(Err(Err(std::io::ErrorKind::UnexpectedEof.into())))
}

/// The descriptor `i` of a reply.
fn take_pipe(fds: &mut Vec<OwnedFd>, i: u32) -> ClientResult<OwnedFd> {
    let i = i as usize;
    if i < fds.len() {
        Ok(fds.remove(i))
    } else {
        Err(ClientError::Request(
            "the engine named a pipe it did not send".into(),
        ))
    }
}

/// A sealed memory file holding `bytes`: what a secret travels in (the
/// credentials of a call, a signing key, the data of a secret).
fn sealed(bytes: &[u8]) -> std::io::Result<OwnedFd> {
    velarx_base::sealed::sealed_memory(bytes)
}

/// The credentials and certificates of a call: [`RegistryAccess::sealed`].
fn sealed_access(access: &RegistryAccess) -> ClientResult<(Option<u32>, Vec<OwnedFd>)> {
    access
        .sealed()
        .map_err(|e| ClientError::Request(format!("the credentials: {e}")))
}

/// The download a reply carries in its first descriptor: the bytes, as
/// they come (a download the engine did not finish is a read error).
fn download(mut pipes: Vec<OwnedFd>) -> ClientResult<Download> {
    let pipe = take_pipe(&mut pipes, 0)?;
    Ok(Box::new(Frames {
        pipe: std::fs::File::from(pipe),
        left: 0,
        done: false,
    }))
}

/// What [`ask_each_fed`] writes to a pipe of its call: the write end and
/// the data.
type Feed<'a> = Option<(OwnedFd, &'a [u8])>;

/// The descriptors of a call that carries `data` in a pipe, and what
/// [`ask_each_fed`] writes to it.
fn piped(data: Option<&[u8]>) -> ClientResult<(Vec<OwnedFd>, Feed<'_>)> {
    let Some(data) = data else {
        return Ok((Vec::new(), None));
    };
    let (read, write) = pipe()?;
    let _ = rustix::pipe::fcntl_setpipe_size(&write, data.len().clamp(4096, 1 << 20));
    Ok((vec![read], Some((write, data))))
}

/// [`ask_each`] of a call that carries a pipe: `feed` is written to it once
/// the call is sent, and the replies are read after (an engine that answered
/// before it read everything says why).
fn ask_each_fed<S, T>(
    call: impl std::future::Future<Output = velarx_proto::zlink::Result<S>>,
    feed: Feed<'_>,
    each: impl FnMut(T) -> bool,
) -> Result<(), CallError>
where
    S: velarx_proto::zlink::futures_util::Stream<
        Item = velarx_proto::zlink::Result<Result<T, EngineError>>,
    >,
{
    let stream = ready(call)?.map_err(call_error)?;
    let written = feed.map(|(pipe, data)| std::fs::File::from(pipe).write_all(data));
    each_reply(stream, each)?;
    match written {
        Some(Err(e)) => Err(CallError::Protocol(e.to_string())),
        _ => Ok(()),
    }
}

/// The filters of a typed call (`--filter KEY=VALUE`s, by key).
fn filters_of(filters: &[String]) -> Vec<Filter> {
    filter_map(filters)
        .into_iter()
        .map(|(key, values)| Filter { key, values })
        .collect()
}

/// The flags of a restore, as `ContainerRestore` takes them.
fn restore_flags(opts: &RestoreOptions) -> velarx_proto::engine::RestoreFlags {
    velarx_proto::engine::RestoreFlags {
        tcp_established: opts.tcp_established,
        tcp_close: opts.tcp_close,
        file_locks: opts.file_locks,
        keep: opts.keep,
        name: opts.name.clone(),
        ignore_rootfs: opts.ignore_rootfs,
        ignore_static_ip: opts.ignore_static_ip,
        ignore_static_mac: opts.ignore_static_mac,
        previous: None,
        pod: opts.pod.clone(),
        publish: opts.publish.clone(),
        print_stats: opts.print_stats,
        verify_image: opts.verify_image.clone(),
    }
}

/// The flags of a checkpoint, as `ContainerCheckpoint` takes them (`export`:
/// an archive is zstd unless asked).
fn checkpoint_flags(opts: &CheckpointOptions, export: bool) -> ClientResult<CheckpointFlags> {
    let compress = match opts.compress.as_deref() {
        None => export.then_some(Compression::Zstd),
        Some(word) => Some(
            Compression::of_word(word)
                .ok_or_else(|| ClientError::api(400, format!("unknown compression `{word}`")))?,
        ),
    };
    Ok(CheckpointFlags {
        leave_running: opts.leave_running,
        create_image: opts.create_image.clone(),
        tcp_established: opts.tcp_established,
        file_locks: opts.file_locks,
        keep: opts.keep,
        ignore_rootfs: opts.ignore_rootfs,
        ignore_volumes: opts.ignore_volumes,
        compress,
        print_stats: opts.print_stats,
        pre_checkpoint: opts.pre_checkpoint,
        with_previous: opts.with_previous,
    })
}

/// podman's report of a restore, of the reply of the engine.
fn restore_report(r: velarx_proto::engine::Restored) -> RestoreReport {
    RestoreReport {
        id: r.id,
        runtime_restore_duration: r.runtime_restore_duration.unwrap_or(0),
        criu_statistics: r.criu_statistics,
    }
}

/// What `PodRun` answers, as the command has it: the errors of the
/// containers of the pod make one error.
fn pod_ran(ran: &velarx_proto::engine::PodRan) -> ClientResult<()> {
    if ran.errors.is_empty() {
        Ok(())
    } else {
        Err(ClientError::api(409, ran.errors.join("; ")))
    }
}

/// A session opened in the engine, for the copy loop of
/// `velarx_proto::stream`.
pub struct Opened {
    pub session: velarx_proto::stream::Session,
    /// Ends the thread that reads the replies when dropped
    pub hangup: Hangup,
}

/// The connection of a session, shut down when dropped: the thread that reads
/// its replies is waiting on it.
pub struct Hangup(Option<OwnedFd>);

impl Drop for Hangup {
    fn drop(&mut self) {
        if let Some(fd) = &self.0 {
            let _ = rustix::net::shutdown(fd, rustix::net::Shutdown::Both);
        }
    }
}

/// The replies of a call that opens a session, read by a thread of its own
/// (the copy loop is asynchronous, the connection is a blocking one): the
/// first to `first`, the others to `tx`, until the last, an error or the end
/// of the connection.  `sent`: whether the first was.
fn pump<S>(
    stream: S,
    first: &std::sync::mpsc::Sender<ClientResult<velarx_proto::stream::Item>>,
    sent: &std::cell::Cell<bool>,
    tx: &tokio::sync::mpsc::Sender<velarx_proto::stream::Item>,
) -> Result<(), CallError>
where
    S: velarx_proto::zlink::futures_util::Stream<
        Item = velarx_proto::zlink::Result<(
            Result<velarx_proto::engine::SessionReply, EngineError>,
            Vec<OwnedFd>,
        )>,
    >,
{
    use velarx_proto::engine::SessionPhase;
    use velarx_proto::zlink::futures_util::StreamExt;
    let mut stream = std::pin::pin!(stream);
    while let Some(reply) = ready(stream.next())? {
        let (reply, fds) = reply.map_err(call_error)?;
        let reply = answered(Ok(reply))?;
        let last = reply.phase == SessionPhase::Ended;
        if !sent.replace(true) {
            if first.send(Ok((reply, fds))).is_err() {
                return Ok(());
            }
        } else if tx.blocking_send((reply, fds)).is_err() {
            return Ok(());
        }
        if last {
            break;
        }
    }
    Ok(())
}

/// A call that opens a session (`$call` on the connection `$conn`): the
/// connection and its replies go to a thread, and the session of the first
/// reply is the result.
macro_rules! open_session {
    ($client:expr, $method:literal, |$conn:ident| $call:expr) => {{
        let (first_tx, first_rx) = std::sync::mpsc::channel();
        let (hangup_tx, hangup_rx) = std::sync::mpsc::channel();
        let (tx, replies) = velarx_proto::stream::replies_channel();
        let client = $client.clone();
        std::thread::Builder::new()
            .name("session".into())
            .spawn(move || {
                let sent = std::cell::Cell::new(false);
                let done = client.typed_once($method, |$conn| {
                    if let Ok(fd) = $conn.read().read_half().0.as_fd().try_clone_to_owned() {
                        let _ = hangup_tx.send(fd);
                    }
                    let stream = ready($call)?.map_err(call_error)?;
                    pump(stream, &first_tx, &sent, &tx)
                });
                if let (Err(e), false) = (done, sent.get()) {
                    let _ = first_tx.send(Err(e));
                }
            })
            .map_err(|e| ClientError::Connection(e.to_string()))?;
        $client.opened(first_rx, hangup_rx, replies)
    }};
}

/// The calls of `org.velarx.Engine`, their parameters as the interface
/// names them.
impl EngineClient {
    /// A call by the typed proxy of the engine, made again when the engine
    /// refused it because it restarts, with its trace points; `call` makes
    /// it with [`ask`].
    fn typed<T>(
        &self,
        method: &str,
        mut call: impl FnMut(&mut Proxy) -> Result<T, CallError>,
    ) -> ClientResult<T> {
        let mut reply = None;
        self.made(method, true, &mut |conn| {
            call(conn).map(|r| reply = Some(r))
        })?;
        Ok(reply.expect("a call that succeeded has its reply"))
    }

    /// [`Self::typed`] of a call made once: one that carries descriptors it
    /// owns, or whose replies are read as they come ([`ask_each`]).
    fn typed_once<T>(
        &self,
        method: &str,
        call: impl FnOnce(&mut Proxy) -> Result<T, CallError>,
    ) -> ClientResult<T> {
        let (mut call, mut reply) = (Some(call), None);
        self.made(method, false, &mut |conn| {
            let call = call.take().expect("a call made once");
            call(conn).map(|r| reply = Some(r))
        })?;
        Ok(reply.expect("a call that succeeded has its reply"))
    }

    /// What [`Self::typed`] and [`Self::typed_once`] do whatever the type of
    /// the reply (one copy of it for every call): connect, make the call
    /// (`again`: again while the engine refuses it because it restarts) and
    /// map its error.
    #[inline(never)]
    fn made(
        &self,
        method: &str,
        again: bool,
        call: &mut dyn FnMut(&mut Proxy) -> Result<(), CallError>,
    ) -> ClientResult<()> {
        trace_call(method, || {
            let mut refused = 0;
            loop {
                let mut link = self.connect()?;
                match call(&mut link.conn) {
                    Err(e) if again && refused < RESTART_RETRIES && restarting(&e) => {
                        refused += 1;
                        std::thread::sleep(refusal_backoff(&e, refused));
                    }
                    reply => {
                        // (a call made again is a plain call, its reply one
                        // message: the connection is free once it came; a
                        // call made once may be a stream or carry descriptors)
                        if again && matches!(reply, Ok(()) | Err(CallError::Remote { .. })) {
                            self.keep(link);
                        }
                        return reply.map_err(client_error);
                    }
                }
            }
        })
    }

    /// [`Self::typed`] for a call that carries an upload: the read end of a
    /// pipe among its descriptors (`call` is given it), the upload written to
    /// the other meanwhile; an engine that answered before it read
    /// everything says why.  Made once: the upload cannot be sent again.
    fn typed_upload<T: Send>(
        &self,
        method: &str,
        body: Upload<'_>,
        call: impl FnOnce(&mut Proxy, Vec<OwnedFd>) -> Result<T, CallError> + Send,
    ) -> ClientResult<T> {
        self.typed_written(method, |pipe| upload_to(Some((pipe, body))), call)
    }

    /// [`Self::typed_upload`] of `data`, written to the pipe as it is (the
    /// call says its length).
    fn typed_data<T: Send>(
        &self,
        method: &str,
        data: &[u8],
        call: impl FnOnce(&mut Proxy, Vec<OwnedFd>) -> Result<T, CallError> + Send,
    ) -> ClientResult<T> {
        self.typed_written(
            method,
            |pipe| std::fs::File::from(pipe).write_all(data).err(),
            call,
        )
    }

    /// A call that carries the credentials and certificates `access` as
    /// the JSON of a sealed memory file, none when there are none: `call`
    /// is given the position of the file and the descriptors.
    fn typed_access<T: Send>(
        &self,
        method: &str,
        access: &RegistryAccess,
        call: impl Fn(&mut Proxy, Option<u32>, Vec<OwnedFd>) -> Result<T, CallError> + Send + Sync,
    ) -> ClientResult<T> {
        self.typed(method, |conn| {
            let (at, fds) = access
                .sealed()
                .map_err(|e| CallError::Protocol(e.to_string()))?;
            call(conn, at, fds)
        })
    }

    fn typed_written<T: Send>(
        &self,
        method: &str,
        write: impl FnOnce(OwnedFd) -> Option<std::io::Error>,
        call: impl FnOnce(&mut Proxy, Vec<OwnedFd>) -> Result<T, CallError> + Send,
    ) -> ClientResult<T> {
        let (mut write, mut call, mut reply) = (Some(write), Some(call), None);
        self.written(
            method,
            &mut |pipe| write.take().and_then(|write| write(pipe)),
            &mut |conn, pipes| {
                let call = call.take().expect("a call made once");
                call(conn, pipes).map(|r| reply = Some(r))
            },
        )?;
        Ok(reply.expect("a call that succeeded has its reply"))
    }

    /// What [`Self::typed_written`] does whatever the type of the reply.
    #[inline(never)]
    fn written(
        &self,
        method: &str,
        write: &mut dyn FnMut(OwnedFd) -> Option<std::io::Error>,
        call: &mut WrittenCall<'_>,
    ) -> ClientResult<()> {
        trace_call(method, || {
            let (read, write_end) = pipe()?;
            let Link { mut conn, .. } = self.connect()?;
            // (the proxy sends the call and reads its reply in one go: it is
            // made on a thread of its own while the pipe is written; the
            // read end goes with the call and is closed once it is sent, so
            // the writing ends when the engine stops reading)
            let (reply, failed) = std::thread::scope(|s| {
                let call = s.spawn(move || call(&mut conn, vec![read]));
                let failed = write(write_end);
                (call.join(), failed)
            });
            let reply = reply.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
            match (reply, failed) {
                (Ok(()), None) => Ok(()),
                // (an engine that answered before it read everything says
                // why, one that went is gone)
                (Err(e @ (CallError::Remote { .. } | CallError::Io(_))), Some(_)) => {
                    Err(client_error(e))
                }
                (_, Some(e)) => Err(ClientError::Request(e.to_string())),
                (Err(e), None) => Err(client_error(e)),
            }
        })
    }

    /// The pull or the push of an artifact: its digest, and with a push how
    /// the destination resolves it.  The access crosses as JSON in a sealed
    /// memory file.
    fn artifact_transfer(&self, push: bool, req: &ArtifactTransfer) -> ClientResult<PushedImage> {
        let (name, tls_verify) = (&req.name, req.tls_verify);
        let retry = req.retry;
        if push {
            let spec = PushSpec {
                images: vec![name.to_string()],
                artifact: true,
                tls_verify,
                retry,
                ..Default::default()
            };
            return self.push_spec(spec, &req.access, None, None, &mut |_| {});
        }
        let spec = PullSpec {
            source: name.to_string(),
            artifact: true,
            tls_verify,
            retry,
            ..Default::default()
        };
        let moved = self.typed_access("ImagePull", &req.access, |conn, access, fds| {
            ask(conn.image_pull(spec.clone(), access, fds))
        })?;
        Ok(PushedImage {
            digest: moved.id.unwrap_or_default(),
            ..Default::default()
        })
    }

    /// Answer the question of a build for credentials.
    fn answer_build(
        &self,
        ask_id: &str,
        answer: &std::collections::BTreeMap<String, velarx_registry::Credentials>,
    ) -> ClientResult<()> {
        let body = zeroize::Zeroizing::new(serde_json::to_vec(answer)?);
        self.typed("ImageBuildAnswer", |conn| {
            let file = sealed(&body).map_err(|e| CallError::Protocol(e.to_string()))?;
            ask(conn.image_build_answer(ask_id, 0, vec![file]))
        })
        .map(|_| ())
    }
}

impl EngineClient {
    /// Pull `reference` (with `lazy` only its metadata), the progress of
    /// its blobs told to `on`: what was pulled.
    fn pull_request(
        &self,
        reference: &str,
        lazy: bool,
        ask: &PullOptions<'_>,
        mut on: Option<Progress>,
    ) -> ClientResult<PullResponse> {
        let spec = PullSpec {
            source: reference.to_string(),
            platform: PlatformSpec {
                platform: ask.platform.map(str::to_string),
                ..Default::default()
            },
            tls_verify: ask.tls_verify,
            retry: ask.retry,
            lazy,
            sources: ask.sources.map(<[String]>::to_vec),
            ..Default::default()
        };
        let (access, fds) = sealed_access(ask.access)?;
        let mut done = None;
        self.typed_once("ImagePull", |conn| {
            ask_each(
                conn.image_pull_progress(spec, access, fds),
                |pulled: Pulled| {
                    if let (Some(on), Some(progress)) = (on.as_mut(), &pulled.progress) {
                        on(progress);
                    }
                    if let Some(id) = pulled.id {
                        done = Some(PullResponse {
                            id,
                            stats: pulled.stats,
                        });
                    }
                    true
                },
            )
        })?;
        done.ok_or_else(|| ClientError::Request("the engine pulled no image".into()))
    }

    /// Push `image` (`all_tags`: every tag of its repository), the progress
    /// of its blobs told to `on`: what was pushed.
    fn push_request(
        &self,
        image: &str,
        request: &PushImageRequest,
        all_tags: bool,
        on: Progress,
    ) -> ClientResult<PushedImage> {
        let compression =
            match request.compression_format.as_deref() {
                None | Some("") | Some("keep") => None,
                Some(word) => Some(LayerCompression::of_word(word).ok_or_else(|| {
                    ClientError::api(400, format!("invalid compression `{word}`"))
                })?),
            };
        let spec = PushSpec {
            images: vec![image.to_string()],
            destination: request.destination.clone(),
            all: true,
            all_tags,
            tls_verify: request.tls_verify,
            retry: request.retry,
            compression,
            compression_level: request.compression_level,
            sinks: request.sinks.clone(),
            ..Default::default()
        };
        self.push_spec(
            spec,
            &request.access,
            request.sign.as_ref(),
            request.destination_fd.as_deref(),
            on,
        )
    }

    /// One `ImagePush` of `spec`: the credentials, the signing key and the
    /// destination the client opened go as descriptors; the progress told to
    /// `on`; what was pushed.
    fn push_spec(
        &self,
        mut spec: PushSpec,
        access: &RegistryAccess,
        sign: Option<&velarx_proto::workload::SigningKey>,
        destination: Option<&OwnedFd>,
        on: Progress,
    ) -> ClientResult<PushedImage> {
        let (access, mut fds) = sealed_access(access)?;
        // (the credentials, when there are any, are the first descriptor)
        if let Some(fd) = destination {
            fds.push(
                fd.try_clone()
                    .map_err(|e| ClientError::Request(e.to_string()))?,
            );
            spec.destination_fd = Some((fds.len() - 1) as u32);
        }
        if let Some(key) = sign {
            let data = zeroize::Zeroizing::new(serde_json::to_vec(key)?);
            fds.push(
                sealed(&data).map_err(|e| ClientError::Request(format!("the signing key: {e}")))?,
            );
            spec.signing = Some((fds.len() - 1) as u32);
        }
        let mut pushed = None;
        self.typed_once("ImagePush", |conn| {
            ask_each(
                conn.image_push_progress(spec, access, fds),
                |reply: Pushed| {
                    if let Some(progress) = &reply.progress {
                        on(progress);
                    }
                    pushed = reply.pushed.or(pushed.take());
                    true
                },
            )
        })?;
        pushed.ok_or_else(|| ClientError::Request("the engine pushed nothing".into()))
    }

    /// The health of the engine and of its parts.
    pub fn health(&self) -> ClientResult<velarx_proto::system::HealthReport> {
        self.typed("Health", |conn| ask(conn.health()))
    }

    /// Start the engine again from the binary that runs (its configuration
    /// read again).
    pub fn restart_server(&self) -> ClientResult<()> {
        self.typed("Restart", |conn| ask(conn.restart(Some(true))))
            .map(|_| ())
    }

    /// Follow the events `filters` select (after those since `since_ns`,
    /// until `until_ns`) as they happen; `each` is called for every event
    /// until it returns false or the stream ends.
    pub fn follow_events(
        &self,
        filters: &[String],
        since_ns: Option<i64>,
        until_ns: Option<i64>,
        each: &mut dyn FnMut(velarx_proto::workload::Event) -> bool,
    ) -> ClientResult<()> {
        self.typed_once("EventList", |conn| {
            ask_each(
                conn.event_list(filters_of(filters), since_ns, until_ns, true),
                |listed: EventListed| listed.event.is_none_or(&mut *each),
            )
        })
    }
}

impl EngineClient {
    /// The changes of a container (`diff_type` `container`) or of an image
    /// (`image`) to the files.
    fn changes(&self, id: &str, diff_type: DiffType) -> ClientResult<Vec<FileChange>> {
        let diff = self.typed("ContainerDiff", |conn| {
            ask(conn.container_diff(id, Some(diff_type), None))
        })?;
        Ok(diff
            .changes
            .into_iter()
            .map(|c| FileChange {
                path: c.path,
                kind: match c.kind {
                    ChangeKind::Modified => 0,
                    ChangeKind::Added => 1,
                    ChangeKind::Deleted => 2,
                },
            })
            .collect())
    }

    /// The artifacts of the store.
    fn artifacts(&self) -> ClientResult<Vec<ArtifactRecord>> {
        let mut all = Vec::new();
        self.typed_once("ArtifactList", |conn| {
            ask_each(conn.artifact_list(), |listed: ArtifactListed| {
                all.extend(listed.artifact);
                true
            })
        })?;
        Ok(all)
    }

    /// A container, `size` with its sizes.
    fn inspected_container(&self, id: &str, size: bool) -> ClientResult<ContainerRecord> {
        let inspected = self.typed("ContainerInspect", |conn| {
            ask(conn.container_inspect(id, size))
        })?;
        Ok(inspected.container)
    }
}

impl EngineClient {
    // Image operations
    pub fn pull_image(&self, reference: &str, ask: &PullOptions<'_>) -> ClientResult<PullResponse> {
        self.pull_request(reference, false, ask, None)
    }

    /// The digest of the manifest the registry has for `reference` (of
    /// `platform`, else the engine's, for a manifest list) and the one of
    /// the image in the store, if any.
    pub fn remote_digest(
        &self,
        reference: &str,
        tls_verify: bool,
        platform: Option<&str>,
        access: &RegistryAccess,
    ) -> ClientResult<RemoteDigest> {
        let digested = self.typed_access("RegistryDigest", access, |conn, access, fds| {
            ask(conn.registry_digest(reference, tls_verify, platform, access, fds))
        })?;
        let remote = digested.digest;
        let local = match self.inspect_image(reference) {
            Ok(image) => Some(image.digest),
            Err(e) if e.is_not_found() => None,
            Err(e) => return Err(e),
        };
        Ok(RemoteDigest { remote, local })
    }

    /// Pull image lazily - download metadata only, fetch files on-demand
    pub fn pull_image_lazy(
        &self,
        reference: &str,
        ask: &PullOptions<'_>,
    ) -> ClientResult<PullResponse> {
        self.pull_request(reference, true, ask, None)
    }

    /// Pull, telling the progress as it goes.
    pub fn pull_image_progress(
        &self,
        reference: &str,
        ask: &PullOptions<'_>,
        on: Progress,
    ) -> ClientResult<PullResponse> {
        self.pull_request(reference, false, ask, Some(on))
    }

    /// The images and the manifest lists `filters` (podman's, `KEY=VALUE`)
    /// select, the oldest first; the intermediate ones of the builds with
    /// `all`.
    pub fn list_images(&self, all: bool, filters: &[String]) -> ClientResult<Vec<ImageRecord>> {
        let mut images = Vec::new();
        self.typed_once("ImageList", |conn| {
            ask_each(
                conn.image_list(filters_of(filters), all, true),
                |listed: ImageListed| {
                    images.extend(listed.image);
                    true
                },
            )
        })?;
        Ok(images)
    }

    pub fn inspect_image(&self, id: &str) -> ClientResult<ImageRecord> {
        let inspected = self.typed("ImageInspect", |conn| ask(conn.image_inspect(id)))?;
        Ok(inspected.image)
    }

    /// What the top layer of an image changes.
    pub fn image_changes(&self, id: &str) -> ClientResult<Vec<FileChange>> {
        self.changes(id, DiffType::Image)
    }

    pub fn container_changes(&self, id: &str) -> ClientResult<Vec<FileChange>> {
        self.changes(id, DiffType::Container)
    }

    /// Remove an image, or the name `id` of an image that has others (by
    /// ID, one of several names is refused unless `force`).
    pub fn remove_image(&self, id: &str, force: bool) -> ClientResult<ImageRemoved> {
        self.typed("ImageRemove", |conn| {
            ask(conn.image_remove(id, force, false, false, false, false))
        })
    }

    /// Remove every image and manifest list (`rmi --all`), libpod's report.
    pub fn remove_all_images(&self, force: bool, ignore: bool) -> ClientResult<ImagesRemoved> {
        self.typed("ImageRemoveMany", |conn| {
            ask(conn.image_remove_many(Vec::new(), force, ignore, false, true, false))
        })
    }

    /// Remove `names` of the image (all of them if empty).
    pub fn untag_image(&self, id: &str, names: &[String]) -> ClientResult<()> {
        self.typed("ImageUntag", |conn| {
            ask(conn.image_untag(id, names.to_vec()))
        })
        .map(|_| ())
    }

    /// Give the image the name `target` (one without a registry is
    /// localhost's, without a tag `latest`).
    pub fn tag_image(&self, id: &str, target: &str) -> ClientResult<()> {
        let (repo, tag) = split_tag(target);
        self.typed("ImageTag", |conn| ask(conn.image_tag(id, repo, tag, false)))
            .map(|_| ())
    }

    pub fn push_image(
        &self,
        image: &str,
        request: &PushImageRequest,
        on: Progress,
    ) -> ClientResult<PushedImage> {
        self.push_request(image, request, false, on)
    }

    /// Where the credentials of the completion of `image` go
    /// (`registry/repository`): the endpoints of its layers that were pulled
    /// with credentials.
    pub fn credential_scopes(&self, image: &str) -> ClientResult<Vec<String>> {
        let scopes = self.typed("ImageCredentialScopes", |conn| {
            ask(conn.image_credential_scopes(image))
        })?;
        Ok(scopes.scopes)
    }

    /// Where the credentials of a pull (`push` false: the mirrors and the
    /// registry) or a push (the registry alone) of `reference` go
    /// (`registry/repository`): the daemon reads the registries
    /// configuration, the client does not.
    pub fn reference_credential_scopes(
        &self,
        reference: &str,
        push: bool,
    ) -> ClientResult<Vec<String>> {
        let scopes = self.typed("RegistryCredentialScopes", |conn| {
            ask(conn.registry_credential_scopes(reference, push))
        })?;
        Ok(scopes.scopes)
    }

    /// The pulls in progress (`images` lists only complete images).
    pub fn image_pulls(&self) -> ClientResult<Vec<velarx_proto::workload::PullListed>> {
        let listed = self.typed("ImagePulls", |conn| ask(conn.image_pulls()))?;
        Ok(listed.pulls)
    }

    /// Fetch what a lazily pulled image lacks and prove its layers.
    /// `access`: the credentials and certificates the layers that were
    /// pulled with such need again.
    pub fn complete_image(
        &self,
        image: &str,
        access: &RegistryAccess,
    ) -> ClientResult<TransferStats> {
        let completed = self.typed_access("ImageComplete", access, |conn, access, fds| {
            ask(conn.image_complete(image, access, fds))
        })?;
        Ok(completed.stats)
    }

    /// Write `images` as an archive (`docker-archive`, refused, `oci-archive`
    /// or `oci-dir`) to `destination`, a file or pipe, or the directory of an
    /// `oci-dir`, which the client opened: a push to it, each image with its
    /// names.
    pub fn save_images(
        &self,
        images: &[String],
        format: &str,
        destination: &std::os::fd::OwnedFd,
    ) -> ClientResult<()> {
        velarx_base::docker::refuse_format_name(format).map_err(|m| ClientError::api(501, m))?;
        let location = match format {
            "oci-dir" => "oci:save",
            _ => "oci-archive:save",
        };
        let spec = PushSpec {
            images: images.to_vec(),
            destination: Some(location.to_string()),
            ..Default::default()
        };
        self.push_spec(
            spec,
            &RegistryAccess::default(),
            None,
            Some(destination),
            &mut |_| {},
        )
        .map(|_| ())
    }

    /// Pull what `source` names (`oci:DIR`, `oci-archive:FILE`,
    /// `docker-archive:FILE`, `dir:DIR` or `archive:FILE`, a load) from
    /// `target`, the file or the directory the command opened: the images
    /// it put in the store, with their names; the progress of their layers
    /// told to `on`.
    pub fn pull_path(
        &self,
        source: &str,
        target: std::os::fd::OwnedFd,
        platform: Option<&str>,
        mut on: Option<Progress>,
    ) -> ClientResult<Vec<PulledImage>> {
        let spec = PullSpec {
            source: source.to_string(),
            source_fd: Some(0),
            platform: PlatformSpec {
                platform: platform.map(str::to_string),
                ..Default::default()
            },
            tls_verify: true,
            ..Default::default()
        };
        let mut done = None;
        let mut target = Some(target);
        self.typed_once("ImagePull", |conn| {
            ask_each(
                conn.image_pull_progress(spec.clone(), None, target.take().into_iter().collect()),
                |pulled: Pulled| {
                    if let (Some(on), Some(progress)) = (on.as_mut(), &pulled.progress) {
                        on(progress);
                    }
                    if let Some(images) = pulled.images {
                        done = Some(images);
                    }
                    true
                },
            )
        })?;
        done.ok_or_else(|| ClientError::Request("the engine pulled no image".into()))
    }

    /// [`EngineClient::pull_path`] for an upload: the frames of a stream the
    /// engine spools to a file before it reads it (what is no tar archive is
    /// refused at its first block).
    pub fn pull_upload(
        &self,
        source: &str,
        platform: Option<&str>,
        body: Upload,
    ) -> ClientResult<Vec<PulledImage>> {
        let spec = PullSpec {
            source: source.to_string(),
            source_fd: Some(0),
            platform: PlatformSpec {
                platform: platform.map(str::to_string),
                ..Default::default()
            },
            tls_verify: true,
            ..Default::default()
        };
        let pulled = self.typed_upload("ImagePull", body, |conn, fds| {
            ask(conn.image_pull(spec.clone(), None, fds))
        })?;
        pulled
            .images
            .ok_or_else(|| ClientError::Request("the engine pulled no image".into()))
    }

    /// An image of the root file system tar `body` writes, for `platform`
    /// (OS/ARCH[/VARIANT], by default this host's): its ID.
    pub fn import_image(
        &self,
        name: Option<&str>,
        changes: &[String],
        message: Option<&str>,
        platform: Option<&str>,
        digest: Option<&str>,
        body: Upload,
    ) -> ClientResult<String> {
        let spec = ImportSpec {
            digest: digest.map(str::to_string),
            changes: changes.to_vec(),
            message: message.map(str::to_string),
            platform: PlatformSpec {
                platform: platform.map(str::to_string),
                ..Default::default()
            },
            reference: name.map(str::to_string),
            ..Default::default()
        };
        let imported = self.typed_upload("ImageImport", body, |conn, archive| {
            ask(conn.image_import(spec, archive))
        })?;
        Ok(imported.id)
    }

    /// `push --all-tags`: the tags and digests pushed.
    pub fn push_image_all_tags(
        &self,
        image: &str,
        request: &PushImageRequest,
        on: Progress,
    ) -> ClientResult<Vec<(String, String)>> {
        let pushed = self.push_request(image, request, true, on)?;
        Ok(pushed.tags.into_iter().map(|t| (t.tag, t.digest)).collect())
    }

    /// The changes of a container as a new image, the progress of its
    /// layer told to `on`: the ID of the image.
    pub fn commit_container(
        &self,
        req: &CommitContainerRequest,
        on: Progress,
    ) -> ClientResult<String> {
        let (repo, tag) = match req.image.as_deref().filter(|i| !i.is_empty()) {
            Some(name) => {
                let (repo, tag) = split_tag(name);
                (Some(repo.to_string()), Some(tag.to_string()))
            }
            None => (None, None),
        };
        let spec = CommitSpec {
            container: req.container.clone(),
            repo,
            tag,
            author: req.author.clone(),
            comment: req.message.clone(),
            changes: req.changes.clone(),
            pause: req.pause,
            include_volumes: req.include_volumes,
            squash: req.squash,
            digest: req.digest.clone(),
            ..Default::default()
        };
        let config = req
            .override_config
            .as_ref()
            .map(serde_json::to_vec)
            .transpose()?;
        let (fds, feed) = piped(config.as_deref())?;
        let mut id = None;
        self.typed_once("ContainerCommit", |conn| {
            ask_each_fed(
                conn.container_commit_progress(spec, config.as_ref().map(|_| 0), fds),
                feed,
                |committed: Committed| {
                    if let Some(progress) = &committed.progress {
                        on(progress);
                    }
                    id = committed.id.or(id.take());
                    true
                },
            )
        })?;
        id.ok_or_else(|| ClientError::Request("the engine committed no image".into()))
    }

    /// Remove the unused images (all, else the dangling ones) `filters`
    /// (`KEY=VALUE`) select: what was removed.
    pub fn prune_images(&self, all: bool, filters: &[String]) -> ClientResult<Vec<PrunedImage>> {
        let mut pruned = Vec::new();
        self.typed_once("ImagePrune", |conn| {
            ask_each(
                conn.image_prune(all, filters_of(filters)),
                |listed: ImagePruneListed| {
                    pruned.extend(listed.image);
                    true
                },
            )
        })?;
        Ok(pruned)
    }

    /// Remove the directories of RUN --mount=type=cache no build uses: the
    /// bytes they took.
    pub fn prune_build_cache(&self) -> ClientResult<u64> {
        let reclaimed = self.typed("BuildCachePrune", |conn| ask(conn.build_cache_prune()))?;
        Ok(reclaimed.space)
    }

    /// Build the context `context` writes (a tar): the ID of the image.
    /// `auth` is the auth file of the command: the build asks for the
    /// entries of the endpoints of each reference it pulls, and only those
    /// leave the client.  `agents`: the sockets of the ssh agents of
    /// `req.ssh`, in its order: each connection of a RUN step to one is a
    /// new connection of the client.
    pub fn build_image(
        &self,
        req: &BuildImageRequest,
        context: Upload,
        auth: Option<&velarx_registry::AuthConfig>,
        agents: &[std::path::PathBuf],
        on: &mut dyn FnMut(BuildEvent),
    ) -> ClientResult<String> {
        let mut req = req.clone();
        req.ask_credentials = auth.is_some();
        if let Some(p) = req.pull.as_deref().filter(|p| !p.is_empty()) {
            if velarx_proto::buildspec::BuildPull::parse(p).is_none() {
                return Err(ClientError::api(400, format!("invalid pull policy `{p}`")));
            }
        }
        // the engine asks for each connection to an agent through the
        // broker; the thread ends when the engine closes its end
        let mut own: Vec<OwnedFd> = Vec::new();
        if !agents.is_empty() {
            let (engine_end, ours) = std::os::unix::net::UnixStream::pair()
                .map_err(|e| ClientError::Request(format!("the agent broker: {e}")))?;
            let agents = agents.to_vec();
            std::thread::Builder::new()
                .name("ssh-broker".into())
                .spawn(move || velarx_wire::buildopts::serve_broker(ours, &agents))
                .map_err(|e| ClientError::Request(format!("the agent broker: {e}")))?;
            own.push(OwnedFd::from(engine_end));
        }
        // the pipes of the call: the spec, the credentials, the context, the
        // broker of the agents
        let spec = serde_json::to_vec(&req.to_spec())?;
        let (spec_read, spec_write) = pipe()?;
        let mut before = vec![spec_read];
        let writers = vec![std::thread::spawn({
            let spec = spec.clone();
            move || std::fs::File::from(spec_write).write_all(&spec)
        })];
        // (the credentials: a sealed memory file, the second descriptor)
        let (access, credentials) = sealed_access(&req.access)?;
        let access = access.map(|_| 1);
        before.extend(credentials);
        // (the context is the next one; then the broker and the standard input)
        let mut after = own;
        // (the descriptor itself: the engine reads it)
        if req.stdin {
            after.push(
                rustix::io::dup(rustix::stdio::stdin())
                    .map_err(|e| ClientError::Request(format!("the standard input: {e}")))?,
            );
        }
        let sent = self.typed_upload("ImageBuild", context, |conn, context| {
            let mut pipes = before;
            // (the spec is the first descriptor, the credentials the second
            // when there are any, the context the next)
            let at = pipes.len() as u32;
            pipes.extend(context);
            pipes.extend(after);
            ask_fds(conn.image_build(0, Some(at), false, access, pipes))
        });
        for w in writers {
            let _ = w.join();
        }
        let (_, mut pipes) = sent?;
        let events = std::fs::File::from(take_pipe(&mut pipes, 0)?);
        let mut image_id = None;
        for line in std::io::BufReader::new(events).lines() {
            let line = line.map_err(|e| ClientError::Request(e.to_string()))?;
            let event: BuildEventRecord = serde_json::from_str(&line)?;
            match event.kind {
                BuildEventKind::Credentials => {
                    let answer = match auth {
                        Some(a) => a.export_for(&event.scopes).map_err(|e| {
                            ClientError::Request(format!("the credentials of the build: {e}"))
                        })?,
                        None => Default::default(),
                    };
                    self.answer_build(&event.ask, &answer)?;
                }
                BuildEventKind::Progress => {
                    if let Some(p) = event.progress {
                        on(BuildEvent::Progress(p));
                    }
                }
                BuildEventKind::Step => on(BuildEvent::Step(event.text)),
                BuildEventKind::Platform => on(BuildEvent::Platform(event.text)),
                BuildEventKind::Output => {
                    let output = event.text;
                    on(match event.stream {
                        BuildStream::Stdout => BuildEvent::Run {
                            stderr: false,
                            output,
                        },
                        BuildStream::Stderr => BuildEvent::Run {
                            stderr: true,
                            output,
                        },
                        BuildStream::Report => BuildEvent::Report(output),
                        BuildStream::Step => BuildEvent::Output(output),
                    });
                }
                BuildEventKind::Complete => image_id = Some(event.text),
                BuildEventKind::Error => return Err(ClientError::api(500, event.text)),
                BuildEventKind::Started => {}
            }
        }
        image_id.ok_or_else(|| ClientError::Request("the build ended without an image".into()))
    }

    // Container operations
    pub fn create_container(&self, req: &CreateContainerRequest) -> ClientResult<IdResponse> {
        let body = serde_json::to_vec(req)?;
        let made = self.typed_data("ContainerCreate", &body, |conn, request| {
            ask(conn.container_create(0, request))
        })?;
        Ok(IdResponse { id: made.id })
    }

    /// The containers `filters` (podman's, `KEY=VALUE`) select, the newest
    /// first: those that run, all with `all`; with `size` the size of their
    /// changes, with `namespace` the namespaces of their processes.
    pub fn list_containers(
        &self,
        all: bool,
        filters: &[String],
        size: bool,
        namespace: bool,
    ) -> ClientResult<Vec<ContainerRecord>> {
        let mut containers = Vec::new();
        self.typed_once("ContainerList", |conn| {
            ask_each(
                conn.container_list(filters_of(filters), all, size, namespace, -1),
                |listed: ContainerListed| {
                    containers.extend(listed.container);
                    true
                },
            )
        })?;
        Ok(containers)
    }

    pub fn inspect_container(&self, id: &str) -> ClientResult<ContainerRecord> {
        self.inspected_container(id, false)
    }

    /// The same with the sizes of its files (`size_rw`, `size_root_fs`).
    pub fn inspect_container_sized(&self, id: &str) -> ClientResult<ContainerRecord> {
        self.inspected_container(id, true)
    }

    /// Start a container; `verify`: the digests (`sha256:...`) typed on the
    /// command, which an enforced start holds the images of the container to.
    pub fn start_container(&self, id: &str, verify: Verify<'_>) -> ClientResult<()> {
        let (verify_image, service, run) = start_parameters(verify);
        self.typed("ContainerStart", |conn| {
            ask(conn.container_start(id, verify_image.to_vec(), service, run))
        })
        .map(|_| ())
    }

    pub fn start_container_attached(
        &self,
        id: &str,
        verify: Verify<'_>,
    ) -> ClientResult<StartedContainer> {
        let (verify_image, service, run) = start_parameters(verify);
        let started = self.typed("ContainerStartAttached", |conn| {
            ask(conn.container_start_attached(id, verify_image.to_vec(), service, run))
        })?;
        Ok(StartedContainer { id: started.id })
    }

    /// Ask the monitor of a container to open its log file again.
    pub fn reopen_container_log(&self, id: &str) -> ClientResult<()> {
        self.typed("ContainerLogReopen", |conn| {
            ask(conn.container_log_reopen(id))
        })
        .map(|_| ())
    }

    /// Stop a container; `service`: for the service manager (shutdown), so
    /// that the restart policy applies at the next boot.  A warning to say.
    pub fn stop_container_with(
        &self,
        id: &str,
        timeout: Option<u32>,
        service: bool,
    ) -> ClientResult<Option<String>> {
        let stopped = self.typed("ContainerStop", |conn| {
            ask(conn.container_stop(id, timeout.map(u64::from), false, Some(service)))
        })?;
        Ok(stopped.warning)
    }

    pub fn restart_container(
        &self,
        id: &str,
        timeout: Option<u32>,
        verify: &[String],
    ) -> ClientResult<()> {
        self.typed("ContainerRestart", |conn| {
            ask(conn.container_restart(id, timeout.map(u64::from), verify.to_vec()))
        })
        .map(|_| ())
    }

    pub fn kill_container(&self, id: &str, signal: &str) -> ClientResult<()> {
        self.typed("ContainerKill", |conn| {
            ask(conn.container_kill(id, Some(signal)))
        })
        .map(|_| ())
    }

    /// The containers that do not run (of the `--filter`s) go.
    pub fn prune_containers(&self, filters: &[String]) -> ClientResult<PruneContainersResponse> {
        check_prune_filters(filters)?;
        let pruned = self.typed("ContainerPrune", |conn| {
            ask(conn.container_prune(filters_of(filters)))
        })?;
        Ok(PruneContainersResponse {
            containers_deleted: pruned.removed,
            space_reclaimed: pruned.space,
        })
    }

    /// Run a command in a container: its output goes to `out` and its
    /// errors to `err` as it comes (a writer that fails ends the call with
    /// its error; the command goes on).
    pub fn exec_container(
        &self,
        id: &str,
        params: &ExecParams,
        out: &mut dyn std::io::Write,
        err: &mut dyn std::io::Write,
    ) -> ClientResult<ExecResponse> {
        let session = self.create_exec(id, params)?;
        if params.detach {
            self.typed_once("ExecStart", |conn| {
                exec_output(
                    ready(conn.exec_start(&session, false, true, 0, 0, Vec::new(), Vec::new()))?
                        .map_err(call_error)?,
                    out,
                    err,
                )
                .map(drop)
            })?;
            // (podman prints the id of the session)
            return Ok(ExecResponse {
                session_id: session,
                ..Default::default()
            });
        }
        self.typed_once("ExecStart", |conn| {
            exec_output(
                ready(conn.exec_start(&session, false, false, 0, 0, Vec::new(), Vec::new()))?
                    .map_err(call_error)?,
                out,
                err,
            )
        })?
        .map_err(|e| match e {
            Ok(e) => ClientError::of_output(e),
            Err(e) => ClientError::Connection(e.to_string()),
        })?;
        let exit_code = self.finish_exec(&session)?;
        Ok(ExecResponse {
            exit_code,
            session_id: String::new(),
        })
    }

    /// Create an exec session of `params` in the container `id`: its id.
    pub fn create_exec(&self, id: &str, params: &ExecParams) -> ClientResult<String> {
        let spec = ExecSpec {
            command: params.command.clone(),
            env: params
                .env
                .iter()
                .map(|e| e.split_once('=').unwrap_or((e, "")))
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            work_dir: params.working_dir.clone().unwrap_or_default(),
            user: params.user.clone().unwrap_or_default(),
            tty: params.tty,
            stdin: params.stdin,
            stdout: true,
            stderr: true,
            privileged: params.privileged,
            detach_keys: params.detach_keys.clone().unwrap_or_default(),
            timeout_ms: params
                .timeout
                .map(|s| i64::try_from(s.saturating_mul(1000)).unwrap_or(i64::MAX)),
            errors_apart: true,
        };
        Ok(self
            .typed("ExecCreate", |conn| ask(conn.exec_create(id, spec.clone())))?
            .id)
    }

    /// The status of an exec session that ended, which is not kept: why its
    /// command could not be run is the error.
    pub fn finish_exec(&self, session: &str) -> ClientResult<i32> {
        let exec = self.typed("ExecInspect", |conn| ask(conn.exec_inspect(session)))?;
        let _ = self.typed("ExecRemove", |conn| ask(conn.exec_remove(session, true)));
        if let Some(why) = exec.exec.error {
            return Err(ClientError::Request(why));
        }
        Ok(i32::try_from(exec.exec.exit_code.unwrap_or(125)).unwrap_or(125))
    }

    /// Attach to the container `name` in the engine: its session, for the
    /// copy loop of `velarx_proto::stream` (`serve_to`).  The replies of the
    /// engine are read by a thread of their own, which ends with the
    /// session.
    pub fn open_attach(&self, name: &str, opts: AttachOptions) -> ClientResult<Opened> {
        let name = name.to_string();
        open_session!(self, "ContainerAttach", |conn| conn
            .container_attach(&name, opts))
    }

    /// Start the exec session `id` for the streams of this process:
    /// `preserved` are the descriptors the command gets as 3, 4, ..., but in
    /// the slots of `holes` (slot 0 is 3), where it gets none.
    pub fn open_exec(
        &self,
        id: &str,
        input: bool,
        size: (u16, u16),
        preserved: Vec<OwnedFd>,
        holes: Vec<u32>,
    ) -> ClientResult<Opened> {
        let id = id.to_string();
        open_session!(self, "ExecStart", |conn| conn.exec_start(
            &id,
            input,
            false,
            i64::from(size.0),
            i64::from(size.1),
            holes,
            preserved
        ))
    }

    /// The session the replies of a call opened: waits for the first.
    fn opened(
        &self,
        first: std::sync::mpsc::Receiver<ClientResult<velarx_proto::stream::Item>>,
        hangup: std::sync::mpsc::Receiver<OwnedFd>,
        replies: velarx_proto::stream::Replies,
    ) -> ClientResult<Opened> {
        let lost = || ClientError::Connection("the engine ended the session".into());
        let first = first.recv().map_err(|_| lost())??;
        let hangup = Hangup(hangup.try_recv().ok());
        let client = self.clone();
        let session = velarx_proto::stream::Session::of_first(first, replies, move |name, what| {
            let client = client.clone();
            async move {
                client
                    .session_control(&name, what)
                    .map_err(|e| std::io::Error::other(e.to_string()))
            }
        })
        .map_err(|e| ClientError::Request(e.to_string()))?
        .ok_or_else(|| ClientError::Request("the engine opened no session".into()))?;
        Ok(Opened { session, hangup })
    }

    /// What the client of a session tells the engine, on a connection of its
    /// own (blocking: the engine answers at once).
    fn session_control(
        &self,
        session: &str,
        what: velarx_proto::stream::Control,
    ) -> ClientResult<()> {
        use velarx_proto::stream::Control;
        match what {
            Control::CloseStdin => self
                .typed_once("SessionCloseStdin", |conn| {
                    ask(conn.session_close_stdin(session))
                })
                .map(drop),
            Control::Detach => self
                .typed_once("SessionDetach", |conn| ask(conn.session_detach(session)))
                .map(drop),
        }
    }

    /// The size of the terminal of a container, in characters.
    pub fn resize_container(&self, name: &str, rows: u16, cols: u16) -> ClientResult<()> {
        self.typed("ContainerResize", |conn| {
            ask(conn.container_resize(name, i64::from(rows), i64::from(cols)))
        })
        .map(drop)
    }

    /// The size of the terminal of an exec session, in characters.
    pub fn resize_exec(&self, id: &str, rows: u16, cols: u16) -> ClientResult<()> {
        self.typed("ExecResize", |conn| {
            ask(conn.exec_resize(id, i64::from(rows), i64::from(cols), true))
        })
        .map(drop)
    }

    /// A TCP connection to `port` on the loopback of the network namespace
    /// of a container or a pod (`kind`), made inside the namespace: the
    /// connected socket.
    pub fn connect_port(
        &self,
        kind: Kind,
        name: &str,
        port: u16,
    ) -> ClientResult<std::os::fd::OwnedFd> {
        let pod = match kind {
            Kind::Container => false,
            Kind::Pod => true,
            _ => {
                return Err(ClientError::Request(
                    "a port is connected in a container or a pod".into(),
                ))
            }
        };
        let (_, mut fds) = self.typed("PortConnect", |conn| {
            ask_fds(conn.port_connect(pod, name, port))
        })?;
        take_pipe(&mut fds, 0)
    }

    /// The log of the container `id` to `out` and `err` as it comes (a
    /// writer that fails ends the call with its error); with `follow` it
    /// goes on until the container exited for good.  Each line begins with
    /// its time with `timestamps`.
    #[allow(clippy::too_many_arguments)]
    pub fn stream_logs(
        &self,
        id: &str,
        follow: bool,
        tail: Option<usize>,
        timestamps: bool,
        since: Option<&str>,
        until: Option<&str>,
        out: &mut dyn std::io::Write,
        err: &mut dyn std::io::Write,
    ) -> ClientResult<()> {
        use std::io::Read;
        use velarx_wire::monitor::logfmt::{now_ns, parse_log_time, Toward};
        let now = now_ns();
        let time = |spec: Option<&str>, toward: Toward| {
            spec.map(|s| {
                parse_log_time(s, now, toward)
                    .ok_or_else(|| ClientError::Request(format!("invalid time: {s}")))
            })
            .transpose()
        };
        let opts = LogOptions {
            stdout: true,
            stderr: true,
            follow,
            timestamps,
            tail: tail.map(|t| i64::try_from(t).unwrap_or(i64::MAX)),
            since_ns: time(since, Toward::Past)?,
            until_ns: time(until, Toward::Future)?,
        };
        let (_, mut fds) = self.typed_once("ContainerLogs", |conn| {
            ask_fds(conn.container_logs(id, opts.clone()))
        })?;
        let mut pipe = std::fs::File::from(take_pipe(&mut fds, 0)?);
        let mut frames = velarx_proto::stream::Unframe::default();
        let mut buf = vec![0u8; 32 * 1024];
        loop {
            let n = pipe
                .read(&mut buf)
                .map_err(|e| ClientError::Connection(e.to_string()))?;
            if n == 0 {
                return Ok(());
            }
            for (stream, data) in frames.push(&buf[..n]) {
                let w: &mut dyn std::io::Write = if stream == 2 { &mut *err } else { &mut *out };
                w.write_all(&data)
                    .and_then(|()| w.flush())
                    .map_err(ClientError::of_output)?;
            }
        }
    }

    /// What the container `id` has at `path` (podman's archive stat), `None`
    /// when there is nothing.
    pub fn archive_stat(&self, id: &str, path: &str) -> ClientResult<Option<ArchiveStat>> {
        let got = self.typed("ContainerArchiveGet", |conn| {
            ask_fds(conn.container_archive_get(id, path, false))
        });
        match got {
            Ok((stat, _)) => Ok(Some(ArchiveStat {
                link_target: stat.link_target,
                is_dir: stat.is_dir,
            })),
            Err(e) if e.is_not_found() => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// The tar of `path` in the container `id`.
    pub fn archive_get(&self, id: &str, path: &str) -> ClientResult<Download> {
        let (_, tar) = self.typed("ContainerArchiveGet", |conn| {
            ask_fds(conn.container_archive_get(id, path, true))
        })?;
        download(tar)
    }

    /// Extract the tar `body` writes into the directory `path` of the
    /// container `id`, the first component of its entries renamed.
    pub fn archive_put(
        &self,
        id: &str,
        path: &str,
        opts: &ArchivePut,
        body: Upload,
    ) -> ClientResult<()> {
        let rename = opts
            .rename
            .iter()
            .map(|(from, to)| (from.clone(), to.clone()))
            .collect();
        self.typed_upload("ContainerArchivePut", body, |conn, archive| {
            ask(conn.container_archive_put(id, path, rename, opts.chown, opts.overwrite, archive))
        })
        .map(|_| ())
    }

    /// Samples of the stats of the containers `names` (none: those that
    /// run; with `all` all of them, those that do not run with zeros), to
    /// `each` until it answers false; with `stream` again every
    /// `interval_ms`, else one.
    pub fn container_stats(
        &self,
        names: &[String],
        all: bool,
        stream: bool,
        interval_ms: u64,
        each: &mut dyn FnMut(Vec<velarx_proto::workload::StatsRecord>) -> bool,
    ) -> ClientResult<()> {
        let (mut sample, mut more) = (Vec::new(), true);
        self.typed_once("ContainerStats", |conn| {
            ask_each(
                conn.container_stats(names.to_vec(), all, false, stream, Some(interval_ms)),
                |listed: StatsListed| {
                    // (the connection closes when `each` is done: the samples end)
                    match listed.stats {
                        Some(record) => sample.push(record),
                        None => more = each(std::mem::take(&mut sample)),
                    }
                    more
                },
            )
        })
    }

    pub fn container_top(&self, id: &str, ps_args: &[String]) -> ClientResult<TopResult> {
        let top = self.typed("ContainerTop", |conn| {
            ask(conn.container_top(id, ps_args.to_vec()))
        })?;
        Ok(TopResult {
            titles: top.titles,
            processes: top.processes,
        })
    }

    pub fn pause_container(&self, id: &str) -> ClientResult<()> {
        self.typed("ContainerPause", |conn| {
            ask(conn.container_pause(id, true, None))
        })
        .map(|_| ())
    }

    pub fn unpause_container(&self, id: &str) -> ClientResult<()> {
        self.typed("ContainerPause", |conn| {
            ask(conn.container_pause(id, false, None))
        })
        .map(|_| ())
    }

    /// Checkpoint a container: podman's report.  The checkpoint is kept with
    /// the container, or with `archive` written in it, an empty regular file
    /// the caller opened for writing.
    pub fn checkpoint_container(
        &self,
        id: &str,
        opts: &CheckpointOptions,
        archive: Option<&std::fs::File>,
    ) -> ClientResult<CheckpointReport> {
        let flags = checkpoint_flags(opts, archive.is_some())?;
        let done = self.typed("ContainerCheckpoint", |conn| {
            let fds = archive
                .map(|file| file.try_clone().map(OwnedFd::from))
                .transpose()
                .map_err(|e| CallError::Protocol(format!("the archive: {e}")))?;
            ask(conn.container_checkpoint(
                id,
                flags.clone(),
                fds.as_ref().map(|_| 0),
                fds.into_iter().collect(),
            ))
        })?;
        Ok(CheckpointReport {
            id: done.id,
            runtime_checkpoint_duration: done.runtime_checkpoint_duration,
            criu_statistics: done.criu_statistics,
        })
    }

    /// Make a container from the checkpoint archive `archive`, a regular
    /// file the caller opened for reading, and restore it: podman's report.
    pub fn restore_import(
        &self,
        opts: &RestoreOptions,
        archive: &std::fs::File,
        previous: Option<&std::fs::File>,
    ) -> ClientResult<RestoreReport> {
        let mut flags = restore_flags(opts);
        flags.previous = previous.map(|_| 1);
        let restored = self.typed("ContainerRestore", |conn| {
            let fds = [Some(archive), previous]
                .into_iter()
                .flatten()
                .map(|f| {
                    f.try_clone()
                        .map(OwnedFd::from)
                        .map_err(|e| CallError::Protocol(format!("the archive: {e}")))
                })
                .collect::<Result<Vec<_>, _>>()?;
            ask(conn.container_restore(None, flags.clone(), Some(0), None, false, fds))
        })?;
        Ok(restore_report(restored))
    }

    /// Share the checkpoint archive at `path` with the peers: its reference.
    pub fn share_checkpoint(&self, path: &std::path::Path) -> ClientResult<String> {
        let mut file = std::fs::File::open(path)
            .map_err(|e| ClientError::Request(format!("{}: {e}", path.display())))?;
        let shared = self.typed_upload(
            "CheckpointShare",
            Box::new(move |w| std::io::copy(&mut file, w).map(|_| ())),
            |conn, archive| ask(conn.checkpoint_share(archive)),
        )?;
        Ok(shared.reference)
    }

    pub fn unshare_checkpoint(&self, reference: &str) -> ClientResult<()> {
        let manifest = reference.split(':').take(2).collect::<Vec<_>>().join(":");
        self.typed("CheckpointUnshare", |conn| {
            ask(conn.checkpoint_unshare(&manifest))
        })
        .map(|_| ())
    }

    /// Make a container from the archive of the shared checkpoint
    /// `reference` (from the content sources) and restore it.
    pub fn restore_from_peers(
        &self,
        opts: &RestoreOptions,
        reference: &str,
        previous: Option<&std::fs::File>,
    ) -> ClientResult<RestoreReport> {
        let mut flags = restore_flags(opts);
        flags.previous = previous.map(|_| 0);
        let restored = self.typed("ContainerRestore", |conn| {
            let fds = previous
                .map(|f| {
                    f.try_clone()
                        .map(OwnedFd::from)
                        .map_err(|e| CallError::Protocol(format!("the archive: {e}")))
                })
                .transpose()?;
            ask(conn.container_restore(
                None,
                flags.clone(),
                None,
                Some(reference),
                false,
                fds.into_iter().collect(),
            ))
        })?;
        Ok(restore_report(restored))
    }

    /// Restore a container from the checkpoint kept with it: podman's report.
    pub fn restore_container(
        &self,
        id: &str,
        opts: &RestoreOptions,
    ) -> ClientResult<RestoreReport> {
        let flags = restore_flags(opts);
        let restored = self.typed("ContainerRestore", |conn| {
            ask(conn.container_restore(Some(id), flags.clone(), None, None, false, Vec::new()))
        })?;
        Ok(restore_report(restored))
    }

    pub fn rename_container(&self, id: &str, new_name: &str) -> ClientResult<()> {
        self.typed("ContainerRename", |conn| {
            ask(conn.container_rename(id, new_name))
        })
        .map(|_| ())
    }

    // Network operations

    /// Create a network; with `ignore_if_exists`, one of that name is the
    /// answer.
    pub fn create_network(
        &self,
        spec: &NetworkSpec,
        ignore_if_exists: bool,
    ) -> ClientResult<NetworkRecord> {
        let created = self.typed("NetworkCreate", |conn| {
            ask(conn.network_create(spec, ignore_if_exists))
        })?;
        Ok(created.network)
    }

    /// The networks `filters` (podman's, `KEY=VALUE`) select.
    pub fn list_networks(&self, filters: &[String]) -> ClientResult<Vec<NetworkRecord>> {
        let mut networks = Vec::new();
        self.typed_once("NetworkList", |conn| {
            ask_each(
                conn.network_list(filters_of(filters)),
                |listed: NetworkListed| {
                    networks.extend(listed.network);
                    true
                },
            )
        })?;
        Ok(networks)
    }

    pub fn inspect_network(&self, name: &str) -> ClientResult<NetworkRecord> {
        let inspected = self.typed("NetworkInspect", |conn| ask(conn.network_inspect(name)))?;
        Ok(inspected.network)
    }

    /// Remove the networks no container uses (of the `--filter`s): their
    /// names.
    pub fn prune_networks(&self, filters: &[String]) -> ClientResult<Vec<String>> {
        check_prune_filters(filters)?;
        let pruned = self.typed("NetworkPrune", |conn| {
            ask(conn.network_prune(filters_of(filters)))
        })?;
        Ok(pruned.removed)
    }

    /// Add and remove DNS servers of a network.
    pub fn update_network(
        &self,
        name: &str,
        dns_add: &[String],
        dns_drop: &[String],
    ) -> ClientResult<()> {
        self.typed("NetworkUpdate", |conn| {
            ask(conn.network_update(name, dns_add.to_vec(), dns_drop.to_vec()))
        })
        .map(|_| ())
    }

    pub fn connect_network(
        &self,
        name: &str,
        container: &str,
        ip: Option<&str>,
        ip6: Option<&str>,
        mac: Option<&str>,
        aliases: &[String],
    ) -> ClientResult<()> {
        self.typed("NetworkConnect", |conn| {
            ask(conn.network_connect(name, container, ip, ip6, mac, aliases.to_vec()))
        })
        .map(|_| ())
    }

    /// Apply the firewall rules of the networks of a running container
    /// again: its ID, empty when `if_configured` and it has none to do it
    /// for.
    pub fn reload_network(&self, container: &str, if_configured: bool) -> ClientResult<String> {
        let reloaded = self.typed("NetworkReload", |conn| {
            ask(conn.network_reload(container, if_configured))
        })?;
        Ok(reloaded.id)
    }

    pub fn disconnect_network(&self, name: &str, container: &str, force: bool) -> ClientResult<()> {
        self.typed("NetworkDisconnect", |conn| {
            ask(conn.network_disconnect(name, container, force))
        })
        .map(|_| ())
    }

    /// Remove a network; with `force` the containers on it go first, given
    /// `time` seconds to stop (their own stop timeout if absent).
    pub fn remove_network(&self, name: &str, force: bool, time: Option<u64>) -> ClientResult<()> {
        let removed = self.typed("NetworkRemove", |conn| {
            ask(conn.network_remove(name, force, time.filter(|_| force)))
        })?;
        warn_all(&removed.warnings);
        Ok(())
    }

    // System operations
    /// The build of the engine and the kernel it runs on.
    pub fn version_inspect(&self) -> ClientResult<velarx_proto::system::VersionRecord> {
        let inspected = self.typed("VersionInspect", |conn| ask(conn.version_inspect()))?;
        Ok(inspected.version)
    }

    /// What the engine is and what it runs on.
    pub fn system_inspect(&self) -> ClientResult<velarx_proto::system::SystemRecord> {
        let inspected = self.typed("SystemInspect", |conn| ask(conn.system_inspect()))?;
        Ok(inspected.system)
    }

    /// What the images, the containers and the volumes use of the disk;
    /// with `store`, the files of the store too.
    pub fn disk_usage(&self, store: bool) -> ClientResult<velarx_proto::system::DiskUsageRecord> {
        let inspected = self.typed("DiskUsageInspect", |conn| {
            ask(conn.disk_usage_inspect(store))
        })?;
        Ok(inspected.usage)
    }

    /// Remove what is not in use (`volumes`: the volumes too, `all`: the
    /// images no container uses, `build`: the containers of builds that
    /// are gone) that `filters` (podman's, `KEY=VALUE`) select, then
    /// collect the garbage of the store.
    pub fn system_prune(
        &self,
        all: bool,
        volumes: bool,
        build: bool,
        filters: &[String],
    ) -> ClientResult<velarx_proto::system::SystemPruneReport> {
        let pruned = self.typed("SystemPrune", |conn| {
            ask(conn.system_prune(all, volumes, build, filters_of(filters)))
        })?;
        Ok(pruned.report)
    }

    /// Collect the garbage of the store (the files, the layers).
    pub fn system_collect(
        &self,
        dry_run: bool,
        files: bool,
        layers: bool,
    ) -> ClientResult<velarx_proto::system::GcReport> {
        let collected = self.typed("SystemCollect", |conn| {
            ask(conn.system_collect(dry_run, files, layers))
        })?;
        Ok(collected.report)
    }

    /// The stores the storage service holds for the user, after `drop` (one
    /// that is not this engine's) was dropped.
    pub fn system_stores(
        &self,
        drop: Option<&str>,
    ) -> ClientResult<velarx_proto::system::StoresReport> {
        let listed = self.typed("SystemStores", |conn| {
            ask(conn.system_stores(drop.map(str::to_string)))
        })?;
        Ok(listed.report)
    }

    pub fn system_check(
        &self,
        spec: &velarx_proto::system::CheckSpec,
    ) -> ClientResult<velarx_proto::system::CheckReport> {
        let checked = self.typed("SystemCheck", |conn| ask(conn.system_check(spec.clone())))?;
        Ok(checked.report)
    }

    // Events
    /// The events kept that `filters` (podman's, `KEY=VALUE`) select, from
    /// `since_ns` to `until_ns`.
    pub fn events(
        &self,
        filters: &[String],
        since_ns: Option<i64>,
        until_ns: Option<i64>,
    ) -> ClientResult<Vec<velarx_proto::workload::Event>> {
        let mut events = Vec::new();
        self.typed_once("EventList", |conn| {
            ask_each(
                conn.event_list(filters_of(filters), since_ns, until_ns, false),
                |listed: EventListed| {
                    events.extend(listed.event);
                    true
                },
            )
        })?;
        Ok(events)
    }

    // Volume operations

    /// Create a volume; with `ignore_if_exists`, one of that name is the
    /// answer.
    pub fn create_volume(
        &self,
        spec: &VolumeSpec,
        ignore_if_exists: bool,
    ) -> ClientResult<VolumeRecord> {
        let created = self.typed("VolumeCreate", |conn| {
            ask(conn.volume_create(spec, ignore_if_exists))
        })?;
        Ok(created.volume)
    }

    pub fn export_volume(&self, name: &str) -> ClientResult<Download> {
        let (_, archive) = self.typed("VolumeExport", |conn| ask_fds(conn.volume_export(name)))?;
        download(archive)
    }

    pub fn import_volume(&self, name: &str, body: Upload) -> ClientResult<()> {
        self.typed_upload("VolumeImport", body, |conn, archive| {
            ask(conn.volume_import(name, archive))
        })
        .map(|_| ())
    }

    /// Mount a volume that needs it: where it is.
    pub fn mount_volume(&self, name: &str) -> ClientResult<String> {
        let mounted = self.typed("VolumeMount", |conn| ask(conn.volume_mount(name)))?;
        Ok(mounted.path)
    }

    pub fn unmount_volume(&self, name: &str) -> ClientResult<()> {
        self.typed("VolumeUnmount", |conn| ask(conn.volume_unmount(name)))
            .map(|_| ())
    }

    /// The volumes `filters` (podman's, `KEY=VALUE`) select.
    pub fn list_volumes(&self, filters: &[String]) -> ClientResult<Vec<VolumeRecord>> {
        let mut volumes = Vec::new();
        self.typed_once("VolumeList", |conn| {
            ask_each(
                conn.volume_list(filters_of(filters)),
                |listed: VolumeListed| {
                    volumes.extend(listed.volume);
                    true
                },
            )
        })?;
        Ok(volumes)
    }

    pub fn inspect_volume(&self, name: &str) -> ClientResult<VolumeRecord> {
        let inspected = self.typed("VolumeInspect", |conn| ask(conn.volume_inspect(name)))?;
        Ok(inspected.volume)
    }

    /// Remove a volume; with `force` the containers that use it go first,
    /// given `time` seconds to stop.
    pub fn remove_volume(&self, name: &str, force: bool, time: Option<u64>) -> ClientResult<()> {
        let removed = self.typed("VolumeRemove", |conn| {
            ask(conn.volume_remove(name, force, time.filter(|_| force)))
        })?;
        warn_all(&removed.warnings);
        Ok(())
    }

    /// Remove the volumes no container uses (of the `--filter`s): their
    /// names.
    pub fn prune_volumes(&self, filters: &[String]) -> ClientResult<Vec<String>> {
        check_prune_filters(filters)?;
        let pruned = self.typed("VolumePrune", |conn| {
            ask(conn.volume_prune(filters_of(filters), false))
        })?;
        Ok(pruned.removed.into_iter().map(|v| v.name).collect())
    }

    // Pod operations
    /// Create the pod `spec` describes: its id (the engine names a pod
    /// without a name).
    pub fn create_pod(&self, spec: &PodSpec) -> ClientResult<String> {
        let spec = serde_json::to_vec(spec)?;
        let made = self.typed_data("PodCreate", &spec, |conn, body| {
            ask(conn.pod_create(0, body))
        })?;
        Ok(made.id)
    }

    /// The pods `filters` (podman's, `KEY=VALUE`) select.
    pub fn list_pods(&self, filters: &[String]) -> ClientResult<Vec<PodRecord>> {
        let mut pods = Vec::new();
        self.typed_once("PodList", |conn| {
            ask_each(conn.pod_list(filters_of(filters)), |listed: PodListed| {
                pods.extend(listed.pod);
                true
            })
        })?;
        Ok(pods)
    }

    /// A pod, with what its infra container says of its network.
    pub fn inspect_pod(&self, name: &str) -> ClientResult<PodRecord> {
        let inspected = self.typed("PodInspect", |conn| ask(conn.pod_inspect(name)))?;
        Ok(inspected.pod)
    }

    /// Apply `action` to the containers of the pod `name` (`timeout`: of a
    /// stop, none: each container's own; `signal`: of a kill, none:
    /// `SIGKILL`); the errors of its containers make one error.  `verify`:
    /// the digests typed on the command of a start or a restart, which the
    /// images of its containers are held to.
    pub fn run_pod(
        &self,
        name: &str,
        action: PodAction,
        timeout: Option<u64>,
        signal: Option<&str>,
        verify: &[String],
    ) -> ClientResult<()> {
        let ran = self.typed("PodRun", |conn| {
            ask(conn.pod_run(name, action, timeout, signal, verify.to_vec(), None::<bool>))
        })?;
        pod_ran(&ran)
    }

    /// Remove a pod and its containers; with `force` the running ones stop,
    /// given `timeout` seconds (none: their own).
    pub fn remove_pod(&self, name: &str, force: bool, timeout: Option<u64>) -> ClientResult<()> {
        let removed = self.typed("PodRemove", |conn| {
            ask(conn.pod_remove(name, force, timeout))
        })?;
        warn_all(&removed.warnings);
        Ok(())
    }

    /// The processes of the containers of a pod that run, as `ps` shows
    /// them with `ps_args` (podman's descriptors or the options of ps).
    pub fn pod_top(&self, name: &str, ps_args: &[String]) -> ClientResult<TopResult> {
        let top = self.typed("PodTop", |conn| ask(conn.pod_top(name, ps_args.to_vec())))?;
        Ok(TopResult {
            titles: top.titles,
            processes: top.processes,
        })
    }

    /// Remove the pods none of whose containers runs: their ids.
    pub fn prune_pods(&self) -> ClientResult<Vec<String>> {
        let pruned = self.typed("PodPrune", |conn| ask(conn.pod_prune()))?;
        Ok(pruned.removed)
    }

    pub fn pod_logs(
        &self,
        id: &str,
        since: Option<&str>,
        until: Option<&str>,
        tail: Option<u64>,
        containers: &[String],
    ) -> ClientResult<Vec<PodLogEntry>> {
        let opts = pod_log_options(since, until, tail, containers, false)?;
        let mut lines = Vec::new();
        self.typed_once("PodLogs", |conn| {
            ask_each(conn.pod_logs(id, opts), |listed: PodLogListed| {
                lines.extend(listed.line.map(pod_log_entry));
                true
            })
        })?;
        Ok(lines)
    }

    /// The logs of a pod as they come: `each` sees every line, merged from
    /// the containers, until it returns false or the containers exited and
    /// their logs were read.
    pub fn pod_logs_follow(
        &self,
        id: &str,
        since: Option<&str>,
        until: Option<&str>,
        tail: Option<u64>,
        containers: &[String],
        each: &mut dyn FnMut(PodLogEntry) -> bool,
    ) -> ClientResult<()> {
        let opts = pod_log_options(since, until, tail, containers, true)?;
        self.typed_once("PodLogs", |conn| {
            ask_each(conn.pod_logs(id, opts), |listed: PodLogListed| {
                listed.line.is_none_or(|line| each(pod_log_entry(line)))
            })
        })
    }

    // Healthcheck methods
    /// Run the health check of a container that runs now: its health after
    /// it, the result last in its log.
    pub fn healthcheck_run(&self, container: &str) -> ClientResult<velarx_proto::health::Health> {
        let checked = self.typed("ContainerHealthcheck", |conn| {
            ask(conn.container_healthcheck(container))
        })?;
        Ok(checked.health)
    }

    /// The steps of the history of an image, the newest first.
    pub fn image_history(&self, image: &str) -> ClientResult<Vec<ImageHistoryEntry>> {
        let mut entries = Vec::new();
        self.typed_once("ImageHistory", |conn| {
            ask_each(conn.image_history(image), |listed: ImageHistoryListed| {
                entries.extend(listed.entry);
                true
            })
        })?;
        Ok(entries)
    }

    /// `image tree`: podman's text of the layers of an image, or with
    /// `what_requires` of the images built on it.
    pub fn image_tree(&self, image: &str, what_requires: bool) -> ClientResult<String> {
        let inspected = self.typed("ImageTree", |conn| ask(conn.image_tree(image)))?;
        Ok(velarx_shape::image::tree(&inspected.tree, what_requires))
    }

    /// What the registries have for a search.
    pub fn search_images(&self, req: &SearchRequest) -> ClientResult<Vec<SearchHit>> {
        let found = self.typed_access("ImageSearch", &req.access, |conn, access, fds| {
            ask(conn.image_search(
                &req.term,
                req.limit,
                req.filters.clone(),
                req.list_tags,
                req.tls_verify,
                access,
                fds,
            ))
        })?;
        Ok(found.hits)
    }

    /// Remove a container with podman's options: what was removed.
    pub fn remove_container_podman(
        &self,
        id: &str,
        opts: &RemoveContainer,
    ) -> ClientResult<Vec<String>> {
        let RemoveContainer {
            force,
            volumes,
            ignore,
            depend,
            timeout,
        } = opts;
        let removed = self.typed("ContainerRemove", |conn| {
            ask(conn.container_remove(id, *force, *volumes, *ignore, *depend, *timeout))
        })?;
        warn_all(&removed.warnings);
        Ok(removed
            .removed
            .into_iter()
            .map(|r| if r.named.is_empty() { r.id } else { r.named })
            .collect())
    }

    /// `wait`: until the container meets one of `conditions` (none: its
    /// exit), `interval_ns` podman's interval; the exit code (-1 for a
    /// condition that is no exit).
    pub fn wait_condition(
        &self,
        id: &str,
        conditions: &[velarx_proto::wait::WaitCondition],
        interval_ns: i64,
    ) -> ClientResult<i64> {
        // (the wait ends with the connection, when the command goes away;
        // the first reply says it is armed)
        let mut status = None;
        self.typed_once("ContainerWait", |conn| {
            ask_each(
                conn.container_wait(id, conditions.to_vec(), interval_ns),
                |waited: Waited| {
                    status = waited.status_code;
                    status.is_none()
                },
            )
        })?;
        status.ok_or_else(|| {
            ClientError::Request("the engine answered a wait without its exit code".into())
        })
    }

    /// The tar of the root file system of a container.
    pub fn export_container(&self, id: &str) -> ClientResult<Download> {
        let (_, tar) = self.typed("ContainerExport", |conn| ask_fds(conn.container_export(id)))?;
        download(tar)
    }

    /// Mount the root file system of a container: where.
    pub fn mount_container(&self, id: &str) -> ClientResult<String> {
        let mounted = self.typed("ContainerMount", |conn| ask(conn.container_mount(id)))?;
        Ok(mounted.path)
    }

    pub fn unmount_container(&self, id: &str) -> ClientResult<()> {
        self.typed("ContainerUnmount", |conn| ask(conn.container_unmount(id)))
            .map(|_| ())
    }

    /// The containers whose root is mounted: their IDs and where.
    pub fn mounted_containers(&self) -> ClientResult<Vec<(String, String)>> {
        let listed = self.typed(
            "ContainerMountList",
            |conn| ask(conn.container_mount_list()),
        )?;
        Ok(listed.mounts.into_iter().collect())
    }

    /// Create a container as `id` was made: under `name` (`NAME-clone`
    /// without), with `image` and `pod` when given.
    pub fn clone_container(
        &self,
        id: &str,
        name: Option<&str>,
        image: Option<&str>,
        pod: Option<&str>,
    ) -> ClientResult<IdResponse> {
        let made = self.typed("ContainerClone", |conn| {
            ask(conn.container_clone(id, name, image, pod))
        })?;
        Ok(IdResponse { id: made.id })
    }

    pub fn init_container(&self, id: &str) -> ClientResult<()> {
        let init = self.typed("ContainerInit", |conn| ask(conn.container_init(id)))?;
        if !init.changed {
            return Err(ClientError::api(
                409,
                format!(
                    "container {id} has already been created in runtime: container state improper"
                ),
            ));
        }
        Ok(())
    }

    /// Change a container as `update` says.
    pub fn update_container(&self, id: &str, update: &UpdateSpec) -> ClientResult<()> {
        self.typed("ContainerAmend", |conn| {
            ask(conn.container_amend(id, update.clone()))
        })
        .map(|_| ())
    }

    pub fn exists(&self, kind: Kind, name: &str) -> ClientResult<bool> {
        let found = match kind {
            Kind::Container => self
                .typed("ContainerExists", |conn| ask(conn.container_exists(name)))
                .map(|_| ()),
            Kind::Image => self
                .typed("ImageExists", |conn| ask(conn.image_exists(name)))
                .map(|_| ()),
            Kind::Volume => self
                .typed("VolumeExists", |conn| ask(conn.volume_exists(name)))
                .map(|_| ()),
            Kind::Network => self
                .typed("NetworkExists", |conn| ask(conn.network_exists(name)))
                .map(|_| ()),
            Kind::Pod => self
                .typed("PodExists", |conn| ask(conn.pod_exists(name)))
                .map(|_| ()),
        };
        match found {
            Ok(()) => Ok(true),
            Err(e) if e.is_not_found() => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// Replace the limits of the cgroup of a pod: its id.
    pub fn update_pod(
        &self,
        name: &str,
        resources: &velarx_proto::pod::PodResources,
    ) -> ClientResult<String> {
        let updated = self.typed("PodUpdate", |conn| {
            ask(conn.pod_update(name, resources.clone()))
        })?;
        Ok(updated.id)
    }

    /// The ID of the secret.
    pub fn secret_create(&self, req: &SecretCreate, data: &[u8]) -> ClientResult<String> {
        let created = self.typed("SecretCreate", |conn| {
            let file = sealed(data).map_err(|e| CallError::Protocol(e.to_string()))?;
            ask(conn.secret_create(
                &req.name,
                req.driver.as_deref().filter(|d| !d.is_empty()),
                req.driver_opts.clone(),
                req.labels.clone(),
                req.replace,
                req.ignore,
                0,
                vec![file],
            ))
        })?;
        Ok(created.id)
    }

    /// The secrets `filters` (podman's, `KEY=VALUE`) select.
    pub fn secret_list(&self, filters: &[String]) -> ClientResult<Vec<SecretRecord>> {
        let mut secrets = Vec::new();
        self.typed_once("SecretList", |conn| {
            ask_each(
                conn.secret_list(filters_of(filters)),
                |listed: SecretListed| {
                    secrets.extend(listed.secret);
                    true
                },
            )
        })?;
        Ok(secrets)
    }

    /// A secret; with `show_data`, with its data.
    pub fn secret_inspect(&self, name: &str, show_data: bool) -> ClientResult<SecretRecord> {
        let (inspected, mut pipes) = self.typed("SecretInspect", |conn| {
            ask_fds(conn.secret_inspect(name, show_data))
        })?;
        let mut secret = inspected.secret;
        if let Some(i) = inspected.data {
            let file = std::fs::File::from(take_pipe(&mut pipes, i)?);
            let data = velarx_base::sealed::read_sealed_whole(
                &file,
                velarx_wire::wire::SECRET_MAX_SIZE as u64,
            )
            .map_err(|why| ClientError::Request(format!("the data of the secret {why}")))?;
            secret.data = Some(data);
        }
        Ok(secret)
    }

    pub fn secret_remove(&self, name: &str) -> ClientResult<()> {
        self.typed("SecretRemove", |conn| ask(conn.secret_remove(name, false)))
            .map(|_| ())
    }

    pub fn secret_remove_all(&self) -> ClientResult<()> {
        self.typed("SecretRemove", |conn| ask(conn.secret_remove("", true)))
            .map(|_| ())
    }

    pub fn secret_exists(&self, name: &str) -> ClientResult<bool> {
        match self.typed("SecretExists", |conn| ask(conn.secret_exists(name))) {
            Ok(_) => Ok(true),
            Err(e) if e.is_not_found() => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// Add a file to an artifact: its digest.
    pub fn artifact_add(&self, req: &ArtifactAdd, body: Upload) -> ClientResult<String> {
        let annotations = req
            .annotations
            .iter()
            .map(|a| {
                a.split_once('=')
                    .map(|(k, v)| (k.to_string(), v.to_string()))
                    .ok_or_else(|| {
                        ClientError::api(400, format!("invalid annotation {a:?}: KEY=VALUE"))
                    })
            })
            .collect::<ClientResult<std::collections::BTreeMap<_, _>>>()?;
        let spec = ArtifactAddSpec {
            name: req.name.clone(),
            file_name: req.file_name.clone(),
            append: req.append,
            replace: req.replace,
            artifact_type: req.artifact_type.clone(),
            file_type: req.file_type.clone(),
            annotations,
            digest: req.digest.clone(),
        };
        let added = self.typed_upload("ArtifactAdd", body, |conn, file| {
            ask(conn.artifact_add(spec, Some(0), None, file))
        })?;
        Ok(added.id)
    }

    /// Pull an artifact: its digest.
    pub fn artifact_pull(&self, req: &ArtifactTransfer) -> ClientResult<String> {
        self.artifact_transfer(false, req).map(|p| p.digest)
    }

    /// Push an artifact: its digest, and how the destination resolves it.
    pub fn artifact_push(&self, req: &ArtifactTransfer) -> ClientResult<PushedImage> {
        self.artifact_transfer(true, req)
    }

    pub fn artifact_list(&self) -> ClientResult<Value> {
        let all = self.artifacts()?;
        Ok(Value::Array(
            all.iter()
                .map(velarx_shape::manifest::artifact_document)
                .collect(),
        ))
    }

    pub fn artifact_inspect(&self, name: &str) -> ClientResult<Value> {
        let inspected = self.typed("ArtifactInspect", |conn| ask(conn.artifact_inspect(name)))?;
        Ok(velarx_shape::manifest::artifact_document(
            &inspected.artifact,
        ))
    }

    /// Remove artifacts (`all`: every one): the digests removed.
    pub fn artifact_remove(
        &self,
        names: &[String],
        all: bool,
        ignore: bool,
    ) -> ClientResult<Vec<String>> {
        let bad = |m: &str| ClientError::api(400, m.into());
        if all && !names.is_empty() {
            return Err(bad(
                "when setting all to true, you may not pass any artifact names or digests",
            ));
        }
        if !all && names.is_empty() {
            return Err(bad("an artifact or all option must be specified"));
        }
        let names: Vec<String> = if all {
            self.artifacts()?.into_iter().map(|a| a.digest).collect()
        } else {
            names.to_vec()
        };
        let mut digests = Vec::new();
        for n in names {
            match self.typed("ArtifactRemove", |conn| ask(conn.artifact_remove(&n))) {
                Ok(removed) => digests.push(removed.id),
                Err(e) if ignore && e.is_not_found() => {}
                Err(e) => return Err(e),
            }
        }
        Ok(digests)
    }

    /// The files of an artifact, as a tar.
    pub fn artifact_extract(
        &self,
        name: &str,
        digest: Option<&str>,
        title: Option<&str>,
    ) -> ClientResult<Download> {
        let (_, tar) = self.typed("ArtifactExtract", |conn| {
            ask_fds(conn.artifact_extract(name, digest, title, false))
        })?;
        download(tar)
    }

    /// `create`, `add`, `annotate` and `remove` on a list: its digest.
    pub fn manifest(
        &self,
        list: &str,
        op: ManifestOp,
        req: &ManifestRequest,
    ) -> ClientResult<String> {
        let instance = instance_spec(&req.instance);
        let index_annotations: std::collections::BTreeMap<String, String> =
            req.index_annotations.clone().into_iter().collect();
        match op {
            ManifestOp::Create => self
                .typed_access("ManifestCreate", &req.access, |conn, access, fds| {
                    ask(conn.manifest_create(
                        list,
                        req.images.clone(),
                        req.amend,
                        req.all,
                        req.tls_verify,
                        index_annotations.clone(),
                        instance.clone(),
                        None,
                        req.algorithm.clone(),
                        access,
                        fds,
                    ))
                })
                .map(|id| id.id),
            ManifestOp::Add => self
                .typed_access("ManifestAddImages", &req.access, |conn, access, fds| {
                    ask(conn.manifest_add_images(
                        list,
                        req.images.clone(),
                        req.all,
                        instance.clone(),
                        req.tls_verify,
                        access,
                        fds,
                    ))
                })
                .map(|id| id.id),
            ManifestOp::Annotate => self
                .typed("ManifestAnnotate", |conn| {
                    ask(conn.manifest_annotate(
                        list,
                        req.images.first().cloned(),
                        instance.clone(),
                        index_annotations.clone(),
                        req.subject.clone(),
                    ))
                })
                .map(|id| id.id),
            ManifestOp::Remove => {
                let digest = req
                    .digest
                    .as_deref()
                    .ok_or_else(|| ClientError::api(400, "no instance to remove".into()))?;
                self.typed("ManifestRemoveInstance", |conn| {
                    ask(conn.manifest_remove_instance(list, digest))
                })
                .map(|id| id.id)
            }
        }
    }

    /// A list, local or of a registry: podman's document of it.
    pub fn manifest_inspect(&self, list: &str, req: &ManifestRequest) -> ClientResult<Value> {
        let record = self.typed_access("ManifestInspect", &req.access, |conn, access, fds| {
            ask(conn.manifest_inspect(list, req.tls_verify, access, fds))
        })?;
        Ok(velarx_shape::manifest::index_document(&record))
    }

    /// Push a list: its digest, and how the destination resolves it.
    pub fn manifest_push(&self, list: &str, req: &ManifestRequest) -> ClientResult<PushedImage> {
        let instance_compression = |c: &str| {
            LayerCompression::of_word(c)
                .ok_or_else(|| ClientError::api(400, format!("unknown compression `{c}`")))
        };
        let format = req.compression_format.as_deref().filter(|c| !c.is_empty());
        let add = req
            .add_compression
            .iter()
            .map(|c| instance_compression(c))
            .collect::<ClientResult<Vec<_>>>()?;
        let compression = format.map(instance_compression).transpose()?;
        let manifest_format = req
            .format
            .as_deref()
            .filter(|f| !f.is_empty())
            .map(velarx_proto::engine::ManifestFormat::of_word)
            .transpose()
            .map_err(|m| ClientError::api(400, m))?;
        let spec = PushSpec {
            images: vec![list.to_string()],
            destination: Some(req.destination.clone().unwrap_or_else(|| list.to_string())),
            all: req.all,
            tls_verify: req.tls_verify,
            compression,
            compression_level: req.compression_level,
            add_compression: add,
            format: manifest_format,
            sinks: req.sinks.clone(),
            ..Default::default()
        };
        self.push_spec(spec, &req.access, req.sign.as_ref(), None, &mut |_| {})
    }

    /// Add artifacts made of `files` to the list (`req`: podman's options).
    pub fn manifest_add_artifact(
        &self,
        list: &str,
        req: &Value,
        files: &[std::path::PathBuf],
        tls_verify: bool,
    ) -> ClientResult<String> {
        let (spec, index_annotations, subject) = crate::client::artifact_spec(req, files)
            .map_err(|message| ClientError::api(400, message))?;
        let mut pipes = Vec::new();
        for f in files {
            let file = std::fs::File::open(f)
                .map_err(|e| ClientError::Request(format!("{}: {e}", f.display())))?;
            pipes.push(OwnedFd::from(file));
        }
        self.typed_once("ManifestAddArtifact", |conn| {
            ask(conn.manifest_add_artifact(list, spec, tls_verify, None, pipes))
        })?;
        // (the id of the list once it is known to be in the store: the
        // inspect of a name that is not looks in its registry)
        let record = self.typed("ManifestInspect", |conn| {
            ask(conn.manifest_inspect(list, true, None, Vec::new()))
        })?;
        let id = record.id;
        if !index_annotations.is_empty() || subject.is_some() {
            self.typed("ManifestAnnotate", |conn| {
                ask(conn.manifest_annotate(
                    list,
                    None,
                    InstanceSpec::default(),
                    index_annotations.clone(),
                    subject.clone(),
                ))
            })?;
        }
        Ok(id)
    }

    /// Remove a list: its digest and the names it had.
    pub fn manifest_delete(&self, list: &str) -> ClientResult<ManifestRemoved> {
        self.typed("ManifestRemove", |conn| ask(conn.manifest_remove(list)))
    }

    pub fn manifest_exists(&self, list: &str) -> ClientResult<bool> {
        match self.typed("ManifestExists", |conn| ask(conn.manifest_exists(list))) {
            Ok(_) => Ok(true),
            Err(e) if e.is_not_found() => Ok(false),
            Err(e) => Err(e),
        }
    }
}

/// How the images of a request are instances, as the engine takes it.
fn instance_spec(i: &velarx_wire::wire::InstanceOptions) -> InstanceSpec {
    InstanceSpec {
        annotations: i.annotations.clone().into_iter().collect(),
        architecture: i.arch.clone().unwrap_or_default(),
        os: i.os.clone().unwrap_or_default(),
        os_version: i.os_version.clone().unwrap_or_default(),
        variant: i.variant.clone().unwrap_or_default(),
        features: i.features.clone(),
        os_features: i.os_features.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// An engine that goes away during a call (it crashed) is said as
    /// such, not as the end of a file.
    #[test]
    fn an_engine_that_goes_away_during_a_call_is_said_so() {
        let gone = client_error(CallError::Io(std::io::ErrorKind::UnexpectedEof.into()));
        assert!(
            matches!(&gone, ClientError::Connection(m) if m == "the engine closed the connection before it answered"),
            "{gone:?}"
        );
    }

    #[test]
    fn the_times_of_the_logs_of_a_pod_are_decoded_here() {
        let opts = pod_log_options(Some("1700000000"), None, Some(5), &["a".into()], true).unwrap();
        assert_eq!(opts.since_ns, Some(1_700_000_000_000_000_000_i64));
        assert_eq!(opts.until_ns, None);
        assert_eq!(opts.tail, Some(5));
        assert!(opts.follow);
        let e = pod_log_options(Some("garbage"), None, None, &[], false).unwrap_err();
        assert!(
            e.to_string().contains("unable to interpret time value"),
            "{e}"
        );
    }

    /// Every method the command line calls by its name is one the engine
    /// serves (a name that is not is a call that fails only when it runs);
    /// the other words in quotes are those of podman's documents.
    #[test]
    fn every_method_the_command_line_calls_is_in_the_definition() {
        const NOT_METHODS: [&str; 3] = ["ArtifactDigest", "ArtifactDigests", "NoSuch"];
        let idl = include_str!("../../interfaces/org.velarx.Engine.varlink");
        let words = |prefix: &'static str| -> std::collections::HashSet<&str> {
            idl.lines()
                .filter_map(|l| l.strip_prefix(prefix))
                .filter_map(|l| l.split(['(', ' ']).next())
                .collect()
        };
        let (methods, errors) = (words("method "), words("error "));
        let source = include_str!("engine.rs");
        let mut called = 0;
        for (at, _) in source.match_indices('"') {
            let rest = &source[at + 1..];
            let Some(end) = rest.find(|c: char| !c.is_ascii_alphabetic()) else {
                continue;
            };
            let name = &rest[..end];
            let camel = rest[end..].starts_with('"')
                && name.len() > 2
                && name.starts_with(|c: char| c.is_ascii_uppercase())
                && name[1..].contains(|c: char| c.is_ascii_uppercase());
            if !camel || errors.contains(name) || NOT_METHODS.contains(&name) {
                continue;
            }
            assert!(
                methods.contains(name),
                "the command line calls {name}, a method the engine does not serve"
            );
            called += 1;
        }
        assert!(called > 40, "{called}");
    }

    /// An engine on a socket that answers every call with `answer(method,
    /// parameters)`, a reply as the JSON of a varlink message (`GetInfo`
    /// with the version of this build).
    fn mock_engine(
        answer: impl Fn(&str, &Value) -> Value + Send + 'static,
    ) -> (tempfile::TempDir, EngineClient) {
        mock_engine_of(
            json!({
                "name": "mock",
                "interface": velarx_proto::PROTO,
                "version": env!("CARGO_PKG_VERSION"),
                "digest": velarx_proto::DIGEST,
                "rootful": false,
            }),
            answer,
        )
    }

    /// [`mock_engine`] that says it is `info`.
    fn mock_engine_of(
        info: Value,
        answer: impl Fn(&str, &Value) -> Value + Send + 'static,
    ) -> (tempfile::TempDir, EngineClient) {
        use std::io::{BufRead, BufReader, Write};
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("engine.sock");
        let listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let mut stream = stream.unwrap();
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                loop {
                    let mut message = Vec::new();
                    if reader.read_until(0, &mut message).unwrap_or(0) == 0 {
                        break;
                    }
                    message.pop();
                    let call: Value = serde_json::from_slice(&message).unwrap();
                    let method = call["method"].as_str().unwrap().rsplit('.').next().unwrap();
                    let reply = match method {
                        "GetInfo" => json!({ "parameters": info }),
                        method => answer(method, &call["parameters"]),
                    };
                    let mut bytes = serde_json::to_vec(&reply).unwrap();
                    bytes.push(0);
                    stream.write_all(&bytes).unwrap();
                }
            }
        });
        (dir, EngineClient::new(&socket).unwrap())
    }

    /// `prune --filter label` (no `=`) is refused through the engine as it
    /// is without it: the engine is not asked.
    #[test]
    fn a_prune_filter_without_a_value_is_refused_before_the_call() {
        let (_dir, client) = mock_engine(|method, _| panic!("{method} asked"));
        for refused in [
            client.prune_containers(&["label".into()]).err(),
            client.prune_volumes(&["label".into()]).err(),
            client
                .prune_networks(&["until=1h".into(), "label".into()])
                .err(),
        ] {
            assert!(
                matches!(&refused, Some(ClientError::Api { status: 500, message, .. })
                    if message == "filter input must be in the form of filter=value: label is invalid"),
                "{refused:?}"
            );
        }
    }

    /// A socket served by a user that is neither this one nor root is not
    /// the engine: the client does not talk to it.
    #[test]
    fn a_server_of_another_user_is_not_the_engine() {
        let (_dir, client) = mock_engine(|_, _| json!({"parameters": {}}));
        assert!(client.open().is_ok());
        let refused = client.open_trusting(|_| false);
        assert!(
            matches!(&refused, Err(ClientError::Connection(m)) if m.contains("another user")),
            "{:?}",
            refused.err()
        );
    }

    /// The calls of a command go over one connection, checked once.
    #[test]
    fn the_calls_of_a_client_share_a_checked_connection() {
        use std::io::{BufRead, BufReader, Write};
        use std::sync::{Arc, Mutex};
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("engine.sock");
        let listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
        let seen = Arc::new(Mutex::new(Vec::<String>::new()));
        let log = seen.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let mut stream = stream.unwrap();
                log.lock().unwrap().push("connection".into());
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                loop {
                    let mut message = Vec::new();
                    if reader.read_until(0, &mut message).unwrap_or(0) == 0 {
                        break;
                    }
                    message.pop();
                    let call: Value = serde_json::from_slice(&message).unwrap();
                    let method = call["method"].as_str().unwrap().rsplit('.').next().unwrap();
                    log.lock().unwrap().push(method.to_string());
                    let reply = match method {
                        "GetInfo" => json!({"parameters": {
                            "name": "mock",
                            "interface": velarx_proto::PROTO,
                            "version": env!("CARGO_PKG_VERSION"),
                            "digest": velarx_proto::DIGEST,
                            "rootful": false,
                        }}),
                        _ => json!({"parameters": {"changed": true}}),
                    };
                    let mut bytes = serde_json::to_vec(&reply).unwrap();
                    bytes.push(0);
                    stream.write_all(&bytes).unwrap();
                }
            }
        });
        let client = EngineClient::new(&socket).unwrap();
        for name in ["a", "b", "c"] {
            client.start_container(name, Verify::Service).unwrap();
        }
        assert_eq!(
            *seen.lock().unwrap(),
            [
                "connection",
                "GetInfo",
                "ContainerStart",
                "ContainerStart",
                "ContainerStart"
            ]
        );
    }

    /// A call the engine refuses because it restarts (on a connection it
    /// took before) is made again on a new connection, and answered there;
    /// one refused every time ends with the engine's message.
    #[test]
    fn a_call_refused_by_a_restart_is_asked_again() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let calls = std::sync::Arc::new(AtomicUsize::new(0));
        let served = calls.clone();
        let (_dir, client) = mock_engine(move |_, parameters| {
            if parameters["name"] == "missing" {
                return json!({"error": "org.velarx.Engine.NoSuchContainer", "parameters": {
                    "cause": "no such container", "message": "no container missing",
                }});
            }
            let n = served.fetch_add(1, Ordering::SeqCst);
            if n == 0 || parameters["name"] == "busy" {
                json!({"error": "org.velarx.Engine.Unavailable", "parameters": {
                    "cause": "", "message": "the engine is restarting: ask again",
                }})
            } else {
                json!({"parameters": {"changed": true}})
            }
        });
        client.start_container("web", Verify::Service).unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        let busy = client.start_container("busy", Verify::Service).unwrap_err();
        assert!(busy.to_string().contains("restarting"), "{busy}");
        assert_eq!(calls.load(Ordering::SeqCst), 3 + RESTART_RETRIES as usize);
        let missing = client
            .start_container("missing", Verify::Service)
            .unwrap_err();
        assert!(
            matches!(&missing, ClientError::Api { status: 404, message, .. } if message == "no container missing"),
            "{missing:?}"
        );
    }

    /// A reply that lacks a member the interface says it has is an error,
    /// never an empty string, a zero or a false: the reply is decoded as
    /// the type of the method.
    #[test]
    fn a_reply_without_a_member_is_an_error() {
        let (_dir, client) = mock_engine(|_, _| json!({"parameters": {}}));
        let failed = |what: &str, reply: ClientResult<()>| {
            assert!(
                matches!(reply, Err(ClientError::Request(_))),
                "{what}: {reply:?}"
            );
        };
        failed("start", client.start_container("a", Verify::Service));
        failed("inspect", client.inspect_container("a").map(|_| ()));
        failed(
            "stop",
            client.stop_container_with("a", None, false).map(|_| ()),
        );
        failed("mount", client.mount_container("a").map(|_| ()));
        failed("init", client.init_container("a"));
        failed("top", client.container_top("a", &[]).map(|_| ()));
        failed("prune", client.prune_containers(&[]).map(|_| ()));
        failed("pod", client.inspect_pod("a").map(|_| ()));
        failed(
            "pod create",
            client.create_pod(&PodSpec::default()).map(|_| ()),
        );
        failed("pod remove", client.remove_pod("a", false, None));
        failed("wait", client.wait_condition("a", &[], 0).map(|_| ()));
        failed("health", client.healthcheck_run("a").map(|_| ()));
    }

    /// The same for the images, the volumes, the networks, the secrets and
    /// the artifacts.
    #[test]
    fn a_reply_without_a_member_is_an_error_for_the_images_and_the_rest() {
        let (_dir, client) = mock_engine(|_, _| json!({"parameters": {}}));
        let failed = |what: &str, reply: ClientResult<()>| {
            assert!(
                matches!(reply, Err(ClientError::Request(_))),
                "{what}: {reply:?}"
            );
        };
        failed("image", client.inspect_image("a").map(|_| ()));
        failed("remove image", client.remove_image("a", false).map(|_| ()));
        failed("scopes", client.credential_scopes("a").map(|_| ()));
        failed("tree", client.image_tree("a", false).map(|_| ()));
        failed("build cache", client.prune_build_cache().map(|_| ()));
        failed("volume", client.inspect_volume("a").map(|_| ()));
        failed("mount volume", client.mount_volume("a").map(|_| ()));
        failed("prune volumes", client.prune_volumes(&[]).map(|_| ()));
        failed("network", client.inspect_network("a").map(|_| ()));
        failed("reload", client.reload_network("a", false).map(|_| ()));
        failed("prune networks", client.prune_networks(&[]).map(|_| ()));
        failed("secret", client.secret_inspect("a", false).map(|_| ()));
        failed("artifact", client.artifact_inspect("a").map(|_| ()));
        failed(
            "manifest",
            client
                .manifest("a", ManifestOp::Add, &Default::default())
                .map(|_| ()),
        );
    }

    /// The same for the calls about the system, the events and the metrics.
    #[test]
    fn a_reply_without_a_member_is_an_error_for_the_system() {
        let (_dir, client) = mock_engine(|_, _| json!({"parameters": {}}));
        let failed = |what: &str, reply: ClientResult<()>| {
            assert!(
                matches!(reply, Err(ClientError::Request(_))),
                "{what}: {reply:?}"
            );
        };
        failed("health", client.health().map(|_| ()));
        failed("version", client.version_inspect().map(|_| ()));
        failed("system", client.system_inspect().map(|_| ()));
        failed("disk usage", client.disk_usage(false).map(|_| ()));
        failed(
            "prune",
            client.system_prune(false, false, false, &[]).map(|_| ()),
        );
        failed(
            "collect",
            client.system_collect(false, false, false).map(|_| ()),
        );
        failed(
            "check",
            client.system_check(&Default::default()).map(|_| ()),
        );
        failed("restart", client.restart_server());
        // (a reply of a list without its member is an empty one: the
        // members of its records are the engine's, one by one)
        assert!(client.events(&[], None, None).unwrap().is_empty());
    }

    /// An engine that goes before it answers is an error of the connection,
    /// as the end of its socket is.
    #[test]
    fn an_engine_that_goes_is_an_error_of_the_connection() {
        use std::io::{BufRead, BufReader, Write};
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("engine.sock");
        let listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut message = Vec::new();
            reader.read_until(0, &mut message).unwrap();
            let info = json!({"parameters": {
                "name": "mock", "interface": velarx_proto::PROTO,
                "version": env!("CARGO_PKG_VERSION"), "digest": velarx_proto::DIGEST,
                "rootful": false,
            }});
            let mut bytes = serde_json::to_vec(&info).unwrap();
            bytes.push(0);
            stream.write_all(&bytes).unwrap();
            // (the call, and the engine goes)
            reader.read_until(0, &mut message).unwrap();
        });
        let client = EngineClient::new(&socket).unwrap();
        let gone = client.inspect_container("a").map(|_| ()).unwrap_err();
        assert!(matches!(gone, ClientError::Connection(_)), "{gone:?}");
    }

    /// An engine whose `GetInfo` answers other members is of another
    /// version: it is asked to start again, as one of another number.
    #[test]
    fn an_engine_whose_info_is_another_is_of_another_version() {
        let restarts = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let asked = restarts.clone();
        let (_dir, client) =
            mock_engine_of(json!({"version": "0.0.1"}), move |method, _| match method {
                "Restart" => {
                    asked.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    json!({"parameters": {"restarted": false}})
                }
                _ => json!({"parameters": {"changed": true}}),
            });
        let text = client
            .start_container("a", Verify::Service)
            .unwrap_err()
            .to_string();
        assert!(text.contains("the engine is of another version"), "{text}");
        assert!(text.contains("runs the binary installed"), "{text}");
        assert_eq!(restarts.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    /// An engine of another version is asked to start again; one that runs
    /// the binary installed is refused with both versions.
    #[test]
    fn an_engine_of_another_version_is_refused() {
        let (_dir, client) = mock_engine_of(
            json!({
                "name": "mock", "interface": velarx_proto::PROTO, "version": "0.0.1",
                "digest": velarx_proto::DIGEST, "rootful": false,
            }),
            |method, _| match method {
                "Restart" => json!({"parameters": {"restarted": false}}),
                _ => json!({"parameters": {"changed": true}}),
            },
        );
        let refused = client.start_container("a", Verify::Service).unwrap_err();
        let text = refused.to_string();
        assert!(text.contains("the engine is 0.0.1"), "{text}");
        assert!(text.contains("runs the binary installed"), "{text}");
    }

    /// Every error of the interface has its place in the table of the
    /// command line: none is taken for a broken answer.
    #[test]
    fn every_error_of_the_engine_is_in_the_table() {
        let idl = include_str!("../../interfaces/org.velarx.Engine.varlink");
        let names: Vec<&str> = idl
            .lines()
            .filter_map(|l| l.strip_prefix("error "))
            .filter_map(|l| l.split_whitespace().next())
            .collect();
        assert!(names.len() > 10, "{names:?}");
        for name in names {
            let e = client_error(CallError::Remote {
                error: format!("{INTERFACE}.{name}"),
                reason: "m".to_string(),
            });
            assert!(!matches!(e, ClientError::Request(_)), "{name}: {e}");
        }
    }
}
