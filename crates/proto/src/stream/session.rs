// SPDX-License-Identifier: Apache-2.0
//! The copy loop of a session: what a frontend does with the replies of
//! `ContainerAttach` and `ExecStart` (the streams of the process): copy the
//! process's output to its client as Docker's frames (raw with a terminal),
//! the client's input to the process (through the detach keys), and tell the
//! engine what the client does.  The engine's side of the replies ([`Out`])
//! is here too.

use super::DetachMatcher;
use crate::engine::{EngineError, SessionOpened, SessionPhase, SessionReply, SessionStreams};
use std::future::Future;
use std::io;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::pin::Pin;
use std::sync::Arc;
use tokio::io::unix::AsyncFd;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, Interest};
use tokio::sync::{mpsc, oneshot};

/// What one read of a stream takes (Docker's frames carry at most this).
const CHUNK: usize = 32 * 1024;
/// The size of the head of a frame.
const HEAD: usize = 8;
/// The most of the input of a client that is read before the streams of its
/// process are there (a container that is not started yet).
const EARLY_INPUT_MAX: usize = 1 << 20;
/// The replies the engine has sent and the frontend has not taken yet.
const QUEUE: usize = 8;

/// Docker's stream types.
const STDOUT: u8 = 1;
const STDERR: u8 = 2;

/// A reply of a session and the descriptors it carried.
pub type Item = (SessionReply, Vec<OwnedFd>);

/// What the frontend tells the engine, by name: the calls
/// `SessionCloseStdin` and `SessionDetach`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Control {
    /// The input of the client ended and was all written
    CloseStdin,
    /// The client typed the detach keys: the session goes on
    Detach,
}

/// What the engine's session is told (the engine's side).
#[derive(Debug, PartialEq, Eq)]
pub enum Event {
    /// The client typed the detach keys: the session goes on
    Detach,
    /// The input of the client ended: the process's is closed
    InputClosed,
    /// The client is gone (it closed the connection of the session)
    Gone,
}

/// How a frontend makes the calls of [`Control`]: on a connection of its
/// own, answered once the engine dealt with it (told the monitor).
pub type Controller =
    Arc<dyn Fn(Control) -> Pin<Box<dyn Future<Output = io::Result<()>> + Send>> + Send + Sync>;

/// The engine's end of a session: the replies it sends and what the client
/// tells it.
pub struct Out {
    tx: mpsc::Sender<Item>,
    control: tokio::sync::Mutex<mpsc::UnboundedReceiver<Call>>,
    /// The answer to the call the engine is dealing with: given when it asks
    /// for the next event (or ends), the one before was done
    pending: std::sync::Mutex<Option<oneshot::Sender<()>>>,
    /// What the engine says as errors of the process, sent with the end
    said: std::sync::Mutex<String>,
    ended: std::sync::atomic::AtomicBool,
}

/// A call of [`Control`] and where its answer goes.
pub type Call = (Control, oneshot::Sender<()>);

/// The sender of the calls of [`Control`] of the session of an [`Out`]; the
/// answer comes once the engine has dealt with the call.
pub type Controls = mpsc::UnboundedSender<Call>;

/// A call of [`Control`] made on `controls`: answered once the engine dealt
/// with it (`false`: the session is over).
pub async fn call(controls: &Controls, control: Control) -> bool {
    let (tx, rx) = oneshot::channel();
    controls.send((control, tx)).is_ok() && rx.await.is_ok()
}

/// The replies of an [`Out`].
pub type Replies = mpsc::Receiver<Item>;

/// A session of the engine: its end, the replies it makes, and the sender
/// of the calls of the frontend to it.
pub fn out(opened: SessionOpened, logs: Option<OwnedFd>) -> (Out, Replies, Controls) {
    let (tx, rx) = mpsc::channel(QUEUE);
    let (control_tx, control) = mpsc::unbounded_channel();
    let fds = logs.into_iter().collect();
    let first = SessionReply {
        phase: SessionPhase::Accepted,
        opened: Some(opened),
        streams: None,
        exit: None,
        message: None,
    };
    // (the queue is empty: it takes the first reply)
    let _ = tx.try_send((first, fds));
    let out = Out {
        tx,
        control: tokio::sync::Mutex::new(control),
        pending: std::sync::Mutex::new(None),
        said: std::sync::Mutex::new(String::new()),
        ended: std::sync::atomic::AtomicBool::new(false),
    };
    (out, rx, control_tx)
}

impl Out {
    /// The descriptors of the session (the engine's side).
    pub async fn send_streams(
        &self,
        stdin: Option<OwnedFd>,
        stdout: Option<OwnedFd>,
        stderr: Option<OwnedFd>,
    ) -> io::Result<()> {
        let mut fds = Vec::new();
        let mut at = |fd: Option<OwnedFd>| {
            fd.map(|fd| {
                fds.push(fd);
                fds.len() as u32 - 1
            })
        };
        let streams = SessionStreams {
            stdin: at(stdin),
            stdout: at(stdout),
            stderr: at(stderr),
        };
        let reply = SessionReply {
            phase: SessionPhase::Streams,
            opened: None,
            streams: Some(streams),
            exit: None,
            message: None,
        };
        self.tx
            .send((reply, fds))
            .await
            .map_err(|_| io::ErrorKind::BrokenPipe.into())
    }

    /// Text for the client, as errors of the process (the engine's side):
    /// sent with the end.
    pub async fn send_text(&self, text: &str) -> io::Result<()> {
        self.said.lock().expect("said").push_str(text);
        Ok(())
    }

    /// The end of the session, with the status of the process when it is
    /// known.
    pub async fn end(&self, exit: Option<i64>) {
        if self.ended.swap(true, std::sync::atomic::Ordering::SeqCst) {
            return;
        }
        let _ = self.tx.send((self.last(exit), Vec::new())).await;
    }

    fn last(&self, exit: Option<i64>) -> SessionReply {
        let said = std::mem::take(&mut *self.said.lock().expect("said"));
        SessionReply {
            phase: SessionPhase::Ended,
            opened: None,
            streams: None,
            exit,
            message: (!said.is_empty()).then_some(said),
        }
    }

    /// The next thing the frontend tells (the engine's side).  Cancel safe.
    pub async fn event(&self) -> Event {
        // (the call before was dealt with: the engine asks for the next)
        self.answer();
        let mut control = self.control.lock().await;
        tokio::select! {
            c = control.recv() => match c {
                Some((c, ack)) => {
                    *self.pending.lock().expect("pending") = Some(ack);
                    match c {
                        Control::Detach => Event::Detach,
                        Control::CloseStdin => Event::InputClosed,
                    }
                }
                None => Event::Gone,
            },
            () = self.tx.closed() => Event::Gone,
        }
    }

    fn answer(&self) {
        if let Some(ack) = self.pending.lock().expect("pending").take() {
            let _ = ack.send(());
        }
    }
}

impl Drop for Out {
    /// A session that ends without its end says so all the same: the
    /// frontend must not wait for a reply that does not come.
    fn drop(&mut self) {
        self.answer();
        if !self.ended.swap(true, std::sync::atomic::Ordering::SeqCst) {
            let _ = self.tx.try_send((self.last(None), Vec::new()));
        }
    }
}

/// What the frontend is told by the engine.
enum Told {
    Streams {
        stdin: Option<OwnedFd>,
        stdout: Option<OwnedFd>,
        stderr: Option<OwnedFd>,
    },
    /// The end of the session, what the engine said as errors of the
    /// process, and the status of the process
    End(Option<String>, Option<i64>),
}

/// The next thing the engine tells.  Cancel safe.
async fn told(replies: &mut Replies) -> Told {
    loop {
        let Some((reply, fds)) = replies.recv().await else {
            return Told::End(None, None);
        };
        match reply.phase {
            SessionPhase::Streams => {
                let mut fds: Vec<Option<OwnedFd>> = fds.into_iter().map(Some).collect();
                let mut take = |at: Option<u32>| at.and_then(|i| fds.get_mut(i as usize)?.take());
                let streams = reply.streams.unwrap_or_default();
                return Told::Streams {
                    stdin: take(streams.stdin),
                    stdout: take(streams.stdout),
                    stderr: take(streams.stderr),
                };
            }
            SessionPhase::Ended => return Told::End(reply.message, reply.exit),
            SessionPhase::Accepted => {}
        }
    }
}

/// A stream of a session, a pipe or a socket, in the reactor.
struct Pipe(AsyncFd<OwnedFd>);

impl Pipe {
    fn new(fd: OwnedFd) -> io::Result<Self> {
        rustix::fs::fcntl_setfl(&fd, rustix::fs::OFlags::NONBLOCK)?;
        Ok(Self(velarx_sys::fd::register(
            fd,
            Interest::READABLE | Interest::WRITABLE,
        )?))
    }

    /// Read some; 0 at the end.  Cancel safe.
    async fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            let mut guard = self.0.readable().await?;
            match guard
                .try_io(|fd| rustix::io::read(fd.get_ref(), &mut *buf).map_err(io::Error::from))
            {
                Ok(r) => return r,
                Err(_would_block) => {}
            }
        }
    }

    /// Write some.  Cancel safe.
    async fn write(&self, buf: &[u8]) -> io::Result<usize> {
        loop {
            let mut guard = self.0.writable().await?;
            match guard.try_io(|fd| rustix::io::write(fd.get_ref(), buf).map_err(io::Error::from)) {
                Ok(r) => return r,
                Err(_would_block) => {}
            }
        }
    }
}

/// The output of a stream, or never when it ended: what it gave, in `buf`
/// from the head's end on.
async fn output(pipe: &mut Option<Pipe>, buf: &mut [u8]) -> usize {
    let Some(p) = pipe.as_ref() else {
        return std::future::pending().await;
    };
    // (an error is the end of the stream, as the monitor closing it)
    match p.read(&mut buf[HEAD..]).await {
        Ok(n) if n > 0 => n,
        _ => {
            *pipe = None;
            0
        }
    }
}

async fn write_some(pipe: &Option<Pipe>, buf: &[u8]) -> io::Result<usize> {
    match pipe {
        Some(p) => p.write(buf).await,
        None => std::future::pending().await,
    }
}

async fn read_client(reader: &mut Option<Reader>, buf: &mut [u8]) -> io::Result<usize> {
    match reader {
        Some(r) => r.read(buf).await,
        None => std::future::pending().await,
    }
}

/// A future that resolves once the client left a connection altogether
/// (see [`hung_up`]); armed when its input ends, so that a half close keeps
/// it waiting for the full close.  It never resolves for a connection that
/// cannot tell (TCP).
type Left = Option<Pin<Box<dyn Future<Output = ()> + Send>>>;

/// Arm `left` for the socket `peer` (once: the descriptor is taken).
fn arm(left: &mut Left, peer: &mut Option<OwnedFd>) {
    if left.is_none() {
        *left = Some(Box::pin(hang_up(peer.take())));
    }
}

/// Wait for `left` (for ever while it is not armed).
async fn wait_left(left: &mut Left) {
    match left {
        Some(f) => f.await,
        None => std::future::pending().await,
    }
}

/// Whether the socket `fd` has a hang up: its peer closed it, where a peer
/// that only closed its output has none.
pub fn hung_up(fd: BorrowedFd<'_>) -> bool {
    let mut fds = [rustix::event::PollFd::from_borrowed_fd(
        fd,
        rustix::event::PollFlags::empty(),
    )];
    matches!(
        rustix::event::poll(&mut fds, Some(&rustix::event::Timespec::default())),
        Ok(1)
    ) && fds[0]
        .revents()
        .intersects(rustix::event::PollFlags::HUP | rustix::event::PollFlags::ERR)
}

/// Resolves when the socket `fd` has a hang up, woken by the event loop
/// (the hang up of a peer that leaves after it closed its output
/// included); never for `None` or a socket it cannot watch.
pub async fn hang_up(fd: Option<OwnedFd>) {
    let Some(fd) = fd else {
        return std::future::pending().await;
    };
    // A descriptor of its own, made by whoever serves the connection: the
    // connection's is in the event loop already.  Watched for output: a hang
    // up ends it for good (WRITE_CLOSED is EPOLLHUP), while the end of the
    // client's input, which is for good too (READ_CLOSED), would wake the
    // watch for ever.
    let watch = velarx_sys::fd::register(fd, Interest::WRITABLE);
    let Ok(watch) = watch else {
        return std::future::pending().await;
    };
    loop {
        let Ok(mut ready) = watch.writable().await else {
            return std::future::pending().await;
        };
        if ready.ready().is_write_closed() || hung_up(watch.get_ref().as_fd()) {
            return;
        }
        // (writable again: a hang up after the check is a new event, which
        // this does not clear)
        ready.clear_ready();
    }
}

/// What a frontend got for a session: its first reply, and the replies that
/// follow.
pub struct Session {
    opened: SessionOpened,
    replies: Replies,
    log: Option<OwnedFd>,
    controller: Controller,
}

impl Session {
    /// The session the first reply of a call (with its descriptors) opened,
    /// `replies` the replies that follow and `control` how the frontend
    /// tells the engine what its client did (a call named by the session,
    /// on a connection of its own): none when the reply opened no session
    /// (a command that runs on its own).  What every frontend does with
    /// the replies of `ContainerAttach` and `ExecStart`.
    pub fn of_first<F, Fut>(first: Item, replies: Replies, control: F) -> io::Result<Option<Self>>
    where
        F: Fn(String, Control) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = io::Result<()>> + Send + 'static,
    {
        let (reply, fds) = first;
        let Some(opened) = reply
            .opened
            .filter(|_| reply.phase == SessionPhase::Accepted)
        else {
            return Ok(None);
        };
        let name = opened.session.clone();
        let control = Arc::new(control);
        let controller: Controller =
            Arc::new(move |what| Box::pin((control.clone())(name.clone(), what)));
        Self::new(opened, fds, replies, controller).map(Some)
    }

    /// The session of a first reply, `fds` the descriptors it carried, and
    /// `replies` the replies that follow.
    pub fn new(
        opened: SessionOpened,
        fds: Vec<OwnedFd>,
        replies: Replies,
        controller: Controller,
    ) -> io::Result<Self> {
        let log = match opened.logs {
            Some(at) => Some(
                fds.into_iter()
                    .nth(at as usize)
                    .ok_or_else(|| io::Error::other("the engine opened a session with no log"))?,
            ),
            None => None,
        };
        Ok(Self {
            opened,
            replies,
            log,
            controller,
        })
    }

    /// Whether the output has no frames (a terminal).
    pub fn tty(&self) -> bool {
        self.opened.tty
    }
}

/// Why a session was not opened.
#[derive(Debug)]
pub enum OpenError {
    /// The engine refused the call
    Engine(EngineError),
    /// The connection or the reply is not what the interface says
    Protocol(crate::zlink::Error),
}

/// The first reply of a call that opens a session, and the others as they
/// come to `tx`, until the last, an error or the end of the connection;
/// they are not read when the receiver is dropped (the connection is closed,
/// the client is gone).  The first reply of a session that has no streams
/// (an exec session of `detach`) is the last: `Ok(None)` with its exit.
pub async fn forward<St>(
    replies: St,
    first: oneshot::Sender<Result<Item, OpenError>>,
    tx: mpsc::Sender<Item>,
) where
    St: crate::zlink::futures_util::Stream<
        Item = crate::zlink::Result<(Result<SessionReply, EngineError>, Vec<OwnedFd>)>,
    >,
{
    use crate::zlink::futures_util::StreamExt;
    let mut replies = std::pin::pin!(replies);
    let mut first = Some(first);
    loop {
        let received = tokio::select! {
            r = replies.next() => r,
            () = tx.closed() => return,
        };
        let item = match received {
            None => return,
            Some(Ok((Ok(reply), fds))) => Ok((reply, fds)),
            Some(Ok((Err(e), _))) => Err(OpenError::Engine(e)),
            Some(Err(e)) => Err(OpenError::Protocol(e)),
        };
        match (first.take(), item) {
            (Some(first), item) => {
                let last = !matches!(&item, Ok((r, _)) if r.phase != SessionPhase::Ended);
                if first.send(item).is_err() || last {
                    return;
                }
            }
            (None, Ok(item)) => {
                let last = item.0.phase == SessionPhase::Ended;
                if tx.send(item).await.is_err() || last {
                    return;
                }
            }
            // (an error after the first reply is the end of the session)
            (None, Err(_)) => return,
        }
    }
}

/// The call of a method that opens a session, `conn.method(args)` (the
/// connection is moved to a task that reads the replies, and lives as long as
/// the session): the first reply and the others, or why there is none.
/// The arguments are owned by the caller's block, which the task takes.
#[macro_export]
macro_rules! session_call {
    ($conn:expr, $method:ident ( $($arg:expr),* $(,)? )) => {{
        let mut conn = $conn;
        let (tx, rx) = $crate::stream::replies_channel();
        let (first_tx, first_rx) = $crate::stream::first_channel();
        $crate::stream::spawn_forward(async move {
            match conn.$method($($arg),*).await {
                Ok(replies) => $crate::stream::forward(replies, first_tx, tx).await,
                Err(e) => {
                    let _ = first_tx.send(Err($crate::stream::OpenError::Protocol(e)));
                }
            }
        });
        $crate::stream::first_reply(first_rx, rx)
    }};
}

#[doc(hidden)]
pub fn replies_channel() -> (mpsc::Sender<Item>, Replies) {
    mpsc::channel(QUEUE)
}

#[doc(hidden)]
pub type First = oneshot::Receiver<Result<Item, OpenError>>;

#[doc(hidden)]
pub fn first_channel() -> (oneshot::Sender<Result<Item, OpenError>>, First) {
    oneshot::channel()
}

#[doc(hidden)]
pub fn spawn_forward(task: impl Future<Output = ()> + Send + 'static) {
    tokio::spawn(task);
}

#[doc(hidden)]
pub async fn first_reply(first: First, replies: Replies) -> Result<(Item, Replies), OpenError> {
    match first.await {
        Ok(item) => Ok((item?, replies)),
        Err(_) => Err(OpenError::Protocol(crate::zlink::Error::UnexpectedEof)),
    }
}

/// The input of a client (one type for all: the copy loop is made once).
pub type Reader = Box<dyn AsyncRead + Unpin + Send>;
/// The output of a client.
pub type Writer = Box<dyn AsyncWrite + Unpin + Send>;

/// Where the output of a session goes.
pub enum Output {
    /// One stream of Docker's frames, raw with a terminal (what the
    /// frontends of the API and the CRI send their clients)
    Framed(Writer),
    /// The output of the process and its errors apart, raw (the command
    /// line: its standard output and error)
    Split {
        out: Writer,
        err: Writer,
        /// The frames of the log so far, which the engine writes, cut
        /// into their streams
        unframe: Unframe,
    },
}

impl Output {
    /// The two streams of a command line.
    pub fn split(out: Writer, err: Writer) -> Self {
        Output::Split {
            out,
            err,
            unframe: Unframe::default(),
        }
    }

    /// The log so far, as the frames the engine wrote.
    async fn log(&mut self, bytes: &[u8]) -> io::Result<()> {
        match self {
            Output::Framed(w) => w.write_all(bytes).await,
            Output::Split { out, err, unframe } => {
                for (stream, data) in unframe.push(bytes) {
                    let w = if stream == STDERR {
                        &mut *err
                    } else {
                        &mut *out
                    };
                    w.write_all(&data).await?;
                }
                Ok(())
            }
        }
    }

    /// Write `data` as the stream `which` if the client asked for it: framed,
    /// or raw with a terminal.  `buf` has it from `HEAD` on, `n` bytes.
    async fn emit(
        &mut self,
        tty: bool,
        which: u8,
        wanted: bool,
        buf: &mut [u8],
        n: usize,
    ) -> io::Result<()> {
        if !wanted {
            return Ok(());
        }
        match self {
            Output::Framed(w) => {
                if tty {
                    return w.write_all(&buf[HEAD..HEAD + n]).await;
                }
                buf[..4].copy_from_slice(&[which, 0, 0, 0]);
                buf[4..HEAD].copy_from_slice(&(n as u32).to_be_bytes());
                w.write_all(&buf[..HEAD + n]).await
            }
            // (a terminal has one stream)
            Output::Split { out, err, .. } => {
                let w = if which == STDERR && !tty { err } else { out };
                w.write_all(&buf[HEAD..HEAD + n]).await?;
                w.flush().await
            }
        }
    }

    /// The end of the response: what the engine said, as errors of the
    /// process, and the end of the output.
    async fn finish(&mut self, text: &[u8]) {
        match self {
            Output::Framed(w) => {
                if !text.is_empty() {
                    // (framed also with a terminal)
                    let mut frame = vec![STDERR, 0, 0, 0];
                    frame.extend_from_slice(&(text.len() as u32).to_be_bytes());
                    frame.extend_from_slice(text);
                    let _ = w.write_all(&frame).await;
                }
                let _ = w.shutdown().await;
            }
            Output::Split { out, err, .. } => {
                if !text.is_empty() {
                    let _ = err.write_all(text).await;
                }
                let _ = out.flush().await;
                let _ = err.flush().await;
            }
        }
    }
}

/// Docker's frames cut into (stream, data), whatever the pieces they arrive
/// in.
#[derive(Default)]
pub struct Unframe {
    head: Vec<u8>,
    left: usize,
    stream: u8,
}

impl Unframe {
    /// The data that `bytes` complete or continue, with the stream of each.
    pub fn push(&mut self, mut bytes: &[u8]) -> Vec<(u8, Vec<u8>)> {
        let mut out = Vec::new();
        while !bytes.is_empty() {
            if self.left > 0 {
                let n = self.left.min(bytes.len());
                out.push((self.stream, bytes[..n].to_vec()));
                self.left -= n;
                bytes = &bytes[n..];
                continue;
            }
            let n = (HEAD - self.head.len()).min(bytes.len());
            self.head.extend_from_slice(&bytes[..n]);
            bytes = &bytes[n..];
            if self.head.len() == HEAD {
                self.stream = self.head[0];
                self.left =
                    u32::from_be_bytes([self.head[4], self.head[5], self.head[6], self.head[7]])
                        as usize;
                self.head.clear();
            }
        }
        out
    }
}

/// How a session ended for the client.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Ended {
    /// The status of the process, when the engine said it
    pub exit: Option<i64>,
    /// The client typed the detach keys
    pub detached: bool,
}

/// Copy between the client and the process of the session until the process
/// ends or the client goes away; how it ended for the client is the result.
/// `reader` is the client's input (none: it
/// cannot send any), `output` where its output goes; `peer` is the socket of the
/// client's connection, when it can tell its hang up (not over TCP).  A
/// client that left altogether, at the end of its input or later, closes
/// the channel at once, idle process or not: the process goes on without it
/// (the engine still records the status of an exec's command).  The end of the
/// client's input is passed on (not for an attach that keeps the input of the
/// container open): the process goes on and its output is still sent.  A client that typed the detach keys and goes away before
/// what it typed was written detaches all the same.
pub async fn serve(
    session: Session,
    reader: Option<Reader>,
    writer: Writer,
    peer: Option<OwnedFd>,
) -> Ended {
    serve_to(session, reader, Output::Framed(writer), peer).await
}

/// [`serve`] with the output of the client where `output` says.
pub async fn serve_to(
    session: Session,
    reader: Option<Reader>,
    output: Output,
    peer: Option<OwnedFd>,
) -> Ended {
    let mut ended = Ended::default();
    copy(session, reader, output, peer, &mut ended).await;
    ended
}

async fn copy(
    session: Session,
    reader: Option<Reader>,
    mut writer: Output,
    mut peer: Option<OwnedFd>,
    ended: &mut Ended,
) {
    let Session {
        opened: h,
        mut replies,
        log,
        controller,
    } = session;
    let mut reader = reader;
    let mut left: Left = None;
    if reader.is_none() {
        arm(&mut left, &mut peer);
    }
    let mut said = Vec::new();
    if let Some(fd) = log {
        // the log so far, as the client gets it
        let Ok(log) = Pipe::new(fd) else { return };
        let mut buf = vec![0u8; CHUNK];
        while let Ok(n @ 1..) = log.read(&mut buf).await {
            if writer.log(&buf[..n]).await.is_err() {
                return;
            }
        }
    }
    // The streams: a container that is not started has none until its start
    // (the input its client sends meanwhile is kept for it).
    let mut early = Vec::new();
    let mut early_eof = false;
    let mut input = [0u8; 4096];
    let (stdin, stdout, stderr) = loop {
        tokio::select! {
            // (what the engine told comes first: a client that typed the
            // detach keys and left must be served the streams that are
            // already here, to detach, not dropped at random)
            biased;
            told = told(&mut replies) => match told {
                Told::Streams { stdin, stdout, stderr } => break (stdin, stdout, stderr),
                Told::End(text, exit) => {
                    said.extend(text.unwrap_or_default().into_bytes());
                    ended.exit = exit;
                    return writer.finish(&said).await;
                }
            },
            () = wait_left(&mut left) => return,
            n = read_client(&mut reader, &mut input), if early.len() < EARLY_INPUT_MAX => match n {
                Err(_) => return,
                Ok(0) => {
                    early_eof = true;
                    reader = None;
                    arm(&mut left, &mut peer);
                }
                Ok(n) => {
                    if h.stdin {
                        early.extend_from_slice(&input[..n]);
                    }
                }
            },
        }
    };
    let (mut stdin, mut stdout, mut stderr) = match (
        stdin.map(Pipe::new).transpose(),
        stdout.map(Pipe::new).transpose(),
        stderr.map(Pipe::new).transpose(),
    ) {
        (Ok(i), Ok(o), Ok(e)) => (i, o, e),
        _ => return,
    };
    let mut matcher = DetachMatcher::new(h.detach_keys.clone());
    // What the process has not taken of the input yet, and where.  It takes
    // it at its pace, which may wait for its output to be read: so it is
    // written beside the output, and the client is read for more only when
    // it took all.
    let (mut pending, mut at) = (Vec::new(), 0usize);
    // The client typed the detach keys: it leaves once what it typed before
    // them is written (the output goes on meanwhile).
    let mut detached = false;
    let mut input_ended = early_eof && h.stdin;
    let mut closed = false;
    if h.stdin && stdin.is_some() {
        let (data, keys) = matcher.feed(&early);
        pending = data;
        detached = keys;
    }
    let (mut out_buf, mut err_buf) = (vec![0u8; HEAD + CHUNK], vec![0u8; HEAD + CHUNK]);
    loop {
        let flushed = at >= pending.len();
        if flushed {
            pending.clear();
            at = 0;
        }
        if detached && flushed {
            // (answered once the engine told the monitor: the streams stay
            // open until then, so that the monitor hears of the detach first)
            ended.detached = true;
            let _ = tokio::join!(controller(Control::Detach), writer.finish(&said));
            return;
        }
        if input_ended && flushed {
            input_ended = false;
            if !h.keep_open {
                // (the pipe is closed here; the engine tells the monitor)
                stdin = None;
                // (not waited for: the output goes on meanwhile)
                tokio::spawn(controller(Control::CloseStdin));
            }
        }
        if stdout.is_none() && stderr.is_none() && closed {
            return writer.finish(&said).await;
        }
        // (the client went away: one that typed the keys detaches without
        // waiting for the process to take what it typed before them)
        let gone = tokio::select! {
            () = wait_left(&mut left) => true,
            n = output(&mut stdout, &mut out_buf) => {
                n > 0 && writer.emit(h.tty, STDOUT, h.stdout, &mut out_buf, n).await.is_err()
            }
            n = output(&mut stderr, &mut err_buf) => {
                n > 0 && writer.emit(h.tty, STDERR, h.stderr, &mut err_buf, n).await.is_err()
            }
            told = told(&mut replies), if !closed => {
                match told {
                    Told::Streams { .. } => {}
                    Told::End(text, exit) => {
                        said.extend(text.unwrap_or_default().into_bytes());
                        ended.exit = exit;
                        closed = true;
                    }
                }
                false
            }
            r = write_some(&stdin, &pending[at..]), if !flushed => {
                match r {
                    Ok(n) => at += n,
                    Err(_) => {
                        // the process takes no more input; its output goes on
                        stdin = None;
                        pending.clear();
                        at = 0;
                        reader = None;
                        arm(&mut left, &mut peer);
                    }
                }
                false
            }
            n = read_client(&mut reader, &mut input), if flushed => {
                match n {
                    Ok(n) if n > 0 => {
                        if h.stdin && stdin.is_some() {
                            let (data, keys) = matcher.feed(&input[..n]);
                            pending = data;
                            at = 0;
                            if keys {
                                // what was typed before the keys goes first
                                detached = true;
                                reader = None;
                                arm(&mut left, &mut peer);
                            }
                        }
                    }
                    _ => {
                        reader = None;
                        input_ended = h.stdin;
                        arm(&mut left, &mut peer);
                    }
                }
                false
            }
        };
        if gone {
            if !detached {
                return;
            }
            pending.clear();
            at = 0;
            left = None;
        }
    }
}

/// The streams of a reply as a connection of this process: a socket whose
/// other end is served as [`serve`] does (`input`: the client can send
/// input).  The socket's output is Docker's frames, or raw with a terminal;
/// when it is closed the session sees its client leave.  Must be called
/// within a tokio runtime.
pub fn connect(session: Session, input: bool) -> io::Result<tokio::net::UnixStream> {
    let (mine, theirs) = tokio::net::UnixStream::pair()?;
    // (a descriptor of its own to watch for the client leaving)
    let peer = mine.as_fd().try_clone_to_owned()?;
    let (r, w) = mine.into_split();
    let reader = input.then(|| Box::new(r) as Reader);
    spawn(session, reader, Box::new(w), Some(peer));
    Ok(theirs)
}

/// [`serve`] in a task of its own, the one place where the copy loop is made
/// (each future that awaited it would carry a copy of it).  Must be called
/// within a tokio runtime.
pub fn spawn(
    session: Session,
    reader: Option<Reader>,
    writer: Writer,
    peer: Option<OwnedFd>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        serve(session, reader, writer, peer).await;
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::time::Duration;
    use tokio::io::AsyncReadExt;

    fn opened() -> SessionOpened {
        SessionOpened {
            session: "s".into(),
            tty: false,
            stdin: true,
            stdout: true,
            stderr: true,
            logs: None,
            detach_keys: Vec::new(),
            keep_open: false,
        }
    }

    /// The frontend's session and the engine's end of it (the replies and
    /// the calls of the frontend go straight from one to the other).
    fn session(h: SessionOpened) -> (Session, Out) {
        let (session, engine, _) = session_with_log(h, None);
        (session, engine)
    }

    fn session_with_log(h: SessionOpened, log: Option<OwnedFd>) -> (Session, Out, Controls) {
        let mut h = h;
        h.logs = log.as_ref().map(|_| 0);
        let (engine, mut replies, controls) = out(h, log);
        let (opened, fds) = {
            let (r, fds) = replies.try_recv().unwrap();
            (r.opened.unwrap(), fds)
        };
        let to = controls.clone();
        let controller: Controller = Arc::new(move |c| {
            let to = to.clone();
            Box::pin(async move {
                call(&to, c)
                    .await
                    .then_some(())
                    .ok_or_else(|| io::ErrorKind::BrokenPipe.into())
            })
        });
        (
            Session::new(opened, fds, replies, controller).unwrap(),
            engine,
            controls,
        )
    }

    fn pipe(size: usize) -> (OwnedFd, OwnedFd) {
        let (r, w) = rustix::pipe::pipe().unwrap();
        rustix::pipe::fcntl_setpipe_size(&r, size).unwrap();
        (r, w)
    }

    /// A monitor that is a `cat` with pipes of one page: it reads its input
    /// only to write it to its output; it writes `first` (a banner) before it
    /// reads, and ends with its input.  The descriptors for the frontend are
    /// sent by the engine's end.
    async fn cat_monitor(engine: &Out, first: Vec<u8>) -> std::thread::JoinHandle<()> {
        let (in_r, in_w) = pipe(4096);
        let (out_r, out_w) = pipe(4096);
        engine
            .send_streams(
                Some(in_w.try_clone().unwrap()),
                Some(out_r.try_clone().unwrap()),
                None,
            )
            .await
            .unwrap();
        drop((in_w, out_r));
        std::thread::spawn(move || {
            let mut input = std::fs::File::from(in_r);
            let mut output = std::fs::File::from(out_w);
            let mut buf = [0u8; 4096];
            let mut wrote = output.write_all(&first);
            while wrote.is_ok() {
                match input.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    // (a client that left takes the output along)
                    Ok(n) => wrote = output.write_all(&buf[..n]),
                }
            }
        })
    }

    #[tokio::test]
    async fn the_input_is_in_order_and_the_output_goes_on() {
        // (the client sends much more than the pipes hold, and reads the
        // output slowly: the input waits for the command, which waits for its
        // output to be read)
        const SIZE: usize = 8 << 20;
        let want: Vec<u8> = (0..SIZE).map(|i| (i / 7 % 251) as u8).collect();
        let mut h = opened();
        h.tty = true;
        let (session, engine) = session(h);
        let (mut client_in, relay_in) = tokio::io::duplex(1024);
        let (relay_out, mut client_out) = tokio::io::duplex(4096);
        let serving = tokio::spawn(serve(
            session,
            Some(Box::new(relay_in)),
            Box::new(relay_out),
            None,
        ));
        // What the client sends before the streams are there: the write
        // returns once more than the buffer was read, by the frontend.
        let (early, sent) = want.split_at(3000);
        client_in.write_all(early).await.unwrap();
        let monitor = cat_monitor(&engine, Vec::new()).await;
        let sent = sent.to_vec();
        let feeder = tokio::spawn(async move {
            let _ = client_in.write_all(&sent).await;
            let _ = client_in.shutdown().await;
        });
        // (an upper bound: a copy that cannot write the input before it reads
        // the output waits for ever)
        let got = tokio::time::timeout(Duration::from_secs(20), async {
            let mut got = Vec::new();
            client_out.read_to_end(&mut got).await.unwrap();
            got
        });
        // (the session is over when the monitor is: its end closes)
        let over = tokio::spawn(async move {
            assert_eq!(engine.event().await, Event::InputClosed);
            tokio::task::spawn_blocking(move || monitor.join().unwrap())
                .await
                .unwrap();
        });
        let got = got
            .await
            .expect("the input and the output waited for each other");
        let at = got.iter().zip(&want).position(|(a, b)| a != b);
        assert_eq!((at, got.len()), (None, want.len()), "first difference");
        feeder.await.unwrap();
        over.await.unwrap();
        serving.await.unwrap();
    }

    #[tokio::test]
    async fn a_detach_with_input_waiting_lets_the_output_go_on() {
        // (the container writes a banner before it reads; the client fills
        // the pipe of the input, then types more and the detach keys: what it
        // typed before them goes in while the output is read, and the client
        // leaves then, the streams staying open until the engine says so)
        let banner = vec![b'='; 1 << 20];
        let mut h = opened();
        h.tty = true;
        h.detach_keys = vec![0x10, 0x11];
        let (session, engine) = session(h);
        let (mut client_in, relay_in) = tokio::io::duplex(1 << 20);
        let (relay_out, mut client_out) = tokio::io::duplex(4096);
        let serving = tokio::spawn(serve(
            session,
            Some(Box::new(relay_in)),
            Box::new(relay_out),
            None,
        ));
        let monitor = cat_monitor(&engine, banner.clone()).await;
        let mut want = banner;
        want.extend_from_slice(&[b'a'; 4096]);
        want.extend_from_slice(&[b'b'; 100]);
        let mut typed = vec![b'a'; 4096];
        typed.extend_from_slice(&[b'b'; 100]);
        typed.extend_from_slice(&[0x10, 0x11]);
        client_in.write_all(&typed).await.unwrap();
        let got = tokio::time::timeout(Duration::from_secs(20), async {
            let mut got = Vec::new();
            client_out.read_to_end(&mut got).await.unwrap();
            got
        })
        .await
        .expect("the detach waited for the input, the input for the output");
        // (the response ended: the engine was told before the streams closed)
        assert_eq!(engine.event().await, Event::Detach);
        drop(engine);
        serving.await.unwrap();
        assert!(got.len() <= want.len() && got[..] == want[..got.len()]);
        drop(client_in);
        monitor.join().unwrap();
    }

    #[tokio::test]
    async fn a_client_that_typed_the_keys_and_left_detaches() {
        // (the process does not read its input, whose pipe is full: what the
        // client typed before the keys waits, and the client goes away
        // meanwhile)
        let mut h = opened();
        h.tty = true;
        h.detach_keys = vec![0x10, 0x11];
        let (session, engine) = session(h);
        let (_mon_in, stdin) = pipe(4096);
        let (_mon_out, out) = std::os::unix::net::UnixStream::pair().unwrap();
        engine
            .send_streams(
                Some(stdin.try_clone().unwrap()),
                Some(OwnedFd::from(out)),
                None,
            )
            .await
            .unwrap();
        std::fs::File::from(stdin).write_all(&[b'='; 4096]).unwrap();
        let (client, served) = tokio::net::UnixStream::pair().unwrap();
        let peer = std::os::fd::AsFd::as_fd(&served)
            .try_clone_to_owned()
            .unwrap();
        let (r, w) = served.into_split();
        let serving = tokio::spawn(serve(session, Some(Box::new(r)), Box::new(w), Some(peer)));
        let (_, mut to) = client.into_split();
        let mut typed = b"ls".to_vec();
        typed.extend_from_slice(&[0x10, 0x11]);
        to.write_all(&typed).await.unwrap();
        drop(to);
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(5), engine.event())
                .await
                .expect("the session waited for input nobody takes"),
            Event::Detach
        );
        drop(engine);
        serving.await.unwrap();
    }

    /// The output as Docker's frames: the streams asked for, each read as a
    /// frame, and what the engine says as the errors of the process.
    #[tokio::test]
    async fn the_output_is_framed_filtered_and_ends_with_the_engine() {
        let mut h = opened();
        h.stderr = false;
        let (session, engine) = session(h);
        let (mut mon_out, out) = std::os::unix::net::UnixStream::pair().unwrap();
        let (mut mon_err, err) = std::os::unix::net::UnixStream::pair().unwrap();
        engine
            .send_streams(None, Some(OwnedFd::from(out)), Some(OwnedFd::from(err)))
            .await
            .unwrap();
        engine.send_text("exec: boom\n").await.unwrap();
        let (relay_out, mut client_out) = tokio::io::duplex(4096);
        let serving = tokio::spawn(serve(session, None, Box::new(relay_out), None));
        mon_out.write_all(b"hello").unwrap();
        mon_err.write_all(b"hidden").unwrap();
        drop((mon_out, mon_err));
        // (the output ended: the response waits for the engine's end)
        let mut head = [0u8; 13];
        client_out.read_exact(&mut head).await.unwrap();
        assert_eq!(&head, b"\x01\0\0\0\0\0\0\x05hello");
        assert!(!serving.is_finished());
        drop(engine);
        let mut rest = Vec::new();
        client_out.read_to_end(&mut rest).await.unwrap();
        assert_eq!(rest, b"\x02\0\0\0\0\0\0\x0bexec: boom\n");
        serving.await.unwrap();
    }

    #[tokio::test]
    async fn a_terminal_is_raw_and_the_input_end_is_told() {
        let mut h = opened();
        h.tty = true;
        let (session, engine) = session(h);
        let (mon_in, stdin) = pipe(4096);
        let (mut mon_out, out) = std::os::unix::net::UnixStream::pair().unwrap();
        engine
            .send_streams(
                Some(stdin.try_clone().unwrap()),
                Some(OwnedFd::from(out)),
                None,
            )
            .await
            .unwrap();
        drop(stdin);
        let (mut client_in, relay_in) = tokio::io::duplex(1024);
        let (relay_out, mut client_out) = tokio::io::duplex(4096);
        let serving = tokio::spawn(serve(
            session,
            Some(Box::new(relay_in)),
            Box::new(relay_out),
            None,
        ));
        client_in.write_all(b"typed").await.unwrap();
        client_in.shutdown().await.unwrap();
        // (the end of the input is written after what was typed; the pipe
        // is closed here and the engine tells the monitor)
        assert_eq!(engine.event().await, Event::InputClosed);
        let mut got = Vec::new();
        std::fs::File::from(mon_in).read_to_end(&mut got).unwrap();
        assert_eq!(got, b"typed");
        mon_out.write_all(b"raw").unwrap();
        drop(mon_out);
        drop(engine);
        let mut shown = Vec::new();
        client_out.read_to_end(&mut shown).await.unwrap();
        assert_eq!(shown, b"raw");
        serving.await.unwrap();
    }

    #[tokio::test]
    async fn an_attach_that_keeps_the_input_open_goes_on_after_the_client_input() {
        let mut h = opened();
        h.keep_open = true;
        let (session, engine) = session(h);
        let (_mon_in, stdin) = pipe(4096);
        let (mut mon_out, out) = std::os::unix::net::UnixStream::pair().unwrap();
        engine
            .send_streams(
                Some(stdin.try_clone().unwrap()),
                Some(OwnedFd::from(out)),
                None,
            )
            .await
            .unwrap();
        let (mut client_in, relay_in) = tokio::io::duplex(1024);
        let (relay_out, mut client_out) = tokio::io::duplex(4096);
        let serving = tokio::spawn(serve(
            session,
            Some(Box::new(relay_in)),
            Box::new(relay_out),
            None,
        ));
        client_in.shutdown().await.unwrap();
        // (the end of the client's input is not the end of the output: what
        // the process prints afterwards, for `kubectl attach -i < file`,
        // is sent, and the input of the container stays open)
        mon_out.write_all(b"after").unwrap();
        drop(mon_out);
        drop(engine);
        let mut shown = Vec::new();
        client_out.read_to_end(&mut shown).await.unwrap();
        assert_eq!(shown, b"\x01\0\0\0\0\0\0\x05after");
        serving.await.unwrap();
    }

    /// The engine sees a client that left, also an idle one, at its input's
    /// end or not, and a client that did not close its output is still there.
    #[tokio::test]
    async fn a_client_that_leaves_is_told_to_the_engine() {
        // (no input for the process: the end of the client's input is not
        // told)
        let mut h = opened();
        h.stdin = false;
        let (session, engine) = session(h);
        let (_mon_out, out) = std::os::unix::net::UnixStream::pair().unwrap();
        engine
            .send_streams(None, Some(OwnedFd::from(out)), None)
            .await
            .unwrap();
        let (client, served) = tokio::net::UnixStream::pair().unwrap();
        let peer = std::os::fd::AsFd::as_fd(&served)
            .try_clone_to_owned()
            .unwrap();
        let (r, w) = served.into_split();
        let serving = tokio::spawn(serve(session, Some(Box::new(r)), Box::new(w), Some(peer)));
        let (mut from, mut to) = client.into_split();
        to.shutdown().await.unwrap();
        // (a half close: the output is still sent)
        assert!(
            tokio::time::timeout(Duration::from_millis(200), engine.event())
                .await
                .is_err(),
            "a half close is not leaving"
        );
        drop((from.read(&mut [0u8; 1]), to));
        drop(from);
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(5), engine.event())
                .await
                .expect("the full close is seen without polling"),
            Event::Gone
        );
        serving.await.unwrap();
    }

    #[tokio::test]
    async fn the_socket_of_a_session_without_input_ends_with_its_client() {
        let mut h = opened();
        h.stdin = false;
        let (session, engine) = session(h);
        let client = connect(session, false).unwrap();
        // (no streams yet: the client leaves a session that waits for its
        // process)
        drop(client);
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(5), engine.event())
                .await
                .expect("the engine was not told"),
            Event::Gone
        );
    }

    #[tokio::test]
    async fn the_log_comes_first_and_a_session_that_never_started_ends() {
        let (log_r, log_w) = pipe(4096);
        let (session, engine, _) = session_with_log(opened(), Some(log_r));
        let (relay_out, mut client_out) = tokio::io::duplex(4096);
        let serving = tokio::spawn(serve(session, None, Box::new(relay_out), None));
        std::fs::File::from(log_w)
            .write_all(b"\x01\0\0\0\0\0\0\x02hi")
            .unwrap();
        // (the container does not start: the engine closes the channel)
        drop(engine);
        let mut shown = Vec::new();
        client_out.read_to_end(&mut shown).await.unwrap();
        assert_eq!(shown, b"\x01\0\0\0\0\0\0\x02hi");
        serving.await.unwrap();
    }

    #[tokio::test]
    async fn a_client_that_left_is_told_from_one_that_closed_its_output() {
        use std::os::fd::AsFd;
        let (a, b) = std::os::unix::net::UnixStream::pair().unwrap();
        assert!(!hung_up(a.as_fd()));
        b.shutdown(std::net::Shutdown::Write).unwrap();
        assert!(!hung_up(a.as_fd()), "a half close is not a hang up");
        let mut left = Box::pin(hang_up(Some(a.as_fd().try_clone_to_owned().unwrap())));
        let waited = tokio::time::timeout(Duration::from_millis(200), &mut left).await;
        assert!(waited.is_err(), "a half close is not leaving");
        drop(b);
        assert!(hung_up(a.as_fd()));
        tokio::time::timeout(Duration::from_secs(5), left)
            .await
            .expect("the full close is seen without polling");
        let waited = tokio::time::timeout(Duration::from_millis(50), hang_up(None)).await;
        assert!(waited.is_err(), "no socket: it cannot tell");
    }

    /// The output of a command line is two streams, not frames, and the
    /// session says how it ended.
    #[tokio::test]
    async fn the_output_can_be_two_streams_and_the_end_is_returned() {
        let (session, engine) = session(opened());
        let (mut mon_out, out) = std::os::unix::net::UnixStream::pair().unwrap();
        let (mut mon_err, err) = std::os::unix::net::UnixStream::pair().unwrap();
        engine
            .send_streams(None, Some(OwnedFd::from(out)), Some(OwnedFd::from(err)))
            .await
            .unwrap();
        mon_out.write_all(b"hello").unwrap();
        mon_err.write_all(b"oops").unwrap();
        drop((mon_out, mon_err));
        let (out_w, mut out_r) = tokio::io::duplex(4096);
        let (err_w, mut err_r) = tokio::io::duplex(4096);
        let serving = tokio::spawn(serve_to(
            session,
            None,
            Output::split(Box::new(out_w), Box::new(err_w)),
            None,
        ));
        engine.send_text("said\n").await.unwrap();
        engine.end(Some(3)).await;
        let ended = serving.await.unwrap();
        assert_eq!(
            ended,
            Ended {
                exit: Some(3),
                detached: false
            }
        );
        let (mut got, mut errs) = (Vec::new(), Vec::new());
        out_r.read_to_end(&mut got).await.unwrap();
        err_r.read_to_end(&mut errs).await.unwrap();
        assert_eq!(got, b"hello");
        assert_eq!(errs, b"oopssaid\n");
    }

    #[test]
    fn frames_are_cut_into_their_streams_in_any_pieces() {
        let mut all = b"\x01\0\0\0\0\0\0\x03abc".to_vec();
        all.extend_from_slice(b"\x02\0\0\0\0\0\0\x02de");
        for size in [1, 3, 8, 100] {
            let mut u = Unframe::default();
            let (mut out, mut err) = (Vec::new(), Vec::new());
            for piece in all.chunks(size) {
                for (stream, data) in u.push(piece) {
                    if stream == 2 { &mut err } else { &mut out }.extend(data);
                }
            }
            assert_eq!(
                (out, err),
                (b"abc".to_vec(), b"de".to_vec()),
                "pieces of {size}"
            );
        }
    }
}
