// SPDX-License-Identifier: Apache-2.0
//! The engine's side of `org.velarx.Monitor` on the runtime: a connection
//! whose replies (the events of `Subscribe`, the start and the end of an
//! attach or exec session) are read without blocking a thread, the
//! `oneway` calls sent on it, and the pipes of a session.  The connection
//! is opened, and the first reply (with the descriptors of the pipes) read,
//! by the blocking client of `velarx_wire::monitor::client`.

use std::io;
use std::os::fd::OwnedFd;
use std::sync::{Arc, Mutex};

use serde::de::DeserializeOwned;
use serde::Serialize;
use velarx_wire::monitor::client::{self, Streams};
use velarx_wire::monitor::iface::{self, ExecReason};
use velarx_wire::varlink::{parse_reply, CallError, Reply};

/// The most of a message of a monitor.
const MAX_MESSAGE: usize = 1 << 20;
/// What one read of a pipe takes.
const CHUNK: usize = 64 * 1024;

/// A connection to a monitor, polled by the runtime.
pub struct MonitorConn {
    stream: tokio::net::UnixStream,
    buf: Vec<u8>,
}

fn monitor_io(e: CallError) -> io::Error {
    match e {
        CallError::Io(e) => e,
        CallError::Protocol(m) => io::Error::other(client::MonitorError::Protocol(m)),
        CallError::Remote { error, reason } => {
            io::Error::other(client::MonitorError::Remote { error, reason })
        }
    }
}

fn encode_call<P: Serialize>(
    method: &str,
    parameters: &P,
    more: bool,
    oneway: bool,
) -> io::Result<Vec<u8>> {
    #[derive(Serialize)]
    struct Wire<'a, P> {
        method: &'a str,
        parameters: &'a P,
        #[serde(skip_serializing_if = "std::ops::Not::not")]
        more: bool,
        #[serde(skip_serializing_if = "std::ops::Not::not")]
        oneway: bool,
    }
    let mut bytes = serde_json::to_vec(&Wire {
        method,
        parameters,
        more,
        oneway,
    })
    .map_err(io::Error::other)?;
    bytes.push(0);
    Ok(bytes)
}

impl MonitorConn {
    /// Go on with a connection the blocking client opened (`rest`: what it
    /// read and did not take).
    pub fn new(stream: std::os::unix::net::UnixStream, rest: Vec<u8>) -> io::Result<Self> {
        stream.set_nonblocking(true)?;
        Ok(Self {
            stream: tokio::net::UnixStream::from_std(stream)?,
            buf: rest,
        })
    }

    /// The engine's own first connection of a monitor: its `Create` (with
    /// the checkpoint to `restore`) and its `Subscribe` are written on it
    /// before the monitor serves it.  The first reply is the result of the
    /// creation.
    pub fn boot(
        stream: std::os::unix::net::UnixStream,
        restore: Option<&client::Restore>,
    ) -> io::Result<Self> {
        client::write_boot_calls(&stream, restore)?;
        Self::new(stream, Vec::new())
    }

    /// The next reply; `None` when the monitor hung up.  Cancel safe: what
    /// was read stays for the next call.
    pub async fn next<T: DeserializeOwned>(&mut self) -> io::Result<Option<Reply<T>>> {
        loop {
            if let Some(end) = self.buf.iter().position(|&b| b == 0) {
                let reply = parse_reply(&self.buf[..end]).map(Some).map_err(monitor_io);
                self.buf.drain(..=end);
                return reply;
            }
            if self.buf.len() > MAX_MESSAGE {
                return Err(io::Error::other(client::MonitorError::Protocol(
                    "a message too large".into(),
                )));
            }
            self.stream.readable().await?;
            let mut chunk = [0u8; 16 * 1024];
            match self.stream.try_read(&mut chunk) {
                Ok(0) => return Ok(None),
                Ok(n) => self.buf.extend_from_slice(&chunk[..n]),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(e) if e.kind() == io::ErrorKind::ConnectionReset => return Ok(None),
                Err(e) => return Err(e),
            }
        }
    }

    /// Send a call that has no reply.
    pub async fn oneway<M: velarx_wire::varlink::Method>(&self, m: &M) -> io::Result<()> {
        let bytes = encode_call(&format!("{}.{}", M::INTERFACE, M::NAME), m, false, true)?;
        let mut at = 0;
        while at < bytes.len() {
            self.stream.writable().await?;
            match self.stream.try_write(&bytes[at..]) {
                Ok(n) => at += n,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }
}

/// What a session tells.
#[derive(Debug)]
pub(in crate::services) enum Told {
    Stdout(Vec<u8>),
    Stderr(Vec<u8>),
    /// The runtime started the command of an exec session.
    Started,
    /// The last reply, once the pipes are read to their end.
    End {
        code: i32,
        reason: ExecReason,
        started: bool,
        /// The session did not read its output fast enough: its streams
        /// ended early.
        output_dropped: bool,
    },
}

/// An attach or exec session: its connection and its pipes.
pub(in crate::services) struct Session {
    conn: MonitorConn,
    exec: bool,
    stdout: Option<OneWay>,
    stderr: Option<OneWay>,
    stdin: Mutex<Option<Arc<OneWay>>>,
    /// The last reply came (or the monitor hung up: none).
    ended: Option<Option<Told>>,
}

/// A stream of a session, one way: a socket the monitor made, or the pipe
/// of a command's input that it passed on.
type OneWay = tokio::io::unix::AsyncFd<OwnedFd>;

fn one_way(fd: Option<OwnedFd>) -> io::Result<Option<OneWay>> {
    fd.map(|fd| {
        rustix::fs::fcntl_setfl(&fd, rustix::fs::OFlags::NONBLOCK)?;
        velarx_sys::fd::register(
            fd,
            tokio::io::Interest::READABLE | tokio::io::Interest::WRITABLE,
        )
    })
    .transpose()
}

async fn read_pipe(p: &mut Option<OneWay>) -> io::Result<Option<Vec<u8>>> {
    let Some(r) = p.as_ref() else {
        return std::future::pending().await;
    };
    let got = loop {
        let mut guard = r.readable().await?;
        let mut buf = vec![0u8; CHUNK];
        match guard.try_io(|fd| rustix::io::read(fd.get_ref(), &mut buf).map_err(io::Error::from)) {
            Ok(Ok(0)) | Ok(Err(_)) => break None,
            Ok(Ok(n)) => {
                buf.truncate(n);
                break Some(buf);
            }
            Err(_would_block) => {}
        }
    };
    if got.is_none() {
        *p = None;
    }
    Ok(got)
}

/// The input of a session on its way to the monitor: what the client sent
/// and the pipe did not take yet.  The pipe takes it at the pace of the
/// command, which may wait for its output to be read: so the session is
/// read while this waits ([`flush`](Self::flush) is a branch of the same
/// `select!` as [`Session::next`]), and the client is read for more only
/// when this is empty.
pub struct Input {
    pipe: Option<Arc<OneWay>>,
    buf: Vec<u8>,
    at: usize,
    ended: bool,
}

impl Input {
    /// Everything given to [`queue`](Self::queue) is in the pipe.
    pub fn is_empty(&self) -> bool {
        self.at >= self.buf.len()
    }

    /// Bytes for the command (dropped when its input is closed).
    pub fn queue(&mut self, data: &[u8]) {
        if self.pipe.is_none() {
            return;
        }
        if self.is_empty() {
            self.buf.clear();
            self.at = 0;
        }
        self.buf.extend_from_slice(data);
    }

    /// The client's input ended: [`take_end`](Self::take_end) says when what
    /// was queued is written.
    pub fn end(&mut self) {
        self.ended = true;
    }

    /// True once, when the input has ended and everything is written: the
    /// pipe is closed here (the session's `eof` tells the monitor).
    pub fn take_end(&mut self) -> bool {
        if self.ended && self.is_empty() {
            self.ended = false;
            self.pipe = None;
            return true;
        }
        false
    }

    /// Write some of what is queued, once the pipe takes it; never ready
    /// while nothing is queued.  An error: the command does not take input
    /// any more (what is queued is dropped).  Cancel safe.
    pub async fn flush(&mut self) -> io::Result<()> {
        let Some(pipe) = self.pipe.clone().filter(|_| !self.is_empty()) else {
            return std::future::pending().await;
        };
        loop {
            let mut guard = pipe.writable().await?;
            let at = self.at;
            match guard.try_io(|fd| {
                rustix::io::write(fd.get_ref(), &self.buf[at..]).map_err(io::Error::from)
            }) {
                Ok(Ok(n)) => {
                    self.at += n;
                    return Ok(());
                }
                Ok(Err(e)) => {
                    self.pipe = None;
                    self.buf.clear();
                    self.at = 0;
                    return Err(e);
                }
                Err(_would_block) => {}
            }
        }
    }
}

impl Session {
    /// A session the blocking client opened.
    pub fn new(
        conn: velarx_wire::varlink::Conn,
        streams: Streams,
        exec: bool,
        exit: Option<i32>,
    ) -> io::Result<Self> {
        let (stream, rest) = conn.into_parts();
        Ok(Self {
            conn: MonitorConn::new(stream, rest)?,
            exec,
            stdout: one_way(streams.stdout)?,
            stderr: one_way(streams.stderr)?,
            stdin: Mutex::new(one_way(streams.stdin)?.map(Arc::new)),
            ended: exit.map(|code| {
                Some(Told::End {
                    code,
                    reason: ExecReason::Exited,
                    started: true,
                    output_dropped: false,
                })
            }),
        })
    }

    /// The last reply's end, from a reply.
    fn end_of(&self, bytes: Reply<serde_json::Value>) -> io::Result<Option<Told>> {
        let bad =
            |e: serde_json::Error| io::Error::other(client::MonitorError::Protocol(e.to_string()));
        if self.exec {
            let r: iface::ExecReply = serde_json::from_value(bytes.parameters).map_err(bad)?;
            if let Some(e) = r.exit {
                return Ok(Some(Told::End {
                    code: e.code,
                    reason: e.reason,
                    started: e.started,
                    output_dropped: r.output_dropped,
                }));
            }
            Ok((r.phase == iface::SessionPhase::Started).then_some(Told::Started))
        } else {
            let r: iface::AttachReply = serde_json::from_value(bytes.parameters).map_err(bad)?;
            Ok(r.exit.map(|code| Told::End {
                code,
                reason: ExecReason::Exited,
                started: true,
                output_dropped: r.output_dropped,
            }))
        }
    }

    /// The next thing the session tells; `None` when the monitor went away
    /// without its last reply.  The output that came before the last reply
    /// is all told before it.
    pub async fn next(&mut self) -> io::Result<Option<Told>> {
        loop {
            if let Some(end) = &mut self.ended {
                if self.stdout.is_none() && self.stderr.is_none() {
                    return Ok(end.take());
                }
            }
            let open = self.ended.is_none();
            tokio::select! {
                d = read_pipe(&mut self.stdout) => {
                    if let Some(d) = d? {
                        return Ok(Some(Told::Stdout(d)));
                    }
                }
                d = read_pipe(&mut self.stderr) => {
                    if let Some(d) = d? {
                        return Ok(Some(Told::Stderr(d)));
                    }
                }
                r = self.conn.next::<serde_json::Value>(), if open => {
                    match r? {
                        None => self.ended = Some(None),
                        Some(r) => match self.end_of(r)? {
                            Some(Told::Started) => return Ok(Some(Told::Started)),
                            Some(end) => self.ended = Some(Some(end)),
                            None => {}
                        },
                    }
                }
            }
        }
    }

    /// The pipe of the input of the session, to write to it from where the
    /// session is read too ([`Input`]); none when the session has no input
    /// or it ended.
    pub fn input(&self) -> Input {
        let pipe = self.stdin.lock().unwrap_or_else(|p| p.into_inner()).clone();
        Input {
            pipe,
            buf: Vec::new(),
            at: 0,
            ended: false,
        }
    }

    /// The input ends.
    pub async fn eof(&self) -> io::Result<()> {
        let had = self.stdin.lock().unwrap_or_else(|p| p.into_inner()).take();
        if had.is_none() {
            return Ok(());
        }
        drop(had);
        self.conn.oneway(&iface::CloseStdin {}).await
    }

    /// The input ends, for a session whose pipes someone else holds (see
    /// [`Streams`]): the monitor closes the input of the process.
    pub async fn close_stdin(&self) -> io::Result<()> {
        self.conn.oneway(&iface::CloseStdin {}).await
    }

    /// The session of an exec goes on without its client (its output is
    /// dropped).
    pub async fn detach(&self) -> io::Result<()> {
        self.conn.oneway(&iface::Detach {}).await
    }

    pub async fn resize(&self, rows: u16, cols: u16) -> io::Result<()> {
        self.conn.oneway(&iface::ResizeParams { rows, cols }).await
    }

    pub async fn signal(&self, signal: i32) -> io::Result<()> {
        self.conn.oneway(&iface::SignalParams { signal }).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input_of(pipe: OwnedFd) -> Input {
        Input {
            pipe: Some(Arc::new(one_way(Some(pipe)).unwrap().unwrap())),
            buf: Vec::new(),
            at: 0,
            ended: false,
        }
    }

    #[tokio::test]
    async fn input_is_written_as_the_pipe_takes_it() {
        let (r, w) = rustix::pipe::pipe_with(rustix::pipe::PipeFlags::CLOEXEC).unwrap();
        rustix::pipe::fcntl_setpipe_size(&w, 4096).unwrap();
        let mut input = input_of(w);
        let want: Vec<u8> = (0..1_000_000u32).map(|i| (i % 253) as u8).collect();
        input.queue(&want);
        let mut reader = tokio::net::unix::pipe::Receiver::from_owned_fd(r).unwrap();
        let mut got = Vec::new();
        let mut buf = [0u8; 1000];
        // (nothing is read until the writer has to wait: the pipe is full)
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(50), async {
                while !input.is_empty() {
                    input.flush().await.unwrap();
                }
            })
            .await
            .is_err()
        );
        assert!(!input.is_empty());
        while !input.is_empty() {
            tokio::select! {
                r = input.flush() => r.unwrap(),
                n = tokio::io::AsyncReadExt::read(&mut reader, &mut buf) => {
                    got.extend_from_slice(&buf[..n.unwrap()]);
                }
            }
        }
        // the end of the input comes once all is written
        input.end();
        assert!(input.take_end());
        assert!(!input.take_end());
        while got.len() < want.len() {
            let n = tokio::io::AsyncReadExt::read(&mut reader, &mut buf)
                .await
                .unwrap();
            assert_ne!(n, 0, "the pipe ended with {} bytes", got.len());
            got.extend_from_slice(&buf[..n]);
        }
        assert!(got == want, "the bytes differ");
        // the pipe is closed with the end: the reader sees it
        assert_eq!(
            tokio::io::AsyncReadExt::read(&mut reader, &mut buf)
                .await
                .unwrap(),
            0
        );
    }

    #[test]
    fn input_of_a_command_that_took_no_more_is_dropped() {
        // (in a process of its own: a process another test forks holds a
        // copy of the read end until its exec, and the write would not
        // find the pipe closed)
        velarx_base::testing::in_child(|| {
            crate::testing::block_on(async {
                let (r, w) = rustix::pipe::pipe().unwrap();
                let mut input = input_of(w);
                drop(r);
                input.queue(b"abc");
                assert!(input.flush().await.is_err());
                assert!(input.is_empty());
                input.queue(b"def");
                assert!(input.is_empty(), "no pipe, no input");
            });
        });
    }
}
