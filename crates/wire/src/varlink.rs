// SPDX-License-Identifier: Apache-2.0
//! Blocking varlink: std, rustix and serde_json only, for the processes that
//! run no async runtime.  The client ([`Conn`]) is what the monitor of a
//! container asks the fetchers with, and what the command line and the
//! engine ask a monitor with (the command line asks the engine through the
//! zlink proxy and only borrows [`CallError`]); the server side is the encoding of the
//! messages ([`parse_call`], [`encode_reply`], [`encode_error`]), which the
//! poll loop of the monitor drives.
//!
//! A varlink message is a JSON object ended by a NUL byte; the descriptors
//! of a message cross in the `SCM_RIGHTS` of the `sendmsg` that carries it.
//! Linux ends a read of a stream socket after the bytes that came with
//! descriptors, and those bytes begin a message (one `sendmsg` for a
//! message with descriptors), so the descriptors of a read are those of
//! the message its last byte is in: the caller takes them
//! ([`Conn::take_fds`]) after each reply.
//!
//! What the other end says is untrusted: a message is at most
//! [`MAX_MESSAGE`] bytes, a read brings at most [`MAX_FDS`] descriptors (a
//! truncated control message is an error), and every read has a deadline.

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::io::{self, IoSlice, IoSliceMut};
use std::mem::MaybeUninit;
use std::os::fd::{BorrowedFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Instant;

/// The largest message accepted.
pub const MAX_MESSAGE: usize = 1 << 20;

/// The most descriptors of one read.
pub const MAX_FDS: usize = 16;

/// The most descriptors received and not taken yet: a peer that sends them
/// with every few bytes of a message could fill the descriptor table.
const MAX_QUEUED_FDS: usize = 4 * MAX_FDS;

/// Why a call failed.
#[derive(Debug)]
pub enum CallError {
    /// The socket: not there, gone, or too slow (`TimedOut`)
    Io(io::Error),
    /// The peer broke the protocol
    Protocol(String),
    /// The peer answered with an error of the interface
    Remote { error: String, reason: String },
}

impl std::fmt::Display for CallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CallError::Io(e) => write!(f, "{e}"),
            CallError::Protocol(m) => write!(f, "protocol error: {m}"),
            CallError::Remote { error, reason } => write!(f, "{error}: {reason}"),
        }
    }
}

impl std::error::Error for CallError {}

impl From<io::Error> for CallError {
    fn from(e: io::Error) -> Self {
        CallError::Io(e)
    }
}

impl CallError {
    /// The peer is not there (a fetcher is skipped at once).
    pub fn is_unreachable(&self) -> bool {
        matches!(self, CallError::Io(e) if matches!(
            e.kind(),
            io::ErrorKind::ConnectionRefused | io::ErrorKind::NotFound | io::ErrorKind::PermissionDenied
        ))
    }
}

fn protocol(m: impl Into<String>) -> CallError {
    CallError::Protocol(m.into())
}

/// A reply: its parameters and whether more follow.
#[derive(Debug)]
pub struct Reply<T> {
    pub parameters: T,
    pub continues: bool,
}

/// What every message says, its parameters skipped.
#[derive(Deserialize)]
struct Head {
    #[serde(default)]
    continues: bool,
    #[serde(default)]
    error: Option<String>,
}

#[derive(Deserialize)]
struct Body<T> {
    parameters: Option<T>,
}

/// The parameters of an error: the reason the interfaces of velarx give.
#[derive(Deserialize, Default)]
struct ErrorParameters {
    #[serde(default)]
    reason: Option<String>,
    /// The `Failure` of an error that carries one: its class and reason
    #[serde(default)]
    failure: Option<FailureText>,
    /// The party that failed (`Failed` of an interface that names it)
    #[serde(default)]
    party: Option<String>,
}

/// The class and the reason of a `Failure`, as text.
#[derive(Deserialize)]
struct FailureText {
    class: String,
    reason: String,
}

/// One message as the bytes before its NUL: a reply with parameters of
/// type `T`, or the error it is.  (Typed: no JSON value is built.)
pub fn parse_reply<T: DeserializeOwned>(bytes: &[u8]) -> Result<Reply<T>, CallError> {
    let bad = |e: serde_json::Error| protocol(format!("a reply: {e}"));
    let head: Head = serde_json::from_slice(bytes).map_err(bad)?;
    if let Some(error) = head.error {
        let p = serde_json::from_slice::<Body<ErrorParameters>>(bytes)
            .ok()
            .and_then(|b| b.parameters)
            .unwrap_or_default();
        // (an error with a `Failure` says its class and, when it has one,
        // its party: `class: reason (party P)`)
        let reason = match (p.reason, p.failure) {
            (Some(reason), _) => reason,
            (None, Some(f)) => match p.party {
                Some(party) => format!("{}: {} (party {party})", f.class, f.reason),
                None => format!("{}: {}", f.class, f.reason),
            },
            (None, None) => String::new(),
        }
        .chars()
        .take(512)
        .collect();
        let error = error.chars().take(128).collect();
        return Err(CallError::Remote { error, reason });
    }
    let body: Body<T> = serde_json::from_slice(bytes).map_err(bad)?;
    Ok(Reply {
        parameters: body
            .parameters
            .ok_or_else(|| protocol("a reply without parameters"))?,
        continues: head.continues,
    })
}

#[derive(Serialize)]
struct WireCall<'a, P> {
    method: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    parameters: Option<&'a P>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    more: bool,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    oneway: bool,
}

/// A call of an interface, as a type: the request is the value, the
/// name of the method and the type of its reply are the type's.  The
/// name of a method appears in the `impl Method` of its request and nowhere
/// else; a contract test per interface checks that every method it serves
/// has exactly one.
pub trait Method: Serialize {
    /// The interface: `org.velarx.Storage`
    const INTERFACE: &'static str;
    /// The method, without the interface
    const NAME: &'static str;
    /// Whether the call is made with `more`: it answers one record per
    /// reply until a last one that does not continue
    const MORE: bool = false;
    /// The parameters of one reply
    type Reply: DeserializeOwned;
}

/// The methods of an interface description and the names of their
/// parameters, in the order of the text: `method Name(a: t, b: ?t) -> ...`,
/// on one line or on several (a comment line between the parameters is
/// skipped).  For the contract test of an interface.
pub fn described_methods(definition: &str) -> Vec<(String, Vec<String>)> {
    let mut out = Vec::new();
    let mut lines = definition.lines();
    while let Some(l) = lines.next() {
        let Some(rest) = l.strip_prefix("method ") else {
            continue;
        };
        let Some((name, mut rest)) = rest.split_once('(').map(|(n, r)| (n, r.to_string())) else {
            continue;
        };
        // the parameters end at the first `)`: no type of a parameter has one
        let mut params = String::new();
        loop {
            let code = rest.split('#').next().unwrap_or_default();
            if let Some((p, _)) = code.split_once(')') {
                params.push_str(p);
                break;
            }
            params.push_str(code);
            params.push(' ');
            match lines.next() {
                Some(next) => rest = next.to_string(),
                None => break,
            }
        }
        let names = params
            .split(',')
            .filter_map(|p| p.split_once(':').map(|(n, _)| n.trim().to_string()))
            .collect();
        out.push((name.to_string(), names));
    }
    out
}

/// A connection to a varlink service.
pub struct Conn {
    stream: UnixStream,
    buf: Vec<u8>,
    /// Where the next message begins in `buf`
    start: usize,
    /// The position in the stream of the first byte of `buf`
    base: u64,
    /// The descriptors of each read that brought some, with the position
    /// of its last byte
    fds: VecDeque<(u64, Vec<OwnedFd>)>,
    /// Those of the message read last
    taken: Vec<OwnedFd>,
    deadline: Option<Instant>,
    /// The largest message accepted
    max_message: usize,
}

impl Conn {
    /// Connect to the socket at `path` (a `/proc/self/fd/N` of an `O_PATH`
    /// descriptor works as well).
    pub fn connect(path: &Path) -> io::Result<Self> {
        Ok(Self::from_stream(UnixStream::connect(path)?))
    }

    /// A connection on a socket that is connected already.
    pub fn from_stream(stream: UnixStream) -> Self {
        Self {
            stream,
            buf: Vec::new(),
            start: 0,
            base: 0,
            fds: VecDeque::new(),
            taken: Vec::new(),
            deadline: None,
            max_message: MAX_MESSAGE,
        }
    }

    /// Accept messages of up to `bytes` instead of [`MAX_MESSAGE`] (the
    /// replies of the engine to the command line).
    pub fn set_max_message(&mut self, bytes: usize) {
        self.max_message = bytes;
    }

    /// Reads after `deadline` fail with `TimedOut`.
    pub fn set_deadline(&mut self, deadline: Instant) {
        self.deadline = Some(deadline);
    }

    /// Send a call, with descriptors.
    pub fn call<P: Serialize>(
        &mut self,
        method: &str,
        parameters: &P,
        more: bool,
        fds: &[BorrowedFd<'_>],
    ) -> io::Result<()> {
        let mut bytes = serde_json::to_vec(&WireCall {
            method,
            parameters: Some(parameters),
            more,
            oneway: false,
        })
        .map_err(io::Error::other)?;
        bytes.push(0);
        self.send_all(&bytes, fds)
    }

    /// Send the call `m`, with descriptors: its method, and `more` as the
    /// type says.
    pub fn send_method<M: Method>(&mut self, m: &M, fds: &[BorrowedFd<'_>]) -> io::Result<()> {
        self.call(&format!("{}.{}", M::INTERFACE, M::NAME), m, M::MORE, fds)
    }

    /// Make the call `m` and read its reply (one: a call with `more` is
    /// followed with [`Conn::reply`]) with the descriptors it carried.
    pub fn call_method<M: Method>(
        &mut self,
        m: &M,
        fds: &[BorrowedFd<'_>],
    ) -> Result<(M::Reply, Vec<OwnedFd>), CallError> {
        self.send_method(m, fds).map_err(CallError::Io)?;
        let reply = self.reply::<M::Reply>()?;
        Ok((reply.parameters, self.take_fds()))
    }

    /// Send a call whose parameters are JSON already (`None`: none).
    pub fn call_raw(
        &mut self,
        method: &str,
        parameters: Option<&[u8]>,
        more: bool,
        fds: &[BorrowedFd<'_>],
    ) -> io::Result<()> {
        let mut bytes = Vec::with_capacity(parameters.map_or(0, <[u8]>::len) + method.len() + 48);
        bytes.extend_from_slice(b"{\"method\":");
        serde_json::to_writer(&mut bytes, method).map_err(io::Error::other)?;
        if let Some(parameters) = parameters {
            bytes.extend_from_slice(b",\"parameters\":");
            bytes.extend_from_slice(parameters);
        }
        if more {
            bytes.extend_from_slice(b",\"more\":true");
        }
        bytes.extend_from_slice(b"}\0");
        self.send_all(&bytes, fds)
    }

    /// Send `bytes` (a message, ended by its NUL: [`encode_reply`],
    /// [`encode_error`]) with `fds`, in the one `sendmsg` that carries the
    /// descriptors: for a server that answers on a connection it reads
    /// calls from ([`Conn::message`], [`parse_call`]).
    pub fn send(&mut self, bytes: &[u8], fds: &[BorrowedFd<'_>]) -> io::Result<()> {
        self.send_all(bytes, fds)
    }

    fn send_all(&mut self, bytes: &[u8], fds: &[BorrowedFd<'_>]) -> io::Result<()> {
        use rustix::net::{sendmsg, SendAncillaryBuffer, SendAncillaryMessage, SendFlags};
        let mut sent = 0;
        while sent < bytes.len() {
            let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(MAX_FDS))];
            let mut control = SendAncillaryBuffer::new(&mut space);
            if sent == 0 && !fds.is_empty() {
                control.push(SendAncillaryMessage::ScmRights(fds));
            }
            match sendmsg(
                &self.stream,
                &[IoSlice::new(&bytes[sent..])],
                &mut control,
                SendFlags::NOSIGNAL,
            ) {
                Ok(n) => sent += n,
                Err(rustix::io::Errno::INTR) => {}
                Err(e) => return Err(e.into()),
            }
        }
        Ok(())
    }

    /// Send a call without parameters.
    pub fn call_bare(&mut self, method: &str) -> io::Result<()> {
        let mut bytes = serde_json::to_vec(&WireCall::<()> {
            method,
            parameters: None,
            more: false,
            oneway: false,
        })
        .map_err(io::Error::other)?;
        bytes.push(0);
        self.send_all(&bytes, &[])
    }

    /// Send a call that has no reply (`oneway`).
    pub fn oneway<P: Serialize>(&mut self, method: &str, parameters: &P) -> io::Result<()> {
        let mut bytes = serde_json::to_vec(&WireCall {
            method,
            parameters: Some(parameters),
            more: false,
            oneway: true,
        })
        .map_err(io::Error::other)?;
        bytes.push(0);
        self.send_all(&bytes, &[])
    }

    /// Send the call `m` as `oneway`: no reply.
    pub fn oneway_method<M: Method>(&mut self, m: &M) -> io::Result<()> {
        self.oneway(&format!("{}.{}", M::INTERFACE, M::NAME), m)
    }

    /// Reads block for as long as it takes.
    pub fn clear_deadline(&mut self) {
        self.deadline = None;
    }

    /// The socket.
    pub fn socket(&self) -> &UnixStream {
        &self.stream
    }

    /// Whether bytes of a message that was not read yet are here already.
    pub fn has_buffered(&self) -> bool {
        self.start < self.buf.len()
    }

    /// The socket and what was read of it and not taken yet (the
    /// descriptors not taken are closed): to go on with it in another way
    /// (an asynchronous reader).
    pub fn into_parts(mut self) -> (UnixStream, Vec<u8>) {
        let rest = self.buf.split_off(self.start);
        (self.stream, rest)
    }

    /// The next message, whole.
    pub fn reply<T: DeserializeOwned>(&mut self) -> Result<Reply<T>, CallError> {
        let (at, end) = self.next_message()?;
        let reply = parse_reply(&self.buf[at..end]);
        self.consumed();
        reply
    }

    /// The next message as its bytes (without its NUL), for a client that
    /// reads it itself (the command line, whose calls are JSON values).
    pub fn message(&mut self) -> Result<Vec<u8>, CallError> {
        let (at, end) = self.next_message()?;
        let message = self.buf[at..end].to_vec();
        self.consumed();
        Ok(message)
    }

    /// Where the next message is in `buf`, its NUL left out; its
    /// descriptors are taken.
    fn next_message(&mut self) -> Result<(usize, usize), CallError> {
        loop {
            if let Some(end) = self.buf[self.start..].iter().position(|&b| b == 0) {
                let at = self.start;
                self.start += end + 1;
                let (first, last) = (self.base + at as u64, self.base + (at + end) as u64);
                self.taken.clear();
                while self.fds.front().is_some_and(|(p, _)| *p <= last) {
                    if let Some((p, got)) = self.fds.pop_front() {
                        // (those of an earlier message not taken are closed)
                        if p >= first {
                            self.taken.extend(got);
                        }
                    }
                }
                return Ok((at, at + end));
            }
            if self.buf.len() - self.start > self.max_message {
                return Err(protocol("a message too large"));
            }
            self.read_more()?;
        }
    }

    /// The buffer is emptied once every message in it was read.
    fn consumed(&mut self) {
        if self.start == self.buf.len() {
            self.base += self.buf.len() as u64;
            self.buf.clear();
            self.start = 0;
        }
    }

    /// The descriptors that came with the message just read.
    pub fn take_fds(&mut self) -> Vec<OwnedFd> {
        std::mem::take(&mut self.taken)
    }

    fn read_more(&mut self) -> Result<(), CallError> {
        use rustix::net::{
            recvmsg, RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, ReturnFlags,
        };
        let timeout = match self.deadline {
            Some(d) => {
                let left = d.saturating_duration_since(Instant::now());
                if left.is_zero() {
                    return Err(CallError::Io(io::ErrorKind::TimedOut.into()));
                }
                Some(left)
            }
            None => None,
        };
        self.stream.set_read_timeout(timeout)?;
        if self.start > 0 {
            self.buf.drain(..self.start);
            self.base += self.start as u64;
            self.start = 0;
        }
        let mut chunk = [0u8; 64 * 1024];
        let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(MAX_FDS))];
        let mut control = RecvAncillaryBuffer::new(&mut space);
        let r = loop {
            match recvmsg(
                &self.stream,
                &mut [IoSliceMut::new(&mut chunk)],
                &mut control,
                RecvFlags::CMSG_CLOEXEC,
            ) {
                Err(rustix::io::Errno::INTR) => {}
                Err(rustix::io::Errno::AGAIN) => {
                    return Err(CallError::Io(io::ErrorKind::TimedOut.into()))
                }
                r => break r.map_err(io::Error::from)?,
            }
        };
        let mut got = Vec::new();
        for m in control.drain() {
            if let RecvAncillaryMessage::ScmRights(received) = m {
                got.extend(received);
            }
        }
        if r.flags.contains(ReturnFlags::CTRUNC) || got.len() > MAX_FDS {
            return Err(protocol("too many descriptors in one message"));
        }
        if r.bytes == 0 {
            return Err(CallError::Io(io::ErrorKind::UnexpectedEof.into()));
        }
        self.buf.extend_from_slice(&chunk[..r.bytes]);
        if !got.is_empty() {
            let last = self.base + self.buf.len() as u64 - 1;
            self.fds.push_back((last, got));
            if self.fds.iter().map(|(_, f)| f.len()).sum::<usize>() > MAX_QUEUED_FDS {
                return Err(protocol("too many descriptors before the end of a message"));
            }
        }
        Ok(())
    }
}

/// What every call says besides its parameters.
#[derive(Debug, Deserialize)]
pub struct CallHead {
    pub method: String,
    #[serde(default)]
    pub more: bool,
    #[serde(default)]
    pub oneway: bool,
    #[serde(default)]
    pub upgrade: bool,
}

/// Why a message is no call that can be answered.
#[derive(Debug, PartialEq, Eq)]
pub enum BadCall {
    /// Not a JSON object with a `method`: the connection is ended.
    NotACall(String),
    /// The parameters do not fit the method: `org.varlink.service.InvalidParameter`.
    InvalidParameter(String),
}

/// The head of the call in `bytes` (the message without its NUL).
pub fn parse_call(bytes: &[u8]) -> Result<CallHead, BadCall> {
    serde_json::from_slice(bytes).map_err(|e| BadCall::NotACall(e.to_string()))
}

/// The parameters of the call in `bytes`: none is the default of `T`.
pub fn call_parameters<T: DeserializeOwned + Default>(bytes: &[u8]) -> Result<T, BadCall> {
    match serde_json::from_slice::<Body<T>>(bytes) {
        Ok(b) => Ok(b.parameters.unwrap_or_default()),
        Err(e) => {
            let text = e.to_string();
            // serde names the field between backquotes
            let name = text
                .split('`')
                .nth(1)
                .filter(|n| {
                    n.len() <= 64 && n.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
                })
                .unwrap_or("parameters");
            Err(BadCall::InvalidParameter(name.to_string()))
        }
    }
}

#[derive(Serialize)]
struct WireReply<'a, P> {
    parameters: &'a P,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    continues: bool,
}

#[derive(Serialize)]
struct WireError<'a, P> {
    error: &'a str,
    parameters: &'a P,
}

/// A reply, ended by its NUL.
pub fn encode_reply<P: Serialize>(parameters: &P, continues: bool) -> Vec<u8> {
    let mut bytes = serde_json::to_vec(&WireReply {
        parameters,
        continues,
    })
    .unwrap_or_else(|_| b"{\"error\":\"org.varlink.service.InvalidParameter\",\"parameters\":{\"parameter\":\"reply\"}}".to_vec());
    bytes.push(0);
    bytes
}

/// An error reply, ended by its NUL.
pub fn encode_error<P: Serialize>(error: &str, parameters: &P) -> Vec<u8> {
    let mut bytes = serde_json::to_vec(&WireError { error, parameters }).unwrap_or_default();
    bytes.push(0);
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::os::fd::AsFd;
    use std::time::Duration;

    fn pair() -> (Conn, UnixStream) {
        let (a, b) = UnixStream::pair().unwrap();
        (Conn::from_stream(a), b)
    }

    /// A reply that is no JSON, an error of the interface: told apart.
    #[test]
    fn a_reply_is_parsed_or_refused() {
        assert!(matches!(
            parse_reply::<serde_json::Value>(
                b"{\"parameters\":{\"kind\":\"done\"},\"continues\":true}"
            ),
            Ok(Reply {
                continues: true,
                ..
            })
        ));
        assert!(matches!(
            parse_reply::<serde_json::Value>(
                b"{\"error\":\"org.velarx.X.Failed\",\"parameters\":{\"reason\":\"no\"}}"
            ),
            Err(CallError::Remote { reason, .. }) if reason == "no"
        ));
        assert!(matches!(
            parse_reply::<serde_json::Value>(b"not json"),
            Err(CallError::Protocol(_))
        ));
        assert!(matches!(
            parse_reply::<serde_json::Value>(b"{}"),
            Err(CallError::Protocol(_))
        ));
    }

    /// A message read as its bytes, then the next one as a reply.
    #[test]
    fn a_message_is_its_bytes() {
        let (mut conn, mut other) = pair();
        other
            .write_all(b"{\"parameters\":{\"a\":1}}\0{\"parameters\":{\"a\":2}}\0")
            .unwrap();
        conn.set_deadline(Instant::now() + Duration::from_secs(5));
        assert_eq!(conn.message().unwrap(), b"{\"parameters\":{\"a\":1}}");
        let next: Reply<serde_json::Value> = conn.reply().unwrap();
        assert_eq!(next.parameters["a"], 2);
    }

    /// A call whose parameters are JSON already, with `more`.
    #[test]
    fn a_raw_call_is_one_message() {
        let (mut conn, other) = pair();
        conn.call_raw("org.velarx.X.Do", Some(b"{\"a\":1}"), true, &[])
            .unwrap();
        conn.call_raw("org.velarx.X.Bare", None, false, &[])
            .unwrap();
        drop(conn);
        let mut bytes = Vec::new();
        std::io::Read::read_to_end(&mut &other, &mut bytes).unwrap();
        let messages: Vec<&[u8]> = bytes.split(|&b| b == 0).collect();
        assert_eq!(messages.len(), 3, "{bytes:?}");
        let head = parse_call(messages[0]).unwrap();
        assert!(head.more);
        assert_eq!(head.method, "org.velarx.X.Do");
        let p: serde_json::Value = call_parameters(messages[0]).unwrap();
        assert_eq!(p["a"], 1);
        let head = parse_call(messages[1]).unwrap();
        assert!(!head.more);
        assert_eq!(messages[1], b"{\"method\":\"org.velarx.X.Bare\"}");
    }

    /// Two messages in one write are two replies; a call carries its
    /// descriptors and its NUL.
    #[test]
    fn messages_are_split_at_their_nul_and_calls_carry_descriptors() {
        let (mut conn, mut other) = pair();
        other
            .write_all(
                b"{\"parameters\":{\"a\":1},\"continues\":true}\0{\"parameters\":{\"a\":2}}\0",
            )
            .unwrap();
        conn.set_deadline(Instant::now() + Duration::from_secs(5));
        let first: Reply<serde_json::Value> = conn.reply().unwrap();
        assert_eq!(first.parameters["a"], 1);
        let last: Reply<serde_json::Value> = conn.reply().unwrap();
        assert_eq!(last.parameters["a"], 2);
        assert!(!last.continues);

        let file = tempfile::tempfile().unwrap();
        conn.call(
            "org.velarx.X.Do",
            &serde_json::json!({"x": 1}),
            true,
            &[file.as_fd()],
        )
        .unwrap();
        let mut back = Conn::from_stream(other);
        back.set_deadline(Instant::now() + Duration::from_secs(5));
        // (a call read as a reply: no `parameters` of a reply, but its own)
        let call: Reply<serde_json::Value> = back.reply().unwrap();
        assert_eq!(call.parameters["x"], 1);
        assert_eq!(back.take_fds().len(), 1);
    }

    /// The descriptors of a message are its own, also when the message
    /// before it, which has none, is read with it.
    #[test]
    fn descriptors_go_with_their_own_message() {
        let (mut conn, other) = pair();
        let mut sender = Conn::from_stream(other);
        let file = tempfile::tempfile().unwrap();
        sender
            .send_all(b"{\"parameters\":{\"a\":1},\"continues\":true}\0", &[])
            .unwrap();
        sender
            .send_all(
                b"{\"parameters\":{\"a\":2},\"continues\":true}\0",
                &[file.as_fd()],
            )
            .unwrap();
        sender
            .send_all(b"{\"parameters\":{\"a\":3}}\0", &[])
            .unwrap();
        conn.set_deadline(Instant::now() + Duration::from_secs(5));
        let first: Reply<serde_json::Value> = conn.reply().unwrap();
        assert_eq!(first.parameters["a"], 1);
        assert!(conn.take_fds().is_empty());
        let second: Reply<serde_json::Value> = conn.reply().unwrap();
        assert_eq!(second.parameters["a"], 2);
        assert_eq!(conn.take_fds().len(), 1);
        let third: Reply<serde_json::Value> = conn.reply().unwrap();
        assert_eq!(third.parameters["a"], 3);
        assert!(conn.take_fds().is_empty());
    }

    /// A peer that sends a descriptor with every byte of a message runs
    /// into a limit, not into the end of the descriptor table.
    #[test]
    fn descriptors_before_the_end_of_a_message_are_bounded() {
        let (mut conn, other) = pair();
        let file = tempfile::tempfile().unwrap();
        let mut sender = Conn::from_stream(other);
        for _ in 0..=MAX_QUEUED_FDS {
            sender.send_all(b" ", &[file.as_fd()]).unwrap();
        }
        conn.set_deadline(Instant::now() + Duration::from_secs(5));
        assert!(matches!(
            conn.reply::<serde_json::Value>(),
            Err(CallError::Protocol(_))
        ));
    }

    /// A message larger than the limit, an end of file, a silent peer.
    #[test]
    fn a_peer_that_sends_too_much_or_nothing_is_an_error() {
        let (mut conn, mut other) = pair();
        conn.set_deadline(Instant::now() + Duration::from_secs(5));
        let big = vec![b' '; MAX_MESSAGE + 128 * 1024];
        let writer = std::thread::spawn(move || {
            let _ = other.write_all(&big);
        });
        assert!(matches!(
            conn.reply::<serde_json::Value>(),
            Err(CallError::Protocol(_))
        ));
        drop(conn);
        writer.join().unwrap();

        let (mut conn, other) = pair();
        conn.set_deadline(Instant::now() + Duration::from_millis(200));
        assert!(
            matches!(&conn.reply::<serde_json::Value>(), Err(CallError::Io(e)) if e.kind() == io::ErrorKind::TimedOut)
        );
        drop(other);
        conn.set_deadline(Instant::now() + Duration::from_secs(5));
        assert!(
            matches!(&conn.reply::<serde_json::Value>(), Err(CallError::Io(e)) if e.kind() == io::ErrorKind::UnexpectedEof)
        );
    }
}
