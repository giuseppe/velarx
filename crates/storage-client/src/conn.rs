// SPDX-License-Identifier: Apache-2.0
//! One connection to a storage driver: the connect, the `GetInfo` that
//! checks the version, the call and its replies, with the deadline of the
//! idle timeout, and what a failed one is for the engine.
//!
//! Everything the driver says is untrusted: a message is at most the limit
//! it stated (and 1 MiB), a reply is typed, an error name this build does not
//! know is a `Storage` error that names it.  The engine's requests are
//! checked against the limits before they are sent: a request over one is an
//! error here, never sent (the callers split what can be split).

use crate::proto::{self, Info, PROTO};
use serde::de::DeserializeOwned;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::io;
use std::os::fd::{BorrowedFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use velarx_graph::longcall::{call_cap, wait_for_call, Step};
use velarx_graph::{DriverError, DriverErrorKind, DriverResult};
use velarx_wire::varlink::{parse_reply, CallError, Conn, Method, Reply};

/// How to reach the driver.
#[derive(Debug, Clone)]
pub struct Link {
    /// The socket the driver listens on (`[storage.varlink] socket`).
    pub socket: PathBuf,
    /// How long a call may be silent before it is failed (`[storage.varlink]
    /// timeout_secs`).
    pub timeout: Duration,
}

/// The limits applied to a connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Limits {
    pub message: u64,
    pub fds: u64,
    pub wants: u64,
    pub ranges: u64,
}

impl Limits {
    /// What this build takes.
    pub const BUILD: Limits = Limits {
        message: proto::MAX_MESSAGE as u64,
        fds: proto::MAX_FDS as u64,
        wants: proto::MAX_WANTS,
        ranges: proto::MAX_RANGES,
    };
}

/// The limits applied to a connection: the driver's (`max_message`,
/// `max_fds`, `max_wants`, `max_ranges`), never above what this build takes.
pub(crate) fn clamp(stated: &BTreeMap<String, u64>) -> Limits {
    let of = |name: &str, build: u64| stated.get(name).map_or(build, |v| (*v).min(build));
    Limits {
        message: of("max_message", Limits::BUILD.message),
        fds: of("max_fds", Limits::BUILD.fds),
        wants: of("max_wants", Limits::BUILD.wants),
        ranges: of("max_ranges", Limits::BUILD.ranges),
    }
}

/// A reply of a call made with `more` and the descriptors it carried.
pub(crate) type Next<M> = (Reply<<M as Method>::Reply>, Vec<OwnedFd>);

/// A connection, after its `GetInfo`.
pub(crate) struct Session<'a> {
    conn: Conn,
    /// The name of the driver, for the errors: the one its client keeps.
    name: &'a str,
    timeout: Duration,
    limits: Limits,
}

/// What a connection that is refused or gone is: the storage service is
/// not there.  A socket this user may not use is there.
fn is_gone(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::ConnectionRefused
            | io::ErrorKind::NotFound
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::BrokenPipe
            | io::ErrorKind::UnexpectedEof
    )
}

/// The name of an error as `DriverError::from_wire` has it: the last
/// component of the varlink name in `snake_case` (`org.velarx.Storage.NotFound`
/// is `not_found`).
pub(crate) fn error_name(error: &str) -> String {
    let last = error.rsplit('.').next().unwrap_or(error);
    let mut out = String::new();
    for (i, c) in last.char_indices() {
        if c.is_ascii_uppercase() {
            if i > 0 {
                out.push('_');
            }
            out.push(c.to_ascii_lowercase());
        } else {
            out.push(c);
        }
    }
    out
}

/// Connect to `socket` within `timeout`: a driver whose backlog is full
/// (it does not accept) is `TimedOut` as one that does not answer, and the
/// same bound stays on every write of the connection (`SO_SNDTIMEO`), so a
/// driver that stops reading a request stalls no call for longer.
fn connect_within(socket: &Path, timeout: Duration) -> io::Result<UnixStream> {
    use rustix::net::sockopt::{set_socket_timeout, Timeout};
    use rustix::net::{AddressFamily, SocketAddrUnix, SocketFlags, SocketType};
    let fd = rustix::net::socket_with(
        AddressFamily::UNIX,
        SocketType::STREAM,
        SocketFlags::CLOEXEC,
        None,
    )?;
    // (a zero timeout is "none" for the kernel)
    set_socket_timeout(
        &fd,
        Timeout::Send,
        Some(timeout.max(Duration::from_millis(1))),
    )?;
    let addr = SocketAddrUnix::new(socket)?;
    loop {
        match rustix::net::connect(&fd, &addr) {
            Ok(()) => return Ok(UnixStream::from(fd)),
            // (a unix socket is not connected yet after a signal: again)
            Err(rustix::io::Errno::INTR) => {}
            Err(rustix::io::Errno::AGAIN) => return Err(io::ErrorKind::TimedOut.into()),
            Err(e) => return Err(e.into()),
        }
    }
}

/// The driver must be served by the engine's user or by root
/// (`SO_PEERCRED`, on every connection): a socket of another user is not a
/// storage service the engine hands its containers' roots to.
fn check_peer(
    stream: &UnixStream,
    name: &str,
    socket: &Path,
    trusted: fn(u32) -> bool,
) -> DriverResult<()> {
    velarx_base::ipc::check_client(stream, trusted).map_err(|e| {
        DriverError::storage(
            name,
            format!(
                "the storage service on {} is not served by this user or root: {e}",
                socket.display()
            ),
        )
    })
}

/// The error names of the interface, as `DriverError::from_wire` has them.
const KNOWN: [&str; 8] = [
    "missing",
    "corrupt",
    "unsupported",
    "not_found",
    "busy",
    "label_refused",
    "unavailable",
    "failed",
];

/// The parameters of an error besides its `reason`.
#[derive(Deserialize)]
struct ErrorBody {
    parameters: Option<ErrorExtra>,
}

#[derive(Deserialize, Default)]
struct ErrorExtra {
    #[serde(default)]
    layer: Option<String>,
    #[serde(default)]
    remedy: Option<serde_json::Value>,
}

/// The first reply of every connection says the version, whatever else it
/// has: a driver of another version may have another shape.
#[derive(Deserialize)]
struct Version {
    proto: u32,
}

impl<'a> Session<'a> {
    /// Connect to the driver and ask `GetInfo`: a `proto` other than ours is
    /// `ProtocolMismatch` (both named), whatever else the reply has.
    pub fn connect(
        link: &Link,
        name: &'a str,
        limits: Option<Limits>,
    ) -> DriverResult<(Self, Info)> {
        let stream = connect_within(&link.socket, link.timeout).map_err(|e| {
            if e.kind() == io::ErrorKind::TimedOut {
                DriverError::timed_out(name, "connect", link.timeout.as_secs().max(1))
            } else if is_gone(&e) {
                DriverError::unavailable(
                    name,
                    format!("cannot connect to {}: {e}", link.socket.display()),
                )
            } else {
                DriverError::io(
                    name,
                    io::Error::new(
                        e.kind(),
                        format!("cannot connect to {}: {e}", link.socket.display()),
                    ),
                )
            }
        })?;
        check_peer(&stream, name, &link.socket, velarx_base::ipc::trusted_uid)?;
        let mut session = Self {
            conn: Conn::from_stream(stream),
            name,
            timeout: link.timeout,
            limits: limits.unwrap_or(Limits::BUILD),
        };
        session.start();
        session.send(&crate::request::GetInfo {}, &[])?;
        let bytes = session.recv_bytes("GetInfo")?;
        match parse_reply::<Version>(&bytes) {
            Ok(r) if r.parameters.proto != PROTO => {
                return Err(DriverError::protocol_mismatch(
                    name,
                    &format!("org.velarx.Storage.{}", r.parameters.proto),
                    &format!("org.velarx.Storage.{PROTO}"),
                ))
            }
            Ok(_) => {}
            Err(e) => return Err(session.failure("GetInfo", e, &bytes)),
        }
        let info: Info = session.parse("GetInfo", &bytes)?.parameters;
        session.limits = clamp(&info.limits);
        session
            .conn
            .set_max_message(session.limits.message as usize);
        Ok((session, info))
    }

    /// The deadline of the next read: the idle timeout from now.
    fn start(&mut self) {
        self.conn.set_deadline(Instant::now() + self.timeout);
    }

    /// What a failed read or write is: the service is gone, too slow, or
    /// something else.
    fn transport(&self, call: &str, e: CallError) -> DriverError {
        match e {
            // (a write the driver did not read within the timeout is
            // `WouldBlock`, `SO_SNDTIMEO`)
            CallError::Io(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                ) =>
            {
                DriverError::timed_out(self.name, call, self.timeout.as_secs().max(1))
            }
            CallError::Io(e) if is_gone(&e) => DriverError::unavailable(
                self.name,
                format!("the storage service closed the connection during {call}: {e}"),
            ),
            CallError::Io(e) => DriverError::io(self.name, e),
            CallError::Protocol(m) => DriverError::storage(
                self.name,
                format!("the storage service broke the protocol in {call}: {m}"),
            ),
            CallError::Remote { error, reason } => {
                DriverError::from_wire(self.name, &error_name(&error), &reason, None, None)
            }
        }
    }

    /// An error reply (`bytes` is the message), or the failure `e` was.
    fn failure(&self, call: &str, e: CallError, bytes: &[u8]) -> DriverError {
        match e {
            CallError::Remote { error, reason } => {
                let extra = serde_json::from_slice::<ErrorBody>(bytes)
                    .ok()
                    .and_then(|b| b.parameters)
                    .unwrap_or_default();
                let remedy = extra.remedy.as_ref().and_then(|v| v.as_str());
                // (a name this build does not know is told as the driver
                // wrote it)
                let snake = error_name(&error);
                let name = if KNOWN.contains(&snake.as_str()) {
                    snake
                } else {
                    error.rsplit('.').next().unwrap_or(&error).to_string()
                };
                DriverError::from_wire(self.name, &name, &reason, extra.layer.as_deref(), remedy)
            }
            e => self.transport(call, e),
        }
    }

    /// The next message, whole, within the idle timeout of the call.
    fn recv_bytes(&mut self, call: &str) -> DriverResult<Vec<u8>> {
        self.start();
        self.conn.message().map_err(|e| self.transport(call, e))
    }

    fn parse<T: DeserializeOwned>(&self, call: &str, bytes: &[u8]) -> DriverResult<Reply<T>> {
        parse_reply::<T>(bytes).map_err(|e| self.failure(call, e, bytes))
    }

    /// Send the call `m`, with the descriptors.  A request over the limits of
    /// the driver is an error, never sent.
    pub fn send<M: Method>(&mut self, m: &M, fds: &[BorrowedFd<'_>]) -> DriverResult<()> {
        let method = M::NAME;
        let bytes = serde_json::to_vec(m)
            .map_err(|e| DriverError::storage(self.name, format!("{method}: {e}")))?;
        // (the envelope: the method name, the flags and the braces)
        let size = bytes.len() + method.len() + 64;
        if size as u64 > self.limits.message {
            return Err(DriverError::storage(
                self.name,
                format!(
                    "the request {method} is {size} bytes, and the storage service takes messages of at most {}: the engine splits what can be split",
                    self.limits.message
                ),
            ));
        }
        if fds.len() as u64 > self.limits.fds {
            return Err(DriverError::storage(
                self.name,
                format!(
                    "the request {method} carries {} descriptors, and the storage service takes at most {}",
                    fds.len(),
                    self.limits.fds
                ),
            ));
        }
        self.conn
            .call_raw(
                &format!("{}.{method}", M::INTERFACE),
                Some(&bytes),
                M::MORE,
                fds,
            )
            .map_err(|e| self.transport(method, CallError::Io(e)))
    }

    /// A call with one reply: its parameters and the descriptors it carried.
    pub fn call<M: Method>(
        &mut self,
        m: &M,
        fds: &[BorrowedFd<'_>],
    ) -> DriverResult<(M::Reply, Vec<OwnedFd>)> {
        debug_assert!(!M::MORE, "{} is called with more", M::NAME);
        self.send(m, fds)?;
        let bytes = self.recv_bytes(M::NAME)?;
        let reply = self.parse::<M::Reply>(M::NAME, &bytes)?;
        Ok((reply.parameters, self.conn.take_fds()))
    }

    /// The next reply of a call made with `more`, within `wait`: none when
    /// nothing came.
    pub fn next<M: Method>(&mut self, wait: Duration) -> DriverResult<Option<Next<M>>> {
        let call = M::NAME;
        self.conn.set_deadline(Instant::now() + wait);
        let bytes = match self.conn.message() {
            Ok(b) => b,
            Err(CallError::Io(e)) if e.kind() == io::ErrorKind::TimedOut => return Ok(None),
            Err(e) => return Err(self.transport(call, e)),
        };
        let reply = self.parse::<M::Reply>(call, &bytes)?;
        Ok(Some((reply, self.conn.take_fds())))
    }

    /// A call made with `more`: `on_reply` gets each reply (its parameters,
    /// its descriptors) and says whether it is the end (`Some`, the result)
    /// or the call goes on (`None`).  Every reply starts the idle deadline
    /// again, so the call lasts as long as the driver sends progress; one that
    /// is silent for the timeout is `TimedOut`, naming the call
    /// ([`wait_for_call`]).
    pub fn long<M: Method, R>(
        &mut self,
        m: &M,
        fds: &[BorrowedFd<'_>],
        mut on_reply: impl FnMut(M::Reply, Vec<OwnedFd>, bool) -> DriverResult<Option<R>>,
    ) -> DriverResult<R> {
        self.send(m, fds)?;
        self.follow::<M, R>(&mut on_reply)
    }

    /// The replies of a call already sent with `more`, as [`Session::long`].
    pub fn follow<M: Method, R>(
        &mut self,
        on_reply: &mut impl FnMut(M::Reply, Vec<OwnedFd>, bool) -> DriverResult<Option<R>>,
    ) -> DriverResult<R> {
        let method = M::NAME;
        let timeout = self.timeout;
        let started = Instant::now();
        let mut failed: Option<DriverError> = None;
        let result = wait_for_call(method, timeout, |wait| {
            match self.next::<M>(wait) {
                Ok(None) => Ok(None),
                Ok(Some((reply, fds))) => {
                    let continues = reply.continues;
                    match on_reply(reply.parameters, fds, continues) {
                        Ok(Some(done)) => Ok(Some(Step::Done(done))),
                        Ok(None) if continues => Ok(Some(Step::Progress)),
                        // (the last reply, and the call did not get what it
                        // waits for)
                        Ok(None) => {
                            failed = Some(DriverError::storage(
                                self.name,
                                format!("the storage service ended {method} without its answer"),
                            ));
                            Err(io::Error::other("ended"))
                        }
                        Err(e) => {
                            failed = Some(e);
                            Err(io::Error::other("failed"))
                        }
                    }
                }
                Err(e) => {
                    failed = Some(e);
                    Err(io::Error::other("failed"))
                }
            }
        });
        result.map_err(|e| {
            failed.take().unwrap_or_else(|| {
                if e.kind() == io::ErrorKind::TimedOut && started.elapsed() >= call_cap(timeout) {
                    // (progress for longer than any call lasts)
                    DriverError::of(self.name, DriverErrorKind::TimedOut, e.to_string())
                } else if e.kind() == io::ErrorKind::TimedOut {
                    DriverError::timed_out(self.name, method, timeout.as_secs().max(1))
                } else {
                    DriverError::io(self.name, e)
                }
            })
        })
    }

    /// The socket, for whoever cancels the call from another thread.
    pub fn socket(&self) -> &UnixStream {
        self.conn.socket()
    }

    /// The idle timeout.
    pub fn timeout(&self) -> Duration {
        self.timeout
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_names_are_snake_case_of_the_last_component() {
        assert_eq!(error_name("org.velarx.Storage.NotFound"), "not_found");
        assert_eq!(error_name("org.velarx.Storage.Missing"), "missing");
        assert_eq!(error_name("Failed"), "failed");
        assert_eq!(
            error_name("org.varlink.service.MethodNotFound"),
            "method_not_found"
        );
    }

    /// A socket served by a user other than the engine's or root is refused
    /// before anything is sent on it.
    #[test]
    fn a_driver_of_another_user_is_refused() {
        let (a, _b) = UnixStream::pair().unwrap();
        check_peer(&a, "t", Path::new("/s"), velarx_base::ipc::trusted_uid).unwrap();
        let e = check_peer(&a, "t", Path::new("/s"), |_| false).unwrap_err();
        assert!(matches!(e.kind, velarx_graph::DriverErrorKind::Storage));
        assert!(
            e.message().contains("not served by this user or root"),
            "{e}"
        );
    }

    /// A driver that answers `GetInfo` and then stops reading cannot hold a
    /// request that does not fit the socket's buffer for longer than the
    /// timeout; one that never accepts is `TimedOut` at the connect.
    #[test]
    fn a_driver_that_stops_reading_or_accepting_is_timed_out() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("s.sock");
        let listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
        let (tx, rx) = std::sync::mpsc::channel::<()>();
        let server = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut conn = Conn::from_stream(stream);
            conn.set_deadline(Instant::now() + Duration::from_secs(5));
            conn.message().unwrap();
            let info = crate::fake::default_info();
            conn.send(&velarx_wire::varlink::encode_reply(&info, false), &[])
                .unwrap();
            // (holds the connection and reads nothing more)
            let _ = rx.recv_timeout(Duration::from_secs(10));
            drop(conn);
            listener
        });
        let link = Link {
            socket: socket.clone(),
            timeout: Duration::from_millis(300),
        };
        let (mut session, _) = Session::connect(&link, "t", None).unwrap();
        let big = "x".repeat(900 * 1024);
        let started = Instant::now();
        let e = session
            .send(
                &crate::request::Status(crate::request::OfStore {
                    store: big.as_str(),
                }),
                &[],
            )
            .unwrap_err();
        assert!(
            matches!(e.kind, velarx_graph::DriverErrorKind::TimedOut),
            "{e}"
        );
        assert!(started.elapsed() < Duration::from_secs(5));
        tx.send(()).unwrap();
        let listener = server.join().unwrap();
        // a listener that accepts nothing: its backlog fills, and the
        // connect that finds it full waits for the timeout only
        rustix::net::listen(&listener, 0).unwrap();
        let mut held = Vec::new();
        let started = Instant::now();
        let e = loop {
            match connect_within(&socket, Duration::from_millis(200)) {
                Ok(s) => held.push(s),
                Err(e) => break e,
            }
            assert!(held.len() < 64, "the backlog never filled");
        };
        assert_eq!(e.kind(), io::ErrorKind::TimedOut, "{e}");
        assert!(started.elapsed() < Duration::from_secs(5));
    }
}
