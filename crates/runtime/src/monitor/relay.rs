// SPDX-License-Identifier: Apache-2.0
//! The relay of the standard streams of this process to a monitor's session
//! (attach or exec), for a process that is its own monitor (`inproc`: there
//! is no engine to ask) and for the tests of the monitor.  Blocking, with
//! `poll`.

use rustix::event::{PollFd, PollFlags};
use std::io;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::path::Path;
use velarx_proto::stream::{parse_detach_keys, DetachMatcher};
use velarx_sys::tty::{window_size, RawTerminal};
use velarx_wire::monitor::client::{kill, next_reply, open_attach, open_exec_with};
use velarx_wire::monitor::iface;
use velarx_wire::monitor::proto::{self, Attach, ExecRequest};
use velarx_wire::varlink::Conn;

use velarx_wire::monitor::client::Streams;

/// Signals this process forwards to a container without a terminal.
pub const PROXIED_SIGNALS: [i32; 6] = [
    libc::SIGINT,
    libc::SIGTERM,
    libc::SIGHUP,
    libc::SIGQUIT,
    libc::SIGUSR1,
    libc::SIGUSR2,
];

pub struct AttachOptions {
    pub stdin: bool,
    pub stdout: bool,
    pub stderr: bool,
    /// The container has a terminal: raw input, resize.
    pub tty: bool,
    pub detach_keys: Option<String>,
    /// Forward the signals this process gets.
    pub sig_proxy: bool,
    /// The container waits for this client before it starts.
    pub start: bool,
    pub stdin_once: bool,
}

impl Default for AttachOptions {
    fn default() -> Self {
        Self {
            stdin: false,
            stdout: true,
            stderr: true,
            tty: false,
            detach_keys: None,
            sig_proxy: true,
            start: false,
            stdin_once: false,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum AttachEnd {
    /// The container exited with this status.
    Exited(i32),
    /// The user typed the detach keys.
    Detached,
    /// The monitor went away without a word: ask the daemon.
    Lost,
}

fn write_all_fd(fd: BorrowedFd<'_>, mut data: &[u8]) -> io::Result<()> {
    while !data.is_empty() {
        match rustix::io::write(fd, data) {
            Ok(n) => data = &data[n..],
            Err(rustix::io::Errno::INTR) => {}
            Err(rustix::io::Errno::AGAIN) => {
                proto::wait_fd(fd, PollFlags::OUT, -1)?;
            }
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}

/// The standard streams of this process.
pub fn stdio() -> (
    BorrowedFd<'static>,
    BorrowedFd<'static>,
    BorrowedFd<'static>,
) {
    (
        rustix::stdio::stdin(),
        rustix::stdio::stdout(),
        rustix::stdio::stderr(),
    )
}

/// What one read takes of a pipe.
const CHUNK: usize = 128 * 1024;

/// Connect to the monitor in `dir` and relay the standard streams of this
/// process (`stdin`, `stdout`, `stderr`) until the container exits or the
/// user detaches.
pub fn attach(
    dir: &Path,
    opts: &AttachOptions,
    stdin: BorrowedFd<'_>,
    stdout: BorrowedFd<'_>,
    stderr: BorrowedFd<'_>,
) -> io::Result<AttachEnd> {
    let session = open_attach(
        dir,
        &Attach {
            stdin: opts.stdin,
            stdout: opts.stdout,
            stderr: opts.stderr,
            start: opts.start,
            stdin_once: opts.stdin_once,
        },
    )?;
    if let Some(code) = session.exit {
        return Ok(AttachEnd::Exited(code));
    }
    Ok(
        match relay(
            dir,
            session.conn,
            session.streams,
            opts,
            false,
            (stdin, stdout, stderr),
        )? {
            SessionEnd::Exited(code, _) => AttachEnd::Exited(code),
            SessionEnd::Detached => AttachEnd::Detached,
            SessionEnd::Lost => AttachEnd::Lost,
        },
    )
}

enum SessionEnd {
    Exited(i32, iface::ExecReason),
    Detached,
    Lost,
}

/// The next reply of a session: `None` when the monitor went away, else
/// the end it says, if it is the last.
fn next_end(conn: &mut Conn, exec: bool) -> io::Result<Option<Option<SessionEnd>>> {
    Ok(if exec {
        next_reply::<iface::ExecReply>(conn)?.map(|r| {
            r.parameters
                .exit
                .map(|e| SessionEnd::Exited(e.code, e.reason))
        })
    } else {
        next_reply::<iface::AttachReply>(conn)?.map(|r| {
            r.parameters
                .exit
                .map(|c| SessionEnd::Exited(c, iface::ExecReason::Exited))
        })
    })
}

/// Read what is left in `fd` (written out and closed by the monitor) to `to`.
fn drain(fd: &mut Option<OwnedFd>, to: BorrowedFd<'_>, buf: &mut [u8]) -> io::Result<()> {
    let Some(f) = fd.take() else { return Ok(()) };
    rustix::fs::fcntl_setfl(&f, rustix::fs::OFlags::empty())?;
    loop {
        match rustix::io::read(&f, &mut *buf) {
            Ok(0) => return Ok(()),
            Ok(n) => write_all_fd(to, &buf[..n])?,
            Err(rustix::io::Errno::INTR) => {}
            // (the monitor is gone with what it had not written)
            Err(_) => return Ok(()),
        }
    }
}

/// Read what `fd` has, up to `buf.len()`: a read, then more while more is
/// there (a pipe brings the small writes of its writer one by one; written
/// on together they wake the reader of the session less): the bytes, and
/// whether the input is at its end.
fn gather(fd: BorrowedFd<'_>, buf: &mut [u8]) -> rustix::io::Result<(usize, bool)> {
    let mut n = rustix::io::read(fd, &mut *buf)?;
    if n == 0 {
        return Ok((0, true));
    }
    while n < buf.len() && proto::wait_fd(fd, PollFlags::IN, 0).unwrap_or(false) {
        match rustix::io::read(fd, &mut buf[n..]) {
            Ok(0) => return Ok((n, true)),
            Ok(m) => n += m,
            Err(_) => break,
        }
    }
    Ok((n, false))
}

/// Relay the standard streams of this process to the pipes of a session,
/// and the signals, the size of the terminal and the end of the input as
/// `oneway` calls on its connection (the signals of an attach are `Kill`
/// calls of the container in `dir`), until its last reply.
fn relay(
    dir: &Path,
    mut conn: Conn,
    mut streams: Streams,
    opts: &AttachOptions,
    exec: bool,
    (stdin, stdout, stderr): (BorrowedFd<'_>, BorrowedFd<'_>, BorrowedFd<'_>),
) -> io::Result<SessionEnd> {
    let keys = match (&opts.detach_keys, opts.tty) {
        (Some(spec), _) => {
            parse_detach_keys(spec).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?
        }
        (None, true) => vec![0x10, 0x11],
        (None, false) => Vec::new(),
    };
    let mut matcher = DetachMatcher::new(keys);

    let mut signals: Vec<i32> = Vec::new();
    if opts.tty {
        signals.push(libc::SIGWINCH);
    } else if opts.sig_proxy {
        signals.extend(PROXIED_SIGNALS);
    }
    let guard = velarx_sys::signal::SignalGuard::new(&signals)?;

    let is_tty = opts.tty && rustix::termios::isatty(stdin);
    let _raw = if opts.stdin && is_tty {
        Some(RawTerminal::new(stdin)?)
    } else {
        None
    };
    let send_size = |conn: &mut Conn| -> io::Result<()> {
        let fd = if rustix::termios::isatty(stdout) {
            stdout
        } else {
            stdin
        };
        match window_size(fd) {
            Some((rows, cols)) => conn.oneway_method(&iface::ResizeParams { rows, cols }),
            None => Ok(()),
        }
    };
    if opts.tty {
        send_size(&mut conn)?;
    }
    if let Some(fd) = &streams.stdin {
        rustix::fs::fcntl_setfl(fd, rustix::fs::OFlags::NONBLOCK)?;
    }
    for fd in [&streams.stdout, &streams.stderr].into_iter().flatten() {
        rustix::fs::fcntl_setfl(fd, rustix::fs::OFlags::NONBLOCK)?;
    }

    let mut input_open = opts.stdin && streams.stdin.is_some();
    // the input that is read and not written to the pipe yet
    let mut pending: Vec<u8> = Vec::new();
    // what of `pending` is written already
    let mut sent = 0;
    // our input ended: once `pending` is written, the pipe closes
    let mut input_ended = false;
    let mut buf = vec![0u8; CHUNK];
    let end = loop {
        if input_ended && pending.is_empty() && streams.stdin.is_some() {
            streams.stdin = None;
            conn.oneway_method(&iface::CloseStdin {})?;
        }
        let mut fds = vec![PollFd::new(conn.socket(), PollFlags::IN)];
        let sig_idx = guard.fd().map(|fd| {
            fds.push(PollFd::from_borrowed_fd(fd, PollFlags::IN));
            fds.len() - 1
        });
        // (read once what was read is written: the pipe sets the pace)
        let in_idx = (input_open && pending.is_empty()).then(|| {
            fds.push(PollFd::new(&stdin, PollFlags::IN));
            fds.len() - 1
        });
        let pipe_idx = match (&streams.stdin, pending.is_empty()) {
            (Some(fd), false) => {
                fds.push(PollFd::new(fd, PollFlags::OUT));
                Some(fds.len() - 1)
            }
            _ => None,
        };
        let out_idx = streams.stdout.as_ref().map(|fd| {
            fds.push(PollFd::new(fd, PollFlags::IN));
            fds.len() - 1
        });
        let err_idx = streams.stderr.as_ref().map(|fd| {
            fds.push(PollFd::new(fd, PollFlags::IN));
            fds.len() - 1
        });
        proto::poll(&mut fds, -1)?;
        let revents: Vec<PollFlags> = fds.iter().map(|f| f.revents()).collect();
        drop(fds);
        let ready = |i: Option<usize>| i.is_some_and(|i| !revents[i].is_empty());

        if ready(sig_idx) {
            for sig in guard.read() {
                if sig == libc::SIGWINCH {
                    send_size(&mut conn)?;
                } else if exec {
                    conn.oneway_method(&iface::SignalParams { signal: sig })?;
                } else {
                    // (a container gets Kill: a session has no signal of its
                    // own; a container that does not run any more is the end
                    // the relay is about to read)
                    let _ = kill(dir, sig);
                }
            }
        }
        for (idx, slot, to) in [
            (out_idx, &mut streams.stdout, stdout),
            (err_idx, &mut streams.stderr, stderr),
        ] {
            if !ready(idx) {
                continue;
            }
            if let Some(fd) = slot.as_ref() {
                match rustix::io::read(fd, &mut buf) {
                    Ok(0) => *slot = None,
                    Ok(n) => write_all_fd(to, &buf[..n])?,
                    Err(rustix::io::Errno::INTR) | Err(rustix::io::Errno::AGAIN) => {}
                    Err(_) => *slot = None,
                }
            }
        }
        if ready(in_idx) {
            match gather(stdin, &mut buf) {
                Ok((0, _)) => {
                    input_open = false;
                    input_ended = true;
                }
                Ok((n, at_end)) => {
                    if at_end {
                        input_open = false;
                        input_ended = true;
                    }
                    let (bytes, detach) = matcher.feed(&buf[..n]);
                    pending.extend_from_slice(&bytes);
                    if detach {
                        // what was typed before the keys goes first
                        if let Some(fd) = &streams.stdin {
                            let _ = rustix::fs::fcntl_setfl(fd, rustix::fs::OFlags::empty());
                            let _ = write_all_fd(fd.as_fd(), &pending[sent..]);
                        }
                        if exec {
                            conn.oneway_method(&iface::Detach {})?;
                        }
                        break SessionEnd::Detached;
                    }
                }
                Err(rustix::io::Errno::INTR) | Err(rustix::io::Errno::AGAIN) => {}
                Err(_) => {
                    input_open = false;
                    input_ended = true;
                }
            }
        }
        if (ready(pipe_idx) || ready(in_idx)) && !pending.is_empty() {
            if let Some(fd) = &streams.stdin {
                match rustix::io::write(fd, &pending[sent..]) {
                    Ok(n) => {
                        sent += n;
                        if sent == pending.len() {
                            pending.clear();
                            sent = 0;
                        }
                    }
                    Err(rustix::io::Errno::INTR) | Err(rustix::io::Errno::AGAIN) => {}
                    // the input of the container is closed
                    Err(_) => {
                        streams.stdin = None;
                        pending.clear();
                        sent = 0;
                        input_open = false;
                        input_ended = false;
                    }
                }
            }
        }
        if !revents[0].is_empty() {
            let found = loop {
                match next_end(&mut conn, exec)? {
                    None => break Some(SessionEnd::Lost),
                    Some(Some(e)) => break Some(e),
                    Some(None) if conn.has_buffered() => {}
                    Some(None) => break None,
                }
            };
            if let Some(e) = found {
                break e;
            }
        }
    };
    if !matches!(end, SessionEnd::Detached) {
        // the monitor wrote everything out before its last reply
        drain(&mut streams.stdout, stdout, &mut buf)?;
        drain(&mut streams.stderr, stderr, &mut buf)?;
    }
    Ok(end)
}

/// A command to run in a container.
#[derive(Default)]
pub struct ExecOptions {
    pub command: Vec<String>,
    pub env: Vec<String>,
    pub cwd: Option<String>,
    pub user: Option<String>,
    pub privileged: bool,
    pub tty: bool,
    pub stdin: bool,
    pub sig_proxy: bool,
    /// Kill the command after this long
    pub timeout_ms: Option<u64>,
    /// The keys that detach from the command, which goes on (with a
    /// terminal, none: ctrl-p,ctrl-q; "": none)
    pub detach_keys: Option<String>,
    /// Descriptors the command gets as 3, 4, ..., but in the slots of
    /// `preserve_holes`
    pub preserve_fds: Vec<OwnedFd>,
    /// The slots (0 is 3) the command gets no descriptor in (a `/dev/null`
    /// stands in for them)
    pub preserve_holes: Vec<u32>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ExecEnd {
    /// The command exited with this status.
    Exited(i32),
    /// The monitor killed it after the timeout.
    TimedOut,
    /// The client detached; the command goes on.
    Detached,
    Lost,
}

/// Run a command in the container of the monitor in `dir`, with the
/// standard streams of this process.  The command goes on if this process
/// goes away (as podman's: its output is dropped then).
pub fn exec(
    dir: &Path,
    opts: &ExecOptions,
    stdin: BorrowedFd<'_>,
    stdout: BorrowedFd<'_>,
    stderr: BorrowedFd<'_>,
) -> io::Result<ExecEnd> {
    let session = open_exec_with(
        dir,
        &opts.preserve_fds,
        &ExecRequest {
            preserve_fds: (opts.preserve_fds.len() + opts.preserve_holes.len()) as u32,
            preserve_holes: opts.preserve_holes.clone(),
            command: opts.command.clone(),
            env: opts.env.clone(),
            cwd: opts.cwd.clone(),
            user: opts.user.clone(),
            tty: opts.tty,
            stdin: opts.stdin,
            timeout_ms: opts.timeout_ms,
            privileged: opts.privileged,
            // (the detach keys detach it later)
            detach: false,
            notify_start: false,
        },
    )?;
    let attach_opts = AttachOptions {
        stdin: opts.stdin,
        tty: opts.tty,
        // (a client that goes away leaves the command running, as podman's
        // does)
        detach_keys: opts.detach_keys.clone(),
        sig_proxy: opts.sig_proxy,
        ..AttachOptions::default()
    };
    Ok(
        match relay(
            dir,
            session.conn,
            session.streams,
            &attach_opts,
            true,
            (stdin, stdout, stderr),
        )? {
            SessionEnd::Exited(_, iface::ExecReason::TimedOut) => ExecEnd::TimedOut,
            SessionEnd::Exited(code, _) => ExecEnd::Exited(code),
            SessionEnd::Detached => ExecEnd::Detached,
            SessionEnd::Lost => ExecEnd::Lost,
        },
    )
}
