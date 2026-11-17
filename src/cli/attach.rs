// SPDX-License-Identifier: Apache-2.0
//! The command line's end of an attach or an exec session: the standard
//! streams of this process and its signals, with the copy loop of
//! `velarx_proto::stream` (the one the API and the CRI use).

use crate::client::Opened;
use std::io;
use std::os::fd::{AsFd, OwnedFd};
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, Interest, ReadBuf};
use velarx_proto::stream::{serve_to, Ended, Output, Reader, Writer};

/// Signals this process forwards to a process without a terminal.
const PROXIED_SIGNALS: [i32; 6] = [
    libc::SIGINT,
    libc::SIGTERM,
    libc::SIGHUP,
    libc::SIGQUIT,
    libc::SIGUSR1,
    libc::SIGUSR2,
];

/// What a session needs of the terminal of the user.
pub struct Relay<'a> {
    /// The process has a terminal: raw input, and the size follows
    pub tty: bool,
    /// The input of this process goes to the process
    pub input: bool,
    /// Forward the signals this process gets
    pub sig_proxy: bool,
    /// The size of the terminal changed (rows, columns)
    pub resize: &'a dyn Fn(u16, u16),
    /// A signal to forward
    pub signal: &'a dyn Fn(i32),
}

/// The size of the terminal of this process, in rows and columns.
pub fn terminal_size() -> Option<(u16, u16)> {
    let (stdin, stdout) = (rustix::stdio::stdin(), rustix::stdio::stdout());
    velarx_sys::tty::window_size(stdout).or_else(|| velarx_sys::tty::window_size(stdin))
}

/// Copy between the standard streams of this process and the session until
/// it ends or the user detaches.
pub fn relay(opened: Opened, r: Relay<'_>) -> anyhow::Result<Ended> {
    let Opened { session, hangup } = opened;
    let stdin = rustix::stdio::stdin();
    let _raw = (r.tty && r.input && velarx_sys::tty::is_terminal(stdin))
        .then(|| velarx_sys::tty::RawTerminal::new(stdin))
        .transpose()?;
    let mut signals: Vec<i32> = Vec::new();
    if r.tty {
        signals.push(libc::SIGWINCH);
    } else if r.sig_proxy {
        signals.extend(PROXIED_SIGNALS);
    }
    let guard = velarx_sys::signal::SignalGuard::new(&signals)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .build()?;
    let ended = runtime.block_on(async {
        let reader: Option<Reader> = if r.input {
            Some(Box::new(Input::new(rustix::io::fcntl_dupfd_cloexec(
                stdin, 0,
            )?)?))
        } else {
            None
        };
        let out: Writer = Box::new(Sink(rustix::io::fcntl_dupfd_cloexec(
            rustix::stdio::stdout(),
            0,
        )?));
        let err: Writer = Box::new(Sink(rustix::io::fcntl_dupfd_cloexec(
            rustix::stdio::stderr(),
            0,
        )?));
        let signalled = async {
            let Some(fd) = guard.fd() else {
                return std::future::pending::<io::Result<()>>().await;
            };
            let watch = velarx_sys::fd::register(fd.try_clone_to_owned()?, Interest::READABLE)?;
            loop {
                let mut ready = watch.readable().await?;
                for sig in guard.read() {
                    match (sig, terminal_size()) {
                        (libc::SIGWINCH, Some((rows, cols))) => (r.resize)(rows, cols),
                        (libc::SIGWINCH, None) => {}
                        (sig, _) => (r.signal)(sig),
                    }
                }
                ready.clear_ready();
            }
        };
        tokio::select! {
            ended = serve_to(session, reader, Output::split(out, err), None) => Ok(ended),
            gone = signalled => gone.map(|()| Ended::default()),
        }
    });
    drop(hangup);
    Ok(ended?)
}

/// The standard input: readable once the reactor says it is, a file at once.
enum Input {
    Polled(tokio::io::unix::AsyncFd<OwnedFd>),
    /// A regular file cannot be watched; reading it does not wait
    Plain(OwnedFd),
}

impl Input {
    /// `fd` in the reactor; a file that cannot be watched (a regular file,
    /// `/dev/null`) is always readable and read as it is.
    fn new(fd: OwnedFd) -> io::Result<Self> {
        let probe = rustix::io::fcntl_dupfd_cloexec(&fd, 3)?;
        match velarx_sys::fd::register(fd, Interest::READABLE) {
            Ok(polled) => {
                drop(probe);
                Ok(Self::Polled(polled))
            }
            Err(_) => Ok(Self::Plain(probe)),
        }
    }
}

impl AsyncRead for Input {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let read = |fd: &OwnedFd, buf: &mut ReadBuf<'_>| -> io::Result<usize> {
            let room = buf.initialize_unfilled();
            let want = room.len();
            let n = rustix::io::read(fd, room)?;
            buf.advance(n);
            Ok(if n < want { n } else { usize::MAX })
        };
        match &*self {
            Input::Plain(fd) => Poll::Ready(read(fd, buf).map(drop)),
            Input::Polled(fd) => loop {
                let mut guard = match fd.poll_read_ready(cx) {
                    Poll::Ready(g) => g?,
                    Poll::Pending => return Poll::Pending,
                };
                match read(guard.get_inner(), buf) {
                    // (the descriptor is a non blocking one that has nothing)
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => guard.clear_ready(),
                    got => {
                        // (it is a blocking one: it does not tell it would
                        // block, so what it had is read, unless the buffer
                        // was full)
                        if matches!(got, Ok(n) if n != usize::MAX) {
                            guard.clear_ready();
                        }
                        return Poll::Ready(got.map(drop));
                    }
                }
            },
        }
    }
}

/// A standard output or error: written whole when asked to (this process has
/// nothing else to do meanwhile, as when it relayed with `poll`).
struct Sink(OwnedFd);

impl AsyncWrite for Sink {
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut data = buf;
        while !data.is_empty() {
            match rustix::io::write(self.0.as_fd(), data) {
                Ok(n) => data = &data[n..],
                Err(rustix::io::Errno::INTR) => {}
                Err(rustix::io::Errno::AGAIN) => {
                    let mut fds = [rustix::event::PollFd::new(
                        &self.0,
                        rustix::event::PollFlags::OUT,
                    )];
                    let _ = rustix::event::poll(&mut fds, None);
                }
                Err(e) => return Poll::Ready(Err(e.into())),
            }
        }
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}
