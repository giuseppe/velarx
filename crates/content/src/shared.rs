// SPDX-License-Identifier: Apache-2.0
//! A fetcher held by open connections: the registry fetcher that the
//! engines of a configuration start and share.
//!
//! * The engine binds the socket of the fetcher in the private services
//!   directory, under a name made of a digest of everything that makes what
//!   the fetcher does ([`SharedRegistry`]): another engine with the same
//!   configuration, environment and binary finds it there and uses it, one
//!   with any other never reaches it.  The lock of the socket serializes
//!   who finds it and who starts it.
//! * The fetcher runs in a session of its own and outlives the
//!   engine that started it: it leaves when its last connection is closed,
//!   at once (`--shared`), and takes its socket away under the lock as it
//!   does; a client that connected before that is served all the same.
//! * The engine connects to it when it needs it, for the calls of its pulls
//!   (it keeps none open once they ended); a connection asks it for more
//!   (`Connect`, the end of a socket pair the fetcher serves), and each one
//!   open keeps the fetcher.
//! * A fetcher that died is not replaced for the calls under way: they
//!   fail.  The engine starts a new one for its next need.

use std::io;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// A connection to the socket at `path`, whatever the length of the path
/// (through an `O_PATH` descriptor of it).
fn connect_long(path: &Path) -> io::Result<UnixStream> {
    let fd = rustix::fs::open(
        path,
        rustix::fs::OFlags::PATH | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )?;
    UnixStream::connect(velarx_sys::fd::proc_str(&fd))
}

/// The fetcher this process and the others of the same configuration
/// share: found at `socket`, or started there (in a session of its
/// own, with `command`, the listener as its descriptor 3, `extra` as 4,
/// 5, ...).  This process holds no connection of its own between its
/// needs: each one connects anew, under the lock of the socket.
pub struct SharedRegistry {
    socket: PathBuf,
    command: Box<dyn Fn() -> std::process::Command + Send + Sync>,
    extra: Vec<OwnedFd>,
    /// Where what the fetcher says goes (it outlives this process and
    /// its standard error)
    log: PathBuf,
    /// The fetcher this process started last
    started: Mutex<Option<u32>>,
}

impl SharedRegistry {
    /// The fetcher at `socket` (in a private directory, of any length);
    /// `command` starts one, with `extra` as its descriptors 4, 5, ...;
    /// what it says goes to `log`, written anew by each one started.
    pub fn new(
        socket: PathBuf,
        log: PathBuf,
        extra: Vec<OwnedFd>,
        command: impl Fn() -> std::process::Command + Send + Sync + 'static,
    ) -> Self {
        Self {
            socket,
            command: Box::new(command),
            extra,
            log,
            started: Mutex::new(None),
        }
    }

    /// The socket of the fetcher.
    pub fn socket(&self) -> &Path {
        &self.socket
    }

    /// The process of the fetcher this process started last, if any.
    pub fn started(&self) -> Option<u32> {
        *lock(&self.started)
    }

    /// A connection to the fetcher that serves the socket, or to one
    /// started now: under the lock of the socket, so that one fetcher
    /// serves it and a fetcher that leaves (it takes the socket away
    /// under the same lock) still serves who connected before.  No call is
    /// made on it yet.
    pub(crate) fn attach(&self) -> io::Result<UnixStream> {
        let stream = {
            let _lock = crate::activation::take_lock(&self.socket)?;
            match connect_long(&self.socket) {
                Ok(stream) => stream,
                // (none, or one that is gone without taking its socket away)
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused
                    ) =>
                {
                    self.start()?
                }
                Err(e) => return Err(e),
            }
        };
        velarx_base::ipc::check_client(&stream, velarx_base::ipc::trusted_uid)?;
        Ok(stream)
    }

    /// Bind the socket, connect to it and start the fetcher on it (the
    /// caller holds the lock).
    fn start(&self) -> io::Result<UnixStream> {
        use std::os::unix::fs::OpenOptionsExt;
        let listener = velarx_base::ipc::bind_private_long(&self.socket)?;
        let started = (|| {
            // (waits in the queue of the listener until the fetcher
            // accepts it)
            let stream = connect_long(&self.socket)?;
            let log = std::fs::OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .mode(0o600)
                .open(&self.log)?;
            let mut cmd = (self.command)();
            // (it outlives this process: in no directory that could be
            // unmounted, with no terminal, out of the session and of the
            // process group of this one, so that the signals of its
            // terminal and its hangup do not reach it)
            cmd.current_dir("/")
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(log);
            velarx_sys::spawn::pre_exec(&mut cmd, |_| {
                rustix::process::setsid()?;
                Ok(())
            });
            let extra = self.extra.iter().map(|f| f.as_raw_fd()).collect();
            velarx_base::spawn::pass_fds(&mut cmd, listener.as_raw_fd(), extra);
            let mut child = cmd.spawn()?;
            *lock(&self.started) = Some(child.id());
            // (reaped when it leaves, while this process lives; after, by
            // whoever reaps the orphans)
            std::thread::Builder::new()
                .name("fetcher-reap".into())
                .spawn(move || {
                    let _ = child.wait();
                })?;
            Ok(stream)
        })();
        if started.is_err() {
            // (nothing would ever accept on it)
            let _ = std::fs::remove_file(&self.socket);
        }
        started
    }
}
