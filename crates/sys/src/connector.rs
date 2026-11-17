// SPDX-License-Identifier: Apache-2.0
//! The connections of a process that confines itself ([`Connector`]).

use std::os::fd::AsRawFd as _;

/// The connections of a process that may look up no UNIX socket: a process
/// forked before the confinement connects to the one socket it was given and
/// passes each connection back as a descriptor, so that the confined process
/// holds no right to resolve any path (Landlock denies every connect by
/// name) and can only ask for a connection to that socket.  The helper does
/// nothing else: it ends when the process that started it does.
#[derive(Debug)]
pub struct Connector {
    requests: std::sync::Mutex<std::os::fd::OwnedFd>,
}

impl Connector {
    /// Start the helper for `path` (this process must have one thread).
    pub fn start(path: &std::path::Path) -> std::io::Result<Self> {
        let (ours, theirs) = pair()?;
        match crate::process::fork_single_threaded("the connector")? {
            crate::process::Fork::Child(child) => {
                // (no handler of the process: see the other start)
                crate::signal::reset_handlers();
                // (nothing of the process but the pair: its listeners, its
                // credentials...)
                child.close_all_but(&[theirs.as_raw_fd(), ours.as_raw_fd()]);
                serve(&theirs, ours, path);
                crate::process::exit_now(0)
            }
            crate::process::Fork::Parent(_) => Ok(Self {
                requests: std::sync::Mutex::new(ours),
            }),
        }
    }

    /// [`Connector::start`] for the main thread of a test binary, which
    /// waits for the thread that runs the test.
    pub fn start_beside_idle_threads(path: &std::path::Path) -> std::io::Result<Self> {
        use std::os::fd::{AsRawFd, FromRawFd};
        let (ours, theirs) = pair()?;
        let (raw, child_path) = (ours.as_raw_fd(), path.to_path_buf());
        crate::process::fork_beside_idle_threads(move |child| {
            // (no handler of the process: the one of a runtime's signal
            // driver writes a byte to the descriptor it knew, which is
            // closed below and may be another connection when a signal
            // comes)
            crate::signal::reset_handlers();
            child.close_all_but(&[theirs.as_raw_fd(), raw]);
            // SAFETY: the child has its own copy of the descriptor `ours`
            // owns in the parent, and owns it here.
            let copy = unsafe { std::os::fd::OwnedFd::from_raw_fd(raw) };
            serve(&theirs, copy, &child_path);
            0
        })?;
        Ok(Self {
            requests: std::sync::Mutex::new(ours),
        })
    }

    /// A new connection to the socket (blocking until the helper has
    /// connected).
    pub fn connect(&self) -> std::io::Result<std::os::unix::net::UnixStream> {
        let requests = self.requests.lock().unwrap_or_else(|e| e.into_inner());
        crate::scm::send(&*requests, &[0], &[])?;
        let mut reply = [0u8; 4];
        let got = crate::scm::recv(&*requests, &mut reply, 1, rustix::net::RecvFlags::empty())?;
        match got.fds.into_iter().next() {
            Some(fd) => Ok(std::os::unix::net::UnixStream::from(fd)),
            None if got.bytes == 4 => {
                Err(std::io::Error::from_raw_os_error(i32::from_le_bytes(reply)))
            }
            None => Err(std::io::Error::other("the connector is gone")),
        }
    }
}

/// A connection to the socket at `path`, whatever the length of the path
/// (through an `O_PATH` descriptor of it, as a socket address holds 107
/// bytes at most).
fn connect_long(path: &std::path::Path) -> std::io::Result<std::os::unix::net::UnixStream> {
    let fd = rustix::fs::open(
        path,
        rustix::fs::OFlags::PATH | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )?;
    std::os::unix::net::UnixStream::connect(crate::fd::proc_str(&fd))
}

fn pair() -> std::io::Result<(std::os::fd::OwnedFd, std::os::fd::OwnedFd)> {
    use rustix::net::{AddressFamily, SocketFlags, SocketType};
    Ok(rustix::net::socketpair(
        AddressFamily::UNIX,
        SocketType::SEQPACKET,
        SocketFlags::CLOEXEC,
        None,
    )?)
}

/// The helper: connect to `path` for each request on `theirs` (the process
/// that asked closes `ours` in the child), until the requests end.
fn serve(theirs: &std::os::fd::OwnedFd, ours: std::os::fd::OwnedFd, path: &std::path::Path) {
    drop(ours);
    let mut byte = [0u8; 1];
    // (an end of file: the process that started this is gone)
    while let Ok(got) = crate::scm::recv(theirs, &mut byte, 0, rustix::net::RecvFlags::empty()) {
        if got.bytes == 0 {
            break;
        }
        let reply = match connect_long(path) {
            Ok(stream) => crate::scm::send(theirs, &[0; 4], &[std::os::fd::AsFd::as_fd(&stream)]),
            Err(e) => crate::scm::send(
                theirs,
                &e.raw_os_error().unwrap_or(libc::EIO).to_le_bytes(),
                &[],
            ),
        };
        if reply.is_err() {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The socket may be at a path a socket address cannot hold (the
    /// services directory of a store in a long path): the helper connects
    /// through a descriptor of it.
    #[test]
    fn a_socket_at_a_long_path_is_reached() {
        let dir = tempfile::tempdir().unwrap();
        // (a directory per component: each short, the whole beyond 107 bytes)
        let mut path = dir.path().to_path_buf();
        while path.as_os_str().len() < 120 {
            path.push("a-directory-with-a-long-name");
        }
        std::fs::create_dir_all(&path).unwrap();
        let socket = path.join("engine");
        let fd = rustix::fs::open(
            &path,
            rustix::fs::OFlags::PATH | rustix::fs::OFlags::DIRECTORY,
            rustix::fs::Mode::empty(),
        )
        .unwrap();
        let listener =
            std::os::unix::net::UnixListener::bind(crate::fd::proc_path(&fd).join("engine"))
                .unwrap();
        let connector = Connector::start_beside_idle_threads(&socket).unwrap();
        let stream = connector.connect().unwrap();
        let (accepted, _) = listener.accept().unwrap();
        drop((stream, accepted));
        // (a socket that is not there is the error of the connect)
        let missing = Connector::start_beside_idle_threads(&path.join("none")).unwrap();
        assert_eq!(
            missing.connect().unwrap_err().raw_os_error(),
            Some(libc::ENOENT)
        );
    }
}
