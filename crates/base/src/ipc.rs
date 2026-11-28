// SPDX-License-Identifier: Apache-2.0
//! Private unix sockets between the daemon and its helpers (the services
//! of the content sources).
//!
//! These sockets carry requests that must not come from other users: they
//! live in a directory only their owner can enter, are created with mode
//! 0600, and every connection is checked with `SO_PEERCRED` on both sides.
//! Only the user running the daemon and root are trusted.

use std::io;
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::UnixListener;
use std::path::Path;

fn me() -> u32 {
    rustix::process::geteuid().as_raw()
}

pub use velarx_proto::trusted_uid;

/// What a failed `accept` asks of the loop that called it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcceptFailure {
    /// The connection went away before it was accepted, or the kernel
    /// refused that one connection (a firewall rule: `EPERM`); accept(2)
    /// says to treat the network errors of the new socket as `EAGAIN`:
    /// accept again, at once
    Retry,
    /// Out of descriptors or memory (of the process or of the host), or an
    /// error not known to be final: the connection stays queued and a retry
    /// at once fails the same way.  Accept again when a connection of this
    /// process ended, and at the latest after [`ACCEPT_WAIT`]: what frees
    /// the room may be another process
    Wait,
    /// The listener itself cannot accept (it is not a listening socket any
    /// more): nothing a retry changes
    Broken,
}

/// The longest wait of [`AcceptFailure::Wait`] before the next accept.
pub const ACCEPT_WAIT: std::time::Duration = std::time::Duration::from_secs(1);

/// What the loop does of the error `e` of an `accept`.
pub fn accept_failure(e: &io::Error) -> AcceptFailure {
    use libc::{
        EAGAIN, EBADF, ECONNABORTED, ECONNRESET, EFAULT, EHOSTDOWN, EHOSTUNREACH, EINTR, EINVAL,
        ENETDOWN, ENETUNREACH, ENONET, ENOPROTOOPT, ENOTSOCK, EOPNOTSUPP, EPERM, EPROTO, ETIMEDOUT,
    };
    match e.raw_os_error() {
        Some(
            EAGAIN | ECONNABORTED | ECONNRESET | EHOSTDOWN | EHOSTUNREACH | EINTR | ENETDOWN
            | ENETUNREACH | ENONET | ENOPROTOOPT | EOPNOTSUPP | EPERM | EPROTO | ETIMEDOUT,
        ) => AcceptFailure::Retry,
        Some(EBADF | EINVAL | ENOTSOCK | EFAULT) => AcceptFailure::Broken,
        // EMFILE, ENFILE, ENOBUFS, ENOMEM, and what accept(2) does not list
        _ => AcceptFailure::Wait,
    }
}

fn denied(msg: String) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, msg)
}

/// Create the directories of `dir` that are missing with mode 0700: the
/// store of a user is the user's alone.  One that exists keeps its mode
/// (the administrator's choice, and what a service manager made).
pub fn create_private_dirs(dir: &Path) -> io::Result<()> {
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
}

/// The directories of the file `path` that are missing are made 0700 and
/// the file, when it is not there, empty with mode 0600 (SQLite gives the
/// `-wal` and `-shm` files of a database its mode): what a user keeps is the
/// user's alone.
pub fn make_private_file(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        create_private_dirs(dir)?;
    }
    match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
    {
        Err(e) if e.kind() != io::ErrorKind::AlreadyExists => Err(e),
        _ => Ok(()),
    }
}

/// Create `dir` (and its missing parents) with mode 0700, or check that an
/// existing one is a directory of this user that nobody else can enter.
pub fn ensure_private_dir(dir: &Path) -> io::Result<()> {
    match std::fs::symlink_metadata(dir) {
        Ok(meta) => check_private_dir(dir, &meta),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            // (the directories above it that are missing are private too)
            if let Some(parent) = dir.parent().filter(|p| !p.as_os_str().is_empty()) {
                std::fs::DirBuilder::new()
                    .recursive(true)
                    .mode(0o700)
                    .create(parent)?;
            }
            match std::fs::DirBuilder::new().mode(0o700).create(dir) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e),
            }
            check_private_dir(dir, &std::fs::symlink_metadata(dir)?)
        }
        Err(e) => Err(e),
    }
}

fn check_private_dir(dir: &Path, meta: &std::fs::Metadata) -> io::Result<()> {
    if !meta.is_dir() {
        return Err(denied(format!(
            "{} is not a directory (symbolic links are not followed)",
            dir.display()
        )));
    }
    if meta.uid() != me() {
        return Err(denied(format!(
            "{} is owned by uid {}, not by uid {}",
            dir.display(),
            meta.uid(),
            me()
        )));
    }
    if meta.mode() & 0o077 != 0 {
        return Err(denied(format!(
            "{} has mode {:04o}: the directory of the private sockets must be accessible \
             to its owner only (chmod 700)",
            dir.display(),
            meta.mode() & 0o7777
        )));
    }
    Ok(())
}

/// Listen on `path`: in a private directory, with mode 0600.  A socket left
/// by an earlier run is replaced; anything else at that path is an error.
pub fn bind_private(path: &Path) -> io::Result<UnixListener> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "socket path without a directory",
            )
        })?;
    ensure_private_dir(parent)?;
    remove_stale(path)?;
    let listener = UnixListener::bind(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(listener)
}

/// Have the sockets `paths` removed when this process is gone, by a
/// process forked now (this process must have one thread): for a service
/// that binds its sockets before it confines itself and may remove no file
/// once confined (a right to remove its sockets would be one to remove the
/// other services' in the same directory).  The returned descriptor is held
/// for the life of the process; when it is closed (the process ends,
/// however) the child removes each socket that is still the one it was
/// (the same inode: one bound since by another process stays) and ends.
/// It then ends `service`, a child of this one: once this process confined
/// itself, its death signal does not leave its domain and would not reach
/// it.  (Its pidfd, taken now, names that process even once it is reaped.)
pub fn remove_when_gone(
    paths: &[std::path::PathBuf],
    service: Option<&std::process::Child>,
) -> io::Result<std::os::fd::OwnedFd> {
    let ids: Vec<(std::path::PathBuf, u64, u64)> = paths
        .iter()
        .filter_map(|p| {
            std::fs::symlink_metadata(p)
                .ok()
                .map(|m| (p.clone(), m.dev(), m.ino()))
        })
        .collect();
    let service = service
        .map(|child| {
            let pid = rustix::process::Pid::from_child(child);
            rustix::process::pidfd_open(pid, rustix::process::PidfdFlags::empty())
        })
        .transpose()?;
    let (read, write) = rustix::pipe::pipe_with(rustix::pipe::PipeFlags::CLOEXEC)?;
    match velarx_sys::process::fork_single_threaded("the remover of the sockets")? {
        velarx_sys::process::Fork::Child(child) => {
            // (nothing of the process but the pipe: its listeners, its
            // credentials...)
            {
                use std::os::fd::AsRawFd;
                let mut keep = vec![read.as_raw_fd(), write.as_raw_fd()];
                keep.extend(service.as_ref().map(|fd| fd.as_raw_fd()));
                child.close_all_but(&keep);
            }
            drop(write);
            let mut byte = [0u8; 1];
            // (an end of file: the parent is gone)
            loop {
                match rustix::io::read(&read, &mut byte) {
                    Ok(0) => break,
                    Ok(_) | Err(rustix::io::Errno::INTR) => continue,
                    Err(_) => break,
                }
            }
            for (path, dev, ino) in &ids {
                if std::fs::symlink_metadata(path).is_ok_and(|m| m.dev() == *dev && m.ino() == *ino)
                {
                    let _ = std::fs::remove_file(path);
                }
            }
            if let Some(service) = &service {
                let _ = rustix::process::pidfd_send_signal(service, rustix::process::Signal::TERM);
            }
            velarx_sys::process::exit_now(0)
        }
        velarx_sys::process::Fork::Parent(_) => Ok(write),
    }
}

/// [`bind_private`] for a socket that is reached through a descriptor of
/// it, never by its path: the path may be longer than the 107 bytes of a
/// socket address, as the socket is bound relative to a descriptor of its
/// directory (`/proc/self/fd/N/NAME`).
pub fn bind_private_long(path: &Path) -> io::Result<UnixListener> {
    let (Some(parent), Some(name)) = (
        path.parent().filter(|p| !p.as_os_str().is_empty()),
        path.file_name(),
    ) else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "socket path without a directory",
        ));
    };
    ensure_private_dir(parent)?;
    remove_stale(path)?;
    let dir = rustix::fs::open(
        parent,
        rustix::fs::OFlags::PATH | rustix::fs::OFlags::DIRECTORY | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )?;
    let short = velarx_sys::fd::proc_path(&dir).join(name);
    let listener = UnixListener::bind(&short)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(listener)
}

/// Listen on `path` for a service that must run once: under a lock of its
/// own (`PATH.lock`), a socket that something still listens on is an error
/// (`AddrInUse`), a stale one is replaced, anything else there is an
/// error.  Two processes that start together cannot both find the socket
/// stale and remove the other's, and a second start never takes the
/// socket of a running service.  With `private` the socket has mode 0600
/// from its creation (the mode of the socket is set before the bind, which
/// makes the file with it less the umask: no window with a wider mode and
/// no change of the umask, which is the process' and not the thread's).
/// The lock file stays: removing it would let a start lock a new file
/// while another holds the old one.
pub fn bind_unique(path: &Path, private: bool) -> io::Result<UnixListener> {
    use rustix::net::{AddressFamily, SocketAddrUnix, SocketFlags, SocketType};
    use std::os::unix::fs::OpenOptionsExt;
    let mut lock_name = path
        .file_name()
        .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?
        .to_os_string();
    lock_name.push(".lock");
    let lock = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path.with_file_name(lock_name))?;
    // (held for the check and the bind: they are short; released when
    // `lock` is closed, after the listen)
    velarx_sys::flock::flock_retrying(&lock, rustix::fs::FlockOperation::LockExclusive)?;
    let addr = SocketAddrUnix::new(path)?;
    if listens(&addr)? {
        return Err(io::Error::new(
            io::ErrorKind::AddrInUse,
            format!("another process listens on {}", path.display()),
        ));
    }
    remove_stale(path)?;
    let fd = rustix::net::socket_with(
        AddressFamily::UNIX,
        SocketType::STREAM,
        SocketFlags::CLOEXEC,
        None,
    )?;
    if private {
        rustix::fs::fchmod(&fd, rustix::fs::Mode::from_raw_mode(0o600))?;
    }
    rustix::net::bind(&fd, &addr)?;
    rustix::net::listen(&fd, libc::SOMAXCONN)?;
    Ok(UnixListener::from(fd))
}

/// Whether something listens on the socket at `addr`: a connection that is
/// refused (or no file) says no; one taken, or one waiting for room in a
/// full backlog, says yes (never blocks); anything else (no permission) is
/// an error, not a reason to remove the socket.
fn listens(addr: &rustix::net::SocketAddrUnix) -> io::Result<bool> {
    use rustix::io::Errno;
    use rustix::net::{AddressFamily, SocketFlags, SocketType};
    let probe = rustix::net::socket_with(
        AddressFamily::UNIX,
        SocketType::STREAM,
        SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
        None,
    )?;
    match rustix::net::connect(&probe, addr) {
        Ok(()) | Err(Errno::AGAIN) | Err(Errno::INPROGRESS) => Ok(true),
        Err(Errno::CONNREFUSED) | Err(Errno::NOENT) => Ok(false),
        Err(e) => Err(e.into()),
    }
}

/// A socket left at `path` by an earlier run is removed; anything else
/// there is an error.
fn remove_stale(path: &Path) -> io::Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_socket() => std::fs::remove_file(path),
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!("{} exists and is not a socket", path.display()),
        )),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

/// Check the process at the other end of a connection we accepted: its user
/// must be one `trusted` accepts (`trusted_uid`, except in tests).
pub fn check_client(stream: &impl std::os::fd::AsFd, trusted: fn(u32) -> bool) -> io::Result<()> {
    let uid = rustix::net::sockopt::socket_peercred(stream)?.uid.as_raw();
    if trusted(uid) {
        Ok(())
    } else {
        Err(denied(format!("connection from uid {uid} refused")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_service_that_runs_keeps_its_socket() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("svc.sock");
        // (0600 from the bind: no chmod after it, whatever the umask)
        let first = bind_unique(&path, true).unwrap();
        let e = bind_unique(&path, true).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::AddrInUse);
        // (the first is still the one that answers)
        assert!(std::os::unix::net::UnixStream::connect(&path).is_ok());
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        // a socket nothing listens on is stale (shut down first: a child
        // another test forks meanwhile holds a copy of the descriptor until
        // its exec, and the socket would listen on through it)
        rustix::net::shutdown(&first, rustix::net::Shutdown::Read).unwrap();
        drop(first);
        bind_unique(&path, true).unwrap();
        // anything else is not replaced
        let other = dir.path().join("file");
        std::fs::write(&other, "x").unwrap();
        assert_eq!(
            bind_unique(&other, true).unwrap_err().kind(),
            io::ErrorKind::AlreadyExists
        );
    }

    /// Starts at once: one listener, the others told it is taken (without
    /// the lock, each removes the socket the one before bound).
    #[test]
    fn starts_at_the_same_time_leave_one_listener() {
        for round in 0..20 {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join(format!("svc{round}.sock"));
            let go = std::sync::Barrier::new(8);
            let results: Vec<_> = std::thread::scope(|s| {
                let starts: Vec<_> = (0..8)
                    .map(|_| s.spawn(|| (go.wait(), bind_unique(&path, true)).1))
                    .collect();
                starts.into_iter().map(|h| h.join().unwrap()).collect()
            });
            let bound = results.iter().filter(|r| r.is_ok()).count();
            assert_eq!(bound, 1, "round {round}: {} listeners", bound);
            assert!(results
                .iter()
                .filter_map(|r| r.as_ref().err())
                .all(|e| e.kind() == io::ErrorKind::AddrInUse));
        }
    }

    #[test]
    fn an_accept_error_says_what_the_loop_does() {
        let os = |n| accept_failure(&io::Error::from_raw_os_error(n));
        for retry in [libc::ECONNABORTED, libc::EPERM, libc::EPROTO, libc::EINTR] {
            assert_eq!(os(retry), AcceptFailure::Retry, "{retry}");
        }
        // (out of room, of the process or of the host: transient, never the
        // end of the service)
        for wait in [libc::EMFILE, libc::ENFILE, libc::ENOBUFS, libc::ENOMEM] {
            assert_eq!(os(wait), AcceptFailure::Wait, "{wait}");
        }
        // an error accept(2) does not list is not taken for a final one
        assert_eq!(os(libc::EIO), AcceptFailure::Wait);
        assert_eq!(
            accept_failure(&io::Error::other("no os error")),
            AcceptFailure::Wait
        );
        for broken in [libc::EBADF, libc::EINVAL, libc::ENOTSOCK] {
            assert_eq!(os(broken), AcceptFailure::Broken, "{broken}");
        }
    }

    #[test]
    fn test_a_private_directory_is_created_with_mode_700() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("a/b/services");
        ensure_private_dir(&dir).unwrap();
        assert_eq!(std::fs::metadata(&dir).unwrap().mode() & 0o777, 0o700);
        ensure_private_dir(&dir).unwrap();
    }

    #[test]
    fn test_a_directory_others_can_enter_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        for mode in [0o750, 0o705, 0o755, 0o770, 0o777] {
            let dir = tmp.path().join(format!("d{mode:o}"));
            std::fs::create_dir(&dir).unwrap();
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(mode)).unwrap();
            let err = ensure_private_dir(&dir).unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::PermissionDenied, "{mode:o}");
        }
    }

    #[test]
    fn test_a_symlink_or_a_file_is_not_a_private_directory() {
        let tmp = tempfile::tempdir().unwrap();
        let real = tmp.path().join("real");
        ensure_private_dir(&real).unwrap();
        let link = tmp.path().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert!(ensure_private_dir(&link).is_err());
        let file = tmp.path().join("file");
        std::fs::write(&file, b"x").unwrap();
        assert!(ensure_private_dir(&file).is_err());
    }

    #[test]
    fn test_a_socket_is_private_and_replaces_a_stale_one() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("services/x.sock");
        let first = bind_private(&path).unwrap();
        assert_eq!(std::fs::metadata(&path).unwrap().mode() & 0o777, 0o600);
        assert_eq!(
            std::fs::metadata(path.parent().unwrap()).unwrap().mode() & 0o777,
            0o700
        );
        // A stale socket (the listener is gone, the file is not).
        drop(first);
        let second = bind_private(&path).unwrap();
        drop(second);
    }

    /// A socket reached through a descriptor is bound whatever the length
    /// of its directory's path, beyond what a socket address holds, private
    /// as the others; it takes a stale one's place, never what is not a
    /// socket.
    #[test]
    fn test_a_socket_reached_by_descriptor_binds_in_a_long_directory() {
        let tmp = tempfile::tempdir().unwrap();
        let mut dir = tmp.path().to_path_buf();
        while dir.as_os_str().len() <= 120 {
            dir.push("a-directory-with-a-long-name");
        }
        let path = dir.join("services/x.sock");
        assert!(path.as_os_str().len() > 107);
        assert!(bind_private(&path).is_err());
        let listener = bind_private_long(&path).unwrap();
        assert!(std::fs::symlink_metadata(&path)
            .unwrap()
            .file_type()
            .is_socket());
        assert_eq!(std::fs::metadata(&path).unwrap().mode() & 0o777, 0o600);
        // reached through a descriptor of it
        let fd = rustix::fs::open(
            &path,
            rustix::fs::OFlags::PATH | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .unwrap();
        let by_fd = velarx_sys::fd::proc_str(&fd);
        let _client = std::os::unix::net::UnixStream::connect(by_fd).unwrap();
        listener.accept().unwrap();
        drop(listener);
        drop(bind_private_long(&path).unwrap());
        std::fs::remove_file(&path).unwrap();
        std::fs::write(&path, b"precious").unwrap();
        assert!(bind_private_long(&path).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"precious");
    }

    #[test]
    fn test_bind_does_not_remove_what_is_not_a_socket() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("services");
        ensure_private_dir(&dir).unwrap();
        let path = dir.join("x.sock");
        std::fs::write(&path, b"precious").unwrap();
        assert!(bind_private(&path).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"precious");
    }

    #[test]
    fn test_this_user_and_root_are_trusted() {
        assert!(trusted_uid(me()));
        assert!(trusted_uid(0));
        let other = if me() == 4242 { 4243 } else { 4242 };
        assert!(!trusted_uid(other));
    }
}
