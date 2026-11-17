// SPDX-License-Identifier: Apache-2.0
//! Descriptors that another process handed over.

use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
use std::path::PathBuf;

/// Whether the number `raw` is an open descriptor of this process.  Nothing
/// is borrowed: the answer is about the number, and is stale when another
/// thread opens or closes descriptors.
pub fn is_open(raw: i32) -> bool {
    // SAFETY: fcntl with F_GETFD takes integers and changes nothing.
    unsafe { libc::fcntl(raw, libc::F_GETFD) != -1 }
}

/// Ask the kernel to start writing the dirty pages of `fd` to the disk
/// (`sync_file_range` with `WRITE`): it does not wait, and the file is the
/// same afterwards.
pub fn start_writeback(fd: BorrowedFd<'_>) {
    // SAFETY: sync_file_range on an open descriptor with integers only; it
    // only asks for the writeback of the dirty pages.
    unsafe {
        libc::sync_file_range(
            std::os::fd::AsRawFd::as_raw_fd(&fd),
            0,
            0,
            libc::SYNC_FILE_RANGE_WRITE,
        );
    }
}

/// `fd`, an owned descriptor, in the reactor of tokio for `interest`.  The
/// result owns it: it is closed with it.
#[cfg(feature = "tokio")]
pub fn register<T: std::os::fd::AsRawFd>(
    fd: T,
    interest: tokio::io::Interest,
) -> std::io::Result<tokio::io::unix::AsyncFd<T>> {
    // SAFETY: `fd` is owned by the value it is made of, which the AsyncFd
    // takes and keeps open for as long as it is registered.
    unsafe { tokio::io::unix::AsyncFd::register_with_interest(fd, interest) }
        .map_err(std::io::Error::from)
}

/// The claim, made once per process, that nothing of it has opened a
/// descriptor yet: the process has only what its parent handed over, as
/// numbers.  A number becomes an owner only here (or in a forked child, see
/// [`crate::spawn::InChild`]), so that a number can never name a descriptor
/// that an [`OwnedFd`] elsewhere in the process owns.
///
/// A binary takes it first thing in `main` and passes `&Startup` to the code
/// that adopts; there is no other way to get one.  The numbers it acts on
/// are those that were open when it was taken (above the standard streams)
/// and that it has not adopted or closed since: what the process opens
/// later, at any number, is out of its reach, however late it is used.
#[derive(Debug)]
pub struct Startup {
    /// The inherited numbers no owner of this process holds yet.
    inherited: std::sync::Mutex<Vec<i32>>,
}

static STARTUP_TAKEN: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

impl Startup {
    /// The token; `None` when it was taken before in this process.  The
    /// caller says by calling it that the process has not opened any
    /// descriptor of its own: the open ones are noted now.
    pub fn take() -> Option<Self> {
        if STARTUP_TAKEN.swap(true, std::sync::atomic::Ordering::SeqCst) {
            return None;
        }
        Some(Self::of(open_numbers()))
    }

    fn of(inherited: Vec<i32>) -> Self {
        Self {
            inherited: std::sync::Mutex::new(inherited),
        }
    }

    fn inherited(&self) -> std::sync::MutexGuard<'_, Vec<i32>> {
        self.inherited.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Whether `raw` was passed by the process that executed this one and
    /// is not adopted or closed yet: what this process opened itself since,
    /// at whatever number, is not.
    pub fn is_inherited(&self, raw: i32) -> bool {
        self.inherited().contains(&raw)
    }

    /// The descriptor `raw`, which the process that executed this one
    /// passed on, as an owned one; `None` when it was not open when the
    /// token was taken, or when it was adopted or closed since (each number
    /// is taken once).
    pub fn adopt(&self, raw: i32) -> Option<OwnedFd> {
        let mut inherited = self.inherited();
        let at = inherited.iter().position(|&n| n == raw)?;
        inherited.swap_remove(at);
        // SAFETY: the number was open when the token was taken, before the
        // process opened anything, and it has not been adopted or closed
        // through the token since: it is the descriptor the parent passed,
        // and nothing of this process owns it.
        Some(unsafe { std::os::fd::FromRawFd::from_raw_fd(raw) })
    }

    /// Close the inherited descriptors from `first` to `last` (both
    /// included) that are not adopted: what the process was passed and
    /// does not use.
    pub fn close_range(&self, first: u32, last: u32) {
        self.inherited().retain(|&n| {
            let inside = (first..=last).contains(&n.unsigned_abs());
            if inside {
                // SAFETY: an inherited number nothing of this process owns
                // (see `adopt`); it is forgotten with the close.
                unsafe {
                    libc::close(n);
                }
            }
            !inside
        });
    }

    /// Close the inherited descriptors from `first` on that are not
    /// adopted.
    pub fn close_from(&self, first: u32) {
        self.close_range(first, u32::MAX);
    }
}

/// The open descriptors of this process above the standard streams, from
/// `/proc/self/fd`; without it (a process that does not see its `/proc`),
/// the numbers below the limit of open files (at most 65536) that are open.
fn open_numbers() -> Vec<i32> {
    let listed = std::fs::read_dir("/proc/self/fd").and_then(|dir| {
        dir.map(|entry| {
            Ok(entry?
                .file_name()
                .to_str()
                .and_then(|n| n.parse::<i32>().ok()))
        })
        .collect::<std::io::Result<Vec<Option<i32>>>>()
    });
    let candidates: Vec<i32> = match listed {
        // (the directory's own descriptor is listed too: it is closed now,
        // and left out by the check below)
        Ok(numbers) => numbers.into_iter().flatten().collect(),
        Err(_) => {
            let limit = rustix::process::getrlimit(rustix::process::Resource::Nofile)
                .current
                .unwrap_or(1024)
                .min(1 << 16);
            (0..limit as i32).collect()
        }
    };
    let mut open: Vec<i32> = candidates
        .into_iter()
        .filter(|&n| n > 2 && is_open(n))
        .collect();
    open.sort_unstable();
    open
}

/// `close_range` of the descriptors `first` to `last`, for a forked child
/// (its token says no other code of the child runs).
pub(crate) fn close_range(first: u32, last: u32) {
    // SAFETY: close_range takes integers and touches no memory.
    unsafe {
        libc::syscall(libc::SYS_close_range, first, last, 0u32);
    }
}

#[cfg(test)]
mod tests {
    use super::Startup;
    use std::os::fd::{AsRawFd, IntoRawFd};

    /// The token is handed out once per process.
    #[test]
    fn the_startup_token_is_taken_once() {
        let token = Startup::take().expect("the first call gets the token");
        assert!(Startup::take().is_none());
        assert!(Startup::take().is_none());
        drop(token);
        assert!(Startup::take().is_none(), "not even after it is dropped");
    }

    /// What was open when the token was taken is noted: the standard
    /// streams are left out, and a descriptor opened after it is not one.
    #[test]
    fn the_open_numbers_are_noted() {
        // (a number far above the ones the other tests of the process get,
        // the lowest free: none of them opens it once it is closed)
        let f = std::fs::File::open("/dev/null").unwrap();
        let high = rustix::io::fcntl_dupfd_cloexec(&f, 1000).unwrap();
        drop(f);
        let raw = high.as_raw_fd();
        let numbers = super::open_numbers();
        assert!(numbers.contains(&raw));
        assert!(numbers.iter().all(|&n| n > 2));
        drop(high);
        assert!(!super::open_numbers().contains(&raw));
    }

    /// A number is adopted when it was inherited, and once; a number the
    /// process opened after the token was taken (an owner holds it) is
    /// never adopted, nor closed by a range.
    #[test]
    fn only_an_inherited_number_is_adopted_once() {
        let inherited = std::fs::File::open("/dev/null").unwrap().into_raw_fd();
        // (the write end of a pipe: its close is seen on the read end)
        let (read_end, write_end) = rustix::pipe::pipe().unwrap();
        let gone = write_end.into_raw_fd();
        let token = Startup::of(vec![inherited, gone]);
        let owned_later = std::fs::File::open("/dev/null").unwrap();
        let later = owned_later.as_raw_fd();

        assert!(token.adopt(later).is_none(), "opened after the token");
        assert!(!token.is_inherited(later) && token.is_inherited(inherited));
        let owned = token.adopt(inherited).expect("an inherited number");
        assert!(!token.is_inherited(inherited), "adopted");
        assert!(token.adopt(inherited).is_none(), "and only once");

        token.close_range(0, u32::MAX);
        let mut b = [0u8; 1];
        assert_eq!(
            rustix::io::read(&read_end, &mut b),
            Ok(0),
            "the inherited one is closed"
        );
        assert!(super::is_open(later), "what an owner holds is not");
        assert!(super::is_open(owned.as_raw_fd()), "nor what was adopted");
        assert!(token.adopt(gone).is_none(), "a closed number is gone");
        drop((owned, owned_later, read_end));
    }

    #[test]
    fn a_number_is_open_while_its_descriptor_is() {
        let f = std::fs::File::open("/dev/null").unwrap();
        let raw = std::os::fd::AsRawFd::as_raw_fd(&f);
        assert!(super::is_open(raw));
        drop(f);
        assert!(!super::is_open(raw));
    }
}

/// The path of an open descriptor in `/proc/self/fd`, which names that file
/// whatever its own path becomes.
pub fn proc_path(fd: &impl AsFd) -> PathBuf {
    PathBuf::from(proc_str(fd))
}

/// [`proc_path`] as a `String`, for the calls that take text.
pub fn proc_str(fd: &impl AsFd) -> String {
    proc_raw(fd.as_fd().as_raw_fd())
}

/// The path in `/proc/self/fd` of the descriptor number `raw`: for a forked
/// child, which has descriptors by number only (no descriptor is borrowed;
/// the path is valid while `raw` is open in the calling process).
pub fn proc_raw(raw: i32) -> String {
    format!("/proc/self/fd/{raw}")
}

/// The path of `name` in the directory `dir` through `/proc/self/fd`, for
/// the `l*xattr` calls: the last component is not followed.
pub fn proc_child(dir: &impl AsFd, name: &std::ffi::OsStr) -> std::io::Result<std::ffi::CString> {
    use std::os::unix::ffi::OsStrExt;
    let mut path = proc_str(dir).into_bytes();
    path.push(b'/');
    path.extend_from_slice(name.as_bytes());
    std::ffi::CString::new(path)
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "a name has a NUL"))
}

/// `fd` opened again on a new open file description, for reading only: what
/// is passed on so that the receiver cannot write to it.
pub fn reopen_read_only(fd: &impl AsFd) -> std::io::Result<std::fs::File> {
    std::fs::File::open(proc_path(fd))
}

#[cfg(test)]
mod proc_tests {
    use super::*;
    use std::io::{Read, Write};

    #[test]
    fn a_descriptor_reopens_read_only_on_its_own_file() {
        let mut f = tempfile::tempfile().unwrap();
        f.write_all(b"abc").unwrap();
        assert!(proc_path(&f).starts_with("/proc/self/fd"));
        let mut again = reopen_read_only(&f).unwrap();
        let mut text = String::new();
        again.read_to_string(&mut text).unwrap();
        assert_eq!(text, "abc");
        // (reading only: a write through it is refused)
        assert!(again.write_all(b"x").is_err());
    }

    /// The paths name the descriptor (or a name in it) exactly: a number,
    /// no trailing slash, the bytes of a name as they are; a NUL in a name
    /// is refused, not cut.
    #[test]
    fn the_proc_paths_name_the_descriptor() {
        use std::os::unix::ffi::OsStrExt;
        let d = tempfile::tempdir().unwrap();
        let dir = std::fs::File::open(d.path()).unwrap();
        let raw = dir.as_raw_fd();
        assert_eq!(proc_str(&dir), format!("/proc/self/fd/{raw}"));
        assert_eq!(proc_raw(raw), proc_str(&dir));
        assert_eq!(proc_path(&dir.as_fd()), PathBuf::from(proc_str(&dir)));
        let name = std::ffi::OsStr::from_bytes(b"f\xff");
        std::fs::write(d.path().join(name), "x").unwrap();
        let child = proc_child(&dir, name).unwrap();
        assert_eq!(
            child.as_bytes(),
            [format!("/proc/self/fd/{raw}/").as_bytes(), b"f\xff"].concat()
        );
        let p = std::path::Path::new(std::ffi::OsStr::from_bytes(child.as_bytes()));
        assert_eq!(std::fs::read(p).unwrap(), b"x");
        let e = proc_child(&dir, std::ffi::OsStr::from_bytes(b"a\0b")).unwrap_err();
        assert_eq!(e.kind(), std::io::ErrorKind::InvalidInput);
    }
}

/// Whether nothing came on the idle connection `socket` and its peer did
/// not close it: a server that says nothing unless asked is still at the
/// other end (an end of file or a hangup says it is gone, and bytes nobody
/// asked for make the connection unusable).  Never waits.
pub fn peer_silent(socket: impl AsFd) -> bool {
    use rustix::event::{poll, PollFd, PollFlags, Timespec};
    let mut fds = [PollFd::new(&socket, PollFlags::IN | PollFlags::RDHUP)];
    let now = Timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    matches!(poll(&mut fds, Some(&now)), Ok(0))
}
