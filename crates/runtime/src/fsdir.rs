// SPDX-License-Identifier: Apache-2.0
//! Directories opened by descriptor, for the copy-up of volumes and the
//! mounts of a container: never through a link that was planted.

use rustix::fs::{self, Mode, OFlags};
use rustix::io::Errno;
use std::io;
use std::os::fd::{BorrowedFd, OwnedFd};

fn io_err(e: Errno) -> io::Error {
    io::Error::from_raw_os_error(e.raw_os_error())
}

/// Open a directory by path, not following a symbolic link in the last
/// component.
pub fn open_dir(path: &std::path::Path) -> io::Result<OwnedFd> {
    fs::openat(
        fs::CWD,
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NOCTTY,
        Mode::empty(),
    )
    .map_err(io_err)
}

/// Open `path`, which is relative to the directory `root`, as if `root` was
/// the root of the file system: absolute links and `..` stay inside.  `None`
/// when it does not exist or is not a directory.
pub fn open_dir_in_root(root: BorrowedFd<'_>, path: &str) -> io::Result<Option<OwnedFd>> {
    let rel = path.trim_start_matches('/');
    let rel = if rel.is_empty() { "." } else { rel };
    match velarx_sys::fs::openat2_retry(
        root,
        rel,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOCTTY,
        Mode::empty(),
        fs::ResolveFlags::IN_ROOT | fs::ResolveFlags::NO_MAGICLINKS,
    ) {
        Ok(fd) => Ok(Some(fd)),
        Err(Errno::NOENT | Errno::NOTDIR) => Ok(None),
        Err(e) => Err(io_err(e)),
    }
}
