// SPDX-License-Identifier: Apache-2.0
//! The mount system calls that `rustix` does not wrap.

use std::io;
use std::os::fd::{AsRawFd, BorrowedFd};

/// `MOUNT_ATTR_IDMAP`: map the ids of the mount with a user namespace.
pub const ATTR_IDMAP: u64 = 0x0010_0000;

/// `struct mount_attr` of mount_setattr(2).
#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct MountAttr {
    pub attr_set: u64,
    pub attr_clr: u64,
    pub propagation: u64,
    pub userns_fd: u64,
}

const SYS_MOUNT_SETATTR: libc::c_long = 442;
const AT_EMPTY_PATH: libc::c_uint = 0x1000;

fn setattr(
    dirfd: i32,
    path: *const libc::c_char,
    flags: libc::c_uint,
    attr: &MountAttr,
) -> io::Result<()> {
    // SAFETY: mount_setattr reads `attr` (its size given) and the NUL
    // terminated `path`, both live for the call; the callers pass a path
    // from a `CStr`.
    let r = unsafe {
        libc::syscall(
            SYS_MOUNT_SETATTR,
            dirfd,
            path,
            flags,
            attr as *const MountAttr,
            std::mem::size_of::<MountAttr>(),
        )
    };
    if r < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// `mount_setattr` on the (detached) mount `mount` itself.
pub fn setattr_fd(mount: BorrowedFd<'_>, attr: &MountAttr) -> io::Result<()> {
    setattr(mount.as_raw_fd(), c"".as_ptr(), AT_EMPTY_PATH, attr)
}

/// `mount_setattr` on the (detached) mount `mount` and every mount below it
/// (`AT_RECURSIVE`).
pub fn setattr_fd_recursive(mount: BorrowedFd<'_>, attr: &MountAttr) -> io::Result<()> {
    const AT_RECURSIVE: libc::c_uint = 0x8000;
    setattr(
        mount.as_raw_fd(),
        c"".as_ptr(),
        AT_EMPTY_PATH | AT_RECURSIVE,
        attr,
    )
}

/// `mount_setattr` on the mount at `path`, a path of the current directory
/// or an absolute one.
pub fn setattr_path(path: &std::ffi::CStr, attr: &MountAttr) -> io::Result<()> {
    setattr(libc::AT_FDCWD, path.as_ptr(), 0, attr)
}

/// `mount_setattr` on the mount at `path` and every mount below it
/// (`AT_RECURSIVE`).
pub fn setattr_path_recursive(path: &std::ffi::CStr, attr: &MountAttr) -> io::Result<()> {
    const AT_RECURSIVE: libc::c_uint = 0x8000;
    setattr(libc::AT_FDCWD, path.as_ptr(), AT_RECURSIVE, attr)
}

/// Make the mount tree at `path` read-only and private, with all the mounts
/// below it (`mount_setattr` with `AT_RECURSIVE`).
pub fn set_tree_read_only_private(path: &std::ffi::CStr) -> io::Result<()> {
    const AT_RECURSIVE: libc::c_uint = 0x8000;
    let attr = MountAttr {
        attr_set: libc::MOUNT_ATTR_RDONLY,
        attr_clr: 0,
        propagation: libc::MS_PRIVATE,
        userns_fd: 0,
    };
    setattr(libc::AT_FDCWD, path.as_ptr(), AT_RECURSIVE, &attr)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A descriptor that is no mount (a file) and no process.
    fn bad_fd() -> std::fs::File {
        std::fs::File::open("/dev/null").unwrap()
    }

    #[test]
    fn a_bad_descriptor_is_an_error() {
        let bad = bad_fd();
        let e = setattr_fd(std::os::fd::AsFd::as_fd(&bad), &MountAttr::default());
        assert!(e.is_err());
    }

    #[test]
    fn a_missing_path_is_an_error() {
        assert!(setattr_path(c"/nonexistent/x", &MountAttr::default()).is_err());
    }
}
