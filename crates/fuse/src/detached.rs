// SPDX-License-Identifier: Apache-2.0
//! A FUSE file system mounted with the new mount API, detached: the
//! descriptor of the mount is the only name it has, and it ends when the
//! last reference to its superblock goes.

use rustix::mount::{
    fsconfig_create, fsconfig_set_fd, fsconfig_set_flag, fsconfig_set_string, fsmount, fsopen,
    FsMountFlags, FsOpenFlags, MountAttrFlags,
};
use std::io;
use std::os::fd::{AsFd, OwnedFd};

fn fail(what: &str, e: rustix::io::Errno) -> io::Error {
    io::Error::other(format!("{what} failed: {e}"))
}

/// The read-only FUSE mount `source`, detached (`nodev`, `nosuid`), and the
/// open `/dev/fuse` its server reads the requests of the kernel from.  With
/// `allow_other` the users of other user namespaces than the server's reach
/// it (the permissions of the files still decide, `default_permissions`).
/// Needs the right to mount in the user namespace of the caller; no
/// `fusermount3`.
pub fn fuse_mount(source: &str, allow_other: bool) -> io::Result<(OwnedFd, OwnedFd)> {
    let dev = rustix::fs::open(
        "/dev/fuse",
        rustix::fs::OFlags::RDWR | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(|e| fail("open(/dev/fuse)", e))?;
    let fs = fsopen("fuse", FsOpenFlags::FSOPEN_CLOEXEC).map_err(|e| fail("fsopen(fuse)", e))?;
    let set = |key: &str, value: String| {
        fsconfig_set_string(fs.as_fd(), key, value)
            .map_err(|e| fail(&format!("fsconfig({key})"), e))
    };
    set("source", source.to_string())?;
    fsconfig_set_fd(fs.as_fd(), "fd", dev.as_fd()).map_err(|e| fail("fsconfig(fd)", e))?;
    set("rootmode", "40000".to_string())?;
    set("user_id", rustix::process::getuid().as_raw().to_string())?;
    set("group_id", rustix::process::getgid().as_raw().to_string())?;
    let flags: &[&str] = if allow_other {
        &["allow_other", "default_permissions", "ro"]
    } else {
        &["default_permissions", "ro"]
    };
    for flag in flags {
        fsconfig_set_flag(fs.as_fd(), *flag).map_err(|e| fail(&format!("fsconfig({flag})"), e))?;
    }
    fsconfig_create(fs.as_fd()).map_err(|e| fail("fsconfig_create(fuse)", e))?;
    let mount = fsmount(
        fs.as_fd(),
        FsMountFlags::FSMOUNT_CLOEXEC,
        MountAttrFlags::MOUNT_ATTR_RDONLY
            | MountAttrFlags::MOUNT_ATTR_NODEV
            | MountAttrFlags::MOUNT_ATTR_NOSUID,
    )
    .map_err(|e| fail("fsmount(fuse)", e))?;
    Ok((mount, dev))
}
