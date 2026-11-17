// SPDX-License-Identifier: Apache-2.0
//! Namespaces.

use rustix::thread::UnshareFlags;
use std::io;

/// Give this thread namespaces of its own (`unshare(2)`): the flags are
/// namespaces only (`NEWNS`, `NEWNET`, `NEWUSER`, `NEWUTS`, ...).  The file
/// descriptor table is not unshared (`EINVAL`): other threads could not use
/// the descriptors this one makes.
pub fn unshare(flags: UnshareFlags) -> io::Result<()> {
    if flags.contains(UnshareFlags::FILES) {
        return Err(io::Error::from_raw_os_error(libc::EINVAL));
    }
    // SAFETY: the flags are namespaces only (FILES, the one flag that makes
    // descriptors of a thread unusable by the others, is refused above).
    unsafe { rustix::thread::unshare_unsafe(flags) }.map_err(io::Error::from)
}

/// A descriptor of the user namespace that owns the namespace `ns`
/// (`NS_GET_USERNS`).
pub fn owner_user_namespace(ns: std::os::fd::BorrowedFd<'_>) -> io::Result<std::os::fd::OwnedFd> {
    use std::os::fd::{AsRawFd, FromRawFd};
    const NS_GET_USERNS: libc::c_ulong = 0xb701;
    // SAFETY: NS_GET_USERNS takes no argument and returns a new descriptor
    // (or -1).
    let fd = unsafe { libc::ioctl(ns.as_raw_fd(), NS_GET_USERNS as _) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` is a new descriptor that nothing else owns.
    Ok(unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) })
}

/// The network namespace of the process of `pidfd`
/// (`PIDFD_GET_NET_NAMESPACE`, Linux 6.11): the process cannot be another
/// one that got its number.  `ENOTTY` or `EINVAL` from an older kernel.
pub fn pidfd_net_namespace(pidfd: std::os::fd::BorrowedFd<'_>) -> io::Result<std::os::fd::OwnedFd> {
    use std::os::fd::{AsRawFd, FromRawFd};
    // _IO(PIDFS_IOCTL_MAGIC 0xFF, 4)
    const PIDFD_GET_NET_NAMESPACE: libc::c_ulong = 0xff04;
    // SAFETY: the request takes no argument and returns a new descriptor
    // (or -1).
    let fd = unsafe { libc::ioctl(pidfd.as_raw_fd(), PIDFD_GET_NET_NAMESPACE as _) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` is a new descriptor that nothing else owns.
    Ok(unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) })
}

/// Start a child in a new user namespace that does nothing and dies with
/// this process (`PDEATHSIG` SIGKILL): its pid.  The caller writes the id
/// maps of the namespace through `/proc/<pid>/` and kills and waits for
/// the child when it is done.
pub fn start_user_namespace_holder() -> io::Result<i32> {
    extern "C" fn child_fn(_arg: *mut libc::c_void) -> libc::c_int {
        // The child runs on its own copy of the stack and only calls
        // prctl and pause, which are async-signal-safe.
        let _ =
            rustix::process::set_parent_process_death_signal(Some(rustix::process::Signal::KILL));
        crate::process::pause_forever()
    }

    // 16-byte aligned, as the ABI wants of a stack; the child only pauses
    #[repr(align(16))]
    struct Stack([u8; 4096]);
    let mut stack = Box::new(Stack([0; 4096]));
    let stack_top = stack.0.as_mut_ptr().wrapping_add(stack.0.len());

    // SAFETY: the child runs `child_fn` on its own copy of the stack (no
    // CLONE_VM) and calls only prctl and pause; `stack` outlives the call.
    let pid = unsafe {
        libc::clone(
            child_fn,
            stack_top as *mut libc::c_void,
            libc::CLONE_NEWUSER | libc::SIGCHLD,
            std::ptr::null_mut(),
        )
    };
    if pid < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(pid)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The namespace of this process through its pidfd is its own (on a
    /// kernel that has the request).
    #[test]
    fn the_net_namespace_of_a_pidfd() {
        use std::os::unix::fs::MetadataExt;
        let pidfd = rustix::process::pidfd_open(
            rustix::process::getpid(),
            rustix::process::PidfdFlags::empty(),
        )
        .unwrap();
        use std::os::fd::AsFd;
        match pidfd_net_namespace(pidfd.as_fd()) {
            Ok(ns) => {
                let own = std::fs::metadata("/proc/self/ns/net").unwrap();
                let got = std::fs::File::from(ns).metadata().unwrap();
                assert_eq!((own.dev(), own.ino()), (got.dev(), got.ino()));
            }
            Err(e) => assert!(
                matches!(e.raw_os_error(), Some(libc::ENOTTY | libc::EINVAL)),
                "{e}"
            ),
        }
    }

    #[test]
    fn the_owner_of_a_namespace_is_a_user_namespace_or_an_error() {
        let net = std::fs::File::open("/proc/self/ns/net").unwrap();
        if let Ok(owner) = owner_user_namespace(std::os::fd::AsFd::as_fd(&net)) {
            let me = std::fs::metadata("/proc/self/ns/user").unwrap();
            let owner = std::fs::File::from(owner).metadata().unwrap();
            assert_eq!(
                std::os::unix::fs::MetadataExt::ino(&owner),
                std::os::unix::fs::MetadataExt::ino(&me)
            );
        }
    }

    #[test]
    fn the_file_table_is_not_unshared() {
        let e = unshare(UnshareFlags::FILES).unwrap_err();
        assert_eq!(e.raw_os_error(), Some(libc::EINVAL));
    }
}
