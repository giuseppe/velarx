// SPDX-License-Identifier: Apache-2.0
//! Calls that a sandbox (a seccomp filter) must refuse, to test it from the
//! inside: each returns what the kernel answered, so that a self-test can
//! tell the filter (`EPERM`) from a failure of another kind.

/// The error number of the `errno` of the last call as an `i32` (0 when
/// there is none).
fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

/// `io_uring_setup` with empty parameters: the error number, 0 when it
/// worked (the descriptor is closed).
pub fn io_uring_setup_errno() -> i32 {
    let mut params = [0u8; 120];
    // SAFETY: io_uring_setup reads and writes the 120 bytes of its
    // parameters (the size of `struct io_uring_params`), which `params`
    // holds, for the time of the call.
    let r = unsafe { libc::syscall(libc::SYS_io_uring_setup, 1u32, params.as_mut_ptr()) };
    if r < 0 {
        return errno();
    }
    // SAFETY: the call made a new descriptor, which nothing else owns.
    drop(unsafe { <std::os::fd::OwnedFd as std::os::fd::FromRawFd>::from_raw_fd(r as i32) });
    0
}

/// `execve("/bin/true")`: the error number.  When it is allowed, the
/// process becomes `true` and does not come back.
pub fn execve_true_errno() -> i32 {
    let argv = [c"/bin/true".as_ptr(), std::ptr::null()];
    // SAFETY: the path and the argv are NUL terminated and live for the call;
    // the environment is empty (a null pointer is the empty one for Linux).
    unsafe {
        libc::execve(c"/bin/true".as_ptr(), argv.as_ptr(), std::ptr::null());
    }
    errno()
}

/// Whether `fork` is refused.  A child that is made ends at once.
pub fn fork_is_refused() -> bool {
    match crate::process::fork_known_single_threaded() {
        Ok(crate::process::Fork::Child(_)) => crate::process::exit_now(0),
        Ok(crate::process::Fork::Parent(_)) => false,
        Err(_) => true,
    }
}

/// `fcntl(fd, cmd, arg)` for a command whose argument is an integer: the
/// error number, 0 when it worked.
pub fn fcntl_errno(fd: i32, cmd: i32, arg: i32) -> i32 {
    // SAFETY: fcntl takes integers (the commands used are those whose
    // argument is one).
    if unsafe { libc::fcntl(fd, cmd, arg) } < 0 {
        errno()
    } else {
        0
    }
}

/// `tgkill(tgid, tid, signum)`: the error number, 0 when it worked.
pub fn tgkill_errno(tgid: i32, tid: i32, signum: i32) -> i32 {
    // SAFETY: tgkill takes three integers.
    if unsafe { libc::syscall(libc::SYS_tgkill, tgid, tid, signum) } < 0 {
        errno()
    } else {
        0
    }
}

/// `setuid(uid)` as a system call of its own (not the C library's, which
/// tells the other threads): the error number, 0 when it worked.
pub fn setuid_errno(uid: u32) -> i32 {
    // SAFETY: setuid takes an integer.
    if unsafe { libc::syscall(libc::SYS_setuid, uid) } < 0 {
        errno()
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unprivileged_setuid_to_root_is_refused() {
        // (as root it would succeed, and change nothing)
        if rustix::process::getuid().as_raw() != 0 {
            assert_ne!(setuid_errno(0), 0);
        }
    }

    #[test]
    fn a_tgkill_of_nothing_is_an_error() {
        assert_ne!(tgkill_errno(i32::MAX, i32::MAX, 0), 0);
    }

    #[test]
    fn fcntl_of_a_closed_descriptor_is_an_error() {
        assert_ne!(fcntl_errno(i32::MAX, libc::F_SETFL, 0), 0);
    }

    #[test]
    fn io_uring_answers_something() {
        let _ = io_uring_setup_errno();
    }
}
