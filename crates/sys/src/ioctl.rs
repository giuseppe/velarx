// SPDX-License-Identifier: Apache-2.0
//! `ioctl` with a structure as its argument.

use std::io;
use std::os::fd::{AsRawFd, BorrowedFd};

/// The return value of the call (a count, for some requests) is returned.
///
/// `ioctl(fd, request, arg)` where the kernel reads the `repr(C)`
/// structure `arg`.  What the structure points to (a salt, a signature)
/// is a live buffer of the caller, valid for the call.
pub fn read_arg<T>(fd: BorrowedFd<'_>, request: libc::c_ulong, arg: &T) -> io::Result<i32> {
    // SAFETY: `arg` is a valid reference for the call and the request, which
    // the caller names for this structure, only reads it (and the buffers
    // its fields point to, which the caller keeps alive); `fd` is open
    // while borrowed.
    let rc = unsafe { libc::ioctl(fd.as_raw_fd(), request, arg as *const T) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(rc)
}

/// `ioctl(fd, request, arg)` where the kernel fills the `repr(C)`
/// structure `arg` (and the buffers its fields point to, which the caller
/// sized and keeps alive for the call).
pub fn fill_arg<T>(fd: BorrowedFd<'_>, request: libc::c_ulong, arg: &mut T) -> io::Result<i32> {
    // SAFETY: `arg` is a valid exclusive reference for the call and the
    // request, which the caller names for this structure, writes at most
    // its size (and into the buffers the caller sized); `fd` is open while
    // borrowed.
    let rc = unsafe { libc::ioctl(fd.as_raw_fd(), request, arg as *mut T) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(rc)
}

#[cfg(test)]
mod tests {
    use std::os::fd::AsFd;

    #[test]
    fn a_request_the_descriptor_does_not_know_fails() {
        let f = std::fs::File::open("/dev/null").unwrap();
        let mut arg = 0u32;
        assert!(super::fill_arg(f.as_fd(), 0xc004_6686, &mut arg).is_err());
        assert!(super::read_arg(f.as_fd(), 0x4004_6685, &arg).is_err());
    }
}
