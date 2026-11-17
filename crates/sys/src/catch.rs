// SPDX-License-Identifier: Apache-2.0
//! Handlers of signals that do one async-signal-safe thing.

use std::sync::atomic::{AtomicI32, Ordering};

static PIPE: AtomicI32 = AtomicI32::new(-1);

extern "C" fn write_signal(sig: libc::c_int) {
    let fd = PIPE.load(Ordering::Relaxed);
    if fd >= 0 {
        let byte = sig as u8;
        // SAFETY: write is async-signal-safe and reads one byte of the stack;
        // the errno of the thread the signal interrupted is put back.
        unsafe {
            let errno = *libc::__errno_location();
            libc::write(fd, (&byte as *const u8).cast(), 1);
            *libc::__errno_location() = errno;
        }
    }
}

/// The descriptor the signals taken by [`catch_into_pipe`] are written to,
/// one byte (the number) each; `-1` for none.  The caller keeps the
/// descriptor open while it is set, and sets one pipe at a time.
pub fn set_pipe(fd: i32) {
    PIPE.store(fd, Ordering::Relaxed);
}

/// A disposition to put back.
pub struct Saved {
    signum: i32,
    old: libc::sigaction,
}

impl Saved {
    /// Put the disposition back.
    pub fn restore(&self) {
        // SAFETY: the action is the one `sigaction` returned for the signal.
        unsafe { libc::sigaction(self.signum, &self.old, std::ptr::null_mut()) };
    }
}

/// Take `signum` (system calls restart): its number is written to the pipe of
/// [`set_pipe`].  The disposition before, to put back, unless the call failed.
pub fn catch_into_pipe(signum: i32) -> Option<Saved> {
    // SAFETY: the sigaction structures are made from zeroes and filled; the
    // handler only calls write and keeps errno.
    unsafe {
        let mut act: libc::sigaction = std::mem::zeroed();
        act.sa_sigaction = write_signal as extern "C" fn(libc::c_int) as libc::sighandler_t;
        act.sa_flags = libc::SA_RESTART;
        libc::sigemptyset(&mut act.sa_mask);
        let mut old: libc::sigaction = std::mem::zeroed();
        (libc::sigaction(signum, &act, &mut old) == 0).then_some(Saved { signum, old })
    }
}

/// Ignore `signum`.  The disposition before, to put back, unless the call
/// failed.
pub fn ignore(signum: i32) -> Option<Saved> {
    // SAFETY: the sigaction structures are made from zeroes and filled; no
    // handler runs.
    unsafe {
        let mut act: libc::sigaction = std::mem::zeroed();
        act.sa_sigaction = libc::SIG_IGN;
        libc::sigemptyset(&mut act.sa_mask);
        let mut old: libc::sigaction = std::mem::zeroed();
        (libc::sigaction(signum, &act, &mut old) == 0).then_some(Saved { signum, old })
    }
}

static EXIT_STATUS: AtomicI32 = AtomicI32::new(1);

extern "C" fn exit_now(_: libc::c_int) {
    // SAFETY: _exit is async-signal-safe.
    unsafe { libc::_exit(EXIT_STATUS.load(Ordering::Relaxed)) }
}

/// End the process at once with `status` when `signum` comes.
pub fn exit_on(signum: i32, status: i32) {
    EXIT_STATUS.store(status, Ordering::Relaxed);
    // SAFETY: the handler only calls _exit.
    unsafe {
        libc::signal(
            signum,
            exit_now as extern "C" fn(libc::c_int) as libc::sighandler_t,
        );
    }
}
