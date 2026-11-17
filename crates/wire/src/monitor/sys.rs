// SPDX-License-Identifier: Apache-2.0
//! The few system calls the monitor needs that `rustix` does not wrap.

use std::os::fd::OwnedFd;

/// Write what is buffered to the standard input of a command (`fd`: its pipe
/// or its terminal).  False when the write would block; true when all is
/// written or nobody reads it any more (the buffer is emptied).
pub fn flush_stdin(fd: Option<&OwnedFd>, buf: &mut std::collections::VecDeque<u8>) -> bool {
    let Some(fd) = fd else {
        buf.clear();
        return true;
    };
    while !buf.is_empty() {
        let (a, _) = buf.as_slices();
        match rustix::io::write(fd, a) {
            Ok(0) => break,
            Ok(n) => {
                buf.drain(..n);
            }
            Err(rustix::io::Errno::AGAIN) => return false,
            Err(rustix::io::Errno::INTR) => continue,
            Err(_) => {
                buf.clear();
                break;
            }
        }
    }
    true
}

/// A signal number the monitor may forward: 1 to 64.
pub fn valid_signal(sig: i32) -> bool {
    (1..=64).contains(&sig)
}

pub use velarx_sys::signal::{peek_zombie, pidfd_send_signal, read_signals, SignalGuard};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_guarded_signal_taken_by_another_thread_reaches_the_guard() {
        // the handler of the signal is that of the whole process
        velarx_base::testing::in_child(|| {
            // a thread started before the guard, which does not block it
            let (go, wait) = std::sync::mpsc::channel::<()>();
            let other = std::thread::spawn(move || {
                wait.recv().unwrap();
                velarx_sys::signal::raise(libc::SIGUSR2); // child-only
            });
            let guard = SignalGuard::new(&[libc::SIGUSR2]).unwrap();
            go.send(()).unwrap();
            other.join().unwrap();
            assert_eq!(guard.read(), [libc::SIGUSR2]);
        });
    }
}
