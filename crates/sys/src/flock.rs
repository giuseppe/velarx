// SPDX-License-Identifier: Apache-2.0
//! `flock(2)` that waits through signals, and a lock let go when it is
//! dropped ([`Held`]).

use rustix::fs::{flock, FlockOperation};
use std::io;
use std::os::fd::AsFd;

/// `flock` on `file`, again when a signal interrupts the wait: a handler
/// installed without `SA_RESTART` (a process that waits for a child or for
/// a stop) would otherwise end a blocking lock with `EINTR`, which is no
/// failure of the lock.
pub fn flock_retrying(file: impl AsFd, op: FlockOperation) -> io::Result<()> {
    loop {
        match flock(&file, op) {
            Err(rustix::io::Errno::INTR) => {}
            r => return r.map_err(io::Error::from),
        }
    }
}

/// A file locked with `flock`, let go (`LOCK_UN`) when it is dropped,
/// before the descriptor is closed.  A lock of `flock` belongs to the open
/// file, which every copy of the descriptor shares: a process forked
/// meanwhile by another thread holds a copy until it closes it or executes
/// (a spawn, a helper that closes what it inherited), and a lock let go by
/// closing ours only would stay held for that long.  `LOCK_UN` lets it go
/// for every copy at once.
#[derive(Debug)]
pub struct Held(std::fs::File);

impl Held {
    /// `file`, locked by the caller.
    pub fn new(file: std::fs::File) -> Self {
        Self(file)
    }
}

impl AsFd for Held {
    fn as_fd(&self) -> std::os::fd::BorrowedFd<'_> {
        self.0.as_fd()
    }
}

impl Drop for Held {
    fn drop(&mut self) {
        let _ = flock(&self.0, FlockOperation::Unlock);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::MetadataExt;
    use std::time::{Duration, Instant};

    /// Whether a thread of this process is asleep in `flock` on the inode
    /// `ino` (a `->` line of `/proc/locks`).
    fn has_waiter(ino: u64) -> bool {
        let (pid, ino) = (std::process::id().to_string(), format!(":{ino}"));
        std::fs::read_to_string("/proc/locks")
            .unwrap_or_default()
            .lines()
            .any(|l| {
                let f: Vec<&str> = l.split_whitespace().collect();
                f.get(1) == Some(&"->") && f.windows(2).any(|w| w[0] == pid && w[1].ends_with(&ino))
            })
    }

    /// A signal that reaches the thread asleep in the lock does not end the
    /// wait: the lock is taken when it is free.
    #[test]
    fn a_signal_during_the_wait_does_not_end_it() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("lock");
        let held = std::fs::File::create(&path).unwrap();
        let ino = held.metadata().unwrap().ino();
        flock_retrying(&held, FlockOperation::LockExclusive).unwrap();
        // (a handler that does nothing, without SA_RESTART)
        crate::signal::wake_on(libc::SIGUSR2);
        let (tid_tx, tid_rx) = std::sync::mpsc::channel();
        let waiting = std::thread::spawn({
            let path = path.clone();
            move || {
                let f = std::fs::File::open(&path).unwrap();
                tid_tx
                    .send(rustix::thread::gettid().as_raw_nonzero().get())
                    .unwrap();
                flock_retrying(&f, FlockOperation::LockExclusive)
            }
        });
        let tid = tid_rx.recv().unwrap();
        let until = Instant::now() + Duration::from_secs(10);
        while !has_waiter(ino) {
            assert!(Instant::now() < until, "the thread never waited");
            std::thread::sleep(Duration::from_millis(2));
        }
        crate::signal::tgkill(tid, libc::SIGUSR2).unwrap();
        // (the signal is handled before the lock is let go)
        std::thread::sleep(Duration::from_millis(50));
        drop(held);
        waiting.join().unwrap().unwrap();
    }

    /// A lock that a forked process still has a copy of is let go when it
    /// is dropped: another open file gets it at once.
    #[test]
    fn a_held_lock_goes_also_for_a_forked_copy() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("lock");
        let file = std::fs::File::create(&path).unwrap();
        flock_retrying(&file, FlockOperation::NonBlockingLockExclusive).unwrap();
        let held = Held::new(file);
        // (a child that keeps every descriptor until it is killed)
        let child = crate::process::fork_async_signal_safe(|_| loop {
            crate::process::pause();
        })
        .unwrap();
        drop(held);
        let other = std::fs::File::open(&path).unwrap();
        let got = flock(&other, FlockOperation::NonBlockingLockExclusive);
        let child = rustix::process::Pid::from_raw(child).unwrap();
        rustix::process::kill_process(child, rustix::process::Signal::KILL).unwrap();
        rustix::process::waitpid(Some(child), rustix::process::WaitOptions::empty()).unwrap();
        assert!(got.is_ok(), "the copy of the child held the lock: {got:?}");
    }
}
