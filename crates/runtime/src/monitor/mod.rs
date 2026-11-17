// SPDX-License-Identifier: Apache-2.0
//! The per-container monitor: the process that owns a container's stdio,
//! writes its log, waits for its exit and keeps the status for the daemon.

mod clients;
pub mod config;
pub(crate) mod confine;
mod exec;
pub mod features;
pub(crate) mod image;
mod journal;
#[cfg(feature = "fuse")]
pub(crate) mod lazy;
pub mod notify;
mod oom;
pub mod relay;
pub mod restart;
mod server;
mod settle;
pub mod syslog;

pub mod inproc;

/// The pid of the monitor, in its run directory.
pub const MONITOR_PID_FILE: &str = "monitor.pid";

/// The file of the run directory the monitor locks for as long as it lives.
const IDENTITY_FILE: &str = "monitor.lock";

/// Take the lock that tells the monitor of the run directory `dir` lives
/// (the kernel drops it when the process ends, however it ends, and the pid
/// that holds it cannot be another process's after a reuse).  Fails when
/// another monitor holds it.
pub(crate) fn hold_identity(dir: std::os::fd::BorrowedFd<'_>) -> std::io::Result<std::fs::File> {
    use rustix::fs::{Mode, OFlags};
    let fd = rustix::fs::openat(
        dir,
        IDENTITY_FILE,
        OFlags::RDWR | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_raw_mode(0o600),
    )?;
    velarx_sys::fs::lock_for_process(std::os::fd::AsFd::as_fd(&fd)).map_err(|e| {
        if e.kind() == std::io::ErrorKind::WouldBlock {
            std::io::Error::other("another monitor runs in this directory")
        } else {
            e
        }
    })?;
    Ok(fd.into())
}

/// A monitor that lives: its pid, and a pidfd of it.
#[derive(Debug)]
pub struct LiveMonitor {
    pub pid: u32,
    /// Of the process that held the lock (non-blocking, close-on-exec): a
    /// process that took the pid later is not it.
    pub pidfd: std::os::fd::OwnedFd,
}

/// The monitor that runs in the run directory `dir`, from the lock it holds
/// ([`hold_identity`]); none when there is none, or only one of a version
/// that took no lock (the socket tells those).  The kernel tells the pid of
/// the holder in the pid namespace of the caller: a monitor that this
/// process's namespace does not see (none of a container engine sees the
/// monitors of another namespace by their pid or their socket peer) is
/// none either.
pub fn live_monitor(dir: &std::path::Path) -> Option<LiveMonitor> {
    use std::os::fd::AsFd;
    let f = std::fs::File::open(dir.join(IDENTITY_FILE)).ok()?;
    let holder = || velarx_sys::fs::lock_holder(f.as_fd()).ok().flatten();
    let pid = holder()?;
    let pidfd = rustix::process::pidfd_open(
        rustix::process::Pid::from_raw(i32::try_from(pid).ok()?)?,
        rustix::process::PidfdFlags::NONBLOCK,
    )
    .ok()?;
    // The lock is held by that pid after the pidfd was opened, and the
    // process of the pidfd still lives then: two live processes do not
    // share a pid, so the pidfd is of the holder (a holder that ended
    // and a pid taken by another process meanwhile fail one of the two).
    (holder() == Some(pid) && !velarx_sys::pidfd::has_exited(&pidfd))
        .then_some(LiveMonitor { pid, pidfd })
}
pub use server::{main, run_in_process, Launch, IMAGE_SERVER_FLAG};
