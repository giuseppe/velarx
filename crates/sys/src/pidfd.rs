// SPDX-License-Identifier: Apache-2.0
//! Processes by pidfd: the way to name a process that cannot name another
//! one after it exited.  A pidfd refers to one process for its whole life;
//! a pid number can be reused once the process is reaped.
//!
//! Only what Linux 6.8 has is used: `pidfd_open`, `SO_PEERPIDFD`,
//! `pidfd_send_signal`, `waitid(P_PIDFD)` and the poll of a pidfd.

use std::io;
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd};

use rustix::event::{PollFd, PollFlags};
use rustix::process::{Pid, PidfdFlags, WaitId, WaitIdOptions};

/// A pidfd (close-on-exec) of the process `pid`.  Nothing here tells that
/// `pid` is still the process the caller means: see [`open_child`].
pub fn open(pid: i32) -> io::Result<OwnedFd> {
    let pid = Pid::from_raw(pid).ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?;
    rustix::process::pidfd_open(pid, PidfdFlags::empty()).map_err(io::Error::from)
}

/// A pidfd (close-on-exec) of the process at the other end of the unix
/// socket `sock` (`SO_PEERPIDFD`): the one that listened, for a socket
/// that connected.  It is that process even when it has ended and its pid
/// was taken by another since, where a pid of `SO_PEERCRED` opened with
/// [`open`] would be the other one.
pub fn of_peer<Fd: AsFd>(sock: Fd) -> io::Result<OwnedFd> {
    let mut fd: libc::c_int = -1;
    let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    // SAFETY: SO_PEERPIDFD writes an int and its length through the two
    // pointers, which point at locals that outlive the call.
    let r = unsafe {
        libc::getsockopt(
            sock.as_fd().as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERPIDFD,
            std::ptr::addr_of_mut!(fd).cast(),
            &mut len,
        )
    };
    if r < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: on success the kernel installed a new descriptor for the
    // caller, which nothing else owns.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// A pidfd of the child `pid` of the caller.  The pid of a child that was
/// not reaped cannot be reused, so the pidfd is its child: a process that
/// is not a child (`ECHILD` from `waitid`) is refused, as its pid may
/// already belong to somebody else.
pub fn open_child(pid: i32) -> io::Result<OwnedFd> {
    let fd = open(pid)?;
    // (a child that exited stays a zombie: it is found, not reaped)
    match rustix::process::waitid(
        WaitId::PidFd(fd.as_fd()),
        WaitIdOptions::EXITED | WaitIdOptions::NOHANG | WaitIdOptions::NOWAIT,
    ) {
        Ok(_) => Ok(fd),
        Err(e) => Err(io::Error::from(e)),
    }
}

/// Whether the process of `pidfd` has exited (it may still be a zombie).
pub fn has_exited<Fd: AsFd>(pidfd: Fd) -> bool {
    let mut fds = [PollFd::new(&pidfd, PollFlags::IN)];
    let none = rustix::event::Timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    matches!(rustix::event::poll(&mut fds, Some(&none)), Ok(n) if n > 0)
}

/// Wait up to `timeout` for the process of `pidfd` to exit: one sleep in
/// the kernel, woken by the exit.  `true` if it exited.
pub fn wait_exit<Fd: AsFd>(pidfd: Fd, timeout: std::time::Duration) -> io::Result<bool> {
    let end = std::time::Instant::now() + timeout;
    loop {
        let left = end.saturating_duration_since(std::time::Instant::now());
        let ts = rustix::event::Timespec {
            tv_sec: left.as_secs() as _,
            tv_nsec: left.subsec_nanos() as _,
        };
        let mut fds = [PollFd::new(&pidfd, PollFlags::IN)];
        match rustix::event::poll(&mut fds, Some(&ts)) {
            Ok(n) => return Ok(n > 0),
            Err(rustix::io::Errno::INTR) => continue,
            Err(e) => return Err(io::Error::from(e)),
        }
    }
}

/// The pid of the process of `fd` if `fd` is a pidfd of a process that has
/// not ended, read from the descriptor itself (`/proc/self/fdinfo`: a pid
/// number says nothing of which process it was).  A descriptor of anything
/// else is an error that says what it is; a process that ended is `ESRCH`.
pub fn pid_of<Fd: AsFd>(fd: Fd) -> io::Result<i32> {
    let fd = fd.as_fd().as_raw_fd();
    let kind = std::fs::read_link(crate::fd::proc_raw(fd))?;
    if kind != std::path::Path::new("anon_inode:[pidfd]") {
        return Err(io::Error::other(format!(
            "the descriptor is {}, not a pidfd",
            kind.display()
        )));
    }
    let info = std::fs::read_to_string(format!("/proc/self/fdinfo/{fd}"))?;
    match info
        .lines()
        .find_map(|l| l.strip_prefix("Pid:"))
        .and_then(|p| p.trim().parse::<i32>().ok())
    {
        Some(pid) if pid > 0 => Ok(pid),
        _ => Err(io::Error::from(rustix::io::Errno::SRCH)),
    }
}

/// Wait for the process of `pidfd` to exit, as long as it takes: one sleep in
/// the kernel, woken by the exit.
pub fn wait_ended<Fd: AsFd>(pidfd: Fd) -> io::Result<()> {
    loop {
        let mut fds = [PollFd::new(&pidfd, PollFlags::IN)];
        match rustix::event::poll(&mut fds, None) {
            Ok(n) if n > 0 => return Ok(()),
            Ok(_) | Err(rustix::io::Errno::INTR) => continue,
            Err(e) => return Err(io::Error::from(e)),
        }
    }
}

/// The exit code of the child behind `pidfd` if it has exited (128 plus
/// the signal if it was killed), reaping it.  `None` while it runs.  A
/// process that is not a child (`ECHILD`: somebody reaped it) is gone with
/// a status nobody knows: an error, not an exit code.
pub fn reap<Fd: AsFd>(pidfd: Fd) -> io::Result<Option<i32>> {
    match rustix::process::waitid(
        WaitId::PidFd(pidfd.as_fd()),
        WaitIdOptions::EXITED | WaitIdOptions::NOHANG,
    ) {
        Ok(Some(st)) => {
            if let Some(code) = st.exit_status() {
                Ok(Some(code))
            } else if let Some(sig) = st.terminating_signal() {
                Ok(Some(128 + sig))
            } else {
                Ok(None)
            }
        }
        Ok(None) => Ok(None),
        Err(e) => Err(io::Error::from(e)),
    }
}

/// Kill the process behind the raw descriptor `fd` (negative: none), for a
/// panic hook that cannot hold a borrowed descriptor.  A descriptor that is
/// not a pidfd, or one whose process is gone, is an error that is ignored.
pub fn kill_raw(fd: i32) {
    if fd < 0 {
        return;
    }
    // SAFETY: pidfd_send_signal with an integer descriptor, no siginfo and
    // no flags; the kernel refuses a descriptor that is not a pidfd.
    unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            fd,
            libc::SIGKILL,
            std::ptr::null::<libc::siginfo_t>(),
            0,
        );
    }
}

// (the children are reaped through their pidfds, which clippy cannot see)
#[cfg(test)]
#[allow(clippy::zombie_processes)]
mod tests {
    use super::*;
    use std::process::{Command, Stdio};

    fn sleeper() -> std::process::Child {
        Command::new("sleep")
            .arg("60")
            .stdin(Stdio::null())
            .spawn()
            .unwrap()
    }

    fn wait_readable(fd: &OwnedFd) {
        let mut fds = [PollFd::new(fd, PollFlags::IN)];
        rustix::event::poll(&mut fds, None).unwrap();
    }

    /// The pid a pidfd is of, as `/proc/self/fdinfo` tells it.
    fn pid_of(fd: &OwnedFd) -> i32 {
        super::pid_of(fd).unwrap()
    }

    /// Only a pidfd of a live process has a pid: a file, or a process that
    /// ended (and was reaped), is an error that says which.
    #[test]
    fn a_pid_is_of_a_pidfd_of_a_live_process() {
        let mut child = sleeper();
        let fd = open(child.id() as i32).unwrap();
        assert_eq!(pid_of(&fd), child.id() as i32);
        child.kill().unwrap();
        child.wait().unwrap();
        let e = super::pid_of(&fd).unwrap_err();
        assert_eq!(e.raw_os_error(), Some(libc::ESRCH), "{e}");
        let file = std::fs::File::open("/dev/null").unwrap();
        let e = super::pid_of(&file).unwrap_err().to_string();
        assert!(e.contains("not a pidfd"), "{e}");
    }

    #[test]
    fn the_peer_of_a_socket_is_the_process_that_listens() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("s");
        let _listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        let stream = std::os::unix::net::UnixStream::connect(&path).unwrap();
        let fd = of_peer(&stream).unwrap();
        assert_eq!(pid_of(&fd), std::process::id() as i32);
        assert!(!has_exited(&fd));
        // (a descriptor that is not a socket has no peer)
        assert!(of_peer(&fd).is_err());
    }

    #[test]
    fn a_child_is_opened_signalled_and_reaped() {
        let child = sleeper();
        let fd = open_child(child.id() as i32).unwrap();
        assert!(!has_exited(&fd));
        assert_eq!(reap(&fd).unwrap(), None);
        crate::signal::pidfd_send_signal(&fd, libc::SIGKILL).unwrap();
        // readable at the death, with no polling interval
        wait_readable(&fd);
        assert!(has_exited(&fd));
        assert_eq!(reap(&fd).unwrap(), Some(128 + libc::SIGKILL));
    }

    #[test]
    fn wait_exit_wakes_at_the_exit_not_at_the_timeout() {
        let child = Command::new("sh")
            .args(["-c", "sleep 0.05"])
            .spawn()
            .unwrap();
        let fd = open_child(child.id() as i32).unwrap();
        let t = std::time::Instant::now();
        assert!(wait_exit(&fd, std::time::Duration::from_secs(30)).unwrap());
        assert!(t.elapsed() < std::time::Duration::from_secs(5));
        let other = sleeper();
        let fd = open_child(other.id() as i32).unwrap();
        assert!(!wait_exit(&fd, std::time::Duration::from_millis(20)).unwrap());
        crate::signal::pidfd_send_signal(&fd, libc::SIGKILL).unwrap();
        assert!(wait_exit(&fd, std::time::Duration::from_secs(30)).unwrap());
    }

    #[test]
    fn the_exit_code_of_a_child() {
        let child = Command::new("sh").args(["-c", "exit 7"]).spawn().unwrap();
        let fd = open_child(child.id() as i32).unwrap();
        wait_readable(&fd);
        assert_eq!(reap(&fd).unwrap(), Some(7));
    }

    #[test]
    fn a_zombie_is_still_ours_and_signals_find_it() {
        let child = Command::new("true").spawn().unwrap();
        let fd = open(child.id() as i32).unwrap();
        wait_readable(&fd);
        // exited, not reaped: the pid is held, the signal is accepted
        assert!(open_child(child.id() as i32).is_ok());
        assert!(crate::signal::pidfd_send_signal(&fd, libc::SIGTERM).is_ok());
        assert_eq!(reap(&fd).unwrap(), Some(0));
    }

    #[test]
    fn a_signal_after_the_reap_is_esrch_and_reaches_nobody() {
        let child = Command::new("true").spawn().unwrap();
        let fd = open_child(child.id() as i32).unwrap();
        wait_readable(&fd);
        assert_eq!(reap(&fd).unwrap(), Some(0));
        let e = crate::signal::pidfd_send_signal(&fd, libc::SIGKILL).unwrap_err();
        assert_eq!(e.raw_os_error(), Some(libc::ESRCH));
    }

    #[test]
    fn a_process_that_is_not_our_child_is_refused() {
        let e = open_child(1).unwrap_err();
        assert_eq!(e.raw_os_error(), Some(libc::ECHILD));
        let e = open_child(std::os::unix::process::parent_id() as i32).unwrap_err();
        assert_eq!(e.raw_os_error(), Some(libc::ECHILD));
    }

    #[test]
    fn a_grandchild_is_not_a_child() {
        let out = Command::new("sh")
            .args(["-c", "sleep 60 >/dev/null 2>&1 </dev/null & echo $!"])
            .output()
            .unwrap();
        let pid: i32 = String::from_utf8_lossy(&out.stdout).trim().parse().unwrap();
        let fd = open(pid).unwrap();
        assert_eq!(
            open_child(pid).unwrap_err().raw_os_error(),
            Some(libc::ECHILD)
        );
        crate::signal::pidfd_send_signal(&fd, libc::SIGKILL).unwrap();
    }

    #[test]
    fn a_thread_that_is_not_the_leader_has_no_pidfd() {
        let (tx, rx) = std::sync::mpsc::channel();
        let (go_tx, go_rx) = std::sync::mpsc::channel::<()>();
        let t = std::thread::spawn(move || {
            tx.send(rustix::thread::gettid().as_raw_nonzero().get())
                .unwrap();
            let _ = go_rx.recv();
        });
        let tid = rx.recv().unwrap();
        // (the kernel answers with an error: which one differs by version)
        assert!(open(tid).is_err());
        assert!(open(std::process::id() as i32).is_ok());
        go_tx.send(()).unwrap();
        t.join().unwrap();
    }

    #[test]
    fn the_pidfd_is_close_on_exec() {
        let fd = open(std::process::id() as i32).unwrap();
        let flags = rustix::io::fcntl_getfd(&fd).unwrap();
        assert!(flags.contains(rustix::io::FdFlags::CLOEXEC));
    }

    /// Processes started after the reap, one of which may get the number:
    /// the old pidfd reaches none of them.
    #[test]
    fn the_old_pidfd_reaches_no_new_process() {
        let child = Command::new("true").spawn().unwrap();
        let fd = open_child(child.id() as i32).unwrap();
        wait_readable(&fd);
        assert_eq!(reap(&fd).unwrap(), Some(0));
        let mut keep: Vec<_> = (0..20).map(|_| sleeper()).collect();
        let e = crate::signal::pidfd_send_signal(&fd, libc::SIGKILL).unwrap_err();
        assert_eq!(e.raw_os_error(), Some(libc::ESRCH));
        for c in &mut keep {
            assert!(c.try_wait().unwrap().is_none(), "a sleeper was signalled");
            let _ = c.kill();
            let _ = c.wait();
        }
    }

    /// The pid number of a reaped child handed to a new process on purpose
    /// (`ns_last_pid` of a pid namespace of our own): the pidfd of the
    /// first one refuses, the second is not touched.  The inner test runs
    /// in the namespace, the outer one starts it (and passes where user
    /// namespaces are not available).
    #[test]
    fn a_pid_forced_to_be_reused_is_not_signalled_through_the_old_pidfd() {
        if std::env::var_os("VELARX_PIDFD_REUSE_INNER").is_none() {
            let out = Command::new("unshare")
                .args(["-Urpf", "--mount-proc"])
                .arg(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "pidfd::tests::a_pid_forced_to_be_reused_is_not_signalled_through_the_old_pidfd",
                    "--nocapture",
                ])
                .env("VELARX_PIDFD_REUSE_INNER", "1")
                .output();
            match out {
                Ok(o) if o.status.success() => {}
                // (the namespaces or the mount of /proc refused: the test
                // did not start)
                Ok(o) if !String::from_utf8_lossy(&o.stdout).contains("running 1 test") => {
                    eprintln!(
                        "no user and pid namespace here: skipped ({})",
                        String::from_utf8_lossy(&o.stderr).trim()
                    );
                }
                Ok(o) => panic!(
                    "{}{}",
                    String::from_utf8_lossy(&o.stdout),
                    String::from_utf8_lossy(&o.stderr)
                ),
                Err(_) => eprintln!("no unshare here: skipped"),
            }
            return;
        }
        let child = Command::new("true").spawn().unwrap();
        let pid = child.id() as i32;
        let fd = open_child(pid).unwrap();
        wait_readable(&fd);
        assert_eq!(reap(&fd).unwrap(), Some(0));
        drop(child);
        std::fs::write("/proc/sys/kernel/ns_last_pid", (pid - 1).to_string()).unwrap();
        let mut other = sleeper();
        assert_eq!(other.id() as i32, pid, "the number was not reused");
        let e = crate::signal::pidfd_send_signal(&fd, libc::SIGKILL).unwrap_err();
        assert_eq!(e.raw_os_error(), Some(libc::ESRCH));
        assert!(
            other.try_wait().unwrap().is_none(),
            "the new process was signalled"
        );
        // the raw pid would have hit it
        crate::process::kill(pid, libc::SIGKILL).unwrap();
        assert!(other.wait().is_ok());
    }
}
