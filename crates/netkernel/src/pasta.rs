// SPDX-License-Identifier: Apache-2.0
//! The stop of pasta: found by its pid file, checked to be the one of the
//! namespace or the container (not by its program: that is renamed `(deleted)`
//! when the package is updated), signalled through a pidfd.  The
//! start and the supervision of pasta are in the runtime.

use std::path::{Path, PathBuf};
use std::time::Duration;

pub fn read_pid(pid_file: &Path) -> Option<rustix::process::Pid> {
    let s = std::fs::read_to_string(pid_file).ok()?;
    let pid: i32 = s.trim().parse().ok()?;
    rustix::process::Pid::from_raw(pid).filter(|p| !p.is_init())
}

/// A pidfd of the pasta of PID_FILE.  The pidfd is opened first, then the
/// process is checked: a reused pid is never signalled.
pub fn pasta_pidfd(pid_file: &Path) -> Option<std::os::fd::OwnedFd> {
    let pid = read_pid(pid_file)?;
    let fd = rustix::process::pidfd_open(pid, rustix::process::PidfdFlags::empty()).ok()?;
    is_pasta_of(pid.as_raw_nonzero().get(), pid_file).then_some(fd)
}

/// Stop the pasta of PID_FILE only if it runs on the namespace at NETNS (its
/// `--netns`): the identity is checked on a pidfd opened first, as `stop`
/// does, and the pid file goes only while it still names that pasta.  What
/// is there when the pasta of another namespace was started since (the pid
/// file is rewritten by whoever starts one) is left alone.  True when a
/// pasta was stopped.
pub fn stop_on(pid_file: &Path, netns: &Path, wait: bool) -> bool {
    let Some(pid) = read_pid(pid_file) else {
        return false;
    };
    let Ok(fd) = rustix::process::pidfd_open(pid, rustix::process::PidfdFlags::empty()) else {
        return false;
    };
    let raw = pid.as_raw_nonzero().get();
    if !is_pasta_of(raw, pid_file) || !runs_on(raw, netns) {
        return false;
    }
    if read_pid(pid_file) == Some(pid) {
        let _ = std::fs::remove_file(pid_file);
    }
    let _ = rustix::process::pidfd_send_signal(&fd, rustix::process::Signal::TERM);
    if wait && !wait_exit(&fd, Duration::from_secs(2)) {
        let _ = rustix::process::pidfd_send_signal(&fd, rustix::process::Signal::KILL);
        wait_exit(&fd, Duration::from_secs(1));
    }
    true
}

/// Whether the process PID was started with `--netns NETNS`.
pub fn runs_on(pid: i32, netns: &Path) -> bool {
    let Ok(cmdline) = std::fs::read(format!("/proc/{pid}/cmdline")) else {
        return false;
    };
    let args: Vec<&[u8]> = cmdline.split(|c| *c == 0).collect();
    let ns = netns.as_os_str().as_encoded_bytes();
    args.windows(2).any(|w| w[0] == b"--netns" && w[1] == ns)
}

/// Whether the pasta of PID_FILE runs.
pub fn is_running(pid_file: &Path) -> bool {
    pasta_pidfd(pid_file).is_some()
}

/// Whether the process PID was started with `--pid PID_FILE`: the file of
/// one container's pasta (what its namespace is called is the path of a
/// descriptor of whichever process started it, and no other process knows
/// it).
pub fn is_pasta_of(pid: i32, pid_file: &Path) -> bool {
    let proc = PathBuf::from(format!("/proc/{pid}"));
    let Ok(cmdline) = std::fs::read(proc.join("cmdline")) else {
        return false;
    };
    let args: Vec<&[u8]> = cmdline.split(|c| *c == 0).collect();
    let file = pid_file.as_os_str().as_encoded_bytes();
    args.windows(2).any(|w| w[0] == b"--pid" && w[1] == file)
}

/// Wait up to TIMEOUT for the process of PIDFD to exit.
pub fn wait_exit(fd: &std::os::fd::OwnedFd, timeout: Duration) -> bool {
    use rustix::event::{poll, PollFd, PollFlags};
    let ts = rustix::event::Timespec {
        tv_sec: timeout.as_secs() as i64,
        tv_nsec: i64::from(timeout.subsec_nanos()),
    };
    let mut fds = [PollFd::new(fd, PollFlags::IN)];
    matches!(poll(&mut fds, Some(&ts)), Ok(n) if n > 0)
}

/// The pasta of a pid file, opened and checked: the process is identified
/// by reading its `/proc` entries, which Landlock refuses to a thread for the
/// processes outside its domain, so it is found before such a thread is
/// confined ([`find`]) and stopped after ([`stop_found`]).
#[derive(Default)]
pub struct Found {
    /// What the pid file said when it was found
    pid: Option<rustix::process::Pid>,
    running: Option<std::os::fd::OwnedFd>,
    exiting: Option<std::os::fd::OwnedFd>,
}

/// Find the pasta of PID_FILE (see [`Found`]).  With `wait`, a pasta that
/// is exiting by itself is found too.
pub fn find(pid_file: &Path, wait: bool) -> Found {
    let pid = read_pid(pid_file);
    let running = pasta_pidfd(pid_file);
    let exiting = (running.is_none() && wait)
        .then(|| exiting_pidfd(pid_file))
        .flatten();
    Found {
        pid,
        running,
        exiting,
    }
}

/// Stop the pasta of PID_FILE.  With `wait` it is waited for until it is
/// gone: until then it keeps the published ports (a pasta that has none
/// ends by itself, and the pasta of the next container does not need it
/// gone).
pub fn stop(pid_file: &Path, wait: bool) {
    stop_found(pid_file, find(pid_file, wait), wait);
}

/// [`stop`] of a pasta that [`find`] found.
pub fn stop_found(pid_file: &Path, found: Found, wait: bool) {
    let Found {
        pid,
        running,
        exiting,
    } = found;
    // (the pid file goes first: a watch that sees the pasta go without it
    // takes it for stopped, not for one to start again; the watch may be
    // another process's, the engine's when the monitor tears the container
    // down.  Only while it names what was found: a pasta started since the
    // find wrote its own)
    if read_pid(pid_file) == pid {
        let _ = std::fs::remove_file(pid_file);
    }
    if let Some(fd) = running {
        let _ = rustix::process::pidfd_send_signal(&fd, rustix::process::Signal::TERM);
        if wait && !wait_exit(&fd, Duration::from_secs(2)) {
            let _ = rustix::process::pidfd_send_signal(&fd, rustix::process::Signal::KILL);
            wait_exit(&fd, Duration::from_secs(1));
        }
    } else if let Some(fd) = exiting {
        // (a pasta that is exiting by itself, its netns file removed, has
        // no command line left but its tap device still: the next pasta
        // could not make its own)
        wait_exit(&fd, Duration::from_secs(2));
    }
}

/// A pidfd of the process of PID_FILE if it is exiting: its memory, and
/// so its command line, is gone, its descriptors are not yet.  Only waited
/// for, never signalled.
pub fn exiting_pidfd(pid_file: &Path) -> Option<std::os::fd::OwnedFd> {
    let pid = read_pid(pid_file)?;
    let fd = rustix::process::pidfd_open(pid, rustix::process::PidfdFlags::empty()).ok()?;
    std::fs::read(format!("/proc/{}/cmdline", pid.as_raw_nonzero()))
        .map_or(true, |c| c.is_empty())
        .then_some(fd)
}

/// The device and inode of the namespace pinned on NETNS: another pin on the
/// path is another namespace; None if nothing is pinned there.
pub fn namespace_id(netns: &Path) -> Option<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata(netns).ok().map(|m| (m.dev(), m.ino()))
}

/// The namespace pinned on NETNS, open, and its device and inode.  Held
/// open, its inode stays its own: the number of a namespace that is gone, as
/// the inode of a file that was removed, is given to the next one, which
/// would be taken for it.
pub fn open_namespace(netns: &Path) -> Option<(std::fs::File, (u64, u64))> {
    use std::os::unix::fs::MetadataExt;
    let f = std::fs::File::open(netns).ok()?;
    let m = f.metadata().ok()?;
    Some((f, (m.dev(), m.ino())))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A pasta is the process of its pid file whatever its program is
    /// called: after an update of the package the link of `/proc/PID/exe`
    /// says `pasta (deleted)`.
    #[test]
    fn a_pasta_is_known_by_its_pid_file_not_by_its_program() {
        let d = tempfile::tempdir().unwrap();
        let pid_file = d.path().join("pasta.pid");
        // (the shell says it runs: until then its command line is that of
        // an exec in progress, and the one command it has is not executed
        // in its place)
        let mut child = std::process::Command::new("sh")
            .args(["-c", "echo; sleep 30; :", "pasta", "--pid"])
            .arg(&pid_file)
            .stdout(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        std::io::BufRead::read_line(
            &mut std::io::BufReader::new(child.stdout.take().unwrap()),
            &mut String::new(),
        )
        .unwrap();
        let pid = child.id() as i32;
        std::fs::write(&pid_file, pid.to_string()).unwrap();
        assert!(is_pasta_of(pid, &pid_file));
        assert!(is_running(&pid_file));
        assert!(!is_pasta_of(pid, &d.path().join("other.pid")));
        child.kill().unwrap();
        child.wait().unwrap();
    }
}
