// SPDX-License-Identifier: Apache-2.0
//! The stop of the port forwarder of a container (its start and its relay
//! are in the runtime).

use std::path::Path;

/// The forwarder of the container ID, opened and checked: its command
/// line is read, which Landlock refuses to a thread for the processes outside
/// its domain, so it is found before such a thread is confined and stopped
/// after ([`stop_found`]).
pub fn find(pid_file: &Path, id: &str) -> Option<std::os::fd::OwnedFd> {
    let pid = std::fs::read_to_string(pid_file)
        .ok()
        .and_then(|s| s.trim().parse::<i32>().ok())
        .and_then(rustix::process::Pid::from_raw)
        .filter(|p| !p.is_init())?;
    let fd = rustix::process::pidfd_open(pid, rustix::process::PidfdFlags::empty()).ok()?;
    is_forwarder_of(pid.as_raw_nonzero().get(), id).then_some(fd)
}

/// Stop the forwarder that [`find`] found: through its pidfd.
pub fn stop_found(pid_file: &Path, found: Option<std::os::fd::OwnedFd>) {
    if let Some(fd) = found {
        let _ = rustix::process::pidfd_send_signal(&fd, rustix::process::Signal::KILL);
        let ts = rustix::event::Timespec {
            tv_sec: 2,
            tv_nsec: 0,
        };
        let mut fds = [rustix::event::PollFd::new(
            &fd,
            rustix::event::PollFlags::IN,
        )];
        let _ = rustix::event::poll(&mut fds, Some(&ts));
    }
    let _ = std::fs::remove_file(pid_file);
}

/// Whether the process PID is the forwarder of the container ID.
pub fn is_forwarder_of(pid: i32, id: &str) -> bool {
    let Ok(cmdline) = std::fs::read(format!("/proc/{pid}/cmdline")) else {
        return false;
    };
    let args: Vec<&[u8]> = cmdline.split(|c| *c == 0).collect();
    args.iter().any(|a| *a == b"port-forward")
        && args
            .windows(2)
            .any(|w| w[0] == b"--id" && w[1] == id.as_bytes())
}
