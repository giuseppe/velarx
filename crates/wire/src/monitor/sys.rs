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

/// The signal names of Linux; the first name of a number is its own.
const SIGNAL_NAMES: &[(&str, i32)] = &[
    ("HUP", libc::SIGHUP),
    ("INT", libc::SIGINT),
    ("QUIT", libc::SIGQUIT),
    ("ILL", libc::SIGILL),
    ("TRAP", libc::SIGTRAP),
    ("ABRT", libc::SIGABRT),
    ("BUS", libc::SIGBUS),
    ("FPE", libc::SIGFPE),
    ("KILL", libc::SIGKILL),
    ("USR1", libc::SIGUSR1),
    ("SEGV", libc::SIGSEGV),
    ("USR2", libc::SIGUSR2),
    ("PIPE", libc::SIGPIPE),
    ("ALRM", libc::SIGALRM),
    ("TERM", libc::SIGTERM),
    ("CHLD", libc::SIGCHLD),
    ("CLD", libc::SIGCHLD),
    ("CONT", libc::SIGCONT),
    ("STOP", libc::SIGSTOP),
    ("TSTP", libc::SIGTSTP),
    ("TTIN", libc::SIGTTIN),
    ("TTOU", libc::SIGTTOU),
    ("URG", libc::SIGURG),
    ("XCPU", libc::SIGXCPU),
    ("XFSZ", libc::SIGXFSZ),
    ("VTALRM", libc::SIGVTALRM),
    ("PROF", libc::SIGPROF),
    ("WINCH", libc::SIGWINCH),
    ("IO", libc::SIGIO),
    ("SYS", libc::SIGSYS),
    ("STKFLT", libc::SIGSTKFLT),
    ("PWR", libc::SIGPWR),
    ("POLL", libc::SIGIO),
    ("IOT", libc::SIGABRT),
];

/// The name of a signal (`SIGINT`), or its number when it has none.
pub fn signal_name(n: i32) -> String {
    SIGNAL_NAMES
        .iter()
        .find(|(_, v)| *v == n)
        .map_or_else(|| n.to_string(), |(name, _)| format!("SIG{name}"))
}

/// A signal given by name (`TERM`, `SIGTERM`) or number.
pub fn parse_signal(s: &str) -> Option<i32> {
    // (kill -s -1, -INT: a leading dash as podman takes it)
    let s = s.trim();
    let s = s.strip_prefix('-').unwrap_or(s);
    if let Ok(n) = s.parse::<i32>() {
        return valid_signal(n).then_some(n);
    }
    let name = s.to_ascii_uppercase();
    let name = name.strip_prefix("SIG").unwrap_or(&name);
    if let Some((_, v)) = SIGNAL_NAMES.iter().find(|(n, _)| *n == name) {
        return Some(*v);
    }
    // RTMIN, RTMIN+N, RTMAX, RTMAX-N
    let (rtmin, rtmax) = (libc::SIGRTMIN(), libc::SIGRTMAX());
    let rt = if let Some(rest) = name.strip_prefix("RTMIN") {
        match rest.strip_prefix('+') {
            None if rest.is_empty() => Some(rtmin),
            Some(n) => n.parse::<i32>().ok().and_then(|n| rtmin.checked_add(n)),
            None => None,
        }
    } else if let Some(rest) = name.strip_prefix("RTMAX") {
        match rest.strip_prefix('-') {
            None if rest.is_empty() => Some(rtmax),
            Some(n) => n.parse::<i32>().ok().and_then(|n| rtmax.checked_sub(n)),
            None => None,
        }
    } else {
        None
    };
    rt.filter(|n| (rtmin..=rtmax).contains(n))
}

pub use velarx_sys::signal::{peek_zombie, pidfd_send_signal, read_signals, SignalGuard};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signal_names() {
        assert_eq!(parse_signal("CLD"), Some(libc::SIGCHLD));
        assert_eq!(parse_signal("sigcld"), Some(libc::SIGCHLD));
        assert_eq!(parse_signal("TERM"), Some(libc::SIGTERM));
        assert_eq!(parse_signal("SIGPWR"), Some(libc::SIGPWR));
        assert_eq!(parse_signal("stkflt"), Some(libc::SIGSTKFLT));
        assert_eq!(parse_signal("RTMIN"), Some(libc::SIGRTMIN()));
        assert_eq!(parse_signal("SIGRTMIN+2"), Some(libc::SIGRTMIN() + 2));
        assert_eq!(parse_signal("RTMAX-1"), Some(libc::SIGRTMAX() - 1));
        assert_eq!(parse_signal("RTMAX+1"), None);
        assert_eq!(parse_signal("RTMIN+99"), None);
        // (the number is the client's: no overflow)
        assert_eq!(parse_signal("RTMIN+2147483647"), None);
        assert_eq!(parse_signal("RTMAX--2147483648"), None);
        assert_eq!(parse_signal("RTMINX"), None);
        assert_eq!(parse_signal("64"), Some(64));
        // a leading dash, as podman takes it (kill -s -1)
        assert_eq!(parse_signal("-1"), Some(libc::SIGHUP));
        assert_eq!(parse_signal("-INT"), Some(libc::SIGINT));
        assert_eq!(parse_signal("-SIGUSR1"), Some(libc::SIGUSR1));
        assert_eq!(parse_signal("--1"), None);
        assert_eq!(parse_signal("sigusr1"), Some(libc::SIGUSR1));
        assert_eq!(parse_signal("9"), Some(9));
        assert_eq!(parse_signal("0"), None);
        assert_eq!(parse_signal("65"), None);
        assert_eq!(parse_signal("NOPE"), None);
    }
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
