// SPDX-License-Identifier: Apache-2.0
//! The little of systemd that the daemon needs, without libsystemd: the
//! notification socket (`NOTIFY_SOCKET`), the watchdog and socket activation
//! (`LISTEN_FDS`).

use std::os::fd::OwnedFd;
use std::os::linux::net::SocketAddrExt;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::{SocketAddr, UnixDatagram};
use std::sync::OnceLock;
use std::time::Duration;

/// The first descriptor passed by systemd.
const LISTEN_FDS_START: i32 = 3;

fn address(path: &[u8]) -> std::io::Result<SocketAddr> {
    match path {
        [] => Err(std::io::ErrorKind::InvalidInput.into()),
        [b'@', name @ ..] => SocketAddr::from_abstract_name(name),
        _ => SocketAddr::from_pathname(std::ffi::OsStr::from_bytes(path)),
    }
}

/// Send `state` to the socket `path` (an `@` prefix is an abstract socket).
pub fn notify_to(path: &[u8], state: &str) -> std::io::Result<()> {
    let addr = address(path)?;
    let sock = UnixDatagram::unbound()?;
    sock.send_to_addr(state.as_bytes(), &addr)?;
    Ok(())
}

/// What the service manager told this process through the environment.
struct Manager {
    notify_socket: Option<std::ffi::OsString>,
    watchdog: Option<Duration>,
    watchdog_usec: Option<std::ffi::OsString>,
}

static MANAGER: OnceLock<Manager> = OnceLock::new();

/// Take `NOTIFY_SOCKET` and the watchdog settings from the environment and
/// remove them, so that no child (monitors, the OCI runtime, containers)
/// inherits the service's notification socket: with `NotifyAccess=all` a
/// child could otherwise change the state or the main pid of the service.
/// Later calls keep the first values.
///
/// Call it early, before any thread is started (it changes the environment).
pub fn take_manager_env() {
    MANAGER.get_or_init(|| {
        let manager = Manager {
            watchdog_usec: std::env::var_os("WATCHDOG_USEC"),
            notify_socket: std::env::var_os("NOTIFY_SOCKET"),
            watchdog: watchdog_interval(
                std::env::var("WATCHDOG_USEC").ok().as_deref(),
                std::env::var("WATCHDOG_PID").ok().as_deref(),
            ),
        };
        for var in ["NOTIFY_SOCKET", "WATCHDOG_USEC", "WATCHDOG_PID"] {
            std::env::remove_var(var);
        }
        manager
    });
}

/// The `NOTIFY_SOCKET` that `take_manager_env` took, for a process that
/// hands it on to the one the service manager should hear from (the engine
/// to the monitor of a container).
pub fn notify_socket() -> Option<std::ffi::OsString> {
    MANAGER.get().and_then(|m| m.notify_socket.clone())
}

/// Send `state` to the service manager; false when there is none or the
/// message could not be sent.  Only what `take_manager_env` took is used.
/// What `take_manager_env` took, for this process again after an exec of
/// itself (a restart): `NOTIFY_SOCKET` and the watchdog, for its pid.
pub fn manager_env() -> Vec<(&'static str, std::ffi::OsString)> {
    let mut env = Vec::new();
    if let Some(m) = MANAGER.get() {
        if let Some(s) = &m.notify_socket {
            env.push(("NOTIFY_SOCKET", s.clone()));
        }
        if let (Some(u), Some(_)) = (&m.watchdog_usec, m.watchdog) {
            env.push(("WATCHDOG_USEC", u.clone()));
            env.push(("WATCHDOG_PID", std::process::id().to_string().into()));
        }
    }
    env
}

pub fn notify(state: &str) -> bool {
    let Some(path) = MANAGER.get().and_then(|m| m.notify_socket.as_ref()) else {
        return false;
    };
    match notify_to(path.as_bytes(), state) {
        Ok(()) => true,
        Err(e) => {
            tracing::warn!("Cannot notify systemd: {e}");
            false
        }
    }
}

/// The interval at which `WATCHDOG=1` has to be sent: half of
/// `WATCHDOG_USEC`, if it is for this process (`WATCHDOG_PID` is optional).
pub fn watchdog_interval(usec: Option<&str>, pid: Option<&str>) -> Option<Duration> {
    if let Some(pid) = pid {
        if pid.parse::<u32>().ok()? != std::process::id() {
            return None;
        }
    }
    let usec: u64 = usec?.trim().parse().ok()?;
    (usec > 0).then(|| Duration::from_micros(usec / 2).max(Duration::from_millis(1)))
}

/// The `WATCHDOG_USEC` of the unit when it is for this process, the period
/// in which the service manager wants `WATCHDOG=1`.
pub fn watchdog_usec() -> Option<String> {
    let m = MANAGER.get()?;
    m.watchdog?;
    m.watchdog_usec
        .as_ref()?
        .to_str()
        .map(|u| u.trim().to_string())
}

/// The watchdog interval of this process, as taken by `take_manager_env`.
pub fn watchdog() -> Option<Duration> {
    MANAGER.get().and_then(|m| m.watchdog)
}

/// A socket passed by systemd.
pub struct ActivatedFd {
    pub fd: OwnedFd,
    pub name: Option<String>,
}

/// The number of descriptors systemd passed to `pid`.
pub fn parse_listen_fds(listen_pid: Option<&str>, listen_fds: Option<&str>, pid: u32) -> usize {
    let (Some(p), Some(n)) = (listen_pid, listen_fds) else {
        return 0;
    };
    if p.trim().parse::<u32>() != Ok(pid) {
        return 0;
    }
    // Bounded: a hostile value cannot make us claim arbitrary descriptors.
    n.trim()
        .parse::<usize>()
        .ok()
        .filter(|n| *n <= 1024)
        .unwrap_or(0)
}

/// Take the sockets that systemd passed (the environment variables are
/// removed so that children do not inherit them).
///
/// The start-up token says that nothing else owns the descriptors from 3
/// on.
pub fn take_listen_fds(startup: &velarx_sys::fd::Startup) -> Vec<ActivatedFd> {
    let n = parse_listen_fds(
        std::env::var("LISTEN_PID").ok().as_deref(),
        std::env::var("LISTEN_FDS").ok().as_deref(),
        std::process::id(),
    );
    let names = std::env::var("LISTEN_FDNAMES").ok();
    std::env::remove_var("LISTEN_PID");
    std::env::remove_var("LISTEN_FDS");
    std::env::remove_var("LISTEN_FDNAMES");
    let mut names = names.as_deref().map(|s| s.split(':')).into_iter().flatten();
    (0..n)
        .filter_map(|i| {
            let name = names.next().map(str::to_string);
            let fd = startup.adopt(LISTEN_FDS_START + i as i32)?;
            if let Err(e) = rustix::io::fcntl_setfd(&fd, rustix::io::FdFlags::CLOEXEC) {
                tracing::warn!(
                    "cannot set close-on-exec on the activated descriptor {}: {e}",
                    LISTEN_FDS_START + i as i32
                );
            }
            Some(ActivatedFd { fd, name })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn notify_reaches_a_path_socket() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("notify");
        let rx = UnixDatagram::bind(&path).unwrap();
        notify_to(path.as_os_str().as_bytes(), "READY=1\nSTATUS=up").unwrap();
        let mut buf = [0u8; 64];
        let n = rx.recv(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"READY=1\nSTATUS=up");
    }

    #[test]
    fn notify_reaches_an_abstract_socket() {
        let name = format!("velarx-test-{}", std::process::id());
        let rx = UnixDatagram::bind_addr(&SocketAddr::from_abstract_name(&name).unwrap()).unwrap();
        notify_to(format!("@{name}").as_bytes(), "STOPPING=1").unwrap();
        let mut buf = [0u8; 16];
        let n = rx.recv(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"STOPPING=1");
    }

    #[test]
    fn notify_errors_are_reported() {
        assert!(notify_to(b"", "READY=1").is_err());
        assert!(notify_to(b"/nonexistent/dir/sock", "READY=1").is_err());
    }

    #[test]
    fn watchdog_is_half_the_period() {
        let me = std::process::id().to_string();
        assert_eq!(
            watchdog_interval(Some("2000000"), None),
            Some(Duration::from_secs(1))
        );
        assert_eq!(
            watchdog_interval(Some("2000000"), Some(&me)),
            Some(Duration::from_secs(1))
        );
        assert_eq!(watchdog_interval(Some("2000000"), Some("1")), None);
        assert_eq!(watchdog_interval(Some("0"), None), None);
        assert_eq!(watchdog_interval(Some("x"), None), None);
        assert_eq!(watchdog_interval(None, None), None);
    }

    #[test]
    fn listen_fds_are_checked() {
        assert_eq!(parse_listen_fds(Some("10"), Some("2"), 10), 2);
        assert_eq!(parse_listen_fds(Some("9"), Some("2"), 10), 0);
        assert_eq!(parse_listen_fds(Some("10"), Some("-1"), 10), 0);
        assert_eq!(parse_listen_fds(Some("10"), Some("99999"), 10), 0);
        assert_eq!(parse_listen_fds(None, Some("1"), 10), 0);
        assert_eq!(parse_listen_fds(Some("10"), None, 10), 0);
    }
}
