// SPDX-License-Identifier: Apache-2.0
//! The sd_notify protocol for containers: the monitor receives what the
//! container sends to its `NOTIFY_SOCKET` and forwards the messages that a
//! container may send to the service manager that runs the engine.

use std::io;
use std::os::fd::OwnedFd;
use std::path::Path;

use rustix::net::{self, AddressFamily, SocketAddrUnix, SocketFlags, SocketType};
use serde::{Deserialize, Serialize};

/// The largest datagram taken.
pub const MAX_DATAGRAM: usize = 8192;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SdNotify {
    /// The container's messages are dropped.
    #[default]
    Ignore,
    /// The container sends them; the monitor forwards what is allowed.
    Container,
    /// The monitor tells that the container runs, once it started.
    Conmon,
    /// The monitor tells that the container is ready when its health check
    /// first passes.
    Healthy,
}

impl SdNotify {
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "" | "ignore" => Self::Ignore,
            "container" => Self::Container,
            "conmon" => Self::Conmon,
            "healthy" => Self::Healthy,
            _ => return None,
        })
    }
}

/// What a container may tell the service manager, as a name or a name and a
/// value.  The main process of the unit and the file descriptor store are the
/// engine's.
fn allowed(line: &str) -> bool {
    let Some((key, value)) = line.split_once('=') else {
        return false;
    };
    if value.len() > 4096 || value.bytes().any(|c| c == 0 || (c < b' ' && c != b'\t')) {
        return false;
    }
    match key {
        "READY" | "STOPPING" | "RELOADING" => value == "1",
        "WATCHDOG" => value == "1" || value == "trigger",
        "STATUS" | "MONOTONIC_USEC" | "ERRNO" | "BUSERROR" | "WATCHDOG_USEC" => true,
        _ => false,
    }
}

/// The part of a message that may be forwarded; `None` when nothing is.
pub fn filter(datagram: &[u8]) -> Option<Vec<u8>> {
    let text = std::str::from_utf8(datagram).ok()?;
    let lines: Vec<&str> = text.lines().filter(|l| allowed(l)).collect();
    (!lines.is_empty()).then(|| {
        let mut out = lines.join("\n").into_bytes();
        out.push(b'\n');
        out
    })
}

/// A datagram socket bound at `path`, where the container's messages come;
/// with `label`, the SELinux context of the socket.
pub fn bind(path: &Path, label: Option<&str>) -> io::Result<OwnedFd> {
    let _ = std::fs::remove_file(path);
    let sock = match label {
        Some(l) => {
            // The context of the sockets this thread makes, for this one.
            let attr = "/proc/thread-self/attr/sockcreate";
            std::fs::write(attr, l)?;
            let sock = new_socket();
            // An empty write (a write call of no byte, which write_all does
            // not make) puts back the default for the sockets that follow.
            let reset = std::fs::OpenOptions::new()
                .write(true)
                .open(attr)
                .and_then(|mut f| std::io::Write::write(&mut f, &[]));
            let sock = sock?;
            reset?;
            sock
        }
        None => new_socket()?,
    };
    net::bind(&sock, &SocketAddrUnix::new(path)?)?;
    // The container may be another user.
    open_to_all(path)?;
    Ok(sock)
}

/// Make the file at `path` writable by everyone, through a descriptor of
/// the name itself: a link the container put there is not followed (the
/// mode of a link cannot change), and the umask of the monitor, which
/// cuts the mode an `fchmod` of the socket before the bind would give,
/// does not matter.
fn open_to_all(path: &Path) -> io::Result<()> {
    use rustix::fs::{Mode, OFlags};
    let file = rustix::fs::open(
        path,
        OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    rustix::fs::chmod(velarx_sys::fd::proc_path(&file), Mode::from_raw_mode(0o666))?;
    Ok(())
}

fn new_socket() -> io::Result<OwnedFd> {
    Ok(net::socket_with(
        AddressFamily::UNIX,
        SocketType::DGRAM,
        SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
        None,
    )?)
}

/// Whether `target` is a socket address a service manager gives: an
/// absolute path or an abstract name.
pub fn valid_target(target: &str) -> bool {
    (target.starts_with('/') || (target.starts_with('@') && target.len() > 1))
        && target.len() < 108
        && !target.contains('\0')
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixDatagram;

    #[test]
    fn only_allowed_messages_pass() {
        assert_eq!(filter(b"READY=1").as_deref(), Some(&b"READY=1\n"[..]));
        assert_eq!(
            filter(b"READY=1\nSTATUS=up and running\nMAINPID=1\nFDSTORE=1\n").as_deref(),
            Some(&b"READY=1\nSTATUS=up and running\n"[..])
        );
        assert_eq!(filter(b"MAINPID=42"), None);
        assert_eq!(filter(b"READY=0"), None);
        assert_eq!(filter(b"garbage"), None);
        assert_eq!(filter(&[0xff, 0xfe]), None);
        assert_eq!(filter(b"STATUS=a\x00b"), None);
        assert_eq!(
            filter(b"WATCHDOG=trigger\nWATCHDOG=2").as_deref(),
            Some(&b"WATCHDOG=trigger\n"[..])
        );
    }

    #[test]
    fn targets() {
        assert!(valid_target("/run/systemd/notify"));
        assert!(valid_target("@abstract"));
        assert!(!valid_target("relative/path"));
        assert!(!valid_target("@"));
        assert!(!valid_target(&format!("/{}", "x".repeat(200))));
    }

    #[test]
    fn the_socket_is_open_to_all() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("notify.sock");
        let _sock = bind(&path, None).unwrap();
        let mode = std::fs::symlink_metadata(&path)
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o7777, 0o666);
    }

    #[test]
    fn a_link_put_at_the_name_is_not_followed() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target");
        std::fs::write(&target, b"").unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600)).unwrap();
        let path = dir.path().join("notify.sock");
        std::os::unix::fs::symlink(&target, &path).unwrap();
        assert!(open_to_all(&path).is_err());
        let mode = std::fs::metadata(&target).unwrap().permissions().mode();
        assert_eq!(mode & 0o7777, 0o600);
    }

    #[test]
    fn a_message_goes_through_a_socket() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("notify");
        let server = UnixDatagram::bind(&path).unwrap();
        velarx_wire::sdnotify::notify_to(path.to_str().unwrap().as_bytes(), "READY=1\n").unwrap();
        let mut buf = [0u8; 64];
        let n = server.recv(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"READY=1\n");
        assert!(velarx_wire::sdnotify::notify_to(b"/nonexistent/socket", "x").is_err());
    }
}
