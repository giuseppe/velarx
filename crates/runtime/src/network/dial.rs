// SPDX-License-Identifier: Apache-2.0
//! A TCP connection made inside the network namespace of a container, handed
//! over as a descriptor: the connecting thread joins the namespace, the
//! daemon's own namespace and its other threads stay where they are, and the
//! socket keeps the namespace it was made in.

use std::fs::File;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream};
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::fs::MetadataExt;
use std::time::Duration;

/// How long a connection may take to be made.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Whether the namespace NS is the one this process runs in: a thread cannot
/// join it without privilege then, and need not.
fn is_own(ns: &File) -> io::Result<bool> {
    let own = std::fs::metadata("/proc/self/ns/net")?;
    let other = ns.metadata()?;
    Ok((own.dev(), own.ino()) == (other.dev(), other.ino()))
}

/// Connect to PORT on the loopback address (IPv4 first, then IPv6) of the
/// network namespace NS (an open `/proc/PID/ns/net` or a pinned one: open
/// before the caller checks the process is still the one it means).
/// Blocks: run it in a blocking thread.
pub fn connect_loopback(ns: &File, port: u16) -> io::Result<OwnedFd> {
    let own = is_own(ns)?;
    let connect = move || {
        let mut last = None;
        for ip in [
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
        ] {
            match TcpStream::connect_timeout(&SocketAddr::new(ip, port), CONNECT_TIMEOUT) {
                Ok(s) => return Ok(OwnedFd::from(s)),
                Err(e) => last = Some(e),
            }
        }
        Err(last.unwrap_or_else(|| io::Error::other("no address")))
    };
    if own {
        return connect();
    }
    velarx_netkernel::bridge::in_netns(ns.as_fd(), connect)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::path::Path;

    fn ns(path: &str) -> File {
        File::open(Path::new(path)).unwrap()
    }

    #[test]
    fn a_connection_to_the_own_namespace() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let fd = connect_loopback(&ns("/proc/self/ns/net"), port).unwrap();
        let (mut server, _) = l.accept().unwrap();
        let mut client = TcpStream::from(fd);
        client.write_all(b"ping").unwrap();
        let mut b = [0u8; 4];
        server.read_exact(&mut b).unwrap();
        assert_eq!(&b, b"ping");
    }

    #[test]
    fn a_closed_port_is_an_error() {
        // a port that is bound and not listening refuses the connections, and
        // no other test can have it while this one holds it
        let socket = rustix::net::socket(
            rustix::net::AddressFamily::INET,
            rustix::net::SocketType::STREAM,
            None,
        )
        .unwrap();
        rustix::net::bind(
            &socket,
            &std::net::SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0),
        )
        .unwrap();
        let bound: std::net::SocketAddrV4 = rustix::net::getsockname(&socket)
            .unwrap()
            .try_into()
            .unwrap();
        let e = connect_loopback(&ns("/proc/self/ns/net"), bound.port()).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::ConnectionRefused);
    }

    /// Run the test NAME in a user namespace of its own, where the process
    /// may join namespaces; true when the caller is that run and goes on.
    fn in_userns(name: &str) -> bool {
        if std::env::var_os("VELARX_DIAL_TEST_NS").is_some() {
            return true;
        }
        let unshare = |args: &[&str]| std::process::Command::new("unshare").args(args).output();
        if !unshare(&["-r", "true"]).is_ok_and(|o| o.status.success()) {
            eprintln!("skipped: no user namespaces");
            return false;
        }
        let out = std::process::Command::new("unshare")
            .arg("-r")
            .arg(std::env::current_exe().unwrap())
            .args(["--exact", &format!("network::dial::tests::{name}")])
            .env("VELARX_DIAL_TEST_NS", "1")
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        false
    }

    /// A thread in a network namespace of its own, with a listener on its
    /// loopback that answers what it reads, upper-cased: the thread and the
    /// port.
    fn server_in_a_namespace() -> (u32, u16) {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            velarx_sys::ns::unshare(rustix::thread::UnshareFlags::NEWNET).unwrap();
            let mut nl = velarx_netkernel::netlink::Netlink::open().unwrap();
            let lo = nl.link_index("lo").unwrap();
            nl.link_up(lo).unwrap();
            let l = TcpListener::bind("127.0.0.1:0").unwrap();
            let tid = rustix::thread::gettid().as_raw_nonzero().get() as u32;
            tx.send((tid, l.local_addr().unwrap().port())).unwrap();
            let (mut c, _) = l.accept().unwrap();
            let mut b = [0u8; 16];
            let n = c.read(&mut b).unwrap();
            c.write_all(&b[..n].to_ascii_uppercase()).unwrap();
        });
        rx.recv().unwrap()
    }

    #[test]
    fn a_connection_inside_another_namespace() {
        if !in_userns("a_connection_inside_another_namespace") {
            return;
        }
        let (tid, port) = server_in_a_namespace();
        // (the namespace of the own process has no listener on that port)
        assert!(TcpStream::connect(("127.0.0.1", port)).is_err());
        let path = format!("/proc/self/task/{tid}/ns/net");
        let fd = connect_loopback(&ns(&path), port).unwrap();
        let mut c = TcpStream::from(fd);
        c.write_all(b"hello").unwrap();
        let mut b = [0u8; 5];
        c.read_exact(&mut b).unwrap();
        assert_eq!(&b, b"HELLO");
    }
}
