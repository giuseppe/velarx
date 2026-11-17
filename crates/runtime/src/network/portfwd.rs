// SPDX-License-Identifier: Apache-2.0
//! The published ports of a container on a rootless bridge network (what
//! rootlessport does for podman).  The bridges live in the rootless network
//! namespace, which the host reaches only through pasta: a forwarder binds
//! the host ports in the namespace of the host, then joins the rootless
//! namespace and relays TCP and UDP to the address of the container.
//!
//! `velarx port-forward [--netns PATH] --id ID --ip IP --pid FILE
//! PORT...` (PORT as `-p` writes them).  It detaches once the ports are
//! bound and tells its parent on its standard output: `ok`, or the error.
//!
//! Without `--netns` it relays in the namespace of the host: the ports a
//! rootful dual-stack container publishes, on `::1` (IPv6 has no
//! `route_localnet`: the firewall cannot send the loopback to a bridge).

use std::collections::HashMap;
use std::io::{self, BufRead, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::os::fd::AsFd;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};
use velarx_base::ipc::{accept_failure, AcceptFailure, ACCEPT_WAIT};
use velarx_wire::addr::{PortSpec, Proto};

const MAX_CONNECTIONS: usize = 1024;
const UDP_IDLE: Duration = Duration::from_secs(60);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Start the forwarder of the container ID and wait until its ports are
/// bound.
pub fn start(
    exe: &Path,
    netns: Option<&Path>,
    id: &str,
    ip: IpAddr,
    ports: &[PortSpec],
    pid_file: &Path,
) -> io::Result<()> {
    let mut cmd = Command::new(exe);
    cmd.arg("port-forward");
    if let Some(netns) = netns {
        cmd.arg("--netns").arg(netns);
    }
    cmd.arg("--id")
        .arg(id)
        .arg("--ip")
        .arg(ip.to_string())
        .arg("--pid")
        .arg(pid_file)
        .args(ports.iter().map(|p| p.to_string()))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let mut child = cmd.spawn().map_err(|e| {
        io::Error::new(
            e.kind(),
            format!("start the port forwarder {}: {e}", exe.display()),
        )
    })?;
    let mut line = String::new();
    if let Some(out) = child.stdout.take() {
        let _ = io::BufReader::new(out.take(4096)).read_line(&mut line);
    }
    // The process forks the forwarder and exits.
    let _ = child.wait();
    match line.trim() {
        "ok" => {
            if let Some(pid) = std::fs::read_to_string(pid_file)
                .ok()
                .and_then(|s| s.trim().parse().ok())
            {
                velarx_nsid::tree::register_holder(pid, "port-forward");
            }
            Ok(())
        }
        "" => Err(io::Error::other("the port forwarder did not start")),
        e => Err(io::Error::new(io::ErrorKind::AddrInUse, e.to_string())),
    }
}

struct Args {
    netns: Option<PathBuf>,
    ip: IpAddr,
    pid_file: PathBuf,
    ports: Vec<PortSpec>,
}

fn parse_args(args: &[String]) -> Result<Args, String> {
    let (mut netns, mut ip, mut pid_file, mut id, mut ports) = (None, None, None, None, Vec::new());
    let mut it = args.iter();
    while let Some(a) = it.next() {
        let mut value = || {
            it.next()
                .cloned()
                .ok_or_else(|| format!("{a} needs a value"))
        };
        match a.as_str() {
            "--netns" => netns = Some(PathBuf::from(value()?)),
            "--ip" => ip = Some(value()?.parse::<IpAddr>().map_err(|e| e.to_string())?),
            "--pid" => pid_file = Some(PathBuf::from(value()?)),
            "--id" => id = Some(value()?),
            p => ports.push(PortSpec::parse(p)?),
        }
    }
    let _ = id.ok_or("no --id")?;
    Ok(Args {
        netns,
        ip: ip.ok_or("no --ip")?,
        pid_file: pid_file.ok_or("no --pid")?,
        ports,
    })
}

enum Bound {
    Tcp(TcpListener, u16),
    Udp(UdpSocket, u16),
}

/// Bind the host ports in the namespace of the caller.  A port with no host
/// address is on every address of both families, as podman's rootlessport
/// has it: a socket for IPv4, one for IPv6 (IPv6 only) when the host has it.
fn bind_all(ports: &[PortSpec]) -> io::Result<Vec<Bound>> {
    let mut out = Vec::new();
    for p in ports {
        let host = p.host_ip.unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        for k in 0..p.range {
            let (hp, cp) = (p.host_port + k, p.container_port + k);
            let fail = |e: io::Error| {
                io::Error::new(
                    e.kind(),
                    format!(
                        "cannot publish the host port {hp}/{}: {e}",
                        p.proto.as_str()
                    ),
                )
            };
            out.push(match p.proto {
                Proto::Tcp => Bound::Tcp(TcpListener::bind((host, hp)).map_err(fail)?, cp),
                Proto::Udp => Bound::Udp(UdpSocket::bind((host, hp)).map_err(fail)?, cp),
                Proto::Sctp => {
                    return Err(io::Error::new(
                        io::ErrorKind::Unsupported,
                        "can't forward protocol: sctp",
                    ))
                }
            });
            if p.host_ip.is_none() {
                // (a host without IPv6 has no second socket: no error)
                match p.proto {
                    Proto::Tcp => {
                        if let Some(l) = bind_v6_only(rustix::net::SocketType::STREAM, hp)? {
                            out.push(Bound::Tcp(TcpListener::from(l), cp));
                        }
                    }
                    Proto::Udp => {
                        if let Some(u) = bind_v6_only(rustix::net::SocketType::DGRAM, hp)? {
                            out.push(Bound::Udp(UdpSocket::from(u), cp));
                        }
                    }
                    Proto::Sctp => {}
                }
            }
        }
    }
    Ok(out)
}

/// A socket on `[::]:PORT` that has no IPv4 (the IPv4 one is another
/// socket, whatever `net.ipv6.bindv6only` says); `None` when the host has no
/// IPv6.  Listening, for a stream.
fn bind_v6_only(
    kind: rustix::net::SocketType,
    port: u16,
) -> io::Result<Option<std::os::fd::OwnedFd>> {
    use rustix::net::{self, AddressFamily, SocketAddrV6};
    let fd = match net::socket(AddressFamily::INET6, kind, None) {
        Ok(fd) => fd,
        Err(e) if e == rustix::io::Errno::AFNOSUPPORT => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    net::sockopt::set_ipv6_v6only(&fd, true)?;
    if kind == rustix::net::SocketType::STREAM {
        net::sockopt::set_socket_reuseaddr(&fd, true)?;
    }
    match net::bind(&fd, &SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, port, 0, 0)) {
        Ok(()) => {}
        // no IPv6 address: the module is there, the family is off
        Err(e) if e == rustix::io::Errno::ADDRNOTAVAIL => return Ok(None),
        Err(e) => {
            return Err(io::Error::new(
                io::Error::from(e).kind(),
                format!("cannot publish the host port {port} on IPv6: {e}"),
            ))
        }
    }
    if kind == rustix::net::SocketType::STREAM {
        net::listen(&fd, 128)?;
    }
    Ok(Some(fd))
}

/// `velarx port-forward ...`: call it first thing in main, while
/// the process has a single thread.
pub fn main(args: &[String]) -> io::Result<()> {
    let mut out = io::stdout();
    let report = |out: &mut io::Stdout, msg: &str| {
        let _ = writeln!(out, "{msg}");
        let _ = out.flush();
    };
    let a = match parse_args(args) {
        Ok(a) => a,
        Err(e) => {
            report(&mut out, &e);
            return Err(io::Error::new(io::ErrorKind::InvalidInput, e));
        }
    };
    let bound = match bind_all(&a.ports) {
        Ok(b) => b,
        Err(e) => {
            report(&mut out, &e.to_string());
            return Err(e);
        }
    };
    // The connections to the container start in the rootless namespace.
    if let Some(netns) = &a.netns {
        let joined = std::fs::File::open(netns).and_then(|ns| {
            rustix::thread::move_into_link_name_space(
                ns.as_fd(),
                Some(rustix::thread::LinkNameSpaceType::Network),
            )
            .map_err(io::Error::from)
        });
        if let Err(e) = joined {
            report(&mut out, &format!("join {}: {e}", netns.display()));
            return Err(e);
        }
    }
    match velarx_sys::process::fork_single_threaded("the port forwarder") {
        Err(e) => {
            report(&mut out, &e.to_string());
            return Err(e);
        }
        Ok(velarx_sys::process::Fork::Parent(_)) => std::process::exit(0),
        Ok(velarx_sys::process::Fork::Child(_)) => {}
    }
    if let Err(e) = rustix::process::setsid() {
        report(&mut out, &format!("setsid: {e}"));
        return Err(e.into());
    }
    if let Err(e) = super::dnsd::process_limits() {
        report(&mut out, &e);
        return Err(io::Error::other(e));
    }
    if let Err(e) = super::dnsd::limit_capabilities(&[]) {
        report(&mut out, &e);
        return Err(io::Error::other(e));
    }
    std::fs::write(&a.pid_file, std::process::id().to_string())?;
    report(&mut out, "ok");
    if let Ok(null) = std::fs::File::options().write(true).open("/dev/null") {
        let _ = rustix::stdio::dup2_stdout(&null);
    }
    serve(bound, a.ip);
    Ok(())
}

/// The TCP connections relayed now, and their ends.
#[derive(Default)]
struct Active {
    count: Mutex<usize>,
    ended: Condvar,
}

impl Active {
    fn end(&self) {
        *self.count.lock().unwrap_or_else(|e| e.into_inner()) -= 1;
        self.ended.notify_all();
    }

    /// Until a connection ends, or [`ACCEPT_WAIT`] at most: what frees the
    /// descriptors may be another process.
    fn wait_for_an_end(&self) {
        let count = self.count.lock().unwrap_or_else(|e| e.into_inner());
        let _ = self.ended.wait_timeout(count, ACCEPT_WAIT);
    }
}

fn serve(bound: Vec<Bound>, ip: IpAddr) {
    let active = Arc::new(Active::default());
    let mut threads = Vec::new();
    for b in bound {
        let active = active.clone();
        threads.push(std::thread::spawn(move || match b {
            Bound::Tcp(l, cp) => serve_tcp(l, SocketAddr::new(ip, cp), active),
            Bound::Udp(s, cp) => serve_udp(s, SocketAddr::new(ip, cp)),
        }));
    }
    for t in threads {
        let _ = t.join();
    }
}

fn serve_tcp(l: TcpListener, to: SocketAddr, active: Arc<Active>) {
    for client in l.incoming() {
        let client = match client {
            Ok(client) => client,
            Err(e) => match accept_failure(&e) {
                AcceptFailure::Retry => continue,
                // (out of descriptors: the connection stays queued, and an
                // accept at once fails the same way)
                AcceptFailure::Wait => {
                    active.wait_for_an_end();
                    continue;
                }
                AcceptFailure::Broken => return,
            },
        };
        {
            let mut n = active.count.lock().unwrap_or_else(|e| e.into_inner());
            if *n >= MAX_CONNECTIONS {
                continue;
            }
            *n += 1;
        }
        let mine = active.clone();
        let spawned = std::thread::Builder::new().spawn(move || {
            if let Ok(upstream) = TcpStream::connect_timeout(&to, CONNECT_TIMEOUT) {
                relay(client, upstream);
            }
            mine.end();
        });
        if spawned.is_err() {
            active.end();
        }
    }
}

/// Copy both ways until both sides are done.
fn relay(a: TcpStream, b: TcpStream) {
    let (Ok(mut a2), Ok(mut b2)) = (a.try_clone(), b.try_clone()) else {
        return;
    };
    let t = std::thread::spawn(move || {
        let mut a = a;
        let mut b = b;
        let _ = io::copy(&mut a, &mut b);
        let _ = b.shutdown(std::net::Shutdown::Write);
    });
    let _ = io::copy(&mut b2, &mut a2);
    let _ = a2.shutdown(std::net::Shutdown::Write);
    let _ = t.join();
}

fn is_timeout(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
    )
}

fn serve_udp(s: UdpSocket, to: SocketAddr) {
    serve_udp_idle(s, to, UDP_IDLE)
}

/// A flow ends when neither side has sent for IDLE.
fn serve_udp_idle(s: UdpSocket, to: SocketAddr, idle: Duration) {
    let s = Arc::new(s);
    type Peers = Mutex<HashMap<SocketAddr, (Arc<UdpSocket>, Instant)>>;
    let peers: Arc<Peers> = Default::default();
    let mut buf = vec![0u8; 65535];
    loop {
        let (n, from) = match s.recv_from(&mut buf) {
            Ok(r) => r,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => {
                eprintln!("port forwarder: receive on the UDP socket: {e}");
                return;
            }
        };
        let upstream = {
            let mut map = peers.lock().unwrap_or_else(|e| e.into_inner());
            let now = Instant::now();
            map.retain(|_, (_, last)| now.duration_since(*last) < idle);
            if let Some((u, last)) = map.get_mut(&from) {
                *last = now;
                Some(u.clone())
            } else if map.len() < MAX_CONNECTIONS {
                let any: IpAddr = if to.is_ipv6() {
                    std::net::Ipv6Addr::UNSPECIFIED.into()
                } else {
                    Ipv4Addr::UNSPECIFIED.into()
                };
                let u = UdpSocket::bind((any, 0))
                    .and_then(|u| u.connect(to).map(|_| u))
                    .ok()
                    .map(Arc::new);
                if let Some(u) = &u {
                    map.insert(from, (u.clone(), now));
                    let (u, s, peers) = (u.clone(), s.clone(), peers.clone());
                    let _ = std::thread::Builder::new().spawn(move || {
                        let _ = u.set_read_timeout(Some(idle));
                        let mut b = vec![0u8; 65535];
                        loop {
                            let got = u.recv(&mut b);
                            if let Ok(n) = got {
                                let _ = s.send_to(&b[..n], from);
                            }
                            // The flow lives while either side sends; a
                            // new flow of the same client is not ours.
                            let mut map = peers.lock().unwrap_or_else(|e| e.into_inner());
                            let Some((mine, last)) = map.get_mut(&from) else {
                                return;
                            };
                            if !Arc::ptr_eq(mine, &u) {
                                return;
                            }
                            match got {
                                Ok(_) => *last = Instant::now(),
                                Err(e) if is_timeout(&e) && last.elapsed() < idle => {}
                                Err(_) => {
                                    map.remove(&from);
                                    return;
                                }
                            }
                        }
                    });
                }
                u
            } else {
                None
            }
        };
        if let Some(u) = upstream {
            let _ = u.send(&buf[..n]);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arguments() {
        let s = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<_>>();
        let a = parse_args(&s(&[
            "--netns", "/n", "--id", "c", "--ip", "10.0.0.2", "--pid", "/p", "8080:80",
        ]))
        .unwrap();
        assert_eq!(
            (a.ip, a.ports.len()),
            (IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 1)
        );
        assert!(parse_args(&s(&["--netns", "/n", "--ip", "10.0.0.2", "--pid", "/p"])).is_err());
        let a = parse_args(&s(&[
            "--id",
            "c",
            "--ip",
            "fd00::2",
            "--pid",
            "/p",
            "[::1]:8080:80",
        ]))
        .unwrap();
        assert!(a.netns.is_none() && a.ip.is_ipv6());
        assert!(parse_args(&s(&[
            "--netns", "/n", "--id", "c", "--ip", "x", "--pid", "/p"
        ]))
        .is_err());
        assert!(parse_args(&s(&["--netns"])).is_err());
    }

    /// The forwarder relays TCP and UDP (without a namespace: to 127.0.0.1).
    #[test]
    fn relays() {
        let echo = TcpListener::bind("127.0.0.1:0").unwrap();
        let cp = echo.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for c in echo.incoming().flatten() {
                let mut c = c;
                let _ = c.write_all(b"hello");
            }
        });
        let uecho = UdpSocket::bind("127.0.0.1:0").unwrap();
        let ucp = uecho.local_addr().unwrap().port();
        std::thread::spawn(move || {
            let mut b = [0u8; 64];
            while let Ok((n, from)) = uecho.recv_from(&mut b) {
                let _ = uecho.send_to(&b[..n], from);
            }
        });
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let hp = l.local_addr().unwrap().port();
        let u = UdpSocket::bind("127.0.0.1:0").unwrap();
        let uhp = u.local_addr().unwrap().port();
        std::thread::spawn(move || {
            serve(
                vec![Bound::Tcp(l, cp), Bound::Udp(u, ucp)],
                IpAddr::V4(Ipv4Addr::LOCALHOST),
            )
        });
        let mut c = TcpStream::connect(("127.0.0.1", hp)).unwrap();
        let mut got = String::new();
        c.read_to_string(&mut got).unwrap();
        assert_eq!(got, "hello");
        let q = UdpSocket::bind("127.0.0.1:0").unwrap();
        q.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        q.send_to(b"ping", ("127.0.0.1", uhp)).unwrap();
        let mut b = [0u8; 16];
        let n = q.recv(&mut b).unwrap();
        assert_eq!(&b[..n], b"ping");
        assert!(!velarx_netkernel::portfwd::is_forwarder_of(
            std::process::id() as i32,
            "c"
        ));
    }

    /// A flow lives while either side sends: a client that sends to a
    /// container that does not answer keeps its upstream socket (the
    /// container sees one source port) past the time without an answer.
    #[test]
    fn a_flow_lives_while_the_client_sends() {
        let sink = UdpSocket::bind("127.0.0.1:0").unwrap();
        let to = sink.local_addr().unwrap();
        let s = UdpSocket::bind("127.0.0.1:0").unwrap();
        let at = s.local_addr().unwrap();
        std::thread::spawn(move || serve_udp_idle(s, to, Duration::from_millis(300)));
        let client = UdpSocket::bind("127.0.0.1:0").unwrap();
        sink.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        let mut seen = Vec::new();
        for _ in 0..12 {
            client.send_to(b"x", at).unwrap();
            let mut b = [0u8; 4];
            let (_, from) = sink.recv_from(&mut b).unwrap();
            seen.push(from);
            std::thread::sleep(Duration::from_millis(100));
        }
        assert!(seen.iter().all(|f| *f == seen[0]), "{seen:?}");
        // a client that stops loses it
        std::thread::sleep(Duration::from_millis(900));
        client.send_to(b"x", at).unwrap();
        let mut b = [0u8; 4];
        let (_, from) = sink.recv_from(&mut b).unwrap();
        assert_ne!(from, seen[0]);
    }

    /// A port without a host address has a socket for IPv6 beside the one
    /// for IPv4, and a client of either reaches the container.
    #[test]
    fn a_port_on_every_address_is_on_both_families() {
        // (a free port: the number of a socket that is closed, which any
        // process may take before it is bound again; a number that is taken
        // is replaced by another)
        let (free, bound) = (0..32)
            .find_map(|_| {
                let free = TcpListener::bind("127.0.0.1:0")
                    .unwrap()
                    .local_addr()
                    .unwrap()
                    .port();
                let spec = PortSpec::parse(&format!("{free}:80")).unwrap();
                match bind_all(&[spec]) {
                    Ok(bound) => Some((free, bound)),
                    Err(e) if e.kind() == io::ErrorKind::AddrInUse => None,
                    Err(e) => panic!("{e}"),
                }
            })
            .expect("a free port in 32 tries");
        let v6 = std::net::TcpStream::connect(("::1", free)).is_ok();
        if !TcpListener::bind("[::1]:0").is_ok() {
            // no IPv6 on this host: one socket
            assert_eq!(bound.len(), 1);
            return;
        }
        assert_eq!(bound.len(), 2);
        assert!(v6, "a client of ::1 reaches the published port");
        assert!(std::net::TcpStream::connect(("127.0.0.1", free)).is_ok());
    }
}
