// SPDX-License-Identifier: Apache-2.0
//! The DNS server of the bridge networks.
//!
//! One server per run root answers on port 53 (UDP and TCP) of the gateways
//! of its DNS networks.  A query is answered from the records of the network
//! whose gateway received it; other names go to the servers of the network
//! or else to those of the host.
//!
//! The records are files, written and removed by the setup and the teardown
//! under the network lock:
//!
//! ```text
//! <state>/dns/<bridge>/network        the gateway, `internal`
//! <state>/dns/<bridge>/servers        the DNS servers of the network
//! <state>/dns/<bridge>/<container>    {"ips": [...], "names": [...]}
//! <state>/dns/server.lock             held by the server
//! <state>/dns/control.sock            a datagram tells it to reload
//! <state>/dns/server.log              what the server says about itself
//! ```
//!
//! The server is `velarx dns-server <state>`, detached.  It exits,
//! holding the network lock, when no record is left, so that a setup that
//! waits for the lock starts a new one.  Its keeper binds the sockets and
//! reads the records; its worker, which parses what containers send, runs
//! as nobody without capabilities, files or TCP (Landlock) and with a
//! seccomp allowlist.

use rustix::event::{poll, PollFd, PollFlags};
use rustix::fs::FlockOperation;
use rustix::net::{sockopt, AddressFamily, SocketType};
use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::os::unix::net::UnixDatagram;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::time::{Duration, Instant};
use velarx_netkernel::bridge::NETWORK_LOCK;
use velarx_netkernel::dns::{self, Answer, Record};
use velarx_netkernel::dnsrec::*;

const MAX_PENDING: usize = 512;
/// What one network may have pending: a container that floods its server
/// does not starve the others.
const MAX_PENDING_NET: usize = 64;
const MAX_TCP: usize = 64;
const MAX_UPSTREAMS: usize = 3;
const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(2);
const TCP_TIMEOUT: Duration = Duration::from_secs(5);
const TCP_MAX: usize = 65535;
const CAP_NET_BIND_SERVICE: u64 = 10;
const CAP_SETGID: u64 = 6;
const CAP_SETUID: u64 = 7;

// The server: a keeper and a worker.
//
// The keeper (the user of the daemon, root when it is) reads the records
// the setups wrote and binds port 53 of the gateways; it never reads what a
// container sends.  The worker gets the zones and the sockets through a
// socket pair and parses the queries: it runs as nobody without any
// capability (or, where nobody is not mapped, without capabilities), with
// no file and no TCP connection allowed by Landlock and a seccomp
// allowlist.

/// A configuration to the worker over the stream FD: its length with the
/// sockets, then the configuration (a message of a socket of messages is
/// limited to the size of the buffer of the socket).
fn send_config(fd: BorrowedFd<'_>, data: &[u8], sockets: &[BorrowedFd<'_>]) -> io::Result<()> {
    velarx_sys::scm::send(fd, &(data.len() as u32).to_le_bytes(), sockets)?;
    velarx_sys::scm::send(fd, data, &[])
}

/// A network as the worker serves it.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct WorkerNet {
    bridge: String,
    gateway: Ipv4Addr,
    /// Names that are not containers get no answer: no way out.
    internal: bool,
    zone: Vec<Record>,
    upstreams: Vec<SocketAddr>,
}

/// What the keeper sends: the sockets follow, UDP and TCP of each network.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct WorkerConfig {
    nets: Vec<WorkerNet>,
    upstreams: Vec<SocketAddr>,
}

const MAX_CONFIG: usize = 16 << 20;

fn lock_file(path: &Path, op: FlockOperation) -> io::Result<File> {
    let f = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(path)?;
    velarx_sys::flock::flock_retrying(&f, op)?;
    Ok(f)
}

fn bind_socket(gateway: Ipv4Addr, ty: SocketType) -> io::Result<OwnedFd> {
    let fd = rustix::net::socket_with(
        AddressFamily::INET,
        ty,
        rustix::net::SocketFlags::CLOEXEC | rustix::net::SocketFlags::NONBLOCK,
        None,
    )?;
    sockopt::set_socket_reuseaddr(&fd, true)?;
    // The bridge may not have its address yet.
    sockopt::set_ip_freebind(&fd, true)?;
    rustix::net::bind(&fd, &SocketAddr::new(IpAddr::V4(gateway), 53))?;
    if ty == SocketType::STREAM {
        rustix::net::listen(&fd, 64)?;
    }
    Ok(fd)
}

/// The networks with records under STATE and the number of records.
fn load(state: &Path) -> (WorkerConfig, usize) {
    let mut cfg = WorkerConfig::default();
    let mut total = 0;
    let mut entries: Vec<_> = fs::read_dir(dns_dir(state))
        .map(|d| d.flatten().collect())
        .unwrap_or_default();
    entries.sort_by_key(|e| e.file_name());
    for e in entries {
        if cfg.nets.len() >= MAX_NETS {
            break;
        }
        let bridge = e.file_name().to_string_lossy().into_owned();
        if !velarx_wire::addr::valid_ifname(&bridge) || !e.file_type().is_ok_and(|t| t.is_dir()) {
            continue;
        }
        let dir = e.path();
        let Some((gateway, internal)) = read_small(&dir.join(NETWORK_FILE))
            .as_deref()
            .and_then(parse_network_file)
        else {
            continue;
        };
        let mut zone = Vec::new();
        for r in fs::read_dir(&dir).into_iter().flatten().flatten() {
            let name = r.file_name().to_string_lossy().into_owned();
            if !valid_record_name(&name) || !r.file_type().is_ok_and(|t| t.is_file()) {
                continue;
            }
            if let Some(rec) = read_small(&r.path()).as_deref().and_then(parse_record) {
                zone.push(rec);
            }
        }
        if zone.is_empty() {
            continue;
        }
        let upstreams = read_small(&dir.join(SERVERS_FILE))
            .map(|s| {
                s.lines()
                    .filter_map(parse_upstream)
                    .take(MAX_UPSTREAMS)
                    .collect()
            })
            .unwrap_or_default();
        total += zone.len();
        cfg.nets.push(WorkerNet {
            bridge,
            gateway,
            internal,
            zone,
            upstreams,
        });
    }
    let gateways: Vec<IpAddr> = cfg.nets.iter().map(|n| IpAddr::V4(n.gateway)).collect();
    cfg.upstreams = read_small(Path::new("/etc/resolv.conf"))
        .map(|c| resolv_conf_servers(&c, |_| None))
        .unwrap_or_default()
        .into_iter()
        .filter(|a| !gateways.contains(&a.ip()))
        // A server on the loopback of the host is not on that of another
        // namespace (the rootless one): the forwarder of the `upstream`
        // file instead.
        .filter(|a| !a.ip().is_loopback() || !dns_dir(state).join(UPSTREAM_FILE).exists())
        .take(MAX_UPSTREAMS)
        .collect();
    if cfg.upstreams.is_empty() {
        cfg.upstreams = read_small(&dns_dir(state).join(UPSTREAM_FILE))
            .map(|s| {
                s.lines()
                    .filter_map(parse_upstream)
                    .take(MAX_UPSTREAMS)
                    .collect()
            })
            .unwrap_or_default();
    }
    (cfg, total)
}

struct KeptNet {
    bridge: String,
    gateway: Ipv4Addr,
    udp: OwnedFd,
    tcp: OwnedFd,
}

struct Keeper {
    state: PathBuf,
    control: UnixDatagram,
    kept: Vec<KeptNet>,
    config: WorkerConfig,
    worker: Option<OwnedFd>,
    starts: Vec<Instant>,
    /// The networks whose sockets could not be bound, which the log has:
    /// said once, not at every reload.
    unserved: Vec<(String, Ipv4Addr)>,
}

impl Keeper {
    /// Load the records and (re)bind the sockets: the number of records.
    /// The caller holds the network lock.
    fn reload(&mut self) -> usize {
        let (cfg, total) = load(&self.state);
        let unserved_before = std::mem::take(&mut self.unserved);
        let mut unserved = Vec::new();
        let mut kept = Vec::new();
        let mut nets = Vec::new();
        for n in cfg.nets {
            let k = match self
                .kept
                .iter()
                .position(|k| k.bridge == n.bridge && k.gateway == n.gateway)
            {
                Some(i) => self.kept.swap_remove(i),
                None => match (
                    bind_socket(n.gateway, SocketType::DGRAM),
                    bind_socket(n.gateway, SocketType::STREAM),
                ) {
                    (Ok(udp), Ok(tcp)) => KeptNet {
                        bridge: n.bridge.clone(),
                        gateway: n.gateway,
                        udp,
                        tcp,
                    },
                    (udp, tcp) => {
                        let key = (n.bridge.clone(), n.gateway);
                        if !unserved_before.contains(&key) {
                            for e in [udp.err(), tcp.err()].into_iter().flatten() {
                                eprintln!(
                                    "the DNS server does not serve the network {} on {}:53: {e}",
                                    n.bridge, n.gateway
                                );
                            }
                        }
                        unserved.push(key);
                        continue;
                    }
                },
            };
            kept.push(k);
            nets.push(n);
        }
        self.kept = kept;
        self.unserved = unserved;
        self.config = WorkerConfig {
            nets,
            upstreams: cfg.upstreams,
        };
        total
    }

    /// Send the configuration and the sockets to the worker: the length of
    /// the configuration with the sockets, then the configuration.
    fn send(&self) -> io::Result<()> {
        let Some(w) = &self.worker else {
            return Err(io::Error::other("no worker"));
        };
        let data = serde_json::to_vec(&self.config).map_err(io::Error::other)?;
        let fds: Vec<_> = self
            .kept
            .iter()
            .flat_map(|k| [k.udp.as_fd(), k.tcp.as_fd()])
            .collect();
        send_config(w.as_fd(), &data, &fds)
    }

    /// Start a worker (a few times a minute at most).
    fn spawn_worker(&mut self) -> io::Result<()> {
        let now = Instant::now();
        self.starts
            .retain(|t| now.duration_since(*t) < Duration::from_secs(60));
        if self.starts.len() >= 5 {
            return Err(io::Error::other("the DNS worker keeps dying"));
        }
        self.starts.push(now);
        let (mine, theirs) = rustix::net::socketpair(
            AddressFamily::UNIX,
            SocketType::STREAM,
            rustix::net::SocketFlags::CLOEXEC,
            None,
        )?;
        // (the keeper has a single thread: nothing in it starts one; it is
        // confined, so /proc/self/task cannot be counted here)
        if let velarx_sys::process::Fork::Child(child) =
            velarx_sys::process::fork_known_single_threaded()?
        {
            drop(mine);
            worker_main(child, theirs);
        }
        drop(theirs);
        self.worker = Some(mine);
        Ok(())
    }

    /// Serve until the server is to exit: the network lock it exits holding.
    fn serve(&mut self) -> io::Result<File> {
        loop {
            let mut fds = vec![PollFd::new(&self.control, PollFlags::IN)];
            if let Some(w) = &self.worker {
                fds.push(PollFd::new(w, PollFlags::IN));
            }
            match poll(&mut fds, None) {
                Ok(_) | Err(rustix::io::Errno::INTR) => {}
                Err(e) => return Err(e.into()),
            }
            let control = !fds[0].revents().is_empty();
            let worker_gone = fds.get(1).is_some_and(|f| !f.revents().is_empty());
            drop(fds);
            if worker_gone {
                self.worker = None;
                self.spawn_worker()?;
                self.send()?;
            }
            if control {
                let mut b = [0u8; 16];
                while self.control.recv(&mut b).is_ok() {}
                let lock = lock_file(
                    &self.state.join(NETWORK_LOCK),
                    FlockOperation::LockExclusive,
                )?;
                if self.reload() == 0 {
                    // Exit holding the network lock: a setup that adds a
                    // record waits for it, then starts a new server.  The
                    // worker sees the end of its socket.
                    let _ = fs::remove_file(dns_dir(&self.state).join(CONTROL));
                    return Ok(lock);
                }
                drop(lock);
                if self.send().is_err() {
                    self.worker = None;
                    self.spawn_worker()?;
                    self.send()?;
                }
            }
        }
    }
}

struct Net {
    udp: Rc<UdpSocket>,
    tcp: TcpListener,
    internal: bool,
    zone: Vec<Record>,
    upstreams: Vec<SocketAddr>,
}

enum Client {
    Udp(Rc<UdpSocket>, SocketAddr),
    Tcp(TcpStream),
}

/// The socket of a query to an upstream: a client that came over TCP is
/// answered over TCP (a UDP answer would have TC set again).
enum Upstream {
    Udp(UdpSocket),
    Connecting(TcpStream),
    /// With what was read of the framed answer
    Reading(TcpStream, Vec<u8>),
}

enum Step {
    Wait,
    Reply(Vec<u8>),
    /// The upstream failed: the next one is asked
    Retry,
}

struct Pending {
    sock: Option<Upstream>,
    net: usize,
    client: Client,
    query: Vec<u8>,
    upstreams: Vec<SocketAddr>,
    upstream: usize,
    deadline: Instant,
}

struct Conn {
    stream: TcpStream,
    net: usize,
    buf: Vec<u8>,
    deadline: Instant,
}

struct Worker {
    keeper: OwnedFd,
    nets: Vec<Net>,
    upstreams: Vec<SocketAddr>,
    pending: Vec<Pending>,
    conns: Vec<Conn>,
}

impl Worker {
    /// Take a configuration from the keeper; false when it is gone.
    fn receive(&mut self) -> bool {
        let mut head = [0u8; 4];
        let fds = match velarx_sys::scm::recv(
            &self.keeper,
            &mut head,
            2 * MAX_NETS,
            rustix::net::RecvFlags::empty(),
        ) {
            Ok(m) if m.bytes == head.len() => m.fds,
            _ => return false,
        };
        let len = u32::from_le_bytes(head) as usize;
        if len > MAX_CONFIG {
            return false;
        }
        let mut data = vec![0u8; len];
        let mut got = 0;
        while got < len {
            match rustix::io::read(&self.keeper, &mut data[got..]) {
                Ok(0) => return false,
                Ok(n) => got += n,
                Err(rustix::io::Errno::INTR) => {}
                Err(_) => return false,
            }
        }
        let Ok(cfg) = serde_json::from_slice::<WorkerConfig>(&data) else {
            return true;
        };
        if fds.len() != 2 * cfg.nets.len() {
            return true;
        }
        // The connections refer to the networks by index.
        self.conns.clear();
        let mut it = fds.into_iter();
        self.nets = cfg
            .nets
            .into_iter()
            .filter_map(|n| {
                let (udp, tcp) = (it.next()?, it.next()?);
                Some(Net {
                    udp: Rc::new(UdpSocket::from(udp)),
                    tcp: TcpListener::from(tcp),
                    internal: n.internal,
                    zone: n.zone,
                    upstreams: n.upstreams,
                })
            })
            .collect();
        self.upstreams = cfg.upstreams;
        true
    }

    fn send_reply(client: &mut Client, data: &[u8]) {
        match client {
            Client::Udp(sock, to) => {
                let _ = sock.send_to(data, *to);
            }
            Client::Tcp(s) => {
                let mut framed = (data.len() as u16).to_be_bytes().to_vec();
                framed.extend_from_slice(data);
                // (the connection is read without blocking, the reply is
                // written with a limit)
                let _ = s.set_nonblocking(false);
                let _ = s.set_write_timeout(Some(Duration::from_secs(1)));
                let _ = s.write_all(&framed);
                let _ = s.set_nonblocking(true);
            }
        }
    }

    /// Send the query to the next upstream that takes it.
    fn send_upstream(p: &mut Pending) -> bool {
        let tcp = matches!(p.client, Client::Tcp(_));
        while p.upstream < p.upstreams.len() {
            let to = p.upstreams[p.upstream];
            let sent = if tcp {
                Self::connect_tcp(to).map(Upstream::Connecting)
            } else {
                Self::send_udp(to, &p.query).map(Upstream::Udp)
            };
            if let Ok(s) = sent {
                p.sock = Some(s);
                p.deadline = Instant::now() + UPSTREAM_TIMEOUT;
                return true;
            }
            p.upstream += 1;
        }
        false
    }

    fn send_udp(to: SocketAddr, query: &[u8]) -> io::Result<UdpSocket> {
        let bind: SocketAddr = if to.is_ipv6() {
            SocketAddr::new(IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED), 0)
        } else {
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
        };
        let s = UdpSocket::bind(bind)?;
        s.set_nonblocking(true)?;
        s.connect(to)?;
        s.send(query)?;
        Ok(s)
    }

    /// A connection that is being made (the std library has none that does
    /// not block).
    fn connect_tcp(to: SocketAddr) -> io::Result<TcpStream> {
        let family = if to.is_ipv6() {
            AddressFamily::INET6
        } else {
            AddressFamily::INET
        };
        let fd = rustix::net::socket_with(
            family,
            SocketType::STREAM,
            rustix::net::SocketFlags::CLOEXEC | rustix::net::SocketFlags::NONBLOCK,
            None,
        )?;
        match rustix::net::connect(&fd, &to) {
            Ok(()) | Err(rustix::io::Errno::INPROGRESS) => Ok(TcpStream::from(fd)),
            Err(e) => Err(e.into()),
        }
    }

    /// The query goes to the upstream after the current one (it did not
    /// answer, or its socket failed); false when there is none.
    fn next_upstream(p: &mut Pending) -> bool {
        p.upstream += 1;
        Self::send_upstream(p)
    }

    fn fail(p: &mut Pending) {
        if let Some(r) = dns::servfail(&p.query) {
            Self::send_reply(&mut p.client, &r);
        }
    }

    fn handle_query(&mut self, net: usize, query: &[u8], mut client: Client) {
        let tcp = matches!(client, Client::Tcp(_));
        let size = if tcp { TCP_MAX } else { dns::UDP_SIZE };
        match dns::answer(&self.nets[net].zone, query, size) {
            Answer::Reply(r) => Self::send_reply(&mut client, &r),
            Answer::Drop => {}
            // An internal network has no way out, not even through names.
            Answer::Forward if self.nets[net].internal => {
                if let Some(r) = dns::servfail(query) {
                    Self::send_reply(&mut client, &r);
                }
            }
            Answer::Forward
                if self.pending.len() >= MAX_PENDING
                    || self.pending.iter().filter(|p| p.net == net).count() >= MAX_PENDING_NET => {}
            Answer::Forward => {
                let upstreams = if self.nets[net].upstreams.is_empty() {
                    self.upstreams.clone()
                } else {
                    self.nets[net].upstreams.clone()
                };
                let mut p = Pending {
                    sock: None,
                    net,
                    client,
                    query: query.to_vec(),
                    upstreams,
                    upstream: 0,
                    deadline: Instant::now(),
                };
                if Self::send_upstream(&mut p) {
                    self.pending.push(p);
                } else {
                    Self::fail(&mut p);
                }
            }
        }
    }

    /// Read what the upstream of the pending query P has for it.
    fn upstream_step(p: &mut Pending) -> Step {
        let wait = |p: &mut Pending, s| {
            p.sock = Some(s);
            Step::Wait
        };
        match p.sock.take() {
            None => Step::Wait,
            Some(Upstream::Udp(s)) => {
                let mut buf = vec![0u8; TCP_MAX];
                match s.recv(&mut buf) {
                    Err(e)
                        if e.kind() == io::ErrorKind::WouldBlock
                            || e.kind() == io::ErrorKind::Interrupted =>
                    {
                        wait(p, Upstream::Udp(s))
                    }
                    // (refused, unreachable: the next upstream is asked)
                    Err(_) => Step::Retry,
                    Ok(n) => Step::Reply(buf[..n].to_vec()),
                }
            }
            Some(Upstream::Connecting(mut s)) => {
                if !matches!(s.take_error(), Ok(None)) {
                    return Step::Retry;
                }
                let mut framed = (p.query.len() as u16).to_be_bytes().to_vec();
                framed.extend_from_slice(&p.query);
                match s.write_all(&framed) {
                    Ok(()) => wait(p, Upstream::Reading(s, Vec::new())),
                    Err(_) => Step::Retry,
                }
            }
            Some(Upstream::Reading(mut s, mut got)) => {
                let mut chunk = vec![0u8; 2 + TCP_MAX - got.len()];
                match s.read(&mut chunk) {
                    Err(e)
                        if e.kind() == io::ErrorKind::WouldBlock
                            || e.kind() == io::ErrorKind::Interrupted =>
                    {
                        wait(p, Upstream::Reading(s, got))
                    }
                    Err(_) | Ok(0) => Step::Retry,
                    Ok(n) => {
                        got.extend_from_slice(&chunk[..n]);
                        let want = match got.as_slice() {
                            [a, b, ..] => 2 + usize::from(u16::from_be_bytes([*a, *b])),
                            _ => usize::MAX,
                        };
                        if got.len() >= want {
                            Step::Reply(got[2..want].to_vec())
                        } else {
                            wait(p, Upstream::Reading(s, got))
                        }
                    }
                }
            }
        }
    }

    fn handle_upstream(&mut self, i: usize) {
        match Self::upstream_step(&mut self.pending[i]) {
            Step::Wait => {}
            Step::Retry => {
                if !Self::next_upstream(&mut self.pending[i]) {
                    let mut p = self.pending.swap_remove(i);
                    Self::fail(&mut p);
                }
            }
            Step::Reply(r) => {
                let mut p = self.pending.swap_remove(i);
                if r.len() >= 12 && r[..2] == p.query[..2] {
                    Self::send_reply(&mut p.client, &r);
                } else {
                    Self::fail(&mut p);
                }
            }
        }
    }

    /// Read from the TCP connection I; the queries that are complete.  The
    /// connection stays for more until it is idle.
    fn handle_tcp(&mut self, i: usize) {
        let c = &mut self.conns[i];
        let mut chunk = vec![0u8; 2 + TCP_MAX - c.buf.len()];
        let n = match c.stream.read(&mut chunk) {
            Err(e)
                if e.kind() == io::ErrorKind::WouldBlock
                    || e.kind() == io::ErrorKind::Interrupted =>
            {
                return
            }
            Err(_) | Ok(0) => {
                self.conns.swap_remove(i);
                return;
            }
            Ok(n) => n,
        };
        c.buf.extend_from_slice(&chunk[..n]);
        let mut queries = Vec::new();
        while c.buf.len() >= 2 {
            let want = 2 + usize::from(u16::from_be_bytes([c.buf[0], c.buf[1]]));
            if c.buf.len() < want {
                break;
            }
            queries.push(c.buf.drain(..want).skip(2).collect::<Vec<u8>>());
            c.deadline = Instant::now() + TCP_TIMEOUT;
        }
        let net = c.net;
        for query in queries {
            let Ok(stream) = self.conns[i].stream.try_clone() else {
                self.conns.swap_remove(i);
                return;
            };
            self.handle_query(net, &query, Client::Tcp(stream));
        }
    }

    fn serve(&mut self) {
        #[derive(Clone, Copy)]
        enum Kind {
            Keeper,
            Udp(usize),
            Tcp(usize),
            Conn(usize),
            Upstream(usize),
        }
        loop {
            let now = Instant::now();
            let mut next = now + Duration::from_secs(60);
            let mut kinds = vec![Kind::Keeper];
            let mut fds = vec![PollFd::new(&self.keeper, PollFlags::IN)];
            for (i, n) in self.nets.iter().enumerate() {
                fds.push(PollFd::new(n.udp.as_ref(), PollFlags::IN));
                kinds.push(Kind::Udp(i));
                if self.conns.len() < MAX_TCP {
                    fds.push(PollFd::new(&n.tcp, PollFlags::IN));
                    kinds.push(Kind::Tcp(i));
                }
            }
            for (i, c) in self.conns.iter().enumerate() {
                fds.push(PollFd::new(&c.stream, PollFlags::IN));
                kinds.push(Kind::Conn(i));
                next = next.min(c.deadline);
            }
            for (i, p) in self.pending.iter().enumerate() {
                let polled = match &p.sock {
                    Some(Upstream::Udp(s)) => Some(PollFd::new(s, PollFlags::IN)),
                    Some(Upstream::Connecting(s)) => Some(PollFd::new(s, PollFlags::OUT)),
                    Some(Upstream::Reading(s, _)) => Some(PollFd::new(s, PollFlags::IN)),
                    None => None,
                };
                if let Some(f) = polled {
                    fds.push(f);
                    kinds.push(Kind::Upstream(i));
                }
                next = next.min(p.deadline);
            }
            let wait = next.saturating_duration_since(now);
            let timeout = rustix::event::Timespec {
                tv_sec: wait.as_secs() as i64,
                tv_nsec: i64::from(wait.subsec_nanos()),
            };
            match poll(&mut fds, Some(&timeout)) {
                Ok(_) | Err(rustix::io::Errno::INTR) => {}
                Err(_) => return,
            }
            let ready: Vec<(Kind, bool)> = fds
                .iter()
                .zip(&kinds)
                .map(|(f, k)| (*k, !f.revents().is_empty()))
                .collect();
            drop(fds);

            // The keeper first: a new configuration changes the sockets.
            if ready[0].1 {
                if !self.receive() {
                    return;
                }
                continue;
            }
            // From the end: removals swap the last entry in.
            for (kind, _) in ready.iter().rev().filter(|(_, r)| *r) {
                match *kind {
                    Kind::Keeper => {}
                    Kind::Udp(i) => {
                        let sock = self.nets[i].udp.clone();
                        let mut buf = vec![0u8; TCP_MAX];
                        if let Ok((n, from)) = sock.recv_from(&mut buf) {
                            self.handle_query(i, &buf[..n], Client::Udp(sock, from));
                        }
                    }
                    Kind::Tcp(i) => {
                        if let Ok((s, _)) = self.nets[i].tcp.accept() {
                            if self.conns.len() < MAX_TCP && s.set_nonblocking(true).is_ok() {
                                self.conns.push(Conn {
                                    stream: s,
                                    net: i,
                                    buf: Vec::new(),
                                    deadline: Instant::now() + TCP_TIMEOUT,
                                });
                            }
                        }
                    }
                    Kind::Conn(i) if i < self.conns.len() => self.handle_tcp(i),
                    Kind::Upstream(i) if i < self.pending.len() => self.handle_upstream(i),
                    _ => {}
                }
            }
            let now = Instant::now();
            for i in (0..self.pending.len()).rev() {
                if self.pending[i].deadline <= now {
                    let p = &mut self.pending[i];
                    if !Self::next_upstream(p) {
                        let mut p = self.pending.swap_remove(i);
                        Self::fail(&mut p);
                    }
                }
            }
            self.conns.retain(|c| c.deadline > now);
        }
    }
}

/// Keep only the capabilities KEEP in the effective and permitted sets, and
/// drop the others from the bounding set.
pub(super) fn limit_capabilities(keep: &[u64]) -> Result<(), String> {
    use rustix::thread::{CapabilitySet, CapabilitySets};
    velarx_sys::caps::drop_bounding_except(|c| keep.contains(&u64::from(c)))
        .map_err(|e| format!("capabilities of the bounding set: {e}"))?;
    let bits =
        CapabilitySet::from_bits_retain(u64::from(keep.iter().fold(0u32, |b, k| b | 1u32 << k)));
    rustix::thread::set_capabilities(
        None,
        CapabilitySets {
            effective: bits,
            permitted: bits,
            inheritable: CapabilitySet::empty(),
        },
    )
    .map_err(|e| format!("capset: {}", io::Error::from(e)))
}

pub(super) fn process_limits() -> Result<(), String> {
    rustix::process::set_dumpable_behavior(rustix::process::DumpableBehavior::NotDumpable)
        .map_err(|e| format!("PR_SET_DUMPABLE: {}", io::Error::from(e)))?;
    rustix::thread::set_no_new_privs(true)
        .map_err(|e| format!("PR_SET_NO_NEW_PRIVS: {}", io::Error::from(e)))?;
    Ok(())
}

/// The keeper: it binds port 53 and reads the records of STATE.
fn confine_keeper(state: &Path) -> Result<(), String> {
    use landlock::{
        Access, AccessFs, CompatLevel, Compatible, PathBeneath, PathFd, Ruleset, RulesetAttr,
        RulesetCreatedAttr, ABI,
    };
    process_limits()?;
    // Port 53, and nobody for the workers it starts.
    limit_capabilities(&[CAP_NET_BIND_SERVICE, CAP_SETGID, CAP_SETUID])?;
    // (who it is, for its workers too: Landlock leaves it no /proc)
    velarx_base::ids::settle().map_err(|e| e.to_string())?;
    let abi = ABI::V6;
    let mut ruleset = Ruleset::default()
        .set_compatibility(CompatLevel::BestEffort)
        .handle_access(AccessFs::from_all(abi))
        .map_err(|e| format!("landlock: {e}"))?
        .create()
        .map_err(|e| format!("landlock: {e}"))?;
    let read = AccessFs::from_read(abi);
    let rules: [(&Path, _); 5] = [
        (state, AccessFs::from_all(abi)),
        (Path::new("/etc/resolv.conf"), read),
        (Path::new("/run/systemd/resolve"), read),
        (Path::new("/proc/sys/kernel/cap_last_cap"), read),
        (Path::new("/dev/null"), AccessFs::from_all(abi)),
    ];
    for (path, access) in rules {
        let Ok(fd) = PathFd::new(path) else { continue };
        ruleset = ruleset
            .add_rule(PathBeneath::new(fd, access))
            .map_err(|e| format!("landlock: {e}"))?;
    }
    let status = ruleset
        .restrict_self()
        .map_err(|e| format!("landlock: {e}"))?;
    enforced(status.ruleset)?;
    for program in keeper_seccomp()? {
        seccompiler::apply_filter(&program).map_err(|e| format!("seccomp: {e}"))?;
    }
    Ok(())
}

/// The architecture of the filters of this build.
fn target_arch() -> Result<seccompiler::TargetArch, String> {
    seccompiler::TargetArch::try_from(std::env::consts::ARCH).map_err(|e| e.to_string())
}

/// What the keeper does after it confined itself (files of the state
/// directory, the sockets of the networks, the worker it forks) and what the
/// worker does before it confines itself in turn (it inherits this filter):
/// the calls of the worker are added by [`keeper_seccomp`].
fn keeper_allowed() -> Vec<i64> {
    let allowed = vec![
        libc::SYS_openat,
        libc::SYS_fstat,
        libc::SYS_newfstatat,
        libc::SYS_statx,
        libc::SYS_lseek,
        libc::SYS_getdents64,
        libc::SYS_flock,
        libc::SYS_unlinkat,
        libc::SYS_dup3,
        libc::SYS_close_range,
        libc::SYS_getpid,
        libc::SYS_listen,
        libc::SYS_socketpair,
        libc::SYS_rt_sigaction,
        libc::SYS_set_robust_list,
        // the worker, before its own confinement (`setgroups`, `setresgid`
        // and `setresuid` are added by [`keeper_seccomp`]: nobody only;
        // `capget` tells whether it may empty its bounding set)
        libc::SYS_capget,
        libc::SYS_capset,
        libc::SYS_landlock_create_ruleset,
        libc::SYS_landlock_add_rule,
        libc::SYS_landlock_restrict_self,
    ];
    #[cfg(target_arch = "x86_64")]
    let allowed = [allowed, vec![libc::SYS_unlink, libc::SYS_dup2]].concat();
    allowed
}

/// The keeper is an allowlist: the calls it and its worker make, the
/// arguments of the ones that could do more limited (IPv4 and IPv6 sockets:
/// no UNIX socket reaches the services of the machine, the `ioctl` that sets
/// a descriptor non-blocking, the `fcntl` and `prctl` commands it uses, no
/// other user or group than nobody, `clone` without a namespace) and
/// `ENOSYS` for `clone3`, whose flags a filter cannot see, so that the C
/// library falls back to `clone`.  The others fail with `EPERM`.
fn keeper_seccomp() -> Result<Vec<seccompiler::BpfProgram>, String> {
    use seccompiler::{
        SeccompAction,
        SeccompCmpArgLen::{Dword, Qword},
        SeccompCmpOp::{Eq, MaskedEq},
        SeccompCondition, SeccompFilter, SeccompRule,
    };
    use velarx_sys::confine::CLONE_NEW_FLAGS;
    let rule = |arg, len, op, value: u64| -> Result<SeccompRule, String> {
        SeccompRule::new(vec![
            SeccompCondition::new(arg, len, op, value).map_err(|e| e.to_string())?
        ])
        .map_err(|e| e.to_string())
    };
    let mut rules: std::collections::BTreeMap<i64, Vec<SeccompRule>> = worker_allowed()
        .into_iter()
        .chain(keeper_allowed())
        .map(|nr| (nr, Vec::new()))
        .collect();
    let any_of = |arg, values: &[u64], rules: &mut Vec<SeccompRule>| -> Result<(), String> {
        for &v in values {
            rules.push(rule(arg, Dword, Eq, v)?);
        }
        Ok(())
    };
    let mut socket = Vec::new();
    any_of(
        0,
        &[libc::AF_INET as u64, libc::AF_INET6 as u64],
        &mut socket,
    )?;
    rules.insert(libc::SYS_socket, socket);
    // the worker becomes nobody, without supplementary groups: the
    // capabilities the keeper keeps for it give no other user or group
    let nobody = |arg| SeccompCondition::new(arg, Dword, Eq, NOBODY.into());
    for nr in [libc::SYS_setresuid, libc::SYS_setresgid] {
        let all = [nobody(0), nobody(1), nobody(2)]
            .into_iter()
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| e.to_string())?;
        rules.insert(nr, vec![SeccompRule::new(all).map_err(|e| e.to_string())?]);
    }
    rules.insert(libc::SYS_setgroups, vec![rule(0, Dword, Eq, 0)?]);
    rules.insert(
        libc::SYS_socketpair,
        vec![rule(0, Dword, Eq, libc::AF_UNIX as u64)?],
    );
    let mut ioctl = Vec::new();
    any_of(1, &[libc::FIONBIO, libc::FIOCLEX], &mut ioctl)?;
    rules.insert(libc::SYS_ioctl, ioctl);
    let mut fcntl = Vec::new();
    any_of(
        1,
        &[
            libc::F_GETFD as u64,
            libc::F_SETFD as u64,
            libc::F_GETFL as u64,
            libc::F_SETFL as u64,
            libc::F_DUPFD_CLOEXEC as u64,
        ],
        &mut fcntl,
    )?;
    rules.insert(libc::SYS_fcntl, fcntl);
    // the limits of the worker: dumpable, no_new_privs, the bounding set
    // (read capability by capability, then dropped)
    let mut prctl = Vec::new();
    any_of(
        0,
        &[
            libc::PR_SET_DUMPABLE as u64,
            libc::PR_SET_NO_NEW_PRIVS as u64,
            libc::PR_CAPBSET_READ as u64,
            libc::PR_CAPBSET_DROP as u64,
        ],
        &mut prctl,
    )?;
    rules.insert(libc::SYS_prctl, prctl);
    // the filter of the worker
    rules.insert(
        libc::SYS_seccomp,
        vec![rule(0, Dword, Eq, libc::SECCOMP_SET_MODE_FILTER as u64)?],
    );
    // the worker is a process; a namespace is not a thing the keeper makes
    rules.insert(
        libc::SYS_clone,
        vec![rule(0, Qword, MaskedEq(CLONE_NEW_FLAGS.into()), 0)?],
    );
    let compile = |rules, mismatch, matched| -> Result<seccompiler::BpfProgram, String> {
        let filter = SeccompFilter::new(rules, mismatch, matched, target_arch()?)
            .map_err(|e| e.to_string())?;
        velarx_sys::confine::seccompiler_program(filter)
    };
    // (a call that two filters answer differently gets the answer of the
    // last one installed when both are errors: the one for `clone3` is last)
    let enosys = [(libc::SYS_clone3, Vec::new())].into_iter().collect();
    Ok(vec![
        compile(
            rules,
            SeccompAction::Errno(libc::EPERM as u32),
            SeccompAction::Allow,
        )?,
        compile(
            enosys,
            SeccompAction::Allow,
            SeccompAction::Errno(libc::ENOSYS as u32),
        )?,
    ])
}

/// The calls the worker makes: sockets it was given or connects to the
/// upstream servers, memory, time.  The others fail with EPERM.
fn worker_allowed() -> Vec<i64> {
    let allowed = vec![
        libc::SYS_read,
        libc::SYS_write,
        libc::SYS_writev,
        libc::SYS_close,
        libc::SYS_ppoll,
        libc::SYS_recvfrom,
        libc::SYS_sendto,
        libc::SYS_recvmsg,
        libc::SYS_sendmsg,
        libc::SYS_socket,
        libc::SYS_connect,
        libc::SYS_bind,
        libc::SYS_accept4,
        libc::SYS_setsockopt,
        libc::SYS_getsockopt,
        libc::SYS_getsockname,
        libc::SYS_ioctl,
        libc::SYS_fcntl,
        libc::SYS_mmap,
        libc::SYS_munmap,
        libc::SYS_mremap,
        libc::SYS_madvise,
        libc::SYS_brk,
        libc::SYS_futex,
        libc::SYS_rt_sigreturn,
        libc::SYS_rt_sigprocmask,
        libc::SYS_sigaltstack,
        libc::SYS_clock_gettime,
        libc::SYS_getrandom,
        libc::SYS_sched_yield,
        libc::SYS_exit,
        libc::SYS_exit_group,
    ];
    #[cfg(target_arch = "x86_64")]
    let allowed = [allowed, vec![libc::SYS_poll, libc::SYS_accept]].concat();
    allowed
}

fn worker_seccomp() -> Result<seccompiler::BpfProgram, String> {
    use seccompiler::{SeccompAction, SeccompFilter};
    let rules = worker_allowed()
        .into_iter()
        .map(|nr| (nr, Vec::new()))
        .collect();
    let filter = SeccompFilter::new(
        rules,
        SeccompAction::Errno(libc::EPERM as u32),
        SeccompAction::Allow,
        target_arch()?,
    )
    .map_err(|e| e.to_string())?;
    velarx_sys::confine::seccompiler_program(filter)
}

/// The worker: nobody, no capability, no file, no TCP connection but to the
/// DNS port.
fn confine_worker() -> Result<(), String> {
    use landlock::{
        Access, AccessFs, AccessNet, CompatLevel, Compatible, NetPort, Ruleset, RulesetAttr,
        RulesetCreatedAttr, Scope, ABI,
    };
    process_limits()?;
    // In a user namespace without nobody it keeps its user, without any
    // capability either way; root of the host always has nobody.
    if let Err(e) = velarx_sys::process::become_user_and_group(NOBODY, NOBODY) {
        if velarx_base::ids::rootful().map_err(|e| e.to_string())? {
            return Err(format!("cannot become nobody: {e}"));
        }
    }
    limit_capabilities(&[])?;
    let abi = ABI::V6;
    let status = Ruleset::default()
        .set_compatibility(CompatLevel::BestEffort)
        .handle_access(AccessFs::from_all(abi))
        .map_err(|e| format!("landlock: {e}"))?
        .handle_access(AccessNet::BindTcp | AccessNet::ConnectTcp)
        .map_err(|e| format!("landlock: {e}"))?
        .scope(Scope::AbstractUnixSocket | Scope::Signal)
        .map_err(|e| format!("landlock: {e}"))?
        .create()
        .map_err(|e| format!("landlock: {e}"))?
        // (the queries of TCP clients go to the DNS port of the upstream)
        .add_rule(NetPort::new(53, AccessNet::ConnectTcp))
        .map_err(|e| format!("landlock: {e}"))?
        .restrict_self()
        .map_err(|e| format!("landlock: {e}"))?;
    enforced(status.ruleset)?;
    seccompiler::apply_filter(&worker_seccomp()?).map_err(|e| format!("seccomp: {e}"))?;
    Ok(())
}

/// The rights of the file system are a must: a kernel without Landlock
/// does not run the server (what newer ABIs add is taken where the kernel
/// has it).
fn enforced(status: landlock::RulesetStatus) -> Result<(), String> {
    if status == landlock::RulesetStatus::NotEnforced {
        return Err("landlock is not enforced by this kernel".into());
    }
    Ok(())
}

const NOBODY: u32 = 65534;

/// Nothing of the keeper stays open in its worker but `keeper`: the control
/// socket, the locks, the sockets (they come again with the configuration).
/// The token of the child is given up: what the worker opens from here on
/// is its own.
fn keep_only(child: velarx_sys::spawn::InChild, keeper: BorrowedFd<'_>) {
    let keep = keeper.as_raw_fd();
    if keep > 3 {
        child.close_range(3, keep as u32 - 1);
    }
    child.close_from(keep as u32 + 1);
}

/// The worker process: never returns.
fn worker_main(child: velarx_sys::spawn::InChild, keeper: OwnedFd) -> ! {
    keep_only(child, keeper.as_fd());
    if let Err(e) = confine_worker() {
        eprintln!("the DNS worker cannot confine itself: {e}");
        std::process::exit(1);
    }
    let mut w = Worker {
        keeper,
        nets: Vec::new(),
        upstreams: Vec::new(),
        pending: Vec::new(),
        conns: Vec::new(),
    };
    w.serve();
    std::process::exit(0)
}

/// `velarx dns-server STATE`: fork the server and exit.  Call it
/// first thing in `main`, while the process has a single thread.  The
/// network lock the server exits holding (if it does) is returned: the
/// caller keeps it until the process ends.
pub fn server_main(state: &Path) -> io::Result<Option<File>> {
    let state = state.to_path_buf();
    let dir = dns_dir(&state);
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&dir)?;
    if let velarx_sys::process::Fork::Parent(_) =
        velarx_sys::process::fork_single_threaded("the DNS server")?
    {
        std::process::exit(0);
    }
    let _ = rustix::process::setsid();
    // A worker that ends is not waited for (the keeper sees its socket
    // close): the kernel reaps it, no zombie stays.
    velarx_sys::signal::ignore(libc::SIGCHLD);
    // (the control socket is bound by a path relative to it)
    std::env::set_current_dir(&dir)
        .map_err(|e| io::Error::new(e.kind(), format!("enter {}: {e}", dir.display())))?;
    // Hold the server lock for the life of the process.
    let server_lock = lock_file(
        &dir.join(SERVER_LOCK),
        FlockOperation::NonBlockingLockExclusive,
    );
    let mut out = io::stdout();
    let Ok(_server_lock) = server_lock else {
        // Another server: it reloads.
        reload(&state);
        let _ = out.write_all(b"0\n");
        return Ok(None);
    };
    let _ = fs::remove_file(dir.join(CONTROL));
    // Relative to the directory: sun_path is short.
    let control = UnixDatagram::bind(CONTROL)?;
    control.set_nonblocking(true)?;
    // It only receives: no datagram goes through it to another socket of
    // the machine (the keeper makes no UNIX socket of its own).
    control.shutdown(std::net::Shutdown::Write)?;
    confine_keeper(&state).map_err(io::Error::other)?;
    out.write_all(format!("{}\n", std::process::id()).as_bytes())?;
    out.flush()?;
    if let Ok(null) = File::options().write(true).open("/dev/null") {
        let _ = rustix::stdio::dup2_stdout(&null);
    }
    let mut k = Keeper {
        state,
        control,
        kept: Vec::new(),
        config: WorkerConfig::default(),
        worker: None,
        starts: Vec::new(),
        unserved: Vec::new(),
    };
    let lock = lock_file(&k.state.join(NETWORK_LOCK), FlockOperation::LockExclusive)?;
    if k.reload() == 0 {
        // (the network lock is given up after the server lock, as when
        // `serve` ends)
        let _ = fs::remove_file(dns_dir(&k.state).join(CONTROL));
        return Ok(Some(lock));
    }
    drop(lock);
    k.spawn_worker()?;
    k.send()?;
    k.serve().map(Some)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The log of the server stays under its limit across starts: one over
    /// it is emptied, one under it is kept.
    #[test]
    fn the_log_of_the_server_is_bounded() {
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join(SERVER_LOG);
        let open = || OpenOptions::new().append(true).open(&path).unwrap();
        fs::write(&path, b"kept\n").unwrap();
        bound_log(&open()).unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"kept\n");
        fs::write(&path, vec![b'x'; SERVER_LOG_LIMIT as usize + 1]).unwrap();
        let log = open();
        bound_log(&log).unwrap();
        (&log).write_all(b"next\n").unwrap();
        assert_eq!(
            fs::read(&path).unwrap(),
            [SERVER_LOG_EMPTIED, b"next\n"].concat()
        );
    }

    #[test]
    fn a_fifo_is_no_record() {
        let d = tempfile::tempdir().unwrap();
        let fifo = d.path().join("fifo");
        velarx_base::testing::make_fifo(&fifo);
        let r =
            velarx_base::testing::returns_within(std::time::Duration::from_secs(10), move || {
                read_small(&fifo)
            });
        assert_eq!(r, None);
    }

    /// A link at the name the file was once written through is not followed.
    #[test]
    fn a_record_is_written_to_a_temporary_name_of_its_own() {
        let d = tempfile::tempdir().unwrap();
        let victim = d.path().join("victim");
        fs::write(&victim, b"keep").unwrap();
        std::os::unix::fs::symlink(&victim, d.path().join(".rec.tmp")).unwrap();
        write_atomic(d.path(), "rec", b"new").unwrap();
        assert_eq!(fs::read(&victim).unwrap(), b"keep");
        assert_eq!(fs::read(d.path().join("rec")).unwrap(), b"new");
    }

    /// The server confines itself with Landlock or does not run: a kernel
    /// that enforces nothing is an error, one that lacks the newer rights
    /// is not.
    #[test]
    fn a_kernel_that_enforces_no_landlock_is_refused() {
        use landlock::RulesetStatus;
        assert!(enforced(RulesetStatus::NotEnforced).is_err());
        assert!(enforced(RulesetStatus::PartiallyEnforced).is_ok());
        assert!(enforced(RulesetStatus::FullyEnforced).is_ok());
    }

    /// An upstream whose socket fails on receive (a port nobody listens on:
    /// refused) leaves the query to the next one.
    #[test]
    fn a_refused_upstream_passes_the_query_on() {
        let closed = {
            let s = UdpSocket::bind("127.0.0.1:0").unwrap();
            s.local_addr().unwrap()
        };
        let live = UdpSocket::bind("127.0.0.1:0").unwrap();
        let client = Rc::new(UdpSocket::bind("127.0.0.1:0").unwrap());
        let mut p = Pending {
            sock: None,
            net: 0,
            client: Client::Udp(client, "127.0.0.1:9".parse().unwrap()),
            query: vec![1, 2, 3],
            upstreams: vec![closed, live.local_addr().unwrap()],
            upstream: 0,
            deadline: Instant::now(),
        };
        assert!(Worker::send_upstream(&mut p));
        let mut buf = [0u8; 16];
        // (the refusal is queued on the socket when the send returns)
        let Some(Upstream::Udp(sock)) = p.sock.as_ref() else {
            panic!("not a UDP upstream");
        };
        assert!(sock.recv(&mut buf).is_err());
        assert!(Worker::next_upstream(&mut p));
        assert_eq!(p.upstream, 1);
        live.set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        assert_eq!(live.recv(&mut buf).unwrap(), 3);
        // and with none left
        assert!(!Worker::next_upstream(&mut p));
    }

    fn pending_over_tcp(upstream: SocketAddr) -> (Pending, TcpStream) {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = TcpStream::connect(l.local_addr().unwrap()).unwrap();
        let (served, _) = l.accept().unwrap();
        // (a question for the root, type A)
        let query = vec![0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1];
        let p = Pending {
            sock: None,
            net: 0,
            client: Client::Tcp(served),
            query,
            upstreams: vec![upstream],
            upstream: 0,
            deadline: Instant::now(),
        };
        (p, client)
    }

    /// A client that came over TCP is answered from the upstream over TCP
    /// (a UDP answer to a big query has TC set again), also when the
    /// answer comes in pieces.
    #[test]
    fn a_query_that_came_over_tcp_goes_to_the_upstream_over_tcp() {
        let up = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = up.local_addr().unwrap();
        let big = 3000;
        let server = std::thread::spawn(move || {
            let (mut s, _) = up.accept().unwrap();
            let mut len = [0u8; 2];
            s.read_exact(&mut len).unwrap();
            let mut q = vec![0u8; usize::from(u16::from_be_bytes(len))];
            s.read_exact(&mut q).unwrap();
            let mut reply = q.clone();
            reply.resize(big, 7);
            let mut framed = (reply.len() as u16).to_be_bytes().to_vec();
            framed.extend_from_slice(&reply);
            s.write_all(&framed[..10]).unwrap();
            s.flush().unwrap();
            std::thread::sleep(Duration::from_millis(50));
            s.write_all(&framed[10..]).unwrap();
        });
        let (mut p, mut client) = pending_over_tcp(addr);
        assert!(Worker::send_upstream(&mut p));
        assert!(matches!(p.sock, Some(Upstream::Connecting(_))));
        let deadline = Instant::now() + Duration::from_secs(5);
        let reply = loop {
            assert!(Instant::now() < deadline, "no answer");
            let fd = match p.sock.as_ref().unwrap() {
                Upstream::Connecting(s) => {
                    (s.as_fd().try_clone_to_owned().unwrap(), PollFlags::OUT)
                }
                Upstream::Reading(s, _) => (s.as_fd().try_clone_to_owned().unwrap(), PollFlags::IN),
                Upstream::Udp(_) => panic!("UDP"),
            };
            let mut fds = [PollFd::new(&fd.0, fd.1)];
            poll(
                &mut fds,
                Some(&rustix::event::Timespec {
                    tv_sec: 1,
                    tv_nsec: 0,
                }),
            )
            .unwrap();
            match Worker::upstream_step(&mut p) {
                Step::Reply(r) => break r,
                Step::Wait => {}
                Step::Retry => panic!("the upstream failed"),
            }
        };
        assert_eq!((reply.len(), &reply[..2]), (big, &[0x12, 0x34][..]));
        Worker::send_reply(&mut p.client, &reply);
        let mut len = [0u8; 2];
        client.read_exact(&mut len).unwrap();
        assert_eq!(usize::from(u16::from_be_bytes(len)), big);
        server.join().unwrap();
    }

    /// A container that floods its server does not use the forwarding of the
    /// other networks.
    #[test]
    fn a_network_has_its_own_quota_of_pending_queries() {
        let net = |upstream: SocketAddr| Net {
            udp: Rc::new(UdpSocket::bind("127.0.0.1:0").unwrap()),
            tcp: TcpListener::bind("127.0.0.1:0").unwrap(),
            internal: false,
            zone: Vec::new(),
            upstreams: vec![upstream],
        };
        let sink = UdpSocket::bind("127.0.0.1:0").unwrap();
        let (keeper, _other) = rustix::net::socketpair(
            AddressFamily::UNIX,
            SocketType::STREAM,
            rustix::net::SocketFlags::CLOEXEC,
            None,
        )
        .unwrap();
        let mut w = Worker {
            keeper,
            nets: vec![
                net(sink.local_addr().unwrap()),
                net(sink.local_addr().unwrap()),
            ],
            upstreams: Vec::new(),
            pending: Vec::new(),
            conns: Vec::new(),
        };
        // a question for `a.example`, type A
        let mut q = vec![0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        q.extend_from_slice(b"\x01a\x07example\x00\x00\x01\x00\x01");
        let client = || {
            let s = Rc::new(UdpSocket::bind("127.0.0.1:0").unwrap());
            Client::Udp(s, "127.0.0.1:9".parse().unwrap())
        };
        for _ in 0..MAX_PENDING_NET + 10 {
            w.handle_query(0, &q, client());
        }
        assert_eq!(w.pending.len(), MAX_PENDING_NET);
        w.handle_query(1, &q, client());
        assert_eq!(w.pending.len(), MAX_PENDING_NET + 1);
    }

    /// A configuration over the size of a message of a socket of messages
    /// reaches the worker, with its sockets.
    #[test]
    fn a_big_configuration_reaches_the_worker() {
        let (mine, theirs) = rustix::net::socketpair(
            AddressFamily::UNIX,
            SocketType::STREAM,
            rustix::net::SocketFlags::CLOEXEC,
            None,
        )
        .unwrap();
        let record = |i: usize| Record {
            names: vec![format!("container-{i}"), format!("alias-{i}")],
            ips: vec![Ipv4Addr::new(10, 88, (i / 250) as u8, (i % 250) as u8)],
            ips6: Vec::new(),
        };
        let cfg = WorkerConfig {
            nets: vec![WorkerNet {
                bridge: "br0".into(),
                gateway: Ipv4Addr::new(10, 88, 0, 1),
                internal: false,
                zone: (0..5000).map(record).collect(),
                upstreams: Vec::new(),
            }],
            upstreams: Vec::new(),
        };
        let data = serde_json::to_vec(&cfg).unwrap();
        assert!(data.len() > 300_000);
        let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
        let tcp = TcpListener::bind("127.0.0.1:0").unwrap();
        let sender = std::thread::spawn(move || {
            send_config(mine.as_fd(), &data, &[udp.as_fd(), tcp.as_fd()]).unwrap();
            mine
        });
        let mut w = Worker {
            keeper: theirs,
            nets: Vec::new(),
            upstreams: Vec::new(),
            pending: Vec::new(),
            conns: Vec::new(),
        };
        assert!(w.receive());
        assert_eq!((w.nets.len(), w.nets[0].zone.len()), (1, 5000));
        // the end of the keeper is the end of the worker
        drop(sender.join().unwrap());
        assert!(!w.receive());
    }

    #[test]
    fn network_files() {
        assert_eq!(
            parse_network_file("10.0.0.1\n"),
            Some((Ipv4Addr::new(10, 0, 0, 1), false))
        );
        assert_eq!(
            parse_network_file("10.0.0.1\ninternal\n"),
            Some((Ipv4Addr::new(10, 0, 0, 1), true))
        );
        assert_eq!(parse_network_file("bogus"), None);
    }

    use velarx_sys::confine::{seccomp_verdict, ARCH};

    /// io_uring: its operations escape the seccomp filters.
    const IO_URING: [i64; 3] = [425, 426, 427];
    const ALLOW: u32 = 0x7fff_0000;
    const EPERM: u32 = libc::SECCOMP_RET_ERRNO | libc::EPERM as u32;
    const ENOSYS: u32 = libc::SECCOMP_RET_ERRNO | libc::ENOSYS as u32;

    fn keeper(nr: i64, args: [u64; 6]) -> u32 {
        seccomp_verdict(&keeper_seccomp().unwrap(), nr as u32, ARCH, args)
    }

    fn plain(nr: i64) -> u32 {
        keeper(nr, [0; 6])
    }

    #[test]
    fn the_worker_filter_is_an_allowlist_without_io_uring() {
        let program = [worker_seccomp().unwrap()];
        for nr in worker_allowed() {
            assert_eq!(seccomp_verdict(&program, nr as u32, ARCH, [0; 6]), ALLOW);
        }
        for nr in IO_URING {
            assert_eq!(seccomp_verdict(&program, nr as u32, ARCH, [0; 6]), EPERM);
        }
        // it is a process of its own: no new one
        for nr in [libc::SYS_clone, libc::SYS_clone3, libc::SYS_execve] {
            assert_eq!(seccomp_verdict(&program, nr as u32, ARCH, [0; 6]), EPERM);
        }
    }

    /// What the keeper and its worker do passes the filter.
    #[test]
    fn the_keeper_filter_allows_what_the_keeper_does() {
        for nr in worker_allowed().into_iter().chain(keeper_allowed()) {
            let ret = plain(nr);
            // (the calls with a condition are checked below)
            assert!(
                ret == ALLOW
                    || [
                        libc::SYS_ioctl,
                        libc::SYS_fcntl,
                        libc::SYS_socket,
                        libc::SYS_socketpair
                    ]
                    .contains(&nr),
                "{nr}: {ret:#x}"
            );
        }
        let af = |d: i32| [d as u64, 0, 0, 0, 0, 0];
        for domain in [libc::AF_INET, libc::AF_INET6] {
            assert_eq!(keeper(libc::SYS_socket, af(domain)), ALLOW);
        }
        // (a UNIX socket would reach the services of the machine: D-Bus,
        // systemd, the engine)
        for domain in [
            libc::AF_UNIX,
            libc::AF_NETLINK,
            libc::AF_PACKET,
            libc::AF_VSOCK,
        ] {
            assert_eq!(keeper(libc::SYS_socket, af(domain)), EPERM, "{domain}");
        }
        // the worker becomes nobody, and nobody else
        let ids = |a: u32, b: u32, c: u32| [a.into(), b.into(), c.into(), 0, 0, 0];
        for nr in [libc::SYS_setresuid, libc::SYS_setresgid] {
            assert_eq!(keeper(nr, ids(NOBODY, NOBODY, NOBODY)), ALLOW);
            for (a, b, c) in [(0, 0, 0), (1000, 1000, 1000), (NOBODY, NOBODY, 0)] {
                assert_eq!(keeper(nr, ids(a, b, c)), EPERM, "{nr} {a} {b} {c}");
            }
        }
        assert_eq!(keeper(libc::SYS_setgroups, [0; 6]), ALLOW);
        assert_eq!(keeper(libc::SYS_setgroups, [1, 0, 0, 0, 0, 0]), EPERM);
        assert_eq!(keeper(libc::SYS_socketpair, af(libc::AF_UNIX)), ALLOW);
        assert_eq!(keeper(libc::SYS_socketpair, af(libc::AF_INET)), EPERM);
        let arg1 = |v: u64| [3, v, 0, 0, 0, 0];
        assert_eq!(keeper(libc::SYS_ioctl, arg1(libc::FIONBIO)), ALLOW);
        assert_eq!(keeper(libc::SYS_ioctl, arg1(libc::TIOCSTI)), EPERM);
        for cmd in [libc::F_GETFD, libc::F_SETFD, libc::F_GETFL, libc::F_SETFL] {
            assert_eq!(keeper(libc::SYS_fcntl, arg1(cmd as u64)), ALLOW);
        }
        for cmd in [libc::F_SETOWN, libc::F_SETLK] {
            assert_eq!(keeper(libc::SYS_fcntl, arg1(cmd as u64)), EPERM);
        }
        let arg0 = |v: u64| [v, 0, 0, 0, 0, 0];
        for op in [
            libc::PR_SET_DUMPABLE,
            libc::PR_SET_NO_NEW_PRIVS,
            libc::PR_CAPBSET_READ,
            libc::PR_CAPBSET_DROP,
        ] {
            assert_eq!(keeper(libc::SYS_prctl, arg0(op as u64)), ALLOW);
        }
        // (what `velarx_sys::caps::drop_bounding_except` of the worker
        // asks first: without it the worker cannot start)
        assert_eq!(keeper(libc::SYS_capget, arg0(0)), ALLOW);
        assert_eq!(
            keeper(libc::SYS_prctl, arg0(libc::PR_SET_SECCOMP as u64)),
            EPERM
        );
        assert_eq!(
            keeper(
                libc::SYS_seccomp,
                arg0(libc::SECCOMP_SET_MODE_FILTER as u64)
            ),
            ALLOW
        );
        assert_eq!(
            keeper(
                libc::SYS_seccomp,
                arg0(libc::SECCOMP_SET_MODE_STRICT as u64)
            ),
            EPERM
        );
    }

    /// The keeper can fork its worker and cannot make a namespace.
    #[test]
    fn the_keeper_forks_but_makes_no_namespace() {
        let flags = |f: i32| [f as u64, 0, 0, 0, 0, 0];
        // fork, as the C library makes it
        let fork = libc::CLONE_CHILD_CLEARTID | libc::CLONE_CHILD_SETTID | libc::SIGCHLD;
        assert_eq!(keeper(libc::SYS_clone, flags(fork)), ALLOW);
        // a thread, as std makes it
        let thread = libc::CLONE_VM
            | libc::CLONE_FS
            | libc::CLONE_FILES
            | libc::CLONE_SIGHAND
            | libc::CLONE_THREAD
            | libc::CLONE_SYSVSEM
            | libc::CLONE_SETTLS
            | libc::CLONE_PARENT_SETTID
            | libc::CLONE_CHILD_CLEARTID;
        assert_eq!(keeper(libc::SYS_clone, flags(thread)), ALLOW);
        for ns in [
            libc::CLONE_NEWUSER,
            libc::CLONE_NEWNS,
            libc::CLONE_NEWNET,
            libc::CLONE_NEWPID,
            libc::CLONE_NEWUTS,
            libc::CLONE_NEWIPC,
            libc::CLONE_NEWCGROUP,
        ] {
            assert_eq!(keeper(libc::SYS_clone, flags(fork | ns)), EPERM, "{ns:#x}");
            assert_eq!(
                keeper(libc::SYS_clone, flags(thread | ns)),
                EPERM,
                "{ns:#x}"
            );
        }
        // the flags of clone3 are in a structure: ENOSYS, and the C library
        // makes the process with clone
        assert_eq!(plain(libc::SYS_clone3), ENOSYS);
    }

    /// The calls the keeper has no use for fail.
    #[test]
    fn the_keeper_filter_refuses_the_rest() {
        let mut denied = vec![
            libc::SYS_unshare,
            libc::SYS_setns,
            libc::SYS_ptrace,
            libc::SYS_mount,
            libc::SYS_umount2,
            libc::SYS_pivot_root,
            libc::SYS_chroot,
            libc::SYS_open_tree,
            libc::SYS_move_mount,
            libc::SYS_fsopen,
            libc::SYS_fsconfig,
            libc::SYS_fsmount,
            libc::SYS_fspick,
            libc::SYS_mount_setattr,
            libc::SYS_bpf,
            libc::SYS_keyctl,
            libc::SYS_add_key,
            libc::SYS_perf_event_open,
            libc::SYS_process_vm_readv,
            libc::SYS_process_vm_writev,
            libc::SYS_userfaultfd,
            libc::SYS_kexec_load,
            libc::SYS_init_module,
            libc::SYS_finit_module,
            libc::SYS_delete_module,
            libc::SYS_open_by_handle_at,
            libc::SYS_name_to_handle_at,
            libc::SYS_personality,
            libc::SYS_reboot,
            libc::SYS_swapon,
            libc::SYS_swapoff,
            libc::SYS_acct,
            libc::SYS_quotactl,
            libc::SYS_execve,
            libc::SYS_kill,
            libc::SYS_mknodat,
            libc::SYS_renameat,
            libc::SYS_mkdirat,
            libc::SYS_symlinkat,
        ];
        denied.extend(IO_URING);
        #[cfg(target_arch = "x86_64")]
        denied.extend([
            libc::SYS_fork,
            libc::SYS_vfork,
            libc::SYS_rename,
            libc::SYS_mkdir,
        ]);
        for nr in denied {
            assert_eq!(plain(nr), EPERM, "{nr}");
        }
    }

    /// Another ABI is refused or kills the process.
    #[test]
    fn the_keeper_filter_checks_the_architecture() {
        let programs = keeper_seccomp().unwrap();
        let nr = libc::SYS_getpid as u32;
        assert_eq!(seccomp_verdict(&programs, nr, ARCH, [0; 6]), ALLOW);
        for other in [0x4000_0003, 0x4000_0028] {
            assert_eq!(
                seccomp_verdict(&programs, nr, other, [0; 6]),
                libc::SECCOMP_RET_KILL_PROCESS
            );
        }
        // x32
        #[cfg(target_arch = "x86_64")]
        assert_eq!(
            seccomp_verdict(&programs, nr | 0x4000_0000, ARCH, [0; 6]),
            EPERM
        );
    }

    #[test]
    fn records() {
        let r =
            parse_record(r#"{"ips": ["10.0.0.2", "bogus"], "names": ["Web", "a b", ""]}"#).unwrap();
        assert_eq!(r.ips, vec![Ipv4Addr::new(10, 0, 0, 2)]);
        assert_eq!(r.names, vec!["web".to_string()]);
        assert!(parse_record("[").is_none());
        assert!(valid_record_name("0123abc"));
        for bad in ["", ".x", "a/b", "network", "servers", "..", "a b"] {
            assert!(!valid_record_name(bad), "{bad}");
        }
    }

    #[test]
    fn resolv_conf() {
        let s = resolv_conf_servers(
            "# x\nnameserver 10.0.0.53\nnameserver  ::1 # c\nsearch a\nnameserver bogus\n",
            |_| None,
        );
        assert_eq!(
            s,
            vec![
                "10.0.0.53:53".parse::<SocketAddr>().unwrap(),
                "[::1]:53".parse().unwrap()
            ]
        );
        // an interface by number or by name; one that is not known is left out
        let eth0 = |name: &str| (name == "eth0").then_some(2);
        let scoped = |ip: &str, scope| {
            SocketAddr::V6(std::net::SocketAddrV6::new(
                ip.parse().unwrap(),
                53,
                0,
                scope,
            ))
        };
        assert_eq!(
            resolv_conf_servers(
                "nameserver fe80::1%eth0\nnameserver fe80::2%7\nnameserver fe80::3%no\n\
                 nameserver 192.0.2.1%eth0\n",
                eth0
            ),
            vec![scoped("fe80::1", 2), scoped("fe80::2", 7)]
        );
        assert_eq!(parse_upstream("192.0.2.9"), "192.0.2.9:53".parse().ok());
        assert_eq!(
            parse_upstream("192.0.2.9:5353"),
            "192.0.2.9:5353".parse().ok()
        );
        assert_eq!(parse_upstream("[::1]:53"), "[::1]:53".parse().ok());
        assert_eq!(parse_upstream("dns.example"), None);
    }
}
