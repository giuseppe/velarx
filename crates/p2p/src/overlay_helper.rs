// SPDX-License-Identifier: Apache-2.0
//! The privileged half of the P2P overlay network.
//!
//! The overlay needs CAP_NET_ADMIN (veth pairs, addresses, routes and
//! rules, sysctls), CAP_NET_RAW (the packet sockets of the containers'
//! veths, the DNS sockets bound to one and transparent),
//! CAP_NET_BIND_SERVICE (port 53 of the DNS sockets) and CAP_SYS_ADMIN (the
//! network namespaces of the containers); velarx-p2p, which talks to
//! the network, needs none of them once those exist.  The
//! helper is a process of its own that keeps them and does only this, on
//! the requests of the service over a socketpair:
//!
//! * `Init { node_subnet, dns_table, dns_rule_priority }`, once: the node's /24 of the overlay (the
//!   service learns it from its peer id), which must be in the overlay the
//!   helper was started with; the DNS of the node's address (the
//!   containers' gateway and name server) is routed to the host: two rules
//!   send the packets to its port 53, TCP and UDP, to a table where the
//!   address is local (`dns_routing`).  The address is no address of the
//!   host: a packet to any other port of it is not the host's, and no
//!   service of the host is reached through it.  The rules and the route go
//!   when the helper ends; what a helper that was killed left is removed by
//!   the next one;
//! * `Forwarding`: IPv4 forwarding on;
//! * `Prepare { id, ip }`: the veth pair of the container, `ip/32` on its
//!   side, the host side up with proxy ARP and the route to `ip`; the
//!   answer carries a packet socket bound to the host side (descriptor
//!   passed), on which the service reads and writes the frames;
//! * `Dns { id, tcp }`: a UDP or TCP (listening) socket on the node's
//!   address, port 53, bound to the host side of the veth of the container
//!   (it sees that container's packets only) and transparent (it binds to
//!   and sends from the address, which is not the host's), passed to the
//!   service, which answers on it: the kernel does the TCP and the reverse
//!   path of the UDP;
//! * `Started { id, default_route }`, with a descriptor of the container's
//!   network namespace: in it, the loopback and `eth0` up, the route
//!   through the node's address, no reverse path filter; the answer
//!   carries the address (MAC) of that `eth0`, which is how the service
//!   knows where to send the container's packets;
//! * `Cleanup { id }`: the host side deleted.
//!
//! Nothing else: no command, no path, no interface name comes from the
//! service.  The names derive from the container id (checked), the
//! addresses must be in the node's subnet the helper was started with, and
//! `Started` only touches a namespace whose `eth0` is the peer of the veth
//! the helper made for that container (not the host's, nor another
//! container's).  The namespace is a descriptor, never a pid, so no other
//! process's namespace is touched when a pid is reused.  The helper
//! confines itself: no new privileges, only the
//! capabilities above, Landlock (`/proc` read, `/proc/sys/net` written),
//! seccomp (an allow-list: no exec, no mount; netlink and packet sockets,
//! and the IPv4 UDP and TCP sockets of the DNS, which it binds and does not
//! use).

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io;
use std::net::Ipv4Addr;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use velarx_netkernel::netlink::Netlink;
use velarx_sys::allow::{self, Allow};

/// The largest message either side sends.
const MAX_MESSAGE: usize = 64 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Request {
    /// The node's subnet in the overlay (once, first): the containers'
    /// addresses, the first one being the node's.
    Init {
        node_subnet: String,
        /// The routing table of the DNS of the containers
        dns_table: u32,
        /// The priority of the rules that send the DNS to that table
        dns_rule_priority: u32,
    },
    Forwarding,
    Prepare {
        id: String,
        ip: Ipv4Addr,
    },
    /// With the descriptor of the container's network namespace
    Started {
        id: String,
        default_route: bool,
    },
    /// A socket for the DNS of the container: UDP, or TCP and listening
    Dns {
        id: String,
        tcp: bool,
    },
    Cleanup {
        id: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "reply", rename_all = "snake_case")]
pub enum Reply {
    Ok,
    /// With a packet socket bound to `veth_host`.
    Prepared {
        veth_host: String,
        veth_container: String,
        host_mac: [u8; 6],
    },
    /// `Started` is done; `mac` is the address of the container's `eth0`
    Started {
        mac: [u8; 6],
    },
    Error {
        message: String,
    },
}

/// The overlay the helper serves: the node's subnet (the containers'
/// addresses), its address (their gateway) and the whole overlay (the
/// route of containers that use another default).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Overlay {
    pub node_subnet: ipnet::Ipv4Net,
    pub node_ip: Ipv4Addr,
    pub overlay: ipnet::Ipv4Net,
    pub dns: DnsRouting,
}

/// The names of the veth pair of the container ID: `vethXXXXXXXX` and
/// `vethXXXXXXXXc` (its first 8 characters, which must be hexadecimal).
pub fn veth_names(id: &str) -> io::Result<(String, String)> {
    let short = id
        .get(..8)
        .filter(|s| id.len() <= 128 && id.bytes().all(|b| b.is_ascii_hexdigit()) && s.len() == 8);
    match short {
        Some(s) => Ok((format!("veth{s}"), format!("veth{s}c"))),
        None => Err(invalid(format!("invalid container id `{}`", printable(id)))),
    }
}

fn invalid(msg: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, msg)
}

fn printable(s: &str) -> String {
    s.chars().take(80).filter(|c| !c.is_control()).collect()
}

/// Send MSG (JSON) and FD, if any, on SOCK (a SOCK_SEQPACKET socket).
pub(crate) fn send(
    sock: BorrowedFd<'_>,
    msg: &impl Serialize,
    fd: Option<BorrowedFd<'_>>,
) -> io::Result<()> {
    use rustix::net::{sendmsg, SendAncillaryBuffer, SendAncillaryMessage, SendFlags};
    let body = serde_json::to_vec(msg).map_err(io::Error::other)?;
    let fds;
    let mut space = [std::mem::MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
    let mut control = SendAncillaryBuffer::new(&mut space);
    if let Some(fd) = fd {
        fds = [fd];
        control.push(SendAncillaryMessage::ScmRights(&fds));
    }
    sendmsg(
        sock,
        &[io::IoSlice::new(&body)],
        &mut control,
        SendFlags::NOSIGNAL,
    )?;
    Ok(())
}

/// A message from SOCK and the descriptor that came with it; None at the
/// end of the stream.
pub(crate) fn recv<T: for<'a> Deserialize<'a>>(
    sock: BorrowedFd<'_>,
) -> io::Result<Option<(T, Option<OwnedFd>)>> {
    let mut buf = vec![0u8; MAX_MESSAGE];
    // (one descriptor at most; more are an error)
    let r = velarx_sys::scm::recv(sock, &mut buf, 1, rustix::net::RecvFlags::empty())?;
    if r.bytes == 0 {
        return Ok(None);
    }
    let msg = serde_json::from_slice(&buf[..r.bytes]).map_err(|e| invalid(e.to_string()))?;
    Ok(Some((msg, r.fds.into_iter().next())))
}

/// What the helper made for a container.
struct Made {
    veth_host: String,
    veth_container: String,
}

/// The helper's side: answer the requests on SOCK until it closes.
pub fn serve(sock: OwnedFd, overlay: ipnet::Ipv4Net) -> io::Result<()> {
    let mut made: HashMap<String, Made> = HashMap::new();
    let mut node: Option<Overlay> = None;
    loop {
        let served = (|| {
            let Some((req, fd)) = recv::<Request>(sock.as_fd())? else {
                return Ok(false);
            };
            let mut packet = None;
            let reply = match handle(&req, fd, overlay, &mut node, &mut made, &mut packet) {
                Ok(r) => r,
                Err(e) => Reply::Error {
                    message: e.to_string(),
                },
            };
            send(sock.as_fd(), &reply, packet.as_ref().map(|f| f.as_fd()))?;
            Ok(true)
        })();
        if !matches!(served, Ok(true)) {
            // (the service is gone, or the socket failed: the routing of
            // the DNS goes with the helper)
            let removed = match node {
                Some(o) => Netlink::open()
                    .and_then(|mut nl| route(&mut nl, o.node_ip, o.dns, o.overlay, false)),
                None => Ok(()),
            };
            return served.and(removed);
        }
    }
}

/// Where the DNS of the containers is routed: the table where the node's
/// address is local (`Netlink::local_route`), and the priority of the rules
/// that send the packets to its port 53 there (before the main table's,
/// 32766).  Only the packets those rules choose are routed by the table.
/// Both are chosen by the settings, as the host may use the defaults.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DnsRouting {
    pub table: u32,
    pub rule_priority: u32,
}

impl DnsRouting {
    /// The table 53053 and the priority 5353: the defaults of the settings.
    pub const DEFAULT: DnsRouting = DnsRouting {
        table: 53053,
        rule_priority: 5353,
    };

    /// The tables 0, 253 (default), 254 (main), 255 (local) and `u32::MAX`
    /// are the kernel's; a rule of priority 0 is the local table's and one
    /// of 32766 or more the main table's.
    pub(crate) fn check(table: u32, rule_priority: u32) -> io::Result<DnsRouting> {
        if matches!(table, 0 | 253..=255) || table == u32::MAX {
            return Err(invalid(format!(
                "the routing table {table} is the kernel's"
            )));
        }
        if !(1..32766).contains(&rule_priority) {
            return Err(invalid(format!(
                "the rule priority {rule_priority} is not between 1 and 32765"
            )));
        }
        Ok(DnsRouting {
            table,
            rule_priority,
        })
    }
}

/// The DNS of NODE_IP routed to the host (`add`), or no longer: the packets
/// to its port 53, TCP and UDP, to the table of ROUTING, where NODE_IP is
/// local.  What an earlier helper that was killed left for NODE_IP goes
/// first.
fn dns_routing(
    nl: &mut Netlink,
    node_ip: Ipv4Addr,
    routing: DnsRouting,
    add: bool,
) -> io::Result<()> {
    let DnsRouting {
        table,
        rule_priority,
    } = routing;
    let lo = nl
        .link("lo")?
        .ok_or_else(|| io::Error::other("no loopback interface"))?;
    let protocols = [libc::IPPROTO_TCP as u8, libc::IPPROTO_UDP as u8];
    for proto in protocols {
        nl.port_rule(false, rule_priority, node_ip, proto, 53, table)?;
    }
    nl.local_route(false, table, node_ip, lo.index)?;
    if add {
        nl.local_route(true, table, node_ip, lo.index)?;
        for proto in protocols {
            nl.port_rule(true, rule_priority, node_ip, proto, 53, table)?;
        }
    }
    Ok(())
}

/// What the helper routes, or no longer (`add`): the DNS of NODE_IP
/// ([`dns_routing`]), and the whole overlay `all` to nowhere.  The routes of
/// the containers are longer: only the packets for a container of this node
/// are forwarded by the kernel, the ones for another node's go through the
/// service's tunnel and the kernel drops its copy, not sends it out of the
/// default route in the clear.
fn route(
    nl: &mut Netlink,
    node_ip: Ipv4Addr,
    dns: DnsRouting,
    all: ipnet::Ipv4Net,
    add: bool,
) -> io::Result<()> {
    dns_routing(nl, node_ip, dns, add)?;
    // (the one an earlier helper that was killed left goes first)
    nl.blackhole_route(false, all.network(), all.prefix_len())?;
    if add {
        nl.blackhole_route(true, all.network(), all.prefix_len())?;
    }
    Ok(())
}

fn handle(
    req: &Request,
    fd: Option<OwnedFd>,
    all: ipnet::Ipv4Net,
    node: &mut Option<Overlay>,
    made: &mut HashMap<String, Made>,
    packet: &mut Option<OwnedFd>,
) -> io::Result<Reply> {
    if let Request::Init {
        node_subnet,
        dns_table,
        dns_rule_priority,
    } = req
    {
        let dns = DnsRouting::check(*dns_table, *dns_rule_priority)?;
        let node_subnet: ipnet::Ipv4Net = node_subnet
            .parse()
            .map_err(|_| invalid(format!("invalid subnet `{}`", printable(node_subnet))))?;
        let node_subnet = &node_subnet;
        if node.is_some() {
            return Err(invalid("the node's subnet is set already".into()));
        }
        if node_subnet.prefix_len() < all.prefix_len()
            || node_subnet.prefix_len() > 30
            || !all.contains(&node_subnet.network())
        {
            return Err(invalid(format!(
                "the subnet {node_subnet} is not one of the overlay {all}"
            )));
        }
        let node_ip = node_subnet
            .hosts()
            .next()
            .ok_or_else(|| invalid("an empty subnet".into()))?;
        let mut nl = Netlink::open()?;
        if let Err(e) = route(&mut nl, node_ip, dns, all, true) {
            // (what was made of it goes)
            return Err(match route(&mut nl, node_ip, dns, all, false) {
                Ok(()) => e,
                Err(r) => io::Error::new(e.kind(), format!("{e}; removing it: {r}")),
            });
        }
        *node = Some(Overlay {
            node_subnet: *node_subnet,
            node_ip,
            overlay: all,
            dns,
        });
        return Ok(Reply::Ok);
    }
    let overlay = node.ok_or_else(|| invalid("no Init yet".into()))?;
    match req {
        Request::Init { .. } => Ok(Reply::Ok),
        Request::Forwarding => {
            std::fs::write("/proc/sys/net/ipv4/ip_forward", "1")?;
            Ok(Reply::Ok)
        }
        Request::Prepare { id, ip } => {
            let (veth_host, veth_container) = veth_names(id)?;
            if !overlay.node_subnet.contains(ip)
                || *ip == overlay.node_ip
                || *ip == overlay.node_subnet.network()
                || *ip == overlay.node_subnet.broadcast()
            {
                return Err(invalid(format!(
                    "the address {ip} is not one of a container"
                )));
            }
            let mut nl = Netlink::open()?;
            // A veth that is still ours for this id is a leftover (the runtime
            // asks for one operation at a time per container, and a
            // cleanup that failed or never came): it is replaced, not a
            // reason to refuse the container.
            // (the entry goes once its veth is gone: a failure keeps it for
            // the next try)
            if let Some(old) = made.get(id) {
                if let Some(l) = nl.link(&old.veth_host)? {
                    if l.kind == "veth" {
                        nl.link_del(l.index)?;
                    }
                }
                made.remove(id);
            }
            nl.veth_pair_add(&veth_host, &veth_container)?;
            let setup = (|| -> io::Result<(u32, [u8; 6], OwnedFd)> {
                // (what the container sends goes through a packet socket to
                // another node: its checksums are complete, not left to a
                // device that never comes)
                velarx_sys::packet::tx_checksum_off(&veth_container)?;
                let host = nl.link_index(&veth_host)?;
                let peer = nl.link_index(&veth_container)?;
                nl.link_up(host)?;
                nl.addr_add(peer, *ip, 32)?;
                nl.link_up(peer)?;
                nl.route_add(*ip, 32, None, host)?;
                std::fs::write(
                    format!("/proc/sys/net/ipv4/conf/{veth_host}/proxy_arp"),
                    "1",
                )?;
                // (the kernel forwards between the containers of the node:
                // a packet that comes in on this veth with the address of
                // another container is not the container's.  The strict
                // filter needs `conf/all/rp_filter` of 0 or 1: the larger of
                // the two applies, and 2 is loose)
                std::fs::write(
                    format!("/proc/sys/net/ipv4/conf/{veth_host}/rp_filter"),
                    "1",
                )?;
                let mac = nl
                    .link(&veth_host)?
                    .and_then(|l| l.mac)
                    .ok_or_else(|| io::Error::other("the veth has no address"))?;
                // (a failure from here on removes the pair like the ones above)
                let sock = packet_socket(host)?;
                Ok((host, mac, sock))
            })();
            let (_host, host_mac, sock) = match setup {
                Ok(r) => r,
                Err(e) => {
                    if let Ok(i) = nl.link_index(&veth_host) {
                        let _ = nl.link_del(i);
                    }
                    return Err(e);
                }
            };
            *packet = Some(sock);
            made.insert(
                id.clone(),
                Made {
                    veth_host: veth_host.clone(),
                    veth_container: veth_container.clone(),
                },
            );
            Ok(Reply::Prepared {
                veth_host,
                veth_container,
                host_mac,
            })
        }
        Request::Dns { id, tcp } => {
            let m = made
                .get(id)
                .ok_or_else(|| invalid("no veth for this container".into()))?;
            *packet = Some(dns_socket(&m.veth_host, overlay.node_ip, *tcp)?);
            Ok(Reply::Ok)
        }
        Request::Started { id, default_route } => {
            let m = made
                .get(id)
                .ok_or_else(|| invalid("no veth for this container".into()))?;
            let netns = fd.ok_or_else(|| invalid("the network namespace is not passed".into()))?;
            let mac = started(m, netns.as_fd(), *default_route, overlay)?;
            Ok(Reply::Started { mac })
        }
        Request::Cleanup { id } => {
            if let Some(m) = made.get(id) {
                let mut nl = Netlink::open()?;
                if let Some(l) = nl.link(&m.veth_host)? {
                    if l.kind == "veth" {
                        nl.link_del(l.index)?;
                    }
                }
                // (kept when the veth could not go: a later Prepare or
                // Cleanup tries again)
                made.remove(id);
            }
            Ok(Reply::Ok)
        }
    }
}

/// The DNS socket of the veth VETH: UDP, or TCP and listening, on port 53 of
/// ADDRESS (routed to the host by `dns_routing`) and only on that interface.
fn dns_socket(veth: &str, address: Ipv4Addr, tcp: bool) -> io::Result<OwnedFd> {
    use rustix::net::{AddressFamily, SocketAddrV4, SocketFlags, SocketType};
    let kind = if tcp {
        SocketType::STREAM
    } else {
        SocketType::DGRAM
    };
    let sock = rustix::net::socket_with(AddressFamily::INET, kind, SocketFlags::CLOEXEC, None)?;
    velarx_sys::packet::bind_to_device(sock.as_fd(), veth)?;
    velarx_sys::packet::set_transparent(sock.as_fd())?;
    if tcp {
        // (a connection of an earlier run in TIME_WAIT is no reason to fail)
        rustix::net::sockopt::set_socket_reuseaddr(&sock, true)?;
    }
    rustix::net::bind(&sock, &SocketAddrV4::new(address, 53))
        .map_err(|e| io::Error::new(e.kind(), format!("bind {address}:53: {e}")))?;
    if tcp {
        rustix::net::listen(&sock, DNS_BACKLOG)?;
    }
    Ok(sock)
}

/// The connections waiting to be accepted on a DNS listener.
const DNS_BACKLOG: i32 = 16;

/// A packet socket for every protocol, bound to the link INDEX.
fn packet_socket(index: u32) -> io::Result<OwnedFd> {
    velarx_sys::packet::bound_socket(index)
}

/// The routes in the network namespace NETNS, once the runtime moved the
/// veth of M there as `eth0`: only when that `eth0` is that veth (joining
/// it fails for a descriptor that is not a network namespace).  The
/// address of that `eth0`.
fn started(
    m: &Made,
    netns: BorrowedFd<'_>,
    default_route: bool,
    overlay: Overlay,
) -> io::Result<[u8; 6]> {
    let host = Netlink::open()?
        .link(&m.veth_host)?
        .filter(|l| l.kind == "veth")
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "the veth is gone"))?;
    use std::os::unix::fs::MetadataExt;
    // (stat is no access Landlock controls)
    let own = std::fs::metadata("/proc/self/ns/net")?;
    let own = (own.dev(), own.ino());
    // The two ends name each other: the indexes are those of the host's
    // namespace for the host side, of the container's for eth0, and two
    // links of the host's namespace never share one.
    let (peer_index, host_index, node_ip) = (host.link, host.index, overlay.node_ip);
    let veth_container = m.veth_container.clone();
    velarx_netkernel::bridge::in_netns(netns, move || {
        let here = std::fs::metadata("/proc/thread-self/ns/net")?;
        if (here.dev(), here.ino()) == own {
            return Err(invalid("the namespace of the process is the host's".into()));
        }
        let mut nl = Netlink::open()?;
        let eth0 = nl
            .link("eth0")?
            .filter(|l| l.kind == "veth" && l.index == peer_index && l.link == host_index)
            .ok_or_else(|| {
                invalid(format!(
                    "eth0 of the namespace is not the veth {veth_container}"
                ))
            })?;
        if let Some(lo) = nl.link("lo")? {
            nl.link_up(lo.index)?;
        }
        nl.link_up(eth0.index)?;
        let (dst, prefix) = if default_route {
            (Ipv4Addr::UNSPECIFIED, 0)
        } else {
            (overlay.overlay.network(), overlay.overlay.prefix_len())
        };
        nl.route_add(dst, prefix, Some(node_ip), eth0.index)?;
        for f in ["eth0", "all"] {
            std::fs::write(format!("/proc/sys/net/ipv4/conf/{f}/rp_filter"), "0")?;
        }
        eth0.mac
            .ok_or_else(|| io::Error::other("eth0 of the namespace has no address"))
    })
}

/// The service's side: requests to the helper, one at a time.
pub struct Client {
    sock: std::sync::Mutex<OwnedFd>,
}

impl Client {
    pub fn new(sock: OwnedFd) -> Self {
        Self {
            sock: std::sync::Mutex::new(sock),
        }
    }

    /// The answer to REQ and the descriptor that came with it.
    pub fn call(&self, req: &Request) -> io::Result<(Reply, Option<OwnedFd>)> {
        self.call_with(req, None)
    }

    /// The answer to REQ, sent with the descriptor FD.
    pub fn call_with(
        &self,
        req: &Request,
        fd: Option<BorrowedFd<'_>>,
    ) -> io::Result<(Reply, Option<OwnedFd>)> {
        let sock = self.sock.lock().unwrap_or_else(|e| e.into_inner());
        send(sock.as_fd(), req, fd)?;
        match recv::<Reply>(sock.as_fd())? {
            Some((Reply::Error { message }, _)) => Err(io::Error::other(format!(
                "overlay helper: {}",
                printable(&message)
            ))),
            Some(r) => Ok(r),
            None => Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "the overlay helper is gone",
            )),
        }
    }
}

/// A connected pair of SOCK_SEQPACKET sockets: the service's and the
/// helper's.
pub fn socketpair() -> io::Result<(OwnedFd, OwnedFd)> {
    use rustix::net::{AddressFamily, SocketFlags, SocketType};
    Ok(rustix::net::socketpair(
        AddressFamily::UNIX,
        SocketType::SEQPACKET,
        SocketFlags::CLOEXEC,
        None,
    )?)
}

/// The capabilities the helper keeps: CAP_NET_BIND_SERVICE (port 53),
/// CAP_NET_ADMIN, CAP_NET_RAW, CAP_SYS_ADMIN (setns into the namespace it
/// is given).
const KEPT_CAPS: [u32; 4] = [10, 12, 13, 21];

/// A mount namespace of the process's own where every mount is read-only
/// but `/proc/sys/net` (the sysctls the helper writes).
fn read_only_but_sysctls() -> Result<(), String> {
    use rustix::mount::{mount_bind, mount_change, MountPropagationFlags};
    use velarx_sys::mount::{setattr_path, setattr_path_recursive, MountAttr};
    const MOUNT_ATTR_RDONLY: u64 = 1;
    velarx_sys::namespace::unshare(rustix::thread::UnshareFlags::NEWNS)
        .map_err(|e| format!("unshare the mounts: {e}"))?;
    mount_change(
        "/",
        MountPropagationFlags::PRIVATE | MountPropagationFlags::REC,
    )
    .map_err(|e| format!("make the mounts private: {e}"))?;
    mount_bind("/proc/sys/net", "/proc/sys/net").map_err(|e| format!("bind /proc/sys/net: {e}"))?;
    let readonly = MountAttr {
        attr_set: MOUNT_ATTR_RDONLY,
        ..MountAttr::default()
    };
    setattr_path_recursive(c"/", &readonly)
        .map_err(|e| format!("make the mounts read-only: {e}"))?;
    let writable = MountAttr {
        attr_clr: MOUNT_ATTR_RDONLY,
        ..MountAttr::default()
    };
    setattr_path(c"/proc/sys/net", &writable)
        .map_err(|e| format!("make /proc/sys/net writable: {e}"))?;
    Ok(())
}

/// Confine the helper before it reads a request (before any thread).
pub fn confine() -> Result<(), String> {
    use rustix::thread::{CapabilitySet, CapabilitySets};
    rustix::thread::set_no_new_privs(true).map_err(|e| format!("PR_SET_NO_NEW_PRIVS: {e}"))?;
    rustix::process::set_dumpable_behavior(rustix::process::DumpableBehavior::NotDumpable)
        .map_err(|e| format!("PR_SET_DUMPABLE: {e}"))?;
    velarx_sys::caps::drop_bounding_except(|c| KEPT_CAPS.contains(&c))
        .map_err(|e| format!("capabilities of the bounding set: {e}"))?;
    let kept = CapabilitySet::from_bits_retain(KEPT_CAPS.iter().fold(0u64, |m, c| m | (1 << c)));
    rustix::thread::set_capabilities(
        None,
        CapabilitySets {
            effective: kept,
            permitted: kept,
            inheritable: CapabilitySet::empty(),
        },
    )
    .map_err(|e| format!("capset: {e}"))?;
    // The files: no Landlock, which would also forbid the namespaces of
    // the containers (they are processes outside of its domain); a mount
    // namespace of its own instead where everything is read-only but
    // /proc/sys/net.
    read_only_but_sysctls()?;
    allow::apply(&allowed(std::process::id())?.programs()?)
}

/// What the helper makes: the runtime, the files of `/proc/sys/net` it
/// writes and the namespace files it reads (Landlock cannot be used, the
/// mount namespace makes the rest read-only), netlink and packet sockets
/// and the IPv4 UDP and TCP sockets of the DNS only (it binds them, and does
/// not use them), `setns` into a network namespace (the containers') and
/// the query of the index of a link.
fn allowed(pid: u32) -> Result<Allow, String> {
    use velarx_sys::allow::{all_are, is, one_of};
    let allow = Allow::runtime(pid)?
        .calls(&[
            libc::SYS_openat,
            libc::SYS_readlinkat,
            libc::SYS_faccessat,
            libc::SYS_faccessat2,
            libc::SYS_getdents64,
            libc::SYS_bind,
            libc::SYS_listen,
            libc::SYS_statfs,
            libc::SYS_fstatfs,
        ])
        .when(
            libc::SYS_socket,
            [
                one_of(0, &[libc::AF_NETLINK as u64, libc::AF_PACKET as u64]),
                [libc::SOCK_DGRAM, libc::SOCK_STREAM]
                    .iter()
                    .map(|ty| {
                        all_are(&[
                            (0, libc::AF_INET as u64),
                            (1, (ty | libc::SOCK_CLOEXEC) as u64),
                        ])
                    })
                    .collect(),
            ]
            .concat(),
        )
        .when(libc::SYS_setns, vec![is(1, libc::CLONE_NEWNET as u64)])
        .plus(
            libc::SYS_ioctl,
            one_of(1, &[libc::SIOCGIFINDEX, libc::SIOCETHTOOL]),
        );
    // (the calls that only x86-64 has)
    #[cfg(target_arch = "x86_64")]
    let allow = allow.calls(&[libc::SYS_open, libc::SYS_readlink, libc::SYS_access]);
    Ok(allow)
}

/// The arguments the helper is started with: the overlay.
pub fn args(overlay: &ipnet::Ipv4Net) -> [String; 1] {
    [overlay.to_string()]
}

/// The helper's entry point: ARGS as `args` writes them, the socket on
/// the standard input.  Call it first thing in main (no thread yet).
pub fn main(args: &[String]) -> io::Result<()> {
    let [all] = args else {
        return Err(invalid("arguments: OVERLAY".into()));
    };
    let overlay: ipnet::Ipv4Net = all
        .parse()
        .map_err(|_| invalid(format!("invalid overlay `{}`", printable(all))))?;
    // (the standard input is the socket the service gave)
    let sock = rustix::io::fcntl_dupfd_cloexec(rustix::stdio::stdin(), 3)?;
    confine().map_err(io::Error::other)?;
    serve(sock, overlay)
}

/// Start the helper from EXE with SUBCOMMAND (`EXE SUBCOMMAND ARGS...`,
/// the socket on its standard input): the client and the process.
pub fn spawn(
    exe: &std::path::Path,
    subcommand: &[&str],
    overlay: &ipnet::Ipv4Net,
) -> io::Result<(Client, std::process::Child)> {
    let (mine, theirs) = socketpair()?;
    let child = std::process::Command::new(exe)
        .args(subcommand)
        .args(args(overlay))
        .env_clear()
        .stdin(std::process::Stdio::from(theirs))
        .stdout(std::process::Stdio::null())
        .spawn()?;
    Ok((Client::new(mine), child))
}

#[cfg(test)]
mod tests {
    use super::*;
    use velarx_sys::allow::testing::{check, check_runtime, verdicts, ALLOW, EPERM};

    /// A message that came with more descriptors than it may have is an
    /// error, not a message with the descriptors the kernel kept.
    #[test]
    fn a_message_with_too_many_descriptors_is_refused() {
        use rustix::net::{sendmsg, SendAncillaryBuffer, SendAncillaryMessage, SendFlags};
        use std::os::fd::AsFd;
        let (a, b) = std::os::unix::net::UnixStream::pair().unwrap();
        let null = std::fs::File::open("/dev/null").unwrap();
        let fds = [null.as_fd(), null.as_fd()];
        let mut space = [std::mem::MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(2))];
        let mut control = SendAncillaryBuffer::new(&mut space);
        control.push(SendAncillaryMessage::ScmRights(&fds));
        sendmsg(
            &a,
            &[io::IoSlice::new(b"{}")],
            &mut control,
            SendFlags::NOSIGNAL,
        )
        .unwrap();
        assert!(recv::<serde_json::Value>(b.as_fd()).is_err());
    }

    /// The table and the priority of the DNS routing are the host's to
    /// choose, but not the kernel's.
    #[test]
    fn the_dns_routing_refuses_the_kernels_tables_and_priorities() {
        let d = DnsRouting::DEFAULT;
        assert_eq!(DnsRouting::check(d.table, d.rule_priority).unwrap(), d);
        assert_eq!(DnsRouting::check(7, 100).unwrap().table, 7);
        for table in [0, 253, 254, 255, u32::MAX] {
            assert!(DnsRouting::check(table, 100).is_err(), "table {table}");
        }
        for priority in [0, 32766, 32767, u32::MAX] {
            assert!(
                DnsRouting::check(7, priority).is_err(),
                "priority {priority}"
            );
        }
    }

    /// The program of the helper, evaluated: netlink and packet sockets, the
    /// UDP and TCP sockets of the DNS, the namespace of a container and
    /// nothing else of the kernel.
    #[test]
    fn the_filters_allow_the_helper_and_refuse_the_rest() {
        let verdict = verdicts(allowed(1).unwrap());
        check_runtime(&verdict);
        let af = |d: i32| [d as u64, 0, 0, 0, 0, 0];
        let inet = |ty: i32| {
            [
                libc::AF_INET as u64,
                (ty | libc::SOCK_CLOEXEC) as u64,
                0,
                0,
                0,
                0,
            ]
        };
        let ioctl = |c: u64| [0, c, 0, 0, 0, 0];
        check(
            &verdict,
            &[
                (libc::SYS_socket, af(libc::AF_NETLINK), ALLOW),
                (libc::SYS_socket, af(libc::AF_PACKET), ALLOW),
                (libc::SYS_socket, inet(libc::SOCK_DGRAM), ALLOW),
                (libc::SYS_socket, inet(libc::SOCK_STREAM), ALLOW),
                (libc::SYS_socket, inet(libc::SOCK_RAW), EPERM),
                (libc::SYS_socket, af(libc::AF_INET), EPERM),
                (libc::SYS_socket, af(libc::AF_INET6), EPERM),
                (libc::SYS_listen, [0; 6], ALLOW),
                (libc::SYS_socket, af(libc::AF_UNIX), EPERM),
                (libc::SYS_bind, [0; 6], ALLOW),
                (
                    libc::SYS_setns,
                    [0, libc::CLONE_NEWNET as u64, 0, 0, 0, 0],
                    ALLOW,
                ),
                (
                    libc::SYS_setns,
                    [0, libc::CLONE_NEWNS as u64, 0, 0, 0, 0],
                    EPERM,
                ),
                (libc::SYS_ioctl, ioctl(libc::SIOCGIFINDEX), ALLOW),
                (libc::SYS_ioctl, ioctl(libc::SIOCETHTOOL), ALLOW),
                (libc::SYS_ioctl, ioctl(libc::SIOCSIFADDR), EPERM),
                (libc::SYS_execve, [0; 6], EPERM),
                (libc::SYS_unshare, [0; 6], EPERM),
                (libc::SYS_mount, [0; 6], EPERM),
                (libc::SYS_connect, [0; 6], EPERM),
                (libc::SYS_memfd_create, [0; 6], EPERM),
            ],
        );
    }

    #[test]
    fn names_come_from_hexadecimal_ids_only() {
        assert_eq!(
            veth_names("0123abcdef").unwrap(),
            ("veth0123abcd".to_string(), "veth0123abcdc".to_string())
        );
        for bad in ["", "0123abc", "../../etc", "0123abcz00", "0123 bcd00"] {
            assert!(veth_names(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn requests_and_replies_cross_with_a_descriptor() {
        let (a, b) = socketpair().unwrap();
        let req = Request::Started {
            id: "0123abcd".into(),
            default_route: true,
        };
        send(a.as_fd(), &req, None).unwrap();
        let (got, fd) = recv::<Request>(b.as_fd()).unwrap().unwrap();
        assert_eq!((got, fd.is_none()), (req, true));
        let null = std::fs::File::open("/dev/null").unwrap();
        send(b.as_fd(), &Reply::Ok, Some(null.as_fd())).unwrap();
        let (got, fd) = recv::<Reply>(a.as_fd()).unwrap().unwrap();
        assert_eq!((got, fd.is_some()), (Reply::Ok, true));
        drop(b);
        assert!(recv::<Reply>(a.as_fd()).unwrap().is_none());
    }
}
