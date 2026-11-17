// SPDX-License-Identifier: Apache-2.0
//! A minimal rtnetlink client: the links, IPv4 addresses and routes of the
//! network namespace of the calling thread.
//!
//! The socket belongs to the namespace of the thread that opens it: open it
//! after joining the namespace to configure.

use rustix::io::Errno;
use rustix::net::netlink::SocketAddrNetlink;
use rustix::net::{
    bind, recv, sendto, socket_with, AddressFamily, RecvFlags, SendFlags, SocketFlags, SocketType,
};
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::fd::{BorrowedFd, OwnedFd};
use velarx_wire::addr::Route;

pub(super) const NLMSG_HDRLEN: usize = 16;
pub(super) const NLMSG_ERROR: u16 = 2;
pub(super) const NLMSG_DONE: u16 = 3;

pub(super) const NLM_F_REQUEST: u16 = 0x1;
pub(super) const NLM_F_ACK: u16 = 0x4;
pub(super) const NLM_F_EXCL: u16 = 0x200;
pub(super) const NLM_F_CREATE: u16 = 0x400;
pub(super) const NLM_F_DUMP: u16 = 0x300;
const NLM_F_DUMP_INTR: u16 = 0x10;
/// How many times a dump that changed meanwhile is made again
const DUMP_TRIES: usize = 5;

const RTM_NEWLINK: u16 = 16;
/// The multicast group of the changes of the links.
const RTMGRP_LINK: u32 = 1;
const RTM_DELLINK: u16 = 17;
const RTM_GETLINK: u16 = 18;
const RTM_NEWADDR: u16 = 20;
const RTM_NEWROUTE: u16 = 24;
const RTM_DELROUTE: u16 = 25;
const RTM_NEWRULE: u16 = 32;
const RTM_DELRULE: u16 = 33;
const RTM_GETADDR: u16 = 22;
const RTM_GETROUTE: u16 = 26;

const IFLA_ADDRESS: u16 = 1;
const IFLA_IFNAME: u16 = 3;
const IFLA_MTU: u16 = 4;
const IFLA_MASTER: u16 = 10;
const IFLA_LINK: u16 = 5;
const IFLA_LINKINFO: u16 = 18;
const IFLA_NET_NS_FD: u16 = 28;
const IFLA_IFALIAS: u16 = 20;
const IFLA_INFO_KIND: u16 = 1;
const IFLA_INFO_DATA: u16 = 2;
const VETH_INFO_PEER: u16 = 1;

const IFA_ADDRESS: u16 = 1;
const IFA_LOCAL: u16 = 2;
const IFA_BROADCAST: u16 = 4;

const RTA_DST: u16 = 1;
const RTA_OIF: u16 = 4;
const RTA_TABLE: u16 = 15;
const RTA_GATEWAY: u16 = 5;

const FRA_DST: u16 = 1;
const FRA_PRIORITY: u16 = 6;
const FRA_TABLE: u16 = 15;
const FRA_IP_PROTO: u16 = 22;
const FRA_DPORT_RANGE: u16 = 24;
/// The action of a rule: the lookup of its table.
const FR_ACT_TO_TBL: u8 = 1;

const AF_UNSPEC: u8 = 0;
const AF_INET: u8 = 2;
const AF_INET6: u8 = 10;
/// No duplicate address detection: the address is usable at once.
const IFA_F_NODAD: u8 = 0x02;
const IFF_UP: u32 = 1;
const RT_TABLE_MAIN: u8 = 254;
const RTPROT_BOOT: u8 = 3;
const RT_SCOPE_UNIVERSE: u8 = 0;
const RTN_UNICAST: u8 = 1;
const RTN_LOCAL: u8 = 2;
const RTN_BLACKHOLE: u8 = 6;
const RT_SCOPE_HOST: u8 = 254;

/// The size of `struct ifinfomsg`, `struct ifaddrmsg`, `struct rtmsg`.
const IFINFOMSG_LEN: usize = 16;
const IFADDRMSG_LEN: usize = 8;
const RTMSG_LEN: usize = 12;
/// The size of `struct fib_rule_hdr`.
const FIB_RULE_HDR_LEN: usize = 12;

const BUF_SIZE: usize = 32 * 1024;
/// Request messages are small; a bigger one is a bug.
const MAX_REQUEST: usize = 4096;

pub fn align(n: usize) -> usize {
    (n + 3) & !3
}

/// A request being built.
#[derive(Clone)]
pub(super) struct Msg {
    buf: Vec<u8>,
}

impl Msg {
    pub(super) fn new(ty: u16, flags: u16, header: &[u8]) -> Self {
        let mut buf = vec![0u8; NLMSG_HDRLEN];
        buf[4..6].copy_from_slice(&ty.to_ne_bytes());
        buf[6..8].copy_from_slice(&(NLM_F_REQUEST | flags).to_ne_bytes());
        buf.extend_from_slice(header);
        buf.resize(align(buf.len()), 0);
        Msg { buf }
    }

    pub(super) fn attr(&mut self, ty: u16, data: &[u8]) -> &mut Self {
        let len = 4 + data.len();
        self.buf.extend_from_slice(&(len as u16).to_ne_bytes());
        self.buf.extend_from_slice(&ty.to_ne_bytes());
        self.buf.extend_from_slice(data);
        self.buf.resize(align(self.buf.len()), 0);
        self
    }

    pub(super) fn attr_u32(&mut self, ty: u16, v: u32) -> &mut Self {
        self.attr(ty, &v.to_ne_bytes())
    }

    pub(super) fn attr_str(&mut self, ty: u16, s: &str) -> &mut Self {
        let mut data = s.as_bytes().to_vec();
        data.push(0);
        self.attr(ty, &data)
    }

    /// Start a nested attribute; `end` sets its length.
    pub(super) fn begin(&mut self, ty: u16) -> usize {
        let at = self.buf.len();
        self.attr(ty, &[]);
        at
    }

    pub(super) fn end(&mut self, at: usize) {
        let len = (self.buf.len() - at) as u16;
        self.buf[at..at + 2].copy_from_slice(&len.to_ne_bytes());
    }

    pub(super) fn len(&self) -> usize {
        self.buf.len()
    }

    pub(super) fn finish(mut self, seq: u32) -> Vec<u8> {
        let len = self.buf.len() as u32;
        self.buf[0..4].copy_from_slice(&len.to_ne_bytes());
        self.buf[8..12].copy_from_slice(&seq.to_ne_bytes());
        self.buf
    }
}

fn ifinfomsg(index: i32, flags: u32, change: u32) -> [u8; IFINFOMSG_LEN] {
    let mut h = [0u8; IFINFOMSG_LEN];
    h[0] = AF_UNSPEC;
    h[4..8].copy_from_slice(&index.to_ne_bytes());
    h[8..12].copy_from_slice(&flags.to_ne_bytes());
    h[12..16].copy_from_slice(&change.to_ne_bytes());
    h
}

pub fn read_u16(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_ne_bytes(b.get(at..at + 2)?.try_into().ok()?))
}

pub fn read_u32(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_ne_bytes(b.get(at..at + 4)?.try_into().ok()?))
}

/// The messages of a reply buffer: (type, seq, payload).
pub fn messages(buf: &[u8]) -> impl Iterator<Item = (u16, u32, &[u8])> {
    let mut off = 0;
    std::iter::from_fn(move || {
        let len = read_u32(buf, off)? as usize;
        if len < NLMSG_HDRLEN || off + len > buf.len() {
            return None;
        }
        let ty = read_u16(buf, off + 4)?;
        let seq = read_u32(buf, off + 8)?;
        let payload = &buf[off + NLMSG_HDRLEN..off + len];
        off += align(len);
        Some((ty, seq, payload))
    })
}

/// The attributes after a fixed header: (type, data).
pub fn attributes(buf: &[u8]) -> impl Iterator<Item = (u16, &[u8])> {
    let mut off = 0;
    std::iter::from_fn(move || {
        let len = read_u16(buf, off)? as usize;
        if len < 4 || off + len > buf.len() {
            return None;
        }
        let ty = read_u16(buf, off + 2)? & 0x3fff;
        let data = &buf[off + 4..off + len];
        off += align(len);
        Some((ty, data))
    })
}

/// A network link.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Link {
    pub index: u32,
    pub name: String,
    /// `bridge`, `veth`, `dummy`...; empty for a physical device.
    pub kind: String,
    pub alias: String,
    /// The bridge it is enslaved to, 0 for none.
    pub master: u32,
    /// `IFLA_LINK`: of a veth, the index of its peer (in the peer's
    /// namespace); 0 when there is none.
    pub link: u32,
    /// The hardware address, when it is an Ethernet one.
    pub mac: Option<[u8; 6]>,
}

/// A NUL terminated string attribute.
pub fn cstr(d: &[u8]) -> String {
    let end = d.iter().position(|c| *c == 0).unwrap_or(d.len());
    String::from_utf8_lossy(&d[..end]).into_owned()
}

/// An rtnetlink socket of the namespace of the thread that opened it.
pub struct Netlink {
    fd: OwnedFd,
    seq: u32,
}

impl Netlink {
    pub fn open() -> io::Result<Self> {
        // NETLINK_ROUTE is protocol 0.
        Self::open_protocol(None)
    }

    pub(super) fn open_protocol(protocol: Option<rustix::net::Protocol>) -> io::Result<Self> {
        let fd = socket_with(
            AddressFamily::NETLINK,
            SocketType::RAW,
            SocketFlags::CLOEXEC,
            protocol,
        )?;
        bind(&fd, &SocketAddrNetlink::new(0, 0))?;
        Ok(Self {
            fd,
            seq: std::process::id(),
        })
    }

    /// Send DATA, messages that are complete.
    pub(super) fn send_raw(&mut self, data: &[u8]) -> io::Result<()> {
        sendto(
            &self.fd,
            data,
            SendFlags::empty(),
            &SocketAddrNetlink::new(0, 0),
        )?;
        Ok(())
    }

    /// Reserve N sequence numbers; the first.
    pub(super) fn take_seq(&mut self, n: u32) -> u32 {
        let first = self.seq.wrapping_add(1);
        self.seq = self.seq.wrapping_add(n);
        first
    }

    pub(super) fn send(&mut self, msg: Msg) -> io::Result<u32> {
        self.seq = self.seq.wrapping_add(1);
        let data = msg.finish(self.seq);
        if data.len() > MAX_REQUEST {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "netlink request too big",
            ));
        }
        sendto(
            &self.fd,
            &data,
            SendFlags::empty(),
            &SocketAddrNetlink::new(0, 0),
        )?;
        Ok(self.seq)
    }

    pub(super) fn recv_into(&self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            match recv(&self.fd, &mut *buf, RecvFlags::empty()) {
                Ok((n, _)) => return Ok(n),
                Err(Errno::INTR) => continue,
                Err(e) => return Err(e.into()),
            }
        }
    }

    /// Send the request and wait for its acknowledgment: the error of the
    /// kernel, 0 for none.
    fn request(&mut self, msg: Msg) -> io::Result<i32> {
        let seq = self.send(msg)?;
        let mut buf = vec![0u8; BUF_SIZE];
        loop {
            let n = self.recv_into(&mut buf)?;
            for (ty, s, payload) in messages(&buf[..n]) {
                if s != seq || ty != NLMSG_ERROR {
                    continue;
                }
                let err = read_u32(payload, 0).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "short netlink error")
                })? as i32;
                return Ok(-err);
            }
        }
    }

    fn checked(&mut self, msg: Msg, ignore_exists: bool, what: &str) -> io::Result<()> {
        match self.request(msg)? {
            0 => Ok(()),
            e if ignore_exists && e == Errno::EXIST.raw_os_error() => Ok(()),
            e => {
                let err = io::Error::from_raw_os_error(e);
                Err(io::Error::new(err.kind(), format!("{what}: {err}")))
            }
        }
    }

    /// The index of the link NAME, 0 if there is none.
    pub fn link_index(&self, name: &str) -> io::Result<u32> {
        if name.is_empty() || name.len() >= 16 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid interface name `{name}`"),
            ));
        }
        // (the kernel answers SIOCGIFINDEX on any socket: no IPv4 socket,
        // which the confined overlay helper may not have)
        match rustix::net::netdevice::name_to_index(&self.fd, name) {
            Ok(i) => Ok(i),
            Err(Errno::NODEV) | Err(Errno::NXIO) => Ok(0),
            Err(e) => Err(e.into()),
        }
    }

    /// Create the bridge NAME with the alias ALIAS (the mark of who owns
    /// it).  EEXIST when a link has the name.  MTU 0: the default.
    pub fn bridge_add(&mut self, name: &str, mtu: u32, alias: &str) -> io::Result<()> {
        let mut m = Msg::new(
            RTM_NEWLINK,
            NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
            &ifinfomsg(0, 0, 0),
        );
        m.attr_str(IFLA_IFNAME, name);
        if mtu > 0 {
            m.attr_u32(IFLA_MTU, mtu);
        }
        let info = m.begin(IFLA_LINKINFO);
        m.attr_str(IFLA_INFO_KIND, "bridge");
        m.end(info);
        self.checked(m, false, &format!("create the bridge `{name}`"))?;
        let index = self.link_index(name)?;
        if let Err(e) = self.link_set_alias(index, alias) {
            let _ = self.link_del(index);
            return Err(e);
        }
        Ok(())
    }

    /// A veth pair: the host end (named by the kernel, `veth%d`) enslaved to
    /// the bridge MASTER and up, the peer PEER_NAME created in the network
    /// namespace NETNS with the address MAC (else the kernel picks one).
    pub fn veth_add(
        &mut self,
        master: u32,
        peer_name: &str,
        mac: Option<[u8; 6]>,
        mtu: u32,
        netns: BorrowedFd<'_>,
    ) -> io::Result<()> {
        let mut m = Msg::new(
            RTM_NEWLINK,
            NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
            &ifinfomsg(0, IFF_UP, IFF_UP),
        );
        m.attr_str(IFLA_IFNAME, "veth%d");
        if mtu > 0 {
            m.attr_u32(IFLA_MTU, mtu);
        }
        m.attr_u32(IFLA_MASTER, master);
        let info = m.begin(IFLA_LINKINFO);
        m.attr_str(IFLA_INFO_KIND, "veth");
        let data = m.begin(IFLA_INFO_DATA);
        let peer = m.begin(VETH_INFO_PEER);
        m.buf.extend_from_slice(&ifinfomsg(0, 0, 0));
        m.attr_str(IFLA_IFNAME, peer_name);
        if let Some(mac) = mac {
            m.attr(IFLA_ADDRESS, &mac);
        }
        if mtu > 0 {
            m.attr_u32(IFLA_MTU, mtu);
        }
        let raw = std::os::fd::AsRawFd::as_raw_fd(&netns);
        m.attr_u32(IFLA_NET_NS_FD, raw as u32);
        m.end(peer);
        m.end(data);
        m.end(info);
        self.checked(m, false, &format!("create the veth pair for `{peer_name}`"))
    }

    /// A macvlan NAME on the link PARENT, of MODE (`IFLA_MACVLAN_MODE`:
    /// private 1, vepa 2, bridge 4, passthru 8), created in the network
    /// namespace NETNS with the address MAC (else the kernel picks one).
    pub fn macvlan_add(
        &mut self,
        parent: u32,
        name: &str,
        mode: u32,
        mac: Option<[u8; 6]>,
        mtu: u32,
        netns: BorrowedFd<'_>,
    ) -> io::Result<()> {
        const IFLA_LINK: u16 = 5;
        const IFLA_MACVLAN_MODE: u16 = 1;
        let mut m = Msg::new(
            RTM_NEWLINK,
            NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
            &ifinfomsg(0, 0, 0),
        );
        m.attr_str(IFLA_IFNAME, name);
        m.attr_u32(IFLA_LINK, parent);
        if let Some(mac) = mac {
            m.attr(IFLA_ADDRESS, &mac);
        }
        if mtu > 0 {
            m.attr_u32(IFLA_MTU, mtu);
        }
        let raw = std::os::fd::AsRawFd::as_raw_fd(&netns);
        m.attr_u32(IFLA_NET_NS_FD, raw as u32);
        let info = m.begin(IFLA_LINKINFO);
        m.attr_str(IFLA_INFO_KIND, "macvlan");
        let data = m.begin(IFLA_INFO_DATA);
        m.attr_u32(IFLA_MACVLAN_MODE, mode);
        m.end(data);
        m.end(info);
        self.checked(m, false, &format!("create the macvlan `{name}`"))
    }

    /// A veth pair NAME and PEER, both here, down.
    pub fn veth_pair_add(&mut self, name: &str, peer: &str) -> io::Result<()> {
        let mut m = Msg::new(
            RTM_NEWLINK,
            NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
            &ifinfomsg(0, 0, 0),
        );
        m.attr_str(IFLA_IFNAME, name);
        let info = m.begin(IFLA_LINKINFO);
        m.attr_str(IFLA_INFO_KIND, "veth");
        let data = m.begin(IFLA_INFO_DATA);
        let p = m.begin(VETH_INFO_PEER);
        m.buf.extend_from_slice(&ifinfomsg(0, 0, 0));
        m.attr_str(IFLA_IFNAME, peer);
        m.end(p);
        m.end(data);
        m.end(info);
        self.checked(m, false, &format!("create the veth pair `{name}`"))
    }

    /// A route to DST/PREFIX on the link INDEX, through GATEWAY if any
    /// (`onlink`: the gateway is on the link whatever its address); no
    /// error if it is there.
    pub fn route_add(
        &mut self,
        dst: Ipv4Addr,
        prefix: u8,
        gateway: Option<Ipv4Addr>,
        index: u32,
    ) -> io::Result<()> {
        const RT_SCOPE_LINK: u8 = 253;
        const RTNH_F_ONLINK: u32 = 4;
        let mut h = [0u8; RTMSG_LEN];
        h[0] = AF_INET;
        h[1] = prefix;
        h[4] = RT_TABLE_MAIN;
        h[5] = RTPROT_BOOT;
        h[6] = if gateway.is_some() {
            RT_SCOPE_UNIVERSE
        } else {
            RT_SCOPE_LINK
        };
        h[7] = RTN_UNICAST;
        if gateway.is_some() {
            h[8..12].copy_from_slice(&RTNH_F_ONLINK.to_ne_bytes());
        }
        let mut m = Msg::new(RTM_NEWROUTE, NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL, &h);
        if prefix > 0 {
            m.attr(RTA_DST, &dst.octets());
        }
        if let Some(gw) = gateway {
            m.attr(RTA_GATEWAY, &gw.octets());
        }
        m.attr_u32(RTA_OIF, index);
        self.checked(m, true, &format!("add the route {dst}/{prefix}"))
    }

    /// The link of the IPv4 default route of the main table, 0 if none.
    pub fn default_route_link(&mut self) -> io::Result<u32> {
        let mut h = [0u8; RTMSG_LEN];
        h[0] = AF_INET;
        let mut out = 0;
        self.dump(Msg::new(RTM_GETROUTE, NLM_F_DUMP, &h), RTM_NEWROUTE, |p| {
            if out != 0 || p.len() < RTMSG_LEN || p[0] != AF_INET || p[1] != 0 {
                return;
            }
            let mut table = u32::from(p[4]);
            let mut oif = 0;
            for (t, d) in attributes(&p[RTMSG_LEN..]) {
                match t {
                    RTA_OIF => oif = read_u32(d, 0).unwrap_or(0),
                    RTA_TABLE => table = read_u32(d, 0).unwrap_or(table),
                    _ => {}
                }
            }
            if table == u32::from(RT_TABLE_MAIN) {
                out = oif;
            }
        })?;
        Ok(out)
    }

    /// The gateway of the IPv4 default route of the main table.
    pub fn default_gateway(&mut self) -> io::Result<Option<Ipv4Addr>> {
        let mut h = [0u8; RTMSG_LEN];
        h[0] = AF_INET;
        let mut out = None;
        self.dump(Msg::new(RTM_GETROUTE, NLM_F_DUMP, &h), RTM_NEWROUTE, |p| {
            if out.is_some() || p.len() < RTMSG_LEN || p[0] != AF_INET || p[1] != 0 {
                return;
            }
            let mut table = u32::from(p[4]);
            let mut gateway = None;
            for (t, d) in attributes(&p[RTMSG_LEN..]) {
                match t {
                    RTA_GATEWAY if d.len() == 4 => {
                        gateway = Some(Ipv4Addr::new(d[0], d[1], d[2], d[3]))
                    }
                    RTA_TABLE => table = read_u32(d, 0).unwrap_or(table),
                    _ => {}
                }
            }
            if table == u32::from(RT_TABLE_MAIN) {
                out = gateway;
            }
        })?;
        Ok(out)
    }

    /// Set the alias of the link INDEX (the kernel ignores it at creation).
    pub fn link_set_alias(&mut self, index: u32, alias: &str) -> io::Result<()> {
        let mut m = Msg::new(RTM_NEWLINK, NLM_F_ACK, &ifinfomsg(index as i32, 0, 0));
        m.attr_str(IFLA_IFALIAS, alias);
        self.checked(m, false, "set the alias of the link")
    }

    pub fn link_up(&mut self, index: u32) -> io::Result<()> {
        let m = Msg::new(
            RTM_NEWLINK,
            NLM_F_ACK,
            &ifinfomsg(index as i32, IFF_UP, IFF_UP),
        );
        self.checked(m, false, "set the link up")
    }

    /// Delete the link INDEX; no error if it is gone.
    pub fn link_del(&mut self, index: u32) -> io::Result<()> {
        let m = Msg::new(RTM_DELLINK, NLM_F_ACK, &ifinfomsg(index as i32, 0, 0));
        match self.request(m)? {
            0 => Ok(()),
            e if e == Errno::NODEV.raw_os_error() => Ok(()),
            e => Err(io::Error::from_raw_os_error(e)),
        }
    }

    /// Add ADDR/PREFIX to the link INDEX; no error if it is there.
    pub fn addr_add(&mut self, index: u32, addr: Ipv4Addr, prefix: u8) -> io::Result<()> {
        let mask = if prefix == 0 {
            0
        } else {
            u32::MAX << (32 - u32::from(prefix))
        };
        let brd = Ipv4Addr::from(u32::from(addr) | !mask);
        let mut h = [0u8; IFADDRMSG_LEN];
        h[0] = AF_INET;
        h[1] = prefix;
        h[3] = RT_SCOPE_UNIVERSE;
        h[4..8].copy_from_slice(&index.to_ne_bytes());
        let mut m = Msg::new(RTM_NEWADDR, NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL, &h);
        m.attr(IFA_LOCAL, &addr.octets());
        m.attr(IFA_ADDRESS, &addr.octets());
        m.attr(IFA_BROADCAST, &brd.octets());
        self.checked(m, true, &format!("add the address {addr}/{prefix}"))
    }

    /// The route of type local to ADDR in the table TABLE, through the link
    /// INDEX (the loopback): a packet that the rules send to that table is
    /// delivered to the sockets of the host, though ADDR is no address of
    /// any link.  With `add` false, the route is deleted; false when there
    /// was none.
    pub fn local_route(
        &mut self,
        add: bool,
        table: u32,
        addr: Ipv4Addr,
        index: u32,
    ) -> io::Result<bool> {
        let mut h = [0u8; RTMSG_LEN];
        h[0] = AF_INET;
        h[1] = 32;
        h[5] = RTPROT_BOOT;
        h[6] = RT_SCOPE_HOST;
        h[7] = RTN_LOCAL;
        let (ty, flags) = if add {
            (RTM_NEWROUTE, NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL)
        } else {
            (RTM_DELROUTE, NLM_F_ACK)
        };
        let mut m = Msg::new(ty, flags, &h);
        m.attr_u32(RTA_TABLE, table);
        m.attr(RTA_DST, &addr.octets());
        m.attr_u32(RTA_OIF, index);
        Self::changed(self.request(m)?, add, Errno::SRCH, || {
            format!("the local route to {addr} in the table {table}")
        })
    }

    /// The route of type blackhole to DST/PREFIX in the main table: the
    /// packets for an address of it that no route longer than it names are
    /// dropped (not sent out by the default route).  With `add` false, the
    /// route is deleted; false when there was none.
    pub fn blackhole_route(&mut self, add: bool, dst: Ipv4Addr, prefix: u8) -> io::Result<bool> {
        let mut h = [0u8; RTMSG_LEN];
        h[0] = AF_INET;
        h[1] = prefix;
        h[4] = RT_TABLE_MAIN;
        h[5] = RTPROT_BOOT;
        h[6] = RT_SCOPE_UNIVERSE;
        h[7] = RTN_BLACKHOLE;
        let (ty, flags) = if add {
            (RTM_NEWROUTE, NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL)
        } else {
            (RTM_DELROUTE, NLM_F_ACK)
        };
        let mut m = Msg::new(ty, flags, &h);
        m.attr(RTA_DST, &dst.octets());
        Self::changed(self.request(m)?, add, Errno::SRCH, || {
            format!("the blackhole route to {dst}/{prefix}")
        })
    }

    /// The rule of priority PRIORITY: the packets to DST of the protocol
    /// PROTO (TCP, UDP) and the port PORT are routed by the table TABLE.
    /// With `add` false, the rule is deleted; false when there was none.
    pub fn port_rule(
        &mut self,
        add: bool,
        priority: u32,
        dst: Ipv4Addr,
        proto: u8,
        port: u16,
        table: u32,
    ) -> io::Result<bool> {
        let mut h = [0u8; FIB_RULE_HDR_LEN];
        h[0] = AF_INET;
        h[1] = 32;
        h[7] = FR_ACT_TO_TBL;
        let (ty, flags) = if add {
            (RTM_NEWRULE, NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL)
        } else {
            (RTM_DELRULE, NLM_F_ACK)
        };
        let mut m = Msg::new(ty, flags, &h);
        m.attr_u32(FRA_PRIORITY, priority);
        m.attr_u32(FRA_TABLE, table);
        m.attr(FRA_DST, &dst.octets());
        m.attr(FRA_IP_PROTO, &[proto]);
        // (`struct fib_rule_port_range`: the first and the last port)
        let mut range = port.to_ne_bytes().to_vec();
        range.extend_from_slice(&port.to_ne_bytes());
        m.attr(FRA_DPORT_RANGE, &range);
        Self::changed(self.request(m)?, add, Errno::NOENT, || {
            format!("the rule to {dst} port {port} of the protocol {proto}")
        })
    }

    /// The outcome ERR of an addition (`add`) or a deletion: the deletion of
    /// what is not there (MISSING) is no error.
    fn changed(
        err: i32,
        add: bool,
        missing: Errno,
        what: impl FnOnce() -> String,
    ) -> io::Result<bool> {
        match err {
            0 => Ok(true),
            e if !add && e == missing.raw_os_error() => Ok(false),
            e => {
                let err = io::Error::from_raw_os_error(e);
                let verb = if add { "add" } else { "delete" };
                Err(io::Error::new(
                    err.kind(),
                    format!("{verb} {}: {err}", what()),
                ))
            }
        }
    }

    /// The default route through GATEWAY on the link INDEX.  EEXIST when
    /// there is one.
    pub fn default_route_add(&mut self, index: u32, gateway: Ipv4Addr) -> io::Result<()> {
        let mut h = [0u8; RTMSG_LEN];
        h[0] = AF_INET;
        h[4] = RT_TABLE_MAIN;
        h[5] = RTPROT_BOOT;
        h[6] = RT_SCOPE_UNIVERSE;
        h[7] = RTN_UNICAST;
        let mut m = Msg::new(RTM_NEWROUTE, NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL, &h);
        m.attr(RTA_GATEWAY, &gateway.octets());
        m.attr_u32(RTA_OIF, index);
        self.checked(m, false, "add the default route")
    }

    /// The static route R through its gateway on the link INDEX.  EEXIST
    /// when there is one.
    pub fn static_route_add(&mut self, index: u32, r: &Route) -> io::Result<()> {
        const RTA_PRIORITY: u16 = 6;
        let mut h = [0u8; RTMSG_LEN];
        h[0] = if r.destination.is_ipv4() {
            AF_INET
        } else {
            AF_INET6
        };
        h[1] = r.prefix;
        h[4] = RT_TABLE_MAIN;
        h[5] = RTPROT_BOOT;
        h[6] = RT_SCOPE_UNIVERSE;
        h[7] = RTN_UNICAST;
        let mut m = Msg::new(RTM_NEWROUTE, NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL, &h);
        let octets = |a: std::net::IpAddr| match a {
            std::net::IpAddr::V4(a) => a.octets().to_vec(),
            std::net::IpAddr::V6(a) => a.octets().to_vec(),
        };
        if r.prefix > 0 {
            m.attr(RTA_DST, &octets(r.destination));
        }
        // (the kernel refuses a gateway of the other family)
        m.attr(RTA_GATEWAY, &octets(r.gateway));
        m.attr_u32(RTA_OIF, index);
        if let Some(metric) = r.metric {
            m.attr_u32(RTA_PRIORITY, metric);
        }
        self.checked(m, false, &format!("add the route {r}"))
    }

    /// Add the IPv6 ADDR/PREFIX to the link INDEX, usable at once (no
    /// duplicate address detection: velarx gives the addresses); no error
    /// if it is there.
    pub fn addr6_add(&mut self, index: u32, addr: Ipv6Addr, prefix: u8) -> io::Result<()> {
        let mut h = [0u8; IFADDRMSG_LEN];
        h[0] = AF_INET6;
        h[1] = prefix;
        h[2] = IFA_F_NODAD;
        h[3] = RT_SCOPE_UNIVERSE;
        h[4..8].copy_from_slice(&index.to_ne_bytes());
        let mut m = Msg::new(RTM_NEWADDR, NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL, &h);
        m.attr(IFA_ADDRESS, &addr.octets());
        self.checked(m, true, &format!("add the address {addr}/{prefix}"))
    }

    /// The IPv6 default route through GATEWAY on the link INDEX.  EEXIST
    /// when there is one.
    pub fn default_route6_add(&mut self, index: u32, gateway: Ipv6Addr) -> io::Result<()> {
        let mut h = [0u8; RTMSG_LEN];
        h[0] = AF_INET6;
        h[4] = RT_TABLE_MAIN;
        h[5] = RTPROT_BOOT;
        h[6] = RT_SCOPE_UNIVERSE;
        h[7] = RTN_UNICAST;
        let mut m = Msg::new(RTM_NEWROUTE, NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL, &h);
        m.attr(RTA_GATEWAY, &gateway.octets());
        m.attr_u32(RTA_OIF, index);
        self.checked(m, false, "add the IPv6 default route")
    }

    /// Send a dump request and give each reply message of type TY to F.  A
    /// dump that changed while it was made (`NLM_F_DUMP_INTR`) is made again.
    pub(super) fn dump(&mut self, req: Msg, ty: u16, mut f: impl FnMut(&[u8])) -> io::Result<()> {
        for _ in 0..DUMP_TRIES {
            if let Some(got) = self.dump_once(req.clone(), ty)? {
                got.iter().for_each(|p| f(p));
                return Ok(());
            }
        }
        Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "netlink dump keeps changing",
        ))
    }

    /// One dump: its messages, none if it was inconsistent.
    fn dump_once(&mut self, req: Msg, ty: u16) -> io::Result<Option<Vec<Vec<u8>>>> {
        let seq = self.send(req)?;
        let mut buf = vec![0u8; BUF_SIZE];
        let (mut got, mut changed) = (Vec::new(), false);
        loop {
            let n = match recv(&self.fd, &mut buf[..], RecvFlags::TRUNC) {
                Ok((n, total)) if total > n => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "netlink message truncated",
                    ))
                }
                Ok((0, _)) => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "netlink closed",
                    ))
                }
                Ok((n, _)) => n,
                Err(Errno::INTR) => continue,
                Err(e) => return Err(e.into()),
            };
            let mut off = 0;
            for (t, s, payload) in messages(&buf[..n]) {
                let flags = read_u16(&buf, off + 6).unwrap_or(0);
                off += align(NLMSG_HDRLEN + payload.len());
                if s != seq {
                    continue;
                }
                changed |= flags & NLM_F_DUMP_INTR != 0;
                match t {
                    NLMSG_DONE => return Ok((!changed).then_some(got)),
                    NLMSG_ERROR => {
                        let e = read_u32(payload, 0).unwrap_or(0) as i32;
                        return Err(io::Error::from_raw_os_error(-e));
                    }
                    t if t == ty => got.push(payload.to_vec()),
                    _ => {}
                }
            }
        }
    }

    /// The links: index, name, kind and alias.
    pub fn links(&mut self) -> io::Result<Vec<Link>> {
        let mut out = Vec::new();
        self.dump(
            Msg::new(RTM_GETLINK, NLM_F_DUMP, &ifinfomsg(0, 0, 0)),
            RTM_NEWLINK,
            |p| {
                if p.len() < IFINFOMSG_LEN {
                    return;
                }
                let mut l = Link {
                    index: read_u32(p, 4).unwrap_or(0),
                    ..Link::default()
                };
                for (t, d) in attributes(&p[IFINFOMSG_LEN..]) {
                    match t {
                        IFLA_IFNAME => l.name = cstr(d),
                        IFLA_IFALIAS => l.alias = cstr(d),
                        IFLA_MASTER => l.master = read_u32(d, 0).unwrap_or(0),
                        IFLA_LINK => l.link = read_u32(d, 0).unwrap_or(0),
                        IFLA_ADDRESS => l.mac = <[u8; 6]>::try_from(d).ok(),
                        IFLA_LINKINFO => {
                            for (it, id) in attributes(d) {
                                if it == IFLA_INFO_KIND {
                                    l.kind = cstr(id);
                                }
                            }
                        }
                        _ => {}
                    }
                }
                out.push(l);
            },
        )?;
        Ok(out)
    }

    /// The link named NAME.
    pub fn link(&mut self, name: &str) -> io::Result<Option<Link>> {
        Ok(self.links()?.into_iter().find(|l| l.name == name))
    }

    /// The number of links enslaved to the bridge INDEX.
    pub fn bridge_ports(&mut self, index: u32) -> io::Result<usize> {
        Ok(self.links()?.iter().filter(|l| l.master == index).count())
    }

    /// Wait (LIMIT at most) until the bridge INDEX has no port left: the
    /// changes of the links are followed, no interval.  Whether it has none.
    pub fn wait_bridge_empty(
        &mut self,
        index: u32,
        limit: std::time::Duration,
    ) -> io::Result<bool> {
        let events = socket_with(
            AddressFamily::NETLINK,
            SocketType::RAW,
            SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
            None,
        )?;
        // (subscribed before the ports are counted: no change is missed)
        bind(&events, &SocketAddrNetlink::new(0, RTMGRP_LINK))?;
        let deadline = std::time::Instant::now() + limit;
        let mut buf = vec![0u8; 16384];
        loop {
            if self.bridge_ports(index)? == 0 {
                return Ok(true);
            }
            let left = deadline.saturating_duration_since(std::time::Instant::now());
            if left.is_zero() {
                return Ok(false);
            }
            let timeout = rustix::event::Timespec {
                tv_sec: left.as_secs() as i64,
                tv_nsec: left.subsec_nanos() as i64,
            };
            let mut fds = [rustix::event::PollFd::new(
                &events,
                rustix::event::PollFlags::IN,
            )];
            // (a signal ends the wait too: the loop counts again)
            let _ = rustix::event::poll(&mut fds, Some(&timeout));
            // (what changed is counted again; an overflow, ENOBUFS, too)
            while recv(&events, &mut buf, RecvFlags::empty()).is_ok_and(|(n, _)| n > 0) {}
        }
    }

    /// The IPv4 addresses: (link index, address, prefix).
    pub fn addresses(&mut self) -> io::Result<Vec<(u32, Ipv4Addr, u8)>> {
        let mut h = [0u8; IFADDRMSG_LEN];
        h[0] = AF_INET;
        let mut out = Vec::new();
        self.dump(Msg::new(RTM_GETADDR, NLM_F_DUMP, &h), RTM_NEWADDR, |p| {
            if p.len() < IFADDRMSG_LEN || p[0] != AF_INET {
                return;
            }
            let (prefix, index) = (p[1], read_u32(p, 4).unwrap_or(0));
            let mut addr = None;
            for (t, d) in attributes(&p[IFADDRMSG_LEN..]) {
                if (t == IFA_LOCAL || (t == IFA_ADDRESS && addr.is_none())) && d.len() == 4 {
                    addr = Some(Ipv4Addr::new(d[0], d[1], d[2], d[3]));
                }
            }
            if let Some(a) = addr {
                out.push((index, a, prefix));
            }
        })?;
        Ok(out)
    }

    /// The global (universe scope) IPv6 addresses: (link index, address,
    /// prefix).
    pub fn global_addresses6(&mut self) -> io::Result<Vec<(u32, Ipv6Addr, u8)>> {
        let mut h = [0u8; IFADDRMSG_LEN];
        h[0] = AF_INET6;
        let mut out = Vec::new();
        self.dump(Msg::new(RTM_GETADDR, NLM_F_DUMP, &h), RTM_NEWADDR, |p| {
            if p.len() < IFADDRMSG_LEN || p[0] != AF_INET6 || p[3] != RT_SCOPE_UNIVERSE {
                return;
            }
            let (prefix, index) = (p[1], read_u32(p, 4).unwrap_or(0));
            let addr = attributes(&p[IFADDRMSG_LEN..])
                .filter(|(t, _)| *t == IFA_ADDRESS)
                .find_map(|(_, d)| <[u8; 16]>::try_from(d).ok());
            if let Some(a) = addr {
                out.push((index, Ipv6Addr::from(a), prefix));
            }
        })?;
        Ok(out)
    }

    /// The gateway of the IPv6 default route of the main table.
    pub fn default_gateway6(&mut self) -> io::Result<Option<Ipv6Addr>> {
        let mut h = [0u8; RTMSG_LEN];
        h[0] = AF_INET6;
        let mut out = None;
        self.dump(Msg::new(RTM_GETROUTE, NLM_F_DUMP, &h), RTM_NEWROUTE, |p| {
            if out.is_some() || p.len() < RTMSG_LEN || p[0] != AF_INET6 || p[1] != 0 {
                return;
            }
            let mut table = u32::from(p[4]);
            let mut gateway = None;
            for (t, d) in attributes(&p[RTMSG_LEN..]) {
                match t {
                    RTA_GATEWAY => gateway = <[u8; 16]>::try_from(d).ok().map(Ipv6Addr::from),
                    RTA_TABLE => table = read_u32(d, 0).unwrap_or(table),
                    _ => {}
                }
            }
            if table == u32::from(RT_TABLE_MAIN) {
                out = gateway;
            }
        })?;
        Ok(out)
    }

    /// The IPv6 routes of the main table but the default one, link-local
    /// and multicast ones: (output link index, destination, prefix).
    pub fn routes6(&mut self) -> io::Result<Vec<(u32, Ipv6Addr, u8)>> {
        let mut h = [0u8; RTMSG_LEN];
        h[0] = AF_INET6;
        let mut out = Vec::new();
        self.dump(Msg::new(RTM_GETROUTE, NLM_F_DUMP, &h), RTM_NEWROUTE, |p| {
            if p.len() < RTMSG_LEN || p[0] != AF_INET6 || p[1] == 0 {
                return;
            }
            let mut table = u32::from(p[4]);
            let (mut dst, mut oif) = (None, 0);
            for (t, d) in attributes(&p[RTMSG_LEN..]) {
                match t {
                    RTA_DST => {
                        if let Ok(b) = <[u8; 16]>::try_from(d) {
                            dst = Some(Ipv6Addr::from(b));
                        }
                    }
                    RTA_OIF => oif = read_u32(d, 0).unwrap_or(0),
                    RTA_TABLE => table = read_u32(d, 0).unwrap_or(table),
                    _ => {}
                }
            }
            let Some(d) = dst else { return };
            let seg = d.segments()[0];
            let local = seg & 0xffc0 == 0xfe80 || seg & 0xff00 == 0xff00;
            if table == u32::from(RT_TABLE_MAIN) && !local {
                out.push((oif, d, p[1]));
            }
        })?;
        Ok(out)
    }

    /// The IPv4 routes of the main table but the default one: (output link
    /// index, destination, prefix).
    pub fn routes(&mut self) -> io::Result<Vec<(u32, Ipv4Addr, u8)>> {
        let mut h = [0u8; RTMSG_LEN];
        h[0] = AF_INET;
        let mut out = Vec::new();
        self.dump(Msg::new(RTM_GETROUTE, NLM_F_DUMP, &h), RTM_NEWROUTE, |p| {
            if p.len() < RTMSG_LEN || p[0] != AF_INET || p[1] == 0 {
                return;
            }
            let mut table = u32::from(p[4]);
            let (mut dst, mut oif) = (None, 0);
            for (t, d) in attributes(&p[RTMSG_LEN..]) {
                match t {
                    RTA_DST if d.len() == 4 => dst = Some(Ipv4Addr::new(d[0], d[1], d[2], d[3])),
                    RTA_OIF => oif = read_u32(d, 0).unwrap_or(0),
                    RTA_TABLE => table = read_u32(d, 0).unwrap_or(table),
                    _ => {}
                }
            }
            if let (Some(d), true) = (dst, table == u32::from(RT_TABLE_MAIN)) {
                out.push((oif, d, p[1]));
            }
        })?;
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Run the test NAME in a user and network namespace of its own;
    /// true when the caller is that run and goes on.
    fn in_namespaces(name: &str) -> bool {
        if std::env::var_os("VELARX_NETLINK_TEST_NS").is_some() {
            return true;
        }
        let unshare = |args: &[&str]| std::process::Command::new("unshare").args(args).output();
        if !unshare(&["-rn", "true"]).is_ok_and(|o| o.status.success()) {
            eprintln!("skipped: no user and network namespaces");
            return false;
        }
        let out = std::process::Command::new("unshare")
            .arg("-rn")
            .arg(std::env::current_exe().unwrap())
            .args(["--exact", &format!("netlink::tests::{name}")])
            .env("VELARX_NETLINK_TEST_NS", "1")
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

    #[test]
    fn the_global_ipv6_address_and_gateway_of_a_namespace() {
        if !in_namespaces("the_global_ipv6_address_and_gateway_of_a_namespace") {
            return;
        }
        let mut nl = Netlink::open().unwrap();
        let lo = nl.link_index("lo").unwrap();
        nl.link_up(lo).unwrap();
        nl.veth_pair_add("va", "vb").unwrap();
        let (va, vb) = (nl.link_index("va").unwrap(), nl.link_index("vb").unwrap());
        nl.link_up(va).unwrap();
        nl.link_up(vb).unwrap();
        // (loopback's ::1 has the host scope, and a link-local address
        // would not be global either)
        assert!(nl.global_addresses6().unwrap().is_empty());
        assert_eq!(nl.default_gateway6().unwrap(), None);
        let (addr, gateway) = ("fd00::2".parse().unwrap(), "fd00::1".parse().unwrap());
        nl.addr6_add(va, addr, 64).unwrap();
        nl.default_route6_add(va, gateway).unwrap();
        assert_eq!(nl.global_addresses6().unwrap(), [(va, addr, 64)]);
        assert_eq!(nl.default_gateway6().unwrap(), Some(gateway));
    }

    #[test]
    fn messages_are_aligned_and_sized() {
        let mut m = Msg::new(RTM_NEWLINK, NLM_F_ACK, &ifinfomsg(0, 0, 0));
        m.attr_str(IFLA_IFNAME, "br0");
        let info = m.begin(IFLA_LINKINFO);
        m.attr_str(IFLA_INFO_KIND, "bridge");
        m.end(info);
        let b = m.finish(7);
        assert_eq!(read_u32(&b, 0), Some(b.len() as u32));
        assert_eq!(b.len() % 4, 0);
        assert_eq!(read_u32(&b, 8), Some(7));
        let attrs: Vec<_> = attributes(&b[NLMSG_HDRLEN + IFINFOMSG_LEN..]).collect();
        assert_eq!(attrs[0], (IFLA_IFNAME, &b"br0\0"[..]));
        assert_eq!(attrs[1].0, IFLA_LINKINFO);
        let inner: Vec<_> = attributes(attrs[1].1).collect();
        assert_eq!(inner, vec![(IFLA_INFO_KIND, &b"bridge\0"[..])]);
    }

    #[test]
    fn malformed_replies_end_the_iteration() {
        assert_eq!(messages(&[1, 2, 3]).count(), 0);
        let mut b = vec![0u8; 20];
        b[0..4].copy_from_slice(&100u32.to_ne_bytes());
        assert_eq!(messages(&b).count(), 0);
        assert_eq!(attributes(&[2, 0, 1, 0]).count(), 0);
    }
}
