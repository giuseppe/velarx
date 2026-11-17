// SPDX-License-Identifier: Apache-2.0
//! Bridge networks for containers, what netavark and aardvark-dns do for
//! podman: a Linux bridge per network, a veth
//! pair per container and network, an nftables table for NAT, forwarding and
//! published ports, and a DNS server for the container names.  IPv4.
//!
//! * The bridge of a network is created on first use with the gateway
//!   address (`route_localnet=1`, for published ports reached from
//!   127.0.0.1); the host end of a veth (`veth%d`) is enslaved to it, the
//!   peer is created directly in the namespace of the container.
//! * The container side (loopback, addresses, the default route through the
//!   first network that is not internal) is configured from a thread that
//!   joins the namespace, so the caller stays where it is.
//! * Teardown deletes the container ends; a bridge left without ports is
//!   deleted with its rules.
//!
//! Everything runs under `<state>/network.lock`: the bridges, the firewall
//! and the DNS records are shared by the containers of a run root.

use crate::dnsrec;
use crate::error::{NetworkError, NetworkResult};
use crate::firewall::Firewall;
use crate::firewalld;
use crate::netlink::Netlink;
use rustix::fs::FlockOperation;
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::{AsFd, BorrowedFd};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use velarx_wire::addr::{valid_ifname, PortSpec, Route, Subnet, Subnet6};

pub const NETWORK_LOCK: &str = "network.lock";

/// A network as the setup needs it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetDef {
    /// The id of the network: the bridge carries it as its alias.
    #[serde(default)]
    pub id: String,
    pub name: String,
    pub bridge: String,
    #[serde(with = "subnet_string")]
    pub subnet: Subnet,
    pub gateway: Ipv4Addr,
    #[serde(default)]
    pub internal: bool,
    #[serde(default)]
    pub dns: bool,
    /// 0: the default.
    #[serde(default)]
    pub mtu: u32,
    /// The servers for the other names, instead of those of the host.
    #[serde(default)]
    pub dns_servers: Vec<IpAddr>,
    /// The IPv6 subnet of a dual-stack network.
    #[serde(default, with = "subnet6_string")]
    pub subnet6: Option<Subnet6>,
    /// A macvlan network: its mode (`bridge`, `private`, `vepa`,
    /// `passthru`); `bridge` is then the parent interface.  No bridge, no
    /// firewall, no DNS server: the containers are on the parent's LAN.
    #[serde(default)]
    pub macvlan: Option<String>,
    #[serde(default)]
    pub gateway6: Option<Ipv6Addr>,
    /// Static routes through the interface of the network.
    #[serde(default, with = "routes_strings")]
    pub routes: Vec<Route>,
}

/// A container on a network.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Attachment {
    pub net: NetDef,
    /// The interface in the container, `eth0`...
    pub ifname: String,
    pub ip: Ipv4Addr,
    /// None: the kernel picks one.
    #[serde(default)]
    pub mac: Option<[u8; 6]>,
    #[serde(default)]
    pub aliases: Vec<String>,
    /// On a dual-stack network.
    #[serde(default)]
    pub ip6: Option<Ipv6Addr>,
}

/// What the setup and the teardown of a container need.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BridgeContainer {
    pub id: String,
    #[serde(default)]
    pub name: String,
    pub attachments: Vec<Attachment>,
    /// Published on the address of the first network.
    #[serde(default, with = "ports_strings")]
    pub ports: Vec<PortSpec>,
}

mod routes_strings {
    use super::Route;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(r: &[Route], ser: S) -> Result<S::Ok, S::Error> {
        ser.collect_seq(r.iter().map(ToString::to_string))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(de: D) -> Result<Vec<Route>, D::Error> {
        Vec::<String>::deserialize(de)?
            .iter()
            .map(|s| Route::parse(s).map_err(serde::de::Error::custom))
            .collect()
    }
}

mod subnet_string {
    use super::Subnet;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(s: &Subnet, ser: S) -> Result<S::Ok, S::Error> {
        ser.collect_str(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(de: D) -> Result<Subnet, D::Error> {
        let s = String::deserialize(de)?;
        Subnet::parse_with(&s, 1)
            .ok_or_else(|| serde::de::Error::custom(format!("invalid subnet `{s}`")))
    }
}

mod subnet6_string {
    use super::Subnet6;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(s: &Option<Subnet6>, ser: S) -> Result<S::Ok, S::Error> {
        match s {
            Some(s) => ser.collect_str(s),
            None => ser.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(de: D) -> Result<Option<Subnet6>, D::Error> {
        match Option::<String>::deserialize(de)? {
            None => Ok(None),
            Some(s) => Subnet6::parse(&s)
                .map(Some)
                .ok_or_else(|| serde::de::Error::custom(format!("invalid subnet `{s}`"))),
        }
    }
}

mod ports_strings {
    use super::PortSpec;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(p: &[PortSpec], ser: S) -> Result<S::Ok, S::Error> {
        ser.collect_seq(p.iter().map(|p| p.to_string()))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(de: D) -> Result<Vec<PortSpec>, D::Error> {
        Vec::<String>::deserialize(de)?
            .iter()
            .map(|s| PortSpec::parse(s).map_err(serde::de::Error::custom))
            .collect()
    }
}

impl BridgeContainer {
    /// Refuse what could not be set up or would end in a path or a rule.
    pub fn validate(&self) -> NetworkResult<()> {
        let bad = |m: String| Err(NetworkError::InvalidConfig(m));
        if self.id.is_empty()
            || self.id.starts_with('.')
            || !self
                .id
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
        {
            return bad(format!("invalid container id `{}`", self.id));
        }
        for a in &self.attachments {
            let n = &a.net;
            if let Some(mode) = &n.macvlan {
                if macvlan_mode(mode).is_err() {
                    return bad(format!("invalid macvlan mode for the network `{}`", n.name));
                }
            }
            if !valid_ifname(&n.bridge) {
                return bad(format!("invalid bridge for the network `{}`", n.name));
            }
            if !valid_ifname(&a.ifname) {
                return bad(format!(
                    "invalid interface name for the network `{}`",
                    n.name
                ));
            }
            if !n.subnet.is_host(n.gateway) || !n.subnet.is_host(a.ip) || a.ip == n.gateway {
                return bad(format!("invalid address for the network `{}`", n.name));
            }
            let v6_ok = match (n.subnet6, n.gateway6, a.ip6) {
                (None, None, None) => true,
                (Some(s), Some(gw), ip6) => {
                    s.is_host(gw) && ip6.is_none_or(|ip| s.is_host(ip) && ip != gw)
                }
                _ => false,
            };
            if !v6_ok {
                return bad(format!("invalid IPv6 address for the network `{}`", n.name));
            }
            if n.mtu != 0 && !(68..=65535).contains(&n.mtu) {
                return bad(format!("invalid MTU for the network `{}`", n.name));
            }
            if a.mac.is_some_and(|m| m == [0; 6] || m[0] & 1 != 0) {
                return bad(format!("invalid MAC address for the network `{}`", n.name));
            }
        }
        for p in &self.ports {
            if p.host_port == 0 || p.container_port == 0 || p.last_host_port() > 65535 {
                return bad(format!("invalid port mapping `{p}`"));
            }
            if u32::from(p.container_port) + u32::from(p.range) - 1 > 65535 {
                return bad(format!("invalid port mapping `{p}`"));
            }
            let v6 = self.attachments.first().is_some_and(|a| a.ip6.is_some());
            if matches!(p.host_ip, Some(IpAddr::V6(_))) && !v6 {
                return bad(format!(
                    "a port published on an IPv6 address needs an IPv6 network: `{p}`"
                ));
            }
        }
        Ok(())
    }
}

/// Where the state of the bridge networks is and what they run.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BridgeOptions {
    /// The lock and the DNS records (created).
    pub state_dir: PathBuf,
    pub firewall: Firewall,
    /// `velarx`, started as the DNS server.
    pub dns_exe: PathBuf,
    /// Where the bridges live: the namespace of the caller when None, else
    /// the namespace pinned there (the rootless one).
    pub netns: Option<PathBuf>,
}

/// Run F where the bridges of OPTS live, with the networks locked: the
/// rootless namespace is opened under the lock, so that it cannot be
/// released (`ContainerNetworks::release_rootless_netns_if_unused`) between
/// the open and F.
fn where_bridges<T: Send + 'static>(
    opts: &BridgeOptions,
    f: impl FnOnce() -> NetworkResult<T> + Send + 'static,
) -> NetworkResult<T> {
    // The engines of every root share the table of the namespace: the one
    // that deletes it with the last bridge must not race with another that
    // makes a bridge.
    let _shared = if opts.netns.is_none() && rustix::process::geteuid().is_root() {
        Some(lock_file(Path::new(SHARED_LOCK))?)
    } else {
        None
    };
    let _lock = lock_networks(&opts.state_dir)?;
    let Some(path) = &opts.netns else {
        return f();
    };
    if !is_nsfs(path) {
        return Err(NetworkError::RootlessNetnsGone);
    }
    let ns = File::open(path)
        .map_err(|e| io::Error::new(e.kind(), format!("open {}: {e}", path.display())))?;
    in_netns(ns.as_fd(), move || Ok(f()))?
}

/// `statfs` magic of the namespace files.
const NSFS_MAGIC: i64 = 0x6e73_6673;

/// Whether PATH is a pinned namespace (not a file left by a gone mount).
pub fn is_nsfs(path: &Path) -> bool {
    rustix::fs::statfs(path).is_ok_and(|s| s.f_type == NSFS_MAGIC)
}

/// The lock of the root engines that set up bridges in their namespace:
/// all of them, whatever their roots.
const SHARED_LOCK: &str = "/run/velarx-networks.lock";

/// Lock the networks of the run root: released when the file is dropped.
pub fn lock_networks(state: &Path) -> io::Result<File> {
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(state)?;
    lock_file(&state.join(NETWORK_LOCK))
}

/// Lock PATH (created): released when the file is dropped.
fn lock_file(path: &Path) -> io::Result<File> {
    let f = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|e| io::Error::new(e.kind(), format!("open {}: {e}", path.display())))?;
    velarx_sys::flock::flock_retrying(&f, FlockOperation::LockExclusive)?;
    Ok(f)
}

fn write_sysctl(path: &str, value: &str) -> io::Result<()> {
    std::fs::write(path, value).map_err(|e| io::Error::new(e.kind(), format!("write {path}: {e}")))
}

/// Run F in a thread that joined the network namespace NETNS: the caller
/// and its other threads stay where they are.
pub fn in_netns<T: Send + 'static>(
    netns: BorrowedFd<'_>,
    f: impl FnOnce() -> io::Result<T> + Send + 'static,
) -> io::Result<T> {
    let fd = netns.try_clone_to_owned()?;
    std::thread::spawn(move || {
        rustix::thread::move_into_link_name_space(
            fd.as_fd(),
            Some(rustix::thread::LinkNameSpaceType::Network),
        )
        .map_err(|e| {
            io::Error::new(
                io::Error::from(e).kind(),
                format!("join the network namespace: {e}"),
            )
        })?;
        f()
    })
    .join()
    .map_err(|_| io::Error::other("the network namespace thread panicked"))?
}

/// The alias of the bridges velarx creates: only a link carrying it is
/// ever reused or deleted, never an interface of the host.
pub const OWNER_PREFIX: &str = "velarx:";

pub fn owner_mark(n: &NetDef) -> String {
    format!(
        "{OWNER_PREFIX}{}",
        if n.id.is_empty() { &n.name } else { &n.id }
    )
}

/// The index of the link NAME if it is a bridge velarx created.
fn owned_bridge(nl: &mut Netlink, name: &str) -> Option<u32> {
    match nl.link(name) {
        Ok(Some(l)) if l.kind == "bridge" && l.alias.starts_with(OWNER_PREFIX) => Some(l.index),
        _ => None,
    }
}

/// Refuse an IPv6 subnet that overlaps a route of the host (an address of
/// it comes with the route of its prefix), but those of the bridge OWN.
pub fn check_subnet6_free(nl: &mut Netlink, subnet: &Subnet6, own: u32) -> io::Result<()> {
    for (oif, dst, prefix) in nl.routes6()? {
        if oif == own && own != 0 {
            continue;
        }
        let other = Subnet6::parse(&format!("{dst}/{}", prefix.clamp(8, 124)));
        if other.is_some_and(|o| o.overlaps(subnet)) {
            return Err(io::Error::new(
                io::ErrorKind::AddrInUse,
                format!("the subnet {subnet} overlaps the route {dst}/{prefix} of the host"),
            ));
        }
    }
    Ok(())
}

/// Refuse a subnet that overlaps an address or a route of the host (but
/// those of the bridge OWN of the network itself).
pub fn check_subnet_free(nl: &mut Netlink, subnet: &Subnet, own: u32) -> io::Result<()> {
    for (idx, addr, prefix) in nl.addresses()? {
        if idx == own {
            continue;
        }
        let other = Subnet::parse_with(&format!("{addr}/{}", prefix.min(30)), 1);
        if subnet.contains(addr) || other.is_some_and(|o| o.overlaps(subnet)) {
            return Err(io::Error::new(
                io::ErrorKind::AddrInUse,
                format!("the subnet {subnet} overlaps the address {addr}/{prefix} of the host"),
            ));
        }
    }
    for (oif, dst, prefix) in nl.routes()? {
        if oif == own && own != 0 {
            continue;
        }
        let other = Subnet::parse_with(&format!("{dst}/{}", prefix.min(30)), 1);
        if other.is_some_and(|o| o.overlaps(subnet)) {
            return Err(io::Error::new(
                io::ErrorKind::AddrInUse,
                format!("the subnet {subnet} overlaps the route {dst}/{prefix} of the host"),
            ));
        }
    }
    Ok(())
}

/// The bridge of N with its address, up.  A link that already has its name
/// must be the bridge velarx created for this network.
fn setup_bridge(nl: &mut Netlink, n: &NetDef) -> io::Result<u32> {
    let mark = owner_mark(n);
    match nl.bridge_add(&n.bridge, n.mtu, &mark) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => match nl.link(&n.bridge)? {
            Some(l) if l.kind == "bridge" && l.alias == mark => {}
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    format!(
                        "the interface `{}` exists and is not the bridge of the network `{}`",
                        n.bridge, n.name
                    ),
                ))
            }
        },
        Err(e) => return Err(e),
    }
    let idx = nl.link_index(&n.bridge)?;
    if idx == 0 {
        return Err(io::Error::other(format!(
            "the bridge `{}` disappeared",
            n.bridge
        )));
    }
    nl.addr_add(idx, n.gateway, n.subnet.prefix)
        .and_then(|_| nl.link_up(idx))
        .map_err(|e| io::Error::new(e.kind(), format!("set up the bridge `{}`: {e}", n.bridge)))?;
    // Published ports reached from 127.0.0.1 are routed to the bridge (the
    // firewall drops the other packets to 127.0.0.0/8 from outside).
    write_sysctl(
        &format!("/proc/sys/net/ipv4/conf/{}/route_localnet", n.bridge),
        "1",
    )?;
    if let (Some(s6), Some(gw6)) = (n.subnet6, n.gateway6) {
        let mut v6 = || -> io::Result<()> {
            write_sysctl(
                &format!("/proc/sys/net/ipv6/conf/{}/disable_ipv6", n.bridge),
                "0",
            )?;
            nl.addr6_add(idx, gw6, s6.prefix)?;
            if !n.internal {
                write_sysctl("/proc/sys/net/ipv6/conf/all/forwarding", "1")?;
            }
            Ok(())
        };
        v6().map_err(|e| {
            io::Error::new(
                e.kind(),
                format!("set up IPv6 on the bridge `{}`: {e}", n.bridge),
            )
        })?;
    }
    Ok(idx)
}

/// In the namespace of the container: the loopback, the addresses and the
/// default route.
fn configure_netns(c: &BridgeContainer) -> io::Result<()> {
    let mut nl = Netlink::open()?;
    let lo = nl.link_index("lo")?;
    if lo > 0 {
        nl.link_up(lo)?;
    }
    let mut has_default = false;
    let mut has_default6 = false;
    for a in &c.attachments {
        let idx = nl.link_index(&a.ifname)?;
        if idx == 0 {
            return Err(io::Error::other(format!(
                "no interface `{}` in the container",
                a.ifname
            )));
        }
        nl.addr_add(idx, a.ip, a.net.subnet.prefix)?;
        if let (Some(ip6), Some(s6)) = (a.ip6, a.net.subnet6) {
            write_sysctl(
                &format!("/proc/sys/net/ipv6/conf/{}/disable_ipv6", a.ifname),
                "0",
            )?;
            nl.addr6_add(idx, ip6, s6.prefix)?;
        }
        nl.link_up(idx)?;
        for r in &a.net.routes {
            match nl.static_route_add(idx, r) {
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
                r => r?,
            }
        }
        if !a.net.internal && !has_default {
            // A network connected to a running container: the default route
            // stays on the first one.
            match nl.default_route_add(idx, a.net.gateway) {
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
                r => r?,
            }
            has_default = true;
        }
        if let (false, false, Some(_), Some(gw6)) =
            (a.net.internal, has_default6, a.ip6, a.net.gateway6)
        {
            match nl.default_route6_add(idx, gw6) {
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
                r => r?,
            }
            has_default6 = true;
        }
    }
    Ok(())
}

/// Delete the interfaces of C in its namespace.
fn unconfigure_netns(c: &BridgeContainer) -> io::Result<()> {
    let mut nl = Netlink::open()?;
    for a in &c.attachments {
        if let Ok(idx) = nl.link_index(&a.ifname) {
            if idx > 0 {
                let _ = nl.link_del(idx);
            }
        }
    }
    Ok(())
}

/// Whether no bridge of ours (of any root) is left in this namespace.
fn no_bridge_left(nl: &mut Netlink) -> bool {
    no_bridge_left_but(nl, &[])
}

/// Whether no bridge of ours is left, but those with the indexes GOING.
fn no_bridge_left_but(nl: &mut Netlink, going: &[u32]) -> bool {
    nl.links().is_ok_and(|links| {
        !links.iter().any(|l| {
            l.kind == "bridge" && l.alias.starts_with(OWNER_PREFIX) && !going.contains(&l.index)
        })
    })
}

fn drop_table_if_unused(opts: &BridgeOptions, nl: &mut Netlink) {
    if !no_bridge_left(nl) {
        return;
    }
    if let Err(e) = opts.firewall.delete_tables() {
        tracing::warn!("delete the table {}: {e}", opts.firewall.table);
    }
}

fn bridge_in_use(nl: &mut Netlink, bridge: &str) -> bool {
    match owned_bridge(nl, bridge) {
        None => false,
        Some(idx) => nl.bridge_ports(idx).map(|n| n > 0).unwrap_or(true),
    }
}

/// Remove what another network with the same bridge left behind without
/// ports (its bridge with the address of the old subnet, the firewall
/// rules), so that it does not get in the way of C.  The bridge of C's own
/// network stays, port or not: it lives until the network goes.
fn remove_stale(opts: &BridgeOptions, nl: &mut Netlink, c: &BridgeContainer) -> io::Result<()> {
    for a in &c.attachments {
        let mark = owner_mark(&a.net);
        if let Ok(Some(l)) = nl.link(&a.net.bridge) {
            if l.kind == "bridge"
                && l.alias.starts_with(OWNER_PREFIX)
                && l.alias != mark
                && nl.bridge_ports(l.index).ok() == Some(0)
            {
                let _ = nl.link_del(l.index);
            }
        }
    }
    // A bridge of velarx that is left is another engine's, maybe one that
    // is being set up and has no port yet: its rules stay.  A failure here
    // is no reason to refuse C's network (the rules are cleaned by the
    // teardown of the bridges later).
    if let Err(e) = opts.firewall.purge(&mut |b| owned_bridge(nl, b).is_some()) {
        tracing::warn!("remove the stale firewall rules: {e}");
    }
    Ok(())
}

/// The `IFLA_MACVLAN_MODE` of a mode of podman's macvlan networks.
pub fn macvlan_mode(mode: &str) -> io::Result<u32> {
    match mode {
        "" | "bridge" => Ok(4),
        "private" => Ok(1),
        "vepa" => Ok(2),
        "passthru" => Ok(8),
        m => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid macvlan mode `{m}`"),
        )),
    }
}

fn do_setup(opts: &BridgeOptions, netns: &Path, c: &BridgeContainer) -> io::Result<()> {
    let ns = File::open(netns)
        .map_err(|e| io::Error::new(e.kind(), format!("open {}: {e}", netns.display())))?;
    if c.attachments.iter().any(|a| a.net.macvlan.is_none()) {
        write_sysctl("/proc/sys/net/ipv4/ip_forward", "1")?;
    }
    let mut nl = Netlink::open()?;
    remove_stale(opts, &mut nl, c)
        .map_err(|e| io::Error::new(e.kind(), format!("remove the stale firewall rules: {e}")))?;
    for a in &c.attachments {
        if let Some(mode) = &a.net.macvlan {
            let parent = nl.link_index(&a.net.bridge)?;
            if parent == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!(
                        "the parent interface `{}` of the network `{}` does not exist",
                        a.net.bridge, a.net.name
                    ),
                ));
            }
            nl.macvlan_add(
                parent,
                &a.ifname,
                macvlan_mode(mode)?,
                a.mac,
                a.net.mtu,
                ns.as_fd(),
            )?;
            continue;
        }
        let bridge = setup_bridge(&mut nl, &a.net)?;
        // (asked at every start: a restart of firewalld forgot it while
        // the bridge stayed; added only when it is not there)
        if opts.netns.is_none() {
            firewalld::trust(&a.net.subnet);
        }
        nl.veth_add(bridge, &a.ifname, a.mac, a.net.mtu, ns.as_fd())?;
    }
    let inside = c.clone();
    in_netns(ns.as_fd(), move || configure_netns(&inside))
        .map_err(|e| io::Error::new(e.kind(), format!("configure the network namespace: {e}")))?;
    if c.attachments.iter().any(|a| a.net.macvlan.is_none()) {
        opts.firewall
            .setup(c)
            .map_err(|e| io::Error::new(e.kind(), format!("set up the firewall: {e}")))?;
    }
    dnsrec::register(&opts.state_dir, c, &opts.dns_exe)
}

/// What becomes of the network namespace of a container the interfaces of
/// which are taken down.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum NetnsFate {
    /// It stays (a network disconnected from a running container, a setup
    /// undone): the interfaces are deleted in it.
    Stays,
    /// It is released with the teardown, and nothing else holds it: the
    /// kernel takes the interfaces down with it, the veth in it with the
    /// port of the bridge it is the peer of, so they are not deleted here
    /// (deleting a veth waits for the kernel to be done with the device,
    /// the release of a namespace does not).
    Released,
}

/// Undo `do_setup`, best effort: every step is tried, the error is the
/// last one.  The bridges and the table of the firewall stay (they live
/// until their network goes, see `network_remove`): the ports of C and its
/// interfaces go, and the rules of a network whose bridge is gone.
fn do_teardown(
    opts: &BridgeOptions,
    netns: Option<&Path>,
    c: &BridgeContainer,
    fate: NetnsFate,
) -> io::Result<()> {
    dnsrec::unregister(&opts.state_dir, c);
    // (in the rootless namespace the interfaces are deleted all the same:
    // the namespace is given up when no bridge in it has a port, which a
    // veth the kernel had not taken down yet would keep)
    let fate = if opts.netns.is_some() {
        NetnsFate::Stays
    } else {
        fate
    };
    let veth = match (fate, netns.and_then(|p| File::open(p).ok())) {
        (NetnsFate::Stays, Some(ns)) => {
            let inside = c.clone();
            Some(std::thread::spawn(move || {
                in_netns(ns.as_fd(), move || unconfigure_netns(&inside))
            }))
        }
        _ => None,
    };
    // The networks whose bridge is not ours (a setup that failed on it) or
    // gone: their rules go.
    let mut remove = vec![false; c.attachments.len()];
    let mut alone = false;
    if let Ok(mut nl) = Netlink::open() {
        for (i, a) in c.attachments.iter().enumerate() {
            remove[i] = a.net.macvlan.is_none() && owned_bridge(&mut nl, &a.net.bridge).is_none();
        }
        alone = no_bridge_left(&mut nl);
    }
    let firewall = teardown_firewall(opts, c, &remove, alone);
    if opts.netns.is_none() {
        for (a, r) in c.attachments.iter().zip(&remove) {
            if *r {
                firewalld::untrust(&a.net.subnet);
            }
        }
    }
    if let Some(v) = veth {
        match v.join() {
            Ok(Ok(_)) => {}
            Ok(Err(e)) => tracing::warn!("remove the interfaces of {}: {e}", c.id),
            Err(_) => tracing::warn!("remove the interfaces of {}: the thread panicked", c.id),
        }
    }
    firewall
}

/// The firewall part of the teardown of C: the tables when ALONE (no bridge
/// of ours), else the ports of C and the rules of the networks in REMOVE.
fn teardown_firewall(
    opts: &BridgeOptions,
    c: &BridgeContainer,
    remove: &[bool],
    alone: bool,
) -> io::Result<()> {
    let fw = &opts.firewall;
    if alone {
        // Nothing of ours stays in the ruleset.
        return fw.delete_tables().inspect_err(|e| {
            tracing::warn!("delete the table {}: {e}", fw.table);
        });
    }
    fw.teardown(c, remove)
}

/// Connect C to its networks in the network namespace NETNS (a path): the
/// bridges, the firewall rules and the DNS records as needed.  On failure
/// what was done is undone.
pub fn setup(opts: &BridgeOptions, netns: &Path, c: &BridgeContainer) -> NetworkResult<()> {
    c.validate()?;
    let (o, n, c) = (opts.clone(), netns.to_path_buf(), c.clone());
    where_bridges(opts, move || {
        // (a bridge this setup makes goes with it if it fails; one that was
        // there stays, with the network)
        let before: Vec<bool> = match Netlink::open() {
            Ok(mut nl) => c
                .attachments
                .iter()
                .map(|a| owned_bridge(&mut nl, &a.net.bridge).is_some())
                .collect(),
            Err(_) => vec![true; c.attachments.len()],
        };
        do_setup(&o, &n, &c).map_err(|e| {
            if let Ok(mut nl) = Netlink::open() {
                for (a, _) in c.attachments.iter().zip(&before).filter(|(_, b)| !**b) {
                    if let Some(idx) = owned_bridge(&mut nl, &a.net.bridge) {
                        if nl.bridge_ports(idx).ok() == Some(0) {
                            let _ = nl.link_del(idx);
                        }
                    }
                }
            }
            if let Err(undo) = do_teardown(&o, Some(&n), &c, NetnsFate::Stays) {
                tracing::warn!("undo the network of {} after `{e}`: {undo}", c.id);
            }
            NetworkError::Netlink(e.to_string())
        })
    })
}

/// Make the bridges and the firewall rules of C again, as they are after
/// `setup`: for the rules a firewall reload or a flush took away.  The
/// interfaces of the container stay.
pub fn reload(opts: &BridgeOptions, c: &BridgeContainer) -> NetworkResult<()> {
    c.validate()?;
    let (o, c) = (opts.clone(), c.clone());
    where_bridges(opts, move || {
        reload_here(&o, &c).map_err(|e| NetworkError::Netlink(e.to_string()))
    })
}

fn reload_here(opts: &BridgeOptions, c: &BridgeContainer) -> io::Result<()> {
    let mut nl = Netlink::open()?;
    for a in c.attachments.iter().filter(|a| a.net.macvlan.is_none()) {
        setup_bridge(&mut nl, &a.net)?;
        // (a restart or a reload of firewalld forgot the source)
        if opts.netns.is_none() {
            firewalld::trust(&a.net.subnet);
        }
    }
    if c.attachments.iter().any(|a| a.net.macvlan.is_none()) {
        opts.firewall
            .setup(c)
            .map_err(|e| io::Error::new(e.kind(), format!("set up the firewall: {e}")))?;
    }
    Ok(())
}

/// Undo `setup`: the interfaces in NETNS (when it is still there), the
/// published ports and the DNS records.  The bridges and the rules of the
/// networks stay, with the table, until the network goes.
pub fn teardown(
    opts: &BridgeOptions,
    netns: Option<&Path>,
    c: &BridgeContainer,
    fate: NetnsFate,
) -> NetworkResult<()> {
    c.validate()?;
    let (o, n, c) = (opts.clone(), netns.map(Path::to_path_buf), c.clone());
    where_bridges(opts, move || {
        do_teardown(&o, n.as_deref(), &c, fate).map_err(|e| NetworkError::Netlink(e.to_string()))
    })
}

/// How long a network that goes waits for the ports its bridge still has:
/// those of a live namespace (a pinned one) keep it.
const PORTS_GONE: std::time::Duration = std::time::Duration::from_secs(5);

/// Remove what the setups did for the network N: its bridge if it has no
/// port left, its rules and its DNS records.  Best effort.
pub fn network_remove(opts: &BridgeOptions, n: &NetDef) -> NetworkResult<()> {
    if !valid_ifname(&n.bridge) {
        return Ok(());
    }
    let (o, n) = (opts.clone(), n.clone());
    where_bridges(opts, move || network_remove_here(&o, &n))
}

/// Remove the network whose id is ID and whose record cannot be read: its
/// bridge is the one with its owner mark, and the subnets and gateways it was
/// set up with are the addresses of the bridge.  No such bridge: what is left
/// of it in the firewall is purged.
pub fn network_remove_by_mark(opts: &BridgeOptions, id: &str) -> NetworkResult<()> {
    let (o, id) = (opts.clone(), id.to_string());
    where_bridges(opts, move || {
        let mut nl = Netlink::open()?;
        let mark = format!("{OWNER_PREFIX}{id}");
        let Some(link) = nl
            .links()?
            .into_iter()
            .find(|l| l.kind == "bridge" && l.alias == mark)
        else {
            if let Err(e) = o.firewall.purge(&mut |b| bridge_in_use(&mut nl, b)) {
                tracing::warn!("purge the table {}: {e}", o.firewall.table);
            }
            drop_table_if_unused(&o, &mut nl);
            return Ok(());
        };
        let (subnet, gateway) = nl
            .addresses()?
            .into_iter()
            .filter(|(i, ..)| *i == link.index)
            .find_map(|(_, a, p)| Some((Subnet::parse(&format!("{a}/{p}"))?, a)))
            .ok_or_else(|| {
                NetworkError::Netlink(format!("the bridge {} has no IPv4 subnet", link.name))
            })?;
        let v6 = nl
            .global_addresses6()?
            .into_iter()
            .filter(|(i, ..)| *i == link.index)
            .find_map(|(_, a, p)| Some((Subnet6::parse(&format!("{a}/{p}"))?, a)));
        let n = NetDef {
            id,
            name: String::new(),
            bridge: link.name,
            subnet,
            gateway,
            internal: false,
            // (what DNS has of it is destroyed: nothing, if it had none)
            dns: true,
            mtu: 0,
            dns_servers: Vec::new(),
            subnet6: v6.map(|(s, _)| s),
            macvlan: None,
            gateway6: v6.map(|(_, g)| g),
            routes: Vec::new(),
        };
        drop(nl);
        network_remove_here(&o, &n)
    })
}

fn network_remove_here(opts: &BridgeOptions, n: &NetDef) -> NetworkResult<()> {
    if n.macvlan.is_some() {
        // No bridge, no rule, no DNS server: the parent is not ours.
        return Ok(());
    }
    dnsrec::remove_network(&opts.state_dir, &n.bridge);
    let mut nl = Netlink::open().ok();
    if let Some(nl) = nl.as_mut() {
        if let Some(idx) = owned_bridge(nl, &n.bridge) {
            // (no container uses the network any more: a port left is
            // mostly the veth of a namespace that went, which the kernel
            // takes down on its own time, after its teardown counted it;
            // one that is still there at the end is released with the
            // bridge: the network is gone from the database either way)
            nl.wait_bridge_empty(idx, PORTS_GONE)
                .map_err(|e| NetworkError::Netlink(format!("bridge {}: {e}", n.bridge)))?;
            let _ = nl.link_del(idx);
            if opts.netns.is_none() {
                firewalld::untrust(&n.subnet);
            }
        }
    }
    if let Some(nl) = nl.as_mut() {
        if let Err(e) = opts.firewall.purge(&mut |b| bridge_in_use(nl, b)) {
            tracing::warn!("purge the table {}: {e}", opts.firewall.table);
        }
    }
    let c = BridgeContainer {
        id: "network".into(),
        name: String::new(),
        attachments: vec![Attachment {
            net: n.clone(),
            ifname: "eth0".into(),
            ip: n.gateway,
            mac: None,
            aliases: Vec::new(),
            ip6: None,
        }],
        ports: Vec::new(),
    };
    let fw = &opts.firewall;
    fw.teardown(&c, &[true])
        .map_err(|e| NetworkError::Netlink(e.to_string()))?;
    if let Some(nl) = nl.as_mut() {
        drop_table_if_unused(opts, nl);
    }
    Ok(())
}

/// Apply the DNS servers of N to its running containers.
pub fn network_dns_update(opts: &BridgeOptions, n: &NetDef) -> NetworkResult<()> {
    let _lock = lock_networks(&opts.state_dir)?;
    // Only files and a datagram to the server: no namespace needed.
    dnsrec::update_servers(&opts.state_dir, n)?;
    Ok(())
}

/// Pin the namespace of the file or descriptor path FROM on TO (created):
/// the slots of the pool of shareable namespaces, which outlive every
/// container and so have no holder, are the only pins left.
pub fn bind_netns(from: &Path, to: &Path) -> io::Result<()> {
    OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(to)?;
    rustix::mount::mount_bind(from, to).map_err(|e| {
        let _ = std::fs::remove_file(to);
        io::Error::new(
            io::Error::from(e).kind(),
            format!("bind mount {} on {}: {e}", from.display(), to.display()),
        )
    })
}

/// Undo `bind_netns`.
pub fn unpin_netns(path: &Path) {
    let _ = rustix::mount::unmount(path, rustix::mount::UnmountFlags::DETACH);
    let _ = std::fs::remove_file(path);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The purge of a setup keeps the rules of a bridge of velarx that has
    /// no port (another engine's, being set up), and removes those of a
    /// bridge that is gone.  In a user and network namespace of its own;
    /// skipped without one.
    #[test]
    fn the_purge_of_a_setup_keeps_the_rules_of_a_bridge_being_set_up() {
        const NAME: &str =
            "bridge::tests::the_purge_of_a_setup_keeps_the_rules_of_a_bridge_being_set_up";
        use crate::nftnl::{Nft, Tab, IP};
        if std::env::var_os("VELARX_BRIDGE_TEST_NS").is_some() {
            let chains = || -> Vec<String> {
                Nft::open()
                    .unwrap()
                    .chains(&Tab {
                        family: IP,
                        name: "shtest",
                    })
                    .unwrap()
                    .into_iter()
                    .map(|c| c.0)
                    .collect()
            };
            let mut other = sample();
            other.id = "beef".into();
            other.ports.clear();
            let a = &mut other.attachments[0];
            a.net.bridge = "shbr9".into();
            a.net.subnet = velarx_wire::addr::Subnet::parse("10.88.9.0/24").unwrap();
            a.net.gateway = "10.88.9.1".parse().unwrap();
            a.ip = "10.88.9.5".parse().unwrap();
            let fw = Firewall {
                table: "shtest".into(),
            };
            let mut nl = Netlink::open().unwrap();
            // another engine's bridge, its rules, no port yet
            nl.bridge_add("shbr9", 0, &owner_mark(&other.attachments[0].net))
                .unwrap();
            fw.setup(&other).unwrap();
            let state = tempfile::tempdir().unwrap();
            let opts = BridgeOptions {
                state_dir: state.path().to_path_buf(),
                firewall: fw,
                dns_exe: PathBuf::from("/bin/false"),
                netns: None,
            };
            remove_stale(&opts, &mut nl, &sample()).unwrap();
            assert!(
                chains().contains(&"shbr9-post".to_string()),
                "{:?}",
                chains()
            );
            // the bridge goes without its teardown: its rules are stale
            let idx = owned_bridge(&mut nl, "shbr9").unwrap();
            nl.link_del(idx).unwrap();
            remove_stale(&opts, &mut nl, &sample()).unwrap();
            assert!(
                !chains().contains(&"shbr9-post".to_string()),
                "{:?}",
                chains()
            );
            return;
        }
        let ok = std::process::Command::new("unshare")
            .args(["-rn", "true"])
            .output()
            .is_ok_and(|o| o.status.success());
        if !ok {
            eprintln!("skipped: no user and network namespaces");
            return;
        }
        let out = std::process::Command::new("unshare")
            .arg("-rn")
            .arg(std::env::current_exe().unwrap())
            .args(["--exact", NAME, "--nocapture"])
            .env("VELARX_BRIDGE_TEST_NS", "1")
            .output()
            .unwrap();
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(out.status.success(), "{text}");
        assert!(text.contains("1 passed"), "{text}");
    }

    /// The teardown of a container whose namespace is released leaves the
    /// host as it was before the container: no port on the bridge (the
    /// kernel took the veth down with the namespace, no delete of ours), no
    /// element of its ports in the firewall, no ARP entry; the bridge and
    /// the table stay until the network goes, and a second container needs
    /// no new bridge.  In a user, mount and network namespace of its own;
    /// skipped without one.
    #[test]
    fn a_released_namespace_leaves_the_bridge_and_the_table_without_the_container() {
        const NAME: &str = "bridge::tests::a_released_namespace_leaves_the_bridge_and_the_table_without_the_container";
        use crate::nftnl::{Nft, Tab, IP};
        if std::env::var_os("VELARX_BRIDGE_TEST_NS").is_some() {
            let tab = Tab {
                family: IP,
                name: "shtest",
            };
            let elements = |set: &str| Nft::open().unwrap().elements(&tab, set).unwrap().len();
            let state = tempfile::tempdir().unwrap();
            let opts = BridgeOptions {
                state_dir: state.path().to_path_buf(),
                firewall: Firewall {
                    table: "shtest".into(),
                },
                dns_exe: PathBuf::from("/bin/false"),
                netns: None,
            };
            let mut c = sample();
            c.attachments[0].net.dns = false;
            let mut nl = Netlink::open().unwrap();
            let first = setup_bridge(&mut nl, &c.attachments[0].net).unwrap();
            assert_eq!(setup_bridge(&mut nl, &c.attachments[0].net).unwrap(), first);
            for round in 0..2 {
                let ns = crate::netns::Netns::create().unwrap();
                let pin = ns.path();
                do_setup(&opts, &pin, &c).unwrap();
                let idx = owned_bridge(&mut nl, "shbr7").unwrap();
                assert_eq!(idx, first, "round {round}: the bridge of the first run");
                assert_eq!(nl.bridge_ports(idx).unwrap(), 1, "round {round}");
                assert_eq!(elements("published"), 1);
                assert!(elements("dnat_tcp") > 0);
                do_teardown(&opts, Some(&pin), &c, NetnsFate::Released).unwrap();
                drop(ns);
                // The ports of C are gone at once, its veth when the
                // kernel is done with the namespace: no wait of a timer.
                assert!(
                    nl.wait_bridge_empty(idx, std::time::Duration::from_secs(30))
                        .unwrap(),
                    "round {round}: the bridge still has a port"
                );
                assert_eq!(elements("published"), 0);
                assert_eq!(elements("dnat_tcp"), 0);
                assert_eq!(elements("net_post"), 2);
                assert_eq!(owned_bridge(&mut nl, "shbr7"), Some(idx), "same bridge");
                assert!(
                    nl.links().unwrap().iter().all(|l| l.kind != "veth"),
                    "a veth is left"
                );
                let arp = std::fs::read_to_string("/proc/net/arp").unwrap();
                assert!(!arp.contains("10.88.7.5"), "{arp}");
            }
            // The network goes: the bridge and the table with it.
            let n = c.attachments[0].net.clone();
            network_remove_here(&opts, &n).unwrap();
            assert!(owned_bridge(&mut nl, "shbr7").is_none());
            assert!(Nft::open().unwrap().chains(&tab).unwrap().is_empty());
            return;
        }
        let ok = std::process::Command::new("unshare")
            .args(["-rnm", "true"])
            .output()
            .is_ok_and(|o| o.status.success());
        if !ok {
            eprintln!("skipped: no user, mount and network namespaces");
            return;
        }
        let out = std::process::Command::new("unshare")
            .args(["-rnm"])
            .arg(std::env::current_exe().unwrap())
            .args(["--exact", NAME, "--nocapture"])
            .env("VELARX_BRIDGE_TEST_NS", "1")
            .output()
            .unwrap();
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(out.status.success(), "{text}");
        assert!(text.contains("1 passed"), "{text}");
    }

    pub(crate) fn sample() -> BridgeContainer {
        serde_json::from_str(
            r#"{"id": "c0ffee", "name": "web", "attachments": [{"net": {"name": "n", "bridge": "shbr7",
                "subnet": "10.88.7.0/24", "gateway": "10.88.7.1", "dns": true}, "ifname": "eth0",
                "ip": "10.88.7.5", "aliases": ["www"]}], "ports": ["8080-8081:80-81/tcp", "127.0.0.1:53:53/udp"]}"#,
        )
        .unwrap()
    }

    #[test]
    fn input_round_trip_and_validation() {
        let c = sample();
        c.validate().unwrap();
        assert_eq!(c.ports.len(), 2);
        let back: BridgeContainer =
            serde_json::from_str(&serde_json::to_string(&c).unwrap()).unwrap();
        assert_eq!(back, c);

        let mut bad = sample();
        bad.id = "../x".into();
        assert!(bad.validate().is_err());
        let mut bad = sample();
        bad.attachments[0].net.bridge = "bad name; drop".into();
        assert!(bad.validate().is_err());
        let mut bad = sample();
        bad.attachments[0].ip = "10.88.8.5".parse().unwrap();
        assert!(bad.validate().is_err());
        let mut bad = sample();
        bad.attachments[0].ip = "10.88.7.1".parse().unwrap();
        assert!(bad.validate().is_err());
        let mut bad = sample();
        bad.attachments[0].net.mtu = 9;
        assert!(bad.validate().is_err());
        let mut bad = sample();
        bad.attachments[0].mac = Some([1, 0, 0, 0, 0, 1]);
        assert!(bad.validate().is_err());
        let mut bad = sample();
        bad.ports = vec![PortSpec::parse("65535:80-81").unwrap_or(PortSpec {
            host_ip: None,
            host_port: 65535,
            container_port: 80,
            range: 2,
            proto: velarx_wire::addr::Proto::Tcp,
        })];
        assert!(bad.validate().is_err());
        assert!(serde_json::from_str::<BridgeContainer>(
            r#"{"id": "a", "attachments": [], "ports": ["x"]}"#
        )
        .is_err());
        assert!(serde_json::from_str::<BridgeContainer>("[]").is_err());
    }
}
