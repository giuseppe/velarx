// SPDX-License-Identifier: Apache-2.0
//! Addresses of bridge networks: IPv4 subnets and ranges, MAC addresses and
//! published ports (`-p`).  Pure parsing, shared by the client, the API and
//! the network setup.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// An IPv4 subnet, its address masked by its prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Subnet {
    pub addr: Ipv4Addr,
    pub prefix: u8,
}

impl Subnet {
    /// `A.B.C.D/P` with P in `min_prefix..=30`; the host bits are dropped.
    pub fn parse_with(s: &str, min_prefix: u8) -> Option<Self> {
        let (ip, prefix) = s.trim().split_once('/')?;
        let ip: Ipv4Addr = ip.parse().ok()?;
        if prefix.is_empty() || !prefix.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        let prefix: u8 = prefix.parse().ok()?;
        if prefix < min_prefix || prefix > 30 {
            return None;
        }
        Some(Self {
            addr: Ipv4Addr::from(u32::from(ip) & mask(prefix)),
            prefix,
        })
    }

    /// A subnet of a network: at least a /8.
    pub fn parse(s: &str) -> Option<Self> {
        Self::parse_with(s, 8)
    }

    pub fn network(&self) -> u32 {
        u32::from(self.addr)
    }

    pub fn broadcast(&self) -> u32 {
        self.network() | !mask(self.prefix)
    }

    pub fn contains(&self, ip: Ipv4Addr) -> bool {
        u32::from(ip) & mask(self.prefix) == self.network()
    }

    pub fn overlaps(&self, other: &Subnet) -> bool {
        self.contains(other.addr) || other.contains(self.addr)
    }

    /// Whether IP can be given to a container: in the subnet, neither the
    /// network nor the broadcast address.
    pub fn is_host(&self, ip: Ipv4Addr) -> bool {
        let v = u32::from(ip);
        self.contains(ip) && v != self.network() && v != self.broadcast()
    }

    /// The first host address, the default gateway.
    pub fn first_host(&self) -> Ipv4Addr {
        Ipv4Addr::from(self.network() + 1)
    }
}

impl fmt::Display for Subnet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix)
    }
}

fn mask(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - u32::from(prefix))
    }
}

/// An IPv6 subnet, its address masked by its prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Subnet6 {
    pub addr: Ipv6Addr,
    pub prefix: u8,
}

fn mask6(prefix: u8) -> u128 {
    if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - u32::from(prefix))
    }
}

impl Subnet6 {
    /// `ADDR/P` with P in 8..=124 (room for a gateway and containers); the
    /// host bits are dropped.
    pub fn parse(s: &str) -> Option<Self> {
        let (ip, prefix) = s.trim().split_once('/')?;
        let ip: Ipv6Addr = ip.parse().ok()?;
        if prefix.is_empty() || !prefix.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        let prefix: u8 = prefix.parse().ok()?;
        if !(8..=124).contains(&prefix) {
            return None;
        }
        Some(Self {
            addr: Ipv6Addr::from(u128::from(ip) & mask6(prefix)),
            prefix,
        })
    }

    /// A random unique local /64 (RFC 4193): `fdXX:XXXX:XXXX:XXXX::/64`.
    pub fn random_ula() -> std::io::Result<Self> {
        let mut b = [0u8; 7];
        rustix::rand::getrandom(&mut b, rustix::rand::GetRandomFlags::empty())?;
        let mut a = [0u8; 16];
        a[0] = 0xfd;
        a[1..8].copy_from_slice(&b);
        Ok(Self {
            addr: Ipv6Addr::from(a),
            prefix: 64,
        })
    }

    pub fn network(&self) -> u128 {
        u128::from(self.addr)
    }

    pub fn contains(&self, ip: Ipv6Addr) -> bool {
        u128::from(ip) & mask6(self.prefix) == self.network()
    }

    pub fn overlaps(&self, other: &Subnet6) -> bool {
        self.contains(other.addr) || other.contains(self.addr)
    }

    /// Whether IP can be given to a container: in the subnet, not the
    /// subnet-router anycast address (the network address).
    pub fn is_host(&self, ip: Ipv6Addr) -> bool {
        self.contains(ip) && u128::from(ip) != self.network()
    }

    /// The first host address, the default gateway.
    pub fn first_host(&self) -> Ipv6Addr {
        Ipv6Addr::from(self.network() + 1)
    }

    /// The last address of the subnet.
    pub fn last(&self) -> Ipv6Addr {
        Ipv6Addr::from(self.network() | !mask6(self.prefix))
    }
}

impl fmt::Display for Subnet6 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix)
    }
}

/// A range of addresses, `FIRST-LAST` or a CIDR, as its first and last
/// addresses.
pub fn parse_ip_range(s: &str) -> Option<(Ipv4Addr, Ipv4Addr)> {
    if let Some((a, b)) = s.split_once('-') {
        let (a, b): (Ipv4Addr, Ipv4Addr) = (a.trim().parse().ok()?, b.trim().parse().ok()?);
        return (u32::from(a) <= u32::from(b)).then_some((a, b));
    }
    let n = Subnet::parse_with(s, 1)?;
    Some((n.addr, Ipv4Addr::from(n.broadcast())))
}

/// A unicast MAC address `aa:bb:cc:dd:ee:ff`, not all zeros.
pub fn parse_mac(s: &str) -> Option<[u8; 6]> {
    let b = s.as_bytes();
    if b.len() != 17 {
        return None;
    }
    let mut mac = [0u8; 6];
    for (i, byte) in mac.iter_mut().enumerate() {
        let hex = std::str::from_utf8(&b[i * 3..i * 3 + 2]).ok()?;
        if !hex.bytes().all(|c| c.is_ascii_hexdigit()) {
            return None;
        }
        *byte = u8::from_str_radix(hex, 16).ok()?;
        if i < 5 && b[i * 3 + 2] != b':' {
            return None;
        }
    }
    (mac != [0; 6] && mac[0] & 1 == 0).then_some(mac)
}

pub fn format_mac(mac: &[u8; 6]) -> String {
    mac.iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// The MAC address Docker derives from an IPv4 address: `02:42:` and the
/// address, so that a container keeps it with its address.
pub fn derive_mac(ip: Ipv4Addr) -> [u8; 6] {
    let o = ip.octets();
    [0x02, 0x42, o[0], o[1], o[2], o[3]]
}

/// A valid interface name: what the kernel accepts, starting with a letter
/// and without the characters that would need quoting in a firewall rule
/// (the chains of a bridge are named after it).
pub fn valid_ifname(s: &str) -> bool {
    s.len() < 16
        && s.bytes().next().is_some_and(|c| c.is_ascii_alphabetic())
        && s.bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_' | b'.'))
}

/// The protocols of a published port.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Proto {
    Tcp,
    Udp,
    /// Accepted when parsing, refused when the network is set up.
    Sctp,
}

impl Proto {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "" | "tcp" => Some(Self::Tcp),
            "udp" => Some(Self::Udp),
            "sctp" => Some(Self::Sctp),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
            Self::Sctp => "sctp",
        }
    }
}

/// A published port: `RANGE` consecutive host ports to as many container
/// ports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortSpec {
    /// None: every address of the host.
    pub host_ip: Option<IpAddr>,
    /// 0 until a free one is picked when the host port was omitted.
    pub host_port: u16,
    pub container_port: u16,
    pub range: u16,
    pub proto: Proto,
}

/// A port or a range of them (`80`, `8000-8010`); the error is what podman
/// says after `parsing host port: `.
fn parse_port_range(s: &str) -> Result<(u16, u16), String> {
    let (a, b) = s.split_once('-').unwrap_or((s, s));
    let num = |p: &str| -> Result<u16, String> {
        if p.is_empty() || !p.bytes().all(|c| c.is_ascii_digit()) {
            return Err(format!(
                "invalid port number: strconv.Atoi: parsing {p:?}: invalid syntax"
            ));
        }
        p.parse::<u32>()
            .ok()
            .filter(|v| (1..=65535).contains(v))
            .map(|v| v as u16)
            .ok_or_else(|| format!("port numbers must be between 1 and 65535 (inclusive), got {p}"))
    };
    let (a, b) = (num(a)?, num(b)?);
    if b < a {
        return Err(format!(
            "invalid port range: the end {b} is before the start {a}"
        ));
    }
    Ok((a, b - a + 1))
}

impl PortSpec {
    /// `[[IP:][HOST[-END]]:]CONTAINER[-END][/PROTO]`, an IPv6 address in
    /// brackets (an IPv4 one may be).  The host port is 0 when it is omitted.
    pub fn parse(s: &str) -> Result<Self, String> {
        let bad = |what: &str| format!("invalid {what} in the port mapping `{s}`");
        let (addr, proto) = match s.rsplit_once('/') {
            Some((a, p)) => (a, Proto::parse(p).ok_or_else(|| bad("protocol"))?),
            None => (s, Proto::Tcp),
        };
        let mut rest = addr;
        let mut host_ip = None;
        if let Some(r) = rest.strip_prefix('[') {
            let (ip, tail) = r.split_once("]:").ok_or_else(|| bad("host address"))?;
            // (podman takes an IPv4 address in brackets too)
            host_ip = Some(ip.parse::<IpAddr>().map_err(|_| bad("host address"))?);
            rest = tail;
        }
        let parts: Vec<&str> = rest.split(':').collect();
        let (ip, host, container) = match (parts.as_slice(), host_ip.is_some()) {
            ([c], false) => ("", "", *c),
            ([h, c], _) => ("", *h, *c),
            ([i, h, c], false) => (*i, *h, *c),
            _ => return Err(format!("invalid port mapping `{s}`")),
        };
        if !ip.is_empty() {
            host_ip = Some(ip.parse().map_err(|_| bad("host address"))?);
        }
        let (container_port, range) =
            parse_port_range(container).map_err(|e| format!("parsing container port: {e}"))?;
        let host_port = if host.is_empty() {
            0
        } else {
            let (h, n) = parse_port_range(host).map_err(|e| format!("parsing host port: {e}"))?;
            if n != range {
                return Err(format!("the port ranges in `{s}` have different sizes"));
            }
            h
        };
        if host_ip.is_some_and(|i| i.is_unspecified()) {
            host_ip = None;
        }
        Ok(Self {
            host_ip,
            host_port,
            container_port,
            range,
            proto,
        })
    }

    /// The mapping of each port of the range, the host port picked by the
    /// daemon when it was omitted.
    pub fn mappings(&self) -> Vec<crate::request::PortMapping> {
        let host_ip = self.host_ip.map(|ip| ip.to_string()).unwrap_or_default();
        (0..self.range)
            .map(|k| crate::request::PortMapping {
                container_port: self.container_port + k,
                host_port: (self.host_port != 0).then(|| self.host_port + k),
                host_ip: host_ip.clone(),
                protocol: self.proto.as_str().to_string(),
            })
            .collect()
    }

    /// One port of a mapping from the API.
    pub fn single(
        host_ip: &str,
        host_port: Option<u16>,
        container_port: u16,
        proto: &str,
    ) -> Result<Self, String> {
        let bad =
            || format!("invalid port mapping {host_ip}:{host_port:?}:{container_port}/{proto}");
        if container_port == 0 || host_port == Some(0) {
            return Err(bad());
        }
        let host_ip = match host_ip.trim_matches(|c| c == '[' || c == ']') {
            "" => None,
            ip => Some(ip.parse::<IpAddr>().map_err(|_| bad())?).filter(|i| !i.is_unspecified()),
        };
        Ok(Self {
            host_ip,
            host_port: host_port.unwrap_or(0),
            container_port,
            range: 1,
            proto: Proto::parse(proto).ok_or_else(bad)?,
        })
    }

    pub fn last_host_port(&self) -> u32 {
        u32::from(self.host_port) + u32::from(self.range) - 1
    }
}

impl fmt::Display for PortSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.host_ip {
            Some(IpAddr::V6(ip)) => write!(f, "[{ip}]:")?,
            Some(IpAddr::V4(ip)) => write!(f, "{ip}:")?,
            None => {}
        }
        let span = |p: u16| {
            if self.range > 1 {
                format!("{}-{}", p, u32::from(p) + u32::from(self.range) - 1)
            } else {
                p.to_string()
            }
        };
        write!(
            f,
            "{}:{}/{}",
            span(self.host_port),
            span(self.container_port),
            self.proto.as_str()
        )
    }
}

/// Bind PORT (0: any free one) for the protocol on the address; returns the
/// socket that holds it and the port.
fn bind_port(
    ip: Option<IpAddr>,
    proto: Proto,
    port: u16,
) -> std::io::Result<(std::os::fd::OwnedFd, u16)> {
    use rustix::net::{bind, getsockname, AddressFamily, SocketAddrAny, SocketType};
    let ip = ip.unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
    let family = if ip.is_ipv6() {
        AddressFamily::INET6
    } else {
        AddressFamily::INET
    };
    let ty = match proto {
        Proto::Tcp => SocketType::STREAM,
        Proto::Udp => SocketType::DGRAM,
        Proto::Sctp => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "can't forward protocol: sctp",
            ))
        }
    };
    // Not inherited: the runtime, the container or any child would keep
    // the port after the monitor released it.
    let fd = rustix::net::socket_with(family, ty, rustix::net::SocketFlags::CLOEXEC, None)?;
    bind(&fd, &std::net::SocketAddr::new(ip, port))?;
    let bound: SocketAddrAny = getsockname(&fd)?;
    let bound = std::net::SocketAddr::try_from(bound)
        .map_err(|_| std::io::Error::other("unexpected socket address"))?;
    Ok((fd, bound.port()))
}

/// The soft limit of open files lets the process hold a socket for each
/// port of PORTS besides what it has open, and what it opens after them:
/// raised to that if it does not (a long range of ports is more than the
/// 1024 of a shell).
fn room_for_ports<'a>(ports: impl Iterator<Item = &'a PortSpec>) -> std::io::Result<()> {
    let count: u64 = ports.map(|p| u64::from(p.range)).sum();
    let open = std::fs::read_dir("/proc/self/fd").map_or(0, |d| d.count() as u64);
    let needed = open + count + velarx_base::hardening::OPEN_FILES_BASE;
    velarx_base::hardening::ensure_open_files(needed).map_err(|e| {
        std::io::Error::other(format!(
            "{count} published ports need {} open files, more than the hard limit {}: raise it (`ulimit -Hn`, `LimitNOFILE=` of the unit)",
            e.needed,
            e.hard.unwrap_or_default()
        ))
    })
}

/// Bind every host port of PORTS, for as long as the sockets live: the
/// port of a service of the host is refused (`address in use`).
pub fn hold_ports(ports: &[PortSpec]) -> std::io::Result<Vec<std::os::fd::OwnedFd>> {
    room_for_ports(ports.iter())?;
    let mut held = Vec::new();
    for p in ports {
        for k in 0..p.range {
            let port = p
                .host_port
                .checked_add(k)
                .filter(|v| *v != 0)
                .ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!("invalid port mapping `{p}`"),
                    )
                })?;
            let (fd, _) = bind_port(p.host_ip, p.proto, port).map_err(|e| {
                std::io::Error::new(
                    e.kind(),
                    format!(
                        "cannot publish the host port {port}/{}: {e}",
                        p.proto.as_str()
                    ),
                )
            })?;
            held.push(fd);
        }
    }
    Ok(held)
}

/// Pick free host ports for the mappings without one: RANGE consecutive
/// ports each.  The ports stay bound until all are picked, so that two
/// mappings never get the same.
pub fn resolve_free_ports(ports: &mut [PortSpec]) -> std::io::Result<()> {
    room_for_ports(ports.iter().filter(|p| p.host_port == 0))?;
    let mut held = Vec::new();
    for p in ports.iter_mut().filter(|p| p.host_port == 0) {
        let mut found = false;
        for _ in 0..64 {
            let (fd, first) = bind_port(p.host_ip, p.proto, 0).map_err(|e| {
                std::io::Error::new(
                    e.kind(),
                    format!(
                        "cannot find a free host port for the container port {}/{}: {e}",
                        p.container_port,
                        p.proto.as_str()
                    ),
                )
            })?;
            let mut group = vec![fd];
            for k in 1..p.range {
                let Some(port) = first.checked_add(k) else {
                    break;
                };
                match bind_port(p.host_ip, p.proto, port) {
                    Ok((fd, _)) => group.push(fd),
                    Err(_) => break,
                }
            }
            if group.len() == usize::from(p.range) {
                p.host_port = first;
                held.extend(group);
                found = true;
                break;
            }
        }
        if !found {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AddrInUse,
                format!("cannot find {} free consecutive host ports", p.range),
            ));
        }
    }
    Ok(())
}

/// A static route of a network (`--route DESTINATION,GATEWAY[,METRIC]`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Route {
    pub destination: IpAddr,
    pub prefix: u8,
    pub gateway: IpAddr,
    pub metric: Option<u32>,
}

impl Route {
    /// podman's checks and words; the destination must be a network
    /// address (no host bits).
    pub fn parse(s: &str) -> Result<Self, String> {
        let parts: Vec<&str> = s.split(',').collect();
        if !(2..=3).contains(&parts.len()) {
            return Err(format!(
                "invalid route: {s}\nFormat: --route <destination in CIDR>,<gateway>,<metric (optional)>"
            ));
        }
        let bad_destination = || format!("invalid route destination {}", parts[0]);
        let (ip, prefix) = parts[0].split_once('/').ok_or_else(bad_destination)?;
        let destination: IpAddr = ip.parse().map_err(|_| bad_destination())?;
        let prefix: u8 = prefix.parse().map_err(|_| bad_destination())?;
        let (width, bits) = match destination {
            IpAddr::V4(a) => (32, u128::from(u32::from(a))),
            IpAddr::V6(a) => (128, u128::from(a)),
        };
        if u32::from(prefix) > width {
            return Err(bad_destination());
        }
        let host = width - u32::from(prefix);
        if host > 0 && bits & (u128::MAX >> (128 - host)) != 0 {
            return Err("route destination invalid".into());
        }
        let gateway = parts[1]
            .parse()
            .map_err(|_| format!("invalid route gateway {}", parts[1]))?;
        let metric = match parts.get(2) {
            Some(m) => Some(m.parse().map_err(|_| format!("invalid route metric {m}"))?),
            None => None,
        };
        Ok(Self {
            destination,
            prefix,
            gateway,
            metric,
        })
    }
}

impl fmt::Display for Route {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{},{}", self.destination, self.prefix, self.gateway)?;
        if let Some(m) = self.metric {
            write!(f, ",{m}")?;
        }
        Ok(())
    }
}

/// The subnets and gateways of a create, by family.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Subnets {
    pub subnet: Option<String>,
    pub gateway: Option<String>,
    pub subnet6: Option<String>,
    pub gateway6: Option<String>,
}

/// Split SUBNETS (and the GATEWAYS given in the same positions) by family:
/// one IPv4 and one IPv6 subnet at most.
pub fn split_subnets(subnets: &[String], gateways: &[String]) -> Result<Subnets, String> {
    if gateways.len() > subnets.len() {
        return Err("a gateway needs a subnet".into());
    }
    let mut out = Subnets::default();
    for (i, s) in subnets.iter().map(|s| s.trim()).enumerate() {
        let gw = gateways
            .get(i)
            .map(|g| g.trim().to_string())
            .filter(|g| !g.is_empty());
        let v6 = s.contains(':');
        if gw.as_deref().is_some_and(|g| g.contains(':') != v6) {
            return Err(format!(
                "the gateway of the subnet `{s}` is not of its family"
            ));
        }
        let (slot, gslot) = if v6 {
            (&mut out.subnet6, &mut out.gateway6)
        } else {
            (&mut out.subnet, &mut out.gateway)
        };
        if slot.is_some() {
            return Err(format!(
                "at most one IPv{} subnet per network",
                if v6 { 6 } else { 4 }
            ));
        }
        *slot = Some(s.to_string());
        *gslot = gw;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    #[test]
    fn sctp_ports_parse_and_cannot_be_held() {
        let p = PortSpec::parse("8080:80/sctp").unwrap();
        assert_eq!(p.proto, Proto::Sctp);
        assert_eq!(p.to_string(), "8080:80/sctp");
        let e = bind_port(None, Proto::Sctp, 0).unwrap_err();
        assert!(e.to_string().contains("can't forward protocol: sctp"));
    }

    #[test]
    fn routes() {
        let r = Route::parse("10.0.0.0/24,10.89.5.5,100").unwrap();
        assert_eq!(r.to_string(), "10.0.0.0/24,10.89.5.5,100");
        assert_eq!(Route::parse("0.0.0.0/0,10.89.5.5").unwrap().prefix, 0);
        assert_eq!(
            Route::parse("fd00:1::/64,fd00::1").unwrap().to_string(),
            "fd00:1::/64,fd00::1"
        );
        for (s, e) in [
            ("bad", "invalid route: bad\nFormat: --route"),
            ("10.0.0.0/24", "invalid route: 10.0.0.0/24"),
            ("10.0.0.0/24,1,2,3", "invalid route: "),
            ("x,10.89.5.5", "invalid route destination x"),
            ("10.0.0.0,10.89.5.5", "invalid route destination 10.0.0.0"),
            (
                "10.0.0.0/33,10.89.5.5",
                "invalid route destination 10.0.0.0/33",
            ),
            ("10.0.0.1/24,10.89.5.5", "route destination invalid"),
            ("10.0.0.0/24,x", "invalid route gateway x"),
            ("10.0.0.0/24,10.89.5.5,-1", "invalid route metric -1"),
        ] {
            let got = Route::parse(s).unwrap_err();
            assert!(got.starts_with(e), "{s}: {got}");
        }
    }

    #[test]
    fn ipv6_subnets() {
        let s = Subnet6::parse("fd12:3456:789a:1::5/64").unwrap();
        assert_eq!(s.to_string(), "fd12:3456:789a:1::/64");
        assert_eq!(s.first_host().to_string(), "fd12:3456:789a:1::1");
        assert!(s.is_host("fd12:3456:789a:1::2".parse().unwrap()));
        assert!(!s.is_host("fd12:3456:789a:1::".parse().unwrap()));
        assert!(!s.contains("fd12:3456:789a:2::1".parse().unwrap()));
        assert_eq!(s.last().to_string(), "fd12:3456:789a:1:ffff:ffff:ffff:ffff");
        let wide = Subnet6::parse("fd12:3456::/32").unwrap();
        assert!(wide.overlaps(&s) && s.overlaps(&wide));
        for bad in [
            "fd12::/7",
            "fd12::/125",
            "fd12::",
            "10.0.0.0/24",
            "fd12::/x",
            "fd12::/",
        ] {
            assert!(Subnet6::parse(bad).is_none(), "{bad}");
        }
        let u = Subnet6::random_ula().unwrap();
        assert_eq!(u.prefix, 64);
        assert_eq!(u.addr.octets()[0], 0xfd);
        assert_eq!(&u.addr.octets()[8..], &[0; 8]);
    }

    use super::*;

    #[test]
    fn subnets() {
        let s = Subnet::parse("10.88.7.9/24").unwrap();
        assert_eq!(s.to_string(), "10.88.7.0/24");
        assert_eq!(s.first_host(), Ipv4Addr::new(10, 88, 7, 1));
        assert!(s.is_host("10.88.7.254".parse().unwrap()));
        assert!(!s.is_host("10.88.7.255".parse().unwrap()));
        assert!(!s.is_host("10.88.7.0".parse().unwrap()));
        assert!(!s.is_host("10.88.8.1".parse().unwrap()));
        assert!(s.overlaps(&Subnet::parse("10.88.0.0/16").unwrap()));
        assert!(!s.overlaps(&Subnet::parse("10.88.8.0/24").unwrap()));
        for bad in [
            "10.0.0.0",
            "10.0.0.0/31",
            "10.0.0.0/7",
            "10.0.0.0/+8",
            "x/24",
            "10.0.0/24",
            "10.0.0.0/",
        ] {
            assert!(Subnet::parse(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn ranges() {
        let ip = |s: &str| s.parse::<Ipv4Addr>().unwrap();
        assert_eq!(
            parse_ip_range("10.0.0.100-10.0.0.110"),
            Some((ip("10.0.0.100"), ip("10.0.0.110")))
        );
        assert_eq!(
            parse_ip_range("10.0.0.128/25"),
            Some((ip("10.0.0.128"), ip("10.0.0.255")))
        );
        assert!(parse_ip_range("10.0.0.9-10.0.0.1").is_none());
        assert!(parse_ip_range("bogus").is_none());
    }

    #[test]
    fn macs() {
        assert_eq!(
            parse_mac("02:42:0A:58:07:05"),
            Some([2, 0x42, 10, 0x58, 7, 5])
        );
        for bad in [
            "01:00:5e:00:00:01",
            "00:00:00:00:00:00",
            "02:42:0a:58:07",
            "02:42:0a:58:07:5",
            "02-42-0a-58-07-05",
            "02:42:0a:58:07:0g",
            " 2:42:0a:58:07:05",
            "02:42:0a:58:07:05 ",
            "+2:42:0a:58:07:05",
        ] {
            assert!(parse_mac(bad).is_none(), "{bad}");
        }
        assert_eq!(
            format_mac(&derive_mac(Ipv4Addr::new(10, 124, 0, 60))),
            "02:42:0a:7c:00:3c"
        );
    }

    #[test]
    fn interface_names() {
        assert!(valid_ifname("velarx0"));
        assert!(valid_ifname("br-1.2_x"));
        for bad in [
            "",
            "a234567890123456",
            "bad name",
            "a;b",
            "a\"b",
            "..",
            "a/b",
            "0br",
            "-x",
        ] {
            assert!(!valid_ifname(bad), "{bad}");
        }
    }

    #[test]
    fn ports() {
        let p = PortSpec::parse("8080:80").unwrap();
        assert_eq!(
            (p.host_ip, p.host_port, p.container_port, p.range, p.proto),
            (None, 8080, 80, 1, Proto::Tcp)
        );
        let p = PortSpec::parse("127.0.0.1:8000-8001:80-81/udp").unwrap();
        assert_eq!(p.host_ip, Some("127.0.0.1".parse().unwrap()));
        assert_eq!(
            (p.host_port, p.container_port, p.range, p.proto),
            (8000, 80, 2, Proto::Udp)
        );
        assert_eq!(p.to_string(), "127.0.0.1:8000-8001:80-81/udp");
        let p = PortSpec::parse("80").unwrap();
        assert_eq!((p.host_port, p.container_port), (0, 80));
        let p = PortSpec::parse("127.0.0.1::80").unwrap();
        assert_eq!((p.host_port, p.container_port), (0, 80));
        let p = PortSpec::parse("[::1]:8080:80").unwrap();
        assert_eq!(p.to_string(), "[::1]:8080:80/tcp");
        assert_eq!(PortSpec::parse("0.0.0.0:1:2").unwrap().host_ip, None);
        for bad in [
            "",
            "0",
            "65536",
            "1-2:80",
            "a:80",
            "1:2:3:4",
            "x.y:80:80",
            "80-79",
            "+80",
            "[::1]80",
        ] {
            assert!(PortSpec::parse(bad).is_err(), "{bad}");
        }
        // podman's words for a port that is not one
        assert_eq!(
            PortSpec::parse("99999:80").unwrap_err(),
            "parsing host port: port numbers must be between 1 and 65535 (inclusive), got 99999"
        );
        assert_eq!(
            PortSpec::parse("80:abc").unwrap_err(),
            "parsing container port: invalid port number: strconv.Atoi: parsing \"abc\": invalid syntax"
        );
        assert!(PortSpec::single("", Some(8080), 80, "tcp").is_ok());
        assert!(PortSpec::single("", Some(0), 80, "tcp").is_err());
        assert!(PortSpec::single("nope", None, 80, "tcp").is_err());
        assert!(PortSpec::single("", None, 80, "sctp").is_ok());
        assert!(PortSpec::single("", None, 80, "icmp").is_err());
    }

    // (in a child of its own: a process another test of this binary starts
    // holds a copy of every descriptor between its fork and its exec, and
    // with it the port that was just released)
    #[test]
    fn held_ports_are_refused_to_others() {
        velarx_base::testing::in_child(|| {
            // Ports below the ephemeral range: once released, no socket of
            // another process gets them by chance.
            let (p, held) = (20000..32000u16)
                .step_by(2)
                .find_map(|port| {
                    let p = vec![
                        PortSpec::parse(&format!("127.0.0.1:{port}-{}:90-91", port + 1)).unwrap(),
                    ];
                    hold_ports(&p).ok().map(|h| (p, h))
                })
                .unwrap();
            assert_eq!(held.len(), 2);
            let e = hold_ports(&p).unwrap_err();
            assert_eq!(e.kind(), std::io::ErrorKind::AddrInUse);
            assert!(e.to_string().contains("cannot publish the host port"));
            drop(held);
            assert!(
                hold_ports(&p).is_ok(),
                "the ports are still held after the drop"
            );
        });
    }

    /// A range of ports longer than the soft limit of open files is held:
    /// the limit is raised for its sockets.
    #[test]
    fn a_range_over_the_soft_limit_of_open_files_is_held() {
        velarx_base::testing::in_child(|| {
            let hard = rustix::process::getrlimit(rustix::process::Resource::Nofile).maximum;
            if hard.is_some_and(|h| h < 1024) {
                eprintln!("SKIPPED: a hard limit of open files under 1024");
                return;
            }
            rustix::process::setrlimit(
                rustix::process::Resource::Nofile,
                rustix::process::Rlimit {
                    current: Some(128),
                    maximum: hard,
                },
            )
            .unwrap();
            let mut ports = vec![PortSpec::parse("127.0.0.1::1-300/udp").unwrap()];
            resolve_free_ports(&mut ports).unwrap();
            assert_eq!(hold_ports(&ports).unwrap().len(), 300);
        });
    }

    /// `-P` of an image that exposes more ports than the host has free
    /// ones ends with an error that names the port, not with the bare one
    /// of the socket.
    #[test]
    fn a_port_with_no_free_host_port_is_named() {
        // (an address of no host: no port of it can be bound)
        let mut ports = vec![PortSpec::parse("192.0.2.1::8080/udp").unwrap()];
        let e = resolve_free_ports(&mut ports).unwrap_err().to_string();
        assert!(
            e.starts_with("cannot find a free host port for the container port 8080/udp: "),
            "{e}"
        );
    }

    #[test]
    fn free_ports_are_distinct() {
        let mut ports = vec![
            PortSpec::parse("127.0.0.1::80-82").unwrap(),
            PortSpec::parse("127.0.0.1::90").unwrap(),
            PortSpec::parse("127.0.0.1:5:5").unwrap(),
        ];
        resolve_free_ports(&mut ports).unwrap();
        assert_ne!(ports[0].host_port, 0);
        assert_ne!(ports[1].host_port, 0);
        let first = u32::from(ports[0].host_port)..=ports[0].last_host_port();
        assert!(!first.contains(&u32::from(ports[1].host_port)));
        assert_eq!(ports[2].host_port, 5);
    }

    #[test]
    fn a_host_address_in_brackets_may_be_ipv4() {
        let p = PortSpec::parse("[127.0.0.1]:5030:5030/udp").unwrap();
        assert_eq!(p.host_ip, Some("127.0.0.1".parse().unwrap()));
        assert_eq!(
            (p.host_port, p.container_port, p.proto),
            (5030, 5030, Proto::Udp)
        );
        assert!(PortSpec::parse("[::1]:80:80")
            .unwrap()
            .host_ip
            .unwrap()
            .is_ipv6());
        assert!(PortSpec::parse("[nope]:80:80").is_err());
    }
}
