// SPDX-License-Identifier: Apache-2.0
//! Where the node dials.
//!
//! The addresses a node dials come from many sources: a provider record of
//! the DHT, the listen addresses a peer tells in identify, the peers a peer
//! names in an exchange.  Some can never be a peer's: loopback, link-local,
//! multicast, unspecified and reserved addresses, and the addresses of the
//! interfaces of the node itself.
//!
//! One filter is applied at the transport, so that it holds for every source
//! of an address (the DHT, gossip, identify, the exchange of peers, mDNS, the
//! retry of the bootstrap peers) and for the QUIC endpoint.  Private ranges are
//! allowed: clusters live there.  `dial_allow` lets addresses through those
//! refusals (a swarm on one host allows 127.0.0.0/8).  The bootstrap peers the
//! operator named are exempt from all of it.
//!
//! An address is judged as the TCP transport reads it, and only one of the
//! form that transport dials is let through (`/ip4|ip6/ADDRESS/tcp/PORT`,
//! then at most a `/p2p/ID`): libp2p's TCP transport reads the last IP
//! address and port of a multiaddress, so a filter that judged another part
//! of it would judge something else than what is dialed.  A name
//! (`/dns4/...`) is refused too: the node dials no name (it has no DNS
//! transport).  Port 0 is no port of a peer.

use crate::stats::Counters;
use ipnet::IpNet;
use libp2p::core::transport::{DialOpts, ListenerId, TransportError, TransportEvent};
use libp2p::core::Transport;
use libp2p::multiaddr::Protocol;
use libp2p::Multiaddr;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::time::Instant;
use tracing::debug;

/// Why a dial was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Refusal {
    Loopback,
    LinkLocal,
    Multicast,
    Unspecified,
    Reserved,
    /// An address of one of this node's interfaces
    OwnInterface,
    /// Not an IP address and a TCP port the node dials (a name, an address
    /// in an address, port 0)
    Unsupported,
}

impl Refusal {
    pub fn name(self) -> &'static str {
        match self {
            Refusal::Loopback => "loopback",
            Refusal::LinkLocal => "link-local",
            Refusal::Multicast => "multicast",
            Refusal::Unspecified => "unspecified",
            Refusal::Reserved => "reserved",
            Refusal::OwnInterface => "own-interface",
            Refusal::Unsupported => "unsupported",
        }
    }
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "refused: {} address", self.name())
    }
}

impl std::error::Error for Refusal {}

/// What the settings say beyond the defaults.
#[derive(Debug, Clone, Default)]
pub struct Rules {
    /// Networks let through the default refusals
    pub allow: Vec<IpNet>,
}

impl Rules {
    /// The rules of nodes that run on one host (a test, a laptop): loopback
    /// is allowed.
    pub fn on_one_host() -> Self {
        Self {
            allow: vec![
                "127.0.0.0/8".parse().expect("a network"),
                "::1/128".parse().expect("a network"),
            ],
        }
    }
}

/// The addresses of the interfaces of the node, asked again when the last
/// answer is old: an interface comes and goes (a bridge, a VPN).
const OWN_VALID: Duration = Duration::from_secs(5);

type OwnAddresses = Box<dyn Fn() -> Vec<IpAddr> + Send + Sync>;

pub struct DialFilter {
    rules: Rules,
    /// The bootstrap peers: an address and the port of its TCP endpoint
    exempt: Vec<(IpAddr, u16)>,
    own: OwnAddresses,
    seen: Mutex<Option<(Instant, Vec<IpAddr>)>>,
    counters: Arc<Counters>,
}

impl DialFilter {
    /// The filter of a node that has `bootstrap` named (exempt), counting
    /// what it refuses in `counters`.
    pub(crate) fn new(rules: Rules, bootstrap: &[Multiaddr], counters: Arc<Counters>) -> Self {
        Self::with_own(rules, bootstrap, counters, Box::new(interface_addresses))
    }

    /// The same, with the addresses of the interfaces from `own`.
    pub(crate) fn with_own(
        rules: Rules,
        bootstrap: &[Multiaddr],
        counters: Arc<Counters>,
        own: OwnAddresses,
    ) -> Self {
        Self {
            rules,
            exempt: bootstrap
                .iter()
                .filter_map(|a| tcp_target(a).ok())
                .map(|(ip, port)| (canonical(ip), port))
                .collect(),
            own,
            seen: Mutex::new(None),
            counters,
        }
    }

    /// A filter that refuses nothing: for what dials only what its caller
    /// names (the tests of a transport).
    pub fn allow_all() -> Self {
        Self::with_own(
            Rules {
                allow: vec![
                    "0.0.0.0/0".parse().expect("a network"),
                    "::/0".parse().expect("a network"),
                ],
            },
            &[],
            Arc::default(),
            Box::new(Vec::new),
        )
    }

    /// Whether the node may dial `addr` over TCP: an IP address and a port
    /// (`tcp_target`), counted and logged when not.
    pub fn check(&self, addr: &Multiaddr) -> Result<(), Refusal> {
        match tcp_target(addr) {
            Ok((ip, port)) => self.check_at(ip, Some(port)),
            Err(reason) => {
                self.counters.dial_refused(reason);
                debug!(%addr, reason = reason.name(), "dial refused");
                Err(reason)
            }
        }
    }

    /// Whether the node may dial `ip` (any port: the QUIC endpoint of a peer
    /// it is connected to), counted and logged when not.
    pub fn check_ip(&self, ip: IpAddr) -> Result<(), Refusal> {
        self.check_at(ip, None)
    }

    /// Whether the node may dial `ip` at TCP port `port` (not known: any),
    /// counted and logged when not.
    fn check_at(&self, ip: IpAddr, port: Option<u16>) -> Result<(), Refusal> {
        let ip = canonical(ip);
        let verdict = self.judge_at(ip, port);
        if let Err(reason) = verdict {
            self.counters.dial_refused(reason);
            debug!(%ip, reason = reason.name(), "dial refused");
        }
        verdict
    }

    /// The verdict for an address, not counted.
    pub fn judge(&self, ip: IpAddr) -> Result<(), Refusal> {
        self.judge_at(ip, None)
    }

    fn judge_at(&self, ip: IpAddr, port: Option<u16>) -> Result<(), Refusal> {
        let ip = canonical(ip);
        // (a bootstrap peer is its address and port, not every port of the host)
        if self
            .exempt
            .iter()
            .any(|(e, p)| *e == ip && port.is_none_or(|port| port == *p))
        {
            return Ok(());
        }
        if self.rules.allow.iter().any(|n| n.contains(&ip)) {
            return Ok(());
        }
        if let Some(reason) = class(ip) {
            return Err(reason);
        }
        if self.is_own(ip) {
            return Err(Refusal::OwnInterface);
        }
        Ok(())
    }

    fn is_own(&self, ip: IpAddr) -> bool {
        let mut seen = self.seen.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        if seen
            .as_ref()
            .is_none_or(|(at, _)| now.duration_since(*at) >= OWN_VALID)
        {
            *seen = Some((now, (self.own)().into_iter().map(canonical).collect()));
        }
        seen.as_ref().is_some_and(|(_, own)| own.contains(&ip))
    }
}

/// An IPv4 address in its IPv6 mapped form is the IPv4 address.
fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        v4 => v4,
    }
}

/// What an address is that no node of a swarm is reached at.
fn class(ip: IpAddr) -> Option<Refusal> {
    match ip {
        IpAddr::V4(ip) => class4(ip),
        IpAddr::V6(ip) => class6(ip),
    }
}

fn class4(ip: Ipv4Addr) -> Option<Refusal> {
    let [a, ..] = ip.octets();
    if ip.is_loopback() {
        Some(Refusal::Loopback)
    } else if a == 0 {
        // ("this network": 0.0.0.0/8)
        Some(Refusal::Unspecified)
    } else if ip.is_link_local() {
        Some(Refusal::LinkLocal)
    } else if ip.is_multicast() {
        Some(Refusal::Multicast)
    } else if a >= 240 {
        // (class E, and the broadcast address)
        Some(Refusal::Reserved)
    } else {
        None
    }
}

fn class6(ip: Ipv6Addr) -> Option<Refusal> {
    if ip.is_loopback() {
        Some(Refusal::Loopback)
    } else if ip.is_unspecified() {
        Some(Refusal::Unspecified)
    } else if ip.is_unicast_link_local() {
        Some(Refusal::LinkLocal)
    } else if ip.is_multicast() {
        Some(Refusal::Multicast)
    } else {
        None
    }
}

/// The IP address in a multiaddress.
pub fn ip_of(addr: &Multiaddr) -> Option<IpAddr> {
    addr.iter().find_map(|p| match p {
        Protocol::Ip4(ip) => Some(IpAddr::V4(ip)),
        Protocol::Ip6(ip) => Some(IpAddr::V6(ip)),
        _ => None,
    })
}

/// Where the TCP transport connects for `addr`: only an address that is an
/// IP address, a TCP port and at most the peer's id (`/p2p/ID`) is one,
/// so that what is judged is what is dialed (libp2p's TCP transport reads
/// the last IP address and port of an address, whatever comes before).
fn tcp_target(addr: &Multiaddr) -> Result<(IpAddr, u16), Refusal> {
    let mut parts = addr.iter();
    let ip = match parts.next() {
        Some(Protocol::Ip4(ip)) => IpAddr::V4(ip),
        Some(Protocol::Ip6(ip)) => IpAddr::V6(ip),
        _ => return Err(Refusal::Unsupported),
    };
    let port = match parts.next() {
        Some(Protocol::Tcp(port)) if port != 0 => port,
        _ => return Err(Refusal::Unsupported),
    };
    match (parts.next(), parts.next()) {
        (None, _) | (Some(Protocol::P2p(_)), None) => Ok((ip, port)),
        _ => Err(Refusal::Unsupported),
    }
}

/// The addresses of the interfaces of this host (the kernel's table).  The
/// IPv6 addresses that are not global are refused by their class already.
pub fn interface_addresses() -> Vec<IpAddr> {
    let Ok(mut netlink) = velarx_netkernel::netlink::Netlink::open() else {
        return Vec::new();
    };
    let v4 = netlink.addresses().unwrap_or_default();
    let v6 = netlink.global_addresses6().unwrap_or_default();
    v4.into_iter()
        .map(|(_, a, _)| IpAddr::V4(a))
        .chain(v6.into_iter().map(|(_, a, _)| IpAddr::V6(a)))
        .collect()
}

/// A transport that dials only what the filter lets through; everything else
/// is the transport's own.  The refusal is an error of the dial that names
/// the reason ([`Refusal`]).
pub struct Filtered<T> {
    inner: T,
    filter: Arc<DialFilter>,
}

impl<T> Filtered<T> {
    pub fn new(inner: T, filter: Arc<DialFilter>) -> Self {
        Self { inner, filter }
    }
}

impl<T> Transport for Filtered<T>
where
    T: Transport<Error = std::io::Error> + Unpin,
{
    type Output = T::Output;
    type Error = std::io::Error;
    type ListenerUpgrade = T::ListenerUpgrade;
    type Dial = T::Dial;

    fn listen_on(
        &mut self,
        id: ListenerId,
        addr: Multiaddr,
    ) -> Result<(), TransportError<Self::Error>> {
        self.inner.listen_on(id, addr)
    }

    fn remove_listener(&mut self, id: ListenerId) -> bool {
        self.inner.remove_listener(id)
    }

    fn dial(
        &mut self,
        addr: Multiaddr,
        opts: DialOpts,
    ) -> Result<Self::Dial, TransportError<Self::Error>> {
        if let Err(reason) = self.filter.check(&addr) {
            return Err(TransportError::Other(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                reason,
            )));
        }
        self.inner.dial(addr, opts)
    }

    fn poll(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<TransportEvent<Self::ListenerUpgrade, Self::Error>> {
        Pin::new(&mut self.get_mut().inner).poll(cx)
    }
}

/// Whether `e`, the error of a dial, is a refusal of the filter, and why.
pub fn refusal_in(e: &libp2p::swarm::DialError) -> Option<Refusal> {
    let libp2p::swarm::DialError::Transport(all) = e else {
        return None;
    };
    all.iter().find_map(|(_, e)| match e {
        TransportError::Other(e) => e
            .get_ref()
            .and_then(|i| i.downcast_ref::<Refusal>())
            .copied(),
        _ => None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn filter(rules: Rules, own: &[&str], bootstrap: &[&str]) -> (DialFilter, Arc<Counters>) {
        let counters = Arc::new(Counters::default());
        let own: Vec<IpAddr> = own.iter().map(|a| a.parse().unwrap()).collect();
        let bootstrap: Vec<Multiaddr> = bootstrap.iter().map(|a| a.parse().unwrap()).collect();
        (
            DialFilter::with_own(
                rules,
                &bootstrap,
                counters.clone(),
                Box::new(move || own.clone()),
            ),
            counters,
        )
    }

    fn net(s: &str) -> IpNet {
        s.parse().unwrap()
    }

    fn judge(f: &DialFilter, ip: &str) -> Result<(), Refusal> {
        f.judge(ip.parse().unwrap())
    }

    #[test]
    fn what_no_node_is_reached_at_is_refused_and_the_ranges_of_clusters_are_not() {
        let (f, _) = filter(Rules::default(), &[], &[]);
        for (ip, reason) in [
            ("127.0.0.1", Refusal::Loopback),
            ("127.1.2.3", Refusal::Loopback),
            ("::1", Refusal::Loopback),
            ("::ffff:127.0.0.1", Refusal::Loopback),
            ("169.254.169.254", Refusal::LinkLocal),
            ("fe80::1", Refusal::LinkLocal),
            ("::ffff:169.254.169.254", Refusal::LinkLocal),
            ("224.0.0.251", Refusal::Multicast),
            ("ff02::fb", Refusal::Multicast),
            ("0.0.0.0", Refusal::Unspecified),
            ("0.1.2.3", Refusal::Unspecified),
            ("::", Refusal::Unspecified),
            ("255.255.255.255", Refusal::Reserved),
            ("240.0.0.1", Refusal::Reserved),
        ] {
            assert_eq!(judge(&f, ip), Err(reason), "{ip}");
        }
        for ip in [
            "10.0.0.1",
            "172.16.5.4",
            "192.168.1.1",
            "100.64.0.1",
            "93.184.216.34",
            "fd00::1",
            "fd00:ec2::253",
            "100.100.100.100",
            "2001:db8::1",
            "::ffff:10.0.0.1",
        ] {
            assert_eq!(judge(&f, ip), Ok(()), "{ip}");
        }
    }

    #[test]
    fn the_addresses_of_the_interfaces_of_the_node_are_refused() {
        let (f, _) = filter(Rules::default(), &["10.1.2.3", "2001:db8::7"], &[]);
        assert_eq!(judge(&f, "10.1.2.3"), Err(Refusal::OwnInterface));
        assert_eq!(judge(&f, "::ffff:10.1.2.3"), Err(Refusal::OwnInterface));
        assert_eq!(judge(&f, "2001:db8::7"), Err(Refusal::OwnInterface));
        assert_eq!(judge(&f, "10.1.2.4"), Ok(()));
    }

    #[test]
    fn an_interface_that_comes_is_known_after_a_while() {
        let own = Arc::new(Mutex::new(Vec::<IpAddr>::new()));
        let shared = own.clone();
        let f = DialFilter::with_own(
            Rules::default(),
            &[],
            Arc::default(),
            Box::new(move || shared.lock().unwrap().clone()),
        );
        let ip: IpAddr = "10.9.9.9".parse().unwrap();
        tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .start_paused(true)
            .build()
            .unwrap()
            .block_on(async {
                assert_eq!(f.judge(ip), Ok(()));
                own.lock().unwrap().push(ip);
                // (the list is kept for a few seconds)
                assert_eq!(f.judge(ip), Ok(()));
                tokio::time::advance(OWN_VALID).await;
                assert_eq!(f.judge(ip), Err(Refusal::OwnInterface));
            });
    }

    #[test]
    fn the_allow_list_lets_through_the_defaults() {
        let rules = Rules {
            allow: vec![net("127.0.0.0/8"), net("169.254.0.0/16"), net("10.0.0.0/8")],
        };
        let (f, _) = filter(rules, &["127.0.0.1", "10.1.2.3"], &[]);
        // (loopback and an own address of an allowed range: allowed)
        assert_eq!(judge(&f, "127.0.0.1"), Ok(()));
        assert_eq!(judge(&f, "10.1.2.3"), Ok(()));
        assert_eq!(judge(&f, "169.254.1.1"), Ok(()));
        // (what is not named stays as it was)
        assert_eq!(judge(&f, "::1"), Err(Refusal::Loopback));
        assert_eq!(judge(&f, "224.0.0.1"), Err(Refusal::Multicast));
    }

    #[test]
    fn a_bootstrap_peer_the_operator_named_is_exempt_from_everything() {
        let (f, _) = filter(
            Rules::default(),
            &["10.0.0.5"],
            &[
                "/ip4/10.0.0.5/tcp/4001/p2p/12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN",
                "/ip4/127.0.0.1/tcp/4001",
            ],
        );
        assert_eq!(judge(&f, "10.0.0.5"), Ok(()));
        assert_eq!(judge(&f, "127.0.0.1"), Ok(()));
        // (the peer at its port: another port of its host is not it)
        let at = |a: &str| f.check(&a.parse().unwrap());
        assert_eq!(at("/ip4/10.0.0.5/tcp/4001"), Ok(()));
        assert_eq!(at("/ip4/10.0.0.5/tcp/22"), Err(Refusal::OwnInterface));
        // (another host of the same range is not)
        assert_eq!(judge(&f, "10.0.0.6"), Ok(()));
        assert_eq!(judge(&f, "127.0.0.2"), Err(Refusal::Loopback));
    }

    /// What is judged is where the TCP transport connects: an address in an
    /// address (the transport takes the last), a name (resolved after the
    /// filter, to wherever its owner wants) or port 0 is no address of a peer.
    #[test]
    fn only_an_address_the_tcp_transport_reads_as_judged_is_dialed() {
        let (f, _) = filter(
            Rules::default(),
            &[],
            &["/ip4/10.0.0.5/tcp/4001/p2p/12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN"],
        );
        let at = |a: &str| f.check(&a.parse().unwrap());
        for a in [
            "/ip4/10.0.0.1/ip4/127.0.0.1/tcp/22",
            "/ip4/10.0.0.1/tcp/1/ip4/169.254.169.254/tcp/80",
            // (the exemption of a bootstrap peer does not cover what follows it)
            "/ip4/10.0.0.5/tcp/4001/ip4/127.0.0.1/tcp/22",
            "/ip4/10.0.0.5/tcp/4001/p2p/12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN/ip4/127.0.0.1/tcp/22",
            "/dns4/metadata.google.internal/tcp/80",
            "/dns6/localhost/tcp/22",
            "/dns/localhost/tcp/22",
            "/dnsaddr/example.org",
            "/ip4/10.0.0.1/tcp/0",
            "/ip4/10.0.0.1/udp/4001/quic-v1",
            "/ip4/10.0.0.1",
            "/tcp/22",
        ] {
            assert_eq!(at(a), Err(Refusal::Unsupported), "{a}");
        }
        assert_eq!(at("/ip4/10.0.0.1/tcp/4001"), Ok(()));
        assert_eq!(
            at("/ip4/10.0.0.1/tcp/4001/p2p/12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN"),
            Ok(())
        );
        assert_eq!(at("/ip6/2001:db8::1/tcp/4001"), Ok(()));
    }

    #[test]
    fn a_refusal_is_counted_by_its_reason() {
        let (f, counters) = filter(Rules::default(), &[], &[]);
        let addr = |a: &str| -> Multiaddr { a.parse().unwrap() };
        assert_eq!(
            f.check(&addr("/ip4/127.0.0.1/tcp/1")),
            Err(Refusal::Loopback)
        );
        assert_eq!(
            f.check(&addr("/ip4/127.0.0.2/tcp/1")),
            Err(Refusal::Loopback)
        );
        assert_eq!(
            f.check(&addr("/ip4/169.254.169.254/tcp/80")),
            Err(Refusal::LinkLocal)
        );
        assert_eq!(f.check(&addr("/ip4/10.0.0.1/tcp/1")), Ok(()));
        assert_eq!(
            f.check(&addr("/dns4/example.org/tcp/1")),
            Err(Refusal::Unsupported)
        );
        let r = counters.snapshot().dials_refused;
        assert_eq!((r.loopback, r.link_local, r.multicast), (2, 1, 0));
        assert_eq!(r.unsupported, 1);
        assert_eq!(
            r.loopback
                + r.link_local
                + r.multicast
                + r.unspecified
                + r.reserved
                + r.own_interface
                + r.unsupported,
            4
        );
    }

    /// A transport that says it dialed.
    struct Dials(Vec<Multiaddr>);

    impl Transport for Dials {
        type Output = ();
        type Error = std::io::Error;
        type ListenerUpgrade = futures::future::Ready<Result<(), std::io::Error>>;
        type Dial = futures::future::Ready<Result<(), std::io::Error>>;
        fn listen_on(
            &mut self,
            _: ListenerId,
            _: Multiaddr,
        ) -> Result<(), TransportError<Self::Error>> {
            Ok(())
        }
        fn remove_listener(&mut self, _: ListenerId) -> bool {
            false
        }
        fn dial(
            &mut self,
            addr: Multiaddr,
            _: DialOpts,
        ) -> Result<Self::Dial, TransportError<Self::Error>> {
            self.0.push(addr);
            Ok(futures::future::ready(Ok(())))
        }
        fn poll(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
        ) -> Poll<TransportEvent<Self::ListenerUpgrade, Self::Error>> {
            Poll::Pending
        }
    }

    #[test]
    fn the_transport_dials_what_the_filter_allows_and_names_why_it_did_not() {
        let (f, counters) = filter(Rules::default(), &[], &[]);
        let mut t = Filtered::new(Dials(Vec::new()), Arc::new(f));
        let opts = || DialOpts {
            role: libp2p::core::Endpoint::Dialer,
            port_use: libp2p::core::transport::PortUse::Reuse,
        };
        assert!(t
            .dial("/ip4/10.0.0.1/tcp/4001".parse().unwrap(), opts())
            .is_ok());
        // (an address in an address: the transport would dial the last)
        assert!(t
            .dial(
                "/ip4/10.0.0.1/ip4/127.0.0.1/tcp/22".parse().unwrap(),
                opts()
            )
            .is_err());
        let refused = t
            .dial("/ip4/169.254.169.254/tcp/80".parse().unwrap(), opts())
            .expect_err("refused");
        let TransportError::Other(e) = refused else {
            panic!("not a refusal: {refused:?}")
        };
        assert_eq!(e.kind(), std::io::ErrorKind::PermissionDenied);
        assert_eq!(e.to_string(), "refused: link-local address");
        // (only the first reached the transport)
        assert_eq!(t.inner.0.len(), 1);
        assert_eq!(counters.snapshot().dials_refused.link_local, 1);
    }
}
