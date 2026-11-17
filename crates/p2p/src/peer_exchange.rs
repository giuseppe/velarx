// SPDX-License-Identifier: Apache-2.0
//! Learning other peers from the peers a node has.
//!
//! A node a full peer refuses (or that has few peers) knows nobody to ask.
//! It asks the peers it has which others they know, and dials some of what
//! they tell, so it joins the swarm through the peers it was told, not only
//! through the bootstrap peer that could not keep it.  Kademlia does a walk
//! for the closest ids; this is the other half: a few peers at random, which
//! need no table of the DHT and spread a swarm over the members instead of
//! over the neighbours of one id.
//!
//! What a peer says, and what is done with it:
//!
//! * what a node tells is only about peers it is connected to and has
//!   identified, at addresses those peers are connected from or to (an
//!   address known to work, not one a peer only names), at most
//!   [`MAX_PEERS`] peers and [`MAX_ADDRESSES`] addresses each: an answer is a
//!   few hundred bytes for a question of a few;
//! * at most that many peers and addresses of an answer are looked at; an
//!   address is dialed only if the filter of the node allows it
//!   ([`crate::dial_filter`]) and it is a TCP address; at most [`MAX_DIALS`]
//!   peers are dialed for one answer, and nobody is asked before [`EVERY`]
//!   has passed since the last time;
//! * what is learnt is dialed with the peer id that was named, so an
//!   address where another peer lives now ends at the handshake (the id is the key
//!   of the connection), and it is told to others only once the node is
//!   connected to that peer and has identified it itself: nothing is
//!   forwarded from one peer's word to another's, no more than one hop.

use crate::dial_filter::{ip_of, DialFilter};
use crate::entropy::Entropy;
use libp2p::multiaddr::Protocol;
use libp2p::{Multiaddr, PeerId};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::str::FromStr;
use std::time::Duration;
use tokio::time::Instant;

/// The peers an answer names, at most, and the addresses of each.
pub const MAX_PEERS: usize = 16;
pub const MAX_ADDRESSES: usize = 2;
/// The peers dialed for one answer, at most.
pub const MAX_DIALS: usize = 8;
/// The peers a node asks at a time.
pub const ASKED_PEERS: usize = 3;
/// The time between two questions to the same peer.
pub const EVERY: Duration = Duration::from_secs(10);

/// A peer an answer names and where it is reached.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerAddress {
    pub peer_id: String,
    pub addresses: Vec<String>,
}

/// What a node can tell of the peers it is connected to.
#[derive(Default)]
pub struct Directory {
    peers: HashMap<PeerId, Vec<Multiaddr>>,
}

impl Directory {
    /// `peer` told in identify that it listens at `listen` and is connected
    /// from or to `connected`: it can be reached where it listens at an IP
    /// address it is connected from or to, else at such an IP address and the
    /// port of its first TCP address.
    pub fn learn(&mut self, peer: PeerId, connected: &[IpAddr], listen: &[Multiaddr]) {
        let tcp: Vec<&Multiaddr> = listen.iter().filter(|a| tcp_only(a)).collect();
        let mut reached: Vec<Multiaddr> = tcp
            .iter()
            .filter(|a| ip_of(a).is_some_and(|ip| connected.contains(&ip)))
            .map(|a| without_peer(a))
            .collect();
        if reached.is_empty() {
            let port = tcp.iter().find_map(|a| {
                a.iter().find_map(|p| match p {
                    Protocol::Tcp(port) => Some(port),
                    _ => None,
                })
            });
            if let (Some(port), Some(ip)) = (port, connected.first()) {
                reached.push(Multiaddr::from(*ip).with(Protocol::Tcp(port)));
            }
        }
        reached.truncate(MAX_ADDRESSES);
        if reached.is_empty() {
            self.peers.remove(&peer);
        } else {
            self.peers.insert(peer, reached);
        }
    }

    /// `peer` is gone.
    pub fn forget(&mut self, peer: &PeerId) {
        self.peers.remove(peer);
    }

    /// The answer to `asker`: up to [`MAX_PEERS`] of the peers that are
    /// `member` (connected, not lent a place for a moment), at random, not
    /// the asker, at the addresses the filter allows.
    pub fn answer(
        &self,
        asker: &PeerId,
        member: impl Fn(&PeerId) -> bool,
        filter: &DialFilter,
        entropy: &Entropy,
    ) -> Vec<PeerAddress> {
        let mut peers: Vec<(&PeerId, &Vec<Multiaddr>)> = self
            .peers
            .iter()
            .filter(|(p, _)| *p != asker && member(p))
            .collect();
        // (the table is not ordered: the sample is of the seed's making)
        peers.sort_by_key(|(p, _)| **p);
        entropy.shuffle(&mut peers);
        peers
            .into_iter()
            .filter_map(|(peer, addresses)| {
                let addresses: Vec<String> = addresses
                    .iter()
                    .filter(|a| ip_of(a).is_some_and(|ip| filter.judge(ip).is_ok()))
                    .map(|a| a.to_string())
                    .collect();
                (!addresses.is_empty()).then(|| PeerAddress {
                    peer_id: peer.to_string(),
                    addresses,
                })
            })
            .take(MAX_PEERS)
            .collect()
    }

    pub fn len(&self) -> usize {
        self.peers.len()
    }

    pub fn is_empty(&self) -> bool {
        self.peers.is_empty()
    }
}

/// A TCP address, the one libp2p of the node dials.
fn tcp_only(addr: &Multiaddr) -> bool {
    let mut tcp = false;
    for p in addr.iter() {
        match p {
            Protocol::Tcp(_) => tcp = true,
            Protocol::Udp(_) | Protocol::QuicV1 | Protocol::Quic => return false,
            _ => {}
        }
    }
    tcp
}

/// The address without the `/p2p/ID` that ends it.
fn without_peer(addr: &Multiaddr) -> Multiaddr {
    addr.iter()
        .filter(|p| !matches!(p, Protocol::P2p(_)))
        .collect()
}

/// The peers of an answer that are worth dialing: at most `want`, never `me`
/// nor a peer that is `known` (connected, or being dialed), each with the TCP
/// addresses the filter allows.  Only the first [`MAX_PEERS`] peers and
/// [`MAX_ADDRESSES`] addresses of each are looked at.
pub fn accepted(
    answer: &[PeerAddress],
    me: &PeerId,
    filter: &DialFilter,
    known: impl Fn(&PeerId) -> bool,
    want: usize,
) -> Vec<(PeerId, Vec<Multiaddr>)> {
    let mut out: Vec<(PeerId, Vec<Multiaddr>)> = Vec::new();
    for entry in answer.iter().take(MAX_PEERS) {
        if out.len() >= want.min(MAX_DIALS) {
            break;
        }
        let Ok(peer) = PeerId::from_str(&entry.peer_id) else {
            continue;
        };
        if peer == *me || known(&peer) || out.iter().any(|(p, _)| *p == peer) {
            continue;
        }
        let addresses: Vec<Multiaddr> = entry
            .addresses
            .iter()
            .take(MAX_ADDRESSES)
            .filter_map(|a| Multiaddr::from_str(a).ok())
            .filter(tcp_only)
            // (an address that names another peer than the one it is
            // given for is not one the peer is at)
            .filter(|a| {
                a.iter()
                    .all(|p| !matches!(p, Protocol::P2p(id) if id != peer))
            })
            .map(|a| without_peer(&a))
            .filter(|a| filter.check(a).is_ok())
            .collect();
        if !addresses.is_empty() {
            out.push((peer, addresses));
        }
    }
    out
}

/// When each peer was last asked.
#[derive(Default)]
pub struct Pacing {
    asked: HashMap<PeerId, Instant>,
}

impl Pacing {
    /// Whether `peer` may be asked now (it is noted as asked when so).
    pub fn may_ask(&mut self, peer: PeerId, now: Instant) -> bool {
        if self
            .asked
            .get(&peer)
            .is_some_and(|at| now.duration_since(*at) < EVERY)
        {
            return false;
        }
        self.asked.retain(|_, at| now.duration_since(*at) < EVERY);
        self.asked.insert(peer, now);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dial_filter::Rules;

    fn peer() -> PeerId {
        libp2p::identity::Keypair::generate_ed25519()
            .public()
            .to_peer_id()
    }

    fn filter() -> DialFilter {
        DialFilter::with_own(
            Rules::default(),
            &[],
            Arc::default(),
            Box::new(|| vec!["10.0.0.1".parse().unwrap()]),
        )
    }

    use std::sync::Arc;

    fn addr(s: &str) -> Multiaddr {
        s.parse().unwrap()
    }

    fn claim(id: &PeerId, addresses: &[&str]) -> PeerAddress {
        PeerAddress {
            peer_id: id.to_string(),
            addresses: addresses.iter().map(|a| a.to_string()).collect(),
        }
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn a_node_tells_only_where_a_peer_is_connected_from_or_to() {
        let mut d = Directory::default();
        let (a, b, c) = (peer(), peer(), peer());
        // it names its own address, and another host's: only its own stays
        d.learn(
            a,
            &[ip("10.0.0.7")],
            &[
                addr("/ip4/10.0.0.7/tcp/4001"),
                addr("/ip4/10.0.0.99/tcp/4001"),
            ],
        );
        // behind a NAT it names an address that is not the one it is seen at:
        // the one it is seen at with its port
        d.learn(b, &[ip("10.0.0.8")], &[addr("/ip4/192.168.1.5/tcp/4002")]);
        // the QUIC endpoint is not an address of libp2p
        d.learn(
            c,
            &[ip("10.0.0.9")],
            &[addr("/ip4/10.0.0.9/udp/4001/quic-v1")],
        );
        let told = d.answer(&peer(), |_| true, &filter(), &Entropy::seeded(1));
        let by_id: HashMap<_, _> = told.iter().map(|t| (t.peer_id.clone(), t)).collect();
        assert_eq!(by_id[&a.to_string()].addresses, ["/ip4/10.0.0.7/tcp/4001"]);
        assert_eq!(by_id[&b.to_string()].addresses, ["/ip4/10.0.0.8/tcp/4002"]);
        assert!(!by_id.contains_key(&c.to_string()), "{told:?}");
        // (never the peer that asks, whoever it asks about)
        let told = d.answer(&a, |_| true, &filter(), &Entropy::seeded(1));
        assert!(told.iter().all(|t| t.peer_id != a.to_string()), "{told:?}");
        assert_eq!(told.len(), 1, "{told:?}");
    }

    #[test]
    fn an_answer_is_bounded_never_has_the_asker_nor_what_is_not_a_member_nor_what_the_filter_refuses(
    ) {
        let mut d = Directory::default();
        let asker = peer();
        let mut ids = vec![asker];
        d.learn(asker, &[ip("10.0.1.1")], &[addr("/ip4/10.0.1.1/tcp/1")]);
        for i in 0..100u8 {
            let p = peer();
            ids.push(p);
            let ip = format!("10.0.2.{i}");
            d.learn(
                p,
                &[ip.parse().unwrap()],
                &[addr(&format!("/ip4/{ip}/tcp/1"))],
            );
        }
        // one at an address the node's filter refuses (its own)
        let own = peer();
        d.learn(own, &[ip("10.0.0.1")], &[addr("/ip4/10.0.0.1/tcp/1")]);
        // and one that the node is lending a place to only
        let lent = peer();
        d.learn(lent, &[ip("10.0.3.1")], &[addr("/ip4/10.0.3.1/tcp/1")]);
        let told = d.answer(&asker, |p| *p != lent, &filter(), &Entropy::seeded(1));
        assert_eq!(told.len(), MAX_PEERS);
        let named: Vec<String> = told.iter().map(|t| t.peer_id.clone()).collect();
        for gone in [asker, own, lent] {
            assert!(!named.contains(&gone.to_string()));
        }
        assert!(told.iter().all(|t| t.addresses.len() <= MAX_ADDRESSES));
        // (a sample, not always the same peers)
        let again = d.answer(&asker, |p| *p != lent, &filter(), &Entropy::seeded(2));
        assert_ne!(told, again);
    }

    #[test]
    fn what_an_answer_names_is_bounded_and_filtered_before_it_is_dialed() {
        let (me, known) = (peer(), peer());
        let f = filter();
        let good: Vec<PeerId> = (0..40).map(|_| peer()).collect();
        let mut answer: Vec<PeerAddress> = vec![
            // oneself, a peer already connected, an id that is no id
            claim(&me, &["/ip4/10.1.0.1/tcp/1"]),
            claim(&known, &["/ip4/10.1.0.2/tcp/1"]),
            PeerAddress {
                peer_id: "not a peer id".into(),
                addresses: vec!["/ip4/10.1.0.3/tcp/1".into()],
            },
            // the addresses a member points at internal hosts
            claim(
                &good[0],
                &["/ip4/127.0.0.1/tcp/22", "/ip4/169.254.169.254/tcp/80"],
            ),
            claim(&good[1], &["/ip4/10.0.0.1/tcp/4001"]),
            claim(
                &good[2],
                &[
                    "/ip4/0.0.0.0/tcp/1",
                    "/ip6/::1/tcp/1",
                    "/ip4/224.0.0.1/tcp/1",
                ],
            ),
            // not TCP, not an address, too long, with another peer's id
            claim(&good[3], &["/ip4/10.1.1.1/udp/4001/quic-v1"]),
            claim(
                &good[4],
                &["garbage", &format!("/ip4/10.1.1.2/tcp/{}", "9".repeat(200))],
            ),
            claim(&good[5], &[&format!("/ip4/10.1.1.3/tcp/1/p2p/{}", good[6])]),
            // one good one, with its own id at the end of the address
            claim(
                &good[7],
                &[&format!("/ip4/10.1.1.4/tcp/4001/p2p/{}", good[7])],
            ),
        ];
        // and then many more good ones, each naming many addresses
        for p in &good[8..] {
            answer.push(claim(
                p,
                &[
                    "/ip4/10.2.0.1/tcp/1",
                    "/ip4/10.2.0.2/tcp/1",
                    "/ip4/10.2.0.3/tcp/1",
                    "/ip4/10.2.0.4/tcp/1",
                ],
            ));
        }
        let taken = accepted(&answer, &me, &f, |p| *p == known, 100);
        // the first sixteen entries only were looked at: the good one among
        // them and the ones after it up to there, with two addresses each
        let named: Vec<PeerId> = taken.iter().map(|(p, _)| *p).collect();
        assert_eq!(named[0], good[7]);
        assert_eq!(taken[0].1, [addr("/ip4/10.1.1.4/tcp/4001")]);
        // (sixteen entries: the ten above, one good, and six more)
        assert_eq!(taken.len(), 7);
        assert!(taken.iter().all(|(_, a)| a.len() <= MAX_ADDRESSES));
        for (p, _) in &taken[1..] {
            assert!(good[8..].contains(p));
        }
        for bad in [
            &me, &known, &good[0], &good[1], &good[2], &good[3], &good[4], &good[5],
        ] {
            assert!(!named.contains(bad), "{bad}");
        }
        // however many good ones there are, no more than `MAX_DIALS` are taken
        let many: Vec<PeerAddress> = (0..MAX_PEERS)
            .map(|i| claim(&peer(), &[&format!("/ip4/10.3.0.{i}/tcp/1")]))
            .collect();
        assert_eq!(accepted(&many, &me, &f, |_| false, 100).len(), MAX_DIALS);
        // what the node wants bounds it too
        assert_eq!(accepted(&answer, &me, &f, |p| *p == known, 2).len(), 2);
        assert!(accepted(&answer, &me, &f, |p| *p == known, 0).is_empty());
    }

    #[test]
    fn what_the_filter_refused_in_an_answer_is_counted() {
        let counters = Arc::<crate::stats::Counters>::default();
        let f = DialFilter::with_own(Rules::default(), &[], counters.clone(), Box::new(Vec::new));
        let (me, a, b) = (peer(), peer(), peer());
        let answer = vec![
            claim(&a, &["/ip4/127.0.0.1/tcp/1", "/ip4/169.254.169.254/tcp/80"]),
            claim(&b, &["/ip4/10.0.0.5/tcp/1"]),
        ];
        let taken = accepted(&answer, &me, &f, |_| false, 8);
        assert_eq!(taken.len(), 1);
        let r = counters.snapshot().dials_refused;
        assert_eq!((r.loopback, r.link_local), (1, 1));
    }

    #[test]
    fn a_peer_is_asked_once_in_a_while() {
        let t0 = Instant::now();
        let mut pacing = Pacing::default();
        let (a, b) = (peer(), peer());
        assert!(pacing.may_ask(a, t0));
        assert!(!pacing.may_ask(a, t0 + EVERY / 2));
        assert!(pacing.may_ask(b, t0 + EVERY / 2));
        assert!(pacing.may_ask(a, t0 + EVERY));
    }
}
