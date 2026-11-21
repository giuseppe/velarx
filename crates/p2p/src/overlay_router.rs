// SPDX-License-Identifier: Apache-2.0
//! The routing table of the TUN overlay network: which peer owns which
//! subnet, and the container addresses of this node.
//!
//! The subnet of a node is a /24 of the overlay network that a hash of its
//! whole peer id and an attempt number gives ([`subnet_for`]): a peer cannot
//! pick another one, only try peer ids for the subnet it wants.  The
//! overlay range is up to a /8, so that honest nodes rarely collide
//! (a /10 has 16384 subnets) and a member has to generate that many peer
//! ids for one subnet.  What it gets by that is nothing: a subnet that two
//! peers claim has no route at all, on any node and whatever the order of
//! the announcements, and the log of the nodes names both peers and the
//! remedy (`settings.overlay.subnet_attempt`).  A member can make the subnet
//! of a victim unreachable that way, and never receives the victim's traffic.  The
//! subnet is routed again when one of the two leaves or takes another
//! attempt number.

use ipnet::Ipv4Net;
use libp2p::PeerId;
use sha2::{Digest, Sha256};
use std::collections::{BTreeSet, HashMap};
use std::net::Ipv4Addr;
use thiserror::Error;
use tokio::sync::RwLock;
use tracing::{debug, error, info};

#[derive(Error, Debug)]
pub enum OverlayError {
    #[error("no route to host: {0}")]
    NoRoute(Ipv4Addr),
    #[error("route refused: {0}")]
    RouteRefused(String),
}

/// The attempt numbers a peer may have used for its subnet (0 unless it
/// collided with another).
pub const MAX_SUBNET_ATTEMPTS: u8 = 16;

/// The widest overlay range (a /8) and the narrowest (a /16: 256 subnets).
pub const MIN_OVERLAY_PREFIX: u8 = 8;
pub const MAX_OVERLAY_PREFIX: u8 = 16;

/// The subnet of `peer` in the range `base` (a prefix of 8 to 16 bits),
/// for `attempt`.
pub fn subnet_for(base: Ipv4Net, peer: &PeerId, attempt: u8) -> Ipv4Net {
    let mut hash = Sha256::new();
    hash.update(b"velarx overlay subnet");
    hash.update(peer.to_bytes());
    hash.update([attempt]);
    let digest = hash.finalize();
    let free_bits = 24 - u32::from(base.prefix_len());
    let index = u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]])
        .checked_shr(32 - free_bits)
        .unwrap_or(0);
    let network = u32::from(base.network()) | (index << 8);
    Ipv4Net::new(Ipv4Addr::from(network), 24).expect("a /24 is a valid prefix")
}

pub type OverlayResult<T> = Result<T, OverlayError>;

/// Information about a peer's overlay network presence
#[derive(Debug, Clone)]
pub struct OverlayPeerEntry {
    /// The peer's libp2p peer ID
    pub peer_id: PeerId,
}

/// The peers whose route a change of the table took or gave back.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Routed {
    /// Peers that have no route now (another peer claims their subnet)
    pub withdrawn: Vec<PeerId>,
    /// Peers that have a route again
    pub restored: Vec<PeerId>,
}

/// What the router knows about the subnets.
#[derive(Default)]
struct Table {
    /// The subnet every peer claimed (this node included), each one a
    /// subnet its peer id gives
    claims: HashMap<PeerId, Ipv4Net>,
    /// The routes: the subnets one peer only claims
    routes: HashMap<Ipv4Net, OverlayPeerEntry>,
}

impl Table {
    /// The peer the packets for `subnet` go to: the one peer that claims
    /// it, unless that is this node.
    fn holder(&self, subnet: &Ipv4Net, local: &PeerId) -> Option<PeerId> {
        let mut claimants = self
            .claims
            .iter()
            .filter(|(_, s)| *s == subnet)
            .map(|(p, _)| *p);
        match (claimants.next(), claimants.next()) {
            (Some(peer), None) if peer != *local => Some(peer),
            _ => None,
        }
    }

    /// The routes of `subnets`, the ones a change of the claims touched,
    /// from the claims (no other subnet changes), and what changed for the
    /// peers.
    fn settle(&mut self, local: &PeerId, subnets: &[Ipv4Net]) -> Routed {
        let mut routed = Routed::default();
        for subnet in subnets {
            let before = self.routes.get(subnet).map(|e| e.peer_id);
            let after = self.holder(subnet, local);
            if before == after {
                continue;
            }
            match after {
                Some(peer_id) => self.routes.insert(*subnet, OverlayPeerEntry { peer_id }),
                None => self.routes.remove(subnet),
            };
            routed.withdrawn.extend(before);
            routed.restored.extend(after);
        }
        // (a peer that moved from one routed subnet to another has a route)
        let moved: Vec<PeerId> = routed
            .withdrawn
            .iter()
            .filter(|p| routed.restored.contains(p))
            .copied()
            .collect();
        routed.withdrawn.retain(|p| !moved.contains(p));
        routed.restored.retain(|p| !moved.contains(p));
        routed
    }

    /// The peers other than `peer` that claim `subnet`.
    fn others(&self, peer: &PeerId, subnet: &Ipv4Net) -> Vec<PeerId> {
        self.claims
            .iter()
            .filter(|(p, s)| *p != peer && *s == subnet)
            .map(|(p, _)| *p)
            .collect()
    }
}

/// Overlay router for TUN-based P2P networking
pub struct OverlayRouter {
    /// This node's peer ID
    local_peer_id: PeerId,
    /// The range the subnets of the nodes are taken from
    base: Ipv4Net,
    /// This node's overlay subnet (e.g., 10.200.1.0/24)
    node_subnet: Ipv4Net,
    /// This node's overlay IP (gateway for local containers)
    node_ip: Ipv4Addr,
    /// The claims and the routes
    table: RwLock<Table>,
    /// Container IPs on this node
    local_container_ips: RwLock<BTreeSet<Ipv4Addr>>,
}

impl OverlayRouter {
    /// Create a new overlay router for the node `local_peer_id`, whose
    /// subnet is `node_subnet` in the range `base`
    pub fn new(local_peer_id: PeerId, base: Ipv4Net, node_subnet: Ipv4Net) -> Self {
        // Use the first IP in the subnet as the node's gateway IP
        let node_ip = node_subnet.hosts().next().unwrap_or(node_subnet.addr());
        let mut table = Table::default();
        table.claims.insert(local_peer_id, node_subnet);

        Self {
            local_peer_id,
            base,
            node_subnet,
            node_ip,
            table: RwLock::new(table),
            local_container_ips: RwLock::default(),
        }
    }

    /// Get this node's overlay IP
    pub fn node_ip(&self) -> Ipv4Addr {
        self.node_ip
    }

    /// Get this node's overlay subnet
    pub fn node_subnet(&self) -> Ipv4Net {
        self.node_subnet
    }

    /// Lookup which peer owns a destination IP
    pub async fn lookup_route(&self, dest: Ipv4Addr) -> OverlayResult<PeerId> {
        let table = self.table.read().await;

        for (subnet, entry) in table.routes.iter() {
            if subnet.contains(&dest) {
                return Ok(entry.peer_id);
            }
        }

        Err(OverlayError::NoRoute(dest))
    }

    /// Whether packets for the subnet of `peer` go to it.
    pub async fn has_route(&self, peer: &PeerId) -> bool {
        self.table
            .read()
            .await
            .routes
            .values()
            .any(|e| e.peer_id == *peer)
    }

    /// Add or update a route from peer gossip.
    ///
    /// A peer says which subnet is its own, and that decides where packets
    /// for it go: it may only claim a subnet that its peer id gives
    /// ([`subnet_for`] with one of the first [`MAX_SUBNET_ATTEMPTS`]
    /// attempts).  A subnet that another peer claims too, this node
    /// included, is routed to none of them.  A peer has one subnet at a
    /// time.  The peers whose route this changed are returned.
    pub async fn add_route(&self, peer_id: PeerId, node_subnet: Ipv4Net) -> OverlayResult<Routed> {
        if peer_id == self.local_peer_id {
            return Ok(Routed::default());
        }
        let refuse = |why: &str| {
            debug!(
                "Refusing the route {} of peer {}: {}",
                node_subnet, peer_id, why
            );
            Err(OverlayError::RouteRefused(why.to_string()))
        };
        if !(0..MAX_SUBNET_ATTEMPTS).any(|k| subnet_for(self.base, &peer_id, k) == node_subnet) {
            return refuse("not a subnet that its peer id gives");
        }
        let mut table = self.table.write().await;
        // One subnet per peer: its previous one goes
        let before = table.claims.insert(peer_id, node_subnet);
        let touched: Vec<Ipv4Net> = before.into_iter().chain([node_subnet]).collect();
        let routed = table.settle(&self.local_peer_id, &touched);
        let others = table.others(&peer_id, &node_subnet);
        if !others.is_empty() {
            let named: Vec<String> = others.iter().map(|p| p.to_string()).collect();
            if others.contains(&self.local_peer_id) {
                error!(
                    "The subnet {} of this node is also the one of peer {}: nobody routes \
                     to either of them; set settings.overlay.subnet_attempt to another \
                     number and restart",
                    node_subnet, peer_id
                );
            } else {
                error!(
                    "The subnet {} is claimed by peer {} and by {}: nobody routes to \
                     either of them until one sets settings.overlay.subnet_attempt to another \
                     number and restarts, or leaves",
                    node_subnet,
                    peer_id,
                    named.join(", ")
                );
            }
        } else {
            info!(
                "Added overlay route: {} via peer {}",
                node_subnet,
                &peer_id.to_string()[..12]
            );
        }
        Ok(routed)
    }

    /// The peer is gone: its claim goes, and a subnet it contested may be
    /// routed again.
    pub async fn remove_peer(&self, peer_id: &PeerId) -> Routed {
        let mut table = self.table.write().await;
        if *peer_id == self.local_peer_id {
            return Routed::default();
        }
        let Some(subnet) = table.claims.remove(peer_id) else {
            return Routed::default();
        };
        debug!("Removed the overlay claim of peer {}", peer_id);
        table.settle(&self.local_peer_id, &[subnet])
    }

    /// Remove a container IP from this node's overlay
    pub async fn remove_container_ip(&self, ip: &Ipv4Addr) {
        self.local_container_ips.write().await.remove(ip);
        debug!("Removed container overlay IP: {}", ip);
    }

    /// Check if an IP address belongs to a local container
    pub async fn is_local_container_ip(&self, ip: &Ipv4Addr) -> bool {
        self.local_container_ips.read().await.contains(ip)
    }

    /// Reserve the next available container IP in our subnet: the first
    /// free one is taken under the write lock, so two callers never get the
    /// same address.  `remove_container_ip` gives it back.
    pub async fn allocate_container_ip(&self) -> Option<Ipv4Addr> {
        let mut ips = self.local_container_ips.write().await;

        // Skip the first IP (node's gateway) and broadcast
        let host = self
            .node_subnet
            .hosts()
            .skip(1)
            .find(|host| !ips.contains(host))?;
        ips.insert(host);
        info!("Reserved container overlay IP: {}", host);
        Some(host)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    impl OverlayRouter {
        async fn get_routes(&self) -> Vec<(Ipv4Net, OverlayPeerEntry)> {
            self.table
                .read()
                .await
                .routes
                .iter()
                .map(|(k, v)| (*k, v.clone()))
                .collect()
        }

        async fn route_count(&self) -> usize {
            self.table.read().await.routes.len()
        }
    }

    fn base() -> Ipv4Net {
        "10.200.0.0/16".parse().unwrap()
    }

    fn net(s: &str) -> Ipv4Net {
        s.parse().unwrap()
    }

    fn own(peer: &PeerId) -> Ipv4Net {
        subnet_for(base(), peer, 0)
    }

    /// A peer whose subnet is none of `not`.
    fn peer_not(not: &[Ipv4Net]) -> PeerId {
        loop {
            let peer = PeerId::random();
            if !not.contains(&own(&peer)) {
                return peer;
            }
        }
    }

    async fn router() -> (OverlayRouter, PeerId) {
        let local = PeerId::random();
        (OverlayRouter::new(local, base(), own(&local)), local)
    }

    /// Two peers that have the same subnet, the one with the lower id first
    /// (an id is made until a collision turns up: 256 subnets).
    fn colliding_peers(not: Ipv4Net) -> (PeerId, PeerId) {
        let mut seen: HashMap<Ipv4Net, PeerId> = HashMap::new();
        loop {
            let peer = PeerId::random();
            let subnet = own(&peer);
            if subnet == not {
                continue;
            }
            if let Some(other) = seen.insert(subnet, peer) {
                return if peer.to_bytes() < other.to_bytes() {
                    (peer, other)
                } else {
                    (other, peer)
                };
            }
        }
    }

    #[test]
    fn a_wide_range_gives_a_subnet_of_the_whole_range() {
        for range in [
            "10.0.0.0/8",
            "10.192.0.0/10",
            "10.200.0.0/16",
            "172.16.0.0/12",
        ] {
            let range = net(range);
            let subnets: std::collections::HashSet<_> = (0..400)
                .map(|_| subnet_for(range, &PeerId::random(), 0))
                .collect();
            assert!(subnets
                .iter()
                .all(|s| s.prefix_len() == 24 && range.contains(s)));
            // (a /16 has 256 subnets, 400 ids cover most of them)
            assert!(subnets.len() > if range.prefix_len() == 16 { 150 } else { 300 });
        }
    }

    #[test]
    fn the_subnet_comes_from_the_whole_peer_id_and_the_attempt() {
        let peer = PeerId::random();
        assert_eq!(own(&peer), own(&peer));
        let subnet = own(&peer);
        assert_eq!(subnet.prefix_len(), 24);
        assert!(base().contains(&subnet));
        // the attempts are other subnets (some of the 16 differ)
        assert!(
            (1..MAX_SUBNET_ATTEMPTS).any(|k| subnet_for(base(), &peer, k) != subnet),
            "the attempts give other subnets"
        );
        // ids that end in the same byte do not share a subnet
        let subnets: std::collections::HashSet<_> =
            (0..200).map(|_| own(&PeerId::random())).collect();
        assert!(subnets.len() > 100, "{}", subnets.len());
    }

    #[tokio::test]
    async fn test_overlay_router_routes() {
        let (router, _) = router().await;
        let remote_peer = peer_not(&[router.node_subnet()]);
        let remote_subnet = own(&remote_peer);
        router.add_route(remote_peer, remote_subnet).await.unwrap();
        assert_eq!(router.route_count().await, 1);
        let routes = router.get_routes().await;
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].0, remote_subnet);
        assert_eq!(routes[0].1.peer_id, remote_peer);
    }

    #[tokio::test]
    async fn test_a_peer_cannot_claim_what_its_peer_id_does_not_give() {
        let (router, _) = router().await;
        // (a peer none of whose attempts gives the subnet of this node: one
        // whose attempt does claims it rightly, and is given no route)
        let peer = loop {
            let p = PeerId::random();
            if (0..MAX_SUBNET_ATTEMPTS).all(|k| subnet_for(base(), &p, k) != router.node_subnet()) {
                break p;
            }
        };
        let given = own(&peer);
        for bad in [
            "0.0.0.0/0",
            "10.0.0.0/8",
            "10.200.0.0/16",
            "10.200.2.0/25",
            "10.201.2.0/24",
            "192.168.1.0/24",
            "10.200.2.7/32",
            // ours
            &router.node_subnet().to_string(),
        ] {
            assert!(router.add_route(peer, net(bad)).await.is_err(), "{bad}");
        }
        // another subnet of the overlay, which the peer's id does not give
        let other = (0..=255u8)
            .map(|third| net(&format!("10.200.{third}.0/24")))
            .find(|n| {
                *n != given
                    && *n != router.node_subnet()
                    && (0..MAX_SUBNET_ATTEMPTS).all(|k| subnet_for(base(), &peer, k) != *n)
            })
            .unwrap();
        assert!(router.add_route(peer, other).await.is_err());
        assert_eq!(router.route_count().await, 0);
        router.add_route(peer, given).await.unwrap();
        assert_eq!(router.route_count().await, 1);
    }

    #[tokio::test]
    async fn a_member_cannot_take_a_subnet_before_its_owner_announces_it() {
        let (router, _) = router().await;
        let owner = peer_not(&[router.node_subnet()]);
        // (a peer none of whose attempts gives the subnet of the owner: one
        // whose later attempt does may take it)
        let squatter = loop {
            let p = peer_not(&[router.node_subnet()]);
            if !(0..MAX_SUBNET_ATTEMPTS).any(|k| subnet_for(base(), &p, k) == own(&owner)) {
                break p;
            }
        };
        assert!(router.add_route(squatter, own(&owner)).await.is_err());
        router.add_route(owner, own(&owner)).await.unwrap();
        assert_eq!(
            router
                .lookup_route(own(&owner).hosts().next().unwrap())
                .await
                .unwrap(),
            owner
        );
    }

    #[tokio::test]
    async fn a_subnet_two_peers_claim_is_routed_to_neither_in_any_order() {
        let local = PeerId::random();
        let (lower, higher) = colliding_peers(own(&local));
        let subnet = own(&lower);
        for order in [[lower, higher], [higher, lower]] {
            let router = OverlayRouter::new(local, base(), own(&local));
            let first = router.add_route(order[0], subnet).await.unwrap();
            assert_eq!(first.restored, vec![order[0]]);
            // the second claim takes the route of the first
            let second = router.add_route(order[1], subnet).await.unwrap();
            assert_eq!(second.withdrawn, vec![order[0]], "{order:?}");
            assert_eq!(router.route_count().await, 0);
            assert!(router
                .lookup_route(subnet.hosts().next().unwrap())
                .await
                .is_err());
            assert!(!router.has_route(&lower).await);
            assert!(!router.has_route(&higher).await);
        }
    }

    #[tokio::test]
    async fn a_subnet_is_routed_again_when_one_of_two_claimants_leaves_or_moves() {
        let local = PeerId::random();
        let (a, b) = colliding_peers(own(&local));
        let subnet = own(&a);
        // the one that leaves
        let router = OverlayRouter::new(local, base(), own(&local));
        router.add_route(a, subnet).await.unwrap();
        router.add_route(b, subnet).await.unwrap();
        assert_eq!(router.remove_peer(&b).await.restored, vec![a]);
        assert_eq!(
            router
                .lookup_route(subnet.hosts().next().unwrap())
                .await
                .unwrap(),
            a
        );
        // the one that takes another attempt number
        let router = OverlayRouter::new(local, base(), own(&local));
        router.add_route(a, subnet).await.unwrap();
        router.add_route(b, subnet).await.unwrap();
        let moved = (1..MAX_SUBNET_ATTEMPTS)
            .map(|k| subnet_for(base(), &b, k))
            .find(|n| *n != subnet && *n != own(&local) && *n != own(&a))
            .unwrap();
        let routed = router.add_route(b, moved).await.unwrap();
        assert_eq!(routed.restored.len(), 2);
        assert!(router.has_route(&a).await && router.has_route(&b).await);
    }

    #[tokio::test]
    async fn a_member_that_derives_the_subnet_of_a_victim_gets_no_traffic_of_it() {
        let (router, _) = router().await;
        let (victim, squatter) = colliding_peers(router.node_subnet());
        let subnet = own(&victim);
        router.add_route(squatter, subnet).await.unwrap();
        router.add_route(victim, subnet).await.unwrap();
        assert!(router
            .lookup_route(subnet.hosts().next().unwrap())
            .await
            .is_err());
    }

    #[tokio::test]
    async fn a_peer_with_the_subnet_of_this_node_has_no_route() {
        let local = PeerId::random();
        let router = OverlayRouter::new(local, base(), own(&local));
        // a peer whose first subnet is ours
        let peer = loop {
            let p = PeerId::random();
            if own(&p) == own(&local) {
                break p;
            }
        };
        assert!(router.add_route(peer, own(&peer)).await.is_ok());
        assert_eq!(router.route_count().await, 0);
        assert!(!router.has_route(&peer).await);
    }

    #[tokio::test]
    async fn test_a_peer_has_one_subnet_and_a_new_attempt_replaces_the_old() {
        let (router, _) = router().await;
        let (a, first, second) = loop {
            let a = peer_not(&[router.node_subnet()]);
            let (first, second) = (subnet_for(base(), &a, 0), subnet_for(base(), &a, 1));
            if first != second && second != router.node_subnet() {
                break (a, first, second);
            }
        };
        router.add_route(a, first).await.unwrap();
        router.add_route(a, first).await.unwrap();
        router.add_route(a, second).await.unwrap();
        assert_eq!(router.route_count().await, 1);
        assert!(router
            .lookup_route(first.hosts().next().unwrap())
            .await
            .is_err());
        assert_eq!(
            router
                .lookup_route(second.hosts().next().unwrap())
                .await
                .unwrap(),
            a
        );
    }

    #[tokio::test]
    async fn test_routes_for_ourselves_are_ignored() {
        let (router, local) = router().await;
        router.add_route(local, net("10.200.7.0/24")).await.unwrap();
        assert_eq!(router.route_count().await, 0);
    }

    #[tokio::test]
    async fn test_container_ip_allocation() {
        let local_peer = PeerId::random();
        let subnet: Ipv4Net = "10.200.1.0/24".parse().unwrap();

        let router = OverlayRouter::new(local_peer, "10.200.0.0/16".parse().unwrap(), subnet);

        // First allocation should be .2 (skip .1 which is the gateway)
        let ip1 = router.allocate_container_ip().await;
        assert!(ip1.is_some());
        let ip1 = ip1.unwrap();
        assert!(ip1.octets()[3] >= 2);

        assert!(router.is_local_container_ip(&ip1).await);

        let ip2 = router.allocate_container_ip().await;
        assert!(ip2.is_some());
        assert_ne!(ip1, ip2.unwrap());
    }

    /// Concurrent allocations never share an address, and a released one is
    /// handed out again.
    #[tokio::test]
    async fn concurrent_allocations_are_distinct() {
        let router = Arc::new(OverlayRouter::new(
            PeerId::random(),
            "10.200.0.0/16".parse().unwrap(),
            "10.200.1.0/24".parse().unwrap(),
        ));
        let tasks: Vec<_> = (0..32)
            .map(|_| {
                let router = router.clone();
                tokio::spawn(async move { router.allocate_container_ip().await.unwrap() })
            })
            .collect();
        let mut ips = BTreeSet::new();
        for task in tasks {
            assert!(ips.insert(task.await.unwrap()));
        }
        let first = *ips.iter().next().unwrap();
        router.remove_container_ip(&first).await;
        assert_eq!(router.allocate_container_ip().await, Some(first));
    }

    /// The routes, whatever the order: nodes that see the same claims in
    /// orders that differ (the announcements of one peer keep theirs, as
    /// gossip has them), with peers that move and leave, end with the same
    /// routes: a subnet one peer claims goes to it (not to the node
    /// itself), one two claim to neither.  And what the calls returned
    /// adds up to the routes.
    #[tokio::test]
    async fn the_routes_are_the_same_on_every_node_in_any_order() {
        use rand::seq::SliceRandom;
        use rand::{Rng, SeedableRng};
        let seed: u64 = rand::random();
        let mut rng = rand::rngs::StdRng::seed_from_u64(seed);
        // a /16 of 256 subnets and 4 attempts each: collisions are many
        let peers: Vec<PeerId> = (0..40).map(|_| PeerId::random()).collect();
        let (a, b) = colliding_peers(own(&peers[0]));
        let peers: Vec<PeerId> = peers.into_iter().chain([a, b]).collect();
        #[derive(Clone, Copy, Debug)]
        enum Event {
            Claim(PeerId, u8),
            Gone(PeerId),
        }
        for round in 0..20 {
            // each peer: a few claims, maybe gone at the end
            let mut lines: Vec<Vec<Event>> = peers
                .iter()
                .map(|p| {
                    let mut line: Vec<Event> = (0..rng.gen_range(1..4))
                        .map(|_| Event::Claim(*p, rng.gen_range(0..4)))
                        .collect();
                    if rng.gen_bool(0.2) {
                        line.push(Event::Gone(*p));
                    }
                    line
                })
                .collect();
            if round % 2 == 0 {
                // (the two that collide, last on their own attempt 0)
                lines[40].push(Event::Claim(a, 0));
                lines[41].push(Event::Claim(b, 0));
            }
            let mut last: HashMap<PeerId, Option<Ipv4Net>> = HashMap::new();
            for line in &lines {
                for e in line {
                    match *e {
                        Event::Claim(p, k) => last.insert(p, Some(subnet_for(base(), &p, k))),
                        Event::Gone(p) => last.insert(p, None),
                    };
                }
            }
            // the nodes: one of the peers (its own claim is its subnet) and
            // two others
            let nodes = [peers[0], PeerId::random(), PeerId::random()];
            let mut tables = Vec::new();
            for local in nodes {
                let local_subnet = last
                    .get(&local)
                    .copied()
                    .flatten()
                    .unwrap_or_else(|| own(&local));
                let router = OverlayRouter::new(local, base(), local_subnet);
                // a merge of the lines in a random order
                let mut cursors = vec![0usize; lines.len()];
                let mut routed: BTreeSet<PeerId> = BTreeSet::new();
                loop {
                    let open: Vec<usize> = (0..lines.len())
                        .filter(|i| cursors[*i] < lines[*i].len())
                        .collect();
                    let Some(&i) = open.choose(&mut rng) else {
                        break;
                    };
                    let event = lines[i][cursors[i]];
                    cursors[i] += 1;
                    let change = match event {
                        Event::Claim(p, _) | Event::Gone(p) if p == local => continue,
                        Event::Claim(p, k) => router
                            .add_route(p, subnet_for(base(), &p, k))
                            .await
                            .unwrap(),
                        Event::Gone(p) => router.remove_peer(&p).await,
                    };
                    for p in change.withdrawn {
                        assert!(routed.remove(&p), "seed {seed}: {p} withdrawn, not routed");
                    }
                    for p in change.restored {
                        assert!(routed.insert(p), "seed {seed}: {p} restored, routed");
                    }
                }
                // what it should be: the claims at the end, this node's own
                let mut claims: HashMap<PeerId, Ipv4Net> = last
                    .iter()
                    .filter_map(|(p, s)| s.map(|s| (*p, s)))
                    .collect();
                claims.insert(local, local_subnet);
                let mut want: Vec<(Ipv4Net, PeerId)> = claims
                    .iter()
                    .filter(|(p, s)| {
                        **p != local && claims.values().filter(|o| o == s).count() == 1
                    })
                    .map(|(p, s)| (*s, *p))
                    .collect();
                want.sort();
                let mut got: Vec<(Ipv4Net, PeerId)> = router
                    .get_routes()
                    .await
                    .into_iter()
                    .map(|(s, e)| (s, e.peer_id))
                    .collect();
                got.sort();
                assert_eq!(got, want, "seed {seed}, node {local}");
                let got_peers: BTreeSet<PeerId> = got.iter().map(|(_, p)| *p).collect();
                assert_eq!(routed, got_peers, "seed {seed}");
                tables.push((local_subnet, got));
            }
            // the two nodes that are no peers route the same, but for the
            // subnets of their own
            let (own1, own2) = (tables[1].0, tables[2].0);
            let but_own = |t: &[(Ipv4Net, PeerId)]| -> Vec<(Ipv4Net, PeerId)> {
                t.iter()
                    .filter(|(s, _)| *s != own1 && *s != own2)
                    .copied()
                    .collect()
            };
            assert_eq!(but_own(&tables[1].1), but_own(&tables[2].1), "seed {seed}");
        }
    }
}
