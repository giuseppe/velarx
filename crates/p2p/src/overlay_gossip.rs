// SPDX-License-Identifier: Apache-2.0
//! What the peers of the overlay swarm tell each other: the subnet of each
//! node's containers and their names.  The overlay node keeps it
//! ([`OverlayGossip`]); the content nodes keep nothing of it.  The messages
//! travel in the one gossip protocol ([`GossipMessage`]); what a peer sends
//! is kept as hints, bounded, and checked before it is used.

use super::gossip::{sane_string, DnsRecord, GossipMessage};
use super::limits::valid_dns_name;
use libp2p::PeerId;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, OnceLock};
use tokio::sync::{mpsc, watch, RwLock};
use tracing::{debug, info, warn};

/// TUN overlay peer information (received via gossip); the packets travel
/// over libp2p streams
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunOverlayPeerInfo {
    /// Peer's node subnet (e.g., "10.200.1.0/24")
    pub node_subnet: ipnet::Ipv4Net,
}

/// What the overlay learns of its peers.
#[derive(Debug)]
pub enum OverlayEvent {
    /// A peer announced its overlay subnet.
    Peer(PeerId, TunOverlayPeerInfo),
    /// A peer is gone.
    Gone(PeerId),
}

/// Where the events of the overlay wait: one for each peer, the last it
/// had, so a peer that sends and sends is no queue that grows.
#[derive(Default)]
struct OverlayQueue {
    latest: std::sync::Mutex<HashMap<PeerId, OverlayEvent>>,
}

/// The events of the overlay peers, in the order of the first of each
/// peer's pending ones ([`OverlayGossip::overlay_events`]).
pub struct OverlayEvents {
    wake: mpsc::UnboundedReceiver<PeerId>,
    queue: Arc<OverlayQueue>,
}

impl OverlayEvents {
    /// The next event; `None` when the node that gives them is gone.
    pub async fn recv(&mut self) -> Option<OverlayEvent> {
        loop {
            let peer = self.wake.recv().await?;
            if let Some(event) = self.take(&peer) {
                return Some(event);
            }
        }
    }

    /// The next event, if there is one now.
    pub fn try_recv(&mut self) -> Option<OverlayEvent> {
        loop {
            let peer = self.wake.try_recv().ok()?;
            if let Some(event) = self.take(&peer) {
                return Some(event);
            }
        }
    }

    fn take(&self, peer: &PeerId) -> Option<OverlayEvent> {
        let mut latest = self.queue.latest.lock().unwrap_or_else(|e| e.into_inner());
        latest.remove(peer)
    }
}

/// The sending end of [`OverlayEvents`].
struct OverlaySender {
    wake: mpsc::UnboundedSender<PeerId>,
    queue: Arc<OverlayQueue>,
}

impl OverlaySender {
    /// `event` of `peer`, which replaces the one of it that was not taken.
    fn send(&self, peer: PeerId, event: OverlayEvent) {
        let new = self
            .queue
            .latest
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(peer, event)
            .is_none();
        if new {
            let _ = self.wake.send(peer);
        }
    }
}

/// What is known of the overlay of the peers: the three maps are read
/// together to answer a name, and changed together when a peer is gone.
#[derive(Default)]
struct Overlay {
    /// TUN overlay peers (peer_id -> tun overlay info)
    peers: HashMap<PeerId, TunOverlayPeerInfo>,
    /// The overlay peers that have no route (their subnet is claimed by
    /// another peer too): no name of theirs is answered
    unrouted: HashSet<PeerId>,
    /// Remote DNS records from peers (peer_id -> records)
    dns_records: HashMap<PeerId, Vec<DnsRecord>>,
    /// The peer each name belongs to: the first that claimed it, as this
    /// node heard them (a name claimed by several peers at once, in one
    /// round of messages, belongs to the smallest container id), for as
    /// long as that peer claims it ([`Overlay::settle`])
    owners: HashMap<String, PeerId>,
    /// The names more than one peer claims, as last told of in the log
    collisions: HashSet<String>,
}

impl Overlay {
    /// Settle the owners of the names after the tables changed, and log the
    /// names that came to be claimed by more than one peer since, with the
    /// peers and the container that answers.  Told when the tables change,
    /// not on every lookup: a name two peers claim would otherwise fill the
    /// log at each query of it (and each PTR query reads every name).
    fn settle(&mut self) {
        let claims = claims_of(self);
        let mut owners = HashMap::new();
        let mut collisions = HashSet::new();
        for (name, claims) in &claims {
            // (the owner keeps the name while it claims it; a name that
            // has none is the smallest container id's)
            let kept = self
                .owners
                .get(name)
                .filter(|o| claims.iter().any(|(p, _)| p == *o));
            let of = |(p, _): &(PeerId, &DnsRecord)| kept.is_none_or(|o| p == o);
            let Some((owner, record)) = claims.iter().copied().filter(of).reduce(better_record)
            else {
                continue;
            };
            owners.insert(name.clone(), owner);
            if claims.iter().all(|(p, _)| *p == owner) {
                continue;
            }
            if !self.collisions.contains(name) {
                let mut peers: Vec<String> = claims.iter().map(|(p, _)| p.to_string()).collect();
                peers.sort();
                peers.dedup();
                warn!(
                    "the name {} is claimed by {} peers ({}): it belongs to {}, container {} at {}",
                    name,
                    peers.len(),
                    peers.join(", "),
                    owner,
                    record.container_id,
                    record.ipv4
                );
            }
            collisions.insert(name.clone());
        }
        self.owners = owners;
        self.collisions = collisions;
    }
}

/// Whether `ip` is in the subnet the peer announced for its containers: a
/// peer can only name its own containers, not point a name at another node.
fn in_subnet_of(peer: Option<&TunOverlayPeerInfo>, ip: &std::net::Ipv4Addr) -> bool {
    peer.is_some_and(|peer| peer.node_subnet.contains(ip))
}

/// Of two claims of one name, the one with the smaller container id, and
/// then the smaller peer when two records share one.  The id is what the
/// peer says it is: this decides the same on every node what no node has
/// seen first, it protects nothing ([`Overlay::owners`] does).
fn better_record<'a>(
    a: (PeerId, &'a DnsRecord),
    b: (PeerId, &'a DnsRecord),
) -> (PeerId, &'a DnsRecord) {
    match a
        .1
        .container_id
        .cmp(&b.1.container_id)
        .then_with(|| a.0.cmp(&b.0))
    {
        std::cmp::Ordering::Less | std::cmp::Ordering::Equal => a,
        std::cmp::Ordering::Greater => b,
    }
}

/// Whether the table answers from this record of a peer: the peer is
/// routed, and the address is in the subnet it announced for its
/// containers.
fn answers_from(overlay: &Overlay, peer: &PeerId, record: &DnsRecord) -> bool {
    !overlay.unrouted.contains(peer) && in_subnet_of(overlay.peers.get(peer), &record.ipv4)
}

/// The claims of the peers on each name (in lower case: names are not
/// case sensitive), in the order the table holds the peers in.
fn claims_of(overlay: &Overlay) -> HashMap<String, Vec<(PeerId, &DnsRecord)>> {
    let mut claims: HashMap<String, Vec<(PeerId, &DnsRecord)>> = HashMap::new();
    for (peer, records) in &overlay.dns_records {
        for record in records.iter().filter(|r| answers_from(overlay, peer, r)) {
            claims
                .entry(record.name.to_ascii_lowercase())
                .or_default()
                .push((*peer, record));
        }
    }
    claims
}

/// The record `name` (in lower case) answers with, among the claims on it:
/// the one of the peer the name belongs to.
fn owned_record<'a>(
    overlay: &Overlay,
    name: &str,
    claims: &[(PeerId, &'a DnsRecord)],
) -> Option<(PeerId, &'a DnsRecord)> {
    let owner = overlay.owners.get(name);
    claims
        .iter()
        .copied()
        .filter(|(p, _)| owner.is_none_or(|o| p == o))
        .reduce(better_record)
}

/// The answer to a name, among the remote records the peers announced.
fn chosen_record<'a>(overlay: &'a Overlay, name: &str) -> Option<(PeerId, &'a DnsRecord)> {
    let name = name.to_ascii_lowercase();
    owned_record(overlay, &name, claims_of(overlay).get(&name)?)
}

/// The record of `name` that the peer `peer` (its id in any case: a DNS
/// question comes in lower case) announced, whoever the name belongs to.
fn scoped_record<'a>(overlay: &'a Overlay, peer: &str, name: &str) -> Option<&'a DnsRecord> {
    let (peer, records) = overlay
        .dns_records
        .iter()
        .find(|(p, _)| p.to_base58().eq_ignore_ascii_case(peer))?;
    records
        .iter()
        .find(|r| r.name.eq_ignore_ascii_case(name) && answers_from(overlay, peer, r))
}

/// The DNS records of a peer that name a container and an IPv4 address.
fn sane_dns_records(records: Vec<DnsRecord>) -> Vec<DnsRecord> {
    records
        .into_iter()
        .filter(|r| valid_dns_name(&r.name) && sane_string(&r.container_id, 128))
        .collect()
}

/// What the overlay node knows of the overlay of its peers, and tells them
/// of its own.
#[derive(Default)]
pub struct OverlayGossip {
    /// What is known of the overlay of the peers
    overlay: RwLock<Overlay>,
    /// Where the overlay events go (set once, by [`Self::overlay_events`])
    overlay_events: OnceLock<OverlaySender>,
    /// The subnet of this node's containers, once it announced it
    subnet: std::sync::Mutex<Option<ipnet::Ipv4Net>>,
    /// Local DNS records (container name -> record)
    local_dns_records: RwLock<HashMap<String, DnsRecord>>,
    /// How many times what is known of the peers changed
    changed: watch::Sender<u64>,
}

impl OverlayGossip {
    /// Handle a gossip message of a peer: its subnet or its names (the
    /// other kinds are the content's).
    pub async fn handle_gossip_message(&self, from: PeerId, msg: GossipMessage) {
        if !matches!(
            msg,
            GossipMessage::TunOverlayAnnounce { .. } | GossipMessage::DnsRecordAnnounce { .. }
        ) {
            return;
        }
        match msg {
            GossipMessage::TunOverlayAnnounce { node_subnet } => {
                debug!(
                    "Received TUN overlay peer info from {}: subnet={}",
                    from, node_subnet
                );

                let peer_info = TunOverlayPeerInfo { node_subnet };

                // (what it said before is nothing new)
                {
                    let mut overlay = self.overlay.write().await;
                    if overlay.peers.get(&from) == Some(&peer_info) {
                        return;
                    }
                    overlay.peers.insert(from, peer_info.clone());
                    overlay.settle();
                }

                if let Some(events) = self.overlay_events.get() {
                    events.send(from, OverlayEvent::Peer(from, peer_info));
                }
            }
            GossipMessage::DnsRecordAnnounce { records } => {
                let records = sane_dns_records(records);
                debug!(
                    "Received DNS records from {}: {} records",
                    from,
                    records.len()
                );
                // (what it said before is nothing new)
                let mut overlay = self.overlay.write().await;
                if overlay.dns_records.get(&from) == Some(&records) {
                    return;
                }
                overlay.dns_records.insert(from, records);
                overlay.settle();
            }
            _ => {}
        }
        self.changed.send_modify(|n| *n += 1);
    }

    /// What is known of the peers as it changes: the receiver is told after
    /// each message of a peer was handled and after a peer was gone.
    pub fn changes(&self) -> watch::Receiver<u64> {
        self.changed.subscribe()
    }

    /// Remove a specific peer (called on disconnect): its subnet, its route
    /// and its DNS records.
    pub async fn remove_peer(&self, peer: &PeerId) {
        {
            let mut overlay = self.overlay.write().await;
            overlay.peers.remove(peer);
            overlay.unrouted.remove(peer);
            overlay.dns_records.remove(peer);
            overlay.settle();
        }
        if let Some(events) = self.overlay_events.get() {
            events.send(*peer, OverlayEvent::Gone(*peer));
        }
        self.changed.send_modify(|n| *n += 1);
    }

    /// Whether the router has a route to the subnet of the peer: when it
    /// has not (it refused the claim, or another peer claims the subnet
    /// too), no name of the peer is answered.
    pub async fn set_tun_overlay_routed(&self, peer: &PeerId, routed: bool) {
        let mut overlay = self.overlay.write().await;
        if routed {
            overlay.unrouted.remove(peer);
        } else {
            overlay.unrouted.insert(*peer);
        }
        overlay.settle();
    }

    /// The events of the TUN overlay peers (announced, gone), the last of
    /// each peer's that were not taken, in the order they came; `None` when
    /// they were asked for before.
    pub fn overlay_events(&self) -> Option<OverlayEvents> {
        let (wake, rx) = mpsc::unbounded_channel();
        let queue = Arc::new(OverlayQueue::default());
        let sender = OverlaySender {
            wake,
            queue: queue.clone(),
        };
        self.overlay_events
            .set(sender)
            .ok()
            .map(|()| OverlayEvents { wake: rx, queue })
    }

    /// The subnet of this node's containers, for the peers: told again to
    /// each peer that connects later ([`Self::hello`]).
    pub fn set_subnet(&self, subnet: ipnet::Ipv4Net) -> GossipMessage {
        *self.subnet.lock().unwrap_or_else(|e| e.into_inner()) = Some(subnet);
        GossipMessage::TunOverlayAnnounce {
            node_subnet: subnet,
        }
    }

    /// What a peer that connects is told: the subnet and the names of this
    /// node's containers.
    pub async fn hello(&self) -> Vec<GossipMessage> {
        let subnet = *self.subnet.lock().unwrap_or_else(|e| e.into_inner());
        let mut told = Vec::new();
        if let Some(node_subnet) = subnet {
            told.push(GossipMessage::TunOverlayAnnounce { node_subnet });
        }
        if !self.local_dns_records.read().await.is_empty() {
            told.push(self.get_dns_announce_message().await);
        }
        told
    }

    /// Add a local DNS record for a container
    pub async fn add_dns_record(&self, record: DnsRecord) {
        info!(
            "Adding DNS record: {} -> {} (container: {})",
            record.name, record.ipv4, record.container_id
        );
        let mut records = self.local_dns_records.write().await;
        records.insert(record.name.to_ascii_lowercase(), record);
    }

    /// Remove DNS record by container ID
    pub async fn remove_dns_record_by_container_id(&self, container_id: &str) {
        let mut records = self.local_dns_records.write().await;
        records.retain(|_, r| r.container_id != container_id);
    }

    /// Create a DNS record announce message
    pub async fn get_dns_announce_message(&self) -> GossipMessage {
        let records = self.local_dns_records.read().await;
        GossipMessage::DnsRecordAnnounce {
            records: records.values().cloned().collect(),
        }
    }

    /// Resolve a DNS name to an IP address (names are not case sensitive).
    /// Searches local records first, then the records the peers announced:
    /// a name belongs to the first peer that claimed it, and its record
    /// answers ([`Overlay::settle`]); a member of the swarm that announces a
    /// name another peer holds does not take it.
    pub async fn resolve_dns(&self, name: &str) -> Option<DnsRecord> {
        {
            let records = self.local_dns_records.read().await;
            if let Some(record) = records.get(&name.to_ascii_lowercase()) {
                return Some(record.clone());
            }
        }

        let overlay = self.overlay.read().await;
        chosen_record(&overlay, name).map(|(_, record)| record.clone())
    }

    /// The record of the container `name` of `peer`, the peer's own word for
    /// what it runs: a name that another peer holds too reaches this one's
    /// container as `name.<peer id>`.
    pub async fn resolve_dns_of(&self, peer: &str, name: &str) -> Option<DnsRecord> {
        let overlay = self.overlay.read().await;
        scoped_record(&overlay, peer, name).cloned()
    }

    /// Get all known DNS records (local + remote)
    pub async fn get_all_dns_records(&self) -> Vec<DnsRecord> {
        let mut all_records = Vec::new();

        {
            let records = self.local_dns_records.read().await;
            all_records.extend(records.values().cloned());
        }

        // Add remote records (deduplicated by name, prefer local): one
        // record per name, the one of the peer the name belongs to.
        let local_names: HashSet<String> = all_records
            .iter()
            .map(|r| r.name.to_ascii_lowercase())
            .collect();
        let overlay = self.overlay.read().await;
        let claims = claims_of(&overlay);
        let mut names: Vec<&String> = claims
            .keys()
            .filter(|n| !local_names.contains(*n))
            .collect();
        names.sort_unstable();
        all_records.extend(names.into_iter().filter_map(|name| {
            owned_record(&overlay, name, &claims[name]).map(|(_, r)| r.clone())
        }));

        all_records
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(name: &str, ip: &str) -> DnsRecord {
        record_of("c1", name, ip)
    }

    /// A record with its container id (`c1` when it is left out): the id,
    /// not the order the peers were heard in, decides which record of a
    /// name two peers claim answers.
    fn record_of(container_id: &str, name: &str, ip: &str) -> DnsRecord {
        DnsRecord {
            name: name.to_string(),
            ipv4: ip.parse().unwrap(),
            container_id: container_id.to_string(),
        }
    }

    #[tokio::test]
    async fn a_peer_without_a_route_has_no_name_until_it_has_one_again() {
        let g = OverlayGossip::default();
        let _events = g.overlay_events();
        let a = PeerId::random();
        g.handle_gossip_message(
            a,
            GossipMessage::TunOverlayAnnounce {
                node_subnet: "10.200.2.0/24".parse().unwrap(),
            },
        )
        .await;
        g.handle_gossip_message(
            a,
            GossipMessage::DnsRecordAnnounce {
                records: vec![record("web", "10.200.2.5")],
            },
        )
        .await;
        assert!(g.resolve_dns("web").await.is_some());
        g.set_tun_overlay_routed(&a, false).await;
        assert!(g.resolve_dns("web").await.is_none());
        assert!(g.get_all_dns_records().await.is_empty());
        g.set_tun_overlay_routed(&a, true).await;
        assert!(g.resolve_dns("web").await.is_some());
    }

    #[tokio::test]
    async fn test_a_peer_can_only_name_addresses_of_its_own_subnet() {
        let g = OverlayGossip::default();
        let _events = g.overlay_events();
        let (a, b) = (PeerId::random(), PeerId::random());
        let announce = |subnet: &str| GossipMessage::TunOverlayAnnounce {
            node_subnet: subnet.parse().unwrap(),
        };
        g.handle_gossip_message(a, announce("10.200.2.0/24")).await;
        g.handle_gossip_message(b, announce("10.200.3.0/24")).await;
        // `a` names its own container, one of b's and garbage.
        g.handle_gossip_message(
            a,
            GossipMessage::DnsRecordAnnounce {
                records: vec![
                    record("web", "10.200.2.5"),
                    record("db", "10.200.3.7"),
                    record("bad name", "10.200.2.6"),
                ],
            },
        )
        .await;
        assert_eq!(
            g.resolve_dns("web").await.unwrap().ipv4,
            "10.200.2.5".parse::<std::net::Ipv4Addr>().unwrap()
        );
        assert!(
            g.resolve_dns("db").await.is_none(),
            "pointing at the subnet of another peer"
        );
        assert!(g.resolve_dns("bad name").await.is_none());
        // b's own record for the name is then the one that counts.
        g.handle_gossip_message(
            b,
            GossipMessage::DnsRecordAnnounce {
                records: vec![record("db", "10.200.3.7")],
            },
        )
        .await;
        assert_eq!(
            g.resolve_dns("db").await.unwrap().ipv4,
            "10.200.3.7".parse::<std::net::Ipv4Addr>().unwrap()
        );
        let all = g.get_all_dns_records().await;
        assert_eq!(all.len(), 2);
        // A peer that never said which subnet is its own names nothing.
        let c = PeerId::random();
        g.handle_gossip_message(
            c,
            GossipMessage::DnsRecordAnnounce {
                records: vec![record("x", "10.200.9.9")],
            },
        )
        .await;
        assert!(g.resolve_dns("x").await.is_none());
    }

    /// A name belongs to the first peer that claimed it, as this node heard
    /// them, for as long as that peer claims it: a member that announces
    /// the name later does not take it, whatever container id it gives.
    /// The container of any peer is reached by `resolve_dns_of`.  The
    /// collision is told of once.
    #[tokio::test]
    async fn a_name_belongs_to_the_first_peer_that_claimed_it() {
        let (a, b, c) = (PeerId::random(), PeerId::random(), PeerId::random());
        let announce = |subnet: &str| GossipMessage::TunOverlayAnnounce {
            node_subnet: subnet.parse().unwrap(),
        };
        let announce_web = |id: &str, ip: &str| GossipMessage::DnsRecordAnnounce {
            records: vec![record_of(id, "web", ip)],
        };
        let ip = |s: &str| s.parse::<std::net::Ipv4Addr>().unwrap();
        for first in [a, b] {
            let second = if first == a { b } else { a };
            let g = OverlayGossip::default();
            let _events = g.overlay_events();
            let (told, again) = {
                let logged = velarx_wire::logcapture::capture(tracing::Level::WARN);
                g.handle_gossip_message(a, announce("10.200.2.0/24")).await;
                g.handle_gossip_message(b, announce("10.200.3.0/24")).await;
                // (the later claim has the smaller container id)
                let (own, late) = if first == a {
                    (("zz", "10.200.2.5"), ("aa", "10.200.3.5"))
                } else {
                    (("zz", "10.200.3.5"), ("aa", "10.200.2.5"))
                };
                g.handle_gossip_message(first, announce_web(own.0, own.1))
                    .await;
                g.handle_gossip_message(second, announce_web(late.0, late.1))
                    .await;
                let told = logged.text();
                g.resolve_dns("web").await;
                g.get_all_dns_records().await;
                g.handle_gossip_message(first, announce_web(own.0, own.1))
                    .await;
                (told, logged.text())
            };
            let web = g.resolve_dns("WEB").await.expect("the name is claimed");
            assert_eq!(
                web.container_id, "zz",
                "the first claim, not the smaller id"
            );
            assert_eq!(g.get_all_dns_records().await, vec![web.clone()]);
            assert!(told.contains("claimed by 2 peers"), "logged: {told}");
            assert!(told.contains(&first.to_string()), "the owner: {told}");
            assert_eq!(told, again, "told once");
            // the container of each peer by its own name
            assert_eq!(g.resolve_dns_of(&first.to_string(), "web").await, Some(web));
            assert_eq!(
                g.resolve_dns_of(&second.to_string().to_ascii_lowercase(), "web")
                    .await
                    .map(|r| r.container_id),
                Some("aa".to_string())
            );
            // the owner is gone: the other answers, and keeps the name when
            // the owner comes back
            g.remove_peer(&first).await;
            assert_eq!(g.resolve_dns("web").await.unwrap().container_id, "aa");
            g.handle_gossip_message(first, announce("10.200.9.0/24"))
                .await;
            g.handle_gossip_message(first, announce_web("0", "10.200.9.5"))
                .await;
            assert_eq!(g.resolve_dns("web").await.unwrap().container_id, "aa");
        }
        // an owner that no longer claims the name leaves it to the smallest
        // container id of the others
        let g = OverlayGossip::default();
        let _events = g.overlay_events();
        for (peer, subnet, id, ip_of) in [
            (a, "10.200.2.0/24", "m", "10.200.2.5"),
            (b, "10.200.3.0/24", "z", "10.200.3.5"),
            (c, "10.200.4.0/24", "b", "10.200.4.5"),
        ] {
            g.handle_gossip_message(peer, announce(subnet)).await;
            g.handle_gossip_message(peer, announce_web(id, ip_of)).await;
        }
        assert_eq!(g.resolve_dns("web").await.unwrap().container_id, "m");
        g.handle_gossip_message(a, GossipMessage::DnsRecordAnnounce { records: vec![] })
            .await;
        assert_eq!(g.resolve_dns("web").await.unwrap().ipv4, ip("10.200.4.5"));
    }

    #[tokio::test]
    async fn the_overlay_events_come_in_the_order_they_happened() {
        let g = OverlayGossip::default();
        let (a, b) = (PeerId::random(), PeerId::random());
        let mut events = g.overlay_events().expect("the first to ask");
        assert!(g.overlay_events().is_none(), "one receiver");
        let announce = |subnet: &str| GossipMessage::TunOverlayAnnounce {
            node_subnet: subnet.parse().unwrap(),
        };
        g.handle_gossip_message(a, announce("10.200.2.0/24")).await;
        g.handle_gossip_message(b, announce("10.200.4.0/24")).await;
        // (what a peer said and nobody took is replaced by what it said
        // after: a peer that says it again and again is one event)
        g.handle_gossip_message(a, announce("10.200.3.0/24")).await;
        for _ in 0..50 {
            g.handle_gossip_message(a, announce("10.200.3.0/24")).await;
        }
        let peer = |event: Option<OverlayEvent>| match event {
            Some(OverlayEvent::Peer(p, info)) => (p, info.node_subnet.to_string()),
            e => panic!("a peer event, not {e:?}"),
        };
        assert_eq!(peer(events.try_recv()), (a, "10.200.3.0/24".to_string()));
        assert_eq!(peer(events.try_recv()), (b, "10.200.4.0/24".to_string()));
        assert!(events.try_recv().is_none(), "nothing else");
        // a peer that is gone after it announced is gone
        g.handle_gossip_message(a, announce("10.200.5.0/24")).await;
        g.remove_peer(&a).await;
        assert!(matches!(events.try_recv(), Some(OverlayEvent::Gone(p)) if p == a));
        assert!(events.try_recv().is_none());
    }

    /// A peer that connects later is told the subnet and the names.
    #[tokio::test]
    async fn a_peer_that_connects_later_is_told_the_subnet_and_the_names() {
        let g = OverlayGossip::default();
        assert!(g.hello().await.is_empty());
        g.set_subnet("10.200.2.0/24".parse().unwrap());
        g.add_dns_record(record("web", "10.200.2.5")).await;
        let told = g.hello().await;
        assert!(matches!(told[0], GossipMessage::TunOverlayAnnounce { .. }));
        assert!(matches!(told[1], GossipMessage::DnsRecordAnnounce { .. }));
    }
}
