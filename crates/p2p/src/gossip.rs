// SPDX-License-Identifier: Apache-2.0
//! What peers tell each other and what they remember of it.
//!
//! The layers a node holds are told as a filter ([`crate::filter`]), which
//! the peers keep in [`Knowledge`] (the one table of who holds what); the
//! messages of it come through here.  A node tells the list of its images
//! only when it was told to announce (`announce_images` in `p2p.toml`,
//! [`GossipDiscovery::announcing`]) and refuses the question for it
//! otherwise; what it holds can be asked for one digest at a time (the probe
//! of the QUIC data protocol, [`super::quic::OP_PROBE`]) or tested in its
//! filter.  What peers tell this node is kept as hints, which are
//! checked before they are used.  The overlay network's announcements
//! (subnet, container names) are the overlay node's
//! ([`crate::overlay_gossip`]).

use super::filter::{FilterDelta, FilterFull};
use super::knowledge::Knowledge;
use super::limits::MAX_REQUEST_BYTES;
use libp2p::PeerId;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{watch, RwLock};
use tracing::debug;
use velarx_types::LayerKey;

pub use velarx_core::store_service::ImageInfo;

/// DNS record for container name resolution across P2P cluster
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DnsRecord {
    /// Container name (the name to resolve)
    pub name: String,
    /// IPv4 address (overlay IP)
    pub ipv4: std::net::Ipv4Addr,
    /// Container ID (for disambiguation if names conflict)
    pub container_id: String,
}

/// Gossip message types
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum GossipMessage {
    /// The layers the sender holds, as a Bloom filter that replaces the one
    /// it sent before (sent unless the sender keeps them to itself)
    LayerFilter(FilterFull),
    /// What the sender added to its filter since a version of it
    LayerFilterDelta(FilterDelta),
    /// The images of the sender (sent only by a node that announces)
    ImageAnnounce {
        /// List of images available on this peer
        images: Vec<ImageInfo>,
    },
    /// The images the peer announces, asked for (a node that does not
    /// announce does not answer): the answer is a [`crate::GossipReply`]
    ImageQuery,
    /// Which peers the receiver is connected to, asked by a node that has few:
    /// the answer is a [`crate::GossipReply`] (`peer_exchange`)
    PeerQuery,
    /// The revocation lists the sender holds, told when it took a newer one
    /// (a node adopts the ones that are signed and newer, so a list reaches
    /// the peers that were connected before it was made)
    Revocations {
        /// The lists, each as text
        lists: Vec<String>,
    },
    /// Announce TUN-based overlay network presence (uses libp2p streams for transport)
    TunOverlayAnnounce {
        /// This node's overlay subnet (e.g., "10.200.1.0/24")
        node_subnet: ipnet::Ipv4Net,
    },
    /// Announce DNS records (container name → IP mappings)
    DnsRecordAnnounce {
        /// List of DNS records from this peer
        records: Vec<DnsRecord>,
    },
}

pub(crate) fn sane_string(s: &str, max: usize) -> bool {
    s.len() <= max && !s.chars().any(char::is_control)
}

/// The images of a peer that are well formed.
fn sane_images(images: Vec<ImageInfo>) -> Vec<ImageInfo> {
    images
        .into_iter()
        .filter(|i| {
            sane_string(&i.id, 128)
                && i.complete
                && crate::limits::is_digest(&i.manifest_digest)
                && crate::limits::is_digest(&i.config_digest)
                && i.repo_digests.iter().all(|t| sane_string(t, 512))
                && i.tags.iter().all(|t| sane_string(t, 256))
                && i.layers.iter().all(|l| LayerKey::parse(l).is_some())
                && sane_string(&i.created_at, 64)
        })
        .collect()
}

/// Gossip-based content discovery service
pub struct GossipDiscovery {
    /// Whether this node tells its peers what it has (`announce_images`)
    announcing: bool,
    /// The images each peer announced
    peer_images: RwLock<HashMap<PeerId, Vec<ImageInfo>>>,
    /// Where the filters of the peers are kept
    knowledge: Arc<Knowledge>,
    /// Images available locally
    local_images: RwLock<Vec<ImageInfo>>,
    /// How many times what is known of the peers changed: a message of a
    /// peer was handled, or a peer was gone ([`Self::changes`])
    changed: watch::Sender<u64>,
}

impl GossipDiscovery {
    /// A node that tells its peers no list of its images.
    pub fn new() -> Self {
        Self {
            announcing: false,
            peer_images: RwLock::default(),
            knowledge: Arc::default(),
            local_images: RwLock::default(),
            changed: watch::Sender::new(0),
        }
    }

    /// A node that tells its peers its images.
    pub fn announcing() -> Self {
        Self {
            announcing: true,
            ..Self::new()
        }
    }

    /// The same, keeping what the peers tell of their layers in `knowledge`.
    pub fn with_knowledge(mut self, knowledge: Arc<Knowledge>) -> Self {
        self.knowledge = knowledge;
        self
    }

    /// What is known of the peers' layers.
    pub fn knowledge(&self) -> &Arc<Knowledge> {
        &self.knowledge
    }

    /// Whether this node tells its peers its images.
    pub fn is_announcing(&self) -> bool {
        self.announcing
    }

    /// The images this node tells.
    pub async fn images_told(&self) -> usize {
        self.local_images.read().await.len()
    }

    /// Handle received gossip message from a peer
    pub async fn handle_gossip_message(&self, from: PeerId, msg: GossipMessage) {
        match msg {
            filter @ (GossipMessage::LayerFilter(_) | GossipMessage::LayerFilterDelta(_)) => {
                // (a refused one leaves the peer with no filter: it is
                // asked as before)
                match self.knowledge.filter_received(from, &filter) {
                    Ok(()) => debug!(
                        "{from} told a filter of {} layers",
                        self.knowledge.filter_keys(&from)
                    ),
                    Err(why) => debug!("The filter of {from} is refused: {why}"),
                }
            }
            GossipMessage::ImageAnnounce { images } => {
                let images = sane_images(images);
                debug!("Peer {} announced {} images", from, images.len());
                self.peer_images.write().await.insert(from, images);
            }
            GossipMessage::ImageQuery => {
                // (the node answers it)
                debug!("Received image query from {}", from);
            }
            GossipMessage::PeerQuery => {
                // (answered by the node, which knows its connections)
                debug!("Received a peer query from {}", from);
            }
            // (taken by the node, which has the authority)
            GossipMessage::Revocations { .. } => {}
            // (the overlay's: a content node keeps nothing of it)
            GossipMessage::TunOverlayAnnounce { .. } | GossipMessage::DnsRecordAnnounce { .. } => {}
        }
        self.changed.send_modify(|n| *n += 1);
    }

    /// What is known of the peers as it changes: the receiver is told after
    /// each message of a peer was handled and after a peer was gone, so a
    /// condition on the tables is checked again then instead of polled.
    pub fn changes(&self) -> watch::Receiver<u64> {
        self.changed.subscribe()
    }

    /// Remove a specific peer (called on disconnect)
    pub async fn remove_peer(&self, peer: &PeerId) {
        self.peer_images.write().await.remove(peer);
        self.knowledge.filter_gone(peer);
        self.changed.send_modify(|n| *n += 1);
    }

    /// The local images, all of them (the list replaces the one before).
    /// Those announced are what a peer keeps, in a message it reads: the
    /// images it would drop are not sent, and the list stops before the
    /// message is larger than a frame (else no image at all would go).
    pub async fn set_images(&self, new_images: Vec<ImageInfo>) {
        if !self.announcing {
            return;
        }
        let given = new_images.len();
        // (room for what holds the list)
        let mut room = MAX_REQUEST_BYTES - 1024;
        let kept: Vec<ImageInfo> = sane_images(new_images)
            .into_iter()
            .take_while(|i| {
                let size = serde_json::to_vec(i).map_or(usize::MAX, |v| v.len() + 1);
                room = room.saturating_sub(size);
                room > 0
            })
            .collect();
        if kept.len() < given {
            debug!("{} of the {given} local images are announced", kept.len());
        }
        *self.local_images.write().await = kept;
    }

    /// Get all remote images from peers
    pub async fn get_remote_images(&self) -> Vec<(PeerId, ImageInfo)> {
        let peer_images = self.peer_images.read().await;
        let mut result = Vec::new();

        for (peer_id, images) in peer_images.iter() {
            for image in images {
                result.push((*peer_id, image.clone()));
            }
        }

        result
    }

    /// The message that tells the peers the images of this node (`None`
    /// when it does not announce).
    pub async fn get_image_announce_message(&self) -> Option<GossipMessage> {
        if !self.announcing {
            return None;
        }
        let images = self.local_images.read().await;
        Some(GossipMessage::ImageAnnounce {
            images: images.clone(),
        })
    }

    /// The answer to a question for the images of this node: nothing when
    /// it does not announce, so that nobody can walk what it has.
    pub async fn image_reply(&self) -> crate::GossipReply {
        if !self.announcing {
            return crate::GossipReply::default();
        }
        crate::GossipReply {
            images: Some(self.local_images.read().await.clone()),
            ..Default::default()
        }
    }
}

impl Default for GossipDiscovery {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex_digest(n: usize) -> String {
        velarx_types::digest::Digest::of(
            velarx_types::digest::Algorithm::Sha256,
            n.to_string().as_bytes(),
        )
        .to_string()
    }

    fn image(id: &str, digest: &str) -> ImageInfo {
        ImageInfo {
            id: id.to_string(),
            manifest_digest: digest.to_string(),
            config_digest: hex_digest(2),
            tags: vec!["a:b".to_string()],
            repo_digests: Vec::new(),
            layers: vec![hex_digest(1)],
            size: 1,
            created_at: "2026-01-01T00:00:00Z".to_string(),
            complete: true,
        }
    }

    /// An image named by a sha512 (an id of 128 hex digits) is kept like one
    /// named by a sha256; a longer id is not.
    #[test]
    fn test_an_image_of_a_sha512_manifest_is_kept() {
        let sha512 =
            velarx_types::digest::Digest::of(velarx_types::digest::Algorithm::Sha512, b"m");
        let named = ImageInfo {
            config_digest: sha512.to_string(),
            ..image(&sha512.hex(), &sha512.to_string())
        };
        let longer = image(&"a".repeat(129), &hex_digest(3));
        let kept = sane_images(vec![named.clone(), longer]);
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].id, named.id);
    }

    /// The images announced are those a peer keeps, in one frame.
    #[tokio::test]
    async fn test_the_images_announced_fit_in_a_message() {
        let g = GossipDiscovery::announcing();
        let mut big = image("big", &hex_digest(9));
        big.layers = (0..512).map(hex_digest).collect();
        let mut images: Vec<ImageInfo> = (0..5000)
            .map(|n| ImageInfo {
                id: format!("{n}"),
                ..big.clone()
            })
            .collect();
        images.insert(
            0,
            ImageInfo {
                complete: false,
                ..image("partial", &hex_digest(8))
            },
        );
        g.set_images(images).await;
        let Some(message) = g.get_image_announce_message().await else {
            panic!("no message");
        };
        let GossipMessage::ImageAnnounce { images } = &message else {
            panic!("{message:?}");
        };
        assert!(!images.is_empty() && images.len() < 5000);
        assert!(images.iter().all(|i| i.complete));
        assert!(serde_json::to_vec(&message).unwrap().len() <= MAX_REQUEST_BYTES);
        let reply = g.image_reply().await;
        assert!(serde_json::to_vec(&reply).unwrap().len() <= MAX_REQUEST_BYTES);
    }

    /// A node that was not told to announce says nothing of its images: none
    /// is announced, and the question for the list has no answer to send.
    #[tokio::test]
    async fn test_a_node_that_does_not_announce_tells_nothing() {
        for g in [GossipDiscovery::new(), GossipDiscovery::default()] {
            assert!(!g.is_announcing());
            g.set_images(vec![image("abc", &hex_digest(7))]).await;
            assert!(g.get_image_announce_message().await.is_none());
            assert!(g.image_reply().await.images.is_none());
            assert!(g.local_images.read().await.is_empty());
        }
        let g = GossipDiscovery::announcing();
        g.set_images(vec![image("abc", &hex_digest(7))]).await;
        assert!(matches!(
            g.get_image_announce_message().await,
            Some(GossipMessage::ImageAnnounce { images }) if images.len() == 1
        ));
        assert!(matches!(
            g.image_reply().await.images,
            Some(images) if images.len() == 1
        ));
    }

    #[tokio::test]
    async fn test_what_a_peer_announced_holds_while_it_is_connected() {
        let g = GossipDiscovery::new();
        let peer = PeerId::random();
        let d = hex_digest(1);
        let mut told = crate::filter::Advertiser::new(
            crate::filter::Config::default(),
            crate::entropy::Entropy::seeded(1),
        );
        told.add(std::slice::from_ref(&d));
        g.handle_gossip_message(peer, told.full().unwrap()).await;
        // (told once: nothing expires it, only the end of the connection)
        g.handle_gossip_message(
            peer,
            GossipMessage::ImageAnnounce {
                images: vec![image("abc", &hex_digest(7))],
            },
        )
        .await;
        assert!(g.knowledge().filtered(&d).maybe.contains(&peer));
        assert_eq!(g.get_remote_images().await.len(), 1);
        g.remove_peer(&peer).await;
        assert!(g.knowledge().filtered(&d).maybe.is_empty());
        assert!(g.get_remote_images().await.is_empty());
    }

    #[tokio::test]
    async fn test_the_images_of_a_peer_are_checked() {
        let g = GossipDiscovery::new();
        let peer = PeerId::random();
        let good = image("abc", &hex_digest(7));
        let mut images = vec![
            good.clone(),
            image("abc", "nope"),
            image(&"x".repeat(129), &hex_digest(8)),
            image("line\nbreak", &hex_digest(9)),
        ];
        let mut bad_layer = good.clone();
        bad_layer.layers = vec!["../../etc".to_string()];
        images.push(bad_layer);
        let mut partial = good.clone();
        partial.complete = false;
        images.push(partial);
        g.handle_gossip_message(peer, GossipMessage::ImageAnnounce { images })
            .await;
        let seen = g.get_remote_images().await;
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].1.id, "abc");
    }

    /// Who waits for what the peers told is woken by each message handled
    /// and by a peer that is gone, instead of asking again and again.
    #[tokio::test]
    async fn a_change_of_the_tables_is_told() {
        let g = GossipDiscovery::new();
        let a = PeerId::random();
        let mut changes = g.changes();
        assert!(!changes.has_changed().unwrap());
        g.handle_gossip_message(a, GossipMessage::PeerQuery).await;
        assert!(changes.has_changed().unwrap(), "a message is not told");
        changes.borrow_and_update();
        g.remove_peer(&a).await;
        assert!(
            changes.has_changed().unwrap(),
            "a peer that is gone is not told"
        );
    }

    /// What a peer sends is typed: a subnet that is none, an address that
    /// is no IPv4 one and the messages nothing sends or handles are not
    /// messages, instead of strings that are parsed again where they are
    /// used (with an address that reads as 0.0.0.0 when they are not).
    #[test]
    fn the_messages_of_a_peer_are_typed() {
        let parse = |text: &str| serde_json::from_str::<GossipMessage>(text);
        assert!(parse(r#"{"TunOverlayAnnounce":{"node_subnet":"10.200.2.0/24"}}"#).is_ok());
        assert!(parse(r#"{"TunOverlayAnnounce":{"node_subnet":"x"}}"#).is_err());
        let record = |ip: &str| {
            format!(
                r#"{{"DnsRecordAnnounce":{{"records":[{{"name":"web","ipv4":"{ip}","container_id":"c"}}]}}}}"#
            )
        };
        assert!(parse(&record("10.200.2.5")).is_ok());
        assert!(parse(&record("::1")).is_err());
        assert!(parse(&record("web")).is_err());
        // (the messages that were read and dropped)
        assert!(parse(r#"{"DnsRecordQuery":{"name":"web"}}"#).is_err());
        assert!(parse(r#"{"DnsRecordResponse":{"records":[]}}"#).is_err());
    }
}
