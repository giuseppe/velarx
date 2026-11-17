// SPDX-License-Identifier: Apache-2.0
//! Nodes of a swarm with a certificate authority: admitted by their
//! certificates, on libp2p (the upgrade after Noise) and on QUIC, with no
//! swarm key; refused with a certificate of another authority; cut off when
//! revoked.

use super::support::{address, connected_within, digest_of, fetch, key, Chunks};
use libp2p::identity::Keypair;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use velarx_p2p::authority::{Authority, Config, Role};
use velarx_p2p::{ca, P2PConfig, P2PNode};

/// The authority of a swarm, in a directory.
struct Swarm {
    dir: tempfile::TempDir,
}

struct Member {
    key: Keypair,
    authority: Arc<Authority>,
}

impl Swarm {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        ca::init(&dir.path().join("ca"), 365).unwrap();
        Self { dir }
    }

    fn ca(&self) -> PathBuf {
        self.dir.path().join("ca")
    }

    fn member(&self, name: &str, role: Role, revocations: Option<&Path>) -> Member {
        let key = Keypair::generate_ed25519();
        let (pem, _) = ca::sign(&self.ca(), &ca::request(&key), name, None, role, 30).unwrap();
        let certificate_path = self.dir.path().join(format!("{name}.crt"));
        std::fs::write(&certificate_path, pem).unwrap();
        let authority = Authority::load(
            Config {
                ca_path: self.ca().join("ca.crt"),
                certificate_path,
                revocation_path: revocations.map(Path::to_path_buf),
                sweep: Duration::from_millis(100),
                ..Config::default()
            },
            &key,
        )
        .unwrap();
        Member { key, authority }
    }
}

async fn node(member: &Member, swarm_key: Option<&Path>) -> Arc<P2PNode> {
    node_of(velarx_p2p::Role::Content, member, swarm_key).await
}

async fn node_of(
    role: velarx_p2p::Role,
    member: &Member,
    swarm_key: Option<&Path>,
) -> Arc<P2PNode> {
    Arc::new(
        P2PNode::with_config(P2PConfig {
            role,
            listen_addrs: vec!["/ip4/127.0.0.1/tcp/0".into()],
            enable_mdns: false,
            identity: Some(member.key.clone()),
            authority: Some(member.authority.clone()),
            private_key_path: swarm_key.map(Path::to_path_buf),
            dial: velarx_p2p::dial_filter::Rules::on_one_host(),
            ..Default::default()
        })
        .await
        .unwrap(),
    )
}

#[tokio::test]
async fn certified_nodes_connect_and_exchange_chunks_without_a_swarm_key() {
    let swarm = Swarm::new();
    let (ma, mb) = (
        swarm.member("a", Role::Both, None),
        swarm.member("b", Role::Both, None),
    );
    let (a, b) = (node(&ma, None).await, node(&mb, None).await);
    let data = b"a chunk of the certified swarm".to_vec();
    let d = digest_of(&data);
    a.set_chunk_provider(Arc::new(Chunks([(d.clone(), data.clone())].into())))
        .unwrap();
    b.dial(address(&a).await).await.unwrap();
    assert!(connected_within(&b, &a, Duration::from_secs(5)).await);
    assert_eq!(
        fetch(&b, &a, std::slice::from_ref(&d)).await.unwrap(),
        [(d, data)]
    );
    // each knows the other by its certificate
    let who = ma.authority.who(&b.peer_id()).unwrap();
    assert_eq!(who.name, "b");
    assert_eq!(mb.authority.who(&a.peer_id()).unwrap().name, "a");
}

#[tokio::test]
async fn the_swarm_key_may_stay_as_an_outer_layer_of_the_tcp_transport() {
    let swarm = Swarm::new();
    let dir = tempfile::tempdir().unwrap();
    let psk = key(dir.path(), "swarm.key");
    let (ma, mb) = (
        swarm.member("a", Role::Both, None),
        swarm.member("b", Role::Both, None),
    );
    let (a, b) = (node(&ma, Some(&psk)).await, node(&mb, Some(&psk)).await);
    b.dial(address(&a).await).await.unwrap();
    assert!(connected_within(&b, &a, Duration::from_secs(5)).await);
}

#[tokio::test]
async fn a_node_with_the_certificate_of_another_authority_is_not_connected() {
    let ours = Swarm::new();
    let theirs = Swarm::new();
    let (ma, stranger) = (
        ours.member("a", Role::Both, None),
        theirs.member("stranger", Role::Both, None),
    );
    let (a, s) = (node(&ma, None).await, node(&stranger, None).await);
    let mut refusals = ma.authority.refusals();
    s.dial(address(&a).await).await.unwrap();
    tokio::time::timeout(Duration::from_secs(5), refusals.wait_for(|n| *n >= 1))
        .await
        .expect("a stranger was not refused")
        .unwrap();
    assert!(!connected_within(&s, &a, Duration::from_millis(200)).await);
    assert!(!connected_within(&a, &s, Duration::from_millis(200)).await);
    assert!(ma.authority.who(&s.peer_id()).is_none());
}

#[tokio::test]
async fn a_node_with_a_key_and_no_certificate_does_not_join_an_authority() {
    let swarm = Swarm::new();
    let dir = tempfile::tempdir().unwrap();
    let psk = key(dir.path(), "swarm.key");
    let ma = swarm.member("a", Role::Both, None);
    let a = node(&ma, Some(&psk)).await;
    let keyed = Arc::new(
        P2PNode::with_config(P2PConfig {
            listen_addrs: vec!["/ip4/127.0.0.1/tcp/0".into()],
            enable_mdns: false,
            private_key_path: Some(psk),
            dial: velarx_p2p::dial_filter::Rules::on_one_host(),
            ..Default::default()
        })
        .await
        .unwrap(),
    );
    let mut refusals = ma.authority.refusals();
    keyed.dial(address(&a).await).await.unwrap();
    // the other end sent no certificate: it is told so (or the exchange
    // times out), and nothing is connected
    tokio::time::timeout(Duration::from_secs(15), refusals.wait_for(|n| *n >= 1))
        .await
        .expect("a node with no certificate was not refused")
        .unwrap();
    assert!(!connected_within(&a, &keyed, Duration::from_millis(200)).await);
}

#[tokio::test]
async fn a_revoked_node_is_disconnected_and_cannot_connect_again() {
    let swarm = Swarm::new();
    let revoked = swarm.dir.path().join("revoked");
    ca::revoke(&swarm.ca(), &[]).unwrap();
    std::fs::copy(swarm.ca().join("revoked"), &revoked).unwrap();
    let (ma, mb) = (
        swarm.member("a", Role::Both, Some(&revoked)),
        swarm.member("b", Role::Both, None),
    );
    let (a, b) = (node(&ma, None).await, node(&mb, None).await);
    let addr = address(&a).await;
    b.dial(addr.clone()).await.unwrap();
    assert!(connected_within(&a, &b, Duration::from_secs(5)).await);
    // the operator revokes b and puts the list where a reads it
    ca::revoke(&swarm.ca(), &[b.peer_id()]).unwrap();
    std::fs::copy(swarm.ca().join("revoked"), &revoked).unwrap();
    let peer = b.peer_id();
    let mut status = a.status_updates();
    tokio::time::timeout(
        Duration::from_secs(10),
        status.wait_for(|s| !s.connected.contains(&peer)),
    )
    .await
    .expect("the revoked node is still connected")
    .unwrap();
    let mut refusals = ma.authority.refusals();
    let before = *refusals.borrow();
    b.dial(addr).await.unwrap();
    tokio::time::timeout(Duration::from_secs(5), refusals.wait_for(|n| *n > before))
        .await
        .expect("the revoked node was not refused")
        .unwrap();
    assert!(!connected_within(&a, &b, Duration::from_millis(200)).await);
}

#[tokio::test]
async fn the_revocation_list_spreads_along_connections() {
    let swarm = Swarm::new();
    let revoked = swarm.dir.path().join("revoked");
    ca::revoke(
        &swarm.ca(),
        &[Keypair::generate_ed25519().public().to_peer_id()],
    )
    .unwrap();
    std::fs::copy(swarm.ca().join("revoked"), &revoked).unwrap();
    // a knows the list; b is told of it when it connects to a
    let ma = swarm.member("a", Role::Both, Some(&revoked));
    let mb = swarm.member("b", Role::Both, None);
    let (a, b) = (node(&ma, None).await, node(&mb, None).await);
    b.dial(address(&a).await).await.unwrap();
    assert!(connected_within(&b, &a, Duration::from_secs(5)).await);
    assert_eq!(mb.authority.revoked_count(), 1);
}

/// A list of 40 000 peers (more than 2 MiB) goes whole in the handshake and
/// in the gossip: the revoked node is cut off by a node that never read the
/// file, and a node that connects later is told all of it.
#[tokio::test]
async fn a_revocation_list_of_tens_of_thousands_of_peers_is_handed_over() {
    let swarm = Swarm::new();
    let revoked = swarm.dir.path().join("revoked");
    let mut peers: Vec<_> = (0..40_000)
        .map(|_| Keypair::generate_ed25519().public().to_peer_id())
        .collect();
    ca::revoke(&swarm.ca(), &peers).unwrap();
    std::fs::copy(swarm.ca().join("revoked"), &revoked).unwrap();
    // only a reads the file
    let ma = swarm.member("a", Role::Both, Some(&revoked));
    let (mb, mc, md) = (
        swarm.member("b", Role::Both, None),
        swarm.member("c", Role::Both, None),
        swarm.member("d", Role::Both, None),
    );
    let (a, b, c) = (
        node(&ma, None).await,
        node(&mb, None).await,
        node(&mc, None).await,
    );
    b.dial(address(&a).await).await.unwrap();
    c.dial(address(&a).await).await.unwrap();
    c.dial(address(&b).await).await.unwrap();
    assert!(connected_within(&b, &a, Duration::from_secs(5)).await);
    assert!(connected_within(&b, &c, Duration::from_secs(5)).await);
    assert_eq!(mb.authority.revoked_count(), 40_000);
    // c is revoked: b learns it from a in the gossip and cuts c off
    peers.push(c.peer_id());
    let list = ca::revoke(&swarm.ca(), &peers).unwrap();
    assert!(list.text().len() > 2 << 20);
    std::fs::copy(swarm.ca().join("revoked"), &revoked).unwrap();
    let peer = c.peer_id();
    let mut status = b.status_updates();
    tokio::time::timeout(
        Duration::from_secs(20),
        status.wait_for(|s| !s.connected.contains(&peer)),
    )
    .await
    .expect("b is still connected to the revoked node")
    .unwrap();
    assert_eq!(mb.authority.revoked_count(), 40_001);
    // d connects to b later: told the whole list, it refuses c
    let d = node(&md, None).await;
    d.dial(address(&b).await).await.unwrap();
    assert!(connected_within(&d, &b, Duration::from_secs(5)).await);
    assert_eq!(md.authority.revoked_count(), 40_001);
    let mut refusals = md.authority.refusals();
    let before = *refusals.borrow();
    c.dial(address(&d).await).await.unwrap();
    tokio::time::timeout(Duration::from_secs(5), refusals.wait_for(|n| *n > before))
        .await
        .expect("the revoked node was not refused")
        .unwrap();
    assert!(!connected_within(&d, &c, Duration::from_millis(200)).await);
}

#[tokio::test]
async fn a_newer_list_reaches_the_nodes_that_were_connected_before_it() {
    let swarm = Swarm::new();
    let revoked = swarm.dir.path().join("revoked");
    ca::revoke(&swarm.ca(), &[]).unwrap();
    std::fs::copy(swarm.ca().join("revoked"), &revoked).unwrap();
    // only a reads the file; b and c have it from their peers
    let ma = swarm.member("a", Role::Both, Some(&revoked));
    let (mb, mc) = (
        swarm.member("b", Role::Both, None),
        swarm.member("c", Role::Both, None),
    );
    let (a, b, c) = (
        node(&ma, None).await,
        node(&mb, None).await,
        node(&mc, None).await,
    );
    b.dial(address(&a).await).await.unwrap();
    c.dial(address(&a).await).await.unwrap();
    c.dial(address(&b).await).await.unwrap();
    assert!(connected_within(&b, &a, Duration::from_secs(5)).await);
    assert!(connected_within(&b, &c, Duration::from_secs(5)).await);
    // the operator revokes c: b learns it from a, over the connection it has
    ca::revoke(&swarm.ca(), &[c.peer_id()]).unwrap();
    std::fs::copy(swarm.ca().join("revoked"), &revoked).unwrap();
    let peer = c.peer_id();
    let mut status = b.status_updates();
    tokio::time::timeout(
        Duration::from_secs(10),
        status.wait_for(|s| !s.connected.contains(&peer)),
    )
    .await
    .expect("b is still connected to the revoked node")
    .unwrap();
    assert_eq!(mb.authority.revoked_count(), 1);
}

/// The overlay nodes (`velarx-p2p overlay`) are admitted as the content's
/// are: by a certificate of the authority, with the swarm key as an outer
/// layer or not; a node with the swarm key and no certificate does not join,
/// and a revoked one is cut off and cannot connect again.
#[tokio::test]
async fn the_overlay_swarm_admits_by_certificate_only() {
    let swarm = Swarm::new();
    let dir = tempfile::tempdir().unwrap();
    let psk = key(dir.path(), "swarm.key");
    let revoked = swarm.dir.path().join("revoked");
    ca::revoke(&swarm.ca(), &[]).unwrap();
    std::fs::copy(swarm.ca().join("revoked"), &revoked).unwrap();
    let overlay = velarx_p2p::Role::Overlay;
    let (ma, mb) = (
        swarm.member("a", Role::Both, Some(&revoked)),
        swarm.member("b", Role::Both, None),
    );
    let a = node_of(overlay, &ma, Some(&psk)).await;
    let b = node_of(overlay, &mb, Some(&psk)).await;
    let addr = address(&a).await;
    b.dial(addr.clone()).await.unwrap();
    assert!(connected_within(&a, &b, Duration::from_secs(5)).await);
    let keyed = Arc::new(
        P2PNode::with_config(P2PConfig {
            role: overlay,
            listen_addrs: vec!["/ip4/127.0.0.1/tcp/0".into()],
            enable_mdns: false,
            private_key_path: Some(psk),
            dial: velarx_p2p::dial_filter::Rules::on_one_host(),
            ..Default::default()
        })
        .await
        .unwrap(),
    );
    let mut refusals = ma.authority.refusals();
    keyed.dial(addr.clone()).await.unwrap();
    tokio::time::timeout(Duration::from_secs(15), refusals.wait_for(|n| *n >= 1))
        .await
        .expect("an overlay node with no certificate was not refused")
        .unwrap();
    assert!(!connected_within(&a, &keyed, Duration::from_millis(200)).await);
    // b is revoked: cut off, and refused when it comes back
    ca::revoke(&swarm.ca(), &[b.peer_id()]).unwrap();
    std::fs::copy(swarm.ca().join("revoked"), &revoked).unwrap();
    let peer = b.peer_id();
    let mut status = a.status_updates();
    tokio::time::timeout(
        Duration::from_secs(10),
        status.wait_for(|s| !s.connected.contains(&peer)),
    )
    .await
    .expect("the revoked overlay node is still connected")
    .unwrap();
    let before = *refusals.borrow();
    b.dial(addr).await.unwrap();
    tokio::time::timeout(Duration::from_secs(5), refusals.wait_for(|n| *n > before))
        .await
        .expect("the revoked overlay node was not refused")
        .unwrap();
    assert!(!connected_within(&a, &b, Duration::from_millis(200)).await);
}
