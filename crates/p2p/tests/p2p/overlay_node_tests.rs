// SPDX-License-Identifier: Apache-2.0
//! The overlay node as a member of a swarm of its own: two overlay nodes
//! find each other, tell each other their subnet (also one that connects
//! after the subnet was announced) and carry packets; a content node is
//! not part of it, and keeps nothing of what the overlay says.

use super::support::{address, connected_within, key};
use std::sync::Arc;
use std::time::Duration;
use velarx_p2p::{OverlayEvent, P2PConfig, P2PNode, Role};

async fn node(role: Role, key: &std::path::Path, bootstrap: Vec<String>) -> Arc<P2PNode> {
    Arc::new(
        P2PNode::with_config(P2PConfig {
            role,
            dial: velarx_p2p::dial_filter::Rules::on_one_host(),
            listen_addrs: vec!["/ip4/127.0.0.1/tcp/0".into()],
            bootstrap_peers: bootstrap,
            enable_mdns: false,
            private_key_path: Some(key.to_path_buf()),
            ..Default::default()
        })
        .await
        .unwrap(),
    )
}

async fn full_address(node: &P2PNode) -> String {
    format!("{}/p2p/{}", address(node).await, node.peer_id())
}

#[tokio::test]
async fn a_node_that_connects_later_is_told_the_subnet_and_the_packets_pass() {
    let dir = tempfile::tempdir().unwrap();
    let key = key(dir.path(), "swarm.key");
    let a = node(Role::Overlay, &key, Vec::new()).await;
    let subnet: ipnet::Ipv4Net = "10.200.2.0/24".parse().unwrap();
    // (told before anybody is connected)
    a.announce_tun_overlay(subnet).await.unwrap();
    let b = node(Role::Overlay, &key, vec![full_address(&a).await]).await;
    let mut events = b.overlay().overlay_events().unwrap();
    assert!(connected_within(&b, &a, Duration::from_secs(10)).await);
    let event = tokio::time::timeout(Duration::from_secs(10), events.recv())
        .await
        .expect("the subnet is told to the node that connected")
        .unwrap();
    match event {
        OverlayEvent::Peer(peer, info) => {
            assert_eq!((peer, info.node_subnet), (a.peer_id(), subnet));
        }
        e => panic!("{e:?}"),
    }
    // a packet of one reaches the handler of the other
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    b.set_tun_packet_handler(move |peer, packet| {
        let _ = tx.send((peer, packet.data));
    })
    .await
    .unwrap();
    a.send_tun_packet(
        b.peer_id(),
        velarx_p2p::tun_tunnel::TunPacket::new(vec![7; 100]),
    )
    .await
    .unwrap();
    let (from, data) = tokio::time::timeout(Duration::from_secs(10), rx.recv())
        .await
        .expect("the packet comes")
        .unwrap();
    assert_eq!((from, data), (a.peer_id(), vec![7; 100]));
}

/// A content node has no tunnel, and the overlay node no QUIC endpoint for
/// chunks: neither is asked for what it does not do.
#[tokio::test]
async fn a_content_node_and_an_overlay_node_do_not_do_each_others_work() {
    let dir = tempfile::tempdir().unwrap();
    let key = key(dir.path(), "swarm.key");
    let overlay = node(Role::Overlay, &key, Vec::new()).await;
    let content = node(Role::Content, &key, vec![full_address(&overlay).await]).await;
    assert!(connected_within(&content, &overlay, Duration::from_secs(10)).await);
    // (a packet to a node with no tunnel is a request nobody takes)
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    overlay
        .set_tun_packet_handler(move |peer, _| {
            let _ = tx.send(peer);
        })
        .await
        .unwrap();
    content
        .send_tun_packet(
            overlay.peer_id(),
            velarx_p2p::tun_tunnel::TunPacket::new(vec![1]),
        )
        .await
        .unwrap();
    assert!(tokio::time::timeout(Duration::from_secs(1), rx.recv())
        .await
        .is_err());
    assert!(content.no_quic_path(overlay.peer_id()).await.is_some());
    assert!(overlay.no_quic_path(content.peer_id()).await.is_some());
}
