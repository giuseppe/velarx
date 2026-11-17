// SPDX-License-Identifier: Apache-2.0
//! What a node does when the swarm is large: nodes that cannot reach their
//! bootstrap peer reach it later, and join through the peers it knows.  Real
//! nodes on the loopback.

use super::support::{address, connected_within, digest_of, key};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use velarx_p2p::{P2PConfig, P2PNode};

const WAIT: Duration = Duration::from_secs(20);

async fn node_with(key: &Path, listen: &str, tune: impl FnOnce(&mut P2PConfig)) -> Arc<P2PNode> {
    let mut config = P2PConfig {
        dial: velarx_p2p::dial_filter::Rules::on_one_host(),
        listen_addrs: vec![listen.into()],
        enable_mdns: false,
        private_key_path: Some(key.to_path_buf()),
        // (retries in milliseconds: the test waits for the connection, not
        // for the time)
        bootstrap_backoff: (Duration::from_millis(20), Duration::from_millis(200)),
        ..Default::default()
    };
    tune(&mut config);
    Arc::new(P2PNode::with_config(config).await.unwrap())
}

/// A TCP port on the loopback nobody listens on (yet).
fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// A node whose bootstrap peer is not there when it starts is connected to
/// it when it is, and again when the bootstrap peer was replaced: the node
/// dialed it once and stayed alone for ever.
#[tokio::test]
async fn test_a_node_reaches_its_bootstrap_peer_when_it_comes_up_and_again_after_it_goes() {
    let dir = tempfile::tempdir().unwrap();
    let swarm = key(dir.path(), "swarm.key");
    let port = free_port();
    let listen = format!("/ip4/127.0.0.1/tcp/{port}");
    let lonely = node_with(&swarm, "/ip4/127.0.0.1/tcp/0", |c| {
        c.bootstrap_peers = vec![listen.clone()];
        c.min_peers = 1;
    })
    .await;

    // (the first dial failed: nothing listens)
    let first = node_with(&swarm, &listen, |c| c.quic_port = Some(0)).await;
    assert!(
        connected_within(&lonely, &first, WAIT).await,
        "the node never dialed its bootstrap peer again"
    );

    // the bootstrap peer goes and another takes its place
    first.shutdown().await.unwrap();
    let second = node_with(&swarm, &listen, |c| c.quic_port = Some(0)).await;
    assert!(
        connected_within(&lonely, &second, WAIT).await,
        "the node stayed without peers when its bootstrap peer was replaced"
    );
}

/// Nodes that all name one bootstrap peer, more than it takes: the ones it
/// refuses get from it the peers it knows and join the swarm through them
/// (they stayed alone for ever, dialing a peer that was full).
#[tokio::test]
async fn test_nodes_a_full_bootstrap_peer_refuses_join_through_the_peers_it_knows() {
    let dir = tempfile::tempdir().unwrap();
    let swarm = key(dir.path(), "swarm.key");
    let full = node_with(&swarm, "/ip4/127.0.0.1/tcp/0", |c| {
        c.max_incoming = 2;
    })
    .await;
    let at = address(&full).await.to_string();
    let mut nodes = Vec::new();
    for _ in 0..8 {
        nodes.push(
            node_with(&swarm, "/ip4/127.0.0.1/tcp/0", |c| {
                c.bootstrap_peers = vec![at.clone()];
                c.min_peers = 1;
            })
            .await,
        );
    }
    // (a refused node is connected to the full one for a moment: what
    // counts is a peer other than it, which the ones it took get too)
    let bootstrap = full.peer_id();
    for (i, node) in nodes.iter().enumerate() {
        let mut status = node.status_updates();
        let joined = tokio::time::timeout(
            WAIT,
            status.wait_for(|s| s.connected.iter().any(|p| *p != bootstrap)),
        )
        .await
        .is_ok_and(|r| r.is_ok());
        assert!(joined, "node {i} of 8 has no peer but the bootstrap peer");
    }
}

/// A swarm of `VELARX_P2P_SCALE_NODES` nodes (12 by default; a run
/// with 400 is the large run), each naming three
/// earlier nodes: nobody stays alone, and the DHT names the node that
/// announces a layer to every other node (all of them are asked once a
/// second, up to a limit), at the default places for connections (a walk of
/// the DHT dials peers it is not connected to, more than the places).
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn scale_a_layer_one_node_announces_is_found_by_the_swarm() {
    let n: usize = std::env::var("VELARX_P2P_SCALE_NODES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(12);
    let dir = tempfile::tempdir().unwrap();
    let swarm = key(dir.path(), "swarm.key");
    let mut nodes: Vec<Arc<P2PNode>> = Vec::new();
    let mut addrs: Vec<String> = Vec::new();
    for i in 0..n {
        let boot: Vec<String> = (0..i.min(3))
            .map(|k| {
                addrs[(i.wrapping_mul(2_654_435_761) ^ k.wrapping_mul(40_503) << 7) % i].clone()
            })
            .collect();
        let node = node_with(&swarm, "/ip4/127.0.0.1/tcp/0", |c| {
            c.bootstrap_peers = boot.clone();
            c.announce_images = true;
            c.min_peers = 3;
        })
        .await;
        let addr = address(&node).await;
        addrs.push(format!("{addr}/p2p/{}", node.peer_id()));
        nodes.push(node);
    }
    // nobody is alone
    let patience = Duration::from_secs(30 + n as u64 / 4);
    let deadline = tokio::time::Instant::now() + patience;
    loop {
        let alone = nodes
            .iter()
            .filter(|node| node.status_updates().borrow().connected.is_empty())
            .count();
        if alone == 0 {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "{alone} of {n} nodes have no peer"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    let layer = digest_of(b"a layer");
    nodes[0].announce_layers(vec![layer.clone()]).await.unwrap();
    let seed = nodes[0].peer_id();
    let mut found = 0;
    let deadline = tokio::time::Instant::now() + patience;
    let mut waiting: Vec<usize> = (1..n).collect();
    while !waiting.is_empty() && tokio::time::Instant::now() < deadline {
        let asked: Vec<_> = waiting
            .iter()
            .map(|&i| {
                let (node, layer) = (nodes[i].clone(), layer.clone());
                async move { (i, node.find_providers(&layer).await.contains(&seed)) }
            })
            .collect();
        let answers = futures::future::join_all(asked).await;
        found += answers.iter().filter(|(_, f)| *f).count();
        waiting.retain(|i| !answers.iter().any(|(j, f)| j == i && *f));
        if !waiting.is_empty() {
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }
    assert!(found == n - 1, "{found} of {} nodes found the layer", n - 1);
}
