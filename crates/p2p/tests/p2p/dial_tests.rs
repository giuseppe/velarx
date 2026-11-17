// SPDX-License-Identifier: Apache-2.0
//! Where a real node dials: an address a peer made up is not dialed when it is
//! the node's own, loopback, link-local..., whatever the source; the bootstrap
//! peers the operator named are.

use super::support::{address, connected_now, connected_within, key};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use velarx_p2p::{P2PConfig, P2PNode};

/// A node on the loopback with the default rules: loopback is refused.
async fn strict(key: &Path, bootstrap: Vec<String>) -> Arc<P2PNode> {
    Arc::new(
        P2PNode::with_config(P2PConfig {
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

#[tokio::test]
async fn a_node_does_not_dial_an_address_the_filter_refuses_and_counts_why() {
    let dir = tempfile::tempdir().unwrap();
    let swarm = key(dir.path(), "swarm.key");
    let (a, b) = (strict(&swarm, vec![]).await, strict(&swarm, vec![]).await);
    let addr = address(&a).await;
    b.dial(addr).await.unwrap();
    // (the swarm of `b` handles its commands in the order they came: when
    // this one is answered, the dial has been made, or refused)
    let _ = b.ask_for_peers(a.peer_id()).await;
    assert!(!connected_now(&b, &a));
    assert!(!connected_now(&a, &b));
    let refused = b.lookups().await.dials_refused;
    assert_eq!(refused.loopback, 1, "{refused:?}");
    assert_eq!(a.lookups().await.dials_refused.loopback, 0);
}

#[tokio::test]
async fn the_bootstrap_peers_the_operator_named_are_dialed_whatever_the_filter_says() {
    let dir = tempfile::tempdir().unwrap();
    let swarm = key(dir.path(), "swarm.key");
    let a = strict(&swarm, vec![]).await;
    let b = strict(&swarm, vec![address(&a).await.to_string()]).await;
    assert!(
        connected_within(&b, &a, Duration::from_secs(5)).await,
        "a bootstrap peer on the loopback was refused"
    );
    assert_eq!(b.lookups().await.dials_refused.loopback, 0);
}
