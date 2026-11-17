// SPDX-License-Identifier: Apache-2.0
//! Real nodes that tell each other which peers they know.

use super::support::{address, connected_now, connected_within, key, quic_known_within};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use velarx_p2p::dial_filter::Rules;
use velarx_p2p::{P2PConfig, P2PNode};

/// A node on the loopback that makes no attempt of its own to find peers
/// (`min_peers = 0`: it only dials its bootstrap peers once), so that what
/// it learns is what it asked for.
async fn node(key: &Path, bootstrap: Vec<String>, rules: Rules) -> Arc<P2PNode> {
    Arc::new(
        P2PNode::with_config(P2PConfig {
            dial: rules,
            listen_addrs: vec!["/ip4/127.0.0.1/tcp/0".into()],
            bootstrap_peers: bootstrap,
            min_peers: 0,
            enable_mdns: false,
            private_key_path: Some(key.to_path_buf()),
            ..Default::default()
        })
        .await
        .unwrap(),
    )
}

/// `a` and `b` are connected and `a` has identified `b`.
async fn joined(a: &Arc<P2PNode>, b: &Arc<P2PNode>) {
    assert!(connected_within(a, b, Duration::from_secs(5)).await);
    assert!(quic_known_within(a, b, Duration::from_secs(5)).await);
}

#[tokio::test]
async fn a_node_learns_a_peer_from_the_peer_it_has_and_connects_to_it() {
    let dir = tempfile::tempdir().unwrap();
    let swarm = key(dir.path(), "swarm.key");
    let hub = node(&swarm, vec![], Rules::on_one_host()).await;
    let hub_addr = address(&hub).await.to_string();
    let b = node(&swarm, vec![hub_addr.clone()], Rules::on_one_host()).await;
    joined(&hub, &b).await;
    // (a newcomer that has the hub and nobody else)
    let c = node(&swarm, vec![hub_addr], Rules::on_one_host()).await;
    joined(&hub, &c).await;
    assert!(!connected_now(&c, &b));
    assert_eq!(c.ask_for_peers(hub.peer_id()).await.unwrap(), 1);
    assert!(
        connected_within(&c, &b, Duration::from_secs(5)).await,
        "the peer the hub named was not connected to"
    );
    assert_eq!(c.lookups().await.exchange_dials, 1);
    assert_eq!(hub.lookups().await.exchange_answered, 1);
}

#[tokio::test]
async fn what_a_peer_names_is_dialed_only_where_the_filter_allows() {
    let dir = tempfile::tempdir().unwrap();
    let swarm = key(dir.path(), "swarm.key");
    let hub = node(&swarm, vec![], Rules::on_one_host()).await;
    let hub_addr = address(&hub).await.to_string();
    let b = node(&swarm, vec![hub_addr.clone()], Rules::on_one_host()).await;
    joined(&hub, &b).await;
    // the newcomer names the hub as a bootstrap peer (exempt) but allows no
    // loopback: the peer the hub names is on the loopback
    let c = node(&swarm, vec![hub_addr], Rules::default()).await;
    joined(&hub, &c).await;
    assert_eq!(c.ask_for_peers(hub.peer_id()).await.unwrap(), 0);
    assert!(!connected_now(&c, &b));
    let refused = c.lookups().await.dials_refused;
    assert_eq!(refused.loopback, 1, "{refused:?}");
    assert_eq!(c.lookups().await.exchange_dials, 0);
}

/// A peer whose first connection was lent is a member through the one the
/// node makes to it while that is open.
#[tokio::test]
async fn a_second_connection_makes_a_member_of_a_peer_that_was_lent_a_place() {
    let dir = tempfile::tempdir().unwrap();
    let swarm = key(dir.path(), "swarm.key");
    let full = Arc::new(
        P2PNode::with_config(P2PConfig {
            dial: Rules::on_one_host(),
            listen_addrs: vec!["/ip4/127.0.0.1/tcp/0".into()],
            max_incoming: 1,
            min_peers: 0,
            enable_mdns: false,
            private_key_path: Some(swarm.clone()),
            ..Default::default()
        })
        .await
        .unwrap(),
    );
    let at = address(&full).await.to_string();
    let member = node(&swarm, vec![at.clone()], Rules::on_one_host()).await;
    assert!(connected_within(&full, &member, Duration::from_secs(5)).await);
    let guest = node(&swarm, vec![at], Rules::on_one_host()).await;
    assert!(connected_within(&guest, &full, Duration::from_secs(5)).await);
    assert!(!full.status().connected.contains(&guest.peer_id()));
    // the node dials it back while the lent place is still open
    full.dial(address(&guest).await).await.unwrap();
    assert!(connected_within(&full, &guest, Duration::from_secs(5)).await);
    // the lent one is taken back within seconds: the peer stays
    tokio::time::sleep(Duration::from_secs(5)).await;
    assert!(full.status().connected.contains(&guest.peer_id()));
}
