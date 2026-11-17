// SPDX-License-Identifier: Apache-2.0
//! Real nodes on the loopback: only nodes with the same swarm key talk, and
//! what a peer asks for is bounded.

use super::support::{address, connected_within, digest_of, fetch, key, Chunks};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use velarx_p2p::{ChunkProvider, P2PConfig, P2PError, P2PNode};

async fn node(key: &Path) -> Arc<P2PNode> {
    Arc::new(
        P2PNode::with_config(P2PConfig {
            dial: velarx_p2p::dial_filter::Rules::on_one_host(),
            listen_addrs: vec!["/ip4/127.0.0.1/tcp/0".into()],
            enable_mdns: false,
            private_key_path: Some(key.to_path_buf()),
            ..Default::default()
        })
        .await
        .unwrap(),
    )
}

/// Whether `a` is connected to `b` within 2 s.
async fn connected(a: &P2PNode, b: &P2PNode) -> bool {
    connected_within(a, b, Duration::from_secs(2)).await
}

#[tokio::test]
async fn test_nodes_with_the_same_key_exchange_chunks_and_others_do_not_connect() {
    let dir = tempfile::tempdir().unwrap();
    let swarm = key(dir.path(), "a.key");
    let other = key(dir.path(), "b.key");
    let (a, b, stranger) = (node(&swarm).await, node(&swarm).await, node(&other).await);

    let data = b"some chunk".to_vec();
    let d = digest_of(&data);
    a.set_chunk_provider(Arc::new(Chunks([(d.clone(), data.clone())].into())))
        .unwrap();
    let addr = address(&a).await;

    b.dial(addr.clone()).await.unwrap();
    assert!(connected(&b, &a).await, "same key, no connection");
    let found = fetch(&b, &a, std::slice::from_ref(&d)).await.unwrap();
    assert_eq!(found, [(d.clone(), data.clone())]);

    // A node with another key never gets past the handshake.
    let _ = stranger.dial(addr).await;
    assert!(
        !connected(&stranger, &a).await,
        "a node with another key connected"
    );
    assert!(!connected(&a, &stranger).await);
    // (a node that never was a member has no endpoint to ask)
    let e = a
        .fetch(stranger.peer_id(), &[(d.clone(), None)])
        .await
        .unwrap_err();
    assert!(matches!(e, P2PError::NoQuicPath { .. }), "{e}");
}

/// What is not a digest is not a request: it does not reach the wire, and the
/// provider of the peer is never asked for it.
#[tokio::test]
async fn test_what_is_not_a_digest_is_not_looked_up() {
    let dir = tempfile::tempdir().unwrap();
    let swarm = key(dir.path(), "a.key");
    let (a, b) = (node(&swarm).await, node(&swarm).await);
    struct Never;
    impl ChunkProvider for Never {
        fn get_chunk(&self, digest: &str) -> std::io::Result<Option<Vec<u8>>> {
            panic!("asked for {digest:?}")
        }
    }
    a.set_chunk_provider(Arc::new(Never)).unwrap();
    // (one provider for the life of the node: a second is refused)
    assert!(a.set_chunk_provider(Arc::new(Never)).is_err());
    b.dial(address(&a).await).await.unwrap();
    assert!(connected(&b, &a).await);
    for bad in ["../../etc/passwd", "sha256:../x", "é", &"é".repeat(40)] {
        assert!(fetch(&b, &a, &[bad.to_string()]).await.is_err(), "{bad}");
        assert!(b.probe(a.peer_id(), bad).await.is_err(), "{bad}");
    }
}

#[tokio::test]
async fn test_what_a_peer_sends_is_not_recorded_as_what_it_announced() {
    let dir = tempfile::tempdir().unwrap();
    let swarm = key(dir.path(), "a.key");
    let (a, b) = (node(&swarm).await, node(&swarm).await);
    let good = b"the real chunk".to_vec();
    let d_good = digest_of(&good);
    let d_lie = digest_of(b"what was asked for");
    let d_batch_lie = digest_of(b"another chunk");
    a.set_chunk_provider(Arc::new(Chunks(
        [
            (d_good.clone(), good),
            (d_lie.clone(), b"something else".to_vec()),
            (d_batch_lie.clone(), b"not it either".to_vec()),
        ]
        .into(),
    )))
    .unwrap();
    b.dial(address(&a).await).await.unwrap();
    assert!(connected(&b, &a).await);

    // (a request records nothing: the table holds the layers a peer
    // announced, and a chunk it sent is not one)
    // (a chunk whose bytes are not what it is named by is not even sent: the
    // store of the peer is told damaged)
    for d in [&d_lie, &d_batch_lie] {
        assert!(matches!(
            fetch(&b, &a, std::slice::from_ref(d)).await,
            Err(P2PError::StoreFailed)
        ));
        assert!(b.knowledge().filtered(d).maybe.is_empty());
    }
    fetch(&b, &a, std::slice::from_ref(&d_good)).await.unwrap();
    assert!(b.knowledge().filtered(&d_good).maybe.is_empty());
}

/// A provider whose store cannot be read.
struct Broken;

impl ChunkProvider for Broken {
    fn get_chunk(&self, _: &str) -> std::io::Result<Option<Vec<u8>>> {
        Err(std::io::Error::other("the store service is gone"))
    }
    fn get_index(&self, _: &str) -> std::io::Result<Option<Vec<u8>>> {
        Err(std::io::Error::other("the store service is gone"))
    }
    fn get_profile(&self, _: &str) -> std::io::Result<Option<Vec<u8>>> {
        Err(std::io::Error::other("the store service is gone"))
    }
    fn open_chunks(&self, _: &[String]) -> std::io::Result<Vec<Option<velarx_storage::ChunkFile>>> {
        Err(std::io::Error::other("the store service is gone"))
    }
}

/// A peer whose store cannot be read is an error to the asker: not a peer
/// without the chunk (which the asker would remember as a miss), and not a
/// failure of QUIC (the peer is still reached over it).
#[tokio::test]
async fn test_a_store_that_cannot_be_read_is_an_error_to_the_asker() {
    use velarx_p2p::provider::{NodePeers, Peers};
    let dir = tempfile::tempdir().unwrap();
    let swarm = key(dir.path(), "a.key");
    let d = digest_of(b"a chunk");
    let image = format!("sha256:{}", "a".repeat(64));
    let (a, b) = (node(&swarm).await, node(&swarm).await);
    a.set_chunk_provider(Arc::new(Broken)).unwrap();
    b.dial(address(&a).await).await.unwrap();
    assert!(connected(&b, &a).await);
    let e = fetch(&b, &a, std::slice::from_ref(&d)).await.unwrap_err();
    assert!(matches!(e, P2PError::StoreFailed), "{e}");
    let peers = NodePeers(b.clone());
    let peer = a.peer_id();
    assert!(
        peers.request(peer, &[(d.clone(), None)]).await.is_err(),
        "chunks"
    );
    assert!(peers.has(peer, &d).await.is_err(), "probe");
    assert!(peers.index(peer, &d, 1 << 20).await.is_err(), "index");
    assert!(
        peers.profile(peer, &image, 1 << 20).await.is_err(),
        "profile"
    );
    // QUIC itself worked: the peer is not taken for one without a path
    assert_eq!(b.no_quic_path(peer).await, None);
    assert!(matches!(
        b.fetch(peer, &[(d, None)]).await,
        Err(P2PError::StoreFailed)
    ));
}

/// A node says what it is serving: the QUIC slots, and what it admitted.
#[tokio::test]
async fn test_a_node_tells_what_it_is_serving() {
    let dir = tempfile::tempdir().unwrap();
    let node = P2PNode::with_config(P2PConfig {
        dial: velarx_p2p::dial_filter::Rules::on_one_host(),
        listen_addrs: vec!["/ip4/127.0.0.1/tcp/0".into()],
        enable_mdns: false,
        private_key_path: Some(key(dir.path(), "swarm.key")),
        ..Default::default()
    })
    .await
    .unwrap();
    let state = node.serving_state();
    let serving = velarx_p2p::Serving::default();
    assert_eq!(state.quic_slots, (0, serving.quic_slots));
    assert_eq!(state.admission.upload.bytes_per_sec, 0);
    // (a peer nobody knows has no QUIC endpoint known)
    assert!(node
        .no_quic_path(libp2p::PeerId::random())
        .await
        .is_some_and(|why| why.contains("advertises no QUIC")));
}
