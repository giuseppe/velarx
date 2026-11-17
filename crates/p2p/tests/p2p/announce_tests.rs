// SPDX-License-Identifier: Apache-2.0
//! What a node tells its peers about what it has: the filter of its layers
//! (unless it keeps them to itself), and its images only with
//! `announce_images`.  Real nodes on the loopback.

use super::support::{
    address, connected_within, digest_of, heard_within, key, quic_known_within, Chunks,
};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use velarx_core::store_service::{Change, ChangeKind};
use velarx_p2p::store::apply_change;
use velarx_p2p::{ImageInfo, P2PConfig, P2PNode, Presence};

async fn node(key: &Path, announce_images: bool) -> Arc<P2PNode> {
    node_with(key, announce_images, true).await
}

async fn node_with(key: &Path, announce_images: bool, advertise: bool) -> Arc<P2PNode> {
    Arc::new(
        P2PNode::with_config(P2PConfig {
            dial: velarx_p2p::dial_filter::Rules::on_one_host(),
            listen_addrs: vec!["/ip4/127.0.0.1/tcp/0".into()],
            enable_mdns: false,
            private_key_path: Some(key.to_path_buf()),
            announce_images,
            filter: velarx_p2p::filter::Config {
                advertise,
                // (a short time: the tests wait for what is told)
                interval: Duration::from_millis(20),
                ..Default::default()
            },
            ..Default::default()
        })
        .await
        .unwrap(),
    )
}

/// How long a connection is waited for at most.
const WITHIN: Duration = Duration::from_secs(10);

/// `a` serving `chunk` (and holding the layers and the image it announces,
/// when it does), `b` connected to it.
async fn pair(swarm: &Path, announce: bool) -> (Arc<P2PNode>, Arc<P2PNode>, String) {
    let (a, b) = (node(swarm, announce).await, node(swarm, false).await);
    let data = b"a chunk".to_vec();
    let d = digest_of(&data);
    a.set_chunk_provider(Arc::new(Chunks([(d.clone(), data)].into())))
        .unwrap();
    b.dial(address(&a).await).await.unwrap();
    assert!(connected_within(&b, &a, WITHIN).await);
    assert!(connected_within(&a, &b, WITHIN).await);
    // (the data is asked at the QUIC endpoint, which identify tells)
    assert!(quic_known_within(&b, &a, WITHIN).await);
    (a, b, d)
}

fn image(layer: &str) -> ImageInfo {
    ImageInfo {
        id: digest_of(b"image")["sha256:".len()..].to_string(),
        manifest_digest: digest_of(b"manifest"),
        config_digest: digest_of(b"config"),
        tags: Vec::new(),
        repo_digests: Vec::new(),
        layers: vec![layer.to_string()],
        size: 1,
        created_at: "2026-01-01T00:00:00Z".to_string(),
        complete: true,
    }
}

/// By default the node tells the filter of its layers and no list of its
/// images, and refuses the question for the list; it answers for a digest
/// the peer knows, as before.
#[tokio::test]
async fn test_a_node_tells_its_filter_and_no_list_by_default() {
    let dir = tempfile::tempdir().unwrap();
    let (a, b, chunk) = pair(&key(dir.path(), "swarm.key"), false).await;
    let layer = digest_of(b"layer");
    assert_eq!(a.announce_layers(vec![layer.clone()]).await.unwrap(), 1);
    a.announce_images(vec![image(&layer)]).await;
    b.query_peer_images().await.unwrap();
    // a peer can test a layer it knows in the filter
    assert!(
        heard_within(&b, WITHIN, || async {
            b.knowledge().filtered(&layer).maybe == [a.peer_id()].into()
        })
        .await,
        "the filter was not told"
    );
    assert!(b
        .knowledge()
        .filtered(&digest_of(b"another"))
        .no
        .contains(&a.peer_id()));
    assert!(b.get_remote_images().await.is_empty());

    // a question for a digest it holds is answered yes, for another no
    assert_eq!(b.probe(a.peer_id(), &chunk).await.unwrap(), Presence::Has);
    assert_eq!(
        b.probe(a.peer_id(), &digest_of(b"unknown")).await.unwrap(),
        Presence::Lacks
    );
    // (the layer is not a chunk of the store: the same no as for any other)
    assert_eq!(b.probe(a.peer_id(), &layer).await.unwrap(), Presence::Lacks);
    // and one that walks (a prefix, a path, nothing) is no question: a
    // probe is one whole digest in the binary form, nothing else is sent
    for walk in [&chunk[..chunk.len() - 1], "sha256:", "", "../../etc/passwd"] {
        let e = b.probe(a.peer_id(), walk).await.unwrap_err();
        assert!(matches!(e, velarx_p2p::P2PError::Quic(_)), "{walk:?}: {e}");
    }
}

/// A node that keeps its layers to itself tells no filter: the peers have
/// none of it, and ask it as before.
#[tokio::test]
async fn test_a_node_that_does_not_advertise_tells_no_filter() {
    let dir = tempfile::tempdir().unwrap();
    let swarm = key(dir.path(), "swarm.key");
    let (a, b) = (
        node_with(&swarm, false, false).await,
        node_with(&swarm, false, true).await,
    );
    let layer = digest_of(b"layer");
    a.announce_layers(vec![layer.clone()]).await.unwrap();
    b.dial(address(&a).await).await.unwrap();
    assert!(connected_within(&b, &a, WITHIN).await);
    assert!(connected_within(&a, &b, WITHIN).await);
    // (B tells A its filter, which A holds: what A would have sent came
    // before the answer to a question that A answers after it handled all)
    b.query_peer_images().await.unwrap();
    assert!(
        heard_within(&a, WITHIN, || async {
            a.knowledge().filtered(&layer).no.contains(&b.peer_id())
        })
        .await
    );
    let filtered = b.knowledge().filtered(&layer);
    assert!(filtered.maybe.is_empty() && filtered.no.is_empty());
    assert!(!a.advertises());
}

/// With `announce_images` the peers also learn the images, and can ask for
/// the list of them.
#[tokio::test]
async fn test_a_node_that_announces_tells_its_images() {
    let dir = tempfile::tempdir().unwrap();
    let swarm = key(dir.path(), "swarm.key");
    let (a, b, _) = pair(&swarm, true).await;
    let layer = digest_of(b"layer");
    assert_eq!(a.announce_layers(vec![layer.clone()]).await.unwrap(), 1);
    assert!(
        heard_within(&b, WITHIN, || async {
            b.knowledge().filtered(&layer).maybe == [a.peer_id()].into()
        })
        .await,
        "the layer was not told"
    );
    a.announce_images(vec![image(&layer)]).await;
    assert!(
        heard_within(&b, WITHIN, || async {
            b.get_remote_images().await.len() == 1
        })
        .await,
        "the image was not announced"
    );
    // a node that asks for the list gets it
    let c = node(&swarm, false).await;
    address(&c).await;
    c.dial(a.status().listen_addresses[0].clone())
        .await
        .unwrap();
    assert!(connected_within(&c, &a, WITHIN).await);
    // (the question returns once the peer answered: no pause, no loop)
    c.query_peer_images().await.unwrap();
    assert_eq!(
        c.get_remote_images().await.len(),
        1,
        "the images were not given to the question"
    );
}

/// The change of the store service of `kind`, with these layers.
fn change(kind: ChangeKind, layers: &[&String]) -> Change {
    Change {
        kind,
        layers: layers.iter().map(|l| l.to_string()).collect(),
        images: Vec::new(),
        content: Vec::new(),
    }
}

/// A layer the store removed is not told to a peer that connects after the
/// removal (it was told for as long as the process lived): the changes of
/// the store service as the P2P service follows them.
#[tokio::test]
async fn test_a_withdrawn_layer_is_not_told_to_new_peers() {
    let dir = tempfile::tempdir().unwrap();
    let swarm = key(dir.path(), "swarm.key");
    let (a, _b, _) = pair(&swarm, true).await;
    let (kept, gone) = (digest_of(b"kept"), digest_of(b"gone"));
    apply_change(&a, change(ChangeKind::Snapshot, &[&kept, &gone])).await;
    // (a layer that another image still has is not in a removal)
    apply_change(&a, change(ChangeKind::Removed, &[&gone])).await;
    let c = node(&swarm, false).await;
    address(&c).await;
    c.dial(a.status().listen_addresses[0].clone())
        .await
        .unwrap();
    assert!(
        heard_within(&c, WITHIN, || async {
            c.knowledge().filtered(&kept).maybe == [a.peer_id()].into()
        })
        .await
    );
    // (the filter a new peer is told is the one without what went)
    assert!(c.knowledge().filtered(&gone).no.contains(&a.peer_id()));
    // a snapshot of the store without `kept` (one after the service was
    // away, or after the P2P service fell behind) withdraws it too
    apply_change(&a, change(ChangeKind::Snapshot, &[])).await;
    let d = node(&swarm, false).await;
    address(&d).await;
    d.dial(a.status().listen_addresses[0].clone())
        .await
        .unwrap();
    assert!(
        heard_within(&d, WITHIN, || async {
            d.knowledge().filtered(&kept).no.contains(&a.peer_id())
        })
        .await,
        "the filter of a node with no layer was not told"
    );
}
