// SPDX-License-Identifier: Apache-2.0
//! How a node finds who has what, on real nodes on the loopback: a node
//! with no room says so, and is not taken for one without the chunk; a
//! provider the DHT names is dialed and used.

use super::support::{address, connected_within, digest_of, key, quic_known_within};
use futures::StreamExt;
use std::path::Path;
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;
use velarx_p2p::provider::{NodePeers, Peers};
use velarx_p2p::{ChunkProvider, P2PConfig, P2PNode, Presence};

async fn node(key: &Path, announce_images: bool) -> Arc<P2PNode> {
    Arc::new(
        P2PNode::with_config(P2PConfig {
            dial: velarx_p2p::dial_filter::Rules::on_one_host(),
            listen_addrs: vec!["/ip4/127.0.0.1/tcp/0".into()],
            enable_mdns: false,
            private_key_path: Some(key.to_path_buf()),
            announce_images,
            ..Default::default()
        })
        .await
        .unwrap(),
    )
}

/// A store that has one chunk and gives it when the gate is opened: until
/// then every read waits (a store that is slow).
struct Gated {
    chunk: String,
    open: Mutex<bool>,
    opened: Condvar,
}

impl Gated {
    fn open(&self) {
        *self.open.lock().unwrap() = true;
        self.opened.notify_all();
    }
}

/// Opens the gate when it goes, so that a test that fails does not leave
/// the reads of the store waiting (and the runtime with them).
struct OpenOnDrop(Arc<Gated>);

impl Drop for OpenOnDrop {
    fn drop(&mut self) {
        self.0.open();
    }
}

impl ChunkProvider for Gated {
    fn get_chunk(&self, digest: &str) -> std::io::Result<Option<Vec<u8>>> {
        let mut open = self.open.lock().unwrap();
        while !*open {
            open = self.opened.wait(open).unwrap();
        }
        Ok((digest == self.chunk).then(|| b"the chunk".to_vec()))
    }
}

/// Probes that arrive when every probe slot of the peer serves one are
/// answered busy: not "it does not have the chunk", which the asker would
/// remember for a minute.  Of 24 probes at once to a peer that has the chunk
/// and a slow store, as many as the peer has probe slots are answered yes and
/// the others busy, none no.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_a_peer_with_no_room_is_busy_and_not_without_the_chunk() {
    let dir = tempfile::tempdir().unwrap();
    let swarm = key(dir.path(), "swarm.key");
    let (a, b) = (node(&swarm, false).await, node(&swarm, false).await);
    let chunk = digest_of(b"the chunk");
    let store = Arc::new(Gated {
        chunk: chunk.clone(),
        open: Mutex::new(false),
        opened: Condvar::new(),
    });
    a.set_chunk_provider(store.clone()).unwrap();
    let _gate = OpenOnDrop(store.clone());
    b.dial(address(&a).await).await.unwrap();
    assert!(connected_within(&b, &a, Duration::from_secs(10)).await);
    assert!(quic_known_within(&b, &a, Duration::from_secs(10)).await);

    let target = a.peer_id();
    let slots = velarx_p2p::PROBE_SLOTS;
    let mut probes: futures::stream::FuturesUnordered<_> = (0..24)
        .map(|_| {
            let (b, chunk) = (b.clone(), chunk.clone());
            async move { b.probe(target, &chunk).await.unwrap() }
        })
        .collect();
    // the ones that found no slot are answered at once
    let mut answers = Vec::new();
    for _ in 0..24 - slots {
        answers.push(probes.next().await.unwrap());
    }
    assert!(answers.iter().all(|p| *p == Presence::Busy), "{answers:?}");
    // the others when the store gives the chunk
    store.open();
    while let Some(answer) = probes.next().await {
        answers.push(answer);
    }
    let count = |what| answers.iter().filter(|p| **p == what).count();
    assert_eq!(
        (
            count(Presence::Has),
            count(Presence::Busy),
            count(Presence::Lacks)
        ),
        (slots, 24 - slots, 0)
    );
    let seen = b.lookups().await;
    assert_eq!(
        (seen.probes_has, seen.probes_busy, seen.probes_lacks),
        (slots as u64, 24 - slots as u64, 0)
    );
}

/// A provider the DHT names is an answer, and is connected to: A announces a
/// layer and is connected to B only, C is connected to B only; C finds A in
/// the DHT and is connected to it after the lookup.
///
/// Whether the lookup dials A is not the test's to decide: a node with few
/// peers walks the DHT when it identifies one (and Kademlia walks by itself
/// half a second after a new peer enters a small routing table), and B
/// names A in the answers of the walk, so C may connect to A before, while
/// or after the lookup.  Before, the lookup has nothing to dial; while, it
/// waits for the walk's dial (one dial); after, it dials A.  What holds in
/// every order is checked: the answer, the connection, at most one dial
/// and no failed one.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_a_provider_the_dht_names_is_dialed_and_used() {
    let dir = tempfile::tempdir().unwrap();
    let swarm = key(dir.path(), "swarm.key");
    let (a, b, c) = (
        node(&swarm, true).await,
        node(&swarm, false).await,
        node(&swarm, false).await,
    );
    a.dial(address(&b).await).await.unwrap();
    for (x, y) in [(&a, &b), (&b, &a)] {
        assert!(quic_known_within(x, y, Duration::from_secs(10)).await);
    }
    let layer = digest_of(b"a layer only A has");
    a.announce_layers(vec![layer.clone()]).await.unwrap();
    // (the record is in the DHT when A was told it is stored)
    let mut status = a.status_updates();
    tokio::time::timeout(
        Duration::from_secs(30),
        status.wait_for(|s| s.provider_records > 0),
    )
    .await
    .expect("the layer was not stored in the DHT")
    .unwrap();
    c.dial(address(&b).await).await.unwrap();
    for (x, y) in [(&b, &c), (&c, &b)] {
        assert!(quic_known_within(x, y, Duration::from_secs(10)).await);
    }

    let peers = NodePeers(c.clone());
    assert_eq!(peers.layer_providers(&layer).await, vec![a.peer_id()]);
    assert!(c.is_connected_to(&a.peer_id()).await);
    let seen = c.lookups().await;
    assert_eq!((seen.dht_found, seen.dials_failed), (1, 0));
    assert!(seen.dials <= 1, "A was dialed {} times", seen.dials);

    // a peer nobody knows an address of is not connected to, and that is
    // told at once (no wait for the limit of the dial)
    let dials = c.lookups().await.dials;
    assert!(!c.connect_provider(libp2p::PeerId::random()).await);
    let seen = c.lookups().await;
    assert_eq!((seen.dials, seen.dials_failed), (dials + 1, 1));

    // nobody has this one
    let none = digest_of(b"a layer nobody has");
    assert!(peers.layer_providers(&none).await.is_empty());
}
