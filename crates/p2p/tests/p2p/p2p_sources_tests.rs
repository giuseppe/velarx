// SPDX-License-Identifier: Apache-2.0
//! Two nodes of a swarm, in one process: the store of node A holds an image,
//! node B pulls it with the P2P service as its first content source.  The
//! bytes travel from A's stores through A's store service and A's node, over
//! the network to B's node, through B's fetcher socket to B's pull engine.

use crate::common::*;
use crate::support::{address, connected_within, heard_within, quic_known_within};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use velarx_config::PullConfig;
use velarx_core::store_service::StoreService;
use velarx_p2p::provider::{NodePeers, PeerSource, Peers, Policy};
use velarx_p2p::store::StoreContent;
use velarx_p2p::ChunkProvider;
use velarx_p2p::{P2PConfig, P2PNode};

struct Swarm {
    _dir: tempfile::TempDir,
    a: Env,
    node_a: Arc<P2PNode>,
    node_b: Arc<P2PNode>,
    /// Socket of the P2P service of B, a source for B's pulls
    b_source: std::path::PathBuf,
    /// The store service of A
    store: std::path::PathBuf,
    /// More nodes that hold the image, as A does
    others: Vec<(Env, Arc<P2PNode>)>,
    /// B's source, to see what it learns
    source: Arc<PeerSource>,
    /// The peers B's source asked for chunks, in order
    requests: Arc<Mutex<Vec<libp2p::PeerId>>>,
    /// What a request to each peer takes on the network
    delays: Arc<Mutex<std::collections::HashMap<libp2p::PeerId, Duration>>>,
    /// What else the network does to the requests to a peer
    faults: Faults,
    key: std::path::PathBuf,
    _servers: Vec<Box<dyn std::any::Any + Send>>,
}

/// How a swarm is made: how many nodes hold the image, the address the first of those listens on (the next ones on the
/// following addresses); how B's source asks the peers, and how long a
/// request to A takes.
#[derive(Clone, Copy)]
struct Opts {
    servers: usize,
    first_ip: [u8; 4],
    policy: Policy,
    a_delay: Duration,
    /// The registry of the nodes that hold the image serves no range: they
    /// pull its layers whole
    whole: bool,
    /// The nodes that hold the image pulled it with credentials
    credentials: bool,
}

impl Default for Opts {
    fn default() -> Self {
        Self {
            servers: 1,
            first_ip: [127, 0, 0, 1],
            policy: Policy::default(),
            a_delay: Duration::ZERO,
            whole: false,
            credentials: false,
        }
    }
}

impl Swarm {
    /// The nodes that hold the image announce its layer, as their services
    /// do for what their daemons have.
    async fn announce(&self, layer: &str) {
        for node in std::iter::once(&self.node_a).chain(self.others.iter().map(|(_, n)| n)) {
            node.announce_layers(vec![layer.to_string()]).await.unwrap();
        }
    }
}

async fn node(key: &Path, ip: [u8; 4]) -> Arc<P2PNode> {
    let [a, b, c, d] = ip;
    Arc::new(
        P2PNode::with_config(P2PConfig {
            dial: velarx_p2p::dial_filter::Rules::on_one_host(),
            listen_addrs: vec![format!("/ip4/{a}.{b}.{c}.{d}/tcp/0")],
            enable_mdns: false,
            private_key_path: Some(key.to_path_buf()),
            quic_streams: env_num("BENCH_QUIC_STREAMS", 4),
            filter: velarx_p2p::filter::Config {
                // (a short wait for the filters the tests need told)
                interval: Duration::from_millis(20),
                ..Default::default()
            },
            ..Default::default()
        })
        .await
        .unwrap(),
    )
}

async fn swarm(layers: &[&Built], media: &[&str]) -> Swarm {
    swarm_with(layers, media, None, Opts::default()).await
}

async fn swarm_sharing(
    layers: &[&Built],
    media: &[&str],
    shared: Option<Arc<velarx_core::services::checkpoint::SharedCheckpoints>>,
) -> Swarm {
    swarm_with(layers, media, shared, Opts::default()).await
}

/// B's source asks the peers with `policy`; `a_delay`: how long a request
/// to node A takes, for the peers' link to have a round-trip time.
async fn swarm_full(
    layers: &[&Built],
    media: &[&str],
    shared: Option<Arc<velarx_core::services::checkpoint::SharedCheckpoints>>,
    policy: Policy,
    a_delay: Duration,
) -> Swarm {
    let opts = Opts {
        policy,
        a_delay,
        ..Opts::default()
    };
    swarm_with(layers, media, shared, opts).await
}

/// A node that holds `layers`: its environment (the image pulled), a
/// store service on top of its stores, and a P2P node serving chunks from
/// it.
async fn server(
    dir: &Path,
    name: &str,
    key: &Path,
    (layers, media): (&[&Built], &[&str]),
    shared: Option<Arc<velarx_core::services::checkpoint::SharedCheckpoints>>,
    ip: [u8; 4],
    opts: Opts,
) -> (Env, Arc<P2PNode>, std::path::PathBuf, StoreServer) {
    let a = env().await;
    a.publish(layers, media);
    if opts.whole {
        *a.reg.mode.lock().unwrap() = RangeMode::Refuse;
    }
    if opts.credentials {
        use velarx_registry::auth::{Credentials, RegistryAccess};
        let client = a.client().with_access(&RegistryAccess {
            creds: Some(Credentials::basic("alice", "secret")),
            ..Default::default()
        });
        let (tx, mut rx) = tokio::sync::mpsc::channel(8);
        tokio::spawn(async move { while rx.recv().await.is_some() {} });
        let image = format!("{}/test:latest", a.host);
        a.service
            .pull_with_client(&client, &image, tx)
            .await
            .unwrap();
    } else {
        a.pull().await.unwrap();
    }
    let service = match shared {
        Some(shared) => StoreService::with_checkpoints(a.db.clone(), a.store.clone(), shared)
            .await
            .unwrap(),
        None => StoreService::new(a.db.clone(), a.store.clone())
            .await
            .unwrap(),
    };
    let socket = dir.join(name).join("services").join("store.sock");
    let served = serve_store(service, &socket).await;
    let node_a = node(key, ip).await;
    node_a
        .set_chunk_provider(Arc::new(StoreContent::new(socket.clone())))
        .unwrap();
    // (what the service tells its peers of the layers of the store: the
    // follower of the store does it in the service)
    let announcement = velarx_core::store_service::Announcement::from_database(&a.db)
        .await
        .unwrap();
    node_a.announce_layers(announcement.layers).await.unwrap();
    (a, node_a, socket, served)
}

/// `from` connected to `to`: the status of the node tells when.
/// `from` is connected to `to` and knows its QUIC endpoint, where the data
/// is asked (identify tells it just after the connection).
async fn connect(from: &P2PNode, to: &P2PNode) {
    from.dial(address(to).await).await.unwrap();
    assert!(connected_within(from, to, Duration::from_secs(5)).await);
    assert!(quic_known_within(from, to, Duration::from_secs(10)).await);
}

async fn swarm_with(
    layers: &[&Built],
    media: &[&str],
    shared: Option<Arc<velarx_core::services::checkpoint::SharedCheckpoints>>,
    opts: Opts,
) -> Swarm {
    let dir = tempfile::tempdir().unwrap();
    let key = dir.path().join("swarm.key");
    velarx_p2p::control::generate_swarm_key(&key).unwrap();
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
    let mut servers: Vec<Box<dyn std::any::Any + Send>> = Vec::new();

    let ip = |i: usize| {
        let mut ip = opts.first_ip;
        ip[3] += i as u8;
        ip
    };
    let (a, node_a, store, served) =
        server(dir.path(), "a", &key, (layers, media), shared, ip(0), opts).await;
    servers.push(Box::new(served));
    let mut others = Vec::new();
    for i in 1..opts.servers {
        let (env, node, _, served) = server(
            dir.path(),
            &format!("a{i}"),
            &key,
            (layers, media),
            None,
            ip(i),
            opts,
        )
        .await;
        servers.push(Box::new(served));
        others.push((env, node));
    }

    // Node B: connected to the others, with a source socket for its pull engine.
    let node_b = node(&key, [127, 0, 0, 1]).await;
    connect(&node_b, &node_a).await;
    for (_, other) in &others {
        connect(&node_b, other).await;
    }
    // (what the servers told of their layers is known before the first pull)
    let keys = velarx_core::store_service::Announcement::from_database(&a.db)
        .await
        .unwrap()
        .layers;
    assert!(!keys.is_empty());
    for server in std::iter::once(&node_a).chain(others.iter().map(|(_, n)| n)) {
        assert!(
            heard_within(&node_b, Duration::from_secs(10), || async {
                keys.iter().all(|k| {
                    node_b
                        .knowledge()
                        .filtered(k)
                        .maybe
                        .contains(&server.peer_id())
                })
            })
            .await,
            "the layers of a server were not told"
        );
    }
    let b_source = dir
        .path()
        .join("b")
        .join("services")
        .join("p2p-fetcher.sock");
    let requests = Arc::new(Mutex::new(Vec::new()));
    let delays = Arc::new(Mutex::new(std::collections::HashMap::new()));
    let faults = Faults::default();
    delays
        .lock()
        .unwrap()
        .insert(node_a.peer_id(), opts.a_delay);
    let peer_source = Arc::new(
        PeerSource::with_peers(Arc::new(Noting(
            NodePeers(node_b.clone()),
            requests.clone(),
            delays.clone(),
            faults.clone(),
        )))
        .with_policy(opts.policy)
        .with_knowledge(node_b.knowledge().clone()),
    );
    let listener = velarx_base::ipc::bind_private(&b_source).unwrap();
    servers.push(Box::new(
        velarx_content::serve_fetch::serve_in_thread(
            listener,
            peer_source.clone(),
            velarx_content::activation::Limits::default(),
        )
        .unwrap(),
    ));
    Swarm {
        _dir: dir,
        a,
        node_a,
        node_b,
        b_source,
        store,
        others,
        source: peer_source,
        requests,
        delays,
        faults,
        key,
        _servers: servers,
    }
}

/// A peer that has nothing.
struct Nothing;

impl ChunkProvider for Nothing {
    fn get_chunk(&self, _: &str) -> std::io::Result<Option<Vec<u8>>> {
        Ok(None)
    }
}

/// The node as the peers' transport, noting who is asked for chunks and
/// taking the time a request to that peer takes on the network (`.2`).
struct Noting(
    NodePeers,
    Arc<Mutex<Vec<libp2p::PeerId>>>,
    Arc<Mutex<std::collections::HashMap<libp2p::PeerId, Duration>>>,
    Faults,
);

/// What the network does to the requests to a peer, besides the delay:
/// the next `drop` of them are lost (they fail), and the answers of a peer
/// that `corrupts` are bytes that are not the chunks.
#[derive(Clone, Copy, Default)]
struct Fault {
    drop: usize,
    corrupt: bool,
}

type Faults = Arc<Mutex<std::collections::HashMap<libp2p::PeerId, Fault>>>;

#[async_trait::async_trait]
impl Peers for Noting {
    async fn connected(&self) -> Vec<libp2p::PeerId> {
        self.0.connected().await
    }

    async fn layer_providers(&self, layer: &str) -> Vec<libp2p::PeerId> {
        self.0.layer_providers(layer).await
    }

    async fn request(
        &self,
        peer: libp2p::PeerId,
        items: &[(String, Option<u64>)],
        urgency: velarx_content::fetcher::fetch::Urgency,
        out: velarx_p2p::ChunkTx,
    ) -> Result<(), velarx_p2p::provider::PeerError> {
        self.1.lock().unwrap().push(peer);
        let delay = self.2.lock().unwrap().get(&peer).copied();
        if let Some(delay) = delay {
            // (a slow peer)
            tokio::time::sleep(delay).await;
        }
        let fault = {
            let mut faults = self.3.lock().unwrap();
            let fault = faults.entry(peer).or_default();
            let seen = *fault;
            fault.drop = fault.drop.saturating_sub(1);
            seen
        };
        if fault.drop > 0 {
            return Err(velarx_p2p::provider::PeerError::Failed(
                "the request was lost".into(),
            ));
        }
        let (inner, mut chunks) = tokio::sync::mpsc::channel(velarx_p2p::CHUNKS_IN_FLIGHT);
        let (answer, ()) = futures::join!(self.0.request(peer, items, urgency, inner), async {
            while let Some((digest, mut data)) = chunks.recv().await {
                if fault.corrupt {
                    if let Some(first) = data.first_mut() {
                        *first ^= 0xff;
                    }
                }
                let _ = out.send((digest, data)).await;
            }
        });
        answer
    }

    async fn index(
        &self,
        peer: libp2p::PeerId,
        layer: &str,
        max: u64,
    ) -> Result<Option<Vec<u8>>, velarx_p2p::provider::PeerError> {
        self.0.index(peer, layer, max).await
    }

    async fn has(
        &self,
        peer: libp2p::PeerId,
        digest: &str,
    ) -> Result<velarx_p2p::Presence, String> {
        self.0.has(peer, digest).await
    }

    async fn profile(
        &self,
        peer: libp2p::PeerId,
        image: &str,
        max: u64,
    ) -> Result<Option<Vec<u8>>, velarx_p2p::provider::PeerError> {
        self.0.profile(peer, image, max).await
    }
}

/// Another node of the swarm, connected to B, that answers with `provider`.
async fn add_peer(s: &Swarm, provider: Arc<dyn ChunkProvider>, delay: Duration) -> Arc<P2PNode> {
    let peer = node(&s.key, [127, 0, 0, 1]).await;
    peer.set_chunk_provider(provider).unwrap();
    let addr = address(&peer).await;
    s.delays.lock().unwrap().insert(peer.peer_id(), delay);
    s.node_b.dial(addr).await.unwrap();
    // (bounded, so a peer that never connects fails the test and does not
    // hang it)
    assert!(
        connected_within(&s.node_b, &peer, Duration::from_secs(10)).await,
        "the slow peer never connected"
    );
    assert!(
        quic_known_within(&s.node_b, &peer, Duration::from_secs(10)).await,
        "the QUIC endpoint of the slow peer was not told"
    );
    peer
}

/// A peer that holds what A holds, serving it from A's store and telling
/// B its filter, as the service of a node that pulled the image does.
async fn add_holder(s: &Swarm, delay: Duration) -> Arc<P2PNode> {
    let peer = add_peer(s, Arc::new(StoreContent::new(s.store.clone())), delay).await;
    let layers = velarx_core::store_service::Announcement::from_database(&s.a.db)
        .await
        .unwrap()
        .layers;
    peer.announce_layers(layers.clone()).await.unwrap();
    assert!(
        heard_within(&s.node_b, Duration::from_secs(10), || async {
            layers.iter().all(|l| {
                s.node_b
                    .knowledge()
                    .filtered(l)
                    .maybe
                    .contains(&peer.peer_id())
            })
        })
        .await,
        "the filter of the peer was not told"
    );
    peer
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_a_partial_pull_takes_its_chunks_from_a_peer() {
    let layer = build_chunked(&sample());
    let s = swarm(&[&layer], &[ZSTD]).await;
    let b = env_with_sources(&[&s.b_source]).await;
    b.publish(&[&layer], &[ZSTD]);
    let result = b.pull().await.unwrap();
    assert!(result.stats.from("source0").0 > 0, "{:?}", result.stats);
    // (the table of contents came from A too: no range of the registry)
    assert_eq!(b.reg.ranged.load(Ordering::SeqCst), 0);
    assert_eq!(b.db.get_layer(&layer.key()).await.unwrap().status, "ready");
    assert!(b.store.contains(&vid(b"hello\n")));
    let stats = s.node_a.get_stats().await;
    assert!(stats.chunks_sent > 0);
    // what B fetched from A, for `p2p status`
    let traffic = s.source.knowledge().traffic();
    assert_eq!(traffic.len(), 1);
    let (peer, t) = traffic[0];
    assert_eq!(peer, s.node_a.peer_id());
    assert!(t.requests >= 1 && t.chunks >= 1 && t.failures == 0, "{t:?}");
    assert_eq!(t.bytes, result.stats.from("source0").0);
    assert!(t.average().is_some());
    // B asked A because its filter said maybe, and A had the layer
    let said = s.node_b.lookups().await;
    assert_eq!(
        (said.filter_hits, said.filter_false_positives),
        (1, 0),
        "{said:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_a_lazy_read_takes_its_file_from_a_peer() {
    let layer = build_chunked(&sample());
    let s = swarm(&[&layer], &[ZSTD]).await;
    let b = env_with_sources(&[&s.b_source]).await;
    b.publish(&[&layer], &[ZSTD]);
    b.pull_lazy().await.unwrap();
    let before = b.reg.ranged.load(Ordering::SeqCst);
    let big = sample()
        .into_iter()
        .find_map(|i| match i {
            Item::File {
                name: "usr/big",
                data,
                ..
            } => Some(data),
            _ => None,
        })
        .unwrap();
    let path = b
        .service
        .fetch_lazy_file(&vid(&big), &layer.key())
        .await
        .unwrap();
    assert_eq!(std::fs::read(path).unwrap(), big);
    assert_eq!(
        b.reg.ranged.load(Ordering::SeqCst),
        before,
        "no range request"
    );
    drop(s);
}

/// A layer with the file `usr/data` of `data`, in chunks of 4 KiB.
fn data_layer(data: Vec<u8>) -> Built {
    build_chunked(&[
        Item::Dir("usr/"),
        Item::File {
            name: "usr/data",
            data,
            chunk: 4096,
        },
    ])
}

/// A node B pulls a layer whose file A has, and A gives its chunks and its
/// table of contents (B's registry gives no range).
async fn pulled_from_a(s: &Swarm, layer: &Built, size: usize) {
    let b = env_with_sources(&[&s.b_source]).await;
    b.publish(&[layer], &[ZSTD]);
    let result = b.pull().await.unwrap();
    let from_a = result.stats.from("source0").0;
    assert!(
        from_a >= size as u64,
        "{from_a} of {size}: {:?}",
        result.stats
    );
    assert_eq!(b.reg.ranged.load(Ordering::SeqCst), 0);
    assert_eq!(b.db.get_layer(&layer.key()).await.unwrap().status, "ready");
}

/// A has the file, but not by the chunks B's layer names (it cut the file
/// some other way, or a layer of it has no chunks): B asks for the file by
/// its fs-verity digest, the identity both have, and gets it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_a_file_comes_whole_from_a_peer_that_lacks_its_chunks() {
    let layer = data_layer(noise(200_000, 12));
    let s = swarm(&[&layer], &[ZSTD]).await;
    s.a.db
        .conn()
        .call(|c| Ok(c.execute("DELETE FROM chunk_locations", [])?))
        .await
        .unwrap();
    pulled_from_a(&s, &layer, 200_000).await;
    drop(s);
}

/// Two nodes pull one zstd:chunked descriptor: A from a registry that serves
/// no range (it gives the blob whole, as the transport of the table's
/// ranges), B lazily.  Each has the layer of the table, never one of the
/// blob: A gives no index for the TOC (nor B's pull asks for one: a labelled
/// descriptor comes by its files), the files A gives are checked against B's
/// TOC, and B's layer is proven by its completion.  A node that pulls the
/// descriptor from a registry with no ranges has the layer of the table too.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_a_layer_is_the_layer_of_its_table_whatever_serves_it() {
    let layer = build_chunked(&sample());
    let s = swarm_with(
        &[&layer],
        &[ZSTD],
        None,
        Opts {
            whole: true,
            ..Opts::default()
        },
    )
    .await;
    let a_keys: Vec<velarx_db::LayerKey> =
        s.a.db
            .list_layers()
            .await
            .unwrap()
            .into_iter()
            .map(|l| l.key)
            .collect();
    assert_eq!(a_keys, [layer.key()]);
    let peers = NodePeers(s.node_b.clone());
    let a = s.node_a.peer_id();
    let toc = layer.key().to_string();
    // (the view of a TOC has no digest to name it by: it cannot be asked)
    assert!(peers.index(a, &toc, 64 << 20).await.is_err());
    assert_eq!(
        peers
            .index(a, &layer.whole().to_string(), 64 << 20)
            .await
            .unwrap(),
        None
    );

    let b = env_with_sources(&[&s.b_source]).await;
    b.publish(&[&layer], &[ZSTD]);
    let lazy = b.pull_lazy().await.unwrap();
    // a lazy pull is staged until its completion: the layer is the staged
    // layer of the TOC (not of A's blob), and the store knows nothing of
    // the image yet
    assert_eq!(b.area().layer_keys(), [layer.key()]);
    let staged = b.area().layer(&layer.key()).unwrap().expect("staged");
    assert_eq!(staged.key(), layer.key());
    assert!(b
        .db
        .get_image_layers_without_toc(&lazy.id)
        .await
        .unwrap()
        .is_empty());
    assert!(b.db.get_layer(&layer.key()).await.is_err());
    let big = sample()
        .into_iter()
        .find_map(|i| match i {
            Item::File {
                name: "usr/big",
                data,
                ..
            } => Some(data),
            _ => None,
        })
        .unwrap();
    let path = b
        .service
        .fetch_lazy_file(&vid(&big), &layer.key())
        .await
        .unwrap();
    assert_eq!(std::fs::read(path).unwrap(), big);
    b.service.complete_image(&lazy.id).await.unwrap();
    // the completion commits it: the image has the layer of its TOC, and
    // the staging area is empty
    let keys: Vec<velarx_db::LayerKey> =
        b.db.get_image_layers_without_toc(&lazy.id)
            .await
            .unwrap()
            .into_iter()
            .map(|l| l.key)
            .collect();
    assert_eq!(keys, [layer.key()]);
    assert!(b.area().layer_keys().is_empty());
    let record = b.db.get_layer(&layer.key()).await.unwrap();
    assert_eq!(
        (record.status.as_str(), record.diff_id.as_ref()),
        ("ready", None)
    );
    assert!(b.db.get_layer(&layer.whole()).await.is_err());
    drop(s);

    // A has the layer of the TOC, C pulls the descriptor from a registry
    // with no ranges: A gives the table of contents and the files
    let s = swarm(&[&layer], &[ZSTD]).await;
    let c = env_with_sources(&[&s.b_source]).await;
    c.publish(&[&layer], &[ZSTD]);
    *c.reg.mode.lock().unwrap() = RangeMode::Refuse;
    let pulled = c.pull().await.unwrap();
    let keys: Vec<velarx_db::LayerKey> =
        c.db.get_image_layers_without_toc(&pulled.id)
            .await
            .unwrap()
            .into_iter()
            .map(|l| l.key)
            .collect();
    assert_eq!(keys, [layer.key()]);
    assert_eq!(
        c.reg.hits.lock().unwrap().get(&sha(&layer.blob)).copied(),
        None,
        "the registry is not asked for the blob"
    );
    let peers = NodePeers(s.node_b.clone());
    let a = s.node_a.peer_id();
    assert_eq!(
        peers
            .index(a, &layer.whole().to_string(), 64 << 20)
            .await
            .unwrap(),
        None
    );
    drop(s);
}

/// The store service hands over the files that hold chunks, as descriptors.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_the_store_hands_over_the_files_of_chunks() {
    use std::io::Read;
    let layer = build_chunked(&sample());
    let s = swarm(&[&layer], &[ZSTD]).await;
    let content = Arc::new(StoreContent::new(s.store.clone()));
    let hello = sha(b"hello\n").to_string();
    let missing = sha(b"not in any store").to_string();
    let asked = [missing, hello];
    let found = tokio::task::spawn_blocking(move || content.open_chunks(&asked))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(found.len(), 2);
    assert!(found[0].is_none());
    let chunk = found[1].as_ref().expect("a file for a stored chunk");
    let mut data = vec![0u8; chunk.len as usize];
    let mut file = &chunk.file;
    std::io::Seek::seek(&mut file, std::io::SeekFrom::Start(chunk.offset)).unwrap();
    file.read_exact(&mut data).unwrap();
    assert_eq!(data, b"hello\n");
    drop(s);
}

/// A gzip layer has no chunks: a peer gives its index (its TOC and
/// tar-split) and its files by digest, and the layer is checked against
/// its diff id; the registry is not asked for it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_a_gzip_layer_comes_from_a_peer() {
    let layer = build_gzip(&sample());
    let s = swarm(&[&layer], &[GZIP]).await;
    let b = env_with_sources(&[&s.b_source]).await;
    b.publish(&[&layer], &[GZIP]);
    let result = b.pull().await.unwrap();
    assert_eq!(
        b.reg
            .hits
            .lock()
            .unwrap()
            .get(&sha(&layer.blob))
            .copied()
            .unwrap_or(0),
        0,
        "the registry was not asked for the layer"
    );
    assert!(result.stats.from("source0").0 > 0, "{:?}", result.stats);
    let rec = b.db.get_layer(&layer.key()).await.unwrap();
    assert_eq!(rec.status, "ready");
    assert_eq!(rec.diff_id.as_ref(), Some(&layer.diff_id));
    assert!(b.store.contains(&vid(b"hello\n")));
    drop(s);
}

/// A node that took a gzip layer from a peer serves it in turn: a third node
/// takes it from that one, with the first one not reachable and the registry
/// never asked for the layer.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_a_gzip_layer_taken_from_a_peer_is_served_by_its_node() {
    let layer = build_gzip(&sample());
    let s = swarm(&[&layer], &[GZIP]).await;
    let b = env_with_sources(&[&s.b_source]).await;
    b.publish(&[&layer], &[GZIP]);
    b.pull().await.unwrap();
    let digest = sha(&layer.blob).to_string();
    // (B is a node of the swarm of its own, which tells its layers)
    let announcement = velarx_core::store_service::Announcement::from_database(&b.db)
        .await
        .unwrap();
    assert!(announcement.layers.contains(&digest), "{announcement:?}");
    let socket = s._dir.path().join("b-store").join("store.sock");
    let service = StoreService::new(b.db.clone(), b.store.clone())
        .await
        .unwrap();
    let _served = serve_store(service, &socket).await;
    let node_b = node(&s.key, [127, 0, 0, 1]).await;
    node_b
        .set_chunk_provider(Arc::new(StoreContent::new(socket)))
        .unwrap();
    node_b.announce_layers(announcement.layers).await.unwrap();
    // C knows B and nobody else
    let node_c = node(&s.key, [127, 0, 0, 1]).await;
    connect(&node_c, &node_b).await;
    assert!(
        heard_within(&node_c, Duration::from_secs(10), || async {
            node_c
                .knowledge()
                .filtered(&digest)
                .maybe
                .contains(&node_b.peer_id())
        })
        .await,
        "the layer of B was not told"
    );
    let source_c = s
        ._dir
        .path()
        .join("c")
        .join("services")
        .join("p2p-fetcher.sock");
    let peers = Arc::new(
        PeerSource::with_peers(Arc::new(NodePeers(node_c.clone())))
            .with_knowledge(node_c.knowledge().clone()),
    );
    let listener = velarx_base::ipc::bind_private(&source_c).unwrap();
    let _fetcher = velarx_content::serve_fetch::serve_in_thread(
        listener,
        peers,
        velarx_content::activation::Limits::default(),
    )
    .unwrap();
    let c = env_with_sources(&[&source_c]).await;
    c.publish(&[&layer], &[GZIP]);
    let result = c.pull().await.unwrap();
    assert_eq!(
        c.reg
            .hits
            .lock()
            .unwrap()
            .get(&sha(&layer.blob))
            .copied()
            .unwrap_or(0),
        0,
        "the registry was not asked for the layer"
    );
    assert!(result.stats.from("source0").0 > 0, "{:?}", result.stats);
    let rec = c.db.get_layer(&layer.key()).await.unwrap();
    assert_eq!(rec.diff_id.as_ref(), Some(&layer.diff_id));
    assert!(c.store.contains(&vid(b"hello\n")));
    drop(s);
}

/// A layer that shares files with one the node has takes from the peers the
/// files it lacks and no other.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_a_new_version_of_a_gzip_layer_takes_only_the_files_it_lacks() {
    let v1 = build_gzip(&sample());
    let mut items = sample();
    items.push(Item::File {
        name: "usr/new",
        data: noise(50_000, 5),
        chunk: 4096,
    });
    let v2 = build_gzip(&items);
    let s = swarm(&[&v1, &v2], &[GZIP, GZIP]).await;
    let b = env_with_sources(&[&s.b_source]).await;
    b.publish(&[&v1], &[GZIP]);
    b.pull().await.unwrap();
    b.publish(&[&v2], &[GZIP]);
    let result = b.pull().await.unwrap();
    assert_eq!(
        b.reg
            .hits
            .lock()
            .unwrap()
            .get(&sha(&v2.blob))
            .copied()
            .unwrap_or(0),
        0,
        "the registry was not asked for the layer"
    );
    // (the file of v2 that v1 does not have)
    assert_eq!(result.stats.from("source0").1, 1, "{:?}", result.stats);
    assert_eq!(b.db.get_layer(&v2.key()).await.unwrap().status, "ready");
    drop(s);
}

/// What a peer sends that is not the file asked for is not taken: the
/// registry gives the layer.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_a_gzip_layer_from_a_peer_that_sends_wrong_bytes_comes_from_the_registry() {
    let layer = build_gzip(&sample());
    let s = swarm(&[&layer], &[GZIP]).await;
    s.faults.lock().unwrap().insert(
        s.node_a.peer_id(),
        Fault {
            drop: 0,
            corrupt: true,
        },
    );
    let b = env_with_sources(&[&s.b_source]).await;
    b.publish(&[&layer], &[GZIP]);
    b.pull().await.unwrap();
    assert!(
        b.reg.hits.lock().unwrap().get(&sha(&layer.blob)).copied() >= Some(1),
        "the registry gave the layer"
    );
    let rec = b.db.get_layer(&layer.key()).await.unwrap();
    assert_eq!(
        (rec.status.as_str(), rec.diff_id.as_ref()),
        ("ready", Some(&layer.diff_id))
    );
    drop(s);
}

/// A file of a gzip layer too big for a peer to give whole (16 MiB) comes in
/// the pieces the layer's table cuts it in: the registry is not asked for
/// the layer.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_a_gzip_layer_with_a_huge_file_comes_from_a_peer() {
    let huge = noise(40 << 20, 9);
    let mut items = sample();
    items.push(Item::File {
        name: "usr/huge",
        data: huge.clone(),
        chunk: 1 << 20,
    });
    let layer = build_gzip(&items);
    let s = swarm(&[&layer], &[GZIP]).await;
    let b = env_with_sources(&[&s.b_source]).await;
    b.publish(&[&layer], &[GZIP]);
    let result = b.pull().await.unwrap();
    assert_eq!(
        b.reg
            .hits
            .lock()
            .unwrap()
            .get(&sha(&layer.blob))
            .copied()
            .unwrap_or(0),
        0,
        "the registry was not asked for the layer"
    );
    assert!(result.stats.from("source0").0 >= huge.len() as u64);
    let rec = b.db.get_layer(&layer.key()).await.unwrap();
    assert_eq!(
        (rec.status.as_str(), rec.diff_id.as_ref()),
        ("ready", Some(&layer.diff_id))
    );
    assert!(b.store.contains(&vid(&huge)));
    drop(s);
}

/// A checkpoint archive node A shares comes to node B over QUIC, piece by
/// piece, each checked, the whole against the manifest.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_a_shared_checkpoint_comes_from_a_peer() {
    use velarx_core::services::checkpoint::{fetch, SharedCheckpoints, PIECE};
    let dir = tempfile::tempdir().unwrap();
    let shared = SharedCheckpoints::new(dir.path()).unwrap();
    let archive: Vec<u8> = (0..PIECE + 4321).map(|i| (i * 7 % 251) as u8).collect();
    let path = dir.path().join("cp.tar");
    std::fs::write(&path, &archive).unwrap();
    let (reference, _) = shared.share(&path).unwrap();
    let layer = build_chunked(&sample());
    let s = swarm_sharing(&[&layer], &[ZSTD], Some(Arc::new(shared))).await;
    // A tells what it shares (its manifest as a layer, in the DHT), as the
    // P2P service follows its store service; B finds it by the manifest
    let (stop, rx) = tokio::sync::broadcast::channel(1);
    let follower =
        velarx_p2p::store::follow_store_on_thread(s.node_a.clone(), s.store.clone(), rx).unwrap();
    let b = env_with_sources(&[&s.b_source]).await;
    let dest = dir.path().join("fetched.tar");
    fetch(&*b.service, &reference, &dest).await.unwrap();
    assert_eq!(std::fs::read(&dest).unwrap(), archive);
    // a reference nobody shares
    let other = velarx_core::services::checkpoint::Reference::parse(&format!(
        "{}:100:{}",
        sha(b"nobody"),
        "11".repeat(32)
    ))
    .unwrap();
    assert!(fetch(&*b.service, &other, &dir.path().join("none.tar"))
        .await
        .is_err());
    let _ = stop.send(());
    follower.join().unwrap();
    drop(s);
}

/// A node that pulled an image with credentials gives it to the peers as any
/// other: a node whose registry does not have the image pulls it by its
/// digest from them.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_a_pull_with_credentials_is_given_to_and_taken_from_the_peers() {
    use velarx_registry::auth::{Credentials, RegistryAccess};
    let layer = build_gzip(&sample());
    let opts = Opts {
        credentials: true,
        ..Opts::default()
    };
    let s = swarm_with(&[&layer], &[GZIP], None, opts).await;
    let record = s.a.db.list_images().await.unwrap().remove(0);
    // (B's registry has nothing: the peers have the image)
    let b = env_with_sources(&[&s.b_source]).await;
    let client = b.client().with_access(&RegistryAccess {
        creds: Some(Credentials::basic("bob", "secret")),
        ..Default::default()
    });
    let (tx, mut rx) = tokio::sync::mpsc::channel(8);
    tokio::spawn(async move { while rx.recv().await.is_some() {} });
    let image = format!("{}/test@{}", b.host, record.manifest_digest);
    let result = b
        .service
        .pull_with_client(&client, &image, tx)
        .await
        .unwrap();
    assert!(result.stats.from("source0").0 > 0, "{:?}", result.stats);
    assert_eq!(b.reg.hits.lock().unwrap().get(&sha(&layer.blob)), None);
    assert!(b.store.contains(&vid(b"hello\n")));
    drop(s);
}

/// A layer of `n` files of `size` bytes in one directory, and their digests.
fn files_layer(n: usize, size: usize) -> (Built, Vec<String>) {
    let mut items = vec![Item::Dir("d/")];
    let mut digests = Vec::new();
    for i in 0..n {
        let name: &'static str = Box::leak(format!("d/f{i:04}").into_boxed_str());
        let data = noise(size + (i % 7) * 512, i as u64 + 1);
        digests.push(vid(&data));
        items.push(Item::File {
            name,
            data,
            chunk: 1 << 20,
        });
    }
    (build_chunked(&items), digests)
}

/// A node B that pulled `layer` lazily with this window, and takes its files
/// from the swarm.
async fn lazy_b(s: &Swarm, layer: &Built, window_files: usize) -> Env {
    let b = env_sources(
        PullConfig {
            lazy_window_files: window_files,
            lazy_window_kib: 1024,
            ..PullConfig::default()
        },
        velarx_config::PushConfig::default(),
        chain_of(&[&s.b_source]),
    )
    .await;
    b.publish(&[layer], &[ZSTD]);
    b.pull_lazy().await.unwrap();
    b
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_the_files_after_a_miss_come_from_a_peer_in_one_request() {
    let (layer, d) = files_layer(30, 3000);
    let layer_digest = layer.key();
    let s = swarm(&[&layer], &[ZSTD]).await;
    let b = lazy_b(&s, &layer, 8).await;
    let ranged = b.reg.ranged.load(Ordering::SeqCst);
    let fetcher = &b.service;
    for f in &d[..9] {
        fetcher.fetch_lazy_file(f, &layer_digest).await.unwrap();
    }
    // the file, and the eight that follow
    let requests = s.requests.lock().unwrap().len();
    assert!(requests <= 2, "{requests} requests for 9 files");
    assert_eq!(b.reg.ranged.load(Ordering::SeqCst), ranged, "no registry");
    // a lazy pull keeps what it fetches in the pool of the staging area,
    // and the store has nothing of it until the completion
    let pooled = b.pooled();
    for f in &d[..9] {
        assert!(pooled.contains(f), "{f} is not in the pool");
        assert!(
            !b.store.contains(f),
            "{f} is in the store before completion"
        );
    }
    assert!(!pooled.contains(&d[9]));
    assert_eq!(pooled.len(), 9);
    // the completion moves the pool into the store
    let id = b.area().pulls()[0].pull.id.clone();
    b.service.complete_image(&id).await.unwrap();
    for f in &d {
        assert!(
            b.store.contains(f),
            "{f} is not in the store after completion"
        );
    }
    assert!(b.pooled().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_a_profile_is_taken_from_a_peer_in_one_request() {
    let (layer, d) = files_layer(30, 3000);
    let layer_digest = layer.key();
    let s = swarm(&[&layer], &[ZSTD]).await;
    let b = lazy_b(&s, &layer, 0).await;
    let ranged = b.reg.ranged.load(Ordering::SeqCst);
    let profile: Vec<String> = [20, 3, 11, 4, 25].iter().map(|&i| d[i].clone()).collect();
    b.service
        .stage_lazy(
            &layer_digest,
            profile.clone(),
            velarx_content::fetcher::fetch::Urgency::Background,
        )
        .await
        .unwrap();
    assert!(s.requests.lock().unwrap().len() <= 2);
    assert_eq!(b.reg.ranged.load(Ordering::SeqCst), ranged, "no registry");
    let pooled = b.pooled();
    for f in &profile {
        assert!(pooled.contains(f), "{f} is not in the pool");
        assert!(
            !b.store.contains(f),
            "{f} is in the store before completion"
        );
    }
    assert_eq!(pooled.len(), profile.len());
}

/// The completion of a lazy pull whose files a peer has takes them from the
/// peer and counts them in its statistics (by source), not as bytes
/// of the registry.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_the_completion_counts_the_bytes_by_source() {
    let (layer, _) = files_layer(12, 3000);
    let s = swarm(&[&layer], &[ZSTD]).await;
    let b = lazy_b(&s, &layer, 0).await;
    let ranged = b.reg.ranged.load(Ordering::SeqCst);
    let id = b.area().pulls()[0].pull.id.clone();
    let stats = b.service.complete_image(&id).await.unwrap();
    assert!(stats.from("source0").0 > 0, "{stats:?}");
    assert_eq!(stats.from("registry").0, 0, "{stats:?}");
    assert_eq!(b.reg.ranged.load(Ordering::SeqCst), ranged, "no registry");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_a_peer_that_has_nothing_of_the_layer_is_not_asked_again() {
    let (layer, d) = files_layer(12, 3000);
    let layer_digest = layer.key();
    let s = swarm(&[&layer], &[ZSTD]).await;
    let empty = add_peer(&s, Arc::new(Nothing), Duration::ZERO).await;
    let b = lazy_b(&s, &layer, 0).await;
    let fetcher = &b.service;
    for f in &d {
        fetcher.fetch_lazy_file(f, &layer_digest).await.unwrap();
    }
    let asked = s.requests.lock().unwrap().clone();
    let empty_asked = asked.iter().filter(|p| **p == empty.peer_id()).count();
    assert!(
        empty_asked <= 1,
        "the empty peer was asked {empty_asked} times"
    );
    assert_eq!(asked.len() - empty_asked, d.len(), "{asked:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_a_slow_peer_does_not_hold_up_a_read_when_another_has_the_file() {
    let (layer, d) = files_layer(6, 3000);
    let layer_digest = layer.key();
    let policy = Policy {
        hedge: true,
        hedge_delay: Some(Duration::from_millis(60)),
        ..Policy::default()
    };
    // A takes two seconds; the other peer, the same content at once
    let s = swarm_full(&[&layer], &[ZSTD], None, policy, Duration::from_secs(2)).await;
    let _quick = add_holder(&s, Duration::ZERO).await;
    let b = lazy_b(&s, &layer, 0).await;
    let ranged = b.reg.ranged.load(Ordering::SeqCst);
    let fetcher = &b.service;
    for f in &d {
        let t = std::time::Instant::now();
        fetcher.fetch_lazy_file(f, &layer_digest).await.unwrap();
        assert!(
            t.elapsed() < Duration::from_millis(1500),
            "{:?}",
            t.elapsed()
        );
        assert!(b.pooled().contains(f), "{f} is not in the pool");
        assert!(!b.store.contains(f));
    }
    assert_eq!(b.reg.ranged.load(Ordering::SeqCst), ranged, "no registry");
}

/// Peers that lose requests or answer with wrong bytes are not asked again
/// by what they cost, and the file comes from a peer that has it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_a_peer_that_loses_requests_or_sends_wrong_bytes_is_replaced_by_one_that_has_the_file()
{
    for (name, fault) in [
        (
            "lost",
            Fault {
                drop: usize::MAX,
                corrupt: false,
            },
        ),
        (
            "wrong",
            Fault {
                drop: 0,
                corrupt: true,
            },
        ),
    ] {
        let (layer, d) = files_layer(4, 3000);
        let layer_digest = layer.key();
        let s = swarm_full(&[&layer], &[ZSTD], None, Policy::default(), Duration::ZERO).await;
        s.faults.lock().unwrap().insert(s.node_a.peer_id(), fault);
        let quick = add_holder(&s, Duration::ZERO).await;
        let b = lazy_b(&s, &layer, 0).await;
        let ranged = b.reg.ranged.load(Ordering::SeqCst);
        for f in &d {
            b.service.fetch_lazy_file(f, &layer_digest).await.unwrap();
            assert!(b.pooled().contains(f), "{name}: {f} is not in the pool");
        }
        assert_eq!(
            b.reg.ranged.load(Ordering::SeqCst),
            ranged,
            "{name}: the registry was asked"
        );
        // the one that did not fail gave the chunks; the wrong bytes of the other were refused
        let traffic = s.source.knowledge().traffic();
        let from_quick = traffic
            .iter()
            .find(|(p, _)| *p == quick.peer_id())
            .map_or(0, |(_, t)| t.chunks);
        let from_a = traffic
            .iter()
            .find(|(p, _)| *p == s.node_a.peer_id())
            .map_or(0, |(_, t)| t.chunks);
        assert!(from_quick > 0 && from_a == 0, "{name}: {traffic:?}");
    }
}

/// Pseudo-random bytes (they do not compress).
fn noise(len: usize, mut x: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    while out.len() < len {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        out.extend_from_slice(&x.to_le_bytes());
    }
    out.truncate(len);
    out
}

fn env_num(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

/// The digests and sizes of a list of files or chunks.
type Digests = Vec<(String, u64)>;

/// The image of the benchmarks: `small` files of 4 to 10 KiB and one of
/// `big_mb` MiB in chunks of 1 MiB; the digests of the small files, of the
/// big one and of its chunks.
fn bench_layer(small: usize, big_mb: usize) -> (Built, Digests, String, Digests) {
    let mut items = vec![Item::Dir("d/")];
    let mut smalls = Vec::new();
    for i in 0..small {
        let name: &'static str = Box::leak(format!("d/f{i:04}").into_boxed_str());
        let data = noise(4096 + (i % 7) * 1024, i as u64 + 1);
        smalls.push((vid(&data), data.len() as u64));
        items.push(Item::File {
            name,
            data,
            chunk: 1 << 20,
        });
    }
    let big = noise(big_mb << 20, 99);
    let big_digest = vid(&big);
    let chunks = big
        .chunks(1 << 20)
        .map(|c| (sha(c).to_string(), c.len() as u64))
        .collect();
    items.push(Item::File {
        name: "big",
        data: big,
        chunk: 1 << 20,
    });
    (build_chunked(&items), smalls, big_digest, chunks)
}

fn bench_opts(servers: usize) -> Opts {
    Opts {
        servers,
        // the nodes that serve are on their own addresses, for tc filters
        first_ip: [127, 0, 0, 2],
        ..Opts::default()
    }
}

/// Fetch `items` from the P2P service of B as the engine asks a fetcher for
/// an item by its digest (`Get` of a `blob`, each on a connection of its
/// own, at the same time): the items and bytes that came, the time to the
/// first byte and the whole time.
async fn source_fetch(
    socket: &std::path::Path,
    items: &[(String, u64)],
    _layer: &str,
) -> (usize, u64, Duration, Duration) {
    let t = std::time::Instant::now();
    let first = std::sync::Mutex::new(None);
    let got = futures::future::join_all(items.iter().map(|(digest, size)| {
        let first = &first;
        async move {
            let data = blob_from(socket, digest, *size).await;
            if data.is_some() {
                first
                    .lock()
                    .unwrap()
                    .get_or_insert_with(std::time::Instant::now);
            }
            data
        }
    }))
    .await;
    let all = t.elapsed();
    let first = first.into_inner().unwrap().map_or(all, |f| f - t);
    let came: Vec<Vec<u8>> = got.into_iter().flatten().collect();
    (
        came.len(),
        came.iter().map(|d| d.len() as u64).sum(),
        first,
        all,
    )
}

fn percentile(times: &mut [Duration], p: usize) -> f64 {
    times.sort();
    times[(times.len() * p / 100).min(times.len() - 1)].as_secs_f64() * 1e3
}

/// What a transfer between peers costs, as B's pull
/// engine sees it (through B's source socket): the time to the first byte
/// of the first request, the latency of a request for one small file, many
/// small files and the chunks of a big one in batches.  Not a check:
/// `tests/perf/p2p.sh` runs it under emulated networks.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "a benchmark, not a check"]
async fn bench_transport() {
    let small = env_num("BENCH_SMALL", 300);
    let big_mb = env_num("BENCH_BIG_MB", 32);
    let servers = env_num("BENCH_SERVERS", 1);
    let batch = env_num("BENCH_BATCH", 64);
    let (layer, smalls, _, chunks) = bench_layer(small, big_mb);
    let layer_digest = layer.key();
    {
        let s = swarm_with(&[&layer], &[ZSTD], None, bench_opts(servers)).await;
        s.announce(&layer_digest.to_string()).await;
        // the peers know each other for a while before the first pull (a
        // window of the benchmark: their routes settle)
        tokio::time::sleep(Duration::from_millis(1500)).await;
        let source = s.b_source.clone();
        let (n, _, first, _) = source_fetch(&source, &smalls[..1], &layer_digest.to_string()).await;
        assert_eq!(n, 1);
        eprintln!(
            "bench first_request_ttfb_ms {:.1}",
            first.as_secs_f64() * 1e3
        );
        let mut times = Vec::new();
        for item in &smalls[1..] {
            let (n, _, _, all) = source_fetch(
                &source,
                std::slice::from_ref(item),
                &layer_digest.to_string(),
            )
            .await;
            assert_eq!(n, 1);
            times.push(all);
        }
        eprintln!(
            "bench small_request_ms p50 {:.1} p99 {:.1}",
            percentile(&mut times, 50),
            percentile(&mut times, 99)
        );
        let t = std::time::Instant::now();
        let mut got = 0;
        for group in smalls.chunks(batch) {
            got += source_fetch(&source, group, &layer_digest.to_string())
                .await
                .0;
        }
        let took = t.elapsed().as_secs_f64();
        assert_eq!(got, smalls.len());
        eprintln!("bench small_batched files_per_s {:.0}", got as f64 / took);
        let big_batch = env_num("BENCH_BIG_BATCH", 16);
        let t = std::time::Instant::now();
        let (mut bytes, mut ttfb) = (0, None);
        for group in chunks.chunks(big_batch) {
            let (n, b, first, _) = source_fetch(&source, group, &layer_digest.to_string()).await;
            assert_eq!(n, group.len());
            ttfb.get_or_insert(first);
            bytes += b;
        }
        let took = t.elapsed().as_secs_f64();
        eprintln!(
            "bench big_chunks mb_per_s {:.1} ttfb_ms {:.1}",
            bytes as f64 / 1e6 / took,
            ttfb.unwrap_or_default().as_secs_f64() * 1e3
        );
        drop(s);
    }
}

/// What a peer transfer costs to the pull engine: a whole pull of a big
/// file and many small ones, then the lazy read of the small ones one by
/// one, then of the big one.  Not a check: `tests/perf/p2p.sh` runs it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "a benchmark, not a check"]
async fn bench_peer_transfer() {
    if std::env::var_os("BENCH_TRACE").is_some() {
        let _ = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .try_init();
    }
    let small = env_num("BENCH_SMALL", 300);
    let big_mb = env_num("BENCH_BIG_MB", 32);
    let servers = env_num("BENCH_SERVERS", 1);
    let (layer, smalls, big_digest, _) = bench_layer(small, big_mb);
    let layer_digest = layer.key();
    {
        let s = swarm_with(&[&layer], &[ZSTD], None, bench_opts(servers)).await;
        s.announce(&layer_digest.to_string()).await;
        // (a window of the benchmark: the peers know each other for a while)
        tokio::time::sleep(Duration::from_millis(1500)).await;

        // a whole pull
        let b = env_with_sources(&[&s.b_source]).await;
        b.publish(&[&layer], &[ZSTD]);
        let t = std::time::Instant::now();
        let result = b.pull().await.unwrap();
        let took = t.elapsed();
        assert!(b.store.contains(&big_digest));
        eprintln!(
            "bench whole_pull s {:.2} mb_per_s {:.1} from_peers {}",
            took.as_secs_f64(),
            result.stats.from("source0").0 as f64 / 1e6 / took.as_secs_f64(),
            result.stats.from("source0").0
        );

        // the lazy reads of the small files, then of the big one
        let c = env_with_sources(&[&s.b_source]).await;
        c.publish(&[&layer], &[ZSTD]);
        c.pull_lazy().await.unwrap();
        let before = c.reg.ranged.load(Ordering::SeqCst);
        let mut times = Vec::new();
        for (d, _) in &smalls {
            let t = std::time::Instant::now();
            c.service.fetch_lazy_file(d, &layer_digest).await.unwrap();
            times.push(t.elapsed());
        }
        eprintln!(
            "bench lazy_small_ms p50 {:.1} p99 {:.1}",
            percentile(&mut times, 50),
            percentile(&mut times, 99)
        );
        let t = std::time::Instant::now();
        c.service
            .fetch_lazy_file(&big_digest, &layer_digest)
            .await
            .unwrap();
        eprintln!(
            "bench lazy_big s {:.2} registry_ranges {}",
            t.elapsed().as_secs_f64(),
            c.reg.ranged.load(Ordering::SeqCst) - before
        );
        drop(s);
    }
}

/// The layers a node announces reach the peers by gossip, those connected
/// and those that connect later: no lookup in the DHT to find who has them.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_the_layers_of_a_node_reach_its_peers_by_gossip() {
    let layer = build_chunked(&sample());
    let s = swarm(&[&layer], &[ZSTD]).await;
    let digest = sha(&layer.blob).to_string();
    let key = s._dir.path().join("swarm.key");
    let announcer = node(&key, [127, 0, 0, 1]).await;
    connect(&s.node_b, &announcer).await;
    announcer
        .announce_layers(vec![digest.clone()])
        .await
        .unwrap();
    // (what a peer told is waited for, at most 5 s)
    async fn told(node: &P2PNode, digest: &str, by: libp2p::PeerId) -> Vec<libp2p::PeerId> {
        let within = Duration::from_secs(5);
        heard_within(node, within, || async {
            node.knowledge().filtered(digest).maybe.contains(&by)
        })
        .await;
        node.knowledge()
            .filtered(digest)
            .maybe
            .into_iter()
            .collect()
    }
    // (the server that holds the layer told too)
    let who = announcer.peer_id();
    assert!(told(&s.node_b, &digest, who).await.contains(&who));
    let late = node(&key, [127, 0, 0, 1]).await;
    connect(&late, &announcer).await;
    assert_eq!(told(&late, &digest, who).await, vec![who]);
    // not what is not a layer it announced
    assert!(late
        .knowledge()
        .filtered(&sha(b"other").to_string())
        .maybe
        .is_empty());
}

/// A file larger than one answer of a peer (16 MiB) comes whole from it:
/// what had no room is asked for again, not taken from the registry.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_a_lazy_file_larger_than_an_answer_comes_from_a_peer() {
    // 20 chunks of 1 MiB and a short one: two answers at least
    let big = noise((20 << 20) + 4321, 7);
    let layer = build_chunked(&[
        Item::Dir("d/"),
        Item::File {
            name: "d/big",
            data: big.clone(),
            chunk: 1 << 20,
        },
    ]);
    let s = swarm(&[&layer], &[ZSTD]).await;
    let b = env_with_sources(&[&s.b_source]).await;
    b.publish(&[&layer], &[ZSTD]);
    b.pull_lazy().await.unwrap();
    let before = b.reg.ranged.load(Ordering::SeqCst);
    let path = b
        .service
        .fetch_lazy_file(&vid(&big), &layer.key())
        .await
        .unwrap();
    assert!(std::fs::read(path).unwrap() == big);
    assert_eq!(
        b.reg.ranged.load(Ordering::SeqCst),
        before,
        "no range request"
    );
    // (the second answer came from the same peer)
    assert!(s.node_a.get_stats().await.chunks_sent >= 21);
    drop(s);
}

/// A node that has no startup profile for an image gets the one of a peer
/// that has the image; not for an image the peer
/// does not have, nor one it may not give.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_a_profile_comes_from_a_peer_that_has_the_image() {
    use velarx_content::fetcher::fetch::PROFILE_MAX_BYTES;
    use velarx_fuse::{composefs, profile};
    let (layer, d) = files_layer(10, 3000);
    let s = swarm(&[&layer], &[ZSTD]).await;
    let id = s.a.db.list_images().await.unwrap()[0].id.clone();
    let path = composefs::profile_path(s.a.store.root(), &id);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let doc = serde_json::json!({"v": 1, "files": [d[3], d[1], "junk"]});
    std::fs::write(&path, doc.to_string()).unwrap();
    let image = format!("sha256:{id}");
    let profile_of = |image: String, max: u64| {
        let socket = s.b_source.clone();
        async move { profile_from(&socket, &image, max).await }
    };
    let got = profile_of(image.clone(), PROFILE_MAX_BYTES)
        .await
        .expect("the profile of the peer");
    assert_eq!(profile::parse(&got, 100), [d[3].clone(), d[1].clone()]);
    // bounded by what is asked
    assert!(profile_of(image.clone(), 10).await.is_none());
    // an image the peer does not have
    assert!(
        profile_of(sha(b"another image").to_string(), PROFILE_MAX_BYTES)
            .await
            .is_none()
    );
    // a profile that is not one is not given
    std::fs::write(&path, b"{\"v\":1,\"files\":[\"junk\"]}").unwrap();
    assert!(profile_of(image.clone(), PROFILE_MAX_BYTES).await.is_none());
    drop(s);
}

/// Read the files one after the other, as a program that starts does: the
/// time of each.
async fn read_in_order(
    b: &Env,
    layer: &velarx_db::LayerKey,
    digests: &[String],
    forget: Option<&PeerSource>,
) -> Vec<Duration> {
    let fetcher = &b.service;
    let mut times = Vec::new();
    for d in digests {
        if let Some(s) = forget {
            s.knowledge().forget();
        }
        let t = std::time::Instant::now();
        fetcher.fetch_lazy_file(d, layer).await.unwrap();
        times.push(t.elapsed());
    }
    times
}

/// What the lazy reads of a node cost with the peers: with a read-ahead
/// window of 0, 8 and 64 files, after the prefetch of a startup profile,
/// and with a peer that has nothing of the layer.  Not a check:
/// `cargo test -p velarx-p2p --test p2p -- --ignored --nocapture p2p_sources_tests::bench_lazy`.
/// BENCH_RTT_MS (20) is what a request to a peer takes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "a benchmark, not a check"]
async fn bench_lazy_peers() {
    let rtt: u64 = std::env::var("BENCH_RTT_MS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(20);
    let n: usize = std::env::var("BENCH_FILES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(200);
    let (layer, d) = files_layer(n, 4096);
    let layer_digest = layer.key();
    let policy = Policy {
        hedge: true,
        hedge_delay: None,
        ..Policy::default()
    };
    eprintln!("bench lazy: {n} files of 4-7 KiB, {rtt} ms to answer a request");

    for window in [0usize, 8, 64] {
        let s = swarm_full(&[&layer], &[ZSTD], None, policy, Duration::from_millis(rtt)).await;
        let b = lazy_b(&s, &layer, window).await;
        let t = std::time::Instant::now();
        let mut times = read_in_order(&b, &layer_digest, &d, None).await;
        eprintln!(
            "bench window {window:>2} files: {:6.2} s for {n} reads, p50 {:6.1} ms, p99 {:6.1} ms, {} requests to the peer",
            t.elapsed().as_secs_f64(),
            percentile(&mut times, 50),
            percentile(&mut times, 99),
            s.requests.lock().unwrap().len()
        );
    }

    // the files of a startup profile, taken in groups of 64, then the reads
    let s = swarm_full(&[&layer], &[ZSTD], None, policy, Duration::from_millis(rtt)).await;
    let b = lazy_b(&s, &layer, 0).await;
    let t = std::time::Instant::now();
    let fetcher = &b.service;
    for group in d.chunks(64) {
        fetcher
            .stage_lazy(
                &layer_digest,
                group.to_vec(),
                velarx_content::fetcher::fetch::Urgency::Background,
            )
            .await
            .unwrap();
    }
    let fetched = t.elapsed();
    let times = read_in_order(&b, &layer_digest, &d, None).await;
    eprintln!(
        "bench profile: {:.2} s to fetch it ({} requests), then {n} reads in {:.1} ms",
        fetched.as_secs_f64(),
        s.requests.lock().unwrap().len(),
        times.iter().sum::<Duration>().as_secs_f64() * 1e3
    );

    // a peer that has nothing of the layer, beside the one that has
    for forget in [true, false] {
        let s = swarm_full(&[&layer], &[ZSTD], None, policy, Duration::from_millis(rtt)).await;
        let empty = add_peer(&s, Arc::new(Nothing), Duration::from_millis(rtt)).await;
        let b = lazy_b(&s, &layer, 0).await;
        let mut times = read_in_order(
            &b,
            &layer_digest,
            &d[..100.min(n)],
            forget.then_some(&*s.source),
        )
        .await;
        let asked = s.requests.lock().unwrap().clone();
        eprintln!(
            "bench empty peer, {}: mean {:6.1} ms, p99 {:6.1} ms, the empty peer asked {} times of {} requests",
            if forget { "knowledge forgotten each time" } else { "knowledge kept" },
            times.iter().sum::<Duration>().as_secs_f64() * 1e3 / times.len() as f64,
            percentile(&mut times, 99),
            asked.iter().filter(|p| **p == empty.peer_id()).count(),
            asked.len()
        );
    }

    // a slow peer beside a quick one
    for (name, policy) in [
        (
            "hedging off",
            Policy {
                hedge: false,
                hedge_delay: None,
                ..Policy::default()
            },
        ),
        (
            "hedging on, 60 ms",
            Policy {
                hedge: true,
                hedge_delay: Some(Duration::from_millis(60)),
                ..Policy::default()
            },
        ),
        (
            "hedging on, adaptive",
            Policy {
                hedge: true,
                hedge_delay: None,
                ..Policy::default()
            },
        ),
    ] {
        for forget in [true, false] {
            let s = swarm_full(&[&layer], &[ZSTD], None, policy, Duration::from_millis(400)).await;
            let _quick = add_peer(
                &s,
                Arc::new(StoreContent::new(s.store.clone())),
                Duration::from_millis(rtt),
            )
            .await;
            let b = lazy_b(&s, &layer, 0).await;
            let mut times = read_in_order(
                &b,
                &layer_digest,
                &d[..60.min(n)],
                forget.then_some(&*s.source),
            )
            .await;
            eprintln!(
                "bench slow (400 ms) + quick ({rtt} ms) peer, {name}, {}: mean {:6.1} ms, p50 {:6.1} ms, p99 {:6.1} ms",
                if forget { "order unknown" } else { "learning" },
                times.iter().sum::<Duration>().as_secs_f64() * 1e3 / times.len() as f64,
                percentile(&mut times, 50),
                percentile(&mut times, 99),
            );
        }
    }
}

/// A peer that has these items.
struct Items(std::collections::HashMap<String, Vec<u8>>);

impl ChunkProvider for Items {
    fn get_chunk(&self, digest: &str) -> std::io::Result<Option<Vec<u8>>> {
        Ok(self.0.get(digest).cloned())
    }
}

/// Two nodes give each other the content of a layer of SHA-512 digests: a
/// chunk by its sha512 and a file by its SHA-512 fs-verity digest, over QUIC
/// (`velarx-chunks/5`); the SHA-256 name of the same bytes is another item the
/// peer has not got, and bytes that are not what their key names are not
/// given.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_sha512_chunks_and_files_go_from_a_peer() {
    use velarx_types::digest::{Algorithm, Digest};
    let dir = tempfile::tempdir().unwrap();
    let key = dir.path().join("swarm.key");
    velarx_p2p::control::generate_swarm_key(&key).unwrap();
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
    let data = b"a file of a layer of sha512 digests".to_vec();
    let chunk = Digest::of(Algorithm::Sha512, &data).to_string();
    let file = velarx_storage::fsverity_digest_of(Algorithm::Sha512, &data);
    let file256 = velarx_storage::fsverity_digest_of(Algorithm::Sha256, &data);
    let lie = velarx_storage::fsverity_digest_of(Algorithm::Sha512, b"what was asked for");
    let a = node(&key, [127, 0, 0, 1]).await;
    a.set_chunk_provider(Arc::new(Items(
        [
            (chunk.clone(), data.clone()),
            (file.clone(), data.clone()),
            (lie.clone(), b"something else".to_vec()),
        ]
        .into(),
    )))
    .unwrap();
    let b = node(&key, [127, 0, 0, 1]).await;
    connect(&b, &a).await;
    let peers = NodePeers(b.clone());
    let asked: Vec<(String, Option<u64>)> = [&chunk, &file, &file256, &lie]
        .into_iter()
        .map(|d| (d.clone(), None))
        .collect();
    let (out, mut chunks) = tokio::sync::mpsc::channel(velarx_p2p::CHUNKS_IN_FLIGHT);
    let (done, got) = futures::join!(
        peers.request(
            a.peer_id(),
            &asked,
            velarx_content::fetcher::fetch::Urgency::Wait,
            out,
        ),
        async move {
            let mut got = std::collections::HashMap::new();
            while let Some((digest, data)) = chunks.recv().await {
                got.insert(digest, data);
            }
            got
        }
    );
    done.unwrap();
    assert_eq!(got.get(&chunk), Some(&data));
    assert_eq!(got.get(&file), Some(&data));
    // (the other algorithm's name of the bytes, and a lie)
    assert!(
        !got.contains_key(&file256) && !got.contains_key(&lie),
        "{:?}",
        got.keys()
    );
    // the items came over QUIC, whose frames carry the kind and the
    // algorithm of each digest
    let found = super::support::fetch_from(&b, a.peer_id(), &asked[..2])
        .await
        .unwrap();
    assert_eq!(found.len(), 2);
}
