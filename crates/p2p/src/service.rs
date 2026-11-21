// SPDX-License-Identifier: Apache-2.0
//! The service (`velarx-p2p`): the only process that talks to peers.
//!
//! One service runs per server.  It holds the node identity, the peer
//! connections and the DHT, and serves the content of the local stores to
//! peers that ask for a digest, even when no container runs, with no daemon;
//! it tells the peers the layers it holds as a filter, and its images and
//! the DHT its layers only with `announce_images`: the
//! content and what may be announced come from the store service
//! (`velarx_core::store_service`).  It is a fetcher (`org.velarx.Fetcher`, on
//! its own socket) for the pulls.  Its commands (`velarx-p2p status`, ...)
//! talk to it on its control socket (`org.velarx.P2p`, [`crate::control`]).
//! The overlay network of the containers is another process
//! ([`crate::overlay_service`]).

use super::provider::{PeerSource, Policy};
use super::staged::{Given, Staged};
use super::store::{follow_store_on_thread, StoreContent};
use super::{P2PConfig as NodeConfig, P2PNode};
use crate::control::{
    Advertised, Belief, BeliefListed, Certificate, Decision, DecisionListed, DialsRefused,
    ImageListed, Lookups, P2pError, Peer, PeerFilter, PeerListed, PeerTraffic, RemoteImage,
    Serving, Slots, Stats, Status, Step, PROTO,
};
use crate::settings::Settings;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tracing::{info, warn};
use velarx_config::Config;
use velarx_core::store_service::Announcement;
use velarx_core::store_service::ImageInfo;
use velarx_proto::info::Info;

/// What the handlers share
struct Service {
    node: Arc<P2PNode>,
    /// What the pulls of this node fetched from each peer
    knowledge: Arc<super::knowledge::Knowledge>,
    /// The recent decisions of the pulls
    decisions: Arc<super::explain::Decisions>,
    /// The store service: the images whose layers an `Explain` names
    store_socket: PathBuf,
}

/// What the pulls of this node fetched from each peer.
fn peer_traffic(knowledge: &super::knowledge::Knowledge) -> Vec<PeerTraffic> {
    let ms = |d: Duration| (d.as_secs_f64() * 1e4).round() / 10.0;
    knowledge
        .traffic()
        .into_iter()
        .map(|(peer, t)| PeerTraffic {
            peer_id: peer.to_string(),
            requests: t.requests,
            failures: t.failures,
            chunks_received: t.chunks,
            bytes_received: t.bytes,
            average_ms: t.average().map(ms),
            rtt_ms: knowledge.rtt(&peer).map(ms),
            busy: t.busy,
        })
        .collect()
}

/// A record of the ring as the interface tells it.
fn decision(r: super::explain::Record) -> Decision {
    use super::explain::{Event, Outcome};
    let ms = |d: Duration| (d.as_secs_f64() * 1e4).round() / 10.0;
    let mut steps = Vec::new();
    let mut sent = 0u64;
    let mut unsent: Option<(usize, &str)> = None;
    for event in &r.events {
        match event {
            Event::Candidates(peers) => steps.extend(peers.iter().map(|(p, why)| Step {
                what: "candidate".into(),
                peer_id: Some(p.to_string()),
                detail: why.name().into(),
                took_ms: None,
                chunks: None,
                bytes: None,
            })),
            Event::Filters { maybe, no, unknown } => steps.push(Step {
                what: "filters".into(),
                peer_id: None,
                detail: format!(
                    "{maybe} peers' filters say maybe, {no} say no (not asked, not probed), \
                     {unknown} have no filter that is believed"
                ),
                took_ms: None,
                chunks: None,
                bytes: None,
            }),
            Event::Probe { peer, answer } => steps.push(Step {
                what: "probe".into(),
                peer_id: Some(peer.to_string()),
                detail: (*answer).into(),
                took_ms: None,
                chunks: None,
                bytes: None,
            }),
            Event::Striped(peers) => steps.extend(peers.iter().map(|p| Step {
                what: "striped".into(),
                peer_id: Some(p.to_string()),
                detail: "the group is spread over it".into(),
                took_ms: None,
                chunks: None,
                bytes: None,
            })),
            Event::Asked {
                peer,
                outcome,
                took,
            } => {
                let (detail, chunks, bytes) = match outcome {
                    Outcome::Sent(n, b) => {
                        sent += n;
                        ("sent".to_string(), Some(*n), Some(*b))
                    }
                    Outcome::NoPath(e) => (format!("no QUIC (UDP) path: {e}"), None, None),
                    Outcome::Failed(e) => (format!("failed: {e}"), None, None),
                    other => (other.name().to_string(), None, None),
                };
                steps.push(Step {
                    what: "asked".into(),
                    peer_id: Some(peer.to_string()),
                    detail,
                    took_ms: Some(ms(*took)),
                    chunks,
                    bytes,
                });
            }
            Event::Slow { rate, best } => steps.push(Step {
                what: "slow".into(),
                peer_id: None,
                detail: format!(
                    "the peers give {} KiB/s, they gave {} KiB/s before",
                    rate >> 10,
                    best >> 10
                ),
                took_ms: None,
                chunks: None,
                bytes: None,
            }),
            Event::Unsent { items, reason } => {
                unsent = Some((*items, reason));
                steps.push(Step {
                    what: "unsent".into(),
                    peer_id: None,
                    detail: (*reason).into(),
                    took_ms: None,
                    chunks: Some(*items as u64),
                    bytes: None,
                });
            }
        }
    }
    let summary = match unsent {
        Some((n, why)) => format!("{n} of {} left to the next source: {why}", r.items),
        None => format!("the peers gave {sent} chunks of {}", r.items),
    };
    Decision {
        id: r.id,
        at: r.at,
        kind: r.kind.name().into(),
        layer: r.layer,
        first: r.first,
        items: r.items as u64,
        steps,
        dropped: r.dropped as u64,
        summary,
    }
}

/// Tell the peers what the store service says may be announced: the layers
/// go in the filter (and the DHT, for a node that announces its images), the
/// images are told only by a node that announces them.
pub(super) async fn announce_to_peers(node: &P2PNode, announcement: Announcement) {
    if !announcement.layers.is_empty() {
        match node.announce_layers(announcement.layers).await {
            Ok(count) => info!("Holding {} layers for the peers", count),
            Err(e) => warn!("Failed to announce layers: {}", e),
        }
    }
    if !announcement.images.is_empty() {
        node.announce_images(announcement.images).await;
    }
}

mod control {
    use super::*;

    /// The calls of `org.velarx.P2p`.
    #[derive(Clone)]
    pub(super) struct Control(pub(super) Arc<Service>);

    #[zlink::service(
        interface = "org.velarx.P2p",
        description = super::description,
        vendor = "org.velarx",
        product = "velarx",
        version = env!("CARGO_PKG_VERSION"),
        url = env!("CARGO_PKG_REPOSITORY"),
        types = [Certificate, Lookups, DialsRefused, PeerTraffic, Peer, PeerFilter, Slots, Belief, Step, Decision, RemoteImage, ImageInfo]
    )]
    impl Control {
        /// Who serves this interface and what it can do.  The first call of a
        /// connection; a client refuses a `proto` other than its own.
        async fn get_info(&self) -> Info {
            Info {
                name: "p2p".into(),
                version: env!("CARGO_PKG_VERSION").to_string(),
                proto: PROTO,
                ..Info::default()
            }
        }

        /// What the node is: its id, addresses, peers and the DHT.
        async fn status(&self) -> Status {
            let status = self.0.node.status();
            let served = self.0.node.get_stats().await;
            Status {
                peer_id: status.peer_id.to_string(),
                listen_addresses: status
                    .listen_addresses
                    .iter()
                    .map(|a| a.to_string())
                    .collect(),
                connected_peers: status.connected.len() as u64,
                connected_without_quic: self.0.node.without_quic().await as u64,
                provider_records: status.provider_records as u64,
                peers: peer_traffic(&self.0.knowledge),
                chunks_sent: served.chunks_sent,
                bytes_sent: served.bytes_sent,
                lookups: self.0.node.lookups().await,
                certificate: self.0.node.authority().map(|a| a.this_node().into()),
                admission_refused: self.0.node.authority().map_or(0, |a| a.refused()),
            }
        }

        /// The peers it is connected to, and what it moved with each, one
        /// a reply.
        #[zlink(more)]
        async fn peer_list(
            &self,
            more: bool,
        ) -> impl futures::Stream<Item = Result<zlink::Reply<PeerListed>, P2pError>> + Unpin
        {
            if !more {
                return list_replies(Err(expected_more("PeerList")), |peer| PeerListed { peer });
            }
            let svc = &self.0;
            let mut traffic: std::collections::HashMap<String, PeerTraffic> =
                peer_traffic(&svc.knowledge)
                    .into_iter()
                    .map(|t| (t.peer_id.clone(), t))
                    .collect();
            let mut filters = svc.knowledge.filter_infos();
            let mut peers = Vec::new();
            for p in svc.node.peers().await {
                let (has, lacks) = svc.knowledge.layers_of(&p.peer_id);
                peers.push(Peer {
                    peer_id: p.peer_id.to_string(),
                    addresses: p.addresses.iter().map(|a| a.to_string()).collect(),
                    no_quic_path: svc.node.no_quic_path(p.peer_id).await,
                    filter: filters.remove(&p.peer_id).map(|f| PeerFilter {
                        keys: f.keys as u64,
                        bytes: f.bytes as u64,
                        version: f.version,
                        estimated_fpr: f.estimated_fpr,
                        age_secs: f.age.as_secs(),
                        believed: f.believed,
                        behind: f.behind,
                        hits: f.hits,
                        false_positives: f.false_positives,
                        refused: f.refused,
                        last_refused: f.last_refused.map(|r| r.to_string()),
                    }),
                    believed_has: has as u64,
                    believed_lacks: lacks as u64,
                    certificate: svc
                        .node
                        .authority()
                        .and_then(|a| a.who(&p.peer_id))
                        .map(Into::into),
                    traffic: traffic.remove(&p.peer_id.to_string()),
                });
            }
            list_replies(Ok(peers), |peer| PeerListed { peer })
        }

        /// What the node tells the peers of the layers and images it has.
        async fn advertised(&self) -> Advertised {
            let own = self.0.node.advertised();
            Advertised {
                announcing: self.0.node.gossip().is_announcing(),
                filter: self.0.node.advertises(),
                layers: own.keys as u64,
                filter_bytes: own.bytes as u64,
                filter_hashes: own.hashes as u64,
                filter_version: own.version,
                estimated_fpr: own.estimated_fpr,
                fulls_sent: own.sent.fulls,
                deltas_sent: own.sent.deltas,
                bytes_sent: own.sent.bytes,
                images: self.0.node.gossip().images_told().await as u64,
                dht_records: self.0.node.status().provider_records as u64,
            }
        }

        /// What the node is serving and has admitted: the slots of its QUIC
        /// server and the upload credit.
        async fn serving(&self) -> Serving {
            let state = self.0.node.serving_state();
            let slots = |(used, total): (usize, usize)| Slots {
                used: used as u64,
                total: total as u64,
            };
            Serving {
                quic_slots: slots(state.quic_slots),
                upload_bytes_per_sec: state.admission.upload.bytes_per_sec,
                upload_waiting_callers: state.admission.upload.waiting_callers as u64,
                upload_waiting_requests: state.admission.upload.waiting_requests as u64,
            }
        }

        /// What the node believes of the layers and the peers: which peers
        /// have a layer (they served it lately) and which lack it (they did
        /// not when asked lately), one a reply; of `layer` only, when given.
        #[zlink(more)]
        async fn belief_list(
            &self,
            more: bool,
            layer: Option<String>,
        ) -> impl futures::Stream<Item = Result<zlink::Reply<BeliefListed>, P2pError>> + Unpin
        {
            let wrap = |belief| BeliefListed { belief };
            if !more {
                return list_replies(Err(expected_more("BeliefList")), wrap);
            }
            let beliefs = self
                .0
                .knowledge
                .beliefs(layer.as_deref())
                .into_iter()
                .map(|b| Belief {
                    layer: b.layer,
                    peer_id: b.peer.to_string(),
                    has: b.has,
                    age_secs: b.age.as_secs(),
                })
                .collect();
            list_replies(Ok(beliefs), wrap)
        }

        /// Why the pulls asked the peers they did: the recent decisions
        /// about `target` (a digest or the start of one, a layer, a chunk
        /// or an image id; the name of an image the store has), the last
        /// first, one a reply; all of them when `target` is empty.
        #[zlink(more)]
        async fn explain(
            &self,
            more: bool,
            target: String,
        ) -> impl futures::Stream<Item = Result<zlink::Reply<DecisionListed>, P2pError>> + Unpin
        {
            let wrap = |decision| DecisionListed { decision };
            if !more {
                return list_replies(Err(expected_more("Explain")), wrap);
            }
            let also = crate::store::layers_of_image(&self.0.store_socket, &target).await;
            let decisions = self
                .0
                .decisions
                .about(&target, &also)
                .into_iter()
                .map(decision)
                .collect();
            list_replies(Ok(decisions), wrap)
        }

        /// What the node moved, in all.
        async fn stats(&self) -> Stats {
            let stats = self.0.node.get_stats().await;
            Stats {
                chunks_sent: stats.chunks_sent,
                bytes_sent: stats.bytes_sent,
            }
        }

        /// The images of the other nodes, one a reply; with `query`, they
        /// are asked to refresh first, and answer within a moment
        /// (`Unavailable`: the node cannot ask them).
        #[zlink(more)]
        async fn image_list(
            &self,
            more: bool,
            query: bool,
        ) -> impl futures::Stream<Item = Result<zlink::Reply<ImageListed>, P2pError>> + Unpin
        {
            let wrap = |image| ImageListed { image };
            if !more {
                return list_replies(Err(expected_more("ImageList")), wrap);
            }
            if query {
                if let Err(e) = self.0.node.query_peer_images().await {
                    return list_replies(
                        Err(P2pError::Unavailable {
                            reason: e.to_string(),
                        }),
                        wrap,
                    );
                }
            }
            let images = self
                .0
                .node
                .get_remote_images()
                .await
                .into_iter()
                .map(|(peer, image)| RemoteImage {
                    peer_id: peer.to_string(),
                    image,
                })
                .collect();
            list_replies(Ok(images), wrap)
        }
    }

    /// The error of a list called without `more`.
    fn expected_more(method: &str) -> P2pError {
        P2pError::InvalidArgument {
            reason: format!("{method} answers one record a reply: call it with more"),
        }
    }

    /// The replies of a list: one record each, the last with `continues:
    /// false`; an empty list is one reply without a record.
    fn list_replies<R: Send + 'static, T: Send + 'static>(
        listed: Result<Vec<R>, P2pError>,
        wrap: fn(Option<R>) -> T,
    ) -> std::pin::Pin<Box<dyn futures::Stream<Item = Result<zlink::Reply<T>, P2pError>> + Send>>
    {
        use futures::stream;
        match listed {
            Err(e) => Box::pin(stream::once(std::future::ready(Err(e)))),
            Ok(list) if list.is_empty() => Box::pin(stream::once(std::future::ready(Ok(
                zlink::Reply::new(Some(wrap(None))).set_continues(Some(false)),
            )))),
            Ok(list) => {
                let last = list.len() - 1;
                Box::pin(stream::iter(list.into_iter().enumerate().map(
                    move |(i, record)| {
                        Ok(zlink::Reply::new(Some(wrap(Some(record))))
                            .set_continues(Some(i < last)))
                    },
                )))
            }
        }
    }

    /// The interface as the macro described it (the binary serves the file).
    #[cfg(test)]
    pub(super) fn description() -> String {
        format!("{}", __Control_INTERFACE_0)
    }
}
use control::Control;

/// The description of an interface of this service as zlink sends it: its
/// checked-in definition without the comment that opens the file.  The
/// service answers `GetInterfaceDescription` with it, not with a description
/// built from the descriptors of its types (the tests compare the two).
fn description(interface: &str) -> String {
    let file = match interface {
        "org.velarx.P2p" => include_str!("../interfaces/org.velarx.P2p.varlink"),
        other => unreachable!("{other} is not served here"),
    };
    let (_, text) = file.split_once("\n\n").expect("a comment, an empty line");
    text.strip_suffix('\n').unwrap_or(text).to_string()
}

/// The text of the interface definition
/// `crates/p2p/interfaces/org.velarx.P2p.varlink`.
#[cfg(test)]
pub fn control_definition() -> String {
    format!(
        "# SPDX-License-Identifier: Apache-2.0\n\
         #\n\
         # The interface org.velarx.P2p: the control socket of velarx-p2p (p2p.sock),\n\
         # for its commands (velarx-p2p status, peers, stats, images).  Generated from\n\
         # the Rust types (crates/p2p/src/control.rs and service.rs) by the test\n\
         # `service::tests::the_interface_files_are_current`:\n\
         # VELARX_WRITE_INTERFACES=1 cargo test -p velarx-p2p --lib service writes it.\n\
         # A client calls GetInfo on each connection and refuses a `proto` other than\n\
         # its own ({}).\n\
         # Who may call: a peer of the same user or root (SO_PEERCRED); any\n\
         # accepted peer may make every call.\n\
         \n{}\n",
        crate::control::PROTO,
        control::description()
    )
}

/// Serve the control interface from a thread of its own, on `listener`,
/// until the returned guard is dropped.
pub(crate) fn serve_control<S>(
    listener: std::os::unix::net::UnixListener,
    name: &'static str,
    limits: velarx_content::activation::Limits,
    control: S,
) -> std::io::Result<tokio::sync::oneshot::Sender<()>>
where
    S: zlink::Service<zlink::tokio::unix::Stream> + Clone + Send + 'static,
{
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    std::thread::Builder::new()
        .name(name.into())
        .spawn(move || {
            let served = || -> std::io::Result<()> {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()?;
                tokio::task::LocalSet::new().block_on(&runtime, async move {
                    listener.set_nonblocking(true)?;
                    let listener = tokio::net::UnixListener::from_std(listener)?;
                    tokio::select! {
                        _ = velarx_content::activation::serve_varlink(
                            listener, None, velarx_base::ipc::trusted_uid, limits, name, control,
                        ) => {}
                        // (the guard was dropped: the sender is gone)
                        _ = stopped => {}
                    }
                    Ok(())
                })
            };
            if let Err(e) = served() {
                warn!("{name}: {e}");
            }
        })?;
    Ok(stop)
}

/// The store service is reached through a process forked now (this one has
/// one thread): once confined, this process looks up no socket by name.
pub fn reach_store_by_connector(config: &Config) -> anyhow::Result<()> {
    let socket = velarx_core::store_service::socket_path(config);
    let connector = velarx_sys::connector::Connector::start(&socket)
        .map_err(|e| anyhow::anyhow!("cannot start the connector of the store service: {e}"))?;
    velarx_content::activation::connect_through(socket, connector);
    Ok(())
}

/// Start the store service the service reads the store from, if nothing
/// serves it (the daemon, systemd): before the service confines itself,
/// which starts no process.  It stays while the service is connected to it.
/// The process started, if one was, is the caller's to reap.
pub fn start_store_service(
    config: &Config,
    config_path: &std::path::Path,
) -> anyhow::Result<Option<std::process::Child>> {
    let exe = velarx_base::spawn::sibling("velarx");
    velarx_core::store_service::start_if_absent(
        config,
        config_path,
        &exe,
        Some(velarx_core::store_service::STARTED_IDLE),
    )
    .map_err(|e| anyhow::anyhow!("cannot start the store service ({}): {e}", exe.display()))
}

/// The sockets of the service, bound before it confines itself (the
/// confined service makes no socket by name and removes none: they are
/// removed when it is gone, `velarx_base::ipc::remove_when_gone`).
pub struct Sockets {
    control: std::os::unix::net::UnixListener,
    fetcher: std::os::unix::net::UnixListener,
    /// Their paths
    pub paths: Vec<PathBuf>,
}

/// Bind the sockets of the service.
pub fn bind_sockets(config: &Config, settings: &Settings) -> anyhow::Result<Sockets> {
    let mut paths = Vec::new();
    let mut bind = |socket: PathBuf| {
        let listener = velarx_base::ipc::bind_private(&socket)
            .map_err(|e| anyhow::anyhow!("cannot create the socket {}: {e}", socket.display()))?;
        paths.push(socket);
        anyhow::Ok(listener)
    };
    // The socket first: a service nobody can talk to is not worth starting.
    let control = bind(settings.control_socket(config))?;
    // And the socket on which the pulls ask for chunks
    let fetcher = bind(settings.fetcher_socket(config))?;
    Ok(Sockets {
        control,
        fetcher,
        paths,
    })
}

/// The node of the settings: its transports, its swarm and its limits.
pub(crate) async fn start_node(
    p2p: &Settings,
    role: super::Role,
    identity: libp2p::identity::Keypair,
    authority: Option<Arc<crate::authority::Authority>>,
) -> anyhow::Result<Arc<P2PNode>> {
    // The swarm key is required: the node refuses to start without one.
    let private_key = std::env::var("VELARX_P2P_SWARM_KEY")
        .ok()
        .filter(|k| !k.trim().is_empty());

    Ok(Arc::new(
        P2PNode::with_config(NodeConfig {
            role,
            listen_addrs: p2p.listen_addresses.clone(),
            bootstrap_peers: p2p.bootstrap_peers.clone(),
            dial: crate::dial_filter::Rules {
                allow: p2p.dial_allow.clone(),
            },
            enable_mdns: p2p.mdns,
            identity: Some(identity),
            authority,
            private_key,
            private_key_path: p2p.private_key_path.clone(),
            quic_port: p2p.quic_port,
            quic_streams: p2p.quic_streams,
            announce_images: p2p.announce_images,
            filter: crate::filter::Config {
                advertise: p2p.advertise_layers && role == super::Role::Content,
                fpr: p2p.filter_fpr,
                max_bytes: p2p.filter_max_kib << 10,
                interval: std::time::Duration::from_secs(p2p.filter_interval_secs),
            },
            max_incoming: p2p.max_incoming,
            max_outgoing: p2p.max_outgoing,
            idle_timeout: std::time::Duration::from_secs(p2p.idle_timeout_secs),
            min_peers: p2p.min_peers,
            bootstrap_backoff: (
                std::time::Duration::from_secs(1),
                std::time::Duration::from_secs(p2p.bootstrap_retry_max_secs.max(1)),
            ),
            serving: p2p.serving,
        })
        .await?,
    ))
}

/// A node that gives the files of `dir` to its peers (`serve --dir`): no
/// engine, no store service, no confinement; the swarm, the addresses and the
/// limits are the settings'.  Until `shutdown`.
pub async fn serve_dir(
    settings: Settings,
    dir: &std::path::Path,
    identity: libp2p::identity::Keypair,
    authority: Option<Arc<crate::authority::Authority>>,
) -> anyhow::Result<()> {
    let files = crate::directory::Directory::open(dir)
        .map_err(|e| anyhow::anyhow!("cannot read {}: {e}", dir.display()))?;
    let digests = files.digests();
    let node = start_node(&settings, super::Role::Content, identity, authority).await?;
    node.set_chunk_provider(Arc::new(files))?;
    info!(
        "P2P node {} serves the {} files of {}",
        node.peer_id(),
        digests.len(),
        dir.display()
    );
    tokio::signal::ctrl_c().await?;
    Ok(())
}

/// `run` with the sockets bound (`bind_sockets`) before the service
/// confined itself.
pub async fn run_with(
    config: Config,
    settings: Settings,
    sockets: Sockets,
    identity: libp2p::identity::Keypair,
    authority: Option<Arc<crate::authority::Authority>>,
) -> anyhow::Result<()> {
    let p2p = &settings;
    let limits = velarx_content::activation::Limits::of(&config.services);
    let Sockets {
        control: listener,
        fetcher: fetcher_listener,
        ..
    } = sockets;

    let node = start_node(p2p, super::Role::Content, identity, authority).await?;
    info!("P2P node {} started", node.peer_id());

    // The chunks of the store, for the peers, come from the store service
    let store_socket = velarx_core::store_service::socket_path(&config);
    let staged = Arc::new(Staged::default());
    node.set_chunk_provider(Arc::new(Given {
        store: Arc::new(StoreContent::new(store_socket.clone())),
        staged: staged.clone(),
    }))?;

    let (shutdown_tx, _) = tokio::sync::broadcast::channel::<()>(1);

    // What the store has and gets, told to the peers (the filter of the
    // layers, the images and the DHT): the store is not followed when
    // nothing is told
    let follower = if p2p.announce_images || p2p.advertise_layers {
        Some(follow_store_on_thread(
            Arc::clone(&node),
            store_socket.clone(),
            shutdown_tx.subscribe(),
        )?)
    } else {
        None
    };

    // The peers as a fetcher of the pulls
    let peer_source = Arc::new(
        PeerSource::new(Arc::clone(&node))
            .with_staged(staged)
            .with_policy(Policy {
                hedge: p2p.hedge,
                hedge_delay: (p2p.hedge_ms > 0).then(|| Duration::from_millis(p2p.hedge_ms)),
                stripe_peers: p2p.stripe_peers,
                query_peers: p2p.query_peers,
            }),
    );
    let knowledge = peer_source.knowledge().clone();
    let decisions = peer_source.decisions().clone();
    let _fetcher =
        velarx_content::serve_fetch::serve_in_thread(fetcher_listener, peer_source, limits)?;

    let svc = Arc::new(Service {
        node: Arc::clone(&node),
        knowledge,
        decisions,
        store_socket,
    });
    let _control = serve_control(listener, "p2p-control", limits, Control(svc))?;

    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = sigterm.recv() => {}
    }
    info!("P2P service shutting down");
    let _ = shutdown_tx.send(());
    if let Some(follower) = follower {
        let _ = tokio::task::spawn_blocking(move || follower.join()).await;
    }
    let _ = node.shutdown().await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The text a service sends for `GetInterfaceDescription` (the file,
    /// embedded) is what the descriptors of the types and methods say.
    #[test]
    fn the_descriptions_served_are_what_the_types_say() {
        assert_eq!(description("org.velarx.P2p"), control::description());
    }

    /// The files are made from the types: when they change they change.
    /// `VELARX_WRITE_INTERFACES=1` writes them.
    #[test]
    fn the_interface_files_are_current() {
        for (name, text) in [
            (
                "crates/p2p/interfaces/org.velarx.P2p.varlink",
                control_definition(),
            ),
            (
                "interfaces/org.velarx.Network.varlink",
                crate::overlay_service::network_definition(),
            ),
        ] {
            velarx_base::testing::assert_interface_file(name, &text);
            // (every type a field names is declared in the file)
            let declared: std::collections::HashSet<&str> = text
                .lines()
                .filter_map(|l| l.strip_prefix("type ")?.split([' ', '(']).next())
                .collect();
            for line in text.lines().filter(|l| !l.trim_start().starts_with('#')) {
                for word in line.split(|c: char| !c.is_alphanumeric() && c != '_') {
                    if word.starts_with(|c: char| c.is_ascii_uppercase())
                        && line.contains(&format!(": {word}"))
                            | line.contains(&format!("?{word}"))
                            | line.contains(&format!("[]{word}"))
                    {
                        assert!(declared.contains(word), "{name}: {word} is not declared");
                    }
                }
            }
        }
    }
    use libp2p::PeerId;

    /// A reply carries what the node knows: nothing in it is a constant or a
    /// counter nobody counts (the DHT mode, the size of a routing table that
    /// is not read, the bytes and chunks a peer is never counted to have
    /// sent, the files and the DHT requests).
    #[test]
    fn no_reply_carries_a_value_the_node_does_not_have() {
        let text = control::description();
        for name in [
            "dht_mode",
            "routing_table_size",
            "files_announced",
            "files_found",
            "dht_requests",
            "peer_discoveries",
        ] {
            assert!(!text.contains(name), "{name} is in the interface");
        }
        let stats = serde_json::to_value(Stats {
            chunks_sent: 1,
            bytes_sent: 10,
        })
        .unwrap();
        assert_eq!(stats.as_object().unwrap().len(), 2);
        let peer = serde_json::to_value(Peer {
            peer_id: String::new(),
            addresses: Vec::new(),
            no_quic_path: None,
            filter: None,
            believed_has: 0,
            believed_lacks: 0,
            certificate: None,
            traffic: None,
        })
        .unwrap();
        assert!(peer.get("bytes_received").is_none() && peer.get("chunks_received").is_none());
    }

    #[test]
    fn a_decision_is_told_with_its_steps_and_a_summary() {
        use crate::explain::{Decisions, Event, Kind, Outcome, Why};
        let (a, b) = (PeerId::random(), PeerId::random());
        let d = Decisions::default();
        let log = d.start(Kind::Chunks, Some("sha256:l"), "sha256:c", 5);
        log.add(Event::Candidates(vec![
            (a, Why::Filter),
            (b, Why::Connected),
        ]));
        log.add(Event::Asked {
            peer: a,
            outcome: Outcome::Sent(3, 300),
            took: Duration::from_millis(7),
        });
        log.add(Event::Asked {
            peer: b,
            outcome: Outcome::Busy,
            took: Duration::from_millis(1),
        });
        log.add(Event::Unsent {
            items: 2,
            reason: "every peer asked had no room",
        });
        let told = decision(d.about("", &[]).remove(0));
        let kinds: Vec<&str> = told.steps.iter().map(|s| s.what.as_str()).collect();
        assert_eq!(
            kinds,
            ["candidate", "candidate", "asked", "asked", "unsent"]
        );
        assert_eq!(told.steps[0].detail, "filter-said-maybe");
        assert_eq!(
            (told.steps[2].chunks, told.steps[2].bytes),
            (Some(3), Some(300))
        );
        assert_eq!(told.steps[3].detail, "busy");
        assert_eq!(
            told.summary,
            "2 of 5 left to the next source: every peer asked had no room"
        );
        assert_eq!(
            (told.kind.as_str(), told.items, told.layer.as_deref()),
            ("chunks", 5, Some("sha256:l"))
        );
    }

    #[test]
    fn the_status_tells_what_each_peer_sent() {
        let k = super::super::knowledge::Knowledge::default();
        let a = PeerId::random();
        k.count(a, Duration::from_millis(12), Some((3, 300)));
        k.count(a, Duration::from_secs(9), None);
        let peers = peer_traffic(&k);
        assert_eq!(
            peers,
            [PeerTraffic {
                peer_id: a.to_string(),
                requests: 2,
                failures: 1,
                chunks_received: 3,
                bytes_received: 300,
                average_ms: Some(12.0),
                rtt_ms: None,
                busy: 0,
            }]
        );
    }
}
