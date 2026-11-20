// SPDX-License-Identifier: Apache-2.0
//! What makes a peer a member of a node's tables: its connections.  A node
//! against a peer made of libp2p alone (the transport of the swarm and the
//! gossip protocol), whose connections the test opens, closes, and stops
//! answering on.

use super::support::{address, digest_of, key};
use futures::StreamExt;
use libp2p::core::transport::upgrade::Version;
use libp2p::request_response::{self, ProtocolSupport};
use libp2p::swarm::{behaviour::toggle::Toggle, ConnectionId, NetworkBehaviour, SwarmEvent};
use libp2p::{noise, ping, pnet, tcp, yamux, Multiaddr, PeerId, Swarm, Transport};
use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use velarx_p2p::{GossipCodec, GossipMessage, GossipReply, P2PConfig, P2PNode, GOSSIP_PROTOCOL};

/// A peer that speaks the gossip, and ping as it is asked to (no
/// identify, no DHT).
#[derive(NetworkBehaviour)]
#[behaviour(prelude = "libp2p::swarm::derive_prelude")]
struct Bare {
    gossip: request_response::Behaviour<GossipCodec>,
    ping: Toggle<ping::Behaviour>,
    mute: Toggle<request_response::Behaviour<Mute>>,
}

/// How a bare peer answers pings.
#[derive(Clone, Copy)]
enum Pings {
    /// as libp2p does
    Answered,
    /// it does not know the protocol
    Unknown,
    /// it takes the stream, and never answers on it
    Unanswered,
}

/// The ping protocol of a peer that takes the stream and is silent on it.
#[derive(Clone, Default)]
struct Mute;

impl request_response::Codec for Mute {
    type Protocol = libp2p::StreamProtocol;
    type Request = ();
    type Response = ();

    async fn read_request<T>(&mut self, _: &Self::Protocol, _: &mut T) -> std::io::Result<()>
    where
        T: futures::AsyncRead + Unpin + Send,
    {
        futures::future::pending().await
    }

    async fn read_response<T>(&mut self, _: &Self::Protocol, _: &mut T) -> std::io::Result<()>
    where
        T: futures::AsyncRead + Unpin + Send,
    {
        futures::future::pending().await
    }

    async fn write_request<T>(
        &mut self,
        _: &Self::Protocol,
        _: &mut T,
        _: (),
    ) -> std::io::Result<()>
    where
        T: futures::AsyncWrite + Unpin + Send,
    {
        Ok(())
    }

    async fn write_response<T>(
        &mut self,
        _: &Self::Protocol,
        _: &mut T,
        _: (),
    ) -> std::io::Result<()>
    where
        T: futures::AsyncWrite + Unpin + Send,
    {
        Ok(())
    }
}

fn bare(key: &Path, pings: Pings) -> Swarm<Bare> {
    let psk = pnet::PreSharedKey::from_str(&std::fs::read_to_string(key).unwrap()).unwrap();
    libp2p::SwarmBuilder::with_new_identity()
        .with_tokio()
        .with_other_transport(
            move |key| -> Result<_, Box<dyn std::error::Error + Send + Sync>> {
                Ok(tcp::tokio::Transport::new(tcp::Config::default())
                    .and_then(move |socket, _| pnet::PnetConfig::new(psk).handshake(socket))
                    .upgrade(Version::V1Lazy)
                    .authenticate(noise::Config::new(key)?)
                    .multiplex(yamux::Config::default()))
            },
        )
        .unwrap()
        .with_behaviour(|_| Bare {
            gossip: request_response::Behaviour::new(
                [(GOSSIP_PROTOCOL, ProtocolSupport::Full)],
                request_response::Config::default(),
            ),
            ping: Toggle::from(
                matches!(pings, Pings::Answered).then(|| ping::Behaviour::new(ping::Config::new())),
            ),
            mute: Toggle::from(matches!(pings, Pings::Unanswered).then(|| {
                request_response::Behaviour::new(
                    [(ping::PROTOCOL_NAME, ProtocolSupport::Inbound)],
                    request_response::Config::default()
                        .with_request_timeout(Duration::from_secs(3600)),
                )
            })),
        })
        .unwrap()
        .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(3600)))
        .build()
}

async fn node(key: &Path) -> Arc<P2PNode> {
    Arc::new(
        P2PNode::with_config(P2PConfig {
            dial: velarx_p2p::dial_filter::Rules::on_one_host(),
            listen_addrs: vec!["/ip4/127.0.0.1/tcp/0".into()],
            enable_mdns: false,
            announce_images: true,
            private_key_path: Some(key.to_path_buf()),
            ..Default::default()
        })
        .await
        .unwrap(),
    )
}

/// Until `holds` holds of the node, at most 10 s.  (Polled: the addresses a
/// peer is reached at change with each of its connections, and the status
/// tells only when the first comes and the last goes.)
async fn until<F, Fut>(what: &str, holds: F)
where
    F: Fn() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    for _ in 0..200 {
        if holds().await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("{what}");
}

/// Until the status of `node` is one `holds` holds of, at most 10 s: the
/// node tells each change of it.
async fn until_status(
    node: &P2PNode,
    what: &str,
    holds: impl FnMut(&velarx_p2p::P2PStatus) -> bool,
) {
    let mut status = node.status_updates();
    tokio::time::timeout(Duration::from_secs(10), status.wait_for(holds))
        .await
        .unwrap_or_else(|_| panic!("{what}"))
        .unwrap();
}

/// What the bare peer sees, as it answers the gossip it is sent.
#[derive(Debug)]
enum Seen {
    Connected(ConnectionId),
    Closed(ConnectionId),
    Told(GossipMessage),
}

async fn next(swarm: &mut Swarm<Bare>) -> Seen {
    loop {
        match swarm.select_next_some().await {
            SwarmEvent::ConnectionEstablished { connection_id, .. } => {
                return Seen::Connected(connection_id)
            }
            SwarmEvent::ConnectionClosed { connection_id, .. } => {
                return Seen::Closed(connection_id)
            }
            SwarmEvent::Behaviour(BareEvent::Gossip(request_response::Event::Message {
                message:
                    request_response::Message::Request {
                        request, channel, ..
                    },
                ..
            })) => {
                let _ = swarm
                    .behaviour_mut()
                    .gossip
                    .send_response(channel, GossipReply::default());
                return Seen::Told(request);
            }
            _ => {}
        }
    }
}

/// Whether the filter a node told says it may hold `layer`.
fn holds(filter: &velarx_p2p::filter::FilterFull, layer: &str) -> bool {
    let now = tokio::time::Instant::now();
    let mut told = velarx_p2p::filter::Received::new(now);
    told.full(filter, now).unwrap();
    told.says(velarx_p2p::filter::key_of(layer), now) == velarx_p2p::filter::Said::Maybe
}

/// The bare peer's next connection, and the filter of the layers the node
/// tells it.
async fn connect(
    swarm: &mut Swarm<Bare>,
    addr: &Multiaddr,
) -> (ConnectionId, velarx_p2p::filter::FilterFull) {
    swarm.dial(addr.clone()).unwrap();
    let mut connection = None;
    loop {
        match tokio::time::timeout(Duration::from_secs(10), next(swarm))
            .await
            .expect("no connection, or no layers told")
        {
            Seen::Connected(id) => connection = Some(id),
            Seen::Told(GossipMessage::LayerFilter(filter)) => {
                if let Some(id) = connection {
                    return (id, filter);
                }
            }
            other => panic!("{other:?}"),
        }
    }
}

async fn members(node: &P2PNode, peer: &PeerId, layer: &str) -> (bool, usize, bool) {
    (
        node.is_connected_to(peer).await,
        node.status().connected.len(),
        node.knowledge().filtered(layer).maybe.contains(peer),
    )
}

/// A peer is a member of the tables (connected, counted once, its layers)
/// while it has a connection, whatever the number; it leaves them with its
/// last one, and a peer that comes back is told the node's layers again.
#[tokio::test]
async fn a_peer_is_a_member_until_its_last_connection_goes() {
    let dir = tempfile::tempdir().unwrap();
    let key = key(dir.path(), "swarm.key");
    let a = node(&key).await;
    let ours = digest_of(b"a layer of the node");
    a.announce_layers(vec![ours.clone()]).await.unwrap();
    let addr = address(&a).await;
    let mut b = bare(&key, Pings::Answered);
    let peer = *b.local_peer_id();

    // two connections to the same node; the layers are told on the first
    let (first, told) = connect(&mut b, &addr).await;
    assert!(holds(&told, &ours));
    b.dial(addr.clone()).unwrap();
    let second = loop {
        if let Seen::Connected(id) = next(&mut b).await {
            break id;
        }
    };
    let theirs = digest_of(b"a layer of the peer");
    let mut ours_to_tell = velarx_p2p::filter::Advertiser::new(
        Default::default(),
        velarx_p2p::entropy::Entropy::seeded(3),
    );
    ours_to_tell.add(std::slice::from_ref(&theirs));
    b.behaviour_mut()
        .gossip
        .send_request(&a.peer_id(), ours_to_tell.full().unwrap());
    // (the answer to the announcement: the node took it)
    let answered = async {
        loop {
            if let SwarmEvent::Behaviour(BareEvent::Gossip(request_response::Event::Message {
                message: request_response::Message::Response { .. },
                ..
            })) = b.select_next_some().await
            {
                return;
            }
        }
    };
    tokio::time::timeout(Duration::from_secs(10), answered)
        .await
        .expect("the node did not take the announcement");
    until(
        "the node does not count the peer's two connections",
        || async {
            a.peers()
                .await
                .iter()
                .any(|p| p.peer_id == peer && p.addresses.len() == 2)
        },
    )
    .await;
    assert_eq!(
        members(&a, &peer, &theirs).await,
        (true, 1, true),
        "two connections are one peer"
    );

    // one goes: the peer stays what it was
    b.close_connection(first);
    loop {
        if let Seen::Closed(id) = next(&mut b).await {
            assert_eq!(id, first);
            break;
        }
    }
    until("the node does not see the connection go", || async {
        a.peers()
            .await
            .iter()
            .any(|p| p.peer_id == peer && p.addresses.len() == 1)
    })
    .await;
    assert_eq!(members(&a, &peer, &theirs).await, (true, 1, true));

    // the last goes: the peer is gone from the tables
    b.close_connection(second);
    loop {
        if let Seen::Closed(id) = next(&mut b).await {
            assert_eq!(id, second);
            break;
        }
    }
    until_status(&a, "the peer is still a member", |s| {
        !s.connected.contains(&peer)
    })
    .await;
    assert_eq!(members(&a, &peer, &theirs).await, (false, 0, false));

    // it comes back: told the layers again, a member again
    let (_, told) = connect(&mut b, &addr).await;
    assert!(holds(&told, &ours));
    until_status(&a, "the peer that came back is not a member", |s| {
        s.connected.contains(&peer)
    })
    .await;
    assert_eq!(a.status().connected.len(), 1);
}

/// A peer that does not answer the node's pings loses its connection (and
/// with it its place in the tables), however long the idle timeout: here
/// one that does not know the protocol.
#[tokio::test]
async fn a_peer_that_does_not_answer_its_pings_is_disconnected() {
    let dir = tempfile::tempdir().unwrap();
    let key = key(dir.path(), "swarm.key");
    let a = node(&key).await;
    let addr = address(&a).await;

    // a peer without ping, that answers what else it is sent
    let mut b = bare(&key, Pings::Unknown);
    let peer = *b.local_peer_id();
    b.dial(addr.clone()).unwrap();
    let connection = loop {
        if let Seen::Connected(id) = next(&mut b).await {
            break id;
        }
    };
    let closed = async {
        loop {
            if let Seen::Closed(id) = next(&mut b).await {
                return id;
            }
        }
    };
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(10), closed)
            .await
            .expect("the node keeps a peer that does not answer its pings"),
        connection
    );
    until_status(&a, "the peer is still a member", |s| {
        !s.connected.contains(&peer)
    })
    .await;
}

/// A peer that is connected and answers nothing on the ping's stream loses
/// its connection after two pings without an answer (libp2p does not tell
/// the first): a timeout, an interval and a timeout, 50 s.  A test that
/// waits: only with `VELARX_SLOW_TESTS`.
#[tokio::test]
async fn a_peer_that_is_silent_on_its_pings_is_disconnected() {
    if std::env::var_os("VELARX_SLOW_TESTS").is_none() {
        eprintln!("(waits 50 s: only with VELARX_SLOW_TESTS)");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let key = key(dir.path(), "swarm.key");
    let a = node(&key).await;
    let addr = address(&a).await;
    let mut silent = bare(&key, Pings::Unanswered);
    let peer = *silent.local_peer_id();
    silent.dial(addr.clone()).unwrap();
    let connection = loop {
        if let Seen::Connected(id) = next(&mut silent).await {
            break id;
        }
    };
    let started = std::time::Instant::now();
    let closed = async {
        loop {
            if let Seen::Closed(id) = next(&mut silent).await {
                return id;
            }
        }
    };
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(90), closed)
            .await
            .expect("the node keeps a peer that does not answer its pings"),
        connection
    );
    assert!(
        started.elapsed() >= Duration::from_secs(40),
        "closed after {:?}, not by the ping's timeout",
        started.elapsed()
    );
    until_status(&a, "the silent peer is still a member", |s| {
        !s.connected.contains(&peer)
    })
    .await;
}

/// A member that tells no QUIC endpoint (a peer made of libp2p alone, as one
/// behind a firewall that drops UDP is for a node that cannot reach it) is
/// connected, is told the layers and takes part in the discovery, and is not
/// asked for data: each ask is a typed error that names it and why, and the
/// status counts it.  Data has no other way.
#[tokio::test]
async fn a_member_with_no_quic_path_is_not_asked_for_data() {
    use velarx_p2p::provider::{NodePeers, PeerError, Peers};
    use velarx_p2p::P2PError;
    let dir = tempfile::tempdir().unwrap();
    let key = key(dir.path(), "swarm.key");
    let a = node(&key).await;
    // (what it tells a new member: the connection is complete when it has)
    a.announce_layers(vec![digest_of(b"a layer")])
        .await
        .unwrap();
    let mut b = bare(&key, Pings::Answered);
    let peer = *b.local_peer_id();
    let (_, told) = connect(&mut b, &address(&a).await).await;
    assert!(
        holds(&told, &digest_of(b"a layer")),
        "a member with no data path still takes part"
    );
    assert!(a.is_connected_to(&peer).await);
    assert_eq!(a.without_quic().await, 1);
    let why = a.no_quic_path(peer).await.expect("no path");
    assert!(why.contains("advertises no QUIC"), "{why}");

    let digest = digest_of(b"a chunk");
    match super::support::fetch_from(&a, peer, &[(digest.clone(), None)]).await {
        Err(P2PError::NoQuicPath {
            peer: named,
            reason,
        }) => {
            assert_eq!(named, peer);
            assert_eq!(reason, why);
        }
        other => panic!("{other:?}"),
    }
    assert!(matches!(
        a.probe(peer, &digest).await,
        Err(P2PError::NoQuicPath { .. })
    ));
    assert!(matches!(
        a.request_index(peer, &digest, 1 << 20).await,
        Err(P2PError::NoQuicPath { .. })
    ));
    assert!(matches!(
        a.request_profile(peer, &digest, 1 << 20).await,
        Err(P2PError::NoQuicPath { .. })
    ));
    // (a pull is told the same, to go on to the next peer)
    let peers = NodePeers(a.clone());
    let (out, _chunks) = tokio::sync::mpsc::channel(1);
    assert!(matches!(
        peers.request(peer, &[(digest, None)], out).await,
        Err(PeerError::NoQuic(_))
    ));
    assert_eq!(peers.without_quic().await, 1);
}

/// An update of the filter that a peer did not take (here the bare peer
/// drops the question without an answer, while it stays connected) is
/// followed by the whole filter at once: a lost delta would otherwise leave
/// the layers it carried out of the peer's filter, which would say "no" for
/// them until the next refresh (minutes).
#[tokio::test]
async fn an_update_a_peer_did_not_take_is_followed_by_the_whole_filter() {
    let dir = tempfile::tempdir().unwrap();
    let key = key(dir.path(), "swarm.key");
    let a = node(&key).await;
    a.announce_layers(vec![digest_of(b"a layer")])
        .await
        .unwrap();
    let mut b = bare(&key, Pings::Answered);
    let (_, told) = connect(&mut b, &address(&a).await).await;
    assert!(holds(&told, &digest_of(b"a layer")));
    let new = digest_of(b"another layer");
    a.announce_layers(vec![new.clone()]).await.unwrap();
    // (every delta is dropped unanswered; the whole filter that follows is
    // answered, and the one that holds the new layer ends the wait)
    let (mut dropped, mut wholes) = (0, 0);
    let told = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            if let SwarmEvent::Behaviour(BareEvent::Gossip(request_response::Event::Message {
                message:
                    request_response::Message::Request {
                        request, channel, ..
                    },
                ..
            })) = b.select_next_some().await
            {
                match request {
                    GossipMessage::LayerFilterDelta(_) => {
                        dropped += 1;
                        drop(channel);
                    }
                    GossipMessage::LayerFilter(filter) => {
                        wholes += 1;
                        let _ = b
                            .behaviour_mut()
                            .gossip
                            .send_response(channel, GossipReply::default());
                        if holds(&filter, &new) {
                            return filter;
                        }
                    }
                    _ => {
                        let _ = b
                            .behaviour_mut()
                            .gossip
                            .send_response(channel, GossipReply::default());
                    }
                }
            }
        }
    })
    .await
    .expect("the update that was not taken was not followed by the whole filter");
    assert!(dropped >= 1 && wholes >= 1, "{dropped} {wholes}");
    assert!(holds(&told, &digest_of(b"a layer")));
    assert!(a.is_connected_to(b.local_peer_id()).await);
}
