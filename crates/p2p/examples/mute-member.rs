// SPDX-License-Identifier: Apache-2.0
//! A member of a swarm whose store is stuck: it joins, answers the
//! handshakes, and never answers a request for data (the rig scenario
//! `mute-member` of tests/p2p-rig uses it).
//!
//!     cargo run -p velarx-p2p --example mute-member -- SWARM_KEY LISTEN_IP

use std::sync::Arc;
use std::time::Duration;
use velarx_p2p::{ChunkProvider, P2PConfig, P2PNode};

struct Stuck;

impl ChunkProvider for Stuck {
    fn get_chunk(&self, _: &str) -> std::io::Result<Option<Vec<u8>>> {
        std::thread::sleep(Duration::from_secs(3600));
        Ok(None)
    }
    fn get_index(&self, _: &str) -> std::io::Result<Option<Vec<u8>>> {
        std::thread::sleep(Duration::from_secs(3600));
        Ok(None)
    }
}

#[tokio::main]
async fn main() {
    let mut args = std::env::args().skip(1);
    let (key, ip) = (
        args.next().expect("SWARM_KEY"),
        args.next().expect("LISTEN_IP"),
    );
    let node = P2PNode::with_config(P2PConfig {
        listen_addrs: vec![format!("/ip4/{ip}/tcp/4001")],
        enable_mdns: false,
        private_key_path: Some(key.into()),
        quic_port: Some(4001),
        ..Default::default()
    })
    .await
    .expect("a node");
    node.set_chunk_provider(Arc::new(Stuck))
        .expect("a provider");
    println!("mute member {}", node.peer_id());
    std::future::pending::<()>().await;
}
