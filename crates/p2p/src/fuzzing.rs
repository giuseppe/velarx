// SPDX-License-Identifier: Apache-2.0
//! The parsers of what a peer sends, each behind a function of a byte slice,
//! for the fuzz targets of `fuzz/` and the replay of their corpora
//! (`crates/p2p/tests/p2p/fuzz_corpus_tests.rs`).  Like [`velarx::fuzzing`]: a function
//! never panics, and never allocates for what the input only claims.

use crate::{GossipDiscovery, GossipMessage};

/// The names of the targets, as `fuzz/fuzz_targets/NAME.rs` and the
/// directories of `fuzz/corpus/` name them.
pub const TARGETS: [&str; 2] = ["p2p_gossip", "p2p_quic_request"];

/// Run the target `name` on `data`; false for a name that is no target.
pub fn run(name: &str, data: &[u8]) -> bool {
    match name {
        "p2p_gossip" => gossip(data),
        "p2p_quic_request" => quic_request(data),
        _ => return false,
    }
    true
}

/// A gossip message of a peer, handled as it would be.
pub fn gossip(data: &[u8]) {
    if let Ok(msg) = serde_json::from_slice::<GossipMessage>(data) {
        let gossip = GossipDiscovery::announcing();
        futures::executor::block_on(gossip.handle_gossip_message(libp2p::PeerId::random(), msg));
    }
}

/// The head and the digests of a request a peer sends to the QUIC server,
/// read as the server reads them ([`crate::quic::parse_request`]).
pub fn quic_request(data: &[u8]) {
    let _ = crate::quic::parse_request(data);
}
