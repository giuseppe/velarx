// SPDX-License-Identifier: Apache-2.0
//! A deterministic simulator of the peer layer: hundreds of nodes in one
//! process, on a virtual clock and a network that is a table of delays.
//!
//! What is simulated is what a socket and a swarm do: the delay, the
//! capacity and the loss of the paths between the nodes, a node going down or
//! coming back, a node that answers busy, never, or wrongly.  What decides is
//! the code of the service, not a copy of it: the source of a pull
//! ([`crate::provider::PeerSource`], through [`crate::provider::Transport`]),
//! what it knows of the peers, the gossip tables, the admission of a request
//! (slots, the upload pacer), the
//! answers of `serve`, and the timers of the bootstrap.  Only the transports
//! are replaced (the DHT and the peers a Kademlia walk finds are models).
//!
//! A run is [`run`]: a seed, a world on a paused clock, and an async closure
//! that builds nodes and watches them.  The same seed gives the same run;
//! when the closure panics the seed and the end of the trace are printed.
//! At the end of every run the decision log of each node is checked for the
//! rules of asking the peers (`check`).

mod check;
mod content;
mod net;
mod node;
mod pull;
mod server;
mod transport;
mod world;

pub use content::{Image, Layer, MemStore};
pub use net::{Net, REGISTRY};
pub use node::{Behavior, Dir, Live, Node, NodeConfig};
pub use pull::{PullReport, Puller};
pub use transport::SimTransport;
pub use world::{peer_id, Dht, Registry, Trace, World};

use std::future::Future;
use std::sync::Arc;

/// Prints the seed and the last events of the run when the scenario fails.
struct Report(Arc<World>);

impl Drop for Report {
    fn drop(&mut self) {
        if std::thread::panicking() {
            eprintln!(
                "p2p simulator: the run failed; seed = {} (VELARX_SIM_SEED={} repeats it); \
                 the last events:",
                self.0.seed, self.0.seed
            );
            for line in self.0.trace.tail(60) {
                eprintln!("  {line}");
            }
        }
    }
}

/// Run `scenario` in a world made from `seed`, on a clock that is paused: time
/// passes when every task waits, as far as the next timer.
pub fn run<F, Fut, T>(seed: u64, scenario: F) -> T
where
    F: FnOnce(Arc<World>) -> Fut,
    Fut: Future<Output = T>,
{
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .start_paused(true)
        .build()
        .expect("a runtime");
    let world = runtime.block_on(async { World::new(seed) });
    let _report = Report(world.clone());
    let result = runtime.block_on(scenario(world.clone()));
    check::decisions(&world);
    result
}

/// The seeds a scenario runs with: `VELARX_SIM_SEED` (one, to repeat a failure),
/// else `default`.
pub fn seeds(default: &[u64]) -> Vec<u64> {
    match std::env::var("VELARX_SIM_SEED")
        .ok()
        .and_then(|s| s.parse().ok())
    {
        Some(seed) => vec![seed],
        None => default.to_vec(),
    }
}
