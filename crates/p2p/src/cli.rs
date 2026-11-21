// SPDX-License-Identifier: Apache-2.0
//! The command line of `velarx-p2p`: the settings of the service (no
//! command) or one of its commands.  It lives in the library so that the
//! man pages (examples/generate-man-p2p.rs of this package, `make man`) are
//! written from the same definition the binary parses.

use clap::{Parser, Subcommand};
use std::path::PathBuf;

/// What `--version` says: the version of the workspace and the commit of the
/// build, which the binary hands to the libraries at its start
/// (`velarx_base::buildinfo::set`).
fn version() -> &'static str {
    static VERSION: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    VERSION.get_or_init(|| {
        format!(
            "{} ({})",
            env!("CARGO_PKG_VERSION"),
            velarx_base::buildinfo::commit()
        )
    })
}

#[derive(Parser)]
#[command(
    name = "velarx-p2p",
    version = version(),
    about = "The velarx P2P service",
    after_long_help = "NETWORK\n\
        libp2p (TCP) keeps the members together; all the data (chunks, files, layer \
        indexes, startup profiles) goes over QUIC (UDP) and over nothing else.  The UDP \
        port must be reachable between the nodes: by default it is the port of the first \
        TCP address of listen_addresses (4001; quic_port sets another).  A peer that \
        cannot be reached over UDP stays a member and is not asked for data; `status` \
        counts such peers and `peers` says why.\n\n\
        ADMISSION\n\
        A swarm is joined with its key (`generate-key`; every holder is a full member) or \
        with a certificate of the swarm's authority (`ca`): each node has one, for the key \
        of its identity file, with a name, a zone and a role (both, serve or pull), signed \
        by the operator, who keeps the key of the authority off the nodes.  The QUIC \
        handshake and the libp2p connection check it (the chain, its time, the revocation \
        list, the allow-list), with no fallback to the key.  `ca init DIR` makes the \
        authority; `ca request` on a node and `ca sign` on the operator's machine make \
        its certificate (sign again before it ends); `ca revoke` revokes a node by peer \
        id.  ca_path, certificate_path, revocation_path, allow_names, allow_peers and \
        ca_sweep_secs of its settings tell the service where they are; see \
        docs/THREAT-MODEL.md."
)]
pub struct Args {
    /// Path to the config file
    #[arg(long, default_value_os_t = velarx::cli::default_config())]
    pub config: PathBuf,

    /// The name of the source the service is in `[[sources.external]]` of
    /// the config file: its `settings` are the settings of the service
    #[arg(long, default_value = "p2p")]
    pub source: String,

    #[arg(long, default_value = "info")]
    pub log_level: String,

    #[arg(long, default_value = "text")]
    pub log_format: String,

    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Subcommand)]
pub enum Command {
    /// Write a new swarm key (the P2P network is private: every node needs
    /// the same key, readable by its owner only)
    GenerateKey {
        /// Where to write it; an existing file is not replaced
        path: PathBuf,
    },
    /// The certificate authority of a swarm: certificates for the nodes
    /// instead of one shared key (it works on files, and needs no service)
    Ca {
        #[command(subcommand)]
        command: CaCommand,
    },
    /// Serve the files of a directory to the peers, with no engine and no
    /// store service (to try a swarm, or to be a seed of plain files): each
    /// regular file under it is a chunk, asked for by the sha256 of its
    /// bytes.  The addresses, the swarm and the limits are the settings'; the
    /// process is not confined (it needs no Landlock ABI 9 kernel)
    Serve {
        /// The directory
        #[arg(long)]
        dir: PathBuf,
    },
    /// Run the overlay network of the containers: a node of a swarm of its
    /// own (its own identity, port and DHT, with the swarm key or authority
    /// of this one), the network provider (`org.velarx.Network`) the engine
    /// names, and the privileged helper that makes the veths.  It takes no
    /// part in the content: no chunks, no layers, no DHT records
    Overlay,
    /// Show the node: its peer id, addresses and what each peer sent
    Status,
    /// List the connected peers, with the filter each told of its layers
    /// (its size, age, and the questions it was right and wrong about)
    Peers,
    /// Show the bytes and chunks the node moved
    Stats,
    /// List the images of the other nodes (they are asked to refresh first)
    Images,
    /// Show what the node tells its peers of the layers it holds: the
    /// filter (its layers, bytes, version and false-positive rate) and what
    /// it sent
    Advertised,
    /// Show what the node is serving: the slots and who waits for the
    /// upload credit
    Serving,
    /// Show which peers the node believes have a layer and which lack it
    Knowledge {
        /// Only this layer (`sha256:...`)
        layer: Option<String>,
    },
    /// Say why the pulls asked the peers they did and what came of it: which
    /// peers were considered and why, what they answered, and why what they
    /// did not give went to the next source (the registry)
    Explain {
        /// A layer or chunk digest (or the start of one), an image id, or the
        /// name of an image the store has; the last decisions of all when
        /// not given
        target: Option<String>,
        /// Print the records as JSON
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
pub enum CaCommand {
    /// Make a certificate authority in a directory: its key (`ca.key`, keep
    /// it where only the operator reaches it; no node needs it) and its
    /// certificate (`ca.crt`), which every node lists in `ca_path`
    Init {
        /// The directory (made, mode 0700)
        dir: PathBuf,
        /// Days the authority is valid
        #[arg(long, default_value_t = 3650)]
        days: u32,
    },
    /// On a node: print its request for a certificate (its public key and
    /// the proof that it holds the key; the key does not leave the node)
    Request {
        /// The identity file of the node (default: `identity_path` of the
        /// settings)
        #[arg(long)]
        identity: Option<PathBuf>,
    },
    /// Sign the request of a node: prints its certificate (PEM), for
    /// `certificate_path` on that node
    Sign {
        /// The directory of the authority
        #[arg(long)]
        ca: PathBuf,
        /// The file written by `ca request` on the node
        request: PathBuf,
        /// The name of the node, in its certificate and the logs
        #[arg(long)]
        name: String,
        /// The zone of the node (a rack, a zone of the cloud)
        #[arg(long)]
        zone: Option<String>,
        /// `both` (default), `serve` (a seed: it is not served) or `pull` (it
        /// is not asked for data)
        #[arg(long, default_value = "both")]
        role: String,
        /// Days the certificate is valid; sign again before it ends
        #[arg(long, default_value_t = 30)]
        days: u32,
        /// Write the certificate here instead of the standard output
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Revoke nodes by peer id: writes `revoked` in the directory of the
    /// authority (every peer revoked so far, signed), which goes to the
    /// nodes (`revocation_path`).  A revoked key does not come back
    Revoke {
        /// The directory of the authority
        #[arg(long)]
        ca: PathBuf,
        /// The peer ids
        #[arg(required = true)]
        peers: Vec<String>,
    },
    /// Say what a certificate file or a revocation list holds
    Show { file: PathBuf },
}
