// SPDX-License-Identifier: Apache-2.0
//! `velarx-cri`: serves the Kubernetes CRI (runtime.v1) on a unix socket.

use clap::Parser;
use std::os::unix::fs::DirBuilderExt;
use std::path::PathBuf;
use std::sync::Arc;
use velarx_cri::engine::checkpoint::{self, Checkpoints};
use velarx_cri::engine::varlink::{default_cri_socket, default_engine_socket, Varlink};
use velarx_cri::service::Cri;
use velarx_cri::stream::{Sessions, StreamServer};
use velarx_proto::confine::{self, Reach};

#[derive(Parser)]
#[command(name = "velarx-cri", version = concat!(env!("CARGO_PKG_VERSION"), " (", env!("VELARX_GIT_COMMIT"), ")"), about = "The Kubernetes CRI frontend of velarx")]
struct Args {
    /// The unix socket the CRI is served on
    #[arg(long)]
    socket: Option<PathBuf>,
    /// The socket of the engine (`org.velarx.Engine`); the engine is started
    /// by whoever serves it (systemd, its socket unit), not by this process
    #[arg(long)]
    engine_socket: Option<PathBuf>,
    /// The directory of the checkpoint archives, the kubelet's: the process
    /// may make and write files there and nowhere else (default:
    /// /var/lib/kubelet/checkpoints, left out when it cannot be made)
    #[arg(long)]
    checkpoint_dir: Option<PathBuf>,
    /// Seconds the containers of a pod may stay paused by CheckpointPod:
    /// past it the dump is given up and they are resumed
    #[arg(long, default_value_t = checkpoint::DEFAULT_TIMEOUT.as_secs())]
    checkpoint_timeout: u64,
    /// The network of the pods, as the engine names it: `cni:` (the first
    /// configuration of the CNI directory) or `cni:NAME`; empty: the
    /// default network of the engine. The engine, which runs the plugins,
    /// has `[network.cni]` in its configuration.
    #[arg(long, default_value = "")]
    pod_network: String,
    /// The image of the infra container of every sandbox (containerd's
    /// `sandbox_image`, what `crictl info` shows as `sandboxImage` and a
    /// kubeadm compares with its pause image); the engine pulls it when it
    /// is missing. Empty: the engine's `infra_image`.
    #[arg(long, default_value = "")]
    sandbox_image: String,
    /// The address of the streaming server (exec, attach, port-forward) the
    /// kubelet connects to
    #[arg(long, default_value = "127.0.0.1:0")]
    stream_address: String,
    /// Seconds after which a port-forward session with no connection open is
    /// closed (0: never)
    #[arg(long, default_value_t = 1800)]
    stream_idle_timeout: u64,
}

/// The CRI socket, `0600` from its creation (no window with the mode of the
/// umask, and the umask is not touched: it is the process', and other
/// threads make files), a stale one replaced and one that something listens
/// on an error.
fn bind_socket(socket: &std::path::Path) -> anyhow::Result<std::os::unix::net::UnixListener> {
    if let Some(dir) = socket.parent() {
        // a directory created here is the caller's only (an existing one,
        // the engine's, keeps its mode)
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)?;
    }
    let bound = velarx_base::ipc::bind_unique(socket, true)
        .map_err(|e| anyhow::anyhow!("cannot listen on {}: {e}", socket.display()))?;
    bound.set_nonblocking(true)?;
    Ok(bound)
}

/// The socket systemd passed (`LISTEN_FDS`: the first descriptor, 3), when
/// this process was started by a socket unit.
fn activated(
    startup: &velarx_sys::fd::Startup,
) -> anyhow::Result<Option<std::os::unix::net::UnixListener>> {
    let ours = std::env::var("LISTEN_PID")
        .ok()
        .and_then(|p| p.parse::<u32>().ok())
        == Some(std::process::id());
    let n: usize = std::env::var("LISTEN_FDS")
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|_| ours)
        .unwrap_or(0);
    for k in ["LISTEN_PID", "LISTEN_FDS", "LISTEN_FDNAMES"] {
        std::env::remove_var(k);
    }
    if n == 0 {
        return Ok(None);
    }
    if n > 1 {
        anyhow::bail!("{n} sockets were passed and the CRI is served on one");
    }
    // (systemd handed this descriptor to this process: LISTEN_PID is ours)
    let Some(fd) = startup.adopt(3) else {
        anyhow::bail!("LISTEN_FDS says a socket was passed and descriptor 3 is not open");
    };
    rustix::io::fcntl_setfd(&fd, rustix::io::FdFlags::CLOEXEC)?;
    let listener = std::os::unix::net::UnixListener::from(fd);
    listener.set_nonblocking(true)?;
    Ok(Some(listener))
}

fn main() -> anyhow::Result<()> {
    let startup = velarx_sys::fd::Startup::take().expect("main is the first to take it");
    // (first: nothing of this process owns a descriptor yet)
    let activated = activated(&startup)?;
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::WARN)
        .with_writer(std::io::stderr)
        .init();
    let mut args = Args::parse();
    if args.pod_network == "cni" {
        args.pod_network = "cni:".into();
    }
    if !args.pod_network.is_empty() && !args.pod_network.starts_with("cni:") {
        anyhow::bail!(
            "--pod-network {}: the networks of the pods are CNI (`cni` or `cni:NAME`) or the default of the engine",
            args.pod_network
        );
    }
    let socket = match args.socket {
        Some(socket) => socket,
        None => default_cri_socket()?,
    };
    let engine_socket = match args.engine_socket {
        Some(socket) => socket,
        None => default_engine_socket()?,
    };
    // The connections to the engine come through a process forked now (one
    // thread so far): this one confines itself to look up no socket by name.
    let connector = velarx_sys::connector::Connector::start(&engine_socket)
        .map_err(|e| anyhow::anyhow!("cannot start the connector to the engine: {e}"))?;
    let dial = velarx_proto::connect::Dial::Connector(Arc::new(connector), engine_socket.clone());
    let mut engine = Varlink::reached(dial.clone());
    if let Some(c) = Checkpoints::configured(dial, args.checkpoint_dir.as_deref())
        .map_err(|e| anyhow::anyhow!("the checkpoint directory: {e}"))?
    {
        engine = engine.with_checkpoints(
            c.with_timeout(std::time::Duration::from_secs(args.checkpoint_timeout)),
        );
    }

    // Everything that needs the file system is done before the process
    // confines itself (it may then reach the engine through its connector and
    // serve the sockets it has, and nothing else).
    let tcp = std::net::TcpListener::bind(&args.stream_address)?;
    tcp.set_nonblocking(true)?;
    let stream_addr = tcp.local_addr()?.to_string();
    let uds = match activated {
        Some(l) => l,
        None => bind_socket(&socket)?,
    };
    // Before the threads of the runtime: Landlock and seccomp apply to the
    // threads made afterwards.
    let mut reach = Reach {
        bind_tcp: Vec::new(),
        create: Vec::new(),
        remove: Vec::new(),
        list: Vec::new(),
        read: Vec::new(),
        serves: true,
        ..Reach::default()
    };
    if let Some(c) = engine.checkpoints() {
        c.grant(&mut reach);
    }
    // (no /proc once confined)
    velarx_base::ids::settle()?;
    let enforced = confine::enter(&reach).map_err(|e| anyhow::anyhow!("cannot confine: {e}"))?;
    if !enforced.full {
        tracing::debug!("confined, not every Landlock right is enforced by this kernel");
    }

    let pod_network = args.pod_network;
    let sandbox_image = args.sandbox_image;
    let engine_gone = engine.engine_gone();
    let idle_timeout = std::time::Duration::from_secs(args.stream_idle_timeout);
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(async move {
            let engine = Arc::new(engine);
            let sessions = Arc::new(Sessions::default());
            tokio::spawn(
                Arc::new(StreamServer {
                    engine: engine.clone(),
                    sessions: sessions.clone(),
                    idle_timeout,
                })
                .serve(tokio::net::TcpListener::from_std(tcp)?),
            );
            let cri = Arc::new(
                Cri::new(engine, sessions, stream_addr)
                    .with_pod_network(&pod_network)
                    .with_sandbox_image(&sandbox_image),
            );
            // (the socket stays when this process ends: it may remove no file,
            // and the next start replaces a socket that nobody serves)
            let incoming =
                velarx_cri::peer::trusted_incoming(tokio::net::UnixListener::from_std(uds)?);
            let served = tonic::transport::Server::builder()
                .add_service(cri.runtime_server())
                .add_service(cri.image_server())
                .serve_with_incoming_shutdown(incoming, async {
                    let mut term =
                        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                            .inspect_err(|e| tracing::warn!("cannot handle SIGTERM: {e}"))
                            .ok();
                    tokio::select! {
                        _ = tokio::signal::ctrl_c() => {}
                        _ = async { match term.as_mut() { Some(t) => { t.recv().await; } None => std::future::pending().await } } => {}
                    }
                });
            // (ending is what lets whoever runs this start it again, with
            // the engine and the confinement of the new directory)
            tokio::select! {
                served = served => Ok(served?),
                () = engine_gone.notified() => {
                    anyhow::bail!("the engine can no longer be reached on {}", engine_socket.display())
                }
            }
        })
}
