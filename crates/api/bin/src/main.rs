// SPDX-License-Identifier: Apache-2.0
//! `velarx-api [--config PATH] [--listen URI]... [--engine-socket PATH]
//! [--idle-exit SECS] [--log-level LEVEL] [--start-engine | --no-start-engine]`:
//! the REST API, a frontend of the engine.
//!
//! The sockets come from systemd (`LISTEN_FDS`), or are bound here: the
//! unix socket of the configuration (`[api] socket`) unless `--listen` or
//! `[api] listen` name others.  TCP only when named (the loopback
//! addresses unless an address is), with a bearer token.  Everything the process needs from the system is
//! done before it confines itself: the configuration is read, the sockets
//! are bound, the engine is started if nothing activates it.

use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tracing::{debug, warn};
use velarx_api::config::Config;
use velarx_api::engine::Engine;
use velarx_api::listen::{self, Place};
use velarx_api::serve::{self, Listener, Why};
use velarx_proto::confine::{self, Reach};
use velarx_proto::connect;
use velarx_proto::serving::Peers;

struct Args {
    config: PathBuf,
    listen: Vec<String>,
    engine_socket: Option<PathBuf>,
    idle_exit: Option<u64>,
    log_level: tracing::Level,
    start_engine: Option<bool>,
    tls_cert: Option<PathBuf>,
    tls_key: Option<PathBuf>,
    tls_client_ca: Option<PathBuf>,
}

fn parse_args() -> anyhow::Result<Args> {
    let mut args = Args {
        config: velarx_base::dirs::DefaultDirs::current()?.config_file,
        listen: Vec::new(),
        engine_socket: None,
        idle_exit: None,
        log_level: tracing::Level::WARN,
        start_engine: None,
        tls_cert: None,
        tls_key: None,
        tls_client_ca: None,
    };
    let mut it = std::env::args_os().skip(1);
    while let Some(arg) = it.next() {
        let mut value = || {
            it.next()
                .ok_or_else(|| anyhow::anyhow!("{} needs a value", arg.to_string_lossy()))
        };
        match arg.to_str() {
            Some("--config") => args.config = PathBuf::from(value()?),
            Some("--listen") => args.listen.push(value()?.to_string_lossy().into_owned()),
            Some("--engine-socket") => args.engine_socket = Some(PathBuf::from(value()?)),
            Some("--idle-exit") => args.idle_exit = Some(value()?.to_string_lossy().parse()?),
            Some("--log-level") => {
                let level = value()?;
                args.log_level = level
                    .to_string_lossy()
                    .parse()
                    .map_err(|_| anyhow::anyhow!("{level:?} is not a log level"))?;
            }
            Some("--tls-cert") => args.tls_cert = Some(PathBuf::from(value()?)),
            Some("--tls-key") => args.tls_key = Some(PathBuf::from(value()?)),
            Some("--tls-client-ca") => args.tls_client_ca = Some(PathBuf::from(value()?)),
            Some("--start-engine") => args.start_engine = Some(true),
            Some("--no-start-engine") => args.start_engine = Some(false),
            Some("--version") | Some("-V") => {
                println!(
                    "velarx-api {} ({})",
                    env!("CARGO_PKG_VERSION"),
                    env!("VELARX_GIT_COMMIT")
                );
                std::process::exit(0);
            }
            Some("--help") | Some("-h") => {
                println!(
                    "usage: velarx-api [--config PATH] [--listen unix:///PATH | tcp://HOST:PORT]... \
                     [--tls-cert PEM --tls-key PEM [--tls-client-ca PEM]] \
                     [--engine-socket PATH] [--idle-exit SECS] [--log-level LEVEL] \
                     [--start-engine | --no-start-engine]"
                );
                std::process::exit(0);
            }
            // (the options of podman's `system service` that velarx-api
            // does not have)
            Some("--cors") => {
                anyhow::bail!("--cors is not supported: velarx-api sends no CORS headers")
            }
            Some(o @ ("--time" | "-t")) => {
                anyhow::bail!("{o} is not an option of velarx-api: --idle-exit SECS is")
            }
            _ => anyhow::bail!("unknown argument {}", arg.to_string_lossy()),
        }
    }
    Ok(args)
}

/// The sockets systemd passed (`LISTEN_FDS`), from descriptor 3.
fn activated(startup: &velarx_sys::fd::Startup) -> Vec<OwnedFd> {
    let n: usize = std::env::var("LISTEN_FDS")
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|_| {
            std::env::var("LISTEN_PID")
                .ok()
                .and_then(|p| p.parse::<u32>().ok())
                == Some(std::process::id())
        })
        .unwrap_or(0)
        .min(64);
    for k in ["LISTEN_PID", "LISTEN_FDS", "LISTEN_FDNAMES"] {
        std::env::remove_var(k);
    }
    (0..n)
        .filter_map(|i| {
            // (systemd handed these descriptors to this process: LISTEN_PID
            // is ours)
            let fd = startup.adopt(3 + i as i32)?;
            let _ = rustix::io::fcntl_setfd(&fd, rustix::io::FdFlags::CLOEXEC);
            Some(fd)
        })
        .collect()
}

/// `READY=1` to the notification socket of whoever started this process, if
/// it named one.
fn notify_ready() {
    let Some(path) = std::env::var_os("NOTIFY_SOCKET").filter(|p| !p.is_empty()) else {
        return;
    };
    std::env::remove_var("NOTIFY_SOCKET");
    // (an abstract socket, '@', is not one a process can name here)
    if path.as_encoded_bytes().first() == Some(&b'/') {
        if let Ok(socket) = std::os::unix::net::UnixDatagram::unbound() {
            let _ = socket.send_to(b"READY=1", &path);
        }
    }
}

fn bind_unix(path: &Path, rootful: bool) -> anyhow::Result<std::os::unix::net::UnixListener> {
    if let Some(dir) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        // (private, like the directory of the engine's socket next to it)
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)?;
    }
    // (the check for a live listener and the bind are one step under a
    // lock: two starts together do not remove each other's socket; the
    // socket of a user is that user's, root's is for whoever its directory
    // lets in)
    let listener = velarx_base::ipc::bind_unique(path, !rootful)
        .map_err(|e| anyhow::anyhow!("cannot listen on {}: {e}", path.display()))?;
    Ok(listener)
}

fn bind_tcp(addrs: &[std::net::SocketAddr]) -> anyhow::Result<Vec<std::net::TcpListener>> {
    let mut bound = Vec::new();
    let mut last = None;
    for addr in addrs {
        match std::net::TcpListener::bind(addr) {
            Ok(l) => bound.push(l),
            // (the loopback of a family the host does not have)
            Err(e) => last = Some((addr, e)),
        }
    }
    match (bound.is_empty(), last) {
        (true, Some((addr, e))) => anyhow::bail!("cannot listen on tcp://{addr}: {e}"),
        (_, Some((addr, e))) => debug!("no listener on tcp://{addr}: {e}"),
        _ => {}
    }
    Ok(bound)
}

fn main() -> anyhow::Result<()> {
    let startup = velarx_sys::fd::Startup::take().expect("main is the first to take it");
    // (first: nothing of this process owns a descriptor yet)
    let passed = activated(&startup);
    let args = parse_args()?;
    tracing_subscriber::fmt()
        .with_max_level(args.log_level)
        .with_writer(std::io::stderr)
        .init();
    // (the ids are read before the process confines itself: it cannot
    // read /proc then)
    velarx_base::ids::settle()?;
    let rootful = velarx_base::ids::rootful()?;
    let mut config = Config::load(&args.config).map_err(anyhow::Error::msg)?;
    if let Some(socket) = args.engine_socket {
        config.engine_socket = socket;
    }
    let api = &mut config.api;
    api.tls_cert = args.tls_cert.or(api.tls_cert.take());
    api.tls_key = args.tls_key.or(api.tls_key.take());
    api.tls_client_ca = args.tls_client_ca.or(api.tls_client_ca.take());

    let activated_by_systemd = !passed.is_empty();
    let mut std_unix = Vec::new();
    let mut std_tcp = Vec::new();
    for fd in passed {
        let family = rustix::net::getsockname(&fd).map(|a| a.address_family());
        match family {
            Ok(rustix::net::AddressFamily::UNIX) => {
                std_unix.push(std::os::unix::net::UnixListener::from(fd))
            }
            Ok(rustix::net::AddressFamily::INET | rustix::net::AddressFamily::INET6) => {
                // (a socket of systemd is not warned about: podman warns
                // about the address it is given)
                std_tcp.push(std::net::TcpListener::from(fd));
            }
            _ => warn!("ignoring a socket of systemd that is neither UNIX nor TCP"),
        }
    }
    if !activated_by_systemd {
        let uris: Vec<String> = if !args.listen.is_empty() {
            args.listen.clone()
        } else if !config.api.listen.is_empty() {
            config.api.listen.clone()
        } else {
            vec![format!("unix://{}", config.api_socket.display())]
        };
        for uri in uris {
            match listen::parse(&uri).map_err(anyhow::Error::msg)? {
                Place::Unix(path) => {
                    std_unix.push(bind_unix(&path, rootful)?);
                }
                Place::Tcp(addrs) => {
                    if config.api.tls_cert.is_none() {
                        warn!("{}", listen::TCP_WARNING);
                    }
                    std_tcp.extend(bind_tcp(&addrs)?);
                }
            }
        }
    }

    // TLS of the TCP listeners; the files are read before the confinement
    let tls = match (&config.api.tls_cert, &config.api.tls_key) {
        (Some(cert), Some(key)) => Some(
            velarx_api::tls::server_config(cert, key, config.api.tls_client_ca.as_deref())
                .map_err(|e| anyhow::anyhow!("TLS: {e}"))?,
        ),
        (None, None) if config.api.tls_client_ca.is_none() => None,
        _ => anyhow::bail!("TLS needs both the certificate and the key (tls_cert, tls_key)"),
    };

    // What the requests on TCP carry; read before the confinement
    let token = match (&config.api.token_file, std_tcp.is_empty()) {
        (_, true) => None,
        // (a client certificate authenticates as a token does)
        (None, false) if config.api.tls_client_ca.is_some() => None,
        (Some(path), false) => Some(std::sync::Arc::new(
            velarx_proto::bearer::Token::load(path)
                .map_err(|e| anyhow::anyhow!("[api] token_file: {e}"))?,
        )),
        (None, false) if config.api.allow_unauthenticated => {
            warn!(
                "the API on TCP has no authentication (allow_unauthenticated): \
                 whoever can connect to it controls the engine"
            );
            None
        }
        (None, false) => anyhow::bail!(
            "a TCP listener has no authentication: whoever can connect to it controls \
             the engine; set [api] token_file (a token the requests carry as \
             `Authorization: Bearer`), tls_client_ca or allow_unauthenticated = true"
        ),
    };

    // The connections to the engine come through a process forked now (no
    // thread yet): this one confines itself to look up no socket by name.
    let connector = velarx_sys::connector::Connector::start(&config.engine_socket)
        .map_err(|e| anyhow::anyhow!("cannot start the connector to the engine: {e}"))?;

    // The engine: started by its socket (systemd), else here
    let start_engine = args
        .start_engine
        .or(config.api.start_engine)
        .unwrap_or(!activated_by_systemd);
    // (held until the process ends: the engine stops with it; one another
    // frontend started is held, so that it is not left without one when
    // that frontend goes)
    let mut engine_kept = None;
    if start_engine {
        let exe = std::env::current_exe()?
            .parent()
            .map(|d| d.join("velarx"))
            .filter(|p| p.is_file())
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "no `velarx` next to velarx-api to start the engine with \
                     (--no-start-engine if something else does)"
                )
            })?;
        let command = || {
            let mut cmd = std::process::Command::new(&exe);
            cmd.arg("--config").arg(&args.config).args([
                "varlink",
                "--listen-fd",
                "3",
                "--time",
                "0",
            ]);
            cmd
        };
        engine_kept = Some(
            connect::keep_engine(&config.engine_socket, command)
                .map_err(|e| anyhow::anyhow!("{e}"))?,
        );
    }

    // (podman's spec of its API is a file it reads after)
    velarx_api::podman::system::open_swagger();
    // Before the threads of the runtime: Landlock and seccomp apply to the
    // threads made afterwards.
    let reach = Reach {
        bind_tcp: Vec::new(),
        create: Vec::new(),
        remove: Vec::new(),
        list: Vec::new(),
        read: Vec::new(),
        serves: true,
        ..Reach::default()
    };
    let enforced = confine::enter(&reach).map_err(|e| anyhow::anyhow!("cannot confine: {e}"))?;
    if !enforced.full {
        debug!("confined, not every Landlock right is enforced by this kernel");
    }

    // Whoever started this frontend by hand and waits for it (the CRI
    // frontend) is told that the sockets are bound and the engine is up.
    notify_ready();

    let idle = activated_by_systemd
        .then(|| args.idle_exit.or(config.api.idle_exit).unwrap_or(30))
        .filter(|s| *s > 0)
        .map(Duration::from_secs);
    let peers = if rootful { Peers::Any } else { Peers::Owner };
    let engine = Engine::reached(velarx_proto::connect::Dial::Connector(
        std::sync::Arc::new(connector),
        config.engine_socket.clone(),
    ));
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(4)
        .build()?;
    let why = runtime.block_on(async move {
        let mut listeners = Vec::new();
        for l in std_unix {
            l.set_nonblocking(true)?;
            listeners.push(Listener::Unix(tokio::net::UnixListener::from_std(l)?));
        }
        for l in std_tcp {
            l.set_nonblocking(true)?;
            listeners.push(Listener::Tcp(
                tokio::net::TcpListener::from_std(l)?,
                tls.clone(),
            ));
        }
        Ok::<_, anyhow::Error>(serve::serve(listeners, engine, peers, idle, token).await)
    })?;
    // (the sockets this process bound stay: it may not remove files, and
    // the next start replaces a socket that nobody serves)
    drop(engine_kept);
    match why {
        Why::Signal => debug!("stopped (signal)"),
        Why::Idle => debug!("stopped (idle)"),
        Why::Failed(reason) => anyhow::bail!("{reason}"),
    }
    Ok(())
}
