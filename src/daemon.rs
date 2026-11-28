// SPDX-License-Identifier: Apache-2.0
//! The daemon (`velarx varlink`).

use crate::api::AppState;
use crate::cli;
use crate::{api, engine_service};
use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tracing::{info, warn};
use velarx_config::Config;
use velarx_content::activation;
use velarx_core::services;
use velarx_core::services::{CgroupManager, ContainerService, ImageService, ServerService};
use velarx_db::Database;
use velarx_proto::connect::LISTEN_FILE_ENV;
use velarx_runtime::container;
use velarx_runtime::network::{self, NetworkService};
use velarx_runtime::userns::{self, UserNamespaceManager};
use velarx_wire::logging;
use velarx_wire::sdnotify;

use crate::cli::engine::{DaemonCli, DaemonCommand};

/// Run a command of the engine: the engine service, the engine commands of a
/// unit...  Must be called before any
/// thread is started.
pub fn run(cli: DaemonCli, startup: &velarx_sys::fd::Startup) -> anyhow::Result<()> {
    // (the engine service starts for a connection and leaves when idle: it
    // says only what is wrong, as the engine of a command does)
    logging::init(cli.log_level.as_deref().unwrap_or("warn"), &cli.log_format);
    // cgroup v2 only: no fallback
    velarx_base::cgroup::require_v2().map_err(anyhow::Error::msg)?;
    // A cgroup of its own for the containers of the daemon (rootless too):
    // before any thread or child exists.  Where it started is where it
    // goes back to when it ends (`delegate::release`).  A restart runs in
    // the cgroup made then, and is told where it started.
    let told = std::env::var(STARTED_CGROUP_ENV).ok();
    std::env::remove_var(STARTED_CGROUP_ENV);
    let restarted = told.is_some();
    let started = told.or_else(|| velarx_base::cgroup::of_process(None).ok());
    if matches!(cli.command, DaemonCommand::Daemon { .. })
        && !userns::rootless::marked()
        && !restarted
    {
        use services::delegate;
        let conf = velarx_config::Config::load_or_default(&cli.config).ok();
        let systemd = conf
            .as_ref()
            .is_some_and(|c| c.server.cgroup_manager == velarx_config::CgroupDriver::Systemd);
        // (`[containers] cgroups = "split"` asks for the layout: no cgroup
        // to split is a misconfiguration, not a reason to go without)
        let split = conf
            .as_ref()
            .is_some_and(|c| c.containers.cgroups == "split");
        match delegate::ensure_delegated_cgroup(systemd).and_then(|cg| {
            delegate::prepare(&cg)
                .map(|_| cg)
                .map_err(delegate::NoCgroup::Other)
        }) {
            Ok(cg) => info!("The daemon manages the cgroup {cg}"),
            Err(delegate::NoCgroup::Ids(e)) => return Err(e.into()),
            Err(e) if systemd => {
                return Err(anyhow::anyhow!("cgroup_manager = \"systemd\": {e}"));
            }
            Err(e) if split => {
                return Err(anyhow::anyhow!("[containers] cgroups = \"split\": {e}"));
            }
            Err(e) => warn!("No delegated cgroup ({e}): the containers get no cgroups"),
        }
    }

    // An unprivileged daemon or engine runs in a user namespace where it is
    // root: this has to happen before any thread is started.
    let role = match cli.command {
        DaemonCommand::Daemon { .. } => "daemon",
        DaemonCommand::Container(_) => "engine",
    };
    // (a command that only reads writes nothing for the namespaces)
    let registers = match &cli.command {
        DaemonCommand::Container(cmd) => cli::container_starts_processes(cmd),
        DaemonCommand::Daemon { .. } => true,
    };
    match userns::rootless::join(&cli.config, role, registers) {
        Ok(()) => {
            if registers {
                // it lives as long as its containers or longer: the next
                // command joins the namespaces through it
                velarx_nsid::tree::register_holder(std::process::id(), role);
            }
        }
        // the engine of a command does nothing outside of them; nor does a
        // process that cannot tell who it is
        Err(e)
            if matches!(cli.command, DaemonCommand::Container(_))
                || velarx_base::ids::IdsError::is_cause_of(&e) =>
        {
            return Err(e.into())
        }
        Err(e) => {
            warn!("Cannot run in a user namespace ({e}), containers will not work");
        }
    }

    match cli.command {
        DaemonCommand::Container(cmd) => {
            // The monitors get the unit's NOTIFY_SOCKET from the engine,
            // nothing else it starts does.
            sdnotify::take_manager_env();
            // The sockets of a unit's socket activation are for the
            // container it runs (Quadlet's `.socket` units).
            // `--preserve-fds` and `--preserve-fd` pass the caller's own
            // descriptors instead (podman ignores LISTEN_FDS then).
            let (activated, preserved) = match &cmd {
                cli::ContainerCommands::Run {
                    preserve_fds,
                    preserve_fd,
                    ..
                } if *preserve_fds > 0 || !preserve_fd.is_empty() => {
                    if std::env::var_os("LISTEN_FDS").is_some_and(|v| !v.is_empty()) {
                        warn!("Ignoring LISTEN_FDS to preserve custom user-specified FDs");
                    }
                    for k in ["LISTEN_PID", "LISTEN_FDS", "LISTEN_FDNAMES"] {
                        std::env::remove_var(k);
                    }
                    let taken = crate::preserve_fds::take(startup, *preserve_fds, preserve_fd)?;
                    (Vec::new(), Some(taken))
                }
                cli::ContainerCommands::Run { .. } => (sdnotify::take_listen_fds(startup), None),
                _ => (Vec::new(), None),
            };
            let code = crate::engine::container_command(&cli.config, cmd, activated, preserved)?;
            std::process::exit(code)
        }
        DaemonCommand::Daemon {
            time,
            listen_fd,
            lifeline_fd,
        } => {
            sdnotify::take_manager_env();
            // (no thread is running yet and nothing has opened a descriptor
            // above 2: the ones systemd passed are ours)
            let activated = sdnotify::take_listen_fds(startup);
            let held = engine_service::take_hold_fds(startup);
            let listen_file = take_listen_file();
            // (the sockets systemd passed, or those of a restart of this
            // daemon, come first: the number of `--listen-fd` is then the
            // same descriptor, which is already owned)
            let activated_listener = activated.iter().any(|a| is_unix_listener(&a.fd));
            let listen = listen_fd
                .filter(|_| !activated_listener)
                .map(|fd| {
                    activation::inherited_listener(startup, fd)
                        .map_err(|e| anyhow::anyhow!("--listen-fd {fd}: {e}"))
                })
                .transpose()?;
            let lifeline = lifeline_fd
                .map(|fd| -> anyhow::Result<std::os::fd::OwnedFd> {
                    // (a number that is no descriptor is refused, not taken)
                    let owned = startup
                        .adopt(fd)
                        .ok_or_else(|| anyhow::anyhow!("descriptor {fd} is not open"))?;
                    rustix::io::fcntl_setfd(&owned, rustix::io::FdFlags::CLOEXEC)?;
                    Ok(owned)
                })
                .transpose()
                .map_err(|e| anyhow::anyhow!("--lifeline-fd: {e}"))?;
            velarx_wire::proctitle::set("velarx-server");
            let ended = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?
                .block_on(run_daemon(
                    &cli.config,
                    activated,
                    time,
                    listen,
                    lifeline,
                    held,
                    listen_file,
                ));
            match ended {
                // (the runtime and its threads are gone)
                Ok(Ended::Restart(listener, own, file, lifeline, holds, upgrade)) => Err(restart(
                    listener,
                    own,
                    file,
                    lifeline,
                    holds,
                    upgrade,
                    started.as_deref(),
                )),
                // a stop, or a failure
                ended => {
                    if let Some(started) = &started {
                        services::delegate::release(std::process::id(), started);
                    }
                    ended.map(|_| ())
                }
            }
        }
    }
}

/// The socket of the engine service: the one systemd passed (socket
/// activation) or a frontend that started the engine (`--listen-fd`), else
/// bound here, which waits while another engine serves it ([`bind_engine`]).
/// The socket file of the listener this process was passed, as the process
/// that bound it named it ([`LISTEN_FILE_ENV`]).  Call it before any thread
/// is started.
fn take_listen_file() -> Option<(u64, u64)> {
    let named = std::env::var(LISTEN_FILE_ENV).ok();
    std::env::remove_var(LISTEN_FILE_ENV);
    let (dev, ino) = named?
        .split_once(':')
        .map(|(d, i)| (d.parse().ok(), i.parse().ok()))?;
    Some((dev?, ino?))
}

async fn engine_listener(
    config: &Config,
    activated: Vec<sdnotify::ActivatedFd>,
    listen: Option<std::os::unix::net::UnixListener>,
    stop: &mut Signals<'_>,
) -> anyhow::Result<Option<(std::os::unix::net::UnixListener, Option<PathBuf>)>> {
    let socket = config.engine_socket();
    if let Some((listener, own)) = activated_listener(activated)? {
        // (after a restart: the socket of the engine itself)
        return Ok(Some((listener, own.then_some(socket))));
    }
    if let Some(listener) = listen {
        return Ok(Some((listener, Some(socket))));
    }
    // (an engine that is stopping refuses a hold and says when it has
    // exited: it is bound here then, as a frontend does)
    let mut cut = 0;
    loop {
        // (the lock of the socket may be held for a while by a process that
        // binds or takes it away: waited for on a thread of its own, so
        // that a signal ends the wait, the thread with the process)
        let (bound_tx, bound_rx) = tokio::sync::oneshot::channel();
        let path = socket.clone();
        let lock = activation::open_lock(&socket)
            .map_err(|e| anyhow::anyhow!("cannot listen on {}: {e}", socket.display()))?;
        std::thread::Builder::new()
            .name("engine-socket".into())
            .spawn(move || {
                let _ = bound_tx.send(bind_engine(&path, lock));
            })?;
        let bound = tokio::select! {
            bound = bound_rx => bound.map_err(|_| anyhow::anyhow!("the bind of {} ended", socket.display()))?,
            _ = stop.int.recv() => return Ok(None),
            _ = stop.term.recv() => return Ok(None),
        };
        match bound? {
            Some(listener) => return Ok(Some((listener, Some(socket)))),
            None => {
                // Another engine serves the socket, one a frontend started
                // as often as not (it won the race of two that start in the
                // same instant): a normal condition. This process keeps it,
                // as a frontend would, for as long as it runs, and takes the
                // socket if that engine goes. None: stopped meanwhile.
                match keep_engine(&socket, stop).await? {
                    Kept::Ended => cut = 0,
                    Kept::Stopped => return Ok(None),
                    // (an engine that closed its socket as this connected:
                    // it is gone, the socket is bound again)
                    Kept::Cut(e) if cut >= 50 => {
                        anyhow::bail!("another engine serves {}: {e}", socket.display())
                    }
                    Kept::Cut(_) => cut += 1,
                }
            }
        }
    }
}

/// The signals that stop the daemon.
struct Signals<'a> {
    int: &'a mut tokio::signal::unix::Signal,
    term: &'a mut tokio::signal::unix::Signal,
}

/// The listener of `socket`, bound under its lock (`lock`, the file opened
/// before) unless an engine serves it.
fn bind_engine(
    socket: &Path,
    lock: std::fs::File,
) -> anyhow::Result<Option<std::os::unix::net::UnixListener>> {
    match activation::connect_or_bind_on(socket, lock)
        .map_err(|e| anyhow::anyhow!("cannot listen on {}: {e}", socket.display()))?
    {
        Ok(_) => Ok(None),
        Err(listener) => Ok(Some(listener)),
    }
}

/// What came of holding another engine.
enum Kept {
    /// The engine ended
    Ended,
    /// A signal stopped this process first
    Stopped,
    /// The engine cut the connection before it answered (it closed its
    /// socket meanwhile)
    Cut(velarx_proto::connect::ConnectError),
}

/// Hold the engine that serves `socket` until it ends or a signal stops
/// this process.  An engine that is stopping, which takes no hold, is
/// waited for the same way: its end of the hold hangs up when it has
/// exited.
async fn keep_engine(socket: &Path, stop: &mut Signals<'_>) -> anyhow::Result<Kept> {
    // (an engine that takes the connection and does not answer is waited for
    // no more than a signal allows)
    let held = tokio::select! {
        held = velarx_proto::connect::hold(socket) => held,
        _ = stop.int.recv() => return Ok(Kept::Stopped),
        _ = stop.term.recv() => return Ok(Kept::Stopped),
    };
    let held = match held {
        Ok(held) => held,
        Err(velarx_proto::connect::ConnectError::Stopping { gone }) => gone,
        Err(
            e @ (velarx_proto::connect::ConnectError::Unreachable { .. }
            | velarx_proto::connect::ConnectError::Protocol(_)),
        ) => return Ok(Kept::Cut(e)),
        Err(e) => anyhow::bail!("another engine serves {}: {e}", socket.display()),
    };
    held.set_nonblocking(true)?;
    let held = tokio::net::UnixStream::from_std(held)?;
    let gone = async {
        let mut buf = [0u8; 16];
        loop {
            if held.readable().await.is_err() {
                return;
            }
            match held.try_read(&mut buf) {
                // (a readiness that was not)
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Ok(0) | Err(_) => return,
                Ok(_) => {}
            }
        }
    };
    Ok(tokio::select! {
        () = gone => Kept::Ended,
        _ = stop.int.recv() => Kept::Stopped,
        _ = stop.term.recv() => Kept::Stopped,
    })
}

/// What ends the daemon, or starts it again.
#[derive(Debug, PartialEq, Eq)]
enum Cause {
    /// SIGHUP
    Hangup,
    /// `Restart` of the engine service
    RestartAsked,
    /// SIGINT or SIGTERM
    Signal,
    /// The frontend that started the engine is gone
    Lifeline,
    /// The service left, idle
    Idle,
}

impl Cause {
    fn restarts(&self) -> bool {
        matches!(self, Cause::Hangup | Cause::RestartAsked)
    }
}

/// What comes first, in this order when several did: a restart (asked by
/// signal or by the service, which stops accepting connections as it asks,
/// and so may be left too), a signal, the end of the frontend that started
/// the engine, the service leaving idle.
async fn what_ends(
    hangup: impl Future<Output = impl Sized>,
    restart_asked: impl Future<Output = ()>,
    interrupt: impl Future<Output = impl Sized>,
    terminate: impl Future<Output = impl Sized>,
    lifeline: impl Future<Output = ()>,
    left: impl Future<Output = ()>,
) -> Cause {
    tokio::select! {
        biased;
        _ = hangup => Cause::Hangup,
        () = restart_asked => Cause::RestartAsked,
        _ = interrupt => Cause::Signal,
        _ = terminate => Cause::Signal,
        () = lifeline => Cause::Lifeline,
        () = left => Cause::Idle,
    }
}

/// How the daemon ended.
enum Ended {
    Stop,
    /// It starts again with this listening socket of the engine (its file
    /// the daemon's, which it names, or systemd's).
    /// The lifeline of the frontend that started the engine, and the holds
    /// of the others, go on in the new process.
    /// With `true` last: from the binary installed (an upgrade).
    Restart(
        std::os::fd::OwnedFd,
        bool,
        Option<(u64, u64)>,
        Option<std::os::fd::OwnedFd>,
        Vec<std::os::fd::OwnedFd>,
        bool,
    ),
}

/// Execute this daemon again, its arguments and environment, with the
/// listening socket of the engine as a socket activation gives it (fd 3,
/// LISTEN_FDS), and what systemd gave (NOTIFY_SOCKET, the watchdog): the
/// pid stays, the clients that connect meanwhile wait in the backlog.  The
/// binary is the one running (/proc/self/exe), even when a newer one
/// replaced it on disk: a reload reads the configuration again; with
/// `upgrade` (`Restart` of a frontend of the newer version) it is the one
/// installed at the path of the running one.  Returns only on a failure.
fn restart(
    listener: std::os::fd::OwnedFd,
    owns_socket: bool,
    socket_file: Option<(u64, u64)>,
    lifeline: Option<std::os::fd::OwnedFd>,
    holds: Vec<std::os::fd::OwnedFd>,
    upgrade: bool,
    started: Option<&str>,
) -> anyhow::Error {
    use std::os::unix::process::CommandExt;
    let exe = match engine_service::installed_binary().filter(|_| upgrade) {
        Some(installed) => installed,
        None => PathBuf::from("/proc/self/exe"),
    };
    let restarted = restart_command(
        &exe,
        &listener,
        owns_socket.then_some(socket_file).flatten(),
        owns_socket,
        lifeline.as_ref(),
        &holds,
        started,
    );
    let mut cmd = match restarted {
        Ok(cmd) => cmd,
        Err(e) => return anyhow::anyhow!("restart: {e}"),
    };
    info!("Restarting");
    anyhow::anyhow!("restart: cannot execute {}: {}", exe.display(), cmd.exec())
}

/// The command [`restart`] executes: `exe` with the arguments and the
/// environment of this process, the listener at 3 (its socket file named,
/// `socket_file`, when it is the daemon's), the lifeline at 4, the cgroup
/// the daemon started in named ([`STARTED_CGROUP_ENV`]).
/// The holds of the other frontends stay at the numbers of their copies,
/// which this process owns, named in [`engine_service::HOLD_FDS_ENV`]: a
/// fixed number may be the descriptor of something another thread still
/// drops (the epoll of the runtime that is gone, kept by a handle), whose
/// close after the placing would take the hold away.
fn restart_command(
    exe: &Path,
    listener: &std::os::fd::OwnedFd,
    socket_file: Option<(u64, u64)>,
    owns_socket: bool,
    lifeline: Option<&std::os::fd::OwnedFd>,
    holds: &[std::os::fd::OwnedFd],
    started: Option<&str>,
) -> std::io::Result<std::process::Command> {
    use std::os::fd::AsRawFd;
    use std::os::unix::process::CommandExt;
    // (not current_exe(): the path of a binary replaced on disk is gone)
    let mut args = std::env::args_os();
    let mut cmd = std::process::Command::new(exe);
    if let Some(argv0) = args.next() {
        cmd.arg0(argv0);
    }
    cmd.args(args);
    for (k, v) in sdnotify::manager_env() {
        cmd.env(k, v);
    }
    cmd.env("LISTEN_PID", std::process::id().to_string())
        .env("LISTEN_FDS", "1")
        .env(
            "LISTEN_FDNAMES",
            if owns_socket { OWN_SOCKET } else { "engine" },
        );
    if let Some((dev, ino)) = socket_file {
        cmd.env(LISTEN_FILE_ENV, format!("{dev}:{ino}"));
    }
    if let Some(started) = started {
        cmd.env(STARTED_CGROUP_ENV, started);
    }
    for hold in holds {
        rustix::io::fcntl_setfd(hold, rustix::io::FdFlags::empty())?;
    }
    let held: Vec<String> = holds.iter().map(|h| h.as_raw_fd().to_string()).collect();
    cmd.env(engine_service::HOLD_FDS_ENV, held.join(","));
    cmd.envs(userns::rootless::marker_env());
    // The lifeline of the frontend that started the engine goes on as
    // descriptor 4 (the arguments say `--lifeline-fd 4`).
    let mut places = vec![(listener.as_raw_fd(), 3)];
    places.extend(lifeline.map(|life| (life.as_raw_fd(), 4)));
    velarx_sys::exec::place_fds(&mut cmd, places);
    Ok(cmd)
}

async fn run_daemon(
    config_path: &Path,
    activated: Vec<sdnotify::ActivatedFd>,
    idle_time: Option<u64>,
    listen: Option<std::os::unix::net::UnixListener>,
    lifeline: Option<std::os::fd::OwnedFd>,
    held: Vec<std::os::fd::OwnedFd>,
    listen_file: Option<(u64, u64)>,
) -> anyhow::Result<Ended> {
    let mut config = Config::load_or_default(config_path)?;
    config.validate()?;
    config.source = config_path.exists().then(|| config_path.to_path_buf());
    // (an engine that a socket unit started leaves after `[engine]
    // idle_exit`; one that was started by hand, or by its frontend, which
    // says --time, stays until it is stopped)
    let by_socket_unit = activated
        .iter()
        .any(|a| a.name.as_deref() != Some(OWN_SOCKET));
    let idle_time = idle_time.unwrap_or(if by_socket_unit {
        config.engine.idle_exit
    } else {
        0
    });
    let config = Arc::new(config);

    info!("Starting velarx daemon");

    // The signals that stop the daemon, from now on: a client may connect
    // to the socket (and a test or a script stop the daemon) before it is
    // ready.
    use tokio::signal::unix::{signal, SignalKind};
    let mut sigint = signal(SignalKind::interrupt())?;
    let mut sigterm = signal(SignalKind::terminate())?;
    // SIGHUP (systemd's ExecReload): the daemon starts again, its
    // configuration read again
    let mut sighup = signal(SignalKind::hangup())?;

    // The socket first: a socket a live engine serves is not taken from it,
    // and this process holds that engine then and does nothing else.
    let Some((front_listener, own_socket)) = engine_listener(
        &config,
        activated,
        listen,
        &mut Signals {
            int: &mut sigint,
            term: &mut sigterm,
        },
    )
    .await?
    else {
        return Ok(Ended::Stop);
    };
    // (the socket file this engine serves: the one it takes away when it
    // ends, not one another engine bound in its place meanwhile; the one
    // the process that bound the listener named, else the one bound here)
    let socket_file = own_socket
        .as_deref()
        .and_then(|path| listen_file.or_else(|| activation::socket_file_id(path)));

    // A signal that comes before the daemon is ready ends it, as one after
    // does (the containers go on): the start waits for the store, the
    // services and the monitors of the containers, and the signal does not
    // wait for them.
    let (ready_tx, mut ready_rx) = tokio::sync::oneshot::channel::<()>();
    let before_ready = tokio::spawn({
        let (own_socket, socket_file) = (own_socket.clone(), socket_file);
        async move {
            tokio::select! {
                biased;
                _ = sigint.recv() => {}
                _ = sigterm.recv() => {}
                _ = &mut ready_rx => return (sigint, sigterm),
            }
            eprintln!("Shutting down... (press Ctrl-C again to force)");
            sdnotify::notify("STOPPING=1\nSTATUS=Shutting down");
            if let Some(path) = &own_socket {
                activation::remove_own_socket(path, socket_file);
            }
            std::process::exit(0)
        }
    });

    // The kernel forgets the AppArmor profiles at a reboot: the containers
    // made before it and those a restart policy brings back need it.
    if let Err(e) = tokio::task::spawn_blocking(container::apparmor::ensure_default_loaded).await? {
        warn!("Cannot load the default AppArmor profile: {e}");
    }

    let state = build_services(config.clone(), config_path, &Role::Server).await?;
    let container_service = state.container_service.clone();
    // the checkpoint archives a daemon that ended had in transit
    velarx_core::services::sweep_checkpoint_staging(&config.server.root_dir);
    // what interrupted shares of checkpoints left, and the modes of the rest
    if let Err(e) =
        velarx_core::services::checkpoint::SharedCheckpoints::open_at_start(&config.storage.root)
    {
        warn!("Cannot sweep the shared checkpoints: {e}");
    }
    // the bundles are the engine's only (create makes it so too)
    {
        use std::os::unix::fs::PermissionsExt;
        let bundles = config.server.root_dir.join("bundles");
        if bundles.is_dir() {
            if let Err(e) =
                std::fs::set_permissions(&bundles, std::fs::Permissions::from_mode(0o700))
            {
                warn!("Cannot make {} the engine's only: {}", bundles.display(), e);
            }
        }
    }

    // The API remembers the exit code of the containers that are removed,
    // and announces what happens to them
    {
        let mut notices = state.container_service.subscribe_notices();
        let state = state.clone();
        tokio::spawn(async move {
            loop {
                match notices.recv().await {
                    Ok(notice) => api::podman::on_notice(&state, notice).await,
                    // (a burst, as the adoption of many containers)
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        warn!("{n} notices of the containers were missed");
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                }
            }
        });
    }
    // Find the monitors of the containers that outlived the previous
    // daemon (once the notices are followed: the exits found are events)
    if let Err(e) = container_service.adopt_containers().await {
        warn!("Failed to adopt the running containers: {}", e);
    }
    if let Err(e) = api::podman::forget_removed_records(&state).await {
        warn!(
            "Cannot remove the requests kept of removed containers: {}",
            e
        );
    }

    let state_clone = state.clone();

    let (shutdown_tx, _) = tokio::sync::broadcast::channel::<()>(1);

    // The daemon owns the database: it keeps its log from growing for
    // ever (readers that come and go, such as monitors, keep SQLite's own
    // checkpoints from shrinking it).
    {
        let db = state.db.clone();
        let mut stop = shutdown_tx.subscribe();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(WAL_CHECK);
            loop {
                tokio::select! {
                    _ = tick.tick() => match db.compact_wal(WAL_LIMIT).await {
                        Ok(true) => info!("Compacted the log of the database"),
                        Ok(false) => {}
                        Err(e) => warn!("Cannot compact the log of the database: {}", e),
                    },
                    _ = stop.recv() => break,
                }
            }
        });
    }

    // The containers a command started are observed here: a command tells
    // nobody (it never calls the service), their monitors record what
    // happens, which is a change of the database.
    {
        let containers = state.container_service.clone();
        let mut stop = shutdown_tx.subscribe();
        match state.db.watch_changes() {
            Ok(mut changes) => {
                tokio::spawn(async move {
                    loop {
                        tokio::select! {
                            r = changes.changed() => if r.is_err() { break },
                            _ = stop.recv() => break,
                        }
                        if let Err(e) = containers.observe_unobserved().await {
                            warn!("Cannot observe the containers a command started: {e}");
                        }
                    }
                });
            }
            Err(e) => warn!("Cannot watch the changes of the containers: {e}"),
        }
    }

    // a copy of the socket, for a restart
    let api_fd = rustix::io::fcntl_dupfd_cloexec(&front_listener, 3)?;
    let restart_asked = state.server_service.restart_signal();
    // (before the engine serves: a container of a lazy pull that misses a
    // file finds the socket from the first call on)
    // The engine service owns the lazy pulls of the store: it answers the
    // misses of their containers on the one socket of the store, and takes
    // over the pulls nobody completes (the service or the machine went down
    // meanwhile)
    let mut image_fetch = match velarx_core::image_fetch::Proxy::start(
        &config.services_dir(),
        velarx_core::image_fetch::ProxyEndpoint::new(
            (*state.image_service).clone(),
            tokio::runtime::Handle::current(),
        ),
    ) {
        Ok(proxy) => {
            info!(
                "The containers of lazy pulls are served on {}",
                velarx_content::imagefetch::socket(&config.services_dir()).display()
            );
            Some(proxy)
        }
        Err(e) => {
            warn!("The containers of lazy pulls get no file they lack: {e}");
            None
        }
    };
    let holds = engine_service::Holds::default();
    // The varlink service of the engine: the frontends and the command line
    // call it.  It leaves when idle, taking its socket away if it bound it.
    let idle = (idle_time > 0).then(|| activation::IdleExit {
        after: std::time::Duration::from_secs(idle_time),
        socket: own_socket.clone(),
        last: false,
        lock: None,
    });
    let engine = engine_service::Engine::new(state_clone, holds.clone());
    let mutating = engine.mutating();
    let rearm = engine.clone();
    let mut engine_server = engine_service::spawn(engine, front_listener, idle)?;
    // (a completion of a lazy pull keeps the service)
    state
        .image_service
        .keep_alive_with(engine_server.activity.clone());
    // (the containers of lazy pulls hold the service through their image
    // servers' connections)
    if let Some(proxy) = image_fetch.as_mut() {
        proxy.keep(engine_server.activity.clone());
    }
    // (after the service: a hold keeps it busy)
    for fd in held {
        holds.adopt(fd);
    }
    rearm.rearm_pause_leases().await;

    // The store service (`org.velarx.Store`) for the services that give the
    // content to others, served here while the daemon runs unless another
    // process serves it already
    if config.server.store_service {
        match velarx_core::store_service::spawn_thread(&state.config) {
            Ok(thread) => thread.into_iter().for_each(|t| t.detach()),
            Err(e) => warn!("The store service is not served: {e}"),
        }
    }

    state.image_service.sweep_layer_files().await;
    state.image_service.resume_pulls();

    let gc_handle = if config.storage.gc_interval_secs > 0 {
        let gc_interval = config.storage.gc_interval_secs;
        let db_clone = state.db.clone();
        let images = state.image_service.clone();
        let config_clone = state.config.clone();
        let mut gc_shutdown_rx = shutdown_tx.subscribe();

        Some(tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(gc_interval));
            interval.tick().await; // Skip first immediate tick

            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        images.resume_pulls();
                        info!("Running automatic garbage collection");
                        let file_store = match config_clone.storage.file_store() {
                            Ok(fs) => Arc::new(fs),
                            Err(e) => {
                                warn!("Failed to create file store for GC: {}", e);
                                continue;
                            }
                        };
                        let gc_service = services::GcService::new(
                            db_clone.clone(),
                            file_store,
                            &config_clone.storage,
                            images.storage().clone(),
                        );
                        // a pull in progress makes it wait for the next time
                        let options = services::GcOptions {
                            wait: false,
                            ..Default::default()
                        };
                        match gc_service.collect(options).await {
                            Ok(report) if report.skipped => info!("GC skipped: the store is in use"),
                            Ok(report) => images.forget_collected(&report).await,
                            Err(e) => warn!("Garbage collection failed: {}", e),
                        }
                    }
                    _ = gc_shutdown_rx.recv() => {
                        info!("GC scheduler shutting down");
                        break;
                    }
                }
            }
        }))
    } else {
        None
    };

    info!("Velarx daemon started");
    let _ = ready_tx.send(());
    let (mut sigint, mut sigterm) = before_ready.await?;
    sdnotify::notify("READY=1\nSTATUS=Ready");

    let watchdog_handle = sdnotify::watchdog().map(|period| {
        let mut stop = shutdown_tx.subscribe();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(period);
            loop {
                tokio::select! {
                    _ = tick.tick() => { sdnotify::notify("WATCHDOG=1"); }
                    _ = stop.recv() => break,
                }
            }
        })
    });

    let mut lifeline = lifeline
        .map(|owned| -> anyhow::Result<tokio::net::UnixStream> {
            let stream = std::os::unix::net::UnixStream::from(owned);
            stream.set_nonblocking(true)?;
            Ok(tokio::net::UnixStream::from_std(stream)?)
        })
        .transpose()
        .map_err(|e| anyhow::anyhow!("--lifeline-fd: {e}"))?;
    // (a copy for a restart, which executes this program again)
    let lifeline_keep = lifeline
        .as_ref()
        .map(|s| rustix::io::fcntl_dupfd_cloexec(s, 10))
        .transpose()?;
    // The engine service holds itself while a container is followed: when
    // the containers it follows change, or a container changes state.
    let hold = {
        let activity = engine_server.activity.clone();
        let containers = state.container_service.clone();
        let mut followed = containers.subscribe_followed();
        let mut changes = state.db.watch_changes().ok();
        tokio::spawn(async move {
            loop {
                activity.hold(!containers.followed().await.is_empty());
                let changed = async {
                    match changes.as_mut() {
                        Some(c) => {
                            if c.changed().await.is_err() {
                                std::future::pending::<()>().await;
                            }
                        }
                        None => std::future::pending().await,
                    }
                };
                tokio::select! {
                    r = followed.changed() => {
                        if r.is_err() {
                            return;
                        }
                    }
                    () = changed => {}
                }
            }
        })
    };
    let left = engine_server.left();
    // The frontend that started the engine lives as long as it holds its end
    // of the lifeline.
    let lifeline = async {
        match lifeline.as_mut() {
            Some(stream) => {
                use tokio::io::AsyncReadExt;
                let mut byte = [0u8; 1];
                // (nothing is ever sent: a read returns when it is closed)
                while stream.read(&mut byte).await.is_ok_and(|n| n > 0) {}
                // the frontends that hold the engine keep it
                holds.none().await;
            }
            None => std::future::pending().await,
        }
    };
    let cause = what_ends(
        sighup.recv(),
        restart_asked.notified(),
        sigint.recv(),
        sigterm.recv(),
        lifeline,
        left,
    )
    .await;
    let restarting = cause.restarts();
    // (the engine that left because it was idle says nothing)
    let quiet = cause == Cause::Idle;
    match cause {
        Cause::Lifeline => info!("The frontend that started the engine is gone: exiting"),
        Cause::Idle => info!("Idle for {idle_time}s: exiting"),
        _ => {}
    }
    if restarting {
        eprintln!("Restarting...");
        sdnotify::notify(&format!(
            "RELOADING=1\nSTATUS=Restarting\nMONOTONIC_USEC={}",
            monotonic_usec()
        ));
    } else {
        if !quiet {
            eprintln!("Shutting down... (press Ctrl-C again to force)");
        }
        sdnotify::notify("STOPPING=1\nSTATUS=Shutting down");
    }

    // A second Ctrl-C ends the shutdown; a second SIGTERM does not (systemd
    // sends it to every process of the unit, the rootless parent forwards it)
    tokio::spawn(async move {
        sigint.recv().await;
        eprintln!("Forced shutdown");
        std::process::exit(1);
    });
    tokio::spawn(async move { while sigterm.recv().await.is_some() {} });

    info!("Initiating graceful shutdown");

    let _ = shutdown_tx.send(());

    hold.abort();
    // From here nothing new starts: a restart takes no more connections (a
    // client that comes waits for the engine that follows), nor does an
    // engine on a socket of systemd's (it keeps the connections that come
    // for the instance it starts next), and every shutdown takes no more
    // calls that change something.
    let followed = restarting || own_socket.is_none();
    if followed {
        engine_server.activity.stop_accepting().await;
    }
    mutating.refuse_new(followed);
    // The builds end as builds asked to stop do: their RUN containers are
    // the builds' own, nothing would end them after this process.
    let limit = std::time::Duration::from_secs(state.config.server.shutdown_timeout_secs);
    let left = state.build_service.stop_all(limit).await;
    if left > 0 {
        warn!(
            "{left} builds did not stop in {}s: `system prune --build` removes their containers",
            limit.as_secs()
        );
    }
    // What changes something finishes (up to the shutdown timeout) before
    // the connections end; on a restart the sockets stay open, so whoever
    // connects meanwhile waits for the engine that comes next.
    let left = mutating.drain(limit).await;
    if left > 0 {
        warn!(
            "{left} calls that change something did not finish in {}s: cut by the {}",
            limit.as_secs(),
            if restarting { "restart" } else { "shutdown" }
        );
    }
    engine_server.stop();
    // (its thread drops the engine and the state it holds, and closes
    // their descriptors, before this process goes on: a restart places the
    // descriptors it passes on at fixed numbers, where such a close would
    // take one away, the hold of another frontend)
    engine_server.ended().await;

    if let Some(handle) = gc_handle {
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), handle).await;
    }

    // The log of the database goes back into it and its files go.
    if let Err(e) = state.db.close().await {
        warn!("Cannot close the database: {}", e);
    }

    if let Some(handle) = watchdog_handle {
        let _ = handle.await;
    }

    if restarting {
        info!("Shutdown complete, starting again");
        return Ok(Ended::Restart(
            api_fd,
            own_socket.is_some(),
            socket_file,
            lifeline_keep,
            holds.fds()?,
            state.server_service.upgrading(),
        ));
    }
    if let Some(path) = &own_socket {
        activation::remove_own_socket(path, socket_file);
    }

    info!("Shutdown complete");
    Ok(Ended::Stop)
}

/// CLOCK_MONOTONIC in microseconds (sd_notify's RELOADING=1 wants it).
fn monotonic_usec() -> u64 {
    let t = rustix::time::clock_gettime(rustix::time::ClockId::Monotonic);
    t.tv_sec as u64 * 1_000_000 + t.tv_nsec as u64 / 1_000
}

/// How often the size of the log of the database is checked, and the size
/// past which it is written back and truncated.
const WAL_CHECK: std::time::Duration = std::time::Duration::from_secs(60);
const WAL_LIMIT: u64 = 32 << 20;

/// What the services of this process are for.
pub enum Role {
    /// The engine service: it serves the layers of root containers, keeps
    /// containers in its cgroup and follows every monitor.
    Server,
    /// The engine that runs one command for its caller (a systemd unit, a
    /// shell): the monitors it starts stay in the caller's cgroup, talk to
    /// the caller's service manager, and serve the root file system.
    Engine {
        notify_socket: Option<std::ffi::OsString>,
        /// The unit's socket activation, for its container.
        listen_fds: Vec<Arc<std::os::fd::OwnedFd>>,
        preserve_holes: Vec<u32>,
        /// The caller's cgroup, split for `--cgroups=split`.
        split_cgroup: Option<String>,
        /// `run --no-monitor`: the process this one split from monitors the
        /// container.
        in_process: Option<Arc<velarx_runtime::monitor::inproc::Handoff>>,
        /// The containers get a scope of their own from the systemd manager
        /// (outside a unit, when one answers): else they stay in the cgroup
        /// of their monitor.
        systemd_cgroups: velarx_core::services::SystemdCgroups,
    },
}

impl Role {
    /// What the monitors this role starts get from it, with the command that
    /// records what happens to a container and the lock of the store (the
    /// same for both).
    fn supervision(
        &self,
        config: &Config,
        engine_command: Option<Vec<std::ffi::OsString>>,
        store_lock: Option<PathBuf>,
    ) -> services::Supervision {
        match self {
            Role::Engine {
                notify_socket,
                listen_fds,
                preserve_holes,
                split_cgroup,
                in_process,
                systemd_cgroups,
            } => services::Supervision {
                notify_socket: notify_socket.clone(),
                listen_fds: listen_fds.clone(),
                preserve_holes: preserve_holes.clone(),
                split_cgroup: split_cgroup.clone(),
                systemd_cgroups: systemd_cgroups.clone(),
                in_process: in_process.clone(),
                observe: false,
                engine_command,
                store_lock,
            },
            Role::Server => services::Supervision {
                notify_socket: None,
                listen_fds: Vec::new(),
                preserve_holes: Vec::new(),
                split_cgroup: None,
                systemd_cgroups: velarx_core::services::SystemdCgroups::known(
                    config.server.cgroup_manager == velarx_config::CgroupDriver::Systemd,
                ),
                in_process: None,
                observe: true,
                engine_command,
                store_lock,
            },
        }
    }
}

/// The services of the API, as the server and the engine use them.
/// What the services of a process that starts, ends or records containers
/// stand on: the database, the images and storage, the networks of the
/// containers, and the container service.
pub(crate) struct Core {
    pub config: Arc<Config>,
    pub db: Database,
    pub image_service: Arc<ImageService>,
    pub userns_manager: Arc<UserNamespaceManager>,
    pub volume_service: Arc<services::VolumeService>,
    pub container_service: Arc<ContainerService>,
    pub net_engine: Arc<network::engine::ContainerNetworks>,
}

/// Where the events are kept beyond a process.
fn event_log(config: &Config) -> velarx_wire::events::log::EventLog {
    let conf = &config.server;
    velarx_wire::events::log::EventLog::from_config(
        &conf.events_logger,
        &conf.events_logfile_path,
        velarx_config::parse_size(&conf.events_logfile_max_size).unwrap_or(0),
        &config.server.root_dir,
    )
}

pub(crate) async fn build_services(
    config: Arc<Config>,
    config_path: &Path,
    role: &Role,
) -> anyhow::Result<Arc<AppState>> {
    let core = build_core(config, config_path, role).await?;
    let Core {
        config,
        db,
        image_service,
        userns_manager,
        volume_service,
        container_service,
        net_engine,
    } = core;
    // After a reboot, what ran does not: set the records right, once.
    if let Err(e) = container_service.reconcile_boot().await {
        warn!("Cannot reconcile the containers with this boot: {}", e);
    }
    net_engine.release_stale_cni().await;
    // the layers of the images a monitor removed with its container
    tokio::spawn({
        let images = image_service.clone();
        async move { images.release_removed().await }
    });
    let state = build_rest(
        config,
        db,
        image_service,
        userns_manager,
        volume_service,
        container_service,
        net_engine,
    )?;
    // The `--rm` containers whose monitor was killed before it removed them
    // (once the events are kept: the removal is one)
    if let Err(e) = state.container_service.finish_removals().await {
        warn!("Cannot finish the removal of the containers: {e}");
    }
    Ok(state)
}

async fn build_core(
    mut config: Arc<Config>,
    config_path: &Path,
    role: &Role,
) -> anyhow::Result<Core> {
    let engine = matches!(role, Role::Engine { .. });
    // (the engine service holds a connection for each client, and the
    // descriptors its calls carry: more than the 1024 of a shell.  The
    // engine of a command keeps the limit it was given, and raises it for
    // the layers of the image it mounts, `ensure_open_files`; the OCI runtime
    // and the hooks get the limit the process had, `MonitorConfig::open_files`,
    // a container the one of its spec)
    if !engine {
        velarx_base::hardening::raise_open_files()
            .map_err(|e| anyhow::anyhow!("cannot raise the limit of open files: {e}"))?;
    }
    container::set_runtime_from_config(&config)?;
    // (`[containers] cgroups = "disabled"`: a holder of the rootless
    // network namespace started outside the start of a container gets no
    // scope either)
    velarx_runtime::network::rootless_netns::set_default_in_caller_cgroup(
        velarx_core::services::cgroups_mode::conf_default(&config.containers.cgroups)
            == velarx_core::services::CgroupsMode::Disabled,
    );
    let mut runtime_args = config.server.runtime_args.clone();
    // (`--cgroup-manager` is crun's: it goes only to the runtimes that take
    // it, `container::args_for_runtime`)
    if engine
        && !runtime_args
            .iter()
            .any(|a| a.starts_with("--cgroup-manager"))
    {
        // Without a cgroup manager of its own, a container stays in the
        // cgroup of its monitor: the unit's.
        runtime_args.extend(["--cgroup-manager".into(), "disabled".into()]);
    }

    {
        // (the runtime state: private, as the tmpfiles.d entry and the
        // DirectoryMode of the socket units make it; the engine's socket
        // is bound only in a private directory)
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&config.server.state_dir)?;
    }
    velarx_base::ipc::create_private_dirs(&config.server.root_dir)?;
    velarx_base::ipc::create_private_dirs(&config.storage.root)?;
    std::fs::create_dir_all(config.storage.objects_dir())?;

    let db = Database::open_store(&config.storage).await?;
    // A store has one run root: two engines with their monitors in two
    // directories would share its database (podman's check and words).
    let runroot = config.server.state_dir.to_string_lossy();
    let recorded = db.store_setting("runroot", &runroot).await?;
    if recorded != runroot {
        anyhow::bail!(
            "database run root {recorded:?} does not match our run root {runroot:?}: \
             database configuration mismatch"
        );
    }
    // A store keeps the storage driver it was made with.
    let driver = config
        .storage
        .resolve_driver(
            &db.store_setting("driver", config.storage.driver_kind().name())
                .await?,
        )
        .map_err(anyhow::Error::from)?;
    if config.storage.driver.as_deref() != Some(driver.name()) {
        Arc::make_mut(&mut config).storage.driver = Some(driver.name().into());
        // (what the store's driver needs of the configuration, now that it
        // is known)
        config.validate().map_err(anyhow::Error::from)?;
    }
    let file_store = Arc::new(config.storage.file_store()?);

    std::fs::create_dir_all(config.storage.staging_dir())?;
    // (before the services find out what the kernel does: the storage driver
    // asks it whether it mounts an EROFS image from a file)
    velarx_core::services::boot::forget_features_of_a_new_boot(&config.server.state_dir);

    let mut image_service = ImageService::new(
        db.clone(),
        Arc::clone(&file_store),
        config.storage.staging_dir(),
        config.storage.verity_mode(),
    )?
    .with_pull_config(config.pull.clone())?
    .with_push_config(config.push.clone())
    .with_transports(config.transports.clone())
    .with_sinks(config.sinks.external.clone())
    .with_default_digest(config.build.digest)
    .with_driver(config.storage.driver_kind())
    .with_image_server(
        velarx_base::spawn::binary(),
        config.server.state_dir.clone(),
        config.clone(),
    )
    .with_composefs(&config.storage.composefs)
    .with_composefs_digests(config.storage.composefs_digests)
    .with_verity_chain(config.storage.verity_chain)
    .with_verity_best_effort(config.storage.fsverity_best_effort);
    // The fetchers of the pulls but the registry fetcher
    image_service = image_service.with_fetchers(config.sources.external.clone());
    // a lazy pull outlives the command that made it: it is the engine
    // service's, which this process is, or which a command's engine
    // finds or starts
    image_service = match role {
        Role::Server => image_service.serve_pulls(),
        Role::Engine { .. } => image_service.with_hand_off(Arc::new(
            crate::engine::pull_service::PullService::new(config.clone(), config_path),
        )),
    };
    // (a driver that checks fs-verity at pull only does not take the settings
    // that enforce it while a container runs, unless best effort is said)
    image_service
        .check_store_config(&config.storage)
        .map_err(|e| std::io::Error::other(format!("[storage]: {e}")))?;
    // every file of the store must have fs-verity: the store must be on a
    // file system that has it, with the digests that name the files
    if config.storage.fsverity_require {
        velarx_storage::probe(&config.storage.objects_dir()).map_err(|e| {
            std::io::Error::other(format!(
                "storage.fsverity_require is set, and {} cannot have the fs-verity it requires: {e}",
                config.storage.objects_dir().display()
            ))
        })?;
    }
    // pulls reach the registry through the fetcher, which has the
    // credentials
    // (the service's fetcher is the one its engines and monitors share;
    // the engine of a command has one of its own for each of its
    // connections)
    let origin = match role {
        Role::Server => velarx_content::list::RegistryOrigin::new(&config),
        Role::Engine { .. } => velarx_content::list::RegistryOrigin::private(&config),
    };
    image_service = image_service.with_origin(origin);
    let image_service = Arc::new(image_service);

    let userns_manager = Arc::new(UserNamespaceManager::new(db.clone(), &config.userns));

    // The daemon moves to a cgroup of its own; the engine stays where its
    // caller put it.
    let systemd_mode = config.server.cgroup_manager == velarx_config::CgroupDriver::Systemd
        || config.containers.cgroups == "split";
    let cgroup_manager = if engine {
        None
    } else {
        match CgroupManager::new() {
            Ok(mut cm) => {
                if let Err(e) = cm.init_daemon_cgroup() {
                    if systemd_mode {
                        anyhow::bail!("the cgroup manager of the daemon (systemd or split): the daemon's cgroup: {e}");
                    }
                    warn!("Failed to initialize daemon cgroup: {}", e);
                    None
                } else {
                    info!("Cgroup manager initialized, daemon moved to dedicated cgroup");
                    Some(Arc::new(cm))
                }
            }
            Err(e) => {
                if systemd_mode {
                    anyhow::bail!("the cgroup manager of the daemon (systemd or split): {e}");
                }
                warn!("No cgroup manager: {}", e);
                None
            }
        }
    };

    if !engine
        && runtime_args.is_empty()
        && cgroup_manager.is_none()
        && userns::rootless::in_user_namespace()?
    {
        // without a delegated cgroup crun spends a second per container
        // trying to enable controllers
        info!("Rootless without a delegated cgroup: --cgroup-manager disabled");
        runtime_args = vec!["--cgroup-manager".into(), "disabled".into()];
    }
    container::set_runtime_args(runtime_args);
    velarx_runtime::monitor::features::keep_in(config.server.state_dir.clone());

    // The networks of the providers (`--network provider:NAME`) need the
    // server: it is told when the container is gone
    let network_providers = if engine {
        Default::default()
    } else {
        velarx_runtime::network::provider::Providers::of_config(&config)
    };

    // Volumes survive a reboot.
    let volumes_dir = config.server.root_dir.join("volumes");
    let volume_service = Arc::new(services::VolumeService::new(db.clone(), volumes_dir)?);

    let container_service = Arc::new(
        ContainerService::new(services::ContainerParts {
            db: db.clone(),
            image_service: image_service.clone(),
            userns_manager: userns_manager.clone(),
            root_dir: config.server.root_dir.clone(),
            state_dir: config.server.state_dir.clone(),
            cgroup_manager,
            network_providers,
            volume_service: volume_service.clone(),
        })?
        .with_containers_config(config.containers.clone())
        .with_base_hosts_file(&config.containers.base_hosts_file)
        .with_default_cgroups(&config.containers.cgroups)
        .with_monitor_env((*config).clone())
        .with_caller_supervised(engine)
        .with_supervision(role.supervision(
            &config,
            engine_command(config_path),
            Some(velarx_storage::StorageLock::path(&config.storage.root)),
        )),
    );

    // Bridge networks and pasta for the containers of this run root.
    let net_engine = Arc::new(network::engine::ContainerNetworks::new(
        db.clone(),
        network::engine::EngineOptions {
            state_dir: config.server.state_dir.clone(),
            db_path: config.storage.database_path(),
            bridge: config.network.bridge.clone(),
            table: "velarx".into(),
            dns_exe: std::env::current_exe().unwrap_or_else(|_| "velarx".into()),
            cni: config.network.cni.clone(),
            providers: config
                .network
                .providers
                .iter()
                .map(|p| velarx_netdetach::provider::ProviderRef {
                    name: p.name.clone(),
                    socket: p.socket.clone(),
                })
                .collect(),
        },
    )?);
    container_service
        .network_manager()
        .set_engine(net_engine.clone());
    Ok(Core {
        config,
        db,
        image_service,
        userns_manager,
        volume_service,
        container_service,
        net_engine,
    })
}

fn build_rest(
    config: Arc<Config>,
    db: Database,
    image_service: Arc<ImageService>,
    userns_manager: Arc<UserNamespaceManager>,
    volume_service: Arc<services::VolumeService>,
    container_service: Arc<ContainerService>,
    net_engine: Arc<network::engine::ContainerNetworks>,
) -> anyhow::Result<Arc<AppState>> {
    let network_service = Arc::new(NetworkService::new(
        db.clone(),
        config.network.clone(),
        net_engine,
    ));

    let server_service = Arc::new(ServerService::new(config.clone(), db.clone()));

    // (the build worker is a mode of this binary, even if it was replaced
    // since it started)
    let build_worker = Some(std::path::PathBuf::from("/proc/self/exe"));
    let build_service = Arc::new(services::BuildService::new(
        image_service.clone(),
        container_service.clone(),
        // Contexts and layers can be large: on the disk of the store, not
        // in the state directory (a tmpfs).
        config.storage.root.join("build"),
        build_worker,
        services::build::BuildSettings {
            limits: services::build::copy::Limits {
                max_bytes: config.build.max_extract_gib.saturating_mul(1 << 30),
                max_entries: config.build.max_extract_entries,
            },
            worker_timeout: std::time::Duration::from_secs(config.build.worker_timeout_secs),
            max_concurrent: config.build.max_concurrent,
            max_pending: config.build.max_pending,
            max_scratch: config.build.max_scratch_gib.saturating_mul(1 << 30),
            entitlements: config.build.insecure_entitlements.clone(),
        },
    )?);

    let pod_service = Arc::new(services::PodService::new(
        container_service.clone(),
        config.server.root_dir.clone(),
    ));

    let state = Arc::new(AppState {
        config: config.clone(),
        db,
        image_service: image_service.clone(),
        container_service: container_service.clone(),
        network_service: network_service.clone(),
        userns_manager,
        server_service,
        volume_service: volume_service.clone(),
        build_service: build_service.clone(),
        pod_service: pod_service.clone(),
        podman: Default::default(),
        build_asks: Default::default(),
    });
    // Where the events are kept beyond this process.
    state.podman.events.set_log(event_log(&config));
    // The monitors of the containers write their events there.
    container_service.set_event_log(event_log(&config));

    Ok(state)
}

/// The API socket that systemd passed (socket activation), if any.
/// The name of the socket a restart passes: the daemon's own (its file is
/// removed when the daemon stops), not systemd's.
const OWN_SOCKET: &str = "velarx-own";

/// The variable that tells a restarted daemon the cgroup it started in,
/// before the cgroup of its own.
const STARTED_CGROUP_ENV: &str = "VELARX_STARTED_CGROUP";

fn activated_listener(
    activated: Vec<sdnotify::ActivatedFd>,
) -> anyhow::Result<Option<(std::os::unix::net::UnixListener, bool)>> {
    for a in activated {
        if is_unix_listener(&a.fd) {
            let own = a.name.as_deref() == Some(OWN_SOCKET);
            return Ok(Some((std::os::unix::net::UnixListener::from(a.fd), own)));
        }
        warn!(
            "Ignoring the descriptor {:?} passed by systemd: not a listening unix stream socket",
            a.name
        );
    }
    Ok(None)
}

fn is_unix_listener(fd: &std::os::fd::OwnedFd) -> bool {
    use rustix::net::sockopt;
    matches!(
        sockopt::socket_type(fd),
        Ok(rustix::net::SocketType::STREAM)
    ) && matches!(sockopt::socket_domain(fd), Ok(d) if d == rustix::net::AddressFamily::UNIX)
        && sockopt::socket_acceptconn(fd).unwrap_or(false)
}

/// This engine's command line up to its command (`velarx --config PATH`):
/// what units run.
fn engine_command(config_path: &Path) -> Option<Vec<std::ffi::OsString>> {
    let exe = std::env::current_exe().ok()?;
    let config = std::path::absolute(config_path).ok()?;
    Some(vec![
        exe.into_os_string(),
        "--config".into(),
        config.into_os_string(),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A restart names the socket file of the daemon, and the holds of the
    /// other frontends by the numbers of their copies, which this process
    /// owns, left open across the exec: it moves only the listener and the
    /// lifeline, to 3 and 4.
    #[test]
    fn a_restart_passes_the_holds_at_their_own_numbers() {
        use std::os::fd::{AsRawFd, OwnedFd};
        let dir = tempfile::tempdir().unwrap();
        let (a, _a) = std::os::unix::net::UnixStream::pair().unwrap();
        let (b, _b) = std::os::unix::net::UnixStream::pair().unwrap();
        let holds: Vec<OwnedFd> = vec![a.into(), b.into()];
        let listener: OwnedFd = std::os::unix::net::UnixListener::bind(dir.path().join("s"))
            .unwrap()
            .into();
        let cmd = restart_command(
            Path::new("/bin/true"),
            &listener,
            Some((7, 9)),
            true,
            None,
            &holds,
            None,
        )
        .unwrap();
        let env = |name: &str| {
            cmd.get_envs()
                .find(|(k, _)| *k == name)
                .and_then(|(_, v)| v)
                .map(|v| v.to_str().unwrap().to_string())
        };
        assert_eq!(env(LISTEN_FILE_ENV).as_deref(), Some("7:9"));
        let numbers: Vec<String> = holds.iter().map(|h| h.as_raw_fd().to_string()).collect();
        assert_eq!(env(engine_service::HOLD_FDS_ENV), Some(numbers.join(",")));
        for hold in &holds {
            let flags = rustix::io::fcntl_getfd(hold).unwrap();
            assert!(!flags.contains(rustix::io::FdFlags::CLOEXEC));
        }
    }

    /// A signal ends the wait for an engine that serves the socket but does
    /// not answer the hold.
    #[tokio::test]
    async fn a_signal_ends_the_hold_of_an_engine_that_does_not_answer() {
        use tokio::signal::unix::{signal, SignalKind};
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("engine.sock");
        let listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
        let mut int = signal(SignalKind::interrupt()).unwrap();
        let mut term = signal(SignalKind::terminate()).unwrap();
        let mut stop = Signals {
            int: &mut int,
            term: &mut term,
        };
        // (the connection waits in the queue of the listener, which never
        // accepts it: the engine does not answer)
        rustix::process::kill_process(rustix::process::getpid(), rustix::process::Signal::TERM)
            .unwrap();
        assert!(matches!(
            keep_engine(&socket, &mut stop).await.unwrap(),
            Kept::Stopped
        ));
        drop(listener);
    }

    /// A signal ends the wait for the lock of the socket, which another
    /// process holds while it binds the socket or takes it away.
    #[tokio::test]
    async fn a_signal_ends_the_wait_for_the_lock_of_the_socket() {
        use tokio::signal::unix::{signal, SignalKind};
        let dir = tempfile::tempdir().unwrap();
        let mut config = Config::default();
        config.engine.socket = Some(dir.path().join("run").join("engine.sock"));
        let _held = activation::take_lock(&config.engine_socket()).unwrap();
        let mut int = signal(SignalKind::interrupt()).unwrap();
        let mut term = signal(SignalKind::terminate()).unwrap();
        let mut stop = Signals {
            int: &mut int,
            term: &mut term,
        };
        rustix::process::kill_process(rustix::process::getpid(), rustix::process::Signal::INT)
            .unwrap();
        let got = engine_listener(&config, Vec::new(), None, &mut stop)
            .await
            .unwrap();
        assert!(got.is_none());
        // (the wait for the lock goes on, on a thread of its own, until
        // the lock is let go: it must find the directory gone and make
        // nothing in its place)
        drop(dir);
    }

    /// A future that is ready when `on`, else never.
    async fn when(on: bool) {
        if !on {
            std::future::pending::<()>().await;
        }
    }

    /// What comes first when `ready` of (hangup, restart asked, signal,
    /// lifeline, idle) are ready all at once.
    async fn first(ready: [bool; 5]) -> Cause {
        what_ends(
            async move { when(ready[0]).await },
            when(ready[1]),
            async move { when(ready[2]).await },
            std::future::pending::<()>(),
            when(ready[3]),
            when(ready[4]),
        )
        .await
    }

    /// A restart wins over what else is ready, whatever the order the
    /// branches are polled in: the service that is asked to restart stops
    /// accepting and may leave before the daemon looks.
    #[tokio::test]
    async fn a_restart_wins_over_the_service_leaving() {
        for _ in 0..16 {
            assert_eq!(
                first([false, true, false, false, true]).await,
                Cause::RestartAsked
            );
            assert_eq!(first([true, true, true, true, true]).await, Cause::Hangup);
            assert_eq!(
                first([false, true, true, true, true]).await,
                Cause::RestartAsked
            );
            assert_eq!(first([false, false, true, true, true]).await, Cause::Signal);
            assert_eq!(
                first([false, false, false, true, true]).await,
                Cause::Lifeline
            );
            assert_eq!(first([false, false, false, false, true]).await, Cause::Idle);
        }
        assert!(Cause::Hangup.restarts() && Cause::RestartAsked.restarts());
        assert!(!Cause::Signal.restarts() && !Cause::Idle.restarts());
    }
}
