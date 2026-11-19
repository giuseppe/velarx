// SPDX-License-Identifier: Apache-2.0
//! The monitor process: one per container, from the creation of the
//! container by the OCI runtime to the recording of its exit.
//!
//! It is a single threaded poll loop.  The monitor is the subreaper of its
//! container: the init of the container is its child once `crun create`
//! returns (a pid file that names a process that is not is refused), so its
//! pid cannot be reused while it is not reaped, and it is followed and
//! signalled only through its pidfd: the exit is a poll event, the status
//! comes from `waitid(P_PIDFD)`, and no timer runs for it.  It owns the
//! container's stdio (pipes or the terminal), writes the log, serves the
//! `attach` socket and tells the daemon what happens.

use std::collections::VecDeque;
use std::fs::File;
use std::io::{self, Write};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rustix::event::{PollFd, PollFlags};
use rustix::fs::{Mode, OFlags};
use rustix::net::{self, AddressFamily, SocketAddrUnix, SocketFlags, SocketType};
use rustix::process::Pid;

use super::clients::{Client, Kind, Pipes};
use super::config::{LogDriver, MonitorConfig};
use super::exec::{ExecSession, Reason, Which};
use super::journal::JournalWriter;
use super::notify::{self, SdNotify};
use super::oom::OomWatch;
use super::settle::Settler;
use velarx_proto::health::OnFailure;
use velarx_wire::monitor::health::{StartupOutcome, Tracker};
use velarx_wire::monitor::iface::{
    self, error, AttachReply, Call, CoreStatusReply, Empty, EventRecord, ExecExit, ExecReason,
    ExecReply, HealthReply, Info, Reason as ErrorReason, Refusal, Request, SessionPhase,
    StartReply, StatusReply, StopReply, Subscribed,
};
use velarx_wire::monitor::logfmt::{self, LogWriter, Stream};
use velarx_wire::monitor::proto::{
    self, Attach, CoreState, CoreStatus, Event, ExecRequest, ExitInfo, RunState, Status,
};
use velarx_wire::monitor::sys;
use velarx_wire::varlink::{encode_error, encode_reply, Method};

/// What one read of the container's output takes.
const READ_CHUNK: usize = 64 * 1024;

/// Queued bytes toward a client above which the container's output is not
/// read until the client catches up.
const HIGH_WATER: usize = 256 * 1024;
/// Queued bytes after which a client is dropped.
const MAX_CLIENT_QUEUE: usize = 4 * 1024 * 1024;
const MAX_CLIENTS: usize = 128;
/// A connection that has not said what it wants.
const HELLO_LIMIT: Duration = Duration::from_secs(10);
/// How long a connection stays open, its input dropped, after the last
/// packet was sent to it: a close with a packet of the client unread resets
/// the connection and the reset comes before what was sent.
const CLOSE_LINGER: Duration = Duration::from_secs(5);
/// Bytes of input waiting for the container.
const STDIN_LIMIT: usize = 256 * 1024;
/// The most of the output of a health check that is kept.
const HEALTH_OUTPUT: usize = 4096;
/// The spec of the restarts, in the run directory.
const RESTART_SPEC: &str = "restart.json";
/// The bundle of the restarts for a runtime that takes no `create --config`
/// (runc, youki): the restart spec as its `config.json`, the root file
/// system by its absolute path.
const RESTART_BUNDLE: &str = "restart-bundle";
/// A runtime command that does not return in this time is killed.
const RUNTIME_TIMEOUT: Duration = Duration::from_secs(120);

/// The start time asked of the service manager while the container is not
/// healthy yet, in microseconds; asked again at half of it.
const EXTEND_USEC: u64 = 60_000_000;

/// The pidfd of the container's init (-1: none), for the panic hook.
static CONTAINER_PIDFD: AtomicI32 = AtomicI32::new(-1);

/// When the next health check of an interval runs: none for 0 (podman's
/// `--health-interval=disable`: only `healthcheck run` checks).
fn after_interval(interval: Option<Duration>) -> Option<Instant> {
    interval.map(|d| now() + d)
}

fn now() -> Instant {
    Instant::now()
}

/// An error reply of the interface.
fn error_reply(name: &str, reason: impl Into<String>) -> Vec<u8> {
    encode_error(
        name,
        &ErrorReason {
            reason: reason.into(),
        },
    )
}

/// How the log of the container is written.
enum Logger {
    File(LogWriter),
    Journal(JournalWriter),
    Syslog(super::syslog::SyslogWriter),
    /// Several destinations (`k8s-file,syslog`): the output goes to all.
    Multi(Vec<Logger>),
    /// The terminal output goes to the output of the monitor.
    Passthrough,
    None,
}

/// Keep the first error of a series that is run to the end.
fn first_error(acc: io::Result<()>, next: io::Result<()>) -> io::Result<()> {
    acc.and(next)
}

impl Logger {
    fn write(&mut self, stream: Stream, data: &[u8]) -> io::Result<()> {
        match self {
            Logger::File(w) => w.write(stream, data),
            Logger::Journal(w) => w.write(stream, data),
            Logger::Syslog(w) => w.write(stream, data),
            // every one gets the output; the first error is told
            Logger::Multi(all) => all
                .iter_mut()
                .map(|l| l.write(stream, data))
                .fold(Ok(()), first_error),
            Logger::Passthrough => match stream {
                Stream::Stdout => io::stdout()
                    .write_all(data)
                    .and_then(|_| io::stdout().flush()),
                Stream::Stderr => io::stderr().write_all(data),
            },
            Logger::None => Ok(()),
        }
    }

    fn finish(&mut self) -> io::Result<()> {
        match self {
            Logger::File(w) => w.finish(),
            Logger::Journal(w) => w.finish(),
            Logger::Syslog(w) => w.finish(),
            Logger::Multi(all) => all.iter_mut().map(|l| l.finish()).fold(Ok(()), first_error),
            Logger::Passthrough | Logger::None => Ok(()),
        }
    }

    fn reopen(&mut self) -> io::Result<()> {
        match self {
            Logger::File(w) => w.reopen(),
            Logger::Multi(all) => all.iter_mut().map(|l| l.reopen()).fold(Ok(()), first_error),
            Logger::Journal(_) | Logger::Syslog(_) | Logger::Passthrough | Logger::None => Ok(()),
        }
    }
}

struct Init {
    pid: i32,
    pidfd: OwnedFd,
}

/// What a poll descriptor stands for.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Src {
    Signal,
    Listener,
    Init,
    Out,
    Err,
    /// The terminal: output, and input when there is some waiting.
    Pty,
    /// The pipe to the container's stdin.
    Stdin,
    /// The connection of a client.
    Client(u64),
    /// The pipes of a client's streams, with bytes waiting for it.
    ClientOut(u64),
    /// The pipe of a client's input.
    ClientIn(u64),
    Oom,
    Notify,
    /// A job thread that records or releases reported.
    Settle,
    ExecChild(u64),
    ExecOut(u64),
    ExecErr(u64),
    ExecPty(u64),
    ExecIn(u64),
    ExecConsole(u64),
}

#[derive(Default)]
struct PollSet<'a> {
    srcs: Vec<Src>,
    fds: Vec<PollFd<'a>>,
}

impl<'a> PollSet<'a> {
    fn add(&mut self, src: Src, fd: BorrowedFd<'a>, flags: PollFlags) {
        self.srcs.push(src);
        self.fds.push(PollFd::from_borrowed_fd(fd, flags));
    }

    /// The sources that are ready, and how.
    fn wait(mut self, timeout_ms: i32) -> io::Result<Vec<(Src, PollFlags)>> {
        if proto::poll(&mut self.fds, timeout_ms)? == 0 {
            return Ok(Vec::new());
        }
        Ok(self
            .srcs
            .into_iter()
            .zip(self.fds.iter().map(|f| f.revents()))
            .filter(|(_, r)| !r.is_empty())
            .collect())
    }
}

/// The exit of the init of a run.
#[derive(Clone, Copy)]
struct Exited {
    code: i32,
    /// Waiting for the end of its output until then (none: not any more).
    drain_until: Option<Instant>,
}

/// The exit of a run that is followed by a restart, and when it happens.
struct PendingRestart {
    exit: ExitInfo,
    at: Instant,
}

/// A health check in the container: the id of the exec session that runs
/// it, and when it began.
struct HealthRun {
    session: u64,
    started_ns: i64,
}

pub struct Monitor {
    cfg: MonitorConfig,
    dir: OwnedFd,
    dir_path: PathBuf,
    signals: sys::SignalGuard,
    listener: OwnedFd,
    clients: Vec<Client>,
    next_id: u64,

    state: RunState,
    init: Option<Init>,
    started_ns: Option<i64>,
    /// When the run started, by the clock that does not step: how long it
    /// ran decides whether its restarts are counted again
    started_at: Option<Instant>,
    exit: Option<ExitInfo>,
    /// Waiting for a client with `Attach::start` until then.
    pending_start: Option<Instant>,
    stop_requested: bool,

    out_r: Option<OwnedFd>,
    err_r: Option<OwnedFd>,
    pty: Option<OwnedFd>,
    stdin_w: Option<OwnedFd>,
    stdin_buf: VecDeque<u8>,
    /// Close the stdin of the container once the buffer is written.
    stdin_close: bool,
    logger: Logger,

    /// The init exited (none while it runs).
    exited: Option<Exited>,
    /// The exit is final.
    done: bool,
    /// The root file system bound where the runtime reaches it (unbound
    /// before the root file system is unmounted).
    public_root: Option<super::image::PublicRoot>,
    /// The sockets that hold the published host ports.
    held_ports: Vec<OwnedFd>,
    /// What the container gets as its descriptors 3, 4, ... at each create.
    preserved: Vec<OwnedFd>,
    /// The root file system this monitor serves, unmounted when it ends.
    rootfs: Option<super::image::Rootfs>,
    /// Records what happens to the container and releases it, by threads of
    /// the monitor.
    settler: Settler,
    /// The runtime was told to forget the container (the end of it).
    runtime_deleted: bool,
    /// The monitor was signalled, or told, to stop the container (not by a
    /// failed health check).
    asked_to_stop: bool,
    stall_limit: Duration,
    execs: Vec<ExecSession>,
    exec_seq: u64,
    oom_watch: Option<OomWatch>,
    oom: bool,
    /// Where the container sends its sd_notify messages.
    notify_sock: Option<OwnedFd>,
    ready_sent: bool,
    /// The socket of the service manager this monitor was started under.
    notify_target: Option<String>,
    /// When to ask the service manager for more start time again.
    extend_next: Option<Instant>,
    tracker: Option<Tracker>,
    health_next: Option<Instant>,
    /// The check that is running.
    health_run: Option<HealthRun>,
    /// Clients waiting for the result of a check they asked for.
    health_waiters: Vec<u64>,
    /// Clients of `Stop` and `Wait`, answered once the exit is recorded.
    stop_waiters: Vec<u64>,
    wait_waiters: Vec<u64>,
    /// The clients of `Remove`, answered once the container is removed
    remove_waiters: Vec<u64>,
    /// A container that never ran goes (`Remove` while created): its end is
    /// the removal, there is no exit to settle
    removing_created: bool,
    /// What the exit for good came to, told to the clients
    settled_told: Option<proto::Settled>,
    /// SIGKILL was needed to stop the container.
    killed: bool,
    /// The runtime froze the container.
    paused: bool,
    /// What happens at the exit for good.
    plan: proto::ExitPlan,
    health_restart: bool,
    /// When a container that was asked to stop by a failing health check is
    /// killed.
    stop_kill_at: Option<Instant>,
    /// The lock that tells the monitor lives, held until it ends.
    _identity: File,
    /// When a container with a time limit is killed.
    run_deadline: Option<Instant>,
    timed_out: bool,
    /// A zombie that is not ours to reap was in the way: look again.
    reap_pending: bool,
    /// The restarts made by the restart policy.
    restart_count: u32,
    /// The exit of a run that is followed by a restart.
    restart: Option<PendingRestart>,
    /// The run was started by the restart policy.
    restarted: bool,
    /// The namespaces of the first run, joined by the next ones.
    pinned: super::restart::Pinned,
    /// The network namespace of the container, held for the life of the
    /// monitor: the descriptor the engine made it with and passed on
    /// (`MonitorConfig::netns_fd`), else the one of the process of the
    /// first run, which the runtime made.  The runtime joins it by
    /// `/proc/self/fd/N`, and the monitor is given it to take the
    /// network down.
    netns: Option<Arc<OwnedFd>>,
    /// The directory of the file of the health results (`<id>-healthcheck.log`),
    /// when the check writes one: the engine's descriptor, replaced by
    /// `Update`.
    health_log_dir: Option<OwnedFd>,
    /// The rootless namespace of the bridge networks, held for life: the
    /// monitor is one of its holders.
    bridge_netns: Option<OwnedFd>,
    /// The spec of the runs after the first: the bundle's, with the pinned
    /// namespaces.
    restart_spec: Option<PathBuf>,
    /// The process of the spec the run was created with: what an exec runs
    /// on (an update of the bundle's spec is for the next start).
    run_process: Option<serde_json::Value>,
    /// The checkpoint to restore at the first creation (`Create(restore)`):
    /// what it asks, and its directory of images.
    restore: Option<(velarx_wire::monitor::proto::RestoreRequest, OwnedFd)>,
    /// CRIU ended the container on a checkpoint.
    checkpointed: bool,
    /// Run in the process that runs the container (`run --no-monitor`).
    in_process: bool,
    /// Where the first call of the boot connection, `Create`, is.
    created: Created,
    /// The container was restored: it runs, and its start is told once
    /// `Create` is answered.
    restored: bool,
}

/// Where `Create` is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Created {
    /// Not called yet: the monitor serves only the boot connection.
    Waiting,
    /// The container is made.
    Done,
    /// It could not be made: the monitor ends once it answered.
    Failed,
}

fn set_nonblocking(fd: &OwnedFd) -> io::Result<()> {
    rustix::fs::fcntl_setfl(fd, OFlags::NONBLOCK).map_err(io::Error::from)
}

pub(super) fn diag(msg: &str) {
    let _ = writeln!(
        io::stderr(),
        "{} {}",
        logfmt::format_rfc3339_ns(logfmt::now_ns()),
        msg
    );
}

/// The entry point of `velarx-monitor --varlink-fd N RUNDIR`.
pub fn main(startup: &velarx_sys::fd::Startup) -> i32 {
    monitor_main(std::env::args_os().skip(1), startup)
}

/// What the command line of `velarx-monitor` asks for.
#[derive(Debug, PartialEq, Eq)]
enum Invocation {
    /// `--image-server`: the layers of an image for the driver.
    ImageServer,
    /// `--varlink-fd N RUNDIR`: the monitor of the container of `RUNDIR`,
    /// whose first connection is the descriptor `N`.
    Monitor { varlink_fd: i32, dir: PathBuf },
}

/// The argument that makes the binary an image server.
pub const IMAGE_SERVER_FLAG: &str = "--image-server";

const USAGE: &str = "usage: velarx-monitor --varlink-fd N RUNDIR | velarx-monitor --image-server";

fn parse_command(args: impl IntoIterator<Item = std::ffi::OsString>) -> Result<Invocation, String> {
    let args: Vec<_> = args.into_iter().collect();
    match args.as_slice() {
        [flag] if flag == IMAGE_SERVER_FLAG => Ok(Invocation::ImageServer),
        [flag, n, dir] if flag == "--varlink-fd" => {
            let varlink_fd = n
                .to_str()
                .and_then(|n| n.parse::<i32>().ok())
                .filter(|n| *n >= 3)
                .ok_or_else(|| format!("--varlink-fd takes a descriptor number, not {n:?}"))?;
            Ok(Invocation::Monitor {
                varlink_fd,
                dir: PathBuf::from(dir),
            })
        }
        _ => Err(USAGE.to_string()),
    }
}

/// The monitor with the arguments after its name: the binary of its own
/// calls this with its arguments, a subcommand of another binary with
/// what follows `monitor`.  Everything the monitor needs is in the run
/// directory and the descriptors it was passed; nothing assumes who started
/// it.
pub fn monitor_main(
    args: impl IntoIterator<Item = std::ffi::OsString>,
    startup: &velarx_sys::fd::Startup,
) -> i32 {
    let (varlink_fd, dir) = match parse_command(args) {
        Ok(Invocation::Monitor { varlink_fd, dir }) => (varlink_fd, dir),
        // (the same binary serves the layers of an image for the driver)
        #[cfg(feature = "fuse")]
        Ok(Invocation::ImageServer) => return crate::imageserver::main(startup),
        #[cfg(not(feature = "fuse"))]
        Ok(Invocation::ImageServer) => {
            eprintln!("velarx-monitor: built without --image-server");
            return 2;
        }
        Err(why) => {
            eprintln!("{why}");
            return 2;
        }
    };
    if let Err(e) = velarx_base::cgroup::require_v2() {
        diag(&format!("monitor failed: {e}"));
        return 1;
    }
    match run(
        &dir,
        Launch::Process {
            startup,
            varlink_fd,
        },
    ) {
        Ok(code) => code,
        Err(e) => {
            diag(&format!("monitor failed: {e}"));
            1
        }
    }
}

/// Where the panic message of the monitor goes, and what happens to the
/// container: without its monitor it cannot be stopped or reaped.
fn install_panic_hook() {
    let default = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        diag(&format!("panic: {info}"));
        velarx_sys::pidfd::kill_raw(CONTAINER_PIDFD.load(Ordering::Relaxed));
        default(info);
    }));
}

/// How the monitor runs.
pub enum Launch<'a> {
    /// A process of its own (`velarx-monitor --varlink-fd N RUNDIR`): the
    /// first connection is its descriptor `varlink_fd`, the others are
    /// named by `MonitorConfig::fds`.  The token is the claim that they are
    /// the numbers the starter passed.
    Process {
        startup: &'a velarx_sys::fd::Startup,
        varlink_fd: i32,
    },
    /// In the process that runs the container in the foreground (`run
    /// --no-monitor`), which keeps its session and its terminal, and whose
    /// client part (with copies of the standard streams, which go to the
    /// log of the monitor as for a process of its own) forwards the signals
    /// it gets to the container.
    InProcess {
        boot: OwnedFd,
        preserved: Vec<OwnedFd>,
        /// The signals that stop the container (as for a monitor of its
        /// own), besides SIGCHLD; the others are the client's.
        stop_signals: Vec<i32>,
        /// The `NOTIFY_SOCKET` of the engine's service manager, if the
        /// container may talk to it.
        notify_socket: Option<String>,
        /// Variables the commands of the monitor get in addition.
        env: Vec<(String, String)>,
        /// The mounts of the root file system (`MonitorConfig::rootfs_fds`)
        rootfs_fds: Vec<OwnedFd>,
        /// The network namespace of the container, if the engine made it
        /// (`MonitorConfig::netns_fd`).
        netns: Option<OwnedFd>,
        /// The directory of the health log (`InheritedFds::health_log_dir`).
        health_log_dir: Option<OwnedFd>,
        /// The rootless namespace of the bridge networks
        /// (`InheritedFds::bridge_netns`).
        bridge_netns: Option<OwnedFd>,
    },
}

/// What the commands of an in-process monitor get besides the environment
/// of the process (the process is the engine's: its own environment is
/// not changed).
static CHILD_ENV: std::sync::OnceLock<Vec<(String, String)>> = std::sync::OnceLock::new();

/// A command of the monitor (the runtime, the hooks, pasta): it sees
/// neither the service manager of the process that started the monitor nor
/// the scope the monitor was asked to enter, which are the monitor's alone.
/// It is started by [`spawn_child`] (an exec sets the limit itself).
pub(super) fn child_command(program: impl AsRef<std::ffi::OsStr>) -> Command {
    let mut cmd = Command::new(program);
    cmd.env_remove("NOTIFY_SOCKET")
        .env_remove(velarx_base::spawn::SCOPE_ENV);
    for (k, v) in CHILD_ENV.get().into_iter().flatten() {
        if k != "NOTIFY_SOCKET" {
            cmd.env(k, v);
        }
    }
    cmd
}

/// Run the monitor of the run directory `dir_path` until it is done; the
/// exit status of its process.
/// Start a command of [`child_command`] with the soft limit of open files
/// the engine's user gave (`MonitorConfig::open_files`), not the raised one
/// of the monitor: the spec's rlimits are the runtime's to apply.  The limit
/// is set last in the child, after the descriptors are placed (the low ones
/// of a monitor that holds many published ports are all in use).
pub(super) fn spawn_child(
    cmd: &mut Command,
    cfg: &MonitorConfig,
) -> io::Result<std::process::Child> {
    velarx_base::hardening::restore_open_files(cmd, cfg.open_files);
    cmd.spawn()
}

pub fn run_in_process(dir_path: &Path, launch: Launch<'_>) -> io::Result<i32> {
    run(dir_path, launch)
}

/// Move to the transient scope the engine named (`spawn::SCOPE_ENV`), so
/// that the monitor of a container does not go with the scope of the
/// command that started it (a terminal, a tmux server, a CI job).  A
/// manager that does not make it leaves the monitor where it is: it only
/// loses that protection.  A monitor that cannot tell whose manager to ask
/// (its uid map is unreadable) does not go on: it is an error of the host.
fn enter_scope() -> io::Result<()> {
    let Some(unit) = std::env::var_os(velarx_base::spawn::SCOPE_ENV) else {
        return Ok(());
    };
    // (not for what the monitor starts: `child_command`)
    let Some(unit) = unit.to_str() else {
        return Ok(());
    };
    let system = crate::manager::system_manager().map_err(io::Error::other)?;
    let pid = std::process::id();
    if let Err(e) =
        velarx_wire::sdbus::start_scope(system, unit, "velarx monitor", &[pid], false, None, true)
    {
        diag(&format!("no scope {unit}: {e}"));
    }
    velarx_base::trace::point("scope requested");
    Ok(())
}

fn run(dir_path: &Path, launch: Launch<'_>) -> io::Result<i32> {
    velarx_base::trace::point("monitor start");
    enter_scope()?;
    rustix::process::umask(Mode::from_raw_mode(0o077));
    let mut cfg = MonitorConfig::read(dir_path)?;
    let in_process = matches!(launch, Launch::InProcess { .. });
    // The mount namespace the monitor started in, where the mounts of the
    // engine are: the jobs that unmount (the removal of an `--rm` container)
    // work in it.
    let mut settler = Settler::new(cfg.settle.clone())?;
    // The service manager of the process that started us is ours alone:
    // what the monitor starts does not see it (`child_command`).
    let notify_target = match &launch {
        Launch::Process { .. } => std::env::var("NOTIFY_SOCKET").ok(),
        Launch::InProcess { notify_socket, .. } => notify_socket.clone(),
    }
    .filter(|t| notify::valid_target(t));
    let netns: Option<Arc<OwnedFd>>;
    let health_log_dir: Option<OwnedFd>;
    let bridge_netns: Option<OwnedFd>;
    let (boot, preserved, signal_set) = match launch {
        Launch::Process {
            startup,
            varlink_fd,
        } => {
            velarx_wire::proctitle::set_cmdline(
                format!(
                    "velarx-monitor: {} {} {}",
                    &cfg.id[..cfg.id.len().min(12)],
                    cfg.log.name,
                    cfg.log.image
                )
                .trim_end(),
            );
            if cfg.leave_parent {
                leave_parent()?;
            }
            netns = netns_fd(startup, &cfg)?;
            health_log_dir = health_log_dir_fd(startup, &cfg)?;
            bridge_netns = bridge_netns_fd(startup, &cfg)?;
            settler.set_netns(netns.clone());
            if cfg.private_mounts {
                // before any mount and any thread
                settler.set_outer_mnt(Some(velarx_nsid::open_of(
                    "thread-self",
                    velarx_nsid::Kind::Mnt,
                )?));
                super::image::private_mount_namespace()?;
            }
            // A session of its own: the monitor outlives the daemon and its
            // terminal.
            let _ = rustix::process::setsid();
            // The daemon's end of the first connection is a descriptor
            // handed down.
            let boot = boot_fd(startup, varlink_fd)?;
            let preserved = preserved_fds(startup, &cfg.fds.preserved);
            super::image::keep_mount_fds(rootfs_fds(startup, &cfg.fds.rootfs));
            if cfg.log.driver != LogDriver::Passthrough {
                redirect_stdio(dir_path)?;
            }
            let signals = vec![
                libc::SIGCHLD,
                libc::SIGTERM,
                libc::SIGINT,
                libc::SIGHUP,
                libc::SIGUSR1,
            ];
            (boot, preserved, signals)
        }
        Launch::InProcess {
            boot,
            preserved,
            stop_signals,
            notify_socket: _,
            env,
            rootfs_fds,
            netns: handed_netns,
            health_log_dir: handed_log_dir,
            bridge_netns: handed_bridge,
        } => {
            health_log_dir = handed_log_dir;
            bridge_netns = handed_bridge;
            let _ = CHILD_ENV.set(env);
            super::image::keep_mount_fds(rootfs_fds.into_iter().map(Some).collect());
            netns = handed_netns.map(Arc::new);
            settler.set_netns(netns.clone());
            // The process is already where it belongs (the main process of
            // a unit, a child of a shell).
            cfg.leave_parent = false;
            if cfg.private_mounts {
                // before any mount; unshare(CLONE_NEWNS) moves this thread
                // only, the monitor's, which forks the runtime and serves
                // FUSE (the attach thread only moves stream data)
                settler.set_outer_mnt(Some(velarx_nsid::open_of(
                    "thread-self",
                    velarx_nsid::Kind::Mnt,
                )?));
                super::image::private_mount_namespace()?;
            }
            // What the monitor says goes to its log as for a process of its
            // own; the client part has its own copies of the streams.
            if cfg.log.driver != LogDriver::Passthrough {
                redirect_stdio(dir_path)?;
            }
            let mut signals = vec![libc::SIGCHLD];
            signals.extend(stop_signals);
            (boot, preserved, signals)
        }
    };
    install_panic_hook();
    if cfg.image.is_some() {
        // What the file system and the fetches say goes to `monitor.log`
        // (with passthrough standard error is the caller's, which the
        // container writes to: nothing of the monitor's goes there).
        // (debug when the engine's is, for an enforced image: the links
        // of its chain of trust, `image::mount`; a few lines a start)
        let level = match cfg.image.as_ref().is_some_and(|i| i.debug && i.enforce) {
            true => tracing::Level::DEBUG,
            false => tracing::Level::INFO,
        };
        let logger = tracing_subscriber::fmt()
            .with_max_level(level)
            .with_ansi(false);
        let _ = if cfg.log.driver == LogDriver::Passthrough {
            open_monitor_log(dir_path)
                .ok()
                .map(|log| logger.with_writer(std::sync::Mutex::new(log)).try_init())
        } else {
            Some(logger.with_writer(std::io::stderr).try_init())
        };
    }

    let signals = sys::SignalGuard::new(&signal_set)?;
    rustix::process::set_child_subreaper(Some(rustix::process::getpid()))?;

    let dir = rustix::fs::open(
        dir_path,
        OFlags::DIRECTORY | OFlags::PATH | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    // (before the socket: from here on the monitor is known to live)
    let identity = super::hold_identity(dir.as_fd())?;
    let _ = rustix::fs::unlinkat(&dir, proto::EXIT_FILE, rustix::fs::AtFlags::empty());
    let _ = rustix::fs::unlinkat(&dir, proto::SOCKET, rustix::fs::AtFlags::empty());
    let listener = net::socket_with(
        AddressFamily::UNIX,
        SocketType::STREAM,
        SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
        None,
    )?;
    net::bind(
        &listener,
        &SocketAddrUnix::new(proto::socket_path(&dir, proto::SOCKET))?,
    )?;
    net::listen(&listener, 16)?;

    let logger = open_logger(&cfg)?;
    let cfg_stall_ms = cfg.client_stall_ms;
    let restart_count = cfg.restart.count;

    // (`--rm` removes its anonymous volumes)
    let plan = proto::ExitPlan {
        remove: cfg.auto_remove,
        volumes: true,
    };
    let mut m = Monitor {
        cfg,
        dir,
        dir_path: dir_path.to_path_buf(),
        signals,
        listener,
        clients: Vec::new(),
        next_id: 1,
        state: RunState::Created,
        init: None,
        started_ns: None,
        started_at: None,
        exit: None,
        pending_start: None,
        stop_requested: false,
        out_r: None,
        err_r: None,
        pty: None,
        stdin_w: None,
        stdin_buf: VecDeque::new(),
        stdin_close: false,
        logger,
        exited: None,
        done: false,
        public_root: None,
        held_ports: Vec::new(),
        preserved,
        rootfs: None,
        settler,
        runtime_deleted: false,
        asked_to_stop: false,
        stall_limit: Duration::from_millis(cfg_stall_ms),
        execs: Vec::new(),
        exec_seq: 0,
        oom_watch: None,
        oom: false,
        notify_sock: None,
        ready_sent: false,
        notify_target,
        extend_next: None,
        tracker: None,
        health_next: None,
        health_run: None,
        health_log_dir,
        bridge_netns,
        health_waiters: Vec::new(),
        stop_waiters: Vec::new(),
        wait_waiters: Vec::new(),
        remove_waiters: Vec::new(),
        removing_created: false,
        settled_told: None,
        killed: false,
        paused: false,
        plan,
        health_restart: false,
        stop_kill_at: None,
        _identity: identity,
        run_deadline: None,
        timed_out: false,
        reap_pending: false,
        restart_count,
        restart: None,
        restarted: false,
        pinned: Default::default(),
        netns,
        restart_spec: None,
        run_process: None,
        restore: None,
        checkpointed: false,
        in_process,
        created: Created::Waiting,
        restored: false,
    };
    // The first call of the boot connection, which the engine wrote before
    // it started us, is `Create`: the container is made when it is answered.
    rustix::fs::fcntl_setfl(&boot, OFlags::NONBLOCK)?;
    let boot = m.add_client(boot);
    m.serve_create(boot)?;
    if m.created == Created::Failed {
        m.flush_all(Duration::from_secs(2));
        m.release_mounts();
        m.cleanup_files();
        return Ok(1);
    }
    if m.restored {
        m.mark_started();
    }
    m.join_bridge_netns();
    m.event_loop();
    // Before the socket goes: a client that sees the monitor gone may start
    // the container again on the same mount points.
    m.release_mounts();
    m.cleanup_files();
    m.leave_cgroups();
    // The root file system is released first: the monitor removes
    // what is under it.
    m.rootfs = None;
    m.settler.finish();
    // The clients have the rest of the output, as long as they read it: one
    // that is only slow is no stalled one (the container is gone already).
    let limit = m.stall_limit.max(Duration::from_secs(2));
    m.flush_all(limit);
    // (the jobs write the store back after they reported: the clients that
    // wait for the end of the container are told already)
    m.settler.wait_ended();
    // The status of the container, so that a service manager that runs the
    // monitor sees how the container ended (`Restart=on-failure`).  For the
    // main process of a unit, a stop that was asked for (`systemctl stop`,
    // `velarx stop`) is a clean end, whatever the stop signal made of the
    // status.
    // (a published --conmon-pidfile is a unit's PIDFile=)
    let unit = m.cfg.leave_parent || m.notify_target.is_some() || m.cfg.monitor_pid_file.is_some();
    Ok(match &m.exit {
        Some(_) if m.asked_to_stop && unit => 0,
        Some(e) => e.code & 0xff,
        None => 0,
    })
}

/// Go on in a child of this process, which exits: the monitor is then a
/// child of the service manager (the subreaper of the unit), not of the
/// command that started it.  systemd waits for the exit of a main process
/// (`MAINPID=`) only if it is its own child; it kills one that is not at
/// once when the unit stops, and the container gets no stop signal.
fn leave_parent() -> io::Result<()> {
    match velarx_sys::process::fork_single_threaded("the monitor")? {
        velarx_sys::process::Fork::Child(_) => Ok(()),
        // leave without running destructors or flushing: the child owns
        // everything
        velarx_sys::process::Fork::Parent(_) => velarx_sys::process::exit_now(0),
    }
}

/// Whether `fd` is a directory: what a call names as one is checked before
/// the runtime is given its path.
fn is_dir(fd: &OwnedFd) -> bool {
    rustix::fs::fstat(fd).is_ok_and(|st| rustix::fs::FileType::from_raw_mode(st.st_mode).is_dir())
}

/// Where the directory of a descriptor is, by the kernel's name for it.
fn fd_path(fd: &OwnedFd) -> io::Result<PathBuf> {
    std::fs::read_link(format!("/proc/self/fd/{}", fd.as_raw_fd()))
}

/// The path of the directory `to` from the directory `from` (both
/// absolute): the way up to what they share, then down.
fn relative_path(from: &Path, to: &Path) -> PathBuf {
    let (from, to): (Vec<_>, Vec<_>) = (from.components().collect(), to.components().collect());
    let shared = from.iter().zip(&to).take_while(|(a, b)| a == b).count();
    let mut out = PathBuf::new();
    for _ in &from[shared..] {
        out.push("..");
    }
    for name in &to[shared..] {
        out.push(name);
    }
    out
}

/// Write `data` to `name` of the directory `dir` as a whole: a temporary file
/// next to it, renamed over it.
fn write_whole_at(dir: &OwnedFd, name: &str, data: &[u8], mode: u32) -> io::Result<()> {
    use rustix::fs::{openat, renameat, unlinkat, AtFlags, Mode, OFlags};
    use std::io::Write;
    let tmp = format!(".{name}.{}.tmp", std::process::id());
    let written = (|| {
        let fd = openat(
            dir,
            tmp.as_str(),
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_raw_mode(mode),
        )?;
        File::from(fd).write_all(data)?;
        renameat(dir, tmp.as_str(), dir, name)?;
        io::Result::Ok(())
    })();
    if written.is_err() {
        let _ = unlinkat(dir, tmp.as_str(), AtFlags::empty());
    }
    written
}

/// Write `pid` to the file `path` as a whole: a temporary file next to it,
/// renamed over it, readable by all as podman's (the umask of the monitor
/// is 077).
fn write_pid_file(path: &Path, pid: i32) -> io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let (Some(dir), Some(name)) = (path.parent(), path.file_name()) else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid pid file {}", path.display()),
        ));
    };
    let mut tmp_name = std::ffi::OsString::from(".");
    tmp_name.push(name);
    tmp_name.push(format!(".{}.tmp", std::process::id()));
    let tmp = dir.join(tmp_name);
    let written = (|| {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .mode(0o644)
            .open(&tmp)?;
        f.set_permissions(std::fs::Permissions::from_mode(0o644))?;
        f.write_all(pid.to_string().as_bytes())?;
        std::fs::rename(&tmp, path)
    })();
    if written.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    written.map_err(|e| io::Error::new(e.kind(), format!("pid file {}: {e}", path.display())))
}

/// The descriptors to hand to the container: what the process that started
/// us passed (`spawn::SpawnOptions::preserve_fds`), at the numbers the
/// configuration names.  At most `spawn::MAX_PRESERVED_FDS`; one that is not
/// open ends the list.
fn preserved_fds(startup: &velarx_sys::fd::Startup, numbers: &[i32]) -> Vec<OwnedFd> {
    let count = numbers.len().min(velarx_base::spawn::MAX_PRESERVED_FDS);
    let mut out = Vec::with_capacity(count);
    for &raw in &numbers[..count] {
        // (passed to us on purpose)
        let Some(fd) = startup.adopt(raw) else {
            break;
        };
        if rustix::io::fcntl_setfd(&fd, rustix::io::FdFlags::CLOEXEC).is_err() {
            break;
        }
        out.push(fd);
    }
    out
}

/// The mounts the engine made for the root file system
/// (`MonitorConfig::fds`), by their place, `None` for one that is not
/// open.  Kept for the life of the monitor and not passed to the container.
fn rootfs_fds(startup: &velarx_sys::fd::Startup, numbers: &[i32]) -> Vec<Option<OwnedFd>> {
    let count = numbers.len().min(velarx_base::spawn::MAX_ROOTFS_FDS);
    numbers[..count]
        .iter()
        .map(|&raw| {
            // (passed to us on purpose)
            let fd = startup.adopt(raw)?;
            rustix::io::fcntl_setfd(&fd, rustix::io::FdFlags::CLOEXEC).ok()?;
            Some(fd)
        })
        .collect()
}

/// The network namespace the engine made for the container, held for the
/// life of the monitor.  Its absence is an error: the spec names it, and
/// the runtime would find another descriptor, or none, at its number.
fn netns_fd(
    startup: &velarx_sys::fd::Startup,
    cfg: &MonitorConfig,
) -> io::Result<Option<Arc<OwnedFd>>> {
    let Some(raw) = cfg.fds.netns else {
        return Ok(None);
    };
    // (passed to us on purpose)
    let fd = startup.adopt(raw).ok_or_else(|| {
        io::Error::other(format!(
            "the network namespace of the container is not descriptor {raw}"
        ))
    })?;
    rustix::io::fcntl_setfd(&fd, rustix::io::FdFlags::CLOEXEC)?;
    Ok(Some(Arc::new(fd)))
}

/// The directory the results of the health checks are written to
/// (`InheritedFds::health_log_dir`), when the configuration names one.
fn health_log_dir_fd(
    startup: &velarx_sys::fd::Startup,
    cfg: &MonitorConfig,
) -> io::Result<Option<OwnedFd>> {
    let Some(raw) = cfg.fds.health_log_dir else {
        return Ok(None);
    };
    let fd = startup.adopt(raw).ok_or_else(|| {
        io::Error::other(format!(
            "the directory of the health log is not descriptor {raw}"
        ))
    })?;
    rustix::io::fcntl_setfd(&fd, rustix::io::FdFlags::CLOEXEC)?;
    Ok(Some(fd))
}

/// The rootless namespace of the bridge networks (`InheritedFds::bridge_netns`),
/// when the configuration names one: held for the life of the monitor.
fn bridge_netns_fd(
    startup: &velarx_sys::fd::Startup,
    cfg: &MonitorConfig,
) -> io::Result<Option<OwnedFd>> {
    let Some(raw) = cfg.fds.bridge_netns else {
        return Ok(None);
    };
    let fd = startup.adopt(raw).ok_or_else(|| {
        io::Error::other(format!(
            "the rootless network namespace is not descriptor {raw}"
        ))
    })?;
    rustix::io::fcntl_setfd(&fd, rustix::io::FdFlags::CLOEXEC)?;
    Ok(Some(fd))
}

/// The first connection, `--varlink-fd`: a descriptor handed down on
/// purpose.  Its absence is an error.
fn boot_fd(startup: &velarx_sys::fd::Startup, raw: i32) -> io::Result<OwnedFd> {
    let fd = startup
        .adopt(raw)
        .ok_or_else(|| io::Error::other(format!("--varlink-fd {raw} is not open")))?;
    rustix::io::fcntl_setfd(&fd, rustix::io::FdFlags::CLOEXEC)?;
    Ok(fd)
}

/// The monitor's own log in its directory.
fn open_monitor_log(dir: &Path) -> io::Result<File> {
    File::options()
        .create(true)
        .append(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(dir.join(proto::LOG_FILE))
}

/// stdin from /dev/null, stdout and stderr to `monitor.log`: the
/// descriptors of the daemon are not kept.
fn redirect_stdio(dir: &Path) -> io::Result<()> {
    let null = File::options().read(true).write(true).open("/dev/null")?;
    rustix::stdio::dup2_stdin(&null)?;
    let log = open_monitor_log(dir).unwrap_or_else(|e| {
        // (stderr is still the starter's: it is what shows the failure)
        diag(&format!(
            "cannot open {}: {e}",
            dir.join(proto::LOG_FILE).display()
        ));
        null
    });
    rustix::stdio::dup2_stdout(&log)?;
    rustix::stdio::dup2_stderr(&log)?;
    Ok(())
}

/// Delete what the runtime holds of a container that failed to start.
fn forget_failed(cfg: &MonitorConfig) {
    match run_runtime(cfg, &["delete", "--force", &cfg.id]) {
        Ok((true, _)) => {}
        Ok((false, text)) => diag(&format!("delete of {} failed: {}", cfg.id, text.trim())),
        Err(e) => diag(&format!("delete of {} failed: {e}", cfg.id)),
    }
}

fn open_logger(cfg: &MonitorConfig) -> io::Result<Logger> {
    let open = |driver: LogDriver| -> io::Result<Logger> {
        Ok(match driver {
            LogDriver::K8sFile => Logger::File(LogWriter::open_in(
                &cfg.log.path,
                cfg.log.allow_dir.as_deref(),
                cfg.log.limits(),
            )?),
            LogDriver::Journald => Logger::Journal(JournalWriter::open(&cfg.id, &cfg.log)?),
            LogDriver::Syslog => {
                Logger::Syslog(super::syslog::SyslogWriter::open(&cfg.id, &cfg.log)?)
            }
            LogDriver::Passthrough => Logger::Passthrough,
            LogDriver::None => Logger::None,
        })
    };
    let first = open(cfg.log.driver)?;
    if cfg.log.also.is_empty() {
        return Ok(first);
    }
    let mut all = vec![first];
    for &d in &cfg.log.also {
        all.push(open(d)?);
    }
    Ok(Logger::Multi(all))
}

/// `--lsm-profile` and `--lsm-mount-context` of a restore, from the
/// configuration of the container: the restored processes get its labels,
/// whatever the images of CRIU say.
fn restore_lsm_args(config: &Path) -> io::Result<Vec<String>> {
    let spec: serde_json::Value = serde_json::from_slice(&std::fs::read(config)?)
        .map_err(|e| io::Error::other(format!("{}: {e}", config.display())))?;
    let text = |p: &str| {
        spec.pointer(p)
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(str::to_string)
    };
    let mut args = Vec::new();
    match (
        text("/process/selinuxLabel"),
        text("/process/apparmorProfile"),
    ) {
        (Some(l), _) => args.push(format!("--lsm-profile=selinux:{l}")),
        (None, Some(p)) => args.push(format!("--lsm-profile=apparmor:{p}")),
        (None, None) => {}
    }
    if let Some(m) = text("/linux/mountLabel") {
        args.push(format!("--lsm-mount-context={m}"));
    }
    Ok(args)
}

fn pipe() -> io::Result<(OwnedFd, OwnedFd)> {
    rustix::pipe::pipe_with(rustix::pipe::PipeFlags::CLOEXEC).map_err(io::Error::from)
}

/// A runtime command: its status and what it wrote to its stderr.
fn run_runtime(cfg: &MonitorConfig, args: &[&str]) -> io::Result<(bool, String)> {
    let (err_r, err_w) = pipe()?;
    set_nonblocking(&err_r)?;
    let mut cmd = child_command(&cfg.runtime);
    cmd.args(&cfg.runtime_args)
        .arg("--root")
        .arg(&cfg.runtime_root)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::from(err_w));
    velarx_sys::spawn::pre_exec(&mut cmd, |child| child.unblock_signals());
    let child = spawn_child(&mut cmd, cfg)?;
    drop(cmd);
    let pidfd = velarx_sys::pidfd::open_child(child.id() as i32)?;
    let mut text = Vec::new();
    let deadline = now() + RUNTIME_TIMEOUT;
    // (a closed standard error is not polled again, and a runtime that was
    // killed is waited for without a time: its end is the event)
    let (mut err_open, mut killed) = (true, false);
    let status = loop {
        let left = if killed {
            -1
        } else {
            deadline
                .saturating_duration_since(now())
                .as_millis()
                .min(i32::MAX as u128) as i32
        };
        let mut fds = [
            PollFd::new(&pidfd, PollFlags::IN),
            PollFd::new(&err_r, PollFlags::IN),
        ];
        let watched = if err_open { 2 } else { 1 };
        let n = proto::poll(&mut fds[..watched], left)?;
        if err_open && !fds[1].revents().is_empty() {
            err_open = !read_some(&err_r, &mut text, 16 * 1024);
        }
        if n == 0 && !killed {
            let _ = rustix::process::pidfd_send_signal(&pidfd, rustix::process::Signal::KILL);
            killed = true;
        }
        if let Some(st) = velarx_sys::pidfd::reap(&pidfd)? {
            break st;
        }
    };
    read_some(&err_r, &mut text, 16 * 1024);
    Ok((
        status == 0,
        String::from_utf8_lossy(&text).trim().to_string(),
    ))
}

/// Append what is readable from `fd` to `out`, up to `limit` bytes.  Whether
/// the end of the stream was read.
fn read_some(fd: &OwnedFd, out: &mut Vec<u8>, limit: usize) -> bool {
    let mut buf = [0u8; 4096];
    while let Ok(n) = rustix::io::read(fd, &mut buf) {
        if n == 0 {
            return true;
        }
        let room = limit.saturating_sub(out.len());
        out.extend_from_slice(&buf[..n.min(room)]);
    }
    false
}

impl Monitor {
    fn add_client(&mut self, conn: OwnedFd) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        self.clients.push(Client::new(id, conn, now()));
        id
    }

    fn client(&mut self, id: u64) -> Option<&mut Client> {
        self.clients.iter_mut().find(|c| c.id == id)
    }

    /// `MAINPID=` of this monitor for the unit's manager: none in process,
    /// where the main process of the unit stays the one it started.
    fn main_pid_line(&self) -> String {
        if self.in_process {
            String::new()
        } else {
            format!("MAINPID={}\n", std::process::id())
        }
    }

    /// Serve the boot connection `id` until `Create`, its first call, is
    /// answered (an error when the connection ends before).
    fn serve_create(&mut self, id: u64) -> io::Result<()> {
        let conn = self
            .client(id)
            .ok_or_else(|| io::Error::other("no boot connection"))?
            .conn()
            .try_clone_to_owned()?;
        while self.created == Created::Waiting {
            if self.client(id).is_none_or(|c| c.gone || c.hung_up) {
                return Err(io::Error::other(
                    "the boot connection ended before `Create`",
                ));
            }
            let mut fds = [PollFd::new(&conn, PollFlags::IN)];
            match rustix::event::poll(&mut fds, None) {
                Ok(_) | Err(rustix::io::Errno::INTR) => {}
                Err(e) => return Err(e.into()),
            }
            let revents = fds[0].revents();
            self.handle_client(id, revents);
        }
        Ok(())
    }

    /// `Create`: make the container, or restore it, and the files a service
    /// manager waits for before the answer that lets `run -d` return.
    fn create_call(&mut self, id: u64, p: velarx_wire::monitor::proto::CreateParams) -> Vec<u8> {
        if self.created != Created::Waiting {
            return error_reply(error::INVALID_STATE, "the container was created already");
        }
        let mut received = self
            .client(id)
            .map(|c| c.take_received())
            .unwrap_or_default();
        if let Some(r) = p.restore {
            let at = r.image_dir as usize;
            if at >= received.len() {
                self.created = Created::Failed;
                return error_reply(
                    error::INVALID_ARGUMENT,
                    "restore: the directory of the images is not among the descriptors",
                );
            }
            let dir = received.swap_remove(at);
            if !is_dir(&dir) {
                self.created = Created::Failed;
                return error_reply(
                    error::INVALID_ARGUMENT,
                    "restore: the images are not a directory",
                );
            }
            self.restore = Some((r, dir));
        }
        let restored = self.restore.is_some();
        // --conmon-pidfile: the pid that stays (after leaving the parent),
        // once there is a container
        let created = self.create();
        velarx_base::trace::point("monitor created");
        let created = created.and_then(|()| match &self.cfg.monitor_pid_file {
            Some(path) => write_pid_file(path, rustix::process::getpid().as_raw_nonzero().get()),
            None => Ok(()),
        });
        // A monitor that left its parent (a unit's) has a pid of its own: the
        // one a unit made by `generate systemd` waits for
        let created = created.and_then(|()| {
            if self.cfg.leave_parent {
                write_pid_file(
                    &self.dir_path.join(super::MONITOR_PID_FILE),
                    rustix::process::getpid().as_raw_nonzero().get(),
                )
            } else {
                Ok(())
            }
        });
        match created {
            Ok(()) => {
                self.created = Created::Done;
                if restored {
                    // it runs: the answer says so, then the event follows
                    self.state = RunState::Running;
                    self.restored = true;
                }
                encode_reply(
                    &StatusReply {
                        status: self.status(),
                    },
                    false,
                )
            }
            Err(e) => {
                diag(&format!("create failed: {e}"));
                // (a restore that failed half way: what CRIU restored and the
                // state of the runtime go, the pid file may be missing; or the
                // runtime made it and a pid file could not be written)
                if restored || self.init.is_some() {
                    self.kill_init();
                    forget_failed(&self.cfg);
                }
                self.created = Created::Failed;
                error_reply(error::FAILED, e.to_string())
            }
        }
    }

    fn broadcast_event(&mut self, event: &Event) {
        // (the exit is recorded by the exit job, once the container is
        // over; the others by the record thread, in order)
        if !matches!(event, Event::Exited(_) | Event::Settled(_)) {
            self.settler.push(event);
        }
        let bytes = encode_reply(
            &Subscribed {
                status: None,
                event: Some(EventRecord::from(event)),
            },
            true,
        );
        let t = now();
        for c in &mut self.clients {
            if matches!(c.kind, Kind::Daemon) && c.stream {
                c.reply(bytes.clone(), t);
            }
        }
    }

    /// Where the container is in its life, as clients are told.
    fn run_state(&self) -> RunState {
        match self.state {
            RunState::Created if self.removing_created => RunState::Removing,
            RunState::Exited if self.settler.removing() => RunState::Removing,
            RunState::Running if self.running() && self.paused => RunState::Paused,
            RunState::Running if self.running() && (self.stop_requested || self.asked_to_stop) => {
                RunState::Stopping
            }
            other => other,
        }
    }

    fn status(&self) -> Status {
        Status {
            state: self.run_state(),
            plan: self.plan,
            pid: self.init.as_ref().map(|i| i.pid),
            started_ns: self.started_ns,
            exit: self.exit.clone(),
            oom: self.oom,
            health: self.tracker.as_ref().map(|t| t.health.clone()),
            restart_count: self.restart_count,
            restarting: self.restart.as_ref().map(|r| r.exit.clone()),
            settled: self.settled_told.clone(),
        }
    }

    /// Send the data of the container's streams to the clients that want
    /// them.
    fn broadcast_data(&mut self, stream: Stream, data: &[u8]) {
        let t = now();
        for c in &mut self.clients {
            if matches!(c.kind, Kind::Attach(_)) && c.wants(stream) {
                c.send_data(stream, data, MAX_CLIENT_QUEUE, t);
            }
        }
    }

    /// The container runs: it started and its init did not exit.
    fn running(&self) -> bool {
        self.state == RunState::Running && self.exited.is_none()
    }

    /// Run `crun create`, keep the standard streams of the container.
    fn create(&mut self) -> io::Result<()> {
        let cfg = &self.cfg;
        let tty = cfg.tty;
        let passthrough = cfg.log.driver == LogDriver::Passthrough;

        // A restart finds them mounted.
        if let (Some(image), None) = (&cfg.image, &self.rootfs) {
            self.rootfs = Some(super::image::mount(image, &self.dir_path)?);
            velarx_base::trace::point("monitor rootfs mounted");
        }
        // A restart holds them already.  (after the mount: the limit of open
        // files is raised for the ports over what the layers hold)
        if self.held_ports.is_empty() && !cfg.hold_ports.is_empty() {
            let specs = cfg
                .hold_ports
                .iter()
                .map(|p| velarx_wire::addr::PortSpec::parse(p).map_err(io::Error::other))
                .collect::<io::Result<Vec<_>>>()?;
            self.held_ports = velarx_wire::addr::hold_ports(&specs)?;
        }
        if let (Some(public), None) = (&cfg.public_rootfs, &self.public_root) {
            self.public_root = Some(super::image::PublicRoot::bind(
                &cfg.bundle.join("rootfs"),
                public,
            )?);
        }

        let console = match (&cfg.console_socket, tty) {
            (Some(path), true) => {
                let _ = std::fs::remove_file(path);
                let l = net::socket_with(
                    AddressFamily::UNIX,
                    SocketType::STREAM,
                    SocketFlags::CLOEXEC,
                    None,
                )?;
                net::bind(&l, &SocketAddrUnix::new(path)?)?;
                net::listen(&l, 1)?;
                Some((l, path.clone()))
            }
            (None, true) => return Err(io::Error::other("a terminal needs a console socket")),
            _ => None,
        };

        // A checkpoint is restored once, at the first creation.
        let restore = self.restore.take();
        if restore.is_some() && tty {
            return Err(io::Error::other(
                "a container with a terminal cannot be restored",
            ));
        }
        let mut cmd = child_command(&cfg.runtime);
        cmd.args(&cfg.runtime_args)
            .arg("--root")
            .arg(&cfg.runtime_root);
        match &restore {
            // the restored init is reparented to this monitor (subreaper);
            // the streams crun gets are those of the restored process
            // (CRIU's inherit-fd, from descriptors.json)
            Some((r, images)) => {
                // (the runtime is a child of this process: it reaches the
                // directory through the descriptor of this one.  CRIU mounts
                // a tmpfs in its work directory (the yard of the cgroups), and
                // a directory the engine opened is a mount of the engine's
                // mount namespace, not of this monitor's own (a mount cannot
                // be made on it): the work directory is the run directory,
                // opened by its path in this namespace)
                let images = format!("/proc/{}/fd/{}", std::process::id(), images.as_raw_fd());
                cmd.arg("restore")
                    .arg("--detach")
                    .arg("--image-path")
                    .arg(&images)
                    .arg("--work-path")
                    .arg(&self.dir_path);
                if r.tcp_established {
                    cmd.arg("--tcp-established");
                }
                if r.tcp_close {
                    cmd.arg("--tcp-close");
                }
                if r.file_locks {
                    cmd.arg("--file-locks");
                }
                // the labels of this container, not those in the images
                for arg in restore_lsm_args(&cfg.bundle.join("config.json"))? {
                    cmd.arg(arg);
                }
            }
            None => {
                cmd.arg("create");
                if cfg.no_new_keyring {
                    cmd.arg("--no-new-keyring");
                }
            }
        }
        let (bundle, spec) = match (&self.restart_spec, &restore) {
            (Some(spec), None) if cfg.create_config => {
                cmd.arg("--config").arg(spec);
                (cfg.bundle.clone(), spec.clone())
            }
            (Some(spec), None) => (
                spec.parent()
                    .map_or_else(|| cfg.bundle.clone(), Path::to_path_buf),
                spec.clone(),
            ),
            _ => (cfg.bundle.clone(), cfg.bundle.join("config.json")),
        };
        cmd.arg("--bundle")
            .arg(&bundle)
            .arg("--pid-file")
            .arg(self.dir_path.join(proto::PID_FILE));
        self.run_process = std::fs::read(&spec)
            .ok()
            .and_then(|s| serde_json::from_slice::<serde_json::Value>(&s).ok())
            .map(|mut s| s["process"].take());
        if let Some((_, path)) = &console {
            cmd.arg("--console-socket").arg(path);
        }
        if !self.preserved.is_empty() {
            cmd.arg("--preserve-fds")
                .arg(self.preserved.len().to_string());
        }
        // The descriptors the runtime inherits: those for the container (3,
        // 4, ...) and the network namespace its spec joins as
        // `/proc/self/fd/N`, after them (`velarx_nsid::runtime_fd`).
        if !self.preserved.is_empty() || self.netns.is_some() {
            let kept = self.preserved.len();
            let mut fds: Vec<i32> = self.preserved.iter().map(|f| f.as_raw_fd()).collect();
            fds.extend(self.netns.iter().map(|f| f.as_raw_fd()));
            let holes = cfg.preserve_holes.clone();
            // (the spec names the descriptor by the number of those preserved)
            if self.netns.is_some() && kept != cfg.fds.preserved.len() {
                return Err(io::Error::other(
                    "the descriptors for the container were not all passed to the monitor",
                ));
            }
            velarx_sys::spawn::pre_exec(&mut cmd, move |child| {
                child.place_fds(&fds, 3)?;
                for &hole in &holes {
                    child.close(3 + hole as i32);
                }
                Ok(())
            });
        }
        cmd.arg(&cfg.id);
        if cfg.sdnotify == SdNotify::Container {
            // The directory is mounted in the container by its spec.
            let notify_dir = self.dir_path.join(proto::NOTIFY_DIR);
            std::fs::create_dir_all(&notify_dir)?;
            std::fs::set_permissions(
                &notify_dir,
                std::os::unix::fs::PermissionsExt::from_mode(0o755),
            )?;
            self.notify_sock = Some(notify::bind(
                &notify_dir.join(proto::NOTIFY_SOCKET),
                cfg.notify_label.as_deref(),
            )?);
        }

        // What the init of the container inherits.
        let (err_r, err_w) = pipe()?;
        set_nonblocking(&err_r)?;
        let mut out_r = None;
        let mut stdin_w = None;
        if tty {
            cmd.stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::from(err_w));
        } else if passthrough {
            cmd.stdin(Stdio::null())
                .stdout(Stdio::inherit())
                .stderr(Stdio::inherit());
            drop(err_w);
        } else {
            let (o_r, o_w) = pipe()?;
            set_nonblocking(&o_r)?;
            out_r = Some(o_r);
            cmd.stdout(Stdio::from(o_w)).stderr(Stdio::from(err_w));
            if cfg.stdin_open {
                let (i_r, i_w) = pipe()?;
                set_nonblocking(&i_w)?;
                stdin_w = Some(i_w);
                cmd.stdin(Stdio::from(i_r));
            } else {
                cmd.stdin(Stdio::null());
            }
        }
        velarx_sys::spawn::pre_exec(&mut cmd, |child| child.unblock_signals());
        let child = spawn_child(&mut cmd, cfg)?;
        // Our copies of the descriptors the container got.
        drop(cmd);
        let cpidfd = velarx_sys::pidfd::open_child(child.id() as i32)?;
        drop(child);

        let mut pty = None;
        let mut crun_text = Vec::new();
        let deadline = now() + RUNTIME_TIMEOUT;
        // (a closed standard error, as with `passthrough`, is not polled
        // again, and a runtime that was killed is waited for without a
        // time: its end is the event)
        let (mut err_open, mut killed) = (true, false);
        let status = loop {
            let left = if killed {
                -1
            } else {
                deadline
                    .saturating_duration_since(now())
                    .as_millis()
                    .min(i32::MAX as u128) as i32
            };
            let mut fds = vec![PollFd::new(&cpidfd, PollFlags::IN)];
            if err_open {
                fds.push(PollFd::new(&err_r, PollFlags::IN));
            }
            if let Some((l, _)) = &console {
                fds.push(PollFd::new(l, PollFlags::IN));
            }
            let n = proto::poll(&mut fds, left)?;
            let flags: Vec<PollFlags> = fds.iter().map(|f| f.revents()).collect();
            drop(fds);
            let console_at = 1 + usize::from(err_open);
            if err_open && !flags[1].is_empty() {
                err_open = !read_some(&err_r, &mut crun_text, 16 * 1024);
            }
            if flags.get(console_at).is_some_and(|f| !f.is_empty()) {
                if let Some((l, _)) = &console {
                    if let Ok(conn) = net::accept_with(l, SocketFlags::CLOEXEC) {
                        pty = receive_fd(&conn).or(pty);
                    }
                }
            }
            if n == 0 && !killed {
                let _ = rustix::process::pidfd_send_signal(&cpidfd, rustix::process::Signal::KILL);
                killed = true;
            }
            if let Some(st) = velarx_sys::pidfd::reap(&cpidfd)? {
                break st;
            }
        };
        read_some(&err_r, &mut crun_text, 16 * 1024);
        if let Some((_, path)) = &console {
            if pty.is_none() && status == 0 {
                // The terminal is sent before crun exits: it is in the queue.
                if let Some((l, _)) = &console {
                    if let Ok(conn) =
                        net::accept_with(l, SocketFlags::CLOEXEC | SocketFlags::NONBLOCK)
                    {
                        pty = receive_fd(&conn);
                    }
                }
            }
            let _ = std::fs::remove_file(path);
        }
        if status != 0 {
            let text = String::from_utf8_lossy(&crun_text).trim().to_string();
            let what = if restore.is_some() {
                "restore"
            } else {
                "create"
            };
            return Err(io::Error::other(if text.is_empty() {
                format!(
                    "{} {what} exited with status {status}",
                    cfg.runtime.display()
                )
            } else if restore.is_some() {
                format!("restore: {text}")
            } else {
                text
            }));
        }
        if !crun_text.is_empty() {
            diag(&format!(
                "runtime: {}",
                String::from_utf8_lossy(&crun_text).trim()
            ));
        }

        let pid: i32 = std::fs::read_to_string(self.dir_path.join(proto::PID_FILE))?
            .trim()
            .parse()
            .map_err(|_| io::Error::other("the runtime wrote no valid pid"))?;
        // The runtime's init is the monitor's child (it is the subreaper):
        // an unreaped child keeps its pid, so the pid file names it, and
        // anything else is not signalled.
        let pidfd = velarx_sys::pidfd::open_child(pid).map_err(|e| {
            io::Error::other(format!(
                "the pid {pid} of the runtime is not a child of the monitor: {e}"
            ))
        })?;
        CONTAINER_PIDFD.store(pidfd.as_raw_fd(), Ordering::Relaxed);
        self.init = Some(Init { pid, pidfd });
        if let Some(path) = &cfg.pid_file {
            write_pid_file(path, pid)?;
        }
        self.keep_netns(pid);
        if self.restart_spec.is_none() {
            self.prepare_restarts(pid);
        }

        if tty {
            let pty =
                pty.ok_or_else(|| io::Error::other("the runtime did not send the terminal"))?;
            set_nonblocking(&pty)?;
            self.pty = Some(pty);
        } else {
            self.out_r = out_r;
            if !passthrough {
                self.err_r = Some(err_r);
            }
            self.stdin_w = stdin_w;
        }
        Ok(())
    }

    /// `crun checkpoint`: the container's processes go to the images of
    /// CRIU in the directory `req.image_dir` names; unless they are left running CRIU ends
    /// them, and that end is a checkpoint, not a reason to restart.
    fn checkpoint(
        &mut self,
        req: &velarx_wire::monitor::proto::CheckpointRequest,
        fds: &[OwnedFd],
    ) -> Vec<u8> {
        if [Some(req.image_dir), req.parent_dir]
            .into_iter()
            .flatten()
            .filter_map(|at| fds.get(at as usize))
            .any(|fd| !is_dir(fd))
        {
            return error_reply(
                error::INVALID_ARGUMENT,
                "the images of a checkpoint are not a directory",
            );
        }
        let place = |at: u32| {
            fds.get(at as usize).map(|fd| {
                // (the runtime is another process: it reaches the directory
                // through the monitor's own table)
                format!("/proc/{}/fd/{}", std::process::id(), fd.as_raw_fd())
            })
        };
        let Some(image) = place(req.image_dir) else {
            return error_reply(
                error::INVALID_ARGUMENT,
                format!("no descriptor {} among those of the call", req.image_dir),
            );
        };
        // (CRIU takes the images to build on relative to the images: where
        // the one directory is from the other, as the descriptors name them)
        let parent = match req.parent_dir {
            None => None,
            Some(at) => {
                let (Some(from), Some(to)) =
                    (fds.get(req.image_dir as usize), fds.get(at as usize))
                else {
                    return error_reply(
                        error::INVALID_ARGUMENT,
                        "the directory of the images to build on is not among the descriptors",
                    );
                };
                match (fd_path(from), fd_path(to)) {
                    (Ok(from), Ok(to)) => Some(relative_path(&from, &to)),
                    (Err(e), _) | (_, Err(e)) => {
                        return error_reply(
                            error::INVALID_ARGUMENT,
                            format!("the directories of the images: {e}"),
                        )
                    }
                }
            }
        };
        if !self.running() || self.init.is_none() {
            return error_reply(error::NOT_RUNNING, "the container is not running");
        }
        if self.cfg.tty {
            return error_reply(
                error::INVALID_ARGUMENT,
                "a container with a terminal cannot be checkpointed",
            );
        }
        let saved = (self.stop_requested, self.asked_to_stop);
        if !req.leave_running && !req.pre_dump {
            // before CRIU kills the init
            self.stop_requested = true;
            self.asked_to_stop = true;
            self.checkpointed = true;
            self.cancel_restart();
        }
        let id = self.cfg.id.clone();
        let mut args = vec![
            "checkpoint",
            "--image-path",
            image.as_str(),
            "--work-path",
            image.as_str(),
        ];
        if req.leave_running {
            args.push("--leave-running");
        }
        if req.tcp_established {
            args.push("--tcp-established");
        }
        if req.file_locks {
            args.push("--file-locks");
        }
        if req.pre_dump {
            args.push("--pre-dump");
        }
        let parent = parent.map(|p| p.to_string_lossy().into_owned());
        if let Some(parent) = &parent {
            args.extend(["--parent-path", parent.as_str()]);
        }
        args.push(&id);
        let result = run_runtime(&self.cfg, &args);
        match result {
            Ok((true, _)) => encode_reply(
                &StatusReply {
                    status: self.status(),
                },
                false,
            ),
            other => {
                (self.stop_requested, self.asked_to_stop) = saved;
                self.checkpointed = false;
                error_reply(
                    error::FAILED,
                    match other {
                        Ok((_, text)) => format!("checkpoint: {}", text.trim()),
                        Err(e) => format!("checkpoint: {e}"),
                    },
                )
            }
        }
    }

    /// `crun start`, once.
    fn start(&mut self) -> io::Result<()> {
        if self.state != RunState::Created {
            return Err(io::Error::other("the container was already started"));
        }
        self.pending_start = None;
        // (the kills of the cgroup are counted from before the process
        // runs: one that is killed at once is not taken for the past)
        self.oom_watch = OomWatch::open(self.init.as_ref().map_or(0, |i| i.pid));
        let id = self.cfg.id.clone();
        let (ok, text) = run_runtime(&self.cfg, &["start", &id])?;
        if !ok {
            return Err(io::Error::other(format!("start: {text}")));
        }
        velarx_base::trace::point("monitor started");
        self.mark_started();
        Ok(())
    }

    /// The container runs (started, or restored): its time limit, health
    /// checks and readiness, and the event.
    fn mark_started(&mut self) {
        let started_ns = logfmt::now_ns();
        self.state = RunState::Running;
        self.started_ns = Some(started_ns);
        self.started_at = Some(Instant::now());
        let pid = self.init.as_ref().map_or(0, |i| i.pid);
        if self.oom_watch.is_none() {
            // (a restore: its processes ran before they were watched)
            self.oom_watch = OomWatch::open(pid);
        }
        self.run_deadline = self
            .cfg
            .timeout_secs
            .map(|s| now() + Duration::from_secs(s));
        if let Some(h) = self.cfg.health.as_ref().filter(|h| h.command().is_some()) {
            let tracker = Tracker::for_config(h, started_ns);
            // The startup check first, at its own interval.
            let first = match &h.startup {
                Some(s) if tracker.in_startup() => Some(s.interval()),
                _ => h.interval(),
            };
            self.tracker = Some(tracker);
            self.health_next = after_interval(first);
        }
        match self.cfg.sdnotify {
            SdNotify::Conmon => {
                self.ready_sent = true;
                self.notify_service_manager(&format!("READY=1\n{}", self.main_pid_line()));
            }
            // The container says when it is ready; the unit's main process
            // is this monitor.
            SdNotify::Container => {
                self.notify_service_manager(&self.main_pid_line());
            }
            SdNotify::Healthy => {
                self.notify_service_manager(&self.main_pid_line());
                self.extend_start_timeout();
            }
            SdNotify::Ignore => {}
        }
        let restarted = std::mem::take(&mut self.restarted);
        self.broadcast_event(&Event::Started {
            pid,
            started_ns,
            restart_count: self.restart_count,
            restarted,
        });
    }

    /// The container has its own network namespace that the engine did not
    /// make (the runtime did, in a user namespace of the container's own):
    /// hold the one of its process, as the engine's descriptor is held for the
    /// others, so that the network the engine sets up outlives the process
    /// and the monitor can take it down.
    fn keep_netns(&mut self, pid: i32) {
        if self.netns.is_some() {
            return;
        }
        let makes_one = std::fs::read(self.cfg.bundle.join("config.json"))
            .ok()
            .and_then(|d| serde_json::from_slice::<serde_json::Value>(&d).ok())
            .and_then(|spec| {
                spec.pointer("/linux/namespaces")?
                    .as_array()?
                    .iter()
                    .find(|n| n.get("type").and_then(|t| t.as_str()) == Some("network"))
                    .map(|n| n.get("path").is_none())
            })
            .unwrap_or(false);
        if !makes_one {
            return;
        }
        match velarx_nsid::open_of(&pid.to_string(), velarx_nsid::Kind::Net) {
            Ok(fd) => {
                let fd = Arc::new(fd);
                self.settler.set_netns(Some(fd.clone()));
                self.netns = Some(fd);
            }
            Err(e) => diag(&format!(
                "the network namespace of the container is not kept: {e}"
            )),
        }
    }

    /// After the first creation, when the container may be started again:
    /// keep the namespaces the next runs join, and write their spec.
    fn prepare_restarts(&mut self, pid: i32) {
        let health_restarts = self
            .cfg
            .health
            .as_ref()
            .is_some_and(|h| h.on_failure == OnFailure::Restart);
        if !self.cfg.restart.possible(health_restarts) {
            return;
        }
        let result = (|| -> io::Result<Option<PathBuf>> {
            let spec: serde_json::Value = match std::fs::read(self.cfg.bundle.join("config.json")) {
                Ok(data) => serde_json::from_slice(&data).map_err(io::Error::other)?,
                // A runtime that takes no spec from the bundle.
                Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
                Err(e) => return Err(e),
            };
            self.pinned = super::restart::pin(&spec, pid)?;
            if self.pinned.is_empty() {
                return Ok(None);
            }
            let mut spec = self.pinned.restart_spec(&spec, std::process::id());
            let path = if self.cfg.create_config {
                std::path::absolute(self.dir_path.join(RESTART_SPEC))?
            } else {
                // (a bundle of its own: the root is found from it no more)
                if let Some(root) = spec.pointer_mut("/root/path") {
                    if let Some(rel) = root.as_str().filter(|p| !p.starts_with('/')) {
                        let abs = std::path::absolute(self.cfg.bundle.join(rel))?;
                        *root = abs.to_string_lossy().into_owned().into();
                    }
                }
                let dir = std::path::absolute(self.dir_path.join(RESTART_BUNDLE))?;
                std::fs::create_dir_all(&dir)?;
                dir.join("config.json")
            };
            crate::container::spec_file::write(&path, &spec)?;
            Ok(Some(path))
        })();
        match result {
            Ok(path) => self.restart_spec = path,
            Err(e) => diag(&format!(
                "the namespaces of the container cannot be kept for its restarts: {e}"
            )),
        }
    }

    /// The start failed: kill the init and record an exit.
    fn abort_start(&mut self, why: &str) {
        diag(&format!("start failed: {why}"));
        if let Some(init) = &self.init {
            let _ = rustix::process::pidfd_send_signal(&init.pidfd, rustix::process::Signal::KILL);
        }
    }

    fn event_loop(&mut self) {
        while !self.done {
            let timeout = self.next_timeout();
            let ready = match self.poll(timeout) {
                Ok(r) => r,
                Err(e) => {
                    diag(&format!("poll: {e}"));
                    break;
                }
            };
            for (src, flags) in ready {
                self.dispatch(src, flags);
            }
            self.tick();
            self.detach_abandoned_execs();
            self.clients.retain(|c| !c.gone);
        }
    }

    fn next_timeout(&self) -> i32 {
        let mut deadline: Option<Instant> = None;
        let mut want = |t: Option<Instant>| {
            if let Some(t) = t {
                deadline = Some(deadline.map_or(t, |d| d.min(t)));
            }
        };
        want(self.pending_start);
        want(self.exited.and_then(|e| e.drain_until));
        want(self.run_deadline);
        want(self.health_next);
        want(self.extend_next);
        want(self.stop_kill_at);
        want(self.restart.as_ref().map(|r| r.at));
        want(self.settler.exit_deadline());
        for e in &self.execs {
            want(e.deadline);
            want(e.kill_runtime_at());
            want(e.drain_until);
        }
        for c in &self.clients {
            if self.idle_limited(c) {
                want(Some(c.since + HELLO_LIMIT));
            }
            want(c.stalled.map(|s| s + self.stall_limit));
            want(c.closing.map(|s| s + CLOSE_LINGER));
        }
        match deadline {
            None => -1,
            Some(d) => {
                d.saturating_duration_since(now())
                    .as_millis()
                    .min(i32::MAX as u128) as i32
                    + 1
            }
        }
    }

    fn backpressure(&self) -> bool {
        self.clients
            .iter()
            .any(|c| matches!(c.kind, Kind::Attach(_)) && c.data_queued() > HIGH_WATER)
    }

    /// A connection that has nothing going on: it goes after
    /// [`HELLO_LIMIT`] without a call.
    fn idle_limited(&self, c: &Client) -> bool {
        matches!(c.kind, Kind::Fresh)
            && !c.stream
            && !c.replies_pending()
            && c.closing.is_none()
            && !self.health_waiters.contains(&c.id)
            && !self.stop_waiters.contains(&c.id)
            && !self.wait_waiters.contains(&c.id)
            && !self.remove_waiters.contains(&c.id)
    }

    fn poll(&mut self, timeout: i32) -> io::Result<Vec<(Src, PollFlags)>> {
        let mut set = PollSet::default();
        if let Some(fd) = self.signals.fd() {
            set.add(Src::Signal, fd, PollFlags::IN);
        }
        set.add(Src::Listener, self.listener.as_fd(), PollFlags::IN);
        if let (Some(i), None) = (&self.init, self.exited) {
            set.add(Src::Init, i.pidfd.as_fd(), PollFlags::IN);
        }
        // (the output of a container that exited is read whatever its
        // clients hold: what its pipes have left is all there is, and the
        // drain's time runs)
        let blocked = self.backpressure() && self.exited.is_none();
        if !blocked {
            if let Some(fd) = &self.out_r {
                set.add(Src::Out, fd.as_fd(), PollFlags::IN);
            }
            if let Some(fd) = &self.err_r {
                set.add(Src::Err, fd.as_fd(), PollFlags::IN);
            }
        }
        if let Some(fd) = &self.pty {
            let mut flags = PollFlags::empty();
            if !blocked {
                flags |= PollFlags::IN;
            }
            if !self.stdin_buf.is_empty() {
                flags |= PollFlags::OUT;
            }
            if !flags.is_empty() {
                set.add(Src::Pty, fd.as_fd(), flags);
            }
        }
        if let Some(fd) = &self.stdin_w {
            if !self.stdin_buf.is_empty() {
                set.add(Src::Stdin, fd.as_fd(), PollFlags::OUT);
            }
        }
        if let Some(fd) = self.oom_watch.as_ref().and_then(|w| w.fd()) {
            set.add(Src::Oom, fd, PollFlags::PRI);
        }
        if let Some(fd) = &self.notify_sock {
            set.add(Src::Notify, fd.as_fd(), PollFlags::IN);
        }
        if self.settler.enabled() {
            set.add(Src::Settle, self.settler.fd(), PollFlags::IN);
        }
        for e in &self.execs {
            let blocked = e.status.is_none()
                && self
                    .clients
                    .iter()
                    .any(|c| c.id == e.client && c.data_queued() > HIGH_WATER);
            set.add(Src::ExecChild(e.client), e.pidfd(), PollFlags::IN);
            if let Some((l, _)) = &e.console {
                set.add(Src::ExecConsole(e.client), l.as_fd(), PollFlags::IN);
            }
            if !blocked {
                if let Some(fd) = &e.out_r {
                    set.add(Src::ExecOut(e.client), fd.as_fd(), PollFlags::IN);
                }
                if let Some(fd) = &e.err_r {
                    set.add(Src::ExecErr(e.client), fd.as_fd(), PollFlags::IN);
                }
            }
            if let Some(fd) = &e.pty {
                let mut flags = PollFlags::empty();
                if !blocked {
                    flags |= PollFlags::IN;
                }
                if e.wants_input() {
                    flags |= PollFlags::OUT;
                }
                if !flags.is_empty() {
                    set.add(Src::ExecPty(e.client), fd.as_fd(), flags);
                }
            }
            if let Some(fd) = e.stdin_fd() {
                if e.wants_input() {
                    set.add(Src::ExecIn(e.client), fd, PollFlags::OUT);
                }
            }
        }
        let stdin_full = self.stdin_buf.len() >= STDIN_LIMIT;
        for c in &self.clients {
            let mut flags = PollFlags::empty();
            if c.wants_calls() {
                flags |= PollFlags::IN;
            }
            if c.replies_pending() {
                flags |= PollFlags::OUT;
            }
            if !flags.is_empty() {
                set.add(Src::Client(c.id), c.conn(), flags);
            }
            for stream in [Stream::Stdout, Stream::Stderr] {
                if let Some(fd) = c.pending_sink(stream) {
                    set.add(Src::ClientOut(c.id), fd, PollFlags::OUT);
                }
            }
            if let Some(fd) = &c.input {
                let full = match c.kind {
                    Kind::Exec => self
                        .execs
                        .iter()
                        .any(|e| e.client == c.id && e.input_full()),
                    _ => stdin_full,
                };
                if !full {
                    set.add(Src::ClientIn(c.id), fd.as_fd(), PollFlags::IN);
                }
            }
        }
        set.wait(timeout)
    }

    fn dispatch(&mut self, src: Src, flags: PollFlags) {
        match src {
            Src::Signal => self.handle_signals(),
            Src::Listener => self.accept_clients(),
            Src::Init => self.handle_init_exit(),
            Src::Out => self.read_output(Stream::Stdout, true),
            Src::Err => self.read_output(Stream::Stderr, true),
            Src::Pty => {
                if flags.intersects(PollFlags::IN | PollFlags::HUP | PollFlags::ERR) {
                    self.read_output(Stream::Stdout, false);
                }
                if flags.contains(PollFlags::OUT) {
                    self.write_stdin();
                }
            }
            Src::Stdin => {
                if flags.intersects(PollFlags::ERR | PollFlags::HUP) {
                    self.stdin_buf.clear();
                    self.stdin_w = None;
                } else {
                    self.write_stdin();
                }
            }
            Src::Client(id) => self.handle_client(id, flags),
            Src::ClientOut(id) => {
                let t = now();
                if let Some(c) = self.client(id) {
                    c.advance(t);
                }
            }
            Src::ClientIn(id) => self.read_client_input(id),
            Src::Oom => self.check_oom(),
            Src::Notify => self.forward_notifications(),
            Src::Settle => self.settler.reap(),
            Src::ExecChild(id) => self.exec_child_exited(id),
            Src::ExecConsole(id) => {
                if let Some(e) = self.execs.iter_mut().find(|e| e.client == id) {
                    e.accept_console();
                }
            }
            Src::ExecOut(id) => self.exec_output(id, Which::Out),
            Src::ExecErr(id) => self.exec_output(id, Which::Err),
            Src::ExecPty(id) => {
                if flags.intersects(PollFlags::IN | PollFlags::HUP | PollFlags::ERR) {
                    self.exec_output(id, Which::Pty);
                }
                if flags.contains(PollFlags::OUT) {
                    if let Some(e) = self.execs.iter_mut().find(|e| e.client == id) {
                        e.write_stdin();
                    }
                }
            }
            Src::ExecIn(id) => {
                if let Some(e) = self.execs.iter_mut().find(|e| e.client == id) {
                    e.write_stdin();
                }
            }
        }
    }

    fn handle_signals(&mut self) {
        for sig in self.signals.read() {
            match sig {
                libc::SIGCHLD => self.reap_strays(),
                libc::SIGUSR1 => {
                    if let Err(e) = self.logger.reopen() {
                        diag(&format!("reopen the log: {e}"));
                    }
                }
                _ => {
                    // Whoever stops the monitor (a service manager that
                    // stops the unit it is the main process of) wants the
                    // container stopped: with its stop signal, and killed
                    // if it takes too long.
                    self.stop(
                        self.cfg.stop_signal,
                        Duration::from_secs(self.cfg.stop_timeout_secs),
                        true,
                    );
                }
            }
        }
    }

    /// `Remove`: the container goes with its exit, now.  The answer comes
    /// once it is removed, or the removal failed.
    fn remove_call(&mut self, id: u64, p: iface::RemoveParams) -> Option<Vec<u8>> {
        if self.settler.plan_absent() {
            return Some(error_reply(
                error::INVALID_STATE,
                "the monitor does not remove the container",
            ));
        }
        match self.run_state() {
            RunState::Removed => {
                return Some(encode_reply(
                    &StatusReply {
                        status: self.status(),
                    },
                    false,
                ))
            }
            RunState::Removing => {
                self.remove_waiters.push(id);
                return None;
            }
            RunState::Created => {
                // (never started: its network, then its files and rows)
                self.plan = proto::ExitPlan {
                    remove: true,
                    volumes: p.volumes,
                };
                self.removing_created = true;
                self.settler.start_exit(None, true, p.volumes);
                self.remove_waiters.push(id);
                return None;
            }
            RunState::Running | RunState::Paused | RunState::Stopping if !p.force => {
                return Some(error_reply(
                    error::INVALID_STATE,
                    "the container is running: stop it first, or remove it with force",
                ));
            }
            _ => {}
        }
        self.plan = proto::ExitPlan {
            remove: true,
            volumes: p.volumes,
        };
        self.remove_waiters.push(id);
        if self.exit.is_some() {
            // (exited: the exit job, or the removal, goes on with the plan)
            self.settler.request_removal(p.volumes);
        } else if self.restart.is_some() || self.running() {
            let timeout = Duration::from_millis(p.timeout_ms.unwrap_or(0));
            self.stop(self.cfg.stop_signal, timeout, true);
        }
        None
    }

    /// Stop the container: no restart for the exit that follows (a restart
    /// that waits is not made), a paused one is resumed first, `signal`
    /// through the pidfd of the init, then SIGKILL after `timeout` (at once
    /// for zero; a stop under way keeps the earlier deadline).  `asked`: the
    /// monitor was told to stop (not a failed health check).
    fn stop(&mut self, signal: i32, timeout: Duration, asked: bool) {
        self.stop_requested = true;
        self.asked_to_stop |= asked;
        // (the restart policy says no: the run that ended is the last one)
        self.cancel_restart();
        if self.exited.is_some() {
            return;
        }
        // (a frozen container would not get the signal)
        if self.paused {
            self.freeze(false);
        }
        let deadline = now() + timeout;
        self.stop_kill_at = Some(self.stop_kill_at.map_or(deadline, |d| d.min(deadline)));
        if let Some(init) = &self.init {
            if timeout.is_zero() {
                self.kill_init();
                self.killed = true;
                self.stop_kill_at = None;
            } else {
                let _ = sys::pidfd_send_signal(&init.pidfd, signal);
            }
        }
    }

    /// Reap the orphans that became ours, but not the children that a
    /// pidfd is waiting for, nor any while a runtime is still starting a
    /// command: that command may be one of them.
    fn reap_strays(&mut self) {
        loop {
            let Some(pid) = sys::peek_zombie() else {
                self.reap_pending = false;
                return;
            };
            // A child somebody waits for through its pidfd is theirs.
            let known = self.init.as_ref().is_some_and(|i| i.pid == pid)
                || self.execs.iter().any(|e| e.pid == pid || e.starting());
            if known {
                self.reap_pending = true;
                return;
            }
            let Some(p) = Pid::from_raw(pid) else {
                return;
            };
            let _ = rustix::process::waitpid(Some(p), rustix::process::WaitOptions::NOHANG);
        }
    }

    fn accept_clients(&mut self) {
        loop {
            let fd = match net::accept_with(
                &self.listener,
                SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
            ) {
                Ok(fd) => fd,
                Err(_) => return,
            };
            let ours = rustix::process::getuid().as_raw();
            // (a peer the kernel does not name is refused too)
            let trusted = net::sockopt::socket_peercred(&fd)
                .is_ok_and(|c| c.uid.as_raw() == ours || c.uid.as_raw() == 0);
            if self.clients.len() >= MAX_CLIENTS || !trusted {
                continue;
            }
            self.add_client(fd);
        }
    }

    fn read_output(&mut self, stream: Stream, pipe: bool) {
        let fd = match (stream, pipe) {
            (Stream::Stdout, true) => self.out_r.as_ref(),
            (Stream::Stderr, true) => self.err_r.as_ref(),
            _ => self.pty.as_ref(),
        };
        let Some(fd) = fd else {
            return;
        };
        let mut buf = vec![0u8; READ_CHUNK];
        match rustix::io::read(fd, &mut buf) {
            Ok(0) | Err(rustix::io::Errno::IO) => self.close_output(stream, pipe),
            Ok(n) => {
                let data = &buf[..n];
                if let Err(e) = self.logger.write(stream, data) {
                    diag(&format!("write the log: {e}"));
                }
                self.broadcast_data(stream, data);
            }
            Err(rustix::io::Errno::AGAIN) | Err(rustix::io::Errno::INTR) => {}
            Err(e) => {
                diag(&format!("read the output: {e}"));
                self.close_output(stream, pipe);
            }
        }
    }

    fn close_output(&mut self, stream: Stream, pipe: bool) {
        match (stream, pipe) {
            (Stream::Stdout, true) => self.out_r = None,
            (Stream::Stderr, true) => self.err_r = None,
            // A terminal that hangs up has no more output; the fd stays
            // for the input until the container is finalized.
            _ => self.pty = None,
        }
    }

    fn outputs_closed(&self) -> bool {
        self.out_r.is_none() && self.err_r.is_none() && self.pty.is_none()
    }

    fn write_stdin(&mut self) {
        let fd = self.pty.as_ref().or(self.stdin_w.as_ref());
        if !velarx_wire::monitor::sys::flush_stdin(fd, &mut self.stdin_buf) {
            return;
        }
        if self.stdin_close && self.stdin_buf.is_empty() {
            self.close_stdin();
        }
    }

    fn close_stdin(&mut self) {
        self.stdin_close = false;
        if self.pty.is_some() {
            // End of transmission: the terminal has no way to close.
            self.stdin_buf.push_back(0x04);
            self.write_stdin();
        } else {
            self.stdin_w = None;
        }
    }

    fn queue_stdin(&mut self, data: &[u8]) {
        if self.pty.is_none() && self.stdin_w.is_none() {
            return;
        }
        self.stdin_buf.extend(data);
        self.write_stdin();
    }

    /// While the container is not healthy the unit is still starting: ask
    /// for more time before the manager's timeout runs out.
    fn extend_start_timeout(&mut self) {
        self.notify_service_manager(&format!("EXTEND_TIMEOUT_USEC={}\n", EXTEND_USEC));
        self.extend_next = Some(now() + Duration::from_micros(EXTEND_USEC / 2));
    }

    fn notify_service_manager(&self, message: &str) {
        if message.is_empty() {
            return;
        }
        if let Some(t) = self.notify_target.as_deref() {
            if let Err(e) = velarx_wire::sdnotify::notify_to(t.as_bytes(), message) {
                diag(&format!("sd_notify: {e}"));
            }
        }
    }

    /// Pass on what the container sent to its notification socket.
    fn forward_notifications(&mut self) {
        let Some(sock) = &self.notify_sock else {
            return;
        };
        let target = self.notify_target.clone();
        let mut buf = vec![0u8; notify::MAX_DATAGRAM];
        for _ in 0..64 {
            let n = match net::recv(sock, &mut buf[..], net::RecvFlags::DONTWAIT) {
                Ok((n, _)) => n,
                Err(rustix::io::Errno::AGAIN) => return,
                Err(rustix::io::Errno::INTR) => continue,
                Err(e) => {
                    diag(&format!("sd_notify: reading the notification socket: {e}"));
                    return;
                }
            };
            if let (Some(t), Some(data)) = (&target, notify::filter(&buf[..n])) {
                if let Err(e) = String::from_utf8(data)
                    .map_err(io::Error::other)
                    .and_then(|d| velarx_wire::sdnotify::notify_to(t.as_bytes(), &d))
                {
                    diag(&format!("sd_notify: {e}"));
                }
            }
        }
    }

    fn kill_init(&mut self) {
        if let (Some(init), None) = (&self.init, self.exited) {
            let _ = rustix::process::pidfd_send_signal(&init.pidfd, rustix::process::Signal::KILL);
        }
    }

    /// Run the health check command in the container.
    fn start_health_check(&mut self) {
        let Some(cfg) = &self.cfg.health else {
            return;
        };
        // The startup check while the container starts, then the regular one.
        let startup = self
            .tracker
            .as_ref()
            .filter(|t| t.in_startup())
            .and(cfg.startup.as_ref());
        let (command, timeout) = match startup {
            Some(s) => (s.command(), Some(s.timeout())),
            None => (cfg.command(), cfg.timeout()),
        };
        let interval = cfg.interval();
        let Some(command) = command else {
            return;
        };
        if self.health_run.is_some() || !self.running() || self.paused {
            return;
        }
        self.exec_seq += 1;
        let id = self.next_id;
        self.next_id += 1;
        let req = ExecRequest {
            command,
            // none: the check runs until it ends
            timeout_ms: timeout.map(|t| t.as_millis().max(1) as u64),
            ..Default::default()
        };
        let started_ns = logfmt::now_ns();
        match ExecSession::spawn(
            &self.cfg,
            self.run_process.as_ref(),
            &self.dir_path,
            self.exec_seq,
            id,
            &req,
            Vec::new(),
        ) {
            Ok(mut session) => {
                session.capture = Some(Vec::new());
                self.health_run = Some(HealthRun {
                    session: id,
                    started_ns,
                });
                self.execs.push(session);
            }
            Err(e) => {
                diag(&format!("health check: {e}"));
                self.health_next = after_interval(interval);
                self.answer_health_waiters();
            }
        }
    }

    /// The result of a health check.
    fn health_done(&mut self, session: &ExecSession) {
        let Some(run) = self.health_run.take() else {
            return;
        };
        let (Some(cfg), Some(tracker)) = (self.cfg.health.as_ref(), self.tracker.as_mut()) else {
            return;
        };
        let timed_out = session.reason() == Reason::TimedOut;
        let output =
            String::from_utf8_lossy(session.capture.as_deref().unwrap_or(&[])).into_owned();
        let result = proto::HealthResult {
            start_ns: run.started_ns,
            end_ns: logfmt::now_ns(),
            exit_code: if timed_out || session.status_lost().is_some() {
                1
            } else {
                i64::from(session.exit_code().unwrap_or(1))
            },
            output: if timed_out {
                "healthcheck timed out".into()
            } else if let Some(why) = session.status_lost() {
                format!("the exit status of the command is unknown: {why}")
            } else {
                output
            },
        };
        if tracker.in_startup() {
            let outcome = tracker.record_startup(cfg, result);
            let health = tracker.health.clone();
            let interval = cfg
                .startup
                .as_ref()
                .map(|s| s.interval())
                .or_else(|| cfg.interval());
            self.write_health_log(cfg, &health);
            self.broadcast_event(&Event::Health(health));
            if self.running() {
                match outcome {
                    StartupOutcome::Again => {
                        self.health_next = after_interval(interval);
                    }
                    StartupOutcome::Passed => self.health_next = Some(now()),
                    StartupOutcome::Restart => {
                        diag("the startup check failed too often");
                        self.health_failed(OnFailure::Restart);
                    }
                }
            }
            self.answer_health_waiters();
            return;
        }
        // (a check that failed as the container stops says nothing of its
        // health, as podman's: one that passed is a pass)
        let stopped = result.exit_code != 0
            && (self.stop_requested || self.asked_to_stop || self.exited.is_some());
        let changed = if stopped {
            tracker.record_stopped(cfg, result)
        } else {
            tracker.record(cfg, result)
        };
        let became_unhealthy = changed && tracker.health.status == proto::HealthStatus::Unhealthy;
        let became_healthy = changed && tracker.health.status == proto::HealthStatus::Healthy;
        let health = tracker.health.clone();
        let (interval, on_failure) = (cfg.interval(), cfg.on_failure);
        self.write_health_log(cfg, &health);
        self.broadcast_event(&Event::Health(health));
        if became_healthy && self.cfg.sdnotify == SdNotify::Healthy && !self.ready_sent {
            self.ready_sent = true;
            self.extend_next = None;
            self.notify_service_manager(&format!("READY=1\n{}", self.main_pid_line()));
        }
        let mut acting = false;
        if self.running() {
            self.health_next = after_interval(interval);
            if became_unhealthy {
                self.health_failed(on_failure);
                // (the one that asked for the check is told once the action
                // is done: the container is gone, or started again)
                acting = !matches!(on_failure, OnFailure::None);
            }
        }
        if !acting {
            self.answer_health_waiters();
        }
    }

    /// With a directory as the destination of the health log, the results
    /// in `<id>-healthcheck.log` of it too (podman's file), replaced whole.
    fn write_health_log(&self, cfg: &velarx_proto::health::Healthcheck, health: &proto::Health) {
        let (true, Some(dir)) = (cfg.log_dir().is_some(), &self.health_log_dir) else {
            return;
        };
        let name = format!("{}-healthcheck.log", self.cfg.id);
        let result = serde_json::to_vec(health)
            .map_err(io::Error::other)
            .and_then(|data| write_whole_at(dir, &name, &data, 0o600));
        if let Err(e) = result {
            diag(&format!("health log {name}: {e}"));
        }
    }

    fn answer_health_waiters(&mut self) {
        let reply = self.health_reply();
        let t = now();
        for id in std::mem::take(&mut self.health_waiters) {
            if let Some(c) = self.client(id) {
                c.reply(reply.clone(), t);
            }
        }
    }

    /// What a container that became unhealthy gets.
    fn health_failed(&mut self, action: OnFailure) {
        diag(&format!("the container is unhealthy: {action:?}"));
        match action {
            OnFailure::None => {}
            OnFailure::Kill => self.kill_init(),
            OnFailure::Restart => {
                self.health_restart = true;
                self.kill_init();
            }
            OnFailure::Stop => self.stop(
                self.cfg.stop_signal,
                Duration::from_secs(self.cfg.stop_timeout_secs),
                false,
            ),
        }
    }

    fn check_oom(&mut self) {
        if self.oom_watch.as_mut().is_some_and(|w| w.check()) && !self.oom {
            self.oom = true;
            self.broadcast_event(&Event::Oom);
        }
    }

    fn handle_init_exit(&mut self) {
        let Some(init) = &self.init else {
            return;
        };
        let code = match velarx_sys::pidfd::reap(&init.pidfd) {
            Ok(Some(c)) => c,
            Ok(None) => return,
            Err(e) => {
                diag(&format!("wait: {e}"));
                255
            }
        };
        if self.exited.is_some() {
            return;
        }
        self.check_oom();
        self.oom_watch = None;
        self.run_deadline = None;
        self.exited = Some(Exited {
            code,
            drain_until: Some(now() + Duration::from_millis(self.cfg.drain_ms)),
        });
        CONTAINER_PIDFD.store(-1, Ordering::Relaxed);
        // Nothing reads the input any more.
        self.stdin_w = None;
        self.stdin_buf.clear();
    }

    /// The timers, and the steps that wait for them or for the outputs.
    fn tick(&mut self) {
        let t = now();
        // (the attach of its client starts a container that waits for one;
        // the time is only the bound for a client that never comes)
        if self.pending_start.is_some_and(|d| t >= d) {
            self.start_pending();
        }
        if self.run_deadline.is_some_and(|d| t >= d) {
            self.run_deadline = None;
            if let (Some(init), None) = (&self.init, self.exited) {
                diag("the time limit of the container is over: killing it");
                self.timed_out = true;
                let _ =
                    rustix::process::pidfd_send_signal(&init.pidfd, rustix::process::Signal::KILL);
            }
        }
        if self.stop_kill_at.is_some_and(|d| t >= d) {
            self.stop_kill_at = None;
            if self.init.is_some() && self.exited.is_none() {
                self.killed = true;
            }
            self.kill_init();
        }
        if self.extend_next.is_some_and(|d| t >= d) {
            self.extend_next = None;
            if !self.ready_sent && self.exited.is_none() {
                self.extend_start_timeout();
            }
        }
        if self.health_next.is_some_and(|d| t >= d) {
            self.health_next = None;
            self.start_health_check();
        }
        self.exec_tick(t);
        if self.reap_pending {
            self.reap_strays();
        }
        let idle: Vec<u64> = self
            .clients
            .iter()
            .filter(|c| self.idle_limited(c) && t >= c.since + HELLO_LIMIT)
            .map(|c| c.id)
            .collect();
        for c in &mut self.clients {
            if idle.contains(&c.id) {
                c.gone = true;
            }
            if c.stalled.is_some_and(|s| t >= s + self.stall_limit) && !c.drop_output(t) {
                c.gone = true;
            }
            if c.closing.is_some_and(|s| t >= s + CLOSE_LINGER) {
                c.gone = true;
            }
        }
        // (the init of a container that never started ends with the removal:
        // no exit to settle)
        if self.exited.is_some()
            && self.exit.is_none()
            && self.restart.is_none()
            && !self.removing_created
        {
            let drained = self.outputs_closed()
                || self
                    .exited
                    .and_then(|e| e.drain_until)
                    .is_some_and(|d| t >= d);
            if drained && !self.schedule_restart() {
                self.finalize();
            }
        }
        if self.restart.as_ref().is_some_and(|r| t >= r.at) {
            self.restart_now();
        }
        // The exit is recorded and the network released; the runtime forgets
        // the container (its poststop hooks run); an `--rm` container is
        // removed: only then are the clients told it is over.
        if self.exit.is_some() || self.removing_created {
            if self.settler.exit_settled() && !self.runtime_deleted {
                self.delete_in_runtime();
                if self.settler.wants_removal() {
                    self.release_mounts();
                    self.settler.start_removal();
                }
            }
            if self.settler.exit_done(t) {
                self.tell_clients_exit();
                self.end();
            }
        }
    }

    /// What the container exited with.
    fn exit_info(&self) -> ExitInfo {
        ExitInfo {
            // (CRIU killed it: a checkpoint is no failure)
            code: if self.checkpointed {
                0
            } else if self.timed_out {
                // (podman's: the end of --timeout is no exit of the
                // container, -1, a run's 255)
                -1
            } else {
                self.exited.map_or(255, |e| e.code)
            },
            finished_ns: logfmt::now_ns(),
            oom: self.oom,
            health_restart: self.health_restart,
            stop_requested: self.stop_requested,
            timed_out: self.timed_out,
            checkpointed: self.checkpointed,
            started_ns: self.started_ns,
            remove: self.plan.remove,
            volumes: self.plan.volumes,
        }
    }

    /// The container exited and its output is read: start it again later if
    /// its restart policy says so.
    fn schedule_restart(&mut self) -> bool {
        let info = self.exit_info();
        if self
            .started_at
            .is_some_and(|t| t.elapsed() >= super::restart::RESET_AFTER)
        {
            self.restart_count = 0;
        }
        if !super::restart::should_restart(&self.cfg.restart, &info, self.restart_count) {
            return false;
        }
        if let Err(e) = self.logger.finish() {
            diag(&format!("finish the log: {e}"));
        }
        self.answer_health_waiters();
        // A check of the run that ended does not count for the next one.
        if let Some(run) = self.health_run.take() {
            if let Some(e) = self.execs.iter_mut().find(|e| e.client == run.session) {
                e.kill_group(Reason::Cancelled);
            }
        }
        self.health_next = None;
        self.stop_kill_at = None;
        self.out_r = None;
        self.err_r = None;
        self.pty = None;
        let delay = super::restart::delay(self.restart_count);
        self.restart_count += 1;
        diag(&format!(
            "the container exited with {}: restart {} in {delay:?}",
            info.code, self.restart_count
        ));
        self.restart = Some(PendingRestart {
            exit: info.clone(),
            at: now() + delay,
        });
        self.state = RunState::Exited;
        self.broadcast_event(&Event::Restarting {
            exit: info.clone(),
            restart_count: self.restart_count,
        });
        // The clients attached to this run are told it is over, as when the
        // monitor ends.
        self.finish_attached(info.code);
        true
    }

    /// Start the container again: a new container of the runtime in the
    /// same bundle, in the namespaces of the first run.
    fn restart_now(&mut self) {
        let Some(PendingRestart { exit: last, .. }) = self.restart.take() else {
            return;
        };
        let id = self.cfg.id.clone();
        match run_runtime(&self.cfg, &["delete", "--force", &id]) {
            Ok((true, _)) => {}
            Ok((false, text)) => diag(&format!("delete: {text}")),
            Err(e) => diag(&format!("delete: {e}")),
        }
        CONTAINER_PIDFD.store(-1, Ordering::Relaxed);
        self.init = None;
        self.exited = None;
        self.oom = false;
        self.oom_watch = None;
        self.timed_out = false;
        self.health_restart = false;
        self.stdin_close = false;
        self.stdin_buf.clear();
        self.state = RunState::Created;
        self.restarted = true;
        let result = self.create().and_then(|()| self.start());
        if let Err(e) = result {
            diag(&format!("restart failed: {e}"));
            self.kill_init();
            // The run that ended is the last one.
            self.restarted = false;
            self.exited = Some(Exited {
                code: last.code,
                drain_until: None,
            });
            self.oom = last.oom;
            self.timed_out = last.timed_out;
            self.finalize();
        }
    }

    /// A stop while a restart waits: the run that ended is the last one.
    fn cancel_restart(&mut self) {
        if self.restart.take().is_some() {
            self.finalize();
        }
    }

    /// The container exited and its output is read: record the exit.
    fn finalize(&mut self) {
        velarx_base::trace::point("monitor exited");
        self.answer_health_waiters();
        if let Err(e) = self.logger.finish() {
            diag(&format!("finish the log: {e}"));
        }
        self.out_r = None;
        self.err_r = None;
        self.pty = None;
        if let Some(e) = &mut self.exited {
            e.drain_until = None;
        }
        let info = self.exit_info();
        self.write_exit_file(&info);
        self.exit = Some(info.clone());
        self.state = RunState::Exited;
        self.broadcast_event(&Event::Exited(info.clone()));
        self.settler
            .start_exit(Some(info.clone()), info.remove, info.volumes);
    }

    /// The clients know: forget the container in the runtime and stop.
    fn end(&mut self) {
        self.delete_in_runtime();
        self.done = true;
    }

    /// The monitor holds the rootless namespace of the bridge networks: it
    /// is one of its holders, which keep it when the holder process is
    /// killed.
    fn join_bridge_netns(&self) {
        let (Some(_), Some(plan)) = (&self.bridge_netns, self.settler.plan()) else {
            return;
        };
        let Some(detach) = &plan.network else {
            return;
        };
        if let Err(e) = velarx_netkernel::rootless_netns::add_monitor_holder(
            &detach.db,
            std::process::id() as i32,
        ) {
            diag(&format!(
                "cannot record the monitor as a holder of the network namespace: {e}"
            ));
        }
    }

    /// The very end: the monitor is the last process in the cgroups of its
    /// container; it leaves them and removes them.
    fn leave_cgroups(&self) {
        let Some(plan) = self.settler.plan() else {
            return;
        };
        if let Some(cgroup) = &plan.cgroup {
            if let Err(e) = crate::settle::cgroup::leave_and_remove(cgroup, &plan.start_lock) {
                diag(&format!("cannot remove the cgroups: {e}"));
            }
        }
    }

    /// Forget the container in the runtime (its poststop hooks run), once.
    fn delete_in_runtime(&mut self) {
        if std::mem::replace(&mut self.runtime_deleted, true) {
            return;
        }
        let id = self.cfg.id.clone();
        match run_runtime(&self.cfg, &["delete", "--force", &id]) {
            Ok((true, _)) => {}
            Ok((false, text)) => diag(&format!("delete: {text}")),
            Err(e) => diag(&format!("delete: {e}")),
        }
    }

    fn tell_clients_exit(&mut self) {
        let Some(settled) = self.settler.settled() else {
            return;
        };
        if self.settled_told.as_ref() != Some(&settled) {
            if settled.removed {
                self.state = RunState::Removed;
            }
            self.settled_told = Some(settled.clone());
            self.broadcast_event(&Event::Settled(settled));
        }
        if let Some(code) = self.exit.as_ref().map(|e| e.code) {
            self.finish_attached(code);
        }
        self.answer_exit_waiters();
        self.answer_remove_waiters();
    }

    /// Answer the clients of `Remove`: the container is removed, or why not.
    fn answer_remove_waiters(&mut self) {
        let Some(settled) = self.settled_told.clone() else {
            return;
        };
        let reply = match &settled.failure {
            Some(f) if !settled.removed => error_reply(error::FAILED, f.reason.clone()),
            _ => encode_reply(
                &StatusReply {
                    status: self.status(),
                },
                false,
            ),
        };
        let t = now();
        for id in std::mem::take(&mut self.remove_waiters) {
            if let Some(c) = self.client(id) {
                c.reply(reply.clone(), t);
            }
        }
    }

    /// What every version of the monitor answers.
    fn core_status(&self) -> CoreStatus {
        let last = self
            .exit
            .as_ref()
            .or(self.restart.as_ref().map(|r| &r.exit));
        CoreStatus {
            state: match self.run_state() {
                RunState::Created => CoreState::Created,
                // (the init exited and its output drains: nothing runs)
                RunState::Running if self.exited.is_some() => CoreState::Exited,
                RunState::Running => CoreState::Running,
                RunState::Paused => CoreState::Paused,
                RunState::Stopping => CoreState::Stopping,
                RunState::Exited | RunState::Removing | RunState::Removed => CoreState::Exited,
            },
            pid: self.init.as_ref().map(|i| i.pid),
            exit_code: last.map(|e| e.code),
            finished_ns: last.map(|e| e.finished_ns),
            recorded: self.exit.is_some() && self.settler.exit_done(now()),
        }
    }

    /// Answer the clients of `Stop` and `Wait` if the container exited for
    /// good and its exit is recorded.
    fn answer_exit_waiters(&mut self) {
        if self.exit.is_none() || !self.settler.exit_done(now()) {
            return;
        }
        let status = self.core_status();
        let stop = encode_reply(
            &StopReply {
                status: status.clone(),
                killed: self.killed,
            },
            false,
        );
        let wait = encode_reply(&CoreStatusReply { status }, false);
        let t = now();
        for id in std::mem::take(&mut self.stop_waiters) {
            if let Some(c) = self.client(id) {
                c.reply(stop.clone(), t);
            }
        }
        for id in std::mem::take(&mut self.wait_waiters) {
            if let Some(c) = self.client(id) {
                c.reply(wait.clone(), t);
            }
        }
    }

    /// The last reply of every attach session: the run ended with `code`.
    fn finish_attached(&mut self, code: i32) {
        let bytes = encode_reply(
            &AttachReply {
                phase: SessionPhase::Ended,
                exit: Some(code),
                ..AttachReply::default()
            },
            false,
        );
        let dropped = encode_reply(
            &AttachReply {
                phase: SessionPhase::Ended,
                exit: Some(code),
                output_dropped: true,
                ..AttachReply::default()
            },
            false,
        );
        let t = now();
        for c in &mut self.clients {
            if matches!(c.kind, Kind::Attach(_)) {
                let last = if c.output_dropped { &dropped } else { &bytes };
                c.finish(last.clone(), t);
            }
        }
    }

    fn write_exit_file(&self, info: &ExitInfo) {
        let Ok(data) = serde_json::to_vec(info) else {
            return;
        };
        let tmp = format!("{}.tmp", proto::EXIT_FILE);
        let result = (|| -> io::Result<()> {
            let fd = rustix::fs::openat(
                &self.dir,
                &tmp,
                OFlags::WRONLY
                    | OFlags::CREATE
                    | OFlags::TRUNC
                    | OFlags::NOFOLLOW
                    | OFlags::CLOEXEC,
                Mode::from_raw_mode(0o600),
            )?;
            let mut f = File::from(fd);
            f.write_all(&data)?;
            rustix::fs::renameat(&self.dir, &tmp, &self.dir, proto::EXIT_FILE)
                .map_err(io::Error::from)
        })();
        if let Err(e) = result {
            diag(&format!("write the exit file: {e}"));
        }
    }

    /// Unmount what this monitor mounted for the container: the bind for
    /// the runtime, then the root file system and the images.
    fn release_mounts(&mut self) {
        self.public_root = None;
        self.rootfs = None;
    }

    fn cleanup_files(&mut self) {
        if self.notify_sock.is_some() {
            let _ = velarx_base::tree::remove_dir_all(self.dir_path.join(proto::NOTIFY_DIR));
        }
        let _ = rustix::fs::unlinkat(&self.dir, proto::SOCKET, rustix::fs::AtFlags::empty());
        let _ = rustix::fs::unlinkat(&self.dir, proto::PID_FILE, rustix::fs::AtFlags::empty());
        let _ = rustix::fs::unlinkat(&self.dir, RESTART_SPEC, rustix::fs::AtFlags::empty());
        let _ = velarx_base::tree::remove_dir_all(self.dir_path.join(RESTART_BUNDLE));
    }

    /// Give the clients a moment to take what is queued for them.
    fn flush_all(&mut self, limit: Duration) {
        let deadline = now() + limit;
        loop {
            let t = now();
            for c in &mut self.clients {
                c.advance(t);
            }
            self.clients.retain(|c| !c.gone);
            if self.clients.iter().all(|c| c.queued() == 0) {
                return;
            }
            let left = deadline.saturating_duration_since(now());
            if left.is_zero() {
                return;
            }
            let mut fds: Vec<PollFd<'_>> = self
                .clients
                .iter()
                .flat_map(|c| c.write_fds())
                .map(|fd| PollFd::from_borrowed_fd(fd, PollFlags::OUT))
                .collect();
            if proto::poll(&mut fds, left.as_millis().min(i32::MAX as u128) as i32).is_err() {
                return;
            }
        }
    }

    fn handle_client(&mut self, id: u64, flags: PollFlags) {
        let t = now();
        if flags.contains(PollFlags::OUT) {
            if let Some(c) = self.client(id) {
                c.advance(t);
            }
        }
        if !flags.intersects(PollFlags::IN | PollFlags::HUP | PollFlags::ERR) {
            return;
        }
        let Some(c) = self.client(id) else {
            return;
        };
        if c.gone || c.hung_up {
            return;
        }
        let (calls, hung_up) = c.read_calls();
        for call in calls {
            self.handle_message(id, &call);
        }
        if hung_up {
            self.client_closed(id);
        }
    }

    /// The commands of the exec clients that went away (a closed
    /// connection, but also one the monitor could not write to, such as a
    /// client that closed before the answer to its request) go on without
    /// them, as podman's do: their output is dropped, their status kept.
    fn detach_abandoned_execs(&mut self) {
        for c in self
            .clients
            .iter()
            .filter(|c| c.gone && matches!(c.kind, Kind::Exec))
        {
            if let Some(e) = self.execs.iter_mut().find(|e| e.client == c.id) {
                e.detached = true;
            }
        }
    }

    /// The client hung up.  An attach client whose input pipe is still
    /// open goes once that is read to its end: what it wrote reaches the
    /// container.
    fn client_closed(&mut self, id: u64) {
        // (the command of an exec goes on, as when it detached)
        if let Some(e) = self.execs.iter_mut().find(|e| e.client == id) {
            e.detached = true;
        }
        let Some(c) = self.client(id) else { return };
        c.hung_up = true;
        if matches!(c.kind, Kind::Attach(_)) && c.input.is_some() {
            return;
        }
        self.client_left(id);
    }

    /// An attach client is gone, its input read.
    fn client_left(&mut self, id: u64) {
        let mut close_stdin = false;
        if let Some(c) = self.client(id) {
            if let Kind::Attach(a) = &c.kind {
                close_stdin = a.stdin_once;
            }
            c.gone = true;
        }
        if close_stdin {
            self.stdin_close = true;
            self.write_stdin();
        }
    }

    /// Read the input a client wrote to its pipe, for the container or its
    /// exec session.
    fn read_client_input(&mut self, id: u64) {
        let mut buf = vec![0u8; READ_CHUNK];
        // (a few reads while the input has room: the other descriptors
        // wait too)
        for _ in 0..8 {
            let Some(c) = self.client(id) else { return };
            let Some(fd) = c.input.as_ref() else { return };
            let n = match rustix::io::read(fd, &mut buf) {
                Ok(n) => n,
                Err(rustix::io::Errno::AGAIN) | Err(rustix::io::Errno::INTR) => return,
                Err(_) => 0,
            };
            let exec = matches!(c.kind, Kind::Exec);
            if n == 0 {
                c.input = None;
                let (asked, hung_up) = (c.input_eof_asked, c.hung_up);
                if asked {
                    self.close_input_of(id, exec);
                }
                if hung_up && !exec {
                    self.client_left(id);
                }
                return;
            }
            let full = if exec {
                match self.execs.iter_mut().find(|e| e.client == id) {
                    Some(e) => {
                        e.queue_stdin(&buf[..n]);
                        e.input_full()
                    }
                    None => true,
                }
            } else {
                self.queue_stdin(&buf[..n]);
                self.stdin_buf.len() >= STDIN_LIMIT
            };
            if full || n < buf.len() {
                return;
            }
        }
    }

    /// The input of a session ends (`CloseStdin` and its pipe read out).
    fn close_input_of(&mut self, id: u64, exec: bool) {
        if exec {
            if let Some(e) = self.execs.iter_mut().find(|e| e.client == id) {
                e.close_stdin();
            }
        } else {
            self.stdin_close = true;
            self.write_stdin();
        }
    }

    /// One message of a client.
    fn handle_message(&mut self, id: u64, bytes: &[u8]) {
        let t = now();
        let Some(c) = self.client(id) else { return };
        if c.closing.is_some() || c.gone {
            return;
        }
        c.since = t;
        let call = match iface::parse_request(bytes) {
            Ok(call) => call,
            Err(why) => {
                diag(&format!("a client sent no call ({why}): dropped"));
                c.gone = true;
                return;
            }
        };
        if c.stream && !call.oneway {
            // (its reply would come after the end of the stream)
            diag("a client called during a stream without `oneway`: dropped");
            c.gone = true;
            return;
        }
        let oneway = call.oneway;
        if let Some(reply) = self.call(id, call) {
            if !oneway {
                if let Some(c) = self.client(id) {
                    c.reply(reply, t);
                }
            }
        }
    }

    /// Do a call: its reply, or none when it comes later (or never: a
    /// stream answers by itself).
    fn call(&mut self, id: u64, call: Call) -> Option<Vec<u8>> {
        let Call { request, more, .. } = call;
        let request = match request {
            Ok(r) => r,
            Err(Refusal::MethodNotFound(m)) => {
                return Some(encode_error(
                    error::METHOD_NOT_FOUND,
                    &iface::MethodName { method: &m },
                ))
            }
            Err(Refusal::InvalidParameter(p)) => {
                return Some(encode_error(
                    error::INVALID_PARAMETER,
                    &iface::InvalidParameter { parameter: &p },
                ))
            }
        };
        let expected_more = |name: &str| {
            Some(encode_error(
                error::EXPECTED_MORE,
                &iface::MethodName { method: name },
            ))
        };
        let status = |m: &Monitor| encode_reply(&StatusReply { status: m.status() }, false);
        let empty = || encode_reply(&Empty {}, false);
        // (the boot connection is served alone until it creates the
        // container: anything else it asks first is refused, and it ends)
        if self.created == Created::Waiting && !matches!(request, Request::Create(_)) {
            self.created = Created::Failed;
            return Some(error_reply(
                error::INVALID_STATE,
                "the first call of the boot connection is Create",
            ));
        }
        match request {
            Request::GetInfo => Some(encode_reply(
                &Info {
                    version: env!("CARGO_PKG_VERSION").into(),
                    commit: velarx_base::buildinfo::commit().into(),
                    core: iface::CORE,
                    digest: iface::interface_digest(),
                    id: self.cfg.id.clone(),
                },
                false,
            )),
            Request::ServiceGetInfo => Some(encode_reply(
                &iface::ServiceInfo {
                    vendor: "velarx",
                    product: "velarx-monitor",
                    version: env!("CARGO_PKG_VERSION"),
                    url: env!("CARGO_PKG_HOMEPAGE"),
                    interfaces: ["org.varlink.service", iface::INTERFACE],
                },
                false,
            )),
            Request::ServiceGetInterfaceDescription(p) => {
                Some(if p.interface == iface::INTERFACE {
                    encode_reply(
                        &iface::Description {
                            description: iface::DEFINITION,
                        },
                        false,
                    )
                } else {
                    encode_error(
                        error::INTERFACE_NOT_FOUND,
                        &iface::InterfaceName {
                            interface: &p.interface,
                        },
                    )
                })
            }
            Request::Create(p) => Some(self.create_call(id, p)),
            Request::Subscribe => {
                if !more {
                    return expected_more(<iface::Subscribe as Method>::NAME);
                }
                let first = encode_reply(
                    &Subscribed {
                        status: Some(self.status()),
                        event: None,
                    },
                    true,
                );
                let t = now();
                if let Some(c) = self.client(id) {
                    c.kind = Kind::Daemon;
                    c.stream = true;
                    c.reply(first, t);
                }
                None
            }
            Request::Status => Some(status(self)),
            Request::Start(p) => Some(self.start_call(p.attach_wait_ms)),
            Request::Stop(p) => {
                if self.state == RunState::Created {
                    return Some(error_reply(
                        error::INVALID_STATE,
                        "the container was not started: quit the monitor instead",
                    ));
                }
                let signal = p.signal.unwrap_or(self.cfg.stop_signal);
                if !sys::valid_signal(signal) {
                    return Some(error_reply(
                        error::INVALID_ARGUMENT,
                        format!("invalid signal {signal}"),
                    ));
                }
                let timeout = p
                    .timeout_ms
                    .map_or(Duration::from_secs(self.cfg.stop_timeout_secs), |ms| {
                        Duration::from_millis(ms)
                    });
                self.stop(signal, timeout, true);
                self.stop_waiters.push(id);
                // The answer comes once the exit is recorded (now, if it is).
                self.answer_exit_waiters();
                None
            }
            Request::Remove(p) => self.remove_call(id, p),
            Request::Kill(p) => {
                if !sys::valid_signal(p.signal) {
                    return Some(error_reply(
                        error::INVALID_ARGUMENT,
                        format!("invalid signal {}", p.signal),
                    ));
                }
                match (&self.init, self.exited) {
                    (Some(init), None) if self.state != RunState::Created => {
                        // a kill of a user is a stop: no restart follows
                        self.stop_requested = true;
                        self.asked_to_stop = true;
                        let _ = sys::pidfd_send_signal(&init.pidfd, p.signal);
                        Some(empty())
                    }
                    _ => Some(error_reply(
                        error::NOT_RUNNING,
                        "the container is not running",
                    )),
                }
            }
            Request::Wait => {
                self.wait_waiters.push(id);
                self.answer_exit_waiters();
                None
            }
            Request::CoreStatus => Some(encode_reply(
                &CoreStatusReply {
                    status: self.core_status(),
                },
                false,
            )),
            Request::Quit => {
                if self.state != RunState::Created {
                    return Some(error_reply(
                        error::INVALID_STATE,
                        format!(
                            "the container is {}, not created",
                            format!("{:?}", self.state).to_lowercase()
                        ),
                    ));
                }
                let cid = self.cfg.id.clone();
                let _ = run_runtime(&self.cfg, &["delete", "--force", &cid]);
                self.done = true;
                Some(empty())
            }
            Request::Checkpoint(req) => {
                let fds = self
                    .client(id)
                    .map(|c| c.take_received())
                    .unwrap_or_default();
                Some(self.checkpoint(&req, &fds))
            }
            Request::Update(u) => {
                let fds = self
                    .client(id)
                    .map(|c| c.take_received())
                    .unwrap_or_default();
                Some(match self.update(u, &fds) {
                    Ok(()) => empty(),
                    Err((name, why)) => error_reply(name, why),
                })
            }
            Request::Pause | Request::Resume => {
                let pause = matches!(request, Request::Pause);
                if pause != !self.paused || !self.running() {
                    return Some(error_reply(
                        error::INVALID_STATE,
                        if pause {
                            "the container is not running"
                        } else {
                            "the container is not paused"
                        },
                    ));
                }
                if !self.freeze(pause) {
                    return Some(error_reply(
                        error::FAILED,
                        if pause {
                            "the runtime could not freeze the container"
                        } else {
                            "the runtime could not thaw the container"
                        },
                    ));
                }
                Some(status(self))
            }
            Request::RunHealthCheck => {
                if self.tracker.is_none()
                    || self.state != RunState::Running
                    || self.exited.is_some()
                {
                    return Some(error_reply(
                        error::NO_HEALTH_CHECK,
                        "the container has no health check running",
                    ));
                }
                self.health_waiters.push(id);
                if self.health_run.is_none() {
                    self.health_next = None;
                    self.start_health_check();
                }
                // The answer comes with the result.
                None
            }
            Request::ReopenLog => Some(match self.logger.reopen() {
                Ok(()) => empty(),
                Err(e) => error_reply(error::FAILED, format!("reopen the log: {e}")),
            }),
            Request::Attach(a) => {
                if !more {
                    return expected_more(<Attach as Method>::NAME);
                }
                self.attach(id, a);
                None
            }
            Request::Exec(req) => {
                if !more {
                    return expected_more(<ExecRequest as Method>::NAME);
                }
                self.start_exec(id, req);
                None
            }
            Request::Resize(r) => {
                let has_terminal = self.pty.is_some();
                match self.exec_of(id) {
                    Some(e) => e.resize(r.rows, r.cols),
                    None if has_terminal => self.resize(r.rows, r.cols),
                    None => {
                        return Some(error_reply(
                            error::INVALID_STATE,
                            "the container has no terminal",
                        ))
                    }
                }
                Some(empty())
            }
            Request::Signal(p) => {
                if !sys::valid_signal(p.signal) {
                    return Some(error_reply(
                        error::INVALID_ARGUMENT,
                        format!("invalid signal {}", p.signal),
                    ));
                }
                match self.exec_of(id) {
                    Some(e) => e.signal(p.signal),
                    None => return Some(error_reply(
                        error::INVALID_STATE,
                        "Signal is for the connection of an exec session (a container gets Kill)",
                    )),
                }
                Some(empty())
            }
            Request::CloseStdin => {
                let c = self.client(id)?;
                let exec = match c.kind {
                    Kind::Exec => true,
                    Kind::Attach(_) => false,
                    _ => {
                        return Some(error_reply(
                            error::INVALID_ARGUMENT,
                            "CloseStdin is for the connection of an attach or exec session",
                        ))
                    }
                };
                c.input_eof_asked = true;
                if c.input.is_none() {
                    self.close_input_of(id, exec);
                }
                Some(empty())
            }
            Request::OpenInit => {
                let fd = match (&self.init, self.exited, self.state) {
                    (Some(init), None, RunState::Running) => init.pidfd.try_clone(),
                    _ => {
                        return Some(error_reply(
                            error::NOT_RUNNING,
                            "the container is not running",
                        ))
                    }
                };
                match fd {
                    Ok(fd) => {
                        let t = now();
                        if let Some(c) = self.client(id) {
                            c.reply_with(
                                encode_reply(&iface::InitReply { pidfd: 0 }, false),
                                vec![fd],
                                t,
                            );
                        }
                        None
                    }
                    Err(e) => Some(error_reply(error::FAILED, format!("pidfd: {e}"))),
                }
            }
            Request::Detach => {
                match self.exec_of(id) {
                    // (its output, with no one to take it, is dropped)
                    Some(e) => e.detached = true,
                    None => {
                        return Some(error_reply(
                            error::INVALID_ARGUMENT,
                            "Detach is for the connection of an exec session",
                        ))
                    }
                }
                Some(empty())
            }
        }
    }

    /// The exec session of the client `id`.
    fn exec_of(&mut self, id: u64) -> Option<&mut ExecSession> {
        let exec = self
            .clients
            .iter()
            .any(|c| c.id == id && matches!(c.kind, Kind::Exec));
        if !exec {
            return None;
        }
        self.execs.iter_mut().find(|e| e.client == id)
    }

    fn health_reply(&self) -> Vec<u8> {
        match &self.tracker {
            Some(t) => encode_reply(
                &HealthReply {
                    health: t.health.clone(),
                },
                false,
            ),
            None => error_reply(error::NO_HEALTH_CHECK, "the container has no health check"),
        }
    }

    /// `Start`.
    fn start_call(&mut self, attach_wait_ms: u64) -> Vec<u8> {
        let started = |m: &Monitor| {
            encode_reply(
                &StartReply {
                    status: Some(m.status()),
                },
                false,
            )
        };
        if self.restart.is_some() {
            // Started by hand while the restart policy waits.
            self.restart_now();
            return match self.exit {
                None => started(self),
                Some(_) => error_reply(error::FAILED, "the container could not be started again"),
            };
        }
        if self.state != RunState::Created {
            return error_reply(
                error::INVALID_STATE,
                "the container is not in the created state",
            );
        }
        if attach_wait_ms > 0 {
            self.pending_start = Some(now() + Duration::from_millis(attach_wait_ms));
            return encode_reply(&StartReply { status: None }, false);
        }
        match self.start() {
            Ok(()) => started(self),
            Err(e) => {
                self.abort_start(&e.to_string());
                error_reply(error::FAILED, e.to_string())
            }
        }
    }

    /// `Update`: the restart policy and the health check from now on.
    /// Freeze (or thaw) the container with the runtime; whether it did.
    fn freeze(&mut self, pause: bool) -> bool {
        let id = self.cfg.id.clone();
        match run_runtime(&self.cfg, &[if pause { "pause" } else { "resume" }, &id]) {
            Ok((true, _)) => {
                self.paused = pause;
                if !pause && self.tracker.is_some() {
                    // the checks that were due while it was frozen
                    self.health_next = Some(now());
                }
                true
            }
            Ok((false, text)) => {
                diag(&format!(
                    "{}: {text}",
                    if pause { "pause" } else { "resume" }
                ));
                false
            }
            Err(e) => {
                diag(&format!("{}: {e}", if pause { "pause" } else { "resume" }));
                false
            }
        }
    }

    /// Change what the monitor was given.  The resources come first: what
    /// the runtime refuses changes nothing.  The error: its name and why.
    fn update(
        &mut self,
        u: velarx_wire::monitor::proto::MonitorUpdate,
        fds: &[OwnedFd],
    ) -> Result<(), (&'static str, String)> {
        // every descriptor the call names is there before anything changes
        let named = |at: u32| {
            fds.get(at as usize).ok_or((
                error::INVALID_ARGUMENT,
                format!("no descriptor {at} among those of the call"),
            ))
        };
        let resources = u.resources.map(named).transpose()?;
        let log_dir = match u.health.as_ref().and_then(|h| h.log_dir) {
            Some(at) => Some(
                Some(named(at)?)
                    .filter(|fd| is_dir(fd))
                    .ok_or((
                        error::INVALID_ARGUMENT,
                        "the health log directory is not a directory".to_string(),
                    ))?
                    .try_clone()
                    .map_err(|e| (error::FAILED, format!("health log directory: {e}")))?,
            ),
            None => None,
        };
        if let Some(fd) = resources {
            if !self.running() {
                return Err((error::NOT_RUNNING, "the container is not running".into()));
            }
            let path = format!("/proc/{}/fd/{}", std::process::id(), fd.as_raw_fd());
            let id = self.cfg.id.clone();
            match run_runtime(&self.cfg, &["update", "--resources", &path, &id]) {
                Ok((true, _)) => {}
                Ok((false, text)) => return Err((error::INVALID_ARGUMENT, text)),
                Err(e) => return Err((error::FAILED, format!("update: {e}"))),
            }
        }
        if let Some(r) = u.restart {
            self.cfg.restart.policy = r.policy;
        }
        if let Some(plan) = u.plan {
            self.plan = plan;
        }
        if let Some(h) = u.health {
            self.cfg.health = h.check;
            self.health_log_dir = log_dir;
            // the checks begin again with the new configuration
            self.tracker = None;
            self.health_next = None;
            let running = self.running();
            if let Some(h) = self
                .cfg
                .health
                .as_ref()
                .filter(|h| running && h.command().is_some())
            {
                let tracker = Tracker::for_config(h, logfmt::now_ns());
                let first = match &h.startup {
                    Some(s) if tracker.in_startup() => Some(s.interval()),
                    _ => h.interval(),
                };
                self.tracker = Some(tracker);
                self.health_next = after_interval(first);
            }
        }
        Ok(())
    }

    /// Run a command in the container for the client `id`.
    fn start_exec(&mut self, id: u64, req: ExecRequest) {
        let refuse = |m: &mut Monitor, name: &str, why: &str| {
            let t = now();
            if let Some(c) = m.client(id) {
                c.refuse(error_reply(name, why), t);
            }
        };
        if !self.running() {
            return refuse(self, error::NOT_RUNNING, "the container is not running");
        }
        if req.command.is_empty() {
            return refuse(self, error::INVALID_ARGUMENT, "no command to run");
        }
        let received = self
            .client(id)
            .map(|c| c.take_received())
            .unwrap_or_default();
        // (the holes are opened here: a client asks for no more of them than
        // the CLI passes on in all)
        if req.preserve_fds as usize > velarx_base::spawn::MAX_PRESERVED_FDS {
            return refuse(
                self,
                error::INVALID_ARGUMENT,
                &format!(
                    "at most {} descriptors can be passed to the command, not {}",
                    velarx_base::spawn::MAX_PRESERVED_FDS,
                    req.preserve_fds
                ),
            );
        }
        let mut holes = req.preserve_holes.clone();
        holes.sort_unstable();
        holes.dedup();
        if received.len() + holes.len() != req.preserve_fds as usize
            || received.len() > velarx_wire::varlink::MAX_FDS
            || holes.len() != req.preserve_holes.len()
            || holes.iter().any(|h| *h >= req.preserve_fds)
        {
            return refuse(
                self,
                error::INVALID_ARGUMENT,
                &format!(
                    "the call says {} descriptors for the command ({} holes) and carries {}",
                    req.preserve_fds,
                    req.preserve_holes.len(),
                    received.len()
                ),
            );
        }
        // (a /dev/null in each hole: the command's descriptors keep their
        // numbers)
        let mut received = received.into_iter();
        let mut preserved = Vec::with_capacity(req.preserve_fds as usize);
        for slot in 0..req.preserve_fds {
            if holes.binary_search(&slot).is_err() {
                preserved.extend(received.next());
                continue;
            }
            match std::fs::File::open("/dev/null") {
                Ok(f) => preserved.push(OwnedFd::from(f)),
                Err(e) => return refuse(self, error::FAILED, &format!("/dev/null: {e}")),
            }
        }
        // (without a terminal the input is the command's own pipe, passed on)
        let pipes = match Pipes::new(req.stdin && req.tty, true, !req.tty) {
            Ok(p) => p,
            Err(e) => return refuse(self, error::FAILED, &format!("pipes: {e}")),
        };
        self.exec_seq += 1;
        let seq = self.exec_seq;
        match ExecSession::spawn(
            &self.cfg,
            self.run_process.as_ref(),
            &self.dir_path,
            seq,
            id,
            &req,
            preserved,
        ) {
            Ok(mut session) => {
                session.notify_start = req.notify_start;
                let mut pipes = pipes;
                if let Some(fd) = session.take_stdin_pipe() {
                    pipes.pass_first(fd);
                }
                let [stdin, stdout, stderr] = pipes.positions;
                let reply = encode_reply(
                    &ExecReply {
                        stdin,
                        stdout,
                        stderr,
                        ..ExecReply::default()
                    },
                    true,
                );
                let t = now();
                if let Some(c) = self.client(id) {
                    c.kind = Kind::Exec;
                    c.stream = true;
                    c.set_pipes(pipes.out, pipes.err, pipes.input);
                    c.reply_with(reply, pipes.theirs, t);
                }
                self.execs.push(session);
            }
            // (the runtime was not started: what is missing here is its
            // binary, the bundle or the user, never the command, which the
            // runtime looks up and reports with its exit)
            Err(e) => refuse(
                self,
                error::NOT_STARTED,
                &format!("cannot run the command: {e}"),
            ),
        }
    }

    fn exec_output(&mut self, id: u64, which: Which) {
        let Some(e) = self.execs.iter_mut().find(|e| e.client == id) else {
            return;
        };
        if let Some((stderr, data)) = e.read(which) {
            if let Some(buf) = e.capture.as_mut() {
                let room = HEALTH_OUTPUT.saturating_sub(buf.len());
                buf.extend_from_slice(&data[..data.len().min(room)]);
                return;
            }
            let data = if stderr {
                match e.pass_stderr(data) {
                    Some(d) => d,
                    None => return,
                }
            } else {
                data
            };
            let stream = if stderr {
                Stream::Stderr
            } else {
                Stream::Stdout
            };
            let t = now();
            if let Some(c) = self.clients.iter_mut().find(|c| c.id == id) {
                c.send_data(stream, &data, MAX_CLIENT_QUEUE, t);
            }
        }
    }

    fn exec_child_exited(&mut self, id: u64) {
        let drain = Duration::from_millis(self.cfg.drain_ms.min(2000));
        if let Some(e) = self.execs.iter_mut().find(|e| e.client == id) {
            e.reap(drain);
        }
    }

    /// Deadlines of the exec sessions, and the end of those that are done.
    fn exec_tick(&mut self, t: Instant) {
        let mut started = Vec::new();
        for e in &mut self.execs {
            if e.take_started() {
                started.push((e.client, e.notify_start, e.take_held_stderr()));
            }
        }
        for (id, notify, held) in started {
            if let Some(c) = self.clients.iter_mut().find(|c| c.id == id) {
                if notify {
                    c.reply(
                        encode_reply(
                            &ExecReply {
                                phase: SessionPhase::Started,
                                ..ExecReply::default()
                            },
                            true,
                        ),
                        t,
                    );
                }
                if !held.is_empty() {
                    c.send_data(Stream::Stderr, &held, MAX_CLIENT_QUEUE, t);
                }
            }
        }
        for e in &mut self.execs {
            e.kill_runtime_if_late(t);
            if e.status.is_none() && e.deadline.is_some_and(|d| t >= d) {
                e.deadline = None;
                e.kill_group(Reason::TimedOut);
            }
        }
        let mut done = Vec::new();
        for (i, e) in self.execs.iter().enumerate() {
            if e.drained() {
                done.push(i);
            }
        }
        for i in done.into_iter().rev() {
            let mut e = self.execs.remove(i);
            if self
                .health_run
                .as_ref()
                .is_some_and(|r| r.session == e.client)
            {
                self.health_done(&e);
                continue;
            }
            let said = e.final_stderr();
            let lost = e.status_lost().map(|why| {
                error_reply(
                    error::FAILED,
                    format!("the exit status of the command is unknown: {why}"),
                )
            });
            let exit = ExecExit {
                code: e.exit_code().unwrap_or(255),
                reason: match e.reason() {
                    Reason::Exited => ExecReason::Exited,
                    Reason::TimedOut => ExecReason::TimedOut,
                    Reason::Cancelled => ExecReason::Cancelled,
                },
                started: e.command_started(),
            };
            if let Some(c) = self.clients.iter_mut().find(|c| c.id == e.client) {
                if !said.is_empty() {
                    c.send_data(Stream::Stderr, &said, MAX_CLIENT_QUEUE, t);
                }
                c.finish(
                    lost.unwrap_or_else(|| {
                        encode_reply(
                            &ExecReply {
                                phase: SessionPhase::Ended,
                                exit: Some(exit),
                                output_dropped: c.output_dropped,
                                ..ExecReply::default()
                            },
                            false,
                        )
                    }),
                    t,
                );
            }
        }
    }

    fn resize(&mut self, rows: u16, cols: u16) {
        if let Some(pty) = &self.pty {
            let ws = rustix::termios::Winsize {
                ws_row: rows.min(1000),
                ws_col: cols.min(1000),
                ws_xpixel: 0,
                ws_ypixel: 0,
            };
            let _ = rustix::termios::tcsetwinsize(pty, ws);
        }
    }

    fn attach(&mut self, id: u64, a: Attach) {
        let t = now();
        if let Some(code) = self.exit.as_ref().map(|e| e.code) {
            // Too late for the output: only the status, once it is recorded
            // (the engine that gets it finds the container as it ended).
            if !self.settler.exit_done(t) {
                if let Some(c) = self.client(id) {
                    c.kind = Kind::Attach(a);
                    c.stream = true;
                }
                return;
            }
            if let Some(c) = self.client(id) {
                c.kind = Kind::Attach(a);
                c.finish(
                    encode_reply(
                        &AttachReply {
                            phase: SessionPhase::Ended,
                            exit: Some(code),
                            ..AttachReply::default()
                        },
                        false,
                    ),
                    t,
                );
            }
            return;
        }
        let tty = self.cfg.tty;
        let pipes = match Pipes::new(a.stdin, a.stdout, a.stderr && !tty) {
            Ok(p) => p,
            Err(e) => {
                let start = a.start;
                if let Some(c) = self.client(id) {
                    c.refuse(error_reply(error::FAILED, format!("pipes: {e}")), t);
                }
                // The client that was to start the container is gone: no
                // other attach will come for it, and the engine has taken
                // the container for started.
                if start {
                    self.start_pending();
                }
                return;
            }
        };
        let start = a.start;
        let [stdin, stdout, stderr] = pipes.positions;
        let reply = encode_reply(
            &AttachReply {
                phase: SessionPhase::Streams,
                stdin,
                stdout,
                stderr,
                exit: None,
                output_dropped: false,
            },
            true,
        );
        if let Some(c) = self.client(id) {
            c.kind = Kind::Attach(a);
            c.stream = true;
            c.set_pipes(pipes.out, pipes.err, pipes.input);
            c.reply_with(reply, pipes.theirs, t);
        }
        if start {
            self.start_pending();
        }
    }

    /// Start the container that waited for its client, if one waits.
    fn start_pending(&mut self) {
        if self.pending_start.is_some() {
            if let Err(e) = self.start() {
                self.abort_start(&e.to_string());
            }
        }
    }
}

/// The first descriptor received on `conn`.
pub(super) fn receive_fd(conn: &OwnedFd) -> Option<OwnedFd> {
    let mut data = [0u8; 64];
    velarx_sys::scm::recv(conn, &mut data, 1, rustix::net::RecvFlags::empty())
        .ok()?
        .fds
        .into_iter()
        .next()
}

#[cfg(test)]
mod tests {
    #[test]
    fn a_directory_is_named_from_another_one() {
        use super::relative_path;
        use std::path::Path;
        let p = |a: &str, b: &str| relative_path(Path::new(a), Path::new(b));
        assert_eq!(p("/s/c/ab", "/s/c/pre"), Path::new("../pre"));
        assert_eq!(p("/s/c", "/s/c/pre"), Path::new("pre"));
        assert_eq!(p("/s/c/a/b", "/s/x"), Path::new("../../../x"));
        assert_eq!(p("/s", "/s"), Path::new(""));
    }

    use super::*;

    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn the_command_line_names_the_connection() {
        let args = |a: &[&str]| a.iter().map(std::ffi::OsString::from).collect::<Vec<_>>();
        assert_eq!(
            parse_command(args(&["--varlink-fd", "3", "/run/x"])),
            Ok(Invocation::Monitor {
                varlink_fd: 3,
                dir: "/run/x".into()
            })
        );
        assert_eq!(
            parse_command(args(&["--image-server"])),
            Ok(Invocation::ImageServer)
        );
        // (no implicit descriptor, and none of the standard ones)
        assert!(parse_command(args(&["/run/x"])).is_err());
        assert!(parse_command(args(&["--varlink-fd", "2", "/run/x"])).is_err());
        assert!(parse_command(args(&["--varlink-fd", "x", "/run/x"])).is_err());
        assert!(parse_command(args(&[])).is_err());
    }

    #[test]
    fn a_command_of_the_monitor_sees_neither_the_manager_nor_the_scope() {
        let cmd = child_command("true");
        let unset = |name: &str| {
            cmd.get_envs()
                .any(|(k, v)| k == std::ffi::OsStr::new(name) && v.is_none())
        };
        assert!(unset("NOTIFY_SOCKET"));
        assert!(unset(velarx_base::spawn::SCOPE_ENV));
    }

    fn config_with_open_files(open_files: Option<u64>) -> MonitorConfig {
        serde_json::from_value(serde_json::json!({
            "id": "c", "runtime": "crun", "runtime_root": "/r", "bundle": "/b",
            "open_files": open_files,
        }))
        .unwrap()
    }

    /// The runtime and what it starts get the limit of open files the
    /// engine's user gave, though the engine (this process) raised its own.
    #[test]
    fn a_command_of_the_monitor_has_the_limit_of_open_files_of_the_engine_user() {
        velarx_base::testing::in_child(|| {
            rustix::process::setrlimit(
                rustix::process::Resource::Nofile,
                rustix::process::Rlimit {
                    current: Some(256),
                    maximum: Some(4096),
                },
            )
            .unwrap();
            velarx_base::hardening::raise_open_files().unwrap();
            let limits = |cfg: &MonitorConfig| {
                let mut cmd = child_command("sh");
                cmd.args(["-c", "echo $(ulimit -Sn) $(ulimit -Hn)"])
                    .stdout(Stdio::piped());
                let out = spawn_child(&mut cmd, cfg).unwrap().wait_with_output();
                String::from_utf8(out.unwrap().stdout).unwrap()
            };
            let original = velarx_base::hardening::original_open_files();
            assert_eq!(original, Some(256));
            assert_eq!(limits(&config_with_open_files(original)), "256 4096\n");
            assert_eq!(limits(&config_with_open_files(None)), "4096 4096\n");
        });
    }

    /// The time this thread ran, in clock ticks (`/proc/thread-self/stat`).
    fn thread_ticks() -> u64 {
        let stat = std::fs::read_to_string("/proc/thread-self/stat").unwrap();
        // (after the command, which is in parentheses: utime and stime are
        // the 12th and 13th fields)
        let rest = &stat[stat.rfind(')').unwrap() + 2..];
        let f: Vec<&str> = rest.split(' ').collect();
        f[11].parse::<u64>().unwrap() + f[12].parse::<u64>().unwrap()
    }

    /// A runtime that closes its standard error and goes on is waited for
    /// asleep: the closed pipe is not polled again (it answers at once).
    #[test]
    fn a_runtime_that_closes_its_stderr_is_waited_for_without_spinning() {
        let dir = tempfile::tempdir().unwrap();
        let runtime = dir.path().join("runtime");
        velarx_base::testing::write_script(&runtime, "echo said >&2\nexec 2>&-\nsleep 1");
        let cfg: MonitorConfig = serde_json::from_value(serde_json::json!({
            "id": "x",
            "runtime": runtime,
            "runtime_root": dir.path(),
            "bundle": dir.path(),
        }))
        .unwrap();
        let before = thread_ticks();
        let (ok, text) = run_runtime(&cfg, &["state", "x"]).unwrap();
        let ran = thread_ticks() - before;
        assert!(ok);
        assert_eq!(text.trim(), "said");
        // (a second of polling a closed pipe is about 100 ticks)
        assert!(ran < 20, "{ran} ticks in the wait for the runtime");
    }

    #[test]
    fn pid_file_is_replaced_whole_and_readable() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("x.pid");
        write_pid_file(&p, 42).unwrap();
        std::fs::write(&p, "old content").unwrap();
        write_pid_file(&p, 7).unwrap();
        assert_eq!(std::fs::read_to_string(&p).unwrap(), "7");
        let mode = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o644);
        // no temporary file is left
        assert_eq!(std::fs::read_dir(d.path()).unwrap().count(), 1);
        // a missing directory fails and leaves nothing
        assert!(write_pid_file(&d.path().join("no/x.pid"), 1).is_err());
        assert!(write_pid_file(Path::new("/"), 1).is_err());
    }

    #[test]
    fn a_restore_takes_the_labels_of_the_container() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("config.json");
        std::fs::write(
            &p,
            r#"{"process":{"selinuxLabel":"system_u:system_r:container_t:s0:c1,c2"},
                "linux":{"mountLabel":"system_u:object_r:container_file_t:s0:c1,c2"}}"#,
        )
        .unwrap();
        assert_eq!(
            restore_lsm_args(&p).unwrap(),
            [
                "--lsm-profile=selinux:system_u:system_r:container_t:s0:c1,c2",
                "--lsm-mount-context=system_u:object_r:container_file_t:s0:c1,c2"
            ]
        );
        std::fs::write(&p, r#"{"process":{"apparmorProfile":"velarx-default"}}"#).unwrap();
        assert_eq!(
            restore_lsm_args(&p).unwrap(),
            ["--lsm-profile=apparmor:velarx-default"]
        );
        std::fs::write(&p, r#"{"process":{}}"#).unwrap();
        assert!(restore_lsm_args(&p).unwrap().is_empty());
    }
}
