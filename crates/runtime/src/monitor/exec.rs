// SPDX-License-Identifier: Apache-2.0
//! Commands run in the container on behalf of a client: `crun exec` with its
//! streams relayed to the connection that asked for it.  The process runs
//! as a session leader, so a timeout or a client that goes away kills its
//! whole process group.
//!
//! The runtime starts the command detached (`crun exec --detach`, as
//! podman's conmon does) and exits once it did: the command is then a child
//! of the monitor, its subreaper, followed and signalled through a pidfd
//! whose process cannot be another one (an unreaped child keeps its pid).
//! The exit of the runtime is the start of the command, or its failure.

use std::collections::VecDeque;
use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant};

use rustix::net::{self, AddressFamily, SocketAddrUnix, SocketFlags, SocketType};
use rustix::process::Pid;

use super::config::MonitorConfig;
use velarx_wire::monitor::proto::ExecRequest;
use velarx_wire::monitor::sys;

/// What one read of an output of the command takes.
const READ_CHUNK: usize = 64 * 1024;
/// The capacity asked for the pipe of a command's input.
const STDIN_PIPE: usize = 256 * 1024;
/// Bytes of input waiting for the command.
const STDIN_LIMIT: usize = 256 * 1024;
/// How much of the standard error is kept to tell why a command did not run.
const STDERR_TAIL: usize = 4096;

/// Why a session ended other than by the exit of its command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    Exited = 0,
    TimedOut = 1,
    Cancelled = 2,
}

/// How long a pending kill waits for the runtime to start the command
/// before it kills the runtime.
const KILL_RUNTIME_AFTER: Duration = Duration::from_secs(5);
/// How long the runtime may take to start a command: one that hangs is
/// killed.  While it starts one the monitor reaps no orphan, as the command
/// may be one of them.
const START_LIMIT: Duration = Duration::from_secs(120);

pub struct ExecSession {
    /// The connection that asked for it.
    pub client: u64,
    /// The process followed through `pidfd`, a child of the monitor: the
    /// runtime until it started the command, then the command.
    pub pid: i32,
    pidfd: OwnedFd,
    pub out_r: Option<OwnedFd>,
    pub err_r: Option<OwnedFd>,
    pub stdin_w: Option<OwnedFd>,
    pub pty: Option<OwnedFd>,
    /// Where the runtime hands over the terminal, until it did.
    pub console: Option<(OwnedFd, PathBuf)>,
    pid_file: PathBuf,
    /// The process the runtime was given.
    process: PathBuf,
    /// The name of the runtime in what the client is told (`crun`, `runc`).
    runtime_name: String,
    /// The runtime started the command, which `pid` and `pidfd` are now.
    started: bool,
    pub deadline: Option<Instant>,
    stdin_buf: VecDeque<u8>,
    stdin_close: bool,
    stderr_tail: Vec<u8>,
    pub status: Option<i32>,
    /// Why the status of the command is not known although it ran: the
    /// code in `status` is then not the command's.
    lost: Option<String>,
    pub drain_until: Option<Instant>,
    reason: Reason,
    /// A size asked for before the terminal arrived.
    pending_size: Option<(u16, u16)>,
    /// The client detached: the command goes on when it goes away.
    pub detached: bool,
    /// A kill asked for before the runtime started the command: since when.
    /// Killing the runtime then could leave the command running; it is
    /// killed when the runtime exits having started it.
    kill_pending: Option<Instant>,
    /// Signals the client sent before the runtime said it started the
    /// command (which may run already): sent once it did.
    signals_pending: Vec<i32>,
    /// When the runtime is killed if it has not started the command.
    start_by: Instant,
    /// The runtime was killed: its exit is awaited, not killed again.
    runtime_killed: bool,
    /// The start of the output, kept for the monitor (a health check): there
    /// is no client to send it to.
    pub capture: Option<Vec<u8>>,
    /// The start of the command was seen (the pid is there).
    pub start_seen: bool,
    /// The client asked to be told when the command starts.
    pub notify_start: bool,
    /// What the runtime said on the standard error before the command
    /// started: it may be its failure, which the client is told in
    /// podman's words once it is known.
    held_err: Vec<u8>,
}

/// What a failed `crun exec` says on its standard error, as the exit code
/// a client expects: 127 not found, 126 cannot run.
fn failure_code(stderr: &str) -> i32 {
    // (podman's define.ExitCode, for a command the runtime did not start)
    let l = stderr.to_lowercase();
    if l.contains("not found")
        || l.contains("no such file")
        || l.contains("executable path is empty")
    {
        127
    } else {
        126
    }
}

/// The user `spec` (`NAME|UID[:GROUP|GID]`) of an exec, from the files of
/// the root file system, with podman's rules (`userspec`): a uid the image
/// does not know has gid 0 and no home; the groups are its group,
/// `--group-add` and, unless `spec` names the group (or `groups_strict`),
/// the groups of the image that list the user.  Uid, gid, groups, home.
fn exec_user(
    rootfs: &Path,
    spec: &str,
    cfg: &MonitorConfig,
) -> io::Result<(u32, u32, Vec<u32>, String)> {
    // (a file the image lacks names nobody)
    let (passwd, group) = (
        read_in_root(rootfs, "etc/passwd").unwrap_or_default(),
        read_in_root(rootfs, "etc/group").unwrap_or_default(),
    );
    let user = crate::container::userspec::resolve_user_groups(
        &passwd,
        &group,
        spec,
        &cfg.group_add,
        cfg.groups_strict,
    )
    .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
    Ok((
        user.uid,
        user.gid,
        user.additional_gids,
        user.home.unwrap_or_default(),
    ))
}

/// A small file of the root file system, a symbolic link kept inside it.
fn read_in_root(rootfs: &Path, path: &str) -> io::Result<String> {
    let root = rustix::fs::open(
        rootfs,
        rustix::fs::OFlags::DIRECTORY | rustix::fs::OFlags::PATH | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(io_err)?;
    let text = velarx_sys::fs::read_in_root(root.as_fd(), path, 1 << 20)?.unwrap_or_default();
    Ok(String::from_utf8_lossy(&text).into_owned())
}

/// The process of an exec (`crun exec --process`, as podman's: `--user`
/// takes no supplementary groups, `--cap` replaces the capabilities).  The
/// container's environment, directory and user, with the command, the
/// variables, the directory and the terminal of `req`; the runtime gives it
/// the capabilities, labels and profile of the container's process unless
/// it has its own.  A `user` of the request gets the groups podman gives
/// it: its group, the container's `--group-add` and, unless it names its
/// group, those of the image that list it; and its home.
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct ExecProcess<'a> {
    args: &'a [String],
    env: Vec<String>,
    cwd: String,
    terminal: bool,
    user: ExecUser,
    no_new_privileges: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    capabilities: Option<ExecCaps>,
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct ExecUser {
    uid: u32,
    gid: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    umask: Option<u64>,
    additional_gids: Vec<u32>,
}

/// `--privileged`: every capability of the engine; a user other than root
/// has them in its bounding set only.
#[derive(serde::Serialize)]
struct ExecCaps {
    bounding: Vec<String>,
    effective: Vec<String>,
    permitted: Vec<String>,
}

/// `process` is the one of the spec the container was created with (the
/// bundle's when none is known).
fn exec_process<'a>(
    cfg: &MonitorConfig,
    process: Option<&serde_json::Value>,
    req: &'a ExecRequest,
) -> io::Result<ExecProcess<'a>> {
    let read: serde_json::Value;
    let p = match process {
        Some(p) => p,
        None => {
            read = serde_json::from_slice(&std::fs::read(cfg.bundle.join("config.json"))?)?;
            &read["process"]
        }
    };
    let id = |v: &serde_json::Value| v.as_u64().unwrap_or(0) as u32;
    let mut env: Vec<String> = p["env"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|e| e.as_str().map(String::from))
        .collect();
    let named = |e: &String, name: &str| e.split('=').next() == Some(name);
    let mut user = ExecUser {
        uid: id(&p["user"]["uid"]),
        gid: id(&p["user"]["gid"]),
        umask: p["user"]["umask"].as_u64(),
        additional_gids: p["user"]["additionalGids"]
            .as_array()
            .into_iter()
            .flatten()
            .map(id)
            .collect(),
    };
    if let Some(spec) = req.user.as_deref().filter(|u| !u.is_empty()) {
        let (uid, gid, gids, home) = exec_user(&cfg.bundle.join("rootfs"), spec, cfg)?;
        (user.uid, user.gid, user.additional_gids) = (uid, gid, gids);
        // (the home the engine gave the container's user is not this one's)
        if !cfg.env_has_home {
            env.retain(|e| !named(e, "HOME"));
            env.push(format!("HOME={home}"));
        }
    }
    for e in &req.env {
        env.retain(|x| !named(x, e.split('=').next().unwrap_or(e)));
        env.push(e.clone());
    }
    let capabilities = req.privileged.then(|| {
        let all = crate::container::caps::bounding_names();
        let given = if user.uid == 0 {
            all.clone()
        } else {
            Vec::new()
        };
        ExecCaps {
            bounding: all,
            effective: given.clone(),
            permitted: given,
        }
    });
    Ok(ExecProcess {
        args: &req.command,
        env,
        cwd: match req.cwd.as_deref().filter(|c| !c.is_empty()) {
            Some(cwd) => cwd.to_string(),
            None => p["cwd"].as_str().unwrap_or("/").to_string(),
        },
        terminal: req.tty,
        user,
        no_new_privileges: p["noNewPrivileges"].as_bool().unwrap_or(false),
        capabilities,
    })
}

/// The resource of an OCI rlimit type (`RLIMIT_NOFILE`).
fn rlimit_resource(name: &str) -> Option<rustix::process::Resource> {
    use rustix::process::Resource;
    Some(match name {
        "RLIMIT_AS" => Resource::As,
        "RLIMIT_CORE" => Resource::Core,
        "RLIMIT_CPU" => Resource::Cpu,
        "RLIMIT_DATA" => Resource::Data,
        "RLIMIT_FSIZE" => Resource::Fsize,
        "RLIMIT_LOCKS" => Resource::Locks,
        "RLIMIT_MEMLOCK" => Resource::Memlock,
        "RLIMIT_MSGQUEUE" => Resource::Msgqueue,
        "RLIMIT_NICE" => Resource::Nice,
        "RLIMIT_NOFILE" => Resource::Nofile,
        "RLIMIT_NPROC" => Resource::Nproc,
        "RLIMIT_RSS" => Resource::Rss,
        "RLIMIT_RTPRIO" => Resource::Rtprio,
        "RLIMIT_RTTIME" => Resource::Rttime,
        "RLIMIT_SIGPENDING" => Resource::Sigpending,
        "RLIMIT_STACK" => Resource::Stack,
        _ => return None,
    })
}

/// The rlimits of the process of the container's spec (unknown ones and
/// a spec that cannot be read give none).
fn container_rlimits(spec: &Path) -> Vec<(rustix::process::Resource, u64, u64)> {
    let Ok(text) = std::fs::read_to_string(spec) else {
        return Vec::new();
    };
    let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) else {
        return Vec::new();
    };
    v["process"]["rlimits"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|r| {
                    let res = rlimit_resource(r["type"].as_str()?)?;
                    Some((res, r["soft"].as_u64()?, r["hard"].as_u64()?))
                })
                .collect()
        })
        .unwrap_or_default()
}

fn io_err(e: rustix::io::Errno) -> io::Error {
    e.into()
}

fn pipe() -> io::Result<(OwnedFd, OwnedFd)> {
    rustix::pipe::pipe_with(rustix::pipe::PipeFlags::CLOEXEC).map_err(io_err)
}

fn nonblocking(fd: &OwnedFd) -> io::Result<()> {
    rustix::fs::fcntl_setfl(fd, rustix::fs::OFlags::NONBLOCK).map_err(io_err)
}

impl ExecSession {
    /// Start `req` in the container.
    pub fn spawn(
        cfg: &MonitorConfig,
        process: Option<&serde_json::Value>,
        dir: &Path,
        seq: u64,
        client: u64,
        req: &ExecRequest,
        preserved: Vec<OwnedFd>,
    ) -> io::Result<Self> {
        if req.command.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "no command to run",
            ));
        }
        let pid_file = dir.join(format!("exec-{seq}.pid"));
        let _ = std::fs::remove_file(&pid_file);
        let mut cmd = super::server::child_command(&cfg.runtime);
        cmd.args(&cfg.runtime_args)
            .arg("--root")
            .arg(&cfg.runtime_root)
            .arg("exec")
            .arg("--detach");
        cmd.arg("--pid-file").arg(&pid_file);
        if !preserved.is_empty() {
            cmd.arg("--preserve-fds").arg(preserved.len().to_string());
        }
        let console = if req.tty {
            let path = dir.join(format!("exec-{seq}.console"));
            let _ = std::fs::remove_file(&path);
            let l = net::socket_with(
                AddressFamily::UNIX,
                SocketType::STREAM,
                SocketFlags::CLOEXEC,
                None,
            )
            .map_err(io_err)?;
            net::bind(&l, &SocketAddrUnix::new(&path)?).map_err(io_err)?;
            net::listen(&l, 1).map_err(io_err)?;
            cmd.arg("--tty").arg("--console-socket").arg(&path);
            Some((l, path))
        } else {
            None
        };
        let file = dir.join(format!("exec-{seq}.process.json"));
        std::fs::write(
            &file,
            serde_json::to_vec(&exec_process(cfg, process, req)?)?,
        )?;
        cmd.arg("--process").arg(&file).arg(&cfg.id);

        let mut out_r = None;
        let mut stdin_w = None;
        let (err_r, err_w) = pipe()?;
        nonblocking(&err_r)?;
        if req.tty {
            cmd.stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::from(err_w));
        } else {
            let (o_r, o_w) = pipe()?;
            nonblocking(&o_r)?;
            out_r = Some(o_r);
            cmd.stdout(Stdio::from(o_w)).stderr(Stdio::from(err_w));
            if req.stdin {
                let (i_r, i_w) = pipe()?;
                nonblocking(&i_w)?;
                // (its client writes to it: a bigger buffer, fewer wake-ups
                // of the command for a fast input)
                let _ = rustix::pipe::fcntl_setpipe_size(&i_w, STDIN_PIPE);
                stdin_w = Some(i_w);
                cmd.stdin(Stdio::from(i_r));
            } else {
                cmd.stdin(Stdio::null());
            }
        }
        // The runtime starts the process with its own limits: those of the
        // container, as podman's exec gets them.
        let limits = container_rlimits(&cfg.bundle.join("config.json"));
        let kept: Vec<i32> = preserved.iter().map(|f| f.as_raw_fd()).collect();
        let holes: Vec<i32> = req.preserve_holes.iter().map(|h| 3 + *h as i32).collect();
        velarx_sys::spawn::pre_exec(&mut cmd, move |child| {
            child.unblock_signals()?;
            child.place_fds(&kept, 3)?;
            for hole in &holes {
                child.close(*hole);
            }
            Ok(())
        });
        // (after the descriptors are placed: the low ones of a monitor that
        // holds many published ports are all in use)
        velarx_base::hardening::restore_open_files(&mut cmd, cfg.open_files);
        velarx_sys::spawn::pre_exec(&mut cmd, move |_| {
            for (resource, soft, hard) in &limits {
                // best effort: one the engine may not raise stays its own
                let _ = rustix::process::setrlimit(
                    *resource,
                    rustix::process::Rlimit {
                        current: Some(*soft),
                        maximum: Some(*hard),
                    },
                );
            }
            Ok(())
        });
        let child = cmd.spawn()?;
        drop(cmd);
        drop(preserved);
        let pid = child.id() as i32;
        let pidfd = velarx_sys::pidfd::open_child(pid)?;
        drop(child);
        Ok(Self {
            client,
            pid,
            pidfd,
            out_r,
            err_r: Some(err_r),
            stdin_w,
            pty: None,
            console,
            pid_file,
            process: file,
            runtime_name: crate::container::runtime_name_of(&cfg.runtime),
            started: false,
            deadline: req
                .timeout_ms
                .map(|ms| Instant::now() + Duration::from_millis(ms)),
            stdin_buf: VecDeque::new(),
            stdin_close: false,
            stderr_tail: Vec::new(),
            status: None,
            lost: None,
            drain_until: None,
            reason: Reason::Exited,
            pending_size: None,
            kill_pending: None,
            signals_pending: Vec::new(),
            start_by: Instant::now() + START_LIMIT,
            runtime_killed: false,
            detached: req.detach,
            capture: None,
            start_seen: false,
            notify_start: false,
            held_err: Vec::new(),
        })
    }

    pub fn pidfd(&self) -> BorrowedFd<'_> {
        self.pidfd.as_fd()
    }

    /// Collect the status of the process followed if it has exited: the
    /// runtime that started the command (which is followed from then on),
    /// or that could not; the command.
    pub fn reap(&mut self, drain: Duration) {
        if self.status.is_some() {
            return;
        }
        match velarx_sys::pidfd::reap(&self.pidfd) {
            Ok(Some(0)) if !self.started => self.runtime_started_it(drain),
            Ok(Some(code)) => self.set_status(code, drain),
            Ok(None) => {}
            Err(e) => self.lose_status(format!("waiting for it: {e}"), drain),
        }
    }

    /// The command ran but its status cannot be had: said so, never a code.
    fn lose_status(&mut self, why: String, drain: Duration) {
        super::server::diag(&format!("the status of an exec is lost: {why}"));
        self.lost = Some(why);
        self.set_status(255, drain);
    }

    /// Why the status of the command is unknown, if it is.
    pub fn status_lost(&self) -> Option<&str> {
        self.lost.as_deref()
    }

    /// The runtime exited with success: the command runs (or ran), a child
    /// of the monitor since the runtime is gone.  A kill that waited for the
    /// start is delivered now.
    fn runtime_started_it(&mut self, drain: Duration) {
        let Some(pid) = self.host_pid() else {
            return self.lose_status("the runtime did not write its pid".into(), drain);
        };
        match velarx_sys::pidfd::open_child(pid) {
            Ok(fd) => {
                self.pid = pid;
                self.pidfd = fd;
                self.started = true;
            }
            Err(e) => {
                return self.lose_status(format!("the command {pid} is not a child: {e}"), drain);
            }
        }
        for sig in std::mem::take(&mut self.signals_pending) {
            let _ = sys::pidfd_send_signal(&self.pidfd, sig);
        }
        if self.kill_pending.is_some() {
            self.kill_known();
        }
    }

    /// Whether the runtime has not yet told if it started the command.  The
    /// command may by then be an orphan of the monitor that already exited,
    /// before its pid is known: its zombie is not a stray, the session
    /// takes it over through its pidfd once the runtime exited.
    pub fn starting(&self) -> bool {
        !self.started && self.status.is_none()
    }

    /// The pid of the command, once the runtime wrote it.
    fn host_pid(&self) -> Option<i32> {
        std::fs::read_to_string(&self.pid_file)
            .ok()?
            .trim()
            .parse()
            .ok()
            .filter(|&p| p > 1)
    }

    /// Kill the command and everything it started.
    pub fn kill_group(&mut self, reason: Reason) {
        if self.status.is_some() {
            return;
        }
        self.reason = reason;
        if !self.kill_known() {
            // (the runtime has not started it yet)
            self.kill_pending.get_or_insert_with(Instant::now);
        }
    }

    /// Kill the command and its group if it started.  The group's id is
    /// the pid of the command, which leads it: an unreaped child of the
    /// monitor, so the number is nobody else's (not reaped: the session has
    /// no status yet).  The command itself goes through its pidfd.
    fn kill_known(&mut self) -> bool {
        if !self.started {
            return false;
        }
        self.kill_pending = None;
        if let Some(p) = Pid::from_raw(self.pid) {
            let _ = rustix::process::kill_process_group(p, rustix::process::Signal::KILL);
        }
        let _ = sys::pidfd_send_signal(&self.pidfd, libc::SIGKILL);
        true
    }

    /// When the runtime is killed: a pending kill gives up on the command,
    /// or the runtime takes too long to start it.
    pub fn kill_runtime_at(&self) -> Option<Instant> {
        if self.status.is_some() || self.started || self.runtime_killed {
            return None;
        }
        let late = self.kill_pending.map(|since| since + KILL_RUNTIME_AFTER);
        Some(late.map_or(self.start_by, |l| l.min(self.start_by)))
    }

    /// Kill the runtime that has not started the command: after
    /// [`KILL_RUNTIME_AFTER`] for a pending kill, after [`START_LIMIT`]
    /// in any case.
    pub fn kill_runtime_if_late(&mut self, t: Instant) {
        if self.status.is_some() || self.started {
            self.kill_pending = None;
            return;
        }
        if self.kill_runtime_at().is_some_and(|at| t >= at) {
            if self.kill_pending.is_none() {
                super::server::diag(&format!(
                    "the runtime did not start a command in {} s: killing it",
                    START_LIMIT.as_secs()
                ));
            }
            let _ = rustix::process::pidfd_send_signal(&self.pidfd, rustix::process::Signal::KILL);
            self.kill_pending = None;
            self.runtime_killed = true;
        }
    }

    /// Send a signal to the command.
    pub fn signal(&mut self, sig: i32) {
        if self.status.is_some() || !sys::valid_signal(sig) {
            return;
        }
        if !self.started {
            // (each once: there are 64 of them)
            if !self.signals_pending.contains(&sig) {
                self.signals_pending.push(sig);
            }
            return;
        }
        let _ = sys::pidfd_send_signal(&self.pidfd, sig);
    }

    pub fn reason(&self) -> Reason {
        self.reason
    }

    /// The terminal arrived on the console socket.
    pub fn accept_console(&mut self) {
        let Some((l, path)) = self.console.take() else {
            return;
        };
        if let Ok(conn) = net::accept_with(&l, SocketFlags::CLOEXEC) {
            if let Some(fd) = super::server::receive_fd(&conn) {
                if nonblocking(&fd).is_ok() {
                    self.pty = Some(fd);
                    if let Some((rows, cols)) = self.pending_size.take() {
                        self.resize(rows, cols);
                    }
                }
            }
        }
        let _ = std::fs::remove_file(path);
    }

    pub fn resize(&mut self, rows: u16, cols: u16) {
        if self.pty.is_none() {
            self.pending_size = Some((rows, cols));
        }
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

    /// Read what a stream has: `(is_stderr, data)`; `None` when it is at its
    /// end (the descriptor is closed) or has nothing yet.
    pub fn read(&mut self, which: Which) -> Option<(bool, Vec<u8>)> {
        let slot = match which {
            Which::Out => &mut self.out_r,
            Which::Err => &mut self.err_r,
            Which::Pty => &mut self.pty,
        };
        let fd = slot.as_ref()?;
        let mut buf = vec![0u8; READ_CHUNK];
        match rustix::io::read(fd, &mut buf) {
            Ok(0) | Err(rustix::io::Errno::IO) => {
                *slot = None;
                None
            }
            Ok(n) => {
                buf.truncate(n);
                let stderr = which == Which::Err;
                if stderr {
                    let room = STDERR_TAIL.saturating_sub(self.stderr_tail.len());
                    self.stderr_tail.extend_from_slice(&buf[..n.min(room)]);
                }
                Some((stderr, buf))
            }
            Err(rustix::io::Errno::AGAIN) | Err(rustix::io::Errno::INTR) => None,
            Err(_) => {
                *slot = None;
                None
            }
        }
    }

    pub fn wants_input(&self) -> bool {
        !self.stdin_buf.is_empty()
    }

    pub fn input_full(&self) -> bool {
        self.stdin_buf.len() >= STDIN_LIMIT
    }

    pub fn queue_stdin(&mut self, data: &[u8]) {
        if self.pty.is_none() && self.stdin_w.is_none() {
            return;
        }
        self.stdin_buf.extend(data);
        self.write_stdin();
    }

    pub fn close_stdin(&mut self) {
        self.stdin_close = true;
        self.write_stdin();
    }

    pub fn write_stdin(&mut self) {
        let fd = self.pty.as_ref().or(self.stdin_w.as_ref());
        if !velarx_wire::monitor::sys::flush_stdin(fd, &mut self.stdin_buf) {
            return;
        }
        if self.stdin_close && self.stdin_buf.is_empty() {
            self.stdin_close = false;
            if self.pty.is_some() {
                // End of transmission: a terminal cannot be closed.
                self.stdin_buf.push_back(0x04);
                self.write_stdin();
            } else {
                self.stdin_w = None;
            }
        }
    }

    /// The write end of the pipe of the command's input, for its client:
    /// what it writes goes to the command without the monitor, and the
    /// command's input ends when the client closes it.
    pub fn take_stdin_pipe(&mut self) -> Option<OwnedFd> {
        if self.pty.is_some() || self.console.is_some() {
            return None;
        }
        self.stdin_buf.clear();
        self.stdin_w.take()
    }

    pub fn stdin_fd(&self) -> Option<BorrowedFd<'_>> {
        self.stdin_w.as_ref().map(|f| f.as_fd())
    }

    /// The command (runtime process) exited with `code`.
    pub fn set_status(&mut self, code: i32, drain: Duration) {
        self.status = Some(code);
        self.stdin_w = None;
        self.stdin_buf.clear();
        self.drain_until = Some(Instant::now() + drain);
    }

    /// The runtime started the command (it exited with success).  What a
    /// session that ends without it says is the runtime's, not the
    /// command's.
    pub fn command_started(&self) -> bool {
        self.started
    }

    /// Standard error of the session: kept while the command has not
    /// started (it is the runtime's), passed on when it has.
    pub fn pass_stderr(&mut self, data: Vec<u8>) -> Option<Vec<u8>> {
        if self.command_started() {
            let mut all = std::mem::take(&mut self.held_err);
            all.extend(data);
            return Some(all);
        }
        let room = STDERR_TAIL.saturating_sub(self.held_err.len());
        self.held_err
            .extend_from_slice(&data[..data.len().min(room)]);
        None
    }

    /// What was kept of the standard error, for the client once the command
    /// started.
    pub fn take_held_stderr(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.held_err)
    }

    /// What the client is told of a session that ended, from the standard
    /// error that was kept: the runtime's failure in podman's words
    /// (`Error: crun: ...: OCI permission denied`), or what the command said.
    pub fn final_stderr(&mut self) -> Vec<u8> {
        let held = std::mem::take(&mut self.held_err);
        if held.is_empty() || self.command_started() {
            return held;
        }
        match self.exit_code() {
            Some(126 | 127) => {
                let text = String::from_utf8_lossy(&held);
                format!(
                    "Error: {}\n",
                    crate::container::oci_error_for(&self.runtime_name, &text)
                )
                .into_bytes()
            }
            _ => held,
        }
    }

    /// Whether the start of the command was just seen.
    pub fn take_started(&mut self) -> bool {
        if self.start_seen || !self.command_started() {
            return false;
        }
        self.start_seen = true;
        true
    }

    /// The exit code for the client, with the code it expects when the
    /// command could not run (127, 126): the runtime exited without having
    /// started it, and says why on its standard error, which can still be
    /// unread when it exits: ask once the session is drained.
    pub fn exit_code(&self) -> Option<i32> {
        let code = self.status?;
        // (a runtime that failed exits with an error, not a signal: crun with
        // 1, runc with 255; a session ended by a kill or its time limit, or
        // whose status is lost, keeps its status)
        let failed = (1..128).contains(&code) || code == 255;
        Some(
            if failed
                && self.reason == Reason::Exited
                && self.lost.is_none()
                && !self.command_started()
            {
                failure_code(&String::from_utf8_lossy(&self.stderr_tail))
            } else {
                code
            },
        )
    }

    /// All the output was read, or the time for it is over.
    pub fn drained(&self) -> bool {
        self.status.is_some()
            && ((self.out_r.is_none() && self.err_r.is_none() && self.pty.is_none())
                || self.drain_until.is_some_and(|d| Instant::now() >= d))
    }
}

impl Drop for ExecSession {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.pid_file);
        let _ = std::fs::remove_file(&self.process);
        if let Some((_, path)) = &self.console {
            let _ = std::fs::remove_file(path);
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Which {
    Out,
    Err,
    Pty,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failures_get_the_usual_codes() {
        assert_eq!(
            failure_code(
                "crun: executable file `/nope` not found in $PATH: No such file or directory"
            ),
            127
        );
        assert_eq!(
            failure_code("crun: chdir to `/x`: No such file or directory"),
            127
        );
        assert_eq!(failure_code("crun: open /x: Permission denied"), 126);
        assert_eq!(
            failure_code("the path `/etc` is not a regular file: Operation not permitted"),
            126
        );
        // (runc's words, and its exit code of 255 is not the command's)
        assert_eq!(
            failure_code("exec failed: unable to start container process: exec: \"x\": executable file not found in $PATH"),
            127
        );
        // (podman: any other failure of the runtime to start it)
        assert_eq!(failure_code("something else"), 126);
    }

    /// A bundle with an image's users and the process of its container,
    /// and the monitor's configuration with `--group-add` `group_add`.
    fn bundle(group_add: &[&str], env_has_home: bool) -> (tempfile::TempDir, MonitorConfig) {
        let dir = tempfile::tempdir().unwrap();
        let etc = dir.path().join("rootfs/etc");
        std::fs::create_dir_all(&etc).unwrap();
        std::fs::write(
            etc.join("passwd"),
            "root:x:0:0:root:/root:/bin/sh\ndaemon:x:2:2:d:/sbin:/sbin/nologin\n",
        )
        .unwrap();
        std::fs::write(
            etc.join("group"),
            "root:x:0:root\nbin:x:1:root,daemon\ndaemon:x:2:\nadm:x:4:daemon\nwheel:x:10:\n",
        )
        .unwrap();
        std::fs::write(
            dir.path().join("config.json"),
            r#"{"process": {"args": ["sleep", "1"], "cwd": "/w", "terminal": true,
                "env": ["PATH=/bin", "HOME=/root", "A=1"],
                "user": {"uid": 0, "gid": 0, "umask": 18, "additionalGids": [0, 1, 10]},
                "capabilities": {"bounding": ["CAP_CHOWN"], "effective": ["CAP_CHOWN"]},
                "noNewPrivileges": true}}"#,
        )
        .unwrap();
        let cfg = serde_json::from_value(serde_json::json!({
            "id": "c", "runtime": "crun", "runtime_root": "/r",
            "bundle": dir.path(), "group_add": group_add, "env_has_home": env_has_home,
        }))
        .unwrap();
        (dir, cfg)
    }

    fn process(cfg: &MonitorConfig, req: &ExecRequest) -> io::Result<serde_json::Value> {
        exec_process(cfg, None, req).map(|p| serde_json::to_value(p).unwrap())
    }

    fn request(user: &str) -> ExecRequest {
        serde_json::from_value(serde_json::json!({
            "command": ["id"], "env": ["A=2", "B=3"], "user": user,
        }))
        .unwrap()
    }

    #[test]
    fn an_exec_as_a_user_gets_its_groups_and_the_added_ones() {
        let (_d, cfg) = bundle(&["wheel", "1234"], false);
        let groups = |user: &str| {
            let p = process(&cfg, &request(user)).unwrap();
            let ids = |k: &str| p["user"][k].clone();
            (ids("uid"), ids("gid"), ids("additionalGids"))
        };
        use serde_json::json;
        // (podman 5.8: the image's groups of the user unless it names its
        // group, its group first, `--group-add` always)
        assert_eq!(
            groups("daemon"),
            (json!(2), json!(2), json!([2, 10, 1234, 1, 4]))
        );
        assert_eq!(groups("2:2"), (json!(2), json!(2), json!([2, 10, 1234])));
        assert_eq!(
            groups("daemon:adm"),
            (json!(2), json!(4), json!([4, 10, 1234]))
        );
        let nogroup = process(&cfg, &request("daemon:nosuch")).unwrap_err();
        assert!(
            nogroup
                .to_string()
                .contains("unable to find group nosuch: no matching entries in group file"),
            "{nogroup}"
        );
        assert_eq!(
            groups("root"),
            (json!(0), json!(0), json!([0, 10, 1234, 1]))
        );
        assert_eq!(
            groups("4321"),
            (json!(4321), json!(0), json!([0, 10, 1234]))
        );
        let ghost = process(&cfg, &request("ghost")).unwrap_err();
        assert!(
            ghost
                .to_string()
                .contains("unable to find user ghost: no matching entries in passwd file"),
            "{ghost}"
        );
    }

    /// The process of the spec the container was created with, not the
    /// bundle's when an update changed it since.
    #[test]
    fn an_exec_runs_on_the_process_the_container_was_created_with() {
        use serde_json::json;
        let (_d, cfg) = bundle(&[], false);
        let created = json!({"args": ["sleep", "1"], "cwd": "/", "env": ["PATH=/bin", "A=old"],
            "user": {"uid": 0, "gid": 0}});
        let mut req = request("");
        req.env.clear();
        let p = serde_json::to_value(exec_process(&cfg, Some(&created), &req).unwrap()).unwrap();
        assert_eq!(p["env"], json!(["PATH=/bin", "A=old"]));
        assert_eq!(p["cwd"], "/");
    }

    #[test]
    fn an_exec_runs_the_command_in_the_process_of_the_container() {
        use serde_json::json;
        let (_d, cfg) = bundle(&[], false);
        let mut req = request("");
        req.tty = true;
        let p = process(&cfg, &req).unwrap();
        assert_eq!(p["args"], json!(["id"]));
        assert_eq!(p["env"], json!(["PATH=/bin", "HOME=/root", "A=2", "B=3"]));
        assert_eq!((&p["cwd"], &p["terminal"]), (&"/w".into(), &true.into()));
        assert_eq!(
            p["user"],
            json!({"uid": 0, "gid": 0, "umask": 18, "additionalGids": [0, 1, 10]})
        );
        // (the runtime gives the container's)
        assert!(p["capabilities"].is_null());
        assert_eq!(p["noNewPrivileges"], true);
        // Another user gets its home, unless the container names one.
        let p = process(&cfg, &request("daemon")).unwrap();
        assert_eq!(p["env"], json!(["PATH=/bin", "HOME=/sbin", "A=2", "B=3"]));
        assert_eq!(
            (&p["terminal"], &p["user"]["umask"]),
            (&false.into(), &18.into())
        );
        let mut req = request("4321");
        req.cwd = Some("/tmp".into());
        let p = process(&cfg, &req).unwrap();
        assert_eq!((&p["env"][1], &p["cwd"]), (&"HOME=".into(), &"/tmp".into()));
        let (_d, cfg) = bundle(&[], true);
        let p = process(&cfg, &request("daemon")).unwrap();
        assert_eq!(p["env"][1], "HOME=/root");
    }

    #[test]
    fn a_privileged_exec_gets_every_capability_as_podman_gives_them() {
        let (_d, cfg) = bundle(&[], false);
        let caps = |user: &str| {
            let mut req = request(user);
            req.privileged = true;
            let p = process(&cfg, &req).unwrap();
            let n = |set: &str| p["capabilities"][set].as_array().map_or(0, Vec::len);
            (n("bounding"), n("effective"))
        };
        let all = crate::container::caps::all_capabilities().len();
        assert!(all > 1);
        assert_eq!(caps(""), (all, all));
        // (not root: the bounding set only, as podman's exec --privileged)
        assert_eq!(caps("daemon"), (all, 0));
    }

    #[test]
    fn a_link_to_the_host_stays_in_the_image() {
        let (d, cfg) = bundle(&[], false);
        // Points outside: resolved inside the root, where there is nothing.
        let passwd = d.path().join("rootfs/etc/passwd");
        std::fs::remove_file(&passwd).unwrap();
        std::os::unix::fs::symlink("/etc/passwd", &passwd).unwrap();
        assert!(process(&cfg, &request("root")).is_err());
    }

    #[test]
    fn the_rlimits_of_the_spec() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("config.json");
        std::fs::write(
            &p,
            r#"{"process": {"rlimits": [{"type": "RLIMIT_NOFILE", "soft": 1024, "hard": 2048}, {"type": "RLIMIT_BOGUS", "soft": 1, "hard": 1}]}}"#,
        )
        .unwrap();
        assert_eq!(
            container_rlimits(&p),
            vec![(rustix::process::Resource::Nofile, 1024, 2048)]
        );
        assert!(container_rlimits(&d.path().join("missing")).is_empty());
    }
}
