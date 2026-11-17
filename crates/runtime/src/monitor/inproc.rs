// SPDX-License-Identifier: Apache-2.0
//! `velarx run --no-monitor`: the process that runs a container in
//! the foreground is its monitor; no `velarx-monitor` process is started.
//!
//! The engine splits in two before it starts any thread ([`split`]):
//!
//! - the child goes on as the engine: it makes the container as usual, but
//!   where it would start a monitor process it hands the run directory to
//!   its parent ([`Handoff::monitor`]), and once the container waits for
//!   its client ([`Handoff::attach`]) it is done and exits;
//! - the parent, the process the caller started (a shell's child, the main
//!   process of a unit), runs the monitor in process
//!   ([`super::run_in_process`]) with a thread that attaches the standard
//!   streams to the container, as the client of a foreground run does, and
//!   exits with the status of the container.
//!
//! The state of the monitor (run directory, socket, exit file, database
//! rows) is the one a monitor process has: other clients see no difference.

use std::io::{self, BufRead, Write};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

use super::relay::{AttachEnd, AttachOptions};
use velarx_base::spawn::SpawnOptions;

/// How the parent attaches to the container: the options of `run`.
#[derive(Debug, Clone, Copy, Default)]
pub struct AttachSpec {
    pub tty: bool,
    pub stdin: bool,
    pub sig_proxy: bool,
}

/// What the engine tells the parent when the monitor is to run.
#[derive(Debug, Serialize, Deserialize, PartialEq)]
struct MonitorMsg {
    dir: PathBuf,
    notify_socket: Option<String>,
    env: Vec<(String, String)>,
    /// The descriptors for the container (`LISTEN_FDS`): the numbers of
    /// the engine, which the parent has too (they were open at the split).
    preserve_fds: Vec<i32>,
    cgroup: Option<PathBuf>,
    /// The mounts of the root file system (`MonitorConfig::rootfs_fds`): this
    /// many descriptors come with the message (made after the split, the
    /// parent has no copy of them)
    #[serde(default)]
    rootfs_fds: usize,
    /// One more descriptor comes after those: the network namespace of the
    /// container (`MonitorConfig::netns_fd`).
    #[serde(default)]
    netns: bool,
    /// One more after that: the directory of the health log.
    #[serde(default)]
    health_log_dir: bool,
    /// One more after that: the rootless namespace of the bridge networks.
    #[serde(default)]
    bridge_netns: bool,
}

/// What the engine keeps of the split: its ends of the first connection
/// of the monitor and of the channel to the parent.
pub struct Handoff {
    daemon_end: Mutex<Option<UnixStream>>,
    ctl: Mutex<Option<UnixStream>>,
}

impl std::fmt::Debug for Handoff {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Handoff")
            .field("pending", &lock(&self.daemon_end).is_some())
            .finish()
    }
}

impl Handoff {
    /// The parent runs the monitor of the run directory `dir`; the
    /// engine's end of its first connection.
    /// Once only: `None` after.
    pub fn monitor(&self, dir: &Path, opts: &SpawnOptions) -> io::Result<Option<UnixStream>> {
        let Some(conn) = lock(&self.daemon_end).take() else {
            return Ok(None);
        };
        let text = |s: &std::ffi::OsStr| {
            s.to_str()
                .map(str::to_string)
                .ok_or_else(|| io::Error::other("an environment variable is not UTF-8"))
        };
        let msg = MonitorMsg {
            dir: dir.to_path_buf(),
            notify_socket: opts.notify_socket.as_deref().map(text).transpose()?,
            env: opts
                .env
                .iter()
                .map(|(k, v)| Ok((text(k)?, text(v)?)))
                .collect::<io::Result<_>>()?,
            preserve_fds: opts.preserve_fds.iter().map(|f| f.as_raw_fd()).collect(),
            cgroup: opts.cgroup.clone(),
            rootfs_fds: opts.rootfs_fds.len(),
            netns: opts.netns.is_some(),
            health_log_dir: opts.health_log_dir.is_some(),
            bridge_netns: opts.bridge_netns.is_some(),
        };
        let mut line = serde_json::to_vec(&msg).map_err(io::Error::other)?;
        line.push(b'\n');
        let mut ctl = lock(&self.ctl);
        let stream = ctl
            .as_mut()
            .ok_or_else(|| io::Error::other("the parent is gone"))?;
        let fds: Vec<_> = opts
            .rootfs_fds
            .iter()
            .chain(&opts.netns)
            .chain(&opts.health_log_dir)
            .chain(&opts.bridge_netns)
            .map(|f| f.as_fd())
            .collect();
        let sent = send_with_fds(stream, &line, &fds)?;
        stream.write_all(&line[sent..])?;
        Ok(Some(conn))
    }

    /// The container waits for its client: the parent attaches.
    pub fn attach(&self) {
        if let Some(mut stream) = lock(&self.ctl).take() {
            let _ = stream.write_all(b"attach\n");
        }
    }
}

/// Send the first bytes of `bytes` with the descriptors `fds` (one
/// `sendmsg`): how many went.
fn send_with_fds(
    stream: &UnixStream,
    bytes: &[u8],
    fds: &[std::os::fd::BorrowedFd<'_>],
) -> io::Result<usize> {
    use rustix::net::{sendmsg, SendAncillaryBuffer, SendAncillaryMessage, SendFlags};
    let mut space = [std::mem::MaybeUninit::uninit();
        rustix::cmsg_space!(ScmRights(
            velarx_base::spawn::MAX_FETCHER_FDS + velarx_base::spawn::MAX_ROOTFS_FDS
        ))];
    let mut control = SendAncillaryBuffer::new(&mut space);
    if !fds.is_empty() && !control.push(SendAncillaryMessage::ScmRights(fds)) {
        return Err(io::Error::other("too many descriptors for the parent"));
    }
    loop {
        match sendmsg(
            stream,
            &[io::IoSlice::new(bytes)],
            &mut control,
            SendFlags::empty(),
        ) {
            Err(rustix::io::Errno::INTR) => {}
            r => return r.map_err(io::Error::from),
        }
    }
}

/// A line of `stream`, read a byte at a time (what follows it is left for
/// the next reader), and the descriptors that came with it.
fn read_line_with_fds(stream: &UnixStream) -> io::Result<(String, Vec<OwnedFd>)> {
    let mut line = Vec::new();
    let mut fds = Vec::new();
    loop {
        let mut byte = [0u8; 1];
        let got = velarx_sys::scm::recv(
            stream,
            &mut byte,
            velarx_base::spawn::MAX_FETCHER_FDS + velarx_base::spawn::MAX_ROOTFS_FDS,
            rustix::net::RecvFlags::empty(),
        )?;
        fds.extend(got.fds);
        if got.bytes == 0 || byte[0] == b'\n' {
            return Ok((String::from_utf8_lossy(&line).into_owned(), fds));
        }
        line.push(byte[0]);
    }
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    match m.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    }
}

/// Split the process: in the child (the engine) the handoff; the parent
/// runs the monitor of the container and exits with its status, it never
/// returns.  Must be called before any thread is started.
pub fn split(spec: AttachSpec, held: &[BorrowedFd<'_>]) -> io::Result<Handoff> {
    let (daemon_end, monitor_end) = UnixStream::pair()?;
    let (ctl_engine, ctl_parent) = UnixStream::pair()?;
    let pid = match velarx_sys::process::fork_single_threaded("the in-process monitor split")? {
        velarx_sys::process::Fork::Parent(pid) => pid,
        velarx_sys::process::Fork::Child(_) => 0,
    };
    if pid == 0 {
        drop(monitor_end);
        drop(ctl_parent);
        return Ok(Handoff {
            daemon_end: Mutex::new(Some(daemon_end)),
            ctl: Mutex::new(Some(ctl_engine)),
        });
    }
    drop(daemon_end);
    drop(ctl_engine);
    let code = be_monitor(pid, monitor_end, ctl_parent, spec, held);
    std::process::exit(code)
}

/// The exit status of the engine `pid`, which went away before it handed
/// the monitor over (it said why on the standard error).
fn engine_status(pid: libc::pid_t) -> i32 {
    velarx_sys::process::wait_exit_code(pid).unwrap_or(1)
}

/// Block `signals` in this thread (and the threads it starts).
fn block(signals: &[i32]) -> io::Result<()> {
    velarx_sys::signal::block(signals)
}

/// The signals the monitor takes, besides SIGCHLD, and those the client
/// part takes: a client without a terminal forwards the usual ones to the
/// container (`--sig-proxy`), one with a terminal only follows its size.
fn signal_sets(spec: AttachSpec) -> (Vec<i32>, Vec<i32>) {
    let stop = vec![libc::SIGTERM, libc::SIGINT, libc::SIGHUP];
    if spec.tty {
        let mut monitor = stop;
        monitor.push(libc::SIGUSR1);
        (monitor, vec![libc::SIGWINCH])
    } else if spec.sig_proxy {
        (Vec::new(), super::relay::PROXIED_SIGNALS.to_vec())
    } else {
        let mut monitor = stop;
        monitor.push(libc::SIGUSR1);
        (monitor, Vec::new())
    }
}

/// The descriptors that came with the request of the engine.
struct Handed {
    rootfs_fds: Vec<OwnedFd>,
    netns: Option<OwnedFd>,
    health_log_dir: Option<OwnedFd>,
    bridge_netns: Option<OwnedFd>,
}

fn be_monitor(
    engine: libc::pid_t,
    monitor_end: UnixStream,
    ctl: UnixStream,
    spec: AttachSpec,
    held: &[BorrowedFd<'_>],
) -> i32 {
    let (msg, rootfs_fds, netns, health_log_dir, bridge_netns) = match read_line_with_fds(&ctl) {
        Ok((line, mut fds)) if !line.is_empty() => {
            match serde_json::from_str::<MonitorMsg>(line.trim_end()) {
                Ok(msg)
                    if msg.rootfs_fds
                        + usize::from(msg.netns)
                        + usize::from(msg.health_log_dir)
                        + usize::from(msg.bridge_netns)
                        == fds.len() =>
                {
                    let bridge_netns = if msg.bridge_netns { fds.pop() } else { None };
                    let health_log_dir = if msg.health_log_dir { fds.pop() } else { None };
                    let netns = if msg.netns { fds.pop() } else { None };
                    (msg, fds, netns, health_log_dir, bridge_netns)
                }
                Ok(_) => {
                    eprintln!("Error: the engine sent the mounts without their descriptors");
                    return 125;
                }
                Err(e) => {
                    eprintln!("Error: the engine sent a bad request: {e}");
                    return 125;
                }
            }
        }
        // The engine failed before there was a container to monitor.
        _ => return engine_status(engine),
    };
    let ctl = io::BufReader::new(ctl);
    match monitor(
        msg,
        Handed {
            rootfs_fds,
            netns,
            health_log_dir,
            bridge_netns,
        },
        held,
        monitor_end,
        ctl,
        spec,
    ) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("Error: the monitor failed: {e}");
            125
        }
    }
}

fn monitor(
    msg: MonitorMsg,
    handed: Handed,
    held: &[BorrowedFd<'_>],
    monitor_end: UnixStream,
    mut ctl: io::BufReader<UnixStream>,
    spec: AttachSpec,
) -> io::Result<i32> {
    if let Some(cg) = &msg.cgroup {
        std::fs::write(cg.join("cgroup.procs"), b"0")?;
    }
    let preserved = msg
        .preserve_fds
        .iter()
        .map(|&number| {
            // (the engine names, by number, descriptors that were open at
            // the split: this side has its own copy of each, never a
            // second owner of the same number)
            held.iter()
                .find(|fd| fd.as_raw_fd() == number)
                .ok_or_else(|| io::Error::from_raw_os_error(libc::EBADF))?
                .try_clone_to_owned()
        })
        .collect::<io::Result<Vec<_>>>()?;

    // Each signal goes to one reader: every thread blocks them all.
    let (monitor_signals, client_signals) = signal_sets(spec);
    let mut all = vec![libc::SIGCHLD];
    all.extend(&monitor_signals);
    all.extend(&client_signals);
    block(&all)?;

    // The streams of the caller, for the client part: the monitor sends
    // what it has to say to its log.
    let dup = |fd: std::os::fd::BorrowedFd<'_>| {
        rustix::io::fcntl_dupfd_cloexec(fd, 3).map_err(io::Error::from)
    };
    let (stdin, stdout, stderr) = super::relay::stdio();
    let streams = (dup(stdin)?, dup(stdout)?, dup(stderr)?);

    let dir = msg.dir.clone();
    let attach = std::thread::Builder::new().name("attach".into()).spawn(
        move || -> Option<io::Result<AttachEnd>> {
            // The engine says when the container waits for us.
            let mut line = String::new();
            match ctl.read_line(&mut line) {
                Ok(n) if n > 0 && line.trim_end() == "attach" => {}
                _ => return None,
            }
            use std::os::fd::AsFd;
            let (stdin, stdout, stderr) = (&streams.0, &streams.1, &streams.2);
            let opts = AttachOptions {
                stdin: spec.stdin,
                tty: spec.tty,
                // Nobody would be left to wait for the container.
                detach_keys: Some(String::new()),
                sig_proxy: spec.sig_proxy,
                start: true,
                ..AttachOptions::default()
            };
            Some(super::relay::attach(
                &dir,
                &opts,
                stdin.as_fd(),
                stdout.as_fd(),
                stderr.as_fd(),
            ))
        },
    )?;

    let code = super::run_in_process(
        &msg.dir,
        super::Launch::InProcess {
            boot: std::os::fd::OwnedFd::from(monitor_end),
            preserved,
            stop_signals: monitor_signals,
            notify_socket: msg.notify_socket.clone(),
            env: msg.env.clone(),
            rootfs_fds: handed.rootfs_fds,
            netns: handed.netns,
            health_log_dir: handed.health_log_dir,
            bridge_netns: handed.bridge_netns,
        },
    );
    let attached = attach.join().ok().flatten();
    match (attached, code) {
        (Some(Ok(AttachEnd::Exited(c))), _) => Ok(c),
        (Some(Err(e)), Ok(c)) => {
            eprintln!("Error: attach: {e}");
            Ok(c)
        }
        (_, code) => code,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_signal_has_one_reader() {
        for spec in [
            AttachSpec {
                tty: true,
                stdin: true,
                sig_proxy: true,
            },
            AttachSpec {
                tty: false,
                stdin: false,
                sig_proxy: true,
            },
            AttachSpec {
                tty: false,
                stdin: false,
                sig_proxy: false,
            },
        ] {
            let (m, c) = signal_sets(spec);
            assert!(m.iter().all(|s| !c.contains(s)), "{spec:?}");
            // SIGINT and SIGTERM always end up somewhere
            for s in [libc::SIGINT, libc::SIGTERM] {
                assert!(
                    spec.tty && m.contains(&s) || !spec.tty && (m.contains(&s) || c.contains(&s))
                );
            }
        }
    }

    /// The descriptors come with the line that names them, and what
    /// follows the line is left for the next reader.
    #[test]
    fn the_descriptors_come_with_the_line() {
        let (engine, parent) = UnixStream::pair().unwrap();
        let file = tempfile::tempfile().unwrap();
        let sent = send_with_fds(&engine, b"{\"x\":1}\nattach\n", &[file.as_fd()]).unwrap();
        assert_eq!(sent, 15);
        let (line, fds) = read_line_with_fds(&parent).unwrap();
        assert_eq!((line.as_str(), fds.len()), ("{\"x\":1}", 1));
        let mut rest = String::new();
        io::BufReader::new(&parent).read_line(&mut rest).unwrap();
        assert_eq!(rest, "attach\n");
    }

    #[test]
    fn the_request_goes_through_json() {
        let msg = MonitorMsg {
            dir: "/run/x".into(),
            notify_socket: Some("/run/systemd/notify".into()),
            env: vec![("A".into(), "b".into())],
            preserve_fds: vec![4, 5],
            cgroup: None,
            rootfs_fds: 1,
            netns: true,
            health_log_dir: true,
            bridge_netns: true,
        };
        let text = serde_json::to_string(&msg).unwrap();
        assert!(!text.contains('\n'));
        assert_eq!(serde_json::from_str::<MonitorMsg>(&text).unwrap(), msg);
    }
}
