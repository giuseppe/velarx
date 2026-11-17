// SPDX-License-Identifier: Apache-2.0
//! The daemon process: it starts, serves its socket, and stops cleanly.

use crate::monitor_common::kill;
use std::io::Read;
use std::os::unix::net::UnixDatagram;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// Wait for `child` at most `limit`; its exit status, or None.
fn wait_for(child: &mut Child, limit: Duration) -> Option<std::process::ExitStatus> {
    velarx_base::testing::wait_exit(child.id() as i32, limit);
    child.try_wait().unwrap()
}

/// A notification socket for a daemon (`NOTIFY_SOCKET`) in `dir`.
fn notify_socket(dir: &Path) -> (std::path::PathBuf, UnixDatagram) {
    let path = dir.join("notify.sock");
    let socket = UnixDatagram::bind(&path).unwrap();
    (path, socket)
}

/// Wait at most `limit` for `daemon` to say READY=1 on `notify`; false
/// when it exited or the time is up.
fn wait_ready(daemon: &Child, notify: &UnixDatagram, limit: Duration) -> bool {
    let pid = rustix::process::Pid::from_raw(daemon.id() as i32).unwrap();
    let Ok(pidfd) = rustix::process::pidfd_open(pid, rustix::process::PidfdFlags::empty()) else {
        return false;
    };
    let deadline = Instant::now() + limit;
    let mut buf = [0u8; 4096];
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        let timeout = rustix::event::Timespec {
            tv_sec: left.as_secs() as i64,
            tv_nsec: left.subsec_nanos() as i64,
        };
        let mut fds = [
            rustix::event::PollFd::new(notify, rustix::event::PollFlags::IN),
            rustix::event::PollFd::new(&pidfd, rustix::event::PollFlags::IN),
        ];
        if left.is_zero() || rustix::event::poll(&mut fds, Some(&timeout)).unwrap_or(0) == 0 {
            return false;
        }
        if fds[0].revents().is_empty() {
            // the daemon exited
            return false;
        }
        let n = notify.recv(&mut buf).unwrap();
        if buf[..n].split(|b| *b == b'\n').any(|l| l == b"READY=1") {
            return true;
        }
    }
}

#[test]
fn the_daemon_stops_cleanly_on_sigterm() {
    stop_a_daemon(
        Path::new(crate::common::worker()),
        &["--log-level", "info", "varlink"],
    );
}

/// Start `program ARGS` as the engine service of a store of its own, stop it
/// with SIGTERM and check that it stopped cleanly; its log.
fn stop_a_daemon(program: &Path, args: &[&str]) -> String {
    let work = tempfile::Builder::new()
        .prefix("shd-")
        .tempdir_in("/var/tmp")
        .unwrap();
    let base = work.path();
    let (home, run) = (base.join("home"), base.join("run"));
    std::fs::create_dir_all(&home).unwrap();
    std::fs::create_dir_all(&run).unwrap();
    std::fs::set_permissions(&run, std::os::unix::fs::PermissionsExt::from_mode(0o700)).unwrap();
    let socket = run.join("engine.sock");
    let config = base.join("config.toml");
    std::fs::write(
        &config,
        format!(
            "[engine]\nsocket = \"{}\"\n[server]\nstate_dir = \"{}\"\nroot_dir = \"{}\"\n\
             [storage]\nroot = \"{}\"\n",
            socket.display(),
            base.join("state").display(),
            base.join("root").display(),
            base.join("storage").display(),
        ),
    )
    .unwrap();
    let log = std::fs::File::create(base.join("daemon.log")).unwrap();
    let (notify_path, notify) = notify_socket(base);
    let mut daemon = Command::new(program)
        .arg("--config")
        .arg(&config)
        .args(args)
        .env("HOME", &home)
        .env("XDG_RUNTIME_DIR", &run)
        .env("NOTIFY_SOCKET", &notify_path)
        .stdin(Stdio::null())
        .stdout(log.try_clone().unwrap())
        .stderr(log)
        .spawn()
        .unwrap();

    if !wait_ready(&daemon, &notify, Duration::from_secs(60)) {
        let _ = daemon.kill();
        panic!(
            "the daemon did not start: {}",
            std::fs::read_to_string(base.join("daemon.log")).unwrap_or_default()
        );
    }
    assert!(std::os::unix::net::UnixStream::connect(&socket).is_ok());

    // SAFETY: signalling the child this test started.
    kill(daemon.id() as i32, libc::SIGTERM);
    let status = wait_for(&mut daemon, Duration::from_secs(30));
    if status.is_none() {
        let _ = daemon.kill();
    }
    let mut text = String::new();
    std::fs::File::open(base.join("daemon.log"))
        .unwrap()
        .read_to_string(&mut text)
        .unwrap();
    let status = status.unwrap_or_else(|| panic!("the daemon did not stop: {text}"));
    assert!(status.success(), "{status:?}: {text}");
    assert!(!text.contains("panicked"), "{text}");
    assert!(text.contains("Shutdown complete"), "{text}");
    text
}

/// A store of its own in a scratch directory, and a daemon started on it in
/// a process group of its own.
struct Store {
    work: tempfile::TempDir,
    daemon: Child,
}

impl Store {
    fn start() -> Self {
        let work = tempfile::Builder::new()
            .prefix("velarx-test")
            .tempdir_in("/var/tmp")
            .unwrap();
        let base = work.path();
        let (home, run) = (base.join("home"), base.join("run"));
        std::fs::create_dir_all(&home).unwrap();
        std::fs::create_dir_all(&run).unwrap();
        std::fs::set_permissions(&run, std::os::unix::fs::PermissionsExt::from_mode(0o700))
            .unwrap();
        let socket = run.join("engine.sock");
        std::fs::write(
            base.join("config.toml"),
            format!(
                "[engine]\nsocket = \"{}\"\n[server]\nstate_dir = \"{}\"\nroot_dir = \"{}\"\n\
                 [storage]\nroot = \"{}\"\n",
                socket.display(),
                base.join("state").display(),
                base.join("root").display(),
                base.join("storage").display(),
            ),
        )
        .unwrap();
        let log = std::fs::File::create(base.join("daemon.log")).unwrap();
        let (notify_path, notify) = notify_socket(base);
        use std::os::unix::process::CommandExt;
        let daemon = Command::new(crate::common::worker())
            .arg("--config")
            .arg(base.join("config.toml"))
            .args(["varlink"])
            .env("HOME", &home)
            .env("XDG_RUNTIME_DIR", &run)
            .env("NOTIFY_SOCKET", &notify_path)
            .process_group(0)
            .stdin(Stdio::null())
            .stdout(log.try_clone().unwrap())
            .stderr(log)
            .spawn()
            .unwrap();
        assert!(
            wait_ready(&daemon, &notify, Duration::from_secs(60)),
            "the daemon did not start: {}",
            std::fs::read_to_string(base.join("daemon.log")).unwrap_or_default()
        );
        assert!(std::os::unix::net::UnixStream::connect(&socket).is_ok());
        Self { work, daemon }
    }

    /// The processes of this store: their pid and name.
    fn processes(&self) -> Vec<(i32, String)> {
        let config = self.work.path().join("config.toml");
        let config = config.to_string_lossy().into_owned();
        let mut out = Vec::new();
        for entry in std::fs::read_dir("/proc").unwrap().flatten() {
            let Some(pid) = entry
                .file_name()
                .to_str()
                .and_then(|s| s.parse::<i32>().ok())
            else {
                continue;
            };
            let Ok(cmdline) = std::fs::read(format!("/proc/{pid}/cmdline")) else {
                continue;
            };
            if cmdline.split(|b| *b == 0).any(|a| a == config.as_bytes()) {
                let comm = std::fs::read_to_string(format!("/proc/{pid}/comm")).unwrap_or_default();
                out.push((pid, comm.trim().to_string()));
            }
        }
        out
    }

    /// Wait at most `limit` for the processes of the store that `which`
    /// keeps to be gone; those left.
    fn wait_gone(&self, limit: Duration, which: impl Fn(&str) -> bool) -> Vec<(i32, String)> {
        let deadline = Instant::now() + limit;
        loop {
            let left: Vec<_> = self
                .processes()
                .into_iter()
                .filter(|(_, c)| which(c))
                .collect();
            if left.is_empty() || Instant::now() > deadline {
                return left;
            }
            for (pid, _) in &left {
                velarx_base::testing::wait_exit(
                    *pid,
                    deadline.saturating_duration_since(Instant::now()),
                );
            }
        }
    }
}

impl Drop for Store {
    fn drop(&mut self) {
        let _ = self.daemon.kill();
        let _ = self.daemon.wait();
        for (pid, comm) in self.processes() {
            if comm.starts_with("velarx") {
                // SAFETY: a process of the store of this test.
                kill(pid, libc::SIGKILL);
            }
        }
    }
}

fn rootless() -> bool {
    !rustix::process::getuid().is_root()
}

/// The daemon is the one process of the store: it joined the rootless
/// namespaces in place (no process waits outside them, none holds them), so
/// nothing is left when it is killed.
#[test]
fn nothing_outlives_a_killed_rootless_daemon() {
    if !rootless() {
        return;
    }
    let mut store = Store::start();
    let all: Vec<_> = store.processes();
    assert_eq!(all.len(), 1, "the daemon alone: {all:?}");
    // SAFETY: the child this test started.
    kill(store.daemon.id() as i32, libc::SIGKILL);
    let _ = store.daemon.wait();
    let left = store.wait_gone(Duration::from_secs(2), |_| true);
    assert!(
        left.is_empty(),
        "left after the daemon was killed: {left:?}"
    );
}
