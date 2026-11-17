// SPDX-License-Identifier: Apache-2.0
//! Starting a monitor: the command line, the environment, the descriptors
//! and the cgroup are the caller's to decide.  The daemon's server uses it,
//! and so can the engine itself, from a process that a service manager
//! supervises.

use std::ffi::OsString;
use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// Where the standard output and error of the monitor go.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum StdioPolicy {
    /// Nowhere: the monitor writes `monitor.log` in its run directory.
    #[default]
    Null,
    /// The ones of the caller: the output of a container whose log driver is
    /// `passthrough` goes to the terminal or the journal of the caller.
    Inherit,
}

/// What the caller decides about the monitor process.
#[derive(Debug, Clone, Default)]
pub struct SpawnOptions {
    /// `NOTIFY_SOCKET` of the monitor: the service manager that the
    /// container may talk to through the monitor.  `None` clears it, so that
    /// nothing the monitor starts can reach the manager.
    pub notify_socket: Option<OsString>,
    /// Variables to set in addition (`NOTIFY_SOCKET` is not one of them).
    pub env: Vec<(OsString, OsString)>,
    /// The cgroup directory to move the monitor to before it runs; `None`
    /// leaves it in the cgroup of the caller (a unit's, under a service
    /// manager).
    pub cgroup: Option<PathBuf>,
    /// The transient scope (`NAME.scope`, of the user's manager unless this
    /// process is root) the monitor moves itself to before it does anything
    /// else (`SCOPE_ENV`: the monitor asks the manager, over its private
    /// socket, as `systemd-run --scope` does, without starting it).  `None`
    /// leaves it in the cgroup of the caller.
    pub scope: Option<String>,
    pub stdio: StdioPolicy,
    /// Descriptors the monitor gets as 4, 5, ... (after the first
    /// connection, 3), to hand to its container: the sockets of a unit's
    /// socket activation (`LISTEN_FDS`).
    pub preserve_fds: Vec<std::sync::Arc<std::os::fd::OwnedFd>>,
    /// Descriptors the monitor gets after those: detached mounts that the
    /// storage driver made for the root file system of the container, which
    /// a `RootfsPlan::MountFd` names by its place in this list
    /// (`MonitorConfig::rootfs_fds`).  Each is used by one start of the monitor.
    pub rootfs_fds: Vec<std::sync::Arc<std::os::fd::OwnedFd>>,
    /// The descriptor after those: the network namespace of the container,
    /// which the engine made and the spec joins (`MonitorConfig::netns_fd`).
    pub netns: Option<std::sync::Arc<std::os::fd::OwnedFd>>,
    /// The descriptor after that: the directory the results of the health
    /// checks are written to (`MonitorConfig::fds`' `health_log_dir`).
    pub health_log_dir: Option<std::sync::Arc<std::os::fd::OwnedFd>>,
    /// The last descriptor: the rootless namespace of the bridge networks,
    /// which the monitor holds for as long as it lives
    /// (`InheritedFds::bridge_netns`).
    pub bridge_netns: Option<std::sync::Arc<std::os::fd::OwnedFd>>,
}

/// The descriptor of the first connection of a monitor (`--varlink-fd`).
pub const VARLINK_FD: i32 = 3;

/// Where the descriptors a monitor is passed are (its first connection is
/// named by `--varlink-fd`): the engine computes it once, from the
/// descriptors it passes (`SpawnOptions`: the preserved ones, the mounts of
/// the root file system, the network namespace, in that order from
/// [`Self::FIRST`]), and writes it to the configuration the monitor reads.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct InheritedFds {
    /// For the container (its 3, 4, ...: socket activation).
    #[serde(default)]
    pub preserved: Vec<i32>,
    /// The detached mounts that the storage driver made for the root file
    /// system, which a `RootfsPlan::MountFd` names by its place among them.
    /// The monitor uses each once, for its own start.
    #[serde(default)]
    pub rootfs: Vec<i32>,
    /// The network namespace of the container, which the engine made (and
    /// set the network up in): the spec joins it as `/proc/self/fd/N`.  The
    /// monitor holds it for as long as it lives.
    #[serde(default)]
    pub netns: Option<i32>,
    /// The directory of the file the results of the health checks are
    /// written to (`Healthcheck::log_dir`), opened by the engine.
    #[serde(default)]
    pub health_log_dir: Option<i32>,
    /// The rootless network namespace of the bridge networks: the monitor
    /// is a holder of it, and the namespace outlives the holder process
    /// that is killed.
    #[serde(default)]
    pub bridge_netns: Option<i32>,
}

impl InheritedFds {
    /// The first number after the descriptors a process starts with (0, 1,
    /// 2) and its first connection (3).
    pub const FIRST: i32 = VARLINK_FD + 1;

    /// The places of `preserved` descriptors, `rootfs` mounts and a network
    /// namespace, as [`command`] and [`spawn_in_cgroup`] pass them.
    pub fn layout(
        preserved: usize,
        rootfs: usize,
        netns: bool,
        health_log_dir: bool,
        bridge_netns: bool,
    ) -> Self {
        let mut next = Self::FIRST;
        let mut take = |n: usize| {
            let v: Vec<i32> = (next..next + n as i32).collect();
            next += n as i32;
            v
        };
        let preserved = take(preserved);
        let rootfs = take(rootfs);
        let netns = take(usize::from(netns)).pop();
        let health_log_dir = take(usize::from(health_log_dir)).pop();
        let bridge_netns = take(usize::from(bridge_netns)).pop();
        Self {
            preserved,
            rootfs,
            netns,
            health_log_dir,
            bridge_netns,
        }
    }

    /// The same with `rootfs` mounts.
    pub fn with_rootfs(&self, rootfs: usize) -> Self {
        Self::layout(
            self.preserved.len(),
            rootfs,
            self.netns.is_some(),
            self.health_log_dir.is_some(),
            self.bridge_netns.is_some(),
        )
    }
}

/// The binary `name`: next to the running executable, else by its name.
pub fn sibling(name: &str) -> PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(|d| d.join(name)))
        .filter(|p| p.exists())
        .unwrap_or_else(|| PathBuf::from(name))
}

/// The monitor binary.
pub fn binary() -> PathBuf {
    sibling("velarx-monitor")
}

/// Make `fd` the descriptor 3 of the process `cmd` starts and close every
/// descriptor above it.  `fd` must stay open until the command is spawned.
pub fn pass_as_fd3(cmd: &mut Command, fd: i32) {
    velarx_sys::spawn::pass_as_fd3(cmd, fd);
}

/// [`pass_as_fd3`], and `others` as 4, 5, ...: the descriptors above are
/// closed on exec.  `fd` and `others` must stay open until the command is
/// spawned.
pub fn pass_fds(cmd: &mut Command, fd: i32, others: Vec<i32>) {
    velarx_sys::spawn::pass_fds(cmd, fd, others);
}

/// The most descriptors that `SpawnOptions::preserve_fds` passes on.
pub const MAX_PRESERVED_FDS: usize = 64;

/// The most descriptors of the fetchers a container's image server is
/// passed (`velarx_content::list::entries`).
pub const MAX_FETCHER_FDS: usize = 16;

/// The most that `SpawnOptions::rootfs_fds` passes on.
pub const MAX_ROOTFS_FDS: usize = 32;

/// The variable that names the scope the monitor moves itself to.
pub const SCOPE_ENV: &str = "VELARX_MONITOR_SCOPE";

/// The descriptors the monitor passes on to its container and its root file
/// system, in the order they get (4, 5, ...).
fn kept_fds(opts: &SpawnOptions) -> io::Result<Vec<i32>> {
    if opts.preserve_fds.len() > MAX_PRESERVED_FDS {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("at most {MAX_PRESERVED_FDS} descriptors can be passed on"),
        ));
    }
    if opts.rootfs_fds.len() > MAX_ROOTFS_FDS {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("at most {MAX_ROOTFS_FDS} mounts can be passed on"),
        ));
    }
    Ok(opts
        .preserve_fds
        .iter()
        .chain(&opts.rootfs_fds)
        .chain(&opts.netns)
        .chain(&opts.health_log_dir)
        .chain(&opts.bridge_netns)
        .map(|f| f.as_raw_fd())
        .collect())
}

/// Start the monitor of `cmd` (made by [`command`], with the same `bootstrap`
/// and `opts`) as a process of the cgroup `cgroup` (a directory of the
/// cgroup file system) from its first instruction: `clone3` with
/// `CLONE_INTO_CGROUP`.  The process that moves to a cgroup later waits for
/// a grace period of the kernel (5-10 ms of every start); this one costs
/// nothing.  The pid.  `std::process::Command` cannot do it, so this
/// follows what it does: the signals are blocked until the child has its
/// own mask, `SIGPIPE` is the default again, standard input is
/// `/dev/null`, and a failed exec is the error of the call.
pub fn spawn_in_cgroup(
    cmd: &Command,
    bootstrap: BorrowedFd<'_>,
    opts: &SpawnOptions,
    cgroup: &Path,
) -> io::Result<u32> {
    use std::collections::BTreeMap;
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    let invalid = |_| io::Error::from(io::ErrorKind::InvalidInput);
    let program = CString::new(cmd.get_program().as_bytes()).map_err(invalid)?;
    let mut argv = vec![program.clone()];
    for a in cmd.get_args() {
        argv.push(CString::new(a.as_bytes()).map_err(invalid)?);
    }
    let mut env: BTreeMap<OsString, OsString> = std::env::vars_os().collect();
    for (k, v) in cmd.get_envs() {
        match v {
            Some(v) => env.insert(k.to_owned(), v.to_owned()),
            None => env.remove(k),
        };
    }
    let mut envp = Vec::with_capacity(env.len());
    for (k, v) in env {
        let mut kv = k.as_bytes().to_vec();
        kv.push(b'=');
        kv.extend_from_slice(v.as_bytes());
        envp.push(CString::new(kv).map_err(invalid)?);
    }
    let exec_args = velarx_sys::spawn::ExecArgs::new(argv, envp);
    let keep = kept_fds(opts)?;
    let fd = bootstrap.as_raw_fd();
    let dir = rustix::fs::open(
        cgroup,
        rustix::fs::OFlags::PATH | rustix::fs::OFlags::DIRECTORY | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )?;
    let null = rustix::fs::open(
        "/dev/null",
        rustix::fs::OFlags::RDWR | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )?;
    // (the child reports a failed exec through this, closed by a good one)
    let (report_r, report_w) = rustix::pipe::pipe_with(rustix::pipe::PipeFlags::CLOEXEC)?;
    let pid = velarx_sys::spawn::fork_into_cgroup(dir.as_fd(), |child| {
        let result = (|| {
            child.dup2(null.as_raw_fd(), 0)?;
            setup_child_fds(child, fd, &keep, None)?;
            Err::<(), _>(exec_args.exec(&program))
        })();
        let errno = result
            .err()
            .and_then(|e| e.raw_os_error())
            .unwrap_or(libc::EIO)
            .to_ne_bytes();
        let _ = rustix::io::write(&report_w, &errno);
        127
    })?;
    drop(report_w);
    let mut errno = [0u8; 4];
    let mut got = 0;
    while got < 4 {
        match rustix::io::read(&report_r, &mut errno[got..]) {
            Ok(0) => break,
            Ok(n) => got += n,
            Err(rustix::io::Errno::INTR) => {}
            Err(e) => return Err(e.into()),
        }
    }
    if got == 4 {
        // the exec failed: the child is gone
        reap(pid);
        return Err(io::Error::from_raw_os_error(i32::from_ne_bytes(errno)));
    }
    Ok(pid)
}

/// Wait for the child `pid` that failed to exec.
fn reap(pid: u32) {
    let Some(pid) = rustix::process::Pid::from_raw(pid as i32) else {
        return;
    };
    while matches!(
        rustix::process::waitpid(Some(pid), rustix::process::WaitOptions::empty()),
        Err(rustix::io::Errno::INTR)
    ) {}
}

/// In the child between fork and exec: place the descriptors (`fd` as 3,
/// `keep` as 4, 5, ...), join the cgroup whose `cgroup.procs` is
/// `cgroup_procs`, and leave nothing else open.  Only calls that are
/// async-signal-safe, on integers and on a C string made before the fork.
fn setup_child_fds(
    child: &velarx_sys::spawn::InChild,
    fd: i32,
    keep: &[i32],
    cgroup_procs: Option<&std::ffi::CStr>,
) -> io::Result<()> {
    // Out of the way of 3 first: systemd's start at 3.
    let mut parked = [0i32; MAX_PRESERVED_FDS + MAX_FETCHER_FDS + MAX_ROOTFS_FDS];
    let above = 4 + keep.len() as i32;
    for (i, &k) in keep.iter().enumerate() {
        parked[i] = child.dup_cloexec_from(k, above)?;
    }
    if let Some(path) = cgroup_procs {
        let f = rustix::fs::open(
            path,
            rustix::fs::OFlags::WRONLY | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )?;
        rustix::io::write(&f, b"0")?;
    }
    if fd == 3 {
        child.clear_cloexec(3)?;
    } else {
        child.dup2(fd, 3)?;
    }
    child.place_fds(&parked[..keep.len()], 4)?;
    for &p in &parked[..keep.len()] {
        child.close(p);
    }
    // Everything above is the caller's business.
    child.cloexec_from(4 + keep.len() as u32);
    Ok(())
}

/// The command that runs `binary` as the monitor of the run directory
/// `run_dir`, with `bootstrap` (the monitor's end of the first connection)
/// as its descriptor 3 and nothing else above 2.  The caller starts it.
pub fn command(
    binary: &Path,
    run_dir: &Path,
    bootstrap: BorrowedFd<'_>,
    opts: &SpawnOptions,
) -> io::Result<Command> {
    let cgroup_procs = match &opts.cgroup {
        Some(dir) => Some(
            std::ffi::CString::new(
                dir.join("cgroup.procs")
                    .into_os_string()
                    .into_encoded_bytes(),
            )
            .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?,
        ),
        None => None,
    };
    let mut cmd = Command::new(binary);
    cmd.arg("--varlink-fd")
        .arg(VARLINK_FD.to_string())
        .arg(run_dir);
    cmd.stdin(Stdio::null());
    cmd.env_remove("NOTIFY_SOCKET");
    cmd.env_remove(SCOPE_ENV);
    crate::ids::scrub_runtime_dir(&mut cmd).map_err(io::Error::other)?;
    if let Some(unit) = &opts.scope {
        cmd.env(SCOPE_ENV, unit);
    }
    if let Some(sock) = &opts.notify_socket {
        cmd.env("NOTIFY_SOCKET", sock);
    }
    for (k, v) in &opts.env {
        if k != "NOTIFY_SOCKET" {
            cmd.env(k, v);
        }
    }
    if opts.stdio == StdioPolicy::Inherit {
        cmd.stdout(Stdio::inherit()).stderr(Stdio::inherit());
    }
    let fd = bootstrap.as_raw_fd();
    let keep = kept_fds(opts)?;
    velarx_sys::spawn::pre_exec(&mut cmd, move |child| {
        setup_child_fds(child, fd, &keep, cgroup_procs.as_deref())
    });
    Ok(cmd)
}

/// The cgroup the daemon keeps itself in, below the cgroup it manages: `engine`,
/// next to the `[<pod>/]<id>` cgroups of the containers (`--cgroups=split`).
pub const DAEMON_CGROUP: &str = "engine";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_scope_is_named_in_the_environment_of_the_monitor() {
        let (a, _b) = std::os::unix::net::UnixStream::pair().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let opts = SpawnOptions {
            scope: Some("velarx-monitor-abc".into()),
            ..SpawnOptions::default()
        };
        let cmd = command(Path::new("/bin/true"), tmp.path(), a.as_fd(), &opts).unwrap();
        let env: Vec<_> = cmd.get_envs().collect();
        assert!(env.contains(&(
            std::ffi::OsStr::new(SCOPE_ENV),
            Some(std::ffi::OsStr::new("velarx-monitor-abc"))
        )));
        let plain = command(
            Path::new("/bin/true"),
            tmp.path(),
            a.as_fd(),
            &SpawnOptions::default(),
        )
        .unwrap();
        assert!(plain
            .get_envs()
            .all(|(k, v)| k != std::ffi::OsStr::new(SCOPE_ENV) || v.is_none()));
    }

    /// The monitor starts in the cgroup it is given (not moved there after),
    /// with descriptor 3 and standard input from /dev/null, and a failed exec
    /// is an error of the spawn.  Needs a cgroup the user may make: below the
    /// delegated one of the user's manager (the scope of this test run); else
    /// it passes.
    #[test]
    fn the_monitor_starts_in_the_cgroup_it_is_given() {
        let own = crate::cgroup::of_process(None).unwrap();
        let own = own.as_str();
        let tmp = tempfile::tempdir().unwrap();
        let cg = Path::new("/sys/fs/cgroup")
            .join(own.trim_start_matches('/'))
            .join(format!("velarx-test-{}", std::process::id()));
        if std::fs::create_dir(&cg).is_err() {
            return;
        }
        let (a, _b) = std::os::unix::net::UnixStream::pair().unwrap();
        let opts = SpawnOptions::default();
        let spawn = |bin: &Path| {
            let cmd = command(bin, tmp.path(), a.as_fd(), &opts).unwrap();
            spawn_in_cgroup(&cmd, a.as_fd(), &opts, &cg)
        };
        let pid = spawn(Path::new(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/probe-monitor"
        )));
        let missing = spawn(&tmp.path().join("no-such-monitor"));
        if let Ok(pid) = pid {
            reap(pid);
            let got = std::fs::read_to_string(tmp.path().join("cgroup")).unwrap();
            assert!(
                got.trim_end()
                    .ends_with(cg.file_name().unwrap().to_str().unwrap()),
                "{got}"
            );
            assert_eq!(
                std::fs::read_to_string(tmp.path().join("stdin"))
                    .unwrap()
                    .trim(),
                "/dev/null"
            );
            let fds = std::fs::read_to_string(tmp.path().join("fds")).unwrap();
            assert!(fds.lines().any(|f| f == "3"), "{fds}");
            assert_eq!(
                missing.expect_err("no such program").kind(),
                io::ErrorKind::NotFound
            );
        }
        let _ = std::fs::remove_dir(&cg);
    }

    #[test]
    fn a_failed_exec_is_an_error_of_the_spawn() {
        let (a, _b) = std::os::unix::net::UnixStream::pair().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let missing = tmp.path().join("no-such-monitor");
        let mut cmd = command(&missing, tmp.path(), a.as_fd(), &SpawnOptions::default()).unwrap();
        let err = cmd.spawn().expect_err("exec of a missing binary must fail");
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn the_monitor_gets_fd_3_and_nothing_above() {
        let (a, _b) = std::os::unix::net::UnixStream::pair().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let status = command(
            Path::new(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/fixtures/probe-monitor"
            )),
            tmp.path(),
            a.as_fd(),
            &SpawnOptions::default(),
        )
        .unwrap()
        .status()
        .unwrap();
        assert!(status.success());
        let mut fds: Vec<i32> = std::fs::read_to_string(tmp.path().join("fds"))
            .unwrap()
            .split_whitespace()
            .map(|f| f.parse().unwrap())
            .collect();
        fds.sort();
        // 0-2, the bootstrap socket as 3, and the descriptor ls opened.
        assert_eq!(&fds[..4], &[0, 1, 2, 3]);
        assert!(fds.len() <= 5, "{fds:?}");
    }

    /// The descriptors of the container come first (4, 5, ...), then the
    /// mounts of the root file system, and nothing else is passed.
    #[test]
    fn the_mounts_follow_the_descriptors_of_the_container() {
        use std::os::fd::OwnedFd;
        use std::sync::Arc;
        let root = Arc::new(OwnedFd::from(std::fs::File::open("/").unwrap()));
        let too_many = SpawnOptions {
            rootfs_fds: (0..=MAX_ROOTFS_FDS).map(|_| root.clone()).collect(),
            ..SpawnOptions::default()
        };
        assert!(kept_fds(&too_many).is_err());
        let (a, _b) = std::os::unix::net::UnixStream::pair().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let file = |name: &str| {
            let path = tmp.path().join(name);
            std::fs::write(&path, name).unwrap();
            Arc::new(OwnedFd::from(std::fs::File::open(&path).unwrap()))
        };
        let opts = SpawnOptions {
            preserve_fds: vec![file("one")],
            rootfs_fds: vec![file("four")],
            ..SpawnOptions::default()
        };
        let probe = Path::new(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/probe-monitor"
        ));
        let status = command(probe, tmp.path(), a.as_fd(), &opts)
            .unwrap()
            .status()
            .unwrap();
        assert!(status.success());
        let text = std::fs::read_to_string(tmp.path().join("out")).unwrap();
        let names: Vec<(&str, &str)> = text
            .lines()
            .map(|l| {
                let (n, path) = l.split_once(' ').unwrap();
                (n, path.rsplit('/').next().unwrap())
            })
            .collect();
        assert_eq!(names[1..], [("4", "one"), ("5", "four")], "{text}");
    }
}
