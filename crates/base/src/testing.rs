// SPDX-License-Identifier: Apache-2.0
//! Helper of the unit tests of the packages: the tests of a package run as
//! threads of one process, so what a test does to the whole process
//! (signals, the environment, the working directory, resource limits,
//! mounts) reaches all the others running at the time.  Such a test runs
//! its body in a child process (`in_child`).  The test in `src/testing.rs`
//! of the root package fails when one does it outside.
//!
//! And the waits of the tests for an event (`wait_exit`, `wait_file`,
//! `wait_path`, `wait_gone`), never for a time.

use rustix::event::{poll, PollFd, PollFlags, Timespec};
use rustix::fs::inotify;
use std::os::fd::AsFd;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// The interface file `name` of `interfaces/` is `text`, which the types make
/// (`VELARX_WRITE_INTERFACES=1` writes it).
pub fn assert_interface_file(name: &str, text: &str) {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../interfaces")
        .join(name);
    if std::env::var_os("VELARX_WRITE_INTERFACES").is_some() {
        std::fs::write(&path, text).unwrap();
    }
    let on_disk = std::fs::read_to_string(&path).unwrap_or_default();
    assert!(
        on_disk == text,
        "{} is not what the types make; run VELARX_WRITE_INTERFACES=1 cargo test --workspace \
         interface and commit it",
        path.display()
    );
    assert!(!text.contains("[`"), "a rustdoc link in the definition");
}

/// Set in the child process of `in_child`.
const CHILD: &str = "VELARX_TEST_CHILD";

/// Run `body` in a child process: the test binary again, running only the
/// test that calls this, with `CHILD` set.  The test fails unless the
/// child ends with success, whatever signals it takes or raises itself.
pub fn in_child<F: FnOnce()>(body: F) {
    if std::env::var_os(CHILD).is_some() {
        in_forked(body);
        return;
    }
    // the type of the closure is named after the test that holds it:
    // `velarx::module::tests::name::{{closure}}`
    let closure = std::any::type_name::<F>();
    let test = closure
        .strip_suffix("::{{closure}}")
        .and_then(|t| t.split_once("::"))
        .map(|(_, t)| t)
        .unwrap_or_else(|| panic!("in_child needs a closure written in the test: {closure}"));
    // The temporary files of the child go in a directory of its own, removed
    // here: the child makes them in a mount namespace and may hold a mount in
    // them or be confined, so it cannot always remove what it made.
    let private = ChildTmp::new();
    let out = std::process::Command::new(std::env::current_exe().unwrap())
        .args([test, "--exact", "--nocapture", "--test-threads=1"])
        .env(CHILD, "1")
        .env("TMPDIR", &private.0)
        .output()
        .unwrap();
    drop(private);
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        out.status.success(),
        "{test} in a child: {}\n{text}",
        out.status
    );
    assert!(
        text.contains("test result: ok. 1 passed"),
        "{test} did not run in the child:\n{text}"
    );
}

/// The directory of the temporary files of a child (`TMPDIR`), removed when
/// this is dropped, after the child is gone and its mounts with it.  (The
/// name starts with `.tmp` like a `tempfile` directory: a test run that
/// leaves one behind is found by the same check.)
struct ChildTmp(std::path::PathBuf);

impl ChildTmp {
    fn new() -> Self {
        static COUNT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        loop {
            let n = COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let p = std::env::temp_dir().join(format!(".tmp-child-{}-{n}", std::process::id()));
            match std::fs::create_dir(&p) {
                Ok(()) => return Self(p),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => panic!("make {}: {e}", p.display()),
            }
        }
    }
}

impl Drop for ChildTmp {
    fn drop(&mut self) {
        if let Err(e) = crate::tree::remove_dir_all_confined(&self.0) {
            if !std::thread::panicking() {
                panic!("remove {}: {e}", self.0.display());
            }
        }
    }
}

/// Run `body` in a process forked from this one, the test binary started
/// for this test alone: the process has the main thread of the harness,
/// which waits for the test and holds nothing, and the thread that runs the
/// test.  The forked process has that thread only, so the code under test
/// forks from a process of one thread, as it does in production.
fn in_forked<F: FnOnce()>(body: F) {
    use std::io::Write;
    let pid = velarx_sys::process::fork_beside_idle_threads(|_| {
        let ok = std::panic::catch_unwind(std::panic::AssertUnwindSafe(body)).is_ok();
        let _ = std::io::stdout().flush();
        let _ = std::io::stderr().flush();
        i32::from(!ok)
    })
    .expect("fork the process of the test");
    let (_, status) = rustix::process::waitpid(
        rustix::process::Pid::from_raw(pid),
        rustix::process::WaitOptions::empty(),
    )
    .expect("wait for the process of the test")
    .expect("a status for the process of the test");
    assert!(status.exited(), "the process of the test: {status:?}");
    assert_eq!(status.exit_status(), Some(0), "the test failed above");
}

// waits for an event
//
// A process that ends (its pidfd), a file that comes, changes or goes
// (inotify on its directory).  The limit is an upper bound, never a delay.

/// Whether `fd` became readable before `deadline`.
fn readable(fd: impl AsFd, deadline: Instant) -> bool {
    let left = deadline.saturating_duration_since(Instant::now());
    let timeout = Timespec {
        tv_sec: left.as_secs() as i64,
        tv_nsec: left.subsec_nanos() as i64,
    };
    let mut fds = [PollFd::new(&fd, PollFlags::IN)];
    poll(&mut fds, Some(&timeout)).unwrap_or(0) > 0
}

/// Waits at most `limit` for the process `pid` to end: false when the time
/// is up.  A process that is gone already has no pidfd.
pub fn wait_exit(pid: i32, limit: Duration) -> bool {
    let pid = rustix::process::Pid::from_raw(pid).expect("a pid to wait for");
    let Ok(pidfd) = rustix::process::pidfd_open(pid, rustix::process::PidfdFlags::empty()) else {
        return true;
    };
    readable(&pidfd, Instant::now() + limit)
}

/// Whether a thread of this process is asleep in `flock(2)` on the file
/// `lock` now: the kernel lists the waiters of locks in `/proc/locks` (`N:
/// -> FLOCK  ADVISORY  WRITE PID MAJOR:MINOR:INODE START END`).  The waiter
/// is matched by its pid (this process: the pids of `/proc/locks` are those
/// of the reader's namespace) and the inode, not by the device, whose
/// number in `stat` differs from the kernel's on btrfs; the inode alone
/// could be a lock of another file system, of another process.
pub fn lock_has_waiter(lock: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    let Ok(meta) = std::fs::metadata(lock) else {
        return false;
    };
    let (pid, ino) = (std::process::id().to_string(), meta.ino().to_string());
    let locks = std::fs::read_to_string("/proc/locks").unwrap_or_default();
    locks.lines().any(|l| {
        let fields: Vec<&str> = l.split_whitespace().collect();
        // (the pid is the field before MAJOR:MINOR:INODE, whatever the
        // columns of the kind of lock before them)
        fields.get(1) == Some(&"->")
            && fields.windows(2).any(|w| {
                w[0] == pid
                    && w[1].matches(':').count() == 2
                    && w[1].rsplit(':').next() == Some(ino.as_str())
            })
    })
}

/// Waits at most `limit` until a thread of this process is asleep in
/// `flock(2)` on the file `lock` ([`lock_has_waiter`]): the proof that it
/// reached its blocking point, which a sleep only guesses.  Nothing
/// announces a waiter, so it is looked at every 2 ms; false when the time
/// is up.
pub fn wait_lock_waiter(lock: &Path, limit: Duration) -> bool {
    let until = Instant::now() + limit;
    loop {
        if lock_has_waiter(lock) {
            return true;
        }
        if Instant::now() >= until {
            return false;
        }
        std::thread::sleep(Duration::from_millis(2));
    }
}

/// An inotify instance on the directory of `path`, for what is written,
/// made, moved there or away and removed in it; on the nearest directory
/// above that exists when that one does not yet (its making is a change).
fn watch_dir(path: &Path) -> rustix::fd::OwnedFd {
    let fd = inotify::init(inotify::CreateFlags::CLOEXEC | inotify::CreateFlags::NONBLOCK).unwrap();
    let mut dir = path.parent().unwrap();
    while !dir.is_dir() {
        dir = dir.parent().unwrap();
    }
    inotify::add_watch(
        &fd,
        dir,
        inotify::WatchFlags::MODIFY
            | inotify::WatchFlags::CREATE
            | inotify::WatchFlags::MOVED_TO
            | inotify::WatchFlags::CLOSE_WRITE
            | inotify::WatchFlags::DELETE
            | inotify::WatchFlags::MOVED_FROM,
    )
    .unwrap();
    fd
}

/// Waits (`limit` at most) until the file at `path` is there with a content
/// `done` takes; that content, or None when the time is up.  The directory
/// is watched before the file is looked at: no change is missed.
pub fn wait_file(path: &Path, limit: Duration, done: impl Fn(&str) -> bool) -> Option<String> {
    let deadline = Instant::now() + limit;
    loop {
        // (again each time: a directory above that was made is watched next)
        let fd = watch_dir(path);
        if let Some(s) = std::fs::read_to_string(path).ok().filter(|s| done(s)) {
            return Some(s);
        }
        if !readable(&fd, deadline) {
            return None;
        }
    }
}

/// Waits (`limit` at most) until something is at `path` (a socket, a
/// directory...): false when the time is up.
pub fn wait_path(path: &Path, limit: Duration) -> bool {
    let deadline = Instant::now() + limit;
    loop {
        let fd = watch_dir(path);
        if path.symlink_metadata().is_ok() {
            return true;
        }
        if !readable(&fd, deadline) {
            return false;
        }
    }
}

/// An executable shell script at `path` with the lines `body`, written by a
/// process of its own: a test of this process that forks while the file is
/// open for writing here would keep a descriptor of it open for writing
/// until its exec, and the exec of the script would fail with ETXTBSY.
/// A test that runs a script uses this and never writes the file itself
/// (`std::fs::write` and a `chmod`), in a child (`in_child`) too:
/// `no_test_writes_a_script_to_run_in_its_own_process` of the root package
/// fails on a shebang in test code that is not marked `// not executed`.
pub fn write_script(path: &Path, body: &str) {
    let made = std::process::Command::new("/bin/sh")
        .arg("-c")
        .arg("printf '#!/bin/sh\\n%s\\n' \"$2\" > \"$1\" && chmod 755 \"$1\"")
        .args(["sh", &path.to_string_lossy(), body])
        .status()
        .unwrap();
    assert!(made.success(), "write {}", path.display());
}

/// A copy of the program `from` at `to`, made by a process of its own (`cp`)
/// for the reason of [`write_script`]: a copy this process writes is open
/// for writing while another test may fork.
pub fn copy_program(from: &Path, to: &Path) {
    let copied = std::process::Command::new("cp")
        .arg("--")
        .arg(from)
        .arg(to)
        .status()
        .unwrap();
    assert!(
        copied.success(),
        "copy {} to {}",
        from.display(),
        to.display()
    );
}

/// What `crun features` printed on a host with crun 1.30 (the document of
/// the OCI runtime-spec features).
pub const CRUN_FEATURES: &str = include_str!("testing/crun.features.json");
/// What `runc features` printed with runc 1.5.2.
pub const RUNC_FEATURES: &str = include_str!("testing/runc.features.json");
/// What `krun features` printed (krun is crun with libkrun).
pub const KRUN_FEATURES: &str = include_str!("testing/krun.features.json");

/// A fake OCI runtime at `path`: a script whose `features` prints
/// `features` (a runtime with no `features` command when it is `None`:
/// it fails like an unknown command); every other call fails.
pub fn write_runtime(path: &Path, features: Option<&str>) {
    let body = match features {
        Some(json) => format!(
            "if [ \"$1\" = features ]; then cat <<'END_OF_FEATURES'\n{json}\nEND_OF_FEATURES\nexit 0; fi; exit 1"
        ),
        None => "echo \"unknown command: $1\" >&2; exit 1".to_string(),
    };
    write_script(path, &body);
}

/// A FIFO at `path`: a reader that does not check what it opens waits for a
/// writer for ever.
pub fn make_fifo(path: &Path) {
    rustix::fs::mknodat(
        rustix::fs::CWD,
        path,
        rustix::fs::FileType::Fifo,
        rustix::fs::Mode::from_raw_mode(0o600),
        0,
    )
    .unwrap();
}

/// The result of `f`, run on a thread of its own; the test fails (the
/// thread is left blocked) when `f` has not returned after `limit`.
pub fn returns_within<T: Send + 'static>(
    limit: Duration,
    f: impl FnOnce() -> T + Send + 'static,
) -> T {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(f());
    });
    rx.recv_timeout(limit)
        .unwrap_or_else(|_| panic!("blocked for {limit:?}"))
}

fn drain(fd: &rustix::fd::OwnedFd) {
    let mut buf = [0u8; 4096];
    while rustix::io::read(fd, &mut buf).is_ok_and(|n| n > 0) {}
}

/// Waits (`limit` at most) until nothing is at `path`: false when the time
/// is up.
pub fn wait_gone(path: &Path, limit: Duration) -> bool {
    let fd = watch_dir(path);
    let deadline = Instant::now() + limit;
    while path.symlink_metadata().is_ok() {
        if !readable(&fd, deadline) {
            return false;
        }
        drain(&fd);
    }
    true
}

/// The nft binary: in $PATH, else the system directories.  The code never
/// runs it; the tests use it as another view of the ruleset than ours.
pub fn find_nft() -> Option<PathBuf> {
    use std::os::unix::fs::PermissionsExt;
    let path = std::env::var_os("PATH").unwrap_or_default();
    std::env::split_paths(&path)
        .chain(
            ["/usr/sbin", "/sbin", "/usr/bin", "/bin"]
                .iter()
                .map(PathBuf::from),
        )
        .map(|d| d.join("nft"))
        .find(|p| {
            p.metadata()
                .map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
                .unwrap_or(false)
        })
}

#[cfg(test)]
mod tests {
    /// A thread blocked in `flock` on a file is seen as its waiter; a lock
    /// that is only held, or a waiter on another file, is not.
    #[test]
    fn a_thread_asleep_in_flock_is_a_waiter_of_that_file() {
        use rustix::fs::{flock, FlockOperation};
        let dir = tempfile::tempdir().unwrap();
        let (a, b) = (dir.path().join("a"), dir.path().join("b"));
        let held = std::fs::File::create(&a).unwrap();
        std::fs::File::create(&b).unwrap();
        flock(&held, FlockOperation::LockExclusive).unwrap();
        assert!(!super::lock_has_waiter(&a), "held, nobody waits");
        let path = a.clone();
        let waiter = std::thread::spawn(move || {
            let f = std::fs::File::open(path).unwrap();
            flock(&f, FlockOperation::LockExclusive).unwrap();
        });
        assert!(super::wait_lock_waiter(
            &a,
            std::time::Duration::from_secs(30)
        ));
        assert!(!super::lock_has_waiter(&b), "a waiter of another file");
        drop(held);
        waiter.join().unwrap();
        assert!(!super::lock_has_waiter(&a), "the waiter got the lock");
    }

    /// The body of `in_child` runs in a process of one thread, as the code
    /// it tests runs in production: the check of a fork holds there as it
    /// is, a second thread and the fork is refused.
    #[test]
    fn the_body_of_a_child_runs_in_a_process_of_one_thread() {
        super::in_child(|| {
            assert_eq!(velarx_sys::process::thread_count().unwrap(), 1);
            velarx_sys::process::ensure_single_threaded("test").unwrap();
            let (stop, wait) = std::sync::mpsc::channel::<()>();
            let t = std::thread::spawn(move || {
                let _ = wait.recv();
            });
            assert!(velarx_sys::process::ensure_single_threaded("test").is_err());
            drop(stop);
            t.join().unwrap();
        });
    }
}
