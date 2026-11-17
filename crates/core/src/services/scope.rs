// SPDX-License-Identifier: Apache-2.0
//! The systemd scope of a container made by a command that runs no server
//! (`cgroups_mode`'s table): `velarx-<id>.scope`, with the monitor in
//! `monitor` below it and the container in `container`.
//!
//! The manager needs 10-15 ms to make a scope: it moves the process the
//! scope is made for into a new cgroup, which waits for a grace period of
//! the kernel.  So the command asks at its beginning ([`begin`]), before it
//! loads the image and makes the bundle, for a scope around a *holder*, a
//! process that does nothing; when the scope is there (a thread waits for
//! it) the holder moves to a subgroup of its own, the controllers are
//! enabled for the children of the scope, and the start of the monitor
//! finds the cgroups made: the monitor is started in `monitor` (`clone3`
//! with `CLONE_INTO_CGROUP`, which moves nothing) and the runtime makes the
//! container in `container` by the cgroupfs manager.  The holder ends when
//! the container is made; the scope lives as long as the monitor and the
//! container.  A start that did not ask in advance (`start` of an existing
//! container, `--no-monitor`, the server) does the same and waits.  A scope
//! that cannot be made fails the start: the engine makes no cgroup of the
//! manager's slices by hand.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};
use tracing::warn;

/// How long the manager has to put the holder in its scope.
const JOIN_TIMEOUT: Duration = Duration::from_secs(5);

/// How long a unit of the same name may take to go.
const UNIT_GONE_TIMEOUT: Duration = Duration::from_secs(2);

/// The cgroups of a scope that is there.  Dropped once the container is
/// made: the holder ends then (the monitor, or with `no-conmon` and
/// `--no-monitor` the container alone, keeps the scope).
#[derive(Debug)]
pub struct Dirs {
    /// The scope.
    pub root: PathBuf,
    /// Where the monitor starts.
    pub monitor: PathBuf,
    holder: i32,
}

/// A scope that is being made.  Dropped without [`Pending::wait`] or
/// [`Pending::cancel`], its holder ends.
pub struct Pending {
    pub id: String,
    holder: i32,
    thread: Option<JoinHandle<io::Result<PathBuf>>>,
}

/// The scope the command asked for in advance.
static EARLY: Mutex<Option<Pending>> = Mutex::new(None);

/// Ask for the scope of the container `id` now; the start of its monitor
/// takes it ([`take`]).  Not for a command that runs in a thread of many:
/// the holder is a fork.
pub fn begin_early() {
    if let Ok(p) = begin(&super::container::new_id()) {
        *EARLY.lock().unwrap_or_else(|e| e.into_inner()) = Some(p);
    }
}

/// The id a command that asked in advance made the scope for: the container
/// it creates gets it (once).
pub fn early_id() -> Option<String> {
    EARLY
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .as_ref()
        .map(|p| p.id.clone())
}

/// The scope asked for in advance for `id`, if there is one.
pub fn take(id: &str) -> Option<Pending> {
    let mut early = EARLY.lock().unwrap_or_else(|e| e.into_inner());
    if early.as_ref().is_some_and(|p| p.id == id) {
        return early.take();
    }
    None
}

/// The container `id` takes no scope of the command (it asks the manager
/// for limits): the one asked for in advance ends.
pub fn cancel(id: &str) {
    if let Some(p) = take(id) {
        p.cancel();
    }
}

/// Ask the manager for the scope of `id`, around a holder process.
pub fn begin(id: &str) -> io::Result<Pending> {
    let name = format!("velarx-{id}");
    let holder = fork_holder(&name)?;
    let system = crate::services::cgroups_mode::system_manager().map_err(io::Error::other)?;
    let thread = std::thread::Builder::new()
        .name("scope".into())
        .spawn(move || make(system, &name, holder))
        .inspect_err(|_| {
            kill(holder);
            reap_later(holder, None);
        })?;
    Ok(Pending {
        id: id.to_string(),
        holder,
        thread: Some(thread),
    })
}

/// Before a scope is asked for again for a container (its `start`): the
/// empty cgroups an earlier start left by hand at `dir` (the scope's
/// cgroup), not known to the manager, go; the manager could not put the
/// holder into a cgroup that has controllers enabled for children.
pub fn remove_leftovers(dir: &std::path::Path) {
    for sub in ["container", "monitor", "holder"] {
        let _ = std::fs::remove_dir(dir.join(sub));
    }
    let _ = std::fs::remove_dir(dir);
}

impl Pending {
    /// Wait for the scope: its cgroups.
    pub fn wait(mut self) -> io::Result<Dirs> {
        let holder = self.holder;
        let joined = self.thread.take().map(JoinHandle::join);
        let failed = |e| {
            kill(holder);
            reap_later(holder, None);
            Err(e)
        };
        match joined {
            Some(Ok(Ok(root))) => Ok(Dirs {
                monitor: root.join("monitor"),
                root,
                holder,
            }),
            Some(Ok(Err(e))) => failed(e),
            _ => failed(io::Error::other("the thread that makes the scope panicked")),
        }
    }

    /// The scope is not needed (the container asks the manager for limits,
    /// and the runtime makes a scope of the same name): wait until it is
    /// gone.
    pub fn cancel(mut self) {
        let holder = self.holder;
        let root = self
            .thread
            .take()
            .and_then(|t| t.join().ok())
            .and_then(|r| r.ok());
        kill(holder);
        let _ = velarx_sys::process::wait_exit_code(holder);
        if let Some(root) = root {
            let _ = std::fs::remove_dir(root.join("holder"));
            // (the manager removes the cgroup of the scope: the removal of the
            // directory is the event; two seconds is the limit)
            if let Err(e) = velarx_sys::watch::wait_removed(&root, Duration::from_secs(2)) {
                warn!("Cannot wait for {} to go: {e}", root.display());
            }
        }
    }
}

impl Drop for Pending {
    /// The holder ends only after the manager has answered and put it in
    /// the scope (or failed): a holder that ends while the manager attaches
    /// it leaves an empty scope running for good (systemd 259).
    fn drop(&mut self) {
        // (`wait` and `cancel` take the thread and see to the holder)
        if let Some(t) = self.thread.take() {
            let _ = t.join();
            kill(self.holder);
            reap_later(self.holder, None);
        }
    }
}

/// At the end of a command: the scope it asked for in advance and no
/// container took (the command failed before the start) ends.
pub fn end_early() {
    let early = EARLY.lock().unwrap_or_else(|e| e.into_inner()).take();
    drop(early);
}

impl Drop for Dirs {
    /// The container is made (or its start failed): the holder ends and
    /// its cgroup goes.
    fn drop(&mut self) {
        kill(self.holder);
        reap_later(self.holder, Some(self.root.join("holder")));
    }
}

fn kill(pid: i32) {
    let _ = velarx_sys::process::kill(pid, libc::SIGKILL);
}

/// Collect the holder when it has ended (a thread: the engine does not wait
/// for it) and remove its cgroup.
fn reap_later(pid: i32, cgroup: Option<PathBuf>) {
    let _ = std::thread::Builder::new()
        .name("scope-reap".into())
        .spawn(move || {
            let _ = velarx_sys::process::wait_exit_code(pid);
            if let Some(cg) = cgroup {
                let _ = std::fs::remove_dir(cg);
            }
        });
}

/// How long a holder, left alone by a command that ended while the manager
/// made the scope, waits for the manager to put it in the scope.
const HOLDER_JOIN_MS: i64 = 2000;

/// A process that does nothing and ends with this one: the scope of `name`
/// is made around it.  When this process dies first (a command killed
/// while the manager makes the scope) the holder does not end at once: a
/// process that ends while the manager moves it into the scope is moved
/// as it exits, which the kernel takes as done with nothing moved (systemd
/// 259 then runs the scope with no process for good: its cgroup never was
/// populated, so it never empties).  The holder waits until it is in the
/// scope (events of the cgroup, [`HOLDER_JOIN_MS`] at most) and then ends:
/// the manager watched the cgroup before it moved the holder and starts
/// the scope in the same turn, so it sees the scope empty and stops it.
fn fork_holder(name: &str) -> io::Result<i32> {
    // (made before the fork: the child allocates nothing)
    let needle = format!("/{name}.scope").into_bytes();
    // (the scope's `cgroup.events` and its ancestors, deepest first)
    let watched: Vec<std::ffi::CString> = scope_dir_of(name)?
        .map(|d| d.join("cgroup.events"))
        .into_iter()
        .flat_map(|p| {
            p.ancestors()
                .take_while(|a| *a != Path::new(super::cgroups_mode::CGROUP_FS))
                .map(|a| {
                    std::ffi::CString::new(a.as_os_str().as_encoded_bytes()).unwrap_or_default()
                })
                .collect::<Vec<_>>()
        })
        .collect();
    let parent = std::process::id() as i32;
    // The child makes only async-signal-safe calls (prctl, getppid,
    // sigaction, sigprocmask, setsid, close_range, pause, open, read, close,
    // clock_gettime, inotify_init1, inotify_add_watch, poll, nanosleep, _exit)
    // on integers and buffers made before the fork.
    velarx_sys::process::fork_async_signal_safe(|child| {
        use velarx_sys::signal;
        signal::wake_on(libc::SIGUSR1);
        let _ = signal::unblock(&[libc::SIGUSR1]);
        let _ =
            rustix::process::set_parent_process_death_signal(Some(rustix::process::Signal::USR1));
        for sig in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP, libc::SIGPIPE] {
            signal::set_default(sig);
        }
        // (out of the process group of the command: a Ctrl-C or a kill
        // of the group ends the command, and the holder as above)
        let _ = rustix::process::setsid();
        // (no descriptor of the command stays open in a process that
        // lives while the scope is made, not even a pipe of its output
        // that a caller reads to the end)
        child.close_from(0);
        let ppid = || rustix::process::getppid().map_or(0, |p| p.as_raw_nonzero().get());
        while ppid() == parent {
            velarx_sys::process::pause();
        }
        let nap = |ms: i64| {
            let t = rustix::time::Timespec {
                tv_sec: ms / 1000,
                tv_nsec: (ms % 1000) * 1_000_000,
            };
            let _ = rustix::thread::nanosleep(&t);
        };
        let now_ms = || {
            let t = rustix::time::clock_gettime(rustix::time::ClockId::Monotonic);
            t.tv_sec * 1000 + t.tv_nsec / 1_000_000
        };
        // The manager creates the cgroup of the scope and then moves the
        // holder in: the events are those of the deepest directory of the
        // path that exists (a creation in it) and, once there, of
        // `cgroup.events` of the scope (a change).  With no way to watch
        // them there is nothing to wait for but the time.
        let watch = rustix::fs::inotify::init(
            rustix::fs::inotify::CreateFlags::CLOEXEC | rustix::fs::inotify::CreateFlags::NONBLOCK,
        )
        .ok()
        .filter(|_| !watched.is_empty());
        let Some(fd) = &watch else {
            nap(HOLDER_JOIN_MS);
            return 0;
        };
        let start = now_ms();
        let mut buf = [0u8; 4096];
        while now_ms() - start < HOLDER_JOIN_MS {
            // (watched before it is looked at: no change falls between)
            for path in &watched {
                let flags = rustix::fs::inotify::WatchFlags::CREATE
                    | rustix::fs::inotify::WatchFlags::MODIFY
                    | rustix::fs::inotify::WatchFlags::MASK_ADD;
                if rustix::fs::inotify::add_watch(fd, path.as_c_str(), flags).is_ok() {
                    break;
                }
            }
            let n = match rustix::fs::open(
                c"/proc/self/cgroup",
                rustix::fs::OFlags::RDONLY,
                rustix::fs::Mode::empty(),
            ) {
                Ok(fd) => rustix::io::read(&fd, &mut buf).unwrap_or(0),
                Err(_) => 0,
            };
            if buf[..n].windows(needle.len()).any(|w| w == &needle[..]) {
                break;
            }
            let left = (HOLDER_JOIN_MS - (now_ms() - start)).max(0);
            let timeout = rustix::time::Timespec {
                tv_sec: left / 1000,
                tv_nsec: (left % 1000) * 1_000_000,
            };
            let mut fds = [rustix::event::PollFd::new(fd, rustix::event::PollFlags::IN)];
            if rustix::event::poll(&mut fds, Some(&timeout)).is_ok() {
                while rustix::io::read(fd, &mut buf).is_ok_and(|n| n > 0) {}
            }
        }
        0
    })
}

/// Whether the scope `name` holds a process: one of the last run of the
/// container, which the start of the next one does not kill.  A cgroup that
/// is gone holds none.
fn in_use(name: &str) -> io::Result<bool> {
    let dir = match name.strip_prefix("velarx-") {
        Some(id) => super::cgroups_mode::engine_scope_path(id)
            .map_err(io::Error::other)?
            .and_then(|path| super::cgroups_mode::engine_scope_dir(&path).map(str::to_string)),
        None => None,
    };
    let Some(dir) = dir else {
        // (where it would be is not known: not touched)
        return Ok(true);
    };
    let events = PathBuf::from(super::cgroups_mode::CGROUP_FS)
        .join(dir.trim_start_matches('/'))
        .join("cgroup.events");
    Ok(std::fs::read_to_string(events).is_ok_and(|e| e.lines().any(|l| l == "populated 1")))
}

/// The cgroup directory the scope `name` has once the manager made it, when
/// it is known from the name.
fn scope_dir_of(name: &str) -> io::Result<Option<PathBuf>> {
    let Some(id) = name.strip_prefix("velarx-") else {
        return Ok(None);
    };
    let Some(path) = super::cgroups_mode::engine_scope_path(id).map_err(io::Error::other)? else {
        return Ok(None);
    };
    Ok(super::cgroups_mode::engine_scope_dir(&path)
        .map(|dir| PathBuf::from(super::cgroups_mode::CGROUP_FS).join(dir.trim_start_matches('/'))))
}

/// The cgroup of `holder` when it is the scope `want` (`/NAME.scope`).
fn cgroup_of_holder(holder: i32, want: &str) -> io::Result<Option<String>> {
    let text = std::fs::read_to_string(format!("/proc/{holder}/cgroup"))?;
    Ok(velarx_base::cgroup::path_in(&text)
        .filter(|p| p.ends_with(want))
        .map(str::to_string))
}

/// Wait until the manager has put `holder` in the scope: the cgroup of the
/// scope is created (an event of its parent directory), then a process
/// joins it (an event of its `cgroup.events`).
fn wait_holder_joined(dir: &std::path::Path, holder: i32, want: &str) -> io::Result<String> {
    let timed_out = || {
        io::Error::new(
            io::ErrorKind::TimedOut,
            format!("the manager did not put the holder in {want}"),
        )
    };
    let start = Instant::now();
    let watch = velarx_sys::watch::Watch::new()?;
    if let Some(parent) = dir.parent() {
        watch.creations_in(parent)?;
    }
    loop {
        // (watched before it is looked at: no change falls between)
        let _ = watch.changes_of(&dir.join("cgroup.events"));
        if let Some(cgroup) = cgroup_of_holder(holder, want)? {
            return Ok(cgroup);
        }
        let left = JOIN_TIMEOUT
            .checked_sub(start.elapsed())
            .ok_or_else(timed_out)?;
        if !watch.wait(left)? && cgroup_of_holder(holder, want)?.is_none() {
            return Err(timed_out());
        }
    }
}

/// Stop the scope `name` of an earlier start of the container, and wait for
/// the job: a manager that has no such unit any more has nothing to stop.
fn stop_stale(socket: &Path, name: &str) -> io::Result<()> {
    match velarx_wire::sdbus::stop_unit_at(socket, &format!("{name}.scope")) {
        Err(e) if velarx_wire::sdbus::no_such_unit(&e) => Ok(()),
        r => r,
    }
}

/// The thread: ask, wait for the holder to be in the scope, and prepare it.
fn make(system: bool, name: &str, holder: i32) -> io::Result<PathBuf> {
    let slice = if system {
        "machine.slice"
    } else {
        "user.slice"
    };
    // The unit of the container's last run may still be loaded: for a
    // moment after its last process ended (the manager collects it on its
    // next turn), or for good when its cgroup went before the manager saw
    // it empty (it then waits for an event of a cgroup that is gone): the
    // name is then taken.  The start lock of the container is held (one
    // start of it at a time) and the container does not run, so no other
    // start has a holder in that unit (a scope asked for at the beginning
    // of a command is for a new id): one with nothing in its cgroup is left
    // over and stopped, and the manager says when it is gone.
    // (the cgroup of the slice is made by the manager with its first unit,
    // after it answered: before that there is no directory to watch, and
    // the answer is waited for)
    let known = scope_dir_of(name)?.filter(|d| d.parent().is_some_and(Path::is_dir));
    let socket = velarx_wire::sdbus::manager_socket(system).map_err(io::Error::other)?;
    let unit = format!("{name}.scope");
    let asked = Instant::now();
    loop {
        match velarx_wire::sdbus::start_scope(
            system,
            name,
            "velarx container",
            &[holder as u32],
            true,
            Some(slice),
            // (without the cgroup the scope will have to watch, the answer
            // is waited for: it comes when the holder is in the scope)
            known.is_none(),
        ) {
            Ok(()) => break,
            Err(e) if velarx_wire::sdbus::unit_exists(&e) => {
                let left = UNIT_GONE_TIMEOUT.saturating_sub(asked.elapsed());
                // (a unit with processes is not ours to stop; the limit
                // only bounds the manager's answer)
                if !in_use(name)? {
                    stop_stale(&socket, name)?;
                }
                if left.is_zero() || !velarx_wire::sdbus::wait_unit_gone(&socket, &unit, left)? {
                    return Err(e);
                }
            }
            Err(e) => return Err(e),
        }
    }
    velarx_base::trace::point("scope requested");
    let want = format!("/{name}.scope");
    let cgroup = match (cgroup_of_holder(holder, &want)?, &known) {
        (Some(cgroup), _) => cgroup,
        (None, Some(dir)) => wait_holder_joined(dir, holder, &want)?,
        (None, None) => {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!("the manager did not put the holder in {name}.scope"),
            ))
        }
    };
    let root = PathBuf::from(super::cgroups_mode::CGROUP_FS).join(cgroup.trim_start_matches('/'));
    // The scope may hold no process of its own once its children get
    // controllers: the holder goes below it, then the controllers, then the
    // monitor's cgroup (the runtime makes the container's).  The move comes
    // soon after the manager's own, which makes it cheap.
    let holder_cg = root.join("holder");
    std::fs::create_dir(&holder_cg)?;
    std::fs::write(holder_cg.join("cgroup.procs"), holder.to_string())?;
    super::cgroups_mode::enable_controllers(&root);
    std::fs::create_dir(root.join("monitor"))?;
    Ok(root)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::OwnedFd;

    /// A descriptor that becomes readable when the process `pid` ends.
    fn pidfd(pid: i32) -> OwnedFd {
        let pid = rustix::process::Pid::from_raw(pid).unwrap();
        rustix::process::pidfd_open(pid, rustix::process::PidfdFlags::empty()).unwrap()
    }

    fn ends_within(fd: &OwnedFd, ms: i64) -> bool {
        let mut fds = [rustix::event::PollFd::new(fd, rustix::event::PollFlags::IN)];
        let timeout = rustix::time::Timespec {
            tv_sec: ms / 1000,
            tv_nsec: (ms % 1000) * 1_000_000,
        };
        rustix::event::poll(&mut fds, Some(&timeout)) == Ok(1)
    }

    /// The holder of a scope ends when the cgroups of the scope are let go
    /// (the container is made, or its start failed), and its cgroup goes.
    #[test]
    fn the_holder_ends_with_its_scope() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir(tmp.path().join("holder")).unwrap();
        let holder = fork_holder("velarx-test").unwrap();
        let fd = pidfd(holder);
        assert!(!ends_within(&fd, 0), "the holder waits");
        drop(Dirs {
            root: tmp.path().to_path_buf(),
            monitor: tmp.path().join("monitor"),
            holder,
        });
        assert!(ends_within(&fd, 10_000), "the holder ended");
    }

    /// A scope that is asked for but never taken (the command failed before
    /// the start) lets its holder go too.
    #[test]
    fn a_pending_scope_that_is_dropped_ends_its_holder() {
        let holder = fork_holder("velarx-test").unwrap();
        let fd = pidfd(holder);
        let thread = std::thread::spawn(|| Err(io::Error::other("no manager")));
        drop(Pending {
            id: "x".into(),
            holder,
            thread: Some(thread),
        });
        assert!(ends_within(&fd, 10_000), "the holder ended");
    }

    /// The empty cgroups an older start left go; one that is not empty
    /// stays.
    /// A unit whose cgroup is not known is not taken for a left over one.
    #[test]
    fn a_scope_of_no_container_is_not_stopped() {
        assert!(in_use("other.scope").unwrap());
        assert!(in_use("velarx-short").unwrap());
    }

    #[test]
    fn leftovers_go_when_empty() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("velarx-x.scope");
        for sub in ["container", "monitor", "holder"] {
            std::fs::create_dir_all(dir.join(sub)).unwrap();
        }
        remove_leftovers(&dir);
        assert!(!dir.exists());
        std::fs::create_dir_all(dir.join("container")).unwrap();
        std::fs::write(dir.join("container/busy"), "").unwrap();
        remove_leftovers(&dir);
        assert!(
            dir.join("container").exists(),
            "not empty: not ours to remove"
        );
    }
}
