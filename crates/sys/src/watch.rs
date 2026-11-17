// SPDX-License-Identifier: Apache-2.0
//! Waits for a change of the file system that an event announces, with no
//! timer: inotify.
//!
//! A user owns a limited number of inotify instances
//! (`fs.inotify.max_user_instances`, 128 by default, shared by all the
//! processes of the user: for root also udev and the service manager), so a
//! process has ONE for all its watches, however many containers it starts,
//! waits for or follows: a thread reads it and wakes the watches by watch
//! descriptor.  A [`Watch`] is a descriptor (an eventfd) that is readable
//! once one of its paths changed after the last [`Watch::clear`], to be
//! waited on with `poll` together with other descriptors, or with
//! [`Watch::wait`].
//!
//! A watch is woken on anything of its paths (an event, a watch the kernel
//! ended, events the kernel dropped: `IN_Q_OVERFLOW`), and the watches of
//! one path share the kernel's watch, whose events are those any of them
//! asked for: whoever is woken looks again at what it waits for.  A path is
//! added before it is looked at, so a change after the look is an event
//! after the watch.

use std::collections::HashMap;
use std::io;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use rustix::fs::inotify::{self, ReadFlags, WatchFlags};

/// A new inotify instance, with an error that says which limit was reached
/// when the user has none left (`QuotaExceeded`).
pub fn inotify_init() -> io::Result<OwnedFd> {
    use rustix::fs::inotify::CreateFlags;
    inotify::init(CreateFlags::CLOEXEC | CreateFlags::NONBLOCK).map_err(|e| {
        if e == rustix::io::Errno::MFILE {
            io::Error::new(
                io::ErrorKind::QuotaExceeded,
                "the user has no inotify instance left (the limit \
                 fs.inotify.max_user_instances is reached: raise it with \
                 `sysctl fs.inotify.max_user_instances=N`), or the process \
                 has no file descriptor left",
            )
        } else {
            e.into()
        }
    })
}

/// Watch `path` in the instance `fd`, with an error that says which limit
/// was reached when the user has no watch left (`QuotaExceeded`).
fn add_watch(fd: &OwnedFd, path: &Path, flags: WatchFlags) -> io::Result<i32> {
    inotify::add_watch(fd, path, flags).map_err(|e| {
        if e == rustix::io::Errno::NOSPC {
            io::Error::new(
                io::ErrorKind::QuotaExceeded,
                format!(
                    "cannot watch {}: the user has no inotify watch left (the \
                 limit fs.inotify.max_user_watches is reached: raise it with \
                 `sysctl fs.inotify.max_user_watches=N`)",
                    path.display()
                ),
            )
        } else {
            e.into()
        }
    })
}

/// The instance of a process, and the watches it wakes.
struct Hub {
    inotify: OwnedFd,
    state: Mutex<State>,
}

#[derive(Default)]
struct State {
    /// The watches of each watch descriptor of the kernel.
    watches: HashMap<i32, Vec<(u64, Arc<OwnedFd>)>>,
    next: u64,
    /// The thread that reads the instance ended: it wakes nobody any more.
    dead: bool,
}

impl Hub {
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn wake(wake: &OwnedFd) {
        // (a counter: a wake that finds it set changes nothing)
        let _ = rustix::io::write(wake, &1u64.to_ne_bytes());
    }

    fn wake_all(state: &State) {
        for (_, wake) in state.watches.values().flatten() {
            Self::wake(wake);
        }
    }

    /// Read the instance for the life of the process.
    fn serve(self: Arc<Self>) {
        let mut buf = [std::mem::MaybeUninit::<u8>::uninit(); 4096];
        loop {
            let mut reader = inotify::Reader::new(&self.inotify, &mut buf);
            let mut told = false;
            loop {
                match reader.next() {
                    Ok(ev) => {
                        told = true;
                        self.event(ev.wd(), ev.events());
                    }
                    Err(rustix::io::Errno::AGAIN) => break,
                    Err(rustix::io::Errno::INTR) => continue,
                    Err(_) => {
                        // (the watches are woken and look again; the next
                        // watch made gets a new instance)
                        let mut state = self.lock();
                        state.dead = true;
                        Self::wake_all(&state);
                        return;
                    }
                }
            }
            if !told {
                // (blocks until something happens: no timer)
                let mut fds = [rustix::event::PollFd::new(
                    &self.inotify,
                    rustix::event::PollFlags::IN,
                )];
                let _ = rustix::event::poll(&mut fds, None);
            }
        }
    }

    fn event(&self, wd: i32, events: ReadFlags) {
        let mut state = self.lock();
        if events.contains(ReadFlags::QUEUE_OVERFLOW) || wd < 0 {
            // events were lost: every watch looks again
            Self::wake_all(&state);
            return;
        }
        if events.contains(ReadFlags::IGNORED) {
            // the path is gone (the kernel ended the watch)
            for (_, wake) in state.watches.remove(&wd).iter().flatten() {
                Self::wake(wake);
            }
            return;
        }
        for (_, wake) in state.watches.get(&wd).into_iter().flatten() {
            Self::wake(wake);
        }
    }
}

/// The hub of this process (a forked child makes its own: the thread does
/// not come along).
fn hub() -> io::Result<Arc<Hub>> {
    static HUB: Mutex<Option<(u32, Arc<Hub>)>> = Mutex::new(None);
    let mut slot = HUB.lock().unwrap_or_else(|e| e.into_inner());
    let pid = std::process::id();
    if let Some((p, hub)) = &*slot {
        if *p == pid && !hub.lock().dead {
            return Ok(hub.clone());
        }
    }
    let hub = Arc::new(Hub {
        inotify: inotify_init()?,
        state: Mutex::default(),
    });
    let served = hub.clone();
    std::thread::Builder::new()
        .name("watch".into())
        .spawn(move || served.serve())?;
    *slot = Some((pid, hub.clone()));
    Ok(hub)
}

/// A watch of paths: for a file to change, a name to appear, a path to go.
pub struct Watch {
    hub: Arc<Hub>,
    id: u64,
    wake: Arc<OwnedFd>,
    /// The watch descriptors this watch is woken by
    wds: Mutex<Vec<i32>>,
}

impl Watch {
    pub fn new() -> io::Result<Self> {
        let hub = hub()?;
        let wake = Arc::new(rustix::event::eventfd(
            0,
            rustix::event::EventfdFlags::CLOEXEC | rustix::event::EventfdFlags::NONBLOCK,
        )?);
        let id = {
            let mut state = hub.lock();
            state.next += 1;
            state.next
        };
        Ok(Self {
            hub,
            id,
            wake,
            wds: Mutex::default(),
        })
    }

    /// Wake for the events `flags` of `path`, from now on (a path added
    /// again changes nothing).
    pub fn add(&self, path: &Path, flags: WatchFlags) -> io::Result<()> {
        let mut state = self.hub.lock();
        // (the watches of a path share the kernel's: its events are those
        // any of them asked for, added up)
        let wd = add_watch(&self.hub.inotify, path, flags | WatchFlags::MASK_ADD)?;
        let readers = state.watches.entry(wd).or_default();
        if !readers.iter().any(|(id, _)| *id == self.id) {
            readers.push((self.id, self.wake.clone()));
        }
        let mut wds = self.wds.lock().unwrap_or_else(|e| e.into_inner());
        if !wds.contains(&wd) {
            wds.push(wd);
        }
        Ok(())
    }

    /// Wake for a change of the content of `path` (a file of a cgroup, say)
    /// and for its removal.
    pub fn changes_of(&self, path: &Path) -> io::Result<()> {
        self.add(
            path,
            WatchFlags::MODIFY | WatchFlags::DELETE_SELF | WatchFlags::ATTRIB,
        )
    }

    /// Wake for a name created or moved into the directory `dir`.
    pub fn creations_in(&self, dir: &Path) -> io::Result<()> {
        self.add(dir, WatchFlags::CREATE | WatchFlags::MOVED_TO)
    }

    /// Readable when a path changed since the last [`clear`](Self::clear).
    pub fn fd(&self) -> BorrowedFd<'_> {
        self.wake.as_fd()
    }

    /// A descriptor of its own that is readable when [`fd`](Self::fd) is:
    /// for a reactor that takes the descriptor it waits on.
    pub fn owned_fd(&self) -> io::Result<OwnedFd> {
        Ok(rustix::io::fcntl_dupfd_cloexec(&*self.wake, 0)?)
    }

    /// Forget the changes told so far: look at the paths after this.
    pub fn clear(&self) {
        let mut b = [0u8; 8];
        let _ = rustix::io::read(&*self.wake, &mut b);
    }

    /// Wake whoever waits on this watch, as a change would.
    pub fn wake(&self) {
        Hub::wake(&self.wake);
    }

    /// Wait for a change, at most `limit` (an upper bound, not the normal
    /// case); whether one came.  What came is one wake: it is cleared.
    pub fn wait(&self, limit: Duration) -> io::Result<bool> {
        self.wait_at_most(Some(limit))
    }

    /// Wait for a change, at most `limit` (none: for ever); whether one
    /// came.  What came is one wake: it is cleared.
    pub fn wait_at_most(&self, limit: Option<Duration>) -> io::Result<bool> {
        use rustix::event::{poll, PollFd, PollFlags};
        let timeout = limit.map(|l| rustix::event::Timespec {
            tv_sec: l.as_secs().min(i64::MAX as u64) as i64,
            tv_nsec: i64::from(l.subsec_nanos()),
        });
        let came = loop {
            let mut fds = [PollFd::new(&*self.wake, PollFlags::IN)];
            match poll(&mut fds, timeout.as_ref()) {
                Err(rustix::io::Errno::INTR) => continue,
                Ok(n) => break n > 0,
                Err(e) => return Err(io::Error::new(e.kind(), format!("poll of a watch: {e}"))),
            }
        };
        self.clear();
        Ok(came)
    }
}

impl Drop for Watch {
    fn drop(&mut self) {
        let mut state = self.hub.lock();
        let wds = std::mem::take(self.wds.get_mut().unwrap_or_else(|e| e.into_inner()));
        for wd in wds {
            let Some(readers) = state.watches.get_mut(&wd) else {
                continue;
            };
            readers.retain(|(id, _)| *id != self.id);
            if readers.is_empty() {
                state.watches.remove(&wd);
                // (under the lock, so that a new watch of the path does not
                // find the one that goes)
                let _ = inotify::remove_watch(&self.hub.inotify, wd);
            }
        }
    }
}

/// Wait until `path` is gone, at most `limit` (an upper bound): the removal
/// of a directory is an event.  Whether it is gone; an error when it cannot
/// be watched.
pub fn wait_removed(path: &Path, limit: Duration) -> io::Result<bool> {
    let start = std::time::Instant::now();
    let watch = Watch::new()?;
    // (watched before it is looked at: no removal falls between)
    match watch.changes_of(path) {
        Ok(()) => {}
        // (nothing to watch: it is gone)
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(true),
        Err(e) => return Err(e),
    }
    while path.exists() {
        let Some(left) = limit.checked_sub(start.elapsed()) else {
            return Ok(false);
        };
        if !watch.wait(left)? && path.exists() {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Return when `path` exists: at once if it does, else when its name is
/// created or moved into its directory.  The directory must exist.
#[cfg(feature = "tokio")]
pub async fn path_exists(path: &Path) -> io::Result<()> {
    let (Some(dir), Some(_)) = (path.parent(), path.file_name()) else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "a path with a directory and a name",
        ));
    };
    let dir = if dir.as_os_str().is_empty() {
        Path::new(".")
    } else {
        dir
    };
    let watch = Watch::new()?;
    watch.creations_in(dir)?;
    let woken = super::fd::register(watch.owned_fd()?, tokio::io::Interest::READABLE)?;
    // (looked at after the watch is armed: no creation falls between)
    loop {
        if path.symlink_metadata().is_ok() {
            return Ok(());
        }
        let mut ready = woken.readable().await?;
        watch.clear();
        ready.clear_ready();
    }
}

#[cfg(test)]
mod sync_tests {
    use super::*;

    /// The removal of a directory ends the wait, a change of a file wakes
    /// it, and the limit ends it when nothing happens.
    #[test]
    fn a_removal_and_a_change_are_events() {
        let dir = tempfile::tempdir().unwrap();
        let gone = dir.path().join("gone");
        std::fs::create_dir(&gone).unwrap();
        assert!(
            !wait_removed(&gone, Duration::from_millis(20)).unwrap(),
            "the limit"
        );
        let waiting = {
            let gone = gone.clone();
            std::thread::spawn(move || wait_removed(&gone, Duration::from_secs(60)))
        };
        std::fs::remove_dir(&gone).unwrap();
        assert!(waiting.join().unwrap().unwrap());
        assert!(
            wait_removed(&gone, Duration::ZERO).unwrap(),
            "there is none"
        );

        let file = dir.path().join("events");
        std::fs::write(&file, "populated 1\n").unwrap();
        let watch = Watch::new().unwrap();
        watch.changes_of(&file).unwrap();
        assert!(!watch.wait(Duration::from_millis(20)).unwrap());
        std::fs::write(&file, "populated 0\n").unwrap();
        assert!(watch.wait(Duration::from_secs(60)).unwrap());
    }

    fn instances() -> usize {
        std::fs::read_dir("/proc/self/fd")
            .unwrap()
            .filter_map(|e| std::fs::read_link(e.ok()?.path()).ok())
            .filter(|l| l.to_string_lossy().contains("inotify"))
            .count()
    }

    /// Many waits at once, each for its own directory to appear and go (the
    /// cgroup of a scope a start waits for): one instance for all of them,
    /// and each returns when its event comes.
    #[test]
    fn concurrent_waits_share_one_instance() {
        let _ = Watch::new().unwrap();
        let before = instances();
        let parent = tempfile::tempdir().unwrap();
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(101));
        let waits: Vec<_> = (0..100)
            .map(|i| {
                let dir = parent.path().join(i.to_string());
                let parent = parent.path().to_path_buf();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    let w = Watch::new().unwrap();
                    w.creations_in(&parent).unwrap();
                    barrier.wait();
                    while !dir.exists() {
                        assert!(w.wait(Duration::from_secs(60)).unwrap(), "a creation wakes");
                    }
                    // (each saw its directory before it goes)
                    barrier.wait();
                    wait_removed(&dir, Duration::from_secs(60))
                })
            })
            .collect();
        barrier.wait();
        assert_eq!(instances(), before, "the waits made no instance");
        for i in 0..100 {
            std::fs::create_dir(parent.path().join(i.to_string())).unwrap();
        }
        barrier.wait();
        for i in 0..100 {
            std::fs::remove_dir(parent.path().join(i.to_string())).unwrap();
        }
        for w in waits {
            assert!(w.join().unwrap().unwrap());
        }
        assert_eq!(instances(), before);
    }

    /// The watches of one path share the kernel's watch: a second one with
    /// other events does not take the events of the first, and the first
    /// that goes leaves the second watching.
    #[test]
    fn watches_of_one_path_keep_their_events() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("events");
        std::fs::write(&file, "populated 1\n").unwrap();
        let changes = Watch::new().unwrap();
        changes.add(&file, WatchFlags::MODIFY).unwrap();
        let attrs = Watch::new().unwrap();
        attrs.add(&file, WatchFlags::ATTRIB).unwrap();
        std::fs::write(&file, "populated 0\n").unwrap();
        assert!(changes.wait(Duration::from_secs(60)).unwrap());
        drop(attrs);
        std::fs::write(&file, "populated 1\n").unwrap();
        assert!(changes.wait(Duration::from_secs(60)).unwrap());
    }

    /// Events the kernel dropped wake every watch: they look again.
    #[test]
    fn lost_events_wake_every_watch() {
        let a = tempfile::tempdir().unwrap();
        let b = tempfile::tempdir().unwrap();
        let (wa, wb) = (Watch::new().unwrap(), Watch::new().unwrap());
        wa.creations_in(a.path()).unwrap();
        wb.creations_in(b.path()).unwrap();
        wa.hub.event(-1, ReadFlags::QUEUE_OVERFLOW);
        assert!(wa.wait(Duration::ZERO).unwrap() && wb.wait(Duration::ZERO).unwrap());
    }

    /// The kernel's watch of a path goes with the last watch of it.
    #[test]
    fn the_last_watch_of_a_path_ends_its_watch() {
        let dir = tempfile::tempdir().unwrap();
        let (one, two) = (Watch::new().unwrap(), Watch::new().unwrap());
        one.creations_in(dir.path()).unwrap();
        two.creations_in(dir.path()).unwrap();
        one.creations_in(dir.path()).unwrap();
        let wd = one.wds.lock().unwrap()[0];
        assert_eq!(one.hub.lock().watches[&wd].len(), 2, "one entry each");
        let hub = one.hub.clone();
        drop(one);
        assert!(hub.lock().watches.contains_key(&wd));
        drop(two);
        assert!(!hub.lock().watches.contains_key(&wd));
    }
}

#[cfg(test)]
mod limit_tests {
    const CHILD: &str = "WATCH_TEST_LIMIT";

    /// Run the test `name` again with the limit `sysctl` of a user namespace
    /// of its own set to 0 (other programs of the host do not share it).
    fn in_namespace(name: &str, sysctl: &str) {
        let exe = std::env::current_exe().unwrap();
        let run = std::process::Command::new("unshare")
            .args(["-Ur", "sh", "-c"])
            .arg(format!(
                "echo 0 > /proc/sys/user/{sysctl} || exit 77; exec \"$0\" --exact {name}"
            ))
            .arg(exe)
            .env(CHILD, "1")
            .output();
        match run {
            // (no user namespaces here, or no limit of its own to set:
            // nothing to run in)
            Ok(o)
                if o.status.code() == Some(77)
                    || String::from_utf8_lossy(&o.stderr).contains("unshare:") => {}
            Ok(o) => assert!(
                o.status.success(),
                "{}{}",
                String::from_utf8_lossy(&o.stdout),
                String::from_utf8_lossy(&o.stderr)
            ),
            Err(_) => {}
        }
    }

    /// With no instance left the error names the limit.
    #[test]
    fn the_error_names_the_limit_of_instances() {
        if std::env::var_os(CHILD).is_some() {
            let e = super::inotify_init().unwrap_err();
            assert_eq!(e.kind(), std::io::ErrorKind::QuotaExceeded);
            let e = e.to_string();
            assert!(e.contains("fs.inotify.max_user_instances"), "{e}");
            let e = super::Watch::new().err().expect("no instance").to_string();
            assert!(e.contains("fs.inotify.max_user_instances"), "{e}");
            return;
        }
        in_namespace(
            "watch::limit_tests::the_error_names_the_limit_of_instances",
            "max_inotify_instances",
        );
    }

    /// With no watch left the error names that limit.
    #[test]
    fn the_error_names_the_limit_of_watches() {
        if std::env::var_os(CHILD).is_some() {
            let dir = tempfile::tempdir().unwrap();
            let w = super::Watch::new().unwrap();
            let e = w.creations_in(dir.path()).unwrap_err().to_string();
            assert!(e.contains("fs.inotify.max_user_watches"), "{e}");
            let e = w.creations_in(dir.path()).unwrap_err();
            assert_eq!(e.kind(), std::io::ErrorKind::QuotaExceeded);
            return;
        }
        in_namespace(
            "watch::limit_tests::the_error_names_the_limit_of_watches",
            "max_inotify_watches",
        );
    }
}

#[cfg(all(test, feature = "tokio"))]
mod tests {
    use super::*;

    /// A path that is there returns at once, one that appears is seen
    /// when it does.
    #[tokio::test]
    async fn a_path_that_appears_is_seen() {
        let dir = tempfile::tempdir().unwrap();
        let there = dir.path().join("there");
        std::fs::write(&there, "").unwrap();
        path_exists(&there).await.unwrap();

        let later = dir.path().join("later");
        let waiting = tokio::spawn({
            let later = later.clone();
            async move { path_exists(&later).await }
        });
        tokio::task::yield_now().await;
        assert!(!waiting.is_finished());
        std::fs::write(dir.path().join("other"), "").unwrap();
        std::fs::write(&later, "").unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(10), waiting)
            .await
            .expect("seen")
            .unwrap()
            .unwrap();
        // a name moved into the directory counts
        let moved = dir.path().join("moved");
        let waiting = tokio::spawn({
            let moved = moved.clone();
            async move { path_exists(&moved).await }
        });
        tokio::task::yield_now().await;
        std::fs::write(dir.path().join(".tmp"), "").unwrap();
        std::fs::rename(dir.path().join(".tmp"), &moved).unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(10), waiting)
            .await
            .expect("seen")
            .unwrap()
            .unwrap();
    }
}
