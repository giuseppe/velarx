// SPDX-License-Identifier: Apache-2.0
//! The change of a log directory, told to every reader that follows a log
//! in it.
//!
//! A reader holds a [`DirWatch`]: a descriptor that is readable once the
//! directory changed after the last [`DirWatch::clear`], to be waited on with
//! `poll` together with its other descriptors.  The watches of a process
//! share its one inotify instance (`velarx_sys::watch`: a host allows 128 to
//! a user, shared with all the programs of the user), and the readers of one
//! directory share its watch, which goes with the last of them.
//!
//! A reader reads the log again whenever it is woken, and it is woken on
//! anything (an event of the directory, a watch that ended, events the kernel
//! dropped: `IN_QUEUE_OVERFLOW`), so no event has to be told exactly.  The watch
//! is made before the reader looks at the log, so a write after the look is
//! an event after the watch.

use std::io;
use std::os::fd::{AsFd, BorrowedFd};
use std::path::Path;

use rustix::fs::inotify::WatchFlags;

/// What of a directory is watched: the log is appended, created, rotated.
const MASK: WatchFlags = WatchFlags::MODIFY
    .union(WatchFlags::CREATE)
    .union(WatchFlags::MOVED_TO)
    .union(WatchFlags::MOVED_FROM);

/// Tells that a log directory changed.
pub struct DirWatch(velarx_sys::watch::Watch);

impl DirWatch {
    /// Watch the directory `dir`, from now on.
    pub fn new(dir: &impl AsFd) -> io::Result<Self> {
        let watch = velarx_sys::watch::Watch::new()?;
        // (the directory opened, not its path again)
        let path = velarx_sys::fd::proc_str(&dir.as_fd());
        watch.add(Path::new(&path), MASK)?;
        Ok(Self(watch))
    }

    /// Readable when the directory changed since the last [`clear`](Self::clear).
    pub fn fd(&self) -> BorrowedFd<'_> {
        self.0.fd()
    }

    /// Forget the changes told so far: read the log after this.
    pub fn clear(&self) {
        self.0.clear();
    }

    /// Wake whoever waits on this watch, as a change would.
    pub fn wake(&self) {
        self.0.wake();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsFd;
    use std::sync::Mutex;

    fn readable(w: &DirWatch, ms: u16) -> bool {
        let mut fds = [rustix::event::PollFd::from_borrowed_fd(
            w.fd(),
            rustix::event::PollFlags::IN,
        )];
        let t = rustix::event::Timespec {
            tv_sec: i64::from(ms / 1000),
            tv_nsec: i64::from(ms % 1000) * 1_000_000,
        };
        rustix::event::poll(&mut fds, Some(&t)).unwrap() > 0
    }

    /// Until the events of what was done are told (a write is several).
    fn settle(w: &DirWatch) {
        loop {
            w.clear();
            if !readable(w, 100) {
                return;
            }
        }
    }

    fn watch(path: &std::path::Path) -> DirWatch {
        let dir = std::fs::File::open(path).unwrap();
        DirWatch::new(&dir.as_fd()).unwrap()
    }

    fn instances() -> usize {
        std::fs::read_dir("/proc/self/fd")
            .unwrap()
            .filter_map(|e| std::fs::read_link(e.ok()?.path()).ok())
            .filter(|l| l.to_string_lossy().contains("inotify"))
            .count()
    }

    /// The tests share the hub of the process, and some wake every reader:
    /// one at a time.
    static ONE: Mutex<()> = Mutex::new(());

    #[test]
    fn the_readers_of_a_process_share_one_instance() {
        let _one = ONE.lock().unwrap_or_else(|e| e.into_inner());
        let dirs: Vec<_> = (0..20).map(|_| tempfile::tempdir().unwrap()).collect();
        let first = watch(dirs[0].path());
        let before = instances();
        let watches: Vec<_> = (0..500).map(|i| watch(dirs[i % 20].path())).collect();
        assert_eq!(instances(), before);
        // a write wakes the readers of its directory only
        std::fs::write(dirs[3].path().join("log"), b"x").unwrap();
        for (i, w) in watches.iter().enumerate() {
            assert_eq!(readable(w, if i % 20 == 3 { 5000 } else { 0 }), i % 20 == 3);
        }
        assert!(!readable(&first, 0));
    }

    #[test]
    fn a_reader_is_woken_by_what_happens_after_it_cleared() {
        let _one = ONE.lock().unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir().unwrap();
        let w = watch(dir.path());
        assert!(!readable(&w, 0));
        std::fs::write(dir.path().join("a"), b"1").unwrap();
        assert!(readable(&w, 5000));
        settle(&w);
        assert!(!readable(&w, 0));
        std::fs::write(dir.path().join("a"), b"2").unwrap();
        assert!(readable(&w, 5000));
    }

    #[test]
    fn rotation_and_truncation_wake_the_readers() {
        let _one = ONE.lock().unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("log");
        std::fs::write(&log, b"abc").unwrap();
        let w = watch(dir.path());
        std::fs::rename(&log, dir.path().join("log.1")).unwrap();
        assert!(readable(&w, 5000));
        settle(&w);
        std::fs::write(&log, b"def").unwrap();
        assert!(readable(&w, 5000));
        settle(&w);
        std::fs::OpenOptions::new()
            .write(true)
            .open(&log)
            .unwrap()
            .set_len(0)
            .unwrap();
        assert!(readable(&w, 5000));
    }

    /// A reader that joins or leaves while events come: the others are
    /// woken as ever, and a directory watched again after the last of its
    /// readers left is watched.
    #[test]
    fn readers_join_and_leave_while_events_come() {
        let _one = ONE.lock().unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir().unwrap();
        let stay = watch(dir.path());
        let writer = {
            let p = dir.path().join("log");
            std::thread::spawn(move || {
                for i in 0..300 {
                    std::fs::write(&p, i.to_string()).unwrap();
                }
            })
        };
        for _ in 0..300 {
            let w = watch(dir.path());
            drop(w);
        }
        writer.join().unwrap();
        assert!(readable(&stay, 5000));
        stay.clear();
        drop(stay);
        let again = watch(dir.path());
        std::fs::write(dir.path().join("log"), b"z").unwrap();
        assert!(readable(&again, 5000));
    }

    /// A directory that goes ends its watch and wakes its readers.
    #[test]
    fn a_removed_directory_wakes_its_readers() {
        let _one = ONE.lock().unwrap_or_else(|e| e.into_inner());
        let parent = tempfile::tempdir().unwrap();
        let sub = parent.path().join("d");
        std::fs::create_dir(&sub).unwrap();
        let w = watch(&sub);
        std::fs::remove_dir(&sub).unwrap();
        assert!(readable(&w, 5000));
    }

    /// Followers do not use the instances of the user: with none left (the
    /// limit of a user namespace of the test, which other programs of the
    /// host do not share) the readers of other logs are made all the same.
    /// The test runs itself in that namespace.
    #[test]
    fn readers_need_no_instance_of_their_own() {
        const CHILD: &str = "LOGWATCH_TEST_NO_INSTANCES";
        let _one = ONE.lock().unwrap_or_else(|e| e.into_inner());
        if std::env::var_os(CHILD).is_some() {
            let dirs: Vec<_> = (0..50).map(|_| tempfile::tempdir().unwrap()).collect();
            // (the instance of the process, made first)
            let mut watches = vec![watch(dirs[0].path())];
            let mut held = Vec::new();
            while let Ok(fd) = rustix::fs::inotify::init(rustix::fs::inotify::CreateFlags::CLOEXEC)
            {
                held.push(fd);
            }
            assert!(!held.is_empty());
            watches.extend(dirs[1..].iter().map(|d| watch(d.path())));
            std::fs::write(dirs[7].path().join("log"), b"x").unwrap();
            assert!(readable(&watches[7], 5000));
            return;
        }
        let exe = std::env::current_exe().unwrap();
        let run = std::process::Command::new("unshare")
            .args(["-Ur", "sh", "-c"])
            .arg(
                "echo 6 > /proc/sys/user/max_inotify_instances || exit 77; exec \"$0\" --exact \
                 monitor::logwatch::tests::readers_need_no_instance_of_their_own",
            )
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
}
