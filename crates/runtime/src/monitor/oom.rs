// SPDX-License-Identifier: Apache-2.0
//! Out of memory kills in the cgroup of the container (cgroup v2):
//! `memory.events` changes, and its `oom_kill` counter says whether the
//! kernel killed a process of the container.  A change of the file wakes
//! `poll` on the open file itself (`POLLPRI`, the notification of the cgroup
//! file system), so the watch holds no inotify instance: the instances of a
//! user are limited (128 by default) and one per container would run out.

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::os::fd::{AsFd, BorrowedFd};
use std::path::Path;

pub struct OomWatch {
    events: File,
    kills: u64,
    /// The cgroup is gone: the file reports a change for ever.
    gone: bool,
}

/// The `oom_kill` counter of the text of a `memory.events` file.
pub fn parse_oom_kills(text: &str) -> u64 {
    text.lines()
        .find_map(|l| l.strip_prefix("oom_kill "))
        .and_then(|n| n.trim().parse().ok())
        .unwrap_or(0)
}

/// The cgroup v2 directory of a process, from `/proc`.
fn cgroup_of(proc_dir: &Path) -> Option<String> {
    let text = std::fs::read_to_string(proc_dir.join("cgroup")).ok()?;
    velarx_base::cgroup::path_in(&text).map(str::to_string)
}

impl OomWatch {
    /// Watch the cgroup of the process `pid`, if it has one of its own: a
    /// container in the cgroup of the monitor shares it with others, and
    /// their kills would be taken for its own.
    pub fn open(pid: i32) -> Option<Self> {
        let theirs = cgroup_of(Path::new(&format!("/proc/{pid}")))?;
        if cgroup_of(Path::new("/proc/self")).as_deref() == Some(theirs.as_str()) || theirs == "/" {
            return None;
        }
        let path = Path::new("/sys/fs/cgroup")
            .join(theirs.trim_start_matches('/'))
            .join("memory.events");
        Self::watching(&path)
    }

    /// Watch the `memory.events` file at `path`.
    fn watching(path: &Path) -> Option<Self> {
        let events = File::open(path).ok()?;
        let mut w = Self {
            events,
            kills: 0,
            gone: false,
        };
        // What happened before the watch does not count.
        w.kills = w.read_kills().ok()?;
        Some(w)
    }

    /// The file to poll for `POLLPRI`; none once the cgroup is gone.
    pub fn fd(&self) -> Option<BorrowedFd<'_>> {
        (!self.gone).then(|| self.events.as_fd())
    }

    fn read_kills(&mut self) -> io::Result<u64> {
        let mut text = String::new();
        self.events.seek(SeekFrom::Start(0))?;
        self.events.read_to_string(&mut text)?;
        Ok(parse_oom_kills(&text))
    }

    /// Whether the kernel killed a process since the last call.
    pub fn check(&mut self) -> bool {
        match self.read_kills() {
            Ok(n) if n > self.kills => {
                self.kills = n;
                true
            }
            // (reading the file is what arms the next notification)
            Ok(_) => false,
            Err(_) => {
                self.gone = true;
                false
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The kills of the cgroup before the watch are not its kills: only a
    /// kill after it is.
    #[test]
    fn the_kills_before_the_watch_do_not_count() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("memory.events");
        std::fs::write(&path, "oom 2\noom_kill 2\n").unwrap();
        let mut w = OomWatch::watching(&path).unwrap();
        assert!(!w.check());
        std::fs::write(&path, "oom 3\noom_kill 3\n").unwrap();
        assert!(w.check());
        assert!(!w.check());
    }

    #[test]
    fn the_counter_is_found() {
        let text = "low 0\nhigh 0\nmax 12\noom 3\noom_kill 2\noom_group_kill 0\n";
        assert_eq!(parse_oom_kills(text), 2);
        assert_eq!(parse_oom_kills("low 0\n"), 0);
        assert_eq!(parse_oom_kills("oom_kill x\n"), 0);
    }

    /// The watch needs no inotify instance: with none left (the limit of a
    /// user namespace of the test, which other programs of the host do not
    /// share) it is made all the same.  The test runs itself in that
    /// namespace.
    #[test]
    fn the_watch_holds_no_inotify_instance() {
        const CHILD: &str = "OOM_TEST_NO_INSTANCES";
        if std::env::var_os(CHILD).is_some() {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("memory.events");
            std::fs::write(&path, "oom_kill 0\n").unwrap();
            assert!(rustix::fs::inotify::init(rustix::fs::inotify::CreateFlags::CLOEXEC).is_err());
            let mut w = OomWatch::watching(&path).expect("a watch with no instance left");
            assert!(w.fd().is_some());
            std::fs::write(&path, "oom_kill 1\n").unwrap();
            assert!(w.check());
            assert!(!w.check());
            return;
        }
        let exe = std::env::current_exe().unwrap();
        let run = std::process::Command::new("unshare")
            .args(["-Ur", "sh", "-c"])
            .arg(
                "echo 0 > /proc/sys/user/max_inotify_instances || exit 77; exec \"$0\" --exact \
                 monitor::oom::tests::the_watch_holds_no_inotify_instance",
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

    /// On the file of a cgroup (that of the test, where it has one): the
    /// read of the watch arms the notification, so `poll` does not wake
    /// while nothing happens, and a watch that is woken reads again.
    #[test]
    fn a_quiet_cgroup_does_not_wake_the_watch() {
        let Some(own) = cgroup_of(Path::new("/proc/self")) else {
            return;
        };
        let path = Path::new("/sys/fs/cgroup")
            .join(own.trim_start_matches('/'))
            .join("memory.events");
        let Some(mut w) = OomWatch::watching(&path) else {
            // (no memory controller here)
            return;
        };
        let quiet = |w: &OomWatch| {
            let mut fds = [rustix::event::PollFd::from_borrowed_fd(
                w.fd().expect("the cgroup is there"),
                rustix::event::PollFlags::PRI,
            )];
            let now = rustix::event::Timespec {
                tv_sec: 0,
                tv_nsec: 0,
            };
            rustix::event::poll(&mut fds, Some(&now)).unwrap() == 0
        };
        // (a memory event of the cgroup of the test may come meanwhile: it
        // is read, and then it is quiet)
        assert!(quiet(&w) || (!w.check() && quiet(&w)));
    }

    #[test]
    fn a_process_in_our_own_cgroup_is_not_watched() {
        assert!(OomWatch::open(std::process::id() as i32).is_none());
        assert!(OomWatch::open(0).is_none());
    }
}
