// SPDX-License-Identifier: Apache-2.0
//! What the tests of the pull need to see which names a pull gives to its
//! files: a name made of a digest is for a file that is what it says.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

/// Whether `name` is named by a digest: the key of a file as the session
/// and the store spell it (`xx/yyyy...`, the hex of one without its first
/// two digits), or the hex of one.
pub(crate) fn is_digest_name(name: &str) -> bool {
    let hex = |s: &str| s.len() >= 62 && s.bytes().all(|b| b.is_ascii_hexdigit());
    name.starts_with("sha256-")
        || name.starts_with("sha512-")
        || name.starts_with("fsverity-")
        || hex(name)
}

/// Every name below `root` that is named by a digest.
pub(crate) fn digest_names(root: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let mut todo = vec![root.to_path_buf()];
    while let Some(dir) = todo.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for e in entries.flatten() {
            if is_digest_name(&e.file_name().to_string_lossy()) {
                found.push(e.path());
            }
            if e.file_type().is_ok_and(|t| t.is_dir()) {
                todo.push(e.path());
            }
        }
    }
    found
}

/// Every name that appears in some directories, as it appears: what a
/// process that looks files up by their digest could meet.  The kernel
/// tells (inotify): a thread waits for its word and does not look by turns.
pub(crate) struct Names {
    seen: Arc<Mutex<Seen>>,
    stop: PathBuf,
    thread: Option<std::thread::JoinHandle<()>>,
}

#[derive(Default)]
struct Seen {
    names: Vec<String>,
    /// What `inspecting`'s function said of a name when it appeared
    complaints: Vec<String>,
}

type Inspect = Box<dyn Fn(&Path) -> Option<String> + Send>;

impl Names {
    const STOP: &'static str = "stop-watching";

    pub(crate) fn watching(dirs: &[&Path]) -> Self {
        Self::inspecting(dirs, Box::new(|_| None))
    }

    /// Watch `dirs`; `inspect` is called with each path as it appears (when
    /// the kernel tells, in the watching thread), and what it returns is a
    /// complaint.
    pub(crate) fn inspecting(dirs: &[&Path], inspect: Inspect) -> Self {
        use rustix::fs::inotify::{self, CreateFlags, Reader, WatchFlags};
        let fd = inotify::init(CreateFlags::CLOEXEC).unwrap();
        let mut watched = std::collections::HashMap::new();
        for dir in dirs {
            let wd =
                inotify::add_watch(&fd, *dir, WatchFlags::CREATE | WatchFlags::MOVED_TO).unwrap();
            watched.insert(wd, dir.to_path_buf());
        }
        let seen = Arc::new(Mutex::new(Seen::default()));
        let thread = std::thread::spawn({
            let seen = seen.clone();
            move || {
                let mut buf = [std::mem::MaybeUninit::<u8>::uninit(); 4096];
                let mut reader = Reader::new(&fd, &mut buf);
                while let Ok(event) = reader.next() {
                    let Some(name) = event.file_name() else {
                        continue;
                    };
                    let name = name.to_string_lossy().into_owned();
                    if name == Self::STOP {
                        return;
                    }
                    let complaint = watched
                        .get(&event.wd())
                        .and_then(|dir| inspect(&dir.join(&name)));
                    let mut seen = seen.lock().unwrap();
                    seen.names.push(name);
                    seen.complaints.extend(complaint);
                }
            }
        });
        Self {
            seen,
            stop: dirs[0].join(Self::STOP),
            thread: Some(thread),
        }
    }

    /// The names that appeared, and the complaints about them, once the
    /// thread has seen all of them.
    pub(crate) fn finish(mut self) -> (Vec<String>, Vec<String>) {
        std::fs::write(&self.stop, b"").unwrap();
        self.thread.take().unwrap().join().unwrap();
        let _ = std::fs::remove_file(&self.stop);
        let mut seen = self.seen.lock().unwrap();
        (
            std::mem::take(&mut seen.names),
            std::mem::take(&mut seen.complaints),
        )
    }
}
