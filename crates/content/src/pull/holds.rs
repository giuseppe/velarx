// SPDX-License-Identifier: Apache-2.0
//! Holds: what a process that works in the staging directory of the store
//! (a pull, a commit, a build) tells the others, so that the garbage
//! collection and `system check` can tell its directory from the leftover of
//! one that died, and know what it uses of the store.
//!
//! A hold is a directory `staging/pull-<id>` or `staging/build-<id>` that is
//! live while an open descriptor of it has an `flock`.  Its owner locks it
//! shared and keeps the descriptor for as long as it works: the kernel drops
//! the lock when the process ends, however it ends.  Whoever wants to judge
//! or remove a hold tries to lock it exclusive without waiting: it gets the
//! lock if nobody holds the directory, and keeps it while it removes it.  A
//! failed try, whatever the reason, is "live": what a live process uses is
//! never taken for garbage.
//!
//! The last user of a hold to let go removes its directory (the owner and
//! whoever joined it: a pull's session and the engine's feed).  Between "the
//! last user unlocked" and "the directory is gone" the hold is unheld, and
//! a look must not see that instant: letting go and probing go through the
//! gate, a lock on the staging directory itself (no file is made for it).
//! A user lets go under the gate exclusive: it unlocks its hold, tries to
//! lock it exclusive without waiting, and, if it got the lock, renames the
//! directory to a dead name (`.new-<random>`, the family of the births, which
//! the sweep takes for no hold).  It then releases the gate and removes the
//! renamed directory while it still holds the exclusive lock (the lock
//! follows the inode, so a sweep that meets the dead directory finds it
//! locked and skips it, and removes it later if this process died before it
//! finished).  A probe takes the gate shared for the try on one hold.  So
//! under the gate a hold is held, or gone from its name for good, and the
//! gate is held for a rename, never for the walk of a tree.  Holders and
//! non-holders of the lock of the store alike take the gate.  Birth and join
//! need no gate: a hold is born locked (temporary name, lock, rename), and a
//! join locks the directory and then looks that its name is still the same
//! directory, so one that races with the last user's removal is refused or
//! finds the directory gone.
//!
//! A gate that cannot be taken is an error, never "live" and never "stale"
//! (a staging directory that is not there has no holds: "gone").  flock does
//! not queue fairly: a stream of overlapping shared probes could delay an
//! exclusive letting go; each probe is short.
//!
//! Lock order: the gate is a leaf.  It is taken (waiting) for the length of
//! one probe or one rename, with nothing else waited for meanwhile (the only
//! other lock taken under it is the try, without waiting, on the hold
//! itself).  The holders of the lock of the store may take the gate; nothing
//! holding the gate takes the lock of the store, a layer's lease,
//! `names.lock`, the database or an image lock.
//!
//! A hold is made under a temporary name (`.new-<random>`), locked, and only
//! then renamed (the lock follows the open file): a directory with a name of
//! a hold is never unlocked while its owner lives.  The file `pins` in it
//! lists what the owner uses of the store, one `layer <key>` or `image <id>`
//! a line, appended with a single write; the pins of a hold nobody holds are
//! of no account.

use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use velarx_sys::flock::{flock_retrying, Held};

/// The file of a hold that lists what it pins.
pub const PINS: &str = "pins";
/// The kind of a pin of a layer (its key).
pub const LAYER: &str = "layer";
/// The kind of a pin of an image (its id), which keeps it from a prune.
pub const IMAGE: &str = "image";
/// The start of the name a hold is made under.
const BORN: &str = ".new-";

/// Whether `name` is the name of a hold: `pull-` or `build-` and a random
/// id.
pub fn is_hold_name(name: &str) -> bool {
    ["pull-", "build-"].iter().any(|prefix| {
        name.strip_prefix(prefix).is_some_and(|id| {
            !id.is_empty() && id.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-')
        })
    })
}

/// A new name of a hold of the kind `prefix` (`pull`, `build`).
pub fn new_name(prefix: &str) -> String {
    format!("{prefix}-{}", velarx_base::random::uuid())
}

/// The open directory `dir`, not followed when it is a link.
fn open_dir(dir: &Path) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(dir)
}

/// Whether `dir` is still the directory `fd` is open on.
fn is_linked(fd: impl std::os::fd::AsFd, dir: &Path) -> io::Result<bool> {
    let held = rustix::fs::fstat(fd)?;
    Ok(fs::symlink_metadata(dir)
        .is_ok_and(|now| (now.dev(), now.ino()) == (held.st_dev as u64, held.st_ino as u64)))
}

/// A hold this process keeps live while it exists.
#[derive(Debug)]
pub struct Hold {
    name: String,
    dir: PathBuf,
    /// Let go when the hold is dropped, before the directory is looked at
    lock: Option<Held>,
}

impl Hold {
    /// Make the hold `name` in `staging`, which exists: an empty directory
    /// (mode 0700) with an empty `pins`, locked shared from its birth.
    pub fn create(staging: &Path, name: &str) -> io::Result<Self> {
        let dir = staging.join(name);
        loop {
            let born = staging.join(format!("{BORN}{}", velarx_base::random::uuid()));
            fs::DirBuilder::new().mode(0o700).create(&born)?;
            let file = match open_dir(&born) {
                Ok(file) => file,
                // (a sweep took it away: another name)
                Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
                Err(e) => return Err(e),
            };
            match flock_retrying(&file, rustix::fs::FlockOperation::NonBlockingLockShared) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                Err(e) => return Err(e),
            }
            // (a sweep that removed it before it was locked: it is not ours)
            if !is_linked(&file, &born)? {
                continue;
            }
            let named = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(born.join(PINS))
                .map(drop)
                .and_then(|()| {
                    rustix::fs::renameat_with(
                        rustix::fs::CWD,
                        &born,
                        rustix::fs::CWD,
                        &dir,
                        rustix::fs::RenameFlags::NOREPLACE,
                    )
                    .map_err(io::Error::from)
                });
            if let Err(e) = named {
                // (best effort: the sweep takes what is left)
                let _ = velarx_base::tree::remove_dir_all(&born);
                return Err(e);
            }
            return Ok(Self {
                name: name.to_string(),
                dir,
                lock: Some(Held::new(file)),
            });
        }
    }

    /// Also hold the hold `name` that another user of it made, which lives:
    /// its owner holds it shared too.  `NotFound` when it is not there.
    pub fn join(staging: &Path, name: &str) -> io::Result<Self> {
        let dir = staging.join(name);
        let file = open_dir(&dir)?;
        flock_retrying(&file, rustix::fs::FlockOperation::NonBlockingLockShared)?;
        if !is_linked(&file, &dir)? {
            return Err(io::ErrorKind::NotFound.into());
        }
        Ok(Self {
            name: name.to_string(),
            dir,
            lock: Some(Held::new(file)),
        })
    }

    /// [`Self::join`] the hold `name`; one that is not there is made, and one
    /// whose last user is taking it away at this moment (the lock is
    /// refused) is replaced by a new one, so that the caller is never
    /// left without.
    pub fn join_or_create(staging: &Path, name: &str) -> io::Result<Self> {
        match Self::join(staging, name) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => Self::create(staging, name),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                Self::create(staging, &new_name("pull"))
            }
            joined => joined,
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn path(&self) -> &Path {
        &self.dir
    }

    /// Remove what is in the directory but the pins: what the owner worked
    /// with is gone, what it still uses of the store is pinned until the
    /// last user lets go.
    pub fn clear(&self) -> io::Result<()> {
        for entry in fs::read_dir(&self.dir)? {
            let entry = entry?;
            if entry.file_name() == PINS {
                continue;
            }
            if entry.file_type()?.is_dir() {
                velarx_base::tree::remove_dir_all(entry.path())?;
            } else {
                fs::remove_file(entry.path())?;
            }
        }
        Ok(())
    }

    /// Pin the `items` of `kind` ([`LAYER`], [`IMAGE`]): what the owner
    /// uses, so that no collection or prune takes it.  The caller checks
    /// that the item is still there.
    pub fn pin<I: std::fmt::Display>(
        &self,
        kind: &str,
        items: impl IntoIterator<Item = I>,
    ) -> io::Result<()> {
        pin(&self.dir, kind, items)
    }
}

/// [`Hold::pin`] to the hold in the directory `dir` of the caller's own
/// (a build pins the images it uses in its own hold).
pub fn pin<I: std::fmt::Display>(
    dir: &Path,
    kind: &str,
    items: impl IntoIterator<Item = I>,
) -> io::Result<()> {
    let mut lines = String::new();
    for item in items {
        lines.push_str(&format!("{kind} {item}\n"));
    }
    if lines.is_empty() {
        return Ok(());
    }
    // (one write: a reader sees whole lines)
    OpenOptions::new()
        .append(true)
        .open(dir.join(PINS))?
        .write_all(lines.as_bytes())
}

/// The last user to let go of a hold removes its directory (see the
/// module): under the gate it unlocks its own lock, tries to lock the hold
/// exclusive without waiting and renames it to a dead name; the removal
/// follows the gate.  Refused: another user is left, which removes it when
/// it lets go.
impl Drop for Hold {
    fn drop(&mut self) {
        let Some(lock) = self.lock.take() else {
            return;
        };
        match self.let_go(lock) {
            // (a staging area that is gone has no hold to remove)
            Err(e) if e.kind() != io::ErrorKind::NotFound => {
                tracing::warn!("Cannot remove the hold {:?}: {}", self.dir, e);
            }
            _ => {}
        }
    }
}

impl Hold {
    fn let_go(&self, lock: Held) -> io::Result<()> {
        let Some(staging) = self.dir.parent() else {
            return Ok(());
        };
        let gate = gate(staging, true)?;
        drop(lock);
        let Probe::Stale(nobody_else) = probe_under_gate(&self.dir)? else {
            return Ok(());
        };
        let dead = staging.join(format!("{BORN}{}", velarx_base::random::uuid()));
        fs::rename(&self.dir, &dead)?;
        drop(gate);
        // (the exclusive lock is kept to the end: the sweep skips it)
        let removed = velarx_base::tree::remove_dir_all(&dead);
        drop(nobody_else);
        removed
    }
}

/// The gate of the staging area `staging`: a lock on the directory, locked
/// `exclusive` or shared, waiting; held for the length of one probe or one
/// letting go.
fn gate(staging: &Path, exclusive: bool) -> io::Result<Held> {
    let file = open_dir(staging)?;
    flock_retrying(
        &file,
        if exclusive {
            rustix::fs::FlockOperation::LockExclusive
        } else {
            rustix::fs::FlockOperation::LockShared
        },
    )?;
    Ok(Held::new(file))
}

/// What a look at a hold finds.
#[derive(Debug)]
pub enum Probe {
    /// The directory is not there
    Gone,
    /// A process holds it, or the lock cannot be tested
    Live,
    /// Nobody holds it: the lock is ours (exclusive) until it is dropped
    Stale(Held),
}

/// Whether the hold `dir` is live, without waiting: its lock tried exclusive
/// under the gate shared, so that the instant a last user is letting go of it
/// is not seen.
pub fn probe(dir: &Path) -> io::Result<Probe> {
    let Some(staging) = dir.parent() else {
        return Ok(Probe::Gone);
    };
    let _gate = match gate(staging, false) {
        Ok(gate) => gate,
        // (no staging directory: no holds)
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Probe::Gone),
        Err(e) => return Err(e),
    };
    probe_under_gate(dir)
}

/// [`probe`] by the caller that holds the gate.
fn probe_under_gate(dir: &Path) -> io::Result<Probe> {
    let file = match open_dir(dir) {
        Ok(file) => file,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Probe::Gone),
        Err(_) => return Ok(Probe::Live),
    };
    Ok(
        match flock_retrying(&file, rustix::fs::FlockOperation::NonBlockingLockExclusive) {
            Ok(()) => Probe::Stale(Held::new(file)),
            Err(_) => Probe::Live,
        },
    )
}

/// The directories of `staging` that are holds (by the name), and the ones
/// being made.
/// A staging directory that is not there has none; one that cannot be read
/// is an error, not an empty list: nothing a live pull uses is taken for
/// garbage because a look failed.
fn directories(staging: &Path, born: bool) -> io::Result<Vec<PathBuf>> {
    let entries = match fs::read_dir(staging) {
        Ok(entries) => entries,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };
    let mut found = Vec::new();
    for entry in entries {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if if born {
            name.starts_with(BORN)
        } else {
            is_hold_name(&name)
        } {
            found.push(entry.path());
        }
    }
    Ok(found)
}

/// The holds of `staging` that nobody holds: what a process that died left.
/// Each is probed and let go.
pub fn stale(staging: &Path) -> io::Result<Vec<PathBuf>> {
    let mut found = Vec::new();
    for dir in directories(staging, false)? {
        if matches!(probe(&dir)?, Probe::Stale(_)) {
            found.push(dir);
        }
    }
    Ok(found)
}

/// Whether some process holds a hold of `staging`.
pub fn any_live(staging: &Path) -> io::Result<bool> {
    for dir in directories(staging, false)? {
        if matches!(probe(&dir)?, Probe::Live) {
            return Ok(true);
        }
    }
    Ok(false)
}

/// What the live holds of a store pin.
#[derive(Debug, Default)]
pub struct Pinned {
    pub layers: HashSet<String>,
    pub images: HashSet<String>,
}

/// What the holds of `staging` that a process holds pin.  Only a hold that
/// ended meanwhile (no `pins`) pins nothing: a `pins` that cannot be read is
/// an error.  Each line is appended whole by one write, and the caller of
/// [`pin`] goes on only when it returned: a last line that is not whole is
/// being written (not pinned yet), or was left by a process that died (its
/// hold is not live).
pub fn pinned(staging: &Path) -> io::Result<Pinned> {
    let mut pinned = Pinned::default();
    for dir in directories(staging, false)? {
        if !matches!(probe(&dir)?, Probe::Live) {
            continue;
        }
        let pins = match fs::read_to_string(dir.join(PINS)) {
            Ok(pins) => pins,
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e),
        };
        for line in pins.split_inclusive('\n').filter(|l| l.ends_with('\n')) {
            match line.trim_end().split_once(' ') {
                Some((LAYER, key)) => pinned.layers.insert(key.to_string()),
                Some((IMAGE, id)) => pinned.images.insert(id.to_string()),
                _ => false,
            };
        }
    }
    Ok(pinned)
}

/// Remove the hold `dir` if nobody holds it, under the lock the probe took:
/// whether it was removed.
pub fn remove_stale(dir: &Path) -> io::Result<bool> {
    match probe(dir)? {
        Probe::Stale(_lock) => match velarx_base::tree::remove_dir_all(dir) {
            Ok(()) => Ok(true),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e),
        },
        Probe::Gone | Probe::Live => Ok(false),
    }
}

/// Remove the holds of `staging` nobody holds and the ones whose birth did
/// not end (a process that died, or one that is about to find its directory
/// gone and make another): how many.  A failure is reported, and the others
/// are removed.
pub fn sweep(staging: &Path) -> (usize, Vec<io::Error>) {
    let (mut removed, mut errors) = (0, Vec::new());
    let mut found = Vec::new();
    for born in [false, true] {
        match directories(staging, born) {
            Ok(dirs) => found.extend(dirs),
            Err(e) => errors.push(e),
        }
    }
    for dir in found {
        match remove_stale(&dir) {
            Ok(true) => removed += 1,
            Ok(false) => {}
            Err(e) => errors.push(e),
        }
    }
    (removed, errors)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A program that is killed when the test ends, however it ends.
    struct Program(std::process::Child);

    impl Drop for Program {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    fn staging() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

    #[test]
    fn names_of_holds() {
        assert!(is_hold_name("pull-0123abcd"));
        assert!(is_hold_name(&new_name("build")));
        assert!(!is_hold_name("pulls"));
        assert!(!is_hold_name("pull-"));
        assert!(!is_hold_name("pull-../x"));
        assert!(!is_hold_name(".new-0123"));
    }

    /// A hold is live while it exists, shows nothing of its birth, and its
    /// pins are read.
    #[test]
    fn a_hold_is_live_and_pins() {
        let dir = staging();
        let hold = Hold::create(dir.path(), "pull-aa").unwrap();
        assert_eq!(hold.path(), dir.path().join("pull-aa"));
        assert_eq!(
            fs::read_dir(dir.path()).unwrap().count(),
            1,
            "no temporary name is left"
        );
        assert!(matches!(probe(hold.path()).unwrap(), Probe::Live));
        assert!(any_live(dir.path()).unwrap());
        assert!(stale(dir.path()).unwrap().is_empty());
        hold.pin(LAYER, ["sha256:1", "sha256:2"]).unwrap();
        hold.pin(IMAGE, ["abc"]).unwrap();
        let pinned = pinned(dir.path()).unwrap();
        assert_eq!(pinned.layers.len(), 2);
        assert!(pinned.layers.contains("sha256:2"));
        assert!(pinned.images.contains("abc"));
    }

    /// A hold of the same name is refused, and not replaced.
    #[test]
    fn a_name_is_made_once() {
        let dir = staging();
        let _hold = Hold::create(dir.path(), "pull-aa").unwrap();
        assert!(Hold::create(dir.path(), "pull-aa").is_err());
    }

    /// The directory goes with the last user of the hold, and no pins of it
    /// are read after.
    #[test]
    fn a_dropped_hold_is_gone() {
        let dir = staging();
        let hold = Hold::create(dir.path(), "pull-aa").unwrap();
        hold.pin(LAYER, ["sha256:1"]).unwrap();
        let path = hold.path().to_path_buf();
        drop(hold);
        assert!(!path.exists());
        assert!(matches!(probe(&path).unwrap(), Probe::Gone));
        assert!(pinned(dir.path()).unwrap().layers.is_empty());
    }

    /// A joiner is live as the owner is, and does not remove the directory;
    /// the hold stays live while one of the two lives.
    #[test]
    fn a_joined_hold_is_held_by_both() {
        let dir = staging();
        let owner = Hold::create(dir.path(), "pull-aa").unwrap();
        let joined = Hold::join(dir.path(), "pull-aa").unwrap();
        joined.pin(LAYER, ["sha256:9"]).unwrap();
        drop(joined);
        assert!(owner.path().exists());
        assert!(matches!(probe(owner.path()).unwrap(), Probe::Live));
        assert!(pinned(dir.path()).unwrap().layers.contains("sha256:9"));
        assert!(Hold::join(dir.path(), "pull-bb").is_err());
        // (the owner ends first: the pins stay for the one that is left)
        let joined = Hold::join(dir.path(), "pull-aa").unwrap();
        fs::write(owner.path().join("work"), "x").unwrap();
        owner.clear().unwrap();
        let path = owner.path().to_path_buf();
        drop(owner);
        assert!(path.join(PINS).exists() && !path.join("work").exists());
        assert!(pinned(dir.path()).unwrap().layers.contains("sha256:9"));
        drop(joined);
        assert!(!path.exists());
    }

    /// A hold nobody holds is stale, its pins are of no account, and the
    /// removal takes it away; one a process holds is not removed.
    #[test]
    fn a_hold_nobody_holds_is_removed() {
        let dir = staging();
        let live = Hold::create(dir.path(), "pull-aa").unwrap();
        // (what a process that died leaves: the directory, locked by no one)
        let dead = dir.path().join("pull-bb");
        fs::create_dir_all(&dead).unwrap();
        fs::write(dead.join(PINS), "layer sha256:dead\n").unwrap();
        fs::write(dead.join("file"), "x").unwrap();
        assert_eq!(stale(dir.path()).unwrap(), std::slice::from_ref(&dead));
        assert!(!pinned(dir.path()).unwrap().layers.contains("sha256:dead"));
        assert!(!remove_stale(live.path()).unwrap());
        assert!(remove_stale(&dead).unwrap());
        assert!(!dead.exists() && live.path().exists());
        assert!(!remove_stale(&dead).unwrap());
    }

    /// The sweep takes what nobody holds, the holds and the births that did
    /// not end, and leaves the live ones and other names.
    #[test]
    fn a_sweep_leaves_the_live_and_the_others() {
        let dir = staging();
        let live = Hold::create(dir.path(), "build-aa").unwrap();
        for d in ["pull-0dead", "build-0dead", ".new-0dead", "pulls", "boot"] {
            fs::create_dir_all(dir.path().join(d).join("sub")).unwrap();
        }
        let (removed, errors) = sweep(dir.path());
        assert!(errors.is_empty());
        assert_eq!(removed, 3);
        assert!(live.path().exists());
        assert!(dir.path().join("pulls").exists() && dir.path().join("boot").exists());
    }

    /// A process that died holds nothing: its hold is stale at once, and
    /// one that lives is live (shared by any number, never exclusive).
    #[test]
    fn the_hold_of_a_killed_process_is_stale() {
        let dir = staging();
        let hold = dir.path().join("pull-cc");
        fs::create_dir_all(&hold).unwrap();
        let mut child = std::process::Command::new("sh")
            .arg("-c")
            .arg("exec 9<\"$1\" && flock -s 9 && echo locked && exec sleep 1000")
            .arg("sh")
            .arg(&hold)
            .stdout(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let mut line = String::new();
        std::io::BufRead::read_line(
            &mut std::io::BufReader::new(child.stdout.take().unwrap()),
            &mut line,
        )
        .unwrap();
        assert_eq!(line, "locked\n");
        let mut child = Program(child);
        assert!(matches!(probe(&hold).unwrap(), Probe::Live));
        // (a joiner takes it shared next to the child)
        assert!(Hold::join(dir.path(), "pull-cc").is_ok());
        child.0.kill().unwrap();
        child.0.wait().unwrap();
        assert!(matches!(probe(&hold).unwrap(), Probe::Stale(_)));
    }

    /// A program the process starts does not keep its hold alive: the
    /// descriptor is not passed on (`O_CLOEXEC`), so the hold is not live
    /// when the process lets go though the program runs on.
    #[test]
    fn a_program_started_does_not_keep_a_hold() {
        let dir = staging();
        fs::create_dir_all(dir.path().join("pull-ee")).unwrap();
        let hold = Hold::join(dir.path(), "pull-ee").unwrap();
        let monitor = Program(
            std::process::Command::new("sleep")
                .arg("1000")
                .spawn()
                .unwrap(),
        );
        drop(hold);
        // (at once, but for the moment another thread of the test binary that
        // starts a program holds a copy until the program is executed)
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while matches!(probe(&dir.path().join("pull-ee")).unwrap(), Probe::Live) {
            assert!(std::time::Instant::now() < deadline, "still held");
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        drop(monitor);
    }

    /// Whoever is about to make a hold finds its directory gone when a sweep
    /// took it away in the meantime: it makes another, and ends with one.
    #[test]
    fn a_birth_is_not_swept_from_under_its_owner() {
        let dir = staging();
        let stop = std::sync::atomic::AtomicBool::new(false);
        std::thread::scope(|s| {
            s.spawn(|| {
                while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                    sweep(dir.path());
                }
            });
            for i in 0..300 {
                let hold = Hold::create(dir.path(), &format!("pull-{i:04x}")).unwrap();
                hold.pin(LAYER, ["sha256:1"]).unwrap();
                assert!(hold.path().join(PINS).exists());
                // (a sweep never takes a hold its owner holds)
                std::thread::sleep(std::time::Duration::from_micros(200));
                assert!(hold.path().join(PINS).exists());
            }
            stop.store(true, std::sync::atomic::Ordering::Relaxed);
        });
    }

    /// Whether this process may read what the mode forbids (the tests of
    /// what cannot be read need a user that cannot).
    fn is_root() -> bool {
        rustix::process::geteuid().is_root()
    }

    /// A `pins` that cannot be read is an error, not a hold that pins
    /// nothing: the collection that asks stops.
    #[test]
    fn pins_that_cannot_be_read_are_an_error() {
        if is_root() {
            return;
        }
        use std::os::unix::fs::PermissionsExt;
        let dir = staging();
        let hold = Hold::create(dir.path(), "pull-aa").unwrap();
        hold.pin(LAYER, ["sha256:1"]).unwrap();
        let pins = hold.path().join(PINS);
        fs::set_permissions(&pins, fs::Permissions::from_mode(0o000)).unwrap();
        assert!(pinned(dir.path()).is_err());
        fs::set_permissions(&pins, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(pinned(dir.path()).unwrap().layers.contains("sha256:1"));
        // (a hold that went has no pins: nothing)
        fs::remove_file(&pins).unwrap();
        assert!(pinned(dir.path()).unwrap().layers.is_empty());
    }

    /// A staging directory that cannot be read is an error for every
    /// question, and one that is not there has no holds.
    #[test]
    fn a_staging_directory_that_cannot_be_read_is_an_error() {
        use std::os::unix::fs::PermissionsExt;
        let dir = staging();
        assert!(pinned(&dir.path().join("none")).unwrap().layers.is_empty());
        assert!(!any_live(&dir.path().join("none")).unwrap());
        if is_root() {
            return;
        }
        let _hold = Hold::create(dir.path(), "pull-aa").unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o000)).unwrap();
        let (pins, live, stale_list, swept) = (
            pinned(dir.path()),
            any_live(dir.path()),
            stale(dir.path()),
            sweep(dir.path()),
        );
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        assert!(pins.is_err() && live.is_err() && stale_list.is_err());
        assert_eq!(swept.1.len(), 2);
    }

    /// A join that is refused the lock because the last user of the hold is
    /// taking it away makes a hold under a new name; one that is not there
    /// is made as asked.
    #[test]
    fn a_join_refused_makes_a_new_hold() {
        let dir = staging();
        let mine = dir.path().join("pull-aa");
        fs::create_dir_all(&mine).unwrap();
        // (the last user, removing it: the exclusive lock is held)
        let Probe::Stale(removing) = probe(&mine).unwrap() else {
            panic!("not stale")
        };
        let e = Hold::join(dir.path(), "pull-aa").unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::WouldBlock);
        let made = Hold::join_or_create(dir.path(), "pull-aa").unwrap();
        assert_ne!(made.name(), "pull-aa");
        assert!(is_hold_name(made.name()) && made.path().exists());
        drop(removing);
        let absent = Hold::join_or_create(dir.path(), "pull-bb").unwrap();
        assert_eq!(absent.name(), "pull-bb");
    }

    /// A staging directory that is not there has no holds: a look says
    /// "gone", the removal says "not removed".  A gate that cannot be taken
    /// for another reason is an error.
    #[test]
    fn a_staging_directory_that_is_not_there_has_no_holds() {
        use std::os::unix::fs::PermissionsExt;
        let dir = staging();
        let none = dir.path().join("none").join("pull-aa");
        assert!(matches!(probe(&none).unwrap(), Probe::Gone));
        assert!(!remove_stale(&none).unwrap());
        if is_root() {
            return;
        }
        let _hold = Hold::create(dir.path(), "pull-aa").unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o000)).unwrap();
        let (looked, removed) = (
            probe(&dir.path().join("pull-aa")),
            remove_stale(&dir.path().join("pull-aa")),
        );
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        assert!(looked.is_err() && removed.is_err());
    }

    /// A hold that fails to be named is not left under its temporary name.
    #[test]
    fn a_birth_that_fails_leaves_nothing() {
        let dir = staging();
        let _hold = Hold::create(dir.path(), "pull-aa").unwrap();
        assert!(Hold::create(dir.path(), "pull-aa").is_err());
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    /// The directory of a hold is renamed under the gate and removed after
    /// it: while it is being removed (here it cannot be, and stays) its
    /// name is free and it is a dead directory that nobody holds, which the
    /// next sweep takes.
    #[test]
    fn a_hold_is_renamed_before_it_is_removed() {
        use std::os::unix::fs::PermissionsExt;
        if is_root() {
            return;
        }
        let dir = staging();
        let hold = Hold::create(dir.path(), "pull-aa").unwrap();
        let sub = hold.path().join("sub");
        fs::create_dir(&sub).unwrap();
        fs::write(sub.join("file"), "x").unwrap();
        // (a directory whose files cannot be removed: the walk fails)
        fs::set_permissions(&sub, fs::Permissions::from_mode(0o500)).unwrap();
        drop(hold);
        assert!(!dir.path().join("pull-aa").exists());
        let dead = directories(dir.path(), true).unwrap();
        assert_eq!(dead.len(), 1, "the renamed directory is left");
        assert!(dead[0].join("sub").join("file").exists());
        // (the gate is free, and nobody holds the dead directory)
        drop(gate(dir.path(), true).unwrap());
        fs::set_permissions(dead[0].join("sub"), fs::Permissions::from_mode(0o700)).unwrap();
        let (removed, errors) = sweep(dir.path());
        assert!(errors.is_empty() && removed == 1);
        assert!(!dead[0].exists());
    }

    /// A dead directory that a process holds (it died before it finished
    /// the removal, or has not) is left by the sweep; when the process is
    /// gone the sweep removes it.
    #[test]
    fn a_dead_directory_is_swept_when_its_remover_died() {
        let dir = staging();
        let dead = dir.path().join(".new-0dead");
        fs::create_dir_all(dead.join("sub")).unwrap();
        fs::write(dead.join("sub").join("file"), "x").unwrap();
        let mut child = std::process::Command::new("sh")
            .arg("-c")
            .arg("exec 9<\"$1\" && flock -x 9 && echo locked && exec sleep 1000")
            .arg("sh")
            .arg(&dead)
            .stdout(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let mut line = String::new();
        std::io::BufRead::read_line(
            &mut std::io::BufReader::new(child.stdout.take().unwrap()),
            &mut line,
        )
        .unwrap();
        assert_eq!(line, "locked\n");
        let mut child = Program(child);
        assert_eq!(sweep(dir.path()).0, 0);
        assert!(dead.exists());
        child.0.kill().unwrap();
        child.0.wait().unwrap();
        let (removed, errors) = sweep(dir.path());
        assert!(errors.is_empty() && removed == 1);
        assert!(!dead.exists());
    }

    /// Whoever probes while a hold with a large tree is let go never waits
    /// for the removal of the tree: the gate is free for the walk.
    #[test]
    fn a_probe_does_not_wait_for_the_removal_of_a_tree() {
        use std::time::{Duration, Instant};
        let dir = tempfile::tempdir_in("/var/tmp").unwrap();
        let other = Hold::create(dir.path(), "pull-bb").unwrap();
        let hold = Hold::create(dir.path(), "pull-aa").unwrap();
        for d in 0..100 {
            let sub = hold.path().join(format!("d{d}"));
            fs::create_dir(&sub).unwrap();
            for f in 0..500 {
                fs::write(sub.join(format!("f{f}")), "").unwrap();
            }
        }
        let (removal, waited) = std::thread::scope(|s| {
            let prober = s.spawn(|| {
                let mut longest = Duration::ZERO;
                // (while the removal runs: its dead directory is there)
                while directories(dir.path(), true).unwrap().is_empty() {
                    std::hint::spin_loop();
                }
                while !directories(dir.path(), true).unwrap().is_empty() {
                    let at = Instant::now();
                    assert!(matches!(probe(other.path()).unwrap(), Probe::Live));
                    longest = longest.max(at.elapsed());
                }
                longest
            });
            let at = Instant::now();
            drop(hold);
            (at.elapsed(), prober.join().unwrap())
        });
        assert!(
            waited * 4 < removal,
            "a probe waited {waited:?} of a removal of {removal:?}"
        );
    }

    /// A join that races with the last user's letting go either gets the
    /// hold (and the directory is there while it has it) or is refused, and
    /// never works in a directory that is being removed.
    #[test]
    fn a_join_racing_the_last_user_never_works_in_a_removed_directory() {
        let dir = staging();
        for _ in 0..2000 {
            let owner = Hold::create(dir.path(), "pull-aa").unwrap();
            let barrier = std::sync::Barrier::new(2);
            let joined = std::thread::scope(|s| {
                let joiner = s.spawn(|| {
                    barrier.wait();
                    Hold::join(dir.path(), "pull-aa")
                });
                barrier.wait();
                drop(owner);
                joiner.join().unwrap()
            });
            match joined {
                Ok(joined) => {
                    assert!(joined.path().join(PINS).exists(), "a joined hold is gone");
                    drop(joined);
                }
                Err(e) => assert!(
                    matches!(
                        e.kind(),
                        io::ErrorKind::NotFound | io::ErrorKind::WouldBlock
                    ),
                    "{e}"
                ),
            }
            assert!(!dir.path().join("pull-aa").exists());
            assert!(directories(dir.path(), true).unwrap().is_empty());
        }
    }
}
