// SPDX-License-Identifier: Apache-2.0
//! The startup profile of an image: the files its containers look up in
//! their first seconds, in the order they did.
//!
//! The first time a lazily pulled image runs, the file system of the
//! container notes the files that are looked up (a short list of digests,
//! bounded in number and in time) and saves it next to the record of the
//! image.  The next container of the image fetches those files first, in
//! that order, so that its reads find them.  Later runs add the files that
//! were not in the list yet.
//!
//! The list is only an order: the digests are checked against the files of
//! the image before they are used, and each file is fetched and verified as
//! any other.  A list that is wrong, or made by somebody else, costs a
//! different order of fetching, nothing more.
//!
//! A profile that turned out poor is recorded again: when most of the files
//! a run looked up were not in it, or most of it was not looked up, the
//! run's own list replaces it instead of being added to it.  That happens at
//! most [`MAX_RERECORDS`] times for an image (the count is in the file), and
//! only for a run that looked up [`MIN_SAMPLE`] files or more, so that two
//! kinds of runs of one image do not keep replacing each other's.

use std::collections::HashSet;
use std::io::Write;
use std::os::fd::AsFd;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::Duration;
use tracing::debug;

/// The most a profile file may weigh when it is read.
const MAX_BYTES: u64 = 2 * 1024 * 1024;

/// The times a profile is replaced by a run's own list, at most.
pub const MAX_RERECORDS: u32 = 3;
/// The files a run must have looked up for its list to judge the profile.
pub const MIN_SAMPLE: usize = 8;

#[derive(serde::Serialize, serde::Deserialize)]
struct Document {
    v: u32,
    files: Vec<String>,
    /// The times it was recorded again because it was poor
    #[serde(default, skip_serializing_if = "is_zero")]
    rerecorded: u32,
}

fn is_zero(n: &u32) -> bool {
    *n == 0
}

/// The name of an object of the store: `fsverity-sha256-12:` and 64
/// lowercase hexadecimal digits, or `fsverity-sha512-12:` and 128.
fn is_digest(s: &str) -> bool {
    velarx_storage::Object::new(s, false).is_some()
}

/// Where a profile is kept: a path, or a name in a directory that is held
/// open (`In`), which is read and written through that descriptor only: the
/// path of the directory is never looked up again, so what a path names
/// meanwhile changes nothing.
#[derive(Clone, Debug)]
pub enum Place {
    Path(PathBuf),
    In(Arc<std::os::fd::OwnedFd>, String),
}

impl From<PathBuf> for Place {
    fn from(path: PathBuf) -> Self {
        Self::Path(path)
    }
}

impl Place {
    /// The file `name` of the directory `dir`: a single plain name.
    pub fn in_dir(dir: Arc<std::os::fd::OwnedFd>, name: &str) -> std::io::Result<Self> {
        if name.is_empty() || name == "." || name == ".." || name.contains(['/', '\0']) {
            return Err(std::io::Error::other(format!(
                "{name:?} is not the name of a file"
            )));
        }
        Ok(Self::In(dir, name.to_string()))
    }

    fn display(&self) -> String {
        match self {
            Self::Path(p) => p.display().to_string(),
            Self::In(_, name) => name.clone(),
        }
    }

    fn open(&self) -> std::io::Result<std::fs::File> {
        match self {
            Self::Path(p) => std::fs::File::open(p),
            Self::In(dir, name) => Ok(rustix::fs::openat(
                dir.as_fd(),
                name,
                rustix::fs::OFlags::RDONLY
                    | rustix::fs::OFlags::NOFOLLOW
                    | rustix::fs::OFlags::NONBLOCK
                    | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::empty(),
            )?
            .into()),
        }
    }

    /// The bytes of the profile, if it is one that may be read.
    pub fn read_bytes(&self) -> Option<Vec<u8>> {
        read_from(&self.open().ok()?)
    }

    /// The digests of the profile, at most `max` (`read`).
    pub fn read(&self, max: usize) -> Vec<String> {
        read_document(self, max).0
    }

    /// Write `data` as the profile where there is none: the file is made
    /// complete under a name of its own first, and does not replace one that
    /// is there.
    pub fn keep_if_absent(&self, data: &[u8]) -> std::io::Result<()> {
        if self.read_bytes().is_some() {
            return Ok(());
        }
        write_bytes(self, data)
    }
}

/// The digests of a profile file, at most `max`, each once, in order.  A
/// missing, unreadable, oversized or malformed file is an empty profile, and
/// so is an entry that is not a digest.
pub fn read(path: &Path, max: usize) -> Vec<String> {
    read_document(&Place::Path(path.to_path_buf()), max).0
}

/// The bytes of an open profile file, if it is one that may be read.
pub fn read_from(file: &std::fs::File) -> Option<Vec<u8>> {
    let mut text = Vec::new();
    if std::io::Read::read_to_end(&mut std::io::Read::take(file, MAX_BYTES + 1), &mut text).is_err()
        || text.len() as u64 > MAX_BYTES
    {
        return None;
    }
    Some(text)
}

/// The digests of a profile and the times it was recorded again.
fn read_document(place: &Place, max: usize) -> (Vec<String>, u32) {
    match place.read_bytes() {
        Some(text) => parse_document(&text, max),
        None => (Vec::new(), 0),
    }
}

/// The digests of the profile `text` (as a profile file holds it, or a
/// peer sent it), at most `max`, each once, in order.  What is not a
/// profile is an empty one, an entry that is not a digest is dropped.
pub fn parse(text: &[u8], max: usize) -> Vec<String> {
    parse_document(text, max).0
}

fn parse_document(text: &[u8], max: usize) -> (Vec<String>, u32) {
    if text.len() as u64 > MAX_BYTES {
        return (Vec::new(), 0);
    }
    let Ok(doc) = serde_json::from_slice::<Document>(text) else {
        return (Vec::new(), 0);
    };
    if doc.v != 1 {
        return (Vec::new(), 0);
    }
    let mut seen = HashSet::new();
    let files = doc
        .files
        .into_iter()
        .filter(|d| is_digest(d))
        .filter(|d| seen.insert(d.clone()))
        .take(max)
        .collect();
    (files, doc.rerecorded)
}

/// Whether the profile `old` served the run that looked up `noted` poorly:
/// most of what the run looked up was not in it, or most of it was not
/// looked up.  A run that looked up few files does not judge.
pub fn poor(old: &[String], noted: &[String]) -> bool {
    if old.is_empty() || noted.len() < MIN_SAMPLE {
        return false;
    }
    let known: HashSet<&str> = old.iter().map(String::as_str).collect();
    let hits = noted.iter().filter(|d| known.contains(d.as_str())).count();
    let missed = noted.len() - hits;
    let unused = old.len().saturating_sub(hits);
    missed * 2 > noted.len() || unused * 2 > old.len()
}

/// Write the profile next to its image, all or nothing.  The temporary
/// file is locked until it has its name: the collection of the store does
/// not take it for a dead writer's.
fn write(place: &Place, files: &[String], rerecorded: u32) -> std::io::Result<()> {
    let text = serde_json::to_vec(&Document {
        v: 1,
        files: files.to_vec(),
        rerecorded,
    })
    .map_err(std::io::Error::other)?;
    write_bytes(place, &text)
}

/// `text` as the file of `place`, all or nothing: through `openat` and
/// `renameat` of the descriptor of the directory for `Place::In`, so the
/// file made and the name it gets are in that directory and nowhere else.
fn write_bytes(place: &Place, text: &[u8]) -> std::io::Result<()> {
    match place {
        Place::Path(path) => {
            let dir = path.parent().unwrap_or(Path::new("."));
            let (mut temp, _lock) = velarx_storage::create_locked(dir, ".profile-", 0o644)?;
            temp.write_all(text)?;
            temp.as_file().sync_all()?;
            temp.persist(path).map_err(|e| e.error)?;
        }
        Place::In(dir, name) => {
            let (mut file, temp, _lock) =
                velarx_storage::create_locked_at(dir.as_fd(), ".profile-", 0o644)?;
            let done = file
                .write_all(text)
                .and_then(|()| file.sync_all())
                .and_then(|()| {
                    rustix::fs::renameat(dir.as_fd(), &temp, dir.as_fd(), name).map_err(Into::into)
                });
            if done.is_err() {
                let _ = rustix::fs::unlinkat(dir.as_fd(), &temp, rustix::fs::AtFlags::empty());
            }
            done?;
        }
    }
    Ok(())
}

/// The files looked up, in the order they were first.
#[derive(Default)]
struct Seen {
    set: HashSet<String>,
    order: Vec<String>,
}

/// The lookups of one container, noted for a while.
pub struct Recording {
    place: Place,
    max: usize,
    seen: Mutex<Seen>,
    saved: AtomicBool,
    /// Dropped to wake the thread that saves the profile when the time is up.
    stop: Mutex<Option<mpsc::Sender<()>>>,
    /// The thread that saves the profile when the time is up.
    saver: Mutex<Option<std::thread::JoinHandle<()>>>,
}

impl Recording {
    /// Note the lookups for `window`, at most `max` files, then save them
    /// to `path` (also when the container ends before).
    pub fn start(place: impl Into<Place>, window: Duration, max: usize) -> Arc<Self> {
        let (tx, rx) = mpsc::channel::<()>();
        let this = Arc::new(Self {
            place: place.into(),
            max,
            seen: Mutex::default(),
            saved: AtomicBool::new(false),
            stop: Mutex::new(Some(tx)),
            saver: Mutex::new(None),
        });
        let saver = this.clone();
        let spawned = std::thread::Builder::new()
            .name("profile".into())
            .spawn(move || {
                // (a timeout, or the sender gone: the container ended)
                let _ = rx.recv_timeout(window);
                saver.save();
            });
        match spawned {
            Ok(thread) => *this.saver.lock().unwrap_or_else(|e| e.into_inner()) = Some(thread),
            Err(_) => this.saved.store(true, Ordering::SeqCst),
        }
        this
    }

    /// The container ended: wake the thread that saves the profile and wait
    /// until it has, so that the file is written by the thread that was made
    /// for it (a process that confined the thread that calls this cannot
    /// write it itself, and may exit right after).
    pub fn finish(&self) {
        self.stop.lock().unwrap_or_else(|e| e.into_inner()).take();
        let saver = self.saver.lock().unwrap_or_else(|e| e.into_inner()).take();
        if let Some(thread) = saver {
            let _ = thread.join();
        }
    }

    /// A file of the image was looked up.  Nothing is kept once the profile
    /// is full or saved.
    pub fn note(&self, digest: &str) {
        if self.saved.load(Ordering::Relaxed) {
            return;
        }
        let mut seen = self.seen.lock().unwrap_or_else(|e| e.into_inner());
        if seen.order.len() >= self.max || !is_digest(digest) || seen.set.contains(digest) {
            return;
        }
        seen.set.insert(digest.to_string());
        seen.order.push(digest.to_string());
    }

    /// Save what was noted, once: after the profile that is there, with the
    /// files it did not have; in its place when it was poor (bounded).
    pub fn save(&self) {
        if self.saved.swap(true, Ordering::SeqCst) {
            return;
        }
        self.stop.lock().unwrap_or_else(|e| e.into_inner()).take();
        let noted = std::mem::take(&mut self.seen.lock().unwrap_or_else(|e| e.into_inner()).order);
        if noted.is_empty() {
            return;
        }
        let (mut files, rerecorded) = read_document(&self.place, self.max);
        let rerecorded = if rerecorded < MAX_RERECORDS && poor(&files, &noted) {
            debug!(
                "The startup profile {} was poor for this run: recorded again",
                self.place.display()
            );
            files = noted;
            rerecorded + 1
        } else {
            let known: HashSet<String> = files.iter().cloned().collect();
            let before = files.len();
            files.extend(noted.into_iter().filter(|d| !known.contains(d)));
            files.truncate(self.max);
            if files.len() == before {
                return;
            }
            rerecorded
        };
        match write(&self.place, &files, rerecorded) {
            Ok(()) => debug!(
                "Saved the startup profile of {} files in {}",
                files.len(),
                self.place.display()
            ),
            Err(e) => debug!("Cannot save {}: {e}", self.place.display()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d(n: u32) -> String {
        format!("fsverity-sha256-12:{n:064x}")
    }

    fn dir() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

    #[test]
    fn what_is_looked_up_is_saved_in_order_and_read_back() {
        let t = dir();
        let path = t.path().join("p.json");
        let r = Recording::start(path.clone(), Duration::from_secs(3600), 100);
        for n in [3, 1, 3, 2, 1] {
            r.note(&d(n));
        }
        r.save();
        assert_eq!(read(&path, 100), [d(3), d(1), d(2)]);
        // nothing is noted or saved after that
        r.note(&d(9));
        r.save();
        assert_eq!(read(&path, 100), [d(3), d(1), d(2)]);
        assert_eq!(
            std::fs::read_dir(t.path()).unwrap().count(),
            1,
            "no temporary"
        );
    }

    #[test]
    fn the_time_up_saves_it_without_anybody_asking() {
        let t = dir();
        let path = t.path().join("p.json");
        let r = Recording::start(path.clone(), Duration::from_millis(20), 100);
        r.note(&d(1));
        assert!(
            velarx_base::testing::wait_file(&path, Duration::from_secs(10), |_| true).is_some(),
            "not saved"
        );
        assert_eq!(read(&path, 100), [d(1)]);
        // later lookups are not kept
        r.note(&d(2));
        assert_eq!(read(&path, 100), [d(1)]);
    }

    #[test]
    fn the_end_of_the_container_saves_it_at_once() {
        let t = dir();
        let path = t.path().join("p.json");
        let r = Recording::start(path.clone(), Duration::from_secs(3600), 100);
        r.note(&d(1));
        r.save();
        assert_eq!(read(&path, 100), [d(1)]);
    }

    #[test]
    fn a_later_run_adds_what_the_profile_lacked() {
        let t = dir();
        let path = t.path().join("p.json");
        let first = Recording::start(path.clone(), Duration::from_secs(3600), 100);
        first.note(&d(1));
        first.note(&d(2));
        first.save();
        let second = Recording::start(path.clone(), Duration::from_secs(3600), 100);
        for n in [2, 5, 1, 6] {
            second.note(&d(n));
        }
        second.save();
        assert_eq!(read(&path, 100), [d(1), d(2), d(5), d(6)]);
    }

    fn record(path: &Path, files: impl IntoIterator<Item = u32>) {
        let r = Recording::start(path.to_path_buf(), Duration::from_secs(3600), 100);
        for n in files {
            r.note(&d(n));
        }
        r.save();
    }

    #[test]
    fn a_poor_profile_is_recorded_again_a_bounded_number_of_times() {
        let t = dir();
        let path = t.path().join("p.json");
        // a first run that read 0..10
        record(&path, 0..10);
        // a run that reads 100..110: nothing of it was in the profile
        record(&path, 100..110);
        assert_eq!(read(&path, 100), (100..110).map(d).collect::<Vec<_>>());
        // a run that the profile serves well (and a bit more) adds to it
        record(&path, (100..110).chain([7]));
        assert_eq!(read(&path, 100).len(), 11);
        // the two kinds of runs, one after the other: replaced twice more,
        // then only added to
        record(&path, 200..220);
        record(&path, 300..320);
        assert_eq!(
            read_document(&Place::Path(path.clone()), 100).1,
            MAX_RERECORDS
        );
        assert_eq!(read(&path, 100), (300..320).map(d).collect::<Vec<_>>());
        record(&path, 400..420);
        let files = read(&path, 100);
        assert_eq!(files.len(), 40, "added, not replaced");
        assert_eq!(files[..20], (300..320).map(d).collect::<Vec<_>>());
    }

    #[test]
    fn what_is_poor_is_judged_on_enough_lookups() {
        let ds = |r: std::ops::Range<u32>| r.map(d).collect::<Vec<_>>();
        // most of the run was not in it
        assert!(poor(&ds(0..10), &ds(5..20)));
        // most of it was not looked up
        assert!(poor(&ds(0..40), &ds(0..10)));
        // it served the run
        assert!(!poor(&ds(0..10), &ds(0..12)));
        // too few lookups to judge, or nothing to judge
        assert!(!poor(&ds(0..10), &ds(50..53)));
        assert!(!poor(&[], &ds(0..20)));
    }

    #[test]
    fn a_profile_from_elsewhere_is_parsed_as_a_file() {
        let text = serde_json::json!({"v": 1, "files": [d(1), "x", d(1), d(2)], "rerecorded": 2});
        assert_eq!(parse(text.to_string().as_bytes(), 10), [d(1), d(2)]);
        assert_eq!(parse(text.to_string().as_bytes(), 1), [d(1)]);
        assert!(parse(b"garbage", 10).is_empty());
        assert!(parse(&vec![b' '; MAX_BYTES as usize + 1], 10).is_empty());
    }

    #[test]
    fn the_profile_is_bounded() {
        let t = dir();
        let path = t.path().join("p.json");
        let r = Recording::start(path.clone(), Duration::from_secs(3600), 3);
        for n in 0..50 {
            r.note(&d(n));
        }
        r.save();
        assert_eq!(read(&path, 100), [d(0), d(1), d(2)]);
        assert_eq!(read(&path, 2), [d(0), d(1)]);
    }

    #[test]
    fn a_hostile_profile_is_an_empty_or_a_clean_one() {
        let t = dir();
        let path = t.path().join("p.json");
        let w = |text: &[u8]| std::fs::write(&path, text).unwrap();
        assert!(read(&t.path().join("none"), 10).is_empty());
        for bad in [
            &b"not json"[..],
            b"{}",
            b"[]",
            b"{\"v\":2,\"files\":[]}",
            b"{\"v\":1,\"files\":\"fsverity-sha256-12:\"}",
            b"{\"v\":1,\"files\":[1,2]}",
            b"\xff\xfe",
        ] {
            w(bad);
            assert!(
                read(&path, 10).is_empty(),
                "{:?}",
                String::from_utf8_lossy(bad)
            );
        }
        // entries that are not digests are dropped, the others kept once
        let text = serde_json::json!({"v": 1, "files": [
            d(1), "../../etc/passwd", "sha256:ABC", format!("sha256:{}", "A".repeat(64)),
            d(1), "", "sha256:", format!("{}/x", d(2)), d(2),
            // an OCI digest names no object, and nor does the wrong length
            format!("sha256:{}", "a".repeat(64)), format!("fsverity-sha512-12:{}", "a".repeat(64)),
            format!("fsverity-sha512-12:{}", "a".repeat(128))
        ]});
        w(text.to_string().as_bytes());
        assert_eq!(
            read(&path, 10),
            [
                d(1),
                d(2),
                format!("fsverity-sha512-12:{}", "a".repeat(128))
            ]
        );
        // too big a file is not read at all
        let big = format!(
            "{{\"v\":1,\"files\":[\"{}\"]}}",
            "x".repeat(MAX_BYTES as usize)
        );
        w(big.as_bytes());
        assert!(read(&path, 10).is_empty());
        // a directory in its place
        std::fs::remove_file(&path).unwrap();
        std::fs::create_dir(&path).unwrap();
        assert!(read(&path, 10).is_empty());
    }

    #[test]
    fn a_lookup_that_is_not_a_digest_is_not_noted() {
        let t = dir();
        let path = t.path().join("p.json");
        let r = Recording::start(path.clone(), Duration::from_secs(3600), 10);
        r.note("");
        r.note("fsverity-sha256-12:xyz");
        r.save();
        assert!(!path.exists());
    }

    #[test]
    fn an_unwritable_place_is_not_an_error() {
        let r = Recording::start(
            PathBuf::from("/does/not/exist/p.json"),
            Duration::from_secs(3600),
            10,
        );
        r.note(&d(1));
        r.save();
    }

    fn held(path: &Path) -> Arc<std::os::fd::OwnedFd> {
        Arc::new(
            rustix::fs::open(
                path,
                rustix::fs::OFlags::PATH | rustix::fs::OFlags::DIRECTORY,
                rustix::fs::Mode::empty(),
            )
            .unwrap(),
        )
    }

    #[test]
    fn a_name_that_is_not_one_file_makes_no_place() {
        let t = dir();
        for name in ["", ".", "..", "a/b", "../x", "/etc/passwd", "a\0b"] {
            assert!(Place::in_dir(held(t.path()), name).is_err(), "{name:?}");
        }
        assert!(Place::in_dir(held(t.path()), "abc.profile.json").is_ok());
    }

    /// The profile of a place in a held directory goes to that directory,
    /// whatever the path of the directory names afterwards, and the name is
    /// replaced when it is a link, never followed.
    #[test]
    fn a_profile_is_written_through_the_directory_that_was_opened() {
        let t = dir();
        let (own, away, other) = (
            t.path().join("own"),
            t.path().join("away"),
            t.path().join("other"),
        );
        std::fs::create_dir(&own).unwrap();
        std::fs::create_dir(&other).unwrap();
        let place = Place::in_dir(held(&own), "p.json").unwrap();
        std::fs::rename(&own, &away).unwrap();
        std::os::unix::fs::symlink(&other, &own).unwrap();
        let victim = other.join("victim");
        let mine = format!(r#"{{"v":1,"files":["{}"]}}"#, d(7));
        std::fs::write(&victim, &mine).unwrap();
        std::os::unix::fs::symlink(&victim, away.join("p.json")).unwrap();
        let r = Recording::start(place.clone(), Duration::from_secs(3600), 100);
        r.note(&d(1));
        r.save();
        assert_eq!(std::fs::read(&victim).unwrap(), mine.as_bytes());
        assert_eq!(std::fs::read_dir(&other).unwrap().count(), 1);
        // (what the link leads to is not read into the profile either)
        assert_eq!(place.read(100), [d(1)]);
        assert_eq!(read(&away.join("p.json"), 100), [d(1)]);
        let names: Vec<_> = std::fs::read_dir(&away).unwrap().collect();
        assert_eq!(names.len(), 1, "no temporary");
    }

    /// The end of the container saves the profile by the thread that was made
    /// for it, and waits for it (a process that confined the thread that
    /// calls cannot write it, and may exit right after): the file is there
    /// when `finish` returns, long before the window is over.
    #[test]
    fn the_end_of_a_run_saves_the_profile_before_it_returns() {
        let t = dir();
        let place = Place::in_dir(held(t.path()), "p.json").unwrap();
        let r = Recording::start(place, Duration::from_secs(3600), 100);
        r.note(&d(1));
        r.note(&d(2));
        let begun = std::time::Instant::now();
        r.finish();
        assert!(begun.elapsed() < Duration::from_secs(60));
        assert_eq!(read(&t.path().join("p.json"), 100), [d(1), d(2)]);
        // (once only: nothing is saved twice)
        r.note(&d(3));
        r.finish();
        r.save();
        assert_eq!(read(&t.path().join("p.json"), 100), [d(1), d(2)]);
    }

    #[test]
    fn a_profile_of_the_peers_is_kept_only_where_there_is_none() {
        let t = dir();
        let place = Place::in_dir(held(t.path()), "p.json").unwrap();
        place.keep_if_absent(br#"{"v":1,"files":[]}"#).unwrap();
        let first = std::fs::read(t.path().join("p.json")).unwrap();
        place
            .keep_if_absent(format!(r#"{{"v":1,"files":["{}"]}}"#, d(1)).as_bytes())
            .unwrap();
        // (an empty list is a profile that is there: it is not replaced)
        assert_eq!(std::fs::read(t.path().join("p.json")).unwrap(), first);
        assert_eq!(std::fs::read_dir(t.path()).unwrap().count(), 1);
    }
}
