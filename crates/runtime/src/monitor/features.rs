// SPDX-License-Identifier: Apache-2.0
//! What the kernel and the tools of this boot can do, found by trying and
//! kept in the run root.
//!
//! Every feature is a marker file in the `features` directory of the run
//! root, named `<feature>-yes` (supported) or `<feature>-no` (not
//! supported); no file means not probed yet, so the next need probes again.
//! `<feature>` is a lowercase kebab-case description of the capability
//! (`overlay-datadir-every-layer`).  Never both files: a writer removes the
//! other one.  A new boot forgets them all (`forget`).
//!
//! This module is the only code that makes or reads the markers
//! (`tools/check-features`, in `make test-lint`, fails on anything else), and callers
//! never spell the suffix.  To add a feature: call `cached` with its name and
//! a probe, once, where the answer is first needed.

use rustix::fs::{openat, renameat, statat, unlinkat, AtFlags, FileType, Mode, OFlags, CWD};
use std::io::{self, Read, Write};
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

/// The directory of the run root that holds the markers.
const DIR: &str = "features";
const YES: &str = "-yes";
const NO: &str = "-no";

/// The number of the next name aside of this process.
static SEQ: AtomicU64 = AtomicU64::new(0);

/// Whether NAME is a feature name: lowercase words of letters and digits
/// joined by single dashes, not ending in what makes a marker's answer.
fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.split('-').all(|w| {
            !w.is_empty()
                && w.bytes()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        })
        && !name.ends_with(YES)
        && !name.ends_with(NO)
}

/// The directory of the markers of the run root RUN.
fn dir(run: &Path) -> PathBuf {
    run.join(DIR)
}

/// The run root this process keeps the answers about its tools in.
static RUN_ROOT: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();

/// Keep the answers about the tools (the OCI runtime, pasta) in the run root
/// RUN, for the commands that follow in other processes.
pub fn keep_in(run: PathBuf) {
    let _ = RUN_ROOT.set(run);
}

/// The run root of [`keep_in`], if any.
pub fn run_root() -> Option<&'static Path> {
    RUN_ROOT.get().map(PathBuf::as_path)
}

/// The key of the answers about the program at PATH: the file as it is (its
/// device, inode and time: a program replaced in place is asked again).
pub fn file_key(path: &Path) -> Option<String> {
    use std::os::unix::fs::MetadataExt;
    let m = std::fs::metadata(path).ok()?;
    Some(format!(
        "{} {}:{} {}.{}",
        path.display(),
        m.dev(),
        m.ino(),
        m.mtime(),
        m.mtime_nsec()
    ))
}

/// A new boot (or a new kernel) may do otherwise: forget what was found.
pub fn forget(run: &Path) -> io::Result<()> {
    match velarx_base::tree::remove_dir_all(dir(run)) {
        Err(e) if e.kind() != io::ErrorKind::NotFound => Err(e),
        _ => Ok(()),
    }
}

/// The directory DIR itself, not what a link of that name points to.
fn open_dir(dir: &Path) -> io::Result<OwnedFd> {
    Ok(openat(
        CWD,
        dir,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?)
}

/// Whether the marker NAME of the directory DIR is there: a file (not a
/// link, a directory or a fifo, which are not followed or waited for)
/// whose content is KEY, what the answer is about (a program that may
/// change, say); another content is a marker of the past, none.
fn present(dir: &OwnedFd, name: &str, key: &str) -> bool {
    let Ok(fd) = openat(
        dir,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    ) else {
        return false;
    };
    let f = std::fs::File::from(fd);
    let mut content = String::new();
    f.metadata().is_ok_and(|m| m.is_file())
        && (&f)
            .take(key.len() as u64 + 2)
            .read_to_string(&mut content)
            .is_ok()
        && content.strip_suffix('\n') == Some(key)
}

/// The answer kept for FEATURE under the run root RUN, else what PROBE finds,
/// kept.  KEY (empty if the answer holds for the boot) is stored with the
/// answer: an answer stored with another key is stale and is probed again.
/// A probe that finds no answer (`None`) keeps nothing and answers `None`.
/// Both markers (which only a race of different answers leaves) answer
/// "not supported".  Err when the probe fails or the marker cannot be made.
pub fn cached(
    run: &Path,
    feature: &str,
    key: &str,
    probe: impl FnOnce() -> io::Result<Option<bool>>,
) -> io::Result<Option<bool>> {
    if !valid_name(feature) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("`{feature}` is not a feature name"),
        ));
    }
    let dir = dir(run);
    let (yes, no) = (format!("{feature}{YES}"), format!("{feature}{NO}"));
    if let Ok(fd) = open_dir(&dir) {
        match (present(&fd, &yes, key), present(&fd, &no, key)) {
            (true, false) => return Ok(Some(true)),
            (_, true) => return Ok(Some(false)),
            (false, false) => {}
        }
    }
    let Some(answer) = probe()? else {
        return Ok(None);
    };
    let (name, other) = if answer { (yes, no) } else { (no, yes) };
    mark(&dir, &name, &other, key).map_err(|e| {
        io::Error::new(
            e.kind(),
            format!("the runtime directory {}: {e}", dir.display()),
        )
    })?;
    Ok(Some(answer))
}

/// The marker NAME in DIR, whole or not at all: written aside (private, no
/// link followed) and renamed, so that processes that find the answer
/// together leave one file and a reader never sees half of one.  Every step
/// is relative to the directory opened once (no link of its name or of the
/// marker's is followed between the check and the creation).  The
/// directory is private, as the run root.
fn mark(dir: &Path, name: &str, other: &str, key: &str) -> io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)?;
    let fd = open_dir(dir)?;
    match statat(&fd, name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(st) if FileType::from_raw_mode(st.st_mode) != FileType::RegularFile => {
            return Err(io::Error::other(format!(
                "{name} is there and is not a file"
            )));
        }
        _ => {}
    }
    // (a name of this process; one left by a process of the same pid in
    // another namespace, or by one that died, is skipped)
    let (tmp, file) = loop {
        let tmp = format!(
            ".{name}.{}.{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        );
        match openat(
            &fd,
            tmp.as_str(),
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
        ) {
            Ok(f) => break (tmp, std::fs::File::from(f)),
            Err(rustix::io::Errno::EXIST) => continue,
            Err(e) => return Err(e.into()),
        }
    };
    let made = (&file)
        .write_all(format!("{key}\n").as_bytes())
        .and_then(|()| Ok(renameat(&fd, tmp.as_str(), &fd, name)?));
    if made.is_err() {
        let _ = unlinkat(&fd, tmp.as_str(), AtFlags::empty());
    }
    made?;
    // (never both)
    let _ = unlinkat(&fd, other, AtFlags::empty());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    const F: &str = "some-feature";

    fn names(run: &Path) -> Vec<String> {
        let mut v: Vec<_> = std::fs::read_dir(dir(run))
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        v.sort();
        v
    }

    #[test]
    fn the_names_are_kebab_case_without_an_answer() {
        for ok in ["a", "overlay-datadir-every-layer", "pasta-v2", "a1-b2"] {
            assert!(valid_name(ok), "{ok}");
        }
        for bad in [
            "", "-a", "a-", "a--b", "A", "a_b", "a b", "a/b", "x-yes", "x-no", "yes-no", "..",
        ] {
            assert!(!valid_name(bad), "{bad}");
        }
        let tmp = tempfile::tempdir().unwrap();
        let e = cached(tmp.path(), "Bad", "", || panic!("probed")).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::InvalidInput);
        assert!(!dir(tmp.path()).exists());
    }

    #[test]
    fn yes_no_and_not_probed_are_three_states() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let run = tmp.path().join("run");
        let probes = Cell::new(0);
        let ask = |found: Option<bool>| {
            cached(&run, F, "", || {
                probes.set(probes.get() + 1);
                Ok(found)
            })
            .unwrap()
        };
        // no answer: nothing kept, asked again
        assert_eq!(ask(None), None);
        assert!(!dir(&run).exists());
        assert_eq!(ask(None), None);
        assert_eq!(probes.get(), 2);
        // found once, then kept, whatever the probe would say
        assert_eq!(ask(Some(true)), Some(true));
        assert_eq!(ask(Some(false)), Some(true));
        assert_eq!(probes.get(), 3);
        assert_eq!(names(&run), ["some-feature-yes"]);
        let mode = |p: PathBuf| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(dir(&run)), 0o700);
        assert_eq!(mode(dir(&run).join("some-feature-yes")), 0o600);
        // the other answer replaces it: never both
        std::fs::remove_file(dir(&run).join("some-feature-yes")).unwrap();
        assert_eq!(ask(Some(false)), Some(false));
        assert_eq!(ask(Some(true)), Some(false));
        assert_eq!(names(&run), ["some-feature-no"]);
        // a probe that fails is an error and keeps nothing
        std::fs::remove_file(dir(&run).join("some-feature-no")).unwrap();
        let e = cached(&run, F, "", || Err(io::Error::other("boom"))).unwrap_err();
        assert_eq!(e.to_string(), "boom");
        assert!(names(&run).is_empty());
        // forgotten at a new boot
        assert_eq!(ask(Some(true)), Some(true));
        forget(&run).unwrap();
        forget(&run).unwrap();
        assert!(!dir(&run).exists());
    }

    /// Both markers, which only a race of different answers leaves, are
    /// "not supported"; a marker that is not a file is none.
    #[test]
    fn both_markers_answer_no() {
        let tmp = tempfile::tempdir().unwrap();
        let d = dir(tmp.path());
        std::fs::create_dir(&d).unwrap();
        for n in ["some-feature-yes", "some-feature-no"] {
            std::fs::write(d.join(n), "\n").unwrap();
        }
        let a = cached(tmp.path(), F, "", || panic!("probed")).unwrap();
        assert_eq!(a, Some(false));
    }

    /// A link or a directory of the name of a marker is no marker and is
    /// not followed when the marker is made.
    #[test]
    fn a_link_is_no_marker() {
        let tmp = tempfile::tempdir().unwrap();
        let d = dir(tmp.path());
        std::fs::create_dir(&d).unwrap();
        let target = tmp.path().join("elsewhere");
        std::fs::write(&target, "\n").unwrap();
        std::os::unix::fs::symlink(&target, d.join("some-feature-yes")).unwrap();
        std::fs::create_dir(d.join("some-feature-no")).unwrap();
        // (neither answers: the probe is asked, and cannot keep its answer)
        let asked = Cell::new(false);
        let r = cached(tmp.path(), F, "", || {
            asked.set(true);
            Ok(Some(true))
        });
        assert!(asked.get() && r.is_err());
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "\n");
        let r = cached(tmp.path(), F, "", || Ok(Some(false)));
        assert!(r.is_err());
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "\n");
    }

    /// A `features` that is a link is not followed, to read or to write; a
    /// fifo is no marker and is not waited for; a marker that is not whole
    /// (or of another key) is none.
    #[test]
    fn only_a_whole_file_of_the_directory_is_a_marker() {
        let tmp = tempfile::tempdir().unwrap();
        let (run, elsewhere) = (tmp.path().join("run"), tmp.path().join("elsewhere"));
        std::fs::create_dir_all(&run).unwrap();
        std::fs::create_dir(&elsewhere).unwrap();
        std::fs::write(elsewhere.join("some-feature-yes"), "\n").unwrap();
        std::os::unix::fs::symlink(&elsewhere, dir(&run)).unwrap();
        let asked = Cell::new(0);
        let r = cached(&run, F, "", || {
            asked.set(asked.get() + 1);
            Ok(Some(false))
        });
        assert!(r.is_err() && asked.get() == 1, "{r:?}");
        assert_eq!(std::fs::read_dir(&elsewhere).unwrap().count(), 1);
        std::fs::remove_file(dir(&run)).unwrap();
        std::fs::create_dir(dir(&run)).unwrap();
        rustix::fs::mkfifoat(
            CWD,
            dir(&run).join("some-feature-no"),
            Mode::from_raw_mode(0o600),
        )
        .unwrap();
        std::fs::write(dir(&run).join("some-feature-yes"), "").unwrap();
        // (neither answers: the empty one is not whole, the fifo no file)
        let r = cached(&run, F, "", || Ok(Some(true)));
        assert_eq!(r.unwrap(), Some(true));
        std::fs::write(dir(&run).join("some-feature-yes"), "\nmore").unwrap();
        let r = cached(&run, F, "", || Ok(None));
        assert_eq!(r.unwrap(), None);
    }

    /// A name left aside by another process of the same pid (another pid
    /// namespace) is skipped, and nothing but the marker is left.
    #[test]
    fn a_name_aside_that_is_taken_is_skipped() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir(tmp.path())).unwrap();
        let from = SEQ.load(Ordering::Relaxed);
        for seq in from..from + 64 {
            let n = format!(".some-feature-yes.{}.{seq}", std::process::id());
            std::fs::write(dir(tmp.path()).join(n), "").unwrap();
        }
        assert_eq!(
            cached(tmp.path(), F, "", || Ok(Some(true))).unwrap(),
            Some(true)
        );
        let made = names(tmp.path());
        assert_eq!(made.iter().filter(|n| !n.starts_with('.')).count(), 1);
        assert!(made.contains(&"some-feature-yes".to_string()));
        assert_eq!(made.len(), 65, "{made:?}");
    }

    /// Writers of different answers at once leave at most one marker.
    #[test]
    fn concurrent_different_answers_never_leave_both() {
        for _ in 0..20 {
            let tmp = tempfile::tempdir().unwrap();
            let run = tmp.path().to_path_buf();
            let threads: Vec<_> = (0..8)
                .map(|i| {
                    let run = run.clone();
                    std::thread::spawn(move || {
                        cached(&run, F, "", || Ok(Some(i % 2 == 0))).unwrap()
                    })
                })
                .collect();
            for t in threads {
                assert!(t.join().unwrap().is_some());
            }
            assert!(names(&run).len() <= 1, "{:?}", names(&run));
        }
    }

    /// An answer kept for another key is stale: probed again and replaced.
    #[test]
    fn an_answer_of_another_key_is_probed_again() {
        let tmp = tempfile::tempdir().unwrap();
        let ask = |key: &str, found| cached(tmp.path(), F, key, || Ok(Some(found))).unwrap();
        assert_eq!(ask("pasta 1", true), Some(true));
        assert_eq!(ask("pasta 1", false), Some(true));
        assert_eq!(ask("pasta 2", false), Some(false));
        assert_eq!(names(tmp.path()), ["some-feature-no"]);
        assert_eq!(ask("pasta 2", true), Some(false));
    }

    #[test]
    fn concurrent_first_needs_agree() {
        let tmp = tempfile::tempdir().unwrap();
        let run = tmp.path().to_path_buf();
        let threads: Vec<_> = (0..8)
            .map(|_| {
                let run = run.clone();
                std::thread::spawn(move || cached(&run, F, "", || Ok(Some(true))).unwrap())
            })
            .collect();
        for t in threads {
            assert_eq!(t.join().unwrap(), Some(true));
        }
        assert_eq!(names(&run), ["some-feature-yes"]);
    }

    /// A run root that cannot keep the answer is an error that names it.
    #[test]
    fn an_unwritable_run_root_is_an_error() {
        let tmp = tempfile::tempdir().unwrap();
        let blocked = tmp.path().join("run");
        std::fs::write(&blocked, "").unwrap();
        let e = cached(&blocked, F, "", || Ok(Some(true))).unwrap_err();
        assert!(e.to_string().contains("the runtime directory"), "{e}");
    }
}
