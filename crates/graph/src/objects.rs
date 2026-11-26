// SPDX-License-Identifier: Apache-2.0
//! What the drivers that keep the objects of the pull share: the tar stream
//! of a layer read back from them, the scan of the objects of the `FileStore`
//! (the ones no row names, the temporary files), their usage, and the number
//! and size of the files below a directory.

use crate::{
    Collected, DriverError, DriverResult, Leftovers, ObjectRange, ObjectSink, Problem, ProblemKind,
    Remedy,
};
use std::collections::HashSet;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use velarx_content::layer::reproduce::StoredLayer;
use velarx_db::{Database, LayerKey};
use velarx_storage::Object;
use velarx_storage::{FileStore, Toc};
use velarx_types::digest::Algorithm;

/// A problem of the file `path` that making the artifacts again mends.
pub fn problem(kind: ProblemKind, path: &Path, message: impl Into<String>) -> Problem {
    Problem {
        kind,
        message: message.into(),
        layer: None,
        path: Some(path.to_path_buf()),
        repair: true,
    }
}

/// A directory opened for reading without following a link at its end.
pub fn open_dir(path: &Path) -> std::io::Result<rustix::fd::OwnedFd> {
    rustix::fs::open(
        path,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(std::io::Error::from)
}

/// The collection of a directory of files one driver owns: every file of
/// `dir` for which `known` (given its name) is false is removed, with
/// `label` (what it is, for the log) and its size counted in the result.  A
/// name that starts with a dot is a writer's temporary file: `temporary`
/// decides what becomes of it (it may be abandoned or still written to).
pub fn sweep(
    dir: &Path,
    known: impl Fn(&std::ffi::OsStr) -> bool,
    label: &str,
    mut temporary: impl FnMut(&Path, &mut Collected),
) -> Collected {
    let mut out = Collected::default();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return out;
    };
    for e in entries.flatten() {
        let name = e.file_name();
        if name.as_encoded_bytes().starts_with(b".") {
            temporary(&e.path(), &mut out);
            continue;
        }
        if known(&name) {
            continue;
        }
        let size = e.metadata().map_or(0, |m| m.len());
        match std::fs::remove_file(e.path()) {
            Ok(()) => {
                tracing::debug!("Removed the {label} {}", e.path().display());
                out.bytes_freed += size;
            }
            Err(err) => out
                .errors
                .push(format!("Failed to remove {}: {err}", e.path().display())),
        }
    }
    out
}

/// How long ago the path last changed.
pub fn idle(path: &Path) -> Option<Duration> {
    let m = std::fs::symlink_metadata(path).ok()?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_secs() as i64;
    Some(Duration::from_secs(
        now.saturating_sub(m.ctime()).max(0) as u64
    ))
}

/// A name that is the one of an object: `xx` and the 62 digits (SHA-256) or
/// 126 (SHA-512).
pub fn is_hex(s: &str, len: usize) -> bool {
    s.len() == len && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Walk the objects of a store: the temporary files (`.tmp*`) whose writer is
/// gone, the other files that are not objects and are old enough to be
/// leftovers (with why), and the objects whose digest is not in `recorded`
/// and are old enough.  A temporary file is judged by its lock
/// ([`velarx_storage::create_locked`]), however old it is.
pub fn objects(
    objects: &Path,
    recorded: &HashSet<String>,
    grace: Duration,
) -> std::io::Result<Leftovers> {
    let old = |p: &Path| idle(p).is_some_and(|d| d >= grace);
    let mut stray = Vec::new();
    let mut orphans = Vec::new();
    if let Ok(top) = std::fs::read_dir(objects) {
        for entry in top.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            let path = entry.path();
            let Ok(ft) = entry.file_type() else { continue };
            if !ft.is_dir() || !is_hex(&name, 2) {
                if ft.is_file() && old(&path) {
                    stray.push((path, "a file in the objects that is not an object".into()));
                }
                continue;
            }
            for f in std::fs::read_dir(&path)?.flatten() {
                let fname = f.file_name().to_string_lossy().into_owned();
                let fpath = f.path();
                let Ok(ft) = f.file_type() else { continue };
                if !ft.is_file() {
                    continue;
                }
                // (an object of either algorithm: the digits say which, and the
                // two are recorded apart even for the same content)
                let object = is_hex(&fname, 62) || is_hex(&fname, 126);
                match Object::from_rel(Path::new(&format!("{name}/{fname}"))) {
                    Some(o) if object => {
                        if !recorded.contains(&o.verity) && old(&fpath) {
                            orphans.push(fpath);
                        }
                    }
                    _ => {
                        let gone = if fname.starts_with(".tmp") {
                            velarx_storage::is_abandoned(&fpath)?
                        } else {
                            old(&fpath)
                        };
                        if gone {
                            stray.push((fpath, "a temporary file in the objects".into()));
                        }
                    }
                }
            }
        }
    }
    stray.sort();
    orphans.sort();
    Ok(Leftovers { stray, orphans })
}

/// The number of files under `dir` (not following links) and their size.
pub fn files_usage(dir: &Path) -> (u64, u64) {
    velarx_base::tree::usage(
        dir,
        &velarx_base::tree::Measure {
            listed_depth: Some(8),
            lenient: true,
            ..Default::default()
        },
    )
    .map_or((0, 0), |u| (u.files, u.file_bytes))
}

/// The layer `key` as the tar stream of its diff id (in `alg`'s), read back
/// from the tar-split of the database and the objects of the store.  A layer
/// that is not there is `Missing` with the remedy of pulling again.
pub async fn open_layer(
    driver: &str,
    db: &Database,
    key: &LayerKey,
    alg: Option<Algorithm>,
) -> DriverResult<StoredLayer> {
    StoredLayer::load_as(db, key, alg)
        .await
        .map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => {
                DriverError::missing(driver, Some(key), e, Remedy::PullAgain)
            }
            _ => DriverError::io(driver, e),
        })
}

/// [`open_layer`] for the layer of an image, whose configuration gives the
/// diff id `expected`: a layer of a table of contents that no recreation of
/// its stream has checked has none of its own, and its stream is checked
/// against this one when it is read or hashed.
pub async fn open_layer_expecting(
    driver: &str,
    db: &Database,
    key: &LayerKey,
    expected: &velarx_types::digest::Digest,
) -> DriverResult<StoredLayer> {
    StoredLayer::load_expecting(db, key, Some(expected.alg()), Some(expected))
        .await
        .map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => {
                DriverError::missing(driver, Some(key), e, Remedy::PullAgain)
            }
            _ => DriverError::io(driver, e),
        })
}

/// The tables of contents of `layers` as the engine's records have them: what
/// a driver that keeps its layers in the engine's database makes the
/// artifacts of the layers again from ([`crate::StorageDriver::repair`]).
pub async fn tocs_of(
    driver: &str,
    db: &Database,
    layers: &[crate::LayerRef],
) -> DriverResult<Vec<(LayerKey, Toc)>> {
    let mut out = Vec::with_capacity(layers.len());
    for l in layers {
        let toc = velarx_content::pull::stored::stored_toc(db, &l.key)
            .await
            .map_err(|e| DriverError::refused(driver, e))?
            .ok_or_else(|| {
                DriverError::missing(
                    driver,
                    Some(&l.key),
                    format!("the layer {} has no table of contents", l.key),
                    Remedy::PullAgain,
                )
            })?;
        out.push((l.key, toc));
    }
    Ok(out)
}

/// The owners of the files of the layers (uids, gids), as the engine's records
/// of the layers say.
pub fn image_owners(layers: &[velarx_db::LayerRecord]) -> (Vec<u32>, Vec<u32>) {
    let mut uids = std::collections::BTreeSet::new();
    let mut gids = std::collections::BTreeSet::new();
    for l in layers {
        if let Some((u, g)) = l
            .owners
            .as_deref()
            .and_then(velarx_fuse::composefs::parse_owners)
        {
            uids.extend(u);
            gids.extend(g);
        }
    }
    (uids.into_iter().collect(), gids.into_iter().collect())
}

/// Which of `layers` a driver that keeps its layers in the engine's database
/// has (see [`crate::StorageDriver::has_layers`]): one answer for each layer
/// asked, in order, true for a layer that has a row proven against the diff id
/// asked, with its tar-split.  One batched query that reads no table of
/// contents and no bytes.
pub async fn has_layers(
    driver: &str,
    db: &Database,
    layers: &[crate::LayerRef],
) -> DriverResult<Vec<bool>> {
    let keys: Vec<LayerKey> = layers.iter().map(|l| l.key).collect();
    let states = db
        .get_own_layer_states(&keys)
        .await
        .map_err(|e| DriverError::io(driver, std::io::Error::other(e.to_string())))?;
    let states: std::collections::HashMap<&LayerKey, &_> =
        states.iter().map(|s| (&s.key, s)).collect();
    Ok(layers
        .iter()
        .map(|l| {
            states
                .get(&l.key)
                .is_some_and(|s| s.is_stored_as(&l.diff_id))
        })
        .collect())
}

/// The objects of the store and of the read-only image stores under it that
/// exist.
pub fn objects_dirs(store: &Arc<FileStore>) -> Vec<std::path::PathBuf> {
    std::iter::once(store.root().to_path_buf())
        .chain(store.additional().iter().filter(|d| d.is_dir()).cloned())
        .collect()
}

/// The (files, bytes) of the objects of the store.
pub fn content_usage(store: &FileStore) -> (u64, u64) {
    files_usage(store.root())
}

/// How much of an object is read at a time by [`read_objects`].
const READ_PIECE: usize = 256 * 1024;

/// The size of the object `range` names, after it is seen that the range lies
/// within it (`Corrupt` with `PullAgain` else): what a service tells in the
/// reply of a range of `ReadObjects`.
pub fn range_object_size(driver: &str, store: &FileStore, r: &ObjectRange) -> DriverResult<u64> {
    let len = open_key(driver, store, &r.key)?
        .metadata()
        .map_err(|e| DriverError::io(driver, e))?
        .len();
    if r.offset.checked_add(r.length).is_none_or(|end| end > len) {
        return Err(DriverError::corrupt(
            driver,
            format!(
                "the object {} has {len} bytes, the range is {} bytes from {}",
                r.key, r.length, r.offset
            ),
            Remedy::PullAgain,
        ));
    }
    Ok(len)
}

/// The object `key` opened from the descriptor of the directory of the store
/// that has it (`FileStore::open_object`: a name that stays below the objects
/// and has no symbolic link, a regular file, never waited on).
fn open_key(driver: &str, store: &FileStore, key: &str) -> DriverResult<std::fs::File> {
    match store.open_object(key) {
        Some(Ok(file)) => Ok(file),
        // (a name that is not a regular file, or that is a symbolic link or
        // crosses a mount: not what the store wrote there)
        Some(Err(e))
            if e.kind() == std::io::ErrorKind::Other
                || matches!(e.raw_os_error(), Some(libc::ELOOP | libc::EXDEV)) =>
        {
            Err(DriverError::corrupt(driver, e, Remedy::PullAgain))
        }
        Some(Err(e)) => Err(DriverError::io(driver, e)),
        None if Object::new(key, false).is_none() => Err(DriverError::missing(
            driver,
            None,
            format!("`{}` is no key of an object", printable(key)),
            Remedy::PullAgain,
        )),
        None => Err(DriverError::missing(
            driver,
            None,
            format!("the object {key} is not in the store"),
            Remedy::PullAgain,
        )),
    }
}

/// The key as a message may show it: nothing a terminal could act on.
fn printable(key: &str) -> String {
    key.chars()
        .take(80)
        .map(|c| if c.is_control() { '?' } else { c })
        .collect()
}

/// The object `key` of `size` bytes, opened as `open_key` does and its size
/// checked: what the file-based drivers answer `StorageDriver::open_object`
/// with.
pub fn open_object(
    driver: &str,
    store: &FileStore,
    key: &str,
    size: u64,
) -> DriverResult<std::fs::File> {
    let file = open_key(driver, store, key)?;
    let len = file
        .metadata()
        .map_err(|e| DriverError::io(driver, e))?
        .len();
    if len != size {
        return Err(DriverError::corrupt(
            driver,
            format!("the object {key} has {len} bytes, its index says {size}"),
            Remedy::PullAgain,
        ));
    }
    Ok(file)
}

/// `StorageDriver::read_objects` of the drivers that keep the objects in a
/// `FileStore`: each range is read from the object opened as `open_object`
/// does, with `pread`, in pieces of 256 KiB from one buffer.
pub fn read_objects(
    driver: &str,
    store: &FileStore,
    ranges: &[ObjectRange],
    sink: &mut dyn ObjectSink,
) -> DriverResult<()> {
    use std::os::unix::fs::FileExt;
    let mut buf: Vec<u8> = Vec::new();
    for (i, r) in ranges.iter().enumerate() {
        let file = open_key(driver, store, &r.key)?;
        let len = file
            .metadata()
            .map_err(|e| DriverError::io(driver, e))?
            .len();
        let end = r.offset.checked_add(r.length).filter(|end| *end <= len);
        let Some(end) = end else {
            return Err(DriverError::corrupt(
                driver,
                format!(
                    "the object {} has {len} bytes, the range is {} bytes from {}",
                    r.key, r.length, r.offset
                ),
                Remedy::PullAgain,
            ));
        };
        let mut at = r.offset;
        while at < end {
            let n = ((end - at) as usize).min(READ_PIECE);
            buf.resize(n, 0);
            let got = file
                .read_at(&mut buf, at)
                .map_err(|e| DriverError::io(driver, e))?;
            if got == 0 {
                return Err(DriverError::corrupt(
                    driver,
                    format!(
                        "the object {} ended at {at}, the range ends at {end}",
                        r.key
                    ),
                    Remedy::PullAgain,
                ));
            }
            sink.data(i, &buf[..got])
                .map_err(|e| DriverError::io(driver, e))?;
            at += got as u64;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_files_usage_counts_the_files_to_a_depth_and_follows_no_link() {
        let tmp = tempfile::tempdir().unwrap();
        let mut d = tmp.path().to_path_buf();
        for i in 0..10 {
            std::fs::write(d.join("f"), vec![0u8; 3]).unwrap();
            if i == 0 {
                std::os::unix::fs::symlink("/", d.join("l")).unwrap();
            }
            d.push("d");
            std::fs::create_dir(&d).unwrap();
        }
        // (the files of the directories at depth 0 to 8)
        assert_eq!(files_usage(tmp.path()), (9, 27));
        assert_eq!(files_usage(&tmp.path().join("nothing")), (0, 0));
    }

    use super::*;
    use crate::DriverErrorKind;

    /// A temporary file is a leftover when its writer is gone, not when it
    /// is old: one whose lock is held is not named, whatever the grace, and
    /// the one of a writer that ended is named at once.
    #[test]
    fn a_temporary_file_is_judged_by_its_lock() {
        velarx_base::testing::in_child(|| {
            let dir = tempfile::tempdir().unwrap();
            let sub = dir.path().join("ab");
            std::fs::create_dir(&sub).unwrap();
            let (temp, lock) = velarx_storage::create_locked(&sub, ".tmp", 0o644).unwrap();
            let path = temp.path().to_path_buf();
            let none = HashSet::new();
            let day = Duration::from_secs(86400);
            let found = objects(dir.path(), &none, Duration::ZERO).unwrap();
            assert!(found.stray.is_empty(), "{found:?}");
            drop(lock);
            // (old or young: the grace does not matter)
            let found = objects(dir.path(), &none, day).unwrap();
            assert_eq!(found.stray.len(), 1, "{found:?}");
            assert_eq!(found.stray[0].0, path);
        });
    }

    /// The sweep keeps the known files, hands a dot-temporary one to the
    /// driver whatever its name, and removes and counts the rest; a missing
    /// directory is nothing to collect.
    #[test]
    fn the_sweep_keeps_the_known_files_and_leaves_the_temporary_ones_to_the_driver() {
        let dir = tempfile::tempdir().unwrap();
        for (name, len) in [("kept", 1), ("gone", 3), (".writing", 5), (".kept", 7)] {
            std::fs::write(dir.path().join(name), vec![0u8; len]).unwrap();
        }
        let mut handed = Vec::new();
        let out = sweep(
            dir.path(),
            |n| n == "kept" || n == ".kept",
            "file",
            |p, _| handed.push(p.file_name().unwrap().to_owned()),
        );
        assert_eq!(out.bytes_freed, 3);
        assert!(out.errors.is_empty(), "{:?}", out.errors);
        handed.sort();
        assert_eq!(handed, [".kept", ".writing"]);
        assert!(dir.path().join("kept").exists());
        assert!(!dir.path().join("gone").exists());
        assert!(dir.path().join(".writing").exists());
        let none = sweep(&dir.path().join("none"), |_| false, "file", |_, _| {});
        assert_eq!((none.bytes_freed, none.errors.len()), (0, 0));
    }

    /// What the store has under the name of an object and that the store did
    /// not write there (a symbolic link, even to the right bytes, a FIFO,
    /// which is not waited on, a directory) is `Corrupt`, and nothing of it
    /// is read.
    #[test]
    fn what_is_not_an_object_file_is_corrupt_and_not_read() {
        let dir = tempfile::tempdir().unwrap();
        let store = FileStore::new(dir.path().join("objects")).unwrap();
        let outside = dir.path().join("outside");
        std::fs::write(&outside, b"hello").unwrap();
        let replace = |key: &str, make: &dyn Fn(&Path)| {
            let path = store.local_path(key).unwrap();
            let _ = std::fs::remove_file(&path);
            make(&path);
        };
        let key = store.put(Algorithm::Sha256, b"hello").unwrap();
        let ok = open_object("t", &store, &key, 5).unwrap();
        assert_eq!(ok.metadata().unwrap().len(), 5);
        let link = |p: &Path| std::os::unix::fs::symlink(&outside, p).unwrap();
        let fifo =
            |p: &Path| rustix::fs::mkfifoat(rustix::fs::CWD, p, rustix::fs::Mode::RUSR).unwrap();
        let directory = |p: &Path| std::fs::create_dir(p).unwrap();
        for (what, make) in [
            ("a link", &link as &dyn Fn(&Path)),
            ("a FIFO", &fifo),
            ("a directory", &directory),
        ] {
            replace(&key, make);
            let e = open_object("t", &store, &key, 5).unwrap_err();
            assert!(
                matches!(e.kind, DriverErrorKind::Corrupt { .. }),
                "{what}: {e:?}"
            );
            let mut got = Vec::new();
            let e = read_objects(
                "t",
                &store,
                &[ObjectRange::whole(&key, 5)],
                &mut |_: usize, b: &[u8]| {
                    got.extend_from_slice(b);
                    Ok(())
                },
            )
            .unwrap_err();
            assert!(
                matches!(e.kind, DriverErrorKind::Corrupt { .. }),
                "{what}: {e:?}"
            );
            assert!(got.is_empty(), "{what}");
            let path = store.local_path(&key).unwrap();
            let _ = std::fs::remove_dir(&path);
        }
    }
}
