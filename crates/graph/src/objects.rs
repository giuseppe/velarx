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
use std::time::Duration;
use velarx_content::layer::reproduce::StoredLayer;
use velarx_db::{Database, LayerKey};
use velarx_storage::{ChunkFile, FileStore, Object, Toc};
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
/// exist: the data-only layers of an overlay.
pub fn objects_dirs(store: &FileStore) -> Vec<std::path::PathBuf> {
    let mut dirs = stores(store);
    dirs.retain(|d| d == store.root() || d.is_dir());
    dirs
}

/// The objects of the store and of every read-only image store, whether
/// they exist or not: where the files and the layer images of each store
/// are looked for (a store whose layers hold every file has no objects).
pub fn stores(store: &FileStore) -> Vec<std::path::PathBuf> {
    std::iter::once(store.root().to_path_buf())
        .chain(store.additional().iter().cloned())
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
        Some(Err(e)) => Err(open_error(driver, e)),
        None => Err(not_found(driver, key)),
    }
}

/// What failed in opening an object: a name that is not a regular file, or
/// that is a symbolic link or crosses a mount, is not what the store wrote
/// there.
fn open_error(driver: &str, e: std::io::Error) -> DriverError {
    if e.kind() == std::io::ErrorKind::Other
        || matches!(e.raw_os_error(), Some(libc::ELOOP | libc::EXDEV))
    {
        DriverError::corrupt(driver, e, Remedy::PullAgain)
    } else {
        DriverError::io(driver, e)
    }
}

fn not_found(driver: &str, key: &str) -> DriverError {
    if Object::new(key, false).is_none() {
        DriverError::missing(
            driver,
            None,
            format!("`{}` is no key of an object", printable(key)),
            Remedy::PullAgain,
        )
    } else {
        DriverError::missing(
            driver,
            None,
            format!("the object {key} is not in the store"),
            Remedy::PullAgain,
        )
    }
}

/// The content of a file as a store holds it.
pub enum Content {
    /// The object, whole.
    Object(std::fs::File),
    /// The extent of the EROFS image of a layer that holds the file
    /// (`layers.inline`), checked to lie in the image.
    Extent(ChunkFile),
}

impl Content {
    /// The bytes of the file as a range of a file: the object whole, or the
    /// extent of the image.
    pub fn range(self, driver: &str) -> DriverResult<ChunkFile> {
        match self {
            Content::Extent(extent) => Ok(extent),
            Content::Object(file) => {
                let len = file
                    .metadata()
                    .map_err(|e| DriverError::io(driver, e))?
                    .len();
                Ok(ChunkFile {
                    file,
                    offset: 0,
                    len,
                })
            }
        }
    }
}

/// The content of the file `key`, store by store (this one, then the
/// read-only ones, in their order): the first store that has it answers, with
/// its object if it has one, else with the extent of an image it holds.  The
/// answer is `Missing` when no store has it.
pub fn find_content(
    driver: &str,
    db: &Database,
    store: &FileStore,
    key: &str,
) -> DriverResult<Content> {
    if Object::new(key, false).is_none() {
        return Err(not_found(driver, key));
    }
    for root in stores(store) {
        match FileStore::open_in(&root, key) {
            Some(Ok(file)) => return Ok(Content::Object(file)),
            Some(Err(e)) => return Err(open_error(driver, e)),
            None => {}
        }
        if let Some(extent) = extent_in(driver, db, &root, key)? {
            return Ok(Content::Extent(extent));
        }
    }
    Err(not_found(driver, key))
}

/// The extent of the file `key` in the EROFS image of the layer that holds it
/// in the store whose objects are `objects`: the image is that layer's in
/// that store, whatever other stores have under its id.  The extent lies in
/// the image, which is `Corrupt` else.
pub fn extent_in(
    driver: &str,
    db: &Database,
    objects: &Path,
    key: &str,
) -> DriverResult<Option<ChunkFile>> {
    let found = crate::blocking(|| futures::executor::block_on(db.inlined_file_in(objects, key)))
        .map_err(|e| DriverError::storage(driver, format!("the file {key}: {e}")))?;
    let Some((layer, file)) = found else {
        return Ok(None);
    };
    let path = velarx_fuse::composefs::layer_image_path(objects, &layer.file_stem());
    let image = velarx_fuse::composefs::open_layer_image(&path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            DriverError::missing(
                driver,
                Some(&layer),
                format!("the image of the layer that holds the file {key} is not there"),
                Remedy::PullAgain,
            )
        } else {
            DriverError::io(driver, e)
        }
    })?;
    let len = image
        .metadata()
        .map_err(|e| DriverError::io(driver, e))?
        .len();
    if file
        .offset
        .checked_add(file.size)
        .is_none_or(|end| end > len)
    {
        return Err(DriverError::corrupt(
            driver,
            format!(
                "the file {key} is {} bytes from {} of the image of layer {layer}, which has {len} bytes",
                file.size, file.offset
            ),
            Remedy::PullAgain,
        ));
    }
    Ok(Some(ChunkFile {
        file: image,
        offset: file.offset,
        len: file.size,
    }))
}

/// The key as a message may show it: nothing a terminal could act on.
fn printable(key: &str) -> String {
    key.chars()
        .take(80)
        .map(|c| if c.is_control() { '?' } else { c })
        .collect()
}

/// The file `key` of `size` bytes as a regular file, what the file-based
/// drivers answer `StorageDriver::open_object` with: the object, opened as
/// [`find_content`] does and its size checked, else a copy of the extent of the
/// EROFS image that holds the file, as an unnamed file of `staging`.
pub fn open_object(
    driver: &str,
    db: &Database,
    store: &FileStore,
    staging: &Path,
    key: &str,
    size: u64,
) -> DriverResult<std::fs::File> {
    let sized = |held: u64| {
        if held == size {
            return Ok(());
        }
        Err(DriverError::corrupt(
            driver,
            format!("the file {key} has {held} bytes, its index says {size}"),
            Remedy::PullAgain,
        ))
    };
    match find_content(driver, db, store, key)? {
        Content::Object(file) => {
            sized(
                file.metadata()
                    .map_err(|e| DriverError::io(driver, e))?
                    .len(),
            )?;
            Ok(file)
        }
        Content::Extent(held) => {
            sized(held.len)?;
            let copy = velarx_content::pull::unnamed::unnamed_file(staging)
                .map_err(|e| DriverError::io(driver, e))?;
            velarx_storage::copy_region(&held.file, held.offset, &copy, 0, size, || Ok(()))
                .map_err(|e| DriverError::io(driver, e))?;
            Ok(copy)
        }
    }
}

/// `StorageDriver::read_objects` of the drivers that keep the objects in a
/// `FileStore`: each range is read from the content of the file ([`find_content`]:
/// an object, or an extent of the EROFS image of a layer) with `pread`, in
/// pieces of 256 KiB from one buffer.
pub fn read_objects(
    driver: &str,
    db: &Database,
    store: &FileStore,
    ranges: &[ObjectRange],
    sink: &mut dyn ObjectSink,
) -> DriverResult<()> {
    use std::os::unix::fs::FileExt;
    let mut buf: Vec<u8> = Vec::new();
    for (i, r) in ranges.iter().enumerate() {
        let held = find_content(driver, db, store, &r.key)?.range(driver)?;
        let len = held.len;
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
            let got = held
                .file
                .read_at(&mut buf, held.offset + at)
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
    #[tokio::test]
    async fn what_is_not_an_object_file_is_corrupt_and_not_read() {
        let db = Database::open_in_memory().await.unwrap();
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
        let ok = open_object("t", &db, &store, dir.path(), &key, 5).unwrap();
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
            let e = open_object("t", &db, &store, dir.path(), &key, 5).unwrap_err();
            assert!(
                matches!(e.kind, DriverErrorKind::Corrupt { .. }),
                "{what}: {e:?}"
            );
            let mut got = Vec::new();
            let e = read_objects(
                "t",
                &db,
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

    /// The content of a file is found store by store: the first store that
    /// has it answers, with its object before an extent, and an extent is
    /// read from the image of its layer in the store of the row, also when
    /// another store holds the same layer (here at another threshold, so the
    /// files are elsewhere in its image).
    #[tokio::test]
    async fn the_content_is_found_store_by_store_from_the_image_of_its_store() {
        use velarx_db::{InlinedFile, LayerCommit, LayerRecord};
        use velarx_storage::VerityHasher;
        use velarx_types::digest::Digest;
        let dir = tempfile::tempdir().unwrap();
        let sha = |b: &[u8]| Digest::of(Algorithm::Sha256, b);
        let key = |content: &[u8]| {
            let mut h = VerityHasher::new(Algorithm::Sha256);
            h.update(content);
            h.finish()
        };
        let layer = LayerKey::Whole(sha(b"layer"));
        let image = |objects: &Path, held: &[(usize, &[u8])]| {
            let path = velarx_fuse::composefs::layer_image_path(objects, &layer.file_stem());
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            let mut bytes = vec![b'.'; 100];
            for (at, content) in held {
                bytes[*at..at + content.len()].copy_from_slice(content);
            }
            std::fs::write(path, bytes).unwrap();
        };
        let commit = |held: &[(usize, &[u8])]| LayerCommit {
            record: LayerRecord {
                stream_size: Some(0),
                inline: 4096,
                key: layer,
                blob: None,
                diff_id: Some(sha(b"diff")),
                other_diff_id: None,
                size: 1,
                status: "ready".into(),
                created_at: "2026-01-01T00:00:00Z".into(),
                registry_ref: None,
                erofs: Some("sha256:a".into()),
                owners: Some("[]".into()),
            },
            files: vec![],
            refs: vec![],
            chunks: vec![],
            toc_digest: sha(b"toc"),
            tarsplit: None,
            blob_checked: false,
            sealed: false,
            inlined: held
                .iter()
                .map(|(at, content)| InlinedFile {
                    digest: key(content),
                    offset: *at as u64,
                    size: content.len() as u64,
                })
                .collect(),
        };
        let (own, ro) = (dir.path().join("own"), dir.path().join("ro"));
        // (the read-only store has the layer with the files in other places
        // than this store has it)
        let ro_held: &[(usize, &[u8])] = &[(50, b"aaa"), (60, b"bbb"), (70, b"ccc")];
        let own_held: &[(usize, &[u8])] = &[(10, b"aaa"), (20, b"ddd"), (30, b"eee")];
        std::fs::create_dir_all(ro.join("objects")).unwrap();
        {
            let db = Database::open(ro.join("db.sqlite")).await.unwrap();
            db.commit_layers(vec![commit(ro_held)], vec![])
                .await
                .unwrap();
            db.checkpoint().await.unwrap();
        }
        image(&ro.join("objects"), ro_held);
        std::fs::create_dir_all(&own).unwrap();
        let db = Database::open(own.join("db.sqlite")).await.unwrap();
        db.commit_layers(vec![commit(own_held)], vec![])
            .await
            .unwrap();
        image(&own.join("objects"), own_held);
        let db = db.with_additional(vec![Database::open_read_only(&ro.join("db.sqlite"))
            .await
            .unwrap()]);
        let store = FileStore::new(own.join("objects"))
            .unwrap()
            .with_additional(vec![ro.join("objects")]);
        let read = |content: &[u8]| {
            let held = find_content("t", &db, &store, &key(content))?.range("t")?;
            let mut bytes = vec![0; held.len as usize];
            std::os::unix::fs::FileExt::read_exact_at(&held.file, &mut bytes, held.offset).unwrap();
            Ok::<_, DriverError>(bytes)
        };
        // the extent of the layer in this store, not in the other
        assert_eq!(read(b"aaa").unwrap(), b"aaa");
        // a file only the other store has is read from its image of the layer
        assert_eq!(read(b"bbb").unwrap(), b"bbb");
        assert_eq!(read(b"ccc").unwrap(), b"ccc");
        // an extent of this store beats an object of the other
        let theirs = FileStore::new(ro.join("objects")).unwrap();
        theirs.put(Algorithm::Sha256, b"ddd").unwrap();
        assert_eq!(read(b"ddd").unwrap(), b"ddd");
        assert!(matches!(
            find_content("t", &db, &store, &key(b"ddd")).unwrap(),
            Content::Extent(_)
        ));
        // in a store, the object beats the extent
        store.put(Algorithm::Sha256, b"eee").unwrap();
        assert!(matches!(
            find_content("t", &db, &store, &key(b"eee")).unwrap(),
            Content::Object(_)
        ));
        let e = read(b"none").err().unwrap();
        assert!(matches!(e.kind, DriverErrorKind::Missing { .. }), "{e}");
    }
}
