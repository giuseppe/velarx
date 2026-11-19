// SPDX-License-Identifier: Apache-2.0
//! The tree of an image as composefs-rs makes it (`composefs-oci`,
//! `image::create_filesystem`), so that the EROFS image of it, and the
//! fs-verity digest of that image, are the ones composefs-rs gives for the
//! same image:
//!
//! * the entries of the layers are applied in order, one at a time, to one
//!   tree (`process_entry`): a whiteout removes the name from the tree as it
//!   is at that point, an opaque marker empties the directory as it is at
//!   that point, a directory over a directory keeps the entries and takes
//!   the new metadata, anything else replaces what was there, and a hard
//!   link is another name of the leaf its target is;
//! * the tree is then made the same for every way of making it
//!   (`transform_for_oci`): the root takes the metadata of `/usr`, `/run` is
//!   emptied, only `security.capability` is kept of the extended attributes;
//! * the regular files are their fs-verity digests (the name of the file in
//!   the objects of the repository), or their content when it has up to 64
//!   bytes.
//!
//! Unlike composefs-rs this does not fail for an entry whose directories are
//! not listed before it (they are made), and does without the changes that
//! need `/usr` when the image has none: its image is not one composefs-rs
//! would make.
//!
//! It deliberately does not follow the rule of the views of an image (the
//! overlay of the images of the layers, `MergedTree`) that a layer has its
//! own root and its own plain directories for those it adds to without
//! listing them: here such a directory keeps what the layers below gave it,
//! as in composefs-rs, so that the digest is the one composefs-rs gives.
//!
//! The image is made only for its digest, the merged EROFS of an image that
//! its manifest states (`composefs.merged.erofs.v1.fsverity-sha256-12`, or
//! `-sha512-12` for an image whose digests are SHA-512): it
//! is not kept, the containers mount the images of the layers.

use composefs::fsverity::FsVerityHashValue;
use composefs::generic_tree::OciTransformOptions;
use composefs::tree::{Directory, FileSystem, Inode, LeafContent, RegularFile, Stat};
use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::io;
use velarx_storage::{TocEntry, TocEntryType};

pub use composefs::INLINE_CONTENT_MAX_V0 as INLINE_MAX;

/// The tree of an image, its regular files by their fs-verity digest (`H`:
/// SHA-256 or SHA-512, the algorithm of the digests of the image).
pub type Tree<H> = FileSystem<H>;

/// The regular file an entry is: its fs-verity digest, and the content of a
/// small one.
pub trait Files<H: FsVerityHashValue> {
    fn regular(&mut self, entry: &TocEntry) -> io::Result<RegularFile<H>>;
}

/// The time of a table of contents entry (RFC 3339) as seconds and
/// nanoseconds; the epoch for none, or before it.
pub(crate) fn unix_time(s: &Option<String>) -> (i64, u32) {
    match velarx_storage::toc_time(s.as_deref()) {
        Some((secs, nsec)) if secs >= 0 => (secs, nsec),
        _ => (0, 0),
    }
}

fn stat_of(e: &TocEntry) -> Stat {
    use base64::Engine;
    let (sec, nsec) = unix_time(&e.mod_time);
    let mut xattrs = BTreeMap::new();
    for (k, v) in &e.xattrs {
        if let Ok(value) = base64::engine::general_purpose::STANDARD.decode(v) {
            xattrs.insert(
                OsString::from(k).into_boxed_os_str(),
                value.into_boxed_slice(),
            );
        }
    }
    Stat {
        st_mode: e.mode & 0o7777,
        st_uid: e.uid,
        st_gid: e.gid,
        st_mtim_sec: sec,
        st_mtim_nsec: nsec,
        xattrs,
    }
}

fn default_dir<H: FsVerityHashValue>() -> Directory<H> {
    Directory::new(Stat {
        st_mode: 0o755,
        st_uid: 0,
        st_gid: 0,
        st_mtim_sec: 0,
        st_mtim_nsec: 0,
        xattrs: BTreeMap::new(),
    })
}

/// The path of an entry as composefs-oci has it: from the root, without a
/// `.` or a trailing slash.
fn path_of(name: &str) -> String {
    let n = name.trim_matches('/');
    let n = n.strip_prefix("./").unwrap_or(n);
    if n == "." {
        String::new()
    } else {
        n.to_string()
    }
}

fn err(path: &str, e: impl std::fmt::Display) -> String {
    format!("`{path}`: {e}")
}

/// Make the directories above `path`, the way an archive extractor does when
/// an entry comes before its directory.
fn make_parents<H: FsVerityHashValue>(fs: &mut Tree<H>, path: &str) -> Result<(), String> {
    let mut prefix = String::new();
    let parts: Vec<&str> = path.split('/').collect();
    for part in &parts[..parts.len() - 1] {
        if !prefix.is_empty() {
            prefix.push('/');
        }
        prefix.push_str(part);
        let (dir, name) = fs
            .root
            .split_mut(OsStr::new(&prefix))
            .map_err(|e| err(&prefix, e))?;
        if dir.lookup(name).is_none() {
            dir.insert(name, Inode::Directory(Box::new(default_dir())));
        }
    }
    Ok(())
}

/// Apply the entries of one layer (`process_entry` for each).
fn apply<H: FsVerityHashValue>(
    fs: &mut Tree<H>,
    entries: &[TocEntry],
    files: &mut dyn Files<H>,
) -> Result<(), String> {
    for e in entries {
        let path = path_of(&e.name);
        if path.is_empty() {
            // the root: its metadata, nothing else
            if e.entry_type != TocEntryType::Dir {
                return Err(err(&e.name, "the root must be a directory"));
            }
            fs.set_root_stat(stat_of(e));
            continue;
        }
        let inode = match e.entry_type {
            TocEntryType::Chunk => continue,
            TocEntryType::Dir => Inode::Directory(Box::new(Directory::new(stat_of(e)))),
            TocEntryType::Hardlink => {
                let target = path_of(e.link_name.as_deref().unwrap_or(""));
                let (dir, name) = fs
                    .root
                    .split(OsStr::new(&target))
                    .map_err(|m| err(&e.name, format!("a hard link to {target}: {m}")))?;
                Inode::leaf(
                    dir.leaf_id(name)
                        .map_err(|m| err(&e.name, format!("a hard link to {target}: {m}")))?,
                )
            }
            kind => {
                let content = match kind {
                    TocEntryType::Symlink => {
                        let Some(target) = &e.link_name else {
                            return Err(err(&e.name, "a symlink with no target"));
                        };
                        LeafContent::Symlink(OsString::from(target.clone()).into_boxed_os_str())
                    }
                    TocEntryType::Char => LeafContent::CharacterDevice(libc::makedev(
                        e.dev_major.unwrap_or(0),
                        e.dev_minor.unwrap_or(0),
                    )),
                    TocEntryType::Block => LeafContent::BlockDevice(libc::makedev(
                        e.dev_major.unwrap_or(0),
                        e.dev_minor.unwrap_or(0),
                    )),
                    TocEntryType::Fifo => LeafContent::Fifo,
                    _ => LeafContent::Regular(files.regular(e).map_err(|m| err(&e.name, m))?),
                };
                Inode::leaf(fs.push_leaf(stat_of(e), content))
            }
        };
        if fs.root.split_mut(OsStr::new(&path)).is_err() {
            make_parents(fs, &path)?;
        }
        let (dir, name) = fs
            .root
            .split_mut(OsStr::new(&path))
            .map_err(|m| err(&e.name, m))?;
        match name.as_encoded_bytes().strip_prefix(b".wh.") {
            Some(b".wh..opq") => dir.clear(),
            Some(target) => dir.remove(OsStr::new(
                std::str::from_utf8(target).map_err(|m| err(&e.name, m))?,
            )),
            None => dir.merge(name, inode),
        }
    }
    Ok(())
}

/// The tree the layers (the entries of each, the lowest layer first) make.
/// `files` gives the regular files.
pub fn merge<H: FsVerityHashValue>(
    layers: &[&[TocEntry]],
    files: &mut dyn Files<H>,
) -> Result<Tree<H>, String> {
    let mut fs = FileSystem::new(Stat::uninitialized());
    for entries in layers {
        apply(&mut fs, entries, files)?;
    }
    let has_usr = fs
        .root
        .get_directory_opt(OsStr::new("usr"))
        .map_err(|e| e.to_string())?
        .is_some();
    if has_usr {
        fs.transform_for_oci(&OciTransformOptions::default())
            .map_err(|e| e.to_string())?;
    } else {
        // (what `transform_for_oci` does without what needs `/usr`)
        fs.filter_xattrs(composefs::generic_tree::is_allowed_container_xattr);
        fs.compact();
    }
    Ok(fs)
}

/// The EROFS image of the tree and its fs-verity digest: the image id of
/// composefs-rs.
pub fn image<H: FsVerityHashValue>(
    fs: Tree<H>,
    version: composefs::erofs::format::FormatVersion,
) -> Result<(Box<[u8]>, H), String> {
    let fs =
        composefs::erofs::writer::ValidatedFileSystem::new(fs).map_err(|e| format!("{e:#}"))?;
    let image = composefs::erofs::writer::mkfs_erofs_versioned(&fs, version);
    let id = composefs::fsverity::compute_verity::<H>(&image);
    Ok((image, id))
}

/// The objects of a store as the tree of composefs-rs wants them: where the
/// bytes of each are, by its fs-verity digest.
struct StoreFiles<'a> {
    objects: &'a dyn Fn(&str) -> Option<std::path::PathBuf>,
}

impl<H: FsVerityHashValue> Files<H> for StoreFiles<'_> {
    fn regular(&mut self, e: &velarx_storage::TocEntry) -> std::io::Result<RegularFile<H>> {
        let other = |m: String| std::io::Error::other(m);
        if e.size == 0 {
            return Ok(RegularFile::Inline(Box::new([])));
        }
        let digest = e
            .verity()
            .ok_or_else(|| other(format!("`{}` has no fs-verity digest", e.name)))?;
        let path = (self.objects)(&digest)
            .ok_or_else(|| other(format!("`{}` is not in the store", e.name)))?;
        let len = std::fs::metadata(&path)?.len();
        if len != e.size {
            return Err(other(format!("`{}` is not of the size it has", e.name)));
        }
        if e.size as usize <= INLINE_MAX {
            return Ok(RegularFile::Inline(
                std::fs::read(&path)?.into_boxed_slice(),
            ));
        }
        // (the digits of the object name: 64 for SHA-256, 128 for SHA-512)
        let hex = velarx_types::digest::Digest::parse_fsverity(&digest)
            .map_err(|e| other(e.to_string()))?
            .hex();
        let id = H::from_hex(&hex).map_err(|e| other(e.to_string()))?;
        Ok(RegularFile::External(id, e.size))
    }
}

/// The image of the root file system as composefs-rs makes it of the layers
/// `tocs`, whose files are the objects of `store` (by their fs-verity digest
/// in `alg`, the algorithm of the digests of the image), and its id: the
/// merged EROFS a sealed manifest states.  It needs the tables of contents
/// and the objects only, so every driver that keeps the objects of the pull
/// answers it the same (the image is not kept).
pub fn image_of_store(
    alg: velarx_types::digest::Algorithm,
    tocs: &[&velarx_storage::Toc],
    store: &velarx_storage::FileStore,
) -> std::io::Result<(Box<[u8]>, String)> {
    image_of(alg, tocs, &|d| store.get_path(d))
}

/// [`image_of_store`] of objects that are where `objects` says (by their
/// fs-verity digest): the files a pull verified are read before they are
/// named in the store.
pub fn image_of(
    alg: velarx_types::digest::Algorithm,
    tocs: &[&velarx_storage::Toc],
    objects: &dyn Fn(&str) -> Option<std::path::PathBuf>,
) -> std::io::Result<(Box<[u8]>, String)> {
    use composefs::fsverity::{Sha256HashValue, Sha512HashValue};
    fn made<H: FsVerityHashValue>(
        tocs: &[&velarx_storage::Toc],
        objects: &dyn Fn(&str) -> Option<std::path::PathBuf>,
    ) -> std::io::Result<(Box<[u8]>, String)> {
        let io = |e: String| std::io::Error::other(e);
        let layers: Vec<&[velarx_storage::TocEntry]> =
            tocs.iter().map(|t| t.entries.as_slice()).collect();
        let mut files = StoreFiles { objects };
        let tree = merge::<H>(&layers, &mut files).map_err(io)?;
        let (image, id) = image(tree, Default::default()).map_err(io)?;
        Ok((image, id.to_hex()))
    }
    match alg {
        velarx_types::digest::Algorithm::Sha256 => made::<Sha256HashValue>(tocs, objects),
        velarx_types::digest::Algorithm::Sha512 => made::<Sha512HashValue>(tocs, objects),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use composefs::erofs::format::FormatVersion;

    /// One reading of the times: the nanoseconds kept, a time before 1970
    /// (which the image cannot hold) the epoch, as for no time at all.
    #[test]
    fn the_times_of_the_table_are_read_once_and_clamped_at_the_epoch() {
        let t = |s: &str| unix_time(&Some(s.to_string()));
        assert_eq!(
            t("2024-01-02T03:04:05.25+00:00"),
            (1_704_164_645, 250_000_000)
        );
        assert_eq!(t("1970-01-01T00:00:00.000000001Z"), (0, 1));
        assert_eq!(t("1969-12-31T23:59:59.5Z"), (0, 0));
        assert_eq!(t("not a time"), (0, 0));
        assert_eq!(unix_time(&None), (0, 0));
        // (the table itself keeps what was before the epoch)
        assert_eq!(
            velarx_storage::toc_time(Some("1969-12-31T23:59:59.5Z")),
            Some((-1, 500_000_000))
        );
    }
    use composefs::fsverity::{FsVerityHashValue, Sha256HashValue, Sha512HashValue};

    struct Fake;
    impl<H: FsVerityHashValue> Files<H> for Fake {
        fn regular(&mut self, e: &TocEntry) -> io::Result<RegularFile<H>> {
            // (the digest of the content is the id here)
            let hex = e
                .digest
                .as_deref()
                .and_then(|d| d.split_once(':'))
                .map(|(_, h)| h);
            match hex {
                _ if e.size <= INLINE_MAX as u64 => Ok(RegularFile::Inline(
                    vec![b'x'; e.size as usize].into_boxed_slice(),
                )),
                Some(h) => Ok(RegularFile::External(
                    H::from_hex(h).map_err(io::Error::other)?,
                    e.size,
                )),
                None => Err(io::Error::other("no digest")),
            }
        }
    }

    fn entry(v: serde_json::Value) -> TocEntry {
        serde_json::from_value(v).unwrap()
    }

    fn d(name: &str) -> TocEntry {
        entry(serde_json::json!({"name": name, "type": "dir", "mode": 0o755}))
    }

    fn f(name: &str, c: char, size: u64) -> TocEntry {
        entry(
            serde_json::json!({"name": name, "type": "reg", "mode": 0o644, "size": size,
            "digest": format!("sha256:{}", c.to_string().repeat(64))}),
        )
    }

    fn paths(fs: &Tree<Sha256HashValue>) -> Vec<String> {
        fn walk(dir: &Directory<Sha256HashValue>, prefix: &str, out: &mut Vec<String>) {
            for (name, inode) in dir.sorted_entries() {
                let p = format!("{prefix}/{}", name.to_string_lossy());
                out.push(p.clone());
                if let Inode::Directory(d) = inode {
                    walk(d, &p, out);
                }
            }
        }
        let mut out = Vec::new();
        walk(&fs.root, "", &mut out);
        out
    }

    fn base() -> Vec<TocEntry> {
        vec![
            d(""),
            d("usr"),
            d("etc"),
            f("etc/a", 'a', 100),
            f("etc/b", 'b', 100),
            d("run"),
            f("run/x", 'c', 100),
        ]
    }

    #[test]
    fn a_symlink_with_no_target_is_refused() {
        let link = entry(serde_json::json!({"name": "etc/l", "type": "symlink", "mode": 0o777}));
        let e = merge::<Sha256HashValue>(&[&base(), &[link]], &mut Fake)
            .err()
            .unwrap();
        assert!(e.contains("etc/l") && e.contains("no target"), "{e}");
    }

    #[test]
    fn whiteouts_apply_where_they_are_in_the_archive() {
        // a whiteout after the file of its own layer removes it (the order
        // of the entries says it), before it does not
        let after = vec![f("etc/c", 'c', 100), f("etc/.wh.c", 'c', 0)];
        let before = vec![f("etc/.wh.c", 'c', 0), f("etc/c", 'c', 100)];
        let tree = |l: Vec<TocEntry>| merge::<Sha256HashValue>(&[&base(), &l], &mut Fake).unwrap();
        assert!(!paths(&tree(after)).contains(&"/etc/c".to_string()));
        assert!(paths(&tree(before)).contains(&"/etc/c".to_string()));
    }

    #[test]
    fn an_opaque_marker_empties_the_directory_as_it_is() {
        let layer = vec![
            f("etc/n", 'd', 100),
            f("etc/.wh..wh..opq", 'e', 0),
            f("etc/m", 'e', 100),
        ];
        let tree = merge::<Sha256HashValue>(&[&base(), &layer], &mut Fake).unwrap();
        let p = paths(&tree);
        // (what the layer had before the marker went too)
        assert!(p.contains(&"/etc/m".to_string()));
        assert!(!p
            .iter()
            .any(|x| x == "/etc/a" || x == "/etc/b" || x == "/etc/n"));
    }

    #[test]
    fn a_directory_over_a_directory_keeps_its_entries_and_takes_the_metadata() {
        let mut dir = d("etc");
        dir.mode = 0o700;
        let tree = merge::<Sha256HashValue>(&[&base(), &[dir]], &mut Fake).unwrap();
        assert!(paths(&tree).contains(&"/etc/a".to_string()));
        let etc = tree.root.get_directory(OsStr::new("etc")).unwrap();
        assert_eq!(etc.stat.st_mode, 0o700);
    }

    #[test]
    fn a_file_over_a_directory_replaces_it() {
        let tree = merge::<Sha256HashValue>(&[&base(), &[f("etc", 'f', 100)]], &mut Fake).unwrap();
        let p = paths(&tree);
        assert!(p.contains(&"/etc".to_string()) && !p.contains(&"/etc/a".to_string()));
    }

    #[test]
    fn a_hard_link_is_the_leaf_of_its_target() {
        let link =
            entry(serde_json::json!({"name": "etc/l", "type": "hardlink", "linkName": "etc/a"}));
        let tree = merge::<Sha256HashValue>(&[&base(), &[link]], &mut Fake).unwrap();
        let etc = tree.root.get_directory(OsStr::new("etc")).unwrap();
        assert_eq!(
            etc.leaf_id(OsStr::new("l")).unwrap(),
            etc.leaf_id(OsStr::new("a")).unwrap()
        );
    }

    #[test]
    fn the_tree_is_made_the_same_for_every_way_of_making_it() {
        let mut usr = d("usr");
        usr.mode = 0o750;
        usr.uid = 7;
        usr.mod_time = Some("2024-05-06T07:08:09Z".into());
        let cap = entry(
            serde_json::json!({"name": "etc/cap", "type": "reg", "mode": 0o755, "size": 100,
            "digest": format!("sha256:{}", "9".repeat(64)),
            "xattrs": {"security.capability": "AQ==", "user.x": "AQ==", "security.selinux": "AQ=="}}),
        );
        let layer = vec![usr, cap];
        let tree = merge::<Sha256HashValue>(&[&base(), &layer], &mut Fake).unwrap();
        // the root has the metadata of /usr, /run is empty, only the
        // capability is kept
        assert_eq!(tree.root.stat.st_mode, 0o750);
        assert_eq!(tree.root.stat.st_uid, 7);
        assert!(!paths(&tree).contains(&"/run/x".to_string()));
        assert!(paths(&tree).contains(&"/run".to_string()));
        let etc = tree.root.get_directory(OsStr::new("etc")).unwrap();
        let id = etc.leaf_id(OsStr::new("cap")).unwrap();
        let keys: Vec<_> = tree
            .leaf(id)
            .stat
            .xattrs
            .keys()
            .map(|k| k.to_string_lossy().into_owned())
            .collect();
        assert_eq!(keys, ["security.capability"]);
    }

    #[test]
    fn the_directories_of_an_entry_are_made_when_the_archive_lacks_them() {
        let tree =
            merge::<Sha256HashValue>(&[&[d("usr"), f("a/b/c", 'a', 100)]], &mut Fake).unwrap();
        assert_eq!(paths(&tree), ["/a", "/a/b", "/a/b/c", "/usr"]);
    }

    #[test]
    fn the_image_is_the_same_each_time() {
        let make = || {
            let tree =
                merge::<Sha256HashValue>(&[&base(), &[f("etc/z", 'e', 5000)]], &mut Fake).unwrap();
            image(tree, FormatVersion::default()).unwrap().1
        };
        assert_eq!(make(), make());
    }

    /// The tree of an image whose digests are SHA-512 holds SHA-512 object
    /// ids, and its image is made with 64-byte digests: another image than
    /// the one of the same files under SHA-256.
    #[test]
    fn the_image_of_sha512_digests_has_sha512_ids() {
        let f512 = |name: &str, c: char| {
            entry(
                serde_json::json!({"name": name, "type": "reg", "mode": 0o644, "size": 5000,
                "digest": format!("sha512:{}", c.to_string().repeat(128))}),
            )
        };
        let layer = vec![d("usr"), d("etc"), f512("etc/a", 'a')];
        let tree = merge::<Sha512HashValue>(&[&layer], &mut Fake).unwrap();
        let (bytes, id) = image(tree, FormatVersion::default()).unwrap();
        assert_eq!(id.to_hex().len(), 128);
        let again = merge::<Sha512HashValue>(&[&layer], &mut Fake).unwrap();
        assert_eq!(image(again, FormatVersion::default()).unwrap().0, bytes);
        // the SHA-256 tree of the same names is another image
        let layer256 = vec![d("usr"), d("etc"), f("etc/a", 'a', 5000)];
        let tree256 = merge::<Sha256HashValue>(&[&layer256], &mut Fake).unwrap();
        assert_ne!(image(tree256, FormatVersion::default()).unwrap().0, bytes);
    }
}
