// SPDX-License-Identifier: Apache-2.0
//! The tar stream of the merged tree of an image (`build --squash-all`):
//! its layers applied in order, whiteouts and hard links resolved, the
//! content read from the file store one file at a time, with the changes
//! of a container applied on top (`commit --squash`).

use crate::services::cpview::xattr_records;
use crate::services::imagecopy::mtime;
use rustix::fd::{AsFd, OwnedFd};
use std::collections::{HashMap, HashSet};
use std::io;
use velarx_content::layer::dirtar::{self, Content, Out, Recorded};
use velarx_fuse::{MergedTree, Node, ROOT};
use velarx_storage::{ObjectOpener, TocEntryType};

/// The directories to visit, the iterator of the children of each.
type Stack<'a> = Vec<(std::collections::btree_map::Iter<'a, String, usize>, String)>;

fn header(n: &Node) -> tar::Header {
    let e = &n.entry;
    let mut h = tar::Header::new_gnu();
    h.set_mode(e.mode & 0o7777);
    h.set_uid(e.uid.into());
    h.set_gid(e.gid.into());
    h.set_mtime(mtime(e).tv_sec.max(0) as u64);
    h.set_size(0);
    h
}

/// The extended header records of the next entry: its xattrs, when it has
/// any.
fn pax(out: &mut dyn Out, e: &velarx_storage::TocEntry) -> io::Result<()> {
    let records = xattr_records(e);
    if records.is_empty() {
        return Ok(());
    }
    let records: Vec<(String, &[u8])> = records
        .iter()
        .map(|(k, v)| (k.clone(), v.as_slice()))
        .collect();
    out.pax(&records)
}

fn add(
    out: &mut dyn Out,
    objects: &dyn ObjectOpener,
    n: &Node,
    idx: usize,
    path: &str,
    links: &mut HashMap<usize, String>,
) -> io::Result<()> {
    let e = &n.entry;
    let mut h = header(n);
    if e.entry_type != TocEntryType::Dir && n.nlink > 1 {
        if let Some(first) = links.get(&idx) {
            h.set_entry_type(tar::EntryType::Link);
            return out.link(&mut h, path, first.as_ref());
        }
        links.insert(idx, path.to_string());
    }
    if e.entry_type != TocEntryType::Symlink {
        pax(out, e)?;
    }
    match e.entry_type {
        TocEntryType::Dir => {
            h.set_entry_type(tar::EntryType::Directory);
            out.entry(&mut h, &format!("{path}/"), Content::None)
        }
        TocEntryType::Reg | TocEntryType::Hardlink | TocEntryType::Chunk => {
            h.set_entry_type(tar::EntryType::Regular);
            h.set_size(e.size);
            if e.size == 0 {
                return out.entry(&mut h, path, Content::None);
            }
            let digest = e
                .verity()
                .ok_or_else(|| io::Error::other(format!("`{path}` has no content digest")))?;
            let file = objects.object_file(&digest, e.size).map_err(|err| {
                io::Error::new(
                    err.kind(),
                    format!("`{path}`: the file {digest} cannot be read back: {err}"),
                )
            })?;
            out.entry(
                &mut h,
                path,
                Content::Opened {
                    file,
                    size: e.size,
                    shown: path,
                    seen: None,
                },
            )
        }
        TocEntryType::Symlink => {
            h.set_entry_type(tar::EntryType::Symlink);
            out.link(&mut h, path, e.link_name.as_deref().unwrap_or("").as_ref())
        }
        TocEntryType::Char | TocEntryType::Block => {
            h.set_entry_type(if e.entry_type == TocEntryType::Char {
                tar::EntryType::Char
            } else {
                tar::EntryType::Block
            });
            h.set_device_major(e.dev_major.unwrap_or(0))?;
            h.set_device_minor(e.dev_minor.unwrap_or(0))?;
            out.entry(&mut h, path, Content::None)
        }
        TocEntryType::Fifo => {
            h.set_entry_type(tar::EntryType::Fifo);
            out.entry(&mut h, path, Content::None)
        }
    }
}

/// The changes of a container (`layer::dirtar`), recorded: the entries are
/// kept decoded, the content of the files is not read until it
/// is written, from the directory of the container (which the commit holds
/// paused, or else changes under it are errors, as in a commit without
/// `--squash`) or the store.  What the merge needs to know about them before
/// the tree is written is in memory.
pub(super) struct Upper {
    /// The directory that was walked.
    root: OwnedFd,
    /// The entries that are not deletions, in order.
    entries: Vec<Recorded>,
    /// the paths deleted (`.wh.NAME`)
    whiteouts: HashSet<String>,
    /// the directories whose content below is hidden
    opaque: HashSet<String>,
    /// the entries that are not directories
    paths: HashSet<String>,
    /// the directories: their entry, written where the tree has the
    /// directory they replace
    dirs: HashMap<String, usize>,
    /// The size of the tar stream the changes make.
    stream_len: u64,
}

/// What an entry of the changes is: a deletion, a hidden directory, or a
/// path.
enum Mark {
    Whiteout(String),
    Opaque(String),
    Path(String),
}

fn mark(path: &str) -> Mark {
    let path = path.trim_end_matches('/');
    let (dir, name) = path.rsplit_once('/').unwrap_or(("", path));
    let join = |n: &str| {
        if dir.is_empty() {
            n.to_string()
        } else {
            format!("{dir}/{n}")
        }
    };
    if name == ".wh..wh..opq" {
        Mark::Opaque(dir.to_string())
    } else if let Some(n) = name.strip_prefix(".wh.") {
        Mark::Whiteout(join(n))
    } else {
        Mark::Path(path.to_string())
    }
}

impl Upper {
    /// Walk the changes in `root`.
    pub(super) fn record(root: OwnedFd, walk: &dirtar::Options) -> io::Result<Self> {
        let recorded = dirtar::record(root.as_fd(), walk)?;
        let mut u = Self {
            root,
            entries: Vec::new(),
            whiteouts: HashSet::new(),
            opaque: HashSet::new(),
            paths: HashSet::new(),
            dirs: HashMap::new(),
            stream_len: 0,
        };
        for e in recorded {
            u.stream_len += e.stream_len();
            match mark(&e.path) {
                Mark::Whiteout(p) => {
                    u.whiteouts.insert(p);
                }
                Mark::Opaque(p) => {
                    u.opaque.insert(p);
                }
                Mark::Path(p) if e.kind == tar::EntryType::Directory => {
                    u.dirs.insert(p, u.entries.len());
                    u.entries.push(e);
                }
                Mark::Path(p) => {
                    u.paths.insert(p);
                    u.entries.push(e);
                }
            }
        }
        Ok(u)
    }

    /// The size of the tar the changes make.
    pub(super) fn len(&self) -> io::Result<u64> {
        Ok(self.stream_len)
    }

    /// Whether the entry of the tree at `path` is not the one of the
    /// merged tree: it is deleted, or the changes have an entry for it.
    fn replaces(&self, path: &str) -> bool {
        self.whiteouts.contains(path) || self.paths.contains(path) || self.dirs.contains_key(path)
    }

    /// Whether what the tree has below the directory `path` is kept.
    fn keeps_below(&self, path: &str) -> bool {
        !self.opaque.contains(path)
    }

    fn write_entry(&self, out: &mut dyn Out, e: &Recorded) -> io::Result<()> {
        dirtar::replay(e, self.root.as_fd(), out)
    }

    /// The entries of the changes the walk of the tree did not write: the
    /// directories (by their position in the entries) it wrote are `written`.
    fn append_rest(&self, out: &mut dyn Out, written: &HashSet<usize>) -> io::Result<()> {
        for (i, e) in self.entries.iter().enumerate() {
            if !written.contains(&i) {
                self.write_entry(out, e)?;
            }
        }
        Ok(())
    }
}

/// What the walk of the tree of a squash meets.
enum Step<'a> {
    /// The entry of the changes (by its position) of a directory they
    /// replace, written where the tree has the directory.
    Changed(usize),
    /// A node of the tree that the changes do not replace.
    Node {
        node: &'a Node,
        idx: usize,
        path: &'a str,
    },
}

/// Walk `tree` as the tar of a squash is written: parents before their
/// children, the names in order, starting with the children of the root;
/// with the `upper` changes applied (what they replace or delete is not a
/// `Node`, what they hide is not entered).
fn walk_tree<'a>(
    tree: &'a MergedTree,
    upper: Option<&Upper>,
    mut visit: impl FnMut(Step<'_>) -> io::Result<()>,
) -> io::Result<()> {
    let root = tree
        .node(ROOT)
        .ok_or_else(|| io::Error::other("the image has no root"))?;
    let mut stack: Stack<'a> = vec![(root.children.iter(), String::new())];
    while let Some((iter, dir)) = stack.last_mut() {
        let Some((name, &idx)) = iter.next() else {
            stack.pop();
            continue;
        };
        let path = if dir.is_empty() {
            name.clone()
        } else {
            format!("{dir}/{name}")
        };
        let node = tree
            .node(idx)
            .ok_or_else(|| io::Error::other(format!("`{path}` is not in the tree")))?;
        let is_dir = node.entry.entry_type == TocEntryType::Dir;
        let mut descend = is_dir;
        if let Some(u) = upper.filter(|u| u.replaces(&path)) {
            if let Some(&i) = u.dirs.get(&path) {
                visit(Step::Changed(i))?;
            }
            descend &= u.dirs.contains_key(&path) && u.keeps_below(&path);
        } else {
            visit(Step::Node {
                node,
                idx,
                path: &path,
            })?;
            descend &= upper.is_none_or(|u| u.keeps_below(&path));
        }
        if descend {
            if stack.len() >= velarx_wire::cp::MAX_DEPTH {
                return Err(io::Error::other("the tree is nested too deeply"));
            }
            stack.push((node.children.iter(), path));
        }
    }
    Ok(())
}

/// The objects a squash reads, as (key, size) each once, in the order it
/// reads them: what a driver behind a socket reads ahead in one call.
fn objects_read(tree: &MergedTree, upper: Option<&Upper>) -> Vec<(String, u64)> {
    let mut seen = HashSet::new();
    let mut linked = HashSet::new();
    let mut objects = Vec::new();
    let _ = walk_tree(tree, upper, |step| {
        let Step::Node { node, idx, .. } = step else {
            return Ok(());
        };
        let e = &node.entry;
        // (a hard link after the first is no read)
        if e.entry_type != TocEntryType::Dir && node.nlink > 1 && !linked.insert(idx) {
            return Ok(());
        }
        if matches!(
            e.entry_type,
            TocEntryType::Reg | TocEntryType::Hardlink | TocEntryType::Chunk
        ) && e.size > 0
        {
            if let Some(key) = e.verity() {
                if seen.insert(key.clone()) {
                    objects.push((key, e.size));
                }
            }
        }
        Ok(())
    });
    objects
}

/// Write the tar of `tree` to `out`, parents before their children and
/// the names in order, starting with the root directory (`./`).  With the
/// `upper` changes applied: what they delete is not written, what they
/// replace is theirs, and what they add comes last.
pub(super) fn write_tree(
    tree: &MergedTree,
    objects: &dyn ObjectOpener,
    upper: Option<&Upper>,
    out: &mut dyn Out,
) -> io::Result<()> {
    // (the files are read in the order of the walk: a driver behind a
    // socket reads the next ones in the same call)
    let ahead = objects.ordered(&mut || objects_read(tree, upper));
    let objects = ahead.as_deref().unwrap_or(objects);
    let mut links = HashMap::new();
    let mut written: HashSet<usize> = HashSet::new();
    let root = tree
        .node(ROOT)
        .ok_or_else(|| io::Error::other("the image has no root"))?;
    let mut h = header(root);
    h.set_entry_type(tar::EntryType::Directory);
    pax(out, &root.entry)?;
    out.entry(&mut h, "./", Content::None)?;
    walk_tree(tree, upper, |step| match step {
        Step::Changed(i) => {
            if let Some(u) = upper {
                u.write_entry(out, &u.entries[i])?;
            }
            written.insert(i);
            Ok(())
        }
        Step::Node { node, idx, path } => add(out, objects, node, idx, path, &mut links),
    })?;
    if let Some(u) = upper {
        u.append_rest(out, &written)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use std::io::{Read, Write};
    use velarx_content::layer::holes::HoleWrite;
    use velarx_content::layer::writer::{write_layer, Compression};
    use velarx_fuse::dir_entry;
    use velarx_storage::{FileStore, TocEntry};
    use velarx_types::digest::{Algorithm, Digest};

    /// The tar stream of the tree, written to `out`.
    fn write_tree_to<W: HoleWrite>(
        tree: &MergedTree,
        objects: &dyn ObjectOpener,
        upper: Option<&Upper>,
        out: W,
    ) -> io::Result<()> {
        let mut tar = dirtar::TarOut::new(out);
        write_tree(tree, objects, upper, &mut tar)?;
        tar.finish()?.flush()
    }

    fn entry(name: &str, t: TocEntryType) -> TocEntry {
        let mut e = dir_entry(name);
        e.entry_type = t;
        e.mode = 0o640;
        e.uid = 1000;
        e.gid = 100;
        e
    }

    fn file(store: &FileStore, name: &str, data: &[u8]) -> TocEntry {
        let mut e = entry(name, TocEntryType::Reg);
        e.size = data.len() as u64;
        let id = store
            .put(velarx_types::digest::Algorithm::Sha256, data)
            .unwrap();
        e.fsverity = velarx_storage::to_toc(&id);
        e
    }

    /// Objects read back as a driver whose bytes are no files of the
    /// engine does: a copy in an unnamed file.
    struct Spooled(FileStore);

    impl ObjectOpener for Spooled {
        fn object_file(&self, key: &str, size: u64) -> io::Result<std::fs::File> {
            use std::io::Seek;
            let mut copy = tempfile::tempfile()?;
            io::copy(&mut self.0.object_file(key, size)?, &mut copy)?;
            copy.rewind()?;
            Ok(copy)
        }
    }

    /// The tar of a squash is made from the objects the driver gives, and
    /// an object it does not have is an error that names the file.
    #[test]
    fn test_the_squash_reads_the_files_through_the_objects() {
        let d = tempfile::tempdir().unwrap();
        let store = FileStore::new(d.path().join("s")).unwrap();
        let entries = vec![
            entry("etc", TocEntryType::Dir),
            file(&store, "etc/a", b"content of a"),
        ];
        let tree = MergedTree::build_entries(&[&entries]).unwrap();
        let mut direct = Vec::new();
        write_tree_to(&tree, &store, None, &mut direct).unwrap();
        let mut spooled = Vec::new();
        write_tree_to(&tree, &Spooled(store), None, &mut spooled).unwrap();
        assert_eq!(direct, spooled);
        assert!(spooled.windows(12).any(|w| w == b"content of a"));

        let empty = FileStore::new(d.path().join("empty")).unwrap();
        let e = write_tree_to(&tree, &Spooled(empty), None, &mut Vec::new()).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::NotFound);
        assert!(e.to_string().contains("etc/a"), "{e}");
    }

    /// The files of a squash are asked for in the order the tar writes them,
    /// each content once, in one list given to a reader that reads ahead, and
    /// that reader's objects are the ones written.
    #[test]
    fn test_the_squash_gives_the_order_of_its_reads_to_the_objects() {
        use std::sync::{Arc, Mutex};
        struct Ahead {
            store: Arc<FileStore>,
            order: Mutex<Vec<Vec<(String, u64)>>>,
            alone: Mutex<usize>,
        }
        struct Taken(Arc<Ahead>);
        impl ObjectOpener for Taken {
            fn object_file(&self, key: &str, size: u64) -> io::Result<std::fs::File> {
                self.0.store.object_file(key, size)
            }
        }
        impl ObjectOpener for Ahead {
            fn object_file(&self, key: &str, size: u64) -> io::Result<std::fs::File> {
                *self.alone.lock().unwrap() += 1;
                self.store.object_file(key, size)
            }
            fn ordered(
                &self,
                order: &mut dyn FnMut() -> Vec<(String, u64)>,
            ) -> Option<Arc<dyn ObjectOpener>> {
                self.order.lock().unwrap().push(order());
                Some(Arc::new(Taken(Arc::new(Ahead {
                    store: self.store.clone(),
                    order: Mutex::default(),
                    alone: Mutex::default(),
                }))))
            }
        }
        let d = tempfile::tempdir().unwrap();
        let store = Arc::new(FileStore::new(d.path().join("s")).unwrap());
        let entries = vec![
            entry("a", TocEntryType::Dir),
            file(&store, "a/z", b"zed"),
            file(&store, "a/b", b"bee"),
            file(&store, "a/same", b"zed"),
            entry("c", TocEntryType::Dir),
            file(&store, "c/d", b"dee"),
            entry("empty", TocEntryType::Reg),
        ];
        let tree = MergedTree::build_entries(&[&entries]).unwrap();
        let ahead = Ahead {
            store: store.clone(),
            order: Mutex::default(),
            alone: Mutex::default(),
        };
        let mut out = Vec::new();
        write_tree_to(&tree, &ahead, None, &mut out).unwrap();
        let mut direct = Vec::new();
        write_tree_to(&tree, &*store, None, &mut direct).unwrap();
        assert_eq!(out, direct);
        let lists = ahead.order.lock().unwrap();
        assert_eq!(lists.len(), 1, "one list for the walk");
        let sizes: Vec<u64> = lists[0].iter().map(|(_, s)| *s).collect();
        assert_eq!(sizes, [3, 3, 3], "names in order: a/b, a/same (= a/z), c/d");
        let keys: HashSet<&String> = lists[0].iter().map(|(k, _)| k).collect();
        assert_eq!(keys.len(), 3, "each content once: {lists:?}");
        assert_eq!(*ahead.alone.lock().unwrap(), 0, "nothing is read alone");
    }

    #[test]
    fn test_the_merged_tree_is_one_tar_without_whiteouts() {
        let d = tempfile::tempdir().unwrap();
        let store = FileStore::new(d.path()).unwrap();
        let mut holes = vec![1u8; 5000];
        holes.extend(vec![0u8; 20_000]);
        holes.extend(vec![2u8; 5000]);
        let mut xa = file(&store, "etc/x", b"xattr\n");
        xa.xattrs.insert(
            "user.k".into(),
            base64::engine::general_purpose::STANDARD.encode(b"v"),
        );
        let mut dev = entry("dev/null", TocEntryType::Char);
        (dev.dev_major, dev.dev_minor) = (Some(1), Some(3));
        let mut hard = entry("etc/hard", TocEntryType::Hardlink);
        hard.link_name = Some("etc/x".into());
        let mut link = entry("etc/link", TocEntryType::Symlink);
        link.link_name = Some("x".into());
        let lower = vec![
            entry("etc", TocEntryType::Dir),
            file(&store, "etc/gone", b"gone\n"),
            file(&store, "etc/replaced", b"old\n"),
            xa,
            hard,
            link,
            entry("dev", TocEntryType::Dir),
            dev,
            entry("old", TocEntryType::Dir),
            file(&store, "old/f", b"f"),
            file(&store, "holes", &holes),
        ];
        let mut wh = entry("etc/.wh.gone", TocEntryType::Reg);
        wh.mode = 0;
        let upper = vec![
            wh,
            file(&store, "etc/replaced", b"new\n"),
            entry(".wh.old", TocEntryType::Reg),
        ];
        let tree = MergedTree::build_entries(&[&lower, &upper]).unwrap();
        let mut tar = Vec::new();
        write_tree_to(&tree, &store, None, &mut tar).unwrap();

        // the same layer made in one pass, as a build makes it: it is the
        // tar that was written (the diff id is its digest), each file read
        // once and staged
        {
            use std::sync::Arc;
            use velarx_content::pull::{made, session::Session, sink::Sink};
            let tmp = tempfile::tempdir().unwrap();
            let files = Arc::new(FileStore::new(tmp.path().join("files")).unwrap());
            let session = Session::create(&tmp.path().join("staging"), files).unwrap();
            let sink: Arc<dyn Sink> = session.clone();
            let (layer, size) = made::from_walk(
                &sink,
                Algorithm::Sha256,
                u64::MAX,
                Box::new(|_| Ok(())),
                |out| write_tree(&tree, &store, None, out),
            )
            .unwrap();
            assert_eq!(layer.diff_id, Digest::of(Algorithm::Sha256, &tar));
            assert_eq!(size, tar.len() as u64);
            let names: Vec<&str> = layer.toc.entries.iter().map(|e| e.name.as_str()).collect();
            assert!(
                names.contains(&"etc/x") && names.contains(&"dev/null"),
                "{names:?}"
            );
        }

        let mut ar = tar::Archive::new(&tar[..]);
        let mut seen = std::collections::BTreeMap::new();
        for e in ar.entries().unwrap() {
            let mut e = e.unwrap();
            let path = e
                .path()
                .unwrap()
                .to_string_lossy()
                .trim_end_matches('/')
                .to_string();
            let h = e.header().clone();
            let mut data = Vec::new();
            e.read_to_end(&mut data).unwrap();
            let link = e
                .link_name()
                .unwrap()
                .map(|l| l.to_string_lossy().into_owned());
            let mut xattrs = Vec::new();
            if let Some(ext) = e.pax_extensions().unwrap() {
                for x in ext {
                    let x = x.unwrap();
                    xattrs.push((x.key().unwrap().to_string(), x.value_bytes().to_vec()));
                }
            }
            seen.insert(path, (h, data, link, xattrs));
        }
        let names: Vec<_> = seen.keys().cloned().collect();
        assert_eq!(
            names,
            [
                ".",
                "dev",
                "dev/null",
                "etc",
                "etc/hard",
                "etc/link",
                "etc/replaced",
                "etc/x",
                "holes"
            ]
        );
        assert_eq!(seen["etc/replaced"].1, b"new\n");
        assert_eq!(seen["holes"].1, holes);
        let x = &seen["etc/x"];
        assert_eq!(x.0.entry_type(), tar::EntryType::Link);
        assert_eq!(x.2.as_deref(), Some("etc/hard"));
        assert_eq!(seen["etc/hard"].1, b"xattr\n");
        assert_eq!(
            seen["etc/hard"].3,
            [("SCHILY.xattr.user.k".to_string(), b"v".to_vec())]
        );
        let n = &seen["dev/null"].0;
        assert_eq!(n.entry_type(), tar::EntryType::Char);
        assert_eq!(
            (n.device_major().unwrap(), n.device_minor().unwrap()),
            (Some(1), Some(3))
        );
        let l = &seen["etc/link"];
        assert_eq!(l.2.as_deref(), Some("x"));
        let h = &seen["etc/replaced"].0;
        assert_eq!(
            (h.mode().unwrap(), h.uid().unwrap(), h.gid().unwrap()),
            (0o640, 1000, 100)
        );

        // the layer writer takes it in every format
        for c in [
            Compression::None,
            Compression::Gzip,
            Compression::ZstdChunked,
        ] {
            let w = write_layer(&tar[..], Algorithm::Sha256, c, io::sink()).unwrap();
            assert!(w.diff_id.to_string().starts_with("sha256:"));
        }
    }

    /// A directory with the entries (a path ending in `/` is a directory;
    /// `.wh.` names are what the walk makes of a deletion, here plain files)
    /// and the record of the walk of it.
    fn upper_dir(items: &[(&str, &[u8])]) -> (tempfile::TempDir, Upper) {
        use std::os::unix::fs::PermissionsExt;
        let d = tempfile::tempdir().unwrap();
        for (path, data) in items {
            let full = d.path().join(path);
            let mode = if path.ends_with('/') {
                std::fs::create_dir_all(&full).unwrap();
                0o700
            } else {
                std::fs::write(&full, data).unwrap();
                0o600
            };
            std::fs::set_permissions(&full, std::fs::Permissions::from_mode(mode)).unwrap();
        }
        let upper = record_dir(d.path());
        (d, upper)
    }

    fn record_dir(dir: &std::path::Path) -> Upper {
        let root = rustix::fs::openat(
            rustix::fs::CWD,
            dir,
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::DIRECTORY,
            rustix::fs::Mode::empty(),
        )
        .unwrap();
        Upper::record(root, &dirtar::Options::default()).unwrap()
    }

    #[test]
    fn test_the_changes_of_a_container_are_applied_to_the_tree() {
        let d = tempfile::tempdir().unwrap();
        let store = FileStore::new(d.path()).unwrap();
        let mut root = entry("./", TocEntryType::Dir);
        root.mode = 0o750;
        let lower = vec![
            root,
            entry("etc", TocEntryType::Dir),
            file(&store, "etc/gone", b"gone\n"),
            file(&store, "etc/keep", b"keep\n"),
            file(&store, "etc/replaced", b"old\n"),
            entry("opq", TocEntryType::Dir),
            file(&store, "opq/old", b"old\n"),
            entry("dir", TocEntryType::Dir),
            file(&store, "dir/child", b"child\n"),
            entry("becomes_file", TocEntryType::Dir),
            file(&store, "becomes_file/x", b"x"),
            file(&store, "becomes_dir", b"f"),
        ];
        let tree = MergedTree::build_entries(&[&lower]).unwrap();
        let (_dir, upper) = upper_dir(&[
            ("etc/", b""),
            ("etc/.wh.gone", b""),
            ("etc/replaced", b"new\n"),
            ("opq/", b""),
            ("opq/.wh..wh..opq", b""),
            ("opq/fresh", b"fresh\n"),
            ("dir/", b""),
            ("becomes_file", b"now a file\n"),
            ("becomes_dir/", b""),
            ("becomes_dir/y", b"y"),
            ("brand/", b""),
            ("brand/new", b"new"),
        ]);
        let mut tar = Vec::new();
        write_tree_to(&tree, &store, Some(&upper), &mut tar).unwrap();

        let mut ar = tar::Archive::new(&tar[..]);
        let mut seen = Vec::new();
        for e in ar.entries().unwrap() {
            let mut e = e.unwrap();
            let mut data = String::new();
            e.read_to_string(&mut data).unwrap();
            let path = e.path().unwrap().to_string_lossy().into_owned();
            seen.push((
                path,
                e.header().mode().unwrap(),
                e.header().uid().unwrap(),
                data,
            ));
        }
        let paths: Vec<&str> = seen.iter().map(|s| s.0.as_str()).collect();
        assert_eq!(
            paths,
            [
                "./",
                "becomes_dir/",
                "dir/",
                "dir/child",
                "etc/",
                "etc/keep",
                "opq/",
                "becomes_dir/y",
                "becomes_file",
                "brand/",
                "brand/new",
                "etc/replaced",
                "opq/fresh",
            ]
        );
        let by: std::collections::HashMap<_, _> = seen.iter().map(|s| (s.0.as_str(), s)).collect();
        assert_eq!(by["./"].1, 0o750);
        // the directory the container changed has its metadata
        assert_eq!(
            (by["dir/"].1, by["dir/"].2),
            (0o700, u64::from(rustix::process::getuid().as_raw()))
        );
        assert_eq!(by["etc/replaced"].3, "new\n");
        assert_eq!(by["becomes_file"].3, "now a file\n");
        assert_eq!(by["opq/fresh"].3, "fresh\n");
    }

    /// Counts the bytes written and the holes told.
    #[derive(Default)]
    struct Counts {
        data: u64,
        holes: u64,
    }

    impl Write for Counts {
        fn write(&mut self, b: &[u8]) -> io::Result<usize> {
            self.data += b.len() as u64;
            Ok(b.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl HoleWrite for Counts {
        fn hole(&mut self, len: u64) -> io::Result<()> {
            self.holes += len;
            Ok(())
        }
    }

    /// The changes are recorded without their content: a sparse file costs
    /// its header, and is read once, when the tree is written, holes as
    /// holes.
    #[test]
    fn test_the_record_of_a_sparse_file_has_its_header_only() {
        use std::os::unix::fs::{FileExt, MetadataExt};
        const SIZE: u64 = 64 << 20;
        let d = tempfile::tempdir().unwrap();
        std::fs::create_dir(d.path().join("data")).unwrap();
        let f = std::fs::File::create(d.path().join("data/sparse")).unwrap();
        f.set_len(SIZE).unwrap();
        f.write_all_at(b"end", SIZE - 3).unwrap();
        let has_holes = f.metadata().unwrap().blocks() * 512 < SIZE / 2;
        let upper = record_dir(d.path());
        // (the size of the tar it stands for)
        assert!(upper.len().unwrap() >= SIZE);

        let store_dir = tempfile::tempdir().unwrap();
        let store = FileStore::new(store_dir.path()).unwrap();
        let tree = MergedTree::build_entries(&[&[file(&store, "etc", b"x")][..]]).unwrap();
        let mut counts = Counts::default();
        write_tree_to(&tree, &store, Some(&upper), &mut counts).unwrap();
        if has_holes {
            assert!(
                counts.holes > SIZE - (1 << 20),
                "{} bytes of holes",
                counts.holes
            );
            assert!(counts.data < 1 << 20, "{} bytes of data", counts.data);
        }
        let mut tar = Vec::new();
        write_tree_to(&tree, &store, Some(&upper), &mut tar).unwrap();
        let mut ar = tar::Archive::new(&tar[..]);
        let mut sparse = None;
        for e in ar.entries().unwrap() {
            let mut e = e.unwrap();
            if e.path().unwrap().to_string_lossy() == "data/sparse" {
                let mut data = Vec::new();
                e.read_to_end(&mut data).unwrap();
                sparse = Some(data);
            }
        }
        let sparse = sparse.unwrap();
        assert_eq!(sparse.len() as u64, SIZE);
        assert_eq!(&sparse[sparse.len() - 3..], b"end");
        assert!(sparse[..sparse.len() - 3].iter().all(|&b| b == 0));
    }
}
