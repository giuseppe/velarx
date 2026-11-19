// SPDX-License-Identifier: Apache-2.0
//! The root file system of an image as its container sees it, read from the
//! EROFS images of its layers where they are mapped, a lookup at a time:
//! what the engine reads of an image without a container running (its users,
//! a working directory, the content of a volume, a copy out of a stopped
//! container).  Nothing is read ahead: a path costs the lookups of its
//! components in the layers that have them.
//!
//! The layers are applied as the overlay applies them: the highest layer that
//! has a name decides, a whiteout hides it, a directory merges with the
//! directories of the layers below up to an opaque one, and takes the
//! attributes of the highest.

use super::erofs_tree::Layer;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Mutex;
use velarx_storage::{TocEntry, TocEntryType};

/// A node of the image: its entry (`name` is its path, `fsverity` the digest
/// of its content), the layer that has it (0 the lowest) and its links; the
/// names of a file with several are the same `key`.
#[derive(Debug, Clone)]
pub struct ViewNode {
    pub entry: TocEntry,
    pub layer: usize,
    pub nlink: u32,
    pub key: (usize, u64),
}

struct Merged {
    path: String,
    /// The nodes of the layers that make it, the highest first: one, or the
    /// directories that merge.
    parts: Vec<(usize, u64)>,
}

pub struct ImageView {
    layers: Vec<Layer>,
    nodes: Mutex<Nodes>,
    /// Whether the store has fs-verity (`has_verity`).
    verity: bool,
}

#[derive(Default)]
struct Nodes {
    all: Vec<Merged>,
    by_name: HashMap<(usize, String), Option<usize>>,
}

pub const VIEW_ROOT: usize = 0;

/// Whether the store has fs-verity, from the image of a layer of it: the
/// images of the layers have it where the objects have it, with the digests
/// that name the files (a file system without fs-verity, or whose blocks are
/// smaller than 4096 bytes, has none of those digests).
pub fn layer_image_has_verity(image: &std::path::Path) -> bool {
    crate::composefs::open_layer_image(image)
        .is_ok_and(|f| velarx_storage::canonical_algorithm(&f).is_some())
}

impl ImageView {
    /// The layers, the lowest first.
    pub fn new(layers: Vec<Layer>) -> Self {
        let mut parts = Vec::new();
        for (i, l) in layers.iter().enumerate().rev() {
            parts.push((i, l.root()));
            if l.is_opaque(l.root()) {
                break;
            }
        }
        Self {
            layers,
            nodes: Mutex::new(Nodes {
                all: vec![Merged {
                    path: String::new(),
                    parts,
                }],
                by_name: HashMap::new(),
            }),
            verity: false,
        }
    }

    /// The images of the layers at `paths`, the lowest first, mapped.
    pub fn open(paths: &[PathBuf]) -> std::io::Result<Self> {
        let layers = paths
            .iter()
            .map(|p| Layer::map(p))
            .collect::<std::io::Result<Vec<_>>>()?;
        let verity = paths.first().is_some_and(|p| layer_image_has_verity(p));
        Ok(Self {
            verity,
            ..Self::new(layers)
        })
    }

    fn parts(&self, id: usize) -> Option<(String, Vec<(usize, u64)>)> {
        let nodes = self.nodes.lock().unwrap_or_else(|e| e.into_inner());
        nodes.all.get(id).map(|m| (m.path.clone(), m.parts.clone()))
    }
}

/// The root file system of an image as its container sees it, read without
/// mounting: what the engine reads of an image for the users of a container,
/// its working directory, the content of a volume, the changes of a writable
/// layer that depend on what is below it, and a copy out of a stopped
/// container.  A storage driver gives one (`image_view` of the driver);
/// nothing is read ahead.
///
/// Nodes are numbers: [`VIEW_ROOT`] is the root, and the others come from
/// `lookup`/`children`.
pub trait ImageTree: Send + Sync {
    /// `name` in the directory `dir`.
    fn lookup(&self, dir: usize, name: &str) -> Option<usize>;

    /// The names of a directory, sorted, with their nodes; an error when the
    /// image does not have its entries whole (a damaged image).
    fn children(&self, dir: usize) -> std::io::Result<Vec<(String, usize)>>;

    /// What the node is.
    fn node(&self, id: usize) -> Option<ViewNode>;

    /// Whether the store of the image has fs-verity, as the engine decides it
    /// for the root of a container: `[storage] fsverity` checks the files of
    /// the store only then.
    fn has_verity(&self) -> bool;

    /// The content of a regular file, opened, for a tree that reads a mount
    /// (the files are the mount's, with no digest to read them back by):
    /// none for a tree whose content is read by the digest of its entries.
    fn open_content(&self, _node: &ViewNode) -> Option<std::io::Result<std::fs::File>> {
        None
    }

    /// The node at `path`, without following symbolic links.
    fn resolve(&self, path: &str) -> Option<usize> {
        let mut cur = VIEW_ROOT;
        for c in path.split('/').filter(|c| !c.is_empty() && *c != ".") {
            cur = self.lookup(cur, c)?;
        }
        Some(cur)
    }

    /// The node at `path`, its symbolic links followed as the kernel
    /// follows them in the root of the image (`..` stays in it); None if
    /// it is not there, or if the links loop.
    fn resolve_following(&self, path: &str) -> Option<usize> {
        let mut todo: Vec<String> = path
            .split('/')
            .filter(|c| !c.is_empty() && *c != ".")
            .rev()
            .map(str::to_string)
            .collect();
        let mut stack: Vec<usize> = vec![VIEW_ROOT];
        let mut links = 0;
        while let Some(c) = todo.pop() {
            if c == "." {
                continue;
            }
            if c == ".." {
                if stack.len() > 1 {
                    stack.pop();
                }
                continue;
            }
            let cur = *stack.last()?;
            let next = self.lookup(cur, &c)?;
            let node = self.node(next)?;
            if node.entry.entry_type == TocEntryType::Symlink {
                links += 1;
                if links > 40 {
                    return None;
                }
                let target = node.entry.link_name.as_deref().unwrap_or_default();
                if target.starts_with('/') {
                    stack.truncate(1);
                }
                for part in target.split('/').filter(|p| !p.is_empty()).rev() {
                    todo.push(part.to_string());
                }
                continue;
            }
            stack.push(next);
        }
        stack.last().copied()
    }
}

impl ImageTree for ImageView {
    /// `name` in the directory `dir`.
    fn lookup(&self, dir: usize, name: &str) -> Option<usize> {
        if name.is_empty() || name == "." || name == ".." || name.contains('/') {
            return None;
        }
        let key = (dir, name.to_string());
        {
            let nodes = self.nodes.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(found) = nodes.by_name.get(&key) {
                return *found;
            }
        }
        let (path, dirs) = self.parts(dir)?;
        let mut parts: Vec<(usize, u64)> = Vec::new();
        for (i, d) in dirs {
            let layer = &self.layers[i];
            if !layer.is_dir(d) {
                continue;
            }
            let Some(c) = layer.lookup(d, name.as_bytes()) else {
                continue;
            };
            if layer.is_whiteout(c) {
                break;
            }
            // (a directory that is not under the one it is reached from: a
            // corrupt image, whose directories would loop for the walkers)
            if layer.is_dir(c) && (c == d || layer.parent(c) != Some(d)) {
                break;
            }
            if !layer.is_dir(c) {
                // a file hides what is below it, and is hidden by a
                // directory above it
                if parts.is_empty() {
                    parts.push((i, c));
                }
                break;
            }
            parts.push((i, c));
            if layer.is_opaque(c) {
                break;
            }
        }
        let mut nodes = self.nodes.lock().unwrap_or_else(|e| e.into_inner());
        let found = (!parts.is_empty()).then(|| {
            nodes.all.push(Merged {
                path: if path.is_empty() {
                    name.to_string()
                } else {
                    format!("{path}/{name}")
                },
                parts,
            });
            nodes.all.len() - 1
        });
        nodes.by_name.insert(key, found);
        found
    }

    /// The names of a directory, sorted, with their nodes; an error when a
    /// layer does not have its entries whole (a damaged image).
    fn children(&self, dir: usize) -> std::io::Result<Vec<(String, usize)>> {
        let Some((_, parts)) = self.parts(dir) else {
            return Ok(Vec::new());
        };
        let mut names = std::collections::BTreeSet::new();
        for (i, d) in parts {
            if !self.layers[i].is_dir(d) {
                return Ok(Vec::new());
            }
            self.layers[i].readdir(d, 0, &mut |_, _, name| {
                if let Ok(n) = std::str::from_utf8(name) {
                    names.insert(n.to_string());
                }
                false
            })?;
        }
        Ok(names
            .into_iter()
            .filter_map(|n| self.lookup(dir, &n).map(|c| (n, c)))
            .collect())
    }

    /// What the node is.
    fn node(&self, id: usize) -> Option<ViewNode> {
        use base64::Engine;
        let (path, parts) = self.parts(id)?;
        let &(i, nid) = parts.first()?;
        let layer = &self.layers[i];
        let a = layer.attr(nid)?;
        let mut e = crate::dir_entry(&path);
        e.entry_type = match a.kind {
            fuser::FileType::Directory => TocEntryType::Dir,
            fuser::FileType::Symlink => TocEntryType::Symlink,
            fuser::FileType::CharDevice => TocEntryType::Char,
            fuser::FileType::BlockDevice => TocEntryType::Block,
            fuser::FileType::NamedPipe => TocEntryType::Fifo,
            _ => TocEntryType::Reg,
        };
        e.mode = u32::from(a.perm);
        (e.uid, e.gid) = (a.uid, a.gid);
        let since = a.mtime.duration_since(std::time::UNIX_EPOCH).ok()?;
        e.mod_time = chrono::DateTime::from_timestamp(since.as_secs() as i64, since.subsec_nanos())
            .map(|t| t.to_rfc3339());
        match e.entry_type {
            TocEntryType::Reg => {
                let (digest, size) = layer.content(nid)?;
                e.size = size;
                e.fsverity = digest.as_deref().and_then(velarx_storage::to_toc);
            }
            TocEntryType::Symlink => {
                e.link_name =
                    Some(String::from_utf8_lossy(&layer.readlink(nid).ok()?).into_owned());
                e.size = 0;
            }
            TocEntryType::Char | TocEntryType::Block => {
                (e.dev_major, e.dev_minor) = (
                    Some(libc::major(a.rdev as libc::dev_t)),
                    Some(libc::minor(a.rdev as libc::dev_t)),
                );
            }
            _ => {}
        }
        for (name, value) in layer.raw_xattrs(nid) {
            let Ok(name) = String::from_utf8(name) else {
                continue;
            };
            if super::image_fs::hidden_xattr(&name) {
                continue;
            }
            e.xattrs.insert(
                name,
                base64::engine::general_purpose::STANDARD.encode(value),
            );
        }
        Some(ViewNode {
            entry: e,
            layer: i,
            nlink: a.nlink,
            key: (i, nid),
        })
    }

    fn has_verity(&self) -> bool {
        self.verity
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonical::unix_time;
    use crate::layer_erofs::layer_image;
    use crate::MergedTree;
    use velarx_storage::Toc;

    fn entry(name: &str, t: TocEntryType) -> TocEntry {
        let mut e = crate::dir_entry(name);
        e.entry_type = t;
        e.mode = if t == TocEntryType::Dir { 0o755 } else { 0o644 };
        e.mod_time = Some("2024-01-02T03:04:05+00:00".into());
        e
    }

    fn file(name: &str, byte: u8, size: u64) -> TocEntry {
        let mut e = entry(name, TocEntryType::Reg);
        (e.size, e.fsverity) = (
            size,
            velarx_storage::to_toc(&format!(
                "fsverity-sha256-12:{}",
                format!("{byte:02x}").repeat(32)
            )),
        );
        e
    }

    fn view(layers: &[&[TocEntry]]) -> ImageView {
        ImageView::new(
            layers
                .iter()
                .map(|l| Layer::open(Box::new(layer_image(l).unwrap().image)).unwrap())
                .collect(),
        )
    }

    /// Everything below the root: path, kind, mode, owners, size, digest,
    /// link, device, time, attributes.
    pub(crate) fn dump_view(v: &ImageView) -> Vec<String> {
        let mut out = Vec::new();
        let mut todo = vec![VIEW_ROOT];
        while let Some(d) = todo.pop() {
            for (_, c) in v.children(d).unwrap() {
                let n = v.node(c).unwrap();
                let e = &n.entry;
                out.push(format!(
                    "/{} {:?} {:o} {}:{} {} {:?} {:?} {:?} {:?} {:?}",
                    e.name,
                    e.entry_type,
                    e.mode,
                    e.uid,
                    e.gid,
                    e.size,
                    e.fsverity,
                    e.link_name,
                    e.dev_major.zip(e.dev_minor),
                    unix_time(&e.mod_time),
                    e.xattrs
                ));
                if e.entry_type == TocEntryType::Dir {
                    todo.push(c);
                }
            }
        }
        out.sort();
        out
    }

    fn dump_tree(t: &MergedTree) -> Vec<String> {
        let mut out = Vec::new();
        let mut todo = vec![(crate::ROOT, String::new())];
        while let Some((i, path)) = todo.pop() {
            for (name, &c) in &t.node(i).unwrap().children {
                let p = format!("{path}/{name}");
                let e = &t.node(c).unwrap().entry;
                let mut x = e.clone();
                x.xattrs.retain(|k, _| !crate::image_fs::hidden_xattr(k));
                out.push(format!(
                    "{p} {:?} {:o} {}:{} {} {:?} {:?} {:?} {:?} {:?}",
                    if e.entry_type == TocEntryType::Hardlink {
                        TocEntryType::Reg
                    } else {
                        e.entry_type
                    },
                    e.mode,
                    e.uid,
                    e.gid,
                    if e.entry_type == TocEntryType::Symlink {
                        0
                    } else {
                        e.size
                    },
                    e.fsverity,
                    e.link_name
                        .as_ref()
                        .filter(|_| e.entry_type == TocEntryType::Symlink),
                    e.dev_major.zip(e.dev_minor),
                    unix_time(&e.mod_time),
                    x.xattrs
                ));
                if e.entry_type == TocEntryType::Dir {
                    todo.push((c, p));
                }
            }
        }
        out.sort();
        out
    }

    /// Layers that list their directories make, through their images, the
    /// tree the tables of contents make when applied.
    #[test]
    fn the_layers_make_the_tree_of_the_tables() {
        let mut link = entry("usr/l", TocEntryType::Symlink);
        link.link_name = Some("/usr/f".into());
        let mut dev = entry("dev/null", TocEntryType::Char);
        (dev.dev_major, dev.dev_minor) = (Some(1), Some(3));
        let mut owned = file("usr/owned", 2, 7);
        (owned.uid, owned.gid) = (1000, 100);
        owned.xattrs.insert("user.k".into(), "dg==".into());
        let l0 = vec![
            entry("usr", TocEntryType::Dir),
            file("usr/f", 1, 5),
            link,
            owned,
            entry("dev", TocEntryType::Dir),
            dev,
            entry("o", TocEntryType::Dir),
            file("o/gone", 3, 1),
            file("o/keep", 3, 1),
            entry("o/dir", TocEntryType::Dir),
            file("o/dir/inner", 3, 1),
            entry("empty", TocEntryType::Reg),
            entry("d2f", TocEntryType::Dir),
            file("d2f/x", 3, 1),
            file("f2d", 3, 1),
        ];
        let mut l1 = vec![
            entry("usr", TocEntryType::Dir),
            file("usr/new", 4, 9),
            entry("usr/.wh.owned", TocEntryType::Reg),
            entry("o", TocEntryType::Dir),
            entry("o/.wh..wh..opq", TocEntryType::Reg),
            file("o/keep", 5, 2),
            entry("o/dir", TocEntryType::Dir),
            file("o/dir/new", 5, 2),
            file("d2f", 6, 3),
            entry("f2d", TocEntryType::Dir),
            file("f2d/y", 6, 3),
        ];
        let mut hard = entry("usr/h", TocEntryType::Hardlink);
        hard.link_name = Some("usr/new".into());
        l1.push(hard);
        let v = view(&[&l0, &l1]);
        let toc = |e: &Vec<TocEntry>| Toc {
            version: 1,
            entries: e.clone(),
            tar_split_digest: None,
        };
        let t = MergedTree::build(&[&toc(&l0), &toc(&l1)]).unwrap();
        assert_eq!(dump_view(&v), dump_tree(&t));
        let f = v.resolve_following("usr/l").unwrap();
        assert_eq!(v.node(f).unwrap().entry.size, 5);
        assert_eq!(v.node(v.resolve("usr/h").unwrap()).unwrap().nlink, 2);
        assert_eq!(v.node(v.resolve("usr/new").unwrap()).unwrap().layer, 1);
        assert!(v.resolve("o/gone").is_none() && v.resolve("usr/owned").is_none());
    }

    /// A directory a layer does not list is the layer's plain directory, as
    /// when the layer is extracted: it takes the place of the one below.
    #[test]
    fn a_directory_a_layer_does_not_list_is_plain() {
        let mut etc = entry("etc", TocEntryType::Dir);
        (etc.mode, etc.uid) = (0o700, 5);
        let v = view(&[&[etc, file("etc/a", 1, 1)], &[file("etc/b", 2, 1)]]);
        let n = v.node(v.resolve("etc").unwrap()).unwrap();
        assert_eq!((n.entry.mode, n.entry.uid, n.layer), (0o755, 0, 1));
        let names: Vec<String> = v
            .children(v.resolve("etc").unwrap())
            .unwrap()
            .into_iter()
            .map(|(n, _)| n)
            .collect();
        assert_eq!(names, ["a", "b"]);
    }

    /// The layers made into a tree by the tables and through their images
    /// show one file system: the root, and everything below it.
    fn agree(layers: &[&[TocEntry]]) -> (ImageView, MergedTree) {
        let v = view(layers);
        let tocs: Vec<Toc> = layers
            .iter()
            .map(|l| Toc {
                version: 1,
                entries: l.to_vec(),
                tar_split_digest: None,
            })
            .collect();
        let t = MergedTree::build(&tocs.iter().collect::<Vec<_>>()).unwrap();
        assert_eq!(dump_view(&v), dump_tree(&t));
        let root = v.node(VIEW_ROOT).unwrap().entry;
        let r = &t.node(crate::ROOT).unwrap().entry;
        assert_eq!(
            (root.mode, root.uid, root.gid, unix_time(&root.mod_time)),
            (r.mode, r.uid, r.gid, unix_time(&r.mod_time))
        );
        (v, t)
    }

    /// A layer with no root entry has a plain root over a layer with a
    /// private one, and the one with an entry has its own.
    #[test]
    fn the_root_of_a_layer_is_its_own() {
        let mut root = entry("", TocEntryType::Dir);
        (root.mode, root.uid) = (0o700, 7);
        let (v, _) = agree(&[&[root.clone(), file("a", 1, 1)], &[file("b", 2, 1)]]);
        let n = v.node(VIEW_ROOT).unwrap().entry;
        assert_eq!((n.mode, n.uid), (0o755, 0));
        let (v, _) = agree(&[&[file("a", 1, 1)], &[root, file("b", 2, 1)]]);
        let n = v.node(VIEW_ROOT).unwrap().entry;
        assert_eq!((n.mode, n.uid), (0o700, 7));
    }

    /// A layer that adds `a/b` and does not list `a` has a plain `a`
    /// over the one below, which has the files of the layer below.
    #[test]
    fn an_unlisted_parent_is_plain_in_every_view() {
        let mut a = entry("a", TocEntryType::Dir);
        (a.mode, a.uid) = (0o750, 1000);
        let (v, _) = agree(&[&[a, file("a/x", 1, 1)], &[file("a/b", 2, 1)]]);
        let n = v.node(v.resolve("a").unwrap()).unwrap().entry;
        assert_eq!((n.mode, n.uid), (0o755, 0));
        assert!(v.resolve("a/x").is_some() && v.resolve("a/b").is_some());
    }

    /// A directory a layer removes and makes does not have what was below
    /// it, wherever the table lists the whiteout.
    #[test]
    fn a_layer_does_not_merge_a_directory_it_removes() {
        let l0 = [
            entry("d", TocEntryType::Dir),
            file("d/old", 1, 1),
            entry("o", TocEntryType::Dir),
            file("o/old", 1, 1),
        ];
        let l1 = [
            entry("d", TocEntryType::Dir),
            file("d/new", 2, 1),
            entry(".wh.d", TocEntryType::Reg),
            file("o/new", 2, 1),
            entry("o/.wh..wh..opq", TocEntryType::Reg),
        ];
        let (v, _) = agree(&[&l0, &l1]);
        assert!(v.resolve("d/new").is_some() && v.resolve("d/old").is_none());
        assert!(v.resolve("o/new").is_some() && v.resolve("o/old").is_none());
    }

    /// Random layers of whiteouts, opaque markers, directories a layer
    /// removes and makes, names under files, hard links, devices 0:0, roots
    /// and names listed twice: the tables merged and the images stacked show
    /// the same tree, or both are an error.
    #[test]
    fn the_tables_merged_are_the_images_stacked() {
        let mut seed: u64 = 1;
        let mut next = |n: u64| {
            seed = seed
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            (seed >> 33) % n
        };
        let names = ["a", "b", ".wh.a", ".wh.b", ".wh..wh..opq"];
        for _ in 0..5000 {
            let mut layers = Vec::new();
            for _ in 0..1 + next(3) {
                let mut l = Vec::new();
                if next(3) == 0 {
                    let mut root = entry("./", TocEntryType::Dir);
                    root.mode = [0o700, 0o555][next(2) as usize];
                    l.push(root);
                }
                for _ in 0..next(7) {
                    let mut parts: Vec<&str> =
                        (0..next(3)).map(|_| names[next(2) as usize]).collect();
                    parts.push(names[next(5) as usize]);
                    let name = parts.join("/");
                    let mut e = entry(&name, TocEntryType::Reg);
                    if !parts[parts.len() - 1].starts_with(".wh.") {
                        match next(6) {
                            0 | 1 => {
                                e = entry(&name, TocEntryType::Dir);
                                (e.mode, e.uid) =
                                    ([0o755, 0o700][next(2) as usize], next(2) as u32);
                            }
                            2 => {
                                e.entry_type = TocEntryType::Symlink;
                                e.link_name = Some("a".into());
                            }
                            3 => {
                                e.entry_type = TocEntryType::Hardlink;
                                e.link_name =
                                    Some(["a", "b", "a/a", "b/b"][next(4) as usize].into());
                            }
                            4 => {
                                e.entry_type = TocEntryType::Char;
                                (e.dev_major, e.dev_minor) = (Some(0), Some(0));
                            }
                            _ => e = file(&name, 1 + next(3) as u8, 1),
                        }
                    }
                    l.push(e);
                }
                layers.push(l);
            }
            let images: Result<Vec<_>, _> = layers.iter().map(|l| layer_image(l)).collect();
            let tocs: Vec<Toc> = layers
                .iter()
                .map(|l| Toc {
                    version: 1,
                    entries: l.clone(),
                    tar_split_digest: None,
                })
                .collect();
            let tree = MergedTree::build(&tocs.iter().collect::<Vec<_>>());
            let shown: Vec<Vec<&str>> = layers
                .iter()
                .map(|l| l.iter().map(|e| e.name.as_str()).collect())
                .collect();
            let (images, tree) = match (images, tree) {
                (Ok(i), Ok(t)) => (i, t),
                (Err(_), Err(_)) => continue,
                (i, t) => panic!("{shown:?}: images {:?}, tables {:?}", i.err(), t.err()),
            };
            let v = ImageView::new(
                images
                    .into_iter()
                    .map(|i| Layer::open(Box::new(i.image)).unwrap())
                    .collect(),
            );
            assert_eq!(dump_view(&v), dump_tree(&tree), "{shown:?}");
            let root = v.node(VIEW_ROOT).unwrap().entry;
            let r = &tree.node(crate::ROOT).unwrap().entry;
            assert_eq!((root.mode, root.uid), (r.mode, r.uid), "{shown:?}");
        }
    }
}
