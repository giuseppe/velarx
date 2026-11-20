// SPDX-License-Identifier: Apache-2.0
//! The root file system of an image as its tables of contents make it, in
//! memory: each layer as its image has it (`layer_erofs`), with its
//! whiteouts (`.wh.name`, `.wh..wh..opq`) and hard links resolved, laid over
//! the layers below it as the overlay of a container lays the images of its
//! layers.  What a build, a squash and the copy of the `vfs` driver read of
//! an image.

use crate::layer_erofs::LINK_BELOW;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use velarx_storage::{Toc, TocEntry, TocEntryType};

const WHITEOUT_PREFIX: &str = ".wh.";
const OPAQUE_MARKER: &str = ".wh..wh..opq";

#[derive(Debug, Clone)]
pub struct Node {
    pub entry: TocEntry,
    /// Index of the layer that last wrote the node.
    pub layer: usize,
    /// Children of a directory.
    pub children: BTreeMap<String, usize>,
    /// Names that refer to the node (hard links).
    pub nlink: u32,
}

#[derive(Debug)]
pub struct MergedTree {
    nodes: Vec<Node>,
}

pub const ROOT: usize = 0;

pub fn dir_entry(name: &str) -> TocEntry {
    TocEntry {
        mode: 0o755,
        ..TocEntry::new(name.to_string(), TocEntryType::Dir)
    }
}

/// Whether the entry is a whiteout of the image of a layer: a device 0:0.
fn is_whiteout(e: &TocEntry) -> bool {
    e.entry_type == TocEntryType::Char && e.dev_major == Some(0) && e.dev_minor == Some(0)
}

fn components(path: &str) -> Result<Vec<&str>, String> {
    let mut out = Vec::new();
    for c in path.split('/') {
        match c {
            "" | "." => {}
            ".." => return Err(format!("`{path}` goes up")),
            c => out.push(c),
        }
    }
    Ok(out)
}

impl MergedTree {
    fn new() -> Self {
        Self {
            nodes: vec![Node {
                entry: dir_entry(""),
                layer: 0,
                children: BTreeMap::new(),
                nlink: 2,
            }],
        }
    }

    pub fn node(&self, idx: usize) -> Option<&Node> {
        self.nodes.get(idx)
    }

    pub fn count(&self) -> usize {
        self.nodes.len()
    }

    /// The owners of the files: the uids and the gids in use.
    pub fn owners(&self) -> (BTreeSet<u32>, BTreeSet<u32>) {
        let mut uids = BTreeSet::new();
        let mut gids = BTreeSet::new();
        for n in &self.nodes {
            uids.insert(n.entry.uid);
            gids.insert(n.entry.gid);
        }
        (uids, gids)
    }

    pub fn lookup(&self, parent: usize, name: &str) -> Option<usize> {
        self.nodes.get(parent)?.children.get(name).copied()
    }

    /// The node at `path`, without following symbolic links.
    pub fn resolve(&self, path: &str) -> Option<usize> {
        self.resolve_from(ROOT, path)
    }

    fn resolve_from(&self, base: usize, path: &str) -> Option<usize> {
        let mut cur = base;
        for c in components(path).ok()? {
            cur = self.lookup(cur, c)?;
        }
        Some(cur)
    }

    /// Apply the layers, the lowest first.
    pub fn build(layers: &[&Toc]) -> Result<Self, String> {
        let entries: Vec<&[TocEntry]> = layers.iter().map(|t| t.entries.as_slice()).collect();
        Self::build_entries(&entries)
    }

    /// Apply the entries of the layers, the lowest first.
    pub fn build_entries(layers: &[&[TocEntry]]) -> Result<Self, String> {
        let mut tree = Self::new();
        for (i, entries) in layers.iter().enumerate() {
            tree.push_layer(i, entries)?;
        }
        Ok(tree)
    }

    /// Lay one more layer over those applied (`build` does it for each), as
    /// the overlay lays the image of a layer over the images below it: the
    /// layer as its image has it ([`MergedTree::of_layer`]), whose root and
    /// directories take the place of those below with their attributes and
    /// merge with them unless they are opaque, whose whiteouts hide what is
    /// below, and whose other files take the place of what is below.
    pub fn push_layer(&mut self, layer: usize, entries: &[TocEntry]) -> Result<(), String> {
        let (own, opaque) = Self::of_layer(entries).map_err(|m| format!("layer {layer}, {m}"))?;
        // (the node of the layer each file of its tree is: a file with
        // several names is one node)
        let mut made: HashMap<usize, usize> = HashMap::new();
        let mut todo = vec![(ROOT, ROOT)];
        while let Some((dir, from)) = todo.pop() {
            let name = std::mem::take(&mut self.nodes[dir].entry.name);
            self.nodes[dir].entry = TocEntry {
                name,
                ..own.nodes[from].entry.clone()
            };
            self.nodes[dir].layer = layer;
            if opaque.contains(&from) {
                let below: Vec<String> = self.nodes[dir].children.keys().cloned().collect();
                for name in below {
                    self.unlink(dir, &name);
                }
            }
            for (name, &c) in &own.nodes[from].children {
                let e = &own.nodes[c].entry;
                let below = self.lookup(dir, name);
                if e.entry_type == TocEntryType::Dir {
                    match below {
                        Some(n) if self.nodes[n].entry.entry_type == TocEntryType::Dir => {
                            todo.push((n, c));
                        }
                        _ => {
                            self.unlink(dir, name);
                            let n = self.new_node(layer, e.clone());
                            self.link(dir, name, n);
                            todo.push((n, c));
                        }
                    }
                    continue;
                }
                self.unlink(dir, name);
                if is_whiteout(e) {
                    continue;
                }
                let n = match made.get(&c) {
                    Some(&n) => n,
                    None => {
                        let n = self.new_node(layer, e.clone());
                        made.insert(c, n);
                        n
                    }
                };
                self.link(dir, name, n);
            }
        }
        Ok(())
    }

    /// The tree of one layer as its image has it (`layer_erofs`), and its
    /// opaque directories.  The last entry of a path wins.  The root is the
    /// `./` entry, or a plain directory (`dir_entry`), and so is a directory
    /// the layer has entries in and does not list, in the place of a file
    /// of the layer that has its name.  A hard link names a file of the
    /// layer.  A whiteout is a device 0:0, unless the layer has the name:
    /// a directory of the layer that it removes is opaque, as is one with
    /// an opaque marker.
    fn of_layer(entries: &[TocEntry]) -> Result<(Self, BTreeSet<usize>), String> {
        let mut by_path: BTreeMap<Vec<&str>, &TocEntry> = BTreeMap::new();
        let mut whiteouts: BTreeSet<Vec<&str>> = BTreeSet::new();
        let mut opaque_dirs: BTreeSet<Vec<&str>> = BTreeSet::new();
        for e in entries {
            if e.entry_type == TocEntryType::Chunk {
                continue;
            }
            let parts = components(&e.name).map_err(|m| format!("`{}`: {m}", e.name))?;
            match parts.split_last() {
                // (the root of an overlay is the merge of the roots of all its
                // layers, whatever the layers say: a marker in the root of a
                // layer hides nothing)
                Some((&OPAQUE_MARKER, [])) => {}
                Some((&OPAQUE_MARKER, dir)) => {
                    opaque_dirs.insert(dir.to_vec());
                }
                Some((last, dir)) if last.starts_with(WHITEOUT_PREFIX) => {
                    // (`.wh.`, `.wh..` and `.wh...` hide nothing)
                    let hidden = &last[WHITEOUT_PREFIX.len()..];
                    if !matches!(hidden, "" | "." | "..") {
                        whiteouts.insert([dir, &[hidden]].concat());
                    }
                }
                _ => {
                    by_path.insert(parts, e);
                }
            }
        }
        let mut t = Self::new();
        let mut links = Vec::new();
        for (parts, e) in by_path {
            let Some((last, dir)) = parts.split_last() else {
                if e.entry_type != TocEntryType::Dir {
                    return Err("the root of the layer is not a directory".into());
                }
                t.nodes[ROOT].entry = TocEntry {
                    name: String::new(),
                    ..e.clone()
                };
                t.nodes[ROOT]
                    .entry
                    .xattrs
                    .retain(|k, _| !super::image_fs::hidden_xattr(k));
                continue;
            };
            if e.entry_type == TocEntryType::Hardlink {
                links.push((parts, e));
                continue;
            }
            let parent = t.dir_at(dir);
            let n = t.new_node(0, e.clone());
            t.unlink(parent, last);
            t.link(parent, last, n);
        }
        // (a link may name another link: until no more of them resolve)
        while !links.is_empty() {
            let before = links.len();
            let mut unresolved = Vec::new();
            for (parts, e) in links {
                let target = e
                    .link_name
                    .as_deref()
                    .ok_or_else(|| format!("`{}`: a hard link without a target", e.name))?;
                let Some(n) = t.resolve(target) else {
                    unresolved.push((parts, e));
                    continue;
                };
                if t.nodes[n].entry.entry_type == TocEntryType::Dir {
                    return Err(format!("`{}`: a hard link to a directory", e.name));
                }
                let (last, dir) = parts.split_last().expect("the root is no link");
                let parent = t.dir_at(dir);
                t.unlink(parent, last);
                t.link(parent, last, n);
            }
            if let Some((_, e)) = unresolved.first().filter(|_| unresolved.len() == before) {
                let target = e.link_name.as_deref().unwrap_or_default();
                return Err(format!(
                    "`{}`: a hard link to `{target}`, {LINK_BELOW}",
                    e.name
                ));
            }
            links = unresolved;
        }
        let mut opaque = BTreeSet::new();
        for parts in whiteouts {
            let (last, dir) = parts.split_last().expect("a whiteout names a file");
            let parent = t.dir_at(dir);
            match t.lookup(parent, last) {
                Some(c) if t.nodes[c].entry.entry_type == TocEntryType::Dir => {
                    opaque.insert(c);
                }
                Some(_) => {}
                None => {
                    let mut w = dir_entry(&parts.join("/"));
                    (w.entry_type, w.mode, w.dev_major, w.dev_minor) =
                        (TocEntryType::Char, 0, Some(0), Some(0));
                    let n = t.new_node(0, w);
                    t.link(parent, last, n);
                }
            }
        }
        for parts in opaque_dirs {
            let d = t.dir_at(&parts);
            opaque.insert(d);
        }
        Ok((t, opaque))
    }

    /// The directory at `parts` of the tree of a layer, made plain where it
    /// is missing or is not a directory.
    fn dir_at(&mut self, parts: &[&str]) -> usize {
        let mut cur = ROOT;
        for (depth, c) in parts.iter().enumerate() {
            cur = match self.lookup(cur, c) {
                Some(n) if self.nodes[n].entry.entry_type == TocEntryType::Dir => n,
                _ => {
                    let n = self.new_node(0, dir_entry(&parts[..=depth].join("/")));
                    self.unlink(cur, c);
                    self.link(cur, c, n);
                    n
                }
            };
        }
        cur
    }

    fn new_node(&mut self, layer: usize, entry: TocEntry) -> usize {
        // (a directory has `.` and its name; a file counts its names)
        let nlink = if entry.entry_type == TocEntryType::Dir {
            2
        } else {
            0
        };
        self.nodes.push(Node {
            entry,
            layer,
            children: BTreeMap::new(),
            nlink,
        });
        self.nodes.len() - 1
    }

    fn link(&mut self, parent: usize, name: &str, node: usize) {
        self.nodes[parent].children.insert(name.to_string(), node);
        if self.nodes[node].entry.entry_type == TocEntryType::Dir {
            self.nodes[parent].nlink += 1;
        } else {
            self.nodes[node].nlink += 1;
        }
    }

    fn unlink(&mut self, parent: usize, name: &str) {
        if let Some(n) = self.nodes[parent].children.remove(name) {
            let node = &mut self.nodes[n];
            if node.entry.entry_type == TocEntryType::Dir {
                self.nodes[parent].nlink -= 1;
            } else {
                node.nlink -= 1;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use velarx_types::digest::{Algorithm, Digest};

    fn e(name: &str, t: TocEntryType) -> TocEntry {
        let mut x = dir_entry(name);
        x.entry_type = t;
        x
    }

    /// The fs-verity digest the tests give the content they call `tag`.
    fn verity(tag: &str) -> Digest {
        let sha = Digest::of(Algorithm::Sha256, tag.as_bytes());
        Digest::fsverity(Algorithm::Sha256, sha.raw()).unwrap()
    }

    fn file(name: &str, digest: &str) -> TocEntry {
        let mut x = e(name, TocEntryType::Reg);
        x.fsverity = Some(verity(digest.trim_start_matches("sha256:")));
        x.size = 1;
        x
    }

    fn toc(entries: Vec<TocEntry>) -> Toc {
        Toc {
            version: 1,
            entries,
            tar_split_digest: None,
        }
    }

    fn list(t: &MergedTree, path: &str) -> Vec<String> {
        let n = t.resolve(path).unwrap();
        t.node(n).unwrap().children.keys().cloned().collect()
    }

    #[test]
    fn test_root_directory_of_a_layer() {
        let d1 = format!("sha256:{}", "1".repeat(64));
        let mut root = e("./", TocEntryType::Dir);
        (root.mode, root.uid) = (0o750, 3);
        let l0 = toc(vec![root, file("a", &d1)]);
        let l1 = toc(vec![file("b", &d1)]);
        // the root is the one of the top layer, plain when it lists none:
        // the children stay
        let t = MergedTree::build(&[&l0]).unwrap();
        let r = &t.node(ROOT).unwrap().entry;
        assert_eq!((r.mode, r.uid, r.name.as_str()), (0o750, 3, ""));
        let t = MergedTree::build(&[&l0, &l1]).unwrap();
        let r = &t.node(ROOT).unwrap().entry;
        assert_eq!((r.mode, r.uid, r.name.as_str()), (0o755, 0, ""));
        assert_eq!(list(&t, "/"), ["a", "b"]);
        let mut top = e(".", TocEntryType::Dir);
        top.mode = 0o711;
        let l2 = toc(vec![top]);
        let t = MergedTree::build(&[&l0, &l1, &l2]).unwrap();
        assert_eq!(t.node(ROOT).unwrap().entry.mode, 0o711);
    }

    /// The attributes of the store (the overlay's and the label's) are not
    /// the root's: the tree hides them as the image of the layer does.
    #[test]
    fn test_the_root_of_a_layer_hides_the_attributes_of_the_store() {
        let mut root = e("./", TocEntryType::Dir);
        for name in ["user.keep", "user.overlay.opaque", "trusted.overlay.opaque"] {
            root.xattrs.insert(name.into(), "eQ==".into());
        }
        let t = MergedTree::build(&[&toc(vec![root])]).unwrap();
        let names: Vec<&String> = t.node(ROOT).unwrap().entry.xattrs.keys().collect();
        assert_eq!(names, ["user.keep"]);
    }

    #[test]
    fn test_a_directory_a_layer_does_not_list_is_plain() {
        let d1 = format!("sha256:{}", "1".repeat(64));
        let mut a = e("a", TocEntryType::Dir);
        (a.mode, a.uid) = (0o750, 1000);
        let l0 = toc(vec![a, file("a/x", &d1)]);
        let l1 = toc(vec![file("a/b", &d1)]);
        let t = MergedTree::build(&[&l0, &l1]).unwrap();
        let a = &t.node(t.resolve("a").unwrap()).unwrap();
        assert_eq!((a.entry.mode, a.entry.uid, a.layer), (0o755, 0, 1));
        assert_eq!(list(&t, "a"), ["b", "x"]);
        // a layer that lists it, in any order, has its own
        let mut own = e("a", TocEntryType::Dir);
        own.mode = 0o700;
        for entries in [
            vec![file("a/b", &d1), own.clone()],
            vec![own, file("a/b", &d1)],
        ] {
            let t = MergedTree::build(&[&l0, &toc(entries)]).unwrap();
            assert_eq!(t.node(t.resolve("a").unwrap()).unwrap().entry.mode, 0o700);
        }
    }

    #[test]
    fn test_resolve_following_links() {
        let mut rel = e("etc/os-release", TocEntryType::Symlink);
        rel.link_name = Some("../usr/lib/os-release".into());
        let mut abs = e("lib", TocEntryType::Symlink);
        abs.link_name = Some("/usr/lib".into());
        let mut up = e("escape", TocEntryType::Symlink);
        up.link_name = Some("../../../usr".into());
        let mut lp = e("loop", TocEntryType::Symlink);
        lp.link_name = Some("loop".into());
        let l = toc(vec![
            file("usr/lib/os-release", "d"),
            e("etc", TocEntryType::Dir),
            rel,
            abs,
            up,
            lp,
        ]);
        use crate::view::ImageTree;
        let t = crate::MergedView::new(&[&l]).unwrap();
        let target = t.resolve("usr/lib/os-release").unwrap();
        assert_eq!(t.resolve_following("/etc/os-release"), Some(target));
        assert_eq!(t.resolve_following("/lib/os-release"), Some(target));
        assert_eq!(t.resolve_following("/escape/lib"), t.resolve("usr/lib"));
        assert_eq!(t.resolve_following("/loop"), None);
        assert_eq!(t.resolve_following("/nosuch"), None);
        assert_eq!(t.resolve_following("/"), Some(ROOT));
    }

    #[test]
    fn test_layers_override_and_add() {
        let l0 = toc(vec![
            e("etc", TocEntryType::Dir),
            file("etc/a", "d1"),
            file("etc/b", "d2"),
        ]);
        let l1 = toc(vec![file("etc/a", "d3"), file("usr/bin/x", "d4")]);
        let t = MergedTree::build(&[&l0, &l1]).unwrap();
        assert_eq!(list(&t, "etc"), ["a", "b"]);
        let a = t.node(t.resolve("etc/a").unwrap()).unwrap();
        assert_eq!(a.entry.fsverity, Some(verity("d3")));
        assert_eq!(list(&t, "usr/bin"), ["x"]);
        assert_eq!(
            t.node(t.resolve("usr").unwrap()).unwrap().entry.entry_type,
            TocEntryType::Dir
        );
    }

    #[test]
    fn test_whiteouts_and_opaque_directories() {
        let l0 = toc(vec![
            file("d/a", "1"),
            file("d/b", "2"),
            file("o/c", "3"),
            file("w", "4"),
        ]);
        let l1 = toc(vec![
            file("d/.wh.a", "-"),
            file("o/.wh..wh..opq", "-"),
            file("o/new", "5"),
            file(".wh.w", "-"),
        ]);
        let t = MergedTree::build(&[&l0, &l1]).unwrap();
        assert_eq!(list(&t, "d"), ["b"]);
        assert_eq!(list(&t, "o"), ["new"]);
        assert!(t.resolve("w").is_none());
        assert!(t.resolve("d/.wh.a").is_none());
    }

    #[test]
    fn test_a_layer_removes_what_is_below_before_it_adds() {
        let d1 = format!("sha256:{}", "1".repeat(64));
        let l0 = toc(vec![
            e("d", TocEntryType::Dir),
            file("d/old", &d1),
            file("f", &d1),
            e("o", TocEntryType::Dir),
            file("o/old", &d1),
        ]);
        // the table lists the removals after what the layer makes: the
        // directory `d` the layer makes does not have what was below it
        let l1 = toc(vec![
            e("d", TocEntryType::Dir),
            file("d/new", &d1),
            file("o/new", &d1),
            file("f", &d1),
            e(".wh.d", TocEntryType::Reg),
            e("o/.wh..wh..opq", TocEntryType::Reg),
        ]);
        let t = MergedTree::build(&[&l0, &l1]).unwrap();
        assert_eq!(list(&t, "d"), ["new"]);
        assert_eq!(list(&t, "o"), ["new"]);
        assert!(t.resolve("f").is_some());
    }

    #[test]
    fn test_whiteout_does_not_remove_same_layer_files() {
        let l0 = toc(vec![file("x", "1")]);
        let l1 = toc(vec![file("x", "2"), file(".wh.x", "-")]);
        let t = MergedTree::build(&[&l0, &l1]).unwrap();
        assert!(t.resolve("x").is_some());
    }

    #[test]
    fn test_hard_links_share_a_node() {
        let mut h = e("usr/bin/y", TocEntryType::Hardlink);
        h.link_name = Some("usr/bin/x".into());
        let l0 = toc(vec![file("usr/bin/x", "1"), h]);
        let t = MergedTree::build(&[&l0]).unwrap();
        let (x, y) = (
            t.resolve("usr/bin/x").unwrap(),
            t.resolve("usr/bin/y").unwrap(),
        );
        assert_eq!(x, y);
        assert_eq!(t.node(x).unwrap().nlink, 2);
        let mut bad = e("z", TocEntryType::Hardlink);
        bad.link_name = Some("missing".into());
        assert!(MergedTree::build(&[&toc(vec![bad])]).is_err());
    }

    #[test]
    fn test_a_hard_link_names_a_file_of_its_layer() {
        // (the table lists the link before its target)
        let mut h = e("y", TocEntryType::Hardlink);
        h.link_name = Some("x".into());
        let t = MergedTree::build(&[&toc(vec![h.clone(), file("x", "1")])]).unwrap();
        assert_eq!(t.resolve("x"), t.resolve("y"));
        // one to a file of a layer below is an error, as the image of the
        // layer is
        let e = MergedTree::build(&[&toc(vec![file("x", "1")]), &toc(vec![h])]).unwrap_err();
        assert!(e.contains(LINK_BELOW), "{e}");
    }

    #[test]
    fn test_file_replaced_by_directory_and_back() {
        let l0 = toc(vec![
            file("a", "1"),
            e("b", TocEntryType::Dir),
            file("b/f", "2"),
        ]);
        let l1 = toc(vec![
            e("a", TocEntryType::Dir),
            file("a/x", "3"),
            file("b", "4"),
        ]);
        let t = MergedTree::build(&[&l0, &l1]).unwrap();
        assert_eq!(list(&t, "a"), ["x"]);
        let b = t.node(t.resolve("b").unwrap()).unwrap();
        assert_eq!(b.entry.entry_type, TocEntryType::Reg);
        assert!(b.children.is_empty());
    }

    #[test]
    fn test_directory_metadata_of_the_upper_layer_wins_and_children_stay() {
        let mut d1 = e("d", TocEntryType::Dir);
        d1.mode = 0o700;
        let l0 = toc(vec![e("d", TocEntryType::Dir), file("d/f", "1")]);
        let l1 = toc(vec![d1]);
        let t = MergedTree::build(&[&l0, &l1]).unwrap();
        let d = t.node(t.resolve("d").unwrap()).unwrap();
        assert_eq!(d.entry.mode, 0o700);
        assert_eq!(list(&t, "d"), ["f"]);
    }

    #[test]
    fn test_paths_that_go_up_are_refused() {
        assert!(MergedTree::build(&[&toc(vec![file("../x", "1")])]).is_err());
    }

    #[test]
    fn test_nlink_of_directories() {
        let l0 = toc(vec![
            e("a", TocEntryType::Dir),
            e("a/b", TocEntryType::Dir),
            e("a/c", TocEntryType::Dir),
        ]);
        let t = MergedTree::build(&[&l0]).unwrap();
        assert_eq!(t.node(t.resolve("a").unwrap()).unwrap().nlink, 4);
        assert_eq!(t.node(ROOT).unwrap().nlink, 3);
    }
}
