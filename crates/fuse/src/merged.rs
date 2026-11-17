// SPDX-License-Identifier: Apache-2.0
//! The root file system of an image as its tables of contents make it: the
//! layers applied in order, with the whiteouts (`.wh.name`, `.wh..wh..opq`)
//! and the hard links resolved, in memory.  What a build reads of the image
//! it works on; a container's root file system is the overlay of the images
//! of its layers (`layer_erofs`).

use std::collections::{BTreeMap, BTreeSet};
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
        name: name.to_string(),
        entry_type: TocEntryType::Dir,
        mode: 0o755,
        uid: 0,
        gid: 0,
        size: 0,
        digest: None,
        fsverity: None,
        offset: 0,
        end_offset: 0,
        chunk_digest: None,
        chunk_size: 0,
        chunk_offset: 0,
        chunk_type: None,
        link_name: None,
        mod_time: None,
        access_time: None,
        change_time: None,
        dev_major: None,
        dev_minor: None,
        xattrs: Default::default(),
    }
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

    /// The node at `path`, its symbolic links followed as the kernel
    /// follows them in the root of the image (`..` stays in it); None if
    /// it is not there, or if the links loop.
    pub fn resolve_following(&self, path: &str) -> Option<usize> {
        let mut todo: Vec<String> = path
            .split('/')
            .filter(|c| !c.is_empty() && *c != ".")
            .rev()
            .map(str::to_string)
            .collect();
        let mut stack: Vec<usize> = vec![ROOT];
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
            let node = self.nodes.get(next)?;
            if matches!(node.entry.entry_type, TocEntryType::Symlink) {
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

    /// Apply one more layer, above those applied (`build` does it for each).
    pub fn push_layer(&mut self, layer: usize, entries: &[TocEntry]) -> Result<(), String> {
        for e in entries {
            self.apply(ROOT, layer, e)
                .map_err(|m| format!("layer {layer}, `{}`: {m}", e.name))?;
        }
        Ok(())
    }

    /// The directory that holds `parts`, created if it is missing.  A
    /// component that is not a directory is replaced, like a lower layer's
    /// file under a new directory of an upper layer.
    fn parent_dir(&mut self, base: usize, layer: usize, parts: &[&str]) -> Result<usize, String> {
        let mut cur = base;
        for (depth, c) in parts.iter().enumerate() {
            match self.lookup(cur, c) {
                Some(n) if self.nodes[n].entry.entry_type == TocEntryType::Dir => cur = n,
                Some(n) if self.nodes[n].layer < layer => {
                    let new = self.new_node(layer, dir_entry(&parts[..=depth].join("/")));
                    self.unlink(cur, c);
                    self.link(cur, c, new);
                    cur = new;
                }
                Some(_) => return Err(format!("`{c}` is not a directory")),
                None => {
                    let new = self.new_node(layer, dir_entry(&parts[..=depth].join("/")));
                    self.link(cur, c, new);
                    cur = new;
                }
            }
        }
        Ok(cur)
    }

    fn new_node(&mut self, layer: usize, entry: TocEntry) -> usize {
        let nlink = if entry.entry_type == TocEntryType::Dir {
            2
        } else {
            1
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
        }
    }

    fn unlink(&mut self, parent: usize, name: &str) {
        if let Some(n) = self.nodes[parent].children.remove(name) {
            let node = &mut self.nodes[n];
            if node.entry.entry_type == TocEntryType::Dir {
                self.nodes[parent].nlink -= 1;
            } else {
                node.nlink = node.nlink.saturating_sub(1);
            }
        }
    }

    fn apply(&mut self, base: usize, layer: usize, e: &TocEntry) -> Result<(), String> {
        if e.entry_type == TocEntryType::Chunk {
            return Ok(());
        }
        let parts = components(&e.name)?;
        let Some((last, dirs)) = parts.split_last() else {
            // the root directory of the layer (`./`)
            if base == ROOT && e.entry_type == TocEntryType::Dir {
                let root = &mut self.nodes[ROOT];
                let name = std::mem::take(&mut root.entry.name);
                root.entry = e.clone();
                root.entry.name = name;
                root.entry
                    .xattrs
                    .retain(|k, _| !super::image_fs::hidden_xattr(k));
                root.layer = layer;
            }
            return Ok(());
        };
        let parent = self.parent_dir(base, layer, dirs)?;

        if e.entry_type == TocEntryType::Char && e.dev_major == Some(0) && e.dev_minor == Some(0) {
            // a whiteout of the images of the layers (a device 0:0)
            if let Some(n) = self.lookup(parent, last) {
                if self.nodes[n].layer < layer {
                    self.unlink(parent, last);
                }
            }
            return Ok(());
        }
        if *last == OPAQUE_MARKER {
            // The directory hides what the lower layers put in it.
            let lower: Vec<String> = self.nodes[parent]
                .children
                .iter()
                .filter(|(_, &n)| self.nodes[n].layer < layer)
                .map(|(k, _)| k.clone())
                .collect();
            for name in lower {
                self.unlink(parent, &name);
            }
            return Ok(());
        }
        if let Some(target) = last.strip_prefix(WHITEOUT_PREFIX) {
            if let Some(n) = self.lookup(parent, target) {
                if self.nodes[n].layer < layer {
                    self.unlink(parent, target);
                }
            }
            return Ok(());
        }

        if e.entry_type == TocEntryType::Hardlink {
            let target = e
                .link_name
                .as_deref()
                .ok_or_else(|| "hard link without a target".to_string())?;
            let t = self
                .resolve_from(base, target)
                .ok_or_else(|| format!("hard link to missing `{target}`"))?;
            if self.nodes[t].entry.entry_type == TocEntryType::Dir {
                return Err("hard link to a directory".into());
            }
            if let Some(old) = self.lookup(parent, last) {
                if old == t {
                    return Ok(());
                }
                self.unlink(parent, last);
            }
            self.nodes[t].nlink += 1;
            self.nodes[parent].children.insert(last.to_string(), t);
            return Ok(());
        }

        match self.lookup(parent, last) {
            Some(n)
                if e.entry_type == TocEntryType::Dir
                    && self.nodes[n].entry.entry_type == TocEntryType::Dir =>
            {
                // Same directory in a higher layer: new metadata, same content.
                let node = &mut self.nodes[n];
                let mut entry = e.clone();
                entry.name = node.entry.name.clone();
                node.entry = entry;
                node.layer = layer;
            }
            existing => {
                if existing.is_some() {
                    self.unlink(parent, last);
                }
                let entry = e.clone();
                let n = self.new_node(layer, entry);
                self.link(parent, last, n);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn e(name: &str, t: TocEntryType) -> TocEntry {
        let mut x = dir_entry(name);
        x.entry_type = t;
        x
    }

    fn file(name: &str, digest: &str) -> TocEntry {
        let mut x = e(name, TocEntryType::Reg);
        x.fsverity = Some(format!(
            "sha256-12:{}",
            digest.trim_start_matches("sha256:")
        ));
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
        // the root takes the metadata the layers give it, the children stay
        let t = MergedTree::build(&[&l0, &l1]).unwrap();
        let r = &t.node(ROOT).unwrap().entry;
        assert_eq!((r.mode, r.uid, r.name.as_str()), (0o750, 3, ""));
        assert_eq!(list(&t, "/"), ["a", "b"]);
        let mut top = e(".", TocEntryType::Dir);
        top.mode = 0o755;
        let l2 = toc(vec![top]);
        let t = MergedTree::build(&[&l0, &l1, &l2]).unwrap();
        assert_eq!(t.node(ROOT).unwrap().entry.mode, 0o755);
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
        let t = MergedTree::build(&[&l]).unwrap();
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
        assert_eq!(a.entry.fsverity.as_deref(), Some("sha256-12:d3"));
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
