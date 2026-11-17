// SPDX-License-Identifier: Apache-2.0
//! The root file system of an image as the tables of contents of its layers
//! make it, in memory: what the engine reads of an image without a container
//! (`ImageTree`), and what the changes of a copy are compared with.

use crate::view::{ImageTree, ViewNode};
use crate::MergedTree;
use std::collections::HashMap;
use velarx_storage::{Toc, TocEntryType};

/// The layers applied in order (whiteouts and hard links resolved).
pub struct MergedView {
    tree: MergedTree,
    /// The links a file has in the layer that made it: a name another layer
    /// replaced is still a link of the file that was below it.
    links: HashMap<usize, u32>,
}

impl MergedView {
    /// The layers, the lowest first.
    pub fn new(layers: &[&Toc]) -> Result<Self, String> {
        let tree = MergedTree::build(layers)?;
        let mut links = HashMap::new();
        for toc in layers {
            let mut count: HashMap<&str, u32> = HashMap::new();
            for e in &toc.entries {
                if e.entry_type == TocEntryType::Hardlink {
                    if let Some(t) = e.link_name.as_deref() {
                        *count.entry(t).or_insert(1) += 1;
                    }
                }
            }
            for e in &toc.entries {
                if let (TocEntryType::Hardlink, Some(t)) = (e.entry_type, e.link_name.as_deref()) {
                    if let Some(id) = tree.resolve(&e.name) {
                        links.insert(id, count[t]);
                    }
                }
            }
        }
        Ok(Self { tree, links })
    }
}

impl MergedView {
    /// The merged tree, to write it as a directory.
    pub fn tree(&self) -> &MergedTree {
        &self.tree
    }
}

impl ImageTree for MergedView {
    fn lookup(&self, dir: usize, name: &str) -> Option<usize> {
        if name.is_empty() || name == "." || name == ".." || name.contains('/') {
            return None;
        }
        self.tree.lookup(dir, name)
    }

    fn children(&self, dir: usize) -> std::io::Result<Vec<(String, usize)>> {
        Ok(self
            .tree
            .node(dir)
            .map(|n| n.children.iter().map(|(k, v)| (k.clone(), *v)).collect())
            .unwrap_or_default())
    }

    fn node(&self, id: usize) -> Option<ViewNode> {
        let n = self.tree.node(id)?;
        Some(ViewNode {
            entry: n.entry.clone(),
            layer: n.layer,
            nlink: self.links.get(&id).copied().unwrap_or(n.nlink),
            key: (0, id as u64),
        })
    }

    /// A copy carries no digest to check while a container runs.
    fn has_verity(&self) -> bool {
        false
    }
}
