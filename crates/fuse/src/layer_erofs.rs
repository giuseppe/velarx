// SPDX-License-Identifier: Apache-2.0
//! The EROFS image of one layer, made from its table of contents alone: what
//! the overlay of a container has as one of its lower layers, the kernel
//! mounting it as root, the FUSE file system of the monitor serving the same
//! bytes rootless.  Made at the pull, kept in the store, shared by every
//! image that has the layer.
//!
//! The image is reproducible: the same entries make the same bytes, whatever
//! their order, the host, the time or the files the store has, so its
//! fs-verity digest is the same everywhere.  It is the layer as an overlay
//! reads a lower layer: a whiteout (`.wh.name`) is a character device 0:0,
//! an opaque directory (`.wh..wh..opq`, or a directory the layer both
//! removes and makes) has `trusted.overlay.opaque`, a regular file with
//! content is a stub of metadata (`trusted.overlay.metacopy`, with the
//! fs-verity digest of the file) that redirects (`trusted.overlay.redirect`)
//! to the object of the store, `/ab/cdef...`, in the data-only layers.  A
//! directory the layer has files in but does not list is a plain one (0755,
//! root): it takes the place of the one below, as when the layer is
//! extracted.  The overlay's own attributes and the SELinux labels of the
//! entries are not kept.  A hard link names a file of its layer: one to a
//! file of a layer below is an error, as when podman extracts the layer (an
//! image made with the layers below would depend on the image the layer is
//! pulled for, when it is the store's for every image that has the layer).
//!
//! The format is EROFS with 4096 bytes blocks, extended inodes, the
//! attributes in the inodes, the directories and symbolic links inline where
//! they fit, and the stubs as a single chunk that is a hole.

use std::collections::{BTreeMap, BTreeSet};
use velarx_storage::{FsVerityHashAlgorithm, TocEntry, TocEntryType};
use velarx_types::digest::Digest;

const BLOCK: usize = 4096;
const SUPERBLOCK_OFFSET: usize = 1024;
const SUPERBLOCK_SIZE: usize = 128;
const INODE_SIZE: usize = 64;
const SLOT: usize = 32;
const MAGIC: u32 = 0xE0F5_E1E2;
const FEATURE_INCOMPAT_CHUNKED_FILE: u32 = 0x4;
const LAYOUT_FLAT_PLAIN: u16 = 0;
const LAYOUT_FLAT_INLINE: u16 = 2;
const LAYOUT_CHUNK_BASED: u16 = 4;
/// One chunk of 2^(12 + 31) bytes: a file is one hole.
const CHUNK_FORMAT_SINGLE: u32 = 31;
const NULL_ADDR: u32 = u32::MAX;

const WHITEOUT_PREFIX: &str = ".wh.";
const OPAQUE_MARKER: &str = ".wh..wh..opq";

pub const XATTR_METACOPY: &str = "trusted.overlay.metacopy";
pub const XATTR_REDIRECT: &str = "trusted.overlay.redirect";
pub const XATTR_OPAQUE: &str = "trusted.overlay.opaque";

/// The prefixes of the attribute names EROFS knows, by index.
const PREFIXES: [(&[u8], u8); 6] = [
    (b"system.posix_acl_access", 2),
    (b"system.posix_acl_default", 3),
    (b"security.", 6),
    (b"trusted.", 4),
    (b"user.", 1),
    (b"lustre.", 5),
];

/// What a layer is, whatever the storage driver and whether its image is ever
/// kept: a property of its table of contents.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LayerIdentity {
    /// The fs-verity digest of its EROFS image, in the algorithm `alg` of the
    /// digests of the layer (what a sealed manifest states, push and the
    /// start check).
    pub erofs: String,
    /// The owners of its files, `[[uids], [gids]]` as JSON.
    pub owners: String,
}

/// The identity of the layer whose table of contents has `entries`: its
/// image is made in memory for the digest and dropped.
pub fn layer_identity(
    alg: velarx_types::digest::Algorithm,
    entries: &[TocEntry],
) -> Result<LayerIdentity, String> {
    layer_image(entries)?.identity(alg)
}

impl LayerImage {
    /// The identity of the layer of this image.
    pub fn identity(&self, alg: velarx_types::digest::Algorithm) -> Result<LayerIdentity, String> {
        Ok(LayerIdentity {
            erofs: velarx_storage::composefs_digest_of(alg, &self.image),
            owners: self.owners_json()?,
        })
    }

    /// The owners of the files, `[[uids], [gids]]` as JSON.
    pub fn owners_json(&self) -> Result<String, String> {
        serde_json::to_string(&self.owners).map_err(|e| e.to_string())
    }
}

/// The image of a layer and what is known of it with it.
pub struct LayerImage {
    pub image: Vec<u8>,
    /// The owners of its entries, sorted (uids, gids).
    pub owners: (Vec<u32>, Vec<u32>),
    /// Its regular files with content, by fs-verity digest
    /// (`erofs_tree::write_index`).
    pub index: Vec<u8>,
}

#[derive(Clone, Debug)]
enum Kind {
    Dir(BTreeMap<Vec<u8>, usize>),
    Reg { size: u64, digest: Option<Digest> },
    Symlink(Vec<u8>),
    Char(u32),
    Block(u32),
    Fifo,
}

#[derive(Clone, Debug)]
struct Node {
    kind: Kind,
    perm: u16,
    uid: u32,
    gid: u32,
    mtime: (u64, u32),
    xattrs: BTreeMap<Vec<u8>, Vec<u8>>,
}

impl Node {
    fn plain_dir() -> Self {
        Node {
            kind: Kind::Dir(BTreeMap::new()),
            perm: 0o755,
            uid: 0,
            gid: 0,
            mtime: (0, 0),
            xattrs: BTreeMap::new(),
        }
    }

    fn mode(&self) -> u16 {
        let fmt = match self.kind {
            Kind::Dir(_) => 0o040000,
            Kind::Reg { .. } => 0o100000,
            Kind::Symlink(_) => 0o120000,
            Kind::Char(_) => 0o020000,
            Kind::Block(_) => 0o060000,
            Kind::Fifo => 0o010000,
        };
        fmt | (self.perm & 0o7777)
    }

    fn file_type(&self) -> u8 {
        match self.kind {
            Kind::Reg { .. } => 1,
            Kind::Dir(_) => 2,
            Kind::Char(_) => 3,
            Kind::Block(_) => 4,
            Kind::Fifo => 5,
            Kind::Symlink(_) => 7,
        }
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

/// `new_encode_dev` of the kernel.
fn encode_dev(major: u32, minor: u32) -> u32 {
    (minor & 0xff) | ((major & 0xfff) << 8) | ((minor & !0xff) << 12)
}

fn mtime_of(e: &TocEntry) -> (u64, u32) {
    let (secs, nsec) = super::canonical::unix_time(&e.mod_time);
    (secs as u64, nsec)
}

fn digest_of(e: &TocEntry) -> Result<Digest, String> {
    e.verity()
        .and_then(|d| Digest::parse_fsverity(&d).ok())
        .ok_or_else(|| format!("`{}` has no fs-verity digest", e.name))
}

/// The value of `trusted.overlay.metacopy` with the fs-verity digest the
/// overlay checks where it is mounted with `verity=` (struct ovl_metacopy:
/// version 0, the length of the rest, flags 0, the fs-verity algorithm, the
/// digest): 4 and 32 bytes for SHA-256, 4 and 64 for SHA-512.
pub fn metacopy(digest: &Digest) -> Vec<u8> {
    let raw = digest.raw();
    let algorithm = FsVerityHashAlgorithm::of(digest.alg()) as u8;
    let mut v = vec![0, (4 + raw.len()) as u8, 0, algorithm];
    v.extend_from_slice(raw);
    v
}

/// The value of `trusted.overlay.redirect` of a stub: the path of the file
/// in the data-only layer of the store (`ab/cdef...`, the digest named: 62
/// digits after the directory for SHA-256, 126 for SHA-512).
pub fn redirect(digest: &Digest) -> Vec<u8> {
    let raw = digest.raw();
    format!("/{:02x}/{}", raw[0], hex::encode(&raw[1..])).into_bytes()
}

/// The tree of a layer: what its entries leave, as an overlay layer.
struct Tree {
    nodes: Vec<Node>,
}

const ROOT: usize = 0;

/// What the error of a hard link to a file the layer does not have says.
pub const LINK_BELOW: &str = "which the layer does not have";

/// The node an entry is.
fn node_of(e: &TocEntry) -> Result<Node, String> {
    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD;
    let mut node = Node {
        kind: Kind::Fifo,
        perm: (e.mode & 0o7777) as u16,
        uid: e.uid,
        gid: e.gid,
        mtime: mtime_of(e),
        xattrs: BTreeMap::new(),
    };
    for (k, v) in &e.xattrs {
        if super::image_fs::hidden_xattr(k) {
            continue;
        }
        let value = b64
            .decode(v)
            .map_err(|_| format!("`{}`: the attribute {k} is not base64", e.name))?;
        node.xattrs.insert(k.as_bytes().to_vec(), value);
    }
    node.kind = match e.entry_type {
        TocEntryType::Dir => Kind::Dir(BTreeMap::new()),
        TocEntryType::Reg if e.size == 0 => Kind::Reg {
            size: 0,
            digest: None,
        },
        TocEntryType::Reg => {
            let digest = digest_of(e)?;
            node.xattrs
                .insert(XATTR_METACOPY.as_bytes().to_vec(), metacopy(&digest));
            node.xattrs
                .insert(XATTR_REDIRECT.as_bytes().to_vec(), redirect(&digest));
            Kind::Reg {
                size: e.size,
                digest: Some(digest),
            }
        }
        TocEntryType::Symlink => match &e.link_name {
            Some(target) => Kind::Symlink(target.clone().into_bytes()),
            None => return Err(format!("`{}` is a symlink with no target", e.name)),
        },
        TocEntryType::Char => Kind::Char(encode_dev(
            e.dev_major.unwrap_or(0),
            e.dev_minor.unwrap_or(0),
        )),
        TocEntryType::Block => Kind::Block(encode_dev(
            e.dev_major.unwrap_or(0),
            e.dev_minor.unwrap_or(0),
        )),
        TocEntryType::Fifo => Kind::Fifo,
        TocEntryType::Hardlink | TocEntryType::Chunk => {
            return Err(format!("`{}` is not a file of its own", e.name))
        }
    };
    Ok(node)
}

impl Tree {
    fn build(entries: &[TocEntry]) -> Result<Self, String> {
        // the entries by path (the last of a path wins, as in the archive),
        // the whiteouts and the opaque directories
        let mut by_path: BTreeMap<Vec<&str>, &TocEntry> = BTreeMap::new();
        let mut whiteouts: BTreeSet<Vec<&str>> = BTreeSet::new();
        let mut opaque: BTreeSet<Vec<&str>> = BTreeSet::new();
        for e in entries {
            if e.entry_type == TocEntryType::Chunk {
                continue;
            }
            let parts = components(&e.name)?;
            match parts.last() {
                Some(&OPAQUE_MARKER) => {
                    opaque.insert(parts[..parts.len() - 1].to_vec());
                }
                Some(last) if last.starts_with(WHITEOUT_PREFIX) => {
                    // (`.wh.`, `.wh..` and `.wh...` hide nothing, as in the
                    // merged views: an entry of no name, `.` or `..` would be
                    // one of the directory itself)
                    let hidden = &last[WHITEOUT_PREFIX.len()..];
                    if !matches!(hidden, "" | "." | "..") {
                        let mut target = parts[..parts.len() - 1].to_vec();
                        target.push(hidden);
                        whiteouts.insert(target);
                    }
                }
                _ => {
                    by_path.insert(parts, e);
                }
            }
        }
        let mut tree = Tree {
            nodes: vec![Node::plain_dir()],
        };
        let mut links: Vec<(Vec<&str>, &TocEntry)> = Vec::new();
        // (parents before their children: the paths are sorted)
        for (parts, e) in &by_path {
            if e.entry_type == TocEntryType::Hardlink {
                links.push((parts.clone(), e));
                continue;
            }
            let node = node_of(e)?;
            if parts.is_empty() {
                if !matches!(node.kind, Kind::Dir(_)) {
                    return Err("the root of the layer is not a directory".into());
                }
                tree.nodes[ROOT] = node;
                continue;
            }
            let parent = tree.parent(parts)?;
            let idx = tree.nodes.len();
            tree.nodes.push(node);
            tree.link(parent, parts.last().unwrap(), idx)?;
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
                let Some(t) = tree.resolve(&components(target)?) else {
                    unresolved.push((parts, e));
                    continue;
                };
                if matches!(tree.nodes[t].kind, Kind::Dir(_)) {
                    return Err(format!("`{}`: a hard link to a directory", e.name));
                }
                let parent = tree.parent(&parts)?;
                tree.link(parent, parts.last().unwrap(), t)?;
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
        for parts in whiteouts {
            let parent = tree.parent(&parts)?;
            let name = parts.last().unwrap().as_bytes();
            match tree.child(parent, name) {
                // a directory of the layer that it removed first: it does
                // not merge with the one below
                Some(c) if matches!(tree.nodes[c].kind, Kind::Dir(_)) => {
                    tree.nodes[c]
                        .xattrs
                        .insert(XATTR_OPAQUE.as_bytes().to_vec(), b"y".to_vec());
                }
                // (an entry of the layer with the name stays: the order of
                // the archive says nothing)
                Some(_) => {}
                None => {
                    let idx = tree.nodes.len();
                    tree.nodes.push(Node {
                        kind: Kind::Char(0),
                        perm: 0,
                        ..Node::plain_dir()
                    });
                    tree.link(parent, parts.last().unwrap(), idx)?;
                }
            }
        }
        for parts in opaque {
            let mut dir = ROOT;
            for c in &parts {
                dir = tree.dir_child(dir, c)?;
            }
            tree.nodes[dir]
                .xattrs
                .insert(XATTR_OPAQUE.as_bytes().to_vec(), b"y".to_vec());
        }
        Ok(tree)
    }

    fn child(&self, dir: usize, name: &[u8]) -> Option<usize> {
        match &self.nodes[dir].kind {
            Kind::Dir(c) => c.get(name).copied(),
            _ => None,
        }
    }

    fn resolve(&self, parts: &[&str]) -> Option<usize> {
        let mut cur = ROOT;
        for c in parts {
            cur = self.child(cur, c.as_bytes())?;
        }
        Some(cur)
    }

    /// The directory `name` of `dir`, made plain if the layer does not list
    /// it (a file of that name gives way to it, as in an extraction).
    fn dir_child(&mut self, dir: usize, name: &str) -> Result<usize, String> {
        match self.child(dir, name.as_bytes()) {
            Some(c) if matches!(self.nodes[c].kind, Kind::Dir(_)) => Ok(c),
            _ => {
                let idx = self.nodes.len();
                self.nodes.push(Node::plain_dir());
                self.link(dir, name, idx)?;
                Ok(idx)
            }
        }
    }

    /// The directory that holds `parts`, made if it is not there.
    fn parent(&mut self, parts: &[&str]) -> Result<usize, String> {
        let mut cur = ROOT;
        for c in &parts[..parts.len().saturating_sub(1)] {
            cur = self.dir_child(cur, c)?;
        }
        Ok(cur)
    }

    fn link(&mut self, dir: usize, name: &str, node: usize) -> Result<(), String> {
        if name.len() > 255 {
            return Err(format!("the name `{name}` is longer than 255 bytes"));
        }
        let Kind::Dir(children) = &mut self.nodes[dir].kind else {
            return Err(format!("the parent of `{name}` is not a directory"));
        };
        children.insert(name.as_bytes().to_vec(), node);
        Ok(())
    }

    fn owners(&self) -> (Vec<u32>, Vec<u32>) {
        let uids: BTreeSet<u32> = self.nodes.iter().map(|n| n.uid).collect();
        let gids: BTreeSet<u32> = self.nodes.iter().map(|n| n.gid).collect();
        (uids.into_iter().collect(), gids.into_iter().collect())
    }
}

/// Where the parts of an inode go.
struct Placed {
    /// The order of the inode, from the root: its nid comes from `offset`.
    offset: usize,
    xattrs: Vec<u8>,
    layout: u16,
    /// The bytes after the inode and its attributes.
    inline: usize,
    /// The data in blocks of their own.
    blocks: usize,
    blkaddr: u32,
    size: u64,
}

/// The entries of a directory, `.` and `..` with them, sorted by name.
fn dir_names(node: &Node) -> Vec<(Vec<u8>, Option<usize>)> {
    let Kind::Dir(children) = &node.kind else {
        return Vec::new();
    };
    let mut all: Vec<(Vec<u8>, Option<usize>)> = children
        .iter()
        .map(|(n, &c)| (n.clone(), Some(c)))
        .chain([(b".".to_vec(), None), (b"..".to_vec(), None)])
        .collect();
    all.sort_by(|a, b| a.0.cmp(&b.0));
    all
}

/// The entries of a directory in blocks: as many as fit in each.
fn dir_blocks(names: &[(Vec<u8>, Option<usize>)]) -> Vec<std::ops::Range<usize>> {
    let mut out = Vec::new();
    let (mut start, mut used) = (0, 0);
    for (i, (name, _)) in names.iter().enumerate() {
        let need = 12 + name.len();
        if used + need > BLOCK {
            out.push(start..i);
            (start, used) = (i, 0);
        }
        used += need;
    }
    out.push(start..names.len());
    out
}

fn dir_block_len(names: &[(Vec<u8>, Option<usize>)]) -> usize {
    names.iter().map(|(n, _)| 12 + n.len()).sum()
}

fn xattr_body(xattrs: &BTreeMap<Vec<u8>, Vec<u8>>) -> Result<Vec<u8>, String> {
    if xattrs.is_empty() {
        return Ok(Vec::new());
    }
    // the header: no name filter, no shared attribute
    let mut out = vec![0u8; 12];
    for (name, value) in xattrs {
        let (suffix, index) = PREFIXES
            .iter()
            .find(|(p, _)| name.starts_with(p))
            .map_or((&name[..], 0), |(p, i)| (&name[p.len()..], *i));
        let name_len = u8::try_from(suffix.len())
            .map_err(|_| format!("the attribute name {} is too long", name.escape_ascii()))?;
        let value_len = u16::try_from(value.len())
            .map_err(|_| format!("the attribute {} is too big", name.escape_ascii()))?;
        out.push(name_len);
        out.push(index);
        out.extend_from_slice(&value_len.to_le_bytes());
        out.extend_from_slice(suffix);
        out.extend_from_slice(value);
        out.resize(out.len().next_multiple_of(4), 0);
    }
    Ok(out)
}

/// The image of the layer whose table of contents has `entries`.
pub fn layer_image(entries: &[TocEntry]) -> Result<LayerImage, String> {
    let tree = Tree::build(entries)?;
    let owners = tree.owners();
    let mut index = Vec::new();
    // the inodes in the order they are reached from the root, a directory's
    // entries by name; a node with several names once
    let mut order: Vec<usize> = Vec::new();
    let mut seen = vec![false; tree.nodes.len()];
    let mut parent = vec![ROOT; tree.nodes.len()];
    let mut nlink = vec![0u32; tree.nodes.len()];
    let mut queue = std::collections::VecDeque::from([ROOT]);
    seen[ROOT] = true;
    nlink[ROOT] = 2;
    while let Some(n) = queue.pop_front() {
        order.push(n);
        if let Kind::Dir(children) = &tree.nodes[n].kind {
            for &c in children.values() {
                if matches!(tree.nodes[c].kind, Kind::Dir(_)) {
                    nlink[n] += 1;
                    nlink[c] = 2;
                    parent[c] = n;
                } else {
                    nlink[c] += 1;
                }
                if !seen[c] {
                    seen[c] = true;
                    queue.push_back(c);
                }
            }
        }
    }
    // the size of each record (inode, attributes, inline data), and where
    // it goes: a record that fits in a block is not cut by its end
    let mut placed: Vec<Option<Placed>> = (0..tree.nodes.len()).map(|_| None).collect();
    let mut cursor = SUPERBLOCK_OFFSET + SUPERBLOCK_SIZE;
    let mut chunked = false;
    for &n in &order {
        let node = &tree.nodes[n];
        let xattrs = xattr_body(&node.xattrs)?;
        let (layout, size, tail, blocks) = match &node.kind {
            Kind::Dir(_) => {
                let names = dir_names(node);
                let split = dir_blocks(&names);
                let last = dir_block_len(&names[split.last().unwrap().clone()]);
                let full = split.len() - 1;
                let size = (full * BLOCK + last) as u64;
                if INODE_SIZE + xattrs.len() + last <= BLOCK && last < BLOCK {
                    (LAYOUT_FLAT_INLINE, size, last, full)
                } else {
                    (LAYOUT_FLAT_PLAIN, size, 0, split.len())
                }
            }
            Kind::Symlink(target) => {
                if target.len() > BLOCK {
                    return Err("a symbolic link longer than a block".into());
                }
                if INODE_SIZE + xattrs.len() + target.len() <= BLOCK && target.len() < BLOCK {
                    (LAYOUT_FLAT_INLINE, target.len() as u64, target.len(), 0)
                } else {
                    (LAYOUT_FLAT_PLAIN, target.len() as u64, 0, 1)
                }
            }
            Kind::Reg {
                size,
                digest: Some(d),
            } => {
                chunked = true;
                if index
                    .first()
                    .is_some_and(|(first, _): &(Digest, u64)| first.alg() != d.alg())
                {
                    return Err(
                        "the layer has files with fs-verity digests of two algorithms".into(),
                    );
                }
                index.push((*d, *size));
                (LAYOUT_CHUNK_BASED, *size, 4, 0)
            }
            _ => (LAYOUT_FLAT_PLAIN, 0, 0, 0),
        };
        let record = INODE_SIZE + xattrs.len() + tail;
        cursor = cursor.next_multiple_of(SLOT);
        if record <= BLOCK && cursor % BLOCK + record > BLOCK {
            cursor = cursor.next_multiple_of(BLOCK);
        }
        placed[n] = Some(Placed {
            offset: cursor,
            xattrs,
            layout,
            inline: tail,
            blocks,
            blkaddr: 0,
            size,
        });
        cursor += record;
    }
    // the blocks of data after the inodes
    let mut block = cursor.div_ceil(BLOCK);
    for &n in &order {
        let p = placed[n].as_mut().unwrap();
        if p.blocks > 0 {
            p.blkaddr = u32::try_from(block).map_err(|_| "the image is too big".to_string())?;
            block += p.blocks;
        }
    }
    let total = block.max(1);
    let nid = |n: usize| (placed[n].as_ref().unwrap().offset / SLOT) as u64;
    let root_nid = u16::try_from(nid(ROOT)).map_err(|_| "the root is too far".to_string())?;
    let mut image = vec![0u8; total * BLOCK];
    {
        let sb = &mut image[SUPERBLOCK_OFFSET..SUPERBLOCK_OFFSET + SUPERBLOCK_SIZE];
        sb[0..4].copy_from_slice(&MAGIC.to_le_bytes());
        sb[12] = 12; // blkszbits
        sb[14..16].copy_from_slice(&root_nid.to_le_bytes());
        sb[16..24].copy_from_slice(&(order.len() as u64).to_le_bytes());
        sb[36..40].copy_from_slice(&(total as u32).to_le_bytes());
        let incompat = if chunked {
            FEATURE_INCOMPAT_CHUNKED_FILE
        } else {
            0
        };
        sb[80..84].copy_from_slice(&incompat.to_le_bytes());
    }
    for (ino, &n) in order.iter().enumerate() {
        let node = &tree.nodes[n];
        let p = placed[n].as_ref().unwrap();
        let u: u32 = match &node.kind {
            Kind::Char(d) | Kind::Block(d) => *d,
            Kind::Reg {
                digest: Some(_), ..
            } => CHUNK_FORMAT_SINGLE,
            _ => p.blkaddr,
        };
        let icount: u16 = if p.xattrs.is_empty() {
            0
        } else {
            u16::try_from((p.xattrs.len() - 12) / 4 + 1)
                .map_err(|_| "too many attributes".to_string())?
        };
        let at = p.offset;
        let h = &mut image[at..at + INODE_SIZE];
        h[0..2].copy_from_slice(&(1 | (p.layout << 1)).to_le_bytes());
        h[2..4].copy_from_slice(&icount.to_le_bytes());
        h[4..6].copy_from_slice(&node.mode().to_le_bytes());
        h[8..16].copy_from_slice(&p.size.to_le_bytes());
        h[16..20].copy_from_slice(&u.to_le_bytes());
        h[20..24].copy_from_slice(&(ino as u32 + 1).to_le_bytes());
        h[24..28].copy_from_slice(&node.uid.to_le_bytes());
        h[28..32].copy_from_slice(&node.gid.to_le_bytes());
        h[32..40].copy_from_slice(&node.mtime.0.to_le_bytes());
        h[40..44].copy_from_slice(&node.mtime.1.to_le_bytes());
        h[44..48].copy_from_slice(&nlink[n].to_le_bytes());
        let mut pos = at + INODE_SIZE;
        image[pos..pos + p.xattrs.len()].copy_from_slice(&p.xattrs);
        pos += p.xattrs.len();
        match &node.kind {
            Kind::Dir(_) => {
                let names = dir_names(node);
                let split = dir_blocks(&names);
                let nids: Vec<(u64, u8)> = names
                    .iter()
                    .map(|(name, c)| match (name.as_slice(), c) {
                        (_, Some(c)) => (nid(*c), tree.nodes[*c].file_type()),
                        (b".", None) => (nid(n), 2),
                        _ => (nid(parent[n]), 2),
                    })
                    .collect();
                for (i, range) in split.iter().enumerate() {
                    let start = match (p.inline > 0, i + 1 == split.len()) {
                        (true, true) => pos,
                        _ => (p.blkaddr as usize + i) * BLOCK,
                    };
                    let mut name_at = 12 * range.len();
                    for (k, j) in range.clone().enumerate() {
                        let d = start + 12 * k;
                        image[d..d + 8].copy_from_slice(&nids[j].0.to_le_bytes());
                        image[d + 8..d + 10].copy_from_slice(&(name_at as u16).to_le_bytes());
                        image[d + 10] = nids[j].1;
                        let name = &names[j].0;
                        image[start + name_at..start + name_at + name.len()].copy_from_slice(name);
                        name_at += name.len();
                    }
                }
            }
            Kind::Symlink(target) => {
                let at = if p.inline > 0 {
                    pos
                } else {
                    p.blkaddr as usize * BLOCK
                };
                image[at..at + target.len()].copy_from_slice(target);
            }
            Kind::Reg {
                digest: Some(_), ..
            } => image[pos..pos + 4].copy_from_slice(&NULL_ADDR.to_le_bytes()),
            _ => {}
        }
    }
    // (a layer has the digests of one algorithm: the one of its index)
    let alg = index
        .first()
        .map_or(velarx_types::digest::Algorithm::Sha256, |(d, _)| d.alg());
    index.sort_unstable();
    index.dedup_by(|b, a| a.0 == b.0);
    Ok(LayerImage {
        image,
        owners,
        index: super::erofs_tree::write_index(alg, index.into_iter().map(|(d, size)| (d, size, 0))),
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    fn entry(name: &str, t: TocEntryType) -> TocEntry {
        let mut e = crate::dir_entry(name);
        e.entry_type = t;
        e.mode = if t == TocEntryType::Dir { 0o755 } else { 0o644 };
        e.mod_time = Some("2024-01-02T03:04:05.25+00:00".into());
        e
    }

    #[test]
    fn a_symlink_with_no_target_is_refused() {
        let link = entry("usr/l", TocEntryType::Symlink);
        let e = node_of(&link).err().unwrap();
        assert!(e.contains("usr/l") && e.contains("no target"), "{e}");
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

    pub(crate) fn sample() -> Vec<TocEntry> {
        let mut link = entry("usr/bin/sh", TocEntryType::Symlink);
        link.link_name = Some("busybox".into());
        let mut hard = entry("usr/bin/ls", TocEntryType::Hardlink);
        hard.link_name = Some("usr/bin/busybox".into());
        let mut dev = entry("dev/null", TocEntryType::Char);
        (dev.dev_major, dev.dev_minor) = (Some(1), Some(3));
        let mut owned = file("home/u/f", 3, 7);
        (owned.uid, owned.gid) = (1000, 100);
        let mut cap = file("usr/bin/ping", 4, 9);
        cap.xattrs.insert(
            "security.capability".into(),
            "AQAAAgAgAAAAAAAAAAAAAAAAAAA=".into(),
        );
        // the image's own overlay attributes are not kept
        cap.xattrs
            .insert("trusted.overlay.opaque".into(), "eQ==".into());
        let mut long = entry("usr/long", TocEntryType::Symlink);
        long.link_name = Some("x".repeat(3000));
        let mut many: Vec<TocEntry> = (0..600)
            .map(|i| file(&format!("many/file-with-a-long-name-{i:04}"), 5, i + 1))
            .collect();
        many.push(entry("many", TocEntryType::Dir));
        let mut out = vec![
            entry("usr", TocEntryType::Dir),
            entry("usr/bin", TocEntryType::Dir),
            file("usr/bin/busybox", 1, 1000),
            hard,
            link,
            long,
            cap,
            dev,
            file("etc/implied/f", 2, 5),
            owned,
            entry("empty", TocEntryType::Reg),
            entry("fifo", TocEntryType::Fifo),
            entry("var/.wh.gone", TocEntryType::Reg),
            entry("opt", TocEntryType::Dir),
            entry("opt/.wh..wh..opq", TocEntryType::Reg),
            entry("srv/.wh.d", TocEntryType::Reg),
            entry("srv/d", TocEntryType::Dir),
            file("srv/d/x", 6, 1),
        ];
        out.append(&mut many);
        out
    }

    /// Each node of an image read with the reader of composefs-rs: path,
    /// mode, owners, size, link, device, attributes.
    pub(crate) fn listing(image: &[u8]) -> Vec<String> {
        use composefs::erofs::reader::{Image, InodeHeader};
        let img = Image::open(image).unwrap();
        let mut out = Vec::new();
        let mut todo = vec![(img.sb.root_nid.get() as u64, String::new())];
        while let Some((nid, path)) = todo.pop() {
            let inode = img.inode(nid).unwrap();
            let (uid, gid, mtime) = crate::erofs_read::owner_time(&img, &inode);
            let mut xs: Vec<String> = crate::erofs_read::xattrs(&img, &inode)
                .into_iter()
                .map(|(n, v)| format!("{}={}", n.escape_ascii(), v.escape_ascii()))
                .collect();
            xs.sort();
            let mode = inode.mode().0.get();
            out.push(format!(
                "{path} {mode:o} {uid}:{gid} {mtime} {} {} {} {:?}",
                inode.size(),
                inode.nlink(),
                inode.u(),
                xs
            ));
            if mode & 0o170000 == 0o040000 {
                for (name, child) in crate::erofs_read::dir_entries(&img, &inode).unwrap() {
                    todo.push((child, format!("{path}/{}", name.escape_ascii())));
                }
            }
        }
        out.sort();
        out
    }

    /// The identity of a layer is what manifests state and what every store
    /// of every driver records for the same layer, made by this velarx or a
    /// later one: its digest is pinned here, so that a change of the EROFS
    /// that is made, or of how it is measured, is seen (it would make the
    /// layers pushed before it differ from the same layers pulled after).
    #[test]
    fn the_identity_of_a_layer_is_pinned() {
        use velarx_types::digest::Algorithm;
        let entries = sample();
        let id = layer_identity(Algorithm::Sha256, &entries).unwrap();
        assert_eq!(
            id.erofs,
            velarx_storage::composefs_digest_of(
                Algorithm::Sha256,
                &layer_image(&entries).unwrap().image
            )
        );
        assert_eq!(
            id.erofs,
            "sha256:bb63dffe4723e8233e3df8cc28a7c43313192b90fb9fe84f5715f4e6d62d581e"
        );
        assert_eq!(id.owners, "[[0,1000],[0,100]]");
        let id512 = layer_identity(Algorithm::Sha512, &entries).unwrap();
        assert_eq!(
            id512.erofs,
            "sha512:33b525f9233cded27a3a06d56e1e0c7dc47f0653b444b715729c53f7434f5fe4c9bcd7d6df5c7623f0769452bac20b22bf8e0e8118361c0559acc4f5f4dff574"
        );
    }

    #[test]
    fn the_image_is_the_same_whatever_the_order_of_the_entries() {
        let entries = sample();
        let a = layer_image(&entries).unwrap();
        let mut reversed = entries.clone();
        reversed.reverse();
        let b = layer_image(&reversed).unwrap();
        let mut shuffled = entries.clone();
        // a fixed permutation: every third entry first
        shuffled.sort_by_key(|e| (e.name.len() % 3, e.name.clone()));
        let c = layer_image(&shuffled).unwrap();
        assert!(a.image == b.image && a.image == c.image);
        assert_eq!(a.index, b.index);
        assert_eq!(
            velarx_storage::fsverity_digest_of(velarx_types::digest::Algorithm::Sha256, &a.image),
            velarx_storage::fsverity_digest_of(velarx_types::digest::Algorithm::Sha256, &c.image)
        );
    }

    /// A whiteout of no name, of `.` or of `..` hides nothing: the
    /// directory gets no entry of those names.
    #[test]
    fn a_whiteout_of_no_name_hides_nothing() {
        let entries = vec![
            entry("d", TocEntryType::Dir),
            entry("d/.wh.", TocEntryType::Reg),
            entry("d/.wh..", TocEntryType::Reg),
            entry("d/.wh...", TocEntryType::Reg),
            entry("d/.wh.x", TocEntryType::Reg),
        ];
        let list = listing(&layer_image(&entries).unwrap().image);
        let names: Vec<&str> = list
            .iter()
            .filter_map(|l| l.split(' ').next())
            .filter(|p| p.starts_with("/d/"))
            .collect();
        assert_eq!(names, ["/d/x"], "{list:#?}");
    }

    #[test]
    fn the_image_reads_back_as_an_overlay_layer() {
        let built = layer_image(&sample()).unwrap();
        let list = listing(&built.image);
        let find = |p: &str| {
            list.iter()
                .find(|l| l.starts_with(&format!("{p} ")))
                .unwrap_or_else(|| panic!("{p} not in {list:#?}"))
                .clone()
        };
        let busybox = find("/usr/bin/busybox");
        assert!(
            busybox.contains("100644 0:0 1704164645 1000 2 31"),
            "{busybox}"
        );
        assert!(
            busybox.contains(&format!("trusted.overlay.redirect=/01/{}", "01".repeat(31))),
            "{busybox}"
        );
        // (version 0, 4 + 32 bytes, no flags, sha256, the digest)
        assert!(
            busybox.contains(r"trusted.overlay.metacopy=\\x00$\\x00\\x01\\x01"),
            "{busybox}"
        );
        // the hard link is the same inode
        assert_eq!(
            find("/usr/bin/ls").split_once(' ').unwrap().1,
            busybox.split_once(' ').unwrap().1
        );
        assert!(find("/usr/bin/sh").starts_with("/usr/bin/sh 120644 0:0 1704164645 7 1"));
        assert!(find("/usr/long").contains(" 3000 "));
        let ping = find("/usr/bin/ping");
        assert!(ping.contains("security.capability="), "{ping}");
        assert!(!ping.contains("opaque"), "{ping}");
        assert!(find("/dev/null").contains(&format!(" {}", 259)));
        // the whiteout, the opaque directories, the plain implied directory
        assert!(find("/var/gone").starts_with("/var/gone 20000 0:0 0 0 1 0"));
        assert!(find("/opt").contains("trusted.overlay.opaque=y"));
        assert!(find("/srv/d").contains("trusted.overlay.opaque=y"));
        assert!(find("/etc/implied").starts_with("/etc/implied 40755 0:0 0 "));
        assert!(find("/home/u/f").contains(" 1000:100 "));
        assert_eq!(built.owners, (vec![0, 1000], vec![0, 100]));
        // a directory of several blocks
        let many = find("/many");
        assert!(many.contains("40755"), "{many}");
        assert_eq!(list.iter().filter(|l| l.starts_with("/many/")).count(), 600);
        let index = crate::erofs_tree::Index::from_bytes(Box::new(built.index)).unwrap();
        assert_eq!(index.count(), 6);
    }

    /// What erofs-utils says of the image, where it is installed (and, with
    /// `VELARX_EROFS_SAMPLE`, the image is left there to be mounted).
    #[test]
    fn fsck_erofs_finds_the_image_sound() {
        let built = layer_image(&sample()).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("layer.erofs");
        std::fs::write(&path, &built.image).unwrap();
        if let Some(keep) = std::env::var_os("VELARX_EROFS_SAMPLE") {
            std::fs::write(keep, &built.image).unwrap();
        }
        let out = match std::process::Command::new("fsck.erofs")
            .arg("--extract")
            .arg(&path)
            .output()
        {
            Ok(o) => o,
            Err(_) => return eprintln!("skipped: no fsck.erofs"),
        };
        assert!(
            out.status.success(),
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }

    /// A link may name another link of the layer, whatever their order; a
    /// link to a file the layer does not have (of a layer below) is an
    /// error, as when podman extracts the layer: the image of a layer is
    /// the same in every image that has it.
    #[test]
    fn a_hard_link_names_a_file_of_its_layer() {
        let mut a = entry("a/first", TocEntryType::Hardlink);
        a.link_name = Some("b/second".into());
        let mut b = entry("b/second", TocEntryType::Hardlink);
        b.link_name = Some("c/file".into());
        let built = layer_image(&[a, b, file("c/file", 1, 3)]).unwrap();
        let list = listing(&built.image);
        let of = |p: &str| {
            let l = list
                .iter()
                .find(|l| l.starts_with(&format!("{p} ")))
                .unwrap();
            l.split_once(' ').unwrap().1.to_string()
        };
        assert_eq!(of("/a/first"), of("/c/file"));
        assert_eq!(of("/b/second"), of("/c/file"));
        assert!(of("/c/file").contains(" 3 3 "), "{}", of("/c/file"));
        let mut below = entry("etc/g", TocEntryType::Hardlink);
        below.link_name = Some("etc/f".into());
        let e = layer_image(&[entry("etc", TocEntryType::Dir), below])
            .err()
            .unwrap();
        assert!(
            e.contains("`etc/g`: a hard link to `etc/f`, which the layer does not have"),
            "{e}"
        );
    }

    #[test]
    fn what_cannot_be_a_layer_is_an_error() {
        let mut hard = entry("a", TocEntryType::Hardlink);
        hard.link_name = Some("missing".into());
        let e = layer_image(&[hard]).err().unwrap();
        assert!(e.contains("which the layer does not have"), "{e}");
        let e = layer_image(&[entry("../x", TocEntryType::Reg)])
            .err()
            .unwrap();
        assert!(e.contains("goes up"), "{e}");
        let mut f = file("f", 1, 1);
        f.fsverity = None;
        assert!(layer_image(&[f]).is_err());
    }
}

#[cfg(test)]
mod corrupt {
    use crate::erofs_tree::{Layer, Layers, Stubs};
    use crate::tree::Tree;
    use crate::view::{ImageTree, ImageView, VIEW_ROOT};

    /// Every node reachable from the root, each asked what the FUSE file
    /// system and the view ask; at most `max` nodes.
    fn walk(tree: &Layers, max: usize) {
        let mut todo = vec![1u64];
        let mut seen = std::collections::HashSet::new();
        while let Some(ino) = todo.pop() {
            if !seen.insert(ino) || seen.len() > max {
                continue;
            }
            let _ = tree.attr(ino);
            let _ = tree.readlink(ino);
            let _ = tree.file(ino);
            let _ = tree.xattrs(ino);
            let mut names = Vec::new();
            let _ = tree.readdir(ino, 0, &mut |child, _, name| {
                names.push(String::from_utf8_lossy(name).into_owned());
                todo.push(child);
                names.len() > 64
            });
            for n in names {
                let _ = tree.lookup(ino, &n);
            }
        }
    }

    fn view_walk(view: &ImageView, max: usize) {
        let mut todo = vec![VIEW_ROOT];
        let mut n = 0;
        while let Some(id) = todo.pop() {
            n += 1;
            if n > max {
                return;
            }
            let _ = view.node(id);
            todo.extend(
                view.children(id)
                    .into_iter()
                    .flatten()
                    .take(64)
                    .map(|(_, c)| c),
            );
        }
        let _ = view.resolve_following("usr/bin/sh/../../etc/x");
    }

    /// The image at `path` opened and checked as the image server does.
    fn opened(path: &std::path::Path, accepted: &[String]) -> std::io::Result<Layer> {
        let file = crate::composefs::open_checked_layer_image(path, accepted, false)?;
        Layer::of_checked_file(file, path)
    }

    /// The FUSE file system reads the image it opened and checked, from
    /// the mapping of that descriptor: the name renamed over, then removed,
    /// changes nothing of what it serves.
    #[test]
    fn the_fuse_file_system_reads_the_open_image_not_its_path() {
        let d = tempfile::tempdir().unwrap();
        let image = d.path().join("layer.erofs");
        let good = super::layer_image(&super::tests::sample()).unwrap().image;
        std::fs::write(&image, &good).unwrap();
        let accepted = [velarx_storage::composefs_digest_of(
            velarx_types::digest::Algorithm::Sha256,
            &good,
        )];
        let layer = opened(&image, &accepted).unwrap();
        let other = d.path().join("other");
        std::fs::write(&other, b"not an image").unwrap();
        std::fs::rename(&other, &image).unwrap();
        std::fs::remove_file(&image).unwrap();
        let tree = Layers::new(vec![layer], None, true, Stubs::Every);
        let mut ino = tree.lookup(1, "layer1").unwrap();
        for c in ["usr", "bin", "ping"] {
            ino = tree.lookup(ino, c).unwrap();
        }
        assert!(tree.attr(ino).is_some());
        assert!(!tree.xattrs(ino).unwrap().is_empty());
        walk(&tree, 2000);
    }

    /// An image file cut short or with bytes changed (a store without
    /// fs-verity, not enforced) is an error or another tree for the FUSE
    /// file system, never a crash.
    #[test]
    fn a_cut_or_corrupt_image_file_is_an_error_not_a_crash() {
        let good = super::layer_image(&super::tests::sample()).unwrap().image;
        let mut changed = good.clone();
        changed[super::SUPERBLOCK_OFFSET + super::SUPERBLOCK_SIZE..][..64].fill(0xff);
        let d = tempfile::tempdir().unwrap();
        let images = [
            good[..100].to_vec(),
            good[..good.len() / 2].to_vec(),
            good[..good.len() - 1].to_vec(),
            changed,
        ];
        for (i, bytes) in images.iter().enumerate() {
            let path = d.path().join(format!("{i}.erofs"));
            std::fs::write(&path, bytes).unwrap();
            let accepted = [velarx_storage::composefs_digest_of(
                velarx_types::digest::Algorithm::Sha256,
                bytes,
            )];
            let outcome = std::panic::catch_unwind(|| match opened(&path, &accepted) {
                Ok(layer) => {
                    walk(&Layers::new(vec![layer], None, true, Stubs::Every), 2000);
                    true
                }
                Err(e) => {
                    assert!(e.to_string().contains(&format!("{i}.erofs")), "{e}");
                    false
                }
            });
            match (i, outcome) {
                (0, Ok(opened)) => assert!(!opened, "an image of 100 bytes is refused"),
                (_, Ok(_)) => {}
                (_, Err(_)) => panic!("image {i}: a panic"),
            }
        }
    }

    /// An image that is not one the generator makes (cut, or with bytes
    /// changed) is an error or reads as another tree: never a panic.
    #[test]
    fn a_corrupt_image_is_never_a_panic() {
        let good = super::layer_image(&super::tests::sample()).unwrap().image;
        // (a fixed sequence: xorshift)
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for round in 0..300 {
            let mut bytes = good.clone();
            match round % 3 {
                0 => bytes.truncate(next() as usize % bytes.len()),
                _ => {
                    for _ in 0..1 + next() % 8 {
                        let at = next() as usize % bytes.len();
                        bytes[at] = next() as u8;
                    }
                }
            }
            let outcome = std::panic::catch_unwind(|| {
                let Ok(layer) = Layer::open(Box::new(bytes.clone())) else {
                    return;
                };
                walk(&Layers::new(vec![layer], None, true, Stubs::Every), 2000);
                let Ok(layer) = Layer::open(Box::new(bytes.clone())) else {
                    return;
                };
                view_walk(&ImageView::new(vec![layer]), 2000);
            });
            assert!(outcome.is_ok(), "round {round}");
        }
        // a time past what the system can say, a directory that holds its
        // parent: what bytes changed by hand give
        let mut bytes = good.clone();
        let root = super::SUPERBLOCK_OFFSET + super::SUPERBLOCK_SIZE;
        bytes[root + 32..root + 40].copy_from_slice(&u64::MAX.to_le_bytes());
        let tree = Layers::new(
            vec![Layer::open(Box::new(bytes)).unwrap()],
            None,
            true,
            Stubs::Every,
        );
        let layer1 = tree.lookup(1, "layer1").unwrap();
        assert!(tree.attr(layer1).is_some());
        walk(&tree, 2000);
        // `/usr` names the root: the view does not go round
        let mut bytes = good.clone();
        let layer = Layer::open(Box::new(good.clone())).unwrap();
        let usr = layer.lookup(layer.root(), b"usr").unwrap();
        // (the entry of the directory in the root's: its nid, then the
        // file type of a directory at 10)
        let at = (root..bytes.len() - 12)
            .find(|&i| bytes[i..i + 8] == usr.to_le_bytes() && bytes[i + 10] == 2)
            .unwrap();
        bytes[at..at + 8].copy_from_slice(&layer.root().to_le_bytes());
        let view = ImageView::new(vec![Layer::open(Box::new(bytes)).unwrap()]);
        assert!(view.resolve("usr").is_none());
        assert!(view.resolve("usr/usr/usr").is_none());
        let good = ImageView::new(vec![layer]);
        assert!(good.resolve("usr/bin/busybox").is_some());
    }

    /// The attributes of the overlay that an image may have are those the
    /// generator writes: another one, or one of the overlay of a user
    /// namespace, is not served.
    #[test]
    fn an_image_cannot_steer_the_overlay() {
        let good = super::layer_image(&super::tests::sample()).unwrap().image;
        // `security.capability` of usr/bin/ping made another name of 10
        // bytes: the header of an attribute is its name's length, the index
        // of its prefix, the length of its value
        let at = good.windows(10).position(|w| w == b"capability").unwrap();
        for (index, suffix) in [(1u8, b"overlay.ab"), (4, b"overlay.up")] {
            let mut bytes = good.clone();
            bytes[at - 3] = index;
            bytes[at..at + 10].copy_from_slice(suffix);
            let tree = Layers::new(
                vec![Layer::open(Box::new(bytes)).unwrap()],
                None,
                true,
                Stubs::Every,
            );
            let mut ino = tree.lookup(1, "layer1").unwrap();
            for c in ["usr", "bin", "ping"] {
                ino = tree.lookup(ino, c).unwrap();
            }
            let names: Vec<String> = tree.xattrs(ino).unwrap().into_iter().map(|x| x.0).collect();
            assert_eq!(
                names,
                ["user.overlay.metacopy", "user.overlay.redirect"],
                "{index}"
            );
        }
    }
}
