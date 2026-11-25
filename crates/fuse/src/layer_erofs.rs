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
//! root), and so is its root when it has no `./` entry: they take the place
//! of the ones below, as when the layer is extracted.  The overlay's own
//! attributes and the SELinux labels of the entries are not kept.  A hard
//! link names a file of its layer: one to a file of a layer below is an
//! error (an image made with the layers below would depend on the image the
//! layer is pulled for, when it is the store's for every image that has the
//! layer).
//!
//! The format is EROFS with 4096 bytes blocks, extended inodes, the
//! attributes in the inodes, the directories and symbolic links inline where
//! they fit, and the stubs as a single chunk that is a hole.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use velarx_overlay_core::{class, rdev, Class};
use velarx_storage::canonical::MAX_ENTRIES;
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

/// The names of the ACLs, which EROFS knows by their index alone.
const EXACT: [(&[u8], u8); 2] = [
    (b"system.posix_acl_access", 2),
    (b"system.posix_acl_default", 3),
];

/// The prefixes of the other attribute names EROFS knows, by index.
const PREFIXES: [(&[u8], u8); 4] = [
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

pub(crate) fn components(path: &str) -> Result<Vec<&str>, String> {
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

/// The `rdev` of a device entry: an error when its numbers do not fit.
fn device_of(e: &TocEntry) -> Result<u32, String> {
    let (major, minor) = (e.dev_major.unwrap_or(0), e.dev_minor.unwrap_or(0));
    rdev(major, minor).ok_or_else(|| {
        format!(
            "`{}`: the device {major}:{minor} is not one an image can have (a major below 4096 and a minor below 2^20)",
            e.name
        )
    })
}

/// What an entry may not have, for every reader of its layer: an attribute
/// with no name, a device that is not one.
fn judge(e: &TocEntry) -> Result<(), String> {
    if let Some(k) = e
        .xattrs
        .keys()
        .find(|k| matches!(class(k.as_bytes()), Class::Refused(_)))
    {
        return Err(format!(
            "`{}`: `{}` is not the name of an attribute",
            e.name,
            k.escape_debug()
        ));
    }
    if matches!(e.entry_type, TocEntryType::Char | TocEntryType::Block) {
        device_of(e)?;
    }
    Ok(())
}

/// The time of an inode: the seconds are the 64 bits of a signed number, as
/// the kernel reads them (so a time before 1970 is kept).
fn mtime_of(e: &TocEntry) -> (u64, u32) {
    let (secs, nsec) = e.mtime();
    (secs as u64, nsec)
}

fn digest_of(e: &TocEntry) -> Result<Digest, String> {
    e.fsverity
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
    let hex = digest.hex();
    format!("/{}/{}", &hex[..2], &hex[2..]).into_bytes()
}

/// The tree of a layer: what its entries leave, as an overlay layer.
struct Tree {
    nodes: Vec<Node>,
}

const ROOT: usize = 0;

/// What the error of a hard link to a file the layer does not have before
/// the link says.
pub const LINK_BELOW: &str = "which the layer does not have before it";

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
        TocEntryType::Char => Kind::Char(device_of(e)?),
        TocEntryType::Block => Kind::Block(device_of(e)?),
        TocEntryType::Fifo => Kind::Fifo,
        TocEntryType::Hardlink | TocEntryType::Chunk => {
            return Err(format!("`{}` is not a file of its own", e.name))
        }
    };
    Ok(node)
}

/// What the entries of a layer make, as an extraction of them in their
/// order: its paths and what each names, its whiteouts and its opaque
/// markers.
pub(crate) struct Resolved<'a> {
    entries: &'a [TocEntry],
    /// The paths: the root first, and every other one after its directory.
    pub paths: Vec<Path<'a>>,
    /// The whiteouts (`.wh.name`): the directory, the name it hides.
    pub whiteouts: BTreeSet<(usize, &'a str)>,
    /// The directories with an opaque marker.
    pub opaque: BTreeSet<usize>,
}

/// A path of a layer.
pub(crate) struct Path<'a> {
    /// The directory it is in (the root is in itself), and its name there.
    pub parent: usize,
    pub name: &'a str,
    /// The entry it names (the one of the file for every name of a hard
    /// link), none for a directory the layer does not list.
    pub entry: Option<usize>,
    children: BTreeMap<&'a str, usize>,
}

/// Walk the entries in their order.  An entry replaces what its path names
/// (a directory merges with a directory, and keeps what is in it); a hard
/// link names the file its target is at that point; a directory that
/// becomes another type, or a path with a parent that is not a directory,
/// is an error.  A whiteout or an opaque marker is collected: the
/// order of the archive says nothing of them.  A layer has at most as many
/// paths, the root aside, as a pull takes entries: the directories it does
/// not list count, as each is a directory of its image.
pub(crate) fn resolve_entries(entries: &[TocEntry]) -> Result<Resolved<'_>, String> {
    let mut r = Resolved {
        entries,
        paths: vec![Path {
            parent: 0,
            name: "",
            entry: None,
            children: BTreeMap::new(),
        }],
        whiteouts: BTreeSet::new(),
        opaque: BTreeSet::new(),
    };
    for (i, e) in entries.iter().enumerate() {
        if e.entry_type == TocEntryType::Chunk {
            continue;
        }
        let parts = components(&e.name)?;
        match parts.split_last() {
            // (the overlay never reads the attribute on the root of a lower
            // layer: a marker in the root hides nothing, and the root has
            // none)
            Some((&OPAQUE_MARKER, [])) => {}
            Some((&OPAQUE_MARKER, dir)) => {
                let d = r.dir(dir)?;
                r.opaque.insert(d);
            }
            Some((last, dir)) if last.starts_with(WHITEOUT_PREFIX) => {
                // (`.wh.`, `.wh..` and `.wh...` hide nothing, as in the
                // merged views: an entry of no name, `.` or `..` would be
                // one of the directory itself)
                let hidden = &last[WHITEOUT_PREFIX.len()..];
                if !matches!(hidden, "" | "." | "..") {
                    let d = r.dir(dir)?;
                    r.whiteouts.insert((d, hidden));
                }
            }
            _ => {
                judge(e)?;
                r.put(i, &parts)?
            }
        }
        if r.paths.len() - 1 > MAX_ENTRIES {
            return Err(format!("the layer has more than {MAX_ENTRIES} paths"));
        }
    }
    Ok(r)
}

impl<'a> Resolved<'a> {
    fn is_dir(&self, entry: Option<usize>) -> bool {
        entry.is_none_or(|i| self.entries[i].entry_type == TocEntryType::Dir)
    }

    /// The path `parts`, if the layer has it now.
    fn find(&self, parts: &[&str]) -> Option<usize> {
        parts
            .iter()
            .try_fold(0, |p, c| self.paths[p].children.get(c).copied())
    }

    fn add(&mut self, parent: usize, name: &'a str, entry: Option<usize>) -> usize {
        let p = self.paths.len();
        self.paths.push(Path {
            parent,
            name,
            entry,
            children: BTreeMap::new(),
        });
        self.paths[parent].children.insert(name, p);
        p
    }

    /// The directory `parts`, and its parents, plain where the layer does
    /// not list them.
    fn dir(&mut self, parts: &[&'a str]) -> Result<usize, String> {
        let mut p = 0;
        for (k, c) in parts.iter().enumerate() {
            p = match self.paths[p].children.get(c) {
                Some(&d) if self.is_dir(self.paths[d].entry) => d,
                Some(_) => {
                    return Err(format!("`{}` is not a directory", parts[..=k].join("/")));
                }
                None => self.add(p, c, None),
            };
        }
        Ok(p)
    }

    fn put(&mut self, i: usize, parts: &[&'a str]) -> Result<(), String> {
        let entries = self.entries;
        let e = &entries[i];
        let entry = if e.entry_type == TocEntryType::Hardlink {
            let target = e
                .link_name
                .as_deref()
                .ok_or_else(|| format!("`{}`: a hard link without a target", e.name))?;
            let at = self
                .find(&components(target)?)
                .ok_or_else(|| format!("`{}`: a hard link to `{target}`, {LINK_BELOW}", e.name))?;
            let entry = self.paths[at].entry;
            if self.is_dir(entry) {
                return Err(format!("`{}`: a hard link to a directory", e.name));
            }
            entry
        } else {
            Some(i)
        };
        let at = match parts.split_last() {
            None => 0,
            Some((last, dir)) => {
                let d = self.dir(dir)?;
                match self.paths[d].children.get(last) {
                    Some(&at) => at,
                    None => {
                        self.add(d, last, entry);
                        return Ok(());
                    }
                }
            }
        };
        if self.is_dir(self.paths[at].entry) && !self.is_dir(entry) {
            return Err(format!("`{}` turns a directory into another type", e.name));
        }
        self.paths[at].entry = entry;
        Ok(())
    }
}

impl Tree {
    fn build(entries: &[TocEntry]) -> Result<Self, String> {
        let layer = resolve_entries(entries)?;
        let mut tree = Tree { nodes: Vec::new() };
        // (the node of each path, the root first: a file with several names
        // is one node)
        let mut node: Vec<usize> = Vec::with_capacity(layer.paths.len());
        let mut made: HashMap<usize, usize> = HashMap::new();
        for (p, path) in layer.paths.iter().enumerate() {
            let n = match path.entry {
                None => tree.push(Node::plain_dir()),
                Some(i) => match made.get(&i) {
                    Some(&n) => n,
                    None => {
                        let n = tree.push(node_of(&entries[i])?);
                        made.insert(i, n);
                        n
                    }
                },
            };
            if p != ROOT {
                tree.link(node[path.parent], path.name, n)?;
            }
            node.push(n);
        }
        for (dir, name) in layer.whiteouts {
            let parent = node[dir];
            match tree.child(parent, name.as_bytes()) {
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
                    let idx = tree.push(Node {
                        kind: Kind::Char(0),
                        perm: 0,
                        ..Node::plain_dir()
                    });
                    tree.link(parent, name, idx)?;
                }
            }
        }
        for dir in layer.opaque {
            tree.nodes[node[dir]]
                .xattrs
                .insert(XATTR_OPAQUE.as_bytes().to_vec(), b"y".to_vec());
        }
        Ok(tree)
    }

    fn push(&mut self, node: Node) -> usize {
        self.nodes.push(node);
        self.nodes.len() - 1
    }

    fn child(&self, dir: usize, name: &[u8]) -> Option<usize> {
        match &self.nodes[dir].kind {
            Kind::Dir(c) => c.get(name).copied(),
            _ => None,
        }
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

/// The index of an attribute name and the rest of it that the record
/// keeps: nothing for the name of an ACL, and a name of at least one byte
/// after any other prefix, as a name of length 0 is read as the ACL of
/// that index.
fn split_name(name: &[u8]) -> Result<(&[u8], u8), String> {
    if let Some((_, i)) = EXACT.iter().find(|(n, _)| name == *n) {
        return Ok((&[], *i));
    }
    match PREFIXES.iter().find(|(p, _)| name.starts_with(p)) {
        Some((p, _)) if name.len() == p.len() => Err(format!(
            "the attribute name {} has nothing after its prefix",
            name.escape_ascii()
        )),
        Some((p, i)) => Ok((&name[p.len()..], *i)),
        None => Ok((name, 0)),
    }
}

fn xattr_body(xattrs: &BTreeMap<Vec<u8>, Vec<u8>>) -> Result<Vec<u8>, String> {
    if xattrs.is_empty() {
        return Ok(Vec::new());
    }
    // the header: no name filter, no shared attribute
    let size = xattrs
        .iter()
        .map(|(k, v)| 8 + k.len() + v.len())
        .sum::<usize>();
    let mut out = Vec::with_capacity(12 + size);
    out.resize(12, 0);
    for (name, value) in xattrs {
        let (suffix, index) = split_name(name)?;
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

    fn device(name: &str, char: bool, major: u32, minor: u32) -> TocEntry {
        let t = if char {
            TocEntryType::Char
        } else {
            TocEntryType::Block
        };
        let mut d = entry(name, t);
        (d.dev_major, d.dev_minor) = (Some(major), Some(minor));
        d
    }

    /// The `rdev` of the node of `path` in an image.
    fn rdev_in(image: &[u8], path: &str) -> String {
        let l = listing(image);
        let l = l
            .iter()
            .find(|l| l.starts_with(&format!("{path} ")))
            .unwrap();
        l.split(' ').nth(6).unwrap().to_string()
    }

    /// A device the numbers of which do not fit the image is an error that
    /// names the entry: it is not made into another device or into a
    /// whiteout.  The numbers at the edge that fit are kept.
    #[test]
    fn a_device_that_does_not_fit_is_refused() {
        for (major, minor) in [(4096, 0), (0, 1 << 20), (8192, 5), (1 << 20, 1 << 20)] {
            let e = layer_image(&[device("dev/x", true, major, minor)])
                .err()
                .unwrap();
            assert!(
                e.contains("`dev/x`") && e.contains(&format!("{major}:{minor}")),
                "{e}"
            );
        }
        let e = layer_image(&[device("dev/b", false, 4096, 0)])
            .err()
            .unwrap();
        assert!(e.contains("`dev/b`"), "{e}");
        let image = layer_image(&[
            device("a", false, 0, 0),
            device("b", true, 4095, (1 << 20) - 1),
            device("c", true, 1, 3),
        ])
        .unwrap()
        .image;
        assert_eq!(rdev_in(&image, "/a"), "0");
        assert_eq!(rdev_in(&image, "/b"), u32::MAX.to_string());
        assert_eq!(rdev_in(&image, "/c"), "259");
    }

    /// The merged view of the layers refuses what the image refuses, so
    /// that a device is the same in both.
    #[test]
    fn the_merged_view_refuses_the_device_of_no_image() {
        let low = file("x", 1, 3);
        let e = crate::merged::MergedTree::build_entries(&[
            std::slice::from_ref(&low),
            &[device("x", true, 4096, 0)],
        ])
        .err()
        .unwrap();
        assert!(e.contains("layer 1") && e.contains("`x`"), "{e}");
        let wh = entry(".wh.x", TocEntryType::Reg);
        let m = crate::merged::MergedTree::build_entries(&[&[low], &[wh]]).unwrap();
        assert_eq!(m.lookup(crate::merged::ROOT, "x"), None);
    }

    /// A character device 0:0 in a layer is a whiteout, in the image (the
    /// node of the number 0 that the overlay reads so) and in the merged
    /// view (it hides the file below it), like a `.wh.` name.
    #[test]
    fn a_character_device_0_0_is_a_whiteout_in_the_image_and_the_view() {
        let low = file("x", 1, 3);
        let wh = device("x", true, 0, 0);
        let image = layer_image(std::slice::from_ref(&wh)).unwrap().image;
        assert_eq!(rdev_in(&image, "/x"), "0");
        let l = listing(&image);
        let l = l.iter().find(|l| l.starts_with("/x ")).unwrap();
        assert!(l.split(' ').nth(1).unwrap().starts_with("20"), "{l}");
        let m = crate::merged::MergedTree::build_entries(&[&[low], &[wh]]).unwrap();
        assert_eq!(m.lookup(crate::merged::ROOT, "x"), None);
    }

    /// The record of an attribute keeps what follows its prefix, and a
    /// name of length 0 only for the two ACLs, which are exact names: a
    /// longer name that begins with one is kept whole, and a prefix with
    /// nothing after it is an error.
    #[test]
    fn an_attribute_name_is_never_written_empty_but_for_an_acl() {
        let split = |n: &str| split_name(n.as_bytes()).map(|(s, i)| (s.to_vec(), i));
        assert_eq!(split("system.posix_acl_access"), Ok((vec![], 2)));
        assert_eq!(split("system.posix_acl_default"), Ok((vec![], 3)));
        assert_eq!(
            split("system.posix_acl_accessX"),
            Ok((b"system.posix_acl_accessX".to_vec(), 0))
        );
        assert_eq!(
            split("system.posix_acl_default.x"),
            Ok((b"system.posix_acl_default.x".to_vec(), 0))
        );
        assert_eq!(split("user.a"), Ok((b"a".to_vec(), 1)));
        assert_eq!(split("trusted.a"), Ok((b"a".to_vec(), 4)));
        assert_eq!(split("lustre.a"), Ok((b"a".to_vec(), 5)));
        assert_eq!(split("security.a"), Ok((b"a".to_vec(), 6)));
        assert_eq!(split("other.a"), Ok((b"other.a".to_vec(), 0)));
        for n in ["user.", "trusted.", "security.", "lustre."] {
            let e = split(n).unwrap_err();
            assert!(e.contains(n) && e.contains("nothing after"), "{e}");
        }
        let mut x = BTreeMap::new();
        x.insert(b"lustre.".to_vec(), b"v".to_vec());
        assert!(xattr_body(&x).is_err());
    }

    /// The attributes an image keeps are the plain ones: those of the
    /// overlay, in any namespace and nested, and the label of the engine
    /// are not, and a name that is only a namespace is an error.
    #[test]
    fn the_attributes_of_the_overlay_do_not_reach_the_image() {
        let attrs = |name: &str| {
            let mut f = file("f", 1, 3);
            f.xattrs.insert(name.into(), "eQ==".into());
            let image = layer_image(&[f])?.image;
            let l = listing(&image);
            let l = l.iter().find(|l| l.starts_with("/f ")).unwrap().clone();
            Ok::<_, String>(l.contains(&format!("{name}=y")))
        };
        for name in [
            "trusted.overlay.redirect",
            "trusted.overlay.metacopy",
            "trusted.overlay.overlay.opaque",
            "user.overlay.redirect",
            "user.overlay.overlay.x",
            "security.overlay.x",
            "system.overlay.x",
            "security.selinux",
        ] {
            assert_eq!(attrs(name), Ok(false), "{name}");
        }
        for name in ["user.x", "security.selinuxx", "user.overlay", "overlay.x"] {
            assert_eq!(attrs(name), Ok(true), "{name}");
        }
        for name in ["user.", "trusted.", "security.", "system.", ""] {
            let e = attrs(name).err().unwrap();
            assert!(
                e.contains("`f`") && e.contains("not the name"),
                "{name}: {e}"
            );
        }
    }

    /// The chunks of a file are not entries of the layer: its image and its
    /// identity are those of the table without them.
    #[test]
    fn the_chunks_of_a_file_change_nothing_of_the_image() {
        let mut entries = sample();
        let at = entries
            .iter()
            .position(|e| e.name == "usr/bin/busybox")
            .unwrap();
        entries[at].chunk_digest = Some(format!("sha256:{}", "1".repeat(64)));
        entries[at].chunk_size = 600;
        let mut chunked = entries.clone();
        for i in 1..3u64 {
            let mut chunk = entry("usr/bin/busybox", TocEntryType::Chunk);
            chunk.chunk_digest = Some(format!("sha256:{}", format!("{i}").repeat(64)));
            (chunk.chunk_size, chunk.chunk_offset) = (200, 600 + 200 * (i - 1));
            chunked.insert(at + i as usize, chunk);
        }
        let alg = velarx_types::digest::Algorithm::Sha256;
        let (plain, cut) = (
            layer_image(&entries).unwrap(),
            layer_image(&chunked).unwrap(),
        );
        assert_eq!(plain.identity(alg).unwrap(), cut.identity(alg).unwrap());
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

    /// The root and a directory the layer adds to and does not list are
    /// plain: 0755, root, no time, no attributes.
    #[test]
    fn the_root_and_the_parents_of_a_layer_are_plain() {
        let list = listing(&layer_image(&[file("a/b/c", 2, 3)]).unwrap().image);
        for dir in ["", "/a", "/a/b"] {
            let l = list
                .iter()
                .find(|l| l.starts_with(&format!("{dir} ")))
                .unwrap();
            assert!(l.starts_with(&format!("{dir} 40755 0:0 0 ")), "{l}");
            assert!(l.ends_with(" []"), "{l}");
        }
    }

    #[test]
    fn the_image_is_the_same_whatever_the_order_of_the_paths() {
        let entries = sample();
        let a = layer_image(&entries).unwrap();
        // (the entries of a path keep their order, and so do the links after
        // the files: the rest is free)
        let linked = |e: &TocEntry| e.entry_type == TocEntryType::Hardlink;
        let mut reversed = entries.clone();
        reversed.reverse();
        reversed.sort_by_key(linked);
        let b = layer_image(&reversed).unwrap();
        let mut shuffled = entries.clone();
        // a fixed permutation: every third entry first
        shuffled.sort_by_key(|e| (linked(e), e.name.len() % 3, e.name.clone()));
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

    /// The overlay never reads the attribute on the root of a lower layer:
    /// the image of a layer with a marker in its root has none there.
    #[test]
    fn the_root_of_a_layer_is_never_opaque() {
        let built = layer_image(&[
            entry(".wh..wh..opq", TocEntryType::Reg),
            entry("d/.wh..wh..opq", TocEntryType::Reg),
        ])
        .unwrap();
        let layer = crate::erofs_tree::Layer::open(Box::new(built.image)).unwrap();
        assert!(!layer.is_opaque(layer.root()));
        let d = layer.lookup(layer.root(), b"d").unwrap();
        assert!(layer.is_opaque(d));
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
        // (a link names a file the archive has at that point: a chain goes
        // from the file on)
        let built = layer_image(&[file("c/file", 1, 3), b, a]).unwrap();
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

    /// A layer as the tests of the order of its entries give it: a file is
    /// the byte of its content.
    #[derive(Debug)]
    enum T {
        File(u8),
        Dir,
        Link(&'static str),
    }

    fn layer(spec: &[(&str, T)]) -> Vec<TocEntry> {
        spec.iter()
            .map(|(name, t)| match t {
                T::File(byte) => file(name, *byte, 1),
                T::Dir => entry(name, TocEntryType::Dir),
                T::Link(to) => {
                    let mut e = entry(name, TocEntryType::Hardlink);
                    e.link_name = Some(to.to_string());
                    e
                }
            })
            .collect()
    }

    /// The content of the files the entries make when `tar` extracts them.
    fn extracted(spec: &[(&str, T)]) -> Result<BTreeMap<String, u8>, String> {
        fn walk(dir: &std::path::Path, prefix: &str, out: &mut BTreeMap<String, u8>) {
            for e in std::fs::read_dir(dir).unwrap() {
                let e = e.unwrap();
                let path = format!("{prefix}{}", e.file_name().to_str().unwrap());
                if e.path().is_dir() {
                    walk(&e.path(), &format!("{path}/"), out);
                } else {
                    out.insert(path, std::fs::read(e.path()).unwrap()[0]);
                }
            }
        }
        let mut tar = tar::Builder::new(Vec::new());
        for (name, t) in spec {
            let mut h = tar::Header::new_gnu();
            h.set_mode(0o755);
            h.set_size(0);
            match t {
                T::File(byte) => {
                    h.set_entry_type(tar::EntryType::Regular);
                    h.set_size(1);
                    tar.append_data(&mut h, name, &[*byte][..])
                }
                T::Dir => {
                    h.set_entry_type(tar::EntryType::Directory);
                    tar.append_data(&mut h, name, std::io::empty())
                }
                T::Link(to) => {
                    h.set_entry_type(tar::EntryType::Link);
                    tar.append_link(&mut h, name, to)
                }
            }
            .unwrap();
        }
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("layer.tar"), tar.into_inner().unwrap()).unwrap();
        let root = dir.path().join("root");
        std::fs::create_dir(&root).unwrap();
        let tar = std::process::Command::new("tar")
            .args(["-xf", "layer.tar", "-C", "root"])
            .current_dir(dir.path())
            .output()
            .unwrap();
        if !tar.status.success() {
            return Err(String::from_utf8_lossy(&tar.stderr).into());
        }
        let mut out = BTreeMap::new();
        walk(&root, "", &mut out);
        Ok(out)
    }

    /// The byte of the content a stub of an image (or an entry) stands for.
    fn byte_of(fsverity_hex: &str) -> u8 {
        u8::from_str_radix(&fsverity_hex[..2], 16).unwrap()
    }

    fn in_image(spec: &[(&str, T)]) -> Result<BTreeMap<String, u8>, String> {
        let image = layer_image(&layer(spec))?.image;
        Ok(listing(&image)
            .iter()
            .filter_map(|l| {
                let (path, rest) = l.split_once(' ').unwrap();
                let at = rest.find("redirect=/")? + "redirect=/".len();
                Some((path[1..].to_string(), byte_of(&rest[at..])))
            })
            .collect())
    }

    fn in_merged(spec: &[(&str, T)]) -> Result<BTreeMap<String, u8>, String> {
        let entries = layer(spec);
        let tree = crate::MergedTree::build_entries(&[&entries])?;
        let mut out = BTreeMap::new();
        let mut todo = vec![(crate::merged::ROOT, String::new())];
        while let Some((n, path)) = todo.pop() {
            let node = tree.node(n).unwrap();
            if let Some(d) = &node.entry.fsverity {
                out.insert(path.clone(), byte_of(&d.hex()));
            }
            for (name, &c) in &node.children {
                let sep = if path.is_empty() { "" } else { "/" };
                todo.push((c, format!("{path}{sep}{name}")));
            }
        }
        Ok(out)
    }

    const LONG: &str = "a-directory-with-a-name-of-more-than-one-hundred-bytes-as-tar-headers-have/and-a-file-in-it";

    /// What a path names follows the order of the entries, as in an
    /// extraction, for the image of the layer and for the merged view.
    #[test]
    fn a_layer_is_what_an_extraction_of_its_entries_makes() {
        use T::*;
        let cases: &[&[(&str, T)]] = &[
            // a link keeps the file it was made to, whatever comes after
            &[("f", File(1)), ("l", Link("f")), ("f", File(2))],
            // a file after a link of its name replaces it, a link after a
            // file replaces it: the order decides, not the type
            &[("f", File(1)), ("g", File(2)), ("f", Link("g"))],
            &[("g", File(2)), ("f", Link("g")), ("f", File(1))],
            // a chain, and a link to a link of the chain
            &[
                ("f", File(1)),
                ("a", Link("f")),
                ("b", Link("a")),
                ("f", File(2)),
                ("c", Link("b")),
            ],
            // a link to what comes later, or to nothing
            &[("l", Link("f")), ("f", File(1))],
            &[("l", Link("missing"))],
            // a link to a directory
            &[("d", Dir), ("l", Link("d"))],
            // a parent that is not a directory, a directory that is
            // not one any more, a file that becomes one
            &[("a", File(1)), ("a/b", File(2))],
            &[("a/b", File(2)), ("a", File(1))],
            &[("a", File(1)), ("a", Dir)],
            &[("a", Dir), ("a/b", File(1)), ("a", Link("a/b"))],
            &[("a", File(1)), ("a/.wh.b", File(2))],
            &[("a", File(1)), ("a/.wh..wh..opq", File(2))],
            // what is fine: parents the layer does not list, a directory
            // again, a file over a file, names spelled with `./`, long names
            &[
                ("a/b/c", File(1)),
                ("a", Dir),
                ("a/b", Dir),
                ("a/b/c", File(2)),
            ],
            &[("./a", File(1)), ("b", Link("./a")), ("./c/", Dir)],
            &[(LONG, File(1)), ("l", Link(LONG)), ("d/l", Link("l"))],
        ];
        for spec in cases {
            let want = extracted(spec).ok();
            assert_eq!(in_image(spec).ok(), want, "image of {spec:?}");
            assert_eq!(in_merged(spec).ok(), want, "merged view of {spec:?}");
        }
        // (a link to a whiteout, which tar makes, is refused: the image has
        // no file there)
        let spec: &[(&str, T)] = &[("a/.wh.b", File(1)), ("c", Link("a/.wh.b"))];
        assert!(in_image(spec).is_err() && in_merged(spec).is_err());
        let spec: &[(&str, T)] = &[("f", File(1)), ("l", Link("f")), ("f", File(2))];
        assert_eq!(
            in_image(spec).unwrap(),
            BTreeMap::from([("f".to_string(), 2), ("l".to_string(), 1)])
        );
    }

    /// A chain of links is resolved once, not once per link of it, and a
    /// path is walked once, not once per parent.
    #[test]
    fn a_long_chain_of_hard_links_or_a_deep_tree_is_fast() {
        let mut entries = vec![file("f", 1, 1)];
        for i in 0..50_000 {
            let mut l = entry(&format!("l{i}"), TocEntryType::Hardlink);
            l.link_name = Some(if i == 0 {
                "f".into()
            } else {
                format!("l{}", i - 1)
            });
            entries.push(l);
        }
        let deep = "d/".repeat(2000);
        let deep: Vec<TocEntry> = (0..2000)
            .map(|i| file(&format!("{deep}f{i}"), 1, 1))
            .collect();
        let start = std::time::Instant::now();
        for entries in [entries, deep] {
            assert!(layer_image(&entries).is_ok());
            assert!(crate::MergedTree::build_entries(&[&entries]).is_ok());
        }
        assert!(start.elapsed().as_secs() < 20, "{:?}", start.elapsed());
    }

    /// A directory a layer does not list costs what one it lists does: a
    /// table of many deep paths, each of its own directories, is as fast
    /// as its directories are many, in the image and in the merged view.
    #[test]
    fn many_deep_paths_are_fast() {
        let chain = "a/".repeat(1999);
        let entries: Vec<TocEntry> = (0..250)
            .map(|i| file(&format!("c{i}/{chain}f"), 1, 1))
            .collect();
        let start = std::time::Instant::now();
        assert!(layer_image(&entries).is_ok());
        let tree = crate::MergedTree::build_entries(&[&entries]).unwrap();
        assert!(start.elapsed().as_secs() < 10, "{:?}", start.elapsed());
        assert_eq!(tree.count(), 1 + 250 * 2001);
    }

    /// The directories a layer does not list count as its entries.
    #[test]
    fn a_layer_has_at_most_as_many_paths_as_a_pull_takes() {
        // (each entry has `depth` paths: its directory, the chain, itself)
        let depth = 4096;
        let chain = "a/".repeat(depth - 2);
        let entries: Vec<TocEntry> = (0..MAX_ENTRIES / depth + 1)
            .map(|i| entry(&format!("{i}/{chain}f"), TocEntryType::Fifo))
            .collect();
        let e = resolve_entries(&entries).err().unwrap();
        assert!(e.contains("more than"), "{e}");
        assert!(resolve_entries(&entries[1..]).is_ok());
    }

    /// A deep tree reads back whole: its paths, the names of its nodes.
    #[test]
    fn a_deep_tree_is_whole() {
        let path = format!("{}f", "d/".repeat(100));
        let entries = vec![entry("d", TocEntryType::Dir), file(&path, 1, 1)];
        let listing = listing(&layer_image(&entries).unwrap().image);
        assert!(listing.iter().any(|l| l.starts_with(&format!("/{path} "))));
        let tree = crate::MergedTree::build_entries(&[&entries]).unwrap();
        let mut dir = crate::merged::ROOT;
        for name in path.split('/') {
            dir = tree.lookup(dir, name).unwrap();
            let node = tree.node(dir).unwrap();
            assert!(node.entry.name.ends_with(name), "{}", node.entry.name);
        }
        assert_eq!(tree.resolve(&path), Some(dir));
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
        let mut root = entry("./", TocEntryType::Hardlink);
        root.link_name = Some("f".into());
        let e = layer_image(&[file("f", 1, 1), root]).err().unwrap();
        assert!(e.contains("turns a directory into another type"), "{e}");
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
