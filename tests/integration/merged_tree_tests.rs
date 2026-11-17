// SPDX-License-Identifier: Apache-2.0
//! The tree the EROFS images of the layers of an image make, checked
//! against trees made another way:
//!
//! * `layers_make_the_tree_the_oci_spec_says`: layers with whiteouts, opaque
//!   directories, replaced kinds and links, applied by a reference written
//!   here, in a few lines, from the text of the image spec; against the
//!   images of the layers read as the engine reads them (`view`) and
//!   stacked as an overlay stacks them.
//! * `an_image_of_the_store_is_what_podman_exports` (ignored): the images a
//!   pull made in a store, against the tar of `podman export` of the same
//!   image (`tests/e2e/bats/merged-tree.bats` runs it).
//!
//! The two trees are compared by what a container sees of each path: kind,
//! permissions, owner, size, link target, device, content digest, extended
//! attributes.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use velarx_fuse::composefs as cfs;
use velarx_fuse::erofs_tree::Layer;
use velarx_fuse::view::{ImageTree, ImageView, VIEW_ROOT};
use velarx_storage::{Toc, TocEntry, TocEntryType};

/// What a container sees of a path.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Seen {
    kind: &'static str,
    mode: u32,
    uid: u32,
    gid: u32,
    size: u64,
    link: String,
    rdev: (u32, u32),
    digest: String,
    xattrs: BTreeMap<String, Vec<u8>>,
}

fn kind(t: TocEntryType) -> &'static str {
    match t {
        TocEntryType::Dir => "dir",
        TocEntryType::Reg => "reg",
        TocEntryType::Symlink => "symlink",
        TocEntryType::Char => "char",
        TocEntryType::Block => "block",
        TocEntryType::Fifo => "fifo",
        TocEntryType::Hardlink => "hardlink",
        TocEntryType::Chunk => "chunk",
    }
}

fn path_of(name: &str) -> String {
    let n = name.trim_matches('/');
    let n = n.strip_prefix("./").unwrap_or(n);
    if n == "." { "" } else { n }.to_string()
}

fn xattrs_of(e: &TocEntry) -> BTreeMap<String, Vec<u8>> {
    use base64::Engine;
    e.xattrs
        .iter()
        .filter(|(k, _)| !k.starts_with("trusted.overlay.") && !k.starts_with("security.selinux"))
        .map(|(k, v)| {
            let v = base64::engine::general_purpose::STANDARD
                .decode(v)
                .unwrap_or_default();
            (k.clone(), v)
        })
        .collect()
}

fn seen(e: &TocEntry) -> Seen {
    Seen {
        kind: kind(e.entry_type),
        mode: e.mode & 0o7777,
        uid: e.uid,
        gid: e.gid,
        size: if e.entry_type == TocEntryType::Reg {
            e.size
        } else {
            0
        },
        link: if e.entry_type == TocEntryType::Symlink {
            e.link_name.clone().unwrap_or_default()
        } else {
            String::new()
        },
        rdev: (e.dev_major.unwrap_or(0), e.dev_minor.unwrap_or(0)),
        digest: if e.entry_type == TocEntryType::Reg && e.size > 0 {
            e.verity().unwrap_or_default()
        } else {
            String::new()
        },
        xattrs: xattrs_of(e),
    }
}

/// The paths of a list of entries, a hard link being the file it links to;
/// and the groups of paths that are one file.
fn tree_of(entries: &[TocEntry]) -> (BTreeMap<String, Seen>, BTreeSet<BTreeSet<String>>) {
    let mut by_path: HashMap<String, &TocEntry> = HashMap::new();
    for e in entries {
        by_path.insert(path_of(&e.name), e);
    }
    let mut out = BTreeMap::new();
    let mut groups: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for e in entries {
        let p = path_of(&e.name);
        if e.entry_type == TocEntryType::Hardlink {
            let mut target = path_of(e.link_name.as_deref().unwrap_or(""));
            let mut hops = 0;
            while let Some(t) = by_path.get(&target) {
                if t.entry_type != TocEntryType::Hardlink || hops > 8 {
                    break;
                }
                target = path_of(t.link_name.as_deref().unwrap_or(""));
                hops += 1;
            }
            let t = by_path
                .get(&target)
                .unwrap_or_else(|| panic!("{p}: a hard link to {target}, which is not there"));
            out.insert(p.clone(), seen(t));
            groups.entry(target).or_default().insert(p);
        } else {
            groups.entry(p.clone()).or_default().insert(p.clone());
            out.insert(p, seen(e));
        }
    }
    let groups = groups.into_values().filter(|g| g.len() > 1).collect();
    out.remove("");
    (out, groups)
}

fn diff(what: &str, want: &BTreeMap<String, Seen>, got: &BTreeMap<String, Seen>) -> Vec<String> {
    let mut out = Vec::new();
    for (p, w) in want {
        match got.get(p) {
            None => out.push(format!(
                "{what}: `{p}` is missing ({:?} {:o})",
                w.kind, w.mode
            )),
            Some(g) if g != w => out.push(format!("{what}: `{p}`\n    want {w:?}\n    got  {g:?}")),
            _ => {}
        }
    }
    for (p, g) in got {
        if !want.contains_key(p) {
            out.push(format!("{what}: `{p}` should not be there ({:?})", g.kind));
        }
    }
    out
}

// the reference: the layers applied as the image spec says

const WH: &str = ".wh.";
const OPQ: &str = ".wh..wh..opq";

/// Apply `layers` (lowest first): a whiteout removes the path from what is
/// below; an opaque marker removes what the directory had; a path that is
/// not a directory replaces what is below it with its descendants; a
/// directory a layer has entries in but does not list is a plain one; a
/// link is the file it names (a copy of it when it is of a layer below).
fn reference(layers: &[Vec<TocEntry>]) -> BTreeMap<String, TocEntry> {
    let mut fs: BTreeMap<String, TocEntry> = BTreeMap::new();
    let below = |fs: &mut BTreeMap<String, TocEntry>, p: &str, keep: &BTreeSet<String>| {
        let prefix = format!("{p}/");
        fs.retain(|k, _| keep.contains(k) || (k != p && !k.starts_with(&prefix)));
    };
    for layer in layers {
        // (whiteouts are of the layers below, whatever their order)
        let mut after: Vec<&TocEntry> = Vec::new();
        for e in layer {
            let p = path_of(&e.name);
            let (dir, base) = p.rsplit_once('/').unwrap_or(("", &p));
            if base == OPQ {
                let prefix = if dir.is_empty() {
                    String::new()
                } else {
                    format!("{dir}/")
                };
                fs.retain(|k, _| k == dir || !k.starts_with(&prefix));
            } else if let Some(t) = base.strip_prefix(WH) {
                let target = if dir.is_empty() {
                    t.to_string()
                } else {
                    format!("{dir}/{t}")
                };
                below(&mut fs, &target, &BTreeSet::new());
            } else {
                after.push(e);
            }
        }
        // (what the layer has stays, whatever the order of its entries)
        let mut mine: BTreeSet<String> = layer
            .iter()
            .filter(|e| {
                let p = path_of(&e.name);
                let base = p.rsplit_once('/').map_or(p.as_str(), |(_, b)| b);
                !base.starts_with(WH)
            })
            .map(|e| path_of(&e.name))
            .collect();
        // a directory the layer has entries in but does not list is a plain
        // one, which takes the place of the one below (as when the layer is
        // extracted, as podman does)
        for e in layer {
            let p = path_of(&e.name);
            let mut a = p.as_str();
            while let Some((parent, _)) = a.rsplit_once('/') {
                a = parent;
                if mine.contains(a) {
                    continue;
                }
                let mut d: TocEntry = serde_json::from_value(
                    serde_json::json!({"name": a, "type": "dir", "mode": 0o755}),
                )
                .unwrap();
                if fs.get(a).is_some_and(|o| o.entry_type != TocEntryType::Dir) {
                    below(&mut fs, a, &BTreeSet::new());
                }
                d.name = a.to_string();
                fs.insert(a.to_string(), d);
            }
        }
        for e in after {
            let p = path_of(&e.name);
            mine.insert(p.clone());
            let mut e = e.clone();
            if e.entry_type == TocEntryType::Hardlink {
                let t = path_of(e.link_name.as_deref().unwrap_or(""));
                let target = fs
                    .get(&t)
                    .unwrap_or_else(|| panic!("{p}: a hard link to {t}"))
                    .clone();
                // (it stays a link, the group says so, to a file of the
                // layer; to a file of a layer below it is a copy, as when
                // the layer is extracted on its own)
                let linked = mine.contains(&t);
                e = TocEntry {
                    name: e.name.clone(),
                    ..target
                };
                if linked {
                    e.entry_type = TocEntryType::Hardlink;
                    e.link_name = Some(t);
                }
                fs.insert(p, e);
                continue;
            }
            let replaces_dir = fs
                .get(&p)
                .is_some_and(|o| o.entry_type == TocEntryType::Dir)
                && e.entry_type == TocEntryType::Dir;
            if !replaces_dir {
                below(&mut fs, &p, &mine);
            }
            fs.insert(p, e);
        }
    }
    fs
}

fn from_reference(fs: &BTreeMap<String, TocEntry>) -> Vec<TocEntry> {
    fs.values().cloned().collect()
}

// the layers stacked as the overlay of a container stacks them

fn is_whiteout(e: &TocEntry) -> bool {
    e.entry_type == TocEntryType::Char && e.dev_major == Some(0) && e.dev_minor == Some(0)
}

/// What a container sees on the images of layers (lowest first) as the lower
/// layers of an overlay: the top-most layer that has a name gives it, a
/// directory is merged with the directories under it until something that is
/// not one or an opaque one, a whiteout hides the name.
fn stacked(images: &[Vec<TocEntry>]) -> BTreeMap<String, TocEntry> {
    let maps: Vec<BTreeMap<String, &TocEntry>> = images
        .iter()
        .map(|l| l.iter().map(|e| (path_of(&e.name), e)).collect())
        .collect();
    fn children(maps: &[BTreeMap<String, &TocEntry>], layers: &[usize], dir: &str) -> Vec<String> {
        let prefix = if dir.is_empty() {
            String::new()
        } else {
            format!("{dir}/")
        };
        let mut names = BTreeSet::new();
        for l in layers {
            for k in maps[*l].keys() {
                if let Some(rest) = k.strip_prefix(&prefix) {
                    if !rest.is_empty() && !rest.contains('/') {
                        names.insert(rest.to_string());
                    }
                }
            }
        }
        names.into_iter().collect()
    }
    fn walk(
        maps: &[BTreeMap<String, &TocEntry>],
        layers: &[usize],
        dir: &str,
        out: &mut BTreeMap<String, TocEntry>,
    ) {
        for name in children(maps, layers, dir) {
            let path = if dir.is_empty() {
                name.clone()
            } else {
                format!("{dir}/{name}")
            };
            let mut merged: Vec<usize> = Vec::new();
            let mut top: Option<&TocEntry> = None;
            for l in layers.iter().rev() {
                let Some(e) = maps[*l].get(&path) else {
                    continue;
                };
                if top.is_none() {
                    if is_whiteout(e) {
                        break;
                    }
                    top = Some(e);
                }
                if e.entry_type == TocEntryType::Dir && !is_whiteout(e) {
                    merged.push(*l);
                    // (an opaque directory hides those below it)
                    if e.xattrs.get("trusted.overlay.opaque").map(String::as_str) == Some("eQ==") {
                        break;
                    }
                } else {
                    break;
                }
            }
            let Some(top) = top else { continue };
            out.insert(path.clone(), top.clone());
            if top.entry_type == TocEntryType::Dir {
                merged.reverse();
                walk(maps, &merged, &path, out);
            }
        }
    }
    let mut out = BTreeMap::new();
    let all: Vec<usize> = (0..images.len()).collect();
    walk(&maps, &all, "", &mut out);
    out
}

fn hex(c: char) -> String {
    c.to_string().repeat(64)
}

fn make(entries: serde_json::Value) -> Vec<TocEntry> {
    serde_json::from_value(entries).unwrap()
}

/// The entries of the image of a layer, as the overlay reads a lower layer:
/// a whiteout is a character device 0:0, a second name of a file a hard link.
fn layer_entries(layer: &Layer) -> Vec<TocEntry> {
    let mut out = Vec::new();
    let mut first: HashMap<u64, String> = HashMap::new();
    let mut todo = vec![(layer.root(), String::new())];
    while let Some((dir, path)) = todo.pop() {
        let mut kids = Vec::new();
        layer
            .readdir(dir, 0, &mut |nid, _, name| {
                kids.push((nid, String::from_utf8_lossy(name).into_owned()));
                false
            })
            .unwrap();
        for (nid, name) in kids {
            let p = if path.is_empty() {
                name
            } else {
                format!("{path}/{name}")
            };
            let mut e = velarx_fuse::dir_entry(&p);
            if !layer.is_dir(nid) {
                if let Some(f) = first.get(&nid) {
                    e.entry_type = TocEntryType::Hardlink;
                    e.link_name = Some(f.clone());
                    out.push(e);
                    continue;
                }
                first.insert(nid, p.clone());
            }
            fill(&mut e, layer, nid);
            if e.entry_type == TocEntryType::Dir {
                todo.push((nid, p));
            }
            out.push(e);
        }
    }
    out
}

fn fill(e: &mut TocEntry, layer: &Layer, nid: u64) {
    use base64::Engine;
    let a = layer.attr(nid).unwrap();
    e.entry_type = match layer.mode(nid).unwrap() & 0o170000 {
        0o040000 => TocEntryType::Dir,
        0o120000 => TocEntryType::Symlink,
        0o020000 => TocEntryType::Char,
        0o060000 => TocEntryType::Block,
        0o010000 => TocEntryType::Fifo,
        _ => TocEntryType::Reg,
    };
    (e.mode, e.uid, e.gid) = (u32::from(a.perm), a.uid, a.gid);
    match e.entry_type {
        TocEntryType::Reg => {
            let (digest, size) = layer.content(nid).unwrap();
            e.size = size;
            e.fsverity = digest.as_deref().and_then(velarx_storage::to_toc);
        }
        TocEntryType::Symlink => {
            e.link_name = Some(String::from_utf8_lossy(&layer.readlink(nid).unwrap()).into_owned())
        }
        TocEntryType::Char | TocEntryType::Block => {
            let d = a.rdev as libc::dev_t;
            (e.dev_major, e.dev_minor) = (Some(libc::major(d)), Some(libc::minor(d)));
        }
        _ => {}
    }
    for (k, v) in layer.raw_xattrs(nid) {
        e.xattrs.insert(
            String::from_utf8_lossy(&k).into_owned(),
            base64::engine::general_purpose::STANDARD.encode(v),
        );
    }
}

/// The root file system the view of the images makes: its entries, the
/// second name of a file a hard link.
fn view_entries(view: &ImageView) -> Vec<TocEntry> {
    let mut out = Vec::new();
    let mut first: HashMap<(usize, u64), String> = HashMap::new();
    let mut todo = vec![VIEW_ROOT];
    while let Some(dir) = todo.pop() {
        for (_, c) in view.children(dir).unwrap() {
            let n = view.node(c).unwrap();
            let mut e = n.entry;
            if e.entry_type != TocEntryType::Dir {
                if let Some(f) = first.get(&n.key) {
                    e.link_name = Some(f.clone());
                    e.entry_type = TocEntryType::Hardlink;
                    out.push(e);
                    continue;
                }
                first.insert(n.key, e.name.clone());
            }
            if e.entry_type == TocEntryType::Dir {
                todo.push(c);
            }
            out.push(e);
        }
    }
    out
}

fn tocs_of(layers: &[Vec<TocEntry>]) -> Vec<Toc> {
    layers
        .iter()
        .map(|entries| {
            serde_json::from_value(serde_json::json!({"version": 1, "entries": entries})).unwrap()
        })
        .collect()
}

/// The images of the layers as a pull makes them: the entries of each, and
/// the view of all of them.
fn images(layers: &[Vec<TocEntry>]) -> (Vec<Vec<TocEntry>>, Vec<TocEntry>) {
    let tocs = tocs_of(layers);
    let mut per_layer = Vec::new();
    let mut mapped = Vec::new();
    for toc in &tocs {
        let built = velarx_fuse::layer_erofs::layer_image(&toc.entries).unwrap();
        let layer = Layer::open(Box::new(built.image)).unwrap();
        per_layer.push(layer_entries(&layer));
        mapped.push(layer);
    }
    (per_layer, view_entries(&ImageView::new(mapped)))
}

fn report(problems: Vec<String>) {
    assert!(
        problems.is_empty(),
        "{} differences:\n{}",
        problems.len(),
        problems.join("\n")
    );
}

fn check(layers: &[Vec<TocEntry>]) {
    let (per_layer, merged) = images(layers);
    let want_entries = from_reference(&reference(layers));
    let (want, want_links) = tree_of(&want_entries);
    let (got, got_links) = tree_of(&merged);
    let mut problems = diff("view of the layers", &want, &got);
    if want_links != got_links {
        problems.push(format!(
            "hard links: want {want_links:?}, got {got_links:?}"
        ));
    }
    let resolved: Vec<Vec<TocEntry>> = per_layer.clone();
    let stack = stacked(&resolved);
    let (stack, _) = tree_of(&stack.into_values().collect::<Vec<_>>());
    problems.extend(diff("layer images stacked", &want, &stack));
    report(problems);
}

fn dir(name: &str) -> serde_json::Value {
    serde_json::json!({"name": name, "type": "dir", "mode": 0o755})
}

fn reg(name: &str, c: char, size: u64) -> serde_json::Value {
    serde_json::json!({"name": name, "type": "reg", "mode": 0o644, "size": size,
        "fsverity": format!("sha256-12:{}", hex(c))})
}

#[test]
fn layers_make_the_tree_the_oci_spec_says() {
    let base = make(serde_json::json!([
        dir(""),
        dir("etc"),
        reg("etc/passwd", 'a', 10),
        reg("etc/shadow", 'b', 11),
        dir("etc/conf.d"),
        reg("etc/conf.d/one", 'c', 12),
        reg("etc/conf.d/two", 'd', 13),
        dir("usr"),
        dir("usr/lib"),
        reg("usr/lib/libx.so.1", 'e', 14),
        {"name": "usr/lib/libx.so", "type": "symlink", "mode": 0o777, "linkName": "libx.so.1"},
        {"name": "usr/lib/liby.so", "type": "hardlink", "mode": 0o644, "linkName": "usr/lib/libx.so.1"},
        dir("var"),
        dir("var/cache"),
        reg("var/cache/blob", 'f', 15),
        dir("opt"),
        reg("opt/file", '1', 16),
        dir("srv"),
        reg("srv/data", '2', 17),
        dir("dev"),
        dir("run"),
        dir("bin"),
        {"name": "dev/null", "type": "char", "mode": 0o666, "devMajor": 1, "devMinor": 3},
        {"name": "run/fifo", "type": "fifo", "mode": 0o600},
        {"name": "bin/ping", "type": "reg", "mode": 0o755, "size": 18, "fsverity": format!("sha256-12:{}", hex('3')),
         "xattrs": {"security.capability": "AQAAAgAgAAAAAAAAAAAAAAAAAAA="}},
        {"name": "bin/su", "type": "reg", "mode": 0o4755, "size": 19, "uid": 0, "gid": 42,
         "fsverity": format!("sha256-12:{}", hex('4'))},
        {"name": "empty", "type": "reg", "mode": 0o644, "size": 0},
    ]));
    let second = make(serde_json::json!([
        // a file replaced, one removed, a directory made opaque
        reg("etc/passwd", '5', 20),
        {"name": "etc/.wh.shadow", "type": "reg"},
        dir("etc/conf.d"),
        {"name": "etc/conf.d/.wh..wh..opq", "type": "reg"},
        reg("etc/conf.d/three", '6', 21),
        // a symlink where a library was, and the other way
        {"name": "usr/lib/.wh.libx.so", "type": "reg"},
        reg("usr/lib/libx.so", '7', 22),
        // a directory replaced by a file, a file by a directory
        {"name": "var/.wh.cache", "type": "reg"},
        reg("var/cache", '8', 23),
        {"name": "opt/.wh.file", "type": "reg"},
        dir("opt/file"),
        reg("opt/file/inside", '9', 24),
        // a directory with new owner and mode, the content as it was
        {"name": "srv", "type": "dir", "mode": 0o700, "uid": 1000, "gid": 1000},
    ]));
    let third = make(serde_json::json!([
        // whiteout of a directory with content, then the directory again
        {"name": ".wh.var", "type": "reg"},
        dir("var"),
        reg("var/new", '0', 25),
        // a hard link to a file of this layer (one to a file of a layer
        // below is an error, as in podman: `layer_erofs`)
        reg("etc/hosts", 'a', 26),
        {"name": "etc/hosts2", "type": "hardlink", "linkName": "etc/hosts"},
        // a whiteout of a file that does not exist, and an entry before its
        // directory
        {"name": "etc/.wh.nothing", "type": "reg"},
        reg("deep/er/file", 'b', 27),
        dir("deep/er"),
        dir("deep"),
        {"name": "srv/data", "type": "reg", "mode": 0o600, "size": 17, "fsverity": format!("sha256-12:{}", hex('2')), "uid": 5},
    ]));
    check(&[base.clone(), second.clone()]);
    check(&[base, second, third]);
}

#[test]
fn a_single_layer_and_an_empty_layer() {
    let one = make(serde_json::json!([dir(""), dir("a"), reg("a/b", 'a', 3)]));
    check(std::slice::from_ref(&one));
    check(&[one, Vec::new()]);
}

fn from_tar(path: &Path) -> Vec<TocEntry> {
    use base64::Engine;
    use std::io::Read;
    let mut ar = tar::Archive::new(std::fs::File::open(path).unwrap());
    let mut out = Vec::new();
    for e in ar.entries().unwrap() {
        let mut e = e.unwrap();
        let name = e.path().unwrap().to_string_lossy().into_owned();
        let h = e.header().clone();
        let mut x = HashMap::new();
        if let Some(ext) = e.pax_extensions().unwrap() {
            for ext in ext.flatten() {
                if let Some(n) = ext.key().ok().and_then(|k| k.strip_prefix("SCHILY.xattr.")) {
                    x.insert(
                        n.to_string(),
                        base64::engine::general_purpose::STANDARD.encode(ext.value_bytes()),
                    );
                }
            }
        }
        use tar::EntryType as T;
        let t = match h.entry_type() {
            T::Regular | T::Continuous => TocEntryType::Reg,
            T::Directory => TocEntryType::Dir,
            T::Symlink => TocEntryType::Symlink,
            T::Link => TocEntryType::Hardlink,
            T::Char => TocEntryType::Char,
            T::Block => TocEntryType::Block,
            T::Fifo => TocEntryType::Fifo,
            _ => continue,
        };
        let mut data = Vec::new();
        if t == TocEntryType::Reg {
            e.read_to_end(&mut data).unwrap();
        }
        let mut te: TocEntry = serde_json::from_value(serde_json::json!({
            "name": name, "type": kind(t), "mode": h.mode().unwrap(),
            "uid": h.uid().unwrap(), "gid": h.gid().unwrap(),
        }))
        .unwrap();
        te.size = data.len() as u64;
        if !data.is_empty() {
            te.fsverity = velarx_storage::to_toc(&velarx_storage::fsverity_digest_of(
                velarx_types::digest::Algorithm::Sha256,
                &data,
            ));
        }
        // (the entry, not its header: a long name is an extension)
        te.link_name = e
            .link_name()
            .unwrap()
            .map(|l| l.to_string_lossy().into_owned());
        if matches!(t, TocEntryType::Char | TocEntryType::Block) {
            te.dev_major = h.device_major().unwrap();
            te.dev_minor = h.device_minor().unwrap();
        }
        te.xattrs = x;
        out.push(te);
    }
    out
}

/// What the images a pull made in a store make of the layers of an image
/// (`CFS_LAYERS`: a file of `[[digest, toc], ...]`, the lowest first; the
/// objects of the store in `CFS_FILES`), against the tar of `podman export`
/// (`CFS_TAR`) of the same image.  Paths podman adds to a container
/// (`CFS_IGNORE`, comma separated) are left out.
#[test]
#[ignore = "needs CFS_FILES, CFS_LAYERS and CFS_TAR"]
fn an_image_of_the_store_is_what_podman_exports() {
    let (Some(files), Some(layers), Some(tar)) = (
        std::env::var_os("CFS_FILES"),
        std::env::var_os("CFS_LAYERS"),
        std::env::var_os("CFS_TAR"),
    ) else {
        eprintln!("CFS_FILES, CFS_LAYERS and CFS_TAR say what to check");
        return;
    };
    let files = Path::new(&files);
    let pairs: Vec<(String, String)> =
        serde_json::from_slice(&std::fs::read(layers).unwrap()).unwrap();
    let digests: Vec<String> = pairs.iter().map(|(d, _)| d.clone()).collect();
    let ignore: Vec<String> = std::env::var("CFS_IGNORE")
        .unwrap_or_default()
        .split(',')
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect();
    let skip = |m: &BTreeMap<String, Seen>| -> BTreeMap<String, Seen> {
        m.iter()
            .filter(|(p, _)| {
                !ignore
                    .iter()
                    .any(|i| *p == i || p.starts_with(&format!("{i}/")))
            })
            .map(|(p, s)| (p.clone(), s.clone()))
            .collect()
    };
    let (want, want_links) = tree_of(&from_tar(Path::new(&tar)));
    let want = skip(&want);
    let mapped: Vec<Layer> = digests
        .iter()
        .map(|d| {
            let stem = velarx_db::LayerKey::parse(d).unwrap().file_stem();
            Layer::map(&cfs::layer_image_path(files, &stem)).unwrap()
        })
        .collect();
    let layer_images: Vec<Vec<TocEntry>> = mapped.iter().map(layer_entries).collect();
    let (got, got_links) = tree_of(&view_entries(&ImageView::new(mapped)));
    // (the layers name the files by the fs-verity digest, not the digest of
    // the content the tar has; the labels are the engine's)
    let nameless = |m: BTreeMap<String, Seen>| -> BTreeMap<String, Seen> {
        m.into_iter()
            .map(|(p, mut s)| {
                s.digest.clear();
                s.xattrs.retain(|k, _| !k.starts_with("security.selinux"));
                (p, s)
            })
            .collect()
    };
    let mut problems = diff(
        "view of the layers",
        &nameless(want.clone()),
        &nameless(skip(&got)),
    );
    let (stack, _) = tree_of(&stacked(&layer_images).into_values().collect::<Vec<_>>());
    problems.extend(diff(
        "layer images stacked",
        &nameless(want.clone()),
        &nameless(skip(&stack)),
    ));
    // the hard links: the groups podman's tar has, within the kept paths
    let kept = |g: &BTreeSet<BTreeSet<String>>| -> BTreeSet<BTreeSet<String>> {
        g.iter()
            .map(|s| {
                s.iter()
                    .filter(|p| want.contains_key(*p))
                    .cloned()
                    .collect()
            })
            .filter(|s: &BTreeSet<String>| s.len() > 1)
            .collect()
    };
    if kept(&want_links) != kept(&got_links) {
        problems.push(format!(
            "hard links: podman {} groups, the layers {}",
            kept(&want_links).len(),
            kept(&got_links).len()
        ));
    }
    eprintln!(
        "{} paths in {} layers: {} differences",
        want.len(),
        digests.len(),
        problems.len()
    );
    report(problems.into_iter().take(60).collect());
}

/// The files of the objects of a store, named by their fs-verity digest.
struct StoreFiles {
    store: velarx_storage::FileStore,
}

impl StoreFiles {
    fn read(objects: &Path) -> Self {
        Self {
            store: velarx_storage::FileStore::new(objects).unwrap(),
        }
    }
}

impl velarx_fuse::canonical::Files<composefs::fsverity::Sha256HashValue> for StoreFiles {
    fn regular(
        &mut self,
        e: &TocEntry,
    ) -> std::io::Result<composefs::tree::RegularFile<composefs::fsverity::Sha256HashValue>> {
        use composefs::tree::RegularFile;
        if e.size == 0 {
            return Ok(RegularFile::Inline(Box::new([])));
        }
        let path = e
            .verity()
            .and_then(|d| self.store.get_path(&d))
            .ok_or_else(|| std::io::Error::other("a file the store does not have"))?;
        let data = std::fs::read(path)?;
        if data.len() <= velarx_fuse::canonical::INLINE_MAX {
            return Ok(RegularFile::Inline(data.into_boxed_slice()));
        }
        Ok(RegularFile::External(
            composefs::fsverity::compute_verity(&data),
            data.len() as u64,
        ))
    }
}

/// The id of the merged EROFS of the layers `CFS_LAYERS` (as above) whose
/// files are in the objects `CFS_FILES`, as `cfsctl oci compute-id` of
/// composefs-rs says (`CFS_EXPECT_ID`, for a repository of
/// `fsverity-sha256-12`).
#[test]
#[ignore = "needs CFS_FILES, CFS_LAYERS and CFS_EXPECT_ID"]
fn the_merged_image_has_the_id_composefs_rs_gives() {
    let (Some(files), Some(layers), Some(expect)) = (
        std::env::var_os("CFS_FILES"),
        std::env::var_os("CFS_LAYERS"),
        std::env::var("CFS_EXPECT_ID").ok(),
    ) else {
        eprintln!("CFS_FILES, CFS_LAYERS and CFS_EXPECT_ID say what to check");
        return;
    };
    let files = Path::new(&files);
    let pairs: Vec<(String, String)> =
        serde_json::from_slice(&std::fs::read(layers).unwrap()).unwrap();
    let tocs: Vec<Toc> = pairs
        .iter()
        .map(|(_, t)| serde_json::from_str(t).unwrap())
        .collect();
    let layers: Vec<&[TocEntry]> = tocs.iter().map(|t| t.entries.as_slice()).collect();
    let mut store = StoreFiles::read(files);
    let tree =
        velarx_fuse::canonical::merge::<composefs::fsverity::Sha256HashValue>(&layers, &mut store)
            .unwrap();
    for version in [
        composefs::erofs::format::FormatVersion::V1,
        composefs::erofs::format::FormatVersion::V2,
    ] {
        let (_, got) = velarx_fuse::canonical::image(tree.clone(), version).unwrap();
        use composefs::fsverity::FsVerityHashValue;
        eprintln!("{version:?}: {} (composefs-rs: {expect})", got.to_hex());
    }
    let (_, got) = velarx_fuse::canonical::image(tree, Default::default()).unwrap();
    use composefs::fsverity::FsVerityHashValue;
    assert_eq!(got.to_hex(), expect);
}

// the same images mounted by the kernel (root) and served by FUSE (rootless)

/// Every path below `root`: kind and mode, owners, size, link target, device,
/// and the attributes (`user.overlay.*` read as `trusted.overlay.*`).
fn mounted_listing(root: &Path) -> Vec<String> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    let mut out = Vec::new();
    let mut todo = vec![root.to_path_buf()];
    while let Some(dir) = todo.pop() {
        for e in std::fs::read_dir(&dir).unwrap() {
            let p = e.unwrap().path();
            let m = std::fs::symlink_metadata(&p).unwrap();
            let mut xattrs: Vec<String> = xattr::list(&p)
                .unwrap()
                .map(|n| {
                    let v = xattr::get(&p, &n).unwrap().unwrap_or_default();
                    let n = n
                        .to_string_lossy()
                        .replace("user.overlay.", "trusted.overlay.");
                    format!("{n}={}", v.escape_ascii())
                })
                .filter(|x| !x.starts_with("security.selinux"))
                .collect();
            xattrs.sort();
            let link = std::fs::read_link(&p)
                .map(|l| l.display().to_string())
                .unwrap_or_default();
            let size = m.len();
            let rdev = if m.file_type().is_char_device() || m.file_type().is_block_device() {
                m.rdev()
            } else {
                0
            };
            out.push(format!(
                "{} {:o} {}:{} {} {link} {rdev} {} {xattrs:?}",
                p.strip_prefix(root).unwrap().display(),
                m.mode(),
                m.uid(),
                m.gid(),
                size,
                m.mtime()
            ));
            if m.is_dir() {
                todo.push(p);
            }
        }
    }
    out.sort();
    out
}

/// The image of a layer served by the FUSE file system of a rootless
/// container (its attributes in the namespace of a user, `userxattr`) is the
/// image the kernel mounts as root: the same paths, kinds, modes, owners,
/// sizes, links, devices, times and attributes.  As root only (the kernel
/// mounts EROFS for root); where FUSE cannot be mounted it is skipped.
#[test]
fn the_image_of_a_layer_is_the_same_mounted_and_served() {
    use std::os::fd::{AsFd, AsRawFd};
    if !rustix::process::geteuid().is_root() {
        eprintln!("skipped: the kernel mounts EROFS for root");
        return;
    }
    let entries = make(serde_json::json!([
        dir(""),
        dir("etc"),
        reg("etc/passwd", 'a', 10),
        {"name": "etc/.wh.gone", "type": "reg"},
        dir("opt"),
        {"name": "opt/.wh..wh..opq", "type": "reg"},
        reg("opt/x", 'b', 4097),
        {"name": "lib", "type": "symlink", "linkName": "usr/lib", "mode": 0o777},
        {"name": "usr/lib/libx.so", "type": "reg", "mode": 0o755, "size": 12, "uid": 7, "gid": 8,
         "fsverity": format!("sha256-12:{}", hex('c')), "xattrs": {"user.k": "dg==", "security.capability": "AQAAAgAgAAAAAAAAAAAAAAAAAAA="}},
        {"name": "usr/lib/liby.so", "type": "hardlink", "linkName": "usr/lib/libx.so"},
        {"name": "dev/null", "type": "char", "mode": 0o666, "devMajor": 1, "devMinor": 3},
        {"name": "run/fifo", "type": "fifo", "mode": 0o600},
        {"name": "empty", "type": "reg", "mode": 0o644, "size": 0},
    ]));
    let built = velarx_fuse::layer_erofs::layer_image(&entries).unwrap();
    // (the kernel does not mount an image of a tmpfs)
    let dir = tempfile::tempdir_in("/var/tmp").unwrap();
    let image = dir.path().join("layer.erofs");
    std::fs::write(&image, &built.image).unwrap();
    let file = std::fs::File::open(&image).unwrap();
    let fs = rustix::mount::fsopen("erofs", rustix::mount::FsOpenFlags::FSOPEN_CLOEXEC).unwrap();
    rustix::mount::fsconfig_set_string(
        fs.as_fd(),
        "source",
        format!("/proc/self/fd/{}", file.as_raw_fd()),
    )
    .unwrap();
    rustix::mount::fsconfig_create(fs.as_fd()).unwrap();
    let mnt = rustix::mount::fsmount(
        fs.as_fd(),
        rustix::mount::FsMountFlags::FSMOUNT_CLOEXEC,
        rustix::mount::MountAttrFlags::MOUNT_ATTR_RDONLY,
    )
    .unwrap();
    let kernel = PathBuf::from(format!("/proc/self/fd/{}", mnt.as_raw_fd()));
    let want = mounted_listing(&kernel);
    // FUSE's, as the image server serves it (a detached mount)
    let store =
        std::sync::Arc::new(velarx_storage::FileStore::new(dir.path().join("objects")).unwrap());
    let mounts = velarx_fuse::ImageMounts::new(store);
    let tree = velarx_fuse::erofs_tree::Layers::new(
        vec![Layer::open(Box::new(built.image)).unwrap()],
        None,
        true,
        velarx_fuse::erofs_tree::Stubs::Every,
    );
    let served = match mounts.mount_tree_detached(
        std::sync::Arc::new(tree),
        vec!["l".into()],
        built.owners,
        None,
    ) {
        Ok(r) => r,
        Err(e) => return eprintln!("skipped: cannot mount FUSE here: {e}"),
    };
    let got = mounted_listing(&PathBuf::from(format!(
        "/proc/self/fd/{}/layer1",
        served.as_raw_fd()
    )));
    drop(served);
    mounts.wait_detached();
    assert_eq!(got, want);
    assert!(
        want.iter().any(|l| l.contains("trusted.overlay.redirect")),
        "{want:#?}"
    );
}
