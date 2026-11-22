// SPDX-License-Identifier: Apache-2.0
//! The files a container start reads, found in the tables of contents of
//! its layers: fetched while the container is being made, so that the start
//! finds them staged instead of waiting for each.
//!
//! The set is what the engine and the runtime read whatever the command is:
//! the files the engine reads to make the container, the files the spec
//! mounts over (the runtime looks them up, and the lookup of a file that is
//! not there waits for its content), and the program the image starts.  It
//! is a list of names looked up in the layers as the overlay would: the
//! topmost layer that has a name wins, a whiteout or an opaque directory hides
//! the layers below, and a symbolic link is followed.

use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::os::unix::fs::FileExt;
use velarx_storage::{Toc, TocEntry, TocEntryType};

/// The most bytes of a start set.
pub const MAX_BYTES: u64 = 64 << 20;

/// What the engine reads to make the container (the users and groups of
/// the image), what the spec mounts over (the files of the network) and
/// the cache of the loader, which a dynamic program reads first.
pub const FILES: [&str; 6] = [
    "/etc/passwd",
    "/etc/group",
    "/etc/hosts",
    "/etc/hostname",
    "/etc/resolv.conf",
    LOADER_CACHE,
];

/// The cache of the loader of a dynamic program.
pub const LOADER_CACHE: &str = "/etc/ld.so.cache";

/// Where a program is looked for when the image has no `PATH`: the `PATH`
/// the engine gives such a container.
const PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

/// The links followed for one name.
const MAX_LINKS: usize = 40;

/// The directories of a `PATH` a program is looked for in.
const MAX_PATH_DIRS: usize = 64;

/// The directories the loader looks a library in when the cache has no path
/// for it, in its order.
const LIB_DIRS: [&str; 4] = ["/lib64", "/usr/lib64", "/lib", "/usr/lib"];

/// The most program headers, dynamic entries, needed names and bytes of a
/// string table read from a program, and the most bytes of the cache.
const MAX_PHNUM: usize = 128;
const MAX_DYNAMIC: usize = 4096;
const MAX_NEEDED: usize = 256;
const MAX_STRTAB: u64 = 1 << 20;
const MAX_CACHE: u64 = 16 << 20;

/// What the loader reads for a program: its interpreter and the names of
/// the libraries it needs.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Loader {
    pub interp: Option<String>,
    pub needed: Vec<String>,
}

fn read_at(file: &File, offset: u64, len: usize) -> Option<Vec<u8>> {
    let mut buf = vec![0; len];
    file.read_exact_at(&mut buf, offset).ok()?;
    Some(buf)
}

/// The little-endian number of `n` bytes at `at`.
fn le(buf: &[u8], at: usize, n: usize) -> Option<u64> {
    let bytes = buf.get(at..at.checked_add(n)?)?;
    Some(bytes.iter().rev().fold(0, |v, b| (v << 8) | u64::from(*b)))
}

/// The string at the start of `bytes`, up to the first NUL and at most
/// `max` bytes.
fn cstr(bytes: &[u8], max: usize) -> Option<&str> {
    let end = bytes.iter().position(|b| *b == 0)?;
    std::str::from_utf8(bytes.get(..end.min(max))?).ok()
}

/// The interpreter and the needed libraries of a 64-bit little-endian ELF
/// program, from its program headers.  Whatever is not that or does not
/// parse gives an empty [`Loader`]: it is a hint for what to fetch.
pub fn loader_of(file: &File) -> Loader {
    parse_loader(file).unwrap_or_default()
}

fn parse_loader(file: &File) -> Option<Loader> {
    let head = read_at(file, 0, 64)?;
    if head[..4] != *b"\x7fELF" || head[4] != 2 || head[5] != 1 || le(&head, 54, 2)? != 56 {
        return None;
    }
    let phnum = usize::try_from(le(&head, 56, 2)?).ok()?.min(MAX_PHNUM);
    let phdrs = read_at(file, le(&head, 32, 8)?, phnum * 56)?;
    // The program headers as (type, offset, vaddr, file size).
    let headers = (0..phnum)
        .map(|i| {
            let at = i * 56;
            Some((
                le(&phdrs, at, 4)?,
                le(&phdrs, at + 8, 8)?,
                le(&phdrs, at + 16, 8)?,
                le(&phdrs, at + 32, 8)?,
            ))
        })
        .collect::<Option<Vec<_>>>()?;
    let of_type = |t| headers.iter().find(|h| h.0 == t);
    let mut loader = Loader::default();
    if let Some(&(_, offset, _, size)) = of_type(3) {
        let bytes = read_at(file, offset, usize::try_from(size.min(4096)).ok()?)?;
        loader.interp = Some(cstr(&bytes, 4096)?.to_string());
    }
    let Some(&(_, offset, _, size)) = of_type(2) else {
        return Some(loader);
    };
    let count = usize::try_from(size / 16).ok()?.min(MAX_DYNAMIC);
    let dynamic = read_at(file, offset, count * 16)?;
    let (mut strtab, mut strsz, mut needed) = (None, 0, Vec::new());
    for i in 0..count {
        let (tag, value) = (le(&dynamic, i * 16, 8)?, le(&dynamic, i * 16 + 8, 8)?);
        match tag {
            0 => break,
            1 => needed.push(value),
            5 => strtab = Some(value),
            10 => strsz = value.min(MAX_STRTAB),
            _ => {}
        }
    }
    let Some(addr) = strtab.filter(|_| !needed.is_empty()) else {
        return Some(loader);
    };
    // The string table is at a virtual address: the file offset is through
    // the segment that has it.
    let &(_, seg_offset, seg_addr, _) = headers
        .iter()
        .find(|h| h.0 == 1 && addr >= h.2 && addr - h.2 < h.3)?;
    let table = read_at(
        file,
        seg_offset.checked_add(addr - seg_addr)?,
        usize::try_from(strsz).ok()?,
    )?;
    for name in needed.into_iter().take(MAX_NEEDED) {
        let from = usize::try_from(name).ok()?;
        if let Some(name) = table.get(from..).and_then(|t| cstr(t, 255)) {
            if !name.contains('/') {
                loader.needed.push(name.to_string());
            }
        }
    }
    Some(loader)
}

/// The paths of each soname in the glibc cache `file` (`/etc/ld.so.cache`,
/// the new format), in the order of the cache.  What is not that or does
/// not parse gives an empty map.
pub fn loader_cache(file: &File) -> HashMap<String, Vec<String>> {
    parse_cache(file).unwrap_or_default()
}

fn parse_cache(file: &File) -> Option<HashMap<String, Vec<String>>> {
    let len = file.metadata().ok()?.len();
    let buf = read_at(file, 0, usize::try_from(len.min(MAX_CACHE)).ok()?)?;
    if !buf.starts_with(b"glibc-ld.so.cache1.1") {
        return None;
    }
    let nlibs = usize::try_from(le(&buf, 20, 4)?).ok()?;
    let string = |at: usize| {
        cstr(
            buf.get(usize::try_from(le(&buf, at, 4)?).ok()?..)?,
            usize::MAX,
        )
    };
    let mut libs: HashMap<String, Vec<String>> = HashMap::new();
    for i in 0..nlibs.min(buf.len() / 24) {
        let at = 48 + i * 24;
        let (key, value) = (string(at + 4)?, string(at + 8)?);
        libs.entry(key.to_string())
            .or_default()
            .push(value.to_string());
    }
    Some(libs)
}

/// The names of the tables of an image, as the overlay of its layers sees them.
pub struct Layers<'a> {
    /// The tables, the lowest layer first
    tocs: Vec<&'a Toc>,
    /// The names of each, the topmost layer first
    tables: Vec<HashMap<&'a str, &'a TocEntry>>,
}

/// A name of a table: without `./` and without the `/` of a directory.
fn plain(name: &str) -> &str {
    name.strip_prefix("./")
        .unwrap_or(name)
        .trim_end_matches('/')
}

fn join(dir: &str, name: &str) -> String {
    if dir.is_empty() {
        name.to_string()
    } else {
        format!("{dir}/{name}")
    }
}

/// Whether the layer of the names `table` hides `path` of the layers below:
/// a whiteout of it or of a directory above it, or one of those directories
/// opaque.
fn hides(table: &HashMap<&str, &TocEntry>, path: &str) -> bool {
    let mut at = path;
    loop {
        let (dir, name) = at.rsplit_once('/').unwrap_or(("", at));
        if table.contains_key(join(dir, &format!(".wh.{name}")).as_str())
            || table.contains_key(join(dir, ".wh..wh..opq").as_str())
        {
            return true;
        }
        if dir.is_empty() {
            return false;
        }
        at = dir;
    }
}

impl<'a> Layers<'a> {
    /// The tables of the layers, the lowest first.
    pub fn new(tocs: &[&'a Toc]) -> Self {
        let tables = tocs
            .iter()
            .rev()
            .map(|toc| {
                let mut names = HashMap::new();
                for e in toc
                    .entries
                    .iter()
                    .filter(|e| e.entry_type != TocEntryType::Chunk)
                {
                    names.entry(plain(&e.name)).or_insert(e);
                }
                names
            })
            .collect();
        Self {
            tocs: tocs.to_vec(),
            tables,
        }
    }

    /// The entry the overlay shows for the name `path` (no link in it
    /// followed): its layer (counted from the topmost) and the entry.
    fn entry(&self, path: &str) -> Option<(usize, &'a TocEntry)> {
        for (i, table) in self.tables.iter().enumerate() {
            if let Some(e) = table.get(path) {
                return Some((i, e));
            }
            if hides(table, path) {
                return None;
            }
        }
        None
    }

    /// The regular file with content that the absolute name `path` is, its
    /// links followed: the position of its layer, counted from the lowest,
    /// and its entry.
    pub fn file(&self, path: &str) -> Option<(usize, &'a TocEntry)> {
        let mut todo: Vec<String> = path.split('/').rev().map(str::to_string).collect();
        let mut at: Vec<String> = Vec::new();
        let mut links = 0;
        while let Some(part) = todo.pop() {
            match part.as_str() {
                "" | "." => continue,
                ".." => {
                    at.pop();
                    continue;
                }
                _ => {}
            }
            let here = join(&at.join("/"), &part);
            let (layer, entry) = self.entry(&here)?;
            match entry.entry_type {
                TocEntryType::Symlink => {
                    links += 1;
                    if links > MAX_LINKS {
                        return None;
                    }
                    let target = entry.link_name.as_deref()?;
                    if target.starts_with('/') {
                        at.clear();
                    }
                    todo.extend(target.split('/').rev().map(str::to_string));
                }
                TocEntryType::Dir => at.push(part),
                TocEntryType::Reg if todo.iter().all(|p| p.is_empty() || p == ".") => {
                    return (entry.size > 0).then_some((self.tables.len() - 1 - layer, entry));
                }
                _ => return None,
            }
        }
        None
    }

    /// The program `command` is: the file of an absolute name, or the first
    /// of the `PATH` directories that has it (of the first [`MAX_PATH_DIRS`]:
    /// the configuration is the image's, and each costs a lookup).
    pub fn program(&self, command: &str, path: Option<&str>) -> Option<(usize, &'a TocEntry)> {
        if command.contains('/') {
            return command.starts_with('/').then(|| self.file(command))?;
        }
        path.unwrap_or(PATH)
            .split(':')
            .take(MAX_PATH_DIRS)
            .find_map(|dir| self.file(&format!("{dir}/{command}")))
    }

    /// The files the loader of `loader` reads, each once: the interpreter,
    /// then for each needed library the first path of the `cache` that is a
    /// file, else the first of the default directories that has it.
    pub fn libraries(
        &self,
        loader: &Loader,
        cache: &HashMap<String, Vec<String>>,
    ) -> Vec<(usize, &'a TocEntry)> {
        let mut found: Vec<(usize, &'a TocEntry)> = Vec::new();
        let files = loader.interp.iter().filter_map(|p| self.file(p)).chain(
            loader.needed.iter().filter_map(|name| {
                let cached = cache.get(name).into_iter().flatten();
                cached.filter_map(|p| self.file(p)).next().or_else(|| {
                    LIB_DIRS
                        .iter()
                        .find_map(|d| self.file(&format!("{d}/{name}")))
                })
            }),
        );
        for (layer, e) in files {
            if !found.iter().any(|(_, f)| std::ptr::eq(*f, e)) {
                found.push((layer, e));
            }
        }
        found
    }

    /// The files of the start set of an image whose configuration is
    /// `config` and whose startup profile is `profile`: each as the position
    /// of its layer (from the lowest) and its fs-verity digest.  The engine's
    /// files come first, then the program, then the files of the profile in
    /// its order, each content once, up to [`MAX_BYTES`].  The profile is a
    /// hint that anybody may have written: what it names that is not a
    /// regular file of one of the tables is left out.
    pub fn start_set(
        &self,
        config: &velarx_types::OciImageConfig,
        profile: &[String],
    ) -> Vec<(usize, String)> {
        let path = config.env.iter().find_map(|e| e.strip_prefix("PATH="));
        let command = config
            .entrypoint
            .iter()
            .chain(&config.cmd)
            .flatten()
            .next()
            .and_then(|c| self.program(c, path));
        let named = FILES
            .iter()
            .filter_map(|f| self.file(f))
            .chain(command)
            .filter_map(|(layer, e)| Some((layer, e.verity()?, e.size)));
        let profiled = (!profile.is_empty())
            .then(|| self.contents())
            .into_iter()
            .flat_map(|at| {
                profile
                    .iter()
                    .filter_map(move |d| at.get(d).map(|&(layer, size)| (layer, d.clone(), size)))
            });
        let mut seen = HashSet::new();
        let mut bytes = 0u64;
        named
            .chain(profiled)
            .filter(|(_, d, size)| {
                let fits = bytes.saturating_add(*size) <= MAX_BYTES;
                if fits && seen.insert(d.clone()) {
                    bytes += size;
                    return true;
                }
                false
            })
            .map(|(layer, d, _)| (layer, d))
            .collect()
    }

    /// The regular files with content of the tables by fs-verity digest: the
    /// lowest layer that has the content, and its size.
    fn contents(&self) -> HashMap<String, (usize, u64)> {
        let mut at = HashMap::new();
        for (layer, toc) in self.tocs.iter().enumerate() {
            for e in toc
                .entries
                .iter()
                .filter(|e| e.entry_type == TocEntryType::Reg && e.size > 0)
            {
                if let Some(d) = e.verity() {
                    at.entry(d).or_insert((layer, e.size));
                }
            }
        }
        at
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use velarx_types::OciImageConfig;

    fn entry(name: &str, kind: TocEntryType, size: u64, link: Option<&str>) -> TocEntry {
        let d = format!(
            "fsverity-sha256-12:{:064x}",
            name.len() as u64 * 1000 + size
        );
        TocEntry {
            size,
            fsverity: (kind == TocEntryType::Reg && size > 0)
                .then(|| velarx_storage::to_toc(&d))
                .flatten(),
            link_name: link.map(str::to_string),
            ..TocEntry::new(name, kind)
        }
    }

    fn toc(entries: Vec<TocEntry>) -> Toc {
        Toc {
            version: 1,
            entries,
            tar_split_digest: None,
        }
    }

    fn file(name: &str, size: u64) -> TocEntry {
        entry(name, TocEntryType::Reg, size, None)
    }

    fn dir(name: &str) -> TocEntry {
        entry(name, TocEntryType::Dir, 0, None)
    }

    fn link(name: &str, to: &str) -> TocEntry {
        entry(name, TocEntryType::Symlink, 0, Some(to))
    }

    fn layer_of(layers: &Layers, path: &str) -> Option<usize> {
        layers.file(path).map(|(l, _)| l)
    }

    #[test]
    fn the_topmost_layer_that_has_a_name_wins() {
        let (low, high) = (
            toc(vec![
                dir("etc/"),
                file("etc/passwd", 10),
                file("etc/group", 5),
            ]),
            toc(vec![dir("./etc/"), file("./etc/passwd", 20)]),
        );
        let layers = Layers::new(&[&low, &high]);
        assert_eq!(layer_of(&layers, "/etc/passwd"), Some(1));
        assert_eq!(layer_of(&layers, "/etc/group"), Some(0));
        assert_eq!(layer_of(&layers, "/etc/shadow"), None);
    }

    #[test]
    fn a_whiteout_and_an_opaque_directory_hide_the_layers_below() {
        let low = toc(vec![
            dir("etc/"),
            file("etc/passwd", 10),
            file("etc/group", 5),
            dir("usr/"),
            file("usr/a", 1),
        ]);
        let high = toc(vec![
            dir("etc/"),
            file("etc/.wh.passwd", 0),
            dir("usr/"),
            file("usr/.wh..wh..opq", 0),
        ]);
        let layers = Layers::new(&[&low, &high]);
        assert_eq!(layer_of(&layers, "/etc/passwd"), None);
        assert_eq!(layer_of(&layers, "/etc/group"), Some(0));
        assert_eq!(layer_of(&layers, "/usr/a"), None);
    }

    #[test]
    fn a_directory_above_hides_what_is_below_it() {
        let low = toc(vec![
            dir("usr/"),
            dir("usr/local/"),
            dir("usr/local/bin/"),
            file("usr/local/bin/tool", 1),
            dir("opt/"),
            dir("opt/app/"),
            file("opt/app/run", 2),
        ]);
        // (the directories are there again above, empty: opaque, or made
        // after a whiteout of the old ones)
        let high = toc(vec![
            dir("usr/"),
            file("usr/.wh..wh..opq", 0),
            dir("usr/local/"),
            file(".wh.opt", 0),
            dir("opt/"),
            dir("opt/app/"),
        ]);
        let layers = Layers::new(&[&low, &high]);
        assert_eq!(layer_of(&layers, "/usr/local/bin/tool"), None);
        assert_eq!(layer_of(&layers, "/opt/app/run"), None);
        let layers = Layers::new(&[&low]);
        assert_eq!(layer_of(&layers, "/usr/local/bin/tool"), Some(0));
    }

    #[test]
    fn links_are_followed_in_the_name_and_at_its_end() {
        let low = toc(vec![
            dir("usr/"),
            dir("usr/bin/"),
            file("usr/bin/real", 7),
            link("usr/bin/alias", "real"),
            link("bin", "usr/bin"),
            link("loop", "loop"),
        ]);
        let high = toc(vec![
            link("tool", "/bin/alias"),
            link("up", "usr/../usr/bin/real"),
        ]);
        let layers = Layers::new(&[&low, &high]);
        assert_eq!(layer_of(&layers, "/tool"), Some(0));
        assert_eq!(layer_of(&layers, "/up"), Some(0));
        assert_eq!(layer_of(&layers, "/bin/real"), Some(0));
        assert_eq!(layer_of(&layers, "/loop"), None);
        assert_eq!(layer_of(&layers, "/usr"), None);
        assert_eq!(layer_of(&layers, "/usr/bin/real/x"), None);
    }

    #[test]
    fn the_start_set_is_the_engines_files_and_the_program() {
        let low = toc(vec![
            dir("etc/"),
            file("etc/passwd", 10),
            file("etc/group", 5),
            file("etc/hosts", 0),
            dir("usr/"),
            dir("usr/local/"),
            dir("usr/local/bin/"),
            file("usr/local/bin/python3.12", 1000),
            link("usr/local/bin/python3", "python3.12"),
            file("usr/local/bin/other", 3),
        ]);
        let layers = Layers::new(&[&low]);
        let config = OciImageConfig {
            cmd: Some(vec!["python3".into()]),
            ..Default::default()
        };
        assert_eq!(sizes(&layers, &config, &[]), [10, 5, 1000]);
        let config = OciImageConfig {
            entrypoint: Some(vec!["/usr/local/bin/other".into()]),
            cmd: Some(vec!["python3".into()]),
            ..Default::default()
        };
        assert_eq!(sizes(&layers, &config, &[]), [10, 5, 3]);
    }

    /// The program is looked for in the first [`MAX_PATH_DIRS`] directories
    /// of the `PATH` of the image only.
    #[test]
    fn the_program_is_looked_for_in_the_first_directories_of_the_path() {
        let low = toc(vec![dir("bin/"), file("bin/sh", 7)]);
        let layers = Layers::new(&[&low]);
        let path = |misses: usize| vec!["/none"; misses].join(":") + ":/bin";
        assert!(layers
            .program("sh", Some(&path(MAX_PATH_DIRS - 1)))
            .is_some());
        assert!(layers.program("sh", Some(&path(MAX_PATH_DIRS))).is_none());
    }

    /// The sizes of the files of the start set, as the table of the first
    /// layer gives them.
    fn sizes(layers: &Layers, config: &OciImageConfig, profile: &[String]) -> Vec<u64> {
        layers
            .start_set(config, profile)
            .iter()
            .map(|(at, d)| {
                layers.tocs[*at]
                    .entries
                    .iter()
                    .find(|e| e.verity().as_deref() == Some(d))
                    .map_or(0, |e| e.size)
            })
            .collect()
    }

    #[test]
    fn the_profile_follows_in_its_order_and_only_names_files_of_the_tables() {
        let low = toc(vec![
            dir("etc/"),
            file("etc/passwd", 10),
            file("usr/a", 1),
            file("usr/b", 2),
            file("usr/c", 3),
            dir("usr/d"),
        ]);
        let layers = Layers::new(&[&low]);
        let digest = |size: u64, name: &str| file(name, size).verity().unwrap();
        let profile = vec![
            digest(3, "usr/c"),
            "fsverity-sha256-12:".to_string() + &"0".repeat(64),
            digest(1, "usr/a"),
            digest(3, "usr/c"),
            digest(10, "etc/passwd"),
        ];
        assert_eq!(
            sizes(&layers, &OciImageConfig::default(), &profile),
            [10, 3, 1]
        );
    }

    #[test]
    fn a_profile_is_bounded_in_bytes() {
        let low = toc(vec![file("a", 1), file("big", MAX_BYTES), file("bb", 2)]);
        let layers = Layers::new(&[&low]);
        let digest = |size: u64, name: &str| file(name, size).verity().unwrap();
        let profile = vec![digest(1, "a"), digest(MAX_BYTES, "big"), digest(2, "bb")];
        assert_eq!(sizes(&layers, &OciImageConfig::default(), &profile), [1, 2]);
    }

    #[test]
    fn the_start_set_is_bounded_in_bytes() {
        let low = toc(vec![
            dir("etc/"),
            file("etc/passwd", 10),
            file("etc/group", MAX_BYTES),
        ]);
        let layers = Layers::new(&[&low]);
        let set = layers.start_set(&OciImageConfig::default(), &[]);
        assert_eq!(set.len(), 1);
    }

    /// A minimal ELF64: one segment of the whole file at its own offsets, an
    /// interpreter, and a dynamic section with the string table `strtab`
    /// and the needed `names`.
    fn elf(interp: &str, names: &[&str]) -> tempfile::NamedTempFile {
        let (interp_at, dyn_at) = (64 + 4 * 56, 64 + 4 * 56 + 64);
        let mut strtab = vec![0u8];
        let offsets: Vec<u64> = names
            .iter()
            .map(|n| {
                strtab.extend(n.bytes().chain([0]));
                (strtab.len() - n.len() - 1) as u64
            })
            .collect();
        let dyn_len = (names.len() + 3) * 16;
        let str_at = (dyn_at + dyn_len) as u64;
        let mut out = vec![0u8; 64];
        out[..4].copy_from_slice(b"\x7fELF");
        out[4] = 2;
        out[5] = 1;
        out[32..40].copy_from_slice(&64u64.to_le_bytes());
        out[54..56].copy_from_slice(&56u16.to_le_bytes());
        out[56..58].copy_from_slice(&4u16.to_le_bytes());
        let total = str_at + strtab.len() as u64;
        let phdr = |kind: u32, offset: u64, size: u64| {
            let mut h = Vec::new();
            h.extend(kind.to_le_bytes());
            h.extend(0u32.to_le_bytes());
            h.extend(offset.to_le_bytes());
            h.extend(offset.to_le_bytes());
            h.extend(offset.to_le_bytes());
            h.extend(size.to_le_bytes());
            h.extend(size.to_le_bytes());
            h.extend(0u64.to_le_bytes());
            h
        };
        out.extend(phdr(1, 0, total));
        out.extend(phdr(3, interp_at as u64, interp.len() as u64 + 1));
        out.extend(phdr(2, dyn_at as u64, dyn_len as u64));
        out.extend(phdr(0x6474e551, 0, 0));
        out.resize(interp_at, 0);
        out.extend(interp.bytes().chain([0]));
        out.resize(dyn_at, 0);
        let mut entries = vec![(5, str_at), (10, strtab.len() as u64)];
        entries.extend(offsets.into_iter().map(|o| (1, o)));
        entries.push((0, 0));
        for (tag, value) in entries {
            out.extend(u64::to_le_bytes(tag));
            out.extend(value.to_le_bytes());
        }
        out.extend(strtab);
        let mut f = tempfile::NamedTempFile::new().unwrap();
        std::io::Write::write_all(&mut f, &out).unwrap();
        f
    }

    fn names(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn the_loader_of_a_program_is_its_interpreter_and_needed_libraries() {
        let f = elf("/lib64/ld-linux-x86-64.so.2", &["libc.so.6", "libm.so.6"]);
        let loader = loader_of(f.as_file());
        assert_eq!(
            loader.interp.as_deref(),
            Some("/lib64/ld-linux-x86-64.so.2")
        );
        assert_eq!(loader.needed, names(&["libc.so.6", "libm.so.6"]));
    }

    #[test]
    fn what_is_not_a_64_bit_little_endian_program_has_no_loader() {
        let f = elf("/lib64/ld.so", &["libc.so.6"]);
        let bytes = std::fs::read(f.path()).unwrap();
        let write = |b: &[u8]| {
            let mut g = tempfile::NamedTempFile::new().unwrap();
            std::io::Write::write_all(&mut g, b).unwrap();
            g
        };
        for len in [0, 3, 63, 64, 100, 300, bytes.len() - 1] {
            assert_eq!(loader_of(write(&bytes[..len]).as_file()), Loader::default());
        }
        let mut be = bytes.clone();
        be[5] = 2;
        assert_eq!(loader_of(write(&be).as_file()), Loader::default());
        let mut small = bytes.clone();
        small[4] = 1;
        assert_eq!(loader_of(write(&small).as_file()), Loader::default());
        let garbage: Vec<u8> = (0..4096u32).map(|i| (i * 31 % 251) as u8).collect();
        assert_eq!(loader_of(write(&garbage).as_file()), Loader::default());
        // A string table address outside the segment.
        let mut wild = bytes.clone();
        wild[64 + 4 * 56 + 64 + 8..][..8].copy_from_slice(&u64::MAX.to_le_bytes());
        assert_eq!(
            loader_of(write(&wild).as_file()).needed,
            Vec::<String>::new()
        );
    }

    fn cache_file(entries: &[(&str, &str)]) -> tempfile::NamedTempFile {
        let mut strings = Vec::new();
        let base = 48 + entries.len() * 24;
        let mut table = Vec::new();
        for (key, value) in entries {
            for s in [key, value] {
                table.push((base + strings.len()) as u32);
                strings.extend(s.bytes().chain([0]));
            }
        }
        let mut out = b"glibc-ld.so.cache1.1".to_vec();
        out.extend((entries.len() as u32).to_le_bytes());
        out.extend((strings.len() as u32).to_le_bytes());
        out.resize(48, 0);
        for pair in table.chunks(2) {
            out.extend(1i32.to_le_bytes());
            out.extend(pair[0].to_le_bytes());
            out.extend(pair[1].to_le_bytes());
            out.extend([0; 12]);
        }
        out.extend(strings);
        let mut f = tempfile::NamedTempFile::new().unwrap();
        std::io::Write::write_all(&mut f, &out).unwrap();
        f
    }

    #[test]
    fn the_cache_maps_a_soname_to_its_paths_in_order() {
        let f = cache_file(&[
            ("libc.so.6", "/lib64/libc.so.6"),
            ("libc.so.6", "/usr/lib/libc.so.6"),
            ("libm.so.6", "/lib64/libm.so.6"),
        ]);
        let cache = loader_cache(f.as_file());
        assert_eq!(cache.len(), 2);
        assert_eq!(
            cache["libc.so.6"],
            names(&["/lib64/libc.so.6", "/usr/lib/libc.so.6"])
        );
        assert_eq!(cache["libm.so.6"], names(&["/lib64/libm.so.6"]));
    }

    #[test]
    fn a_cache_that_is_not_the_new_format_is_empty() {
        let f = cache_file(&[("libc.so.6", "/lib64/libc.so.6")]);
        let bytes = std::fs::read(f.path()).unwrap();
        for b in [
            &bytes[..30],
            &bytes[..60],
            b"ld.so-1.7.0 and more bytes",
            b"",
        ] {
            let mut g = tempfile::NamedTempFile::new().unwrap();
            std::io::Write::write_all(&mut g, b).unwrap();
            assert!(loader_cache(g.as_file()).is_empty());
        }
    }

    #[test]
    fn the_libraries_are_from_the_cache_or_the_default_directories() {
        let low = toc(vec![
            dir("lib64/"),
            file("lib64/ld.so", 1),
            file("lib64/libc.so.6", 2),
            dir("opt/"),
            file("opt/libc.so.6", 3),
            dir("usr/"),
            dir("usr/lib64/"),
            file("usr/lib64/libm.so.6", 4),
            file("usr/lib64/libreal.so", 5),
            link("usr/lib64/libm-link.so", "libreal.so"),
        ]);
        let layers = Layers::new(&[&low]);
        let loader = Loader {
            interp: Some("/lib64/ld.so".into()),
            needed: names(&[
                "libc.so.6",
                "libm.so.6",
                "libm-link.so",
                "libreal.so",
                "libnone.so",
            ]),
        };
        let cache = HashMap::from([(
            "libc.so.6".to_string(),
            names(&["/gone/libc.so.6", "/opt/libc.so.6"]),
        )]);
        let sizes = |cache| -> Vec<u64> {
            layers
                .libraries(&loader, cache)
                .iter()
                .map(|(_, e)| e.size)
                .collect()
        };
        assert_eq!(sizes(&cache), [1, 3, 4, 5]);
        assert_eq!(sizes(&HashMap::new()), [1, 2, 4, 5]);
    }
}
