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
use velarx_storage::{Toc, TocEntry, TocEntryType};

/// The most bytes of a start set.
pub const MAX_BYTES: u64 = 64 << 20;

/// What the engine reads to make the container (the users and groups of
/// the image) and what the spec mounts over (the files of the network).
const FILES: [&str; 5] = [
    "/etc/passwd",
    "/etc/group",
    "/etc/hosts",
    "/etc/hostname",
    "/etc/resolv.conf",
];

/// Where a program is looked for when the image has no `PATH`: the `PATH`
/// the engine gives such a container.
const PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

/// The links followed for one name.
const MAX_LINKS: usize = 40;

/// The directories of a `PATH` a program is looked for in.
const MAX_PATH_DIRS: usize = 64;

/// The names of the tables of an image, as the overlay of its layers sees them.
pub struct Layers<'a> {
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
        Self { tables }
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
    fn program(&self, command: &str, path: Option<&str>) -> Option<(usize, &'a TocEntry)> {
        if command.contains('/') {
            return command.starts_with('/').then(|| self.file(command))?;
        }
        path.unwrap_or(PATH)
            .split(':')
            .take(MAX_PATH_DIRS)
            .find_map(|dir| self.file(&format!("{dir}/{command}")))
    }

    /// The files of the start set of an image whose configuration is
    /// `config`: each as the position of its layer (from the lowest) and its
    /// fs-verity digest.  The engine's files come first, then the program,
    /// each content once, up to [`MAX_BYTES`].
    pub fn start_set(&self, config: &velarx_types::OciImageConfig) -> Vec<(usize, String)> {
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
        let mut seen = HashSet::new();
        let mut bytes = 0u64;
        named
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
        assert_eq!(sizes(&layers, &[&low], &config), [10, 5, 1000]);
        let config = OciImageConfig {
            entrypoint: Some(vec!["/usr/local/bin/other".into()]),
            cmd: Some(vec!["python3".into()]),
            ..Default::default()
        };
        assert_eq!(sizes(&layers, &[&low], &config), [10, 5, 3]);
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
    fn sizes(layers: &Layers, tocs: &[&Toc], config: &OciImageConfig) -> Vec<u64> {
        layers
            .start_set(config)
            .iter()
            .map(|(at, d)| {
                tocs[*at]
                    .entries
                    .iter()
                    .find(|e| e.verity().as_deref() == Some(d))
                    .map_or(0, |e| e.size)
            })
            .collect()
    }

    #[test]
    fn the_start_set_is_bounded_in_bytes() {
        let low = toc(vec![
            dir("etc/"),
            file("etc/passwd", 10),
            file("etc/group", MAX_BYTES),
        ]);
        let layers = Layers::new(&[&low]);
        let set = layers.start_set(&OciImageConfig::default());
        assert_eq!(set.len(), 1);
    }
}
