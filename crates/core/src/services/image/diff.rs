// SPDX-License-Identifier: Apache-2.0
//! What a layer changes in the image below it, from the tables of contents
//! of the layers (`podman image diff`), and the paths of an image (to tell
//! the files a container added from the ones it changed).

use super::*;
use std::collections::BTreeSet;
use velarx_content::layer::dirtar::Change;
use velarx_content::pull::stored::stored_tocs;
use velarx_storage::TocEntry;

/// A path of a layer without `./`, `/` or a trailing slash.
fn clean(name: &str) -> &str {
    name.trim_start_matches("./")
        .trim_start_matches('/')
        .trim_end_matches('/')
}

/// What a whiteout entry hides: `Some((dir, None))` for an opaque
/// directory, `Some((dir, Some(name)))` for one path.
fn whiteout(path: &str) -> Option<(&str, Option<&str>)> {
    let (dir, base) = match path.rsplit_once('/') {
        Some((d, b)) => (d, b),
        None => ("", path),
    };
    let hidden = base.strip_prefix(".wh.")?;
    if hidden == ".wh..opq" {
        return Some((dir, None));
    }
    Some((dir, Some(hidden)))
}

fn join(dir: &str, name: &str) -> String {
    if dir.is_empty() {
        name.to_string()
    } else {
        format!("{dir}/{name}")
    }
}

/// Remove `path` and what is below it.
fn remove_tree(set: &mut BTreeSet<String>, path: &str) {
    set.remove(path);
    remove_below(set, path);
}

fn remove_below(set: &mut BTreeSet<String>, dir: &str) {
    let prefix = if dir.is_empty() {
        String::new()
    } else {
        format!("{dir}/")
    };
    let below: Vec<String> = set
        .range(prefix.clone()..)
        .take_while(|p| p.starts_with(&prefix))
        .cloned()
        .collect();
    for p in below {
        set.remove(&p);
    }
}

/// The paths of the image made of these layers, the lowest first.
pub fn merged_paths(tocs: &[Toc]) -> BTreeSet<String> {
    let mut set = BTreeSet::new();
    for toc in tocs {
        let names = toc
            .entries
            .iter()
            .filter(|e| e.entry_type != TocEntryType::Chunk)
            .map(|e| clean(&e.name))
            .filter(|n| !n.is_empty());
        // The whiteouts of a layer hide what is below it, not what is in
        // the layer itself.
        let mut added = Vec::new();
        for name in names {
            match whiteout(name) {
                Some((dir, None)) => remove_below(&mut set, dir),
                Some((dir, Some(hidden))) => remove_tree(&mut set, &join(dir, hidden)),
                None => added.push(name.to_string()),
            }
        }
        for name in added {
            // The parents of a path are in the image even if the layer does
            // not list them.
            let mut parent = name.as_str();
            while let Some((p, _)) = parent.rsplit_once('/') {
                set.insert(p.to_string());
                parent = p;
            }
            set.insert(name);
        }
    }
    set
}

/// The paths of the image made of these layers with their last entry
/// (None for a directory the layers only imply).
fn merged_entries(tocs: &[Toc]) -> std::collections::BTreeMap<String, Option<&TocEntry>> {
    let mut map = std::collections::BTreeMap::new();
    for toc in tocs {
        let entries = toc
            .entries
            .iter()
            .filter(|e| e.entry_type != TocEntryType::Chunk)
            .map(|e| (clean(&e.name), e))
            .filter(|(n, _)| !n.is_empty());
        let mut added = Vec::new();
        for (name, e) in entries {
            match whiteout(name) {
                Some((dir, None)) => {
                    let prefix = if dir.is_empty() {
                        String::new()
                    } else {
                        format!("{dir}/")
                    };
                    map.retain(|k: &String, _| !k.starts_with(&prefix));
                }
                Some((dir, Some(hidden))) => {
                    let path = join(dir, hidden);
                    let prefix = format!("{path}/");
                    map.remove(&path);
                    map.retain(|k: &String, _| !k.starts_with(&prefix));
                }
                None => added.push((name.to_string(), e)),
            }
        }
        for (name, e) in added {
            let mut parent = name.as_str();
            while let Some((p, _)) = parent.rsplit_once('/') {
                map.entry(p.to_string()).or_insert(None);
                parent = p;
            }
            map.insert(name, Some(e));
        }
    }
    map
}

/// Whether two entries of a path differ, as containers/storage compares
/// them: the type, the owner, the mode, and for what is not a directory
/// the size, the content, the target and the modification time.
fn entry_changed(a: &TocEntry, b: &TocEntry) -> bool {
    if a.entry_type != b.entry_type || (a.mode, a.uid, a.gid) != (b.mode, b.uid, b.gid) {
        return true;
    }
    a.entry_type != TocEntryType::Dir
        && (a.size != b.size
            || a.verity() != b.verity()
            || a.link_name != b.link_name
            || a.mod_time != b.mod_time)
}

/// What the image of `to` changes from the image of `from`, path by path.
pub fn changes_between(from: &[Toc], to: &[Toc]) -> Vec<(String, Change)> {
    let old = merged_entries(from);
    let new = merged_entries(to);
    let mut out = Vec::new();
    for (path, e) in &new {
        match old.get(path) {
            None => out.push((format!("/{path}"), Change::Added)),
            Some(o) => {
                if let (Some(o), Some(e)) = (o, e) {
                    if entry_changed(o, e) {
                        out.push((format!("/{path}"), Change::Modified));
                    }
                }
            }
        }
    }
    for path in old.keys() {
        if !new.contains_key(path) {
            out.push((format!("/{path}"), Change::Deleted));
        }
    }
    out.sort();
    out
}

/// The changes of the top layer of `tocs` against the layers below it.
pub fn layer_changes(tocs: &[Toc]) -> Vec<(String, Change)> {
    let Some((top, below)) = tocs.split_last() else {
        return Vec::new();
    };
    let lower = merged_paths(below);
    let mut out: Vec<(String, Change)> = Vec::new();
    for e in top
        .entries
        .iter()
        .filter(|e| e.entry_type != TocEntryType::Chunk)
    {
        let name = clean(&e.name);
        if name.is_empty() {
            continue;
        }
        match whiteout(name) {
            // (the kernel's overlay marks a directory made in a container as
            // opaque too: it is changed only if the layers below have it)
            Some((dir, None)) => {
                if lower.contains(dir) {
                    out.push((format!("/{dir}"), Change::Modified));
                }
            }
            Some((dir, Some(hidden))) => {
                out.push((format!("/{}", join(dir, hidden)), Change::Deleted))
            }
            None => {
                let change = if lower.contains(name) {
                    Change::Modified
                } else {
                    Change::Added
                };
                out.push((format!("/{name}"), change));
            }
        }
    }
    out.sort();
    out.dedup_by(|a, b| a.0 == b.0);
    out
}

impl ImageService {
    /// The tables of contents of the layers of an image, the lowest first.
    pub async fn layer_tocs(&self, image: &ImageRecord) -> ImageResult<Vec<Toc>> {
        let layers = self.db.get_image_layers(&image.id).await?;
        stored_tocs(&self.db, &layers.iter().map(|l| l.key).collect::<Vec<_>>()).await
    }

    /// What the image `reference` changes from the image `parent`.
    pub async fn image_changes_from(
        &self,
        parent: &str,
        reference: &str,
    ) -> ImageResult<Vec<(String, Change)>> {
        let from = self.layer_tocs(&self.get(parent).await?).await?;
        let to = self.layer_tocs(&self.get(reference).await?).await?;
        Ok(changes_between(&from, &to))
    }

    /// What the top layer of an image changes.
    pub async fn image_changes(&self, reference: &str) -> ImageResult<Vec<(String, Change)>> {
        let image = self.get(reference).await?;
        let tocs = self.layer_tocs(&image).await?;
        Ok(layer_changes(&tocs))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(name: &str, t: TocEntryType) -> TocEntry {
        TocEntry {
            mode: 0o644,
            ..TocEntry::new(name, t)
        }
    }

    fn toc(names: &[&str]) -> Toc {
        Toc {
            version: 1,
            entries: names
                .iter()
                .map(|n| {
                    let t = if n.ends_with('/') {
                        TocEntryType::Dir
                    } else {
                        TocEntryType::Reg
                    };
                    entry(n, t)
                })
                .collect(),
            tar_split_digest: None,
        }
    }

    #[test]
    fn test_changes_between_two_images() {
        let base = toc(&["etc/", "etc/a", "etc/b", "usr/", "usr/x"]);
        let mut changed = toc(&["etc/b"]);
        changed.entries[0].fsverity =
            velarx_storage::to_toc(&format!("fsverity-sha256-12:{}", "1".repeat(64)));
        let other = [
            base.clone(),
            changed,
            toc(&["etc/.wh.a", "usr/.wh..wh..opq", "srv/new"]),
        ];
        let got: Vec<(String, u8)> = changes_between(std::slice::from_ref(&base), &other)
            .into_iter()
            .map(|(p, c)| (p, c.kind()))
            .collect();
        let (m, a, d) = (
            Change::Modified.kind(),
            Change::Added.kind(),
            Change::Deleted.kind(),
        );
        assert_eq!(
            got,
            vec![
                ("/etc/a".to_string(), d),
                ("/etc/b".to_string(), m),
                ("/srv".to_string(), a),
                ("/srv/new".to_string(), a),
                ("/usr/x".to_string(), d),
            ]
        );
        assert!(
            changes_between(std::slice::from_ref(&base), std::slice::from_ref(&base)).is_empty()
        );
    }

    #[test]
    fn test_merged_paths_apply_whiteouts() {
        let base = toc(&["etc/", "etc/motd", "etc/a/b", "usr/x", "opt/old/f"]);
        let top = toc(&[
            "etc/.wh.motd",
            "etc/.wh.a",
            "opt/old/.wh..wh..opq",
            "opt/old/new",
        ]);
        let set = merged_paths(&[base, top]);
        let v: Vec<&str> = set.iter().map(String::as_str).collect();
        assert_eq!(v, ["etc", "opt", "opt/old", "opt/old/new", "usr", "usr/x"]);
    }

    #[test]
    fn test_layer_changes() {
        let base = toc(&["etc/", "etc/motd", "usr/x"]);
        let top = toc(&["etc/", "etc/.wh.motd", "etc/new", "usr/x", "./"]);
        let c = layer_changes(&[base, top]);
        assert_eq!(
            c,
            [
                ("/etc".to_string(), Change::Modified),
                ("/etc/motd".to_string(), Change::Deleted),
                ("/etc/new".to_string(), Change::Added),
                ("/usr/x".to_string(), Change::Modified),
            ]
        );
        assert!(layer_changes(&[]).is_empty());
    }

    #[test]
    fn test_layer_changes_opaque_directory_of_the_layer() {
        let base = toc(&["etc/", "etc/motd"]);
        // a directory made in a container on the kernel's overlay is opaque
        // in the layer; one that was there and was emptied is changed
        let top = toc(&[
            "app/",
            "app/.wh..wh..opq",
            "app/sub",
            "etc/",
            "etc/.wh..wh..opq",
        ]);
        let c = layer_changes(&[base, top]);
        assert_eq!(
            c,
            [
                ("/app".to_string(), Change::Added),
                ("/app/sub".to_string(), Change::Added),
                ("/etc".to_string(), Change::Modified),
            ]
        );
    }
}
