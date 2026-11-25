// SPDX-License-Identifier: Apache-2.0
//! The canonical tar against tarballs of other producers: a tar goes to a
//! table of contents (what a layer converter does: sorted, one entry for
//! a path, the first path of a file is the file), the table to the canonical
//! tar, and the validator accepts it.
//!
//! The tarballs are made here with GNU tar and with Go's `archive/tar`
//! (the test is skipped where they are not installed), and by a random
//! generator; the layers of real images are the ones of the directory named
//! by `VELARX_LAYER_TARS`, when it is set.

use base64::Engine;
use rand::{rngs::StdRng, Rng, SeedableRng};
use std::collections::{BTreeMap, HashMap};
use std::io::{self, Read};
use std::path::Path;
use std::process::Command;
use velarx_storage::canonical::{stream_size, validate, validate_tar, write};
use velarx_storage::{fsverity_digest_of, to_toc, TocEntry, TocEntryType};
use velarx_types::digest::Algorithm;

type Contents = HashMap<String, Vec<u8>>;

fn blank(name: &str, kind: TocEntryType) -> TocEntry {
    TocEntry::new(name.to_string(), kind)
}

fn rfc3339(secs: i64, nanos: u32) -> Option<String> {
    (secs != 0 || nanos != 0).then(|| {
        chrono::DateTime::from_timestamp(secs, nanos)
            .unwrap()
            .to_rfc3339()
    })
}

/// A PAX time: `[-]seconds[.fraction]`.
fn pax_time(v: &[u8]) -> (i64, u32) {
    let s = std::str::from_utf8(v).unwrap();
    let (neg, s) = s.strip_prefix('-').map_or((false, s), |s| (true, s));
    let (secs, frac) = s.split_once('.').unwrap_or((s, ""));
    let secs: i64 = secs.parse().unwrap();
    let nanos: u32 = if frac.is_empty() {
        0
    } else {
        format!("{frac:0<9}")[..9].parse().unwrap()
    };
    match (neg, nanos) {
        (false, n) => (secs, n),
        (true, 0) => (-secs, 0),
        (true, n) => (-secs - 1, 1_000_000_000 - n),
    }
}

/// The PAX records before each entry of a tar (the `x` entries and the GNU
/// long names are not entries: the `tar` crate folds them in the next one).
fn pax_records(tar: &[u8]) -> Vec<Vec<(String, Vec<u8>)>> {
    let mut out = Vec::new();
    let mut pending = Vec::new();
    let mut at = 0;
    while at + 512 <= tar.len() && tar[at..at + 512] != [0; 512] {
        let h = &tar[at..at + 512];
        let size = std::str::from_utf8(&h[124..135])
            .ok()
            .and_then(|s| usize::from_str_radix(s.trim_matches(['\0', ' ']), 8).ok())
            .unwrap_or(0);
        let data = &tar[at + 512..(at + 512 + size).min(tar.len())];
        match h[156] {
            b'x' => {
                let mut rest = data;
                while !rest.is_empty() {
                    let space = rest.iter().position(|&b| b == b' ').unwrap();
                    let len: usize = std::str::from_utf8(&rest[..space])
                        .unwrap()
                        .parse()
                        .unwrap();
                    let record = &rest[space + 1..len - 1];
                    let eq = record.iter().position(|&b| b == b'=').unwrap();
                    let key = String::from_utf8(record[..eq].to_vec()).unwrap();
                    pending.push((key, record[eq + 1..].to_vec()));
                    rest = &rest[len..];
                }
            }
            b'L' | b'K' => {}
            _ => out.push(std::mem::take(&mut pending)),
        }
        let data_size = if matches!(h[156], b'0' | b'7' | 0 | b'x' | b'g' | b'L' | b'K') {
            size
        } else {
            0
        };
        at += 512 + data_size.next_multiple_of(512);
    }
    out
}

/// The components of a path of a tar, without the empty and `.` ones.
fn path_parts(path: &[u8]) -> Result<Vec<String>, String> {
    let path = std::str::from_utf8(path).map_err(|_| "a name that is not UTF-8")?;
    let mut parts = Vec::new();
    for c in path.split('/') {
        match c {
            "" | "." => {}
            ".." => return Err("a `..` in a name".into()),
            c => parts.push(c.to_string()),
        }
    }
    Ok(parts)
}

fn canonical_name(parts: &[String], dir: bool) -> String {
    let mut name = format!("./{}", parts.join("/"));
    if dir && !parts.is_empty() {
        name.push('/');
    }
    name
}

fn sort_key(e: &TocEntry) -> Vec<&str> {
    let n = e.name.strip_prefix("./").unwrap();
    let n = n.strip_suffix('/').unwrap_or(n);
    if n.is_empty() {
        vec![]
    } else {
        n.split('/').collect()
    }
}

#[derive(Clone)]
struct Item {
    entry: TocEntry,
    data: Vec<u8>,
    xattrs: BTreeMap<String, Vec<u8>>,
}

/// The table of contents of the layer a tar holds, and the contents of its
/// files.  What it does is what a converter of foreign layers has to do: the
/// rules of the canonical tar do not say what to do with a tar that breaks
/// them, they only fix the stream a table of contents has.
fn convert(tar: &[u8]) -> Result<(Vec<TocEntry>, Contents), String> {
    let mut items: HashMap<String, Item> = HashMap::new();
    let mut archive = tar::Archive::new(tar);
    let records = pax_records(tar);
    for (entry, records) in archive.entries().map_err(|e| e.to_string())?.zip(records) {
        let mut entry = entry.map_err(|e| e.to_string())?;
        let kind = match entry.header().entry_type() {
            tar::EntryType::Regular | tar::EntryType::Continuous => TocEntryType::Reg,
            tar::EntryType::Link => TocEntryType::Hardlink,
            tar::EntryType::Symlink => TocEntryType::Symlink,
            tar::EntryType::Char => TocEntryType::Char,
            tar::EntryType::Block => TocEntryType::Block,
            tar::EntryType::Directory => TocEntryType::Dir,
            tar::EntryType::Fifo => TocEntryType::Fifo,
            tar::EntryType::XGlobalHeader => continue,
            t => return Err(format!("the type {t:?}")),
        };
        let parts = path_parts(&entry.path_bytes())?;
        let name = canonical_name(&parts, kind == TocEntryType::Dir);
        let mut e = blank(&name, kind);
        e.mode = entry.header().mode().map_err(|e| e.to_string())? & 0o7777;
        e.uid = entry.header().uid().map_err(|e| e.to_string())? as u32;
        e.gid = entry.header().gid().map_err(|e| e.to_string())? as u32;
        let mut mtime = (entry.header().mtime().map_err(|e| e.to_string())? as i64, 0);
        let mut xattrs = BTreeMap::new();
        for (key, value) in &records {
            match key.as_str() {
                "uid" => {
                    e.uid = std::str::from_utf8(value)
                        .unwrap()
                        .parse()
                        .map_err(|_| "uid")?
                }
                "gid" => {
                    e.gid = std::str::from_utf8(value)
                        .unwrap()
                        .parse()
                        .map_err(|_| "gid")?
                }
                "mtime" => mtime = pax_time(value),
                key => {
                    if let Some(n) = key.strip_prefix("SCHILY.xattr.") {
                        if !n.starts_with("trusted.overlay.") && !n.starts_with("user.overlay.") {
                            xattrs.insert(n.to_string(), value.clone());
                        }
                    } else if key.starts_with("SCHILY.acl.") {
                        return Err(format!("`{name}` has ACLs"));
                    }
                }
            }
        }
        e.mod_time = rfc3339(
            mtime.0.clamp(-62_135_596_800, 253_402_300_799),
            if (-62_135_596_800..=253_402_300_799).contains(&mtime.0) {
                mtime.1
            } else {
                0
            },
        );
        if let Some(l) = entry.link_name_bytes() {
            e.link_name = Some(match kind {
                TocEntryType::Hardlink => canonical_name(&path_parts(&l)?, false),
                _ => {
                    String::from_utf8(l.to_vec()).map_err(|_| "a link target that is not UTF-8")?
                }
            });
        }
        if matches!(kind, TocEntryType::Char | TocEntryType::Block) {
            e.dev_major = entry.header().device_major().map_err(|e| e.to_string())?;
            e.dev_minor = entry.header().device_minor().map_err(|e| e.to_string())?;
        }
        let mut data = Vec::new();
        if kind == TocEntryType::Reg {
            entry.read_to_end(&mut data).map_err(|e| e.to_string())?;
            e.size = data.len() as u64;
        }
        let base = parts.last().map(String::as_str).unwrap_or("");
        if base.starts_with(".wh.")
            || (kind == TocEntryType::Char && e.dev_major == Some(0) && e.dev_minor == Some(0))
        {
            let base = base.trim_start_matches(".wh.");
            let mut wh = parts.clone();
            if let Some(last) = wh.last_mut() {
                *last = format!(".wh.{base}");
            }
            e = blank(&canonical_name(&wh, false), TocEntryType::Reg);
            e.mode = 0o644;
            data = Vec::new();
            xattrs = BTreeMap::new();
        }
        items.insert(
            e.name.clone(),
            Item {
                entry: e,
                data,
                xattrs,
            },
        );
    }

    // the first path of a file is the file, the others are links to it
    let mut groups: HashMap<String, Vec<String>> = HashMap::new();
    let links: Vec<(String, String)> = items
        .values()
        .filter(|i| i.entry.entry_type == TocEntryType::Hardlink)
        .map(|i| (i.entry.name.clone(), i.entry.link_name.clone().unwrap()))
        .collect();
    let by_name = |n: &String| items.get(n).map(|i| i.entry.entry_type);
    for (name, mut target) in links {
        while by_name(&target) == Some(TocEntryType::Hardlink) {
            target = items[&target].entry.link_name.clone().unwrap();
        }
        if by_name(&target).is_none() {
            return Err(format!(
                "`{name}` is a link to `{target}`, which is not in the layer"
            ));
        }
        groups.entry(target).or_default().push(name);
    }
    for (target, mut names) in groups {
        names.push(target.clone());
        let key = |n: &String| {
            let e = &items[n].entry;
            sort_key(e)
                .into_iter()
                .map(String::from)
                .collect::<Vec<_>>()
        };
        names.sort_by_key(key);
        let first = names[0].clone();
        let original = items[&target].clone();
        for n in &names {
            let i = items.get_mut(n).unwrap();
            let mut e = original.entry.clone();
            e.name = n.clone();
            if *n == first {
                i.data = original.data.clone();
                i.xattrs = original.xattrs.clone();
            } else {
                e.entry_type = TocEntryType::Hardlink;
                e.link_name = Some(first.clone());
                e.size = 0;
                e.dev_major = None;
                e.dev_minor = None;
                i.data.clear();
                i.xattrs.clear();
            }
            i.entry = e;
        }
    }
    let mut list: Vec<Item> = items.into_values().collect();
    list.sort_by(|a, b| sort_key(&a.entry).cmp(&sort_key(&b.entry)));
    let mut contents = Contents::new();
    let mut entries = Vec::new();
    for mut i in list {
        for (k, v) in &i.xattrs {
            i.entry.xattrs.insert(
                k.clone(),
                base64::engine::general_purpose::STANDARD.encode(v),
            );
        }
        if i.entry.size > 0 {
            i.entry.fsverity = to_toc(&fsverity_digest_of(Algorithm::Sha256, &i.data));
            (i.entry.offset, i.entry.end_offset) = (1, 2);
            contents.insert(i.entry.name.clone(), i.data);
        }
        entries.push(i.entry);
    }
    Ok((entries, contents))
}

fn generate(entries: &[TocEntry], contents: &Contents) -> Vec<u8> {
    let mut out = Vec::new();
    write(entries, &mut out, |e, w| w.write_all(&contents[&e.name])).unwrap();
    out
}

/// The tar read back: what every entry says, as the `tar` crate and the
/// table of contents have it.
fn check_against_the_table(canonical: &[u8], entries: &[TocEntry], contents: &Contents) {
    let mut archive = tar::Archive::new(canonical);
    let mut tar_entries = archive.entries().unwrap();
    let mut records = pax_records(canonical).into_iter();
    for e in entries
        .iter()
        .filter(|e| e.entry_type != TocEntryType::Chunk)
    {
        let mut t = tar_entries
            .next()
            .expect("an entry less in the tar")
            .unwrap();
        let records = records.next().unwrap();
        assert_eq!(t.path_bytes().as_ref(), e.name.as_bytes());
        let (mut uid, mut gid) = (t.header().uid().unwrap(), t.header().gid().unwrap());
        let mut mtime = (t.header().mtime().unwrap() as i64, 0);
        let mut xattrs = BTreeMap::new();
        for (key, value) in &records {
            match key.as_str() {
                "uid" => uid = std::str::from_utf8(value).unwrap().parse().unwrap(),
                "gid" => gid = std::str::from_utf8(value).unwrap().parse().unwrap(),
                "mtime" => mtime = pax_time(value),
                k => {
                    if let Some(n) = k.strip_prefix("SCHILY.xattr.") {
                        xattrs.insert(
                            n.to_string(),
                            base64::engine::general_purpose::STANDARD.encode(value),
                        );
                    }
                }
            }
        }
        let want = e
            .mod_time
            .as_deref()
            .map_or((0, 0), |t| velarx_storage::toc_time(Some(t)).unwrap());
        assert_eq!(mtime, want, "{}", e.name);
        assert_eq!(
            (uid, gid, t.header().mode().unwrap()),
            (e.uid.into(), e.gid.into(), e.mode),
            "{}",
            e.name
        );
        assert_eq!(
            xattrs,
            e.xattrs
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect::<BTreeMap<_, _>>(),
            "{}",
            e.name
        );
        assert!(t.header().username_bytes().is_none_or(|b| b.is_empty()));
        assert!(t.header().groupname_bytes().is_none_or(|b| b.is_empty()));
        match e.entry_type {
            TocEntryType::Reg => {
                assert!(t.header().entry_type().is_file());
                let mut data = Vec::new();
                t.read_to_end(&mut data).unwrap();
                assert_eq!(data.len() as u64, e.size);
                if e.size > 0 {
                    assert_eq!(data, contents[&e.name], "{}", e.name);
                }
            }
            TocEntryType::Dir => assert!(t.header().entry_type().is_dir()),
            TocEntryType::Symlink => {
                assert!(t.header().entry_type().is_symlink());
                assert_eq!(
                    t.link_name_bytes().unwrap().as_ref(),
                    e.link_name.as_ref().unwrap().as_bytes()
                );
            }
            TocEntryType::Hardlink => {
                assert!(t.header().entry_type().is_hard_link());
                assert_eq!(
                    t.link_name_bytes().unwrap().as_ref(),
                    e.link_name.as_ref().unwrap().as_bytes()
                );
            }
            TocEntryType::Char => assert!(t.header().entry_type().is_character_special()),
            TocEntryType::Block => assert!(t.header().entry_type().is_block_special()),
            TocEntryType::Fifo => assert!(t.header().entry_type().is_fifo()),
            TocEntryType::Chunk => unreachable!(),
        }
    }
    assert!(tar_entries.next().is_none(), "an entry more in the tar");
}

/// What a tar of another producer gives through the table and the canonical
/// tar: every property of the format.
fn round_trip(tar: &[u8], what: &str) -> Vec<u8> {
    let (entries, contents) = convert(tar).unwrap_or_else(|e| panic!("{what}: {e}"));
    validate(&entries).unwrap_or_else(|e| panic!("{what}: {e}"));
    let canonical = generate(&entries, &contents);
    validate_tar(&canonical[..]).unwrap_or_else(|e| panic!("{what}: {e}"));
    assert_eq!(
        canonical.len() as u64,
        stream_size(&entries).unwrap(),
        "{what}"
    );
    check_against_the_table(&canonical, &entries, &contents);
    // the canonical tar of a canonical tar is itself
    let (again, again_contents) = convert(&canonical).unwrap();
    assert_eq!(generate(&again, &again_contents), canonical, "{what}");
    canonical
}

fn gnu_tar_works() -> bool {
    Command::new("tar")
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success())
}

fn run(dir: &Path, cmd: &str, args: &[&str]) {
    let out = Command::new(cmd)
        .args(args)
        .current_dir(dir)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{cmd} {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// A directory of the kinds of things a layer has.
fn tree(root: &Path) {
    let long = "d".repeat(80);
    let deep = root.join(&long).join(&long).join(&long);
    std::fs::create_dir_all(&deep).unwrap();
    std::fs::create_dir_all(root.join("a")).unwrap();
    std::fs::write(root.join("a/b"), b"in a").unwrap();
    std::fs::write(root.join("a-c"), b"before a/b in a string sort").unwrap();
    std::fs::write(root.join("a.d"), vec![7u8; 1500]).unwrap();
    std::fs::write(deep.join("e".repeat(120)), b"long path").unwrap();
    std::fs::write(root.join("empty"), b"").unwrap();
    std::fs::write(root.join("big"), vec![1u8; 100_000]).unwrap();
    std::fs::write(root.join("unicode-\u{e9}\u{4e2d}"), b"u").unwrap();
    std::fs::write(root.join("z"), b"later").unwrap();
    std::fs::hard_link(root.join("z"), root.join("a/first-link")).unwrap();
    std::fs::hard_link(root.join("z"), root.join("m-link")).unwrap();
    std::os::unix::fs::symlink("a/b", root.join("sym")).unwrap();
    std::os::unix::fs::symlink("t".repeat(150), root.join("longsym")).unwrap();
    std::fs::write(root.join(".wh.gone"), b"").unwrap();
    std::fs::write(root.join("a/.wh..wh..opq"), b"").unwrap();
    run(root, "mkfifo", &["fifo"]);
    for (f, t) in [
        ("a/b", "2023-11-14 22:13:20.123456789 +0000"),
        ("a-c", "2001-02-03 04:05:06 +0000"),
        ("z", "2023-11-14 22:13:20.5 +0000"),
        ("big", "1960-05-06 07:08:09.25 +0000"),
        ("sym", "2023-11-14 22:13:20.000000001 +0000"),
    ] {
        run(root, "touch", &["-h", "-d", t, f]);
    }
    run(root, "chmod", &["4755", "a/b"]);
    run(root, "chmod", &["1777", "a"]);
    if Command::new("setfattr")
        .args(["-n", "user.test", "-v", "va\nlue", "a/b"])
        .current_dir(root)
        .status()
        .is_ok_and(|s| s.success())
    {
        run(root, "setfattr", &["-n", "user.other", "-v", "2", "a/b"]);
    }
}

#[test]
fn tarballs_of_gnu_tar_go_through_the_canonical_tar() {
    if !gnu_tar_works() {
        return eprintln!("skipped: no GNU tar");
    }
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("root");
    std::fs::create_dir(&root).unwrap();
    tree(&root);
    let mut sizes = Vec::new();
    for format in ["gnu", "oldgnu", "posix", "pax", "ustar", "v7"] {
        for owner in [&[][..], &["--owner=3000000", "--group=2097152"][..]] {
            for xattrs in [&[][..], &["--xattrs"][..]] {
                let tarball = dir.path().join("t.tar");
                let mut args = vec![
                    "-cf",
                    tarball.to_str().unwrap(),
                    "--numeric-owner",
                    "--format",
                    format,
                ];
                args.extend(owner);
                args.extend(xattrs);
                args.extend(["-C", root.to_str().unwrap(), "."]);
                let out = Command::new("tar").args(&args).output().unwrap();
                if !out.status.success() {
                    // (a format that cannot hold the tree: v7 has no long names)
                    continue;
                }
                let bytes = std::fs::read(&tarball).unwrap();
                let what = format!("GNU tar {format} {owner:?} {xattrs:?}");
                match convert(&bytes) {
                    Ok(_) => sizes.push(round_trip(&bytes, &what).len()),
                    Err(e) => assert!(format == "v7" || format == "ustar", "{what}: {e}"),
                }
            }
        }
    }
    // (the formats that hold the tree: gnu, oldgnu, posix and pax)
    assert!(sizes.len() >= 8, "{sizes:?}");
}

#[test]
fn the_canonical_tar_is_read_by_gnu_tar_without_a_word() {
    if !gnu_tar_works() {
        return eprintln!("skipped: no GNU tar");
    }
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("root");
    std::fs::create_dir(&root).unwrap();
    tree(&root);
    let tarball = dir.path().join("t.tar");
    run(
        &root,
        "tar",
        &[
            "-cf",
            tarball.to_str().unwrap(),
            "--numeric-owner",
            "--format",
            "pax",
            ".",
        ],
    );
    let canonical = round_trip(&std::fs::read(&tarball).unwrap(), "pax");
    let path = dir.path().join("canonical.tar");
    std::fs::write(&path, &canonical).unwrap();
    let out = Command::new("tar")
        .args(["-tvf", path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(out.status.success());
    assert_eq!(String::from_utf8_lossy(&out.stderr), "");
    let listing = String::from_utf8(out.stdout).unwrap();
    assert!(listing.contains("./a/b"), "{listing}");
    // extracted, the files are the ones of the table: content and time
    let into = dir.path().join("out");
    std::fs::create_dir(&into).unwrap();
    let out = Command::new("tar")
        .args(["-xf", path.to_str().unwrap(), "-C", into.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(std::fs::read(into.join("a/b")).unwrap(), b"in a");
    let stat = |p: &Path| {
        let o = Command::new("stat")
            .args(["-c", "%.9Y %s"])
            .arg(p)
            .output()
            .unwrap();
        String::from_utf8(o.stdout).unwrap()
    };
    for f in ["a/b", "a-c", "z", "big", "empty", "a/first-link"] {
        assert_eq!(stat(&root.join(f)), stat(&into.join(f)), "{f}");
    }
    assert_eq!(
        std::fs::metadata(into.join("z")).unwrap().ino(),
        std::fs::metadata(into.join("m-link")).unwrap().ino()
    );
}

use std::os::unix::fs::MetadataExt;

const GO_PROGRAM: &str = r#"
package main

import (
	"archive/tar"
	"fmt"
	"os"
	"strings"
	"time"
)

func main() {
	for _, f := range []tar.Format{tar.FormatUSTAR, tar.FormatPAX, tar.FormatGNU} {
		out, err := os.Create(fmt.Sprintf("%s/go-%d.tar", os.Args[1], f))
		if err != nil {
			panic(err)
		}
		w := tar.NewWriter(out)
		long := strings.Repeat("d", 80)
		entries := []tar.Header{
			{Typeflag: tar.TypeDir, Name: "./", Mode: 0755},
			{Typeflag: tar.TypeDir, Name: "usr/", Mode: 0755, ModTime: time.Unix(1700000000, 0)},
			{Typeflag: tar.TypeReg, Name: "usr/bin", Mode: 04755, Uid: 1000, Gid: 2097152, Size: 5, ModTime: time.Unix(1700000000, 0)},
			{Typeflag: tar.TypeReg, Name: "usr-x", Mode: 0644, Size: 3, ModTime: time.Unix(1, 0)},
			{Typeflag: tar.TypeLink, Name: "usr/bin2", Linkname: "usr/bin", Mode: 04755, Uid: 1000, Gid: 2097152},
			{Typeflag: tar.TypeSymlink, Name: "usr/sh", Linkname: "bin", Mode: 0777},
			{Typeflag: tar.TypeReg, Name: long + "/" + long + "/" + long + "/file", Mode: 0600, Size: 2},
			{Typeflag: tar.TypeFifo, Name: "fifo", Mode: 0600},
			{Typeflag: tar.TypeChar, Name: "dev/null", Mode: 0666, Devmajor: 1, Devminor: 3},
			{Typeflag: tar.TypeReg, Name: ".wh.removed", Mode: 0},
		}
		if f == tar.FormatUSTAR {
			entries[2].Gid = 2097151
			entries[4].Gid = 2097151
		}
		if f == tar.FormatPAX {
			entries[2].ModTime = time.Unix(1700000000, 123456789)
			entries[2].PAXRecords = map[string]string{"SCHILY.xattr.user.k": "v\n\x00w", "SCHILY.xattr.security.capability": "cap"}
			entries[3].ModTime = time.Unix(-5, 250000000)
			entries[6].ModTime = time.Unix(8589934592, 7)
		}
		if f == tar.FormatGNU {
			entries[3].ModTime = time.Unix(-5, 0)
			entries[6].ModTime = time.Unix(8589934592, 0)
		}
		for i := range entries {
			h := entries[i]
			h.Format = f
			if f == tar.FormatUSTAR && len(h.Name) > 100 {
				continue
			}
			if f != tar.FormatUSTAR || h.Size < 1<<33 {
				if err := w.WriteHeader(&h); err != nil {
					panic(fmt.Sprint(f, h.Name, err))
				}
				w.Write([]byte(strings.Repeat("c", int(h.Size))))
			}
		}
		w.Close()
		out.Close()
	}
}
"#;

#[test]
fn tarballs_of_go_archive_tar_go_through_the_canonical_tar() {
    if Command::new("go").arg("version").output().is_err() {
        return eprintln!("skipped: no go");
    }
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("src");
    std::fs::create_dir(&src).unwrap();
    std::fs::write(src.join("main.go"), GO_PROGRAM).unwrap();
    let out = dir.path().join("out");
    std::fs::create_dir(&out).unwrap();
    let ran = Command::new("go")
        .args(["run", "main.go", out.to_str().unwrap()])
        .current_dir(&src)
        .env("GOCACHE", dir.path().join("cache"))
        .env("GO111MODULE", "off")
        .output()
        .unwrap();
    assert!(
        ran.status.success(),
        "{}",
        String::from_utf8_lossy(&ran.stderr)
    );
    let mut n = 0;
    for f in std::fs::read_dir(&out).unwrap() {
        let f = f.unwrap().path();
        let bytes = std::fs::read(&f).unwrap();
        round_trip(&bytes, f.to_str().unwrap());
        n += 1;
    }
    assert_eq!(n, 3);
}

/// The layers of real images, uncompressed, in the directory of
/// `VELARX_LAYER_TARS`.
#[test]
fn the_layers_of_real_images_go_through_the_canonical_tar() {
    let Some(dir) = std::env::var_os("VELARX_LAYER_TARS") else {
        return eprintln!("skipped: VELARX_LAYER_TARS is not set");
    };
    let mut n = 0;
    for f in std::fs::read_dir(dir).unwrap() {
        let f = f.unwrap().path();
        if f.extension().is_none_or(|e| e != "tar") {
            continue;
        }
        let bytes = std::fs::read(&f).unwrap();
        round_trip(&bytes, f.to_str().unwrap());
        n += 1;
    }
    assert!(n > 0);
    eprintln!("{n} layers");
}

fn random_name(rng: &mut StdRng) -> String {
    const PARTS: [&str; 12] = [
        "a", "b", "ab", "a-c", "a.d", "é", "中", "z", ".h", "_", "0", "x y",
    ];
    let mut s = String::new();
    for _ in 0..rng.gen_range(1..=3) {
        s.push_str(PARTS[rng.gen_range(0..PARTS.len())]);
    }
    if rng.gen_ratio(1, 8) {
        s.push_str(&"n".repeat(rng.gen_range(90..130)));
    }
    s
}

/// A random layer: the table and the contents.
fn random_layer(rng: &mut StdRng) -> (Vec<TocEntry>, Contents) {
    let mut paths: BTreeMap<Vec<String>, TocEntry> = BTreeMap::new();
    for _ in 0..rng.gen_range(0..40) {
        let depth = rng.gen_range(1..=3);
        let parts: Vec<String> = (0..depth).map(|_| random_name(rng)).collect();
        let kind = match rng.gen_range(0..10) {
            0..=2 => TocEntryType::Dir,
            3..=5 => TocEntryType::Reg,
            6 => TocEntryType::Symlink,
            7 => TocEntryType::Fifo,
            8 => TocEntryType::Char,
            _ => TocEntryType::Reg,
        };
        let name = canonical_name(&parts, kind == TocEntryType::Dir);
        let mut e = blank(&name, kind);
        e.mode = [0o644, 0o755, 0o4755, 0o1777, 0o7777, 0, 0o600][rng.gen_range(0..7)];
        e.uid = [0, 1000, 2_097_151, 2_097_152, u32::MAX, 65534][rng.gen_range(0..6)];
        e.gid = [0, 1000, 2_097_151, 2_097_152, u32::MAX, 65534][rng.gen_range(0..6)];
        let secs = [
            0i64,
            1,
            1_700_000_000,
            8_589_934_591,
            8_589_934_592,
            -1,
            -62_135_596_800,
            253_402_300_799,
        ][rng.gen_range(0..8)];
        let nanos = [0u32, 0, 5, 500_000_000, 999_999_999, 123_456_780][rng.gen_range(0..6)];
        e.mod_time = rfc3339(secs, if secs == 253_402_300_799 { 0 } else { nanos });
        match kind {
            TocEntryType::Symlink => {
                e.link_name = Some("t".repeat(rng.gen_range(1..130)));
                e.mode = 0o777;
            }
            TocEntryType::Char => {
                e.dev_major = Some(rng.gen_range(1..4096));
                e.dev_minor = Some(rng.gen_range(0..1 << 20));
            }
            _ => {}
        }
        if kind == TocEntryType::Reg && !parts.last().unwrap().starts_with(".wh.") {
            e.size = rng.gen_range(0..1500);
        }
        if kind != TocEntryType::Dir || rng.gen_bool(0.5) {
            for _ in 0..rng.gen_range(0..3) {
                let mut v = vec![0u8; rng.gen_range(0..40)];
                rng.fill(&mut v[..]);
                e.xattrs.insert(
                    format!("user.k{}", rng.gen_range(0..5)),
                    base64::engine::general_purpose::STANDARD.encode(&v),
                );
            }
        }
        paths.insert(parts, e);
    }
    if rng.gen_bool(0.5) {
        paths.insert(vec![], {
            let mut r = blank("./", TocEntryType::Dir);
            r.mode = 0o755;
            r
        });
    }
    // a whiteout or two
    for _ in 0..rng.gen_range(0..3) {
        let parts = vec![format!(".wh.{}", random_name(rng))];
        let mut w = blank(&canonical_name(&parts, false), TocEntryType::Reg);
        w.mode = 0o644;
        paths.insert(parts, w);
    }
    let mut entries: Vec<TocEntry> = paths.into_values().collect();
    entries.sort_by(|a, b| sort_key(a).cmp(&sort_key(b)));
    // contents, and hard links to a file of an earlier path
    let mut contents = Contents::new();
    let mut out: Vec<TocEntry> = Vec::new();
    let mut files: Vec<usize> = Vec::new();
    for mut e in entries {
        if e.has_content() {
            let mut data = vec![0u8; e.size as usize];
            rng.fill(&mut data[..]);
            e.fsverity = to_toc(&fsverity_digest_of(Algorithm::Sha256, &data));
            (e.offset, e.end_offset) = (1, 2);
            contents.insert(e.name.clone(), data);
        }
        let linkable = matches!(
            e.entry_type,
            TocEntryType::Reg | TocEntryType::Symlink | TocEntryType::Fifo
        ) && !e.name.rsplit('/').next().unwrap().starts_with(".wh.");
        if linkable && !files.is_empty() && rng.gen_ratio(1, 3) {
            let target = &out[files[rng.gen_range(0..files.len())]];
            let link = TocEntry {
                name: e.name,
                entry_type: TocEntryType::Hardlink,
                link_name: Some(target.name.clone()),
                ..blank("", TocEntryType::Hardlink)
            };
            let link = TocEntry {
                mode: target.mode,
                uid: target.uid,
                gid: target.gid,
                mod_time: target.mod_time.clone(),
                ..link
            };
            contents.remove(&link.name);
            out.push(link);
        } else {
            if linkable {
                files.push(out.len());
            }
            out.push(e);
        }
    }
    (out, contents)
}

#[test]
fn random_layers_have_a_canonical_tar_that_is_valid() {
    let mut rng = StdRng::seed_from_u64(0xc0ffee);
    let mut hard_links = 0;
    for round in 0..300 {
        let (entries, contents) = random_layer(&mut rng);
        hard_links += entries
            .iter()
            .filter(|e| e.entry_type == TocEntryType::Hardlink)
            .count();
        validate(&entries).unwrap_or_else(|e| panic!("round {round}: {e}"));
        let tar = generate(&entries, &contents);
        validate_tar(&tar[..]).unwrap_or_else(|e| panic!("round {round}: {e}"));
        assert_eq!(tar.len() as u64, stream_size(&entries).unwrap());
        check_against_the_table(&tar, &entries, &contents);
        // and the table read back from the tar is the table
        let (back, back_contents) = convert(&tar).unwrap();
        assert_eq!(generate(&back, &back_contents), tar, "round {round}");
        assert_eq!(back.len(), entries.len());
    }
    assert!(hard_links > 20, "{hard_links}");
}

#[test]
fn a_tar_is_canonical_exactly_when_it_is_what_the_generator_makes_of_it() {
    let mut rng = StdRng::seed_from_u64(7);
    let (mut accepted, mut rejected) = (0, 0);
    for _ in 0..40 {
        let (entries, contents) = random_layer(&mut rng);
        let tar = generate(&entries, &contents);
        for _ in 0..60 {
            let mut bad = tar.clone();
            match rng.gen_range(0..6) {
                0 => {
                    let at = rng.gen_range(0..bad.len().max(1));
                    if !bad.is_empty() {
                        bad[at] ^= 1 << rng.gen_range(0..8);
                    }
                }
                1 => bad.truncate(rng.gen_range(0..=bad.len())),
                2 => {
                    let at = rng.gen_range(0..=bad.len());
                    let n = rng.gen_range(1..40);
                    bad.splice(at..at, (0..n).map(|_| rng.gen::<u8>()));
                }
                3 => {
                    // a block removed or repeated
                    let blocks = bad.len() / 512;
                    let b = rng.gen_range(0..blocks) * 512;
                    if rng.gen_bool(0.5) {
                        bad.drain(b..b + 512);
                    } else {
                        let block = bad[b..b + 512].to_vec();
                        bad.splice(b..b, block);
                    }
                }
                4 => {
                    let at = rng.gen_range(0..bad.len());
                    bad[at] = [0, b' ', b'0', b'7', b'x', b'/', 0xff][rng.gen_range(0..7)];
                }
                _ => {
                    let blocks = bad.len() / 512;
                    let (a, b) = (
                        rng.gen_range(0..blocks) * 512,
                        rng.gen_range(0..blocks) * 512,
                    );
                    for i in 0..512 {
                        bad.swap(a + i, b + i);
                    }
                }
            }
            if validate_tar(&bad[..]).is_ok() {
                accepted += 1;
                // what is accepted is what the generator makes of it
                let (again, again_contents) = convert(&bad).expect("a canonical tar is a layer");
                assert_eq!(generate(&again, &again_contents), bad);
            } else {
                rejected += 1;
            }
        }
    }
    assert!(rejected > 1500, "{rejected}");
    // (content bytes and the values of records change into other valid ones)
    assert!(accepted > 20, "{accepted}");
}

#[test]
fn a_stream_that_ends_where_it_likes_is_an_error_and_never_a_panic() {
    struct Cut(Vec<u8>, usize);
    impl Read for Cut {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if self.1 >= self.0.len() {
                return Err(io::Error::other("the read failed"));
            }
            let n = buf.len().min(self.0.len() - self.1);
            buf[..n].copy_from_slice(&self.0[self.1..self.1 + n]);
            self.1 += n;
            Ok(n)
        }
    }
    let mut rng = StdRng::seed_from_u64(3);
    let (entries, contents) = random_layer(&mut rng);
    let tar = generate(&entries, &contents);
    assert!(validate_tar(Cut(tar, 0)).is_err());
    // random bytes and a header of random bytes
    for _ in 0..200 {
        let mut junk = vec![0u8; rng.gen_range(0..4096)];
        rng.fill(&mut junk[..]);
        assert!(validate_tar(&junk[..]).is_err());
    }
}

const GO_READER: &str = r#"
package main

import (
	"archive/tar"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
)

func main() {
	f, err := os.Open(os.Args[1])
	if err != nil {
		panic(err)
	}
	r := tar.NewReader(f)
	for {
		h, err := r.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			panic(err)
		}
		var x []string
		for k, v := range h.PAXRecords {
			if strings.HasPrefix(k, "SCHILY.xattr.") {
				x = append(x, strings.TrimPrefix(k, "SCHILY.xattr.")+"="+hex.EncodeToString([]byte(v)))
			}
		}
		sort.Strings(x)
		n, _ := io.Copy(io.Discard, r)
		fmt.Printf("%s\t%d.%09d\t%d\t%d\t%o\t%d\t%c\t%s\t%s\t%d\n", h.Name, h.ModTime.Unix(), h.ModTime.Nanosecond(), h.Uid, h.Gid, h.Mode&07777, h.Size, h.Typeflag, h.Linkname, strings.Join(x, ","), n)
	}
}
"#;

const PYTHON_READER: &str = r#"
import sys, tarfile
t = tarfile.open(sys.argv[1], mode="r:")
for m in t:
    print("\t".join(map(str, [m.name, m.mtime, m.uid, m.gid, oct(m.mode & 0o7777)[2:], m.size, m.type.decode(), m.linkname])))
"#;

/// What a reader says of the entry: the line of the Go program.
fn go_line(e: &TocEntry) -> String {
    let (secs, nanos) = e
        .mod_time
        .as_deref()
        .map_or((0, 0), |t| velarx_storage::toc_time(Some(t)).unwrap());
    let typ = match e.entry_type {
        TocEntryType::Reg => '0',
        TocEntryType::Hardlink => '1',
        TocEntryType::Symlink => '2',
        TocEntryType::Char => '3',
        TocEntryType::Block => '4',
        TocEntryType::Dir => '5',
        _ => '6',
    };
    let mut x: Vec<String> = e
        .xattrs
        .iter()
        .map(|(k, v)| {
            let v = base64::engine::general_purpose::STANDARD.decode(v).unwrap();
            format!(
                "{k}={}",
                v.iter().map(|b| format!("{b:02x}")).collect::<String>()
            )
        })
        .collect();
    x.sort();
    format!(
        "{}\t{secs}.{nanos:09}\t{}\t{}\t{:o}\t{}\t{typ}\t{}\t{}\t{}",
        e.name,
        e.uid,
        e.gid,
        e.mode,
        e.size,
        e.link_name.as_deref().unwrap_or(""),
        x.join(","),
        e.size
    )
}

#[test]
fn the_canonical_tar_is_read_by_go_and_python() {
    let go = Command::new("go").arg("version").output().is_ok();
    let python = Command::new("python3").arg("--version").output().is_ok();
    if !go && !python {
        return eprintln!("skipped: no go and no python3");
    }
    let dir = tempfile::tempdir().unwrap();
    let mut reader = None;
    if go {
        let src = dir.path().join("reader.go");
        std::fs::write(&src, GO_READER).unwrap();
        let bin = dir.path().join("reader");
        let built = Command::new("go")
            .args(["build", "-o", bin.to_str().unwrap(), src.to_str().unwrap()])
            .env("GOCACHE", dir.path().join("cache"))
            .env("GO111MODULE", "off")
            .output()
            .unwrap();
        assert!(
            built.status.success(),
            "{}",
            String::from_utf8_lossy(&built.stderr)
        );
        reader = Some(bin);
    }
    let mut rng = StdRng::seed_from_u64(11);
    for round in 0..25 {
        let (entries, contents) = random_layer(&mut rng);
        let tar = generate(&entries, &contents);
        let path = dir.path().join("t.tar");
        std::fs::write(&path, &tar).unwrap();
        if let Some(bin) = &reader {
            let out = Command::new(bin).arg(&path).output().unwrap();
            assert!(
                out.status.success(),
                "round {round}: {}",
                String::from_utf8_lossy(&out.stderr)
            );
            let got = String::from_utf8(out.stdout).unwrap();
            let want: Vec<String> = entries.iter().map(go_line).collect();
            assert_eq!(
                got.lines().collect::<Vec<_>>(),
                want.iter().map(String::as_str).collect::<Vec<_>>(),
                "round {round}"
            );
        }
        if python {
            let out = Command::new("python3")
                .args(["-I", "-c", PYTHON_READER])
                .arg(&path)
                .output()
                .unwrap();
            assert!(
                out.status.success(),
                "round {round}: {}",
                String::from_utf8_lossy(&out.stderr)
            );
            let got = String::from_utf8(out.stdout).unwrap();
            assert_eq!(got.lines().count(), entries.len(), "round {round}");
            for (line, e) in got.lines().zip(&entries) {
                let f: Vec<&str> = line.split('\t').collect();
                let (secs, nanos) = e
                    .mod_time
                    .as_deref()
                    .map_or((0, 0), |t| velarx_storage::toc_time(Some(t)).unwrap());
                let want = secs as f64 + f64::from(nanos) / 1e9;
                let got: f64 = f[1].parse().unwrap();
                assert!((got - want).abs() < 1e-4, "{} {got} {want}", e.name);
                // (Python takes the `/` of a directory away)
                assert_eq!(f[0], e.name.trim_end_matches('/'));
                assert_eq!(
                    (f[2], f[3]),
                    (e.uid.to_string().as_str(), e.gid.to_string().as_str())
                );
                assert_eq!(f[4], format!("{:o}", e.mode));
                assert_eq!(f[5], e.size.to_string());
            }
        }
    }
}
