// SPDX-License-Identifier: Apache-2.0
//! The mount table of a process (`/proc/PID/mountinfo`).

use std::path::{Path, PathBuf};

/// One mount of the table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mount {
    pub id: u32,
    /// The mount this one is mounted on: for a mount over another at the
    /// same place, that other one.
    pub parent: u32,
    /// The file system's device, `MAJOR:MINOR`: two mounts of one file
    /// system have the same.
    pub device: String,
    /// The directory of the file system that is the root of this mount.
    pub root: PathBuf,
    pub point: PathBuf,
    pub fs_type: String,
    /// The options of the file system (`upperdir=...` of an overlay).
    pub super_options: String,
}

/// `\040` is a space in the paths of `mountinfo`: undo the octal escapes.
pub fn unescape(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\\'
            && i + 3 < b.len()
            && b[i + 1..i + 4].iter().all(|c| (b'0'..=b'7').contains(c))
        {
            let v = (b[i + 1] - b'0') as u32 * 64
                + (b[i + 2] - b'0') as u32 * 8
                + (b[i + 3] - b'0') as u32;
            out.push(v as u8);
            i += 4;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// The mounts of the table `text`, in its order.  A line that is not one of
/// the kernel's is skipped.
pub fn parse(text: &str) -> Vec<Mount> {
    text.lines().filter_map(parse_line).collect()
}

fn parse_line(line: &str) -> Option<Mount> {
    let (pre, post) = line.split_once(" - ")?;
    let mut f = pre.split(' ');
    let id = f.next()?.parse().ok()?;
    let parent = f.next()?.parse().ok()?;
    let device = f.next()?.to_string();
    let root = PathBuf::from(unescape(f.next()?));
    let point = PathBuf::from(unescape(f.next()?));
    let mut p = post.split(' ');
    let fs_type = p.next()?.to_string();
    let _source = p.next()?;
    let super_options = p.next().unwrap_or_default().to_string();
    Some(Mount {
        id,
        parent,
        device,
        root,
        point,
        fs_type,
        super_options,
    })
}

/// Whether `path` is a mount point in the table `text`.
pub fn is_mount_point(text: &str, path: &Path) -> bool {
    parse(text).iter().any(|m| m.point == path)
}

/// The mounts at `dir` or below it, the ones that must go first first: a
/// mount is listed after every mount on it, those over it at the same place
/// included, so that one `umount` of each in this order takes the table
/// apart.
pub fn at_or_below(text: &str, dir: &Path) -> Vec<Mount> {
    let all = parse(text);
    let depth = |m: &Mount| {
        let mut d = 0usize;
        let mut cur = m.parent;
        // (a table is a tree; the bound is only against a damaged one)
        while let Some(p) = all.iter().find(|p| p.id == cur) {
            d += 1;
            if d > all.len() {
                break;
            }
            cur = p.parent;
        }
        d
    };
    let mut found: Vec<(usize, Mount)> = all
        .iter()
        .filter(|m| m.point.starts_with(dir))
        .map(|m| (depth(m), m.clone()))
        .collect();
    found.sort_by_key(|a| std::cmp::Reverse(a.0));
    found.into_iter().map(|(_, m)| m).collect()
}

/// How many mounts the table `text` has at exactly `path`.
pub fn stacked_at(text: &str, path: &Path) -> usize {
    parse(text).iter().filter(|m| m.point == path).count()
}

/// Detach every mount stacked on `path` of this process's mount namespace
/// (none is fine): as many unmounts as the table has mounts there, the
/// topmost first.  How many were detached.
pub fn detach_stacked(path: &Path) -> std::io::Result<usize> {
    use rustix::io::Errno;
    use rustix::mount::{unmount, UnmountFlags};
    let path = match std::fs::canonicalize(path) {
        Ok(p) => p,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(e) => return Err(e),
    };
    let stacked = stacked_at(&std::fs::read_to_string("/proc/self/mountinfo")?, &path);
    for done in 0..stacked {
        match unmount(&path, UnmountFlags::DETACH) {
            Ok(()) => {}
            // (gone with another process's unmount meanwhile)
            Err(Errno::INVAL) | Err(Errno::NOENT) => return Ok(done),
            Err(e) => return Err(e.into()),
        }
    }
    Ok(stacked)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TABLE: &str = "\
20 1 0:5 / /b rw - tmpfs t rw
21 20 0:6 / /b/x\\040y rw - tmpfs t rw
22 21 0:7 / /b/x\\040y rw - overlay o rw,upperdir=/u
23 22 0:8 /sub /b/x\\040y/c rw - tmpfs t rw
30 1 0:9 / /other rw - tmpfs t rw
";

    #[test]
    fn the_escapes_of_a_path_are_undone() {
        // the kernel escapes a space, a tab, a newline and a backslash
        assert_eq!(unescape("/a\\040b\\011c\\012d\\134e"), "/a b\tc\nd\\e");
        // what is not three octal digits stays as it is
        assert_eq!(unescape("/x\\"), "/x\\");
        assert_eq!(unescape("/x\\04"), "/x\\04");
        assert_eq!(unescape("/x\\0a9"), "/x\\0a9");
        assert_eq!(unescape("/end\\040"), "/end ");
        let m = parse(TABLE);
        assert_eq!(m[1].point, Path::new("/b/x y"));
        assert_eq!(m[2].super_options, "rw,upperdir=/u");
        assert_eq!(m[3].root, Path::new("/sub"));
    }

    #[test]
    fn mounts_at_one_place_are_counted() {
        assert_eq!(stacked_at(TABLE, Path::new("/b/x y")), 2);
        assert_eq!(stacked_at(TABLE, Path::new("/b")), 1);
        assert_eq!(stacked_at(TABLE, Path::new("/b/x")), 0);
    }

    /// The mounts over another at the same place go before it, and the
    /// children before their parent, each listed once.
    #[test]
    fn stacked_mounts_go_top_first() {
        let ids: Vec<u32> = at_or_below(TABLE, Path::new("/b"))
            .iter()
            .map(|m| m.id)
            .collect();
        assert_eq!(ids, [23, 22, 21, 20]);
        assert!(is_mount_point(TABLE, Path::new("/other")));
        assert!(!is_mount_point(TABLE, Path::new("/oth")));
        // a name that only starts like the directory is not below it
        assert!(at_or_below(TABLE, Path::new("/o")).is_empty());
    }
}
