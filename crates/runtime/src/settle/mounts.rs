// SPDX-License-Identifier: Apache-2.0
//! The mounts a container leaves behind, which only a process of the
//! namespace they were made in can unmount.

use std::fs;
use std::path::{Path, PathBuf};
use velarx_sys::statmount::{self, Mount};

/// The points of the mounts at `dir` or below it, the ones that must go
/// first first: a
/// mount is listed after every mount on it, those over it at the same place
/// included, so that one `umount` of each in this order takes the table
/// apart.
fn at_or_below(dir: &Path) -> std::io::Result<Vec<PathBuf>> {
    let all = statmount::table()?;
    let depth = |m: &Mount| {
        let mut d = 0usize;
        let mut cur = m.parent;
        // (the root mount is its own parent)
        while let Some(p) = all.iter().find(|p| p.id == cur && p.parent != p.id) {
            d += 1;
            cur = p.parent;
        }
        d
    };
    // (the table has the mounts that have a point)
    let mut found: Vec<(usize, PathBuf)> = all
        .iter()
        .filter_map(|m| {
            let point = m.point.as_ref()?;
            point.starts_with(dir).then(|| (depth(m), point.clone()))
        })
        .collect();
    found.sort_by_key(|a| std::cmp::Reverse(a.0));
    Ok(found.into_iter().map(|(_, m)| m).collect())
}

/// Detach every mount at `dir` or below it (what a monitor that was killed
/// left: the root file system and what is mounted on it, an image of a
/// container), so that the directory can be removed.  Whether nothing is
/// mounted there any more.
///
/// Each pass unmounts once each mount the table has there, the ones on top
/// first.  A mount that another hides (mounted later over a directory above
/// it) is reached only once that one is gone: the next pass takes it.  A
/// pass that takes none away ends it (what is left cannot be unmounted).
pub fn detach_mounts_below(dir: &Path) -> bool {
    use rustix::mount::{unmount, UnmountFlags};
    let mut before = usize::MAX;
    loop {
        let Ok(mounts) = at_or_below(dir) else {
            return false;
        };
        if mounts.is_empty() {
            return true;
        }
        if mounts.len() >= before {
            return false;
        }
        before = mounts.len();
        for point in mounts {
            // (one that is busy goes when its last user does; one that is
            // hidden, or went with another, fails here; a link at the end
            // of a point is not followed, as `is_mount_point` does not)
            if unmount(&point, UnmountFlags::NOFOLLOW).is_err() {
                let _ = unmount(&point, UnmountFlags::DETACH | UnmountFlags::NOFOLLOW);
            }
        }
    }
}

/// Release the `/dev/shm` of a container that exited: the mount of its IPC
/// namespace's tmpfs and, with the directory, the mount of the namespace
/// where it was made (a monitor runs in a mount namespace of its own: an
/// unmount there does not reach the engine's).  The containers that joined
/// it keep theirs.
pub fn release_shm_dir(dir: &Path) {
    if detach_mounts_below(dir) {
        // (a mount point of other namespaces only is removed, and its mounts
        // are detached there)
        let _ = fs::remove_dir(dir);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn is_mount_point(path: &Path) -> bool {
        match statmount::is_mount_point(path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
            r => r.unwrap(),
        }
    }

    /// What a monitor that was killed can leave: mounts stacked at one
    /// place, and one below them hidden by a mount made later over the
    /// directory above it.  They all go, and what is next to the directory
    /// stays.
    #[test]
    fn stacked_and_hidden_mounts_are_all_detached() {
        velarx_base::testing::in_child(|| {
            use rustix::mount::{mount, mount_change, MountFlags, MountPropagationFlags};
            // (without user namespaces there is nothing this process may mount)
            if velarx_sys::namespace::unshare_user_mapped_to_root(
                rustix::thread::UnshareFlags::NEWNS,
            )
            .is_err()
            {
                return;
            }
            mount_change(
                "/",
                MountPropagationFlags::REC | MountPropagationFlags::PRIVATE,
            )
            .unwrap();
            let d = tempfile::tempdir().unwrap();
            let (b, keep) = (d.path().join("b"), d.path().join("keep"));
            let (x, hidden) = (b.join("x"), b.join("x/c"));
            fs::create_dir_all(&x).unwrap();
            fs::create_dir(&keep).unwrap();
            let tmpfs = |at: &Path| mount("tmpfs", at, "tmpfs", MountFlags::empty(), None).unwrap();
            tmpfs(&keep);
            tmpfs(&x);
            fs::create_dir(&hidden).unwrap();
            tmpfs(&hidden);
            tmpfs(&x);
            tmpfs(&x);
            assert!(detach_mounts_below(&b));
            assert!(!is_mount_point(&x));
            assert!(!is_mount_point(&hidden));
            assert!(is_mount_point(&keep));
            // (nothing left: nothing to do)
            assert!(detach_mounts_below(&b));
        });
    }

    /// A directory with the bytes the mount table writes as escapes (space,
    /// tab, newline, backslash) or that are not UTF-8, mounts below it, and
    /// a directory with the same start next to it: what is below goes, the
    /// other stays.
    #[test]
    fn mounts_of_odd_names_are_detached() {
        velarx_base::testing::in_child(|| {
            use rustix::mount::{mount, MountFlags};
            use std::os::unix::ffi::OsStrExt;
            if !velarx_base::testing::private_namespace() {
                return;
            }
            let d = tempfile::tempdir().unwrap();
            let tmpfs = |at: &Path| mount("t", at, "tmpfs", MountFlags::empty(), None).unwrap();
            for name in [&b"a b"[..], b"a\tb\n\\c", b"x\xffy"] {
                let dir = d.path().join(std::ffi::OsStr::from_bytes(name));
                let beside = d
                    .path()
                    .join(std::ffi::OsStr::from_bytes(&[name, b"2"].concat()));
                let x = dir.join("x y");
                let y = x.join(std::ffi::OsStr::from_bytes(&[name, b"z"].concat()));
                fs::create_dir_all(&x).unwrap();
                fs::create_dir(&beside).unwrap();
                tmpfs(&x);
                tmpfs(&x);
                fs::create_dir(&y).unwrap();
                tmpfs(&y);
                tmpfs(&beside);
                assert!(detach_mounts_below(&dir), "{dir:?}");
                assert!(!is_mount_point(&x), "{x:?}");
                assert!(!is_mount_point(&y), "{y:?}");
                assert!(is_mount_point(&beside), "{beside:?}");
            }
        });
    }
}
