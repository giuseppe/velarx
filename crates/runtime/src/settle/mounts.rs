// SPDX-License-Identifier: Apache-2.0
//! The mounts a container leaves behind, which only a process of the
//! namespace they were made in can unmount.

use std::fs;
use std::path::Path;

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
        let Ok(info) = fs::read_to_string("/proc/self/mountinfo") else {
            return false;
        };
        let mounts = velarx_base::mountinfo::at_or_below(&info, dir);
        if mounts.is_empty() {
            return true;
        }
        if mounts.len() >= before {
            return false;
        }
        before = mounts.len();
        for m in mounts {
            // (one that is busy goes when its last user does; one that is
            // hidden, or went with another, fails here)
            if unmount(&m.point, UnmountFlags::empty()).is_err() {
                let _ = unmount(&m.point, UnmountFlags::DETACH);
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
        let info = fs::read_to_string("/proc/self/mountinfo").unwrap();
        velarx_base::mountinfo::at_or_below(&info, path)
            .iter()
            .any(|m| m.point == path)
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
}
