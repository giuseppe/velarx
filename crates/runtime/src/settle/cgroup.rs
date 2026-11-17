// SPDX-License-Identifier: Apache-2.0
//! The cgroups of a container the monitor ends with: the monitor is the last
//! process in them, so it leaves them for `<parent>/exiting` and removes
//! them, with no engine alive.

use serde::{Deserialize, Serialize};
use std::io;
use std::path::{Path, PathBuf};

/// The directory the monitor leaves its cgroup for, below the cgroup that
/// holds the containers and the pods.
pub const EXITING: &str = "exiting";

/// The runtime's and the container's cgroups, below a container's.
const LEAVES: [&str; 2] = ["container", "runtime"];

/// The cgroups of a container, as paths of the cgroup file system.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CgroupPlan {
    /// The cgroup that holds the containers and the pods
    pub parent: PathBuf,
    /// The container's own
    pub dir: PathBuf,
    /// The cgroup of its pod, which goes with the last container in it
    pub pod_dir: Option<PathBuf>,
}

/// Remove the empty cgroups of a container, and its pod's if it was the last
/// one in it: what is not empty stays.
pub fn remove_dirs(dir: &Path, pod_dir: Option<&Path>) {
    for leaf in LEAVES {
        let _ = std::fs::remove_dir(dir.join(leaf));
    }
    let _ = std::fs::remove_dir(dir);
    if let Some(pod) = pod_dir {
        let _ = std::fs::remove_dir(pod);
    }
}

/// The monitor is at its end: leave the cgroups and remove them, unless a
/// start holds the lock of the container (it reuses them).  The last call of
/// the monitor, from its main thread.
pub fn leave_and_remove(plan: &CgroupPlan, start_lock: &Path) -> io::Result<()> {
    // (a lock file that is gone: the container was removed, none starts)
    let _lock = match std::fs::OpenOptions::new().write(true).open(start_lock) {
        Ok(file) => {
            match velarx_sys::flock::flock_retrying(
                &file,
                rustix::fs::FlockOperation::NonBlockingLockExclusive,
            ) {
                Ok(()) => Some(file),
                Err(e) if e.raw_os_error() == Some(libc::EWOULDBLOCK) => return Ok(()),
                Err(e) => return Err(e),
            }
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => None,
        Err(e) => return Err(e),
    };
    let exiting = plan.parent.join(EXITING);
    let pid = std::process::id().to_string();
    let mut tries = 0;
    loop {
        match std::fs::create_dir(&exiting) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e),
        }
        match std::fs::write(exiting.join("cgroup.procs"), &pid) {
            Ok(()) => break,
            // (a sweep removed it in between)
            Err(e) if e.kind() == io::ErrorKind::NotFound && tries == 0 => tries += 1,
            Err(e) => return Err(e),
        }
    }
    remove_dirs(&plan.dir, plan.pod_dir.as_deref());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A start that holds the lock of the container reuses the cgroups: the
    /// monitor that ends leaves them (the end of an old monitor after a
    /// restart does not take the new run's cgroups).
    #[test]
    fn a_start_in_progress_keeps_the_cgroups() {
        let d = tempfile::tempdir().unwrap();
        let dir = d.path().join("ctr");
        std::fs::create_dir_all(dir.join("runtime")).unwrap();
        let lock = d.path().join("ctr.lock");
        let held = super::super::lock::exclusive(&lock).unwrap();
        let plan = CgroupPlan {
            parent: d.path().to_path_buf(),
            dir: dir.clone(),
            pod_dir: None,
        };
        leave_and_remove(&plan, &lock).unwrap();
        assert!(dir.join("runtime").exists());
        drop(held);
    }

    #[test]
    fn the_empty_cgroups_of_a_container_and_its_pod_go() {
        let d = tempfile::tempdir().unwrap();
        let pod = d.path().join("pod");
        let dir = pod.join("ctr");
        for leaf in LEAVES {
            std::fs::create_dir_all(dir.join(leaf)).unwrap();
        }
        remove_dirs(&dir, Some(&pod));
        assert!(!pod.exists());
        // what is not empty stays
        std::fs::create_dir_all(dir.join("runtime/inner")).unwrap();
        remove_dirs(&dir, Some(&pod));
        assert!(dir.join("runtime/inner").exists());
    }
}
