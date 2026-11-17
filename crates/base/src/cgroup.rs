// SPDX-License-Identifier: Apache-2.0
//! The cgroup v2 hierarchy as the engine reads it: where a process is, and
//! the controllers a cgroup gives to its children.  Velarx supports cgroup
//! v2 only: [`require_v2`] is what every process that touches cgroups asks
//! first.

use std::io;
use std::path::{Path, PathBuf};

/// Where the unified hierarchy is mounted.
pub const ROOT: &str = "/sys/fs/cgroup";

/// The file system type (`f_type` of statfs) of a cgroup v2 mount.
pub const CGROUP2_SUPER_MAGIC: u64 = 0x6367_7270;

/// Why [`ROOT`] is not a cgroup v2 mount, in one line for the user.
fn refusal(path: &Path, f_type: io::Result<u64>) -> Result<(), String> {
    match f_type {
        Ok(CGROUP2_SUPER_MAGIC) => Ok(()),
        Ok(t) => Err(format!(
            "velarx needs cgroup v2 and {} is not a cgroup2 mount (file system type {t:#x}; \
             cgroup v1 and the hybrid layout are not supported): boot with \
             systemd.unified_cgroup_hierarchy=1",
            path.display()
        )),
        Err(e) => Err(format!(
            "velarx needs cgroup v2 and cannot tell what {} is: {e}",
            path.display()
        )),
    }
}

/// Fails unless `path` is the mount of a cgroup v2 hierarchy.
pub fn require_v2_at(path: &Path) -> Result<(), String> {
    refusal(
        path,
        rustix::fs::statfs(path)
            .map(|s| s.f_type as u64)
            .map_err(io::Error::from),
    )
}

/// Fails, with a message that says why, unless the cgroup hierarchy of the
/// host is cgroup v2 (the unified one, at [`ROOT`]).  There is no fallback:
/// the processes that need cgroups (the engine service and the engine of a
/// command, the monitor) call this first and leave when it fails; commands
/// that need none (`--help`, `version`, a client of a remote engine) do not
/// call it.
pub fn require_v2() -> Result<(), String> {
    require_v2_at(Path::new(ROOT))
}

/// The controllers the cgroups of the containers and of the units around
/// them get from their parent (the list the OCI runtimes ask for).
pub const CONTROLLERS: [&str; 7] = ["cpu", "cpuset", "io", "memory", "pids", "hugetlb", "misc"];

/// The cgroup v2 path in the text of a `/proc/PID/cgroup` (the `0::` entry,
/// `/user.slice/...`).
pub fn path_in(text: &str) -> Option<&str> {
    text.lines()
        .find_map(|l| l.strip_prefix("0::"))
        .map(str::trim)
}

/// The cgroup v2 path of the process `pid`, or of this process.
pub fn of_process(pid: Option<i32>) -> io::Result<String> {
    let file = match pid {
        Some(pid) => format!("/proc/{pid}/cgroup"),
        None => "/proc/self/cgroup".to_string(),
    };
    let text = std::fs::read_to_string(&file)?;
    path_in(&text)
        .map(str::to_string)
        .ok_or_else(|| io::Error::other(format!("no cgroup v2 in {file}")))
}

/// The directory of the cgroup `rel` (`/a/b`, as [`of_process`] gives it).
pub fn dir(rel: &str) -> PathBuf {
    Path::new(ROOT).join(rel.trim_start_matches('/'))
}

/// Enable for the children of the cgroup `dir` the controllers of
/// [`CONTROLLERS`] that it has, one at a time (one that cannot be enabled
/// leaves the others).  What each write gave.  The controllers the cgroup
/// has, and those it has enabled already, are compared by name, one by one:
/// `cpuset` is not `cpu`.
pub fn enable_controllers(dir: &Path) -> io::Result<Vec<(&'static str, io::Result<()>)>> {
    let have = std::fs::read_to_string(dir.join("cgroup.controllers"))?;
    let have: Vec<&str> = have.split_whitespace().collect();
    let enabled = std::fs::read_to_string(dir.join("cgroup.subtree_control")).unwrap_or_default();
    let enabled: Vec<&str> = enabled.split_whitespace().collect();
    Ok(CONTROLLERS
        .iter()
        .filter(|c| have.contains(c) && !enabled.contains(c))
        .map(|c| {
            (
                *c,
                std::fs::write(dir.join("cgroup.subtree_control"), format!("+{c}")),
            )
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_cgroup2_magic_is_accepted() {
        let at = Path::new("/sys/fs/cgroup");
        refusal(at, Ok(CGROUP2_SUPER_MAGIC)).unwrap();
        // tmpfs (cgroup v1 and the hybrid layout have it at the top), and
        // the magic of cgroup v1 itself
        for magic in [0x0102_1994, 0x2735_4c53, 0] {
            let e = refusal(at, Ok(magic)).unwrap_err();
            assert!(e.contains("/sys/fs/cgroup is not a cgroup2 mount"), "{e}");
            assert!(e.contains("cgroup v1"), "{e}");
        }
        let e = refusal(at, Err(io::Error::from_raw_os_error(2))).unwrap_err();
        assert!(e.contains("cannot tell what /sys/fs/cgroup is"), "{e}");
    }

    #[test]
    fn a_directory_that_is_not_a_cgroup_mount_is_refused() {
        let d = tempfile::tempdir().unwrap();
        let e = require_v2_at(d.path()).unwrap_err();
        assert!(e.starts_with("velarx needs cgroup v2"), "{e}");
        let e = require_v2_at(&d.path().join("missing")).unwrap_err();
        assert!(e.contains("cannot tell"), "{e}");
    }

    #[test]
    fn the_unified_entry_is_found_among_the_hierarchies() {
        assert_eq!(
            path_in("12:cpu:/old\n0::/user.slice/x.service \n"),
            Some("/user.slice/x.service")
        );
        assert_eq!(path_in("1:name=systemd:/a\n"), None);
    }

    #[test]
    fn a_controller_is_not_taken_for_one_whose_name_contains_it() {
        let d = tempfile::tempdir().unwrap();
        std::fs::write(d.path().join("cgroup.controllers"), "cpuset memory\n").unwrap();
        std::fs::write(d.path().join("cgroup.subtree_control"), "").unwrap();
        let done = enable_controllers(d.path()).unwrap();
        let names: Vec<&str> = done.iter().map(|(c, _)| *c).collect();
        assert_eq!(names, ["cpuset", "memory"]);
        assert!(done.iter().all(|(_, r)| r.is_ok()));
    }

    #[test]
    fn a_controller_that_is_enabled_is_not_written_again() {
        let d = tempfile::tempdir().unwrap();
        std::fs::write(d.path().join("cgroup.controllers"), "cpuset cpu memory\n").unwrap();
        std::fs::write(d.path().join("cgroup.subtree_control"), "cpu memory\n").unwrap();
        let done = enable_controllers(d.path()).unwrap();
        let names: Vec<&str> = done.iter().map(|(c, _)| *c).collect();
        assert_eq!(names, ["cpuset"]);
    }
}
