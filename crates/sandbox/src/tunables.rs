// SPDX-License-Identifier: Apache-2.0
//! The kernel's global files, out of reach of a process that is root of the
//! initial user namespace.
//!
//! Landlock cannot say "only `/proc/self` of the writer", so the domain of
//! the fetcher's front process lets it write under `/proc` (its
//! workers write the maps of their own user namespace there).  For a
//! process whose euid is 0 in the initial user namespace the permission
//! bits of `/proc/sys/*` (`kernel.core_pattern` runs a helper as root
//! outside every domain), `/proc/sysrq-trigger` and the like need no
//! capability.  What `ProtectKernelTunables=` of a systemd unit does is
//! done here for the process that systemd did not start: a mount namespace
//! of its own, in which those files are read-only.  The files of
//! `/proc/self` stay as they are, and so do the namespaces the workers
//! make from this one.

use std::path::Path;

/// The files and directories of the kernel that are not per process and
/// that root may write with no capability (the permission bits): what
/// `ProtectKernelTunables=` makes read-only, and the control groups
/// (`ProtectControlGroups=`: nothing of the front writes there, a scope is
/// made by the manager over D-Bus).  `/sys` takes the file systems mounted
/// below it along.  Left out, as they have no write, a write there needs
/// a capability the front gives up, or it only resets statistics (and a
/// container masks some of them with a writable `/dev/null`, which would
/// make the front need `CAP_SYS_ADMIN` there): `/proc/kcore`, `/proc/kmsg`,
/// `/proc/timer_list`, `/proc/mtrr`, `/proc/latency_stats`.
pub const KERNEL_TUNABLES: &[&str] = &[
    "/proc/sys",
    "/proc/sysrq-trigger",
    "/proc/irq",
    "/proc/bus",
    "/proc/fs",
    "/proc/acpi",
    "/proc/scsi",
    "/proc/asound",
    "/sys",
];

/// Whether the process is root of the initial user namespace: the only
/// one that is global root for the files of the kernel.
pub fn is_global_root() -> Result<bool, velarx_base::ids::IdsError> {
    Ok(rustix::process::geteuid().is_root() && !velarx_base::ids::in_user_namespace()?)
}

fn os_error(what: &str, path: &str, e: impl std::fmt::Display) -> String {
    format!("{what} {path}: {e}")
}

fn c_path(path: &str) -> Result<std::ffi::CString, String> {
    std::ffi::CString::new(path).map_err(|e| format!("{path}: {e}"))
}

/// Whether the mount that holds `path` is read-only.
fn read_only(path: &str) -> Result<bool, String> {
    let st = rustix::fs::statvfs(path).map_err(|e| os_error("statvfs", path, e))?;
    Ok(st.f_flag.contains(rustix::fs::StatVfsMountFlags::RDONLY))
}

/// Make the mount tree at `path` read-only and private, in the mount
/// namespace of the process: bind it on itself with what is mounted below
/// (a bind mount that leaves the submounts out hides them, `binfmt_misc`
/// in `/proc/sys`) and set the flag on all of them.  Private: a file system
/// the host mounts below it later (`binfmt_misc` behind its automount) is
/// not propagated in, writable.
fn make_read_only(path: &str) -> Result<(), String> {
    let c = c_path(path)?;
    rustix::mount::mount_bind_recursive(path, path).map_err(|e| os_error("bind mount", path, e))?;
    // (Linux 5.12; Landlock, which the callers require, is 5.13)
    velarx_sys::mount::set_tree_read_only_private(&c)
        .map_err(|e| os_error("make read-only", path, e))?;
    if !read_only(path)? {
        return Err(format!("{path} is still writable"));
    }
    Ok(())
}

/// Make `paths` read-only in a mount namespace of this process (the paths
/// the system does not have are skipped, and so are those that already are
/// read-only: a systemd unit with `ProtectKernelTunables=`, a container
/// runtime's masks).  Returns the paths it made read-only.  Call it while
/// the process still has `CAP_SYS_ADMIN` and no thread but this one.
pub fn make_all_read_only(paths: &[&str]) -> Result<Vec<String>, String> {
    let mut todo = Vec::new();
    for path in paths {
        if !Path::new(path).exists() {
            continue;
        }
        if !read_only(path)? {
            todo.push(*path);
        }
    }
    if todo.is_empty() {
        return Ok(Vec::new());
    }
    let cannot = |what: &str, e: &dyn std::fmt::Display| {
        format!(
            "{what}: {} (a process that is root of the initial user namespace must not be able \
             to write the files of the kernel: it needs CAP_SYS_ADMIN to make them read-only \
             in a mount namespace of its own, or has to be started with them read-only, \
             ProtectKernelTunables=yes)",
            e
        )
    };
    velarx_sys::namespace::unshare(rustix::thread::UnshareFlags::NEWNS)
        .map_err(|e| cannot("unshare a mount namespace", &e))?;
    // (slave: the file systems the host unmounts are unmounted here, too;
    // the read-only trees are made private)
    rustix::mount::mount_change(
        "/",
        rustix::mount::MountPropagationFlags::DOWNSTREAM
            | rustix::mount::MountPropagationFlags::REC,
    )
    .map_err(|e| cannot("make the mounts slaves", &e))?;
    for path in &todo {
        make_read_only(path)?;
    }
    Ok(todo.into_iter().map(String::from).collect())
}

/// What a process that is root of the initial user namespace must not be
/// able to write: [`KERNEL_TUNABLES`] read-only in a mount namespace of
/// its own.  Any other process (a user's, or root of a user namespace of
/// its own, which is not root for these files) is left as it is.
pub fn protect_kernel_tunables() -> Result<Vec<String>, String> {
    if !is_global_root().map_err(|e| e.to_string())? {
        return Ok(Vec::new());
    }
    make_all_read_only(KERNEL_TUNABLES)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::OpenOptionsExt;

    fn errno_of_write(path: &str) -> Option<i32> {
        std::fs::OpenOptions::new()
            .write(true)
            .custom_flags(libc::O_NOCTTY)
            .open(path)
            .err()
            .and_then(|e| e.raw_os_error())
    }

    fn mount_namespace() -> std::path::PathBuf {
        std::fs::read_link("/proc/thread-self/ns/mnt").unwrap()
    }

    /// A process that is not global root is left alone: no mount
    /// namespace, nothing read-only.
    #[test]
    fn a_process_that_is_not_global_root_is_left_alone() {
        velarx_base::testing::in_child(|| {
            if is_global_root().unwrap() {
                return;
            }
            let before = mount_namespace();
            assert_eq!(protect_kernel_tunables().unwrap(), Vec::<String>::new());
            assert_eq!(mount_namespace(), before);
            assert!(!read_only("/proc/sys").unwrap());
        });
    }

    /// The files of the kernel are read-only after, in a mount namespace of
    /// the process; the maps of a user namespace made from it are written.
    /// Run as the global root, it is the real case (EROFS for the
    /// permission bits that allow the write); otherwise in the user and mount
    /// namespaces of the test, where the process has `CAP_SYS_ADMIN`.
    #[test]
    fn the_kernel_files_are_read_only_and_the_maps_of_a_worker_are_not() {
        velarx_base::testing::in_child(|| {
            let root = is_global_root().unwrap();
            if !root
                && velarx_sys::namespace::unshare_user_mapped_to_root(
                    rustix::thread::UnshareFlags::NEWNS,
                )
                .is_err()
            {
                eprintln!("no user namespace here: skipped");
                return;
            }
            let before = mount_namespace();
            let done = if root {
                protect_kernel_tunables()
            } else {
                make_all_read_only(KERNEL_TUNABLES)
            };
            let Ok(done) = done else {
                // (a locked /proc of a container, say: only the root case is a must)
                assert!(!root, "{done:?}");
                eprintln!("{done:?}: skipped");
                return;
            };
            assert_ne!(mount_namespace(), before, "{done:?}");
            assert!(done.contains(&"/proc/sys".to_string()), "{done:?}");
            for path in &done {
                assert!(read_only(path).unwrap(), "{path}");
            }
            let denied = errno_of_write("/proc/sys/kernel/printk_ratelimit");
            assert!(
                matches!(denied, Some(libc::EROFS | libc::EACCES)),
                "{denied:?}"
            );
            if root {
                assert_eq!(denied, Some(libc::EROFS));
                assert_eq!(
                    errno_of_write("/proc/sys/kernel/core_pattern"),
                    Some(libc::EROFS)
                );
                assert_eq!(errno_of_write("/proc/sysrq-trigger"), Some(libc::EROFS));
            }
            // a worker makes its namespaces and writes its maps
            let code = velarx_sys::process::fork_status(|| {
                use rustix::thread::UnshareFlags;
                let ok = velarx_sys::namespace::unshare_user_mapped_to_root(
                    UnshareFlags::NEWNS | UnshareFlags::NEWIPC,
                )
                .is_ok();
                i32::from(!ok)
            })
            .unwrap();
            assert_eq!(code, 0);
            // what is mounted below is still there
            assert!(std::fs::read_to_string("/proc/sys/kernel/cap_last_cap").is_ok());
        });
    }

    /// Nothing to do when the files are read-only already.
    #[test]
    fn read_only_already_or_missing_paths_are_skipped() {
        assert_eq!(
            make_all_read_only(&["/nonexistent/for/sure"]).unwrap(),
            Vec::<String>::new()
        );
    }
}
