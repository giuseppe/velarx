// SPDX-License-Identifier: Apache-2.0
//! Running the daemon rootless.
//!
//! An unprivileged daemon cannot mount file systems, which the containers it
//! creates need.  Like `podman` does for its commands, it runs inside a user
//! namespace where it is root, with its own mount namespace: root maps to the
//! user, and the ids `1..` map to the subordinate ids of `/etc/subuid` and
//! `/etc/subgid` (set up by `newuidmap` and `newgidmap`; without them, only
//! the user's own id is mapped).  The mounts of the daemon live in that mount
//! namespace and go away with it.  `tree` joins or makes them.

use std::io;
use std::os::fd::AsFd;
use std::path::Path;
use std::process::{Command, Stdio};
use tracing::debug;

/// Set in the environment of the daemon that runs in the namespace.
pub const ENV_MARKER: &str = "VELARX_ROOTLESS";

/// This process joined the namespaces of the store.  The environment of a
/// running process is not changed for it: the processes it starts get
/// [`ENV_MARKER`] with [`marker_env`] (and those they start inherit it).
static JOINED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Remember that this process is in the namespaces of the store.
pub(super) fn set_joined() {
    JOINED.store(true, std::sync::atomic::Ordering::Relaxed);
}

/// The process was started in the namespaces of the store by one that
/// joined them, or joined them itself.
pub fn marked() -> bool {
    JOINED.load(std::sync::atomic::Ordering::Relaxed) || std::env::var_os(ENV_MARKER).is_some()
}

/// The variable that tells a process `cmd` starts that it is in the
/// namespaces of the store, if this one is.
pub fn marker_env() -> Vec<(std::ffi::OsString, std::ffi::OsString)> {
    marker_for(JOINED.load(std::sync::atomic::Ordering::Relaxed))
}

fn marker_for(joined: bool) -> Vec<(std::ffi::OsString, std::ffi::OsString)> {
    if joined {
        vec![(ENV_MARKER.into(), "1".into())]
    } else {
        Vec::new()
    }
}

pub use velarx_base::ids::{host_uid, in_user_namespace};

/// Where the root file system of a container with a user namespace that
/// does not map the daemon is reached when the ids of the container cannot
/// traverse the directories of its bundle (a run directory in
/// $XDG_RUNTIME_DIR is 0700): the monitor binds the root file system, in a
/// mount namespace nobody else sees, below a directory of /tmp that anyone
/// may traverse.  `None` when the bundle can be used.
pub fn public_rootfs(
    bundle: &std::path::Path,
    id: &str,
    uid_mappings: &[crate::container::IdMapping],
) -> Result<Option<std::path::PathBuf>, velarx_base::ids::IdsError> {
    if uid_mappings.is_empty() {
        return Ok(None);
    }
    let euid = rustix::process::geteuid().as_raw();
    let mapped = uid_mappings
        .iter()
        .any(|m| euid.checked_sub(m.host_id).is_some_and(|off| off < m.size));
    if mapped || traversable_by_others(bundle) {
        return Ok(None);
    }
    Ok(Some(public_rootfs_base()?.join(id)))
}

/// Whether anyone may traverse `dir` and every directory above it.
fn traversable_by_others(dir: &std::path::Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    dir.ancestors()
        .all(|d| std::fs::metadata(d).is_ok_and(|m| m.permissions().mode() & 0o001 != 0))
}

/// `/tmp/velarx-rootfs-UID`, made 0711 and the user's; root's is
/// `/run/velarx-rootfs-0`, where no other user can make a directory.
pub fn public_rootfs_base() -> Result<std::path::PathBuf, velarx_base::ids::IdsError> {
    let uid = host_uid()?;
    let parent = if uid == 0 { "/run" } else { "/tmp" };
    Ok(std::path::PathBuf::from(format!(
        "{parent}/velarx-rootfs-{uid}"
    )))
}

/// Whether `base` is a directory (not a link) of the user `uid`, as the
/// base of the public roots is when this user made it; if not, an error
/// that names it.
pub fn check_public_base(base: &std::path::Path, uid: u32) -> io::Result<()> {
    use std::os::unix::fs::MetadataExt;
    let st = std::fs::symlink_metadata(base)
        .map_err(|e| io::Error::new(e.kind(), format!("`{}`: {e}", base.display())))?;
    if !st.is_dir() || st.uid() != uid {
        return Err(io::Error::other(format!(
            "`{}` is not a directory of user {uid}",
            base.display()
        )));
    }
    Ok(())
}

/// Where the public root of the container `id` is, if the base of the
/// public roots is the user's: a directory of another user is none of
/// this engine's to look into or remove from.
pub fn own_public_rootfs(id: &str) -> Option<std::path::PathBuf> {
    let base = public_rootfs_base().ok()?;
    check_public_base(&base, rustix::process::geteuid().as_raw()).ok()?;
    Some(base.join(id))
}

pub fn user_name(uid: u32) -> Option<String> {
    velarx_sys::ffi::user_name(uid)
}

/// The arguments of `newuidmap` or `newgidmap` for the process `pid`: the
/// id `id` of the user as 0, the subordinate `ranges` after it, from 1 on.
fn map_args(pid: u32, id: u32, ranges: &[(u32, u32)]) -> Vec<String> {
    let mut args = vec![pid.to_string(), "0".into(), id.to_string(), "1".into()];
    let mut next = 1u32;
    for (start, count) in ranges {
        args.extend([next.to_string(), start.to_string(), count.to_string()]);
        next = next.saturating_add(*count);
    }
    args
}

/// Run `tool` with `args`, started: the wait for it is [`finish`].
fn start(tool: &str, args: &[String]) -> io::Result<std::process::Child> {
    Command::new(tool)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| io::Error::new(e.kind(), format!("cannot run {tool}: {e}")))
}

/// Wait for `child`, the helper `tool`: an error with what it said if it
/// failed.
fn finish(tool: &str, child: std::process::Child) -> io::Result<()> {
    let out = child.wait_with_output()?;
    if out.status.success() {
        return Ok(());
    }
    Err(io::Error::other(format!(
        "{tool} failed ({}): {}",
        out.status,
        String::from_utf8_lossy(&out.stderr).trim()
    )))
}

/// Set the maps of the namespace of `pid`: with subordinate ids in
/// `/etc/subuid` and `/etc/subgid` for the user (by its name or its numeric
/// id, as `newuidmap` and `newgidmap` look them up; for both files, the
/// user's, not the group's), those and the user's own id through the
/// helpers, which must succeed; without, only the user's own id.
pub(super) fn write_maps(pid: u32) -> io::Result<()> {
    let uid = rustix::process::getuid().as_raw();
    let gid = rustix::process::getgid().as_raw();
    let name = user_name(uid);
    let ranges = |file: &str| -> io::Result<Vec<(u32, u32)>> {
        match std::fs::read_to_string(file) {
            Ok(c) => Ok(velarx_base::idmap::subid_ranges(
                &c,
                name.as_deref(),
                Some(uid),
            )),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Vec::new()),
            Err(e) => Err(io::Error::new(e.kind(), format!("{file}: {e}"))),
        }
    };
    let (subuid, subgid) = (ranges("/etc/subuid")?, ranges("/etc/subgid")?);

    if !subuid.is_empty() && !subgid.is_empty() {
        // (both at once: each is an exec of a setuid program)
        let uid_map = start("newuidmap", &map_args(pid, uid, &subuid));
        let gid_map = start("newgidmap", &map_args(pid, gid, &subgid));
        let uid_done = uid_map.and_then(|c| finish("newuidmap", c));
        let gid_done = gid_map.and_then(|c| finish("newgidmap", c));
        return uid_done.and(gid_done);
    }
    debug!("No subordinate ids for the user: mapping only its own id");
    std::fs::write(format!("/proc/{pid}/uid_map"), format!("0 {uid} 1\n"))?;
    std::fs::write(format!("/proc/{pid}/setgroups"), "deny\n")?;
    std::fs::write(format!("/proc/{pid}/gid_map"), format!("0 {gid} 1\n"))?;
    Ok(())
}

/// Put the process in the namespaces of the rootless user of the store that
/// the configuration file `config` describes, if it is not root and not in
/// them already; `role` says what the process is, and `register` that it
/// is recorded as a holder of them from its join on (it starts processes
/// that outlive it): else it writes nothing when the namespaces exist.
/// Before any thread.
/// Either way the processes it starts can be recorded as members
/// (`tree::register_holder`).
pub fn join(config: &Path, role: &str, register: bool) -> io::Result<()> {
    // A process started in the namespaces (a command run by `velarx
    // unshare`) is root there: it is in them, and
    // what it starts (a restarted container's monitor) must be recorded
    // like what any other process of them starts.
    let inside = marked() && in_user_namespace().map_err(io::Error::other)?;
    if rustix::process::geteuid().is_root() && !inside {
        return Ok(());
    }
    let config = velarx_config::Config::load_or_default(config).map_err(io::Error::other)?;
    let db = config.storage.database_path();
    if inside {
        velarx_nsid::tree::remember(db)?;
    } else {
        // (its close costs no sync once the engine's connection is open)
        velarx_db::volatile::keep(&db, super::tree::enter(&db, role, register)?);
    }
    velarx_base::trace::point("userns joined");
    Ok(())
}

/// `velarx unshare`: run `argv` (a program found in PATH) in the user and
/// mount namespaces of the rootless user,
/// made if no process lives in them; with `netns_run`, in the
/// rootless network namespace of the networks in that directory too
/// (`--rootless-netns`; looked for once in the mount namespace, where the
/// pin of the namespace is).  `env` is added
/// to the environment.  The command replaces this process: it returns only
/// with the error.  Must be called before any thread is started.
pub fn unshare(
    db: &Path,
    argv: &[std::ffi::OsString],
    env: &[(String, std::ffi::OsString)],
    netns_run: Option<&Path>,
) -> io::Error {
    use std::os::unix::process::CommandExt;
    if rustix::process::geteuid().is_root() {
        return io::Error::other(
            "velarx unshare is for rootless users: root runs in the namespaces of the host",
        );
    }
    let Some((program, args)) = argv.split_first() else {
        return io::Error::other("no command");
    };
    // (the program it runs may live on, a shell that starts containers: it
    // is a holder)
    if let Err(e) = super::tree::enter(db, "unshare", true) {
        return io::Error::other(format!("velarx unshare: {e}"));
    }
    if let Some(run) = netns_run {
        let path = match velarx_netkernel::rootless_netns::path_in(run, db, velarx_nsid::tree::members) {
            Ok(Some(path)) => path,
            Ok(None) => {
                return io::Error::other(
                    "velarx unshare: no rootless network namespace (no container uses a bridge network)",
                )
            }
            Err(e) => return io::Error::other(format!("velarx unshare: {e}")),
        };
        let joined = std::fs::File::open(&path).and_then(|ns| {
            rustix::thread::move_into_link_name_space(
                ns.as_fd(),
                Some(rustix::thread::LinkNameSpaceType::Network),
            )
            .map_err(io::Error::from)
        });
        if let Err(e) = joined {
            return io::Error::other(format!(
                "velarx unshare: the rootless network namespace {}: {e}",
                path.display()
            ));
        }
    }
    let mut command = Command::new(program);
    command
        .args(args)
        .envs(env.iter().map(|(k, v)| (k, v)))
        .envs(marker_env());
    let e = command.exec();
    io::Error::new(
        e.kind(),
        format!(
            "velarx unshare: cannot run {}: {e}",
            program.to_string_lossy()
        ),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_public_root_only_when_the_bundle_is_out_of_reach() {
        use std::os::unix::fs::PermissionsExt;
        let d = tempfile::tempdir().unwrap();
        let bundle = d.path().join("run/bundles/c");
        std::fs::create_dir_all(&bundle).unwrap();
        for p in [
            d.path(),
            &d.path().join("run"),
            &d.path().join("run/bundles"),
            &bundle,
        ] {
            std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let maps = |host: u32| {
            vec![crate::container::IdMapping {
                container_id: 0,
                host_id: host,
                size: 65536,
            }]
        };
        let euid = rustix::process::geteuid().as_raw();
        let other = euid.wrapping_add(100_000);
        assert_eq!(public_rootfs(&bundle, "c", &[]).unwrap(), None);
        // (a TMPDIR below a directory others may not traverse, a private one
        // or one in a home, puts every bundle of the test out of reach)
        if traversable_by_others(d.path()) {
            assert_eq!(public_rootfs(&bundle, "c", &maps(other)).unwrap(), None);
        } else {
            eprintln!("TMPDIR is out of reach of others: a reachable bundle is not tested");
        }
        std::fs::set_permissions(d.path().join("run"), std::fs::Permissions::from_mode(0o700))
            .unwrap();
        assert_eq!(
            public_rootfs(&bundle, "c", &maps(other)).unwrap(),
            Some(public_rootfs_base().unwrap().join("c"))
        );
        // a namespace that maps the daemon reaches its directories
        assert_eq!(public_rootfs(&bundle, "c", &maps(euid)).unwrap(), None);
        // (root's is under /run, where nobody else can make a directory)
        let base = public_rootfs_base().unwrap();
        let parent = if euid == 0 { "/run" } else { "/tmp" };
        assert_eq!(
            base.to_string_lossy(),
            format!("{parent}/velarx-rootfs-{}", host_uid().unwrap())
        );
    }

    #[test]
    fn the_base_of_the_public_roots_must_be_the_users_directory() {
        let d = tempfile::tempdir().unwrap();
        let uid = rustix::process::geteuid().as_raw();
        let base = d.path().join("base");
        std::fs::create_dir(&base).unwrap();
        check_public_base(&base, uid).unwrap();
        // another user's is refused, and named
        let e = check_public_base(&base, uid + 1).unwrap_err().to_string();
        assert_eq!(
            e,
            format!(
                "`{}` is not a directory of user {}",
                base.display(),
                uid + 1
            )
        );
        // a link to one of the user's is not one
        let link = d.path().join("link");
        std::os::unix::fs::symlink(&base, &link).unwrap();
        assert!(check_public_base(&link, uid).is_err());
        assert!(check_public_base(&d.path().join("none"), uid).is_err());
    }

    #[test]
    fn the_helpers_map_the_user_and_then_every_range() {
        assert_eq!(
            map_args(42, 1000, &[(100000, 65536), (300000, 10)]),
            ["42", "0", "1000", "1", "1", "100000", "65536", "65537", "300000", "10"]
        );
        assert_eq!(map_args(42, 7, &[]), ["42", "0", "7", "1"]);
    }

    #[test]
    fn test_initial_namespace_is_detected() {
        // The tests run as an ordinary user or root in the initial namespace
        // (or in a container: then the answer is whatever the map says).
        let map = std::fs::read_to_string("/proc/self/uid_map").unwrap();
        let initial = map.split_whitespace().collect::<Vec<_>>() == ["0", "0", "4294967295"];
        assert_eq!(in_user_namespace().unwrap(), !initial);
    }

    #[test]
    fn the_marker_is_passed_in_the_environment_of_the_child() {
        let mut cmd = Command::new("true");
        cmd.envs(marker_for(true));
        assert!(cmd
            .get_envs()
            .any(|(k, v)| k == ENV_MARKER && v.is_some_and(|v| v == "1")));
        let mut cmd = Command::new("true");
        cmd.envs(marker_for(false));
        assert_eq!(cmd.get_envs().count(), 0);
    }
}
