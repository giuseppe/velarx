// SPDX-License-Identifier: Apache-2.0
//! A cgroup of its own for the daemon, delegated to it, so that the
//! containers it starts get cgroups (limits, stats) even rootless.
//!
//! The daemon owns its cgroup when it is alone in it, can write it and
//! systemd delegated it to its unit (`Delegate=yes`: marked in the cgroup
//! for root, asked of the user's manager rootless); it keeps it.
//! Otherwise (a login session, a scope of a shell, a unit without
//! `Delegate=`) the cgroup is the manager's, not the daemon's, and the daemon
//! asks the manager for a new scope, `velarx-PID.scope` with `Delegate=yes`
//! (`StartTransientUnit`, in the slice it was in, so that the limits of that
//! slice still apply), and moves into it before any other process or thread
//! exists.  With `cgroup_manager = "cgroupfs"` and no manager it makes a new
//! cgroup next to its own instead, or goes on without cgroups for the
//! containers; with `cgroup_manager = "systemd"` there is no such fallback:
//! a cgroup it does not own and no manager that makes one is an error that
//! names the cause.  Either way the daemon then moves into `engine/` and
//! [`CgroupManager`] puts the containers next to it, `<id>/runtime` and
//! `<id>/container`, a pod a level above its members.
//!
//! [`CgroupManager`]: super::cgroup::CgroupManager

use std::io;
use std::path::Path;
use velarx_base::cgroup::dir as full;
use velarx_base::spawn::DAEMON_CGROUP;

fn writable(p: &Path) -> bool {
    rustix::fs::access(p, rustix::fs::Access::WRITE_OK).is_ok()
}

/// The pids of a cgroup.
fn procs(cg: &Path) -> Vec<u32> {
    std::fs::read_to_string(cg.join("cgroup.procs"))
        .unwrap_or_default()
        .lines()
        .filter_map(|l| l.trim().parse().ok())
        .collect()
}

/// systemd marked `cg` as delegated (`Delegate=yes`).
fn marked_delegated(cg: &Path) -> bool {
    ["trusted.delegate", "user.delegate"].iter().any(|name| {
        let mut buf = [0u8; 8];
        rustix::fs::getxattr(cg, *name, &mut buf[..]).is_ok_and(|n| buf[..n].starts_with(b"1"))
    })
}

/// The daemon can keep its cgroup `cg`: it is alone in it (a previous run
/// left it in `engine/` below it, which counts as its own), may write it
/// and systemd delegated it to its unit.  As root (which may write any
/// cgroup) the cgroup has the mark of it; rootless there is none to read
/// (the user's manager sets no `user.delegate` on a unit with
/// `Delegate=yes`, systemd 259) and every cgroup below `user@UID.service` is
/// writable by the user, so the manager is asked.
fn keepable(cg: &Path, pid: u32, socket: &Path) -> io::Result<bool> {
    let own = if cg.ends_with(DAEMON_CGROUP) {
        cg.parent().unwrap_or(cg)
    } else {
        cg
    };
    if !usable(cg, pid) {
        return Ok(false);
    }
    if rustix::process::geteuid().is_root() {
        Ok(marked_delegated(own))
    } else {
        user_unit_delegated(own, socket)
    }
}

/// The interface of the properties of the unit of the cgroup `cg` (its
/// name, `x.service` or `x.scope`), which has `Delegate`; none for a cgroup
/// that is not such a unit's.
fn unit_interface(cg: &Path) -> Option<(&str, &'static str)> {
    let name = cg.file_name()?.to_str()?;
    let interface = match name.rsplit_once('.')?.1 {
        "service" => "org.freedesktop.systemd1.Service",
        "scope" => "org.freedesktop.systemd1.Scope",
        _ => return None,
    };
    Some((name, interface))
}

/// The user's manager says the unit of the cgroup `cg` has `Delegate=yes`.
/// With no manager to ask (no socket, nobody listens) nobody else decides
/// about the cgroup: it is the daemon's.  A manager that does not have the
/// unit loaded did not delegate it; any other failure is the caller's to
/// report.  `socket`: the private socket of the manager.
fn user_unit_delegated(cg: &Path, socket: &Path) -> io::Result<bool> {
    let Some((unit, interface)) = unit_interface(cg) else {
        return Ok(false);
    };
    match velarx_wire::sdbus::unit_bool_at(socket, unit, interface, "Delegate") {
        Ok(delegated) => Ok(delegated),
        Err(e) if velarx_wire::sdbus::no_such_unit(&e) => Ok(false),
        Err(e)
            if matches!(
                e.kind(),
                io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused
            ) =>
        {
            tracing::debug!("No manager to ask whether {unit} is delegated: {e}");
            Ok(true)
        }
        Err(e) => Err(io::Error::new(
            e.kind(),
            format!("the manager does not say whether {unit} is delegated: {e}"),
        )),
    }
}

/// The daemon can use `cg`: it is alone in it (a previous run left it in
/// `engine/` below it, which counts as its own) and may write it.
fn usable(cg: &Path, pid: u32) -> bool {
    let own = if cg.ends_with(DAEMON_CGROUP) {
        cg.parent().unwrap_or(cg)
    } else {
        cg
    };
    let others = procs(own).into_iter().any(|p| p != pid)
        || (own != cg && procs(cg).into_iter().any(|p| p != pid));
    !others && writable(&own.join("cgroup.procs")) && writable(&own.join("cgroup.subtree_control"))
}

/// The slice that contains the cgroup `rel` (`app.slice`), if any; for a
/// user manager, a slice of its own (below `user@UID.service`).
fn slice_of(rel: &str, user: bool) -> Option<String> {
    let rel = match user {
        true => rel.split_once(".service/")?.1,
        false => rel,
    };
    rel.rsplit('/')
        .skip(1)
        .find(|c| c.ends_with(".slice"))
        .map(str::to_string)
}

/// The limits that apply to a cgroup: the lowest of it and its parents.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct Limits {
    memory: Option<u64>,
    swap: Option<u64>,
    pids: Option<u64>,
}

fn limit_file(cg: &Path, name: &str) -> Option<u64> {
    std::fs::read_to_string(cg.join(name))
        .ok()?
        .trim()
        .parse()
        .ok()
}

fn effective_limits(rel: &str) -> Limits {
    let mut l = Limits::default();
    let min = |a: Option<u64>, b: Option<u64>| match (a, b) {
        (Some(x), Some(y)) => Some(x.min(y)),
        (x, y) => x.or(y),
    };
    let mut cur = Some(Path::new(rel));
    while let Some(p) = cur.filter(|p| p.as_os_str() != "/" && !p.as_os_str().is_empty()) {
        let cg = full(&p.to_string_lossy());
        l.memory = min(l.memory, limit_file(&cg, "memory.max"));
        l.swap = min(l.swap, limit_file(&cg, "memory.swap.max"));
        l.pids = min(l.pids, limit_file(&cg, "pids.max"));
        cur = p.parent();
    }
    l
}

/// Whether the limits `now` are as strict as `before` (none was lifted).
fn kept(before: Limits, now: Limits) -> bool {
    let ok = |b: Option<u64>, n: Option<u64>| match (b, n) {
        (None, _) => true,
        (Some(b), Some(n)) => n <= b,
        (Some(_), None) => false,
    };
    ok(before.memory, now.memory) && ok(before.swap, now.swap) && ok(before.pids, now.pids)
}

/// Ask the manager for a scope with `Delegate=yes` around the daemon, with
/// the limits of the cgroup it leaves, on the manager's private `socket`.
fn systemd_scope(rel: &str, pid: u32, limits: Limits, socket: &Path) -> Result<String, String> {
    use velarx_wire::sdbus::Property;
    let unit = format!("velarx-{pid}.scope");
    let system = rustix::process::geteuid().is_root();
    let mut props = vec![
        Property::Str("Description", "velarx daemon".into()),
        Property::Bool("Delegate", true),
        Property::Str("CollectMode", "inactive-or-failed".into()),
        // a container or a pull worker the kernel kills for its memory
        // does not stop the daemon and the others
        Property::Str("OOMPolicy", "continue".into()),
        Property::Pids(vec![pid]),
    ];
    if let Some(slice) = slice_of(rel, !system) {
        props.push(Property::Str("Slice", slice));
    }
    for (name, v) in [
        ("MemoryMax", limits.memory),
        ("MemorySwapMax", limits.swap),
        ("TasksMax", limits.pids),
    ] {
        if let Some(v) = v {
            props.push(Property::U64(name, v));
        }
    }
    // (returns once the job is done: the daemon is in the scope then)
    velarx_wire::sdbus::start_unit_at(socket, &unit, &props, true)
        .map_err(|e| format!("systemd did not make the scope {unit}: {e}"))?;
    velarx_base::cgroup::of_process(None)
        .ok()
        .filter(|c| c.ends_with(&format!("/{unit}")))
        .ok_or_else(|| format!("the job of the scope {unit} ended without the daemon in it"))
}

/// Without systemd: a new cgroup next to the current one, with its limits.
fn sibling(rel: &str, pid: u32, limits: Limits) -> Result<String, String> {
    let parent = Path::new(rel).parent().ok_or("no parent cgroup")?;
    let name = format!("velarx-{pid}");
    let new_rel = parent.join(&name).to_string_lossy().into_owned();
    let dir = full(&new_rel);
    // A daemon that had this pid before left its cgroup (nothing removes it
    // once its daemon is gone): it goes, unless a process is still in it.
    match std::fs::create_dir(&dir) {
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
            remove_tree(&dir).and_then(|()| std::fs::create_dir(&dir))
        }
        r => r,
    }
    .map_err(|e| format!("create {}: {e}", dir.display()))?;
    let setup = || -> Result<(), String> {
        for (file, v) in [
            ("memory.max", limits.memory),
            ("memory.swap.max", limits.swap),
            ("pids.max", limits.pids),
        ] {
            if let Some(v) = v {
                std::fs::write(dir.join(file), v.to_string())
                    .map_err(|e| format!("set {file} of {}: {e}", dir.display()))?;
            }
        }
        std::fs::write(dir.join("cgroup.procs"), pid.to_string())
            .map_err(|e| format!("move to {}: {e}", dir.display()))
    };
    if let Err(e) = setup() {
        let _ = std::fs::remove_dir(&dir);
        return Err(e);
    }
    Ok(new_rel)
}

/// Remove the cgroup `dir` and the cgroups below it, the deepest first.
/// The kernel refuses to remove a cgroup a process is in, so only a tree
/// with no process goes.
fn remove_tree(dir: &Path) -> io::Result<()> {
    for e in std::fs::read_dir(dir)? {
        let e = e?;
        if e.file_type()?.is_dir() {
            remove_tree(&e.path())?;
        }
    }
    std::fs::remove_dir(dir)
}

/// Why the daemon does not own the cgroup `cg`.
fn why_not_owned(cg: &Path, pid: u32) -> String {
    let own = if cg.ends_with(DAEMON_CGROUP) {
        cg.parent().unwrap_or(cg)
    } else {
        cg
    };
    if procs(own).into_iter().any(|p| p != pid) {
        "other processes are in it".into()
    } else if !writable(&own.join("cgroup.procs")) || !writable(&own.join("cgroup.subtree_control"))
    {
        "the daemon cannot write it".into()
    } else {
        "systemd did not delegate it to a unit (Delegate=yes)".into()
    }
}

/// Make sure the daemon has a cgroup of its own that it may manage, before
/// any thread or child exists.  The cgroup, or why there is none (the
/// containers get no cgroups then).  `systemd`: `cgroup_manager =
/// "systemd"`, which has no fallback to a cgroup made by hand.
pub fn ensure_delegated_cgroup(systemd: bool) -> Result<String, NoCgroup> {
    // (the system's manager for root, else the user's)
    let socket = velarx_wire::sdbus::manager_socket(rustix::process::geteuid().is_root())?;
    delegated_cgroup(systemd, &socket).map_err(NoCgroup::Other)
}

/// Why [`ensure_delegated_cgroup`] gives no cgroup.
#[derive(Debug, thiserror::Error)]
pub enum NoCgroup {
    /// Who the daemon is cannot be told: it does not go on.
    #[error(transparent)]
    Ids(#[from] velarx_base::ids::IdsError),
    /// Why there is none: the containers get no cgroups.
    #[error("{0}")]
    Other(String),
}

fn delegated_cgroup(systemd: bool, socket: &Path) -> Result<String, String> {
    let pid = std::process::id();
    let rel = velarx_base::cgroup::of_process(None).map_err(|e| e.to_string())?;
    if keepable(&full(&rel), pid, socket).map_err(|e| e.to_string())? {
        return Ok(rel);
    }
    // The limits of the cgroup it leaves go with the daemon: its containers
    // must not escape them.
    let limits = effective_limits(&rel);
    let moved = match systemd_scope(&rel, pid, limits, socket) {
        Ok(cg) => cg,
        Err(manager) if systemd => {
            return Err(format!(
                "the daemon is in the cgroup {rel}, which it does not own ({}), and the \
                 manager does not make it a scope: {manager}; start the daemon from a unit \
                 with Delegate=yes, or where a systemd manager answers",
                why_not_owned(&full(&rel), pid)
            ));
        }
        Err(manager) => {
            sibling(&rel, pid, limits).map_err(|e| format!("{manager}; without systemd: {e}"))?
        }
    };
    let why = if !kept(limits, effective_limits(&moved)) {
        Some(format!("the cgroup {moved} lifts the limits of {rel}"))
    } else if !usable(&full(&moved), pid) {
        Some(format!("the cgroup {moved} is not delegated to the daemon"))
    } else {
        None
    };
    match why {
        None => Ok(moved),
        Some(why) => {
            // back where it was, limits and all
            if let Err(e) = std::fs::write(full(&rel).join("cgroup.procs"), pid.to_string()) {
                tracing::warn!("Process {pid} is not back in its cgroup {rel}: {e}");
            }
            Err(why)
        }
    }
}

/// The layout the containers need, made before the daemon has children (a
/// cgroup whose controllers are enabled for its children holds no process of
/// its own): the daemon in `engine/`, the controllers of the cgroup enabled
/// for the containers next to it.
pub fn prepare(rel: &str) -> Result<(), String> {
    let cg = full(
        rel.strip_suffix(&format!("/{DAEMON_CGROUP}"))
            .unwrap_or(rel),
    );
    let daemon = cg.join(DAEMON_CGROUP);
    match std::fs::create_dir(&daemon) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(format!("create {}: {e}", daemon.display())),
    }
    std::fs::write(daemon.join("cgroup.procs"), std::process::id().to_string())
        .map_err(|e| format!("move to {}: {e}", daemon.display()))?;
    // (one at a time: a controller that cannot be enabled leaves the others)
    for (c, r) in velarx_base::cgroup::enable_controllers(&cg)
        .map_err(|e| format!("read the controllers of {}: {e}", cg.display()))?
    {
        if let Err(e) = r {
            tracing::debug!("cannot enable the {c} controller for the containers: {e}");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slices() {
        let user = "/user.slice/user-1.slice/user@1.service/app.slice/x.scope";
        assert_eq!(slice_of(user, true).as_deref(), Some("app.slice"));
        assert_eq!(
            slice_of("/user.slice/user-1.slice/user@1.service/init.scope", true),
            None
        );
        assert_eq!(
            slice_of("/user.slice/user-1.slice/session-2.scope", true),
            None
        );
        assert_eq!(
            slice_of("/system.slice/velarx.service", false).as_deref(),
            Some("system.slice")
        );
        assert_eq!(slice_of("/x.scope", false), None);
    }

    #[test]
    fn why_the_cgroup_is_not_the_daemons() {
        let d = tempfile::tempdir().unwrap();
        for f in ["cgroup.procs", "cgroup.subtree_control"] {
            std::fs::write(d.path().join(f), "").unwrap();
        }
        // alone and writable, but not marked: systemd did not delegate it
        assert!(why_not_owned(d.path(), 7).contains("did not delegate"));
        std::fs::write(d.path().join("cgroup.procs"), "7\n8\n").unwrap();
        assert!(why_not_owned(d.path(), 7).contains("other processes"));
        let unwritable = tempfile::tempdir().unwrap();
        assert!(why_not_owned(&unwritable.path().join("none"), 7).contains("cannot write"));
    }

    #[test]
    fn only_a_service_or_a_scope_has_delegate() {
        assert_eq!(
            unit_interface(Path::new("/u/app.slice/velarx-engine.service")),
            Some(("velarx-engine.service", "org.freedesktop.systemd1.Service"))
        );
        assert_eq!(
            unit_interface(Path::new("/u/app.slice/tmux-spawn-1.scope")),
            Some(("tmux-spawn-1.scope", "org.freedesktop.systemd1.Scope"))
        );
        for other in ["/u/app.slice", "/u/velarx-1", "/"] {
            assert_eq!(unit_interface(Path::new(other)), None, "{other}");
        }
    }

    #[test]
    fn a_plain_directory_is_not_delegated() {
        let d = tempfile::tempdir().unwrap();
        assert!(!marked_delegated(d.path()));
    }

    #[test]
    fn limits_are_kept() {
        let l = |m: Option<u64>, s: Option<u64>, p: Option<u64>| Limits {
            memory: m,
            swap: s,
            pids: p,
        };
        assert!(kept(
            l(Some(10), None, Some(5)),
            l(Some(10), Some(1), Some(4))
        ));
        assert!(kept(l(None, None, None), l(None, None, None)));
        assert!(!kept(l(Some(10), None, None), l(None, None, None)));
        assert!(!kept(l(Some(10), None, None), l(Some(11), None, None)));
        assert!(!kept(l(None, None, Some(5)), l(None, None, Some(6))));
        // the root of the hierarchy has no limit files
        assert_eq!(effective_limits("/"), Limits::default());
    }

    #[test]
    fn a_cgroup_with_others_is_not_usable() {
        let d = tempfile::tempdir().unwrap();
        for f in ["cgroup.procs", "cgroup.subtree_control"] {
            std::fs::write(d.path().join(f), "").unwrap();
        }
        assert!(usable(d.path(), 7));
        std::fs::write(d.path().join("cgroup.procs"), "7\n").unwrap();
        assert!(usable(d.path(), 7));
        std::fs::write(d.path().join("cgroup.procs"), "7\n8\n").unwrap();
        assert!(!usable(d.path(), 7));
        // engine/ of a previous run: its parent is what counts
        let daemon = d.path().join(DAEMON_CGROUP);
        std::fs::create_dir(&daemon).unwrap();
        std::fs::write(daemon.join("cgroup.procs"), "7\n").unwrap();
        std::fs::write(d.path().join("cgroup.procs"), "").unwrap();
        assert!(usable(&daemon, 7));
    }

    #[test]
    fn the_cgroup_an_earlier_daemon_of_the_pid_left_is_taken() {
        // a child stands for the daemon, next to the cgroup of the test
        let rel = velarx_base::cgroup::of_process(None).unwrap();
        let parent = Path::new(&rel).parent().unwrap();
        let mut child = std::process::Command::new("sleep")
            .arg("1000")
            .spawn()
            .unwrap();
        let pid = child.id();
        // what a daemon that had this pid left: its cgroup, engine/ in it
        let stale = full(&parent.join(format!("velarx-{pid}")).to_string_lossy());
        let made = std::fs::create_dir_all(stale.join(DAEMON_CGROUP));
        let got = made.is_ok().then(|| sibling(&rel, pid, Limits::default()));
        let moved = velarx_base::cgroup::of_process(Some(pid as i32));
        child.kill().unwrap();
        child.wait().unwrap();
        let Some(got) = got else {
            return eprintln!("skipped: no cgroup can be made next to the test's: {made:?}");
        };
        remove_tree(&stale).unwrap();
        let got = got.unwrap();
        assert!(got.ends_with(&format!("/velarx-{pid}")), "{got}");
        assert_eq!(moved.unwrap(), got);
    }
}
