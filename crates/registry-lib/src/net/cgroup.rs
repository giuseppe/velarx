// SPDX-License-Identifier: Apache-2.0
//! The resources the pull workers of a pull may use: a cgroup v2 of their
//! own, so that a hostile registry cannot make them eat the memory of the
//! host nor start more tasks than `[pull] pids_max`.
//!
//! - In the daemon, which keeps itself in `<cgroup>/engine` and the cgroups
//!   of its containers next to it, the workers of a pool go to
//!   `<cgroup>/pulls/<id>`: `memory.high` slows them down (reclaim), above
//!   `memory.max` the kernel kills all of them (`memory.oom.group`), and
//!   the daemon is untouched, if the systemd unit that holds it has
//!   `OOMPolicy=continue`: with `stop` systemd would stop it.
//! - Without that layout (the engine without a daemon, a unit that stops
//!   on an OOM kill) the front asks the systemd of the user (of the system,
//!   for root) over the manager's private socket, once and before it
//!   confines itself, for a scope of its own with the cgroup delegated
//!   (`velarx-registry-<id>.scope`, `OOMPolicy=continue`); it moves itself
//!   to `<scope>/front` and the workers of a pool go to
//!   `<scope>/pulls/<id>`, with the same limits.  The confined front talks
//!   to no manager: it reaches no UNIX socket by name.
//! - Without either the workers keep the cgroup of their parent and only
//!   have the rlimits of their sandbox, silently, unless `[pull]
//!   require_cgroup` is set.
//!
//! [`place`] decides where the cgroups of the pools go, before the front
//! confines itself; its Landlock domain may make and remove directories and
//! write files beneath that `pulls` directory only.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use tracing::debug;
use velarx_config::PullConfig;

const CGROUP_ROOT: &str = "/sys/fs/cgroup";

/// What the workers of a pool may use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    pub memory_high: u64,
    pub memory_max: u64,
    pub pids_max: u64,
}

impl Limits {
    pub fn from_config(c: &PullConfig) -> Self {
        let mib = |n: u64| n.saturating_mul(1024 * 1024);
        Self {
            memory_high: mib(c.memory_high_mib),
            memory_max: mib(c.memory_max_mib),
            pids_max: c.pids_max,
        }
    }
}

enum Kind {
    /// A cgroup of the pool, below the `pulls` directory of [`place`]
    Cgroup(Cgroup),
    /// Nothing the workers can be put in
    None,
    /// Who this process is could not be told (its uid map is unreadable),
    /// or the cgroup of the pool could not be made where it was to be:
    /// where the workers would go is not known, none is started
    Failed(String),
}

/// Where the cgroups of the pools of this process go, decided once by
/// [`place`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Placement {
    /// Below this `pulls` directory (of the daemon's cgroup, or of the
    /// delegated scope of the front)
    Below(PathBuf),
    /// Nowhere: the workers keep the cgroup of their parent
    Nowhere,
    /// Not known (who this process is could not be told)
    Failed(String),
}

impl Placement {
    /// The directory the cgroups of the pools are made in, if any.
    pub fn dir(&self) -> Option<&Path> {
        match self {
            Placement::Below(dir) => Some(dir),
            _ => None,
        }
    }
}

static PLACEMENT: OnceLock<Placement> = OnceLock::new();

/// Decide, once for the process, where the cgroups of the pools of `config`
/// go: below the daemon's cgroup, else in a scope of its own the manager
/// delegates to this process, else nowhere.  The front calls it before it
/// confines itself (the manager is asked here and never later); a process
/// that did not is placed below the daemon's cgroup or nowhere.
pub fn place(config: &PullConfig) -> &'static Placement {
    PLACEMENT.get_or_init(|| {
        placement(
            Limits::from_config(config),
            velarx_base::ids::rootful().map_err(|e| e.to_string()),
            true,
        )
    })
}

fn placement(limits: Limits, rootful: Result<bool, String>, scope: bool) -> Placement {
    if limits.memory_max == 0 && limits.memory_high == 0 && limits.pids_max == 0 {
        return Placement::Nowhere;
    }
    let system = match rootful {
        Err(e) => return Placement::Failed(format!("the pull workers cannot get a cgroup: {e}")),
        Ok(system) => system,
    };
    if let Some(pulls) = below_daemon(system) {
        return Placement::Below(pulls);
    }
    if scope && scopes_available(system) {
        match own_scope(system) {
            Ok(pulls) => return Placement::Below(pulls),
            Err(e) => debug!("no delegated scope for the pull workers: {e}"),
        }
    }
    Placement::Nowhere
}

/// The `pulls` directory below the daemon's cgroup, if this process is a
/// daemon in the layout of the `CgroupManager` (itself in `engine/`, the
/// controllers enabled for its siblings) and may write it.
fn below_daemon(system: bool) -> Option<PathBuf> {
    let own = velarx_base::cgroup::of_process(None).ok()?;
    let rel = own.strip_suffix(&format!("/{}", velarx_base::spawn::DAEMON_CGROUP))?;
    if !unit_survives_oom(rel, system) {
        debug!("no cgroup for the pull workers below {rel}: an OOM kill would stop its unit");
        return None;
    }
    let parent = Path::new(CGROUP_ROOT).join(rel.trim_start_matches('/'));
    pulls_below(&parent)
        .inspect_err(|e| {
            debug!(
                "no cgroup for the pull workers below {}: {e}",
                parent.display()
            )
        })
        .ok()
}

/// A scope of the manager for this process, its cgroup delegated, which
/// survives the kill of a worker for memory: this process moves itself to
/// `<scope>/front`, and the cgroups of the pools are made in
/// `<scope>/pulls`.
fn own_scope(system: bool) -> io::Result<PathBuf> {
    use velarx_wire::sdbus::Property;
    let socket = manager_socket(system)
        .ok_or_else(|| io::Error::other("no XDG_RUNTIME_DIR: no manager to ask"))?;
    let props = vec![
        Property::Str("Description", "velarx registry fetcher".to_string()),
        Property::Str("CollectMode", "inactive-or-failed".to_string()),
        Property::Str("OOMPolicy", "continue".to_string()),
        Property::Bool("Delegate", true),
        Property::Pids(vec![std::process::id()]),
    ];
    velarx_wire::sdbus::start_unit_at(
        &socket,
        &format!("velarx-registry-{}.scope", velarx_base::random::uuid()),
        &props,
        true,
    )?;
    let own = velarx_base::cgroup::of_process(None).map_err(io::Error::other)?;
    if !own.ends_with(".scope") || !own.contains("/velarx-registry-") {
        return Err(io::Error::other(format!(
            "the manager left this process in {own}"
        )));
    }
    let scope = Path::new(CGROUP_ROOT).join(own.trim_start_matches('/'));
    // (a cgroup with processes of its own gives no controller to its
    // children: this process goes to a leaf)
    let front = scope.join("front");
    std::fs::create_dir(&front)?;
    std::fs::write(front.join("cgroup.procs"), std::process::id().to_string())?;
    std::fs::write(scope.join("cgroup.subtree_control"), "+memory +pids")?;
    pulls_below(&scope)
}

/// Make `<parent>/pulls`, which gives the memory and pids controllers to the
/// cgroups of the pools, and remove those a process that was killed left.
fn pulls_below(parent: &Path) -> io::Result<PathBuf> {
    let pulls = parent.join("pulls");
    match std::fs::create_dir(&pulls) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e),
    }
    // (a cgroup with no process of its own may give its controllers to its
    // children)
    let available = std::fs::read_to_string(pulls.join("cgroup.controllers"))?;
    for c in ["memory", "pids"] {
        if !available.split_whitespace().any(|a| a == c) {
            return Err(io::Error::other(format!("no {c} controller")));
        }
    }
    std::fs::write(pulls.join("cgroup.subtree_control"), "+memory +pids")?;
    sweep(&pulls);
    Ok(pulls)
}

/// How the workers of one pool are confined.  Where they go is decided when
/// the first worker is started (asking the manager is a connection): a
/// command that starts none (`rm`, `ps`, the cleanup of a container with
/// `--cgroups=disabled`) touches no cgroup and no manager.
pub struct Confinement {
    limits: Limits,
    required: bool,
    /// Whether this process is root of the host, or why that is not known
    rootful: Result<bool, String>,
    /// Decided once, by the first worker: the others wait for it
    kind: tokio::sync::OnceCell<Kind>,
}

impl Confinement {
    /// The confinement `config` asks for, with what this process can do.
    pub fn new(config: &PullConfig) -> Self {
        Self::of(config, velarx_base::ids::rootful())
    }

    /// [`Confinement::new`] for a process that is root of the host or not
    /// (`rootful`, [`velarx_base::ids::rootful`]).
    fn of(config: &PullConfig, rootful: Result<bool, velarx_base::ids::IdsError>) -> Self {
        Self {
            limits: Limits::from_config(config),
            required: config.require_cgroup,
            rootful: rootful.map_err(|e| e.to_string()),
            kind: tokio::sync::OnceCell::new(),
        }
    }

    /// A confinement whose place is known.
    #[cfg(test)]
    fn fixed(limits: Limits, kind: Kind) -> Self {
        Self {
            limits,
            required: false,
            rootful: Ok(false),
            kind: tokio::sync::OnceCell::new_with(Some(kind)),
        }
    }

    /// Where the workers go, decided the first time it is needed: the
    /// manager is asked (a connection, the `OOMPolicy` of the daemon's unit)
    /// and the cgroup made on a thread that may block, not on one of the
    /// runtime's.
    async fn kind(&self) -> &Kind {
        self.kind
            .get_or_init(|| async {
                let (limits, rootful) = (self.limits, self.rootful.clone());
                tokio::task::spawn_blocking(move || decide(limits, rootful))
                    .await
                    .unwrap_or_else(|e| {
                        Kind::Failed(format!("the pull workers cannot get a cgroup: {e}"))
                    })
            })
            .await
    }

    /// Fail the start of a worker that cannot be confined when the
    /// configuration requires a cgroup.
    pub async fn check(&self) -> io::Result<()> {
        match self.kind().await {
            Kind::Failed(why) => Err(io::Error::other(why.clone())),
            Kind::None if self.required => Err(io::Error::other(
                "the pull workers cannot get a cgroup: no delegated cgroup of the daemon and \
                 no systemd to delegate a scope ([pull] require_cgroup = false allows it)",
            )),
            _ => Ok(()),
        }
    }

    /// Put the worker `pid` in the cgroup of the pool, or in a scope of its
    /// own.
    pub async fn adopt(&self, pid: u32) -> io::Result<()> {
        match self.kind().await {
            Kind::Cgroup(cg) => cg.adopt(pid),
            Kind::None => Ok(()),
            Kind::Failed(why) => Err(io::Error::other(why.clone())),
        }
    }

    /// Whether a failure to confine a worker is to be reported.
    pub fn required(&self) -> bool {
        self.required
    }

    /// The kernel's count of the processes of the cgroup it killed for
    /// memory (0 without a cgroup of the pool, or before
    /// [`Confinement::check`] decided where the workers go): taken before a
    /// worker is put in it, for [`Confinement::killed_for_memory`].
    pub fn memory_kills(&self) -> u64 {
        match self.kind.get() {
            Some(Kind::Cgroup(cg)) => cg.oom_kills(),
            _ => 0,
        }
    }

    /// Why a worker is gone, when the kernel killed a process of its cgroup
    /// for memory since its count was `before`: only the cgroup's own
    /// account of its kills says so (a SIGKILL or a SIGABRT may come from
    /// anyone), so a worker in a scope or in no cgroup is never reported as
    /// out of memory.  Without a memory limit of the cgroup the kill is the
    /// host's.
    pub fn killed_for_memory(&self, before: u64) -> Option<String> {
        let Some(Kind::Cgroup(cg)) = self.kind.get() else {
            return None;
        };
        if cg.oom_kills() <= before {
            return None;
        }
        if self.limits.memory_max == 0 {
            return Some("the kernel killed it: the host is out of memory".to_string());
        }
        Some(format!(
            "the kernel killed it for the memory of its cgroup ([pull] memory_max_mib = {}, memory_high_mib = {})",
            self.limits.memory_max / (1024 * 1024),
            self.limits.memory_high / (1024 * 1024)
        ))
    }
}

/// Where the workers with `limits` go, in a process that is root of the
/// host or not (`rootful`): a cgroup of the pool where [`place`] put them,
/// else nothing.
fn decide(limits: Limits, rootful: Result<bool, String>) -> Kind {
    if limits.memory_max == 0 && limits.memory_high == 0 && limits.pids_max == 0 {
        return Kind::None;
    }
    if let Err(e) = rootful {
        return Kind::Failed(format!("the pull workers cannot get a cgroup: {e}"));
    }
    let placed = PLACEMENT.get_or_init(|| placement(limits, rootful, false));
    match placed {
        Placement::Below(pulls) => match Cgroup::create(pulls, limits) {
            Ok(cg) => Kind::Cgroup(cg),
            Err(e) => {
                debug!(
                    "no cgroup for the pull workers below {}: {e}",
                    pulls.display()
                );
                Kind::None
            }
        },
        Placement::Nowhere => Kind::None,
        Placement::Failed(why) => Kind::Failed(why.clone()),
    }
}

/// The private socket of the manager the scope of the front is asked of:
/// the user's, the system's (`system`) for root of the host.
fn manager_socket(system: bool) -> Option<PathBuf> {
    velarx_wire::sdbus::private_socket(system)
}

/// Whether the manager of the user (or the system's, for root: `system`)
/// makes scopes: it listens on its private socket.
fn scopes_available(system: bool) -> bool {
    let ok = match manager_socket(system) {
        Some(socket) => match std::os::unix::net::UnixStream::connect(&socket) {
            Ok(_) => true,
            Err(e) => {
                debug!("no manager to make scopes at {}: {e}", socket.display());
                false
            }
        },
        None => {
            debug!("no XDG_RUNTIME_DIR: no manager to make scopes");
            false
        }
    };
    debug!("a systemd scope for the pull workers: {ok}");
    ok
}

/// Whether the systemd unit that holds the cgroup `rel` goes on when the
/// kernel kills one of its processes for its memory (`OOMPolicy=continue`):
/// with `stop`, systemd's default, the kill of a worker below the daemon
/// would stop the daemon.  Asked of the manager (the system's: `system`)
/// once.
fn unit_survives_oom(rel: &str, system: bool) -> bool {
    static SURVIVES: OnceLock<bool> = OnceLock::new();
    *SURVIVES.get_or_init(|| {
        let Some(unit) = rel
            .rsplit('/')
            .find(|c| c.ends_with(".service") || c.ends_with(".scope"))
        else {
            // (no systemd unit, nobody to stop it)
            return true;
        };
        let interface = if unit.ends_with(".scope") {
            "org.freedesktop.systemd1.Scope"
        } else {
            "org.freedesktop.systemd1.Service"
        };
        let Some(socket) = manager_socket(system) else {
            debug!("no manager to ask the OOMPolicy of {unit}");
            return false;
        };
        match velarx_wire::sdbus::unit_string_at(&socket, unit, interface, "OOMPolicy") {
            Ok(policy) => {
                debug!("OOMPolicy of {unit}: {policy}");
                policy == "continue"
            }
            Err(e) => {
                debug!("cannot ask the manager the OOMPolicy of {unit}: {e}");
                false
            }
        }
    })
}

/// Remove the cgroups of the pools of a daemon that stopped without
/// removing them (it was killed): its workers died with it, so they are
/// empty, and a cgroup in use cannot be removed.  Once per process (by
/// [`place`]), before it makes any of its own.
fn sweep(pulls: &Path) {
    for e in std::fs::read_dir(pulls).into_iter().flatten().flatten() {
        if e.file_type().is_ok_and(|t| t.is_dir()) {
            if let Err(err) = std::fs::remove_dir(e.path()) {
                debug!("Cannot remove the cgroup {}: {err}", e.path().display());
            }
        }
    }
}

/// The processes the kernel killed for memory, in the text of `memory.events`.
fn oom_kills(events: &str) -> u64 {
    events
        .lines()
        .find_map(|l| l.strip_prefix("oom_kill "))
        .and_then(|n| n.trim().parse().ok())
        .unwrap_or(0)
}

/// The cgroup of one pool: `<cgroup of the daemon>/pulls/<id>`.
struct Cgroup {
    dir: PathBuf,
}

impl Cgroup {
    /// The cgroup of a new pool in `pulls` ([`pulls_below`]).
    fn create(pulls: &Path, limits: Limits) -> io::Result<Self> {
        let dir = pulls.join(velarx_base::random::uuid());
        std::fs::create_dir(&dir)?;
        let cg = Self { dir };
        // (the directory goes with the error)
        cg.limit(limits)?;
        Ok(cg)
    }

    fn limit(&self, limits: Limits) -> io::Result<()> {
        let set = |file: &str, value: String| {
            std::fs::write(self.dir.join(file), value)
                .map_err(|e| io::Error::new(e.kind(), format!("{file}: {e}")))
        };
        if limits.memory_high != 0 {
            set("memory.high", limits.memory_high.to_string())?;
        }
        if limits.memory_max != 0 {
            set("memory.max", limits.memory_max.to_string())?;
            set("memory.swap.max", "0".into())?;
        }
        if limits.pids_max != 0 {
            set("pids.max", limits.pids_max.to_string())?;
        }
        // all the workers of a pull die together
        set("memory.oom.group", "1".into())
    }

    fn adopt(&self, pid: u32) -> io::Result<()> {
        std::fs::write(self.dir.join("cgroup.procs"), pid.to_string())
    }

    /// The processes of the cgroup the kernel killed for memory (0 when its
    /// account cannot be read).
    fn oom_kills(&self) -> u64 {
        std::fs::read_to_string(self.dir.join("memory.events"))
            .map_or(0, |events| oom_kills(&events))
    }

    /// The most memory the workers used, for the logs.
    fn peak(&self) -> Option<u64> {
        std::fs::read_to_string(self.dir.join("memory.peak"))
            .ok()?
            .trim()
            .parse()
            .ok()
    }
}

impl Drop for Cgroup {
    fn drop(&mut self) {
        debug!(
            "The pull workers of {} used at most {} MiB",
            self.dir.display(),
            self.peak().map_or(0, |b| b / (1024 * 1024))
        );
        let _ = std::fs::write(self.dir.join("cgroup.kill"), "1");
        if std::fs::remove_dir(&self.dir).is_ok() {
            return;
        }
        // killed workers are still leaving: the kernel says when the last
        // one has
        let dir = std::mem::take(&mut self.dir);
        std::thread::spawn(move || {
            let Ok(events) = std::fs::File::open(dir.join("cgroup.events")) else {
                return;
            };
            loop {
                let populated = std::fs::read_to_string(dir.join("cgroup.events"))
                    .is_ok_and(|s| s.lines().any(|l| l == "populated 1"));
                if !populated {
                    let _ = std::fs::remove_dir(&dir);
                    return;
                }
                let mut fds = [rustix::event::PollFd::new(
                    &events,
                    rustix::event::PollFlags::PRI | rustix::event::PollFlags::ERR,
                )];
                if rustix::event::poll(&mut fds, None).is_err() {
                    return;
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Nothing asks the manager, nor opens a cgroup, until a worker needs to
    /// know where it goes.
    #[tokio::test]
    async fn where_the_workers_go_is_not_decided_before_one_starts() {
        let c = Confinement::new(&PullConfig::default());
        assert!(c.kind.get().is_none());
        assert!(!c.required());
        assert_eq!(c.memory_kills(), 0);
        assert_eq!(c.killed_for_memory(0), None);
        assert!(c.kind.get().is_none());
        let _ = c.check().await;
        assert!(c.kind.get().is_some());
    }

    /// Workers that start together wait for the one decision: made once,
    /// on the thread of one of them, even on a runtime of one thread.
    #[tokio::test]
    async fn workers_that_start_together_share_one_decision() {
        let c = std::sync::Arc::new(Confinement::new(&PullConfig {
            memory_high_mib: 0,
            memory_max_mib: 0,
            pids_max: 0,
            require_cgroup: true,
            ..Default::default()
        }));
        let checks: Vec<_> = (0..8)
            .map(|_| {
                let c = c.clone();
                tokio::spawn(async move { c.check().await.is_err() })
            })
            .collect();
        for check in checks {
            assert!(check.await.unwrap());
        }
        assert!(matches!(c.kind.get(), Some(Kind::None)));
    }

    #[test]
    fn limits_are_in_bytes() {
        let l = Limits::from_config(&PullConfig {
            memory_high_mib: 1,
            memory_max_mib: 2,
            pids_max: 3,
            ..Default::default()
        });
        assert_eq!(
            l,
            Limits {
                memory_high: 1 << 20,
                memory_max: 2 << 20,
                pids_max: 3
            }
        );
    }

    /// The cgroup of the user's systemd manager that holds the apps: the
    /// tests that need a writable cgroup use it, when there is one.
    fn user_app_slice() -> Option<PathBuf> {
        let own = velarx_base::cgroup::of_process(None).ok()?;
        let rel = own.as_str();
        let (manager, _) = rel.split_once(".service/")?;
        let slice = Path::new(CGROUP_ROOT)
            .join(format!("{}.service", manager.trim_start_matches('/')))
            .join("app.slice");
        rustix::fs::access(
            slice.join("cgroup.subtree_control"),
            rustix::fs::Access::WRITE_OK,
        )
        .ok()
        .map(|_| slice)
    }

    /// The workers of a pool are put in a cgroup below the daemon's, with
    /// the limits, and the cgroup goes when the pool does.
    #[test]
    fn a_pool_gets_a_cgroup_with_the_limits() {
        let Some(parent) = user_app_slice() else {
            return;
        };
        let limits = Limits {
            memory_high: 300 << 20,
            memory_max: 400 << 20,
            pids_max: 50,
        };
        let Ok(pulls) = pulls_below(&parent) else {
            return;
        };
        let Ok(cg) = Cgroup::create(&pulls, limits) else {
            return;
        };
        let read = |f: &str| std::fs::read_to_string(cg.dir.join(f)).unwrap();
        assert_eq!(read("memory.max").trim(), (400u64 << 20).to_string());
        assert_eq!(read("memory.high").trim(), (300u64 << 20).to_string());
        assert_eq!(read("pids.max").trim(), "50");
        assert_eq!(read("memory.oom.group").trim(), "1");
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .unwrap();
        cg.adopt(child.id()).unwrap();
        let procs = read("cgroup.procs");
        assert_eq!(procs.trim(), child.id().to_string());
        let dir = cg.dir.clone();
        // everything in it is killed with it
        drop(cg);
        child.wait().unwrap();
        let _ = std::fs::remove_dir(&dir);
        let _ = std::fs::remove_dir(dir.parent().unwrap());
    }

    /// Nothing to limit: no cgroup and no manager; a process that cannot
    /// tell who it is is placed nowhere it could be wrong about.
    #[test]
    fn a_placement_needs_limits_and_ids() {
        let none = Limits {
            memory_high: 0,
            memory_max: 0,
            pids_max: 0,
        };
        assert_eq!(placement(none, Ok(false), true), Placement::Nowhere);
        assert_eq!(placement(none, Err("x".into()), true), Placement::Nowhere);
        let some = Limits::from_config(&PullConfig::default());
        assert!(matches!(
            placement(some, Err("denied".into()), true),
            Placement::Failed(why) if why.contains("denied")
        ));
        assert_eq!(Placement::Nowhere.dir(), None);
    }

    #[test]
    fn only_the_kernels_count_of_kills_is_out_of_memory() {
        assert_eq!(oom_kills("low 0\nhigh 3\nmax 9\noom 1\noom_kill 0\n"), 0);
        assert_eq!(oom_kills("max 9\noom 1\noom_kill 2\noom_group_kill 1\n"), 2);
        assert_eq!(oom_kills(""), 0);
    }

    /// A kill by a signal says nothing of the memory when there is no
    /// cgroup of the pool to ask: a worker in none is never reported as out
    /// of memory.
    #[test]
    fn a_worker_outside_a_cgroup_is_never_out_of_memory() {
        let limits = Limits::from_config(&PullConfig::default());
        let c = Confinement::fixed(limits, Kind::None);
        assert_eq!(c.memory_kills(), 0);
        assert_eq!(c.killed_for_memory(0), None);
    }

    /// A kill of the cgroup counts for the workers that were in it when it
    /// happened, not for those that came after; without a memory limit it
    /// is the host's.
    #[test]
    fn a_kill_counts_for_the_workers_it_found() {
        let dir = tempfile::tempdir().unwrap();
        let events = |n: u64| {
            std::fs::write(
                dir.path().join("memory.events"),
                format!("low 0\nhigh 0\nmax 3\noom 1\noom_kill {n}\n"),
            )
            .unwrap()
        };
        let confined = |memory_max_mib| {
            Confinement::fixed(
                Limits::from_config(&PullConfig {
                    memory_max_mib,
                    ..PullConfig::default()
                }),
                Kind::Cgroup(Cgroup {
                    dir: dir.path().to_path_buf(),
                }),
            )
        };
        let c = confined(64);
        events(0);
        let before = c.memory_kills();
        assert_eq!(c.killed_for_memory(before), None);
        events(1);
        assert!(c
            .killed_for_memory(before)
            .unwrap()
            .contains("memory_max_mib = 64"));
        // (a worker started after the kill)
        assert_eq!(c.killed_for_memory(c.memory_kills()), None);
        assert!(confined(0)
            .killed_for_memory(before)
            .unwrap()
            .contains("the host is out of memory"));
    }

    #[tokio::test]
    async fn nothing_to_limit_nothing_to_confine() {
        let c = Confinement::new(&PullConfig {
            memory_high_mib: 0,
            memory_max_mib: 0,
            pids_max: 0,
            require_cgroup: true,
            ..Default::default()
        });
        // required, and there is no cgroup: reported
        assert!(c.check().await.is_err());
        assert!(c.adopt(1).await.is_ok());
    }

    /// A process that cannot tell who it is starts no worker, whether a
    /// cgroup is required or not: where the worker would go is not known,
    /// and the cause is what the start of the worker fails with.
    #[tokio::test]
    async fn unknown_ids_start_no_worker() {
        let denied = || {
            velarx_base::ids::IdsError(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "denied by the test",
            ))
        };
        let c = Confinement::of(&PullConfig::default(), Err(denied()));
        assert!(!c.required());
        let e = c.check().await.unwrap_err().to_string();
        assert!(e.contains("/proc/self/uid_map"), "{e}");
        assert!(e.contains("denied by the test"), "{e}");
        assert!(c.adopt(1).await.is_err());
        // (nothing to confine: nothing to know)
        let none = Confinement::of(
            &PullConfig {
                memory_high_mib: 0,
                memory_max_mib: 0,
                pids_max: 0,
                ..Default::default()
            },
            Err(denied()),
        );
        assert!(none.check().await.is_ok());
    }
}
