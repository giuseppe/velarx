// SPDX-License-Identifier: Apache-2.0
//! `--cgroups`: where a container and its monitor go (podman's modes).
//!
//! Decision table (what [`container_cgroup`] and the monitor's start do);
//! "manager" is a systemd manager that answers, for a command that runs no
//! server and is not in a unit (`systemd_cgroups`), or the server with
//! `cgroup_manager = "systemd"`:
//!
//! | mode (`--cgroups=`) | manager | container | monitor |
//! |---|---|---|---|
//! | none given, `enabled` | yes, no limits | `velarx-<id>.scope`, made by the command before it creates the container (see [`super::scope`]); the container is `container` below it; a scope that cannot be made fails the start (no cgroup is made by hand); without the manager's private socket, or a session outside the user's manager, as the next line | in that scope (`monitor`) |
//! | none given, `enabled` | a command, resource limits or `--cgroup-parent` | `velarx-<id>.scope` made by the runtime through the manager (`--systemd-cgroup`), which applies the limits | `velarx-monitor-<id>.scope` |
//! | none given, `enabled`, `split` | the server with a delegated cgroup (the default), `cgroup_manager = "cgroupfs"` or `"systemd"`, limits or not | `<root>/[<pod>/]<id>/container`, `<root>` the cgroup the server splits at its start (`CgroupManager`, the limits written there by the runtime, which makes the init of the container in it with `clone3(CLONE_INTO_CGROUP)`; the server itself is in `<root>/engine`, next to the pods and containers); "systemd" and an explicit `split` need a server cgroup it owns (below) and refuse to start without one, the default goes on without cgroups | `<root>/[<pod>/]<id>/runtime`, started into it with `clone3` |
//! | none given, `enabled` | the server, `[containers] cgroups = "scope"`, `--cgroups=scope`, or a slice as `--cgroup-parent`, or no delegated cgroup | as a command's, the two lines above: `velarx-<id>.scope` outside the server's unit (no limits: made by the server; limits, a slice: by the runtime); a pod's members are scopes in its slice (`--cgroup-parent`, by default `machine.slice` or `user.slice`; a pod with limits has `<parent stem>-velarx_pod_<id>.slice`) | in the scope, or `velarx-monitor-<id>.scope` |
//! | none given, `enabled` | the server, `cgroup_manager = "systemd"`, `--cgroup-parent=X.slice` | `velarx-<id>.scope` in that slice, made by the runtime through the manager (the only way to be in a slice) | the server's `engine` |
//! | none given, `enabled` | a command with no manager | with no cgroup to put it below, the cgroup of its monitor (limits are refused) | where it is started |
//! | `no-conmon` | yes | as `enabled` | stays where it is started |
//! | `split` | a command in a unit with `Delegate=yes` | `<cgroup>/velarx-payload-<id>` (the unit's cgroup is split in two) | `<cgroup>/runtime` |
//! | `disabled` | any (a command, the server in either manager) | none: no cgroup is made, no manager is asked, nothing of the cgroups is touched; the runtime is told (`--cgroup-manager disabled`) and its spec has no `linux.resources` and no `linux.cgroupsPath`; a resource limit, `--cgroup-parent` or another setting of a cgroup is an error (exit 125, `cgroup_settings`) | where it is started |
//!
//! The mode of a container that asks for none is `[containers] cgroups`
//! of the configuration ([`conf_default`]); for the server `split` (the
//! default, and what `enabled` means there) when it has a delegated cgroup to
//! split, else the other rows.  `pod create --cgroups=` is the mode of the
//! infra container; a pod made `disabled` has no cgroup, takes no parent or
//! limits, and its members are disabled too (another mode for one is an
//! error).  `disabled` decides before anything asks the manager: the engine
//! of a command probes it ([`systemd_answers`]) only when a container that
//! may have a scope needs to know (`Supervision::systemd_cgroups`), and the
//! holder of the rootless network namespace started for a disabled
//! container stays in the caller's cgroup (`rootless_netns::in_caller_cgroup`).
//!
//! A pod has a cgroup of its own where its containers are in the server's tree
//! (`<server cgroup>/<pod>`, the parent of theirs; [`super::cgroup`]), or, in a
//! slice (the rows with `--cgroup-parent=X.slice`), a slice
//! `X-velarx_pod_<id>.slice` that their scopes are in ([`super::podslice`]); the
//! limits of a pod (`resources` of its spec) are those of that cgroup, applied
//! when it is made and changed by `PodUpdate`.  A pod with limits where there is
//! none is an error.
//!
//! `--cgroups=scope` (`enabled` takes `[containers] cgroups` if it names it)
//! is `enabled` and says that the server's containers are scopes of the
//! manager outside its unit instead of cgroups next to the engine's.  It is
//! resolved when a container or a pod is made and stored with it (the members
//! of a pod have the pod's): an explicit `scope` where no manager makes
//! scopes is an error, as an explicit `split` where the server has no
//! delegated cgroup.  A command's containers are scopes; with `disabled` and
//! `split` it does not apply.
//!
//! The layout of `split`, in a cgroup `<root>` the server owns:
//!
//! ```text
//! <root>/engine/                  the server and its helpers
//! <root>/pulls/<id>/              the workers of a pull
//! <root>/<id>/container/          a container outside a pod (<id> the full id)
//! <root>/<id>/runtime/            its monitor
//! <root>/<pod>/<id>/container/    a member of a pod, the infra container too
//! <root>/<pod>/<id>/runtime/      (the limits of a pod are those of <root>/<pod>)
//! ```
//!
//! A cgroup with controllers enabled for its children holds no process (cgroup
//! v2), so the monitor is in a `runtime` next to the `container` the runtime
//! makes, and `<id>` gives them both the controllers.  The runtime is given
//! the path of `container` and the `cgroupfs` manager: it makes the init with
//! `clone3(CLONE_INTO_CGROUP)`, and the monitor is started into its own with
//! the same call, so neither waits for the kernel's grace period that a move
//! to a cgroup costs (5-10 ms of every start).  A restart of the server finds
//! them again by their ids; nothing moves.
//!
//! The server's cgroup, in both managers (`delegate`): a unit with
//! `Delegate=yes` that holds only the server owns its cgroup, and the tree is
//! below it, so `systemctl status` of the unit shows the server and every
//! container (rootless, any unit of the user's manager that holds only the
//! server: there is no mark of `Delegate=` to check and the user owns them
//! all).  A server in a cgroup it does not own (a login session, a shell's
//! scope, other processes next to it; as root a unit without `Delegate=`) asks the manager for a new scope
//! with `Delegate=yes` around itself, `velarx-<pid>.scope`, and the tree is
//! below that; "cgroupfs" falls back to a cgroup made by hand next to its own,
//! "systemd" does not (it is an error naming the cause), nor does an explicit
//! `[containers] cgroups = "split"`.  The rule of the command (a scope for
//! every container) is not the server's: the containers of one server are the
//! cgroups of one delegated tree, as in the table.
//!
//! Why the scope is made before the container: the manager needs 10-15 ms to
//! make one (moving a process into a new cgroup waits for an RCU grace
//! period of the kernel), a start waits for none of it when the command
//! asks at its beginning, while it loads the image and makes the bundle.
//!
use super::cgroup::CgroupManager;
use super::container::ContainerService;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use velarx_wire::request::{CgroupMode, CgroupsMode, CreateContainerRequest, NsMode};

pub use velarx_runtime::manager::{scope_manager_answers, system_manager};

/// The mode a container that asks for none gets from `[containers]
/// cgroups` of the configuration (`conf`), in the services (the server, and the
/// engine for what is not `run`/`create`: the infra containers of pods): "" is the default, `enabled`.  `split` is taken by `run` and
/// `create` of a command, which split the caller's cgroup before the
/// container is made; the server splits its own when it starts, and that is
/// its default ([`ContainerService::resolve_cgroups`]).
pub fn conf_default(conf: &str) -> CgroupsMode {
    match CgroupsMode::parse(conf) {
        Ok(m @ (CgroupsMode::Disabled | CgroupsMode::NoConmon)) => m,
        _ => CgroupsMode::Unset,
    }
}

/// Whether `[containers] cgroups` (`conf`) is `scope`: the containers of the
/// engine service that ask for none are scopes, not next to the engine.
pub fn conf_scope(conf: &str) -> bool {
    CgroupsMode::parse(conf).is_ok_and(|m| m == CgroupsMode::Scope)
}

/// The `scope` of a container or a pod (`--cgroups=scope`), as it is stored
/// with it: `asked`; none where it does not apply (`--cgroups=disabled` and
/// `split`, which ignore it, and a server with no manager that makes scopes:
/// its containers are next to the engine, in the only cgroup it has).
/// `command`: the engine of a command, which has no cgroup tree of its own
/// (its containers are scopes); `scopes`: a manager makes the scopes.  An
/// explicit scope the server cannot honour is an error.
pub fn cgroup_mode_of(
    asked: Option<CgroupMode>,
    cgroups: CgroupsMode,
    command: bool,
    scopes: impl Fn() -> Result<bool, velarx_base::ids::IdsError>,
) -> Result<Option<CgroupMode>, String> {
    if matches!(cgroups, CgroupsMode::Disabled | CgroupsMode::Split) {
        return Ok(None);
    }
    Ok(match asked {
        _ if command => Some(CgroupMode::Scope),
        Some(CgroupMode::Scope) if scopes().map_err(|e| e.to_string())? => Some(CgroupMode::Scope),
        Some(CgroupMode::Scope) => return Err(NO_SCOPES.into()),
        None => None,
    })
}

/// Why `--cgroups=split` is refused by a server with no delegated cgroup.
const NO_SPLIT: &str = "--cgroups=split puts the container next to the engine in the cgroup it \
     splits at its start, and the engine has no cgroup it owns (it needs Delegate=yes of its \
     unit, or a manager that makes it a scope)";

/// Why a slice is refused as the `--cgroup-parent` of the cgroupfs manager
/// (podman's words).
const SLICE_WITH_CGROUPFS: &str = "systemd slice received as cgroup parent when using cgroupfs";

/// Why `--cgroups=scope` is refused.
const NO_SCOPES: &str = "--cgroups=scope puts the container in a systemd scope of its own, \
     and no systemd manager answers the engine service (or it has no delegated cgroup): use \
     --cgroups=split";

/// The slice the scopes of the containers are in by default: `machine.slice`
/// of the system's manager, `user.slice` of the user's.
pub fn default_slice() -> Result<&'static str, velarx_base::ids::IdsError> {
    Ok(if system_manager()? {
        "machine.slice"
    } else {
        "user.slice"
    })
}

/// What a mode makes of the cgroups of a container (the table at the top).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Placement {
    /// No cgroup is made and no manager is asked.
    Untouched,
    /// A scope the command made, `velarx-<id>.scope`, the container below.
    CommandScope,
    /// A scope the runtime asks the manager for (limits, a parent slice).
    ManagerScope,
    /// No scope: a cgroup of the server's tree (`CgroupManager`), else none.
    NoScope,
}

/// The placement of a container in `mode` (`enabled`, `no-conmon`; `split`
/// has its own).  `systemd`: a manager makes the scopes (a command outside a
/// unit that finds one, or the server configured for it); `command`: the
/// engine of a command, not the server; `limits`: resource limits, which
/// only a cgroup of the container can take; `parent`: a `--cgroup-parent`,
/// a slice for the manager.
pub fn placement(
    mode: CgroupsMode,
    systemd: bool,
    command: bool,
    limits: bool,
    parent: bool,
) -> Placement {
    match mode {
        CgroupsMode::Disabled => Placement::Untouched,
        _ if !systemd => Placement::NoScope,
        _ if command && !limits && !parent => Placement::CommandScope,
        // the server's containers are cgroups of its delegated tree, limits
        // or not; only a slice that is asked for needs the manager
        _ if !command && !parent => Placement::NoScope,
        _ => Placement::ManagerScope,
    }
}

/// Whether the OCI runtime `path` has crun's `--cgroup-manager=disabled`
/// (what its `features` say, `container::has_crun_options`): crun and the
/// runtimes built on it.  runc and youki have no way to run a container
/// without making its cgroup, and an empty `cgroupsPath` only makes them
/// choose one.
pub fn runtime_can_disable_cgroups(path: &Path) -> bool {
    crate::container::has_crun_options(path)
}

/// Why the engine of a command gives a container no cgroup of its own.
pub const NO_CGROUP: &str = "with no API server the container has no cgroup of its own (no \
     systemd manager answers, or the command runs in a systemd unit, whose cgroup it shares): \
     its resource limits, --cgroup-parent and --cgroups=enabled need one; set the limits on \
     the unit (MemoryMax=, CPUQuota=, TasksMax=), use --cgroups=split in a unit with \
     Delegate=yes, or run the container through the API server";

/// The scope of the monitor of a container, `velarx-monitor-<id>.scope`
/// (without the suffix).
pub fn monitor_scope(id: &str) -> String {
    format!("velarx-monitor-{id}")
}

/// Whether the monitor of a container needs a scope of its own: only when
/// the container got a systemd scope (`--cgroups=enabled`, the default),
/// like podman's conmon.  With `disabled`, `no-conmon` and `split` the
/// monitor stays where it is started, and no `systemd-run` (several
/// milliseconds of every `run`) is spent on it.
pub fn monitor_needs_scope(mode: CgroupsMode, cgroups_path: Option<&str>) -> bool {
    mode.or_enabled() == CgroupsMode::Enabled && cgroups_path.is_some_and(is_systemd_path)
}

/// Whether a systemd manager answers, for the scopes of the containers:
/// the private socket of the system's for root, of the user's for a user
/// (the one the scopes are asked on).
pub fn systemd_answers() -> Result<bool, velarx_base::ids::IdsError> {
    Ok(
        std::os::unix::net::UnixStream::connect(velarx_wire::sdbus::manager_socket(
            system_manager()?,
        )?)
        .is_ok(),
    )
}

/// The name of the cgroup of a container in a split cgroup.
fn payload_name(id: &str) -> String {
    format!("velarx-payload-{}", &id[..id.len().min(12)])
}

/// Where the cgroup of a pod is, by how its containers are placed.
pub(crate) enum PodCgroup {
    /// A cgroup of the server's tree, `<parent>/<pod>`, with the cgroups of
    /// the containers below it.
    Tree(Arc<CgroupManager>),
    /// The containers are scopes of the manager in a slice (a systemd
    /// `--cgroup-parent`): the cgroup of a pod is a slice of its own.
    Slice,
    /// The engine makes no cgroup for the containers of this process.
    None,
}

impl ContainerService {
    /// The kind of cgroup the pods with the cgroup parent `parent` have:
    /// that of their members ([`placement`]); `scope`: the pod's
    /// `--cgroups` is `scope`, its members are scopes in a slice (a
    /// path of the cgroupfs manager is a tree below it, as in a unit).
    pub(crate) fn pod_cgroup(
        &self,
        parent: Option<&str>,
        scope: bool,
    ) -> Result<PodCgroup, velarx_base::ids::IdsError> {
        if self.pod_scopes_in_slice(scope)? && !self.tree_parent(parent)? {
            return Ok(PodCgroup::Slice);
        }
        Ok(
            match placement(
                CgroupsMode::Enabled,
                self.supervision.systemd_cgroups.get()?,
                self.caller_supervised,
                false,
                parent.is_some(),
            ) {
                Placement::NoScope => match &self.cgroup_manager {
                    Some(cm) if !self.caller_supervised => PodCgroup::Tree(Arc::clone(cm)),
                    _ => PodCgroup::None,
                },
                Placement::ManagerScope => PodCgroup::Slice,
                Placement::CommandScope | Placement::Untouched => PodCgroup::None,
            },
        )
    }

    /// Whether the containers of a pod made with `--cgroups=scope` (`scope`)
    /// are scopes in a slice: those of the server, and those of a command
    /// when a systemd manager answers it on its private socket (the slice
    /// is of the pod: it goes when the pod's containers stop, and comes back
    /// with the next start).
    pub(crate) fn pod_scopes_in_slice(
        &self,
        scope: bool,
    ) -> Result<bool, velarx_base::ids::IdsError> {
        Ok(scope
            && (!self.caller_supervised
                || (self.supervision.systemd_cgroups.get()? && scope_manager_answers()?)))
    }

    /// Whether `parent` is a `--cgroup-parent` of the server's cgroupfs
    /// manager, a path the tree of the container is made below.
    fn tree_parent(&self, parent: Option<&str>) -> Result<bool, velarx_base::ids::IdsError> {
        Ok(!self.caller_supervised
            && !self.supervision.systemd_cgroups.get()?
            && parent.is_some_and(|p| p.starts_with('/')))
    }

    /// A `--cgroup-parent` that is asked for (of a pod, or of a container
    /// out of a pod: not the slice a pod gives its members) is a path with
    /// the server's cgroupfs manager, whatever the `--cgroups=scope|unit`: a slice
    /// is refused.
    pub(crate) fn check_parent_kind(&self, parent: Option<&str>) -> Result<(), String> {
        match parent {
            Some(p)
                if !self.caller_supervised
                    && !self
                        .supervision
                        .systemd_cgroups
                        .get()
                        .map_err(|e| e.to_string())?
                    && p.ends_with(".slice") =>
            {
                Err(SLICE_WITH_CGROUPFS.into())
            }
            _ => Ok(()),
        }
    }

    /// Resolve the `--cgroups` of a new container or pod: `scope` becomes
    /// `enabled` and the `mode` that is stored with it ([`cgroup_mode_of`];
    /// `mode` is also what a pod gives its members, so one that differs from
    /// the value is an error).  The server with a delegated cgroup makes
    /// `split` of what asks for no scope, `enabled` and none given: its
    /// containers are next to the engine, unless `parent` is a slice (the
    /// manager makes the scope) or the configuration says `scope`.
    pub(crate) fn resolve_cgroups(
        &self,
        cgroups: &mut CgroupsMode,
        mode: &mut Option<CgroupMode>,
        parent: Option<&str>,
    ) -> Result<(), String> {
        let (value, asked) = cgroups.split();
        if let (Some(asked), Some(mode)) = (asked, *mode) {
            if asked != mode {
                return Err(format!(
                    "--cgroups={asked}: the pod was made with --cgroups={mode}, which its \
                     containers share"
                ));
            }
        }
        let scope = asked
            .or(*mode)
            .or(self.default_scope.then_some(CgroupMode::Scope));
        if !self.caller_supervised && value == CgroupsMode::Split {
            if self.cgroup_manager.is_none() {
                return Err(NO_SPLIT.into());
            }
            if let Some(scope) = asked.or(*mode) {
                return Err(format!(
                    "--cgroups=split: the pod was made with --cgroups={scope}, which its \
                     containers share"
                ));
            }
        }
        if is_default_split(
            self.caller_supervised,
            self.cgroup_manager.is_some(),
            scope,
            value,
            parent,
        ) {
            *mode = None;
            *cgroups = CgroupsMode::Split;
            return Ok(());
        }
        *mode = self.cgroup_mode_for(scope, value)?;
        *cgroups = value;
        Ok(())
    }

    /// The `scope` of a new container or pod that asks for `asked`, with the
    /// `--cgroups` mode `cgroups`.
    fn cgroup_mode_for(
        &self,
        asked: Option<CgroupMode>,
        cgroups: CgroupsMode,
    ) -> Result<Option<CgroupMode>, String> {
        cgroup_mode_of(asked, cgroups, self.caller_supervised, || {
            Ok(self.cgroup_manager.is_some() && scope_manager_answers()?)
        })
    }

    /// The cgroup path of a new container (`linux.cgroupsPath`), by its
    /// `--cgroups` mode; why not, for a mode or combination this process
    /// cannot honour.
    pub(crate) fn container_cgroup(
        &self,
        req: &CreateContainerRequest,
        id: &str,
    ) -> Result<Option<String>, String> {
        let mode = req.cgroups.or_enabled();
        match mode {
            CgroupsMode::Split if self.caller_supervised => {
                if req.cgroup_parent.is_some() {
                    return Err("--cgroups=split and --cgroup-parent exclude each other".into());
                }
                // A container of a pod (Quadlet's .container with Pod=) is in
                // the cgroup of its own unit: it shares the namespaces of the
                // pod, not its cgroup, so the limits of the pod do not apply
                // to it (podman's documented limitation).
                match &self.supervision.split_cgroup {
                    Some(parent) => Ok(Some(format!(
                        "{}/{}",
                        parent.trim_end_matches('/'),
                        payload_name(id)
                    ))),
                    None => Err(
                        "the cgroup of the caller is not split (--cgroups=split needs \
                                 a cgroup of its own that it may write: Delegate=yes)"
                            .into(),
                    ),
                }
            }
            CgroupsMode::Disabled => {
                let runtime = self
                    .find_runtime(req.runtime.as_deref().unwrap_or_default())
                    .map_err(|e| e.to_string())?;
                if !runtime_can_disable_cgroups(&runtime) {
                    return Err(format!(
                        "--cgroups=disabled needs an OCI runtime that can run a container \
                         without making its cgroup (crun's --cgroup-manager=disabled, which \
                         the features of a runtime show by the run.oci. annotations): {} \
                         makes one whatever the spec says",
                        runtime.display()
                    ));
                }
                if req.cgroup_parent.is_some() {
                    return Err("cannot set cgroup parent if not creating cgroups".into());
                }
                let limits = cgroup_settings(req);
                if !limits.is_empty() {
                    return Err(format!(
                        "cannot set {} without cgroups: --cgroups=disabled makes no cgroup \
                         to apply it to",
                        limits.join(", ")
                    ));
                }
                if req.cgroupns_mode != NsMode::Default {
                    return Err("--cgroups=disabled and --cgroupns exclude each other".into());
                }
                Ok(None)
            }
            // (scope is enabled, once resolved; the server's split is the
            // tree of its cgroup manager, as enabled without a scope)
            CgroupsMode::Enabled
            | CgroupsMode::Split
            | CgroupsMode::NoConmon
            | CgroupsMode::Scope
            | CgroupsMode::Unset => {
                if mode == CgroupsMode::Split && self.cgroup_manager.is_none() {
                    return Err(NO_SPLIT.into());
                }
                let limits = req.resources.as_ref().is_some_and(|r| r.need_cgroup())
                    || req.pids_limit.is_some();
                // (not the slice a pod of `--cgroups=scope` gives its members,
                // which a member that is not in the pod's cgroup keeps)
                let pod_slice = !self.caller_supervised
                    && req.cgroup_mode == Some(CgroupMode::Scope)
                    && req.cgroup_parent.as_deref()
                        == Some(default_slice().map_err(|e| e.to_string())?);
                if req.pod.is_none() && !pod_slice {
                    self.check_parent_kind(req.cgroup_parent.as_deref())?;
                }
                // `--cgroups=scope`: the server's container is placed as
                // a command's, in a scope of the manager outside the
                // server's unit (a path of the cgroupfs manager is a tree
                // below it, as in a unit)
                let scope = !self.caller_supervised
                    && req.cgroup_mode == Some(CgroupMode::Scope)
                    && !self
                        .tree_parent(req.cgroup_parent.as_deref())
                        .map_err(|e| e.to_string())?;
                match placement(
                    mode,
                    scope
                        || self
                            .supervision
                            .systemd_cgroups
                            .get()
                            .map_err(|e| e.to_string())?,
                    scope || self.caller_supervised,
                    limits,
                    req.cgroup_parent.is_some(),
                ) {
                    Placement::CommandScope => {
                        // (the command asks the manager on its private
                        // socket; without it, or outside the user's manager,
                        // the runtime asks over the bus)
                        if scope_manager_answers().map_err(|e| e.to_string())? {
                            if let Some(path) = engine_scope_path(id).map_err(|e| e.to_string())? {
                                return Ok(Some(path));
                            }
                        }
                        super::scope::cancel(id);
                        return systemd_scope(req.cgroup_parent.as_deref(), id).map(Some);
                    }
                    Placement::ManagerScope => {
                        // (the one the command asked for in advance is not needed)
                        super::scope::cancel(id);
                        return systemd_scope(req.cgroup_parent.as_deref(), id).map(Some);
                    }
                    Placement::NoScope | Placement::Untouched => {}
                }
                if self.caller_supervised {
                    // with no cgroup of its own the container is in the
                    // cgroup of its monitor: what limits it would be
                    // dropped
                    let limited = req.resources.as_ref().is_some_and(|r| r.need_cgroup())
                        || req.pids_limit.is_some()
                        || req.cgroup_parent.is_some();
                    if !req.cgroups.is_unset() || limited {
                        return Err(NO_CGROUP.to_string());
                    }
                    return Ok(None);
                }
                let parent = match req.cgroup_parent.as_deref() {
                    Some(p) => {
                        let valid = p.starts_with('/')
                            && p.split('/').all(|c| c != "." && c != "..")
                            && !p.contains('\0');
                        if !valid {
                            return Err(format!(
                                "invalid cgroup parent `{p}`: an absolute path is expected"
                            ));
                        }
                        Some(p)
                    }
                    None => None,
                };
                match (&self.cgroup_manager, parent) {
                    (Some(cm), parent) => Ok(Some(cm.container_cgroup_path(
                        parent,
                        req.pod.as_deref(),
                        id,
                    ))),
                    (None, None) => Ok(None),
                    (None, Some(_)) => {
                        Err("--cgroup-parent needs the daemon to manage cgroups (root)".into())
                    }
                }
            }
        }
    }
}

/// Whether a container that asks for `value` (no `split`, no `scope`), with
/// the `--cgroup-parent` `parent`, is made `split`: the server's default, when
/// it has a delegated cgroup (`manager`).  A slice as parent is the manager's
/// (a scope in it), `scope` is asked for, a command has no tree.
pub(crate) fn is_default_split(
    command: bool,
    manager: bool,
    scope: Option<CgroupMode>,
    value: CgroupsMode,
    parent: Option<&str>,
) -> bool {
    !command
        && manager
        && scope.is_none()
        && matches!(value, CgroupsMode::Unset | CgroupsMode::Enabled)
        && parent.is_none_or(|p| p.starts_with('/'))
}

/// The settings of a request that are applied to a cgroup (limits, the
/// device and OOM rules, raw cgroup files), by the flag that sets each.
/// `--ulimit`, `--oom-score-adj`, `--shm-size` and `--device` are not.
pub(crate) fn cgroup_settings(req: &CreateContainerRequest) -> Vec<&'static str> {
    let none = velarx_wire::request::ResourceLimits::default();
    let r = req.resources.as_ref().unwrap_or(&none);
    let flags = [
        (r.memory.is_some(), "--memory"),
        // (a swap with a memory limit is named by --memory: the frontends
        // give one to every --memory, as podman's)
        (
            r.memory_swap.is_some() && r.memory.is_none(),
            "--memory-swap",
        ),
        (r.memory_reservation.is_some(), "--memory-reservation"),
        (r.cpu_quota.is_some(), "--cpus/--cpu-quota"),
        (r.cpu_period.is_some(), "--cpu-period"),
        (r.cpu_shares.is_some(), "--cpu-shares"),
        (r.cpuset_cpus.is_some(), "--cpuset-cpus"),
        (r.cpuset_mems.is_some(), "--cpuset-mems"),
        (r.blkio_weight.is_some(), "--blkio-weight"),
        (!r.blkio_weight_device.is_empty(), "--blkio-weight-device"),
        (
            !r.blkio_device_read_bps.is_empty() || r.device_read_bps.is_some(),
            "--device-read-bps",
        ),
        (
            !r.blkio_device_write_bps.is_empty() || r.device_write_bps.is_some(),
            "--device-write-bps",
        ),
        (
            !r.blkio_device_read_iops.is_empty() || r.device_read_iops.is_some(),
            "--device-read-iops",
        ),
        (
            !r.blkio_device_write_iops.is_empty() || r.device_write_iops.is_some(),
            "--device-write-iops",
        ),
        (
            r.cgroup_conf.as_ref().is_some_and(|c| !c.is_empty()),
            "--cgroup-conf",
        ),
        (!r.hugepage_limits.is_empty(), "hugepage limits"),
        (req.pids_limit.is_some(), "--pids-limit"),
        (req.oom_kill_disable, "--oom-kill-disable"),
        (!req.device_cgroup_rules.is_empty(), "--device-cgroup-rule"),
    ];
    flags
        .iter()
        .filter(|(on, _)| *on)
        .map(|(_, flag)| *flag)
        .collect()
}

/// The `linux.cgroupsPath` of a container in a transient scope made by the
/// runtime through systemd: `<slice>:velarx:<id>`, the scope
/// `velarx-<id>.scope` in `slice`, by default `machine.slice` (root) or
/// `user.slice` of the user's manager.  A `--cgroup-parent` is then a slice.
fn systemd_scope(parent: Option<&str>, id: &str) -> Result<String, String> {
    let slice = match parent {
        Some(p) => {
            let valid = p.ends_with(".slice")
                && p.len() > ".slice".len()
                && p.chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '@'));
            if !valid {
                return Err(format!(
                    "invalid cgroup parent `{p}`: the systemd cgroup manager takes a slice \
                     (NAME.slice)"
                ));
            }
            p.to_string()
        }
        None => default_slice().map_err(|e| e.to_string())?.to_string(),
    };
    Ok(format!("{slice}:velarx:{id}"))
}

/// The cgroup of the scope the command makes for a container
/// (`<slice>/velarx-<id>.scope`, the slice `user.slice` of the user's
/// manager or `machine.slice`), below which the container is `container`:
/// the `linux.cgroupsPath` of a container that asks for no limits.  `own` is
/// the cgroup of this process (`/proc/self/cgroup`); `None` when it is not
/// below the user's manager (a session of `logind`), whose slices a user
/// cannot reach.
pub fn scope_cgroup_path(own: &str, uid: u32, root: bool, id: &str) -> Option<String> {
    let slice = if root {
        "/machine.slice".to_string()
    } else {
        let marker = format!("/user@{uid}.service");
        let end = own.find(&marker)? + marker.len();
        format!("{}/user.slice", &own[..end])
    };
    Some(format!("{slice}/velarx-{id}.scope/container"))
}

/// [`scope_cgroup_path`] for this process.
pub fn engine_scope_path(id: &str) -> Result<Option<String>, velarx_base::ids::IdsError> {
    let Ok(own) = velarx_base::cgroup::of_process(None) else {
        return Ok(None);
    };
    Ok(scope_cgroup_path(
        &own,
        velarx_base::ids::host_uid()?,
        system_manager()?,
        id,
    ))
}

/// The scope (its cgroup, without `/container`) of a `linux.cgroupsPath`
/// made by [`scope_cgroup_path`].
pub fn engine_scope_dir(path: &str) -> Option<&str> {
    let dir = path.strip_suffix("/container")?;
    let name = dir.rsplit('/').next()?;
    (path.starts_with('/')
        && name
            .strip_prefix("velarx-")
            .and_then(|n| n.strip_suffix(".scope"))
            .is_some_and(|id| id.len() == 64 && id.bytes().all(|b| b.is_ascii_hexdigit())))
    .then_some(dir)
}

pub(crate) const CGROUP_FS: &str = velarx_base::cgroup::ROOT;

/// Enable for the children of the cgroup `dir` the controllers it has,
/// before the runtime makes the container in it (its own write then finds
/// nothing to do).
pub(crate) fn enable_controllers(dir: &Path) {
    match velarx_base::cgroup::enable_controllers(dir) {
        Ok(done) => {
            for (c, r) in done {
                if let Err(e) = r {
                    tracing::warn!("Controller {c} not enabled in {}: {e}", dir.display());
                }
            }
        }
        Err(e) => tracing::warn!("Controllers not enabled in {}: {e}", dir.display()),
    }
}

/// Whether a `linux.cgroupsPath` is a systemd one (`slice:prefix:name`).
pub fn is_systemd_path(path: &str) -> bool {
    !path.starts_with('/') && path.contains(':')
}

/// The options of the runtime for a container: a container with a cgroup
/// path is made with the cgroupfs manager (the engine and a rootless server
/// disable it for the others), or with systemd's (`--systemd-cgroup`) for a
/// path of the systemd manager; one with `--cgroups=disabled` without one.
/// `--cgroup-manager` is crun's only: another `runtime` gets none of it (its
/// `features` say whether it has it).
pub(crate) fn runtime_args_for(
    mut args: Vec<String>,
    mode: CgroupsMode,
    cgroups_path: Option<&str>,
    runtime: &Path,
) -> Vec<String> {
    let disabled = |a: &[String], i: usize| {
        a[i] == "--cgroup-manager" && a.get(i + 1).is_some_and(|v| v == "disabled")
            || a[i] == "--cgroup-manager=disabled"
    };
    if let Some(path) = cgroups_path {
        if is_systemd_path(path) && !args.iter().any(|a| a == "--systemd-cgroup") {
            args.push("--systemd-cgroup".into());
        }
        let mut i = 0;
        while i < args.len() {
            if disabled(&args, i) {
                let n = if args[i].contains('=') { 1 } else { 2 };
                args.drain(i..i + n);
            } else {
                i += 1;
            }
        }
    } else if mode == CgroupsMode::Disabled && !(0..args.len()).any(|i| disabled(&args, i)) {
        args.extend(["--cgroup-manager".into(), "disabled".into()]);
    }
    crate::container::args_for_runtime(runtime, &args)
}

/// Split the cgroup of this process for `--cgroups=split`: every process of
/// it moves to `<cgroup>/runtime` (a cgroup that gives controllers to its
/// children may have no process of its own), and the controllers are
/// enabled for the children.  The cgroup that was split, relative to the
/// root of the hierarchy (for `linux.cgroupsPath`).  A process already in
/// the `runtime` of a split cgroup (a second command of the unit) splits
/// nothing.
pub fn split_own_cgroup() -> io::Result<String> {
    split_cgroup(
        Path::new(CGROUP_FS),
        &velarx_base::cgroup::of_process(None)?,
    )
}

fn split_cgroup(root: &Path, own: &str) -> io::Result<String> {
    let own = own.trim_end_matches('/');
    let parent = match own.strip_suffix("/runtime") {
        Some(p)
            if root
                .join(p.trim_start_matches('/'))
                .join("cgroup.subtree_control")
                .exists() =>
        {
            p.to_string()
        }
        _ => own.to_string(),
    };
    if parent.is_empty() || parent == "/" {
        return Err(io::Error::other("the root cgroup is not split"));
    }
    let dir: PathBuf = root.join(parent.trim_start_matches('/'));
    let runtime = dir.join("runtime");
    match std::fs::create_dir(&runtime) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e),
    }
    let procs = std::fs::read_to_string(dir.join("cgroup.procs"))?;
    for pid in procs.split_whitespace() {
        match std::fs::write(runtime.join("cgroup.procs"), pid) {
            Ok(()) => {}
            // Gone meanwhile.
            Err(e) if e.raw_os_error() == Some(libc::ESRCH) => {}
            Err(e) => return Err(io::Error::new(e.kind(), format!("move {pid}: {e}"))),
        }
    }
    for (c, r) in velarx_base::cgroup::enable_controllers(&dir)? {
        if let Err(e) = r {
            tracing::warn!("Cannot enable the {c} controller of {}: {e}", dir.display());
        }
    }
    Ok(parent)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    /// A fake runtime whose `features` print `features` (none: it has no
    /// such command).  The name says nothing.
    fn runtime(dir: &Path, name: &str, features: Option<&str>) -> std::path::PathBuf {
        let path = dir.join(name);
        velarx_base::testing::write_runtime(&path, features);
        path
    }

    #[test]
    fn a_container_with_a_cgroup_gets_a_manager() {
        let dir = tempfile::tempdir().unwrap();
        let crun = runtime(
            dir.path(),
            "runc",
            Some(velarx_base::testing::CRUN_FEATURES),
        );
        let args_for = |args: Vec<String>, mode: CgroupsMode, path: Option<&str>| {
            runtime_args_for(args, mode, path, &crun)
        };
        let engine = s(&["--log-level", "warn", "--cgroup-manager", "disabled"]);
        assert_eq!(
            args_for(
                engine.clone(),
                CgroupsMode::Split,
                Some("/u.service/velarx-payload-a")
            ),
            s(&["--log-level", "warn"])
        );
        assert_eq!(args_for(engine.clone(), CgroupsMode::Unset, None), engine);
        assert_eq!(
            args_for(
                s(&["--cgroup-manager=disabled"]),
                CgroupsMode::Unset,
                Some("/x")
            ),
            Vec::<String>::new()
        );
        assert_eq!(
            args_for(Vec::new(), CgroupsMode::Disabled, None),
            s(&["--cgroup-manager", "disabled"])
        );
        assert_eq!(
            args_for(engine.clone(), CgroupsMode::Disabled, None),
            engine
        );
    }

    #[test]
    fn a_runtime_that_does_not_list_the_cgroup_manager_gets_none_of_crun() {
        let dir = tempfile::tempdir().unwrap();
        // (the name says nothing: the features do)
        let runc = runtime(
            dir.path(),
            "crun",
            Some(velarx_base::testing::RUNC_FEATURES),
        );
        assert_eq!(
            runtime_args_for(Vec::new(), CgroupsMode::Disabled, None, &runc),
            Vec::<String>::new()
        );
        // what the engine or a rootless daemon adds for every container
        let engine = s(&["--log-level", "warn", "--cgroup-manager", "disabled"]);
        assert_eq!(
            runtime_args_for(engine, CgroupsMode::Unset, None, &runc),
            s(&["--log-level", "warn"])
        );
        // a systemd path still gets the manager of systemd, that runc takes
        // too
        assert_eq!(
            runtime_args_for(
                Vec::new(),
                CgroupsMode::Unset,
                Some("user.slice:velarx:a"),
                &runc
            ),
            s(&["--systemd-cgroup"])
        );
        assert_eq!(
            runtime_args_for(
                s(&["--cgroup-manager", "disabled"]),
                CgroupsMode::Unset,
                Some("/x"),
                &runc
            ),
            Vec::<String>::new()
        );
        // a runtime with no `features` has none of crun's options
        let none = runtime(dir.path(), "nofeatures", None);
        assert_eq!(
            runtime_args_for(
                s(&["--cgroup-manager", "disabled"]),
                CgroupsMode::Unset,
                None,
                &none
            ),
            Vec::<String>::new()
        );
        let missing = dir.path().join("none");
        assert_eq!(
            runtime_args_for(
                s(&["--cgroup-manager", "disabled"]),
                CgroupsMode::Unset,
                None,
                &missing
            ),
            Vec::<String>::new()
        );
    }

    #[test]
    fn the_monitor_scope_is_named_after_the_container() {
        assert_eq!(monitor_scope("abc"), "velarx-monitor-abc");
    }

    #[test]
    fn only_a_container_in_a_scope_gives_its_monitor_one() {
        let scope = Some("user.slice:velarx:abc");
        assert!(monitor_needs_scope(CgroupsMode::Unset, scope));
        assert!(monitor_needs_scope(CgroupsMode::Enabled, scope));
        for mode in [
            CgroupsMode::Disabled,
            CgroupsMode::NoConmon,
            CgroupsMode::Split,
        ] {
            assert!(!monitor_needs_scope(mode, scope), "{mode}");
        }
        assert!(!monitor_needs_scope(CgroupsMode::Unset, None));
        assert!(!monitor_needs_scope(
            CgroupsMode::Unset,
            Some("/machine.slice/abc")
        ));
    }

    #[test]
    fn systemd_scopes() {
        assert!(systemd_scope(Some("web.slice"), "abc").unwrap() == "web.slice:velarx:abc");
        for bad in ["/a/b", "web", ".slice", "a b.slice", "../x.slice"] {
            assert!(systemd_scope(Some(bad), "abc").is_err(), "{bad}");
        }
        let default = systemd_scope(None, "abc").unwrap();
        assert!(default.ends_with(".slice:velarx:abc"), "{default}");
        assert!(is_systemd_path("machine.slice:velarx:abc"));
        assert!(!is_systemd_path("/machine.slice/abc"));
        let dir = tempfile::tempdir().unwrap();
        let crun = runtime(
            dir.path(),
            "myruntime",
            Some(velarx_base::testing::CRUN_FEATURES),
        );
        assert_eq!(
            runtime_args_for(
                s(&["--cgroup-manager", "disabled"]),
                CgroupsMode::Unset,
                Some("user.slice:velarx:a"),
                &crun
            ),
            s(&["--systemd-cgroup"])
        );
    }

    #[test]
    fn the_default_of_the_configuration() {
        use CgroupsMode::{Disabled, NoConmon, Unset};
        for (conf, mode) in [
            ("", Unset),
            ("enabled", Unset),
            ("disabled", Disabled),
            ("no-conmon", NoConmon),
            // (a command splits the caller's cgroup, the server its own)
            ("split", Unset),
            ("bogus", Unset),
        ] {
            assert_eq!(conf_default(conf), mode, "{conf}");
        }
    }

    #[test]
    fn the_cgroup_mode_of_a_container() {
        use velarx_wire::request::CgroupMode::Scope;
        use CgroupsMode::{Disabled, Enabled, NoConmon, Split, Unset};
        // (asked, --cgroups, command, scopes) -> stored
        let ok = |asked, cgroups, command, scopes| {
            cgroup_mode_of(asked, cgroups, command, || Ok(scopes))
        };
        // a scope that is asked for, a manager that answers
        assert_eq!(ok(Some(Scope), Unset, false, true), Ok(Some(Scope)));
        // none asked: next to the engine (no mode stored)
        assert_eq!(ok(None, Enabled, false, true), Ok(None));
        assert_eq!(ok(None, Unset, false, false), Ok(None));
        // no manager: an explicit scope is an error
        assert!(ok(Some(Scope), Unset, false, false)
            .unwrap_err()
            .contains("no systemd manager"));
        // a command has no tree: its containers are scopes
        assert_eq!(ok(None, Unset, true, false), Ok(Some(Scope)));
        // disabled and split ignore it, even an explicit one
        for cgroups in [Disabled, Split] {
            assert_eq!(ok(Some(Scope), cgroups, false, false), Ok(None));
        }
        assert_eq!(ok(None, NoConmon, true, true), Ok(Some(Scope)));
    }

    #[test]
    fn the_server_splits_by_default() {
        use CgroupsMode::{Disabled, Enabled, NoConmon, Unset};
        let scope = Some(CgroupMode::Scope);
        // (command, manager, scope, --cgroups, parent)
        assert!(is_default_split(false, true, None, Unset, None));
        assert!(is_default_split(false, true, None, Enabled, None));
        assert!(is_default_split(false, true, None, Unset, Some("/a/b")));
        // no delegated cgroup: the other rows
        assert!(!is_default_split(false, false, None, Unset, None));
        // a command has no tree to split into; a scope, a slice, another
        // mode are asked for
        assert!(!is_default_split(true, true, None, Unset, None));
        assert!(!is_default_split(false, true, scope, Unset, None));
        assert!(!is_default_split(false, true, None, Unset, Some("x.slice")));
        assert!(!is_default_split(false, true, None, Disabled, None));
        assert!(!is_default_split(false, true, None, NoConmon, None));
    }

    #[test]
    fn scope_is_a_value_of_cgroups() {
        assert!(conf_scope("scope"));
        for c in ["", "enabled", "disabled", "split", "unit"] {
            assert!(!conf_scope(c), "{c}");
        }
        assert_eq!(conf_default("scope"), CgroupsMode::Unset);
        assert_eq!(conf_default("disabled"), CgroupsMode::Disabled);
    }

    #[test]
    fn the_decision_table() {
        use CgroupsMode::*;
        use Placement::*;
        // (mode, manager, command, limits, parent) -> placement
        let table = [
            (Enabled, true, true, false, false, CommandScope),
            (Enabled, true, true, true, false, ManagerScope),
            (Enabled, true, true, false, true, ManagerScope),
            // the server in the systemd mode: a cgroup of its tree, limits
            // or not, a scope only for the slice it is asked for
            (Enabled, true, false, false, false, NoScope),
            (Enabled, true, false, true, false, NoScope),
            (Enabled, true, false, false, true, ManagerScope),
            (Enabled, true, false, true, true, ManagerScope),
            (Enabled, false, true, false, false, NoScope),
            (Enabled, false, false, false, false, NoScope),
            (Enabled, false, false, true, true, NoScope),
            (NoConmon, true, true, false, false, CommandScope),
            (NoConmon, true, true, true, false, ManagerScope),
            (NoConmon, true, false, true, false, NoScope),
            (NoConmon, false, true, false, false, NoScope),
            (Disabled, true, true, false, false, Untouched),
            (Disabled, true, false, true, true, Untouched),
            (Disabled, false, true, false, false, Untouched),
        ];
        for (mode, manager, command, limits, parent, want) in table {
            assert_eq!(
                placement(mode, manager, command, limits, parent),
                want,
                "{mode:?} manager={manager} command={command} limits={limits} parent={parent}"
            );
        }
    }

    const ID: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[test]
    fn the_scope_of_a_container_is_below_the_slice_of_the_manager() {
        let own = "/user.slice/user-1002.slice/user@1002.service/app.slice/tmux-spawn-1.scope";
        assert_eq!(
            scope_cgroup_path(own, 1002, false, ID).as_deref(),
            Some(format!("/user.slice/user-1002.slice/user@1002.service/user.slice/velarx-{ID}.scope/container").as_str())
        );
        // a session outside the user's manager has no slice of its own
        assert_eq!(
            scope_cgroup_path(
                "/user.slice/user-1002.slice/session-3.scope",
                1002,
                false,
                ID
            ),
            None
        );
        // the manager of another user is not ours
        assert_eq!(scope_cgroup_path(own, 1000, false, ID), None);
        assert_eq!(
            scope_cgroup_path("/system.slice/x.service", 0, true, ID).as_deref(),
            Some(format!("/machine.slice/velarx-{ID}.scope/container").as_str())
        );
    }

    #[test]
    fn only_the_scopes_of_the_command_are_recognised() {
        let path = format!("/a/user.slice/velarx-{ID}.scope/container");
        assert_eq!(
            engine_scope_dir(&path),
            Some(format!("/a/user.slice/velarx-{ID}.scope").as_str())
        );
        for other in [
            format!("/a/app.slice/{ID}"),
            format!("/a/velarx-{ID}/container"),
            format!("user.slice:velarx:{ID}"),
            "/a/velarx-abc.scope/container".to_string(),
            format!("/a/velarx-{ID}.scope/monitor"),
            format!("/a/velarx-payload-{}", &ID[..12]),
        ] {
            assert_eq!(engine_scope_dir(&other), None, "{other}");
        }
        // a scope of the command is not one of the runtime's (systemd) paths
        assert!(!is_systemd_path(&path));
        assert!(!monitor_needs_scope(CgroupsMode::Unset, Some(&path)));
    }

    #[test]
    fn only_a_runtime_with_crun_options_can_run_without_a_cgroup() {
        use velarx_base::testing::{CRUN_FEATURES, KRUN_FEATURES, RUNC_FEATURES};
        let dir = tempfile::tempdir().unwrap();
        // (a name says nothing: crun copied as myruntime can, a runc named
        // crun cannot; a runtime with no `features` has none of the options)
        let features_without_run_oci = r#"{"potentiallyUnsafeConfigAnnotations":["bundle"]}"#;
        for (name, features, ok) in [
            ("myruntime", Some(CRUN_FEATURES), true),
            ("krun", Some(KRUN_FEATURES), true),
            ("crun", Some(RUNC_FEATURES), false),
            ("runc", Some(RUNC_FEATURES), false),
            ("custom", Some(features_without_run_oci), false),
            ("garbage", Some("not json"), false),
            ("empty", Some(""), false),
            ("crun-1.30", None, false),
        ] {
            let path = runtime(dir.path(), name, features);
            assert_eq!(runtime_can_disable_cgroups(&path), ok, "{name}");
        }
        assert!(!runtime_can_disable_cgroups(&dir.path().join("missing")));
    }

    #[test]
    fn settings_that_need_a_cgroup() {
        use velarx_wire::request::ResourceLimits;
        let req = |f: &dyn Fn(&mut CreateContainerRequest)| {
            let mut r = CreateContainerRequest::default();
            f(&mut r);
            cgroup_settings(&r)
        };
        let res = |f: &dyn Fn(&mut ResourceLimits)| {
            req(&|r| {
                let mut l = ResourceLimits::default();
                f(&mut l);
                r.resources = Some(l);
            })
        };
        assert!(req(&|_| {}).is_empty());
        // (the size of /dev/shm, ulimits, the OOM score and devices are not)
        assert!(res(&|l| l.shm_size = Some(1)).is_empty());
        assert!(req(&|r| r.oom_score_adj = Some(5)).is_empty());
        assert_eq!(req(&|r| r.pids_limit = Some(5)), ["--pids-limit"]);
        assert_eq!(req(&|r| r.oom_kill_disable = true), ["--oom-kill-disable"]);
        assert_eq!(
            req(&|r| r.device_cgroup_rules = vec!["c *:* rwm".into()]),
            ["--device-cgroup-rule"]
        );
        assert_eq!(res(&|l| l.memory = Some(1)), ["--memory"]);
        assert_eq!(res(&|l| l.cpu_shares = Some(1)), ["--cpu-shares"]);
        assert_eq!(
            res(&|l| l.cpuset_mems = Some("0".into())),
            ["--cpuset-mems"]
        );
        assert_eq!(
            res(&|l| {
                l.memory = Some(1);
                l.device_write_iops = Some("/dev/x:1".into());
            }),
            ["--memory", "--device-write-iops"]
        );
    }

    #[test]
    fn a_split_moves_the_processes_and_enables_the_controllers() {
        // A fake hierarchy: files instead of the kernel's.
        let root = tempfile::tempdir().unwrap();
        let unit = root.path().join("app.slice/web.service");
        std::fs::create_dir_all(&unit).unwrap();
        std::fs::write(unit.join("cgroup.procs"), "").unwrap();
        std::fs::write(unit.join("cgroup.controllers"), "cpu memory pids hugetlb\n").unwrap();
        std::fs::write(unit.join("cgroup.subtree_control"), "").unwrap();
        let got = split_cgroup(root.path(), "/app.slice/web.service").unwrap();
        assert_eq!(got, "/app.slice/web.service");
        assert!(unit.join("runtime").is_dir());
        // The last write of the fake file: the last controller of the list
        // that the cgroup has (`cpu` and `cpuset` of the list do not take
        // each other's place).
        assert_eq!(
            std::fs::read_to_string(unit.join("cgroup.subtree_control")).unwrap(),
            "+hugetlb"
        );
        // From the runtime of a split cgroup, the same cgroup.
        let again = split_cgroup(root.path(), "/app.slice/web.service/runtime").unwrap();
        assert_eq!(again, "/app.slice/web.service");
        assert!(split_cgroup(root.path(), "/").is_err());
    }
}
