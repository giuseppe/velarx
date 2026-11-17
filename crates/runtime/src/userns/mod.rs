// SPDX-License-Identifier: Apache-2.0
use crate::container::IdMapping;
use std::collections::HashMap;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
use std::path::Path;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use velarx_base::idmap::{self, IdSet, Kind, UsernsSpec};
use velarx_config::UserNamespaceConfig;
use velarx_db::{Database, UsernsAllocation as DbUsernsAllocation};
use velarx_wire::request::UsernsChoice;

pub mod rootless;
pub mod tree;

use thiserror::Error;
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

/// A detached clone of the mount of `source` (open_tree with
/// OPEN_TREE_CLONE), mapped with the ids of the user namespace `userns`.
pub fn create_idmapped_mount_fd(source: &Path, userns: BorrowedFd<'_>) -> std::io::Result<OwnedFd> {
    let tree = rustix::mount::open_tree(
        rustix::fs::CWD,
        source,
        rustix::mount::OpenTreeFlags::OPEN_TREE_CLONE
            | rustix::mount::OpenTreeFlags::OPEN_TREE_CLOEXEC,
    )?;
    idmap_mount(tree.as_fd(), userns)?;
    debug!(
        "Created idmapped mount fd for {:?} (userns_fd={})",
        source,
        userns.as_raw_fd()
    );
    Ok(tree)
}

/// Give the detached mount `mount` (from fsmount or open_tree) the
/// mapping of the user namespace `userns`, before it is attached anywhere.
pub fn idmap_mount(mount: BorrowedFd<'_>, userns: BorrowedFd<'_>) -> std::io::Result<()> {
    velarx_sys::mount::setattr_fd(
        mount,
        &velarx_sys::mount::MountAttr {
            attr_set: velarx_sys::mount::ATTR_IDMAP,
            userns_fd: userns.as_raw_fd() as u64,
            ..Default::default()
        },
    )
}

/// Create a user namespace with the specified UID/GID mappings.
///
/// This uses clone(CLONE_NEWUSER) to create a child process directly in a new
/// user namespace. The parent (still in the initial namespace with CAP_SYS_ADMIN)
/// then writes the uid_map and gid_map for the child. The child just pauses
/// until killed, keeping the namespace alive.
///
/// # Arguments
/// * `uid_mappings` - List of (container_id, host_id, count) tuples for UID mapping
/// * `gid_mappings` - List of (container_id, host_id, count) tuples for GID mapping
///
/// # Returns
/// An OwnedFd for the user namespace
pub fn create_userns_for_idmap(
    uid_mappings: &[(u32, u32, u32)],
    gid_mappings: &[(u32, u32, u32)],
) -> std::io::Result<OwnedFd> {
    // The child is born in the new user namespace (not fork + unshare): the
    // parent stays in the original one, where it may write the child's maps.
    let pid = velarx_sys::ns::start_user_namespace_holder()?;

    // the child is killed and reaped whatever happens below
    struct Child(libc::pid_t);
    impl Drop for Child {
        fn drop(&mut self) {
            let _ = velarx_sys::process::kill(self.0, libc::SIGKILL);
            let _ = velarx_sys::process::wait_exit_code(self.0);
        }
    }
    let child = Child(pid);

    // the descriptor keeps the namespace alive once the child is gone
    let ns_fd = OwnedFd::from(std::fs::File::open(format!("/proc/{pid}/ns/user"))?);

    // the parent has CAP_SYS_ADMIN, so it can write any mapping
    let map = |mappings: &[(u32, u32, u32)]| -> String {
        mappings
            .iter()
            .map(|(container_id, host_id, count)| format!("{container_id} {host_id} {count}\n"))
            .collect()
    };
    std::fs::write(format!("/proc/{pid}/uid_map"), map(uid_mappings))
        .inspect_err(|e| warn!("Failed to write uid_map: {e}"))?;
    std::fs::write(format!("/proc/{pid}/gid_map"), map(gid_mappings))
        .inspect_err(|e| warn!("Failed to write gid_map: {e}"))?;
    drop(child);

    debug!(
        "Created user namespace with mappings: uid={:?}, gid={:?}",
        uid_mappings, gid_mappings
    );

    Ok(ns_fd)
}

#[derive(Error, Debug)]
pub enum UsernsError {
    #[error("{0}")]
    NoAvailableRanges(String),
    #[error(transparent)]
    Database(#[from] velarx_types::DbError),
    #[error("parse error: {0}")]
    Parse(String),
    #[error("{0}")]
    IdMap(#[from] idmap::IdMapError),
    #[error("{0}")]
    Unsupported(String),
}

pub type UsernsResult<T> = Result<T, UsernsError>;

/// A range of ids of the configuration: `START-END`, both included.
#[derive(Debug, Clone)]
pub struct IdRange {
    pub start: u32,
    pub count: u32,
}

impl IdRange {
    pub fn parse(s: &str) -> UsernsResult<Self> {
        let parts: Vec<&str> = s.split('-').collect();
        if parts.len() != 2 {
            return Err(UsernsError::Parse(format!("Invalid range format: {}", s)));
        }

        let start: u32 = parts[0]
            .parse()
            .map_err(|e| UsernsError::Parse(format!("Invalid start: {}", e)))?;
        let end: u32 = parts[1]
            .parse()
            .map_err(|e| UsernsError::Parse(format!("Invalid end: {}", e)))?;

        if end <= start || end == u32::MAX {
            return Err(UsernsError::Parse(format!(
                "End must be greater than start and a valid id: {}",
                s
            )));
        }

        Ok(Self {
            start,
            count: end - start + 1,
        })
    }
}

#[derive(Debug, Clone)]
pub struct UsernsAllocationInfo {
    pub id: String,
    pub label: Option<String>,
    pub uid_start: u32,
    pub uid_count: u32,
    pub gid_start: u32,
    pub gid_count: u32,
    pub container_id: Option<String>,
}

/// The user namespace of the daemon as its `/proc/self/{uid,gid}_map` says:
/// the ids a container may use as parent ids.
#[derive(Debug, Clone)]
pub struct DaemonIds {
    /// `container_id` is the id inside the namespace, `host_id` the one outside
    pub uid_map: Vec<IdMapping>,
    pub gid_map: Vec<IdMapping>,
}

impl DaemonIds {
    pub fn read() -> Self {
        let read = |f: &str| std::fs::read_to_string(f).map(|c| idmap::parse_proc_map(&c));
        Self {
            uid_map: read("/proc/self/uid_map").unwrap_or_default(),
            gid_map: read("/proc/self/gid_map").unwrap_or_default(),
        }
    }

    fn map(&self, gid: bool) -> &[IdMapping] {
        if gid {
            &self.gid_map
        } else {
            &self.uid_map
        }
    }

    /// Whether the daemon runs in a user namespace other than the initial one.
    pub fn is_nested(&self) -> bool {
        self.uid_map.as_slice()
            != [IdMapping {
                container_id: 0,
                host_id: 0,
                size: u32::MAX,
            }]
    }

    /// The ids inside the daemon's namespace that map to something.
    pub fn granted(&self, gid: bool) -> IdSet {
        IdSet::of_container_ids(self.map(gid))
    }

    /// The id outside the namespace of its root (the user that started it).
    pub fn owner(&self, gid: bool) -> u32 {
        idmap::to_parent(self.map(gid), 0).unwrap_or(0)
    }

    /// The number of sub ids: the ids `1..` that are mapped without a gap.
    pub fn sub_ids(&self, gid: bool) -> u32 {
        let g = self.granted(gid);
        g.intervals()
            .iter()
            .find(|(s, e)| *s <= 1 && 1 < *e)
            .map_or(0, |(_, e)| (e - 1).min(u64::from(u32::MAX)) as u32)
    }
}

/// What a container asks of its user namespace.
#[derive(Debug, Default, Clone)]
pub struct UsernsRequest {
    /// the value of `--userns`
    pub mode: UsernsChoice,
    /// raw `--uidmap` / `--gidmap` values
    pub uidmap: Vec<String>,
    pub gidmap: Vec<String>,
    /// mappings already parsed (the API)
    pub uid_mappings: Vec<IdMapping>,
    pub gid_mappings: Vec<IdMapping>,
    pub subuidname: Option<String>,
    pub subgidname: Option<String>,
    /// the highest id the image uses, plus one, for the size of `auto`
    pub image_max_id: u32,
}

/// The user namespace of a container.
#[derive(Debug)]
pub struct Resolved {
    /// `host`, `private`, `auto`, `keep-id`, `nomap`, `custom`, `ns:PATH` or
    /// `container:ID`, what the container is shown with
    pub mode: String,
    pub spec: UsernsSpec,
    pub uid_mappings: Vec<IdMapping>,
    pub gid_mappings: Vec<IdMapping>,
    /// `keep-id` runs the container as the user, unless one is given
    pub user: Option<(u32, u32)>,
    /// holds the range until the container is recorded
    pub reservation: Option<Reservation>,
}

#[derive(Default)]
struct Held {
    uid: IdSet,
    gid: IdSet,
}

/// Parent ids taken by a container that is being created.  Dropping it
/// releases them: by then the container is in the database, which is where
/// the ids in use are read from.
#[derive(Debug)]
pub struct Reservation {
    held: Arc<std::sync::Mutex<HashMap<u64, Held>>>,
    key: u64,
}

impl std::fmt::Debug for Held {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Held")
    }
}

impl Drop for Reservation {
    fn drop(&mut self) {
        // (a poisoned map is still the map: the ids must go back)
        self.held
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&self.key);
    }
}

pub struct UserNamespaceManager {
    db: Database,
    config: UserNamespaceConfig,
    ids: DaemonIds,
    subuid: PathBuf,
    subgid: PathBuf,
    held: Arc<std::sync::Mutex<HashMap<u64, Held>>>,
    next_key: AtomicU64,
    lock: Mutex<()>,
}

impl UserNamespaceManager {
    pub fn new(db: Database, config: &UserNamespaceConfig) -> Self {
        Self::with_ids(db, config, DaemonIds::read(), "/etc/subuid", "/etc/subgid")
    }

    pub fn with_ids(
        db: Database,
        config: &UserNamespaceConfig,
        ids: DaemonIds,
        subuid: impl Into<PathBuf>,
        subgid: impl Into<PathBuf>,
    ) -> Self {
        Self {
            db,
            config: config.clone(),
            ids,
            subuid: subuid.into(),
            subgid: subgid.into(),
            held: Arc::new(std::sync::Mutex::new(HashMap::new())),
            next_key: AtomicU64::new(1),
            lock: Mutex::new(()),
        }
    }

    pub fn ids(&self) -> &DaemonIds {
        &self.ids
    }

    pub fn squash_unmapped_owners(&self) -> bool {
        self.config.squash_unmapped_owners
    }

    /// The parent ids that `auto` and `private` take their ranges from: the
    /// ids of the daemon's namespace but the user's when nested; the ranges
    /// of the configuration, else the sub ids of `auto_user`, when not.
    fn pool(&self, gid: bool) -> UsernsResult<IdSet> {
        if self.ids.is_nested() {
            let pool = self
                .ids
                .granted(gid)
                .subtract(&IdSet::from_intervals([(0, 1)]));
            if pool.is_empty() {
                return Err(UsernsError::NoAvailableRanges(
                    "the daemon has only the id of its user: add the user to /etc/subuid and /etc/subgid and install newuidmap and newgidmap".into(),
                ));
            }
            return Ok(pool);
        }
        let configured = if gid {
            &self.config.gid_ranges
        } else {
            &self.config.uid_ranges
        };
        if !configured.is_empty() {
            let mut intervals = Vec::new();
            for r in configured {
                let r = IdRange::parse(r)?;
                intervals.push((u64::from(r.start), u64::from(r.start) + u64::from(r.count)));
            }
            return Ok(IdSet::from_intervals(intervals));
        }
        let path = if gid { &self.subgid } else { &self.subuid };
        let content = read_sub_ids(path)?;
        let ranges = idmap::subid_ranges(&content, Some(&self.config.auto_user), None);
        if ranges.is_empty() {
            return Err(UsernsError::NoAvailableRanges(format!(
                "no ids for automatic user namespaces: add the user `{}` to {} or set the ranges in [userns]",
                self.config.auto_user,
                path.display()
            )));
        }
        Ok(IdSet::from_intervals(
            ranges
                .into_iter()
                .map(|(s, c)| (u64::from(s), u64::from(s) + u64::from(c))),
        ))
    }

    /// The parent ids in use: by the containers, by the allocations made
    /// through the API and by the containers being created.
    async fn used(&self) -> UsernsResult<(IdSet, IdSet)> {
        let (mut uids, mut gids) = (Vec::new(), Vec::new());
        for c in self.db.list_containers(true).await? {
            // (a configuration that cannot be read has ranges nobody knows:
            // they would be handed out again)
            let cfg = serde_json::from_str::<crate::container::ContainerConfig>(&c.config)
                .map_err(|e| {
                    UsernsError::Parse(format!(
                        "cannot read the configuration of the container {}, whose ids are in \
                         use: {e}",
                        c.id
                    ))
                })?;
            uids.extend_from_slice(&cfg.uid_mappings);
            gids.extend_from_slice(&cfg.gid_mappings);
        }
        let mut uid_set = IdSet::of_host_ids(&uids);
        let mut gid_set = IdSet::of_host_ids(&gids);
        for (s, n) in self.db.get_allocated_uid_ranges().await? {
            uid_set = uid_set.union(&IdSet::from_intervals([(
                u64::from(s),
                u64::from(s) + u64::from(n),
            )]));
        }
        for (s, n) in self.db.get_allocated_gid_ranges().await? {
            gid_set = gid_set.union(&IdSet::from_intervals([(
                u64::from(s),
                u64::from(s) + u64::from(n),
            )]));
        }
        // (a poisoned map is still the map: its ids are held)
        let held = self.held.lock().unwrap_or_else(|e| e.into_inner());
        for h in held.values() {
            uid_set = uid_set.union(&h.uid);
            gid_set = gid_set.union(&h.gid);
        }
        Ok((uid_set, gid_set))
    }

    /// The first free ranges of `size` ids, reserved until the returned
    /// reservation is dropped.
    async fn allocate_range(
        &self,
        size: u32,
        extra_uid: &[IdMapping],
        extra_gid: &[IdMapping],
    ) -> UsernsResult<(Vec<IdMapping>, Vec<IdMapping>, Reservation)> {
        let _guard = self.lock.lock().await;
        let (used_uid, used_gid) = self.used().await?;
        let uid = idmap::auto_map(size, &self.pool(false)?, &used_uid, extra_uid)
            .map_err(|e| self.no_space(e, "uid", size))?;
        let gid = idmap::auto_map(size, &self.pool(true)?, &used_gid, extra_gid)
            .map_err(|e| self.no_space(e, "gid", size))?;
        let key = self.next_key.fetch_add(1, Ordering::Relaxed);
        self.held
            .lock()
            .map_err(|_| UsernsError::Parse("reservations poisoned".into()))?
            .insert(
                key,
                Held {
                    uid: IdSet::of_host_ids(&uid),
                    gid: IdSet::of_host_ids(&gid),
                },
            );
        Ok((
            uid,
            gid,
            Reservation {
                held: self.held.clone(),
                key,
            },
        ))
    }

    fn no_space(&self, e: idmap::IdMapError, what: &str, size: u32) -> UsernsError {
        match e {
            idmap::IdMapError::NoSpace(_) => UsernsError::NoAvailableRanges(format!(
                "no free range of {size} {what}s for the user namespace"
            )),
            e => e.into(),
        }
    }

    /// Work out the user namespace of a new container: parse the request,
    /// check it against the ids the daemon can give and take the ranges of
    /// `auto` and `private` (reserved in the result).
    pub async fn resolve(&self, req: &UsernsRequest) -> UsernsResult<Resolved> {
        let mut spec = UsernsSpec::resolve(&req.mode, &self.ids.uid_map, &self.ids.gid_map)?;
        let explicit = !req.uidmap.is_empty()
            || !req.gidmap.is_empty()
            || !req.uid_mappings.is_empty()
            || !req.gid_mappings.is_empty()
            || req.subuidname.is_some()
            || req.subgidname.is_some();
        let (mut uid, mut gid) = (Vec::new(), Vec::new());
        let mut user = None;
        let mut reservation = None;
        let mode;
        if explicit {
            if !matches!(spec, UsernsSpec::Host | UsernsSpec::Private) {
                return Err(UsernsError::Unsupported(
                    "--userns and --uidmap/--gidmap/--subuidname/--subgidname are mutually exclusive".into(),
                ));
            }
            (uid, gid) = self.explicit_maps(req)?;
            spec = UsernsSpec::Private;
            mode = "custom".to_string();
        } else {
            match &spec {
                UsernsSpec::Host => mode = "host".into(),
                UsernsSpec::Private => {
                    mode = "private".into();
                    let (u, g, r) = self
                        .allocate_range(self.config.allocation_size, &[], &[])
                        .await?;
                    (uid, gid, reservation) = (u, g, Some(r));
                }
                UsernsSpec::Auto(o) => {
                    mode = "auto".into();
                    let size = idmap::auto_size(
                        o.size,
                        req.image_max_id,
                        self.config.auto_min_size,
                        self.config.auto_max_size,
                    )?;
                    let (u, g, r) = self
                        .allocate_range(size, &o.uid_mappings, &o.gid_mappings)
                        .await?;
                    (uid, gid, reservation) = (u, g, Some(r));
                }
                UsernsSpec::KeepId(o) => {
                    mode = "keep-id".into();
                    self.need_nested("keep-id")?;
                    let (su, sg) = (self.ids.sub_ids(false), self.ids.sub_ids(true));
                    let (u, g) = (
                        o.uid.unwrap_or_else(|| self.ids.owner(false)),
                        o.gid.unwrap_or_else(|| self.ids.owner(true)),
                    );
                    (uid, gid) = idmap::keep_id(u, g, su, sg, o.size);
                    user = Some((u, g));
                }
                UsernsSpec::NoMap => {
                    mode = "nomap".into();
                    self.need_nested("nomap")?;
                    (uid, gid) = idmap::no_map(self.ids.sub_ids(false), self.ids.sub_ids(true))?;
                }
                UsernsSpec::Ns(p) => mode = format!("ns:{p}"),
                UsernsSpec::Container(c) => mode = format!("container:{c}"),
            }
        }
        if matches!(
            spec,
            UsernsSpec::Private | UsernsSpec::Auto(_) | UsernsSpec::KeepId(_) | UsernsSpec::NoMap
        ) {
            self.check_granted(&uid, &gid)?;
            if self.ids.is_nested() {
                uid = idmap::split_on(&uid, &self.ids.uid_map);
                gid = idmap::split_on(&gid, &self.ids.gid_map);
            }
        }
        Ok(Resolved {
            mode,
            spec,
            uid_mappings: uid,
            gid_mappings: gid,
            user,
            reservation,
        })
    }

    fn need_nested(&self, mode: &str) -> UsernsResult<()> {
        if self.ids.is_nested() {
            Ok(())
        } else {
            Err(UsernsError::Unsupported(format!(
                "--userns={mode} is for rootless containers: a daemon running as root has no user to keep"
            )))
        }
    }

    /// Every parent id of the mappings must be an id of the daemon's
    /// namespace: the kernel would refuse the others, this says why.
    fn check_granted(&self, uid: &[IdMapping], gid: &[IdMapping]) -> UsernsResult<()> {
        for (maps, gid_) in [(uid, false), (gid, true)] {
            let granted = self.ids.granted(gid_);
            idmap::validate(maps)?;
            for m in maps {
                if !granted.contains_range(u64::from(m.host_id), u64::from(m.size)) {
                    return Err(UsernsError::Unsupported(format!(
                        "the {} mapping {m} uses ids that are not mapped in the user namespace of the daemon",
                        if gid_ { "gid" } else { "uid" }
                    )));
                }
            }
        }
        Ok(())
    }

    /// `--uidmap`, `--gidmap`, `--subuidname` and `--subgidname`; one of
    /// the maps implies the other.
    fn explicit_maps(&self, req: &UsernsRequest) -> UsernsResult<(Vec<IdMapping>, Vec<IdMapping>)> {
        let nested = self.ids.is_nested();
        let mut subuid = req.subuidname.as_deref();
        let mut subgid = req.subgidname.as_deref();
        if subuid.is_none() {
            subuid = subgid;
        }
        if subgid.is_none() {
            subgid = subuid;
        }
        let (mut uid, mut gid) = (req.uid_mappings.clone(), req.gid_mappings.clone());
        if let (Some(u), Some(g)) = (subuid, subgid) {
            if nested {
                return Err(UsernsError::Unsupported(
                    "--subuidname and --subgidname are for containers run by root".into(),
                ));
            }
            uid = sub_map(&self.subuid, u)?;
            gid = sub_map(&self.subgid, g)?;
        }
        let (raw_u, raw_g) = if req.gidmap.is_empty() && !req.uidmap.is_empty() {
            (&req.uidmap, &req.uidmap)
        } else if req.uidmap.is_empty() && !req.gidmap.is_empty() {
            (&req.gidmap, &req.gidmap)
        } else {
            (&req.uidmap, &req.gidmap)
        };
        if !raw_u.is_empty() {
            uid.extend(idmap::parse_id_map(
                raw_u,
                Kind::Uid,
                &self.ids.uid_map,
                nested,
            )?);
        }
        if !raw_g.is_empty() {
            gid.extend(idmap::parse_id_map(
                raw_g,
                Kind::Gid,
                &self.ids.gid_map,
                nested,
            )?);
        }
        if gid.is_empty() {
            gid = uid.clone();
        }
        if uid.is_empty() {
            uid = gid.clone();
        }
        let (uid, gid) = (idmap::sort_and_merge(&uid), idmap::sort_and_merge(&gid));
        idmap::validate(&uid)?;
        idmap::validate(&gid)?;
        if nested {
            self.check_granted(&uid, &gid)?;
        }
        Ok((uid, gid))
    }

    /// Reserve a range (an allocation of the database that no container takes).
    pub async fn allocate(&self, label: Option<&str>) -> UsernsResult<UsernsAllocationInfo> {
        let (uid, gid, _reservation) = self
            .allocate_range(self.config.allocation_size, &[], &[])
            .await?;
        let id = velarx_base::random::uuid();
        let now = chrono::Utc::now().to_rfc3339();
        let (Some(u), Some(g), 1, 1) = (uid.first(), gid.first(), uid.len(), gid.len()) else {
            return Err(UsernsError::NoAvailableRanges(
                "no contiguous range is free".into(),
            ));
        };
        let db_alloc = DbUsernsAllocation {
            id: id.clone(),
            label: label.map(|s| s.to_string()),
            uid_start: u.host_id,
            uid_count: u.size,
            gid_start: g.host_id,
            gid_count: g.size,
            container_id: None,
            created_at: now,
        };
        self.db.insert_userns_allocation(&db_alloc).await?;
        info!(
            "Allocated user namespace {}: uid {}+{}, gid {}+{}",
            id, u.host_id, u.size, g.host_id, g.size
        );
        Ok(UsernsAllocationInfo {
            id,
            label: label.map(|s| s.to_string()),
            uid_start: u.host_id,
            uid_count: u.size,
            gid_start: g.host_id,
            gid_count: g.size,
            container_id: None,
        })
    }

    pub async fn release(&self, id: &str) -> UsernsResult<()> {
        let _guard = self.lock.lock().await;
        self.db.delete_userns_allocation(id).await?;
        info!("Released user namespace allocation {}", id);
        Ok(())
    }

    pub async fn list(&self) -> UsernsResult<Vec<UsernsAllocationInfo>> {
        let allocations = self.db.list_userns_allocations().await?;
        Ok(allocations
            .into_iter()
            .map(|a| UsernsAllocationInfo {
                id: a.id,
                label: a.label,
                uid_start: a.uid_start,
                uid_count: a.uid_count,
                gid_start: a.gid_start,
                gid_count: a.gid_count,
                container_id: a.container_id,
            })
            .collect())
    }

    /// The free ranges of `allocation_size` ids, the number of them that
    /// are free and the number of allocations in use.
    pub async fn get_available(&self) -> UsernsResult<(Vec<IdRange>, Vec<IdRange>, u32, u32)> {
        let size = u64::from(self.config.allocation_size.max(1));
        let (used_uid, used_gid) = self.used().await?;
        let windows = |pool: IdSet| -> Vec<IdRange> {
            let mut out = Vec::new();
            for &(s, e) in pool.intervals() {
                let mut at = s;
                while at + size <= e {
                    out.push(IdRange {
                        start: at as u32,
                        count: size as u32,
                    });
                    at += size;
                }
            }
            out
        };
        let uids = windows(self.pool(false)?.subtract(&used_uid));
        let gids = windows(self.pool(true)?.subtract(&used_gid));
        let total_available = uids.len() as u32;
        let total_allocated = self.db.get_allocated_uid_ranges().await?.len() as u32;
        Ok((uids, gids, total_available, total_allocated))
    }
}

/// The mappings of the user namespace `/proc/PID/ns/user`, as the container
/// ids and the ids of the daemon's namespace they map to.
pub fn maps_of_namespace(path: &str) -> UsernsResult<(Vec<IdMapping>, Vec<IdMapping>)> {
    let pid = path
        .strip_prefix("/proc/")
        .and_then(|p| p.strip_suffix("/ns/user"))
        .filter(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
        .ok_or_else(|| {
            UsernsError::Unsupported(format!(
                "the mappings of the user namespace {path} are unknown: use /proc/PID/ns/user"
            ))
        })?;
    let read = |f: &str| {
        std::fs::read_to_string(format!("/proc/{pid}/{f}"))
            .map(|c| idmap::parse_proc_map(&c))
            .map_err(|e| UsernsError::Unsupported(format!("cannot read /proc/{pid}/{f}: {e}")))
    };
    Ok((read("uid_map")?, read("gid_map")?))
}

/// The text of a sub id file: empty when there is none (the user has no
/// ids then), an error for any other failure (a file that cannot be read
/// is not a file with no ids).
fn read_sub_ids(path: &Path) -> UsernsResult<String> {
    match std::fs::read_to_string(path) {
        Ok(text) => Ok(text),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(String::new()),
        Err(e) => Err(UsernsError::Unsupported(format!(
            "cannot read {}: {e}",
            path.display()
        ))),
    }
}

/// The ranges of a user in `/etc/subuid` or `/etc/subgid` as a mapping from
/// container id 0, one range after the other.
fn sub_map(path: &Path, name: &str) -> UsernsResult<Vec<IdMapping>> {
    let content = read_sub_ids(path)?;
    let ranges = idmap::subid_ranges(&content, Some(name), None);
    if ranges.is_empty() {
        return Err(UsernsError::NoAvailableRanges(format!(
            "no ids for `{name}` in {}",
            path.display()
        )));
    }
    let mut next = 0u64;
    let mut out = Vec::new();
    for (start, count) in ranges {
        out.push(IdMapping {
            container_id: next as u32,
            host_id: start,
            size: count,
        });
        next += u64::from(count);
    }
    idmap::validate(&out)?;
    Ok(out)
}
