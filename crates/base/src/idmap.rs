// SPDX-License-Identifier: Apache-2.0
//! Id mappings of user namespaces: the syntax of `--userns`, `--uidmap` and
//! the `idmap` mount option, the arithmetic on mappings and the layout of
//! the automatic ranges.  Nothing here does I/O: the callers pass what they
//! read from `/proc/self/{uid,gid}_map` and `/etc/sub{u,g}id`.
//!
//! The semantics are those of podman (`pkg/util`, `storage/userns.go`,
//! `storage/idset.go`).  A mapping is `(container id, parent id, size)`, with
//! parent ids in the namespace of the daemon: the host for a root daemon, the
//! user namespace of the daemon when rootless (where `0` is the user and `1..`
//! are the sub ids).  That is the view of the OCI runtime, which is why a
//! rootless mapping needs no composition with the daemon's.

use thiserror::Error;
use velarx_proto::modes::UsernsChoice;
use velarx_proto::pod::IdMapping;

/// Ids are 32 bits and `u32::MAX` is not a valid id: a mapping must end at
/// `u32::MAX` at the latest (`0 0 4294967295` is the identity).
pub const ID_LIMIT: u64 = u32::MAX as u64;

/// The kernel accepts this many lines in a `uid_map` (since Linux 4.15).
pub const MAX_EXTENTS: usize = 340;

#[derive(Error, Debug, PartialEq, Eq)]
pub enum IdMapError {
    #[error("{0}")]
    Invalid(String),
    #[error("the mapping {0} overlaps another one")]
    Overlap(String),
    #[error("no {0} ids are available for the user namespace")]
    NoSpace(u64),
}

pub type IdMapResult<T> = Result<T, IdMapError>;

fn invalid<T>(msg: impl Into<String>) -> IdMapResult<T> {
    Err(IdMapError::Invalid(msg.into()))
}

fn map(container_id: u64, host_id: u64, size: u64) -> IdMapping {
    // Callers only build mappings from values below `ID_LIMIT`.
    IdMapping {
        container_id: container_id as u32,
        host_id: host_id as u32,
        size: size as u32,
    }
}

/// A set of ids as sorted, disjoint and non adjacent intervals `[start, end)`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct IdSet {
    intervals: Vec<(u64, u64)>,
}

impl IdSet {
    pub fn from_intervals(intervals: impl IntoIterator<Item = (u64, u64)>) -> Self {
        let mut v: Vec<(u64, u64)> = intervals.into_iter().filter(|(s, e)| s < e).collect();
        v.sort_unstable();
        let mut out: Vec<(u64, u64)> = Vec::with_capacity(v.len());
        for (s, e) in v {
            match out.last_mut() {
                Some(last) if s <= last.1 => last.1 = last.1.max(e),
                _ => out.push((s, e)),
            }
        }
        Self { intervals: out }
    }

    /// The parent (host) ids of `maps`.
    pub fn of_host_ids(maps: &[IdMapping]) -> Self {
        Self::from_intervals(maps.iter().map(|m| {
            (
                u64::from(m.host_id),
                u64::from(m.host_id) + u64::from(m.size),
            )
        }))
    }

    /// The container ids of `maps`.
    pub fn of_container_ids(maps: &[IdMapping]) -> Self {
        Self::from_intervals(maps.iter().map(|m| {
            (
                u64::from(m.container_id),
                u64::from(m.container_id) + u64::from(m.size),
            )
        }))
    }

    pub fn intervals(&self) -> &[(u64, u64)] {
        &self.intervals
    }

    pub fn size(&self) -> u64 {
        self.intervals.iter().map(|(s, e)| e - s).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.intervals.is_empty()
    }

    #[cfg(test)]
    pub fn contains(&self, id: u64) -> bool {
        self.intervals.iter().any(|&(s, e)| s <= id && id < e)
    }

    /// Whether every id of `[start, start + len)` is in the set.
    pub fn contains_range(&self, start: u64, len: u64) -> bool {
        len == 0
            || self
                .intervals
                .iter()
                .any(|&(s, e)| s <= start && start + len <= e)
    }

    pub fn union(&self, other: &IdSet) -> IdSet {
        Self::from_intervals(self.intervals.iter().chain(&other.intervals).copied())
    }

    pub fn subtract(&self, other: &IdSet) -> IdSet {
        let mut out = Vec::new();
        for &(s, e) in &self.intervals {
            let mut start = s;
            for &(os, oe) in &other.intervals {
                if oe <= start {
                    continue;
                }
                if os >= e {
                    break;
                }
                if os > start {
                    out.push((start, os));
                }
                start = start.max(oe);
                if start >= e {
                    break;
                }
            }
            if start < e {
                out.push((start, e));
            }
        }
        IdSet { intervals: out }
    }

    /// The first `n` ids of the set (they may come from several intervals,
    /// like `findAvailable` of c/storage).
    pub fn find_available(&self, n: u64) -> IdMapResult<IdSet> {
        let mut left = n;
        let mut out = Vec::new();
        for &(s, e) in &self.intervals {
            if left == 0 {
                break;
            }
            let end = e.min(s + left);
            out.push((s, end));
            left -= end - s;
        }
        if left > 0 {
            return Err(IdMapError::NoSpace(n));
        }
        Ok(IdSet { intervals: out })
    }

    /// Pair the ids of `self` (parent ids) with the container ids in `container`,
    /// both in ascending order, until one runs out.
    pub fn zip(&self, container: &IdSet) -> Vec<IdMapping> {
        let mut out = Vec::new();
        let mut hosts = self.intervals.iter().copied();
        let mut ctrs = container.intervals.iter().copied();
        let (mut h, mut c) = (hosts.next(), ctrs.next());
        while let (Some((hs, he)), Some((cs, ce))) = (h, c) {
            let n = (he - hs).min(ce - cs);
            out.push(map(cs, hs, n));
            h = if hs + n < he {
                Some((hs + n, he))
            } else {
                hosts.next()
            };
            c = if cs + n < ce {
                Some((cs + n, ce))
            } else {
                ctrs.next()
            };
        }
        out
    }
}

/// The parent id of the container id `id`, if mapped.
pub fn to_parent(maps: &[IdMapping], id: u32) -> Option<u32> {
    maps.iter().find_map(|m| {
        let off = id.checked_sub(m.container_id).filter(|o| *o < m.size)?;
        m.host_id.checked_add(off)
    })
}

/// The container id of the parent id `id`, if mapped.
pub fn to_container(maps: &[IdMapping], id: u32) -> Option<u32> {
    maps.iter().find_map(|m| {
        let off = id.checked_sub(m.host_id).filter(|o| *o < m.size)?;
        m.container_id.checked_add(off)
    })
}

/// Cut the entries of `maps` where the extents of `parent` (the map of the
/// namespace that the new one is a child of: `container_id` inside, `host_id`
/// outside) end.  The kernel refuses a line whose parent ids are in two
/// extents of the parent's map, even when the ids are contiguous.
pub fn split_on(maps: &[IdMapping], parent: &[IdMapping]) -> Vec<IdMapping> {
    let mut cuts: Vec<u64> = parent
        .iter()
        .map(|p| u64::from(p.container_id) + u64::from(p.size))
        .collect();
    cuts.sort_unstable();
    let mut out = Vec::new();
    for m in maps {
        let (mut c, mut h, mut left) = (
            u64::from(m.container_id),
            u64::from(m.host_id),
            u64::from(m.size),
        );
        while left > 0 {
            // the next end of an extent after h, if inside this entry
            let n = cuts
                .iter()
                .find(|&&e| e > h && e - h < left)
                .map_or(left, |e| e - h);
            out.push(map(c, h, n));
            c += n;
            h += n;
            left -= n;
        }
    }
    out
}

/// Check a mapping: no empty entry, nothing past `ID_LIMIT`, no overlap in
/// the container ids or in the parent ids, at most `MAX_EXTENTS` entries.
pub fn validate(maps: &[IdMapping]) -> IdMapResult<()> {
    if maps.len() > MAX_EXTENTS {
        return invalid(format!(
            "{} id mappings, the kernel accepts {MAX_EXTENTS}",
            maps.len()
        ));
    }
    for m in maps {
        if m.size == 0 {
            return invalid(format!("the id mapping {m} is empty"));
        }
        if u64::from(m.container_id) + u64::from(m.size) > ID_LIMIT
            || u64::from(m.host_id) + u64::from(m.size) > ID_LIMIT
        {
            return invalid(format!("the id mapping {m} is past the last id"));
        }
    }
    for (i, a) in maps.iter().enumerate() {
        for b in &maps[..i] {
            let (ac, bc) = (u64::from(a.container_id), u64::from(b.container_id));
            let (ah, bh) = (u64::from(a.host_id), u64::from(b.host_id));
            let (asz, bsz) = (u64::from(a.size), u64::from(b.size));
            if (ac < bc + bsz && bc < ac + asz) || (ah < bh + bsz && bh < ah + asz) {
                return Err(IdMapError::Overlap(a.to_string()));
            }
        }
    }
    Ok(())
}

/// Sort by container id and merge the entries that continue each other.
pub fn sort_and_merge(maps: &[IdMapping]) -> Vec<IdMapping> {
    let mut sorted = maps.to_vec();
    sorted.sort_by_key(|m| m.container_id);
    let mut out: Vec<IdMapping> = Vec::with_capacity(sorted.len());
    for m in sorted {
        match out.last_mut() {
            Some(last)
                if u64::from(last.container_id) + u64::from(last.size)
                    == u64::from(m.container_id)
                    && u64::from(last.host_id) + u64::from(last.size) == u64::from(m.host_id) =>
            {
                last.size += m.size;
            }
            _ => out.push(m),
        }
    }
    out
}

/// Remove from `mapping` the parts that overlap `ext` in the container or
/// the parent ids, then add `ext` (podman `breakInsert`).
fn break_insert(mapping: &[IdMapping], ext: IdMapping) -> Vec<IdMapping> {
    let mut out = Vec::new();
    let (ec, eh, en) = (
        i64::from(ext.container_id),
        i64::from(ext.host_id),
        i64::from(ext.size),
    );
    for p in mapping {
        let (pc, ph, n) = (
            i64::from(p.container_id),
            i64::from(p.host_id),
            i64::from(p.size),
        );
        // What the extension covers of the piece, in offsets from its start.
        let mut cuts: Vec<(i64, i64)> = [(ec - pc, ec - pc + en), (eh - ph, eh - ph + en)]
            .into_iter()
            .map(|(a, b)| (a.max(0), b.min(n)))
            .filter(|(a, b)| a < b)
            .collect();
        cuts.sort_unstable();
        let mut pos = 0;
        let mut keep = |from: i64, to: i64| {
            if from < to {
                out.push(map(
                    (pc + from) as u64,
                    (ph + from) as u64,
                    (to - from) as u64,
                ));
            }
        };
        for (a, b) in cuts {
            keep(pos, a);
            pos = pos.max(b);
        }
        keep(pos, n);
    }
    out.push(ext);
    out
}

/// Give the container ids that `idmap` leaves unmapped, starting from zero,
/// the parent ids of `available` in order (podman `fillIDMap`).
fn fill(idmap: &[IdMapping], available: &IdSet) -> Vec<IdMapping> {
    let free = IdSet::from_intervals([(0, ID_LIMIT)]).subtract(&IdSet::of_container_ids(idmap));
    let mut out = idmap.to_vec();
    out.extend(available.zip(&free));
    sort_and_merge(&out)
}

/// uid or gid: the entries of a `--uidmap` that apply to one of them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Uid,
    Gid,
}

fn parse_u32(s: &str, what: &str, spec: &str) -> IdMapResult<u32> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return invalid(format!("invalid {what} `{s}` in the id mapping `{spec}`"));
    }
    s.parse().or_else(|_| {
        invalid(format!(
            "the {what} `{s}` of the id mapping `{spec}` is too big"
        ))
    })
}

/// The parent ids `[start, start + len)` of the outside of the daemon's
/// namespace, as ids inside it, as one mapping per run of `parent`.
/// `parent` maps ids inside (`container_id`) to ids outside (`host_id`).
fn outside_to_inside(
    parent: &[IdMapping],
    start: u64,
    len: u64,
    spec: &str,
) -> IdMapResult<Vec<(u64, u64)>> {
    let mut out = Vec::new();
    let mut at = start;
    let end = start + len;
    while at < end {
        let Some(m) = parent
            .iter()
            .find(|m| u64::from(m.host_id) <= at && at < u64::from(m.host_id) + u64::from(m.size))
        else {
            return invalid(format!(
                "the id {at} of the mapping `{spec}` is not mapped in the user namespace of the daemon"
            ));
        };
        let m_end = u64::from(m.host_id) + u64::from(m.size);
        let n = (m_end - at).min(end - at);
        out.push((u64::from(m.container_id) + (at - u64::from(m.host_id)), n));
        at += n;
    }
    Ok(out)
}

/// Parse `--uidmap` or `--gidmap` values: `[+ug]CONTAINER:[@]PARENT[:SIZE]`,
/// several triples per value allowed.  `@ID` is an id of the outside of the
/// daemon's namespace (`parent`, the content of `/proc/self/uid_map`).  A
/// leading `+` removes what the previous entries map at those ids; when
/// rootless and no mapping precedes it, the rest of the container ids are
/// mapped to all the remaining ids of the namespace.
pub fn parse_id_map(
    specs: &[String],
    kind: Kind,
    parent: &[IdMapping],
    rootless: bool,
) -> IdMapResult<Vec<IdMapping>> {
    let mut idmap: Vec<IdMapping> = Vec::new();
    let mut fill_map = false;
    for spec in specs.iter().filter(|s| !s.is_empty()) {
        let mut parts: Vec<&str> = spec.split(':').collect();
        if parts.len() == 2 {
            parts.push("1");
        }
        if !parts.len().is_multiple_of(3) || parts.iter().any(|p| p.is_empty()) {
            return invalid(format!(
                "the id mapping `{spec}` is malformed, expected `[+ug]CONTAINER:[@]PARENT[:SIZE]`"
            ));
        }
        for triple in parts.chunks(3) {
            let (mut extends, mut users, mut groups) = (false, false, false);
            let mut digits = None;
            for (i, ch) in triple[0].char_indices() {
                match ch {
                    '0'..='9' => {
                        digits = Some(i);
                        break;
                    }
                    '+' => extends = true,
                    'u' => users = true,
                    'g' => groups = true,
                    _ => return invalid(format!("unknown flag `{ch}` in the id mapping `{spec}`")),
                }
            }
            let Some(at) = digits else {
                return invalid(format!("no container id in the id mapping `{spec}`"));
            };
            if !users && !groups {
                users = true;
                groups = true;
            }
            let cid = u64::from(parse_u32(&triple[0][at..], "container id", spec)?);
            let size = u64::from(parse_u32(triple[2], "size", spec)?);
            let (relative, host) = match triple[1].strip_prefix('@') {
                Some(h) => (true, h),
                None => (false, triple[1]),
            };
            let hid = u64::from(parse_u32(host, "parent id", spec)?);
            if cid + size > ID_LIMIT || hid + size > ID_LIMIT {
                return invalid(format!("the id mapping `{spec}` is past the last id"));
            }
            let applies = match kind {
                Kind::Uid => users,
                Kind::Gid => groups,
            };
            if !applies || size == 0 {
                continue;
            }
            let mut entries = Vec::new();
            if relative {
                let mut c = cid;
                for (inside, n) in outside_to_inside(parent, hid, size, spec)? {
                    entries.push(map(c, inside, n));
                    c += n;
                }
            } else {
                entries.push(map(cid, hid, size));
            }
            for e in entries {
                if !extends {
                    idmap.push(e);
                    continue;
                }
                if idmap.is_empty() && rootless {
                    fill_map = true;
                }
                idmap = break_insert(&idmap, e);
            }
        }
    }
    if fill_map {
        let inside = IdSet::from_intervals(parent.iter().map(|m| {
            (
                u64::from(m.container_id),
                u64::from(m.container_id) + u64::from(m.size),
            )
        }));
        let available = inside.subtract(&IdSet::of_host_ids(&idmap));
        idmap = fill(&idmap, &available);
    }
    Ok(sort_and_merge(&idmap))
}

/// `uidmapping=` and `gidmapping=` of `--userns=auto`: one triple
/// `CONTAINER:[@]PARENT[:SIZE]`, without flags.
fn parse_auto_map(value: &str, parent: &[IdMapping]) -> IdMapResult<Vec<IdMapping>> {
    if value.starts_with(|c: char| !c.is_ascii_digit()) {
        return invalid(format!("the id mapping `{value}` is malformed"));
    }
    parse_id_map(&[value.to_string()], Kind::Uid, parent, false)
}

/// Options of `--userns=auto`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AutoOptions {
    /// The number of ids, otherwise the size of the image decides.
    pub size: Option<u32>,
    pub uid_mappings: Vec<IdMapping>,
    pub gid_mappings: Vec<IdMapping>,
}

/// Options of `--userns=keep-id`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct KeepIdOptions {
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub size: Option<u32>,
}

/// The value of `--userns`, its options read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UsernsSpec {
    /// No user namespace of the container (rootless: the daemon's).
    Host,
    /// A user namespace of the configured allocation size.
    Private,
    Auto(AutoOptions),
    KeepId(KeepIdOptions),
    /// The user is not mapped.
    NoMap,
    /// Join the namespace at this path.
    Ns(String),
    /// Join the namespace of this container.
    Container(String),
}

impl UsernsSpec {
    /// The namespace `choice` asks for, with its options read.  `parent` is
    /// the map of the daemon (`/proc/self/uid_map`), for the `@` ids of
    /// `auto:uidmapping=`.
    pub fn resolve(
        choice: &UsernsChoice,
        parent_uid: &[IdMapping],
        parent_gid: &[IdMapping],
    ) -> IdMapResult<Self> {
        // (the options as typed, for the messages)
        let value = choice.to_string();
        let options = |opts: &Option<String>| -> IdMapResult<Vec<(String, String)>> {
            opts.iter()
                .flat_map(|o| o.split(','))
                .map(|kv| match kv.split_once('=') {
                    Some((k, v)) => Ok((k.to_string(), v.to_string())),
                    None => invalid(format!("invalid option `{kv}` of the user namespace")),
                })
                .collect()
        };
        match choice {
            UsernsChoice::Host => Ok(Self::Host),
            UsernsChoice::Private => Ok(Self::Private),
            UsernsChoice::NoMap => Ok(Self::NoMap),
            UsernsChoice::Ns(p) => Ok(Self::Ns(p.clone())),
            UsernsChoice::Container(c) => Ok(Self::Container(c.clone())),
            UsernsChoice::KeepId(opts) => {
                let mut o = KeepIdOptions::default();
                for (k, v) in options(opts)? {
                    let n = parse_u32(&v, &k, &value)?;
                    match k.as_str() {
                        "uid" => o.uid = Some(n),
                        "gid" => o.gid = Some(n),
                        "size" => o.size = Some(n),
                        _ => return invalid(format!("unknown option `{k}` of keep-id")),
                    }
                }
                Ok(Self::KeepId(o))
            }
            UsernsChoice::Auto(opts) => {
                let mut o = AutoOptions::default();
                for (k, v) in options(opts)? {
                    match k.as_str() {
                        "size" => {
                            let n = parse_u32(&v, &k, &value)?;
                            if n == 0 {
                                return invalid("the size of the user namespace is 0");
                            }
                            o.size = Some(n);
                        }
                        "uidmapping" => o.uid_mappings.extend(parse_auto_map(&v, parent_uid)?),
                        "gidmapping" => o.gid_mappings.extend(parse_auto_map(&v, parent_gid)?),
                        _ => return invalid(format!("unknown option `{k}` of auto")),
                    }
                }
                Ok(Self::Auto(o))
            }
        }
    }
}

/// The mappings of `--userns=keep-id`: the user `uid:gid` of the daemon's
/// namespace (id `0` there) keeps its number in the container, the sub ids
/// are below and above it.  `sub_uid` and `sub_gid` are the numbers of sub
/// ids of the daemon's namespace; `size` limits the highest id.
pub fn keep_id(
    uid: u32,
    gid: u32,
    sub_uid: u32,
    sub_gid: u32,
    size: Option<u32>,
) -> (Vec<IdMapping>, Vec<IdMapping>) {
    let one = |id: u32, sub: u32| {
        let mut max = u64::from(sub);
        if let Some(s) = size.filter(|s| *s > 0) {
            max = max.min(u64::from(s) - 1);
        }
        let id = u64::from(id);
        let mut out = Vec::new();
        if sub > 0 && id != 0 && max.min(id) > 0 {
            out.push(map(0, 1, max.min(id)));
        }
        out.push(map(id, 0, 1));
        if max > id {
            out.push(map(id + 1, id + 1, max - id));
        }
        out
    };
    (one(uid, sub_uid), one(gid, sub_gid))
}

/// The mappings of `--userns=nomap`: everything but the user, from `0`.
pub fn no_map(sub_uid: u32, sub_gid: u32) -> IdMapResult<(Vec<IdMapping>, Vec<IdMapping>)> {
    if sub_uid == 0 || sub_gid == 0 {
        return invalid("nomap needs sub ids in /etc/subuid and /etc/subgid");
    }
    Ok((
        vec![map(0, 1, sub_uid.into())],
        vec![map(0, 1, sub_gid.into())],
    ))
}

/// The mappings of `--userns=auto` of `size` ids: the first free ids of
/// `pool` that `used` and the parent ids of the extra mappings do not take,
/// for the container ids that the extra mappings do not use.
pub fn auto_map(
    size: u32,
    pool: &IdSet,
    used: &IdSet,
    extra: &[IdMapping],
) -> IdMapResult<Vec<IdMapping>> {
    let target = IdSet::from_intervals([(0, u64::from(size))]);
    let wanted = target.subtract(&IdSet::of_container_ids(extra));
    let free = pool
        .subtract(used)
        .subtract(&IdSet::of_host_ids(extra))
        .find_available(wanted.size())?;
    let mut maps = free.zip(&wanted);
    maps.extend_from_slice(extra);
    let maps = sort_and_merge(&maps);
    validate(&maps)?;
    Ok(maps)
}

/// The number of ids to give to an automatic namespace: the request, else
/// at least `minimum` and enough for the ids the image uses.
pub fn auto_size(
    requested: Option<u32>,
    image_max_id: u32,
    minimum: u32,
    maximum: u32,
) -> IdMapResult<u32> {
    if let Some(s) = requested {
        return Ok(s);
    }
    let size = minimum.max(image_max_id);
    if maximum > 0 && size > maximum {
        return invalid(format!(
            "the container needs a user namespace of {size} ids, more than the maximum of {maximum} of --userns=auto"
        ));
    }
    Ok(size)
}

/// The largest id of the content of `/etc/passwd` and `/etc/group` plus one,
/// the `nobody` entries and 65534 left out (they would make every image
/// need 65536 ids).
pub fn max_id_of_passwd_group(passwd: &str, group: &str) -> u32 {
    let mut size = 0u64;
    let mut bump = |id: u64| {
        if id != 65534 {
            size = size.max(id + 1);
        }
    };
    for line in passwd.lines() {
        let f: Vec<&str> = line.split(':').collect();
        if f.len() < 4 || matches!(f[0], "nobody" | "nogroup") {
            continue;
        }
        for v in &f[2..4] {
            if let Ok(id) = v.parse::<u64>() {
                bump(id);
            }
        }
    }
    for line in group.lines() {
        let f: Vec<&str> = line.split(':').collect();
        if f.len() < 3 || matches!(f[0], "nobody" | "nogroup") {
            continue;
        }
        if let Ok(id) = f[2].parse::<u64>() {
            bump(id);
        }
    }
    size.min(ID_LIMIT) as u32
}

/// The mappings of the `idmap` option of a mount: `idmap` alone is the
/// mapping of the container, `idmap=uids=A-B-C#...;gids=...` lists
/// `CONTAINER-PARENT-SIZE` ranges, a leading `@` meaning that the second number
/// is an id of the container, which the mapping of the container turns into a
/// parent id.
pub fn parse_mount_idmap(
    option: &str,
    ctr_uid: &[IdMapping],
    ctr_gid: &[IdMapping],
) -> IdMapResult<(Vec<IdMapping>, Vec<IdMapping>)> {
    let (mut uids, mut gids) = (ctr_uid.to_vec(), ctr_gid.to_vec());
    let Some(value) = option.strip_prefix("idmap=") else {
        if option == "idmap" {
            return Ok((uids, gids));
        }
        return invalid(format!("`{option}` is not an idmap option"));
    };
    let ranges = |list: &str, ctr: &[IdMapping]| -> IdMapResult<Vec<IdMapping>> {
        list.split('#')
            .map(|r| {
                if r.is_empty() {
                    return invalid(format!("empty range in `{option}`"));
                }
                let (relative, r) = match r.strip_prefix('@') {
                    Some(r) => (true, r),
                    None => (false, r),
                };
                let n: Vec<&str> = r.split('-').collect();
                if n.len() != 3 {
                    return invalid(format!("the range `{r}` of `{option}` is not `CONTAINER-PARENT-SIZE`"));
                }
                let c = parse_u32(n[0], "container id", option)?;
                let mut h = parse_u32(n[1], "parent id", option)?;
                let size = parse_u32(n[2], "size", option)?;
                if size == 0 {
                    return invalid(format!("the range `{r}` of `{option}` is empty"));
                }
                if relative {
                    let Some(p) = to_parent(ctr, h) else {
                        return invalid(format!(
                            "the id {h} of `{option}` is not mapped in the user namespace of the container"
                        ));
                    };
                    h = p;
                }
                if u64::from(c) + u64::from(size) > ID_LIMIT
                    || u64::from(h) + u64::from(size) > ID_LIMIT
                {
                    return invalid(format!("the range `{r}` of `{option}` is past the last id"));
                }
                Ok(IdMapping {
                    container_id: c,
                    host_id: h,
                    size,
                })
            })
            .collect()
    };
    for part in value.split(';') {
        if let Some(l) = part.strip_prefix("uids=") {
            uids = ranges(l, ctr_uid)?;
        } else if let Some(l) = part.strip_prefix("gids=") {
            gids = ranges(l, ctr_gid)?;
        } else {
            return invalid(format!("unknown option `{part}` in `{option}`"));
        }
    }
    Ok((uids, gids))
}

/// Parse `/proc/self/uid_map`: `inside outside count` lines.  The result
/// has the inside ids as `container_id` and the outside ones as `host_id`.
pub fn parse_proc_map(content: &str) -> Vec<IdMapping> {
    content
        .lines()
        .filter_map(|l| {
            let mut f = l.split_whitespace().map(|v| v.parse::<u64>().ok());
            let (inside, outside, count) = (f.next()??, f.next()??, f.next()??);
            // The initial namespace maps 4294967295 ids, which the type of
            // the size holds.
            (inside.checked_add(count)? <= u64::from(u32::MAX) + 1
                && outside.checked_add(count)? <= u64::from(u32::MAX) + 1)
                .then(|| IdMapping {
                    container_id: inside as u32,
                    host_id: outside as u32,
                    size: count.min(u64::from(u32::MAX)) as u32,
                })
        })
        .collect()
}

/// The ranges `(start, count)` of `/etc/subuid` or `/etc/subgid` for a name
/// or a numeric id.
pub fn subid_ranges(content: &str, name: Option<&str>, id: Option<u32>) -> Vec<(u32, u32)> {
    let id = id.map(|i| i.to_string());
    content
        .lines()
        .filter_map(|line| {
            let mut f = line.trim().split(':');
            let who = f.next()?;
            let start: u32 = f.next()?.parse().ok()?;
            let count: u32 = f.next()?.parse().ok()?;
            let ours = Some(who) == name || Some(who) == id.as_deref();
            (ours
                && count > 0
                && !who.starts_with('#')
                && u64::from(start) + u64::from(count) <= ID_LIMIT)
                .then_some((start, count))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m(c: u32, h: u32, n: u32) -> IdMapping {
        IdMapping {
            container_id: c,
            host_id: h,
            size: n,
        }
    }

    fn strs(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    fn parse(specs: &[&str], parent: &[IdMapping]) -> Vec<IdMapping> {
        parse_id_map(&strs(specs), Kind::Uid, parent, false).unwrap()
    }

    // The cases of podman `pkg/util/utils_test.go`.

    #[test]
    fn test_break_insert() {
        let r = break_insert(&[m(1000, 1000, 1)], m(2, 2, 1));
        assert_eq!(r, [m(1000, 1000, 1), m(2, 2, 1)]);
        let r = break_insert(&[m(4, 5, 4)], m(1, 1, 3));
        assert_eq!(r, [m(4, 5, 4), m(1, 1, 3)]);
        let r = break_insert(&[m(0, 0, 20)], m(10, 1, 1));
        assert_eq!(
            sort_and_merge(&r),
            [m(0, 0, 1), m(2, 2, 8), m(10, 1, 1), m(11, 11, 9)]
        );
    }

    #[test]
    fn test_sort_and_merge() {
        assert_eq!(sort_and_merge(&[m(1, 1, 3), m(4, 4, 4)]), [m(1, 1, 7)]);
        assert_eq!(
            sort_and_merge(&[m(4, 9, 4), m(1, 1, 3)]),
            [m(1, 1, 3), m(4, 9, 4)]
        );
    }

    #[test]
    fn test_parse_id_map_relative() {
        let parent = [m(20, 1002, 1)];
        assert_eq!(parse(&["+100000:@1002:1"], &parent), [m(100000, 20, 1)]);
        // The size defaults to 1.
        assert_eq!(parse(&["+100000:@1002"], &parent), [m(100000, 20, 1)]);
        assert!(parse_id_map(&strs(&["0:@1003:1"]), Kind::Uid, &parent, false).is_err());
    }

    #[test]
    fn test_parse_id_map_extend() {
        assert_eq!(
            parse(&["0:2000:100000", "+1:100:1"], &[]),
            [m(0, 2000, 1), m(1, 100, 1), m(2, 2002, 99998)]
        );
        assert_eq!(
            parse(
                &["0:0:20", "24:24:6", "+7:1000:2", "+12:2000:3", "+18:3000:7"],
                &[]
            ),
            [
                m(0, 0, 7),
                m(7, 1000, 2),
                m(9, 9, 3),
                m(12, 2000, 3),
                m(15, 15, 3),
                m(18, 3000, 7),
                m(25, 25, 5)
            ]
        );
        assert_eq!(
            parse(&["0:0:20", "+10:1:1"], &[]),
            [m(0, 0, 1), m(2, 2, 8), m(10, 1, 1), m(11, 11, 9)]
        );
        assert_eq!(
            parse(&["0:20:10", "15:35:10", "+8:23:16"], &[]),
            [m(0, 20, 3), m(8, 23, 16), m(24, 44, 1)]
        );
    }

    #[test]
    fn test_parse_id_map_user_group_flags() {
        let specs = strs(&["u1:3:1", "g2:4:2"]);
        assert_eq!(
            parse_id_map(&specs, Kind::Uid, &[], false).unwrap(),
            [m(1, 3, 1)]
        );
        assert_eq!(
            parse_id_map(&specs, Kind::Gid, &[], false).unwrap(),
            [m(2, 4, 2)]
        );
    }

    #[test]
    fn test_parse_id_map_several_triples_in_a_value() {
        assert_eq!(
            parse(&["0:1:10:10:0:1:11:11:5"], &[]),
            [m(0, 1, 10), m(10, 0, 1), m(11, 11, 5)]
        );
    }

    #[test]
    fn test_parse_id_map_errors() {
        for bad in [
            "1",
            "a:b:c",
            "0:1:2:3",
            "0::1",
            "0:1:x",
            "-1:0:1",
            "x0:1:1",
            "0:1:4294967296",
            "4294967294:0:2",
            "0:4294967294:2",
            "+:1:1",
        ] {
            assert!(
                parse_id_map(&strs(&[bad]), Kind::Uid, &[], false).is_err(),
                "{bad}"
            );
        }
    }

    #[test]
    fn test_fill_rootless() {
        // `+0:@1000:1` of a rootless user: 0 is the user, the rest the sub ids.
        let parent = [m(0, 1000, 1), m(1, 100000, 65536)];
        let r = parse_id_map(&strs(&["+0:@1000:1"]), Kind::Uid, &parent, true).unwrap();
        // The entries that continue each other are one.
        assert_eq!(r, [m(0, 0, 65537)]);
        // Not rootless: no fill.
        let r = parse_id_map(&strs(&["+0:@1000:1"]), Kind::Uid, &parent, false).unwrap();
        assert_eq!(r, [m(0, 0, 1)]);
    }

    #[test]
    fn test_fill_id_map() {
        let avail = IdSet::from_intervals([(0, 10), (10000, 20000)]);
        let r = fill(&[m(1, 1000, 10), m(30, 2000, 20)], &avail);
        assert_eq!(
            r,
            [
                m(0, 0, 1),
                m(1, 1000, 10),
                m(11, 1, 9),
                m(20, 10000, 10),
                m(30, 2000, 20),
                m(50, 10010, 9990)
            ]
        );
    }

    #[test]
    fn test_available_ranges() {
        let all = IdSet::from_intervals([(0, 30), (50, 70)]);
        let used = IdSet::from_intervals([(2, 4), (25, 55)]);
        assert_eq!(all.subtract(&used).intervals(), [(0, 2), (4, 25), (55, 70)]);
    }

    #[test]
    fn test_find_available_spans_intervals() {
        let s = IdSet::from_intervals([(0, 2), (10, 20)]);
        assert_eq!(s.find_available(5).unwrap().intervals(), [(0, 2), (10, 13)]);
        assert_eq!(s.find_available(12).unwrap().size(), 12);
        assert_eq!(s.find_available(13), Err(IdMapError::NoSpace(13)));
        assert_eq!(
            s.find_available(5)
                .unwrap()
                .zip(&IdSet::from_intervals([(0, 5)])),
            [m(0, 0, 2), m(2, 10, 3)]
        );
    }

    #[test]
    fn test_mode_parsing() {
        let p = |v: &str| -> Result<UsernsSpec, String> {
            let choice = UsernsChoice::parse(v).map_err(|e| e.to_string())?;
            UsernsSpec::resolve(&choice, &[], &[]).map_err(|e| e.to_string())
        };
        assert_eq!(p("").unwrap(), UsernsSpec::Host);
        assert_eq!(p("host").unwrap(), UsernsSpec::Host);
        assert_eq!(p("private").unwrap(), UsernsSpec::Private);
        assert_eq!(p("nomap").unwrap(), UsernsSpec::NoMap);
        assert_eq!(
            p("keep-id").unwrap(),
            UsernsSpec::KeepId(KeepIdOptions::default())
        );
        assert_eq!(
            p("keep-id:uid=200,gid=210,size=1000").unwrap(),
            UsernsSpec::KeepId(KeepIdOptions {
                uid: Some(200),
                gid: Some(210),
                size: Some(1000)
            })
        );
        assert_eq!(p("auto").unwrap(), UsernsSpec::Auto(AutoOptions::default()));
        assert_eq!(
            p("auto:size=500").unwrap(),
            UsernsSpec::Auto(AutoOptions {
                size: Some(500),
                ..Default::default()
            })
        );
        assert_eq!(
            p("auto:size=500,uidmapping=100:2000:5,gidmapping=100:3000:5").unwrap(),
            UsernsSpec::Auto(AutoOptions {
                size: Some(500),
                uid_mappings: vec![m(100, 2000, 5)],
                gid_mappings: vec![m(100, 3000, 5)],
            })
        );
        assert_eq!(
            p("ns:/proc/12/ns/user").unwrap(),
            UsernsSpec::Ns("/proc/12/ns/user".into())
        );
        assert_eq!(
            p("container:web").unwrap(),
            UsernsSpec::Container("web".into())
        );
        for bad in [
            "bogus",
            "auto:bogus",
            "auto:size=0",
            "auto:size=x",
            "auto:foo=1",
            "keep-id:uid",
            "keep-id:foo=1",
            "ns:relative",
            "ns:",
            "container:",
            "host:1",
            "private:x",
            "auto:uidmapping=@1:1:1:1",
        ] {
            assert!(p(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn test_auto_mapping_relative() {
        let parent = [m(0, 1000, 1), m(1, 100000, 65536)];
        let choice = UsernsChoice::parse("auto:uidmapping=100:@100000:1").unwrap();
        let s = UsernsSpec::resolve(&choice, &parent, &[]).unwrap();
        assert_eq!(
            s,
            UsernsSpec::Auto(AutoOptions {
                size: None,
                uid_mappings: vec![m(100, 1, 1)],
                gid_mappings: vec![],
            })
        );
    }

    // The cases of `getRootlessKeepIDMapping`.

    #[test]
    fn test_keep_id() {
        // Without sub ids only the user is mapped.
        let (u, g) = keep_id(1000, 1000, 0, 0, None);
        assert_eq!((u, g), (vec![m(1000, 0, 1)], vec![m(1000, 0, 1)]));
        // The usual rootless user.
        let (u, _) = keep_id(1000, 1000, 65536, 65536, None);
        assert_eq!(u, [m(0, 1, 1000), m(1000, 0, 1), m(1001, 1001, 64536)]);
        let (u, g) = keep_id(2000, 3000, 65536, 65536, None);
        assert_eq!(u, [m(0, 1, 2000), m(2000, 0, 1), m(2001, 2001, 63536)]);
        assert_eq!(g, [m(0, 1, 3000), m(3000, 0, 1), m(3001, 3001, 62536)]);
        // Root keeps 0.
        let (u, _) = keep_id(0, 0, 65536, 65536, None);
        assert_eq!(u, [m(0, 0, 1), m(1, 1, 65536)]);
        let (u, _) = keep_id(0, 0, 65536, 65536, Some(1024));
        assert_eq!(u, [m(0, 0, 1), m(1, 1, 1023)]);
        let (u, _) = keep_id(0, 0, 65536, 65536, Some(1));
        assert_eq!(u, [m(0, 0, 1)]);
        let (u, _) = keep_id(0, 0, 65536, 65536, Some(2));
        assert_eq!(u, [m(0, 0, 1), m(1, 1, 1)]);
        // A size below the user: no empty entry.
        let (u, _) = keep_id(1000, 1000, 65536, 65536, Some(1));
        assert_eq!(u, [m(1000, 0, 1)]);
        let (u, _) = keep_id(1000, 1000, 65536, 65536, Some(1000000));
        assert_eq!(u, [m(0, 1, 1000), m(1000, 0, 1), m(1001, 1001, 64536)]);
        for (u, g) in [
            keep_id(1000, 1000, 65536, 65536, None),
            keep_id(1000, 0, 5, 7, Some(3)),
        ] {
            validate(&u).unwrap();
            validate(&g).unwrap();
        }
    }

    #[test]
    fn test_no_map() {
        let (u, g) = no_map(65536, 1000).unwrap();
        assert_eq!((u, g), (vec![m(0, 1, 65536)], vec![m(0, 1, 1000)]));
        assert!(no_map(0, 10).is_err());
        assert!(no_map(10, 0).is_err());
    }

    #[test]
    fn test_auto_map() {
        // Rootless: the ids 1..=65536 of the namespace.
        let pool = IdSet::from_intervals([(1, 65537)]);
        let none = IdSet::default();
        let first = auto_map(1024, &pool, &none, &[]).unwrap();
        assert_eq!(first, [m(0, 1, 1024)]);
        let used = IdSet::of_host_ids(&first);
        let second = auto_map(2000, &pool, &used, &[]).unwrap();
        assert_eq!(second, [m(0, 1025, 2000)]);
        // The range of the first container is free again.
        let used = IdSet::of_host_ids(&second);
        assert_eq!(auto_map(100, &pool, &used, &[]).unwrap(), [m(0, 1, 100)]);
        // A hole is used with what follows it.
        let used = IdSet::from_intervals([(1, 11), (21, 40000)]);
        assert_eq!(
            auto_map(30, &pool, &used, &[]).unwrap(),
            [m(0, 11, 10), m(10, 40000, 20)]
        );
        // Not enough ids.
        let used = IdSet::from_intervals([(1, 65000)]);
        assert_eq!(
            auto_map(1024, &pool, &used, &[]),
            Err(IdMapError::NoSpace(1024))
        );
        // Root: the sub ids of `containers`.
        let pool = IdSet::from_intervals([(786432, 786432 + 65536)]);
        assert_eq!(
            auto_map(65536, &pool, &none, &[]).unwrap(),
            [m(0, 786432, 65536)]
        );
    }

    #[test]
    fn test_auto_map_with_extra_mappings() {
        let pool = IdSet::from_intervals([(1, 100)]);
        // Container id 5 is mapped by hand to parent id 2: the automatic range
        // takes neither.
        let extra = [m(5, 2, 1)];
        let r = auto_map(10, &pool, &IdSet::default(), &extra).unwrap();
        assert_eq!(r, [m(0, 1, 1), m(1, 3, 4), m(5, 2, 1), m(6, 7, 4)]);
        validate(&r).unwrap();
    }

    #[test]
    fn test_auto_size() {
        assert_eq!(auto_size(Some(10), 100000, 1024, 65536), Ok(10));
        assert_eq!(auto_size(None, 0, 1024, 65536), Ok(1024));
        assert_eq!(auto_size(None, 2000, 1024, 65536), Ok(2000));
        assert!(auto_size(None, 70000, 1024, 65536).is_err());
        assert_eq!(auto_size(None, 70000, 1024, 0), Ok(70000));
    }

    #[test]
    fn test_max_id_of_passwd_group() {
        let passwd = "root:x:0:0::/root:/bin/sh\nnobody:x:65534:65534::/:/sbin/nologin\n\
                      app:x:1500:1600::/app:/bin/sh\nbad\n";
        let group = "root:x:0:\nnogroup:x:65533:\nstaff:x:2000:app\n";
        assert_eq!(max_id_of_passwd_group(passwd, group), 2001);
        assert_eq!(max_id_of_passwd_group("", ""), 0);
        assert_eq!(max_id_of_passwd_group("x:x:65534:65534::/:/bin/sh", ""), 0);
    }

    #[test]
    fn test_split_on_extents_of_the_parent() {
        let parent = [m(0, 1000, 1), m(1, 100000, 65536)];
        assert_eq!(
            split_on(&[m(0, 0, 65537)], &parent),
            [m(0, 0, 1), m(1, 1, 65536)]
        );
        assert_eq!(split_on(&[m(0, 1, 100)], &parent), [m(0, 1, 100)]);
        assert_eq!(split_on(&[m(5, 0, 3)], &parent), [m(5, 0, 1), m(6, 1, 2)]);
        // The initial namespace has one extent.
        assert_eq!(
            split_on(&[m(0, 5, 100)], &[m(0, 0, u32::MAX)]),
            [m(0, 5, 100)]
        );
    }

    #[test]
    fn test_validate() {
        validate(&[m(0, 1, 10), m(10, 0, 1)]).unwrap();
        assert!(matches!(
            validate(&[m(0, 1, 10), m(5, 100, 1)]),
            Err(IdMapError::Overlap(_))
        ));
        assert!(matches!(
            validate(&[m(0, 1, 10), m(20, 5, 1)]),
            Err(IdMapError::Overlap(_))
        ));
        assert!(validate(&[m(0, 1, 0)]).is_err());
        assert!(validate(&[m(4294967290, 0, 10)]).is_err());
        assert!(validate(&[m(0, 4294967295, 1)]).is_err());
        validate(&[m(0, 0, 4294967295)]).unwrap();
        let many: Vec<_> = (0..341).map(|i| m(i * 2, i * 2, 1)).collect();
        assert!(validate(&many).is_err());
        validate(&many[..340]).unwrap();
    }

    #[test]
    fn test_to_parent_and_back() {
        let maps = [m(0, 100000, 65536), m(65536, 5, 1)];
        assert_eq!(to_parent(&maps, 5), Some(100005));
        assert_eq!(to_parent(&maps, 65536), Some(5));
        assert_eq!(to_parent(&maps, 65537), None);
        assert_eq!(to_container(&maps, 100005), Some(5));
        assert_eq!(to_container(&maps, 5), Some(65536));
        assert_eq!(to_container(&maps, 6), None);
        assert_eq!(to_parent(&[], 7), None);
    }

    #[test]
    fn test_mount_idmap() {
        let ctr_u = [m(0, 1, 1000), m(1000, 0, 1)];
        let ctr_g = [m(0, 1, 1000), m(1000, 0, 1)];
        // Plain: the mapping of the container.
        let (u, g) = parse_mount_idmap("idmap", &ctr_u, &ctr_g).unwrap();
        assert_eq!((u, g), (ctr_u.to_vec(), ctr_g.to_vec()));
        // Explicit ranges.
        let (u, g) =
            parse_mount_idmap("idmap=uids=0-1000-1#1-0-1;gids=0-5-3", &ctr_u, &ctr_g).unwrap();
        assert_eq!(u, [m(0, 1000, 1), m(1, 0, 1)]);
        assert_eq!(g, [m(0, 5, 3)]);
        // Only uids given: the gids are those of the container.
        let (_, g) = parse_mount_idmap("idmap=uids=0-0-1", &ctr_u, &ctr_g).unwrap();
        assert_eq!(g, ctr_g.to_vec());
        // `@`: the second number is a container id.
        let (u, _) = parse_mount_idmap("idmap=uids=@0-1000-1#@1-1-1", &ctr_u, &ctr_g).unwrap();
        assert_eq!(u, [m(0, 0, 1), m(1, 2, 1)]);
        for bad in [
            "idmap=",
            "idmap=uids=",
            "idmap=uids=1-2",
            "idmap=uids=1-2-0",
            "idmap=foo=1-2-3",
            "idmap=uids=@1-5000-1",
            "idmap=uids=x-1-1",
            "idmap=uids=4294967295-0-1",
            "bind",
        ] {
            assert!(parse_mount_idmap(bad, &ctr_u, &ctr_g).is_err(), "{bad}");
        }
    }

    #[test]
    fn test_proc_map() {
        let initial = parse_proc_map("         0          0 4294967295\n");
        assert_eq!(initial, [m(0, 0, 4294967295)]);
        let rootless = parse_proc_map("0 1002 1\n1 655360 65536\n");
        assert_eq!(rootless, [m(0, 1002, 1), m(1, 655360, 65536)]);
        assert!(parse_proc_map("garbage\n0 1\n").is_empty());
    }

    #[test]
    fn test_subid_ranges() {
        let c = "alice:100000:65536\n1002:655360:65536\n# comment\nbob:1:2\nalice:200000:10\n\
                 bad:x:1\nbig:4294967000:1000\n";
        assert_eq!(
            subid_ranges(c, Some("alice"), Some(1000)),
            [(100000, 65536), (200000, 10)]
        );
        assert_eq!(
            subid_ranges(c, Some("carol"), Some(1002)),
            [(655360, 65536)]
        );
        assert!(subid_ranges(c, Some("carol"), Some(1003)).is_empty());
        assert!(subid_ranges(c, Some("big"), None).is_empty());
        assert!(subid_ranges("alice:5:0", Some("alice"), None).is_empty());
    }

    #[test]
    fn test_outside_to_inside_spans_runs() {
        let parent = [m(0, 1000, 1), m(1, 100000, 65536)];
        // 1001 is not mapped: the id before the run of 100000.. is.
        assert!(outside_to_inside(&parent, 1000, 2, "x").is_err());
        assert_eq!(
            outside_to_inside(&parent, 100000, 5, "x").unwrap(),
            [(1, 5)]
        );
    }

    #[test]
    fn test_idset_ops() {
        let a = IdSet::from_intervals([(5, 10), (0, 3), (3, 4), (9, 12)]);
        assert_eq!(a.intervals(), [(0, 4), (5, 12)]);
        assert!(a.contains(11) && !a.contains(4) && !a.contains(12));
        assert!(a.contains_range(5, 7) && !a.contains_range(3, 3) && a.contains_range(9, 0));
        let b = IdSet::from_intervals([(2, 7)]);
        assert_eq!(a.subtract(&b).intervals(), [(0, 2), (7, 12)]);
        assert_eq!(a.union(&b).intervals(), [(0, 12)]);
        assert_eq!(a.size(), 11);
        assert!(IdSet::default().is_empty());
    }
}
