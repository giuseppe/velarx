// SPDX-License-Identifier: Apache-2.0
//! Id mappings of user namespaces: the syntax of `--userns`, `--uidmap` and
//! the `idmap` mount option, and the glue to the arithmetic on mappings and
//! the layout of the automatic ranges, which is `velarx-idmap-core`.  Nothing
//! here does I/O: the callers pass what they read from
//! `/proc/self/{uid,gid}_map` and `/etc/sub{u,g}id`.
//!
//! The semantics are those of podman (`pkg/util`, `storage/userns.go`,
//! `storage/idset.go`).  A mapping is `(container id, parent id, size)`, with
//! parent ids in the namespace of the daemon: the host for a root daemon, the
//! user namespace of the daemon when rootless (where `0` is the user and `1..`
//! are the sub ids).  That is the view of the OCI runtime, which is why a
//! rootless mapping needs no composition with the daemon's.

use thiserror::Error;
use velarx_idmap_core as core;
use velarx_idmap_core::{AutoFault, Fault, Map};
use velarx_proto::modes::UsernsChoice;
use velarx_proto::pod::IdMapping;

pub use velarx_idmap_core::{IdSet, ID_LIMIT, MAX_EXTENTS};

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

fn map(container_id: u64, host_id: u64, size: u64) -> Map {
    // Callers only build mappings from values below `ID_LIMIT`.
    Map {
        container_id: container_id as u32,
        parent_id: host_id as u32,
        size: size as u32,
    }
}

fn to_core(maps: &[IdMapping]) -> Vec<Map> {
    maps.iter()
        .map(|m| Map {
            container_id: m.container_id,
            parent_id: m.host_id,
            size: m.size,
        })
        .collect()
}

fn from_core(maps: Vec<Map>) -> Vec<IdMapping> {
    maps.into_iter()
        .map(|m| IdMapping {
            container_id: m.container_id,
            host_id: m.parent_id,
            size: m.size,
        })
        .collect()
}

/// The error for the entry of `maps` that `validate` of the core names.
fn fault(f: Fault, maps: &[IdMapping]) -> IdMapError {
    match f {
        Fault::TooMany(n) => {
            IdMapError::Invalid(format!("{n} id mappings, the kernel accepts {MAX_EXTENTS}"))
        }
        Fault::Empty(i) => IdMapError::Invalid(format!("the id mapping {} is empty", maps[i])),
        Fault::PastLimit(i) => {
            IdMapError::Invalid(format!("the id mapping {} is past the last id", maps[i]))
        }
        Fault::Overlap(i) => IdMapError::Overlap(maps[i].to_string()),
    }
}

/// The parent (host) ids of `maps`.
pub fn host_ids(maps: &[IdMapping]) -> IdSet {
    IdSet::of_parent_ids(&to_core(maps))
}

/// The container ids of `maps`.
pub fn container_ids(maps: &[IdMapping]) -> IdSet {
    IdSet::of_container_ids(&to_core(maps))
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
    from_core(core::split_on(&to_core(maps), &to_core(parent)))
}

/// Check a mapping: no empty entry, nothing past `ID_LIMIT`, no overlap in
/// the container ids or in the parent ids, at most `MAX_EXTENTS` entries.
pub fn validate(maps: &[IdMapping]) -> IdMapResult<()> {
    core::validate(&to_core(maps)).map_err(|f| fault(f, maps))
}

/// Sort by container id and merge the entries that continue each other.
/// Two entries whose sizes do not fit one are left apart: the second is
/// then past the last id and [`validate`] refuses it.
pub fn sort_and_merge(maps: &[IdMapping]) -> Vec<IdMapping> {
    from_core(core::sort_and_merge(&to_core(maps)))
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
    let mut idmap: Vec<Map> = Vec::new();
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
                idmap = core::break_insert(&idmap, e);
            }
        }
    }
    if fill_map {
        let available = container_ids(parent).subtract(&IdSet::of_parent_ids(&idmap));
        idmap = core::fill(&idmap, &available);
    }
    Ok(from_core(core::sort_and_merge(&idmap)))
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
    (
        from_core(core::keep_id(uid, sub_uid, size)),
        from_core(core::keep_id(gid, sub_gid, size)),
    )
}

/// The mappings of `--userns=nomap`: everything but the user, from `0`.
pub fn no_map(sub_uid: u32, sub_gid: u32) -> IdMapResult<(Vec<IdMapping>, Vec<IdMapping>)> {
    if sub_uid == 0 || sub_gid == 0 {
        return invalid("nomap needs sub ids in /etc/subuid and /etc/subgid");
    }
    Ok((
        from_core(vec![map(0, 1, sub_uid.into())]),
        from_core(vec![map(0, 1, sub_gid.into())]),
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
    core::auto_map(size, pool, used, &to_core(extra))
        .map(from_core)
        .map_err(|e| match e {
            AutoFault::NoSpace(n) => IdMapError::NoSpace(n),
            AutoFault::Invalid(f) => fault(f, extra),
            AutoFault::TooMany(n) => fault(Fault::TooMany(n), extra),
        })
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
            size = size.max(id.saturating_add(1));
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
                    let Some(p) = core::range_to_parent(&to_core(ctr), h, size) else {
                        return invalid(format!(
                            "the ids {h}+{size} of `{option}` are not in one range of the user namespace of the container"
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
    fn test_sort_and_merge() {
        assert_eq!(sort_and_merge(&[m(1, 1, 3), m(4, 4, 4)]), [m(1, 1, 7)]);
        assert_eq!(
            sort_and_merge(&[m(4, 9, 4), m(1, 1, 3)]),
            [m(1, 1, 3), m(4, 9, 4)]
        );
    }

    #[test]
    fn test_sort_and_merge_size_overflow() {
        let maps = [m(0, 0, u32::MAX), m(u32::MAX, u32::MAX, 2)];
        let merged = sort_and_merge(&maps);
        assert_eq!(merged, maps);
        assert!(validate(&merged).is_err());
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
        let pool = IdSet::from_intervals(&[(1, 65537)]);
        let none = IdSet::default();
        let first = auto_map(1024, &pool, &none, &[]).unwrap();
        assert_eq!(first, [m(0, 1, 1024)]);
        let used = host_ids(&first);
        let second = auto_map(2000, &pool, &used, &[]).unwrap();
        assert_eq!(second, [m(0, 1025, 2000)]);
        // The range of the first container is free again.
        let used = host_ids(&second);
        assert_eq!(auto_map(100, &pool, &used, &[]).unwrap(), [m(0, 1, 100)]);
        // A hole is used with what follows it.
        let used = IdSet::from_intervals(&[(1, 11), (21, 40000)]);
        assert_eq!(
            auto_map(30, &pool, &used, &[]).unwrap(),
            [m(0, 11, 10), m(10, 40000, 20)]
        );
        // Not enough ids.
        let used = IdSet::from_intervals(&[(1, 65000)]);
        assert_eq!(
            auto_map(1024, &pool, &used, &[]),
            Err(IdMapError::NoSpace(1024))
        );
        // Root: the sub ids of `containers`.
        let pool = IdSet::from_intervals(&[(786432, 786432 + 65536)]);
        assert_eq!(
            auto_map(65536, &pool, &none, &[]).unwrap(),
            [m(0, 786432, 65536)]
        );
    }

    #[test]
    fn test_auto_map_with_extra_mappings() {
        let pool = IdSet::from_intervals(&[(1, 100)]);
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
    fn test_max_id_of_passwd_group_at_the_end_of_u64() {
        // ids of a file of the image: any number that fits 64 bits
        let big = u64::MAX.to_string();
        let passwd = format!("a:x:{big}:0::/:/bin/sh\n");
        assert_eq!(max_id_of_passwd_group(&passwd, ""), u32::MAX);
        assert_eq!(
            max_id_of_passwd_group("", &format!("g:x:{big}:\n")),
            u32::MAX
        );
        let last = (u64::MAX - 1).to_string();
        assert_eq!(
            max_id_of_passwd_group("", &format!("g:x:{last}:\n")),
            u32::MAX
        );
        let edge = (ID_LIMIT - 1).to_string();
        assert_eq!(
            max_id_of_passwd_group("", &format!("g:x:{edge}:\n")),
            u32::MAX
        );
        let before = (ID_LIMIT - 2).to_string();
        assert_eq!(
            max_id_of_passwd_group("", &format!("g:x:{before}:\n")),
            u32::MAX - 1
        );
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
    fn test_mount_idmap_relative_range_in_one_extent() {
        // container ids 0..1000 are the parent ids 1..1001, 1000 is 0
        let ctr = [m(0, 1, 1000), m(1000, 0, 1), m(2000, 5000, 10)];
        let one = |o: &str| parse_mount_idmap(o, &ctr, &ctr).map(|(u, _)| u);
        // the whole range is in an extent: the parent ids follow the start
        assert_eq!(one("idmap=uids=@7-998-2").unwrap(), [m(7, 999, 2)]);
        assert_eq!(one("idmap=uids=@7-0-1000").unwrap(), [m(7, 1, 1000)]);
        assert_eq!(one("idmap=uids=@7-2005-5").unwrap(), [m(7, 5005, 5)]);
        // the last id of an extent, and one id past it
        assert_eq!(one("idmap=uids=@7-999-1").unwrap(), [m(7, 1000, 1)]);
        // a range that runs past its extent would map parent ids that the
        // container does not own: 1001 (not mapped) or 0 (another id)
        for bad in [
            "idmap=uids=@7-999-2",
            "idmap=uids=@7-0-1001",
            "idmap=uids=@7-500-501",
            "idmap=uids=@7-2005-6",
            "idmap=uids=@7-998-3#@8-0-1",
        ] {
            assert!(one(bad).is_err(), "{bad}");
        }
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

    // The tables below pin the arithmetic at its edges: empty, adjacent and
    // overlapping ranges, and ids next to `u32::MAX`.

    const MAX: u32 = u32::MAX;

    #[test]
    fn table_sort_and_merge() {
        for (input, want) in [
            (vec![], vec![]),
            (vec![m(5, 5, 1)], vec![m(5, 5, 1)]),
            // continue each other in both ids: one
            (vec![m(0, 0, 2), m(2, 2, 2), m(4, 4, 2)], vec![m(0, 0, 6)]),
            // in the container ids only, or in the parent ids only: two
            (vec![m(0, 0, 2), m(2, 9, 2)], vec![m(0, 0, 2), m(2, 9, 2)]),
            (vec![m(0, 0, 2), m(5, 2, 2)], vec![m(0, 0, 2), m(5, 2, 2)]),
            // out of order
            (vec![m(2, 2, 2), m(0, 0, 2)], vec![m(0, 0, 4)]),
            // overlapping entries are left alone, for validate to refuse
            (vec![m(0, 0, 4), m(2, 2, 4)], vec![m(0, 0, 4), m(2, 2, 4)]),
            // the same container id twice: the order of the input stays
            (vec![m(1, 7, 1), m(1, 3, 1)], vec![m(1, 7, 1), m(1, 3, 1)]),
            // empty entries are kept, and do not merge unless they continue
            (vec![m(0, 0, 2), m(2, 2, 0)], vec![m(0, 0, 2)]),
            (vec![m(0, 0, 0), m(0, 0, 3)], vec![m(0, 0, 3)]),
            // sizes that add up to the last id merge, one more does not
            (
                vec![m(0, 0, MAX - 1), m(MAX - 1, MAX - 1, 1)],
                vec![m(0, 0, MAX)],
            ),
            (
                vec![m(0, 0, MAX), m(MAX, MAX, 1)],
                vec![m(0, 0, MAX), m(MAX, MAX, 1)],
            ),
            (
                vec![m(0, 0, MAX - 1), m(MAX - 1, MAX - 1, 2)],
                vec![m(0, 0, MAX - 1), m(MAX - 1, MAX - 1, 2)],
            ),
        ] {
            assert_eq!(sort_and_merge(&input), want, "{input:?}");
        }
    }

    #[test]
    fn table_split_on() {
        let parent = [m(0, 100, 5), m(5, 200, 5), m(20, 300, 10)];
        for (input, want) in [
            (vec![], vec![]),
            // inside one extent
            (vec![m(0, 1, 3)], vec![m(0, 1, 3)]),
            // ends exactly at the end of an extent
            (vec![m(0, 2, 3)], vec![m(0, 2, 3)]),
            // one more id: two entries
            (vec![m(0, 2, 4)], vec![m(0, 2, 3), m(3, 5, 1)]),
            // across two extents and into the third
            // (the cuts are at the ends of the extents: 5, 10 and 30)
            (
                vec![m(0, 3, 20)],
                vec![m(0, 3, 2), m(2, 5, 5), m(7, 10, 13)],
            ),
            // starts at the beginning of an extent
            (vec![m(7, 5, 5)], vec![m(7, 5, 5)]),
            // one id
            (vec![m(9, 9, 1)], vec![m(9, 9, 1)]),
            // empty entries vanish
            (vec![m(3, 3, 0), m(4, 4, 1)], vec![m(4, 4, 1)]),
            // each entry on its own
            (
                vec![m(0, 4, 2), m(10, 9, 2)],
                vec![m(0, 4, 1), m(1, 5, 1), m(10, 9, 1), m(11, 10, 1)],
            ),
        ] {
            assert_eq!(split_on(&input, &parent), want, "{input:?}");
        }
        // no extents, no cuts
        assert_eq!(split_on(&[m(0, 0, MAX)], &[]), [m(0, 0, MAX)]);
        // near the last id
        let top = [m(0, 0, MAX - 1), m(MAX - 1, MAX - 1, 1)];
        assert_eq!(
            split_on(&[m(MAX - 4, MAX - 4, 4)], &top),
            [m(MAX - 4, MAX - 4, 3), m(MAX - 1, MAX - 1, 1)]
        );
        assert_eq!(split_on(&[m(0, 0, MAX)], &[m(0, 0, MAX)]), [m(0, 0, MAX)]);
    }

    #[test]
    fn table_auto_map_edges() {
        let set = |v: &[(u64, u64)]| IdSet::from_intervals(v);
        let top = u64::from(MAX);
        let none = IdSet::default();
        // no ids asked
        assert_eq!(auto_map(0, &set(&[(1, 9)]), &none, &[]), Ok(vec![]));
        // the whole range of ids, and one too many
        assert_eq!(
            auto_map(MAX, &set(&[(0, top)]), &none, &[]),
            Ok(vec![m(0, 0, MAX)])
        );
        assert_eq!(
            auto_map(MAX, &set(&[(1, top)]), &none, &[]),
            Err(IdMapError::NoSpace(top))
        );
        // the pool is used from its first id; the used ids of the middle are skipped
        assert_eq!(
            auto_map(3, &set(&[(10, 20)]), &set(&[(11, 12)]), &[]),
            Ok(vec![m(0, 10, 1), m(1, 12, 2)])
        );
        // exactly enough, one less
        assert_eq!(
            auto_map(3, &set(&[(10, 12), (20, 21)]), &none, &[]),
            Ok(vec![m(0, 10, 2), m(2, 20, 1)])
        );
        assert_eq!(
            auto_map(3, &set(&[(10, 12), (20, 21)]), &set(&[(20, 21)]), &[]),
            Err(IdMapError::NoSpace(3))
        );
        // the used ids may be outside the pool
        assert_eq!(
            auto_map(2, &set(&[(10, 12)]), &set(&[(0, 5), (50, 60)]), &[]),
            Ok(vec![m(0, 10, 2)])
        );
        // the pool ends at the last id: a range that goes past it is refused
        assert!(auto_map(2, &set(&[(top - 1, top + 1)]), &none, &[]).is_err());
        // extra mappings: their ids are not given twice, the NoSpace count is
        // of the ids that are left to map
        assert_eq!(
            auto_map(4, &set(&[(10, 12)]), &none, &[m(0, 10, 1)]),
            Err(IdMapError::NoSpace(3))
        );
        assert_eq!(
            auto_map(4, &set(&[(10, 14)]), &none, &[m(0, 10, 1)]),
            Ok(vec![m(0, 10, 4)])
        );
        // an extra mapping beyond the size is kept
        assert_eq!(
            auto_map(2, &set(&[(10, 20)]), &none, &[m(50, 3, 1)]),
            Ok(vec![m(0, 10, 2), m(50, 3, 1)])
        );
        // extra mappings that overlap each other are refused
        assert!(matches!(
            auto_map(2, &set(&[(10, 20)]), &none, &[m(5, 3, 2), m(6, 30, 1)]),
            Err(IdMapError::Overlap(_))
        ));
        // so is one that is empty
        assert!(auto_map(2, &set(&[(10, 20)]), &none, &[m(5, 3, 0)]).is_err());
    }

    #[test]
    fn table_keep_id_edges() {
        // (id, sub, size) -> entries
        for (id, sub, size, want) in [
            (0, 0, None, vec![m(0, 0, 1)]),
            (5, 0, None, vec![m(5, 0, 1)]),
            (0, 3, None, vec![m(0, 0, 1), m(1, 1, 3)]),
            (1, 3, None, vec![m(0, 1, 1), m(1, 0, 1), m(2, 2, 2)]),
            (3, 3, None, vec![m(0, 1, 3), m(3, 0, 1)]),
            (4, 3, None, vec![m(0, 1, 3), m(4, 0, 1)]),
            // `size` 0 is no limit
            (1, 3, Some(0), vec![m(0, 1, 1), m(1, 0, 1), m(2, 2, 2)]),
            // the highest id is size - 1: the sub ids are cut
            (1, 3, Some(3), vec![m(0, 1, 1), m(1, 0, 1), m(2, 2, 1)]),
            (1, 3, Some(2), vec![m(0, 1, 1), m(1, 0, 1)]),
            // the user stays, wherever
            (7, 3, Some(2), vec![m(0, 1, 1), m(7, 0, 1)]),
            (7, 3, Some(1), vec![m(7, 0, 1)]),
            (0, 3, Some(1), vec![m(0, 0, 1)]),
            (0, 3, Some(2), vec![m(0, 0, 1), m(1, 1, 1)]),
            // a size above the sub ids changes nothing
            (1, 3, Some(100), vec![m(0, 1, 1), m(1, 0, 1), m(2, 2, 2)]),
            // the last ids
            (MAX, 3, None, vec![m(0, 1, 3), m(MAX, 0, 1)]),
            (0, MAX, None, vec![m(0, 0, 1), m(1, 1, MAX)]),
            (
                MAX - 1,
                MAX,
                None,
                vec![m(0, 1, MAX - 1), m(MAX - 1, 0, 1), m(MAX, MAX, 1)],
            ),
        ] {
            let (u, g) = keep_id(id, id, sub, sub, size);
            assert_eq!(u, want, "{id} {sub} {size:?}");
            assert_eq!(g, want);
        }
        // the uid and the gid do not mix
        let (u, g) = keep_id(2, 5, 3, 1, Some(10));
        assert_eq!(u, [m(0, 1, 2), m(2, 0, 1), m(3, 3, 1)]);
        assert_eq!(g, [m(0, 1, 1), m(5, 0, 1)]);
    }

    #[test]
    fn table_validate_edges() {
        let top = MAX - 1;
        for (maps, ok) in [
            (vec![], true),
            (vec![m(0, 0, 1)], true),
            // adjacent, in either order, in one id space only
            (vec![m(0, 0, 2), m(2, 2, 2)], true),
            (vec![m(2, 2, 2), m(0, 0, 2)], true),
            (vec![m(0, 5, 2), m(2, 0, 2)], true),
            // one id in common, in the container ids or the parent ids
            (vec![m(0, 0, 3), m(2, 10, 1)], false),
            (vec![m(2, 10, 1), m(0, 0, 3)], false),
            (vec![m(0, 0, 3), m(10, 2, 1)], false),
            // the same entry twice, one inside the other
            (vec![m(1, 1, 1), m(1, 1, 1)], false),
            (vec![m(0, 0, 10), m(3, 30, 2)], false),
            // the last ids: the last valid one, and the first past them
            (vec![m(top, top, 1)], true),
            (vec![m(MAX, 0, 1)], false),
            (vec![m(0, MAX, 1)], false),
            (vec![m(0, 0, MAX)], true),
            (vec![m(1, 0, MAX)], false),
            (vec![m(0, 1, MAX)], false),
            (vec![m(MAX, MAX, MAX)], false),
            (vec![m(0, 0, 1), m(0, 0, 0)], false),
        ] {
            assert_eq!(validate(&maps).is_ok(), ok, "{maps:?}");
        }
        // an empty entry is named before an overlap that comes first
        assert!(matches!(
            validate(&[m(0, 0, 2), m(1, 5, 1), m(9, 9, 0)]),
            Err(IdMapError::Invalid(_))
        ));
        // the first entry that overlaps an earlier one is the one named
        assert_eq!(
            validate(&[m(0, 0, 2), m(5, 5, 1), m(1, 9, 1), m(5, 7, 1)]),
            Err(IdMapError::Overlap("1:9:1".into()))
        );
    }

    #[test]
    fn table_to_parent_and_container_edges() {
        let maps = [m(0, MAX - 3, 3), m(MAX - 1, 0, 1), m(10, 20, 5)];
        assert_eq!(to_parent(&maps, 0), Some(MAX - 3));
        assert_eq!(to_parent(&maps, 2), Some(MAX - 1));
        assert_eq!(to_parent(&maps, 3), None);
        assert_eq!(to_parent(&maps, MAX - 1), Some(0));
        assert_eq!(to_parent(&maps, MAX), None);
        assert_eq!(to_parent(&maps, 14), Some(24));
        assert_eq!(to_parent(&maps, 15), None);
        assert_eq!(to_container(&maps, MAX - 1), Some(2));
        assert_eq!(to_container(&maps, MAX), None);
        assert_eq!(to_container(&maps, 0), Some(MAX - 1));
        assert_eq!(to_container(&maps, 24), Some(14));
        // an entry that runs past the last id (validate refuses it): the ids
        // that 32 bits cannot name are unmapped, `u32::MAX` is not
        let past = [m(MAX - 1, MAX - 1, 5)];
        assert_eq!(to_parent(&past, MAX - 1), Some(MAX - 1));
        assert_eq!(to_parent(&past, MAX), Some(MAX));
        assert_eq!(to_container(&past, MAX), Some(MAX));
        // an empty entry maps nothing
        assert_eq!(to_parent(&[m(3, 3, 0)], 3), None);
    }
}
