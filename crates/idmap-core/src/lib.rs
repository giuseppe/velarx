// SPDX-License-Identifier: Apache-2.0
//! The id mappings of a user namespace, as podman has them (`pkg/util`,
//! `storage/idset.go`): a list of `(container id, parent id, size)`, the
//! sets of ids that the automatic ranges are taken from, and the layouts of
//! `--userns=auto` and `--userns=keep-id`.
//!
//! What this is for: no two containers share a parent id unless the user
//! asked for it, a mapping never maps a container id to a parent id that
//! the user does not own, a mapping is a function in both directions (no
//! container id twice, no parent id twice), and no id wraps around 32 bits.
//! `rules` states that for what these functions answer, and `walk` checks
//! it on every small input.
//!
//! The parent ids are those of the namespace of the daemon: the host for a
//! root daemon, the user namespace of the daemon when rootless.  What stays
//! in the shell: the syntax of the options, the files with the ranges, the
//! daemon's own map, and what is in use by the other containers.
//!
//! Written to be translated (tools/verify): plain integers, structs and
//! lists, loops with a flag, no closure, no iterator adapter, no sort of the
//! library.  Ids are `u64` where a sum of two of them must not wrap.

/// A mapping may not end past this id: `u32::MAX` is not a valid id, so
/// `0 0 4294967295` is the identity.
pub const ID_LIMIT: u64 = u32::MAX as u64;

/// The kernel accepts this many lines in a `uid_map` (since Linux 4.15).
pub const MAX_EXTENTS: usize = 340;

/// `size` ids from `container_id` are those from `parent_id` on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Map {
    pub container_id: u32,
    pub parent_id: u32,
    pub size: u32,
}

/// What is wrong with a list of mappings; the index is that of the first
/// entry at fault.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fault {
    /// This many entries, more than [`MAX_EXTENTS`].
    TooMany(usize),
    Empty(usize),
    /// The entry ends past [`ID_LIMIT`] in the container or the parent ids.
    PastLimit(usize),
    /// The entry has a container id or a parent id of an earlier one.
    Overlap(usize),
}

/// Why the automatic mapping cannot be made.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AutoFault {
    /// The ids wanted: the container ids to map, which the pool has too few
    /// free ids for.
    NoSpace(u64),
    /// An entry of the extra mappings is at fault (the index is theirs).
    Invalid(Fault),
    /// The ids are there, in so many pieces that the mapping has this many
    /// entries, more than [`MAX_EXTENTS`].
    TooMany(usize),
}

/// A set of ids as sorted, disjoint and non adjacent intervals `[start,
/// end)`.  Any `u64` ids: the sum of the sizes cannot wrap, the intervals
/// are disjoint.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct IdSet {
    intervals: Vec<(u64, u64)>,
}

impl IdSet {
    /// The ids of the intervals, empty ones left out, overlapping and
    /// adjacent ones joined.
    pub fn from_intervals(list: &[(u64, u64)]) -> IdSet {
        // insertion sort by the start
        let mut sorted: Vec<(u64, u64)> = Vec::new();
        let mut i = 0;
        while i < list.len() {
            let (s, e) = list[i];
            if s < e {
                sorted.push((s, e));
                let mut j = sorted.len() - 1;
                while j > 0 && sorted[j - 1].0 > s {
                    sorted[j] = sorted[j - 1];
                    j -= 1;
                }
                sorted[j] = (s, e);
            }
            i += 1;
        }
        let mut out: Vec<(u64, u64)> = Vec::new();
        let mut i = 0;
        while i < sorted.len() {
            let (s, e) = sorted[i];
            let n = out.len();
            if n > 0 && s <= out[n - 1].1 {
                if e > out[n - 1].1 {
                    out[n - 1].1 = e;
                }
            } else {
                out.push((s, e));
            }
            i += 1;
        }
        IdSet { intervals: out }
    }

    /// The ids that the entries of `maps` have, by parent id or by container id.
    fn of_maps(maps: &[Map], parent: bool) -> IdSet {
        let mut list: Vec<(u64, u64)> = Vec::new();
        let mut i = 0;
        while i < maps.len() {
            let start = if parent {
                u64::from(maps[i].parent_id)
            } else {
                u64::from(maps[i].container_id)
            };
            list.push((start, start + u64::from(maps[i].size)));
            i += 1;
        }
        IdSet::from_intervals(&list)
    }

    /// The parent ids of `maps`.
    pub fn of_parent_ids(maps: &[Map]) -> IdSet {
        IdSet::of_maps(maps, true)
    }

    /// The container ids of `maps`.
    pub fn of_container_ids(maps: &[Map]) -> IdSet {
        IdSet::of_maps(maps, false)
    }

    pub fn intervals(&self) -> &[(u64, u64)] {
        &self.intervals
    }

    /// The number of ids.
    pub fn size(&self) -> u64 {
        let mut total = 0;
        let mut i = 0;
        while i < self.intervals.len() {
            total += self.intervals[i].1 - self.intervals[i].0;
            i += 1;
        }
        total
    }

    pub fn is_empty(&self) -> bool {
        self.intervals.is_empty()
    }

    /// Whether every id of `[start, start + len)` is in the set.
    pub fn contains_range(&self, start: u64, len: u64) -> bool {
        let mut found = len == 0;
        let mut i = 0;
        while i < self.intervals.len() && !found {
            let (s, e) = self.intervals[i];
            found = s <= start && start <= e && len <= e - start;
            i += 1;
        }
        found
    }

    pub fn union(&self, other: &IdSet) -> IdSet {
        let mut list: Vec<(u64, u64)> = Vec::new();
        let mut i = 0;
        while i < self.intervals.len() {
            list.push(self.intervals[i]);
            i += 1;
        }
        let mut i = 0;
        while i < other.intervals.len() {
            list.push(other.intervals[i]);
            i += 1;
        }
        IdSet::from_intervals(&list)
    }

    /// The ids of `self` that `other` does not have.
    pub fn subtract(&self, other: &IdSet) -> IdSet {
        let mut out: Vec<(u64, u64)> = Vec::new();
        let mut i = 0;
        while i < self.intervals.len() {
            let (s, e) = self.intervals[i];
            let mut start = s;
            let mut j = 0;
            let mut done = false;
            while j < other.intervals.len() && !done {
                let (os, oe) = other.intervals[j];
                if os >= e {
                    done = true;
                } else if oe > start {
                    if os > start {
                        out.push((start, os));
                    }
                    start = oe;
                    done = start >= e;
                }
                j += 1;
            }
            if start < e {
                out.push((start, e));
            }
            i += 1;
        }
        IdSet { intervals: out }
    }

    /// The ids of the set below `limit`.
    fn below(&self, limit: u64) -> IdSet {
        let mut out: Vec<(u64, u64)> = Vec::new();
        let mut i = 0;
        while i < self.intervals.len() {
            let (s, e) = self.intervals[i];
            if s < limit {
                out.push((s, if e < limit { e } else { limit }));
            }
            i += 1;
        }
        IdSet { intervals: out }
    }

    /// The first `n` ids of the set (they may come from several intervals,
    /// like `findAvailable` of c/storage), or nothing if it has fewer.
    fn find_available(&self, n: u64) -> Option<IdSet> {
        let mut left = n;
        let mut out: Vec<(u64, u64)> = Vec::new();
        let mut i = 0;
        while i < self.intervals.len() && left > 0 {
            let (s, e) = self.intervals[i];
            if e - s <= left {
                out.push((s, e));
                left -= e - s;
            } else {
                out.push((s, s + left));
                left = 0;
            }
            i += 1;
        }
        if left > 0 {
            None
        } else {
            Some(IdSet { intervals: out })
        }
    }

    /// Pair the ids of `self` (parent ids) with the container ids in
    /// `container`, both in ascending order, until one runs out.  Only ids
    /// below [`ID_LIMIT`] are paired: the others cannot be in a mapping.
    fn zip(&self, container: &IdSet) -> Vec<Map> {
        let hosts = self.below(ID_LIMIT);
        let ctrs = container.below(ID_LIMIT);
        let mut out: Vec<Map> = Vec::new();
        let (mut i, mut j) = (0, 0);
        let mut hs = 0;
        let mut cs = 0;
        if !hosts.intervals.is_empty() {
            hs = hosts.intervals[0].0;
        }
        if !ctrs.intervals.is_empty() {
            cs = ctrs.intervals[0].0;
        }
        while i < hosts.intervals.len() && j < ctrs.intervals.len() {
            let he = hosts.intervals[i].1;
            let ce = ctrs.intervals[j].1;
            let n = if he - hs < ce - cs { he - hs } else { ce - cs };
            out.push(Map {
                container_id: cs as u32,
                parent_id: hs as u32,
                size: n as u32,
            });
            hs += n;
            cs += n;
            if hs == he {
                i += 1;
                if i < hosts.intervals.len() {
                    hs = hosts.intervals[i].0;
                }
            }
            if cs == ce {
                j += 1;
                if j < ctrs.intervals.len() {
                    cs = ctrs.intervals[j].0;
                }
            }
        }
        out
    }
}

/// Whether every id of the entry is a 32 bit id, valid or not.  The
/// functions that cut an entry leave the others as they are: [`validate`]
/// refuses them.
fn fits(m: &Map) -> bool {
    u64::from(m.container_id) + u64::from(m.size) <= ID_LIMIT + 1
        && u64::from(m.parent_id) + u64::from(m.size) <= ID_LIMIT + 1
}

/// Check a mapping: at most [`MAX_EXTENTS`] entries, none empty or past
/// [`ID_LIMIT`], and no container id and no parent id twice.
pub fn validate(maps: &[Map]) -> Result<(), Fault> {
    if maps.len() > MAX_EXTENTS {
        return Err(Fault::TooMany(maps.len()));
    }
    let mut res: Result<(), Fault> = Ok(());
    let mut i = 0;
    while i < maps.len() && matches!(res, Ok(())) {
        let m = maps[i];
        if m.size == 0 {
            res = Err(Fault::Empty(i));
        } else if u64::from(m.container_id) + u64::from(m.size) > ID_LIMIT
            || u64::from(m.parent_id) + u64::from(m.size) > ID_LIMIT
        {
            res = Err(Fault::PastLimit(i));
        }
        i += 1;
    }
    let mut i = 0;
    while i < maps.len() && matches!(res, Ok(())) {
        let a = maps[i];
        let (ac, ah, asz) = (
            u64::from(a.container_id),
            u64::from(a.parent_id),
            u64::from(a.size),
        );
        let mut j = 0;
        while j < i && matches!(res, Ok(())) {
            let b = maps[j];
            let (bc, bh, bsz) = (
                u64::from(b.container_id),
                u64::from(b.parent_id),
                u64::from(b.size),
            );
            if (ac < bc + bsz && bc < ac + asz) || (ah < bh + bsz && bh < ah + asz) {
                res = Err(Fault::Overlap(i));
            }
            j += 1;
        }
        i += 1;
    }
    res
}

/// Sort by container id (entries with the same one stay in order) and merge
/// the entries that continue each other.  Two entries whose sizes do not fit
/// one are left apart: the second is then past the last id and [`validate`]
/// refuses it.  The ids that are mapped, and where to, do not change.
pub fn sort_and_merge(maps: &[Map]) -> Vec<Map> {
    let mut sorted: Vec<Map> = Vec::new();
    let mut i = 0;
    while i < maps.len() {
        sorted.push(maps[i]);
        let mut j = sorted.len() - 1;
        while j > 0 && sorted[j - 1].container_id > maps[i].container_id {
            sorted[j] = sorted[j - 1];
            j -= 1;
        }
        sorted[j] = maps[i];
        i += 1;
    }
    let mut out: Vec<Map> = Vec::new();
    let mut i = 0;
    while i < sorted.len() {
        let m = sorted[i];
        let n = out.len();
        if n > 0
            && u64::from(out[n - 1].container_id) + u64::from(out[n - 1].size)
                == u64::from(m.container_id)
            && u64::from(out[n - 1].parent_id) + u64::from(out[n - 1].size)
                == u64::from(m.parent_id)
            && u64::from(out[n - 1].size) + u64::from(m.size) <= u64::from(u32::MAX)
        {
            out[n - 1].size += m.size;
        } else {
            out.push(m);
        }
        i += 1;
    }
    out
}

/// Cut the entries of `maps` where the extents of `parent` (the map of the
/// namespace that the new one is a child of: `container_id` inside,
/// `parent_id` outside) end.  The kernel refuses a line whose parent ids are
/// in two extents of the parent's map, even when the ids are contiguous.
/// The ids that are mapped, and where to, do not change; an empty entry
/// goes.
pub fn split_on(maps: &[Map], parent: &[Map]) -> Vec<Map> {
    let mut out: Vec<Map> = Vec::new();
    let mut i = 0;
    while i < maps.len() {
        let m = maps[i];
        if !fits(&m) {
            out.push(m);
        } else {
            let (mut c, mut h, mut left) = (
                u64::from(m.container_id),
                u64::from(m.parent_id),
                u64::from(m.size),
            );
            while left > 0 {
                // the nearest end of an extent after h
                let mut n = left;
                let mut k = 0;
                while k < parent.len() {
                    let e = u64::from(parent[k].container_id) + u64::from(parent[k].size);
                    if e > h && e - h < n {
                        n = e - h;
                    }
                    k += 1;
                }
                out.push(Map {
                    container_id: c as u32,
                    parent_id: h as u32,
                    size: n as u32,
                });
                c += n;
                h += n;
                left -= n;
            }
        }
        i += 1;
    }
    out
}

/// The parent id of the container id `start`, when the ids `[start, start +
/// len)` are all in the one entry of `maps` that has `start`: the parent
/// ids of them follow.  A range that goes on into another entry is not
/// translated, even where that one continues the first: what is past the
/// entry is not what the entry gives.
pub fn range_to_parent(maps: &[Map], start: u32, len: u32) -> Option<u32> {
    let mut found = None;
    let mut done = false;
    let mut i = 0;
    while i < maps.len() && !done {
        let m = maps[i];
        let end = u64::from(m.container_id) + u64::from(m.size);
        if m.container_id <= start && u64::from(start) < end {
            done = true;
            let parent = u64::from(m.parent_id) + u64::from(start - m.container_id);
            if u64::from(start) + u64::from(len) <= end && parent <= u64::from(u32::MAX) {
                found = Some(parent as u32);
            }
        }
        i += 1;
    }
    found
}

/// The part of `[from, to)` of the entry `p`, if there is one.
fn push_part(out: &mut Vec<Map>, p: &Map, from: u64, to: u64) {
    if from < to {
        out.push(Map {
            container_id: (u64::from(p.container_id) + from) as u32,
            parent_id: (u64::from(p.parent_id) + from) as u32,
            size: (to - from) as u32,
        });
    }
}

/// The ids of `[start, start + len)` that are also in `[pstart, pstart + n)`,
/// as offsets from `pstart`: `(0, 0)` when there are none.
fn common(start: u64, len: u64, pstart: u64, n: u64) -> (u64, u64) {
    let lo = if start > pstart { start } else { pstart };
    let hi = if start + len < pstart + n {
        start + len
    } else {
        pstart + n
    };
    if lo < hi {
        (lo - pstart, hi - pstart)
    } else {
        (0, 0)
    }
}

/// Remove from `mapping` the parts that have a container id or a parent id
/// of `ext`, then add `ext` (podman `breakInsert`).  The other ids stay
/// mapped where they were.
pub fn break_insert(mapping: &[Map], ext: Map) -> Vec<Map> {
    let mut out: Vec<Map> = Vec::new();
    let (ec, eh, en) = (
        u64::from(ext.container_id),
        u64::from(ext.parent_id),
        u64::from(ext.size),
    );
    let mut i = 0;
    while i < mapping.len() {
        let p = mapping[i];
        if !fits(&p) {
            out.push(p);
        } else {
            let n = u64::from(p.size);
            // what the extension covers of the entry, by container id and
            // by parent id, from the first one
            let a0 = common(ec, en, u64::from(p.container_id), n);
            let b0 = common(eh, en, u64::from(p.parent_id), n);
            let (a, b) = if b0.1 > b0.0 && (a0.1 <= a0.0 || b0.0 < a0.0) {
                (b0, a0)
            } else {
                (a0, b0)
            };
            let mut pos = 0;
            if a.1 > a.0 {
                push_part(&mut out, &p, pos, a.0);
                pos = a.1;
            }
            if b.1 > b.0 {
                push_part(&mut out, &p, pos, b.0);
                if b.1 > pos {
                    pos = b.1;
                }
            }
            push_part(&mut out, &p, pos, n);
        }
        i += 1;
    }
    out.push(ext);
    out
}

/// Give the container ids that `idmap` leaves unmapped, starting from zero,
/// the parent ids of `available` in order (podman `fillIDMap`).
pub fn fill(idmap: &[Map], available: &IdSet) -> Vec<Map> {
    let free = IdSet::from_intervals(&[(0, ID_LIMIT)]).subtract(&IdSet::of_container_ids(idmap));
    let mut out: Vec<Map> = Vec::new();
    let mut i = 0;
    while i < idmap.len() {
        out.push(idmap[i]);
        i += 1;
    }
    let added = available.zip(&free);
    let mut i = 0;
    while i < added.len() {
        out.push(added[i]);
        i += 1;
    }
    sort_and_merge(&out)
}

/// The mappings of `--userns=auto` of `size` ids: the first free ids of
/// `pool` that `used` and the parent ids of the extra mappings do not take,
/// for the container ids that the extra mappings do not use.  The extra
/// mappings are the user's own: they are in the result as they are, and
/// refused first when they are no mapping.
pub fn auto_map(
    size: u32,
    pool: &IdSet,
    used: &IdSet,
    extra: &[Map],
) -> Result<Vec<Map>, AutoFault> {
    if let Err(f) = validate(extra) {
        return Err(AutoFault::Invalid(f));
    }
    let target = IdSet::from_intervals(&[(0, u64::from(size))]);
    let wanted = target.subtract(&IdSet::of_container_ids(extra));
    let free = pool
        .below(ID_LIMIT)
        .subtract(used)
        .subtract(&IdSet::of_parent_ids(extra));
    match free.find_available(wanted.size()) {
        None => Err(AutoFault::NoSpace(wanted.size())),
        Some(taken) => {
            let mut maps = taken.zip(&wanted);
            let mut i = 0;
            while i < extra.len() {
                maps.push(extra[i]);
                i += 1;
            }
            let maps = sort_and_merge(&maps);
            // (what the pieces make cannot clash, but there may be too many)
            if maps.len() > MAX_EXTENTS {
                Err(AutoFault::TooMany(maps.len()))
            } else {
                Ok(maps)
            }
        }
    }
}

/// The mappings of `--userns=keep-id` for one of uid and gid: the user `id`
/// of the daemon's namespace (parent id `0` there) keeps its number in the
/// container, the `sub` sub ids (parent ids `1..=sub`) are below and above
/// it.  `size` limits the highest id of the sub ids.
pub fn keep_id(id: u32, sub: u32, size: Option<u32>) -> Vec<Map> {
    let mut max = u64::from(sub);
    if let Some(s) = size {
        if s > 0 && u64::from(s) - 1 < max {
            max = u64::from(s) - 1;
        }
    }
    let user = u64::from(id);
    let below = if max < user { max } else { user };
    let mut out: Vec<Map> = Vec::new();
    if sub > 0 && id != 0 && below > 0 {
        out.push(Map {
            container_id: 0,
            parent_id: 1,
            size: below as u32,
        });
    }
    out.push(Map {
        container_id: id,
        parent_id: 0,
        size: 1,
    });
    if max > user {
        out.push(Map {
            container_id: id + 1,
            parent_id: id + 1,
            size: (max - user) as u32,
        });
    }
    out
}

#[cfg(test)]
mod rules;
#[cfg(test)]
mod tables;
#[cfg(test)]
mod walk;
