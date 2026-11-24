// SPDX-License-Identifier: Apache-2.0
//! The rules of the id mappings, checked on every answer of the functions
//! of the crate.  They are stated by what the ids mean, not by how the
//! functions compute: a mapping is read as the explicit list of the pairs
//! `(container id, parent id)` it maps, and a set of ids as the explicit
//! set, so that a computation that is wrong in another way than the one it
//! was written for still fails one.  The inputs of the walk are small, so
//! that every entry can be spelled out id by id.
//!
//! The claim, and where each rule is:
//! - a mapping never maps one container id twice, nor one parent id twice,
//!   and nothing past the last id: `check_validate`;
//! - rewriting a mapping (`sort_and_merge`, `split_on`) does not change
//!   what is mapped to what, and what `break_insert` and `fill` change they
//!   say: `check_merge`, `check_split`, `check_break_insert`, `check_fill`;
//! - the automatic mapping gives container ids `[0, size)` only parent ids
//!   of the pool that nobody uses, the first ones, and fails only when
//!   there are not enough: `check_auto`;
//! - keep-id maps the user to itself and the others to its sub ids, and to
//!   nothing else: `check_keep_id`;
//! - a range of ids is translated only when it is in one entry:
//!   `check_range`;
//! - the sets of ids are the sets: `check_sets`.

use super::*;
use std::collections::BTreeSet;

/// What `maps` maps, as the sorted list of `(container id, parent id)`.  A
/// pair that two entries give is twice in the list.
pub fn pairs(maps: &[Map]) -> Vec<(u64, u64)> {
    let mut out = Vec::new();
    for m in maps {
        for k in 0..u64::from(m.size) {
            out.push((u64::from(m.container_id) + k, u64::from(m.parent_id) + k));
        }
    }
    out.sort();
    out
}

/// The container ids of `maps`.
pub fn containers(maps: &[Map]) -> BTreeSet<u64> {
    pairs(maps).into_iter().map(|p| p.0).collect()
}

/// The parent ids of `maps`.
fn parents(maps: &[Map]) -> BTreeSet<u64> {
    pairs(maps).into_iter().map(|p| p.1).collect()
}

/// The ids of a set, one by one.
pub fn explicit(set: &IdSet) -> BTreeSet<u64> {
    let mut out = BTreeSet::new();
    for &(s, e) in set.intervals() {
        out.extend(s..e);
    }
    out
}

/// Whether two entries have a container id, or a parent id, in common: one
/// of them starts inside the other.
fn clash(a: &Map, b: &Map) -> bool {
    let inside =
        |x: u64, start: u32, n: u32| u64::from(start) <= x && x < u64::from(start) + u64::from(n);
    let (ac, bc) = (u64::from(a.container_id), u64::from(b.container_id));
    let (ah, bh) = (u64::from(a.parent_id), u64::from(b.parent_id));
    a.size > 0
        && b.size > 0
        && (inside(ac, b.container_id, b.size)
            || inside(bc, a.container_id, a.size)
            || inside(ah, b.parent_id, b.size)
            || inside(bh, a.parent_id, a.size))
}

/// Whether every entry has ids and ends at the last id at the latest, and
/// no container id and no parent id is given twice.
pub fn is_valid(maps: &[Map]) -> bool {
    maps.len() <= MAX_EXTENTS
        && maps.iter().all(|m| {
            m.size > 0
                && u64::from(m.container_id) + u64::from(m.size) <= ID_LIMIT
                && u64::from(m.parent_id) + u64::from(m.size) <= ID_LIMIT
        })
        && (0..maps.len()).all(|i| (0..i).all(|j| !clash(&maps[i], &maps[j])))
}

/// `validate` accepts the mappings that are functions both ways, and when
/// it does not, says which entry is the first at fault.
pub fn check_validate(maps: &[Map], answer: Result<(), Fault>) {
    let what = || format!("{maps:?}: {answer:?}");
    assert_eq!(answer.is_ok(), is_valid(maps), "{}", what());
    if maps.len() > MAX_EXTENTS {
        assert_eq!(answer, Err(Fault::TooMany(maps.len())), "{}", what());
        return;
    }
    // the first entry that is empty or past the last id
    for (i, m) in maps.iter().enumerate() {
        if m.size == 0 {
            assert_eq!(answer, Err(Fault::Empty(i)), "{}", what());
            return;
        }
        if u64::from(m.container_id) + u64::from(m.size) > ID_LIMIT
            || u64::from(m.parent_id) + u64::from(m.size) > ID_LIMIT
        {
            assert_eq!(answer, Err(Fault::PastLimit(i)), "{}", what());
            return;
        }
    }
    // the first entry that has an id of an earlier one
    for i in 0..maps.len() {
        if (0..i).any(|j| clash(&maps[i], &maps[j])) {
            assert_eq!(answer, Err(Fault::Overlap(i)), "{}", what());
            return;
        }
    }
    assert_eq!(answer, Ok(()), "{}", what());
}

/// Whether no two entries of the list continue each other (in both ids,
/// with a size that fits).
fn nothing_to_merge(maps: &[Map]) -> bool {
    maps.windows(2).all(|w| {
        let end_c = u64::from(w[0].container_id) + u64::from(w[0].size);
        let end_p = u64::from(w[0].parent_id) + u64::from(w[0].size);
        let both = u64::from(w[0].size) + u64::from(w[1].size);
        !(end_c == u64::from(w[1].container_id)
            && end_p == u64::from(w[1].parent_id)
            && both <= u64::from(u32::MAX))
    })
}

/// `sort_and_merge` adds nothing and loses nothing: the same pairs, by
/// container id, with no entry that could be joined to the next.
pub fn check_merge(maps: &[Map], out: &[Map]) {
    let what = || format!("{maps:?} -> {out:?}");
    if maps.iter().map(|m| u64::from(m.size)).sum::<u64>() <= 1000 {
        assert_eq!(pairs(out), pairs(maps), "{}", what());
    } else if is_valid(maps) {
        // (too many ids to spell out: where the ids start and end)
        for m in maps.iter().chain(out) {
            let (start, end) = (
                u128::from(m.container_id),
                u128::from(m.container_id) + u128::from(m.size),
            );
            for c in [start, end - 1, end] {
                assert_eq!(parent_of(out, c), parent_of(maps, c), "{c}: {}", what());
            }
        }
    }
    assert!(
        out.windows(2)
            .all(|w| w[0].container_id <= w[1].container_id),
        "not sorted: {}",
        what()
    );
    assert!(nothing_to_merge(out), "{}", what());
    assert!(out.len() <= maps.len(), "{}", what());
    if is_valid(maps) {
        assert!(is_valid(out), "{}", what());
    }
}

/// `split_on` changes where the entries are cut and nothing else: the same
/// pairs, each entry in one extent of `parent` (given that the parent ids
/// are all in the extents, which is what makes a mapping a possible one),
/// and cut only where an extent ends.
pub fn check_split(maps: &[Map], parent: &[Map], out: &[Map]) {
    let what = || format!("{maps:?} on {parent:?} -> {out:?}");
    assert_eq!(pairs(out), pairs(maps), "{}", what());
    let extent_of = |id: u64| {
        parent.iter().position(|e| {
            u64::from(e.container_id) <= id && id < u64::from(e.container_id) + u64::from(e.size)
        })
    };
    for o in out {
        let first = extent_of(u64::from(o.parent_id));
        assert!(first.is_some(), "{}", what());
        for k in 0..u64::from(o.size) {
            assert_eq!(extent_of(u64::from(o.parent_id) + k), first, "{}", what());
        }
    }
    // one entry more for each end of an extent inside an entry
    let mut want = 0;
    for m in maps.iter().filter(|m| m.size > 0) {
        let (h, n) = (u64::from(m.parent_id), u64::from(m.size));
        let ends = parent
            .iter()
            .filter(|e| {
                let end = u64::from(e.container_id) + u64::from(e.size);
                h < end && end < h + n
            })
            .count();
        want += 1 + ends;
    }
    assert_eq!(out.len(), want, "{}", what());
}

/// Whether every id of the entry is a 32 bit id (valid or not).  (Written
/// again, not taken from the crate: a rule that shares the code it checks
/// cannot fail with it.)
fn fits(m: &Map) -> bool {
    u64::from(m.container_id) + u64::from(m.size) <= ID_LIMIT + 1
        && u64::from(m.parent_id) + u64::from(m.size) <= ID_LIMIT + 1
}

/// `break_insert` keeps what `mapping` maps but for the container ids and
/// the parent ids of `ext`, and adds what `ext` maps.  An entry that has an
/// id that 32 bits cannot hold is not cut: it is refused by `validate`.
pub fn check_break_insert(mapping: &[Map], ext: Map, out: &[Map]) {
    let what = || format!("{mapping:?} + {ext:?} -> {out:?}");
    let (c, p) = (containers(&[ext]), parents(&[ext]));
    let mut want: Vec<(u64, u64)> = Vec::new();
    for m in mapping {
        for pair in pairs(&[*m]) {
            if !fits(m) || (!c.contains(&pair.0) && !p.contains(&pair.1)) {
                want.push(pair);
            }
        }
    }
    want.extend(pairs(&[ext]));
    want.sort();
    assert_eq!(pairs(out), want, "{}", what());
    assert_eq!(out.last(), Some(&ext), "{}", what());
    if is_valid(mapping) && is_valid(&[ext]) {
        assert!(is_valid(out), "{}", what());
    }
}

/// `fill` keeps what `idmap` maps and gives the lowest container ids that
/// it does not map, in order, the ids of `available` that are valid ids, in
/// order.
pub fn check_fill(idmap: &[Map], available: &IdSet, out: &[Map]) {
    let what = || format!("{idmap:?} + {available:?} -> {out:?}");
    let taken = containers(idmap);
    let free = (0..ID_LIMIT).filter(|c| !taken.contains(c));
    let avail = explicit(available).into_iter().filter(|a| *a < ID_LIMIT);
    let mut want = pairs(idmap);
    want.extend(free.zip(avail));
    want.sort();
    assert_eq!(pairs(out), want, "{}", what());
    assert!(nothing_to_merge(out), "{}", what());
    // a function stays a function when the ids that are added are new ones
    if is_valid(idmap) && explicit(available).is_disjoint(&parents(idmap)) {
        assert!(is_valid(out), "{}", what());
    }
}

/// The automatic mapping of `size` ids.
///
/// The ids that it picks are the first of `pool` below the last id that
/// `used` and the parent ids of `extra` do not have, one by one for the
/// container ids of `[0, size)` that `extra` does not map, in order.  It
/// fails with the fault of `extra` when `extra` is no mapping (first,
/// whatever the pool has), and with the number of ids it lacks when the pool
/// has fewer, and with their number when the pool has them in so many pieces
/// that the mapping has more entries than the kernel accepts.  The user's own entries are in the answer as they are, and may
/// use any parent id, even a used one: they are the ones that were asked
/// for.
pub fn check_auto(
    size: u32,
    pool: &IdSet,
    used: &IdSet,
    extra: &[Map],
    answer: Result<Vec<Map>, AutoFault>,
) {
    let what = || format!("{size} {pool:?} {used:?} {extra:?}: {answer:?}");
    if !is_valid(extra) {
        match answer {
            Err(AutoFault::Invalid(f)) => check_validate(extra, Err(f)),
            _ => panic!("an extra mapping that is not one: {}", what()),
        }
        return;
    }
    let extra_c = containers(extra);
    let extra_p = parents(extra);
    let wanted: Vec<u64> = (0..u64::from(size))
        .filter(|c| !extra_c.contains(c))
        .collect();
    let used = explicit(used);
    let free: Vec<u64> = explicit(pool)
        .into_iter()
        .filter(|p| *p < ID_LIMIT && !used.contains(p) && !extra_p.contains(p))
        .collect();
    if free.len() < wanted.len() {
        assert_eq!(
            answer,
            Err(AutoFault::NoSpace(wanted.len() as u64)),
            "{}",
            what()
        );
        return;
    }
    let maps = match &answer {
        Ok(maps) => maps.clone(),
        // refused for the pieces: the entries are those of the pairs below,
        // where an entry goes on in both ids, and there are too many
        Err(AutoFault::TooMany(n)) => {
            assert!(*n > MAX_EXTENTS, "{}", what());
            return;
        }
        Err(_) => panic!("refused for nothing: {}", what()),
    };
    let mut want: Vec<(u64, u64)> = wanted.iter().copied().zip(free.iter().copied()).collect();
    want.extend(pairs(extra));
    want.sort();
    assert_eq!(pairs(&maps), want, "{}", what());
    assert!(is_valid(&maps), "{}", what());
    // The container ids are those of the size and the user's.
    let all: BTreeSet<u64> = (0..u64::from(size)).chain(extra_c).collect();
    assert_eq!(containers(&maps), all, "{}", what());
}

/// What the layout of keep-id maps the container id `c` to, from what the
/// user is and has: the user to the parent id `0`, the ids below it to the
/// sub ids `1..` (by one), the ones above it to the same sub ids, and the
/// others to nothing; `size` stops the sub ids at the container id
/// `size - 1`.  (Everything in `u128` so that nothing can wrap.)
fn keep_id_of(c: u128, id: u32, sub: u32, size: Option<u32>) -> Option<u128> {
    let id = u128::from(id);
    let mut max = u128::from(sub);
    if let Some(s) = size.filter(|s| *s > 0) {
        max = max.min(u128::from(s) - 1);
    }
    if c == id {
        Some(0)
    } else if sub > 0 && c < id && c < max {
        Some(c + 1)
    } else if c > id && c <= max {
        Some(c)
    } else {
        None
    }
}

/// What `out` maps the container id `c` to, `None` if nothing.
fn parent_of(out: &[Map], c: u128) -> Option<u128> {
    let mut found = None;
    for m in out {
        let start = u128::from(m.container_id);
        if start <= c && c < start + u128::from(m.size) {
            assert!(found.is_none(), "{c} twice in {out:?}");
            found = Some(u128::from(m.parent_id) + (c - start));
        }
    }
    found
}

/// `keep_id` for one of uid and gid: the layout above, as a function that
/// nothing maps twice, with only the parent ids `0..=sub`, the user's own
/// parent id from the user's id alone.  The ids that are probed are the
/// small ones and those next to every edge of the layout.
pub fn check_keep_id(id: u32, sub: u32, size: Option<u32>, out: &[Map]) {
    let what = || format!("{id} {sub} {size:?} -> {out:?}");
    // no id twice, in the parent ids either
    for (i, a) in out.iter().enumerate() {
        for b in &out[..i] {
            let (ac, ah) = (u128::from(a.container_id), u128::from(a.parent_id));
            let (bc, bh) = (u128::from(b.container_id), u128::from(b.parent_id));
            let (an, bn) = (u128::from(a.size), u128::from(b.size));
            assert!(
                (ac + an <= bc || bc + bn <= ac) && (ah + an <= bh || bh + bn <= ah),
                "{}",
                what()
            );
        }
        assert!(a.size > 0, "{}", what());
        // the user's own id and its sub ids: nothing else of the parent
        assert!(ah_end(a) <= u128::from(sub) + 1, "{}", what());
    }
    let max = size.map_or(sub, |s| if s > 0 { sub.min(s - 1) } else { sub });
    let mut probes: BTreeSet<u128> = (0..20).collect();
    for edge in [u128::from(id), u128::from(max), u128::from(sub)] {
        probes.extend(edge.saturating_sub(2)..edge + 3);
    }
    probes.extend(u128::from(u32::MAX) - 3..=u128::from(u32::MAX));
    for c in probes {
        assert_eq!(
            parent_of(out, c),
            keep_id_of(c, id, sub, size),
            "{c}: {}",
            what()
        );
    }
}

/// The end of the parent ids of an entry.
fn ah_end(m: &Map) -> u128 {
    u128::from(m.parent_id) + u128::from(m.size)
}

/// The set operations are those of sets, and every set the crate builds is
/// sorted, disjoint and not adjacent.
pub fn check_sets(a: &IdSet, b: &IdSet) {
    let what = || format!("{a:?} {b:?}");
    let (ea, eb) = (explicit(a), explicit(b));
    for s in [a, b] {
        let iv = s.intervals();
        assert!(iv.iter().all(|(s, e)| s < e), "{}", what());
        assert!(iv.windows(2).all(|w| w[0].1 < w[1].0), "{}", what());
        assert_eq!(s.size(), explicit(s).len() as u64, "{}", what());
        assert_eq!(s.is_empty(), explicit(s).is_empty(), "{}", what());
    }
    let union = a.union(b);
    let diff = a.subtract(b);
    assert_eq!(
        explicit(&union),
        ea.union(&eb).copied().collect(),
        "{}",
        what()
    );
    assert_eq!(
        explicit(&diff),
        ea.difference(&eb).copied().collect(),
        "{}",
        what()
    );
    for s in [&union, &diff] {
        let iv = s.intervals();
        assert!(iv.windows(2).all(|w| w[0].1 < w[1].0), "{}", what());
    }
    for limit in [0, 1, 3, ID_LIMIT, ID_LIMIT + 2] {
        let below = a.below(limit);
        assert_eq!(
            explicit(&below),
            ea.iter().copied().filter(|x| *x < limit).collect(),
            "{limit}: {}",
            what()
        );
    }
    // the first n ids, or nothing
    for n in 0..=ea.len() as u64 + 1 {
        match a.find_available(n) {
            Some(f) => {
                assert!(n <= ea.len() as u64, "{n}: {}", what());
                assert_eq!(
                    explicit(&f),
                    ea.iter().copied().take(n as usize).collect(),
                    "{n}: {}",
                    what()
                );
            }
            None => assert!(n > ea.len() as u64, "{n}: {}", what()),
        }
    }
    // the ids in order, pairwise, to the last of the shorter, below the last id
    let hosts: Vec<u64> = ea.iter().copied().filter(|x| *x < ID_LIMIT).collect();
    let ctrs: Vec<u64> = eb.iter().copied().filter(|x| *x < ID_LIMIT).collect();
    let zipped = a.zip(b);
    let want: Vec<(u64, u64)> = ctrs.iter().copied().zip(hosts.iter().copied()).collect();
    assert_eq!(pairs(&zipped), want, "{}", what());
    // a range is in the set when every one of its ids is
    for start in ea.iter().chain(eb.iter()).copied().chain([0, 1]) {
        for len in 0..4 {
            let yes = (start..start + len).all(|x| ea.contains(&x));
            assert_eq!(
                a.contains_range(start, len),
                yes,
                "{start}+{len}: {}",
                what()
            );
        }
    }
    assert!(!a.contains_range(u64::MAX, 2));
    assert!(a.contains_range(u64::MAX, 0));
}

/// `range_to_parent` translates a range of container ids that is in one
/// entry, to the parent ids that the entry gives them, and nothing else.
pub fn check_range(maps: &[Map], start: u32, len: u32, answer: Option<u32>) {
    let what = || format!("{maps:?} {start}+{len}: {answer:?}");
    let first = maps.iter().find(|m| {
        u64::from(m.container_id) <= u64::from(start)
            && u64::from(start) < u64::from(m.container_id) + u64::from(m.size)
    });
    match (first, answer) {
        (None, None) => {}
        (Some(m), Some(p)) => {
            // every id of the range is the entry's, at the parent id it gives
            let all = pairs(std::slice::from_ref(m));
            for k in 0..u64::from(len) {
                let pair = (u64::from(start) + k, u64::from(p) + k);
                assert!(all.contains(&pair), "{pair:?}: {}", what());
            }
        }
        (Some(m), None) => {
            // refused: the range does not end in the entry (or the parent id
            // is not a 32 bit one)
            let end = u64::from(m.container_id) + u64::from(m.size);
            let parent = u64::from(m.parent_id) + u64::from(start - m.container_id);
            assert!(
                u64::from(start) + u64::from(len) > end || parent > u64::from(u32::MAX),
                "{}",
                what()
            );
        }
        (None, Some(_)) => panic!("translated what is not mapped: {}", what()),
    }
}
