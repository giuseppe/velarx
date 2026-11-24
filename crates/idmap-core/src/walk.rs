// SPDX-License-Identifier: Apache-2.0
//! Every small input of the functions of the crate, and the rules checked
//! on each answer (see `rules`).  A small input is made of the ids `0..4`
//! or so, and of the ids next to the last one (where the sums come close
//! to a wrap), and of entries of up to three ids: every list of up to three
//! entries for the functions on a mapping, every pool and every set of used
//! ids for the automatic mapping, every user and number of sub ids for
//! keep-id.

use super::rules::*;
use super::*;

const MAX: u32 = u32::MAX;

fn m(c: u32, h: u32, n: u32) -> Map {
    Map {
        container_id: c,
        parent_id: h,
        size: n,
    }
}

/// The entries with these container ids, parent ids and sizes.
fn entries(cs: &[u32], hs: &[u32], sizes: std::ops::RangeInclusive<u32>) -> Vec<Map> {
    let mut out = Vec::new();
    for &c in cs {
        for &h in hs {
            for n in sizes.clone() {
                out.push(m(c, h, n));
            }
        }
    }
    out
}

/// Every list of up to `len` of the entries, the empty one included; the
/// number of them.
fn each_list(from: &[Map], len: usize, f: &mut dyn FnMut(&[Map])) -> usize {
    fn go(from: &[Map], left: usize, acc: &mut Vec<Map>, f: &mut dyn FnMut(&[Map])) -> usize {
        f(acc);
        let mut count = 1;
        if left > 0 {
            for e in from {
                acc.push(*e);
                count += go(from, left - 1, acc, f);
                acc.pop();
            }
        }
        count
    }
    go(from, len, &mut Vec::new(), f)
}

/// The ids next to the last one, to the ones of the small world.
fn near_top(span: u32) -> Vec<u32> {
    (MAX - span + 1..=MAX).collect()
}

/// The ids of the small world and of the end of them.
fn both(low: u32, top: u32) -> Vec<u32> {
    (0..low).chain(near_top(top)).collect()
}

/// The ids of the small world, and of the end of the ids and the two past it
/// (2^32 is `0` in 32 bits).
fn small_ids() -> Vec<u64> {
    (0..4).collect()
}

fn end_ids() -> Vec<u64> {
    (ID_LIMIT - 1..ID_LIMIT + 3).collect()
}

/// Every set that is made of any of these ids.
fn sets(ids: &[u64]) -> Vec<IdSet> {
    (0..1u32 << ids.len())
        .map(|bits| {
            let list: Vec<(u64, u64)> = (0..ids.len())
                .filter(|i| bits >> i & 1 == 1)
                .map(|i| (ids[i], ids[i] + 1))
                .collect();
            IdSet::from_intervals(&list)
        })
        .collect()
}

/// The lists of the functions of a mapping: `validate` and `sort_and_merge`.
fn walk_lists() -> usize {
    let mut checked = 0;
    // the small ids, up to three entries
    let small = entries(&[0, 1, 2, 3, 4], &[0, 1, 2, 3, 4], 0..=3);
    checked += each_list(&small, 3, &mut |l| {
        check_validate(l, validate(l));
        check_merge(l, &sort_and_merge(l));
    });
    // the ends of both id spaces, together with the small ones
    let ids = both(4, 4);
    let ends = entries(&ids, &ids, 0..=3);
    checked += each_list(&ends, 2, &mut |l| {
        check_validate(l, validate(l));
        check_merge(l, &sort_and_merge(l));
    });
    // the entries that fill the ids to the last one
    let wide = [
        m(0, 0, MAX),
        m(0, 0, MAX - 1),
        m(1, 1, MAX - 1),
        m(MAX - 1, 0, 1),
    ];
    checked += each_list(&wide, 2, &mut |l| {
        check_validate(l, validate(l));
        check_merge(l, &sort_and_merge(l));
    });
    checked
}

/// More entries than the kernel accepts, and the one that is at the limit.
fn walk_extents() -> usize {
    let many: Vec<Map> = (0..MAX_EXTENTS as u32 + 1)
        .map(|i| m(2 * i, 2 * i, 1))
        .collect();
    check_validate(&many, validate(&many));
    check_validate(&many[..MAX_EXTENTS], validate(&many[..MAX_EXTENTS]));
    check_merge(&many, &sort_and_merge(&many));
    2
}

fn walk_break_insert() -> usize {
    let mut checked = 0;
    let small = entries(&[0, 1, 2, 3, 4], &[0, 1, 2, 3, 4], 0..=3);
    let ids = both(4, 4);
    let ends = entries(&ids, &ids, 0..=3);
    for (mappings, exts, len) in [(&small, &small, 2), (&ends, &ends, 1)] {
        for ext in exts {
            checked += each_list(mappings, len, &mut |l| {
                check_break_insert(l, *ext, &break_insert(l, *ext));
            });
        }
    }
    checked
}

/// The extents of a parent namespace that are around `base`, and the
/// entries whose parent ids are in them.
fn walk_split_around(base: u32) -> usize {
    let ids: Vec<u32> = (base..base + 6).collect();
    let parents_all = entries(&ids, &[0, 1], 1..=3);
    let mappings = entries(&ids[..3], &ids, 0..=4);
    let mut checked = 0;
    each_list(&parents_all, 2, &mut |parent| {
        if !is_valid(parent) {
            return;
        }
        let granted = containers(parent);
        let ok: Vec<Map> = mappings
            .iter()
            .copied()
            .filter(|e| {
                (0..u64::from(e.size)).all(|k| granted.contains(&(u64::from(e.parent_id) + k)))
            })
            .collect();
        checked += each_list(&ok, 2, &mut |l| {
            check_split(l, parent, &split_on(l, parent))
        });
    });
    checked
}

fn walk_split() -> usize {
    walk_split_around(0) + walk_split_around(MAX - 8)
}

fn walk_fill() -> usize {
    let mut checked = 0;
    let all = sets(&[small_ids(), end_ids()].concat());
    let ids = both(4, 4);
    let ends = entries(&ids, &ids, 0..=3);
    for avail in &all {
        checked += each_list(&ends, 1, &mut |l| check_fill(l, avail, &fill(l, avail)));
    }
    let small = entries(&[0, 1, 2, 3], &[0, 1, 2, 3], 0..=3);
    for avail in sets(&small_ids()).iter() {
        checked += each_list(&small, 2, &mut |l| check_fill(l, avail, &fill(l, avail)));
    }
    checked
}

fn walk_auto() -> usize {
    let mut checked = 0;
    let mut go = |size: u32, pool: &IdSet, used: &IdSet, extra: &[Map]| {
        check_auto(size, pool, used, extra, auto_map(size, pool, used, extra));
        checked += 1;
    };
    let pools = sets(&[small_ids(), end_ids()].concat());
    let low = sets(&small_ids());
    for size in 0..=5 {
        for pool in &pools {
            for used in &pools {
                go(size, pool, used, &[]);
            }
        }
    }
    let one = entries(&[0, 1, 2, 3, MAX - 1, MAX], &both(4, 3), 0..=3);
    for size in 0..=4 {
        for pool in &pools {
            for used in low.iter().step_by(3) {
                for e in &one {
                    go(size, pool, used, &[*e]);
                }
            }
        }
    }
    // (the sets of used ids are sampled here and above: every third and
    // every fifth of the 16 that are made of the small ids)
    let two = entries(&[0, 1, 2, 3], &[0, 1, 2, 3], 0..=2);
    for size in 0..=4 {
        for pool in &low {
            for used in low.iter().step_by(5) {
                each_list(&two, 2, &mut |l| go(size, pool, used, l));
            }
        }
    }
    checked
}

fn walk_keep_id() -> usize {
    let ids: Vec<u32> = (0..8).chain([MAX - 2, MAX - 1, MAX]).collect();
    let mut sizes: Vec<Option<u32>> = vec![None];
    sizes.extend((0..10).chain([MAX - 1, MAX]).map(Some));
    let mut checked = 0;
    for &id in &ids {
        for &sub in &ids {
            for &size in &sizes {
                check_keep_id(id, sub, size, &keep_id(id, sub, size));
                checked += 1;
            }
        }
    }
    checked
}

fn walk_sets() -> usize {
    let all = sets(&[small_ids(), end_ids()].concat());
    for a in &all {
        for b in &all {
            check_sets(a, b);
        }
    }
    // the intervals of the list in any order, empty or not
    let mut one = Vec::new();
    for ends in [
        (0..5).collect::<Vec<u64>>(),
        (ID_LIMIT - 2..ID_LIMIT + 3).collect(),
    ] {
        for &s in &ends {
            for &e in &ends {
                one.push((s, e));
            }
        }
    }
    let mut checked = 0;
    for a in &one {
        for b in &one {
            for c in [(0, 0), (2, 3)] {
                let list = [*a, *b, c];
                let set = IdSet::from_intervals(&list);
                let mut want = std::collections::BTreeSet::new();
                for &(s, e) in &list {
                    want.extend(s..e);
                }
                assert_eq!(explicit(&set), want, "{list:?}");
                check_sets(&set, &set);
                checked += 1;
            }
        }
    }
    all.len() * all.len() + checked
}

/// The ones that are too big to spell out.
#[test]
fn the_whole_range_of_ids() {
    let full = IdSet::from_intervals(&[(0, ID_LIMIT)]);
    let none = IdSet::default();
    assert_eq!(auto_map(MAX, &full, &none, &[]), Ok(vec![m(0, 0, MAX)]));
    assert_eq!(
        auto_map(MAX, &full, &IdSet::from_intervals(&[(5, 6)]), &[]),
        Err(AutoFault::NoSpace(u64::from(MAX)))
    );
    assert_eq!(
        auto_map(MAX, &full, &none, &[m(MAX - 1, 1, 1)]),
        Ok(vec![m(0, 0, 1), m(1, 2, MAX - 2), m(MAX - 1, 1, 1)])
    );
    assert_eq!(
        fill(
            &[m(0, 0, MAX - 2)],
            &IdSet::from_intervals(&[(1, 2), (5, 6), (7, 8)])
        ),
        [m(0, 0, MAX - 2), m(MAX - 2, 1, 1), m(MAX - 1, 5, 1)]
    );
    assert_eq!(fill(&[m(0, 0, MAX)], &full), [m(0, 0, MAX)]);
    assert_eq!(fill(&[], &full), [m(0, 0, MAX)]);
}

/// Every range of every list: the ranges that are in an entry and the ones
/// that are not.
fn walk_range() -> usize {
    let ids = both(4, 3);
    let ents = entries(&ids, &ids, 0..=3);
    let mut checked = 0;
    for start in ids.iter().copied().chain([5]) {
        for len in 0..=4 {
            checked += each_list(&ents, 2, &mut |l| {
                check_range(l, start, len, range_to_parent(l, start, len));
            });
        }
    }
    checked
}

/// The ids of a set are any `u64`: nothing wraps at the end of them.
#[test]
fn sets_up_to_the_last_u64() {
    let top = IdSet::from_intervals(&[(u64::MAX - 3, u64::MAX), (0, u64::MAX - 2)]);
    assert_eq!(top.intervals(), [(0, u64::MAX)]);
    assert_eq!(top.size(), u64::MAX);
    assert_eq!(
        top.find_available(u64::MAX).map(|s| s.size()),
        Some(u64::MAX)
    );
    assert!(top.find_available(u64::MAX).is_some());
    assert!(top.contains_range(u64::MAX - 1, 1));
    assert!(!top.contains_range(u64::MAX - 1, 2));
    assert!(!top.contains_range(u64::MAX, 1));
    assert!(top.subtract(&top).is_empty());
    assert_eq!(top.below(ID_LIMIT).size(), ID_LIMIT);
    // the ids that 32 bits cannot hold are not paired
    let high = IdSet::from_intervals(&[(1 << 32, 1 << 33)]);
    assert!(high.zip(&top).is_empty());
    assert!(top.zip(&high).is_empty());
    assert_eq!(
        auto_map(3, &high, &IdSet::default(), &[]),
        Err(AutoFault::NoSpace(3))
    );
}

/// An empty entry of the user is refused, also when it would have gone
/// into the one that comes before it.
#[test]
fn an_empty_extra_entry_is_refused() {
    let pool = IdSet::from_intervals(&[(10, 20)]);
    let none = IdSet::default();
    for extra in [m(4, 14, 0), m(9, 9, 0)] {
        assert_eq!(
            auto_map(4, &pool, &none, &[extra]),
            Err(AutoFault::Invalid(Fault::Empty(0)))
        );
    }
    // the faults of the entries come before the lack of ids
    assert_eq!(
        auto_map(4, &none, &none, &[m(4, 14, 0)]),
        Err(AutoFault::Invalid(Fault::Empty(0)))
    );
}

#[test]
fn every_list_of_entries() {
    // 1 + 100 + 100^2 + 100^3, 1 + 256 + 256^2, 1 + 4 + 16
    assert_eq!(walk_lists(), 1_010_101 + 65_793 + 21);
}

/// A pool in as many pieces as the kernel accepts entries, and one more.
#[test]
fn a_pool_in_too_many_pieces() {
    let pieces = |n: u64| {
        let list: Vec<(u64, u64)> = (0..n).map(|i| (2 * i + 1, 2 * i + 2)).collect();
        IdSet::from_intervals(&list)
    };
    let none = IdSet::default();
    let n = MAX_EXTENTS as u32;
    let ok = auto_map(n, &pieces(u64::from(n)), &none, &[]).unwrap();
    assert_eq!(ok.len(), MAX_EXTENTS);
    assert_eq!(
        auto_map(n + 1, &pieces(u64::from(n) + 1), &none, &[]),
        Err(AutoFault::TooMany(MAX_EXTENTS + 1))
    );
    // with more ids than the size needs the first ones are used: no more pieces
    assert!(auto_map(n, &pieces(u64::from(n) + 1), &none, &[]).is_ok());
}

#[test]
fn more_than_the_kernel_accepts() {
    assert_eq!(walk_extents(), 2);
}

#[test]
fn every_entry_broken_into_a_mapping() {
    // 100 entries to insert in the 10101 lists of up to two, 256 in the 257
    assert_eq!(walk_break_insert(), 100 * 10_101 + 256 * 257);
}

#[test]
fn every_split_on_the_extents_of_a_parent() {
    // (what the generators make: one that shrinks by mistake changes it)
    assert_eq!(walk_split(), 379_854);
}

#[test]
fn every_fill() {
    // 256 sets of ids in the 257 lists of ends, 16 in the 4161 small ones
    assert_eq!(walk_fill(), 256 * 257 + 16 * 4161);
}

#[test]
fn every_automatic_mapping() {
    // none extra: 6 sizes, 256 pools, 256 used; one: 5 sizes, 256 pools, 6
    // used, 168 entries; two: 5 sizes, 16 pools, 4 used, 2353 lists
    assert_eq!(
        walk_auto(),
        6 * 256 * 256 + 5 * 256 * 6 * 168 + 5 * 16 * 4 * 2353
    );
}

#[test]
fn every_range_to_parent() {
    // 8 starts and 5 lengths, in the 1 + 196 + 196^2 lists of up to two of
    // the 7 * 7 * 4 entries
    assert_eq!(walk_range(), 8 * 5 * (1 + 196 + 196 * 196));
}

#[test]
fn every_keep_id() {
    assert_eq!(walk_keep_id(), 11 * 11 * 13);
}

#[test]
fn every_set_of_ids() {
    // every two of 256 sets, and 50 * 50 pairs of intervals with each of two
    // more
    assert_eq!(walk_sets(), 256 * 256 + 2 * 50 * 50);
}
