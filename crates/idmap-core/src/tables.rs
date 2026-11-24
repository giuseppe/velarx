// SPDX-License-Identifier: Apache-2.0
//! The cases of podman (`pkg/util/utils_test.go`) and the edges of the
//! arithmetic, as they were pinned in `velarx-base` before the algebra moved
//! here: one table for each function that `rules` and `walk` check in
//! general.

use super::*;

const MAX: u32 = u32::MAX;

fn m(c: u32, h: u32, n: u32) -> Map {
    Map {
        container_id: c,
        parent_id: h,
        size: n,
    }
}

#[test]
fn pin_break_insert() {
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
fn pin_fill_id_map() {
    let avail = IdSet::from_intervals(&[(0, 10), (10000, 20000)]);
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
fn pin_available_ranges() {
    let all = IdSet::from_intervals(&[(0, 30), (50, 70)]);
    let used = IdSet::from_intervals(&[(2, 4), (25, 55)]);
    assert_eq!(all.subtract(&used).intervals(), [(0, 2), (4, 25), (55, 70)]);
}

#[test]
fn pin_find_available_spans_intervals() {
    let s = IdSet::from_intervals(&[(0, 2), (10, 20)]);
    assert_eq!(s.find_available(5).unwrap().intervals(), [(0, 2), (10, 13)]);
    assert_eq!(s.find_available(12).unwrap().size(), 12);
    assert_eq!(s.find_available(13), None);
    assert_eq!(
        s.find_available(5)
            .unwrap()
            .zip(&IdSet::from_intervals(&[(0, 5)])),
        [m(0, 0, 2), m(2, 10, 3)]
    );
}

#[test]
fn pin_idset_ops() {
    let a = IdSet::from_intervals(&[(5, 10), (0, 3), (3, 4), (9, 12)]);
    assert_eq!(a.intervals(), [(0, 4), (5, 12)]);
    assert!(a.contains_range(11, 1) && !a.contains_range(4, 1) && !a.contains_range(12, 1));
    assert!(a.contains_range(5, 7) && !a.contains_range(3, 3) && a.contains_range(9, 0));
    let b = IdSet::from_intervals(&[(2, 7)]);
    assert_eq!(a.subtract(&b).intervals(), [(0, 2), (7, 12)]);
    assert_eq!(a.union(&b).intervals(), [(0, 12)]);
    assert_eq!(a.size(), 11);
    assert!(IdSet::default().is_empty());
}

#[test]
fn table_idset_from_intervals() {
    let set = |v: &[(u64, u64)]| IdSet::from_intervals(v);
    assert!(set(&[]).is_empty());
    assert!(set(&[(3, 3), (9, 2)]).is_empty());
    // adjacent ranges are one, in any order
    assert_eq!(set(&[(4, 8), (0, 4)]).intervals(), [(0, 8)]);
    // overlapping, one inside the other, and a gap of one id
    assert_eq!(
        set(&[(0, 10), (2, 3), (5, 12), (13, 14)]).intervals(),
        [(0, 12), (13, 14)]
    );
    // the end of the ids: the last valid one and the first past them
    let top = u64::from(MAX);
    assert_eq!(
        set(&[(top - 2, top), (top, top + 5)]).intervals(),
        [(top - 2, top + 5)]
    );
    assert_eq!(set(&[(0, top), (0, top)]).size(), top);
}

#[test]
fn table_idset_subtract_union() {
    let set = |v: &[(u64, u64)]| IdSet::from_intervals(v);
    let a = set(&[(0, 4), (6, 10)]);
    for (b, sub, uni) in [
        (set(&[]), vec![(0, 4), (6, 10)], vec![(0, 4), (6, 10)]),
        (set(&[(0, 10)]), vec![], vec![(0, 10)]),
        (set(&[(4, 6)]), vec![(0, 4), (6, 10)], vec![(0, 10)]),
        (
            set(&[(1, 2)]),
            vec![(0, 1), (2, 4), (6, 10)],
            vec![(0, 4), (6, 10)],
        ),
        (set(&[(3, 7)]), vec![(0, 3), (7, 10)], vec![(0, 10)]),
        (set(&[(0, 4)]), vec![(6, 10)], vec![(0, 4), (6, 10)]),
        (set(&[(9, 20)]), vec![(0, 4), (6, 9)], vec![(0, 4), (6, 20)]),
        (
            set(&[(10, 12)]),
            vec![(0, 4), (6, 10)],
            vec![(0, 4), (6, 12)],
        ),
        (
            set(&[(11, 12)]),
            vec![(0, 4), (6, 10)],
            vec![(0, 4), (6, 10), (11, 12)],
        ),
        (
            set(&[(1, 2), (3, 7), (9, 11)]),
            vec![(0, 1), (2, 3), (7, 9)],
            vec![(0, 11)],
        ),
    ] {
        assert_eq!(a.subtract(&b).intervals(), sub, "{b:?}");
        assert_eq!(a.union(&b).intervals(), uni, "{b:?}");
    }
    assert!(IdSet::default().subtract(&a).is_empty());
    let top = u64::from(MAX);
    let all = set(&[(0, top)]);
    assert_eq!(
        all.subtract(&set(&[(top - 1, top)])).intervals(),
        [(0, top - 1)]
    );
    assert_eq!(all.subtract(&set(&[(0, 1)])).intervals(), [(1, top)]);
}

#[test]
fn table_idset_find_available_and_contains() {
    let s = IdSet::from_intervals(&[(2, 5), (8, 9)]);
    for (n, got) in [
        (0, Some(vec![])),
        (1, Some(vec![(2, 3)])),
        (3, Some(vec![(2, 5)])),
        (4, Some(vec![(2, 5), (8, 9)])),
        (5, None),
    ] {
        assert_eq!(
            s.find_available(n).map(|f| f.intervals().to_vec()),
            got,
            "{n}"
        );
    }
    assert_eq!(IdSet::default().find_available(1), None);
    assert!(IdSet::default().find_available(0).unwrap().is_empty());
    for (start, len, yes) in [
        (2, 3, true),
        (2, 4, false),
        (4, 1, true),
        (4, 2, false),
        (5, 0, true),
        (7, 0, true),
        (8, 1, true),
        (8, 2, false),
        (1, 1, false),
        (0, 100, false),
    ] {
        assert_eq!(s.contains_range(start, len), yes, "{start} {len}");
    }
}

#[test]
fn table_zip() {
    let set = |v: &[(u64, u64)]| IdSet::from_intervals(v);
    // one side runs out first, either one
    assert_eq!(set(&[(10, 12)]).zip(&set(&[(0, 5)])), [m(0, 10, 2)]);
    assert_eq!(set(&[(10, 15)]).zip(&set(&[(0, 2)])), [m(0, 10, 2)]);
    assert!(set(&[]).zip(&set(&[(0, 5)])).is_empty());
    assert!(set(&[(0, 5)]).zip(&set(&[])).is_empty());
    // runs cut at the end of either side
    assert_eq!(
        set(&[(10, 13), (20, 22)]).zip(&set(&[(0, 2), (5, 8)])),
        [m(0, 10, 2), m(5, 12, 1), m(6, 20, 2)]
    );
    // the last ids
    let top = u64::from(MAX);
    assert_eq!(
        set(&[(top - 3, top)]).zip(&set(&[(0, 3)])),
        [m(0, MAX - 3, 3)]
    );
}

#[test]
fn table_break_insert() {
    let none: [Map; 0] = [];
    assert_eq!(break_insert(&none, m(3, 4, 5)), [m(3, 4, 5)]);
    for (piece, ext, want) in [
        // nothing in common
        (m(0, 0, 10), m(20, 20, 2), vec![m(0, 0, 10)]),
        // inside, in the container ids
        (m(0, 0, 10), m(3, 100, 2), vec![m(0, 0, 3), m(5, 5, 5)]),
        // inside, in the parent ids
        (m(0, 0, 10), m(100, 4, 2), vec![m(0, 0, 4), m(6, 6, 4)]),
        // different places of the piece on both sides
        (
            m(0, 0, 10),
            m(1, 7, 2),
            vec![m(0, 0, 1), m(3, 3, 4), m(9, 9, 1)],
        ),
        // the two cuts overlap
        (m(0, 0, 10), m(2, 4, 4), vec![m(0, 0, 2), m(8, 8, 2)]),
        // at the start, at the end, all of it
        (m(0, 0, 10), m(0, 50, 3), vec![m(3, 3, 7)]),
        (m(0, 0, 10), m(7, 50, 3), vec![m(0, 0, 7)]),
        (m(5, 5, 2), m(0, 0, 100), vec![]),
        // one id at either side of the piece
        (m(5, 5, 2), m(4, 40, 1), vec![m(5, 5, 2)]),
        (m(5, 5, 2), m(7, 70, 1), vec![m(5, 5, 2)]),
        // the extension continues the piece: both stay
        (m(0, 0, 4), m(4, 4, 4), vec![m(0, 0, 4)]),
        // a piece that does not map to itself
        (m(10, 0, 10), m(12, 50, 2), vec![m(10, 0, 2), m(14, 4, 6)]),
        (m(10, 0, 10), m(50, 3, 2), vec![m(10, 0, 3), m(15, 5, 5)]),
    ] {
        let mut want = want;
        want.push(ext);
        assert_eq!(break_insert(&[piece], ext), want, "{piece:?} {ext:?}");
    }
    // the last ids
    assert_eq!(
        break_insert(&[m(0, 0, MAX)], m(MAX - 2, MAX - 2, 1)),
        [
            m(0, 0, MAX - 2),
            m(MAX - 1, MAX - 1, 1),
            m(MAX - 2, MAX - 2, 1)
        ]
    );
    assert_eq!(
        break_insert(&[m(MAX - 5, MAX - 5, 5)], m(0, MAX - 3, 2)),
        [
            m(MAX - 5, MAX - 5, 2),
            m(MAX - 1, MAX - 1, 1),
            m(0, MAX - 3, 2)
        ]
    );
    // several pieces, in order
    assert_eq!(
        break_insert(&[m(0, 0, 4), m(10, 10, 4)], m(2, 12, 1)),
        [
            m(0, 0, 2),
            m(3, 3, 1),
            m(10, 10, 2),
            m(13, 13, 1),
            m(2, 12, 1)
        ]
    );
}

#[test]
fn table_fill() {
    let set = |v: &[(u64, u64)]| IdSet::from_intervals(v);
    // nothing available: the entries as they are, sorted and merged
    assert_eq!(fill(&[m(5, 5, 1), m(0, 0, 5)], &set(&[])), [m(0, 0, 6)]);
    // nothing mapped: the ids start at zero
    assert_eq!(fill(&[], &set(&[(5, 8)])), [m(0, 5, 3)]);
    // the holes of the container ids in order, then what follows
    assert_eq!(
        fill(&[m(0, 100, 2), m(3, 200, 1)], &set(&[(0, 1), (50, 53)])),
        [m(0, 100, 2), m(2, 0, 1), m(3, 200, 1), m(4, 50, 3)]
    );
    // every container id is taken
    assert_eq!(fill(&[m(0, 0, MAX)], &set(&[(1000, 2000)])), [m(0, 0, MAX)]);
    // the available ids continue the mapping: one entry
    assert_eq!(fill(&[m(0, 0, 10)], &set(&[(10, 12)])), [m(0, 0, 12)]);
    // the last container ids go to the available ids
    assert_eq!(
        fill(&[m(0, 0, MAX - 2)], &set(&[(MAX as u64, MAX as u64)])),
        [m(0, 0, MAX - 2)]
    );
    assert_eq!(
        fill(&[m(0, 0, MAX - 2)], &set(&[(1, 2), (5, 6), (7, 8)])),
        [m(0, 0, MAX - 2), m(MAX - 2, 1, 1), m(MAX - 1, 5, 1)]
    );
}
