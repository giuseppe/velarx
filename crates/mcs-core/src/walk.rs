// SPDX-License-Identifier: Apache-2.0
//! The inputs of the world, every one of them, and the rules checked on each
//! answer (see `rules`): every string up to six bytes of the alphabet of a
//! level, a table of the edges that the alphabet does not reach (numbers at
//! 1023, 1024 and beyond a `u16`), every pair of categories, every attempt
//! of the random numbers, and the used levels that block a pair.

use super::rules::*;
use super::*;

/// Every string of up to `max` bytes over `alphabet`.
fn strings(alphabet: &[&str], max: usize) -> Vec<String> {
    let mut all = vec![String::new()];
    let mut from = 0;
    for _ in 0..max {
        let to = all.len();
        for i in from..to {
            for a in alphabet {
                all.push(format!("{}{a}", all[i]));
            }
        }
        from = to;
    }
    all
}

fn pick_str(rand: &[u32], used: &[&str]) -> Option<Label> {
    let used: Vec<Vec<u8>> = used.iter().map(|u| u.as_bytes().to_vec()).collect();
    pick(rand, &used)
}

const ALPHABET: [&str; 9] = ["s", "0", "1", "-", ":", "c", ",", ".", "9"];

const EDGES: [&str; 44] = [
    "s00",
    "s0-s1-s2",
    "s0:c00",
    "s0:c10.c01",
    "s0:c1023",
    "s0:c1024",
    "s0:c1025",
    "s0:c10230",
    "s0:c65535",
    "s0:c65536",
    "s0:c99999999999",
    "s0:c0000000000000000000001",
    "s0:c1023.c1023",
    "s0:c1023.c1024",
    "s0:c0.c1023",
    "s0:c0.c1023,c5",
    "s0:c1000.c1023,c0.c10",
    "s0-s15:c0.c1023",
    "s0-s0-s0:c3",
    "s99999999999999999999:c1",
    "s0:c1,c2,c3,c4,c5,c6,c7,c8,c9,c10",
    "s0:c1\"",
    "s0:c1,c2\",context=x",
    "s0:c1\n",
    "s0:c١",
    "s٠",
    "s0\0",
    "S0",
    "s0:C1",
    "s0:c+1",
    "s0:c-1",
    "s0:c 1",
    "s0::c1",
    "s0:c1:c2",
    "s0:c1..c2",
    "s0:c5.c3",
    "s0:c1.c2.c3",
    "s0:c1,c1",
    "s0:c3.c3",
    "s0:c2,c1",
    "s0:c01,c2",
    "s0:c1.c2",
    "s0:c1,c2,c3",
    "s0-s5:c1,c2",
];

#[test]
fn every_small_string_and_the_edges() {
    let all = strings(&ALPHABET, 6);
    assert_eq!(all.len(), (0..=6).map(|n| 9usize.pow(n)).sum::<usize>());
    for s in all.iter().map(String::as_str).chain(EDGES) {
        check_parse(s);
        check_strict(s);
        check_alphabet(s);
        check_read(s);
        check_context(s);
    }
    let taken = all.iter().filter(|s| parse(s.as_bytes()).is_some()).count();
    assert!(taken > 100, "{taken}");
}

#[test]
fn every_pair_of_small_strings_overlaps_as_the_sets_say() {
    let small: Vec<String> = strings(&ALPHABET, 4)
        .into_iter()
        .filter(|s| parse(s.as_bytes()).is_some())
        .collect();
    assert!(small.len() > 20, "{}", small.len());
    for a in small.iter().map(String::as_str).chain(EDGES) {
        for b in &small {
            check_overlap(a, b);
            check_contains(a, b);
        }
    }
    check_overlap("junk", "s0:c1");
    check_overlap("", "");
}

#[test]
fn every_pair_of_categories() {
    for low in 0..=CATEGORIES + 1 {
        for high in 0..=CATEGORIES + 1 {
            check_pair(low, high);
        }
    }
}

#[test]
fn every_first_attempt_gives_a_pair_and_each_pair_twice() {
    let mut seen = vec![0u8; 1024 * 1024];
    for r1 in 0..1024u32 {
        for r2 in 0..1023u32 {
            let l = pick(&[r1, r2], &[]).unwrap();
            let (low, high) = read_pair(l.as_bytes()).unwrap();
            seen[low as usize * 1024 + high as usize] += 1;
        }
    }
    for low in 0..1024usize {
        for high in 0..1024usize {
            let want = if low < high { 2 } else { 0 };
            assert_eq!(seen[low * 1024 + high], want, "{low} {high}");
        }
    }
    // numbers of any size are taken modulo
    for r in [u32::MAX, u32::MAX - 1, 1 << 31, 1024, 1023, 1022] {
        for s in [0, 1, 1022, 1023, 1024, u32::MAX] {
            check_pick(&[r, s], &[]);
        }
    }
}

#[test]
fn used_levels_block_what_they_reach() {
    let rand = [1, 0, 1, 1, 2, 3, 5, 5, 9, 8, 7, 7, 0, 4];
    let used_sets: [&[&str]; 14] = [
        &[],
        &["s0"],
        &["s0:c1,c2"],
        &["s0:c2,c1"],
        &["s0:c1"],
        &["s0:c1,c2,c3"],
        &["s0:c0.c1023"],
        &["s0:c1,c2", "s0:c2,c4", "s0:c6,c9"],
        &["junk"],
        &["s0:c5.c9", "s0:c2.c3", "s0:c0,c1"],
        &["s0-s5:c1,c2"],
        &["s0:c1.c2", "s0:c5"],
        &["s0:c1023"],
        &["s0:c1,c2", "s0", ""],
    ];
    for used in used_sets {
        for n in 0..=rand.len() {
            check_pick(&rand[..n], used);
        }
    }
    // a spelling that is not canonical blocks the pair all the same
    assert_eq!(pick_str(&[0, 0], &["s0:c1,c0"]), None);
    assert_eq!(
        pick_str(&[0, 0, 5, 6], &["s0:c1,c0"]).unwrap().as_bytes(),
        b"s0:c5,c7"
    );
    // every attempt blocked: nothing, and not a loop
    let all: Vec<u32> = (0..2000).collect();
    assert_eq!(
        pick_str(&all, &["s0:c0.c1023"]).unwrap().as_bytes(),
        b"s0:c0,c2"
    );
    assert_eq!(pick(&[], &[]), None);
    assert_eq!(pick(&[7], &[]), None);
}

#[test]
fn an_exhausted_pair_space_ends_in_none() {
    // c0..c1023 covered by 512 disjoint pairs leaves every pair with a
    // category of its own that other pairs share: a pair is free only if it
    // is not equal to, and does not contain, a used pair
    let used: Vec<String> = (0..512)
        .map(|i| format!("s0:c{},c{}", 2 * i, 2 * i + 1))
        .collect();
    let used: Vec<&str> = used.iter().map(String::as_str).collect();
    let rand: Vec<u32> = (0..400).collect();
    check_pick(&rand, &used);
    // the pair (0, 2) shares categories with two used pairs but contains
    // neither: it is free
    assert_eq!(pick_str(&[0, 1], &used).unwrap().as_bytes(), b"s0:c0,c2");
}

/// Each case written from the rules of the levels, not from the code: the
/// categories a level has, as the list of its members.
#[test]
fn the_edges_by_the_rules() {
    let members = |l: &str| parse(l.as_bytes()).map(|c| (0..1024).filter(|n| c.has(*n)).collect());
    let all: Vec<u16> = (0..1024).collect();
    assert_eq!(members("s0"), Some(vec![]));
    assert_eq!(members("s0:c0.c1023"), Some(all.clone()));
    // a range of sensitivities: the categories are the ones written after it
    assert_eq!(members("s0-s0:c0.c1023"), Some(all));
    assert_eq!(members("s0-s15:c3"), Some(vec![3]));
    assert_eq!(members("s0:c1023"), Some(vec![1023]));
    assert_eq!(members("s0:c3.c3"), Some(vec![3]));
    // a category twice is one
    assert_eq!(members("s0:c1,c1,c2"), Some(vec![1, 2]));
    assert_eq!(members("s0:c2,c1.c3"), Some(vec![1, 2, 3]));
    // a range runs up: a reversed one is refused, not read as empty or flipped
    assert_eq!(members("s0:c5.c1"), None);
    // c1023 is the last category
    assert_eq!(members("s0:c1024"), None);
    assert_eq!(members("s0:c0.c1024"), None);
    // a colon with nothing after it, a trailing or a doubled comma
    assert_eq!(members("s0:"), None);
    assert_eq!(members("s0:c1,"), None);
    assert_eq!(members("s0:c1,,c2"), None);
    // a level in use may have a leading zero (`parse` is lenient), one a
    // user gives may not
    assert_eq!(members("s00:c01"), Some(vec![1]));
    assert!(!strict(b"s00") && !strict(b"s0:c01") && !strict(b"s0-s1-s2"));
    assert!(strict(b"s0") && strict(b"s0:c0") && strict(b"s0-s15:c0.c1023"));
    assert!(strict(b"s10:c10.c100") && strict(b"s0:c0,c10"));
}

/// A wide level in use does not stop a fresh pair, and no pair ever is the
/// same set as one in use.
#[test]
fn wide_levels_in_use() {
    let rand = [0, 0, 5, 6];
    for wide in ["s0:c0.c1023", "s0-s0:c0.c1023", "s0:c0.c1000"] {
        assert_eq!(
            pick_str(&rand, &[wide]).unwrap().as_bytes(),
            b"s0:c0,c1",
            "{wide}"
        );
    }
    // a pair that sticks out of the wide level reaches nothing: preferred
    assert_eq!(
        pick_str(&[0, 0, 1001, 1000], &["s0:c0.c1000"])
            .unwrap()
            .as_bytes(),
        b"s0:c1000,c1001"
    );
    // a pair that contains a level in use is refused in both passes
    assert_eq!(pick_str(&[1, 4], &["s0:c1"]), None);
    assert_eq!(pick_str(&[1, 4], &["s0:c1", "s0:c3.c1022"]), None);
    // a pair that is free is taken over an earlier one inside a used level
    assert_eq!(
        pick_str(&[0, 0, 10, 10], &["s0:c0,c1,c2"])
            .unwrap()
            .as_bytes(),
        b"s0:c10,c11"
    );
    // when every pair is inside, the first one is taken
    assert_eq!(
        pick_str(&[0, 0, 10, 10], &["s0:c0.c1023"])
            .unwrap()
            .as_bytes(),
        b"s0:c0,c1"
    );
}
