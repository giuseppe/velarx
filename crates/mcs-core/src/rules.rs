// SPDX-License-Identifier: Apache-2.0
//! The rules of the levels, checked on every answer of the functions of the
//! crate.  They are stated with the standard library's text functions and
//! sorted lists of numbers, not with the bit sets and the byte loops of the
//! functions, so that a mistake of the loops does not repeat in the check.
//!
//! The claim, and where each rule is:
//! - a level is taken exactly when it is a sensitivity (or a dash-separated
//!   list of them) and, after a colon, a comma-separated list of categories
//!   and ranges below 1024, and the categories it gives are those spelled:
//!   `check_parse`; so no level that is taken has a byte outside
//!   `s c 0-9 - : , .`: `check_alphabet`;
//! - two levels overlap when both have categories and one's are all in the
//!   other's, a level that is none overlaps everything, and it is the same
//!   for the spelling of a level: `check_overlap`;
//! - a pair label is `s0:cA,cB`, is taken, and is read back as its pair, and
//!   a level that reads as a pair is that pair's label: `check_pair`;
//! - `contains(a, b)`: both are taken, `b` has categories, and all of them
//!   are in `a`: `check_contains`;
//! - a level that a user may give (`strict`) is one that is taken, with at
//!   most two sensitivities and no number with a leading zero: `check_strict`;
//! - what `pick` gives, from the attempts in order, in two passes: the first
//!   attempt whose pair reaches none of the used levels; only when there is
//!   none, the first whose pair is not equal to or a superset of a used level
//!   that has categories (so a pair inside a wide level in use is taken, but
//!   a pair never is the same set as one in use).  The label is two distinct
//!   categories in order, and nothing is given only when both passes find
//!   none: `check_pick`;
//! - the level of a context is what follows its third colon:
//!   `check_context`.

use super::*;

/// The categories of `level` by the plain way: the sensitivity part, then the
/// items one by one.  `None` when it is not a level.
pub(crate) fn oracle(level: &str) -> Option<Vec<u16>> {
    let (sens, cats) = match level.split_once(':') {
        Some((s, c)) => (s, Some(c)),
        None => (level, None),
    };
    let one = |s: &str| {
        s.strip_prefix('s')
            .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
    };
    if !sens.split('-').all(one) {
        return None;
    }
    let category = |c: &str| -> Option<u16> {
        c.strip_prefix('c')
            .filter(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))?
            .parse()
            .ok()
            .filter(|n| *n < CATEGORIES)
    };
    let mut out = Vec::new();
    for item in cats.into_iter().flat_map(|c| c.split(',')) {
        match item.split_once('.') {
            Some((lo, hi)) => {
                let (lo, hi) = (category(lo)?, category(hi)?);
                if lo > hi {
                    return None;
                }
                out.extend(lo..=hi);
            }
            None => out.push(category(item)?),
        }
    }
    out.sort_unstable();
    out.dedup();
    Some(out)
}

fn members(c: &Cats) -> Vec<u16> {
    (0..CATEGORIES).filter(|n| c.has(*n)).collect()
}

pub(crate) fn check_parse(level: &str) {
    let got = parse(level.as_bytes());
    let want = oracle(level);
    assert_eq!(got.as_ref().map(members), want, "{level:?}");
    if let Some(c) = got {
        assert_eq!(c.count() as usize, want.unwrap().len(), "{level:?}");
        assert_eq!(c.is_empty(), members(&c).is_empty(), "{level:?}");
    }
}

pub(crate) fn check_alphabet(level: &str) {
    if parse(level.as_bytes()).is_some() {
        assert!(
            level.bytes().all(|b| b"sc0123456789-:,.".contains(&b)),
            "{level:?}"
        );
    }
}

pub(crate) fn check_overlap(a: &str, b: &str) {
    let want = match (oracle(a), oracle(b)) {
        (Some(x), Some(y)) => {
            !x.is_empty()
                && !y.is_empty()
                && (x.iter().all(|c| y.contains(c)) || y.iter().all(|c| x.contains(c)))
        }
        _ => true,
    };
    assert_eq!(overlap(a.as_bytes(), b.as_bytes()), want, "{a:?} {b:?}");
    assert_eq!(overlap(b.as_bytes(), a.as_bytes()), want, "{b:?} {a:?}");
}

pub(crate) fn check_pair(low: u16, high: u16) {
    let label = pair_label(low, high);
    if low < high && high < CATEGORIES {
        let text = format!("s0:c{low},c{high}");
        let label = label.unwrap();
        assert_eq!(label.as_bytes(), text.as_bytes());
        assert!(parse(label.as_bytes()).is_some());
        assert_eq!(read_pair(text.as_bytes()), Some((low, high)));
        assert_eq!(oracle(&text), Some(vec![low, high]));
    } else {
        assert!(label.is_none(), "{low} {high}");
    }
}

/// A level that reads as a pair is the label of that pair.
pub(crate) fn check_read(level: &str) {
    if let Some((low, high)) = read_pair(level.as_bytes()) {
        assert_eq!(level, format!("s0:c{low},c{high}"));
        assert!(low < high && high < CATEGORIES);
    } else if let Some(c) = oracle(level) {
        let canonical = c.len() == 2 && level == format!("s0:c{},c{}", c[0], c[1]);
        assert!(!canonical, "{level:?}");
    }
}

pub(crate) fn check_pick(rand: &[u32], used: &[&str]) {
    let used_bytes: Vec<Vec<u8>> = used.iter().map(|u| u.as_bytes().to_vec()).collect();
    let got = pick(rand, &used_bytes);
    let attempt = |a: usize| {
        let first = (rand[a] % 1024) as u16;
        let second = {
            let s = (rand[a + 1] % 1023) as u16;
            if s >= first {
                s + 1
            } else {
                s
            }
        };
        (first.min(second), first.max(second))
    };
    let attempts: Vec<(u16, u16)> = (0..rand.len() / 2).map(|n| attempt(2 * n)).collect();
    let text = |(low, high): (u16, u16)| format!("s0:c{low},c{high}");
    let apart = |p: &(u16, u16)| used.iter().all(|u| !oracle_overlap(&text(*p), u));
    let not_inside = |p: &(u16, u16)| used.iter().all(|u| !oracle_contains(&text(*p), u));
    let want = attempts
        .iter()
        .find(|p| apart(p))
        .or_else(|| attempts.iter().find(|p| not_inside(p)));
    match (got, want) {
        (None, None) => {}
        (Some(label), Some(p)) => {
            assert_eq!(label.as_bytes(), text(*p).as_bytes(), "{rand:?} {used:?}");
            assert!(p.0 < p.1 && p.1 < 1024);
            assert!(not_inside(p));
            // an attempt that reaches nothing is always preferred
            if attempts.iter().any(apart) {
                assert!(apart(p));
            }
        }
        (g, w) => panic!("{rand:?} {used:?}: got {g:?}, want {w:?}"),
    }
}

fn oracle_overlap(a: &str, b: &str) -> bool {
    match (oracle(a), oracle(b)) {
        (Some(x), Some(y)) => {
            !x.is_empty()
                && !y.is_empty()
                && (x.iter().all(|c| y.contains(c)) || y.iter().all(|c| x.contains(c)))
        }
        _ => true,
    }
}

/// `outer` has all the categories of `inner`, which has some.
fn oracle_contains(outer: &str, inner: &str) -> bool {
    match (oracle(outer), oracle(inner)) {
        (Some(o), Some(i)) => !i.is_empty() && i.iter().all(|c| o.contains(c)),
        _ => false,
    }
}

pub(crate) fn check_contains(a: &str, b: &str) {
    assert_eq!(
        contains(a.as_bytes(), b.as_bytes()),
        oracle_contains(a, b),
        "{a:?} {b:?}"
    );
}

/// A level a user may give, from the text: the numbers after `s` and `c`
/// have no leading zero, and there are one or two sensitivities.
pub(crate) fn check_strict(level: &str) {
    let plain = |n: &str| n == "0" || !n.starts_with('0');
    let want = oracle(level).is_some() && {
        let (sens, cats) = match level.split_once(':') {
            Some((s, c)) => (s, c),
            None => (level, ""),
        };
        sens.split('-').count() <= 2
            && sens.split('-').all(|s| plain(&s[1..]))
            && cats
                .split([',', '.'])
                .all(|c| c.is_empty() || plain(&c[1..]))
    };
    assert_eq!(strict(level.as_bytes()), want, "{level:?}");
    if strict(level.as_bytes()) {
        assert!(parse(level.as_bytes()).is_some(), "{level:?}");
    }
}

pub(crate) fn check_context(context: &str) {
    let want: Vec<usize> = context
        .char_indices()
        .filter(|(_, c)| *c == ':')
        .map(|(i, _)| i)
        .take(3)
        .collect();
    match context_colons(context.as_bytes()) {
        Some(at) => assert_eq!(at.to_vec(), want, "{context:?}"),
        None => assert!(want.len() < 3, "{context:?}"),
    }
}
