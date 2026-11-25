// SPDX-License-Identifier: Apache-2.0
//! The SELinux MCS levels of containers, as podman has them: what a level
//! given by a user or by the CRI may be (`s0`, `s0:c1,c2`, `s0-s15:c0.c1023`),
//! which levels reach each other's files, the fresh pair of categories of a
//! new container, and where the level of a full context
//! `user:role:type:level` starts.
//!
//! What this is for: a level that is taken has a sensitivity and categories
//! below 1024 and nothing else (so that it cannot carry a quote or a comma
//! into the `context=` of a mount), two levels are compared by the sets of
//! their categories and not by their spelling, and a fresh pair
//! reaches no level that is in use; when every pair does, because a level in
//! use is wide on purpose (`s0:c0.c1023`), the pair is at least not equal to
//! or a superset of any level in use.  `rules` states that for what these functions
//! answer, and `walk` checks it on every small input.
//!
//! What stays in the shell: the random numbers, the levels in use (the
//! database), the files of the policy, the parts of a label other than the
//! level, and the text of the errors.
//!
//! Written to be translated (tools/verify): bytes and numbers, loops with a
//! flag, no closure, no iterator adapter, no `String`.

/// The categories of a level are `c0` to `c1023`.
pub const CATEGORIES: u16 = 1024;

const WORDS: usize = 16;

/// A set of categories: bit `c % 64` of word `c / 64`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cats {
    words: [u64; WORDS],
}

impl Cats {
    /// No category.
    pub fn empty() -> Cats {
        Cats { words: [0; WORDS] }
    }

    /// `c` is in the set (false for `c` past the last category).
    pub fn has(&self, c: u16) -> bool {
        let c = c as usize;
        c < CATEGORIES as usize && (self.words[c / 64] >> (c % 64)) & 1 == 1
    }

    fn add(&mut self, c: u16) {
        let c = c as usize;
        self.words[c / 64] |= 1u64 << (c % 64);
    }

    /// No category in the set.
    pub fn is_empty(&self) -> bool {
        let mut i = 0;
        let mut empty = true;
        while i < WORDS {
            if self.words[i] != 0 {
                empty = false;
            }
            i += 1;
        }
        empty
    }

    /// How many categories are in the set (only the tests count them).
    #[cfg(test)]
    pub fn count(&self) -> u32 {
        let mut i = 0;
        let mut n = 0;
        while i < WORDS {
            n += self.words[i].count_ones();
            i += 1;
        }
        n
    }

    /// Every category of the set is in `other`.
    pub fn within(&self, other: &Cats) -> bool {
        let mut i = 0;
        let mut all = true;
        while i < WORDS {
            if self.words[i] & !other.words[i] != 0 {
                all = false;
            }
            i += 1;
        }
        all
    }
}

/// A category `cN` read at a place.
struct Read {
    /// The index after its digits.
    end: usize,
    value: u16,
    /// It is `c`, digits, and a number below `CATEGORIES`.
    ok: bool,
}

/// The category at `from`; the number saturates, so that `c` followed by any
/// number of digits is read without a wrap.
#[allow(clippy::manual_range_contains)] // (`contains` is a library call the proofs would model)
fn category(s: &[u8], from: usize) -> Read {
    let mut i = from;
    let mut value: u16 = 0;
    let mut digits: usize = 0;
    if i < s.len() && s[i] == b'c' {
        i += 1;
        while i < s.len() && s[i] >= b'0' && s[i] <= b'9' {
            value = value * 10 + (s[i] - b'0') as u16;
            if value > CATEGORIES {
                value = CATEGORIES;
            }
            digits += 1;
            i += 1;
        }
    }
    Read {
        end: i,
        value,
        ok: digits > 0 && value < CATEGORIES,
    }
}

/// The sensitivities `sN` or `sN-sM-...` in `s[..end]`: each is `s` and
/// digits, and a `-` is between two of them.
#[allow(clippy::manual_range_contains)] // (as in `category`)
fn sensitivities(s: &[u8], end: usize) -> bool {
    // one state, as the translator joins no flag with a counter: 0 is a
    // `s` next; 1 is digits next, none yet; 2 is digits, or a `-`
    let mut state = 0;
    let mut ok = true;
    let mut i = 0;
    while i < end {
        let b = s[i];
        if state == 0 && b == b's' {
            state = 1;
        } else if state >= 1 && b >= b'0' && b <= b'9' {
            state = 2;
        } else if state == 2 && b == b'-' {
            state = 0;
        } else {
            ok = false;
        }
        i += 1;
    }
    ok && state == 2
}

/// The categories of a level, or `None` when it is not one.  A level is a
/// sensitivity (or two or more, `s0-s15`) and, after a colon, categories
/// separated by commas, each `cN` or a range `cN.cM` with N <= M, all below
/// `CATEGORIES`.  The categories of the high part of a range of sensitivities
/// are the ones of the level.  `s0` has none; `s0,c1`, `s0:`, `s0:c1,`,
/// `s0:c1024` and every other string are none.
pub fn parse(level: &[u8]) -> Option<Cats> {
    let n = level.len();
    let mut colon = n;
    let mut found = false;
    let mut i = 0;
    while i < n {
        if !found && level[i] == b':' {
            colon = i;
            found = true;
        }
        i += 1;
    }
    let mut ok = sensitivities(level, colon);
    let mut cats = Cats::empty();
    if ok && found {
        let mut at = colon + 1;
        let mut more = true;
        while ok && more {
            let lo = category(level, at);
            ok = lo.ok;
            at = lo.end;
            if ok && at < n && level[at] == b'.' {
                let hi = category(level, at + 1);
                ok = hi.ok && lo.value <= hi.value;
                at = hi.end;
                let mut c = lo.value;
                while ok && c <= hi.value {
                    cats.add(c);
                    c += 1;
                }
            } else if ok {
                cats.add(lo.value);
            }
            if ok && at == n {
                more = false;
            } else if ok && level[at] == b',' {
                at += 1;
            } else {
                ok = false;
            }
        }
    }
    if ok {
        Some(cats)
    } else {
        None
    }
}

/// The level `outer` has all the categories of `inner`, and `inner` has some
/// (`s0` is inside nothing and holds nothing).  A level that is none is
/// neither.
pub fn contains(outer: &[u8], inner: &[u8]) -> bool {
    match (parse(outer), parse(inner)) {
        (Some(o), Some(i)) => !i.is_empty() && i.within(&o),
        _ => false,
    }
}

/// A container at `a` and one at `b` reach each other's files: the
/// categories of one are all in the other (an empty set, `s0`, is left out:
/// the allocator gives none).  A level that is none counts as reaching.
pub fn overlap(a: &[u8], b: &[u8]) -> bool {
    match (parse(a), parse(b)) {
        (Some(x), Some(y)) => !x.is_empty() && !y.is_empty() && (x.within(&y) || y.within(&x)),
        _ => true,
    }
}

/// A level that a user or the CRI may give: one `parse` takes, with at most
/// two sensitivities (`s0-s15`, not `s0-s1-s2`) and no number with a leading
/// zero (`c0` and `s0` are fine, `c01` and `s00` are not).  `parse` stays
/// lenient, for the levels that are already in use.
pub fn strict(level: &[u8]) -> bool {
    let mut ok = parse(level).is_some();
    let mut dashes: usize = 0;
    let mut i = 0;
    while i < level.len() {
        let b = level[i];
        if b == b'-' {
            dashes += 1;
        }
        if (b == b's' || b == b'c')
            && i + 2 < level.len()
            && level[i + 1] == b'0'
            && level[i + 2] >= b'0'
            && level[i + 2] <= b'9'
        {
            ok = false;
        }
        i += 1;
    }
    ok && dashes <= 1
}

/// `s0:cA,cB`, the longest being `s0:c1022,c1023`.
const LABEL: usize = 14;

/// The level of a pair of categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Label {
    bytes: [u8; LABEL],
    len: usize,
}

impl Label {
    /// The level, as text.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

/// Write `c` in decimal at `at`; the index after it.
fn put_number(out: &mut [u8; LABEL], at: usize, c: u16) -> usize {
    let mut size = 1;
    let mut rest = c / 10;
    while rest > 0 {
        size += 1;
        rest /= 10;
    }
    let mut v = c;
    let mut i = size;
    while i > 0 {
        i -= 1;
        out[at + i] = b'0' + (v % 10) as u8;
        v /= 10;
    }
    at + size
}

/// The level `s0:cLOW,cHIGH` of two categories in order, `None` unless
/// `low < high < CATEGORIES`.
pub fn pair_label(low: u16, high: u16) -> Option<Label> {
    if low >= high || high >= CATEGORIES {
        return None;
    }
    let mut bytes = [0u8; LABEL];
    bytes[0] = b's';
    bytes[1] = b'0';
    bytes[2] = b':';
    bytes[3] = b'c';
    let at = put_number(&mut bytes, 4, low);
    bytes[at] = b',';
    bytes[at + 1] = b'c';
    let len = put_number(&mut bytes, at + 2, high);
    Some(Label { bytes, len })
}

/// The two categories of a level of the form `pair_label` writes, and of no
/// other spelling (not `s0:c2,c1`, `s0:c01,c2`, `s0:c1.c2`, a third category
/// or a range of sensitivities).
pub fn read_pair(level: &[u8]) -> Option<(u16, u16)> {
    // the first two categories of the set; a set of another size, or a text
    // that is not the label of these two, is not the label of a pair
    match parse(level) {
        None => None,
        Some(cats) => {
            let mut low = 0;
            while low < CATEGORIES && !cats.has(low) {
                low += 1;
            }
            let mut high = low + 1;
            while high < CATEGORIES && !cats.has(high) {
                high += 1;
            }
            match pair_label(low, high) {
                Some(label) if label.as_bytes() == level => Some((low, high)),
                _ => None,
            }
        }
    }
}

/// The pair of the attempt at `a` of `rand`: one category from the first
/// number and a different one from the second, in order, so that a pair is
/// always two distinct categories and every pair is equally likely for
/// uniform numbers.
fn attempt(rand: &[u32], a: usize) -> Option<Label> {
    let first = (rand[a] % CATEGORIES as u32) as u16;
    let mut second = (rand[a + 1] % (CATEGORIES as u32 - 1)) as u16;
    if second >= first {
        second += 1;
    }
    if first < second {
        pair_label(first, second)
    } else {
        pair_label(second, first)
    }
}

/// The level of a fresh container, from the attempts of `rand` (two numbers
/// to an attempt, the rest of an odd list is not used), in two passes over
/// the same attempts:
/// - the first attempt whose pair reaches none of the levels `used` (neither
///   has the categories of the other); such a pair is always taken over any
///   other;
/// - only when no attempt is like that, the first attempt whose pair is not
///   equal to, and does not contain, a level in use that has categories.  A
///   pair inside a wider level in use is taken then: that level was made
///   wide on purpose (`s0:c0.c1023`), and no pair can avoid it.
///
/// `None` when no attempt passes either.  `used` has an owned level each:
/// the translator does not take a slice of slices.
pub fn pick(rand: &[u32], used: &[Vec<u8>]) -> Option<Label> {
    let mut found = None;
    let mut done = false;
    let mut pass = 0;
    while !done && pass < 2 {
        let mut a = 0;
        while !done && a + 1 < rand.len() {
            if let Some(label) = attempt(rand, a) {
                let mut free = true;
                let mut u = 0;
                while u < used.len() {
                    if pass == 0 && overlap(label.as_bytes(), &used[u]) {
                        free = false;
                    }
                    if pass == 1 && contains(label.as_bytes(), &used[u]) {
                        free = false;
                    }
                    u += 1;
                }
                if free {
                    found = Some(label);
                    done = true;
                }
            }
            a += 2;
        }
        pass += 1;
    }
    found
}

/// The indexes of the first three colons of a context `user:role:type:level`;
/// the level is what follows the third (it has colons of its own), `None`
/// when there are not three.
pub fn context_colons(context: &[u8]) -> Option<[usize; 3]> {
    let mut at = [0usize; 3];
    let mut seen = 0;
    let mut i = 0;
    while i < context.len() {
        if context[i] == b':' && seen < 3 {
            at[seen] = i;
            seen += 1;
        }
        i += 1;
    }
    if seen == 3 {
        Some(at)
    } else {
        None
    }
}

#[cfg(test)]
mod rules;
#[cfg(test)]
mod walk;
