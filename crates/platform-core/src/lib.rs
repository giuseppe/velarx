// SPDX-License-Identifier: Apache-2.0
//! Which image of an index runs.  An index lists images, each for a
//! platform (os, architecture, variant); a registry answers it, so it is
//! untrusted.  The platform asked for (`--platform`, or the host's) is
//! not one platform but a list of acceptable ones in order of preference,
//! as containers/image builds it (`WantedPlatforms`), and the entry taken
//! is the first one of the best of them (`chooseInstance`).
//!
//! The shell reads the JSON into [`Entry`]s, in the order of the index,
//! the platforms as bytes (an absent variant is an empty one: both are one
//! thing for containers/image), and takes the digest of the entry
//! [`choose`] names; it checks the digest of every document it reads.
//!
//! The rules, for every entries and every platform asked for (see
//! `rules`):
//!
//! 1. Nothing panics, whatever the bytes.
//! 2. The acceptable platforms ([`wanted_variant`]) are of the os and the
//!    architecture asked for, and differ in the variant only.  With no
//!    variant asked for they are: none, then the variants arm and arm64
//!    are known to have, best (`v8`) first.  With a variant: it and the
//!    known variants below it (arm: `v8`, `v7`, `v6`, `v5`; arm64: `v8`),
//!    then none; a variant that is not known stands alone before none.
//!    So arm64 with and without `v8` are one platform, and `v6` is
//!    acceptable to an `arm/v7` request but `v7` is not to `arm/v6`.
//!    (Variants of amd64, `v2` or `v3`, are not known: only the one
//!    asked for is acceptable.)
//! 3. The entry [`choose`] names is an image, of the os and the
//!    architecture asked for, with an acceptable variant.
//! 4. No image entry has a variant more preferred than the one of the
//!    entry named, and none before it has the same one.
//! 5. Nothing is named exactly when no image entry is acceptable: an
//!    entry of another os or architecture, and an entry that is not an
//!    image (an attestation, `unknown/unknown`), is never named, even
//!    when it is the platform asked for.
//!
//! Not in the core: the detection of the variant of the host (the shell
//! reads /proc/cpuinfo), and the names of the architectures (the shell
//! turns `x86_64` and `aarch64` into their OCI names, containers/image
//! compares them as they are); the core compares bytes.  Not
//! implemented: an entry with no platform at all (containers/image keeps
//! it as the least preferred candidate of an OCI index; here the shell
//! makes it no image, so it is never chosen), `os.version`,
//! `os.features`, and the preference for a compression of the layers.
//!
//! Written to be translated (tools/verify): plain structs, index loops with
//! flags, no closure, no iterator adapter, no library call that needs a
//! model.  The entries are not walked by a loop but by halving ([`choose`]):
//! the translator takes no loop over entries that hold slices, and a call
//! for each entry would be as deep as the index is long.

/// The most platforms [`wanted_variant`] has: none and four variants.
const MOST: usize = 5;

/// The platform of an entry of an index, or the one asked for.  The
/// variant is empty when there is none.
#[derive(Clone, Copy)]
#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
pub struct Platform<'a> {
    pub os: &'a [u8],
    pub arch: &'a [u8],
    pub variant: &'a [u8],
}

/// An entry of an index: its platform, and whether it is an image at all
/// (an attestation, an entry of platform `unknown/unknown`, is not).
#[derive(Clone, Copy)]
#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
pub struct Entry<'a> {
    pub platform: Platform<'a>,
    pub image: bool,
}

fn same(a: &[u8], b: &[u8]) -> bool {
    let mut ok = a.len() == b.len();
    let mut i = 0;
    while i < a.len() && ok {
        ok = a[i] == b[i];
        i += 1;
    }
    ok
}

/// How many variants an architecture is known to have.
fn known_len(arch: &[u8]) -> usize {
    if same(arch, b"arm") {
        4
    } else if same(arch, b"arm64") {
        1
    } else {
        0
    }
}

/// A variant that is acceptable for a platform asked for.
#[derive(Clone, Copy)]
#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
pub enum Wanted {
    /// No variant.
    Absent,
    V8,
    V7,
    V6,
    V5,
    /// The variant the request names, one that its architecture is not
    /// known to have.
    Asked,
}

/// The `i`th known variant of `arch`, the best first.
fn known_at(arch: &[u8], i: usize) -> Wanted {
    if same(arch, b"arm64") || i == 0 {
        Wanted::V8
    } else if i == 1 {
        Wanted::V7
    } else if i == 2 {
        Wanted::V6
    } else {
        Wanted::V5
    }
}

/// `variant` is the acceptable variant `wanted`, for a request that names
/// the variant `asked`.
fn is_wanted(wanted: Wanted, asked: &[u8], variant: &[u8]) -> bool {
    match wanted {
        Wanted::Absent => variant.is_empty(),
        Wanted::V8 => same(variant, b"v8"),
        Wanted::V7 => same(variant, b"v7"),
        Wanted::V6 => same(variant, b"v6"),
        Wanted::V5 => same(variant, b"v5"),
        Wanted::Asked => same(variant, asked),
    }
}

/// The `k`th acceptable variant of `arch` for a request of `variant`, `k`
/// from 0 (the most preferred); none past the last.
pub fn wanted_variant(arch: &[u8], variant: &[u8], k: usize) -> Option<Wanted> {
    let n = known_len(arch);
    if variant.is_empty() {
        // none, then every known one
        if k == 0 {
            Some(Wanted::Absent)
        } else if k <= n {
            Some(known_at(arch, k - 1))
        } else {
            None
        }
    } else {
        let mut at = 0;
        // (a known variant does not look at `asked`)
        while at < n && !is_wanted(known_at(arch, at), variant, variant) {
            at += 1;
        }
        if at < n {
            // it and the ones below it, then none
            if k + at < n {
                Some(known_at(arch, at + k))
            } else if k + at == n {
                Some(Wanted::Absent)
            } else {
                None
            }
        } else if k == 0 {
            Some(Wanted::Asked)
        } else if k == 1 {
            Some(Wanted::Absent)
        } else {
            None
        }
    }
}

/// The place of `entry` among the acceptable platforms of `want` (0 the
/// most preferred), none if it is not acceptable.
pub fn rank(entry: Platform, want: Platform) -> Option<usize> {
    let mut found = None;
    if same(entry.os, want.os) && same(entry.arch, want.arch) {
        let mut k = 0;
        let mut going = true;
        while k < MOST && going {
            match wanted_variant(want.arch, want.variant, k) {
                Some(wanted) => {
                    if is_wanted(wanted, want.variant, entry.variant) {
                        found = Some(k);
                        going = false;
                    }
                }
                None => going = false,
            }
            k += 1;
        }
    }
    found
}

/// The place of the entry `i` of an index among the acceptable platforms of
/// `want`; `MOST` if it is not acceptable or not an image.
fn rank_at(entries: &[Entry], i: usize, want: Platform) -> usize {
    let mut place = MOST;
    if entries[i].image {
        if let Some(k) = rank(entries[i].platform, want) {
            place = k;
        }
    }
    place
}

/// The best entry of a part of an index: its place in the acceptable
/// platforms, and where it is in the index.
#[derive(Clone, Copy)]
struct Best {
    rank: usize,
    at: usize,
}

/// The best of the entries `from..to` of an index: the most preferred of
/// them, the first of the equal ones.  It halves the part, so that an index
/// of any length takes a few calls on the stack, not one call per entry.
fn best_of(entries: &[Entry], want: Platform, from: usize, to: usize) -> Best {
    if to - from == 0 {
        Best {
            rank: MOST,
            at: from,
        }
    } else if to - from == 1 {
        Best {
            rank: rank_at(entries, from, want),
            at: from,
        }
    } else {
        let middle = from + (to - from) / 2;
        let first = best_of(entries, want, from, middle);
        let second = best_of(entries, want, middle, to);
        if second.rank < first.rank {
            second
        } else {
            first
        }
    }
}

/// The entry of an index to take for `want`: of the image entries the
/// acceptable ones, the most preferred, the first of them in the index.
pub fn choose(entries: &[Entry], want: Platform) -> Option<usize> {
    let best = best_of(entries, want, 0, entries.len());
    if best.rank < MOST {
        Some(best.at)
    } else {
        None
    }
}

#[cfg(test)]
mod rules;

#[cfg(test)]
mod walk;
