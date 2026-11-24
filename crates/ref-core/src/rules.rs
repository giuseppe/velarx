// SPDX-License-Identifier: Apache-2.0
//! The rules of a reference, stated on its grammar and not on how `parse`
//! walks it.  The grammar is data (a sequence, a choice, a repeat, a byte
//! range) with a matcher that tries every way, and a reference is split by
//! trying every place for the host, the tag and the digest: `parse` accepts
//! a string exactly when one split of it is in the grammar and the bounds
//! hold, and it finds that split.  What an accepted string cannot hold and
//! what `print` and `normalize` do are checked on each answer.

use super::*;

/// A grammar: what a string of bytes may be.
enum G {
    Lit(&'static [u8]),
    /// One byte, from the first to the second.
    In(u8, u8),
    Seq(&'static [G]),
    Alt(&'static [G]),
    /// Between so many and so many times.
    Rep(&'static G, usize, usize),
}

const MANY: usize = 4096;
const LOWER: G = G::In(b'a', b'z');
const UPPER: G = G::In(b'A', b'Z');
const DIGIT: G = G::In(b'0', b'9');
const ALNUM: G = G::Alt(&[LOWER, DIGIT]);
const ALNUMS: G = G::Rep(&ALNUM, 1, MANY);
const HEX: G = G::Alt(&[DIGIT, G::In(b'a', b'f')]);
const DASHES: G = G::Rep(&G::Lit(b"-"), 1, MANY);

/// A component of a path: letters and digits, joined by `.`, `_`, `__` or
/// dashes.
const COMPONENT: G = G::Seq(&[
    ALNUMS,
    G::Rep(
        &G::Seq(&[
            G::Alt(&[G::Lit(b"."), G::Lit(b"_"), G::Lit(b"__"), DASHES]),
            ALNUMS,
        ]),
        0,
        MANY,
    ),
]);
const PATH: G = G::Seq(&[
    COMPONENT,
    G::Rep(&G::Seq(&[G::Lit(b"/"), COMPONENT]), 0, MANY),
]);

/// A label of a domain: it begins and ends with a letter or a digit.
const LABEL: G = G::Seq(&[
    ALNUM,
    G::Rep(&G::Seq(&[G::Rep(&G::Lit(b"-"), 0, MANY), ALNUM]), 0, MANY),
]);
const DOMAIN: G = G::Seq(&[LABEL, G::Rep(&G::Seq(&[G::Lit(b"."), LABEL]), 0, MANY)]);
const PORT: G = G::Seq(&[G::Lit(b":"), G::Rep(&DIGIT, 1, MANY)]);
const BRACKETS: G = G::Seq(&[
    G::Lit(b"["),
    G::Rep(&G::Alt(&[HEX, G::Lit(b":")]), 1, MANY),
    G::Lit(b"]"),
]);
const HOST: G = G::Seq(&[G::Alt(&[DOMAIN, BRACKETS]), G::Rep(&PORT, 0, 1)]);

const WORD: G = G::Alt(&[LOWER, UPPER, DIGIT, G::Lit(b"_")]);
const TAG: G = G::Seq(&[
    WORD,
    G::Rep(&G::Alt(&[WORD, G::Lit(b"."), G::Lit(b"-")]), 0, 127),
]);
const DIGEST: G = G::Alt(&[
    G::Seq(&[G::Lit(b"sha256:"), G::Rep(&HEX, 64, 64)]),
    G::Seq(&[G::Lit(b"sha384:"), G::Rep(&HEX, 96, 96)]),
    G::Seq(&[G::Lit(b"sha512:"), G::Rep(&HEX, 128, 128)]),
]);

fn union(into: &mut Vec<usize>, more: Vec<usize>) {
    for e in more {
        if !into.contains(&e) {
            into.push(e);
        }
    }
}

/// Every place where a match of `g` that begins at `from` can end.
fn ends(g: &G, s: &[u8], from: usize) -> Vec<usize> {
    match g {
        G::Lit(lit) => {
            if s[from..].starts_with(lit) {
                vec![from + lit.len()]
            } else {
                vec![]
            }
        }
        G::In(lo, hi) => {
            if from < s.len() && *lo <= s[from] && s[from] <= *hi {
                vec![from + 1]
            } else {
                vec![]
            }
        }
        G::Seq(parts) => {
            let mut at = vec![from];
            for part in *parts {
                let mut next = Vec::new();
                for a in at {
                    union(&mut next, ends(part, s, a));
                }
                at = next;
            }
            at
        }
        G::Alt(alts) => {
            let mut out = Vec::new();
            for alt in *alts {
                union(&mut out, ends(alt, s, from));
            }
            out
        }
        G::Rep(one, min, max) => {
            let mut out = Vec::new();
            let mut at = vec![from];
            let mut count = 0;
            while !at.is_empty() && count <= *max {
                if count >= *min {
                    union(&mut out, at.clone());
                }
                let mut next = Vec::new();
                for a in at {
                    union(&mut next, ends(one, s, a));
                }
                at = next;
                count += 1;
            }
            out
        }
    }
}

/// All of `s` is a match of `g`.
fn is(g: &G, s: &[u8]) -> bool {
    ends(g, s, 0).contains(&s.len())
}

/// The first component of `s` is a host and not a path: it has a `.` or a
/// `:`, or is `localhost`.
fn hosty(first: &[u8]) -> bool {
    first.contains(&b'.') || first.contains(&b':') || first == b"localhost"
}

fn at_of(s: &[u8], b: u8) -> Vec<usize> {
    (0..s.len()).filter(|i| s[*i] == b).collect()
}

/// Every way to read `s` as `[host/]path[:tag][@digest]` with each part in
/// its grammar, and the first component a host exactly when it looks like
/// one: the bounds are not looked at.
pub fn splits(s: &[u8]) -> Vec<Spans> {
    let n = s.len();
    let mut out = Vec::new();
    let mut digests = vec![(n, None)];
    for k in at_of(s, b'@') {
        if is(&DIGEST, &s[k + 1..]) {
            digests.push((k, Some((k + 1, n))));
        }
    }
    for (rest, digest) in digests {
        let mut tags = vec![(rest, None)];
        for c in at_of(&s[..rest], b':') {
            if is(&TAG, &s[c + 1..rest]) {
                tags.push((c, Some((c + 1, rest))));
            }
        }
        for (name_end, tag) in tags {
            let name = &s[..name_end];
            let mut hosts = vec![0];
            for h in at_of(name, b'/') {
                if h > 0 && hosty(&name[..h]) && is(&HOST, &name[..h]) {
                    hosts.push(h);
                }
            }
            for host_end in hosts {
                let path = if host_end > 0 {
                    &name[host_end + 1..]
                } else {
                    name
                };
                // no host: a path of components has no host as its first
                let first = path.split(|b| *b == b'/').next().unwrap();
                let hostless = host_end > 0 || !path.contains(&b'/') || !hosty(first);
                if is(&PATH, path) && hostless {
                    out.push(Spans {
                        host_end,
                        name_end,
                        tag,
                        digest,
                    });
                }
            }
        }
    }
    out
}

/// The bytes of the name after the defaults of docker.io, counted from the
/// text.
fn normal_len(s: &[u8], spans: &Spans) -> usize {
    let host = &s[..spans.host_end];
    let path = &s[if spans.host_end > 0 {
        spans.host_end + 1
    } else {
        0
    }..spans.name_end];
    let hub = host.is_empty() || host == b"docker.io" || host == b"index.docker.io";
    let library = if hub && !path.contains(&b'/') { 8 } else { 0 };
    (if hub { 9 } else { host.len() }) + 1 + library + path.len()
}

/// What the bounds say of a split of `s`: it is too long, an image id, or
/// fine.
fn bounds(s: &[u8], spans: &Spans) -> Option<Error> {
    let id = s.len() == 64
        && s.iter()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b));
    if s.len() > 1024 || normal_len(s, spans) > 255 {
        Some(Error::TooLong)
    } else if id {
        Some(Error::Id)
    } else {
        None
    }
}

/// The split the grammar has, if any, and whether the bounds let it be.
fn expected(s: &[u8]) -> (Option<Spans>, bool) {
    let mut all = splits(s);
    assert!(all.len() <= 1, "{s:?} has two splits: {all:?}");
    let split = all.pop();
    let fine = s.len() <= 1024 && split.as_ref().is_some_and(|sp| bounds(s, sp).is_none());
    (split, fine)
}

/// What `prefix_ok` must answer: the whole of `s` is a host, or a host, a
/// `/` and a path, in the grammar.
pub fn prefix_spec(s: &[u8]) -> bool {
    is(&HOST, s)
        || (0..s.len()).any(|h| s[h] == b'/' && is(&HOST, &s[..h]) && is(&PATH, &s[h + 1..]))
}

/// What an accepted string is made of: no byte but those of the grammar, no
/// `@` but the one of the digest, and no part that could leave its place in
/// a URL.
fn assert_safe(s: &[u8], spans: &Spans, name: &Name) {
    let what = format!("{:?}", String::from_utf8_lossy(s));
    for (i, b) in s.iter().enumerate() {
        let in_tag = spans.tag.is_some_and(|(from, to)| from <= i && i < to);
        assert!(
            b.is_ascii_lowercase()
                || b.is_ascii_digit()
                || b"._-:/@[]".contains(b)
                || (in_tag && b.is_ascii_uppercase()),
            "{what}: byte {i}"
        );
    }
    assert_eq!(
        s.iter().filter(|b| **b == b'@').count(),
        usize::from(spans.digest.is_some())
    );
    for part in [&name.host, &name.path] {
        for b in part.iter() {
            assert!(!b"@?#% ".contains(b) && b.is_ascii_graphic(), "{what}");
        }
    }
    assert!(!name.host.contains(&b'/'), "{what}");
    for component in name.path.split(|b| *b == b'/') {
        assert!(!component.is_empty() && component != b"." && component != b"..");
        assert!(!component.windows(2).any(|w| w == b".."), "{what}");
    }
    assert!(name.host.len() + 1 + name.path.len() <= 255, "{what}");
}

/// The host is docker.io, as written or as `normalize` makes it.
fn is_hub_host(host: &[u8]) -> bool {
    host == b"docker.io" || host == b"index.docker.io"
}

/// What an error says: where the string is wrong is a place in it, and the
/// error is of the part that is.
fn assert_located(s: &[u8], e: &Error, split: &Option<Spans>) {
    match e {
        Error::Empty => assert!(s.is_empty()),
        Error::TooLong => assert!(s.len() > 1024 || split.is_some(), "{s:?}"),
        Error::Id => assert!(split.is_some() && s.len() == 64, "{s:?}"),
        Error::Host(at) | Error::Path(at) | Error::Tag(at) | Error::Digest(at) => {
            assert!(*at <= s.len() && split.is_none(), "{e:?} for {s:?}")
        }
    }
}

/// Checks the answer of `parse` for `s`, and tells whether it is accepted;
/// a rule that fails panics with its words and the input.
pub fn verify(s: &[u8]) -> bool {
    let answer = parse(s);
    let (split, fine) = expected(s);
    match (&answer, &split) {
        (Ok(spans), Some(found)) if fine => {
            assert_eq!(spans, found, "{s:?}");
            let name = normalize(s, spans);
            assert_safe(s, spans, &name);
            let tag = spans.tag.map(|(a, b)| &s[a..b]);
            let digest = spans.digest.map(|(a, b)| &s[a..b]);
            // what is printed is a reference with a host that stays as it is
            let printed = print(&name, tag, digest);
            let again =
                parse(&printed).unwrap_or_else(|e| panic!("{s:?} prints {printed:?}: {e:?}"));
            assert!(again.host_end > 0, "{printed:?}");
            let renamed = normalize(&printed, &again);
            assert_eq!(renamed, name, "{printed:?}");
            assert_eq!(again.tag.map(|(a, b)| &printed[a..b]), tag, "{printed:?}");
            assert_eq!(
                again.digest.map(|(a, b)| &printed[a..b]),
                digest,
                "{printed:?}"
            );
            assert_eq!(print(&renamed, tag, digest), printed);
            // a reference written in the full form prints as it was written
            let host = &s[..spans.host_end];
            if spans.host_end > 0
                && host != b"index.docker.io"
                && !(is_hub_host(host) && !s[spans.host_end + 1..spans.name_end].contains(&b'/'))
            {
                assert_eq!(printed, s, "{s:?}");
            }
            true
        }
        (Err(e), _) if !fine => {
            assert_located(s, e, &split);
            false
        }
        _ => panic!("{s:?}: answered {answer:?}, the grammar says {split:?} ({fine})"),
    }
}
