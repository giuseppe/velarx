// SPDX-License-Identifier: Apache-2.0
//! The decision of the signature policy of an image, on bytes and vectors:
//! which scope of policy.json applies to its name, whether its requirements
//! accept it before any signature is read, and whether the signatures that
//! were checked satisfy them.  What reads policy.json, loads keys, checks
//! signatures and writes the messages is `velarx-signature`: it turns what
//! it finds into the `Item`s and `Fact`s here and the answer into text.
//!
//! A name is `host[:port]/path` as `velarx-signature` normalizes it
//! (`docker.io` for no host, `library/` added), compared as written.  A tag
//! or a digest is never empty.  The scopes are the keys of policy.json as
//! they are.
//!
//! The types derive nothing that is not a plain comparison or copy of
//! numbers (`Debug`, `Clone` and `==` of a `Vec` or an `Option` are
//! functions of the standard library that Aeneas knows nothing of): the
//! tests have them.
//!
//! The code is plain loops over slices and vectors with indices, and a
//! `match` on a borrowed enum only in a function of its own, so that Aeneas
//! can translate it (tools/verify/policy-core).

/// A reference: a name, and the tag and the digest it was asked by or
/// signed for.
#[cfg_attr(test, derive(Debug, Clone, PartialEq, Eq))]
pub struct Ref {
    pub name: Vec<u8>,
    pub tag: Option<Vec<u8>>,
    pub digest: Option<Vec<u8>>,
}

/// Which signed references satisfy a signature requirement (its
/// `signedIdentity`, the references already made).
#[cfg_attr(test, derive(Debug, Clone, PartialEq, Eq))]
pub enum Rule {
    /// The same name, tag and digest, and one of them is there.
    Exact,
    /// The same reference when the image is asked by tag, the same name
    /// when it is asked by digest.
    RepoDigestOrExact,
    /// The same name, whatever the tag and the digest.
    Repository,
    /// This reference (it has a tag or a digest), whatever the image was
    /// asked by.
    ExactReference(Ref),
    /// This name, whatever the tag and the digest and the image.
    ExactRepository(Vec<u8>),
    /// As `RepoDigestOrExact`, for this reference: the image's after its
    /// prefix was replaced.
    Remapped(Ref),
    /// No signed reference matches: a rule that cannot be made into one.
    Nothing,
}

/// What was found of one signature of the image for one requirement.
#[cfg_attr(test, derive(Debug, Clone, PartialEq, Eq))]
pub enum Fact {
    /// Not a signature of the kind, not verified, or not readable.
    Unverified,
    /// Verified by a key of the requirement; `digest_matches` says it names
    /// the manifest, `signed` is the reference it names and `time` when it
    /// was made.
    Verified {
        digest_matches: bool,
        signed: Ref,
        time: i64,
    },
}

/// A requirement of the scope that applies, with what was found of the
/// signatures of the image for it (one `Fact` for each signature of the
/// image, in its order).
#[cfg_attr(test, derive(Debug, Clone, PartialEq, Eq))]
pub enum Item {
    AcceptAnything,
    Reject,
    /// `signedBaseLayer`, which is not implemented.
    Unimplemented,
    /// A signature requirement that cannot be used: no keys, bad keys, a
    /// key type that is not implemented.
    Unusable,
    Signed(Rule, Vec<Fact>),
}

/// How the requirements judge an image.
#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(test, derive(Debug))]
pub enum Mode {
    /// All of them: a pull, and `signature=check`.
    Whole,
    /// The signature requirements only (`reject` and `signedBaseLayer` are
    /// for pulls): the create and the start of an image of the store.
    SignaturesOnly,
    /// All of them, and one must be a signature requirement that a signature
    /// satisfied.
    MustBeSigned,
}

/// Why an image is refused.
#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(test, derive(Debug))]
pub enum Why {
    /// There is no requirement.
    Empty,
    Rejected,
    Unimplemented,
    Unusable,
    /// No signature satisfies the requirement.
    NoSignature,
    /// `MustBeSigned`, and no requirement asks for a signature.
    NotSigned,
}

/// What the requirements say before any signature is read.
#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(test, derive(Debug))]
pub enum Pre {
    /// Accepted, whatever the signatures.
    Accept,
    /// Their signatures decide.
    NeedsSignatures,
    /// Refused whatever the signatures, by the requirement `at`.
    Refuse { at: usize, why: Why },
}

/// What the requirements decide of the image, signatures included.
#[cfg_attr(test, derive(Debug, Clone, PartialEq, Eq))]
pub enum Outcome {
    /// `used` are the indexes of the signatures that satisfied the
    /// requirements (one for each signature requirement, the newest; the
    /// same index may be there twice), `signed` the oldest of their times
    /// (0 when there is none).
    Accept { used: Vec<usize>, signed: i64 },
    /// Refused by the requirement `at`.
    Refuse { at: usize, why: Why },
}

/// A record of the tag, as far as the pick of the newest one needs it: when
/// the policy accepted it (`Outcome::Accept::signed`), and the digest of
/// the manifest it names.
#[cfg_attr(test, derive(Debug, Clone, PartialEq, Eq))]
pub struct Signed {
    pub time: i64,
    pub digest: Vec<u8>,
}

/// What a list of accepted records names.
#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(test, derive(Debug))]
pub enum Picked {
    /// The list is empty.
    Nothing,
    /// The digest of this record: the first of the latest time, and every
    /// record of that time has its digest.
    One(usize),
    /// The first record of the latest time, and the last of that time
    /// whose digest is not its digest.
    Tie(usize, usize),
}

/// The two are the same bytes.
pub fn same(a: &[u8], b: &[u8]) -> bool {
    let mut equal = a.len() == b.len();
    let mut i = 0;
    while equal && i < a.len() {
        equal = a[i] == b[i];
        i += 1;
    }
    equal
}

/// `a` is the beginning of `b`.
// (`starts`, `is_joined` and `is_reference` are functions of their own so
// that the translator accepts their loops and matches)
fn starts(a: &[u8], b: &[u8]) -> bool {
    let mut ok = a.len() <= b.len();
    let mut i = 0;
    while ok && i < a.len() {
        ok = a[i] == b[i];
        i += 1;
    }
    ok
}

/// `scope` is a repository, a namespace or a host (with its port) of
/// `name`: the beginning of it, up to the end or a `/`.  `x/a` is not one
/// of `x/ab`.
pub fn covers(scope: &[u8], name: &[u8]) -> bool {
    starts(scope, name) && (scope.len() == name.len() || name[scope.len()] == b'/')
}

/// The length of the host of `name`, without its port.
fn host_len(name: &[u8]) -> usize {
    let mut n = 0;
    while n < name.len() && name[n] != b'/' && name[n] != b':' {
        n += 1;
    }
    n
}

/// `scope` is `name`, `sep` and `tail`.
fn is_joined(scope: &[u8], name: &[u8], sep: u8, tail: &[u8]) -> bool {
    // (a difference, not a sum: no length can overflow)
    let mut ok = scope.len() > name.len() && scope.len() - name.len() - 1 == tail.len();
    let mut i = 0;
    while ok && i < scope.len() {
        let expected = if i < name.len() {
            name[i]
        } else if i == name.len() {
            sep
        } else {
            tail[i - name.len() - 1]
        };
        ok = scope[i] == expected;
        i += 1;
    }
    ok
}

/// `scope` is the name of `image` with its digest, or with its tag when it
/// has no digest.
fn is_reference(scope: &[u8], image: &Ref) -> bool {
    match &image.digest {
        Some(digest) => is_joined(scope, &image.name, b'@', digest),
        None => match &image.tag {
            Some(tag) => is_joined(scope, &image.name, b':', tag),
            None => false,
        },
    }
}

/// `scope` is `*.suffix` and the host of `name` ends with `.suffix`.
fn wildcard_covers(scope: &[u8], name: &[u8]) -> bool {
    let host = host_len(name);
    let mut ok =
        scope.len() >= 2 && scope[0] == b'*' && scope[1] == b'.' && scope.len() - 1 <= host;
    let mut i = 1;
    while ok && i < scope.len() {
        ok = scope[i] == name[host - (scope.len() - i)];
        i += 1;
    }
    ok
}

/// How specifically `scope` applies to `image`: 4 for its exact reference,
/// 3 for its name or a namespace or host of it, 2 for a wildcard of its
/// host, 1 for the scope of the transport (the empty one), 0 for none.
fn class(scope: &[u8], image: &Ref) -> u8 {
    if is_reference(scope, image) {
        4
    } else if !scope.is_empty() && covers(scope, &image.name) {
        3
    } else if wildcard_covers(scope, &image.name) {
        2
    } else if scope.is_empty() {
        1
    } else {
        0
    }
}

/// The scope of policy.json that applies to `image`: the one of the highest
/// class, and of those the longest.  None when no scope applies (the
/// default of the policy does).
pub fn select(scopes: &[Vec<u8>], image: &Ref) -> Option<usize> {
    let mut best: Option<usize> = None;
    let mut best_class = 0;
    let mut best_len = 0;
    let mut i = 0;
    while i < scopes.len() {
        let c = class(&scopes[i], image);
        let len = scopes[i].len();
        if c > 0 && (c > best_class || (c == best_class && len > best_len)) {
            best = Some(i);
            best_class = c;
            best_len = len;
        }
        i += 1;
    }
    best
}

// (a function of its own so that the translator accepts the match)
fn same_option(a: &Option<Vec<u8>>, b: &Option<Vec<u8>>) -> bool {
    match (a, b) {
        (None, None) => true,
        (Some(x), Some(y)) => same(x, y),
        _ => false,
    }
}

fn has_tag_or_digest(r: &Ref) -> bool {
    r.tag.is_some() || r.digest.is_some()
}

fn same_reference(a: &Ref, b: &Ref) -> bool {
    same(&a.name, &b.name) && same_option(&a.tag, &b.tag) && same_option(&a.digest, &b.digest)
}

/// Both have a tag or a digest, and they are the same reference.
fn exact(a: &Ref, b: &Ref) -> bool {
    has_tag_or_digest(a) && has_tag_or_digest(b) && same_reference(a, b)
}

/// `matchRepoDigestOrExact`.
fn repo_digest_or_exact(intended: &Ref, signed: &Ref) -> bool {
    if !has_tag_or_digest(signed) {
        false
    } else if intended.tag.is_some() {
        same_reference(intended, signed)
    } else {
        intended.digest.is_some() && same(&intended.name, &signed.name)
    }
}

/// Whether a signature for `signed` is a signature for the image asked by
/// `intended`, under `rule`.
pub fn identity_matches(rule: &Rule, intended: &Ref, signed: &Ref) -> bool {
    match rule {
        Rule::Exact => exact(intended, signed),
        Rule::RepoDigestOrExact => repo_digest_or_exact(intended, signed),
        Rule::Repository => same(&intended.name, &signed.name),
        Rule::ExactReference(r) => exact(r, signed),
        Rule::ExactRepository(name) => same(name, &signed.name),
        Rule::Remapped(r) => repo_digest_or_exact(r, signed),
        Rule::Nothing => false,
    }
}

/// The fact satisfies `rule` for `intended`: verified, for the manifest, and
/// for the reference.
fn counts(rule: &Rule, intended: &Ref, fact: &Fact) -> bool {
    match fact {
        Fact::Unverified => false,
        Fact::Verified {
            digest_matches,
            signed,
            time: _,
        } => *digest_matches && identity_matches(rule, intended, signed),
    }
}

// (a function of its own so that the translator accepts the match)
fn time_of(fact: &Fact) -> i64 {
    match fact {
        Fact::Unverified => 0,
        Fact::Verified {
            digest_matches: _,
            signed: _,
            time,
        } => *time,
    }
}

/// The newest fact that satisfies `rule`, its index and its time; the first
/// of those of one time.
fn newest(rule: &Rule, intended: &Ref, facts: &[Fact]) -> Option<(usize, i64)> {
    let mut best: Option<(usize, i64)> = None;
    let mut i = 0;
    while i < facts.len() {
        if counts(rule, intended, &facts[i]) {
            let time = time_of(&facts[i]);
            let newer = match best {
                None => true,
                Some((_, t)) => time > t,
            };
            if newer {
                best = Some((i, time));
            }
        }
        i += 1;
    }
    best
}

/// What a requirement refuses by its kind alone.
fn refusal_of(mode: Mode, item: &Item) -> Option<Why> {
    let for_pulls = match mode {
        Mode::SignaturesOnly => false,
        Mode::Whole | Mode::MustBeSigned => true,
    };
    match item {
        Item::AcceptAnything | Item::Signed(_, _) => None,
        Item::Reject if for_pulls => Some(Why::Rejected),
        Item::Unimplemented if for_pulls => Some(Why::Unimplemented),
        Item::Reject | Item::Unimplemented => None,
        Item::Unusable => Some(Why::Unusable),
    }
}

// (a function of its own so that the translator accepts the match)
fn is_signed(item: &Item) -> bool {
    match item {
        Item::Signed(_, _) => true,
        Item::AcceptAnything | Item::Reject | Item::Unimplemented | Item::Unusable => false,
    }
}

// (a function of its own so that the translator accepts the match)
fn must_be_signed(mode: Mode) -> bool {
    match mode {
        Mode::MustBeSigned => true,
        Mode::Whole | Mode::SignaturesOnly => false,
    }
}

/// What the requirements say before any signature is read (`Signed` items
/// may carry no facts).  The first that refuses by its kind decides, in the
/// order of the list.
pub fn precheck(mode: Mode, items: &[Item]) -> Pre {
    let mut refused: Option<(usize, Why)> = None;
    let mut needs = false;
    let mut i = 0;
    while i < items.len() && refused.is_none() {
        if let Some(why) = refusal_of(mode, &items[i]) {
            refused = Some((i, why));
        }
        if is_signed(&items[i]) {
            needs = true;
        }
        i += 1;
    }
    if items.is_empty() {
        Pre::Refuse {
            at: 0,
            why: Why::Empty,
        }
    } else if let Some((at, why)) = refused {
        Pre::Refuse { at, why }
    } else if must_be_signed(mode) && !needs {
        Pre::Refuse {
            at: 0,
            why: Why::NotSigned,
        }
    } else if needs {
        Pre::NeedsSignatures
    } else {
        Pre::Accept
    }
}

/// What one requirement says of the image.
// (`Verdict` and `weigh` are apart from `decide` so that the translator
// accepts the match on a borrowed item inside its loop)
enum Verdict {
    Holds,
    /// The signature, by its index and its time, that satisfies it.
    Signed(usize, i64),
    Refuses(Why),
}

fn weigh(mode: Mode, intended: &Ref, item: &Item) -> Verdict {
    if let Some(why) = refusal_of(mode, item) {
        Verdict::Refuses(why)
    } else {
        match item {
            Item::Signed(rule, facts) => match newest(rule, intended, facts) {
                Some((index, time)) => Verdict::Signed(index, time),
                None => Verdict::Refuses(Why::NoSignature),
            },
            Item::AcceptAnything | Item::Reject | Item::Unimplemented | Item::Unusable => {
                Verdict::Holds
            }
        }
    }
}

/// Whether the requirements accept the image asked by `intended`: every
/// one must, in the order of the list, and the first that does not decides.
/// A signature requirement holds when one of its facts is verified, names
/// the manifest and satisfies its rule.
pub fn decide(mode: Mode, intended: &Ref, items: &[Item]) -> Outcome {
    let mut used: Vec<usize> = Vec::new();
    let mut signed = 0;
    let mut refused: Option<(usize, Why)> = None;
    let mut i = 0;
    while i < items.len() && refused.is_none() {
        match weigh(mode, intended, &items[i]) {
            Verdict::Holds => {}
            Verdict::Signed(index, time) => {
                used.push(index);
                if used.len() == 1 || time < signed {
                    signed = time;
                }
            }
            Verdict::Refuses(why) => refused = Some((i, why)),
        }
        i += 1;
    }
    if items.is_empty() {
        Outcome::Refuse {
            at: 0,
            why: Why::Empty,
        }
    } else if let Some((at, why)) = refused {
        Outcome::Refuse { at, why }
    } else if must_be_signed(mode) && used.is_empty() {
        Outcome::Refuse {
            at: 0,
            why: Why::NotSigned,
        }
    } else {
        Outcome::Accept { used, signed }
    }
}

// (a function of its own so that the translator accepts the loop of `pick`)
fn same_digest(records: &[Signed], i: usize, j: usize) -> bool {
    same(&records[i].digest, &records[j].digest)
}

/// What a tag names among `records` (in their order of arrival, which is
/// not trusted): the digest of the latest time, or a tie when two records
/// of that time name different digests.  A record of a later time always
/// ends a tie of an earlier one.
pub fn pick(records: &[Signed]) -> Picked {
    // (the first record of the latest time, and the last record of that
    // time whose digest differs from its digest)
    let mut best = 0;
    let mut other = 0;
    let mut tied = false;
    let mut i = 1;
    while i < records.len() {
        if records[i].time > records[best].time {
            best = i;
            tied = false;
        } else if records[i].time == records[best].time && !same_digest(records, i, best) {
            other = i;
            tied = true;
        }
        i += 1;
    }
    if records.is_empty() {
        Picked::Nothing
    } else if tied {
        Picked::Tie(best, other)
    } else {
        Picked::One(best)
    }
}

#[cfg(test)]
mod rules;

#[cfg(test)]
mod walk;

#[cfg(test)]
mod tests {
    use super::*;

    fn bytes(s: &str) -> Vec<u8> {
        s.as_bytes().to_vec()
    }

    /// A reference of `name` with a `tag` and a `digest` when they are not
    /// empty.
    fn reference(name: &str, tag: &str, digest: &str) -> Ref {
        Ref {
            name: bytes(name),
            tag: (!tag.is_empty()).then(|| bytes(tag)),
            digest: (!digest.is_empty()).then(|| bytes(digest)),
        }
    }

    fn scopes(list: &[&str]) -> Vec<Vec<u8>> {
        list.iter().map(|s| bytes(s)).collect()
    }

    /// The scope of `list` that applies to the reference, as a string.
    fn selected(list: &[&str], image: &Ref) -> Option<String> {
        select(&scopes(list), image).map(|i| list[i].to_string())
    }

    #[test]
    fn bytes_are_the_same_when_all_of_them_are() {
        assert!(same(b"", b""));
        assert!(same(b"quay.io/a", b"quay.io/a"));
        assert!(!same(b"quay.io/a", b"quay.io/b"));
        assert!(!same(b"quay.io/a", b"quay.io/a/"));
        assert!(!same(b"quay.io/a/", b"quay.io/a"));
        assert!(!same(b"", b"a"));
    }

    #[test]
    fn a_scope_covers_whole_components() {
        assert!(covers(b"x", b"x"));
        assert!(covers(b"x", b"x/a"));
        assert!(covers(b"x/a", b"x/a/b"));
        assert!(covers(b"x/a", b"x/a"));
        // the neighbours that share the bytes
        assert!(!covers(b"x/a", b"x/ab"));
        assert!(!covers(b"x/a", b"x/ab/c"));
        assert!(!covers(b"x/a/b", b"x/a"));
        assert!(!covers(b"x", b"xy"));
        // a port is part of the host
        assert!(covers(b"localhost:5000", b"localhost:5000/a"));
        assert!(!covers(b"localhost", b"localhost:5000/a"));
        assert!(!covers(b"", b"a"));
    }

    #[test]
    fn the_host_ends_at_the_port_or_the_path() {
        assert_eq!(host_len(b"quay.io/a/b"), 7);
        assert_eq!(host_len(b"localhost:5000/a"), 9);
        assert_eq!(host_len(b"quay.io"), 7);
        assert_eq!(host_len(b""), 0);
    }

    #[test]
    fn a_wildcard_covers_the_hosts_below_its_suffix() {
        let covered = |scope: &str, name: &str| wildcard_covers(scope.as_bytes(), name.as_bytes());
        assert!(covered("*.example.com", "reg.example.com/a"));
        assert!(covered("*.example.com", "a.b.example.com/a"));
        assert!(covered("*.com", "reg.example.com/a"));
        // the port is not part of the host
        assert!(covered("*.example.com", "reg.example.com:5000/a"));
        // strictly below: the suffix itself, or another host that ends the
        // same, is not covered
        assert!(!covered("*.example.com", "example.com/a"));
        assert!(!covered("*.example.com", "reg.xexample.com/a"));
        assert!(!covered("*.example.com", "reg.example.org/a"));
        // only the host: not the path
        assert!(!covered("*.example.com", "other.org/reg.example.com"));
        // not a wildcard
        assert!(!covered("example.com", "reg.example.com/a"));
        assert!(!covered("*", "reg.example.com/a"));
        assert!(!covered("*example.com", "reg.example.com/a"));
        assert!(!covered("", "reg.example.com/a"));
    }

    #[test]
    fn the_exact_reference_is_the_name_with_the_digest_or_the_tag() {
        let d = "sha256:00";
        let tagged = reference("quay.io/a/b", "v1", "");
        let digested = reference("quay.io/a/b", "", d);
        let both = reference("quay.io/a/b", "v1", d);
        assert!(is_reference(b"quay.io/a/b:v1", &tagged));
        assert!(!is_reference(b"quay.io/a/b:v2", &tagged));
        assert!(!is_reference(b"quay.io/a/b", &tagged));
        assert!(!is_reference(b"quay.io/a/b@sha256:00", &tagged));
        // a scope shorter than the name, or longer than the reference
        assert!(!is_reference(b"quay.io", &tagged));
        assert!(!is_reference(b"", &tagged));
        assert!(!is_reference(b"quay.io/a/b:v1:v1", &tagged));
        assert!(is_reference(b"quay.io/a/b@sha256:00", &digested));
        assert!(!is_reference(b"quay.io/a/b:v1", &digested));
        // the digest, when there is one: not the tag
        assert!(is_reference(b"quay.io/a/b@sha256:00", &both));
        assert!(!is_reference(b"quay.io/a/b:v1", &both));
        assert!(!is_reference(
            b"quay.io/a/b",
            &reference("quay.io/a/b", "", "")
        ));
    }

    #[test]
    fn the_most_specific_scope_applies() {
        let image = reference("reg.example.com/ns/img", "v1", "");
        let list = [
            "reg.example.com/ns/img:v1",
            "reg.example.com/ns/img",
            "reg.example.com/ns",
            "reg.example.com",
            "*.example.com",
            "*.com",
            "",
        ];
        // each scope applies when the more specific ones are gone
        for first in 0..list.len() {
            assert_eq!(
                selected(&list[first..], &image).as_deref(),
                Some(list[first]),
                "{first}"
            );
        }
        // no matter in which order the scopes are
        let mut reversed = list.to_vec();
        reversed.reverse();
        assert_eq!(
            selected(&reversed, &image).as_deref(),
            Some("reg.example.com/ns/img:v1")
        );
        assert_eq!(selected(&[], &image), None);
        assert_eq!(selected(&["other.io", "reg.example.org/ns"], &image), None);
    }

    #[test]
    fn the_digest_names_the_image_and_the_tag_does_not_when_it_has_one() {
        let d = "sha256:00";
        let image = reference("quay.io/a/b", "v1", d);
        assert_eq!(
            selected(
                &["quay.io/a/b@sha256:00", "quay.io/a/b:v1", "quay.io/a/b"],
                &image
            )
            .as_deref(),
            Some("quay.io/a/b@sha256:00")
        );
        assert_eq!(
            selected(&["quay.io/a/b:v1", "quay.io/a/b"], &image).as_deref(),
            Some("quay.io/a/b")
        );
        assert_eq!(selected(&["quay.io/a/b@sha256:11"], &image), None);
    }

    #[test]
    fn a_scope_that_is_not_a_whole_component_does_not_apply() {
        let image = reference("x/ab", "v1", "");
        assert_eq!(selected(&["x/a"], &image), None);
        assert_eq!(selected(&["x/a", "x"], &image).as_deref(), Some("x"));
        let port = reference("localhost:5000/a", "", "");
        assert_eq!(selected(&["localhost"], &port), None);
        assert_eq!(
            selected(&["localhost", "localhost:5000"], &port).as_deref(),
            Some("localhost:5000")
        );
    }

    #[test]
    fn a_wildcard_applies_to_the_host_without_its_port_and_a_longer_one_wins() {
        let image = reference("a.b.example.com:5000/x", "", "");
        assert_eq!(
            selected(&["*.com", "*.example.com", "*.b.example.com"], &image).as_deref(),
            Some("*.b.example.com")
        );
        assert_eq!(selected(&["*.com", ""], &image).as_deref(), Some("*.com"));
        assert_eq!(selected(&[""], &image).as_deref(), Some(""));
        // a name beats a wildcard whatever their lengths
        assert_eq!(
            selected(&["*.b.example.com", "a.b.example.com:5000"], &image).as_deref(),
            Some("a.b.example.com:5000")
        );
    }

    #[test]
    fn each_rule_compares_what_it_names() {
        let d = "sha256:00";
        let tagged = reference("a/b", "v1", "");
        let digested = reference("a/b", "", d);
        let both = reference("a/b", "v1", d);
        let name = reference("a/b", "", "");
        let (v1, v2) = (reference("a/b", "v1", ""), reference("a/b", "v2", ""));
        let other = reference("a/c", "v1", "");
        // Exact: the same reference, and one of the tag and the digest
        assert!(identity_matches(&Rule::Exact, &tagged, &v1));
        assert!(!identity_matches(&Rule::Exact, &tagged, &v2));
        assert!(!identity_matches(&Rule::Exact, &tagged, &other));
        assert!(!identity_matches(&Rule::Exact, &tagged, &both));
        assert!(identity_matches(&Rule::Exact, &digested, &digested));
        assert!(identity_matches(&Rule::Exact, &both, &both));
        assert!(!identity_matches(&Rule::Exact, &name, &name));
        assert!(!identity_matches(&Rule::Exact, &tagged, &name));
        // RepoDigestOrExact: by tag the same reference, by digest the same name
        let rde = Rule::RepoDigestOrExact;
        assert!(identity_matches(&rde, &tagged, &v1));
        assert!(!identity_matches(&rde, &tagged, &v2));
        assert!(!identity_matches(&rde, &tagged, &name));
        assert!(identity_matches(&rde, &digested, &v2));
        assert!(identity_matches(&rde, &digested, &digested));
        assert!(!identity_matches(&rde, &digested, &other));
        assert!(!identity_matches(&rde, &digested, &name));
        assert!(identity_matches(&rde, &both, &both));
        assert!(!identity_matches(&rde, &both, &digested));
        assert!(!identity_matches(&rde, &name, &v1));
        // Repository: the name, whatever else
        assert!(identity_matches(&Rule::Repository, &tagged, &v2));
        assert!(identity_matches(&Rule::Repository, &tagged, &name));
        assert!(identity_matches(&Rule::Repository, &name, &digested));
        assert!(!identity_matches(&Rule::Repository, &tagged, &other));
        // ExactReference: the reference of the rule, not the image's
        let exact_v1 = Rule::ExactReference(v1.clone());
        assert!(identity_matches(&exact_v1, &digested, &v1));
        assert!(!identity_matches(&exact_v1, &tagged, &v2));
        assert!(!identity_matches(&exact_v1, &tagged, &name));
        assert!(!identity_matches(
            &Rule::ExactReference(name.clone()),
            &tagged,
            &name
        ));
        // ExactRepository: the name of the rule
        let repo = Rule::ExactRepository(bytes("a/b"));
        assert!(identity_matches(&repo, &other, &v2));
        assert!(identity_matches(&repo, &other, &name));
        assert!(!identity_matches(&repo, &tagged, &other));
        // Remapped: as RepoDigestOrExact, for the reference of the rule
        let remapped = Rule::Remapped(reference("a/b", "v1", ""));
        assert!(identity_matches(&remapped, &other, &v1));
        assert!(!identity_matches(&remapped, &tagged, &v2));
        assert!(identity_matches(
            &Rule::Remapped(digested.clone()),
            &other,
            &v2
        ));
        assert!(!identity_matches(&Rule::Remapped(name), &tagged, &v1));
        // Nothing: no signed reference
        assert!(!identity_matches(&Rule::Nothing, &tagged, &v1));
    }

    fn verified(signed: &Ref, time: i64) -> Fact {
        Fact::Verified {
            digest_matches: true,
            signed: signed.clone(),
            time,
        }
    }

    fn signed(rule: Rule, facts: Vec<Fact>) -> Item {
        Item::Signed(rule, facts)
    }

    #[test]
    fn the_newest_fact_that_counts_is_found() {
        let image = reference("a/b", "v1", "");
        let rule = Rule::RepoDigestOrExact;
        let v1 = reference("a/b", "v1", "");
        let v2 = reference("a/b", "v2", "");
        let wrong_digest = Fact::Verified {
            digest_matches: false,
            signed: v1.clone(),
            time: 90,
        };
        let facts = vec![
            verified(&v1, 10),
            Fact::Unverified,
            verified(&v2, 50),
            wrong_digest,
            verified(&v1, 30),
            verified(&v1, 30),
        ];
        assert_eq!(newest(&rule, &image, &facts), Some((4, 30)));
        assert_eq!(newest(&rule, &image, &facts[1..4]), None);
        assert_eq!(newest(&rule, &image, &[]), None);
        // a time that is not later does not replace the first
        assert_eq!(newest(&rule, &image, &facts[4..]), Some((0, 30)));
        // times before the epoch count as any other
        assert_eq!(
            newest(&rule, &image, &[verified(&v1, -5), verified(&v1, -7)]),
            Some((0, -5))
        );
    }

    #[test]
    fn the_kind_of_a_requirement_refuses_by_the_mode() {
        let kinds = [
            (Item::Reject, Why::Rejected),
            (Item::Unimplemented, Why::Unimplemented),
            (Item::Unusable, Why::Unusable),
        ];
        for (item, why) in kinds {
            for mode in [Mode::Whole, Mode::MustBeSigned] {
                assert_eq!(refusal_of(mode, &item), Some(why), "{item:?} {mode:?}");
            }
        }
        // what is for pulls is not for the create of an image of the store
        assert_eq!(refusal_of(Mode::SignaturesOnly, &Item::Reject), None);
        assert_eq!(refusal_of(Mode::SignaturesOnly, &Item::Unimplemented), None);
        assert_eq!(
            refusal_of(Mode::SignaturesOnly, &Item::Unusable),
            Some(Why::Unusable)
        );
        for mode in [Mode::Whole, Mode::SignaturesOnly, Mode::MustBeSigned] {
            assert_eq!(refusal_of(mode, &Item::AcceptAnything), None);
            assert_eq!(refusal_of(mode, &signed(Rule::Exact, Vec::new())), None);
        }
    }

    #[test]
    fn the_precheck_answers_before_any_signature_is_read() {
        let sig = || signed(Rule::Nothing, Vec::new());
        let any = || Item::AcceptAnything;
        let refuse = |at, why| Pre::Refuse { at, why };
        for mode in [Mode::Whole, Mode::SignaturesOnly, Mode::MustBeSigned] {
            assert_eq!(precheck(mode, &[]), refuse(0, Why::Empty), "{mode:?}");
            assert_eq!(precheck(mode, &[sig()]), Pre::NeedsSignatures, "{mode:?}");
            assert_eq!(
                precheck(mode, &[any(), sig()]),
                Pre::NeedsSignatures,
                "{mode:?}"
            );
            assert_eq!(
                precheck(mode, &[Item::Unusable, sig()]),
                refuse(0, Why::Unusable),
                "{mode:?}"
            );
        }
        assert_eq!(precheck(Mode::Whole, &[any()]), Pre::Accept);
        assert_eq!(precheck(Mode::SignaturesOnly, &[any()]), Pre::Accept);
        assert_eq!(
            precheck(Mode::MustBeSigned, &[any()]),
            refuse(0, Why::NotSigned)
        );
        // the first requirement that refuses decides, a signature requirement
        // before it or after it
        assert_eq!(
            precheck(Mode::Whole, &[sig(), Item::Reject]),
            refuse(1, Why::Rejected)
        );
        assert_eq!(
            precheck(Mode::Whole, &[any(), Item::Unimplemented, Item::Reject]),
            refuse(1, Why::Unimplemented)
        );
        assert_eq!(
            precheck(Mode::MustBeSigned, &[Item::Reject, sig()]),
            refuse(0, Why::Rejected)
        );
        // in the create of a stored image they are not for the image
        assert_eq!(precheck(Mode::SignaturesOnly, &[Item::Reject]), Pre::Accept);
        assert_eq!(
            precheck(
                Mode::SignaturesOnly,
                &[Item::Reject, Item::Unimplemented, sig()]
            ),
            Pre::NeedsSignatures
        );
    }

    #[test]
    fn a_signature_requirement_holds_by_a_signature_that_counts() {
        let image = reference("a/b", "v1", "");
        let v1 = reference("a/b", "v1", "");
        let v2 = reference("a/b", "v2", "");
        let holds = |facts: Vec<Fact>| {
            decide(
                Mode::Whole,
                &image,
                &[signed(Rule::RepoDigestOrExact, facts)],
            )
        };
        assert_eq!(
            holds(vec![verified(&v1, 7)]),
            Outcome::Accept {
                used: vec![0],
                signed: 7
            }
        );
        assert_eq!(
            holds(vec![Fact::Unverified, verified(&v2, 9), verified(&v1, 3)]),
            Outcome::Accept {
                used: vec![2],
                signed: 3
            }
        );
        for facts in [
            vec![],
            vec![Fact::Unverified],
            vec![verified(&v2, 9)],
            vec![Fact::Verified {
                digest_matches: false,
                signed: v1.clone(),
                time: 1,
            }],
        ] {
            assert_eq!(
                holds(facts),
                Outcome::Refuse {
                    at: 0,
                    why: Why::NoSignature
                }
            );
        }
    }

    #[test]
    fn every_requirement_must_hold_and_the_first_that_does_not_decides() {
        let image = reference("a/b", "v1", "");
        let v1 = reference("a/b", "v1", "");
        let good = || signed(Rule::Exact, vec![verified(&v1, 5)]);
        let bad = || signed(Rule::Exact, vec![Fact::Unverified]);
        let accept = |used: Vec<usize>, signed| Outcome::Accept { used, signed };
        let refuse = |at, why| Outcome::Refuse { at, why };
        let run = |mode, items: Vec<Item>| decide(mode, &image, &items);
        assert_eq!(run(Mode::Whole, vec![]), refuse(0, Why::Empty));
        assert_eq!(
            run(Mode::Whole, vec![Item::AcceptAnything]),
            accept(vec![], 0)
        );
        assert_eq!(
            run(Mode::Whole, vec![Item::AcceptAnything, good()]),
            accept(vec![0], 5)
        );
        assert_eq!(
            run(Mode::Whole, vec![good(), bad()]),
            refuse(1, Why::NoSignature)
        );
        assert_eq!(
            run(Mode::Whole, vec![bad(), good()]),
            refuse(0, Why::NoSignature)
        );
        assert_eq!(
            run(Mode::Whole, vec![good(), Item::Reject, bad()]),
            refuse(1, Why::Rejected)
        );
        assert_eq!(
            run(Mode::Whole, vec![good(), Item::Unimplemented]),
            refuse(1, Why::Unimplemented)
        );
        assert_eq!(
            run(Mode::Whole, vec![good(), Item::Unusable]),
            refuse(1, Why::Unusable)
        );
        // the signatures that satisfied them, and the oldest time of them
        let old = signed(Rule::Exact, vec![verified(&v1, 2), verified(&v1, 4)]);
        assert_eq!(run(Mode::Whole, vec![good(), old]), accept(vec![0, 1], 4));
        let newer = signed(Rule::Exact, vec![Fact::Unverified, verified(&v1, 8)]);
        assert_eq!(run(Mode::Whole, vec![good(), newer]), accept(vec![0, 1], 5));
    }

    #[test]
    fn the_modes_judge_the_same_list_differently() {
        let image = reference("a/b", "v1", "");
        let v1 = reference("a/b", "v1", "");
        let good = || signed(Rule::Exact, vec![verified(&v1, 5)]);
        let any = || Item::AcceptAnything;
        let accept = |used: Vec<usize>, signed| Outcome::Accept { used, signed };
        let refuse = |at, why| Outcome::Refuse { at, why };
        let modes = [Mode::Whole, Mode::SignaturesOnly, Mode::MustBeSigned];
        let all = |items: Vec<Item>| modes.map(|mode| decide(mode, &image, &items));
        assert_eq!(
            all(vec![any()]),
            [
                accept(vec![], 0),
                accept(vec![], 0),
                refuse(0, Why::NotSigned)
            ]
        );
        assert_eq!(
            all(vec![Item::Reject]),
            [
                refuse(0, Why::Rejected),
                accept(vec![], 0),
                refuse(0, Why::Rejected)
            ]
        );
        assert_eq!(
            all(vec![Item::Unimplemented, good()]),
            [
                refuse(0, Why::Unimplemented),
                accept(vec![0], 5),
                refuse(0, Why::Unimplemented)
            ]
        );
        assert_eq!(
            all(vec![good()]),
            [accept(vec![0], 5), accept(vec![0], 5), accept(vec![0], 5)]
        );
        // a requirement that cannot be used refuses in every mode
        assert_eq!(
            all(vec![Item::Unusable]),
            [
                refuse(0, Why::Unusable),
                refuse(0, Why::Unusable),
                refuse(0, Why::Unusable)
            ]
        );
        assert_eq!(
            all(vec![]),
            [
                refuse(0, Why::Empty),
                refuse(0, Why::Empty),
                refuse(0, Why::Empty)
            ]
        );
    }

    fn record(time: i64, digest: &str) -> Signed {
        Signed {
            time,
            digest: bytes(digest),
        }
    }

    #[test]
    fn the_latest_record_is_picked_and_equal_ones_make_a_tie_of_digests() {
        assert_eq!(pick(&[]), Picked::Nothing);
        let a = |t| record(t, "a");
        let b = |t| record(t, "b");
        assert_eq!(pick(&[a(1)]), Picked::One(0));
        assert_eq!(pick(&[a(1), b(2), a(0)]), Picked::One(1));
        // the first of equal records is named
        assert_eq!(pick(&[a(1), a(1)]), Picked::One(0));
        assert_eq!(pick(&[a(0), b(3), b(3)]), Picked::One(1));
        // A, B, A at one time is a tie of the first and the last that differs
        assert_eq!(pick(&[a(1), b(1), a(1)]), Picked::Tie(0, 1));
        assert_eq!(pick(&[a(1), b(1), record(1, "c")]), Picked::Tie(0, 2));
        // a later record ends the tie, wherever it is
        assert_eq!(pick(&[a(1), b(1), a(2)]), Picked::One(2));
        assert_eq!(pick(&[b(2), a(1), b(1)]), Picked::One(0));
        // a tie of an earlier time does not matter
        assert_eq!(pick(&[a(1), b(1), b(2)]), Picked::One(2));
        // a digest that is a prefix of another is another digest
        assert_eq!(pick(&[record(1, "a"), record(1, "ab")]), Picked::Tie(0, 1));
    }
}
