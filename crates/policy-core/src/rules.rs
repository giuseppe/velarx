// SPDX-License-Identifier: Apache-2.0
//! The rules of the decision, checked on its answers: which scope applies,
//! what the requirements say before a signature is read, and whether the
//! signatures satisfy them.  They are stated by what the policy says (the
//! candidate scopes of a name in their order, a reference compared field
//! by field, "every requirement holds"), not by how the functions loop, so
//! that a function that is wrong in another way than the one it was written
//! for still fails one.

use super::*;

fn text(bytes: &[u8]) -> &str {
    std::str::from_utf8(bytes).unwrap()
}

/// The scopes of policy.json that can apply to `image`, the most specific
/// first, as containers/image looks them up: its exact reference (the
/// digest, else the tag), its name and each parent of it up to the host with
/// its port, `*.suffix` for each dot of the host without its port (the
/// longest suffix first), and the scope of the transport.
fn candidates(image: &Ref) -> Vec<String> {
    let name = text(&image.name);
    let mut all = Vec::new();
    match (&image.digest, &image.tag) {
        (Some(digest), _) => all.push(format!("{name}@{}", text(digest))),
        (None, Some(tag)) => all.push(format!("{name}:{}", text(tag))),
        (None, None) => {}
    }
    let mut parent = Some(name);
    while let Some(n) = parent {
        all.push(n.to_string());
        parent = n.rsplit_once('/').map(|(p, _)| p);
    }
    let host = name.split(['/', ':']).next().unwrap();
    for (i, _) in host.match_indices('.') {
        all.push(format!("*{}", &host[i..]));
    }
    all.push(String::new());
    all
}

/// Whether `scope` is a repository, namespace or host of `name`, as text.
fn covers_text(scope: &str, name: &str) -> bool {
    name == scope
        || name
            .strip_prefix(scope)
            .is_some_and(|rest| rest.starts_with('/'))
}

/// How `scope` applies to `image` (its class and its length), by what it
/// says; None when it does not.
fn applies(scope: &str, image: &Ref) -> Option<(u8, usize)> {
    let name = text(&image.name);
    let host = name.split(['/', ':']).next().unwrap();
    let reference = match (&image.digest, &image.tag) {
        (Some(digest), _) => Some(format!("{name}@{}", text(digest))),
        (None, Some(tag)) => Some(format!("{name}:{}", text(tag))),
        (None, None) => None,
    };
    let wildcard = scope
        .strip_prefix('*')
        .filter(|suffix| suffix.starts_with('.'));
    if reference.as_deref() == Some(scope) {
        Some((4, scope.len()))
    } else if !scope.is_empty() && covers_text(scope, name) {
        Some((3, scope.len()))
    } else if wildcard.is_some_and(|suffix| host.ends_with(suffix)) {
        Some((2, scope.len()))
    } else if scope.is_empty() {
        Some((1, 0))
    } else {
        None
    }
}

/// Checks the scope `select` answers for `scopes` and `image`.
pub fn check_selection(scopes: &[&str], image: &Ref) {
    let what = || format!("{scopes:?} for {image:?}");
    let bytes: Vec<Vec<u8>> = scopes.iter().map(|s| s.as_bytes().to_vec()).collect();
    let got = select(&bytes, image);
    // S1: the first scope that is a candidate, the most specific candidate
    // first
    let candidates = candidates(image);
    let first = candidates
        .iter()
        .find_map(|c| scopes.iter().position(|s| s == c));
    assert_eq!(
        got,
        first,
        "the most specific candidate applies: {}",
        what()
    );
    // S2: the scope chosen applies and none applies more specifically; one
    // applies when there is any
    let best = scopes.iter().filter_map(|s| applies(s, image)).max();
    let chosen = got.map(|i| applies(scopes[i], image));
    assert_eq!(
        chosen.unwrap_or(None),
        best,
        "the chosen scope applies: {}",
        what()
    );
    assert_eq!(
        got.is_some(),
        best.is_some_and(|(class, _)| class > 0),
        "{}",
        what()
    );
    // S3: the order of the scopes does not matter
    let mut reversed = bytes.clone();
    reversed.reverse();
    let again = select(&reversed, image).map(|i| &reversed[i]);
    assert_eq!(
        again,
        got.map(|i| &bytes[i]),
        "the order does not matter: {}",
        what()
    );
    // S4: a scope covers whole components of a name only
    for scope in scopes {
        let name = text(&image.name);
        assert_eq!(
            covers(scope.as_bytes(), name.as_bytes()),
            covers_text(scope, name),
            "{scope:?} covers {name:?}"
        );
    }
}

fn has_reference(r: &Ref) -> bool {
    r.tag.is_some() || r.digest.is_some()
}

/// The same reference as `RepoDigestOrExact` says it for `intended`.
fn repo_digest_or_exact(intended: &Ref, signed: &Ref) -> bool {
    has_reference(signed)
        && if intended.tag.is_some() {
            intended == signed
        } else {
            intended.digest.is_some() && intended.name == signed.name
        }
}

/// What the rule says, with the references compared field by field.
fn identity_text(rule: &Rule, intended: &Ref, signed: &Ref) -> bool {
    match rule {
        Rule::Exact => has_reference(intended) && has_reference(signed) && intended == signed,
        Rule::RepoDigestOrExact => repo_digest_or_exact(intended, signed),
        Rule::Repository => intended.name == signed.name,
        Rule::ExactReference(r) => has_reference(r) && has_reference(signed) && r == signed,
        Rule::ExactRepository(name) => *name == signed.name,
        Rule::Remapped(r) => repo_digest_or_exact(r, signed),
        Rule::Nothing => false,
    }
}

/// The fact is a signature that satisfies the rule.
fn counts(rule: &Rule, intended: &Ref, fact: &Fact) -> bool {
    match fact {
        Fact::Unverified => false,
        Fact::Verified {
            digest_matches,
            signed,
            ..
        } => *digest_matches && identity_text(rule, intended, signed),
    }
}

/// The signature of a requirement: the newest that counts, the first of
/// them when two are as new.
fn newest_of(rule: &Rule, intended: &Ref, facts: &[Fact]) -> Option<(usize, i64)> {
    let mut best: Option<(usize, i64)> = None;
    for (i, fact) in facts.iter().enumerate() {
        if let Fact::Verified { time, .. } = fact {
            if counts(rule, intended, fact) && best.is_none_or(|(_, t)| *time > t) {
                best = Some((i, *time));
            }
        }
    }
    best
}

fn for_pulls(mode: Mode) -> bool {
    mode != Mode::SignaturesOnly
}

/// What the kind of a requirement refuses, by the table.
fn refuses_by_kind(mode: Mode, item: &Item) -> Option<Why> {
    match item {
        Item::Reject if for_pulls(mode) => Some(Why::Rejected),
        Item::Unimplemented if for_pulls(mode) => Some(Why::Unimplemented),
        Item::Unusable => Some(Why::Unusable),
        _ => None,
    }
}

fn is_signed(item: &Item) -> bool {
    matches!(item, Item::Signed(..))
}

/// Checks what `precheck` answers for the kinds of `items`, and that it
/// holds whatever the facts of the signatures are.
pub fn check_precheck(mode: Mode, intended: &Ref, items: &[Item]) {
    let what = || format!("{mode:?} {items:?}");
    let by_kind = items
        .iter()
        .enumerate()
        .find_map(|(at, item)| refuses_by_kind(mode, item).map(|why| (at, why)));
    let wanted = if items.is_empty() {
        Pre::Refuse {
            at: 0,
            why: Why::Empty,
        }
    } else if let Some((at, why)) = by_kind {
        Pre::Refuse { at, why }
    } else if mode == Mode::MustBeSigned && !items.iter().any(is_signed) {
        Pre::Refuse {
            at: 0,
            why: Why::NotSigned,
        }
    } else if items.iter().any(is_signed) {
        Pre::NeedsSignatures
    } else {
        Pre::Accept
    };
    let got = precheck(mode, items);
    assert_eq!(got, wanted, "the pre-check by the table: {}", what());
    // P6: what is said before the signatures holds whatever they are
    let outcome = decide(mode, intended, items);
    match got {
        Pre::Refuse { .. } => {
            assert!(matches!(outcome, Outcome::Refuse { .. }), "{}", what());
        }
        Pre::Accept => {
            assert!(matches!(outcome, Outcome::Accept { .. }), "{}", what());
        }
        Pre::NeedsSignatures => {}
    }
}

/// Checks what `decide` answers for `items`.
pub fn check_decision(mode: Mode, intended: &Ref, items: &[Item]) {
    let what = || format!("{mode:?} for {intended:?}: {items:?}");
    let got = decide(mode, intended, items);
    // D1: the table: every requirement must hold, the first that does not
    // refuses, an empty list refuses, and `MustBeSigned` needs a signature
    let mut used = Vec::new();
    let mut refused = None;
    for (at, item) in items.iter().enumerate() {
        let why = match (refuses_by_kind(mode, item), item) {
            (Some(why), _) => Some(why),
            (None, Item::Signed(rule, facts)) => match newest_of(rule, intended, facts) {
                Some(found) => {
                    used.push(found);
                    None
                }
                None => Some(Why::NoSignature),
            },
            (None, _) => None,
        };
        if let Some(why) = why {
            refused = Some(Outcome::Refuse { at, why });
            break;
        }
    }
    let wanted = if items.is_empty() {
        Outcome::Refuse {
            at: 0,
            why: Why::Empty,
        }
    } else if let Some(refusal) = refused {
        refusal
    } else if mode == Mode::MustBeSigned && used.is_empty() {
        Outcome::Refuse {
            at: 0,
            why: Why::NotSigned,
        }
    } else {
        Outcome::Accept {
            used: used.iter().map(|(i, _)| *i).collect(),
            signed: used.iter().map(|(_, t)| *t).min().unwrap_or(0),
        }
    };
    assert_eq!(got, wanted, "the decision by the table: {}", what());
    match &got {
        Outcome::Refuse { at, .. } => {
            // D2: a refusal names a requirement of the list
            assert!(*at < items.len().max(1), "{}", what());
        }
        Outcome::Accept { used, signed } => {
            check_security(mode, intended, items, used, *signed, &what)
        }
    }
}

/// The security claim: when the image is accepted, each signature
/// requirement has a signature that was verified, names the manifest and
/// the reference the rule says, and is the newest of those; no
/// requirement that refuses by its kind is there; and the times are of
/// those signatures.
fn check_security(
    mode: Mode,
    intended: &Ref,
    items: &[Item],
    used: &[usize],
    signed: i64,
    what: &dyn Fn() -> String,
) {
    let signed_items: Vec<(&Rule, &Vec<Fact>)> = items
        .iter()
        .filter_map(|item| match item {
            Item::Signed(rule, facts) => Some((rule, facts)),
            _ => None,
        })
        .collect();
    assert_eq!(
        used.len(),
        signed_items.len(),
        "one signature for each: {}",
        what()
    );
    let mut times = Vec::new();
    for ((rule, facts), index) in signed_items.iter().zip(used) {
        let Fact::Verified {
            digest_matches: true,
            signed: named,
            time,
        } = &facts[*index]
        else {
            panic!(
                "a signature that was verified and names the manifest: {}",
                what()
            );
        };
        times.push(*time);
        match rule {
            Rule::Exact => assert!(
                named.name == intended.name
                    && named.tag == intended.tag
                    && named.digest == intended.digest
                    && has_reference(named),
                "exactly the reference asked: {}",
                what()
            ),
            Rule::RepoDigestOrExact if intended.tag.is_some() => {
                assert_eq!(named, intended, "the reference asked, by tag: {}", what())
            }
            Rule::RepoDigestOrExact => {
                assert!(
                    intended.digest.is_some() && named.name == intended.name,
                    "the name asked, by digest: {}",
                    what()
                )
            }
            Rule::Repository => assert_eq!(named.name, intended.name, "{}", what()),
            Rule::ExactReference(r) => assert_eq!(named, r, "{}", what()),
            Rule::ExactRepository(name) => assert_eq!(&named.name, name, "{}", what()),
            Rule::Remapped(r) if r.tag.is_some() => assert_eq!(named, r, "{}", what()),
            Rule::Remapped(r) => assert!(
                r.digest.is_some() && named.name == r.name,
                "the name remapped, by digest: {}",
                what()
            ),
            Rule::Nothing => panic!("a rule that matches nothing was satisfied: {}", what()),
        }
        // no signature that counts is newer
        for fact in facts.iter() {
            if let Fact::Verified { time: other, .. } = fact {
                assert!(
                    !counts(rule, intended, fact) || other <= time,
                    "the newest signature: {}",
                    what()
                );
            }
        }
    }
    assert_eq!(
        signed,
        times.iter().copied().min().unwrap_or(0),
        "the oldest time: {}",
        what()
    );
    assert!(
        !items
            .iter()
            .any(|item| refuses_by_kind(mode, item).is_some()),
        "no requirement that refuses: {}",
        what()
    );
    assert!(mode != Mode::MustBeSigned || !used.is_empty(), "{}", what());
}

/// A signature found for one more requirement never turns an acceptance
/// into a refusal: `extra` is added to the facts of each signature
/// requirement, at the front and at the end.
pub fn check_monotonic(mode: Mode, intended: &Ref, items: &[Item], extra: &Fact) {
    if !matches!(decide(mode, intended, items), Outcome::Accept { .. }) {
        return;
    }
    for (k, item) in items.iter().enumerate() {
        let Item::Signed(rule, facts) = item else {
            continue;
        };
        for front in [true, false] {
            let mut more = facts.clone();
            if front {
                more.insert(0, extra.clone());
            } else {
                more.push(extra.clone());
            }
            let mut items = items.to_vec();
            items[k] = Item::Signed(rule.clone(), more);
            assert!(
                matches!(decide(mode, intended, &items), Outcome::Accept { .. }),
                "a signature added to {k} refuses: {mode:?} {intended:?} {items:?} {extra:?}"
            );
        }
    }
}

/// The records of the latest time of `records`, by index.
fn latest(records: &[Signed]) -> Vec<usize> {
    let time = records.iter().map(|r| r.time).max();
    (0..records.len())
        .filter(|i| Some(records[*i].time) == time)
        .collect()
}

/// Checks what `pick` answers for `records`.
pub fn check_pick(records: &[Signed]) {
    let what = || format!("{records:?}");
    let got = pick(records);
    // K1: by what the claims say: no record names nothing; otherwise the
    // first record of the latest time is named, and it is a tie when one
    // of that time has another digest (the last such is the other)
    let latest = latest(records);
    let wanted = match latest.first() {
        None => Picked::Nothing,
        Some(&first) => {
            let other = latest
                .iter()
                .rfind(|j| records[**j].digest != records[first].digest);
            match other {
                None => Picked::One(first),
                Some(&other) => Picked::Tie(first, other),
            }
        }
    };
    assert_eq!(got, wanted, "{}", what());
    // K2: a record strictly later than all of them wins, whatever is
    // below it
    if records.iter().all(|r| r.time < i64::MAX) {
        let later = records.iter().map(|r| r.time).max().map_or(0, |t| t + 1);
        for digest in ["a", "b"] {
            let mut more = records.to_vec();
            more.push(Signed {
                time: later,
                digest: digest.as_bytes().to_vec(),
            });
            assert_eq!(pick(&more), Picked::One(records.len()), "{}", what());
        }
    }
}

/// `again` is `records` in another order: the same time, and the same
/// digest or a tie again; the index may name another of equal records.
pub fn check_order(records: &[Signed], again: &[Signed]) {
    let what = || format!("{records:?} and {again:?}");
    match (pick(records), pick(again)) {
        (Picked::Nothing, Picked::Nothing) | (Picked::Tie(..), Picked::Tie(..)) => {}
        (Picked::One(a), Picked::One(b)) => {
            assert_eq!(records[a], again[b], "the same record: {}", what())
        }
        (a, b) => panic!("{a:?} and {b:?}: {}", what()),
    }
}
