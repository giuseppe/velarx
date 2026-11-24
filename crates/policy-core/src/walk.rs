// SPDX-License-Identifier: Apache-2.0
//! The decisions of small worlds, every one of them, and the rules checked
//! on each (see `rules`): the scopes of policy.json that apply to every name
//! of a small alphabet, and the requirements of a policy with every kind of
//! requirement, every rule of identity and a few signatures, in every mode.

use super::rules::{
    check_decision, check_monotonic, check_order, check_pick, check_precheck, check_selection,
};
use super::*;

/// Every string of 0 to `most` letters of `of`.
fn strings(of: &str, most: usize) -> Vec<String> {
    let mut all = vec![String::new()];
    let mut from = 0;
    for _ in 0..most {
        let to = all.len();
        for at in from..to {
            for letter in of.chars() {
                all.push(format!("{}{letter}", all[at]));
            }
        }
        from = to;
    }
    all
}

/// Every sequence of 0 to `most` items of `of`.
fn sequences<T: Clone>(of: &[T], most: usize) -> Vec<Vec<T>> {
    let mut all = vec![Vec::new()];
    let mut from = 0;
    for _ in 0..most {
        let to = all.len();
        for at in from..to {
            for item in of {
                let mut longer = all[at].clone();
                longer.push(item.clone());
                all.push(longer);
            }
        }
        from = to;
    }
    all
}

/// The names walked, and what is walked of the scopes.
struct Selection {
    /// The letters of a name: a host, with or without a port, and a path of
    /// components, are made of them (`.` and `:` and `/` between letters).
    alphabet: &'static str,
    /// Longest name.
    name: usize,
    /// Scopes in a policy, at most.
    scopes: usize,
}

/// The scopes that can matter to `image`: its candidates, and for each
/// of them one that is shorter by a letter and one that is longer by one.
fn neighbours(image: &Ref) -> Vec<String> {
    let name = String::from_utf8(image.name.clone()).unwrap();
    let mut near: Vec<String> = ["", "*", "*.", "*a", "*.a", "*.b"]
        .map(String::from)
        .to_vec();
    let mut reference = vec![name.clone()];
    reference.extend(
        image
            .tag
            .iter()
            .map(|t| format!("{name}:{}", String::from_utf8_lossy(t))),
    );
    reference.extend(
        image
            .digest
            .iter()
            .map(|d| format!("{name}@{}", String::from_utf8_lossy(d))),
    );
    let mut parents = vec![name.clone()];
    let mut n = name.as_str();
    while let Some((parent, _)) = n.rsplit_once('/') {
        parents.push(parent.to_string());
        n = parent;
    }
    let host = name.split(['/', ':']).next().unwrap().to_string();
    for (i, _) in host.match_indices('.') {
        parents.push(format!("*{}", &host[i..]));
    }
    for scope in reference.into_iter().chain(parents) {
        let mut shorter = scope.clone();
        shorter.pop();
        near.push(format!("{scope}a"));
        near.push(shorter);
        near.push(scope);
    }
    near.sort();
    near.dedup();
    near
}

/// The selections checked.
fn walk_selection(scope: &Selection) -> usize {
    let mut checked = 0;
    for name in strings(scope.alphabet, scope.name)
        .iter()
        .filter(|n| !n.is_empty())
    {
        for tag in [None, Some("t")] {
            for digest in [None, Some("sha256:d")] {
                let image = Ref {
                    name: name.as_bytes().to_vec(),
                    tag: tag.map(|t| t.as_bytes().to_vec()),
                    digest: digest.map(|d| d.as_bytes().to_vec()),
                };
                let near = neighbours(&image);
                for policy in sequences(&near, scope.scopes) {
                    let scopes: Vec<&str> = policy.iter().map(String::as_str).collect();
                    check_selection(&scopes, &image);
                    checked += 1;
                }
            }
        }
    }
    checked
}

#[test]
fn the_rules_hold_in_the_scopes_of_a_small_world() {
    let n = walk_selection(&Selection {
        alphabet: "a/:.",
        name: 4,
        scopes: 2,
    });
    println!("{n} selections");
}

/// What the requirements of a policy are made of.
struct Decision {
    names: &'static [&'static str],
    /// The names, tags and digests of the references (of the image, of the
    /// signatures and of the rules).
    tags: &'static [Option<&'static str>],
    digests: &'static [Option<&'static str>],
    /// Signatures of a requirement, at most, when it is the only one.
    facts: usize,
    /// Requirements of a policy, at most.
    items: usize,
    /// When a signature was made.
    times: &'static [i64],
}

fn references(world: &Decision) -> Vec<Ref> {
    let mut all = Vec::new();
    for name in world.names {
        for tag in world.tags {
            for digest in world.digests {
                all.push(Ref {
                    name: name.as_bytes().to_vec(),
                    tag: tag.map(|t| t.as_bytes().to_vec()),
                    digest: digest.map(|d| d.as_bytes().to_vec()),
                });
            }
        }
    }
    all
}

fn rules(refs: &[Ref]) -> Vec<Rule> {
    let mut all = vec![
        Rule::Exact,
        Rule::RepoDigestOrExact,
        Rule::Repository,
        Rule::Nothing,
    ];
    for r in refs {
        all.push(Rule::ExactReference(r.clone()));
        all.push(Rule::Remapped(r.clone()));
    }
    for name in [&refs[0].name, &refs[refs.len() - 1].name] {
        all.push(Rule::ExactRepository(name.clone()));
    }
    all
}

fn facts(world: &Decision, refs: &[Ref]) -> Vec<Fact> {
    let mut all = vec![Fact::Unverified];
    for digest_matches in [true, false] {
        for signed in refs {
            for time in world.times {
                all.push(Fact::Verified {
                    digest_matches,
                    signed: signed.clone(),
                    time: *time,
                });
            }
        }
    }
    all
}

const MODES: [Mode; 3] = [Mode::Whole, Mode::SignaturesOnly, Mode::MustBeSigned];

/// The decisions checked: one signature requirement of every rule with
/// every list of signatures (`facts`), and lists of requirements of every
/// kind.
fn walk_decision(world: &Decision, one: &[Rule], pair: &[Rule]) -> usize {
    let refs = references(world);
    let all_facts = facts(world, &refs);
    let lists = sequences(&all_facts, world.facts);
    let kinds = [
        Item::AcceptAnything,
        Item::Reject,
        Item::Unimplemented,
        Item::Unusable,
    ];
    let mut checked = 0;
    // (the walk must see both answers in every mode)
    let (mut accepts, mut refuses) = ([0; 3], [0; 3]);
    let mut tally = |m: usize, mode: Mode, intended: &Ref, items: &[Item]| match decide(
        mode, intended, items,
    ) {
        Outcome::Accept { .. } => accepts[m] += 1,
        Outcome::Refuse { .. } => refuses[m] += 1,
    };
    // one requirement of a rule with every list of signatures
    for intended in &refs {
        for rule in one {
            for facts in &lists {
                let items = [Item::Signed(rule.clone(), facts.clone())];
                for (m, mode) in MODES.into_iter().enumerate() {
                    check_decision(mode, intended, &items);
                    check_precheck(mode, intended, &items);
                    tally(m, mode, intended, &items);
                    for extra in all_facts.iter().step_by(3) {
                        check_monotonic(mode, intended, &items, extra);
                    }
                    checked += 1;
                }
            }
        }
    }
    // lists of requirements of every kind, each signature requirement with
    // at most one signature
    let mut each: Vec<Item> = kinds.to_vec();
    for rule in pair {
        for fact in all_facts.iter().step_by(3) {
            each.push(Item::Signed(rule.clone(), vec![fact.clone()]));
        }
        each.push(Item::Signed(rule.clone(), Vec::new()));
    }
    for intended in &refs {
        for items in sequences(&each, world.items) {
            for (m, mode) in MODES.into_iter().enumerate() {
                check_decision(mode, intended, &items);
                check_precheck(mode, intended, &items);
                tally(m, mode, intended, &items);
                checked += 1;
            }
        }
    }
    assert!(
        accepts.iter().chain(&refuses).all(|n| *n > 0),
        "{accepts:?} {refuses:?}"
    );
    checked
}

#[test]
fn the_rules_hold_in_the_decisions_of_a_small_world() {
    let world = Decision {
        names: &["a", "ab"],
        tags: &[None, Some("1")],
        digests: &[None, Some("sha256:d")],
        facts: 2,
        items: 2,
        times: &[1, 2],
    };
    let refs = references(&world);
    let n = walk_decision(&world, &rules(&refs), &rules(&refs));
    println!("{n} decisions");
}

/// Longer names and policies of three scopes.
/// `cargo test --release -p velarx-policy-core -- --ignored`.
#[test]
#[ignore]
fn the_rules_hold_in_the_scopes_of_a_larger_world() {
    let n = walk_selection(&Selection {
        alphabet: "a/:.",
        name: 5,
        scopes: 3,
    });
    println!("{n} selections, all");
}

/// Two tags and every rule in the lists of requirements.
/// `cargo test --release -p velarx-policy-core -- --ignored`.
#[test]
#[ignore]
fn the_rules_hold_in_the_decisions_of_a_larger_world() {
    let world = Decision {
        names: &["a", "ab", "b"],
        tags: &[None, Some("1"), Some("2")],
        digests: &[None, Some("sha256:d")],
        facts: 2,
        items: 2,
        times: &[1, 2],
    };
    let refs = references(&world);
    let all = rules(&refs);
    let n = walk_decision(&world, &all, &all);
    println!("{n} decisions, all");
}

/// Every order of `list`.
fn orders<T: Clone>(list: &[T]) -> Vec<Vec<T>> {
    if list.is_empty() {
        return vec![Vec::new()];
    }
    let mut all = Vec::new();
    for i in 0..list.len() {
        let mut rest = list.to_vec();
        let first = rest.remove(i);
        for mut order in orders(&rest) {
            order.insert(0, first.clone());
            all.push(order);
        }
    }
    all
}

/// Every list of up to 4 records of 3 times (the extremes of `i64` and one
/// between) and 3 digests (one is the beginning of another), in every
/// order: what each names, and that they agree.
#[test]
fn the_rules_hold_in_the_picks_of_a_small_world() {
    let mut all = Vec::new();
    for time in [i64::MIN, 0, i64::MAX] {
        for digest in ["a", "ab", "b"] {
            all.push(Signed {
                time,
                digest: digest.as_bytes().to_vec(),
            });
        }
    }
    let (mut checked, mut seen) = (0, [0; 3]);
    for records in sequences(&all, 4) {
        for order in orders(&records) {
            check_pick(&order);
            check_order(&records, &order);
            match pick(&order) {
                Picked::Nothing => seen[0] += 1,
                Picked::One(_) => seen[1] += 1,
                Picked::Tie(..) => seen[2] += 1,
            }
            checked += 1;
        }
    }
    assert!(seen.iter().all(|n| *n > 0), "{seen:?}");
    println!("{checked} picks");
}
