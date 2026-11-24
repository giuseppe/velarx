// SPDX-License-Identifier: Apache-2.0
//! The inputs of a small world, every one of them, and the rules checked on
//! each answer (see `rules`): the references are four hosts (one with a
//! port, one the Hub) and two paths, pushed or pulled, with or without a
//! digest, with TLS verified or not; the blocks are one block of every
//! prefix (among them a port, the beginning of a port, a path and a
//! wildcard), of every location, every combination of the flags and every
//! choice of up to two mirrors, and every pair of smaller blocks of two
//! different prefixes.

use super::rules::check;
use super::*;

const HOSTS: [&str; 4] = ["a.test", "a.test:5000", "b.test", "docker.io"];
const PATHS: [&str; 2] = ["x", "x/y"];
const PREFIXES: [&str; 7] = [
    "a.test",
    "a.test:5000",
    "a.test:5",
    "a.test/x",
    "b.test",
    "*.test",
    "docker.io",
];
const LOCATIONS: [&str; 4] = ["m.test/z", "a.test", "n.test", "docker.io/mm"];
const MODES: [Mode; 3] = [Mode::All, Mode::DigestOnly, Mode::TagOnly];

fn mirror(location: &str, insecure: bool, mode: Mode) -> Mirror {
    Mirror {
        location: location.as_bytes().to_vec(),
        insecure,
        mode,
    }
}

/// Every mirror of the world.
fn mirrors() -> Vec<Mirror> {
    let mut all = Vec::new();
    for location in LOCATIONS {
        for insecure in [false, true] {
            for mode in MODES {
                all.push(mirror(location, insecure, mode));
            }
        }
    }
    all
}

/// No mirror, each one, and every pair of the six first of different place.
fn mirror_sets(pairs: bool) -> Vec<Vec<Mirror>> {
    let all = mirrors();
    let mut sets = vec![Vec::new()];
    for m in &all {
        sets.push(vec![m.clone()]);
    }
    for (i, a) in all.iter().enumerate().take(if pairs { 6 } else { 0 }) {
        for (j, b) in all.iter().enumerate().take(6) {
            if i != j {
                sets.push(vec![a.clone(), b.clone()]);
            }
        }
    }
    sets
}

/// The blocks of a prefix: every location, every flag, and the mirrors.
fn blocks_of(prefix: &str, locations: &[Option<&str>], sets: &[Vec<Mirror>]) -> Vec<Block> {
    let mut all = Vec::new();
    for location in locations {
        // (a wildcard prefix has no location: the file is refused)
        if prefix.starts_with("*.") && location.is_some() {
            continue;
        }
        for flags in 0..8 {
            for mirrors in sets {
                all.push(Block {
                    prefix: prefix.as_bytes().to_vec(),
                    location: location.map(|l| l.as_bytes().to_vec()),
                    insecure: flags & 1 != 0,
                    blocked: flags & 2 != 0,
                    allow_private: flags & 4 != 0,
                    mirrors: mirrors.clone(),
                });
            }
        }
    }
    all
}

/// The rules on every reference of the world; how many answers, how many
/// refused, how many with a mirror.
fn references(blocks: &[Block], counts: &mut [usize; 3]) {
    for host in HOSTS {
        for path in PATHS {
            for push in [false, true] {
                for has_digest in [false, true] {
                    for tls_verify in [false, true] {
                        let ask = Ask {
                            has_digest,
                            push,
                            tls_verify,
                        };
                        check(blocks, host, path, &ask);
                        counts[0] += 1;
                        match endpoints(blocks, host.as_bytes(), path.as_bytes(), &ask) {
                            Err(_) => counts[1] += 1,
                            Ok(all) => counts[2] += usize::from(all.len() > 1),
                        }
                    }
                }
            }
        }
    }
}

fn walk() -> [usize; 3] {
    let mut counts = [0; 3];
    // no block, and one block of every kind
    references(&[], &mut counts);
    let locations = [None, Some("m.test/z"), Some("m.test"), Some("docker.io/q")];
    let sets = mirror_sets(true);
    for prefix in PREFIXES {
        for block in blocks_of(prefix, &locations, &sets) {
            references(&[block], &mut counts);
        }
    }
    // two blocks of different prefixes, in either order
    let small = [None];
    // (no mirror, one at no block, one at the block of a.test, one at the
    // block of docker.io)
    let sets = mirror_sets(false);
    let one = [
        sets[0].clone(),
        sets[1].clone(),
        sets[1 + 6].clone(),
        sets[1 + 18].clone(),
    ];
    let mut smaller = Vec::new();
    for prefix in PREFIXES {
        smaller.extend(blocks_of(prefix, &small, &one));
    }
    for a in &smaller {
        for b in &smaller {
            if a.prefix != b.prefix {
                references(&[a.clone(), b.clone()], &mut counts);
            }
        }
    }
    counts
}

#[test]
fn every_input_of_the_world_satisfies_the_rules() {
    let [all, refused, mirrored] = walk();
    // (the walk is not empty, and the rules are checked on answers of
    // every kind)
    assert_eq!(all, 3_456_576);
    assert!(refused > 0 && mirrored > 0 && refused + mirrored < all);
}
