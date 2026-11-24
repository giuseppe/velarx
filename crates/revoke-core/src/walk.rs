// SPDX-License-Identifier: Apache-2.0
//! The inputs of a small world, every one of them, and the rules checked on
//! each answer (see `rules`): three issuers, the numbers 0, 1, 2 and
//! `u64::MAX`, each held or not, and every series of parts (an issuer, a
//! number, verified or not) of up to three parts, and of four parts of two
//! issuers and the numbers 1, 2, `u64::MAX`.

use super::rules::{check, ISSUERS};
use super::*;

const NUMBERS: [u64; 4] = [0, 1, 2, u64::MAX];

/// Every state held: each of the first two issuers has none or a number.
fn states() -> Vec<Vec<Held>> {
    let mut all = vec![Vec::new()];
    for issuer in 0..2 {
        let before = all.clone();
        for state in before {
            for number in NUMBERS {
                let mut with = state.clone();
                with.push(Held { issuer, number });
                all.push(with);
            }
        }
    }
    all
}

/// Every series of `n` parts of the issuers and numbers given.
fn series(n: usize, issuers: &[u64], numbers: &[u64]) -> Vec<Vec<Part>> {
    let mut all = vec![Vec::new()];
    for _ in 0..n {
        let mut longer = Vec::new();
        for parts in &all {
            for &issuer in issuers {
                for &number in numbers {
                    for verified in [false, true] {
                        let mut more = parts.clone();
                        more.push(Part {
                            issuer,
                            number,
                            verified,
                        });
                        longer.push(more);
                    }
                }
            }
        }
        all = longer;
    }
    all
}

/// The counts of the walk: the answers, and how many adopt something.
fn walk() -> [usize; 2] {
    let mut counts = [0; 2];
    let every: Vec<u64> = (0..ISSUERS).collect();
    let mut worlds = Vec::new();
    for n in 0..=3 {
        worlds.extend(series(n, &every, &NUMBERS));
    }
    worlds.extend(series(4, &[0, 1], &[1, 2, u64::MAX]));
    for held in states() {
        for parts in &worlds {
            check(&held, parts, parts.len() <= 4);
            counts[0] += 1;
            counts[1] += usize::from(!adopt(&held, parts).is_empty());
        }
    }
    counts
}

#[test]
fn every_input_of_the_world_satisfies_the_rules() {
    let [all, adopting] = walk();
    // (the walk is not empty: the number of inputs is the product of what
    // the world says, and a part of them adopts)
    assert_eq!(all, 25 * (1 + 24 + 576 + 13824 + 20736));
    assert!(adopting > 0 && adopting < all);
}
