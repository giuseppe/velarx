// SPDX-License-Identifier: Apache-2.0
//! The inputs of a small world, every one of them, and the rules checked on
//! each answer (see `rules`): the platform asked for is of two operating
//! systems (one of them `unknown`), three architectures (two with known
//! variants) and six variants (none, the four of arm, and v9, which is
//! known to nobody); the index is every list of up to two entries of
//! three operating systems, three architectures and six variants,
//! image or not, and every list of three of a smaller kind.

use super::rules::check;
use super::*;

const OSES: [&str; 3] = ["linux", "windows", "unknown"];
const ARCHES: [&str; 3] = ["amd64", "arm", "arm64"];
const VARIANTS: [&str; 6] = ["", "v5", "v6", "v7", "v8", "v9"];

fn entries_of(
    oses: &[&'static str],
    arches: &[&'static str],
    variants: &[&'static str],
) -> Vec<Entry<'static>> {
    let mut all = Vec::new();
    for os in oses {
        for arch in arches {
            for variant in variants {
                for image in [true, false] {
                    all.push(Entry {
                        platform: Platform {
                            os: os.as_bytes(),
                            arch: arch.as_bytes(),
                            variant: variant.as_bytes(),
                        },
                        image,
                    });
                }
            }
        }
    }
    all
}

/// Every platform asked for.
fn wants() -> Vec<Platform<'static>> {
    let mut all = Vec::new();
    for os in ["linux", "unknown"] {
        for arch in ARCHES {
            for variant in VARIANTS {
                all.push(Platform {
                    os: os.as_bytes(),
                    arch: arch.as_bytes(),
                    variant: variant.as_bytes(),
                });
            }
        }
    }
    all
}

/// The lists of `size` entries of `pool`; the number checked, and the
/// number that name an entry.
fn lists(pool: &[Entry], size: usize, counts: &mut [usize; 2]) {
    let mut at = vec![0; size];
    let mut list = Vec::new();
    loop {
        list.clear();
        list.extend(at.iter().map(|&i| pool[i]));
        for want in wants() {
            check(&list, want);
            counts[0] += 1;
            counts[1] += usize::from(choose(&list, want).is_some());
        }
        // the next list, an odometer
        let mut digit = 0;
        while digit < size && at[digit] + 1 == pool.len() {
            at[digit] = 0;
            digit += 1;
        }
        if digit == size {
            break;
        }
        at[digit] += 1;
    }
}

fn walk() -> [usize; 2] {
    let mut counts = [0; 2];
    lists(&[], 0, &mut counts);
    let pool = entries_of(&OSES, &ARCHES, &VARIANTS);
    lists(&pool, 1, &mut counts);
    lists(&pool, 2, &mut counts);
    let small = entries_of(
        &["linux", "unknown"],
        &["arm", "arm64"],
        &["", "v6", "v7", "v8"],
    );
    lists(&small, 3, &mut counts);
    counts
}

#[test]
fn every_input_of_the_world_satisfies_the_rules() {
    let [all, chosen] = walk();
    // (the walk is not empty, and the rules are checked on answers of
    // both kinds)
    assert_eq!(all, 1_603_476);
    assert_eq!(chosen, 160_358);
}
