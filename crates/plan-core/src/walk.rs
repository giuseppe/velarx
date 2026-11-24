// SPDX-License-Identifier: Apache-2.0
//! The plans of a small world, every one of them, and the rules checked on
//! each (see `rules`): layers of a few files of a few contents and sizes,
//! whatever the stores hold, whatever the profile names, under limits that
//! cut groups at every place.

use super::rules::check;
use super::*;

/// The worlds walked.
struct Scope {
    layers: usize,
    /// Files of a layer, at most.
    files: usize,
    contents: u32,
    sizes: &'static [u64],
    /// Contents the profile names, at most.
    profile: usize,
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

/// The plans checked.
fn walk(scope: &Scope) -> usize {
    let all_files: Vec<File> = (0..scope.contents)
        .flat_map(|content| scope.sizes.iter().map(move |&size| File { content, size }))
        .collect();
    let tables = sequences(&all_files, scope.files);
    let contents: Vec<Content> = (0..scope.contents).collect();
    let profiles = sequences(&contents, scope.profile);
    let mut worlds = vec![Vec::new()];
    for _ in 0..scope.layers {
        worlds = worlds
            .iter()
            .flat_map(|w: &Vec<Vec<File>>| {
                tables.iter().map(move |t| {
                    let mut more = w.clone();
                    more.push(t.clone());
                    more
                })
            })
            .collect();
    }
    let mut checked = 0;
    for layers in &worlds {
        for held in 0..1u32 << scope.contents {
            let present: Vec<bool> = (0..scope.contents).map(|c| held >> c & 1 == 1).collect();
            for profile in &profiles {
                for files in [1, 2] {
                    for bytes in [2, 4] {
                        let limits = Limits { files, bytes };
                        check(
                            layers,
                            &present,
                            profile,
                            limits,
                            &plan(layers, &present, profile, limits),
                        );
                        checked += 1;
                    }
                }
            }
        }
    }
    checked
}

#[test]
fn the_rules_hold_in_the_plans_of_a_small_world() {
    walk(&Scope {
        layers: 3,
        files: 2,
        contents: 2,
        sizes: &[1, 3],
        profile: 2,
    });
}

/// A group is cut by the files at its third file, with profiles of three.
#[test]
fn the_rules_hold_in_the_plans_of_layers_of_three_files() {
    walk(&Scope {
        layers: 2,
        files: 3,
        contents: 3,
        sizes: &[1],
        profile: 3,
    });
}

/// Sizes that overflow when added: a hostile table.
#[test]
fn the_rules_hold_in_the_plans_of_huge_files() {
    walk(&Scope {
        layers: 2,
        files: 2,
        contents: 2,
        sizes: &[1, u64::MAX],
        profile: 2,
    });
}

/// The same with three contents and profiles of three: 100 million plans.
/// `cargo test --release -p velarx-plan-core -- --ignored`.
#[test]
#[ignore]
fn the_rules_hold_in_every_plan_of_a_larger_world() {
    let n = walk(&Scope {
        layers: 3,
        files: 2,
        contents: 3,
        sizes: &[1, 3],
        profile: 3,
    });
    println!("{n} plans, all");
}
