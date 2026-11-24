// SPDX-License-Identifier: Apache-2.0
//! The states the core reaches with a few items and peers, whatever
//! the loop reports and in whatever order, and the rules checked at every
//! step of the way (see `rules`).
//!
//! The calls are those the loop may make (see `rules::Shell`).  Nothing is
//! assumed of the order, nor of how many items an answer brings.

use super::rules::{Event, Shell};
use std::collections::HashSet;

/// Every call that may come next.
fn calls(s: &Shell) -> Vec<Event> {
    let mut calls = Vec::new();
    if !s.running().is_empty() && s.passed < s.items {
        calls.extend([Event::Chunk(0), Event::Chunk(1)]);
    }
    for &peer in s.running() {
        for grew in 0..=s.items - s.passed {
            calls.push(Event::Ended(peer, false, grew));
            calls.push(Event::Ended(peer, true, grew));
        }
    }
    if s.searching() {
        for n in 0..=s.room() {
            calls.push(Event::Found(n));
        }
    }
    if s.group.hedge().is_some() {
        calls.push(Event::HedgeDue);
    }
    calls
}

/// Every state reached from a group of `items` items that may take `max`
/// peers, with any number of items passed on already, each seen once.
fn walk(items: usize, max: usize) -> usize {
    let mut seen = HashSet::new();
    let mut reached: Vec<Shell> = (0..items)
        .map(|passed| Shell::new(items, passed, max))
        .collect();
    while !reached.is_empty() {
        let mut next = Vec::new();
        for s in reached.iter().filter(|s| !s.finished) {
            for call in calls(s) {
                let mut s = s.clone();
                s.tell(call);
                if seen.insert(s.key()) {
                    next.push(s);
                }
            }
        }
        reached = next;
    }
    seen.len()
}

/// Three items, four peers: one under way, one hedged, one that had no room,
/// one still to ask.  29 thousand states.
#[test]
fn the_rules_hold_in_every_state_of_a_small_group() {
    walk(3, 4);
}

/// The same with four items and five peers: 1.1 million states, 8 seconds
/// in release.  `cargo test --release -p velarx-group-core -- --ignored`.
#[test]
#[ignore]
fn the_rules_hold_in_every_state_of_a_bigger_group() {
    println!("{} states", walk(4, 5));
}
