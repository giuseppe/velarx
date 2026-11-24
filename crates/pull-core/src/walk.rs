// SPDX-License-Identifier: Apache-2.0
//! The states the core reaches with three names, five starts of a pull and
//! two layers, whatever the server calls and in whatever order, and the
//! rules checked at every step of the way (see `rules`).
//!
//! The calls are those the server may make, with a number it may still
//! hold: the pull of a name that began again, one that was forgotten, one
//! that is over.  Nothing is assumed of the order.

use super::rules::{Event, Shell, WANTS};
use super::*;
use std::collections::HashSet;

const NAMES: usize = 3;
const WHYS: [Why; 4] = [Why::Aborted, Why::Late, Why::Gone, Why::Failed];

/// Every call that may come next.
fn calls(s: &Shell) -> Vec<Event> {
    let mut calls = Vec::new();
    for name in 0..NAMES {
        // (a pull that lives answers busy or resumed, it does not start)
        let lives = s.names[name].is_some_and(|n| s.core.live(n));
        if lives || (s.core.last as usize) < WANTS.len() {
            calls.push(Event::Begin(name));
        }
    }
    for p in 1..=s.core.last {
        calls.extend([Event::Claim(p), Event::Staged(p), Event::Commit(p)]);
        calls.extend(WHYS.map(|why| Event::Stop(p, why)));
        calls.extend([Event::End(p, false), Event::End(p, true), Event::Forget(p)]);
    }
    calls
}

/// The states reached with at most `depth` calls, each seen once.
fn walk(depth: u32) -> usize {
    let mut seen = HashSet::new();
    let mut reached = vec![Shell::default()];
    for _ in 0..depth {
        let mut next = Vec::new();
        for s in &reached {
            for call in calls(s) {
                let mut s = s.clone();
                s.tell(call);
                if seen.insert(s.key()) {
                    next.push(s);
                }
            }
        }
        reached = next;
        if reached.is_empty() {
            break;
        }
    }
    seen.len()
}

#[test]
fn the_rules_hold_in_the_states_a_few_calls_reach() {
    walk(6);
}

/// The same, to the end: every state there is, 290 thousand of them.
/// `cargo test --release -p velarx-pull-core -- --ignored`.
#[test]
#[ignore]
fn the_rules_hold_in_every_state_of_a_small_world() {
    println!("{} states, all", walk(u32::MAX));
}
