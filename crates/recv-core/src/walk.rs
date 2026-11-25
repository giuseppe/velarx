// SPDX-License-Identifier: Apache-2.0
//! The inputs of the world, every one of them, and the rules checked on
//! each (see `rules`): every status byte; every answer of up to three
//! digests over the five kinds of status and the lengths and sizes at the
//! edges of two small bounds; every correct peer over the same lengths;
//! the room of an answer over the edges of its bounds; every shape of a
//! message over the edges of its limits; every sequence of up to five
//! messages of one run of a sender; every sequence of up to four messages
//! of two runs mixed; and every sequence of up to four messages of two
//! runs, with any versions of 0 to 2 (the numbers of an untrusted peer).

use super::rules::*;
use super::*;

/// The lengths around two bounds, `max_item` 4 and `max_payload` 6.
const LENS: [u64; 8] = [0, 1, 2, 3, 4, 5, 6, u64::MAX];
/// The bounds that are tried: the real ones, small ones, and the extremes.
const BOUNDS: [(u64, u64); 5] = [(4, 6), (4, 4), (6, 4), (0, 0), (u64::MAX, u64::MAX)];

#[test]
fn every_status_byte() {
    for byte in 0..=255u8 {
        check_status(byte);
    }
}

#[test]
fn every_small_answer() {
    let sizes: [Option<u64>; 4] = [None, Some(0), Some(2), Some(4)];
    // one item of an answer: a status byte, a length and a size asked
    let mut items: Vec<(u8, u64, Option<u64>)> = Vec::new();
    for byte in [0u8, 1, 2, 3, 4, 255] {
        for len in LENS {
            for size in sizes {
                // (a length and a size mean something for a chunk only)
                if byte == 1 || (len == 0 && size.is_none()) {
                    items.push((byte, len, size));
                }
            }
        }
    }
    let mut checked = 0;
    for (max_item, max_payload) in BOUNDS {
        for asked in 0..=3usize {
            let mut sent: Vec<Vec<(u8, u64, Option<u64>)>> = vec![Vec::new()];
            // answers of up to asked + 1 turns, the last one past the end
            for _ in 0..=asked.min(2) + 1 {
                let mut more = Vec::new();
                for prefix in &sent {
                    for it in &items {
                        let mut v = prefix.clone();
                        v.push(*it);
                        more.push(v);
                    }
                }
                if more.len() > 60_000 {
                    break;
                }
                for v in &more {
                    check_answer(asked, max_item, max_payload, v);
                    checked += 1;
                }
                sent = more;
            }
        }
    }
    assert!(checked > 100_000, "{checked}");
}

#[test]
fn every_correct_peer_is_taken() {
    let mut lists: Vec<Vec<u64>> = vec![Vec::new()];
    let mut from = 0;
    for _ in 0..4 {
        let to = lists.len();
        for i in from..to {
            for len in LENS {
                let mut v = lists[i].clone();
                v.push(len);
                lists.push(v);
            }
        }
        from = to;
    }
    for (max_item, max_payload) in BOUNDS {
        for l in &lists {
            check_correct_peer(max_item, max_payload, l);
        }
    }
}

#[test]
fn every_room_at_the_edges() {
    let edges = [0, 1, 2, 3, 4, 5, 6, 7, u64::MAX - 1, u64::MAX];
    for payload in edges {
        for len in edges {
            for max in edges {
                // (`payload` of an answer is at most the larger bound)
                if payload <= max.max(len) {
                    check_room(payload, len, max);
                }
            }
        }
    }
}

#[test]
fn every_item_length_at_the_edges() {
    for len in LENS.into_iter().chain([7, 100]) {
        for max in LENS.into_iter().chain([7, 100]) {
            check_item(len, max);
        }
    }
}

#[test]
fn every_shape_at_the_edges() {
    let sizes = [
        0,
        1,
        7,
        8,
        9,
        16,
        8 * MAX_DELTA_KEYS - 8,
        8 * MAX_DELTA_KEYS,
        8 * MAX_DELTA_KEYS + 8,
        MAX_FILTER_BYTES - 8,
        MAX_FILTER_BYTES - 1,
        MAX_FILTER_BYTES,
        MAX_FILTER_BYTES + 8,
        usize::MAX,
    ];
    for bytes in sizes {
        for hashes in [0u8, 1, 2, 15, 16, 17, 255] {
            check_shape(bytes, hashes);
        }
    }
    for bytes in 0..300 {
        check_shape(bytes, 1);
    }
}

/// Every message of one run over the versions 0 to `top`: a whole filter
/// of each, and a delta from each to each, a version that is not past the
/// one it starts from, or is 0, included (a peer may send any).
fn run_messages(epoch: u64, top: u64) -> Vec<Msg> {
    let mut all = Vec::new();
    for version in 0..=top {
        all.push(Msg::Full { epoch, version });
    }
    for from in 0..=top {
        for to in 0..=top {
            all.push(Msg::Delta { epoch, from, to });
        }
    }
    all
}

/// Every sequence of up to `n` messages of `all`.
fn sequences(all: &[Msg], n: usize) -> Vec<Vec<Msg>> {
    let mut out: Vec<Vec<Msg>> = vec![Vec::new()];
    let mut from = 0;
    for _ in 0..n {
        let to = out.len();
        for i in from..to {
            for m in all {
                let mut v = out[i].clone();
                v.push(*m);
                out.push(v);
            }
        }
        from = to;
    }
    out
}

/// The messages of a sender that adds a key at each version, whose versions
/// start at 1: a whole filter of each version, and the delta that follows
/// each (the deltas of a sender are those from one version to the next).
fn senders_messages(epoch: u64) -> Vec<Msg> {
    run_messages(epoch, 4)
        .into_iter()
        .filter(|m| match m {
            Msg::Delta { from, to, .. } => *from >= 1 && *from + 1 == *to,
            Msg::Full { version, .. } => *version >= 1,
        })
        .collect()
}

#[test]
fn whatever_the_versions_a_delta_of_another_run_leaves_the_filter_behind() {
    let mut both = run_messages(1, 2);
    both.extend(run_messages(2, 2));
    let all = sequences(&both, 4);
    assert!(all.len() > 300_000, "{}", all.len());
    for s in &all {
        check_closed(s);
    }
}

#[test]
fn within_one_run_no_key_that_arrived_is_said_no() {
    let all = sequences(&senders_messages(7), 5);
    assert!(all.len() > 4000, "{}", all.len());
    for s in &all {
        check_no_false_no(s);
    }
}

#[test]
fn of_two_runs_mixed_no_key_since_the_run_changed_is_said_no() {
    let mut both = senders_messages(1);
    both.extend(senders_messages(2));
    let all = sequences(&both, 4);
    assert!(all.len() > 20_000, "{}", all.len());
    for s in &all {
        check_no_false_no(s);
    }
}

#[test]
fn a_whole_filter_of_an_old_run_after_a_message_of_the_new_one_says_no() {
    // (the runs are random numbers: nothing orders them, rule 9)
    let mut m = Model::new();
    m.receive(Msg::Delta {
        epoch: 2,
        from: 1,
        to: 2,
    });
    assert_eq!(m.says(1), Said::Unknown);
    m.receive(Msg::Full {
        epoch: 1,
        version: 1,
    });
    assert_eq!(m.says(0), Said::Maybe);
    // (key 1 is held by the sender of run 2)
    assert_eq!(m.says(1), Said::No);
}

#[test]
fn a_delta_of_another_run_makes_the_filter_say_no_no() {
    let mut m = Model::new();
    m.receive(Msg::Full {
        epoch: 1,
        version: 3,
    });
    assert_eq!(m.says(9), Said::No);
    m.receive(Msg::Delta {
        epoch: 2,
        from: 1,
        to: 2,
    });
    assert!(m.seen.behind());
    assert_eq!(m.says(9), Said::Unknown);
    // (a whole filter of that run replaces it, and is believed again)
    m.receive(Msg::Full {
        epoch: 2,
        version: 2,
    });
    assert!(!m.seen.behind());
    assert_eq!(m.says(9), Said::No);
}

#[test]
fn stale_messages_leave_the_state_alone() {
    let mut s = Seen::new();
    assert_eq!(s.full(5, 4, false), OnFull::Take);
    let held = s;
    assert_eq!(s.full(5, 3, true), OnFull::Stale);
    assert_eq!(s, held);
    // (the same version again is the refresh, and renews what is held)
    assert_eq!(s.full(5, 4, true), OnFull::Take);
    assert_eq!(s, held);
    assert_eq!(s.delta(5, 4, true), OnDelta::Stale);
    assert_eq!(s, held);
    // (without a filter, an older whole one is taken)
    assert_eq!(s.full(5, 3, false), OnFull::Take);
    assert_eq!(s.version(), 3);
}
