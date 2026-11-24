// SPDX-License-Identifier: Apache-2.0
//! Every request of a small world and every series of answers to it, to
//! the end: the registry's origin, the origin of an upload host and another
//! (a CDN), https or http, allowed by the address policy or not, with a
//! body or not, of each method; at each step every answer the shell can
//! tell, with every target of a redirect that the origins can make (an
//! origin has one scheme), and an event that does not answer the last action.  The steps are those of a graph of states; each
//! state is visited once, and each step checked against the rules (see
//! `rules`).  A request ends in at most `(MAX_RETRIES + 1) *
//! (MAX_REDIRECTS + 1)` sends, whatever the answers.

use super::rules::check;
use super::*;
use std::collections::{HashSet, VecDeque};

/// A state, what it asked for, the number of sends so far, and whether a
/// send of the pass went to another origin, and whether the pass holds an
/// `Authorization`.
type Node = (State, Action, u8, bool, bool);

fn target(home: bool, start: bool, https: bool, allowed: bool) -> Target {
    Target {
        home,
        start,
        https,
        allowed,
    }
}

/// Every request: the registry's own URL, or a URL of another origin;
/// an origin has one scheme.
fn begins() -> Vec<Begin> {
    let mut all = Vec::new();
    for home_https in [false, true] {
        let mut starts = vec![target(true, true, home_https, true)];
        for https in [false, true] {
            for allowed in [false, true] {
                starts.push(target(false, true, https, allowed));
            }
        }
        for start in starts {
            for method in [Method::Get, Method::Head, Method::Other] {
                for body in [false, true] {
                    for cacheable in [false, true] {
                        all.push(Begin {
                            home_https,
                            start,
                            method,
                            body,
                            cacheable,
                        });
                    }
                }
            }
        }
    }
    all
}

/// The targets of a redirect of the request `b`: each origin has one
/// scheme, and the origin of the start is the registry's or another.
fn targets(b: &Begin) -> Vec<Target> {
    let mut all = Vec::new();
    for home in [false, true] {
        for start in [false, true] {
            for https in [false, true] {
                for allowed in [false, true] {
                    let scheme =
                        (!home || https == b.home_https) && (!start || https == b.start.https);
                    let origins = if b.start.home {
                        home == start
                    } else {
                        !(home && start)
                    };
                    if scheme && origins && (!home || allowed) {
                        all.push(target(home, start, https, allowed));
                    }
                }
            }
        }
    }
    all
}

fn events(b: &Begin, last: &Action) -> Vec<Event> {
    let mut all = Vec::new();
    match last {
        Action::Pass { refresh } => {
            all.push(Event::Authed {
                probe: false,
                held: false,
            });
            all.push(Event::Authed {
                probe: false,
                held: true,
            });
            if !refresh {
                all.push(Event::Authed {
                    probe: true,
                    held: false,
                });
            }
        }
        Action::Send(_) => {
            all.push(Event::Got(Answer::Hinted));
            all.push(Event::Got(Answer::Unauthorized { challenge: false }));
            all.push(Event::Got(Answer::Unauthorized { challenge: true }));
            all.push(Event::Got(Answer::Missing));
            all.push(Event::Got(Answer::Unusable));
            all.push(Event::Got(Answer::Served));
            for keeps in [false, true] {
                for next in targets(b) {
                    all.push(Event::Got(Answer::Redirect { keeps, next }));
                }
            }
        }
        Action::AskV2 => {
            all.push(Event::V2(false));
            all.push(Event::V2(true));
        }
        Action::Done | Action::Refuse(_) => {}
    }
    all
}

/// Events that do not answer what the core waits for: one of each kind (the
/// refusal does not read what they say).
fn out_of_turn(s: &State) -> Vec<Event> {
    [
        Event::Authed {
            probe: false,
            held: true,
        },
        Event::Got(Answer::Served),
        Event::V2(true),
    ]
    .into_iter()
    .filter(|e| !answers(s.wait, e))
    .collect()
}

/// The steps taken from every request, and how many ended in each way:
/// `[nodes, steps, done, refused, longest]`.
fn walk() -> [usize; 5] {
    let mut counts = [0; 5];
    for b in begins() {
        let (s, a) = begin(&b);
        let first: Node = (s, a, 0, false, false);
        let mut seen = HashSet::from([first]);
        let mut todo = VecDeque::from([first]);
        while let Some((s, last, sent, left, held)) = todo.pop_front() {
            counts[0] += 1;
            counts[4] = counts[4].max(usize::from(sent));
            match last {
                Action::Done => counts[2] += 1,
                Action::Refuse(_) => counts[3] += 1,
                _ => {}
            }
            for e in events(&b, &last).into_iter().chain(out_of_turn(&s)) {
                let (n, a) = step(&s, &e);
                let held = match e {
                    Event::Authed { held, .. } => held,
                    _ => held,
                };
                check(&s, &e, &n, &a, left, held);
                let left = left || matches!(a, Action::Send(Request::Away { .. }));
                counts[1] += 1;
                let sent = sent + u8::from(matches!(a, Action::Send(_)));
                assert!(
                    usize::from(sent)
                        <= (usize::from(MAX_RETRIES) + 1) * (usize::from(MAX_REDIRECTS) + 1)
                );
                if seen.insert((n, a, sent, left, held)) {
                    todo.push_back((n, a, sent, left, held));
                }
            }
        }
    }
    counts
}

#[test]
fn every_request_of_the_world_satisfies_the_rules() {
    let [nodes, steps, done, refused, longest] = walk();
    assert!(nodes > 0 && steps >= nodes && done > 0 && refused > 0);
    // (the longest request: every pass of 11 sends, the four passes)
    assert_eq!(longest, 44);
}

/// The answers of an honest exchange, from the start of a request of the
/// registry's own origin to its end.
fn run(b: &Begin, probe: bool, held: bool, answers: &[Answer]) -> Vec<Action> {
    let (mut s, mut a) = begin(b);
    let mut actions = vec![a];
    let mut next = answers.iter();
    let mut event = Event::Authed { probe, held };
    loop {
        (s, a) = step(&s, &event);
        actions.push(a);
        event = match a {
            Action::Send(_) => Event::Got(*next.next().expect("an answer for each send")),
            Action::Pass { .. } => Event::Authed {
                probe: false,
                held: true,
            },
            Action::AskV2 => Event::V2(true),
            Action::Done | Action::Refuse(_) => return actions,
        };
    }
}

#[test]
fn an_honest_exchange_completes() {
    for home_https in [false, true] {
        let home = target(true, true, home_https, true);
        let cdn = target(false, false, home_https, true);
        for body in [false, true] {
            let b = Begin {
                home_https,
                start: home,
                method: Method::Get,
                body,
                cacheable: true,
            };
            let served = [Answer::Served];
            // a 200
            let done = run(&b, false, false, &served);
            assert!(matches!(done.last(), Some(Action::Done)));
            // a challenge, then a 200 with the token
            let challenge = [Answer::Unauthorized { challenge: true }, Answer::Served];
            let done = run(&b, true, false, &challenge);
            assert!(matches!(done.last(), Some(Action::Done)));
            // a redirect to an allowed CDN, then a 200
            let redirect = [
                Answer::Redirect {
                    keeps: false,
                    next: cdn,
                },
                Answer::Served,
            ];
            let done = run(&b, false, true, &redirect);
            assert!(matches!(done.last(), Some(Action::Done)));
            assert!(done
                .iter()
                .any(|a| matches!(a, Action::Send(Request::Away { remember: true, .. }))));
        }
    }
}
