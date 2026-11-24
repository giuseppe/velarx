// SPDX-License-Identifier: Apache-2.0
//! The rules of the send loop (see the head of the crate), checked on every
//! step of the walk: the state and the action before, the event, the state
//! and the action after.  They are stated by what a request may do (which
//! URL, which credentials, which body), not by how `step` computes, and the
//! facts of the target of a send are read from the event, not from the
//! action.

use super::*;

/// The facts of the URL the send of `a` goes to, if `e` leads to one.
fn target_of(s: &State, e: &Event) -> Option<Target> {
    match e {
        Event::Authed { .. } => Some(s.begin.start),
        Event::Got(Answer::Redirect { next, .. }) => Some(*next),
        _ => None,
    }
}

/// The method that follows a redirect of a request with `method`.
fn after(method: Method, keeps: bool) -> Method {
    match (keeps, method) {
        (true, m) => m,
        (false, Method::Head) => Method::Head,
        (false, _) => Method::Get,
    }
}

fn check_send(s: &State, e: &Event, n: &State, x: &Request, left: bool, held: bool) {
    let to = target_of(s, e).expect("a send follows a pass or a redirect");
    assert!(to.allowed, "a send to a URL the policy refused");
    // 3. no http for a request of an https registry, nor after https
    assert!(to.https || !s.begin.home_https);
    let (Request::Home { method, body, .. } | Request::Away { method, body, .. }) = *x;
    // 1. the credentials: the type of a send away has none; a send home has
    // the pass's own, and a send home is to the registry's origin
    match *x {
        Request::Home { auth, .. } => {
            assert!(to.home && !left);
            // the pass's own
            assert_eq!(auth, held);
        }
        Request::Away { remember, .. } => {
            assert!(!to.home || left);
            // 4. what is remembered is the first redirect of a blob that
            // leaves the origin of the request, and it was allowed
            if remember {
                let Event::Got(Answer::Redirect { .. }) = e else {
                    panic!("remembered a URL that was not a redirect")
                };
                assert!(s.hops == 0 && s.begin.cacheable && !to.start);
            }
        }
    }
    // 2. the body goes to the origin the request started at, and was not
    // dropped by the answer that turned the request into a GET
    assert!(!body || to.start);
    match e {
        Event::Authed { .. } => {
            assert_eq!(method, s.begin.method);
            assert_eq!(body, s.begin.body);
            assert_eq!(n.hops, 0);
        }
        Event::Got(Answer::Redirect { keeps, .. }) => {
            assert_eq!(method, after(s.method, *keeps));
            assert_eq!(body, s.body && *keeps);
            assert_eq!(n.hops, s.hops + 1);
            // 3. no redirect from https to http
            assert!(!s.https || to.https);
        }
        _ => unreachable!(),
    }
    // the state after has what was sent
    assert_eq!((n.https, n.at_home), (to.https, to.home && !left));
}

fn check_refusal(s: &State, e: &Event, why: Why) {
    match (e, why) {
        (Event::Authed { .. }, Why::Policy) => assert!(!s.begin.start.allowed),
        (Event::Authed { .. }, Why::Downgrade) => {
            assert!(s.begin.home_https && !s.begin.start.https)
        }
        (Event::Got(Answer::Redirect { next, .. }), Why::Policy) => assert!(!next.allowed),
        (Event::Got(Answer::Redirect { .. } | Answer::Unusable), Why::TooMany) => {
            assert_eq!(s.hops, MAX_REDIRECTS)
        }
        (Event::Got(Answer::Redirect { next, .. }), Why::Downgrade) => {
            assert!((s.https || s.begin.home_https) && !next.https && s.hops < MAX_REDIRECTS)
        }
        (Event::Got(Answer::Redirect { keeps, next }), Why::Body) => {
            assert!(*keeps && s.body && !next.start && s.hops < MAX_REDIRECTS)
        }
        (Event::Got(Answer::Unusable), Why::Location) => assert!(s.hops < MAX_REDIRECTS),
        // the event is not the one that was waited for, and nothing else was done
        (_, Why::OutOfTurn) => assert!(!answers(s.wait, e)),
        _ => panic!("a refusal the answer does not give"),
    }
}

/// An honest redirect: within the bounds, not to http from https, a body
/// kept only to the origin of the start, allowed.
fn honest(s: &State, keeps: bool, next: &Target) -> bool {
    s.hops < MAX_REDIRECTS
        && !((s.https || s.begin.home_https) && !next.https)
        && !(keeps && s.body && !next.start)
        && next.allowed
}

/// `left`: a send of the pass before this step went to another origin;
/// `held`: the last `Authed` said the pass has an `Authorization`.
pub fn check(s: &State, e: &Event, n: &State, a: &Action, left: bool, held: bool) {
    // 5. the counters stay in their bounds, and only grow
    assert!(n.retries <= MAX_RETRIES && n.hops <= MAX_REDIRECTS);
    assert!(n.retries >= s.retries && (n.refreshed || !s.refreshed));
    assert!(n.hops >= s.hops || matches!(e, Event::Authed { .. }));
    // an event out of turn is refused, and only such an event; the request is over
    assert_eq!(
        answers(s.wait, e),
        !matches!(a, Action::Refuse(Why::OutOfTurn))
    );
    assert!(matches!(n.wait, Wait::Over) == matches!(a, Action::Done | Action::Refuse(_)));
    match a {
        Action::Send(x) => check_send(s, e, n, x, left, held),
        Action::Refuse(why) => check_refusal(s, e, *why),
        Action::Pass { refresh } => {
            // 6. a new pass is the answer of the registry's own, before the
            // request has been away
            assert!(!left);
            assert_eq!(n.retries, s.retries + 1);
            assert_eq!(*refresh, n.refreshed);
            // a fresh token is asked once: only the answer that refreshes asks for it
            assert!(!*refresh || !s.refreshed);
            match e {
                Event::Got(Answer::Hinted) => {
                    assert!(s.at_home && !s.refreshed && n.refreshed == s.refreshed)
                }
                Event::Got(Answer::Unauthorized { challenge }) => {
                    assert!(s.at_home && !s.refreshed);
                    // a challenge is learned by a probe; otherwise the
                    // token that was refused is asked again, once
                    assert_eq!(n.refreshed, !(s.probe && *challenge));
                }
                Event::V2(true) => assert!(!s.refreshed && n.refreshed == s.refreshed),
                _ => panic!("a pass that no answer of the registry asked for"),
            }
        }
        Action::AskV2 => {
            assert!(matches!(e, Event::Got(Answer::Missing)) && s.at_home && s.probe);
            assert!(!left);
        }
        Action::Done => {}
    }
    // the answers the rules above leave nothing to decide
    match (e, a) {
        _ if !answers(s.wait, e) => {}
        (Event::Got(Answer::Served), a) => assert!(matches!(a, Action::Done)),
        (Event::Got(Answer::Redirect { keeps, next }), a) if honest(s, *keeps, next) => {
            assert!(matches!(a, Action::Send(_)))
        }
        (Event::Got(Answer::Redirect { .. }), Action::Pass { .. } | Action::AskV2) => {
            panic!("a redirect asked for a token")
        }
        (Event::Got(Answer::Unauthorized { .. } | Answer::Missing), _) if !s.at_home => {
            assert!(matches!(a, Action::Done))
        }
        _ => {}
    }
}

#[test]
fn a_redirect_that_turns_a_request_into_a_get_drops_the_body() {
    let start = Target {
        home: true,
        start: true,
        https: true,
        allowed: true,
    };
    let cdn = Target {
        home: false,
        start: false,
        https: true,
        allowed: true,
    };
    for keeps in [false, true] {
        for method in [Method::Get, Method::Head, Method::Other] {
            let b = Begin {
                home_https: true,
                start,
                method,
                body: true,
                cacheable: false,
            };
            let (s, _) = begin(&b);
            let (s, _) = step(
                &s,
                &Event::Authed {
                    probe: false,
                    held: true,
                },
            );
            let (n, a) = step(&s, &Event::Got(Answer::Redirect { keeps, next: cdn }));
            match (keeps, a) {
                // a body is not sent to another origin
                (true, Action::Refuse(Why::Body)) => {}
                (
                    false,
                    Action::Send(Request::Away {
                        method: m, body, ..
                    }),
                ) => {
                    assert!(!body && n.hops == 1);
                    assert_eq!(m, after(method, false));
                }
                _ => panic!("a redirect with a body"),
            }
        }
    }
}
