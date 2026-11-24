// SPDX-License-Identifier: Apache-2.0
//! What the registry client does with each answer.  A registry, and the
//! hosts it names (the token realm, the CDN of a blob, the host of an
//! upload), may be hostile or broken: the credentials of the registry and
//! the bytes of an upload must go only where the request was meant to go,
//! whatever they answer, and a request must end.
//!
//! The shell sends one request and tells what came back as an [`Answer`];
//! [`step`] says what to do next as an [`Action`].  A request is a series
//! of passes (a pass starts at the URL asked for, with or without an
//! `Authorization`, and follows the redirects), and a pass ends in the
//! answer or in another pass: the first one probes a registry that is not
//! known to ask for a token, a 401 with its challenge starts the one with
//! the token, a 401 to the token starts one with a fresh token.  The shell
//! takes the `Authorization` between the passes (that is where a realm is
//! asked, a token is fetched, and what the hints of the cache say is
//! settled): the core says only that one is wanted, and whether it is a new
//! one.
//!
//! The origin of each URL is judged by the shell and told as a [`Target`]:
//! the registry's own (`home`), the one of the URL the request started at
//! (`start`: an upload session may be on another host than the registry),
//! whether it is https, and whether the address policy lets the engine go
//! there.
//!
//! The rules, for every request and every series of answers (see `rules`):
//!
//! 1. The `Authorization` goes only to the registry's own origin
//!    ([`Request::Home`]): the type of a send to another origin has none.
//!    And never again once a request has gone to another origin: what
//!    follows, even a return to the registry, is a URL the other origin
//!    chose.
//! 2. A body goes only to the origin of the URL the request started at, and
//!    to no URL after a 301, 302 or 303 (those turn the request into a GET).
//! 3. Nothing is sent to http by a request that goes to an https registry,
//!    or has been to https: no downgrade, for a redirect nor for the URL a
//!    request starts at (the next URL of an upload).
//! 4. Every URL that is sent to was allowed by the address policy before it
//!    was sent, and so was every one that is to be remembered
//!    ([`Request::Away`] with `remember`).
//! 5. At most [`MAX_REDIRECTS`] redirects of a pass and [`MAX_RETRIES`]
//!    passes after the first: a request is at most
//!    `(MAX_RETRIES + 1) * (MAX_REDIRECTS + 1)` sends, and the counters are
//!    the state's own, so this holds whatever the registry says.
//! 6. A new pass, a new token and the `/v2/` challenge are asked only for
//!    the answer to a request the registry's own origin got with our
//!    authority (not one after the request left it); a fresh token only
//!    once.
//! 7. An event that does not answer the last action is refused
//!    ([`Why::OutOfTurn`]), and what a request has left behind (the origin it
//!    went to) is never forgotten within it: the rules above hold for every
//!    series of events, not only for the shell that tells them in order.
//! 8. An honest exchange ends: a 200, a challenge and then a 200, a redirect
//!    to an allowed CDN and then a 200.
//!
//! Written to be translated (tools/verify): plain enums and structs of
//! numbers and flags, no closure, no iterator adapter, no loop.

/// The method of a request: the shell has the real one.
#[derive(Clone, Copy)]
#[cfg_attr(test, derive(Debug, PartialEq, Eq, Hash))]
pub enum Method {
    Get,
    Head,
    Other,
}

/// What the shell knows of a URL a request may go to.
#[derive(Clone, Copy)]
#[cfg_attr(test, derive(Debug, PartialEq, Eq, Hash))]
pub struct Target {
    /// The origin (scheme, host, port) of the registry.
    pub home: bool,
    /// The origin of the URL the request started at.
    pub start: bool,
    pub https: bool,
    /// The address policy lets the engine go there (the shell says it for
    /// the registry's own origin too).
    pub allowed: bool,
}

/// What a request is, as the shell knows it before the first answer.
#[derive(Clone, Copy)]
#[cfg_attr(test, derive(Debug, PartialEq, Eq, Hash))]
pub struct Begin {
    pub home_https: bool,
    /// The URL the request starts at.
    pub start: Target,
    pub method: Method,
    /// The request has a body that is not empty.
    pub body: bool,
    /// The redirect of a first hop may be remembered (a blob).
    pub cacheable: bool,
}

/// What an answer was.
#[derive(Clone, Copy)]
#[cfg_attr(test, derive(Debug, PartialEq, Eq, Hash))]
pub enum Answer {
    /// A 401 or a 403 to a request with an `Authorization` that came from a
    /// hint of the cache, which the shell dropped (the registry is asked
    /// what it wants).
    Hinted,
    /// A 401; whether it carries a challenge the shell understood.
    Unauthorized { challenge: bool },
    /// A 403 or a 404.
    Missing,
    /// A redirect (not a 304) with a `Location` the shell resolved to a
    /// URL of http or https; `keeps` for a 307 or a 308.
    Redirect { keeps: bool, next: Target },
    /// A redirect with no `Location`, or one that is no URL of http or
    /// https.
    Unusable,
    /// Any other answer: it is the request's.
    Served,
}

/// What the shell tells.  They come in the order the actions ask.
#[derive(Clone, Copy)]
#[cfg_attr(test, derive(Debug, PartialEq, Eq, Hash))]
pub enum Event {
    /// The pass has its `Authorization` or not (`held`); `probe` when it
    /// went without on purpose, to learn what the registry wants.
    Authed {
        probe: bool,
        held: bool,
    },
    Got(Answer),
    /// The `/v2/` challenge was learned (or not).
    V2(bool),
}

/// Why a request is refused.
#[derive(Clone, Copy)]
#[cfg_attr(test, derive(Debug, PartialEq, Eq, Hash))]
pub enum Why {
    TooMany,
    Location,
    Downgrade,
    Body,
    Policy,
    /// The event does not answer the last action.
    OutOfTurn,
}

/// The next request.  `Home` is a request to the registry's own origin of a
/// request that never left it, and the only one that has an `Authorization`
/// to carry; every other, a return to the registry after another origin
/// included, is `Away`, which has no field for it.
#[derive(Clone, Copy)]
#[cfg_attr(test, derive(Debug, PartialEq, Eq, Hash))]
pub enum Request {
    Home {
        auth: bool,
        method: Method,
        body: bool,
    },
    Away {
        method: Method,
        body: bool,
        /// The URL is the redirect of the registry for what was asked:
        /// the shell may keep it for the next requests.
        remember: bool,
    },
}

#[derive(Clone, Copy)]
#[cfg_attr(test, derive(Debug, PartialEq, Eq, Hash))]
pub enum Action {
    /// Begin a pass from the URL the request started at: take its
    /// `Authorization` (`refresh`: not the one that was refused), or probe,
    /// and tell with `Authed`.
    Pass {
        refresh: bool,
    },
    Send(Request),
    /// Learn the challenge of the registry from `/v2/` and tell with `V2`.
    AskV2,
    /// The last answer is the request's.
    Done,
    Refuse(Why),
}

/// Redirects of a pass.
pub const MAX_REDIRECTS: u8 = 10;

/// Passes after the first.
pub const MAX_RETRIES: u8 = 3;

/// What the core waits for: the event that answers the last action.
#[derive(Clone, Copy)]
#[cfg_attr(test, derive(Debug, PartialEq, Eq, Hash))]
enum Wait {
    /// An `Authed`, after a `Pass`.
    Pass,
    /// An answer, after a `Send`.
    Answer,
    /// A `V2`, after an `AskV2`.
    V2,
    /// Nothing: the request is over.
    Over,
}

#[derive(Clone, Copy)]
#[cfg_attr(test, derive(Debug, PartialEq, Eq, Hash))]
pub struct State {
    begin: Begin,
    wait: Wait,
    retries: u8,
    refreshed: bool,
    probe: bool,
    held: bool,
    hops: u8,
    /// The last send was to the registry, before the request left it.
    at_home: bool,
    /// A send of the pass went to another origin.
    left_home: bool,
    https: bool,
    method: Method,
    body: bool,
}

/// A request begins: the shell takes the first `Authorization`.
pub fn begin(b: &Begin) -> (State, Action) {
    let s = State {
        begin: *b,
        wait: Wait::Pass,
        retries: 0,
        refreshed: false,
        probe: false,
        held: false,
        hops: 0,
        at_home: false,
        left_home: false,
        https: b.start.https,
        method: b.method,
        body: b.body,
    };
    (s, Action::Pass { refresh: false })
}

/// The send to `to` of the request as it is in `s`.
fn send(s: &State, to: &Target, remember: bool) -> (State, Action) {
    let mut n = *s;
    // what follows a send to another origin is not the registry's, even
    // at its own URL: a path that origin chose
    let home = if s.left_home { false } else { to.home };
    n.at_home = home;
    n.left_home = if to.home { s.left_home } else { true };
    n.https = to.https;
    if (s.https || s.begin.home_https) && !to.https {
        return (n, Action::Refuse(Why::Downgrade));
    }
    if !to.allowed {
        return (n, Action::Refuse(Why::Policy));
    }
    let request = if home {
        Request::Home {
            auth: s.held,
            method: s.method,
            body: s.body,
        }
    } else {
        Request::Away {
            method: s.method,
            body: s.body,
            remember,
        }
    };
    (n, Action::Send(request))
}

/// Another pass, if the request may have one.
fn retry(s: &State) -> (State, Action) {
    if s.retries >= MAX_RETRIES {
        return (*s, Action::Done);
    }
    let mut n = *s;
    n.retries += 1;
    (
        n,
        Action::Pass {
            refresh: s.refreshed,
        },
    )
}

fn redirect(s: &State, keeps: bool, next: &Target) -> (State, Action) {
    if s.hops >= MAX_REDIRECTS {
        return (*s, Action::Refuse(Why::TooMany));
    }
    if keeps && s.body && !next.start {
        return (*s, Action::Refuse(Why::Body));
    }
    let mut n = *s;
    n.hops += 1;
    if !keeps {
        n.method = match s.method {
            Method::Head => Method::Head,
            _ => Method::Get,
        };
        n.body = false;
    }
    let remember = if next.start {
        false
    } else {
        s.hops == 0 && s.begin.cacheable && next.allowed
    };
    send(&n, next, remember)
}

fn got(s: &State, a: &Answer) -> (State, Action) {
    match *a {
        Answer::Hinted if s.at_home && !s.refreshed => retry(s),
        Answer::Unauthorized { challenge } if s.at_home && !s.refreshed => {
            if s.probe && challenge {
                retry(s)
            } else {
                let mut n = *s;
                n.refreshed = true;
                retry(&n)
            }
        }
        Answer::Missing if s.at_home && s.probe => (*s, Action::AskV2),
        Answer::Redirect { keeps, next } => redirect(s, keeps, &next),
        Answer::Unusable if s.hops >= MAX_REDIRECTS => (*s, Action::Refuse(Why::TooMany)),
        Answer::Unusable => (*s, Action::Refuse(Why::Location)),
        _ => (*s, Action::Done),
    }
}

/// The request goes on, for an event that answers the last action.
fn advance(s: &State, e: &Event) -> (State, Action) {
    match *e {
        Event::Authed { probe, held } => {
            let mut n = *s;
            n.probe = probe;
            n.held = held;
            n.hops = 0;
            n.https = false;
            n.method = s.begin.method;
            n.body = s.begin.body;
            send(&n, &s.begin.start, false)
        }
        Event::Got(a) => got(s, &a),
        Event::V2(true) if !s.refreshed => retry(s),
        Event::V2(_) => (*s, Action::Done),
    }
}

/// The event is the one the core waits for: an `Authed` after a pass, an
/// answer after a send, a `V2` after the challenge was asked.
fn answers(wait: Wait, e: &Event) -> bool {
    match wait {
        Wait::Pass => matches!(e, Event::Authed { .. }),
        Wait::Answer => matches!(e, Event::Got(_)),
        Wait::V2 => matches!(e, Event::V2(_)),
        Wait::Over => false,
    }
}

/// What the core waits for after it gave `a`.
fn waits_after(a: Action) -> Wait {
    match a {
        Action::Pass { .. } => Wait::Pass,
        Action::Send(_) => Wait::Answer,
        Action::AskV2 => Wait::V2,
        Action::Done | Action::Refuse(_) => Wait::Over,
    }
}

/// The state, and what it waits for after the action `a`.
fn settle(s: &State, a: Action) -> (State, Action) {
    let mut n = *s;
    n.wait = waits_after(a);
    (n, a)
}

/// What to do after `e`, from the state `s`.  An event that does not answer
/// the last action is refused, whatever else the state says.
pub fn step(s: &State, e: &Event) -> (State, Action) {
    if answers(s.wait, e) {
        let (n, a) = advance(s, e);
        settle(&n, a)
    } else {
        settle(s, Action::Refuse(Why::OutOfTurn))
    }
}

#[cfg(test)]
mod rules;

#[cfg(test)]
mod walk;
