// SPDX-License-Identifier: Apache-2.0
//! The rules of the decisions of a pull, checked after every call of
//! the core: what each call answers for the phase the pull was in, how a
//! phase may change, and what the table holds when the call is over.
//!
//! [`Shell`] stands for the server around the core: it keeps the layers
//! each pull asked for and the number of the pull each name last began,
//! and makes the calls the server makes, with the numbers it may still
//! hold, those of pulls that ended included.

use super::*;
use std::collections::BTreeMap;

/// What the pulls ask for, in the order they start: they share layers.
pub const WANTS: [&[LayerId]; 5] = [&[10, 11], &[11], &[10], &[10, 11], &[11]];

/// What the server does to the core.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    /// The pull of a name begins again.
    Begin(usize),
    Claim(PullId),
    Staged(PullId),
    Commit(PullId),
    Stop(PullId, Why),
    End(PullId, bool),
    Forget(PullId),
}

impl Event {
    /// The pull the call is about; a begin is about a name.
    fn pull(self) -> Option<PullId> {
        match self {
            Event::Begin(_) => None,
            Event::Claim(p) | Event::Staged(p) | Event::Commit(p) => Some(p),
            Event::Stop(p, _) | Event::End(p, _) | Event::Forget(p) => Some(p),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct Shell {
    pub core: Core,
    /// The pull each name began last.
    pub names: [Option<PullId>; 3],
    wants: BTreeMap<PullId, &'static [LayerId]>,
    log: Vec<String>,
}

/// How far a pull is: a phase never goes back.  Committing and stopping
/// are one rank, so that neither turns into the other.
fn rank(phase: Phase) -> u8 {
    match phase {
        Phase::Waiting => 0,
        Phase::Fetching => 1,
        Phase::Staged => 2,
        Phase::Committing | Phase::Stopping(_) => 3,
        Phase::Over(_) => 4,
    }
}

/// The layers the table says `p` holds.
fn holds(c: &Core, p: PullId) -> Vec<LayerId> {
    let mut layers: Vec<_> = c
        .claims
        .iter()
        .filter(|h| h.pull == p)
        .map(|h| h.layer)
        .collect();
    layers.sort();
    layers
}

/// `layers`, sorted, to compare with what [`holds`] says.
fn sorted(layers: &[LayerId]) -> Vec<LayerId> {
    let mut layers = layers.to_vec();
    layers.sort();
    layers
}

impl Shell {
    fn wants(&self, p: PullId) -> &'static [LayerId] {
        self.wants.get(&p).copied().unwrap_or(&[])
    }

    pub fn key(&self) -> String {
        format!("{:?}{:?}{:?}", self.core, self.names, self.wants)
    }

    fn must(&self, ok: bool, rule: &str) {
        assert!(ok, "{rule}\n{}", self.log.join("\n"));
    }

    /// Make the call, and check the rules of it.
    pub fn tell(&mut self, event: Event) {
        self.log.push(format!("{event:?}"));
        let before = self.core.clone();
        match event {
            Event::Begin(name) => {
                let old = self.names[name];
                let got = self.core.begin(old);
                let expected = match old.and_then(|o| before.phase(o)) {
                    Some(Phase::Staged | Phase::Committing) => Some(Begin::Resumed),
                    Some(Phase::Waiting | Phase::Fetching | Phase::Stopping(_)) => {
                        Some(Begin::Busy)
                    }
                    _ => None,
                };
                match (expected, got) {
                    (Some(expected), got) => {
                        self.must(
                            got == expected,
                            "a begin on a live pull answers by its phase",
                        );
                    }
                    (None, Begin::Started(n)) => {
                        let new = self.wants.keys().all(|k| *k < n);
                        self.must(new, "a pull starts under a number never used");
                        self.wants.insert(n, WANTS[n as usize - 1]);
                        self.names[name] = Some(n);
                    }
                    (None, _) => self.must(false, "a begin on a pull that is over starts one"),
                }
            }
            Event::Claim(p) => {
                let wanted = self.wants(p);
                let got = self.core.claim(p, wanted);
                let free = wanted.iter().all(|l| !before.held(*l));
                let waiting = before.phase(p) == Some(Phase::Waiting);
                self.must(
                    waiting || got == Claim::Stopped,
                    "a pull that is not waiting claims nothing",
                );
                self.must(
                    !(waiting && free) || got == Claim::Yes,
                    "a waiting pull claims layers that are free",
                );
                self.must(
                    !(waiting && !free) || got == Claim::Wait,
                    "a waiting pull waits for layers that are held",
                );
                let all_or_none = if got == Claim::Yes {
                    holds(&self.core, p) == sorted(wanted)
                } else {
                    holds(&self.core, p) == holds(&before, p)
                };
                self.must(all_or_none, "a claim takes all the layers or none");
            }
            Event::Staged(p) => {
                let got = self.core.staged(p);
                let fetching = before.phase(p) == Some(Phase::Fetching);
                self.must(
                    got == fetching,
                    "staged answers yes to a fetching pull only",
                );
            }
            Event::Commit(p) => {
                let got = self.core.commit(p);
                let expected = match before.phase(p) {
                    None => Commit::Unknown,
                    Some(Phase::Waiting | Phase::Fetching) => Commit::Early,
                    Some(Phase::Over(outcome)) => Commit::Over(outcome),
                    Some(_) => Commit::Wait,
                };
                self.must(got == expected, "a commit answers by the phase of the pull");
            }
            Event::Stop(p, why) => {
                self.core.stop(p, why);
                let stops = matches!(
                    before.phase(p),
                    Some(Phase::Waiting | Phase::Fetching | Phase::Staged)
                );
                let expected = if stops {
                    Some(Phase::Stopping(why))
                } else {
                    before.phase(p)
                };
                self.must(self.core.phase(p) == expected, "a stop takes at once, once");
            }
            Event::End(p, published) => {
                self.core.end(p, published);
                let over = matches!(self.core.phase(p), Some(Phase::Over(_)));
                self.must(over || before.phase(p).is_none(), "an end ends the pull");
            }
            Event::Forget(p) => self.core.forget(p),
        }
        self.moved(&before, event);
        self.table();
    }

    /// How the pulls changed: a phase goes forward, by the call that
    /// moves it, and a stop or a commit stands.
    fn moved(&self, before: &Core, event: Event) {
        let numbers = before.pulls.iter().chain(&self.core.pulls).map(|x| x.id);
        for n in numbers {
            let (a, b) = (before.phase(n), self.core.phase(n));
            let begins = matches!(event, Event::Begin(_));
            match (a, b) {
                (None, None) => {}
                (None, Some(b)) => self.must(
                    begins && b == Phase::Waiting,
                    "only a begin starts a pull, waiting",
                ),
                (Some(_), None) => self.must(
                    begins || event == Event::Forget(n),
                    "only a forget or a begin drops a pull",
                ),
                (Some(a), Some(b)) if a == b => {}
                (Some(Phase::Over(_)), Some(_)) => {
                    self.must(false, "an outcome stays (a second end changes nothing)")
                }
                (Some(a), Some(b)) => {
                    self.must(event.pull() == Some(n), "a call moves only its own pull");
                    if let Phase::Stopping(why) = a {
                        self.must(b == Phase::Over(Some(why)), "the first stop stands");
                    }
                    if a == Phase::Committing {
                        self.must(
                            matches!(b, Phase::Over(_)),
                            "a commit is not turned into a stop",
                        );
                    }
                    self.must(rank(a) < rank(b), "a phase goes forward");
                    if b == Phase::Over(None) {
                        let end = event == Event::End(n, true);
                        self.must(
                            a == Phase::Committing && end,
                            "published only from committing",
                        );
                    }
                    if b == Phase::Committing {
                        let commit = event == Event::Commit(n);
                        self.must(a == Phase::Staged && commit, "committing only from staged");
                    }
                    if matches!(b, Phase::Stopping(_)) {
                        self.must(matches!(event, Event::Stop(..)), "only a stop stops a pull");
                    }
                }
            }
            let claims = matches!(event, Event::Claim(p) if p == n);
            if self.core.live(n) && before.live(n) && !claims {
                let kept = holds(before, n) == holds(&self.core, n);
                self.must(kept, "claims change only by a claim, an end or a forget");
            }
        }
    }

    /// What the table holds after any call.
    fn table(&self) {
        let c = &self.core;
        let mut layers: Vec<_> = c.claims.iter().map(|h| h.layer).collect();
        layers.sort();
        layers.dedup();
        self.must(layers.len() == c.claims.len(), "a layer has one claimant");
        self.must(
            c.claims.iter().all(|h| c.live(h.pull)),
            "a claimant is a pull that is not over",
        );
        for x in &c.pulls {
            let held = holds(c, x.id);
            let all = held == sorted(self.wants(x.id));
            let none = held.is_empty();
            let rule = "a pull holds what it asked for, or nothing";
            match x.phase {
                // (a waiting pull holds nothing, so it waits only for one
                // that does not wait: no deadlock)
                Phase::Waiting | Phase::Over(_) => self.must(none, rule),
                Phase::Stopping(_) => self.must(all || none, rule),
                _ => self.must(all, rule),
            }
        }
        self.must(
            c.busy() == c.pulls.iter().any(|x| c.live(x.id)),
            "busy says whether a pull is not over",
        );
        // (every number the core or the shell knows, and one more)
        for n in 0..=c.last + 1 {
            let expected = match c.phase(n) {
                Some(Phase::Staged) => Asked::Wait,
                Some(Phase::Committing) => Asked::Publish,
                Some(Phase::Stopping(why) | Phase::Over(Some(why))) => Asked::Stop(why),
                _ => Asked::Stop(Why::Gone),
            };
            self.must(
                c.asked(n) == expected,
                "a staged pull is asked by its phase",
            );
        }
    }
}

#[test]
fn the_rules_hold_in_the_life_of_a_pull() {
    let mut s = Shell::default();
    s.tell(Event::Begin(0));
    s.tell(Event::Begin(1));
    s.tell(Event::Claim(1));
    s.tell(Event::Claim(2));
    s.tell(Event::Staged(1));
    s.tell(Event::Commit(1));
    s.tell(Event::Stop(1, Why::Aborted));
    s.tell(Event::End(1, true));
    s.tell(Event::Stop(2, Why::Aborted));
    s.tell(Event::Claim(2));
    s.tell(Event::End(2, false));
    s.tell(Event::Begin(0));
    s.tell(Event::Forget(2));
    assert_eq!(s.core.phase(3), Some(Phase::Waiting));
}
