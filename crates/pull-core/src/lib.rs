// SPDX-License-Identifier: Apache-2.0
//! The decisions of a pull of the storage server.  Pulls and layers are
//! numbers; every function is one atomic step on the table, called with the
//! server's lock held, and answers what its caller is to do.  A decision is
//! made once: the first stop of a pull is the one that counts, and a pull
//! that is stopping only ends.  Time is the caller's: a deadline that passed
//! is reported as [`Core::stop`] with [`Why::Late`].
//!
//! What Aeneas does not translate (an `iter_mut` that hands out a reference
//! to the phase) is avoided in the code (tools/verify/pull-core): a pull is
//! found by its place in the table, and `held` and `free` are plain loops.

pub type PullId = u32;
pub type LayerId = u32;

/// Why a pull is stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Why {
    /// The engine aborted it.
    Aborted,
    /// The engine did not decide in time.
    Late,
    /// The engine went away.
    Gone,
    /// It ended without being stopped, and did not publish.
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    /// Waiting for the layers another pull holds.
    Waiting,
    Fetching,
    /// Every object is in the store, the engine decides.
    Staged,
    /// The engine committed: the layers are being published.
    Committing,
    /// Told to stop; it ends when its task notices.
    Stopping(Why),
    /// Ended: published (`None`) or not.
    Over(Option<Why>),
}

#[derive(Debug, PartialEq, Eq)]
pub enum Begin {
    /// A new pull, with a number of its own.
    Started(PullId),
    /// The pull is staged or committing: the engine asks again.
    Resumed,
    Busy,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Claim {
    /// The layers are the pull's: it fetches.
    Yes,
    Wait,
    Stopped,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Asked {
    Wait,
    Publish,
    Stop(Why),
}

#[derive(Debug, PartialEq, Eq)]
pub enum Commit {
    /// The pull publishes, or is ending: wait for its end.
    Wait,
    /// It has not staged yet.
    Early,
    Unknown,
    Over(Option<Why>),
}

#[derive(Clone, Debug)]
struct Pull {
    id: PullId,
    phase: Phase,
}

#[derive(Clone, Debug)]
struct Held {
    layer: LayerId,
    pull: PullId,
}

#[derive(Clone, Debug, Default)]
pub struct Core {
    pulls: Vec<Pull>,
    claims: Vec<Held>,
    /// The number of the last pull started.
    last: PullId,
}

impl Core {
    /// Where the pull `p` is in the table.
    fn pull_at(&self, p: PullId) -> Option<usize> {
        self.pulls.iter().position(|x| x.id == p)
    }

    pub fn phase(&self, p: PullId) -> Option<Phase> {
        self.pull_at(p).map(|at| self.pulls[at].phase)
    }

    /// The pull `p` is not over.
    pub fn live(&self, p: PullId) -> bool {
        !matches!(self.phase(p), None | Some(Phase::Over(_)))
    }

    /// A pull is not over (only such a pull holds layers).
    pub fn busy(&self) -> bool {
        self.pulls
            .iter()
            .any(|x| !matches!(x.phase, Phase::Over(_)))
    }

    pub fn held(&self, layer: LayerId) -> bool {
        for held in self.claims.iter() {
            if held.layer == layer {
                return true;
            }
        }
        false
    }

    /// A pull starts, unless `old`, the pull the engine began before under
    /// the same name, is not over.  A new number each time: what an ended
    /// pull still does (its settling) cannot touch the one that replaces it.
    pub fn begin(&mut self, old: Option<PullId>) -> Begin {
        if let Some(old) = old {
            match self.phase(old) {
                Some(Phase::Staged | Phase::Committing) => return Begin::Resumed,
                Some(Phase::Waiting | Phase::Fetching | Phase::Stopping(_)) => return Begin::Busy,
                Some(Phase::Over(_)) | None => self.forget(old),
            }
        }
        self.last += 1;
        self.pulls.push(Pull {
            id: self.last,
            phase: Phase::Waiting,
        });
        Begin::Started(self.last)
    }

    /// None of the layers is held.
    fn free(&self, layers: &[LayerId]) -> bool {
        for layer in layers {
            if self.held(*layer) {
                return false;
            }
        }
        true
    }

    /// All the layers or none, so that two pulls cannot hold one each and
    /// wait for the other's.  The caller names each layer once.
    pub fn claim(&mut self, p: PullId, layers: &[LayerId]) -> Claim {
        let Some(at) = self.pull_at(p) else {
            return Claim::Stopped;
        };
        if self.pulls[at].phase != Phase::Waiting {
            return Claim::Stopped;
        }
        if !self.free(layers) {
            return Claim::Wait;
        }
        for layer in layers {
            self.claims.push(Held {
                layer: *layer,
                pull: p,
            });
        }
        self.pulls[at].phase = Phase::Fetching;
        Claim::Yes
    }

    /// The pull has everything in the store; false when it was stopped.
    pub fn staged(&mut self, p: PullId) -> bool {
        match self.pull_at(p) {
            Some(at) if self.pulls[at].phase == Phase::Fetching => {
                self.pulls[at].phase = Phase::Staged;
                true
            }
            _ => false,
        }
    }

    /// What a staged pull does now.
    pub fn asked(&self, p: PullId) -> Asked {
        match self.phase(p) {
            Some(Phase::Staged) => Asked::Wait,
            Some(Phase::Committing) => Asked::Publish,
            Some(Phase::Stopping(why) | Phase::Over(Some(why))) => Asked::Stop(why),
            // (forgotten: a pull of the same name replaced it)
            _ => Asked::Stop(Why::Gone),
        }
    }

    /// The engine commits the pull; asking again is the way to wait.
    pub fn commit(&mut self, p: PullId) -> Commit {
        let Some(at) = self.pull_at(p) else {
            return Commit::Unknown;
        };
        match self.pulls[at].phase {
            Phase::Staged => {
                self.pulls[at].phase = Phase::Committing;
                Commit::Wait
            }
            Phase::Committing | Phase::Stopping(_) => Commit::Wait,
            Phase::Waiting | Phase::Fetching => Commit::Early,
            Phase::Over(outcome) => Commit::Over(outcome),
        }
    }

    /// The pull is told to stop, unless it is stopping, publishing or over:
    /// the first decision stands.
    pub fn stop(&mut self, p: PullId, why: Why) {
        if let Some(at) = self.pull_at(p) {
            if matches!(
                self.pulls[at].phase,
                Phase::Waiting | Phase::Fetching | Phase::Staged
            ) {
                self.pulls[at].phase = Phase::Stopping(why);
            }
        }
    }

    /// The pull is over, published or not; its layers are free.  Ending a
    /// pull that is over changes nothing.
    pub fn end(&mut self, p: PullId, published: bool) {
        if let Some(at) = self.pull_at(p) {
            match self.pulls[at].phase {
                Phase::Over(_) => {}
                Phase::Committing if published => self.pulls[at].phase = Phase::Over(None),
                Phase::Stopping(why) => self.pulls[at].phase = Phase::Over(Some(why)),
                _ => self.pulls[at].phase = Phase::Over(Some(Why::Failed)),
            }
        }
        self.claims.retain(|h| h.pull != p);
    }

    /// Drop the record of the pull.
    pub fn forget(&mut self, p: PullId) {
        self.pulls.retain(|x| x.id != p);
        self.claims.retain(|h| h.pull != p);
    }
}

#[cfg(test)]
mod rules;

#[cfg(test)]
mod walk;

#[cfg(test)]
mod tests {
    use super::*;

    /// A pull in `phase`, reached by the calls that lead there.
    fn at(phase: Phase) -> Core {
        let mut c = Core::default();
        c.begin(None);
        if phase == Phase::Waiting {
            return c;
        }
        c.claim(1, &[7]);
        match phase {
            Phase::Staged | Phase::Committing | Phase::Over(None) => {
                c.staged(1);
            }
            _ => {}
        }
        match phase {
            Phase::Committing | Phase::Over(None) => {
                c.commit(1);
            }
            Phase::Stopping(why) => {
                c.stop(1, why);
            }
            Phase::Over(Some(Why::Failed)) => c.end(1, false),
            Phase::Over(Some(why)) => {
                c.stop(1, why);
                c.end(1, false);
            }
            _ => {}
        }
        if phase == Phase::Over(None) {
            c.end(1, true);
        }
        assert_eq!(c.phase(1), Some(phase));
        c
    }

    #[test]
    fn begin_starts_a_pull_unless_one_lives() {
        let mut c = Core::default();
        assert_eq!(c.begin(None), Begin::Started(1));
        assert_eq!(c.phase(1), Some(Phase::Waiting));
        assert_eq!(c.begin(Some(1)), Begin::Busy);
        assert_eq!(c.begin(None), Begin::Started(2));
        assert_eq!(at(Phase::Staged).begin(Some(1)), Begin::Resumed);
        assert_eq!(at(Phase::Committing).begin(Some(1)), Begin::Resumed);
        assert_eq!(at(Phase::Fetching).begin(Some(1)), Begin::Busy);
        assert_eq!(at(Phase::Stopping(Why::Late)).begin(Some(1)), Begin::Busy);
        let mut over = at(Phase::Over(None));
        assert_eq!(over.begin(Some(1)), Begin::Started(2));
        assert_eq!(over.phase(1), None);
        assert_eq!(over.phase(2), Some(Phase::Waiting));
        // (the settling of the ended pull does not stage its successor)
        over.claim(2, &[]);
        assert!(!over.staged(1));
        assert_eq!(over.phase(2), Some(Phase::Fetching));
    }

    #[test]
    fn claim_takes_all_the_layers_or_none() {
        let mut c = at(Phase::Fetching);
        c.begin(None);
        assert_eq!(c.claim(2, &[6, 7]), Claim::Wait);
        assert!(!c.held(6));
        c.end(1, false);
        assert_eq!(c.claim(2, &[6, 7]), Claim::Yes);
        assert!(c.held(6) && c.held(7));
        assert_eq!(c.phase(2), Some(Phase::Fetching));
        assert_eq!(c.claim(2, &[8]), Claim::Stopped);
        assert_eq!(c.claim(3, &[8]), Claim::Stopped);
        let mut stopped = Core::default();
        stopped.begin(None);
        stopped.stop(1, Why::Gone);
        assert_eq!(stopped.claim(1, &[]), Claim::Stopped);
    }

    #[test]
    fn staged_moves_a_fetching_pull_only() {
        let mut c = at(Phase::Fetching);
        assert!(c.staged(1));
        assert_eq!(c.phase(1), Some(Phase::Staged));
        assert!(!c.staged(1));
        assert!(!at(Phase::Stopping(Why::Aborted)).staged(1));
        assert!(!at(Phase::Over(Some(Why::Failed))).staged(1));
        assert!(!Core::default().staged(1));
    }

    #[test]
    fn asked_tells_a_staged_pull_what_to_do() {
        assert_eq!(at(Phase::Staged).asked(1), Asked::Wait);
        assert_eq!(at(Phase::Committing).asked(1), Asked::Publish);
        let stopping = at(Phase::Stopping(Why::Late));
        assert_eq!(stopping.asked(1), Asked::Stop(Why::Late));
        let over = at(Phase::Over(Some(Why::Aborted)));
        assert_eq!(over.asked(1), Asked::Stop(Why::Aborted));
        assert_eq!(Core::default().asked(1), Asked::Stop(Why::Gone));
    }

    #[test]
    fn commit_moves_a_staged_pull_and_answers_the_others() {
        let mut c = at(Phase::Staged);
        assert_eq!(c.commit(1), Commit::Wait);
        assert_eq!(c.phase(1), Some(Phase::Committing));
        assert_eq!(c.commit(1), Commit::Wait);
        assert_eq!(at(Phase::Stopping(Why::Gone)).commit(1), Commit::Wait);
        assert_eq!(at(Phase::Waiting).commit(1), Commit::Early);
        assert_eq!(at(Phase::Fetching).commit(1), Commit::Early);
        assert_eq!(at(Phase::Over(None)).commit(1), Commit::Over(None));
        let mut failed = at(Phase::Over(Some(Why::Failed)));
        assert_eq!(failed.commit(1), Commit::Over(Some(Why::Failed)));
        assert_eq!(Core::default().commit(1), Commit::Unknown);
    }

    #[test]
    fn stop_keeps_the_first_decision() {
        for before in [Phase::Waiting, Phase::Fetching, Phase::Staged] {
            let mut c = at(before);
            c.stop(1, Why::Aborted);
            assert_eq!(c.phase(1), Some(Phase::Stopping(Why::Aborted)));
            c.stop(1, Why::Late);
            assert_eq!(c.phase(1), Some(Phase::Stopping(Why::Aborted)));
        }
        let mut committing = at(Phase::Committing);
        committing.stop(1, Why::Aborted);
        assert_eq!(committing.phase(1), Some(Phase::Committing));
        let mut over = at(Phase::Over(None));
        over.stop(1, Why::Aborted);
        assert_eq!(over.phase(1), Some(Phase::Over(None)));
        Core::default().stop(1, Why::Aborted);
    }

    #[test]
    fn end_frees_the_claims_and_keeps_the_first_outcome() {
        let mut c = at(Phase::Committing);
        c.end(1, true);
        assert_eq!(c.phase(1), Some(Phase::Over(None)));
        assert!(!c.held(7));
        c.end(1, false);
        assert_eq!(c.phase(1), Some(Phase::Over(None)));
        let mut stopping = at(Phase::Stopping(Why::Late));
        stopping.end(1, false);
        assert_eq!(stopping.phase(1), Some(Phase::Over(Some(Why::Late))));
        let mut fetching = at(Phase::Fetching);
        fetching.end(1, false);
        assert_eq!(fetching.phase(1), Some(Phase::Over(Some(Why::Failed))));
        assert!(!fetching.held(7));
        let mut unpublished = at(Phase::Staged);
        unpublished.end(1, true);
        assert_eq!(unpublished.phase(1), Some(Phase::Over(Some(Why::Failed))));
    }

    #[test]
    fn forget_drops_the_pull() {
        let mut c = at(Phase::Fetching);
        c.forget(1);
        assert_eq!(c.phase(1), None);
        assert!(!c.held(7));
    }

    #[test]
    fn live_and_busy_and_held_look_at_the_table() {
        let none = Core::default();
        assert!(!none.busy() && !none.live(1) && !none.held(7));
        let waiting = at(Phase::Waiting);
        assert!(waiting.live(1) && waiting.busy() && !waiting.held(7));
        let fetching = at(Phase::Fetching);
        assert!(fetching.live(1) && fetching.busy() && fetching.held(7));
        let over = at(Phase::Over(None));
        assert!(!over.live(1) && !over.busy());
    }
}
