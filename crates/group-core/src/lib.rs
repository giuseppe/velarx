// SPDX-License-Identifier: Apache-2.0
//! The turns of a group fetch: the chunks of one layer asked of the peers
//! until they are all passed on.  The core knows how many items the group
//! has and how many were passed on, the peers by number (in the order the
//! search found them), and the requests under way; it answers, after every
//! event of the shell, what to do next ([`Do`]).  A peer has at most one
//! request, so a request is its peer.
//!
//! What stays in the shell: the search itself and whom it finds, the
//! requests, the check of the bytes and which item they are, the knowledge
//! about the peers, and all time (the hedge delay, the check that a group
//! is slow).  The core is told only how many items were passed on.
//!
//! Written to be translated (tools/verify): plain loops over `Vec`s with
//! indices, no iterator adapter where a result matters, no closure.

/// A peer of the group, numbered in the order the searches found them.
pub type Peer = usize;

/// What the shell does next.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Do {
    /// Nothing: an event will come.
    Wait,
    /// Start a search for more peers.
    Search,
    /// Send this peer a request for what is not passed on yet.
    Ask(Peer),
    /// The group is over: everything is passed on, or nobody is left.
    Finish,
}

/// The state of one group.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Group {
    /// The items of the group, and how many are passed on.
    items: usize,
    passed: usize,
    /// How many peers the group may take, and how many it has.
    max: usize,
    found: usize,
    /// A search found nobody.
    exhausted: bool,
    searching: bool,
    /// Found, or with room again, not asked yet; in the order to ask.
    next: Vec<Peer>,
    under_way: Vec<Peer>,
    /// The peers that had no room, and how many items were passed on when
    /// the last of them said so.
    busy: Vec<Peer>,
    passed_when_busy: usize,
    /// The peer asked last.
    last: Peer,
}

fn without(v: &[Peer], peer: Peer) -> Vec<Peer> {
    let mut rest = Vec::new();
    let mut i = 0;
    while i < v.len() {
        if v[i] != peer {
            rest.push(v[i]);
        }
        i += 1;
    }
    rest
}

/// The first of `v`, which has one, taken out.
fn take_first(v: &mut Vec<Peer>) -> Peer {
    let first = v[0];
    let mut rest = Vec::new();
    let mut i = 1;
    while i < v.len() {
        rest.push(v[i]);
        i += 1;
    }
    *v = rest;
    first
}

impl Group {
    /// A group of `items` items, `passed` of them passed on already (fewer
    /// than `items`), that may take `max` peers.  It starts with a search.
    pub fn new(items: usize, passed: usize, max: usize) -> (Group, Do) {
        let group = Group {
            items,
            passed,
            max,
            found: 0,
            exhausted: false,
            searching: true,
            next: Vec::new(),
            under_way: Vec::new(),
            busy: Vec::new(),
            passed_when_busy: 0,
            last: 0,
        };
        (group, Do::Search)
    }

    /// Whether a search may find another peer.
    fn may_search(&self) -> bool {
        !self.exhausted && self.found < self.max
    }

    /// Ask the first peer of the queue, which has one.
    fn ask_first(&mut self) -> Do {
        let peer = take_first(&mut self.next);
        self.under_way.push(peer);
        self.last = peer;
        Do::Ask(peer)
    }

    /// Whether to start a search: nobody is under way or queued, none is
    /// running, and another peer may be found.
    fn should_search(&self) -> bool {
        self.next.is_empty() && !self.searching && self.may_search()
    }

    /// Give the peers that had no room back to the queue, once items came
    /// in since the last of them said so.
    fn requeue(&mut self) {
        if self.next.is_empty()
            && !self.searching
            && !self.busy.is_empty()
            && self.passed > self.passed_when_busy
        {
            let mut i = 0;
            while i < self.busy.len() {
                self.next.push(self.busy[i]);
                i += 1;
            }
            self.busy = Vec::new();
        }
    }

    /// What to do after any event: end when everything is passed on; when
    /// no request is under way, search, or give the peers that had no room
    /// back to the queue once items came in since, and ask the first of the
    /// queue; end when there is none and no search is under way.
    fn go(&mut self) -> Do {
        if self.passed == self.items {
            Do::Finish
        } else if !self.under_way.is_empty() {
            Do::Wait
        } else if self.should_search() {
            self.searching = true;
            Do::Search
        } else {
            self.requeue();
            if !self.next.is_empty() {
                self.ask_first()
            } else if self.searching {
                Do::Wait
            } else {
                Do::Finish
            }
        }
    }

    /// A chunk was taken: `passed` items are passed on now.
    pub fn chunk(&mut self, passed: usize) -> Do {
        self.passed = passed;
        self.go()
    }

    /// The request of `peer` (which is under way) ended, with `passed` items
    /// passed on now; `no_room` when the peer had no room for it.
    pub fn ended(&mut self, peer: Peer, no_room: bool, passed: usize) -> Do {
        self.under_way = without(&self.under_way, peer);
        self.passed = passed;
        if no_room {
            self.busy.push(peer);
            self.passed_when_busy = passed;
        }
        self.go()
    }

    /// The search that was under way found `n` peers (at most the room left
    /// to take), numbered after the ones found before; none when no source
    /// has a peer left.  The peers a search started by [`Self::hedge_due`]
    /// finds are asked at once, beside the request under way.
    pub fn found(&mut self, n: usize) -> Do {
        self.searching = false;
        if n == 0 {
            self.exhausted = true;
        }
        let mut i = 0;
        while i < n {
            self.next.push(self.found + i);
            i += 1;
        }
        self.found += n;
        // (a request under way during a search means the hedge timer started
        // that search: what it finds is asked at once, beside the request)
        if !self.under_way.is_empty() && !self.next.is_empty() {
            self.ask_first()
        } else {
            self.go()
        }
    }

    /// The hedge timer fired (see [`Self::hedge`]): ask the next peer beside
    /// the one under way, or search for one.
    pub fn hedge_due(&mut self) -> Do {
        if !self.next.is_empty() {
            self.ask_first()
        } else if self.may_search() {
            self.searching = true;
            Do::Search
        } else {
            Do::Wait
        }
    }

    /// When the shell is to arm its hedge timer: the peer asked last and how
    /// many requests are under way, if one is, no search is, and a peer or
    /// a search is there to ask beside it.
    pub fn hedge(&self) -> Option<(Peer, usize)> {
        if !self.under_way.is_empty()
            && !self.searching
            && (!self.next.is_empty() || self.may_search())
        {
            Some((self.last, self.under_way.len()))
        } else {
            None
        }
    }

    /// The peers whose requests are under way.
    pub fn under_way(&self) -> &[Peer] {
        &self.under_way
    }
}

#[cfg(test)]
mod rules;

#[cfg(test)]
mod walk;

#[cfg(test)]
mod tests {
    use super::*;

    /// A group of three items with room for four peers, three found and the
    /// first of them asked.
    fn asked_one() -> Group {
        let (mut g, _) = Group::new(3, 0, 4);
        assert_eq!(g.found(3), Do::Ask(0));
        g
    }

    #[test]
    fn the_lists_are_taken_apart_in_order() {
        assert_eq!(without(&[3, 1, 3, 2], 3), [1, 2]);
        let mut v = vec![4, 5, 6];
        assert_eq!(take_first(&mut v), 4);
        assert_eq!(v, [5, 6]);
    }

    #[test]
    fn a_group_starts_with_a_search() {
        let (g, todo) = Group::new(3, 1, 4);
        assert_eq!(todo, Do::Search);
        assert!(g.searching && g.under_way().is_empty());
        assert_eq!(g.hedge(), None);
    }

    #[test]
    fn the_peers_found_are_asked_one_at_a_time_and_numbered_in_order() {
        let (mut g, _) = Group::new(3, 0, 4);
        assert_eq!(g.found(2), Do::Ask(0));
        assert_eq!(g.next, [1]);
        assert_eq!(g.chunk(1), Do::Wait);
        assert_eq!(g.under_way(), [0]);
        // the request ended and left items: the next peer is asked
        assert_eq!(g.ended(0, false, 2), Do::Ask(1));
        assert_eq!(g.under_way(), [1]);
    }

    #[test]
    fn a_group_ends_when_everything_is_passed_on() {
        let mut g = asked_one();
        assert_eq!(g.chunk(3), Do::Finish);
        let mut g = asked_one();
        assert_eq!(g.ended(0, false, 3), Do::Finish);
    }

    #[test]
    fn a_search_is_started_when_nobody_is_under_way_and_no_peer_is_queued() {
        let (mut g, _) = Group::new(3, 0, 4);
        assert_eq!(g.found(1), Do::Ask(0));
        assert_eq!(g.ended(0, false, 1), Do::Search);
        assert!(g.searching);
        // it asks nobody while the search is under way
        assert_eq!(g.chunk(2), Do::Wait);
    }

    #[test]
    fn no_search_is_started_when_the_peers_are_all_taken() {
        let (mut g, _) = Group::new(3, 0, 2);
        assert_eq!(g.found(2), Do::Ask(0));
        assert_eq!(g.ended(0, false, 0), Do::Ask(1));
        assert_eq!(g.ended(1, false, 0), Do::Finish);
    }

    #[test]
    fn a_search_that_finds_nobody_ends_the_group_when_nothing_is_under_way() {
        let (mut g, _) = Group::new(3, 0, 4);
        assert_eq!(g.found(0), Do::Finish);
        assert!(g.exhausted);
        // or when what was asked ended without the items
        let (mut g, _) = Group::new(3, 0, 4);
        assert_eq!(g.found(1), Do::Ask(0));
        assert_eq!(g.ended(0, false, 1), Do::Search);
        assert_eq!(g.found(0), Do::Finish);
    }

    #[test]
    fn a_search_that_ends_while_a_request_is_under_way_waits_for_it() {
        let mut g = asked_one();
        assert_eq!(g.hedge_due(), Do::Ask(1));
        assert_eq!(g.hedge_due(), Do::Ask(2));
        assert_eq!(g.hedge_due(), Do::Search);
        assert_eq!(g.found(0), Do::Wait);
        assert_eq!(g.hedge_due(), Do::Wait);
        assert_eq!(g.under_way(), [0, 1, 2]);
    }

    #[test]
    fn a_peer_with_no_room_is_asked_again_only_after_items_came_in() {
        let (mut g, _) = Group::new(3, 0, 4);
        assert_eq!(g.found(2), Do::Ask(0));
        assert_eq!(g.ended(0, true, 0), Do::Ask(1));
        // the other gave nothing: no progress, nobody left, a search
        assert_eq!(g.ended(1, false, 0), Do::Search);
        assert_eq!(g.found(0), Do::Finish);

        let (mut g, _) = Group::new(3, 0, 4);
        assert_eq!(g.found(2), Do::Ask(0));
        assert_eq!(g.ended(0, true, 0), Do::Ask(1));
        assert_eq!(g.ended(1, false, 1), Do::Search);
        assert_eq!(g.found(0), Do::Ask(0));
    }

    #[test]
    fn the_peers_with_no_room_come_back_in_the_order_they_said() {
        let (mut g, _) = Group::new(3, 0, 3);
        assert_eq!(g.found(2), Do::Ask(0));
        assert_eq!(g.ended(0, true, 0), Do::Ask(1));
        assert_eq!(g.ended(1, true, 1), Do::Search);
        assert_eq!(g.found(1), Do::Ask(2));
        // no peer is left to find: both come back, the first is asked
        assert_eq!(g.ended(2, false, 2), Do::Ask(0));
        assert_eq!(g.next, [1]);
        assert!(g.busy.is_empty());
    }

    #[test]
    fn a_peer_with_no_room_is_kept_once() {
        let (mut g, _) = Group::new(5, 0, 2);
        assert_eq!(g.found(1), Do::Ask(0));
        assert_eq!(g.ended(0, true, 0), Do::Search);
        assert_eq!(g.found(0), Do::Finish);
        assert_eq!(g.busy, [0]);
        let (mut g, _) = Group::new(5, 0, 2);
        assert_eq!(g.found(1), Do::Ask(0));
        assert_eq!(g.ended(0, true, 0), Do::Search);
        assert_eq!(g.found(1), Do::Ask(1));
        assert_eq!(g.ended(1, false, 1), Do::Ask(0));
        assert_eq!(g.ended(0, true, 1), Do::Finish);
        assert_eq!(g.busy, [0]);
        assert_eq!(g.passed_when_busy, 1);
    }

    #[test]
    fn the_hedge_is_armed_when_a_request_runs_and_a_peer_or_a_search_is_there() {
        let (mut g, _) = Group::new(3, 0, 2);
        assert_eq!(g.hedge(), None);
        g.found(1);
        // one peer asked, room for another: a search would find it
        assert_eq!(g.hedge(), Some((0, 1)));
        assert_eq!(g.hedge_due(), Do::Search);
        assert_eq!(g.hedge(), None, "not while a search is under way");
        assert_eq!(g.found(1), Do::Ask(1));
        assert_eq!(g.hedge(), None, "the room is taken");
        let (mut g, _) = Group::new(3, 0, 4);
        g.found(2);
        assert_eq!(g.hedge(), Some((0, 1)));
        assert_eq!(g.hedge_due(), Do::Ask(1));
        assert_eq!(g.hedge(), Some((1, 2)), "the one asked last, two under way");
    }

    #[test]
    fn the_hedge_is_not_armed_when_the_search_found_nobody() {
        let (mut g, _) = Group::new(3, 0, 4);
        g.found(1);
        assert_eq!(g.hedge_due(), Do::Search);
        assert_eq!(g.found(0), Do::Wait);
        assert_eq!(g.hedge(), None);
    }

    #[test]
    fn what_a_hedged_search_finds_is_asked_at_once_beside_the_request() {
        let (mut g, _) = Group::new(3, 0, 4);
        assert_eq!(g.found(1), Do::Ask(0));
        assert_eq!(g.hedge_due(), Do::Search);
        assert_eq!(g.found(2), Do::Ask(1));
        assert_eq!(g.under_way(), [0, 1]);
        assert_eq!(g.next, [2]);
    }

    #[test]
    fn what_a_search_finds_after_the_requests_ended_is_asked_at_once() {
        let (mut g, _) = Group::new(3, 0, 4);
        g.found(1);
        assert_eq!(g.hedge_due(), Do::Search);
        // the request ended while the search ran: nobody is asked until it
        // answers
        assert_eq!(g.ended(0, false, 1), Do::Wait);
        assert_eq!(g.found(1), Do::Ask(1));
    }

    #[test]
    fn a_search_after_a_hedge_is_started_again_by_the_turn() {
        let (mut g, _) = Group::new(3, 0, 4);
        g.found(1);
        assert_eq!(g.hedge_due(), Do::Search);
        assert_eq!(g.found(1), Do::Ask(1));
        assert_eq!(g.ended(0, false, 1), Do::Wait);
        assert_eq!(g.ended(1, false, 1), Do::Search);
    }
}
