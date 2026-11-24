// SPDX-License-Identifier: Apache-2.0
//! The rules of the turns of a group, checked after every call of the core:
//! what each answer may be for the state the group was in.
//!
//! [`Shell`] stands for the loop around the core: it keeps what the loop
//! knows without the core (which requests are under way, whether a search
//! is, how many peers were found, how often each was asked, and what the
//! last answer was a consequence of) and makes the calls the loop may make,
//! each only when the loop could make it: a request ends only if it is under
//! way, a search finds at most the room left, a chunk comes only while a
//! request is under way, and the hedge timer fires only when `hedge()` says
//! it is armed.

use super::*;

/// What the loop does to the core.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    /// A chunk was taken: this many more items (none for a wrong chunk or
    /// one an item had already) are passed on.
    Chunk(usize),
    /// The request of the peer ended; whether the peer had no room, and how
    /// many items were passed on meanwhile.
    Ended(Peer, bool, usize),
    /// The search found this many peers.
    Found(usize),
    /// The hedge timer fired.
    HedgeDue,
}

#[derive(Debug, Clone)]
pub struct Shell {
    pub group: Group,
    /// The items of the group, and the peers it may take.
    pub items: usize,
    max: usize,
    /// What the loop sees of the group: the requests under way, the search,
    /// the items passed on, the peers found.
    running: Vec<Peer>,
    searching: bool,
    /// The search under way was started by the hedge timer.
    hedged: bool,
    exhausted: bool,
    pub passed: usize,
    pub found: usize,
    /// For each peer: how often it was asked, and whether its last request
    /// ended with no room.
    asked: Vec<usize>,
    no_room: Vec<bool>,
    /// How many items were passed on at the last answer of no room, of each
    /// peer and of any (the core keeps one counter, which is the second).
    passed_when_no_room_of: Vec<usize>,
    passed_when_no_room: usize,
    pub finished: bool,
    log: Vec<String>,
}

impl Shell {
    /// The group as the loop starts it.
    pub fn new(items: usize, passed: usize, max: usize) -> Shell {
        let (group, todo) = Group::new(items, passed, max);
        let mut shell = Shell {
            group,
            items,
            max,
            running: Vec::new(),
            searching: false,
            hedged: false,
            exhausted: false,
            passed,
            found: 0,
            asked: vec![0; max],
            no_room: vec![false; max],
            passed_when_no_room_of: vec![0; max],
            passed_when_no_room: 0,
            finished: false,
            log: vec![format!("new: {todo:?}")],
        };
        shell.must(todo == Do::Search, "a group starts with a search");
        shell.searching = true;
        shell
    }

    pub fn key(&self) -> String {
        format!(
            "{:?}{:?}{}{}{}{}{}{:?}{:?}{:?}{}",
            self.group,
            self.running,
            self.searching,
            self.hedged,
            self.exhausted,
            self.passed,
            self.found,
            self.asked,
            self.no_room,
            self.passed_when_no_room_of,
            self.passed_when_no_room
        )
    }

    pub fn running(&self) -> &[Peer] {
        &self.running
    }

    pub fn searching(&self) -> bool {
        self.searching
    }

    fn must(&self, ok: bool, rule: &str) {
        assert!(ok, "{rule}\n{}", self.log.join("\n"));
    }

    /// Whether a search may find another peer, as the loop sees it.
    pub fn room(&self) -> usize {
        if self.exhausted {
            0
        } else {
            self.max - self.found
        }
    }

    /// Make the call, and check the rules of its answer.
    pub fn tell(&mut self, event: Event) {
        self.log.push(format!("{event:?}"));
        let todo = match event {
            Event::Chunk(grew) => {
                self.passed += grew;
                self.group.chunk(self.passed)
            }
            Event::Ended(peer, no_room, grew) => {
                self.must(self.running.contains(&peer), "a request ends once");
                self.running.retain(|p| *p != peer);
                self.passed += grew;
                self.no_room[peer] = no_room;
                if no_room {
                    self.passed_when_no_room_of[peer] = self.passed;
                    self.passed_when_no_room = self.passed;
                }
                self.group.ended(peer, no_room, self.passed)
            }
            Event::Found(n) => {
                self.must(self.searching, "a search finds only while it is under way");
                self.searching = false;
                self.exhausted = n == 0;
                self.found += n;
                self.group.found(n)
            }
            Event::HedgeDue => {
                self.must(
                    self.group.hedge().is_some(),
                    "the timer fires only if armed",
                );
                self.group.hedge_due()
            }
        };
        self.log.push(format!("  -> {todo:?}"));
        let by_hedge = match event {
            Event::HedgeDue => true,
            Event::Found(_) => self.hedged,
            _ => false,
        };
        match todo {
            Do::Wait => {}
            Do::Search => {
                self.must(!self.searching, "at most one search is under way");
                self.must(self.room() > 0, "a search is asked for only with room left");
                self.must(
                    self.running.is_empty() || event == Event::HedgeDue,
                    "a search beside a request comes of a hedge",
                );
                self.searching = true;
                self.hedged = event == Event::HedgeDue;
            }
            Do::Ask(peer) => {
                self.must(peer < self.found, "only a peer that was found is asked");
                self.must(!self.running.contains(&peer), "a peer has one request");
                self.must(
                    self.running.is_empty() || by_hedge,
                    "a request beside one under way comes of a hedge",
                );
                if self.asked[peer] > 0 {
                    self.must(self.no_room[peer], "asked again, but not after no room");
                    self.must(
                        self.passed > self.passed_when_no_room_of[peer],
                        "asked again, but no item came in since its no room",
                    );
                }
                self.asked[peer] += 1;
                self.must(
                    self.asked[peer] <= self.items + 1,
                    "a peer is asked for ever",
                );
                self.running.push(peer);
            }
            Do::Finish => {
                self.finished = true;
                self.check_finish();
            }
        }
        if !self.finished {
            self.must(
                !self.running.is_empty() || self.searching,
                "the group waits with nothing under way",
            );
        }
        self.must(
            self.group.under_way() == self.running,
            "the core's requests",
        );
    }

    /// The group may end only if everything is passed on, or nothing is
    /// under way and nobody is left: no peer found and not asked, no peer
    /// that had no room and may have some now, no room for a search.
    fn check_finish(&self) {
        if self.passed == self.items {
            return;
        }
        self.must(
            self.running.is_empty() && !self.searching,
            "finished with something under way",
        );
        self.must(self.room() == 0, "finished with a search possible");
        for peer in 0..self.found {
            self.must(self.asked[peer] > 0, "finished with a peer not asked");
            self.must(
                !self.no_room[peer] || self.passed <= self.passed_when_no_room,
                "finished with a peer that may have room",
            );
        }
    }
}
