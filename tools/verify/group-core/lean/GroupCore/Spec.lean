-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: what is proved of crates/group-core, the turns of a group fetch of the
-- peer-to-peer provider: the chunks of one layer asked of peers found by searches, until all are
-- passed on.  After each event of the loop around it (a chunk came, a request ended, a search
-- ended, the hedge timer fired) the core says what to do next: wait, search, ask a peer, or
-- finish.  This file is what a reviewer reads, in words and in statements, with no proof; Lean
-- checks the rest (the other files of GroupCore/; Theorems.lean ties each claim below to its
-- proof).
--
-- Why it is needed: the group is the one place where a fetch can ask the same peer twice, ask more
-- peers than allowed, stop with a peer unasked, or wait with nothing under way (a group that never
-- ends).  The tests of the crate (src/rules.rs, src/walk.rs) check the rules after every call, on
-- every order of events for three items and four peers (and, on demand, four and five); each claim
-- below is the same rule for EVERY number of items and peers.  A proof is worth what its statement
-- says, so each claim has a comment of what it claims and of what it does NOT.
--
-- Words.  The LOOP is what rules.rs calls `Shell`: it keeps what the loop around the core knows
-- (the requests under way, whether a search is, how many peers were found, how often each was
-- asked, and whether it said it had no room) and makes the calls the loop may make, each only when
-- it could make it (`Enabled`): a request ends only if it is under way, a search finds at most the
-- room left, a chunk comes only while a request is under way, the hedge timer fires only when
-- `hedge` says it is armed.  A STATE is reached (`Reach`) from the start by any such calls, in any
-- order, as far as the group is not finished.  The numbers `pre s ev` are what the loop knows once
-- it has the event and before the core answers.  A PEER is a number: the order the searches found
-- them in.  The ANSWER is `todo` (`Do.Wait`, `Do.Search`, `Do.Ask peer`, `Do.Finish`), and `g` the
-- group the core is left in.
--
-- Total correctness: `EveryCallReturns` says the core returns (no panic, no overflow, no index
-- outside a list, no endless loop) at every call the loop may make; the other claims are about the
-- answer of a call that returns.
--
-- Read before this file: the header of crates/group-core/src/lib.rs, and rules.rs.
--
-- Index.  What each claim is about, what is trusted and what is not claimed, in one place.
--
--   Claimed (for every number of items and peers; "the answer" is of a call the loop may make):
--     AGroupStartsWithASearch              a new group asks for a search
--     EveryCallReturns                     no call of the loop makes the core panic
--     TheCoreAgreesWithTheLoop             what the core counts is what the loop counts
--     TheGroupTakesAtMostItsPeers          no more peers found than the group may take; only a
--                                          found peer was ever asked
--     AtMostOneSearch                      a search is asked for only when none is under way
--     ASearchNeedsRoom                     ... and only when a peer may still be found
--     ASearchBesideARequestIsAHedge        ... and beside a request only when the hedge timer fired
--     AnAskedPeerWasFound                  a peer asked was found
--     APeerHasOneRequest                   ... and has no request under way
--     ARequestBesideAnotherIsAHedge        a request beside another comes of a hedge
--     APeerIsAskedAgainOnlyAfterProgress   a peer asked again said "no room" and items came in
--                                          since
--     APeerIsAskedAtMostItemsPlusOneTimes  so it is asked at most items + 1 times
--     NoPeerIsAskedOnceAllIsPassed         nobody is asked while every item is passed on
--     AllItemsPassedEndTheGroup            the report that passes the last item ends the group
--     AGroupEndsOnlyWhenNobodyIsLeft       the group ends with items left only if nothing is under
--                                          way, no search is, no peer may be found, every peer
--                                          found was asked, and none that had no room may have some
--     TheGroupNeverWaitsWithNothingUnderWay  every answer but "finish" leaves a request or a search
--     AnArmedHedgeActs                     when the hedge timer fires, the core asks or searches
--
--   Trusted (not checked here):
--     Charon and Aeneas (the versions in ../../pins) and the models Aeneas has of the library; no
--     function of the standard library is written by hand; Lean itself.
--
--   Not claimed:
--     that a group ENDS: the claims say what the core does when it answers, never that it answers
--     enough (every group finishes, or finishes in a time) -- that depends on searches finding
--     peers and peers answering;
--     what the loop does with the answer: that a chunk is checked and put once, that an item is not
--     asked again once delivered (the core only knows HOW MANY items were passed on, not which),
--     that a peer that sends wrong bytes is marked failing and the item asked of another (the core
--     is told nothing of bytes: that is the shell, tested in the p2p crate);
--     time of any kind: when the hedge timer is armed (the core says that it may be: `hedge`) or
--     how long it runs, and the check that a group is slow;
--     that the counts the loop gives the core are true;
--     that the peer asked after a "no room" is the best (one counter, `passed_when_busy`, decides
--     for all peers whether items came in since their own answer: a peer may be asked again a
--     little later than it could; never sooner);
--     that the loop obeys `Enabled` (the p2p crate's simulator tests make the same calls);
--     that the loop settles a request still under way when the core says to finish (it says so as
--     soon as the last item is passed on, with the request that sent it perhaps not ended).
--
-- Notation: `f x = ok r` is "the Rust `f` returns on `x`, with no panic and no endless loop, and
-- its answer is `r`"; `↑x` is the number a machine integer is; `s.pre ev` is the state after the
-- event and before the answer; `∀`, `∃`, `∧`, `∨`, `→` are "for all", "there is", "and", "or", "if
-- ... then".
import Extracted.Funs
open Aeneas Aeneas.Std Result velarx_group_core
namespace GroupCore

/-- What the loop may report to the core (rules.rs `Event`): the number of items passed on is the
total after the event. -/
inductive Event where
  /-- A chunk was taken, `passed` items are passed on now. -/
  | chunk (passed : Std.Usize)
  /-- The request of `peer` ended; whether it had no room; `passed` items are passed on now. -/
  | ended (peer : Std.Usize) (noRoom : Bool) (passed : Std.Usize)
  /-- The search found `n` peers. -/
  | found (n : Std.Usize)
  /-- The hedge timer fired. -/
  | hedgeDue

/-- What the loop knows (rules.rs `Shell`), and the core's group `group`. -/
structure Loop where
  /-- The group of the core. -/
  group : Group
  /-- The items of the group, and the peers it may take. -/
  items : Nat
  max : Nat
  /-- The requests under way, whether a search is, and whether it was started by the hedge timer. -/
  running : List Nat
  searching : Bool
  hedged : Bool
  /-- The last search found nobody. -/
  exhausted : Bool
  /-- The items passed on, and the peers found. -/
  passed : Nat
  found : Nat
  /-- For each peer: how often it was asked, whether its last request ended with no room, and how
  many items were passed on when it did. -/
  asked : Nat → Nat
  noRoom : Nat → Bool
  noRoomAt : Nat → Nat
  /-- How many items were passed on at the last answer of no room of any peer. -/
  noRoomAny : Nat
  /-- The core said to finish. -/
  finished : Bool

/-- The loop as it starts a group of the core: nobody found, a search under way. -/
def Loop.start (g : Group) : Loop where
  group := g
  items := g.items.val
  max := g.max.val
  running := []
  searching := true
  hedged := false
  exhausted := false
  passed := g.passed.val
  found := 0
  asked := fun _ => 0
  noRoom := fun _ => false
  noRoomAt := fun _ => 0
  noRoomAny := 0
  finished := false

/-- How many more peers a search may find, as the loop sees it. -/
def Loop.room (s : Loop) : Nat := if s.exhausted then 0 else s.max - s.found

/-- The call the loop makes may be made now (rules.rs: "each only when the loop could make it"). -/
def Loop.Enabled (s : Loop) : Event → Prop
  | .chunk p => s.running ≠ [] ∧ s.passed ≤ p.val ∧ p.val ≤ s.items
  | .ended q _ p => q.val ∈ s.running ∧ s.passed ≤ p.val ∧ p.val ≤ s.items
  | .found n => s.searching = true ∧ n.val ≤ s.room
  | .hedgeDue => ∃ x, Group.hedge s.group = ok (some x)

/-- What the loop knows once it has the event and before the core answers. -/
def Loop.pre (s : Loop) : Event → Loop
  | .chunk p => { s with passed := p.val }
  | .ended q nr p =>
    { s with
      passed := p.val
      running := s.running.filter (fun x => decide (x ≠ q.val))
      noRoom := Function.update s.noRoom q.val nr
      noRoomAt := if nr then Function.update s.noRoomAt q.val p.val else s.noRoomAt
      noRoomAny := if nr then p.val else s.noRoomAny }
  | .found n => { s with searching := false, exhausted := decide (n.val = 0), found := s.found + n.val }
  | .hedgeDue => s

/-- The call of the core that the event is. -/
def Loop.call (s : Loop) : Event → Result (Do × Group)
  | .chunk p => Group.chunk s.group p
  | .ended q nr p => Group.ended s.group q nr p
  | .found n => Group.impl.found s.group n
  | .hedgeDue => Group.hedge_due s.group

/-- What the loop knows after the core answered `todo` and is left in the group `g`: a search is
under way after "search" (started by the hedge timer if that was the event), the peer is under way
and asked once more after "ask", the group is finished after "finish". -/
def Loop.after (s : Loop) (ev : Event) (todo : Do) (g : Group) : Loop :=
  let p := { s.pre ev with group := g }
  match todo with
  | .Wait => p
  | .Search => { p with searching := true, hedged := (match ev with | .hedgeDue => true | _ => false) }
  | .Ask q => { p with asked := Function.update p.asked q.val (p.asked q.val + 1),
                       running := p.running ++ [q.val] }
  | .Finish => { p with finished := true }

/-- The states a group can be in: the start, and the state after any call the loop may make in a
state that is not finished, whatever the core answers. -/
inductive Reach : Loop → Prop
  | start (items passed max : Std.Usize) (g : Group) (below : passed.val < items.val)
      (new : Group.new items passed max = ok (g, Do.Search)) : Reach (Loop.start g)
  | step (s : Loop) (ev : Event) (todo : Do) (g : Group) : Reach s → s.finished = false →
      s.Enabled ev → s.call ev = ok (todo, g) → Reach (s.after ev todo g)

/-- The loop is in `s`, makes the call `ev`, and the core answers `todo` and is left in `g`. -/
def Answers (s : Loop) (ev : Event) (todo : Do) (g : Group) : Prop :=
  Reach s ∧ s.finished = false ∧ s.Enabled ev ∧ s.call ev = ok (todo, g)

/-- A new group asks for a search, and starts with no peer queued and no request under way.

Not said: anything of `passed` and `items` beyond that the group is told them. -/
def AGroupStartsWithASearch : Prop :=
  ∀ items passed max : Std.Usize, ∃ g, Group.new items passed max = ok (g, Do.Search) ∧
    g.searching = true ∧ g.next.val = [] ∧ g.under_way.val = []

/-- Whatever the loop reports, in whatever order, as long as it is a call it may make, the core
returns: no panic, no overflow, no index outside a list, no endless loop.

Not said: that what it answers is right (the claims below), or anything of a call the loop may not
make. -/
def EveryCallReturns : Prop :=
  ∀ (s : Loop) (ev : Event), Reach s → s.finished = false → s.Enabled ev → ∃ r, s.call ev = ok r

/-- What the core counts is what the loop counts: the items, the peers it may take and found, the
items passed on, the requests under way, whether a search is and whether the last found nobody.

Not said: that these numbers are the truth about the world; the loop tells the core. -/
def TheCoreAgreesWithTheLoop : Prop :=
  ∀ s : Loop, Reach s → s.finished = false →
    s.group.items.val = s.items ∧ s.group.max.val = s.max ∧ s.group.passed.val = s.passed ∧
    s.group.found.val = s.found ∧ s.group.exhausted = s.exhausted ∧
    s.group.searching = s.searching ∧ s.group.under_way.val.map (·.val) = s.running

/-- No more peers are found than the group may take, and a peer that was never found was never
asked.

Not said: that a search finds peers that exist. -/
def TheGroupTakesAtMostItsPeers : Prop :=
  ∀ s : Loop, Reach s → s.finished = false → s.found ≤ s.max ∧ ∀ q, s.found ≤ q → s.asked q = 0

/-- The core asks for a search only when none is under way (`Do.Search`).

Not said: that a search is asked for when it should be. -/
def AtMostOneSearch : Prop :=
  ∀ s ev todo g, Answers s ev todo g → todo = Do.Search → (s.pre ev).searching = false

/-- The core asks for a search only when a peer may still be found: the last search did not find
nobody, and fewer than the peers the group may take were found. -/
def ASearchNeedsRoom : Prop :=
  ∀ s ev todo g, Answers s ev todo g → todo = Do.Search → 0 < (s.pre ev).room

/-- A search asked for while a request is under way comes of the hedge timer (the core's way of
asking one more peer beside a slow one), never of another event.

Not said: when the hedge timer fires. -/
def ASearchBesideARequestIsAHedge : Prop :=
  ∀ s ev todo g, Answers s ev todo g → todo = Do.Search → (s.pre ev).running ≠ [] → ev = .hedgeDue

/-- A peer the core asks has been found (it is a number below the found). -/
def AnAskedPeerWasFound : Prop :=
  ∀ s ev todo g q, Answers s ev todo g → todo = Do.Ask q → q.val < (s.pre ev).found

/-- A peer the core asks has no request under way: a peer has at most one request. -/
def APeerHasOneRequest : Prop :=
  ∀ s ev todo g q, Answers s ev todo g → todo = Do.Ask q → q.val ∉ (s.pre ev).running

/-- A request asked while another is under way comes of the hedge timer, or of the end of a search
that the hedge timer started; never of a chunk or of the end of a request. -/
def ARequestBesideAnotherIsAHedge : Prop :=
  ∀ s ev todo g q, Answers s ev todo g → todo = Do.Ask q → (s.pre ev).running ≠ [] →
    ev = .hedgeDue ∨ ((∃ n, ev = .found n) ∧ (s.pre ev).hedged = true)

/-- A peer asked before is asked again only if its last request ended with no room, and items were
passed on since it did.

Not said: that it is asked again as soon as it could be: the core keeps one counter for all peers
that had no room, the one of the last of them. -/
def APeerIsAskedAgainOnlyAfterProgress : Prop :=
  ∀ s ev todo g q, Answers s ev todo g → todo = Do.Ask q → 0 < (s.pre ev).asked q.val →
    (s.pre ev).noRoom q.val = true ∧ (s.pre ev).noRoomAt q.val < (s.pre ev).passed

/-- No peer is asked more than items + 1 times (each time after the first needs one more item passed
on: so the loop is not endless). -/
def APeerIsAskedAtMostItemsPlusOneTimes : Prop :=
  ∀ s ev todo g q, Answers s ev todo g → todo = Do.Ask q →
    (s.pre ev).asked q.val + 1 ≤ (s.pre ev).items + 1

/-- Nobody is asked while every item is passed on. -/
def NoPeerIsAskedOnceAllIsPassed : Prop :=
  ∀ s ev todo g q, Answers s ev todo g → todo = Do.Ask q → (s.pre ev).passed < (s.pre ev).items

/-- The chunk or the end of a request that makes the number of items passed on the number of items
of the group is answered "finish".

Not said: that the items are all there (the loop counts them). -/
def AllItemsPassedEndTheGroup : Prop :=
  ∀ s ev todo g, Answers s ev todo g → (∃ p, ev = .chunk p) ∨ (∃ q nr p, ev = .ended q nr p) →
    (s.pre ev).passed = (s.pre ev).items → todo = Do.Finish

/-- The core says to finish with items left only if nothing is under way, no search is, no peer may
be found any more, every peer found was asked, and no peer that had no room may have some now (no
item was passed on since the last that said so).

Not said: that the group ends: that is the loop's, when the core says so. -/
def AGroupEndsOnlyWhenNobodyIsLeft : Prop :=
  ∀ s ev todo g, Answers s ev todo g → todo = Do.Finish →
    (s.pre ev).passed = (s.pre ev).items ∨
    ((s.pre ev).running = [] ∧ (s.pre ev).searching = false ∧ (s.pre ev).room = 0 ∧
      ∀ q, q < (s.pre ev).found → 0 < (s.pre ev).asked q ∧
        ((s.pre ev).noRoom q = false ∨ (s.pre ev).passed ≤ (s.pre ev).noRoomAny))

/-- Every answer but "finish" leaves a request under way or a search: the group does not wait for
nothing.

Not said: that a request or a search ends. -/
def TheGroupNeverWaitsWithNothingUnderWay : Prop :=
  ∀ s ev todo g, Answers s ev todo g → todo ≠ Do.Finish →
    (s.after ev todo g).running ≠ [] ∨ (s.after ev todo g).searching = true

/-- When the hedge timer fires (the core said it was armed), the core asks one more peer or starts a
search: it does not wait or finish. -/
def AnArmedHedgeActs : Prop :=
  ∀ s todo g, Answers s .hedgeDue todo g → todo = Do.Search ∨ ∃ q, todo = Do.Ask q

end GroupCore
