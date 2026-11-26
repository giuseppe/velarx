-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: what is true of every state a group can reach (`Inv`), and that the start
-- satisfies it.
--
-- Why it is needed: each rule of rules.rs holds because of what the state already is: a peer is
-- asked again only if it said "no room" and items came in since, because the only way back to the
-- queue is through the list of the peers that said so; the group ends with nobody left because
-- every peer found is in the queue, under way, in that list or finished.  `Inv` writes these facts
-- down.
--
-- Read before this file: Machine.lean.
import GroupCore.Machine
namespace GroupCore

/-- What holds in every reachable state (the numbers are those of rules.rs `Shell`; `s.g` is what
the core holds). -/
structure Inv (s : AS) : Prop where
  -- the core and the loop agree
  items_eq : s.g.items = s.items
  max_eq : s.g.max = s.max
  passed_eq : s.g.passed = s.passed
  found_eq : s.g.found = s.found
  exhausted_eq : s.g.exhausted = s.exhausted
  searching_eq : s.g.searching = s.searching
  running_eq : s.g.underWay = s.running
  -- the counts
  passed_le : s.passed ≤ s.items
  found_le : s.found ≤ s.max
  -- the peers: each is in one place, once, and was found
  next_nodup : s.g.next.Nodup
  running_nodup : s.running.Nodup
  busy_nodup : s.g.busy.Nodup
  next_running : ∀ p ∈ s.g.next, p ∉ s.running
  next_busy : ∀ p ∈ s.g.next, p ∉ s.g.busy
  running_busy : ∀ p ∈ s.running, p ∉ s.g.busy
  next_below : ∀ p ∈ s.g.next, p < s.found
  running_below : ∀ p ∈ s.running, p < s.found
  busy_below : ∀ p ∈ s.g.busy, p < s.found
  -- a peer never asked is queued, and nobody beyond the found was asked
  unasked : ∀ p, p < s.found → s.asked p = 0 → p ∈ s.g.next
  beyond : ∀ p, s.found ≤ p → s.asked p = 0
  -- a request under way was asked, and not more often than items came in, plus one
  running_asked : ∀ p ∈ s.running, 0 < s.asked p ∧ s.asked p ≤ 1 + s.passed
  -- a peer queued again said "no room", and items came in since
  next_again : ∀ p ∈ s.g.next, 0 < s.asked p →
    s.noRoom p = true ∧ s.noRoomAt p < s.passed ∧ s.asked p ≤ 1 + s.noRoomAt p
  -- a peer in the list of those that said "no room"
  busy_facts : ∀ p ∈ s.g.busy, 0 < s.asked p ∧ s.noRoom p = true ∧
    s.noRoomAt p ≤ s.noRoomAny ∧ s.asked p ≤ 1 + s.noRoomAt p
  -- a peer whose last answer was "no room", and that is not queued or under way, is in that list
  lost : ∀ p, p < s.found → 0 < s.asked p → p ∉ s.g.next → p ∉ s.running →
    s.noRoom p = true → p ∈ s.g.busy
  -- the one counter of the core
  pwb_eq : s.g.passedWhenBusy = s.noRoomAny
  any_le : s.noRoomAny ≤ s.passed
  -- a search under way: nobody is queued, nothing is left to be found by it, and a request
  -- beside it is the hedge's
  search_next : s.searching = true → s.g.next = []
  search_ex : s.searching = true → s.exhausted = false
  search_hedge : s.searching = true → s.running ≠ [] → s.hedged = true

/-- A group starts in a state that satisfies `Inv`. -/
theorem start_inv (items passed max : Nat) (below : passed < items) :
    Inv (AS.start items passed max) := by
  constructor <;> simp [AS.start]
  omega

/-- A chunk keeps `Inv`: only the number of items passed on grows. -/
theorem chunk_inv (s : AS) (hi : Inv s) (p : Nat) (en : EnabledA s (.chunk p)) :
    Inv (s.pre (.chunk p)) := by
  obtain ⟨_, le, le'⟩ := en
  obtain ⟨h1, h2, h3, h4, h5, h6, h7, h8, h9, h10, h11, h12, h13, h14, h15, h16, h17, h18, h19, h20,
    h21, h22, h23, h24, h25, h26, h27, h28, h29⟩ := hi
  constructor <;> simp only [AS.pre, chunkIn] <;> first | omega | grind

/-- The end of a request keeps `Inv`: the peer leaves the requests under way, and goes to the list
of those with no room if it said so. -/
theorem ended_inv (s : AS) (hi : Inv s) (q : Nat) (nr : Bool) (p : Nat)
    (en : EnabledA s (.ended q nr p)) : Inv (s.pre (.ended q nr p)) := by
  obtain ⟨inq, le, le'⟩ := en
  obtain ⟨h1, h2, h3, h4, h5, h6, h7, h8, h9, h10, h11, h12, h13, h14, h15, h16, h17, h18, h19, h20,
    h21, h22, h23, h24, h25, h26, h27, h28, h29⟩ := hi
  have qbusy : q ∉ s.g.busy := h15 q inq
  cases nr
  · constructor <;> simp only [AS.pre, endedIn] <;> first | omega | grind
  · constructor <;> simp only [AS.pre, endedIn] <;> first | omega | grind

/-- The end of a search keeps `Inv`: the peers it found are numbered after the others and queued. -/
theorem found_inv (s : AS) (hi : Inv s) (n : Nat) (en : EnabledA s (.found n)) :
    Inv (s.pre (.found n)) := by
  obtain ⟨searching, enough⟩ := en
  obtain ⟨h1, h2, h3, h4, h5, h6, h7, h8, h9, h10, h11, h12, h13, h14, h15, h16, h17, h18, h19, h20,
    h21, h22, h23, h24, h25, h26, h27, h28, h29⟩ := hi
  have none_left : s.exhausted = true → n = 0 := by
    intro e; simp [AS.room, e] at enough; omega
  have fits : s.found + n ≤ s.max := by
    unfold AS.room at enough; split at enough <;> omega
  constructor <;> simp only [AS.pre, foundIn] <;> first | omega | grind [List.nodup_append, List.nodup_range', List.mem_range']

/-- The hedge timer keeps `Inv`: nothing changes. -/
theorem hedge_due_inv (s : AS) (hi : Inv s) : Inv (s.pre .hedgeDue) := hi

/-- Whether the group is finished is no part of `Inv`. -/
theorem inv_finished {s : AS} (b : Bool) (h : Inv s) : Inv { s with finished := b } := by
  cases h; constructor <;> assumption

end GroupCore
