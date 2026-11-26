-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: the Rust functions of the group do exactly what the functions of Model.lean
-- do: each returns on every group that is `Wf` (and for `found`, every count that fits), with the
-- answer and the group the model gives.
--
-- Why it is needed: it is the one place where a loop or a `Vec` of the Rust is read; the files
-- after it speak of the model only.
--
-- Read before this file: Model.lean.
--
-- Notation: as in Model.lean; `step` goes through one line of a Rust function.
import GroupCore.Model
open Aeneas Aeneas.Std Result velarx_group_core
namespace GroupCore

/-- The flag of a search under way is the same in the record. -/
@[simp] theorem abs_searching (g : Group) : g.abs.searching = g.searching := rfl

/-- The record keeps the number of items passed on. -/
@[simp] theorem abs_passed (g : Group) : g.abs.passed = g.passed.val := rfl

/-- The record keeps the number of items of the group. -/
@[simp] theorem abs_items (g : Group) : g.abs.items = g.items.val := rfl

/-- The queue of the record is empty exactly when the `Vec` is. -/
theorem abs_next_nil (g : Group) : g.abs.next = [] ↔ g.next.length = 0 := by
  simp [Group.abs, alloc.vec.Vec.length]

/-- The requests under way of the record are none exactly when the `Vec` is empty. -/
theorem abs_under_way_nil (g : Group) : g.abs.underWay = [] ↔ g.under_way.length = 0 := by
  simp [Group.abs, alloc.vec.Vec.length]

/-- The peers with no room of the record are none exactly when the `Vec` is empty. -/
theorem abs_busy_nil (g : Group) : g.abs.busy = [] ↔ g.busy.length = 0 := by
  simp [Group.abs, alloc.vec.Vec.length]

/-- `may_search` returns, and says whether another peer may be found. -/
@[step]
theorem may_search_spec (g : Group) : Group.may_search g ⦃ r => r = g.abs.mayFind ⦄ := by
  unfold Group.may_search
  split <;> simp_all [AG.mayFind, Group.abs]

/-- `should_search` returns, and says whether to start a search: nobody queued, no search, room. -/
@[step]
theorem should_search_spec (g : Group) :
    Group.should_search g ⦃ r => r = decide (g.abs.next = [] ∧ g.abs.searching = false ∧
      g.abs.mayFind = true) ⦄ := by
  unfold Group.should_search
  step*
  all_goals simp_all [abs_next_nil, AG.mayFind]

/-- `ask_first` returns, when the queue is not empty, and does what `askFirstA` does. -/
@[step]
theorem ask_first_spec (g : Group) (nonempty : g.next.val ≠ []) (wf : Wf g) :
    Group.ask_first g ⦃ r => (r.1.act, r.2.abs) = askFirstA g.abs ⦄ := by
  unfold Group.ask_first
  have more : 0 < g.next.length := by
    simpa [alloc.vec.Vec.length] using List.length_pos_iff.mpr nonempty
  step as ⟨ taken, rest, taken_post ⟩
  step as ⟨ pushed, pushed_post ⟩
  · unfold Wf at wf; scalar_tac
  · simp only [askFirstA, Group.abs, Do.act, pushed_post, taken_post]
    simp

/-- `requeue` returns, and does what `requeueA` does. -/
@[step]
theorem requeue_spec (g : Group) :
    Group.requeue g ⦃ r => r.abs = requeueA g.abs ∧ r.under_way = g.under_way ⦄ := by
  unfold Group.requeue
  step*
  all_goals simp_all [requeueA, Group.abs, alloc.vec.Vec.length, alloc.vec.Vec.new]

/-- When nothing is passed on in full, nothing is under way and no search is to start, `go` asks the
first of the queue once the peers with no room are back, or waits, or ends. -/
theorem go_requeued (a : AG) (items : a.passed ≠ a.items) (idle : a.underWay = [])
    (no_search : ¬(a.next = [] ∧ a.searching = false ∧ a.mayFind = true)) :
    goA a = if (requeueA a).next ≠ [] then askFirstA (requeueA a)
      else if (requeueA a).searching then (.wait, requeueA a) else (.finish, requeueA a) := by
  simp [goA, items, idle, no_search]

/-- What `go` has learned when it gets past its first three tests. -/
theorem go_gets_past (g : Group) (b b1 : Bool) (incomplete : ¬g.passed = g.items)
    (b_post : (b = true) = (g.under_way.length = 0)) (idle : b = true)
    (b1_post : b1 = decide (g.abs.next = [] ∧ g.abs.searching = false ∧ g.abs.mayFind = true))
    (no_search : ¬b1 = true) :
    goA g.abs = if (requeueA g.abs).next ≠ [] then askFirstA (requeueA g.abs)
      else if (requeueA g.abs).searching then (.wait, requeueA g.abs)
      else (.finish, requeueA g.abs) := by
  apply go_requeued
  · exact fun h => incomplete (UScalar.eq_of_val_eq h)
  · apply (abs_under_way_nil g).mpr
    rw [← b_post]; exact idle
  · intro hP; apply no_search; rw [b1_post]; exact decide_eq_true (by simpa using hP)

/-- `go` returns, and does what `goA` does. -/
@[step]
theorem go_spec (g : Group) :
    Group.go g ⦃ r => (r.1.act, r.2.abs) = goA g.abs ⦄ := by
  -- the lines of `go` in order: complete, requests under way, search, requeue, ask or wait or end
  unfold Group.go
  step*
  · simp_all [goA, Group.abs, Do.act]
  · simp_all [goA, Group.abs, Do.act, AG.mayFind]
  · rw [go_gets_past g b b1 ‹_› b_post ‹_› b1_post ‹_›, ← self1_post]
    have empty : self1.abs.next = [] := (abs_next_nil self1).mpr (by rw [← b2_post]; exact ‹b2 = true›)
    simp [empty, Do.act, ‹self1.searching = true›]
  · rw [go_gets_past g b b1 ‹_› b_post ‹_› b1_post ‹_›, ← self1_post]
    have empty : self1.abs.next = [] := (abs_next_nil self1).mpr (by rw [← b2_post]; exact ‹b2 = true›)
    simp [empty, Do.act, ‹¬self1.searching = true›]
  · unfold Wf
    rw [self1_post1]
    have : self1.next.length ≤ Std.Usize.max := self1.next.property
    have uw : g.under_way.length = 0 := by rw [← b_post]; exact ‹b = true›
    omega
  · rw [go_gets_past g b b1 ‹_› b_post ‹_› b1_post ‹_›, ← self1_post]
    have full : self1.abs.next ≠ [] := fun h =>
      ‹¬b2 = true› (by rw [b2_post]; exact (abs_next_nil self1).mp h)
    simp [full, r_post]
  · simp_all [goA, Group.abs, Do.act]

/-- Dropping a peer from a list of peers is dropping its number from the list of numbers. -/
theorem map_val_filter (l : List Std.Usize) (p : Std.Usize) :
    (l.filter (fun x => decide (x ≠ p))).map (·.val) =
      (l.map (·.val)).filter (fun x => decide (x ≠ p.val)) := by
  induction l with
  | nil => simp
  | cons a t ih =>
    have key : decide (a ≠ p) = decide (a.val ≠ p.val) := by
      by_cases same : a = p
      · simp [same]
      · have : ¬ a.val = p.val := fun h => same (UScalar.eq_of_val_eq h)
        simp [same, this]
    simp only [List.filter_cons, List.map_cons, key]
    split <;> simp only [List.map_cons, ih]

/-- A peer is in a list of peers exactly when its number is in the list of the numbers. -/
theorem mem_map_val (l : List Std.Usize) (p : Std.Usize) : p.val ∈ l.map (·.val) ↔ p ∈ l := by
  simp only [List.mem_map]
  constructor
  · rintro ⟨x, hx, h⟩
    rw [UScalar.eq_of_val_eq h] at hx; exact hx
  · intro h; exact ⟨p, h, rfl⟩

/-- `chunk` returns, and does what `chunkA` does. -/
@[step]
theorem chunk_spec (g : Group) (passed : Std.Usize) :
    Group.chunk g passed ⦃ r => (r.1.act, r.2.abs) = chunkA g.abs passed.val ⦄ := by
  unfold Group.chunk
  step as ⟨ r, hr ⟩
  simpa [chunkA, chunkIn, Group.abs] using hr

/-- `ended` returns, when there is room for one more peer with no room, and does what `endedA`
does. -/
@[step]
theorem ended_spec (g : Group) (peer : Std.Usize) (no_room : Bool) (passed : Std.Usize)
    (room : g.busy.length < Std.Usize.max) :
    Group.ended g peer no_room passed ⦃ r =>
      (r.1.act, r.2.abs) = endedA g.abs peer.val no_room passed.val ⦄ := by
  unfold Group.ended
  have room' : g.busy.val.length < Std.Usize.max := room
  step as ⟨ kept, kept_post ⟩
  have filtered : (kept.val.map (·.val)) =
      g.abs.underWay.filter (fun x => decide (x ≠ peer.val)) := by
    rw [kept_post]
    simpa [Group.abs, alloc.vec.Vec.deref] using map_val_filter g.under_way.val peer
  -- a request ended without "no room": only the request leaves
  cases no_room
  · simp only [Bool.false_eq_true, ite_false, Std.bind_ok]
    step as ⟨ r, hr ⟩
    rw [hr, endedA, endedIn]
    simp [Group.abs, filtered]
  -- "no room": the peer is kept at the end of the list of those, and the counter is set
  · simp only [ite_true]
    step as ⟨ pushed, pushed_post ⟩
    step as ⟨ r, hr ⟩
    rw [hr, endedA, endedIn]
    simp [Group.abs, filtered, pushed_post]

/-- `found` returns, when the new peers fit, and does what `foundA` does. -/
@[step]
theorem found_spec (g : Group) (n : Std.Usize) (fits : g.found.val + n.val ≤ Std.Usize.max)
    (room : g.under_way.length + g.next.length + n.val ≤ Std.Usize.max) :
    Group.impl.found g n ⦃ r => (r.1.act, r.2.abs) = foundA g.abs n.val ⦄ := by
  unfold Group.impl.found
  obtain ⟨b, hb, hb'⟩ : ∃ b : Bool, (if n = 0#usize then ok true else ok g.exhausted : Result Bool) = ok b ∧
      b = (decide (n.val = 0) || g.exhausted) := by
    by_cases z : n = 0#usize
    · refine ⟨true, by simp [z], ?_⟩
      have : n.val = 0 := by rw [z]; rfl
      simp [this]
    · refine ⟨g.exhausted, by simp [z], ?_⟩
      have : ¬ n.val = 0 := fun h => z (UScalar.eq_of_val_eq (by simpa using h))
      simp [this]
  -- the new count of the exhausted flag, then the loop that queues the new peers
  rw [hb]
  simp only [Std.bind_ok]
  step as ⟨ v, added, v_post, added_post ⟩
  step as ⟨ i, i_post ⟩
  step as ⟨ idle, idle_post ⟩
  have next_is : v.val.map (·.val) = g.abs.next ++ List.range' g.abs.found n.val := by
    simp [v_post, Group.abs, added_post]
  by_cases idle_yes : idle = true
  · simp only [idle_yes, ite_true]
    step as ⟨ r, hr ⟩
    have no_requests : g.under_way.val = [] := by
      have : g.under_way.length = 0 := by rw [← idle_post]; exact idle_yes
      simpa [alloc.vec.Vec.length] using this
    rw [hr, foundA, foundIn]
    simp [Group.abs, i_post, hb', no_requests, v_post, added_post]
  · have idle_no : idle = false := by simpa using idle_yes
    simp only [idle_no, Bool.false_eq_true, ite_false]
    step as ⟨ empty, empty_post ⟩
    by_cases empty_yes : empty = true
    · simp only [empty_yes, ite_true]
      step as ⟨ r, hr ⟩
      have nothing : v.val = [] := by
        have : v.length = 0 := by rw [← empty_post]; exact empty_yes
        simpa [alloc.vec.Vec.length] using this
      rw [hr, foundA, foundIn]
      have none_added : added = [] := by
        have := v_post; rw [nothing] at this; exact (List.append_eq_nil_iff.mp this.symm).2
      have no_peers : n.val = 0 := by
        have := congrArg List.length added_post
        simpa [none_added] using this.symm
      have no_queue : g.next.val = [] := by
        have := v_post; rw [nothing] at this; exact (List.append_eq_nil_iff.mp this.symm).1
      simp [Group.abs, i_post, hb', nothing, no_peers, no_queue]
    · have empty_no : empty = false := by simpa using empty_yes
      simp only [empty_no, Bool.false_eq_true, ite_false]
      have queued : v.val ≠ [] := by
        intro h
        apply empty_yes
        rw [empty_post]; simp [alloc.vec.Vec.length, h]
      have added_length : added.length = n.val := by
        have := congrArg List.length added_post
        simpa using this
      have busy_now : g.under_way.val ≠ [] := by
        intro h
        apply idle_yes
        rw [idle_post]; simp [alloc.vec.Vec.length, h]
      step as ⟨ r, hr ⟩
      · simp only [Wf]
        simp [alloc.vec.Vec.length, v_post, added_length] at room ⊢
        omega
      · rw [hr, foundA, foundIn]
        have next_ne : g.abs.next ++ List.range' g.abs.found n.val ≠ [] := by
          rw [← next_is]; simpa using queued
        simp [Group.abs, i_post, hb', busy_now, v_post, added_post] at next_ne ⊢
        intro h1 h2
        exact absurd h2 (next_ne h1)

/-- `hedge_due` returns on a `Wf` group, and does what `hedgeDueA` does. -/
@[step]
theorem hedge_due_spec (g : Group) (wf : Wf g) :
    Group.hedge_due g ⦃ r => (r.1.act, r.2.abs) = hedgeDueA g.abs ⦄ := by
  unfold Group.hedge_due
  step*
  · simp_all [hedgeDueA, Group.abs, Do.act, AG.mayFind, alloc.vec.Vec.length]
  · simp_all [hedgeDueA, Group.abs, Do.act, AG.mayFind, alloc.vec.Vec.length]
  · simp_all [hedgeDueA, Group.abs, Do.act, alloc.vec.Vec.length]

/-- `hedge` returns, says "armed" exactly when `hedgeA` holds, and names the peer asked last and
how many requests are under way. -/
@[step]
theorem hedge_spec (g : Group) :
    Group.hedge g ⦃ r => (r ≠ none ↔ hedgeA g.abs) ∧
      ∀ x, r = some x → x.1.val = g.abs.last ∧ x.2.val = g.abs.underWay.length ⦄ := by
  unfold Group.hedge
  step*
  all_goals simp_all [hedgeA, Group.abs, AG.mayFind, alloc.vec.Vec.length]

end GroupCore
