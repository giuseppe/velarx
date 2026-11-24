-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: the small functions of crates/lazy-core that only look at the core and
-- answer, return: `pull_at`, `layer_at` and `group_at` (where the pull, the layer or the group of
-- a number is, if it is held), `lacking`, `wanting`, `goes`, `starting`, `in_flight`,
-- `slots_held`, `next_wake`, `backoff`, `has_all`, and the counts and searches of `advance`.
-- For each it says that it returns, and what the caller needs of its result (a place found is
-- inside the vector it was looked up in; the names `lacking` gives are no more than the pulls).
--
-- Why it is needed: nothing in the core is an index.  A pull, a layer or a group is found by its
-- number each time, and a number the core does not hold gives `none`, which the caller ignores.
-- So these lookups are where the claim "no panic on a number of the event" is decided: they return
-- on every number, and a place they give is inside the vector.  The loops over the pulls, the
-- layers and the groups go down a slice that does not change, one element each time.
--
-- Read before this file: Spec.lean, ReturnsBasics.lean, and in lib.rs the functions named above
-- (they are plain loops, so that a proof can follow them: see the header of lib.rs).
--
-- The tactics a reader meets in the proofs.  `step*` follows the Rust function line by line: for
-- each call it uses the lemma of this development that says when the call returns and what it
-- gives (the lemmas marked `@[step]`), and leaves what is to be shown (that a `Vec` has room, that
-- an index is inside) as goals.  `step as ⟨x, hx⟩` does one line and names the result `x` and what
-- is known of it `hx`.  `loop.spec_decr_nat` proves that a loop returns because a number goes down
-- at each turn (here, the elements left to read) while a fact (the invariant) is kept.
-- `bookkeeping` (ReturnsBasics.lean) closes the goals that are only sums of lengths.
--
-- Notation: `m ⦃ r => P r ⦄` is "the call `m` returns, and its result `r` satisfies `P r`";
-- `iter.i` is the place an iterator is at, `iter.slice.val` the list it goes over;
-- `usize_max_is` says that on a 64-bit machine the largest `usize` is `2^64 - 1`.
import LazyCore.ReturnsBasics

open Aeneas Aeneas.Std Result velarx_lazy_core

namespace LazyCore

/-- `Pull::lacks` returns. -/
@[step] theorem lacks_returns (p : Pull) (l : Std.U32) : Pull.lacks p l ⦃ _ => True ⦄ := by
  rw [lacks_iff]; exact (WP.spec_ok _).mpr trivial

/-- `Pull::working` returns. -/
@[step] theorem working_returns (p : Pull) : Pull.working p ⦃ _ => True ⦄ := by
  unfold Pull.working
  step*

/-- `Pull::wants` returns. -/
@[step] theorem wants_returns (p : Pull) (g : Group) : Pull.wants p g ⦃ _ => True ⦄ := by
  unfold Pull.wants
  obtain ⟨it, found⟩ := any_iff Pull.wants.closure.Insts.CoreOpsFunctionFnMutTupleShared0U32Bool
    (fun l => l ∈ p.layers.val) (alloc.vec.Vec.deref g.needed_by) p (fun x => by
      simp [Pull.wants.closure.Insts.CoreOpsFunctionFnMutTupleShared0U32Bool.call_mut, lacks_iff])
  simp only [core.slice.Slice.iter, found, bind_ok]
  exact (WP.spec_ok _).mpr trivial

/-- On a 64-bit machine the largest `usize` is `2^64 - 1`. -/
theorem usize_max_is (on64 : OnA64BitMachine) : Usize.max = 2 ^ 64 - 1 := by
  simp [Usize.max, Usize.numBits, on64]

/-- `pull_at` returns a place inside the vector, if it finds one. -/
@[step] theorem pull_at_returns (c : Core) (p : Std.U32) :
    Core.pull_at c p ⦃ o => ∀ n, o = some n → n.val < c.pulls.val.length ⦄ := by
  obtain ⟨o, it, found, result⟩ := position_pure
    Core.pull_at.closure.Insts.CoreOpsFunctionFnMutTupleShared0PullBool (fun q : Pull => q.id = p)
    c.pulls.deref p (fun _ => rfl)
  have deref : (c.pulls.deref).val = c.pulls.val := by simp [alloc.vec.Vec.deref]
  unfold Core.pull_at
  simp only [core.slice.Slice.iter, found, bind_ok]
  cases o with
  | none => exact (WP.spec_ok _).mpr fun n h => absurd h (by simp)
  | some n =>
    obtain ⟨hn, _, _⟩ := result
    exact (WP.spec_ok _).mpr fun m h => by cases h; simpa [deref] using hn

/-- `layer_at` returns a place inside the vector, if it finds one. -/
@[step] theorem layer_at_returns (c : Core) (l : Std.U32) :
    Core.layer_at c l ⦃ o => ∀ n, o = some n → n.val < c.layers.val.length ⦄ := by
  obtain ⟨o, it, found, result⟩ := position_pure
    Core.layer_at.closure.Insts.CoreOpsFunctionFnMutTupleShared0LayerBool
    (fun q : Layer => q.id = l) c.layers.deref l (fun _ => rfl)
  have deref : (c.layers.deref).val = c.layers.val := by simp [alloc.vec.Vec.deref]
  unfold Core.layer_at
  simp only [core.slice.Slice.iter, found, bind_ok]
  cases o with
  | none => exact (WP.spec_ok _).mpr fun n h => absurd h (by simp)
  | some n =>
    obtain ⟨hn, _, _⟩ := result
    exact (WP.spec_ok _).mpr fun m h => by cases h; simpa [deref] using hn

/-- `group_at` returns a place inside the vector, if it finds one. -/
@[step] theorem group_at_returns (c : Core) (g : Std.U32) :
    Core.group_at c g ⦃ o => ∀ n, o = some n → n.val < c.groups.val.length ⦄ := by
  obtain ⟨o, it, found, result⟩ := position_pure
    Core.group_at.closure.Insts.CoreOpsFunctionFnMutTupleShared0GroupBool
    (fun q : Group => q.id = g) c.groups.deref g (fun _ => rfl)
  have deref : (c.groups.deref).val = c.groups.val := by simp [alloc.vec.Vec.deref]
  unfold Core.group_at
  simp only [core.slice.Slice.iter, found, bind_ok]
  cases o with
  | none => exact (WP.spec_ok _).mpr fun n h => absurd h (by simp)
  | some n =>
    obtain ⟨hn, _, _⟩ := result
    exact (WP.spec_ok _).mpr fun m h => by cases h; simpa [deref] using hn

/-- The test of the closure of `lacking` returns. -/
theorem lacking_closure_answers :
    ∀ p y, ∃ b p', Core.lacking.closure.Insts.CoreOpsFunctionFnMutTupleShared0U32Bool.call_mut
      p y = ok (b, p') := by
  intro p y
  unfold Core.lacking.closure.Insts.CoreOpsFunctionFnMutTupleShared0U32Bool.call_mut
  simp [lacks_iff]

/-- The `any` of `lacking` over the layers returns. -/
@[step] theorem any_lacking_returns (it : core.slice.iter.Iter Std.U32) (x : Pull) :
    core.slice.iter.Iter.Insts.CoreIterTraitsIteratorIteratorSharedAT.any
      Core.lacking.closure.Insts.CoreOpsFunctionFnMutTupleShared0U32Bool it x ⦃ _ _ => True ⦄ := by
  obtain ⟨r, found⟩ := any_total
    Core.lacking.closure.Insts.CoreOpsFunctionFnMutTupleShared0U32Bool it x lacking_closure_answers
  rw [found]
  exact (WP.spec_ok _).mpr trivial

/-- `lacking`: the loop pushes the name of a pull at most for each pull. -/
@[step] theorem lacking_loop_returns (on64 : OnA64BitMachine) (iter : core.slice.iter.Iter Pull)
    (layers : Slice Std.U32) (lacking : alloc.vec.Vec Std.U32) (L : Nat)
    (i_le : iter.i ≤ iter.slice.val.length)
    (room : lacking.val.length + (iter.slice.val.length - iter.i) ≤ L) (small : L ≤ 2 ^ 40) :
    Core.lacking_loop iter layers lacking ⦃ r => r.val.length ≤ L ⦄ := by
  have max_is := usize_max_is on64
  unfold Core.lacking_loop
  -- a loop returns because a number goes down at each turn, while the invariant (what the loop
  -- keeps true: there is room for what is left to push) is kept
  apply loop.spec_decr_nat (fun p => p.1.slice.val.length - p.1.i)
    (fun p => p.1.slice = iter.slice ∧ p.1.i ≤ iter.slice.val.length ∧
      p.2.val.length + (iter.slice.val.length - p.1.i) ≤ L)
  · rintro ⟨it, acc⟩ ⟨same, i_le, room⟩
    dsimp only at same i_le room
    unfold Core.lacking_loop.body
    simp only
    -- a turn: the next element is read, and when there is none the loop is over
    step as ⟨o, it1, ho⟩
    rcases ho with ⟨more, x, rfl, same1, i1⟩ | ⟨done, rfl, rfl⟩
    · simp only
      step*
      all_goals
        simp only [same1, same, i1, true_and]
        rw [same] at more
        omega
    · simp only
      step*
  · exact ⟨rfl, i_le, room⟩

/-- `lacking` returns the names of some of the pulls. -/
@[step] theorem lacking_returns (on64 : OnA64BitMachine) (c : Core) (layers : Slice Std.U32)
    (fit : Short c) :
    Core.lacking c layers ⦃ r => r.val.length ≤ c.pulls.val.length ⦄ := by
  have small : c.pulls.val.length ≤ 2 ^ 40 := by have := fit.1; omega
  unfold Core.lacking
  step*
  simp only [iter_post, iter_post1, deref_val]
  simp [alloc.vec.Vec.new]

/-- The loop that asks whether a group of the layer is not done returns. -/
@[step] theorem waits_for_groups_loop_returns (iter : core.slice.iter.Iter Group) (layer : Std.U32)
    (i_le : iter.i ≤ iter.slice.val.length) :
    waits_for_groups_loop iter layer ⦃ _ => True ⦄ := by
  unfold waits_for_groups_loop
  -- a loop returns because a number goes down at each turn, while the invariant (what the loop
  -- keeps true: where it is in what it walks) is kept
  apply loop.spec_decr_nat (fun p => p.slice.val.length - p.i)
    (fun p => p.slice = iter.slice ∧ p.i ≤ iter.slice.val.length)
  · rintro it ⟨same, i_le⟩
    unfold waits_for_groups_loop.body
    -- a turn: the next element is read, and when there is none the loop is over
    step as ⟨o, it1, ho⟩
    rcases ho with ⟨more, x, rfl, same1, i1⟩ | ⟨done, rfl, rfl⟩
    · simp only
      step*
    · simp only
      step*
  · exact ⟨rfl, i_le⟩

/-- `waits_for_groups` returns. -/
@[step] theorem waits_for_groups_returns (groups : Slice Group) (layer : Std.U32) :
    waits_for_groups groups layer ⦃ _ => True ⦄ := by
  unfold waits_for_groups
  step*

/-- The count of the groups in flight for a pull returns. -/
@[step] theorem in_flight_loop_returns (iter : core.slice.iter.Iter Group) (pull : Std.U32)
    (sent : Std.U32) (i_le : iter.i ≤ iter.slice.val.length) :
    in_flight_loop iter pull sent ⦃ _ => True ⦄ := by
  unfold in_flight_loop
  -- a loop returns because a number goes down at each turn, while the invariant (what the loop
  -- keeps true: the elements left to read) is kept
  apply loop.spec_decr_nat (fun p => p.1.slice.val.length - p.1.i)
    (fun p => p.1.slice = iter.slice ∧ p.1.i ≤ iter.slice.val.length)
  · rintro ⟨it, s⟩ ⟨same, i_le⟩
    dsimp only at same i_le
    unfold in_flight_loop.body
    simp only
    -- a turn: the next element is read, and when there is none the loop is over
    step as ⟨o, it1, ho⟩
    rcases ho with ⟨more, x, rfl, same1, i1⟩ | ⟨done, rfl, rfl⟩
    · simp only
      step*
    · simp only
      step*
  · exact ⟨rfl, i_le⟩

/-- `in_flight` returns: it counts the groups of the core, saturating at the top of a `u32`. -/
@[step] theorem in_flight_returns (c : Core) (pull : Std.U32) :
    in_flight c pull ⦃ _ => True ⦄ := by
  unfold in_flight
  step*

/-- The count of the slots the pulls hold returns. -/
@[step] theorem slots_held_loop_returns (iter : core.slice.iter.Iter Pull) (held : Std.U32)
    (i_le : iter.i ≤ iter.slice.val.length) :
    slots_held_loop iter held ⦃ _ => True ⦄ := by
  unfold slots_held_loop
  -- a loop returns because a number goes down at each turn, while the invariant (what the loop
  -- keeps true: the elements left to read) is kept
  apply loop.spec_decr_nat (fun p => p.1.slice.val.length - p.1.i)
    (fun p => p.1.slice = iter.slice ∧ p.1.i ≤ iter.slice.val.length)
  · rintro ⟨it, s⟩ ⟨same, i_le⟩
    dsimp only at same i_le
    unfold slots_held_loop.body
    simp only
    -- a turn: the next element is read, and when there is none the loop is over
    step as ⟨o, it1, ho⟩
    rcases ho with ⟨more, x, rfl, same1, i1⟩ | ⟨done, rfl, rfl⟩
    · simp only
      step*
    · simp only
      step*
  · exact ⟨rfl, i_le⟩

/-- `slots_held` returns: it counts the pulls that hold a slot, saturating at the top of a
`u32`. -/
@[step] theorem slots_held_returns (c : Core) : slots_held c ⦃ _ => True ⦄ := by
  unfold slots_held
  step*

/-- The count of the working pulls (in `advance`) returns. -/
@[step] theorem advance_loop0_returns (iter : core.slice.iter.Iter Pull) (working : Std.Usize)
    (working_le : working.val ≤ iter.i)
    (i_le : iter.i ≤ iter.slice.val.length) :
    advance_loop0 iter working ⦃ r => r.val ≤ iter.slice.val.length ⦄ := by
  unfold advance_loop0
  -- a loop returns because a number goes down at each turn, while the invariant (what the loop
  -- keeps true: where it is in what it walks) is kept
  apply loop.spec_decr_nat (fun p => p.1.slice.val.length - p.1.i)
    (fun p => p.1.slice = iter.slice ∧ p.2.val ≤ p.1.i ∧ p.1.i ≤ iter.slice.val.length)
  · rintro ⟨it, s⟩ ⟨same, s_le, i_le⟩
    dsimp only at same s_le i_le
    unfold advance_loop0.body
    simp only
    -- a turn: the next element is read, and when there is none the loop is over
    step as ⟨o, it1, ho⟩
    rcases ho with ⟨more, x, rfl, same1, i1⟩ | ⟨done, rfl, rfl⟩
    · simp only
      step*
    · simp only
      step*
  · exact ⟨rfl, working_le, i_le⟩

/-- The count of the layers being committed (in `advance`) returns. -/
@[step] theorem advance_loop1_returns (iter : core.slice.iter.Iter Layer) (committing : Std.Usize)
    (committing_le : committing.val ≤ iter.i)
    (i_le : iter.i ≤ iter.slice.val.length) :
    advance_loop1 iter committing ⦃ r => r.val ≤ iter.slice.val.length ⦄ := by
  unfold advance_loop1
  -- a loop returns because a number goes down at each turn, while the invariant (what the loop
  -- keeps true: where it is in what it walks) is kept
  apply loop.spec_decr_nat (fun p => p.1.slice.val.length - p.1.i)
    (fun p => p.1.slice = iter.slice ∧ p.2.val ≤ p.1.i ∧ p.1.i ≤ iter.slice.val.length)
  · rintro ⟨it, s⟩ ⟨same, s_le, i_le⟩
    dsimp only at same s_le i_le
    unfold advance_loop1.body
    simp only
    -- a turn: the next element is read, and when there is none the loop is over
    step as ⟨o, it1, ho⟩
    rcases ho with ⟨more, x, rfl, same1, i1⟩ | ⟨done, rfl, rfl⟩
    · simp only
      step*
    · simp only
      step*
  · exact ⟨rfl, committing_le, i_le⟩

/-- The search for the first working pull that wants a group returns. -/
@[step] theorem wanting_loop_returns (iter : core.slice.iter.Iter Pull) (group : Group)
    (i_le : iter.i ≤ iter.slice.val.length) :
    wanting_loop iter group ⦃ _ => True ⦄ := by
  unfold wanting_loop
  -- a loop returns because a number goes down at each turn, while the invariant (what the loop
  -- keeps true: where it is in what it walks) is kept
  apply loop.spec_decr_nat (fun p => p.slice.val.length - p.i)
    (fun p => p.slice = iter.slice ∧ p.i ≤ iter.slice.val.length)
  · rintro it ⟨same, i_le⟩
    unfold wanting_loop.body
    -- a turn: the next element is read, and when there is none the loop is over
    step as ⟨o, it1, ho⟩
    rcases ho with ⟨more, x, rfl, same1, i1⟩ | ⟨done, rfl, rfl⟩
    · simp only
      step*
    · simp only
      step*
  · exact ⟨rfl, i_le⟩

/-- `wanting` returns. -/
@[step] theorem wanting_returns (pulls : Slice Pull) (group : Group) :
    wanting pulls group ⦃ _ => True ⦄ := by
  unfold wanting
  step*

/-- The test of the closure of `goes` (that no pull lacks the layer) returns, whatever it is given.
-/
theorem goes_closure_answers :
    ∀ p y, ∃ b p', goes.closure.Insts.CoreOpsFunctionFnMutTupleShared0PullBool.call_mut
      p y = ok (b, p') := by
  intro p y
  unfold goes.closure.Insts.CoreOpsFunctionFnMutTupleShared0PullBool.call_mut
  simp [lacks_iff]

/-- The `any` of `goes` over the pulls returns. -/
@[step] theorem any_goes_returns (it : core.slice.iter.Iter Pull) (x : Std.U32) :
    core.slice.iter.Iter.Insts.CoreIterTraitsIteratorIteratorSharedAT.any
      goes.closure.Insts.CoreOpsFunctionFnMutTupleShared0PullBool it x ⦃ _ _ => True ⦄ := by
  obtain ⟨r, found⟩ := any_total goes.closure.Insts.CoreOpsFunctionFnMutTupleShared0PullBool it x
    goes_closure_answers
  rw [found]
  exact (WP.spec_ok _).mpr trivial

/-- `goes` returns. -/
@[step] theorem goes_returns (layer : Std.U32) (mine : Slice Std.U32) (pulls : Slice Pull) :
    goes layer mine pulls ⦃ _ => True ⦄ := by
  unfold goes
  step*

/-- The test of the closure of `starting` (that a start is in flight in a layer the pull lacks,
or ended lately) returns. -/
theorem starting_closure_returns (p : Core.starting.closure) (y : ContainerStart) :
    Core.starting.closure.Insts.CoreOpsFunctionFnMutTupleShared0ContainerStartBool.call_mut p y
      ⦃ _ _ => True ⦄ := by
  unfold Core.starting.closure.Insts.CoreOpsFunctionFnMutTupleShared0ContainerStartBool.call_mut
  rcases p with ⟨a, i, c1⟩
  step*

/-- `Core::starting` returns. -/
@[step] theorem starting_returns (c : Core) (p : Pull) (now : Std.U64) :
    Core.starting c p now ⦃ _ => True ⦄ := by
  unfold Core.starting
  step*
  obtain ⟨r, found⟩ := any_total
    Core.starting.closure.Insts.CoreOpsFunctionFnMutTupleShared0ContainerStartBool
    i (p, now, c) (answers_of_spec (inst :=
    Core.starting.closure.Insts.CoreOpsFunctionFnMutTupleShared0ContainerStartBool)
    starting_closure_returns)
  rw [found]
  obtain ⟨b, _⟩ := r
  simp [WP.spec_ok]

/-- `sooner` returns. -/
@[step] theorem sooner_returns (next : Option Std.U64) (t now : Std.U64) :
    sooner next t now ⦃ _ => True ⦄ := by
  unfold sooner
  step*

/-- `backoff` returns: the shift, the minimum and the product cannot fail. -/
@[step] theorem backoff_returns (failures : Std.U32) (max : Std.U64) :
    backoff failures max ⦃ _ => True ⦄ := by
  unfold backoff
  step*

/-- The loop of `next_wake` over the pulls returns. -/
@[step] theorem next_wake_loop0_returns (iter : core.slice.iter.Iter Pull) (now : Std.U64)
    (next : Option Std.U64) (i_le : iter.i ≤ iter.slice.val.length) :
    next_wake_loop0 iter now next ⦃ _ => True ⦄ := by
  unfold next_wake_loop0
  -- a loop returns because a number goes down at each turn, while the invariant (what the loop
  -- keeps true: where it is in what it walks) is kept
  apply loop.spec_decr_nat (fun p => p.1.slice.val.length - p.1.i)
    (fun p => p.1.slice = iter.slice ∧ p.1.i ≤ iter.slice.val.length)
  · rintro ⟨it, s⟩ ⟨same, i_le⟩
    dsimp only at same i_le
    unfold next_wake_loop0.body
    simp only
    -- a turn: the next element is read, and when there is none the loop is over
    step as ⟨o, it1, ho⟩
    rcases ho with ⟨more, x, rfl, same1, i1⟩ | ⟨done, rfl, rfl⟩
    · simp only
      split <;> step*
    · simp only
      step*
  · exact ⟨rfl, i_le⟩

/-- The loop of `next_wake` over the starts returns. -/
@[step] theorem next_wake_loop1_returns (iter : core.slice.iter.Iter ContainerStart) (c : Cfg)
    (now : Std.U64) (next : Option Std.U64) (i_le : iter.i ≤ iter.slice.val.length) :
    next_wake_loop1 iter c now next ⦃ _ => True ⦄ := by
  unfold next_wake_loop1
  -- a loop returns because a number goes down at each turn, while the invariant (what the loop
  -- keeps true: where it is in what it walks) is kept
  apply loop.spec_decr_nat (fun p => p.1.slice.val.length - p.1.i)
    (fun p => p.1.slice = iter.slice ∧ p.1.i ≤ iter.slice.val.length)
  · rintro ⟨it, s⟩ ⟨same, i_le⟩
    dsimp only at same i_le
    unfold next_wake_loop1.body
    simp only
    -- a turn: the next element is read, and when there is none the loop is over
    step as ⟨o, it1, ho⟩
    rcases ho with ⟨more, x, rfl, same1, i1⟩ | ⟨done, rfl, rfl⟩
    · simp only
      step*
    · simp only
      step*
  · exact ⟨rfl, i_le⟩

/-- `next_wake` returns. -/
@[step] theorem next_wake_returns (c : Core) (now : Std.U64) :
    next_wake c now ⦃ _ => True ⦄ := by
  unfold next_wake
  step*

/-- The test of the closure of `progress` returns. -/
theorem progress_closure_returns (p : progress.closure) (y : Std.U32) :
    progress.closure.Insts.CoreOpsFunctionFnMutTupleShared0U32Bool.call_mut p y
      ⦃ _ _ => True ⦄ := by
  unfold progress.closure.Insts.CoreOpsFunctionFnMutTupleShared0U32Bool.call_mut
  step*

/-- The `any` of `progress` over the layers returns. -/
@[step] theorem any_progress_returns (it : core.slice.iter.Iter Std.U32) (x : Pull) :
    core.slice.iter.Iter.Insts.CoreIterTraitsIteratorIteratorSharedAT.any
      progress.closure.Insts.CoreOpsFunctionFnMutTupleShared0U32Bool it x ⦃ _ _ => True ⦄ := by
  obtain ⟨r, found⟩ := any_total progress.closure.Insts.CoreOpsFunctionFnMutTupleShared0U32Bool
    it x (answers_of_spec (inst := progress.closure.Insts.CoreOpsFunctionFnMutTupleShared0U32Bool)
    progress_closure_returns)
  rw [found]
  exact (WP.spec_ok _).mpr trivial

/-- The loop of `has_all` returns, if the test it is given returns. -/
theorem has_all_loop_returns {T0 : Type} (inst : core.ops.function.Fn T0 LayerState Bool)
    (p : Pull) (done : T0) (iter : core.slice.iter.Iter Layer)
    (answers : ∀ s, inst.call done s ⦃ _ => True ⦄) (i_le : iter.i ≤ iter.slice.val.length) :
    Pull.has_all_loop inst iter p done ⦃ _ => True ⦄ := by
  unfold Pull.has_all_loop
  -- a loop returns because a number goes down at each turn, while the invariant (what the loop
  -- keeps true: where it is in what it walks) is kept
  apply loop.spec_decr_nat (fun it => it.slice.val.length - it.i)
    (fun it => it.slice = iter.slice ∧ it.i ≤ iter.slice.val.length)
  · rintro it ⟨same, i_le⟩
    unfold Pull.has_all_loop.body
    -- a turn: the next element is read, and when there is none the loop is over
    step as ⟨o, it1, ho⟩
    rcases ho with ⟨more, x, rfl, same1, i1⟩ | ⟨done, rfl, rfl⟩
    · simp only
      step*
    · simp only
      step*
  · exact ⟨rfl, i_le⟩

/-- `has_all` returns, for a test that returns. -/
theorem has_all_returns {T0 : Type} (inst : core.ops.function.Fn T0 LayerState Bool) (p : Pull)
    (layers : Slice Layer) (done : T0) (answers : ∀ s, inst.call done s ⦃ _ => True ⦄) :
    Pull.has_all inst p layers done ⦃ _ => True ⦄ := by
  unfold Pull.has_all
  step*
  exact has_all_loop_returns inst p done _ answers (by simp [*])

/-- The test of `advance` that the layers are stored returns. -/
@[step] theorem has_all_stored_returns (p : Pull) (layers : Slice Layer) :
    Pull.has_all advance.closure.Insts.CoreOpsFunctionFnTupleLayerStateBool p layers ()
      ⦃ _ => True ⦄ :=
  has_all_returns _ p layers () (fun s => by
    show advance.closure.Insts.CoreOpsFunctionFnTupleLayerStateBool.call () s ⦃ _ => True ⦄
    rw [stored_test]
    exact (WP.spec_ok _).mpr trivial)

/-- The test of `advance` that the layers are ready or stored returns. -/
@[step] theorem has_all_ready_returns (p : Pull) (layers : Slice Layer) :
    Pull.has_all advance.closure_1.Insts.CoreOpsFunctionFnTupleLayerStateBool p layers ()
      ⦃ _ => True ⦄ :=
  has_all_returns _ p layers () (fun s => by
    show advance.closure_1.Insts.CoreOpsFunctionFnTupleLayerStateBool.call () s ⦃ _ => True ⦄
    rw [ready_test]
    exact (WP.spec_ok _).mpr trivial)

end LazyCore
