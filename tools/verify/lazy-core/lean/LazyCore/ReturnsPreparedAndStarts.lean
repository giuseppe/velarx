-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: that `prepared` (the answer of a preparation: the layers and the groups
-- the try lacks) and `start_at` (the record of the starts of containers in a layer) return, with
-- their loops.  `prepared` adds the layers and groups that are new to the tables and sets the pull
-- working; for a late answer (a pull that is not preparing) it only forgets what it was told.
--
-- Why it is needed: these are the only places where the tables GROW (a pull is added by `add`,
-- see ReturnsLeaving.lean): the lemmas ask for room for what is added (`Roomy` of Spec.lean), and
-- say that the tables are short afterwards.  `prepared` also looks up the pull by its number and
-- tests its place (`filter_preparing_returns`): a late answer for a pull that is gone finds no
-- place and does nothing, which is what makes a bad number of the event harmless.
--
-- Read before this file: Spec.lean (`Roomy`), ReturnsQueries.lean, and in lib.rs `prepared` and
-- `start_at`.
--
-- The tactics a reader meets in the proofs.  `step*` follows the Rust function line by line: for
-- each call it uses the lemma of this development that says when the call returns and what it
-- gives (the lemmas marked `@[step]`), and leaves what is to be shown (that a `Vec` has room, that
-- an index is inside) as goals.  `step as ⟨x, hx⟩` does one line and names the result `x` and what
-- is known of it `hx`.  `loop.spec_decr_nat` proves that a loop returns because a number goes down
-- at each turn (here, the elements left to read) while a fact (the invariant) is kept.
-- `bookkeeping` (ReturnsBasics.lean) closes the goals that are only sums of lengths.
--
-- Notation: as in ReturnsLeaving.lean; `GroupFact` is a group an answer lists, with the layers
-- that wait for it.
import LazyCore.ReturnsLeaving

open Aeneas Aeneas.Std Result velarx_lazy_core
open Aeneas.Data.Coinductive

namespace LazyCore

/-- The loop of `prepared` for a late answer asks to forget each new layer. -/
@[step] theorem prepared_loop0_returns (on64 : OnA64BitMachine)
    (iter : alloc.vec.into_iter.IntoIter Std.U32)
    (out : alloc.vec.Vec Action) (room : out.val.length + iter.val.length ≤ 2 ^ 63) :
    prepared_loop0 iter out ⦃ r => r.val.length ≤ out.val.length + iter.val.length ⦄ := by
  have max_is := usize_max_is on64
  unfold prepared_loop0
  -- a loop returns because a number goes down at each turn, while the invariant (what the loop
  -- keeps true: there is room for what is left to push) is kept
  apply loop.spec_decr_nat (fun p => p.1.val.length)
    (fun p => p.2.val.length + p.1.val.length ≤ out.val.length + iter.val.length)
  · rintro ⟨it, acc⟩ room1
    dsimp only at room1
    unfold prepared_loop0.body
    simp only
    -- a turn: the next element is read, and when there is none the loop is over
    step as ⟨o, it1, ho⟩
    rcases ho with ⟨empty, rfl, rfl⟩ | ⟨x, l, split, rfl, done_l⟩
    · simp only
      step*
    · simp only
      step*
  · dsimp only; omega

/-- The loop of `prepared` for a late answer asks to forget each group. -/
@[step] theorem prepared_loop1_returns (on64 : OnA64BitMachine)
    (iter : alloc.vec.into_iter.IntoIter GroupFact)
    (out : alloc.vec.Vec Action) (room : out.val.length + iter.val.length ≤ 2 ^ 63) :
    prepared_loop1 iter out ⦃ r => r.val.length ≤ out.val.length + iter.val.length ⦄ := by
  have max_is := usize_max_is on64
  unfold prepared_loop1
  -- a loop returns because a number goes down at each turn, while the invariant (what the loop
  -- keeps true: there is room for what is left to push) is kept
  apply loop.spec_decr_nat (fun p => p.1.val.length)
    (fun p => p.2.val.length + p.1.val.length ≤ out.val.length + iter.val.length)
  · rintro ⟨it, acc⟩ room1
    dsimp only at room1
    unfold prepared_loop1.body
    simp only
    -- a turn: the next element is read, and when there is none the loop is over
    step as ⟨o, it1, ho⟩
    rcases ho with ⟨empty, rfl, rfl⟩ | ⟨x, l, split, rfl, done_l⟩
    · simp only
      step*
    · simp only
      step*
  · dsimp only; omega

/-- The loop of `prepared` that adds the new layers to the table. -/
@[step] theorem prepared_loop3_returns (on64 : OnA64BitMachine)
    (iter : alloc.vec.into_iter.IntoIter Std.U32)
    (v : alloc.vec.Vec Layer) (room : v.val.length + iter.val.length ≤ 2 ^ 25) :
    prepared_loop3 iter v ⦃ r => r.val.length ≤ v.val.length + iter.val.length ⦄ := by
  have max_is := usize_max_is on64
  unfold prepared_loop3
  -- a loop returns because a number goes down at each turn, while the invariant (what the loop
  -- keeps true: there is room for what is left to push) is kept
  apply loop.spec_decr_nat (fun p => p.1.val.length)
    (fun p => p.2.val.length + p.1.val.length ≤ v.val.length + iter.val.length)
  · rintro ⟨it, acc⟩ room1
    dsimp only at room1
    unfold prepared_loop3.body
    simp only
    -- a turn: the next element is read, and when there is none the loop is over
    step as ⟨o, it1, ho⟩
    rcases ho with ⟨empty, rfl, rfl⟩ | ⟨x, l, split, rfl, done_l⟩
    · simp only
      step*
    · simp only
      step*
  · dsimp only; omega

/-- The test of the closure of `prepared` on the layers a group names (that the layer is new)
returns. -/
theorem prepared_closure2_returns (p : prepared.closure_2) (y : Std.U32) :
    prepared.closure_2.Insts.CoreOpsFunctionFnMutTupleShared1U32Bool.call_mut p y
      ⦃ _ _ => True ⦄ := by
  unfold prepared.closure_2.Insts.CoreOpsFunctionFnMutTupleShared1U32Bool.call_mut
  step*

/-- The `retain` of `prepared` over the layers a group names returns, and keeps no more than it
had. -/
@[step] theorem retain_prepared_closure2 (v : alloc.vec.Vec Std.U32) (f : prepared.closure_2) :
    alloc.vec.Vec.retain alloc.alloc.Global
      prepared.closure_2.Insts.CoreOpsFunctionFnMutTupleShared1U32Bool v f
      ⦃ r => r.val.length ≤ v.val.length ⦄ :=
  retain_total _ _ v f (answers_of_spec (inst :=
    prepared.closure_2.Insts.CoreOpsFunctionFnMutTupleShared1U32Bool) prepared_closure2_returns)

/-- The test of the closure of `prepared` on a layer (that the core does not hold it) returns. -/
theorem prepared_closure1_returns (p : prepared.closure_1) (y : Std.U32) :
    prepared.closure_1.Insts.CoreOpsFunctionFnMutTupleShared1U32Bool.call_mut p y
      ⦃ _ _ => True ⦄ := by
  unfold prepared.closure_1.Insts.CoreOpsFunctionFnMutTupleShared1U32Bool.call_mut
  step*

/-- The `retain` of `prepared` over the layers of the answer returns, and keeps no more than
it had. -/
@[step] theorem retain_prepared_closure1 (v : alloc.vec.Vec Std.U32) (f : prepared.closure_1) :
    alloc.vec.Vec.retain alloc.alloc.Global
      prepared.closure_1.Insts.CoreOpsFunctionFnMutTupleShared1U32Bool v f
      ⦃ r => r.val.length ≤ v.val.length ⦄ :=
  retain_total _ _ v f (answers_of_spec (inst :=
    prepared.closure_1.Insts.CoreOpsFunctionFnMutTupleShared1U32Bool) prepared_closure1_returns)

/-- The loop of `prepared` over the groups the answer lists. -/
@[step] theorem prepared_loop2_returns (on64 : OnA64BitMachine)
    (iter : alloc.vec.into_iter.IntoIter GroupFact) (v : alloc.vec.Vec Group)
    (out : alloc.vec.Vec Action) (fresh : alloc.vec.Vec Std.U32)
    (room : out.val.length + iter.val.length ≤ 2 ^ 63)
    (v_room : v.val.length + iter.val.length ≤ 2 ^ 25) :
    prepared_loop2 iter v out fresh ⦃ v1 out1 =>
      v1.val.length ≤ v.val.length + iter.val.length ∧
      out1.val.length ≤ out.val.length + iter.val.length ⦄ := by
  have max_is := usize_max_is on64
  unfold prepared_loop2
  -- a loop returns because a number goes down at each turn, while the invariant (what the loop
  -- keeps true: there is room for what is left to push) is kept
  apply loop.spec_decr_nat (fun p => p.1.val.length)
    (fun p => p.2.1.val.length + p.1.val.length ≤ v.val.length + iter.val.length ∧
      p.2.2.val.length + p.1.val.length ≤ out.val.length + iter.val.length)
  · rintro ⟨it, v1, acc⟩ ⟨v_room1, room1⟩
    dsimp only at v_room1 room1
    unfold prepared_loop2.body
    simp only
    -- a turn: the next element is read, and when there is none the loop is over
    step as ⟨o, it1, ho⟩
    rcases ho with ⟨empty, rfl, rfl⟩ | ⟨x, l, split, rfl, done_l⟩
    · simp only
      step*
      bookkeeping
    · simp only
      step*
      all_goals bookkeeping
  · dsimp only; omega

/-- `Option::filter` of the place of a pull by the test of `prepared` (that its try is preparing)
keeps a place inside the table, if it keeps one. -/
@[step] theorem filter_preparing_returns (o : Option Std.Usize) (pulls : alloc.vec.Vec Pull)
    (inside : ∀ n, o = some n → n.val < pulls.val.length) :
    core.option.Option.filter
      prepared.closure.Insts.CoreOpsFunctionFnOnceTupleShared1UsizeBool o pulls
      ⦃ r => ∀ n, r = some n → n.val < pulls.val.length ⦄ := by
  unfold core.option.Option.filter
  cases o with
  | none => simp [WP.spec_ok]
  | some t =>
    simp only
    have : t.val < pulls.val.length := inside t rfl
    unfold prepared.closure.Insts.CoreOpsFunctionFnOnceTupleShared1UsizeBool.call_once
    step*
    split <;> simp_all

/-- `prepared` adds the layers and groups of the answer to the tables and sets the pull working. -/
@[step] theorem prepared_returns (on64 : OnA64BitMachine) (c : Core) (pull : Std.U32)
    (layers : alloc.vec.Vec Std.U32) (groups : alloc.vec.Vec GroupFact)
    (out : alloc.vec.Vec Action) (fit : Short c)
    (layers_room : c.layers.val.length + layers.val.length ≤ 2 ^ 25)
    (groups_room : c.groups.val.length + groups.val.length ≤ 2 ^ 25)
    (room : out.val.length + layers.val.length + groups.val.length ≤ 2 ^ 63) :
    prepared c pull layers groups out ⦃ c1 out1 => Short c1 ∧
      c1.pulls.val.length = c.pulls.val.length ∧
      out1.val.length ≤ out.val.length + layers.val.length + groups.val.length ⦄ := by
  have max_is := usize_max_is on64
  obtain ⟨pulls_fit, layers_fit, groups_fit, starts_fit⟩ := fit
  unfold prepared
  -- the pull is looked up and tested; a late answer forgets what it was told; otherwise the
  -- groups and the layers are added to the tables (room for them is asked) and the pull works
  step*
  all_goals bookkeeping

/-- The test of the closure of `start_at` (that a record is of the layer, or of a start that is
in flight or ended lately) returns. -/
theorem start_at_closure_returns (p : start_at.closure) (y : ContainerStart) :
    start_at.closure.Insts.CoreOpsFunctionFnMutTupleShared3ContainerStartBool.call_mut p y
      ⦃ _ _ => True ⦄ := by
  unfold start_at.closure.Insts.CoreOpsFunctionFnMutTupleShared3ContainerStartBool.call_mut
  rcases p with ⟨a, b, c⟩
  step*

/-- The `retain` of `start_at` over the records returns, and keeps no more than it had. -/
@[step] theorem retain_start_at (v : alloc.vec.Vec ContainerStart) (f : start_at.closure) :
    alloc.vec.Vec.retain alloc.alloc.Global
      start_at.closure.Insts.CoreOpsFunctionFnMutTupleShared3ContainerStartBool v f
      ⦃ r => r.val.length ≤ v.val.length ⦄ :=
  retain_total _ _ v f (answers_of_spec (inst :=
    start_at.closure.Insts.CoreOpsFunctionFnMutTupleShared3ContainerStartBool)
    start_at_closure_returns)

/-- The search of the record of the starts of a layer finds a place inside the table, if any. -/
@[step] theorem position_start_returns (it : core.slice.iter.Iter ContainerStart)
    (layer : Std.U32) (start : it.i = 0) :
    core.slice.iter.Iter.Insts.CoreIterTraitsIteratorIteratorSharedAT.position
      start_at.closure_1.Insts.CoreOpsFunctionFnMutTupleShared0ContainerStartBool it layer
      ⦃ o _ => ∀ n, o = some n → n.val < it.slice.val.length ⦄ := by
  obtain ⟨slice, i⟩ := it
  simp only at start
  subst start
  obtain ⟨o, it1, found, result⟩ := position_pure
    start_at.closure_1.Insts.CoreOpsFunctionFnMutTupleShared0ContainerStartBool
    (fun s : ContainerStart => s.layer = layer) slice layer (fun _ => rfl)
  rw [found]
  cases o with
  | none => simp [WP.spec_ok]
  | some n =>
    obtain ⟨hn, _, _⟩ := result
    simp only [WP.spec_ok, WP.uncurry']
    intro m h
    cases h
    exact hn

/-- `start_at` finds or makes the record of the starts in a layer; it makes at most one. -/
@[step] theorem start_at_returns (on64 : OnA64BitMachine) (c : Core) (layer : Std.U32)
    (now : Std.U64)
    (fit : Short c) (room : c.starts.val.length + 1 ≤ 2 ^ 25) :
    start_at c layer now ⦃ _ back => ∀ cs, Short (back cs) ⦄ := by
  have max_is := usize_max_is on64
  obtain ⟨pulls_fit, layers_fit, groups_fit, starts_fit⟩ := fit
  unfold start_at
  -- the records that no start is in or was lately are dropped, then the record of the layer is
  -- found, or one more is pushed
  refine WP.spec_bind (retain_start_at _ _) ?_
  intro v v_post
  step*
  all_goals (try intro cs)
  all_goals bookkeeping

end LazyCore
