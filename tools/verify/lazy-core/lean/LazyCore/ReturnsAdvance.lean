-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: that `advance` (what can go on now does: the layers whose files are
-- there are committed, the pulls whose layers are done go on, the groups that fit in the window of
-- a pull are fetched) and its five loops return.  The three loops that ask for something are
-- bounded: one commit for each layer, one image or driver's pull for each pull, one fetch for each
-- group for each pull (a product of two tables, at most 2^50).
--
-- Why it is needed: every event but the start of a container ends with `advance`, so the claim
-- that `step` returns rests on it.  It is also the function with the most `iter_mut` loops: the
-- lemmas say that they put the layers, the pulls and the groups back in as many.
--
-- Read before this file: Spec.lean, ReturnsQueries.lean, and in lib.rs `advance`.
--
-- The tactics a reader meets in the proofs.  `step*` follows the Rust function line by line: for
-- each call it uses the lemma of this development that says when the call returns and what it
-- gives (the lemmas marked `@[step]`), and leaves what is to be shown (that a `Vec` has room, that
-- an index is inside) as goals.  `step as ⟨x, hx⟩` does one line and names the result `x` and what
-- is known of it `hx`.  `loop.spec_decr_nat` proves that a loop returns because a number goes down
-- at each turn (here, the elements left to read) while a fact (the invariant) is kept.
-- `bookkeeping` (ReturnsBasics.lean) closes the goals that are only sums of lengths.
--
-- Notation: as in ReturnsLeaving.lean.  The loops are numbered as Aeneas does (`advance_loop0` is
-- the
-- first loop of `advance` in the Rust, in the order they come; the one inside the last loop is
-- `advance_loop4_loop0`).
import LazyCore.ReturnsQueries

open Aeneas Aeneas.Std Result velarx_lazy_core
open Aeneas.Data.Coinductive

namespace LazyCore

/-- The loop of `advance` over the layers asks for the commit of at most one for each. -/
@[step] theorem advance_loop2_returns (on64 : OnA64BitMachine)
    (iter : core.slice.iter.IterMut Layer)
    (back : core.slice.iter.IterMut Layer → core.slice.iter.IterMut Layer) (cfg : Cfg)
    (out : alloc.vec.Vec Action) (working committing : Std.Usize) (groups : alloc.vec.Vec Group)
    (i_le : iter.i ≤ iter.slice.val.length)
    (room : out.val.length + (iter.slice.val.length - iter.i) ≤ 2 ^ 63)
    (back_ok : ∀ it', (back it').slice.val.length = it'.slice.val.length) :
    advance_loop2 iter back cfg out working committing groups ⦃ _ out1 im back2 =>
      out1.val.length ≤ out.val.length + (iter.slice.val.length - iter.i) ∧
      im.slice = iter.slice ∧ ∀ it', (back2 it').slice.val.length = it'.slice.val.length ⦄ := by
  have max_is := usize_max_is on64
  unfold advance_loop2
  -- a loop returns because a number goes down at each turn, while the invariant (what the loop
  -- keeps true: there is room for what is left to push) is kept
  apply loop.spec_decr_nat (fun p => p.1.slice.val.length - p.1.i)
    (fun p => p.1.slice = iter.slice ∧ p.1.i ≤ iter.slice.val.length ∧
      (∀ it', (p.2.1 it').slice.val.length = it'.slice.val.length) ∧
      p.2.2.1.val.length + (iter.slice.val.length - p.1.i) ≤
        out.val.length + (iter.slice.val.length - iter.i))
  · rintro ⟨it, back1, acc, comm⟩ ⟨same, i_le, back_ok, room⟩
    dsimp only at same i_le back_ok room
    unfold advance_loop2.body
    simp only
    -- a turn: the next element is read, and when there is none the loop is over
    step as ⟨o, it1, next_back, same1, next_ok, ho⟩
    rcases ho with ⟨more, x, rfl, i1⟩ | ⟨done, rfl, i1⟩
    · simp only
      step*
      all_goals bookkeeping
    · simp only
      step*
      bookkeeping
  · exact ⟨rfl, i_le, back_ok, by dsimp only; omega⟩

/-- The loop of `advance` over the pulls asks for the commit of the image or the pull of the
driver of at most one for each, and puts the pulls back in as many. -/
@[step] theorem advance_loop3_returns (on64 : OnA64BitMachine) (iter : core.slice.iter.IterMut Pull)
    (back : core.slice.iter.IterMut Pull → core.slice.iter.IterMut Pull)
    (out : alloc.vec.Vec Action) (layers : alloc.vec.Vec Layer)
    (i_le : iter.i ≤ iter.slice.val.length)
    (room : out.val.length + (iter.slice.val.length - iter.i) ≤ 2 ^ 63)
    (back_ok : ∀ it', (back it').slice.val.length = it'.slice.val.length) :
    advance_loop3 iter back out layers ⦃ out1 im back2 =>
      out1.val.length ≤ out.val.length + (iter.slice.val.length - iter.i) ∧
      im.slice = iter.slice ∧ ∀ it', (back2 it').slice.val.length = it'.slice.val.length ⦄ := by
  have max_is := usize_max_is on64
  unfold advance_loop3
  -- a loop returns because a number goes down at each turn, while the invariant (what the loop
  -- keeps true: there is room for what is left to push) is kept
  apply loop.spec_decr_nat (fun p => p.1.slice.val.length - p.1.i)
    (fun p => p.1.slice = iter.slice ∧ p.1.i ≤ iter.slice.val.length ∧
      (∀ it', (p.2.1 it').slice.val.length = it'.slice.val.length) ∧
      p.2.2.val.length + (iter.slice.val.length - p.1.i) ≤
        out.val.length + (iter.slice.val.length - iter.i))
  · rintro ⟨it, back1, acc⟩ ⟨same, i_le, back_ok, room⟩
    dsimp only at same i_le back_ok room
    unfold advance_loop3.body
    simp only
    -- a turn: the next element is read, and when there is none the loop is over
    step as ⟨o, it1, next_back, same1, next_ok, ho⟩
    rcases ho with ⟨more, x, rfl, i1⟩ | ⟨done, rfl, i1⟩
    · simp only
      step*
      all_goals bookkeeping
    · simp only
      step*
      bookkeeping
  · exact ⟨rfl, i_le, back_ok, by dsimp only; omega⟩

/-- The loop of `advance` over the groups of a pull asks to fetch at most one for each. -/
@[step] theorem advance_loop4_loop0_returns (on64 : OnA64BitMachine)
    (iter : core.ops.range.Range Std.Usize) (pulls : alloc.vec.Vec Pull)
    (v : alloc.vec.Vec Group) (out : alloc.vec.Vec Action) (p : Std.Usize) (limit id sent : Std.U32)
    (start_le : iter.start.val ≤ iter.end.val) (end_le : iter.end.val ≤ v.val.length)
    (p_in : p.val < pulls.val.length)
    (room : out.val.length + (iter.end.val - iter.start.val) ≤ 2 ^ 63) :
    advance_loop4_loop0 iter pulls v out p limit id sent ⦃ v1 out1 =>
      v1.val.length = v.val.length ∧
      out1.val.length ≤ out.val.length + (iter.end.val - iter.start.val) ⦄ := by
  have max_is := usize_max_is on64
  unfold advance_loop4_loop0
  -- a loop returns because a number goes down at each turn, while the invariant (what the loop
  -- keeps true: there is room for what is left to push) is kept
  apply loop.spec_decr_nat (fun p => p.1.end.val - p.1.start.val)
    (fun p => p.1.end.val = iter.end.val ∧ p.1.start.val ≤ p.1.end.val ∧
      p.2.1.val.length = v.val.length ∧
      p.2.2.1.val.length + (iter.end.val - p.1.start.val) ≤
        out.val.length + (iter.end.val - iter.start.val))
  · rintro ⟨it, v1, acc, sent1⟩ ⟨same_end, start_le, same_len, room⟩
    dsimp only at same_end start_le same_len room
    unfold advance_loop4_loop0.body
    simp only
    -- a turn: the next element is read, and when there is none the loop is over
    step as ⟨o, it1, ho, same_end1⟩
    have same_end1 : it1.end.val = it.end.val := by rw [same_end1]
    by_cases lt : it.start.val < it.end.val
    · simp only [lt, ↓reduceIte] at ho
      obtain ⟨rfl, i1⟩ := ho
      simp only
      step*
      all_goals bookkeeping
    · simp only [lt, ↓reduceIte] at ho
      obtain ⟨rfl, _⟩ := ho
      simp only
      step*
  · exact ⟨rfl, start_le, rfl, by dsimp only; omega⟩

/-- The loop of `advance` over the pulls: a pull that is working and not yielding to the start of a
container asks to fetch the groups it wants, as many as its window; at most one fetch for each
group, for each pull. -/
@[step] theorem advance_loop4_returns (on64 : OnA64BitMachine)
    (iter : core.ops.range.Range Std.Usize)
    (cfg : Cfg) (pulls : alloc.vec.Vec Pull) (layers : alloc.vec.Vec Layer)
    (groups : alloc.vec.Vec Group) (starts : alloc.vec.Vec ContainerStart) (now : Std.U64)
    (out : alloc.vec.Vec Action) (start_le : iter.start.val ≤ iter.end.val)
    (end_le : iter.end.val ≤ pulls.val.length)
    (groups_fit : groups.val.length ≤ 2 ^ 25)
    (room : out.val.length + (iter.end.val - iter.start.val) * 2 ^ 25 ≤ 2 ^ 63) :
    advance_loop4 iter cfg pulls layers groups starts now out ⦃ _ groups1 out1 =>
      groups1.val.length = groups.val.length ∧
      out1.val.length ≤ out.val.length + (iter.end.val - iter.start.val) * 2 ^ 25 ⦄ := by
  have max_is := usize_max_is on64
  unfold advance_loop4
  -- a loop returns because a number goes down at each turn, while the invariant (what the loop
  -- keeps true: there is room for what is left to push) is kept
  apply loop.spec_decr_nat (fun p => p.1.end.val - p.1.start.val)
    (fun p => p.1.end.val = iter.end.val ∧ p.1.start.val ≤ p.1.end.val ∧
      p.2.1.val.length = groups.val.length ∧
      p.2.2.val.length + (iter.end.val - p.1.start.val) * 2 ^ 25 ≤
        out.val.length + (iter.end.val - iter.start.val) * 2 ^ 25)
  · rintro ⟨it, g1, acc⟩ ⟨same_end, start_le, same_len, room⟩
    dsimp only at same_end start_le same_len room
    unfold advance_loop4.body
    simp only
    -- a turn: the next element is read, and when there is none the loop is over
    step as ⟨o, it1, ho, same_end1⟩
    have same_end1 : it1.end.val = it.end.val := by rw [same_end1]
    by_cases lt : it.start.val < it.end.val
    · simp only [lt, ↓reduceIte] at ho
      obtain ⟨rfl, i1⟩ := ho
      simp only
      step as ⟨pull, pull_post⟩
      step as ⟨b⟩
      split
      · step as ⟨b1⟩
        split
        · step*
          bookkeeping
        · by_cases hb : pull.boosted = true <;>
            simp only [hb, Bool.false_eq_true, ↓reduceIte, bind_ok] <;> step* <;> bookkeeping
      · step*
        bookkeeping
    · simp only [lt, ↓reduceIte] at ho
      obtain ⟨rfl, _⟩ := ho
      simp only
      step*
  · exact ⟨rfl, start_le, rfl, by dsimp only; omega⟩

/-- `advance` asks for what can go on, as much as one action for each layer and each pull, and one
fetch for each group and each pull. -/
@[step] theorem advance_returns (on64 : OnA64BitMachine) (c : Core) (now : Std.U64)
    (out : alloc.vec.Vec Action) (fit : Short c)
    (room : out.val.length + (2 ^ 25 * 2 ^ 25 + 2 * 2 ^ 25) ≤ 2 ^ 63) :
    advance c now out ⦃ c1 out1 => Short c1 ∧ c1.pulls.val.length = c.pulls.val.length ∧
      out1.val.length ≤ out.val.length + (2 ^ 25 * 2 ^ 25 + 2 * 2 ^ 25) ⦄ := by
  have max_is := usize_max_is on64
  obtain ⟨pulls_fit, layers_fit, groups_fit, starts_fit⟩ := fit
  unfold advance
  -- the working pulls and the layers being committed are counted; the loop over the layers asks
  -- for commits, the loop over the pulls for images and driver's pulls, the loop over the pulls
  -- and their groups for fetches; each put what it walked back in as many
  step*
  all_goals bookkeeping

end LazyCore
