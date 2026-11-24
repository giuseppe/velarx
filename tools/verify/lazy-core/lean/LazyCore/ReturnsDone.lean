-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: that what a `Done` does returns: `succeeded` (a group, a layer or a
-- pull whose work ended well: `progress` marks the pulls that lacked it, the driver's pull stores
-- the layers, the end of an image or of a stop makes the pull leave) and `failed` (the tries that
-- waited for the work fail: `try_failed` for each of them, found by `lacking`), with their loops.
--
-- Why it is needed: `failed` is the most costly of the events: a failed group fails the try of
-- every
-- pull that waits for it, and each failed try may let go of the layers and the groups, so the
-- number of actions is a product of two tables (at most 2^25 each).  The lemma says it is below
-- `2^51`, so that the claim that `step` returns can ask for an action list of `2^62` at most.
--
-- Read before this file: Spec.lean, ReturnsQueries.lean, ReturnsLeaving.lean, and in lib.rs
-- `progress`, `succeeded`, `failed`.
--
-- The tactics a reader meets in the proofs.  `step*` follows the Rust function line by line: for
-- each call it uses the lemma of this development that says when the call returns and what it
-- gives (the lemmas marked `@[step]`), and leaves what is to be shown (that a `Vec` has room, that
-- an index is inside) as goals.  `step as ⟨x, hx⟩` does one line and names the result `x` and what
-- is known of it `hx`.  `loop.spec_decr_nat` proves that a loop returns because a number goes down
-- at each turn (here, the elements left to read) while a fact (the invariant) is kept.
-- `bookkeeping` (ReturnsBasics.lean) closes the goals that are only sums of lengths.
--
-- Notation: as in ReturnsLeaving.lean; `back` is the function Aeneas gives with an `iter_mut`:
-- it puts the elements the loop changed back in the vector, and does not change its length.
import LazyCore.ReturnsLeaving

open Aeneas Aeneas.Std Result velarx_lazy_core
open Aeneas.Data.Coinductive

namespace LazyCore

/-- The loop of `progress` over the pulls marks some of them and puts them back in as many. -/
@[step] theorem progress_loop_returns (iter : core.slice.iter.IterMut Pull)
    (back : core.slice.iter.IterMut Pull → core.slice.iter.IterMut Pull)
    (layers : Slice Std.U32) (i_le : iter.i ≤ iter.slice.val.length)
    (back_ok : ∀ it', (back it').slice.val.length = it'.slice.val.length) :
    progress_loop iter back layers ⦃ r => r.slice.val.length = iter.slice.val.length ⦄ := by
  unfold progress_loop
  -- a loop returns because a number goes down at each turn, while the invariant (what the loop
  -- keeps true: where it is in what it walks) is kept
  apply loop.spec_decr_nat (fun p => p.1.slice.val.length - p.1.i)
    (fun p => p.1.slice = iter.slice ∧ p.1.i ≤ iter.slice.val.length ∧
      (∀ it', (p.2 it').slice.val.length = it'.slice.val.length))
  · rintro ⟨it, back1⟩ ⟨same, i_le, back_ok⟩
    dsimp only at same i_le back_ok
    unfold progress_loop.body
    simp only
    -- a turn: the next element is read, and when there is none the loop is over
    step as ⟨o, it1, next_back, same1, next_ok, ho⟩
    rcases ho with ⟨more, x, rfl, i1⟩ | ⟨done, rfl, i1⟩
    · simp only
      step*
      all_goals bookkeeping
    · simp only
      step*
  · exact ⟨rfl, i_le, back_ok⟩

/-- `progress` marks the pulls that lack one of the layers and keeps the tables as many. -/
@[step] theorem progress_returns (c : Core) (layers : Slice Std.U32) :
    progress c layers ⦃ r => r.pulls.val.length = c.pulls.val.length ∧ r.layers = c.layers ∧
      r.groups = c.groups ∧ r.starts = c.starts ⦄ := by
  unfold progress
  step*
  bookkeeping

/-- The loop of `succeeded` over the layers marks some of them stored and puts them back in as
many. -/
@[step] theorem succeeded_loop_returns (iter : core.slice.iter.IterMut Layer)
    (back : core.slice.iter.IterMut Layer → core.slice.iter.IterMut Layer) (p : Pull)
    (i_le : iter.i ≤ iter.slice.val.length)
    (back_ok : ∀ it', (back it').slice.val.length = it'.slice.val.length) :
    succeeded_loop iter back p ⦃ r => r.slice.val.length = iter.slice.val.length ⦄ := by
  unfold succeeded_loop
  -- a loop returns because a number goes down at each turn, while the invariant (what the loop
  -- keeps true: where it is in what it walks) is kept
  apply loop.spec_decr_nat (fun p => p.1.slice.val.length - p.1.i)
    (fun p => p.1.slice = iter.slice ∧ p.1.i ≤ iter.slice.val.length ∧
      (∀ it', (p.2 it').slice.val.length = it'.slice.val.length))
  · rintro ⟨it, back1⟩ ⟨same, i_le, back_ok⟩
    dsimp only at same i_le back_ok
    unfold succeeded_loop.body
    simp only
    -- a turn: the next element is read, and when there is none the loop is over
    step as ⟨o, it1, next_back, same1, next_ok, ho⟩
    rcases ho with ⟨more, x, rfl, i1⟩ | ⟨done, rfl, i1⟩
    · simp only
      step*
      all_goals bookkeeping
    · simp only
      step*
  · exact ⟨rfl, i_le, back_ok⟩

/-- `succeeded` ends the pull, or marks the progress of a work, and keeps the tables as few. -/
@[step] theorem succeeded_returns (on64 : OnA64BitMachine) (c : Core) (work : Work)
    (out : alloc.vec.Vec Action) (fit : Short c) (room : out.val.length + 6 * 2 ^ 25 ≤ 2 ^ 63) :
    succeeded c work out ⦃ c1 out1 => Short c1 ∧ c1.pulls.val.length ≤ c.pulls.val.length ∧
      out1.val.length ≤ out.val.length + 6 * 2 ^ 25 ⦄ := by
  have max_is := usize_max_is on64
  obtain ⟨pulls_fit, layers_fit, groups_fit, starts_fit⟩ := fit
  unfold succeeded
  -- one case for each kind of work: a pull (it may leave), a layer or a group (`progress`)
  cases work with
  | Pull pull =>
    simp only
    step as ⟨o, at_ok⟩
    rcases o with _ | at_
    · simp only
      step*
      bookkeeping
    · simp only
      have inside := at_ok at_ rfl
      step as ⟨p, p_post⟩
      split <;> try split
      all_goals step*
      all_goals settle
  | Layer layer =>
    simp only
    step as ⟨o, at_ok⟩
    rcases o with _ | l
    · simp only
      step*
      bookkeeping
    · simp only
      have inside := at_ok l rfl
      step*
      all_goals bookkeeping
  | Group group =>
    simp only
    step as ⟨o, at_ok⟩
    rcases o with _ | g
    · simp only
      step*
      bookkeeping
    · simp only
      have inside := at_ok g rfl
      step as ⟨g1, g1_post⟩
      split <;> step*
      all_goals bookkeeping

/-- The loop of `failed` over the pulls that wait for a work fails the try of each. -/
@[step] theorem failed_loop0_returns (on64 : OnA64BitMachine)
    (iter : alloc.vec.into_iter.IntoIter Std.U32)
    (c : Core) (now : Std.U64) (cl : Class) (out : alloc.vec.Vec Action) (fit : Short c)
    (room : out.val.length + iter.val.length * (6 * 2 ^ 25 + 3) ≤ 2 ^ 63) :
    failed_loop0 iter c now cl out ⦃ c1 out1 => Short c1 ∧
      c1.pulls.val.length ≤ c.pulls.val.length ∧
      out1.val.length ≤ out.val.length + iter.val.length * (6 * 2 ^ 25 + 3) ⦄ := by
  have max_is := usize_max_is on64
  unfold failed_loop0
  -- a loop returns because a number goes down at each turn, while the invariant (what the loop
  -- keeps true: the tables are short, there is room for what is left to push) is kept
  apply loop.spec_decr_nat (fun p => p.1.val.length)
    (fun p => Short p.2.1 ∧ p.2.1.pulls.val.length ≤ c.pulls.val.length ∧
      p.2.2.val.length + p.1.val.length * (6 * 2 ^ 25 + 3) ≤
        out.val.length + iter.val.length * (6 * 2 ^ 25 + 3))
  · rintro ⟨it, c1, acc⟩ ⟨fit1, same_len, room1⟩
    dsimp only at fit1 same_len room1
    unfold failed_loop0.body
    simp only
    -- a turn: the next element is read, and when there is none the loop is over
    step as ⟨o, it1, ho⟩
    rcases ho with ⟨empty, rfl, rfl⟩ | ⟨x, l, split, rfl, done_l⟩
    · simp only
      step*
    · simp only
      step as ⟨o1, at_ok⟩
      rcases o1 with _ | at_
      · simp only
        step*
      · simp only
        have inside := at_ok at_ rfl
        step*
  · exact ⟨fit, le_refl _, by dsimp only; omega⟩

/-- The loop of `failed` over the pulls that wait for a work fails the try of each. -/
@[step] theorem failed_loop1_returns (on64 : OnA64BitMachine)
    (iter : alloc.vec.into_iter.IntoIter Std.U32)
    (c : Core) (now : Std.U64) (cl : Class) (out : alloc.vec.Vec Action) (fit : Short c)
    (room : out.val.length + iter.val.length * (6 * 2 ^ 25 + 3) ≤ 2 ^ 63) :
    failed_loop1 iter c now cl out ⦃ c1 out1 => Short c1 ∧
      c1.pulls.val.length ≤ c.pulls.val.length ∧
      out1.val.length ≤ out.val.length + iter.val.length * (6 * 2 ^ 25 + 3) ⦄ := by
  -- Aeneas writes this loop of `failed` three times (`failed_loop0` to `failed_loop2`), as
  -- the same function
  rw [show failed_loop1 = failed_loop0 from rfl]
  exact failed_loop0_returns on64 iter c now cl out fit room

/-- The loop of `failed` over the pulls that wait for a work fails the try of each. -/
@[step] theorem failed_loop2_returns (on64 : OnA64BitMachine)
    (iter : alloc.vec.into_iter.IntoIter Std.U32)
    (c : Core) (now : Std.U64) (cl : Class) (out : alloc.vec.Vec Action) (fit : Short c)
    (room : out.val.length + iter.val.length * (6 * 2 ^ 25 + 3) ≤ 2 ^ 63) :
    failed_loop2 iter c now cl out ⦃ c1 out1 => Short c1 ∧
      c1.pulls.val.length ≤ c.pulls.val.length ∧
      out1.val.length ≤ out.val.length + iter.val.length * (6 * 2 ^ 25 + 3) ⦄ := by
  -- Aeneas writes this loop of `failed` three times (`failed_loop0` to `failed_loop2`), as
  -- the same function
  rw [show failed_loop2 = failed_loop0 from rfl]
  exact failed_loop0_returns on64 iter c now cl out fit room

/-- `failed` fails the tries of the pulls that wait for a work. -/
@[step] theorem failed_returns (on64 : OnA64BitMachine) (c : Core) (now : Std.U64) (work : Work)
    (cl : Class)
    (out : alloc.vec.Vec Action) (fit : Short c)
    (room : out.val.length + (2 ^ 25 * (6 * 2 ^ 25 + 3) + 6 * 2 ^ 25) ≤ 2 ^ 63) :
    failed c now work cl out ⦃ c1 out1 => Short c1 ∧ c1.pulls.val.length ≤ c.pulls.val.length ∧
      out1.val.length ≤ out.val.length + (2 ^ 25 * (6 * 2 ^ 25 + 3) + 6 * 2 ^ 25) ⦄ := by
  have max_is := usize_max_is on64
  obtain ⟨pulls_fit, layers_fit, groups_fit, starts_fit⟩ := fit
  unfold failed
  -- one case for each kind of work: the pulls that wait for it fail their try, one by one
  cases work with
  | Pull pull =>
    simp only
    step as ⟨o, at_ok⟩
    rcases o with _ | at_
    · simp only
      step*
      bookkeeping
    · simp only
      have inside := at_ok at_ rfl
      step as ⟨p, p_post⟩
      split <;> step*
      all_goals settle
  | Layer layer =>
    simp only
    step as ⟨o, at_ok⟩
    rcases o with _ | l
    · simp only
      step*
      bookkeeping
    · simp only
      have inside := at_ok l rfl
      step*
      all_goals bookkeeping
  | Group group =>
    simp only
    step as ⟨o, at_ok⟩
    rcases o with _ | g
    · simp only
      step*
      bookkeeping
    · simp only
      have inside := at_ok g rfl
      step as ⟨g1, g1_post⟩
      split <;> simp only [bind_ok, Bool.false_eq_true, ↓reduceIte] <;> step* <;> bookkeeping

end LazyCore
