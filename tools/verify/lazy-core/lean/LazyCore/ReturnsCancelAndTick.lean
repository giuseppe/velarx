-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: that `cancel` (with its loop) and the loop of a `Tick` over the pulls
-- (`step_loop`) return.  A cancel ends a pull that waits, or stops one that runs and makes the
-- pulls
-- that shared a layer with it prepare again (one `let_go` and one `begin_try` for each of them);
-- a `Tick` begins the try of each pull whose wait is over.
--
-- Why it is needed: they are two of the events of `step`, and the ones whose cost is not linear
-- in the tables: a cancel can ask for the stop of the layers and the groups of as many pulls as
-- there are (at most 2^25), so the number of actions it pushes is bounded by a product, still far
-- below the room a list of actions has (`2^63`).
--
-- Read before this file: Spec.lean, ReturnsQueries.lean, ReturnsLeaving.lean, and in lib.rs
-- `cancel` and the `Tick` arm of `step`.
--
-- The tactics a reader meets in the proofs.  `step*` follows the Rust function line by line: for
-- each call it uses the lemma of this development that says when the call returns and what it
-- gives (the lemmas marked `@[step]`), and leaves what is to be shown (that a `Vec` has room, that
-- an index is inside) as goals.  `step as ⟨x, hx⟩` does one line and names the result `x` and what
-- is known of it `hx`.  `loop.spec_decr_nat` proves that a loop returns because a number goes down
-- at each turn (here, the elements left to read) while a fact (the invariant) is kept.
-- `bookkeeping` (ReturnsBasics.lean) closes the goals that are only sums of lengths.
--
-- Notation: as in ReturnsLeaving.lean; `iter.val.length` is the number of names left in the list
-- a loop goes over, `iter.start` and `iter.end` the places a `for at in 0..len` goes from and to.
import LazyCore.ReturnsLeaving

open Aeneas Aeneas.Std Result velarx_lazy_core
open Aeneas.Data.Coinductive

namespace LazyCore

/-- The loop of `cancel` makes the pulls that shared a layer with the cancelled one plan again. -/
@[step] theorem cancel_loop_returns (on64 : OnA64BitMachine)
    (iter : alloc.vec.into_iter.IntoIter Std.U32)
    (c : Core) (out : alloc.vec.Vec Action) (fit : Short c)
    (room : out.val.length + iter.val.length * (4 * 2 ^ 25 + 2) ≤ 2 ^ 63) :
    cancel_loop iter c out ⦃ c1 out1 => Short c1 ∧ c1.pulls.val.length ≤ c.pulls.val.length ∧
      out1.val.length ≤ out.val.length + iter.val.length * (4 * 2 ^ 25 + 2) ⦄ := by
  have max_is := usize_max_is on64
  unfold cancel_loop
  -- a loop returns because a number goes down at each turn, while the invariant (what the loop
  -- keeps true: the tables are short, there is room for what is left to push) is kept
  apply loop.spec_decr_nat (fun p => p.1.val.length)
    (fun p => Short p.2.1 ∧ p.2.1.pulls.val.length ≤ c.pulls.val.length ∧
      p.2.2.val.length + p.1.val.length * (4 * 2 ^ 25 + 2) ≤
        out.val.length + iter.val.length * (4 * 2 ^ 25 + 2))
  · rintro ⟨it, c1, acc⟩ ⟨fit1, same_len, room1⟩
    dsimp only at fit1 same_len room1
    unfold cancel_loop.body
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
        bookkeeping
  · exact ⟨fit, le_refl _, by dsimp only; omega⟩

/-- `cancel` ends the pull, or stops it and makes the pulls that shared a layer with it plan again.
-/
@[step] theorem cancel_returns (on64 : OnA64BitMachine) (c : Core) (pull : Std.U32)
    (out : alloc.vec.Vec Action) (fit : Short c)
    (room : out.val.length + (2 ^ 25 * (4 * 2 ^ 25 + 2) + 6 * 2 ^ 25 + 1) ≤ 2 ^ 63) :
    cancel c pull out ⦃ c1 out1 => Short c1 ∧ c1.pulls.val.length ≤ c.pulls.val.length ∧
      out1.val.length ≤ out.val.length + (2 ^ 25 * (4 * 2 ^ 25 + 2) + 6 * 2 ^ 25 + 1) ⦄ := by
  have max_is := usize_max_is on64
  obtain ⟨pulls_fit, layers_fit, groups_fit, starts_fit⟩ := fit
  unfold cancel
  -- the pull is looked up; if it is queued or waits it leaves; if it runs it is stopped
  -- (`let_go`, then `Abort`), and the pulls that shared a layer with it begin again
  step as ⟨o, at_ok⟩
  rcases o with _ | at_
  · simp only
    step*
    bookkeeping
  · simp only
    have inside := at_ok at_ rfl
    step as ⟨p, p_post⟩
    split <;> step* <;> bookkeeping

/-- The loop of a `Tick` over the pulls begins the try of each pull whose wait is over. -/
@[step] theorem step_loop_returns (on64 : OnA64BitMachine) (iter : core.ops.range.Range Std.Usize)
    (c : Core) (now : Std.U64) (out : alloc.vec.Vec Action) (fit : Short c)
    (start_le : iter.start.val ≤ iter.end.val) (end_le : iter.end.val ≤ c.pulls.val.length)
    (room : out.val.length + 2 * (iter.end.val - iter.start.val) ≤ 2 ^ 63) :
    step_loop iter c now out ⦃ c1 out1 => Short c1 ∧ c1.pulls.val.length = c.pulls.val.length ∧
      out1.val.length ≤ out.val.length + 2 * (iter.end.val - iter.start.val) ⦄ := by
  have max_is := usize_max_is on64
  unfold step_loop
  -- a loop returns because a number goes down at each turn, while the invariant (what the loop
  -- keeps true: the tables are short, there is room for what is left to push) is kept
  apply loop.spec_decr_nat (fun p => p.1.end.val - p.1.start.val)
    (fun p => p.1.end.val = iter.end.val ∧ p.1.start.val ≤ p.1.end.val ∧ Short p.2.1 ∧
      p.2.1.pulls.val.length = c.pulls.val.length ∧
      p.2.2.val.length + 2 * (iter.end.val - p.1.start.val) ≤
        out.val.length + 2 * (iter.end.val - iter.start.val))
  · rintro ⟨it, c1, acc⟩ ⟨same_end, start_le, fit1, same_len, room⟩
    dsimp only at same_end start_le fit1 same_len room
    unfold step_loop.body
    simp only
    -- a turn: the next element is read, and when there is none the loop is over
    step as ⟨o, it1, ho, same_end1⟩
    have same_end1 : it1.end.val = it.end.val := by rw [same_end1]
    by_cases lt : it.start.val < it.end.val
    · simp only [lt, ↓reduceIte] at ho
      obtain ⟨rfl, i1⟩ := ho
      simp only
      step as ⟨p, p_post⟩
      split <;> step* <;> bookkeeping
    · simp only [lt, ↓reduceIte] at ho
      obtain ⟨rfl, _⟩ := ho
      simp only
      step*
  · exact ⟨rfl, start_le, fit, rfl, by dsimp only; omega⟩

end LazyCore
