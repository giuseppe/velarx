-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: `step_returns`, that `step` of crates/lazy-core returns.  `step` is a
-- `match` on the event: one case for each, each a call of a function of the files before this
-- one, then `advance`.  The proof follows the `match`; what is not a call (the boost of
-- `Hurry`, the record of a start of a container, the loop and the `Wake` of a `Tick`) is
-- followed line by line.
--
-- Why it is needed: it is the whole of the claim.  `Returns.lean` puts it in the words of Spec.lean
-- (`AStepAlwaysReturns`).  What it asks is the hypotheses of Spec.lean: the tables of the core are
-- short (`Short`), the event leaves room (`Roomy`), the list of actions is not huge, and the
-- machine
-- has 64-bit words.  What it says is that `step` returns, a short core, and no more than `2^54`
-- actions pushed.
--
-- Read before this file: Spec.lean, and the files named `Returns...` before it in `Theorems.lean`.
--
-- The tactics a reader meets in the proofs.  `step*` follows the Rust function line by line: for
-- each call it uses the lemma of this development that says when the call returns and what it
-- gives (the lemmas marked `@[step]`), and leaves what is to be shown (that a `Vec` has room, that
-- an index is inside) as goals.  `step as ⟨x, hx⟩` does one line and names the result `x` and what
-- is known of it `hx`.  `loop.spec_decr_nat` proves that a loop returns because a number goes down
-- at each turn (here, the elements left to read) while a fact (the invariant) is kept.
-- `bookkeeping` (ReturnsBasics.lean) closes the goals that are only sums of lengths.
--
-- Notation: as in ReturnsLeaving.lean.
import LazyCore.ReturnsCancelAndTick
import LazyCore.ReturnsDone
import LazyCore.ReturnsPreparedAndStarts
import LazyCore.ReturnsAdvance

open Aeneas Aeneas.Std Result velarx_lazy_core
open Aeneas.Data.Coinductive

namespace LazyCore

/-- Closes the bookkeeping goals of `step_returns`. -/
macro "step_bookkeeping" : tactic =>
  `(tactic| first
    | omega
    | (simp only [Short, vec_set_val_length] at *; omega)
    | (simp_all [Short] <;> omega))

/-- **`step` returns.**  Whatever the event, if the tables of the core are short and the event
leaves room in them, `step` returns, the tables of the core it leaves are short, and no more than
`2^54` actions are pushed. -/
theorem step_returns (on64 : OnA64BitMachine) (c : Core) (now : Std.U64) (ev : Event)
    (out : alloc.vec.Vec Action) (fit : Short c) (room_ev : Roomy c ev)
    (room : out.val.length + 2 ^ 54 ≤ 2 ^ 63) :
    step c now ev out ⦃ c1 out1 => Short c1 ∧ out1.val.length ≤ out.val.length + 2 ^ 54 ⦄ := by
  have max_is := usize_max_is on64
  obtain ⟨pulls_fit, layers_fit, groups_fit, starts_fit⟩ := fit
  unfold step
  cases ev with
  | Added pull containers =>
    -- `add` finds room for the pull, then `advance` goes on
    simp only
    simp only [Roomy] at room_ev
    step*
    step_bookkeeping
  | Hurry pull =>
    -- the pull is looked up: a number the core does not hold changes nothing
    simp only
    step as ⟨o, at_ok⟩
    rcases o with _ | at_
    · simp only
      step*
      step_bookkeeping
    · -- the pull is held: it is boosted, and begins its try if it is queued or waits
      simp only
      have inside := at_ok at_ rfl
      step*
      all_goals try step_bookkeeping
      cases hph : p1.phase <;> simp only [bind_ok, Bool.false_eq_true, ↓reduceIte] <;> step* <;>
        step_bookkeeping
  | Cancel pull =>
    -- `cancel`, then `advance`
    simp only
    step*
    step_bookkeeping
  | Prepared pull layers groups =>
    -- `prepared` finds room for the layers and the groups, then `advance`
    simp only
    simp only [Roomy] at room_ev
    step*
    step_bookkeeping
  | Done work r =>
    -- `succeeded` or `failed`, then `advance`
    simp only
    cases r with
    | Ok done =>
      simp only
      step*
      step_bookkeeping
    | Err cl =>
      simp only
      step*
      step_bookkeeping
  | StartBegan layer =>
    -- the record of the starts in the layer is made if there is none (room for one more)
    simp only
    simp only [Roomy] at room_ev
    step*
    step_bookkeeping
  | StartEnded layer =>
    simp only
    simp only [Roomy] at room_ev
    step*
    step_bookkeeping
  | Tick =>
    -- the loop over the pulls begins the try of those whose wait is over, `advance` goes on, and
    -- the time of the next try is asked for
    simp only
    step*
    step_bookkeeping

end LazyCore
