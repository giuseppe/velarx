-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: what `take` and `Span::end` answer.
-- Why it is needed: the readers cut the data into spans with `take`, which checks the length
-- against the end of the data; every claim that a span lies inside the data comes from the theorem
-- of this file.
-- Read before this file: BigEndian.lean.
-- Notation: as in BigEndian.lean.
import SigparseCore.Spec
open Aeneas Aeneas.Std Result velarx_sigparse_core
namespace SigparseCore

/-- The end of a span that lies in a slice is where its bytes stop: `Span::end`, with no overflow.
-/
theorem span_end_is_the_sum (span : Span) (fits : span.off.val + span.len.val ≤ Usize.max) :
    Span.end span ⦃ r => r.val = span.off.val + span.len.val ⦄ := by
  unfold Span.end
  step as ⟨ r, hr ⟩
  exact hr

/-- `take` gives the span of the `len` bytes at `at_` when they are all there: it returns, and its
answer is that span, or a refusal because the input ends before it. -/
theorem take_gives_the_span (data : Slice Std.U8) (at_ len : Std.Usize) :
    take data at_ len ⦃ r =>
      (∀ s, r = core.result.Result.Ok s →
        s.off = at_ ∧ s.len = len ∧ at_.val + len.val ≤ data.val.length) ∧
      (∀ e, r = core.result.Result.Err e → data.val.length < at_.val + len.val) ⦄ := by
  unfold take
  dsimp only [Slice.len]
  split
  · rename_i past
    simp only [WP.spec_ok, reduceCtorEq, false_implies, implies_true, true_and]
    intro e _
    scalar_tac
  · step as ⟨ room, hroom ⟩
    split
    · rename_i short
      simp only [WP.spec_ok, reduceCtorEq, false_implies, implies_true, true_and]
      intro e _
      scalar_tac
    · rename_i fits
      simp only [WP.spec_ok, reduceCtorEq, false_implies, implies_true, and_true]
      intro s same
      cases same
      exact ⟨rfl, rfl, by scalar_tac⟩

end SigparseCore
