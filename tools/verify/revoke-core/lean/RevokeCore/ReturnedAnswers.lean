-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: that a Rust function that is known to return an answer with a property
-- (`f x ⦃ r => P r ⦄`) does return some answer, and that the answer has the property.
-- Why it is needed: the claims of Spec.lean about `adopt` are written "if `adopt` answers `r`,
-- then ..." (`adopt held parts = ok r`); the proofs know that it returns and what the answer is
-- like, and this turns one into the other.
-- Read before this file: nothing.
-- Notation: `f x ⦃ r => P r ⦄` reads: `f x` returns, and its answer `r` satisfies `P r`;
-- `f x = ok r` reads: `f x` returns `r`.
import Aeneas

open Aeneas Aeneas.Std Result Aeneas.Data.Coinductive

unseal Result
attribute [local implicit_reducible] Result

namespace RevokeCore

/-- A call that returns with an answer that has a property has an answer that has it. -/
theorem returned_answer {α : Type} {m : Result α} {P : α → Prop} (returns : m ⦃ r => P r ⦄) :
    ∃ x, m = Result.ok x ∧ P x := by
  cases m using ITree.cases with
  | ret x => exact ⟨x, rfl, (WP.spec_ok x).mp returns⟩
  | vis e k => exact ((WP.spec_vis e k).mp returns).elim
  | div => exact (WP.spec_div.mp returns).elim

/-- A call that is known to return `x` returns an answer that has a property when `x` has it. -/
theorem answer_has {α : Type} {m : Result α} {P : α → Prop} {x : α} (returns : m ⦃ r => P r ⦄)
    (is_x : m = Result.ok x) : P x := by
  obtain ⟨y, is_y, answer⟩ := returned_answer returns
  rw [is_x] at is_y
  have same : x = y := by simpa using is_y
  rw [same]
  exact answer

end RevokeCore
