-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: a call that returns what a claim says is `ok x` for such an `x`.
-- Why it is needed: some proofs need the value a function returned, not only its claim.
-- Read before this file: nothing.
-- Notation: `f x ⦃ r => P r ⦄` is "the Rust `f` returns on `x`, with no panic and no endless loop,
--    and its answer `r` satisfies `P`"; `step` goes through one line of the Rust function and
--    `scalar_tac` proves a fact about machine numbers by arithmetic; `↑x` is the number a
--    machine integer is.
import Aeneas
open Aeneas Aeneas.Std Aeneas.Data.Coinductive Result

unseal Result
attribute [local implicit_reducible] Result

namespace UserCore

/-- A call that returns what a claim says returns something: the call is `ok x` for an `x` that
satisfies the claim. -/
theorem spec_ok_eq {α : Type} {m : Result α} {P : α → Prop} (h : m ⦃ r => P r ⦄) :
    ∃ x, m = ok x ∧ P x := by
  cases m using ITree.cases with
  | ret x => exact ⟨x, rfl, (WP.spec_ok x).mp h⟩
  | vis e k => exact ((WP.spec_vis e k).mp h).elim
  | div => exact (WP.spec_div.mp h).elim

end UserCore
