-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: the proofs of the claims about the functions that have no loop and no arithmetic of two numbers: `weight_of_shares`, `shares_ok`, `limit_of`.
-- Why it is needed: the other files use them, and they show the way every proof of this crate goes: unfold the Rust function, step through its lines, and let `scalar_tac` do the arithmetic on machine integers.
-- Read before this file: Spec.lean.
-- Notation: `f x ⦃ r => P r ⦄` is "the Rust `f` returns on `x`, with no panic and no endless loop,
--    and its answer `r` satisfies `P`"; `step` goes through one line of the Rust function and
--    `scalar_tac` proves a fact about machine numbers by arithmetic; `↑x` (or `x.val`) is the number
--    a machine integer is.
import LimitCore.Spec
open Aeneas Aeneas.Std Result velarx_limit_core
namespace LimitCore

/-- `float::weight` returns (the model of Models.lean says no more). -/
theorem float_weight_spec (s : Std.U64) : float.weight s ⦃ _ => True ⦄ := by
  unfold float.weight; simp [WP.spec_ok]

/-- Proof of `TheWeightOfShares`: the branches of `weight_of_shares` are the ends, or the clamp of the float answer. -/
theorem weight_of_shares_spec : TheWeightOfShares := by
  intro shares
  unfold weight_of_shares
  simp only [MIN_SHARES, MAX_SHARES, MAX_WEIGHT]
  step*
  step with float_weight_spec as ⟨w⟩
  step*
  scalar_tac

/-- `weight_of_shares` returns, which the claim about its answer says. -/
theorem weight_of_shares_returns (shares : Std.U64) : weight_of_shares shares ⦃ _ => True ⦄ :=
  WP.spec_mono (weight_of_shares_spec shares) (fun _ _ => trivial)

/-- Proof of `TheSharesAreChecked`: the comparisons of `shares_ok` read as written. -/
theorem shares_ok_spec : TheSharesAreChecked := by
  intro shares
  unfold shares_ok
  simp only [MIN_SHARES, MAX_SHARES]
  step*

/-- Proof of `TheLimitOfARequest`: each branch of `limit_of` is a line of `LimitIs`; a positive number keeps its value as a `u64`. -/
theorem limit_of_spec : TheLimitOfARequest := by
  intro v
  unfold limit_of
  step*
  all_goals (unfold LimitIs; split_ifs <;> try scalar_tac)
  exact ⟨i, rfl, by simp only [i_post]; scalar_tac⟩
end LimitCore
