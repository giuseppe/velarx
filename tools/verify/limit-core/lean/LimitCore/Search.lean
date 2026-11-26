-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: the proof that `shares_of_weight`, a binary search, ends and answers as the claim says.
-- Why it is needed: a loop must be shown to end (the measure is the size of the interval) and to keep its bounds.
-- Read before this file: Sandbox.lean.
-- Notation: `f x ⦃ r => P r ⦄` is "the Rust `f` returns on `x`, with no panic and no endless loop,
--    and its answer `r` satisfies `P`"; `step` goes through one line of the Rust function and
--    `scalar_tac` proves a fact about machine numbers by arithmetic; `↑x` (or `x.val`) is the number
--    a machine integer is.
import LimitCore.Sandbox
open Aeneas Aeneas.Std Aeneas.Data.Coinductive Result velarx_limit_core
namespace LimitCore

/-- A call of `weight_of_shares` that returns is `ok` of what it answers. -/
theorem weight_of_shares_eq (n : Std.U64) : weight_of_shares n ⦃ w => weight_of_shares n = ok w ⦄ := by
  obtain ⟨w, hw, _⟩ := spec_ok_eq (weight_of_shares_returns n)
  rw [hw]; simp only [WP.spec_ok]

/-- The weight of `mid` shares reaches `weight`, as a statement that the call returns it. -/
def Reaches (weight : Std.U64) (n : Std.U64) : Prop :=
  weight_of_shares n ⦃ w => weight.val ≤ w.val ⦄

/-- The binary search of `shares_of_weight`: it ends (the interval gets smaller), keeps 2 to 262144, and the end it stops on is 262144 or reaches the weight asked. -/
theorem shares_of_weight_loop_spec (weight low high : Std.U64)
    (h : 2 ≤ low.val ∧ low.val ≤ high.val ∧ high.val ≤ 262144 ∧
      (high.val = 262144 ∨ Reaches weight high)) :
    shares_of_weight_loop weight low high ⦃ r =>
      2 ≤ r.val ∧ r.val ≤ 262144 ∧ (r.val = 262144 ∨ Reaches weight r) ⦄ := by
  unfold shares_of_weight_loop
  apply loop.spec_decr_nat (fun (q : Std.U64 × Std.U64) => q.2.val - q.1.val)
    (fun (q : Std.U64 × Std.U64) => 2 ≤ q.1.val ∧ q.1.val ≤ q.2.val ∧ q.2.val ≤ 262144 ∧
      (q.2.val = 262144 ∨ Reaches weight q.2))
    (fun r => 2 ≤ r.val ∧ r.val ≤ 262144 ∧ (r.val = 262144 ∨ Reaches weight r))
  · rintro ⟨low1, high1⟩ ⟨h1, h2, h3, h4⟩
    simp only at h1 h2 h3 h4 ⊢
    unfold shares_of_weight_loop.body
    -- the middle of the interval is below the end, so the interval gets smaller whichever half is kept
    split
    · step as ⟨d, hd⟩
      step as ⟨d2, hd2⟩
      step as ⟨mid, hmid⟩
      step with weight_of_shares_eq as ⟨w, hw⟩
      split
      · simp only [WP.spec_ok]
        and_intros <;> first | scalar_tac |
          (right; unfold Reaches; rw [hw]; simp only [WP.spec_ok]; scalar_tac)
      · step as ⟨low2, hlow2⟩
        refine ⟨by scalar_tac, by scalar_tac, by scalar_tac, h4, by scalar_tac⟩
    · simp only [WP.spec_ok]
      refine ⟨by scalar_tac, by scalar_tac, ?_⟩
      have e : low1 = high1 := by scalar_tac
      subst e; exact h4
  · exact h

/-- Proof of `TheSharesOfWeight`: 0 is 0, any other weight is searched in 2 to 262144. -/
theorem shares_of_weight_post (weight : Std.U64) : shares_of_weight weight ⦃ r =>
    (weight.val = 0 → r.val = 0) ∧
    (0 < weight.val → 2 ≤ r.val ∧ r.val ≤ 262144 ∧
      (r.val = 262144 ∨ weight_of_shares r ⦃ w => weight.val ≤ w.val ⦄)) ⦄ := by
  unfold shares_of_weight
  split
  · simp only [WP.spec_ok]; scalar_tac
  · simp only [MIN_SHARES, MAX_SHARES]
    refine WP.spec_mono (shares_of_weight_loop_spec weight 2#u64 262144#u64 ?_) ?_
    · exact ⟨by scalar_tac, by scalar_tac, by scalar_tac, Or.inl rfl⟩
    · intro r hr
      exact ⟨fun h => by scalar_tac, fun _ => hr⟩

end LimitCore
