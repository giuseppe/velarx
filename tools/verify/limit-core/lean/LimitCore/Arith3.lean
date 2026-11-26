-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: the proofs about `quota_per_sec` and `oom_score_adj`.
-- Why it is needed: a quota of a second is made in 128 bits and cut at the top of `u64`; a score keeps its value.
-- Read before this file: Arith2.lean.
-- Notation: `f x ⦃ r => P r ⦄` is "the Rust `f` returns on `x`, with no panic and no endless loop,
--    and its answer `r` satisfies `P`"; `step` goes through one line of the Rust function and
--    `scalar_tac` proves a fact about machine numbers by arithmetic; `↑x` (or `x.val`) is the number
--    a machine integer is.
import LimitCore.Arith2
open Aeneas Aeneas.Std Aeneas.Data.Coinductive Result velarx_limit_core
namespace LimitCore

/-- `quota_per_sec` is the quotient of the 128-bit product, cut at 2^64 - 1; for the quotas and periods `cpu_max` takes the quotient is below 2^64 and is not cut. -/
theorem quota_per_sec_post (quota period : Std.U64) : quota_per_sec quota period ⦃ r =>
    r.val = min (quota.val * 1000000 / PeriodOf period.val) (2 ^ 64 - 1) ∧
    (1000 ≤ quota.val → quota.val ≤ MaxQuota →
      (period.val = 0 ∨ (1000 ≤ period.val ∧ period.val ≤ 1000000)) →
      r.val = quota.val * 1000000 / PeriodOf period.val) ⦄ := by
  unfold quota_per_sec
  obtain ⟨p1, hp1, hv⟩ := period_norm period
  have hpos : 1 ≤ p1.val := by unfold PeriodOf at hv; split_ifs at hv <;> scalar_tac
  simp only [hp1]
  step*
  all_goals
    have hq : (i.val : Nat) = quota.val := by simp only [i_post]; scalar_tac
    have hi2 : i2.val = p1.val := by simp only [i2_post]; scalar_tac
    have hn : n.val = quota.val * 1000000 / p1.val := by
      rw [n_post, i1_post, hi2, hq]
    rw [← hv]
    -- the product is made in 128 bits; it is cut at `u64::MAX`, and not for a quota that `cpu_max` takes
    have hmax : (core.num.U64.MAX).val = 2 ^ 64 - 1 := by rfl
    have hi3 : i3.val = 2 ^ 64 - 1 := by
      rw [i3_post, UScalar.cast_val_eq, hmax]; rfl
    have h1000 : 1000 ≤ quota.val → quota.val ≤ MaxQuota →
        (period.val = 0 ∨ (1000 ≤ period.val ∧ period.val ≤ 1000000)) →
        quota.val * 1000000 / p1.val < 2 ^ 64 - 1 := by
      intro a b c
      unfold MaxQuota at b
      have hp1000 : 1000 ≤ p1.val := by
        unfold PeriodOf at hv; split_ifs at hv <;> omega
      have := Nat.div_le_div_left (a := quota.val * 1000000) hp1000 (by omega)
      omega
    first
      | (have hgt : 2 ^ 64 - 1 < n.val := by scalar_tac
         rw [hmax]
         refine ⟨(min_eq_right (by omega)).symm, fun a b c => ?_⟩
         have := h1000 a b c
         omega)
      | (have hle : n.val ≤ 2 ^ 64 - 1 := by scalar_tac
         have hc : (UScalar.cast UScalarTy.U64 n).val = n.val := by
           rw [UScalar.cast_val_eq]
           exact Nat.mod_eq_of_lt (by simp [UScalarTy.numBits]; omega)
         rw [hc]
         exact ⟨by rw [hn]; exact (min_eq_left (by omega)).symm, fun _ _ _ => by omega⟩)

/-- `oom_score_adj` keeps a number of -1000 to 1000 (the `as i32` is exact there) and refuses the others. -/
theorem oom_post (v : Std.I64) : oom_score_adj v ⦃ r =>
    (-1000 ≤ v.val → v.val ≤ 1000 → ∃ s : Std.I32, r = some s ∧ s.val = v.val) ∧
    ((v.val < -1000 ∨ 1000 < v.val) → r = none) ⦄ := by
  unfold oom_score_adj
  step*
  refine ⟨fun _ _ => ⟨i, rfl, ?_⟩, fun h => by exfalso; scalar_tac⟩
  have hb : (((2 ^ min IScalarTy.I32.numBits IScalarTy.I64.numBits : Nat)) : Int) = 2 ^ 32 := by rfl
  rw [i_post, IScalar.cast_val_eq, Int.bmod_def, hb]
  split_ifs <;> omega

end LimitCore
