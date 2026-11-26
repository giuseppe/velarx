-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: the proofs about the sums of a pod's sandbox: `with_overhead`, `sandbox_shares`, `sandbox_swap`, `sandbox_quota`, `sandbox_period`.
-- Why it is needed: a sum of limits must not wrap into a smaller one.
-- Read before this file: Arith3.lean.
-- Notation: `f x ⦃ r => P r ⦄` is "the Rust `f` returns on `x`, with no panic and no endless loop,
--    and its answer `r` satisfies `P`"; `step` goes through one line of the Rust function and
--    `scalar_tac` proves a fact about machine numbers by arithmetic; `↑x` (or `x.val`) is the number
--    a machine integer is.
import LimitCore.Arith3
open Aeneas Aeneas.Std Aeneas.Data.Coinductive Result velarx_limit_core
namespace LimitCore

/-- `i64::saturating_add`: the sum, held between the two ends of `i64`. -/
theorem saturating_add_val (a b : Std.I64) :
    (core.num.I64.saturating_add a b).val = max (-(2 ^ 63)) (min (2 ^ 63 - 1) (a.val + b.val)) := by
  have ha := a.hBounds
  have hb := b.hBounds
  simp only [core.num.I64.saturating_add, IScalar.saturating_add, IScalar.val, BitVec.toInt_ofInt]
  simp only [IScalar.min, IScalar.max, IScalarTy.numBits] at *
  norm_num at *
  rw [Int.bmod_eq_of_le] <;> omega

/-- `with_overhead` is `WithOverhead`, never below `r` for a set limit, and `r` itself for a limit that is not set: `saturating_add` is the sum cut at both ends of `i64`. -/
theorem with_overhead_post (r o : Std.I64) : with_overhead r o ⦃ x =>
    x.val = WithOverhead r.val o.val ∧ (0 < r.val → r.val ≤ x.val) ∧ (r.val ≤ 0 → x.val = r.val) ⦄ := by
  unfold with_overhead
  split
  · split
    · step*
      rw [saturating_add_val]; unfold WithOverhead MaxI64
      refine ⟨?_, ?_, ?_⟩ <;> scalar_tac
    · step*
      rw [saturating_add_val]; unfold WithOverhead MaxI64
      refine ⟨?_, ?_, ?_⟩ <;> scalar_tac
  · simp only [WP.spec_ok]; unfold WithOverhead; split_ifs <;> scalar_tac

attribute [local step] with_overhead_post

/-- `sandbox_shares` is `WithOverhead` cut at 262144. -/
theorem sandbox_shares_post (r o : Std.I64) : sandbox_shares r o ⦃ x =>
    x.val = min (WithOverhead r.val o.val) 262144 ⦄ := by
  unfold sandbox_shares
  simp only [MAX_SHARES]
  step*

/-- `sandbox_swap` is `WithOverhead` of the greater overhead. -/
theorem sandbox_swap_post (rs os om : Std.I64) : sandbox_swap rs os om ⦃ x =>
    x.val = WithOverhead rs.val (max os.val om.val) ⦄ := by
  unfold sandbox_swap
  split
  · step*; rw [x_post]; congr 1; scalar_tac
  · step*; rw [x_post]; congr 1; scalar_tac

/-- `sandbox_period` is the containers' period when it is positive, else the overhead's. -/
theorem sandbox_period_post (rp op : Std.I64) : sandbox_period rp op ⦃ x =>
    x.val = if 0 < rp.val then rp.val else op.val ⦄ := by
  unfold sandbox_period
  split <;> simp only [WP.spec_ok] <;> split_ifs <;> scalar_tac

/-- A number of `i64` keeps its value in `i128`. -/
theorem cast_i128_val (x : Std.I64) : (IScalar.cast IScalarTy.I128 x).val = x.val := by
  have h := x.hBounds
  have hb : (((2 ^ min IScalarTy.I128.numBits IScalarTy.I64.numBits : Nat)) : Int) = 2 ^ 64 := by rfl
  rw [IScalar.cast_val_eq, Int.bmod_def, hb]
  simp only [IScalarTy.numBits] at h
  split_ifs <;> omega

/-- A number of `i128` that fits `i64` keeps its value in `i64`. -/
theorem cast_i64_val (x : Std.I128) (h : -(2 ^ 63) ≤ x.val ∧ x.val < 2 ^ 63) :
    (IScalar.cast IScalarTy.I64 x).val = x.val := by
  have hb : (((2 ^ min IScalarTy.I64.numBits IScalarTy.I128.numBits : Nat)) : Int) = 2 ^ 64 := by rfl
  rw [IScalar.cast_val_eq, Int.bmod_def, hb]
  split_ifs <;> omega

/-- Division that rounds toward zero is the usual division on a number that is not negative. -/
theorem tdiv_nonneg (a b : Int) (ha : 0 ≤ a) : a.tdiv b = a / b := by
  rw [Int.tdiv_eq_ediv]; simp [ha]

/-- The product of two positive numbers below 2^63 is positive and at most 2^126. -/
theorem mul_bounds (a b : Int) (ha : 0 < a) (ha' : a < 2 ^ 63) (hb : 0 < b) (hb' : b < 2 ^ 63) :
    0 < a * b ∧ a * b ≤ 2 ^ 126 := by
  refine ⟨Int.mul_pos ha hb, ?_⟩
  calc a * b ≤ 2 ^ 63 * 2 ^ 63 := Int.mul_le_mul ha'.le hb'.le (by omega) (by omega)
    _ = 2 ^ 126 := by norm_num

/-- `sandbox_quota` is `SandboxQuotaOf`: the product of two `i64` fits 126 bits of the `i128` it is made in, the divisor is positive, and the sum is made only when it fits. -/
theorem sandbox_quota_post (r rp o op : Std.I64) : sandbox_quota r rp o op ⦃ x =>
    x.val = SandboxQuotaOf r.val rp.val o.val op.val ∧ (0 < r.val → r.val ≤ x.val) ⦄ := by
  unfold sandbox_quota SandboxQuotaOf
  by_cases hq : 0 < r.val ∧ 0 < o.val ∧ 0 < op.val ∧ 0 < rp.val
  · rw [if_yes (show r > 0#i64 by scalar_tac), if_yes (show o > 0#i64 by scalar_tac),
      if_yes (show op > 0#i64 by scalar_tac), if_yes (show rp > 0#i64 by scalar_tac), if_yes hq]
    -- each product and sum is made in a type that holds it: 126 bits in the 127 of `i128`, and the
    -- sum with `r` only when the overhead is not above what is left of `i64::MAX`
    have ho := o.hBounds
    have hrp := rp.hBounds
    have hop := op.hBounds
    have hr := r.hBounds
    simp only [IScalarTy.numBits] at ho hrp hop hr
    norm_num at ho hrp hop hr
    have hmin128 : (I128.min : Int) = -(2 ^ 127) := by simp [I128.min_def, I128.numBits]
    have hmax128 : (I128.max : Int) = 2 ^ 127 - 1 := by simp [I128.max_def, I128.numBits]
    step as ⟨i, hi⟩
    have hiv : i.val = o.val := by rw [hi]; exact cast_i128_val o
    step as ⟨i1, hi1⟩
    have hi1v : i1.val = rp.val := by rw [hi1]; exact cast_i128_val rp
    have hprod := mul_bounds i.val i1.val (by omega) (by omega) (by omega) (by omega)
    step as ⟨i2, hi2⟩
    step as ⟨i3, hi3⟩
    have hi3v : i3.val = op.val := by rw [hi3]; exact cast_i128_val op
    step as ⟨converted, hconv⟩
    rw [tdiv_nonneg _ _ (by omega)] at hconv
    have hc : converted.val = o.val * rp.val / op.val := by rw [hconv, hi2, hi3v, hiv, hi1v]
    have hc0 : 0 ≤ converted.val := by
      rw [hc]; exact Int.ediv_nonneg (Int.mul_pos (by omega) (by omega)).le (by omega)
    have hmax64 : (core.num.I64.MAX).val = 2 ^ 63 - 1 := by rfl
    step as ⟨i4, hi4⟩
    have hi4v : i4.val = 2 ^ 63 - 1 - r.val := by rw [hi4, I64.rMax]; omega
    step as ⟨i5, hi5⟩
    have hi5v : i5.val = 2 ^ 63 - 1 - r.val := by rw [hi5, cast_i128_val, hi4v]
    split
    · simp only [WP.spec_ok]
      unfold MaxI64
      refine ⟨?_, fun _ => ?_⟩ <;> scalar_tac
    · step as ⟨i6, hi6⟩
      have hi6v : i6.val = converted.val := by
        rw [hi6]; exact cast_i64_val converted (by scalar_tac)
      step as ⟨x, hx⟩
      unfold MaxI64
      refine ⟨?_, fun _ => ?_⟩ <;> scalar_tac
  · rw [if_no hq]
    repeat' split
    all_goals step*

end LimitCore
