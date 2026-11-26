-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: the proofs about `nano_cpus_of` and `nano_cpus_max`, and that the quota of a count of CPUs gives the count back, rounded down.
-- Why it is needed: the product of a quota and 10^9 is made in 128 bits, so no step wraps.
-- Read before this file: Arith.lean.
-- Notation: `f x ⦃ r => P r ⦄` is "the Rust `f` returns on `x`, with no panic and no endless loop,
--    and its answer `r` satisfies `P`"; `step` goes through one line of the Rust function and
--    `scalar_tac` proves a fact about machine numbers by arithmetic; `↑x` (or `x.val`) is the number
--    a machine integer is.
import LimitCore.Arith
open Aeneas Aeneas.Std Aeneas.Data.Coinductive Result velarx_limit_core
namespace LimitCore

unseal Result
attribute [local implicit_reducible] Result

/-- The period `0` stands for the default. -/
theorem period_norm (period : Std.U64) :
    ∃ p1 : Std.U64, (if period = 0#u64 then ok DEFAULT_PERIOD else ok period) = ok p1 ∧
      p1.val = PeriodOf period.val := by
  unfold PeriodOf DEFAULT_PERIOD
  split <;> rename_i h
  · exact ⟨100000#u64, by simp, by simp [h]⟩
  · exact ⟨period, by simp, by split_ifs <;> scalar_tac⟩

/-- `nano_cpus_of` is the quotient of the 128-bit product, cut at `i64::MAX`: the product of a quota and 10^9 fits 128 bits, the divisor is not 0. -/
theorem nano_cpus_of_post (quota : Std.I64) (period : Std.U64) : nano_cpus_of quota period ⦃ n =>
    n.val = if quota.val ≤ 0 then 0
      else min (quota.val * 1000000000 / (PeriodOf period.val : Int)) MaxI64 ⦄ := by
  unfold nano_cpus_of
  -- the period is 0 or not: `p1` is the one used
  obtain ⟨p1, hp1, hv⟩ := period_norm period
  have hpos : 1 ≤ p1.val := by unfold PeriodOf at hv; split_ifs at hv <;> scalar_tac
  simp only [hp1]
  step*
  all_goals (try scalar_tac)
  all_goals
    -- the casts keep the values, and the quotient of the 128-bit product is the one of the claim
    have hi : (i.val : Int) = quota.val := by simp only [i_post]; scalar_tac
    have hi2 : i2.val = p1.val := by simp only [i2_post]; scalar_tac
    have hn : (n.val : Int) = quota.val * 1000000000 / (p1.val : Int) := by
      rw [n_post, Int.natCast_div, ← hi2, ← hi]; rw [i1_post]; push_cast; rfl
    have hmax : (core.num.I64.MAX).val = 2 ^ 63 - 1 := by rfl
    have hi3 : i3.val = 2 ^ 63 - 1 := by rw [i3_post, IScalar.hcast_val_eq, hmax]; rfl
    -- the answer is the quotient, or `i64::MAX` when the quotient is greater
    rw [← hv, if_no (by scalar_tac)]
    unfold MaxI64
    simp only [← hn]
    have hb : (((2 ^ IScalarTy.I64.numBits : Nat)) : Int) = 2 ^ 64 := by rfl
    first
      | (rw [hmax]; have hgt : 2 ^ 63 - 1 < n.val := by scalar_tac
         omega)
      | (have hle : n.val ≤ 2 ^ 63 - 1 := by scalar_tac
         rw [UScalar.hcast_val_eq, Int.bmod_def, hb]; split_ifs <;> omega)

/-- `nano_cpus_max` answers as the claim says: below 10000 it is invalid, else it is `cpu_max` of `nano / 10000` and a period of 100000. -/
theorem nano_cpus_max_post (nano : Std.I64) : nano_cpus_max nano ⦃ r =>
    (nano.val ≤ 0 → r = CpuMax.Unlimited) ∧
    (0 < nano.val → nano.val < 10000 → r = CpuMax.Invalid) ∧
    (10000 ≤ nano.val → CpuMaxIs (nano.val / 10000) 100000 r) ∧
    (0 < nano.val → r ≠ CpuMax.Unlimited) ⦄ := by
  unfold nano_cpus_max
  split
  · simp only [WP.spec_ok]; refine ⟨?_, ?_, ?_, ?_⟩ <;> scalar_tac
  · -- the quota is `nano / 10000` (rounded toward zero, the number is positive)
    step as ⟨i, hi⟩
    have hpos : 0 < nano.val := by scalar_tac
    rw [Int.tdiv_eq_ediv] at hi
    simp only [show 0 ≤ nano.val by omega, true_or, ite_true, add_zero] at hi
    split
    · simp only [WP.spec_ok]
      refine ⟨?_, ?_, ?_, ?_⟩
      · intros; trivial
      · intros; trivial
      · intro h; exfalso; scalar_tac
      · intro; nofun
    · simp only [DEFAULT_PERIOD]
      refine WP.spec_mono (cpu_max_post i 100000#u64) ?_
      intro r ⟨h1, h2⟩
      have hq : i.val = nano.val / 10000 := by scalar_tac
      refine ⟨fun h => by exfalso; scalar_tac, fun h1' h2' => by exfalso; scalar_tac,
        fun h => ?_, fun h => h2 (by scalar_tac)⟩
      rw [← hq]; simpa using h1

/-- The count of a quota that `nano_cpus_max` made is the count asked, rounded down to a multiple of 10000. -/
theorem nano_round_trip (nano : Std.I64) : nano_cpus_max nano ⦃ r => ∀ (q p : Std.U64) (i : Std.I64),
    r = CpuMax.Quota q p → i.val = q.val →
      nano_cpus_of i 100000#u64 ⦃ n => n.val ≤ nano.val ∧ nano.val - n.val < 10000 ⦄ ⦄ := by
  refine WP.spec_mono (nano_cpus_max_post nano) ?_
  intro r ⟨h1, h2, h3, h4⟩ q p i hr hi
  have hp : 0 < nano.val := by
    by_contra hn
    have := h1 (by omega)
    rw [hr] at this; cases this
  have hbig : 10000 ≤ nano.val := by
    by_contra hn
    have := h2 hp (by omega)
    rw [hr] at this; cases this
  have hc := h3 hbig
  subst hr
  simp only [CpuMaxIs, PeriodOf, MaxQuota] at hc
  norm_num at hc
  refine WP.spec_mono (nano_cpus_of_post i 100000#u64) ?_
  intro n hn
  have hnano : nano.val ≤ MaxI64 := by unfold MaxI64; scalar_tac
  simp only [PeriodOf, MaxI64] at hn hnano
  norm_num at hn
  rw [if_no (by omega)] at hn
  omega

end LimitCore
