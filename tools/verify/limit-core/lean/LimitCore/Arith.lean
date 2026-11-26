-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: the proofs about `io_weight_of_blkio`, `swap_max` and `cpu_max`.
-- Why it is needed: these are the conversions where a number of a client could be taken for another.
-- Read before this file: Simple.lean.
-- Notation: `f x ⦃ r => P r ⦄` is "the Rust `f` returns on `x`, with no panic and no endless loop,
--    and its answer `r` satisfies `P`"; `step` goes through one line of the Rust function and
--    `scalar_tac` proves a fact about machine numbers by arithmetic; `↑x` (or `x.val`) is the number
--    a machine integer is.
import LimitCore.Simple
open Aeneas Aeneas.Std Aeneas.Data.Coinductive Result velarx_limit_core
namespace LimitCore

unseal Result
attribute [local implicit_reducible] Result

/-- A call that returns what a claim says returns something: the call is `ok x` for an `x` that satisfies the claim. -/
theorem spec_ok_eq {α : Type} {m : Result α} {P : α → Prop} (h : m ⦃ r => P r ⦄) :
    ∃ x, m = ok x ∧ P x := by
  cases m using ITree.cases with
  | ret x => exact ⟨x, rfl, (WP.spec_ok x).mp h⟩
  | vis e k => exact ((WP.spec_vis e k).mp h).elim
  | div => exact (WP.spec_div.mp h).elim

/-- The constant `MAX_QUOTA` (`(1 << 44) - 1`) is computed without overflow and is 17592186044415. -/
theorem max_quota_is : MAX_QUOTA ⦃ r => r.val = 17592186044415 ⦄ := by
  unfold MAX_QUOTA; step*

/-- A condition that holds picks the first branch. -/
theorem if_yes {α : Type _} {c : Prop} [Decidable c] (h : c) (a b : α) :
    (if c then a else b) = a := by simp [h]

/-- A condition that does not hold picks the second branch. -/
theorem if_no {α : Type _} {c : Prop} [Decidable c] (h : ¬ c) (a b : α) :
    (if c then a else b) = b := by simp [h]

/-- `limit_of` for the other proofs: the claim, as a fact about the call. -/
theorem limit_of_spec' (v : Std.I64) : limit_of v ⦃ r => LimitIs v.val r ⦄ := limit_of_spec v

/-- The derived `==` of `Limit` answers true exactly for two equal limits, here for `Invalid`. -/
theorem limit_eq_spec (m : Limit) :
    Limit.Insts.CoreCmpPartialEqLimit.eq m Limit.Invalid ⦃ b => b = true ↔ m = Limit.Invalid ⦄ := by
  cases m <;> simp [Limit.Insts.CoreCmpPartialEqLimit.eq, Limit.read_discriminant, WP.spec_ok]

/-- `io_weight_of_blkio` answers `IoWeightOf`, and 1 to 10000 for a weight that is set: the multiplication by 9999 cannot overflow as the weight is held in 10 to 1000. -/
theorem io_weight_post (w : Std.U64) : io_weight_of_blkio w ⦃ r =>
    r.val = IoWeightOf w.val ∧ (0 < w.val → 1 ≤ r.val ∧ r.val ≤ 10000) ⦄ := by
  unfold io_weight_of_blkio
  have e1 : (10000#u64 - 1#u64) = ok 9999#u64 := by rfl
  have e2 : (1000#u64 - 10#u64) = ok 990#u64 := by rfl
  simp only [MIN_BLKIO_WEIGHT, MAX_BLKIO_WEIGHT, MAX_WEIGHT, e1, e2]
  split
  · subst_vars; simp [IoWeightOf]
  · split
    · step*
      unfold IoWeightOf; split_ifs <;> scalar_tac
    · split
      · step*
        unfold IoWeightOf; split_ifs <;> scalar_tac
      · step*
        unfold IoWeightOf; split_ifs <;> scalar_tac

/-- Proof of `TheBlockIoWeight`: the answer is `IoWeightOf`, which does not shrink when the weight grows. -/
theorem io_weight_spec : TheBlockIoWeight := by
  refine ⟨io_weight_post, ?_⟩
  intro a b hab
  obtain ⟨x, hx, px⟩ := spec_ok_eq (io_weight_post a)
  obtain ⟨y, hy, py⟩ := spec_ok_eq (io_weight_post b)
  rw [hx]; simp only [WP.spec_ok]; rw [hy]; simp only [WP.spec_ok]
  rw [px.1, py.1]; unfold IoWeightOf; split_ifs <;> scalar_tac

/-- Proof of `TheSwapOfTheCgroup`: the two limits are read by `limit_of`, and each of the sixteen pairs of kinds is a line of `SwapIs`; the difference of two positive numbers with the second not above the first does not wrap. -/
theorem swap_max_spec : TheSwapOfTheCgroup := by
  intro m s
  unfold swap_max
  -- the two limits are read by `limit_of`
  step with limit_of_spec' as ⟨lm, hlm⟩
  step with limit_of_spec' as ⟨ls, hls⟩
  unfold LimitIs at hlm hls
  unfold SwapIs
  -- one case for each kind of the memory limit and of the swap limit; in each, the `match` of
  -- the Rust function is a line of `SwapIs`
  split_ifs at hlm <;> split_ifs at hls <;>
    obtain ⟨b, rfl, hb⟩ := hlm <;> obtain ⟨c, rfl, hc⟩ := hls <;>
    simp [Limit.Insts.CoreCmpPartialEqLimit.eq, Limit.read_discriminant, WP.spec_ok] <;>
    (try step*) <;> scalar_tac

attribute [local step] max_quota_is

/-- `cpu_max` answers `CpuMaxIs`, and never `Unlimited` for a positive quota: each comparison of the Rust is a line of the table. -/
theorem cpu_max_post (quota : Std.I64) (period : Std.U64) : cpu_max quota period ⦃ r =>
    CpuMaxIs quota.val period.val r ∧ (0 < quota.val → r ≠ CpuMax.Unlimited) ⦄ := by
  unfold cpu_max
  simp only [MIN_PERIOD, MAX_PERIOD, DEFAULT_PERIOD, MIN_QUOTA]
  split <;> step* <;> (unfold CpuMaxIs PeriodOf MaxQuota; split_ifs <;> first | scalar_tac |
      (refine ⟨⟨_, _, rfl, ?_, ?_⟩, ?_⟩ <;> (try simp); scalar_tac))

end LimitCore
