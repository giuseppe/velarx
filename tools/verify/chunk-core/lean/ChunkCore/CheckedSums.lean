-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: what the two small functions of crates/chunk-core that do arithmetic on
-- sizes return: `within` (a sum that must not pass a cap, `None` if it does or if it does not fit
-- in a `u64`) and `compressed_bound` (the saturating formula), as facts about natural numbers.
--
-- Why it is needed: both loops of `check` call them.  The proofs of the loops need to know only
-- what is here, not how the sums are written.
--
-- Read before this file: Spec.lean, and `compressed_bound` and `within` of src/lib.rs.
--
-- Notation: `x ⦃ r => P r ⦄` is "the function returns, and its result `r` satisfies `P r`";
-- `@[step]` makes `step` use a fact when it meets that call (as `step as ⟨ r, hr ⟩` in the proofs
-- after this file); `x.val` is the natural number a machine integer is; `min a b` the smaller
-- of two numbers; `omega` is the tactic that decides facts about sums and comparisons of numbers.
import ChunkCore.Spec

open Aeneas Aeneas.Std Result velarx_chunk_core

namespace ChunkCore

/-- `within total more cap` is the sum `total + more` if it fits in a `u64` and is at most `cap`,
and nothing otherwise: when it says nothing, the sum (of natural numbers) is more than `cap`. -/
@[step]
theorem within_spec (total more cap : Std.U64) :
    within total more cap ⦃ answer =>
      (∀ sum, answer = some sum → sum.val = total.val + more.val ∧ sum.val ≤ cap.val) ∧
      (answer = none → cap.val < total.val + more.val) ⦄ := by
  unfold within
  -- the sum is `checked_add`, and Aeneas says when it is `none`
  simp only [lift]
  have fits := Std.U64.checked_add_bv_spec total more
  cases sum : total.checked_add more with
  | none =>
    -- it does not fit in a `u64`, so it is more than any cap
    simp only [sum] at fits
    simp only [Std.bind_ok, WP.spec_ok]
    refine ⟨by simp, fun _ => ?_⟩
    have : cap.val ≤ Std.U64.max := by scalar_tac
    omega
  | some s =>
    -- it fits: the answer is the sum if it is within the cap, else `none`
    simp only [sum] at fits
    simp only [Std.bind_ok]
    split_ifs with within
    · simp only [WP.spec_ok]
      refine ⟨fun x hx => ?_, by simp⟩
      cases hx
      exact ⟨fits.2.1, by simpa using within⟩
    · simp only [WP.spec_ok]
      refine ⟨by simp, fun _ => ?_⟩
      have : cap.val < s.val := by simpa using within
      omega

/-- `saturating_add` is the sum, or the largest `u64` if that is more. -/
theorem saturating_add_val (x y : Std.U64) :
    (core.num.U64.saturating_add x y).val = min Std.U64.max (x.val + y.val) := by
  simp only [core.num.U64.saturating_add, UScalar.saturating_add, UScalar.val, BitVec.toNat_ofNat]
  have positive : 0 < 2 ^ UScalarTy.U64.numBits := by positivity
  have same : Std.U64.max = UScalar.max UScalarTy.U64 := by simp [Std.U64.max]
  rw [same]
  apply Nat.mod_eq_of_lt (by simp only [UScalar.max]; omega)


/-- `compressed_bound` is `size + size / 64 + 2^20`, or the largest `u64` when that is more.
This is the claim `CompressedBoundIsTheFormula` of Spec.lean. -/
@[step]
theorem compressed_bound_val (size : Std.U64) :
    compressed_bound size ⦃ bound => bound.val = min (CompressedBoundOf size.val) Std.U64.max ⦄ := by
  unfold compressed_bound
  -- `size / 64`, then `size + size / 64` (saturating), then `1 << 20`, then the last sum
  step as ⟨ i, hi ⟩
  simp only [lift, Std.bind_ok]
  step as ⟨ i2, hi2 ⟩
  have mebibyte : i2.val = 2 ^ 20 := by
    rw [hi2]; simp [Std.U64.size, Std.U64.numBits]
  have small : size.val ≤ Std.U64.max := by scalar_tac
  simp only [saturating_add_val, mebibyte, CompressedBoundOf, hi]
  omega

end ChunkCore
