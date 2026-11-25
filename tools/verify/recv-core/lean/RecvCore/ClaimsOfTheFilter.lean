-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: the proofs of the claims of Spec.lean about the filter of a peer: the sizes a message may
--   have, what to do with a whole filter or a delta, what the filter says.
-- Why it is needed: Theorems.lean names what is proved; the proofs are here.  As in ClaimsOfTheReading.lean, each
--   function is opened, cut at its `if`s, and the arithmetic of each line is left to `step*`.
-- Read before this file: Spec.lean, ClaimsOfTheReading.lean.
-- Notation: `rcases` splits a given "or" or "and"; `by_cases h : P` goes on once with `P` and once with `¬ P`;
--   `UScalar.eq_equiv` turns an equality of two numbers of a type into one of their values.
import RecvCore.ClaimsOfTheReading
open Aeneas Aeneas.Std Result velarx_recv_core
namespace RecvCore

/-- `MAX_FILTER_BYTES` is 4 MiB: `4 << 20`, on a computer of 32 or of 64 bits. -/
theorem max_filter_bytes_is : MAX_FILTER_BYTES ⦃ n => n.val = 4194304 ⦄ := by
  unfold MAX_FILTER_BYTES
  have bits := System.Platform.numBits_eq
  step*
  · rcases bits with h | h <;> simp [h]
  · have size := Usize.size_scalarTac_eq.2
    rcases bits with h | h <;> simp [n_post, size, h]

attribute [local step] max_filter_bytes_is

/-- `is_multiple_of bytes 8` says whether `bytes` is a multiple of 8. -/
theorem multiple_of_eight_is (bytes : Std.Usize) :
    core.num.Usize.is_multiple_of bytes 8#usize ⦃ b => (b = true ↔ bytes.val % 8 = 0) ⦄ := by
  unfold core.num.Usize.is_multiple_of UScalar.is_multiple_of
  refine (WP.spec_ok _).mpr ?_
  simp

/-- Proof of the first half of `TheSizesOfAFilter`: each `if` of `full_ok` is one condition of the claim. -/
theorem full_ok_is (bytes : Std.Usize) (hashes : Std.U8) : full_ok bytes hashes ⦃ b =>
    (b = true ↔ bytes.val ≠ 0 ∧ bytes.val % 8 = 0 ∧ bytes.val ≤ 4194304 ∧
      1 ≤ hashes.val ∧ hashes.val ≤ 16) ⦄ := by
  unfold full_ok
  split_ifs <;> step*
  simp_all [MAX_HASHES, UScalar.le_equiv, UScalar.eq_equiv, bne_iff_ne]
  omega

/-- Proof of the second half of `TheSizesOfAFilter`: the same for `delta_ok`. -/
theorem delta_ok_is (bytes : Std.Usize) : delta_ok bytes ⦃ b =>
    (b = true ↔ bytes.val ≠ 0 ∧ bytes.val % 8 = 0 ∧ bytes.val / 8 ≤ 8192) ⦄ := by
  unfold delta_ok
  split_ifs <;> step*
  simp_all [MAX_DELTA_KEYS, UScalar.le_equiv, UScalar.eq_equiv, bne_iff_ne]

/-- The text of a filter is below the bound `max / 3 * 4 + 4`, worked out in 128 bits. -/
theorem full_text_ok_is (text max : Std.Usize) : full_text_ok text max ⦃ b =>
    (b = true ↔ text.val ≤ max.val / 3 * 4 + 4) ⦄ := by
  unfold full_text_ok
  -- (a `usize` is of 32 or 64 bits, so below 2^64)
  have fits : ∀ x : Std.Usize, x.val < 2 ^ 64 := by
    intro x
    have := x.hBounds
    rcases System.Platform.numBits_eq with h | h <;> simp [UScalarTy.numBits, h] at this <;> omega
  have wide : ∀ x : Std.Usize, (UScalar.cast UScalarTy.U128 x).val = x.val := by
    intro x
    apply UScalar.cast_val_mod_pow_of_inBounds_eq
    have := fits x
    simp [UScalarTy.numBits]
    omega
  have small := fits max
  step*

/-- Proof of `AFilterTextOfAnyAllowedSizeIsAccepted`: `full_text_ok_is`, and the text of `bytes` bytes is
`(bytes + 2) / 3 * 4` characters, which is at most `max / 3 * 4 + 4` when `bytes` is at most `max`. -/
theorem a_filter_text_of_any_allowed_size_is_accepted : AFilterTextOfAnyAllowedSizeIsAccepted := by
  refine ⟨full_text_ok_is, fun bytes max text small text_is => ?_⟩
  refine WP.spec_mono (full_text_ok_is text max) ?_
  intro b verdict
  exact verdict.mpr (by omega)

/-- Proof of `TheSizesOfAFilter`: `full_ok_is` and `delta_ok_is`. -/
theorem the_sizes_of_a_filter : TheSizesOfAFilter :=
  ⟨full_ok_is, delta_ok_is⟩

end RecvCore
