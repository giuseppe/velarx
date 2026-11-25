-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: the decimal writing of a number: its digits are digits and they write the
--    number.
-- Why it is needed: the canonical label of a pair has the numbers in decimal; the proofs need that
--    the writing is exact.
-- Read before this file: Spec.lean.
-- Notation: `Decimal n` is the digits of `n`, `Value ds` the number the digits write.
import McsCore.Spec
open Aeneas Aeneas.Std Result velarx_mcs_core
namespace McsCore

/-- A number below 10 is written with one digit. -/
theorem decimal_small (n : Nat) (h : n < 10) : Decimal n = [digitByte n] := by
  rw [Decimal]; simp [h]

/-- A number of 10 or more is written as the digits of a tenth of it and its last digit. -/
theorem decimal_big (n : Nat) (h : 10 ≤ n) : Decimal n = Decimal (n / 10) ++ [digitByte (n % 10)] := by
  rw [Decimal]; simp [show ¬ n < 10 by omega]

/-- The byte of a digit below 10 is 48 plus the digit. -/
theorem digitByte_val (k : Nat) (h : k < 10) : (digitByte k).val = 48 + k := by
  unfold digitByte
  simp [Std.UScalar.val, BitVec.toNat_ofNat]
  omega

/-- The byte of a digit below 10 is a digit. -/
theorem digitByte_isDigit (k : Nat) (h : k < 10) : IsDigit (digitByte k) := by
  unfold IsDigit; rw [digitByte_val k h]; omega

/-- Every byte of the decimal writing of a number is a digit. -/
theorem decimal_digits (n : Nat) : ∀ d ∈ Decimal n, IsDigit d := by
  induction n using Nat.strong_induction_on with
  | _ n ih =>
    by_cases h : n < 10
    · rw [decimal_small n h]; intro d hd; simp at hd; rw [hd]; exact digitByte_isDigit n h
    · rw [decimal_big n (by omega)]
      intro d hd
      rcases List.mem_append.mp hd with hd | hd
      · exact ih (n / 10) (by omega) d hd
      · simp at hd; rw [hd]; exact digitByte_isDigit _ (by omega)

/-- The decimal writing of a number is never empty. -/
theorem decimal_ne_nil (n : Nat) : Decimal n ≠ [] := by
  by_cases h : n < 10
  · rw [decimal_small n h]; simp
  · rw [decimal_big n (by omega)]; simp

/-- Adding a digit at the end of a number writing multiplies it by ten and adds the digit. -/
theorem value_append_digit (ds : List Std.U8) (d : Std.U8) :
    Value (ds ++ [d]) = 10 * Value ds + (d.val - 48) := by
  unfold Value; simp [List.foldl_append]

/-- The number that the decimal writing of `n` writes is `n`. -/
theorem decimal_value (n : Nat) : Value (Decimal n) = n := by
  induction n using Nat.strong_induction_on with
  | _ n ih =>
    by_cases h : n < 10
    · rw [decimal_small n h]
      simp [Value, digitByte_val n h]
    · rw [decimal_big n (by omega), value_append_digit, ih (n / 10) (by omega),
        digitByte_val _ (by omega)]
      omega

end McsCore
