-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: what the four small functions that sort a byte say: `is_alnum`, `is_hex`,
-- `is_digit` and `is_word` answer `true` exactly for the bytes `IsAlnum`, `IsHex`, `IsDigit` and
-- `IsWordByte` of Spec.lean name.
-- Why it is needed: every check of the crate is made of them.
-- Read before this file: Spec.lean.
-- Notation: `f x ⦃ r => P r ⦄` is "the Rust function `f` returns on `x`, and its answer `r`
-- satisfies `P r`"; `b.val` is the number a byte `b` is; `↔` is "exactly when".
import RefCore.Spec
open Aeneas Aeneas.Std Result velarx_ref_core
namespace RefCore

/-- `is_alnum` says `true` exactly for a lower-case letter or a digit. -/
@[step] theorem is_alnum_says (b : Std.U8) : is_alnum b ⦃ r => (r = true ↔ IsAlnum b.val) ⦄ := by
  unfold is_alnum IsAlnum IsLower IsDigit
  by_cases low : 97#u8 ≤ b <;> by_cases high : b ≤ 122#u8 <;>
    by_cases zero : 48#u8 ≤ b <;> by_cases nine : b ≤ 57#u8 <;>
    simp only [low, high, zero, nine, ite_true, ite_false, WP.spec_ok] <;> scalar_tac

/-- `is_hex` says `true` exactly for a digit or a lower-case letter `a` to `f`. -/
@[step] theorem is_hex_says (b : Std.U8) : is_hex b ⦃ r => (r = true ↔ IsHex b.val) ⦄ := by
  unfold is_hex IsHex IsDigit
  by_cases low : 97#u8 ≤ b <;> by_cases high : b ≤ 102#u8 <;>
    by_cases zero : 48#u8 ≤ b <;> by_cases nine : b ≤ 57#u8 <;>
    simp only [low, high, zero, nine, ite_true, ite_false, WP.spec_ok] <;> scalar_tac

/-- `is_digit` says `true` exactly for a decimal digit (it subtracts `0` with wrapping and
compares). -/
@[step] theorem is_digit_says (b : Std.U8) : is_digit b ⦃ r => (r = true ↔ IsDigit b.val) ⦄ := by
  unfold is_digit IsDigit
  simp only [lift, core.num.U8.wrapping_sub]
  simp [UScalar.lt_equiv]
  scalar_tac

/-- The number of the byte `_`. -/
theorem underscore_is_95 : (95#8#uscalar : Std.U8).val = 95 := rfl

/-- `is_word` says `true` exactly for a letter of either case, a digit or `_`. -/
@[step] theorem is_word_says (b : Std.U8) : is_word b ⦃ r => (r = true ↔ IsWordByte b.val) ⦄ := by
  unfold is_word IsWordByte IsAlnum IsLower IsDigit IsUpper
  by_cases low : 97#u8 ≤ b <;> by_cases high : b ≤ 122#u8 <;>
    by_cases up : 65#u8 ≤ b <;> by_cases upper : b ≤ 90#u8 <;>
    by_cases zero : 48#u8 ≤ b <;> by_cases nine : b ≤ 57#u8 <;>
    simp only [low, high, up, upper, zero, nine, ite_true, ite_false, WP.spec_ok] <;>
    (try split) <;> (try simp only [WP.spec_ok]) <;>
    first | scalar_tac | simp_all [UScalar.le_equiv, underscore_is_95]

end RefCore
