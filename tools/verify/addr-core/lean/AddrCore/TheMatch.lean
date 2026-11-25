-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: a number's high bits, xor-ed with a prefix start, are zero exactly when the number
--   is in the prefix (`in_block`).
-- Why it is needed: the code tests a prefix with `(a ^^^ first) >>> (bits - len) == 0` and the statement
--   says `first <= a < first + 2^(bits - len)`; this is the one fact that joins them, for every number and
--   every length.
-- Read before this file: Spec.lean.
-- Notation: `a ^^^ b` is the xor of two numbers, `a >>> k` shifts `a` right by `k` bits (divides by 2^k).
import AddrCore.TheNumbers
open Aeneas Aeneas.Std Result velarx_addr_core
namespace AddrCore

/-- A number `a` shifted right by `k` places, xor a block start `f` shifted likewise, is zero exactly when `a` is in the block -/
theorem in_block (a f k : Nat) (aligned : f % 2 ^ k = 0) :
    (a ^^^ f) >>> k = 0 ↔ f ≤ a ∧ a < f + 2 ^ k := by
  obtain ⟨q, rfl⟩ := Nat.dvd_of_mod_eq_zero aligned
  have pos : 0 < 2 ^ k := Nat.two_pow_pos k
  rw [Nat.shiftRight_xor_distrib, Nat.xor_eq_zero_iff, Nat.shiftRight_eq_div_pow, Nat.shiftRight_eq_div_pow,
    Nat.mul_div_cancel_left _ pos]
  generalize 2 ^ k = P at *
  rw [Nat.mul_comm P q]
  constructor
  · intro h
    have h1 := Nat.div_mul_le_self a P
    have h2 := Nat.lt_div_mul_add (a := a) pos
    rw [h] at h1 h2
    constructor <;> omega
  · rintro ⟨h1, h2⟩
    apply Nat.le_antisymm
    · apply Nat.le_of_lt_succ
      rw [Nat.div_lt_iff_lt_mul pos, Nat.succ_mul]
      omega
    · rw [Nat.le_div_iff_mul_le pos]
      omega

end AddrCore
