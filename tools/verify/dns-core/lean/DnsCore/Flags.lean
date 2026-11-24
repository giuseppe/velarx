-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: what the masks and the or of the flags of a DNS header do, as sums of
-- numbers: whether the response bit and the operation code of a query are clear, which bits `reply`
-- and `error_reply` put in the flags of an answer, and what adding the authoritative and the
-- truncation bits does.
--
-- Why it is needed: the flags are a 16-bit number where each bit means something (RFC 1035) and the
-- code builds them with `|||` and `&&&`; the claims say them as a sum (Spec.lean, `IsTheReply`).
-- The facts are proved on the numbers themselves, bit by bit (`Nat.testBit`), not by a solver.
--
-- Read before this file: Spec.lean (`Bit`, `Opcode`).
--
-- Notation: `a ||| b` and `a &&& b` are the bitwise or and and; `n / 2 ^ k % 2` is the bit `k` of
-- `n`; `flags.val` is the number of a 16-bit machine integer; `x ↔ y` is "exactly when".
import DnsCore.Spec

open Aeneas Aeneas.Std Result velarx_dns_core

namespace DnsCore

/-- Masking a number with `2 ^ k` gives 0 exactly when its bit `k` is 0. -/
theorem masked_bit_is_zero (n k : Nat) : n &&& 2 ^ k = 0 ↔ n / 2 ^ k % 2 = 0 := by
  rw [Nat.and_two_pow, Nat.testBit_eq_decide_div_mod_eq]
  have : n / 2 ^ k % 2 = 0 ∨ n / 2 ^ k % 2 = 1 := by omega
  rcases this with bit | bit <;> simp [bit]

/-- The response bit (`FLAG_QR`, the top bit of the flags) is clear exactly when the flags are
below 32768. -/
theorem response_bit_clear (flags : Std.U16) :
    (flags &&& FLAG_QR = 0#u16) ↔ flags.val < 32768 := by
  have mask : FLAG_QR = 32768#u16 := by simp [global_simps]
  have below := flags.hBounds
  rw [mask, UScalar.eq_equiv, UScalar.val_and, show (32768#u16).val = 2 ^ 15 by rfl,
    show (0#u16).val = 0 by rfl, masked_bit_is_zero]
  have below' : flags.val < 65536 := by scalar_tac
  omega

/-- The operation code of the flags (bits 11 to 14, `OPCODE`) is 0 exactly when masking the flags
with `OPCODE` gives 0. -/
theorem opcode_clear (flags : Std.U16) :
    (flags &&& OPCODE = 0#u16) ↔ Opcode flags.val = 0 := by
  have mask : OPCODE = 30720#u16 := by simp [global_simps]
  have each_bit : flags.val &&& 30720 = 0 ↔ flags.val / 2 ^ 11 % 2 = 0 ∧
      flags.val / 2 ^ 12 % 2 = 0 ∧ flags.val / 2 ^ 13 % 2 = 0 ∧ flags.val / 2 ^ 14 % 2 = 0 := by
    rw [show (30720 : Nat) = ((2 ^ 11 ||| 2 ^ 12) ||| 2 ^ 13) ||| 2 ^ 14 by rfl,
      Nat.and_or_distrib_left, Nat.and_or_distrib_left, Nat.and_or_distrib_left]
    simp only [Nat.or_eq_zero_iff, masked_bit_is_zero, and_assoc]
  rw [mask, UScalar.eq_equiv, UScalar.val_and, show (30720#u16).val = 30720 by rfl,
    show (0#u16).val = 0 by rfl, each_bit]
  unfold Opcode
  omega

/-- Or-ing a number that is less than `2 ^ j` into one that is a multiple of `2 ^ j` adds it. -/
theorem or_below (a b j : Nat) (below : b < 2 ^ j) (multiple : 2 ^ j ∣ a) : a ||| b = a + b := by
  obtain ⟨c, rfl⟩ := multiple
  rw [← Nat.two_pow_add_eq_or_of_lt below, Nat.add_comm]

/-- The flags of a reply without the authoritative and truncation bits, as numbers: the response
bit (32768), the recursion available bit (128), the recursion desired bit of the query (`rd`, 0 or
256) and the code (`rc`, below 16), or-ed in the order the code does it, are their sum. -/
theorem flag_bits_add_up (rd rc : Nat) (rd_is : rd = 0 ∨ rd = 256) (rc_is : rc < 16) :
    ((32768 ||| 128) ||| rd) ||| rc = 32768 + 128 + rd + rc := by
  rcases rd_is with rfl | rfl <;>
    simp only [Nat.reduceOr] <;>
    rw [or_below _ _ 4 (by omega) (by omega)]

/-- The recursion desired bit of the flags of a query, kept by masking with `FLAG_RD`: 0 or 256,
the bit 8 of the flags in its place. -/
theorem recursion_desired_bit (flags : Std.U16) :
    (flags &&& FLAG_RD).val = Bit flags.val 8 * 256 := by
  have : FLAG_RD = 256#u16 := by simp [global_simps]
  rw [this, UScalar.val_and, show (256#u16).val = 2 ^ 8 by rfl, Nat.and_two_pow,
    Nat.testBit_eq_decide_div_mod_eq]
  unfold Bit
  have : flags.val / 256 % 2 = 0 ∨ flags.val / 256 % 2 = 1 := by omega
  rcases this with bit | bit <;> simp [bit]

/-- The response code kept by masking with `RCODE`: the code modulo 16. -/
theorem code_bits (rcode : Std.U16) : (rcode &&& RCODE).val = rcode.val % 16 := by
  have : RCODE = 15#u16 := by simp [global_simps]
  rw [this, UScalar.val_and, show (15#u16).val = 2 ^ 4 - 1 by rfl, Nat.and_two_pow_sub_one_eq_mod]

/-- The flags the code builds for a reply before the authoritative and truncation bits: the
response bit and the recursion available bit, the recursion desired bit of the query, and the
code, are the sum of what they are (`Bit` of the query flags 8 is its recursion desired bit). -/
theorem base_flags_value (flags rcode : Std.U16) :
    (((FLAG_QR ||| FLAG_RA) ||| (flags &&& FLAG_RD)) ||| (rcode &&& RCODE)).val =
      32768 + 128 + 256 * Bit flags.val 8 + rcode.val % 16 := by
  have qr : FLAG_QR = 32768#u16 := by simp [global_simps]
  have ra : FLAG_RA = 128#u16 := by simp [global_simps]
  have rd := recursion_desired_bit flags
  have rc := code_bits rcode
  have rc_below : rcode.val % 16 < 16 := Nat.mod_lt _ (by omega)
  have rd_is : Bit flags.val 8 * 256 = 0 ∨ Bit flags.val 8 * 256 = 256 := by
    unfold Bit
    omega
  have := flag_bits_add_up _ _ rd_is rc_below
  simp only [UScalar.val_or, qr, ra, rd, rc]
  rw [show (32768#u16).val = 32768 from rfl, show (128#u16).val = 128 from rfl, this]
  omega

/-- Or-ing the bit `2 ^ k` into a number that does not have it adds it. -/
theorem or_into_a_clear_bit (n k : Nat) (clear : n % 2 ^ (k + 1) < 2 ^ k) :
    n ||| 2 ^ k = n + 2 ^ k := by
  obtain ⟨q, r, small, rfl⟩ : ∃ q r, r < 2 ^ (k + 1) ∧ n = 2 ^ (k + 1) * q + r :=
    ⟨n / 2 ^ (k + 1), n % 2 ^ (k + 1), Nat.mod_lt _ (by positivity),
      (Nat.div_add_mod n (2 ^ (k + 1))).symm⟩
  have r_is : r = (2 ^ (k + 1) * q + r) % 2 ^ (k + 1) := by
    rw [Nat.mul_add_mod]
    exact (Nat.mod_eq_of_lt small).symm
  rw [← r_is] at clear
  have top : 2 ^ (k + 1) * q ||| r = 2 ^ (k + 1) * q + r :=
    or_below _ _ (k + 1) small (Dvd.intro _ rfl)
  have bit : r ||| 2 ^ k = 2 ^ k + r := by
    rw [Nat.or_comm]
    exact or_below _ _ k clear (dvd_refl _)
  rw [← top, Nat.or_assoc, bit]
  have : 2 ^ k + r < 2 ^ (k + 1) := by
    rw [Nat.pow_succ]
    omega
  rw [or_below _ _ (k + 1) this (Dvd.intro _ rfl)]
  omega

/-- The authoritative bit (`FLAG_AA`, 1024) is added when it is asked for, to flags that do not
have it (nor the one above it). -/
theorem authoritative_bit_is_added (flags : Std.U16) (authoritative : Bool)
    (clear : flags.val % 2048 < 1024) :
    (if authoritative = true then ok (flags ||| FLAG_AA) else ok flags) ⦃ with_it =>
      with_it.val = flags.val + (if authoritative = true then 1024 else 0) ⦄ := by
  have : FLAG_AA = 1024#u16 := by simp [global_simps]
  cases authoritative
  · simp
  · simp only [this, ite_true, WP.spec_ok, UScalar.val_or]
    exact or_into_a_clear_bit flags.val 10 (by simpa using clear)

/-- The truncation bit (`FLAG_TC`, 512) is added when it is asked for, to flags that do not have
it (nor the one above it). -/
theorem truncation_bit_is_added (flags : Std.U16) (truncated : Bool)
    (clear : flags.val % 1024 < 512) :
    (if truncated = true then ok (flags ||| FLAG_TC) else ok flags) ⦃ with_it =>
      with_it.val = flags.val + (if truncated = true then 512 else 0) ⦄ := by
  have : FLAG_TC = 512#u16 := by simp [global_simps]
  cases truncated
  · simp
  · simp only [this, ite_true, WP.spec_ok, UScalar.val_or]
    exact or_into_a_clear_bit flags.val 9 (by simpa using clear)

end DnsCore
