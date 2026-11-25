-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: the number of the bytes of an address (`Number` of Spec.lean) is what `v4_number`
--   and `v6_number` return: the loops that read 4 or 16 bytes into one 32 or 128 bit number.
-- Why it is needed: every claim speaks of the number of an address, and the code works on that number only;
--   the loops must be shown not to lose a bit (a shift left that overflows would).
-- Read before this file: Spec.lean.
-- Notation: `loop.spec_decr_nat` proves a loop's answer from a fact (the invariant) each turn keeps and a
--   number that goes down; `step as ⟨ x, hx ⟩` runs one Rust line and names its result `x` and what is known
--   of it `hx`; `l.take i` is the first `i` of the list `l`; `x.val` is the number inside a machine integer.
import AddrCore.Spec
open Aeneas Aeneas.Std Result velarx_addr_core
namespace AddrCore

/-- The number of a list and one byte after it is the number of the list moved up one byte, plus the byte. -/
theorem number_append_byte (l : List Std.U8) (b : Std.U8) :
    Number (l ++ [b]) = 256 * Number l + b.val := by
  simp [Number, List.foldl_append]

/-- The number of `k` bytes is below 256 to the power `k`. -/
theorem number_lt (l : List Std.U8) : Number l < 256 ^ l.length := by
  induction l using List.reverseRecOn with
  | nil => simp [Number]
  | append_singleton l b ih =>
    rw [number_append_byte, List.length_append, List.length_singleton, pow_succ]
    have : b.val < 256 := by scalar_tac
    omega

/-- The number of the first `i + 1` bytes of a list is that of the first `i` moved up one byte, plus byte `i`. -/
theorem number_take_succ (l : List Std.U8) (i : Nat) (inside : i < l.length) :
    Number (l.take (i + 1)) = 256 * Number (l.take i) + l[i].val := by
  rw [List.take_succ_eq_append_getElem inside, number_append_byte]

/-- shifting a number of a few bytes left by a byte, then adding a byte -/
theorem shift_or (n b : Nat) (small : b < 256) : (n * 256) ||| b = n * 256 + b := by
  have := Nat.shiftLeft_add_eq_or_of_lt (a := n) (b := b) (i := 8) small
  simpa [Nat.shiftLeft_eq] using this.symm

/-- The loop of `v4_number`, from the byte `i` with the first `i` bytes already read in `n`: it returns the number of the 4 bytes (each turn moves the number up a byte, which cannot overflow 32 bits while fewer than 4 bytes are read). -/
theorem v4_number_loop_is (a : Std.Array Std.U8 4#usize) (n : Std.U32) (i : Std.Usize)
    (inside : i.val ≤ 4) (so_far : n.val = Number (a.val.take i.val)) :
    v4_number_loop a n i ⦃ r => r.val = Number a.val ⦄ := by
  unfold v4_number_loop
  apply loop.spec_decr_nat (fun q => 4 - q.2.val)
    (fun q => q.2.val ≤ 4 ∧ q.1.val = Number (a.val.take q.2.val))
  · rintro ⟨n, i⟩ ⟨inside, so_far⟩
    simp only at inside so_far ⊢
    unfold v4_number_loop.body
    by_cases below : i < 4#usize
    · simp only [below, ite_true]
      have below' : i.val < 4 := by scalar_tac
      have length : a.val.length = 4 := by simp
      have small : n.val < 256 ^ 3 := by
        have : (a.val.take i.val).length ≤ 3 := by simp [length]; omega
        calc n.val = _ := so_far
          _ < 256 ^ (a.val.take i.val).length := number_lt _
          _ ≤ 256 ^ 3 := Nat.pow_le_pow_right (by omega) this
      step as ⟨ i1, h1 ⟩
      step as ⟨ i2, h2 ⟩
      step as ⟨ i3, h3 ⟩
      step as ⟨ n1, h4 ⟩
      step as ⟨ i4, h5 ⟩
      refine ⟨by scalar_tac, ?_, by scalar_tac⟩
      have bound : i2.val < 256 := by scalar_tac
      have cast : i3.val = i2.val := by rw [h3]; simp
      have shifted : i1.val = n.val * 256 := by
        rw [h1, Nat.shiftLeft_eq]; simp [U32.size, U32.numBits]; omega
      rw [h5, h4, UScalar.val_or, shifted, cast, shift_or _ _ bound, number_take_succ _ _ (by omega), so_far, h2]; ring
    · simp only [below, ite_false]
      refine (WP.spec_ok _).mpr ?_
      have at_end : i.val = 4 := by scalar_tac
      have length : a.val.length = 4 := by simp
      show n.val = _
      rw [so_far, at_end, List.take_of_length_le (by omega)]
  · exact ⟨inside, so_far⟩

/-- The loop of `v6_number`, from the byte `i` with the first `i` bytes already read in `n`: it returns the number of the 16 bytes (a turn cannot overflow 128 bits while fewer than 16 bytes are read). -/
theorem v6_number_loop_is (a : Std.Array Std.U8 16#usize) (n : Std.U128) (i : Std.Usize)
    (inside : i.val ≤ 16) (so_far : n.val = Number (a.val.take i.val)) :
    v6_number_loop a n i ⦃ r => r.val = Number a.val ⦄ := by
  unfold v6_number_loop
  apply loop.spec_decr_nat (fun q => 16 - q.2.val)
    (fun q => q.2.val ≤ 16 ∧ q.1.val = Number (a.val.take q.2.val))
  · rintro ⟨n, i⟩ ⟨inside, so_far⟩
    simp only at inside so_far ⊢
    unfold v6_number_loop.body
    by_cases below : i < 16#usize
    · simp only [below, ite_true]
      have below' : i.val < 16 := by scalar_tac
      have length : a.val.length = 16 := by simp
      have small : n.val < 256 ^ 15 := by
        have : (a.val.take i.val).length ≤ 15 := by simp [length]; omega
        calc n.val = _ := so_far
          _ < 256 ^ (a.val.take i.val).length := number_lt _
          _ ≤ 256 ^ 15 := Nat.pow_le_pow_right (by omega) this
      step as ⟨ i1, h1 ⟩
      step as ⟨ i2, h2 ⟩
      step as ⟨ i3, h3 ⟩
      step as ⟨ n1, h4 ⟩
      step as ⟨ i4, h5 ⟩
      refine ⟨by scalar_tac, ?_, by scalar_tac⟩
      have bound : i2.val < 256 := by scalar_tac
      have cast : i3.val = i2.val := by rw [h3]; simp
      have shifted : i1.val = n.val * 256 := by
        rw [h1, Nat.shiftLeft_eq]; simp [U128.size, U128.numBits]; omega
      rw [h5, h4, UScalar.val_or, shifted, cast, shift_or _ _ bound, number_take_succ _ _ (by omega), so_far, h2]; ring
    · simp only [below, ite_false]
      refine (WP.spec_ok _).mpr ?_
      have at_end : i.val = 16 := by scalar_tac
      have length : a.val.length = 16 := by simp
      show n.val = _
      rw [so_far, at_end, List.take_of_length_le (by omega)]
  · exact ⟨inside, so_far⟩


/-- `v4_number` returns the number of the 4 bytes. -/
@[step]
theorem v4_number_is (a : Std.Array Std.U8 4#usize) : v4_number a ⦃ r => r.val = Number a.val ⦄ := by
  unfold v4_number
  exact v4_number_loop_is a 0#u32 0#usize (by scalar_tac) (by simp [Number])

/-- `v6_number` returns the number of the 16 bytes. -/
@[step]
theorem v6_number_is (a : Std.Array Std.U8 16#usize) : v6_number a ⦃ r => r.val = Number a.val ⦄ := by
  unfold v6_number
  exact v6_number_loop_is a 0#u128 0#usize (by scalar_tac) (by simp [Number])

end AddrCore
