-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: what `rdev` and `major_minor` answer, as statements on the 32 bits of the numbers (`.bv` is
-- the number as bits), and that `WHITEOUT` is 0.
-- Why it is needed: the claims about devices (the numbers fit exactly, they come back, two devices never share a
-- number) are proved from these two statements, bit by bit: two 32-bit numbers are equal when they agree at
-- each of the 32 places (`equal_at_each_place`), and each place is a statement `simp` settles.
-- Read before this file: Spec.lean.
-- Notation: `x.bv` is the 32 bits of the number `x`; `&&&` is and, `|||` or, `<<<` and `>>>` shift left and
-- right; `10#32` is the 32-bit number 10; `step` goes through one line of the Rust function.
import OverlayCore.Spec

open Aeneas Aeneas.Std Result velarx_overlay_core
namespace OverlayCore

/-- `WHITEOUT` is the number 0. -/
theorem whiteout_is_zero : WHITEOUT = 0#u32 := by
  unfold WHITEOUT; rfl

/-- **What `rdev` answers**: a number exactly when the major is below 4096 and the minor below
2^20, and then the number is the minor's low 8 bits, the major shifted by 8, and the minor's next
12 bits shifted by 12, as 32 bits.  (The Rust function checks the two bounds, then builds the
number with shifts and masks; each step is a bit operation that cannot overflow.) -/
theorem rdev_answers (major minor : Std.U32) :
    rdev major minor ⦃ r =>
      (r ≠ none ↔ major.val < 4096 ∧ minor.val < 1048576) ∧
      ∀ x, r = some x →
        x.bv = (minor.bv &&& 255#32) ||| (major.bv <<< 8) ||| ((minor.bv &&& 1048320#32) <<< 12) ⦄ := by
  unfold rdev
  step as ⟨ i, is_i ⟩
  have size : U32.size = 4294967296 := by norm_num [U32.size, U32.numBits]
  have i_is : i.val = 4096 := by rw [is_i, size]; decide
  by_cases fits_major : major < i
  · simp only [fits_major, ite_true]
    step as ⟨ j, is_j ⟩
    have j_is : j.val = 1048576 := by rw [is_j, size]; decide
    by_cases fits_minor : minor < j
    · simp only [fits_minor, ite_true]
      step as ⟨ i2, is_i2, bv2 ⟩
      step as ⟨ i3, is_i3, bv3 ⟩
      step as ⟨ i4, is_i4, bv4 ⟩
      step as ⟨ i5, is_i5, bv5 ⟩
      step as ⟨ i6, is_i6, bv6 ⟩
      step as ⟨ i7, is_i7, bv7 ⟩
      refine ⟨⟨fun _ => ⟨by scalar_tac, by scalar_tac⟩, fun _ => by simp⟩, ?_⟩
      intro x same
      cases same
      simp [bv7, bv4, bv2, bv3, bv5, bv6]
    · simp only [fits_minor, ite_false]
      refine (WP.spec_ok _).mpr ?_
      refine ⟨⟨fun no => absurd rfl no, fun ⟨_, big⟩ => ?_⟩, by simp⟩
      exfalso; apply fits_minor; scalar_tac
  · simp only [fits_major, ite_false]
    refine (WP.spec_ok _).mpr ?_
    refine ⟨⟨fun no => absurd rfl no, fun ⟨big, _⟩ => ?_⟩, by simp⟩
    exfalso; apply fits_major; scalar_tac

/-- **What `major_minor` answers**: the major is bits 8 to 19 of the number, the minor is its
low 8 bits and its bits 20 to 31 moved down by 12; it always returns. -/
theorem major_minor_answers (encoded : Std.U32) :
    major_minor encoded ⦃ p =>
      p.1.bv = (encoded.bv >>> 8) &&& 4095#32 ∧
      p.2.bv = (encoded.bv &&& 255#32) ||| ((encoded.bv >>> 12) &&& 1048320#32) ⦄ := by
  unfold major_minor
  step as ⟨ i, is_i, bv1 ⟩
  step as ⟨ i1, is_i1, bv2 ⟩
  step as ⟨ i2, is_i2, bv3 ⟩
  step as ⟨ i3, is_i3, bv4 ⟩
  step as ⟨ i4, is_i4, bv5 ⟩
  step as ⟨ i5, is_i5, bv6 ⟩
  simp [bv2, bv1, bv6, bv3, bv5, bv4]

/-- A statement that holds at each of the 32 places holds at every place below 32. -/
theorem at_every_place (P : Nat → Prop) (each :
    P 0 ∧ P 1 ∧ P 2 ∧ P 3 ∧ P 4 ∧ P 5 ∧ P 6 ∧ P 7 ∧
    P 8 ∧ P 9 ∧ P 10 ∧ P 11 ∧ P 12 ∧ P 13 ∧ P 14 ∧ P 15 ∧
    P 16 ∧ P 17 ∧ P 18 ∧ P 19 ∧ P 20 ∧ P 21 ∧ P 22 ∧ P 23 ∧
    P 24 ∧ P 25 ∧ P 26 ∧ P 27 ∧ P 28 ∧ P 29 ∧ P 30 ∧ P 31) :
    ∀ i, i < 32 → P i := by
  intro i hi
  have places :
    i = 0 ∨ i = 1 ∨ i = 2 ∨ i = 3 ∨ i = 4 ∨ i = 5 ∨ i = 6 ∨ i = 7 ∨
    i = 8 ∨ i = 9 ∨ i = 10 ∨ i = 11 ∨ i = 12 ∨ i = 13 ∨ i = 14 ∨ i = 15 ∨
    i = 16 ∨ i = 17 ∨ i = 18 ∨ i = 19 ∨ i = 20 ∨ i = 21 ∨ i = 22 ∨ i = 23 ∨
    i = 24 ∨ i = 25 ∨ i = 26 ∨ i = 27 ∨ i = 28 ∨ i = 29 ∨ i = 30 ∨ i = 31 := by omega
  obtain ⟨p0, p1, p2, p3, p4, p5, p6, p7, p8, p9, p10, p11, p12, p13, p14, p15, p16, p17, p18, p19, p20, p21, p22, p23, p24, p25, p26, p27, p28, p29, p30, p31⟩ := each
  rcases places with
    rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl |
    rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl |
    rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl |
    rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl
  all_goals assumption

/-- Two 32-bit numbers are equal when they agree at each of the 32 places. -/
theorem equal_at_each_place (x y : BitVec 32) (each :
    x.getLsbD 0 = y.getLsbD 0 ∧ x.getLsbD 1 = y.getLsbD 1 ∧ x.getLsbD 2 = y.getLsbD 2 ∧ x.getLsbD 3 = y.getLsbD 3 ∧
    x.getLsbD 4 = y.getLsbD 4 ∧ x.getLsbD 5 = y.getLsbD 5 ∧ x.getLsbD 6 = y.getLsbD 6 ∧ x.getLsbD 7 = y.getLsbD 7 ∧
    x.getLsbD 8 = y.getLsbD 8 ∧ x.getLsbD 9 = y.getLsbD 9 ∧ x.getLsbD 10 = y.getLsbD 10 ∧ x.getLsbD 11 = y.getLsbD 11 ∧
    x.getLsbD 12 = y.getLsbD 12 ∧ x.getLsbD 13 = y.getLsbD 13 ∧ x.getLsbD 14 = y.getLsbD 14 ∧ x.getLsbD 15 = y.getLsbD 15 ∧
    x.getLsbD 16 = y.getLsbD 16 ∧ x.getLsbD 17 = y.getLsbD 17 ∧ x.getLsbD 18 = y.getLsbD 18 ∧ x.getLsbD 19 = y.getLsbD 19 ∧
    x.getLsbD 20 = y.getLsbD 20 ∧ x.getLsbD 21 = y.getLsbD 21 ∧ x.getLsbD 22 = y.getLsbD 22 ∧ x.getLsbD 23 = y.getLsbD 23 ∧
    x.getLsbD 24 = y.getLsbD 24 ∧ x.getLsbD 25 = y.getLsbD 25 ∧ x.getLsbD 26 = y.getLsbD 26 ∧ x.getLsbD 27 = y.getLsbD 27 ∧
    x.getLsbD 28 = y.getLsbD 28 ∧ x.getLsbD 29 = y.getLsbD 29 ∧ x.getLsbD 30 = y.getLsbD 30 ∧ x.getLsbD 31 = y.getLsbD 31) :
    x = y := by
  apply BitVec.eq_of_getLsbD_eq
  intro i hi
  exact at_every_place (fun k => x.getLsbD k = y.getLsbD k) each i hi

/-- A number below `2 ^ k` has no bit set from the place `k` on. -/
theorem no_bit_above (x : BitVec 32) (k : Nat) (small : x.toNat < 2 ^ k) (j : Nat) (hj : j < 32)
    (above : k ≤ j) : x[j] = false := by
  rw [← BitVec.getLsbD_eq_getElem, ← BitVec.testBit_toNat]
  exact Nat.testBit_lt_two_pow (lt_of_lt_of_le small (Nat.pow_le_pow_right (by omega) above))

/-- The major is what is left of the number `rdev` builds, bits 8 to 19, when the major and the
minor fit. -/
theorem the_major_comes_back (major minor : BitVec 32) (major_fits : major.toNat < 2 ^ 12)
    (minor_fits : minor.toNat < 2 ^ 20) :
    ((((minor &&& 255#32) ||| (major <<< 8) ||| ((minor &&& 1048320#32) <<< 12)) >>> 8) &&&
      4095#32) = major := by
  have major_high := no_bit_above major 12 major_fits
  have minor_high := no_bit_above minor 20 minor_fits
  apply equal_at_each_place
  and_intros <;> simp [major_high, minor_high]

/-- The minor is what is left of the number `rdev` builds, bits 0 to 7 and 20 to 31, when the major
and the minor fit. -/
theorem the_minor_comes_back (major minor : BitVec 32) (major_fits : major.toNat < 2 ^ 12)
    (minor_fits : minor.toNat < 2 ^ 20) :
    ((((minor &&& 255#32) ||| (major <<< 8) ||| ((minor &&& 1048320#32) <<< 12)) &&& 255#32) |||
      ((((minor &&& 255#32) ||| (major <<< 8) ||| ((minor &&& 1048320#32) <<< 12)) >>> 12) &&&
        1048320#32)) = minor := by
  have major_high := no_bit_above major 12 major_fits
  have minor_high := no_bit_above minor 20 minor_fits
  apply equal_at_each_place
  and_intros <;> simp [major_high, minor_high]

/-- Every number is built from the major and the minor it is decoded to. -/
theorem every_number_is_built (x : BitVec 32) :
    (((x &&& 255#32) ||| ((x >>> 12) &&& 1048320#32)) &&& 255#32) |||
        ((((x >>> 8) &&& 4095#32) <<< 8)) |||
      ((((x &&& 255#32) ||| ((x >>> 12) &&& 1048320#32)) &&& 1048320#32) <<< 12) = x := by
  apply equal_at_each_place
  and_intros <;> simp

/-- What `major_minor` decodes is below 4096 and below 2^20. -/
theorem the_decoded_numbers_fit (x : BitVec 32) :
    ((x >>> 8) &&& 4095#32).toNat < 4096 ∧
      ((x &&& 255#32) ||| ((x >>> 12) &&& 1048320#32)).toNat < 2 ^ 20 := by
  constructor
  · rw [BitVec.toNat_and]
    exact lt_of_le_of_lt Nat.and_le_right (by decide)
  · rw [BitVec.toNat_or, BitVec.toNat_and, BitVec.toNat_and]
    exact Nat.or_lt_two_pow (Nat.and_lt_two_pow _ (by decide)) (Nat.and_lt_two_pow _ (by decide))

end OverlayCore
