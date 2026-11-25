-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: the proofs of the claims of Spec.lean about devices: the numbers fit exactly, come back, no two
-- devices share a number, the number 0 is 0:0 only, a whiteout is a character device 0:0.
-- Why it is needed: Theorems.lean names what is proved; the proofs are here, read off `rdev_answers` and
-- `major_minor_answers` (TheDevices.lean).
-- Read before this file: Spec.lean, TheDevices.lean.
-- Notation: `Prod.ext` shows two pairs equal from their two halves; `x.bv` is the 32 bits of the number
-- `x`; `rw` replaces one side of an equation by the other.
import OverlayCore.ClaimsOfTheNames
import OverlayCore.TheDevices
open Aeneas Aeneas.Std Result velarx_overlay_core
namespace OverlayCore

/-- **What `whiteout` answers**: true exactly when the device is a character device 0:0; it always
returns. -/
theorem whiteout_answers (is_char : Bool) (major minor : Std.U32) :
    whiteout is_char major minor ⦃ w =>
      (w = true ↔ is_char = true ∧ major = 0#u32 ∧ minor = 0#u32) ⦄ := by
  unfold whiteout
  by_cases char : is_char = true
  · simp only [char, ite_true]
    by_cases zero_major : major = 0#u32
    · simp only [zero_major, ite_true]
      refine (WP.spec_ok _).mpr ?_
      simp
    · simp only [zero_major, ite_false]
      refine (WP.spec_ok _).mpr ?_
      simp
  · simp only [char, Bool.false_eq_true, ite_false]
    refine (WP.spec_ok _).mpr ?_
    simp

/-- Proof of `TheFunctionsAlwaysReturn`: each of the four functions returns, by the statement of
what it answers. -/
theorem the_functions_always_return : TheFunctionsAlwaysReturn := by
  refine ⟨fun attr => ?_, fun major minor => ?_, fun encoded => ?_, fun is_char major minor => ?_⟩
  · exact WP.spec_mono (class_answers attr) (fun _ _ => trivial)
  · exact WP.spec_mono (rdev_answers major minor) (fun _ _ => trivial)
  · exact WP.spec_mono (major_minor_answers encoded) (fun _ _ => trivial)
  · exact WP.spec_mono (whiteout_answers is_char major minor) (fun _ _ => trivial)

/-- Proof of `DevicesFitExactly`: `rdev_answers` says it. -/
theorem devices_fit_exactly : DevicesFitExactly := by
  intro major minor
  refine WP.spec_mono (rdev_answers major minor) ?_
  intro r ⟨fits, _⟩
  rw [← Option.ne_none_iff_exists', fits]
  norm_num

/-- A major that fits is below 2^12 as a bit vector. -/
theorem major_is_small (major : Std.U32) (fits : major.val < 4096) : major.bv.toNat < 2 ^ 12 := by
  rw [Std.UScalar.bv_toNat]; omega

/-- A minor that fits is below 2^20 as a bit vector. -/
theorem minor_is_small (minor : Std.U32) (fits : minor.val < 1048576) :
    minor.bv.toNat < 2 ^ 20 := by
  rw [Std.UScalar.bv_toNat]; omega

/-- Proof of `TheNumbersComeBack`: the number is built from the major and the minor (they fit),
and the bits of the major and of the minor are still there where `major_minor` reads them. -/
theorem the_numbers_come_back : TheNumbersComeBack := by
  intro major minor
  refine WP.spec_mono (rdev_answers major minor) ?_
  intro r ⟨fits, enc⟩ x is_x
  have ⟨major_fits, minor_fits⟩ := fits.mp (by rw [is_x]; simp)
  have encoded := enc x is_x
  refine WP.spec_mono (major_minor_answers x) ?_
  intro p ⟨first, second⟩
  refine Prod.ext ?_ ?_
  · rw [Std.UScalar.eq_equiv_bv_eq]
    show p.1.bv = major.bv
    rw [first, encoded]
    exact the_major_comes_back _ _ (major_is_small major major_fits) (minor_is_small minor minor_fits)
  · rw [Std.UScalar.eq_equiv_bv_eq]
    show p.2.bv = minor.bv
    rw [second, encoded]
    exact the_minor_comes_back _ _ (major_is_small major major_fits) (minor_is_small minor minor_fits)

/-- Proof of `EveryNumberIsOneDevice`: what `major_minor` gives fits, so `rdev` answers, and the
number it builds is the one decoded, bit for bit. -/
theorem every_number_is_one_device : EveryNumberIsOneDevice := by
  intro x
  refine WP.spec_mono (major_minor_answers x) ?_
  intro p ⟨first, second⟩
  obtain ⟨major_fits, minor_fits⟩ := the_decoded_numbers_fit x.bv
  refine WP.spec_mono (rdev_answers p.1 p.2) ?_
  intro r ⟨fits, enc⟩
  rw [← first] at major_fits
  rw [← second] at minor_fits
  have there : r ≠ none := fits.mpr ⟨major_fits, by norm_num at minor_fits; exact minor_fits⟩
  obtain ⟨y, is_y⟩ := Option.ne_none_iff_exists'.mp there
  have encoded := enc y is_y
  rw [is_y]
  congr 1
  rw [Std.UScalar.eq_equiv_bv_eq]
  show y.bv = x.bv
  rw [encoded, first, second]
  exact every_number_is_built x.bv

/-- Proof of `OnlyDeviceZeroIsNumberZero`: the number built from fitting numbers is 0 exactly when
both are 0: the major and the minor are read back from the number (`the_major_comes_back`). -/
theorem only_device_zero_is_number_zero : OnlyDeviceZeroIsNumberZero := by
  intro major minor
  refine WP.spec_mono (rdev_answers major minor) ?_
  intro r ⟨fits, enc⟩ x is_x
  have ⟨major_fits, minor_fits⟩ := fits.mp (by rw [is_x]; simp)
  have encoded := enc x is_x
  have major_back := the_major_comes_back _ _ (major_is_small major major_fits)
    (minor_is_small minor minor_fits)
  have minor_back := the_minor_comes_back _ _ (major_is_small major major_fits)
    (minor_is_small minor minor_fits)
  rw [← encoded] at major_back minor_back
  rw [whiteout_is_zero, Std.UScalar.eq_equiv_bv_eq, Std.UScalar.eq_equiv_bv_eq,
    Std.UScalar.eq_equiv_bv_eq]
  show x.bv = 0#32 ↔ major.bv = 0#32 ∧ minor.bv = 0#32
  constructor
  · intro zero
    rw [zero] at major_back minor_back
    exact ⟨by rw [← major_back]; simp, by rw [← minor_back]; simp⟩
  · rintro ⟨zero_major, zero_minor⟩
    rw [encoded, zero_major, zero_minor]
    simp

/-- Proof of `TheWhiteoutIsACharacterDeviceZero`: `whiteout_answers`, and the device 0:0 fits and
its number is 0. -/
theorem the_whiteout_is_a_character_device_zero : TheWhiteoutIsACharacterDeviceZero := by
  refine ⟨whiteout_answers, ?_⟩
  refine WP.spec_mono (rdev_answers 0#u32 0#u32) ?_
  intro r ⟨fits, enc⟩
  have there : r ≠ none := fits.mpr ⟨by decide, by decide⟩
  obtain ⟨y, is_y⟩ := Option.ne_none_iff_exists'.mp there
  have encoded := enc y is_y
  rw [is_y, whiteout_is_zero]
  congr 1
  rw [Std.UScalar.eq_equiv_bv_eq]
  simpa using encoded

end OverlayCore
