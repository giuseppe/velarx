-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: the proof of `WorkedExamples` of Spec.lean: the names and the devices of the tests of the
-- crate, each answered as the claims say.
-- Why it is needed: the examples show that the claims give the answers a reader expects; they are not run on
-- the code but worked out from `class_answers` and `rdev_answers`.
-- Read before this file: Spec.lean, ClaimsOfTheNames.lean, ClaimsOfTheDevices.lean.
-- Notation: `decide` computes a statement about fixed lists and fixed 32-bit numbers.
import OverlayCore.ClaimsOfTheDevices
open Aeneas Aeneas.Std Result velarx_overlay_core
namespace OverlayCore

/-- Proof of `WorkedExamples`: the names are computed to be what the five statements of
`class_answers` ask for, and the numbers are the ones `rdev_answers` builds. -/
theorem worked_examples : WorkedExamples := by
  refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩
  · intro attr is_it
    refine WP.spec_mono (class_answers attr) ?_
    intro c answers
    refine (plain_iff attr.val c answers).mpr ?_
    rw [is_it]
    refine ⟨by decide, by decide, by decide, ?_, by decide⟩
    unfold OverlayName; decide
  · intro attr is_it
    refine WP.spec_mono (class_answers attr) ?_
    intro c answers
    refine (plain_iff attr.val c answers).mpr ?_
    rw [is_it]
    refine ⟨by decide, by decide, by decide, ?_, by decide⟩
    unfold OverlayName; decide
  · intro attr is_it
    refine WP.spec_mono (class_answers attr) ?_
    intro c ⟨_, _, _, overlay, _⟩
    refine overlay.mpr ⟨by rw [is_it]; decide, ?_⟩
    rw [is_it]; unfold OverlayName; decide
  · intro attr is_it
    refine WP.spec_mono (class_answers attr) ?_
    intro c ⟨_, _, _, overlay, _⟩
    refine overlay.mpr ⟨by rw [is_it]; decide, ?_⟩
    rw [is_it]; unfold OverlayName; decide
  · intro attr is_it
    refine WP.spec_mono (class_answers attr) ?_
    intro c ⟨_, _, _, _, label⟩
    exact label.mpr is_it
  · intro attr is_it
    refine WP.spec_mono (class_answers attr) ?_
    intro c ⟨_, _, no_name, _, _⟩
    exact no_name.mpr (by rw [is_it]; decide)
  · intro attr is_it
    refine WP.spec_mono (class_answers attr) ?_
    intro c ⟨empty, _⟩
    exact empty.mpr is_it
  · refine WP.spec_mono (rdev_answers 8#u32 1#u32) ?_
    intro r ⟨fits, enc⟩
    obtain ⟨y, is_y⟩ := Option.ne_none_iff_exists'.mp (fits.mpr ⟨by decide, by decide⟩)
    have encoded := enc y is_y
    rw [is_y]; congr 1
    rw [Std.UScalar.eq_equiv_bv_eq]
    have major_bv : U32.bv 8#u32 = 8#32 := rfl
    have minor_bv : U32.bv 1#u32 = 1#32 := rfl
    have result_bv : U32.bv 2049#u32 = 2049#32 := rfl
    show y.bv = U32.bv _
    rw [major_bv, minor_bv] at encoded
    rw [result_bv, encoded]; decide
  · refine WP.spec_mono (rdev_answers 4096#u32 0#u32) ?_
    intro r ⟨fits, _⟩
    by_contra there
    have := (fits.mp there).1
    simp at this
  · refine WP.spec_mono (rdev_answers 0#u32 1048576#u32) ?_
    intro r ⟨fits, _⟩
    by_contra there
    have := (fits.mp there).2
    simp at this
  · refine WP.spec_mono (rdev_answers 4095#u32 1048575#u32) ?_
    intro r ⟨fits, enc⟩
    obtain ⟨y, is_y⟩ := Option.ne_none_iff_exists'.mp (fits.mpr ⟨by decide, by decide⟩)
    have encoded := enc y is_y
    rw [is_y]; congr 1
    rw [Std.UScalar.eq_equiv_bv_eq]
    have major_bv : U32.bv 4095#u32 = 4095#32 := rfl
    have minor_bv : U32.bv 1048575#u32 = 1048575#32 := rfl
    have result_bv : U32.bv 4294967295#u32 = 4294967295#32 := rfl
    show y.bv = U32.bv _
    rw [major_bv, minor_bv] at encoded
    rw [result_bv, encoded]; decide

end OverlayCore
