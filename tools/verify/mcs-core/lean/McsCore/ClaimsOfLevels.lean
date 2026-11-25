-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: the proofs of the claims about `parse`, `contains` and `overlap` of
--    Spec.lean.
-- Why it is needed: Theorems.lean lists them.
-- Read before this file: TheParse.lean, TheOverlap.lean.
-- Notation: `In cats c`: the category `c` is in the set.
import McsCore.TheOverlap
import McsCore.TheReadPair
open Aeneas Aeneas.Std Result velarx_mcs_core
namespace McsCore

/-- The category is in the set exactly when its bit is. -/
theorem in_iff_mem (cats : Cats) (c : Nat) : In cats c ↔ Mem cats c := by
  constructor
  · rintro ⟨u, rfl, h⟩
    obtain ⟨b, hb, hiff⟩ := spec_returns (has_spec cats u)
    rw [hb] at h
    have := Result.ok_injective h
    subst this
    exact hiff.mp rfl
  · intro m
    have lt : c < 1024 := m.1
    refine ⟨⟨BitVec.ofNat 16 c⟩, ?_, ?_⟩
    · simp [UScalar.val, BitVec.toNat_ofNat]; omega
    · obtain ⟨b, hb, hiff⟩ := spec_returns (has_spec cats ⟨BitVec.ofNat 16 c⟩)
      rw [hb]
      have : b = true := hiff.mpr (by
        have : (⟨BitVec.ofNat 16 c⟩ : Std.U16).val = c := by
          simp [UScalar.val, BitVec.toNat_ofNat]; omega
        rw [this]; exact m)
      rw [this]

/-- Proof of `ParseIsExactlyTheLevels`. -/
theorem parse_is_exactly_the_levels : ParseIsExactlyTheLevels := by
  intro level
  refine WP.spec_mono (parse_spec level) ?_
  rintro r ⟨complete, sound⟩
  refine ⟨fun S lvl => ?_, fun cats hc => ?_⟩
  · obtain ⟨cats, hr, mem⟩ := complete S lvl
    exact ⟨cats, hr, fun c => (in_iff_mem cats c).trans (mem c)⟩
  · obtain ⟨S, lvl, mem⟩ := sound cats hc
    exact ⟨S, lvl, fun c => (in_iff_mem cats c).trans (mem c)⟩

/-- Proof of `NoCategoryBeyond1023`. -/
theorem no_category_beyond_1023 : NoCategoryBeyond1023 := by
  intro level
  refine WP.spec_mono (parse_spec level) ?_
  rintro r ⟨_, sound⟩ cats hc c hin
  obtain ⟨S, _, mem⟩ := sound cats hc
  exact ((in_iff_mem cats c).mp hin).1

/-- Proof of `RangesAreExact`. -/
theorem ranges_are_exact : RangesAreExact := by
  intro a b level le small text
  refine WP.spec_mono (parse_spec level) ?_
  rintro r ⟨complete, _⟩
  have cat1 : CatText (Text "c" ++ Decimal a) a :=
    ⟨Decimal a, rfl, decimal_ne_nil a, decimal_digits a, decimal_value a, by omega⟩
  have cat2 : CatText (Text "c" ++ Decimal b) b :=
    ⟨Decimal b, rfl, decimal_ne_nil b, decimal_digits b, decimal_value b, small⟩
  have sens : Sens (Text "s0") :=
    Sens.first ⟨[48#u8], by rw [text_s]; decide, by simp, by
      intro d hd; simp at hd; rw [hd]; exact ⟨by decide, by decide⟩⟩
  have lvl := Level.categories sens (Items.last (Item.range cat1 cat2 le))
  have eq : level.val = Text "s0" ++ Text ":" ++
      (Text "c" ++ Decimal a ++ Text "." ++ (Text "c" ++ Decimal b)) := by
    rw [text]
    have h1 : Text "s0:c" = Text "s0" ++ Text ":" ++ Text "c" := by decide
    have h2 : Text ".c" = Text "." ++ Text "c" := by decide
    rw [h1, h2]; simp
  rw [eq] at complete
  obtain ⟨cats, hr, mem⟩ := complete _ lvl
  exact ⟨cats, hr, fun c => (in_iff_mem cats c).trans (mem c)⟩

/-- Proof of `ContainsMeansWhatItSays`. -/
theorem contains_means_what_it_says : ContainsMeansWhatItSays := by
  intro outer inner
  exact contains_spec outer inner

/-- Proof of `OverlapMeansWhatItSays`. -/
theorem overlap_means_what_it_says : OverlapMeansWhatItSays := by
  intro a b
  exact overlap_spec a b

/-- Proof of `OverlapIsSymmetric`. -/
theorem overlap_is_symmetric : OverlapIsSymmetric := by
  intro a b
  refine WP.spec_mono (overlap_spec a b) ?_
  intro r hr
  refine WP.spec_mono (overlap_spec b a) ?_
  intro r' hr'
  have sym : Reach a.val b.val ↔ Reach b.val a.val := by
    unfold Reach
    constructor
    · rintro ((h | h) | ⟨S, T, la, lb, ne1, ne2, sub⟩)
      · exact Or.inl (Or.inr h)
      · exact Or.inl (Or.inl h)
      · exact Or.inr ⟨T, S, lb, la, ne2, ne1, sub.symm⟩
    · rintro ((h | h) | ⟨S, T, la, lb, ne1, ne2, sub⟩)
      · exact Or.inl (Or.inr h)
      · exact Or.inl (Or.inl h)
      · exact Or.inr ⟨T, S, lb, la, ne2, ne1, sub.symm⟩
  rw [Bool.eq_iff_iff, hr, hr']
  exact sym

end McsCore
