-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: the proofs of the claim about `strict` and of the worked examples of
--    Spec.lean.
-- Why it is needed: Theorems.lean lists them.
-- Read before this file: ClaimsOfPairs.lean, TheStrict.lean.
-- Notation: `⦃ ⦄` as in ThePair.lean.
import McsCore.ClaimsOfPairs
import McsCore.TheColons
import McsCore.TheStrict
open Aeneas Aeneas.Std Result velarx_mcs_core
namespace McsCore

/-- Proof of `StrictMeansWhatItSays`. -/
theorem strict_means_what_it_says : StrictMeansWhatItSays := by
  intro level small
  exact strict_spec level small

/-- Proof of `WorkedExamples`. -/
theorem worked_examples : WorkedExamples := by
  have z1 : (1#u16).val = 1 := rfl
  have z2 : (2#u16).val = 2 := rfl
  have text12 : PairText 1 2 = Text "s0:c1,c2" := by
    unfold PairText Text; simp [Decimal, digitByte]
  refine ⟨?_, ?_, ?_, ?_⟩
  · refine WP.spec_mono (pair_label_spec 1#u16 2#u16) ?_
    rintro r ⟨iff1, bytes1⟩
    cases r with
    | none => exact absurd (iff1.mp rfl) (by simp [z1, z2])
    | some label =>
      refine ⟨label, rfl, ?_⟩
      refine WP.spec_mono (bytes1 label rfl) ?_
      intro b hb
      rw [z1, z2, text12] at hb
      refine ⟨hb, ?_⟩
      refine WP.spec_mono (read_pair_spec b) ?_
      rintro p ⟨-, again⟩
      exact again 1#u16 2#u16 (by rw [z1, z2, text12]; exact hb) (by rw [z1, z2]; omega) (by rw [z2]; omega)
  · intro level hl
    refine WP.spec_mono (parse_spec level) ?_
    rintro r ⟨complete, -⟩
    have lvl : Level level.val (fun c => c = 1 ∨ c = 2) := by
      rw [hl, ← text12]; exact pair_text_level 1 2 (by omega) (by omega)
    obtain ⟨cats, hr, mem⟩ := complete _ lvl
    exact ⟨cats, hr, fun c => (in_iff_mem cats c).trans (mem c)⟩
  · intro level hl
    refine WP.spec_mono (ranges_are_exact 0 1023 level (by omega) (by omega) ?_ ) ?_
    · rw [hl]; unfold Text; simp [Decimal, digitByte]
    · rintro r ⟨cats, hr, mem⟩
      exact ⟨cats, hr, fun c => (mem c).trans (by omega)⟩
  · intro level hl
    refine WP.spec_mono (parse_spec level) ?_
    rintro r ⟨complete, -⟩
    have sens : Sens (Text "s0") :=
      Sens.first ⟨[48#u8], by rw [text_s]; decide, by simp, by
        intro d hd; simp at hd; rw [hd]; exact ⟨by decide, by decide⟩⟩
    have lvl : Level level.val (fun _ => False) := by rw [hl]; exact Level.plain sens
    obtain ⟨cats, hr, mem⟩ := complete _ lvl
    exact ⟨cats, hr, fun c h => (mem c |>.mp ((in_iff_mem cats c).mp h)).elim⟩

end McsCore
