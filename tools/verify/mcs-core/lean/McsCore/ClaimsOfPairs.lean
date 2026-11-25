-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: the proofs of the claims about `pair_label` and `read_pair` of Spec.lean.
-- Why it is needed: Theorems.lean lists them.
-- Read before this file: ThePair.lean, TheReadPair.lean.
-- Notation: `⦃ ⦄`: see ThePair.lean.
import McsCore.ClaimsOfLevels
import McsCore.ThePick
open Aeneas Aeneas.Std Result velarx_mcs_core
namespace McsCore

/-- Proof of `PairLabelIsTheCanonicalSpelling`. -/
theorem pair_label_is_the_canonical_spelling : PairLabelIsTheCanonicalSpelling := by
  intro low high
  exact pair_label_spec low high

/-- Proof of `ReadPairTakesOnlyTheCanonicalSpelling`. -/
theorem read_pair_takes_only_the_canonical_spelling : ReadPairTakesOnlyTheCanonicalSpelling := by
  intro level
  refine WP.spec_mono (read_pair_spec level) ?_
  exact fun r h => h.1

/-- Proof of `ReadPairGivesBackThePair`. -/
theorem read_pair_gives_back_the_pair : ReadPairGivesBackThePair := by
  intro low high lt1 lt2
  refine WP.spec_mono (pair_label_spec low high) ?_
  rintro r ⟨iff1, bytes1⟩
  cases r with
  | none => exact absurd (iff1.mp rfl) (by simp [lt1, lt2])
  | some label =>
    refine ⟨label, rfl, ?_⟩
    refine WP.spec_mono (bytes1 label rfl) ?_
    intro b hb
    refine WP.spec_mono (read_pair_spec b) ?_
    rintro p ⟨_, again⟩
    exact again low high hb lt1 lt2

end McsCore
