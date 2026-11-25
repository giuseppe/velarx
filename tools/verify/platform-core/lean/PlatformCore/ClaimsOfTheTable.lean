-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: the proofs of the two claims of Spec.lean about the table of acceptable
-- platforms: `WantedVariantIsTheTable` and `RankIsThePlaceInTheTable`.
-- Why it is needed: Theorems.lean ties each claim to its proof; these two are the theorems of
-- TheAcceptableVariants.lean and TheRankOfAnEntry.lean.
-- Read before this file: Spec.lean.
import PlatformCore.TheBestOfAPart

open Aeneas Aeneas.Std Result velarx_platform_core

namespace PlatformCore

/-- `wanted_variant` answers the table: `wanted_variant_answers_the_table`. -/
theorem wanted_variant_is_the_table : WantedVariantIsTheTable :=
  fun arch variant k room => wanted_variant_answers_the_table arch variant k room

/-- `rank` is the place in the table: `rank_answers`. -/
theorem rank_is_the_place_in_the_table : RankIsThePlaceInTheTable :=
  fun entry want => rank_answers entry want

end PlatformCore
