-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: the list of what is proved of crates/platform-core.  The statements are in
-- PlatformCore/Spec.lean, the proofs in the other files of PlatformCore/ (the ones named Claims...,
-- which use the files before them).
-- ../../run ends on this file: it fails unless every line `#proved T` below prints "proved: T".
--
-- Why it is needed: Lean checks a proof when it is read, but nothing says that the theorem is the
-- one of the statement or that no `sorry` or new axiom is behind it.  `#proved T`
-- (../../Proved.lean) prints the axioms `T` rests on and fails unless they are the three of Lean
-- and the library functions the crate has no model of (the run prints none for this crate).
--
-- Read before this file: PlatformCore/Spec.lean.
import Proved
import PlatformCore.ClaimsOfExamples

-- Each theorem is a proof of the statement of that name in Spec.lean: Lean checks the type of each
-- line below, so Theorems.lean and Spec.lean suffice.
example : PlatformCore.TheFunctionsAlwaysReturn :=
  PlatformCore.the_functions_always_return
#proved PlatformCore.the_functions_always_return
example : PlatformCore.WantedVariantIsTheTable :=
  PlatformCore.wanted_variant_is_the_table
#proved PlatformCore.wanted_variant_is_the_table
example : PlatformCore.RankIsThePlaceInTheTable :=
  PlatformCore.rank_is_the_place_in_the_table
#proved PlatformCore.rank_is_the_place_in_the_table
example : PlatformCore.TheChosenEntryIsAnAcceptableImage :=
  PlatformCore.the_chosen_entry_is_an_acceptable_image
#proved PlatformCore.the_chosen_entry_is_an_acceptable_image
example : PlatformCore.TheChosenEntryIsTheBestAndTheFirst :=
  PlatformCore.the_chosen_entry_is_the_best_and_the_first
#proved PlatformCore.the_chosen_entry_is_the_best_and_the_first
example : PlatformCore.NothingIsChosenExactlyWhenNothingMatches :=
  PlatformCore.nothing_is_chosen_exactly_when_nothing_matches
#proved PlatformCore.nothing_is_chosen_exactly_when_nothing_matches
example : PlatformCore.WorkedExamples :=
  PlatformCore.worked_examples
#proved PlatformCore.worked_examples
