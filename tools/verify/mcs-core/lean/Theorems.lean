-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: the list of what is proved of crates/mcs-core.  The statements are in
-- McsCore/Spec.lean, the proofs in the other files of McsCore/ (the ones named Claims..., which use
-- the files before them).
-- ../../run ends on this file: it fails unless every line `#proved T` below prints "proved: T".
--
-- Why it is needed: Lean checks a proof when it is read, but nothing says that the theorem is the
-- one of the statement or that no `sorry` or new axiom is behind it.  `#proved T`
-- (../../Proved.lean) prints the axioms `T` rests on and fails unless they are the three of Lean
-- and the library functions the crate has no model of (the run prints none for this crate).
--
-- Read before this file: McsCore/Spec.lean.
import Proved
import McsCore.ClaimsOfExamples
import McsCore.ClaimsOfPick
import McsCore.TheColons

-- Each theorem is a proof of the statement of that name in Spec.lean: Lean checks the type of each
-- line below, so Theorems.lean and Spec.lean suffice.
example : McsCore.ParseIsExactlyTheLevels :=
  McsCore.parse_is_exactly_the_levels
#proved McsCore.parse_is_exactly_the_levels
example : McsCore.NoCategoryBeyond1023 :=
  McsCore.no_category_beyond_1023
#proved McsCore.no_category_beyond_1023
example : McsCore.RangesAreExact :=
  McsCore.ranges_are_exact
#proved McsCore.ranges_are_exact
example : McsCore.ContainsMeansWhatItSays :=
  McsCore.contains_means_what_it_says
#proved McsCore.contains_means_what_it_says
example : McsCore.OverlapMeansWhatItSays :=
  McsCore.overlap_means_what_it_says
#proved McsCore.overlap_means_what_it_says
example : McsCore.OverlapIsSymmetric :=
  McsCore.overlap_is_symmetric
#proved McsCore.overlap_is_symmetric
example : McsCore.PairLabelIsTheCanonicalSpelling :=
  McsCore.pair_label_is_the_canonical_spelling
#proved McsCore.pair_label_is_the_canonical_spelling
example : McsCore.ReadPairGivesBackThePair :=
  McsCore.read_pair_gives_back_the_pair
#proved McsCore.read_pair_gives_back_the_pair
example : McsCore.ReadPairTakesOnlyTheCanonicalSpelling :=
  McsCore.read_pair_takes_only_the_canonical_spelling
#proved McsCore.read_pair_takes_only_the_canonical_spelling
example : McsCore.TheFreshLevelIsSeparate :=
  McsCore.the_fresh_level_is_separate
#proved McsCore.the_fresh_level_is_separate
example : McsCore.APairThatReachesNoLevelWins :=
  McsCore.a_pair_that_reaches_no_level_wins
#proved McsCore.a_pair_that_reaches_no_level_wins
example : McsCore.NoneOnlyWhenNoAttemptPasses :=
  McsCore.none_only_when_no_attempt_passes
#proved McsCore.none_only_when_no_attempt_passes
example : McsCore.WithNoLevelInUseALabelIsAnswered :=
  McsCore.with_no_level_in_use_a_label_is_answered
#proved McsCore.with_no_level_in_use_a_label_is_answered
example : McsCore.ContextColonsAreTheFirstThree :=
  McsCore.context_colons_are_the_first_three
#proved McsCore.context_colons_are_the_first_three
example : McsCore.StrictMeansWhatItSays :=
  McsCore.strict_means_what_it_says
#proved McsCore.strict_means_what_it_says
example : McsCore.WorkedExamples :=
  McsCore.worked_examples
#proved McsCore.worked_examples
