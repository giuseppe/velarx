-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: the list of what is proved of the model of the inline threshold.
-- The statements are in InlineModel/Spec.lean, the proofs in InlineModel/Claims.lean (which
-- uses the files before it in InlineModel/).
-- ../../run ends on this file: it fails unless every line `#proved T` below
-- prints "proved: T".
--
-- Why it is needed: Lean checks a proof when it is read, but nothing
-- says that the theorem is the one of the statement or that no `sorry`
-- or new axiom is behind it.  `#proved T` (../../Proved.lean) prints the
-- axioms `T` rests on and fails unless they are the three of Lean (the model has no
-- function of the standard library that it assumes anything of).
--
-- Read before this file: InlineModel/Spec.lean.
import Proved
import InlineModel.Claims

-- Each theorem is a proof of the statement of that name in Spec.lean: Lean
-- checks the type of each line below, so Theorems.lean and Spec.lean suffice.
example : InlineModel.NothingAtZero :=
  InlineModel.nothing_at_zero
example : InlineModel.EveryFileAtMinusOne :=
  InlineModel.every_file_at_minus_one
example : InlineModel.UpToAndIncludingN :=
  InlineModel.up_to_and_including_n
example : InlineModel.ExtentsAreTheHeldFiles :=
  InlineModel.extents_are_the_held_files
example : InlineModel.ZeroIsTheImageOfToday :=
  InlineModel.zero_is_the_image_of_today
example : InlineModel.TheThresholdIsInclusive :=
  InlineModel.the_threshold_is_inclusive
example : InlineModel.ExtentsAreInTheImage :=
  InlineModel.extents_are_in_the_image
example : InlineModel.ExtentsDoNotOverlap :=
  InlineModel.extents_do_not_overlap
example : InlineModel.ExtentsKeepTheirBytes :=
  InlineModel.extents_keep_their_bytes
example : InlineModel.TheBlockRules :=
  InlineModel.the_block_rules
example : InlineModel.TheWriterNeverGoesBack :=
  InlineModel.the_writer_never_goes_back
example : InlineModel.TheTableHasEachDigestOnce :=
  InlineModel.the_table_has_each_digest_once
example : InlineModel.TheRowIsTheFirstExtent :=
  InlineModel.the_row_is_the_first_extent
example : InlineModel.AnObjectBeatsAnExtent :=
  InlineModel.an_object_beats_an_extent
example : InlineModel.FirstStoreWins :=
  InlineModel.first_store_wins
example : InlineModel.FirstRowWins :=
  InlineModel.first_row_wins
example : InlineModel.AnAnswerIsHeld :=
  InlineModel.an_answer_is_held
example : InlineModel.NoAnswerMeansNothingIsHeld :=
  InlineModel.no_answer_means_nothing_is_held

#proved InlineModel.nothing_at_zero
#proved InlineModel.every_file_at_minus_one
#proved InlineModel.up_to_and_including_n
#proved InlineModel.extents_are_the_held_files
#proved InlineModel.zero_is_the_image_of_today
#proved InlineModel.the_threshold_is_inclusive
#proved InlineModel.extents_are_in_the_image
#proved InlineModel.extents_do_not_overlap
#proved InlineModel.extents_keep_their_bytes
#proved InlineModel.the_block_rules
#proved InlineModel.the_writer_never_goes_back
#proved InlineModel.the_table_has_each_digest_once
#proved InlineModel.the_row_is_the_first_extent
#proved InlineModel.an_object_beats_an_extent
#proved InlineModel.first_store_wins
#proved InlineModel.first_row_wins
#proved InlineModel.an_answer_is_held
#proved InlineModel.no_answer_means_nothing_is_held
