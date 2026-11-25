-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: the list of what is proved of crates/recv-core.  The statements are in
-- RecvCore/Spec.lean, the proofs in the other files of RecvCore/ (the ones named Claims..., which use
-- the files before them).
-- ../../run ends on this file: it fails unless every line `#proved T` below prints "proved: T".
--
-- Why it is needed: Lean checks a proof when it is read, but nothing says that the theorem is the
-- one of the statement or that no `sorry` or new axiom is behind it.  `#proved T`
-- (../../Proved.lean) prints the axioms `T` rests on and fails unless they are the three of Lean
-- and the library functions the crate has no model of (the run prints none for this crate).
--
-- Read before this file: RecvCore/Spec.lean.
import Proved
import RecvCore.ClaimsOfExamples

-- Each theorem is a proof of the statement of that name in Spec.lean: Lean checks the type of each
-- line below, so Theorems.lean and Spec.lean suffice.
example : RecvCore.TheFunctionsAlwaysReturn :=
  RecvCore.the_functions_always_return
#proved RecvCore.the_functions_always_return
example : RecvCore.WhatTheStatusBytesSay :=
  RecvCore.what_the_status_bytes_say
#proved RecvCore.what_the_status_bytes_say
example : RecvCore.WhatRoomSaysExactly :=
  RecvCore.what_room_says_exactly
#proved RecvCore.what_room_says_exactly
example : RecvCore.WhatTakeAcceptsExactly :=
  RecvCore.what_take_accepts_exactly
#proved RecvCore.what_take_accepts_exactly
example : RecvCore.TheBoundsOfAnAnswerHold :=
  RecvCore.the_bounds_of_an_answer_hold
#proved RecvCore.the_bounds_of_an_answer_hold
example : RecvCore.TheTurnsAreThoseAsked :=
  RecvCore.the_turns_are_those_asked
#proved RecvCore.the_turns_are_those_asked
example : RecvCore.EveryDigestAskedHasOneTurn :=
  RecvCore.every_digest_asked_has_one_turn
#proved RecvCore.every_digest_asked_has_one_turn
example : RecvCore.AnAnswerThatEndedGivesNoTurn :=
  RecvCore.an_answer_that_ended_gives_no_turn
#proved RecvCore.an_answer_that_ended_gives_no_turn
example : RecvCore.ACorrectPeerIsAlwaysTaken :=
  RecvCore.a_correct_peer_is_always_taken
#proved RecvCore.a_correct_peer_is_always_taken
example : RecvCore.WhatAnItemIsTakenExactly :=
  RecvCore.what_an_item_is_taken_exactly
#proved RecvCore.what_an_item_is_taken_exactly
example : RecvCore.TheSizesOfAFilter :=
  RecvCore.the_sizes_of_a_filter
#proved RecvCore.the_sizes_of_a_filter
example : RecvCore.AFilterTextOfAnyAllowedSizeIsAccepted :=
  RecvCore.a_filter_text_of_any_allowed_size_is_accepted
#proved RecvCore.a_filter_text_of_any_allowed_size_is_accepted
example : RecvCore.WhatAWholeFilterDoes :=
  RecvCore.what_a_whole_filter_does
#proved RecvCore.what_a_whole_filter_does
example : RecvCore.WhatADeltaDoes :=
  RecvCore.what_a_delta_does
#proved RecvCore.what_a_delta_does
example : RecvCore.WhatAddedDoes :=
  RecvCore.what_added_does
#proved RecvCore.what_added_does
example : RecvCore.WhatSaysAnswersExactly :=
  RecvCore.what_says_answers_exactly
#proved RecvCore.what_says_answers_exactly
example : RecvCore.ADeltaThatDoesNotFollowLeavesTheFilterBehind :=
  RecvCore.a_delta_that_does_not_follow_leaves_the_filter_behind
#proved RecvCore.a_delta_that_does_not_follow_leaves_the_filter_behind
example : RecvCore.AWholeFilterThenItsDeltasKeepTheFilterCurrent :=
  RecvCore.a_whole_filter_then_its_deltas_keep_the_filter_current
#proved RecvCore.a_whole_filter_then_its_deltas_keep_the_filter_current
example : RecvCore.AFilterThatSaysNoIsAWholeFilterAndTheDeltasThatFollowedIt :=
  RecvCore.a_filter_that_says_no_is_a_whole_filter_and_the_deltas_that_followed_it
#proved RecvCore.a_filter_that_says_no_is_a_whole_filter_and_the_deltas_that_followed_it
example : RecvCore.TheWorkedExamples :=
  RecvCore.the_worked_examples
#proved RecvCore.the_worked_examples
