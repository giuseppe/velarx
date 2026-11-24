-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: the list of what is proved of crates/request-core.  The statements are in
-- RequestCore/Spec.lean; the proofs are in RequestCore/ClaimsOf*.lean and AlgorithmLengths.lean,
-- which use what the other files of RequestCore/ say of the loop and the functions of the crate.
-- ../../run ends on this file: it fails unless every line `#proved T` below prints "proved: T".
--
-- Why it is needed: Lean checks a proof when it is read, but nothing says that the theorem is the
-- one of the statement or that no `sorry` or new axiom is behind it.  `#proved T`
-- (../../Proved.lean) prints the axioms `T` rests on and fails unless they are the three of Lean
-- and the library functions the crate has no model of (there are none).
--
-- Read before this file: RequestCore/Spec.lean.
import Proved
import RequestCore.ClaimsOfExamples

-- Each theorem is a proof of the statement of that name in Spec.lean: Lean checks the type of each
-- line below, so Theorems.lean and Spec.lean suffice.
example : RequestCore.ParseAlwaysReturns :=
  RequestCore.parse_always_returns
example : RequestCore.DoneIsSaidWhenAHeadBegins :=
  RequestCore.done_is_said_when_a_head_begins
example : RequestCore.ADoneHeadIsAsLongAsItsFieldsSay :=
  RequestCore.a_done_head_is_as_long_as_its_fields_say
example : RequestCore.NeedIsSaidWhenAHeadCanStillBegin :=
  RequestCore.need_is_said_when_a_head_can_still_begin
example : RequestCore.NeedAsksForMoreButNoMoreThanAHeadTakes :=
  RequestCore.need_asks_for_more_but_no_more_than_a_head_takes
example : RequestCore.BadIsSaidWhenNoHeadCanBegin :=
  RequestCore.bad_is_said_when_no_head_can_begin
example : RequestCore.AnUnknownAlgorithmIsRefused :=
  RequestCore.an_unknown_algorithm_is_refused
example : RequestCore.AlgLenIsTheTable :=
  RequestCore.alg_len_is_the_table
example : RequestCore.MostIsTheLongestHead :=
  RequestCore.most_is_the_longest_head
example : RequestCore.WorkedExamples :=
  RequestCore.worked_examples

#proved RequestCore.parse_always_returns
#proved RequestCore.done_is_said_when_a_head_begins
#proved RequestCore.a_done_head_is_as_long_as_its_fields_say
#proved RequestCore.need_is_said_when_a_head_can_still_begin
#proved RequestCore.need_asks_for_more_but_no_more_than_a_head_takes
#proved RequestCore.bad_is_said_when_no_head_can_begin
#proved RequestCore.an_unknown_algorithm_is_refused
#proved RequestCore.alg_len_is_the_table
#proved RequestCore.most_is_the_longest_head
#proved RequestCore.worked_examples
