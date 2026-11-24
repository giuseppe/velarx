-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: the list of what is proved of crates/endpoint-core.  The statements are in
-- EndpointCore/Spec.lean; the proofs are in EndpointCore/ClaimsOf*.lean, which use what the other
-- files of EndpointCore/ say of the loops and the functions of the crate.
-- ../../run ends on this file: it fails unless every line `#proved T` below prints "proved: T".
--
-- Why it is needed: Lean checks a proof when it is read, but nothing says that the theorem is the
-- one of the statement or that no `sorry` or new axiom is behind it.  `#proved T`
-- (../../Proved.lean) prints the axioms `T` rests on and fails unless they are the three of Lean
-- and the library functions the crate has no model of (there are none: Models.lean is empty).
--
-- Read before this file: EndpointCore/Spec.lean.
import Proved
import EndpointCore.ClaimsOfSelect
import EndpointCore.ClaimsOfTheEndpoints
import EndpointCore.ClaimsOfExamples

-- Each theorem is a proof of the statement of that name in Spec.lean: Lean checks the type of each
-- line below, so Theorems.lean and Spec.lean suffice.
example : EndpointCore.SelectAndEndpointsAlwaysReturn :=
  EndpointCore.select_and_endpoints_always_return
example : EndpointCore.SelectReturnsTheBlockChosen :=
  EndpointCore.select_returns_the_block_chosen
example : EndpointCore.NoBlockIsChosenWithoutABoundary :=
  EndpointCore.no_block_is_chosen_without_a_boundary
example : EndpointCore.CommandLineCredentialsAreForTheHostNamed :=
  EndpointCore.command_line_credentials_are_for_the_host_named
example : EndpointCore.TheListIsTheListedMirrorsThenTheRegistry :=
  EndpointCore.the_list_is_the_listed_mirrors_then_the_registry
example : EndpointCore.FlagsAreTheirOwn :=
  EndpointCore.flags_are_their_own
example : EndpointCore.ByDigestIsForADigestMirror :=
  EndpointCore.by_digest_is_for_a_digest_mirror
example : EndpointCore.BlockedIsRefusedExactly :=
  EndpointCore.blocked_is_refused_exactly
example : EndpointCore.NoRepositoryIsRefusedExactly :=
  EndpointCore.no_repository_is_refused_exactly
example : EndpointCore.OtherwiseAListIsAnswered :=
  EndpointCore.otherwise_a_list_is_answered
example : EndpointCore.AnAnswerIsNeverEmpty :=
  EndpointCore.an_answer_is_never_empty
example : EndpointCore.WorkedExamples :=
  EndpointCore.worked_examples

#proved EndpointCore.select_and_endpoints_always_return
#proved EndpointCore.select_returns_the_block_chosen
#proved EndpointCore.no_block_is_chosen_without_a_boundary
#proved EndpointCore.command_line_credentials_are_for_the_host_named
#proved EndpointCore.the_list_is_the_listed_mirrors_then_the_registry
#proved EndpointCore.flags_are_their_own
#proved EndpointCore.by_digest_is_for_a_digest_mirror
#proved EndpointCore.blocked_is_refused_exactly
#proved EndpointCore.no_repository_is_refused_exactly
#proved EndpointCore.otherwise_a_list_is_answered
#proved EndpointCore.an_answer_is_never_empty
#proved EndpointCore.worked_examples
