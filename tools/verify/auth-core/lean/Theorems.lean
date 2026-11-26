-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: the list of what is proved of crates/auth-core.  The statements are in
-- AuthCore/Spec.lean, the proofs in the other files of AuthCore/ (TheClaims.lean has the ones that
-- put the answers of the functions together; the others are one function each).
-- ../../run ends on this file: it fails unless every line `#proved T` below prints "proved: T".
--
-- Why it is needed: Lean checks a proof when it is read, but nothing says that the theorem is the
-- one of the statement or that no `sorry` or new axiom is behind it.  `#proved T`
-- (../../Proved.lean) prints the axioms `T` rests on and fails unless they are the three of Lean
-- and the library functions the crate has no model of (the run prints none for this crate).
--
-- Read before this file: AuthCore/Spec.lean.
import Proved
import AuthCore.TheClaims
import AuthCore.TheNormalizeTwice
import AuthCore.TheExamples

-- Each theorem is a proof of the statement of that name in Spec.lean: Lean checks the type of each
-- line below, so Theorems.lean and Spec.lean suffice.
example : AuthCore.EveryFunctionReturns :=
  AuthCore.every_function_returns
#proved AuthCore.every_function_returns
example : AuthCore.MatchesIsExactlyTheDefinition :=
  AuthCore.matches_is_exactly_the_definition
#proved AuthCore.matches_is_exactly_the_definition
example : AuthCore.AKeyIsForItsHostOnly :=
  AuthCore.a_key_is_for_its_host_only
#proved AuthCore.a_key_is_for_its_host_only
example : AuthCore.HubAliasIsTheTwoOtherNames :=
  AuthCore.hub_alias_is_the_two_other_names
#proved AuthCore.hub_alias_is_the_two_other_names
example : AuthCore.TheHubIsOneHost :=
  AuthCore.the_hub_is_one_host
#proved AuthCore.the_hub_is_one_host
example : AuthCore.AHubNameWithAPortIsNotTheHub :=
  AuthCore.a_hub_name_with_a_port_is_not_the_hub
#proved AuthCore.a_hub_name_with_a_port_is_not_the_hub
example : AuthCore.PickIsTheMostSpecificKey :=
  AuthCore.pick_is_the_most_specific_key
#proved AuthCore.pick_is_the_most_specific_key
example : AuthCore.ExactIsTheHostAlone :=
  AuthCore.exact_is_the_host_alone
#proved AuthCore.exact_is_the_host_alone
example : AuthCore.NormalizeIsTheRuleOfTheKey :=
  AuthCore.normalize_is_the_rule_of_the_key
#proved AuthCore.normalize_is_the_rule_of_the_key
example : AuthCore.NormalizeTwiceIsNormalize :=
  AuthCore.normalize_twice_is_normalize
#proved AuthCore.normalize_twice_is_normalize
example : AuthCore.AWebKeyIsItsHost :=
  AuthCore.a_web_key_is_its_host
#proved AuthCore.a_web_key_is_its_host
example : AuthCore.WorkedExamples :=
  AuthCore.worked_examples
#proved AuthCore.worked_examples
