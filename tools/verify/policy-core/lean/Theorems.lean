-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: the list of what is proved of crates/policy-core.
-- The statements are in PolicyCore/Spec.lean, the proofs in PolicyCore/Claims.lean (which uses
-- the files before it in PolicyCore/).
-- ../../run ends on this file: it fails unless every line `#proved T` below
-- prints "proved: T".
--
-- Why it is needed: Lean checks a proof when it is read, but nothing
-- says that the theorem is the one of the statement or that no `sorry`
-- or new axiom is behind it.  `#proved T` (../../Proved.lean) prints the
-- axioms `T` rests on and fails unless they are the three of Lean and the
-- library functions the crate has no model of (the run prints none for this crate).
--
-- Read before this file: PolicyCore/Spec.lean.
import Proved
import PolicyCore.Claims

-- Each theorem is a proof of the statement of that name in Spec.lean: Lean
-- checks the type of each line below, so Theorems.lean and Spec.lean suffice.
example : PolicyCore.SelectNeverFails :=
  PolicyCore.select_never_fails
example : PolicyCore.SelectChoosesTheMostSpecificScope :=
  PolicyCore.select_chooses_the_most_specific_scope
example : PolicyCore.SameIsEqualityOfBytes :=
  PolicyCore.same_is_equality_of_bytes
example : PolicyCore.SameRefIsAnEquivalence :=
  PolicyCore.same_ref_is_an_equivalence
example : PolicyCore.IdentityMatchesIsTheRule :=
  PolicyCore.identity_matches_is_the_rule
example : PolicyCore.ExactAcceptsExactlyTheSameReference :=
  PolicyCore.exact_accepts_exactly_the_same_reference
example : PolicyCore.PrecheckNeverFails :=
  PolicyCore.precheck_never_fails
example : PolicyCore.PrecheckAcceptsWhenNothingNeedsASignature :=
  PolicyCore.precheck_accepts_when_nothing_needs_a_signature
example : PolicyCore.PrecheckLeavesTheDecisionToTheSignatures :=
  PolicyCore.precheck_leaves_the_decision_to_the_signatures
example : PolicyCore.PickNeverFails :=
  PolicyCore.pick_never_fails
example : PolicyCore.PickNamesWhatTheLatestRecordsSay :=
  PolicyCore.pick_names_what_the_latest_records_say
example : PolicyCore.PickLaterRecordWins :=
  PolicyCore.pick_later_record_wins
example : PolicyCore.PickDoesNotDependOnTheOrder :=
  PolicyCore.pick_does_not_depend_on_the_order
example : PolicyCore.DecideNeverFails :=
  PolicyCore.decide_never_fails
example : PolicyCore.DecideAcceptsExactlyTheAcceptable :=
  PolicyCore.decide_accepts_exactly_the_acceptable
example : PolicyCore.WholeModeAcceptMeansEveryRequirementHolds :=
  PolicyCore.whole_mode_accept_means_every_requirement_holds
example : PolicyCore.SignaturesOnlyModeAcceptMeansEverySignatureRequirementHolds :=
  PolicyCore.signatures_only_mode_accept_means_every_signature_requirement_holds
example : PolicyCore.MustBeSignedModeAcceptMeansASignatureSatisfiedARequirement :=
  PolicyCore.must_be_signed_mode_accept_means_a_signature_satisfied_a_requirement
example : PolicyCore.PrecheckAcceptIsKeptByDecide :=
  PolicyCore.precheck_accept_is_kept_by_decide
example : PolicyCore.PrecheckRefusalIsKeptByDecide :=
  PolicyCore.precheck_refusal_is_kept_by_decide

#proved PolicyCore.select_never_fails
#proved PolicyCore.select_chooses_the_most_specific_scope
#proved PolicyCore.same_is_equality_of_bytes
#proved PolicyCore.same_ref_is_an_equivalence
#proved PolicyCore.identity_matches_is_the_rule
#proved PolicyCore.exact_accepts_exactly_the_same_reference
#proved PolicyCore.precheck_never_fails
#proved PolicyCore.precheck_accepts_when_nothing_needs_a_signature
#proved PolicyCore.precheck_leaves_the_decision_to_the_signatures
#proved PolicyCore.pick_never_fails
#proved PolicyCore.pick_names_what_the_latest_records_say
#proved PolicyCore.pick_later_record_wins
#proved PolicyCore.pick_does_not_depend_on_the_order
#proved PolicyCore.decide_never_fails
#proved PolicyCore.decide_accepts_exactly_the_acceptable
#proved PolicyCore.whole_mode_accept_means_every_requirement_holds
#proved PolicyCore.signatures_only_mode_accept_means_every_signature_requirement_holds
#proved PolicyCore.must_be_signed_mode_accept_means_a_signature_satisfied_a_requirement
#proved PolicyCore.precheck_accept_is_kept_by_decide
#proved PolicyCore.precheck_refusal_is_kept_by_decide
