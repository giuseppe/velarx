-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: the list of what is proved of crates/revoke-core.  The statements are in
-- RevokeCore/Spec.lean; the proofs are in RevokeCore/ClaimsOf*.lean, which use what the other files
-- of RevokeCore/ say of the loops of the crate.
-- ../../run ends on this file: it fails unless every line `#proved T` below prints "proved: T".
--
-- Why it is needed: Lean checks a proof when it is read, but nothing says that the theorem is the
-- one of the statement or that no `sorry` or new axiom is behind it.  `#proved T`
-- (../../Proved.lean) prints the axioms `T` rests on and fails unless they are the three of Lean
-- and the library functions the crate has no model of (there are none).
--
-- Read before this file: RevokeCore/Spec.lean.
import Proved
import RevokeCore.ClaimsOfWhichPartsAreAdopted
import RevokeCore.ClaimsOfWhatIsHeldAfter
import RevokeCore.ClaimsOfExamples

-- Each theorem is a proof of the statement of that name in Spec.lean: Lean checks the type of each
-- line below, so Theorems.lean and Spec.lean suffice.
example : RevokeCore.NewerAndAdoptAlwaysReturn :=
  RevokeCore.newer_and_adopt_always_return
example : RevokeCore.NewerMeansHigherThanEveryNumberHeld :=
  RevokeCore.newer_means_higher_than_every_number_held
example : RevokeCore.AdoptsExactlyTheUnbeatenNewerVerifiedParts :=
  RevokeCore.adopts_exactly_the_unbeaten_newer_verified_parts
example : RevokeCore.OnePartOfAnIssuerAtMost :=
  RevokeCore.one_part_of_an_issuer_at_most
example : RevokeCore.AHigherVerifiedPartIsAlwaysAdopted :=
  RevokeCore.a_higher_verified_part_is_always_adopted
example : RevokeCore.UnverifiedPartsAreNeverAdopted :=
  RevokeCore.unverified_parts_are_never_adopted
example : RevokeCore.UnverifiedPartsAreNotThere :=
  RevokeCore.unverified_parts_are_not_there
example : RevokeCore.TheNumberHeldAfterIsTheGreatest :=
  RevokeCore.the_number_held_after_is_the_greatest
example : RevokeCore.TheNumberHeldNeverDecreases :=
  RevokeCore.the_number_held_never_decreases
example : RevokeCore.TheOrderOfThePartsDoesNotMatter :=
  RevokeCore.the_order_of_the_parts_does_not_matter
example : RevokeCore.AdoptingAgainAdoptsNothing :=
  RevokeCore.adopting_again_adopts_nothing
example : RevokeCore.WorkedExamples :=
  RevokeCore.worked_examples

#proved RevokeCore.newer_and_adopt_always_return
#proved RevokeCore.newer_means_higher_than_every_number_held
#proved RevokeCore.adopts_exactly_the_unbeaten_newer_verified_parts
#proved RevokeCore.one_part_of_an_issuer_at_most
#proved RevokeCore.a_higher_verified_part_is_always_adopted
#proved RevokeCore.unverified_parts_are_never_adopted
#proved RevokeCore.unverified_parts_are_not_there
#proved RevokeCore.the_number_held_after_is_the_greatest
#proved RevokeCore.the_number_held_never_decreases
#proved RevokeCore.the_order_of_the_parts_does_not_matter
#proved RevokeCore.adopting_again_adopts_nothing
#proved RevokeCore.worked_examples
