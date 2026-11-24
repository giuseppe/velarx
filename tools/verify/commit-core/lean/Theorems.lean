-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: the list of what is proved of crates/commit-core.
-- The statements are in CommitCore/Spec.lean, the proofs in CommitCore/ClaimsOf*.lean (which
-- use the other files of CommitCore/: what each small function says, what the plan and the
-- verdict are case by case, and the evidence of a name).
-- ../../run ends on this file: it fails unless every line `#proved T` below
-- prints "proved: T".
--
-- Why it is needed: Lean checks a proof when it is read, but nothing
-- says that the theorem is the one of the statement or that no `sorry`
-- or new axiom is behind it.  `#proved T` (../../Proved.lean) prints the
-- axioms `T` rests on and fails unless they are the three of Lean and the
-- library functions the crate has no model of (the run prints none for this crate).
--
-- Read before this file: CommitCore/Spec.lean.
import Proved
import CommitCore.ClaimsOfEvidence
import CommitCore.ClaimsOfTheStore
import CommitCore.ClaimsOfThePlan
import CommitCore.ClaimsOfLiveness

-- Each theorem is a proof of the statement of that name in Spec.lean: Lean
-- checks the type of each line below, so Theorems.lean and Spec.lean suffice.
example : CommitCore.NothingEverPanics :=
  CommitCore.nothing_ever_panics
example : CommitCore.DigestEqualityIsSameDigest :=
  CommitCore.digest_equality_is_same_digest
example : CommitCore.SameDigestIsAnEquality :=
  CommitCore.same_digest_is_an_equality
example : CommitCore.NamedImpliesEvidence :=
  CommitCore.named_implies_evidence
example : CommitCore.ReplayedByAnotherProducerIsNeverTrusted :=
  CommitCore.replayed_by_another_producer_is_never_trusted
example : CommitCore.NoNameAgainstTheMeasure :=
  CommitCore.no_name_against_the_measure
example : CommitCore.RequiredMeansMeasured :=
  CommitCore.required_means_measured
example : CommitCore.CheckedMeansTheKernelMeasured :=
  CommitCore.checked_means_the_kernel_measured
example : CommitCore.AnUnmeasuredObjectIsNeverKeptWhenRequired :=
  CommitCore.an_unmeasured_object_is_never_kept_when_required
example : CommitCore.AStoreObjectIsNeverLinkedOver :=
  CommitCore.a_store_object_is_never_linked_over
example : CommitCore.KeepNeverNamesWhatItWasNotGiven :=
  CommitCore.keep_never_names_what_it_was_not_given
example : CommitCore.KeepNeedsAMeasureWhenRequired :=
  CommitCore.keep_needs_a_measure_when_required
example : CommitCore.ANameIsAnFsVerityDigest :=
  CommitCore.a_name_is_an_fs_verity_digest
example : CommitCore.TheVerdictIsForThePlan :=
  CommitCore.the_verdict_is_for_the_plan
example : CommitCore.ThePlanFitsTheFileSystem :=
  CommitCore.the_plan_fits_the_file_system
example : CommitCore.OnlyTrustedFilesAreLinkedUnread :=
  CommitCore.only_trusted_files_are_linked_unread
example : CommitCore.WrongExactlyWhenADigestDisagrees :=
  CommitCore.wrong_exactly_when_a_digest_disagrees
example : CommitCore.AFailureHasItsReason :=
  CommitCore.a_failure_has_its_reason
example : CommitCore.AKernelProofMeansTheStoreWasAsked :=
  CommitCore.a_kernel_proof_means_the_store_was_asked
example : CommitCore.AMeasuredFileIsNamed :=
  CommitCore.a_measured_file_is_named
example : CommitCore.AReadFileIsNamed :=
  CommitCore.a_read_file_is_named
example : CommitCore.ACopiedFileIsNamed :=
  CommitCore.a_copied_file_is_named
example : CommitCore.AFileTheEngineVouchesForIsNamed :=
  CommitCore.a_file_the_engine_vouches_for_is_named
example : CommitCore.AKnownObjectIsKept :=
  CommitCore.a_known_object_is_kept

#proved CommitCore.nothing_ever_panics
#proved CommitCore.digest_equality_is_same_digest
#proved CommitCore.same_digest_is_an_equality
#proved CommitCore.named_implies_evidence
#proved CommitCore.replayed_by_another_producer_is_never_trusted
#proved CommitCore.no_name_against_the_measure
#proved CommitCore.required_means_measured
#proved CommitCore.checked_means_the_kernel_measured
#proved CommitCore.an_unmeasured_object_is_never_kept_when_required
#proved CommitCore.a_store_object_is_never_linked_over
#proved CommitCore.keep_never_names_what_it_was_not_given
#proved CommitCore.keep_needs_a_measure_when_required
#proved CommitCore.a_name_is_an_fs_verity_digest
#proved CommitCore.the_verdict_is_for_the_plan
#proved CommitCore.the_plan_fits_the_file_system
#proved CommitCore.only_trusted_files_are_linked_unread
#proved CommitCore.wrong_exactly_when_a_digest_disagrees
#proved CommitCore.a_failure_has_its_reason
#proved CommitCore.a_kernel_proof_means_the_store_was_asked
#proved CommitCore.a_measured_file_is_named
#proved CommitCore.a_read_file_is_named
#proved CommitCore.a_copied_file_is_named
#proved CommitCore.a_file_the_engine_vouches_for_is_named
#proved CommitCore.a_known_object_is_kept
