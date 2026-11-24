-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: the proofs of the claims of Spec.lean about the plan and about what the
-- verdict does with it: TheVerdictIsForThePlan, ThePlanFitsTheFileSystem,
-- OnlyTrustedFilesAreLinkedUnread, WrongExactlyWhenADigestDisagrees and AFailureHasItsReason.
--
-- Why it is needed: Theorems.lean names one theorem for each claim; these are those theorems.
--
-- Read before this file: Spec.lean, ThePlan.lean, TheVerdict.lean, PlanInversions.lean.
--
-- Notation: as in ClaimsOfTheStore.lean.
import CommitCore.NamesHaveEvidence
import CommitCore.PlanInversions
open Aeneas Aeneas.Std Result velarx_commit_core
namespace CommitCore

/-- What was read, if the plan asked for it, is there. -/
theorem content_was_seen {claim : Claim} {content : Bool} {seen : Seen}
    (read : ContentRead claim content seen) : content = true → seen.content ≠ none := by
  intro asked
  obtain ⟨_, c, _, got, _⟩ := read asked
  simp [got]

/-- The verdict is for the plan it made: each case that names or keeps is of a plan that links,
reads, copies or keeps, and what that plan asked was seen. -/
theorem the_verdict_is_for_the_plan : TheVerdictIsForThePlan := by
  intro f seen
  obtain ⟨p, is_plan, _, answered⟩ := verdict_is f seen
  refine WP.spec_mono answered ?_
  intro v answer
  refine ⟨p, is_plan, ?_, ?_⟩
  · -- a kept object
    rintro ⟨n, is_keep⟩
    cases answer with
    | kept content _ _ _ _ _ shape read _ _ _ _ =>
      subst shape
      exact ⟨⟨content, rfl⟩, content_was_seen read⟩
    | _ => simp at is_keep
  · -- a name
    rintro ⟨n, is_name⟩
    cases answer with
    | linked_by_measure _ _ _ shape _ => subst shape; exact ⟨Or.inl rfl, trivial⟩
    | linked_unread _ _ _ shape _ _ => subst shape; exact ⟨Or.inl rfl, trivial⟩
    | read_by_measure content merkle _ _ planned shape read seen_kernel =>
      subst shape
      refine ⟨Or.inr (Or.inl ⟨content, merkle, rfl⟩), content_was_seen read, fun hashes => ?_⟩
      have no_merkle := measured_read_has_no_merkle planned (by simp [seen_kernel])
      simp [no_merkle] at hashes
    | read_hashed content _ _ _ shape read _ merkle =>
      subst shape
      exact ⟨Or.inr (Or.inl ⟨content, true, rfl⟩), content_was_seen read, fun _ => by simp [merkle]⟩
    | copy_named content _ _ _ _ shape read merkle _ _ =>
      subst shape
      exact ⟨Or.inr (Or.inr ⟨content, rfl⟩), content_was_seen read, by simp [merkle]⟩
    | _ => simp at is_name

/-- The plan fits the file system: read off each plan of `PlanIs`. -/
theorem the_plan_fits_the_file_system : ThePlanFitsTheFileSystem := by
  intro f kernel held
  refine WP.spec_mono (plan_is f kernel held) ?_
  intro p planned
  refine ⟨fun content shape => ?_, ?_⟩
  · subst shape
    exact copy_is_off_the_store_fs planned
  · rintro (shape | ⟨content, merkle, shape⟩)
    · subst shape
      exact link_is_on_the_store_fs planned
    · subst shape
      exact read_is_on_the_store_fs planned

/-- Only the trusted are linked unread: the two plans of `PlanIs` that link. -/
theorem only_trusted_files_are_linked_unread : OnlyTrustedFilesAreLinkedUnread := by
  intro f kernel held
  refine WP.spec_mono (plan_is f kernel held) ?_
  intro p planned shape
  subst shape
  cases planned with
  | link_measured _ _ _ measured no_read => exact Or.inl ⟨measured, no_read⟩
  | link_trusted _ _ _ unmeasured not_required vouched =>
    exact Or.inr ⟨unmeasured, not_required, vouched⟩

/-- A refusal exactly when a digest disagrees: only the first case of `VerdictIs` refuses, and
every other case has nothing that disagrees. -/
theorem wrong_exactly_when_a_digest_disagrees : WrongExactlyWhenADigestDisagrees := by
  intro f seen
  obtain ⟨_, _, _, answered⟩ := verdict_is f seen
  refine WP.spec_mono answered ?_
  intro v answer
  cases answer with
  | refused why mismatch => exact ⟨fun _ => mismatch, fun _ => ⟨why, rfl⟩⟩
  | bad_report _ _ => simp [*]
  | plan_failed _ agrees _ _ => simp [agrees]
  | kept_unread _ agrees _ _ _ _ => simp [agrees]
  | kept _ _ _ _ agrees _ _ _ _ _ _ _ => simp [agrees]
  | linked_by_measure _ agrees _ _ _ => simp [agrees]
  | linked_unread _ agrees _ _ _ _ => simp [agrees]
  | read_unread _ _ agrees _ _ _ _ => simp [agrees]
  | read_by_measure _ _ _ agrees _ _ _ _ => simp [agrees]
  | read_hashed _ _ agrees _ _ _ _ _ => simp [agrees]
  | read_not_hashed _ agrees _ _ _ _ _ => simp [agrees]
  | copy_unread _ agrees _ _ _ _ => simp [agrees]
  | copy_unmeasured _ agrees _ _ _ _ _ => simp [agrees]
  | copy_not_hashed _ agrees _ _ _ _ _ => simp [agrees]
  | copy_named _ _ _ agrees _ _ _ _ _ _ => simp [agrees]

/-- A failure has its reason: the failures of `VerdictIs` and of the plans that fail. -/
theorem a_failure_has_its_reason : AFailureHasItsReason := by
  intro f seen
  obtain ⟨_, _, _, answered⟩ := verdict_is f seen
  refine WP.spec_mono answered ?_
  intro v answer why is_fail
  cases answer with
  | plan_failed _ _ planned shape =>
    cases is_fail
    subst shape
    cases planned with
    | fail_store _ _ required => exact ⟨by simp, fun _ => required⟩
    | fail_no_measure _ _ _ required => exact ⟨by simp, fun _ => required⟩
  | bad_report => cases is_fail; exact ⟨by simp, by simp⟩
  | kept_unread => cases is_fail; exact ⟨by simp, by simp⟩
  | read_unread => cases is_fail; exact ⟨by simp, by simp⟩
  | read_not_hashed => cases is_fail; exact ⟨by simp, by simp⟩
  | copy_unread => cases is_fail; exact ⟨by simp, by simp⟩
  | copy_unmeasured _ _ _ _ _ required _ => cases is_fail; exact ⟨by simp, fun _ => required⟩
  | copy_not_hashed => cases is_fail; exact ⟨by simp, by simp⟩
  | _ => simp at is_fail

end CommitCore
