-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: the proofs of the claims of Spec.lean that say the other way, that the
-- honest evidence gives a name: AMeasuredFileIsNamed, AReadFileIsNamed, ACopiedFileIsNamed,
-- AFileTheEngineVouchesForIsNamed and AKnownObjectIsKept.
--
-- Why it is needed: "a file is named only on evidence" is satisfied by a core that names nothing.
-- Each of these claims says what `verdict` answers when the evidence is there.  Each is proved the
-- same way: the plan is known from what the facts say (PlanInversions.lean), so only the cases of
-- `VerdictIs` for that plan are left, and the other cases are shown not to be (their plan, or what
-- they say was seen, is not what the claim says).
--
-- Read before this file: Spec.lean, TheVerdict.lean, PlanInversions.lean.
--
-- Notation: as in ClaimsOfTheStore.lean; `simp at shape` closes a case whose plan is not the
-- plan it was shown to be.
import CommitCore.NamesHaveEvidence
import CommitCore.PlanInversions
open Aeneas Aeneas.Std Result velarx_commit_core
namespace CommitCore

/-- When the key is met, the content the plan asked for was read. -/
theorem content_was_read {f : Facts} {seen : Seen} {content : Bool}
    (key_met : TheKeyIsMet f seen) (reads : content = true ↔ ReadsContent f.claim seen.kernel)
    (asked : content = true) : seen.content ≠ none := by
  have asks := reads.mp asked
  obtain ⟨k, has_key⟩ := Option.ne_none_iff_exists'.mp (reads_content_has_key asks)
  obtain ⟨c, got, _⟩ := key_met asks k has_key
  simp [got]

/-- When the key is met, the plan's content was read, and it is the content of the claim's key. -/
theorem content_read_of_key_met {f : Facts} {seen : Seen} {content : Bool}
    (key_met : TheKeyIsMet f seen) (reads : content = true ↔ ReadsContent f.claim seen.kernel) :
    ContentRead f.claim content seen := by
  intro asked
  have asks := reads.mp asked
  obtain ⟨k, has_key⟩ := Option.ne_none_iff_exists'.mp (reads_content_has_key asks)
  obtain ⟨c, got, same⟩ := key_met asks k has_key
  exact ⟨k, c, has_key, got, same⟩

/-- A measured file is named: the plan is to link it or to read it for its content, and in each
case the answer is the name `m`. -/
theorem a_measured_file_is_named : AMeasuredFileIsNamed := by
  intro f seen m agrees reports lacks same_fs measured key_met
  obtain ⟨_, _, _, answered⟩ := verdict_is f seen
  refine WP.spec_mono answered ?_
  intro v answer
  cases answer with
  | refused _ mismatch => exact absurd mismatch agrees
  | bad_report _ not_reports => exact absurd reports not_reports
  | plan_failed _ _ planned shape =>
    rcases plan_for_a_measured_file planned agrees lacks same_fs measured with rfl | rfl <;>
      simp at shape
  | kept_unread _ _ planned shape =>
    rcases plan_for_a_measured_file planned agrees lacks same_fs measured with rfl | rfl <;>
      simp at shape
  | kept _ _ _ _ _ planned shape =>
    rcases plan_for_a_measured_file planned agrees lacks same_fs measured with rfl | rfl <;>
      simp at shape
  | linked_by_measure m' _ _ _ seen_kernel =>
    rw [measured] at seen_kernel
    cases seen_kernel
    rfl
  | linked_unread _ _ _ _ unmeasured _ => simp [measured] at unmeasured
  | read_unread content _ _ planned shape asked unread =>
    subst shape
    exact absurd unread (content_was_read key_met (plan_read_reads planned) asked)
  | read_by_measure _ _ m' _ _ _ _ seen_kernel =>
    rw [measured] at seen_kernel
    cases seen_kernel
    rfl
  | read_hashed _ _ _ planned shape _ unmeasured _ => simp [measured] at unmeasured
  | read_not_hashed _ _ _ _ _ unmeasured _ => simp [measured] at unmeasured
  | copy_unread _ _ planned shape =>
    rcases plan_for_a_measured_file planned agrees lacks same_fs measured with rfl | rfl <;>
      simp at shape
  | copy_unmeasured _ _ planned shape =>
    rcases plan_for_a_measured_file planned agrees lacks same_fs measured with rfl | rfl <;>
      simp at shape
  | copy_not_hashed _ _ planned shape =>
    rcases plan_for_a_measured_file planned agrees lacks same_fs measured with rfl | rfl <;>
      simp at shape
  | copy_named _ _ _ _ planned shape =>
    rcases plan_for_a_measured_file planned agrees lacks same_fs measured with rfl | rfl <;>
      simp at shape

/-- A read file is named: the plan is to read it for the digest, and the answer is the name `d`. -/
theorem a_read_file_is_named : AReadFileIsNamed := by
  intro f seen d agrees reports lacks same_fs unmeasured not_required not_vouched merkle key_met
  obtain ⟨p, _, planned, answered⟩ := verdict_is f seen
  obtain ⟨c, rfl⟩ :=
    plan_for_an_unmeasured_file planned agrees lacks same_fs unmeasured not_required not_vouched
  refine WP.spec_mono answered ?_
  intro v answer
  cases answer with
  | refused _ mismatch => exact absurd mismatch agrees
  | bad_report _ not_reports => exact absurd reports not_reports
  | plan_failed _ _ _ shape => simp at shape
  | kept_unread _ _ _ shape => simp at shape
  | kept _ _ _ _ _ _ shape => simp at shape
  | linked_by_measure _ _ _ shape => simp at shape
  | linked_unread _ _ _ shape => simp at shape
  | read_unread content merkle' _ _ shape asked unread =>
    cases shape
    exact absurd unread (content_was_read key_met (plan_read_reads planned) asked)
  | read_by_measure _ _ _ _ _ _ _ seen_kernel => simp [unmeasured] at seen_kernel
  | read_hashed _ d' _ _ _ _ _ merkle' =>
    rw [merkle] at merkle'
    cases merkle'
    exact ⟨_, rfl, rfl, rfl⟩
  | read_not_hashed _ _ _ _ _ _ merkle' => simp [merkle] at merkle'
  | copy_unread _ _ _ shape => simp at shape
  | copy_unmeasured _ _ _ shape => simp at shape
  | copy_not_hashed _ _ _ shape => simp at shape
  | copy_named _ _ _ _ _ shape => simp at shape

/-- A copied file is named: the plan is to copy it, and the answer is the name `d`. -/
theorem a_copied_file_is_named : ACopiedFileIsNamed := by
  intro f seen d agrees reports lacks off merkle key_met measured_when_required
  obtain ⟨p, _, planned, answered⟩ := verdict_is f seen
  obtain ⟨c, rfl⟩ := plan_for_a_copied_file planned agrees lacks off
  refine WP.spec_mono answered ?_
  intro v answer
  cases answer with
  | refused _ mismatch => exact absurd mismatch agrees
  | bad_report _ not_reports => exact absurd reports not_reports
  | plan_failed _ _ _ shape => simp at shape
  | kept_unread _ _ _ shape => simp at shape
  | kept _ _ _ _ _ _ shape => simp at shape
  | linked_by_measure _ _ _ shape => simp at shape
  | linked_unread _ _ _ shape => simp at shape
  | read_unread _ _ _ _ shape => simp at shape
  | read_by_measure _ _ _ _ _ shape => simp at shape
  | read_hashed _ _ _ _ shape => simp at shape
  | read_not_hashed _ _ _ shape => simp at shape
  | copy_unread content _ _ shape asked unread =>
    cases shape
    exact absurd unread (content_was_read key_met (plan_copy_reads planned) asked)
  | copy_unmeasured _ _ _ shape _ required unmeasured =>
    exact absurd (measured_when_required required) unmeasured
  | copy_not_hashed _ _ _ shape _ _ merkle' => simp [merkle] at merkle'
  | copy_named _ d' checked _ _ shape _ merkle' is_checked _ =>
    rw [merkle] at merkle'
    cases merkle'
    exact ⟨_, rfl, rfl, is_checked⟩

/-- A file the engine vouches for is named: the plan is to link it unread. -/
theorem a_file_the_engine_vouches_for_is_named : AFileTheEngineVouchesForIsNamed := by
  intro f seen d agrees reports lacks same_fs unmeasured not_required vouched claimed
  obtain ⟨p, _, planned, answered⟩ := verdict_is f seen
  have link := plan_for_a_vouched_file planned agrees lacks same_fs unmeasured not_required vouched
  subst link
  refine WP.spec_mono answered ?_
  intro v answer
  cases answer with
  | refused _ mismatch => exact absurd mismatch agrees
  | bad_report _ not_reports => exact absurd reports not_reports
  | plan_failed _ _ _ shape => simp at shape
  | kept_unread _ _ _ shape => simp at shape
  | kept _ _ _ _ _ _ shape => simp at shape
  | linked_by_measure _ _ _ _ seen_kernel => simp [unmeasured] at seen_kernel
  | linked_unread d' _ _ _ _ vouching =>
    rcases vouching with claim_is | ⟨k, claim_is⟩ <;>
      · rw [claim_is] at claimed
        simp [claimedVerity] at claimed
        subst claimed
        rfl
  | read_unread _ _ _ _ shape => simp at shape
  | read_by_measure _ _ _ _ _ shape => simp at shape
  | read_hashed _ _ _ _ shape => simp at shape
  | read_not_hashed _ _ _ shape => simp at shape
  | copy_unread _ _ _ shape => simp at shape
  | copy_unmeasured _ _ _ shape => simp at shape
  | copy_not_hashed _ _ _ shape => simp at shape
  | copy_named _ _ _ _ _ shape => simp at shape

/-- A known object is kept: the plan is to keep it, and the answer is that. -/
theorem a_known_object_is_kept : AKnownObjectIsKept := by
  intro f seen d agrees reports has_it asked_dig fine key_met
  obtain ⟨p, _, planned, answered⟩ := verdict_is f seen
  have asks : AsksStore f.claim seen.kernel seen.held := asks_store_of_asked_dig asked_dig has_it
  have not_failed : ¬ (f.required = true ∧ seen.held = .Unmeasured) := by
    rintro ⟨required, unmeasured⟩
    rcases fine with not_required | measures
    · simp [required] at not_required
    · simp [unmeasured] at measures
  obtain ⟨c, rfl⟩ := plan_for_a_known_object planned agrees asks not_failed
  refine WP.spec_mono answered ?_
  intro v answer
  cases answer with
  | refused _ mismatch => exact absurd mismatch agrees
  | bad_report _ not_reports => exact absurd reports not_reports
  | plan_failed _ _ _ shape => simp at shape
  | kept_unread content _ _ shape asked unread =>
    cases shape
    exact absurd unread (content_was_read key_met (plan_keep_reads planned) asked)
  | kept _ d' checked proof _ _ _ _ asked_dig' is_checked _ _ =>
    rw [asked_dig] at asked_dig'
    cases asked_dig'
    exact ⟨_, rfl, rfl, is_checked⟩
  | linked_by_measure _ _ _ shape => simp at shape
  | linked_unread _ _ _ shape => simp at shape
  | read_unread _ _ _ _ shape => simp at shape
  | read_by_measure _ _ _ _ _ shape => simp at shape
  | read_hashed _ _ _ _ shape => simp at shape
  | read_not_hashed _ _ _ shape => simp at shape
  | copy_unread _ _ _ shape => simp at shape
  | copy_unmeasured _ _ _ shape => simp at shape
  | copy_not_hashed _ _ _ shape => simp at shape
  | copy_named _ _ _ _ _ shape => simp at shape

end CommitCore
