-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: the proofs of the claims of Spec.lean about the store and about
-- fs-verity being required: RequiredMeansMeasured, CheckedMeansTheKernelMeasured,
-- AnUnmeasuredObjectIsNeverKeptWhenRequired, AStoreObjectIsNeverLinkedOver,
-- KeepNeverNamesWhatItWasNotGiven, KeepNeedsAMeasureWhenRequired and
-- AKernelProofMeansTheStoreWasAsked.
--
-- Why it is needed: Theorems.lean names one theorem for each claim; these are those theorems.
-- Each takes the answers of `verdict` (or of `keep`) one by one, from the lists of the files
-- before it, and shows the claim of the answer or that the answer cannot be.
--
-- Read before this file: Spec.lean, TheVerdict.lean, TheKeep.lean, PlanInversions.lean.
--
-- Notation: as in ClaimsOfEvidence.lean; `subst shape` replaces the plan by the plan the case says
-- it is; `cases is_answer` finds that the name asked about is the one the case answers.
import CommitCore.NamesHaveEvidence
import CommitCore.PlanInversions
import CommitCore.TheKeep
open Aeneas Aeneas.Std Result velarx_commit_core
namespace CommitCore

/-- Fs-verity required means measured: the cases that name unread are the ones that need it not to
be required, and the kept object is measured because the plan keeps only a measured one. -/
theorem required_means_measured : RequiredMeansMeasured := by
  intro f seen required
  obtain ⟨_, _, _, answered⟩ := verdict_is f seen
  refine WP.spec_mono answered ?_
  intro v answer
  cases answer with
  | refused _ _ => exact ⟨by simp, by simp⟩
  | bad_report _ _ => exact ⟨by simp, by simp⟩
  | plan_failed _ _ _ _ => exact ⟨by simp, by simp⟩
  | kept_unread _ _ _ _ _ _ => exact ⟨by simp, by simp⟩
  | kept content d checked proof agrees planned shape _ _ is_checked _ _ =>
    subst shape
    refine ⟨by simp, ?_⟩
    rintro n is_answer
    cases is_answer
    obtain ⟨asked, fine⟩ := keep_has_the_store planned
    have measures : seen.held = .Measures := by
      cases held : seen.held
      · exact absurd held asked.2
      · rfl
      · exact absurd ⟨required, held⟩ fine
    exact ⟨is_checked.mpr measures, measures⟩
  | linked_by_measure m _ planned shape seen_kernel =>
    subst shape
    refine ⟨?_, by simp⟩
    rintro n is_answer
    cases is_answer
    exact ⟨rfl, Or.inl ⟨link_is_on_the_store_fs planned, m, seen_kernel, same_refl m⟩⟩
  | linked_unread d _ planned shape unmeasured _ =>
    subst shape
    simp [unmeasured_link_is_not_required planned unmeasured] at required
  | read_unread _ _ _ _ _ _ _ => exact ⟨by simp, by simp⟩
  | read_by_measure _ _ m _ planned shape _ seen_kernel =>
    subst shape
    refine ⟨?_, by simp⟩
    rintro n is_answer
    cases is_answer
    exact ⟨rfl, Or.inl ⟨read_is_on_the_store_fs planned, m, seen_kernel, same_refl m⟩⟩
  | read_hashed content d _ planned shape _ _ _ =>
    subst shape
    simp [(hashed_read_is_not_required planned).2] at required
  | read_not_hashed _ _ _ _ _ _ _ => exact ⟨by simp, by simp⟩
  | copy_unread _ _ _ _ _ _ => exact ⟨by simp, by simp⟩
  | copy_unmeasured _ _ _ _ _ _ _ => exact ⟨by simp, by simp⟩
  | copy_not_hashed _ _ _ _ _ _ _ => exact ⟨by simp, by simp⟩
  | copy_named content d checked _ planned shape _ merkle is_checked needs_check =>
    subst shape
    refine ⟨?_, by simp⟩
    rintro n is_answer
    cases is_answer
    have measured := is_checked.mp (needs_check required)
    obtain ⟨c, m, copy, hashed, same⟩ := measured
    rw [merkle] at hashed
    cases hashed
    exact ⟨needs_check required, Or.inr ⟨copy_is_off_the_store_fs planned, c, copy, same⟩⟩

/-- `checked` is whether the kernel measured: read off each case that names or keeps. -/
theorem checked_means_the_kernel_measured : CheckedMeansTheKernelMeasured := by
  intro f seen
  obtain ⟨_, _, _, answered⟩ := verdict_is f seen
  refine WP.spec_mono answered ?_
  intro v answer
  cases answer with
  | refused _ _ => exact ⟨by simp, by simp⟩
  | bad_report _ _ => exact ⟨by simp, by simp⟩
  | plan_failed _ _ _ _ => exact ⟨by simp, by simp⟩
  | kept_unread _ _ _ _ _ _ => exact ⟨by simp, by simp⟩
  | kept content d checked proof agrees planned shape _ _ is_checked _ _ =>
    refine ⟨by simp, ?_⟩
    rintro n is_answer
    cases is_answer
    exact is_checked
  | linked_by_measure m _ planned shape seen_kernel =>
    subst shape
    refine ⟨?_, by simp⟩
    rintro n is_answer
    cases is_answer
    exact ⟨fun _ => Or.inl ⟨link_is_on_the_store_fs planned, m, seen_kernel, same_refl m⟩,
      fun _ => rfl⟩
  | linked_unread d _ planned shape unmeasured _ =>
    subst shape
    refine ⟨?_, by simp⟩
    rintro n is_answer
    cases is_answer
    refine ⟨by simp, ?_⟩
    rintro (⟨_, m, seen_kernel, _⟩ | ⟨off, _⟩)
    · simp [unmeasured] at seen_kernel
    · simp [link_is_on_the_store_fs planned] at off
  | read_unread _ _ _ _ _ _ _ => exact ⟨by simp, by simp⟩
  | read_by_measure content merkle m _ planned shape _ seen_kernel =>
    subst shape
    refine ⟨?_, by simp⟩
    rintro n is_answer
    cases is_answer
    exact ⟨fun _ => Or.inl ⟨read_is_on_the_store_fs planned, m, seen_kernel, same_refl m⟩,
      fun _ => rfl⟩
  | read_hashed content d _ planned shape _ unmeasured _ =>
    subst shape
    refine ⟨?_, by simp⟩
    rintro n is_answer
    cases is_answer
    refine ⟨by simp, ?_⟩
    rintro (⟨_, m, seen_kernel, _⟩ | ⟨off, _⟩)
    · simp [unmeasured] at seen_kernel
    · simp [read_is_on_the_store_fs planned] at off
  | read_not_hashed _ _ _ _ _ _ _ => exact ⟨by simp, by simp⟩
  | copy_unread _ _ _ _ _ _ => exact ⟨by simp, by simp⟩
  | copy_unmeasured _ _ _ _ _ _ _ => exact ⟨by simp, by simp⟩
  | copy_not_hashed _ _ _ _ _ _ _ => exact ⟨by simp, by simp⟩
  | copy_named content d checked _ planned shape _ merkle is_checked _ =>
    subst shape
    refine ⟨?_, by simp⟩
    rintro n is_answer
    cases is_answer
    have off := copy_is_off_the_store_fs planned
    constructor
    · intro checked_true
      obtain ⟨c, m, copy, hashed, same⟩ := is_checked.mp checked_true
      rw [merkle] at hashed
      cases hashed
      exact Or.inr ⟨off, ⟨c, copy, same⟩, ⟨d, merkle, same_refl d⟩⟩
    · rintro (⟨on, _⟩ | ⟨_, ⟨c, copy, same⟩, ⟨m, hashed, _⟩⟩)
      · simp [off] at on
      · rw [merkle] at hashed
        cases hashed
        exact is_checked.mpr ⟨c, d, copy, merkle, same⟩

/-- An object the kernel does not measure is not kept when required: the store has it, so the plan
is a failure for it (or a refusal), and no case that names or keeps can be. -/
theorem an_unmeasured_object_is_never_kept_when_required :
    AnUnmeasuredObjectIsNeverKeptWhenRequired := by
  intro f seen required unmeasured asked_dig
  obtain ⟨_, _, _, answered⟩ := verdict_is f seen
  refine WP.spec_mono answered ?_
  have asks : AsksStore f.claim seen.kernel seen.held := ⟨asked_dig, by simp [unmeasured]⟩
  intro v answer
  cases answer with
  | refused why _ => exact Or.inl ⟨why, rfl⟩
  | bad_report _ _ => exact Or.inr (Or.inr rfl)
  | plan_failed why _ planned shape =>
    subst shape
    rcases plan_when_the_store_has_it planned asks with ⟨_, shape⟩ | ⟨_, shape⟩ | shape <;>
      simp at shape
    · subst shape
      exact Or.inr (Or.inl rfl)
  | kept_unread _ _ planned shape _ _ =>
    subst shape
    exact absurd ⟨required, unmeasured⟩ (keep_has_the_store planned).2
  | kept _ _ _ _ _ planned shape _ _ _ _ _ =>
    subst shape
    exact absurd ⟨required, unmeasured⟩ (keep_has_the_store planned).2
  | linked_by_measure _ _ planned shape _ =>
    exact absurd shape (plan_never_links_over_the_store planned asks).1
  | linked_unread _ _ planned shape _ _ =>
    exact absurd shape (plan_never_links_over_the_store planned asks).1
  | read_unread _ _ _ planned shape _ _ =>
    exact absurd shape ((plan_never_links_over_the_store planned asks).2.1 _ _)
  | read_by_measure _ _ _ _ planned shape _ _ =>
    exact absurd shape ((plan_never_links_over_the_store planned asks).2.1 _ _)
  | read_hashed _ _ _ planned shape _ _ _ =>
    exact absurd shape ((plan_never_links_over_the_store planned asks).2.1 _ _)
  | read_not_hashed _ _ planned shape _ _ _ =>
    exact absurd shape ((plan_never_links_over_the_store planned asks).2.1 _ _)
  | copy_unread _ _ planned shape _ _ =>
    exact absurd shape ((plan_never_links_over_the_store planned asks).2.2 _)
  | copy_unmeasured _ _ planned shape _ _ _ =>
    exact absurd shape ((plan_never_links_over_the_store planned asks).2.2 _)
  | copy_not_hashed _ _ planned shape _ _ _ =>
    exact absurd shape ((plan_never_links_over_the_store planned asks).2.2 _)
  | copy_named _ _ _ _ planned shape _ _ _ _ =>
    exact absurd shape ((plan_never_links_over_the_store planned asks).2.2 _)

/-- The store's object is never linked over: the plan of a store that has the object is never to
link, read or copy. -/
theorem a_store_object_is_never_linked_over : AStoreObjectIsNeverLinkedOver := by
  intro f seen asked_dig has_it
  obtain ⟨_, _, _, answered⟩ := verdict_is f seen
  refine WP.spec_mono answered ?_
  have asks : AsksStore f.claim seen.kernel seen.held := ⟨asked_dig, has_it⟩
  have links : ∀ {p : Plan}, PlanIs f seen.kernel seen.held p →
      AsksStore f.claim seen.kernel seen.held →
      p ≠ .Link ∧ (∀ c m, p ≠ .Read c m) ∧ ∀ c, p ≠ .Copy c :=
    fun planned asks => plan_never_links_over_the_store planned asks
  intro v answer n is_name
  cases answer with
  | linked_by_measure _ _ planned shape _ => exact absurd shape (links planned asks).1
  | linked_unread _ _ planned shape _ _ => exact absurd shape (links planned asks).1
  | read_by_measure _ _ _ _ planned shape _ _ => exact absurd shape ((links planned asks).2.1 _ _)
  | read_hashed _ _ _ planned shape _ _ _ => exact absurd shape ((links planned asks).2.1 _ _)
  | copy_named _ _ _ _ planned shape _ _ _ _ => exact absurd shape ((links planned asks).2.2 _)
  | _ => simp at is_name

/-- `keep` names what it was given, only when the store lacks it: the four answers of `keep_is`. -/
theorem keep_never_names_what_it_was_not_given : KeepNeverNamesWhatItWasNotGiven := by
  intro f named held
  refine WP.spec_mono (keep_is f named held) ?_
  rintro v (⟨lacks, rfl⟩ | ⟨measures, rfl⟩ | ⟨unmeasured, required, rfl⟩ |
    ⟨unmeasured, required, rfl⟩)
  · refine ⟨fun m is_name => ⟨by cases is_name; rfl, lacks⟩, by simp, fun _ => rfl, ?_⟩
    intro has_it
    exact absurd lacks has_it
  · refine ⟨by simp, ?_, by simp [measures], fun _ _ => ⟨_, rfl⟩⟩
    intro m is_keep
    cases is_keep
    exact ⟨rfl, by simp [measures], rfl, by simp [measures]⟩
  · refine ⟨by simp, by simp, by simp [unmeasured], ?_⟩
    intro _ either
    rcases either with not_required | measured
    · simp [required] at not_required
    · simp [unmeasured] at measured
  · refine ⟨by simp, ?_, by simp [unmeasured], fun _ _ => ⟨_, rfl⟩⟩
    intro m is_keep
    cases is_keep
    exact ⟨rfl, by simp [unmeasured], rfl, by simp [unmeasured]⟩

/-- `keep`, fs-verity required: the four answers of `keep_is`. -/
theorem keep_needs_a_measure_when_required : KeepNeedsAMeasureWhenRequired := by
  intro f named held required
  refine WP.spec_mono (keep_is f named held) ?_
  rintro v (⟨lacks, rfl⟩ | ⟨measures, rfl⟩ | ⟨unmeasured, _, rfl⟩ | ⟨unmeasured, not_required, rfl⟩)
  · refine ⟨by simp [lacks], by simp, by simp⟩
  · refine ⟨by simp [measures], ?_, by simp⟩
    intro m is_keep
    cases is_keep
    exact ⟨measures, rfl⟩
  · exact ⟨fun _ => rfl, by simp, fun why is_fail => ⟨unmeasured, by cases is_fail; rfl⟩⟩
  · simp [required] at not_required

/-- The proof a name computed from the bytes has is not `Kernel`. -/
theorem tagged_is_not_kernel {claim : Claim} {proof : Proof} (not_kernel : proof ≠ .Kernel) :
    tagged claim proof ≠ .Kernel := by
  cases claim <;> simp [tagged, not_kernel]

/-- A name with the proof `Kernel` was asked of the store: only the two cases that name by the
kernel's measure, and the plan that links or reads never does so over the store's object. -/
theorem a_kernel_proof_means_the_store_was_asked : AKernelProofMeansTheStoreWasAsked := by
  intro f seen
  obtain ⟨_, _, _, answered⟩ := verdict_is f seen
  refine WP.spec_mono answered ?_
  intro v answer
  -- a file the kernel measured, linked or read, was asked of the store, which lacks it
  have lacks_when_measured : ∀ {p : Plan} {m : Dig}, PlanIs f seen.kernel seen.held p →
      seen.kernel = some m → (p = .Link ∨ ∃ c merkle, p = .Read c merkle) →
      seen.held = .Lacks := by
    intro p m planned measured shape
    by_contra has_it
    have asks : AsksStore f.claim seen.kernel seen.held := ⟨by simp [askedDig, measured], has_it⟩
    have links := plan_never_links_over_the_store planned asks
    rcases shape with shape | ⟨c, merkle, shape⟩
    · exact links.1 shape
    · exact links.2.1 c merkle shape
  refine ⟨fun n is_name => ?_, fun n is_keep => ?_⟩
  · cases answer with
    | linked_by_measure m _ planned shape seen_kernel =>
      cases is_name
      exact ⟨⟨fun _ => ⟨link_is_on_the_store_fs (shape ▸ planned), seen_kernel⟩, fun _ => rfl⟩,
        fun _ => ⟨by simp [askedDig, seen_kernel],
          lacks_when_measured planned seen_kernel (Or.inl shape)⟩⟩
    | read_by_measure content merkle m _ planned shape _ seen_kernel =>
      cases is_name
      exact ⟨⟨fun _ => ⟨read_is_on_the_store_fs (shape ▸ planned), seen_kernel⟩, fun _ => rfl⟩,
        fun _ => ⟨by simp [askedDig, seen_kernel],
          lacks_when_measured planned seen_kernel (Or.inr ⟨content, merkle, shape⟩)⟩⟩
    | linked_unread _ _ _ _ unmeasured _ =>
      cases is_name
      refine ⟨⟨by simp, ?_⟩, by simp⟩
      rintro ⟨_, seen_kernel⟩
      simp [unmeasured] at seen_kernel
    | read_hashed _ _ _ _ _ _ unmeasured _ =>
      cases is_name
      refine ⟨⟨fun is_kernel => absurd is_kernel (tagged_is_not_kernel (by simp)), ?_⟩,
        fun is_kernel => absurd is_kernel (tagged_is_not_kernel (by simp))⟩
      rintro ⟨_, seen_kernel⟩
      simp [unmeasured] at seen_kernel
    | copy_named _ _ _ _ planned shape _ _ _ _ =>
      cases is_name
      subst shape
      have off := copy_is_off_the_store_fs planned
      refine ⟨⟨fun is_kernel => absurd is_kernel (tagged_is_not_kernel (by simp)), ?_⟩,
        fun is_kernel => absurd is_kernel (tagged_is_not_kernel (by simp))⟩
      rintro ⟨on, _⟩
      simp [off] at on
    | _ => simp at is_name
  · cases answer with
    | kept _ _ _ proof _ _ _ _ _ _ none_store some_kernel =>
      cases is_keep
      constructor
      · intro is_kernel is_none
        simp [none_store is_none] at is_kernel
      · intro measured
        exact some_kernel measured
    | _ => simp at is_keep

end CommitCore
