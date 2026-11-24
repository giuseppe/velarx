-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: `answer_has_evidence`, that every answer of `verdict` that names a file
-- (`Name n`) or keeps the store's object (`Keep n`) has `Evidence` (Spec.lean) for the digest
-- `n.verity`: the kernel's measure, or the bytes read, or the engine's word, or, for a kept
-- object of a `Verity` claim, the store's word.
--
-- Why it is needed: this is the central claim of the store (NamedImpliesEvidence), and two others
-- (ReplayedByAnotherProducerIsNeverTrusted, ANameIsAnFsVerityDigest) are read from it.
-- It is proved one way of answering at a time, from the cases of `VerdictIs`
-- (TheVerdict.lean); each case says which of the three evidences it is.
--
-- Read before this file: Spec.lean (`Evidence`, `KernelEvidence`, `ReadEvidence`,
-- `TrustedEvidence`, `TheStoreHoldsIt`), TheVerdict.lean, ClaimFacts.lean.
--
-- Notation: `left`/`right` choose a side of an "or"; `⟨a, b, c⟩` builds an "and" of three
-- facts; `rintro n is_answer; cases is_answer` takes the name `n` and finds that it is the one the
-- case answers; `simp at h` rewrites `h` and closes the case when `h` is false.
import CommitCore.ClaimFacts
open Aeneas Aeneas.Std Result velarx_commit_core
namespace CommitCore

/-- A file that is named or kept agrees with its claim: nothing it reported is refused. -/
theorem answer_agrees {f : Facts} {seen : Seen} {p : Plan} {v : Verdict} {n : Named}
    (answer : VerdictIs f seen p v) (named : v = .Name n ∨ v = .Keep n) :
    ¬ Mismatch f seen := by
  cases answer <;> rcases named with named | named <;> first | assumption | simp at named

/-- Nothing is refused: the claim is not malformed. -/
theorem not_malformed_of_agrees {f : Facts} {seen : Seen} (agrees : ¬ Mismatch f seen) :
    ¬ Malformed f.claim := fun bad => agrees (Or.inl bad)

/-- Nothing is refused: the kernel's measure is not different from what the claim expects. -/
theorem not_differs_kernel_of_agrees {f : Facts} {seen : Seen} (agrees : ¬ Mismatch f seen) :
    ¬ Differs f.claim seen.kernel := fun bad => agrees (Or.inr (Or.inl bad))

/-- Nothing is refused: the computed digest is not different from what the claim expects. -/
theorem not_differs_merkle_of_agrees {f : Facts} {seen : Seen} (agrees : ¬ Mismatch f seen) :
    ¬ Differs f.claim seen.merkle := fun bad => agrees (Or.inr (Or.inr (Or.inl bad)))

/-- Every file the verdict names has evidence, and every object it keeps has evidence or is the
store's word.  Case by case:
- kept: the store was asked about the kernel's measure (the kernel's evidence), or about the
  digest of a `Verity` claim (the store's word);
- linked by the measure, or read and named by it: the kernel's evidence;
- linked unread: the engine's word;
- read and named by the computed digest: the evidence of the bytes read;
- copied and named by the computed digest: the evidence of the bytes read, unless the plan did not
  ask for the content because the kernel measured a replay as the digest it proved: then the
  kernel's evidence. -/
theorem answer_has_evidence {f : Facts} {seen : Seen} {p : Plan} {v : Verdict}
    (answer : VerdictIs f seen p v) :
    (∀ n, v = .Name n → Evidence f seen n.verity) ∧
    (∀ n, v = .Keep n → Evidence f seen n.verity ∨ TheStoreHoldsIt f seen n.verity) := by
  cases answer with
  | refused why _ => exact ⟨by simp, by simp⟩
  | bad_report _ _ => exact ⟨by simp, by simp⟩
  | plan_failed why _ _ _ => exact ⟨by simp, by simp⟩
  | kept_unread _ _ _ _ _ _ => exact ⟨by simp, by simp⟩
  | kept content d checked proof agrees planned shape read asked_dig _ _ _ =>
    subst shape
    refine ⟨by simp, ?_⟩
    rintro n is_answer
    cases is_answer
    simp only
    cases seen_kernel : seen.kernel with
    | none =>
      cases claim_is : f.claim with
      | Verity v =>
        simp [askedDig, seen_kernel, claim_is] at asked_dig
        subst asked_dig
        right
        cases planned with
        | keep _ _ asked fine _ =>
          refine ⟨seen_kernel, claim_is, asked.2, fun required => ?_⟩
          -- the store has the object, and fs-verity required: the plan kept only a measured one
          cases held : seen.held
          · exact absurd held asked.2
          · rfl
          · exact absurd ⟨required, held⟩ fine
      | _ => simp [askedDig, seen_kernel, claim_is] at asked_dig
    | some m =>
      simp [askedDig, seen_kernel] at asked_dig
      subst asked_dig
      left; left
      refine ⟨⟨m, seen_kernel, same_refl m⟩, ?_, fun k is_content => ?_⟩
      · exact allows_of_not_differs (seen_kernel ▸ not_differs_kernel_of_agrees agrees)
      · exact content_key_is_read (plan_keep_reads planned) read is_content
  | linked_by_measure m agrees planned shape seen_kernel =>
    subst shape
    refine ⟨?_, by simp⟩
    rintro n is_answer
    cases is_answer
    left
    refine ⟨⟨m, seen_kernel, same_refl m⟩, ?_, fun k is_content => ?_⟩
    · exact allows_of_not_differs (seen_kernel ▸ not_differs_kernel_of_agrees agrees)
    · exfalso
      cases planned with
      | link_measured _ _ _ _ no_read =>
        exact no_read (by rw [is_content]; exact content_claim_reads)
      | link_trusted _ _ _ unmeasured => simp [seen_kernel] at unmeasured
  | linked_unread d agrees planned shape unmeasured vouched =>
    subst shape
    refine ⟨?_, by simp⟩
    rintro n is_answer
    cases is_answer
    right; right
    have engine := link_unmeasured_is_trusted planned unmeasured
    rcases vouched with claim_is | ⟨k, claim_is⟩
    · exact ⟨engine, d, by simp [claimedVerity, claim_is], same_refl d⟩
    · exact ⟨engine, d, by simp [claimedVerity, claim_is], same_refl d⟩
  | read_unread _ _ _ _ _ _ _ => exact ⟨by simp, by simp⟩
  | read_by_measure content merkle m agrees planned shape read seen_kernel =>
    subst shape
    refine ⟨?_, by simp⟩
    rintro n is_answer
    cases is_answer
    left
    exact ⟨⟨m, seen_kernel, same_refl m⟩,
      allows_of_not_differs (seen_kernel ▸ not_differs_kernel_of_agrees agrees),
      fun k is_content => content_key_is_read (plan_read_reads planned) read is_content⟩
  | read_hashed content d agrees planned shape read seen_kernel merkle =>
    subst shape
    refine ⟨?_, by simp⟩
    rintro n is_answer
    cases is_answer
    right; left
    refine ⟨⟨d, merkle, same_refl d⟩,
      allows_of_not_differs (merkle ▸ not_differs_merkle_of_agrees agrees), fun k has_key => ?_⟩
    have asked : content = true :=
      (plan_read_reads planned).mpr (seen_kernel ▸ key_is_read_when_unmeasured has_key)
    obtain ⟨k', c, key, got, same⟩ := read asked
    rw [has_key] at key
    simp only [Option.some.injEq] at key
    subst key
    exact ⟨c, got, same⟩
  | read_not_hashed _ _ _ _ _ _ _ => exact ⟨by simp, by simp⟩
  | copy_unread _ _ _ _ _ _ => exact ⟨by simp, by simp⟩
  | copy_unmeasured _ _ _ _ _ _ _ => exact ⟨by simp, by simp⟩
  | copy_not_hashed _ _ _ _ _ _ _ => exact ⟨by simp, by simp⟩
  | copy_named content d checked agrees planned shape read merkle _ _ =>
    subst shape
    refine ⟨?_, by simp⟩
    rintro n is_answer
    cases is_answer
    simp only
    have allows : Allows f.claim d :=
      allows_of_not_differs (merkle ▸ not_differs_merkle_of_agrees agrees)
    have reads := plan_copy_reads planned
    -- the key is read when the plan asks for the content; otherwise the kernel proved the replay
    by_cases asks : ReadsContent f.claim seen.kernel
    · right; left
      refine ⟨⟨d, merkle, same_refl d⟩, allows, fun k has_key => ?_⟩
      obtain ⟨k', c, key, got, same⟩ := read (reads.mpr asks)
      rw [has_key] at key
      simp only [Option.some.injEq] at key
      subst key
      exact ⟨c, got, same⟩
    · cases claim_is : f.claim with
      | Replayed k r =>
        left
        have measured : ∃ m, seen.kernel = some m ∧ Same m r := by
          by_contra none_measured
          exact asks (by simp [ReadsContent, claim_is, none_measured])
        obtain ⟨m, seen_kernel, same⟩ := measured
        refine ⟨⟨m, seen_kernel, ?_⟩, allows, fun k is_content => by simp [claim_is] at is_content⟩
        exact same_trans same (allows r (by rw [claim_is]; rfl))
      | Content k => exact absurd (by simp [ReadsContent, claim_is]) asks
      | Verity _ | Verified _ | Engine =>
        right; left
        exact ⟨⟨d, merkle, same_refl d⟩, allows,
          fun k has_key => by simp [contentKey, claim_is] at has_key⟩

end CommitCore
