-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: small facts about claims and about the plans of the content, that the
-- proofs of the claims use again and again: a digest that does not differ from what the claim
-- expects is allowed by it, a claim that is not malformed expects a digest that is an fs-verity
-- one, a plan that asks for the content has its flag in the words of `ReadsContent`, and the key
-- of a `Content` claim is read when the plan asked for the content.
--
-- Why it is needed: each of these would otherwise be proved again in each case of each claim.
--
-- Read before this file: Spec.lean, ThePlan.lean, TheVerdict.lean.
--
-- Notation: `Allows claim d` is "the claim allows `d` as its fs-verity digest"; `by_contra h`
-- supposes the opposite and looks for a contradiction; `simp_all` simplifies all the facts.
import CommitCore.TheVerdict
import CommitCore.SameDigest
open Aeneas Aeneas.Std Result velarx_commit_core
namespace CommitCore

/-- A digest reported that is not different from what the claim expects is allowed by it. -/
theorem allows_of_not_differs {claim : Claim} {d : Dig}
    (agrees : ¬ Differs claim (some d)) : Allows claim d := by
  intro e expected
  by_contra differ
  exact agrees ⟨e, d, expected, rfl, differ⟩

/-- A claim that is not malformed expects an fs-verity digest, if it expects one. -/
theorem expected_is_fs_verity {claim : Claim} {e : Dig} (fine : ¬ Malformed claim)
    (expected : claimedVerity claim = some e) : e.verity = true := by
  by_contra not_verity
  exact fine ⟨e, expected, by simpa using not_verity⟩

/-- With no kernel's measure to prove it, a claim that has a key asks for the content. -/
theorem key_is_read_when_unmeasured {claim : Claim} {k : Dig}
    (has_key : contentKey claim = some k) : ReadsContent claim none := by
  cases claim <;> simp_all [contentKey, ReadsContent]

/-- A `Content` claim always asks for the content to be read. -/
theorem content_claim_reads {kernel : Option Dig} {k : Dig} :
    ReadsContent (.Content k) kernel := trivial

/-- A plan that keeps the store's object asks for the content exactly when the claim needs it. -/
theorem plan_keep_reads {f : Facts} {kernel : Option Dig} {held : Held} {content : Bool}
    (planned : PlanIs f kernel held (.Keep content)) :
    content = true ↔ ReadsContent f.claim kernel := by
  cases planned with
  | keep _ _ _ _ reads => exact reads

/-- A plan that copies the file asks for the content exactly when the claim needs it. -/
theorem plan_copy_reads {f : Facts} {kernel : Option Dig} {held : Held} {content : Bool}
    (planned : PlanIs f kernel held (.Copy content)) :
    content = true ↔ ReadsContent f.claim kernel := by
  cases planned with
  | copy _ _ _ _ reads => exact reads

/-- A plan that reads the file asks for the content exactly when the claim needs it. -/
theorem plan_read_reads {f : Facts} {kernel : Option Dig} {held : Held}
    {content merkle : Bool} (planned : PlanIs f kernel held (.Read content merkle)) :
    content = true ↔ ReadsContent f.claim kernel := by
  cases planned with
  | read_measured _ _ _ _ reads => exact ⟨fun _ => reads, fun _ => rfl⟩
  | read_hashed _ _ _ _ _ _ _ reads => exact reads

/-- The content hash the plan asked for was read and is the key; so a `Content` claim's key is
read when the plan asks for the content (as it always does for such a claim). -/
theorem content_key_is_read {f : Facts} {seen : Seen} {content : Bool} {k : Dig}
    (reads : content = true ↔ ReadsContent f.claim seen.kernel)
    (read : ContentRead f.claim content seen) (is_content : f.claim = .Content k) :
    KeyIsRead seen k := by
  have asked : content = true := reads.mpr (by rw [is_content]; exact content_claim_reads)
  obtain ⟨k', c, key, got, same⟩ := read asked
  rw [is_content] at key
  simp only [contentKey, Option.some.injEq] at key
  subst key
  exact ⟨c, got, same⟩

end CommitCore
