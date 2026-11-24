-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: what can be said of a plan (`PlanIs`, ThePlan.lean) once something is
-- known of the facts: the store has the object, the file is measured, it is unmeasured and the
-- engine does not vouch for it, it is off the store's file system, it is vouched for, or the store
-- has an object nothing disagrees with.  Each theorem names the plan, or the few plans, that can
-- be, and the plans that cannot.
--
-- Why it is needed: the claims of "a file is never named when ..." and the claims of the other
-- direction ("the honest file is named") both come to knowing which plan was made.  Here that is
-- done once for each case, by taking the cases of `PlanIs` apart.
--
-- Read before this file: Spec.lean, ThePlan.lean.
--
-- Notation: `cases planned with | keep ... => ...` makes one case for each way `planned` can be
-- true and names what is known in it; `exact absurd a b` closes a case in which `a` and its
-- opposite `b` are both known; `simp [h] at x` rewrites `x` with `h` and closes the case if `x`
-- becomes false.
import CommitCore.ClaimFacts
open Aeneas Aeneas.Std Result velarx_commit_core
namespace CommitCore

/-- When the store has the object it is asked about, the plan keeps it (or refuses the file, or
fails for an object the kernel does not measure): it never says to link, read or copy. -/
theorem plan_when_the_store_has_it {f : Facts} {kernel : Option Dig} {held : Held} {p : Plan}
    (planned : PlanIs f kernel held p) (asked : AsksStore f.claim kernel held) :
    (∃ why, p = .Wrong why) ∨ (∃ content, p = .Keep content) ∨ p = .Fail .StoreUnmeasured := by
  cases planned with
  | wrong_malformed why _ => exact Or.inl ⟨why, rfl⟩
  | wrong_differs why _ _ => exact Or.inl ⟨why, rfl⟩
  | fail_store => exact Or.inr (Or.inr rfl)
  | keep content => exact Or.inr (Or.inl ⟨content, rfl⟩)
  | fail_no_measure _ free => exact absurd asked free
  | copy _ _ free => exact absurd asked free
  | link_measured _ free => exact absurd asked free
  | read_measured _ free => exact absurd asked free
  | link_trusted _ free => exact absurd asked free
  | read_hashed _ _ free => exact absurd asked free

/-- The store is asked about the object when the kernel measured the file, or the claim names
the digest of the object. -/
theorem asks_store_of_asked_dig {claim : Claim} {kernel : Option Dig} {held : Held} {d : Dig}
    (asked_dig : askedDig claim kernel = some d) (has_it : held ≠ .Lacks) :
    AsksStore claim kernel held := ⟨by simp [asked_dig], has_it⟩

/-- A plan that reads the bytes for the kernel's measure (the file is measured) asks only for the
content hash, never for the fs-verity digest of the bytes. -/
theorem measured_read_has_no_merkle {f : Facts} {kernel : Option Dig} {held : Held}
    {content merkle : Bool} (read : PlanIs f kernel held (.Read content merkle))
    (measured : kernel ≠ none) : merkle = false := by
  cases read with
  | read_measured => rfl
  | read_hashed _ _ _ _ unmeasured => exact absurd unmeasured measured

/-- A plan that links, reads or copies is not for a file whose object the store has. -/
theorem plan_never_links_over_the_store {f : Facts} {kernel : Option Dig} {held : Held}
    {p : Plan} (planned : PlanIs f kernel held p) (asked : AsksStore f.claim kernel held) :
    p ≠ .Link ∧ (∀ c m, p ≠ .Read c m) ∧ ∀ c, p ≠ .Copy c := by
  rcases plan_when_the_store_has_it planned asked with ⟨why, rfl⟩ | ⟨c, rfl⟩ | rfl <;>
    simp

/-- The plan for a file the kernel measured, whose object the store lacks and whose staging is on
the store's file system, and nothing disagrees with the claim: it links it, or reads it for its
content. -/
theorem plan_for_a_measured_file {f : Facts} {seen : Seen} {m : Dig} {p : Plan}
    (planned : PlanIs f seen.kernel seen.held p) (agrees : ¬ Mismatch f seen)
    (lacks : seen.held = .Lacks) (same_fs : f.same_fs = true) (measured : seen.kernel = some m) :
    p = .Link ∨ p = .Read true false := by
  cases planned with
  | wrong_malformed _ bad => exact absurd bad (fun b => agrees (Or.inl b))
  | wrong_differs _ _ bad => exact absurd bad (fun b => agrees (Or.inr (Or.inl b)))
  | fail_store _ _ _ unmeasured => simp [lacks] at unmeasured
  | keep _ _ asked => exact absurd lacks asked.2
  | fail_no_measure _ _ unmeasured => simp [measured] at unmeasured
  | copy _ _ _ off => simp [same_fs] at off
  | link_measured => exact Or.inl rfl
  | read_measured => exact Or.inr rfl
  | link_trusted _ _ _ unmeasured => simp [measured] at unmeasured
  | read_hashed _ _ _ _ unmeasured => simp [measured] at unmeasured

/-- The plan for a file the kernel did not measure, on the store's file system, whose object the
store lacks, with fs-verity not required, and the engine not vouching for it: it reads it, for
the fs-verity digest, and for the content where the claim has a key. -/
theorem plan_for_an_unmeasured_file {f : Facts} {seen : Seen} {p : Plan}
    (planned : PlanIs f seen.kernel seen.held p) (agrees : ¬ Mismatch f seen)
    (lacks : seen.held = .Lacks) (same_fs : f.same_fs = true)
    (unmeasured : seen.kernel = none) (not_required : f.required = false)
    (not_vouched : ¬ TheEngineVouches f) : ∃ content, p = .Read content true := by
  cases planned with
  | wrong_malformed _ bad => exact absurd bad (fun b => agrees (Or.inl b))
  | wrong_differs _ _ bad => exact absurd bad (fun b => agrees (Or.inr (Or.inl b)))
  | fail_store _ _ _ unmeasured => simp [lacks] at unmeasured
  | keep _ _ asked => exact absurd lacks asked.2
  | fail_no_measure _ _ _ required => simp [not_required] at required
  | copy _ _ _ off => simp [same_fs] at off
  | link_measured _ _ _ measured => exact absurd unmeasured measured
  | read_measured _ _ _ measured => exact absurd unmeasured measured
  | link_trusted _ _ _ _ _ vouched => exact absurd vouched not_vouched
  | read_hashed content => exact ⟨content, rfl⟩

/-- The plan for a file that is not on the store's file system, whose object the store lacks, and
nothing disagrees with the claim: it copies it. -/
theorem plan_for_a_copied_file {f : Facts} {seen : Seen} {p : Plan}
    (planned : PlanIs f seen.kernel seen.held p) (agrees : ¬ Mismatch f seen)
    (lacks : seen.held = .Lacks) (off : f.same_fs = false) : ∃ content, p = .Copy content := by
  cases planned with
  | wrong_malformed _ bad => exact absurd bad (fun b => agrees (Or.inl b))
  | wrong_differs _ _ bad => exact absurd bad (fun b => agrees (Or.inr (Or.inl b)))
  | fail_store _ _ _ unmeasured => simp [lacks] at unmeasured
  | keep _ _ asked => exact absurd lacks asked.2
  | fail_no_measure _ _ _ _ same_fs => simp [off] at same_fs
  | copy content => exact ⟨content, rfl⟩
  | link_measured _ _ same_fs => simp [off] at same_fs
  | read_measured _ _ same_fs => simp [off] at same_fs
  | link_trusted _ _ same_fs => simp [off] at same_fs
  | read_hashed _ _ _ same_fs => simp [off] at same_fs

/-- The plan for a file the engine vouches for, which the kernel did not measure, on the store's
file system, with fs-verity not required and the store lacking the object: it links it unread. -/
theorem plan_for_a_vouched_file {f : Facts} {seen : Seen} {p : Plan}
    (planned : PlanIs f seen.kernel seen.held p) (agrees : ¬ Mismatch f seen)
    (lacks : seen.held = .Lacks) (same_fs : f.same_fs = true)
    (unmeasured : seen.kernel = none) (not_required : f.required = false)
    (vouched : TheEngineVouches f) : p = .Link := by
  cases planned with
  | wrong_malformed _ bad => exact absurd bad (fun b => agrees (Or.inl b))
  | wrong_differs _ _ bad => exact absurd bad (fun b => agrees (Or.inr (Or.inl b)))
  | fail_store _ _ _ unmeasured => simp [lacks] at unmeasured
  | keep _ _ asked => exact absurd lacks asked.2
  | fail_no_measure _ _ _ required => simp [not_required] at required
  | copy _ _ _ off => simp [same_fs] at off
  | link_measured _ _ _ measured => exact absurd unmeasured measured
  | read_measured _ _ _ measured => exact absurd unmeasured measured
  | link_trusted => rfl
  | read_hashed _ _ _ _ _ _ not_vouched => exact absurd vouched not_vouched

/-- The plan for a file whose object the store has and is asked about, when nothing disagrees
with the claim and the object is not unmeasured with fs-verity required: it keeps the object. -/
theorem plan_for_a_known_object {f : Facts} {seen : Seen} {p : Plan}
    (planned : PlanIs f seen.kernel seen.held p) (agrees : ¬ Mismatch f seen)
    (asked : AsksStore f.claim seen.kernel seen.held)
    (fine : ¬ (f.required = true ∧ seen.held = .Unmeasured)) :
    ∃ content, p = .Keep content := by
  rcases plan_when_the_store_has_it planned asked with ⟨why, rfl⟩ | ⟨c, rfl⟩ | rfl
  · cases planned with
    | wrong_malformed _ bad => exact absurd bad (fun b => agrees (Or.inl b))
    | wrong_differs _ _ bad => exact absurd bad (fun b => agrees (Or.inr (Or.inl b)))
  · exact ⟨c, rfl⟩
  · cases planned with
    | fail_store _ _ required unmeasured => exact absurd ⟨required, unmeasured⟩ fine

/-- A plan that links is for a file on the store's file system. -/
theorem link_is_on_the_store_fs {f : Facts} {kernel : Option Dig} {held : Held}
    (planned : PlanIs f kernel held .Link) : f.same_fs = true := by
  cases planned with
  | link_measured _ _ same_fs => exact same_fs
  | link_trusted _ _ same_fs => exact same_fs

/-- A plan that reads is for a file on the store's file system. -/
theorem read_is_on_the_store_fs {f : Facts} {kernel : Option Dig} {held : Held}
    {content merkle : Bool} (planned : PlanIs f kernel held (.Read content merkle)) :
    f.same_fs = true := by
  cases planned with
  | read_measured _ _ same_fs => exact same_fs
  | read_hashed _ _ _ same_fs => exact same_fs

/-- A plan that copies is for a file that is not on the store's file system. -/
theorem copy_is_off_the_store_fs {f : Facts} {kernel : Option Dig} {held : Held}
    {content : Bool} (planned : PlanIs f kernel held (.Copy content)) : f.same_fs = false := by
  cases planned with
  | copy _ _ _ off => exact off

/-- A file read for its fs-verity digest (the kernel measured nothing) is not one that fs-verity
is required for: the plan fails it instead. -/
theorem hashed_read_is_not_required {f : Facts} {kernel : Option Dig} {held : Held}
    {content : Bool} (planned : PlanIs f kernel held (.Read content true)) :
    kernel = none ∧ f.required = false := by
  cases planned with
  | read_hashed _ _ _ _ unmeasured not_required => exact ⟨unmeasured, not_required⟩

/-- A file the kernel did not measure that the plan links is one fs-verity is not required for. -/
theorem unmeasured_link_is_not_required {f : Facts} {kernel : Option Dig} {held : Held}
    (planned : PlanIs f kernel held .Link) (unmeasured : kernel = none) :
    f.required = false := by
  cases planned with
  | link_measured _ _ _ measured => exact absurd unmeasured measured
  | link_trusted _ _ _ _ not_required => exact not_required

/-- A plan that keeps the store's object is for an object the store has and the kernel measures,
or fs-verity is not required. -/
theorem keep_has_the_store {f : Facts} {kernel : Option Dig} {held : Held} {content : Bool}
    (planned : PlanIs f kernel held (.Keep content)) :
    AsksStore f.claim kernel held ∧ ¬ (f.required = true ∧ held = .Unmeasured) := by
  cases planned with
  | keep _ _ asked fine => exact ⟨asked, fine⟩

end CommitCore
