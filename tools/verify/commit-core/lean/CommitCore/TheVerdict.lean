-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: what `verdict` (crates/commit-core, src/lib.rs) answers, case by case.
-- `VerdictIs f seen p v` says that `v` is one of the answers `verdict` gives for these facts and
-- this report of the shell, when the plan `plan` makes is `p`, with the conditions of that case.
-- `verdict_is` says that `verdict` returns, that the plan it follows is the one `plan` makes
-- (`plan f seen.kernel seen.held`, which `verdict` asks for itself), and that its answer is
-- `VerdictIs`.
--
-- Why it is needed: the claims of Spec.lean are about the answers, not about the order of the
-- checks in the code.  `verdict` is read once here, from the refusal (a digest that disagrees
-- is refused before anything else) through the five plans, and every claim is proved from the
-- list of cases below.  Each case is written with the words of the claims and with everything that
-- is known when the code takes it, so a claim that rules a case out has the fact in hand.
--
-- Read before this file: Spec.lean, SmallFunctions.lean, ThePlan.lean and `verdict` in src/lib.rs.
--
-- Notation: as in ThePlan.lean; `⟨d, checked, proof⟩` is the record `Named` (the digest, whether
-- the kernel measured it, and why it was named); `subst h` replaces a name by what an equation
-- says it is; `rcases h with a | b` makes a case for each way `h` can be true.
import CommitCore.ThePlan
open Aeneas Aeneas.Std Result velarx_commit_core
namespace CommitCore

/-- The content hash the plan asked for was read and is the key. -/
def ContentRead (claim : Claim) (content : Bool) (seen : Seen) : Prop :=
  content = true → ∃ k c, contentKey claim = some k ∧ seen.content = some c ∧ Same k c

/-- `content_checked` says nothing is wrong when the content was not asked for or was read and is
the key, and `Fail Unread` when it was asked for and not read (it can say nothing else once the
claim agrees with what was reported and has a key whenever it asks for the content). -/
theorem content_checked_spec (f : Facts) (content : Bool) (seen : Seen)
    (agrees : ¬ KeyDiffers f.claim seen.content)
    (has_key : content = true → contentKey f.claim ≠ none) :
    content_checked f content seen ⦃ o =>
      (o = none ∧ ContentRead f.claim content seen) ∨
      (o = some (Verdict.Fail Why.Unread) ∧ content = true ∧ seen.content = none) ⦄ := by
  unfold content_checked
  cases content with
  | false => simp [ContentRead]
  | true =>
    cases seen_content : seen.content with
    | none => simp
    | some c =>
      simp only [↓reduceIte]
      rw [key_of_eq]
      simp only [Std.bind_ok]
      cases claim_key : contentKey f.claim with
      | none => exact absurd claim_key (has_key rfl)
      | some k =>
        simp only
        refine WP.spec_bind (dig_eq_spec k c) ?_
        intro same is_same
        have agree : Same k c := by
          by_contra differ
          exact agrees ⟨k, c, claim_key, seen_content, differ⟩
        have same_true : same = true := is_same.mpr agree
        simp [same_true, ContentRead, claim_key, seen_content, agree]

/-- The proof a digest computed from the bytes is given: the engine's own file is `Trusted`. -/
def tagged (claim : Claim) (proof : Proof) : Proof :=
  match claim with
  | .Engine => .Trusted
  | _ => proof

/-- `computed` fails (`Unread`) when no digest was computed, else names the file by it, with the
proof it is given (the engine's own file is `Trusted`). -/
theorem computed_spec (f : Facts) (proof : Proof) (d : Option Dig) (checked : Bool) :
    computed f proof d checked ⦃ v =>
      (d = none ∧ v = .Fail .Unread) ∨
      ∃ d1, d = some d1 ∧ v = .Name ⟨d1, checked, tagged f.claim proof⟩ ⦄ := by
  cases d <;> cases claim : f.claim <;> simp [computed, claim, tagged]

/-- What `verdict` answers, case by case, for the plan `p` that `plan` makes: each way out of
`verdict` with what is known when it takes it.  `VerdictIs f seen p v` says that `v` is one of
the answers.  The claims of Spec.lean are proved from this, not from the code.  In order:
- `refused`: something reported disagrees with the claim: `Wrong`;
- `bad_report`: what the shell reported as fs-verity digests is not: `Fail NotFsVerity`;
- `plan_failed`: the plan is a failure (no measure with fs-verity required, or an object the
  kernel does not measure): the same `Fail`;
- `kept_unread`, `kept`: the plan keeps the store's object; the content asked for was not read
  (`Fail Unread`), or it was and the object is kept under the digest the store was asked about;
- `linked_by_measure`, `linked_unread`: the plan links the file, named by the kernel's measure,
  or (no measure, the engine vouches) by the digest of the claim;
- `read_unread`, `read_by_measure`, `read_hashed`, `read_not_hashed`: the plan reads the file:
  the content was not read, or the kernel's measure names it, or the computed digest names it,
  or none was computed (`Fail Unread`);
- `copy_unread`, `copy_unmeasured`, `copy_not_hashed`, `copy_named`: the plan copies the file:
  the content was not read, or fs-verity is required and the kernel did not measure the copy
  as what was hashed (`Fail NoMeasure`), or nothing was hashed, or the computed digest names it
  (`checked` when the kernel measured the copy). -/
inductive VerdictIs (f : Facts) (seen : Seen) (p : Plan) : Verdict → Prop
  | refused (why : Why) : Mismatch f seen → VerdictIs f seen p (.Wrong why)
  | bad_report : ¬ Mismatch f seen → ¬ ReportsAreFsVerity seen →
      VerdictIs f seen p (.Fail .NotFsVerity)
  | plan_failed (why : Why) : ¬ Mismatch f seen → PlanIs f seen.kernel seen.held p →
      p = .Fail why → VerdictIs f seen p (.Fail why)
  | kept_unread (content : Bool) : ¬ Mismatch f seen → PlanIs f seen.kernel seen.held p →
      p = .Keep content → content = true → seen.content = none →
      VerdictIs f seen p (.Fail .Unread)
  | kept (content : Bool) (d : Dig) (checked : Bool) (proof : Proof) :
      ¬ Mismatch f seen → PlanIs f seen.kernel seen.held p → p = .Keep content →
      ContentRead f.claim content seen → askedDig f.claim seen.kernel = some d →
      (checked = true ↔ seen.held = .Measures) →
      (seen.kernel = none → proof = .Store) → (seen.kernel ≠ none → proof = .Kernel) →
      VerdictIs f seen p (.Keep ⟨d, checked, proof⟩)
  | linked_by_measure (m : Dig) : ¬ Mismatch f seen → PlanIs f seen.kernel seen.held p →
      p = .Link → seen.kernel = some m → VerdictIs f seen p (.Name ⟨m, true, .Kernel⟩)
  | linked_unread (d : Dig) : ¬ Mismatch f seen → PlanIs f seen.kernel seen.held p →
      p = .Link → seen.kernel = none → (f.claim = .Verified d ∨ ∃ k, f.claim = .Replayed k d) →
      VerdictIs f seen p (.Name ⟨d, false, .Trusted⟩)
  | read_unread (content merkle : Bool) : ¬ Mismatch f seen →
      PlanIs f seen.kernel seen.held p → p = .Read content merkle → content = true →
      seen.content = none → VerdictIs f seen p (.Fail .Unread)
  | read_by_measure (content merkle : Bool) (m : Dig) : ¬ Mismatch f seen →
      PlanIs f seen.kernel seen.held p → p = .Read content merkle →
      ContentRead f.claim content seen → seen.kernel = some m →
      VerdictIs f seen p (.Name ⟨m, true, .Kernel⟩)
  | read_hashed (content : Bool) (d : Dig) : ¬ Mismatch f seen →
      PlanIs f seen.kernel seen.held p → p = .Read content true →
      ContentRead f.claim content seen → seen.kernel = none → seen.merkle = some d →
      VerdictIs f seen p (.Name ⟨d, false, tagged f.claim .Read⟩)
  | read_not_hashed (content : Bool) : ¬ Mismatch f seen →
      PlanIs f seen.kernel seen.held p → p = .Read content true →
      ContentRead f.claim content seen → seen.kernel = none → seen.merkle = none →
      VerdictIs f seen p (.Fail .Unread)
  | copy_unread (content : Bool) : ¬ Mismatch f seen → PlanIs f seen.kernel seen.held p →
      p = .Copy content → content = true → seen.content = none →
      VerdictIs f seen p (.Fail .Unread)
  | copy_unmeasured (content : Bool) : ¬ Mismatch f seen → PlanIs f seen.kernel seen.held p →
      p = .Copy content → ContentRead f.claim content seen → f.required = true →
      ¬ CopyMeasured seen → VerdictIs f seen p (.Fail .NoMeasure)
  | copy_not_hashed (content : Bool) : ¬ Mismatch f seen →
      PlanIs f seen.kernel seen.held p → p = .Copy content →
      ContentRead f.claim content seen → f.required = false → seen.merkle = none →
      VerdictIs f seen p (.Fail .Unread)
  | copy_named (content : Bool) (d : Dig) (checked : Bool) : ¬ Mismatch f seen →
      PlanIs f seen.kernel seen.held p → p = .Copy content →
      ContentRead f.claim content seen → seen.merkle = some d →
      (checked = true ↔ CopyMeasured seen) → (f.required = true → checked = true) →
      VerdictIs f seen p (.Name ⟨d, checked, tagged f.claim .Copy⟩)

/-- `verdict` returns, follows the plan `plan` makes, and answers as `VerdictIs` says.  The
proof follows the code: first the refusal, then the plan (`Keep`, `Link`, `Read`, `Copy`) and,
for each, what the shell reported. -/
theorem verdict_is_and_reports (f : Facts) (seen : Seen) :
    ∃ p, plan f seen.kernel seen.held = ok p ∧ PlanIs f seen.kernel seen.held p ∧
      verdict f seen ⦃ v => VerdictIs f seen p v ∧
        (ReportsAreFsVerity seen ∨ ∀ n, v ≠ .Name n ∧ v ≠ .Keep n) ⦄ := by
  obtain ⟨p, is_plan, planned⟩ := spec_gives_ok (plan_is f seen.kernel seen.held)
  refine ⟨p, is_plan, planned, ?_⟩
  unfold verdict
  refine WP.spec_bind (reported_spec f seen) ?_
  intro mismatch_why is_reported
  cases mismatch_why with
  | some why =>
    simp only [WP.spec_ok]
    exact ⟨VerdictIs.refused why (by simpa using is_reported), Or.inr (by simp)⟩
  | none =>
    have agrees : ¬ Mismatch f seen := by simpa using is_reported
    have key_agrees : ¬ KeyDiffers f.claim seen.content :=
      fun differs => agrees (Or.inr (Or.inr (Or.inr (Or.inl differs))))
    refine WP.spec_bind (reports_fs_verity_spec seen) ?_
    intro reports_ok is_reports
    cases reports_ok with
    | false =>
      simp only [Bool.false_eq_true, ↓reduceIte, WP.spec_ok]
      exact ⟨VerdictIs.bad_report agrees (fun reports => by simpa using is_reports.mpr reports),
        Or.inr (by simp)⟩
    | true =>
      simp only [↓reduceIte]
      have reports := is_reports.mp rfl
      refine WP.spec_mono (P₀ := fun v => VerdictIs f seen p v) ?_ fun _ a => ⟨a, Or.inl reports⟩
      rw [is_plan]
      simp only [Std.bind_ok]
      -- nothing reported disagrees; the plan is followed
      cases p with
      | Wrong why =>
        -- a plan that refuses is for a disagreement, which there is not
        exact absurd (plan_wrong_is_a_mismatch planned seen rfl) agrees
      | Fail why =>
        -- the plan fails: so does the verdict
        simp only [WP.spec_ok]
        exact VerdictIs.plan_failed why agrees planned rfl
      | Keep content =>
        -- the store has the object: the content asked for is checked, then the object is kept
        have has_key : content = true → contentKey f.claim ≠ none := by
          cases planned with
          | keep _ _ _ _ reads => exact fun yes => reads_content_has_key (reads.mp yes)
        refine WP.spec_bind (content_checked_spec f content seen key_agrees has_key) ?_
        intro o1 is_checked
        rw [asked_eq]
        simp only [Std.bind_ok]
        rcases is_checked with ⟨rfl, read⟩ | ⟨rfl, yes, unread⟩
        · -- the content, if one was asked for, is the key
          have asks : askedDig f.claim seen.kernel ≠ none := by
            cases planned with
            | keep _ _ asked _ _ => exact asked.1
          cases asked_dig : askedDig f.claim seen.kernel with
          | none => exact absurd asked_dig asks
          | some d =>
            simp only
            cases seen_kernel : seen.kernel with
            | none =>
              simp only [Std.bind_ok]
              refine WP.spec_bind (held_eq_spec seen.held Held.Measures) ?_
              intro measures is_measures
              simp only [WP.spec_ok]
              exact VerdictIs.kept content d measures .Store agrees planned rfl read asked_dig
                is_measures (fun _ => rfl) (fun some_kernel => absurd seen_kernel some_kernel)
            | some m =>
              simp only [Std.bind_ok]
              refine WP.spec_bind (held_eq_spec seen.held Held.Measures) ?_
              intro measures is_measures
              simp only [WP.spec_ok]
              exact VerdictIs.kept content d measures .Kernel agrees planned rfl read asked_dig
                is_measures (fun none_kernel => absurd none_kernel (by simp [seen_kernel]))
                (fun _ => rfl)
        · simp only [WP.spec_ok]
          exact VerdictIs.kept_unread content agrees planned rfl yes unread
      | Link =>
        -- linked: by the kernel's measure, else by the claim of the engine
        cases seen_kernel : seen.kernel with
        | some m =>
          simp only [WP.spec_ok]
          exact VerdictIs.linked_by_measure m agrees planned rfl seen_kernel
        | none =>
          have trusted := link_unmeasured_is_trusted planned seen_kernel
          cases claim_is : f.claim with
          | Replayed k d =>
            simp only [WP.spec_ok]
            exact VerdictIs.linked_unread d agrees planned rfl seen_kernel (Or.inr ⟨k, claim_is⟩)
          | Verified d =>
            simp only [WP.spec_ok]
            exact VerdictIs.linked_unread d agrees planned rfl seen_kernel (Or.inl claim_is)
          | Verity _ => simp [TheEngineVouches, claim_is] at trusted
          | Content _ => simp [TheEngineVouches, claim_is] at trusted
          | Engine => simp [TheEngineVouches, claim_is] at trusted
      | Read content merkle =>
        -- read: the content asked for is checked, then the file is named by the kernel's measure
        -- or by the digest computed from the bytes
        have has_key : content = true → contentKey f.claim ≠ none := by
          cases planned with
          | read_measured _ _ _ _ reads => exact fun _ => reads_content_has_key reads
          | read_hashed _ _ _ _ _ _ _ reads => exact fun yes => reads_content_has_key (reads.mp yes)
        refine WP.spec_bind (content_checked_spec f content seen key_agrees has_key) ?_
        intro o1 is_checked
        rcases is_checked with ⟨rfl, read⟩ | ⟨rfl, yes, unread⟩
        · cases seen_kernel : seen.kernel with
          | some m =>
            simp only [WP.spec_ok]
            exact VerdictIs.read_by_measure content merkle m agrees planned rfl read seen_kernel
          | none =>
            have hashes := read_unmeasured_hashes planned seen_kernel
            subst hashes
            simp only [↓reduceIte]
            refine WP.spec_mono (computed_spec f .Read seen.merkle false) ?_
            rintro v (⟨no_merkle, rfl⟩ | ⟨d, merkle, rfl⟩)
            · exact VerdictIs.read_not_hashed content agrees planned rfl read seen_kernel no_merkle
            · exact VerdictIs.read_hashed content d agrees planned rfl read seen_kernel merkle
        · simp only [WP.spec_ok]
          exact VerdictIs.read_unread content merkle agrees planned rfl yes unread
      | Copy content =>
        -- copied: the content asked for is checked, then the file is named by the digest computed
        -- from the bytes, and checked when the kernel measured the copy as that digest
        have has_key : content = true → contentKey f.claim ≠ none := by
          cases planned with
          | copy _ _ _ _ reads => exact fun yes => reads_content_has_key (reads.mp yes)
        refine WP.spec_bind (content_checked_spec f content seen key_agrees has_key) ?_
        intro o1 is_checked
        rcases is_checked with ⟨rfl, read⟩ | ⟨rfl, yes, unread⟩
        · simp only
          -- the copy is checked when the kernel measures it as what was hashed
          refine WP.spec_bind (measured_as_spec seen.copy_kernel seen.merkle) ?_
          intro checked measured
          cases required : f.required
          · simp only [Bool.false_eq_true, ↓reduceIte]
            refine WP.spec_mono (computed_spec f .Copy seen.merkle checked) ?_
            rintro v (⟨no_merkle, rfl⟩ | ⟨d, merkle, rfl⟩)
            · exact VerdictIs.copy_not_hashed content agrees planned rfl read required no_merkle
            · exact VerdictIs.copy_named content d checked agrees planned rfl read merkle measured
                (fun requires => by simp [required] at requires)
          · simp only [↓reduceIte]
            cases checked with
            | false =>
              simp only [Bool.false_eq_true, ↓reduceIte, WP.spec_ok]
              exact VerdictIs.copy_unmeasured content agrees planned rfl read required
                (fun is_measured => absurd (measured.mpr is_measured) (by simp))
            | true =>
              simp only [↓reduceIte]
              refine WP.spec_mono (computed_spec f .Copy seen.merkle true) ?_
              rintro v (⟨no_merkle, rfl⟩ | ⟨d, merkle, rfl⟩)
              · obtain ⟨_, _, _, has_merkle, _⟩ := measured.mp rfl
                simp [no_merkle] at has_merkle
              · exact VerdictIs.copy_named content d true agrees planned rfl read merkle measured
                  (fun _ => rfl)
        · simp only [WP.spec_ok]
          exact VerdictIs.copy_unread content agrees planned rfl yes unread

end CommitCore

namespace CommitCore

/-- `verdict` returns, follows the plan `plan` makes, and answers as `VerdictIs` says. -/
theorem verdict_is (f : Facts) (seen : Seen) :
    ∃ p, plan f seen.kernel seen.held = ok p ∧ PlanIs f seen.kernel seen.held p ∧
      verdict f seen ⦃ v => VerdictIs f seen p v ⦄ := by
  obtain ⟨p, is_plan, planned, answered⟩ := verdict_is_and_reports f seen
  exact ⟨p, is_plan, planned, WP.spec_mono answered (fun _ answer => answer.1)⟩

end CommitCore
