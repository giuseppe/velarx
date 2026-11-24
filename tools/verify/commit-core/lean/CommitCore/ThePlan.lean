-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: what `plan` (crates/commit-core, src/lib.rs) answers, case by case.
-- `PlanIs f kernel held p` says that `p` is one of the plans `plan` can make for these facts, the
-- kernel's measure and the state of the store, with the conditions of the case (the claim is
-- well formed, the store is asked or not, the file is on the store's file system or not, ...).
-- `plan_is` says that `plan` returns, and its plan is `PlanIs`.  The rest are facts that follow
-- from a plan being `PlanIs` and that the claims use.
--
-- Why it is needed: Aeneas writes `plan` as a tree of `if` and `match` with the end of the
-- decision copied three times.  The claims are about the answers, not about the tree, so the tree
-- is read once here, and every claim is proved from the list of cases below.  The cases are
-- written with the words of the claims (`Malformed`, `Differs`, `ReadsContent`,
-- `TheEngineVouches`), in the order `plan` takes them, each with all that is known when it
-- takes it, so no two of them hold together except the plans that differ only in the reason.
--
-- Read before this file: Spec.lean, SmallFunctions.lean, and `plan` in src/lib.rs.
--
-- Notation: `inductive PlanIs ... | wrong_malformed ...` lists the ways a statement can be
-- true; to use one, `cases planned` makes a case for each way (the cases that cannot be, because
-- the plan is known, disappear); `A → B → C` is "if A and B then C"; `h ▸ x` rewrites `x` with
-- the equation `h`; `rw`, `simp`, `exact` are the usual tactics, `by_cases` splits on a statement.
import CommitCore.SmallFunctions
open Aeneas Aeneas.Std Result velarx_commit_core
namespace CommitCore

/-- Nothing is wrong with the claim or with the kernel's measure against it: `plan` goes on. -/
def Fine (f : Facts) (kernel : Option Dig) : Prop :=
  ¬ Malformed f.claim ∧ ¬ Differs f.claim kernel

/-- The store is asked about an object (the kernel measured the file, or the claim names the
digest) and has it. -/
def AsksStore (claim : Claim) (kernel : Option Dig) (held : Held) : Prop :=
  askedDig claim kernel ≠ none ∧ held ≠ Held.Lacks

/-- The plans `plan` makes, each with what is true when it makes it.  In order:
- the claim cannot be met, or the kernel's measure is not the one it expects: `Wrong`;
- the store has the object, fs-verity is required and the kernel does not measure it: `Fail`;
- the store has the object: `Keep` it, reading the content if the claim asks for it;
- nothing is asked of the store, no measure, fs-verity required, same file system: `Fail`;
- not on the store's file system: `Copy`;
- the kernel measured it: `Link` it, or `Read` it for the content first;
- the kernel measured nothing: `Link` it unread if the engine vouches for it, else `Read` it
  for its fs-verity digest (and the content where the claim has a key). -/
inductive PlanIs (f : Facts) (kernel : Option Dig) (held : Held) : Plan → Prop
  | wrong_malformed (why : Why) : Malformed f.claim → PlanIs f kernel held (.Wrong why)
  | wrong_differs (why : Why) : ¬ Malformed f.claim → Differs f.claim kernel →
      PlanIs f kernel held (.Wrong why)
  | fail_store : Fine f kernel → AsksStore f.claim kernel held → f.required = true →
      held = .Unmeasured → PlanIs f kernel held (.Fail .StoreUnmeasured)
  | keep (content : Bool) : Fine f kernel → AsksStore f.claim kernel held →
      ¬ (f.required = true ∧ held = .Unmeasured) →
      (content = true ↔ ReadsContent f.claim kernel) → PlanIs f kernel held (.Keep content)
  | fail_no_measure : Fine f kernel → ¬ AsksStore f.claim kernel held → kernel = none →
      f.required = true → f.same_fs = true → PlanIs f kernel held (.Fail .NoMeasure)
  | copy (content : Bool) : Fine f kernel → ¬ AsksStore f.claim kernel held →
      f.same_fs = false → (content = true ↔ ReadsContent f.claim kernel) →
      PlanIs f kernel held (.Copy content)
  | link_measured : Fine f kernel → ¬ AsksStore f.claim kernel held → f.same_fs = true →
      kernel ≠ none → ¬ ReadsContent f.claim kernel → PlanIs f kernel held .Link
  | read_measured : Fine f kernel → ¬ AsksStore f.claim kernel held → f.same_fs = true →
      kernel ≠ none → ReadsContent f.claim kernel → PlanIs f kernel held (.Read true false)
  | link_trusted : Fine f kernel → ¬ AsksStore f.claim kernel held → f.same_fs = true →
      kernel = none → f.required = false → TheEngineVouches f → PlanIs f kernel held .Link
  | read_hashed (content : Bool) : Fine f kernel → ¬ AsksStore f.claim kernel held →
      f.same_fs = true → kernel = none → f.required = false → ¬ TheEngineVouches f →
      (content = true ↔ ReadsContent f.claim kernel) → PlanIs f kernel held (.Read content true)

/-- What `plan` does once the store is not in question, as Aeneas wrote it (three copies of
the same decision, one inside each branch). -/
def planWhenFree (f : Facts) (kernel : Option Dig) (content : Bool) : Result Plan :=
  if core.option.Option.is_none kernel = true then
    if f.required = true then
      if f.same_fs = true then ok (Plan.Fail Why.NoMeasure)
      else
        if f.same_fs = true then
          match kernel with
          | none =>
            match f.claim with
            | Claim.Verity _ => ok (Plan.Read content true)
            | Claim.Content _ => ok (Plan.Read content true)
            | Claim.Replayed _ _ =>
              if f.own = true then ok Plan.Link else ok (Plan.Read content true)
            | Claim.Engine => ok (Plan.Read content true)
            | Claim.Verified _ => ok Plan.Link
          | some _ => if content = true then ok (Plan.Read content false) else ok Plan.Link
        else ok (Plan.Copy content)
    else
      if f.same_fs = true then
        match kernel with
        | none =>
          match f.claim with
          | Claim.Verity _ => ok (Plan.Read content true)
          | Claim.Content _ => ok (Plan.Read content true)
          | Claim.Replayed _ _ =>
            if f.own = true then ok Plan.Link else ok (Plan.Read content true)
          | Claim.Engine => ok (Plan.Read content true)
          | Claim.Verified _ => ok Plan.Link
        | some _ => if content = true then ok (Plan.Read content false) else ok Plan.Link
      else ok (Plan.Copy content)
  else
    if f.same_fs = true then
      match kernel with
      | none =>
        match f.claim with
        | Claim.Verity _ => ok (Plan.Read content true)
        | Claim.Content _ => ok (Plan.Read content true)
        | Claim.Replayed _ _ =>
          if f.own = true then ok Plan.Link else ok (Plan.Read content true)
        | Claim.Engine => ok (Plan.Read content true)
        | Claim.Verified _ => ok Plan.Link
      | some _ => if content = true then ok (Plan.Read content false) else ok Plan.Link
    else ok (Plan.Copy content)

/-- The plan when the store is not in question is `PlanIs`: whether the kernel measured the file,
whether fs-verity is required, whether the staging is on the store's file system, whether the
content is asked for, and which claim (and whether it is own) decide it. -/
theorem plan_when_free (f : Facts) (kernel : Option Dig) (held : Held) (content : Bool)
    (fine : Fine f kernel) (free : ¬ AsksStore f.claim kernel held)
    (reads : content = true ↔ ReadsContent f.claim kernel) :
    planWhenFree f kernel content ⦃ p => PlanIs f kernel held p ⦄ := by
  unfold planWhenFree
  cases kernel with
  | none =>
    cases required : f.required <;> cases same_fs : f.same_fs <;> cases content <;>
      cases claim_is : f.claim <;> cases own : f.own <;>
      simp only [core.option.Option.is_none, Option.isNone_none, Bool.false_eq_true,
        ↓reduceIte, WP.spec_ok] <;>
      first
      | exact PlanIs.fail_no_measure fine free rfl required same_fs
      | exact PlanIs.copy _ fine free same_fs reads
      | exact PlanIs.link_trusted fine free same_fs rfl required
          (by simp [TheEngineVouches, claim_is, own])
      | exact PlanIs.read_hashed _ fine free same_fs rfl required
          (by simp [TheEngineVouches, claim_is, own]) reads
  | some measure =>
    cases required : f.required <;> cases same_fs : f.same_fs <;> cases content <;>
      simp only [core.option.Option.is_none, Option.isNone_some, Bool.false_eq_true,
        ↓reduceIte, WP.spec_ok] <;>
      first
      | exact PlanIs.copy _ fine free same_fs reads
      | exact PlanIs.link_measured fine free same_fs (by simp) (by simpa using reads)
      | exact PlanIs.read_measured fine free same_fs (by simp) (reads.mp rfl)

/-- `plan` returns, and its plan is `PlanIs`.  Two steps (the store is asked, the file system):
`plan_when_free` is the case where nothing is asked of the store, which the code reaches in two
places. -/
theorem plan_is (f : Facts) (kernel : Option Dig) (held : Held) :
    plan f kernel held ⦃ p => PlanIs f kernel held p ⦄ := by
  unfold plan
  -- the claim cannot be met
  refine WP.spec_bind (malformed_spec f.claim) ?_
  intro malformed_claim is_malformed
  cases malformed_claim with
  | some why =>
    simp only [WP.spec_ok]
    exact PlanIs.wrong_malformed why (by simpa using is_malformed)
  | none =>
    have not_malformed : ¬ Malformed f.claim := by simpa using is_malformed
    -- the kernel's measure is not the one the claim expects
    refine WP.spec_bind (differs_spec f.claim kernel false) ?_
    intro kernel_differs is_differs
    cases kernel_differs with
    | some why =>
      simp only [WP.spec_ok]
      exact PlanIs.wrong_differs why not_malformed (by simpa using is_differs)
    | none =>
      have not_differs : ¬ Differs f.claim kernel := by simpa using is_differs
      have fine : Fine f kernel := ⟨not_malformed, not_differs⟩
      refine WP.spec_bind (reads_content_spec f.claim kernel) ?_
      intro content reads
      rw [asked_eq]
      simp only [Std.bind_ok]
      -- the store is asked about an object, and has it
      by_cases store_asked : askedDig f.claim kernel ≠ none
      · have is_some : core.option.Option.is_some (askedDig f.claim kernel) = true := by
          cases h : askedDig f.claim kernel <;> simp_all [core.option.Option.is_some]
        simp only [is_some, ↓reduceIte]
        refine WP.spec_bind (held_ne_spec held Held.Lacks) ?_
        intro has_it is_has_it
        by_cases has : has_it = true
        · have in_store : held ≠ Held.Lacks := is_has_it.mp has
          have asked : AsksStore f.claim kernel held := ⟨store_asked, in_store⟩
          simp only [has, ↓reduceIte]
          cases required : f.required
          · simp only [Bool.false_eq_true, ↓reduceIte, WP.spec_ok]
            exact PlanIs.keep content fine asked (by simp [required]) reads
          · simp only [↓reduceIte]
            refine WP.spec_bind (held_eq_spec held Held.Unmeasured) ?_
            intro unmeasured is_unmeasured
            cases unmeasured
            · simp only [Bool.false_eq_true, ↓reduceIte, WP.spec_ok]
              exact PlanIs.keep content fine asked (by simpa [required] using is_unmeasured) reads
            · simp only [↓reduceIte, WP.spec_ok]
              exact PlanIs.fail_store fine asked required (is_unmeasured.mp rfl)
        · have lacks : held = Held.Lacks := by
            by_contra other
            exact has (is_has_it.mpr other)
          have free : ¬ AsksStore f.claim kernel held := fun asked => asked.2 lacks
          simp only [has, Bool.false_eq_true, ↓reduceIte]
          exact plan_when_free f kernel held content fine free reads
      · have not_some : ¬ core.option.Option.is_some (askedDig f.claim kernel) = true := by
          cases h : askedDig f.claim kernel <;> simp_all [core.option.Option.is_some]
        have free : ¬ AsksStore f.claim kernel held := fun asked => store_asked asked.1
        simp only [not_some, Bool.false_eq_true, ↓reduceIte]
        exact plan_when_free f kernel held content fine free reads

/-- A plan that asks for the content is for a claim that has a key to compare it with. -/
theorem reads_content_has_key {claim : Claim} {kernel : Option Dig}
    (reads : ReadsContent claim kernel) : contentKey claim ≠ none := by
  cases claim <;> simp_all [ReadsContent, contentKey]

/-- A plan that refuses the file is for a mismatch the shell reported (the kernel's measure of the
file is the one `seen` has). -/
theorem plan_wrong_is_a_mismatch {f : Facts} {kernel : Option Dig} {held : Held} {why : Why}
    (wrong : PlanIs f kernel held (.Wrong why)) (seen : Seen) (kernel_seen : seen.kernel = kernel) :
    Mismatch f seen := by
  cases wrong with
  | wrong_malformed _ bad => exact Or.inl bad
  | wrong_differs _ _ bad => exact Or.inr (Or.inl (kernel_seen ▸ bad))

/-- A file linked with no measure and no read is one the engine vouches for. -/
theorem link_unmeasured_is_trusted {f : Facts} {kernel : Option Dig} {held : Held}
    (link : PlanIs f kernel held .Link) (unmeasured : kernel = none) : TheEngineVouches f := by
  cases link with
  | link_measured _ _ _ measured => exact absurd unmeasured measured
  | link_trusted _ _ _ _ _ trusted => exact trusted

/-- A file the kernel did not measure that is read is read for its fs-verity digest. -/
theorem read_unmeasured_hashes {f : Facts} {kernel : Option Dig} {held : Held}
    {content merkle : Bool} (read : PlanIs f kernel held (.Read content merkle))
    (unmeasured : kernel = none) : merkle = true := by
  cases read with
  | read_measured _ _ _ measured => exact absurd unmeasured measured
  | read_hashed _ _ _ _ _ _ _ => rfl

end CommitCore
