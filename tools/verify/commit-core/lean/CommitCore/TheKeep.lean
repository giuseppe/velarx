-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: what `keep` (crates/commit-core, src/lib.rs) answers, case by case:
-- `keep_is` says that it returns, and that its answer is one of four: the store lacks the object
-- (the name it was given), the store's object is measured (kept, `checked`), it is not measured
-- and fs-verity is required (a failure), or not required (kept, not `checked`).
--
-- Why it is needed: `keep` is a short function with a `match`, but the claims about it
-- (KeepNeverNamesWhatItWasNotGiven, KeepNeedsAMeasureWhenRequired) are stated about the answers,
-- so they are proved from this list.
--
-- Read before this file: Spec.lean, SmallFunctions.lean, and `keep` in src/lib.rs.
--
-- Notation: `{ named with checked := true, proof := .Store }` is the record `named` with two
-- fields changed; `v = .Keep n` is "the answer is `Keep n`"; the rest as in ThePlan.lean.
import CommitCore.SmallFunctions
import CommitCore.SameDigest
open Aeneas Aeneas.Std Result velarx_commit_core
namespace CommitCore

/-- `keep` returns, and answers by the state of the store: it names what it was given when the
store lacks the object; it keeps the store's object (replacing `checked` by whether the kernel
measures it, and the proof by `Store`) when the store has it, unless the store's object is not
measured and fs-verity is required, which fails. -/
theorem keep_is (f : Facts) (named : Named) (held : Held) :
    keep f named held ⦃ v =>
      (held = .Lacks ∧ v = .Name named) ∨
      (held = .Measures ∧ v = .Keep { named with checked := true, proof := .Store }) ∨
      (held = .Unmeasured ∧ f.required = true ∧ v = .Fail .StoreUnmeasured) ∨
      (held = .Unmeasured ∧ f.required = false ∧
        v = .Keep { named with checked := false, proof := .Store }) ⦄ := by
  unfold keep
  cases held with
  | Lacks => simp
  | Measures =>
    refine WP.spec_bind (held_eq_spec .Measures .Measures) ?_
    intro measures is_measures
    simp only [WP.spec_ok]
    have : measures = true := is_measures.mpr rfl
    simp [this]
  | Unmeasured =>
    cases required : f.required
    · simp only [Bool.false_eq_true, ↓reduceIte]
      refine WP.spec_bind (held_eq_spec .Unmeasured .Measures) ?_
      intro measures is_measures
      simp only [WP.spec_ok]
      have : measures = false := by simpa using is_measures
      simp [this]
    · simp

end CommitCore
