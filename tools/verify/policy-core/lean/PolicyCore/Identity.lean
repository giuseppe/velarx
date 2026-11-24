-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: the functions that compare references, from `same_option` up to
-- `identity_matches`, and that the last answers `RuleAccepts` of Spec.lean for each rule.
--
-- Why it is needed: the security rule is stated with `RuleAccepts`, the rules in words; this file
-- is what connects it to the code of `identity_matches`.
--
-- Read before this file: Spec.lean, Scope.lean.
--
-- Notation: `m ⦃ r => P r ⦄` is "the Rust function `m` returns, and its result `r` satisfies
-- `P r`" (as in Spec.lean); `loop.spec_decr_nat` proves that a loop returns because a number
-- goes down at each turn and an invariant is kept by the body; `step as ⟨ x, hx ⟩` runs one line
-- of the Rust function and names its result `x` and what is known of it `hx`; `v.val` is the
-- list inside a vector or a slice; `l[k]?` is the element `k` of a list, if there is one.
import PolicyCore.Select
open Aeneas Aeneas.Std Result velarx_policy_core
namespace PolicyCore

/-- `same_option` compares the bytes inside two options. -/
@[step]
theorem same_option_is (a b : Option (alloc.vec.Vec Std.U8)) :
    same_option a b ⦃ r => r = true ↔ a.map (·.val) = b.map (·.val) ⦄ := by
  unfold same_option
  cases a with
  | none => cases b <;> simp
  | some x =>
    cases b with
    | none => simp
    | some y =>
      simp only
      step as ⟨ equal, h_equal ⟩
      simp only [deref_val] at h_equal
      simpa using h_equal
/-- `has_tag_or_digest` says whether the reference has a tag or a digest. -/
@[step]
theorem has_tag_or_digest_is (r : Ref) :
    has_tag_or_digest r ⦃ b => b = true ↔ HasTagOrDigest r ⦄ := by
  unfold has_tag_or_digest
  cases hr : core.option.Option.is_some r.tag <;>
    simp [HasTagOrDigest, core.option.Option.is_some] at hr ⊢ <;> simp [hr]

/-- `same_reference` says whether the two references are the same. -/
@[step]
theorem same_reference_is (a b : Ref) :
    same_reference a b ⦃ r => r = true ↔ SameRef a b ⦄ := by
  unfold same_reference
  step as ⟨ same_name, h_name ⟩
  simp only [deref_val] at h_name
  by_cases named : same_name = true
  · simp only [named, ↓reduceIte]
    step as ⟨ same_tag, h_tag ⟩
    by_cases tagged : same_tag = true
    · simp only [tagged, ↓reduceIte]
      step as ⟨ same_digest, h_digest ⟩
      rw [h_digest]
      unfold SameRef
      simp [h_name.mp named, h_tag.mp tagged]
    · simp only [tagged, Bool.false_eq_true, ↓reduceIte, WP.spec_ok, false_iff]
      exact fun same => tagged (h_tag.mpr same.2.1)
  · simp only [named, Bool.false_eq_true, ↓reduceIte, WP.spec_ok, false_iff]
    exact fun same => named (h_name.mpr same.1)
/-- `exact` says whether both references have a tag or a digest and are the same. -/
@[step]
theorem exact_is (a b : Ref) :
    exact a b ⦃ r => r = true ↔ HasTagOrDigest a ∧ HasTagOrDigest b ∧ SameRef a b ⦄ := by
  unfold exact
  step as ⟨ a_has, h_a ⟩
  by_cases a_yes : a_has = true
  · simp only [a_yes, ↓reduceIte]
    step as ⟨ b_has, h_b ⟩
    by_cases b_yes : b_has = true
    · simp only [b_yes, ↓reduceIte]
      step as ⟨ same, h_same ⟩
      rw [h_same]
      exact ⟨fun s => ⟨h_a.mp a_yes, h_b.mp b_yes, s⟩, fun all => all.2.2⟩
    · simp only [b_yes, Bool.false_eq_true, ↓reduceIte, WP.spec_ok, false_iff]
      exact fun all => b_yes (h_b.mpr all.2.1)
  · simp only [a_yes, Bool.false_eq_true, ↓reduceIte, WP.spec_ok, false_iff]
    exact fun all => a_yes (h_a.mpr all.1)

/-- `repo_digest_or_exact` says what `RepoDigestOrExactAccepts` says. -/
@[step]
theorem repo_digest_or_exact_is (intended signed : Ref) :
    repo_digest_or_exact intended signed ⦃ r =>
      r = true ↔ RepoDigestOrExactAccepts intended signed ⦄ := by
  unfold repo_digest_or_exact
  step as ⟨ signed_has, h_signed ⟩
  by_cases signed_yes : signed_has = true
  · simp only [signed_yes, ↓reduceIte]
    by_cases by_tag : intended.tag.isSome = true
    · -- asked by tag: the same reference
      simp only [by_tag, ↓reduceIte]
      step as ⟨ same, h_same ⟩
      rw [h_same]
      simp [RepoDigestOrExactAccepts, by_tag, h_signed.mp signed_yes]
    · by_cases by_digest : intended.digest.isSome = true
      · -- asked by digest: the same name
        simp only [by_tag, by_digest, Bool.false_eq_true, ↓reduceIte]
        step as ⟨ same, h_same ⟩
        simp only [deref_val] at h_same
        rw [h_same]
        simp [RepoDigestOrExactAccepts, by_tag, by_digest, h_signed.mp signed_yes]
      · simp only [by_tag, by_digest, Bool.false_eq_true, ↓reduceIte, WP.spec_ok, false_iff]
        simp [RepoDigestOrExactAccepts, by_tag, by_digest]
  · simp only [signed_yes, Bool.false_eq_true, ↓reduceIte, WP.spec_ok, false_iff]
    exact fun accepted => signed_yes (h_signed.mpr accepted.1)
/-- `identity_matches` says what `RuleAccepts` says of the rule. -/
@[step]
theorem identity_matches_is (rule : Rule) (intended signed : Ref) :
    identity_matches rule intended signed ⦃ r => r = true ↔ RuleAccepts rule intended signed ⦄ := by
  unfold identity_matches
  cases rule with
  | Exact => exact exact_is intended signed
  | RepoDigestOrExact => exact repo_digest_or_exact_is intended signed
  | Repository =>
    step as ⟨ same, h_same ⟩
    simpa [RuleAccepts] using h_same
  | ExactReference r => exact exact_is r signed
  | ExactRepository repository =>
    step as ⟨ same, h_same ⟩
    simpa [RuleAccepts] using h_same
  | Remapped r => exact repo_digest_or_exact_is r signed
  | Nothing => simp [RuleAccepts]
end PolicyCore
