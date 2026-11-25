-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: two rules for the loops of the crate: a loop answers a claim of its first
--    state when its body keeps it, and a call that returns gives one value to every claim.
-- Why it is needed: the loops are written with a flag and an index; each proof of a loop has the
--    same shape, said once here.
-- Read before this file: Spec.lean.
-- Notation: `loop body x` is a Rust `while` that starts in the state `x`.
import McsCore.Spec
open Aeneas Aeneas.Std Aeneas.Data.Coinductive Result velarx_mcs_core
namespace McsCore

/-- A loop answers what is wanted of it from its state `x`. -/
theorem loop_answers {α β : Type} (body : α → Result (ControlFlow α β)) (answer : α → β → Prop)
    (measure : α → Nat) (inv : α → Prop) (x0 : α)
    (step : ∀ x, inv x → body x ⦃ r => match r with
      | .done y => answer x y
      | .cont x' => inv x' ∧ measure x' < measure x ∧ ∀ y, answer x' y → answer x y ⦄)
    (start : inv x0) : loop body x0 ⦃ y => answer x0 y ⦄ := by
  apply loop.spec_decr_nat measure (fun x' => inv x' ∧ ∀ y, answer x' y → answer x0 y)
    (fun y => answer x0 y) body x0
  · rintro x ⟨holds, carries⟩
    refine WP.spec_mono (step x holds) ?_
    intro r hr
    cases r with
    | done y => exact carries y hr
    | cont x' =>
      obtain ⟨holds', smaller, back⟩ := hr
      exact ⟨⟨holds', fun y h => carries y (back y h)⟩, smaller⟩
  · exact ⟨start, fun _ h => h⟩

unseal Result in
attribute [local implicit_reducible] Result in
/-- When a call returns a value of which each of several claims holds, it satisfies all the claims
at once (a call is a function: it returns one value). -/
theorem spec_all {α ι : Type} {m : Result α} (I : ι → Prop) (P : ι → α → Prop)
    (some : ∃ i, I i) (h : ∀ i, I i → m ⦃ y => P i y ⦄) :
    m ⦃ y => ∀ i, I i → P i y ⦄ := by
  obtain ⟨i0, hi0⟩ := some
  have h0 := h i0 hi0
  cases m using ITree.cases with
  | ret x =>
    change ok x ⦃ y => ∀ i, I i → P i y ⦄
    rw [WP.spec_ok]
    intro i hi
    have hx := h i hi
    change ok x ⦃ y => P i y ⦄ at hx
    exact (WP.spec_ok x).mp hx
  | vis e k => exact ((WP.spec_vis e k).mp h0).elim
  | div => exact (WP.spec_div.mp h0).elim

unseal Result in
attribute [local implicit_reducible] Result in
/-- A call that satisfies a claim returns a value (of which the claim holds). -/
theorem spec_returns {α : Type} {m : Result α} {P : α → Prop} (h : m ⦃ y => P y ⦄) :
    ∃ x, m = ok x ∧ P x := by
  cases m using ITree.cases with
  | ret x =>
    change ok x ⦃ y => P y ⦄ at h
    exact ⟨x, rfl, (WP.spec_ok x).mp h⟩
  | vis e k => exact ((WP.spec_vis e k).mp h).elim
  | div => exact (WP.spec_div.mp h).elim

end McsCore
