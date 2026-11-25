-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: the loop of `parse` that adds the categories of a range `cA.cB`.
-- Why it is needed: a range names every category between its ends.
-- Read before this file: TheSets.lean, TheLoops.lean.
-- Notation: `Mem s c`: the category `c` is in the set `s`.
import McsCore.TheSets
import McsCore.TheLoops
open Aeneas Aeneas.Std Result velarx_mcs_core
namespace McsCore

/-- The loop of `parse` that adds a range: it adds the categories from `lo` to `hi` and no others. -/
theorem parse_loop1_loop0_spec (ok1 : Bool) (cats : Cats) (hi lo : Std.U16)
    (small : ok1 = true → hi.val < 1024) :
    parse_loop1_loop0 ok1 cats hi lo ⦃ r =>
      ∀ d, Mem r d ↔ Mem cats d ∨ (ok1 = true ∧ lo.val ≤ d ∧ d ≤ hi.val) ⦄ := by
  unfold parse_loop1_loop0
  apply loop_answers (fun x => parse_loop1_loop0.body ok1 hi x.1 x.2)
    (fun x y => ∀ d, Mem y d ↔ Mem x.1 d ∨ (ok1 = true ∧ x.2.val ≤ d ∧ d ≤ hi.val))
    (fun x => hi.val + 1 - x.2.val)
    (fun _ => True)
  · rintro ⟨cats', c⟩ _
    simp only
    unfold parse_loop1_loop0.body
    by_cases ok : ok1 = true
    · simp only [ok, ite_true]
      have small' := small ok
      by_cases le : c ≤ hi
      · simp only [le, ite_true]
        have le' : c.val ≤ hi.val := by scalar_tac
        step with add_spec cats' c (by omega) as ⟨ cats1, is_cats1 ⟩
        step as ⟨ c1, is_c1 ⟩
        refine ⟨by omega, ?_⟩
        intro y h d
        rw [h d, is_cats1 d]
        constructor
        · rintro ((m | rfl) | ⟨a, b⟩)
          · exact Or.inl m
          · exact Or.inr ⟨le_refl _, le'⟩
          · exact Or.inr ⟨by omega, b⟩
        · rintro (m | ⟨a, b⟩)
          · exact Or.inl (Or.inl m)
          · rcases Nat.eq_or_lt_of_le a with eq | lt
            · exact Or.inl (Or.inr eq.symm)
            · exact Or.inr ⟨by omega, b⟩
      · simp only [le, ite_false]
        refine (WP.spec_ok _).mpr ?_
        intro d
        have : ¬ c.val ≤ hi.val := by scalar_tac
        constructor
        · exact fun m => Or.inl m
        · rintro (m | ⟨a, b⟩)
          · exact m
          · omega
    · simp only [ok, Bool.false_eq_true, ite_false]
      refine (WP.spec_ok _).mpr ?_
      intro d
      simp [ok]
  · trivial

end McsCore
