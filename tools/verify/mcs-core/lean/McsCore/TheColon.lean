-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: the loop of `parse` that finds the first colon.
-- Why it is needed: the sensitivities are what is before it and the categories what is after.
-- Read before this file: TheLoops.lean.
-- Notation: `level.val[k]!` is the byte at the place `k`.
import McsCore.TheLoops
open Aeneas Aeneas.Std Result velarx_mcs_core
namespace McsCore

/-- `k` is the place of the first colon of `l`. -/
def FirstColon (l : List Std.U8) (k : Nat) : Prop :=
  k < l.length ∧ l[k]! = 58#u8 ∧ ∀ j, j < k → l[j]! ≠ 58#u8

/-- What the loop of `parse` that looks for the first colon answers: whether there is one and where
the first is. -/
theorem parse_loop0_spec (level : Slice Std.U8) (colon : Std.Usize) (found : Bool) (i : Std.Usize)
    (inside : i.val ≤ level.length) :
    parse_loop0 level (Slice.len level) colon found i ⦃ r =>
      (found = true → r = (colon, true)) ∧
      (found = false → (r.2 = true ↔ ∃ k, i.val ≤ k ∧ k < level.length ∧ level.val[k]! = 58#u8)) ∧
      (found = false → r.2 = true →
        r.1.val ≥ i.val ∧ level.val[r.1.val]! = 58#u8 ∧ r.1.val < level.length ∧
          ∀ j, i.val ≤ j → j < r.1.val → level.val[j]! ≠ 58#u8) ∧
      (found = false → r.2 = false → r.1 = colon) ⦄ := by
  unfold parse_loop0
  apply loop_answers (fun x => parse_loop0.body level (Slice.len level) x.1 x.2.1 x.2.2)
    (fun x y =>
      (x.2.1 = true → y = (x.1, true)) ∧
      (x.2.1 = false → (y.2 = true ↔ ∃ k, x.2.2.val ≤ k ∧ k < level.length ∧ level.val[k]! = 58#u8)) ∧
      (x.2.1 = false → y.2 = true →
        y.1.val ≥ x.2.2.val ∧ level.val[y.1.val]! = 58#u8 ∧ y.1.val < level.length ∧
          ∀ j, x.2.2.val ≤ j → j < y.1.val → level.val[j]! ≠ 58#u8) ∧
      (x.2.1 = false → y.2 = false → y.1 = x.1))
    (fun x => level.length - x.2.2.val)
    (fun x => x.2.2.val ≤ level.length)
  · rintro ⟨colon', found', i'⟩ inside'
    simp only at inside' ⊢
    unfold parse_loop0.body
    have is_len : (Slice.len level).val = level.length := by simp [Slice.len]
    by_cases below : i' < Slice.len level
    · simp only [below, ite_true]
      have below' : i'.val < level.length := by scalar_tac
      have room : i'.val + 1 ≤ Usize.max := by scalar_tac
      by_cases hf : found' = true
      · rw [if_pos hf]
        simp only [bind_tc_ok, bind_ok]
        step as ⟨ i1, is_i1 ⟩
        refine ⟨by scalar_tac, by scalar_tac, fun y h1 _ _ _ => ?_⟩
        exact ⟨fun _ => h1 hf, by simp [hf], by simp [hf], by simp [hf]⟩
      · have hf' : found' = false := by simpa using hf
        rw [if_neg hf]
        step as ⟨ b, is_b ⟩
        by_cases colon_here : b = 58#u8
        · simp only [colon_here, ite_true]
          step as ⟨ i1, is_i1 ⟩
          refine ⟨by scalar_tac, by scalar_tac, fun y h1 _ _ _ => ?_⟩
          have y_is := h1 trivial
          have byte : level.val[i'.val]! = 58#u8 := by
            rw [← colon_here, is_b]; simp [List.getElem!_eq_getElem?_getD, below']
          refine ⟨by simp [hf'], ?_, ?_, ?_⟩
          · intro _; rw [y_is]
            exact ⟨fun _ => ⟨i'.val, le_refl _, below', byte⟩, fun _ => rfl⟩
          · intro _ _; rw [y_is]
            exact ⟨le_refl _, byte, below', fun j a b => absurd (lt_of_le_of_lt a b) (lt_irrefl _)⟩
          · intro _ no; rw [y_is] at no; simp at no
        · simp only [colon_here, ite_false]
          step as ⟨ i1, is_i1 ⟩
          refine ⟨by scalar_tac, by scalar_tac, fun y _ h2 h3 h4 => ?_⟩
          have byte : level.val[i'.val]! ≠ 58#u8 := by
            rw [is_b] at colon_here; simpa [List.getElem!_eq_getElem?_getD, below'] using colon_here
          have h2' := h2 hf'
          rw [is_i1] at h2'
          refine ⟨by simp [hf'], ?_, ?_, ?_⟩
          · intro _
            rw [h2']
            constructor
            · rintro ⟨k, a, b, c⟩; exact ⟨k, by omega, b, c⟩
            · rintro ⟨k, a, b, c⟩
              refine ⟨k, ?_, b, c⟩
              rcases Nat.eq_or_lt_of_le a with eq | lt
              · rw [← eq] at c; exact absurd c byte
              · omega
          · intro _ yt
            obtain ⟨g1, g2, g3, g4⟩ := h3 hf' yt
            rw [is_i1] at g1 g4
            refine ⟨by omega, g2, g3, ?_⟩
            intro j a b
            rcases Nat.eq_or_lt_of_le a with eq | lt
            · rw [← eq]; exact byte
            · exact g4 j (by omega) b
          · intro _ no
            exact h4 hf' no
    · simp only [below, ite_false]
      refine (WP.spec_ok _).mpr ⟨fun hf => by simp [hf], ?_, ?_, ?_⟩
      · intro hf
        simp only [hf]
        constructor
        · intro h; exact absurd h (by simp)
        · rintro ⟨k, a, b, c⟩; scalar_tac
      · intro hf h
        have : found' = true := h
        rw [hf] at this; exact absurd this (by simp)
      · intro _ _; rfl
  · exact inside

end McsCore
