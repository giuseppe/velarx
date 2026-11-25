-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: when two lists of numbers have the same highest number (`max?`): when each
-- number of one is at most some number of the other, and the other way round.
-- Why it is needed: the claims about the number held after the adoption are about the highest
-- number of a list (`NumbersHeld`, `NumbersVerified`); the lists on the two sides of a claim are
-- different lists (the numbers of the adopted parts, those of all the verified parts, the same
-- numbers in another order), and this is the one fact that makes them equal.
-- Read before this file: Spec.lean (only for what `max?` is).
-- Notation: `l.max?` is the highest number of `l`, `none` when `l` is empty; `a ∈ l` is "a is in
-- l".
import RevokeCore.Spec

namespace RevokeCore

/-- A list that has a number has a highest one: it is that number or a higher one. -/
theorem highest_exists (l : List Nat) (x : Nat) (member : x ∈ l) :
    ∃ top, l.max? = some top ∧ x ≤ top := by
  cases is_max : l.max? with
  | none => simp [List.max?_eq_none_iff] at is_max; simp [is_max] at member
  | some top =>
    exact ⟨top, rfl, (List.max?_eq_some_iff.mp is_max).2 x member⟩

/-- Two lists in which each number is at most some number of the other have the same highest
number (and are empty together). -/
theorem same_highest (l l' : List Nat)
    (left_below : ∀ x ∈ l, ∃ y ∈ l', x ≤ y) (right_below : ∀ y ∈ l', ∃ x ∈ l, y ≤ x) :
    l.max? = l'.max? := by
  cases is_left : l.max? with
  | none =>
    simp only [List.max?_eq_none_iff] at is_left
    subst is_left
    cases is_right : l'.max? with
    | none => rfl
    | some top =>
      have top_in := (List.max?_eq_some_iff.mp is_right).1
      obtain ⟨x, x_in, _⟩ := right_below top top_in
      simp at x_in
  | some top =>
    have ⟨top_in, top_highest⟩ := List.max?_eq_some_iff.mp is_left
    obtain ⟨y, y_in, top_below_y⟩ := left_below top top_in
    obtain ⟨top', is_right, y_below_top'⟩ := highest_exists l' y y_in
    obtain ⟨x, x_in, top'_below_x⟩ := right_below top' (List.max?_eq_some_iff.mp is_right).1
    have x_below_top := top_highest x x_in
    rw [is_right]
    congr 1
    omega

/-- Lists with the same numbers in another order have the same highest number. -/
theorem highest_of_a_reordering (l l' : List Nat) (reordered : l.Perm l') :
    l.max? = l'.max? :=
  same_highest l l' (fun x x_in => ⟨x, reordered.subset x_in, le_refl x⟩)
    (fun y y_in => ⟨y, reordered.symm.subset y_in, le_refl y⟩)

end RevokeCore
