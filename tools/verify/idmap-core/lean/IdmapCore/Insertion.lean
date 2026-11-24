-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: the list facts behind the two insertion sorts of the crate (the one of
-- `IdSet::from_intervals`, by start, and the one of `sort_and_merge`, by container id).  Both
-- push the new element at the end and move it down while the one before it is greater: the list
-- is then `before ++ [spare] ++ after` where `spare` is a copy that the next move overwrites, and
-- the new element is written into the place it ends in.
--
-- Read before this file: nothing.  Notation: `l ++ m` is the list `l` followed by `m`; `x :: l` is
-- `x` followed by `l`; `l.set i x` is `l` with the element `i` replaced by `x`; `l.Pairwise R`
-- is "`R a b` for every `a` and every `b` after it".
import Aeneas

namespace IdmapCore

/-- Moving the spare place one down: the element before the spare place is copied over it. -/
theorem copy_the_last_one_over_the_spare {α : Type} (before : List α) (last spare : α)
    (after : List α) :
    ((before ++ [last]) ++ spare :: after).set (before ++ [last]).length last =
      before ++ [last] ++ last :: after := by
  rw [List.set_append_right _ _ (Nat.le_refl _)]
  simp

/-- A list that is sorted by `key` stays sorted when `x` is put between the part before it, whose
keys are at most that of `x`, and the part after it, whose keys are at least that of `x`. -/
theorem sorted_after_inserting {α : Type} (key : α → Nat) (before after : List α) (x : α)
    (sorted : (before ++ after).Pairwise (fun a b => key a ≤ key b))
    (before_le : ∀ b ∈ before, key b ≤ key x) (x_le : ∀ a ∈ after, key x ≤ key a) :
    (before ++ x :: after).Pairwise (fun a b => key a ≤ key b) := by
  rw [List.pairwise_append] at sorted ⊢
  obtain ⟨sorted_before, sorted_after, between⟩ := sorted
  refine ⟨sorted_before, ?_, ?_⟩
  · exact List.pairwise_cons.mpr ⟨x_le, sorted_after⟩
  · intro b b_in y y_in
    rcases List.mem_cons.mp y_in with rfl | y_in
    · exact before_le b b_in
    · exact between b b_in y y_in

/-- If the key of the last element of `before` is at most `k`, and the list is sorted, so is the
key of every element of `before`. -/
theorem every_key_is_at_most_the_last {α : Type} (key : α → Nat) (before : List α) (last : α)
    (sorted : (before ++ [last]).Pairwise (fun a b => key a ≤ key b)) :
    ∀ b ∈ before, key b ≤ key last := by
  intro b b_in
  rw [List.pairwise_append] at sorted
  exact sorted.2.2 b b_in last (List.mem_singleton_self last)

/-- The element right before the spare place. -/
theorem the_element_before_the_spare {α : Type} (init : List α) (last spare : α) (after l : List α)
    (is_l : l = (init ++ [last]) ++ spare :: after) (i : Nat) (is_i : i = init.length)
    (inside : i < l.length) : l[i] = last := by
  subst is_l is_i
  simp

/-- Writing the new element over the spare place puts it between the two parts. -/
theorem write_over_the_spare {α : Type} (before : List α) (spare : α) (after : List α) (x : α) :
    (before ++ spare :: after).set before.length x = before ++ x :: after := by
  rw [List.set_append_right _ _ (Nat.le_refl _)]
  simp

/-- The last element of a list: the one after the `init.length` elements before it. -/
theorem the_element_before_the_spare_at_the_end {α : Type} (init : List α) (last : α)
    (l : List α) (is_l : l = init ++ [last]) (i : Nat) (is_i : i = init.length)
    (inside : i < l.length) : l[i] = last := by
  subst is_l is_i
  simp

end IdmapCore
