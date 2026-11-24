-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: small facts about the first `k` elements of a list, which the proofs of
-- the loops use (a loop that has read `k` entries has seen exactly `l.take k`).
--
-- Read before this file: nothing.  Notation: `l.take k` is the first `k` elements of `l`;
-- `l[k]` is the element `k` of `l`, counted from 0; `∀ e ∈ l, P e` is "every element satisfies P".
import Aeneas

namespace IdmapCore

/-- Taking one more element of a list adds the element `k` at the end. -/
theorem take_one_more {α : Type} (l : List α) (k : Nat) (inside : k < l.length) :
    l.take (k + 1) = l.take k ++ [l[k]] := by
  rw [List.take_add_one, List.getElem?_eq_getElem inside]
  rfl

/-- "Every one of the first `k + 1` elements satisfies `P`" is "every one of the first `k` does,
and so does the element `k`". -/
theorem all_of_take_one_more {α : Type} (l : List α) (k : Nat) (inside : k < l.length)
    (P : α → Prop) :
    (∀ e ∈ l.take (k + 1), P e) ↔ (∀ e ∈ l.take k, P e) ∧ P l[k] := by
  rw [take_one_more l k inside]
  simp only [List.mem_append, List.mem_singleton]
  constructor
  · intro all
    exact ⟨fun e e_in => all e (Or.inl e_in), all _ (Or.inr rfl)⟩
  · rintro ⟨before, last⟩ e (e_in | rfl)
    · exact before e e_in
    · exact last

/-- An element among the first `j` elements of a list is among the first `i`, when `j ≤ i`. -/
theorem mem_take_of_le {α : Type} (l : List α) (j i : Nat) (j_le : j ≤ i) (e : α)
    (e_in : e ∈ l.take j) : e ∈ l.take i := by
  have same : l.take j = (l.take i).take j := by
    rw [List.take_take, Nat.min_eq_left j_le]
  rw [same] at e_in
  exact List.mem_of_mem_take e_in

/-- A relation holds between all the elements of the first `k + 1` elements of a list, in order,
when it holds between those of the first `k`, and between each of those and the element `k`. -/
theorem pairwise_of_take_one_more {α : Type} (l : List α) (k : Nat) (inside : k < l.length)
    (R : α → α → Prop) :
    (l.take (k + 1)).Pairwise R ↔ (l.take k).Pairwise R ∧ ∀ e ∈ l.take k, R e l[k] := by
  rw [take_one_more l k inside, List.pairwise_append]
  simp

end IdmapCore
