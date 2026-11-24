-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: three small facts about the first `i` elements of a list (`l.take i`) that
-- the proofs of the loops use: one more element is the next one added at the end; two lists have
-- the same first `i + 1` elements exactly when they have the same first `i` and the next one is
-- the same; and the first `i` elements of a list at least that long are `i` elements.
-- Why it is needed: the loops of the crate go over a list byte by byte; the fact they keep true is
-- "what was seen so far is the first `i` bytes".
-- Read before this file: nothing.
-- Notation: `l.take i` is the first `i` elements of `l`, `l[i]` its element at the place `i`
-- (the places count from 0), `l ++ l'` is `l` and then `l'`.
namespace EndpointCore

/-- The first `i + 1` elements are the first `i` and then the element at the place `i`. -/
theorem take_one_more {α : Type} (l : List α) (i : Nat) (inside : i < l.length) :
    l.take (i + 1) = l.take i ++ [l[i]] := by
  rw [List.take_add_one, List.getElem?_eq_getElem inside]
  rfl

/-- Two lists have the same first `i + 1` elements exactly when they have the same first `i` and
the same element at the place `i` (both lists have a place `i`). -/
theorem equal_prefixes_grow {α : Type} (l m : List α) (i : Nat) (in_l : i < l.length)
    (in_m : i < m.length) :
    l.take (i + 1) = m.take (i + 1) ↔ l.take i = m.take i ∧ l[i] = m[i] := by
  rw [take_one_more l i in_l, take_one_more m i in_m]
  have same_length : (l.take i).length = (m.take i).length := by
    simp only [List.length_take]
    omega
  constructor
  · intro same
    have := List.append_inj same same_length
    simpa using this
  · rintro ⟨same_front, same_next⟩
    rw [same_front, same_next]

end EndpointCore
