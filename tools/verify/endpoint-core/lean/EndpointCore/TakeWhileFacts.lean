-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: how long `l.takeWhile p` is, when a scan that went over the first `i`
-- elements of `l` found them all to satisfy `p` and stopped at the place `i` (the end of the list
-- or an element that does not): it is `i` long, and `l.dropWhile p` is what follows.
-- Why it is needed: the scans of the crate (to the first `/`, to the first `/` or `@`) are loops
-- that stop at such a place, and Spec.lean says where they stop with `takeWhile` and `dropWhile`.
-- Read before this file: nothing.
-- Notation: `l.takeWhile p` is the elements of `l` from the start up to the first one that does
-- not satisfy `p`; `l.dropWhile p` is the others; `l.drop n` is `l` without its first `n`.
namespace EndpointCore

/-- When the first `i` elements of `l` all satisfy `p`, `l.takeWhile p` is these `i` and what
`(l.drop i).takeWhile p` takes after them. -/
theorem take_while_goes_on {α : Type} (p : α → Bool) :
    ∀ (i : Nat) (l : List α), i ≤ l.length →
      (∀ j, (_ : j < i) → (_ : j < l.length) → p l[j] = true) →
      (l.takeWhile p).length = i + ((l.drop i).takeWhile p).length
  | 0, l, _, _ => by simp
  | i + 1, [], inside, _ => by simp at inside
  | i + 1, x :: rest, inside, all => by
    have first : p x = true := all 0 (by omega) (by simp)
    have more := take_while_goes_on p i rest (by simp at inside; omega) (fun j hj hj' => by
      have := all (j + 1) (by omega) (by simp; omega)
      simpa using this)
    simp [first, more]
    omega

/-- When the first `i` elements of `l` all satisfy `p` and the place `i` is the end of the list or
an element that does not, `l.takeWhile p` is `i` elements long. -/
theorem take_while_stops_at {α : Type} (p : α → Bool) (l : List α) (i : Nat) (inside : i ≤ l.length)
    (before : ∀ j, (_ : j < i) → (_ : j < l.length) → p l[j] = true)
    (stop : ∀ (_ : i < l.length), p l[i] = false) :
    (l.takeWhile p).length = i := by
  have := take_while_goes_on p i l inside before
  rw [this]
  by_cases at_end : i < l.length
  · have : (l.drop i).takeWhile p = [] := by
      rw [List.drop_eq_getElem_cons at_end, List.takeWhile_cons, stop at_end]
      rfl
    simp [this]
  · have : l.drop i = [] := List.drop_of_length_le (by omega)
    simp [this]

/-- `l.dropWhile p` is `l` without the elements that `l.takeWhile p` takes. -/
theorem drop_while_is_the_rest {α : Type} (p : α → Bool) (l : List α) :
    l.dropWhile p = l.drop (l.takeWhile p).length := by
  have split := List.takeWhile_append_dropWhile (p := p) (l := l)
  calc l.dropWhile p = (l.takeWhile p ++ l.dropWhile p).drop (l.takeWhile p).length :=
        (List.drop_left' rfl).symm
    _ = l.drop (l.takeWhile p).length := by rw [split]

/-- `l.takeWhile p` is not longer than `l`. -/
theorem take_while_is_not_longer {α : Type} (p : α → Bool) (l : List α) :
    (l.takeWhile p).length ≤ l.length := by
  have split := congrArg List.length (List.takeWhile_append_dropWhile (p := p) (l := l))
  rw [List.length_append] at split
  omega

/-- The first `n` elements of `l`, where `n` is how many `l.takeWhile p` takes, are those. -/
theorem take_while_is_the_beginning {α : Type} (p : α → Bool) (l : List α) :
    l.take (l.takeWhile p).length = l.takeWhile p := by
  have split := List.takeWhile_append_dropWhile (p := p) (l := l)
  calc l.take (l.takeWhile p).length
      = (l.takeWhile p ++ l.dropWhile p).take (l.takeWhile p).length := by rw [split]
    _ = l.takeWhile p := List.take_left' rfl

/-- `l.takeWhile p` stops before the end of `l` exactly when an element of `l` does not satisfy
`p`. -/
theorem take_while_stops_short {α : Type} (p : α → Bool) :
    ∀ l : List α, (l.takeWhile p).length < l.length ↔ ∃ x ∈ l, p x = false
  | [] => by simp
  | x :: rest => by
    by_cases first : p x = true
    · simp only [List.takeWhile_cons, first, ite_true, List.length_cons, Nat.add_lt_add_iff_right]
      rw [take_while_stops_short p rest]
      constructor
      · rintro ⟨y, y_in, no⟩
        exact ⟨y, List.mem_cons_of_mem _ y_in, no⟩
      · rintro ⟨y, y_in, no⟩
        rcases List.mem_cons.mp y_in with is_first | in_rest
        · rw [is_first] at no
          simp [first] at no
        · exact ⟨y, in_rest, no⟩
    · have no : p x = false := by simpa using first
      simp [no]

end EndpointCore
