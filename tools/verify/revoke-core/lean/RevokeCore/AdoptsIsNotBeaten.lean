-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: the two ways to say that the part at the place `i` of a text is adopted:
-- `Adopts` of Spec.lean (the parts before it, and the parts after it, are listed apart) and the way
-- the code reads it (the part is verified, newer than what is held, and no part at any place
-- `Beats` it, see BeatenLoop.lean).  They say the same.
-- Why it is needed: the claims are written in the first way, which is the one a reader follows;
-- the loops of `adopt` are written in the second.
-- Read before this file: Spec.lean, BeatenLoop.lean.
-- Notation: `l.take i` and `l.drop i` are the first `i` elements of `l` and `l` without them;
-- `l[k]?` is `some` of the element at the place `k`, or `none`.
import RevokeCore.BeatenLoop

open Aeneas Aeneas.Std Result velarx_revoke_core

namespace RevokeCore

/-- A part at the place `k` of the text, with `k` before `i`, is among the parts before `i`. -/
theorem is_before (parts : List Part) (i k : Nat) (q : Part) (before : k < i)
    (at_k : parts[k]? = some q) : q ∈ parts.take i :=
  List.mem_iff_getElem?.mpr ⟨k, by simp [List.getElem?_take_of_lt before, at_k]⟩

/-- A part at the place `k` of the text, with `k` after `i`, is among the parts after `i`. -/
theorem is_after (parts : List Part) (i k : Nat) (q : Part) (after : i < k)
    (at_k : parts[k]? = some q) : q ∈ parts.drop (i + 1) :=
  List.mem_iff_getElem?.mpr ⟨k - (i + 1), by
    rw [List.getElem?_drop, show i + 1 + (k - (i + 1)) = k by omega]
    exact at_k⟩

/-- A part among the parts before the place `i` is at a place before `i`. -/
theorem before_has_a_place (parts : List Part) (i : Nat) (q : Part) (member : q ∈ parts.take i) :
    ∃ k, k < i ∧ parts[k]? = some q := by
  obtain ⟨k, at_k⟩ := List.mem_iff_getElem?.mp member
  have before : k < i := by
    have := (List.getElem?_eq_some_iff.mp at_k).1
    simp at this
    omega
  exact ⟨k, before, by simpa [List.getElem?_take_of_lt before] using at_k⟩

/-- A part among the parts after the place `i` is at a place after `i`. -/
theorem after_has_a_place (parts : List Part) (i : Nat) (q : Part)
    (member : q ∈ parts.drop (i + 1)) :
    ∃ k, i < k ∧ parts[k]? = some q := by
  obtain ⟨m, at_m⟩ := List.mem_iff_getElem?.mp member
  exact ⟨i + 1 + m, by omega, by simpa [List.getElem?_drop] using at_m⟩

/-- **The part at the place `i` is adopted exactly when it is verified, newer than what is held,
and no part at any place beats it.** -/
theorem adopts_is_not_beaten (held : List Held) (parts : List Part) (i : Nat) (p : Part)
    (at_i : parts[i]? = some p) :
    Adopts held (parts.take i) p (parts.drop (i + 1)) ↔
      p.verified = true ∧ NewerThanHeld held p.issuer p.number ∧ NoneBeatsFrom parts i 0 := by
  constructor
  · rintro ⟨verified, newer, before_lower, after_not_higher⟩
    refine ⟨verified, newer, ?_⟩
    rintro k _ ⟨q, p', at_k, at_i', q_verified, same, order⟩
    rw [at_i] at at_i'
    cases at_i'
    rcases Nat.lt_trichotomy k i with earlier | same_place | later
    · have := before_lower q (is_before parts i k q earlier at_k) q_verified same
      omega
    · subst same_place
      rw [at_i] at at_k
      cases at_k
      omega
    · have := after_not_higher q (is_after parts i k q later at_k) q_verified same
      omega
  · rintro ⟨verified, newer, not_beaten⟩
    refine ⟨verified, newer, ?_, ?_⟩
    · intro q member q_verified same
      obtain ⟨k, earlier, at_k⟩ := before_has_a_place parts i q member
      by_contra not_lower
      exact not_beaten k (Nat.zero_le k) ⟨q, p, at_k, at_i, q_verified, same, by omega⟩
    · intro q member q_verified same
      obtain ⟨k, later, at_k⟩ := after_has_a_place parts i q member
      by_contra not_below
      exact not_beaten k (Nat.zero_le k) ⟨q, p, at_k, at_i, q_verified, same, by omega⟩

end RevokeCore
