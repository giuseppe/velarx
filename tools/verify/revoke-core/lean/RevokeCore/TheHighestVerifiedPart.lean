-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: how the parts that are adopted relate to the highest number among the
-- verified parts of an issuer.  A part that is adopted has that number, and for an issuer with
-- verified parts, either a part with the highest number is adopted, or a number held is not lower
-- than it.
-- Why it is needed: the number held after the adoption is the highest of the numbers held before
-- and the numbers of the verified parts (`TheNumberHeldAfterIsTheGreatest`); these two facts are
-- what makes the parts that are adopted enough to give that number.
-- Read before this file: Spec.lean, AdoptsIsNotBeaten.lean.
-- Notation: `x ∈ NumbersVerified parts issuer` is "x is the number of a verified part of the
-- issuer"; `∃ n ∈ l, P n` reads "some `n` of `l` has `P`".
import RevokeCore.AdoptsIsNotBeaten

open Aeneas Aeneas.Std Result velarx_revoke_core

open Classical

namespace RevokeCore

/-- A number is in `NumbersVerified` exactly when a verified part of the issuer has it. -/
theorem number_is_of_a_verified_part (parts : List Part) (issuer : Std.U64) (x : Nat) :
    x ∈ NumbersVerified parts issuer ↔
      ∃ q ∈ parts, q.verified = true ∧ q.issuer = issuer ∧ q.number.val = x := by
  simp only [NumbersVerified, List.mem_map, List.mem_filter, decide_eq_true_eq]
  constructor
  · rintro ⟨q, ⟨member, verified, same⟩, is_x⟩
    exact ⟨q, member, verified, same, is_x⟩
  · rintro ⟨q, member, verified, same, is_x⟩
    exact ⟨q, ⟨member, verified, same⟩, is_x⟩

/-- The first part with the highest number: when no verified part of the issuer is higher than
`top` and one has the number `top`, the text is some parts, a part `t` with that number, and the
rest, and the verified parts of the issuer before `t` have a lower number and those after it are
not higher. -/
theorem first_with_the_highest_number (parts : List Part) (issuer : Std.U64) (top : Nat)
    (not_higher : ∀ q ∈ parts, q.verified = true → q.issuer = issuer → q.number.val ≤ top)
    (there : ∃ q ∈ parts, q.verified = true ∧ q.issuer = issuer ∧ q.number.val = top) :
    ∃ before t after, parts = before ++ t :: after ∧ t.verified = true ∧ t.issuer = issuer ∧
      t.number.val = top ∧
      (∀ q ∈ before, q.verified = true → q.issuer = issuer → q.number.val < top) ∧
      (∀ q ∈ after, q.verified = true → q.issuer = issuer → q.number.val ≤ top) := by
  induction parts with
  | nil => obtain ⟨q, member, _⟩ := there; simp at member
  | cons first rest more =>
    by_cases is_top : first.verified = true ∧ first.issuer = issuer ∧ first.number.val = top
    · exact ⟨[], first, rest, rfl, is_top.1, is_top.2.1, is_top.2.2, by simp,
        fun q member => not_higher q (List.mem_cons_of_mem _ member)⟩
    · -- the first part is not the one: it is lower, and the one is in the rest
      obtain ⟨q, member, verified, same, is_top_q⟩ := there
      have in_rest : ∃ q ∈ rest, q.verified = true ∧ q.issuer = issuer ∧ q.number.val = top := by
        rcases List.mem_cons.mp member with is_first | in_rest
        · subst is_first; exact absurd ⟨verified, same, is_top_q⟩ is_top
        · exact ⟨q, in_rest, verified, same, is_top_q⟩
      obtain ⟨before, t, after, split, t_verified, t_issuer, t_number, before_lower,
          after_not_higher⟩ :=
        more (fun q member => not_higher q (List.mem_cons_of_mem _ member)) in_rest
      refine ⟨first :: before, t, after, by simp [split], t_verified, t_issuer, t_number, ?_,
        after_not_higher⟩
      intro q member verified same
      rcases List.mem_cons.mp member with is_first | in_before
      · subst is_first
        have := not_higher _ (List.mem_cons_self) verified same
        have : q.number.val ≠ top := fun equal => is_top ⟨verified, same, equal⟩
        omega
      · exact before_lower q in_before verified same

/-- **A part with the highest number is adopted, or a number held is not lower.**  If `top` is the
highest number of the verified parts of an issuer, then either a part of that issuer with the
number `top` is adopted, or a number held of that issuer is at least `top`. -/
theorem the_highest_is_adopted_or_held (held : List Held) (parts : List Part) (issuer : Std.U64)
    (top : Nat) (is_highest : (NumbersVerified parts issuer).max? = some top) :
    (∃ i, AdoptedAt held parts i ∧ ∃ a, parts[i]? = some a ∧ a.issuer = issuer ∧
        a.number.val = top) ∨
      ∃ n ∈ NumbersHeld held issuer, top ≤ n := by
  obtain ⟨top_in, top_highest⟩ := List.max?_eq_some_iff.mp is_highest
  obtain ⟨before, t, after, split, verified, same, is_top, before_lower, after_not_higher⟩ :=
    first_with_the_highest_number parts issuer top
      (fun q member verified same =>
        top_highest _ ((number_is_of_a_verified_part parts issuer _).mpr
          ⟨q, member, verified, same, rfl⟩))
      ((number_is_of_a_verified_part parts issuer top).mp top_in)
  by_cases newer : NewerThanHeld held t.issuer t.number
  · left
    refine ⟨before.length, ⟨t, by simp [split], ?_⟩, t, by simp [split], same, is_top⟩
    rw [split]
    rw [List.take_left' rfl, show (before ++ t :: after).drop (before.length + 1) = after by simp]
    refine ⟨verified, newer, ?_, ?_⟩
    · intro q member q_verified q_same
      rw [is_top]
      exact before_lower q member q_verified (q_same.trans same)
    · intro q member q_verified q_same
      rw [is_top]
      exact after_not_higher q member q_verified (q_same.trans same)
  · right
    simp only [NewerThanHeld, not_forall, Nat.not_lt] at newer
    obtain ⟨n, member, high⟩ := newer
    rw [same] at member
    exact ⟨n, member, by omega⟩

/-- **A part that is adopted has the highest number.**  If the part `a` at the place `i` is
adopted, then its number is the number of a verified part of its issuer and no number of a verified
part of that issuer is higher. -/
theorem an_adopted_part_is_the_highest (held : List Held) (parts : List Part) (i : Nat)
    (a : Part) (at_i : parts[i]? = some a) (adopted : AdoptedAt held parts i) :
    a.number.val ∈ NumbersVerified parts a.issuer ∧
      ∀ x ∈ NumbersVerified parts a.issuer, x ≤ a.number.val := by
  obtain ⟨a', at_i', adopts⟩ := adopted
  rw [at_i] at at_i'
  cases at_i'
  obtain ⟨verified, _, before_lower, after_not_higher⟩ := adopts
  refine ⟨(number_is_of_a_verified_part parts a.issuer _).mpr
    ⟨a, List.mem_of_getElem? at_i, verified, rfl, rfl⟩, ?_⟩
  intro x x_in
  obtain ⟨q, member, q_verified, q_same, is_x⟩ := (number_is_of_a_verified_part _ _ _).mp x_in
  obtain ⟨k, at_k⟩ := List.mem_iff_getElem?.mp member
  rcases Nat.lt_trichotomy k i with earlier | same_place | later
  · have := before_lower q (is_before parts i k q earlier at_k) q_verified q_same
    omega
  · subst same_place
    rw [at_i] at at_k
    cases at_k
    omega
  · have := after_not_higher q (is_after parts i k q later at_k) q_verified q_same
    omega

end RevokeCore
