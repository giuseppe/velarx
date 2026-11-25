-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: what the inner loop of `adopt` answers.  For the part at the place `i`, it
-- looks at the parts from the place `j` on, and clears its flag when one BEATS the part at `i`: a
-- verified part of the same issuer with a higher number, or with the same number and an earlier
-- place.  Its answer is true exactly when the flag was true and none of these parts beats it.
-- Why it is needed: `adopt` adopts a part when it is verified, newer than what is held, and not
-- beaten; this is the "not beaten".
-- Read before this file: Spec.lean, NewerLoop.lean (the same shape, one loop simpler).
-- Notation: as in NewerLoop.lean.
import RevokeCore.Spec

open Aeneas Aeneas.Std Result velarx_revoke_core

open Classical

namespace RevokeCore

/-- The part at the place `j` BEATS the part at the place `i`: it is verified, of the same issuer,
and has a higher number, or the same number and an earlier place. -/
def Beats (parts : List Part) (j i : Nat) : Prop :=
  ∃ q p, parts[j]? = some q ∧ parts[i]? = some p ∧ q.verified = true ∧ q.issuer = p.issuer ∧
    (p.number.val < q.number.val ∨ (q.number.val = p.number.val ∧ j < i))

/-- No part from the place `j` on beats the part at the place `i`. -/
def NoneBeatsFrom (parts : List Part) (i j : Nat) : Prop :=
  ∀ k, j ≤ k → ¬ Beats parts k i

/-- From the end of the parts, none is left to beat. -/
theorem none_beats_from_the_end (parts : List Part) (i j : Nat) (at_the_end : parts.length ≤ j) :
    NoneBeatsFrom parts i j := by
  rintro k from_j ⟨q, p, at_k, _⟩
  have := (List.getElem?_eq_some_iff.mp at_k).1
  omega

/-- One more part: none from the place `j` on beats the part at `i` exactly when the part at `j`
does not and none from the place after does. -/
theorem none_beats_from_the_next (parts : List Part) (i j : Nat) :
    NoneBeatsFrom parts i j ↔ ¬ Beats parts j i ∧ NoneBeatsFrom parts i (j + 1) := by
  constructor
  · intro none_beats
    exact ⟨none_beats j (le_refl j), fun k later => none_beats k (by omega)⟩
  · rintro ⟨not_j, rest⟩ k from_j
    rcases Nat.eq_or_lt_of_le from_j with same | after
    · subst same; exact not_j
    · exact rest k after

/-- **The test of the inner loop**: for the part `q` at the place `j` and the part `p` at the
place `i`, the Rust condition that `q` beats `p` answers `Beats`. -/
theorem the_test_is_beats (parts : Slice Part) (i j : Std.Usize) (q p : Part)
    (at_j : parts.val[j.val]? = some q) (at_i : parts.val[i.val]? = some p) :
    (if q.verified = true then do
        let p1 ← parts.index_usize i
        if q.issuer = p1.issuer then
          if q.number > p1.number then ok true
          else if q.number = p1.number then ok (decide (j < i)) else ok false
        else ok false
      else ok false : Result Bool) = ok (decide (Beats parts.val j.val i.val)) := by
  have read_p : parts.index_usize i = ok p := by
    simp [Slice.index_usize, at_i]
  have beats_when : Beats parts.val j.val i.val ↔ q.verified = true ∧ q.issuer = p.issuer ∧
      (p.number.val < q.number.val ∨ (q.number.val = p.number.val ∧ j.val < i.val)) := by
    constructor
    · rintro ⟨q', p', at_q', at_p', verified, same, order⟩
      rw [at_j] at at_q'
      rw [at_i] at at_p'
      cases at_q'
      cases at_p'
      exact ⟨verified, same, order⟩
    · rintro ⟨verified, same, order⟩
      exact ⟨q, p, at_j, at_i, verified, same, order⟩
  by_cases verified : q.verified = true
  · by_cases same : q.issuer = p.issuer
    · by_cases higher : q.number > p.number
      · have higher' : p.number.val < q.number.val := by scalar_tac
        simp [read_p, verified, same, beats_when, higher']
      · by_cases equal : q.number = p.number
        · simp [read_p, verified, same, equal, beats_when]
        · have lower : q.number.val < p.number.val := by scalar_tac
          have not_higher : ¬ p.number.val < q.number.val := by omega
          have not_equal : ¬ q.number.val = p.number.val := by omega
          simp [read_p, verified, same, equal, beats_when, not_higher, not_equal]
    · simp [read_p, verified, same, beats_when]
  · simp [verified, beats_when]

/-- **The inner loop of `adopt`** answers true exactly when the flag it was given is true and no
part from the place `j` on beats the part at the place `i`.  It always returns. -/
theorem beaten_loop_answers (parts : Slice Part) (i : Std.Usize) (p : Part)
    (at_i : parts.val[i.val]? = some p) (best : Bool) (j : Std.Usize) :
    adopt_loop0_loop0 parts i best j ⦃ r =>
      (r = true ↔ best = true ∧ NoneBeatsFrom parts.val i.val j.val) ⦄ := by
  unfold adopt_loop0_loop0
  apply loop.spec_decr_nat (fun (q : Bool × Std.Usize) => parts.length - q.2.val)
    (fun (q : Bool × Std.Usize) =>
      (q.1 = true ∧ NoneBeatsFrom parts.val i.val q.2.val ↔
        best = true ∧ NoneBeatsFrom parts.val i.val j.val))
  · rintro ⟨best', j'⟩ same_answer
    simp only at same_answer ⊢
    unfold adopt_loop0_loop0.body
    by_cases below : j'.val < parts.length
    · have below' : j' < Slice.len parts := by scalar_tac
      simp only [below', ite_true]
      by_cases still : best' = true
      · simp only [still, ite_true]
        step as ⟨ q, is_q ⟩
        have at_j' : parts.val[j'.val]? = some q := by
          rw [is_q]; exact List.getElem?_eq_getElem below
        rw [the_test_is_beats parts i j' q p at_j' at_i]
        step as ⟨ j1, is_j1 ⟩
        have next := none_beats_from_the_next parts.val i.val j'.val
        refine ⟨?_, by scalar_tac⟩
        rw [← same_answer, is_j1]
        simp only [still, true_and, decide_not, Bool.not_eq_true']
        rw [next]
        simp only [decide_eq_true_eq, decide_eq_false_iff_not]
      · -- the flag is false: the loop ends with it
        simp only [still]
        refine (WP.spec_ok _).mpr ?_
        simpa [still] using same_answer
    · -- no part left: the loop ends with the flag
      have below' : ¬ j' < Slice.len parts := by scalar_tac
      simp only [below', ite_false]
      refine (WP.spec_ok _).mpr ?_
      rw [← same_answer]
      have parts_length : parts.length = parts.val.length := rfl
      have at_the_end : parts.val.length ≤ j'.val := by omega
      simp only [none_beats_from_the_end parts.val i.val j'.val at_the_end, and_true]
  · exact Iff.rfl

end RevokeCore
