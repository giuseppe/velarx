-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: what the outer loop of `adopt` answers: from a place `i` of the text, it
-- pushes, in order, the places of the parts that are adopted (`AdoptedAt`) after those it already
-- holds.  `adopt` is that loop from the place 0 with an empty answer, so it answers the places of
-- all the parts that are adopted, in increasing order, each once, and it always returns.
-- Why it is needed: it is the claim about what `adopt` answers, from which the claims of Spec.lean
-- about which parts are adopted and what is held afterwards are read.
-- Read before this file: Spec.lean, NewerLoop.lean, BeatenLoop.lean, AdoptsIsNotBeaten.lean.
-- Notation: `(List.range n).drop i` is the places `i`, `i + 1`, ... up to `n - 1`;
-- `l.filter p` keeps the elements of `l` that satisfy `p`.  `step with f as ⟨x, is_x⟩` goes
-- through one line of the Rust function that calls a function `f` we know the answer of.
import RevokeCore.AdoptsIsNotBeaten
import RevokeCore.NewerLoop
import RevokeCore.ReturnedAnswers

open Aeneas Aeneas.Std Result velarx_revoke_core

open Classical

namespace RevokeCore

noncomputable section

/-- The places from `i` on of a text of `n` parts that are adopted, in order. -/
def AdoptedFrom (held : List Held) (parts : List Part) (i : Nat) : List Nat :=
  ((List.range parts.length).drop i).filter fun k => decide (AdoptedAt held parts k)

/-- At a place inside the text, the places from `i` on are `i` and then those from `i + 1` on. -/
theorem adopted_from_the_next (held : List Held) (parts : List Part) (i : Nat)
    (inside : i < parts.length) :
    AdoptedFrom held parts i =
      (if AdoptedAt held parts i then [i] else []) ++ AdoptedFrom held parts (i + 1) := by
  unfold AdoptedFrom
  rw [List.drop_eq_getElem_cons (by simpa using inside)]
  by_cases adopted : AdoptedAt held parts i <;> simp [adopted]

/-- At the end of the text, no place is left. -/
theorem adopted_from_the_end (held : List Held) (parts : List Part) (i : Nat)
    (at_the_end : parts.length ≤ i) : AdoptedFrom held parts i = [] := by
  unfold AdoptedFrom
  rw [List.drop_of_length_le (by simpa using at_the_end)]
  simp

/-- The Rust test of the outer loop for the part `p` at the place `i` (verified, newer, not beaten)
is `AdoptedAt`. -/
theorem the_test_is_adopted (held : List Held) (parts : List Part) (i : Nat) (p : Part)
    (at_i : parts[i]? = some p) (newer : Bool) (newer_is : newer = true ↔
      p.verified = true ∧ NewerThanHeld held p.issuer p.number) (flag : Bool)
    (flag_is : flag = true ↔ newer = true ∧ NoneBeatsFrom parts i 0) :
    flag = true ↔ AdoptedAt held parts i := by
  rw [flag_is, newer_is]
  constructor
  · rintro ⟨⟨verified, newer⟩, not_beaten⟩
    exact ⟨p, at_i, (adopts_is_not_beaten held parts i p at_i).mpr ⟨verified, newer, not_beaten⟩⟩
  · rintro ⟨p', at_i', adopts⟩
    rw [at_i] at at_i'
    cases at_i'
    obtain ⟨verified, newer, not_beaten⟩ := (adopts_is_not_beaten held parts i p at_i).mp adopts
    exact ⟨⟨verified, newer⟩, not_beaten⟩

/-- **The outer loop of `adopt`** pushes, after the places it already holds, the places from `i`
on of the parts that are adopted, in order; it always returns.  (It is given room: what it holds
is no longer than `i`, so the vector never grows past what a `usize` counts.) -/
theorem adopt_loop_answers (held : Slice Held) (parts : Slice Part)
    (adopted : alloc.vec.Vec Std.Usize) (i : Std.Usize) (room : adopted.length ≤ i.val) :
    adopt_loop0 held parts adopted i ⦃ r =>
      r.val.map (fun k => k.val) =
        adopted.val.map (fun k => k.val) ++ AdoptedFrom held.val parts.val i.val ⦄ := by
  unfold adopt_loop0
  apply loop.spec_decr_nat (fun (q : alloc.vec.Vec Std.Usize × Std.Usize) => parts.length - q.2.val)
    (fun (q : alloc.vec.Vec Std.Usize × Std.Usize) =>
      q.1.val.map (fun k => k.val) ++ AdoptedFrom held.val parts.val q.2.val =
        adopted.val.map (fun k => k.val) ++ AdoptedFrom held.val parts.val i.val ∧
      q.1.length ≤ q.2.val)
  · rintro ⟨found, i'⟩ ⟨same_answer, room'⟩
    simp only at same_answer room' ⊢
    unfold adopt_loop0.body
    have parts_length : parts.length = parts.val.length := rfl
    by_cases below : i'.val < parts.length
    · -- the place is inside the text: the part at that place is read
      have below' : i' < Slice.len parts := by scalar_tac
      simp only [below', ite_true]
      step as ⟨ p, is_p ⟩
      have at_i' : parts.val[i'.val]? = some p := by
        rw [is_p]; exact List.getElem?_eq_getElem below
      -- the part is verified and newer than what is held
      obtain ⟨best, is_best⟩ : ∃ best : Bool,
          (if p.verified = true then newer held p.issuer p.number else ok false) = ok best ∧
            (best = true ↔ p.verified = true ∧ NewerThanHeld held.val p.issuer p.number) := by
        by_cases verified : p.verified = true
        · simp only [verified, ite_true, true_and]
          obtain ⟨best, is_best, answer⟩ :=
            returned_answer (newer_is_newer_than_held held p.issuer p.number)
          exact ⟨best, is_best, answer⟩
        · exact ⟨false, by simp [verified], by simp [verified]⟩
      rw [is_best.1]
      simp only [bind_ok]
      -- no part beats it
      obtain ⟨flag, is_flag, flag_answer⟩ := returned_answer
        (beaten_loop_answers parts i' p at_i' best 0#usize)
      rw [is_flag]
      simp only [bind_ok]
      have adopted_when : flag = true ↔ AdoptedAt held.val parts.val i'.val :=
        the_test_is_adopted held.val parts.val i'.val p at_i' best is_best.2 flag
          (by simpa using flag_answer)
      have next := adopted_from_the_next held.val parts.val i'.val (by omega)
      by_cases adopted_here : flag = true
      · simp only [adopted_here, ite_true]
        have room_left : found.val.length < Std.Usize.max := by
          have : found.length = found.val.length := rfl
          scalar_tac
        step as ⟨ found', is_found' ⟩
        step as ⟨ i2, is_i2 ⟩
        refine ⟨?_, by scalar_tac, by scalar_tac⟩
        rw [← same_answer, next, is_found', is_i2]
        simp [adopted_when.mp adopted_here]
      · simp only [adopted_here, Bool.false_eq_true, ite_false]
        step as ⟨ i2, is_i2 ⟩
        refine ⟨?_, by scalar_tac, by scalar_tac⟩
        have not_adopted : ¬ AdoptedAt held.val parts.val i'.val :=
          fun here => adopted_here (adopted_when.mpr here)
        rw [← same_answer, next, is_i2]
        simp [not_adopted]
    · -- no place left: the loop ends with what it holds
      have below' : ¬ i' < Slice.len parts := by scalar_tac
      simp only [below', ite_false]
      refine (WP.spec_ok _).mpr ?_
      rw [← List.append_nil (found.val.map _)] at same_answer
      have at_the_end : parts.val.length ≤ i'.val := by omega
      rw [adopted_from_the_end held.val parts.val i'.val at_the_end] at same_answer
      simpa using same_answer
  · exact ⟨rfl, room⟩

/-- **`adopt` answers the places of the parts that are adopted**, in increasing order; it always
returns. -/
theorem adopt_answers_the_places (held : Slice Held) (parts : Slice Part) :
    adopt held parts ⦃ r => Places r = AdoptedFrom held.val parts.val 0 ⦄ := by
  unfold adopt
  refine WP.spec_mono (adopt_loop_answers held parts (alloc.vec.Vec.new Std.Usize) 0#usize
    (by simp [alloc.vec.Vec.new])) ?_
  intro r answer
  simpa [Places, alloc.vec.Vec.new] using answer

end

end RevokeCore
