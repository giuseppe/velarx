-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: what the loop of `newer` answers: from a place `i` of the entries held, it
-- answers true when the flag it was given is true and no entry from `i` on names the issuer with
-- a number that is not lower than the one asked.  `newer` is that loop from the first place with
-- the flag true, and so it is true exactly when the number is higher than every number held of the
-- issuer (`NewerThanHeld`).
-- Why it is needed: `adopt` asks `newer` for each part, and the claims about what `adopt` answers
-- read `newer` as `NewerThanHeld`.
-- Read before this file: Spec.lean.
-- Notation: `loop body x ⦃ post ⦄` reads: the loop returns and its answer satisfies `post`.
-- `step` goes through one line of the Rust function, and `scalar_tac` proves a fact about the
-- numbers of the machine (`usize`, `u64`) by arithmetic.
import RevokeCore.Spec

open Aeneas Aeneas.Std Result velarx_revoke_core

namespace RevokeCore

/-- No entry from the place `i` of `held` names `issuer` with a number that is not lower than
`number`. -/
def NoneAsHighFrom (held : List Held) (issuer number : Std.U64) (i : Nat) : Prop :=
  ∀ k, i ≤ k → ∀ h, held[k]? = some h → h.issuer = issuer → h.number.val < number.val

/-- One more entry: `NoneAsHighFrom` from the place `i` holds exactly when the entry at `i` is not
of the issuer or has a lower number, and it holds from the place after. -/
theorem none_as_high_from_the_next (held : List Held) (issuer number : Std.U64) (i : Nat)
    (entry : Held) (at_i : held[i]? = some entry) :
    NoneAsHighFrom held issuer number i ↔
      (entry.issuer = issuer → entry.number.val < number.val) ∧
        NoneAsHighFrom held issuer number (i + 1) := by
  constructor
  · intro none_as_high
    exact ⟨none_as_high i (le_refl i) entry at_i, fun k later => none_as_high k (by omega)⟩
  · rintro ⟨entry_low, rest_low⟩ k from_i h at_k is_issuer
    rcases Nat.eq_or_lt_of_le from_i with same | after
    · subst same
      rw [at_i] at at_k
      cases at_k
      exact entry_low is_issuer
    · exact rest_low k after h at_k is_issuer

/-- From a place at or after the end, no entry is left. -/
theorem none_as_high_from_the_end (held : List Held) (issuer number : Std.U64) (i : Nat)
    (at_the_end : held.length ≤ i) : NoneAsHighFrom held issuer number i := by
  intro k from_i h at_k
  have := (List.getElem?_eq_some_iff.mp at_k).1
  omega

/-- **The loop of `newer`** answers true exactly when the flag it was given is true and no entry
from the place `i` on names the issuer with a number that is not lower than `number`.  It always
returns. -/
theorem newer_loop_answers (held : Slice Held) (issuer number : Std.U64) (flag : Bool)
    (i : Std.Usize) :
    newer_loop held issuer number flag i ⦃ r =>
      (r = true ↔ flag = true ∧ NoneAsHighFrom held.val issuer number i.val) ⦄ := by
  unfold newer_loop
  apply loop.spec_decr_nat (fun (q : Bool × Std.Usize) => held.length - q.2.val)
    (fun (q : Bool × Std.Usize) =>
      (q.1 = true ∧ NoneAsHighFrom held.val issuer number q.2.val ↔
        flag = true ∧ NoneAsHighFrom held.val issuer number i.val))
  · rintro ⟨flag', i'⟩ same_answer
    simp only at same_answer ⊢
    unfold newer_loop.body
    by_cases below : i'.val < held.length
    · -- the place is inside the entries held
      have below' : i' < Slice.len held := by scalar_tac
      simp only [below', ite_true]
      by_cases still : flag' = true
      · -- the flag is still true: the entry at the place is read
        simp only [still, ite_true]
        step as ⟨ h, is_h ⟩
        have at_i' : held.val[i'.val]? = some h := by
          rw [is_h]; exact List.getElem?_eq_getElem below
        have next := none_as_high_from_the_next held.val issuer number i'.val h at_i'
        by_cases same_issuer : h.issuer = issuer
        · by_cases high : h.number ≥ number
          · -- an entry of the issuer with a number that is not lower: the flag falls
            simp only [same_issuer, high, ite_true]
            step as ⟨ i2, is_i2 ⟩
            refine ⟨?_, by scalar_tac⟩
            rw [← same_answer]
            simp only [Bool.false_eq_true, false_and, false_iff, not_and]
            intro _ none_as_high
            have low := (next.mp none_as_high).1 same_issuer
            have : h.number.val ≥ number.val := by scalar_tac
            omega
          · -- an entry of the issuer with a lower number
            simp only [same_issuer, high, ite_true, ite_false]
            step as ⟨ i2, is_i2 ⟩
            have low : h.number.val < number.val := by scalar_tac
            refine ⟨?_, by scalar_tac⟩
            rw [← same_answer, is_i2]
            simp only [still, true_and]
            rw [next]
            exact ⟨fun rest => ⟨fun _ => low, rest⟩, fun ⟨_, rest⟩ => rest⟩
        · -- an entry of another issuer
          simp only [same_issuer, ite_false]
          step as ⟨ i2, is_i2 ⟩
          refine ⟨?_, by scalar_tac⟩
          rw [← same_answer, is_i2]
          simp only [still, true_and]
          rw [next]
          exact ⟨fun rest => ⟨fun same => absurd same same_issuer, rest⟩, fun ⟨_, rest⟩ => rest⟩
      · -- the flag is false: the loop ends with it
        simp only [still]
        refine (WP.spec_ok _).mpr ?_
        simpa [still] using same_answer
    · -- no entry left: the loop ends with the flag
      have below' : ¬ i' < Slice.len held := by scalar_tac
      simp only [below', ite_false]
      refine (WP.spec_ok _).mpr ?_
      rw [← same_answer]
      have held_length : held.length = held.val.length := rfl
      have at_the_end : held.val.length ≤ i'.val := by omega
      simp only [none_as_high_from_the_end held.val issuer number i'.val at_the_end, and_true]
  · exact Iff.rfl

/-- **`newer` answers true exactly when the number is higher than every number held of the
issuer** (`NewerThanHeld`); it always returns. -/
theorem newer_is_newer_than_held (held : Slice Held) (issuer number : Std.U64) :
    newer held issuer number ⦃ r => r = true ↔ NewerThanHeld held.val issuer number ⦄ := by
  unfold newer
  refine WP.spec_mono (newer_loop_answers held issuer number true 0#usize) ?_
  intro r answer
  rw [answer]
  simp only [true_and, show (0#usize).val = 0 from rfl]
  constructor
  · intro none_as_high n n_held
    simp only [NumbersHeld, List.mem_map, List.mem_filter, decide_eq_true_eq] at n_held
    obtain ⟨h, ⟨h_in, same_issuer⟩, is_n⟩ := n_held
    obtain ⟨k, at_k⟩ := List.getElem_of_mem h_in
    have := none_as_high k (Nat.zero_le k) h (by simp [List.getElem?_eq_getElem at_k.1, at_k.2])
      same_issuer
    omega
  · intro newer_than_held k _ h at_k same_issuer
    exact newer_than_held h.number.val (by
      simp only [NumbersHeld, List.mem_map, List.mem_filter, decide_eq_true_eq]
      exact ⟨h, ⟨List.mem_of_getElem? at_k, same_issuer⟩, rfl⟩)

end RevokeCore
