-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: what `same` answers: true exactly when its two slices are the same bytes.
-- Why it is needed: every comparison of the crate (an operating system, an architecture, a variant,
-- the names `arm` and `v7`) is a call of `same`, so the claims about what is chosen read it as the
-- equality of two lists of bytes.
-- Read before this file: Spec.lean.
-- Notation: `loop body x ⦃ post ⦄` reads: the loop returns and its answer satisfies `post`.
-- `step` goes through one line of the Rust function, and `scalar_tac` proves a fact about the
-- numbers of the machine (`usize`) by arithmetic.
import PlatformCore.Spec

open Aeneas Aeneas.Std Result velarx_platform_core

namespace PlatformCore

/-- The two slices agree at the place `i` and at every place after it exactly when they agree from
`i` on: one more place. -/
theorem agree_from_the_next (a b : Slice Std.U8) (i : Nat) (inside : i < a.length) :
    (∀ k, i ≤ k → k < a.length → a.val[k]? = b.val[k]?) ↔
      a.val[i]? = b.val[i]? ∧ ∀ k, i + 1 ≤ k → k < a.length → a.val[k]? = b.val[k]? := by
  constructor
  · intro agree
    exact ⟨agree i (le_refl i) inside, fun k later in_a => agree k (by omega) in_a⟩
  · rintro ⟨here, rest⟩ k from_i in_a
    rcases Nat.eq_or_lt_of_le from_i with same_place | after
    · rw [← same_place]; exact here
    · exact rest k after in_a

/-- **The loop of `same`** from the place `i`, with the flag `flag`: it answers true exactly when
the flag is true and the two slices agree at every place from `i` on that is inside the first.  The
flag may be true only when the slices have the same length (the loop reads the second slice at the
places of the first). -/
theorem same_loop_answers (a b : Slice Std.U8) (flag : Bool) (i : Std.Usize)
    (same_length : flag = true → a.length = b.length) :
    same_loop a b flag i ⦃ r =>
      r = true ↔ flag = true ∧ ∀ k, i.val ≤ k → k < a.length → a.val[k]? = b.val[k]? ⦄ := by
  unfold same_loop
  apply loop.spec_decr_nat (fun (q : Bool × Std.Usize) => a.length - q.2.val)
    (fun (q : Bool × Std.Usize) =>
      (q.1 = true → a.length = b.length) ∧
      ((q.1 = true ∧ ∀ k, q.2.val ≤ k → k < a.length → a.val[k]? = b.val[k]?) ↔
        (flag = true ∧ ∀ k, i.val ≤ k → k < a.length → a.val[k]? = b.val[k]?)))
  · rintro ⟨flag', i'⟩ ⟨same_length', same_answer⟩
    simp only at same_length' same_answer ⊢
    unfold same_loop.body
    by_cases below : i'.val < a.length
    · -- the place is inside the first slice
      have below' : i' < Slice.len a := by scalar_tac
      simp only [below', ite_true]
      by_cases still : flag' = true
      · -- the flag is still true: both bytes are read and compared
        simp only [still, ite_true]
        have inside : i'.val < b.length := by have := same_length' still; omega
        step as ⟨ x, is_x ⟩
        step as ⟨ y, is_y ⟩
        step as ⟨ i2, is_i2 ⟩
        have at_a : a.val[i'.val]? = some x := by
          rw [is_x]; exact List.getElem?_eq_getElem below
        have at_b : b.val[i'.val]? = some y := by
          rw [is_y]; exact List.getElem?_eq_getElem inside
        have next := agree_from_the_next a b i'.val below
        refine ⟨fun _ => same_length' still, ?_, by scalar_tac⟩
        rw [← same_answer, is_i2, next, at_a, at_b]
        simp [still]
      · -- the flag is false: the loop ends with it
        simp only [still]
        refine (WP.spec_ok _).mpr ?_
        rw [← same_answer]
        simp [still]
    · -- no place is left: the loop ends with the flag
      have below' : ¬ i' < Slice.len a := by scalar_tac
      simp only [below', ite_false]
      refine (WP.spec_ok _).mpr ?_
      rw [← same_answer]
      have nothing_left : ∀ k, i'.val ≤ k → k < a.length → a.val[k]? = b.val[k]? := by
        intro k from_i' in_a; omega
      exact ⟨fun still => ⟨still, nothing_left⟩, fun ⟨still, _⟩ => still⟩
  · exact ⟨same_length, Iff.rfl⟩

/-- **`same` answers true exactly when the two slices are the same bytes** (the same length, the
same byte at every place); it always returns. -/
@[step]
theorem same_is_equal (a b : Slice Std.U8) : same a b ⦃ r => r = true ↔ a.val = b.val ⦄ := by
  unfold same
  refine WP.spec_mono (same_loop_answers a b _ 0#usize ?_) ?_
  · intro same_length
    have := congrArg Std.UScalar.val (of_decide_eq_true same_length)
    simpa [Slice.len_val] using this
  · intro r answer
    rw [answer]
    constructor
    · rintro ⟨same_length, agree⟩
      have same_length' : a.val.length = b.val.length := by
        have := congrArg Std.UScalar.val (of_decide_eq_true same_length)
        simpa [Slice.len_val] using this
      apply List.ext_getElem?
      intro k
      by_cases inside : k < a.length
      · exact agree k (Nat.zero_le k) inside
      · have outside_a : a.val.length ≤ k := by simp [Slice.length] at inside; omega
        rw [List.getElem?_eq_none outside_a, List.getElem?_eq_none (by omega)]
    · intro same_bytes
      have same_length : a.length = b.length := by simp [Slice.length, same_bytes]
      refine ⟨decide_eq_true ?_, fun k _ _ => by rw [same_bytes]⟩
      apply Std.UScalar.eq_of_val_eq
      rw [Slice.len_val, Slice.len_val]
      exact same_length

end PlatformCore
