-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: the facts about the bit operations of `u64` that the proofs of
-- crates/caps-core use, and nothing else: which capabilities are in `a &&& b`, `a ||| b` and
-- `~~~a`, and that two sets with the same capabilities are equal.
--
-- Why it is needed: `sets` is a few `&&&`, `|||` and `~~~` on 64-bit masks.  A claim says
-- things bit by bit ("capability `i` is in the set"); these lemmas are the bridge between
-- the two.  With them, each question about `sets` becomes a question about true and false,
-- one capability at a time, which Lean's `tauto` decides.
--
-- Read before this file: Spec.lean (`Has`, `Within`).
--
-- Notation: `a &&& b` is "in both", `a ||| b` is "in one or both", `~~~a` is "not in a"; `0#u64`
-- is the empty set; `Has a i` is "capability i is in a" (Spec.lean); `[simp]` lemmas are used
-- by Lean's `simp` by themselves.
import CapsCore.Spec

open Aeneas Aeneas.Std Result velarx_caps_core

namespace CapsCore

/-- A capability is in `a &&& b` when it is in both. -/
@[simp] theorem has_and (a b : Std.U64) (i : Fin 64) : Has (a &&& b) i ↔ Has a i ∧ Has b i := by
  simp [Has]

/-- A capability is in `a ||| b` when it is in one of them. -/
@[simp] theorem has_or (a b : Std.U64) (i : Fin 64) : Has (a ||| b) i ↔ Has a i ∨ Has b i := by
  simp [Has]

/-- A capability is in `~~~a` when it is not in `a` (the 64 bits are all there is). -/
@[simp] theorem has_not (a : Std.U64) (i : Fin 64) : Has (~~~a) i ↔ ¬ Has a i := by
  simp [Has]

/-- No capability is in the empty set. -/
@[simp] theorem has_zero (i : Fin 64) : ¬ Has 0#u64 i := by
  simp [Has]

/-- Two sets that have the same capabilities are the same number. -/
theorem eq_of_has (a b : Std.U64) (same : ∀ i, Has a i ↔ Has b i) : a = b := by
  cases a with | mk a => cases b with | mk b =>
  congr
  apply BitVec.eq_of_getElem_eq
  intro i inside
  have := same ⟨i, inside⟩
  simpa [Has] using this

/-- `a &&& ~~~b` (what `sets` computes for "the capabilities of `a` that `b` lacks") is empty
exactly when `a` is within `b`. -/
theorem and_not_eq_zero (a b : Std.U64) : a &&& ~~~b = 0#u64 ↔ Within a b := by
  constructor
  · intro empty i in_a
    by_contra not_in_b
    have in_both := (has_and a (~~~b) i).mpr ⟨in_a, (has_not b i).mpr not_in_b⟩
    rw [empty] at in_both
    exact has_zero i in_both
  · intro within
    apply eq_of_has
    intro i
    simp only [has_and, has_not]
    constructor
    · rintro ⟨in_a, not_in_b⟩
      exact absurd (within i in_a) not_in_b
    · intro in_zero
      exact absurd in_zero (has_zero i)

/-- The test `sets` makes (`a & !b != 0`) is true exactly when `a` is not within `b`. -/
theorem and_not_ne_zero (a b : Std.U64) : (a &&& ~~~b != 0#u64) = true ↔ ¬ Within a b := by
  rw [← and_not_eq_zero]
  simp

end CapsCore
