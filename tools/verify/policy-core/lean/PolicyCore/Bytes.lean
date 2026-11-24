-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: what the two loops that compare bytes answer: `same` (the two slices are
-- the same bytes) and `starts` (the first is the beginning of the second), loop by loop.
--
-- Why it is needed: every comparison of names, tags, digests and scopes in the crate is one of
-- these two loops.  Their answers are stated about lists (`a.val = b.val`, `a.val <+: b.val`),
-- so that the rest of the proofs never looks at an index.  The invariant of each loop says,
-- at each turn, what the flag already means for the bytes before the position `i`.
--
-- Read before this file: Spec.lean (the notation).
--
-- Notation: `m ⦃ r => P r ⦄` is "the Rust function `m` returns, and its result `r` satisfies
-- `P r`" (as in Spec.lean); `loop.spec_decr_nat` proves that a loop returns because a number
-- goes down at each turn and an invariant is kept by the body; `step as ⟨ x, hx ⟩` runs one line
-- of the Rust function and names its result `x` and what is known of it `hx`; `v.val` is the
-- list inside a vector or a slice; `l[k]?` is the element `k` of a list, if there is one.
import Extracted.Funs
open Aeneas Aeneas.Std Result velarx_policy_core
namespace PolicyCore

/-- Two lists are equal when they have the same length and agree at every position. -/
theorem list_eq_iff_agree {α : Type} (a b : List α) :
    a = b ↔ a.length = b.length ∧ ∀ k < a.length, a[k]? = b[k]? := by
  constructor
  · rintro rfl
    exact ⟨rfl, fun _ _ => rfl⟩
  · rintro ⟨same_length, agree⟩
    refine List.ext_getElem? (fun k => ?_)
    by_cases before : k < a.length
    · exact agree k before
    · rw [List.getElem?_eq_none (by omega), List.getElem?_eq_none (by omega)]

/-- A list is the beginning of another when it is not longer and they agree on its length. -/
theorem prefix_iff_agree {α : Type} (a b : List α) :
    a <+: b ↔ a.length ≤ b.length ∧ ∀ k < a.length, a[k]? = b[k]? := by
  rw [List.prefix_iff_getElem?]
  constructor
  · intro all
    refine ⟨?_, fun k below => by rw [all k below, List.getElem?_eq_getElem below]⟩
    exact (List.prefix_iff_getElem?.mpr all).length_le
  · rintro ⟨_, agree⟩ k below
    rw [← agree k below, List.getElem?_eq_getElem below]

/-- The loop of `same`: at each turn the flag says that the lengths are equal and the bytes
before the position `i` are. -/
theorem same_loop_is_equal (a b : Slice Std.U8) (equal : Bool) (i : Std.Usize)
    (read : i.val ≤ a.length)
    (state : equal = true ↔ a.length = b.length ∧ ∀ k < i.val, a.val[k]? = b.val[k]?) :
    same_loop a b equal i ⦃ r => r = true ↔ a.val = b.val ⦄ := by
  unfold same_loop
  apply loop.spec_decr_nat (fun q => a.length - q.2.val)
    (fun q => q.2.val ≤ a.length ∧
      (q.1 = true ↔ a.length = b.length ∧ ∀ k < q.2.val, a.val[k]? = b.val[k]?))
  · rintro ⟨equal, i⟩ ⟨read, state⟩
    simp only at read state ⊢
    unfold same_loop.body
    dsimp only [Slice.len]
    split
    · split
      · rename_i going below
        -- the bytes at `i` are read and compared
        step as ⟨ x, hx ⟩
        step as ⟨ y, hy ⟩
        step as ⟨ next, hnext ⟩
        obtain ⟨same_length, agree⟩ := state.mp going
        have below : i.val < a.length := by scalar_tac
        have x_is : a.val[i.val]? = some x := by simp [hx]
        have y_is : b.val[i.val]? = some y := by
          have : i.val < b.length := by omega
          simp [hy]
        refine ⟨by omega, ?_, by omega⟩
        rw [decide_eq_true_iff]
        constructor
        · intro same_byte
          refine ⟨same_length, fun k before => ?_⟩
          rcases Nat.lt_succ_iff_lt_or_eq.mp (by omega : k < i.val + 1) with earlier | at_i
          · exact agree k earlier
          · rw [at_i, x_is, y_is, same_byte]
        · rintro ⟨_, all⟩
          have := all i.val (by omega)
          rw [x_is, y_is] at this
          exact Option.some.inj this
      · rename_i going not_below
        -- every byte was compared
        have at_end : i.val = a.length := by scalar_tac
        simp only [WP.spec_ok]
        rw [state, ← at_end]
        have := list_eq_iff_agree a.val b.val
        simp only [Slice.length, ← at_end] at this ⊢
        exact this.symm
    · rename_i stopped
      -- a difference was found: the flag is false and stays so
      simp only [WP.spec_ok]
      have not_equal : equal = false := by simpa using stopped
      rw [not_equal]
      simp only [Bool.false_eq_true, false_iff]
      intro equal
      have := state.mpr ⟨congrArg List.length equal, fun k _ => by rw [equal]⟩
      rw [not_equal] at this
      cases this
  · exact ⟨read, state⟩

/-- The loop of `starts`: at each turn the flag says that `a` is not longer than `b` and the bytes
before the position `i` are the same. -/
theorem starts_loop_is_prefix (a b : Slice Std.U8) (equal : Bool) (i : Std.Usize)
    (read : i.val ≤ a.length)
    (state : equal = true ↔ a.length ≤ b.length ∧ ∀ k < i.val, a.val[k]? = b.val[k]?) :
    starts_loop a b equal i ⦃ r => r = true ↔ a.val <+: b.val ⦄ := by
  unfold starts_loop
  apply loop.spec_decr_nat (fun q => a.length - q.2.val)
    (fun q => q.2.val ≤ a.length ∧
      (q.1 = true ↔ a.length ≤ b.length ∧ ∀ k < q.2.val, a.val[k]? = b.val[k]?))
  · rintro ⟨equal, i⟩ ⟨read, state⟩
    simp only at read state ⊢
    unfold starts_loop.body
    dsimp only [Slice.len]
    split
    · split
      · rename_i going below
        -- the bytes at `i` are read and compared
        step as ⟨ x, hx ⟩
        step as ⟨ y, hy ⟩
        step as ⟨ next, hnext ⟩
        obtain ⟨fits, agree⟩ := state.mp going
        have below : i.val < a.length := by scalar_tac
        have x_is : a.val[i.val]? = some x := by simp [hx]
        have y_is : b.val[i.val]? = some y := by
          have : i.val < b.length := by omega
          simp [hy]
        refine ⟨by omega, ?_, by omega⟩
        rw [decide_eq_true_iff]
        constructor
        · intro same_byte
          refine ⟨fits, fun k before => ?_⟩
          rcases Nat.lt_succ_iff_lt_or_eq.mp (by omega : k < i.val + 1) with earlier | at_i
          · exact agree k earlier
          · rw [at_i, x_is, y_is, same_byte]
        · rintro ⟨_, all⟩
          have := all i.val (by omega)
          rw [x_is, y_is] at this
          exact Option.some.inj this
      · rename_i going not_below
        -- every byte was compared
        have at_end : i.val = a.length := by scalar_tac
        simp only [WP.spec_ok]
        rw [state, ← at_end]
        have := prefix_iff_agree a.val b.val
        simp only [Slice.length, ← at_end] at this ⊢
        exact this.symm
    · rename_i stopped
      -- a difference was found: the flag is false and stays so
      simp only [WP.spec_ok]
      have not_equal : equal = false := by simpa using stopped
      rw [not_equal]
      simp only [Bool.false_eq_true, false_iff]
      intro is_prefix
      obtain ⟨short, agree⟩ := (prefix_iff_agree a.val b.val).mp is_prefix
      have := state.mpr ⟨short, fun k before => agree k (by
        simp only [Slice.length] at read
        omega)⟩
      rw [not_equal] at this
      cases this
  · exact ⟨read, state⟩

end PolicyCore
