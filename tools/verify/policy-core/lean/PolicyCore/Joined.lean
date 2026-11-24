-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: `is_joined` (the scope is the name, a separator and a tail) and
-- `is_reference` (the scope is the exact reference of the image): what each answers, and that
-- they never read outside a slice.
--
-- Why it is needed: the class 4 of a scope (`IsReferenceOf`) is `is_reference`.  `is_joined`
-- compares the length first by a difference (the code is written so that no sum of lengths can
-- overflow), then the bytes one by one.
--
-- Read before this file: Scope.lean.
--
-- Notation: `m ⦃ r => P r ⦄` is "the Rust function `m` returns, and its result `r` satisfies
-- `P r`" (as in Spec.lean); `loop.spec_decr_nat` proves that a loop returns because a number
-- goes down at each turn and an invariant is kept by the body; `step as ⟨ x, hx ⟩` runs one line
-- of the Rust function and names its result `x` and what is known of it `hx`; `v.val` is the
-- list inside a vector or a slice; `l[k]?` is the element `k` of a list, if there is one.
import PolicyCore.Scope
open Aeneas Aeneas.Std Result velarx_policy_core
namespace PolicyCore

/-- The byte `i` of `name ++ sep :: tail`, as `is_joined` computes it: from the name, the
separator, or the tail. -/
@[step]
theorem joined_byte (full tail : Slice Std.U8) (sep : Std.U8) (i : Std.Usize)
    (inside : i.val < full.length + 1 + tail.length) :
    (do let i2 := Slice.len full
        if i < i2 then full.index_usize i
        else
          let i3 := Slice.len full
          if i = i3 then ok sep
          else do
            let i4 := Slice.len full
            let i5 ← i - i4
            let i6 ← i5 - 1#usize
            tail.index_usize i6) ⦃ e => (full.val ++ sep :: tail.val)[i.val]? = some e ⦄ := by
  dsimp only [Slice.len]
  split
  · rename_i in_name
    have in_name : i.val < full.length := by simpa [Slice.length] using in_name
    step as ⟨ e, he ⟩
    rw [List.getElem?_append_left (by simpa [Slice.length] using in_name)]
    simp [he]
  · rename_i past_name
    have past_name : full.length ≤ i.val := by simpa [Slice.length] using past_name
    split
    · rename_i at_sep
      have at_sep : i.val = full.length := (index_eq_len_iff i full).mp at_sep
      simp [at_sep, Slice.length]
    · rename_i after_sep
      have after_sep : i.val ≠ full.length := fun at_sep =>
        after_sep ((index_eq_len_iff i full).mpr at_sep)
      step as ⟨ i5, h5 ⟩
      step as ⟨ i6, h6 ⟩
      step as ⟨ e, he ⟩
      rw [List.getElem?_append_right (by simpa [Slice.length] using past_name)]
      have in_tail : i.val - full.val.length = i6.val + 1 := by
        simp only [Usize.ofNatCore, UScalar.ofNatCore_val_eq] at h5
        omega
      rw [in_tail, List.getElem?_cons_succ]
      simp [he]
/-- The loop of `is_joined`: at each turn the flag says that the scope has the length of
`name`, the separator and the tail, and that its bytes before the position `i` are theirs. -/
theorem is_joined_loop_is (scope full : Slice Std.U8) (sep : Std.U8) (tail : Slice Std.U8)
    (flag : Bool) (i : Std.Usize) (read : i.val ≤ scope.length)
    (state : flag = true ↔ scope.length = full.length + 1 + tail.length ∧
      ∀ k < i.val, scope.val[k]? = (full.val ++ sep :: tail.val)[k]?) :
    is_joined_loop scope full sep tail flag i ⦃ r =>
      r = true ↔ scope.val = full.val ++ sep :: tail.val ⦄ := by
  unfold is_joined_loop
  apply loop.spec_decr_nat (fun q => scope.length - q.2.val)
    (fun q => q.2.val ≤ scope.length ∧
      (q.1 = true ↔ scope.length = full.length + 1 + tail.length ∧
        ∀ k < q.2.val, scope.val[k]? = (full.val ++ sep :: tail.val)[k]?))
  · rintro ⟨flag, i⟩ ⟨read, state⟩
    simp only at read state ⊢
    unfold is_joined_loop.body
    dsimp only [Slice.len]
    split
    · split
      · rename_i going below
        obtain ⟨right_length, agree⟩ := state.mp going
        have inside : i.val < scope.length := by scalar_tac
        -- the byte the scope should have at `i` is computed, then the one it has is read
        refine WP.spec_bind (joined_byte full tail sep i (by omega)) (fun e expected => ?_)
        step as ⟨ y, hy ⟩
        step as ⟨ next, hnext ⟩
        have y_is : scope.val[i.val]? = some y := by simp [hy]
        refine ⟨by omega, ?_, by omega⟩
        rw [decide_eq_true_iff]
        constructor
        · intro same_byte
          refine ⟨right_length, fun k before => ?_⟩
          rcases Nat.lt_succ_iff_lt_or_eq.mp (by omega : k < i.val + 1) with earlier | at_i
          · exact agree k earlier
          · rw [at_i, y_is, expected, same_byte]
        · rintro ⟨_, all⟩
          have := all i.val (by omega)
          rw [y_is, expected] at this
          exact Option.some.inj this
      · rename_i going not_below
        -- every byte was compared
        have at_end : i.val = scope.val.length := by
          have : i.val = scope.length := by scalar_tac
          simpa [Slice.length] using this
        simp only [WP.spec_ok]
        rw [state]
        constructor
        · rintro ⟨right_length, agree⟩
          refine (list_eq_iff_agree _ _).mpr ⟨?_, fun k below => agree k (by omega)⟩
          simp only [Slice.length, List.length_append, List.length_cons] at right_length ⊢
          omega
        · intro joined
          refine ⟨?_, fun k _ => by rw [joined]⟩
          simp only [Slice.length, joined, List.length_append, List.length_cons]
          omega
    · rename_i stopped
      -- a difference was found
      simp only [WP.spec_ok]
      have not_flag : flag = false := by simpa using stopped
      rw [not_flag]
      simp only [Bool.false_eq_true, false_iff]
      intro joined
      have right_length : scope.length = full.length + 1 + tail.length := by
        simp only [Slice.length, joined, List.length_append, List.length_cons]
        omega
      have := state.mpr ⟨right_length, fun k _ => by rw [joined]⟩
      rw [not_flag] at this
      cases this
  · exact ⟨read, state⟩
/-- `is_joined` says whether the scope is the name, the separator and the tail. -/
@[step]
theorem is_joined_is (scope full : Slice Std.U8) (sep : Std.U8) (tail : Slice Std.U8) :
    is_joined scope full sep tail ⦃ r =>
      r = true ↔ scope.val = full.val ++ sep :: tail.val ⦄ := by
  unfold is_joined
  -- the length is checked first, by a difference, not a sum
  refine WP.spec_bind (Pₘ := fun flag => flag = true ↔
    scope.length = full.length + 1 + tail.length) ?_ (fun flag right_length => ?_)
  · dsimp only [Slice.len]
    split
    · rename_i longer
      have longer : full.length < scope.length := by simpa [Slice.length] using longer
      step as ⟨ i4, h4 ⟩
      step as ⟨ i5, h5 ⟩
      rw [decide_eq_true_iff, UScalar.eq_equiv]
      simp only [Usize.ofNatCore, UScalar.ofNatCore_val_eq] at h4 ⊢
      simp only [Slice.length] at longer ⊢
      omega
    · rename_i not_longer
      simp only [WP.spec_ok, Bool.false_eq_true, false_iff]
      simp only [GT.gt, UScalar.lt_equiv, Usize.ofNatCore, UScalar.ofNatCore_val_eq] at not_longer
      simp only [Slice.length]
      omega
  · apply is_joined_loop_is
    · simp
    · simpa using right_length
/-- `is_reference` says whether the scope is the exact reference of the image. -/
@[step]
theorem is_reference_is (scope : Slice Std.U8) (image : Ref) :
    is_reference scope image ⦃ r => r = true ↔ IsReferenceOf scope.val image ⦄ := by
  unfold is_reference
  rcases digest : image.digest with _ | digest
  · rcases tag : image.tag with _ | tag
    · simp [IsReferenceOf, digest, tag]
    · simp only [IsReferenceOf, digest, tag]
      step as ⟨ r, hr ⟩
      simpa [colon] using hr
  · simp only [IsReferenceOf, digest]
    step as ⟨ r, hr ⟩
    simpa [at_sign] using hr
end PolicyCore
