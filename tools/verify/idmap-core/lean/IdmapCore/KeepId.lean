-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: the shape of what `keep_id` returns: at most one entry for the container
-- ids below the user (to the sub ids from 1), then the entry of the user (to the parent id 0),
-- then at most one entry for the container ids above the user (to the same parent ids).  From the
-- shape, the claims about the pairs it maps and about `validate` follow (KeepIdClaims.lean).
--
-- Read before this file: Spec.lean (`KeepIdTop`, `KeepIdLayout`).
import IdmapCore.Spec

open Aeneas Aeneas.Std Result velarx_idmap_core

namespace IdmapCore

/-- What `keep_id` returns, in pieces: `below` the entries for the ids below the user (none, or
one), the entry of the user, and `above` the entries for the ids above it (none, or one). -/
def KeepIdShape (id sub : U32) (size : Option U32) (out : List Map) : Prop :=
  ∃ below above : List Map,
    out = below ++ [⟨id, 0#u32, 1#u32⟩] ++ above ∧
    (∀ a ∈ below, a.container_id.val = 0 ∧ a.parent_id.val = 1 ∧ 0 < a.size.val ∧
      a.size.val = min (KeepIdTop sub size) id.val) ∧
    (below ≠ [] ↔ (0 < sub.val ∧ id.val ≠ 0 ∧ 0 < min (KeepIdTop sub size) id.val)) ∧
    below.length ≤ 1 ∧
    (∀ a ∈ above, a.container_id.val = id.val + 1 ∧ a.parent_id.val = id.val + 1 ∧
      a.size.val = KeepIdTop sub size - id.val) ∧
    (above ≠ [] ↔ id.val < KeepIdTop sub size) ∧ above.length ≤ 1

/-- **`keep_id` returns the pieces**, for every id, number of sub ids and limit. -/
theorem keep_id_returns_the_pieces (id sub : U32) (size : Option U32) :
    keep_id id sub size ⦃ out => KeepIdShape id sub size out.val ⦄ := by
  unfold keep_id
  simp only [Std.lift, Std.bind_ok]
  have hsub := core.convert.num.FromU64U32.from_val_eq sub
  have hid := core.convert.num.FromU64U32.from_val_eq id
  refine WP.spec_bind (Pₘ := fun max1 : U64 => max1.val = KeepIdTop sub size) ?_ ?_
  · cases size with
    | none =>
      refine (WP.spec_ok _).mpr ?_
      simp [KeepIdTop, hsub]
    | some s =>
      simp only []
      split
      · rename_i positive
        have positive : 0 < s.val := by
          have := (UScalar.lt_equiv 0#u32 s).mp positive
          simpa using this
        have hs := core.convert.num.FromU64U32.from_val_eq s
        step as ⟨ i1, hi1 ⟩
        split
        · rename_i below
          have below : i1.val < (core.convert.num.FromU64U32.from sub).val := by
            have := (UScalar.lt_equiv i1 _).mp below
            exact this
          step as ⟨ i2, hi2 ⟩
          simp only [KeepIdTop]
          simp [show 0 < s.val ∧ s.val - 1 < sub.val from ⟨positive, by omega⟩]
          omega
        · rename_i not_below
          have not_below : ¬ i1.val < (core.convert.num.FromU64U32.from sub).val :=
            (UScalar.lt_equiv i1 _).not.mp not_below
          refine (WP.spec_ok _).mpr ?_
          simp only [KeepIdTop]
          simp [show ¬ (0 < s.val ∧ s.val - 1 < sub.val) from by omega]
      · rename_i not_positive
        have : s.val = 0 := by
          have := (UScalar.lt_equiv 0#u32 s).not.mp not_positive
          simpa using this
        refine (WP.spec_ok _).mpr ?_
        simp only [KeepIdTop]
        simp [show ¬ (0 < s.val ∧ s.val - 1 < sub.val) from by omega]
  · intro max1 is_max1
    have top_small : KeepIdTop sub size ≤ sub.val := by
      unfold KeepIdTop
      cases size with
      | none => simp
      | some s =>
        simp only []
        split <;> omega
    have id_small : id.val < 4294967296 := by
      have := id.hBounds
      simpa [UScalarTy.numBits] using this
    refine WP.spec_bind (Pₘ := fun below : U64 => below.val = min (KeepIdTop sub size) id.val)
      ?_ ?_
    · split
      · rename_i smaller
        have := (UScalar.lt_equiv max1 _).mp smaller
        refine (WP.spec_ok _).mpr ?_
        omega
      · rename_i not_smaller
        have := (UScalar.lt_equiv max1 _).not.mp not_smaller
        refine (WP.spec_ok _).mpr ?_
        omega
    · intro below is_below
      refine WP.spec_bind (Pₘ := fun out : alloc.vec.Vec Map =>
        (∀ a ∈ out.val, a.container_id.val = 0 ∧ a.parent_id.val = 1 ∧ 0 < a.size.val ∧
          a.size.val = min (KeepIdTop sub size) id.val) ∧
        (out.val ≠ [] ↔ (0 < sub.val ∧ id.val ≠ 0 ∧ 0 < min (KeepIdTop sub size) id.val)) ∧
        out.val.length ≤ 1) ?_ ?_
      · split
        · rename_i has_sub
          have has_sub : 0 < sub.val := by
            have := (UScalar.lt_equiv 0#u32 sub).mp has_sub
            simpa using this
          split
          · rename_i not_zero
            have not_zero : id.val ≠ 0 := by
              intro zero
              have : id = 0#u32 := UScalar.eq_of_val_eq zero
              simp [this] at not_zero
            split
            · rename_i positive
              have positive : 0 < below.val := by
                have := (UScalar.lt_equiv 0#u64 below).mp positive
                simpa using this
              step as ⟨ out, is_out ⟩
              have cast_is : (UScalar.cast UScalarTy.U32 below).val = below.val := by
                rw [UScalar.cast_val_eq]
                simp
                omega
              refine ⟨?_, ?_, by simp [is_out]⟩
              · intro a a_in
                rw [is_out] at a_in
                simp at a_in
                subst a_in
                simp
                omega
              · simp [is_out]
                omega
            · rename_i not_positive
              have not_positive : ¬ 0 < below.val := by
                have := (UScalar.lt_equiv 0#u64 below).not.mp not_positive
                simpa using this
              refine (WP.spec_ok _).mpr ⟨by simp [alloc.vec.Vec.new], ?_,
                by simp [alloc.vec.Vec.new]⟩
              simp [alloc.vec.Vec.new]
              omega
          · rename_i is_zero
            have is_zero : id.val = 0 := by
              simpa using is_zero
            refine (WP.spec_ok _).mpr ⟨by simp [alloc.vec.Vec.new], ?_, by simp [alloc.vec.Vec.new]⟩
            simp [alloc.vec.Vec.new]
            omega
        · rename_i no_sub
          have no_sub : sub.val = 0 := by
            have := (UScalar.lt_equiv 0#u32 sub).not.mp no_sub
            simpa using this
          refine (WP.spec_ok _).mpr ⟨by simp [alloc.vec.Vec.new], ?_, by simp [alloc.vec.Vec.new]⟩
          simp [alloc.vec.Vec.new]
          omega
      · intro out ⟨below_facts, below_iff, below_short⟩
        have room_for_user : out.val.length < Usize.max := by scalar_tac
        step as ⟨ out1, is_out1 ⟩
        split
        · rename_i above_user
          have above_user : id.val < KeepIdTop sub size := by
            have := (UScalar.lt_equiv (core.convert.num.FromU64U32.from id) max1).mp above_user
            omega
          have room_for_above : out1.val.length < Usize.max := by
            have : out1.val.length ≤ 2 := by simp [is_out1]; omega
            scalar_tac
          have sub_small : sub.val < 4294967296 := by
            have := sub.hBounds
            simpa [UScalarTy.numBits] using this
          step as ⟨ next, is_next ⟩
          step as ⟨ count, is_count ⟩
          step as ⟨ out2, is_out2 ⟩
          have cast_is : (UScalar.cast UScalarTy.U32 count).val = count.val := by
            rw [UScalar.cast_val_eq]
            simp
            omega
          refine ⟨out.val, [⟨next, next, UScalar.cast UScalarTy.U32 count⟩],
            by simp [is_out2, is_out1],
            below_facts, below_iff, below_short, ?_, ?_, by simp⟩
          · intro a a_in
            simp at a_in
            subst a_in
            simp
            omega
          · simp
            omega
        · rename_i not_above
          have not_above : ¬ id.val < KeepIdTop sub size := by
            have := (UScalar.lt_equiv (core.convert.num.FromU64U32.from id) max1).not.mp not_above
            omega
          refine (WP.spec_ok _).mpr ⟨out.val, [], by simp [is_out1], below_facts, below_iff,
            below_short, by simp, by simp [not_above], by simp⟩

end IdmapCore
