-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: `sort_and_merge`: the entries it returns map exactly what the entries it
-- is given map, and when the given entries are sane and apart, so are the returned ones.
--
-- Read before this file: Spec.lean, SortAndMergeSort.lean, MergeState.lean.
import IdmapCore.SortAndMergeSort
import IdmapCore.MergeState

open Aeneas Aeneas.Std Result velarx_idmap_core

namespace IdmapCore

/-- The merge loop of `sort_and_merge`. -/
theorem merge_loop_keeps_the_pairs (sorted : alloc.vec.Vec Map) :
    sort_and_merge_loop1 sorted (alloc.vec.Vec.new Map) 0#usize ⦃ out =>
      MergeState sorted.val out.val sorted.val.length ⦄ := by
  unfold sort_and_merge_loop1
  apply loop.spec_decr_nat (fun q => sorted.length - q.2.val)
    (fun q => MergeState sorted.val q.1.val q.2.val)
  · rintro ⟨out, i⟩ state
    simp only at state ⊢
    unfold sort_and_merge_loop1.body
    dsimp only
    have same_length : sorted.length = sorted.val.length := rfl
    split
    · rename_i inside
      have inside : i.val < sorted.val.length := by scalar_tac
      step as ⟨ m, is_m ⟩
      have is_m' : sorted.val[i.val]? = some m := by rw [List.getElem?_eq_getElem inside, is_m]
      have m_in : m ∈ sorted.val := List.mem_of_getElem? is_m'
      have push_case : MergeState sorted.val (out.val ++ [m]) (i.val + 1) :=
        merge_state_after_adding sorted.val out.val i.val m state is_m'
      have room : out.val.length < Usize.max := by
        have := sorted.property
        have := state.2.1
        scalar_tac
      have push : out.push m ⦃ out1 => MergeState sorted.val out1.val (i.val + 1) ⦄ := by
        step as ⟨ out1, is_out1 ⟩
        rw [is_out1]
        exact push_case
      refine WP.spec_bind (Pₘ := fun out1 : alloc.vec.Vec Map =>
        MergeState sorted.val out1.val (i.val + 1)) ?_ ?_
      · split
        · rename_i kept
          have positive : 0 < out.val.length := by
            have := (UScalar.lt_equiv 0#usize out.len).mp kept
            have same : out.len.val = out.val.length := rfl
            simp at this
            omega
          obtain ⟨init, last, is_out⟩ : ∃ init last, out.val = init ++ [last] := by
            rcases List.eq_nil_or_concat out.val with empty | ⟨init, last, is_out⟩
            · simp [empty] at positive
            · exact ⟨init, last, by simpa using is_out⟩
          step as ⟨ i2, is_i2 ⟩
          have len_is : out.len.val = init.length + 1 := by
            have : out.len.val = out.val.length := rfl
            rw [this, is_out]
            simp
          have is_i2' : i2.val = init.length := by omega
          have i2_inside : i2.val < out.val.length := by
            rw [is_out]
            simp [is_i2']
          have last_is : out.val[i2.val] = last :=
            the_element_before_the_spare_at_the_end init last out.val is_out i2.val is_i2'
              i2_inside
          have hc_last := core.convert.num.FromU64U32.from_val_eq last.container_id
          have hp_last := core.convert.num.FromU64U32.from_val_eq last.parent_id
          have hs_last := core.convert.num.FromU64U32.from_val_eq last.size
          have hc_m := core.convert.num.FromU64U32.from_val_eq m.container_id
          have hp_m := core.convert.num.FromU64U32.from_val_eq m.parent_id
          have hs_m := core.convert.num.FromU64U32.from_val_eq m.size
          simp only [Std.lift, Std.bind_ok]
          step as ⟨ m1, is_m1 ⟩
          step as ⟨ m2, is_m2 ⟩
          have m1_is : m1 = last := by rw [is_m1, last_is]
          have m2_is : m2 = last := by rw [is_m2, last_is]
          step as ⟨ i5, is_i5 ⟩
          rw [m1_is, m2_is] at is_i5
          split
          · rename_i adjacent_c
            have adjacent_c : last.container_id.val + last.size.val = m.container_id.val := by
              have := congrArg UScalar.val adjacent_c
              omega
            step as ⟨ m3, is_m3 ⟩
            step as ⟨ m4, is_m4 ⟩
            have m3_is : m3 = last := by rw [is_m3, last_is]
            have m4_is : m4 = last := by rw [is_m4, last_is]
            step as ⟨ i9, is_i9 ⟩
            rw [m3_is, m4_is] at is_i9
            split
            · rename_i adjacent_p
              have adjacent_p : last.parent_id.val + last.size.val = m.parent_id.val := by
                have := congrArg UScalar.val adjacent_p
                omega
              step as ⟨ m5, is_m5 ⟩
              have m5_is : m5 = last := by rw [is_m5, last_is]
              step as ⟨ i13, is_i13 ⟩
              rw [m5_is] at is_i13
              split
              · rename_i fits
                have fits : last.size.val + m.size.val ≤ 4294967295 := by
                  have := (UScalar.le_equiv i13 _).mp fits
                  have max_is : (core.convert.num.FromU64U32.from core.num.U32.MAX).val =
                      4294967295 := by
                    rw [core.convert.num.FromU64U32.from_val_eq]
                    exact (by decide : core.num.U32.MAX.val = 4294967295)
                  omega
                step as ⟨ m6, index_mut_back, is_m6, is_back ⟩
                have m6_is : m6 = last := by rw [is_m6, last_is]
                step as ⟨ i15, is_i15 ⟩
                rw [m6_is] at *
                have joined_is : (index_mut_back
                    { container_id := last.container_id, parent_id := last.parent_id,
                      size := i15 }).val = init ++ [⟨last.container_id, last.parent_id, i15⟩] := by
                  rw [is_back, alloc.vec.Vec.set_val_eq, is_out, is_i2']
                  exact write_over_the_spare init last [] _
                rw [joined_is]
                refine merge_state_after_joining sorted.val init last i.val m _
                  (by rw [← is_out]; exact state) is_m' ⟨adjacent_c, adjacent_p, rfl, rfl, ?_⟩
                simpa using is_i15
              · exact push
            · exact push
          · exact push
        · rename_i empty
          exact push
      · intro out1 state1
        step as ⟨ i1, is_i1 ⟩
        refine ⟨?_, by omega⟩
        rw [is_i1]
        exact state1
    · rename_i outside
      have : i.val = sorted.val.length := by
        have h := (UScalar.lt_equiv i sorted.len).not.mp outside
        have h2 := state.1
        have same : sorted.len.val = sorted.val.length := rfl
        omega
      refine (WP.spec_ok _).mpr ?_
      rw [← this]
      exact state
  · refine ⟨by simp, by simp [alloc.vec.Vec.new], fun c p => ?_, fun sane apart => ?_⟩
    · simp [alloc.vec.Vec.new, maps_of_nothing]
    · simp [alloc.vec.Vec.new]

/-- Two entries that are apart are apart the other way round. -/
theorem apart_is_symmetric (a b : Map) (apart : Apart a b) : Apart b a :=
  ⟨fun c ⟨in_b, in_a⟩ => apart.1 c ⟨in_a, in_b⟩, fun p ⟨in_b, in_a⟩ => apart.2 p ⟨in_a, in_b⟩⟩

/-- **`sort_and_merge`**: it returns, and its answer maps exactly the pairs that its input maps.
Moreover when the input has only sane entries that are apart, so has the answer, and the answer
has no more entries than the input. -/
theorem sort_and_merge_keeps_the_pairs (maps : Slice Map) :
    sort_and_merge maps ⦃ out =>
      (∀ c p, Maps out.val c p ↔ Maps maps.val c p) ∧
      ((∀ e ∈ maps.val, Sane e) → maps.val.Pairwise Apart →
        (∀ e ∈ out.val, Sane e) ∧ out.val.Pairwise Apart) ∧
      out.val.length ≤ maps.val.length ⦄ := by
  unfold sort_and_merge
  step with sort_keeps_the_entries maps as ⟨ sorted, perm ⟩
  step with merge_loop_keeps_the_pairs sorted as ⟨ out, state ⟩
  obtain ⟨_, out_few, same_maps, rest⟩ := state
  rw [List.take_length] at same_maps rest
  refine ⟨fun c p => by rw [same_maps, maps_of_a_reordering _ _ perm], fun sane apart => ?_,
    by rw [← perm.length_eq]; exact out_few⟩
  have sorted_sane : ∀ e ∈ sorted.val, Sane e := fun e e_in => sane e (perm.subset e_in)
  have sorted_apart : sorted.val.Pairwise Apart :=
    (perm.pairwise_iff (fun {a b} h => apart_is_symmetric a b h)).mpr apart
  obtain ⟨out_sane, out_apart, _⟩ := rest sorted_sane sorted_apart
  exact ⟨out_sane, out_apart⟩

end IdmapCore
