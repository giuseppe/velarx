-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: the first half of `sort_and_merge`, its insertion sort.  Each entry is
-- put at the end of the sorted list and moved down while the one before it has a greater
-- container id (the same loop as in `from_intervals`, Insertion.lean).  What is proved is only
-- that the sorted list has the entries of the input, each once (it is a permutation of it): the
-- order is what makes the merge join entries, and the claims do not depend on it.
--
-- Read before this file: Spec.lean, Lists.lean, Insertion.lean.
import IdmapCore.Spec
import IdmapCore.Insertion
import IdmapCore.Lists

open Aeneas Aeneas.Std Result velarx_idmap_core

namespace IdmapCore

/-- The inner loop of the insertion sort: the list is `before ++ spare :: after`; it moves the
spare place down while the entry before it has a greater container id than the new entry `i` of
`maps`.  The entries are the same, and the spare place is at `j`. -/
theorem sort_moves_the_new_entry_down (maps : Slice Map) (i : Usize)
    (sorted : alloc.vec.Vec Map) (j : Usize) (before after : List Map) (spare : Map)
    (inside : i.val < maps.val.length) (is_sorted : sorted.val = before ++ spare :: after)
    (is_j : j.val = before.length) :
    sort_and_merge_loop0_loop0 maps sorted i j ⦃ r =>
      ∃ before' after' spare', r.1.val = before' ++ spare' :: after' ∧
        before' ++ after' = before ++ after ∧ r.2.val = before'.length ⦄ := by
  unfold sort_and_merge_loop0_loop0
  apply loop.spec_decr_nat (fun q => q.2.val)
    (fun q => ∃ before' after' spare', q.1.val = before' ++ spare' :: after' ∧
        before' ++ after' = before ++ after ∧ q.2.val = before'.length)
  · rintro ⟨sorted1, j1⟩ ⟨before1, after1, spare1, is_sorted1, same, is_j1⟩
    simp only at is_sorted1 same is_j1 ⊢
    unfold sort_and_merge_loop0_loop0.body
    split
    · rename_i positive
      have positive : 0 < j1.val := by scalar_tac
      step as ⟨ i1, hi1 ⟩
      obtain ⟨init, last, is_before1⟩ : ∃ init last, before1 = init ++ [last] := by
        rcases List.eq_nil_or_concat before1 with empty | ⟨init, last, is_before1⟩
        · simp [empty] at is_j1; omega
        · exact ⟨init, last, by simpa using is_before1⟩
      have last_is_before : sorted1.val[i1.val]'(by simp [is_sorted1]; scalar_tac) = last :=
        the_element_before_the_spare init last spare1 after1 sorted1.val
          (by rw [is_sorted1, is_before1]) i1.val (by simp [is_before1] at is_j1; omega)
          (by simp [is_sorted1]; scalar_tac)
      step as ⟨ m, is_m ⟩
      have inside' : i.val < maps.length := inside
      step as ⟨ m1, is_m1 ⟩
      split
      · -- the entry before is greater: it is copied over the spare place
        step as ⟨ copy, is_copy ⟩
        step as ⟨ spare_place, put, is_spare, put_is ⟩
        have copy_is_last : copy = last := by rw [is_copy]; exact last_is_before
        have sorted_is : sorted1.val = (init ++ [last]) ++ spare1 :: after1 := by
          rw [is_sorted1, is_before1]
        refine ⟨⟨init, last :: after1, last, ?_, ?_, ?_⟩, by omega⟩
        · rw [put_is, copy_is_last, alloc.vec.Vec.set_val_eq, sorted_is]
          have j1_is : j1.val = (init ++ [last]).length := by rw [is_j1, is_before1]
          rw [j1_is, copy_the_last_one_over_the_spare]
          simp
        · rw [is_before1] at same
          simpa using same
        · simp [hi1, is_j1, is_before1]
      · -- it is not: this is the place
        exact (WP.spec_ok _).mpr ⟨before1, after1, spare1, is_sorted1, same, is_j1⟩
    · -- the new entry is at the front
      exact (WP.spec_ok _).mpr ⟨before1, after1, spare1, is_sorted1, same, is_j1⟩
  · exact ⟨before, after, spare, is_sorted, rfl, is_j⟩

/-- **The insertion sort of `sort_and_merge`** puts every entry of `maps` in the list, once: the
list it makes is a permutation of `maps`. -/
theorem sort_keeps_the_entries (maps : Slice Map) :
    sort_and_merge_loop0 maps (alloc.vec.Vec.new Map) 0#usize ⦃ sorted =>
      sorted.val.Perm maps.val ⦄ := by
  unfold sort_and_merge_loop0
  apply loop.spec_decr_nat (fun q => maps.length - q.2.val)
    (fun q => q.2.val ≤ maps.length ∧ q.1.val.Perm (maps.val.take q.2.val))
  · rintro ⟨sorted, i⟩ ⟨bound, perm⟩
    simp only at bound perm ⊢
    unfold sort_and_merge_loop0.body
    dsimp only [Slice.len]
    split
    · rename_i inside
      have inside : i.val < maps.length := by scalar_tac
      have inside_list : i.val < maps.val.length := inside
      have same_length : sorted.val.length = i.val := by
        have := perm.length_eq
        simp only [List.length_take] at this
        have : maps.val.length = maps.length := rfl
        omega
      step as ⟨ m, is_m ⟩
      have room : sorted.val.length < Usize.max := by scalar_tac
      step as ⟨ sorted1, is_sorted1 ⟩
      step as ⟨ j, is_j ⟩
      step with sort_moves_the_new_entry_down maps i sorted1 j sorted.val [] m inside_list
        (by simp [is_sorted1]) (by simp [is_j, is_sorted1]) as
        ⟨ sorted2, j1, front, back, spare, is_sorted2, same_list, is_j1 ⟩
      have front_back : front ++ back = sorted.val := by simpa using same_list
      step as ⟨ m1, is_m1 ⟩
      have j1_inside : j1.val < sorted2.length := by
        simp [is_sorted2, is_j1]
      step as ⟨ spare_place, put, is_spare, put_is ⟩
      step as ⟨ i3, is_i3 ⟩
      have written : (put m1).val = front ++ m1 :: back := by
        rw [put_is, alloc.vec.Vec.set_val_eq, is_sorted2, is_j1]
        exact write_over_the_spare front spare back m1
      have m1_is : m1 = maps.val[i.val] := by rw [is_m1]
      have take_is : maps.val.take (i.val + 1) = maps.val.take i.val ++ [maps.val[i.val]] :=
        take_one_more maps.val i.val inside_list
      refine ⟨by omega, ?_, by omega⟩
      rw [written, is_i3, take_is, ← m1_is]
      have moved : (front ++ m1 :: back).Perm (m1 :: (front ++ back)) := List.perm_middle
      rw [front_back] at moved
      exact moved.trans ((List.perm_append_singleton m1 sorted.val).symm.trans
        (perm.append_right [m1]))
    · rename_i outside
      have : i.val = maps.length := by scalar_tac
      refine (WP.spec_ok _).mpr ?_
      have same_length : maps.val.length = maps.length := rfl
      rw [this, ← same_length] at perm
      simpa using perm
  · refine ⟨by simp, ?_⟩
    simp [alloc.vec.Vec.new]

end IdmapCore
