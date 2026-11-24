-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: `IdSet::union`: it copies the intervals of the two sets into one list and
-- gives it to `from_intervals`, which puts them in order and joins them.
--
-- Read before this file: Spec.lean, FromIntervals.lean (what `from_intervals` gives).
import IdmapCore.FromIntervals
import IdmapCore.HasIdFacts

open Aeneas Aeneas.Std Result velarx_idmap_core

namespace IdmapCore

/-- The first copying loop of `union`: from the interval `i` on, it appends the intervals of
`self` to `list`. -/
theorem union_copies_the_intervals_of_self (self : IdSet) (list : alloc.vec.Vec (U64 × U64))
    (i : Usize) (inside : i.val ≤ self.intervals.val.length)
    (fits : list.val.length + (self.intervals.val.length - i.val) ≤ Usize.max) :
    IdSet.union_loop0 self list i ⦃ r =>
      r.val = list.val ++ self.intervals.val.drop i.val ⦄ := by
  unfold IdSet.union_loop0
  apply loop.spec_decr_nat (fun q => self.intervals.val.length - q.2.val)
    (fun q => q.2.val ≤ self.intervals.val.length ∧
      q.1.val.length + (self.intervals.val.length - q.2.val) ≤ Usize.max ∧
      q.1.val ++ self.intervals.val.drop q.2.val = list.val ++ self.intervals.val.drop i.val)
  · rintro ⟨list1, j⟩ ⟨bound, room, same⟩
    simp only at bound room same ⊢
    unfold IdSet.union_loop0.body
    dsimp only
    split
    · rename_i more
      have same_length : self.intervals.length = self.intervals.val.length := rfl
      have more : j.val < self.intervals.val.length := by
        have : j.val < self.intervals.length := by scalar_tac
        omega
      step as ⟨ p, is_p ⟩
      have room_to_push : list1.val.length < Usize.max := by omega
      step as ⟨ list2, is_list2 ⟩
      step as ⟨ j1, is_j1 ⟩
      have longer : list2.val.length = list1.val.length + 1 := by simp [is_list2]
      refine ⟨by omega, by omega, ?_, by omega⟩
      rw [is_list2, is_j1, ← same, List.drop_eq_getElem_cons more, is_p]
      simp
    · rename_i done
      have : j.val = self.intervals.val.length := by
        have same_length : self.intervals.length = self.intervals.val.length := rfl
        scalar_tac
      refine (WP.spec_ok _).mpr ?_
      rw [← same, this]
      simp
  · exact ⟨inside, fits, rfl⟩

/-- The second copying loop of `union`: the same for `other`. -/
theorem union_copies_the_intervals_of_other (other : IdSet) (list : alloc.vec.Vec (U64 × U64))
    (i : Usize) (inside : i.val ≤ other.intervals.val.length)
    (fits : list.val.length + (other.intervals.val.length - i.val) ≤ Usize.max) :
    IdSet.union_loop1 other list i ⦃ r =>
      r.val = list.val ++ other.intervals.val.drop i.val ⦄ := by
  unfold IdSet.union_loop1
  apply loop.spec_decr_nat (fun q => other.intervals.val.length - q.2.val)
    (fun q => q.2.val ≤ other.intervals.val.length ∧
      q.1.val.length + (other.intervals.val.length - q.2.val) ≤ Usize.max ∧
      q.1.val ++ other.intervals.val.drop q.2.val = list.val ++ other.intervals.val.drop i.val)
  · rintro ⟨list1, j⟩ ⟨bound, room, same⟩
    simp only at bound room same ⊢
    unfold IdSet.union_loop1.body
    dsimp only
    split
    · rename_i more
      have same_length : other.intervals.length = other.intervals.val.length := rfl
      have more : j.val < other.intervals.val.length := by
        have : j.val < other.intervals.length := by scalar_tac
        omega
      step as ⟨ p, is_p ⟩
      have room_to_push : list1.val.length < Usize.max := by omega
      step as ⟨ list2, is_list2 ⟩
      step as ⟨ j1, is_j1 ⟩
      have longer : list2.val.length = list1.val.length + 1 := by simp [is_list2]
      refine ⟨by omega, by omega, ?_, by omega⟩
      rw [is_list2, is_j1, ← same, List.drop_eq_getElem_cons more, is_p]
      simp
    · rename_i done
      have : j.val = other.intervals.val.length := by
        have same_length : other.intervals.length = other.intervals.val.length := rfl
        scalar_tac
      refine (WP.spec_ok _).mpr ?_
      rw [← same, this]
      simp
  · exact ⟨inside, fits, rfl⟩

/-- **`union`**: for any two sets with fewer than 2^64 intervals together (more cannot be held by
a computer), it returns an ordered set that has exactly the ids that one of them has. -/
theorem union_has_the_ids_of_both (self other : IdSet)
    (fits : self.intervals.val.length + other.intervals.val.length ≤ Usize.max) :
    IdSet.union self other ⦃ s =>
      Ordered s.intervals.val ∧ ∀ id, HasId s.intervals.val id ↔
        (HasId self.intervals.val id ∨ HasId other.intervals.val id) ⦄ := by
  unfold IdSet.union
  step with union_copies_the_intervals_of_self self (alloc.vec.Vec.new (U64 × U64)) 0#usize
    (by simp) (by simp [alloc.vec.Vec.new])
    as ⟨ list, is_list ⟩
  step with union_copies_the_intervals_of_other other list 0#usize (by simp)
    (by rw [is_list]; simp; omega) as ⟨ list1, is_list1 ⟩
  step with from_intervals_is_the_union as ⟨ s, ordered, has_ids ⟩
  refine ⟨ordered, fun id => ?_⟩
  rw [has_ids id]
  simp [alloc.vec.Vec.deref, is_list1, is_list, has_id_of_append, alloc.vec.Vec.new]

end IdmapCore
