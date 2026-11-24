-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: `IdSet::of_maps`, which `of_parent_ids` and `of_container_ids` call: the
-- set of the parent ids (or of the container ids) of the entries of a mapping.  Its first loop
-- writes one interval `[start, start + size)` for each entry; then `from_intervals` puts them in
-- order and joins them.
--
-- Read before this file: Spec.lean, FromIntervals.lean (what `from_intervals` gives).
import IdmapCore.FromIntervals

open Aeneas Aeneas.Std Result velarx_idmap_core

namespace IdmapCore

/-- The ids of the entry `e`: its parent ids when `parent` is true, else its container ids. -/
def EntryHasId (parent : Bool) (e : Map) (id : Nat) : Prop :=
  if parent then InParents e id else InContainers e id

/-- The loop of `of_maps`: one interval for each entry, `[start, start + size)` where `start` is
the parent id or the container id, so the intervals have exactly the ids of the entries. -/
theorem of_maps_writes_one_interval_for_each_entry (maps : Slice Map) (parent : Bool) :
    IdSet.of_maps_loop maps parent (alloc.vec.Vec.new (U64 × U64)) 0#usize ⦃ list =>
      (∀ id, HasId list.val id ↔ ∃ e ∈ maps.val, EntryHasId parent e id) ∧
      list.val.length ≤ maps.val.length ⦄ := by
  unfold IdSet.of_maps_loop
  apply loop.spec_decr_nat (fun q => maps.length - q.2.val)
    (fun q => q.2.val ≤ maps.length ∧ q.1.val.length ≤ q.2.val ∧
      ∀ id, HasId q.1.val id ↔ ∃ e ∈ maps.val.take q.2.val, EntryHasId parent e id)
  · rintro ⟨list, i⟩ ⟨bound, few, covers⟩
    simp only at bound few covers ⊢
    unfold IdSet.of_maps_loop.body
    dsimp only [Slice.len]
    split
    · rename_i inside
      have inside : i.val < maps.length := by scalar_tac
      have room : list.val.length < Usize.max := by
        have : maps.val.length ≤ Usize.max := maps.property
        have same : maps.length = maps.val.length := rfl
        omega
      have hs := core.convert.num.FromU64U32.from_val_eq maps.val[i.val].size
      have hp := core.convert.num.FromU64U32.from_val_eq maps.val[i.val].parent_id
      have hc := core.convert.num.FromU64U32.from_val_eq maps.val[i.val].container_id
      refine WP.spec_bind (Pₘ := fun start => start.val =
        (if parent then maps.val[i.val].parent_id.val else maps.val[i.val].container_id.val)) ?_ ?_
      · split
        · rename_i is_parent
          step as ⟨ m, hm ⟩
          simp [hm, hp]
        · rename_i not_parent
          step as ⟨ m, hm ⟩
          simp [hm, hc]
      · intro start is_start
        step as ⟨ m, hm ⟩
        simp only [Std.lift, Std.bind_ok]
        have start_small : start.val ≤ U32.max := by
          rw [is_start]
          split <;> scalar_tac
        have size_small := (maps.val[i.val].size).hBounds
        step as ⟨ i3, is_i3 ⟩
        have size_is : (core.convert.num.FromU64U32.from m.size).val =
            maps.val[i.val].size.val := by rw [hm]; exact hs
        step as ⟨ list1, is_list1 ⟩
        step as ⟨ i4, is_i4 ⟩
        refine ⟨by omega, by simp [is_list1]; omega, fun id => ?_, by omega⟩
        rw [is_i4, is_list1, take_one_more maps.val i.val inside, has_id_after_adding, covers id]
        simp only [List.mem_append, List.mem_singleton]
        constructor
        · rintro (⟨e, e_in, has⟩ | in_run)
          · exact ⟨e, Or.inl e_in, has⟩
          · refine ⟨maps.val[i.val], Or.inr rfl, ?_⟩
            unfold EntryHasId InRun at *
            cases parent <;> simp [InParents, InContainers] at in_run is_start ⊢ <;> omega
        · rintro ⟨e, e_in | rfl, has⟩
          · exact Or.inl ⟨e, e_in, has⟩
          · refine Or.inr ?_
            unfold EntryHasId InRun at *
            cases parent <;> simp [InParents, InContainers] at has is_start ⊢ <;> omega
    · rename_i outside
      have : i.val = maps.length := by scalar_tac
      have same_length : maps.length = maps.val.length := rfl
      refine (WP.spec_ok _).mpr ⟨fun id => ?_, by omega⟩
      rw [covers id, this]
      simp
  · exact ⟨by simp, by simp [alloc.vec.Vec.new], fun id => by simp [alloc.vec.Vec.new, HasId]⟩

/-- **`of_maps`**: it returns an ordered set of the parent ids (or of the container ids) of the
entries of `maps`, with no more intervals than there are entries. -/
theorem of_maps_has_the_ids_of_the_entries (maps : Slice Map) (parent : Bool) :
    IdSet.of_maps maps parent ⦃ s =>
      Ordered s.intervals.val ∧
      (∀ id, HasId s.intervals.val id ↔ ∃ e ∈ maps.val, EntryHasId parent e id) ∧
      s.intervals.val.length ≤ maps.val.length ⦄ := by
  unfold IdSet.of_maps
  step with of_maps_writes_one_interval_for_each_entry maps parent as ⟨ list, covers, few ⟩
  step with from_intervals_is_the_union_with_few_intervals as ⟨ s, ordered, has_ids, few_s ⟩
  refine ⟨ordered, fun id => ?_, ?_⟩
  · rw [has_ids id]
    simpa [alloc.vec.Vec.deref] using covers id
  · simp [alloc.vec.Vec.deref] at few_s
    omega

/-- **`of_parent_ids`**: an ordered set with exactly the parent ids of the entries, and no more
intervals than there are entries. -/
theorem of_parent_ids_has_the_parent_ids_in_few_intervals (maps : Slice Map) :
    IdSet.of_parent_ids maps ⦃ s =>
      Ordered s.intervals.val ∧
      (∀ id, HasId s.intervals.val id ↔ ∃ e ∈ maps.val, InParents e id) ∧
      s.intervals.val.length ≤ maps.val.length ⦄ := by
  unfold IdSet.of_parent_ids
  step with of_maps_has_the_ids_of_the_entries maps true as ⟨ s, ordered, has_ids, few ⟩
  exact ⟨ordered, fun id => by simpa [EntryHasId] using has_ids id, few⟩

/-- **`of_parent_ids`**: an ordered set with exactly the parent ids of the entries. -/
theorem of_parent_ids_has_the_parent_ids (maps : Slice Map) :
    IdSet.of_parent_ids maps ⦃ s =>
      Ordered s.intervals.val ∧
      ∀ id, HasId s.intervals.val id ↔ ∃ e ∈ maps.val, InParents e id ⦄ :=
  WP.spec_mono (of_parent_ids_has_the_parent_ids_in_few_intervals maps)
    (fun _ h => ⟨h.1, h.2.1⟩)

/-- **`of_container_ids`**: an ordered set with exactly the container ids of the entries, and no
more intervals than there are entries. -/
theorem of_container_ids_has_the_container_ids_in_few_intervals (maps : Slice Map) :
    IdSet.of_container_ids maps ⦃ s =>
      Ordered s.intervals.val ∧
      (∀ id, HasId s.intervals.val id ↔ ∃ e ∈ maps.val, InContainers e id) ∧
      s.intervals.val.length ≤ maps.val.length ⦄ := by
  unfold IdSet.of_container_ids
  step with of_maps_has_the_ids_of_the_entries maps false as ⟨ s, ordered, has_ids, few ⟩
  exact ⟨ordered, fun id => by simpa [EntryHasId] using has_ids id, few⟩

/-- **`of_container_ids`**: an ordered set with exactly the container ids of the entries. -/
theorem of_container_ids_has_the_container_ids (maps : Slice Map) :
    IdSet.of_container_ids maps ⦃ s =>
      Ordered s.intervals.val ∧
      ∀ id, HasId s.intervals.val id ↔ ∃ e ∈ maps.val, InContainers e id ⦄ :=
  WP.spec_mono (of_container_ids_has_the_container_ids_in_few_intervals maps)
    (fun _ h => ⟨h.1, h.2.1⟩)

end IdmapCore
