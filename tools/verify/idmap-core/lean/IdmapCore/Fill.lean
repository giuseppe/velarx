-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: `fill` (podman `fillIDMap`): it gives the container ids that the mapping
-- leaves unmapped the parent ids of `available`, in order, and sorts and merges the result.  The
-- container ids to fill are all those below the limit that no entry of the mapping has; they are
-- paired with the ids of `available` by `zip`.
--
-- Read before this file: Spec.lean, Zip.lean, SortAndMerge.lean, AutoMap.lean.
import IdmapCore.Zip
import IdmapCore.SortAndMerge
import IdmapCore.IdSetSubtract
import IdmapCore.OfMaps
import IdmapCore.Limits

open Aeneas Aeneas.Std Result velarx_idmap_core

namespace IdmapCore

/-- The first loop of `fill`: it copies the entries of the mapping. -/
theorem fill_copies_the_mapping (idmap : Slice Map) (out : alloc.vec.Vec Map) (i : Usize)
    (bound : i.val ≤ idmap.val.length)
    (room : out.val.length + idmap.val.length - i.val ≤ Usize.max) :
    fill_loop0 idmap out i ⦃ r => r.val = out.val ++ idmap.val.drop i.val ⦄ := by
  unfold fill_loop0
  apply loop.spec_decr_nat (fun q => idmap.length - q.2.val)
    (fun q => q.2.val ≤ idmap.val.length ∧ q.1.val ++ idmap.val.drop q.2.val =
      out.val ++ idmap.val.drop i.val ∧ q.1.val.length + idmap.val.length - q.2.val ≤ Usize.max)
  · rintro ⟨out1, j⟩ ⟨bound, same, room⟩
    simp only at bound same room ⊢
    unfold fill_loop0.body
    dsimp only [Slice.len]
    have same_length : idmap.length = idmap.val.length := rfl
    split
    · rename_i inside
      have inside : j.val < idmap.val.length := by scalar_tac
      step as ⟨ m, is_m ⟩
      have room_push : out1.val.length < Usize.max := by omega
      step as ⟨ out2, is_out2 ⟩
      step as ⟨ j1, is_j1 ⟩
      refine ⟨by omega, ?_, by simp [is_out2]; omega, by omega⟩
      rw [is_out2, is_j1, List.append_assoc]
      have : idmap.val.drop j.val = m :: idmap.val.drop (j.val + 1) := by
        rw [List.drop_eq_getElem_cons inside, is_m]
      rw [this] at same
      simpa using same
    · rename_i outside
      have : j.val = idmap.val.length := by scalar_tac
      refine (WP.spec_ok _).mpr ?_
      rw [this] at same
      simpa using same
  · exact ⟨bound, rfl, by simpa using room⟩

/-- The second loop of `fill`: it adds the entries made by `zip` after those of the mapping. -/
theorem fill_adds_the_new_entries (out added : alloc.vec.Vec Map) (i : Usize)
    (bound : i.val ≤ added.val.length)
    (room : out.val.length + added.val.length - i.val ≤ Usize.max) :
    fill_loop1 out added i ⦃ r => r.val = out.val ++ added.val.drop i.val ⦄ := by
  unfold fill_loop1
  apply loop.spec_decr_nat (fun q => added.length - q.2.val)
    (fun q => q.2.val ≤ added.val.length ∧ q.1.val ++ added.val.drop q.2.val =
      out.val ++ added.val.drop i.val ∧ q.1.val.length + added.val.length - q.2.val ≤ Usize.max)
  · rintro ⟨out1, j⟩ ⟨bound, same, room⟩
    simp only at bound same room ⊢
    unfold fill_loop1.body
    dsimp only
    have same_length : added.length = added.val.length := rfl
    split
    · rename_i inside
      have inside : j.val < added.val.length := by
        have := (UScalar.lt_equiv j added.len).mp inside
        have : added.len.val = added.val.length := rfl
        omega
      step as ⟨ m, is_m ⟩
      have room_push : out1.val.length < Usize.max := by omega
      step as ⟨ out2, is_out2 ⟩
      step as ⟨ j1, is_j1 ⟩
      refine ⟨by omega, ?_, by simp [is_out2]; omega, by omega⟩
      rw [is_out2, is_j1, List.append_assoc]
      have : added.val.drop j.val = m :: added.val.drop (j.val + 1) := by
        rw [List.drop_eq_getElem_cons inside, is_m]
      rw [this] at same
      simpa using same
    · rename_i outside
      have : j.val = added.val.length := by
        have := (UScalar.lt_equiv j added.len).not.mp outside
        have : added.len.val = added.val.length := rfl
        omega
      refine (WP.spec_ok _).mpr ?_
      rw [this] at same
      simpa using same
  · exact ⟨bound, rfl, by simpa using room⟩

/-- **`fill`.**  What the answer maps: everything `idmap` maps; and what `zip` pairs of the ids of
`available` with the container ids that `idmap` leaves unmapped (below the limit), and nothing
else; and, when `available` has at least as many ids (below the limit) as there are container
ids to fill, all of these container ids. -/
theorem fill_adds_the_free_container_ids (idmap : Slice Map) (available : IdSet)
    (available_ordered : Ordered available.intervals.val) (few : idmap.val.length ≤ ExtentLimit)
    (wide : 4294967636 ≤ Usize.max) :
    fill idmap available ⦃ out =>
      (∀ c p, Maps idmap.val c p → Maps out.val c p) ∧
      (∀ c p, Maps out.val c p → Maps idmap.val c p ∨
        (c < IdLimit ∧ (∀ e ∈ idmap.val, ¬ InContainers e c) ∧
          HasId available.intervals.val p ∧ p < IdLimit)) ∧
      ((∀ k m, ExactlyIds (fun p => HasId available.intervals.val p ∧ p < IdLimit) k →
          ExactlyIds (fun c => c < IdLimit ∧ ∀ e ∈ idmap.val, ¬ InContainers e c) m → m ≤ k) →
        ∀ c, c < IdLimit → (∀ e ∈ idmap.val, ¬ InContainers e c) → ∃ p, Maps out.val c p) ⦄ := by
  unfold fill
  rw [id_limit_is_the_largest_u32]
  simp only [Std.lift, Std.bind_ok]
  unfold ExtentLimit at few
  step with from_intervals_is_the_union_with_few_intervals as ⟨ everything, everything_ordered,
    everything_ids, everything_few ⟩
  have everything_ids' : ∀ id, HasId everything.intervals.val id ↔ id < IdLimit := by
    intro id
    rw [everything_ids id]
    simp [HasId, InRun, IdLimit]
  have everything_few' : everything.intervals.val.length ≤ 1 := by simpa using everything_few
  step with of_container_ids_has_the_container_ids_in_few_intervals idmap as ⟨ taken,
    taken_ordered, taken_ids, taken_few ⟩
  step with subtract_has_the_ids_of_the_first_not_in_the_second everything taken
    everything_ordered taken_ordered (by nlinarith [wide]) as ⟨ free, free_ordered, free_ids,
    free_few ⟩
  have free_ids' : ∀ id, HasId free.intervals.val id ↔
      id < IdLimit ∧ ∀ e ∈ idmap.val, ¬ InContainers e id := by
    intro id
    rw [free_ids id, everything_ids' id, taken_ids id]
    simp only [not_exists, not_and]
  step with fill_copies_the_mapping idmap (alloc.vec.Vec.new Map) 0#usize (by simp)
    (by simp [alloc.vec.Vec.new]) as ⟨ copied, is_copied ⟩
  step with zip_pairs_the_ids_in_order available free available_ordered free_ordered as ⟨ added,
    added_sane, added_apart, added_sound, added_covers, added_few ⟩
  have copied_is : copied.val = idmap.val := by simpa [alloc.vec.Vec.new] using is_copied
  step with fill_adds_the_new_entries copied added 0#usize (by simp) (by
    have zero : (0#usize).val = 0 := rfl
    have := congrArg List.length copied_is
    unfold IdLimit at added_few
    omega) as ⟨ filled, is_filled ⟩
  step with sort_and_merge_keeps_the_pairs as ⟨ merged, same_pairs, _ ⟩
  have filled_is : (alloc.vec.Vec.deref filled).val = idmap.val ++ added.val := by
    simpa [alloc.vec.Vec.deref, copied_is] using is_filled
  have pairs : ∀ c p, Maps merged.val c p ↔ Maps idmap.val c p ∨ Maps added.val c p := by
    intro c p
    rw [same_pairs c p, filled_is, maps_of_append]
  refine ⟨fun c p is_map => (pairs c p).mpr (Or.inl is_map), fun c p is_map => ?_,
    fun fewer c below none_has => ?_⟩
  · rcases (pairs c p).mp is_map with in_idmap | in_added
    · exact Or.inl in_idmap
    · have sound := added_sound c p in_added
      exact Or.inr ⟨sound.2.2.2, ((free_ids' c).mp sound.2.2.1).2, sound.1, sound.2.1⟩
  · obtain ⟨p, is_map⟩ := added_covers (fun k m is_k is_m => fewer k m is_k
      (exactly_ids_are_the_same_for_equivalent_properties _ _ _
        (fun id => ⟨fun h => ((free_ids' id).mp h.1), fun h => ⟨(free_ids' id).mpr h, h.1⟩⟩)
        is_m)) c ((free_ids' c).mpr ⟨below, none_has⟩) below
    exact ⟨p, (pairs c p).mpr (Or.inr is_map)⟩

end IdmapCore
