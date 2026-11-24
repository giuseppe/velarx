-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: how `Maps` (which container id goes to which parent id) behaves when a
-- list of entries is made of two lists, is reordered, or has two entries that continue each other
-- replaced by one: nothing changes in what is mapped.  `sort_and_merge`, `split_on` and `fill`
-- are proved with these.
--
-- Read before this file: Spec.lean (`Maps`, `InContainers`, `InParents`).
import IdmapCore.Spec

open Aeneas Aeneas.Std velarx_idmap_core

namespace IdmapCore

/-- A list of two lists maps what one of the two maps. -/
theorem maps_of_append (a b : List Map) (c p : Nat) :
    Maps (a ++ b) c p ↔ Maps a c p ∨ Maps b c p := by
  simp only [Maps, List.mem_append]
  constructor
  · rintro ⟨e, in_a | in_b, rest⟩
    · exact Or.inl ⟨e, in_a, rest⟩
    · exact Or.inr ⟨e, in_b, rest⟩
  · rintro (⟨e, in_a, rest⟩ | ⟨e, in_b, rest⟩)
    · exact ⟨e, Or.inl in_a, rest⟩
    · exact ⟨e, Or.inr in_b, rest⟩

/-- A list of one entry maps what the entry maps. -/
theorem maps_of_one_entry (e : Map) (c p : Nat) :
    Maps [e] c p ↔ InContainers e c ∧ p = e.parent_id.val + (c - e.container_id.val) := by
  simp [Maps]

/-- The empty list maps nothing. -/
theorem maps_of_nothing (c p : Nat) : ¬ Maps [] c p := by
  simp [Maps]

/-- Putting the entries in another order does not change what is mapped. -/
theorem maps_of_a_reordering (a b : List Map) (same : a.Perm b) (c p : Nat) :
    Maps a c p ↔ Maps b c p := by
  simp only [Maps]
  constructor
  · rintro ⟨e, e_in, rest⟩
    exact ⟨e, same.subset e_in, rest⟩
  · rintro ⟨e, e_in, rest⟩
    exact ⟨e, same.symm.subset e_in, rest⟩

/-- Two entries where the second goes on where the first ends, in the container ids and in the
parent ids, are one entry of the sizes added: the ids of the one are those of the two. -/
def Continues (first second joined : Map) : Prop :=
  first.container_id.val + first.size.val = second.container_id.val ∧
  first.parent_id.val + first.size.val = second.parent_id.val ∧
  joined.container_id.val = first.container_id.val ∧
  joined.parent_id.val = first.parent_id.val ∧
  joined.size.val = first.size.val + second.size.val

/-- An entry that continues another maps what the two map. -/
theorem maps_of_joined_entries (first second joined : Map)
    (continues : Continues first second joined) (c p : Nat) :
    Maps [joined] c p ↔ Maps [first] c p ∨ Maps [second] c p := by
  obtain ⟨c_end, p_end, same_c, same_p, size⟩ := continues
  simp only [maps_of_one_entry, InContainers, same_c, same_p]
  omega

/-- The container ids of an entry that continues another are those of the two. -/
theorem containers_of_joined_entries (first second joined : Map)
    (continues : Continues first second joined) (c : Nat) :
    InContainers joined c ↔ InContainers first c ∨ InContainers second c := by
  obtain ⟨c_end, p_end, same_c, same_p, size⟩ := continues
  simp only [InContainers, same_c]
  omega

/-- The parent ids of an entry that continues another are those of the two. -/
theorem parents_of_joined_entries (first second joined : Map)
    (continues : Continues first second joined) (p : Nat) :
    InParents joined p ↔ InParents first p ∨ InParents second p := by
  obtain ⟨c_end, p_end, same_c, same_p, size⟩ := continues
  simp only [InParents, same_p]
  omega

end IdmapCore
