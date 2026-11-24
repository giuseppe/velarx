-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: a valid mapping list is a function both ways: no container id has two
-- parent ids, and no parent id has two container ids.  `validate` checks that no two entries share
-- a container id or a parent id; this is why that is enough for the ids that the list maps.
--
-- Read before this file: Spec.lean (`Maps`, `Valid`, `Apart`, `FunctionBothWays`).
import IdmapCore.Spec

open Aeneas Aeneas.Std Result velarx_idmap_core

namespace IdmapCore

/-- Being apart does not depend on the order of the two entries. -/
theorem apart_comm (a b : Map) (apart : Apart a b) : Apart b a :=
  ⟨fun c both => apart.1 c ⟨both.2, both.1⟩, fun p both => apart.2 p ⟨both.2, both.1⟩⟩

/-- (Lean needs to be told that being apart is symmetric to use it on a list.) -/
instance : Std.Symm Apart := ⟨apart_comm⟩

/-- Two different entries of a valid list are apart. -/
theorem entries_of_a_valid_list_are_apart (m : List Map) (valid : Valid m) (e f : Map)
    (e_in : e ∈ m) (f_in : f ∈ m) (different : e ≠ f) : Apart e f :=
  valid.2.2.forall e_in f_in different

/-- The container id `c` is mapped by one entry only, so it has one parent id. -/
theorem valid_lists_give_one_parent_each (m : List Map) (valid : Valid m) : OneParentEach m := by
  rintro c p q ⟨e, e_in, c_in_e, is_p⟩ ⟨f, f_in, c_in_f, is_q⟩
  by_cases same : e = f
  · subst same
    rw [is_p, is_q]
  · exact absurd ⟨c_in_e, c_in_f⟩
      ((entries_of_a_valid_list_are_apart m valid e f e_in f_in same).1 c)

/-- The parent id `p` is the image of one entry only, and a container id of an entry is
determined by its parent id, so a parent id has one container id. -/
theorem valid_lists_give_one_container_each (m : List Map) (valid : Valid m) :
    OneContainerEach m := by
  rintro c d p ⟨e, e_in, c_in_e, is_p⟩ ⟨f, f_in, d_in_f, is_q⟩
  by_cases same : e = f
  · subst same
    unfold InContainers at c_in_e d_in_f
    omega
  · have p_in_e : InParents e p := by
      unfold InParents
      unfold InContainers at c_in_e
      omega
    have p_in_f : InParents f p := by
      unfold InParents
      unfold InContainers at d_in_f
      omega
    exact absurd ⟨p_in_e, p_in_f⟩
      ((entries_of_a_valid_list_are_apart m valid e f e_in f_in same).2 p)

/-- A valid list is a function both ways. -/
theorem valid_lists_are_functions_both_ways (m : List Map) (valid : Valid m) :
    FunctionBothWays m :=
  ⟨valid_lists_give_one_parent_each m valid, valid_lists_give_one_container_each m valid⟩

end IdmapCore
