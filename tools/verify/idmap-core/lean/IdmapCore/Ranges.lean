-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: when two entries of a mapping share a container id or a parent id, as the
-- sums and comparisons of `validate` say it: `a` and `b` (neither empty) share an id exactly when
-- each begins before the other ends.
--
-- Read before this file: Spec.lean (`InContainers`, `InParents`, `Apart`).
import IdmapCore.Spec

open Aeneas Aeneas.Std Result velarx_idmap_core

namespace IdmapCore

/-- Two non-empty runs of ids, `[x, x + s)` and `[y, y + t)`, share an id exactly when each begins
before the other ends. -/
theorem runs_share_an_id_iff (x s y t : Nat) (a_has_ids : 0 < s) (b_has_ids : 0 < t) :
    (∃ id, (x ≤ id ∧ id < x + s) ∧ (y ≤ id ∧ id < y + t)) ↔ (x < y + t ∧ y < x + s) := by
  constructor
  · rintro ⟨id, ⟨x_le, lt_x_end⟩, ⟨y_le, lt_y_end⟩⟩
    omega
  · intro overlap
    exact ⟨max x y, ⟨by omega, by omega⟩, ⟨by omega, by omega⟩⟩

/-- Two entries that are not empty are apart (no container id and no parent id in common) exactly
when neither the container ids nor the parent ids overlap, as `validate` compares them: an overlap
is that each run begins before the other ends. -/
theorem apart_iff_no_overlap (b a : Map) (a_has_ids : 0 < a.size.val) (b_has_ids : 0 < b.size.val) :
    Apart b a ↔
      ¬ (a.container_id.val < b.container_id.val + b.size.val ∧
         b.container_id.val < a.container_id.val + a.size.val) ∧
      ¬ (a.parent_id.val < b.parent_id.val + b.size.val ∧
         b.parent_id.val < a.parent_id.val + a.size.val) := by
  have containers := runs_share_an_id_iff a.container_id.val a.size.val b.container_id.val
    b.size.val a_has_ids b_has_ids
  have parents := runs_share_an_id_iff a.parent_id.val a.size.val b.parent_id.val
    b.size.val a_has_ids b_has_ids
  unfold Apart InContainers InParents
  constructor
  · rintro ⟨no_container, no_parent⟩
    refine ⟨fun overlap => ?_, fun overlap => ?_⟩
    · obtain ⟨id, in_a, in_b⟩ := containers.mpr overlap
      exact no_container id ⟨in_b, in_a⟩
    · obtain ⟨id, in_a, in_b⟩ := parents.mpr overlap
      exact no_parent id ⟨in_b, in_a⟩
  · rintro ⟨no_container, no_parent⟩
    refine ⟨fun id ⟨in_b, in_a⟩ => no_container (containers.mp ⟨id, in_a, in_b⟩),
      fun id ⟨in_b, in_a⟩ => no_parent (parents.mp ⟨id, in_a, in_b⟩)⟩

end IdmapCore
