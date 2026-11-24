-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: how many ids an ordered list of intervals has: the sum of the lengths of
-- its intervals (which is what `IdSet::size` adds up).  The ids are listed once each, because
-- no two intervals have an id in common.
--
-- Read before this file: Spec.lean (`Ordered`, `HasId`, `ExactlyIds`).
import IdmapCore.Spec

open Aeneas Aeneas.Std

namespace IdmapCore

/-- The sum of the lengths of the intervals. -/
def Total (runs : List (U64 × U64)) : Nat :=
  (runs.map (fun iv => iv.2.val - iv.1.val)).sum

/-- The ids of an interval, as a list. -/
def IdsOf (iv : U64 × U64) : List Nat :=
  List.range' iv.1.val (iv.2.val - iv.1.val)

/-- Two intervals, the first of which ends before the second begins, have no id in common. -/
theorem runs_that_do_not_touch_have_no_id_in_common (a b : U64 × U64)
    (before : a.2.val < b.1.val) : List.Disjoint (IdsOf a) (IdsOf b) := by
  intro id in_a in_b
  unfold IdsOf at in_a in_b
  rw [List.mem_range'_1] at in_a in_b
  omega

/-- The ids of the intervals of an ordered list are the ids listed one after the other, and they
are all different. -/
theorem ordered_runs_list_their_ids_once (runs : List (U64 × U64)) (ordered : Ordered runs) :
    (runs.flatMap IdsOf).Nodup := by
  rw [List.nodup_flatMap]
  refine ⟨fun iv _ => List.nodup_range', ?_⟩
  exact ordered.2.imp (fun before => runs_that_do_not_touch_have_no_id_in_common _ _ before)

/-- **An ordered list of intervals has as many ids as the sum of its lengths**: exactly
`Total runs` ids are in some interval. -/
theorem ordered_runs_have_total_ids (runs : List (U64 × U64)) (ordered : Ordered runs) :
    ExactlyIds (HasId runs) (Total runs) := by
  refine ⟨runs.flatMap IdsOf, ordered_runs_list_their_ids_once runs ordered, ?_, ?_⟩
  · intro id
    simp only [List.mem_flatMap, HasId, IdsOf, List.mem_range'_1, InRun]
    constructor
    · rintro ⟨iv, iv_in, in_run⟩
      exact ⟨iv, iv_in, by omega, by omega⟩
    · rintro ⟨iv, iv_in, below, above⟩
      exact ⟨iv, iv_in, by omega, by omega⟩
  · unfold Total
    rw [List.length_flatMap]
    simp [IdsOf]

end IdmapCore
