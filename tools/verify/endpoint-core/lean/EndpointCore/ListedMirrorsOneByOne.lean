-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: how the list of the mirrors that are listed (`ListedAmong` of Spec.lean)
-- grows when one more mirror is looked at after the others: the mirror is added when it is listed
-- and not otherwise; and a request that is a push lists none.
-- Why it is needed: `endpoints` goes over the mirrors of the block one by one; this is the step of
-- its loop, said without the code.
-- Read before this file: Spec.lean.
-- Notation: `ms ++ [m]` is the list `ms` with `m` added at the end.
import EndpointCore.Spec

open Aeneas Aeneas.Std Result velarx_endpoint_core

namespace EndpointCore

open Classical

/-- A mirror that is listed is added, with its address, after those listed before it. -/
theorem a_listed_mirror_is_added (blocks : List Block) (block : Block) (ask : Ask)
    (ref registry : Bytes) (ms : List Mirror) (m : Mirror)
    (listed : Listed blocks block ask ref registry m) :
    ListedAmong blocks block ask ref registry (ms ++ [m]) =
      ListedAmong blocks block ask ref registry ms ++ [(m, MirrorAddress block m ref)] := by
  simp [ListedAmong, List.filter_append, listed]

/-- A mirror that is not listed changes nothing. -/
theorem a_mirror_that_is_not_listed_changes_nothing (blocks : List Block) (block : Block)
    (ask : Ask) (ref registry : Bytes) (ms : List Mirror) (m : Mirror)
    (not_listed : ¬ Listed blocks block ask ref registry m) :
    ListedAmong blocks block ask ref registry (ms ++ [m]) =
      ListedAmong blocks block ask ref registry ms := by
  simp [ListedAmong, List.filter_append, not_listed]

/-- A push lists no mirror. -/
theorem a_push_lists_no_mirror (blocks : List Block) (block : Block) (ask : Ask)
    (ref registry : Bytes) (ms : List Mirror) (push : ask.push = true) :
    ListedAmong blocks block ask ref registry ms = [] := by
  unfold ListedAmong
  have : ms.filter (fun m => decide (Listed blocks block ask ref registry m)) = [] := by
    rw [List.filter_eq_nil_iff]
    intro m _
    have : ¬ Listed blocks block ask ref registry m := fun ⟨⟨no_push, _⟩, _⟩ => by
      rw [push] at no_push
      cases no_push
    simpa using this
  rw [this]
  rfl

/-- There are no more listed mirrors than mirrors. -/
theorem listed_mirrors_are_not_more_than_mirrors (blocks : List Block) (block : Block) (ask : Ask)
    (ref registry : Bytes) (ms : List Mirror) :
    (ListedAmong blocks block ask ref registry ms).length ≤ ms.length := by
  unfold ListedAmong
  simp only [List.length_map]
  exact List.length_filter_le _ _

end EndpointCore
