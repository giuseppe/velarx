-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: how "some interval of the list has the id" (`HasId`) behaves when a list
-- is made of two lists, or of one more interval: it is "the first has it, or the second has it".
-- The loops of the crate build lists of intervals one interval at a time, so each step of their
-- proofs uses these.
--
-- Read before this file: Spec.lean (`InRun`, `HasId`).  Notation: `l ++ m` is `l` then `m`;
-- `x :: l` is `x` then `l`; `∃ x ∈ l, P x` is "some element of `l` satisfies `P`".
import IdmapCore.Spec

open Aeneas Aeneas.Std

namespace IdmapCore

/-- The empty list has no id. -/
theorem no_id_in_the_empty_list (id : Nat) : ¬ HasId [] id := by
  simp [HasId]

/-- A list of two lists has an id when one of the two has it. -/
theorem has_id_of_append (first second : List (U64 × U64)) (id : Nat) :
    HasId (first ++ second) id ↔ HasId first id ∨ HasId second id := by
  simp only [HasId, List.mem_append]
  constructor
  · rintro ⟨iv, in_first | in_second, in_run⟩
    · exact Or.inl ⟨iv, in_first, in_run⟩
    · exact Or.inr ⟨iv, in_second, in_run⟩
  · rintro (⟨iv, in_first, in_run⟩ | ⟨iv, in_second, in_run⟩)
    · exact ⟨iv, Or.inl in_first, in_run⟩
    · exact ⟨iv, Or.inr in_second, in_run⟩

/-- A list of one interval has the ids of the interval. -/
theorem has_id_of_one_interval (iv : U64 × U64) (id : Nat) :
    HasId [iv] id ↔ InRun iv id := by
  simp [HasId]

/-- A list with one more interval at the end has the ids of the list and those of the interval. -/
theorem has_id_after_adding (runs : List (U64 × U64)) (iv : U64 × U64) (id : Nat) :
    HasId (runs ++ [iv]) id ↔ HasId runs id ∨ InRun iv id := by
  rw [has_id_of_append, has_id_of_one_interval]

end IdmapCore
