-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: the proofs of the claims about the lookup of the content of a digest
-- (Spec.lean, the last part): they follow the definitions of `Store.find` and `lookup`.
--
-- Why it is needed: nothing more than to keep the proofs out of Spec.lean.
--
-- Read before this file: Model.lean (`Store.find`, `lookup`) and Spec.lean.
-- Notation: `Option.or a b` is `a` when it is `some _`, otherwise `b`.
import InlineModel.Spec

namespace InlineModel

/-- A store with the object answers with it. -/
theorem find_of_object (s : Store) (d : Digest) (has : d ∈ s.objects) :
    s.find d = some (.object d) := by
  simp [Store.find, has]

/-- `lookup` of a store and the rest: the store if it has an answer, the rest otherwise. -/
theorem lookup_first_store (s : Store) (ss : List Store) (d : Digest) :
    (s.find d ≠ none → lookup (s :: ss) d = s.find d) ∧
    (s.find d = none → lookup (s :: ss) d = lookup ss d) := by
  constructor
  · intro found
    cases h : s.find d with
    | none => exact absurd h found
    | some a => simp [lookup, h]
  · intro none
    simp [lookup, none]

/-- With no object and a row for the digest, the answer is the first such row. -/
theorem find_of_row (s : Store) (d : Digest) (absent : d ∉ s.objects)
    (r : Nat × Extent) (mem : r ∈ s.rows) (digest : r.2.digest = d) :
    ∃ r' ∈ s.rows, r'.2.digest = d ∧ s.find d = some (.extent r'.1 r'.2) ∧
      s.rows.find? (·.2.digest == d) = some r' := by
  cases found : s.rows.find? (·.2.digest == d) with
  | none => exact absurd (by simp [digest]) (List.find?_eq_none.mp found r mem)
  | some r' =>
    have holds := List.find?_some found
    refine ⟨r', List.mem_of_find?_eq_some found, by simpa using holds, ?_, rfl⟩
    simp [Store.find, absent, found]

/-- An answer is an object or a row of a store of the list. -/
theorem lookup_is_held (stores : List Store) (d : Digest) (src : Source)
    (answer : lookup stores d = some src) :
    ∃ s ∈ stores,
      (src = .object d ∧ d ∈ s.objects) ∨
      (∃ r ∈ s.rows, src = .extent r.1 r.2 ∧ r.2.digest = d) := by
  induction stores with
  | nil => simp [lookup] at answer
  | cons s ss ih =>
    cases found : s.find d with
    | none =>
      simp [lookup, found] at answer
      obtain ⟨t, mem, h⟩ := ih answer
      exact ⟨t, .tail _ mem, h⟩
    | some a =>
      simp [lookup, found] at answer
      subst answer
      refine ⟨s, .head _, ?_⟩
      unfold Store.find at found
      split at found
      · simp at found; subst found; exact .inl ⟨rfl, ‹_›⟩
      · cases row : s.rows.find? (·.2.digest == d) with
        | none => simp [row] at found
        | some r =>
          simp [row] at found
          subst found
          exact .inr ⟨r, List.mem_of_find?_eq_some row, rfl, by simpa using List.find?_some row⟩

/-- No answer means no store has an object or a row for the digest. -/
theorem lookup_none_is_nothing (stores : List Store) (d : Digest)
    (answer : lookup stores d = none) :
    ∀ s ∈ stores, d ∉ s.objects ∧ ∀ r ∈ s.rows, r.2.digest ≠ d := by
  induction stores with
  | nil => intro s mem; cases mem
  | cons s ss ih =>
    simp only [lookup, Option.or_eq_none_iff] at answer
    intro t mem
    rcases List.mem_cons.mp mem with rfl | mem
    · refine ⟨fun has => ?_, fun r mem same => ?_⟩
      · simp [Store.find, has] at answer
      · have := answer.1
        unfold Store.find at this
        split at this
        · simp at this
        · have row : t.rows.find? (·.2.digest == d) = none := Option.map_eq_none_iff.mp this
          exact absurd (by simp [same]) (List.find?_eq_none.mp row r mem)
    · exact ih answer.2 t mem

end InlineModel
