-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: that the name of a `Question` that `question` gave can be written with
-- `encode_name`, and gives the bytes of the query in lower case.
--
-- Why it is needed: this is the proof of `AQuestionNameCanBeWrittenBack`.  The two functions are
-- proved apart (Question.lean, EncodeName.lean); here they are put together: lower case letters
-- are still good labels, and the labels of a name that can be written are determined by its dotted
-- bytes.
--
-- Read before this file: Spec.lean, Question.lean, EncodeName.lean.
--
-- Notation: `Lower` is the lower case of a byte (Spec.lean); `labels.map f` is the list of the `f`
-- of each label.
import DnsCore.EncodeName
import DnsCore.Parse

open Aeneas Aeneas.Std Result velarx_dns_core

namespace DnsCore

/-- Names that can be written have one set of labels: two lists of writable labels joined by dots
into the same bytes are the same list. -/
theorem joined_labels_are_unique (labels labels' : List (List Nat))
    (writable : ∀ label ∈ labels, WritableLabel label)
    (writable' : ∀ label ∈ labels', WritableLabel label)
    (same_bytes : Joined labels = Joined labels') : labels = labels' := by
  have nothing_if_empty : ∀ others : List (List Nat), (∀ label ∈ others, WritableLabel label) →
      Joined others = [] → others = [] := fun others good empty => by
    cases others with
    | nil => rfl
    | cons label more =>
      have := (good label (by simp)).1
      cases more
      · simp [Joined] at empty
        simp [empty] at this
      · simp [Joined] at empty
  by_cases no_labels : labels = []
  · subst no_labels
    exact (nothing_if_empty labels' writable' same_bytes.symm).symm
  · have no_labels' : labels' ≠ [] := fun empty => by
      subst empty
      exact no_labels (nothing_if_empty labels writable same_bytes)
    obtain ⟨more, same_labels, rest⟩ := labels_with_dots_split labels labels' [] writable writable'
      (by rw [List.append_nil, ← joined_and_a_dot _ no_labels, ← joined_and_a_dot _ no_labels',
        same_bytes])
    cases more with
    | nil => simpa using same_labels.symm
    | cons label others =>
      have := (writable' label (by simp [same_labels])).1
      simp [LabelsWithDots] at rest

/-- Putting the labels of a name in lower case does not change what makes them writable. -/
theorem lower_case_labels_are_writable (labels : List (List Nat)) (good : GoodName labels) :
    Writable (labels.map fun label => label.map Lower) := by
  refine ⟨fun label inside => ?_, ?_⟩
  · obtain ⟨original, original_inside, rfl⟩ := List.mem_map.mp inside
    obtain ⟨long_enough, short_enough, letters⟩ := good.1 original original_inside
    refine ⟨by simpa using long_enough, by simpa using short_enough, fun c lowered => ?_⟩
    obtain ⟨letter, letter_inside, rfl⟩ := List.mem_map.mp lowered
    have := (letters letter letter_inside).1
    unfold Lower
    split <;> omega
  · have := good.2
    simpa [OnWire, List.flatMap_map, Function.comp_def] using this

/-- The name on the wire with its labels in lower case is the bytes on the wire in lower case:
the lengths (at most 63) and the zero are not capital letters. -/
theorem lower_case_wire (labels : List (List Nat)) (good : GoodName labels) :
    OnWire (labels.map fun label => label.map Lower) = (OnWire labels).map Lower := by
  have lengths_stay : ∀ label ∈ labels, Lower label.length = label.length := fun label inside => by
    have := (good.1 label inside).2.1
    unfold Lower
    split <;> omega
  simp only [OnWire, List.map_append, List.map_flatMap, List.flatMap_map]
  congr 1
  apply List.flatMap_congr
  intro label inside
  simp [lengths_stay label inside]

/-- The name of the `Question` that `question` gave, put through `encode_name`, gives the bytes of
the name of the query on the wire with its capital letters made small. -/
theorem a_question_name_can_be_written_back (m : Slice Std.U8) :
    question m ⦃ r => ∀ q, r = some q → ∃ labels tail, QueryWith (Bytes m.val) labels tail ∧
      encode_name q.name.slice ⦃ w =>
        ∃ wire, w = some wire ∧ Bytes wire.val = (OnWire labels).map Lower ⦄ ⦄ := by
  apply WP.spec_mono (question_reads m)
  intro r reads q is_q
  obtain ⟨labels, tail, query, is_the_question⟩ := reads.1 q is_q
  refine ⟨labels, tail, query, ?_⟩
  have writable := lower_case_labels_are_writable labels query.name_is_good
  have name_is : Bytes q.name.slice.val = Joined (labels.map fun label => label.map Lower) :=
    is_the_question.name_is_dotted
  apply WP.spec_mono (encode_name_writes_the_wire q.name.slice)
  intro w written
  cases w with
  | none =>
    exact absurd ⟨_, writable, name_is⟩ (written.2 rfl)
  | some wire =>
    obtain ⟨labels', writable', joined, wire_is⟩ := written.1 wire rfl
    obtain rfl := joined_labels_are_unique _ _ writable.1 writable'.1 (name_is.symm.trans joined)
    exact ⟨wire, rfl, by rw [wire_is, lower_case_wire labels query.name_is_good]⟩

end DnsCore
