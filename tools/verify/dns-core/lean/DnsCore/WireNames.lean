-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: facts about a name on the wire (a list of labels, each after its length,
-- and a zero) that do not depend on the code: how its bytes are split, and that the bytes of a name
-- are read in only one way.
--
-- Why it is needed: `question` reads the labels one by one, and to say that it refuses a name
-- exactly when the name cannot be read, the proofs need that the labels it has read are the
-- beginning of any reading of the bytes (`labels_on_wire_split`).  `name_on_wire_is_unique` is the
-- claim `ThereIsOneReading`.
--
-- Read before this file: Spec.lean (`OnWire`, `GoodName`, `Dotted`).
--
-- Notation: `labels` is a list of labels, each a list of bytes; `LabelsOnWire labels` is the labels
-- each after its length (`OnWire` is that and a zero); `l ++ l'` is `l` and then `l'`; `∃ x, P` is
-- "there is an x such that P".
import DnsCore.Spec

namespace DnsCore

/-- The labels of a name on the wire, each after its length, without the zero that ends the
name: `OnWire` is this and a zero. -/
def LabelsOnWire (labels : List (List Nat)) : List Nat :=
  labels.flatMap fun label => label.length :: label

/-- A name on the wire is its labels, each after its length, and a zero byte. -/
theorem on_wire_is_labels_and_a_zero (labels : List (List Nat)) :
    OnWire labels = LabelsOnWire labels ++ [0] := rfl

/-- One more label at the end of the name is written after the others. -/
theorem labels_on_wire_snoc (labels : List (List Nat)) (label : List Nat) :
    LabelsOnWire (labels ++ [label]) = LabelsOnWire labels ++ (label.length :: label) := by
  simp [LabelsOnWire]

/-- The bytes of a name on the wire that begin with the labels `done` (all of at least a byte) can
only be the name of `labels` if `done` is the beginning of `labels`, and what follows `done` is
the rest of the labels, the zero, and what follows the name. -/
theorem labels_on_wire_split (done labels : List (List Nat)) (rest tail : List Nat)
    (not_empty : ∀ label ∈ done, 1 ≤ label.length)
    (same_bytes : LabelsOnWire done ++ rest = OnWire labels ++ tail) :
    ∃ more, labels = done ++ more ∧ rest = OnWire more ++ tail := by
  induction done generalizing labels with
  | nil => exact ⟨labels, rfl, by simpa [LabelsOnWire] using same_bytes⟩
  | cons first others ih =>
    cases labels with
    | nil =>
      have := not_empty first (by simp)
      simp [LabelsOnWire, OnWire] at same_bytes
      simp [same_bytes.1] at this
    | cons label labels =>
      simp only [LabelsOnWire, OnWire, List.flatMap_cons, List.cons_append,
        List.append_assoc] at same_bytes
      obtain ⟨same_length, same_rest⟩ := List.cons.inj same_bytes
      obtain ⟨same_label, same_others⟩ := List.append_inj same_rest same_length
      obtain ⟨more, same_labels, same_rest⟩ := ih labels
        (fun other inside => not_empty other (by simp [inside]))
        (by simpa [LabelsOnWire, OnWire] using same_others)
      exact ⟨more, by simp [same_label, same_labels], same_rest⟩

/-- A name on the wire is read in one way: the same bytes with two good names and two tails give
the same name and the same tail. -/
theorem name_on_wire_is_unique (labels labels' : List (List Nat)) (tail tail' : List Nat)
    (good : GoodName labels) (good' : GoodName labels')
    (same_bytes : OnWire labels ++ tail = OnWire labels' ++ tail') :
    labels = labels' ∧ tail = tail' := by
  obtain ⟨more, same_labels, same_tail⟩ := labels_on_wire_split labels labels' ([0] ++ tail) tail'
    (fun label inside => (good.1 label inside).1)
    (by simpa [OnWire, LabelsOnWire] using same_bytes)
  cases more with
  | nil => exact ⟨by simpa using same_labels.symm, by simpa [OnWire] using same_tail⟩
  | cons label _ =>
    have long_enough := (good'.1 label (by simp [same_labels])).1
    simp [OnWire] at same_tail
    simp [same_tail.1] at long_enough

/-- A name that has labels is not empty: each label has a byte. -/
theorem dotted_is_empty_only_without_labels (labels : List (List Nat))
    (good : ∀ label ∈ labels, GoodLabel label) : Dotted labels = [] ↔ labels = [] := by
  cases labels with
  | nil => simp [Dotted, Joined]
  | cons label labels =>
    have := (good label (by simp)).1
    cases labels <;> simp [Dotted, Joined]
    intro h
    simp [h] at this

/-- One more label at the end of the name is written after the labels before it, and a dot if
there are any. -/
theorem dotted_snoc (labels : List (List Nat)) (label : List Nat) :
    Dotted (labels ++ [label]) =
      (if labels = [] then [] else Dotted labels ++ [46]) ++ label.map Lower := by
  induction labels with
  | nil => simp [Dotted, Joined]
  | cons first others ih =>
    cases others with
    | nil => simp [Dotted, Joined]
    | cons second more =>
      simp [Dotted, Joined, List.intercalate] at ih ⊢
      exact ih

end DnsCore
