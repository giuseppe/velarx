-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: facts about a name dotted as `encode_name` walks it (each label followed
-- by a dot, also the last one): that it is the name joined by dots and a dot, how long it is on
-- the wire, and that the label before the first dot is determined by the bytes.
--
-- Why it is needed: `encode_name` cuts the dotted bytes at each dot.  To say that it refuses a name
-- exactly when the name cannot be written, the proofs need that any writing of the bytes begins
-- with the labels it has written (`labels_with_dots_split`).
--
-- Read before this file: Spec.lean (`Joined`, `OnWire`), WireNames.lean.
--
-- Notation: `LabelsWithDots labels` is each label followed by a dot; `Joined labels` is the labels
-- joined by dots; `l ++ l'` is `l` and then `l'`.
import DnsCore.WireNames

namespace DnsCore

/-- The labels of a name, each followed by a dot (also the last): the dotted name as `encode_name`
walks it, with a dot added at the end. -/
def LabelsWithDots (labels : List (List Nat)) : List Nat :=
  labels.flatMap fun label => label ++ [46]

/-- One more label at the end of the name is written after the others and a dot. -/
theorem with_dots_snoc (labels : List (List Nat)) (label : List Nat) :
    LabelsWithDots (labels ++ [label]) = LabelsWithDots labels ++ (label ++ [46]) := by
  simp [LabelsWithDots]

/-- A name that has labels, followed by a dot, is the labels each followed by a dot. -/
theorem joined_and_a_dot (labels : List (List Nat)) (has_labels : labels ≠ []) :
    Joined labels ++ [46] = LabelsWithDots labels := by
  induction labels with
  | nil => exact absurd rfl has_labels
  | cons label others ih =>
    cases others with
    | nil => simp [Joined, LabelsWithDots]
    | cons next more =>
      have := ih (by simp)
      simp only [Joined, LabelsWithDots, List.intercalate, List.flatMap_cons] at this ⊢
      rw [List.intersperse_cons_cons, List.flatten_cons, List.flatten_cons]
      simpa [List.append_assoc] using this

/-- The bytes before the first dot are the label: two names with no dot before a dot, and the same
bytes, have the same label and what follows. -/
theorem label_before_the_first_dot (x y after_x after_y : List Nat)
    (x_has_no_dot : ∀ c ∈ x, c ≠ 46) (y_has_no_dot : ∀ c ∈ y, c ≠ 46)
    (same_bytes : x ++ 46 :: after_x = y ++ 46 :: after_y) : x = y ∧ after_x = after_y := by
  induction x generalizing y with
  | nil =>
    cases y with
    | nil => exact ⟨rfl, (List.cons.inj same_bytes).2⟩
    | cons c _ => exact absurd (List.cons.inj same_bytes).1.symm (y_has_no_dot c (by simp))
  | cons c others ih =>
    cases y with
    | nil => exact absurd (List.cons.inj same_bytes).1 (x_has_no_dot c (by simp))
    | cons d more =>
      obtain ⟨same_byte, same_rest⟩ := List.cons.inj same_bytes
      obtain ⟨same_labels, same_after⟩ := ih more
        (fun e inside => x_has_no_dot e (by simp [inside]))
        (fun e inside => y_has_no_dot e (by simp [inside])) same_rest
      exact ⟨by simp [same_byte, same_labels], same_after⟩

/-- The bytes of a name that begin with the labels `done` (each followed by a dot, and none with a
dot inside) can only be the labels of `labels` followed by dots if `done` is the beginning of
`labels`, and what follows `done` is the other labels. -/
theorem labels_with_dots_split (done labels : List (List Nat)) (rest : List Nat)
    (done_labels : ∀ label ∈ done, WritableLabel label)
    (labels_labels : ∀ label ∈ labels, WritableLabel label)
    (same_bytes : LabelsWithDots done ++ rest = LabelsWithDots labels) :
    ∃ more, labels = done ++ more ∧ rest = LabelsWithDots more := by
  induction done generalizing labels with
  | nil => exact ⟨labels, rfl, by simpa [LabelsWithDots] using same_bytes⟩
  | cons first others ih =>
    cases labels with
    | nil => simp [LabelsWithDots] at same_bytes
    | cons label labels =>
      simp only [LabelsWithDots, List.flatMap_cons, List.append_assoc,
        List.cons_append] at same_bytes
      obtain ⟨same_label, same_others⟩ := label_before_the_first_dot first label _ _
        (done_labels first (by simp)).2.2 (labels_labels label (by simp)).2.2 same_bytes
      obtain ⟨more, same_labels, same_rest⟩ := ih labels
        (fun other inside => done_labels other (by simp [inside]))
        (fun other inside => labels_labels other (by simp [inside]))
        (by simpa [LabelsWithDots] using same_others)
      exact ⟨more, by simp [same_label, same_labels], same_rest⟩

/-- The labels on the wire (without the zero) and with dots take as many bytes: a byte for the
length or for the dot. -/
theorem labels_on_wire_and_with_dots_are_as_long (labels : List (List Nat)) :
    (LabelsOnWire labels).length = (LabelsWithDots labels).length := by
  induction labels with
  | nil => rfl
  | cons label others ih =>
    simp only [LabelsOnWire, LabelsWithDots] at ih ⊢
    simp only [List.flatMap_cons, List.length_append, List.length_cons, List.length_nil]
    omega

/-- A name that has labels is two bytes longer on the wire than dotted: the length of the first
label and the zero that ends it. -/
theorem wire_is_two_bytes_longer (labels : List (List Nat)) (has_labels : labels ≠ []) :
    (OnWire labels).length = (Joined labels).length + 2 := by
  have := congrArg List.length (joined_and_a_dot labels has_labels)
  have := labels_on_wire_and_with_dots_are_as_long labels
  simp only [List.length_append, List.length_singleton, OnWire, LabelsOnWire] at *
  omega

end DnsCore
