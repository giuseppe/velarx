-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: what the loops that write a label do in `encode_name` (they copy its
-- bytes), what the outer loop knows at each turn (`Encoded`: the labels written, the text begins
-- with them, the label being read has no dot), and that the label before a dot is the only one a
-- name that can be written can have there (`the_label_before_a_dot_is_forced`).
--
-- Why it is needed: these are the pieces the loop of EncodeName.lean is made of; with them each
-- turn is a few lines.
--
-- Read before this file: Spec.lean, LabelsWithDots.lean, and `encode_name` in lib.rs.
--
-- Notation: as in LabelLoop.lean; `Encoded text out start i` is the invariant of the outer loop;
-- `NoEncoding text` is "no writable name is the text".
import DnsCore.Words
import DnsCore.LabelsWithDots
import DnsCore.NameLoop

open Aeneas Aeneas.Std Result velarx_dns_core

namespace DnsCore

/-- The loop that copies the label `j` to `i` of the name after what is already written copies
the bytes there. -/
theorem copy_loop_copies (text : Slice Std.U8) (out : alloc.vec.Vec Std.U8) (i j : Std.Usize)
    (in_order : j.val ≤ i.val) (inside : i.val ≤ text.length)
    (room : out.length + (i.val - j.val) ≤ 65535) :
    encode_name_loop0_loop0 text out i j ⦃ r =>
      Bytes r.val = Bytes out.val ++ ((Bytes text.val).drop j.val).take (i.val - j.val) ⦄ := by
  unfold encode_name_loop0_loop0
  apply loop.spec_decr_nat (fun q => i.val - q.2.val)
    (fun q => q.2.val ≤ i.val ∧ j.val ≤ q.2.val ∧
      q.1.length ≤ out.length + (q.2.val - j.val) ∧
      Bytes q.1.val = Bytes out.val ++ ((Bytes text.val).drop j.val).take (q.2.val - j.val))
  · rintro ⟨written, k⟩ ⟨k_le, ge_j, short, copied⟩
    simp only at k_le ge_j short copied ⊢
    unfold encode_name_loop0_loop0.body
    split
    · rename_i below
      step as ⟨ byte, byte_post ⟩
      step as ⟨ written', written'_post ⟩
      step as ⟨ k', k'_post ⟩
      have below' : k.val < i.val := by scalar_tac
      have text_inside : k.val < text.length := by omega
      refine ⟨by omega, by omega, ?_, ?_, by omega⟩
      · have longer : written'.val.length = written.val.length + 1 := by simp [written'_post]
        have same_written : written.length = written.val.length := rfl
        have same_written' : written'.length = written'.val.length := rfl
        omega
      · have taken : ((Bytes text.val).drop j.val).take (k'.val - j.val) =
            ((Bytes text.val).drop j.val).take (k.val - j.val) ++ [byte.val] := by
          have : k'.val - j.val = (k.val - j.val) + 1 := by omega
          rw [this, List.take_add_one]
          simp [List.getElem?_drop, Bytes, byte_post, text_inside,
            show j.val + (k.val - j.val) = k.val by omega]
        rw [taken, ← List.append_assoc, ← copied, written'_post]
        simp [Bytes]
    · rename_i not_below
      simp only [WP.spec_ok]
      have : k.val = i.val := by scalar_tac
      rw [copied, this]
  · exact ⟨in_order, Nat.le_refl _, by simp, by simp⟩

/-- The loop that copies a label before a dot (the second copy of the same loop in `encode_name`)
does the same. -/
theorem copy_loop_copies_before_a_dot (text : Slice Std.U8) (out : alloc.vec.Vec Std.U8)
    (i j : Std.Usize) (in_order : j.val ≤ i.val) (inside : i.val ≤ text.length)
    (room : out.length + (i.val - j.val) ≤ 65535) :
    encode_name_loop0_loop1 text out i j ⦃ r =>
      Bytes r.val = Bytes out.val ++ ((Bytes text.val).drop j.val).take (i.val - j.val) ⦄ := by
  have := copy_loop_copies text out i j in_order inside room
  unfold encode_name_loop0_loop0 encode_name_loop0_loop0.body at this
  unfold encode_name_loop0_loop1 encode_name_loop0_loop1.body
  exact this

/-- No labels can give the text: the text, with a dot added, is not the labels of any writable
name, each followed by a dot. -/
def NoEncoding (text : List Nat) : Prop :=
  ∀ labels, Writable labels → text ++ [46] = LabelsWithDots labels → False

/-- What the outer loop of `encode_name` has done when it is at the byte `i` of the text with the
label beginning at `start`: it has written the labels `done` before it (so the text, with a dot
added, begins with them, each followed by a dot, and what is written is as long as what they
take of the text), and the bytes from `start` to `i` have no dot. -/
def Encoded (text : List Nat) (out : alloc.vec.Vec Std.U8) (start i : Nat) : Prop :=
  ∃ done : List (List Nat), (∀ label ∈ done, WritableLabel label) ∧
    Bytes out.val = LabelsOnWire done ∧ (LabelsOnWire done).length = start ∧
    start ≤ i ∧ i ≤ text.length + 1 ∧ (text ++ [46]).take start = LabelsWithDots done ∧
    ∀ c ∈ ((text ++ [46]).drop start).take (i - start), c ≠ 46

/-- When the loop is at a dot (a real one, or the one added at the end) a name made of labels
from the text can only be written with the label that ends there, and that label is good and
fits. -/
theorem the_label_before_a_dot_is_forced (text : List Nat) (out : alloc.vec.Vec Std.U8)
    (start i : Nat) (state : Encoded text out start i) (at_a_dot : (text ++ [46])[i]? = some 46)
    (labels : List (List Nat)) (writable : Writable labels)
    (same_bytes : text ++ [46] = LabelsWithDots labels) :
    1 ≤ i - start ∧ i - start ≤ 63 := by
  obtain ⟨done, done_writable, written, room, in_order, within, begins, no_dot⟩ := state
  have i_inside : i < (text ++ [46]).length := (List.getElem?_eq_some_iff.mp at_a_dot).1
  obtain ⟨more, same_labels, rest⟩ := labels_with_dots_split done labels
    ((text ++ [46]).drop start) done_writable writable.1
    (by rw [← begins, List.take_append_drop, same_bytes])
  have label_and_dot : (text ++ [46]).drop start =
      ((text ++ [46]).drop start).take (i - start) ++ 46 :: (text ++ [46]).drop (i + 1) := by
    have after := drop_at_a_byte (text ++ [46]) i 46 at_a_dot
    have split := List.take_append_drop (i - start) ((text ++ [46]).drop start)
    rw [List.drop_drop, Nat.add_sub_cancel' in_order, after] at split
    exact split.symm
  cases more with
  | nil =>
    have := congrArg List.length rest
    simp only [List.length_drop, LabelsWithDots, List.flatMap_nil, List.length_nil] at this
    omega
  | cons label more' =>
    rw [label_and_dot] at rest
    simp only [LabelsWithDots, List.flatMap_cons, List.append_assoc, List.cons_append] at rest
    obtain ⟨same_label, _⟩ := label_before_the_first_dot _ label _ _ no_dot
      (writable.1 label (by simp [same_labels])).2.2 rest
    have label_good := writable.1 label (by simp [same_labels])
    have taken_length : (((text ++ [46]).drop start).take (i - start)).length = i - start := by
      simp only [List.length_take, List.length_drop, List.length_append, List.length_singleton]
      omega
    have long_enough := label_good.1
    have short_enough := label_good.2.1
    rw [← same_label, taken_length] at long_enough short_enough
    exact ⟨long_enough, short_enough⟩

/-- The text, with the dot added, and the text itself agree before the end of the text. -/
theorem text_and_the_added_dot_agree (text : List Nat) (start l : Nat)
    (inside : start + l ≤ text.length) :
    ((text ++ [46]).drop start).take l = (text.drop start).take l := by
  apply List.ext_getElem?
  intro k
  by_cases within : k < l
  · simp [List.getElem?_take_of_lt within, List.getElem?_drop,
      List.getElem?_append_left (by omega : start + k < text.length)]
  · simp [within]

/-- The label that ends at a dot is written (its length, then its bytes), and the loop is then at
the byte after the dot with nothing read of the next label. -/
theorem a_label_is_written (text : List Nat) (out out' : alloc.vec.Vec Std.U8) (start i : Nat)
    (state : Encoded text out start i) (at_a_dot : (text ++ [46])[i]? = some 46)
    (long_enough : 1 ≤ i - start) (short_enough : i - start ≤ 63)
    (written : Bytes out'.val = Bytes out.val ++
      ((i - start) :: (text.drop start).take (i - start))) :
    Encoded text out' (i + 1) (i + 1) := by
  obtain ⟨done, done_writable, out_is, room, in_order, within, begins, no_dot⟩ := state
  have i_inside : i < (text ++ [46]).length := (List.getElem?_eq_some_iff.mp at_a_dot).1
  simp only [List.length_append, List.length_singleton] at i_inside
  have same_label := text_and_the_added_dot_agree text start (i - start) (by omega)
  have label_length : ((text.drop start).take (i - start)).length = i - start := by
    simp only [List.length_take, List.length_drop]
    omega
  refine ⟨done ++ [(text.drop start).take (i - start)], ?_, ?_, ?_, by omega, by omega, ?_, by simp⟩
  · intro label inside
    rcases List.mem_append.mp inside with before | now
    · exact done_writable label before
    · rw [List.mem_singleton.mp now]
      refine ⟨by omega, by omega, ?_⟩
      rw [← same_label]
      exact no_dot
  · rw [written, out_is, labels_on_wire_snoc, label_length]
  · rw [labels_on_wire_snoc, label_length]
    simp only [List.length_append, List.length_cons]
    omega
  · have until_the_dot : (text ++ [46]).take (i + 1) =
        (text ++ [46]).take start ++ ((text ++ [46]).drop start).take (i - start) ++ [46] := by
      rw [List.take_add_one, at_a_dot, ← List.take_add, Nat.add_sub_cancel' in_order]
      simp
    rw [until_the_dot, with_dots_snoc, ← begins, same_label, List.append_assoc]

end DnsCore
