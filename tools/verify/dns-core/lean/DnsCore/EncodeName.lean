-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: what `encode_name` does: its loop writes the labels of a text, and the
-- function writes the zero that ends the name, or refuses.
--
-- Why it is needed: this is the proof of `EncodeNameWritesTheWire`.
--
-- Read before this file: Spec.lean, EncodeLabels.lean, and `encode_name` in lib.rs.
--
-- Notation: as in EncodeLabels.lean.
import DnsCore.EncodeLabels

open Aeneas Aeneas.Std Result velarx_dns_core

namespace DnsCore

/-- In plain words: the loop cuts the text at each dot and writes each piece after its length.
When it ends well, what it wrote is the labels of the text on the wire (without the zero), as
long as the text plus one byte; when it ends badly, no name that can be written is the text.  The
text is at most 253 bytes (`encode_name` checks it first). -/
theorem encode_loop_writes_the_labels (text : Slice Std.U8) (short : text.length ≤ 253) :
    encode_name_loop0 text (alloc.vec.Vec.new Std.U8) true 0#usize 0#usize ⦃ r =>
      r.1.length ≤ text.length + 1 ∧
      (r.2 = true → ∃ labels, (∀ label ∈ labels, WritableLabel label) ∧
        Bytes r.1.val = LabelsOnWire labels ∧ (LabelsOnWire labels).length = text.length + 1 ∧
        Bytes text.val = Joined labels) ∧
      (r.2 = false → NoEncoding (Bytes text.val)) ⦄ := by
  unfold encode_name_loop0
  have len_same : (↑text : List Std.U8).length = text.length := rfl
  have bytes_len : (Bytes text.val).length = text.length := by simp
  apply loop.spec_decr_nat
    (fun q => if q.2.1 = true then text.length + 2 - q.2.2.2.val else 0)
    (fun q => q.1.length ≤ text.length + 1 ∧
      (q.2.1 = true → Encoded (Bytes text.val) q.1 q.2.2.1.val q.2.2.2.val) ∧
      (q.2.1 = false → NoEncoding (Bytes text.val)))
  · rintro ⟨written, ok', start, i⟩ ⟨written_small, state, failed⟩
    simp only at written_small state failed ⊢
    unfold encode_name_loop0.body
    split
    · rename_i going
      subst going
      have so_far := state rfl
      dsimp only
      split
      · rename_i inside
        split
        · -- the end of the text: the last label
          rename_i at_the_end
          have end_val : i.val = text.length := by scalar_tac
          have at_a_dot : ((Bytes text.val) ++ [46])[i.val]? = some 46 := by
            simp [end_val]
          have in_order : start.val ≤ i.val := by
            obtain ⟨_, _, _, _, in_order, _⟩ := so_far
            exact in_order
          step as ⟨ l, l_post ⟩
          split
          · -- an empty label
            rename_i empty
            step as ⟨ next, next_post ⟩
            refine ⟨written_small, fun h => by simp at h, fun _ labels writable same => ?_,
              by simp; omega⟩
            have := the_label_before_a_dot_is_forced _ written start.val i.val so_far at_a_dot
              labels writable same
            scalar_tac
          split
          · -- a label that is too long
            rename_i too_long
            step as ⟨ next, next_post ⟩
            refine ⟨written_small, fun h => by simp at h, fun _ labels writable same => ?_,
              by simp; omega⟩
            have := the_label_before_a_dot_is_forced _ written start.val i.val so_far at_a_dot
              labels writable same
            scalar_tac
          · -- a label that is written
            rename_i not_too_long
            have l_val : l.val = i.val - start.val := l_post
            have long_enough : 1 ≤ i.val - start.val := by scalar_tac
            have short_enough : i.val - start.val ≤ 63 := by scalar_tac
            have written_length : written.length = start.val := by
              obtain ⟨_, _, written_is, size, _⟩ := so_far
              have := congrArg List.length written_is
              simp only [bytes_length] at this
              rw [vec_length_is_the_list_length]
              omega
            simp only [lift, bind_ok]
            step as ⟨ with_length, with_length_post ⟩
            have with_length_length : with_length.length = start.val + 1 := by
              rw [vec_length_is_the_list_length, with_length_post]
              simp [written_length]
            step with copy_loop_copies text with_length i start in_order (by omega) (by omega)
              as ⟨ copied, copied_post ⟩
            step as ⟨ start1, start1_post ⟩
            have encoded : Encoded (Bytes text.val) copied (i.val + 1) (i.val + 1) := by
              refine a_label_is_written _ written copied start.val i.val so_far at_a_dot long_enough
                short_enough ?_
              rw [copied_post, with_length_post]
              simp [Bytes, UScalar.cast_val_eq, l_val]
              omega
            have copied_small : copied.length ≤ text.length + 1 := by
              obtain ⟨_, _, copied_is, size, _⟩ := encoded
              have := congrArg List.length copied_is
              simp only [bytes_length] at this
              rw [vec_length_is_the_list_length]
              omega
            have start1_val : start1.val = i.val + 1 := start1_post
            refine ⟨copied_small, fun _ => ?_, fun h => by simp at h, by simp; omega⟩
            rw [start1_val]
            exact encoded
        · rename_i not_the_end
          step as ⟨ byte, byte_post ⟩
          split
          · -- a dot: a label ends
            rename_i is_a_dot
            have not_the_end_val : i.val < text.length := by scalar_tac
            have byte_is : (Bytes text.val)[i.val]? = some byte.val := by
              simp [Bytes, byte_post, List.getElem?_eq_getElem not_the_end_val]
            have at_a_dot : ((Bytes text.val) ++ [46])[i.val]? = some 46 := by
              rw [List.getElem?_append_left (by simpa using not_the_end_val), byte_is]
              simp [is_a_dot]
            have in_order : start.val ≤ i.val := by
              obtain ⟨_, _, _, _, in_order, _⟩ := so_far
              exact in_order
            step as ⟨ l, l_post ⟩
            split
            · -- an empty label
              rename_i empty
              step as ⟨ next, next_post ⟩
              refine ⟨written_small, fun h => by simp at h, fun _ labels writable same => ?_,
              by simp; omega⟩
              have := the_label_before_a_dot_is_forced _ written start.val i.val so_far at_a_dot
                labels writable same
              scalar_tac
            split
            · -- a label that is too long
              rename_i too_long
              step as ⟨ next, next_post ⟩
              refine ⟨written_small, fun h => by simp at h, fun _ labels writable same => ?_,
              by simp; omega⟩
              have := the_label_before_a_dot_is_forced _ written start.val i.val so_far at_a_dot
                labels writable same
              scalar_tac
            · -- a label that is written
              rename_i not_too_long
              have l_val : l.val = i.val - start.val := l_post
              have long_enough : 1 ≤ i.val - start.val := by scalar_tac
              have short_enough : i.val - start.val ≤ 63 := by scalar_tac
              have written_length : written.length = start.val := by
                obtain ⟨_, _, written_is, size, _⟩ := so_far
                have := congrArg List.length written_is
                simp only [bytes_length] at this
                rw [vec_length_is_the_list_length]
                omega
              simp only [lift, bind_ok]
              step as ⟨ with_length, with_length_post ⟩
              have with_length_length : with_length.length = start.val + 1 := by
                rw [vec_length_is_the_list_length, with_length_post]
                simp [written_length]
              step with copy_loop_copies_before_a_dot text with_length i start in_order (by omega)
                (by omega) as ⟨ copied, copied_post ⟩
              step as ⟨ start1, start1_post ⟩
              have encoded : Encoded (Bytes text.val) copied (i.val + 1) (i.val + 1) := by
                refine a_label_is_written _ written copied start.val i.val so_far at_a_dot
                  long_enough short_enough ?_
                rw [copied_post, with_length_post]
                simp [Bytes, UScalar.cast_val_eq, l_val]
                omega
              have copied_small : copied.length ≤ text.length + 1 := by
                obtain ⟨_, _, copied_is, size, _⟩ := encoded
                have := congrArg List.length copied_is
                simp only [bytes_length] at this
                rw [vec_length_is_the_list_length]
                omega
              have start1_val : start1.val = i.val + 1 := start1_post
              refine ⟨copied_small, fun _ => ?_, fun h => by simp at h, by simp; omega⟩
              rw [start1_val]
              exact encoded
          · -- a byte of a label
            rename_i not_a_dot
            have not_the_end_val : i.val < text.length := by scalar_tac
            have byte_is : (Bytes text.val)[i.val]? = some byte.val := by
              simp [Bytes, byte_post, List.getElem?_eq_getElem not_the_end_val]
            have byte_is_there : (Bytes text.val ++ [46])[i.val]? = some byte.val := by
              rw [List.getElem?_append_left (by omega), byte_is]
            have byte_not_a_dot : byte.val ≠ 46 := fun is_46 =>
              not_a_dot (UScalar.eq_of_val_eq (by simpa using is_46))
            step as ⟨ next, next_post ⟩
            refine ⟨written_small, fun _ => ?_, fun h => by simp at h, by simp; omega⟩
            obtain ⟨done, done_writable, written_is, size, in_order, within, begins, no_dot⟩ :=
              so_far
            refine ⟨done, done_writable, written_is, size, by omega, by omega, begins, ?_⟩
            have next_val : next.val = i.val + 1 := next_post
            rw [next_val]
            have taken : ((Bytes text.val ++ [46]).drop start.val).take (i.val + 1 - start.val) =
                ((Bytes text.val ++ [46]).drop start.val).take (i.val - start.val) ++
                  [byte.val] := by
              rw [show i.val + 1 - start.val = (i.val - start.val) + 1 by omega, List.take_add_one]
              simp [List.getElem?_drop, byte_is_there,
                show start.val + (i.val - start.val) = i.val by omega]
            rw [taken]
            intro c inside
            rcases List.mem_append.mp inside with before | now
            · exact no_dot c before
            · rw [List.mem_singleton.mp now]
              exact byte_not_a_dot
      · -- every byte has been looked at
        rename_i past_the_end
        simp only [WP.spec_ok]
        refine ⟨written_small, fun _ => ?_, fun h => by simp at h⟩
        obtain ⟨done, done_writable, written_is, size, in_order, within, begins, no_dot⟩ :=
          so_far
        have i_val : i.val = text.length + 1 := by scalar_tac
        -- the dot at the end is in the bytes from `start` to `i`, unless `start` is past it
        have start_val : start.val = text.length + 1 := by
          by_contra before_the_end
          have in_the_label : 46 ∈ ((Bytes text.val ++ [46]).drop start.val).take
              (i.val - start.val) := by
            refine List.mem_iff_getElem?.mpr ⟨text.length - start.val, ?_⟩
            rw [List.getElem?_take_of_lt (by omega), List.getElem?_drop,
              show start.val + (text.length - start.val) = text.length by omega]
            simp [bytes_len]
          exact no_dot 46 in_the_label rfl
        have whole : Bytes text.val ++ [46] = LabelsWithDots done := by
          rw [← begins, start_val]
          simp [bytes_len]
        have has_labels : done ≠ [] := by
          rintro rfl
          simp [LabelsWithDots] at whole
        refine ⟨done, done_writable, written_is, by omega, ?_⟩
        have := joined_and_a_dot done has_labels
        rw [← whole] at this
        exact List.append_cancel_right this.symm
    · rename_i not_going
      have not_ok : ok' = false := by simpa using not_going
      simp only [WP.spec_ok]
      exact ⟨written_small, fun h => by simp [not_ok] at h, fun _ => failed not_ok⟩
  · simp only
    refine ⟨by simp, fun _ => ⟨[], by simp, by simp [Bytes, LabelsOnWire], by simp [LabelsOnWire],
      by simp, by simp, by simp [LabelsWithDots], by simp⟩, fun h => by simp at h⟩

/-- In plain words: 253 is the longest dotted name, because the wire name is two bytes longer and
the wire name has at most 255.  A name that can be written is at most 253 bytes dotted. -/
theorem a_writable_name_is_short (labels : List (List Nat)) (writable : Writable labels) :
    (Joined labels).length ≤ 253 := by
  by_cases has_labels : labels = []
  · simp [has_labels, Joined]
  · have := wire_is_two_bytes_longer labels has_labels
    have := writable.2
    omega

/-- In plain words: `encode_name` writes a name that can be written and refuses the others.  It
refuses a text of more than 253 bytes at once, writes the zero byte for the empty text, and for
the others writes the labels (the loop above) and the zero that ends the name. -/
theorem encode_name_writes_the_wire (text : Slice Std.U8) :
    encode_name text ⦃ r =>
      (∀ wire, r = some wire → ∃ labels, Writable labels ∧ Bytes text.val = Joined labels ∧
        Bytes wire.val = OnWire labels) ∧
      (r = none → ¬ ∃ labels, Writable labels ∧ Bytes text.val = Joined labels) ⦄ := by
  unfold encode_name
  have max_name : MAX_NAME.val = 255 := by simp [global_simps]
  step as ⟨ limit, limit_post ⟩
  split
  · -- too long
    rename_i too_long
    simp only [WP.spec_ok]
    refine ⟨fun w h => by simp at h, fun _ ⟨labels, writable, same⟩ => ?_⟩
    have := a_writable_name_is_short labels writable
    rw [← same] at this
    simp only [bytes_length] at this
    have : text.length ≤ 253 := by omega
    scalar_tac
  · rename_i short
    have short' : text.length ≤ 253 := by scalar_tac
    step as ⟨ is_empty, is_empty_post ⟩
    split
    · -- no name: the root
      rename_i empty
      step as ⟨ root, root_post ⟩
      refine ⟨fun w same => ?_, fun h => by simp at h⟩
      simp only [Option.some.injEq] at same
      subst same
      have : text.length = 0 := Eq.mp is_empty_post empty
      refine ⟨[], ⟨by simp, by simp [OnWire]⟩, ?_, by simp [Bytes, OnWire, root_post]⟩
      have : text.val = [] := List.eq_nil_of_length_eq_zero this
      simp [Bytes, this, Joined]
    · rename_i not_empty
      step with encode_loop_writes_the_labels text short'
        as ⟨ out, ok', out_small, written, failed ⟩
      step as ⟨ out1, out1_post ⟩
      split
      · rename_i is_ok
        simp only [WP.spec_ok]
        refine ⟨fun w same => ?_, fun h => by simp at h⟩
        simp only [Option.some.injEq] at same
        subst same
        obtain ⟨labels, writable, written_is, size, joined⟩ := written is_ok
        refine ⟨labels, ⟨writable, ?_⟩, joined, ?_⟩
        · rw [on_wire_is_labels_and_a_zero]
          simp only [List.length_append, List.length_singleton]
          omega
        · rw [on_wire_is_labels_and_a_zero, ← written_is]
          simp [Bytes, out1_post]
      · rename_i not_ok
        simp only [WP.spec_ok]
        refine ⟨fun w h => by simp at h, fun _ ⟨labels, writable, same⟩ => ?_⟩
        refine failed (by simpa using not_ok) labels writable ?_
        have has_labels : labels ≠ [] := by
          rintro rfl
          have : text.length = 0 := by
            have := congrArg List.length same
            simpa [Bytes, Joined] using this
          exact not_empty (Eq.mpr is_empty_post this)
        rw [same]
        exact joined_and_a_dot labels has_labels

end DnsCore
