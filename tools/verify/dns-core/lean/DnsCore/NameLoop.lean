-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: what the loop of `read_name` does (`read_name_loop0`): it reads the labels
-- of the name after the header one by one, and either has read the whole name or has found that
-- no name can be read.
--
-- Why it is needed: this is the heart of `question`.  Each turn keeps `ReadSoFar` (the labels read,
-- the name written, the bytes read are those labels on the wire); each refusal is shown to be a
-- refusal of any name (`NoName`: if the next label is cut, too long, too many bytes on the wire, or
-- has a dot or a NUL, then no good name begins with the labels read).
--
-- Read before this file: Spec.lean, WireNames.lean, LabelLoop.lean, and `read_name` in lib.rs.
--
-- Notation: the same as LabelLoop.lean; `loop.spec_decr_nat` here takes as the number that goes
-- down the bytes of the message not read yet; `NoName bytes` is "no good name is at the byte 12 of
-- `bytes`".
import DnsCore.LabelLoop

open Aeneas Aeneas.Std Result velarx_dns_core

namespace DnsCore

/-- No name can be read from the bytes after the header: they are not the bytes of a good name
followed by anything. -/
def NoName (bytes : List Nat) : Prop :=
  ∀ labels tail, GoodName labels → bytes.drop 12 = OnWire labels ++ tail → False

/-- What `read_name` has read when it is at the byte `off`, `done` or not: some good labels, with
the bytes of the message after the header being those labels on the wire (and the zero, if
`done`) and then the bytes from `off`; the name written so far is those labels, joined by dots, in
lower case; and there is room for the zero that ends the name. -/
def ReadSoFar (bytes : List Nat) (written : alloc.vec.Vec Std.U8) (off : Nat) (done : Bool) :
    Prop :=
  ∃ labels : List (List Nat), (∀ label ∈ labels, GoodLabel label) ∧
    12 ≤ off ∧ off ≤ bytes.length ∧ written.length ≤ off - 12 ∧
    Bytes written.val = Dotted labels ∧
    (done = false → bytes.drop 12 = LabelsOnWire labels ++ bytes.drop off ∧ off - 12 + 1 ≤ 255) ∧
    (done = true → bytes.drop 12 = OnWire labels ++ bytes.drop off ∧ off - 12 ≤ 255)

/-- In plain words: a list is its first byte and the others. The bytes from `off` are the byte
`off` and the bytes from `off + 1`. -/
theorem drop_at_a_byte (bytes : List Nat) (off l : Nat) (is_l : bytes[off]? = some l) :
    bytes.drop off = l :: bytes.drop (off + 1) := by
  rw [List.drop_eq_getElem_cons (by simpa using (List.getElem?_eq_some_iff.mp is_l).1)]
  simp [List.getElem?_eq_some_iff.mp is_l |>.2]

/-- In plain words: the next byte is the length of the next label.  A name that is read from the
bytes after the header, when `read_name` is at the byte `off`, has the label at `off` next: if
the byte `off` is `l` (not 0), the labels after the ones read are a label of `l` bytes, followed
by others, and the bytes after `off` are that label and the rest. -/
theorem the_next_label (bytes : List Nat) (off l : Nat) (more : List (List Nat))
    (tail : List Nat) (is_l : bytes[off]? = some l) (not_the_end : l ≠ 0)
    (rest : bytes.drop off = OnWire more ++ tail) :
    ∃ label more', more = label :: more' ∧ label.length = l ∧
      bytes.drop (off + 1) = label ++ (OnWire more' ++ tail) := by
  have first := drop_at_a_byte bytes off l is_l
  cases more with
  | nil =>
    simp [OnWire, first] at rest
    exact absurd rest.1 not_the_end
  | cons label more' =>
    simp only [OnWire, List.flatMap_cons, List.cons_append, List.append_assoc, first] at rest
    obtain ⟨same_length, same_rest⟩ := List.cons.inj rest
    exact ⟨label, more', rfl, same_length.symm, by simpa [OnWire] using same_rest⟩

/-- In plain words: what is left to read of any good name is what the labels read so far leave.
If the bytes after the header are a good name, and `read_name` is at the byte `off` with the
labels `ReadSoFar`, then the bytes from `off` are the rest of that name (its other labels, the
zero) and what follows, and the name is not longer than 255 bytes with the bytes already read. -/
theorem the_rest_of_the_name (bytes : List Nat) (written : alloc.vec.Vec Std.U8) (off : Nat)
    (state : ReadSoFar bytes written off false) (labels : List (List Nat)) (tail : List Nat)
    (good : GoodName labels) (same_bytes : bytes.drop 12 = OnWire labels ++ tail) :
    ∃ more, bytes.drop off = OnWire more ++ tail ∧ (∀ label ∈ more, GoodLabel label) ∧
      off - 12 + (OnWire more).length ≤ 255 := by
  obtain ⟨done, good_done, at_least, at_most, _, _, reading, _⟩ := state
  obtain ⟨same_so_far, _⟩ := reading rfl
  obtain ⟨more, same_labels, same_rest⟩ := labels_on_wire_split done labels (bytes.drop off) tail
    (fun label inside => (good_done label inside).1) (same_so_far.symm.trans same_bytes)
  have so_far_length : (LabelsOnWire done).length = off - 12 := by
    have := congrArg List.length same_so_far
    simp only [List.length_drop, List.length_append] at this
    omega
  refine ⟨more, same_rest, fun label inside => good.1 label (by simp [same_labels, inside]), ?_⟩
  have := good.2
  simp only [same_labels, OnWire, List.flatMap_append, List.append_assoc,
    List.length_append] at this ⊢
  simp only [LabelsOnWire] at so_far_length
  omega

/-- In plain words: if no good name can go on from here, there is no good name.  No name can be
read when what remains of any good name from `off` is impossible. -/
theorem no_name_when_the_rest_is_impossible (bytes : List Nat) (written : alloc.vec.Vec Std.U8)
    (off : Nat) (state : ReadSoFar bytes written off false)
    (impossible : ∀ more tail, bytes.drop off = OnWire more ++ tail →
      (∀ label ∈ more, GoodLabel label) → off - 12 + (OnWire more).length ≤ 255 → False) :
    NoName bytes := by
  intro labels tail good same_bytes
  obtain ⟨more, rest, good_more, short⟩ :=
    the_rest_of_the_name bytes written off state labels tail good same_bytes
  exact impossible more tail rest good_more short

/-- `read_name` reads the name that follows the header: if it returns with `ok`, the bytes after
the header are a good name and what follows it, the name is the labels in lower case joined by
dots, and the offset is where the name ends; if it returns without, no good name is there. -/
theorem name_loop_reads_the_name (m : Slice Std.U8) (has_a_header : 12 ≤ m.length) :
    read_name_loop0 m (alloc.vec.Vec.new Std.U8) HEADER true false ⦃ r =>
      (r.2.2 = true → ∃ labels, GoodName labels ∧ Bytes r.1.val = Dotted labels ∧
        12 ≤ r.2.1.val ∧ r.2.1.val ≤ m.length ∧
        (Bytes m.val).drop 12 = OnWire labels ++ (Bytes m.val).drop r.2.1.val) ∧
      (r.2.2 = false → NoName (Bytes m.val)) ⦄ := by
  unfold read_name_loop0
  apply loop.spec_decr_nat
    (fun q => if q.2.2.1 = true ∧ q.2.2.2 = false then m.length + 1 - q.2.1.val else 0)
    (fun q => (q.2.2.1 = true → ReadSoFar (Bytes m.val) q.1 q.2.1.val q.2.2.2) ∧
      (q.2.2.1 = false → NoName (Bytes m.val)))
  · rintro ⟨written, off, ok', done'⟩ ⟨state, failed⟩
    simp only at state failed ⊢
    unfold read_name_loop0.body
    have h12 := header_is_12
    have max_name : MAX_NAME.val = 255 := by simp [global_simps]
    have bytes_length : (Bytes m.val).length = m.length := by simp [Bytes]
    split
    · rename_i going
      subst going
      split
      · -- the zero was read before
        rename_i finished
        obtain ⟨labels, good_labels, ge12, within, short, written_is, _, reading⟩ := state rfl
        obtain ⟨same_bytes, room⟩ := reading finished
        have same_length := congrArg List.length same_bytes
        simp only [List.length_drop, List.length_append] at same_length
        simp only [WP.spec_ok]
        refine ⟨fun _ => ⟨labels, ⟨good_labels, by omega⟩, written_is, ge12, by omega,
          same_bytes⟩, fun is_bad => by simp at is_bad⟩
      · rename_i not_finished
        have not_done : done' = false := by simpa using not_finished
        have so_far := state rfl
        rw [not_done] at so_far
        have off_le : off.val ≤ m.length := by
          obtain ⟨_, _, _, within, _⟩ := so_far
          omega
        dsimp only
        split
        · -- the message ends
          rename_i past_the_end
          simp only [WP.spec_ok]
          refine ⟨⟨fun is_ok => by simp at is_ok, fun _ => ?_⟩, ?_⟩
          · refine no_name_when_the_rest_is_impossible _ written off so_far ?_
            intro more tail rest _ _
            have : (Bytes m.val).drop off = [] := by
              apply List.drop_eq_nil_of_le
              scalar_tac
            simp [this, OnWire] at rest
          · simp [not_done]
            omega
        · rename_i inside
          have inside' : off.val < m.length := by scalar_tac
          step as ⟨ i1, i1_post ⟩
          simp only [lift]
          step as ⟨ off1, off1_post ⟩
          have first_byte : (Bytes m.val)[off.val]? =
              some (core.convert.num.FromUsizeU8.from i1).val := by
            simp [Bytes, i1_post, core.convert.num.FromUsizeU8.from_val_eq,
              List.getElem?_eq_getElem inside']
          have l_val := core.convert.num.FromUsizeU8.from_val_eq i1
          generalize core.convert.num.FromUsizeU8.from i1 = l at *
          split
          · -- the zero that ends the name
            rename_i the_end
            have is_zero : l.val = 0 := by simp [the_end]
            rw [is_zero] at first_byte
            have after : (Bytes m.val).drop off = 0 :: (Bytes m.val).drop (off + 1) :=
              drop_at_a_byte _ _ _ first_byte
            obtain ⟨labels, good_labels, ge12, within, short, written_is, reading, _⟩ := so_far
            obtain ⟨same_bytes, room⟩ := reading rfl
            simp only [WP.spec_ok]
            refine ⟨fun _ => ⟨labels, good_labels, by omega, by omega, by omega, written_is,
              fun is_not_done => by simp at is_not_done, fun _ => ⟨?_, by omega⟩⟩,
              fun is_bad => by simp at is_bad, by simp; omega⟩
            rw [same_bytes, after, off1_post]
            simp [OnWire, LabelsOnWire]
          · rename_i not_the_end
            split
            · -- a label of 64 bytes or more
              rename_i too_long
              simp only [WP.spec_ok]
              refine ⟨fun is_ok => by simp at is_ok, fun _ => ?_, by simp [not_done]; omega⟩
              refine no_name_when_the_rest_is_impossible _ written off so_far ?_
              intro more tail rest good_more _
              obtain ⟨label, _, more_is, label_length, _⟩ := the_next_label _ off l.val more tail
                first_byte (by simpa using not_the_end) rest
              have := (good_more label (by simp [more_is])).2.1
              scalar_tac
            · rename_i short_enough
              step as ⟨ i2, i2_post ⟩
              step as ⟨ i3, i3_post ⟩
              step as ⟨ i4, i4_post ⟩
              split
              · -- the name would be over 255 bytes
                rename_i too_big
                simp only [WP.spec_ok]
                refine ⟨fun is_ok => by simp at is_ok, fun _ => ?_, by simp [not_done]; omega⟩
                refine no_name_when_the_rest_is_impossible _ written off so_far ?_
                intro more tail rest _ short
                obtain ⟨label, more', more_is, label_length, _⟩ := the_next_label _ off l.val
                  more tail first_byte (by simpa using not_the_end) rest
                simp only [more_is, OnWire, List.flatMap_cons, List.append_assoc,
                  List.length_append, List.length_cons, label_length] at short
                scalar_tac
              · rename_i fits
                step as ⟨ i5, i5_post ⟩
                split
                · -- the label is cut
                  rename_i cut
                  simp only [WP.spec_ok]
                  refine ⟨fun is_ok => by simp at is_ok, fun _ => ?_, by simp [not_done]; omega⟩
                  refine no_name_when_the_rest_is_impossible _ written off so_far ?_
                  intro more tail rest _ _
                  obtain ⟨label, more', more_is, label_length, after_the_byte⟩ :=
                    the_next_label _ off l.val more tail first_byte (by simpa using not_the_end)
                      rest
                  have := congrArg List.length after_the_byte
                  simp only [List.length_drop, List.length_append, label_length] at this
                  scalar_tac
                · rename_i whole
                  have fits' : i4.val ≤ 255 := by scalar_tac
                  have whole' : off1.val + l.val ≤ m.length := by scalar_tac
                  have l_pos : 1 ≤ l.val := by scalar_tac
                  have l_small : l.val ≤ 63 := by scalar_tac
                  have state_now := so_far
                  obtain ⟨labels, good_labels, ge12, within, short, written_is, reading, _⟩ :=
                    so_far
                  obtain ⟨same_bytes, room⟩ := reading rfl
                  -- a dot goes before the label if there is one before it
                  step as ⟨ empty, empty_says ⟩
                  have nothing_written : empty = true ↔ labels = [] := by
                    rw [empty_says]
                    have := dotted_is_empty_only_without_labels labels good_labels
                    rw [← this, ← written_is]
                    simp [Bytes]
                  have room_for_dot : written.length + 1 < Usize.max := by scalar_tac
                  have wrote_dot : (if empty = true then ok written
                      else written.push 46#u8) ⦃ name1 =>
                      Bytes name1.val = Dotted labels ++ (if labels = [] then [] else [46]) ∧
                      name1.length ≤ written.length + 1 ⦄ := by
                    by_cases is_empty : empty = true
                    · simp [is_empty, nothing_written.mp is_empty, written_is]
                    · have has_labels : ¬ labels = [] := fun h => is_empty (nothing_written.mpr h)
                      simp only [is_empty, has_labels, Bool.false_eq_true, ↓reduceIte]
                      step as ⟨ name1, name1_post ⟩
                      simp [Bytes, name1_post]
                      exact written_is
                  step with wrote_dot as ⟨ name1, name1_bytes, name1_length ⟩
                  step with label_loop_reads_the_label m name1 off1 l whole' (by scalar_tac)
                    as ⟨ inner, inner_ok, inner_good, inner_failed ⟩
                  step as ⟨ off2, off2_post ⟩
                  have len_same : (↑m : List Std.U8).length = m.length := rfl
                  have label_length : (LabelAt m off1 l).length = l.val := by
                    simp [LabelAt]
                    omega
                  have next_bytes : (Bytes m.val).drop off = l.val :: (LabelAt m off1 l ++
                      (Bytes m.val).drop off2.val) := by
                    rw [drop_at_a_byte _ _ _ first_byte, ← off1_post]
                    refine congrArg (l.val :: ·) ?_
                    unfold LabelAt
                    conv_lhs => rw [← List.take_append_drop l.val ((Bytes m.val).drop off1.val)]
                    rw [List.drop_drop, off2_post]
                  refine ⟨fun is_ok => ?_, fun is_bad => ?_, ?_⟩
                  · -- the label is read, and the name goes on
                    obtain ⟨inner_bytes, label_good⟩ := inner_good is_ok
                    rw [not_done]
                    have inner_length := congrArg List.length inner_bytes
                    simp only [Bytes, List.length_map, List.length_append] at inner_length
                    refine ⟨labels ++ [LabelAt m off1 l], ?_, by omega, by omega, ?_, ?_,
                      fun _ => ⟨?_, by omega⟩, fun h => by simp at h⟩
                    · intro label inside
                      rcases List.mem_append.mp inside with before | now
                      · exact good_labels label before
                      · rw [List.mem_singleton.mp now]
                        exact ⟨by omega, by omega, label_good⟩
                    · have same_inner : inner.length = (↑inner : List Std.U8).length := rfl
                      have same_name1 : name1.length = (↑name1 : List Std.U8).length := rfl
                      omega
                    · rw [dotted_snoc, inner_bytes, name1_bytes]
                      by_cases no_labels : labels = [] <;> simp [no_labels, Dotted, Joined]
                    · rw [labels_on_wire_snoc, same_bytes, next_bytes, label_length]
                      simp
                  · -- a byte that cannot be in a label: no name
                    refine no_name_when_the_rest_is_impossible _ written off state_now ?_
                    intro more tail rest good_more _
                    obtain ⟨label, more', more_is, label_is_l, after_the_byte⟩ :=
                      the_next_label _ off l.val more tail first_byte (by simpa using not_the_end)
                      rest
                    obtain ⟨c, in_label, bad_byte⟩ := inner_failed is_bad
                    have same_label : label = LabelAt m off1 l := by
                      have next_label : (Bytes m.val).drop (off.val + 1) =
                          LabelAt m off1 l ++ (Bytes m.val).drop off2.val := by
                        have := drop_at_a_byte _ _ _ first_byte
                        rw [this] at next_bytes
                        exact (List.cons.inj next_bytes).2
                      rw [next_label] at after_the_byte
                      exact (List.append_inj after_the_byte.symm (by omega)).1
                    rw [← same_label] at in_label
                    have := (good_more label (by simp [more_is])).2.2 c in_label
                    omega
                  · by_cases inner_is_ok : inner_ok = true
                    · simp [inner_is_ok, not_done]
                      omega
                    · simp [inner_is_ok]
                      omega
    · rename_i stopped
      have not_ok : ok' = false := by simpa using stopped
      simp only [WP.spec_ok]
      exact ⟨fun is_ok => by simp [not_ok] at is_ok, fun _ => failed not_ok⟩
  · have h12 := header_is_12
    have bytes_length : (Bytes m.val).length = m.length := by simp [Bytes]
    simp only
    refine ⟨fun _ => ⟨[], by simp, by omega, by omega, by simp, by simp [Bytes, Dotted, Joined],
      fun _ => ⟨by simp [LabelsOnWire, h12], by omega⟩, fun h => by simp at h⟩,
      fun h => by simp at h⟩

end DnsCore
