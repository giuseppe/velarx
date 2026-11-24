-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: what the inner loop of `read_name` does (`read_name_loop0_loop0`): it
-- copies the bytes of one label into the name, as lower case, and stops at a dot or a NUL.
--
-- Why it is needed: this is where the name in lower case is made and where a dot or a NUL in a
-- label
-- is refused; the loop of the labels (NameLoop.lean) uses what it says.
--
-- Read before this file: Spec.lean, Words.lean, WireNames.lean.
--
-- Notation: `loop.spec_decr_nat` proves that a loop returns because a number goes down at each turn
-- and a fact (the invariant) is kept by each turn; `split` makes one case of each `if`; `step as
-- ⟨ x, hx ⟩` runs one Rust line and names its result `x` and what is known of it `hx`; `LabelAt m
-- off l` is the `l` bytes of the message from the byte `off`.
import DnsCore.Words
import DnsCore.WireNames

open Aeneas Aeneas.Std Result velarx_dns_core

namespace DnsCore

/-- The bytes of the label of `l` bytes at `off` in the message, as numbers. -/
def LabelAt (m : Slice Std.U8) (off l : Nat) : List Nat :=
  ((Bytes m.val).drop off).take l

/-- The byte `i` of the label is the byte `off + i` of the message. -/
theorem label_byte (m : Slice Std.U8) (off l i : Nat) (c : Std.U8) (inside : i < l)
    (is_c : m.val[off + i]? = some c) : (LabelAt m off l)[i]? = some c.val := by
  simp [LabelAt, List.getElem?_take_of_lt inside, List.getElem?_drop, Bytes, is_c]

/-- The inner loop of `read_name` (`read_name_loop0_loop0`) goes through the `l` bytes of the label
at `off`: it says `true` when none of them is a dot or a NUL, and then it has written them after
the name written so far, each in lower case; it says `false` when one of them is. -/
theorem label_loop_reads_the_label (m : Slice Std.U8) (written : alloc.vec.Vec Std.U8)
    (off l : Std.Usize) (label_is_there : off.val + l.val ≤ m.length)
    (room : written.length + l.val ≤ 255) :
    read_name_loop0_loop0 m written off true l 0#usize ⦃ r =>
      (r.2 = true → Bytes r.1.val = Bytes written.val ++ (LabelAt m off l).map Lower ∧
        ∀ c ∈ LabelAt m off l, c ≠ 46 ∧ c ≠ 0) ∧
      (r.2 = false → ∃ c ∈ LabelAt m off l, c = 46 ∨ c = 0) ⦄ := by
  unfold read_name_loop0_loop0
  apply loop.spec_decr_nat (fun q => if q.2.1 = true then l.val + 1 - q.2.2.val else 0)
    (fun q => q.2.2.val ≤ l.val ∧ q.1.length ≤ written.length + q.2.2.val ∧
      (q.2.1 = true → Bytes q.1.val = Bytes written.val ++
          ((LabelAt m off l).take q.2.2.val).map Lower ∧
        ∀ c ∈ (LabelAt m off l).take q.2.2.val, c ≠ 46 ∧ c ≠ 0) ∧
      (q.2.1 = false → ∃ c ∈ LabelAt m off l, c = 46 ∨ c = 0))
  · rintro ⟨written', ok', i⟩ ⟨i_le, short, good, bad⟩
    simp only at i_le short good bad ⊢
    unfold read_name_loop0_loop0.body
    split
    · rename_i going
      split
      · rename_i below
        step as ⟨ i1, i1_post ⟩
        step as ⟨ c, c_post ⟩
        have below' : i.val < l.val := by scalar_tac
        have c_is : (LabelAt m off l)[i.val]? = some c.val := by
          refine label_byte m off l i c (by scalar_tac) ?_
          rw [← i1_post]
          simp [c_post]
        have c_inside : c.val ∈ LabelAt m off l := List.mem_iff_getElem?.mpr ⟨i.val, c_is⟩
        split
        · -- a dot
          rename_i is_dot
          have c_val : c.val = 46 := by simp [is_dot]
          simp only [WP.spec_ok]
          exact ⟨i_le, short, by simp, fun _ => ⟨c.val, c_inside, Or.inl c_val⟩, by simp; omega⟩
        split
        · -- a zero
          rename_i is_zero
          have c_val : c.val = 0 := by simp [is_zero]
          simp only [WP.spec_ok]
          exact ⟨i_le, short, by simp, fun _ => ⟨c.val, c_inside, Or.inr c_val⟩, by simp; omega⟩
        · -- a byte of the label
          rename_i not_dot not_zero
          have c_not_dot : c.val ≠ 46 := fun is_dot =>
            not_dot (UScalar.eq_of_val_eq (by simpa using is_dot))
          have c_not_zero : c.val ≠ 0 := fun is_zero =>
            not_zero (UScalar.eq_of_val_eq (by simpa using is_zero))
          have room_left : written'.length + 1 < Usize.max := by scalar_tac
          -- the byte is written in lower case: a capital letter (65 to 90) becomes a small one
          have wrote : (if c >= 65#u8 then
                if c <= 90#u8 then do
                  let i2 ← c + 32#u8
                  written'.push i2
                else written'.push c
              else written'.push c) ⦃ name1 =>
                Bytes name1.val = Bytes written'.val ++ [Lower c.val] ∧
                name1.length = written'.length + 1 ⦄ := by
            split
            · rename_i low
              have is_low : 65 ≤ c.val := by scalar_tac
              split
              · rename_i high
                have is_high : c.val ≤ 90 := by scalar_tac
                step as ⟨ small, small_post ⟩
                step as ⟨ name1, name1_post ⟩
                simp [name1_post, Bytes, small_post, Lower, is_low, is_high]
              · rename_i high
                have not_high : ¬ c.val ≤ 90 := by scalar_tac
                step as ⟨ name1, name1_post ⟩
                simp [name1_post, Bytes, Lower, not_high]
            · rename_i low
              have not_low : ¬ 65 ≤ c.val := by scalar_tac
              step as ⟨ name1, name1_post ⟩
              simp [name1_post, Bytes, Lower, not_low]
          step with wrote as ⟨ name1, name1_bytes, name1_length ⟩
          step as ⟨ i2, i2_post ⟩
          refine ⟨by omega, by omega, fun is_ok => ?_, fun is_bad => by simp [going] at is_bad,
            by simp [going]; omega⟩
          obtain ⟨old_bytes, old_good⟩ := good is_ok
          have taken : (LabelAt m off l).take (i.val + 1) =
              (LabelAt m off l).take i.val ++ [c.val] := by
            rw [List.take_add_one, c_is]
            rfl
          rw [i2_post, taken, name1_bytes, old_bytes, List.map_append]
          refine ⟨by simp, fun d inside => ?_⟩
          rcases List.mem_append.mp inside with before | now
          · exact old_good d before
          · rw [List.mem_singleton.mp now]
            exact ⟨c_not_dot, c_not_zero⟩
      · -- every byte of the label was looked at
        rename_i not_below
        have at_end : i.val = l.val := by scalar_tac
        have whole : (LabelAt m off l).take i.val = LabelAt m off l := by
          rw [at_end]
          exact List.take_of_length_le (by simp [LabelAt])
        simp only [WP.spec_ok]
        refine ⟨fun _ => ?_, fun is_bad => by simp [going] at is_bad⟩
        have := good going
        rwa [whole] at this
    · -- a byte that cannot be in a label was found
      rename_i stopped
      have not_ok : ok' = false := by simpa using stopped
      simp only [WP.spec_ok]
      exact ⟨fun is_ok => by simp [not_ok] at is_ok, fun _ => bad not_ok⟩
  · simp
