-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: what the three small functions of the crate that read and write a 16-bit
-- number (`get16`, `put16`, `push16`) do, in terms of `Word` (Spec.lean), and a few facts about
-- `Word`, the length of a vector and `HEADER` that the proofs of the other files need.
--
-- Why it is needed: every field of a DNS header is read or written by these functions, so each
-- claim about a header goes through them.  After this file nobody looks at a shift or an or of a
-- byte again.
--
-- Read before this file: Spec.lean (`Bytes`, `Word`).
--
-- Notation: `f x ⦃ r => P r ⦄` is "the Rust function `f` returns, and its result `r` satisfies
-- `P r`"; `step with t as ⟨ x, hx ⟩` (in the later files) runs one line of a Rust function with the
-- fact `t` about it and names its result `x` and what is known of it `hx`; `x.val` is the number
-- a machine integer is; `v.val` is the list inside a vector or a slice.
import DnsCore.Spec
import DnsCore.ByteLists

open Aeneas Aeneas.Std Result velarx_dns_core

namespace DnsCore

/-- `HEADER` is 12. -/
theorem header_is_12 : HEADER.val = 12 := by
  simp [global_simps]

/-- The length of a vector is the length of the list inside it. -/
theorem vec_length_is_the_list_length {α : Type} (v : alloc.vec.Vec α) :
    v.length = v.val.length := rfl

/-- A message and its bytes as numbers have the same length. -/
@[simp] theorem bytes_length (bytes : List Std.U8) : (Bytes bytes).length = bytes.length := by
  simp [Bytes]

/-- What is added at the end of a vector makes it that much longer. -/
theorem length_after_adding (before after : alloc.vec.Vec Std.U8) (added : List Nat)
    (is_added : Bytes after.val = Bytes before.val ++ added) :
    after.length = before.length + added.length := by
  have := congrArg List.length is_added
  simp only [bytes_length, List.length_append] at this
  rw [vec_length_is_the_list_length, vec_length_is_the_list_length]
  exact this

/-- One byte added at the end of a vector makes it one byte longer. -/
theorem length_after_adding_a_byte (before after : alloc.vec.Vec Std.U8) (added : Nat)
    (is_added : Bytes after.val = Bytes before.val ++ [added]) :
    after.length = before.length + 1 :=
  length_after_adding before after [added] is_added

/-- The number at the place `j` of the bytes from `k` is the number at the place `k + j`. -/
theorem word_of_the_rest (bytes : List Nat) (k j : Nat) :
    Word (bytes.drop k) j = Word bytes (k + j) := by
  simp only [Word, List.length_drop, List.getD_eq_getElem?_getD, List.getElem?_drop,
    Nat.add_assoc]
  by_cases there : k + (j + 2) ≤ bytes.length
  · have : j + 2 ≤ bytes.length - k := by omega
    simp [there, this]
  · have : ¬ j + 2 ≤ bytes.length - k := by omega
    simp [there, this]

/-- The number at the place `k` of a message is the same in a message that goes on after it. -/
theorem word_of_a_beginning (bytes more : List Nat) (k : Nat) (inside : k + 2 ≤ bytes.length) :
    Word (bytes ++ more) k = Word bytes k := by
  simp only [Word, List.length_append, List.getD_eq_getElem?_getD]
  have : k + 2 ≤ bytes.length + more.length := by omega
  simp [inside, this, List.getElem?_append_left (by omega : k < bytes.length),
    List.getElem?_append_left (by omega : k + 1 < bytes.length)]

/-- The number at the place `k` of the first `n` bytes of a message, if both its bytes are there,
is the number in the message. -/
theorem word_of_a_prefix (bytes : List Nat) (n k : Nat) (inside : k + 2 ≤ n)
    (short : n ≤ bytes.length) : Word (bytes.take n) k = Word bytes k := by
  simp only [Word, List.length_take, List.getD_eq_getElem?_getD]
  have : k + 2 ≤ bytes.length := by omega
  simp [List.getElem?_take_of_lt (by omega : k < n),
    List.getElem?_take_of_lt (by omega : k + 1 < n),
    this, show k + 2 ≤ min n bytes.length by omega]

/-- `get16` reads the two bytes at `k` as one number, big end first (`Word`), when there are two
there, and says `None` when there are not. -/
theorem get16_reads (m : Slice Std.U8) (k : Std.Usize) :
    get16 m k ⦃ r =>
      (∀ v, r = some v → k.val + 2 ≤ m.length ∧ v.val = Word (Bytes m.val) k.val) ∧
      (r = none → ¬ k.val + 2 ≤ m.length) ⦄ := by
  unfold get16
  step*
  simp only [lift]
  step*
  have high := i3.hBounds
  have low := i7.hBounds
  have within : k.val + 2 ≤ m.length := by scalar_tac
  refine ⟨fun v is_v => ?_, fun is_none => by simp at is_none⟩
  cases is_v
  refine ⟨within, ?_⟩
  have i3_val : i3.val = (Bytes m.val).getD k.val 0 := by
    simp [i3_post, Bytes, List.getD_eq_getElem?_getD,
      List.getElem?_eq_getElem (by scalar_tac : k.val < m.val.length)]
  have i7_val : i7.val = (Bytes m.val).getD (k.val + 1) 0 := by
    simp [i7_post, i6_post, Bytes, List.getD_eq_getElem?_getD,
      List.getElem?_eq_getElem (by scalar_tac : k.val + 1 < m.val.length)]
  simp only [UScalar.val_or, i5_post, core.convert.num.FromU16U8.from_val_eq, Word]
  have high' : i3.val < 256 := by simpa using high
  have low' : i7.val < 256 := by simpa using low
  have shifted : i3.val <<< 8 % U16.size = i3.val * 256 := by
    rw [Nat.shiftLeft_eq]
    exact Nat.mod_eq_of_lt (by scalar_tac)
  rw [shifted, or_byte _ _ low']
  simp [Bytes, within, i3_val, i7_val]

/-- `put16` writes the number `v` into the bytes `k` and `k + 1`, big end first, and leaves the
others as they were (when the two bytes are there). -/
theorem put16_writes (out : Slice Std.U8) (k : Std.Usize) (v : Std.U16)
    (inside : k.val + 2 ≤ out.length) :
    put16 out k v ⦃ r =>
      Bytes r.val = (Bytes out.val).take k.val ++ [v.val / 256, v.val % 256] ++
        (Bytes out.val).drop (k.val + 2) ⦄ := by
  unfold put16
  step*
  have hv : v.val < 65536 := by scalar_tac
  have high : i1.val = v.val / 256 := by
    simp [i1_post, UScalar.cast_val_eq, i_post, Nat.shiftRight_eq_div_pow]
    omega
  have low : i4.val = v.val % 256 := by
    simp [i4_post, UScalar.cast_val_eq, i2_post, and_255]
  rw [r_post, out1_post]
  simp only [Slice.set_val_eq, Bytes, List.map_set, i3_post, high, low]
  exact set_two _ _ _ _ (by simpa [Bytes] using inside)

/-- `push16` adds the number `v` at the end, big end first. -/
theorem push16_writes (out : alloc.vec.Vec Std.U8) (v : Std.U16)
    (room : out.length + 2 ≤ Std.Usize.max) :
    push16 out v ⦃ r => Bytes r.val = Bytes out.val ++ [v.val / 256, v.val % 256] ⦄ := by
  unfold push16
  step*
  · rw [out1_post]
    simp only [List.length_append, List.length_singleton]
    scalar_tac
  have hv : v.val < 65536 := by scalar_tac
  have high : i1.val = v.val / 256 := by
    simp [i1_post, UScalar.cast_val_eq, i_post, Nat.shiftRight_eq_div_pow]
    omega
  have low : i3.val = v.val % 256 := by
    simp [i3_post, UScalar.cast_val_eq, i2_post, and_255]
  simp [Bytes, r_post, out1_post, high, low]

end DnsCore
