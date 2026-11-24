-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: what `error_reply` builds: 12 bytes, the id, the flags, and zeros.
--
-- Why it is needed: this is the proof of `ErrorReplyIsAHeader`.
--
-- Read before this file: Spec.lean, Words.lean, Flags.lean, and `error_reply` in lib.rs.
--
-- Notation: as in Words.lean.
import DnsCore.Flags
import DnsCore.Words

open Aeneas Aeneas.Std Result velarx_dns_core

namespace DnsCore

/-- What `get16` reads, or 0 when it reads nothing, is the number of the bytes there (`Word`). -/
theorem unwrapped_word (m : Slice Std.U8) (k : Std.Usize) (o : Option Std.U16)
    (read : ∀ v, o = some v → k.val + 2 ≤ m.length ∧ v.val = Word (Bytes m.val) k.val)
    (missing : o = none → ¬ k.val + 2 ≤ m.length) :
    (core.option.Option.unwrap_or o 0#u16).val = Word (Bytes m.val) k.val := by
  cases o with
  | none => simp [Word, missing rfl]
  | some v => simp [(read v rfl).2]

/-- `error_reply` is a header: 12 bytes, the number of the query first (0 if it has none), then
the flags (the response bit, the recursion available bit, the recursion desired bit of the query,
the code), and no other section. -/
theorem error_reply_is_a_header (m : Slice Std.U8) (rcode : Std.U16) :
    error_reply m rcode ⦃ r =>
      r.length = 12 ∧ Word (Bytes r.val) 0 = Word (Bytes m.val) 0 ∧
      Word (Bytes r.val) 2 =
        32768 + 128 + 256 * Bit (Word (Bytes m.val) 2) 8 + rcode.val % 16 ∧
      (Bytes r.val).drop 4 = List.replicate 8 0 ⦄ := by
  unfold error_reply
  have h12 := header_is_12
  step with get16_reads m 2#usize as ⟨ flags_o, flags_read, flags_missing ⟩
  simp only [lift, bind_ok]
  step as ⟨ blank, blank_is, blank_length ⟩
  simp only [alloc.vec.Vec.deref_mut]
  step with get16_reads m 0#usize as ⟨ id_o, id_read, id_missing ⟩
  have blank_slice : blank.slice.length = 12 := by
    rw [← h12]
    exact blank_length
  step with put16_writes blank.slice 0#usize (core.option.Option.unwrap_or id_o 0#u16)
    (by scalar_tac) as ⟨ with_id, with_id_is ⟩
  have id_is := unwrapped_word m 0#usize id_o id_read id_missing
  have flags_is := unwrapped_word m 2#usize flags_o flags_read flags_missing
  have blank_bytes : Bytes blank.slice.val = List.replicate 12 0 := by
    simp [Bytes, ← h12, show blank.slice.val = blank.val from rfl, blank_is]
  have with_id_bytes : Bytes with_id.val = [(Word (Bytes m.val) 0) / 256,
      (Word (Bytes m.val) 0) % 256] ++ List.replicate 10 0 := by
    rw [with_id_is, blank_bytes]
    simp [id_is]
  have with_id_length : with_id.length = 12 := by
    have := congrArg List.length with_id_bytes
    simpa using this
  step with put16_writes with_id 2#usize _ (by scalar_tac) as ⟨ done, done_is ⟩
  have flags_value := base_flags_value (core.option.Option.unwrap_or flags_o 0#u16) rcode
  simp only [flags_is] at flags_value
  rw [flags_value] at done_is
  have done_bytes : Bytes done.val = [Word (Bytes m.val) 0 / 256, Word (Bytes m.val) 0 % 256,
      (32768 + 128 + 256 * Bit (Word (Bytes m.val) 2) 8 + rcode.val % 16) / 256,
      (32768 + 128 + 256 * Bit (Word (Bytes m.val) 2) 8 + rcode.val % 16) % 256] ++
      List.replicate 8 0 := by
    rw [done_is, with_id_bytes]
    simp [List.replicate]
  have done_length := congrArg List.length done_bytes
  simp only [bytes_length, List.length_append, List.length_cons, List.length_nil,
    List.length_replicate] at done_length
  show done.length = 12 ∧ Word (Bytes done.val) 0 = _ ∧ Word (Bytes done.val) 2 = _ ∧
    (Bytes done.val).drop 4 = _
  rw [done_bytes]
  refine ⟨by omega, ?_, ?_, by simp⟩
  · simp [Word, List.replicate]
    omega
  · simp [Word, List.replicate]
    omega
