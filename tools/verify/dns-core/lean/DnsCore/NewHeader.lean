-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: what `reply` makes of the bytes it has written (the question and the
-- records) when it writes the flags and the counts into the header: the same bytes with the bytes
-- 2, 3 and 6 to 11 changed (`NewHeader`), and what that does to each number of the header.
--
-- Why it is needed: `reply` writes the header last, with four calls of `put16`; the claims are
-- about the numbers of the header of the result, so this file reads them off the four changes.
--
-- Read before this file: Words.lean.
--
-- Notation: `l.set k a` is `l` with its element `k` replaced by `a`; `Word b k` is the number of
-- the bytes `k` and `k + 1` of `b` (Spec.lean).
import DnsCore.Words

open Aeneas Aeneas.Std Result velarx_dns_core

namespace DnsCore

/-- `put16` writes the number `v` into the bytes `k` and `k + 1`, as two changes of one byte. -/
theorem put16_sets (out : Slice Std.U8) (k : Std.Usize) (v : Std.U16)
    (inside : k.val + 2 ≤ out.length) :
    put16 out k v ⦃ r =>
      Bytes r.val = ((Bytes out.val).set k.val (v.val / 256)).set (k.val + 1) (v.val % 256) ⦄ := by
  apply WP.spec_mono (put16_writes out k v inside)
  intro r written
  rw [written, set_two _ _ _ _ (by simpa [Bytes] using inside)]

/-- The four numbers `reply` writes into the header of the message that has the bytes of the
query and of the records: the flags, the number of records, and two zeros. -/
def NewHeader (header : List Nat) (flags count : Nat) : List Nat :=
  ((((((((header.set 2 (flags / 256)).set 3 (flags % 256)).set 6 (count / 256)).set 7
    (count % 256)).set 8 0).set 9 0).set 10 0).set 11 0)

/-- What the new header has: the length it had, its first two bytes and its question count, the
flags and the number of records written in, the other two counts zero, and the rest of the
message as it was. -/
theorem new_header_says (header : List Nat) (flags count : Nat) (long_enough : 12 ≤ header.length)
    (flags_fit : flags < 65536) (count_fits : count < 65536) :
    (NewHeader header flags count).length = header.length ∧
    Word (NewHeader header flags count) 0 = Word header 0 ∧
    Word (NewHeader header flags count) 2 = flags ∧
    Word (NewHeader header flags count) 4 = Word header 4 ∧
    Word (NewHeader header flags count) 6 = count ∧
    Word (NewHeader header flags count) 8 = 0 ∧
    Word (NewHeader header flags count) 10 = 0 ∧
    (NewHeader header flags count).drop 12 = header.drop 12 := by
  unfold NewHeader
  match header, long_enough with
  | a0 :: a1 :: a2 :: a3 :: a4 :: a5 :: a6 :: a7 :: a8 :: a9 :: a10 :: a11 :: rest, _ =>
    have := flags_fit
    have := count_fits
    simp [Word]
    omega

end DnsCore
