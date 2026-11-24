-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: what is proved of crates/tarsplit-header, the
-- arithmetic of a tar header (the number fields, the padding of an entry,
-- the records of a PAX header, the CRC-64) and the arithmetic of writing a
-- canonical tar (`emit.rs`: the number fields, the length of a record, the
-- order of the paths), in words and in statements, with no proof.  This file
-- and ../Models.lean are what a reviewer reads; Lean checks the rest (the
-- proofs are in Cstr.lean, Number.lean, Padding.lean, Crc64.lean, Pax.lean,
-- Emit.lean and Order.lean).
--
-- Why it is needed: a proof is worth what its statement says.  Each
-- statement here is a `def ... : Prop`: a claim, which `Theorems.lean`
-- asks Lean to prove.  Each has a comment of what it claims and of what it
-- does NOT.  The few definitions before the claims (`octalValue`,
-- `decimalValue`, `numDigits`, `compareComponents` and what it is made of) are
-- their only vocabulary.  This code reads archives that are not trusted, so the
-- first claim of each function is that it NEVER panics and never overflows,
-- whatever bytes it is given: the Rust arithmetic Aeneas translates stops
-- (panics) on an overflow, so "it returns" is also "nothing overflowed".
--
-- Not proved here: `checksum_ok`.  It adds up the 512 bytes of a header
-- (at most 512 * 255 or -512 * 128, far from an overflow) and reads its
-- field with `number`; a proof needs three more models of the library.
--
-- Read before this file: lib.rs, crc64.rs and emit.rs of
-- crates/tarsplit-header, then ../Models.lean.
--
-- Index.  What each claim is about (the Rust function of crates/tarsplit-header), what is
-- trusted, and what is not claimed, in one place.
--
--   Claimed (each says: the function returns, whatever the bytes, and ...):
--     CstrIsThePrefixToTheFirstNul      cstr
--     NumberOfBlanksIsZero              number
--     NumberOfOctalDigitsIsTheirValue   number
--     NumberNeverFails                  number
--     PaddingFillsTheBlock              padding
--     Crc64NeverFails                   crc64::update
--     DecimalNeverFails                 decimal
--     PaxTimeNeverFails                 pax_time
--     PaxRecordStaysInside              pax_record
--     PutOctalFitsOrIsRefused           emit::put_octal
--     PutOctalWritesTheDigits           emit::put_octal
--     PutOctalIsReadBack                emit::put_octal, number
--     PutDecimalWritesTheDigits         emit::put_decimal
--     DecimalOfDigitsIsTheirValue       decimal
--     RecordLenCountsItself             emit::record_len
--     PathOrderIsByComponents           emit::path_order
--     ComponentOrderIsStrictTotal       (the order PathOrderIsByComponents names)
--
--   Trusted (the proofs rest on them, and a reviewer cannot see them in a statement):
--     - Charon and Aeneas: that the Lean is what the Rust does (../../pins);
--     - the models of the standard library Aeneas itself has (the integer operations and their
--       overflow rule, `Vec` and slice indexing): nothing prints them;
--     - the five models of ../Models.lean: `RangeInclusive::contains`,
--       `checked_next_multiple_of`, the two halves of `?` on an `Option`, and `as_chunks`;
--     - no function of std is left without a model: `run` prints none.
--
--   Not claimed: `checksum_ok` (above); that `pax_time` and `pax_record` read the number or the
--   record that the bytes spell (`decimal` is claimed only on digits), and that `crc64::update` is the CRC-64 of the ISO
--   polynomial (the unit tests check these); anything of a header as a whole; of `emit.rs`, the
--   checksum `seal` and the PAX time `put_time` (the unit tests check them).
--
--   To check that a claim is not trivial: (a) it is about every input, so there is no
--   hypothesis to reach (but the room of a vector, below); (b) put in a bug the claim excludes, by hand in
--   crates/tarsplit-header, and `tools/verify/run tarsplit-header` must fail; (c) take a
--   conjunct out of the conclusion, or make it stronger, and `run` must fail.
--
--   To see what `padding` looks like to Lean, side by side with the Rust: run
--   `tools/verify/run tarsplit-header`, then read
--   $VERIFY_CACHE/tarsplit-header/work/Extracted/Funs.lean (the functions, `padding` among
--   them, as Aeneas wrote them) and Types.lean (the types); `run` prints the directory when
--   it ends.  Nothing generated is in the tree.
--
-- Notation:
--   - `f x ⦃ r => P r ⦄` reads: the Rust function `f`, given `x`,
--     returns (it does not panic, it does not loop for ever) and the
--     result `r` satisfies `P r`.
--   - `∀ x, P` is "for every x, P"; `∃ x, P` is "there is an x such that
--     P"; `∧` is "and", `→` is "if ... then"; `∈` is "is an element of".
--   - `field.val` is the list of the bytes of a slice; `l ++ m` joins two
--     lists; `l.takeWhile p` is the longest beginning of `l` whose elements
--     all satisfy `p`; `0#u8` is the byte 0, `n#u64` the 64-bit number `n`;
--     `b.val` is the number a byte `b` is.
import Extracted.Funs

open Aeneas Aeneas.Std Result velarx_tarsplit_header

namespace TarsplitHeader

/-- The number the octal digits `ds` (bytes `'0'` to `'7'`) spell, most
significant first: `"17"` is `8 * 1 + 7`. -/
def octalValue (ds : List Std.U8) : Nat :=
  ds.foldl (fun v d => 8 * v + (d.val - 48)) 0

/-- The number the decimal digits `ds` (bytes `'0'` to `'9'`) spell, most
significant first: `"17"` is `10 * 1 + 7`. -/
def decimalValue (ds : List Std.U8) : Nat :=
  ds.foldl (fun v d => 10 * v + (d.val - 48)) 0

/-- The number of decimal digits of `n`: 0 and 7 have one, 10 has two. -/
def numDigits (n : Nat) : Nat := Nat.log 10 n + 1

/-- The comparison of two lists from the front: the first place where they differ decides,
by `cmp`; a list that is the beginning of the other is the smaller; the same list is `.eq`. -/
def lexCompare {α : Type} (cmp : α → α → Ordering) : List α → List α → Ordering
  | [], [] => .eq
  | [], _ :: _ => .lt
  | _ :: _, [] => .gt
  | x :: xs, y :: ys => (cmp x y).then (lexCompare cmp xs ys)

/-- The comparison of two bytes as numbers. -/
def compareBytes (a b : Std.U8) : Ordering := compare a.val b.val

/-- The piece of a path before its first `/` (the `/` byte is 47), and the pieces after it. -/
def pieces : List Std.U8 → List Std.U8 × List (List Std.U8)
  | [] => ([], [])
  | x :: xs =>
    let (first, rest) := pieces xs
    if x = 47#u8 then ([], first :: rest) else (x :: first, rest)

/-- The components of a path: the pieces between its `/`, as `split('/')` gives them (`"a/b"` is
`["a", "b"]`, `""` is `[""]`, `"a/"` is `["a", ""]`). -/
def components (path : List Std.U8) : List (List Std.U8) :=
  (pieces path).1 :: (pieces path).2

/-- The comparison of two paths by their components, one after the other, each component
compared as its bytes (`lexCompare` of `compareBytes`). -/
def compareComponents (a b : List Std.U8) : Ordering :=
  lexCompare (lexCompare compareBytes) (components a) (components b)

/-- **`cstr` is the bytes up to the first NUL.**  For any field, `cstr`
returns the bytes of the field before its first NUL byte, all of them if
there is none.

Not said: that the result is a view of the field and not a copy (the Rust
type says it), nor anything of the bytes after the NUL. -/
def CstrIsThePrefixToTheFirstNul : Prop :=
  ∀ field : Slice Std.U8,
    cstr field ⦃ r => r.val = field.val.takeWhile (· != 0#u8) ⦄

/-- **A blank number field is 0.**  A field of only spaces and NULs, or an
empty one, is read by `number` as 0 (the documented value of "nothing at
all").

Not said: any other field. -/
def NumberOfBlanksIsZero : Prop :=
  ∀ field : Slice Std.U8, (∀ b ∈ field.val, b = 0#u8 ∨ b = 32#u8) →
    number field ⦃ r => r = core.result.Result.Ok 0#u64 ⦄

/-- **Octal digits are their value.**  A field of octal digits (bytes `'0'`
to `'7'`) followed by a NUL, whatever follows the NUL, is read by `number` as
the number the digits spell if it fits in 64 bits, and refused as an overflow
if it does not.  Never as a wrong number: no bit is lost.

Not said: digits that fill the field with no NUL after them, digits with
spaces around them, or base 256 (the claim below says only that these do
not panic). -/
def NumberOfOctalDigitsIsTheirValue : Prop :=
  ∀ (field : Slice Std.U8) (ds rest : List Std.U8),
    field.val = ds ++ 0#u8 :: rest → (∀ d ∈ ds, 48 ≤ d.val ∧ d.val ≤ 55) →
    number field ⦃ r =>
      if octalValue ds < 2 ^ 64 then
        ∃ n : Std.U64, r = core.result.Result.Ok n ∧ n.val = octalValue ds
      else r = core.result.Result.Err NumError.Overflow ⦄

/-- **`number` never panics.**  For any field, of any length (empty too)
and with any bytes in it (an octal field with anything in it, or a base-256
field of any length), `number` returns a value or an error (`NumError`), and
nothing overflows: not the value, not the shifts.

Not said: which of the two, or which error (the claims above say it for
some fields). -/
def NumberNeverFails : Prop :=
  ∀ field : Slice Std.U8, number field ⦃ _ => True ⦄

/-- **`padding` fills the last block.**  For any size of content, `padding`
returns `k` with `k` less than a block (512) and `size + k` a whole number of
blocks that fits in 64 bits (`size + k < 2^64`, as a sum of natural numbers: a
`k` that makes it wrap round to 0 is not one), or `None` exactly when the size
is above `2^64 - 512`, the largest whole number of blocks in 64 bits.  So `k` is
the smallest number of bytes to add, and nothing overflows.

Not said: that the size is that of a tar entry; this is the arithmetic
alone. -/
def PaddingFillsTheBlock : Prop :=
  ∀ size : Std.U64, padding size ⦃ r => match r with
    | some k => k.val < 512 ∧ (size.val + k.val) % 512 = 0 ∧ size.val + k.val < 2 ^ 64
    | none => 2 ^ 64 - 512 < size.val ⦄

/-- **The CRC-64 never panics.**  For any running CRC and any bytes,
`crc64::update` returns: the tables it reads are made without a panic and
every lookup is inside them, whatever the bytes.

Not said: that the result is the CRC-64 of the ISO polynomial (the unit
tests check the value of `"123456789"`; a proof of it is not here). -/
def Crc64NeverFails : Prop :=
  ∀ (crc : Std.U64) (data : Slice Std.U8), crc64.update crc data ⦃ _ => True ⦄

/-- **`decimal` never panics.**  For any bytes, of any length (empty too),
`decimal` returns a number or an error (`NumError`), and nothing overflows,
not the value and not the check that the next digit still fits.

Not said: which number or which error (the unit tests check them: the digits
spell the number, a sign or a space is refused). -/
def DecimalNeverFails : Prop :=
  ∀ digits : Slice Std.U8, decimal digits ⦃ _ => True ⦄

/-- **A PAX time never panics and has less than a second of nanoseconds.**
For any bytes, `pax_time` returns a time or an error, and nothing overflows:
not the number of nanoseconds being added up, nor the negation of the
seconds, nor the subtraction from a second that a negative time makes.  When
it returns a time, the nanoseconds are below 10^9.

Not said: that the time is the one the text spells (the unit tests check
it); which text is refused. -/
def PaxTimeNeverFails : Prop :=
  ∀ value : Slice Std.U8, pax_time value ⦃ r => match r with
    | core.result.Result.Ok (_, nanos) => nanos.val < 10 ^ 9
    | core.result.Result.Err _ => True ⦄

/-- **A PAX record stays inside the payload, and the reader advances.**  For
any payload, `pax_record` returns without a panic (nothing overflows, no
index is outside the payload), and when it accepts a record:
- the record is `len` bytes, `len` at least 1 and at most the payload, and it
  ends with its newline (the byte `len - 1` is 10);
- the key starts right after a space (the byte before `key.start` is 32) and
  ends at the first `=` after it (the byte `key.end` is 61, and no byte of the
  key is);
- the value starts right after that `=` and ends before the newline.
So every range lies inside the first `len` bytes of the payload and starts
before it ends, and the next record, at `len`, is further on: the reader never
reads outside and never loops on the same bytes.  (The bytes are said with
`[i]?`, which is `none` outside the payload: that they are `some` says the
index is inside.)

Not said: that what is before the space is the length in decimal (`decimal`
reads it; the unit tests check which payloads are accepted), or which error
a refused payload gives. -/
def PaxRecordStaysInside : Prop :=
  ∀ data : Slice Std.U8, pax_record data ⦃ r => match r with
    | core.result.Result.Ok rec =>
        0 < rec.len.val ∧ rec.len.val ≤ data.length ∧
        data.val[rec.len.val - 1]? = some 10#u8 ∧
        0 < rec.key.start.val ∧ data.val[rec.key.start.val - 1]? = some 32#u8 ∧
        rec.key.start.val ≤ rec.key.end.val ∧ data.val[rec.key.end.val]? = some 61#u8 ∧
        (∀ j, rec.key.start.val ≤ j → j < rec.key.end.val → data.val[j]? ≠ some 61#u8) ∧
        rec.key.end.val + 1 = rec.value.start.val ∧
        rec.value.start.val ≤ rec.value.end.val ∧ rec.value.end.val + 1 = rec.len.val
    | core.result.Result.Err _ => True ⦄

/-- **A number written to an octal field fits it or is refused.**  For any field (empty too) and
any number, `put_octal` returns, leaves the field as long as it was, and says `true` exactly when
the field has a digit and a NUL and the number is below 8 to the number of digits (the field minus
its last byte): `0o7_777_777` fits the 8 bytes of a mode, `0o10_000_000` does not.  Nothing
overflows.

Not said: what is in the field when it says `false` (the low digits of the number: the caller
refuses the number and drops the field), nor what the field holds when it says `true` (the
claim below). -/
def PutOctalFitsOrIsRefused : Prop :=
  ∀ (field : Slice Std.U8) (value : Std.U64), emit.put_octal field value ⦃ r =>
    r.2.length = field.length ∧
      (r.1 = true ↔ 0 < field.length ∧ value.val < 8 ^ (field.length - 1)) ⦄

/-- **`put_octal` writes octal digits and a NUL.**  When `put_octal` says `true`, the field it
leaves is bytes `'0'` to `'7'` (all of the field but its last byte) and then a NUL, and the digits
spell the number (most significant first, zeros in front).  This pins the bytes of the field,
which the claim below does not: `number` also takes spaces and base 256.

Not said: anything of the field when it says `false`. -/
def PutOctalWritesTheDigits : Prop :=
  ∀ (field : Slice Std.U8) (value : Std.U64), emit.put_octal field value ⦃ r =>
    r.1 = true → ∃ ds : List Std.U8, r.2.val = ds ++ [0#u8] ∧
      (∀ d ∈ ds, 48 ≤ d.val ∧ d.val ≤ 55) ∧ octalValue ds = value.val ⦄

/-- **What `put_octal` writes is read back by `number`.**  When `put_octal` says `true`, the field
it leaves is read by `number` (the reader of the tar) as the number written.

Not said: that the number fits when it says `false`; the bytes of the field (the claim above
says them). -/
def PutOctalIsReadBack : Prop :=
  ∀ (field : Slice Std.U8) (value : Std.U64), emit.put_octal field value ⦃ r =>
    r.1 = true → number r.2 ⦃ n => n = core.result.Result.Ok value ⦄ ⦄

/-- **`put_decimal` appends the digits of the number.**  For any vector with room for the 20
digits of a 64-bit number (the push of a full vector is an out-of-memory abort, not a claim here)
and any number, `put_decimal` returns the vector with, after what it had, bytes `'0'` to `'9'`
that spell the number (most significant first), with no zero in front: the number 0 is one
`'0'`, any other number starts with another digit.

Not said: the room is a hypothesis, the only one of these claims about a vector. -/
def PutDecimalWritesTheDigits : Prop :=
  ∀ (out : alloc.vec.Vec Std.U8) (value : Std.U64), out.val.length + 20 ≤ Std.Usize.max →
    emit.put_decimal out value ⦃ r => ∃ ds : List Std.U8, r.val = out.val ++ ds ∧
      (∀ d ∈ ds, 48 ≤ d.val ∧ d.val ≤ 57) ∧ decimalValue ds = value.val ∧
      (value.val = 0 → ds = [48#u8]) ∧ (value.val ≠ 0 → ds.head? ≠ some 48#u8) ⦄

/-- **`decimal` reads digits as the number they spell.**  Given at least one byte `'0'` to `'9'`,
`decimal` returns the number they spell if it is below 2^64, and the refusal `Overflow` if it is
not.  With the claim above, what `put_decimal` writes is read back.

Not said: what it does with a byte that is no digit (`DecimalNeverFails` says only that it
returns; the unit tests check which bytes are refused). -/
def DecimalOfDigitsIsTheirValue : Prop :=
  ∀ s : Slice Std.U8, (∀ b ∈ s.val, 48 ≤ b.val ∧ b.val ≤ 57) → s.val ≠ [] →
    decimal s ⦃ r =>
      if decimalValue s.val < 2 ^ 64 then
        ∃ n : Std.U64, r = core.result.Result.Ok n ∧ n.val = decimalValue s.val
      else r = core.result.Result.Err NumError.Overflow ⦄

/-- **The length of a PAX record counts itself, and is the smallest that does.**  The record
`LEN KEY=VALUE\n` has `LEN` written in decimal, and `LEN` is the length of the whole record: the
bytes after the digits, `rest`, and the digits.  For any `rest`, `record_len` returns without a
panic or an overflow either a length `len` with `len = rest + numDigits len` such that no smaller
number does the same (there can be two: for `rest = 8`, both 9 and 10 do, and 9 is the record),
or `None`, and then no number that fits a `usize` does.

Not said: that the digits are the decimal ones `put_decimal` writes (they are, by construction:
the unit tests write a record and read it with `pax_record`). -/
def RecordLenCountsItself : Prop :=
  ∀ rest : Std.Usize, emit.record_len rest ⦃ r => match r with
    | some len => len.val = rest.val + numDigits len.val ∧
        ∀ other, other = rest.val + numDigits other → len.val ≤ other
    | none => ∀ other, other ≤ Std.Usize.max → other ≠ rest.val + numDigits other ⦄

/-- **`path_order` is the comparison of the components.**  For any two byte strings, `path_order`
returns, with no index outside them, the answer of `compareComponents`: the strings split at the
`/`, the pieces compared one after the other, each as bytes, a piece before the ones it is the
start of.  So `a/b` is before `a-c` (the piece `a` is before `a-c`), though the byte `-` is before
`/`.  It is the order of `a.split('/')` and `b.split('/')` of Rust.

Not said: that the strings are paths of the layer (no empty or `.` component, no NUL): the order
is of any strings. -/
def PathOrderIsByComponents : Prop :=
  ∀ a b : Slice Std.U8, emit.path_order a b ⦃ r => r = compareComponents a.val b.val ⦄

/-- **That order is a strict total order.**  Every path is equal to itself and only to itself, the
answer for the paths the other way round is the opposite one, and before is transitive: with the
claim above, a sort by `path_order` is well defined, and two sorts give the same list.

Not said: anything of the speed of a sort. -/
def ComponentOrderIsStrictTotal : Prop :=
  (∀ a, compareComponents a a = .eq) ∧
  (∀ a b, compareComponents a b = .eq → a = b) ∧
  (∀ a b, compareComponents b a = (compareComponents a b).swap) ∧
  (∀ a b c, compareComponents a b = .lt → compareComponents b c = .lt →
    compareComponents a c = .lt)

end TarsplitHeader
