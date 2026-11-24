-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: what is proved of crates/chunk-core, the judgement of the chunks of one
-- file of a zstd:chunked layer (`check`: from the chunks the table of contents gives, the limits
-- of the pull and the totals of the files before, the new totals, or a refusal), in words and in
-- statements, with no proof.  This file is what a reviewer reads; Lean checks the rest (the proofs
-- are in Tiling.lean, Sums.lean, CheckedSums.lean, Ranges.lean, WalkTheChunks.lean,
-- WalkTheRanges.lean, Check.lean and Claims.lean).
--
-- Why it is needed: the table comes from an image nobody vouched for, so `check` is what keeps a
-- hostile table from making the pull fetch bytes outside the compressed range of the file, leave
-- bytes of the file with no chunk, or take more than its limits.  The tests of the crate
-- (src/walk.rs, src/rules.rs) check these rules on millions of small cases (small numbers: 0, 1,
-- near the largest 64-bit number); each claim below is the same rule for EVERY file, with numbers
-- of 64 bits and chunk lists of any length.  A proof is worth what its statement says, so
-- each claim has a comment of what it claims and of what it does NOT.
--
-- The statements are about plain natural numbers (`Nat`: 0, 1, 2, ... with no largest one, so no
-- overflow can happen in them).  The definitions below (`TilesFrom`, `HoleBytes`, `CompEnd`, ...)
-- are small and say what the words mean; none of them is the code of `check` written again.
--
-- Total correctness: each claim says that the function RETURNS (no panic, no overflow, no index
-- outside the chunks, every loop ends) on every input, and that its answer is as stated.  No claim
-- assumes anything of the input beyond the one it names.
--
-- Upper and lower bounds: "if `check` accepts, the chunks are good" alone is satisfied by a
-- `check` that always refuses.  So `EveryGoodListIsAccepted` says the other way: every list that
-- is good is accepted, and `AcceptedIsGood` the way back: together they say that `check` accepts
-- EXACTLY the good lists, when `before` is within the caps (see `AcceptedIsGood`).  The
-- totals it returns are equal to the sums, not only below them, so an answer of empty totals does
-- not satisfy them.
--
-- Read before this file: lib.rs and rules.rs of crates/chunk-core.
--
-- Index.  What each claim is about, what is trusted and what is not claimed:
--
--   Claimed (each for every file, chunks, caps and totals; the function returns, and):
--     CompressedBoundIsTheFormula      `compressed_bound` is size + size/64 + 1 MiB, cut at the
--                                      largest `u64`
--     CompRangeIsTheRangeOfTheChunk    `comp_range` of the chunk `j` is its offset and the offset
--                                      of the next chunk, or the end of the file's range
--     CheckAlwaysReturns               `check` returns, always (no condition)
--     AcceptedChunksTileTheFile        accepted: the chunks tile the file exactly
--     AcceptedDataChunksFitTheCap      accepted: no chunk of data is bigger than the chunk cap
--     AcceptedTotalsAreTheSums         accepted: the totals are `before` plus the bytes of holes
--                                      and the bytes of data of this file
--     AcceptedTotalsAreWithinTheCaps   accepted, and `before` within the caps: so are the totals
--     AcceptedRangesAreInTheFileInOrder  accepted, file placed: every compressed range is in the
--                                      range of the file, in order, none overlaps another
--     AcceptedDataRangesHaveBytesWithinTheBound  accepted, file placed: the range of a chunk of
--                                      data is not empty and at most the compressed bound
--     AcceptedIsGood                   `before` within the caps, accepted: the list is good (all
--                                      of the above in one statement)
--     EveryGoodListIsAccepted          a good list is accepted (so `check` accepts exactly the
--                                      good lists, when `before` is within the caps)
--     ARefusalNamesAFalseStatement     a refusal names a statement that does not hold
--
--   Trusted: Charon and Aeneas (../../pins) and the models of the standard library Aeneas itself
--   has (the integer operations on `u64`, `checked_add`, `saturating_add`, slice indexing);
--   no model is written by hand.
--
--   Not claimed: anything of the shell, `pull/chunked` of velarx-content, that reads the table,
--   builds the `File` and the `Chunk`s from it and the plan from what is accepted: the claims are
--   about the numbers it gives; that the numbers of the table are true (a chunk of data may lie
--   about its compressed range, and `check` only says the range is possible); that the compressed
--   bytes decompress to the bytes of the chunk, or hash to its digest; that a file that is not
--   `placed` has any offset right (its offsets are not looked at); that `before` is the sum of the
--   files before (the caller's business, see `AcceptedIsGood`: the shell passes only totals that an
--   earlier `check` returned, or zero, so they are within the caps); that the same content is not
--   in two files (deduplication across files is the shell's); that the end of the compressed range
--   of the file, `comp_end`, is the real end of it (`check` trusts it for the last chunk); which
--   refusal is given when several apply (any of them names a false statement: the first the code
--   finds).
--
-- Notation:
--   - `check file chunks caps before ⦃ answer => P answer ⦄` reads: the Rust function `check`,
--     given those, returns (it does not panic, it does not loop for ever) and its answer
--     satisfies `P answer`.  `answer = core.result.Result.Ok t` is "accepted, with totals `t`";
--     `core.result.Result.Err why` is "refused, for the reason `why`".
--   - `chunks : Slice Chunk` is the Rust slice; `chunks.val` is the list inside it; `l[j]` is the
--     element `j` of a list (counted from 0); `l[j]?` is the element `j` if there is one.
--   - `x.val` is the natural number a machine integer is.  `file.size`, `c.file_off`, ... are
--     the fields of the Rust structs (lib.rs).
--   - `∀ x, P` is "for every x, P"; `∃ x, P` is "there is an x such that P"; `∧` is "and",
--     `→` is "if ... then", `¬` is "not", `∈` is "is an element of"; `a < b`, `a ≤ b` as usual.
--   - `l.filter keep` is the elements of `l` that `keep` says yes to, `l.map f` the list of the
--     `f` of each, `l.sum` the sum of a list of numbers.
import Extracted.Funs

open Aeneas Aeneas.Std Result velarx_chunk_core

namespace ChunkCore

/-- The chunks of the list tile the bytes `start` to `stop` of the file: the first one begins at
`start`, each one has at least a byte and begins where the one before it ends, and the last
one ends at `stop` (no chunk tiles `start` to `stop` when they are equal and nothing else).  There
is no gap and no overlap. -/
def TilesFrom : List Chunk → Nat → Nat → Prop
  | [], start, stop => start = stop
  | c :: rest, start, stop =>
      c.file_off.val = start ∧ 0 < c.size.val ∧ TilesFrom rest (start + c.size.val) stop

/-- The chunks tile the file: from its first byte to its last, in order, with no gap and no
overlap. -/
def Tiles (file : File) (chunks : List Chunk) : Prop :=
  TilesFrom chunks 0 file.size.val

/-- The bytes of the holes in the chunks: the sum of the sizes of those that are zeros. -/
def HoleBytes (chunks : List Chunk) : Nat :=
  ((chunks.filter (fun c => c.zeros)).map (fun c => c.size.val)).sum

/-- The bytes of data in the chunks: the sum of the sizes of those that are not zeros. -/
def DataBytes (chunks : List Chunk) : Nat :=
  ((chunks.filter (fun c => !c.zeros)).map (fun c => c.size.val)).sum

/-- The most bytes the compressed form of `size` bytes may have: what zstd needs for data it
cannot compress (the size, a sixty-fourth more) and a mebibyte of framing.  A number that
can be as large as it likes: `compressed_bound` cuts it at the largest `u64`. -/
def CompressedBoundOf (size : Nat) : Nat :=
  size + size / 64 + 2 ^ 20

/-- Where the compressed range of the chunk `j` ends: where the chunk after it begins (in the
layer), or, for the last chunk, where the range of the file ends. -/
def CompEnd (file : File) (chunks : List Chunk) (j : Nat) : Nat :=
  match chunks[j + 1]? with
  | some next => next.comp_off.val
  | none => file.comp_end.val

/-- No chunk of data is bigger than the cap of a chunk (`caps.chunk`).  A hole may be. -/
def DataChunksFitTheCap (caps : Caps) (chunks : List Chunk) : Prop :=
  ∀ c ∈ chunks, c.zeros = false → c.size.val ≤ caps.chunk.val

/-- With the holes of these chunks, the layer has at most `caps.zeros` bytes of holes (`before` is
what the files before this one hold). -/
def HolesFitTheCap (caps : Caps) (before : Totals) (chunks : List Chunk) : Prop :=
  before.zeros.val + HoleBytes chunks ≤ caps.zeros.val

/-- With the data of these chunks, the layer has at most `caps.planned` bytes of data to fetch. -/
def DataFitsTheCap (caps : Caps) (before : Totals) (chunks : List Chunk) : Prop :=
  before.planned.val + DataBytes chunks ≤ caps.planned.val

/-- The compressed range of every chunk is in the compressed range of the file: it begins at or
after its start, it does not end before it begins, and it ends at or before the end. -/
def RangesAreInTheFile (file : File) (chunks : List Chunk) : Prop :=
  ∀ (j : Nat) (hj : j < chunks.length),
    file.comp_start.val ≤ chunks[j].comp_off.val ∧
    chunks[j].comp_off.val ≤ CompEnd file chunks j ∧
    CompEnd file chunks j ≤ file.comp_end.val

/-- The compressed ranges are in order and none overlaps another: the range of a chunk ends
at or before the place where the range of each chunk after it begins. -/
def RangesAreInOrder (file : File) (chunks : List Chunk) : Prop :=
  ∀ (j k : Nat) (hk : k < chunks.length), j < k →
    CompEnd file chunks j ≤ chunks[k].comp_off.val

/-- The compressed range of every chunk of data has at least a byte. -/
def DataRangesHaveBytes (file : File) (chunks : List Chunk) : Prop :=
  ∀ (j : Nat) (hj : j < chunks.length), chunks[j].zeros = false →
    chunks[j].comp_off.val < CompEnd file chunks j

/-- The compressed range of every chunk of data is at most the compressed bound of its size
(from where it begins, it does not end after that many bytes). -/
def DataRangesAreWithinTheBound (file : File) (chunks : List Chunk) : Prop :=
  ∀ (j : Nat) (hj : j < chunks.length), chunks[j].zeros = false →
    CompEnd file chunks j ≤ chunks[j].comp_off.val + CompressedBoundOf chunks[j].size.val

/-- The statements about the compressed ranges, together: they are the ones of a file that
is placed (a file with no offsets has none to look at). -/
def RangesAreGood (file : File) (chunks : List Chunk) : Prop :=
  RangesAreInTheFile file chunks ∧ RangesAreInOrder file chunks ∧
  DataRangesHaveBytes file chunks ∧ DataRangesAreWithinTheBound file chunks

/-- The chunks are good: they tile the file, no chunk of data is over its cap, the holes and the
data of the layer are within theirs, and, when the file is placed, the compressed ranges are
good.  `check` accepts exactly the chunks that are good, when `before` is within the caps (the
files before this one were accepted, or there are none): see `AcceptedIsGood` and
`EveryGoodListIsAccepted`. -/
def Good (file : File) (chunks : List Chunk) (caps : Caps) (before : Totals) : Prop :=
  Tiles file chunks ∧ DataChunksFitTheCap caps chunks ∧
  HolesFitTheCap caps before chunks ∧ DataFitsTheCap caps before chunks ∧
  (file.placed = true → RangesAreGood file chunks)

/-- What a refusal `why` says (the words of `Refusal` in lib.rs): that a statement of `Good` is
false of the input.  `Named why file chunks caps before` is that fact. -/
def Named (why : Refusal) (file : File) (chunks : List Chunk) (caps : Caps)
    (before : Totals) : Prop :=
  match why with
  | .NotTiled => ¬ Tiles file chunks
  | .ChunkTooBig => ¬ DataChunksFitTheCap caps chunks
  | .TooManyZeros => ¬ HolesFitTheCap caps before chunks
  | .TooMuchData => ¬ DataFitsTheCap caps before chunks
  -- (a range is outside the file, out of order, or a data range is empty)
  | .Misplaced => file.placed = true ∧
      ¬ (RangesAreInTheFile file chunks ∧ RangesAreInOrder file chunks ∧
         DataRangesHaveBytes file chunks)
  | .CompressedTooBig => file.placed = true ∧ ¬ DataRangesAreWithinTheBound file chunks

/-- **`compressed_bound` is the formula.**  For every size, `compressed_bound` returns, and
its answer is `size + size / 64 + 2^20` (`CompressedBoundOf`; the division is whole), or
the largest `u64` if that is more: it does not wrap round to a small number, so a huge size
never gets a small bound.

Not said: that the bound is the right one for zstd (it is the limit `check` holds a chunk to). -/
def CompressedBoundIsTheFormula : Prop :=
  ∀ size : Std.U64, compressed_bound size ⦃ bound =>
    bound.val = min (CompressedBoundOf size.val) Std.U64.max ⦄

/-- **`comp_range` gives the compressed range of the chunk.**  For every file, every chunks and
every chunk `j` of them (`j` below the number of chunks), `comp_range` returns, and its answer is
the pair (where the chunk begins in the layer, where its range ends): the end is the offset
of the chunk `j + 1` if there is one, else the end of the compressed range of the file
(`CompEnd`).

Not said: that this is a range (it is for what `check` accepts, see
`AcceptedRangesAreInTheFileInOrder`); anything for a `j` that is not a chunk (the function
panics there, and `check` never asks). -/
def CompRangeIsTheRangeOfTheChunk : Prop :=
  ∀ (file : File) (chunks : Slice Chunk) (j : Std.Usize) (hj : j.val < chunks.val.length),
    comp_range file chunks j ⦃ range =>
      range.1.val = chunks.val[j.val].comp_off.val ∧
      range.2.val = CompEnd file chunks.val j.val ⦄

/-- **`check` always returns.**  For every file, every list of chunks of any length, every caps and
every totals: no panic, no overflow in a sum of sizes or of totals, no index outside the chunks,
and both loops end.

Not said: what it answers (the claims below). -/
def CheckAlwaysReturns : Prop :=
  ∀ (file : File) (chunks : Slice Chunk) (caps : Caps) (before : Totals),
    check file chunks caps before ⦃ _ => True ⦄

/-- **The chunks of an accepted file tile it.**  `check` returns, and when it accepts (with any
totals), the chunks begin at the first byte of the file, each begins where the one before it
ends, each has at least a byte, and the last ends at the last byte of the file (`Tiles`): there
is no gap and no overlap, and no byte of the file is left without a chunk.  The file of no bytes
has no chunk.

Not said: anything of the compressed ranges, the caps or the totals (the claims below). -/
def AcceptedChunksTileTheFile : Prop :=
  ∀ (file : File) (chunks : Slice Chunk) (caps : Caps) (before : Totals),
    check file chunks caps before ⦃ answer =>
      ∀ t, answer = core.result.Result.Ok t → Tiles file chunks.val ⦄

/-- **No accepted chunk of data is over the cap.**  `check` returns, and when it accepts, every
chunk that is data (not a hole) has at most `caps.chunk` bytes.

Not said: that a hole is small (a hole is written, not fetched, and only the total of the holes of
the layer has a limit: `AcceptedTotalsAreWithinTheCaps`). -/
def AcceptedDataChunksFitTheCap : Prop :=
  ∀ (file : File) (chunks : Slice Chunk) (caps : Caps) (before : Totals),
    check file chunks caps before ⦃ answer =>
      ∀ t, answer = core.result.Result.Ok t → DataChunksFitTheCap caps chunks.val ⦄

/-- **The totals are the sums.**  `check` returns, and when it accepts with totals `t`, `t.zeros`
is `before.zeros` plus the bytes of the holes of this file, and `t.planned` is `before.planned`
plus the bytes of the data of this file, as sums of natural numbers (no wrapping, no saturating:
a sum that does not fit in a `u64` is a refusal).

Not said: that they are within the caps (the next claim), or that `before` is right. -/
def AcceptedTotalsAreTheSums : Prop :=
  ∀ (file : File) (chunks : Slice Chunk) (caps : Caps) (before : Totals),
    check file chunks caps before ⦃ answer =>
      ∀ t, answer = core.result.Result.Ok t →
        t.zeros.val = before.zeros.val + HoleBytes chunks.val ∧
        t.planned.val = before.planned.val + DataBytes chunks.val ⦄

/-- **The totals are within the caps.**  `check` returns, and when the files before this one
were within the caps (`before.zeros ≤ caps.zeros`, `before.planned ≤ caps.planned`, which
`check` itself kept true for each file before, the first having `before` of no bytes) and
it accepts with totals `t`, then `t.zeros ≤ caps.zeros` and `t.planned ≤ caps.planned`.

Not said: anything when `before` is already over a cap and the file adds nothing to it
(`check` then accepts and gives `before` back: it judges this file, not the files before). -/
def AcceptedTotalsAreWithinTheCaps : Prop :=
  ∀ (file : File) (chunks : Slice Chunk) (caps : Caps) (before : Totals),
    before.zeros.val ≤ caps.zeros.val → before.planned.val ≤ caps.planned.val →
    check file chunks caps before ⦃ answer =>
      ∀ t, answer = core.result.Result.Ok t →
        t.zeros.val ≤ caps.zeros.val ∧ t.planned.val ≤ caps.planned.val ⦄

/-- **The compressed ranges of an accepted file are in the file, in order.**  `check` returns,
and when it accepts a file that is placed (`file.placed = true`):
- the compressed range of every chunk (as `comp_range` gives it) begins at or after the start of
  the compressed range of the file, does not end before it begins, and ends at or before the end
  of the compressed range of the file (`RangesAreInTheFile`);
- the ranges are in order and none overlaps another: each ends at or before the place where each
  chunk after it begins (`RangesAreInOrder`).

Not said: anything of a file that is not placed (it has no offsets to look at); that the bytes
are what the table says (`check` has not seen them). -/
def AcceptedRangesAreInTheFileInOrder : Prop :=
  ∀ (file : File) (chunks : Slice Chunk) (caps : Caps) (before : Totals),
    check file chunks caps before ⦃ answer =>
      ∀ t, answer = core.result.Result.Ok t → file.placed = true →
        RangesAreInTheFile file chunks.val ∧ RangesAreInOrder file chunks.val ⦄

/-- **The compressed range of an accepted chunk of data has bytes, and not too many.**  `check`
returns, and when it accepts a file that is placed, the compressed range of every chunk of data
has at least a byte (`DataRangesHaveBytes`) and is at most `CompressedBoundOf` the size of the
chunk (`DataRangesAreWithinTheBound`).

Not said: anything of the range of a hole (it may be empty, and any length: a hole is not
fetched); that the data compresses to that many bytes. -/
def AcceptedDataRangesHaveBytesWithinTheBound : Prop :=
  ∀ (file : File) (chunks : Slice Chunk) (caps : Caps) (before : Totals),
    check file chunks caps before ⦃ answer =>
      ∀ t, answer = core.result.Result.Ok t → file.placed = true →
        DataRangesHaveBytes file chunks.val ∧ DataRangesAreWithinTheBound file chunks.val ⦄

/-- **An accepted list is good.**  When the files before this one were within the caps
(`before.zeros ≤ caps.zeros`, `before.planned ≤ caps.planned`), `check` returns, and when it
accepts, the list is `Good`: all the statements of the claims above, in one.  The precondition
is harmless: the shell passes `before` of no bytes for the first file of a layer, and for the
next ones the totals an earlier `check` returned, which are within the caps by the claim
`AcceptedTotalsAreWithinTheCaps`.  It is needed: with `before` over a cap and a file that adds
nothing to it (no holes, say), `check` accepts and the holes still do not fit.

Not said: anything when `before` is over a cap. -/
def AcceptedIsGood : Prop :=
  ∀ (file : File) (chunks : Slice Chunk) (caps : Caps) (before : Totals),
    before.zeros.val ≤ caps.zeros.val → before.planned.val ≤ caps.planned.val →
    check file chunks caps before ⦃ answer =>
      ∀ t, answer = core.result.Result.Ok t → Good file chunks.val caps before ⦄

/-- **A good list is accepted.**  When the statements of `Good` hold (the chunks tile the
file, no chunk of data is over the cap, the holes and the data are within theirs, and, if the file
is placed, the compressed ranges are good), `check` returns, and it accepts: it answers with some
totals, never a refusal.  With `AcceptedIsGood` this says that `check` accepts EXACTLY the good
lists: it refuses nothing it should accept.

Not said: which totals (`AcceptedTotalsAreTheSums`).  That a good list exists is shown by the
example at the end of Claims.lean. -/
def EveryGoodListIsAccepted : Prop :=
  ∀ (file : File) (chunks : Slice Chunk) (caps : Caps) (before : Totals),
    Good file chunks.val caps before →
    check file chunks caps before ⦃ answer => ∃ t, answer = core.result.Result.Ok t ⦄

/-- **A refusal names a statement that does not hold.**  `check` returns, and when it refuses
with `why`, `Named why` holds, that is, the statement the refusal names is false of the input:
`NotTiled` says the chunks do not tile the file; `ChunkTooBig` that a chunk of data is over the cap; `TooManyZeros` and `TooMuchData` that
the holes or the data would be over theirs; `Misplaced` that the file is placed and its ranges
are not in the file, not in order, or a range of data is empty; `CompressedTooBig` that the file
is placed and a range of data is over the bound.

Not said: that `why` is the first thing wrong, in any order of the statements; only that it is
something wrong. -/
def ARefusalNamesAFalseStatement : Prop :=
  ∀ (file : File) (chunks : Slice Chunk) (caps : Caps) (before : Totals),
    check file chunks caps before ⦃ answer =>
      ∀ why, answer = core.result.Result.Err why →
        Named why file chunks.val caps before ⦄

end ChunkCore
