-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: what is proved of crates/request-core, the head of a chunk request over
-- QUIC, in words and in statements, with no proof.  The head is the first bytes a member peer
-- sends on a stream, before anything is known of it: an operation, an urgency, a count, one byte
-- for each digest that says its algorithm, and then the raw bytes of the digests.  `parse` says,
-- of the bytes the shell has read so far, whether they hold a head (`Done`), are the beginning of
-- one and need more (`Need`), or are not (`Bad`); `alg_len` is the length of a digest of an
-- algorithm byte and `most` the most a head takes.  This file is what a reviewer reads; Lean
-- checks the rest (the proofs are in the other files of RequestCore/, and Theorems.lean ties
-- each claim below to its proof).
--
-- Why it is needed: the bytes come from a peer that may be hostile or broken, so they can be
-- anything.  The shell reads exactly as many bytes as `parse` asks for (`Need n`), so a wrong
-- answer lets a peer make it wait for bytes that never matter, read past the head into what
-- follows, or take bytes for a head that is not.  The tests of the crate (src/walk.rs,
-- src/rules.rs) check the rules on every short byte string over a small alphabet; each claim below
-- is the same rule for EVERY byte string and every bound.  A proof is worth what its statement
-- says, so each claim has a comment of what it claims and of what it does NOT.
--
-- Words.  A HEAD (`IsAHead`) is the bytes of: an operation, an urgency, a count in two bytes
-- (high byte first, so `256 * high + low`), as many algorithm bytes as the count, and then as
-- many raw bytes as those algorithms say, each algorithm byte with the length of its digest
-- (`AlgorithmLength`: the low seven bits 1 is SHA-256, 32 bytes, 2 is SHA-512, 64 bytes; the high
-- bit says an fs-verity digest and does not change the length; any other algorithm is not known).
-- The count of a head is at least 1 and at most the bound `max` the shell gives, and every
-- algorithm byte is known.  The bytes BEGIN with a head (`BeginsWithAHead`) when a head is the
-- beginning of them (what follows is whatever the peer sent next), and they CAN BECOME a head
-- (`CanBecomeAHead`) when some bytes appended to them begin with a head.
--
-- Totality: each claim about a function says that it RETURNS (no panic, no overflow, no byte read
-- outside the bytes given, every loop ends) and what its answer is.  Nothing is assumed of the
-- bytes.
--
-- Both directions: "a head that is read is a head" alone is satisfied by a function that always
-- says `Bad`.  So `Done`, `Need` and `Bad` are each said EXACTLY when, and the worked examples
-- show a head that is read, the same head with a byte missing that is asked for, and a byte that
-- is refused.
--
-- A rule that is the code's and is stated, not hidden: the count is read when all four first bytes
-- are there.  With fewer than four bytes the answer is always `Need 4`, also for bytes that no
-- head can ever begin with (for example the three bytes `0 0 255` when `max` is 10, or any bytes
-- when `max` is 0); `Bad` is said from the fourth byte on.  The claims say exactly that
-- (`BadIsSaidWhenNoHeadCanBegin`).
--
-- Read before this file: the header of crates/request-core/src/lib.rs, and rules.rs.
--
-- Index.  What each claim is about:
--
--   Claimed (each for every bytes and every bound):
--
--   The functions return
--     ParseAlwaysReturns                 `parse` returns, for every bytes and bound
--
--   `Done`
--     DoneIsSaidWhenAHeadBegins          `Done count used` exactly when the bytes begin with a
--                                        head of that count and that length; whatever follows
--                                        the head is not looked at
--     ADoneHeadIsAsLongAsItsFieldsSay    the count is that of the bytes, within the bound, and
--                                        `used` is the four bytes, the algorithm bytes and the
--                                        lengths the algorithms say, exactly
--
--   `Need`
--     NeedIsSaidWhenAHeadCanStillBegin   `Need` exactly when no head is there yet and either
--                                        fewer than four bytes are held or more bytes could
--                                        still make one
--     NeedAsksForMoreButNoMoreThanAHeadTakes
--                                        the total asked for is more than the bytes held, at
--                                        most what any head they can be the beginning of has,
--                                        and at most `most`
--
--   `Bad`
--     BadIsSaidWhenNoHeadCanBegin        `Bad` exactly when four bytes or more cannot become a
--                                        head: a prefix of a head is never `Bad`, and a head
--                                        that cannot become valid is never `Need`
--     AnUnknownAlgorithmIsRefused        a valid count and an unknown algorithm byte among the
--                                        bytes given: `Bad`, whatever follows
--
--   The table
--     AlgLenIsTheTable                   `alg_len` is 32 for the algorithm 1, 64 for the
--                                        algorithm 2, with or without the fs-verity bit, and 0
--                                        for every other byte
--     MostIsTheLongestHead               `most max` is `4 + 65 * max`, and no head is longer
--
--   Examples
--     WorkedExamples                     a head with two digests of different algorithms: read,
--                                        with a byte missing, and with an unknown algorithm
--
--   Trusted: Charon and Aeneas (../../pins) and Lean; nothing else (the crate calls no function
--   of the standard library that has to be modelled by hand).
--
--   Not claimed:
--   - that the shell reads exactly the bytes `Need` asks for and stops at the head, and what it
--     does with the digests (it makes them from the raw bytes);
--   - the lengths of the algorithms against the table of the shell (that 32 is the length of
--     SHA-256 and 64 of SHA-512 where the digests are made): that is the shell's, the claim is
--     about the table of this crate;
--   - the operation and the urgency, which are any bytes (the shell checks the operation first:
--     the head of a request for signatures has another count and is not read here);
--   - QUIC itself, the streams, the time a peer takes, and the bound `max` the shell chooses
--     (the claims hold for every bound), and `most` for a bound so high that `4 + 65 * max`
--     does not fit a `usize` (no shell gives one);
--   - that some head is `most max` long (one is, for `max` <= 65535, since the count has two
--     bytes);
--   - the case of fewer than four bytes (always `Need 4`, even when the bytes cannot become a
--     head): the shell always calls `parse` with the four header bytes already read, so it does
--     not arise there.
--
-- Notation:
--   - `f x ⦃ r => P r ⦄` reads: the Rust function `f`, given `x`, returns (it does not panic and
--     does not loop for ever) and its answer `r` satisfies `P r`.
--   - `s : Slice Std.U8` is a Rust slice of bytes; `s.val` is the list inside it, `s.length` its
--     length.  `l[i]?` is `some` of the element at the place `i` of `l`, or `none`.
--   - `l ++ l'` is `l` and then `l'`; `x :: l` is `l` with `x` before; `l <+: l'` is "l is the
--     beginning of l'"; `l.take n` and `l.drop n` are the first `n` elements and the rest;
--     `l.map f` applies `f` to each element; `l.sum` adds the numbers of a list.
--   - `∀ x, P` is "for every x, P"; `∃ x, P` is "there is an x such that P"; `∧` is "and", `∨` is
--     "or", `→` is "if ... then", `↔` is "exactly when", `¬` is "not", `∈` is "is in".
import Extracted.Funs

open Aeneas Aeneas.Std Result velarx_request_core

namespace RequestCore

open Classical

noncomputable section

/-! ### The head -/

/-- The length of a digest of the algorithm that a byte says: its low seven bits are 1 (SHA-256,
32 bytes) or 2 (SHA-512, 64 bytes); the high bit (fs-verity) does not change it; 0 for a byte that
says no algorithm that is known. -/
def AlgorithmLength (byte : Std.U8) : Nat :=
  if byte.val % 128 = 1 then 32 else if byte.val % 128 = 2 then 64 else 0

/-- `head` is a HEAD of `count` digests for the bound `max`: an operation, an urgency, the count in
two bytes (high, then low), `count` algorithm bytes that are all known, and then as many raw bytes
as the algorithms say; the count is at least 1 and at most `max`. -/
def IsAHead (max : Nat) (head : List Std.U8) (count : Nat) : Prop :=
  ∃ (operation urgency high low : Std.U8) (algorithms raw : List Std.U8),
    head = operation :: urgency :: high :: low :: (algorithms ++ raw) ∧
    count = high.val * 256 + low.val ∧ 1 ≤ count ∧ count ≤ max ∧
    algorithms.length = count ∧ (∀ a ∈ algorithms, AlgorithmLength a ≠ 0) ∧
    raw.length = (algorithms.map AlgorithmLength).sum

/-- The bytes BEGIN with a head of `count` digests that is `used` bytes long: some head is the
beginning of them (and `rest` is what follows it, whatever it is). -/
def BeginsWithAHead (max : Nat) (bytes : List Std.U8) (count used : Nat) : Prop :=
  ∃ head rest, bytes = head ++ rest ∧ IsAHead max head count ∧ head.length = used

/-- The bytes CAN BECOME a head: some bytes appended to them begin with a head. -/
def CanBecomeAHead (max : Nat) (bytes : List Std.U8) : Prop :=
  ∃ more count used, BeginsWithAHead max (bytes ++ more) count used

/-! ### The claims -/

/-- **`parse` returns.**  For every bytes and every bound, `parse` returns (no panic, no overflow
of a counter, no byte read outside the bytes, every loop ends).

Not said: what it answers (the claims below). -/
def ParseAlwaysReturns : Prop :=
  ∀ (bytes : Slice Std.U8) (max : Std.Usize), parse bytes max ⦃ _ => True ⦄

/-- **`Done`.**  `parse` says `Done count used` exactly when the bytes begin with a head of `count`
digests that is `used` bytes long (`BeginsWithAHead`).  A head is the beginning of the bytes and
nothing is asked of what follows it: the bytes after the head are never looked at, so a peer that
sends more cannot change the answer.  So a function that says `Bad` or `Need` for a head fails
this claim, and so does one that says `Done` for something that is not one.

Not said: that the shell stops reading at `used`. -/
def DoneIsSaidWhenAHeadBegins : Prop :=
  ∀ (bytes : Slice Std.U8) (max : Std.Usize),
    parse bytes max ⦃ r => ∀ count used : Std.Usize,
      r = Parse.Done count used ↔ BeginsWithAHead max.val bytes.val count.val used.val ⦄

/-- **What `Done` carries is what the bytes say.**  When `parse` says `Done count used`: `count` is
the number the third and the fourth bytes say (`256 * high + low`), at least 1 and at most the
bound; the algorithm bytes are the `count` bytes after the four, all known; `used` is the four
bytes, the `count` algorithm bytes and the lengths the algorithms say, added: nothing more and
nothing less; and the bytes given are at least that long.

Not said: what the operation and the urgency are (any bytes). -/
def ADoneHeadIsAsLongAsItsFieldsSay : Prop :=
  ∀ (bytes : Slice Std.U8) (max count used : Std.Usize),
    parse bytes max ⦃ r => r = Parse.Done count used →
      ∃ high low, bytes.val[2]? = some high ∧ bytes.val[3]? = some low ∧
        count.val = high.val * 256 + low.val ∧ 1 ≤ count.val ∧ count.val ≤ max.val ∧
        (∀ a ∈ (bytes.val.drop 4).take count.val, AlgorithmLength a ≠ 0) ∧
        ((bytes.val.drop 4).take count.val).length = count.val ∧
        used.val = 4 + count.val + (((bytes.val.drop 4).take count.val).map AlgorithmLength).sum ∧
        used.val ≤ bytes.length ⦄

/-- **`Need`.**  `parse` says `Need n`, for some `n`, exactly when the bytes do not begin with a
head and either they are fewer than four or they can become a head (`CanBecomeAHead`).  So bytes
that are the beginning of a head are `Need` until the head is whole, and a function that says
`Need` of bytes that are not the beginning of any head, or `Bad` of a prefix of a head, fails this
claim.

Not said: how much it asks for (the next claim), and that bytes shorter than four that no head can
begin with are `Bad` (they are `Need 4`: see the header). -/
def NeedIsSaidWhenAHeadCanStillBegin : Prop :=
  ∀ (bytes : Slice Std.U8) (max : Std.Usize),
    parse bytes max ⦃ r => (∃ n, r = Parse.Need n) ↔
      (¬ ∃ count used, BeginsWithAHead max.val bytes.val count used) ∧
        (bytes.length < 4 ∨ CanBecomeAHead max.val bytes.val) ⦄

/-- **What `Need` asks for.**  When `parse` says `Need n`: `n` is more than the bytes held (the
shell has something to read), at most what every head they can be the beginning of takes (it
never waits for more than a head takes), and at most `most max` (what a peer can make the shell
wait for is bounded by the bound it gave).

Not said: that `n` is the length of the head (it is when the algorithm bytes are all there; before
that it is the four bytes and the algorithm bytes, which a head takes at least). -/
def NeedAsksForMoreButNoMoreThanAHeadTakes : Prop :=
  ∀ (bytes : Slice Std.U8) (max n : Std.Usize),
    parse bytes max ⦃ r => r = Parse.Need n →
      bytes.length < n.val ∧
      (∀ head count, IsAHead max.val head count → bytes.val <+: head → n.val ≤ head.length) ∧
      n.val ≤ 4 + 65 * max.val ⦄

/-- **`Bad`.**  `parse` says `Bad` exactly when the bytes are four or more and no bytes appended to
them begin with a head (`CanBecomeAHead`).  So a prefix of a head is never `Bad`, and, from the
fourth byte on, bytes that cannot become a head are never `Need`: the earliest byte that is wrong
decides, and what follows it does not matter.

Not said: the case of fewer than four bytes (the header says why it is always `Need 4`). -/
def BadIsSaidWhenNoHeadCanBegin : Prop :=
  ∀ (bytes : Slice Std.U8) (max : Std.Usize),
    parse bytes max ⦃ r => r = Parse.Bad ↔ 4 ≤ bytes.length ∧ ¬ CanBecomeAHead max.val bytes.val ⦄

/-- **An unknown algorithm is refused.**  If the bytes hold a count that is valid (at least 1 and
at most the bound) and, among the algorithm bytes of the head, one that says no known algorithm
(neither 1 nor 2 in the low seven bits), `parse` says `Bad`, whatever the other bytes are and
whatever follows: the byte 0 and the byte 0x80 (fs-verity without an algorithm) are refused.

Not said: that the bytes before the unknown one were checked (they are: see the claim of `Bad`). -/
def AnUnknownAlgorithmIsRefused : Prop :=
  ∀ (bytes : Slice Std.U8) (max : Std.Usize) (high low algorithm : Std.U8) (k : Nat),
    bytes.val[2]? = some high → bytes.val[3]? = some low →
    1 ≤ high.val * 256 + low.val → high.val * 256 + low.val ≤ max.val →
    k < high.val * 256 + low.val → bytes.val[4 + k]? = some algorithm →
    AlgorithmLength algorithm = 0 →
      parse bytes max ⦃ r => r = Parse.Bad ⦄

/-- **`alg_len` is the table.**  `alg_len b` returns 32 when the low seven bits of `b` are 1, 64
when they are 2, and 0 for every other byte; the high bit (fs-verity) does not change it.

Not said: that these lengths are those of the digests the shell makes. -/
def AlgLenIsTheTable : Prop :=
  ∀ (byte : Std.U8), alg_len byte ⦃ r => r.val = AlgorithmLength byte ⦄

/-- **`most` is the longest head.**  No head is longer than `4 + 65 * max`: the four bytes, `max`
algorithm bytes and `max` digests of 64 bytes; and `most max` is that number, for a bound that
fits (`4 + 65 * max` is at most the largest `usize`).

Not said: the bound that is so high that the number does not fit (the shell gives a small one). -/
def MostIsTheLongestHead : Prop :=
  (∀ max head count, IsAHead max head count → head.length ≤ 4 + 65 * max) ∧
  (∀ (max : Std.Usize), 4 + 65 * max.val ≤ Std.Usize.max →
    most max ⦃ r => r.val = 4 + 65 * max.val ⦄)

/-! ### Examples -/

/-- Some bytes as a slice, for the examples. -/
def BytesOf (bytes : List Std.U8) (few : bytes.length ≤ 255 := by decide) : Slice Std.U8 :=
  Slice.from bytes (by scalar_tac)

/-- A head of two digests of different algorithms: the operation 7, the urgency 1, the count 2, an
fs-verity SHA-256 (the byte 0x81) and a SHA-512 (the byte 2), 32 bytes of 0xAA and 64 of 0xBB. -/
def TwoDigests : List Std.U8 :=
  [7#u8, 1#u8, 0#u8, 2#u8, 129#u8, 2#u8] ++ List.replicate 32 170#u8 ++ List.replicate 64 187#u8

/-- **A few examples**, worked out from the claims above (not by running the code).  The head
`TwoDigests` is 102 bytes long (4 + 2 + 32 + 64).
1. With bound 256, `parse` of it says `Done 2 102`; with three more bytes after it, the same.
2. Without its last byte, `parse` says `Need 102`: it is the beginning of a head that needs the
   last byte.
3. With the second algorithm byte replaced by 3, an unknown algorithm, `parse` says `Bad`: it
   says so from the bytes given, so also with only the first six bytes. -/
def WorkedExamples : Prop :=
  (parse (BytesOf TwoDigests) 256#usize ⦃ r => r = Parse.Done 2#usize 102#usize ⦄) ∧
  (parse (BytesOf (TwoDigests ++ [9#u8, 9#u8, 9#u8])) 256#usize ⦃ r =>
    r = Parse.Done 2#usize 102#usize ⦄) ∧
  (parse (BytesOf (TwoDigests.take 101)) 256#usize ⦃ r => r = Parse.Need 102#usize ⦄) ∧
  (parse (BytesOf ([7#u8, 1#u8, 0#u8, 2#u8, 129#u8, 3#u8] ++ TwoDigests.drop 6)) 256#usize ⦃ r =>
    r = Parse.Bad ⦄) ∧
  (parse (BytesOf [7#u8, 1#u8, 0#u8, 2#u8, 129#u8, 3#u8]) 256#usize ⦃ r => r = Parse.Bad ⦄)

end

end RequestCore
