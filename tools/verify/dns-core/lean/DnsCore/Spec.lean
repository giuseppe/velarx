-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: what is proved of crates/dns-core, the DNS messages of the container name
-- server (`question` and `parse` read the question of a query that any container can send,
-- `reply` and `error_reply` build the answer, `encode_name` writes a name in wire format), in
-- words and in statements, with no proof.  This file is what a reviewer reads; Lean checks the
-- rest (the proofs are in the other files of DnsCore/, the first of them Words.lean).
--
-- Why it is needed: the bytes come from any container of a bridge, so a query can be anything.  The
-- tests of the crate (src/lib.rs) check the rules on every short message over a small alphabet and
-- on 100000 random ones; each claim below is the same rule for EVERY message, of any length, with
-- any sizes and any records.  A proof is worth what its statement says, so each claim has a
-- comment of what it claims and of what it does NOT.
--
-- The statements are about plain lists of natural numbers (`Bytes`: each byte as a number from 0
-- to 255).  The definitions below (`Word`, `OnWire`, `GoodName`, `QueryWith`, ...) are small and
-- say what the words mean (RFC 1035); none of them is the code written again.  The name of a
-- query is a list of labels: `[[119, 101, 98], [120]]` is the name `web.x`.
--
-- Total correctness: each claim says that the function RETURNS (no panic, no overflow, no index
-- outside the bytes, every loop ends) on every input, and that its answer is as stated.  Each
-- claim holds for every input; nothing about it is assumed.
--
-- Both directions: "if it answers, the answer is right" alone is satisfied by a parser that
-- refuses everything and a builder that builds nothing.  So `QuestionIsReadExactlyWhenReadable`,
-- `ParseSaysExactly` and `ReplyAnswersExactlyWhenTheQuestionFits` say what is answered when, with
-- both the answer and the refusal, and `QueryWith` and `IsTheReply` can be met (the examples at the
-- end of Claims.lean).
--
-- Read before this file: lib.rs of crates/dns-core (its header has the rules).
--
-- Index.  What each claim is about, what is trusted and what is not claimed:
--
--   Claimed (each for every message, size and records):
--     NothingPanics                    the five functions always return
--     QuestionIsReadExactlyWhenReadable  `question` reads the question exactly when it is readable
--     ThereIsOneReading                a message has at most one readable question
--     ParseSaysExactly                 `parse`: dropped, FORMERR, NOTIMP or a query, each
--                                      exactly when
--     ErrorReplyIsAHeader              `error_reply` is 12 bytes: the id, the flags, nothing else
--     ReplyAnswersExactlyWhenTheQuestionFits  `reply` answers exactly when the question is
--                                      readable and fits the size
--     ReplyIs                          every fact about a reply that `IsTheReply` says: the size,
--                                      the echo, the records, the other counts 0, the flags
--     ReplyFitsTheSize                 a reply is at most the size and at most 65535 bytes
--     ReplyEchoesTheQuery              the reply has the id and the question bytes of the query
--     ReplyCountsWholeRecords          the count is the number of whole records written, and the
--                                      truncation bit says that some are left out
--     ReplyFlagsAreAsAsked             the flags of a reply: response, recursion, the code, AA
--     EncodeNameWritesTheWire          `encode_name` writes exactly the names that can be written
--     AQuestionNameCanBeWrittenBack    the name `question` reads is written back as the query
--                                      had it
--
--   Trusted: Charon and Aeneas (../../pins) and Lean; nothing else (the crate calls no function of
--   the standard library that has to be modelled by hand).
--
--   Not claimed: anything of the shell, `velarx-netkernel` (dns): that it sets AA on the answers
--   from the zone, its Latin-1 mapping of the names it looks up, where `out_size` comes from (512
--   for UDP, the framing of TCP), the SERVFAIL path, the lookup in the zone, the forwarding to the
--   upstream servers and the moving of the datagrams; that the records are right (`reply` writes
--   them as it is given them); the additional records of a query (EDNS) and what is after the
--   question: `question` does not look at them; that a name is a good host name (it only has to
--   be readable: labels of 1 to 63 bytes with no dot and no NUL).
--
-- Notation:
--   - `f x ⦃ r => P r ⦄` reads: the Rust function `f`, given `x`, returns (it does not panic, it
--     does not loop for ever) and its answer `r` satisfies `P r`.
--   - `m : Slice Std.U8` is the Rust slice of bytes; `m.val` is the list inside it; `m.length` its
--     length.  `x.val` is the natural number a machine integer is.
--   - `l[k]?` is the element `k` of a list (counted from 0), if there is one; `l.take n` and
--     `l.drop n` are the first `n` elements and the others; `l ++ l'` is `l` and then `l'`;
--     `l.map f` is the list of the `f` of each; `l.flatMap f` is those lists one after the other.
--   - `∀ x, P` is "for every x, P"; `∃ x, P` is "there is an x such that P"; `∧` is "and", `∨` is
--     "or", `→` is "if ... then", `↔` is "exactly when", `¬` is "not"; `a ∈ l` is "a is an element
--     of l".
--   - `some x` and `none` are Rust's `Some(x)` and `None`.
import Extracted.Funs

open Aeneas Aeneas.Std Result velarx_dns_core

namespace DnsCore

/-- The bytes of a message as plain numbers from 0 to 255. -/
def Bytes (s : List Std.U8) : List Nat :=
  s.map (fun b => b.val)

/-- The 16-bit number written in the bytes `k` and `k + 1` of a message, the first byte being the
big end (`Word b 2` is the flags of a DNS header); 0 when the message has no two bytes there. -/
def Word (b : List Nat) (k : Nat) : Nat :=
  if k + 2 ≤ b.length then b.getD k 0 * 256 + b.getD (k + 1) 0 else 0

/-- The bit number `k` of a number, counted from the lowest bit (bit 0): 0 or 1. -/
def Bit (n k : Nat) : Nat :=
  n / 2 ^ k % 2

/-- The operation code of the flags: the bits 11 to 14, 0 for a query. -/
def Opcode (flags : Nat) : Nat :=
  flags / 2 ^ 11 % 16

/-- A letter of a name in lower case: an ASCII capital letter `A` to `Z` (65 to 90) becomes the
small one (97 to 122), every other byte is left as it is. -/
def Lower (c : Nat) : Nat :=
  if 65 ≤ c ∧ c ≤ 90 then c + 32 else c

/-- A label of a name that `question` reads: from 1 to 63 bytes, none of them a dot (46) or a
zero.  (A length of 64 or more is a pointer or a longer label than DNS has: refused.) -/
def GoodLabel (label : List Nat) : Prop :=
  1 ≤ label.length ∧ label.length ≤ 63 ∧ ∀ c ∈ label, c ≠ 46 ∧ c ≠ 0

/-- A name as it is on the wire (RFC 1035): each label after its length, then a zero byte. -/
def OnWire (labels : List (List Nat)) : List Nat :=
  (labels.flatMap fun label => label.length :: label) ++ [0]

/-- A name that `question` reads: its labels are all good, and its bytes on the wire (the lengths
and the zero that ends it included) are at most 255.  The name of no label (the root) is one. -/
def GoodName (labels : List (List Nat)) : Prop :=
  (∀ label ∈ labels, GoodLabel label) ∧ (OnWire labels).length ≤ 255

/-- The labels joined by dots: `[[119, 101, 98], [120]]` (`web` and `x`) is `web.x`. -/
def Joined (labels : List (List Nat)) : List Nat :=
  List.intercalate [46] labels

/-- The name of `Question`: the labels in lower case, joined by dots, with no dot at the end. -/
def Dotted (labels : List (List Nat)) : List Nat :=
  Joined (labels.map fun label => label.map Lower)

/-- A label that `encode_name` writes: from 1 to 63 bytes, none of them a dot (46).  (A zero is
allowed here: only `question` refuses it.) -/
def WritableLabel (label : List Nat) : Prop :=
  1 ≤ label.length ∧ label.length ≤ 63 ∧ ∀ c ∈ label, c ≠ 46

/-- A name that `encode_name` writes: its labels are all writable, and its bytes on the wire (the
lengths and the zero that ends it included) are at most 255. -/
def Writable (labels : List (List Nat)) : Prop :=
  (∀ label ∈ labels, WritableLabel label) ∧ (OnWire labels).length ≤ 255

/-- The facts that make `m` a query with a question that can be read: it has a header (12 bytes),
the response bit of the flags is clear, the count of questions is 1, the bytes from the byte 12 are
the name `labels` on the wire and then `tail`, the name is good, and `tail` begins with the type
and the class (4 bytes).  Whatever else the message has (the other counts, the bytes after the
question, the additional records) is not looked at. -/
structure QueryWith (m : List Nat) (labels : List (List Nat)) (tail : List Nat) : Prop where
  has_a_header : 12 ≤ m.length
  not_a_response : Word m 2 < 32768
  one_question : Word m 4 = 1
  name_follows_the_header : m.drop 12 = OnWire labels ++ tail
  type_and_class_follow : 4 ≤ tail.length
  name_is_good : GoodName labels

/-- The message has a question that can be read (`QueryWith` for some name and some bytes after
it). -/
def HasAQuestion (m : List Nat) : Prop :=
  ∃ labels tail, QueryWith m labels tail

/-- Where the question of a query with the name `labels` ends: the header, the name, the type and
the class. -/
def QuestionEnd (labels : List (List Nat)) : Nat :=
  12 + (OnWire labels).length + 4

/-- The `Question` that `question` gives for the query `m` of the name `labels`, `tail` being the
bytes after the name: its id and flags (the words 0 and 2 of the header), its name (dotted, in lower
case), its type and its class (the two numbers after the name), and the place where it ends. -/
structure IsTheQuestion (q : Question) (m : List Nat) (labels : List (List Nat))
    (tail : List Nat) : Prop where
  id_is_the_first_word : q.id.val = Word m 0
  flags_are_the_second_word : q.flags.val = Word m 2
  name_is_dotted : Bytes q.name.val = Dotted labels
  type_follows_the_name : q.qtype.val = Word tail 0
  class_follows_the_type : q.qclass.val = Word tail 2
  ends_after_the_class : q.end.val = QuestionEnd labels

/-- The bytes of the record that `reply` writes for the record `rr` (type, data): the pointer to
the question name (192, 12: the name at the byte 12), the type, the class IN (0, 1), the time to
live of 60 seconds (0, 0, 0, 60), the length of the data, the data. -/
def RecordOf (rr : Rr) : List Nat :=
  [192, 12, rr.ty.val / 256, rr.ty.val % 256, 0, 1, 0, 0, 0, 60,
    rr.data.length / 256, rr.data.length % 256] ++ Bytes rr.data.val

/-- The summary of a reply: `IsTheReply` is claimed whole by `ReplyIs`, and its parts one by one by
`ReplyFitsTheSize`, `ReplyEchoesTheQuery`, `ReplyCountsWholeRecords` and `ReplyFlagsAreAsAsked`.
The facts that make the bytes `o` the reply that `reply` builds to the query `m` (of the name
`labels`, with the bytes `tail` after it), for the code `rcode`, the answer `authoritative`, the
limit `limit` (the size, or 65535 if that is less) and the records `rrs` it is given:
- the reply is not longer than the limit;
- its id is the id of the query, its count of questions is 1, and its question is the one of the
  query, byte for byte (the case of the name too);
- the bytes after the question are the first `Word o 6` records, each whole, and no others; the
  number `Word o 6` is the count of the header, and not more than the records given;
- the counts of authority and of additional records are 0;
- the flags are the response bit (32768), the recursion available bit (128), the recursion desired
  bit of the query, the authoritative bit (1024) when asked for, the truncation bit (512) when
  some record was left out, and the code (the flags of no other bit are 0);
- if a record was left out, the first of them would not have fitted. -/
structure IsTheReply (o m : List Nat) (rcode : Nat) (authoritative : Bool) (limit : Nat)
    (rrs : List Rr) (labels : List (List Nat)) (tail : List Nat) : Prop where
  fits_the_limit : o.length ≤ limit
  echoes_the_id : Word o 0 = Word m 0
  echoes_the_question : (o.drop 12).take (QuestionEnd labels - 12) = OnWire labels ++ tail.take 4
  has_one_question : Word o 4 = 1
  records_are_whole : o.drop (QuestionEnd labels) = (rrs.take (Word o 6)).flatMap RecordOf
  counts_no_more_than_it_was_given : Word o 6 ≤ rrs.length
  no_other_sections : Word o 8 = 0 ∧ Word o 10 = 0
  flags_are : Word o 2 = 32768 + 128 + 256 * Bit (Word m 2) 8 +
    (if authoritative then 1024 else 0) + (if Word o 6 < rrs.length then 512 else 0) + rcode % 16
  stops_only_when_full : ∀ rr, rrs[Word o 6]? = some rr → limit < o.length + (RecordOf rr).length

/-- A message that is dropped, without a reply: shorter than a header, or with the response bit. -/
def Dropped (m : List Nat) : Prop :=
  m.length < 12 ∨ 32768 ≤ Word m 2

/-- The header counts answer records or authority records (a query has none of them; the count of
additional records, the word 10, is not looked at). -/
def HasRecords (m : List Nat) : Prop :=
  Word m 6 ≠ 0 ∨ Word m 8 ≠ 0

/-- What `parse` answers (`r`) for the message `m`: `Drop` exactly when the message is dropped;
`Refuse FORMERR` exactly when it is not dropped and has records or no question that can be read;
`Refuse NOTIMP` exactly when it is not dropped, has no records, has a question that can be read,
and has an operation code other than 0; `Query q` exactly when it is not dropped, has no records,
has the operation code 0 and a question that can be read, and `q` is that question. -/
def ParseIs (m : List Nat) (r : Parsed) : Prop :=
  (r = Parsed.Drop ↔ Dropped m) ∧
  (r = Parsed.Refuse RCODE_FORMERR ↔ ¬ Dropped m ∧ (HasRecords m ∨ ¬ HasAQuestion m)) ∧
  (r = Parsed.Refuse RCODE_NOTIMP ↔ ¬ Dropped m ∧ ¬ HasRecords m ∧ HasAQuestion m ∧
    Opcode (Word m 2) ≠ 0) ∧
  (∀ q, r = Parsed.Query q ↔ ¬ Dropped m ∧ ¬ HasRecords m ∧ Opcode (Word m 2) = 0 ∧
    ∃ labels tail, QueryWith m labels tail ∧ IsTheQuestion q m labels tail)

/-- **The five functions always return.**  For every message, every code, every size and every
records (a data of any length among them): no panic, no overflow, no index outside the bytes, and
every loop ends.

Not said: what they answer (the claims below). -/
def NothingPanics : Prop :=
  (∀ m : Slice Std.U8, question m ⦃ _ => True ⦄) ∧
  (∀ m : Slice Std.U8, parse m ⦃ _ => True ⦄) ∧
  (∀ (m : Slice Std.U8) (rcode : Std.U16), error_reply m rcode ⦃ _ => True ⦄) ∧
  (∀ text : Slice Std.U8, encode_name text ⦃ _ => True ⦄) ∧
  (∀ (m : Slice Std.U8) (rcode : Std.U16) (authoritative : Bool) (out_size : Std.Usize)
      (rrs : Slice Rr), reply m rcode authoritative out_size rrs ⦃ _ => True ⦄)

/-- **`question` reads the question exactly when it is readable.**  `question` returns, and:
- if it gives a `Question`, the message is a query with a question that can be read (`QueryWith`:
  a header, the response bit clear, one question, a name of labels of 1 to 63 bytes with no
  pointer, no dot and no NUL, at most 255 bytes on the wire, then the type and the class), and the
  `Question` is that one (`IsTheQuestion`: the id and the flags of the header, the name in lower
  case and dotted, the type, the class, where it ends);
- if the message is a query with a question that can be read, it gives one.

Not said: that the message is a query that `parse` answers (the other counts and the operation
code are `parse`'s: see `ParseSaysExactly`); anything of the bytes after the question. -/
def QuestionIsReadExactlyWhenReadable : Prop :=
  ∀ m : Slice Std.U8, question m ⦃ r =>
    (∀ q, r = some q → ∃ labels tail, QueryWith (Bytes m.val) labels tail ∧
      IsTheQuestion q (Bytes m.val) labels tail) ∧
    (HasAQuestion (Bytes m.val) → ∃ q, r = some q) ⦄

/-- **A message has at most one readable question.**  The name and the bytes after it are
determined by the bytes of the message: two readings of it (`QueryWith`) are the same.  So
`HasAQuestion` and the questions of the claims are about the one the message has.

Not said: that there is one (the claim above). -/
def ThereIsOneReading : Prop :=
  ∀ (m : List Nat) (labels labels' : List (List Nat)) (tail tail' : List Nat),
    QueryWith m labels tail → QueryWith m labels' tail' → labels = labels' ∧ tail = tail'

/-- **What `parse` answers, exactly.**  `parse` returns, and for every message (see `ParseIs`):
- `Drop` (no reply) exactly when the message is shorter than a header or has the response bit;
- the reply FORMERR exactly when the message is not dropped and has an answer or authority count
  other than 0, or has no question that can be read (a count of questions other than 1, a name
  that is cut, a pointer, a label of 64 bytes or more, a dot or a NUL in a label, more than 255
  bytes on the wire, no type or class after it);
- the reply NOTIMP exactly when it is not dropped, has no records, has a question that can be read
  and has an operation code other than 0;
- `Query q` exactly when it is not dropped, has no records, has the operation code 0 and a question
  that can be read, and `q` is that question.
So `parse` neither refuses a well-formed query (a name of letters, one question, no records, the
operation code 0 is answered `Query`) nor answers a malformed one.

Not said: the reply that goes with a refusal (`ErrorReplyIsAHeader`); the count of additional
records (not looked at). -/
def ParseSaysExactly : Prop :=
  ∀ m : Slice Std.U8, parse m ⦃ r => ParseIs (Bytes m.val) r ⦄

/-- **`error_reply` is a header.**  `error_reply` returns, for every message and every code, 12
bytes: the first word of the message as the id (0 if it has none), the flags (the response bit, the
recursion available bit, the recursion desired bit of the message, the code), and everything else
0: no question, no records.

Not said: that the message is a query (the reply is for a message `parse` refused). -/
def ErrorReplyIsAHeader : Prop :=
  ∀ (m : Slice Std.U8) (rcode : Std.U16), error_reply m rcode ⦃ r =>
    r.length = 12 ∧ Word (Bytes r.val) 0 = Word (Bytes m.val) 0 ∧
    Word (Bytes r.val) 2 = 32768 + 128 + 256 * Bit (Word (Bytes m.val) 2) 8 + rcode.val % 16 ∧
    (Bytes r.val).drop 4 = List.replicate 8 0 ⦄

/-- **`reply` answers exactly when the question fits.**  `reply` returns, for every message,
code, size and records, and it gives a reply exactly when the message has a question that can be
read (`QueryWith`: it need not be a query that `parse` answers) and the question (the header, the
name, the type and the class: `QuestionEnd`) is not longer than the size, nor than 65535.  So it is
not a builder that returns nothing: with a size of the question and the header, it builds.

Not said: what the reply holds (the claims below). -/
def ReplyAnswersExactlyWhenTheQuestionFits : Prop :=
  ∀ (m : Slice Std.U8) (rcode : Std.U16) (authoritative : Bool) (out_size : Std.Usize)
      (rrs : Slice Rr), reply m rcode authoritative out_size rrs ⦃ r =>
    (∀ out, r = some out → ∃ labels tail, QueryWith (Bytes m.val) labels tail ∧
      QuestionEnd labels ≤ min out_size.val 65535) ∧
    ((∃ labels tail, QueryWith (Bytes m.val) labels tail ∧
      QuestionEnd labels ≤ min out_size.val 65535) → ∃ out, r = some out) ⦄

/-- **A reply is what `IsTheReply` says.**  `reply` returns, and when it gives a reply to a query
with the name `labels` (the bytes `tail` after it), the reply has every fact of `IsTheReply`: it
fits the limit, echoes the id and the question, has one question, has whole records counted by the
header, has the counts of authority and of additional records 0 (so it has no other section than
the answers), has the flags as asked, and stops only when the next record does not fit.  The
claims below read a part of this each.

Not said: anything of the records beyond their bytes (they are the shell's). -/
def ReplyIs : Prop :=
  ∀ (m : Slice Std.U8) (rcode : Std.U16) (authoritative : Bool) (out_size : Std.Usize)
      (rrs : Slice Rr), reply m rcode authoritative out_size rrs ⦃ r =>
    ∀ out, r = some out → ∃ labels tail, QueryWith (Bytes m.val) labels tail ∧
      IsTheReply (Bytes out.val) (Bytes m.val) rcode.val authoritative
        (min out_size.val 65535) rrs.val labels tail ⦄

/-- **A reply is never longer than the size.**  `reply` returns, and when it gives a reply it is at
most `out_size` bytes long, and at most 65535 (the most a message of DNS over TCP can be).

Not said: that it is as long as it can be (the records stop where one does not fit: see
`ReplyCountsWholeRecords`). -/
def ReplyFitsTheSize : Prop :=
  ∀ (m : Slice Std.U8) (rcode : Std.U16) (authoritative : Bool) (out_size : Std.Usize)
      (rrs : Slice Rr), reply m rcode authoritative out_size rrs ⦃ r =>
    ∀ out, r = some out → out.length ≤ out_size.val ∧ out.length ≤ 65535 ⦄

/-- **A reply echoes the query.**  `reply` returns, and when it gives a reply to a query with the
name `labels` (the bytes `tail` after it): its first two bytes are the id of the query, its count
of questions is 1, and the bytes of its question (the name, the type and the class, from the byte
12) are the ones of the query, byte for byte, the capital letters of the name too.

Not said: the flags and the records (the claims below). -/
def ReplyEchoesTheQuery : Prop :=
  ∀ (m : Slice Std.U8) (rcode : Std.U16) (authoritative : Bool) (out_size : Std.Usize)
      (rrs : Slice Rr), reply m rcode authoritative out_size rrs ⦃ r =>
    ∀ out, r = some out → ∃ labels tail, QueryWith (Bytes m.val) labels tail ∧
      Word (Bytes out.val) 0 = Word (Bytes m.val) 0 ∧ Word (Bytes out.val) 4 = 1 ∧
      ((Bytes out.val).drop 12).take (QuestionEnd labels - 12) = OnWire labels ++ tail.take 4 ⦄

/-- **The records of a reply are whole, and counted.**  `reply` returns, and when it gives a reply
(to a query with the name `labels`, the question ending at `QuestionEnd labels`), with `n` the count
of answers of its header:
- `n` is not more than the records it was given, and the bytes after the question are the first
  `n` of them, each whole (the pointer to the name, the type, the class, the time to live, the
  length, the data: `RecordOf`), and nothing else: the count is the number written, no record is
  cut, the message ends where a record ends;
- the truncation bit (512) of the flags is set exactly when `n` is less than the records given;
  so it is clear when all of them fit;
- when a record was left out, the first of them would not have fitted: the reply and that record
  are longer than the limit (so the reply is as full as it can be, in order).

Not said: that the records are right (the shell's); which are left out beyond the first. -/
def ReplyCountsWholeRecords : Prop :=
  ∀ (m : Slice Std.U8) (rcode : Std.U16) (authoritative : Bool) (out_size : Std.Usize)
      (rrs : Slice Rr), reply m rcode authoritative out_size rrs ⦃ r =>
    ∀ out, r = some out → ∃ labels tail, QueryWith (Bytes m.val) labels tail ∧
      Word (Bytes out.val) 6 ≤ rrs.length ∧
      (Bytes out.val).drop (QuestionEnd labels) =
        (rrs.val.take (Word (Bytes out.val) 6)).flatMap RecordOf ∧
      (Bit (Word (Bytes out.val) 2) 9 = 1 ↔ Word (Bytes out.val) 6 < rrs.length) ∧
      (∀ rr, rrs.val[Word (Bytes out.val) 6]? = some rr →
        min out_size.val 65535 < out.length + (RecordOf rr).length) ⦄

/-- **The flags of a reply are as asked.**  `reply` returns, and when it gives a reply (to a query
with the flags `f`), its flags are the sum of: the response bit (32768), the recursion available
bit (128), the recursion desired bit of the query (256 if it has it), the authoritative bit (1024)
if and only if the caller says so (`authoritative`: the crate does not know the zone), the
truncation bit (512) if and only if a record was left out, and the code (`rcode` modulo 16).  The
operation code and every other bit are 0.

Not said: which code is right for what was looked up (the shell's). -/
def ReplyFlagsAreAsAsked : Prop :=
  ∀ (m : Slice Std.U8) (rcode : Std.U16) (authoritative : Bool) (out_size : Std.Usize)
      (rrs : Slice Rr), reply m rcode authoritative out_size rrs ⦃ r =>
    ∀ out, r = some out → Word (Bytes out.val) 2 =
      32768 + 128 + 256 * Bit (Word (Bytes m.val) 2) 8 + (if authoritative then 1024 else 0) +
      (if Word (Bytes out.val) 6 < rrs.length then 512 else 0) + rcode.val % 16 ⦄

/-- **`encode_name` writes exactly the names that can be written.**  `encode_name` returns, for
every bytes, and:
- if it gives bytes, they are the wire form of a name (`OnWire`) whose labels are of 1 to 63 bytes
  with no dot (`Writable`: at most 255 bytes on the wire), and the bytes given are the labels
  joined by dots;
- if the bytes are the labels of such a name joined by dots, it gives bytes (the empty name is the
  root: the byte 0).
So it refuses an empty label (`a..b`, a dot at the beginning or at the end), a label of 64 bytes or
more, and a name of more than 253 bytes.

Not said: that the labels are letters or digits (any byte but a dot). -/
def EncodeNameWritesTheWire : Prop :=
  ∀ text : Slice Std.U8, encode_name text ⦃ r =>
    (∀ wire, r = some wire → ∃ labels, Writable labels ∧ Bytes text.val = Joined labels ∧
      Bytes wire.val = OnWire labels) ∧
    ((∃ labels, Writable labels ∧ Bytes text.val = Joined labels) → ∃ wire, r = some wire) ⦄

/-- **A name `question` reads can be written back.**  `question` returns, and when it gives a
`Question` for a query of the name `labels`, `encode_name` of the name of the `Question` gives the
wire bytes of the name of the query in lower case: the round trip of a client's question, as the
code does it (the capital letters become small, and nothing else changes: the lengths, 1 to 63,
and the 0 that ends the name are not letters, so `Lower` leaves them).

Not said: that it is written in the case the client had (the question bytes of a reply are the
client's: `ReplyEchoesTheQuery`). -/
def AQuestionNameCanBeWrittenBack : Prop :=
  ∀ m : Slice Std.U8, question m ⦃ r =>
    ∀ q, r = some q → ∃ labels tail, QueryWith (Bytes m.val) labels tail ∧
      encode_name q.name.slice ⦃ w =>
        ∃ wire, w = some wire ∧ Bytes wire.val = (OnWire labels).map Lower ⦄ ⦄

end DnsCore
