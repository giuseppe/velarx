-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: what is proved of crates/sigparse-core, the reading of the bytes of a
-- signature that come from a registry or a file nobody vouched for: the packets of OpenPGP data
-- (`packets`), the signature packet and its subpackets (`signature`), and DER elements and
-- sequences (`der::element`, `der::sequence_items`).  Statements in words and in Lean, with no
-- proof.  This file is what a reviewer reads; Lean checks the rest (the proofs are in the other
-- files of SigparseCore/, and Claims.lean ties each claim below to its proof).
--
-- Why it is needed: the bytes are hostile.  The tests of the crate (src/tests.rs) check the rules
-- of the header of src/lib.rs on many cases; each claim below is the same rule for EVERY byte
-- string, lengths near 2^32 included.  A proof is worth what its statement says, so each claim has
-- a comment of what it claims and of what it does NOT.
--
-- The statements are about plain natural numbers (`Nat`: 0, 1, 2, ... with no largest one, so no
-- overflow can happen in them) and lists of bytes.  The definitions (`DerContent`, `LengthAt`,
-- `AreaMadeOf`, `PiecesFrom`, ...) are small and say what the formats are (RFC 4880, 4.2 and 5.2.3;
-- X.690 for DER); none is the code written again.
--
-- Total correctness: each claim says that the function RETURNS (no panic, no overflow, no index
-- outside the data, every loop ends) on every input, and that its answer, when it accepts, is as
-- stated.  No claim assumes anything of the input.  (The lengths of the slices are those of the
-- Aeneas model: a slice has at most as many bytes as the largest `usize`; nothing smaller is
-- assumed, and in particular no length is assumed to leave room for a sum.)
--
-- Upper and lower bounds: "when it accepts, the answer is such" is also satisfied by a reader
-- that refuses everything.  So the claims that say what IS accepted come with them.  DER:
-- `DerElementIsAcceptedExactlyWhenItIsWellFormed` says it both ways.  `signature`: it accepts
-- exactly the packets `WellFormedSignature` describes (`WellFormedSignaturesAreAccepted` and
-- `AcceptedSignaturesAreWellFormed`), and the two simplest cases
-- (`ASignatureWithNoSubpacketsIsAccepted`, `ASignatureWithOneCreationTimeIsAccepted`) also say what
-- the answer is.  `packets`: it accepts the empty data (`EmptyDataIsAccepted`) and every list of
-- packets in the new format with one-byte lengths (`SimplePacketsAreAccepted`).  See "Not claimed"
-- for what is not shown accepted.
--
-- Read before this file: the header of src/lib.rs (the 11 rules).
--
-- Index.  What each claim is about:
--
--   DER (`der::element`, `der::sequence_items`):
--     DerElementAlwaysReturns            `element` returns, always
--     DerElementIsAcceptedExactlyWhenItIsWellFormed
--                                        it accepts exactly the elements with a one-byte tag and a
--                                        definite length (short, or long of 1 to 4 bytes) that
--                                        lies inside the data
--     AnAcceptedDerElementIsDefiniteAndInside
--                                        the content of an accepted element is after its header
--                                        and inside the data
--     SequenceItemsAlwaysReturns         `sequence_items` returns, always
--     AcceptedSequenceItemsFillTheSequence
--                                        accepted: the data begins with a sequence (tag 0x30) and
--                                        the items are its elements, in order, with no overlap,
--                                        filling its content exactly
--   OpenPGP packets (`packets`):
--     PacketsAlwaysReturn                `packets` returns, always
--     AcceptedPacketsCoverTheInput       accepted: the pieces of the bodies are in order, each
--                                        after a header of at least a byte, and the last ends at
--                                        the end of the data (nothing is left, nothing is ignored)
--     AcceptedPacketSpansAreInsideTheInput
--                                        every piece lies inside the data
--     AcceptedPacketsAreNoMoreThanTheLimit
--                                        at most MAX_PACKETS pieces
--     EmptyDataIsAccepted                the empty data is accepted, with no packet
--     SimplePacketsAreAccepted           any packets in the new format with one-byte lengths are
--                                        accepted, with exactly those tags and bodies
--   The signature packet (`signature`):
--     SignatureAlwaysReturns             `signature` returns, always
--     AcceptedSignatureIsLaidOutLikeVersion4
--                                        the version is 4; the hashed area, the unhashed area, the
--                                        16 bits of the hash and the values are laid out as the
--                                        lengths in the bytes say
--     TheTrailerIsTheBytesUpToTheEndOfTheHashedArea
--                                        the bytes the signature hashes after the data begin with
--                                        the bytes of the packet up to the end of the hashed area
--     AcceptedValuesFollowTheAreas       the values follow the unhashed area, in order, inside the
--                                        data, as many as the algorithm has
--     TheHashedAreaIsMadeOfSubpackets    the hashed area is made of subpackets, with no byte left
--                                        over
--     NoUnknownCriticalSubpacketInTheHashedArea
--                                        every critical subpacket of the hashed area is of a known
--                                        kind
--     NoCriticalNotationIsAccepted       in particular, no critical notation
--     TimesAndFlagsAreOfTheHashedAreaOnly
--                                        the creation time, the expirations and the key flags
--                                        are those of the last subpacket of their kind of the
--                                        HASHED area; the unhashed area is not looked at for them
--     EmbeddedSignaturesAreTheValuesOfTheEmbeddedSubpackets
--                                        the embedded signatures are the values of the subpackets
--                                        of kind 32 of either area, in order
--     TheIssuerFingerprintIsInsideTheAreas
--                                        a fingerprint, if any, lies inside the areas
--     WellFormedSignaturesAreAccepted    every packet `WellFormedSignature` describes is accepted
--     AcceptedSignaturesAreWellFormed    the converse: an accepted packet is a
--                                        `WellFormedSignature` (so exactly those are accepted)
--     SignaturesThatAgreeUpToTheHashedAreaHaveTheSameTimes
--                                        two accepted packets with the same bytes up to the end of
--                                        the hashed area have the same times and key flags
--     ASignatureWithNoSubpacketsIsAccepted
--                                        a packet with both areas empty is accepted: trailer = the
--                                        first 6 bytes, no time, no key flags
--     ASignatureWithOneCreationTimeIsAccepted
--                                        the same with one creation time subpacket: accepted, with
--                                        that time
--
--   Trusted: Charon and Aeneas (../../pins) and the models of the standard library Aeneas itself
--   has.  Nothing is written by hand (Models.lean is empty).
--
--   Not claimed: which signatures are valid (that is the cryptography of `velarx-signature`);
--   that a key may make a signature; what a refusal says (the kind of error is not claimed: only
--   that there is one, and that an accepted answer is as stated); that the issuer key ID is
--   anything but a hint (it only decides which key is tried first; every key is tried); that the
--   unhashed area has no critical subpacket (it may: the bit means nothing there); the armor
--   layer; the signature type and the hash algorithm (they are not checked here); that `packets`
--   accepts the old format, two-octet and five-octet lengths and partial lengths (only the empty
--   data and the new format with one-octet lengths are shown to be accepted, so a reader that
--   refused every other packet would satisfy the claims about `packets`); the bytes of the
--   headers of the packets (their top bit and their format, which decide where a body begins, are
--   the code's: the claims say the bodies are in order and inside, with at least a byte before
--   each); the contents of the subpackets that are not read; that a partial length is refused for
--   a packet that may not have one (the code does; the claims do not repeat it).
--
-- Notation:
--   - `f x ⦃ r => P r ⦄` reads: the Rust function `f`, given `x`, returns (it does not panic and
--     does not loop for ever) and its answer `r` satisfies `P r`.  `r = core.result.Result.Ok v` is
--     "accepted, with `v`"; `core.result.Result.Err e` is "refused".
--   - `data : Slice Std.U8` is a Rust slice of bytes; `data.val` is the list inside it; `l[j]?` is
--     the element `j` of a list (counted from 0), if there is one; `l.length` its length.
--   - `x.val` is the natural number a machine integer is; `c.off`, `c.len` are the fields of a span
--     (lib.rs): where it begins and how long it is.
--   - `∀ x, P` is "for every x, P"; `∃ x, P` is "there is an x such that P"; `∧` is "and", `∨`
--     "or", `→` "if ... then", `¬` "not", `∈` "is an element of"; `a ≤ b`, `a < b` as usual.
import Extracted.Funs
open Aeneas Aeneas.Std Result velarx_sigparse_core
namespace SigparseCore

/-- The number the `n` bytes from `start` of `bytes` make, the first one the most significant. -/
def BigEndian (bytes : List Std.U8) (start n : Nat) : Nat :=
  ((bytes.drop start).take n).foldl (fun value byte => value * 256 + byte.val) 0

/-- Where the content of the DER element that begins at `start` is, as (where it begins, how long it
is), when the element is read inside the bytes before `stop`: the tag is one byte, then the length,
then the content.  A length is one byte below 128, or, from 129 to 132 (0x81 to 0x84), the number of
bytes of a big endian number that follows.  There is none (`none`) when the length is the indefinite
form (0x80), is written in more than 4 bytes, or reaches past `stop`, or when the tag or the length
are cut by `stop`. -/
def DerContent (bytes : List Std.U8) (start stop : Nat) : Option (Nat × Nat) :=
  match bytes[start + 1]? with
  | none => none
  | some first =>
    if stop < start + 2 then none
    else if first.val < 128 then
      if start + 2 + first.val ≤ stop then some (start + 2, first.val) else none
    else
      let octets := first.val - 128
      if octets = 0 ∨ 4 < octets ∨ stop < start + 2 + octets then none
      else if start + 2 + octets + BigEndian bytes (start + 2) octets ≤ stop then
        some (start + 2 + octets, BigEndian bytes (start + 2) octets)
      else none

/-- The elements of a DER sequence that end before `stop`, in order, from `start` to `finish`: a
list of spans (their contents) of which the first is the content of the element that begins at
`start`, each of the others the content of the element that begins where the one before it ends, and
the last ends at `finish`.  Each element is read as `DerContent` says, inside the bytes before
`stop`. -/
def ElementsRun (bytes : List Std.U8) (stop : Nat) : Nat → Nat → List Span → Prop
  | start, finish, [] => start = finish
  | start, finish, item :: rest =>
      DerContent bytes start stop = some (item.off.val, item.len.val) ∧
      ElementsRun bytes stop (item.off.val + item.len.val) finish rest

/-- The elements fill the bytes from `start` to `stop`: the elements of a sequence whose content is
those bytes.  No byte is left out and none is in two elements. -/
def ElementsFill (bytes : List Std.U8) (start stop : Nat) (items : List Span) : Prop :=
  ElementsRun bytes stop start stop items

/-- The pieces of the bodies of a list of packets, in order: for each packet its body, then its
further pieces (a packet cut by partial lengths has several). -/
def Pieces : List packet.Packet → List Span
  | [] => []
  | packet :: rest => packet.body :: (packet.more.val ++ Pieces rest)

/-- The pieces are laid out in order after position `start`, and the last one ends at `stop`: the
first begins at least a byte after `start` (a header, or the length octets of a partial piece, is
between), each of the others begins at least a byte after the end of the one before, and nothing is
left after the last one (the pieces and the bytes between them are the whole of the bytes from
`start` to `stop`).  With no pieces, `start` is `stop`. -/
def PiecesFrom : Nat → List Span → Nat → Prop
  | start, [], stop => start = stop
  | start, piece :: rest, stop =>
      start < piece.off.val ∧ PiecesFrom (piece.off.val + piece.len.val) rest stop

/-- A subpacket of a signature, as the bytes say it: where its length octets begin (`start`), where
its kind byte is (`body`, just after the length octets), and its length (`len`: the kind byte and
the value that follows it). -/
structure Sub where
  start : Nat
  body : Nat
  len : Nat

/-- The length written at `p`, and the number of octets it takes, for a subpacket inside the bytes
before `stop` (RFC 4880, 5.2.3.1): a first octet below 192 is the length itself; from 192 to 254 it
and the next octet make `(first - 192) * 256 + second + 192`; 255 begins a length of 4 octets. There
is none (`none`) when the octets are cut by `stop`. -/
def LengthAt (bytes : List Std.U8) (p stop : Nat) : Option (Nat × Nat) :=
  match bytes[p]? with
  | none => none
  | some first =>
    if first.val < 192 then some (first.val, 1)
    else if first.val < 255 then
      if p + 1 < stop then
        (bytes[p + 1]?).map (fun second => ((first.val - 192) * 256 + second.val + 192, 2))
      else none
    else if p + 5 ≤ stop then some (BigEndian bytes (p + 1) 4, 5) else none

/-- The subpackets of an area that end before `stop`, in order, from `start` to `finish`: the first
begins at `start`, each of the others where the one before it ends, and the last ends at `finish`.
Each has a length written as `LengthAt` says, of at least one (the kind), and ends before `stop`. -/
def SubsRun (bytes : List Std.U8) (stop : Nat) : Nat → Nat → List Sub → Prop
  | start, finish, [] => start = finish
  | start, finish, sub :: rest =>
      start < stop ∧ sub.start = start ∧
      (∃ octets, LengthAt bytes start stop = some (sub.len, octets) ∧ sub.body = start + octets) ∧
      1 ≤ sub.len ∧ sub.body + sub.len ≤ stop ∧ SubsRun bytes stop (sub.body + sub.len) finish rest

/-- The subpackets that make up the area from `start` to `stop`: they fill it, with no byte left
over and none in two of them. -/
def AreaMadeOf (bytes : List Std.U8) (start stop : Nat) (subs : List Sub) : Prop :=
  SubsRun bytes stop start stop subs

/-- The byte at `p` as a number (0 when there is none). -/
def ByteAt (bytes : List Std.U8) (p : Nat) : Nat :=
  ((bytes[p]?).map (fun byte => byte.val)).getD 0

/-- The kind of a subpacket: the low 7 bits of its first byte. -/
def Sub.kind (bytes : List Std.U8) (sub : Sub) : Nat := ByteAt bytes sub.body % 128

/-- A subpacket is critical when the top bit of its first byte is set: the signer says a reader that
does not understand it must refuse the signature. -/
def Sub.Critical (bytes : List Std.U8) (sub : Sub) : Prop := 128 ≤ ByteAt bytes sub.body

/-- The last subpacket of the kind `kind` of a list, if there is one. -/
def LastOfKind (bytes : List Std.U8) (subs : List Sub) (kind : Nat) : Option Sub :=
  (subs.filter (fun sub => sub.kind bytes == kind)).getLast?

/-- The time a time subpacket says: the 4 bytes of its value, after the kind byte. -/
def Sub.Time (bytes : List Std.U8) (sub : Sub) : Nat := BigEndian bytes (sub.body + 1) 4

/-- The key flags a subpacket says: the first byte of its value, or none (no flag) when it has no
byte. -/
def Sub.Flags (bytes : List Std.U8) (sub : Sub) : Nat :=
  if 2 ≤ sub.len then ByteAt bytes (sub.body + 1) else 0

/-- The subpacket kinds the reader reads: 2 creation time, 3 signature expiration time, 9 key
expiration time, 16 issuer key ID, 27 key flags, 32 embedded signature, 33 issuer fingerprint. -/
def ReadKinds : List Nat := [2, 3, 9, 16, 27, 32, 33]

/-- The other subpacket kinds that may carry the critical bit and are still accepted in the hashed
area: they say nothing a verifier of simple signing has to act on (RFC 4880 and RFC 9580: 4
exportable certification, 5 trust, 7 revocable, 11 preferred symmetric algorithms, 12 revocation
key, 21 preferred hash algorithms, 22 preferred compression algorithms, 23 key server preferences,
25 primary user ID, 26 policy URI, 28 signer's user ID, 29 reason for revocation, 30 features, 31
signature target, 34 preferred AEAD algorithms, RFC 4880bis). -/
def IgnoredKinds : List Nat := [4, 5, 7, 11, 12, 21, 22, 23, 25, 26, 28, 29, 30, 31, 34]

/-- The subpacket kinds a critical subpacket of the hashed area may be of: the ones the reader reads
and the ones it may ignore.  Not in it: 20 (a notation), which no reader of this crate understands,
and every kind not named here. -/
def KnownKinds : List Nat := ReadKinds ++ IgnoredKinds

/-- A subpacket of the hashed area that the reader does not refuse for what it says (its length and
its place are another matter: `AreaMadeOf`): a creation time, a signature expiration time or a key
expiration time has 4 bytes of value (so its length, the kind byte and them, is 5), and a critical
one is of a known kind. -/
def Sub.Acceptable (bytes : List Std.U8) (sub : Sub) : Prop :=
  (sub.kind bytes = 2 ∨ sub.kind bytes = 3 ∨ sub.kind bytes = 9 → sub.len = 5) ∧
  (sub.Critical bytes → sub.kind bytes ∈ KnownKinds)

/-- The spans follow each other from `start` to `finish`: the first begins at or after `start`, each
of the others at or after the end of the one before, and the last ends at `finish` (with none,
`start` is `finish`).  Nothing says what is between them. -/
def Follow : Nat → List Span → Nat → Prop
  | start, [], finish => start = finish
  | start, span :: rest, finish =>
      start ≤ span.off.val ∧ Follow (span.off.val + span.len.val) rest finish

/-- How many values a signature of the algorithm `algo` has (RFC 4880 and 9580): 1 for RSA (1, 3)
and for Ed25519 (27), 2 for DSA, ECDSA and legacy EdDSA (17, 19, 22); none for any other algorithm,
which the reader refuses. -/
def ValueCount (algo : Nat) : Option Nat :=
  if algo = 1 ∨ algo = 3 ∨ algo = 27 then some 1
  else if algo = 17 ∨ algo = 19 ∨ algo = 22 then some 2
  else none

/-- Where `count` integers end when the first begins at `start`: each is two bytes of a bit count
and the bytes the bits need (the bit count, rounded up to whole bytes; RFC 4880, 3.2), so the first
ends at `start + 2 + (bits + 7) / 8` and the next begins there. -/
def IntegersEnd (bytes : List Std.U8) : Nat → Nat → Nat → Prop
  | 0, start, finish => finish = start
  | count + 1, start, finish =>
      IntegersEnd bytes count (start + 2 + (BigEndian bytes start 2 + 7) / 8) finish

/-- The `count` integers that begin at `position` are all inside the data: they end at or before the
end of the data. -/
def IntegersFrom (bytes : List Std.U8) (count position : Nat) : Prop :=
  ∃ finish, IntegersEnd bytes count position finish ∧ finish ≤ bytes.length

/-- The values of a signature of the algorithm `algo` that begin at `position`, as the reader takes
them: a known algorithm (`ValueCount`), and for Ed25519 (27) one value of 64 raw bytes, no bit
count, for the others their integers (`IntegersFrom`), all inside the data. -/
def ValuesFrom (bytes : List Std.U8) (algo position : Nat) : Prop :=
  match ValueCount algo with
  | none => False
  | some count =>
      if algo = 27 then position + 64 ≤ bytes.length else IntegersFrom bytes count position

/-- Where the hashed area of a signature packet ends: it begins at byte 6, and its length is the
number bytes 4 and 5 make.  The bytes before this position are the trailer the signature hashes. -/
def HashedEnd (bytes : List Std.U8) : Nat := 6 + BigEndian bytes 4 2

/-- Where the unhashed area ends: it begins two bytes (its length) after the hashed area. -/
def UnhashedEnd (bytes : List Std.U8) : Nat :=
  HashedEnd bytes + 2 + BigEndian bytes (HashedEnd bytes) 2

/-- The v4 signature packets `signature` accepts, described from the RFC (5.2.3), not from the
code. -/
structure WellFormedSignature (bytes : List Std.U8) : Prop where
  /-- The first byte is the version, 4 (a list with no first byte has none). -/
  version_four : ByteAt bytes 0 = 4
  /-- The hashed area, and the two bytes of the length of the unhashed area after it, are inside
  the data. -/
  hashed_area_inside : HashedEnd bytes + 2 ≤ bytes.length
  /-- The hashed area is made of subpackets (`AreaMadeOf`), each of which the reader accepts there
  (`Sub.Acceptable`): the times have 4 bytes, and a critical one is of a known kind. -/
  hashed_area_is_subpackets : ∃ subs, AreaMadeOf bytes 6 (HashedEnd bytes) subs ∧
    ∀ sub ∈ subs, sub.Acceptable bytes
  /-- The unhashed area, and the two bytes of the 16 bits of the hash after it, are inside the
  data. -/
  unhashed_area_inside : UnhashedEnd bytes + 2 ≤ bytes.length
  /-- The unhashed area is made of subpackets.  Nothing else is asked of them: the times, the
  critical bit and the kinds mean nothing there. -/
  unhashed_area_is_subpackets :
    ∃ subs, AreaMadeOf bytes (HashedEnd bytes + 2) (UnhashedEnd bytes) subs
  /-- The algorithm (byte 2) is one with a known number of values, and they follow the 16 bits of
  the hash and lie inside the data: for each integer a bit count and the bytes it needs, or for
  Ed25519 64 bytes (`ValuesFrom`).  Bytes after the values are allowed and not looked at; the type
  (byte 1) and the hash algorithm (byte 3) may be any byte here. -/
  values_are_there : ValuesFrom bytes (ByteAt bytes 2) (UnhashedEnd bytes + 2)

/-- The bytes a span of `bytes` is: `len` bytes from `off`. -/
def SpanBytes (bytes : List Std.U8) (span : Span) : List Std.U8 :=
  (bytes.drop span.off.val).take span.len.val

/-- The bytes are packets in the new format, each with a length of one byte, as the list says (the
tag and the body of each, in order): each is a header byte (192 plus the tag, which is below 64), a
length byte (the length of the body, below 192) and the body, and nothing follows the last. -/
def SimplePackets : List Std.U8 → List (Nat × List Std.U8) → Prop
  | bytes, [] => bytes = []
  | bytes, (tag, body) :: rest =>
      tag < 64 ∧ body.length < 192 ∧
      ∃ header length after, bytes = header :: length :: (body ++ after) ∧
        header.val = 192 + tag ∧ length.val = body.length ∧ SimplePackets after rest


/-- The spans as pairs (where it begins, how long it is). -/
def SpanPairs (spans : alloc.vec.Vec Span) : List (Nat × Nat) :=
  spans.val.map (fun span => (span.off.val, span.len.val))



/-! ### DER -/

/-- **`element` always returns.**  For every byte string, whatever its length and whatever the
length it says: no panic, no overflow, no byte read outside the data, every loop ends.

Not said: what it answers (the next two claims). -/
def DerElementAlwaysReturns : Prop :=
  ∀ data : Slice Std.U8, der.element data ⦃ _ => True ⦄

/-- **`element` accepts exactly the well-formed elements.**  It returns, and:
- when it accepts, the tag is the first byte of the data, and the content is where `DerContent` puts
  it: the tag is one byte, the length is definite (a byte below 128, or the number of bytes of a big
  endian number that follows, from 1 to 4), and the content lies inside the data;
- when it refuses, there is no such element (`DerContent` is `none`: the indefinite form 0x80, a
  long form of more than 4 bytes, a length past the end, or a header that is cut). So a reader that
  refuses everything does not satisfy it: every element `DerContent` finds is accepted.  (A long
  form that is not minimal is accepted: `DerContent` takes it.)

Not said: anything of what follows the element (it is not looked at), or of the tag (any byte). -/
def DerElementIsAcceptedExactlyWhenItIsWellFormed : Prop :=
  ∀ data : Slice Std.U8, der.element data ⦃ r =>
    (∀ tag content, r = core.result.Result.Ok (tag, content) →
      data.val[0]? = some tag ∧
      DerContent data.val 0 data.val.length = some (content.off.val, content.len.val)) ∧
    (∀ why, r = core.result.Result.Err why → DerContent data.val 0 data.val.length = none) ⦄

/-- **The content of an accepted element is after its header and inside the data.**  `element`
returns, and when it accepts, the content begins at least two bytes in (after the tag and at least
one byte of length) and ends at or before the end of the data.

Not said: that it ends exactly there (what follows is not looked at). -/
def AnAcceptedDerElementIsDefiniteAndInside : Prop :=
  ∀ data : Slice Std.U8, der.element data ⦃ r =>
    ∀ tag content, r = core.result.Result.Ok (tag, content) →
      2 ≤ content.off.val ∧ content.off.val + content.len.val ≤ data.val.length ⦄

/-- **`sequence_items` always returns.**  For every byte string: no panic, no overflow, no index
outside the data, every loop ends, and the list of items is not longer than the data allows.

Not said: what it answers (the next claim). -/
def SequenceItemsAlwaysReturns : Prop :=
  ∀ data : Slice Std.U8, der.sequence_items data ⦃ _ => True ⦄

/-- **The items of an accepted sequence fill it.**  `sequence_items` returns, and when it accepts,
the data begins with a DER element of tag 0x30 and a definite length (`DerContent`), and the items
are the contents of the elements that fill its content (`ElementsFill`): the first element begins
where the content begins, each other where the one before it ends, each one is a well-formed element
that ends inside the content, and the last ends where the content ends.  So the items are in order,
do not overlap (each is after the tag and the length of its element) and leave no byte of the
content out.

Not said: the tags of the items (they are not looked at: any byte); what follows the sequence in the
data (it is not looked at); that the sequence is the one of a certificate (no more is checked). -/
def AcceptedSequenceItemsFillTheSequence : Prop :=
  ∀ data : Slice Std.U8, der.sequence_items data ⦃ r =>
    ∀ items, r = core.result.Result.Ok items →
      ∃ content : Span, data.val[0]? = some 48#u8 ∧
        DerContent data.val 0 data.val.length = some (content.off.val, content.len.val) ∧
        ElementsFill data.val content.off.val (content.off.val + content.len.val) items.val ⦄

/-! ### OpenPGP packets -/

/-- **`packets` always returns.**  For every byte string, with any lengths in its headers (a
four-byte length near 2^32 included): no panic, no overflow, no index outside the data, every loop
ends, and no more than `MAX_PACKETS` pieces are collected.

Not said: what it answers (the next claims). -/
def PacketsAlwaysReturn : Prop :=
  ∀ data : Slice Std.U8, packet.packets data ⦃ _ => True ⦄

/-- **The packets of accepted data cover it.**  `packets` returns, and when it accepts, the pieces
of the bodies of its packets (the body of each packet, then its further pieces when partial lengths
cut it: `Pieces`) are laid out over all the data (`PiecesFrom`): the first begins at least a byte
after the start (the header), each of the others at least a byte after the end of the one before
(the header of the next packet, or the length octets of the next piece), and the last ends at the
end of the data.  So the bodies are in order and do not overlap, and no byte is left: data with a
byte after the last packet (a byte that does not begin a packet, or begins one that is cut) is
refused.

Not said: what is in the bytes between the pieces (the headers: the claim only says there is at
least one byte before each piece); the tags. -/
def AcceptedPacketsCoverTheInput : Prop :=
  ∀ data : Slice Std.U8, packet.packets data ⦃ r =>
    ∀ packets, r = core.result.Result.Ok packets →
      PiecesFrom 0 (Pieces packets.val) data.val.length ⦄

/-- **Every piece of an accepted packet lies inside the data.**  `packets` returns, and when it
accepts, every piece of every packet ends at or before the end of the data. -/
def AcceptedPacketSpansAreInsideTheInput : Prop :=
  ∀ data : Slice Std.U8, packet.packets data ⦃ r =>
    ∀ packets, r = core.result.Result.Ok packets →
      ∀ piece ∈ Pieces packets.val, piece.off.val + piece.len.val ≤ data.val.length ⦄

/-- **No more than `MAX_PACKETS` pieces.**  `packets` returns, and when it accepts, the pieces of
all the packets are at most `MAX_PACKETS` (100000: the packets when no partial length is used). -/
def AcceptedPacketsAreNoMoreThanTheLimit : Prop :=
  ∀ data : Slice Std.U8, packet.packets data ⦃ r =>
    ∀ packets, r = core.result.Result.Ok packets →
      (Pieces packets.val).length ≤ packet.MAX_PACKETS.val ⦄

/-- **Empty data is accepted, with no packet.**  `packets` of the empty byte string returns, and
accepts, with no packet.  It shows that the claims above are not satisfied by a reader that refuses
everything.

Not said: that any other data is accepted. -/
def EmptyDataIsAccepted : Prop :=
  packet.packets (Slice.new Std.U8) ⦃ r =>
    ∃ packets, r = core.result.Result.Ok packets ∧ packets.val = [] ⦄

/-! ### The signature packet -/

/-- **`signature` always returns.**  For every byte string, with any lengths in its fields and its
subpackets: no panic, no overflow, no index outside the data, every loop ends.

Not said: what it answers (the next claims). -/
def SignatureAlwaysReturns : Prop :=
  ∀ body : Slice Std.U8, sig.signature body ⦃ _ => True ⦄

/-- **An accepted signature is laid out like a version 4 packet.**  `signature` returns, and when it
accepts: the version byte is 4 (any other version is refused); the hashed area begins at byte 6,
after the version, the type, the algorithm, the hash and the two bytes of its length, which it is;
the unhashed area begins two bytes after the hashed area, which are its length; two more bytes (16
bits of the hash) follow, and they are inside the data; the type, the algorithm and the hash are the
bytes 1, 2 and 3.

Not said: anything of the values or the subpackets (the claims below); that the algorithm is one
that can verify. -/
def AcceptedSignatureIsLaidOutLikeVersion4 : Prop :=
  ∀ body : Slice Std.U8, sig.signature body ⦃ r =>
    ∀ signature, r = core.result.Result.Ok signature →
      ByteAt body.val 0 = 4 ∧ signature.sig_type.val = ByteAt body.val 1 ∧
      signature.algo.val = ByteAt body.val 2 ∧ signature.hash.val = ByteAt body.val 3 ∧
      signature.hashed.off.val = 6 ∧
      signature.hashed.len.val = BigEndian body.val 4 2 ∧
      signature.unhashed.off.val = signature.hashed.off.val + signature.hashed.len.val + 2 ∧
      signature.unhashed.len.val =
        BigEndian body.val (signature.hashed.off.val + signature.hashed.len.val) 2 ∧
      signature.unhashed.off.val + signature.unhashed.len.val + 2 ≤ body.val.length ⦄

/-- **The trailer is the bytes from the start of the body to the end of the hashed area.**
`signature` returns, and when it accepts, the hashed area is the bytes 6 to `6 + n` where `n` is the
number the bytes 4 and 5 make, and it is inside the data.  So the bytes `body[..hashed.end()]`,
which the shell hashes after the data (then the trailer 0x04, 0xff and their length), are the
version, the type, the algorithm, the hash, the length and the hashed subpackets, and no byte of the
unhashed area.

Not said: the bytes the shell adds. -/
def TheTrailerIsTheBytesUpToTheEndOfTheHashedArea : Prop :=
  ∀ body : Slice Std.U8, sig.signature body ⦃ r =>
    ∀ signature, r = core.result.Result.Ok signature →
      signature.hashed.off.val = 6 ∧
      signature.hashed.off.val + signature.hashed.len.val = 6 + BigEndian body.val 4 2 ∧
      signature.hashed.off.val + signature.hashed.len.val + 2 ≤ body.val.length ⦄

/-- **The values follow the areas, and are as many as the algorithm has.**  `signature` returns, and
when it accepts, the values (their spans) follow each other from the end of the unhashed area and
the 16 bits of the hash, in order, and the last ends inside the data (`Follow`); there are as many
as the algorithm has (`ValueCount`: 1 for RSA and Ed25519, 2 for DSA, ECDSA and legacy EdDSA; any
other algorithm is refused).

Not said: what is after the values (it is not looked at: a signature may be padded and still
verify); that the numbers of the values are right. -/
def AcceptedValuesFollowTheAreas : Prop :=
  ∀ body : Slice Std.U8, sig.signature body ⦃ r =>
    ∀ signature, r = core.result.Result.Ok signature →
      (∃ finish, Follow (signature.unhashed.off.val + signature.unhashed.len.val + 2)
        signature.values.val finish ∧ finish ≤ body.val.length) ∧
      ValueCount signature.algo.val = some signature.values.val.length ⦄

/-- **The hashed area is made of subpackets.**  `signature` returns, and when it accepts, the hashed
area is made up of subpackets (`AreaMadeOf`): from its first byte, each has a length written as the
RFC says (one, two or five bytes), at least one (its kind), and ends inside the area, and the last
ends where the area ends: no byte is left over, and a subpacket that is cut refuses the signature.
The same holds of the unhashed area.

Not said: that the areas are the only way to read the bytes (they are; see the next claims, which
say `∀ subs` and rest on the decomposition being unique). -/
def TheHashedAreaIsMadeOfSubpackets : Prop :=
  ∀ body : Slice Std.U8, sig.signature body ⦃ r =>
    ∀ signature, r = core.result.Result.Ok signature →
      ∃ hashed_subs unhashed_subs,
        AreaMadeOf body.val signature.hashed.off.val
          (signature.hashed.off.val + signature.hashed.len.val) hashed_subs ∧
        AreaMadeOf body.val signature.unhashed.off.val
          (signature.unhashed.off.val + signature.unhashed.len.val) unhashed_subs ⦄

/-- **No critical subpacket of an unknown kind is in the hashed area of an accepted signature.**
`signature` returns, and when it accepts, every subpacket of the hashed area (as `AreaMadeOf` splits
it) whose critical bit is set is of a kind of `KnownKinds`: the kinds the reader reads (2, 3, 9, 16,
27, 32, 33) and the ones that say nothing a verifier of simple signing has to act on
(`IgnoredKinds`). Any other kind with the bit set refuses the signature, and so does a notation
(kind 20).

Not said: anything of the unhashed area (the bit means nothing there: anybody can add subpackets to
it); anything of a subpacket without the critical bit (it may be of any kind: it is a note). -/
def NoUnknownCriticalSubpacketInTheHashedArea : Prop :=
  ∀ body : Slice Std.U8, sig.signature body ⦃ r =>
    ∀ signature, r = core.result.Result.Ok signature →
      ∀ subs, AreaMadeOf body.val signature.hashed.off.val
          (signature.hashed.off.val + signature.hashed.len.val) subs →
        ∀ sub ∈ subs, sub.Critical body.val → sub.kind body.val ∈ KnownKinds ⦄

/-- **No critical notation is accepted.**  `signature` returns, and when it accepts, no subpacket of
the hashed area is a notation (kind 20) with the critical bit: the reader understands no notation,
so the signer's "refuse if you do not understand" is obeyed.  A notation without the bit is a note
and is accepted.

Not said: anything of the unhashed area. -/
def NoCriticalNotationIsAccepted : Prop :=
  ∀ body : Slice Std.U8, sig.signature body ⦃ r =>
    ∀ signature, r = core.result.Result.Ok signature →
      ∀ subs, AreaMadeOf body.val signature.hashed.off.val
          (signature.hashed.off.val + signature.hashed.len.val) subs →
        ∀ sub ∈ subs, sub.kind body.val = 20 → ¬ sub.Critical body.val ⦄

/-- **The times and the key flags are those of the hashed area, and of it only.**  `signature`
returns, and when it accepts, for each of the creation time (kind 2), the signature expiration time
(3), the key expiration time (9) and the key flags (27): the value in the answer is that of the LAST
subpacket of that kind of the hashed area (`LastOfKind`), and there is none in the answer when there
is no such subpacket.  The time subpackets have 4 bytes of value.  Key flags of no byte are the
flags 0 (nothing is allowed), not "no flags".  What the answer holds is read off the subpackets of
the hashed area only: the subpackets of that area, and their kinds, lengths and values, are
determined by the bytes between its start and its end (`LengthAt`, `ByteAt`, `BigEndian` look at no
byte at or after the end of the area), so appending subpackets to the unhashed area, or changing
anything after the hashed area, cannot change them.

Not said: that the last is what the signer meant; gpg reads the first of duplicates, go-crypto the
last.  For two inputs that agree up to the end of the hashed area see
`SignaturesThatAgreeUpToTheHashedAreaHaveTheSameTimes`. -/
def TimesAndFlagsAreOfTheHashedAreaOnly : Prop :=
  ∀ body : Slice Std.U8, sig.signature body ⦃ r =>
    ∀ signature, r = core.result.Result.Ok signature →
      ∀ subs, AreaMadeOf body.val signature.hashed.off.val
          (signature.hashed.off.val + signature.hashed.len.val) subs →
        signature.sub.created.map (fun time => time.val) =
          (LastOfKind body.val subs 2).map (·.Time body.val) ∧
        signature.sub.expires.map (fun time => time.val) =
          (LastOfKind body.val subs 3).map (·.Time body.val) ∧
        signature.sub.key_expires.map (fun time => time.val) =
          (LastOfKind body.val subs 9).map (·.Time body.val) ∧
        signature.sub.key_flags.map (fun flags => flags.val) =
          (LastOfKind body.val subs 27).map (·.Flags body.val) ∧
        (∀ sub ∈ subs, (sub.kind body.val = 2 ∨ sub.kind body.val = 3 ∨ sub.kind body.val = 9) →
          sub.len = 5) ⦄

/-- **The embedded signatures are the values of the embedded subpackets.**  `signature` returns, and
when it accepts, the embedded signatures of the answer are, in order, the values (the bytes after
the kind byte) of the subpackets of kind 32 of the hashed area and then of the unhashed area (the
areas are as `AreaMadeOf` splits them).  They are hints: the shell verifies each against the subkey.

Not said: that an embedded signature is valid. -/
def EmbeddedSignaturesAreTheValuesOfTheEmbeddedSubpackets : Prop :=
  ∀ body : Slice Std.U8, sig.signature body ⦃ r =>
    ∀ signature, r = core.result.Result.Ok signature →
      ∀ hashed_subs unhashed_subs,
        AreaMadeOf body.val signature.hashed.off.val
          (signature.hashed.off.val + signature.hashed.len.val) hashed_subs →
        AreaMadeOf body.val signature.unhashed.off.val
          (signature.unhashed.off.val + signature.unhashed.len.val) unhashed_subs →
          SpanPairs signature.sub.embedded =
            ((hashed_subs ++ unhashed_subs).filter (fun sub => sub.kind body.val == 32)).map
              (fun sub => (sub.body + 1, sub.len - 1)) ⦄

/-- **The issuer fingerprint lies inside the areas.**  `signature` returns, and when it accepts, a
fingerprint in the answer, if there is one, ends inside the subpacket areas (so inside the data).

Not said: that it is the fingerprint of the signer (a hint). -/
def TheIssuerFingerprintIsInsideTheAreas : Prop :=
  ∀ body : Slice Std.U8, sig.signature body ⦃ r =>
    ∀ signature, r = core.result.Result.Ok signature →
      ∀ span, signature.sub.issuer_fpr = some span →
        span.off.val + span.len.val ≤ signature.unhashed.off.val + signature.unhashed.len.val ⦄

/-! ### The signature packet: what is accepted -/

/-- **A well formed signature packet is accepted.**  `signature` returns, and for every byte string
that is a well formed version 4 signature packet (`WellFormedSignature`: version 4; both areas
inside the data and made of subpackets, those of the hashed area being ones the reader accepts,
which are the ones that have no time of a wrong size and no critical subpacket of an unknown kind;
a known algorithm, and its values all there), it accepts.  With `AcceptedSignaturesAreWellFormed`
this says that `signature` accepts exactly the well formed packets.

It shows that a reader that refuses everything does not satisfy the claims about `signature`.

Not said: what the answer is (the claims above, and the two below for the simplest packets); that
the values are as the RFC wants them (their bit counts and the bytes they need are laid out, no
more: that an accepted value has no leading zero bit, for instance, is not looked at); that an
accepted packet is valid, or that it verifies. -/
def WellFormedSignaturesAreAccepted : Prop :=
  ∀ body : Slice Std.U8, WellFormedSignature body.val →
    sig.signature body ⦃ r => ∃ signature, r = core.result.Result.Ok signature ⦄

/-- **An accepted signature packet is well formed.**  `signature` returns, and when it accepts, the
bytes are a `WellFormedSignature`: the version is 4; the areas are inside the data and made of
subpackets, those of the hashed area being ones the reader accepts (no time of a wrong size, no
critical subpacket of an unknown kind); the algorithm is a known one and its values are all there,
each integer as a bit count and the bytes it needs.  With `WellFormedSignaturesAreAccepted` this is
"`signature` accepts exactly the well formed signature packets".

Not said: what the answer is (the claims above); what is after the values. -/
def AcceptedSignaturesAreWellFormed : Prop :=
  ∀ body : Slice Std.U8, sig.signature body ⦃ r =>
    ∀ signature, r = core.result.Result.Ok signature → WellFormedSignature body.val ⦄

/-- **Two accepted signatures that agree up to the end of the hashed area have the same times and
key flags.**  Take two byte strings, and suppose `signature` accepts both, with the answers
`signature` and `signature'`, and that they begin with the same bytes up to the end of the hashed
area of the first (`HashedEnd`: these are the bytes the signature hashes after the data, with the
version, the type, the algorithm, the hash and the length of the hashed area; so the second has
the same hashed area).  Then the creation time, the signature expiration, the key expiration and
the key flags of the two answers are the same.  It follows that nothing after the hashed area (the
unhashed area, the hash bits, the values, whatever follows) can change them, which is what makes
them the signer's: the signature covers the bytes they are read from.

Not said: anything of the other fields of the answer (the unhashed area, the values and the
issuer hints, which are not covered by the signature and may differ). -/
def SignaturesThatAgreeUpToTheHashedAreaHaveTheSameTimes : Prop :=
  ∀ (body body' : Slice Std.U8) (signature signature' : sig.Signature),
    sig.signature body = ok (core.result.Result.Ok signature) →
    sig.signature body' = ok (core.result.Result.Ok signature') →
    body.val.take (HashedEnd body.val) = body'.val.take (HashedEnd body.val) →
    signature.sub.created = signature'.sub.created ∧
    signature.sub.expires = signature'.sub.expires ∧
    signature.sub.key_expires = signature'.sub.key_expires ∧
    signature.sub.key_flags = signature'.sub.key_flags

/-- **A signature with no subpacket is accepted.** The packet is the version 4 (byte 0), the type,
the algorithm and the hash (bytes 1 to 3), a hashed area of length 0 (bytes 4 and 5), an unhashed
area of length 0 (bytes 6 and 7), two bytes of the hash (8 and 9), and the values from byte 10: for
a known algorithm, either 64 bytes (Ed25519) or its integers, each a two byte bit count and the
bytes the bits need (`ValuesFrom`). Then `signature` accepts it, the bytes the signature hashes
after the data are the first 6 bytes (the hashed area ends at byte 6), and the answer has no
creation time, no expiration, no key expiration and no key flags.

Not said: anything of packets with subpackets (the next claim and
`WellFormedSignaturesAreAccepted`); what is after the values (not looked at). -/
def ASignatureWithNoSubpacketsIsAccepted : Prop :=
  ∀ body : Slice Std.U8, ByteAt body.val 0 = 4 → BigEndian body.val 4 2 = 0 →
    BigEndian body.val 6 2 = 0 → 10 ≤ body.val.length →
    ValuesFrom body.val (ByteAt body.val 2) 10 →
    sig.signature body ⦃ r => ∃ signature, r = core.result.Result.Ok signature ∧
      signature.hashed.off.val + signature.hashed.len.val = 6 ∧
      signature.sub.created = none ∧ signature.sub.expires = none ∧
      signature.sub.key_expires = none ∧ signature.sub.key_flags = none ⦄

/-- **A signature with one creation time is accepted, with that time.** The packet is as in
`ASignatureWithNoSubpacketsIsAccepted`, but the hashed area has length 6 (bytes 4 and 5) and is one
subpacket: the length 5 (byte 6), the kind 2, a creation time (byte 7), and the four bytes of the
time (8 to 11); then the unhashed area, of length 0 (bytes 12 and 13), two bytes of the hash (14 and
15), and the values from byte 16. Then `signature` accepts it, the bytes the signature hashes after
the data are the first 12 bytes, the creation time is the number the bytes 8 to 11 make, and there
is no expiration, no key expiration and no key flags.

Not said: anything of other subpackets (the claims above), or of two creation times (the last one
counts). -/
def ASignatureWithOneCreationTimeIsAccepted : Prop :=
  ∀ body : Slice Std.U8, ByteAt body.val 0 = 4 → BigEndian body.val 4 2 = 6 →
    ByteAt body.val 6 = 5 → ByteAt body.val 7 = 2 → BigEndian body.val 12 2 = 0 →
    16 ≤ body.val.length → ValuesFrom body.val (ByteAt body.val 2) 16 →
    sig.signature body ⦃ r => ∃ signature, r = core.result.Result.Ok signature ∧
      signature.hashed.off.val + signature.hashed.len.val = 12 ∧
      signature.sub.created.map (fun time => time.val) = some (BigEndian body.val 8 4) ∧
      signature.sub.expires = none ∧ signature.sub.key_expires = none ∧
      signature.sub.key_flags = none ⦄

/-! ### OpenPGP packets: what is accepted -/

/-- **Packets in the new format with one-byte lengths are accepted.**  For every list of packets (a
tag below 64 and a body shorter than 192 bytes each, at most `MAX_PACKETS` of them), the data that
is their concatenation, each as a header byte (192 plus the tag), a length byte and the body
(`SimplePackets`), is accepted by `packets`; the packets of the answer are those, in order: the tags
are the tags, the bodies (the bytes of their spans) are the bodies, and none has a second piece.

It shows that `packets` does not refuse everything: with `AcceptedPacketsCoverTheInput` it says that
for these inputs the answer is the one and only reading.

Not said: anything of the other formats (the old format, two-byte and five-byte lengths, partial
lengths); that the data of any other shape is accepted or refused. -/
def SimplePacketsAreAccepted : Prop :=
  ∀ (data : Slice Std.U8) (parts : List (Nat × List Std.U8)), SimplePackets data.val parts →
    parts.length ≤ packet.MAX_PACKETS.val →
    packet.packets data ⦃ r => ∃ packets, r = core.result.Result.Ok packets ∧
      (∀ packet ∈ packets.val, packet.more.val = []) ∧
      packets.val.map (fun packet => (packet.tag.val, SpanBytes data.val packet.body)) = parts ⦄

end SigparseCore
