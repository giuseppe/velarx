-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: what is proved of crates/recv-core, the two judgements a node makes about what
-- a peer of the peer-to-peer network sends it, a peer that is trusted for nothing:
--   * the ANSWER to a request for chunks (`Reading`): which status bytes there are, which turn each
--     digest asked has, whether the length a peer announces for a chunk is taken, and how many bytes an
--     answer may hold (`Reading::new`, `claim`, `take`, `end`, `room`, `status`, `turn`, `item`);
--   * the FILTER a peer tells of the layers it holds (`Seen`): whether the size of a message may be a
--     filter's (`full_ok`, `delta_ok`, `full_text_ok`), what to do with a whole filter or a delta
--     (`Seen::full`, `delta`, `added`), and when the filter says "this peer does not have the layer"
--     (`Seen::says`).
-- This file is what a reviewer reads, in words and in statements, with no proof; Lean checks the rest
-- (the proofs are in the other files of RecvCore/, and Theorems.lean ties each claim below to its
-- proof).
--
-- Why it is needed: the peer may send any bytes, in any order, any size, again, for what was not
-- asked.  A length taken without a bound is memory handed to a stranger; a counter that wraps lets an
-- answer hold more than it may; a digest answered twice or never is a chunk that is stored under the
-- wrong name or a request that never ends; a filter that says "no" while a message of the peer is
-- missing hides a layer the peer holds.  The tests of the crate (src/walk.rs, src/rules.rs) check every
-- input of a small world; each claim below is the same rule for EVERY input.  A proof is worth what
-- its statement says, so each claim has a comment of what it claims and of what it does NOT.
--
-- Words.  A READING is the state of the answer to one request: how many digests were `asked`, how many
-- have had their turn (`next`), how many bytes of chunks were taken (`payload`), and the two bounds:
-- `max_item`, the most one chunk may weigh, and `max_payload`, the most an answer may hold.  A TURN is
-- the place of a digest in the list asked (0 for the first); `claim` gives it before the status byte of
-- that digest is read.  A chunk is TAKEN when `take` says `true` for the length the peer announced: its
-- bytes then count in `payload`.  There is ROOM for a chunk when the answer holds no bytes yet, or the
-- bytes held and the chunk are at most `max_payload` together (`HasRoom`).  A SEEN is what the node
-- keeps of one peer's filter: the RUN of the sender (`epoch`, a random number, so runs cannot be
-- ordered), the VERSION of the filter held, and the last version of that run HEARD of (`heard`).  The
-- filter is BEHIND when a version was heard of that the filter held does not have (`Behind`: `heard` is
-- past `version`): a message was lost, comes late, or is of another run.  The filter is CURRENT
-- otherwise (`Current`).  "BELIEVED" and "CONTAINS" are what the shell of the node tells `says`: that it
-- holds a filter it believes, and that the bits of the Bloom filter hold the key (the Bloom filter
-- itself and the clock are not in this crate).
--
-- Total correctness: each claim says that the function RETURNS (no panic, no overflow) and what its
-- answer is.  Nothing is assumed of a number beyond its type.
--
-- Both directions: "a chunk longer than the maximum is refused" alone is satisfied by a function that
-- refuses everything.  So the claims come in two kinds, what is refused and what must be taken
-- (`WhatTakeAcceptsExactly`, `ACorrectPeerIsAlwaysTaken`, `TheSizesOfAFilter`,
-- `AFilterTextOfAnyAllowedSizeIsAccepted`, `AWholeFilterThenItsDeltasKeepTheFilterCurrent`, the
-- examples), and most claims are an "exactly".
--
-- Read before this file: the header of crates/recv-core/src/lib.rs (its numbered rules), rules.rs and
-- walk.rs.
--
-- Index.  What each claim is about:
--
--   Claimed (each for every input):
--
--   The functions return
--     TheFunctionsAlwaysReturn            every function of the crate returns, whatever the numbers
--
--   The answer to a request for chunks (lib.rs, rules 2, 3 and 4)
--     WhatTheStatusBytesSay               the four status bytes are told apart, any other is `Bad`
--     WhatRoomSaysExactly                 there is room exactly by `HasRoom`, for any numbers
--     WhatTakeAcceptsExactly              a length is taken exactly when it is at most the largest item,
--                                         is the size asked, and there is room; then the bytes are added
--                                         with no wrapping, otherwise nothing changes
--     TheBoundsOfAnAnswerHold             the bytes held never pass the two maxima, after any calls
--     TheTurnsAreThoseAsked               a turn is the next one in the list, and `next` never passes `asked`
--     EveryDigestAskedHasOneTurn          the turns of an answer are 0, 1, .., asked - 1, once each, then none
--     AnAnswerThatEndedGivesNoTurn        after `end` no turn is given
--     ACorrectPeerIsAlwaysTaken           a chunk of the size asked, within the maxima, with room: taken
--     WhatAnItemIsTakenExactly            the answer to a request for one thing: taken exactly when it
--                                         is not empty and at most the bound asked
--
--   The filter (lib.rs, rules 6, 7, 8 and 9)
--     TheSizesOfAFilter                   `full_ok`, `delta_ok`: exactly the caps, no zero words
--     AFilterTextOfAnyAllowedSizeIsAccepted  `full_text_ok` never refuses the text of a filter of an allowed size
--     WhatAWholeFilterDoes                a whole filter is stale exactly when it is older than the one held
--     WhatADeltaDoes                      what the run, version and last heard become after a delta
--     WhatAddedDoes                       the version follows a delta only when it applied to it
--     WhatSaysAnswersExactly              "no" exactly when believed, not containing and not behind
--     ADeltaThatDoesNotFollowLeavesTheFilterBehind  a delta of the wrong base, from 0, or of another run
--                                         (for every version it names): behind
--     AWholeFilterThenItsDeltasKeepTheFilterCurrent  a whole filter, then the deltas in order: current
--     AFilterThatSaysNoIsAWholeFilterAndTheDeltasThatFollowedIt
--                                         after any messages, a "no" means one run, no gap: the last whole
--                                         filter and the deltas that moved the version since
--
--   Examples
--     TheWorkedExamples                   the answers for the numbers of the tests
--
--   Trusted: Charon and Aeneas (../../pins) and Lean; the crate calls the standard library only for
--   `is_multiple_of`, which Aeneas models; no model is written by hand.
--
--   Not claimed:
--   - the bytes themselves: that a chunk taken is the one asked (its digest is checked by the shell,
--     provider.rs), the base64, the Bloom filter bits, the clock, how long a filter is believed, and
--     what a peer that was wrong costs: this crate judges numbers, the shell keeps the rest;
--   - that a Bloom filter that holds a key is "contained": `says` is told whether the key is in the
--     bits; rule 9's "no key of the messages since the run last changed is ever answered no" needs the
--     bits (the rules.rs check does it with sets of keys) and is not stated here.  What is claimed is
--     the part that is the crate's: a "no" needs a believed, current filter (`WhatSaysAnswersExactly`),
--     and a message that does not follow leaves the filter behind
--     (`ADeltaThatDoesNotFollowLeavesTheFilterBehind`);
--   - the order of the digests in the answer matching what was asked (the shell reads the digests
--     from its own list, by the turn `claim` gives) and that a peer answers every digest: a byte that
--     never comes leaves its digest unanswered, which the shell sees as a short answer;
--   - that the sum of the answers of several requests is bounded: a reading is one request.
--
-- Notation:
--   - `f x ⦃ r => P r ⦄` reads: the Rust function `f`, given `x`, returns (it does not panic) and
--     its answer `r` satisfies `P r`.
--   - `x.val` is the number inside a `u8`, `u64` or `usize`, as a plain whole number (no wrapping);
--     `r.payload` is the field `payload` of the reading `r`; `a.1`, `a.2` are the first and the second
--     of a pair `a`.
--   - `Option` answers: `some x` is a value, `none` is "no value".
--   - `∀ x, P` is "for every x, P"; `∃ x, P` is "there is an x such that P"; `∧` is "and", `∨` is
--     "or", `→` is "if ... then", `↔` is "exactly when", `¬` is "not", `≠` is "is not equal to".
import Extracted.Funs

open Aeneas Aeneas.Std Result velarx_recv_core

namespace RecvCore

/-- There is room in an answer that holds `payload` bytes for a chunk of `len` more, when it may hold
`max`: the answer holds no bytes yet (the first chunk goes in whatever it weighs), or the chunk and the
bytes held are at most `max` together.  The sum is a plain number: it does not wrap. -/
def HasRoom (payload len max : Std.U64) : Prop :=
  payload.val = 0 ∨ payload.val + len.val ≤ max.val

/-- A chunk of `len` bytes is of the size asked: no size was asked (`none`), or the size asked is `len`. -/
def SizeMatches (len : Std.U64) (size : Option Std.U64) : Prop :=
  ∀ s, size = some s → s.val = len.val

/-- The answer holds what it may, or one chunk that was alone: its bytes are at most `max_payload`, or
at most `max_item` (the first chunk of an answer goes in whatever the answer may hold, up to the
largest item). -/
def Within (r : Reading) : Prop :=
  r.payload.val ≤ r.max_payload.val ∨ r.payload.val ≤ r.max_item.val

/-- The filter held is BEHIND: a version of the run was heard of that is past the version held. -/
def Behind (s : Seen) : Prop :=
  s.version.val < s.heard.val

/-- The filter is CURRENT at the version `v` of the run `e`: the run and the version are those, and
nothing newer was heard of (so it is not behind). -/
def Current (s : Seen) (e v : Std.U64) : Prop :=
  s.epoch = e ∧ s.version = v ∧ s.heard = v

/-- The turns of an answer as they are given, one `claim` after the other, `n` of them, from the
reading `r`: the list of what each gave.  This only repeats the call, as the node does while it reads. -/
def Turns : Nat → Reading → Result (List (Option Std.Usize))
  | 0, _ => ok []
  | n + 1, r => do
    let (turn, r') ← Reading.claim r
    let rest ← Turns n r'
    ok (turn :: rest)

/-- The versions of the deltas that come after the version `v` are in order: each is past the one before. -/
def Increasing : Std.U64 → List Std.U64 → Prop
  | _, [] => True
  | v, t :: ts => v.val < t.val ∧ Increasing t ts

/-- A filter that is held takes the deltas that go from `v`, in the order of their versions `tos`, as the
node does it (filter.rs): `delta`, then, when the delta is to be added, `added` once its keys are in. -/
def Follow (e : Std.U64) : Std.U64 → List Std.U64 → Seen → Result Seen
  | _, [], s => ok s
  | v, t :: ts, s => do
    let (_, s1) ← Seen.delta s e t true
    let s2 ← Seen.added s1 v t
    Follow e t ts s2

/-- A message of the peer about its filter: a whole filter of the run `e` and the version `v`, or a delta
of the run `e` that goes from the version `base` to the version `upto`.  Any numbers: the peer is
trusted for nothing. -/
inductive Message where
  | whole (e v : Std.U64)
  | delta (e base upto : Std.U64)

/-- What the node keeps of a peer's filter, and what it has to know to say how the filter got where it
is: the `Seen`; whether a whole filter was taken (`held`: the shell holds a filter then); and the CHAIN,
which is not in the code, only in this statement: the run and the version that the last whole filter
taken, then each delta of its run that moved the version since, lead to, each from the version the one
before reached and to a later one, and none from version 0.  The chain is `none` when no whole
filter was taken, or when a delta of another run came since the one that was. -/
structure Node where
  seen : Seen
  held : Bool
  chain : Option (Std.U64 × Std.U64)

/-- The chain after a delta of the run `e` from `base` to `upto` was added: it goes on to `upto` when the
chain is of that run, at the version `base`, which is not 0, and `upto` is past it; it is `none` when the
delta is of another run; and it is as it was otherwise (the keys of that delta are added to the filter, but
it is not the next step of the chain). -/
def Extend (chain : Option (Std.U64 × Std.U64)) (e base upto : Std.U64) :
    Option (Std.U64 × Std.U64) :=
  match chain with
  | none => none
  | some (run, version) =>
    if run ≠ e then none
    else if version = base ∧ version.val ≠ 0 ∧ version.val < upto.val then some (e, upto)
    else some (run, version)

/-- A node that has heard nothing, and the node after a message, as the shell does it (filter.rs): a whole
filter goes to `Seen::full`, and when it is taken the chain is that filter; a delta goes to
`Seen::delta`, and when it is to be added (`Add`), `Seen::added` is told once its keys are in, and the chain
is extended. -/
def Receive (m : Message) (n : Node) : Result Node :=
  match m with
  | Message.whole e v => do
    let (taken, s) ← Seen.full n.seen e v n.held
    match taken with
    | OnFull.Take => ok ⟨s, true, some (e, v)⟩
    | OnFull.Stale => ok ⟨s, n.held, n.chain⟩
  | Message.delta e base upto => do
    let (what, s1) ← Seen.delta n.seen e upto n.held
    match what with
    | OnDelta.Add =>
      let s2 ← Seen.added s1 base upto
      ok ⟨s2, n.held, Extend n.chain e base upto⟩
    | OnDelta.Stale => ok ⟨s1, n.held, n.chain⟩
    | OnDelta.Skip => ok ⟨s1, n.held, n.chain⟩

/-- The node after a list of messages, in the order they came, from `n`. -/
def Receives : List Message → Node → Result Node
  | [], n => ok n
  | m :: ms, n => do
    let n1 ← Receive m n
    Receives ms n1

/-- **The functions always return.**  Every function of the crate returns for every input: `status`,
`turn`, `Reading::new`, `next`, `payload`, `claim`, `end`, `take`, `room`, `item`, and `full_text_ok`, `full_ok`, `delta_ok`,
and `Seen::new`, `full`, `delta`, `added`, `says`, `behind`: no panic and no overflow, whatever the
numbers (a reading of any state, not only one reached by the calls).

Not said: what they return (the claims below). -/
def TheFunctionsAlwaysReturn : Prop :=
  (∀ b : Std.U8, status b ⦃ _ => True ⦄) ∧ (∀ b : Std.U8, turn b ⦃ _ => True ⦄) ∧
  (∀ asked mi mp, Reading.new asked mi mp ⦃ _ => True ⦄) ∧
  (∀ r : Reading, Reading.claim r ⦃ _ => True ⦄) ∧ (∀ r : Reading, Reading.end r ⦃ _ => True ⦄) ∧
  (∀ r len size, Reading.take r len size ⦃ _ => True ⦄) ∧
  (∀ payload len mp, room payload len mp ⦃ _ => True ⦄) ∧
  (∀ len max, item len max ⦃ _ => True ⦄) ∧
  (∀ r : Reading, Reading.impl.next r ⦃ _ => True ⦄) ∧
  (∀ r : Reading, Reading.impl.payload r ⦃ _ => True ⦄) ∧
  (∀ s : Seen, Seen.impl.version s ⦃ _ => True ⦄) ∧
  (∀ text max, full_text_ok text max ⦃ _ => True ⦄) ∧
  (∀ bytes hashes, full_ok bytes hashes ⦃ _ => True ⦄) ∧ (∀ bytes, delta_ok bytes ⦃ _ => True ⦄) ∧
  (Seen.new ⦃ _ => True ⦄) ∧
  (∀ s e v held, Seen.full s e v held ⦃ _ => True ⦄) ∧
  (∀ s e upto held, Seen.delta s e upto held ⦃ _ => True ⦄) ∧
  (∀ s base upto, Seen.added s base upto ⦃ _ => True ⦄) ∧
  (∀ s believed contains, Seen.says s believed contains ⦃ _ => True ⦄) ∧
  (∀ s, Seen.behind s ⦃ _ => True ⦄)

/-- **What the status bytes say** (rule 2).  `status` returns, and the byte 0 is `Absent`, 1 is `Here`,
2 is `NoRoom`, 3 is `Failed`, and every other byte (4 to 255) is `Bad`; each answer is given for that byte
only.  `turn` returns, and gives for the byte the turn of the same name (`Absent`, `NoRoom`, `Failed`,
`Here`), and `Bad` for every other byte.

Not said: what the node does with a `Bad` (it drops the peer) or a `Failed` (it asks another peer). -/
def WhatTheStatusBytesSay : Prop :=
  (∀ b : Std.U8, status b ⦃ s =>
    (s = Status.Absent ↔ b.val = 0) ∧ (s = Status.Here ↔ b.val = 1) ∧
    (s = Status.NoRoom ↔ b.val = 2) ∧ (s = Status.Failed ↔ b.val = 3) ∧
    (s = Status.Bad ↔ 4 ≤ b.val) ⦄) ∧
  (∀ b : Std.U8, turn b ⦃ t =>
    (t = Turn.Absent ↔ b.val = 0) ∧ (t = Turn.Here ↔ b.val = 1) ∧
    (t = Turn.NoRoom ↔ b.val = 2) ∧ (t = Turn.Failed ↔ b.val = 3) ∧
    (t = Turn.Bad ↔ 4 ≤ b.val) ⦄)

/-- **There is room exactly by `HasRoom`** (rule 3).  `room` returns, for any three numbers, and says
`true` exactly when the answer holds no bytes, or the bytes held and the chunk are at most the maximum
together, computed as plain numbers.  The same function is the rule of the server's own sending.

Not said: that `payload` is a number an answer can hold (the claim holds for all of them). -/
def WhatRoomSaysExactly : Prop :=
  ∀ payload len mp : Std.U64, room payload len mp ⦃ b => (b = true ↔ HasRoom payload len mp) ⦄

/-- **What `take` accepts, exactly** (rule 3).  `take` returns, and the chunk is taken exactly when
- its length is at most `max_item`, and
- it is of the size asked, when a size was asked, and
- there is room for it (`HasRoom`, the rule of `room`: one rule for the two).
When it is taken, the bytes held are the bytes held before and the length, as plain numbers (no
wrapping); when it is not, the reading is the one given, unchanged.  The other fields (`asked`, `next`,
the two maxima) never change.

Not said: the digest of the bytes (the shell checks it); that a length is allocated or read before this
is decided (it is the shell's order: `take` is called with the length alone). -/
def WhatTakeAcceptsExactly : Prop :=
  ∀ (r : Reading) (len : Std.U64) (size : Option Std.U64), Reading.take r len size ⦃ a =>
    (a.1 = true ↔ len.val ≤ r.max_item.val ∧ SizeMatches len size ∧
      HasRoom r.payload len r.max_payload) ∧
    (a.1 = true → a.2.payload.val = r.payload.val + len.val) ∧
    (a.1 = false → a.2 = r) ∧
    a.2.asked = r.asked ∧ a.2.next = r.next ∧ a.2.max_item = r.max_item ∧
    a.2.max_payload = r.max_payload ⦄

/-- **The bounds of an answer hold, after any calls** (rule 3).  A new reading holds no bytes and has
given no turn.  Every call keeps `Within`: `claim`, `end` and `take` of a reading that is within gives
one that is within, whatever the lengths and the order of the calls (so the bytes held are at most the
larger of the two maxima, always, and at most `max_payload` as soon as a second chunk is in:
only the first chunk of an answer may pass `max_payload`, and then it is at most `max_item`).
Also, when a chunk is taken after bytes were held, the bytes held are at most `max_payload`.

Not said: that the bytes held are at most `max_payload` always: the first chunk may be up to
`max_item` when that is larger (rule 3 says so; the worked examples show it). -/
def TheBoundsOfAnAnswerHold : Prop :=
  (∀ asked mi mp, Reading.new asked mi mp ⦃ r =>
    Within r ∧ r.payload.val = 0 ∧ r.next.val = 0 ∧ r.asked = asked ⦄) ∧
  (∀ r : Reading, Within r → Reading.claim r ⦃ a => Within a.2 ⦄) ∧
  (∀ r : Reading, Within r → Reading.end r ⦃ r' => Within r' ⦄) ∧
  (∀ (r : Reading) len size, Within r → Reading.take r len size ⦃ a => Within a.2 ⦄) ∧
  (∀ (r : Reading) len size, Reading.take r len size ⦃ a =>
    a.1 = true → r.payload.val ≠ 0 → a.2.payload.val ≤ r.max_payload.val ⦄)

/-- **The turns are those asked** (rule 2).  `claim` returns, and
- when fewer turns were given than digests asked (`next` below `asked`), it gives the turn `next`, the
  next one in the list, and `next` grows by one;
- otherwise it gives none, and nothing changes.
`new` starts at 0 and `end` makes `next` equal to `asked`; `claim`, `end` and `take` of a reading with
`next` at most `asked` keep it so.  So `next` never passes `asked`: a peer cannot make the node read
more answers than digests it asked, whatever it sends.

Not said: what the shell reads for a turn (the status byte). -/
def TheTurnsAreThoseAsked : Prop :=
  (∀ r : Reading, Reading.claim r ⦃ a =>
    (r.next.val < r.asked.val → a.1 = some r.next ∧ a.2.next.val = r.next.val + 1 ∧
      a.2.asked = r.asked ∧ a.2.payload = r.payload ∧ a.2.max_item = r.max_item ∧
      a.2.max_payload = r.max_payload) ∧
    (r.asked.val ≤ r.next.val → a.1 = none ∧ a.2 = r) ⦄) ∧
  (∀ r : Reading, r.next.val ≤ r.asked.val → Reading.claim r ⦃ a => a.2.next.val ≤ a.2.asked.val ⦄) ∧
  (∀ r : Reading, Reading.end r ⦃ r' =>
    r'.next = r.asked ∧ r'.asked = r.asked ∧ r'.payload = r.payload ⦄) ∧
  (∀ (r : Reading) len size, r.next.val ≤ r.asked.val →
    Reading.take r len size ⦃ a => a.2.next.val ≤ a.2.asked.val ⦄)

/-- **Every digest asked has one turn** (rule 2).  From a new reading for `asked` digests, `asked + 2`
calls of `claim` give the turns `0, 1, ..., asked - 1`, each once and in this order, and then none, and
again none: no turn for what was not asked, and none twice.  (`Turns` repeats the call, nothing else.)

Not said: that the peer answers each turn. -/
def EveryDigestAskedHasOneTurn : Prop :=
  ∀ asked mi mp, Reading.new asked mi mp ⦃ r =>
    Turns (asked.val + 2) r ⦃ l =>
      l.map (Option.map (·.val)) = (List.range asked.val).map some ++ [none, none] ⦄ ⦄

/-- **An answer that ended gives no turn** (rule 2).  `end` returns, and after it `claim` gives none,
whatever the reading was: the rest of an answer that failed is for another peer.

Not said: which digests were answered before it ended. -/
def AnAnswerThatEndedGivesNoTurn : Prop :=
  ∀ r : Reading, Reading.end r ⦃ r' => Reading.claim r' ⦃ a => a.1 = none ⦄ ⦄

/-- **A correct peer is always taken** (rule 4).  `take` accepts a chunk whose length is at most
`max_item`, that is of the size asked (or none was asked), and for which there is room (`HasRoom`): it
returns `true`, and adds exactly its length, whatever the reading was and whatever was taken before.
So a function that refuses everything fails this claim, and the room that a correct server decides by
(`room`, the same rule: `WhatRoomSaysExactly`) is the room the node takes by.

Not said: a whole answer by a peer that holds all the chunks (the claim is of each chunk; the turns
come by `EveryDigestAskedHasOneTurn`). -/
def ACorrectPeerIsAlwaysTaken : Prop :=
  ∀ (r : Reading) (len : Std.U64) (size : Option Std.U64),
    len.val ≤ r.max_item.val → SizeMatches len size → HasRoom r.payload len r.max_payload →
    Reading.take r len size ⦃ a => a.1 = true ∧ a.2.payload.val = r.payload.val + len.val ⦄

/-- **An item is taken exactly when it is not empty and within the bound** (rule 5).  `item len max`,
for the answer to a request for one thing (an index, a profile, signatures) that may be at most `max`
bytes, returns `true` exactly when `len` is not 0 and is at most `max`.  So an empty answer is refused and
every length from 1 up to the bound is taken.

Not said: what the item is, or what bound the asker gives. -/
def WhatAnItemIsTakenExactly : Prop :=
  ∀ len max : Std.U64, item len max ⦃ b => (b = true ↔ len.val ≠ 0 ∧ len.val ≤ max.val) ⦄

/-- **The sizes of a filter** (rule 6).  `full_ok bytes hashes` returns `true` exactly when `bytes` is
not zero, a whole number of 64-bit words (a multiple of 8), at most 4194304 (4 MiB, `MAX_FILTER_BYTES`),
and `hashes` is from 1 to 16 (`MAX_HASHES`).  `delta_ok bytes` returns `true` exactly when `bytes` is
not zero, a multiple of 8, and at most 8192 keys of 8 bytes (65536 bytes, `MAX_DELTA_KEYS`).  So zero
words are refused and every size inside the caps is taken.

Not said: what the bytes are (the Bloom filter is the shell's), or that a filter of the largest size is
sensible to hold (the node's own setting is below). -/
def TheSizesOfAFilter : Prop :=
  (∀ (bytes : Std.Usize) (hashes : Std.U8), full_ok bytes hashes ⦃ b =>
    (b = true ↔ bytes.val ≠ 0 ∧ bytes.val % 8 = 0 ∧ bytes.val ≤ 4194304 ∧
      1 ≤ hashes.val ∧ hashes.val ≤ 16) ⦄) ∧
  (∀ bytes : Std.Usize, delta_ok bytes ⦃ b =>
    (b = true ↔ bytes.val ≠ 0 ∧ bytes.val % 8 = 0 ∧ bytes.val / 8 ≤ 8192) ⦄)

/-- **The text of a filter of an allowed size is accepted** (rule 6, the check before the decoding).
`full_text_ok text max` returns `true` exactly when `text ≤ (max / 3) * 4 + 4`.  And it never
refuses the base64 text of bytes that a filter of at most `max` bytes has: for `bytes` at most `max`, the
text of `bytes` bytes, `(bytes + 2) / 3 * 4` characters, is accepted (the largest filter is 4194304 bytes,
so a text of 5592408 characters is the largest taken).

Not said: that a text this long decodes (the shell decodes it, and refuses it if it does not). -/
def AFilterTextOfAnyAllowedSizeIsAccepted : Prop :=
  (∀ text max : Std.Usize, full_text_ok text max ⦃ b =>
    (b = true ↔ text.val ≤ max.val / 3 * 4 + 4) ⦄) ∧
  (∀ (bytes max text : Std.Usize), bytes.val ≤ max.val → text.val = (bytes.val + 2) / 3 * 4 →
    full_text_ok text max ⦃ b => b = true ⦄)

/-- **What a whole filter does** (rule 7).  `Seen::full` returns, and
- the filter is `Stale`, not taken, exactly when it is of the run held, of an older version than the
  one held, and a filter is held (`held`: a message that came after a newer one); then the `Seen` is
  unchanged;
- otherwise it is `Take`n, and the run becomes its run, the version becomes its version, and the last
  heard becomes the larger of its version and of the last heard before (this one only when the run is the
  same: a new run starts from nothing heard).
Taking a whole filter never makes the `Seen` forget a newer version of the run that was heard of, so a
message that is behind stays behind.

Not said: that the bytes of the filter are kept (the shell does that on `Take`). -/
def WhatAWholeFilterDoes : Prop :=
  ∀ (s : Seen) (e v : Std.U64) (held : Bool), Seen.full s e v held ⦃ a =>
    (a.1 = OnFull.Stale ↔ e = s.epoch ∧ v.val < s.version.val ∧ held = true) ∧
    (a.1 = OnFull.Stale → a.2 = s) ∧
    (a.1 = OnFull.Take → a.2.epoch = e ∧ a.2.version = v ∧
      a.2.heard.val = max v.val (if e = s.epoch then s.heard.val else 0)) ⦄

/-- **What a delta does** (rule 8).  `Seen::delta` returns, and
- it is `Stale`, nothing to add, exactly when it is of the run held and goes no further than the version
  held (`to` at most `version`); then the `Seen` is unchanged;
- otherwise the run becomes its run; the version is the version held when the run is the same, and 0 when
  it is another (nothing of the new run is held); the last heard is the larger of `to` and the last heard
  before when the run is the same, and the larger of `to` and 1 when it is another (so it is past the
  version 0, whatever `to` is, even 0);
- the answer is `Add` when a filter is held, `Skip` when not, for a delta that is not stale.
It never changes the version held in the same run: that is `added`'s, once the keys are in.

Not said: what is done with the keys (the shell adds them to the Bloom filter on `Add`). -/
def WhatADeltaDoes : Prop :=
  ∀ (s : Seen) (e upto : Std.U64) (held : Bool), Seen.delta s e upto held ⦃ a =>
    (a.1 = OnDelta.Stale ↔ e = s.epoch ∧ upto.val ≤ s.version.val) ∧
    (a.1 = OnDelta.Stale → a.2 = s) ∧
    (a.1 = OnDelta.Add ↔ ¬ (e = s.epoch ∧ upto.val ≤ s.version.val) ∧ held = true) ∧
    (a.1 = OnDelta.Skip ↔ ¬ (e = s.epoch ∧ upto.val ≤ s.version.val) ∧ held = false) ∧
    (a.1 ≠ OnDelta.Stale → a.2.epoch = e ∧
      a.2.version.val = (if e = s.epoch then s.version.val else 0) ∧
      a.2.heard.val = (if e = s.epoch then max upto.val s.heard.val else max upto.val 1)) ⦄

/-- **What `added` does** (rule 8).  `Seen::added from to` is told the keys of the delta from `from` to
`to` were added, and returns, and the run and the last heard are as they were; the version becomes `to`
exactly when `from` is the version held and is not 0 (the delta applied to the filter held; version 0 is
no filter of the run, and the versions of a sender start at 1), and stays as it was otherwise.

Not said: that the keys were added (the shell does it before). -/
def WhatAddedDoes : Prop :=
  ∀ (s : Seen) (base upto : Std.U64), Seen.added s base upto ⦃ s' =>
    s'.epoch = s.epoch ∧ s'.heard = s.heard ∧
    (base = s.version ∧ base.val ≠ 0 → s'.version = upto) ∧
    (¬ (base = s.version ∧ base.val ≠ 0) → s'.version = s.version) ⦄

/-- **What the filter says, exactly** (rule 9).  `Seen::says believed contains` returns, and
- `No` exactly when the filter is believed, does not contain the key, and is not behind;
- `Maybe` exactly when it is believed and contains the key;
- `Unknown` exactly when it is not believed, or is believed, does not contain the key and is behind.
So a "no" is never said by a filter that is not believed (a node that holds none), nor by a filter that is
behind, and a believed current filter that lacks the key does say "no" (a function that never says "no"
fails).  `behind` returns `true` exactly when `Behind`.

Not said: whether the filter contains the key (the bits are the shell's), and that the key is the right
one for the layer. -/
def WhatSaysAnswersExactly : Prop :=
  (∀ (s : Seen) (believed contains : Bool), Seen.says s believed contains ⦃ a =>
    (a = Said.No ↔ believed = true ∧ contains = false ∧ ¬ Behind s) ∧
    (a = Said.Maybe ↔ believed = true ∧ contains = true) ∧
    (a = Said.Unknown ↔ believed = false ∨ (contains = false ∧ Behind s)) ⦄) ∧
  (∀ s : Seen, Seen.behind s ⦃ b => (b = true ↔ Behind s) ⦄)

/-- **A message that does not follow leaves the filter behind** (rules 8 and 9).  For every `Seen` and
every delta that is not stale (`delta` returns, and when it is not `Stale`, `added` is told its keys were
added), the filter is behind afterwards when
- the delta is of another run than the one held, WHATEVER versions it says it goes from and to (0
  included: the run held is not the peer's current one, and nothing of the new run is held), or
- the delta is of the run held and does not go from the version held, or goes from version 0 (a
  message is missing or came out of order; version 0 is no filter).
So a filter with a hole in it never says "no" (`WhatSaysAnswersExactly`).  A delta that goes no further
than the version held is stale, and changes nothing (`WhatADeltaDoes`).

Not said: the same run with `from` equal to the version held and not 0 (it follows, and the filter may
be current: `AWholeFilterThenItsDeltasKeepTheFilterCurrent`). -/
def ADeltaThatDoesNotFollowLeavesTheFilterBehind : Prop :=
  ∀ (s : Seen) (e base upto : Std.U64) (held : Bool), Seen.delta s e upto held ⦃ a =>
    a.1 ≠ OnDelta.Stale → Seen.added a.2 base upto ⦃ s' =>
      (e = s.epoch → (base ≠ s.version ∨ base.val = 0) → Behind s') ∧
      (e ≠ s.epoch → Behind s') ⦄ ⦄

/-- **A whole filter then its deltas in order keep the filter current** (rules 7 and 8).  After a whole
filter of the run `e` and the version `v` (when the run is another, or the filter is no older than the
version held and than anything heard of), it is taken and the `Seen` is current at `v`.  Then, for any `Seen` that is current at `v`,
the version `v` being at least 1 (the first version of a sender), the deltas of
the same run that go from `v` up through the versions `tos` (each past the one before), each added after
its keys are in, leave it current at the last of them (or at `v` when there are none).  So the peer's
filter is believed, and says "no", again after the messages that a correct sender sends in order.

Not said: a lost or a late message (then the filter is behind, until a whole one comes). -/
def AWholeFilterThenItsDeltasKeepTheFilterCurrent : Prop :=
  (∀ (s : Seen) (e v : Std.U64) (held : Bool),
    e ≠ s.epoch ∨ (s.version.val ≤ v.val ∧ s.heard.val ≤ v.val) →
    Seen.full s e v held ⦃ a => a.1 = OnFull.Take ∧ Current a.2 e v ∧ ¬ Behind a.2 ⦄) ∧
  (∀ (s : Seen) (e v : Std.U64) (tos : List Std.U64), Current s e v → v.val ≠ 0 → Increasing v tos →
    Follow e v tos s ⦃ s' => Current s' e (tos.getLastD v) ∧ ¬ Behind s' ⦄)

/-- **A filter that says "no" is the last whole filter and the deltas that followed it, with no gap**
(rules 7, 8 and 9, end to end).  Start with nothing heard.  After ANY list of messages with ANY numbers
(whole filters and deltas, of any runs, in any order, repeated, with any versions, 0 included): if the node
believes the filter (`believed`: it holds one) and `says` answers "no" to a key, then the last whole filter
taken and each delta that moved the version since are of one run and chained by version without a gap (the
`Node` chain, from the version of the whole filter up to the version held), and that run and that
version are those of the `Seen`.  So no "no" comes from a filter that lost a message, or that a delta of another run, with any
versions, was added to.

Not said: that the keys of a delta that did not move the version, added to the filter all the same, are not
in it (they are, they only make it say "maybe" more: it never hurts a "no"); that the filter contains
every key the sender told (the bits are the shell's: rules.rs); or that the chain is the whole story of the
sender (a whole filter of an old run that comes late is taken, and says "no" to what only the new run
holds, until the next whole filter: rule 9, since the runs cannot be ordered). -/
def AFilterThatSaysNoIsAWholeFilterAndTheDeltasThatFollowedIt : Prop :=
  ∀ (msgs : List Message) (believed contains : Bool),
    Seen.new ⦃ s0 => Receives msgs ⟨s0, false, none⟩ ⦃ n =>
      (believed = true → n.held = true) →
      Seen.says n.seen believed contains ⦃ a =>
        a = Said.No → n.chain = some (n.seen.epoch, n.seen.version) ⦄ ⦄ ⦄

/-- **The worked examples.**  Numbers of the tests of the crate, to see that the claims above say what a
reader expects:
- the status bytes 0, 1, 2, 3 are the four, 4 and 255 are `Bad`;
- with at most 4 per chunk and 6 per answer: a first chunk of 4 is taken, a chunk of 5 is not (above the
  largest item), a chunk of 4 asked as 3 is not, a chunk of 3 after 4 held is not (7 is more than 6), a
  chunk of 2 after 4 held is taken, and a first chunk of 6 is taken when the largest item is 6 and the
  answer may hold 4, after which no byte more is;
- a whole filter of 8 bytes and 1 hash, of 4194304 bytes and 16 hashes are taken; of 0 bytes, of 7, of
  4194312 bytes, of 8 bytes and 0 or 17 hashes are not; a delta of 8 bytes and of 65536 bytes is taken; of
  0, 7 and 65544 is not;
- a filter current at version 5 of the run 7 says "no" to a key it lacks; a delta of the run to version 7
  (version 6 missing) is added, the filter is behind, and it says "unknown", not "no"; the whole filter of
  version 7 makes it current again and it says "no"; an older whole filter of the same run that comes
  after a newer one is stale, and one of another run is taken; a delta of another run that goes from
  version 0 to version 0 is added, and the filter is behind all the same.

Not said: anything beyond these numbers. -/
def TheWorkedExamples : Prop :=
  (status 0#u8 ⦃ s => s = Status.Absent ⦄ ∧ status 1#u8 ⦃ s => s = Status.Here ⦄ ∧
   status 2#u8 ⦃ s => s = Status.NoRoom ⦄ ∧ status 3#u8 ⦃ s => s = Status.Failed ⦄ ∧
   status 4#u8 ⦃ s => s = Status.Bad ⦄ ∧ status 255#u8 ⦃ s => s = Status.Bad ⦄) ∧
  (Reading.take ⟨3#usize, 0#usize, 0#u64, 4#u64, 6#u64⟩ 4#u64 (some 4#u64) ⦃ a =>
      a.1 = true ∧ a.2.payload = 4#u64 ⦄ ∧
   Reading.take ⟨3#usize, 0#usize, 0#u64, 4#u64, 6#u64⟩ 5#u64 none ⦃ a => a.1 = false ⦄ ∧
   Reading.take ⟨3#usize, 0#usize, 0#u64, 4#u64, 6#u64⟩ 4#u64 (some 3#u64) ⦃ a => a.1 = false ⦄ ∧
   Reading.take ⟨3#usize, 1#usize, 4#u64, 4#u64, 6#u64⟩ 3#u64 none ⦃ a => a.1 = false ⦄ ∧
   Reading.take ⟨3#usize, 1#usize, 4#u64, 4#u64, 6#u64⟩ 2#u64 none ⦃ a =>
      a.1 = true ∧ a.2.payload = 6#u64 ⦄ ∧
   Reading.take ⟨3#usize, 0#usize, 0#u64, 6#u64, 4#u64⟩ 6#u64 none ⦃ a =>
      a.1 = true ∧ a.2.payload = 6#u64 ⦄ ∧
   Reading.take ⟨3#usize, 1#usize, 6#u64, 6#u64, 4#u64⟩ 1#u64 none ⦃ a => a.1 = false ⦄) ∧
  (full_ok 8#usize 1#u8 ⦃ b => b = true ⦄ ∧ full_ok 4194304#usize 16#u8 ⦃ b => b = true ⦄ ∧
   full_ok 0#usize 1#u8 ⦃ b => b = false ⦄ ∧ full_ok 7#usize 1#u8 ⦃ b => b = false ⦄ ∧
   full_ok 4194312#usize 1#u8 ⦃ b => b = false ⦄ ∧ full_ok 8#usize 0#u8 ⦃ b => b = false ⦄ ∧
   full_ok 8#usize 17#u8 ⦃ b => b = false ⦄ ∧ delta_ok 8#usize ⦃ b => b = true ⦄ ∧
   delta_ok 65536#usize ⦃ b => b = true ⦄ ∧ delta_ok 0#usize ⦃ b => b = false ⦄ ∧
   delta_ok 7#usize ⦃ b => b = false ⦄ ∧ delta_ok 65544#usize ⦃ b => b = false ⦄) ∧
  (Seen.says ⟨7#u64, 5#u64, 5#u64⟩ true false ⦃ a => a = Said.No ⦄ ∧
   Seen.delta ⟨7#u64, 5#u64, 5#u64⟩ 7#u64 7#u64 true ⦃ a =>
      a.1 = OnDelta.Add ∧ Seen.added a.2 6#u64 7#u64 ⦃ s' =>
        Behind s' ∧ Seen.says s' true false ⦃ x => x = Said.Unknown ⦄ ⦄ ⦄ ∧
   Seen.full ⟨7#u64, 5#u64, 7#u64⟩ 7#u64 7#u64 true ⦃ a =>
      a.1 = OnFull.Take ∧ Seen.says a.2 true false ⦃ x => x = Said.No ⦄ ⦄ ∧
   Seen.full ⟨7#u64, 5#u64, 5#u64⟩ 7#u64 3#u64 true ⦃ a => a.1 = OnFull.Stale ⦄ ∧
   Seen.full ⟨7#u64, 5#u64, 5#u64⟩ 9#u64 1#u64 true ⦃ a => a.1 = OnFull.Take ⦄ ∧
   Seen.delta ⟨7#u64, 5#u64, 5#u64⟩ 9#u64 0#u64 true ⦃ a =>
      a.1 = OnDelta.Add ∧ Seen.added a.2 0#u64 0#u64 ⦃ s' => Behind s' ⦄ ⦄)

end RecvCore
