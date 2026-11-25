-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: what is proved of crates/revoke-core, which revocation lists a p2p node
-- adopts, in words and in statements, with no proof.  `adopt` says which parts of a text become
-- the lists the node holds, and `newer` says whether a list would be newer than what is held.
-- This file is what a reviewer reads; Lean checks the rest (the proofs are in the other files of
-- RevokeCore/, and Theorems.lean ties each claim below to its proof).
--
-- Why it is needed: a revoked peer wants to stay admitted, and the lists reach a node in texts that
-- other peers relay, a relayer that may be hostile.  It can put forged, unsigned or junk parts in
-- a text, with the highest number it can write.  What the node adopts must not depend on them: a
-- list with a valid signature, once given to the core, must be adopted whatever else the text
-- holds.  The tests of the
-- crate (src/walk.rs, src/rules.rs) check the rules on every small input; each claim below is the
-- same rule for EVERY list of parts, of any length, with any numbers.  A proof is worth what its
-- statement says, so each claim has a comment of what it claims and of what it does NOT.
--
-- Words.  The shell reads a text in parts, one per list, and checks the signature of each.  A PART
-- has an issuer (a number the shell gives each authority of the node), a number (the version of
-- the list: a higher number is a newer list) and a flag `verified`, set by the shell when the
-- signature is one of an authority of the node.  What the node HOLDS is a list of `Held`: an
-- issuer and the number of the list it has of it.  `adopt` answers the PLACES of the parts to
-- adopt (the first part of the text is the place 0).  The vocabulary of the claims is written
-- first, by what things ARE, not by how the code computes them:
--   - `NumbersHeld`: the numbers the node holds of an issuer.  The shell holds one entry for each
--     issuer, but the claims do not need it: with several, what counts is the highest;
--   - a list is NEWER than what is held (`NewerThanHeld`) when its number is higher than every
--     number held of its issuer (higher than none: when nothing is held of the issuer);
--   - a part is ADOPTED (`Adopts`) when it is verified, newer than what is held, no verified part
--     of its issuer BEFORE it has a number as high as its own, and no verified part of its issuer
--     AFTER it has a higher number.  So of the verified parts of an issuer that are newer than
--     what is held, exactly one is adopted: the one with the highest number, and of equal numbers
--     the first (the TIE RULE: two lists of one number are one list, unless the authority signed
--     two, which it should not);
--   - what is held AFTER the adoption (`StateAfter`): the adopted lists replace what was held of
--     their issuers, what is held of the others stays.
--
-- Totality: each claim about a function says that it RETURNS (no panic, no overflow of a `usize`,
-- no part read outside the text, every loop ends) and what its answer is.  Nothing is assumed of
-- the input.
--
-- Both directions: "an unverified part is never adopted" alone is satisfied by a function that
-- adopts nothing.  So the claims say exactly which parts are adopted (the claim
-- `AdoptsExactlyTheUnbeatenNewerVerifiedParts`), that a verified part that is newer and the
-- highest is adopted whatever else the text holds, and what the worked examples adopt.
--
-- Read before this file: the header of crates/revoke-core/src/lib.rs, and rules.rs.
--
-- Index.  What each claim is about:
--
--   Claimed (each for every list of parts and every state held):
--
--   The functions return
--     NewerAndAdoptAlwaysReturn           `newer` and `adopt` return (no panic, no overflow)
--
--   Which parts are adopted
--     NewerMeansHigherThanEveryNumberHeld `newer` is true exactly when the number is higher than
--                                         every number held of the issuer
--     AdoptsExactlyTheUnbeatenNewerVerifiedParts
--                                         the places `adopt` answers are exactly those of the
--                                         parts that `Adopts` says, in order, each once
--     OnePartOfAnIssuerAtMost             no two parts of one issuer are adopted
--     AHigherVerifiedPartIsAlwaysAdopted  a verified part that is newer than what is held and
--                                         has a higher number than every other verified part of
--                                         its issuer IS adopted, whatever else the text holds
--
--   The security claim
--     UnverifiedPartsAreNeverAdopted      a part that is not verified is not adopted
--     UnverifiedPartsAreNotThere          what is adopted is the same as when only the verified
--                                         parts are given (where each is in the text does not
--                                         matter, only its order among the verified ones)
--
--   What is held afterwards
--     TheNumberHeldAfterIsTheGreatest     of each issuer, the number held after is the highest of
--                                         the numbers held before and the numbers of its
--                                         verified parts
--     TheNumberHeldNeverDecreases         so the highest number held of an issuer never goes down
--     TheOrderOfThePartsDoesNotMatter     the numbers held after do not depend on the order of
--                                         the parts
--     AdoptingAgainAdoptsNothing          from what is held after, the same parts adopt nothing
--
--   Examples
--     WorkedExamples                      the hostile text of the report, both orders; a tie;
--                                         an issuer of which nothing is held
--
--   Trusted: Charon and Aeneas (../../pins) and Lean; nothing else (the crate calls no function of
--   the standard library that has to be modelled by hand).
--
--   Not claimed:
--   - the verification of a signature, and that the shell sets `verified` only for a signature
--     that holds and builds the part from the bytes that were verified (a part that says the
--     number 7 over a signature of a list of the number 3 is the shell's to refuse);
--   - the bound of the signatures the shell checks in a text, and that it asks `newer` before it
--     checks one (it checks at most two parts per authority, so two junk parts that name an
--     authority before its genuine list keep that list from the core; a relayer could drop it
--     anyway);
--   - that the shell's update of its own state (one list per issuer) matches `StateAfter`, which
--     is a Lean definition here;
--   - the sets of revoked peers: the shell keeps them, a list holds its own;
--   - that a newer list may drop a peer that an older one revoked: the authority signs lists
--     that hold every peer revoked so far, and what an authority that is rolled back or
--     compromised can do is not a property of this crate;
--   - that an issuer is a known authority of the node: the crate does not know the authorities.
--     A verified part of an issuer of which nothing is held is adopted (it is the first list),
--     so a part of an issuer the node does not know is not adopted because the shell gives the
--     core only parts of its own authorities, and verifies a signature only against them.
--
-- Notation:
--   - `f x ⦃ r => P r ⦄` reads: the Rust function `f`, given `x`, returns (it does not panic and
--     does not loop for ever) and its answer `r` satisfies `P r`.  `f x = ok r` reads: it returns
--     `r`.
--   - `s : Slice Part` is a Rust slice; `s.val` is the list inside it.  `l[i]?` is `some` of the
--     element at the place `i` of `l`, or `none`; `l.take i` is its first `i` elements and
--     `l.drop i` is `l` without them; `l ++ l'` is `l` and then `l'`; `x :: l` is `l` with `x`
--     before; `l.max?` is the highest number of the list `l` (`none` for the empty list).
--   - `l.Perm l'` reads: `l'` has the elements of `l` in another order.
--   - `∀ x, P` is "for every x, P"; `∃ x, P` is "there is an x such that P"; `∧` is "and", `∨` is
--     "or", `→` is "if ... then", `↔` is "exactly when", `¬` is "not", `∈` is "is in".
import Extracted.Funs

open Aeneas Aeneas.Std Result velarx_revoke_core

namespace RevokeCore

open Classical

noncomputable section

/-! ### What is held, and what a text holds -/

/-- The numbers the node holds of `issuer`: those of the entries of `held` that name it. -/
def NumbersHeld (held : List Held) (issuer : Std.U64) : List Nat :=
  (held.filter fun h => h.issuer = issuer).map fun h => h.number.val

/-- The numbers of the verified parts of `issuer` in a text. -/
def NumbersVerified (parts : List Part) (issuer : Std.U64) : List Nat :=
  (parts.filter fun p => p.verified = true ∧ p.issuer = issuer).map fun p => p.number.val

/-- A list of `issuer` with the number `number` is NEWER than what is held: its number is higher
than every number held of that issuer (so it is, when nothing is held of the issuer). -/
def NewerThanHeld (held : List Held) (issuer number : Std.U64) : Prop :=
  ∀ n ∈ NumbersHeld held issuer, n < number.val

/-- The part `p`, with the parts `before` it and the parts `after` it in the text, is ADOPTED:
it is verified, it is newer than what is held, no verified part of its issuer before it has a
number as high as its own, and none after it has a higher one.  Of two parts of one issuer with
the same number, the first is the one adopted (the tie rule). -/
def Adopts (held : List Held) (before : List Part) (p : Part) (after : List Part) : Prop :=
  p.verified = true ∧ NewerThanHeld held p.issuer p.number ∧
  (∀ q ∈ before, q.verified = true → q.issuer = p.issuer → q.number.val < p.number.val) ∧
  (∀ q ∈ after, q.verified = true → q.issuer = p.issuer → q.number.val ≤ p.number.val)

/-- The part at the place `i` of the text `parts` is adopted (`Adopts`). -/
def AdoptedAt (held : List Held) (parts : List Part) (i : Nat) : Prop :=
  ∃ p, parts[i]? = some p ∧ Adopts held (parts.take i) p (parts.drop (i + 1))

/-- The places that `adopt` answers, as numbers. -/
def Places (adopted : alloc.vec.Vec Std.Usize) : List Nat :=
  adopted.val.map fun i => i.val

/-- The entry `Held` for a part: its issuer and its number. -/
def HeldOf (p : Part) : Held := { issuer := p.issuer, number := p.number }

/-- What is held AFTER the parts at the places `adopted` are adopted: they replace what was held
of their issuers (the shell puts the new list where the old one was), and what is held of the
other issuers stays. -/
def StateAfter (held : List Held) (parts : List Part) (adopted : List Nat) : List Held :=
  let new := (adopted.filterMap fun i => parts[i]?).map HeldOf
  (held.filter fun h => ∀ a ∈ new, a.issuer ≠ h.issuer) ++ new

/-! ### The claims -/

/-- **The functions return.**  `newer` and `adopt` return, for every state held and every text
(no panic, no overflow of a counter, no part read outside the text, every loop ends).

Not said: what they answer (the claims below). -/
def NewerAndAdoptAlwaysReturn : Prop :=
  (∀ (held : Slice Held) (issuer number : Std.U64), newer held issuer number ⦃ _ => True ⦄) ∧
  (∀ (held : Slice Held) (parts : Slice Part), adopt held parts ⦃ _ => True ⦄)

/-- **`newer` says whether a list is newer.**  It answers true exactly when the number is higher
than every number held of the issuer (`NewerThanHeld`), and so also when nothing is held of the
issuer.  A number equal to the one held is not newer.  So a function that answers true, or false,
always fails this claim.

Not said: what `adopt` does with it (the next claims). -/
def NewerMeansHigherThanEveryNumberHeld : Prop :=
  ∀ (held : Slice Held) (issuer number : Std.U64),
    newer held issuer number ⦃ r => r = true ↔ NewerThanHeld held.val issuer number ⦄

/-- **`adopt` answers exactly the parts that are adopted** (`Adopts`): a place is in the answer
exactly when the part at that place is verified, newer than what is held, not beaten by a verified
part of its issuer before it with a number as high or after it with a higher number; and the
places come in increasing order, each once.  So a function that adopts too much (a part that is
not verified, an old list) or too little (nothing; or not the highest, or not the first of equal
numbers) fails this claim.

Not said: that the shell gave a true `verified` (see the header), what is done with the answer. -/
def AdoptsExactlyTheUnbeatenNewerVerifiedParts : Prop :=
  ∀ (held : Slice Held) (parts : Slice Part),
    adopt held parts ⦃ adopted =>
      (∀ i, i ∈ Places adopted ↔ AdoptedAt held.val parts.val i) ∧
      (Places adopted).Pairwise (· < ·) ⦄

/-- **One part of an issuer at most.**  Two different places in the answer of `adopt` are of two
different issuers: an issuer is adopted at most once, so the shell does not replace a list by
another of the same text and the order of its replacements does not matter.

Not said: which part is adopted for an issuer (the claims above and below). -/
def OnePartOfAnIssuerAtMost : Prop :=
  ∀ (held : Slice Held) (parts : Slice Part) (adopted : alloc.vec.Vec Std.Usize),
    adopt held parts = ok adopted →
      ∀ i j p q, i ∈ Places adopted → j ∈ Places adopted →
        parts.val[i]? = some p → parts.val[j]? = some q → p.issuer = q.issuer → i = j

/-- **JUNK CANNOT HIDE A LIST** (the bug that was fixed).  If a verified part is newer than what is
held and every OTHER verified part of its issuer has a lower number, then its place is in the
answer of `adopt`, whatever else the text holds: parts that are not verified, with any number
(`u64::MAX` too), before it or after it, parts of other issuers, verified parts of its issuer
with a lower number.

Not said: what happens when another verified part of the issuer has the same or a higher number
(then that one is adopted, or the first of the equals: see the claims above). -/
def AHigherVerifiedPartIsAlwaysAdopted : Prop :=
  ∀ (held : Slice Held) (parts : Slice Part) (adopted : alloc.vec.Vec Std.Usize),
    adopt held parts = ok adopted →
      ∀ i p, parts.val[i]? = some p → p.verified = true →
        NewerThanHeld held.val p.issuer p.number →
        (∀ j q, j ≠ i → parts.val[j]? = some q → q.verified = true → q.issuer = p.issuer →
          q.number.val < p.number.val) →
        i ∈ Places adopted

/-- **THE SECURITY CLAIM, the part that is not verified.**  A part that is not verified is never
adopted, whatever its issuer and its number: no place of a part with `verified = false` is in the
answer of `adopt`.

Not said: that a part that IS adopted is genuine (that is `verified`, which the shell sets). -/
def UnverifiedPartsAreNeverAdopted : Prop :=
  ∀ (held : Slice Held) (parts : Slice Part) (adopted : alloc.vec.Vec Std.Usize),
    adopt held parts = ok adopted →
      ∀ i p, parts.val[i]? = some p → p.verified = false → i ∉ Places adopted

/-- **THE SECURITY CLAIM, the text without the junk.**  What `adopt` answers for a text is what it
answers when the parts that are not verified are not in it: `kept` is the text with only its
verified parts, in their order; a verified part is adopted from the text exactly when it is
adopted from `kept`, where its place is the number of verified parts before it.
So a forged or unsigned part, wherever it is and whatever number it claims, changes nothing: it
hides no part, and it makes none be adopted.

Not said: that the junk is cheap for the shell to check (the bound of the signatures per text). -/
def UnverifiedPartsAreNotThere : Prop :=
  ∀ (held : Slice Held) (parts kept : Slice Part) (adopted kept_adopted : alloc.vec.Vec Std.Usize),
    kept.val = parts.val.filter (fun p => p.verified = true) →
    adopt held parts = ok adopted → adopt held kept = ok kept_adopted →
      ∀ before p after, parts.val = before ++ p :: after → p.verified = true →
        (before.length ∈ Places adopted ↔
          (before.filter fun q => q.verified = true).length ∈ Places kept_adopted)

/-- **THE NUMBER HELD AFTER.**  After the adoption (`StateAfter`), the number held of each issuer
is the highest of the numbers held of it before and the numbers of its verified parts; of an
issuer with none of these, nothing is held.  So a verified list is adopted when it is newer than
every list held and every other verified list of its issuer, and the older ones, and the ones
that are not verified, play no part.

Not said: which place is adopted (the claims above), what the lists revoke. -/
def TheNumberHeldAfterIsTheGreatest : Prop :=
  ∀ (held : Slice Held) (parts : Slice Part) (adopted : alloc.vec.Vec Std.Usize),
    adopt held parts = ok adopted → ∀ issuer,
      (NumbersHeld (StateAfter held.val parts.val (Places adopted)) issuer).max? =
        (NumbersHeld held.val issuer ++ NumbersVerified parts.val issuer).max?

/-- **The number held never decreases.**  If a number is held of an issuer, the highest number
held of it after the adoption exists and is at least as high as before.  (It is the previous
claim, read for the issuers that have a list held.)

Not said: that the number held grows (a text with no newer list leaves it as it is). -/
def TheNumberHeldNeverDecreases : Prop :=
  ∀ (held : Slice Held) (parts : Slice Part) (adopted : alloc.vec.Vec Std.Usize),
    adopt held parts = ok adopted → ∀ issuer b,
      (NumbersHeld held.val issuer).max? = some b →
        ∃ a, (NumbersHeld (StateAfter held.val parts.val (Places adopted)) issuer).max? = some a ∧
          b ≤ a

/-- **The order of the parts does not matter** (for the numbers).  Two texts with the same parts
in another order give the same highest number held of every issuer.  (Of two lists of the same
number, which is adopted can change: that is the tie rule, and the number is the same.)

Not said: that the same places are adopted (they are the places of other parts). -/
def TheOrderOfThePartsDoesNotMatter : Prop :=
  ∀ (held : Slice Held) (parts parts' : Slice Part) (adopted adopted' : alloc.vec.Vec Std.Usize),
    parts.val.Perm parts'.val →
    adopt held parts = ok adopted → adopt held parts' = ok adopted' → ∀ issuer,
      (NumbersHeld (StateAfter held.val parts.val (Places adopted)) issuer).max? =
        (NumbersHeld (StateAfter held.val parts'.val (Places adopted')) issuer).max?

/-- **Adopting again changes nothing.**  If the node holds what is held after the adoption of a
text, the same text adopts nothing (`adopt` returns, and the answer is empty).

Not said: that the shell does not hold the lists twice (it does not). -/
def AdoptingAgainAdoptsNothing : Prop :=
  ∀ (held : Slice Held) (parts : Slice Part) (adopted : alloc.vec.Vec Std.Usize)
    (held' : Slice Held),
    adopt held parts = ok adopted →
    held'.val = StateAfter held.val parts.val (Places adopted) →
      ∃ again, adopt held' parts = ok again ∧ again.val = []

/-! ### Examples -/

/-- The part of `issuer` and `number`, verified or not, for the examples. -/
def PartOf (issuer number : Std.U64) (verified : Bool) : Part :=
  { issuer := issuer, number := number, verified := verified }

/-- The entry held of `issuer` and `number`, for the examples. -/
def HeldWith (issuer number : Std.U64) : Held := { issuer := issuer, number := number }

/-- Some parts as a slice, for the examples. -/
def PartsOf (parts : List Part) (few : parts.length ≤ 255 := by decide) : Slice Part :=
  Slice.from parts (by scalar_tac)

/-- Some entries held as a slice, for the examples. -/
def HeldOfList (held : List Held) (few : held.length ≤ 255 := by decide) : Slice Held :=
  Slice.from held (by scalar_tac)

/-- **A few examples**, worked out from the claims above (not by running the code).  The node
holds the list number 1 of the issuer 0.
1. The hostile text of the report: a part that claims the number `u64::MAX` and is not verified,
   then the genuine list number 2.  The genuine one, at the place 1, is adopted, and the junk, at
   the place 0, is not.
2. The same text in the other order: the genuine list is at the place 0 and is adopted, the junk
   at the place 1 is not.
3. Two verified lists of the number 2 of the issuer 0: the first is adopted, the second is not
   (the tie rule).
4. A verified list of the number 1, the number held, and one of the number 0: neither is adopted
   (equal and older are not newer).
5. Of the issuer 5, of which nothing is held, a verified part of the number 0 is adopted (it is
   the first list), and an unverified part of the number 0 is not. -/
def WorkedExamples : Prop :=
  (adopt (HeldOfList [HeldWith 0#u64 1#u64])
      (PartsOf [PartOf 0#u64 18446744073709551615#u64 false, PartOf 0#u64 2#u64 true]) ⦃ r =>
    0 ∉ Places r ∧ 1 ∈ Places r ⦄) ∧
  (adopt (HeldOfList [HeldWith 0#u64 1#u64])
      (PartsOf [PartOf 0#u64 2#u64 true, PartOf 0#u64 18446744073709551615#u64 false]) ⦃ r =>
    0 ∈ Places r ∧ 1 ∉ Places r ⦄) ∧
  (adopt (HeldOfList [HeldWith 0#u64 1#u64])
      (PartsOf [PartOf 0#u64 2#u64 true, PartOf 0#u64 2#u64 true]) ⦃ r =>
    0 ∈ Places r ∧ 1 ∉ Places r ⦄) ∧
  (adopt (HeldOfList [HeldWith 0#u64 1#u64])
      (PartsOf [PartOf 0#u64 1#u64 true, PartOf 0#u64 0#u64 true]) ⦃ r =>
    0 ∉ Places r ∧ 1 ∉ Places r ⦄) ∧
  (adopt (HeldOfList [HeldWith 0#u64 1#u64])
      (PartsOf [PartOf 5#u64 0#u64 true, PartOf 5#u64 0#u64 false]) ⦃ r =>
    0 ∈ Places r ∧ 1 ∉ Places r ⦄)

end

end RevokeCore
