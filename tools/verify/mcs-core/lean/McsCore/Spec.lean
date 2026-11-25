-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: what is proved of crates/mcs-core, the SELinux MCS levels of the containers:
-- `parse` says what a level is (`s0`, `s0:c1,c2`, `s0-s15:c0.c1023`) and which categories it has,
-- `strict` takes the levels that a user or the CRI may give, `contains` and `overlap` compare two
-- levels by their categories, `pair_label` and `read_pair` write and read the fresh pair of
-- categories of a container (`s0:cA,cB`), `pick` chooses a fresh pair from random numbers so that
-- it keeps away from the levels in use, and `context_colons` finds where the level of a context
-- `user:role:type:level` starts.  This file is what a reviewer reads, in words and in statements,
-- with no proof; Lean checks the rest (the proofs are in the other files of McsCore/, and
-- Theorems.lean ties each claim below to its proof).
--
-- Why it is needed: two containers whose levels reach each other can read each other's files, so
-- the fresh level of a container must keep away from the levels in use, and a level that comes from
-- a user must not carry a quote or a comma into the `context=` of a mount.  The tests of the crate
-- (src/walk.rs, src/rules.rs) check the rules on every small input; each claim below is the same
-- rule for EVERY byte string, EVERY list of random numbers and EVERY list of levels in use.  A
-- proof is worth what its statement says, so each claim has a comment of what it claims and of
-- what it does NOT.
--
-- Words.  A LEVEL is `sN`, or `sN-sM` (and more, for `parse`), and then, after a colon, one or more
-- GROUPS of categories separated by commas; a group is a category `cN` or a range `cA.cB` with A at
-- most B; every number N of a category is below 1024 (leading zeros are fine for `parse`).  `s0`
-- has no category.  A CATEGORY SET is what `parse` answers; `In cats c` says the category `cN` is
-- in it.  A level REACHES another (`Reach`) when one of them is no level, or both have categories
-- and the categories of one are all in the other; a level COVERS another (`Covers`) when both are
-- levels, the inner has a category, and all of them are in the outer.  The CANONICAL spelling of a
-- pair is `s0:cLOW,cHIGH` with LOW < HIGH < 1024 and the numbers in decimal without leading zero
-- (`PairText`).  An ATTEMPT is a pair of two random numbers of `rand` (an even place and the one
-- after it); `pick` tries the attempts in order, twice: the first pass wants a pair that reaches no
-- level in use, the second (only when no attempt passes the first) a pair that is not equal to, and
-- does not contain, a level in use that has categories.  `Text "s0"` is the bytes of the letters
-- between the quotes.
--
-- Total correctness: each claim says that the function RETURNS (no panic, no overflow, no byte read
-- outside the text) and what its answer is.  The one condition a claim names is the length of a
-- text in `strict`: a text so long that the place two bytes after its end does not fit in a
-- `usize` (a Rust slice is never so long).
--
-- Both directions: "`pick` never answers a pair that is in use" alone is satisfied by a `pick` that
-- answers nothing.  So the claims come in two kinds: what may NOT happen (TheFreshLevelIsSeparate,
-- NoneOnlyWhenNoAttemptPasses) and what MUST (APairThatReachesNoLevelWins,
-- WithNoLevelInUseALabelIsAnswered).  In the same way `parse` is proved to take every level and
-- refuse every other text at once (ParseIsExactlyTheLevels), and `read_pair` to give back what
-- `pair_label` wrote (ReadPairGivesBackThePair) and nothing else
-- (ReadPairTakesOnlyTheCanonicalSpelling).
--
-- Read before this file: the header of crates/mcs-core/src/lib.rs, and rules.rs.
--
-- Index.  What each claim is about:
--
--   Claimed (each for every text, every list of numbers and every list of levels in use):
--
--   The levels
--     ParseIsExactlyTheLevels       `parse` takes exactly the levels of the grammar, and answers
--                                   their categories
--     NoCategoryBeyond1023          no category of 1024 or more is ever in a set
--     RangesAreExact                `s0:cA.cB` has exactly the categories A to B
--     StrictMeansWhatItSays         `strict` takes a level with no leading zero and at most two
--                                   sensitivities
--
--   Two levels
--     ContainsMeansWhatItSays       `contains`: both levels, the inner has categories, all in the outer
--     OverlapMeansWhatItSays        `overlap`: one is no level, or the categories of one are in the other
--     OverlapIsSymmetric            `overlap a b` and `overlap b a` answer the same
--
--   The fresh pair
--     PairLabelIsTheCanonicalSpelling  `pair_label` writes `s0:cLOW,cHIGH` and refuses a pair not
--                                      LOW < HIGH < 1024
--     ReadPairGivesBackThePair         `read_pair` of what `pair_label` wrote gives the pair
--     ReadPairTakesOnlyTheCanonicalSpelling  what `read_pair` answers has that spelling
--     TheFreshLevelIsSeparate          the label `pick` answers is a canonical pair that is neither
--                                      equal to nor contains the categories of a level in use
--     APairThatReachesNoLevelWins      a pair that reaches no level in use is taken over any other
--     NoneOnlyWhenNoAttemptPasses      `pick` answers nothing only when no pair is separate
--     WithNoLevelInUseALabelIsAnswered with no level in use a label is answered
--
--   The context
--     ContextColonsAreTheFirstThree    the places answered are those of the first three colons; none
--                                      when there are not three
--
--   Examples
--     WorkedExamples                   the pair 1, 2 and the levels `s0:c1,c2`, `s0:c0.c1023`, `s0`
--
--   Trusted: Charon and Aeneas (../../pins) and Lean; the crate calls the standard library only for
--   the length of a slice, an index, an array, `Vec::deref`, `Option::is_some` and the equality of two
--   slices of bytes, which Aeneas models; no model is written by hand.
--
--   Not claimed:
--   - that the random numbers are uniform or that every pair is equally likely (the shell gives the
--     numbers; the tests of the crate check the spread);
--   - that the level of the database is the one of the container (the shell stores `pick`'s answer);
--   - that the policy of the host allows a level (the shell asks for that);
--   - the text of an error: the crate has none, the shell writes them;
--   - that `parse` takes the sensitivities of SELinux as the kernel does (it takes the form
--     `sN-sM-...` and does not look at the numbers); `strict` is the one that allows two;
--   - the speed of the functions.
--
-- Notation:
--   - `f x ⦃ r => P r ⦄` reads: the Rust function `f`, given `x`, returns (it does not panic) and
--     its answer `r` satisfies `P r`.
--   - `level : Slice Std.U8` is a Rust slice of bytes; `level.val` is the list inside it.  `l ++ m`
--     is `l` and then `m`; `[]` is the empty list; `x ∈ l` says `x` is in the list `l`.
--   - `some x` is an answer, `none` is "nothing".
--   - `∀ x, P` is "for every x, P"; `∃ x, P` is "there is an x such that P"; `∧` is "and", `∨` is
--     "or", `→` is "if ... then", `↔` is "exactly when", `¬` is "not".
--   - `(S : Nat → Prop)` is a set of numbers: `S c` says `c` is in it.
--   - `a.val` is the number inside a `u8`, `u16`, `u32` or `usize`; `1#u16` is the 16-bit number 1.
import Extracted.Funs
open Aeneas Aeneas.Std Result velarx_mcs_core
namespace McsCore

/-- The bytes of a text written in letters (they are ASCII). -/
def Text (word : String) : List Std.U8 :=
  word.toList.map (fun letter => ⟨BitVec.ofNat 8 letter.toNat⟩)

/-- The byte is a digit `0` to `9`. -/
def IsDigit (b : Std.U8) : Prop := 48 ≤ b.val ∧ b.val ≤ 57

instance (b : Std.U8) : Decidable (IsDigit b) := by unfold IsDigit; infer_instance

/-- The number the digits write, read from the left: `Value (Text "012")` is 12. -/
def Value (digits : List Std.U8) : Nat :=
  digits.foldl (fun n d => 10 * n + (d.val - 48)) 0

/-- The digit byte of a number below 10: `digitByte 7` is the byte of the letter `7`. -/
def digitByte (k : Nat) : Std.U8 := ⟨BitVec.ofNat 8 (48 + k)⟩

/-- The digits that write the number `n` in decimal, most significant first, with no leading zero:
`Decimal 1023` is the bytes of `1023`, `Decimal 0` the byte of `0`. -/
def Decimal (n : Nat) : List Std.U8 :=
  if n < 10 then [digitByte n] else Decimal (n / 10) ++ [digitByte (n % 10)]
termination_by n
decreasing_by omega

/-- The category `cN` is in the set (the bit test of the crate says so). -/
def In (cats : Cats) (c : Nat) : Prop :=
  ∃ u : Std.U16, u.val = c ∧ Cats.has cats u = ok true

/-- A category written `cN`: `c` and the digits of a number `N` below 1024 (leading zeros are fine). -/
def CatText (l : List Std.U8) (n : Nat) : Prop :=
  ∃ digits, l = Text "c" ++ digits ∧ digits ≠ [] ∧ (∀ d ∈ digits, IsDigit d) ∧
    Value digits = n ∧ n < 1024

/-- A group of categories: `cA`, or a range `cA.cB` with A at most B.  The second argument is the
set of the categories it names. -/
inductive Item : List Std.U8 → (Nat → Prop) → Prop
  | single {l : List Std.U8} {n : Nat} : CatText l n → Item l (fun c => c = n)
  | range {l₁ l₂ : List Std.U8} {a b : Nat} :
      CatText l₁ a → CatText l₂ b → a ≤ b → Item (l₁ ++ Text "." ++ l₂) (fun c => a ≤ c ∧ c ≤ b)

/-- One or more groups separated by commas, and the set of the categories of all of them. -/
inductive Items : List Std.U8 → (Nat → Prop) → Prop
  | last {l : List Std.U8} {S : Nat → Prop} : Item l S → Items l S
  | more {l r : List Std.U8} {S T : Nat → Prop} :
      Item l S → Items r T → Items (l ++ Text "," ++ r) (fun c => S c ∨ T c)

/-- A sensitivity `sN`: `s` and one or more digits. -/
def SensText (l : List Std.U8) : Prop :=
  ∃ digits, l = Text "s" ++ digits ∧ digits ≠ [] ∧ ∀ d ∈ digits, IsDigit d

/-- One sensitivity, or a range of them `sN-sM` (and more: `strict` is the one that allows two). -/
inductive Sens : List Std.U8 → Prop
  | first {l : List Std.U8} : SensText l → Sens l
  | more {l r : List Std.U8} : Sens l → SensText r → Sens (l ++ Text "-" ++ r)

/-- A level, and the set of its categories: sensitivities alone (no category), or sensitivities, a
colon, and groups of categories. -/
inductive Level : List Std.U8 → (Nat → Prop) → Prop
  | plain {l : List Std.U8} : Sens l → Level l (fun _ => False)
  | categories {l r : List Std.U8} {S : Nat → Prop} :
      Sens l → Items r S → Level (l ++ Text ":" ++ r) S

/-- The level `s0:cA,cB` that `pair_label` writes for the categories A and B. -/
def PairText (low high : Nat) : List Std.U8 :=
  Text "s0:c" ++ Decimal low ++ Text ",c" ++ Decimal high

/-- Two levels REACH each other (what `overlap` says): one of them is no level, or both have
categories and the categories of one are all in the other. -/
def Reach (a b : List Std.U8) : Prop :=
  (¬ (∃ S, Level a S) ∨ ¬ (∃ T, Level b T)) ∨
  ∃ S T, Level a S ∧ Level b T ∧ (∃ c, S c) ∧ (∃ c, T c) ∧
    ((∀ c, S c → T c) ∨ (∀ c, T c → S c))

/-- The level `outer` COVERS the level `inner` (what `contains` says): both are levels, the inner
one has a category, and each category of the inner one is in the outer one. -/
def Covers (outer inner : List Std.U8) : Prop :=
  ∃ S T, Level outer S ∧ Level inner T ∧ (∃ c, T c) ∧ ∀ c, T c → S c

/-- The places `i0 < i1 < i2` are those of the first three colons of `l`: each is a colon and no
other place before `i2` is. -/
def ColonsAt (l : List Std.U8) (i0 i1 i2 : Nat) : Prop :=
  i0 < i1 ∧ i1 < i2 ∧ i2 < l.length ∧ l[i0]! = 58#u8 ∧ l[i1]! = 58#u8 ∧ l[i2]! = 58#u8 ∧
    ∀ j, j < i2 → l[j]! = 58#u8 → j = i0 ∨ j = i1

/-- No `s` or `c` of the text is followed by `0` and another digit (a number with a leading zero:
`s00`, `c01`). -/
def NoLeadingZero (l : List Std.U8) : Prop :=
  ∀ i, i + 2 < l.length → (l[i]! = 115#u8 ∨ l[i]! = 99#u8) → l[i + 1]! = 48#u8 →
    ¬ IsDigit l[i + 2]!

/-! ## The claims -/

/-- **A level is exactly what the grammar says.**  `parse` returns for every byte string.  When the
bytes are a level of the grammar above, it answers the categories of that level (`In cats c`: the
category `cN` is in the set); when it answers a set of categories, the bytes are a level of the
grammar and these are its categories.  So `parse` refuses exactly what is not a level, and it takes
every level.

Not said: the text of an error (`parse` has none: it answers a set or nothing). -/
def ParseIsExactlyTheLevels : Prop :=
  ∀ level : Slice Std.U8, parse level ⦃ r =>
    (∀ S, Level level.val S → ∃ cats, r = some cats ∧ ∀ c, In cats c ↔ S c) ∧
    (∀ cats, r = some cats → ∃ S, Level level.val S ∧ ∀ c, In cats c ↔ S c) ⦄

/-- **No category of 1024 or more is ever in a set.**  Whatever the bytes, the set `parse` answers
has no category `cN` with N >= 1024 (so none that could carry a longer number into a mount option).

Not said: that a level is refused when it names one (`ParseIsExactlyTheLevels` says it: the grammar
allows only numbers below 1024). -/
def NoCategoryBeyond1023 : Prop :=
  ∀ level : Slice Std.U8, parse level ⦃ r => ∀ cats, r = some cats → ∀ c, In cats c → c < 1024 ⦄

/-- **A range is exactly its categories.**  For numbers A <= B < 1024, the level `s0:cA.cB` (A and B
written in decimal) is taken, and its categories are exactly the numbers from A to B.

Not said: what other spellings of a range give (the grammar above). -/
def RangesAreExact : Prop :=
  ∀ (a b : Nat) (level : Slice Std.U8), a ≤ b → b < 1024 →
    level.val = Text "s0:c" ++ Decimal a ++ Text ".c" ++ Decimal b →
    parse level ⦃ r => ∃ cats, r = some cats ∧ ∀ c, In cats c ↔ a ≤ c ∧ c ≤ b ⦄

/-- **`contains` says what it says.**  `contains outer inner` returns, and it is true exactly when
both are levels, the inner one has some category, and every category of the inner one is in the
outer one.  (`s0` is inside nothing and holds nothing; what is not a level is neither.)

Not said: anything of what a caller does with the answer. -/
def ContainsMeansWhatItSays : Prop :=
  ∀ outer inner : Slice Std.U8, contains outer inner ⦃ b => b = true ↔ Covers outer.val inner.val ⦄

/-- **`overlap` says what it says.**  `overlap a b` returns, and it is true exactly when one of them
is no level, or both are levels with categories and the categories of one are all in the other.

Not said: that this is the rule of SELinux (it is the rule of the allocator of the crate: a level
that is none counts as reaching, so that the allocator keeps away from it). -/
def OverlapMeansWhatItSays : Prop :=
  ∀ a b : Slice Std.U8, overlap a b ⦃ r => r = true ↔ Reach a.val b.val ⦄

/-- **`overlap` is symmetric.**  `overlap a b` and `overlap b a` both return, with the same answer. -/
def OverlapIsSymmetric : Prop :=
  ∀ a b : Slice Std.U8, overlap a b ⦃ r => overlap b a ⦃ r' => r = r' ⦄ ⦄

/-- **`pair_label` writes one spelling and refuses the rest.**  `pair_label low high` returns, it
answers nothing exactly when it is not true that low < high < 1024, and otherwise the bytes of its
label are `s0:cLOW,cHIGH` (the numbers in decimal, no leading zero).

Not said: how the label is stored (`Label` keeps its bytes and its length). -/
def PairLabelIsTheCanonicalSpelling : Prop :=
  ∀ low high : Std.U16, pair_label low high ⦃ r =>
    (r = none ↔ ¬ (low.val < high.val ∧ high.val < 1024)) ∧
    ∀ label, r = some label → Label.as_bytes label ⦃ b => b.val = PairText low.val high.val ⦄ ⦄

/-- **`read_pair` gives back what `pair_label` wrote.**  For every pair of categories with
low < high < 1024, `pair_label` answers a label, and `read_pair` of the bytes of that label answers
the same pair.

Not said: that `read_pair` takes only this spelling (the next claim). -/
def ReadPairGivesBackThePair : Prop :=
  ∀ low high : Std.U16, low.val < high.val → high.val < 1024 →
    pair_label low high ⦃ r => ∃ label, r = some label ∧
      Label.as_bytes label ⦃ b => read_pair b ⦃ p => p = some (low, high) ⦄ ⦄ ⦄

/-- **`read_pair` takes only the canonical spelling.**  `read_pair` returns for every byte string,
and when it answers `(low, high)`, the bytes ARE `s0:cLOW,cHIGH` with low < high < 1024: not
`s0:c2,c1`, not `s0:c01,c2`, not `s0:c1.c2`, not a third category.

Not said: anything of a level in another spelling than this one (it answers nothing). -/
def ReadPairTakesOnlyTheCanonicalSpelling : Prop :=
  ∀ level : Slice Std.U8, read_pair level ⦃ r => ∀ p, r = some p →
    level.val = PairText p.1.val p.2.val ∧ p.1.val < p.2.val ∧ p.2.val < 1024 ⦄

/-- The attempt number `k` of `rand` (a place, an even one, with a number after it) gives the label
`label`, whose bytes are `b`. -/
def Offers (rand : Slice Std.U32) (k : Nat) (label : Label) (b : Slice Std.U8) : Prop :=
  k + 1 < rand.length ∧ k % 2 = 0 ∧ (∃ k' : Std.Usize, k'.val = k ∧ attempt rand k' = ok (some label)) ∧
    Label.as_bytes label = ok b

/-- No level in use is reached by the level `b`. -/
def ReachesNone (b : Slice Std.U8) (used : Slice (alloc.vec.Vec Std.U8)) : Prop :=
  ∀ u ∈ used.val, ¬ Reach b.val u.val

/-- No level in use is covered by the level `b` (equal to it, or inside it, with categories). -/
def CoversNone (b : Slice Std.U8) (used : Slice (alloc.vec.Vec Std.U8)) : Prop :=
  ∀ u ∈ used.val, ¬ Covers b.val u.val

/-- **The fresh level is separate.**  When `pick` answers a label, the label is that of a pair
low < high < 1024 (its bytes are `s0:cLOW,cHIGH`, and `read_pair` gives the pair back), and each
level in use that is a level with some category has a category that is neither low nor high.  So
the pair is not equal to the categories of a level in use and does not contain them, in either pass
(a level in use that is not a level does not count: it has no categories).

Not said: that the pair reaches no level in use (the first pass does that when it can: the next
claim says when; a wide level in use, as `s0:c0.c1023`, makes it impossible). -/
def TheFreshLevelIsSeparate : Prop :=
  ∀ (rand : Slice Std.U32) (used : Slice (alloc.vec.Vec Std.U8)),
    pick rand used ⦃ r => ∀ label, r = some label →
      ∃ low high : Std.U16, low.val < high.val ∧ high.val < 1024 ∧
        Label.as_bytes label ⦃ b => b.val = PairText low.val high.val ∧
          read_pair b ⦃ p => p = some (low, high) ⦄ ∧
          ∀ u ∈ used.val, ∀ T, Level u.val T → (∃ c, T c) → ∃ c, T c ∧ c ≠ low.val ∧ c ≠ high.val ⦄ ⦄

/-- **A pair that reaches no level in use is taken over any other.**  When some attempt of `rand`
gives a pair that reaches none of the levels in use, `pick` answers a label, and that label reaches
none of them.

Not said: that it is the first such attempt (it is, but the claim does not need it). -/
def APairThatReachesNoLevelWins : Prop :=
  ∀ (rand : Slice Std.U32) (used : Slice (alloc.vec.Vec Std.U8)),
    (∃ k label b, Offers rand k label b ∧ ReachesNone b used) →
    pick rand used ⦃ r => ∃ label b, r = some label ∧ Label.as_bytes label = ok b ∧ ReachesNone b used ⦄

/-- **`pick` answers nothing only when no attempt is separate.**  When `pick` answers nothing, every
pair that an attempt gives is equal to, or contains, a level in use that has categories (so it
fails the second rule).  And it answers a label with a pair of an attempt that passes the second
rule when no pair passes the first (the claim above and `TheFreshLevelIsSeparate`).

Not said: that the label is the first one that passes (it is). -/
def NoneOnlyWhenNoAttemptPasses : Prop :=
  ∀ (rand : Slice Std.U32) (used : Slice (alloc.vec.Vec Std.U8)),
    pick rand used ⦃ r => r = none → ∀ k label b, Offers rand k label b → ¬ CoversNone b used ⦄

/-- **With no level in use, a label is answered.**  With no level in use and at least one attempt
(two numbers), `pick` answers a label: an allocator that refuses everything does not satisfy this.

Not said: how likely each pair is (the shell gives random numbers). -/
def WithNoLevelInUseALabelIsAnswered : Prop :=
  ∀ (rand : Slice Std.U32) (used : Slice (alloc.vec.Vec Std.U8)),
    used.length = 0 → 2 ≤ rand.length → pick rand used ⦃ r => ∃ label, r = some label ⦄

/-- **`context_colons` finds the first three colons.**  `context_colons` returns for every context.
When it answers three places, they are those of the first three colons (so the level, which has
colons of its own, is what follows the third).  When it answers nothing, the context does not have
three colons.

Not said: that the parts between the colons are valid (the shell checks them). -/
def ContextColonsAreTheFirstThree : Prop :=
  ∀ ctx : Slice Std.U8, context_colons ctx ⦃ r =>
    (∀ a, r = some a → ColonsAt ctx.val a.val[0]!.val a.val[1]!.val a.val[2]!.val) ∧
    (r = none → ¬ ∃ i0 i1 i2, i0 < i1 ∧ i1 < i2 ∧ i2 < ctx.length ∧
      ctx.val[i0]! = 58#u8 ∧ ctx.val[i1]! = 58#u8 ∧ ctx.val[i2]! = 58#u8) ⦄

/-- **`strict` is a level, with no leading zero, and at most two sensitivities.**  `strict` returns
for every level (of a length that a Rust slice has), and it is true exactly when the bytes are a
level of the grammar, no `s` or `c` is followed by `0` and another digit (`s00`, `c01` are refused:
`s0` and `c0` are fine), and there is at most one dash (`s0-s15`, not `s0-s1-s2`).  So what `strict`
takes, `parse` takes (a level in use is parsed with `parse`, which is more lenient).

Not said: that the level is allowed by the policy of the host (the shell's). -/
def StrictMeansWhatItSays : Prop :=
  ∀ level : Slice Std.U8, level.length + 2 ≤ Std.Usize.max → strict level ⦃ r =>
    r = true ↔ (∃ S, Level level.val S) ∧ NoLeadingZero level.val ∧ level.val.count 45#u8 ≤ 1 ⦄

/-- **Worked examples.**  The pair 1, 2 is written `s0:c1,c2` and read back as 1, 2; the level
`s0:c1,c2` has the categories 1 and 2 and no other; `s0:c0.c1023` has all of the 1024 categories;
`s0` has none.

Not said: anything of other levels (the claims above are for all). -/
def WorkedExamples : Prop :=
  pair_label 1#u16 2#u16 ⦃ r => ∃ label, r = some label ∧
    Label.as_bytes label ⦃ b => b.val = Text "s0:c1,c2" ∧ read_pair b ⦃ p => p = some (1#u16, 2#u16) ⦄ ⦄ ⦄ ∧
  (∀ level : Slice Std.U8, level.val = Text "s0:c1,c2" →
    parse level ⦃ r => ∃ cats, r = some cats ∧ ∀ c, In cats c ↔ c = 1 ∨ c = 2 ⦄) ∧
  (∀ level : Slice Std.U8, level.val = Text "s0:c0.c1023" →
    parse level ⦃ r => ∃ cats, r = some cats ∧ ∀ c, In cats c ↔ c ≤ 1023 ⦄) ∧
  (∀ level : Slice Std.U8, level.val = Text "s0" →
    parse level ⦃ r => ∃ cats, r = some cats ∧ ∀ c, ¬ In cats c ⦄)

end McsCore
