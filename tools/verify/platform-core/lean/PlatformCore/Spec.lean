-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: what is proved of crates/platform-core, which image of an index runs:
-- `choose` takes the entry of an index to run for the platform asked for (`--platform`, or the
-- host's), `rank` says how well one platform suits another, and `wanted_variant` lists the
-- variants that are acceptable, best first.  This file is what a reviewer reads, in words and in
-- statements, with no proof; Lean checks the rest (the proofs are in the other files of
-- PlatformCore/, and Theorems.lean ties each claim below to its proof).
--
-- Why it is needed: an index is an answer of a registry, so untrusted, and it lists images for
-- several platforms.  Running an image of another operating system or architecture, an
-- attestation that is no image, or a worse variant when a better one is listed, is a bug a user
-- does not see until the container fails, or does not fail.  The tests of the crate (src/walk.rs,
-- src/rules.rs) check the rules on every index of a small world (up to three entries); each claim
-- below is the same rule for EVERY list of entries, of any length, with any names.  A proof is
-- worth what its statement says, so each claim has a comment of what it claims and of what it
-- does NOT.
--
-- Words.  A PLATFORM is an operating system, an architecture and a variant (the bytes of three
-- names; no variant is the empty name).  An ENTRY of the index has a platform and a flag `image`,
-- which the shell sets (it is false for an attestation, an entry of platform `unknown/unknown`, an
-- entry with no operating system or architecture).  The platform asked for is not one platform but
-- a list of ACCEPTABLE ones, best first; they differ in the variant only.  `Acceptable` writes the
-- list down, as containers/image builds it:
--   - the VARIANTS KNOWN of an architecture, best first: `arm` has v8, v7, v6, v5; `arm64` has v8;
--     any other architecture has none;
--   - a request with no variant accepts: no variant first, then every known variant;
--   - a request for a variant that is known accepts it and the known ones below it, then no
--     variant (so `arm` with `v7` accepts v7, v6, v5, none: it never accepts v8, and `arm` with
--     `v6` never accepts v7);
--   - a request for a variant that is not known (of `amd64`, or `v9`) accepts that one, then none.
-- An entry MATCHES the k-th acceptable platform (`Accepts`, k from 0, the best) when it has the
-- operating system and the architecture asked for and the k-th acceptable variant.
--
-- Totality: each claim says that the function RETURNS (no panic, no overflow, no entry read
-- outside the index) and what its answer is.  Nothing is assumed of the input beyond the one
-- condition a claim names.
--
-- Both directions: "the entry chosen is acceptable" alone is satisfied by a `choose` that never
-- chooses, and "nothing better exists" by one that chooses the worst.  So the claims say that
-- what is chosen is acceptable (`TheChosenEntryIsAnAcceptableImage`), that it is the best and the
-- first of the best (`TheChosenEntryIsTheBestAndTheFirst`), and that something is chosen exactly
-- when some image entry is acceptable (`NothingIsChosenExactlyWhenNothingMatches`).
--
-- Read before this file: the header of crates/platform-core/src/lib.rs, and rules.rs.
--
-- Index.  What each claim is about:
--
--   Claimed (each for every entries and every platform asked for):
--
--   The functions return
--     TheFunctionsAlwaysReturn            `choose`, `rank` and `wanted_variant` return
--
--   The table of the acceptable platforms
--     WantedVariantIsTheTable             the k-th answer of `wanted_variant` is the k-th
--                                         acceptable variant of `Acceptable`, none past the last
--     RankIsThePlaceInTheTable            `rank` is the place of the entry in the table, none when
--                                         it matches none
--
--   What is chosen
--     TheChosenEntryIsAnAcceptableImage   an image entry, of the operating system and the
--                                         architecture asked for, with an acceptable variant
--     TheChosenEntryIsTheBestAndTheFirst  no image entry matches a platform before the one the
--                                         chosen entry matches; of those matching that one it is
--                                         the first of the index
--     NothingIsChosenExactlyWhenNothingMatches
--                                         nothing is chosen exactly when no image entry matches
--
--   Examples
--     WorkedExamples                      the table of `arm` and `arm64`; `arm` with `v7` against
--                                         v5, v6, v7 and v8 takes v7, with `v6` takes v6; `arm64`
--                                         with and without a variant; an attestation is skipped
--
--   Trusted: Charon and Aeneas (../../pins) and Lean; the crate calls the standard library only
--   for the length of a slice and whether it is empty, which Aeneas models.
--
--   Not claimed:
--   - the reading of the index (JSON), the normalising of names (`x86_64` is `amd64`) and the
--     setting of the flag `image`: the shell does them, and the core compares the bytes it is
--     given;
--   - that the host variant is detected right (the shell reads /proc/cpuinfo);
--   - that an entry is hashed or its digest verified;
--   - an entry with no platform at all (containers/image keeps it as a last resort; here it is no
--     image and is never chosen);
--   - the variants of `amd64` (`v2`, `v3`): only the variant asked for is acceptable;
--   - `wanted_variant` for a `k` within four of the largest `usize` (`HasRoom`): it adds to `k`
--     and may overflow; `rank`, its only caller, asks for `k` below 5;
--   - `os.version`, `os.features`, and the preference for a compression of the layers.
--
-- Notation:
--   - `f x ⦃ r => P r ⦄` reads: the Rust function `f`, given `x`, returns (it does not panic) and
--     its answer `r` satisfies `P r`.
--   - `entries : Slice Entry` is a Rust slice; `entries.val` is the list inside it.  `l[j]?` is
--     `some` of the element at the place `j` of `l`, or `none`; `x :: l` is `l` with `x` before;
--     `l ++ m` is `l` and then `m`; `l.drop n` is `l` without its first `n` elements.
--   - `Option` answers: `some k` is a place, `none` is "nothing".  `r.map f` applies `f` to what
--     is inside a `some`.
--   - `∀ x, P` is "for every x, P"; `∃ x, P` is "there is an x such that P"; `∧` is "and", `∨` is
--     "or", `→` is "if ... then", `↔` is "exactly when", `¬` is "not", `∈` is "is in".
import Extracted.Funs

open Aeneas Aeneas.Std Result velarx_platform_core

namespace PlatformCore

/-- The bytes of a name written in letters (they are ASCII). -/
def Text (word : String) : List Std.U8 :=
  word.toList.map (fun letter => ⟨BitVec.ofNat 8 letter.toNat⟩)

/-- The variants known of an architecture, best first: `arm` has v8, v7, v6, v5, `arm64` has v8,
any other architecture has none. -/
def Known (arch : List Std.U8) : List (List Std.U8) :=
  if arch = Text "arm" then [Text "v8", Text "v7", Text "v6", Text "v5"]
  else if arch = Text "arm64" then [Text "v8"]
  else []

/-- The acceptable variants for a request of `variant` on `arch`, best first (the table of the
header).  The empty list of bytes is "no variant". -/
def Acceptable (arch variant : List Std.U8) : List (List Std.U8) :=
  if variant = [] then [] :: Known arch
  else if variant ∈ Known arch then (Known arch).drop ((Known arch).idxOf variant) ++ [[]]
  else [variant, []]

/-- The platform `entry` matches the `k`-th acceptable platform of the request `want`: it has the
operating system and the architecture asked for, and the `k`-th acceptable variant. -/
def Accepts (want entry : Platform) (k : Nat) : Prop :=
  entry.os.val = want.os.val ∧ entry.arch.val = want.arch.val ∧
  (Acceptable want.arch.val want.variant.val)[k]? = some entry.variant.val

/-- The entry at the place `j` of the index is an image entry that matches the `k`-th acceptable
platform of `want`. -/
def ImageMatches (entries : Slice Entry) (want : Platform) (j k : Nat) : Prop :=
  ∃ entry, entries.val[j]? = some entry ∧ entry.image = true ∧ Accepts want entry.platform k

/-- What an acceptable variant of `wanted_variant` stands for in bytes: no variant, one of the
known ones, or `asked`, the variant the request names (when it is not a known one). -/
def WantedBytes (asked : List Std.U8) : Wanted → List Std.U8
  | Wanted.Absent => []
  | Wanted.V8 => Text "v8"
  | Wanted.V7 => Text "v7"
  | Wanted.V6 => Text "v6"
  | Wanted.V5 => Text "v5"
  | Wanted.Asked => asked

/-- `wanted_variant` adds a number of at most four to `k`: `k` is not within four of the largest
`usize`.  (`rank` asks for `k` below 5, so it never meets the case that is left out.) -/
def HasRoom (k : Std.Usize) : Prop :=
  k.val + 4 ≤ Std.Usize.max

/-- **`choose`, `rank` and `wanted_variant` always return.**  For every entries and every platform
asked for: no panic, whatever the bytes, the length of the index or the combination of flags
(`wanted_variant` for every `k` that has room to add the four places it may add).

Not said: what they return (the claims below). -/
def TheFunctionsAlwaysReturn : Prop :=
  (∀ (entries : Slice Entry) (want : Platform), choose entries want ⦃ _ => True ⦄) ∧
  (∀ entry want : Platform, rank entry want ⦃ _ => True ⦄) ∧
  (∀ (arch variant : Slice Std.U8) (k : Std.Usize), HasRoom k →
    wanted_variant arch variant k ⦃ _ => True ⦄)

/-- **`wanted_variant` is the table.**  Its `k`-th answer is the `k`-th acceptable variant of
`Acceptable` for the architecture and variant asked, and none past the last: for `arm` with no
variant, none, v8, v7, v6, v5; for `arm` with `v7`, v7, v6, v5, none.

Not said: that `rank` and `choose` use the table right (the claims below). -/
def WantedVariantIsTheTable : Prop :=
  ∀ (arch variant : Slice Std.U8) (k : Std.Usize), HasRoom k →
    wanted_variant arch variant k ⦃ r =>
      r.map (WantedBytes variant.val) = (Acceptable arch.val variant.val)[k.val]? ⦄

/-- **`rank` is the place in the table.**  `rank entry want` is `some k` exactly when the platform
`entry` matches the `k`-th acceptable platform of `want` (the first, and the only one: the
acceptable variants are all different), and none exactly when it matches none: another operating
system or architecture, or a variant that is not acceptable.

Not said: whether the entry is an image (`rank` does not look at the flag; `choose` does). -/
def RankIsThePlaceInTheTable : Prop :=
  ∀ entry want : Platform, rank entry want ⦃ r =>
    (∀ k : Std.Usize, r = some k ↔ Accepts want entry k.val) ∧
    (r = none ↔ ∀ k, ¬ Accepts want entry k) ⦄

/-- **The entry chosen is an acceptable image.**  `choose` returns, and if it names the entry at the
place `i`, that entry is an image, has the operating system and the architecture asked for, and
has one of the acceptable variants of the request.  So another operating system, another
architecture, an attestation (not an image) and an entry `unknown/unknown` are never chosen, even
when the request itself is `unknown/unknown`.

Not said: that it is the best (`TheChosenEntryIsTheBestAndTheFirst`), or that something is chosen
when it could be (`NothingIsChosenExactlyWhenNothingMatches`). -/
def TheChosenEntryIsAnAcceptableImage : Prop :=
  ∀ (entries : Slice Entry) (want : Platform), choose entries want ⦃ r =>
    ∀ i : Std.Usize, r = some i → ∃ entry, entries.val[i.val]? = some entry ∧
      entry.image = true ∧ entry.platform.os.val = want.os.val ∧
      entry.platform.arch.val = want.arch.val ∧
      entry.platform.variant.val ∈ Acceptable want.arch.val want.variant.val ⦄

/-- **The entry chosen is the best, and the first of the best.**  If `choose` names the entry at
the place `i`, which matches the `k`-th acceptable platform, then no image entry matches a platform
that comes before the `k`-th, and every image entry that matches the `k`-th one is the entry `i` or
comes after it in the index.

Not said: that what is chosen matches at all (`TheChosenEntryIsAnAcceptableImage`). -/
def TheChosenEntryIsTheBestAndTheFirst : Prop :=
  ∀ (entries : Slice Entry) (want : Platform), choose entries want ⦃ r =>
    ∀ (i : Std.Usize) (k : Nat), r = some i → ImageMatches entries want i.val k →
      ∀ j l : Nat, ImageMatches entries want j l → k ≤ l ∧ (l = k → i.val ≤ j) ⦄

/-- **Nothing is chosen exactly when nothing matches.**  `choose` names no entry exactly when no
image entry matches any acceptable platform: it does not give up while an acceptable image is
listed.

Not said: which entry is named otherwise (the two claims before). -/
def NothingIsChosenExactlyWhenNothingMatches : Prop :=
  ∀ (entries : Slice Entry) (want : Platform), choose entries want ⦃ r =>
    r = none ↔ ∀ j k : Nat, ¬ ImageMatches entries want j k ⦄

/-- The entry `entry` is an entry of `os`, `arch` and `variant` (as words), image or not. -/
def IsEntry (entry : Entry) (description : String × String × String × Bool) : Prop :=
  entry.platform.os.val = Text description.1 ∧
  entry.platform.arch.val = Text description.2.1 ∧
  entry.platform.variant.val = Text description.2.2.1 ∧ entry.image = description.2.2.2

/-- The entries of the index are, in order, the entries described. -/
def Describes (entries : Slice Entry) (descriptions : List (String × String × String × Bool)) :
    Prop :=
  List.Forall₂ IsEntry entries.val descriptions

/-- The platform asked for is `os`, `arch` and `variant` (as words). -/
def Asks (want : Platform) (os arch variant : String) : Prop :=
  want.os.val = Text os ∧ want.arch.val = Text arch ∧ want.variant.val = Text variant

/-- **The worked examples.**  Each is derived from the claims above, not by running the code.
The table: `arm` with no variant accepts none, v8, v7, v6, v5; with `v7` it accepts v7, v6, v5,
none (no v8); with `v6`, v6, v5, none; `arm64` with `v8` accepts v8 and none, with no variant
none and v8; `amd64` with `v3` accepts `v3` and none.  The choice, for `linux/arm` against an index
of the entries v5, v6, v7, v8: a request for `v7` takes v7 (the third entry), a request for `v6`
takes v6 (the second), a request with no variant takes v8 (the fourth: none is listed, and v8
is the best of the known variants); `linux/arm64`
with `v8` takes an entry with no variant, and one with no variant takes an entry with `v8`; an
attestation of the platform asked for is skipped for the image after it, and is never taken when
alone.

Not said: anything of other indexes (the claims above are for all). -/
def WorkedExamples : Prop :=
  -- the table
  Acceptable (Text "arm") [] = [[], Text "v8", Text "v7", Text "v6", Text "v5"] ∧
  Acceptable (Text "arm") (Text "v7") = [Text "v7", Text "v6", Text "v5", []] ∧
  Acceptable (Text "arm") (Text "v6") = [Text "v6", Text "v5", []] ∧
  Acceptable (Text "arm64") (Text "v8") = [Text "v8", []] ∧
  Acceptable (Text "arm64") [] = [[], Text "v8"] ∧
  Acceptable (Text "amd64") (Text "v3") = [Text "v3", []] ∧
  -- the choice
  (∀ (entries : Slice Entry) (want : Platform),
    Describes entries [("linux", "arm", "v5", true), ("linux", "arm", "v6", true),
      ("linux", "arm", "v7", true), ("linux", "arm", "v8", true)] →
    (Asks want "linux" "arm" "v7" → choose entries want ⦃ r => r = some 2#usize ⦄) ∧
    (Asks want "linux" "arm" "v6" → choose entries want ⦃ r => r = some 1#usize ⦄) ∧
    (Asks want "linux" "arm" "" → choose entries want ⦃ r => r = some 3#usize ⦄)) ∧
  (∀ (entries : Slice Entry) (want : Platform),
    Describes entries [("linux", "arm64", "", true)] →
    Asks want "linux" "arm64" "v8" → choose entries want ⦃ r => r = some 0#usize ⦄) ∧
  (∀ (entries : Slice Entry) (want : Platform),
    Describes entries [("linux", "arm64", "v8", true)] →
    Asks want "linux" "arm64" "" → choose entries want ⦃ r => r = some 0#usize ⦄) ∧
  (∀ (entries : Slice Entry) (want : Platform),
    Describes entries [("linux", "amd64", "", false), ("linux", "amd64", "", true)] →
    Asks want "linux" "amd64" "" → choose entries want ⦃ r => r = some 1#usize ⦄) ∧
  (∀ (entries : Slice Entry) (want : Platform),
    Describes entries [("unknown", "unknown", "", false)] →
    Asks want "unknown" "unknown" "" → choose entries want ⦃ r => r = none ⦄)

end PlatformCore
