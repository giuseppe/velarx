-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: what is proved of crates/ref-core, the one grammar of an image reference
-- `[host/]path[:tag][@digest]` (`parse` cuts a string into its parts, `normalize` adds the defaults
-- of docker.io, `print` writes the full form, `host_error` and `prefix_error` check a host and a
-- prefix), in words and in statements, with no proof.  This file is what a reviewer reads; Lean
-- checks the rest (the proofs are in the other files of RefCore/, and Claims.lean ties each claim
-- below to its proof).
--
-- Why it is needed: a reference comes from a user or from an image nobody vouched for, and its
-- parts are put in URLs and compared as text.  The tests of the crate (src/rules.rs, src/walk.rs)
-- check the grammar on every short string over a small alphabet; each claim below is the same rule
-- for EVERY string.  A proof is worth what its statement says, so each claim has a comment of what
-- it claims and of what it does NOT.
--
-- The grammar is written first, over plain lists of numbers (`Bytes`: each byte as a number from 0
-- to 255), by what a host, a path, a tag and a digest ARE (`Domain`, `Component`, `Path`,
-- `IsTag`, `IsDigest`, `Reference.InGrammar`).  None of it is the Rust code written again, so a
-- claim that says the code accepts the grammar says something.  What the code accepts (the
-- grammar of src/lib.rs, rules 1 to 6 of its header) is: a host is a domain name (labels of
-- lower-case letters, digits and inner hyphens joined by dots) with an optional port, or an address
-- in brackets (hex digits and colons, an optional port); it is read as a host when the first
-- component of the name has a `.` or a `:` or is `localhost`.  A path is components of lower-case
-- letters and digits joined by one `.`, one or two `_`, or a run of `-`, and the components are
-- joined by `/`.  A tag is at most 128 bytes, the first a letter, a digit or `_`, the others also
-- `.` and `-`.  A digest is `sha256:`, `sha384:` or `sha512:` and 64, 96 or 128 lower-case hex
-- digits.  The string is at most 1024 bytes, the name after the defaults of docker.io at most 255,
-- and 64 hex digits alone are the id of an image, not a name.
--
-- Where this grammar differs from containers/image on purpose: a bracketed IPv6 host is accepted
-- (podman's copy has none); a host is lower case only; a reference is at most 1024 bytes.
--
-- Total correctness: each claim says that the function RETURNS (no panic, no overflow, no index
-- outside the string, every loop ends) and what its answer is.  The only assumption is for
-- `prefix_error` and `prefix_ok`: the string leaves room for 8 more bytes of length, which every
-- Rust slice does (its length is at most `isize::MAX`); `parse` needs no assumption, it refuses
-- what is over 1024 bytes first.
--
-- Both directions: "if it accepts, the answer is right" alone is satisfied by a parser that
-- refuses everything.  So `parse` is claimed to accept exactly the grammar (what it accepts is in
-- it, and everything in it is accepted, with one reading), and `host_error` and `prefix_error`
-- exactly a host and a prefix.
--
-- Read before this file: the header of crates/ref-core/src/lib.rs.
--
-- Index.  What each claim is about:
--
--   Claimed (each for every string):
--     ParseAlwaysReturns                 `parse` returns
--     TheOtherReadersAlwaysReturn        `looks_like_host`, `host_error`, `host_ok`,
--                                        `prefix_error`, `prefix_ok`, and `normalize` on what
--                                        `parse` accepts, return
--     AcceptedReferencesAreInTheGrammar  what `parse` accepts is a reference of the grammar, and
--                                        its spans cut the string into its parts
--     ParseAcceptsTheGrammar             `parse` accepts EVERY string of the grammar (with the
--                                        claim above: exactly the strings of the grammar)
--     AcceptedStringsHaveOneReading      the spans of an accepted string cut it into the parts
--                                        of the grammar that it is written from: no other split
--     AcceptedPartsAreSafe               no accepted host holds `/`, `@`, `?`, `#`, `%`, a capital,
--                                        white space, a control byte or a byte over 127;
--                                        no accepted path component is empty, `.` or `..` or
--                                        holds `/ ? # % @ :` or white space
--     AcceptedBytesAreOnlyThese          the same, by what may be there: a host is lower-case
--                                        letters, digits and `.-:[]`; a path is lower-case
--                                        letters, digits and `._-/`, with no `..`
--     ExamplesAreRead                    `alpine`, `quay.io/a/b:1` and `localhost:5000/x@sha256:..`
--                                        accepted and cut as they should be, `alpine` after the
--                                        defaults, `Alpine` and 64 zeros refused
--     LooksLikeHostIsExact               `looks_like_host` says `true` exactly for a first
--                                        component with a `.` or a `:` or `localhost`
--     HostErrorFindsExactlyHosts         `host_error`/`host_ok` find no fault exactly in a host
--     PrefixErrorFindsExactlyPrefixes    `prefix_error`/`prefix_ok` find no fault exactly in a
--                                        prefix
--     NormalizeAddsTheDefaults           `normalize` makes the name of `Reference.Normal`: the
--                                        host `docker.io` for none and for `index.docker.io`, and
--                                        `library/` before a path of one component of docker.io
--     NormalNameIsFixed                  adding the defaults of docker.io to a name that has
--                                        them changes nothing
--     NormalNameIsInTheGrammar           the name after the defaults of a reference of the
--                                        grammar is a reference of the grammar
--     PrintWritesTheNormalName           `print` of what `normalize` made, with the tag and the
--                                        digest, writes the name in full: its host, `/`, its
--                                        path, `:` and its tag, `@` and its digest
--     PrintedNormalNameIsAccepted        that string is accepted by `parse`, as the name after
--                                        the defaults, and `normalize` leaves it as it is
--
--   The rules of the header of src/lib.rs and the claims of each: 1 ParseAlwaysReturns; 2
--   AcceptedReferencesAreInTheGrammar, AcceptedPartsAreSafe; 3 AcceptedStringsHaveOneReading,
--   ParseAcceptsTheGrammar; 4 AcceptedReferencesAreInTheGrammar, ParseAcceptsTheGrammar; 5 the
--   spans cut the string as it is written (AcceptedReferencesAreInTheGrammar) and
--   NormalizeAddsTheDefaults; 6 PrintWritesTheNormalName, PrintedNormalNameIsAccepted,
--   NormalNameIsFixed, NormalNameIsInTheGrammar.
--
--   Trusted: Charon and Aeneas (../../pins) and Lean; nothing else (the crate calls no function of
--   the standard library that has to be modelled by hand).
--
--   Not claimed: the canonical spelling of an IPv6 address (the shell checks it with the standard
--   library; the core only checks hex digits and colons between brackets); that every shell of the
--   engine goes through this grammar; registries.conf and policy matching; DNS; what a registry
--   does with a name; the fallback to a stored name (names recorded by older versions); the case
--   of a host: upper case is refused, not folded (containers/image accepts it); that a port is
--   at most 65535 (a port is any number of digits, as `IsPort` says); `normalize` and `print` of
--   `Spans` or a `Name` the caller makes itself (the fields are public): the claims are about what
--   `parse` and `normalize` give; which error a refusal names, and its offset.
--
-- Notation:
--   - `f x ⦃ r => P r ⦄` reads: the Rust function `f`, given `x`, returns (it does not panic and
--     does not loop for ever) and its answer `r` satisfies `P r`.
--   - `s : Slice Std.U8` is a Rust slice of bytes; `s.val` is the list inside it; `s.length` its
--     length; `Bytes s.val` the bytes as numbers.
--   - `l ++ l'` is `l` and then `l'`; `x ∈ l` is "x is in l"; `l.take n`/`l.drop n` are the first n
--     elements and the others; `Piece text a b` is the bytes of `text` from the place `a` up to the
--     place `b`.
--   - `∀ x, P` is "for every x, P"; `∃ x, P` is "there is an x such that P"; `∧` is "and", `∨` is
--     "or", `→` is "if ... then", `↔` is "exactly when", `¬` is "not".
--   - `some x` and `none` are Rust's `Some(x)` and `None`.
import Extracted.Funs

open Aeneas Aeneas.Std Result velarx_ref_core

namespace RefCore

/-! ### Bytes -/

/-- The bytes of a slice or a vector as plain numbers from 0 to 255. -/
def Bytes (l : List Std.U8) : List Nat := l.map (·.val)

/-- The numbers of the bytes of a piece of text, for example `Ascii "sha256:"`. -/
def Ascii (text : String) : List Nat := text.toList.map Char.toNat

/-- The bytes of `text` from the place `start` up to, not including, the place `stop` (the places
count from 0; nothing is there when `stop` is not after `start`). -/
def Piece (text : List Nat) (start stop : Nat) : List Nat := (text.drop start).take (stop - start)

/-- A lower-case letter `a` to `z`. -/
def IsLower (b : Nat) : Prop := 97 ≤ b ∧ b ≤ 122
/-- An upper-case letter `A` to `Z`. -/
def IsUpper (b : Nat) : Prop := 65 ≤ b ∧ b ≤ 90
/-- A decimal digit `0` to `9`. -/
def IsDigit (b : Nat) : Prop := 48 ≤ b ∧ b ≤ 57
/-- A lower-case letter or a digit. -/
def IsAlnum (b : Nat) : Prop := IsLower b ∨ IsDigit b
/-- A lower-case hexadecimal digit: `0` to `9`, `a` to `f`. -/
def IsHex (b : Nat) : Prop := IsDigit b ∨ (97 ≤ b ∧ b ≤ 102)
/-- A letter of either case, a digit or `_`: the bytes a tag may begin with. -/
def IsWordByte (b : Nat) : Prop := IsAlnum b ∨ IsUpper b ∨ b = 95

/-- Not empty, and made of lower-case letters and digits only. -/
def Alnums (w : List Nat) : Prop := w ≠ [] ∧ ∀ b ∈ w, IsAlnum b

/-! ### The host -/

/-- A label of a host name: lower-case letters, digits and hyphens, beginning and ending with a
letter or a digit (the hyphens are inner). -/
def IsLabel (l : List Nat) : Prop :=
  (∀ b ∈ l, IsAlnum b ∨ b = 45) ∧ (∃ b, l.head? = some b ∧ IsAlnum b) ∧
    (∃ b, l.getLast? = some b ∧ IsAlnum b)

/-- A domain name: a label, or a domain name, a dot and a label. -/
inductive Domain : List Nat → Prop
  | label {l : List Nat} : IsLabel l → Domain l
  | join {d l : List Nat} : Domain d → IsLabel l → Domain (d ++ [46] ++ l)

/-- A port: one or more decimal digits. -/
def IsPort (p : List Nat) : Prop := p ≠ [] ∧ ∀ b ∈ p, IsDigit b

/-- An address in brackets, as the core checks it: `[`, one or more hexadecimal
digits and colons, `]`, and optionally `:` and a port.  (That the digits and colons
are a good address is for the shell.) -/
def IsBracketed (h : List Nat) : Prop :=
  ∃ inner rest, h = [91] ++ inner ++ [93] ++ rest ∧ inner ≠ [] ∧
    (∀ b ∈ inner, IsHex b ∨ b = 58) ∧ (rest = [] ∨ ∃ p, rest = 58 :: p ∧ IsPort p)

/-- A domain name with an optional port: `registry.example.org` or `localhost:5000`. -/
def IsDomainHost (h : List Nat) : Prop :=
  Domain h ∨ ∃ d p, Domain d ∧ IsPort p ∧ h = d ++ [58] ++ p

/-- A host: a domain name with an optional port, or an address in brackets. -/
def IsHost (h : List Nat) : Prop := IsBracketed h ∨ IsDomainHost h

/-- The part of a name before its first `/` is read as a host, and not as the first component of
a path, when it has a `.` or a `:` or is `localhost` (`looks_like_host`). -/
def LooksLikeHost (first : List Nat) : Prop :=
  46 ∈ first ∨ 58 ∈ first ∨ first = Ascii "localhost"

/-! ### The path -/

/-- A separator inside a component: one `.`, one or two `_`, or a run of `-`. -/
def IsSeparator (sep : List Nat) : Prop :=
  sep = [46] ∨ sep = [95] ∨ sep = [95, 95] ∨ (sep ≠ [] ∧ ∀ b ∈ sep, b = 45)

/-- A component of a path: lower-case letters and digits, or a component, a separator and lower-case
letters and digits. -/
inductive Component : List Nat → Prop
  | word {w : List Nat} : Alnums w → Component w
  | join {c sep w : List Nat} : Component c → IsSeparator sep → Alnums w →
      Component (c ++ sep ++ w)

/-- A path: a component, or a path, a `/` and a component. -/
inductive Path : List Nat → Prop
  | one {c : List Nat} : Component c → Path c
  | more {p c : List Nat} : Path p → Component c → Path (p ++ [47] ++ c)

/-- What a block of registries.conf or a rule of a signature policy can name: a host, or a host, a
`/` and a path (`host/a/b`). -/
def IsPrefix (p : List Nat) : Prop :=
  IsHost p ∨ ∃ h rest, IsHost h ∧ Path rest ∧ p = h ++ [47] ++ rest

/-- The components of a path written one after the other with a `/` between two. -/
def JoinedBySlashes : List (List Nat) → List Nat
  | [] => []
  | [c] => c
  | c :: d :: rest => c ++ [47] ++ JoinedBySlashes (d :: rest)

/-! ### The tag and the digest -/

/-- A tag: at most 128 bytes; the first a letter, a digit or `_`; the others also `.` and `-`. -/
def IsTag (t : List Nat) : Prop :=
  (∃ b, t.head? = some b ∧ IsWordByte b) ∧ t.length ≤ 128 ∧
    ∀ b ∈ t, IsWordByte b ∨ b = 46 ∨ b = 45

/-- A digest: `sha256:` and 64, `sha384:` and 96, or `sha512:` and 128 lower-case
hexadecimal digits. -/
def IsDigest (d : List Nat) : Prop :=
  ∃ algorithm count hex, d = Ascii algorithm ++ hex ∧ (∀ b ∈ hex, IsHex b) ∧ hex.length = count ∧
    ((algorithm = "sha256:" ∧ count = 64) ∨ (algorithm = "sha384:" ∧ count = 96) ∨
      (algorithm = "sha512:" ∧ count = 128))

/-! ### A reference -/

/-- The four parts of a reference `[host/]path[:tag][@digest]`. -/
structure Reference where
  host : Option (List Nat)
  path : List Nat
  tag : Option (List Nat)
  digest : Option (List Nat)

/-- The reference written as a string: `host/`, the path, `:tag` and `@digest`, each
present when the part is. -/
def Reference.Text (r : Reference) : List Nat :=
  (r.host.map (· ++ [47])).getD [] ++ r.path ++ (r.tag.map (58 :: ·)).getD [] ++
    (r.digest.map (64 :: ·)).getD []

/-- The host that a name with no host, and `index.docker.io`, is of. -/
def Hub : List Nat := Ascii "docker.io"

/-- The host is docker.io: none, `docker.io` or `index.docker.io`. -/
def Reference.OnTheHub (r : Reference) : Prop :=
  r.host = none ∨ r.host = some Hub ∨ r.host = some (Ascii "index.docker.io")

/-- The path is one component: it has no `/`. -/
def Reference.OneComponent (r : Reference) : Prop := 47 ∉ r.path

open Classical in
/-- The reference after the defaults of docker.io (`normalize`): the host is `docker.io` when it
was none or `index.docker.io`; and on docker.io a path of one component is under `library/`. -/
noncomputable def Reference.Normal (r : Reference) : Reference where
  host := if r.OnTheHub then some Hub else r.host
  path := (if r.OnTheHub ∧ r.OneComponent then Ascii "library/" else []) ++ r.path
  tag := r.tag
  digest := r.digest

/-- The bytes of the name of a reference after the defaults: its host, `/` and its path (the
`+ 1` is the `/`). -/
noncomputable def Reference.NameLength (r : Reference) : Nat :=
  (r.Normal.host.getD []).length + 1 + r.Normal.path.length

/-- A string of 64 lower-case hexadecimal digits is the id of an image, not a name. -/
def Reference.IsImageId (r : Reference) : Prop :=
  r.host = none ∧ r.tag = none ∧ r.digest = none ∧ r.path.length = 64 ∧ ∀ b ∈ r.path, IsHex b

/-- A reference of the grammar. -/
structure Reference.InGrammar (r : Reference) : Prop where
  /-- A host is a host, and is read as one (it looks like one). -/
  host : ∀ h, r.host = some h → IsHost h ∧ LooksLikeHost h
  /-- The path is a path. -/
  path : Path r.path
  /-- With no host, the first component of a path of several is not read as a host. -/
  first_component : r.host = none → 47 ∈ r.path → ¬ LooksLikeHost (r.path.takeWhile (· ≠ 47))
  tag : ∀ t, r.tag = some t → IsTag t
  digest : ∀ d, r.digest = some d → IsDigest d
  /-- The string is at most 1024 bytes. -/
  short : r.Text.length ≤ 1024
  /-- The name, after the defaults of docker.io, is at most 255 bytes. -/
  name_short : r.NameLength ≤ 255
  /-- It is not the id of an image. -/
  not_an_id : ¬ r.IsImageId

/-! ### What `parse` returns -/

/-- Where the path of the spans begins: after the host and its `/`, or at the start
when there is no host. -/
def PathStart (host_end : Nat) : Nat := if host_end = 0 then 0 else host_end + 1

/-- The reference that the spans of `s` cut out of it (the parts are the pieces of
`s` that the spans give). -/
def _root_.velarx_ref_core.Spans.Reading (s : Slice Std.U8) (spans : Spans) : Reference where
  host := if spans.host_end.val = 0 then none else some (Piece (Bytes s.val) 0 spans.host_end)
  path := Piece (Bytes s.val) (PathStart spans.host_end) spans.name_end
  tag := spans.tag.map fun t => Piece (Bytes s.val) t.1 t.2
  digest := spans.digest.map fun d => Piece (Bytes s.val) d.1 d.2

/-! ### What each byte of a host and of a path can be -/

/-- A byte that must never be in a host: a `/`, an `@`, a `?`, a `#`, a `%`, an upper-case letter,
white space or a control byte (32 or less, or 127), or a byte over 127. -/
def Dangerous (b : Nat) : Prop :=
  b = 47 ∨ b = 64 ∨ b = 63 ∨ b = 35 ∨ b = 37 ∨ IsUpper b ∨ b ≤ 32 ∨ 127 ≤ b

/-- A host with none of those bytes. -/
def HostIsSafe (h : List Nat) : Prop := ∀ b ∈ h, ¬ Dangerous b

/-- A path that is components joined by `/`, none of them empty, `.` or `..`, and none with a
byte that a URL or a file name would read as something else: `/`, `?`, `#`, `%`, `@`, `:`, white
space, a control byte or a byte over 127. -/
def PathIsSafe (p : List Nat) : Prop :=
  ∃ comps, comps ≠ [] ∧ p = JoinedBySlashes comps ∧ ∀ c ∈ comps, c ≠ [] ∧ c ≠ [46] ∧ c ≠ [46, 46] ∧
    ∀ b ∈ c, ¬ (b = 47 ∨ b = 63 ∨ b = 35 ∨ b = 37 ∨ b = 64 ∨ b = 58 ∨ b ≤ 32 ∨ 127 ≤ b)

/-! ### The claims -/

/-- **`parse` always returns.**  For every byte string, whatever its length, content or order of
parts: no panic, no overflow, no byte read outside the string, every loop ends.  (The claim after
this one says what it answers.)

Not said: what it answers. -/
def ParseAlwaysReturns : Prop :=
  ∀ s : Slice Std.U8, velarx_ref_core.parse s ⦃ _ => True ⦄

/-- **The other readers always return.**  `looks_like_host` and `host_error` and `host_ok` on every
byte string; `prefix_error` and `prefix_ok` on every byte string a Rust slice can be (its length
leaves room for 8 more, which every length up to `isize::MAX` does); and `normalize` on the
spans that `parse` accepts.

Not said: what they answer (the claims after this one). -/
def TheOtherReadersAlwaysReturn : Prop :=
  (∀ first : Slice Std.U8, velarx_ref_core.looks_like_host first ⦃ _ => True ⦄) ∧
  (∀ s : Slice Std.U8, velarx_ref_core.host_error s ⦃ _ => True ⦄) ∧
  (∀ s : Slice Std.U8, velarx_ref_core.host_ok s ⦃ _ => True ⦄) ∧
  (∀ s : Slice Std.U8, s.length + 8 ≤ Usize.max → velarx_ref_core.prefix_error s ⦃ _ => True ⦄) ∧
  (∀ s : Slice Std.U8, s.length + 8 ≤ Usize.max → velarx_ref_core.prefix_ok s ⦃ _ => True ⦄) ∧
  (∀ s : Slice Std.U8, velarx_ref_core.parse s ⦃ r => ∀ spans, r = core.result.Result.Ok spans →
    velarx_ref_core.normalize s spans ⦃ _ => True ⦄ ⦄)

/-- **What `parse` accepts is in the grammar, and the spans cut the string into its parts.**
`parse` returns, and when it accepts, with spans `spans`: the host, the path, the tag and the digest
that the spans cut out of the string (`Spans.Reading`) are a reference of the grammar
(`Reference.InGrammar`: the host, the path, the tag and the digest each as they are defined above,
the string at most 1024 bytes, the name after the defaults of docker.io at most 255 bytes, and not
the id of an image), and written one after the other (`Reference.Text`) they are exactly the string.

Not said: that every string of the grammar is accepted, or that an accepted string has only
this reading (the next two claims); that a part is a name that a registry has. -/
def AcceptedReferencesAreInTheGrammar : Prop :=
  ∀ s : Slice Std.U8, velarx_ref_core.parse s ⦃ r => ∀ spans, r = core.result.Result.Ok spans →
    (spans.Reading s).InGrammar ∧ (spans.Reading s).Text = Bytes s.val ⦄

/-- **`parse` accepts every reference of the grammar.**  For every byte string `s` and every
reference `r` of the grammar (`Reference.InGrammar`: the host, the path, the tag and the digest each
as they are defined above, the string at most 1024 bytes, the name after the defaults of docker.io
at most 255 bytes, and not the id of an image) that is written as `s` (`r.Text`): `parse s` returns,
and its answer is `Ok spans` for some `spans`.  With the claim above (what `parse` accepts is in the
grammar) this says that `parse` accepts exactly the strings of the grammar.

Not said: where the spans are (the next claim); what the other readers do with the string. -/
def ParseAcceptsTheGrammar : Prop :=
  ∀ (s : Slice Std.U8) (r : Reference), r.InGrammar → r.Text = Bytes s.val →
    velarx_ref_core.parse s ⦃ res => ∃ spans, res = core.result.Result.Ok spans ⦄

/-- **An accepted string has only one reading.**  For every byte string `s` and every reference `r`
of the grammar that is written as `s`: whatever spans `parse` accepts `s` with, they cut `s` into
exactly the parts of `r` (`spans.Reading s = r`).  So there is no other way to split the string
into a host, a path, a tag and a digest of the grammar: the first component is a host only when it
looks like one, the tag is after the first `:` of the last component, and the digest is after the
one `@` (the rule 3 of the header of src/lib.rs).

Not said: that `parse` accepts at all (the claim before this one). -/
def AcceptedStringsHaveOneReading : Prop :=
  ∀ (s : Slice Std.U8) (r : Reference), r.InGrammar → r.Text = Bytes s.val →
    velarx_ref_core.parse s ⦃ res => ∀ spans, res = core.result.Result.Ok spans →
      spans.Reading s = r ⦄

/-- **What an accepted host and path cannot hold.**  When `parse` accepts, the host (if there is
one) has no `/`, `@`, `?`, `#`, `%`, no upper-case letter, no white space, no control byte and no
byte over 127 (`HostIsSafe`), and the path is components joined by `/` of which none is empty, `.`
or `..` and none has a `/`, `?`, `#`, `%`, `@`, `:`, white space, a control byte or a byte over 127
(`PathIsSafe`).  This is what keeps a reference from reaching a URL as something else.

Not said: that a host is a good name for a machine, or that the path is a name that exists. -/
def AcceptedPartsAreSafe : Prop :=
  ∀ s : Slice Std.U8, velarx_ref_core.parse s ⦃ r => ∀ spans, r = core.result.Result.Ok spans →
    (∀ h, (spans.Reading s).host = some h → HostIsSafe h) ∧ PathIsSafe (spans.Reading s).path ⦄

/-- **What an accepted host and path are made of.**  When `parse` accepts, every byte of the host
(if there is one) is a lower-case letter, a digit, `-`, `.`, `:`, `[` or `]`; every byte of the
path is a lower-case letter, a digit, `.`, `_`, `-` or `/`; and the path has no two `.` next to
each other (so no component holds `..`).  This is the same safety as `AcceptedPartsAreSafe`, said
by what may be there instead of by what may not.

Not said: that every such byte can be anywhere (the grammar above says where). -/
def AcceptedBytesAreOnlyThese : Prop :=
  ∀ s : Slice Std.U8, velarx_ref_core.parse s ⦃ r => ∀ spans, r = core.result.Result.Ok spans →
    (∀ h, (spans.Reading s).host = some h →
      ∀ b ∈ h, IsAlnum b ∨ b = 45 ∨ b = 46 ∨ b = 58 ∨ b = 91 ∨ b = 93) ∧
    (∀ b ∈ (spans.Reading s).path, IsAlnum b ∨ b = 46 ∨ b = 95 ∨ b = 45 ∨ b = 47) ∧
    List.IsChain (fun a b => ¬ (a = 46 ∧ b = 46)) (spans.Reading s).path ⦄

/-- **Three references read, one name after the defaults, and two refusals, as the claims above
give them.**  A string of the bytes of
`alpine` is accepted; one of `quay.io/a/b:1` is accepted and cut into the host `quay.io`, the path
`a/b` and the tag `1`; one of `localhost:5000/x@sha256:` and 64 zeros is accepted and cut into the
host `localhost:5000`, the path `x` and that digest; `alpine` after the defaults of docker.io is
`docker.io/library/alpine`; and a string of the bytes of `Alpine` (a capital) is refused, and so
is one of 64 zeros (the id of an image).  Each is shown from the claims, not by running the code,
so that a reader sees what they say on references everyone knows.

Not said: anything about other strings. -/
def ExamplesAreRead : Prop :=
  (∀ s : Slice Std.U8, Bytes s.val = Ascii "alpine" →
    velarx_ref_core.parse s ⦃ res => ∃ spans, res = core.result.Result.Ok spans ⦄) ∧
  (∀ s : Slice Std.U8, Bytes s.val = Ascii "quay.io/a/b:1" →
    velarx_ref_core.parse s ⦃ res => ∃ spans, res = core.result.Result.Ok spans ∧
      spans.Reading s = ⟨some (Ascii "quay.io"), Ascii "a/b", some (Ascii "1"), none⟩ ⦄) ∧
  (∀ s : Slice Std.U8,
    Bytes s.val = Ascii "localhost:5000/x@" ++ Ascii "sha256:" ++ List.replicate 64 48 →
    velarx_ref_core.parse s ⦃ res => ∃ spans, res = core.result.Result.Ok spans ∧
      spans.Reading s = ⟨some (Ascii "localhost:5000"), Ascii "x", none,
        some (Ascii "sha256:" ++ List.replicate 64 48)⟩ ⦄) ∧
  (Reference.Normal ⟨none, Ascii "alpine", none, none⟩ =
    ⟨some Hub, Ascii "library/alpine", none, none⟩) ∧
  (∀ s : Slice Std.U8, Bytes s.val = Ascii "Alpine" →
    velarx_ref_core.parse s ⦃ res => ∀ spans, res ≠ core.result.Result.Ok spans ⦄) ∧
  (∀ s : Slice Std.U8, Bytes s.val = List.replicate 64 48 →
    velarx_ref_core.parse s ⦃ res => ∀ spans, res ≠ core.result.Result.Ok spans ⦄)

/-- **`looks_like_host` says exactly when the first component is read as a host.**  For every byte
string it says `true` exactly when the string has a `.`, a `:`, or is `localhost`.

Not said: anything of what follows the first component. -/
def LooksLikeHostIsExact : Prop :=
  ∀ first : Slice Std.U8, velarx_ref_core.looks_like_host first ⦃ r =>
    (r = true ↔ LooksLikeHost (Bytes first.val)) ⦄

/-- **`host_error` and `host_ok` find no fault exactly in a host.**  For every byte string,
`host_error` says there is no error, and `host_ok` says `true`, exactly when the string is a host of
the grammar (a domain name with an optional port, or an address in brackets), and so a string with
none of the dangerous bytes.

Not said: the canonical spelling of an IPv6 address, which the shell checks with
the standard library. -/
def HostErrorFindsExactlyHosts : Prop :=
  (∀ s : Slice Std.U8, velarx_ref_core.host_error s ⦃ r =>
    (r = core.result.Result.Ok () ↔ IsHost (Bytes s.val)) ⦄) ∧
  (∀ s : Slice Std.U8, velarx_ref_core.host_ok s ⦃ r => (r = true ↔ IsHost (Bytes s.val)) ⦄)

/-- **`prefix_error` and `prefix_ok` find no fault exactly in a prefix.**  For every byte string a
Rust slice can be, `prefix_error` says there is no error, and `prefix_ok` says `true`, exactly when
the string is a host, or a host, a `/` and a path of the grammar (`IsPrefix`: the shape of a block
of registries.conf or of a rule of a policy).

Not said: registries.conf and policy matching. -/
def PrefixErrorFindsExactlyPrefixes : Prop :=
  (∀ s : Slice Std.U8, s.length + 8 ≤ Usize.max → velarx_ref_core.prefix_error s ⦃ r =>
    (r = core.result.Result.Ok () ↔ IsPrefix (Bytes s.val)) ⦄) ∧
  (∀ s : Slice Std.U8, s.length + 8 ≤ Usize.max → velarx_ref_core.prefix_ok s ⦃ r =>
    (r = true ↔ IsPrefix (Bytes s.val)) ⦄)

/-- **`normalize` adds the defaults of docker.io, exactly as `Reference.Normal` says.**  When
`parse` accepts with spans `spans`, `normalize` returns a name whose host is `docker.io` when the
reference has no host, or `docker.io`, or `index.docker.io`, and the host of the reference
otherwise; and whose path is `library/` and the path when the host is one of those three and the
path is one component, and the path otherwise.

Not said: that two references with the same name are the same for every consumer. -/
def NormalizeAddsTheDefaults : Prop :=
  ∀ s : Slice Std.U8, velarx_ref_core.parse s ⦃ r => ∀ spans, r = core.result.Result.Ok spans →
    velarx_ref_core.normalize s spans ⦃ n =>
      Bytes n.host.val = ((spans.Reading s).Normal.host).getD [] ∧
      Bytes n.path.val = (spans.Reading s).Normal.path ⦄ ⦄

/-- **Adding the defaults of docker.io to a name that has them changes nothing.**  For every
reference `r`, the name after the defaults, `r.Normal`, has the host `docker.io` (or the host it
had, if that is not docker.io) and `library/` where it was needed, so a second time there is
nothing to add: `r.Normal.Normal = r.Normal`.  This is about the definition of the name after the
defaults; `NormalizeAddsTheDefaults` ties it to what `normalize` computes.

Not said: anything about strings. -/
def NormalNameIsFixed : Prop :=
  ∀ r : Reference, r.Normal.Normal = r.Normal

/-- **The name after the defaults of a reference of the grammar is a reference of the grammar.**
For every reference `r` of the grammar (`Reference.InGrammar`), `r.Normal` is one too: its host
(`docker.io` or the host it had) is a host, `library/` and the path is a path, the tag and the
digest are the same, the string is at most 1024 bytes, the name at most 255, and it is not the id
of an image (it has a host).

Not said: that a string is accepted (the next claim). -/
def NormalNameIsInTheGrammar : Prop :=
  ∀ r : Reference, r.InGrammar → r.Normal.InGrammar

/-- The slices that the shell gives to `print` hold the bytes of the tag and of the digest of a
reference: a slice when the reference has one, none when it has not. -/
def HoldTagAndDigest (tag digest : Option (Slice Std.U8)) (r : Reference) : Prop :=
  tag.map (fun t => Bytes t.val) = r.tag ∧ digest.map (fun d => Bytes d.val) = r.digest

/-- **`print` writes the name after the defaults in full.**  For every byte string that `parse`
accepts, with spans `spans`: `print` of the name that `normalize` made, with slices that hold the
tag and the digest of the reference the spans cut out (`HoldTagAndDigest`), returns, and what it
writes is the name after the defaults, `Reference.Normal`, written as a string (`Reference.Text`):
the host, a `/`, the path, a `:` and the tag if there is one, an `@` and the digest if there is
one.  For a string that is already in full form (its host is there, is not `index.docker.io`, and
the path is not a lone component of docker.io) this is the string itself.

Not said: that the written string is accepted (the next claim). -/
def PrintWritesTheNormalName : Prop :=
  ∀ s : Slice Std.U8, velarx_ref_core.parse s ⦃ res => ∀ spans, res = core.result.Result.Ok spans →
    velarx_ref_core.normalize s spans ⦃ n => ∀ tag digest : Option (Slice Std.U8),
      HoldTagAndDigest tag digest (spans.Reading s) →
        velarx_ref_core.print n tag digest ⦃ out =>
          Bytes out.val = (spans.Reading s).Normal.Text ⦄ ⦄ ⦄

/-- **`parse (print (normalize s))` is `Ok`: it reads as the normal name, and normalizing again
changes nothing.**  For every byte string that `parse` accepts, with spans `spans`: `parse`
accepts what `print` writes of the name that `normalize` made (with the tag and the digest),
with spans that cut it into exactly the parts of the name after the defaults
(`(spans.Reading s).Normal`, which has a host), and `normalize` of that gives the host and
the path that were printed.  So the full form can be stored, read again and compared as text.

Not said: that two different strings never have the same full form (they do: `alpine` and
`docker.io/library/alpine`, which is the point). -/
def PrintedNormalNameIsAccepted : Prop :=
  ∀ s : Slice Std.U8, velarx_ref_core.parse s ⦃ res => ∀ spans, res = core.result.Result.Ok spans →
    velarx_ref_core.normalize s spans ⦃ n => ∀ tag digest : Option (Slice Std.U8),
      HoldTagAndDigest tag digest (spans.Reading s) →
        velarx_ref_core.print n tag digest ⦃ out =>
          velarx_ref_core.parse out.deref ⦃ res' => ∃ spans',
            res' = core.result.Result.Ok spans' ∧
            spans'.Reading out.deref = (spans.Reading s).Normal ∧
            velarx_ref_core.normalize out.deref spans' ⦃ n' =>
              Bytes n'.host.val = Bytes n.host.val ∧ Bytes n'.path.val = Bytes n.path.val ⦄ ⦄ ⦄ ⦄ ⦄

end RefCore
