-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: what is proved of crates/overlay-core, the judgement of what an entry of an
-- image may bring to the overlay file system mounted over it: `class` says what an extended
-- attribute NAME is (an attribute of a layer, one of the overlay, the SELinux label, or no name at
-- all), `rdev` makes the number of a DEVICE from its major and its minor, `major_minor` takes it
-- apart, and `whiteout` says whether a device is the whiteout of the overlay.  This file is what a
-- reviewer reads, in words and in statements, with no proof; Lean checks the rest (the proofs are in
-- the other files of OverlayCore/, and Theorems.lean ties each claim below to its proof).
--
-- Why it is needed: the entries of a layer come from a registry, a peer or a table that nobody
-- vouched for, and the overlay OBEYS what it finds in the layers below it: the attribute
-- `trusted.overlay.redirect` makes a lookup follow a path of the object store, `metacopy` makes a
-- file with no data take its data from another, `opaque` hides what is below, and a character
-- device 0:0 hides a file of a lower layer.  An image that could bring such an attribute would
-- steer the overlay of the machine that runs it.  The tests of the crate (src/walk.rs,
-- src/rules.rs) check the rules on every name of a small world and on the edges of the numbers; each
-- claim below is the same rule for EVERY name, of any length and any bytes, and for EVERY pair of
-- 32-bit numbers.  A proof is worth what its statement says, so each claim has a comment of what it
-- claims and of what it does NOT.
--
-- Words.  A NAME is a list of bytes.  A NAMESPACE is one of `trusted.`, `user.`, `security.`,
-- `system.` (with the dot).  A name is the OVERLAY'S when it is a namespace, then `overlay.`, then
-- anything (`trusted.overlay.redirect`, `user.overlay.x`, also `trusted.overlay.` alone and the
-- nested `trusted.overlay.overlay.x`).  The attribute `trusted.overlay` with no dot after it is not
-- the overlay's, as the kernel reads only the names with the dot.  `Text "user."` is the bytes of
-- the letters between the quotes.  A DEVICE has a MAJOR and a MINOR number; an image keeps them in
-- one 32-bit number, the `rdev`, as the kernel's `new_encode_dev` makes it: the low 8 bits of the
-- minor, then the 12 bits of the major, then the other 12 bits of the minor (so a major must be
-- below 4096 and a minor below 2^20 = 1048576).
--
-- Total correctness: each claim says that the function RETURNS (no panic, no overflow, no byte read
-- outside the name) and what its answer is.  Nothing is assumed of a name or of a number beyond the
-- one condition a claim names.
--
-- Both directions: "an overlay name never gets through" alone is satisfied by a `class` that refuses
-- everything.  So the claims come in two kinds: what may NOT pass (NoOverlayNameGetsThrough) and
-- what MUST (TheNamesOfLayersAreKept, TheNamesOfRealLayersAreKept), and then the exact answer for
-- the rest (WhatIsRefusedExactly, WhatIsOverlayAndWhatIsLabelExactly).  In the same way
-- "`rdev` returns a number that decodes back" alone is satisfied by a function that answers nothing,
-- so DevicesFitExactly says when it answers.
--
-- Read before this file: the header of crates/overlay-core/src/lib.rs, and rules.rs.
--
-- Index.  What each claim is about:
--
--   Claimed (each for every name and every pair of numbers):
--
--   The functions return
--     TheFunctionsAlwaysReturn            `class`, `rdev`, `major_minor` and `whiteout` return
--
--   The names
--     NoOverlayNameGetsThrough            a name that `class` calls plain does not begin with
--                                         `trusted.overlay.`, `user.overlay.`, `security.overlay.`
--                                         or `system.overlay.`, and is not `security.selinux`
--     TheNamesOfLayersAreKept             a namespace and a rest that is not empty, has no NUL and
--                                         does not begin with `overlay.` is plain (the label apart)
--     TheNamesOfRealLayersAreKept         `security.capability`, `security.ima`,
--                                         `system.posix_acl_access`, `system.posix_acl_default`,
--                                         `user.overlay` and `user.xdg.origin.url` are plain
--     WhatIsRefusedExactly                a name is refused exactly when it is empty, has a NUL, or is a
--                                         namespace alone, and the refusal says which
--     WhatIsOverlayAndWhatIsLabelExactly  a name is the overlay's exactly when it begins with a
--                                         namespace and `overlay.` and has no NUL; it is the label
--                                         exactly when it is `security.selinux`
--
--   The devices
--     DevicesFitExactly                   `rdev` answers a number exactly when the major is below
--                                         4096 and the minor below 2^20
--     TheNumbersComeBack                  `major_minor` of what `rdev` answered is the major and the
--                                         minor given: nothing is cut
--     EveryNumberIsOneDevice              every 32-bit number is the `rdev` of the device it decodes
--                                         to: no two devices share a number
--     OnlyDeviceZeroIsNumberZero          the number of a device is 0 (`WHITEOUT`) only for 0:0
--     TheWhiteoutIsACharacterDeviceZero   `whiteout` is true exactly for a character device 0:0, and
--                                         0:0 has the number `WHITEOUT`
--
--   Examples
--     WorkedExamples                      the answers for the names and the numbers of the tests
--
--   Trusted: Charon and Aeneas (../../pins) and Lean; the crate calls the standard library only for
--   the length of a slice and whether it is empty, which Aeneas models; no model is written by hand.
--
--   Not claimed:
--   - what the callers do with a refused or an overlay name (drop the entry, fail the pull): the
--     crates that read the layers decide, `class` only judges;
--   - that the kernel reads exactly these names: the claims are about the rule of the crate (the
--     four namespaces and `overlay.`); that a name of another namespace (`foo.x`, `overlay.x`) is
--     called plain is the rule of the crate, and is said, not judged;
--   - that `trusted.overlay` and `user.overlay` with no dot after them are plain (they are: the
--     kernel reads the names with the dot only);
--   - the escaping of names in a tar or a table of contents, the values of the attributes, and
--     what the overlay does with a plain attribute;
--   - that a character device of another number than 0:0, or a block device, is harmless: only the
--     whiteout is judged;
--   - which files are whiteouts by their NAME (`.wh.x`): that is the reader of the tar's.
--
-- Notation:
--   - `f x ⦃ r => P r ⦄` reads: the Rust function `f`, given `x`, returns (it does not panic) and
--     its answer `r` satisfies `P r`.
--   - `attr : Slice Std.U8` is a Rust slice of bytes; `attr.val` is the list inside it.
--     `a <+: b` says that the list `a` is the beginning of the list `b`; `a ++ b` is `a` and then
--     `b`; `[]` is the empty list; `x ∈ l` says `x` is in the list `l`; `0#u8` is the byte 0.
--   - `Option` answers: `some x` is a number, `none` is "no number".
--   - `∀ x, P` is "for every x, P"; `∃ x, P` is "there is an x such that P"; `∧` is "and", `∨` is
--     "or", `→` is "if ... then", `↔` is "exactly when", `¬` is "not".
--   - `a.val` is the number inside a `u32`; `a.bv` the same as 32 bits, which `&&&` (and), `|||`
--     (or), `<<<` and `>>>` (shifts) work on.
import Extracted.Funs

open Aeneas Aeneas.Std Result velarx_overlay_core

namespace OverlayCore

/-- The bytes of a name written in letters (they are ASCII). -/
def Text (word : String) : List Std.U8 :=
  word.toList.map (fun letter => ⟨BitVec.ofNat 8 letter.toNat⟩)

/-- The four namespaces of an attribute that the crate knows, with their dots. -/
def Namespaces : List (List Std.U8) :=
  [Text "trusted.", Text "user.", Text "security.", Text "system."]

/-- The name is the overlay's: a namespace, then `overlay.`, then anything (what the namespace
and `overlay.` make is the beginning of the name). -/
def OverlayName (b : List Std.U8) : Prop :=
  ∃ ns ∈ Namespaces, (ns ++ Text "overlay.") <+: b

/-- **The functions always return.**  `class` for every name, `rdev` and `whiteout` for every
numbers, `major_minor` for every number: no panic, no overflow, no byte read outside the name, for
a name of any length and any bytes.

Not said: what they return (the claims below). -/
def TheFunctionsAlwaysReturn : Prop :=
  (∀ attr : Slice Std.U8, «class» attr ⦃ _ => True ⦄) ∧
  (∀ major minor : Std.U32, rdev major minor ⦃ _ => True ⦄) ∧
  (∀ encoded : Std.U32, major_minor encoded ⦃ _ => True ⦄) ∧
  (∀ (is_char : Bool) (major minor : Std.U32), whiteout is_char major minor ⦃ _ => True ⦄)

/-- **No overlay name gets through.**  `class` returns, and when it calls a name plain (an
attribute of a layer, which the image may carry), the name does not begin with
`trusted.overlay.`, `user.overlay.`, `security.overlay.` or `system.overlay.`, and it is not
`security.selinux` (the label is the engine's).  So whatever an image says, the overlay finds in
it none of the attributes that steer it: not `redirect`, `metacopy`, `opaque`, `origin`, not one
nested under another `overlay.`.

Not said: that a name is called plain (`TheNamesOfLayersAreKept` says it, so that a `class` that
calls nothing plain does not satisfy this claim); the namespaces `trusted.overlay` and
`user.overlay` with no dot (plain, as the kernel reads only the names with the dot). -/
def NoOverlayNameGetsThrough : Prop :=
  ∀ attr : Slice Std.U8, «class» attr ⦃ c => c = Class.Plain →
    ¬ Text "trusted.overlay." <+: attr.val ∧ ¬ Text "user.overlay." <+: attr.val ∧
    ¬ Text "security.overlay." <+: attr.val ∧ ¬ Text "system.overlay." <+: attr.val ∧
    attr.val ≠ Text "security.selinux" ⦄

/-- **The names of the layers are kept.**  `class` returns, and when a name is one of the four
namespaces and then a rest (`user.x`, `trusted.foo`, `system.posix_acl_access`) with
- a rest that is not empty,
- a rest with no NUL byte,
- a rest that does not begin with `overlay.`,
- and the name is not `security.selinux`,
then the answer is plain: the attribute passes.  This holds for every rest, of any length.

Not said: that these are the only plain names (`foo.x`, with no namespace, is plain too: that
follows from `WhatIsRefusedExactly` and `WhatIsOverlayAndWhatIsLabelExactly`, not from this claim). -/
def TheNamesOfLayersAreKept : Prop :=
  ∀ (attr : Slice Std.U8) (ns rest : List Std.U8), ns ∈ Namespaces → attr.val = ns ++ rest →
    rest ≠ [] → 0#u8 ∉ rest → ¬ Text "overlay." <+: rest → attr.val ≠ Text "security.selinux" →
    «class» attr ⦃ c => c = Class.Plain ⦄

/-- **The attributes that real layers carry are kept.**  `class` returns, and for each of these
names the answer is plain: `security.capability` (file capabilities), `security.ima`,
`system.posix_acl_access` and `system.posix_acl_default` (ACLs), `user.xdg.origin.url`, and
`user.overlay` (no dot after `overlay`, so not the overlay's).

Not said: that these are the only ones kept (`TheNamesOfLayersAreKept` says it for all). -/
def TheNamesOfRealLayersAreKept : Prop :=
  ∀ attr : Slice Std.U8,
    (attr.val = Text "security.capability" ∨ attr.val = Text "security.ima" ∨
     attr.val = Text "system.posix_acl_access" ∨ attr.val = Text "system.posix_acl_default" ∨
     attr.val = Text "user.xdg.origin.url" ∨ attr.val = Text "user.overlay") →
    «class» attr ⦃ c => c = Class.Plain ⦄

/-- **A name is refused exactly when it is no name.**  `class` returns, and its answer is a
refusal exactly when the name
- is empty (`Refusal.Empty`), or
- has a NUL byte, and is not empty (`Refusal.Nul`), or
- is one of the namespaces and nothing after it, `user.`, `trusted.`, `security.`, `system.`
  (`Refusal.NoName`);
and the refusal says which of the three.  Nothing else is refused: the name `user.x`, a name of
another namespace, `trusted.overlay.x` are not.

Not said: what the caller does with a refusal. -/
def WhatIsRefusedExactly : Prop :=
  ∀ attr : Slice Std.U8, «class» attr ⦃ c =>
    ((∃ why, c = Class.Refused why) ↔ attr.val = [] ∨ 0#u8 ∈ attr.val ∨ attr.val ∈ Namespaces) ∧
    (c = Class.Refused Refusal.Empty ↔ attr.val = []) ∧
    (c = Class.Refused Refusal.Nul ↔ attr.val ≠ [] ∧ 0#u8 ∈ attr.val) ∧
    (c = Class.Refused Refusal.NoName ↔ attr.val ∈ Namespaces) ⦄

/-- **The overlay's names and the label are told exactly.**  `class` returns, and
- the answer is `Overlay` exactly when the name has no NUL byte and begins with `trusted.overlay.`,
  `user.overlay.`, `security.overlay.` or `system.overlay.`;
- the answer is `Label` exactly when the name is `security.selinux`.
(A name with a NUL byte is refused, whatever it begins with.)  Together with the claims above this
is the whole answer: plain is what none of the other answers is.

Not said: anything of the values of the attributes. -/
def WhatIsOverlayAndWhatIsLabelExactly : Prop :=
  ∀ attr : Slice Std.U8, «class» attr ⦃ c =>
    (c = Class.Overlay ↔ 0#u8 ∉ attr.val ∧
      (Text "trusted.overlay." <+: attr.val ∨ Text "user.overlay." <+: attr.val ∨
       Text "security.overlay." <+: attr.val ∨ Text "system.overlay." <+: attr.val)) ∧
    (c = Class.Label ↔ attr.val = Text "security.selinux") ⦄

/-- **`rdev` answers exactly when the numbers fit.**  `rdev` returns, and its answer is a number
(not `none`) exactly when the major is below 4096 and the minor below 2^20.  A pair that does not fit
is not squeezed into 32 bits, and one that fits is not refused.

Not said: which number it is (the next claims). -/
def DevicesFitExactly : Prop :=
  ∀ major minor : Std.U32, rdev major minor ⦃ r =>
    ((∃ x, r = some x) ↔ major.val < 4096 ∧ minor.val < 2 ^ 20) ⦄

/-- **The numbers come back.**  `rdev` returns, and when its answer is a number `x`, then
`major_minor x` returns the major and the minor that were given.  So the major and the minor of a
device are not cut or mixed by the encoding.

Not said: that `x` is what the kernel's `new_encode_dev` makes (the layout is in the words above,
and `EveryNumberIsOneDevice` pins it down together with this). -/
def TheNumbersComeBack : Prop :=
  ∀ major minor : Std.U32, rdev major minor ⦃ r =>
    ∀ x, r = some x → major_minor x ⦃ p => p = (major, minor) ⦄ ⦄

/-- **Every number is one device.**  For every 32-bit number `x`, `major_minor x` returns a major
and a minor, `rdev` of those fits and answers `x`.  So two devices never have the same number (a
number decodes to one pair, which gives it back), and a number of an image is always the number of
a device that fits.

Not said: anything of what the device is (character, block). -/
def EveryNumberIsOneDevice : Prop :=
  ∀ x : Std.U32, major_minor x ⦃ p => rdev p.1 p.2 ⦃ r => r = some x ⦄ ⦄

/-- **The number 0 is the device 0:0 only.**  `rdev` returns, and when its answer is a number `x`,
`x` is `WHITEOUT` (0) exactly when the major and the minor are both 0.  So no other device is taken
for the whiteout by its number.

Not said: that a device 0:0 is a whiteout (the next claim). -/
def OnlyDeviceZeroIsNumberZero : Prop :=
  ∀ major minor : Std.U32, rdev major minor ⦃ r =>
    ∀ x, r = some x → (x = WHITEOUT ↔ major = 0#u32 ∧ minor = 0#u32) ⦄

/-- **A whiteout is a character device 0:0.**  `whiteout` returns, and its answer is true exactly
when the device is a character device (`is_char`) with major 0 and minor 0; and the device 0:0 has
the number `WHITEOUT`, which is the one the overlay reads as a whiteout.

Not said: that the entry may be in the layer (it may: a layer tarred from an upper dir has them). -/
def TheWhiteoutIsACharacterDeviceZero : Prop :=
  (∀ (is_char : Bool) (major minor : Std.U32), whiteout is_char major minor ⦃ w =>
    (w = true ↔ is_char = true ∧ major = 0#u32 ∧ minor = 0#u32) ⦄) ∧
  rdev 0#u32 0#u32 ⦃ r => r = some WHITEOUT ⦄

/-- **Worked examples** of the answers, each a name or a pair of numbers of the tests of the crate:
`user.x` is plain, `trusted.overlay.redirect` and `user.overlay.x` are the overlay's,
`security.selinux` is the label, `user.` and the empty name are refused, `trusted.overlay` (no dot)
is plain; the device 8:1 has the number 2049 (0x801), 4096:0 and 0:2^20 have none, and the largest
fitting pair 4095:1048575 has the number 4294967295.

Not said: anything of other names (the claims above are for all). -/
def WorkedExamples : Prop :=
  (∀ attr : Slice Std.U8, attr.val = Text "user.x" → «class» attr ⦃ c => c = Class.Plain ⦄) ∧
  (∀ attr : Slice Std.U8, attr.val = Text "trusted.overlay" → «class» attr ⦃ c => c = Class.Plain ⦄) ∧
  (∀ attr : Slice Std.U8, attr.val = Text "trusted.overlay.redirect" →
    «class» attr ⦃ c => c = Class.Overlay ⦄) ∧
  (∀ attr : Slice Std.U8, attr.val = Text "user.overlay.x" → «class» attr ⦃ c => c = Class.Overlay ⦄) ∧
  (∀ attr : Slice Std.U8, attr.val = Text "security.selinux" → «class» attr ⦃ c => c = Class.Label ⦄) ∧
  (∀ attr : Slice Std.U8, attr.val = Text "user." →
    «class» attr ⦃ c => c = Class.Refused Refusal.NoName ⦄) ∧
  (∀ attr : Slice Std.U8, attr.val = [] → «class» attr ⦃ c => c = Class.Refused Refusal.Empty ⦄) ∧
  rdev 8#u32 1#u32 ⦃ r => r = some 2049#u32 ⦄ ∧
  rdev 4096#u32 0#u32 ⦃ r => r = none ⦄ ∧
  rdev 0#u32 1048576#u32 ⦃ r => r = none ⦄ ∧
  rdev 4095#u32 1048575#u32 ⦃ r => r = some 4294967295#u32 ⦄

end OverlayCore
