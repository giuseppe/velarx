-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: what is proved of crates/user-core, the user a container runs as: the
-- `--user` of a run, the `User` of an image or the user of a pod (`NAME`, `UID`, `NAME:GROUP`,
-- `UID:GID`) against the `/etc/passwd` and `/etc/group` of the image.  `resolve` turns them into a
-- uid, a gid, a home and the supplementary groups, or refuses.  This file is what a reviewer reads,
-- in words and in statements, with no proof; Lean checks the rest (the other files of UserCore/;
-- Theorems.lean ties each claim below to its proof).
--
-- Why it is needed: both files come from the image, so they are bytes nobody vouched for, and they
-- decide the uid and the groups of a process.  The tests of the crate (src/rules.rs, src/walk.rs)
-- check the rules on every small input; each claim below is the same rule for EVERY byte string.
-- A proof is worth what its statement says, so each claim has a comment of what it claims and of
-- what it does NOT.
--
-- Words.  A LINE of a file ends at a newline (a carriage return before it is no part of it).  A
-- passwd ENTRY is a line with at least six colons, whose third field (uid) and fourth (gid) are
-- ids; the first field is the name, the sixth the home.  A group line has at least three colons,
-- an id in the third field, and the members (separated by commas) after the next one; a line that
-- starts with `#` is a comment.  An ID is one or more digits whose value is below 4294967295
-- (`ParsedId`).  The USER PART of a user string is what comes before its first colon, the GROUP
-- PART what comes after (`UserPart`, `GroupPart`); the empty string is read as `0`
-- (`UserString`).  `Lists` says a name is a whole member between commas.
--
-- Total correctness: each claim says that the function RETURNS (no panic, no overflow, no byte
-- read outside the data) and what its answer is.  The one condition a claim names is `Short`: a
-- Rust slice is never as long as `Usize.max`, so that the place after its end fits in a `usize`.
--
-- Read before this file: the header of crates/user-core/src/lib.rs, and rules.rs.
--
-- Index.  What each claim is about:
--
--   Claimed (each for every passwd, group, user string, list of added groups and `strict`):
--     ResolveAlwaysReturns             `resolve` and its helpers return on any bytes
--     AnIdIsTheNumberWritten           `parse_id`: exactly the digits, below 4294967295
--     ANumericUserKeepsItsId           a numeric user keeps the uid written
--     ANamedUserIsAnEntryOfTheFile     a named user is an entry of a line of the passwd file
--     TheGroupsAreIdsOnceAndBounded    gid first, no gid twice, at most 65536, ids below the limit
--     WhereAGroupComesFrom             each group is the gid, a `group_add`, or a group listing the user
--     TheRefusalsOfTheUserString       `Malformed` and `BadUserId` exactly when
--     TheEmptyUserIsZero               the empty user string is `0`
--
--   Trusted (not checked here):
--     Charon and Aeneas (the versions in ../../pins) and the models Aeneas has of the library;
--     Models.lean, the three functions of the standard library written by hand: `Option::branch`
--     and `Option::from_residual` (the `?` on an option) and `Option::eq`; Lean itself.
--
--   Not claimed:
--     that the entry found for a name is the FIRST of that name (the tests of the crate check it),
--     that `passwd_find` and `has_uid` find an entry whenever the file has one (so the "no entry
--     of that uid" of `ANumericUserKeepsItsId` is said as `has_uid` answering false),
--     what `home` answers (a three-way choice, tested), what the shell does with the answer (reads
--     of the files below the root, their bounds, the words of the errors, `keep-groups`, the
--     entries added for a user the image has not), the time and the memory used, and that an
--     answer `NoUser`, `NoGroup`, `BadGroupId` or `TooManyGroups` is given in exactly the cases the
--     comments of lib.rs list (only that those are the only other refusals).
--
-- Notation: `f x ⦃ r => P r ⦄` is "the Rust `f` returns on `x`, with no panic and no endless loop,
-- and its answer `r` satisfies `P`"; `↑x` is the number of a machine integer; `l[i]?` is the
-- byte at the place `i` of `l`, if there is one; `∀`, `∃`, `∧`, `∨`, `→`, `↔` are "for all",
-- "there is", "and", "or", "if ... then", "exactly when".
import Extracted.Funs
open Aeneas Aeneas.Std Result velarx_user_core
namespace UserCore

/-- The byte is an ASCII digit, `0` to `9`. -/
def IsDigit (b : Std.U8) : Prop := 48 ≤ b.val ∧ b.val ≤ 57
/-- The bytes are one or more digits. -/
def IsDigits (s : List Std.U8) : Prop := s ≠ [] ∧ ∀ b ∈ s, IsDigit b
/-- The number that digits write in decimal. -/
def Value (s : List Std.U8) : Nat := s.foldl (fun n b => 10 * n + (b.val - 48)) 0
/-- 4294967295, which means "no id" to the kernel: never an id of ours. -/
def NoId : Nat := 4294967295

/-- The byte is a colon. -/
def Colon (b : Std.U8) : Bool := b.val == 58
/-- The user string `u` as it is read: the empty one is `0`. -/
def UserString (u : List Std.U8) : List Std.U8 := if u = [] then [48#u8] else u
/-- The user part of a user string: the bytes before the first colon. -/
def UserPart (u : List Std.U8) : List Std.U8 := u.takeWhile (fun b => !Colon b)
/-- The group part of a user string: the bytes after the first colon, if it has one. -/
def GroupPart (u : List Std.U8) : Option (List Std.U8) :=
  if u.any Colon then some (u.drop ((UserPart u).length + 1)) else none

/-- The byte at the place `i` is the number `c`. -/
def ByteAt (d : List Std.U8) (i c : Nat) : Prop := d[i]?.map (·.val) = some c

/-- Whether the byte at a place is a given number can be decided. -/
instance (d : List Std.U8) (i c : Nat) : Decidable (ByteAt d i c) := by unfold ByteAt; infer_instance

/-- No byte from the place `a` to before `b` is `c`. -/
def NoByte (d : List Std.U8) (c a b : Nat) : Prop := ∀ i, a ≤ i → i < b → ¬ ByteAt d i c

/-- `start` to `stop` is a line of `d`: it starts the file or follows a newline, has no newline in
it and ends at the end of the file, at a newline, or at a carriage return before a newline. -/
def IsLine (d : List Std.U8) (start stop : Nat) : Prop :=
  start ≤ stop ∧ stop ≤ d.length ∧ (start = 0 ∨ ByteAt d (start - 1) 10) ∧ NoByte d 10 start stop ∧
    (stop = d.length ∨ ByteAt d stop 10 ∨ (ByteAt d stop 13 ∧ ByteAt d (stop + 1) 10))

/-- The places of the colons from `start` to before `stop`. -/
def Colons (d : List Std.U8) (start stop : Nat) : List Nat :=
  (List.range' start (stop - start)).filter (fun i => decide (ByteAt d i 58))

/-- `s` is the written form of the id `n`. -/
def ParsedId (s : List Std.U8) (n : Std.U32) : Prop := IsDigits s ∧ Value s = n.val ∧ n.val < NoId

/-- `e` is the passwd entry that a line of `d` makes: it has at least six colons, and the name, the
uid, the gid, the gecos and the home are what lies between them. -/
def IsPasswdEntry (d : List Std.U8) (start stop : Nat) (e : Passwd) : Prop :=
  ∃ c0 c1 c2 c3 c4 c5 rest, Colons d start stop = c0 :: c1 :: c2 :: c3 :: c4 :: c5 :: rest ∧
    e.name.1.val = start ∧ e.name.2.val = c0 ∧
    ParsedId (List.slice (c1 + 1) c2 d) e.uid ∧ ParsedId (List.slice (c2 + 1) c3 d) e.gid ∧
    e.gecos.1.val = c3 + 1 ∧ e.gecos.2.val = c4 ∧ e.home.1.val = c4 + 1 ∧ e.home.2.val = c5

/-- The name, the gid and the members of `g` lie between the first colons of the line. -/
def GroupColons (d : List Std.U8) (start stop : Nat) (g : GroupLine) : Prop :=
  ∃ c0 c1 c2 rest, Colons d start stop = c0 :: c1 :: c2 :: rest ∧
    g.name.1.val = start ∧ g.name.2.val = c0 ∧ ParsedId (List.slice (c1 + 1) c2 d) g.gid ∧
    g.members.1.val = c2 + 1 ∧ g.members.2.val = (rest.head?.getD stop)

/-- `g` is the group line of `d` from `start` to `stop`: not a comment, and with the colons. -/
def IsGroupEntry (d : List Std.U8) (start stop : Nat) (g : GroupLine) : Prop :=
  ¬ (start < stop ∧ ByteAt d start 35) ∧ GroupColons d start stop g

/-- `e` is an entry of the passwd file `d` that has the name or the uid asked for. -/
def FoundEntry (d : List Std.U8) (who : Option (Slice Std.U8)) (uid : Option Std.U32)
    (e : Passwd) : Prop :=
  ∃ start stop, IsLine d start stop ∧ IsPasswdEntry d start stop e ∧
    ((∃ n, who = some n ∧ List.slice e.name.1.val e.name.2.val d = n.val) ∨ uid = some e.uid)

/-- `a` to `b` is one of the comma separated fields of the members `m0` to `m1` of `d`. -/
def FieldOf (d : List Std.U8) (m0 m1 a b : Nat) : Prop :=
  m0 ≤ a ∧ a ≤ b ∧ b ≤ m1 ∧ (a = m0 ∨ ByteAt d (a - 1) 44) ∧ (b = m1 ∨ ByteAt d b 44) ∧
    NoByte d 44 a b

/-- `word` is one of the comma separated members `m` of `d`, whole. -/
def Lists (d : List Std.U8) (m : Nat × Nat) (word : List Std.U8) : Prop :=
  ∃ a b, FieldOf d m.1 m.2 a b ∧ List.slice a b d = word

/-- `gid` is that of a group line of `d` of the name `word`. -/
def GroupNamed (d : List Std.U8) (word : List Std.U8) (gid : Std.U32) : Prop :=
  ∃ start stop g, IsLine d start stop ∧ IsGroupEntry d start stop g ∧ g.gid = gid ∧
    List.slice g.name.1.val g.name.2.val d = word

/-- The group `g` of `--group-add` or of the user string names the gid `x`: it is written as an id,
or (not all digits) it is the name of a group line of the file. -/
def NamesGroup (group : List Std.U8) (g : List Std.U8) (x : Std.U32) : Prop :=
  ParsedId g x ∨ (¬ IsDigits g ∧ GroupNamed group g x)

/-- A refusal that comes from the groups of the request. -/
def GroupRefusal (r : Refusal) : Prop :=
  r = Refusal.TooManyGroups ∨ (∃ w, r = Refusal.BadGroupId w) ∨ (∃ w, r = Refusal.NoGroup w)

/-- `x` is the gid of a group line of `d` that lists `who` among its members. -/
def ListedIn (d : List Std.U8) (who : List Std.U8) (x : Std.U32) : Prop :=
  ∃ start stop g, IsLine d start stop ∧ IsGroupEntry d start stop g ∧ g.gid = x ∧
    Lists d (g.members.1.val, g.members.2.val) who

/-- `parse_id s` is `some n` exactly when `s` is one or more digits whose decimal value is `n` and `n` is below 4294967295: `007` is 7; `-1`, `+1`, ` 1`, `1x`, the empty string and a number that does not fit are no id, never taken modulo 2^32.  NOT said: how long it takes. -/
def AnIdIsTheNumberWritten : Prop :=
  ∀ s : Slice Std.U8, parse_id s ⦃ r => ∀ n : Std.U32, r = some n ↔ ParsedId s.val n ⦄


/-- The files are shorter than `Usize.max` bytes, so that the place after the end of each fits in a
`usize` (a Rust slice is never as long as `Usize.max`). -/
def Short (passwd group : Slice Std.U8) : Prop :=
  passwd.length < Std.Usize.max ∧ group.length < Std.Usize.max

/-- `resolve` returns, whatever the bytes of the files, the user string and the groups added (no panic, no overflow, no endless loop), and so do the helpers `parse_id`, `split_user`, `passwd_find`, `has_uid`, `has_gid` and `home`.  NOT said: what `home` answers, nor the time or memory used. -/
def ResolveAlwaysReturns : Prop :=
  (∀ passwd group user ga strict, Short passwd group →
    resolve passwd group user ga strict ⦃ _ => True ⦄) ∧
  (∀ s, parse_id s ⦃ _ => True ⦄) ∧
  (∀ user, split_user user ⦃ _ => True ⦄) ∧
  (∀ passwd who uid, passwd.length < Std.Usize.max → passwd_find passwd who uid ⦃ _ => True ⦄) ∧
  (∀ passwd uid, passwd.length < Std.Usize.max → has_uid passwd uid ⦃ _ => True ⦄) ∧
  (∀ group gid, group.length < Std.Usize.max → has_gid group gid ⦃ _ => True ⦄) ∧
  (∀ h w, home h w ⦃ _ => True ⦄)

/-- When the user part is digits and `resolve` answers, the uid is the number written (an id, never modulo 2^32); and for a uid that the passwd file has no entry of, with no group part, the gid is 0 and there is no home.  NOT said: that the digits are no id (see `TheRefusalsOfTheUserString`). -/
def ANumericUserKeepsItsId : Prop :=
  ∀ passwd group user ga strict, Short passwd group →
    IsDigits (UserPart (UserString user.val)) →
    resolve passwd group user ga strict ⦃ r => ∀ res, r = core.result.Result.Ok res →
      ParsedId (UserPart (UserString user.val)) res.uid ∧
      ∀ id : Std.U32, ParsedId (UserPart (UserString user.val)) id → has_uid passwd id = ok false →
        GroupPart (UserString user.val) = none → res.gid = 0#u32 ∧ res.home = none ⦄

/-- When the user part is not digits and `resolve` answers, its uid, its home and (with no group part) its gid are those of an entry that is a line of the passwd file: seven or more fields, uid and gid written as ids, a name equal to the user part.  NOT said: that it is the FIRST line of that name (the first-line rule is tested in the crate, not proved), nor that no earlier line was skipped for a good reason. -/
def ANamedUserIsAnEntryOfTheFile : Prop :=
  ∀ passwd group user ga strict, Short passwd group →
    ¬ IsDigits (UserPart (UserString user.val)) →
    resolve passwd group user ga strict ⦃ r => ∀ res, r = core.result.Result.Ok res →
      ∃ (e : Passwd) (start stop : Nat), IsLine passwd.val start stop ∧
        IsPasswdEntry passwd.val start stop e ∧
        List.slice e.name.1.val e.name.2.val passwd.val = UserPart (UserString user.val) ∧
        res.uid = e.uid ∧ res.home = some e.home ∧
        (GroupPart (UserString user.val) = none → res.gid = e.gid) ⦄

/-- In an answer the gid comes first in `gids`, no gid is twice, there are at most 65536, and the uid, the gid and every group are below 4294967295.  NOT said: which groups (see `WhereAGroupComesFrom`). -/
def TheGroupsAreIdsOnceAndBounded : Prop :=
  ∀ passwd group user ga strict, Short passwd group →
    resolve passwd group user ga strict ⦃ r => ∀ res, r = core.result.Result.Ok res →
      res.gids.val.head? = some res.gid ∧ res.gids.val.Nodup ∧ res.gids.val.length ≤ 65536 ∧
      res.uid.val < NoId ∧ res.gid.val < NoId ∧ ∀ x ∈ res.gids.val, x.val < NoId ⦄

/-- Each group of an answer is the gid, or the gid a `group_add` names (as an id or as a group name of the file), or, with no group part and no `strict`, the gid of a group line of the group file that lists the name of the entry (not empty) whole between commas.  The gid itself is that of the group part when there is one.  NOT said: that every such group is in the answer (the list may be cut by the limit, which is an error here), nor their order beyond the gid first. -/
def WhereAGroupComesFrom : Prop :=
  ∀ passwd group user ga strict, Short passwd group →
    resolve passwd group user ga strict ⦃ r => ∀ res, r = core.result.Result.Ok res →
      (∀ g, GroupPart (UserString user.val) = some g → NamesGroup group.val g res.gid) ∧
      ∀ x ∈ res.gids.val, x = res.gid ∨
        (∃ (k : Nat) (s : alloc.vec.Vec Std.U8), ga.val[k]? = some s ∧ NamesGroup group.val s.val x) ∨
        (GroupPart (UserString user.val) = none ∧ strict = false ∧
          ∃ (e : Passwd) (start stop : Nat), IsLine passwd.val start stop ∧
            IsPasswdEntry passwd.val start stop e ∧ e.uid = res.uid ∧ res.home = some e.home ∧
            e.name.1.val < e.name.2.val ∧
            ListedIn group.val (List.slice e.name.1.val e.name.2.val passwd.val) x) ⦄

/-- For the user string as read, `Malformed` is answered exactly for an empty user part or an empty group part, and `BadUserId` exactly when neither is empty and the user part is digits that are no id.  NOT said: the other refusals (`NoUser`, the group ones) beyond what the other claims say. -/
def TheRefusalsOfTheUserString : Prop :=
  ∀ passwd group user ga strict, Short passwd group →
    resolve passwd group user ga strict ⦃ r =>
      (r = core.result.Result.Err Refusal.Malformed ↔
        (UserPart (UserString user.val) = [] ∨ GroupPart (UserString user.val) = some [])) ∧
      (r = core.result.Result.Err Refusal.BadUserId ↔
        (¬ (UserPart (UserString user.val) = [] ∨ GroupPart (UserString user.val) = some []) ∧
          IsDigits (UserPart (UserString user.val)) ∧ NoId ≤ Value (UserPart (UserString user.val)))) ⦄

/-- The empty user string is read as `0`: `resolve` of it is `resolve` of `0`. -/
def TheEmptyUserIsZero : Prop :=
  ∀ passwd group user ga strict, user.val = [] → ∀ zero : Slice Std.U8, zero.val = [48#u8] →
    resolve passwd group user ga strict = resolve passwd group zero ga strict

end UserCore
