-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: what is proved of crates/idmap-core, the id mappings of a user namespace
-- (a list of `(container id, parent id, size)`, the checks on it, the sets of ids and the layouts
-- of `--userns=auto` and `--userns=keep-id`), in words and in statements, with no proof.  This
-- file is what a reviewer reads; Lean checks the rest (the proofs are in the other files of
-- IdmapCore/, named for what they say; Claims.lean has the proof of each statement below).
--
-- Why it is needed: a mapping decides which ids of the host a process of a container acts as.  If
-- two containers got the same parent id, or a container were mapped to an id the user does not own,
-- one could act as the other.  The tests of the crate (src/rules.rs, src/walk.rs) check these
-- rules on every small input; each claim below is the same rule for EVERY input, with ids of 32
-- bits (sums of 64) and lists of any length.  A proof is worth what its statement says, so each
-- claim has a comment of what it claims and of what it does NOT.
--
-- The statements are about plain natural numbers (`Nat`: 0, 1, 2, ... with no largest one, so no
-- overflow can happen in them).  The one idea is `Maps m c p`: "the mapping list `m` maps the
-- container id `c` to the parent id `p`".  It is defined once, from the entries, and every claim is
-- said with it.  None of the definitions is the code of a function written again.
--
-- Total correctness: each claim says that the function RETURNS (no panic, no overflow, no index
-- outside a list, every loop ends) and that its answer is as stated.
--
-- Upper and lower bounds: "if `validate` accepts, the list is good" alone is satisfied by a
-- `validate` that always refuses.  So where that matters a claim says both ways (`iff`: accepted
-- exactly when ...).
--
-- Read before this file: lib.rs of crates/idmap-core, then rules.rs.
--
-- Index.  What each claim is about, what is trusted and what is not claimed:
--
--   Claimed (each for every input; the function returns, and):
--
--   The checks on a mapping:
--     ValidateAcceptsExactlyTheValidLists  `validate` accepts exactly the valid lists: at most 340
--                                      entries, none empty, none ending past the limit, and no two
--                                      entries share a container id or a parent id (both ways)
--     ValidListsAreFunctionsBothWays   a valid list maps no container id to two parent ids and no
--                                      parent id from two container ids
--   The sets of ids (`IdSet`):
--     FromIntervalsHasTheIdsOfTheIntervals  `IdSet::from_intervals` builds an ordered set with
--                                      exactly the ids of the intervals
--     OfParentIdsHasTheParentIds       `of_parent_ids`: the parent ids of the entries, exactly
--     OfContainerIdsHasTheContainerIds `of_container_ids`: the container ids, exactly
--     SizeIsTheNumberOfIds             `IdSet::size` is the number of ids, without overflow
--     UnionHasTheIdsOfBoth             `IdSet::union` has the ids of one or the other, ordered
--     IsEmptyIsTrueExactlyForTheEmptySet  `IdSet::is_empty` is true exactly for the empty set
--     ContainsRangeIsTrueExactlyForARangeInTheSet  `contains_range` says whether every id of a
--                                      range is in the set
--     SubtractHasTheIdsOfTheFirstNotInTheSecond  `IdSet::subtract` is the difference of the sets
--     BelowHasTheIdsUnderTheLimit      `below` keeps the ids under a limit
--     FindAvailableGivesNIdsOrSaysThereAreFewer  `find_available`: `n` ids of the set or "fewer"
--     ZipMapsTheSecondSetOntoTheFirst  `zip` pairs the ids of two sets: apart, sane, all of the 2nd
--   `--userns=keep-id`:
--     KeepIdMapsExactlyTheLayout       `keep_id` maps the pairs of the layout and no other
--     KeepIdUsesOnlyTheSubIds          `keep_id` uses only the parent ids 0 to `sub`
--     KeepIdIsValid                    `keep_id` is valid (for ids below the limit)
--   Finding the parent id of a range:
--     RangeToParentAnswersForARangeInOneEntry  an answer of `range_to_parent` is right, and the
--                                      whole range is in one entry
--     RangeToParentAnswersWhenTheRangeIsInOneEntry  for a valid list it answers when it is
--   Putting entries in order:
--     SortAndMergeKeepsThePairs        `sort_and_merge` maps exactly what its input maps
--     SortAndMergeKeepsSaneApartEntries  and keeps entries that are sane and apart so
--   Filling the free container ids:
--     FillKeepsWhatTheMappingMaps      `fill` keeps what the mapping maps
--     FillAddsOnlyFreeContainerIds     and adds only free container ids, with ids of `available`
--     FillMapsEveryFreeContainerIdWhenThereAreEnoughIds  and all of them if there are enough
--   `--userns=auto`:
--     AutoMapIsValid                   when `auto_map` answers with a mapping it is valid
--     AutoMapUsesOnlyFreeParentIds     it uses only the user's extra parent ids and free ids of
--                                      the pool: no two containers share a host id unless asked
--     AutoMapMapsTheContainerIdsAsked  it maps the container ids below `size` and those of the
--                                      extra mappings, and no other
--     AutoMapKeepsTheExtraMappings     every pair of the extra mappings is in it
--     AutoMapKeepsTheAutomaticPartApartFromTheExtraMappings  its own choice never uses a parent
--                                      id of the extra mappings; container ids from `size` up are
--                                      mapped by the extra mappings only
--     AutoMapAnswersWhenTheFreeIdsBeginWithARun  with no extra mappings and free ids that begin
--                                      with a run of `size` ids, it answers with a mapping
--     AutoMapRefusesOnlyForAReason     when it refuses, the reason is true (see the claim);
--                                      the one case where it must answer is the claim before
--   Cutting a mapping where the parent's extents end (the rootless `uid_map` goes through it):
--     SplitOnKeepsThePairs             `split_on` maps exactly what its input maps
--   Inserting a mapping into another (`--uidmap` with `+`):
--     BreakInsertMapsTheNewAndWhatItDoesNotTouch  `break_insert` maps the inserted entry and
--                                      the pairs of the old mapping that share no container id
--                                      and no parent id with it, and nothing else
--     BreakInsertKeepsAFunctionBothWays  from a valid mapping it makes a function both ways
--
--   The rootless `uid_map` is the answer of `auto_map` (or `keep_id`) after `split_on`: both are
--   proved, and so is what they have in common (the same pairs), not what the kernel then makes
--   of the lines.
--
--   Trusted: Charon and Aeneas (../../pins) and the models of the standard library Aeneas itself
--   has (the integer operations, slice and vector indexing); no model is written by hand.  The
--   derived `Debug`, `==` and `Default` of `IdSet` call library functions that are left as axioms
--   in the template that Aeneas writes (Models.lean only says that it adds none); no claim
--   speaks of them.
--
--   Not claimed:
--   - anything of the shell (velarx-base idmap.rs and velarx-runtime userns: the syntax of the
--     options, the files with the ranges, what other containers use);
--   - two engine processes that share one database: `auto_map` answers for the sets it is given,
--     and one process serialises the allocation with a lock; two processes are not covered;
--   - `newuidmap` and `newgidmap` (the programs that write a rootless map), and what the kernel
--     does with a mapping;
--   - where the pool comes from: in rootless mode it is the ids the daemon was granted, minus 0,
--     not `/etc/subuid`; that the ids of the pool belong to the user is what the caller says;
--   - that `used` really holds every id that other containers use (the caller says so:
--     `auto_map` only avoids what it is given);
--   - `validate` is stricter than "function both ways": it also refuses a repeated entry, or two
--     entries that overlap but agree (the kernel refuses such lines), so it accepts fewer lists
--     than the functions both ways;
--   - that `auto_map` takes the lowest free ids, or fewer entries than another choice of free
--     ids would give.
--
-- Notation:
--   - `validate maps ⦃ r => P r ⦄` reads: the Rust function `validate`, given `maps`, returns (it
--     does not panic, it does not loop for ever) and its answer `r` satisfies `P r`.
--     `core.result.Result.Ok ()` is "accepted"; `core.result.Result.Err why` is "refused".
--   - `maps : Slice Map` is the Rust slice; `maps.val` is the list inside it; `e.container_id.val`
--     is the natural number of a field of an entry `e`.
--   - `∀ x, P` is "for every x, P"; `∃ x, P` is "there is an x such that P"; `∧` is "and", `∨`
--     "or", `→` "if ... then", `¬` "not", `↔` "exactly when", `∈` "is an element of".
--   - `l.Pairwise R` is "`R a b` holds for each element `a` and each element `b` after it".
--   - `∀ m, answer = core.result.Result.Ok m → P m` is "if the answer is a mapping `m`, then
--     `P m`" (the other answer, `Err`, says why there is none).
import Extracted.Funs

open Aeneas Aeneas.Std Result velarx_idmap_core

namespace IdmapCore

/-- No mapping may end past this id (`ID_LIMIT`: `u32::MAX` is not a valid id). -/
def IdLimit : Nat := 4294967295

/-- The largest 32 bit number, `u32::MAX`: the largest id (a parent id that a function returns
must be at most this). -/
def U32Max : Nat := 4294967295

/-- The most lines a mapping may have (`MAX_EXTENTS`, what the kernel accepts). -/
def ExtentLimit : Nat := 340

/-- The entry `e` has the container id `c`: `c` is one of the `e.size` ids that begin at
`e.container_id`. -/
def InContainers (e : Map) (c : Nat) : Prop :=
  e.container_id.val ≤ c ∧ c < e.container_id.val + e.size.val

/-- The entry `e` has the parent id `p`: `p` is one of the `e.size` ids that begin at
`e.parent_id`. -/
def InParents (e : Map) (p : Nat) : Prop :=
  e.parent_id.val ≤ p ∧ p < e.parent_id.val + e.size.val

/-- **The one idea of the crate.**  The mapping list `m` maps the container id `c` to the parent
id `p`: some entry of `m` has `c`, and `p` is its parent id plus how far `c` is from its first
container id. -/
def Maps (m : List Map) (c p : Nat) : Prop :=
  ∃ e ∈ m, InContainers e c ∧ p = e.parent_id.val + (c - e.container_id.val)

/-- No container id has two parent ids. -/
def OneParentEach (m : List Map) : Prop :=
  ∀ c p q, Maps m c p → Maps m c q → p = q

/-- No parent id is the image of two container ids. -/
def OneContainerEach (m : List Map) : Prop :=
  ∀ c d p, Maps m c p → Maps m d p → c = d

/-- A function both ways: each container id has at most one parent id and each parent id at most
one container id.  This is what the kernel needs of a `uid_map`, and what keeps two ids of a
container from being the same id outside. -/
def FunctionBothWays (m : List Map) : Prop := OneParentEach m ∧ OneContainerEach m

/-- The entry is not empty and does not end past the limit, in the container ids or in the parent
ids. -/
def Sane (e : Map) : Prop :=
  0 < e.size.val ∧ e.container_id.val + e.size.val ≤ IdLimit ∧
  e.parent_id.val + e.size.val ≤ IdLimit

/-- The two entries have no container id in common and no parent id in common. -/
def Apart (a b : Map) : Prop :=
  (∀ c, ¬ (InContainers a c ∧ InContainers b c)) ∧ (∀ p, ¬ (InParents a p ∧ InParents b p))

/-- A valid list: at most `ExtentLimit` entries, every entry sane, and every two entries apart
(for each entry, those after it in the list). -/
def Valid (m : List Map) : Prop :=
  m.length ≤ ExtentLimit ∧ (∀ e ∈ m, Sane e) ∧ m.Pairwise Apart

/-- **`validate` accepts exactly the valid lists.**  For every list of entries of any length,
`validate` returns, and its answer is `Ok` when the list is `Valid` and a refusal when it is not:
too many entries, an empty entry, an entry that ends past the limit, or two entries that share a
container id or a parent id.  So it refuses nothing it should accept, and accepts nothing it
should refuse.

Not said: which refusal is given when several apply (the first the code finds). -/
def ValidateAcceptsExactlyTheValidLists : Prop :=
  ∀ maps : Slice Map, validate maps ⦃ answer =>
    (answer = core.result.Result.Ok () ↔ Valid maps.val) ⦄

/-- **A valid list is a function both ways.**  For every valid list `m`, no container id has two
parent ids (`OneParentEach`) and no parent id has two container ids (`OneContainerEach`).  With
`ValidateAcceptsExactlyTheValidLists`: what `validate` accepts maps each id one way only.

Not said: that a function both ways is valid (a list may repeat an entry, or have two entries that
agree where they overlap: it is a function both ways, and `validate` refuses it, as the kernel
does). -/
def ValidListsAreFunctionsBothWays : Prop :=
  ∀ m : List Map, Valid m → FunctionBothWays m

/-- The ids of an interval `[start, end)` of an `IdSet` (the interval is a pair of 64 bit numbers:
its first id and the first id past it). -/
def InRun (iv : U64 × U64) (id : Nat) : Prop :=
  iv.1.val ≤ id ∧ id < iv.2.val

/-- Some interval of the list has the id. -/
def HasId (runs : List (U64 × U64)) (id : Nat) : Prop :=
  ∃ iv ∈ runs, InRun iv id

/-- The list of intervals is how an `IdSet` keeps its ids: every interval has an id, and each one
ends before the next one begins (so they are in order, none overlaps another, and none touches
the next).  Every `IdSet` the crate builds is `Ordered`. -/
def Ordered (runs : List (U64 × U64)) : Prop :=
  (∀ iv ∈ runs, iv.1.val < iv.2.val) ∧ runs.Pairwise (fun a b => a.2.val < b.1.val)

/-- Exactly `n` ids satisfy `P`: there are `n` different ids, listed once each, and an id is among
them exactly when it satisfies `P`. -/
def ExactlyIds (P : Nat → Prop) (n : Nat) : Prop :=
  ∃ ids : List Nat, ids.Nodup ∧ (∀ id, id ∈ ids ↔ P id) ∧ ids.length = n

/-- **`IdSet::from_intervals` builds the set of the ids of the intervals.**  For every list of
intervals (empty ones, overlapping ones and ones that touch included), `from_intervals` returns,
and its answer is `Ordered` (so it is a valid `IdSet`), and has an id exactly when some interval
of the list has it.

Not said: how many intervals the answer has (they are joined as far as possible). -/
def FromIntervalsHasTheIdsOfTheIntervals : Prop :=
  ∀ list : Slice (U64 × U64), IdSet.from_intervals list ⦃ s =>
    Ordered s.intervals.val ∧ ∀ id, HasId s.intervals.val id ↔ HasId list.val id ⦄

/-- **`of_parent_ids` is the set of the parent ids of a mapping.**  For every list of entries,
`of_parent_ids` returns an `Ordered` set that has an id exactly when some entry has it as a parent
id (`InParents`).  Without any condition on the entries: an entry that is empty has no id, one
that is too large still has its ids (the sums are in 64 bits). -/
def OfParentIdsHasTheParentIds : Prop :=
  ∀ maps : Slice Map, IdSet.of_parent_ids maps ⦃ s =>
    Ordered s.intervals.val ∧ ∀ id, HasId s.intervals.val id ↔ ∃ e ∈ maps.val, InParents e id ⦄

/-- **`of_container_ids` is the set of the container ids of a mapping.**  The same, for the
container ids (`InContainers`). -/
def OfContainerIdsHasTheContainerIds : Prop :=
  ∀ maps : Slice Map, IdSet.of_container_ids maps ⦃ s =>
    Ordered s.intervals.val ∧ ∀ id, HasId s.intervals.val id ↔ ∃ e ∈ maps.val, InContainers e id ⦄

/-- **`IdSet::size` is the number of ids.**  For every `IdSet` that is `Ordered` (as all that the
crate builds are), `size` returns, without overflow, and exactly that many ids are in the set
(`ExactlyIds`: that many different ids, and no other). -/
def SizeIsTheNumberOfIds : Prop :=
  ∀ s : IdSet, Ordered s.intervals.val →
    IdSet.size s ⦃ n => ExactlyIds (HasId s.intervals.val) n.val ⦄

/-- **`IdSet::union` is the union.**  For every two sets (with fewer than 2^64 intervals together:
more do not fit in the memory of a computer), `union` returns an `Ordered` set that has an id
exactly when one of the two has it.  Whatever the two sets are: it does not need them to be
`Ordered`. -/
def UnionHasTheIdsOfBoth : Prop :=
  ∀ a b : IdSet, a.intervals.val.length + b.intervals.val.length ≤ Usize.max →
    IdSet.union a b ⦃ s =>
      Ordered s.intervals.val ∧
      ∀ id, HasId s.intervals.val id ↔ (HasId a.intervals.val id ∨ HasId b.intervals.val id) ⦄

/-- **`IdSet::is_empty` is true exactly for the empty set.**  For every `Ordered` set, `is_empty`
returns, and answers `true` exactly when no id is in the set. -/
def IsEmptyIsTrueExactlyForTheEmptySet : Prop :=
  ∀ s : IdSet, Ordered s.intervals.val →
    IdSet.is_empty s ⦃ answer => answer = true ↔ ∀ id, ¬ HasId s.intervals.val id ⦄

/-- **`IdSet::contains_range` says whether every id of the range is in the set.**  For every
`Ordered` set, and every `start` and `len`, `contains_range` returns, and answers `true` exactly
when every id from `start` up to (but not with) `start + len` is in the set.  A range with no id
(`len = 0`) is in every set. -/
def ContainsRangeIsTrueExactlyForARangeInTheSet : Prop :=
  ∀ (s : IdSet) (start len : Std.U64), Ordered s.intervals.val →
    IdSet.contains_range s start len ⦃ answer =>
      answer = true ↔ ∀ k, k < len.val → HasId s.intervals.val (start.val + k) ⦄

/-- **`IdSet::subtract` has the ids of the first set that the second does not have.**  For two
`Ordered` sets (whose numbers of intervals are such that the answer fits in the memory of a
computer: the number of intervals of the first, times one more than that of the second, is at most
the largest `usize`), `subtract` returns an `Ordered` set that has an id exactly when the first has
it and the second does not.  On a 64 bit computer the condition leaves out only sets with about
2^32 intervals each or more (two sets of that size are 128 GB of memory), none that a user
namespace has.

Not said: how many intervals the answer has. -/
def SubtractHasTheIdsOfTheFirstNotInTheSecond : Prop :=
  ∀ a b : IdSet, Ordered a.intervals.val → Ordered b.intervals.val →
    a.intervals.val.length * (b.intervals.val.length + 1) ≤ Usize.max →
    IdSet.subtract a b ⦃ s =>
      Ordered s.intervals.val ∧
      ∀ id, HasId s.intervals.val id ↔ (HasId a.intervals.val id ∧ ¬ HasId b.intervals.val id) ⦄

/-- **`IdSet::below` keeps the ids under a limit.**  For every `Ordered` set and every `limit`,
`below` returns an `Ordered` set that has an id exactly when the set has it and it is less than
`limit`. -/
def BelowHasTheIdsUnderTheLimit : Prop :=
  ∀ (s : IdSet) (limit : Std.U64), Ordered s.intervals.val →
    IdSet.below s limit ⦃ r =>
      Ordered r.intervals.val ∧
      ∀ id, HasId r.intervals.val id ↔ (HasId s.intervals.val id ∧ id < limit.val) ⦄

/-- **`IdSet::find_available` takes `n` ids of the set, or says there are fewer.**  For every
`Ordered` set and every `n`, `find_available` returns either an `Ordered` set of exactly `n` ids,
all of them in the set, or nothing, and then the set has fewer than `n` ids.

Not said: which `n` ids it takes (the first ones, in order). -/
def FindAvailableGivesNIdsOrSaysThereAreFewer : Prop :=
  ∀ (s : IdSet) (n : Std.U64), Ordered s.intervals.val →
    IdSet.find_available s n ⦃ answer =>
      match answer with
      | some t => Ordered t.intervals.val ∧
          (∀ id, HasId t.intervals.val id → HasId s.intervals.val id) ∧
          ExactlyIds (HasId t.intervals.val) n.val
      | none => ∃ k, ExactlyIds (HasId s.intervals.val) k ∧ k < n.val ⦄

/-- **`IdSet::zip` pairs the ids of two sets.**  For two `Ordered` sets `a` (the parent ids) and
`b` (the container ids), `zip` returns entries that have ids, end before the limit, and are apart;
each id they map is an id of `a` (parent) or `b` (container), below `IdLimit`; the answer has
at most `IdLimit` entries; and, when the ids of `b` below `IdLimit` are no more than the ids of
`a` below `IdLimit`, every id of `b` below `IdLimit` is mapped (the ids at or past the limit
cannot be in a mapping, and `zip` leaves them out).  In words: if `b` has no more ids below the
limit than `a`, then every id of `b` below the limit gets a parent id.

Not said: which parent id each container id gets (they are paired in order: the lowest with the
lowest). -/
def ZipMapsTheSecondSetOntoTheFirst : Prop :=
  ∀ a b : IdSet, Ordered a.intervals.val → Ordered b.intervals.val →
    IdSet.zip a b ⦃ out =>
      (∀ e ∈ out.val, Sane e) ∧ out.val.Pairwise Apart ∧
      (∀ c p, Maps out.val c p →
        (HasId a.intervals.val p ∧ p < IdLimit) ∧ (HasId b.intervals.val c ∧ c < IdLimit)) ∧
      ((∀ k m, ExactlyIds (fun id => HasId a.intervals.val id ∧ id < IdLimit) k →
          ExactlyIds (fun id => HasId b.intervals.val id ∧ id < IdLimit) m → m ≤ k) →
        ∀ c, HasId b.intervals.val c → c < IdLimit → ∃ p, Maps out.val c p) ∧
      out.val.length ≤ IdLimit ⦄

/-- The highest container id of the sub ids that `keep_id` maps: `sub`, or `size - 1` when `size`
is given, is more than 0 and is less. -/
def KeepIdTop (sub : Std.U32) (size : Option Std.U32) : Nat :=
  match size with
  | none => sub.val
  | some s => if 0 < s.val ∧ s.val - 1 < sub.val then s.val - 1 else sub.val

/-- What `keep_id` is meant to map, as the pairs (container id, parent id): the user `id` to the
parent id 0 (the user of the namespace of the daemon); when there are sub ids (`sub > 0`), the
container ids below the user, up to the top, to the sub ids 1, 2, ... in order; the container ids
above the user, up to the top, to the same parent ids; and nothing else. -/
def KeepIdLayout (id sub : Std.U32) (size : Option Std.U32) (c p : Nat) : Prop :=
  (c = id.val ∧ p = 0) ∨
  (0 < sub.val ∧ c < id.val ∧ c < KeepIdTop sub size ∧ p = c + 1) ∨
  (id.val < c ∧ c ≤ KeepIdTop sub size ∧ p = c)

/-- **`keep_id` maps exactly the layout.**  For every `id`, `sub` and `size`, `keep_id` returns,
and the pairs (container id, parent id) its answer maps are those of `KeepIdLayout`, and no
others: the user `id` is mapped to the parent id 0 (to itself, as the user of the namespace of the
daemon), the container ids below it to the sub ids 1, 2, ... of the user, those above it to the same
parent ids, and the sub ids stop at `sub` (or at `size - 1`).

Not said: that the answer is valid (the next claims, for ids that are below the limit). -/
def KeepIdMapsExactlyTheLayout : Prop :=
  ∀ (id sub : Std.U32) (size : Option Std.U32), keep_id id sub size ⦃ out =>
    ∀ c p, Maps out.val c p ↔ KeepIdLayout id sub size c p ⦄

/-- **`keep_id` uses only the parent ids 0 to `sub`**: 0 is the user of the daemon's namespace and
1 to `sub` are its sub ids, whatever `id` and `size` are. -/
def KeepIdUsesOnlyTheSubIds : Prop :=
  ∀ (id sub : Std.U32) (size : Option Std.U32), keep_id id sub size ⦃ out =>
    ∀ c p, Maps out.val c p → p ≤ sub.val ⦄

/-- **`keep_id` is valid.**  When `id` and `sub` are below the limit (`u32::MAX - 1` at most), the
answer of `keep_id` is `Valid`: no more than three entries, none empty or ending past the limit,
and no two sharing a container id or a parent id.  So `validate` accepts it.

Not said: anything for `id` or `sub` equal to `u32::MAX` (the answer then has an entry that ends
past the limit and `validate` refuses it: neither is an id of a user). -/
def KeepIdIsValid : Prop :=
  ∀ (id sub : Std.U32) (size : Option Std.U32), id.val < IdLimit → sub.val < IdLimit →
    keep_id id sub size ⦃ out => Valid out.val ⦄

/-- Where the container id `start` of the entry `e` goes: the parent id of the entry plus how far
`start` is from its first container id. -/
def ParentOf (e : Map) (start : Nat) : Nat :=
  e.parent_id.val + (start - e.container_id.val)

/-- **`range_to_parent` answers only for a range in one entry, and the answer is right.**  For
every list of entries (valid or not), every `start` and `len`, `range_to_parent` returns, and when
it answers `q`, some entry of the list has the container id `start`, has the whole range
(`start + len` is at most where the entry ends), and `q` is its parent id for `start`
(`ParentOf`); and every id of the range, `start + k` for `k` below `len`, is mapped by the list
to the corresponding parent id `q + k`.

Not said: that it answers when it can (the next claim, for a valid list). -/
def RangeToParentAnswersForARangeInOneEntry : Prop :=
  ∀ (maps : Slice Map) (start len : Std.U32), range_to_parent maps start len ⦃ r =>
    ∀ q, r = some q → ∃ e ∈ maps.val, InContainers e start.val ∧
      start.val + len.val ≤ e.container_id.val + e.size.val ∧ q.val = ParentOf e start.val ∧
      ∀ k, k < len.val → Maps maps.val (start.val + k) (q.val + k) ⦄

/-- **`range_to_parent` answers when the range is in one entry.**  For every valid list, and every
entry that has the container id `start` and the whole range, `range_to_parent` returns, and its
answer is the parent id of the entry for `start`.  With the previous claim: for a valid list, it
answers exactly when the whole range is in one entry, and then correctly.  (When the range goes on
into the next entry, even one that continues the first, it does not answer: nothing above says
what the next entry gives.) -/
def RangeToParentAnswersWhenTheRangeIsInOneEntry : Prop :=
  ∀ (maps : Slice Map) (start len : Std.U32), Valid maps.val →
    ∀ e ∈ maps.val, InContainers e start.val →
      start.val + len.val ≤ e.container_id.val + e.size.val →
      range_to_parent maps start len ⦃ r =>
        ∃ q, r = some q ∧ q.val = ParentOf e start.val ⦄

/-- **`sort_and_merge` maps exactly what its input maps.**  For every list of entries (valid or
not, of any length), `sort_and_merge` returns, and a container id is mapped to a parent id by the
answer exactly when it is by the input.  It puts the entries in order of container id and joins
those that follow each other, and that changes nothing of what is mapped, even for entries that
overlap or have no ids.

Not said: that the answer is in order, or has fewer entries (the order is how it joins entries;
only what is mapped is claimed). -/
def SortAndMergeKeepsThePairs : Prop :=
  ∀ maps : Slice Map, sort_and_merge maps ⦃ out =>
    ∀ c p, Maps out.val c p ↔ Maps maps.val c p ⦄

/-- **`sort_and_merge` keeps entries sane and apart.**  When the entries it is given all have ids
and end before the limit (`Sane`) and no two share a container id or a parent id (`Apart`), so do
the entries it returns.  With the previous claim: a mapping that `validate` would accept in
these two ways is still so after `sort_and_merge`.

Not said: anything about the number of entries (`ExtentLimit`); `auto_map` checks it itself. -/
def SortAndMergeKeepsSaneApartEntries : Prop :=
  ∀ maps : Slice Map, sort_and_merge maps ⦃ out =>
    (∀ e ∈ maps.val, Sane e) → maps.val.Pairwise Apart →
      (∀ e ∈ out.val, Sane e) ∧ out.val.Pairwise Apart ⦄

/-- What the claims about `fill` ask of what the caller gives: `available` is a set as `IdSet`
makes it (`Ordered`), the mapping has at most `ExtentLimit` entries (as any mapping), and the
computer has 64 bit addresses (as for `AutoMapInputsFit`). -/
def FillInputsFit (idmap : Slice Map) (available : IdSet) : Prop :=
  Ordered available.intervals.val ∧ idmap.val.length ≤ ExtentLimit ∧ 4294967636 ≤ Usize.max

/-- **`fill` keeps what the mapping maps.**  For every mapping `idmap` and set `available`
(`FillInputsFit`), `fill` returns, and every pair (container id, parent id) that `idmap` maps is
mapped by the answer. -/
def FillKeepsWhatTheMappingMaps : Prop :=
  ∀ (idmap : Slice Map) (available : IdSet), FillInputsFit idmap available →
    fill idmap available ⦃ out => ∀ c p, Maps idmap.val c p → Maps out.val c p ⦄

/-- **`fill` adds only free container ids, with ids of `available`.**  Every pair that the answer
maps is one of `idmap`, or has a container id below `IdLimit` that no entry of `idmap` has and a
parent id that is in `available` (and below `IdLimit`).

Not said: that the added parent ids are not parent ids of `idmap` (the caller takes them out of
`available`), or that the answer is valid for that reason. -/
def FillAddsOnlyFreeContainerIds : Prop :=
  ∀ (idmap : Slice Map) (available : IdSet), FillInputsFit idmap available →
    fill idmap available ⦃ out =>
      ∀ c p, Maps out.val c p → Maps idmap.val c p ∨
        (c < IdLimit ∧ (∀ e ∈ idmap.val, ¬ InContainers e c) ∧
          HasId available.intervals.val p ∧ p < IdLimit) ⦄

/-- **`fill` maps every free container id when `available` has enough ids.**  When the ids of
`available` below `IdLimit` are at least as many as the container ids below `IdLimit` that `idmap`
does not map, every such container id is mapped by the answer. -/
def FillMapsEveryFreeContainerIdWhenThereAreEnoughIds : Prop :=
  ∀ (idmap : Slice Map) (available : IdSet), FillInputsFit idmap available →
    fill idmap available ⦃ out =>
      (∀ k m, ExactlyIds (fun p => HasId available.intervals.val p ∧ p < IdLimit) k →
          ExactlyIds (fun c => c < IdLimit ∧ ∀ e ∈ idmap.val, ¬ InContainers e c) m → m ≤ k) →
        ∀ c, c < IdLimit → (∀ e ∈ idmap.val, ¬ InContainers e c) → ∃ p, Maps out.val c p ⦄

/-- What the claims about `auto_map` ask of the sets the caller gives, in plain words: `pool`
(the ids of the user) and `used` (the ids other containers use) are sets as `IdSet` makes them
(`Ordered`); the computer has 64 bit addresses (a list of 2^32 entries fits in its memory); and
the sets do not have so many intervals that the work of `auto_map` on them would not fit in the
memory of a computer (`auto_map` cuts `pool` by `used`, and the result by the extra mappings, which
are at most 340: the number of intervals of `pool` times one more than that of `used`, times 341,
is at most the largest `usize`).  On a 64 bit computer this leaves out only sets with about
2^28 intervals each or more; the pool is the lines of the user's subuid file and `used` is the
ranges of the other containers: some tens to some thousands, not hundreds of millions. -/
def AutoMapInputsFit (pool used : IdSet) : Prop :=
  Ordered pool.intervals.val ∧ Ordered used.intervals.val ∧
  pool.intervals.val.length * (used.intervals.val.length + 1) * 341 ≤ Usize.max ∧
  4294967636 ≤ Usize.max

/-- **`auto_map` answers with a valid mapping.**  For the container ids `[0, size)`, any `pool`,
`used` and `extra` mappings (the ones the user asked for), when `auto_map` answers with a mapping
`m`, `m` is `Valid`: no two entries share a container id or a parent id, none is empty or ends
past the limit, and there are at most `ExtentLimit` of them.  So `validate` accepts it.

Not said: that it answers (see the others). -/
def AutoMapIsValid : Prop :=
  ∀ (size : Std.U32) (pool used : IdSet) (extra : Slice Map), AutoMapInputsFit pool used →
    auto_map size pool used extra ⦃ answer =>
      ∀ m, answer = core.result.Result.Ok m → Valid m.val ⦄

/-- **`auto_map` takes only parent ids that are free or asked for.**  When `auto_map` answers with
a mapping `m`, every parent id that `m` maps a container id to is either a parent id of one of the
`extra` mappings (the user asked for it), or is an id of the `pool` that is not in `used`.  So no
container gets a host id that another container uses, and none gets an id the user does not own
(if `pool` is the ids of the user), unless the user asked for it in `extra`.  With
`AutoMapIsValid`, no two containers of this namespace share a host id either.

Not said: that `used` holds all the ids that others use, or that `pool` is the user's: those are
what the caller gives; which of the free ids are taken (the lowest ones, in order). -/
def AutoMapUsesOnlyFreeParentIds : Prop :=
  ∀ (size : Std.U32) (pool used : IdSet) (extra : Slice Map), AutoMapInputsFit pool used →
    auto_map size pool used extra ⦃ answer =>
      ∀ m, answer = core.result.Result.Ok m → ∀ c p, Maps m.val c p →
        (∃ e ∈ extra.val, InParents e p) ∨
          (HasId pool.intervals.val p ∧ ¬ HasId used.intervals.val p) ⦄

/-- **`auto_map` maps the container ids asked for, and no other.**  When `auto_map` answers with a
mapping `m`, the container ids that `m` maps are those below `size` and those of the `extra`
mappings, and every container id below `size` is mapped.

Not said: where to (the previous claim). -/
def AutoMapMapsTheContainerIdsAsked : Prop :=
  ∀ (size : Std.U32) (pool used : IdSet) (extra : Slice Map), AutoMapInputsFit pool used →
    auto_map size pool used extra ⦃ answer =>
      ∀ m, answer = core.result.Result.Ok m →
        (∀ c p, Maps m.val c p → c < size.val ∨ ∃ e ∈ extra.val, InContainers e c) ∧
        (∀ c, c < size.val → ∃ p, Maps m.val c p) ⦄

/-- **`auto_map` keeps the extra mappings.**  When `auto_map` answers with a mapping `m`, every
pair (container id, parent id) that the `extra` mappings map is mapped by `m` too: the user's own
mappings are as the user asked, even when they use a parent id that `used` has (the user asked for
it).

Not said: that `extra` is a mapping (when it is not `auto_map` refuses it, which is not claimed
here). -/
def AutoMapKeepsTheExtraMappings : Prop :=
  ∀ (size : Std.U32) (pool used : IdSet) (extra : Slice Map), AutoMapInputsFit pool used →
    auto_map size pool used extra ⦃ answer =>
      ∀ m, answer = core.result.Result.Ok m →
        ∀ c p, Maps extra.val c p → Maps m.val c p ⦄

/-- **`auto_map` keeps the automatic part apart from the extra mappings.**  When `auto_map` answers
with a mapping `m`, every pair (container id, parent id) that `m` maps is either a pair of the
`extra` mappings, or its container id is below `size` and not a container id of an extra mapping,
and its parent id is a free id of the pool (in `pool`, not in `used`) that is not a parent id of an
extra mapping either.  So the part that `auto_map` chooses never uses a parent id of the extra
mappings, and the container ids at or above `size` are mapped only by the extra mappings.

Not said: which free ids it chooses (the previous claims). -/
def AutoMapKeepsTheAutomaticPartApartFromTheExtraMappings : Prop :=
  ∀ (size : Std.U32) (pool used : IdSet) (extra : Slice Map), AutoMapInputsFit pool used →
    auto_map size pool used extra ⦃ answer =>
      ∀ m, answer = core.result.Result.Ok m → ∀ c p, Maps m.val c p → Maps extra.val c p ∨
        (c < size.val ∧ (∀ e ∈ extra.val, ¬ InContainers e c) ∧
          (∀ e ∈ extra.val, ¬ InParents e p) ∧
          HasId pool.intervals.val p ∧ ¬ HasId used.intervals.val p) ⦄

/-- An id of the pool that `auto_map` may take when there are no extra mappings: it is in the
`pool`, below `IdLimit`, and not in `used`. -/
def FreeInPool (pool used : List (U64 × U64)) (id : Nat) : Prop :=
  HasId pool id ∧ id < IdLimit ∧ ¬ HasId used id

/-- The free ids of the pool begin with a run of `size` ids: there is an id `first` such that
`first`, `first + 1`, ..., `first + size - 1` are all free, and no free id is below `first`.  (A
pool nobody has used yet is so, and so is a pool whose lowest free interval is `size` ids wide.) -/
def FreeIdsBeginWithARunOf (size : Nat) (pool used : List (U64 × U64)) : Prop :=
  ∃ first, (∀ k, k < size → FreeInPool pool used (first + k)) ∧
    ∀ id, id < first → ¬ FreeInPool pool used id

/-- **`auto_map` answers with a mapping when the free ids begin with a run.**  When there are no
`extra` mappings and the free ids of the pool begin with a run of `size` ids
(`FreeIdsBeginWithARunOf`), `auto_map` returns, and its answer is a mapping, not a refusal.  The
claims above then say what that mapping is: valid, with the container ids below `size` each mapped,
and parent ids that are free.

Not said: anything for `extra` that is not empty, or for free ids that begin with fewer than `size`
ids in a run (the answer may then be a refusal, for a reason of `AutoMapRefusedForAReason`, or a
mapping); how many entries the mapping has (the proof only shows that there are at most 340). -/
def AutoMapAnswersWhenTheFreeIdsBeginWithARun : Prop :=
  ∀ (size : Std.U32) (pool used : IdSet) (extra : Slice Map), AutoMapInputsFit pool used →
    extra.val = [] → FreeIdsBeginWithARunOf size.val pool.intervals.val used.intervals.val →
    auto_map size pool used extra ⦃ answer => ∃ m, answer = core.result.Result.Ok m ⦄

/-- Why `auto_map` refused (the answer `answer` is one of its three refusals), as the facts that
are true then, for the container ids `[0, size)`, the user's `pool`, the ids `used` and the
`extra` mappings:
- `Invalid`: your `extra` mappings break a rule of `validate` (they are not `Valid`);
- `NoSpace n`: `n` container ids still need a parent id (those below `size` that the extra
  mappings do not map) and the pool has fewer free ids, `k` (those of the pool below `IdLimit`
  that are not in `used` and not parent ids of the extra mappings);
- `TooMany n`: there are enough ids (as many free ids as container ids to map), but they are
  scattered so that the mapping needs `n` entries, more than `ExtentLimit` (340).

In the last two the `extra` mappings are `Valid`.  Not said: which of the refusals is given when
more than one applies (the first the code finds: `Invalid`, then `NoSpace`, then `TooMany`). -/
def AutoMapRefusedForAReason (size : Nat) (pool used : List (U64 × U64)) (extra : List Map)
    (answer : core.result.Result (alloc.vec.Vec Map) AutoFault) : Prop :=
  (∀ f, answer = core.result.Result.Err (AutoFault.Invalid f) → ¬ Valid extra) ∧
  (∀ n, answer = core.result.Result.Err (AutoFault.NoSpace n) → Valid extra ∧
    ∃ k, ExactlyIds (fun p => HasId pool p ∧ p < IdLimit ∧ ¬ HasId used p ∧
        ¬ ∃ e ∈ extra, InParents e p) k ∧ k < n.val ∧
      ExactlyIds (fun c => c < size ∧ ¬ ∃ e ∈ extra, InContainers e c) n.val) ∧
  (∀ n, answer = core.result.Result.Err (AutoFault.TooMany n) → Valid extra ∧ ExtentLimit < n.val ∧
    ∃ k w, ExactlyIds (fun p => HasId pool p ∧ p < IdLimit ∧ ¬ HasId used p ∧
        ¬ ∃ e ∈ extra, InParents e p) k ∧
      ExactlyIds (fun c => c < size ∧ ¬ ∃ e ∈ extra, InContainers e c) w ∧ w ≤ k)

/-- **`auto_map` refuses only for a reason.**  Whatever the `extra` mappings, `pool` and `used`
(see `AutoMapInputsFit`), `auto_map` returns, and when it refuses the reason is true
(`AutoMapRefusedForAReason`): the extra mappings are not a mapping, or the pool has fewer free ids
than there are container ids to map, or the mapping would have more than `ExtentLimit` entries.
This says what the refusals mean; that `auto_map` does answer with a mapping is the claim
`AutoMapAnswersWhenTheFreeIdsBeginWithARun`, and only for the case that one covers.

Not said: that the free ids of the pool are counted from `used` as it should be (the caller's);
nor that it never needs more than `ExtentLimit` entries when it could do with fewer by taking other
free ids (it takes the lowest ones, and the pieces they make are what they are). -/
def AutoMapRefusesOnlyForAReason : Prop :=
  ∀ (size : Std.U32) (pool used : IdSet) (extra : Slice Map), AutoMapInputsFit pool used →
    auto_map size pool used extra ⦃ answer =>
      AutoMapRefusedForAReason size.val pool.intervals.val used.intervals.val extra.val answer ⦄

/-- What the claim about `split_on` asks of what the caller gives: the mapping has at most
`ExtentLimit` entries (as any mapping), and the computer has 64 bit addresses: the pieces
`split_on` writes (at most 2^32 for each entry) fit in its memory. -/
def SplitOnInputsFit (maps : Slice Map) : Prop :=
  maps.val.length ≤ ExtentLimit ∧ 340 * 4294967296 ≤ Usize.max

/-- **`split_on` keeps the pairs.**  For every mapping `maps` (`SplitOnInputsFit`) and every
`parent` mapping, `split_on` returns, and a container id is mapped to a parent id by its answer
exactly when it is by `maps`.  It cuts the entries where the extents of `parent` end, and that
changes nothing of what is mapped; an entry that ends past the limit is passed on as it is, and
an empty one is dropped.  This is the function that the shell calls on the answer of `auto_map` and of `keep_id`
before it writes the `uid_map` of a rootless container, so the map written maps the pairs that the
claims about those two describe.

Not said: where it cuts (that no entry of the answer has parent ids in two extents of `parent`);
that the answer is `Valid` (cutting can give more than `ExtentLimit` entries, which the kernel
would refuse); the order of the entries. -/
def SplitOnKeepsThePairs : Prop :=
  ∀ maps parent : Slice Map, SplitOnInputsFit maps →
    split_on maps parent ⦃ out => ∀ c p, Maps out.val c p ↔ Maps maps.val c p ⦄

/-- All the ids of the entry end at 2^32 at most (one past the largest id), in the container ids
and in the parent ids: what `fits` in lib.rs tests.  An entry that does not (the kernel would
refuse it, `validate` does) is not cut by `break_insert`. -/
def EndsIn32Bits (e : Map) : Prop :=
  e.container_id.val + e.size.val ≤ 4294967296 ∧ e.parent_id.val + e.size.val ≤ 4294967296

/-- What the claims about `break_insert` ask of what the caller gives: the answer has at most three
entries for each entry of `mapping` (an entry is cut into three pieces at most) and the one
inserted, and that many entries fit in the memory of the computer. -/
def BreakInsertInputsFit (mapping : Slice Map) : Prop :=
  3 * mapping.val.length + 1 ≤ Usize.max

/-- **`break_insert` maps the inserted entry and what it does not touch.**  For every `mapping`
(`BreakInsertInputsFit`) and every entry `ext`, `break_insert` returns, and the answer maps a
container id `c` to a parent id `p` exactly when
  - `ext` does (`c` and `p` are a pair of the inserted entry), or
  - an entry `e` of `mapping` does, and either `e` is not `EndsIn32Bits` (it is kept as it is) or
    `c` is not a container id of `ext` and `p` is not a parent id of `ext`.
So the pairs of the old mapping that the answer loses are those with a container id of `ext` or
with a parent id of `ext`: the container id would be mapped twice, or the parent id would.  The
shell does this when the user asks for a mapping with `+` (`--uidmap=+...`: the new one takes
the ids it names from the existing ones, as podman's `breakInsert` does).

Example: `mapping` is one entry, the container ids 0 to 19 to the parent ids 100 to 119, and `ext`
maps the container ids 10 and 11 to the parent ids 105 and 106.  The old container ids 10 and 11
and the old parent ids 105 and 106 (of the container ids 5 and 6) are taken by `ext`, so the old
entry is broken in three: the container ids 0 to 4 (parent ids 100 to 104), 7 to 9 (parent ids 107
to 109) and 12 to 19 (parent ids 112 to 119); then comes `ext`.

Not said: the order of the entries (the inserted one is the last: `rules.rs` tests it); how many
entries the answer has (up to three for each entry of `mapping`, possibly more than
`ExtentLimit`); that the entries of the answer are joined (`sort_and_merge` does it, in the shell,
and keeps the pairs: `SortAndMergeKeepsThePairs`). -/
def BreakInsertMapsTheNewAndWhatItDoesNotTouch : Prop :=
  ∀ (mapping : Slice Map) (ext : Map), BreakInsertInputsFit mapping →
    break_insert mapping ext ⦃ out => ∀ c p, Maps out.val c p ↔ Maps [ext] c p ∨
      ∃ e ∈ mapping.val, Maps [e] c p ∧
        (EndsIn32Bits e → ¬ InContainers ext c ∧ ¬ InParents ext p) ⦄

/-- **`break_insert` keeps a function both ways.**  For every `mapping` that is `Valid` (so that
every entry is `EndsIn32Bits`) and every entry `ext`, `break_insert` returns, and its answer maps
no container id to two parent ids and no parent id from two container ids: this is why the shell
breaks the old entries instead of adding `ext` to them, where the ids of `ext` would be given
twice.  `FunctionBothWays` only depends on what the list maps, so it holds as well after the
`sort_and_merge` that the shell calls on the answer (`SortAndMergeKeepsThePairs`).

Not said: that `ext` is sane (an empty entry maps nothing, one past the limit is a function by
itself and breaks the entries it overlaps all the same); that the answer is `Valid` (it may have
more than `ExtentLimit` entries); anything when `mapping` is not `Valid` (the shell calls
`break_insert` again on its own answer, which is `Valid` only if it has at most `ExtentLimit`
entries; what it maps, for any mapping, is the claim before). -/
def BreakInsertKeepsAFunctionBothWays : Prop :=
  ∀ (mapping : Slice Map) (ext : Map), BreakInsertInputsFit mapping → Valid mapping.val →
    break_insert mapping ext ⦃ out => FunctionBothWays out.val ⦄

end IdmapCore
