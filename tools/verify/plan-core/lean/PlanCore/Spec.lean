-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: what is proved of crates/plan-core, the planning of
-- a lazy pull (which files are fetched, in which groups, and which layers
-- wait for each group), in words and in statements, with no proof.  This
-- file is what a reviewer reads (the crate needs no model of the standard
-- library); Lean checks the rest
-- (the proofs are in Tables.lean, Add.lean, Planned.lean, Loops.lean, Waits.lean and
-- Claims.lean).
--
-- Why it is needed: a proof is worth what its statement says.  Each
-- statement here is a `def ... : Prop`: a claim, which `Theorems.lean`
-- asks Lean to prove.  Each has a comment of what it claims and of what it
-- does NOT.  The claims are rules P1, P2 and P3 of src/rules.rs, the rules
-- the walk of the crate (src/walk.rs) checks on 100 million small plans,
-- clause by clause: the same words, here for EVERY plan.  The small
-- definitions before the claims (`Has`, `Lacks`, `Home`, `listed`, `Fits`)
-- are their vocabulary.
--
-- Together with the claim of lazy-core that a layer is committed only after
-- every group it waits for was fetched, P1 and P2 give "a layer is committed
-- only after every file it lacked was fetched", PROVIDED the following, none
-- of which is proved here or in lazy-core:
--   (a) the shell maps the plan to the state machine (the layer numbers and
--       the `needed_by` of each group, in the completer `prepared` of
--       crates/core); the plan and that code use the same list of layers, with
--       repeated keys dropped;
--   (b) lazy-core keeps a group only for the layers that are new to it: a
--       layer another pull already holds relies on that pull's plan, made from
--       an older snapshot of the stores;
--   (c) which groups lazy-core lets go of is not proved;
--   (d) "fetched" is what the caller answered: that a fetch moved every file
--       of the group is not proved;
--   (e) "lacked" is: an entry with content that neither the store nor the
--       staging had at the one moment the plan looked (`present`);
--   (f) lazy-core claims that the step returns only for short tables (`Short`,
--       `Roomy`) on a 64-bit machine;
--   (g) the layer a group is fetched INTO (`layer`, P3) is not something the
--       state machine is told.
-- P3 is not used by that composition: it is what excludes a file planned into
-- another layer's group (the earlier bug: that layer was then committed without
-- the file).
--
-- The rules of src/rules.rs, word for word: P1 is the rule.  P2 says `Lacks`
-- where the rule says "has a file of the group": the same, by P1 (every file of
-- a group is lacked).  P3's `Home` is the rule plus "not present", so it is
-- stronger.  The rule "a group is not empty" has no statement of its own: it
-- follows from P2 (`needed_by` is not empty, and a layer is in it only for a
-- file of the group).
--
-- Not proved here: P4 (a group is cut by the limits and `bytes` is the
-- saturating sum of the sizes) and P5 (the profile comes first, in its
-- order, then the tables in order): the walk checks them, and the files of
-- a group are an order and a size the fetch uses, never what a layer waits
-- for.  Nothing is said of the shell, `plan_groups` of velarx-core, that
-- numbers the contents, reads the tables and asks the stores for `present`:
-- the claims are about the numbers it gives.  That two runs plan the same
-- holds because `plan` is a function in the translation: it rests on the
-- translation, not on a claim here.
--
-- Total correctness: each claim says that `plan` RETURNS (no panic, no
-- index outside a table, no overflow, the loops end) on every input that
-- satisfies `Fits`, and that its answer is as stated.  `Fits` is kept
-- by the shell for an image of fewer than 2^32 contents and layers: a content
-- is below the number of contents, and the number of layers is a `u32`.
--
-- Read before this file: lib.rs and rules.rs of crates/plan-core.
--
-- Index.  What each claim is about, what is trusted and what is
-- not claimed, in one place.
--
--   Claimed (each for every input that `Fits`; `plan` returns, and):
--     EveryLackedContentIsPlannedOnce    P1: a content a layer lacks is in exactly one group,
--                                        nothing else is planned
--     AGroupIsWaitedForByWhoLacksItsFiles  P2: `needed_by` is exactly the layers that lack a
--                                        file of the group, ascending, once each, never empty
--     AGroupIsFetchedIntoTheHomeOfItsFiles P3: the layer of a group is the first that has each
--                                        of its files
--
--   Trusted: Charon and Aeneas (../../pins) and the models of the standard
--   library Aeneas itself has (`Vec` and slice indexing, `push`, the integer
--   operations, `saturating_add`, `Option::is_none`); no model is written by hand.
--
--   Not claimed: P4, P5 and the shell (above); that the groups come in a good
--   order for the fetch; that two runs plan the same (the code iterates no hash table).
--
-- Notation:
--   - `plan x ⦃ r => P r ⦄` reads: the Rust function `plan`, given `x`, returns (it
--     does not panic, it does not loop for ever) and the result `r` satisfies `P r`.
--   - `∀ x, P` is "for every x, P"; `∃ x, P` is "there is an x such that P"; `∧` is "and",
--     `∨` is "or", `→` is "if ... then", `↔` is "exactly when", `¬` is "not",
--     `∈` is "is an element of".
--   - `v.val` is the list inside a vector or a slice; `v.length` its length;
--     `v.val[l]? = some x` is "the element `l` of the list is `x`"; `l.count c` is the number
--     of times `c` is in the list `l`; `l.Pairwise (· < ·)` is "each element is below
--     all that follow it" (a strictly ascending list: nothing twice); `x.val` is the number a
--     machine integer is.
import Extracted.Funs

open Aeneas Aeneas.Std Result velarx_plan_core

namespace PlanCore

/-- Layer `l` has a file with content `c`: the file is in its table, whatever its
size.  Layers are counted from 0 as in the slice `layers` of `plan`. -/
def Has (layers : Slice (alloc.vec.Vec File)) (l : Nat) (c : Std.U32) : Prop :=
  ∃ table, layers.val[l]? = some table ∧ ∃ file ∈ table.val, file.content = c

/-- Layer `l` lacks content `c`: it has a file with that content and the stores do
not (`present` says, for each content, whether the stores hold it).  This is a
file the pull has to fetch before it commits the layer. -/
def Lacks (layers : Slice (alloc.vec.Vec File)) (present : Slice Bool) (l : Nat)
    (c : Std.U32) : Prop :=
  Has layers l c ∧ present.val[c.val]? = some false

/-- Layer `l` is the home of content `c`: it lacks it and no layer before it has
it.  A content is fetched once, for its home, and the other layers that have it
wait for that fetch. -/
def Home (layers : Slice (alloc.vec.Vec File)) (present : Slice Bool) (l : Nat)
    (c : Std.U32) : Prop :=
  Lacks layers present l c ∧ ∀ k < l, ¬ Has layers k c

/-- The contents of the files of all the groups, one after the other (a content that
is in two groups, or twice in one, is in the list twice). -/
def listed (groups : alloc.vec.Vec Group) : List Std.U32 :=
  groups.val.flatMap (fun group => group.files.val)

/-- The input `plan` is made for: there are at most `u32` layers, and every content
the tables and the profile name is below the number of contents (`present` has
an entry for each).  The shell keeps this for an image of fewer than 2^32 contents and layers. -/
def Fits (layers : Slice (alloc.vec.Vec File)) (present : Slice Bool)
    (profile : Slice Std.U32) : Prop :=
  layers.length ≤ Std.U32.max ∧
  (∀ table ∈ layers.val, ∀ file ∈ table.val, file.content.val < present.length) ∧
  ∀ c ∈ profile.val, c.val < present.length

/-- **Every content a layer lacks is in exactly one group, and nothing else is
planned** (rule P1).  `plan` returns, and in its groups
- each content that some layer lacks is listed exactly once: in one file of one
  group, so one group fetches it;
- every content listed is lacked by some layer: a content that is present in the stores,
  or that no layer has (a profile may name one), is not planned.

Not said: in which group or in which layer (P3 and the layer a content is fetched
into), or in which order (P5, which the walk checks). -/
def EveryLackedContentIsPlannedOnce : Prop :=
  ∀ (layers : Slice (alloc.vec.Vec File)) (present : Slice Bool)
    (profile : Slice Std.U32) (limits : Limits),
    Fits layers present profile →
    plan layers present profile limits ⦃ groups =>
      (∀ l c, Lacks layers present l c → (listed groups).count c = 1) ∧
      (∀ c ∈ listed groups, ∃ l, Lacks layers present l c) ⦄

/-- **A group is waited for by the layers that lack one of its files** (rule P2).
`plan` returns, and for each group it answers, the list `needed_by`:
- is not empty;
- is strictly ascending, so no layer is in it twice;
- has a layer exactly when that layer lacks a file of the group (the file is in the
  group's list `files`, which may be fetched for another layer: the home of the content).

The walk's rule P2 says "has a file of the group": the same, since every file of
a group is lacked (P1).

Not said: the order of the groups, when each is fetched (the business of
lazy-core), the bytes or the limits. -/
def AGroupIsWaitedForByWhoLacksItsFiles : Prop :=
  ∀ (layers : Slice (alloc.vec.Vec File)) (present : Slice Bool)
    (profile : Slice Std.U32) (limits : Limits),
    Fits layers present profile →
    plan layers present profile limits ⦃ groups =>
      ∀ group ∈ groups.val,
        group.needed_by.val ≠ [] ∧
        (group.needed_by.val.map (·.val)).Pairwise (· < ·) ∧
        ∀ l, l ∈ group.needed_by.val.map (·.val) ↔
          ∃ c ∈ group.files.val, Lacks layers present l c ⦄

/-- **A group is fetched into the home of each of its files** (rule P3).  `plan`
returns, and for each group it answers, each file of the group has the group's
`layer` as its home: that layer lacks the content and no layer before it has it.
This excludes the earlier bug: a file planned into another layer's group, so
that layer was committed without it.

Not said: that a layer's groups are all it waits for (P2 gives that); the
order of the files in the group, or how many there are (P4, P5). -/
def AGroupIsFetchedIntoTheHomeOfItsFiles : Prop :=
  ∀ (layers : Slice (alloc.vec.Vec File)) (present : Slice Bool)
    (profile : Slice Std.U32) (limits : Limits),
    Fits layers present profile →
    plan layers present profile limits ⦃ groups =>
      ∀ group ∈ groups.val, ∀ c ∈ group.files.val,
        Home layers present group.layer.val c ⦄

end PlanCore
