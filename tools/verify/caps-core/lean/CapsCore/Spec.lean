-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: what is proved of crates/caps-core, the capability sets of a
-- container process (`sets`: from what a request asks and what the engine can give, the five
-- sets of the process, or a refusal), in words and in statements, with no proof.  This file is
-- what a reviewer reads; Lean checks the rest (the proofs are in Bits.lean, Answer.lean and
-- Claims.lean).
--
-- Why it is needed: the walk of the crate (src/walk.rs) checks the rules of src/rules.rs on
-- every request of a world of FOUR capabilities.  The real masks have 64 bits.  Each claim
-- below is a rule of rules.rs, for EVERY request, over all 64 bits.  A proof is worth what
-- its statement says, so each claim has a comment of what it claims and of what it does NOT.
--
-- Total correctness: each claim says that `sets` RETURNS, whatever the request (there is no
-- panic, no overflow: the code is a few bit operations and no division, loop or index), and
-- that its answer is as stated.  No claim assumes anything of the request beyond the one
-- each names (for example "not privileged"): every combination of the nine fields is covered.
--
-- Upper and lower bounds: "no set has more than ..." alone is satisfied by a `sets` that
-- always answers with empty sets.  So the claims come in two kinds: what no set may have
-- (NoSetBeyondTheEngine, NothingDroppedIsGiven, NothingComesFromNowhere) and what each set
-- DOES have (TheBoundingSetHasWhatWasAsked, AllGivesTheEngineMinusDrop, WhatEachSetIs,
-- WhatAPrivilegedContainerHas).
--
-- Read before this file: lib.rs and rules.rs of crates/caps-core.
--
-- Index.  What each claim is about, what is trusted and what is not claimed:
--
--   Claimed (each for every request; `sets` returns, and):
--     SetsNeverPanics                   the function returns, always (no condition)
--     NoSetBeyondTheEngine              every set of an answer is within the engine's bounding set
--     NothingDroppedIsGiven             not privileged: no dropped capability is in any set
--     NothingComesFromNowhere           not privileged, no `all`: each capability of each set
--                                       was a default, was added, or is ambient
--     TheBoundingSetHasWhatWasAsked     the bounding set has the defaults the engine has, what was
--                                       added and the ambient capabilities, but the dropped ones
--     AllGivesTheEngineMinusDrop        not privileged, with `all`: the bounding set is the
--                                       engine's minus `drop`, and no set has more
--     WhatEachSetIs                     for every answer: exactly what root and what another user
--                                       have in each set (`--privileged` and `drop` included)
--     TheSetsFitTogether                ambient within permitted and inheritable, effective within
--                                       permitted (the kernel); inheritable within permitted,
--                                       permitted within bounding (the code)
--     WhatAPrivilegedContainerHas       privileged: the same as numbers, with no `drop`
--     ARequestIsRefusedExactlyWhen      a refusal happens exactly when one of the three
--                                       conditions of the code holds
--     TheRefusalSaysWhy                 which refusal, with which capabilities named
--
--   Trusted: Charon and Aeneas (../../pins) and the models of the standard library Aeneas
--   itself has (the integer operations on `u64`); no model is written by hand.
--
--   Not claimed (the claims are about the sets as numbers): the conversion of capability
--   names to bits, and of the word `all` to a flag (the shell does both); the conversion of
--   the CRI request to a `Request`; that the bounding set of the engine is read correctly
--   from the machine; that the defaults are the right ones; that the user is root when
--   `root` says so; what the runtime and the kernel do with the sets; the meaning of the
--   bits above the last capability of the kernel (41 to 63): the sets are masks of 64 bits
--   and these are treated as any other; how the OCI types are built from the sets.
--
-- Notation:
--   - `sets r ⦃ answer => P answer ⦄` reads: the Rust function `sets`, given `r`, returns (it
--     does not panic) and its answer satisfies `P answer`.
--   - A set of capabilities is a `u64` `s`; `Has s i` says bit `i` of `s` is 1, that is,
--     capability `i` is in the set.
--   - `∀ x, P` is "for every x, P"; `∃ x, P` is "there is an x such that P"; `∧` is "and",
--     `∨` is "or", `→` is "if ... then", `↔` is "exactly when", `¬` is "not".
--   - `r.add`, `s.permitted` are the field `add` of the request `r` and the field `permitted`
--     of the sets `s`.  `Ok s` and `Err e` are the two answers: sets, or a refusal.
import Extracted.Funs

open Aeneas Aeneas.Std Result velarx_caps_core

namespace CapsCore

/-- Capability `i` is in the set `s`: bit `i` of the `u64` is 1 (bit 0 is the lowest). -/
def Has (s : Std.U64) (i : Fin 64) : Prop :=
  s.bv[i] = true

/-- Every capability of `a` is in `b`: `a` is a part of `b` (`a` may be equal to `b`). -/
def Within (a b : Std.U64) : Prop :=
  ∀ i, Has a i → Has b i

/-- No capability of `d` is in `s`: the two sets have nothing in common. -/
def Misses (d s : Std.U64) : Prop :=
  ∀ i, Has d i → ¬ Has s i

/-- The property `P` holds of each of the five sets of the process. -/
def EverySet (s : Sets) (P : Std.U64 → Prop) : Prop :=
  P s.bounding ∧ P s.effective ∧ P s.permitted ∧ P s.inheritable ∧ P s.ambient

/-- `--cap-drop` takes capability `i` away from the container: it is in `r.drop`, and the
container is not privileged (a privileged container drops nothing). -/
def Dropped (r : Request) (i : Fin 64) : Prop :=
  r.privileged = false ∧ Has r.drop i

/-- The four sets other than the bounding set (effective, permitted, inheritable, ambient)
have exactly the capabilities `i` for which `P i` holds. -/
def FourSetsHave (s : Sets) (P : Fin 64 → Prop) : Prop :=
  (∀ i, Has s.effective i ↔ P i) ∧ (∀ i, Has s.permitted i ↔ P i) ∧
  (∀ i, Has s.inheritable i ↔ P i) ∧ (∀ i, Has s.ambient i ↔ P i)

/-- The four sets other than the bounding set are all equal to `x`. -/
def FourSetsAre (s : Sets) (x : Std.U64) : Prop :=
  s.effective = x ∧ s.permitted = x ∧ s.inheritable = x ∧ s.ambient = x

/-- The refusal for `--cap-add all` with `--cap-drop all`: a request that is not
privileged (a privileged container has no `drop`) and has both. -/
def Contradicts (r : Request) : Prop :=
  r.privileged = false ∧ r.add_all = true ∧ r.drop_all = true

/-- `m` is exactly the capabilities of `a` that `b` lacks (what a refusal names). -/
def Lacking (m a b : Std.U64) : Prop :=
  ∀ i, Has m i ↔ Has a i ∧ ¬ Has b i

/-- **`sets` always returns.**  For every request, over all 64 bits of every mask: no
panic, no overflow, whatever the combination of flags.  This is what the walk of four
bits cannot say.

Not said: what it returns (the claims below). -/
def SetsNeverPanics : Prop :=
  ∀ r : Request, sets r ⦃ _ => True ⦄

/-- **No set of an answer is beyond the engine.**  `sets` returns, and when its answer is
sets `s`, each of the five (bounding, effective, permitted, inheritable, ambient) is
within the bounding set `r.bounding` of the engine: the runtime never gives a capability
the engine does not have, not for `--privileged`, not for `all`, not for root.

Not said: that a set has anything (it may be empty); which capabilities it has (the claims
`TheBoundingSetHasWhatWasAsked`, `AllGivesTheEngineMinusDrop` and `WhatEachSetIs` say it). -/
def NoSetBeyondTheEngine : Prop :=
  ∀ r : Request, sets r ⦃ answer =>
    ∀ s, answer = core.result.Result.Ok s → EverySet s (fun set => Within set r.bounding) ⦄

/-- **A dropped capability is in no set.**  `sets` returns, and when the request is not
privileged and its answer is sets `s`, no capability of `r.drop` is in any of the five
sets: `--cap-drop` takes it from all of them, the ambient ones too.

Not said: anything of a privileged request (it has no `drop`, and `WhatEachSetIs` and
`WhatAPrivilegedContainerHas` say what it has). -/
def NothingDroppedIsGiven : Prop :=
  ∀ r : Request, r.privileged = false → sets r ⦃ answer =>
    ∀ s, answer = core.result.Result.Ok s → EverySet s (fun set => Misses r.drop set) ⦄

/-- **Nothing comes from nowhere.**  `sets` returns, and when the request is not
privileged, has no `--cap-add all`, and the answer is sets `s`: each capability of each of
the five sets is a default (`r.defaults`, and `--cap-drop all` has not taken the defaults away), or was added (`r.add`), or is ambient
(`r.ambient`).  So the runtime invents nothing: `all` and `--privileged` are the only ways
to have what no list names.

Not said: that every default, added or ambient capability is given (`TheBoundingSetHasWhatWasAsked`
says it of the bounding set); which of the three each capability came from. -/
def NothingComesFromNowhere : Prop :=
  ∀ r : Request, r.privileged = false → r.add_all = false → sets r ⦃ answer =>
    ∀ s, answer = core.result.Result.Ok s →
      EverySet s (fun set => ∀ i, Has set i →
        (r.drop_all = false ∧ Has r.defaults i) ∨ Has r.add i ∨ Has r.ambient i) ⦄

/-- **The bounding set has what was asked for.**  `sets` returns, and when its answer is sets
`s`, every capability that is not dropped (see `Dropped`) is in the bounding set `s.bounding`
if it is
- in `r.add`, or
- in `r.ambient`, or
- a default (`r.defaults`) that the engine has (`r.bounding`), when `--cap-drop all` was not
  asked.

Not said: that nothing else is in it (the claims above bound it; the next two say more); that
a default the engine lacks is given (it is left out without a word); what the other sets
have (`WhatEachSetIs`). -/
def TheBoundingSetHasWhatWasAsked : Prop :=
  ∀ r : Request, sets r ⦃ answer =>
    ∀ s, answer = core.result.Result.Ok s → ∀ i, ¬ Dropped r i →
      (Has r.add i ∨ Has r.ambient i ∨
        (r.drop_all = false ∧ Has r.defaults i ∧ Has r.bounding i)) → Has s.bounding i ⦄

/-- **`--cap-add all` gives the engine's capabilities, minus `drop`.**  `sets` returns, and
when the request is not privileged, has `--cap-add all`, and the answer is sets `s`:
- the bounding set has exactly the capabilities of `r.bounding` that are not in `r.drop`;
- so each of the five sets is within that: nothing the engine has and `drop` took away, and
  nothing the engine lacks.

Not said: what the other four sets have (`WhatEachSetIs`: for another user `all` gives them
the whole bounding set, for root it does not). -/
def AllGivesTheEngineMinusDrop : Prop :=
  ∀ r : Request, r.privileged = false → r.add_all = true → sets r ⦃ answer =>
    ∀ s, answer = core.result.Result.Ok s →
      (∀ i, Has s.bounding i ↔ Has r.bounding i ∧ ¬ Has r.drop i) ∧
      EverySet s (fun set => ∀ i, Has set i → Has r.bounding i ∧ ¬ Has r.drop i) ⦄

/-- **What each set is.**  `sets` returns, and when its answer is sets `s` (for any request,
`--privileged` included: a privileged container has no `drop`, see `Dropped`):
- root: the effective and the permitted set are the bounding set `s.bounding` of the answer;
  the inheritable and the ambient set are the ambient capabilities `r.ambient` that were not
  dropped;
- another user: each of the effective, permitted, inheritable and ambient sets has exactly the
  capabilities that are the bounding set `s.bounding` when `--cap-add all` was asked, or that
  are in `r.add` and not dropped, or that are in `r.ambient` and not dropped.

Not said: what the bounding set `s.bounding` is (the claims `TheBoundingSetHasWhatWasAsked`,
`AllGivesTheEngineMinusDrop` and `NothingComesFromNowhere` bound it); that dropping a capability
the container never had has an effect, it has none and this is not stated. -/
def WhatEachSetIs : Prop :=
  ∀ r : Request, sets r ⦃ answer =>
    ∀ s, answer = core.result.Result.Ok s →
      (r.root = true →
        s.effective = s.bounding ∧ s.permitted = s.bounding ∧
        (∀ i, Has s.inheritable i ↔ Has r.ambient i ∧ ¬ Dropped r i) ∧
        (∀ i, Has s.ambient i ↔ Has r.ambient i ∧ ¬ Dropped r i)) ∧
      (r.root = false → FourSetsHave s (fun i =>
        (r.add_all = true ∧ Has s.bounding i) ∨
        (Has r.add i ∧ ¬ Dropped r i) ∨ (Has r.ambient i ∧ ¬ Dropped r i))) ⦄

/-- **The five sets fit together**, for every request.  `sets` returns, and when its answer is
sets `s`, the sets are nested as the kernel needs:
- the ambient set is within the permitted set and within the inheritable set;
- the effective set is within the permitted set;
and the code ensures two more (the kernel does not require them):
- the inheritable set is within the permitted set: root inherits only the ambient
  capabilities, another user only what it was given;
- the permitted set is within the bounding set of the process.

Not said: that the bounding set of the process is within the engine's (the claim
`NoSetBeyondTheEngine` says it). -/
def TheSetsFitTogether : Prop :=
  ∀ r : Request, sets r ⦃ answer =>
    ∀ s, answer = core.result.Result.Ok s →
      (Within s.ambient s.permitted ∧ Within s.ambient s.inheritable ∧
        Within s.effective s.permitted) ∧
      (Within s.inheritable s.permitted ∧ Within s.permitted s.bounding) ⦄

/-- **A privileged container has the engine's bounding set**, the same as numbers.  `sets`
returns, and when the request is privileged and the answer is sets `s` (`r.drop` is not looked
at):
- the bounding set of the process is exactly `r.bounding`, the engine's;
- for root, the effective and the permitted set are exactly `r.bounding` too, and the
  inheritable and the ambient set are exactly the ambient capabilities `r.ambient`;
- for another user, with `--cap-add all`, the four other sets are exactly `r.bounding`;
- for another user, without it, the four other sets are exactly what was asked for by name:
  the capabilities of `r.add` and of `r.ambient` together.

Not said: what the engine's bounding set is; the privileged case with a refusal (it is
refused if `add` or `ambient` has a capability the engine lacks: see the last two claims). -/
def WhatAPrivilegedContainerHas : Prop :=
  ∀ r : Request, r.privileged = true → sets r ⦃ answer =>
    ∀ s, answer = core.result.Result.Ok s →
      s.bounding = r.bounding ∧
      (r.root = true →
        s.effective = r.bounding ∧ s.permitted = r.bounding ∧
        s.inheritable = r.ambient ∧ s.ambient = r.ambient) ∧
      (r.root = false → r.add_all = true → FourSetsAre s r.bounding) ∧
      (r.root = false → r.add_all = false → FourSetsAre s (r.add ||| r.ambient)) ⦄

/-- **A request is refused exactly when** one of three things holds, and `sets` returns
in every case.  The answer is a refusal if and only if:
- the request is not privileged and has both `--cap-add all` and `--cap-drop all`; or
- `r.add` has a capability that the engine's bounding set `r.bounding` lacks; or
- `r.ambient` has a capability that `r.bounding` lacks.
So a request that none of the three describes is never refused, and one that one of them
describes always is.

Not said: which of the refusals is the answer when several hold (the next claim); that a
default the engine lacks is refused (it is not: it is left out, without a word). -/
def ARequestIsRefusedExactlyWhen : Prop :=
  ∀ r : Request, sets r ⦃ answer =>
    (∃ e, answer = core.result.Result.Err e) ↔
      (Contradicts r ∨ ¬ Within r.add r.bounding ∨ ¬ Within r.ambient r.bounding) ⦄

/-- **The refusal says why.**  `sets` returns, and:
- when `--cap-add all` and `--cap-drop all` contradict each other (see `Contradicts`), the
  answer is the refusal `AddAndDropAll`;
- else, when `r.add` has capabilities outside `r.bounding`, the answer is `Add m`, and `m`
  is exactly those capabilities;
- else, when `r.ambient` has capabilities outside `r.bounding`, the answer is `Ambient m`,
  and `m` is exactly those capabilities.
The order is the one of the code: a contradiction is reported before a lack, and a lack of
`add` before a lack of `ambient`.

Not said: the words of the message the shell makes of the refusal. -/
def TheRefusalSaysWhy : Prop :=
  ∀ r : Request, sets r ⦃ answer =>
    (Contradicts r → answer = core.result.Result.Err Refusal.AddAndDropAll) ∧
    (¬ Contradicts r → ¬ Within r.add r.bounding →
      ∃ m, Lacking m r.add r.bounding ∧ answer = core.result.Result.Err (Refusal.Add m)) ∧
    (¬ Contradicts r → Within r.add r.bounding → ¬ Within r.ambient r.bounding →
      ∃ m, Lacking m r.ambient r.bounding ∧
        answer = core.result.Result.Err (Refusal.Ambient m)) ⦄

end CapsCore
