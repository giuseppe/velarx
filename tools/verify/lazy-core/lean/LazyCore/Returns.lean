-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: the proofs of the claims of Spec.lean that say `step` RETURNS:
-- `ANewCoreIsShort`, `AStepAlwaysReturns`, `StepReturnsOnEveryReachableCore`,
-- `AStepReturnsAndKeepsTheTablesWellFormed` and `TheOtherClaimsHoldWithoutTheIf`.
--
-- Why it is needed: the claims of Spec.lean that were proved first say what holds IF `step`
-- returns.  Here the proof is that it does: `step_returns` (ReturnsStep.lean) follows `step` event
-- by event, down to each loop, and says that it returns and leaves a short core; the claims here
-- put it in the words of Spec.lean, and join it to the older claims (so that they hold without
-- the "if").
--
-- How the proof of `step_returns` goes, in short.  The core keeps no index, so no function can
-- fail on a number it was told: `pull_at`, `layer_at` and `group_at` look the number up and say
-- where the pull, the layer or the group is, or that it is not there (ReturnsQueries.lean).  What
-- is left that can fail is `Vec::push`, an index that was found one line before, an addition, and
-- a loop that does not end.  A loop ends because a number goes down at each turn (the elements
-- left to read); a `push` has room because each loop is given room for what it pushes, in a
-- number of actions that is bounded by the size of the tables (at most 2^25 entries), so that
-- everything `step` pushes is less than 2^54 and fits in a vector of 2^63 more than it had.
--
-- Read before this file: Spec.lean, ReturnsStep.lean.
--
-- Notation: `m ⦃ r => P r ⦄` is "the call `m` returns, and its result `r` satisfies `P r`";
-- `∃ x, ...` is "there is an `x` such that"; `induction` proves a claim for the cores reached by
-- the cases of `Reachable`.
import Ok
import LazyCore.ReturnsStep
import LazyCore.Tables
import LazyCore.Step

open Aeneas Aeneas.Std Result velarx_lazy_core

namespace LazyCore

/-- **A new core is short** (the statement of Spec.lean): `Core::new` makes four empty tables. -/
theorem a_new_core_is_short : ANewCoreIsShort := by
  intro cfg c made
  have empty : Ok (Core.new cfg) (fun c => Short c) := by
    unfold Core.new
    exact Ok.ok.mpr (by simp [Short, alloc.vec.Vec.new])
  exact empty.eq made

/-- **`step` always returns on a short core** (the statement of Spec.lean): `step_returns`, with
the pair it says `step` returns taken apart. -/
theorem a_step_always_returns : AStepAlwaysReturns := by
  intro c now ev out on64 short roomy not_huge
  obtain ⟨⟨c', out'⟩, found, result⟩ :=
    spec_imp_ok (step_returns on64 c now ev out short roomy (by omega))
  exact ⟨c', out', found, result⟩

/-- Every core the machine reaches is short: the first one is, and a step that returns from a short
core leaves a short one (`AStepAlwaysReturns`). -/
theorem a_reachable_core_is_short (on64 : OnA64BitMachine) :
    ∀ c, Reachable c → Short c := by
  intro c reached
  induction reached with
  | first cfg c made => exact a_new_core_is_short cfg c made
  | next c now ev out c' out' reached leaves_room not_huge returned short =>
    obtain ⟨c2, out2, found, short2, _⟩ :=
      a_step_always_returns c now ev out on64 short leaves_room not_huge
    rw [returned] at found
    have same : (c2, out2) = (c', out') :=
      Ok.eq (m := ok (c', out')) (P := fun r => r = (c', out')) (Ok.ok.mpr rfl) found
    obtain ⟨rfl, rfl⟩ := Prod.mk.inj same
    exact short2

/-- **`step` always returns on the states the machine can reach** (the statement of Spec.lean):
the core is short (`a_reachable_core_is_short`), so `AStepAlwaysReturns` applies. -/
theorem step_returns_on_every_reachable_core : StepReturnsOnEveryReachableCore := by
  intro c reached now ev out on64 leaves_room not_huge
  obtain ⟨c', out', found, _⟩ := a_step_always_returns c now ev out on64
    (a_reachable_core_is_short on64 c reached) leaves_room not_huge
  exact ⟨c', out', found⟩

/-- **A step returns and keeps the tables well formed** (the statement of Spec.lean): `step`
returns (`AStepAlwaysReturns`), and what it returns is well formed
(`TheTablesStayWellFormed`) and only adds actions (`AStepOnlyAddsActions`). -/
theorem a_step_returns_and_keeps_the_tables_well_formed :
    AStepReturnsAndKeepsTheTablesWellFormed := by
  intro c now ev out on64 well_formed short well_told leaves_room not_huge
  obtain ⟨c', out', found, short', _⟩ :=
    a_step_always_returns c now ev out on64 short leaves_room not_huge
  exact ⟨c', out', found, the_tables_stay_well_formed c now ev out c' out' well_formed well_told
    found, short', a_step_only_adds_actions c now ev out c' out' found⟩

/-- **A claim that holds "if the step returns" holds without the "if"** (the statement of
Spec.lean): the step returns on a reachable core (`StepReturnsOnEveryReachableCore`), and what it
returns satisfies `P` because every step that returns does. -/
theorem the_other_claims_hold_without_the_if : TheOtherClaimsHoldWithoutTheIf := by
  intro P c now ev out on64 reached leaves_room not_huge partial_claim
  obtain ⟨c', out', found⟩ :=
    step_returns_on_every_reachable_core c reached now ev out on64 leaves_room not_huge
  exact ⟨c', out', found, partial_claim c' out' found⟩

end LazyCore
