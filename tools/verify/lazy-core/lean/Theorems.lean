-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: the list of what is proved of crates/lazy-core.
-- The statements are in LazyCore/Spec.lean, the proofs in LazyCore/Step.lean, LazyCore/Cancel.lean,
-- LazyCore/Verdict.lean, LazyCore/Names.lean, LazyCore/Stopping.lean,
-- LazyCore/Sharers.lean, LazyCore/Held.lean, LazyCore/Tables.lean,
-- LazyCore/Image.lean, LazyCore/Commits.lean and LazyCore/Returns.lean (which rests on
-- LazyCore/ReturnsStep.lean and the files it rests on).
-- ../../run ends on this file: it fails unless every line `#proved T` below
-- prints "proved: T".
--
-- Why it is needed: Lean checks a proof when it is read, but nothing
-- says that the theorem is the one of the statement or that no `sorry`
-- or new axiom is behind it.  `#proved T` (../../Proved.lean) prints the
-- axioms `T` rests on and fails unless they are the three of Lean and the
-- library functions Models.lean does not define.
--
-- Read before this file: LazyCore/Spec.lean.
import Proved
import LazyCore.Step
import LazyCore.Cancel
import LazyCore.Verdict
import LazyCore.Names
import LazyCore.Stopping
import LazyCore.Sharers
import LazyCore.Tables
import LazyCore.Image
import LazyCore.Commits
import LazyCore.Held
import LazyCore.Returns

-- Each theorem is a proof of the statement of that name in Spec.lean: Lean
-- checks the type of each line below, so Theorems.lean and Spec.lean suffice.
example : LazyCore.AStepOnlyAddsActions := LazyCore.a_step_only_adds_actions
example : LazyCore.ACancelIsNeverLost := LazyCore.a_cancel_is_never_lost
example : LazyCore.TheVerdictOfAFailure := LazyCore.the_verdict_of_a_failure
example : LazyCore.AStoppingPullOnlyEnds := LazyCore.a_stopping_pull_only_ends
example : LazyCore.TheEndOfTheStopEndsIt := LazyCore.the_end_of_the_stop_ends_it
example : LazyCore.TheNamesStayDistinct := LazyCore.the_names_stay_distinct
example : LazyCore.ACancelMakesTheSharersPlanAgain :=
  LazyCore.a_cancel_makes_the_sharers_plan_again
example : LazyCore.ANewCoreHasNoPull := LazyCore.a_new_core_has_no_pull
example : LazyCore.TheTablesStayWellFormed := LazyCore.the_tables_stay_well_formed
example : LazyCore.AnImageIsCommittedAfterItsLayers :=
  LazyCore.an_image_is_committed_after_its_layers
example : LazyCore.ADriverPullFollowsItsLayers := LazyCore.a_driver_pull_follows_its_layers
example : LazyCore.ALayerIsCommittedAfterItsGroups :=
  LazyCore.a_layer_is_committed_after_its_groups
example : LazyCore.AGroupIsHeldForTheNewLayersThatNeedIt :=
  LazyCore.a_group_is_held_for_the_new_layers_that_need_it
example : LazyCore.ANewCoreIsWellFormed := LazyCore.a_new_core_is_well_formed
example : LazyCore.ANewCoreIsShort := LazyCore.a_new_core_is_short
example : LazyCore.AStepAlwaysReturns := LazyCore.a_step_always_returns
example : LazyCore.StepReturnsOnEveryReachableCore :=
  LazyCore.step_returns_on_every_reachable_core
example : LazyCore.AStepReturnsAndKeepsTheTablesWellFormed :=
  LazyCore.a_step_returns_and_keeps_the_tables_well_formed
example : LazyCore.TheOtherClaimsHoldWithoutTheIf :=
  LazyCore.the_other_claims_hold_without_the_if

#proved LazyCore.a_step_only_adds_actions
#proved LazyCore.a_cancel_is_never_lost
#proved LazyCore.the_verdict_of_a_failure
#proved LazyCore.a_stopping_pull_only_ends
#proved LazyCore.the_end_of_the_stop_ends_it
#proved LazyCore.the_names_stay_distinct
#proved LazyCore.a_cancel_makes_the_sharers_plan_again
#proved LazyCore.a_new_core_has_no_pull
#proved LazyCore.the_tables_stay_well_formed
#proved LazyCore.an_image_is_committed_after_its_layers
#proved LazyCore.a_driver_pull_follows_its_layers
#proved LazyCore.a_layer_is_committed_after_its_groups
#proved LazyCore.a_group_is_held_for_the_new_layers_that_need_it
#proved LazyCore.a_new_core_is_well_formed
#proved LazyCore.a_new_core_is_short
#proved LazyCore.a_step_always_returns
#proved LazyCore.step_returns_on_every_reachable_core
#proved LazyCore.a_step_returns_and_keeps_the_tables_well_formed
#proved LazyCore.the_other_claims_hold_without_the_if
