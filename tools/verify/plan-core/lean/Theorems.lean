-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: the list of what is proved of crates/plan-core.
-- The statements are in PlanCore/Spec.lean, the proofs in PlanCore/Claims.lean (which uses
-- the files before it in PlanCore/).
-- ../../run ends on this file: it fails unless every line `#proved T` below
-- prints "proved: T".
--
-- Why it is needed: Lean checks a proof when it is read, but nothing
-- says that the theorem is the one of the statement or that no `sorry`
-- or new axiom is behind it.  `#proved T` (../../Proved.lean) prints the
-- axioms `T` rests on and fails unless they are the three of Lean and the
-- library functions the crate has no model of (the run prints none for this crate).
--
-- Read before this file: PlanCore/Spec.lean.
import Proved
import PlanCore.Claims

-- Each theorem is a proof of the statement of that name in Spec.lean: Lean
-- checks the type of each line below, so Theorems.lean and Spec.lean suffice.
example : PlanCore.EveryLackedContentIsPlannedOnce :=
  PlanCore.every_lacked_content_is_planned_once
example : PlanCore.AGroupIsWaitedForByWhoLacksItsFiles :=
  PlanCore.a_group_is_waited_for_by_who_lacks_its_files
example : PlanCore.AGroupIsFetchedIntoTheHomeOfItsFiles :=
  PlanCore.a_group_is_fetched_into_the_home_of_its_files

#proved PlanCore.every_lacked_content_is_planned_once
#proved PlanCore.a_group_is_waited_for_by_who_lacks_its_files
#proved PlanCore.a_group_is_fetched_into_the_home_of_its_files
