-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: the list of what is proved of crates/pull-core.
-- The statements are in PullCore/Spec.lean, the proofs in PullCore/Ends.lean,
-- PullCore/Phases.lean and PullCore/Claims.lean.
-- ../../run ends on this file: it fails unless every line `#proved T` below
-- prints "proved: T".
--
-- Why it is needed: Lean checks a proof when it is read, but nothing
-- says that the theorem is the one of the statement or that no `sorry`
-- or new axiom is behind it.  `#proved T` (../../Proved.lean) prints the
-- axioms `T` rests on and fails unless they are the three of Lean and the
-- library functions Models.lean does not define.
--
-- Read before this file: PullCore/Spec.lean.
import Proved
import PullCore.Ends
import PullCore.Phases
import PullCore.Claims

-- Each theorem is a proof of the statement of that name in Spec.lean: Lean
-- checks the type of each line below, so Theorems.lean and Spec.lean suffice.
example : PullCore.ALayerHasOneLiveClaimant := PullCore.the_table_stays_sound
example : PullCore.APullIsPublishedOnlyFromCommitting :=
  PullCore.a_pull_is_published_only_from_committing
example : PullCore.TheFirstDecisionStands := PullCore.the_first_decision_stands
example : PullCore.AnEndFreesTheClaimsOnce := PullCore.an_end_frees_the_claims_once

#proved PullCore.the_table_stays_sound
#proved PullCore.a_pull_is_published_only_from_committing
#proved PullCore.the_first_decision_stands
#proved PullCore.an_end_frees_the_claims_once
