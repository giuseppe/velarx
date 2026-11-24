-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: the list of what is proved of crates/caps-core.
-- The statements are in CapsCore/Spec.lean, the proofs in CapsCore/Claims.lean (which uses
-- the files before it in CapsCore/).
-- ../../run ends on this file: it fails unless every line `#proved T` below
-- prints "proved: T".
--
-- Why it is needed: Lean checks a proof when it is read, but nothing
-- says that the theorem is the one of the statement or that no `sorry`
-- or new axiom is behind it.  `#proved T` (../../Proved.lean) prints the
-- axioms `T` rests on and fails unless they are the three of Lean and the
-- library functions the crate has no model of (the run prints none for this crate).
--
-- Read before this file: CapsCore/Spec.lean.
import Proved
import CapsCore.Claims

-- Each theorem is a proof of the statement of that name in Spec.lean: Lean
-- checks the type of each line below, so Theorems.lean and Spec.lean suffice.
example : CapsCore.SetsNeverPanics :=
  CapsCore.sets_never_panics
example : CapsCore.NoSetBeyondTheEngine :=
  CapsCore.no_set_beyond_the_engine
example : CapsCore.NothingDroppedIsGiven :=
  CapsCore.nothing_dropped_is_given
example : CapsCore.NothingComesFromNowhere :=
  CapsCore.nothing_comes_from_nowhere
example : CapsCore.TheBoundingSetHasWhatWasAsked :=
  CapsCore.the_bounding_set_has_what_was_asked
example : CapsCore.AllGivesTheEngineMinusDrop :=
  CapsCore.all_gives_the_engine_minus_drop
example : CapsCore.WhatEachSetIs :=
  CapsCore.what_each_set_is
example : CapsCore.TheSetsFitTogether :=
  CapsCore.the_sets_fit_together
example : CapsCore.WhatAPrivilegedContainerHas :=
  CapsCore.what_a_privileged_container_has
example : CapsCore.ARequestIsRefusedExactlyWhen :=
  CapsCore.a_request_is_refused_exactly_when
example : CapsCore.TheRefusalSaysWhy :=
  CapsCore.the_refusal_says_why

#proved CapsCore.sets_never_panics
#proved CapsCore.no_set_beyond_the_engine
#proved CapsCore.nothing_dropped_is_given
#proved CapsCore.nothing_comes_from_nowhere
#proved CapsCore.the_bounding_set_has_what_was_asked
#proved CapsCore.all_gives_the_engine_minus_drop
#proved CapsCore.what_each_set_is
#proved CapsCore.the_sets_fit_together
#proved CapsCore.what_a_privileged_container_has
#proved CapsCore.a_request_is_refused_exactly_when
#proved CapsCore.the_refusal_says_why
