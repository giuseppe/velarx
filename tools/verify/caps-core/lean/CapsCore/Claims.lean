-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: the proofs of the claims of Spec.lean, one theorem for each, in the
-- order of Spec.lean.
--
-- Why it is needed: ../Theorems.lean names what is proved; the proofs are here.
--
-- Read before this file: Spec.lean, Bits.lean, Answer.lean.
--
-- How a proof goes (the same for all of them): `sets_eq` (Answer.lean) replaces `sets r` by
-- `answer_of r`, a function with no way to fail; `ok_sets` says that if the answer is sets
-- `s`, they are `sets_of r` and the request is not refused.  `sets_of` has a few `if`s on the
-- flags: `split_ifs` makes one case of each combination.  In a case, "capability `i` is in
-- this set" is a statement about the true-or-false facts "`i` is in `r.add`", "`i` is in
-- `r.drop`", and so on; `simp` (with the lemmas of Bits.lean) writes it so, and `tauto`
-- decides it.  Nothing depends on how many bits there are: the case is for one `i`, whatever it is.
--
-- Notation: `intro` takes the "for every" or the "if" of the goal as a given; `refine ⟨?_, ...⟩`
-- splits an "and" into goals; `tauto` proves what follows from the givens by logic alone.
import CapsCore.Answer

open Aeneas Aeneas.Std Result velarx_caps_core

namespace CapsCore

/-- `sets` returns for every request: it is `answer_of`, which has no way to fail. -/
theorem sets_never_panics : SetsNeverPanics := by
  intro r
  rw [sets_eq, WP.spec_ok]
  trivial

/-- Each of the five sets is within the engine's, in each case of the flags. -/
theorem no_set_beyond_the_engine : NoSetBeyondTheEngine := by
  intro r
  apply sets_ok_spec
  intro free add_in ambient_in
  unfold sets_of bounding_of ambient_of EverySet Within
  split_ifs <;> refine ⟨?_, ?_, ?_, ?_, ?_⟩ <;> intro i <;>
    have := add_in i <;> have := ambient_in i <;> simp <;> tauto

/-- Not privileged, each of the five sets has `drop` taken out, in each case of the flags. -/
theorem nothing_dropped_is_given : NothingDroppedIsGiven := by
  intro r not_privileged
  apply sets_ok_spec
  intro free add_in ambient_in
  unfold sets_of bounding_of ambient_of EverySet Misses
  simp only [not_privileged, ↓reduceIte, Bool.false_eq_true]
  split_ifs <;> refine ⟨?_, ?_, ?_, ?_, ?_⟩ <;> intro i <;> simp <;> tauto

/-- Not privileged and no `all`, each capability of each set is in the defaults (when they were
not dropped all), `add` or `ambient`, in each case of the flags. -/
theorem nothing_comes_from_nowhere : NothingComesFromNowhere := by
  intro r not_privileged no_all
  apply sets_ok_spec
  intro free add_in ambient_in
  unfold sets_of bounding_of ambient_of EverySet
  simp only [not_privileged, no_all, ↓reduceIte, Bool.false_eq_true]
  split_ifs <;> refine ⟨?_, ?_, ?_, ?_, ?_⟩ <;> intro i <;> simp [*] <;> tauto

/-- The bounding set is `(base ||| add) minus drop ||| ambient minus drop`: a capability that
is asked for and not dropped is in one of the three parts, whatever the flags. -/
theorem the_bounding_set_has_what_was_asked : TheBoundingSetHasWhatWasAsked := by
  intro r
  apply sets_ok_spec
  intro free add_in ambient_in i not_dropped asked
  unfold sets_of bounding_of ambient_of Dropped at *
  split_ifs <;> simp [*] at * <;> tauto

/-- With `all`, the base is the engine's bounding set: the lower bound is the same case
analysis as the upper bound, and the upper bound is the first part of the claim. -/
theorem all_gives_the_engine_minus_drop : AllGivesTheEngineMinusDrop := by
  intro r not_privileged add_all
  apply sets_ok_spec
  intro free add_in ambient_in
  unfold sets_of bounding_of ambient_of EverySet
  simp only [not_privileged, add_all, ↓reduceIte, Bool.false_eq_true]
  refine ⟨?_, ?_⟩
  · intro i
    have := add_in i
    have := ambient_in i
    split_ifs <;> simp <;> tauto
  · split_ifs <;> refine ⟨?_, ?_, ?_, ?_, ?_⟩ <;> intro i <;>
      have := add_in i <;> have := ambient_in i <;> simp <;> tauto

/-- Root and another user, each as `sets_of` says; `Dropped` is unfolded so that the flags that
decide it are in view. -/
theorem what_each_set_is : WhatEachSetIs := by
  intro r
  apply sets_ok_spec
  intro free add_in ambient_in
  refine ⟨fun root => ?_, fun not_root => ?_⟩
  · rw [sets_of_root root]
    refine ⟨rfl, rfl, fun i => ?_, fun i => ?_⟩ <;>
      cases privileged : r.privileged <;> simp [ambient_of, Dropped, privileged]
  · rw [sets_of_user not_root]
    refine ⟨fun i => ?_, fun i => ?_, fun i => ?_, fun i => ?_⟩ <;>
      have := add_in i <;> have := ambient_in i <;>
      cases privileged : r.privileged <;> cases add_all : r.add_all <;>
      cases drop_all : r.drop_all <;> simp [bounding_of, ambient_of, Dropped, *] <;> tauto

/-- The five sets fit together, in each case of the flags. -/
theorem the_sets_fit_together : TheSetsFitTogether := by
  intro r
  apply sets_ok_spec
  intro free add_in ambient_in
  unfold sets_of bounding_of ambient_of Within
  split_ifs <;> refine ⟨⟨?_, ?_, ?_⟩, ?_, ?_⟩ <;> intro i <;> simp <;> tauto

/-- Privileged: the flags that are known are put in, and what is left is an equality of two
sets, proved capability by capability. -/
theorem what_a_privileged_container_has : WhatAPrivilegedContainerHas := by
  intro r privileged
  apply sets_ok_spec
  intro free add_in ambient_in
  refine ⟨?_, fun root => ?_, fun root add_all => ?_, fun root add_all => ?_⟩
  all_goals simp only [sets_of, bounding_of, ambient_of, FourSetsAre, ↓reduceIte,
    Bool.false_eq_true, *]
  · split_ifs <;> apply eq_of_has <;> intro i <;> have := add_in i <;> have := ambient_in i <;>
      simp <;> tauto
  all_goals constructorm* _ ∧ _
  all_goals try trivial
  all_goals apply eq_of_has
  all_goals intro i
  all_goals have := add_in i
  all_goals have := ambient_in i
  all_goals simp
  all_goals tauto

/-- Refused exactly when one of the three holds: each case of the three is a rewrite by the
matching lemma of Answer.lean. -/
theorem a_request_is_refused_exactly_when : ARequestIsRefusedExactlyWhen := by
  intro r
  rw [sets_eq, WP.spec_ok]
  by_cases contradicts : Contradicts r
  · simp [answer_contradicts contradicts, contradicts]
  by_cases add_in : Within r.add r.bounding
  swap
  · simp [answer_add_lacks contradicts add_in, add_in]
  by_cases ambient_in : Within r.ambient r.bounding
  swap
  · simp [answer_ambient_lacks contradicts add_in ambient_in, ambient_in]
  simp [answer_sets contradicts add_in ambient_in, contradicts, add_in, ambient_in]

/-- The refusal names `add &&& ~~~bounding` or `ambient &&& ~~~bounding`, which are exactly
the capabilities that lack (Bits.lean). -/
theorem the_refusal_says_why : TheRefusalSaysWhy := by
  intro r
  rw [sets_eq, WP.spec_ok]
  refine ⟨answer_contradicts, fun free add_lacks => ?_, fun free add_in ambient_lacks => ?_⟩
  · exact ⟨r.add &&& ~~~r.bounding, fun i => by simp, answer_add_lacks free add_lacks⟩
  · exact ⟨r.ambient &&& ~~~r.bounding, fun i => by simp,
      answer_ambient_lacks free add_in ambient_lacks⟩

end CapsCore
