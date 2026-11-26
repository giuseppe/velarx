-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: the proofs of the claims of Spec.lean.  Each is the rule of Step.lean for
-- the copy of the loop (Machine.lean), moved to the loop and the Rust core by Link.lean.
--
-- Why it is needed: Theorems.lean names a theorem for every claim.
--
-- Read before this file: Spec.lean, Step.lean, Link.lean.
import GroupCore.Link
open Aeneas Aeneas.Std Result velarx_group_core
namespace GroupCore

/-- What the loop knows once it has the event, field by field, is what the copy knows. -/
theorem pre_fields (s : Loop) (ev : Event) :
    (s.pre ev).searching = (s.abs.pre ev.abs).searching ∧
    (s.pre ev).hedged = (s.abs.pre ev.abs).hedged ∧
    (s.pre ev).running = (s.abs.pre ev.abs).running ∧
    (s.pre ev).passed = (s.abs.pre ev.abs).passed ∧
    (s.pre ev).items = (s.abs.pre ev.abs).items ∧
    (s.pre ev).found = (s.abs.pre ev.abs).found ∧
    (s.pre ev).room = (s.abs.pre ev.abs).room ∧
    (s.pre ev).asked = (s.abs.pre ev.abs).asked ∧
    (s.pre ev).noRoom = (s.abs.pre ev.abs).noRoom ∧
    (s.pre ev).noRoomAt = (s.abs.pre ev.abs).noRoomAt ∧
    (s.pre ev).noRoomAny = (s.abs.pre ev.abs).noRoomAny := by
  have key := pre_abs s ev
  have exhausted : (s.pre ev).exhausted = (s.abs.pre ev.abs).exhausted := congrArg AS.exhausted key
  have max : (s.pre ev).max = (s.abs.pre ev.abs).max := congrArg AS.max key
  have found : (s.pre ev).found = (s.abs.pre ev.abs).found := congrArg AS.found key
  exact ⟨congrArg AS.searching key, congrArg AS.hedged key, congrArg AS.running key,
    congrArg AS.passed key, congrArg AS.items key, found,
    by simp only [Loop.room, AS.room, exhausted, max, found],
    congrArg AS.asked key, congrArg AS.noRoom key, congrArg AS.noRoomAt key,
    congrArg AS.noRoomAny key⟩

/-- In a state the loop reaches, and a call it may make, the rules of Step.lean hold for the
answer. -/
theorem answers_rules {s : Loop} {ev : Event} {todo : Do} {g : Group} (h : Answers s ev todo g) :
    RulesA s.abs ev.abs todo.act g.abs := by
  obtain ⟨hr, fresh, en, call⟩ := h
  have ra := reach_abs hr
  obtain ⟨hi, below⟩ := reach_inv ra (by simpa [Loop.abs] using fresh)
  obtain ⟨todo', g', call', hans⟩ := call_returns s ev hi en
  rw [call] at call'
  simp only [ok.injEq, Prod.mk.injEq] at call'
  obtain ⟨rfl, rfl⟩ := call'
  have rules := (step_ok s.abs ev.abs hi below (enabled_abs s ev en)).2
  rw [← hans] at rules
  exact rules

/-- A new group asks for a search. -/
theorem a_group_starts_with_a_search : AGroupStartsWithASearch := by
  intro items passed max
  refine ⟨_, rfl, ?_⟩
  simp

/-- The core returns at every call the loop may make. -/
theorem every_call_returns : EveryCallReturns := by
  intro s ev reach fresh en
  have ra := reach_abs reach
  obtain ⟨hi, _⟩ := reach_inv ra (by simpa [Loop.abs] using fresh)
  obtain ⟨todo, g, call, _⟩ := call_returns s ev hi en
  exact ⟨_, call⟩

/-- The core's numbers are the loop's. -/
theorem the_core_agrees_with_the_loop : TheCoreAgreesWithTheLoop := by
  intro s reach fresh
  have ra := reach_abs reach
  obtain ⟨hi, _⟩ := reach_inv ra (by simpa [Loop.abs] using fresh)
  refine ⟨hi.items_eq, hi.max_eq, hi.passed_eq, hi.found_eq, hi.exhausted_eq, hi.searching_eq, ?_⟩
  have := hi.running_eq
  simpa [Loop.abs, Group.abs] using this

/-- The group takes at most its peers, and nobody is asked that was not found. -/
theorem the_group_takes_at_most_its_peers : TheGroupTakesAtMostItsPeers := by
  intro s reach fresh
  have ra := reach_abs reach
  obtain ⟨hi, _⟩ := reach_inv ra (by simpa [Loop.abs] using fresh)
  exact ⟨hi.found_le, hi.beyond⟩

/-- A search is asked for only when none is under way. -/
theorem at_most_one_search : AtMostOneSearch := by
  intro s ev todo g ans e
  subst e
  obtain ⟨searching, _⟩ := pre_fields s ev
  rw [searching]
  exact (answers_rules ans).search_once rfl

/-- A search is asked for only with room left. -/
theorem a_search_needs_room : ASearchNeedsRoom := by
  intro s ev todo g ans e
  subst e
  obtain ⟨_, _, _, _, _, _, room, _⟩ := pre_fields s ev
  rw [room]
  exact (answers_rules ans).search_room rfl

/-- A search beside a request comes of the hedge timer. -/
theorem a_search_beside_a_request_is_a_hedge : ASearchBesideARequestIsAHedge := by
  intro s ev todo g ans e busy
  subst e
  obtain ⟨_, _, running, _⟩ := pre_fields s ev
  rw [running] at busy
  have := (answers_rules ans).search_beside rfl busy
  cases ev <;> simp_all [Event.abs]

/-- A peer asked was found. -/
theorem an_asked_peer_was_found : AnAskedPeerWasFound := by
  intro s ev todo g q ans e
  subst e
  obtain ⟨_, _, _, _, _, found, _⟩ := pre_fields s ev
  rw [found]
  exact (answers_rules ans).ask_found q.val rfl

/-- A peer asked has no request. -/
theorem a_peer_has_one_request : APeerHasOneRequest := by
  intro s ev todo g q ans e
  subst e
  obtain ⟨_, _, running, _⟩ := pre_fields s ev
  rw [running]
  exact (answers_rules ans).ask_free q.val rfl

/-- A request beside another comes of a hedge. -/
theorem a_request_beside_another_is_a_hedge : ARequestBesideAnotherIsAHedge := by
  intro s ev todo g q ans e busy
  subst e
  obtain ⟨_, hedged, running, _⟩ := pre_fields s ev
  rw [running] at busy
  have := (answers_rules ans).ask_beside q.val rfl busy
  rw [← hedged] at this
  cases ev <;> simp_all [Event.abs]

/-- A peer is asked again only after no room and progress. -/
theorem a_peer_is_asked_again_only_after_progress : APeerIsAskedAgainOnlyAfterProgress := by
  intro s ev todo g q ans e again
  subst e
  obtain ⟨_, _, _, passed, _, _, _, asked, noRoom, noRoomAt, _⟩ := pre_fields s ev
  rw [asked] at again
  have := (answers_rules ans).ask_again q.val rfl again
  rw [noRoom, noRoomAt, passed]
  exact this

/-- A peer is asked at most items + 1 times. -/
theorem a_peer_is_asked_at_most_items_plus_one_times : APeerIsAskedAtMostItemsPlusOneTimes := by
  intro s ev todo g q ans e
  subst e
  obtain ⟨_, _, _, _, items, _, _, asked, _⟩ := pre_fields s ev
  rw [asked, items]
  exact (answers_rules ans).ask_times q.val rfl

/-- Nobody is asked once everything is passed on. -/
theorem no_peer_is_asked_once_all_is_passed : NoPeerIsAskedOnceAllIsPassed := by
  intro s ev todo g q ans e
  subst e
  obtain ⟨_, _, _, passed, items, _⟩ := pre_fields s ev
  rw [passed, items]
  exact (answers_rules ans).ask_unpassed q.val rfl

/-- The report that passes the last item ends the group. -/
theorem all_items_passed_end_the_group : AllItemsPassedEndTheGroup := by
  intro s ev todo g ans reports all
  obtain ⟨_, _, _, passed, items, _⟩ := pre_fields s ev
  rw [passed, items] at all
  have reports' : ev.abs.reports := by
    rcases reports with ⟨p, rfl⟩ | ⟨q, nr, p, rfl⟩ <;> trivial
  have := (answers_rules ans).all_passed reports' all
  cases todo <;> simp_all [Do.act]

/-- The group ends only when nobody is left. -/
theorem a_group_ends_only_when_nobody_is_left : AGroupEndsOnlyWhenNobodyIsLeft := by
  intro s ev todo g ans e
  subst e
  obtain ⟨searching, _, running, passed, items, found, room, asked, noRoom, _, noRoomAny⟩ :=
    pre_fields s ev
  have := (answers_rules ans).finish_when rfl
  rw [searching, running, passed, items, found, room, asked, noRoom, noRoomAny]
  exact this

/-- The group never waits with nothing under way. -/
theorem the_group_never_waits_with_nothing_under_way : TheGroupNeverWaitsWithNothingUnderWay := by
  intro s ev todo g ans notFinish
  have := (answers_rules ans).never_idle (by cases todo <;> simp_all [Do.act])
  have key := after_abs s ev todo g
  have r := congrArg AS.running key
  have c := congrArg AS.searching key
  simp only [Loop.abs] at r c
  rw [r, c]
  exact this

/-- An armed hedge asks or searches. -/
theorem an_armed_hedge_acts : AnArmedHedgeActs := by
  intro s todo g ans
  have := (answers_rules ans).hedge_acts rfl
  cases todo <;> simp_all [Do.act]

end GroupCore
