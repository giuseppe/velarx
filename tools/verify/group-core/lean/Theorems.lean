-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: the list of what is proved of crates/group-core.  The statements are in
-- GroupCore/Spec.lean; the proofs are in the other files of GroupCore/, from Claims.lean.
-- ../../run ends on this file: it fails unless every line `#proved T` below prints "proved: T".
--
-- Why it is needed: Lean checks a proof when it is read, but nothing says that the theorem is the
-- one of the statement or that no `sorry` or new axiom is behind it.  `#proved T`
-- (../../Proved.lean) prints the axioms `T` rests on and fails unless they are the three of Lean
-- and the library functions the crate has no model of (there are none).
--
-- Read before this file: GroupCore/Spec.lean.
import Proved
import GroupCore.Claims

example : GroupCore.AGroupStartsWithASearch := GroupCore.a_group_starts_with_a_search
example : GroupCore.EveryCallReturns := GroupCore.every_call_returns
example : GroupCore.TheCoreAgreesWithTheLoop := GroupCore.the_core_agrees_with_the_loop
example : GroupCore.TheGroupTakesAtMostItsPeers := GroupCore.the_group_takes_at_most_its_peers
example : GroupCore.AtMostOneSearch := GroupCore.at_most_one_search
example : GroupCore.ASearchNeedsRoom := GroupCore.a_search_needs_room
example : GroupCore.ASearchBesideARequestIsAHedge := GroupCore.a_search_beside_a_request_is_a_hedge
example : GroupCore.AnAskedPeerWasFound := GroupCore.an_asked_peer_was_found
example : GroupCore.APeerHasOneRequest := GroupCore.a_peer_has_one_request
example : GroupCore.ARequestBesideAnotherIsAHedge := GroupCore.a_request_beside_another_is_a_hedge
example : GroupCore.APeerIsAskedAgainOnlyAfterProgress := GroupCore.a_peer_is_asked_again_only_after_progress
example : GroupCore.APeerIsAskedAtMostItemsPlusOneTimes := GroupCore.a_peer_is_asked_at_most_items_plus_one_times
example : GroupCore.NoPeerIsAskedOnceAllIsPassed := GroupCore.no_peer_is_asked_once_all_is_passed
example : GroupCore.AllItemsPassedEndTheGroup := GroupCore.all_items_passed_end_the_group
example : GroupCore.AGroupEndsOnlyWhenNobodyIsLeft := GroupCore.a_group_ends_only_when_nobody_is_left
example : GroupCore.TheGroupNeverWaitsWithNothingUnderWay := GroupCore.the_group_never_waits_with_nothing_under_way
example : GroupCore.AnArmedHedgeActs := GroupCore.an_armed_hedge_acts

#proved GroupCore.a_group_starts_with_a_search
#proved GroupCore.every_call_returns
#proved GroupCore.the_core_agrees_with_the_loop
#proved GroupCore.the_group_takes_at_most_its_peers
#proved GroupCore.at_most_one_search
#proved GroupCore.a_search_needs_room
#proved GroupCore.a_search_beside_a_request_is_a_hedge
#proved GroupCore.an_asked_peer_was_found
#proved GroupCore.a_peer_has_one_request
#proved GroupCore.a_request_beside_another_is_a_hedge
#proved GroupCore.a_peer_is_asked_again_only_after_progress
#proved GroupCore.a_peer_is_asked_at_most_items_plus_one_times
#proved GroupCore.no_peer_is_asked_once_all_is_passed
#proved GroupCore.all_items_passed_end_the_group
#proved GroupCore.a_group_ends_only_when_nobody_is_left
#proved GroupCore.the_group_never_waits_with_nothing_under_way
#proved GroupCore.an_armed_hedge_acts
