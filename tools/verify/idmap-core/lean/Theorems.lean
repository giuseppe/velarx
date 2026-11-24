-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: the list of what is proved of crates/idmap-core.  The statements are in
-- IdmapCore/Spec.lean, the proofs in IdmapCore/Claims.lean (which uses the files before it in
-- IdmapCore/).
-- ../../run ends on this file: it fails unless every line `#proved T` below
-- prints "proved: T".
--
-- Why it is needed: Lean checks a proof when it is read, but nothing says that the theorem is the
-- one of the statement or that no `sorry` or new axiom is behind it.  `#proved T`
-- (../../Proved.lean) prints the axioms `T` rests on and fails unless they are the three of Lean
-- and the library functions the crate has no model of (none is used by these claims).
--
-- Read before this file: IdmapCore/Spec.lean.
import Proved
import IdmapCore.Claims

-- Each theorem is a proof of the statement of that name in Spec.lean: Lean
-- checks the type of each line below, so Theorems.lean and Spec.lean suffice.
example : IdmapCore.ValidateAcceptsExactlyTheValidLists :=
  IdmapCore.validate_accepts_exactly_the_valid_lists_claim
example : IdmapCore.ValidListsAreFunctionsBothWays :=
  IdmapCore.valid_lists_are_functions_both_ways_claim
example : IdmapCore.FromIntervalsHasTheIdsOfTheIntervals :=
  IdmapCore.from_intervals_has_the_ids_of_the_intervals_claim
example : IdmapCore.OfParentIdsHasTheParentIds :=
  IdmapCore.of_parent_ids_has_the_parent_ids_claim
example : IdmapCore.OfContainerIdsHasTheContainerIds :=
  IdmapCore.of_container_ids_has_the_container_ids_claim
example : IdmapCore.SizeIsTheNumberOfIds :=
  IdmapCore.size_is_the_number_of_ids_claim
example : IdmapCore.UnionHasTheIdsOfBoth :=
  IdmapCore.union_has_the_ids_of_both_claim
example : IdmapCore.IsEmptyIsTrueExactlyForTheEmptySet :=
  IdmapCore.is_empty_is_true_exactly_for_the_empty_set_claim
example : IdmapCore.ContainsRangeIsTrueExactlyForARangeInTheSet :=
  IdmapCore.contains_range_is_true_exactly_for_a_range_in_the_set_claim
example : IdmapCore.SubtractHasTheIdsOfTheFirstNotInTheSecond :=
  IdmapCore.subtract_has_the_ids_of_the_first_not_in_the_second_claim
example : IdmapCore.BelowHasTheIdsUnderTheLimit :=
  IdmapCore.below_has_the_ids_under_the_limit_claim
example : IdmapCore.FindAvailableGivesNIdsOrSaysThereAreFewer :=
  IdmapCore.find_available_gives_n_ids_or_says_there_are_fewer_claim
example : IdmapCore.ZipMapsTheSecondSetOntoTheFirst :=
  IdmapCore.zip_maps_the_second_set_onto_the_first_claim
example : IdmapCore.KeepIdMapsExactlyTheLayout :=
  IdmapCore.keep_id_maps_exactly_the_layout_claim
example : IdmapCore.KeepIdUsesOnlyTheSubIds :=
  IdmapCore.keep_id_uses_only_the_sub_ids_claim
example : IdmapCore.KeepIdIsValid :=
  IdmapCore.keep_id_is_valid_claim
example : IdmapCore.RangeToParentAnswersForARangeInOneEntry :=
  IdmapCore.range_to_parent_answers_for_a_range_in_one_entry_claim
example : IdmapCore.RangeToParentAnswersWhenTheRangeIsInOneEntry :=
  IdmapCore.range_to_parent_answers_when_the_range_is_in_one_entry_claim
example : IdmapCore.SortAndMergeKeepsThePairs :=
  IdmapCore.sort_and_merge_keeps_the_pairs_claim
example : IdmapCore.SortAndMergeKeepsSaneApartEntries :=
  IdmapCore.sort_and_merge_keeps_sane_apart_entries_claim
example : IdmapCore.FillKeepsWhatTheMappingMaps :=
  IdmapCore.fill_keeps_what_the_mapping_maps_claim
example : IdmapCore.FillAddsOnlyFreeContainerIds :=
  IdmapCore.fill_adds_only_free_container_ids_claim
example : IdmapCore.FillMapsEveryFreeContainerIdWhenThereAreEnoughIds :=
  IdmapCore.fill_maps_every_free_container_id_when_there_are_enough_ids_claim
example : IdmapCore.AutoMapIsValid :=
  IdmapCore.auto_map_is_valid_claim
example : IdmapCore.AutoMapUsesOnlyFreeParentIds :=
  IdmapCore.auto_map_uses_only_free_parent_ids_claim
example : IdmapCore.AutoMapMapsTheContainerIdsAsked :=
  IdmapCore.auto_map_maps_the_container_ids_asked_claim
example : IdmapCore.AutoMapKeepsTheExtraMappings :=
  IdmapCore.auto_map_keeps_the_extra_mappings_claim
example : IdmapCore.AutoMapKeepsTheAutomaticPartApartFromTheExtraMappings :=
  IdmapCore.auto_map_keeps_the_automatic_part_apart_from_the_extra_mappings_claim
example : IdmapCore.AutoMapAnswersWhenTheFreeIdsBeginWithARun :=
  IdmapCore.auto_map_answers_when_the_free_ids_begin_with_a_run_claim
example : IdmapCore.AutoMapRefusesOnlyForAReason :=
  IdmapCore.auto_map_refuses_only_for_a_reason_claim
example : IdmapCore.SplitOnKeepsThePairs :=
  IdmapCore.split_on_keeps_the_pairs_claim
example : IdmapCore.BreakInsertMapsTheNewAndWhatItDoesNotTouch :=
  IdmapCore.break_insert_maps_the_new_and_what_it_does_not_touch_claim
example : IdmapCore.BreakInsertKeepsAFunctionBothWays :=
  IdmapCore.break_insert_keeps_a_function_both_ways_claim

#proved IdmapCore.validate_accepts_exactly_the_valid_lists_claim
#proved IdmapCore.valid_lists_are_functions_both_ways_claim
#proved IdmapCore.from_intervals_has_the_ids_of_the_intervals_claim
#proved IdmapCore.of_parent_ids_has_the_parent_ids_claim
#proved IdmapCore.of_container_ids_has_the_container_ids_claim
#proved IdmapCore.size_is_the_number_of_ids_claim
#proved IdmapCore.union_has_the_ids_of_both_claim
#proved IdmapCore.is_empty_is_true_exactly_for_the_empty_set_claim
#proved IdmapCore.contains_range_is_true_exactly_for_a_range_in_the_set_claim
#proved IdmapCore.subtract_has_the_ids_of_the_first_not_in_the_second_claim
#proved IdmapCore.below_has_the_ids_under_the_limit_claim
#proved IdmapCore.find_available_gives_n_ids_or_says_there_are_fewer_claim
#proved IdmapCore.zip_maps_the_second_set_onto_the_first_claim
#proved IdmapCore.keep_id_maps_exactly_the_layout_claim
#proved IdmapCore.keep_id_uses_only_the_sub_ids_claim
#proved IdmapCore.keep_id_is_valid_claim
#proved IdmapCore.range_to_parent_answers_for_a_range_in_one_entry_claim
#proved IdmapCore.range_to_parent_answers_when_the_range_is_in_one_entry_claim
#proved IdmapCore.sort_and_merge_keeps_the_pairs_claim
#proved IdmapCore.sort_and_merge_keeps_sane_apart_entries_claim
#proved IdmapCore.fill_keeps_what_the_mapping_maps_claim
#proved IdmapCore.fill_adds_only_free_container_ids_claim
#proved IdmapCore.fill_maps_every_free_container_id_when_there_are_enough_ids_claim
#proved IdmapCore.auto_map_is_valid_claim
#proved IdmapCore.auto_map_uses_only_free_parent_ids_claim
#proved IdmapCore.auto_map_maps_the_container_ids_asked_claim
#proved IdmapCore.auto_map_keeps_the_extra_mappings_claim
#proved IdmapCore.auto_map_keeps_the_automatic_part_apart_from_the_extra_mappings_claim
#proved IdmapCore.auto_map_answers_when_the_free_ids_begin_with_a_run_claim
#proved IdmapCore.auto_map_refuses_only_for_a_reason_claim
#proved IdmapCore.split_on_keeps_the_pairs_claim
#proved IdmapCore.break_insert_maps_the_new_and_what_it_does_not_touch_claim
#proved IdmapCore.break_insert_keeps_a_function_both_ways_claim
