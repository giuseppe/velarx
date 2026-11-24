-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: the proof of each statement of Spec.lean, from the theorems of the files
-- before it (each is named for what it says).
--
-- Read before this file: Spec.lean.
import IdmapCore.Validate
import IdmapCore.ValidMeansFunction
import IdmapCore.OfMaps
import IdmapCore.IdSetSize
import IdmapCore.IdSetUnion
import IdmapCore.KeepIdClaims
import IdmapCore.RangeToParent
import IdmapCore.AutoMap
import IdmapCore.IdSetContains
import IdmapCore.Fill
import IdmapCore.SplitOn
import IdmapCore.BreakInsert

namespace IdmapCore

/-- Proof of `ValidateAcceptsExactlyTheValidLists`. -/
theorem validate_accepts_exactly_the_valid_lists_claim : ValidateAcceptsExactlyTheValidLists :=
  validate_accepts_exactly_the_valid_lists

/-- Proof of `ValidListsAreFunctionsBothWays`. -/
theorem valid_lists_are_functions_both_ways_claim : ValidListsAreFunctionsBothWays :=
  valid_lists_are_functions_both_ways

/-- Proof of `FromIntervalsHasTheIdsOfTheIntervals`. -/
theorem from_intervals_has_the_ids_of_the_intervals_claim :
    FromIntervalsHasTheIdsOfTheIntervals :=
  from_intervals_is_the_union

/-- Proof of `OfParentIdsHasTheParentIds`. -/
theorem of_parent_ids_has_the_parent_ids_claim : OfParentIdsHasTheParentIds :=
  of_parent_ids_has_the_parent_ids

/-- Proof of `OfContainerIdsHasTheContainerIds`. -/
theorem of_container_ids_has_the_container_ids_claim : OfContainerIdsHasTheContainerIds :=
  of_container_ids_has_the_container_ids

/-- Proof of `SizeIsTheNumberOfIds`. -/
theorem size_is_the_number_of_ids_claim : SizeIsTheNumberOfIds :=
  size_is_the_number_of_ids

/-- Proof of `UnionHasTheIdsOfBoth`. -/
theorem union_has_the_ids_of_both_claim : UnionHasTheIdsOfBoth :=
  union_has_the_ids_of_both

/-- Proof of `KeepIdMapsExactlyTheLayout`. -/
theorem keep_id_maps_exactly_the_layout_claim : KeepIdMapsExactlyTheLayout :=
  keep_id_maps_the_layout

/-- Proof of `KeepIdUsesOnlyTheSubIds`. -/
theorem keep_id_uses_only_the_sub_ids_claim : KeepIdUsesOnlyTheSubIds :=
  keep_id_uses_only_the_sub_ids

/-- Proof of `KeepIdIsValid`. -/
theorem keep_id_is_valid_claim : KeepIdIsValid :=
  keep_id_is_valid

/-- Proof of `RangeToParentAnswersForARangeInOneEntry`. -/
theorem range_to_parent_answers_for_a_range_in_one_entry_claim :
    RangeToParentAnswersForARangeInOneEntry :=
  an_answer_comes_from_an_entry

/-- Proof of `RangeToParentAnswersWhenTheRangeIsInOneEntry`. -/
theorem range_to_parent_answers_when_the_range_is_in_one_entry_claim :
    RangeToParentAnswersWhenTheRangeIsInOneEntry :=
  fun maps start len valid e e_in has fits =>
    an_entry_with_the_range_gives_the_answer maps start len valid e e_in has fits

/-- Proof of `SortAndMergeKeepsThePairs`. -/
theorem sort_and_merge_keeps_the_pairs_claim : SortAndMergeKeepsThePairs :=
  fun maps => Aeneas.Std.WP.spec_mono (sort_and_merge_keeps_the_pairs maps) (fun _ h => h.1)

/-- Proof of `SortAndMergeKeepsSaneApartEntries`. -/
theorem sort_and_merge_keeps_sane_apart_entries_claim : SortAndMergeKeepsSaneApartEntries :=
  fun maps => Aeneas.Std.WP.spec_mono (sort_and_merge_keeps_the_pairs maps) (fun _ h => h.2.1)

/-- Proof of `AutoMapIsValid`. -/
theorem auto_map_is_valid_claim : AutoMapIsValid :=
  fun size pool used extra ⟨pool_ordered, used_ordered, fits, wide⟩ =>
    Aeneas.Std.WP.spec_mono (auto_map_answers_with_what_it_promises size pool used extra
      pool_ordered used_ordered fits wide) (fun _ h m is_m => (h.1 m is_m).1)

/-- Proof of `AutoMapUsesOnlyFreeParentIds`. -/
theorem auto_map_uses_only_free_parent_ids_claim : AutoMapUsesOnlyFreeParentIds :=
  fun size pool used extra ⟨pool_ordered, used_ordered, fits, wide⟩ =>
    Aeneas.Std.WP.spec_mono (auto_map_answers_with_what_it_promises size pool used extra
      pool_ordered used_ordered fits wide)
      (fun _ h m is_m c p is_map => (h.1 m is_m).2.1 c p is_map)

/-- Proof of `AutoMapMapsTheContainerIdsAsked`. -/
theorem auto_map_maps_the_container_ids_asked_claim : AutoMapMapsTheContainerIdsAsked :=
  fun size pool used extra ⟨pool_ordered, used_ordered, fits, wide⟩ =>
    Aeneas.Std.WP.spec_mono (auto_map_answers_with_what_it_promises size pool used extra
      pool_ordered used_ordered fits wide)
      (fun _ h m is_m => ⟨(h.1 m is_m).2.2.1, (h.1 m is_m).2.2.2.1⟩)

/-- Proof of `AutoMapKeepsTheExtraMappings`. -/
theorem auto_map_keeps_the_extra_mappings_claim : AutoMapKeepsTheExtraMappings :=
  fun size pool used extra ⟨pool_ordered, used_ordered, fits, wide⟩ =>
    Aeneas.Std.WP.spec_mono (auto_map_answers_with_what_it_promises size pool used extra
      pool_ordered used_ordered fits wide) (fun _ h m is_m => (h.1 m is_m).2.2.2.2)

/-- Proof of `AutoMapKeepsTheAutomaticPartApartFromTheExtraMappings`. -/
theorem auto_map_keeps_the_automatic_part_apart_from_the_extra_mappings_claim :
    AutoMapKeepsTheAutomaticPartApartFromTheExtraMappings :=
  fun size pool used extra ⟨pool_ordered, used_ordered, fits, wide⟩ =>
    Aeneas.Std.WP.spec_mono (auto_map_answers_with_what_it_promises size pool used extra
      pool_ordered used_ordered fits wide) (fun _ h m is_m =>
        the_automatic_part_is_apart_from_the_extra _ _ _ _ _ (h.1 m is_m))

/-- Proof of `AutoMapRefusesOnlyForAReason`. -/
theorem auto_map_refuses_only_for_a_reason_claim : AutoMapRefusesOnlyForAReason :=
  fun size pool used extra ⟨pool_ordered, used_ordered, fits, wide⟩ =>
    Aeneas.Std.WP.spec_mono (auto_map_answers_with_what_it_promises size pool used extra
      pool_ordered used_ordered fits wide) (fun _ h => h.2.1)

/-- Proof of `AutoMapAnswersWhenTheFreeIdsBeginWithARun`. -/
theorem auto_map_answers_when_the_free_ids_begin_with_a_run_claim :
    AutoMapAnswersWhenTheFreeIdsBeginWithARun :=
  fun size pool used extra ⟨pool_ordered, used_ordered, fits, wide⟩ no_extra run =>
    Aeneas.Std.WP.spec_mono (auto_map_answers_with_what_it_promises size pool used extra
      pool_ordered used_ordered fits wide) (fun _ h => h.2.2 no_extra run)

/-- Proof of `IsEmptyIsTrueExactlyForTheEmptySet`. -/
theorem is_empty_is_true_exactly_for_the_empty_set_claim : IsEmptyIsTrueExactlyForTheEmptySet :=
  is_empty_is_true_for_the_empty_set

/-- Proof of `ContainsRangeIsTrueExactlyForARangeInTheSet`. -/
theorem contains_range_is_true_exactly_for_a_range_in_the_set_claim :
    ContainsRangeIsTrueExactlyForARangeInTheSet :=
  fun s start len ordered => contains_range_is_true_for_a_range_in_the_set s start len ordered

/-- Proof of `SubtractHasTheIdsOfTheFirstNotInTheSecond`. -/
theorem subtract_has_the_ids_of_the_first_not_in_the_second_claim :
    SubtractHasTheIdsOfTheFirstNotInTheSecond :=
  fun a b a_ordered b_ordered fits =>
    Aeneas.Std.WP.spec_mono
      (subtract_has_the_ids_of_the_first_not_in_the_second a b a_ordered b_ordered fits)
      (fun _ h => ⟨h.1, h.2.1⟩)

/-- Proof of `BelowHasTheIdsUnderTheLimit`. -/
theorem below_has_the_ids_under_the_limit_claim : BelowHasTheIdsUnderTheLimit :=
  fun s limit ordered =>
    Aeneas.Std.WP.spec_mono (below_is_the_ids_under_the_limit s limit ordered)
      (fun _ h => ⟨h.1, h.2.1⟩)

/-- Proof of `FindAvailableGivesNIdsOrSaysThereAreFewer`. -/
theorem find_available_gives_n_ids_or_says_there_are_fewer_claim :
    FindAvailableGivesNIdsOrSaysThereAreFewer :=
  fun s n ordered =>
    Aeneas.Std.WP.spec_mono (find_available_gives_n_ids_or_says_there_are_fewer s n ordered)
      (fun answer h => by
        cases answer with
        | some t => exact ⟨h.1, h.2.1, h.2.2.1⟩
        | none => exact ⟨Total s.intervals.val, ordered_runs_have_total_ids _ ordered, h⟩)

/-- Proof of `ZipMapsTheSecondSetOntoTheFirst`. -/
theorem zip_maps_the_second_set_onto_the_first_claim : ZipMapsTheSecondSetOntoTheFirst :=
  fun a b a_ordered b_ordered =>
    Aeneas.Std.WP.spec_mono (zip_pairs_the_ids_in_order a b a_ordered b_ordered)
      (fun _ h => ⟨h.1, h.2.1, h.2.2.1, h.2.2.2.1, h.2.2.2.2.1⟩)

/-- Proof of `FillKeepsWhatTheMappingMaps`. -/
theorem fill_keeps_what_the_mapping_maps_claim : FillKeepsWhatTheMappingMaps :=
  fun idmap available ⟨ordered, few, wide⟩ =>
    Aeneas.Std.WP.spec_mono (fill_adds_the_free_container_ids idmap available ordered few wide)
      (fun _ h => h.1)

/-- Proof of `FillAddsOnlyFreeContainerIds`. -/
theorem fill_adds_only_free_container_ids_claim : FillAddsOnlyFreeContainerIds :=
  fun idmap available ⟨ordered, few, wide⟩ =>
    Aeneas.Std.WP.spec_mono (fill_adds_the_free_container_ids idmap available ordered few wide)
      (fun _ h => h.2.1)

/-- Proof of `FillMapsEveryFreeContainerIdWhenThereAreEnoughIds`. -/
theorem fill_maps_every_free_container_id_when_there_are_enough_ids_claim :
    FillMapsEveryFreeContainerIdWhenThereAreEnoughIds :=
  fun idmap available ⟨ordered, few, wide⟩ =>
    Aeneas.Std.WP.spec_mono (fill_adds_the_free_container_ids idmap available ordered few wide)
      (fun _ h => h.2.2)

/-- Proof of `SplitOnKeepsThePairs`. -/
theorem split_on_keeps_the_pairs_claim : SplitOnKeepsThePairs :=
  fun maps parent ⟨few, wide⟩ =>
    Aeneas.Std.WP.spec_mono (split_on_keeps_the_pairs maps parent few (by simpa using wide))
      (fun _ h c p => h c p)

/-- Proof of `BreakInsertMapsTheNewAndWhatItDoesNotTouch`. -/
theorem break_insert_maps_the_new_and_what_it_does_not_touch_claim :
    BreakInsertMapsTheNewAndWhatItDoesNotTouch :=
  fun mapping ext room =>
    Aeneas.Std.WP.spec_mono (break_insert_maps_the_new_and_what_is_left mapping ext room)
      (fun _ h c p => h c p)

/-- Proof of `BreakInsertKeepsAFunctionBothWays`. -/
theorem break_insert_keeps_a_function_both_ways_claim : BreakInsertKeepsAFunctionBothWays :=
  fun mapping ext room valid => break_insert_makes_a_function_both_ways mapping ext room valid

end IdmapCore
