-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: the proofs of the three claims of Spec.lean.  `plan_tables` follows `plan`
-- from the top, one loop at a time, with the lemma of each loop (Tables.lean, Loops.lean,
-- Waits.lean); the claims then read what they need from what it leaves.
--
-- Why it is needed: each claim is a statement about the groups `plan` returns; the work is in
-- the loops, and this file is where they are put together.
--
-- Read before this file: Spec.lean, then the other files in this directory.
--
-- Notation: as in Tables.lean; `refine WP.spec_mono (h) ?_` is "use the result `h` about `plan`,
-- and show that what it says is enough".
import PlanCore.Waits

open Aeneas Aeneas.Std Result velarx_plan_core

namespace PlanCore

/-- Nothing was seen before the first position. -/
theorem nothing_before_the_start {layers : Slice (alloc.vec.Vec File)}
    (P : Nat → Std.U32 → Prop) : ¬ Before layers 0 0 P := by
  rintro ⟨k, t, i, x, -, -, -, hk⟩
  omega

/-- What `plan` leaves behind, for the three claims: the groups, and the slots (the group each
content is in), such that the tables are good, every content some layer has that is not present
has a group, and each group waits for the layers that have a file it lists. -/
theorem plan_tables (layers : Slice (alloc.vec.Vec File)) (present : Slice Bool)
    (profile : Slice Std.U32) (limits : Limits) (fits : Fits layers present profile) :
    plan layers present profile limits ⦃ groups =>
      ∃ slot : alloc.vec.Vec (Option Std.Usize),
        slot.length = present.length ∧ Planned layers present slot groups ∧
        Covered layers present layers.length 0 slot ∧
        ∀ (j : Nat) (group : Group), groups.val[j]? = some group →
          Waits layers layers.length 0 group ⦄ := by
  obtain ⟨many, named, profiled⟩ := fits
  unfold plan
  step as ⟨ home, slot, hhome, hslot ⟩
  · simp
  · simp
  have home_size : home.length = present.length := by simp [alloc.vec.Vec.length, hhome]
  have slot_size : slot.length = present.length := by simp [alloc.vec.Vec.length, hslot]
  step as ⟨ home1, home1_size, home1_table ⟩
  · intro c hc
    have : home.val[c.val]? = some none := by rw [hhome]; simp [← home_size, hc]
    refine ⟨⟨fun _ => nothing_before_the_start _, fun _ => ?_⟩, fun k s h => ?_⟩
    · exact this
    · rw [this] at h; simp at h
  obtain ⟨planned0, unwaited0⟩ := planned_start layers present slot hslot (alloc.vec.Vec.new Group) rfl
  step as ⟨ slot1, groups, grown1, planned1, unwaited1 ⟩
  step as ⟨ slot2, groups1, grown2, planned2, unwaited2, covered2 ⟩
  · intro c _ _ seen
    exact (nothing_before_the_start _ seen).elim
  have : ∀ (j : Nat) (group : Group), groups1.val[j]? = some group →
      Waits layers (0#u32).val 0 group := by
    intro j group group_is
    refine ⟨?_, fun k => ⟨fun member => ?_, fun seen => (nothing_before_the_start _ seen).elim⟩⟩
    · rw [unwaited2 j group group_is]; simp
    · rw [unwaited2 j group group_is] at member; simp at member
  step as ⟨ groups2, planned3, waiting3 ⟩
  exact ⟨slot2, by rw [grown2, grown1, slot_size], planned3, covered2, waiting3⟩

/-- A layer that has a file with content `c`, `c` before the end of the tables. -/
theorem seen_of_has {layers : Slice (alloc.vec.Vec File)} {l : Nat} {c : Std.U32}
    (has : Has layers l c) (P : Nat → Std.U32 → Prop) (holds : P l c) :
    Before layers layers.length 0 P := by
  obtain ⟨table, table_is, file, member, rfl⟩ := has
  obtain ⟨i, file_is⟩ := List.mem_iff_getElem?.mp member
  exact ⟨l, table, i, file, table_is, file_is, holds,
    Or.inl (List.getElem?_eq_some_iff.mp table_is).1⟩

/-- **P1** is proved. -/
theorem every_lacked_content_is_planned_once : EveryLackedContentIsPlannedOnce := by
  intro layers present profile limits fits
  refine WP.spec_mono (plan_tables layers present profile limits fits) ?_
  rintro groups ⟨slot, slot_size, planned, covered, -⟩
  refine ⟨fun l c lacks => ?_, fun c member => ?_⟩
  · obtain ⟨has, not_present⟩ := lacks
    have inside : c.val < present.length := (List.getElem?_eq_some_iff.mp not_present).1
    obtain ⟨g, said⟩ := covered c (by rw [slot_size]; exact inside) not_present
      (seen_of_has has (fun _ c' => c' = c) rfl)
    exact List.count_eq_one_of_mem (listed_nodup planned) ((mem_listed planned c).mpr ⟨g, said⟩)
  · obtain ⟨group, group_in, member⟩ := List.mem_flatMap.mp member
    obtain ⟨j, group_is⟩ := List.mem_iff_getElem?.mp group_in
    exact ⟨_, (planned.grounded j group group_is c member).2.1⟩

/-- **P3** is proved. -/
theorem a_group_is_fetched_into_the_home_of_its_files : AGroupIsFetchedIntoTheHomeOfItsFiles := by
  intro layers present profile limits fits
  refine WP.spec_mono (plan_tables layers present profile limits fits) ?_
  rintro groups ⟨slot, -, planned, -, -⟩ group group_in c member
  obtain ⟨j, group_is⟩ := List.mem_iff_getElem?.mp group_in
  exact (planned.grounded j group group_is c member).2

/-- **P2** is proved. -/
theorem a_group_is_waited_for_by_who_lacks_its_files : AGroupIsWaitedForByWhoLacksItsFiles := by
  intro layers present profile limits fits
  refine WP.spec_mono (plan_tables layers present profile limits fits) ?_
  rintro groups ⟨slot, -, planned, -, waiting⟩ group group_in
  obtain ⟨j, group_is⟩ := List.mem_iff_getElem?.mp group_in
  have waits := waiting j group group_is
  have lacked := fun c member => (planned.grounded j group group_is c member).2.1
  have in_range : ∀ k (c : Std.U32), c ∈ group.files.val → Has layers k c →
      k ∈ group.needed_by.val.map (·.val) := fun k c member has =>
    (waits.2 k).mpr (seen_of_has has (fun k' c' => k' = k ∧ c' ∈ group.files.val) ⟨rfl, member⟩)
  refine ⟨?_, waits.1, fun k => ⟨fun waited => ?_, fun ⟨c, member, lacks⟩ => ?_⟩⟩
  · obtain ⟨c, member⟩ := List.exists_mem_of_ne_nil _ (planned.filled j group group_is)
    have layer_has := (lacked c member).1
    intro empty
    have := in_range _ c member layer_has
    rw [empty] at this
    simp at this
  · obtain ⟨k', t, i, x, kt, it, ⟨rfl, member⟩, -⟩ := (waits.2 k).mp waited
    exact ⟨x.content, member, ⟨t, kt, x, List.mem_of_getElem? it, rfl⟩,
      (lacked x.content member).2⟩
  · exact in_range k c member lacks.1

end PlanCore
