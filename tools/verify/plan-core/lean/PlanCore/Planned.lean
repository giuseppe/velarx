-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: the invariant of the passes that make the groups (`Planned`): `slot`
-- says, for each content, the group it is in, and the groups list each content once, hold
-- only contents their layer is the home of, and have a file.  And that `add` followed by
-- writing the slot keeps it (`planned_added`).  From it follow: the contents of the groups are
-- all different (`listed_nodup`), a content is in a group exactly when its slot says so
-- (`mem_listed`), and there is room for one more group and file (`room_to_add`, so no push can
-- fail).
--
-- Why it is needed: P1 and P3 are this invariant at the end of the passes.
--
-- Read before this file: Spec.lean, Tables.lean and Add.lean.
--
-- Notation: as in Tables.lean; `Nodup l` is "no element is twice in `l`"; `l.Nodup`;
-- `slot.val[c.val]? = some (some g)` is "the slot of `c` holds the group `g`".
import PlanCore.Add

open Aeneas Aeneas.Std Result velarx_plan_core

namespace PlanCore

/-- The tables of planning once some contents are in groups: `slot` says, for each content, the
group it is in (if any), and the groups are as they should be. -/
structure Planned (layers : Slice (alloc.vec.Vec File)) (present : Slice Bool)
    (slot : alloc.vec.Vec (Option Std.Usize)) (groups : alloc.vec.Vec Group) : Prop where
  /-- The group a content is said to be in lists it. -/
  slot_group : ∀ (c : Std.U32) (g : Std.Usize), slot.val[c.val]? = some (some g) →
    ∃ group : Group, groups.val[g.val]? = some group ∧ c ∈ group.files.val
  /-- A content a group lists is said to be in that group. -/
  group_slot : ∀ (i : Nat) (group : Group), groups.val[i]? = some group →
    ∀ c ∈ group.files.val, ∃ g : Std.Usize, slot.val[c.val]? = some (some g) ∧ g.val = i
  /-- A group lists a content once. -/
  distinct : ∀ (i : Nat) (group : Group), groups.val[i]? = some group → group.files.val.Nodup
  /-- A content of a group is a content (below the number of contents) lacked by the layer of
  the group, which is the first to have it. -/
  grounded : ∀ (i : Nat) (group : Group), groups.val[i]? = some group →
    ∀ c ∈ group.files.val,
    c.val < slot.length ∧ Home layers present group.layer.val c
  /-- A group has a file. -/
  filled : ∀ (i : Nat) (group : Group), groups.val[i]? = some group → group.files.val ≠ []

/-- No layer waits for a group yet (`needed_by` is filled by the last pass). -/
def Unwaited (groups : alloc.vec.Vec Group) : Prop :=
  ∀ (i : Nat) (group : Group), groups.val[i]? = some group → group.needed_by.val = []

/-- The first content is put in a group: no groups, nothing in the slots. -/
theorem planned_start (layers : Slice (alloc.vec.Vec File)) (present : Slice Bool)
    (slot : alloc.vec.Vec (Option Std.Usize)) (empty : slot.val = List.replicate present.length none)
    (groups : alloc.vec.Vec Group) (none_yet : groups.val = []) :
    Planned layers present slot groups ∧ Unwaited groups := by
  refine ⟨⟨?_, ?_, ?_, ?_, ?_⟩, ?_⟩ <;> simp [Unwaited, empty, none_yet, List.getElem?_replicate]

/-- Which groups are changed by `add`, and what the changed one holds: the group `i` ends with
`pre ++ [c]` (`pre` is what it held, nothing for a new group), no other group changes, and all of `pre` is as
the tables say. -/
theorem added_shape {layers : Slice (alloc.vec.Vec File)} {present : Slice Bool}
    {slot : alloc.vec.Vec (Option Std.Usize)} {groups groups' : alloc.vec.Vec Group}
    {layer c : Std.U32} {i : Std.Usize}
    (planned : Planned layers present slot groups) (unwaited : Unwaited groups)
    (added : Added groups layer c i groups') :
    ∃ (pre : List Std.U32) (new : Group),
      (∀ j, j ≠ i.val → groups'.val[j]? = groups.val[j]?) ∧
      groups'.val[i.val]? = some new ∧ new.files.val = pre ++ [c] ∧ new.layer = layer ∧
      new.needed_by.val = [] ∧ pre.Nodup ∧
      (∀ group, groups.val[i.val]? = some group → group.files.val = pre) ∧
      ∀ c' ∈ pre, (∃ g, slot.val[c'.val]? = some (some g) ∧ g.val = i.val) ∧
        c'.val < slot.length ∧ Home layers present layer.val c' := by
  rcases added with ⟨old, new, old_is, old_layer, groups_is, new_files, new_layer, new_waits⟩ |
      ⟨at_end, new, groups_is, new_layer, new_files, new_waits⟩
  · have in_range := (List.getElem?_eq_some_iff.mp old_is).1
    refine ⟨old.files.val, new, ?_, ?_, new_files, by rw [new_layer, old_layer], ?_,
      planned.distinct _ old old_is, ?_, ?_⟩
    · intro j differs
      rw [groups_is]
      exact List.getElem?_set_ne (Ne.symm differs)
    · rw [groups_is]
      exact (List.getElem?_set_self in_range)
    · rw [new_waits]
      exact unwaited _ old old_is
    · intro group group_is
      rw [old_is] at group_is
      cases group_is
      rfl
    · intro c' member
      obtain ⟨g, slot_is, hg⟩ := planned.group_slot _ old old_is c' member
      obtain ⟨inside, home'⟩ := planned.grounded _ old old_is c' member
      rw [old_layer] at home'
      exact ⟨⟨g, slot_is, hg⟩, inside, home'⟩
  · refine ⟨[], new, ?_, ?_, by simpa using new_files, new_layer, new_waits, List.nodup_nil, ?_,
      by simp⟩
    · intro j differs
      rw [groups_is, List.getElem?_append]
      split
      · rfl
      · rename_i beyond
        have at_end' : i.val = groups.val.length := at_end
        rw [List.getElem?_eq_none (by simp; omega), List.getElem?_eq_none (by omega)]
    · rw [groups_is, at_end]
      simp
    · intro group group_is
      rw [at_end] at group_is
      simp at group_is

/-- The slots after a content `c` was put in a group: every content that had a group still has
one, and `c` has one. -/
def Fills (slot slot' : alloc.vec.Vec (Option Std.Usize)) (c : Std.U32) : Prop :=
  (∀ c' : Std.U32, (∃ g, slot.val[c'.val]? = some (some g)) →
    ∃ g, slot'.val[c'.val]? = some (some g)) ∧
  ∃ g, slot'.val[c.val]? = some (some g)

/-- A content that is in no group yet (its slot is empty) is put in a group, as `add` does, and
the slot of it says that group: the tables stay good. -/
theorem planned_added {layers : Slice (alloc.vec.Vec File)} {present : Slice Bool}
    {slot slot' : alloc.vec.Vec (Option Std.Usize)} {groups groups' : alloc.vec.Vec Group}
    {layer c : Std.U32} {i : Std.Usize}
    (planned : Planned layers present slot groups) (unwaited : Unwaited groups)
    (added : Added groups layer c i groups')
    (empty_slot : slot.val[c.val]? = some none) (home : Home layers present layer.val c)
    (inside : c.val < slot.length) (slot_is : slot'.val = slot.val.set c.val (some i)) :
    Planned layers present slot' groups' ∧ Unwaited groups' ∧ Fills slot slot' c := by
  obtain ⟨pre, new, other, at_i, new_files, new_layer, new_waits, pre_nodup, pre_is, pre_ok⟩ :=
    added_shape planned unwaited added
  have length_is : slot'.length = slot.length := by
    simp [alloc.vec.Vec.length, slot_is]
  have slot_c : slot'.val[c.val]? = some (some i) := by
    rw [slot_is]; exact List.getElem?_set_self inside
  have slot_else : ∀ c' : Std.U32, c' ≠ c → slot'.val[c'.val]? = slot.val[c'.val]? := by
    intro c' differs
    rw [slot_is]
    exact List.getElem?_set_ne (fun h => differs (UScalar.eq_of_val_eq h.symm))
  have not_in_pre : c ∉ pre := by
    intro member
    obtain ⟨⟨g, slot_is', -⟩, -⟩ := pre_ok c member
    rw [empty_slot] at slot_is'
    simp at slot_is'
  have not_empty : ∀ c' : Std.U32, ∀ g, slot.val[c'.val]? = some (some g) → c' ≠ c := by
    intro c' g found same
    subst same
    rw [empty_slot] at found
    simp at found
  refine ⟨⟨?_, ?_, ?_, ?_, ?_⟩, ?_, ?_, ⟨i, slot_c⟩⟩
  · -- the group a content is said to be in lists it
    intro c' g said
    by_cases same : c' = c
    · subst same
      rw [slot_c] at said
      cases said
      exact ⟨new, at_i, by rw [new_files]; simp⟩
    · rw [slot_else c' same] at said
      obtain ⟨group, group_is, member⟩ := planned.slot_group c' g said
      by_cases here : g.val = i.val
      · rw [here] at group_is
        refine ⟨new, by rw [here]; exact at_i, ?_⟩
        rw [new_files, ← pre_is group group_is]
        exact List.mem_append_left _ member
      · exact ⟨group, by rw [other _ here]; exact group_is, member⟩
  · -- a content a group lists is said to be in it
    intro j group group_is c' member
    by_cases here : j = i.val
    · subst here
      rw [at_i] at group_is
      cases group_is
      rw [new_files] at member
      rcases List.mem_append.mp member with member | member
      · obtain ⟨⟨g, said, hg⟩, -⟩ := pre_ok c' member
        have differs : c' ≠ c := fun same => not_in_pre (same ▸ member)
        exact ⟨g, by rw [slot_else c' differs]; exact said, hg⟩
      · rw [List.mem_singleton.mp member]
        exact ⟨i, slot_c, rfl⟩
    · rw [other _ here] at group_is
      obtain ⟨g, said, hg⟩ := planned.group_slot j group group_is c' member
      exact ⟨g, by rw [slot_else c' (not_empty c' g said)]; exact said, hg⟩
  · -- a group lists a content once
    intro j group group_is
    by_cases here : j = i.val
    · subst here
      rw [at_i] at group_is
      cases group_is
      rw [new_files]
      exact List.nodup_append.mpr ⟨pre_nodup, List.nodup_singleton _, 
        fun a ha b hb => by
          rw [List.mem_singleton.mp hb]
          exact fun same => not_in_pre (same ▸ ha)⟩
    · rw [other _ here] at group_is
      exact planned.distinct j group group_is
  · -- the contents of a group are contents its layer is the home of
    intro j group group_is c' member
    by_cases here : j = i.val
    · subst here
      rw [at_i] at group_is
      cases group_is
      rw [new_files] at member
      rw [new_layer]
      rcases List.mem_append.mp member with member | member
      · obtain ⟨-, inside', home'⟩ := pre_ok c' member
        exact ⟨by rw [length_is]; exact inside', home'⟩
      · rw [List.mem_singleton.mp member]
        exact ⟨by rw [length_is]; exact inside, home⟩
    · rw [other _ here] at group_is
      obtain ⟨inside', home'⟩ := planned.grounded j group group_is c' member
      exact ⟨by rw [length_is]; exact inside', home'⟩
  · -- a group has a file
    intro j group group_is
    by_cases here : j = i.val
    · subst here
      rw [at_i] at group_is
      cases group_is
      rw [new_files]
      simp
    · rw [other _ here] at group_is
      exact planned.filled j group group_is
  · -- no layer waits yet
    intro j group group_is
    by_cases here : j = i.val
    · subst here
      rw [at_i] at group_is
      cases group_is
      exact new_waits
    · rw [other _ here] at group_is
      exact unwaited j group group_is
  · -- every content that had a group still has it
    rintro c' ⟨g, said⟩
    exact ⟨g, by rw [slot_else c' (not_empty c' g said)]; exact said⟩

/-- A list of distinct contents below `n`, without `c`, which is below `n` too, has less than
`n` elements. -/
theorem nodup_length_lt (l : List Std.U32) (n : Nat) (distinct : l.Nodup)
    (below : ∀ x ∈ l, x.val < n) (c : Std.U32) (c_below : c.val < n) (absent : c ∉ l) :
    l.length < n := by
  have values : (l.map (·.val)).Nodup :=
    distinct.map (fun _ _ same => UScalar.eq_of_val_eq same)
  have within : l.map (·.val) ⊆ (List.range n).erase c.val := by
    intro y member
    obtain ⟨x, x_in, rfl⟩ := List.mem_map.mp member
    refine (List.mem_erase_of_ne ?_).mpr (List.mem_range.mpr (below x x_in))
    exact fun same => absent (UScalar.eq_of_val_eq same ▸ x_in)
  have := (values.subperm within).length_le
  rw [List.length_erase_of_mem (List.mem_range.mpr c_below), List.length_range,
    List.length_map] at this
  omega

/-- The contents of all the groups, one after the other, are distinct. -/
theorem listed_nodup {layers : Slice (alloc.vec.Vec File)} {present : Slice Bool}
    {slot : alloc.vec.Vec (Option Std.Usize)} {groups : alloc.vec.Vec Group}
    (planned : Planned layers present slot groups) : (listed groups).Nodup := by
  unfold listed
  rw [List.nodup_flatMap]
  refine ⟨fun group member => ?_, ?_⟩
  · obtain ⟨i, i_is⟩ := List.mem_iff_getElem?.mp member
    exact planned.distinct i group i_is
  · rw [List.pairwise_iff_getElem]
    intro i j i_in j_in order c in_i in_j
    obtain ⟨g, said, hg⟩ := planned.group_slot i _ (List.getElem?_eq_getElem i_in) c in_i
    obtain ⟨g', said', hg'⟩ := planned.group_slot j _ (List.getElem?_eq_getElem j_in) c in_j
    rw [said] at said'
    cases said'
    omega

/-- A content is in the groups exactly when its slot says a group. -/
theorem mem_listed {layers : Slice (alloc.vec.Vec File)} {present : Slice Bool}
    {slot : alloc.vec.Vec (Option Std.Usize)} {groups : alloc.vec.Vec Group}
    (planned : Planned layers present slot groups) (c : Std.U32) :
    c ∈ listed groups ↔ ∃ g, slot.val[c.val]? = some (some g) := by
  constructor
  · intro member
    obtain ⟨group, group_in, member⟩ := List.mem_flatMap.mp member
    obtain ⟨i, i_is⟩ := List.mem_iff_getElem?.mp group_in
    obtain ⟨g, said, -⟩ := planned.group_slot i group i_is c member
    exact ⟨g, said⟩
  · rintro ⟨g, said⟩
    obtain ⟨group, group_is, member⟩ := planned.slot_group c g said
    exact List.mem_flatMap.mpr ⟨group, List.mem_of_getElem? group_is, member⟩

/-- There is room for one more group, and one more file in a group, when a content has no
slot: there are less groups than contents, and less files in a group. -/
theorem room_to_add {layers : Slice (alloc.vec.Vec File)} {present : Slice Bool}
    {slot : alloc.vec.Vec (Option Std.Usize)} {groups : alloc.vec.Vec Group}
    (planned : Planned layers present slot groups) (c : Std.U32)
    (inside : c.val < slot.length) (empty_slot : slot.val[c.val]? = some none) :
    (∀ group ∈ groups.val, group.files.length < Std.Usize.max) ∧
      groups.length < Std.Usize.max := by
  have max := slot.property
  have unplanned : ∀ group ∈ groups.val, c ∉ group.files.val := by
    intro group member listed_in
    obtain ⟨i, i_is⟩ := List.mem_iff_getElem?.mp member
    obtain ⟨g, said, -⟩ := planned.group_slot i group i_is c listed_in
    rw [empty_slot] at said
    simp at said
  refine ⟨fun group member => ?_, ?_⟩
  · obtain ⟨i, i_is⟩ := List.mem_iff_getElem?.mp member
    have := nodup_length_lt group.files.val slot.length (planned.distinct i group i_is)
      (fun x x_in => (planned.grounded i group i_is x x_in).1) c inside (unplanned group member)
    simp only [alloc.vec.Vec.length] at this ⊢
    omega
  · have not_listed : c ∉ listed groups := fun member => by
      obtain ⟨g, said⟩ := (mem_listed planned c).mp member
      rw [empty_slot] at said
      simp at said
    have fewer := nodup_length_lt (listed groups) slot.length (listed_nodup planned)
      (fun x x_in => by
        obtain ⟨group, group_in, member⟩ := List.mem_flatMap.mp x_in
        obtain ⟨i, i_is⟩ := List.mem_iff_getElem?.mp group_in
        exact (planned.grounded i group i_is x member).1) c inside not_listed
    have each : ∀ group ∈ groups.val, 1 ≤ group.files.val.length := by
      intro group member
      obtain ⟨i, i_is⟩ := List.mem_iff_getElem?.mp member
      exact List.length_pos_iff.mpr (planned.filled i group i_is)
    have : groups.val.length ≤ (listed groups).length := by
      unfold listed
      rw [List.length_flatMap]
      have := List.length_le_sum_of_one_le (groups.val.map (fun group => group.files.val.length))
        (fun x x_in => by
          obtain ⟨group, group_in, rfl⟩ := List.mem_map.mp x_in
          exact each group group_in)
      simpa using this
    simp only [alloc.vec.Vec.length] at fewer max ⊢
    omega

end PlanCore
