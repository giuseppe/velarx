-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: the last pass of `plan`: for each file of each layer, in order, the layer
-- is added at the end of `needed_by` of the group of that content, unless it is already the
-- last (`wait_for`).  The invariant (`Waits`) is: what `needed_by` holds after the files before a
-- position are the layers that have a file before it whose content the group lists, strictly
-- ascending.  Changing `needed_by` leaves the rest of the groups as they are (`Shape`).
--
-- Why it is needed: this is P2.  Ascending and once each is why a layer is pushed only when it
-- is not the last: the layers come in order, a layer's files one after the other.
--
-- Read before this file: Planned.lean and Loops.lean.
--
-- Notation: as in Tables.lean; `l.Pairwise (· < ·)` is "each element is below all that follow";
-- `{ group with needed_by := w }` is the group with only `needed_by` changed.
import PlanCore.Loops

open Aeneas Aeneas.Std Result velarx_plan_core

namespace PlanCore

/-- The code that makes layer `l` wait for the group `g`: it adds `l` at the end of the layers of
the group, unless `l` is the last one already. -/
theorem wait_for (groups : alloc.vec.Vec Group) (g : Std.Usize) (l : Std.U32) (group : Group)
    (group_is : groups.val[g.val]? = some group)
    (room : group.needed_by.val.getLast? ≠ some l → group.needed_by.length < Std.Usize.max) :
    (do let (g1, index_mut_back) ← groups.index_mut_usize g
        let n := alloc.vec.Vec.len g1.needed_by
        if n = 0#usize then
          do let waits ← alloc.vec.Vec.push g1.needed_by l
             ok (index_mut_back { g1 with needed_by := waits })
        else
          do let i4 ← n - 1#usize
             let i5 ← g1.needed_by.index_usize i4
             if i5 != l then
               do let waits ← alloc.vec.Vec.push g1.needed_by l
                  ok (index_mut_back { g1 with needed_by := waits })
             else ok (index_mut_back g1)) ⦃ r =>
      ∃ waits : alloc.vec.Vec Std.U32,
        r.val = groups.val.set g.val { group with needed_by := waits } ∧
        ((group.needed_by.val.getLast? = some l ∧ waits = group.needed_by) ∨
         (group.needed_by.val.getLast? ≠ some l ∧ waits.val = group.needed_by.val ++ [l])) ⦄ := by
  have inside : g.val < groups.length := (List.getElem?_eq_some_iff.mp group_is).1
  have found : groups.val[g.val] = group := by
    have := (List.getElem?_eq_some_iff.mp group_is).2; exact this
  step as ⟨ old, back, hold, hback ⟩
  rw [found] at hold
  subst hold hback
  have len_val : (alloc.vec.Vec.len old.needed_by).val = old.needed_by.val.length := rfl
  by_cases empty : alloc.vec.Vec.len old.needed_by = 0#usize
  · simp only [empty, ↓reduceIte]
    have none_yet : old.needed_by.val = [] := by
      have := congrArg UScalar.val empty
      rw [len_val] at this
      exact List.length_eq_zero_iff.mp this
    step as ⟨ waits, hwaits ⟩
    exact ⟨waits, by simp, Or.inr ⟨by simp [none_yet], hwaits⟩⟩
  · simp only [empty, ↓reduceIte]
    have nonempty : old.needed_by.val.length ≠ 0 := fun h => empty (by
      apply UScalar.eq_of_val_eq; rw [len_val, h]; rfl)
    step as ⟨ i4, hi4 ⟩
    have last_is : i4.val < old.needed_by.val.length := by rw [hi4, len_val]; omega
    step as ⟨ i5, hi5 ⟩
    have last : old.needed_by.val.getLast? = some i5 := by
      rw [List.getLast?_eq_getElem?, show old.needed_by.val.length - 1 = i4.val by rw [hi4, len_val],
        List.getElem?_eq_getElem last_is, hi5]
    by_cases differs : (i5 != l) = true
    · simp only [differs, ↓reduceIte]
      have last_differs : old.needed_by.val.getLast? ≠ some l := by
        rw [last]; intro same; simp at differs; exact differs (congrArg UScalar.val (Option.some.inj same))
      have := room last_differs
      step as ⟨ waits, hwaits ⟩
      exact ⟨waits, by simp, Or.inr ⟨last_differs, hwaits⟩⟩
    · simp only [differs, Bool.false_eq_true, ↓reduceIte]
      simp at differs
      refine (WP.spec_ok _).mpr ?_
      refine ⟨old.needed_by, by simp, Or.inl ⟨?_, rfl⟩⟩
      rw [last, UScalar.eq_of_val_eq differs]

/-- What `needed_by` of a group holds once the files before the position (`l`, `f`) were read:
the layers that have a file before that position whose content the group lists, strictly
ascending. -/
def Waits (layers : Slice (alloc.vec.Vec File)) (l f : Nat) (group : Group) : Prop :=
  (group.needed_by.val.map (·.val)).Pairwise (· < ·) ∧
  ∀ k, k ∈ group.needed_by.val.map (·.val) ↔
    Before layers l f (fun k' c' => k' = k ∧ c' ∈ group.files.val)

/-- The layers a group waits for are not after the layer being read. -/
theorem waits_bounded {layers : Slice (alloc.vec.Vec File)} {l f : Nat} {group : Group}
    (waits : Waits layers l f group) : ∀ k ∈ group.needed_by.val.map (·.val), k ≤ l := by
  intro k member
  obtain ⟨k', t, i, x, -, -, ⟨rfl, -⟩, hk⟩ := (waits.2 k).mp member
  omega

/-- A file whose content the group does not list changes nothing in what the group waits for. -/
theorem waits_step_other {layers : Slice (alloc.vec.Vec File)} {l f : Nat}
    {table : alloc.vec.Vec File} {file : File} (table_is : layers.val[l]? = some table)
    (file_is : table.val[f]? = some file) {group : Group} (waits : Waits layers l f group)
    (other : file.content ∉ group.files.val) : Waits layers l (f + 1) group := by
  refine ⟨waits.1, fun k => ?_⟩
  rw [waits.2 k, before_step table_is file_is]
  constructor
  · exact Or.inl
  · rintro (before | ⟨-, member⟩)
    · exact before
    · exact (other member).elim

/-- When the last layer a group waits for is not `layer`, which is the layer read, all of them
are below it. -/
theorem waits_below {layers : Slice (alloc.vec.Vec File)} {l f : Nat} {group : Group}
    (waits : Waits layers l f group) (layer : Std.U32) (layer_is : layer.val = l)
    (last : group.needed_by.val.getLast? ≠ some layer) :
    ∀ x ∈ group.needed_by.val.map (·.val), x < l := by
  have bounded := waits_bounded waits
  rcases List.eq_nil_or_concat group.needed_by.val with empty | ⟨init, b, hnb⟩
  · simp [empty]
  · rw [List.concat_eq_append] at hnb
    have ascending := waits.1
    rw [hnb] at last bounded ascending ⊢
    have b_ne : b.val ≠ l := by
      intro same
      apply last
      rw [List.getLast?_concat]
      exact congrArg some (UScalar.eq_of_val_eq (same.trans layer_is.symm))
    have b_le : b.val ≤ l := bounded b.val (by simp)
    rw [List.map_append, List.pairwise_append] at ascending
    intro x member
    rw [List.map_append, List.mem_append] at member
    rcases member with member | member
    · have := ascending.2.2 x member b.val (by simp)
      omega
    · have : x = b.val := by simpa using member
      omega

/-- A group that waits only for layers below `l` waits for at most `l` of them. -/
theorem waits_few {layers : Slice (alloc.vec.Vec File)} {l f : Nat} {group : Group}
    (waits : Waits layers l f group) (below : ∀ x ∈ group.needed_by.val.map (·.val), x < l) :
    group.needed_by.length ≤ l := by
  have distinct : (group.needed_by.val.map (·.val)).Nodup := waits.1.imp (fun h => Nat.ne_of_lt h)
  have within : group.needed_by.val.map (·.val) ⊆ List.range l :=
    fun x member => List.mem_range.mpr (below x member)
  have := (distinct.subperm within).length_le
  simpa using this

/-- A file whose content the group lists makes its layer wait for it, once. -/
theorem waits_step_listed {layers : Slice (alloc.vec.Vec File)} {l f : Nat}
    {table : alloc.vec.Vec File} {file : File} (table_is : layers.val[l]? = some table)
    (file_is : table.val[f]? = some file) {group : Group} (waits : Waits layers l f group)
    (listed : file.content ∈ group.files.val) (layer : Std.U32) (layer_is : layer.val = l)
    (waits' : alloc.vec.Vec Std.U32)
    (made : (group.needed_by.val.getLast? = some layer ∧ waits' = group.needed_by) ∨
      (group.needed_by.val.getLast? ≠ some layer ∧ waits'.val = group.needed_by.val ++ [layer])) :
    Waits layers l (f + 1) { group with needed_by := waits' } := by
  have bounded := waits_bounded waits
  rcases made with ⟨last, rfl⟩ | ⟨last, pushed⟩
  · refine ⟨waits.1, fun k => ?_⟩
    simp only
    rw [waits.2 k, before_step table_is file_is]
    constructor
    · exact Or.inl
    · rintro (before | ⟨rfl, -⟩)
      · exact before
      · rw [← waits.2]
        exact List.mem_map.mpr ⟨layer, List.mem_of_getLast? last, layer_is⟩
  · -- every layer waited for so far is below `l`, since the last one is not `l`
    have below := waits_below waits layer layer_is last
    refine ⟨?_, fun k => ?_⟩
    · simp only [pushed, List.map_append, List.pairwise_append]
      refine ⟨waits.1, by simp, fun x member y yin => ?_⟩
      have := below x member
      simp at yin
      omega
    · simp only [pushed, List.map_append, List.mem_append, List.map_singleton, List.mem_singleton]
      rw [waits.2 k, before_step table_is file_is]
      constructor
      · rintro (before | rfl)
        · exact Or.inl before
        · exact Or.inr ⟨layer_is.symm, listed⟩
      · rintro (before | ⟨rfl, -⟩)
        · exact Or.inl before
        · exact Or.inr layer_is.symm

/-- The groups `groups'` have, in each place, the files and the layer the groups `groups` have
(only `needed_by` may differ). -/
abbrev Shape (groups groups' : alloc.vec.Vec Group) : Prop :=
  ∀ j : Nat, (groups'.val[j]?).map (fun (x : Group) => (x.files, x.layer)) =
    (groups.val[j]?).map (fun (x : Group) => (x.files, x.layer))

/-- A group in one list is in the other, with the same files and layer. -/
theorem Shape.get {groups groups' : alloc.vec.Vec Group} (shape : Shape groups groups')
    {j : Nat} {group : Group} (group_is : groups.val[j]? = some group) :
    ∃ group', groups'.val[j]? = some group' ∧ group'.files = group.files ∧
      group'.layer = group.layer := by
  have := shape j
  rw [group_is] at this
  cases h : groups'.val[j]? with
  | none => rw [h] at this; simp at this
  | some group' =>
    rw [h] at this
    simp only [Option.map_some, Option.some.injEq, Prod.mk.injEq] at this
    exact ⟨group', rfl, this⟩

/-- `Shape` is symmetric. -/
theorem Shape.symm {groups groups' : alloc.vec.Vec Group} (shape : Shape groups groups') :
    Shape groups' groups := fun j => (shape j).symm

/-- Changing only the layers some groups wait for keeps the tables. -/
theorem planned_of_shape {layers : Slice (alloc.vec.Vec File)} {present : Slice Bool}
    {slot : alloc.vec.Vec (Option Std.Usize)} {groups groups' : alloc.vec.Vec Group}
    (planned : Planned layers present slot groups) (shape : Shape groups groups') :
    Planned layers present slot groups' := by
  refine ⟨?_, ?_, ?_, ?_, ?_⟩
  · intro c g said
    obtain ⟨group, group_is, member⟩ := planned.slot_group c g said
    obtain ⟨group', group'_is, files, -⟩ := shape.get group_is
    exact ⟨group', group'_is, files ▸ member⟩
  · intro j group' group'_is c member
    obtain ⟨group, group_is, files, -⟩ := shape.symm.get group'_is
    exact planned.group_slot j group group_is c (files.symm ▸ member)
  · intro j group' group'_is
    obtain ⟨group, group_is, files, -⟩ := shape.symm.get group'_is
    rw [← files]; exact planned.distinct j group group_is
  · intro j group' group'_is c member
    obtain ⟨group, group_is, files, layer⟩ := shape.symm.get group'_is
    rw [← layer]; exact planned.grounded j group group_is c (files.symm ▸ member)
  · intro j group' group'_is
    obtain ⟨group, group_is, files, -⟩ := shape.symm.get group'_is
    rw [← files]; exact planned.filled j group group_is

/-- Replacing the layers a group waits for changes nothing else. -/
theorem shape_set {groups groups' : alloc.vec.Vec Group} {g : Nat} {group : Group}
    (group_is : groups.val[g]? = some group) (waits : alloc.vec.Vec Std.U32)
    (groups_is : groups'.val = groups.val.set g { group with needed_by := waits }) :
    Shape groups groups' := by
  intro j
  rw [groups_is]
  by_cases here : j = g
  · subst here
    rw [group_is, List.getElem?_set_self (List.getElem?_eq_some_iff.mp group_is).1]
    rfl
  · rw [List.getElem?_set_ne (Ne.symm here)]

/-- The inner loop of the last pass: for each file of layer `l`, the layer waits for the group
of its content, if it has one. -/
@[step]
theorem waits_of_a_layer (layers : Slice (alloc.vec.Vec File)) (present : Slice Bool)
    (slot : alloc.vec.Vec (Option Std.Usize)) (groups : alloc.vec.Vec Group) (l : Std.U32)
    (table : alloc.vec.Vec File) (table_is : layers.val[l.val]? = some table)
    (f : Std.Usize) (many : layers.length ≤ Std.U32.max)
    (named : ∀ file ∈ table.val, file.content.val < slot.length) (read : f.val ≤ table.length)
    (planned : Planned layers present slot groups)
    (waiting : ∀ (j : Nat) (group : Group), groups.val[j]? = some group → Waits layers l.val f.val group) :
    plan_loop4_loop0 layers slot groups l f ⦃ r =>
      Planned layers present slot r ∧
      ∀ (j : Nat) (group : Group), r.val[j]? = some group → Waits layers l.val table.length group ⦄ := by
  unfold plan_loop4_loop0
  apply loop.spec_decr_nat (fun q => table.length - q.2.val)
    (fun q => Planned layers present slot q.1 ∧
      (∀ (j : Nat) (group : Group), q.1.val[j]? = some group → Waits layers l.val q.2.val group) ∧
      q.2.val ≤ table.length)
  · rintro ⟨now, f⟩ ⟨planned, waiting, read⟩
    simp only at planned waiting read ⊢
    unfold plan_loop4_loop0.body
    simp only [layer_bind table_is]
    split
    · rename_i below
      -- the file `f` of layer `l` is read, and the slot of its content looked up
      have below : f.val < table.length := by scalar_tac
      simp only [alloc.vec.Vec.index_slice_index, alloc.vec.Vec.index_mut_slice_index]
      step as ⟨ file, hfile ⟩
      have file_is : table.val[f.val]? = some file := by
        rw [hfile]; exact List.getElem?_eq_getElem below
      have named_file : file.content.val < slot.length := named file (List.mem_of_getElem? file_is)
      step as ⟨ i3, hi3 ⟩
      step as ⟨ o, ho ⟩
      refine WP.spec_bind (Pₘ := fun r => Planned layers present slot r ∧
        ∀ (j : Nat) (group : Group), r.val[j]? = some group → Waits layers l.val (f.val + 1) group) ?_ ?_
      · cases o with
        | none =>
          -- no group: no group lists the content, so nothing changes
          refine (WP.spec_ok _).mpr ⟨planned, fun j group group_is => ?_⟩
          refine waits_step_other table_is file_is (waiting j group group_is) fun member => ?_
          obtain ⟨g, said, -⟩ := planned.group_slot j group group_is _ member
          have slot_is : slot.val[file.content.val]? = some none := by
            rw [← hi3, List.getElem?_eq_getElem (by rw [hi3]; exact named_file), ← ho]
          rw [slot_is] at said
          simp at said
        | some g =>
          -- the group `g` lists the content: layer `l` is added to it, unless it is the last
          have slot_is : slot.val[file.content.val]? = some (some g) := by
            rw [← hi3, List.getElem?_eq_getElem (by rw [hi3]; exact named_file), ← ho]
          obtain ⟨group, group_is, member⟩ := planned.slot_group file.content g slot_is
          have waits_g := waiting g.val group group_is
          have layer_below : l.val < layers.length := (List.getElem?_eq_some_iff.mp table_is).1
          refine WP.spec_mono (wait_for now g l group group_is ?_) ?_
          · intro last
            have few := waits_few waits_g (waits_below waits_g l rfl last)
            have : Std.U32.max ≤ Std.Usize.max := by scalar_tac
            omega
          · rintro r ⟨waits, r_is, made⟩
            refine ⟨planned_of_shape planned (shape_set group_is waits r_is), fun j group' group'_is => ?_⟩
            by_cases here : j = g.val
            · subst here
              rw [r_is, List.getElem?_set_self (List.getElem?_eq_some_iff.mp group_is).1] at group'_is
              cases group'_is
              exact waits_step_listed table_is file_is waits_g member l rfl waits made
            · rw [r_is, List.getElem?_set_ne (Ne.symm here)] at group'_is
              refine waits_step_other table_is file_is (waiting j group' group'_is) fun listed => ?_
              obtain ⟨g', said, hg'⟩ := planned.group_slot j group' group'_is _ listed
              rw [slot_is] at said
              cases said
              exact here hg'.symm
      · rintro groups1 ⟨planned1, waiting1⟩
        step as ⟨ f1, hf1 ⟩
        exact ⟨planned1, fun j group group_is => by rw [hf1]; exact waiting1 j group group_is,
          by omega, by omega⟩
    · have : f.val = table.length := by scalar_tac
      simp only [WP.spec_ok]
      rw [← this]
      exact ⟨planned, waiting⟩
  · exact ⟨planned, waiting, read⟩

/-- The last pass over all the layers: afterwards each group waits for exactly the layers that
have a file whose content it lists. -/
@[step]
theorem waits_of_the_layers (layers : Slice (alloc.vec.Vec File)) (present : Slice Bool)
    (slot : alloc.vec.Vec (Option Std.Usize)) (groups : alloc.vec.Vec Group) (l : Std.U32)
    (many : layers.length ≤ Std.U32.max)
    (named : ∀ table ∈ layers.val, ∀ file ∈ table.val, file.content.val < slot.length)
    (read : l.val ≤ layers.length) (planned : Planned layers present slot groups)
    (waiting : ∀ (j : Nat) (group : Group), groups.val[j]? = some group →
      Waits layers l.val 0 group) :
    plan_loop4 layers slot groups l ⦃ r =>
      Planned layers present slot r ∧
      ∀ (j : Nat) (group : Group), r.val[j]? = some group →
        Waits layers layers.length 0 group ⦄ := by
  unfold plan_loop4
  apply loop.spec_decr_nat (fun q => layers.length - q.2.val)
    (fun q => Planned layers present slot q.1 ∧
      (∀ (j : Nat) (group : Group), q.1.val[j]? = some group → Waits layers q.2.val 0 group) ∧
      q.2.val ≤ layers.length)
  · rintro ⟨now, l⟩ ⟨planned, waiting, read⟩
    simp only at planned waiting read ⊢
    unfold plan_loop4.body
    step as ⟨ i, hi ⟩
    dsimp only [Slice.len]
    split
    · rename_i below
      have below : l.val < layers.length := by scalar_tac
      obtain ⟨table, table_is⟩ : ∃ table, layers.val[l.val]? = some table :=
        ⟨_, List.getElem?_eq_getElem below⟩
      have table_in := List.mem_of_getElem? table_is
      step as ⟨ groups1, planned1, waiting1 ⟩
      step as ⟨ next, hnext ⟩
      refine ⟨planned1, fun j group group_is => ?_, by omega, by omega⟩
      rw [hnext]
      simpa only [Waits, before_next_layer table_is] using waiting1 j group group_is
    · have : l.val = layers.length := by scalar_tac
      simp only [WP.spec_ok]
      rw [← this]
      exact ⟨planned, waiting⟩
  · exact ⟨planned, waiting, read⟩

end PlanCore
