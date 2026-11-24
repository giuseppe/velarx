-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: the two passes of `plan` that make the groups, loop by loop: the profile
-- (`profile_groups`), then every file of every layer in the order of the tables (`rest_of_a_layer`
-- for one layer, `rest_of_the_layers` for all).  Each puts the contents that are not present
-- and have no group yet into a group, keeping `Planned`; after the second, every content some
-- layer has that is not present has a group (`Covered`).
--
-- Why it is needed: P1 (nothing lacked is missed, nothing planned twice) and P3 (a file goes
-- to the layer that is its home) are the invariants of these loops.  The home is right because
-- the layers are read in order: when a content has no group at layer `l`, no earlier layer has it.
--
-- Read before this file: Planned.lean.
--
-- Notation: as in Tables.lean; `loop.spec_decr_nat` proves a loop returns by a number that goes
-- down at each turn (here, what is left to read) and an invariant kept by the body.
import PlanCore.Planned

open Aeneas Aeneas.Std Result velarx_plan_core

namespace PlanCore

/-- What the code does when it puts a content in a group: `add` the file to the groups, then
write the group it went to in the slot of the content. -/
theorem put_in_group (layers : Slice (alloc.vec.Vec File)) (present : Slice Bool)
    (limits : Limits) (start : Std.Usize) (layer : Std.U32) (file : File)
    (slot : alloc.vec.Vec (Option Std.Usize)) (groups : alloc.vec.Vec Group)
    (planned : Planned layers present slot groups) (unwaited : Unwaited groups)
    (inside : file.content.val < slot.length)
    (empty_slot : slot.val[file.content.val]? = some none)
    (home : Home layers present layer.val file.content) :
    (do let (i4, groups2) ← add groups start layer file limits
        let i5 ← lift (UScalar.cast .Usize file.content)
        let (_, index_mut_back) ← slot.index_mut_usize i5
        let slot2 := index_mut_back (some i4)
        ok (slot2, groups2)) ⦃ r =>
      r.1.length = slot.length ∧ Planned layers present r.1 r.2 ∧ Unwaited r.2 ∧
        Fills slot r.1 file.content ⦄ := by
  obtain ⟨room_in_files, room_in_groups⟩ := room_to_add planned _ inside empty_slot
  step as ⟨ i4, groups2, added ⟩
  step as ⟨ i5, hi5 ⟩
  simp only [index_mut_eq slot i5 (by omega), Std.bind_ok]
  refine (WP.spec_ok _).mpr ⟨by simp [alloc.vec.Vec.length], ?_⟩
  exact planned_added planned unwaited added empty_slot home inside (by simp [hi5])

/-- The loop over the profile: each content it names that some layer has, that is not present,
and that is in no group yet goes into a group of the layer that is its home. -/
@[step]
theorem profile_groups (layers : Slice (alloc.vec.Vec File)) (present : Slice Bool)
    (profile : Slice Std.U32) (limits : Limits)
    (home : alloc.vec.Vec (Option (Std.U32 × Std.U64)))
    (slot : alloc.vec.Vec (Option Std.Usize)) (groups : alloc.vec.Vec Group) (p : Std.Usize)
    (home_table : HomeTable layers layers.length 0 home) (home_size : home.length = slot.length)
    (present_size : present.length = slot.length)
    (named : ∀ c ∈ profile.val, c.val < slot.length) (read : p.val ≤ profile.length)
    (planned : Planned layers present slot groups) (unwaited : Unwaited groups) :
    plan_loop2 present profile limits home slot groups p ⦃ r =>
      r.1.length = slot.length ∧ Planned layers present r.1 r.2 ∧ Unwaited r.2 ⦄ := by
  unfold plan_loop2
  apply loop.spec_decr_nat (fun q => profile.length - q.2.2.val)
    (fun q => q.1.length = slot.length ∧ Planned layers present q.1 q.2.1 ∧
      Unwaited q.2.1 ∧ q.2.2.val ≤ profile.length)
  · rintro ⟨now, groups, p⟩ ⟨same, planned, unwaited, read⟩
    simp only at same planned unwaited read ⊢
    unfold plan_loop2.body
    dsimp only [Slice.len]
    split
    · rename_i below
      -- the profile entry `p` is read, and `home` says which layer has it, if any
      have below : p.val < profile.length := by scalar_tac
      simp only [alloc.vec.Vec.index_slice_index, alloc.vec.Vec.index_mut_slice_index]
      step as ⟨ content, hcontent ⟩
      have named_content : content.val < slot.length := by
        rw [hcontent]; exact named _ (List.getElem_mem below)
      step as ⟨ i1, hi1 ⟩
      step as ⟨ o, ho ⟩
      refine WP.spec_bind (Pₘ := fun r => r.1.length = now.length ∧
        Planned layers present r.1 r.2 ∧ Unwaited r.2) ?_ ?_
      · cases o with
        | none => exact (WP.spec_ok _).mpr ⟨rfl, planned, unwaited⟩
        | some found =>
          obtain ⟨layer, size⟩ := found
          step as ⟨ i2, hi2 ⟩
          step as ⟨ b, hb ⟩
          by_cases listed : b = true
          · simp only [listed, ↓reduceIte]
            exact (WP.spec_ok _).mpr ⟨rfl, planned, unwaited⟩
          -- not present: `slot[content].is_none()` decides whether it is planned already
          · have b_false : b = false := by simpa using listed
            have not_present : present.val[content.val]? = some false := by
              have hlen : i2.val < present.length := by
                rw [hi2, present_size]; exact named_content
              rw [← hi2, List.getElem?_eq_getElem hlen, ← hb, b_false]
            have homed : home.val[content.val]? = some (some (layer, size)) := by
              have hlen : i1.val < home.length := by
                rw [hi1, home_size]; exact named_content
              rw [← hi1, List.getElem?_eq_getElem hlen, ← ho]
            have first := (home_table content (by rw [home_size]; exact named_content)).2
              layer size homed
            simp only [b_false, Bool.false_eq_true, ↓reduceIte]
            step as ⟨ i3, hi3 ⟩
            step as ⟨ o1, ho1 ⟩
            -- no group yet: `add` puts it in a group of its home, and the slot says which
            by_cases fresh : o1.isNone = true
            · simp only [fresh, ↓reduceIte]
              have empty_slot : now.val[content.val]? = some none := by
                have hlen : i3.val < now.length := by
                  rw [hi3, same]; exact named_content
                have : now.val[i3.val] = none := by
                  rw [ho1] at fresh; exact Option.isNone_iff_eq_none.mp fresh
                rw [← hi3, List.getElem?_eq_getElem hlen, this]
              exact WP.spec_mono (put_in_group layers present limits 0#usize layer
                { content, size } now groups planned unwaited
                (by rw [same]; exact named_content) empty_slot ⟨⟨first.1, not_present⟩, first.2⟩)
                (fun _ done => ⟨done.1, done.2.1, done.2.2.1⟩)
            · simp only [fresh]
              exact (WP.spec_ok _).mpr ⟨rfl, planned, unwaited⟩
      -- the next entry of the profile
      · rintro ⟨slot1, groups1⟩ ⟨grown, planned1, unwaited1⟩
        step as ⟨ p1, hp1 ⟩
        exact ⟨grown.trans same, planned1, unwaited1, by omega, by omega⟩
    · have : p.val = profile.length := by scalar_tac
      simp only [WP.spec_ok, same, true_and]
      exact ⟨planned, unwaited⟩
  · exact ⟨rfl, planned, unwaited, read⟩

/-- Every content that is not present and was seen before the position (`l`, `f`) has a group. -/
def Covered (layers : Slice (alloc.vec.Vec File)) (present : Slice Bool) (l f : Nat)
    (slot : alloc.vec.Vec (Option Std.Usize)) : Prop :=
  ∀ c : Std.U32, c.val < slot.length → present.val[c.val]? = some false →
    Seen layers l f c → ∃ g, slot.val[c.val]? = some (some g)

/-- The inner loop of the second pass: the files of layer `l`, in the order of its table; each
content that is not present and has no group yet goes into a group of layer `l`, which is its
home, since the layers before were done. -/
@[step]
theorem rest_of_a_layer (layers : Slice (alloc.vec.Vec File)) (present : Slice Bool)
    (limits : Limits) (slot : alloc.vec.Vec (Option Std.Usize))
    (groups : alloc.vec.Vec Group) (start : Std.Usize) (l : Std.U32)
    (table : alloc.vec.Vec File) (table_is : layers.val[l.val]? = some table)
    (f : Std.Usize) (present_size : present.length = slot.length)
    (named : ∀ file ∈ table.val, file.content.val < slot.length) (read : f.val ≤ table.length)
    (planned : Planned layers present slot groups) (unwaited : Unwaited groups)
    (covered : Covered layers present l.val f.val slot) :
    plan_loop3_loop0 layers present limits slot groups start l f ⦃ r =>
      r.1.length = slot.length ∧ Planned layers present r.1 r.2 ∧ Unwaited r.2 ∧
      Covered layers present l.val table.length r.1 ⦄ := by
  unfold plan_loop3_loop0
  apply loop.spec_decr_nat (fun q => table.length - q.2.2.val)
    (fun q => q.1.length = slot.length ∧ Planned layers present q.1 q.2.1 ∧
      Unwaited q.2.1 ∧ Covered layers present l.val q.2.2.val q.1 ∧ q.2.2.val ≤ table.length)
  · rintro ⟨now, groups, f⟩ ⟨same, planned, unwaited, covered, read⟩
    simp only at same planned unwaited covered read ⊢
    unfold plan_loop3_loop0.body
    simp only [layer_bind table_is, alloc.vec.Vec.len]
    split
    · rename_i below
      -- the file `f` of layer `l` is read, and `present` says whether its content is
      have below : f.val < table.length := by scalar_tac
      simp only [alloc.vec.Vec.index_slice_index, alloc.vec.Vec.index_mut_slice_index]
      step as ⟨ file, hfile ⟩
      have file_is : table.val[f.val]? = some file := by
        rw [hfile]; exact List.getElem?_eq_getElem below
      have named_file : file.content.val < slot.length := named file (List.mem_of_getElem? file_is)
      have named_now : file.content.val < now.length := by rw [same]; exact named_file
      step as ⟨ i3, hi3 ⟩
      step as ⟨ b, hb ⟩
      have hlen : i3.val < present.length := by rw [hi3, present_size]; exact named_file
      refine WP.spec_bind (Pₘ := fun r => r.1.length = now.length ∧
        Planned layers present r.1 r.2 ∧ Unwaited r.2 ∧
        (∀ (c' : Std.U32) (g : Std.Usize), now.val[c'.val]? = some (some g) →
          ∃ g, r.1.val[c'.val]? = some (some g)) ∧
        (present.val[file.content.val]? = some false →
          ∃ g, r.1.val[file.content.val]? = some (some g))) ?_ ?_
      · by_cases listed : b = true
        · simp only [listed, ↓reduceIte]
          refine (WP.spec_ok _).mpr ⟨rfl, planned, unwaited, fun _ g h => ⟨g, h⟩, fun absent => ?_⟩
          have : present.val[file.content.val]? = some true := by
            rw [← hi3, List.getElem?_eq_getElem hlen, ← hb, listed]
          rw [this] at absent
          simp at absent
        -- not present: the slot is looked at
        · have b_false : b = false := by simpa using listed
          have not_present : present.val[file.content.val]? = some false := by
            rw [← hi3, List.getElem?_eq_getElem hlen, ← hb, b_false]
          simp only [b_false, Bool.false_eq_true, ↓reduceIte]
          step as ⟨ i4, hi4 ⟩
          step as ⟨ o, ho ⟩
          have slot_lt : i4.val < now.val.length := by rw [hi4]; exact named_now
          by_cases fresh : o.isNone = true
          · simp only [fresh, ↓reduceIte]
            have empty_slot : now.val[file.content.val]? = some none := by
              have : now.val[i4.val] = none := by
                rw [ho] at fresh; exact Option.isNone_iff_eq_none.mp fresh
              rw [← hi4, List.getElem?_eq_getElem slot_lt, this]
            -- no group yet: layer `l` is the home, since a group of an earlier layer would
            -- have been made when that layer was read (`covered`)
            have home : Home layers present l.val file.content := by
              refine ⟨⟨⟨table, table_is, file, List.mem_of_getElem? file_is, rfl⟩, not_present⟩,
                fun k before has => ?_⟩
              obtain ⟨g, said⟩ := covered file.content named_now not_present
                (by obtain ⟨t, tk, x, xt, hx⟩ := has
                    obtain ⟨i, hi⟩ := List.mem_iff_getElem?.mp xt
                    exact ⟨k, t, i, x, tk, hi, hx, Or.inl before⟩)
              rw [empty_slot] at said
              simp at said
            exact WP.spec_mono (put_in_group layers present limits start l file now groups
              planned unwaited named_now empty_slot home)
              (fun _ done => ⟨done.1, done.2.1, done.2.2.1,
                fun c' g said => done.2.2.2.1 c' ⟨g, said⟩, fun _ => done.2.2.2.2⟩)
          · simp only [fresh]
            have taken : ∃ g, now.val[file.content.val]? = some (some g) := by
              cases o with
              | none => exact (fresh rfl).elim
              | some g =>
                refine ⟨g, ?_⟩
                rw [← hi4, List.getElem?_eq_getElem slot_lt, ← ho]
            exact (WP.spec_ok _).mpr ⟨rfl, planned, unwaited, fun _ g h => ⟨g, h⟩, fun _ => taken⟩
      · rintro ⟨slot1, groups1⟩ ⟨grown, planned1, unwaited1, kept, added⟩
        step as ⟨ f1, hf1 ⟩
        refine ⟨grown.trans same, planned1, unwaited1, ?_, by omega, by omega⟩
        intro c hc hpresent seen
        rw [hf1] at seen
        have seen_step : Seen layers l.val (f.val + 1) c ↔
            Seen layers l.val f.val c ∨ file.content = c :=
          before_step table_is file_is (fun _ c' => c' = c)
        rcases seen_step.mp seen with before | same_content
        · obtain ⟨g, said⟩ := covered c (grown ▸ hc) hpresent before
          exact kept c g said
        · subst same_content
          exact added hpresent
    · have : f.val = table.length := by scalar_tac
      simp only [WP.spec_ok, same, true_and]
      rw [← this]
      exact ⟨planned, unwaited, covered⟩
  · exact ⟨rfl, planned, unwaited, covered, read⟩

/-- The second pass over all the layers: afterwards every content some layer has, that is not
present, has a group. -/
@[step]
theorem rest_of_the_layers (layers : Slice (alloc.vec.Vec File)) (present : Slice Bool)
    (limits : Limits) (slot : alloc.vec.Vec (Option Std.Usize))
    (groups : alloc.vec.Vec Group) (start : Std.Usize) (l : Std.U32)
    (many : layers.length ≤ Std.U32.max) (present_size : present.length = slot.length)
    (named : ∀ table ∈ layers.val, ∀ file ∈ table.val, file.content.val < slot.length)
    (read : l.val ≤ layers.length)
    (planned : Planned layers present slot groups) (unwaited : Unwaited groups)
    (covered : Covered layers present l.val 0 slot) :
    plan_loop3 layers present limits slot groups start l ⦃ r =>
      r.1.length = slot.length ∧ Planned layers present r.1 r.2 ∧ Unwaited r.2 ∧
      Covered layers present layers.length 0 r.1 ⦄ := by
  unfold plan_loop3
  apply loop.spec_decr_nat (fun q => layers.length - q.2.2.val)
    (fun q => q.1.length = slot.length ∧ Planned layers present q.1 q.2.1 ∧
      Unwaited q.2.1 ∧ Covered layers present q.2.2.val 0 q.1 ∧ q.2.2.val ≤ layers.length)
  · rintro ⟨now, groups, l⟩ ⟨same, planned, unwaited, covered, read⟩
    simp only at same planned unwaited covered read ⊢
    unfold plan_loop3.body
    step as ⟨ i, hi ⟩
    dsimp only [Slice.len]
    split
    · rename_i below
      have below : l.val < layers.length := by scalar_tac
      obtain ⟨table, table_is⟩ : ∃ table, layers.val[l.val]? = some table :=
        ⟨_, List.getElem?_eq_getElem below⟩
      have table_in := List.mem_of_getElem? table_is
      step as ⟨ slot1, groups1, grown, planned1, unwaited1, covered1 ⟩
      step as ⟨ next, hnext ⟩
      refine ⟨grown.trans same, planned1, unwaited1, ?_, by omega, by omega⟩
      rw [hnext]
      simpa only [Covered, Seen, before_next_layer table_is] using covered1
    · have : l.val = layers.length := by scalar_tac
      simp only [WP.spec_ok, same, true_and]
      rw [← this]
      exact ⟨planned, unwaited, covered⟩
  · exact ⟨rfl, planned, unwaited, covered, read⟩

end PlanCore
