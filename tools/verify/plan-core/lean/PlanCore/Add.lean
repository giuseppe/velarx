-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: what `add` of crates/plan-core does to the groups: the file joins the
-- last group (if it is of the same layer and has room) or starts a group at the end; nothing
-- else changes (`Added`), and it never panics.
--
-- Why it is needed: both passes that make the groups (the profile and the rest) call `add`, so
-- Loops.lean needs to know only this, not how it is written.
--
-- Read before this file: Tables.lean, and `add` and `has_room` of src/lib.rs.
--
-- Notation: as in Tables.lean; `old`, `new` are the group before and after; `l ++ [c]` is the
-- list `l` with `c` at its end.
import PlanCore.Tables

open Aeneas Aeneas.Std Result velarx_plan_core

namespace PlanCore

/-- A saturating sum never panics. -/
@[step]
theorem saturating_add_total (a b : Std.U64) :
    lift (core.num.U64.saturating_add a b) ⦃ _ => True ⦄ := by
  simp [lift]

/-- `has_room` never panics. -/
@[step]
theorem has_room_total (group : Group) (size : Std.U64) (limits : Limits) :
    has_room group size limits ⦃ _ => True ⦄ := by
  unfold has_room
  step*

/-- What `add` does to the groups: `c` joins the group `i`, which is of `layer`, at the end of its
files, or `c` starts a new group at the end, of `layer`; nothing else changes, and a group made or
left has no layer waiting. -/
def Added (groups : alloc.vec.Vec Group) (layer c : Std.U32) (i : Std.Usize)
    (groups' : alloc.vec.Vec Group) : Prop :=
  (∃ old new, groups.val[i.val]? = some old ∧ old.layer = layer ∧
      groups'.val = groups.val.set i.val new ∧ new.files.val = old.files.val ++ [c] ∧
      new.layer = old.layer ∧ new.needed_by = old.needed_by) ∨
  (i.val = groups.length ∧ ∃ new, groups'.val = groups.val ++ [new] ∧ new.layer = layer ∧
      new.files.val = [c] ∧ new.needed_by.val = [])

/-- (The helpers `start_group`, `put_in_group`, `wait_for` and `layer_bind` copy a fragment of the
code Aeneas generated and say what it does; they are not definitions of ours, and a change of the
translation makes the proof fail where they are used.)

A group of one file, `c`, starts at the end of the groups. -/
theorem start_group (groups : alloc.vec.Vec Group) (layer c : Std.U32) (size : Std.U64)
    (room : groups.length < Std.Usize.max) :
    (do let y ← lift (Std.Array.to_slice (Array.make 1#usize [c] (by simp) : Array Std.U32 1#usize))
        let groups1 ← groups.push { layer, files := alloc.slice.Slice.into_vec y, bytes := size,
                                    needed_by := alloc.vec.Vec.new Std.U32 }
        ok (groups.len, groups1)) ⦃ r => Added groups layer c r.1 r.2 ⦄ := by
  simp only [lift, Std.bind_ok]
  step as ⟨ groups1, hgroups1 ⟩
  right
  refine ⟨by simp [alloc.vec.Vec.len], _, hgroups1, rfl, ?_, rfl⟩
  rfl

/-- `add` returns, when there is room in the vectors, and it does what `Added` says. -/
@[step]
theorem add_adds (groups : alloc.vec.Vec Group) (start : Std.Usize) (layer : Std.U32)
    (file : File) (limits : Limits)
    (room_in_files : ∀ group ∈ groups.val, group.files.length < Std.Usize.max)
    (room_in_groups : groups.length < Std.Usize.max) :
    add groups start layer file limits ⦃ r => Added groups layer file.content r.1 r.2 ⦄ := by
  unfold add
  simp only [alloc.vec.Vec.index_slice_index, alloc.vec.Vec.index_mut_slice_index]
  split
  · rename_i some_after
    step as ⟨ i, hi ⟩
    step as ⟨ last, hlast ⟩
    by_cases same_layer : last.layer = layer
    · simp only [same_layer, ↓reduceIte]
      have inside : i.val < groups.length := by scalar_tac
      step as ⟨ g1, hg1 ⟩
      step as ⟨ fits ⟩
      by_cases roomy : fits = true
      · simp only [roomy, ↓reduceIte, index_mut_eq groups i inside, Std.bind_ok]
        step as ⟨ files, hfiles ⟩
        · exact room_in_files _ (List.getElem_mem inside)
        step as ⟨ g3, hg3 ⟩
        step as ⟨ i1 ⟩
        generalize hold : groups.val[i.val] = old at hfiles hg3 ⊢
        have inside' : ∀ x : Group, i.val < (groups.set i x).length :=
          fun _ => by simpa using inside
        simp only [index_mut_eq _ i (inside' _), Std.bind_ok, alloc.vec.Vec.set_val_eq,
          List.getElem_set_self]
        refine (WP.spec_ok _).mpr ?_
        have old_is : groups.val[i.val]? = some old := by
          rw [← hold]; exact List.getElem?_eq_getElem inside
        left
        refine ⟨old, { layer := old.layer, files := files, bytes := i1, needed_by := old.needed_by },
          old_is, ?_, by simp [List.set_set], by simpa using hfiles, rfl, rfl⟩
        rw [← same_layer, hlast]
        simp only [← hold]
      · have not_roomy : fits = false := by simpa using roomy
        simp only [not_roomy, Bool.false_eq_true, ↓reduceIte]
        exact start_group groups layer file.content file.size room_in_groups
    · simp only [same_layer, ↓reduceIte]
      exact start_group groups layer file.content file.size room_in_groups
  · exact start_group groups layer file.content file.size room_in_groups

end PlanCore
